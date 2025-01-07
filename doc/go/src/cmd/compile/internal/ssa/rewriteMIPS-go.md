Response: The user wants a summary of the functionalities of the provided Go code snippet. This code is part of the Go compiler for the MIPS architecture.

The code defines a function `rewriteValueMIPS(v *Value) bool` which is likely part of the instruction rewriting phase in the SSA (Static Single Assignment) intermediate representation. This function takes an SSA value `v` as input and attempts to rewrite it into a more optimized or architecture-specific form.

The code is structured as a large switch statement on the `Op` field of the `Value`. Each case corresponds to a different high-level SSA operation and defines how it should be translated into MIPS-specific operations.

Therefore, the main functionality of this code is to **perform instruction selection and optimization for the MIPS architecture within the Go compiler's SSA framework**.

I will go through the cases and group them into logical categories to provide a concise summary.
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteMIPS.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明,
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第1部分，共3部分，请归纳一下它的功能
```

**功能列举:**

这段 Go 代码的主要功能是定义了 `rewriteValueMIPS` 函数，该函数负责将 Go 语言的通用 SSA (Static Single Assignment) 中间表示中的操作 (Op) 转换为 MIPS 架构特定的操作。具体来说，它针对不同的 SSA 操作类型，进行了以下转换或处理：

1. **简单的一对一操作映射:**  将一些通用的算术、逻辑、类型转换等操作直接映射到 MIPS 架构对应的指令。例如， `OpAdd32` 映射到 `OpMIPSADD`。

2. **带有辅助信息的重写:** 一些操作的转换需要借助辅助信息 (Aux) ，例如 `OpAddr` 被重写为 `OpMIPSMOVWaddr` 并携带了符号信息。

3. **更复杂的模式匹配和重写:**  某些 SSA 操作的转换逻辑较为复杂，可能涉及到多个 MIPS 指令的组合，或者根据特定的条件进行不同的重写。例如 `OpAdd32withcarry` 的重写。

4. **原子操作的底层实现:**  Go 语言的原子操作（如 `OpAtomicAdd32`，`OpAtomicAnd32` 等）被转换为 MIPS 架构提供的底层原子操作指令 (`OpMIPSLoweredAtomicAdd` 等)。

5. **常量加载:**  将常量操作 (`OpConst16`, `OpConst32` 等) 转换为 MIPS 的加载常量指令 (`OpMIPSMOVWconst` 等)。

6. **函数调用:**  将不同的函数调用方式 (`OpClosureCall`, `OpInterCall`, `OpStaticCall`, `OpTailCall`) 转换为 MIPS 架构的调用指令 (`OpMIPSCALLclosure` 等)。

7. **比较操作的转换:**  将 Go 语言的比较操作 (`OpEq32`, `OpLess16` 等) 转换为 MIPS 的比较和条件跳转相关的指令 (`OpMIPSSGTUconst`, `OpMIPSCMPEQF` 等)。

8. **位运算和移位操作的优化:**  针对不同大小的移位操作，以及常量移位等情况，进行特定的 MIPS 指令选择和优化。

9. **Load 和 Store 操作:**  根据不同的数据类型，将 `OpLoad` 和 `OpStore` 操作转换为 MIPS 架构相应的加载和存储指令 (`OpMIPSMOVBload`, `OpMIPSMOVWstore` 等)。

10. **本地变量地址计算:**  `OpLocalAddr` 被转换为 `OpMIPSMOVWaddr`，用于获取栈上局部变量的地址。

**推断的 Go 语言功能实现 (及代码示例):**

这段代码是 Go 编译器中将中间表示转换为 MIPS 汇编代码的关键部分。它处理了 Go 语言的各种基本操作。以下是一些示例：

* **算术运算:**
  ```go
  // 假设输入 SSA Value v 代表 a + b，其中 a 和 b 是 int32 类型的变量
  // 输入: v.Op = OpAdd32, v.Args = [a_value, b_value]
  // 输出: v.Op 会被设置为 OpMIPSADD
  var a int32 = 10
  var b int32 = 5
  sum := a + b
  println(sum)
  ```

* **原子操作:**
  ```go
  // 假设输入 SSA Value v 代表 atomic.AddInt32(&count, 1)
  // 输入: v.Op = OpAtomicAdd32, v.Args = [ptr_to_count, const_1, memory_state]
  // 输出: v.Op 会被设置为 OpMIPSLoweredAtomicAdd
  package main

  import (
  	"fmt"
  	"sync/atomic"
  )

  func main() {
  	var count int32 = 0
  	atomic.AddInt32(&count, 1)
  	fmt.Println(count)
  }
  ```

* **比较运算:**
  ```go
  // 假设输入 SSA Value v 代表 x == y，其中 x 和 y 是 int32 类型的变量
  // 输入: v.Op = OpEq32, v.Args = [x_value, y_value]
  // 输出: v.Op 会被设置为 OpMIPSSGTUconst, 并引入 XOR 操作
  var x int32 = 10
  var y int32 = 10
  equal := x == y
  println(equal)
  ```

* **Load 和 Store:**
  ```go
  // 假设输入 SSA Value v 代表 *ptr = value，其中 ptr 是 *int32，value 是 int32
  // 输入: v.Op = OpStore, v.Args = [ptr_value, value_value, memory_state]
  // 输出: v.Op 会被设置为 OpMIPSMOVWstore

  var val int32 = 10
  ptr := new(int32)
  *ptr = val
  println(*ptr)

  // 假设输入 SSA Value v 代表 value := *ptr，其中 ptr 是 *int32
  // 输入: v.Op = OpLoad, v.Args = [ptr_value, memory_state]
  // 输出: v.Op 会被设置为 OpMIPSMOVWload
  var loadedValue int32 = *ptr
  println(loadedValue)
  ```

**代码推理 (带假设的输入与输出):**

以 `OpAdd32withcarry` 为例：

**假设输入:**

```
v = &Value{
    Op: OpAdd32withcarry,
    Type: types.Types[TINT32], // 假设 TINT32 代表 int32 类型
    Args: []*Value{
        &Value{ /* 代表第一个加数 */ },
        &Value{ /* 代表第二个加数 */ },
        &Value{ /* 代表进位 */ },
    },
    Block: /* 当前代码块 */,
}
```

**输出:**

```
v = &Value{
    Op: OpMIPSADD,
    Type: types.Types[TINT32],
    Args: []*Value{
        &Value{
            Op: OpMIPSADD,
            Type: types.Types[TINT32],
            Args: []*Value{
                v.Args[0], // 第一个加数
                v.Args[1], // 第二个加数
            },
            Block: v.Block,
        },
        v.Args[2], // 进位
    },
    Block: v.Block,
}
```

**推理说明:**  `OpAdd32withcarry` 在 MIPS 架构上通常没有直接对应的单条指令。这段代码将其分解为两个 `OpMIPSADD` 操作，先将两个加数相加，然后将结果与进位相加。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。它属于 Go 编译器的内部实现，处理命令行参数的是 `go` 命令以及编译器驱动程序。编译器驱动程序会解析命令行参数，并配置编译过程的各个阶段，包括 SSA 的生成和优化。

**归纳一下它的功能 (第1部分):**

这段 `rewriteMIPS.go` 代码 (第 1 部分) 的主要功能是 **定义了将 Go 语言的抽象 SSA 操作转换为 MIPS 架构特定指令的初步转换规则**。 它处理了大量的基本操作，包括算术运算、逻辑运算、类型转换、常量加载、原子操作和部分 Load/Store 操作的转换。  这为后续更复杂的 MIPS 特定的优化和代码生成奠定了基础。 简单来说，它完成了从与架构无关的中间表示到与 MIPS 架构相关的指令的初步映射。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteMIPS.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第1部分，共3部分，请归纳一下它的功能

"""
// Code generated from _gen/MIPS.rules using 'go generate'; DO NOT EDIT.

package ssa

import "cmd/compile/internal/types"

func rewriteValueMIPS(v *Value) bool {
	switch v.Op {
	case OpAbs:
		v.Op = OpMIPSABSD
		return true
	case OpAdd16:
		v.Op = OpMIPSADD
		return true
	case OpAdd32:
		v.Op = OpMIPSADD
		return true
	case OpAdd32F:
		v.Op = OpMIPSADDF
		return true
	case OpAdd32withcarry:
		return rewriteValueMIPS_OpAdd32withcarry(v)
	case OpAdd64F:
		v.Op = OpMIPSADDD
		return true
	case OpAdd8:
		v.Op = OpMIPSADD
		return true
	case OpAddPtr:
		v.Op = OpMIPSADD
		return true
	case OpAddr:
		return rewriteValueMIPS_OpAddr(v)
	case OpAnd16:
		v.Op = OpMIPSAND
		return true
	case OpAnd32:
		v.Op = OpMIPSAND
		return true
	case OpAnd8:
		v.Op = OpMIPSAND
		return true
	case OpAndB:
		v.Op = OpMIPSAND
		return true
	case OpAtomicAdd32:
		v.Op = OpMIPSLoweredAtomicAdd
		return true
	case OpAtomicAnd32:
		v.Op = OpMIPSLoweredAtomicAnd
		return true
	case OpAtomicAnd8:
		return rewriteValueMIPS_OpAtomicAnd8(v)
	case OpAtomicCompareAndSwap32:
		v.Op = OpMIPSLoweredAtomicCas
		return true
	case OpAtomicExchange32:
		v.Op = OpMIPSLoweredAtomicExchange
		return true
	case OpAtomicLoad32:
		v.Op = OpMIPSLoweredAtomicLoad32
		return true
	case OpAtomicLoad8:
		v.Op = OpMIPSLoweredAtomicLoad8
		return true
	case OpAtomicLoadPtr:
		v.Op = OpMIPSLoweredAtomicLoad32
		return true
	case OpAtomicOr32:
		v.Op = OpMIPSLoweredAtomicOr
		return true
	case OpAtomicOr8:
		return rewriteValueMIPS_OpAtomicOr8(v)
	case OpAtomicStore32:
		v.Op = OpMIPSLoweredAtomicStore32
		return true
	case OpAtomicStore8:
		v.Op = OpMIPSLoweredAtomicStore8
		return true
	case OpAtomicStorePtrNoWB:
		v.Op = OpMIPSLoweredAtomicStore32
		return true
	case OpAvg32u:
		return rewriteValueMIPS_OpAvg32u(v)
	case OpBitLen32:
		return rewriteValueMIPS_OpBitLen32(v)
	case OpClosureCall:
		v.Op = OpMIPSCALLclosure
		return true
	case OpCom16:
		return rewriteValueMIPS_OpCom16(v)
	case OpCom32:
		return rewriteValueMIPS_OpCom32(v)
	case OpCom8:
		return rewriteValueMIPS_OpCom8(v)
	case OpConst16:
		return rewriteValueMIPS_OpConst16(v)
	case OpConst32:
		return rewriteValueMIPS_OpConst32(v)
	case OpConst32F:
		v.Op = OpMIPSMOVFconst
		return true
	case OpConst64F:
		v.Op = OpMIPSMOVDconst
		return true
	case OpConst8:
		return rewriteValueMIPS_OpConst8(v)
	case OpConstBool:
		return rewriteValueMIPS_OpConstBool(v)
	case OpConstNil:
		return rewriteValueMIPS_OpConstNil(v)
	case OpCtz32:
		return rewriteValueMIPS_OpCtz32(v)
	case OpCtz32NonZero:
		v.Op = OpCtz32
		return true
	case OpCvt32Fto32:
		v.Op = OpMIPSTRUNCFW
		return true
	case OpCvt32Fto64F:
		v.Op = OpMIPSMOVFD
		return true
	case OpCvt32to32F:
		v.Op = OpMIPSMOVWF
		return true
	case OpCvt32to64F:
		v.Op = OpMIPSMOVWD
		return true
	case OpCvt64Fto32:
		v.Op = OpMIPSTRUNCDW
		return true
	case OpCvt64Fto32F:
		v.Op = OpMIPSMOVDF
		return true
	case OpCvtBoolToUint8:
		v.Op = OpCopy
		return true
	case OpDiv16:
		return rewriteValueMIPS_OpDiv16(v)
	case OpDiv16u:
		return rewriteValueMIPS_OpDiv16u(v)
	case OpDiv32:
		return rewriteValueMIPS_OpDiv32(v)
	case OpDiv32F:
		v.Op = OpMIPSDIVF
		return true
	case OpDiv32u:
		return rewriteValueMIPS_OpDiv32u(v)
	case OpDiv64F:
		v.Op = OpMIPSDIVD
		return true
	case OpDiv8:
		return rewriteValueMIPS_OpDiv8(v)
	case OpDiv8u:
		return rewriteValueMIPS_OpDiv8u(v)
	case OpEq16:
		return rewriteValueMIPS_OpEq16(v)
	case OpEq32:
		return rewriteValueMIPS_OpEq32(v)
	case OpEq32F:
		return rewriteValueMIPS_OpEq32F(v)
	case OpEq64F:
		return rewriteValueMIPS_OpEq64F(v)
	case OpEq8:
		return rewriteValueMIPS_OpEq8(v)
	case OpEqB:
		return rewriteValueMIPS_OpEqB(v)
	case OpEqPtr:
		return rewriteValueMIPS_OpEqPtr(v)
	case OpGetCallerPC:
		v.Op = OpMIPSLoweredGetCallerPC
		return true
	case OpGetCallerSP:
		v.Op = OpMIPSLoweredGetCallerSP
		return true
	case OpGetClosurePtr:
		v.Op = OpMIPSLoweredGetClosurePtr
		return true
	case OpHmul32:
		return rewriteValueMIPS_OpHmul32(v)
	case OpHmul32u:
		return rewriteValueMIPS_OpHmul32u(v)
	case OpInterCall:
		v.Op = OpMIPSCALLinter
		return true
	case OpIsInBounds:
		return rewriteValueMIPS_OpIsInBounds(v)
	case OpIsNonNil:
		return rewriteValueMIPS_OpIsNonNil(v)
	case OpIsSliceInBounds:
		return rewriteValueMIPS_OpIsSliceInBounds(v)
	case OpLeq16:
		return rewriteValueMIPS_OpLeq16(v)
	case OpLeq16U:
		return rewriteValueMIPS_OpLeq16U(v)
	case OpLeq32:
		return rewriteValueMIPS_OpLeq32(v)
	case OpLeq32F:
		return rewriteValueMIPS_OpLeq32F(v)
	case OpLeq32U:
		return rewriteValueMIPS_OpLeq32U(v)
	case OpLeq64F:
		return rewriteValueMIPS_OpLeq64F(v)
	case OpLeq8:
		return rewriteValueMIPS_OpLeq8(v)
	case OpLeq8U:
		return rewriteValueMIPS_OpLeq8U(v)
	case OpLess16:
		return rewriteValueMIPS_OpLess16(v)
	case OpLess16U:
		return rewriteValueMIPS_OpLess16U(v)
	case OpLess32:
		return rewriteValueMIPS_OpLess32(v)
	case OpLess32F:
		return rewriteValueMIPS_OpLess32F(v)
	case OpLess32U:
		return rewriteValueMIPS_OpLess32U(v)
	case OpLess64F:
		return rewriteValueMIPS_OpLess64F(v)
	case OpLess8:
		return rewriteValueMIPS_OpLess8(v)
	case OpLess8U:
		return rewriteValueMIPS_OpLess8U(v)
	case OpLoad:
		return rewriteValueMIPS_OpLoad(v)
	case OpLocalAddr:
		return rewriteValueMIPS_OpLocalAddr(v)
	case OpLsh16x16:
		return rewriteValueMIPS_OpLsh16x16(v)
	case OpLsh16x32:
		return rewriteValueMIPS_OpLsh16x32(v)
	case OpLsh16x64:
		return rewriteValueMIPS_OpLsh16x64(v)
	case OpLsh16x8:
		return rewriteValueMIPS_OpLsh16x8(v)
	case OpLsh32x16:
		return rewriteValueMIPS_OpLsh32x16(v)
	case OpLsh32x32:
		return rewriteValueMIPS_OpLsh32x32(v)
	case OpLsh32x64:
		return rewriteValueMIPS_OpLsh32x64(v)
	case OpLsh32x8:
		return rewriteValueMIPS_OpLsh32x8(v)
	case OpLsh8x16:
		return rewriteValueMIPS_OpLsh8x16(v)
	case OpLsh8x32:
		return rewriteValueMIPS_OpLsh8x32(v)
	case OpLsh8x64:
		return rewriteValueMIPS_OpLsh8x64(v)
	case OpLsh8x8:
		return rewriteValueMIPS_OpLsh8x8(v)
	case OpMIPSADD:
		return rewriteValueMIPS_OpMIPSADD(v)
	case OpMIPSADDconst:
		return rewriteValueMIPS_OpMIPSADDconst(v)
	case OpMIPSAND:
		return rewriteValueMIPS_OpMIPSAND(v)
	case OpMIPSANDconst:
		return rewriteValueMIPS_OpMIPSANDconst(v)
	case OpMIPSCMOVZ:
		return rewriteValueMIPS_OpMIPSCMOVZ(v)
	case OpMIPSCMOVZzero:
		return rewriteValueMIPS_OpMIPSCMOVZzero(v)
	case OpMIPSLoweredAtomicAdd:
		return rewriteValueMIPS_OpMIPSLoweredAtomicAdd(v)
	case OpMIPSLoweredAtomicStore32:
		return rewriteValueMIPS_OpMIPSLoweredAtomicStore32(v)
	case OpMIPSMOVBUload:
		return rewriteValueMIPS_OpMIPSMOVBUload(v)
	case OpMIPSMOVBUreg:
		return rewriteValueMIPS_OpMIPSMOVBUreg(v)
	case OpMIPSMOVBload:
		return rewriteValueMIPS_OpMIPSMOVBload(v)
	case OpMIPSMOVBreg:
		return rewriteValueMIPS_OpMIPSMOVBreg(v)
	case OpMIPSMOVBstore:
		return rewriteValueMIPS_OpMIPSMOVBstore(v)
	case OpMIPSMOVBstorezero:
		return rewriteValueMIPS_OpMIPSMOVBstorezero(v)
	case OpMIPSMOVDload:
		return rewriteValueMIPS_OpMIPSMOVDload(v)
	case OpMIPSMOVDstore:
		return rewriteValueMIPS_OpMIPSMOVDstore(v)
	case OpMIPSMOVFload:
		return rewriteValueMIPS_OpMIPSMOVFload(v)
	case OpMIPSMOVFstore:
		return rewriteValueMIPS_OpMIPSMOVFstore(v)
	case OpMIPSMOVHUload:
		return rewriteValueMIPS_OpMIPSMOVHUload(v)
	case OpMIPSMOVHUreg:
		return rewriteValueMIPS_OpMIPSMOVHUreg(v)
	case OpMIPSMOVHload:
		return rewriteValueMIPS_OpMIPSMOVHload(v)
	case OpMIPSMOVHreg:
		return rewriteValueMIPS_OpMIPSMOVHreg(v)
	case OpMIPSMOVHstore:
		return rewriteValueMIPS_OpMIPSMOVHstore(v)
	case OpMIPSMOVHstorezero:
		return rewriteValueMIPS_OpMIPSMOVHstorezero(v)
	case OpMIPSMOVWload:
		return rewriteValueMIPS_OpMIPSMOVWload(v)
	case OpMIPSMOVWnop:
		return rewriteValueMIPS_OpMIPSMOVWnop(v)
	case OpMIPSMOVWreg:
		return rewriteValueMIPS_OpMIPSMOVWreg(v)
	case OpMIPSMOVWstore:
		return rewriteValueMIPS_OpMIPSMOVWstore(v)
	case OpMIPSMOVWstorezero:
		return rewriteValueMIPS_OpMIPSMOVWstorezero(v)
	case OpMIPSMUL:
		return rewriteValueMIPS_OpMIPSMUL(v)
	case OpMIPSNEG:
		return rewriteValueMIPS_OpMIPSNEG(v)
	case OpMIPSNOR:
		return rewriteValueMIPS_OpMIPSNOR(v)
	case OpMIPSNORconst:
		return rewriteValueMIPS_OpMIPSNORconst(v)
	case OpMIPSOR:
		return rewriteValueMIPS_OpMIPSOR(v)
	case OpMIPSORconst:
		return rewriteValueMIPS_OpMIPSORconst(v)
	case OpMIPSSGT:
		return rewriteValueMIPS_OpMIPSSGT(v)
	case OpMIPSSGTU:
		return rewriteValueMIPS_OpMIPSSGTU(v)
	case OpMIPSSGTUconst:
		return rewriteValueMIPS_OpMIPSSGTUconst(v)
	case OpMIPSSGTUzero:
		return rewriteValueMIPS_OpMIPSSGTUzero(v)
	case OpMIPSSGTconst:
		return rewriteValueMIPS_OpMIPSSGTconst(v)
	case OpMIPSSGTzero:
		return rewriteValueMIPS_OpMIPSSGTzero(v)
	case OpMIPSSLL:
		return rewriteValueMIPS_OpMIPSSLL(v)
	case OpMIPSSLLconst:
		return rewriteValueMIPS_OpMIPSSLLconst(v)
	case OpMIPSSRA:
		return rewriteValueMIPS_OpMIPSSRA(v)
	case OpMIPSSRAconst:
		return rewriteValueMIPS_OpMIPSSRAconst(v)
	case OpMIPSSRL:
		return rewriteValueMIPS_OpMIPSSRL(v)
	case OpMIPSSRLconst:
		return rewriteValueMIPS_OpMIPSSRLconst(v)
	case OpMIPSSUB:
		return rewriteValueMIPS_OpMIPSSUB(v)
	case OpMIPSSUBconst:
		return rewriteValueMIPS_OpMIPSSUBconst(v)
	case OpMIPSXOR:
		return rewriteValueMIPS_OpMIPSXOR(v)
	case OpMIPSXORconst:
		return rewriteValueMIPS_OpMIPSXORconst(v)
	case OpMod16:
		return rewriteValueMIPS_OpMod16(v)
	case OpMod16u:
		return rewriteValueMIPS_OpMod16u(v)
	case OpMod32:
		return rewriteValueMIPS_OpMod32(v)
	case OpMod32u:
		return rewriteValueMIPS_OpMod32u(v)
	case OpMod8:
		return rewriteValueMIPS_OpMod8(v)
	case OpMod8u:
		return rewriteValueMIPS_OpMod8u(v)
	case OpMove:
		return rewriteValueMIPS_OpMove(v)
	case OpMul16:
		v.Op = OpMIPSMUL
		return true
	case OpMul32:
		v.Op = OpMIPSMUL
		return true
	case OpMul32F:
		v.Op = OpMIPSMULF
		return true
	case OpMul32uhilo:
		v.Op = OpMIPSMULTU
		return true
	case OpMul64F:
		v.Op = OpMIPSMULD
		return true
	case OpMul8:
		v.Op = OpMIPSMUL
		return true
	case OpNeg16:
		v.Op = OpMIPSNEG
		return true
	case OpNeg32:
		v.Op = OpMIPSNEG
		return true
	case OpNeg32F:
		v.Op = OpMIPSNEGF
		return true
	case OpNeg64F:
		v.Op = OpMIPSNEGD
		return true
	case OpNeg8:
		v.Op = OpMIPSNEG
		return true
	case OpNeq16:
		return rewriteValueMIPS_OpNeq16(v)
	case OpNeq32:
		return rewriteValueMIPS_OpNeq32(v)
	case OpNeq32F:
		return rewriteValueMIPS_OpNeq32F(v)
	case OpNeq64F:
		return rewriteValueMIPS_OpNeq64F(v)
	case OpNeq8:
		return rewriteValueMIPS_OpNeq8(v)
	case OpNeqB:
		v.Op = OpMIPSXOR
		return true
	case OpNeqPtr:
		return rewriteValueMIPS_OpNeqPtr(v)
	case OpNilCheck:
		v.Op = OpMIPSLoweredNilCheck
		return true
	case OpNot:
		return rewriteValueMIPS_OpNot(v)
	case OpOffPtr:
		return rewriteValueMIPS_OpOffPtr(v)
	case OpOr16:
		v.Op = OpMIPSOR
		return true
	case OpOr32:
		v.Op = OpMIPSOR
		return true
	case OpOr8:
		v.Op = OpMIPSOR
		return true
	case OpOrB:
		v.Op = OpMIPSOR
		return true
	case OpPanicBounds:
		return rewriteValueMIPS_OpPanicBounds(v)
	case OpPanicExtend:
		return rewriteValueMIPS_OpPanicExtend(v)
	case OpRotateLeft16:
		return rewriteValueMIPS_OpRotateLeft16(v)
	case OpRotateLeft32:
		return rewriteValueMIPS_OpRotateLeft32(v)
	case OpRotateLeft64:
		return rewriteValueMIPS_OpRotateLeft64(v)
	case OpRotateLeft8:
		return rewriteValueMIPS_OpRotateLeft8(v)
	case OpRound32F:
		v.Op = OpCopy
		return true
	case OpRound64F:
		v.Op = OpCopy
		return true
	case OpRsh16Ux16:
		return rewriteValueMIPS_OpRsh16Ux16(v)
	case OpRsh16Ux32:
		return rewriteValueMIPS_OpRsh16Ux32(v)
	case OpRsh16Ux64:
		return rewriteValueMIPS_OpRsh16Ux64(v)
	case OpRsh16Ux8:
		return rewriteValueMIPS_OpRsh16Ux8(v)
	case OpRsh16x16:
		return rewriteValueMIPS_OpRsh16x16(v)
	case OpRsh16x32:
		return rewriteValueMIPS_OpRsh16x32(v)
	case OpRsh16x64:
		return rewriteValueMIPS_OpRsh16x64(v)
	case OpRsh16x8:
		return rewriteValueMIPS_OpRsh16x8(v)
	case OpRsh32Ux16:
		return rewriteValueMIPS_OpRsh32Ux16(v)
	case OpRsh32Ux32:
		return rewriteValueMIPS_OpRsh32Ux32(v)
	case OpRsh32Ux64:
		return rewriteValueMIPS_OpRsh32Ux64(v)
	case OpRsh32Ux8:
		return rewriteValueMIPS_OpRsh32Ux8(v)
	case OpRsh32x16:
		return rewriteValueMIPS_OpRsh32x16(v)
	case OpRsh32x32:
		return rewriteValueMIPS_OpRsh32x32(v)
	case OpRsh32x64:
		return rewriteValueMIPS_OpRsh32x64(v)
	case OpRsh32x8:
		return rewriteValueMIPS_OpRsh32x8(v)
	case OpRsh8Ux16:
		return rewriteValueMIPS_OpRsh8Ux16(v)
	case OpRsh8Ux32:
		return rewriteValueMIPS_OpRsh8Ux32(v)
	case OpRsh8Ux64:
		return rewriteValueMIPS_OpRsh8Ux64(v)
	case OpRsh8Ux8:
		return rewriteValueMIPS_OpRsh8Ux8(v)
	case OpRsh8x16:
		return rewriteValueMIPS_OpRsh8x16(v)
	case OpRsh8x32:
		return rewriteValueMIPS_OpRsh8x32(v)
	case OpRsh8x64:
		return rewriteValueMIPS_OpRsh8x64(v)
	case OpRsh8x8:
		return rewriteValueMIPS_OpRsh8x8(v)
	case OpSelect0:
		return rewriteValueMIPS_OpSelect0(v)
	case OpSelect1:
		return rewriteValueMIPS_OpSelect1(v)
	case OpSignExt16to32:
		v.Op = OpMIPSMOVHreg
		return true
	case OpSignExt8to16:
		v.Op = OpMIPSMOVBreg
		return true
	case OpSignExt8to32:
		v.Op = OpMIPSMOVBreg
		return true
	case OpSignmask:
		return rewriteValueMIPS_OpSignmask(v)
	case OpSlicemask:
		return rewriteValueMIPS_OpSlicemask(v)
	case OpSqrt:
		v.Op = OpMIPSSQRTD
		return true
	case OpSqrt32:
		v.Op = OpMIPSSQRTF
		return true
	case OpStaticCall:
		v.Op = OpMIPSCALLstatic
		return true
	case OpStore:
		return rewriteValueMIPS_OpStore(v)
	case OpSub16:
		v.Op = OpMIPSSUB
		return true
	case OpSub32:
		v.Op = OpMIPSSUB
		return true
	case OpSub32F:
		v.Op = OpMIPSSUBF
		return true
	case OpSub32withcarry:
		return rewriteValueMIPS_OpSub32withcarry(v)
	case OpSub64F:
		v.Op = OpMIPSSUBD
		return true
	case OpSub8:
		v.Op = OpMIPSSUB
		return true
	case OpSubPtr:
		v.Op = OpMIPSSUB
		return true
	case OpTailCall:
		v.Op = OpMIPSCALLtail
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
	case OpWB:
		v.Op = OpMIPSLoweredWB
		return true
	case OpXor16:
		v.Op = OpMIPSXOR
		return true
	case OpXor32:
		v.Op = OpMIPSXOR
		return true
	case OpXor8:
		v.Op = OpMIPSXOR
		return true
	case OpZero:
		return rewriteValueMIPS_OpZero(v)
	case OpZeroExt16to32:
		v.Op = OpMIPSMOVHUreg
		return true
	case OpZeroExt8to16:
		v.Op = OpMIPSMOVBUreg
		return true
	case OpZeroExt8to32:
		v.Op = OpMIPSMOVBUreg
		return true
	case OpZeromask:
		return rewriteValueMIPS_OpZeromask(v)
	}
	return false
}
func rewriteValueMIPS_OpAdd32withcarry(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Add32withcarry <t> x y c)
	// result: (ADD c (ADD <t> x y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		c := v_2
		v.reset(OpMIPSADD)
		v0 := b.NewValue0(v.Pos, OpMIPSADD, t)
		v0.AddArg2(x, y)
		v.AddArg2(c, v0)
		return true
	}
}
func rewriteValueMIPS_OpAddr(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Addr {sym} base)
	// result: (MOVWaddr {sym} base)
	for {
		sym := auxToSym(v.Aux)
		base := v_0
		v.reset(OpMIPSMOVWaddr)
		v.Aux = symToAux(sym)
		v.AddArg(base)
		return true
	}
}
func rewriteValueMIPS_OpAtomicAnd8(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (AtomicAnd8 ptr val mem)
	// cond: !config.BigEndian
	// result: (LoweredAtomicAnd (AND <typ.UInt32Ptr> (MOVWconst [^3]) ptr) (OR <typ.UInt32> (SLL <typ.UInt32> (ZeroExt8to32 val) (SLLconst <typ.UInt32> [3] (ANDconst <typ.UInt32> [3] ptr))) (NORconst [0] <typ.UInt32> (SLL <typ.UInt32> (MOVWconst [0xff]) (SLLconst <typ.UInt32> [3] (ANDconst <typ.UInt32> [3] ptr))))) mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		if !(!config.BigEndian) {
			break
		}
		v.reset(OpMIPSLoweredAtomicAnd)
		v0 := b.NewValue0(v.Pos, OpMIPSAND, typ.UInt32Ptr)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(^3)
		v0.AddArg2(v1, ptr)
		v2 := b.NewValue0(v.Pos, OpMIPSOR, typ.UInt32)
		v3 := b.NewValue0(v.Pos, OpMIPSSLL, typ.UInt32)
		v4 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v4.AddArg(val)
		v5 := b.NewValue0(v.Pos, OpMIPSSLLconst, typ.UInt32)
		v5.AuxInt = int32ToAuxInt(3)
		v6 := b.NewValue0(v.Pos, OpMIPSANDconst, typ.UInt32)
		v6.AuxInt = int32ToAuxInt(3)
		v6.AddArg(ptr)
		v5.AddArg(v6)
		v3.AddArg2(v4, v5)
		v7 := b.NewValue0(v.Pos, OpMIPSNORconst, typ.UInt32)
		v7.AuxInt = int32ToAuxInt(0)
		v8 := b.NewValue0(v.Pos, OpMIPSSLL, typ.UInt32)
		v9 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v9.AuxInt = int32ToAuxInt(0xff)
		v8.AddArg2(v9, v5)
		v7.AddArg(v8)
		v2.AddArg2(v3, v7)
		v.AddArg3(v0, v2, mem)
		return true
	}
	// match: (AtomicAnd8 ptr val mem)
	// cond: config.BigEndian
	// result: (LoweredAtomicAnd (AND <typ.UInt32Ptr> (MOVWconst [^3]) ptr) (OR <typ.UInt32> (SLL <typ.UInt32> (ZeroExt8to32 val) (SLLconst <typ.UInt32> [3] (ANDconst <typ.UInt32> [3] (XORconst <typ.UInt32> [3] ptr)))) (NORconst [0] <typ.UInt32> (SLL <typ.UInt32> (MOVWconst [0xff]) (SLLconst <typ.UInt32> [3] (ANDconst <typ.UInt32> [3] (XORconst <typ.UInt32> [3] ptr)))))) mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		if !(config.BigEndian) {
			break
		}
		v.reset(OpMIPSLoweredAtomicAnd)
		v0 := b.NewValue0(v.Pos, OpMIPSAND, typ.UInt32Ptr)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(^3)
		v0.AddArg2(v1, ptr)
		v2 := b.NewValue0(v.Pos, OpMIPSOR, typ.UInt32)
		v3 := b.NewValue0(v.Pos, OpMIPSSLL, typ.UInt32)
		v4 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v4.AddArg(val)
		v5 := b.NewValue0(v.Pos, OpMIPSSLLconst, typ.UInt32)
		v5.AuxInt = int32ToAuxInt(3)
		v6 := b.NewValue0(v.Pos, OpMIPSANDconst, typ.UInt32)
		v6.AuxInt = int32ToAuxInt(3)
		v7 := b.NewValue0(v.Pos, OpMIPSXORconst, typ.UInt32)
		v7.AuxInt = int32ToAuxInt(3)
		v7.AddArg(ptr)
		v6.AddArg(v7)
		v5.AddArg(v6)
		v3.AddArg2(v4, v5)
		v8 := b.NewValue0(v.Pos, OpMIPSNORconst, typ.UInt32)
		v8.AuxInt = int32ToAuxInt(0)
		v9 := b.NewValue0(v.Pos, OpMIPSSLL, typ.UInt32)
		v10 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v10.AuxInt = int32ToAuxInt(0xff)
		v9.AddArg2(v10, v5)
		v8.AddArg(v9)
		v2.AddArg2(v3, v8)
		v.AddArg3(v0, v2, mem)
		return true
	}
	return false
}
func rewriteValueMIPS_OpAtomicOr8(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (AtomicOr8 ptr val mem)
	// cond: !config.BigEndian
	// result: (LoweredAtomicOr (AND <typ.UInt32Ptr> (MOVWconst [^3]) ptr) (SLL <typ.UInt32> (ZeroExt8to32 val) (SLLconst <typ.UInt32> [3] (ANDconst <typ.UInt32> [3] ptr))) mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		if !(!config.BigEndian) {
			break
		}
		v.reset(OpMIPSLoweredAtomicOr)
		v0 := b.NewValue0(v.Pos, OpMIPSAND, typ.UInt32Ptr)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(^3)
		v0.AddArg2(v1, ptr)
		v2 := b.NewValue0(v.Pos, OpMIPSSLL, typ.UInt32)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v3.AddArg(val)
		v4 := b.NewValue0(v.Pos, OpMIPSSLLconst, typ.UInt32)
		v4.AuxInt = int32ToAuxInt(3)
		v5 := b.NewValue0(v.Pos, OpMIPSANDconst, typ.UInt32)
		v5.AuxInt = int32ToAuxInt(3)
		v5.AddArg(ptr)
		v4.AddArg(v5)
		v2.AddArg2(v3, v4)
		v.AddArg3(v0, v2, mem)
		return true
	}
	// match: (AtomicOr8 ptr val mem)
	// cond: config.BigEndian
	// result: (LoweredAtomicOr (AND <typ.UInt32Ptr> (MOVWconst [^3]) ptr) (SLL <typ.UInt32> (ZeroExt8to32 val) (SLLconst <typ.UInt32> [3] (ANDconst <typ.UInt32> [3] (XORconst <typ.UInt32> [3] ptr)))) mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		if !(config.BigEndian) {
			break
		}
		v.reset(OpMIPSLoweredAtomicOr)
		v0 := b.NewValue0(v.Pos, OpMIPSAND, typ.UInt32Ptr)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(^3)
		v0.AddArg2(v1, ptr)
		v2 := b.NewValue0(v.Pos, OpMIPSSLL, typ.UInt32)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v3.AddArg(val)
		v4 := b.NewValue0(v.Pos, OpMIPSSLLconst, typ.UInt32)
		v4.AuxInt = int32ToAuxInt(3)
		v5 := b.NewValue0(v.Pos, OpMIPSANDconst, typ.UInt32)
		v5.AuxInt = int32ToAuxInt(3)
		v6 := b.NewValue0(v.Pos, OpMIPSXORconst, typ.UInt32)
		v6.AuxInt = int32ToAuxInt(3)
		v6.AddArg(ptr)
		v5.AddArg(v6)
		v4.AddArg(v5)
		v2.AddArg2(v3, v4)
		v.AddArg3(v0, v2, mem)
		return true
	}
	return false
}
func rewriteValueMIPS_OpAvg32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Avg32u <t> x y)
	// result: (ADD (SRLconst <t> (SUB <t> x y) [1]) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPSADD)
		v0 := b.NewValue0(v.Pos, OpMIPSSRLconst, t)
		v0.AuxInt = int32ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpMIPSSUB, t)
		v1.AddArg2(x, y)
		v0.AddArg(v1)
		v.AddArg2(v0, y)
		return true
	}
}
func rewriteValueMIPS_OpBitLen32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (BitLen32 <t> x)
	// result: (SUB (MOVWconst [32]) (CLZ <t> x))
	for {
		t := v.Type
		x := v_0
		v.reset(OpMIPSSUB)
		v0 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(32)
		v1 := b.NewValue0(v.Pos, OpMIPSCLZ, t)
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS_OpCom16(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Com16 x)
	// result: (NORconst [0] x)
	for {
		x := v_0
		v.reset(OpMIPSNORconst)
		v.AuxInt = int32ToAuxInt(0)
		v.AddArg(x)
		return true
	}
}
func rewriteValueMIPS_OpCom32(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Com32 x)
	// result: (NORconst [0] x)
	for {
		x := v_0
		v.reset(OpMIPSNORconst)
		v.AuxInt = int32ToAuxInt(0)
		v.AddArg(x)
		return true
	}
}
func rewriteValueMIPS_OpCom8(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Com8 x)
	// result: (NORconst [0] x)
	for {
		x := v_0
		v.reset(OpMIPSNORconst)
		v.AuxInt = int32ToAuxInt(0)
		v.AddArg(x)
		return true
	}
}
func rewriteValueMIPS_OpConst16(v *Value) bool {
	// match: (Const16 [val])
	// result: (MOVWconst [int32(val)])
	for {
		val := auxIntToInt16(v.AuxInt)
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(int32(val))
		return true
	}
}
func rewriteValueMIPS_OpConst32(v *Value) bool {
	// match: (Const32 [val])
	// result: (MOVWconst [int32(val)])
	for {
		val := auxIntToInt32(v.AuxInt)
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(int32(val))
		return true
	}
}
func rewriteValueMIPS_OpConst8(v *Value) bool {
	// match: (Const8 [val])
	// result: (MOVWconst [int32(val)])
	for {
		val := auxIntToInt8(v.AuxInt)
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(int32(val))
		return true
	}
}
func rewriteValueMIPS_OpConstBool(v *Value) bool {
	// match: (ConstBool [t])
	// result: (MOVWconst [b2i32(t)])
	for {
		t := auxIntToBool(v.AuxInt)
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(b2i32(t))
		return true
	}
}
func rewriteValueMIPS_OpConstNil(v *Value) bool {
	// match: (ConstNil)
	// result: (MOVWconst [0])
	for {
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
}
func rewriteValueMIPS_OpCtz32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz32 <t> x)
	// result: (SUB (MOVWconst [32]) (CLZ <t> (SUBconst <t> [1] (AND <t> x (NEG <t> x)))))
	for {
		t := v.Type
		x := v_0
		v.reset(OpMIPSSUB)
		v0 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(32)
		v1 := b.NewValue0(v.Pos, OpMIPSCLZ, t)
		v2 := b.NewValue0(v.Pos, OpMIPSSUBconst, t)
		v2.AuxInt = int32ToAuxInt(1)
		v3 := b.NewValue0(v.Pos, OpMIPSAND, t)
		v4 := b.NewValue0(v.Pos, OpMIPSNEG, t)
		v4.AddArg(x)
		v3.AddArg2(x, v4)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS_OpDiv16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div16 x y)
	// result: (Select1 (DIV (SignExt16to32 x) (SignExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect1)
		v0 := b.NewValue0(v.Pos, OpMIPSDIV, types.NewTuple(typ.Int32, typ.Int32))
		v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpDiv16u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div16u x y)
	// result: (Select1 (DIVU (ZeroExt16to32 x) (ZeroExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect1)
		v0 := b.NewValue0(v.Pos, OpMIPSDIVU, types.NewTuple(typ.UInt32, typ.UInt32))
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpDiv32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div32 x y)
	// result: (Select1 (DIV x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect1)
		v0 := b.NewValue0(v.Pos, OpMIPSDIV, types.NewTuple(typ.Int32, typ.Int32))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpDiv32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div32u x y)
	// result: (Select1 (DIVU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect1)
		v0 := b.NewValue0(v.Pos, OpMIPSDIVU, types.NewTuple(typ.UInt32, typ.UInt32))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpDiv8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8 x y)
	// result: (Select1 (DIV (SignExt8to32 x) (SignExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect1)
		v0 := b.NewValue0(v.Pos, OpMIPSDIV, types.NewTuple(typ.Int32, typ.Int32))
		v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpDiv8u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8u x y)
	// result: (Select1 (DIVU (ZeroExt8to32 x) (ZeroExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect1)
		v0 := b.NewValue0(v.Pos, OpMIPSDIVU, types.NewTuple(typ.UInt32, typ.UInt32))
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpEq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq16 x y)
	// result: (SGTUconst [1] (XOR (ZeroExt16to32 x) (ZeroExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSSGTUconst)
		v.AuxInt = int32ToAuxInt(1)
		v0 := b.NewValue0(v.Pos, OpMIPSXOR, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpEq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq32 x y)
	// result: (SGTUconst [1] (XOR x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSSGTUconst)
		v.AuxInt = int32ToAuxInt(1)
		v0 := b.NewValue0(v.Pos, OpMIPSXOR, typ.UInt32)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpEq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq32F x y)
	// result: (FPFlagTrue (CMPEQF x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSFPFlagTrue)
		v0 := b.NewValue0(v.Pos, OpMIPSCMPEQF, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpEq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq64F x y)
	// result: (FPFlagTrue (CMPEQD x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSFPFlagTrue)
		v0 := b.NewValue0(v.Pos, OpMIPSCMPEQD, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpEq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq8 x y)
	// result: (SGTUconst [1] (XOR (ZeroExt8to32 x) (ZeroExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSSGTUconst)
		v.AuxInt = int32ToAuxInt(1)
		v0 := b.NewValue0(v.Pos, OpMIPSXOR, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpEqB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (EqB x y)
	// result: (XORconst [1] (XOR <typ.Bool> x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSXORconst)
		v.AuxInt = int32ToAuxInt(1)
		v0 := b.NewValue0(v.Pos, OpMIPSXOR, typ.Bool)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpEqPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (EqPtr x y)
	// result: (SGTUconst [1] (XOR x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSSGTUconst)
		v.AuxInt = int32ToAuxInt(1)
		v0 := b.NewValue0(v.Pos, OpMIPSXOR, typ.UInt32)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpHmul32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Hmul32 x y)
	// result: (Select0 (MULT x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpMIPSMULT, types.NewTuple(typ.Int32, typ.Int32))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpHmul32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Hmul32u x y)
	// result: (Select0 (MULTU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpMIPSMULTU, types.NewTuple(typ.UInt32, typ.UInt32))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpIsInBounds(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (IsInBounds idx len)
	// result: (SGTU len idx)
	for {
		idx := v_0
		len := v_1
		v.reset(OpMIPSSGTU)
		v.AddArg2(len, idx)
		return true
	}
}
func rewriteValueMIPS_OpIsNonNil(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (IsNonNil ptr)
	// result: (SGTU ptr (MOVWconst [0]))
	for {
		ptr := v_0
		v.reset(OpMIPSSGTU)
		v0 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg2(ptr, v0)
		return true
	}
}
func rewriteValueMIPS_OpIsSliceInBounds(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (IsSliceInBounds idx len)
	// result: (XORconst [1] (SGTU idx len))
	for {
		idx := v_0
		len := v_1
		v.reset(OpMIPSXORconst)
		v.AuxInt = int32ToAuxInt(1)
		v0 := b.NewValue0(v.Pos, OpMIPSSGTU, typ.Bool)
		v0.AddArg2(idx, len)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpLeq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq16 x y)
	// result: (XORconst [1] (SGT (SignExt16to32 x) (SignExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSXORconst)
		v.AuxInt = int32ToAuxInt(1)
		v0 := b.NewValue0(v.Pos, OpMIPSSGT, typ.Bool)
		v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpLeq16U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq16U x y)
	// result: (XORconst [1] (SGTU (ZeroExt16to32 x) (ZeroExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSXORconst)
		v.AuxInt = int32ToAuxInt(1)
		v0 := b.NewValue0(v.Pos, OpMIPSSGTU, typ.Bool)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpLeq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq32 x y)
	// result: (XORconst [1] (SGT x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSXORconst)
		v.AuxInt = int32ToAuxInt(1)
		v0 := b.NewValue0(v.Pos, OpMIPSSGT, typ.Bool)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpLeq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq32F x y)
	// result: (FPFlagTrue (CMPGEF y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSFPFlagTrue)
		v0 := b.NewValue0(v.Pos, OpMIPSCMPGEF, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpLeq32U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq32U x y)
	// result: (XORconst [1] (SGTU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSXORconst)
		v.AuxInt = int32ToAuxInt(1)
		v0 := b.NewValue0(v.Pos, OpMIPSSGTU, typ.Bool)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpLeq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq64F x y)
	// result: (FPFlagTrue (CMPGED y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSFPFlagTrue)
		v0 := b.NewValue0(v.Pos, OpMIPSCMPGED, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpLeq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq8 x y)
	// result: (XORconst [1] (SGT (SignExt8to32 x) (SignExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSXORconst)
		v.AuxInt = int32ToAuxInt(1)
		v0 := b.NewValue0(v.Pos, OpMIPSSGT, typ.Bool)
		v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpLeq8U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq8U x y)
	// result: (XORconst [1] (SGTU (ZeroExt8to32 x) (ZeroExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSXORconst)
		v.AuxInt = int32ToAuxInt(1)
		v0 := b.NewValue0(v.Pos, OpMIPSSGTU, typ.Bool)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpLess16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less16 x y)
	// result: (SGT (SignExt16to32 y) (SignExt16to32 x))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSSGT)
		v0 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v0.AddArg(y)
		v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS_OpLess16U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less16U x y)
	// result: (SGTU (ZeroExt16to32 y) (ZeroExt16to32 x))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSSGTU)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v0.AddArg(y)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS_OpLess32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Less32 x y)
	// result: (SGT y x)
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSSGT)
		v.AddArg2(y, x)
		return true
	}
}
func rewriteValueMIPS_OpLess32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less32F x y)
	// result: (FPFlagTrue (CMPGTF y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSFPFlagTrue)
		v0 := b.NewValue0(v.Pos, OpMIPSCMPGTF, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpLess32U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Less32U x y)
	// result: (SGTU y x)
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSSGTU)
		v.AddArg2(y, x)
		return true
	}
}
func rewriteValueMIPS_OpLess64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less64F x y)
	// result: (FPFlagTrue (CMPGTD y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSFPFlagTrue)
		v0 := b.NewValue0(v.Pos, OpMIPSCMPGTD, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS_OpLess8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less8 x y)
	// result: (SGT (SignExt8to32 y) (SignExt8to32 x))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSSGT)
		v0 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v0.AddArg(y)
		v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS_OpLess8U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less8U x y)
	// result: (SGTU (ZeroExt8to32 y) (ZeroExt8to32 x))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPSSGTU)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v0.AddArg(y)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS_OpLoad(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Load <t> ptr mem)
	// cond: t.IsBoolean()
	// result: (MOVBUload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(t.IsBoolean()) {
			break
		}
		v.reset(OpMIPSMOVBUload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is8BitInt(t) && t.IsSigned())
	// result: (MOVBload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is8BitInt(t) && t.IsSigned()) {
			break
		}
		v.reset(OpMIPSMOVBload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is8BitInt(t) && !t.IsSigned())
	// result: (MOVBUload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is8BitInt(t) && !t.IsSigned()) {
			break
		}
		v.reset(OpMIPSMOVBUload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is16BitInt(t) && t.IsSigned())
	// result: (MOVHload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is16BitInt(t) && t.IsSigned()) {
			break
		}
		v.reset(OpMIPSMOVHload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is16BitInt(t) && !t.IsSigned())
	// result: (MOVHUload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is16BitInt(t) && !t.IsSigned()) {
			break
		}
		v.reset(OpMIPSMOVHUload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is32BitInt(t) || isPtr(t))
	// result: (MOVWload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is32BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpMIPSMOVWload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: is32BitFloat(t)
	// result: (MOVFload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is32BitFloat(t)) {
			break
		}
		v.reset(OpMIPSMOVFload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: is64BitFloat(t)
	// result: (MOVDload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is64BitFloat(t)) {
			break
		}
		v.reset(OpMIPSMOVDload)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueMIPS_OpLocalAddr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (LocalAddr <t> {sym} base mem)
	// cond: t.Elem().HasPointers()
	// result: (MOVWaddr {sym} (SPanchored base mem))
	for {
		t := v.Type
		sym := auxToSym(v.Aux)
		base := v_0
		mem := v_1
		if !(t.Elem().HasPointers()) {
			break
		}
		v.reset(OpMIPSMOVWaddr)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpSPanchored, typ.Uintptr)
		v0.AddArg2(base, mem)
		v.AddArg(v0)
		return true
	}
	// match: (LocalAddr <t> {sym} base _)
	// cond: !t.Elem().HasPointers()
	// result: (MOVWaddr {sym} base)
	for {
		t := v.Type
		sym := auxToSym(v.Aux)
		base := v_0
		if !(!t.Elem().HasPointers()) {
			break
		}
		v.reset(OpMIPSMOVWaddr)
		v.Aux = symToAux(sym)
		v.AddArg(base)
		return true
	}
	return false
}
func rewriteValueMIPS_OpLsh16x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x16 <t> x y)
	// result: (CMOVZ (SLL <t> x (ZeroExt16to32 y) ) (MOVWconst [0]) (SGTUconst [32] (ZeroExt16to32 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPSCMOVZ)
		v0 := b.NewValue0(v.Pos, OpMIPSSLL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v2.AuxInt = int32ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpMIPSSGTUconst, typ.Bool)
		v3.AuxInt = int32ToAuxInt(32)
		v3.AddArg(v1)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValueMIPS_OpLsh16x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x32 <t> x y)
	// result: (CMOVZ (SLL <t> x y) (MOVWconst [0]) (SGTUconst [32] y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPSCMOVZ)
		v0 := b.NewValue0(v.Pos, OpMIPSSLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpMIPSSGTUconst, typ.Bool)
		v2.AuxInt = int32ToAuxInt(32)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueMIPS_OpLsh16x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Lsh16x64 x (Const64 [c]))
	// cond: uint32(c) < 16
	// result: (SLLconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint32(c) < 16) {
			break
		}
		v.reset(OpMIPSSLLconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (Lsh16x64 _ (Const64 [c]))
	// cond: uint32(c) >= 16
	// result: (MOVWconst [0])
	for {
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint32(c) >= 16) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueMIPS_OpLsh16x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x8 <t> x y)
	// result: (CMOVZ (SLL <t> x (ZeroExt8to32 y) ) (MOVWconst [0]) (SGTUconst [32] (ZeroExt8to32 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPSCMOVZ)
		v0 := b.NewValue0(v.Pos, OpMIPSSLL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v2.AuxInt = int32ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpMIPSSGTUconst, typ.Bool)
		v3.AuxInt = int32ToAuxInt(32)
		v3.AddArg(v1)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValueMIPS_OpLsh32x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x16 <t> x y)
	// result: (CMOVZ (SLL <t> x (ZeroExt16to32 y) ) (MOVWconst [0]) (SGTUconst [32] (ZeroExt16to32 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPSCMOVZ)
		v0 := b.NewValue0(v.Pos, OpMIPSSLL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v2.AuxInt = int32ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpMIPSSGTUconst, typ.Bool)
		v3.AuxInt = int32ToAuxInt(32)
		v3.AddArg(v1)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValueMIPS_OpLsh32x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x32 <t> x y)
	// result: (CMOVZ (SLL <t> x y) (MOVWconst [0]) (SGTUconst [32] y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPSCMOVZ)
		v0 := b.NewValue0(v.Pos, OpMIPSSLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpMIPSSGTUconst, typ.Bool)
		v2.AuxInt = int32ToAuxInt(32)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueMIPS_OpLsh32x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Lsh32x64 x (Const64 [c]))
	// cond: uint32(c) < 32
	// result: (SLLconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint32(c) < 32) {
			break
		}
		v.reset(OpMIPSSLLconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (Lsh32x64 _ (Const64 [c]))
	// cond: uint32(c) >= 32
	// result: (MOVWconst [0])
	for {
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint32(c) >= 32) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueMIPS_OpLsh32x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x8 <t> x y)
	// result: (CMOVZ (SLL <t> x (ZeroExt8to32 y) ) (MOVWconst [0]) (SGTUconst [32] (ZeroExt8to32 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPSCMOVZ)
		v0 := b.NewValue0(v.Pos, OpMIPSSLL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v2.AuxInt = int32ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpMIPSSGTUconst, typ.Bool)
		v3.AuxInt = int32ToAuxInt(32)
		v3.AddArg(v1)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValueMIPS_OpLsh8x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x16 <t> x y)
	// result: (CMOVZ (SLL <t> x (ZeroExt16to32 y) ) (MOVWconst [0]) (SGTUconst [32] (ZeroExt16to32 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPSCMOVZ)
		v0 := b.NewValue0(v.Pos, OpMIPSSLL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v2.AuxInt = int32ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpMIPSSGTUconst, typ.Bool)
		v3.AuxInt = int32ToAuxInt(32)
		v3.AddArg(v1)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValueMIPS_OpLsh8x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x32 <t> x y)
	// result: (CMOVZ (SLL <t> x y) (MOVWconst [0]) (SGTUconst [32] y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPSCMOVZ)
		v0 := b.NewValue0(v.Pos, OpMIPSSLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpMIPSSGTUconst, typ.Bool)
		v2.AuxInt = int32ToAuxInt(32)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueMIPS_OpLsh8x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Lsh8x64 x (Const64 [c]))
	// cond: uint32(c) < 8
	// result: (SLLconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint32(c) < 8) {
			break
		}
		v.reset(OpMIPSSLLconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (Lsh8x64 _ (Const64 [c]))
	// cond: uint32(c) >= 8
	// result: (MOVWconst [0])
	for {
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint32(c) >= 8) {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueMIPS_OpLsh8x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x8 <t> x y)
	// result: (CMOVZ (SLL <t> x (ZeroExt8to32 y) ) (MOVWconst [0]) (SGTUconst [32] (ZeroExt8to32 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPSCMOVZ)
		v0 := b.NewValue0(v.Pos, OpMIPSSLL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v2.AuxInt = int32ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpMIPSSGTUconst, typ.Bool)
		v3.AuxInt = int32ToAuxInt(32)
		v3.AddArg(v1)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValueMIPS_OpMIPSADD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADD x (MOVWconst <t> [c]))
	// cond: !t.IsPtr()
	// result: (ADDconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpMIPSMOVWconst {
				continue
			}
			t := v_1.Type
			c := auxIntToInt32(v_1.AuxInt)
			if !(!t.IsPtr()) {
				continue
			}
			v.reset(OpMIPSADDconst)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (ADD x (NEG y))
	// result: (SUB x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpMIPSNEG {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpMIPSSUB)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	return false
}
func rewriteValueMIPS_OpMIPSADDconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ADDconst [off1] (MOVWaddr [off2] {sym} ptr))
	// result: (MOVWaddr [off1+off2] {sym} ptr)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSMOVWaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		v.reset(OpMIPSMOVWaddr)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg(ptr)
		return true
	}
	// match: (ADDconst [0] x)
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (ADDconst [c] (MOVWconst [d]))
	// result: (MOVWconst [int32(c+d)])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSMOVWconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(int32(c + d))
		return true
	}
	// match: (ADDconst [c] (ADDconst [d] x))
	// result: (ADDconst [c+d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSADDconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpMIPSADDconst)
		v.AuxInt = int32ToAuxInt(c + d)
		v.AddArg(x)
		return true
	}
	// match: (ADDconst [c] (SUBconst [d] x))
	// result: (ADDconst [c-d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSSUBconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpMIPSADDconst)
		v.AuxInt = int32ToAuxInt(c - d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueMIPS_OpMIPSAND(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (AND x (MOVWconst [c]))
	// result: (ANDconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpMIPSMOVWconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			v.reset(OpMIPSANDconst)
			v.AuxInt = int32ToAuxInt(c)
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
	// match: (AND (SGTUconst [1] x) (SGTUconst [1] y))
	// result: (SGTUconst [1] (OR <x.Type> x y))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpMIPSSGTUconst || auxIntToInt32(v_0.AuxInt) != 1 {
				continue
			}
			x := v_0.Args[0]
			if v_1.Op != OpMIPSSGTUconst || auxIntToInt32(v_1.AuxInt) != 1 {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpMIPSSGTUconst)
			v.AuxInt = int32ToAuxInt(1)
			v0 := b.NewValue0(v.Pos, OpMIPSOR, x.Type)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	return false
}
func rewriteValueMIPS_OpMIPSANDconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ANDconst [0] _)
	// result: (MOVWconst [0])
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (ANDconst [-1] x)
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != -1 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (ANDconst [c] (MOVWconst [d]))
	// result: (MOVWconst [c&d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSMOVWconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(c & d)
		return true
	}
	// match: (ANDconst [c] (ANDconst [d] x))
	// result: (ANDconst [c&d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpMIPSANDconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpMIPSANDconst)
		v.AuxInt = int32ToAuxInt(c & d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueMIPS_OpMIPSCMOVZ(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVZ _ f (MOVWconst [0]))
	// result: f
	for {
		f := v_1
		if v_2.Op != OpMIPSMOVWconst || auxIntToInt32(v_2.AuxInt) != 0 {
			break
		}
		v.copyOf(f)
		return true
	}
	// match: (CMOVZ a _ (MOVWconst [c]))
	// cond: c!=0
	// result: a
	for {
		a := v_0
		if v_2.Op != OpMIPSMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(c != 0) {
			break
		}
		v.copyOf(a)
		return true
	}
	// match: (CMOVZ a (MOVWconst [0]) c)
	// result: (CMOVZzero a c)
	for {
		a := v_0
		if v_1.Op != OpMIPSMOVWconst || auxIntToInt32(v_1.AuxInt) != 0 {
			break
		}
		c := v_2
		v.reset(OpMIPSCMOVZzero)
		v.AddArg2(a, c)
		return true
	}
	return false
}
func rewriteValueMIPS_OpMIPSCMOVZzero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVZzero _ (MOVWconst [0]))
	// result: (MOVWconst [0])
	for {
		if v_1.Op != OpMIPSMOVWconst || auxIntToInt32(v_1.AuxInt) != 0 {
			break
		}
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (CMOVZzero a (MOVWconst [c]))
	// cond: c!=0
	// result: a
	for {
		a := v_0
		if v_1.Op != OpMIPSMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(c != 0) {
			break
		}
		v.copyOf(a)
		return true
	}
	return false
}
func rewriteValueMIPS_OpMIPSLoweredAtomicAdd(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (LoweredAtomicAdd ptr (MOVWconst [c]) mem)
	// cond: is16Bit(int64(c))
	// result: (LoweredAtomicAddconst [c] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpMIPSMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		mem := v_2
		if !(is16Bit(int64(c))) {
			break
		}
		v.reset(OpMIPSLoweredAtomicAddconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueMIPS_OpMIPSLoweredAtomicStore32(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (LoweredAtomicStore32 ptr (MOVWconst [0]) mem)
	// result: (LoweredAtomicStorezero ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpMIPSMOVWconst || auxIntToInt32(v_1.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.reset(OpMIPSLoweredAtomicStorezero)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueMIPS_OpMIPSMOVBUload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBUload [off1] {sym} x:(ADDconst [off2] ptr) mem)
	// cond: (is16Bit(int64(off1+off2)) || x.Uses == 1)
	// result: (MOVBUload [off1+off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		if x.Op != OpMIPSADDconst {
			break
		}
		off2 := auxIntToInt32(x.AuxInt)
		ptr := x.Args[0]
		mem := v_1
		if !(is16Bit(int64(off1+off2)) || x.Uses == 1) {
			break
		}
		v.reset(OpMIPSMOVBUload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBUload [off1] {sym1} (MOVWaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2)
	// result: (MOVBUload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpMIPSMOVWaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpMIPSMOVBUload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBUload [off] {sym} ptr (MOVBstore [off2] {sym2} ptr2 x _))
	// cond: sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)
	// result: (MOVBUreg x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpMIPSMOVBstore {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		x := v_1.Args[1]
		ptr2 := v_1.Args[0]
		if !(sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)) {
			break
		}
		v.reset(OpMIPSMOVBUreg)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueMIPS_OpMIPSMOVBUreg(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (MOVBUreg x:(MOVBUload _ _))
	// result: (MOVWreg x)
	for {
		x := v_0
		if x.Op != OpMIPSMOVBUload {
			break
		}
		v.reset(OpMIPSMOVWreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBUreg x:(MOVBUreg _))
	// result: (MOVWreg x)
	for {
		x := v_0
		if x.Op != OpMIPSMOVBUreg {
			break
		}
		v.reset(OpMIPSMOVWreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBUreg <t> x:(MOVBload [off] {sym} ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVBUload <t> [off] {sym} ptr mem)
	for {
		t := v.Type
		x := v_0
		if x.Op != OpMIPSMOVBload {
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
		v0 := b.NewValue0(x.Pos, OpMIPSMOVBUload, t)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBUreg (ANDconst [c] x))
	// result: (ANDconst [c&0xff] x)
	for {
		if v_0.Op != OpMIPSANDconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpMIPSANDconst)
		v.AuxInt = int32ToAuxInt(c & 0xff)
		v.AddArg(x)
		return true
	}
	// match: (MOVBUreg (MOVWconst [c]))
	// result: (MOVWconst [int32(uint8(c))])
	for {
		if v_0.Op != OpMIPSMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(int32(uint8(c)))
		return true
	}
	return false
}
func rewriteValueMIPS_OpMIPSMOVBload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBload [off1] {sym} x:(ADDconst [off2] ptr) mem)
	// cond: (is16Bit(int64(off1+off2)) || x.Uses == 1)
	// result: (MOVBload [off1+off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		if x.Op != OpMIPSADDconst {
			break
		}
		off2 := auxIntToInt32(x.AuxInt)
		ptr := x.Args[0]
		mem := v_1
		if !(is16Bit(int64(off1+off2)) || x.Uses == 1) {
			break
		}
		v.reset(OpMIPSMOVBload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBload [off1] {sym1} (MOVWaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2)
	// result: (MOVBload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpMIPSMOVWaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpMIPSMOVBload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBload [off] {sym} ptr (MOVBstore [off2] {sym2} ptr2 x _))
	// cond: sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)
	// result: (MOVBreg x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpMIPSMOVBstore {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		x := v_1.Args[1]
		ptr2 := v_1.Args[0]
		if !(sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)) {
			break
		}
		v.reset(OpMIPSMOVBreg)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueMIPS_OpMIPSMOVBreg(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (MOVBreg x:(MOVBload _ _))
	// result: (MOVWreg x)
	for {
		x := v_0
		if x.Op != OpMIPSMOVBload {
			break
		}
		v.reset(OpMIPSMOVWreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg x:(MOVBreg _))
	// result: (MOVWreg x)
	for {
		x := v_0
		if x.Op != OpMIPSMOVBreg {
			break
		}
		v.reset(OpMIPSMOVWreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg <t> x:(MOVBUload [off] {sym} ptr mem))
	// cond: x.Uses == 1 && clobber(x)
	// result: @x.Block (MOVBload <t> [off] {sym} ptr mem)
	for {
		t := v.Type
		x := v_0
		if x.Op != OpMIPSMOVBUload {
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
		v0 := b.NewValue0(x.Pos, OpMIPSMOVBload, t)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBreg (ANDconst [c] x))
	// cond: c & 0x80 == 0
	// result: (ANDconst [c&0x7f] x)
	for {
		if v_0.Op != OpMIPSANDconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c&0x80 == 0) {
			break
		}
		v.reset(OpMIPSANDconst)
		v.AuxInt = int32ToAuxInt(c & 0x7f)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg (MOVWconst [c]))
	// result: (MOVWconst [int32(int8(c))])
	for {
		if v_0.Op != OpMIPSMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpMIPSMOVWconst)
		v.AuxInt = int32ToAuxInt(int32(int8(c)))
		return true
	}
	return false
}
func rewriteValueMIPS_OpMIPSMOVBstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBstore [off1] {sym} x:(ADDconst [off2] ptr) val mem)
	// cond: (is16Bit(int64(off1+off2)) || x.Uses == 1)
	// result: (MOVBstore [off1+off2] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		if x.Op != OpMIPSADDconst {
			break
		}
		off2 := auxIntToInt32(x.AuxInt)
		ptr := x.Args[0]
		val := v_1
		mem := v_2
		if !(is16Bit(int64(off1+off2)) || x.Uses == 1) {
			break
		}
		v.reset(OpMIPSMOVBstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVBstore [off1] {sym1} (MOVWaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2)
	// result: (MOVBstore [off1+off2] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpMIPSMOVWaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpMIPSMOVBstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVWconst [0]) mem)
	// result: (MOVBstorezero [off] {sym} ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpMIPSMOVWconst || auxIntToInt32(v_1.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.reset(OpMIPSMOVBstorezero)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVBreg x) mem)
	// result: (MOVBstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpMIPSMOVBreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpMIPSMOVBstore)
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
		if v_1.Op != OpMIPSMOVBUreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpMIPSMOVBstore)
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
		if v_1.Op != OpMIPSMOVHreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpMIPSMOVBstore)
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
		if v_1.Op != OpMIPSMOVHUreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpMIPSMOVBstore)
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
		if v_1.Op != OpMIPSMOVWreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpMIPSMOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	return false
}
func rewriteValueMIPS_OpMIPSMOVBstorezero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBstorezero [off1] {sym} x
"""




```