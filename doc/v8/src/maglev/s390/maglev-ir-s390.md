Response: Let's break down the thought process for summarizing this C++ code and relating it to JavaScript.

1. **Understand the Goal:** The request asks for the functionality of the C++ code and its relationship to JavaScript, including a JavaScript example. This means we need to identify what the C++ code *does* and how that relates to what a JavaScript engine needs to execute.

2. **Identify the File's Context:** The file path `v8/src/maglev/s390/maglev-ir-s390.cc` is crucial.
    * `v8`: This immediately tells us it's part of the V8 JavaScript engine.
    * `src`:  Indicates source code.
    * `maglev`: This is the name of a specific component within V8. Knowing about Maglev (or doing a quick search) reveals it's an *intermediate representation (IR)* and *compiler* within V8. This is a key piece of information.
    * `s390`:  Specifies the target architecture – IBM System z. While important for the *how*, it's less critical for the *what* at a high level.
    * `maglev-ir-s390.cc`:  This strongly suggests that the file defines the instruction set (or a subset of it) for the Maglev IR, specifically tailored for the s390 architecture.

3. **Scan the Includes:** The `#include` directives provide clues about dependencies and the overall purpose:
    * `"src/base/logging.h"`: Likely for debugging/logging.
    * `"src/codegen/s390/assembler-s390.h"`, `"src/codegen/s390/register-s390.h"`: This confirms the s390 architecture and indicates interaction with the assembler (low-level code generation).
    * `"src/maglev/maglev-assembler-inl.h"`, `"src/maglev/maglev-graph-processor.h"`, `"src/maglev/maglev-graph.h"`, `"src/maglev/maglev-ir-inl.h"`, `"src/maglev/maglev-ir.h"`:  These are internal Maglev components, further reinforcing the IR and compiler focus.
    * `"src/maglev/s390/maglev-assembler-s390-inl.h"`:  s390-specific Maglev assembler.

4. **Analyze the Code Structure:** The code is organized into a namespace `v8::internal::maglev`. It defines several classes, each seemingly representing an operation: `Int32NegateWithOverflow`, `Int32AbsWithOverflow`, `BuiltinStringFromCharCode`, `Int32AddWithOverflow`, `Float64Add`, `Return`, etc.

5. **Focus on Key Methods:**  Within each class, the `GenerateCode` method is prominent. This strongly suggests that these classes are responsible for generating the low-level machine code for the corresponding operations. The `SetValueLocationConstraints` method likely deals with register allocation and operand placement.

6. **Infer Individual Node Functionality:**  By looking at the operations and the generated assembly code snippets within `GenerateCode`, we can deduce what each node does:
    * `Int32...WithOverflow`: Integer arithmetic operations with overflow checks.
    * `BuiltinStringFromCharCode`: Creating a string from a character code.
    * `ArgumentsLength`, `RestLength`: Accessing function arguments.
    * `Float64...`: Floating-point arithmetic.
    * `LoadTypedArrayLength`, `CheckJSDataViewBounds`: Operations related to typed arrays and data views.
    * `Return`:  Handles function returns.
    * `ReduceInterruptBudgetForLoop`, `ReduceInterruptBudgetForReturn`:  Mechanisms for managing execution budget and handling interrupts (related to long-running loops and tiering).

7. **Connect to JavaScript:** Now, the crucial step: how do these C++ operations relate to JavaScript?  Think about common JavaScript operations that involve these concepts:
    * Integer arithmetic (`+`, `-`, `*`, `/`, `%`, bitwise operators).
    * String creation (`String.fromCharCode()`).
    * Accessing function arguments (`arguments`, rest parameters).
    * Floating-point arithmetic.
    * Typed arrays (`Uint8Array`, `Float64Array`, etc.).
    * Function calls and returns.
    * Optimization and handling of long-running scripts (interrupts/tiering).

8. **Formulate the Summary:**  Based on the above analysis, we can start drafting the summary: This file defines part of the Maglev IR for the s390 architecture. It provides the implementation for various operations...

9. **Construct the JavaScript Examples:** For each key category of C++ operations, create corresponding JavaScript examples that would likely trigger those operations in the V8 engine. This requires some understanding of how V8 compiles and executes JavaScript. For instance, simple integer arithmetic will likely use the `Int32...` operations, `String.fromCharCode` will use `BuiltinStringFromCharCode`, and so on.

10. **Refine and Organize:**  Review the summary and examples for clarity, accuracy, and completeness. Ensure the language is accessible and explains the connection between the C++ code and JavaScript concepts effectively. Organize the information logically (e.g., group related operations together).

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe this is just about low-level assembly instructions.
* **Correction:**  The presence of `Maglev` in the path and class names indicates it's a higher-level IR, not just raw assembly. The `GenerateCode` methods produce assembly, but the classes represent more abstract operations.
* **Initial thought:**  Focus heavily on the s390-specific instructions.
* **Correction:** While the s390 details are there, the core *functionality* is more about the *type* of operation (integer math, string creation, etc.). The s390 instructions are the *implementation* detail for that architecture. The JavaScript relationship is at the higher, operation level.
* **Consideration:** Should I include all the nodes?
* **Decision:**  Focus on a representative set of nodes that illustrate the key functionalities and their JavaScript counterparts. Listing every single node might be too verbose. Mentioning the pattern of "defining Maglev IR nodes" covers the rest.

By following these steps, iteratively analyzing the code, and relating it to JavaScript concepts, we arrive at a comprehensive and accurate summary like the example provided.
这个C++源代码文件 `v8/src/maglev/s390/maglev-ir-s390.cc` 是V8 JavaScript 引擎中 **Maglev** 优化编译器针对 **s390** 架构的 **中间表示 (IR)** 的一部分实现。

**功能归纳:**

1. **定义 Maglev IR 指令的具体代码生成逻辑:**  该文件为 Maglev IR 中定义的各种操作（节点）提供了在 s390 架构上的代码生成实现。每个操作都对应一个 C++ 类，例如 `Int32NegateWithOverflow`，`BuiltinStringFromCharCode`，`Float64Add`，`Return` 等。

2. **处理不同数据类型的操作:**  文件中包含了针对不同数据类型（例如 32 位整数、64 位浮点数）的操作实现，包括算术运算、位运算、类型转换等。

3. **处理与 JavaScript 语义相关的操作:**  实现了一些直接对应 JavaScript 语义的操作，例如 `BuiltinStringFromCharCode` (对应 `String.fromCharCode`)，`ArgumentsLength` (对应访问 `arguments.length`)，以及与类型化数组和 DataView 相关的操作。

4. **处理控制流操作:**  包含了 `Return` 节点的代码生成逻辑，负责生成函数返回的代码。

5. **处理优化相关的操作:**  例如 `ReduceInterruptBudgetForLoop` 和 `ReduceInterruptBudgetForReturn` 节点，用于在循环和函数返回时减少中断预算，这与 V8 的分层编译和优化机制有关。

6. **处理溢出和边界检查:**  一些操作（例如 `Int32NegateWithOverflow`，`Int32AddWithOverflow`）包含了溢出检查，并在发生溢出时触发反优化 (deoptimization)。`CheckJSDataViewBounds` 则负责检查 DataView 的访问是否越界。

7. **利用 s390 汇编指令:**  在 `GenerateCode` 方法中，使用了 s390 架构的汇编指令（通过 `MaglevAssembler` 类提供）来实现 IR 节点的具体功能。

**与 JavaScript 的关系及 JavaScript 示例:**

这个文件是 V8 引擎将 JavaScript 代码编译成高效机器码的关键部分。Maglev 编译器会将 JavaScript 代码转换成 Maglev IR，然后 `maglev-ir-s390.cc` 中的代码负责将这些 IR 指令翻译成可以在 s390 架构上执行的机器码。

下面是一些例子，说明了 `maglev-ir-s390.cc` 中定义的某些操作与 JavaScript 功能的对应关系：

**1. `Int32NegateWithOverflow` (带溢出检查的 32 位整数取反):**

```javascript
function negate(x) {
  return -x;
}

// 当 x 为 -2147483648 时，取反会发生溢出
console.log(negate(10));   // 输出 -10
console.log(negate(-2147483648)); // 可能触发反优化，因为结果超出 32 位有符号整数范围
```

**2. `BuiltinStringFromCharCode` (从字符编码创建字符串):**

```javascript
function fromCharCode(code) {
  return String.fromCharCode(code);
}

console.log(fromCharCode(65)); // 输出 "A"
console.log(fromCharCode(0x1F600)); // 输出 "😀"
```

**3. `Float64Add` (64 位浮点数加法):**

```javascript
function addFloats(a, b) {
  return a + b;
}

console.log(addFloats(1.5, 2.5)); // 输出 4
console.log(addFloats(0.1, 0.2)); // 输出 0.30000000000000004 (浮点数精度问题)
```

**4. `ArgumentsLength` (获取函数参数个数):**

```javascript
function myFunction(a, b, c) {
  console.log(arguments.length);
}

myFunction(1, 2); // 输出 2
myFunction(1, 2, 3, 4); // 输出 4
```

**5. `Return` (函数返回):**

```javascript
function add(x, y) {
  return x + y;
}

let result = add(5, 3);
console.log(result); // 输出 8
```

**总结:**

`v8/src/maglev/s390/maglev-ir-s390.cc` 是 Maglev 编译器在 s390 架构上生成高效 JavaScript 执行代码的关键组成部分。它将高级的 Maglev IR 指令转换为底层的机器码，使得 JavaScript 代码可以在 s390 平台上快速运行。 文件中定义的各种操作都直接或间接地对应着 JavaScript 语言的特性和语义。

### 提示词
```
这是目录为v8/src/maglev/s390/maglev-ir-s390.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/logging.h"
#include "src/codegen/s390/assembler-s390.h"
#include "src/codegen/s390/register-s390.h"
#include "src/maglev/maglev-assembler-inl.h"
#include "src/maglev/maglev-graph-processor.h"
#include "src/maglev/maglev-graph.h"
#include "src/maglev/maglev-ir-inl.h"
#include "src/maglev/maglev-ir.h"
#include "src/maglev/s390/maglev-assembler-s390-inl.h"

namespace v8 {
namespace internal {
namespace maglev {

#define __ masm->

void Int32NegateWithOverflow::SetValueLocationConstraints() {
  UseRegister(value_input());
  DefineAsRegister(this);
}

void Int32NegateWithOverflow::GenerateCode(MaglevAssembler* masm,
                                           const ProcessingState& state) {
  Register value = ToRegister(value_input());
  Register out = ToRegister(result());

  // Deopt when result would be -0.
  __ CmpS32(value, Operand(0));
  __ EmitEagerDeoptIf(eq, DeoptimizeReason::kOverflow, this);

  __ lcr(out, value);
  __ LoadS32(out, out);

  // Output register must not be a register input into the eager deopt info.
  DCHECK_REGLIST_EMPTY(RegList{out} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
  __ EmitEagerDeoptIf(overflow, DeoptimizeReason::kOverflow, this);
}

void Int32AbsWithOverflow::GenerateCode(MaglevAssembler* masm,
                                        const ProcessingState& state) {
  Register out = ToRegister(result());
  __ lpr(out, out);
  // Output register must not be a register input into the eager deopt info.
  DCHECK_REGLIST_EMPTY(RegList{out} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
  __ EmitEagerDeoptIf(overflow, DeoptimizeReason::kOverflow, this);
  __ lgfr(out, out);
}

void Int32IncrementWithOverflow::SetValueLocationConstraints() {
  UseRegister(value_input());
  DefineAsRegister(this);
}

void Int32IncrementWithOverflow::GenerateCode(MaglevAssembler* masm,
                                              const ProcessingState& state) {
  Register value = ToRegister(value_input());
  Register out = ToRegister(result());
  __ AddS32(out, value, Operand(1));
  __ LoadS32(out, out);

  // Output register must not be a register input into the eager deopt info.
  DCHECK_REGLIST_EMPTY(RegList{out} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
  __ EmitEagerDeoptIf(overflow, DeoptimizeReason::kOverflow, this);
}

void Int32DecrementWithOverflow::SetValueLocationConstraints() {
  UseRegister(value_input());
  DefineAsRegister(this);
}

void Int32DecrementWithOverflow::GenerateCode(MaglevAssembler* masm,
                                              const ProcessingState& state) {
  Register value = ToRegister(value_input());
  Register out = ToRegister(result());
  __ AddS32(out, value, Operand(-1));
  __ LoadS32(out, out);

  // Output register must not be a register input into the eager deopt info.
  DCHECK_REGLIST_EMPTY(RegList{out} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
  __ EmitEagerDeoptIf(overflow, DeoptimizeReason::kOverflow, this);
}

int BuiltinStringFromCharCode::MaxCallStackArgs() const {
  return AllocateDescriptor::GetStackParameterCount();
}
void BuiltinStringFromCharCode::SetValueLocationConstraints() {
  if (code_input().node()->Is<Int32Constant>()) {
    UseAny(code_input());
  } else {
    UseAndClobberRegister(code_input());
  }
  set_temporaries_needed(1);
  DefineAsRegister(this);
}
void BuiltinStringFromCharCode::GenerateCode(MaglevAssembler* masm,
                                             const ProcessingState& state) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.AcquireScratch();
  Register result_string = ToRegister(result());
  if (Int32Constant* constant = code_input().node()->TryCast<Int32Constant>()) {
    int32_t char_code = constant->value() & 0xFFFF;
    if (0 <= char_code && char_code < String::kMaxOneByteCharCode) {
      __ LoadSingleCharacterString(result_string, char_code);
    } else {
      // Ensure that {result_string} never aliases {scratch}, otherwise the
      // store will fail.
      bool reallocate_result = (scratch == result_string);
      if (reallocate_result) {
        result_string = temps.AcquireScratch();
      }
      DCHECK(scratch != result_string);
      __ AllocateTwoByteString(register_snapshot(), result_string, 1);
      __ Move(scratch, char_code);
      __ StoreU16(scratch,
                  FieldMemOperand(result_string,
                                  OFFSET_OF_DATA_START(SeqTwoByteString)));
      if (reallocate_result) {
        __ Move(ToRegister(result()), result_string);
      }
    }
  } else {
    __ StringFromCharCode(register_snapshot(), nullptr, result_string,
                          ToRegister(code_input()), scratch,
                          MaglevAssembler::CharCodeMaskMode::kMustApplyMask);
  }
}

void InlinedAllocation::SetValueLocationConstraints() {
  UseRegister(allocation_block());
  if (offset() == 0) {
    DefineSameAsFirst(this);
  } else {
    DefineAsRegister(this);
  }
}

void InlinedAllocation::GenerateCode(MaglevAssembler* masm,
                                     const ProcessingState& state) {
  if (offset() != 0) {
    __ lay(ToRegister(result()),
           MemOperand(ToRegister(allocation_block()), offset()));
  }
}

void ArgumentsLength::SetValueLocationConstraints() { DefineAsRegister(this); }

void ArgumentsLength::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  Register argc = ToRegister(result());
  __ LoadU64(argc, MemOperand(fp, StandardFrameConstants::kArgCOffset));
  __ SubS64(argc, Operand(1));  // Remove receiver.
}

void RestLength::SetValueLocationConstraints() { DefineAsRegister(this); }

void RestLength::GenerateCode(MaglevAssembler* masm,
                              const ProcessingState& state) {
  Register length = ToRegister(result());
  Label done;
  __ LoadU64(length, MemOperand(fp, StandardFrameConstants::kArgCOffset));
  __ SubS32(length, Operand(formal_parameter_count() + 1));
  __ bge(&done);
  __ Move(length, 0);
  __ bind(&done);
  __ UncheckedSmiTagInt32(length);
}

int CheckedObjectToIndex::MaxCallStackArgs() const { return 0; }

void Int32AddWithOverflow::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsRegister(this);
}

void Int32AddWithOverflow::GenerateCode(MaglevAssembler* masm,
                                        const ProcessingState& state) {
  Register left = ToRegister(left_input());
  Register right = ToRegister(right_input());
  Register out = ToRegister(result());
  __ AddS32(out, left, right);
  __ LoadS32(out, out);
  // The output register shouldn't be a register input into the eager deopt
  // info.
  DCHECK_REGLIST_EMPTY(RegList{out} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
  __ EmitEagerDeoptIf(overflow, DeoptimizeReason::kOverflow, this);
}

void Int32SubtractWithOverflow::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsRegister(this);
}
void Int32SubtractWithOverflow::GenerateCode(MaglevAssembler* masm,
                                             const ProcessingState& state) {
  Register left = ToRegister(left_input());
  Register right = ToRegister(right_input());
  Register out = ToRegister(result());
  __ SubS32(out, left, right);
  __ LoadS32(out, out);
  // The output register shouldn't be a register input into the eager deopt
  // info.
  DCHECK_REGLIST_EMPTY(RegList{out} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
  __ EmitEagerDeoptIf(overflow, DeoptimizeReason::kOverflow, this);
}

void Int32MultiplyWithOverflow::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsRegister(this);
  set_temporaries_needed(1);
}
void Int32MultiplyWithOverflow::GenerateCode(MaglevAssembler* masm,
                                             const ProcessingState& state) {
  Register left = ToRegister(left_input());
  Register right = ToRegister(right_input());
  Register out = ToRegister(result());

  // TODO(leszeks): peephole optimise multiplication by a constant.

  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register temp = temps.AcquireScratch();
  __ Or(temp, left, right);
  __ MulS32(out, left, right);
  __ LoadS32(out, out);
  DCHECK_REGLIST_EMPTY(RegList{temp, out} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
  __ EmitEagerDeoptIf(overflow, DeoptimizeReason::kOverflow, this);

  // If the result is zero, check if either lhs or rhs is negative.
  Label end;
  __ CmpS32(out, Operand::Zero());
  __ bne(&end);
  __ CmpS32(temp, Operand::Zero());
  // If one of them is negative, we must have a -0 result, which is non-int32,
  // so deopt.
  __ EmitEagerDeoptIf(lt, DeoptimizeReason::kOverflow, this);

  __ bind(&end);
}

void Int32DivideWithOverflow::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsRegister(this);
}
void Int32DivideWithOverflow::GenerateCode(MaglevAssembler* masm,
                                           const ProcessingState& state) {
  Register left = ToRegister(left_input());
  Register right = ToRegister(right_input());
  Register out = ToRegister(result());

  // TODO(leszeks): peephole optimise division by a constant.

  // Pre-check for overflow, since idiv throws a division exception on overflow
  // rather than setting the overflow flag. Logic copied from
  // effect-control-linearizer.cc

  // Check if {right} is positive (and not zero).
  __ CmpS32(right, Operand(0));
  ZoneLabelRef done(masm);
  __ JumpToDeferredIf(
      le,
      [](MaglevAssembler* masm, ZoneLabelRef done, Register left,
         Register right, Int32DivideWithOverflow* node) {
        // {right} is negative or zero.

        // TODO(leszeks): Using kNotInt32 here, but in same places
        // kDivisionByZerokMinusZero/kMinusZero/kOverflow would be better. Right
        // now all eager deopts in a node have to be the same -- we should allow
        // a node to emit multiple eager deopts with different reasons.
        Label* deopt = __ GetDeoptLabel(node, DeoptimizeReason::kNotInt32);

        // Check if {right} is zero.
        // We've already done the compare and flags won't be cleared yet.
        __ JumpIf(eq, deopt);

        // Check if {left} is zero, as that would produce minus zero.
        __ CmpS32(left, Operand::Zero());
        __ JumpIf(eq, deopt);

        // Check if {left} is kMinInt and {right} is -1, in which case we'd have
        // to return -kMinInt, which is not representable as Int32.
        __ CmpS32(left, Operand(kMinInt));
        __ JumpIf(ne, *done);
        __ CmpS32(right, Operand(-1));
        __ JumpIf(ne, *done);
        __ JumpToDeopt(deopt);
      },
      done, left, right, this);
  __ bind(*done);

  // Perform the actual integer division.
  __ DivS32(out, left, right);
  __ LoadS32(out, out);

  // Check that the remainder is zero.
  __ CmpS64(r0, Operand::Zero());
  __ EmitEagerDeoptIf(ne, DeoptimizeReason::kNotInt32, this);
}

void Int32ModulusWithOverflow::SetValueLocationConstraints() {
  UseAndClobberRegister(left_input());
  UseAndClobberRegister(right_input());
  DefineAsRegister(this);
}
void Int32ModulusWithOverflow::GenerateCode(MaglevAssembler* masm,
                                            const ProcessingState& state) {
  // If AreAliased(lhs, rhs):
  //   deopt if lhs < 0  // Minus zero.
  //   0

  // Using same algorithm as in EffectControlLinearizer:
  //   if rhs <= 0 then
  //     rhs = -rhs
  //     deopt if rhs == 0
  //   if lhs < 0 then
  //     let lhs_abs = -lsh in
  //     let res = lhs_abs % rhs in
  //     deopt if res == 0
  //     -res
  //   else
  //     let msk = rhs - 1 in
  //     if rhs & msk == 0 then
  //       lhs & msk
  //     else
  //       lhs % rhs

  Register lhs = ToRegister(left_input());
  Register rhs = ToRegister(right_input());
  Register out = ToRegister(result());

  static constexpr DeoptimizeReason deopt_reason =
      DeoptimizeReason::kDivisionByZero;

  if (lhs == rhs) {
    // For the modulus algorithm described above, lhs and rhs must not alias
    // each other.
    __ CmpS32(lhs, Operand::Zero());
    // TODO(victorgomes): This ideally should be kMinusZero, but Maglev only
    // allows one deopt reason per IR.
    __ EmitEagerDeoptIf(lt, deopt_reason, this);
    __ Move(out, 0);
    return;
  }

  DCHECK_NE(lhs, rhs);

  ZoneLabelRef done(masm);
  ZoneLabelRef rhs_checked(masm);
  __ CmpS32(rhs, Operand(0));
  __ JumpToDeferredIf(
      le,
      [](MaglevAssembler* masm, ZoneLabelRef rhs_checked, Register rhs,
         Int32ModulusWithOverflow* node) {
        __ lcr(rhs, rhs);
        __ bne(*rhs_checked);
        __ EmitEagerDeopt(node, deopt_reason);
      },
      rhs_checked, rhs, this);
  __ bind(*rhs_checked);

  __ CmpS32(lhs, Operand(0));
  __ JumpToDeferredIf(
      lt,
      [](MaglevAssembler* masm, ZoneLabelRef done, Register lhs, Register rhs,
         Register out, Int32ModulusWithOverflow* node) {
        __ lcr(lhs, lhs);
        __ ModU32(out, lhs, rhs);
        __ lcr(out, out);
        // TODO(victorgomes): This ideally should be kMinusZero, but Maglev
        // only allows one deopt reason per IR.
        __ bne(*done);
        __ EmitEagerDeopt(node, deopt_reason);
      },
      done, lhs, rhs, out, this);

  Label rhs_not_power_of_2;
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register mask = temps.AcquireScratch();
  __ AddS32(mask, rhs, Operand(-1));
  __ And(r0, mask, rhs);
  __ JumpIf(ne, &rhs_not_power_of_2);

  // {rhs} is power of 2.
  __ And(out, mask, lhs);
  __ Jump(*done);
  // {mask} can be reused from now on.
  temps.IncludeScratch(mask);

  __ bind(&rhs_not_power_of_2);
  __ ModU32(out, lhs, rhs);
  __ bind(*done);
  __ LoadS32(out, out);
}

#define DEF_BITWISE_BINOP(Instruction, opcode)                   \
  void Instruction::SetValueLocationConstraints() {              \
    UseRegister(left_input());                                   \
    UseRegister(right_input());                                  \
    DefineAsRegister(this);                                      \
  }                                                              \
                                                                 \
  void Instruction::GenerateCode(MaglevAssembler* masm,          \
                                 const ProcessingState& state) { \
    Register left = ToRegister(left_input());                    \
    Register right = ToRegister(right_input());                  \
    Register out = ToRegister(result());                         \
    __ opcode(out, left, right);                                 \
    __ LoadS32(out, out);                                        \
  }
DEF_BITWISE_BINOP(Int32BitwiseAnd, And)
DEF_BITWISE_BINOP(Int32BitwiseOr, Or)
DEF_BITWISE_BINOP(Int32BitwiseXor, Xor)
#undef DEF_BITWISE_BINOP

#define DEF_SHIFT_BINOP(Instruction, opcode)                     \
  void Instruction::SetValueLocationConstraints() {              \
    UseRegister(left_input());                                   \
    if (right_input().node()->Is<Int32Constant>()) {             \
      UseAny(right_input());                                     \
    } else {                                                     \
      UseRegister(right_input());                                \
    }                                                            \
    DefineAsRegister(this);                                      \
  }                                                              \
  void Instruction::GenerateCode(MaglevAssembler* masm,          \
                                 const ProcessingState& state) { \
    Register left = ToRegister(left_input());                    \
    Register out = ToRegister(result());                         \
    if (Int32Constant* constant =                                \
            right_input().node()->TryCast<Int32Constant>()) {    \
      uint32_t shift = constant->value() & 31;                   \
      if (shift == 0) {                                          \
        __ Move(out, left);                                      \
        return;                                                  \
      }                                                          \
      __ opcode(out, left, Operand(shift));                      \
      __ LoadS32(out, out);                                      \
    } else {                                                     \
      MaglevAssembler::TemporaryRegisterScope temps(masm);       \
      Register scratch = temps.AcquireScratch();                 \
      Register right = ToRegister(right_input());                \
      __ And(scratch, right, Operand(31));                       \
      __ opcode(out, left, scratch);                             \
      __ LoadS32(out, out);                                      \
    }                                                            \
  }
DEF_SHIFT_BINOP(Int32ShiftLeft, ShiftLeftU32)
DEF_SHIFT_BINOP(Int32ShiftRight, ShiftRightS32)
DEF_SHIFT_BINOP(Int32ShiftRightLogical, ShiftRightU32)
#undef DEF_SHIFT_BINOP

void Int32BitwiseNot::SetValueLocationConstraints() {
  UseRegister(value_input());
  DefineAsRegister(this);
}

void Int32BitwiseNot::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  Register value = ToRegister(value_input());
  Register out = ToRegister(result());
  __ Not32(out, value);
  __ LoadS32(out, out);
}

void Float64Add::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsRegister(this);
}

void Float64Add::GenerateCode(MaglevAssembler* masm,
                              const ProcessingState& state) {
  DoubleRegister left = ToDoubleRegister(left_input());
  DoubleRegister right = ToDoubleRegister(right_input());
  DoubleRegister out = ToDoubleRegister(result());
  __ AddF64(out, left, right);
}

void Float64Subtract::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsRegister(this);
}

void Float64Subtract::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  DoubleRegister left = ToDoubleRegister(left_input());
  DoubleRegister right = ToDoubleRegister(right_input());
  DoubleRegister out = ToDoubleRegister(result());
  __ SubF64(out, left, right);
}

void Float64Multiply::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsRegister(this);
}

void Float64Multiply::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  DoubleRegister left = ToDoubleRegister(left_input());
  DoubleRegister right = ToDoubleRegister(right_input());
  DoubleRegister out = ToDoubleRegister(result());
  __ MulF64(out, left, right);
}

void Float64Divide::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsRegister(this);
}

void Float64Divide::GenerateCode(MaglevAssembler* masm,
                                 const ProcessingState& state) {
  DoubleRegister left = ToDoubleRegister(left_input());
  DoubleRegister right = ToDoubleRegister(right_input());
  DoubleRegister out = ToDoubleRegister(result());
  __ DivF64(out, left, right);
}

void Float64Modulus::SetValueLocationConstraints() {
  UseFixed(left_input(), d0);
  UseFixed(right_input(), d2);
  DefineSameAsFirst(this);
}
void Float64Modulus::GenerateCode(MaglevAssembler* masm,
                                  const ProcessingState& state) {
  FrameScope scope(masm, StackFrame::MANUAL);
  __ Push(r2, r3, r4, r5);
  __ PrepareCallCFunction(0, 2);
  __ CallCFunction(ExternalReference::mod_two_doubles_operation(), 0, 2);
  __ Pop(r2, r3, r4, r5);
}

void Float64Negate::SetValueLocationConstraints() {
  UseRegister(input());
  DefineAsRegister(this);
}
void Float64Negate::GenerateCode(MaglevAssembler* masm,
                                 const ProcessingState& state) {
  DoubleRegister value = ToDoubleRegister(input());
  DoubleRegister out = ToDoubleRegister(result());
  __ lcdbr(out, value);
}

void Float64Abs::GenerateCode(MaglevAssembler* masm,
                              const ProcessingState& state) {
  DoubleRegister in = ToDoubleRegister(input());
  DoubleRegister out = ToDoubleRegister(result());
  __ lpdbr(out, in);
}

void Float64Round::GenerateCode(MaglevAssembler* masm,
                                const ProcessingState& state) {
  DoubleRegister in = ToDoubleRegister(input());
  DoubleRegister out = ToDoubleRegister(result());
  if (kind_ == Kind::kNearest) {
    MaglevAssembler::TemporaryRegisterScope temps(masm);
    DoubleRegister temp = temps.AcquireScratchDouble();
    DoubleRegister temp2 = temps.AcquireScratchDouble();
    __ Move(temp, in);
    __ NearestIntF64(out, in);
    __ SubF64(temp, temp, out);
    __ Move(temp2, 0.5);
    __ CmpF64(temp, temp2);
    Label done;
    __ JumpIf(ne, &done, Label::kNear);
    __ AddF64(out, out, temp2);
    __ AddF64(out, out, temp2);
    __ bind(&done);
  } else if (kind_ == Kind::kCeil) {
    __ CeilF64(out, in);
  } else if (kind_ == Kind::kFloor) {
    __ FloorF64(out, in);
  }
}

int Float64Exponentiate::MaxCallStackArgs() const { return 0; }
void Float64Exponentiate::SetValueLocationConstraints() {
  UseFixed(left_input(), d0);
  UseFixed(right_input(), d2);
  DefineSameAsFirst(this);
}
void Float64Exponentiate::GenerateCode(MaglevAssembler* masm,
                                       const ProcessingState& state) {
  FrameScope scope(masm, StackFrame::MANUAL);
  __ Push(r2, r3, r4, r5);
  __ PrepareCallCFunction(0, 2);
  __ CallCFunction(ExternalReference::ieee754_pow_function(), 0, 2);
  __ Pop(r2, r3, r4, r5);
}

int Float64Ieee754Unary::MaxCallStackArgs() const { return 0; }
void Float64Ieee754Unary::SetValueLocationConstraints() {
  UseFixed(input(), d0);
  DefineSameAsFirst(this);
}
void Float64Ieee754Unary::GenerateCode(MaglevAssembler* masm,
                                       const ProcessingState& state) {
  FrameScope scope(masm, StackFrame::MANUAL);
  __ Push(r2, r3, r4, r5);
  __ PrepareCallCFunction(0, 1);
  __ CallCFunction(ieee_function_ref(), 0, 1);
  __ Pop(r2, r3, r4, r5);
}

void LoadTypedArrayLength::SetValueLocationConstraints() {
  UseRegister(receiver_input());
  DefineAsRegister(this);
}

void LoadTypedArrayLength::GenerateCode(MaglevAssembler* masm,
                                        const ProcessingState& state) {
  Register object = ToRegister(receiver_input());
  Register result_register = ToRegister(result());
  if (v8_flags.debug_code) {
    __ AssertObjectType(object, JS_TYPED_ARRAY_TYPE,
                        AbortReason::kUnexpectedValue);
  }

  __ LoadBoundedSizeFromObject(result_register, object,
                               JSTypedArray::kRawByteLengthOffset);
  int element_size = ElementsKindSize(elements_kind_);
  if (element_size > 1) {
    // TODO(leszeks): Merge this shift with the one in LoadBoundedSize.
    DCHECK(element_size == 2 || element_size == 4 || element_size == 8);
    __ ShiftLeftU64(result_register, result_register,
                    Operand(base::bits::CountTrailingZeros(element_size)));
  }
}

int CheckJSDataViewBounds::MaxCallStackArgs() const { return 1; }
void CheckJSDataViewBounds::SetValueLocationConstraints() {
  UseRegister(receiver_input());
  UseRegister(index_input());
  set_temporaries_needed(1);
}
void CheckJSDataViewBounds::GenerateCode(MaglevAssembler* masm,
                                         const ProcessingState& state) {
  USE(element_type_);
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register object = ToRegister(receiver_input());
  Register index = ToRegister(index_input());
  if (v8_flags.debug_code) {
    __ AssertObjectType(object, JS_DATA_VIEW_TYPE,
                        AbortReason::kUnexpectedValue);
  }

  // Normal DataView (backed by AB / SAB) or non-length tracking backed by GSAB.
  Register byte_length = temps.AcquireScratch();
  __ LoadBoundedSizeFromObject(byte_length, object,
                               JSDataView::kRawByteLengthOffset);

  int element_size = compiler::ExternalArrayElementSize(element_type_);
  if (element_size > 1) {
    __ SubS64(byte_length, Operand(element_size - 1));
    __ EmitEagerDeoptIf(lt, DeoptimizeReason::kOutOfBounds, this);
  }
  __ CmpS32(index, byte_length);
  __ EmitEagerDeoptIf(ge, DeoptimizeReason::kOutOfBounds, this);
}

void HoleyFloat64ToMaybeNanFloat64::SetValueLocationConstraints() {
  UseRegister(input());
  DefineSameAsFirst(this);
}
void HoleyFloat64ToMaybeNanFloat64::GenerateCode(MaglevAssembler* masm,
                                                 const ProcessingState& state) {
  DoubleRegister value = ToDoubleRegister(input());
  // The hole value is a signalling NaN, so just silence it to get the float64
  // value.
  __ lzdr(kDoubleRegZero);
  __ SubF64(value, value, kDoubleRegZero);
}

namespace {

enum class ReduceInterruptBudgetType { kLoop, kReturn };

void HandleInterruptsAndTiering(MaglevAssembler* masm, ZoneLabelRef done,
                                Node* node, ReduceInterruptBudgetType type,
                                Register scratch0) {
  // For loops, first check for interrupts. Don't do this for returns, as we
  // can't lazy deopt to the end of a return.
  if (type == ReduceInterruptBudgetType::kLoop) {
    Label next;
    // Here, we only care about interrupts since we've already guarded against
    // real stack overflows on function entry.
    {
      Register stack_limit = scratch0;
      __ LoadStackLimit(stack_limit, StackLimitKind::kInterruptStackLimit);
      __ CmpU64(sp, stack_limit);
      __ bgt(&next);
    }

    // An interrupt has been requested and we must call into runtime to handle
    // it; since we already pay the call cost, combine with the TieringManager
    // call.
    {
      SaveRegisterStateForCall save_register_state(masm,
                                                   node->register_snapshot());
      Register function = scratch0;
      __ LoadU64(function,
                 MemOperand(fp, StandardFrameConstants::kFunctionOffset));
      __ Push(function);
      // Move into kContextRegister after the load into scratch0, just in case
      // scratch0 happens to be kContextRegister.
      __ Move(kContextRegister, masm->native_context().object());
      __ CallRuntime(Runtime::kBytecodeBudgetInterruptWithStackCheck_Maglev, 1);
      save_register_state.DefineSafepointWithLazyDeopt(node->lazy_deopt_info());
    }
    __ b(*done);  // All done, continue.
    __ bind(&next);
  }

  // No pending interrupts. Call into the TieringManager if needed.
  {
    SaveRegisterStateForCall save_register_state(masm,
                                                 node->register_snapshot());
    Register function = scratch0;
    __ LoadU64(function,
               MemOperand(fp, StandardFrameConstants::kFunctionOffset));
    __ Push(function);
    // Move into kContextRegister after the load into scratch0, just in case
    // scratch0 happens to be kContextRegister.
    __ Move(kContextRegister, masm->native_context().object());
    // Note: must not cause a lazy deopt!
    __ CallRuntime(Runtime::kBytecodeBudgetInterrupt_Maglev, 1);
    save_register_state.DefineSafepoint();
  }
  __ b(*done);
}

void GenerateReduceInterruptBudget(MaglevAssembler* masm, Node* node,
                                   ReduceInterruptBudgetType type, int amount) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.AcquireScratch();
  Register feedback_cell = scratch;
  Register budget = temps.AcquireScratch();
  __ LoadU64(feedback_cell,
             MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ LoadTaggedField(
      feedback_cell,
      FieldMemOperand(feedback_cell, JSFunction::kFeedbackCellOffset));
  __ LoadU32(budget, FieldMemOperand(feedback_cell,
                                     FeedbackCell::kInterruptBudgetOffset));
  __ SubS32(budget, Operand(amount));
  __ StoreU32(budget, FieldMemOperand(feedback_cell,
                                      FeedbackCell::kInterruptBudgetOffset));
  ZoneLabelRef done(masm);
  __ JumpToDeferredIf(lt, HandleInterruptsAndTiering, done, node, type,
                      scratch);
  __ bind(*done);
}

}  // namespace

int ReduceInterruptBudgetForLoop::MaxCallStackArgs() const { return 1; }
void ReduceInterruptBudgetForLoop::SetValueLocationConstraints() {
  set_temporaries_needed(1);
}
void ReduceInterruptBudgetForLoop::GenerateCode(MaglevAssembler* masm,
                                                const ProcessingState& state) {
  GenerateReduceInterruptBudget(masm, this, ReduceInterruptBudgetType::kLoop,
                                amount());
}

int ReduceInterruptBudgetForReturn::MaxCallStackArgs() const { return 1; }
void ReduceInterruptBudgetForReturn::SetValueLocationConstraints() {
  set_temporaries_needed(1);
}
void ReduceInterruptBudgetForReturn::GenerateCode(
    MaglevAssembler* masm, const ProcessingState& state) {
  GenerateReduceInterruptBudget(masm, this, ReduceInterruptBudgetType::kReturn,
                                amount());
}

// ---
// Control nodes
// ---
void Return::SetValueLocationConstraints() {
  UseFixed(value_input(), kReturnRegister0);
}
void Return::GenerateCode(MaglevAssembler* masm, const ProcessingState& state) {
  DCHECK_EQ(ToRegister(value_input()), kReturnRegister0);

  // Read the formal number of parameters from the top level compilation unit
  // (i.e. the outermost, non inlined function).
  int formal_params_size =
      masm->compilation_info()->toplevel_compilation_unit()->parameter_count();

  // We're not going to continue execution, so we can use an arbitrary register
  // here instead of relying on temporaries from the register allocator.
  Register actual_params_size = r6;

  // Compute the size of the actual parameters + receiver (in bytes).
  // TODO(leszeks): Consider making this an input into Return to re-use the
  // incoming argc's register (if it's still valid).
  __ LoadU64(actual_params_size,
             MemOperand(fp, StandardFrameConstants::kArgCOffset));

  // Leave the frame.
  __ LeaveFrame(StackFrame::MAGLEV);

  // If actual is bigger than formal, then we should use it to free up the stack
  // arguments.
  Label drop_dynamic_arg_size;
  __ CmpS32(actual_params_size, Operand(formal_params_size));
  __ bgt(&drop_dynamic_arg_size);
  __ mov(actual_params_size, Operand(formal_params_size));
  __ bind(&drop_dynamic_arg_size);

  // Drop receiver + arguments according to dynamic arguments size.
  __ DropArguments(actual_params_size);
  __ Ret();
}

}  // namespace maglev
}  // namespace internal
}  // namespace v8
```