Response:
My thinking process to answer the request about `v8/src/maglev/x64/maglev-ir-x64.cc` goes like this:

1. **Understand the Core Request:** The primary goal is to describe the functionality of this specific C++ file within the V8 JavaScript engine. The request also has specific sub-questions about Torque, JavaScript relationship, code logic, and common errors.

2. **Initial Analysis of the File Path and Contents:**
    * `v8/src/`:  Indicates a source file within the V8 project.
    * `maglev/`:  Suggests this file is related to the Maglev compiler, a newer, faster tier in V8's compilation pipeline.
    * `x64/`:  Clearly specifies that the code is for the x64 architecture.
    * `maglev-ir-x64.cc`:  The "ir" likely stands for Intermediate Representation. This strongly suggests the file defines the structure and operations used by the Maglev compiler for x64. The ".cc" extension confirms it's a C++ source file.
    * The `#include` directives confirm the dependencies on V8's internal components like codegen, assembler, objects, and other Maglev-specific headers. The presence of `assembler-x64.h` is a key indicator of low-level code generation.

3. **Deconstruct the Code (High-Level):** I'd read through the code, paying attention to the class names and their methods. I'd notice patterns like:
    * Classes inheriting from some base `Node` type (implicitly or explicitly).
    * Methods like `SetValueLocationConstraints()` and `GenerateCode()`.
    * Code that manipulates registers (e.g., `ToRegister()`, `__ movq()`, `__ addl()`).
    * References to V8 internal structures (e.g., `StandardFrameConstants`, `JSFunction`, `FeedbackCell`).
    * The presence of `EmitEagerDeoptIf()`, which is a mechanism for optimizing compilers to revert to slower, more general code if certain assumptions are violated.

4. **Identify Key Functionality Areas:**  Based on the classes and their code, I would group the functionalities into logical categories:
    * **Memory Allocation:**  `InlinedAllocation`
    * **Argument Handling:** `ArgumentsLength`, `RestLength`
    * **Typed Array/DataView Operations:** `LoadTypedArrayLength`, `CheckJSDataViewBounds`
    * **String Operations:** `BuiltinStringFromCharCode`
    * **Integer Arithmetic (with Overflow Checks):** `Int32AddWithOverflow`, `Int32SubtractWithOverflow`, etc. The "WithOverflow" suffix is crucial.
    * **Bitwise Operations:** `Int32BitwiseAnd`, `Int32BitwiseOr`, etc.
    * **Shift Operations:** `Int32ShiftLeft`, `Int32ShiftRight`, etc.
    * **Increment/Decrement:** `Int32IncrementWithOverflow`, `Int32DecrementWithOverflow`
    * **Negation/Absolute Value:** `Int32NegateWithOverflow`, `Int32AbsWithOverflow`
    * **Floating-Point Arithmetic:** `Float64Add`, `Float64Subtract`, etc.
    * **Floating-Point Specific Operations:** `Float64Modulus`, `Float64Negate`, `Float64Abs`, `Float64Round`, `Float64Exponentiate`, `Float64Ieee754Unary`, `HoleyFloat64ToMaybeNanFloat64`.
    * **Interrupt Handling/Tiering:** `ReduceInterruptBudgetForLoop`, `ReduceInterruptBudgetForReturn`
    * **Control Flow:** `Return`

5. **Address Specific Sub-Questions:**
    * **Torque:** The filename ending in `.cc` immediately tells me it's *not* a Torque file. I explicitly state this.
    * **JavaScript Relationship:**  I connect the operations in the file to their corresponding JavaScript operators and methods. For example, `Int32AddWithOverflow` relates to the `+` operator for integers, `Float64Multiply` to the `*` operator for floating-point numbers, and `StringFromCharCode` to `String.fromCharCode()`. Providing concrete JavaScript examples is essential here.
    * **Code Logic Reasoning:** For a few selected nodes (like `RestLength`, `Int32ModulusWithOverflow`, `Int32DivideWithOverflow`), I try to explain the logic. This involves describing the assumptions, the steps taken in the assembly code, and the potential deoptimization conditions. I use hypothetical inputs and outputs to illustrate the behavior.
    * **Common Programming Errors:** I link the "overflow" checks in the integer operations to the common programming error of exceeding the maximum or minimum representable integer value. I also connect `CheckJSDataViewBounds` to out-of-bounds access errors with typed arrays/data views.

6. **Structure the Answer:** I organize the information logically:
    * Start with a clear summary of the file's main purpose.
    * List the key functionalities in a structured way.
    * Address each sub-question separately and clearly.
    * Use code formatting for clarity (both C++ and JavaScript).

7. **Refine and Review:**  I'd reread my answer to ensure accuracy, clarity, and completeness. I'd double-check the JavaScript examples and the code logic explanations. I would also make sure to explicitly address all parts of the original prompt.

By following these steps, I can systematically analyze the C++ code and provide a comprehensive and informative answer that addresses all aspects of the request. The key is to combine an understanding of the code's structure with knowledge of JavaScript semantics and common programming practices.
`v8/src/maglev/x64/maglev-ir-x64.cc` 是 V8 JavaScript 引擎中 Maglev 编译器针对 x64 架构的**中间表示 (Intermediate Representation, IR)** 的定义和代码生成实现。

**主要功能:**

1. **定义 Maglev IR 节点的 x64 特定实现:** 该文件定义了各种 Maglev IR 节点 (例如 `InlinedAllocation`, `ArgumentsLength`, `Int32AddWithOverflow`, `Float64Add`, `Return` 等) 在 x64 架构下的具体行为和代码生成逻辑。

2. **为 Maglev IR 节点生成 x64 汇编代码:**  每个 IR 节点都包含一个 `GenerateCode` 方法，该方法负责将该节点的操作转换为相应的 x64 汇编指令。Maglev 编译器会遍历 IR 图，并调用每个节点的 `GenerateCode` 方法来生成最终的可执行机器码。

3. **管理寄存器分配和约束:**  每个 IR 节点都有一个 `SetValueLocationConstraints` 方法，用于声明其输入和输出值在寄存器中的使用约束。这有助于 Maglev 编译器的寄存器分配器有效地分配寄存器，避免冲突。

4. **处理特定的 x64 指令细节:** 该文件中的代码会利用 x64 特有的指令 (例如 `leaq`, `movq`, `addl`, `addsd` 等) 来实现各种操作。

5. **集成 V8 内部组件:**  代码中可以看到对 V8 其他内部组件的引用，例如 `AssemblerX64`, `MaglevAssembler`, `FeedbackCell`, `JSFunction` 等，表明 Maglev 编译器与 V8 的其他部分紧密集成。

**关于 .tq 结尾：**

该文件以 `.cc` 结尾，因此**不是**一个 V8 Torque 源代码文件。 Torque 文件通常以 `.tq` 结尾，用于定义类型系统和一些内置函数的实现。

**与 JavaScript 的关系 (通过举例说明)：**

该文件中的 IR 节点和生成的代码直接对应于 JavaScript 的各种操作和语法。以下是一些示例：

* **`ArgumentsLength`:**  对应于 JavaScript 函数内部的 `arguments.length`。
   ```javascript
   function foo(a, b) {
     console.log(arguments.length);
   }
   foo(1, 2, 3); // 输出 3
   ```
   在 `ArgumentsLength::GenerateCode` 中，可以看到它从栈帧中读取参数计数。

* **`Int32AddWithOverflow`:** 对应于 JavaScript 中的整数加法运算，并且考虑了溢出的情况。
   ```javascript
   let x = 2147483647; // 最大的 32 位有符号整数
   let y = 1;
   let sum = x + y;
   console.log(sum); // 输出 -2147483648 (溢出)
   ```
   `Int32AddWithOverflow::GenerateCode` 中使用了 `addl` 指令，并通过 `EmitEagerDeoptIf(overflow, ...)` 来处理溢出情况，这会导致代码回退到更慢但更安全的代码执行路径。

* **`Float64Add`:** 对应于 JavaScript 中的浮点数加法运算。
   ```javascript
   let a = 1.5;
   let b = 2.5;
   let sum = a + b;
   console.log(sum); // 输出 4
   ```
   `Float64Add::GenerateCode` 中使用了 `Addsd` 指令来进行双精度浮点数加法。

* **`Return`:** 对应于 JavaScript 函数的 `return` 语句。
   ```javascript
   function add(a, b) {
     return a + b;
   }
   let result = add(5, 3);
   console.log(result); // 输出 8
   ```
   `Return::GenerateCode` 负责生成将返回值放入寄存器并清理栈帧的代码。

**代码逻辑推理 (假设输入与输出)：**

让我们以 `RestLength` 节点为例：

**假设输入:**
* `formal_parameter_count()`:  一个 JavaScript 函数声明的形参个数，例如 `function foo(a, b, ...rest)` 的形参个数为 2。
* 函数调用时实际传入的参数个数存储在栈帧的 `StandardFrameConstants::kArgCOffset` 位置。假设函数被调用时传入了 5 个参数。

**代码逻辑 (`RestLength::GenerateCode`):**

1. 从栈帧中读取实际参数的个数到寄存器 `length`。 (假设 `length` 寄存器最初包含 5)
2. 从 `length` 中减去 `formal_parameter_count() + 1` (加 1 是为了移除 receiver，即 `this`)。 在我们的例子中，是 `2 + 1 = 3`。  `length` 现在是 `5 - 3 = 2`。
3. 检查 `length` 是否大于等于 0。如果是，则跳转到 `done` 标签。
4. 如果 `length` 小于 0，则将 `length` 设置为 0。 这处理了实际参数少于形参的情况。
5. 在 `done` 标签处，将 `length` (剩余参数的个数) 进行 Smi 标记（V8 中表示小整数的方式）。

**输出:**
* `result()` 寄存器将包含剩余参数的个数的 Smi 表示。 在我们的例子中，剩余参数个数为 `5 - 2 = 3`，因此 `result()` 寄存器将包含 3 的 Smi 表示。

**用户常见的编程错误 (与该文件相关)：**

* **整数溢出:**  当 JavaScript 中的整数运算结果超出 32 位有符号整数的范围时，会发生溢出。 例如：
   ```javascript
   let maxInt = 2147483647;
   let result = maxInt + 1; // 溢出，结果为 -2147483648
   ```
   `Int32AddWithOverflow` 等节点的存在就是为了检测这种溢出情况，并在 Maglev 编译器生成的代码中进行处理（例如，通过 deoptimization 回退到更安全的代码执行）。

* **访问 Typed Array 或 DataView 越界:**  尝试访问 Typed Array 或 DataView 中超出其边界的索引会导致错误。 例如：
   ```javascript
   const buffer = new ArrayBuffer(10);
   const view = new DataView(buffer);
   view.getInt8(10); // 错误：Index out of range
   ```
   `CheckJSDataViewBounds` 节点用于在编译时插入边界检查，防止这种运行时错误。如果检查失败，会触发 deoptimization。

总之，`v8/src/maglev/x64/maglev-ir-x64.cc` 是 Maglev 编译器在 x64 架构上生成高性能 JavaScript 代码的关键组成部分，它定义了中间表示节点的具体实现，并负责将这些节点转换为底层的机器指令，同时处理一些常见的运行时错误和优化机会。

### 提示词
```
这是目录为v8/src/maglev/x64/maglev-ir-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/x64/maglev-ir-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/logging.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/x64/assembler-x64-inl.h"
#include "src/codegen/x64/assembler-x64.h"
#include "src/codegen/x64/register-x64.h"
#include "src/maglev/maglev-assembler-inl.h"
#include "src/maglev/maglev-graph-processor.h"
#include "src/maglev/maglev-graph.h"
#include "src/maglev/maglev-ir-inl.h"
#include "src/maglev/maglev-ir.h"
#include "src/objects/feedback-cell.h"
#include "src/objects/instance-type.h"
#include "src/objects/js-function.h"

namespace v8 {
namespace internal {
namespace maglev {

#define __ masm->

// ---
// Nodes
// ---

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
    __ leaq(ToRegister(result()),
            Operand(ToRegister(allocation_block()), offset()));
  }
}

void ArgumentsLength::SetValueLocationConstraints() { DefineAsRegister(this); }

void ArgumentsLength::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  __ movq(ToRegister(result()),
          Operand(rbp, StandardFrameConstants::kArgCOffset));
  __ decl(ToRegister(result()));  // Remove receiver.
}

void RestLength::SetValueLocationConstraints() { DefineAsRegister(this); }

void RestLength::GenerateCode(MaglevAssembler* masm,
                              const ProcessingState& state) {
  Register length = ToRegister(result());
  Label done;
  __ movq(length, Operand(rbp, StandardFrameConstants::kArgCOffset));
  __ subl(length, Immediate(formal_parameter_count() + 1));
  __ j(greater_equal, &done, Label::Distance::kNear);
  __ Move(length, 0);
  __ bind(&done);
  __ UncheckedSmiTagInt32(length);
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
    __ AssertNotSmi(object);
    __ CmpObjectType(object, JS_TYPED_ARRAY_TYPE, kScratchRegister);
    __ Assert(equal, AbortReason::kUnexpectedValue);
  }
  __ LoadBoundedSizeFromObject(result_register, object,
                               JSTypedArray::kRawByteLengthOffset);
  int element_size = ElementsKindSize(elements_kind_);
  if (element_size > 1) {
    // TODO(leszeks): Merge this shift with the one in LoadBoundedSize.
    DCHECK(element_size == 2 || element_size == 4 || element_size == 8);
    __ shrq(result_register,
            Immediate(base::bits::CountTrailingZeros(element_size)));
  }
}

void CheckJSDataViewBounds::SetValueLocationConstraints() {
  UseRegister(receiver_input());
  UseRegister(index_input());
}
void CheckJSDataViewBounds::GenerateCode(MaglevAssembler* masm,
                                         const ProcessingState& state) {
  Register object = ToRegister(receiver_input());
  Register index = ToRegister(index_input());
  Register byte_length = kScratchRegister;
  if (v8_flags.debug_code) {
    __ AssertNotSmi(object);
    __ CmpObjectType(object, JS_DATA_VIEW_TYPE, kScratchRegister);
    __ Assert(equal, AbortReason::kUnexpectedValue);
  }

  // Normal DataView (backed by AB / SAB) or non-length tracking backed by GSAB.
  __ LoadBoundedSizeFromObject(byte_length, object,
                               JSDataView::kRawByteLengthOffset);

  int element_size = compiler::ExternalArrayElementSize(element_type_);
  if (element_size > 1) {
    __ subq(byte_length, Immediate(element_size - 1));
    __ EmitEagerDeoptIf(negative, DeoptimizeReason::kOutOfBounds, this);
  }
  __ cmpl(index, byte_length);
  __ EmitEagerDeoptIf(above_equal, DeoptimizeReason::kOutOfBounds, this);
}

int CheckedObjectToIndex::MaxCallStackArgs() const {
  return MaglevAssembler::ArgumentStackSlotsForCFunctionCall(1);
}

int BuiltinStringFromCharCode::MaxCallStackArgs() const {
  return AllocateDescriptor::GetStackParameterCount();
}
void BuiltinStringFromCharCode::SetValueLocationConstraints() {
  if (code_input().node()->Is<Int32Constant>()) {
    UseAny(code_input());
  } else {
    UseAndClobberRegister(code_input());
    set_temporaries_needed(1);
  }
  DefineAsRegister(this);
}
void BuiltinStringFromCharCode::GenerateCode(MaglevAssembler* masm,
                                             const ProcessingState& state) {
  Register result_string = ToRegister(result());
  if (Int32Constant* constant = code_input().node()->TryCast<Int32Constant>()) {
    int32_t char_code = constant->value() & 0xFFFF;
    if (0 <= char_code && char_code < String::kMaxOneByteCharCode) {
      __ LoadSingleCharacterString(result_string, char_code);
    } else {
      __ AllocateTwoByteString(register_snapshot(), result_string, 1);
      __ movw(
          FieldOperand(result_string, OFFSET_OF_DATA_START(SeqTwoByteString)),
          Immediate(char_code));
    }
  } else {
    MaglevAssembler::TemporaryRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    Register char_code = ToRegister(code_input());
    __ StringFromCharCode(register_snapshot(), nullptr, result_string,
                          char_code, scratch,
                          MaglevAssembler::CharCodeMaskMode::kMustApplyMask);
  }
}

void Int32AddWithOverflow::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineSameAsFirst(this);
}

void Int32AddWithOverflow::GenerateCode(MaglevAssembler* masm,
                                        const ProcessingState& state) {
  Register left = ToRegister(left_input());
  Register right = ToRegister(right_input());
  __ addl(left, right);
  // None of the mutated input registers should be a register input into the
  // eager deopt info.
  DCHECK_REGLIST_EMPTY(RegList{left} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
  __ EmitEagerDeoptIf(overflow, DeoptimizeReason::kOverflow, this);
}

void Int32SubtractWithOverflow::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineSameAsFirst(this);
}

void Int32SubtractWithOverflow::GenerateCode(MaglevAssembler* masm,
                                             const ProcessingState& state) {
  Register left = ToRegister(left_input());
  Register right = ToRegister(right_input());
  __ subl(left, right);
  // None of the mutated input registers should be a register input into the
  // eager deopt info.
  DCHECK_REGLIST_EMPTY(RegList{left} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
  __ EmitEagerDeoptIf(overflow, DeoptimizeReason::kOverflow, this);
}

void Int32MultiplyWithOverflow::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineSameAsFirst(this);
  set_temporaries_needed(1);
}

void Int32MultiplyWithOverflow::GenerateCode(MaglevAssembler* masm,
                                             const ProcessingState& state) {
  Register result = ToRegister(this->result());
  Register right = ToRegister(right_input());
  DCHECK_EQ(result, ToRegister(left_input()));

  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register saved_left = temps.Acquire();
  __ movl(saved_left, result);
  // TODO(leszeks): peephole optimise multiplication by a constant.
  __ imull(result, right);
  // None of the mutated input registers should be a register input into the
  // eager deopt info.
  DCHECK_REGLIST_EMPTY(RegList{saved_left, result} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
  __ EmitEagerDeoptIf(overflow, DeoptimizeReason::kOverflow, this);

  // If the result is zero, check if either lhs or rhs is negative.
  Label end;
  __ cmpl(result, Immediate(0));
  __ j(not_zero, &end);
  {
    __ orl(saved_left, right);
    __ cmpl(saved_left, Immediate(0));
    // If one of them is negative, we must have a -0 result, which is non-int32,
    // so deopt.
    // TODO(leszeks): Consider splitting these deopts to have distinct deopt
    // reasons. Otherwise, the reason has to match the above.
    __ EmitEagerDeoptIf(less, DeoptimizeReason::kOverflow, this);
  }
  __ bind(&end);
}

void Int32ModulusWithOverflow::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseAndClobberRegister(right_input());
  DefineAsFixed(this, rdx);
  // rax,rdx are clobbered by div.
  RequireSpecificTemporary(rax);
  RequireSpecificTemporary(rdx);
}

void Int32ModulusWithOverflow::GenerateCode(MaglevAssembler* masm,
                                            const ProcessingState& state) {
  // If AreAliased(lhs, rhs):
  //   deopt if lhs < 0  // Minus zero.
  //   0
  //
  // Otherwise, use the same algorithm as in EffectControlLinearizer:
  //   if rhs <= 0 then
  //     rhs = -rhs
  //     deopt if rhs == 0
  //   if lhs < 0 then
  //     let lhs_abs = -lhs in
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

  static constexpr DeoptimizeReason deopt_reason =
      DeoptimizeReason::kDivisionByZero;

  if (lhs == rhs) {
    // For the modulus algorithm described above, lhs and rhs must not alias
    // each other.
    __ testl(lhs, lhs);
    // TODO(victorgomes): This ideally should be kMinusZero, but Maglev only
    // allows one deopt reason per IR.
    __ EmitEagerDeoptIf(negative, deopt_reason, this);
    __ Move(ToRegister(result()), 0);
    return;
  }

  DCHECK(!AreAliased(lhs, rhs, rax, rdx));

  ZoneLabelRef done(masm);
  ZoneLabelRef rhs_checked(masm);

  __ cmpl(rhs, Immediate(0));
  __ JumpToDeferredIf(
      less_equal,
      [](MaglevAssembler* masm, ZoneLabelRef rhs_checked, Register rhs,
         Int32ModulusWithOverflow* node) {
        __ negl(rhs);
        __ j(not_zero, *rhs_checked);
        __ EmitEagerDeopt(node, deopt_reason);
      },
      rhs_checked, rhs, this);
  __ bind(*rhs_checked);

  __ cmpl(lhs, Immediate(0));
  __ JumpToDeferredIf(
      less,
      [](MaglevAssembler* masm, ZoneLabelRef done, Register lhs, Register rhs,
         Int32ModulusWithOverflow* node) {
        // `divl(divisor)` divides rdx:rax by the divisor and stores the
        // quotient in rax, the remainder in rdx.
        __ movl(rax, lhs);
        __ negl(rax);
        __ xorl(rdx, rdx);
        __ divl(rhs);
        __ negl(rdx);
        __ j(not_zero, *done);
        // TODO(victorgomes): This ideally should be kMinusZero, but Maglev only
        // allows one deopt reason per IR.
        __ EmitEagerDeopt(node, deopt_reason);
      },
      done, lhs, rhs, this);

  Label rhs_not_power_of_2;
  Register mask = rax;
  __ leal(mask, Operand(rhs, -1));
  __ testl(rhs, mask);
  __ j(not_zero, &rhs_not_power_of_2, Label::kNear);

  // {rhs} is power of 2.
  __ andl(mask, lhs);
  __ movl(ToRegister(result()), mask);
  __ jmp(*done, Label::kNear);

  __ bind(&rhs_not_power_of_2);
  // `divl(divisor)` divides rdx:rax by the divisor and stores the
  // quotient in rax, the remainder in rdx.
  __ movl(rax, lhs);
  __ xorl(rdx, rdx);
  __ divl(rhs);
  // Result is implicitly written to rdx.
  DCHECK_EQ(ToRegister(result()), rdx);

  __ bind(*done);
}

void Int32DivideWithOverflow::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsFixed(this, rax);
  // rax,rdx are clobbered by idiv.
  RequireSpecificTemporary(rax);
  RequireSpecificTemporary(rdx);
}

void Int32DivideWithOverflow::GenerateCode(MaglevAssembler* masm,
                                           const ProcessingState& state) {
  Register left = ToRegister(left_input());
  Register right = ToRegister(right_input());
  __ movl(rax, left);

  // TODO(leszeks): peephole optimise division by a constant.

  // Sign extend eax into edx.
  __ cdq();

  // Pre-check for overflow, since idiv throws a division exception on overflow
  // rather than setting the overflow flag. Logic copied from
  // effect-control-linearizer.cc

  // Check if {right} is positive (and not zero).
  __ cmpl(right, Immediate(0));
  ZoneLabelRef done(masm);
  __ JumpToDeferredIf(
      less_equal,
      [](MaglevAssembler* masm, ZoneLabelRef done, Register right,
         Int32DivideWithOverflow* node) {
        // {right} is negative or zero.

        // Check if {right} is zero.
        // We've already done the compare and flags won't be cleared yet.
        // TODO(leszeks): Using kNotInt32 here, but kDivisionByZero would be
        // better. Right now all eager deopts in a node have to be the same --
        // we should allow a node to emit multiple eager deopts with different
        // reasons.
        __ EmitEagerDeoptIf(equal, DeoptimizeReason::kNotInt32, node);

        // Check if {left} is zero, as that would produce minus zero. Left is in
        // rax already.
        __ cmpl(rax, Immediate(0));
        // TODO(leszeks): Better DeoptimizeReason = kMinusZero.
        __ EmitEagerDeoptIf(equal, DeoptimizeReason::kNotInt32, node);

        // Check if {left} is kMinInt and {right} is -1, in which case we'd have
        // to return -kMinInt, which is not representable as Int32.
        __ cmpl(rax, Immediate(kMinInt));
        __ j(not_equal, *done);
        __ cmpl(right, Immediate(-1));
        __ j(not_equal, *done);
        // TODO(leszeks): Better DeoptimizeReason = kOverflow, but
        // eager_deopt_info is already configured as kNotInt32.
        __ EmitEagerDeopt(node, DeoptimizeReason::kNotInt32);
      },
      done, right, this);
  __ bind(*done);

  // Perform the actual integer division.
  __ idivl(right);

  // Check that the remainder is zero.
  __ cmpl(rdx, Immediate(0));
  // None of the mutated input registers should be a register input into the
  // eager deopt info.
  DCHECK_REGLIST_EMPTY(RegList{rax, rdx} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
  __ EmitEagerDeoptIf(not_equal, DeoptimizeReason::kNotInt32, this);
  DCHECK_EQ(ToRegister(result()), rax);
}

#define DEF_BITWISE_BINOP(Instruction, opcode)                   \
  void Instruction::SetValueLocationConstraints() {              \
    UseRegister(left_input());                                   \
    UseRegister(right_input());                                  \
    DefineSameAsFirst(this);                                     \
  }                                                              \
                                                                 \
  void Instruction::GenerateCode(MaglevAssembler* masm,          \
                                 const ProcessingState& state) { \
    Register left = ToRegister(left_input());                    \
    Register right = ToRegister(right_input());                  \
    __ opcode(left, right);                                      \
  }
DEF_BITWISE_BINOP(Int32BitwiseAnd, andl)
DEF_BITWISE_BINOP(Int32BitwiseOr, orl)
DEF_BITWISE_BINOP(Int32BitwiseXor, xorl)
#undef DEF_BITWISE_BINOP

#define DEF_SHIFT_BINOP(Instruction, opcode)                     \
  void Instruction::SetValueLocationConstraints() {              \
    UseRegister(left_input());                                   \
    if (right_input().node()->Is<Int32Constant>()) {             \
      UseAny(right_input());                                     \
    } else {                                                     \
      UseFixed(right_input(), rcx);                              \
    }                                                            \
    DefineSameAsFirst(this);                                     \
  }                                                              \
                                                                 \
  void Instruction::GenerateCode(MaglevAssembler* masm,          \
                                 const ProcessingState& state) { \
    Register left = ToRegister(left_input());                    \
    if (Int32Constant* constant =                                \
            right_input().node()->TryCast<Int32Constant>()) {    \
      int right = constant->value() & 31;                        \
      if (right != 0) {                                          \
        __ opcode(left, Immediate(right));                       \
      }                                                          \
    } else {                                                     \
      DCHECK_EQ(rcx, ToRegister(right_input()));                 \
      __ opcode##_cl(left);                                      \
    }                                                            \
  }
DEF_SHIFT_BINOP(Int32ShiftLeft, shll)
DEF_SHIFT_BINOP(Int32ShiftRight, sarl)
DEF_SHIFT_BINOP(Int32ShiftRightLogical, shrl)
#undef DEF_SHIFT_BINOP

void Int32IncrementWithOverflow::SetValueLocationConstraints() {
  UseRegister(value_input());
  DefineSameAsFirst(this);
}

void Int32IncrementWithOverflow::GenerateCode(MaglevAssembler* masm,
                                              const ProcessingState& state) {
  Register value = ToRegister(value_input());
  __ incl(value);
  __ EmitEagerDeoptIf(overflow, DeoptimizeReason::kOverflow, this);
}

void Int32DecrementWithOverflow::SetValueLocationConstraints() {
  UseRegister(value_input());
  DefineSameAsFirst(this);
}

void Int32DecrementWithOverflow::GenerateCode(MaglevAssembler* masm,
                                              const ProcessingState& state) {
  Register value = ToRegister(value_input());
  __ decl(value);
  __ EmitEagerDeoptIf(overflow, DeoptimizeReason::kOverflow, this);
}

void Int32NegateWithOverflow::SetValueLocationConstraints() {
  UseRegister(value_input());
  DefineSameAsFirst(this);
}

void Int32NegateWithOverflow::GenerateCode(MaglevAssembler* masm,
                                           const ProcessingState& state) {
  Register value = ToRegister(value_input());
  // Deopt when the result would be -0.
  __ testl(value, value);
  __ EmitEagerDeoptIf(zero, DeoptimizeReason::kOverflow, this);

  __ negl(value);
  __ EmitEagerDeoptIf(overflow, DeoptimizeReason::kOverflow, this);
}

void Int32AbsWithOverflow::GenerateCode(MaglevAssembler* masm,
                                        const ProcessingState& state) {
  Register value = ToRegister(result());
  Label done;
  __ cmpl(value, Immediate(0));
  __ j(greater_equal, &done);
  __ negl(value);
  __ EmitEagerDeoptIf(overflow, DeoptimizeReason::kOverflow, this);
  __ bind(&done);
}

void Int32BitwiseNot::SetValueLocationConstraints() {
  UseRegister(value_input());
  DefineSameAsFirst(this);
}

void Int32BitwiseNot::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  Register value = ToRegister(value_input());
  __ notl(value);
}

void Float64Add::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineSameAsFirst(this);
}

void Float64Add::GenerateCode(MaglevAssembler* masm,
                              const ProcessingState& state) {
  DoubleRegister left = ToDoubleRegister(left_input());
  DoubleRegister right = ToDoubleRegister(right_input());
  __ Addsd(left, right);
}

void Float64Subtract::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineSameAsFirst(this);
}

void Float64Subtract::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  DoubleRegister left = ToDoubleRegister(left_input());
  DoubleRegister right = ToDoubleRegister(right_input());
  __ Subsd(left, right);
}

void Float64Multiply::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineSameAsFirst(this);
}

void Float64Multiply::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  DoubleRegister left = ToDoubleRegister(left_input());
  DoubleRegister right = ToDoubleRegister(right_input());
  __ Mulsd(left, right);
}

void Float64Divide::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineSameAsFirst(this);
}

void Float64Divide::GenerateCode(MaglevAssembler* masm,
                                 const ProcessingState& state) {
  DoubleRegister left = ToDoubleRegister(left_input());
  DoubleRegister right = ToDoubleRegister(right_input());
  __ Divsd(left, right);
}

void Float64Modulus::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  RequireSpecificTemporary(rax);
  DefineAsRegister(this);
}

void Float64Modulus::GenerateCode(MaglevAssembler* masm,
                                  const ProcessingState& state) {
  // Approach copied from code-generator-x64.cc
  // Allocate space to use fld to move the value to the FPU stack.
  __ AllocateStackSpace(kDoubleSize);
  Operand scratch_stack_space = Operand(rsp, 0);
  __ Movsd(scratch_stack_space, ToDoubleRegister(right_input()));
  __ fld_d(scratch_stack_space);
  __ Movsd(scratch_stack_space, ToDoubleRegister(left_input()));
  __ fld_d(scratch_stack_space);
  // Loop while fprem isn't done.
  Label mod_loop;
  __ bind(&mod_loop);
  // This instructions traps on all kinds inputs, but we are assuming the
  // floating point control word is set to ignore them all.
  __ fprem();
  // The following 2 instruction implicitly use rax.
  __ fnstsw_ax();
  if (CpuFeatures::IsSupported(SAHF)) {
    CpuFeatureScope sahf_scope(masm, SAHF);
    __ sahf();
  } else {
    __ shrl(rax, Immediate(8));
    __ andl(rax, Immediate(0xFF));
    __ pushq(rax);
    __ popfq();
  }
  __ j(parity_even, &mod_loop);
  // Move output to stack and clean up.
  __ fstp(1);
  __ fstp_d(scratch_stack_space);
  __ Movsd(ToDoubleRegister(result()), scratch_stack_space);
  __ addq(rsp, Immediate(kDoubleSize));
}

void Float64Negate::SetValueLocationConstraints() {
  UseRegister(input());
  DefineSameAsFirst(this);
}

void Float64Negate::GenerateCode(MaglevAssembler* masm,
                                 const ProcessingState& state) {
  DoubleRegister value = ToDoubleRegister(input());
  __ Negpd(value, value, kScratchRegister);
}

void Float64Abs::GenerateCode(MaglevAssembler* masm,
                              const ProcessingState& state) {
  DoubleRegister out = ToDoubleRegister(result());
  __ Abspd(out, out, kScratchRegister);
}

void Float64Round::GenerateCode(MaglevAssembler* masm,
                                const ProcessingState& state) {
  DoubleRegister in = ToDoubleRegister(input());
  DoubleRegister out = ToDoubleRegister(result());

  if (kind_ == Kind::kNearest) {
    MaglevAssembler::TemporaryRegisterScope temps(masm);
    DoubleRegister temp = temps.AcquireDouble();
    __ Move(temp, in);
    __ Roundsd(out, in, kRoundToNearest);
    // RoundToNearest rounds to even on tie, while JS expects it to round
    // towards +Infinity. Fix the difference by checking if we rounded down by
    // exactly 0.5, and if so, round to the other side.
    __ Subsd(temp, out);
    __ Move(kScratchDoubleReg, 0.5);
    Label done;
    __ Ucomisd(temp, kScratchDoubleReg);
    __ JumpIf(not_equal, &done, Label::kNear);
    // Fix wrong tie-to-even by adding 0.5 twice.
    __ Addsd(out, kScratchDoubleReg);
    __ Addsd(out, kScratchDoubleReg);
    __ bind(&done);
  } else if (kind_ == Kind::kFloor) {
    __ Roundsd(out, in, kRoundDown);
  } else if (kind_ == Kind::kCeil) {
    __ Roundsd(out, in, kRoundUp);
  }
}

int Float64Exponentiate::MaxCallStackArgs() const {
  return MaglevAssembler::ArgumentStackSlotsForCFunctionCall(2);
}
void Float64Exponentiate::SetValueLocationConstraints() {
  UseFixed(left_input(), xmm0);
  UseFixed(right_input(), xmm1);
  DefineSameAsFirst(this);
}
void Float64Exponentiate::GenerateCode(MaglevAssembler* masm,
                                       const ProcessingState& state) {
  AllowExternalCallThatCantCauseGC scope(masm);
  __ PrepareCallCFunction(2);
  __ CallCFunction(ExternalReference::ieee754_pow_function(), 2);
}

int Float64Ieee754Unary::MaxCallStackArgs() const {
  return MaglevAssembler::ArgumentStackSlotsForCFunctionCall(1);
}
void Float64Ieee754Unary::SetValueLocationConstraints() {
  UseFixed(input(), xmm0);
  DefineSameAsFirst(this);
}
void Float64Ieee754Unary::GenerateCode(MaglevAssembler* masm,
                                       const ProcessingState& state) {
  AllowExternalCallThatCantCauseGC scope(masm);
  __ PrepareCallCFunction(1);
  __ CallCFunction(ieee_function_ref(), 1);
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
  __ Xorpd(kScratchDoubleReg, kScratchDoubleReg);
  __ Subsd(value, kScratchDoubleReg);
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
    __ cmpq(rsp, __ StackLimitAsOperand(StackLimitKind::kInterruptStackLimit));
    __ j(above, &next);

    // An interrupt has been requested and we must call into runtime to handle
    // it; since we already pay the call cost, combine with the TieringManager
    // call.
    {
      SaveRegisterStateForCall save_register_state(masm,
                                                   node->register_snapshot());
      __ Move(kContextRegister, masm->native_context().object());
      __ Push(MemOperand(rbp, StandardFrameConstants::kFunctionOffset));
      __ CallRuntime(Runtime::kBytecodeBudgetInterruptWithStackCheck_Maglev, 1);
      save_register_state.DefineSafepointWithLazyDeopt(node->lazy_deopt_info());
    }
    __ jmp(*done);  // All done, continue.

    __ bind(&next);
  }

  // No pending interrupts. Call into the TieringManager if needed.
  {
    SaveRegisterStateForCall save_register_state(masm,
                                                 node->register_snapshot());
    __ Move(kContextRegister, masm->native_context().object());
    __ Push(MemOperand(rbp, StandardFrameConstants::kFunctionOffset));
    // Note: must not cause a lazy deopt!
    __ CallRuntime(Runtime::kBytecodeBudgetInterrupt_Maglev, 1);
    save_register_state.DefineSafepoint();
  }
  __ jmp(*done);
}

void GenerateReduceInterruptBudget(MaglevAssembler* masm, Node* node,
                                   ReduceInterruptBudgetType type, int amount) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.Acquire();
  __ movq(scratch, MemOperand(rbp, StandardFrameConstants::kFunctionOffset));
  __ LoadTaggedField(scratch,
                     FieldOperand(scratch, JSFunction::kFeedbackCellOffset));
  __ subl(FieldOperand(scratch, FeedbackCell::kInterruptBudgetOffset),
          Immediate(amount));
  ZoneLabelRef done(masm);
  __ JumpToDeferredIf(less, HandleInterruptsAndTiering, done, node, type,
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
  Register actual_params_size = r8;

  // Compute the size of the actual parameters + receiver (in bytes).
  // TODO(leszeks): Consider making this an input into Return to re-use the
  // incoming argc's register (if it's still valid).
  __ movq(actual_params_size,
          MemOperand(rbp, StandardFrameConstants::kArgCOffset));

  // Leave the frame.
  __ LeaveFrame(StackFrame::MAGLEV);

  // If actual is bigger than formal, then we should use it to free up the stack
  // arguments.
  Label drop_dynamic_arg_size;
  __ cmpq(actual_params_size, Immediate(formal_params_size));
  __ j(greater, &drop_dynamic_arg_size);

  // Drop receiver + arguments according to static formal arguments size.
  __ Ret(formal_params_size * kSystemPointerSize, kScratchRegister);

  __ bind(&drop_dynamic_arg_size);
  // Drop receiver + arguments according to dynamic arguments size.
  __ DropArguments(actual_params_size, r9);
  __ Ret();
}

}  // namespace maglev
}  // namespace internal
}  // namespace v8
```