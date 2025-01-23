Response: Let's break down the thought process for summarizing this C++ file and connecting it to JavaScript.

1. **Understand the Context:** The first clue is the directory: `v8/src/maglev/x64/`. This immediately tells us we're dealing with V8 (the JavaScript engine), specifically the Maglev compiler (a newer tier in V8's compilation pipeline), and even more specifically, the x64 architecture implementation for Maglev. The `.cc` extension confirms it's a C++ source file.

2. **Identify the Core Purpose:** The filename `maglev-ir-x64.cc` is also very informative. "IR" stands for Intermediate Representation. This suggests the file is responsible for defining and generating code for the Maglev compiler's internal representation of code, tailored for the x64 architecture.

3. **Scan for Key Structures and Patterns:**  Quickly skim through the code, looking for recurring patterns and keywords:
    * **`class ... : public ...`:**  Lots of class definitions. These likely represent different operations or nodes in the IR.
    * **`SetValueLocationConstraints()`:**  This function name is repeated within each class. It suggests managing how values are stored (registers, stack). The name implies rules or restrictions.
    * **`GenerateCode(MaglevAssembler* masm, const ProcessingState& state)`:**  Another repeated function, and the name is a dead giveaway. This is the core of the code generation process. `MaglevAssembler` likely provides the interface for emitting x64 assembly instructions.
    * **`#define __ masm->`:** A macro to simplify writing assembler instructions.
    * **`__ movq`, `__ addl`, `__ subsd`, etc.:** These are x64 assembly instructions (move quad-word, add long, subtract scalar double-precision float, etc.). This confirms the code generation aspect.
    * **JavaScript-related terms:**  `ArgumentsLength`, `RestLength`, `LoadTypedArrayLength`, `CheckJSDataViewBounds`, `BuiltinStringFromCharCode`. These directly relate to JavaScript features.
    * **Math operations with overflow checks:**  `Int32AddWithOverflow`, `Int32MultiplyWithOverflow`, etc. This points to handling potential errors in integer arithmetic.
    * **Float operations:** `Float64Add`, `Float64Subtract`, etc.
    * **Control flow:** `Return`.
    * **Tiering/Interrupts:** `ReduceInterruptBudgetForLoop`, `ReduceInterruptBudgetForReturn`. This hints at V8's optimization and interruption handling.

4. **Infer Functionality from Class Names and Code:**  Based on the identified patterns, start grouping related classes and infer their purpose:
    * **Allocation:** `InlinedAllocation` -  Handles allocating memory.
    * **Arguments:** `ArgumentsLength`, `RestLength` -  Deals with function arguments.
    * **Typed Arrays/Data Views:** `LoadTypedArrayLength`, `CheckJSDataViewBounds` - Implements operations specific to JavaScript's typed arrays and data views.
    * **String Operations:** `BuiltinStringFromCharCode` -  Generates code for converting character codes to strings.
    * **Integer Arithmetic:** `Int32AddWithOverflow`, `Int32SubtractWithOverflow`, etc. - Implements integer arithmetic with overflow checks.
    * **Bitwise Operations:** `Int32BitwiseAnd`, `Int32BitwiseOr`, etc.
    * **Shift Operations:** `Int32ShiftLeft`, `Int32ShiftRight`, etc.
    * **Floating-Point Arithmetic:** `Float64Add`, `Float64Subtract`, etc. - Implements floating-point operations.
    * **Control Flow:** `Return` - Handles function returns.
    * **Optimization/Management:** `ReduceInterruptBudgetForLoop`, `ReduceInterruptBudgetForReturn` -  Manages the execution budget and handles potential interruptions for optimization.

5. **Formulate the Summary:** Combine the inferences into a concise description of the file's purpose. Emphasize the core functionality: generating x64 assembly code for Maglev's IR. Mention the key categories of operations handled.

6. **Connect to JavaScript with Examples:**  This is where the JavaScript-related terms become crucial. For each key area identified, think of a simple JavaScript code snippet that would trigger the corresponding IR node:
    * **Arguments:** A function using `arguments` or rest parameters.
    * **Typed Arrays:** Creating and accessing a typed array's length.
    * **Data Views:**  Creating and accessing a data view with bounds checking.
    * **`String.fromCharCode()`:** Directly use this function.
    * **Integer Arithmetic with Overflow:**  Perform integer operations that might overflow (though JavaScript's standard numbers are floats, these nodes likely represent optimized cases or internal representations).
    * **Floating-Point Arithmetic:**  Basic floating-point operations.

7. **Refine and Organize:** Review the summary and examples for clarity and accuracy. Ensure the examples clearly demonstrate the connection between the C++ code and JavaScript functionality. Structure the answer logically with clear headings.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This is just low-level assembly generation."
* **Correction:** "While it *is* assembly generation, it's specifically for Maglev's IR and tied to JavaScript semantics."  The presence of nodes like `ArgumentsLength` and `BuiltinStringFromCharCode` makes it more than just raw assembly generation.
* **Initial thought about examples:**  Just show any JavaScript code.
* **Correction:**  Focus on *specific* JavaScript features that directly relate to the C++ classes. This makes the connection much clearer. For instance, instead of just `a + b`, show how `arguments.length` relates to `ArgumentsLength`.
* **Consider the audience:** The prompt asks for a summary and examples understandable to someone familiar with JavaScript but perhaps not V8 internals. Avoid overly technical jargon where simpler explanations suffice.

By following these steps and actively thinking about the purpose and connections, you can arrive at a comprehensive and accurate summary like the example provided in the initial prompt.
这个C++源代码文件 `v8/src/maglev/x64/maglev-ir-x64.cc`  定义了 **Maglev 编译器在 x64 架构下所使用的中间表示 (IR) 节点的具体实现和代码生成逻辑。**

**更具体地说，它做了以下几件事：**

1. **定义了各种 Maglev IR 节点在 x64 架构下的行为:**  每个 `class` (例如 `InlinedAllocation`, `ArgumentsLength`, `Int32AddWithOverflow`, `Float64Add`, `Return` 等) 都代表 Maglev IR 中的一个操作或概念。这个文件为这些节点提供了 x64 架构特定的实现。

2. **实现了节点的 `SetValueLocationConstraints()` 方法:**  这个方法定义了在代码生成过程中，节点的值应该如何存储（例如，在寄存器中、在栈上、或者与某个输入相同的位置）。这对于寄存器分配和代码优化至关重要。

3. **实现了节点的 `GenerateCode(MaglevAssembler* masm, const ProcessingState& state)` 方法:** 这是核心功能。这个方法负责将 Maglev IR 节点翻译成实际的 x64 汇编代码。它使用 `MaglevAssembler` 类来生成机器指令。

**与 JavaScript 功能的关系:**

Maglev 是 V8 引擎中的一个中间层编译器，它接收从 Ignition (解释器) 或 TurboFan (优化编译器) 传递过来的字节码或 IR，并生成更优化的机器码。 因此，`maglev-ir-x64.cc` 中定义的每个 IR 节点都对应着某些 JavaScript 语言特性或操作。

**JavaScript 示例:**

下面是一些 JavaScript 例子，以及它们可能对应在 `maglev-ir-x64.cc` 中的 IR 节点：

1. **获取函数参数的长度:**

   ```javascript
   function foo(a, b, c) {
     console.log(arguments.length); // 输出 3
   }
   foo(1, 2, 3);
   ```

   * **对应的 IR 节点 (可能):** `ArgumentsLength`。  `ArgumentsLength::GenerateCode` 方法会生成 x64 代码来获取 `arguments` 对象的长度。

2. **使用剩余参数 (rest parameters):**

   ```javascript
   function bar(a, ...rest) {
     console.log(rest.length);
   }
   bar(1, 2, 3, 4); // 输出 3
   ```

   * **对应的 IR 节点 (可能):** `RestLength`。 `RestLength::GenerateCode` 方法会生成 x64 代码来计算剩余参数的长度。

3. **创建 Typed Array 并获取其长度:**

   ```javascript
   const typedArray = new Uint32Array(10);
   console.log(typedArray.length); // 输出 10
   ```

   * **对应的 IR 节点 (可能):** `LoadTypedArrayLength`。 `LoadTypedArrayLength::GenerateCode` 方法会生成 x64 代码来加载 Typed Array 的长度。

4. **进行整数加法并处理溢出 (虽然 JavaScript 的 Number 是浮点数，但 V8 内部可能对某些整数操作进行优化):**

   ```javascript
   let x = 2147483647; // 32位有符号整数的最大值
   let y = 1;
   let z = x + y;
   // 在 JavaScript 中，这会变成一个浮点数，但在 V8 内部可能先尝试整数加法
   ```

   * **对应的 IR 节点 (可能):** `Int32AddWithOverflow`。 `Int32AddWithOverflow::GenerateCode` 方法会生成 x64 代码来进行整数加法并检查溢出。如果发生溢出，可能会触发去优化 (deoptimization)。

5. **进行浮点数加法:**

   ```javascript
   let a = 1.5;
   let b = 2.5;
   let c = a + b; // 4
   ```

   * **对应的 IR 节点 (可能):** `Float64Add`。 `Float64Add::GenerateCode` 方法会生成 x64 代码来进行浮点数加法。

6. **函数返回:**

   ```javascript
   function add(a, b) {
     return a + b;
   }
   ```

   * **对应的 IR 节点 (可能):** `Return`。 `Return::GenerateCode` 方法会生成 x64 代码来进行函数返回，包括清理栈帧等操作。

**总结:**

`v8/src/maglev/x64/maglev-ir-x64.cc` 是 Maglev 编译器在 x64 架构下的蓝图，它详细定义了如何将 JavaScript 的各种操作转换成高效的机器码。理解这个文件有助于深入了解 V8 引擎的编译过程和性能优化。

### 提示词
```
这是目录为v8/src/maglev/x64/maglev-ir-x64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
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