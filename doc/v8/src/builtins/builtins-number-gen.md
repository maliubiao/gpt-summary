Response: Let's break down the thought process for analyzing this C++ code.

1. **Understand the Context:** The filename `builtins-number-gen.cc` and the directory `v8/src/builtins` immediately tell us this code is part of V8, the JavaScript engine used in Chrome and Node.js. The "builtins" part suggests it implements fundamental JavaScript operations. The "-gen" suffix often indicates generated code or code that sets up built-in functions.

2. **Identify Key Structures:** The most striking feature is the repeated use of macros: `DEF_BINOP`, `DEF_BINOP_RHS_SMI`, `DEF_UNOP`, and `DEF_COMPARE`. These macros are clearly used to define built-in functions concisely. This suggests a pattern and that the file's purpose is to define a set of operations.

3. **Analyze the Macros:**
    * **`DEF_BINOP`:**  This macro defines binary operations (taking two operands). It takes a `Name` (e.g., `Add_WithFeedback`) and a `Generator` (e.g., `Generate_AddWithFeedback`). The generated code fetches parameters (`lhs`, `rhs`, `context`, `feedback_vector`, `slot`), creates a `BinaryOpAssembler`, calls the `Generator` with specific arguments (including feedback), and returns the result. The "WithFeedback" and "Baseline" variants suggest different optimization levels or execution paths.
    * **`DEF_BINOP_RHS_SMI`:** Similar to `DEF_BINOP` but the name suggests it might be optimized for cases where the right-hand side is a Small Integer (Smi), a common optimization in V8.
    * **`DEF_UNOP`:**  Defines unary operations (taking one operand). It follows a similar pattern to `DEF_BINOP` using `UnaryOpAssembler`.
    * **`DEF_COMPARE`:** Defines comparison operations. It includes error handling using `ScopedExceptionHandler` and updates feedback.

4. **Identify the Operations:**  By looking at the `Name` arguments to the macros, we can list the supported operations:
    * **Binary:** Add, Subtract, Multiply, Divide, Modulus, Exponentiate, Bitwise OR, Bitwise XOR, Bitwise AND, Shift Left, Shift Right, Shift Right Logical. These all have "WithFeedback", "Baseline", and some even "Smi_Baseline" variants.
    * **Unary:** Bitwise NOT, Decrement, Increment, Negate (with "WithFeedback" and "Baseline").
    * **Comparison:** Less Than, Less Than Or Equal, Greater Than, Greater Than Or Equal, Equal, Strict Equal (with "WithFeedback" and "Baseline").

5. **Connect to JavaScript:**  The names of the operations directly correspond to JavaScript operators. `Add_WithFeedback` is clearly related to `+`, `Subtract_WithFeedback` to `-`, and so on.

6. **Understand "WithFeedback" and "Baseline":** The presence of these suffixes is crucial. V8 uses feedback vectors to optimize code execution. The "WithFeedback" versions likely collect information about the types of operands to inform future optimizations. "Baseline" might represent a less optimized but still efficient execution path. The code loading `FeedbackVector` and `Context` reinforces this idea.

7. **CodeStubAssembler (CSA):** The code uses `CodeStubAssembler`. A quick search or prior knowledge reveals that CSA is V8's internal assembly language, allowing for low-level, efficient implementation of built-in functions.

8. **Illustrative JavaScript Examples:**  Now, to demonstrate the connection to JavaScript, we need to provide examples that would trigger the execution of these built-in functions. Simple arithmetic, bitwise operations, and comparisons with numbers are the direct counterparts. It's important to illustrate both binary and unary operations, and different comparison types.

9. **Structure the Summary:**  Finally, organize the findings into a clear and concise summary. Start with the main purpose of the file, then detail the operations, explain the "WithFeedback" and "Baseline" concepts, mention the use of CSA, and provide the JavaScript examples.

**Self-Correction/Refinement During Analysis:**

* **Initial thought:**  Maybe this file *generates* code. While the filename suggests it, the content focuses more on *defining* the built-in functions using a code generation approach with macros. The `CodeStubAssembler` directly creates the machine code or intermediate representation.
* **Clarifying "Baseline":** Initially, I might think "Baseline" is unoptimized. However, it's likely a stage in V8's tiered compilation, representing a functional but perhaps less aggressively optimized version compared to fully optimized code.
* **Focus on Numbers:**  The directory and filename clearly indicate these built-ins are *specifically* for number operations. While JavaScript's operators are more general, V8 has optimized paths for numeric operations.

By following this thought process, which combines code analysis, knowledge of V8 internals (or looking up key terms), and connecting the C++ implementation to JavaScript concepts, we can arrive at the comprehensive summary provided in the initial prompt's good answer.
这个C++源代码文件 `builtins-number-gen.cc` 是 V8 JavaScript 引擎的一部分，其主要功能是**定义和生成用于处理 JavaScript Number 对象的内置函数 (built-ins)**。  更具体地说，它定义了各种与数字相关的操作，例如算术运算、位运算和比较运算。

**核心功能归纳:**

1. **定义数字运算的内置函数:** 文件中大量使用了宏 (`DEF_BINOP`, `DEF_UNOP`, `DEF_COMPARE`) 来定义各种内置函数。这些宏简化了为不同操作生成相似结构代码的过程。
2. **处理带反馈 (WithFeedback) 和基线 (Baseline) 的操作:**  文件中定义了两种版本的内置函数：
    * **`_WithFeedback` 版本:**  这些版本在执行操作的同时收集类型反馈信息。这些反馈信息被 V8 引擎用于优化后续的相同操作，例如，如果 V8 发现某个加法操作总是发生在两个整数之间，它可以生成更优化的代码。
    * **`_Baseline` 版本:** 这些版本通常用于优化的早期阶段或当没有足够的反馈信息时。它们提供了一种相对高效的执行路径。
3. **支持二元运算 (Binary Operations):**  `DEF_BINOP` 宏用于定义诸如加法、减法、乘法、除法、取模、幂运算以及各种位运算（OR, XOR, AND, 左移, 右移, 无符号右移）等二元操作符的内置函数。
4. **支持一元运算 (Unary Operations):** `DEF_UNOP` 宏用于定义诸如按位取反、自减、自增和取负等一元操作符的内置函数。
5. **支持比较运算 (Comparison Operations):** `DEF_COMPARE` 宏用于定义诸如小于、小于等于、大于、大于等于以及相等和严格相等比较操作符的内置函数。
6. **利用 CodeStubAssembler (CSA):**  这些内置函数是使用 V8 的 `CodeStubAssembler` (CSA) 来实现的。CSA 是一种用于生成高效机器码的内部 DSL (领域特定语言)。
7. **与反馈向量 (FeedbackVector) 和上下文 (Context) 交互:**  带有 `_WithFeedback` 后缀的内置函数会接收 `FeedbackVector` 和 `Context` 参数，用于更新反馈信息和访问当前执行上下文。
8. **优化特定场景 (例如 `_RHS_SMI`):**  存在一些针对特定场景的优化，例如 `DEF_BINOP_RHS_SMI` 宏定义的版本，它可能针对右操作数是小整数 (Smi, Small Integer) 的情况进行优化。

**与 JavaScript 的关系及示例:**

这个文件定义的 C++ 内置函数直接对应于 JavaScript 中对数字执行的操作。当你在 JavaScript 代码中对数字进行运算或比较时，V8 引擎很可能会调用这里定义的相应的 C++ 内置函数来执行这些操作。

**JavaScript 示例:**

```javascript
// 算术运算
let a = 10;
let b = 5;
let sum = a + b; // 对应 Add_WithFeedback 或 Add_Baseline
let difference = a - b; // 对应 Subtract_WithFeedback 或 Subtract_Baseline
let product = a * b; // 对应 Multiply_WithFeedback 或 Multiply_Baseline
let quotient = a / b; // 对应 Divide_WithFeedback 或 Divide_Baseline
let remainder = a % b; // 对应 Modulus_WithFeedback 或 Modulus_Baseline
let exponent = a ** b; // 对应 Exponentiate_WithFeedback 或 Exponentiate_Baseline

// 位运算
let c = 7;  // 二进制 0111
let d = 3;  // 二进制 0011
let orResult = c | d;  // 对应 BitwiseOr_WithFeedback 或 BitwiseOr_Baseline
let xorResult = c ^ d; // 对应 BitwiseXor_WithFeedback 或 BitwiseXor_Baseline
let andResult = c & d; // 对应 BitwiseAnd_WithFeedback 或 BitwiseAnd_Baseline
let leftShift = c << 1; // 对应 ShiftLeft_WithFeedback 或 ShiftLeft_Baseline
let rightShift = c >> 1; // 对应 ShiftRight_WithFeedback 或 ShiftRight_Baseline
let unsignedRightShift = c >>> 1; // 对应 ShiftRightLogical_WithFeedback 或 ShiftRightLogical_Baseline
let notResult = ~c; // 对应 BitwiseNot_WithFeedback 或 BitwiseNot_Baseline

// 自增自减
let counter = 0;
counter++; // 对应 Increment_WithFeedback 或 Increment_Baseline
counter--; // 对应 Decrement_WithFeedback 或 Decrement_Baseline

// 取负
let negativeA = -a; // 对应 Negate_WithFeedback 或 Negate_Baseline

// 比较运算
let isEqual = a == b; // 对应 Equal_WithFeedback 或 Equal_Baseline
let isStrictEqual = a === b; // 对应 StrictEqual_WithFeedback 或 StrictEqual_Baseline
let isLessThan = a < b; // 对应 LessThan_WithFeedback 或 LessThan_Baseline
let isGreaterThan = a > b; // 对应 GreaterThan_WithFeedback 或 GreaterThan_Baseline
let isLessThanOrEqual = a <= b; // 对应 LessThanOrEqual_WithFeedback 或 LessThanOrEqual_Baseline
let isGreaterThanOrEqual = a >= b; // 对应 GreaterThanOrEqual_WithFeedback 或 GreaterThanOrEqual_Baseline
```

**总结:**

`builtins-number-gen.cc` 文件是 V8 引擎中至关重要的组成部分，它定义了 JavaScript 中数字操作的基础实现。通过使用宏和 `CodeStubAssembler`，它高效地生成了用于执行这些操作的内置函数，并利用反馈机制来优化代码执行。每当你对 JavaScript 中的数字进行操作时，幕后很可能就有这个文件中的 C++ 代码在辛勤工作。

### 提示词
```
这是目录为v8/src/builtins/builtins-number-gen.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins-utils-gen.h"
#include "src/builtins/builtins.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/ic/binary-op-assembler.h"
#include "src/ic/unary-op-assembler.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

// -----------------------------------------------------------------------------
// ES6 section 20.1 Number Objects

#define DEF_BINOP(Name, Generator)                                           \
  TF_BUILTIN(Name, CodeStubAssembler) {                                      \
    auto lhs = Parameter<Object>(Descriptor::kLeft);                         \
    auto rhs = Parameter<Object>(Descriptor::kRight);                        \
    auto context = Parameter<Context>(Descriptor::kContext);                 \
    auto feedback_vector =                                                   \
        Parameter<FeedbackVector>(Descriptor::kFeedbackVector);              \
    auto slot = UncheckedParameter<UintPtrT>(Descriptor::kSlot);             \
                                                                             \
    BinaryOpAssembler binop_asm(state());                                    \
    TNode<Object> result =                                                   \
        binop_asm.Generator([&]() { return context; }, lhs, rhs, slot,       \
                            [&]() { return feedback_vector; },               \
                            UpdateFeedbackMode::kGuaranteedFeedback, false); \
                                                                             \
    Return(result);                                                          \
  }
DEF_BINOP(Add_WithFeedback, Generate_AddWithFeedback)
DEF_BINOP(Subtract_WithFeedback, Generate_SubtractWithFeedback)
DEF_BINOP(Multiply_WithFeedback, Generate_MultiplyWithFeedback)
DEF_BINOP(Divide_WithFeedback, Generate_DivideWithFeedback)
DEF_BINOP(Modulus_WithFeedback, Generate_ModulusWithFeedback)
DEF_BINOP(Exponentiate_WithFeedback, Generate_ExponentiateWithFeedback)
DEF_BINOP(BitwiseOr_WithFeedback, Generate_BitwiseOrWithFeedback)
DEF_BINOP(BitwiseXor_WithFeedback, Generate_BitwiseXorWithFeedback)
DEF_BINOP(BitwiseAnd_WithFeedback, Generate_BitwiseAndWithFeedback)
DEF_BINOP(ShiftLeft_WithFeedback, Generate_ShiftLeftWithFeedback)
DEF_BINOP(ShiftRight_WithFeedback, Generate_ShiftRightWithFeedback)
DEF_BINOP(ShiftRightLogical_WithFeedback,
          Generate_ShiftRightLogicalWithFeedback)
#undef DEF_BINOP

#define DEF_BINOP(Name, Generator)                                   \
  TF_BUILTIN(Name, CodeStubAssembler) {                              \
    auto lhs = Parameter<Object>(Descriptor::kLeft);                 \
    auto rhs = Parameter<Object>(Descriptor::kRight);                \
    auto slot = UncheckedParameter<UintPtrT>(Descriptor::kSlot);     \
                                                                     \
    BinaryOpAssembler binop_asm(state());                            \
    TNode<Object> result = binop_asm.Generator(                      \
        [&]() { return LoadContextFromBaseline(); }, lhs, rhs, slot, \
        [&]() { return LoadFeedbackVectorFromBaseline(); },          \
        UpdateFeedbackMode::kGuaranteedFeedback, false);             \
                                                                     \
    Return(result);                                                  \
  }
DEF_BINOP(Add_Baseline, Generate_AddWithFeedback)
DEF_BINOP(Subtract_Baseline, Generate_SubtractWithFeedback)
DEF_BINOP(Multiply_Baseline, Generate_MultiplyWithFeedback)
DEF_BINOP(Divide_Baseline, Generate_DivideWithFeedback)
DEF_BINOP(Modulus_Baseline, Generate_ModulusWithFeedback)
DEF_BINOP(Exponentiate_Baseline, Generate_ExponentiateWithFeedback)
DEF_BINOP(BitwiseOr_Baseline, Generate_BitwiseOrWithFeedback)
DEF_BINOP(BitwiseXor_Baseline, Generate_BitwiseXorWithFeedback)
DEF_BINOP(BitwiseAnd_Baseline, Generate_BitwiseAndWithFeedback)
DEF_BINOP(ShiftLeft_Baseline, Generate_ShiftLeftWithFeedback)
DEF_BINOP(ShiftRight_Baseline, Generate_ShiftRightWithFeedback)
DEF_BINOP(ShiftRightLogical_Baseline, Generate_ShiftRightLogicalWithFeedback)
#undef DEF_BINOP

#define DEF_BINOP_RHS_SMI(Name, Generator)                           \
  TF_BUILTIN(Name, CodeStubAssembler) {                              \
    auto lhs = Parameter<Object>(Descriptor::kLeft);                 \
    auto rhs = Parameter<Object>(Descriptor::kRight);                \
    auto slot = UncheckedParameter<UintPtrT>(Descriptor::kSlot);     \
                                                                     \
    BinaryOpAssembler binop_asm(state());                            \
    TNode<Object> result = binop_asm.Generator(                      \
        [&]() { return LoadContextFromBaseline(); }, lhs, rhs, slot, \
        [&]() { return LoadFeedbackVectorFromBaseline(); },          \
        UpdateFeedbackMode::kGuaranteedFeedback, true);              \
                                                                     \
    Return(result);                                                  \
  }
DEF_BINOP_RHS_SMI(AddSmi_Baseline, Generate_AddWithFeedback)
DEF_BINOP_RHS_SMI(SubtractSmi_Baseline, Generate_SubtractWithFeedback)
DEF_BINOP_RHS_SMI(MultiplySmi_Baseline, Generate_MultiplyWithFeedback)
DEF_BINOP_RHS_SMI(DivideSmi_Baseline, Generate_DivideWithFeedback)
DEF_BINOP_RHS_SMI(ModulusSmi_Baseline, Generate_ModulusWithFeedback)
DEF_BINOP_RHS_SMI(ExponentiateSmi_Baseline, Generate_ExponentiateWithFeedback)
DEF_BINOP_RHS_SMI(BitwiseOrSmi_Baseline, Generate_BitwiseOrWithFeedback)
DEF_BINOP_RHS_SMI(BitwiseXorSmi_Baseline, Generate_BitwiseXorWithFeedback)
DEF_BINOP_RHS_SMI(BitwiseAndSmi_Baseline, Generate_BitwiseAndWithFeedback)
DEF_BINOP_RHS_SMI(ShiftLeftSmi_Baseline, Generate_ShiftLeftWithFeedback)
DEF_BINOP_RHS_SMI(ShiftRightSmi_Baseline, Generate_ShiftRightWithFeedback)
DEF_BINOP_RHS_SMI(ShiftRightLogicalSmi_Baseline,
                  Generate_ShiftRightLogicalWithFeedback)
#undef DEF_BINOP_RHS_SMI

#define DEF_UNOP(Name, Generator)                                \
  TF_BUILTIN(Name, CodeStubAssembler) {                          \
    auto value = Parameter<Object>(Descriptor::kValue);          \
    auto context = Parameter<Context>(Descriptor::kContext);     \
    auto feedback_vector =                                       \
        Parameter<FeedbackVector>(Descriptor::kFeedbackVector);  \
    auto slot = UncheckedParameter<UintPtrT>(Descriptor::kSlot); \
                                                                 \
    UnaryOpAssembler a(state());                                 \
    TNode<Object> result =                                       \
        a.Generator(context, value, slot, feedback_vector,       \
                    UpdateFeedbackMode::kGuaranteedFeedback);    \
                                                                 \
    Return(result);                                              \
  }
#ifndef V8_ENABLE_EXPERIMENTAL_TSA_BUILTINS
DEF_UNOP(BitwiseNot_WithFeedback, Generate_BitwiseNotWithFeedback)
#endif
DEF_UNOP(Decrement_WithFeedback, Generate_DecrementWithFeedback)
DEF_UNOP(Increment_WithFeedback, Generate_IncrementWithFeedback)
DEF_UNOP(Negate_WithFeedback, Generate_NegateWithFeedback)
#undef DEF_UNOP

#define DEF_UNOP(Name, Generator)                                \
  TF_BUILTIN(Name, CodeStubAssembler) {                          \
    auto value = Parameter<Object>(Descriptor::kValue);          \
    auto context = LoadContextFromBaseline();                    \
    auto feedback_vector = LoadFeedbackVectorFromBaseline();     \
    auto slot = UncheckedParameter<UintPtrT>(Descriptor::kSlot); \
                                                                 \
    UnaryOpAssembler a(state());                                 \
    TNode<Object> result =                                       \
        a.Generator(context, value, slot, feedback_vector,       \
                    UpdateFeedbackMode::kGuaranteedFeedback);    \
                                                                 \
    Return(result);                                              \
  }
DEF_UNOP(BitwiseNot_Baseline, Generate_BitwiseNotWithFeedback)
DEF_UNOP(Decrement_Baseline, Generate_DecrementWithFeedback)
DEF_UNOP(Increment_Baseline, Generate_IncrementWithFeedback)
DEF_UNOP(Negate_Baseline, Generate_NegateWithFeedback)
#undef DEF_UNOP

#define DEF_COMPARE(Name)                                                  \
  TF_BUILTIN(Name##_WithFeedback, CodeStubAssembler) {                     \
    auto lhs = Parameter<Object>(Descriptor::kLeft);                       \
    auto rhs = Parameter<Object>(Descriptor::kRight);                      \
    auto context = Parameter<Context>(Descriptor::kContext);               \
    auto feedback_vector =                                                 \
        Parameter<FeedbackVector>(Descriptor::kFeedbackVector);            \
    auto slot = UncheckedParameter<UintPtrT>(Descriptor::kSlot);           \
                                                                           \
    TVARIABLE(Smi, var_type_feedback);                                     \
    TVARIABLE(Object, var_exception);                                      \
    Label if_exception(this, Label::kDeferred);                            \
    TNode<Boolean> result;                                                 \
    {                                                                      \
      ScopedExceptionHandler handler(this, &if_exception, &var_exception); \
      result = RelationalComparison(Operation::k##Name, lhs, rhs, context, \
                                    &var_type_feedback);                   \
    }                                                                      \
    UpdateFeedback(var_type_feedback.value(), feedback_vector, slot);      \
                                                                           \
    Return(result);                                                        \
    BIND(&if_exception);                                                   \
    {                                                                      \
      UpdateFeedback(var_type_feedback.value(), feedback_vector, slot);    \
      CallRuntime(Runtime::kReThrow, context, var_exception.value());      \
      Unreachable();                                                       \
    }                                                                      \
  }
DEF_COMPARE(LessThan)
DEF_COMPARE(LessThanOrEqual)
DEF_COMPARE(GreaterThan)
DEF_COMPARE(GreaterThanOrEqual)
#undef DEF_COMPARE

#define DEF_COMPARE(Name)                                                   \
  TF_BUILTIN(Name##_Baseline, CodeStubAssembler) {                          \
    auto lhs = Parameter<Object>(Descriptor::kLeft);                        \
    auto rhs = Parameter<Object>(Descriptor::kRight);                       \
    auto slot = UncheckedParameter<UintPtrT>(Descriptor::kSlot);            \
                                                                            \
    TVARIABLE(Smi, var_type_feedback);                                      \
    TVARIABLE(Object, var_exception);                                       \
    Label if_exception(this, Label::kDeferred);                             \
    TNode<Boolean> result;                                                  \
    {                                                                       \
      ScopedExceptionHandler handler(this, &if_exception, &var_exception);  \
      result = RelationalComparison(                                        \
          Operation::k##Name, lhs, rhs,                                     \
          [&]() { return LoadContextFromBaseline(); }, &var_type_feedback); \
    }                                                                       \
    auto feedback_vector = LoadFeedbackVectorFromBaseline();                \
    UpdateFeedback(var_type_feedback.value(), feedback_vector, slot);       \
                                                                            \
    Return(result);                                                         \
    BIND(&if_exception);                                                    \
    {                                                                       \
      auto feedback_vector = LoadFeedbackVectorFromBaseline();              \
      UpdateFeedback(var_type_feedback.value(), feedback_vector, slot);     \
      CallRuntime(Runtime::kReThrow, LoadContextFromBaseline(),             \
                  var_exception.value());                                   \
      Unreachable();                                                        \
    }                                                                       \
  }
DEF_COMPARE(LessThan)
DEF_COMPARE(LessThanOrEqual)
DEF_COMPARE(GreaterThan)
DEF_COMPARE(GreaterThanOrEqual)
#undef DEF_COMPARE

TF_BUILTIN(Equal_WithFeedback, CodeStubAssembler) {
  auto lhs = Parameter<Object>(Descriptor::kLeft);
  auto rhs = Parameter<Object>(Descriptor::kRight);
  auto context = Parameter<Context>(Descriptor::kContext);
  auto feedback_vector = Parameter<FeedbackVector>(Descriptor::kFeedbackVector);
  auto slot = UncheckedParameter<UintPtrT>(Descriptor::kSlot);

  TVARIABLE(Smi, var_type_feedback);
  TVARIABLE(Object, var_exception);
  Label if_exception(this, Label::kDeferred);
  TNode<Boolean> result;
  {
    ScopedExceptionHandler handler(this, &if_exception, &var_exception);
    result = Equal(lhs, rhs, [&]() { return context; }, &var_type_feedback);
  }
  UpdateFeedback(var_type_feedback.value(), feedback_vector, slot);
  Return(result);

  BIND(&if_exception);
  UpdateFeedback(var_type_feedback.value(), feedback_vector, slot);
  CallRuntime(Runtime::kReThrow, LoadContextFromBaseline(),
              var_exception.value());
  Unreachable();
}

TF_BUILTIN(StrictEqual_WithFeedback, CodeStubAssembler) {
  auto lhs = Parameter<Object>(Descriptor::kLeft);
  auto rhs = Parameter<Object>(Descriptor::kRight);
  auto feedback_vector = Parameter<FeedbackVector>(Descriptor::kFeedbackVector);
  auto slot = UncheckedParameter<UintPtrT>(Descriptor::kSlot);

  TVARIABLE(Smi, var_type_feedback);
  TNode<Boolean> result = StrictEqual(lhs, rhs, &var_type_feedback);
  UpdateFeedback(var_type_feedback.value(), feedback_vector, slot);

  Return(result);
}

TF_BUILTIN(Equal_Baseline, CodeStubAssembler) {
  auto lhs = Parameter<Object>(Descriptor::kLeft);
  auto rhs = Parameter<Object>(Descriptor::kRight);
  auto slot = UncheckedParameter<UintPtrT>(Descriptor::kSlot);

  TVARIABLE(Smi, var_type_feedback);
  TVARIABLE(Object, var_exception);
  Label if_exception(this, Label::kDeferred);
  TNode<Boolean> result;
  {
    ScopedExceptionHandler handler(this, &if_exception, &var_exception);
    result = Equal(
        lhs, rhs, [&]() { return LoadContextFromBaseline(); },
        &var_type_feedback);
  }
  auto feedback_vector = LoadFeedbackVectorFromBaseline();
  UpdateFeedback(var_type_feedback.value(), feedback_vector, slot);
  Return(result);

  BIND(&if_exception);
  {
    auto feedback_vector = LoadFeedbackVectorFromBaseline();
    UpdateFeedback(var_type_feedback.value(), feedback_vector, slot);
    CallRuntime(Runtime::kReThrow, LoadContextFromBaseline(),
                var_exception.value());
    Unreachable();
  }
}

TF_BUILTIN(StrictEqual_Baseline, CodeStubAssembler) {
  auto lhs = Parameter<Object>(Descriptor::kLeft);
  auto rhs = Parameter<Object>(Descriptor::kRight);
  auto slot = UncheckedParameter<UintPtrT>(Descriptor::kSlot);

  TVARIABLE(Smi, var_type_feedback);
  TNode<Boolean> result = StrictEqual(lhs, rhs, &var_type_feedback);
  auto feedback_vector = LoadFeedbackVectorFromBaseline();
  UpdateFeedback(var_type_feedback.value(), feedback_vector, slot);

  Return(result);
}

#include "src/codegen/undef-code-stub-assembler-macros.inc"

}  // namespace internal
}  // namespace v8
```