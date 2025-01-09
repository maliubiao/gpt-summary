Response:
Let's break down the thought process for analyzing this V8 Maglev IR code.

1. **Understanding the Request:** The core request is to analyze the provided C++ code, which is part of the V8 JavaScript engine. The analysis should focus on functionality, potential JavaScript relevance, logic/input/output, and common programming errors. The prompt also includes a crucial hint about `.tq` files (Torque) which is a dead end here, but important to check.

2. **Initial Scan for Clues:** Quickly read through the code, looking for recognizable keywords, patterns, and comments. Key observations:
    * It's C++ (includes, namespaces).
    * It's within the `v8::internal::maglev::s390` namespace, indicating it's specific to the S390 architecture and the Maglev compiler.
    * There are classes with names like `Int32NegateWithOverflow`, `BuiltinStringFromCharCode`, `Float64Add`, `Return`, etc. These strongly suggest individual operations or instructions.
    * There are `SetValueLocationConstraints` and `GenerateCode` methods within these classes. This is a common pattern for defining instruction behavior in compilers—constraints on register usage and the actual code generation steps.
    * The code uses `MaglevAssembler`, `masm->`, and architecture-specific instructions like `lcr`, `AddS32`, `AddF64`, which confirm it's low-level code generation.
    * There are mentions of "deoptimization" (`EmitEagerDeoptIf`), which is a vital concept in optimizing compilers like V8.

3. **High-Level Functional Grouping:**  Based on the class names, start grouping the functionality:
    * **Integer Arithmetic:** `Int32NegateWithOverflow`, `Int32AbsWithOverflow`, `Int32IncrementWithOverflow`, `Int32DecrementWithOverflow`, `Int32AddWithOverflow`, `Int32SubtractWithOverflow`, `Int32MultiplyWithOverflow`, `Int32DivideWithOverflow`, `Int32ModulusWithOverflow`.
    * **Bitwise Operations:** `Int32BitwiseAnd`, `Int32BitwiseOr`, `Int32BitwiseXor`, `Int32BitwiseNot`, `Int32ShiftLeft`, `Int32ShiftRight`, `Int32ShiftRightLogical`.
    * **Floating-Point Arithmetic:** `Float64Add`, `Float64Subtract`, `Float64Multiply`, `Float64Divide`, `Float64Modulus`, `Float64Negate`, `Float64Abs`, `Float64Round`, `Float64Exponentiate`.
    * **String Operations:** `BuiltinStringFromCharCode`.
    * **Memory/Object Operations:** `InlinedAllocation`.
    * **Function Arguments:** `ArgumentsLength`, `RestLength`.
    * **Type Checking/Conversion:** `CheckedObjectToIndex`, `HoleyFloat64ToMaybeNanFloat64`.
    * **Typed Array Operations:** `LoadTypedArrayLength`, `CheckJSDataViewBounds`.
    * **Control Flow/Performance:** `ReduceInterruptBudgetForLoop`, `ReduceInterruptBudgetForReturn`, `Return`.

4. **Detailed Analysis of Representative Examples:** Pick a few key classes from each group to analyze in detail:

    * **`Int32NegateWithOverflow`:**
        * **Functionality:** Integer negation with overflow detection.
        * **JavaScript Relevance:**  The unary negation operator (`-`).
        * **Logic:** Loads the value, compares it to 0 (to avoid `-0`), performs the negation, and checks for overflow.
        * **Input/Output:** Input: An integer. Output: Its negation (as an integer).
        * **Common Errors:**  Overflow when negating the minimum integer value (`-2147483648`).

    * **`BuiltinStringFromCharCode`:**
        * **Functionality:** Creates a string from a character code.
        * **JavaScript Relevance:** `String.fromCharCode()`.
        * **Logic:** Handles both single-byte and two-byte characters, including allocation and storing the character code.
        * **Input/Output:** Input: An integer representing a character code. Output: A string.
        * **Common Errors:** Providing a character code outside the valid range (0-65535).

    * **`Float64Add`:**
        * **Functionality:**  Floating-point addition.
        * **JavaScript Relevance:** The `+` operator for numbers.
        * **Logic:**  Directly uses the S390 floating-point addition instruction.
        * **Input/Output:** Input: Two floating-point numbers. Output: Their sum (as a floating-point number).
        * **Common Errors:**  Loss of precision due to floating-point representation.

    * **`Return`:**
        * **Functionality:**  Handles function return.
        * **JavaScript Relevance:** The `return` statement.
        * **Logic:**  Manages the stack frame, calculates argument sizes, and executes the return instruction.
        * **Input/Output:** Input: The value to return. Output:  The function's return value.
        * **Common Errors:** Mismatched number of arguments in the call stack.

5. **Generalizing the Analysis:** Once a few examples are understood, generalize the analysis to the other classes, focusing on:
    * The mathematical or logical operation performed.
    * How it relates to JavaScript operators or built-in functions.
    * The overflow/error conditions they handle (often leading to deoptimization).
    * The use of registers and assembler instructions.

6. **Addressing Specific Prompt Points:**
    * **`.tq` check:** Explicitly state that the file doesn't end with `.tq` and is therefore not Torque.
    * **JavaScript Examples:** Provide concrete JavaScript code snippets that would trigger the functionality of the analyzed C++ classes.
    * **Logic/Input/Output:**  For each representative example, clearly define the expected input and output.
    * **Common Programming Errors:**  Link the deoptimization reasons and potential issues in the C++ code back to common mistakes JavaScript developers might make. Think about type errors, out-of-bounds access, overflow, division by zero, etc.

7. **Structuring the Output:** Organize the analysis in a clear and logical manner, using headings and bullet points for readability. Start with a general overview, then delve into specific examples.

8. **Refinement and Review:**  Read through the generated analysis to ensure accuracy, clarity, and completeness. Correct any mistakes or ambiguities. Ensure the JavaScript examples are correct and relevant.

Self-Correction Example During the Process: Initially, I might have just listed the classes and their names. However, the prompt asks for *functionality*. Realizing this, I would go back and add descriptions of what each class *does*. Similarly, just saying "handles overflow" isn't as helpful as explaining *when* and *why* overflow occurs in a JavaScript context. This iterative refinement is crucial for producing a good analysis.
好的，让我们来分析一下 `v8/src/maglev/s390/maglev-ir-s390.cc` 这个文件。

**文件功能概要**

`v8/src/maglev/s390/maglev-ir-s390.cc` 文件是 V8 JavaScript 引擎中 Maglev 编译器针对 s390 架构的中间表示 (IR) 节点的代码生成实现。  它定义了如何在 s390 汇编指令中实现 Maglev IR 图中的各种操作。

具体来说，这个文件包含了多个类的 `GenerateCode` 方法，这些类对应着 Maglev IR 中的不同节点类型。每个 `GenerateCode` 方法负责将相应的 IR 节点转换成 s390 汇编指令。这些指令会被 Maglev 汇编器 (`MaglevAssembler`) 组装成最终的可执行代码。

**关键功能点:**

1. **实现 Maglev IR 节点的代码生成:** 文件中的每个类，例如 `Int32NegateWithOverflow`，`BuiltinStringFromCharCode`，`Float64Add` 等，都代表了 Maglev IR 中的一个特定操作。`GenerateCode` 方法包含了将这些操作翻译成 s390 汇编指令的逻辑。

2. **处理不同数据类型:** 代码涉及了多种数据类型的操作，包括：
   - **整数 (Int32):**  例如 `Int32NegateWithOverflow` (取反)，`Int32AddWithOverflow` (加法)，`Int32BitwiseAnd` (按位与) 等。
   - **浮点数 (Float64):** 例如 `Float64Add` (加法)，`Float64Subtract` (减法) 等。
   - **字符串 (String):** 例如 `BuiltinStringFromCharCode` (从字符码创建字符串)。
   - **对象 (Object):**  例如 `LoadTypedArrayLength` (加载类型化数组的长度)。

3. **处理溢出和错误:**  许多整数运算节点（例如带 `WithOverflow` 后缀的）都包含了溢出检测，并在发生溢出时触发去优化 (deoptimization)。这是为了确保 JavaScript 的语义正确性。

4. **调用运行时函数:** 对于一些更复杂的操作，例如 `Float64Modulus` (浮点数取模) 和 `Float64Exponentiate` (浮点数指数运算)，代码会调用 V8 的运行时 (Runtime) 函数来实现。

5. **处理函数调用和参数:**  `ArgumentsLength` 和 `RestLength` 节点用于获取函数参数的长度。 `Return` 节点处理函数返回时的栈帧清理和返回值设置。

6. **处理类型化数组和 DataView:**  `LoadTypedArrayLength` 和 `CheckJSDataViewBounds` 节点涉及对类型化数组和 DataView 的操作，包括边界检查。

7. **性能优化:**  `ReduceInterruptBudgetForLoop` 和 `ReduceInterruptBudgetForReturn` 节点与 V8 的中断预算和分层编译有关，用于在循环和函数返回时检查是否需要进行中断处理或触发分层编译。

**关于 .tq 结尾的文件**

如果 `v8/src/maglev/s390/maglev-ir-s390.cc` 以 `.tq` 结尾，那么它会是一个 **V8 Torque 源代码**。Torque 是一种用于编写 V8 内部代码的 DSL (领域特定语言)，它可以生成 C++ 代码。  当前这个文件以 `.cc` 结尾，所以它是直接用 C++ 编写的。

**与 JavaScript 功能的关系及示例**

这个文件中的代码直接对应着 JavaScript 中各种操作的底层实现。以下是一些 JavaScript 示例以及它们可能触发的代码：

* **整数运算:**
  ```javascript
  let a = 10;
  let b = -a; // 触发 Int32NegateWithOverflow
  let c = a + 5; // 触发 Int32AddWithOverflow
  ```

* **浮点数运算:**
  ```javascript
  let x = 3.14;
  let y = x * 2.0; // 触发 Float64Multiply
  let z = Math.pow(x, 3); // 触发 Float64Exponentiate
  ```

* **字符串操作:**
  ```javascript
  let charCode = 65;
  let str = String.fromCharCode(charCode); // 触发 BuiltinStringFromCharCode
  ```

* **函数参数:**
  ```javascript
  function foo(a, b, ...rest) {
    console.log(arguments.length); // 触发 ArgumentsLength
    console.log(rest.length);     // 触发 RestLength
    return a + b;                 // 触发 Return
  }
  foo(1, 2, 3, 4);
  ```

* **类型化数组:**
  ```javascript
  let buffer = new ArrayBuffer(16);
  let view = new Int32Array(buffer);
  console.log(view.length);      // 触发 LoadTypedArrayLength
  view[0] = 10;
  ```

**代码逻辑推理和假设输入/输出**

以 `Int32NegateWithOverflow::GenerateCode` 为例：

**假设输入:** 一个 `Int32NegateWithOverflow` 类型的 IR 节点，其 `value_input()` 连接着一个值为 10 的寄存器。

**代码逻辑:**

1. `Register value = ToRegister(value_input());`：将输入值所在的寄存器赋值给 `value` 变量。假设 `value` 现在指向寄存器 `r3`，并且 `r3` 的值为 10。
2. `Register out = ToRegister(result());`：获取结果寄存器。假设 `out` 指向寄存器 `r4`。
3. `__ CmpS32(value, Operand(0));`：比较 `value` (寄存器 `r3`) 的值和 0。
4. `__ EmitEagerDeoptIf(eq, DeoptimizeReason::kOverflow, this);`：如果 `value` 等于 0，则执行去优化，因为对 0 取反不会溢出，但这里是为了避免生成 `-0`。
5. `__ lcr(out, value);`：执行取反操作，将 `value` (10) 的相反数 (-10) 放入 `out` (寄存器 `r4`)。
6. `__ LoadS32(out, out);`：确保结果是 32 位整数。
7. `__ EmitEagerDeoptIf(overflow, DeoptimizeReason::kOverflow, this);`：检查是否发生溢出。对于输入 10，不会发生溢出。

**输出:** 寄存器 `r4` 的值为 -10。

**假设输入（溢出情况）:** 一个 `Int32NegateWithOverflow` 类型的 IR 节点，其 `value_input()` 连接着一个值为 -2147483648 (Int32 的最小值) 的寄存器。

**代码逻辑:** 当执行 `__ lcr(out, value);` 时，对 -2147483648 取反会导致溢出，因为 2147483648 超出了 Int32 的最大值。`__ EmitEagerDeoptIf(overflow, DeoptimizeReason::kOverflow, this);` 会检测到溢出并触发去优化。

**用户常见的编程错误**

这个文件中的代码主要处理的是底层的代码生成，用户通常不会直接与这些代码交互。但是，JavaScript 中的一些常见编程错误可能会导致 Maglev 生成的代码触发去优化，或者产生意外的结果。以下是一些例子：

1. **整数溢出:**
   ```javascript
   let maxInt = 2147483647;
   let overflow = maxInt + 1; // JavaScript 中会变成浮点数，但在 Maglev 的 Int32 操作中可能触发溢出检查并去优化。
   ```
   Maglev 尝试进行优化假设它是 Int32 运算，如果结果超出 Int32 范围，就会触发 `Int32AddWithOverflow` 中的溢出检测。

2. **对可能为 `undefined` 或 `null` 的值进行操作:**
   ```javascript
   function process(value) {
     return value + 10;
   }
   let result = process(undefined); // 可能会导致类型错误，Maglev 生成的代码中会有相应的类型检查。
   ```
   Maglev 可能会假设 `value` 是一个数字，并生成相应的加法指令。如果 `value` 是 `undefined`，会导致运行时错误或去优化。

3. **不正确的类型转换:**
   ```javascript
   let str = "10";
   let num = str + 5; // JavaScript 中会进行字符串拼接 "105"，但如果 Maglev 误认为要进行数字加法，可能会产生错误。
   ```
   Maglev 可能会尝试优化数字加法，但由于类型不匹配，可能会导致去优化或产生非预期的结果。

4. **除零错误:**
   ```javascript
   let x = 10;
   let y = 0;
   let result = x / y; // 在 `Int32DivideWithOverflow` 中会检查除零情况并可能触发去优化。
   ```

5. **使用超出范围的字符码:**
   ```javascript
   let invalidCharCode = 100000;
   let str = String.fromCharCode(invalidCharCode); // `BuiltinStringFromCharCode` 会处理超出范围的情况。
   ```
   虽然 JavaScript 允许这样做，但了解其底层处理方式可以帮助理解性能和可能的限制。

总而言之，`v8/src/maglev/s390/maglev-ir-s390.cc` 是 V8 引擎中至关重要的一个文件，它负责将高级的 Maglev IR 转换成底层的 s390 汇编代码，从而使得 JavaScript 代码能够在 s390 架构的处理器上高效执行。理解这个文件的功能有助于深入了解 V8 引擎的内部工作原理和 JavaScript 的执行过程。

Prompt: 
```
这是目录为v8/src/maglev/s390/maglev-ir-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/s390/maglev-ir-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
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

"""

```