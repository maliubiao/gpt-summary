Response:
Let's break down the thought process for analyzing this C++ code and generating the response.

1. **Understanding the Request:** The request asks for the functionality of a specific V8 source file (`maglev-ir-arm64.cc`). Key points are:  listing functions, checking for `.tq` (Torque), JavaScript relation with examples, code logic with input/output, and common programming errors.

2. **Initial Scan and File Type:** The first step is to quickly scan the file's contents. The `#include` directives suggest this is C++ code interacting with V8's internals (assembler, objects, etc.). The absence of `.tq` anywhere in the file confirms it's not a Torque file.

3. **Identifying the Core Functionality:** The namespace `v8::internal::maglev` and the file name `maglev-ir-arm64.cc` immediately point to Maglev, V8's mid-tier optimizing compiler, and specifically the ARM64 architecture. The `ir` in the name likely stands for "Intermediate Representation."  This suggests the file defines the building blocks or operations used within Maglev for ARM64.

4. **Analyzing Individual Classes/Functions:** The next step is to examine each class and its `GenerateCode` method. The class names (e.g., `Int32NegateWithOverflow`, `Float64Add`, `LoadTypedArrayLength`) are highly descriptive. The `GenerateCode` methods, using `MaglevAssembler`, clearly indicate that these classes represent instructions or operations that Maglev will translate into actual ARM64 assembly code.

5. **Categorizing Functionality:**  As I go through the classes, I start to group them conceptually:
    * **Integer Operations:**  `Int32NegateWithOverflow`, `Int32AbsWithOverflow`, `Int32AddWithOverflow`, etc. These perform arithmetic and bitwise operations on 32-bit integers, often with overflow detection.
    * **Floating-Point Operations:** `Float64Add`, `Float64Subtract`, `Float64Multiply`, etc. These handle operations on 64-bit floating-point numbers.
    * **String Operations:** `BuiltinStringFromCharCode`.
    * **Memory/Object Operations:** `InlinedAllocation`, `LoadTypedArrayLength`, `CheckJSDataViewBounds`. These deal with memory allocation and accessing properties of JavaScript objects (like TypedArrays).
    * **Control Flow:** `Return`, `ReduceInterruptBudgetForLoop`, `ReduceInterruptBudgetForReturn`. These manage the flow of execution within a Maglev-compiled function.
    * **Argument Handling:** `ArgumentsLength`, `RestLength`. These deal with accessing function arguments.
    * **Type Conversion:** `HoleyFloat64ToMaybeNanFloat64`.

6. **Connecting to JavaScript:**  For each category, I think about how these low-level operations relate to JavaScript code. For example:
    * Integer operations directly correspond to JavaScript's integer arithmetic (e.g., `+`, `-`, `*`, `~`, `&`, `|`, `^`, `<<`, `>>`, `>>>`).
    * Floating-point operations map to JavaScript's floating-point arithmetic.
    * String operations like `String.fromCharCode()` directly relate.
    * Array and TypedArray manipulations are represented by `LoadTypedArrayLength` and `CheckJSDataViewBounds`.
    * Function calls and returns are handled by the `Return` node.

7. **Crafting JavaScript Examples:** Based on the connections, I create simple JavaScript snippets that would likely involve the corresponding Maglev IR operations. The goal is to make the connection clear.

8. **Inferring Code Logic and Providing Input/Output:** For some of the simpler operations (like `Int32NegateWithOverflow`), I can easily reason about the input and output. I choose examples that illustrate the core functionality and also trigger potential deoptimization scenarios (like overflow).

9. **Identifying Common Programming Errors:**  I consider what kind of mistakes JavaScript developers might make that would lead to these specific Maglev operations being executed and potentially deoptimizing. Overflow errors in integer arithmetic, out-of-bounds access on TypedArrays, and incorrect use of `String.fromCharCode` are good examples.

10. **Structuring the Response:**  Finally, I organize the information logically, using headings and bullet points to make it easy to read and understand. I make sure to address each part of the original request. I start with the overall functionality, then provide the JavaScript connections, code logic examples, and finally the common errors.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe I should dive deep into the assembly code within `GenerateCode`. **Correction:**  The request asks for *functionality*, not a detailed assembly code walkthrough. Focus on the *what* and *why* rather than the exact *how* of the assembly.
* **Struggle:**  How to explain `ReduceInterruptBudget`? **Solution:**  Relate it to long-running loops and V8's mechanisms for handling interrupts and tiering up/down.
* **Realization:** Some nodes have "WithOverflow" in their name. **Action:**  Highlight the importance of overflow checks and how they relate to deoptimization.
* **Ensuring Clarity:** Am I using too much V8-specific terminology? **Correction:**  Provide brief explanations where necessary (e.g., "deoptimization").

By following this thought process, combining code analysis with an understanding of JavaScript and common programming practices, I can generate a comprehensive and informative answer.This C++ source file, `v8/src/maglev/arm64/maglev-ir-arm64.cc`, is a crucial part of V8's Maglev compiler, specifically for the ARM64 architecture. It defines the **Intermediate Representation (IR)** nodes that Maglev uses to represent JavaScript code before generating machine code for ARM64 processors.

Here's a breakdown of its functionality:

**Core Functionality:**

1. **Defining Maglev IR Nodes for ARM64:** This file defines C++ classes that represent various operations that can occur in JavaScript code. Each class corresponds to a specific operation (e.g., integer addition, floating-point multiplication, loading array length). These classes are part of Maglev's IR.

2. **Generating ARM64 Assembly Code:**  Each IR node class has a `GenerateCode` method. This method is responsible for emitting the corresponding ARM64 assembly instructions to perform the operation represented by the node. It uses the `MaglevAssembler` (an ARM64-specific assembler) to generate these instructions.

3. **Handling Deoptimization:** Many of the IR nodes include logic for "deoptimization." This is a process where the optimized code generated by Maglev needs to revert back to a less optimized version (like the interpreter) if certain assumptions made during optimization turn out to be incorrect at runtime. This often involves checking for conditions like overflow or unexpected object types. The `__ EmitEagerDeoptIf` calls within the `GenerateCode` methods handle this.

4. **Managing Register Allocation and Constraints:** The `SetValueLocationConstraints` method in each IR node helps the register allocator determine where the input and output values for the operation should be located (e.g., in registers, on the stack). This ensures efficient use of CPU registers.

5. **Interaction with V8's Runtime:** Some nodes interact with V8's runtime system through `__ CallRuntime` calls. This is necessary for operations that cannot be efficiently implemented directly in assembly or require interaction with V8's object model (e.g., handling interrupts, calling built-in functions).

**Checking for `.tq` Extension:**

The file name `v8/src/maglev/arm64/maglev-ir-arm64.cc` ends with `.cc`, not `.tq`. Therefore, **it is not a V8 Torque source code file.** Torque files are typically used for defining built-in functions and often have a `.tq` extension.

**Relationship with JavaScript Functionality (with JavaScript Examples):**

This file directly translates JavaScript operations into low-level ARM64 instructions. Here are some examples:

* **`Int32AddWithOverflow`:**  This node handles the JavaScript `+` operator when both operands are likely to be 32-bit integers.

   ```javascript
   function add(a, b) {
     return a + b;
   }
   // If Maglev compiles this function and determines 'a' and 'b' are likely Int32,
   // it might use the Int32AddWithOverflow node.
   ```

* **`Float64Multiply`:** This node handles the JavaScript `*` operator when floating-point numbers are involved.

   ```javascript
   function multiply(x, y) {
     return x * y;
   }
   // Maglev would likely use Float64Multiply for this.
   ```

* **`BuiltinStringFromCharCode`:** This node implements the functionality of `String.fromCharCode()`.

   ```javascript
   function getChar(code) {
     return String.fromCharCode(code);
   }
   // This node would be used to generate the string from the character code.
   ```

* **`LoadTypedArrayLength`:** This node accesses the `length` property of a TypedArray.

   ```javascript
   const array = new Uint8Array(10);
   const length = array.length; // Accessing the length property
   // LoadTypedArrayLength would be used to retrieve the length.
   ```

**Code Logic Reasoning (with Hypothetical Input and Output):**

Let's take the `Int32NegateWithOverflow` node as an example:

**Assumptions:**

* The `value_input()` holds the 32-bit integer to be negated.
* The `result()` will store the negated value.

**Hypothetical Input and Output:**

* **Input:** `value_input()` contains the integer `5`.
* **Output:** The `GenerateCode` method will execute the `Negs` instruction, which negates the value. `result()` will contain `-5`. The carry flag (`vs`) will *not* be set in this case because there is no overflow.

* **Input:** `value_input()` contains the integer `-2147483648` (the minimum 32-bit signed integer).
* **Output:** The `Negs` instruction will attempt to negate it. The result would be `2147483648`, which is outside the range of a signed 32-bit integer. The overflow flag (`vs`) will be set. The `__ EmitEagerDeoptIf(vs, DeoptimizeReason::kOverflow, this);` line will be triggered, causing deoptimization.

**Common Programming Errors and How This Code Handles Them:**

This code often deals with the consequences of common programming errors in JavaScript that can lead to unexpected values or overflows.

* **Integer Overflow:**  Operations like `Int32AddWithOverflow`, `Int32MultiplyWithOverflow`, etc., explicitly check for overflow conditions. A common error is performing arithmetic operations on integers that exceed the maximum or minimum safe integer values in JavaScript.

   ```javascript
   function overflowAdd() {
     let maxInt = 2147483647;
     return maxInt + 1; // This will wrap around in standard JavaScript
   }
   // Maglev's Int32AddWithOverflow would detect this if it's treating the
   // values as Int32 and potentially deoptimize or handle it based on
   // the context.
   ```

* **Accessing TypedArrays Out of Bounds:** The `CheckJSDataViewBounds` node ensures that accesses to `DataView` objects are within the valid bounds. A common error is trying to read or write data beyond the allocated size of a `DataView`.

   ```javascript
   const buffer = new ArrayBuffer(10);
   const dataView = new DataView(buffer);
   dataView.getInt8(15); // This will cause an error in standard JavaScript
   // Maglev's CheckJSDataViewBounds would generate code to prevent this and
   // potentially deoptimize if the access is out of bounds.
   ```

* **Incorrect Usage of `String.fromCharCode`:**  `BuiltinStringFromCharCode` handles cases where the input code is outside the valid range for a character.

   ```javascript
   String.fromCharCode(70000); // This might produce unexpected characters
   // Maglev's BuiltinStringFromCharCode handles these cases.
   ```

In summary, `v8/src/maglev/arm64/maglev-ir-arm64.cc` is a foundational file for V8's Maglev compiler on ARM64. It defines the building blocks for representing JavaScript operations and generating efficient machine code, while also incorporating mechanisms to handle potential runtime errors and deoptimization.

Prompt: 
```
这是目录为v8/src/maglev/arm64/maglev-ir-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/arm64/maglev-ir-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/logging.h"
#include "src/codegen/arm64/assembler-arm64-inl.h"
#include "src/codegen/arm64/register-arm64.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/maglev/arm64/maglev-assembler-arm64-inl.h"
#include "src/maglev/maglev-assembler-inl.h"
#include "src/maglev/maglev-graph-processor.h"
#include "src/maglev/maglev-graph.h"
#include "src/maglev/maglev-ir-inl.h"
#include "src/maglev/maglev-ir.h"
#include "src/objects/feedback-cell.h"
#include "src/objects/js-function.h"

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
  Register value = ToRegister(value_input()).W();
  Register out = ToRegister(result()).W();

  // Deopt when result would be -0.
  static_assert(Int32NegateWithOverflow::kProperties.can_eager_deopt());
  Label* fail = __ GetDeoptLabel(this, DeoptimizeReason::kOverflow);
  __ RecordComment("-- Jump to eager deopt");
  __ Cbz(value, fail);

  __ Negs(out, value);
  // Output register must not be a register input into the eager deopt info.
  DCHECK_REGLIST_EMPTY(RegList{out} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
  __ EmitEagerDeoptIf(vs, DeoptimizeReason::kOverflow, this);
}

void Int32AbsWithOverflow::GenerateCode(MaglevAssembler* masm,
                                        const ProcessingState& state) {
  Register out = ToRegister(result()).W();
  Label done;
  DCHECK(ToRegister(input()).W().Aliases(out));
  __ Cmp(out, Immediate(0));
  __ JumpIf(ge, &done);
  __ Negs(out, out);
  // Output register must not be a register input into the eager deopt info.
  DCHECK_REGLIST_EMPTY(RegList{out} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
  __ EmitEagerDeoptIf(vs, DeoptimizeReason::kOverflow, this);
  __ bind(&done);
}

void Int32IncrementWithOverflow::SetValueLocationConstraints() {
  UseRegister(value_input());
  DefineAsRegister(this);
}

void Int32IncrementWithOverflow::GenerateCode(MaglevAssembler* masm,
                                              const ProcessingState& state) {
  Register value = ToRegister(value_input()).W();
  Register out = ToRegister(result()).W();
  __ Adds(out, value, Immediate(1));
  // Output register must not be a register input into the eager deopt info.
  DCHECK_REGLIST_EMPTY(RegList{out} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
  __ EmitEagerDeoptIf(vs, DeoptimizeReason::kOverflow, this);
}

void Int32DecrementWithOverflow::SetValueLocationConstraints() {
  UseRegister(value_input());
  DefineAsRegister(this);
}

void Int32DecrementWithOverflow::GenerateCode(MaglevAssembler* masm,
                                              const ProcessingState& state) {
  Register value = ToRegister(value_input()).W();
  Register out = ToRegister(result()).W();
  __ Subs(out, value, Immediate(1));
  // Output register must not be a register input into the eager deopt info.
  DCHECK_REGLIST_EMPTY(RegList{out} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
  __ EmitEagerDeoptIf(vs, DeoptimizeReason::kOverflow, this);
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
  Register scratch = temps.Acquire();
  Register result_string = ToRegister(result());
  if (Int32Constant* constant = code_input().node()->TryCast<Int32Constant>()) {
    int32_t char_code = constant->value() & 0xFFFF;
    if (0 <= char_code && char_code < String::kMaxOneByteCharCode) {
      __ LoadSingleCharacterString(result_string, char_code);
    } else {
      __ AllocateTwoByteString(register_snapshot(), result_string, 1);
      __ Move(scratch, char_code);
      __ Strh(scratch.W(),
              FieldMemOperand(result_string,
                              OFFSET_OF_DATA_START(SeqTwoByteString)));
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
    __ Add(ToRegister(result()), ToRegister(allocation_block()), offset());
  }
}

void ArgumentsLength::SetValueLocationConstraints() { DefineAsRegister(this); }

void ArgumentsLength::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  Register argc = ToRegister(result());
  __ Ldr(argc, MemOperand(fp, StandardFrameConstants::kArgCOffset));
  __ Sub(argc, argc, 1);  // Remove receiver.
}

void RestLength::SetValueLocationConstraints() { DefineAsRegister(this); }

void RestLength::GenerateCode(MaglevAssembler* masm,
                              const ProcessingState& state) {
  Register length = ToRegister(result());
  Label done;
  __ Ldr(length, MemOperand(fp, StandardFrameConstants::kArgCOffset));
  __ Subs(length, length, formal_parameter_count() + 1);
  __ B(kGreaterThanEqual, &done);
  __ Move(length, 0);
  __ Bind(&done);
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
  Register left = ToRegister(left_input()).W();
  Register right = ToRegister(right_input()).W();
  Register out = ToRegister(result()).W();
  __ Adds(out, left, right);
  // The output register shouldn't be a register input into the eager deopt
  // info.
  DCHECK_REGLIST_EMPTY(RegList{out} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
  __ EmitEagerDeoptIf(vs, DeoptimizeReason::kOverflow, this);
}

void Int32SubtractWithOverflow::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsRegister(this);
}
void Int32SubtractWithOverflow::GenerateCode(MaglevAssembler* masm,
                                             const ProcessingState& state) {
  Register left = ToRegister(left_input()).W();
  Register right = ToRegister(right_input()).W();
  Register out = ToRegister(result()).W();
  __ Subs(out, left, right);
  // The output register shouldn't be a register input into the eager deopt
  // info.
  DCHECK_REGLIST_EMPTY(RegList{out} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
  __ EmitEagerDeoptIf(vs, DeoptimizeReason::kOverflow, this);
}

void Int32MultiplyWithOverflow::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsRegister(this);
}
void Int32MultiplyWithOverflow::GenerateCode(MaglevAssembler* masm,
                                             const ProcessingState& state) {
  Register left = ToRegister(left_input()).W();
  Register right = ToRegister(right_input()).W();
  Register out = ToRegister(result()).W();

  // TODO(leszeks): peephole optimise multiplication by a constant.

  MaglevAssembler::TemporaryRegisterScope temps(masm);
  bool out_alias_input = out == left || out == right;
  Register res = out.X();
  if (out_alias_input) {
    res = temps.AcquireScratch();
  }

  __ Smull(res, left, right);

  // if res != (res[0:31] sign extended to 64 bits), then the multiplication
  // result is too large for 32 bits.
  __ Cmp(res, Operand(res.W(), SXTW));
  __ EmitEagerDeoptIf(ne, DeoptimizeReason::kOverflow, this);

  // If the result is zero, check if either lhs or rhs is negative.
  Label end;
  __ CompareAndBranch(res, Immediate(0), ne, &end);
  {
    MaglevAssembler::TemporaryRegisterScope temps(masm);
    Register temp = temps.AcquireScratch().W();
    __ Orr(temp, left, right);
    // If one of them is negative, we must have a -0 result, which is non-int32,
    // so deopt.
    // TODO(leszeks): Consider splitting these deopts to have distinct deopt
    // reasons. Otherwise, the reason has to match the above.
    __ RecordComment("-- Jump to eager deopt if the result is negative zero");
    __ Tbnz(temp, temp.SizeInBits() - 1,
            __ GetDeoptLabel(this, DeoptimizeReason::kOverflow));
  }
  __ Bind(&end);
  if (out_alias_input) {
    __ Move(out, res.W());
  }
}

void Int32DivideWithOverflow::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsRegister(this);
}
void Int32DivideWithOverflow::GenerateCode(MaglevAssembler* masm,
                                           const ProcessingState& state) {
  Register left = ToRegister(left_input()).W();
  Register right = ToRegister(right_input()).W();
  Register out = ToRegister(result()).W();

  // TODO(leszeks): peephole optimise division by a constant.

  // Pre-check for overflow, since idiv throws a division exception on overflow
  // rather than setting the overflow flag. Logic copied from
  // effect-control-linearizer.cc

  // Check if {right} is positive (and not zero).
  __ Cmp(right, Immediate(0));
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
        __ CompareAndBranch(left, Immediate(0), eq, deopt);

        // Check if {left} is kMinInt and {right} is -1, in which case we'd have
        // to return -kMinInt, which is not representable as Int32.
        __ Cmp(left, Immediate(kMinInt));
        __ JumpIf(ne, *done);
        __ Cmp(right, Immediate(-1));
        __ JumpIf(ne, *done);
        __ JumpToDeopt(deopt);
      },
      done, left, right, this);
  __ Bind(*done);

  // Perform the actual integer division.
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  bool out_alias_input = out == left || out == right;
  Register res = out;
  if (out_alias_input) {
    res = temps.AcquireScratch().W();
  }
  __ Sdiv(res, left, right);

  // Check that the remainder is zero.
  Register temp = temps.AcquireScratch().W();
  __ Msub(temp, res, right, left);
  __ CompareAndBranch(temp, Immediate(0), ne,
                      __ GetDeoptLabel(this, DeoptimizeReason::kNotInt32));

  __ Move(out, res);
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
  //
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

  Register lhs = ToRegister(left_input()).W();
  Register rhs = ToRegister(right_input()).W();
  Register out = ToRegister(result()).W();

  static constexpr DeoptimizeReason deopt_reason =
      DeoptimizeReason::kDivisionByZero;

  if (lhs == rhs) {
    // For the modulus algorithm described above, lhs and rhs must not alias
    // each other.
    __ Tst(lhs, lhs);
    // TODO(victorgomes): This ideally should be kMinusZero, but Maglev only
    // allows one deopt reason per IR.
    __ EmitEagerDeoptIf(mi, deopt_reason, this);
    __ Move(ToRegister(result()), 0);
    return;
  }

  DCHECK(!AreAliased(lhs, rhs));

  ZoneLabelRef done(masm);
  ZoneLabelRef rhs_checked(masm);
  __ Cmp(rhs, Immediate(0));
  __ JumpToDeferredIf(
      le,
      [](MaglevAssembler* masm, ZoneLabelRef rhs_checked, Register rhs,
         Int32ModulusWithOverflow* node) {
        __ Negs(rhs, rhs);
        __ B(*rhs_checked, ne);
        __ EmitEagerDeopt(node, deopt_reason);
      },
      rhs_checked, rhs, this);
  __ Bind(*rhs_checked);

  __ Cmp(lhs, Immediate(0));
  __ JumpToDeferredIf(
      lt,
      [](MaglevAssembler* masm, ZoneLabelRef done, Register lhs, Register rhs,
         Register out, Int32ModulusWithOverflow* node) {
        MaglevAssembler::TemporaryRegisterScope temps(masm);
        Register res = temps.AcquireScratch().W();
        __ Neg(lhs, lhs);
        __ Udiv(res, lhs, rhs);
        __ Msub(out, res, rhs, lhs);
        __ Negs(out, out);
        __ B(*done, ne);
        // TODO(victorgomes): This ideally should be kMinusZero, but Maglev
        // only allows one deopt reason per IR.
        __ EmitEagerDeopt(node, deopt_reason);
      },
      done, lhs, rhs, out, this);

  Label rhs_not_power_of_2;
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register mask = temps.AcquireScratch().W();
  __ Add(mask, rhs, Immediate(-1));
  __ Tst(mask, rhs);
  __ JumpIf(ne, &rhs_not_power_of_2);

  // {rhs} is power of 2.
  __ And(out, mask, lhs);
  __ Jump(*done);

  __ Bind(&rhs_not_power_of_2);

  // We store the result of the Udiv in a temporary register in case {out} is
  // the same as {lhs} or {rhs}: we'll still need those 2 registers intact to
  // get the remainder.
  Register res = mask;
  __ Udiv(res, lhs, rhs);
  __ Msub(out, res, rhs, lhs);

  __ Bind(*done);
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
    Register left = ToRegister(left_input()).W();                \
    Register right = ToRegister(right_input()).W();              \
    Register out = ToRegister(result()).W();                     \
    __ opcode(out, left, right);                                 \
  }
DEF_BITWISE_BINOP(Int32BitwiseAnd, and_)
DEF_BITWISE_BINOP(Int32BitwiseOr, orr)
DEF_BITWISE_BINOP(Int32BitwiseXor, eor)
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
                                                                 \
  void Instruction::GenerateCode(MaglevAssembler* masm,          \
                                 const ProcessingState& state) { \
    Register out = ToRegister(result()).W();                     \
    Register left = ToRegister(left_input()).W();                \
    if (Int32Constant* constant =                                \
            right_input().node()->TryCast<Int32Constant>()) {    \
      int right = constant->value() & 31;                        \
      if (right == 0) {                                          \
        __ Move(out, left);                                      \
      } else {                                                   \
        __ opcode(out, left, right);                             \
      }                                                          \
    } else {                                                     \
      Register right = ToRegister(right_input()).W();            \
      __ opcode##v(out, left, right);                            \
    }                                                            \
  }
DEF_SHIFT_BINOP(Int32ShiftLeft, lsl)
DEF_SHIFT_BINOP(Int32ShiftRight, asr)
DEF_SHIFT_BINOP(Int32ShiftRightLogical, lsr)
#undef DEF_SHIFT_BINOP

void Int32BitwiseNot::SetValueLocationConstraints() {
  UseRegister(value_input());
  DefineAsRegister(this);
}

void Int32BitwiseNot::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  Register value = ToRegister(value_input()).W();
  Register out = ToRegister(result()).W();
  __ Mvn(out, value);
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
  __ Fadd(out, left, right);
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
  __ Fsub(out, left, right);
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
  __ Fmul(out, left, right);
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
  __ Fdiv(out, left, right);
}

int Float64Modulus::MaxCallStackArgs() const { return 0; }
void Float64Modulus::SetValueLocationConstraints() {
  UseFixed(left_input(), v0);
  UseFixed(right_input(), v1);
  DefineSameAsFirst(this);
}
void Float64Modulus::GenerateCode(MaglevAssembler* masm,
                                  const ProcessingState& state) {
  AllowExternalCallThatCantCauseGC scope(masm);
  __ CallCFunction(ExternalReference::mod_two_doubles_operation(), 0, 2);
}

void Float64Negate::SetValueLocationConstraints() {
  UseRegister(input());
  DefineAsRegister(this);
}
void Float64Negate::GenerateCode(MaglevAssembler* masm,
                                 const ProcessingState& state) {
  DoubleRegister value = ToDoubleRegister(input());
  DoubleRegister out = ToDoubleRegister(result());
  __ Fneg(out, value);
}

void Float64Abs::GenerateCode(MaglevAssembler* masm,
                              const ProcessingState& state) {
  DoubleRegister in = ToDoubleRegister(input());
  DoubleRegister out = ToDoubleRegister(result());
  __ Fabs(out, in);
}

void Float64Round::GenerateCode(MaglevAssembler* masm,
                                const ProcessingState& state) {
  DoubleRegister in = ToDoubleRegister(input());
  DoubleRegister out = ToDoubleRegister(result());
  if (kind_ == Kind::kNearest) {
    MaglevAssembler::TemporaryRegisterScope temps(masm);
    DoubleRegister temp = temps.AcquireScratchDouble();
    DoubleRegister half_one = temps.AcquireScratchDouble();
    __ Move(temp, in);
    // Frintn rounds to even on tie, while JS expects it to round towards
    // +Infinity. Fix the difference by checking if we rounded down by exactly
    // 0.5, and if so, round to the other side.
    __ Frintn(out, in);
    __ Fsub(temp, temp, out);
    __ Move(half_one, 0.5);
    __ Fcmp(temp, half_one);
    Label done;
    __ JumpIf(ne, &done, Label::kNear);
    // Fix wrong tie-to-even by adding 0.5 twice.
    __ Fadd(out, out, half_one);
    __ Fadd(out, out, half_one);
    __ bind(&done);
  } else if (kind_ == Kind::kCeil) {
    __ Frintp(out, in);
  } else if (kind_ == Kind::kFloor) {
    __ Frintm(out, in);
  }
}

int Float64Exponentiate::MaxCallStackArgs() const { return 0; }
void Float64Exponentiate::SetValueLocationConstraints() {
  UseFixed(left_input(), v0);
  UseFixed(right_input(), v1);
  DefineSameAsFirst(this);
}
void Float64Exponentiate::GenerateCode(MaglevAssembler* masm,
                                       const ProcessingState& state) {
  AllowExternalCallThatCantCauseGC scope(masm);
  __ CallCFunction(ExternalReference::ieee754_pow_function(), 2);
}

int Float64Ieee754Unary::MaxCallStackArgs() const { return 0; }
void Float64Ieee754Unary::SetValueLocationConstraints() {
  UseFixed(input(), v0);
  DefineSameAsFirst(this);
}
void Float64Ieee754Unary::GenerateCode(MaglevAssembler* masm,
                                       const ProcessingState& state) {
  AllowExternalCallThatCantCauseGC scope(masm);
  __ CallCFunction(ieee_function_ref(), 1);
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
    __ Lsr(result_register, result_register,
           base::bits::CountTrailingZeros(element_size));
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
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register object = ToRegister(receiver_input());
  Register index = ToRegister(index_input());
  if (v8_flags.debug_code) {
    __ AssertObjectType(object, JS_DATA_VIEW_TYPE,
                        AbortReason::kUnexpectedValue);
  }

  // Normal DataView (backed by AB / SAB) or non-length tracking backed by GSAB.
  Register byte_length = temps.Acquire();
  __ LoadBoundedSizeFromObject(byte_length, object,
                               JSDataView::kRawByteLengthOffset);

  int element_size = compiler::ExternalArrayElementSize(element_type_);
  if (element_size > 1) {
    __ Subs(byte_length, byte_length, Immediate(element_size - 1));
    __ EmitEagerDeoptIf(mi, DeoptimizeReason::kOutOfBounds, this);
  }
  __ Cmp(index, byte_length);
  __ EmitEagerDeoptIf(hs, DeoptimizeReason::kOutOfBounds, this);
}

void HoleyFloat64ToMaybeNanFloat64::SetValueLocationConstraints() {
  UseRegister(input());
  DefineAsRegister(this);
}
void HoleyFloat64ToMaybeNanFloat64::GenerateCode(MaglevAssembler* masm,
                                                 const ProcessingState& state) {
  // The hole value is a signalling NaN, so just silence it to get the float64
  // value.
  __ CanonicalizeNaN(ToDoubleRegister(result()), ToDoubleRegister(input()));
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
      __ Cmp(sp, stack_limit);
      __ B(&next, hi);
    }

    // An interrupt has been requested and we must call into runtime to handle
    // it; since we already pay the call cost, combine with the TieringManager
    // call.
    {
      SaveRegisterStateForCall save_register_state(masm,
                                                   node->register_snapshot());
      Register function = scratch0;
      __ Ldr(function, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
      __ Push(function);
      // Move into kContextRegister after the load into scratch0, just in case
      // scratch0 happens to be kContextRegister.
      __ Move(kContextRegister, masm->native_context().object());
      __ CallRuntime(Runtime::kBytecodeBudgetInterruptWithStackCheck_Maglev, 1);
      save_register_state.DefineSafepointWithLazyDeopt(node->lazy_deopt_info());
    }
    __ B(*done);  // All done, continue.
    __ Bind(&next);
  }

  // No pending interrupts. Call into the TieringManager if needed.
  {
    SaveRegisterStateForCall save_register_state(masm,
                                                 node->register_snapshot());
    Register function = scratch0;
    __ Ldr(function, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
    __ Push(function);
    // Move into kContextRegister after the load into scratch0, just in case
    // scratch0 happens to be kContextRegister.
    __ Move(kContextRegister, masm->native_context().object());
    // Note: must not cause a lazy deopt!
    __ CallRuntime(Runtime::kBytecodeBudgetInterrupt_Maglev, 1);
    save_register_state.DefineSafepoint();
  }
  __ B(*done);
}

void GenerateReduceInterruptBudget(MaglevAssembler* masm, Node* node,
                                   ReduceInterruptBudgetType type, int amount) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.Acquire();
  Register feedback_cell = scratch;
  Register budget = temps.Acquire().W();
  __ Ldr(feedback_cell,
         MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ LoadTaggedField(
      feedback_cell,
      FieldMemOperand(feedback_cell, JSFunction::kFeedbackCellOffset));
  __ Ldr(budget,
         FieldMemOperand(feedback_cell, FeedbackCell::kInterruptBudgetOffset));
  __ Subs(budget, budget, Immediate(amount));
  __ Str(budget,
         FieldMemOperand(feedback_cell, FeedbackCell::kInterruptBudgetOffset));
  ZoneLabelRef done(masm);
  __ JumpToDeferredIf(lt, HandleInterruptsAndTiering, done, node, type,
                      scratch);
  __ Bind(*done);
}

}  // namespace

int ReduceInterruptBudgetForLoop::MaxCallStackArgs() const { return 1; }
void ReduceInterruptBudgetForLoop::SetValueLocationConstraints() {
  set_temporaries_needed(2);
}
void ReduceInterruptBudgetForLoop::GenerateCode(MaglevAssembler* masm,
                                                const ProcessingState& state) {
  GenerateReduceInterruptBudget(masm, this, ReduceInterruptBudgetType::kLoop,
                                amount());
}

int ReduceInterruptBudgetForReturn::MaxCallStackArgs() const { return 1; }
void ReduceInterruptBudgetForReturn::SetValueLocationConstraints() {
  set_temporaries_needed(2);
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
  // We cannot use scratch registers, since they're used in LeaveFrame and
  // DropArguments.
  Register actual_params_size = x9;
  Register params_size = x10;

  // Compute the size of the actual parameters + receiver (in bytes).
  // TODO(leszeks): Consider making this an input into Return to re-use the
  // incoming argc's register (if it's still valid).
  __ Ldr(actual_params_size,
         MemOperand(fp, StandardFrameConstants::kArgCOffset));
  __ Mov(params_size, Immediate(formal_params_size));

  // If actual is bigger than formal, then we should use it to free up the stack
  // arguments.
  Label corrected_args_count;
  __ CompareAndBranch(params_size, actual_params_size, ge,
                      &corrected_args_count);
  __ Mov(params_size, actual_params_size);
  __ Bind(&corrected_args_count);

  // Leave the frame.
  __ LeaveFrame(StackFrame::MAGLEV);

  // Drop receiver + arguments according to dynamic arguments size.
  __ DropArguments(params_size);
  __ Ret();
}

}  // namespace maglev
}  // namespace internal
}  // namespace v8

"""

```