Response:
The user wants a summary of the functionality of the provided C++ code. I need to analyze the code and identify its purpose and key functionalities.

The code defines several classes within the `v8::internal::maglev` namespace. These classes seem to represent intermediate representation (IR) nodes for the Maglev compiler in V8, specifically for the ARM architecture. Each class corresponds to a specific operation, like integer negation, addition, string creation, etc.

Key observations:
- The code heavily utilizes the `MaglevAssembler` for generating ARM assembly instructions.
- Many classes have `SetValueLocationConstraints` to specify register usage and allocation.
- `GenerateCode` methods within each class emit the actual ARM assembly code for the corresponding operation.
- Several operations involve overflow checks and eager deoptimization.
- There are specific nodes for handling JavaScript concepts like arguments length, rest parameters, and typed arrays.
- Floating-point operations are also included.
- There's logic for handling interrupts and tiering (performance optimization).

Based on these observations, I can summarize the functionality of the code as defining the ARM-specific code generation logic for various Maglev IR nodes, which represent different operations in the JavaScript execution pipeline.

Regarding the user's specific questions:
- **.tq extension:** The file does not have a `.tq` extension, so it's not a Torque file.
- **Relationship to JavaScript:**  The operations defined in the code directly correspond to JavaScript language features (e.g., arithmetic operations, string manipulation, function arguments).
- **Code logic and examples:**  The code includes logic for handling overflows, different data types, and control flow. I can provide examples for some of these.
- **Common programming errors:**  The overflow checks hint at potential errors like exceeding integer limits.

Plan:
1. State that the file is a C++ source file for the ARM architecture in V8's Maglev compiler.
2. Mention that it defines code generation for various Maglev IR nodes.
3. List some of the key categories of operations handled (integer, float, string, arguments, typed arrays, control flow).
4. Confirm it's not a Torque file.
5. Provide a simple JavaScript example related to one of the operations (e.g., integer addition with overflow).
6. Give a hypothetical input/output for a simple operation (e.g., `Int32NegateWithOverflow`).
7. Provide an example of a common programming error related to integer overflow.
这个C++源代码文件 `v8/src/maglev/arm/maglev-ir-arm.cc` 是 V8 JavaScript 引擎中 Maglev 编译器的针对 ARM 架构的实现部分。它的主要功能是 **定义了如何将 Maglev 中间表示 (IR) 的各种操作节点转换为具体的 ARM 汇编指令**。

具体来说，这个文件：

1. **定义了多种 IR 节点的 ARM 架构特定实现**。  每个以 `void ClassName::GenerateCode(MaglevAssembler* masm, const ProcessingState& state)` 形式定义的函数，都负责将一个特定的 Maglev IR 节点（如 `Int32NegateWithOverflow`，`Int32AddWithOverflow` 等）翻译成对应的 ARM 汇编代码。这些汇编代码由 `MaglevAssembler` 对象 `masm` 生成。

2. **处理各种算术和逻辑运算**，包括：
    *   带溢出检查的整数运算（加、减、乘、除、取模、取反、绝对值、递增、递减）。
    *   位运算（与、或、异或、非、左移、右移、无符号右移）。
    *   浮点数运算（加、减、乘、除、取模、取反、绝对值、舍入、指数）。

3. **处理字符串操作**，例如：
    *   通过字符码创建字符串 (`BuiltinStringFromCharCode`)。

4. **处理内存分配** (`InlinedAllocation`)。

5. **处理函数参数相关操作**，例如：
    *   获取 `arguments` 对象的长度 (`ArgumentsLength`)。
    *   计算剩余参数的长度 (`RestLength`)。

6. **处理类型化数组**，例如：
    *   加载类型化数组的长度 (`LoadTypedArrayLength`)。
    *   检查 `DataView` 的边界 (`CheckJSDataViewBounds`)。

7. **处理类型转换**，例如：
    *   将可能包含洞（holes）的 Float64 值转换为非信号 NaN 的 Float64 值 (`HoleyFloat64ToMaybeNanFloat64`)。

8. **处理控制流相关的操作**，例如：
    *   函数返回 (`Return`)。
    *   减少中断预算以进行循环和返回，用于性能分析和分层编译 (`ReduceInterruptBudgetForLoop`, `ReduceInterruptBudgetForReturn`)。

9. **定义了值的寄存器分配约束**。  许多类都有 `SetValueLocationConstraints()` 方法，用于指定输入和输出值应该位于哪些寄存器中，或者是否可以使用寄存器。

**关于你的问题：**

*   **`.tq` 结尾：**  `v8/src/maglev/arm/maglev-ir-arm.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 v8 的 Torque 源代码。Torque 文件通常用于定义内置函数的类型和实现。

*   **与 javascript 的功能关系：**  这个文件中的代码直接对应着 JavaScript 的各种操作。例如：

    ```javascript
    // 对应 Int32NegateWithOverflow
    let a = 5;
    let b = -a;

    // 对应 Int32AddWithOverflow
    let x = 10;
    let y = 20;
    let z = x + y;

    // 对应 BuiltinStringFromCharCode
    let charCode = 65;
    let str = String.fromCharCode(charCode); // str 为 "A"

    // 对应 Float64Add
    let num1 = 1.5;
    let num2 = 2.5;
    let sum = num1 + num2;
    ```

*   **代码逻辑推理和假设输入输出：**

    以 `Int32NegateWithOverflow` 为例：

    **假设输入：**  一个 `Int32NegateWithOverflow` 节点，其 `value_input()` 连接到一个值为 `5` 的节点。

    **代码逻辑：**
    1. 将输入值 (5) 加载到寄存器 `value`。
    2. 比较 `value` 和 `0`。
    3. 如果 `value` 为 `0`，则跳转到 eager deopt，因为 `-0` 不是一个标准的正负 `0` 的溢出情况，需要特殊处理。
    4. 执行 `rsb` 指令（Reverse Subtract），计算 `0 - value`，结果存入寄存器 `out`，并设置条件码。
    5. 检查溢出标志 `vs`。如果设置了溢出标志（例如，输入是 `kMinInt`，取反会超出 `Int32` 的表示范围），则跳转到 eager deopt。

    **预期输出：**  `out` 寄存器将包含 `-5`。

*   **用户常见的编程错误：**

    许多节点都涉及到溢出检查，这与 JavaScript 程序员常见的整数溢出错误有关。例如：

    ```javascript
    // 整数溢出示例
    let maxInt = 2147483647;
    let result = maxInt + 1; // 在某些情况下，这可能会导致意想不到的结果，
                             // V8 的 Maglev 编译器会进行溢出检查。

    let minInt = -2147483648;
    let negatedMinInt = -minInt; // 也会触发溢出检查
    ```

    在这些情况下，如果 Maglev 编译器生成的代码检测到溢出，它可能会执行 "eager deopt"，即放弃当前优化的代码，退回到解释器执行，以确保程序的正确性。

**归纳一下它的功能：**

`v8/src/maglev/arm/maglev-ir-arm.cc` 文件的主要功能是 **定义了 Maglev 编译器在 ARM 架构下，如何将各种高级的中间表示操作转换为底层的 ARM 汇编指令**。它负责实现 JavaScript 语言中各种操作的底层细节，并处理诸如溢出检查、类型转换等问题，是 V8 引擎将 JavaScript 代码高效执行的关键组成部分。

### 提示词
```
这是目录为v8/src/maglev/arm/maglev-ir-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/arm/maglev-ir-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/logging.h"
#include "src/codegen/arm/assembler-arm.h"
#include "src/codegen/arm/register-arm.h"
#include "src/maglev/arm/maglev-assembler-arm-inl.h"
#include "src/maglev/maglev-assembler-inl.h"
#include "src/maglev/maglev-graph-processor.h"
#include "src/maglev/maglev-graph.h"
#include "src/maglev/maglev-ir-inl.h"
#include "src/maglev/maglev-ir.h"

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
  __ cmp(value, Operand(0));
  __ EmitEagerDeoptIf(eq, DeoptimizeReason::kOverflow, this);

  __ rsb(out, value, Operand(0), SetCC);
  // Output register must not be a register input into the eager deopt info.
  DCHECK_REGLIST_EMPTY(RegList{out} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
  __ EmitEagerDeoptIf(vs, DeoptimizeReason::kOverflow, this);
}

void Int32AbsWithOverflow::GenerateCode(MaglevAssembler* masm,
                                        const ProcessingState& state) {
  Register out = ToRegister(result());
  Label done;
  __ cmp(out, Operand(0));
  __ JumpIf(ge, &done);
  __ rsb(out, out, Operand(0), SetCC);
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
  Register value = ToRegister(value_input());
  Register out = ToRegister(result());
  __ add(out, value, Operand(1), SetCC);
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
  Register value = ToRegister(value_input());
  Register out = ToRegister(result());
  __ sub(out, value, Operand(1), SetCC);
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
      DCHECK_NE(scratch, result_string);
      __ AllocateTwoByteString(register_snapshot(), result_string, 1);
      __ Move(scratch, char_code);
      __ strh(scratch, FieldMemOperand(result_string,
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
    __ add(ToRegister(result()), ToRegister(allocation_block()),
           Operand(offset()));
  }
}

void ArgumentsLength::SetValueLocationConstraints() { DefineAsRegister(this); }

void ArgumentsLength::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  Register argc = ToRegister(result());
  __ ldr(argc, MemOperand(fp, StandardFrameConstants::kArgCOffset));
  __ sub(argc, argc, Operand(1));  // Remove receiver.
}

void RestLength::SetValueLocationConstraints() { DefineAsRegister(this); }

void RestLength::GenerateCode(MaglevAssembler* masm,
                              const ProcessingState& state) {
  Register length = ToRegister(result());
  Label done;
  __ ldr(length, MemOperand(fp, StandardFrameConstants::kArgCOffset));
  __ sub(length, length, Operand(formal_parameter_count() + 1), SetCC);
  __ b(kGreaterThanEqual, &done);
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
  __ add(out, left, right, SetCC);
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
  Register left = ToRegister(left_input());
  Register right = ToRegister(right_input());
  Register out = ToRegister(result());
  __ sub(out, left, right, SetCC);
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
  Register left = ToRegister(left_input());
  Register right = ToRegister(right_input());
  Register out = ToRegister(result());

  // TODO(leszeks): peephole optimise multiplication by a constant.

  MaglevAssembler::TemporaryRegisterScope temps(masm);
  bool out_alias_input = out == left || out == right;
  Register res_low = out;
  if (out_alias_input) {
    res_low = temps.AcquireScratch();
  }
  Register res_high = temps.AcquireScratch();
  __ smull(res_low, res_high, left, right);

  // ARM doesn't set the overflow flag for multiplication, so we need to
  // test on kNotEqual.
  __ cmp(res_high, Operand(res_low, ASR, 31));
  __ EmitEagerDeoptIf(ne, DeoptimizeReason::kOverflow, this);

  // If the result is zero, check if either lhs or rhs is negative.
  Label end;
  __ tst(res_low, res_low);
  __ b(ne, &end);
  Register temp = res_high;
  __ orr(temp, left, right, SetCC);
  // If one of them is negative, we must have a -0 result, which is non-int32,
  // so deopt.
  __ EmitEagerDeoptIf(mi, DeoptimizeReason::kOverflow, this);

  __ bind(&end);
  if (out_alias_input) {
    __ Move(out, res_low);
  }
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
  __ cmp(right, Operand(0));
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
        __ tst(left, left);
        __ JumpIf(eq, deopt);

        // Check if {left} is kMinInt and {right} is -1, in which case we'd have
        // to return -kMinInt, which is not representable as Int32.
        __ cmp(left, Operand(kMinInt));
        __ JumpIf(ne, *done);
        __ cmp(right, Operand(-1));
        __ JumpIf(ne, *done);
        __ JumpToDeopt(deopt);
      },
      done, left, right, this);
  __ bind(*done);

  // Perform the actual integer division.
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  bool out_alias_input = out == left || out == right;
  Register res = out;
  if (out_alias_input) {
    res = temps.AcquireScratch();
  }
  if (CpuFeatures::IsSupported(SUDIV)) {
    CpuFeatureScope scope(masm, SUDIV);
    __ sdiv(res, left, right);
  } else {
    UseScratchRegisterScope temps(masm);
    LowDwVfpRegister double_right = temps.AcquireLowD();
    SwVfpRegister tmp = double_right.low();
    DwVfpRegister double_left = temps.AcquireD();
    DwVfpRegister double_res = double_left;
    __ vmov(tmp, left);
    __ vcvt_f64_s32(double_left, tmp);
    __ vmov(tmp, right);
    __ vcvt_f64_s32(double_right, tmp);
    __ vdiv(double_res, double_left, double_right);
    __ vcvt_s32_f64(tmp, double_res);
    __ vmov(res, tmp);
  }

  // Check that the remainder is zero.
  Register temp = temps.AcquireScratch();
  __ mul(temp, res, right);
  __ cmp(temp, left);
  __ EmitEagerDeoptIf(ne, DeoptimizeReason::kNotInt32, this);

  __ Move(out, res);
}

namespace {
void Uint32Mod(MaglevAssembler* masm, Register out, Register left,
               Register right) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register res = temps.AcquireScratch();
  if (CpuFeatures::IsSupported(SUDIV)) {
    CpuFeatureScope scope(masm, SUDIV);
    __ udiv(res, left, right);
  } else {
    UseScratchRegisterScope temps(masm);
    LowDwVfpRegister double_right = temps.AcquireLowD();
    SwVfpRegister tmp = double_right.low();
    DwVfpRegister double_left = temps.AcquireD();
    DwVfpRegister double_res = double_left;
    __ vmov(tmp, left);
    __ vcvt_f64_s32(double_left, tmp);
    __ vmov(tmp, right);
    __ vcvt_f64_s32(double_right, tmp);
    __ vdiv(double_res, double_left, double_right);
    __ vcvt_s32_f64(tmp, double_res);
    __ vmov(res, tmp);
  }
  if (CpuFeatures::IsSupported(ARMv7)) {
    __ mls(out, res, right, left);
  } else {
    __ mul(res, res, right);
    __ sub(out, left, res);
  }
}
}  // namespace

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

  Register lhs = ToRegister(left_input());
  Register rhs = ToRegister(right_input());
  Register out = ToRegister(result());

  static constexpr DeoptimizeReason deopt_reason =
      DeoptimizeReason::kDivisionByZero;

  if (lhs == rhs) {
    // For the modulus algorithm described above, lhs and rhs must not alias
    // each other.
    __ tst(lhs, lhs);
    // TODO(victorgomes): This ideally should be kMinusZero, but Maglev only
    // allows one deopt reason per IR.
    __ EmitEagerDeoptIf(mi, deopt_reason, this);
    __ Move(ToRegister(result()), 0);
    return;
  }

  DCHECK_NE(lhs, rhs);

  ZoneLabelRef done(masm);
  ZoneLabelRef rhs_checked(masm);
  __ cmp(rhs, Operand(0));
  __ JumpToDeferredIf(
      le,
      [](MaglevAssembler* masm, ZoneLabelRef rhs_checked, Register rhs,
         Int32ModulusWithOverflow* node) {
        __ rsb(rhs, rhs, Operand(0), SetCC);
        __ b(ne, *rhs_checked);
        __ EmitEagerDeopt(node, deopt_reason);
      },
      rhs_checked, rhs, this);
  __ bind(*rhs_checked);

  __ cmp(lhs, Operand(0));
  __ JumpToDeferredIf(
      lt,
      [](MaglevAssembler* masm, ZoneLabelRef done, Register lhs, Register rhs,
         Register out, Int32ModulusWithOverflow* node) {
        __ rsb(lhs, lhs, Operand(0));
        Uint32Mod(masm, out, lhs, rhs);
        __ rsb(out, out, Operand(0), SetCC);
        // TODO(victorgomes): This ideally should be kMinusZero, but Maglev
        // only allows one deopt reason per IR.
        __ b(ne, *done);
        __ EmitEagerDeopt(node, deopt_reason);
      },
      done, lhs, rhs, out, this);

  Label rhs_not_power_of_2;
  {
    MaglevAssembler::TemporaryRegisterScope temps(masm);
    Register mask = temps.AcquireScratch();
    __ add(mask, rhs, Operand(-1));
    __ tst(mask, rhs);
    __ JumpIf(ne, &rhs_not_power_of_2);

    // {rhs} is power of 2.
    __ and_(out, mask, lhs);
    __ Jump(*done);
    // {mask} can be reused from now on.
  }

  __ bind(&rhs_not_power_of_2);
  Uint32Mod(masm, out, lhs, rhs);
  __ bind(*done);
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
  }
DEF_BITWISE_BINOP(Int32BitwiseAnd, and_)
DEF_BITWISE_BINOP(Int32BitwiseOr, orr)
DEF_BITWISE_BINOP(Int32BitwiseXor, eor)
#undef DEF_BITWISE_BINOP

#define DEF_SHIFT_BINOP(Instruction, opcode)                                   \
  void Instruction::SetValueLocationConstraints() {                            \
    UseRegister(left_input());                                                 \
    if (right_input().node()->Is<Int32Constant>()) {                           \
      UseAny(right_input());                                                   \
    } else {                                                                   \
      UseRegister(right_input());                                              \
    }                                                                          \
    DefineAsRegister(this);                                                    \
  }                                                                            \
  void Instruction::GenerateCode(MaglevAssembler* masm,                        \
                                 const ProcessingState& state) {               \
    Register left = ToRegister(left_input());                                  \
    Register out = ToRegister(result());                                       \
    if (Int32Constant* constant =                                              \
            right_input().node()->TryCast<Int32Constant>()) {                  \
      uint32_t shift = constant->value() & 31;                                 \
      if (shift == 0) {                                                        \
        /* TODO(victorgomes): Arm will do a shift of 32 if right == 0. Ideally \
         * we should not even emit the shift in the first place. We do a move  \
         * here for the moment. */                                             \
        __ Move(out, left);                                                    \
      } else {                                                                 \
        __ opcode(out, left, Operand(shift));                                  \
      }                                                                        \
    } else {                                                                   \
      MaglevAssembler::TemporaryRegisterScope temps(masm);                     \
      Register scratch = temps.AcquireScratch();                               \
      Register right = ToRegister(right_input());                              \
      __ and_(scratch, right, Operand(31));                                    \
      __ opcode(out, left, Operand(scratch));                                  \
    }                                                                          \
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
  Register value = ToRegister(value_input());
  Register out = ToRegister(result());
  __ mvn(out, Operand(value));
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
  __ vadd(out, left, right);
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
  __ vsub(out, left, right);
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
  __ vmul(out, left, right);
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
  __ vdiv(out, left, right);
}

int Float64Modulus::MaxCallStackArgs() const { return 0; }
void Float64Modulus::SetValueLocationConstraints() {
  UseFixed(left_input(), d0);
  UseFixed(right_input(), d1);
  DefineAsRegister(this);
}
void Float64Modulus::GenerateCode(MaglevAssembler* masm,
                                  const ProcessingState& state) {
  FrameScope scope(masm, StackFrame::MANUAL);
  __ PrepareCallCFunction(0, 2);
  __ MovToFloatParameters(ToDoubleRegister(left_input()),
                          ToDoubleRegister(right_input()));
  __ CallCFunction(ExternalReference::mod_two_doubles_operation(), 0, 2);
  // Move the result in the double result register.
  __ MovFromFloatResult(ToDoubleRegister(result()));
}

void Float64Negate::SetValueLocationConstraints() {
  UseRegister(input());
  DefineAsRegister(this);
}
void Float64Negate::GenerateCode(MaglevAssembler* masm,
                                 const ProcessingState& state) {
  DoubleRegister value = ToDoubleRegister(input());
  DoubleRegister out = ToDoubleRegister(result());
  __ vneg(out, value);
}

void Float64Abs::GenerateCode(MaglevAssembler* masm,
                              const ProcessingState& state) {
  DoubleRegister in = ToDoubleRegister(input());
  DoubleRegister out = ToDoubleRegister(result());
  __ vabs(out, in);
}

void Float64Round::GenerateCode(MaglevAssembler* masm,
                                const ProcessingState& state) {
  DoubleRegister in = ToDoubleRegister(input());
  DoubleRegister out = ToDoubleRegister(result());
  CpuFeatureScope scope(masm, ARMv8);
  if (kind_ == Kind::kNearest) {
    MaglevAssembler::TemporaryRegisterScope temps(masm);
    DoubleRegister temp = temps.AcquireDouble();
    __ Move(temp, in);
    // vrintn rounds to even on tie, while JS expects it to round towards
    // +Infinity. Fix the difference by checking if we rounded down by exactly
    // 0.5, and if so, round to the other side.
    __ vrintn(out, in);
    __ vsub(temp, temp, out);
    DoubleRegister half_one = temps.AcquireScratchDouble();
    __ Move(half_one, 0.5);
    __ VFPCompareAndSetFlags(temp, half_one);
    Label done;
    __ JumpIf(ne, &done, Label::kNear);
    // Fix wrong tie-to-even by adding 0.5 twice.
    __ vadd(out, out, half_one);
    __ vadd(out, out, half_one);
    __ bind(&done);
  } else if (kind_ == Kind::kCeil) {
    __ vrintp(out, in);
  } else if (kind_ == Kind::kFloor) {
    __ vrintm(out, in);
  }
}

int Float64Exponentiate::MaxCallStackArgs() const { return 0; }
void Float64Exponentiate::SetValueLocationConstraints() {
  UseFixed(left_input(), d0);
  UseFixed(right_input(), d1);
  DefineAsRegister(this);
}
void Float64Exponentiate::GenerateCode(MaglevAssembler* masm,
                                       const ProcessingState& state) {
  DoubleRegister left = ToDoubleRegister(left_input());
  DoubleRegister right = ToDoubleRegister(right_input());
  DoubleRegister out = ToDoubleRegister(result());
  FrameScope scope(masm, StackFrame::MANUAL);
  __ PrepareCallCFunction(0, 2);
  __ MovToFloatParameters(left, right);
  __ CallCFunction(ExternalReference::ieee754_pow_function(), 0, 2);
  __ MovFromFloatResult(out);
}

int Float64Ieee754Unary::MaxCallStackArgs() const { return 0; }
void Float64Ieee754Unary::SetValueLocationConstraints() {
  UseFixed(input(), d0);
  DefineAsRegister(this);
}
void Float64Ieee754Unary::GenerateCode(MaglevAssembler* masm,
                                       const ProcessingState& state) {
  DoubleRegister value = ToDoubleRegister(input());
  DoubleRegister out = ToDoubleRegister(result());
  FrameScope scope(masm, StackFrame::MANUAL);
  __ PrepareCallCFunction(0, 1);
  __ MovToFloatParameter(value);
  __ CallCFunction(ieee_function_ref(), 0, 1);
  __ MovFromFloatResult(out);
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
    __ lsr(result_register, result_register,
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
    __ sub(byte_length, byte_length, Operand(element_size - 1), SetCC);
    __ EmitEagerDeoptIf(mi, DeoptimizeReason::kOutOfBounds, this);
  }
  __ cmp(index, byte_length);
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
  __ VFPCanonicalizeNaN(ToDoubleRegister(result()), ToDoubleRegister(input()));
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
      __ cmp(sp, stack_limit);
      __ b(hi, &next);
    }

    // An interrupt has been requested and we must call into runtime to handle
    // it; since we already pay the call cost, combine with the TieringManager
    // call.
    {
      SaveRegisterStateForCall save_register_state(masm,
                                                   node->register_snapshot());
      Register function = scratch0;
      __ ldr(function, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
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
    __ ldr(function, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
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
  Register scratch = temps.Acquire();
  Register feedback_cell = scratch;
  Register budget = temps.Acquire();
  __ ldr(feedback_cell,
         MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ LoadTaggedField(
      feedback_cell,
      FieldMemOperand(feedback_cell, JSFunction::kFeedbackCellOffset));
  __ ldr(budget,
         FieldMemOperand(feedback_cell, FeedbackCell::kInterruptBudgetOffset));
  __ sub(budget, budget, Operand(amount), SetCC);
  __ str(budget,
         FieldMemOperand(feedback_cell, FeedbackCell::kInterruptBudgetOffset));
  ZoneLabelRef done(masm);
  __ JumpToDeferredIf(lt, HandleInterruptsAndTiering, done, node, type,
                      scratch);
  __ bind(*done);
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
      masm->compilation_info()->toplevel_compilation_unit()->pa
```