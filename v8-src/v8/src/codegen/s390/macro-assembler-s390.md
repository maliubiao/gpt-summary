Response: The user wants to understand the functionality of the provided C++ code snippet. This is the first part of a larger file. The code seems to be part of the V8 JavaScript engine, specifically the S390 architecture's macro assembler.

Here's a breakdown of the thinking process to summarize the functionality:

1. **Identify the Core Purpose:** The file name `macro-assembler-s390.cc` strongly suggests that this code is responsible for generating machine code instructions for the S390 architecture. A "macro assembler" typically provides higher-level abstractions over raw assembly instructions.

2. **Examine Included Headers:** The included headers provide clues about the code's responsibilities:
    * `<assert.h>`, `<limits.h>`: Standard C++ utilities.
    * `src/base/...`: V8's base library, likely containing utility functions.
    * `src/builtins/...`:  Code related to built-in JavaScript functions.
    * `src/codegen/...`: Core code generation components, including `macro-assembler.h` (the base class), `register-configuration.h`, and `code-factory.h`.
    * `src/debug/...`: Debugging support.
    * `src/deoptimizer/...`: Handling deoptimization (reverting to less optimized code).
    * `src/execution/...`: Runtime execution aspects like stack frames.
    * `src/heap/...`: Memory management and garbage collection.
    * `src/init/...`: Initialization processes.
    * `src/logging/...`: Performance tracking.
    * `src/objects/...`: Representation of JavaScript objects.
    * `src/runtime/...`: Implementation of JavaScript runtime functions.
    * `src/snapshot/...`: Creating and loading snapshots of the heap.

3. **Analyze Namespace and Defines:**
    * `namespace v8 { namespace internal {`: Indicates this code is within the internal implementation of V8.
    * `#define __ ACCESS_MASM(masm)`: A macro to simplify accessing the `MacroAssembler` instance.

4. **Scrutinize Key Functions:**  The code contains numerous functions. Focusing on the prominent ones reveals the core functionalities:
    * `DoubleMax`, `DoubleMin`, `FloatMax`, `FloatMin`: Implementations of `Math.max` and `Math.min` for floating-point numbers, potentially optimized for the S390 architecture (including vector enhancements).
    * `CeilF32`, `FloorF64`, `TruncF32`, `NearestIntF64`: Implementations of math functions like `Math.ceil`, `Math.floor`, etc.
    * `PushCallerSaved`, `PopCallerSaved`:  Functions for saving and restoring registers that are the responsibility of the caller to preserve.
    * `LoadFromConstantsTable`, `LoadRootRelative`, `StoreRootRelative`:  Accessing constants and the root object in V8's heap.
    * `Jump`, `Call`:  Generating jump and call instructions.
    * `Move`:  Generating instructions to move data between registers and memory.
    * `Push`, `Pop`:  Stack manipulation.
    * `RecordWriteField`, `RecordWrite`: Implementing the write barrier for garbage collection.
    * `PushCommonFrame`, `PopCommonFrame`, `PushStandardFrame`, `RestoreFrameStateForTailCall`, `EnterFrame`, `LeaveFrame`, `EnterExitFrame`, `LeaveExitFrame`: Managing stack frames for function calls.
    * `ConvertIntToDouble`, `ConvertDoubleToInt32`, etc.: Type conversion instructions.
    * `StubPrologue`, `Prologue`: Function prologues.
    * `DropArguments`:  Adjusting the stack pointer.
    * `InvokePrologue`, `InvokeFunctionCode`, `InvokeFunctionWithNewTarget`, `InvokeFunction`: Implementing function call logic.
    * `PushStackHandler`, `PopStackHandler`: Managing stack handlers for exception handling.
    * `IsObjectType`, `CompareObjectTypeRange`, `CompareRoot`: Type checking and comparisons.
    * `TruncateDoubleToI`, `TryInlineTruncateDoubleToI`:  Converting floating-point numbers to integers.

5. **Identify JavaScript Relevance:** The presence of functions like `DoubleMax`, `DoubleMin`, and the general concern with function calls and object manipulation clearly link this code to the execution of JavaScript.

6. **Construct a JavaScript Example:**  Based on the identified JavaScript-related functions, create a simple JavaScript example that would likely involve the execution of this C++ code. Mathematical operations and function calls are good candidates.

7. **Synthesize the Summary:** Combine the findings into a concise summary of the file's functionality, emphasizing its role as a macro assembler for the S390 architecture within V8, its connection to JavaScript features, and the kinds of operations it handles. Mention that this is only part of the file.
该文件是V8 JavaScript引擎中针对S390架构的宏汇编器（MacroAssembler）的C++实现的第一部分。 宏汇编器提供了一组高级接口，用于生成底层的S390汇编指令。

**功能归纳:**

1. **提供S390架构的汇编指令抽象:**  该文件定义了 `MacroAssembler` 类，其中包含了许多成员函数，这些函数对应着S390架构的各种汇编指令，例如加载、存储、跳转、调用、算术运算、比较等等。 这些函数隐藏了直接编写汇编代码的复杂性，并提供了更易于使用的接口。

2. **处理浮点数运算:** 包含了 `DoubleMax`, `DoubleMin`, `FloatMax`, `FloatMin` 等函数，用于实现浮点数的最大值和最小值操作。 这些函数可能针对S390架构的特性进行了优化，例如利用了向量增强设施 (VECTOR_ENHANCE_FACILITY_1)。  还包含 `CeilF32`, `FloorF64`, `TruncF32`, `NearestIntF64` 等函数，用于实现浮点数的取整操作。

3. **管理函数调用约定和栈帧:**  包含了 `PushCallerSaved`, `PopCallerSaved` 用于保存和恢复调用者保存的寄存器。  `PushCommonFrame`, `PopCommonFrame`, `PushStandardFrame`, `EnterFrame`, `LeaveFrame`, `EnterExitFrame`, `LeaveExitFrame` 等函数用于处理函数调用时的栈帧的建立、销毁和状态管理。

4. **处理常量池和根对象:** 提供了 `LoadFromConstantsTable`, `LoadRootRelative`, `StoreRootRelative` 等函数，用于加载和存储常量表中的值以及相对于根对象的偏移。

5. **实现跳转和调用:**  提供了 `Jump`, `Call`, `TailCallBuiltin`, `CallBuiltin` 等函数，用于生成跳转和调用指令，包括对内置函数的调用。

6. **数据移动操作:**  提供了 `Move`, `Push`, `Pop`, `MultiPush`, `MultiPop` 等函数，用于在寄存器、内存和栈之间移动数据。

7. **实现写屏障 (Write Barrier):** 包含了 `RecordWriteField`, `RecordWrite` 等函数，用于在修改堆对象时，记录旧对象的信息，以便垃圾回收器能够正确追踪对象引用。

8. **类型转换:**  提供了多种类型转换函数，例如 `ConvertIntToDouble`, `ConvertDoubleToInt32` 等，用于在整数和浮点数之间进行转换。

9. **支持调试:**  包含 `CheckDebugHook` 函数，用于在函数调用时检查是否需要触发调试钩子。

10. **处理函数调用序言和尾声:**  `StubPrologue`, `Prologue` 用于生成函数调用的序言代码，`RestoreFrameStateForTailCall` 用于处理尾调用。

**与 Javascript 功能的关系及 Javascript 示例:**

该文件中的代码是 V8 引擎执行 JavaScript 代码的基础。  当 JavaScript 代码需要执行某些操作时，V8 引擎会根据目标架构（这里是 S390）选择相应的宏汇编器来生成机器码。

**示例:**

假设有以下 JavaScript 代码：

```javascript
function add(a, b) {
  return Math.max(a, b);
}

let result = add(5.2, 3.8);
```

当 V8 引擎执行这段代码时，以下操作可能会涉及到 `macro-assembler-s390.cc` 中的代码：

1. **调用 `add` 函数:**  `InvokeFunction` 系列的函数会被调用，用于设置栈帧、传递参数、跳转到 `add` 函数的代码。
2. **调用 `Math.max`:**  `DoubleMax` 函数会被调用，生成比较 `a` 和 `b` 并返回较大值的 S390 汇编指令。
3. **浮点数运算:**  `DoubleMax` 函数内部会使用 S390 的浮点数比较和条件跳转指令 (`cdbr`, `bge`, `ldr` 等)。
4. **返回值:**  生成的汇编代码会将 `Math.max` 的结果存储到特定的寄存器中，然后通过栈帧返回。

**更具体的 `Math.max` 示例:**

JavaScript 代码:

```javascript
let x = 10.5;
let y = 5.2;
let maximum = Math.max(x, y);
```

在 S390 架构上，`MacroAssembler::DoubleMax` 函数可能会生成如下类似的汇编指令 (简化表示):

```assembly
  cdbr  d0, d2       ; 比较 d0 (x) 和 d2 (y)
  bunordered return_nan ; 如果无序 (NaN)，跳转到 return_nan
  beq   check_zero   ; 如果相等，跳转到 check_zero
  bge   return_left  ; 如果 d0 >= d2，跳转到 return_left
  b     return_right ; 否则跳转到 return_right

return_left:
  ldr   d0, d0       ; 将 d0 (x) 加载到结果寄存器 d0
  b     done

return_right:
  ldr   d0, d2       ; 将 d2 (y) 加载到结果寄存器 d0
  b     done

return_nan:
  adbr  d0, d2       ; 如果是 NaN，传播 NaN
  b     return_left

check_zero:
  lzdr  f0           ; 加载 0.0 到 f0
  cdbr  d0, f0       ; 比较 d0 和 0.0
  bne   return_left  ; 如果不等于 0，返回 d0
  ldr   d0, d0       ; 否则，执行 +0 + -0 的逻辑 (假设 d0 和 d2 都是 0 或 -0)
  adbr  d0, d2
  b     done

done:
  ; ... 继续执行 ...
```

总而言之，该文件是 V8 引擎在 S390 架构上执行 JavaScript 代码的关键组成部分，它负责将高级的 JavaScript 操作转化为底层的机器指令。

Prompt: 
```
这是目录为v8/src/codegen/s390/macro-assembler-s390.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <assert.h>  // For assert
#include <limits.h>  // For LONG_MIN, LONG_MAX.

#if V8_TARGET_ARCH_S390X

#include "src/base/bits.h"
#include "src/base/division-by-constant.h"
#include "src/builtins/builtins-inl.h"
#include "src/codegen/callable.h"
#include "src/codegen/code-factory.h"
#include "src/codegen/external-reference-table.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/register-configuration.h"
#include "src/codegen/register.h"
#include "src/debug/debug.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/frames-inl.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/init/bootstrapper.h"
#include "src/logging/counters.h"
#include "src/objects/smi.h"
#include "src/runtime/runtime.h"
#include "src/snapshot/snapshot.h"

// Satisfy cpplint check, but don't include platform-specific header. It is
// included recursively via macro-assembler.h.
#if 0
#include "src/codegen/s390/macro-assembler-s390.h"
#endif

#define __ ACCESS_MASM(masm)

namespace v8 {
namespace internal {

namespace {

// For WebAssembly we care about the full floating point (Simd) registers. If we
// are not running Wasm, we can get away with saving half of those (F64)
// registers.
#if V8_ENABLE_WEBASSEMBLY
constexpr int kStackSavedSavedFPSizeInBytes =
    kNumCallerSavedDoubles * kSimd128Size;
#else
constexpr int kStackSavedSavedFPSizeInBytes =
    kNumCallerSavedDoubles * kDoubleSize;
#endif  // V8_ENABLE_WEBASSEMBLY

}  // namespace

void MacroAssembler::DoubleMax(DoubleRegister result_reg,
                               DoubleRegister left_reg,
                               DoubleRegister right_reg) {
  if (CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_1)) {
    vfmax(result_reg, left_reg, right_reg, Condition(1), Condition(8),
          Condition(3));
    return;
  }

  Label check_zero, return_left, return_right, return_nan, done;
  cdbr(left_reg, right_reg);
  bunordered(&return_nan, Label::kNear);
  beq(&check_zero);
  bge(&return_left, Label::kNear);
  b(&return_right, Label::kNear);

  bind(&check_zero);
  lzdr(kDoubleRegZero);
  cdbr(left_reg, kDoubleRegZero);
  /* left == right != 0. */
  bne(&return_left, Label::kNear);
  /* At this point, both left and right are either 0 or -0. */
  /* N.B. The following works because +0 + -0 == +0 */
  /* For max we want logical-and of sign bit: (L + R) */
  ldr(result_reg, left_reg);
  adbr(result_reg, right_reg);
  b(&done, Label::kNear);

  bind(&return_nan);
  /* If left or right are NaN, adbr propagates the appropriate one.*/
  adbr(left_reg, right_reg);
  b(&return_left, Label::kNear);

  bind(&return_right);
  if (right_reg != result_reg) {
    ldr(result_reg, right_reg);
  }
  b(&done, Label::kNear);

  bind(&return_left);
  if (left_reg != result_reg) {
    ldr(result_reg, left_reg);
  }
  bind(&done);
}

void MacroAssembler::DoubleMin(DoubleRegister result_reg,
                               DoubleRegister left_reg,
                               DoubleRegister right_reg) {
  if (CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_1)) {
    vfmin(result_reg, left_reg, right_reg, Condition(1), Condition(8),
          Condition(3));
    return;
  }
  Label check_zero, return_left, return_right, return_nan, done;
  cdbr(left_reg, right_reg);
  bunordered(&return_nan, Label::kNear);
  beq(&check_zero);
  ble(&return_left, Label::kNear);
  b(&return_right, Label::kNear);

  bind(&check_zero);
  lzdr(kDoubleRegZero);
  cdbr(left_reg, kDoubleRegZero);
  /* left == right != 0. */
  bne(&return_left, Label::kNear);
  /* At this point, both left and right are either 0 or -0. */
  /* N.B. The following works because +0 + -0 == +0 */
  /* For min we want logical-or of sign bit: -(-L + -R) */
  lcdbr(left_reg, left_reg);
  ldr(result_reg, left_reg);
  if (left_reg == right_reg) {
    adbr(result_reg, right_reg);
  } else {
    sdbr(result_reg, right_reg);
  }
  lcdbr(result_reg, result_reg);
  b(&done, Label::kNear);

  bind(&return_nan);
  /* If left or right are NaN, adbr propagates the appropriate one.*/
  adbr(left_reg, right_reg);
  b(&return_left, Label::kNear);

  bind(&return_right);
  if (right_reg != result_reg) {
    ldr(result_reg, right_reg);
  }
  b(&done, Label::kNear);

  bind(&return_left);
  if (left_reg != result_reg) {
    ldr(result_reg, left_reg);
  }
  bind(&done);
}

void MacroAssembler::FloatMax(DoubleRegister result_reg,
                              DoubleRegister left_reg,
                              DoubleRegister right_reg) {
  if (CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_1)) {
    vfmax(result_reg, left_reg, right_reg, Condition(1), Condition(8),
          Condition(2));
    return;
  }
  Label check_zero, return_left, return_right, return_nan, done;
  cebr(left_reg, right_reg);
  bunordered(&return_nan, Label::kNear);
  beq(&check_zero);
  bge(&return_left, Label::kNear);
  b(&return_right, Label::kNear);

  bind(&check_zero);
  lzdr(kDoubleRegZero);
  cebr(left_reg, kDoubleRegZero);
  /* left == right != 0. */
  bne(&return_left, Label::kNear);
  /* At this point, both left and right are either 0 or -0. */
  /* N.B. The following works because +0 + -0 == +0 */
  /* For max we want logical-and of sign bit: (L + R) */
  ldr(result_reg, left_reg);
  aebr(result_reg, right_reg);
  b(&done, Label::kNear);

  bind(&return_nan);
  /* If left or right are NaN, aebr propagates the appropriate one.*/
  aebr(left_reg, right_reg);
  b(&return_left, Label::kNear);

  bind(&return_right);
  if (right_reg != result_reg) {
    ldr(result_reg, right_reg);
  }
  b(&done, Label::kNear);

  bind(&return_left);
  if (left_reg != result_reg) {
    ldr(result_reg, left_reg);
  }
  bind(&done);
}

void MacroAssembler::FloatMin(DoubleRegister result_reg,
                              DoubleRegister left_reg,
                              DoubleRegister right_reg) {
  if (CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_1)) {
    vfmin(result_reg, left_reg, right_reg, Condition(1), Condition(8),
          Condition(2));
    return;
  }

  Label check_zero, return_left, return_right, return_nan, done;
  cebr(left_reg, right_reg);
  bunordered(&return_nan, Label::kNear);
  beq(&check_zero);
  ble(&return_left, Label::kNear);
  b(&return_right, Label::kNear);

  bind(&check_zero);
  lzdr(kDoubleRegZero);
  cebr(left_reg, kDoubleRegZero);
  /* left == right != 0. */
  bne(&return_left, Label::kNear);
  /* At this point, both left and right are either 0 or -0. */
  /* N.B. The following works because +0 + -0 == +0 */
  /* For min we want logical-or of sign bit: -(-L + -R) */
  lcebr(left_reg, left_reg);
  ldr(result_reg, left_reg);
  if (left_reg == right_reg) {
    aebr(result_reg, right_reg);
  } else {
    sebr(result_reg, right_reg);
  }
  lcebr(result_reg, result_reg);
  b(&done, Label::kNear);

  bind(&return_nan);
  /* If left or right are NaN, aebr propagates the appropriate one.*/
  aebr(left_reg, right_reg);
  b(&return_left, Label::kNear);

  bind(&return_right);
  if (right_reg != result_reg) {
    ldr(result_reg, right_reg);
  }
  b(&done, Label::kNear);

  bind(&return_left);
  if (left_reg != result_reg) {
    ldr(result_reg, left_reg);
  }
  bind(&done);
}

void MacroAssembler::CeilF32(DoubleRegister dst, DoubleRegister src) {
  fiebra(ROUND_TOWARD_POS_INF, dst, src);
}

void MacroAssembler::CeilF64(DoubleRegister dst, DoubleRegister src) {
  fidbra(ROUND_TOWARD_POS_INF, dst, src);
}

void MacroAssembler::FloorF32(DoubleRegister dst, DoubleRegister src) {
  fiebra(ROUND_TOWARD_NEG_INF, dst, src);
}

void MacroAssembler::FloorF64(DoubleRegister dst, DoubleRegister src) {
  fidbra(ROUND_TOWARD_NEG_INF, dst, src);
}

void MacroAssembler::TruncF32(DoubleRegister dst, DoubleRegister src) {
  fiebra(ROUND_TOWARD_0, dst, src);
}

void MacroAssembler::TruncF64(DoubleRegister dst, DoubleRegister src) {
  fidbra(ROUND_TOWARD_0, dst, src);
}

void MacroAssembler::NearestIntF32(DoubleRegister dst, DoubleRegister src) {
  fiebra(ROUND_TO_NEAREST_TO_EVEN, dst, src);
}

void MacroAssembler::NearestIntF64(DoubleRegister dst, DoubleRegister src) {
  fidbra(ROUND_TO_NEAREST_TO_EVEN, dst, src);
}

int MacroAssembler::RequiredStackSizeForCallerSaved(SaveFPRegsMode fp_mode,
                                                    Register exclusion1,
                                                    Register exclusion2,
                                                    Register exclusion3) const {
  int bytes = 0;

  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = kJSCallerSaved - exclusions;
  bytes += list.Count() * kSystemPointerSize;

  if (fp_mode == SaveFPRegsMode::kSave) {
    bytes += kStackSavedSavedFPSizeInBytes;
  }

  return bytes;
}

int MacroAssembler::PushCallerSaved(SaveFPRegsMode fp_mode, Register scratch,
                                    Register exclusion1, Register exclusion2,
                                    Register exclusion3) {
  int bytes = 0;

  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = kJSCallerSaved - exclusions;
  MultiPush(list);
  bytes += list.Count() * kSystemPointerSize;

  if (fp_mode == SaveFPRegsMode::kSave) {
    MultiPushF64OrV128(kCallerSavedDoubles, scratch);
    bytes += kStackSavedSavedFPSizeInBytes;
  }

  return bytes;
}

int MacroAssembler::PopCallerSaved(SaveFPRegsMode fp_mode, Register scratch,
                                   Register exclusion1, Register exclusion2,
                                   Register exclusion3) {
  int bytes = 0;
  if (fp_mode == SaveFPRegsMode::kSave) {
    MultiPopF64OrV128(kCallerSavedDoubles, scratch);
    bytes += kStackSavedSavedFPSizeInBytes;
  }

  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = kJSCallerSaved - exclusions;
  MultiPop(list);
  bytes += list.Count() * kSystemPointerSize;

  return bytes;
}

void MacroAssembler::LoadFromConstantsTable(Register destination,
                                            int constant_index) {
  DCHECK(RootsTable::IsImmortalImmovable(RootIndex::kBuiltinsConstantsTable));

  const uint32_t offset = OFFSET_OF_DATA_START(FixedArray) +
                          constant_index * kSystemPointerSize - kHeapObjectTag;

  CHECK(is_uint19(offset));
  DCHECK_NE(destination, r0);
  LoadRoot(destination, RootIndex::kBuiltinsConstantsTable);
  LoadTaggedField(destination,
                  FieldMemOperand(destination, FixedArray::OffsetOfElementAt(
                                                   constant_index)),
                  r1);
}

void MacroAssembler::LoadRootRelative(Register destination, int32_t offset) {
  LoadU64(destination, MemOperand(kRootRegister, offset));
}

void MacroAssembler::StoreRootRelative(int32_t offset, Register value) {
  StoreU64(value, MemOperand(kRootRegister, offset));
}

void MacroAssembler::LoadRootRegisterOffset(Register destination,
                                            intptr_t offset) {
  if (offset == 0) {
    mov(destination, kRootRegister);
  } else if (is_uint12(offset)) {
    la(destination, MemOperand(kRootRegister, offset));
  } else {
    DCHECK(is_int20(offset));
    lay(destination, MemOperand(kRootRegister, offset));
  }
}

MemOperand MacroAssembler::ExternalReferenceAsOperand(
    ExternalReference reference, Register scratch) {
  if (root_array_available()) {
    if (reference.IsIsolateFieldId()) {
      return MemOperand(kRootRegister, reference.offset_from_root_register());
    }
    if (options().enable_root_relative_access) {
      intptr_t offset =
          RootRegisterOffsetForExternalReference(isolate(), reference);
      if (is_int32(offset)) {
        return MemOperand(kRootRegister, static_cast<int32_t>(offset));
      }
    }
    if (options().isolate_independent_code) {
      if (IsAddressableThroughRootRegister(isolate(), reference)) {
        // Some external references can be efficiently loaded as an offset from
        // kRootRegister.
        intptr_t offset =
            RootRegisterOffsetForExternalReference(isolate(), reference);
        CHECK(is_int32(offset));
        return MemOperand(kRootRegister, static_cast<int32_t>(offset));
      } else {
        // Otherwise, do a memory load from the external reference table.
        LoadU64(scratch,
                MemOperand(kRootRegister,
                           RootRegisterOffsetForExternalReferenceTableEntry(
                               isolate(), reference)));
        return MemOperand(scratch, 0);
      }
    }
  }
  Move(scratch, reference);
  return MemOperand(scratch, 0);
}

void MacroAssembler::Jump(Register target, Condition cond) { b(cond, target); }

void MacroAssembler::Jump(intptr_t target, RelocInfo::Mode rmode,
                          Condition cond) {
  Label skip;

  if (cond != al) b(NegateCondition(cond), &skip);

  mov(ip, Operand(target, rmode));
  b(ip);

  bind(&skip);
}

void MacroAssembler::Jump(Address target, RelocInfo::Mode rmode,
                          Condition cond) {
  DCHECK(!RelocInfo::IsCodeTarget(rmode));
  Jump(static_cast<intptr_t>(target), rmode, cond);
}

void MacroAssembler::Jump(Handle<Code> code, RelocInfo::Mode rmode,
                          Condition cond) {
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  DCHECK_IMPLIES(options().isolate_independent_code,
                 Builtins::IsIsolateIndependentBuiltin(*code));

  Builtin builtin = Builtin::kNoBuiltinId;
  if (isolate()->builtins()->IsBuiltinHandle(code, &builtin)) {
    TailCallBuiltin(builtin, cond);
    return;
  }
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  jump(code, RelocInfo::RELATIVE_CODE_TARGET, cond);
}

void MacroAssembler::Jump(const ExternalReference& reference) {
#if V8_OS_ZOS
  // Place reference into scratch r12 ip register
  Move(ip, reference);
  // z/OS uses function descriptors, extract code entry into r6
  LoadMultipleP(r5, r6, MemOperand(ip));
  // Preserve return address into r14
  mov(r14, r7);
  // Call C Function
  StoreReturnAddressAndCall(r6);
  // Branch to return address in r14
  b(r14);
#else
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Move(scratch, reference);
  Jump(scratch);
#endif
}

void MacroAssembler::Call(Register target) {
  // Branch to target via indirect branch
  basr(r14, target);
}

void MacroAssembler::CallJSEntry(Register target) {
  DCHECK(target == r4);
  Call(target);
}

int MacroAssembler::CallSizeNotPredictableCodeSize(Address target,
                                                   RelocInfo::Mode rmode,
                                                   Condition cond) {
  // S390 Assembler::move sequence is IILF / IIHF
  int size;
  size = 14;  // IILF + IIHF + BASR
  return size;
}

void MacroAssembler::Call(Address target, RelocInfo::Mode rmode,
                          Condition cond) {
  DCHECK(cond == al);

  mov(ip, Operand(target, rmode));
  basr(r14, ip);
}

void MacroAssembler::Call(Handle<Code> code, RelocInfo::Mode rmode,
                          Condition cond) {
  DCHECK(RelocInfo::IsCodeTarget(rmode) && cond == al);

  DCHECK_IMPLIES(options().isolate_independent_code,
                 Builtins::IsIsolateIndependentBuiltin(*code));

  Builtin builtin = Builtin::kNoBuiltinId;
  if (isolate()->builtins()->IsBuiltinHandle(code, &builtin)) {
    CallBuiltin(builtin);
    return;
  }
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  call(code, rmode);
}

void MacroAssembler::CallBuiltin(Builtin builtin, Condition cond) {
  ASM_CODE_COMMENT_STRING(this, CommentForOffHeapTrampoline("call", builtin));
  // Use ip directly instead of using UseScratchRegisterScope, as we do not
  // preserve scratch registers across calls.
  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute: {
      mov(ip, Operand(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET));
      Call(ip);
      break;
    }
    case BuiltinCallJumpMode::kPCRelative:
      UNREACHABLE();
    case BuiltinCallJumpMode::kIndirect:
      LoadU64(ip, EntryFromBuiltinAsOperand(builtin));
      Call(ip);
      break;
    case BuiltinCallJumpMode::kForMksnapshot: {
      Handle<Code> code = isolate()->builtins()->code_handle(builtin);
      call(code, RelocInfo::CODE_TARGET);
      break;
    }
  }
}

void MacroAssembler::TailCallBuiltin(Builtin builtin, Condition cond) {
  ASM_CODE_COMMENT_STRING(this,
                          CommentForOffHeapTrampoline("tail call", builtin));
  // Use ip directly instead of using UseScratchRegisterScope, as we do not
  // preserve scratch registers across calls.
  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute: {
      mov(ip, Operand(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET));
      Jump(ip, cond);
      break;
    }
    case BuiltinCallJumpMode::kPCRelative:
      UNREACHABLE();
    case BuiltinCallJumpMode::kIndirect:
      LoadU64(ip, EntryFromBuiltinAsOperand(builtin));
      Jump(ip, cond);
      break;
    case BuiltinCallJumpMode::kForMksnapshot: {
      if (options().use_pc_relative_calls_and_jumps_for_mksnapshot) {
        Handle<Code> code = isolate()->builtins()->code_handle(builtin);
        jump(code, RelocInfo::RELATIVE_CODE_TARGET, cond);
      } else {
        LoadU64(ip, EntryFromBuiltinAsOperand(builtin));
        Jump(ip, cond);
      }
      break;
    }
  }
}

void MacroAssembler::Drop(int count) {
  if (count > 0) {
    int total = count * kSystemPointerSize;
    if (is_uint12(total)) {
      la(sp, MemOperand(sp, total));
    } else if (is_int20(total)) {
      lay(sp, MemOperand(sp, total));
    } else {
      AddS64(sp, Operand(total));
    }
  }
}

void MacroAssembler::Drop(Register count, Register scratch) {
  ShiftLeftU64(scratch, count, Operand(kSystemPointerSizeLog2));
  AddS64(sp, sp, scratch);
}

void MacroAssembler::TestCodeIsMarkedForDeoptimization(Register code,
                                                       Register scratch) {
  LoadU32(scratch, FieldMemOperand(code, Code::kFlagsOffset));
  TestBit(scratch, Code::kMarkedForDeoptimizationBit, scratch);
}

Operand MacroAssembler::ClearedValue() const {
  return Operand(static_cast<int32_t>(i::ClearedValue(isolate()).ptr()));
}

void MacroAssembler::Call(Label* target) { b(r14, target); }

void MacroAssembler::Push(Handle<HeapObject> handle) {
  mov(r0, Operand(handle));
  push(r0);
}

void MacroAssembler::Push(Tagged<Smi> smi) {
  mov(r0, Operand(smi));
  push(r0);
}

void MacroAssembler::Push(Tagged<TaggedIndex> index) {
  // TaggedIndex is the same as Smi for 32 bit archs.
  mov(r0, Operand(static_cast<uint32_t>(index.value())));
  push(r0);
}

void MacroAssembler::Move(Register dst, Handle<HeapObject> value,
                          RelocInfo::Mode rmode) {
  // TODO(jgruber,v8:8887): Also consider a root-relative load when generating
  // non-isolate-independent code. In many cases it might be cheaper than
  // embedding the relocatable value.
  if (root_array_available_ && options().isolate_independent_code) {
    IndirectLoadConstant(dst, value);
    return;
  } else if (RelocInfo::IsCompressedEmbeddedObject(rmode)) {
    EmbeddedObjectIndex index = AddEmbeddedObject(value);
    DCHECK(is_uint32(index));
    mov(dst, Operand(static_cast<int>(index), rmode));
  } else {
    DCHECK(RelocInfo::IsFullEmbeddedObject(rmode));
    mov(dst, Operand(value.address(), rmode));
  }
}

void MacroAssembler::Move(Register dst, ExternalReference reference) {
  if (root_array_available()) {
    if (reference.IsIsolateFieldId()) {
      AddS64(dst, kRootRegister,
             Operand(reference.offset_from_root_register()));
      return;
    }
    if (options().isolate_independent_code) {
      IndirectLoadExternalReference(dst, reference);
      return;
    }
  }

  // External references should not get created with IDs if
  // `!root_array_available()`.
  CHECK(!reference.IsIsolateFieldId());
  mov(dst, Operand(reference));
}

void MacroAssembler::LoadIsolateField(Register dst, IsolateFieldId id) {
  Move(dst, ExternalReference::Create(id));
}

void MacroAssembler::Move(Register dst, Register src, Condition cond) {
  if (dst != src) {
    if (cond == al) {
      mov(dst, src);
    } else {
      LoadOnConditionP(cond, dst, src);
    }
  }
}

void MacroAssembler::Move(DoubleRegister dst, DoubleRegister src) {
  if (dst != src) {
    ldr(dst, src);
  }
}

void MacroAssembler::Move(Register dst, const MemOperand& src) {
  LoadU64(dst, src);
}

// Wrapper around Assembler::mvc (SS-a format)
void MacroAssembler::MoveChar(const MemOperand& opnd1, const MemOperand& opnd2,
                              const Operand& length) {
  mvc(opnd1, opnd2, Operand(static_cast<intptr_t>(length.immediate() - 1)));
}

// Wrapper around Assembler::clc (SS-a format)
void MacroAssembler::CompareLogicalChar(const MemOperand& opnd1,
                                        const MemOperand& opnd2,
                                        const Operand& length) {
  clc(opnd1, opnd2, Operand(static_cast<intptr_t>(length.immediate() - 1)));
}

// Wrapper around Assembler::xc (SS-a format)
void MacroAssembler::ExclusiveOrChar(const MemOperand& opnd1,
                                     const MemOperand& opnd2,
                                     const Operand& length) {
  xc(opnd1, opnd2, Operand(static_cast<intptr_t>(length.immediate() - 1)));
}

// Wrapper around Assembler::risbg(n) (RIE-f)
void MacroAssembler::RotateInsertSelectBits(Register dst, Register src,
                                            const Operand& startBit,
                                            const Operand& endBit,
                                            const Operand& shiftAmt,
                                            bool zeroBits) {
  if (zeroBits)
    // High tag the top bit of I4/EndBit to zero out any unselected bits
    risbg(dst, src, startBit,
          Operand(static_cast<intptr_t>(endBit.immediate() | 0x80)), shiftAmt);
  else
    risbg(dst, src, startBit, endBit, shiftAmt);
}

void MacroAssembler::BranchRelativeOnIdxHighP(Register dst, Register inc,
                                              Label* L) {
  brxhg(dst, inc, L);
}

void MacroAssembler::PushArray(Register array, Register size, Register scratch,
                               Register scratch2, PushArrayOrder order) {
  Label loop, done;

  if (order == kNormal) {
    ShiftLeftU64(scratch, size, Operand(kSystemPointerSizeLog2));
    lay(scratch, MemOperand(array, scratch));
    bind(&loop);
    CmpS64(array, scratch);
    bge(&done);
    lay(scratch, MemOperand(scratch, -kSystemPointerSize));
    lay(sp, MemOperand(sp, -kSystemPointerSize));
    MoveChar(MemOperand(sp), MemOperand(scratch), Operand(kSystemPointerSize));
    b(&loop);
    bind(&done);
  } else {
    DCHECK_NE(scratch2, r0);
    ShiftLeftU64(scratch, size, Operand(kSystemPointerSizeLog2));
    lay(scratch, MemOperand(array, scratch));
    mov(scratch2, array);
    bind(&loop);
    CmpS64(scratch2, scratch);
    bge(&done);
    lay(sp, MemOperand(sp, -kSystemPointerSize));
    MoveChar(MemOperand(sp), MemOperand(scratch2), Operand(kSystemPointerSize));
    lay(scratch2, MemOperand(scratch2, kSystemPointerSize));
    b(&loop);
    bind(&done);
  }
}

void MacroAssembler::MultiPush(RegList regs, Register location) {
  int16_t num_to_push = regs.Count();
  int16_t stack_offset = num_to_push * kSystemPointerSize;

  SubS64(location, location, Operand(stack_offset));
  for (int16_t i = Register::kNumRegisters - 1; i >= 0; i--) {
    if ((regs.bits() & (1 << i)) != 0) {
      stack_offset -= kSystemPointerSize;
      StoreU64(ToRegister(i), MemOperand(location, stack_offset));
    }
  }
}

void MacroAssembler::MultiPop(RegList regs, Register location) {
  int16_t stack_offset = 0;

  for (int16_t i = 0; i < Register::kNumRegisters; i++) {
    if ((regs.bits() & (1 << i)) != 0) {
      LoadU64(ToRegister(i), MemOperand(location, stack_offset));
      stack_offset += kSystemPointerSize;
    }
  }
  AddS64(location, location, Operand(stack_offset));
}

void MacroAssembler::MultiPushDoubles(DoubleRegList dregs, Register location) {
  int16_t num_to_push = dregs.Count();
  int16_t stack_offset = num_to_push * kDoubleSize;

  SubS64(location, location, Operand(stack_offset));
  for (int16_t i = DoubleRegister::kNumRegisters - 1; i >= 0; i--) {
    if ((dregs.bits() & (1 << i)) != 0) {
      DoubleRegister dreg = DoubleRegister::from_code(i);
      stack_offset -= kDoubleSize;
      StoreF64(dreg, MemOperand(location, stack_offset));
    }
  }
}

void MacroAssembler::MultiPushV128(DoubleRegList dregs, Register scratch,
                                   Register location) {
  int16_t num_to_push = dregs.Count();
  int16_t stack_offset = num_to_push * kSimd128Size;

  SubS64(location, location, Operand(stack_offset));
  for (int16_t i = Simd128Register::kNumRegisters - 1; i >= 0; i--) {
    if ((dregs.bits() & (1 << i)) != 0) {
      Simd128Register dreg = Simd128Register::from_code(i);
      stack_offset -= kSimd128Size;
      StoreV128(dreg, MemOperand(location, stack_offset), scratch);
    }
  }
}

void MacroAssembler::MultiPopDoubles(DoubleRegList dregs, Register location) {
  int16_t stack_offset = 0;

  for (int16_t i = 0; i < DoubleRegister::kNumRegisters; i++) {
    if ((dregs.bits() & (1 << i)) != 0) {
      DoubleRegister dreg = DoubleRegister::from_code(i);
      LoadF64(dreg, MemOperand(location, stack_offset));
      stack_offset += kDoubleSize;
    }
  }
  AddS64(location, location, Operand(stack_offset));
}

void MacroAssembler::MultiPopV128(DoubleRegList dregs, Register scratch,
                                  Register location) {
  int16_t stack_offset = 0;

  for (int16_t i = 0; i < Simd128Register::kNumRegisters; i++) {
    if ((dregs.bits() & (1 << i)) != 0) {
      Simd128Register dreg = Simd128Register::from_code(i);
      LoadV128(dreg, MemOperand(location, stack_offset), scratch);
      stack_offset += kSimd128Size;
    }
  }
  AddS64(location, location, Operand(stack_offset));
}

void MacroAssembler::MultiPushF64OrV128(DoubleRegList dregs, Register scratch,
                                        Register location) {
#if V8_ENABLE_WEBASSEMBLY
  bool generating_bultins =
      isolate() && isolate()->IsGeneratingEmbeddedBuiltins();
  if (generating_bultins) {
    Label push_doubles, simd_pushed;
    Move(r1, ExternalReference::supports_wasm_simd_128_address());
    LoadU8(r1, MemOperand(r1));
    LoadAndTestP(r1, r1);  // If > 0 then simd is available.
    ble(&push_doubles, Label::kNear);
    // Save vector registers, don't save double registers anymore.
    MultiPushV128(dregs, scratch);
    b(&simd_pushed);
    bind(&push_doubles);
    // Simd not supported, only save double registers.
    MultiPushDoubles(dregs);
    // We still need to allocate empty space on the stack as if
    // Simd rgeisters were saved (see kFixedFrameSizeFromFp).
    lay(sp, MemOperand(sp, -(dregs.Count() * kDoubleSize)));
    bind(&simd_pushed);
  } else {
    if (CpuFeatures::SupportsWasmSimd128()) {
      MultiPushV128(dregs, scratch);
    } else {
      MultiPushDoubles(dregs);
      lay(sp, MemOperand(sp, -(dregs.Count() * kDoubleSize)));
    }
  }
#else
  MultiPushDoubles(dregs);
#endif
}

void MacroAssembler::MultiPopF64OrV128(DoubleRegList dregs, Register scratch,
                                       Register location) {
#if V8_ENABLE_WEBASSEMBLY
  bool generating_bultins =
      isolate() && isolate()->IsGeneratingEmbeddedBuiltins();
  if (generating_bultins) {
    Label pop_doubles, simd_popped;
    Move(r1, ExternalReference::supports_wasm_simd_128_address());
    LoadU8(r1, MemOperand(r1));
    LoadAndTestP(r1, r1);  // If > 0 then simd is available.
    ble(&pop_doubles, Label::kNear);
    // Pop vector registers, don't pop double registers anymore.
    MultiPopV128(dregs, scratch);
    b(&simd_popped);
    bind(&pop_doubles);
    // Simd not supported, only pop double registers.
    lay(sp, MemOperand(sp, dregs.Count() * kDoubleSize));
    MultiPopDoubles(dregs);
    bind(&simd_popped);
  } else {
    if (CpuFeatures::SupportsWasmSimd128()) {
      MultiPopV128(dregs, scratch);
    } else {
      lay(sp, MemOperand(sp, dregs.Count() * kDoubleSize));
      MultiPopDoubles(dregs);
    }
  }
#else
  MultiPopDoubles(dregs);
#endif
}

void MacroAssembler::PushAll(RegList registers) {
  if (registers.is_empty()) return;
  ASM_CODE_COMMENT(this);
  // TODO(victorgomes): {stm/ldm} pushes/pops registers in the opposite order
  // as expected by Maglev frame. Consider massaging Maglev to accept this
  // order instead.
  // Can not use MultiPush(registers, sp) due to orders
  for (Register reg : registers) {
    Push(reg);
  }
}

void MacroAssembler::PopAll(RegList registers) {
  if (registers.is_empty()) return;
  ASM_CODE_COMMENT(this);
  // Can not use MultiPop(registers, sp);
  for (Register reg : base::Reversed(registers)) {
    Pop(reg);
  }
}

void MacroAssembler::PushAll(DoubleRegList registers, int stack_slot_size) {
  if (registers.is_empty()) return;
  ASM_CODE_COMMENT(this);
  MultiPushDoubles(registers, sp);
}

void MacroAssembler::PopAll(DoubleRegList registers, int stack_slot_size) {
  if (registers.is_empty()) return;
  ASM_CODE_COMMENT(this);
  MultiPopDoubles(registers, sp);
}

void MacroAssembler::LoadTaggedRoot(Register destination, RootIndex index) {
  ASM_CODE_COMMENT(this);
  if (CanBeImmediate(index)) {
    mov(destination, Operand(ReadOnlyRootPtr(index), RelocInfo::Mode::NO_INFO));
    return;
  }
  LoadRoot(destination, index);
}

void MacroAssembler::LoadRoot(Register destination, RootIndex index,
                              Condition) {
  if (CanBeImmediate(index)) {
    DecompressTagged(destination, ReadOnlyRootPtr(index));
    return;
  }
  LoadU64(destination,
          MemOperand(kRootRegister, RootRegisterOffsetForRootIndex(index)), r0);
}

void MacroAssembler::LoadTaggedField(const Register& destination,
                                     const MemOperand& field_operand,
                                     const Register& scratch) {
  if (COMPRESS_POINTERS_BOOL) {
    DecompressTagged(destination, field_operand);
  } else {
    LoadU64(destination, field_operand, scratch);
  }
}
void MacroAssembler::LoadTaggedFieldWithoutDecompressing(
    const Register& destination, const MemOperand& field_operand,
    const Register& scratch) {
  if (COMPRESS_POINTERS_BOOL) {
    LoadU32(destination, field_operand, scratch);
  } else {
    LoadU64(destination, field_operand, scratch);
  }
}
void MacroAssembler::SmiUntag(Register dst, const MemOperand& src) {
  if (SmiValuesAre31Bits()) {
    LoadS32(dst, src);
  } else {
    LoadU64(dst, src);
  }
  SmiUntag(dst);
}

void MacroAssembler::SmiUntagField(Register dst, const MemOperand& src) {
  SmiUntag(dst, src);
}

void MacroAssembler::StoreTaggedField(const Register& value,
                                      const MemOperand& dst_field_operand,
                                      const Register& scratch) {
  if (COMPRESS_POINTERS_BOOL) {
    RecordComment("[ StoreTagged");
    StoreU32(value, dst_field_operand);
    RecordComment("]");
  } else {
    StoreU64(value, dst_field_operand, scratch);
  }
}

void MacroAssembler::DecompressTaggedSigned(Register destination,
                                            Register src) {
  RecordComment("[ DecompressTaggedSigned");
  llgfr(destination, src);
  RecordComment("]");
}

void MacroAssembler::DecompressTaggedSigned(Register destination,
                                            MemOperand field_operand) {
  RecordComment("[ DecompressTaggedSigned");
  llgf(destination, field_operand);
  RecordComment("]");
}

void MacroAssembler::DecompressTagged(Register destination, Register source) {
  RecordComment("[ DecompressTagged");
  llgfr(destination, source);
  agr(destination, kPtrComprCageBaseRegister);
  RecordComment("]");
}

void MacroAssembler::DecompressTagged(Register destination,
                                      MemOperand field_operand) {
  RecordComment("[ DecompressTagged");
  llgf(destination, field_operand);
  agr(destination, kPtrComprCageBaseRegister);
  RecordComment("]");
}

void MacroAssembler::DecompressTagged(const Register& destination,
                                      Tagged_t immediate) {
  ASM_CODE_COMMENT(this);
  mov(destination, Operand(immediate, RelocInfo::NO_INFO));
  agr(destination, kRootRegister);
}

void MacroAssembler::LoadTaggedSignedField(Register destination,
                                           MemOperand field_operand) {
  if (COMPRESS_POINTERS_BOOL) {
    DecompressTaggedSigned(destination, field_operand);
  } else {
    LoadU64(destination, field_operand);
  }
}

void MacroAssembler::RecordWriteField(Register object, int offset,
                                      Register value, Register slot_address,
                                      LinkRegisterStatus lr_status,
                                      SaveFPRegsMode save_fp,
                                      SmiCheck smi_check) {
  // First, check if a write barrier is even needed. The tests below
  // catch stores of Smis.
  Label done;

  // Skip barrier if writing a smi.
  if (smi_check == SmiCheck::kInline) {
    JumpIfSmi(value, &done);
  }

  // Although the object register is tagged, the offset is relative to the start
  // of the object, so so offset must be a multiple of kSystemPointerSize.
  DCHECK(IsAligned(offset, kTaggedSize));

  lay(slot_address, MemOperand(object, offset - kHeapObjectTag));
  if (v8_flags.debug_code) {
    Label ok;
    AndP(r0, slot_address, Operand(kTaggedSize - 1));
    beq(&ok, Label::kNear);
    stop();
    bind(&ok);
  }

  RecordWrite(object, slot_address, value, lr_status, save_fp, SmiCheck::kOmit);

  bind(&done);

  // Clobber clobbered input registers when running with the debug-code flag
  // turned on to provoke errors.
  if (v8_flags.debug_code) {
    mov(value, Operand(base::bit_cast<intptr_t>(kZapValue + 4)));
    mov(slot_address, Operand(base::bit_cast<intptr_t>(kZapValue + 8)));
  }
}

void MacroAssembler::MaybeSaveRegisters(RegList registers) {
  if (registers.is_empty()) return;
  MultiPush(registers);
}

void MacroAssembler::MaybeRestoreRegisters(RegList registers) {
  if (registers.is_empty()) return;
  MultiPop(registers);
}

void MacroAssembler::CallEphemeronKeyBarrier(Register object,
                                             Register slot_address,
                                             SaveFPRegsMode fp_mode) {
  DCHECK(!AreAliased(object, slot_address));
  RegList registers =
      WriteBarrierDescriptor::ComputeSavedRegisters(object, slot_address);
  MaybeSaveRegisters(registers);

  Register object_parameter = WriteBarrierDescriptor::ObjectRegister();
  Register slot_address_parameter =
      WriteBarrierDescriptor::SlotAddressRegister();

  Push(object);
  Push(slot_address);
  Pop(slot_address_parameter);
  Pop(object_parameter);

  CallBuiltin(Builtins::EphemeronKeyBarrier(fp_mode));
  MaybeRestoreRegisters(registers);
}

void MacroAssembler::CallRecordWriteStubSaveRegisters(Register object,
                                                      Register slot_address,
                                                      SaveFPRegsMode fp_mode,
                                                      StubCallMode mode) {
  DCHECK(!AreAliased(object, slot_address));
  RegList registers =
      WriteBarrierDescriptor::ComputeSavedRegisters(object, slot_address);
  MaybeSaveRegisters(registers);

  Register object_parameter = WriteBarrierDescriptor::ObjectRegister();
  Register slot_address_parameter =
      WriteBarrierDescriptor::SlotAddressRegister();

  Push(object);
  Push(slot_address);
  Pop(slot_address_parameter);
  Pop(object_parameter);

  CallRecordWriteStub(object_parameter, slot_address_parameter, fp_mode, mode);

  MaybeRestoreRegisters(registers);
}

void MacroAssembler::CallRecordWriteStub(Register object, Register slot_address,
                                         SaveFPRegsMode fp_mode,
                                         StubCallMode mode) {
  // Use CallRecordWriteStubSaveRegisters if the object and slot registers
  // need to be caller saved.
  DCHECK_EQ(WriteBarrierDescriptor::ObjectRegister(), object);
  DCHECK_EQ(WriteBarrierDescriptor::SlotAddressRegister(), slot_address);
#if V8_ENABLE_WEBASSEMBLY
  if (mode == StubCallMode::kCallWasmRuntimeStub) {
    auto wasm_target =
        static_cast<Address>(wasm::WasmCode::GetRecordWriteBuiltin(fp_mode));
    Call(wasm_target, RelocInfo::WASM_STUB_CALL);
#else
  if (false) {
#endif
  } else {
    CallBuiltin(Builtins::RecordWrite(fp_mode));
  }
}

// Will clobber 4 registers: object, address, scratch, ip.  The
// register 'object' contains a heap object pointer.  The heap object
// tag is shifted away.
void MacroAssembler::RecordWrite(Register object, Register slot_address,
                                 Register value, LinkRegisterStatus lr_status,
                                 SaveFPRegsMode fp_mode, SmiCheck smi_check) {
  DCHECK(!AreAliased(object, slot_address, value));
  if (v8_flags.debug_code) {
    LoadTaggedField(r0, MemOperand(slot_address));
    CmpS64(value, r0);
    Check(eq, AbortReason::kWrongAddressOrValuePassedToRecordWrite);
  }

  if (v8_flags.disable_write_barriers) {
    return;
  }
  // First, check if a write barrier is even needed. The tests below
  // catch stores of smis and stores into the young generation.
  Label done;

  if (smi_check == SmiCheck::kInline) {
    JumpIfSmi(value, &done);
  }

  CheckPageFlag(value,
                value,  // Used as scratch.
                MemoryChunk::kPointersToHereAreInterestingMask, eq, &done);
  CheckPageFlag(object,
                value,  // Used as scratch.
                MemoryChunk::kPointersFromHereAreInterestingMask, eq, &done);

  // Record the actual write.
  if (lr_status == kLRHasNotBeenSaved) {
    push(r14);
  }
  CallRecordWriteStubSaveRegisters(object, slot_address, fp_mode);
  if (lr_status == kLRHasNotBeenSaved) {
    pop(r14);
  }

  if (v8_flags.debug_code) mov(slot_address, Operand(kZapValue));

  bind(&done);

  // Clobber clobbered registers when running with the debug-code flag
  // turned on to provoke errors.
  if (v8_flags.debug_code) {
    mov(slot_address, Operand(base::bit_cast<intptr_t>(kZapValue + 12)));
    mov(value, Operand(base::bit_cast<intptr_t>(kZapValue + 16)));
  }
}

void MacroAssembler::PushCommonFrame(Register marker_reg) {
  ASM_CODE_COMMENT(this);
  int fp_delta = 0;
  if (marker_reg.is_valid()) {
    Push(r14, fp, marker_reg);
    fp_delta = 1;
  } else {
    Push(r14, fp);
    fp_delta = 0;
  }
  la(fp, MemOperand(sp, fp_delta * kSystemPointerSize));
}

void MacroAssembler::PopCommonFrame(Register marker_reg) {
  if (marker_reg.is_valid()) {
    Pop(r14, fp, marker_reg);
  } else {
    Pop(r14, fp);
  }
}

void MacroAssembler::PushStandardFrame(Register function_reg) {
  int fp_delta = 0;
  if (function_reg.is_valid()) {
    Push(r14, fp, cp, function_reg);
    fp_delta = 2;
  } else {
    Push(r14, fp, cp);
    fp_delta = 1;
  }
  la(fp, MemOperand(sp, fp_delta * kSystemPointerSize));
  Push(kJavaScriptCallArgCountRegister);
}

void MacroAssembler::RestoreFrameStateForTailCall() {
  // if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
  //   LoadU64(kConstantPoolRegister,
  //         MemOperand(fp, StandardFrameConstants::kConstantPoolOffset));
  //   set_constant_pool_available(false);
  // }
  DCHECK(!V8_EMBEDDED_CONSTANT_POOL_BOOL);
  LoadU64(r14, MemOperand(fp, StandardFrameConstants::kCallerPCOffset));
  LoadU64(fp, MemOperand(fp, StandardFrameConstants::kCallerFPOffset));
}

void MacroAssembler::CanonicalizeNaN(const DoubleRegister dst,
                                     const DoubleRegister src) {
  // Turn potential sNaN into qNaN
  if (dst != src) ldr(dst, src);
  lzdr(kDoubleRegZero);
  sdbr(dst, kDoubleRegZero);
}

void MacroAssembler::ConvertIntToDouble(DoubleRegister dst, Register src) {
  cdfbr(dst, src);
}

void MacroAssembler::ConvertUnsignedIntToDouble(DoubleRegister dst,
                                                Register src) {
  if (CpuFeatures::IsSupported(FLOATING_POINT_EXT)) {
    cdlfbr(Condition(5), Condition(0), dst, src);
  } else {
    // zero-extend src
    llgfr(src, src);
    // convert to double
    cdgbr(dst, src);
  }
}

void MacroAssembler::ConvertIntToFloat(DoubleRegister dst, Register src) {
  cefbra(Condition(4), dst, src);
}

void MacroAssembler::ConvertUnsignedIntToFloat(DoubleRegister dst,
                                               Register src) {
  celfbr(Condition(4), Condition(0), dst, src);
}

void MacroAssembler::ConvertInt64ToFloat(DoubleRegister double_dst,
                                         Register src) {
  cegbr(double_dst, src);
}

void MacroAssembler::ConvertInt64ToDouble(DoubleRegister double_dst,
                                          Register src) {
  cdgbr(double_dst, src);
}

void MacroAssembler::ConvertUnsignedInt64ToFloat(DoubleRegister double_dst,
                                                 Register src) {
  celgbr(Condition(0), Condition(0), double_dst, src);
}

void MacroAssembler::ConvertUnsignedInt64ToDouble(DoubleRegister double_dst,
                                                  Register src) {
  cdlgbr(Condition(0), Condition(0), double_dst, src);
}

void MacroAssembler::ConvertFloat32ToInt64(const Register dst,
                                           const DoubleRegister double_input,
                                           FPRoundingMode rounding_mode) {
  Condition m = Condition(0);
  switch (rounding_mode) {
    case kRoundToZero:
      m = Condition(5);
      break;
    case kRoundToNearest:
      UNIMPLEMENTED();
    case kRoundToPlusInf:
      m = Condition(6);
      break;
    case kRoundToMinusInf:
      m = Condition(7);
      break;
    default:
      UNIMPLEMENTED();
  }
  cgebr(m, dst, double_input);
}

void MacroAssembler::ConvertDoubleToInt64(const Register dst,
                                          const DoubleRegister double_input,
                                          FPRoundingMode rounding_mode) {
  Condition m = Condition(0);
  switch (rounding_mode) {
    case kRoundToZero:
      m = Condition(5);
      break;
    case kRoundToNearest:
      UNIMPLEMENTED();
    case kRoundToPlusInf:
      m = Condition(6);
      break;
    case kRoundToMinusInf:
      m = Condition(7);
      break;
    default:
      UNIMPLEMENTED();
  }
  cgdbr(m, dst, double_input);
}

void MacroAssembler::ConvertDoubleToInt32(const Register dst,
                                          const DoubleRegister double_input,
                                          FPRoundingMode rounding_mode) {
  Condition m = Condition(0);
  switch (rounding_mode) {
    case kRoundToZero:
      m = Condition(5);
      break;
    case kRoundToNearest:
      m = Condition(4);
      break;
    case kRoundToPlusInf:
      m = Condition(6);
      break;
    case kRoundToMinusInf:
      m = Condition(7);
      break;
    default:
      UNIMPLEMENTED();
  }
  lghi(dst, Operand::Zero());
  cfdbr(m, dst, double_input);
}

void MacroAssembler::ConvertFloat32ToInt32(const Register result,
                                           const DoubleRegister double_input,
                                           FPRoundingMode rounding_mode) {
  Condition m = Condition(0);
  switch (rounding_mode) {
    case kRoundToZero:
      m = Condition(5);
      break;
    case kRoundToNearest:
      m = Condition(4);
      break;
    case kRoundToPlusInf:
      m = Condition(6);
      break;
    case kRoundToMinusInf:
      m = Condition(7);
      break;
    default:
      UNIMPLEMENTED();
  }
  lghi(result, Operand::Zero());
  cfebr(m, result, double_input);
}

void MacroAssembler::ConvertFloat32ToUnsignedInt32(
    const Register result, const DoubleRegister double_input,
    FPRoundingMode rounding_mode) {
  Condition m = Condition(0);
  switch (rounding_mode) {
    case kRoundToZero:
      m = Condition(5);
      break;
    case kRoundToNearest:
      UNIMPLEMENTED();
    case kRoundToPlusInf:
      m = Condition(6);
      break;
    case kRoundToMinusInf:
      m = Condition(7);
      break;
    default:
      UNIMPLEMENTED();
  }
  lghi(result, Operand::Zero());
  clfebr(m, Condition(0), result, double_input);
}

void MacroAssembler::ConvertFloat32ToUnsignedInt64(
    const Register result, const DoubleRegister double_input,
    FPRoundingMode rounding_mode) {
  Condition m = Condition(0);
  switch (rounding_mode) {
    case kRoundToZero:
      m = Condition(5);
      break;
    case kRoundToNearest:
      UNIMPLEMENTED();
    case kRoundToPlusInf:
      m = Condition(6);
      break;
    case kRoundToMinusInf:
      m = Condition(7);
      break;
    default:
      UNIMPLEMENTED();
  }
  clgebr(m, Condition(0), result, double_input);
}

void MacroAssembler::ConvertDoubleToUnsignedInt64(
    const Register dst, const DoubleRegister double_input,
    FPRoundingMode rounding_mode) {
  Condition m = Condition(0);
  switch (rounding_mode) {
    case kRoundToZero:
      m = Condition(5);
      break;
    case kRoundToNearest:
      UNIMPLEMENTED();
    case kRoundToPlusInf:
      m = Condition(6);
      break;
    case kRoundToMinusInf:
      m = Condition(7);
      break;
    default:
      UNIMPLEMENTED();
  }
  clgdbr(m, Condition(0), dst, double_input);
}

void MacroAssembler::ConvertDoubleToUnsignedInt32(
    const Register dst, const DoubleRegister double_input,
    FPRoundingMode rounding_mode) {
  Condition m = Condition(0);
  switch (rounding_mode) {
    case kRoundToZero:
      m = Condition(5);
      break;
    case kRoundToNearest:
      UNIMPLEMENTED();
    case kRoundToPlusInf:
      m = Condition(6);
      break;
    case kRoundToMinusInf:
      m = Condition(7);
      break;
    default:
      UNIMPLEMENTED();
  }
  lghi(dst, Operand::Zero());
  clfdbr(m, Condition(0), dst, double_input);
}

void MacroAssembler::MovDoubleToInt64(Register dst, DoubleRegister src) {
  lgdr(dst, src);
}

void MacroAssembler::MovInt64ToDouble(DoubleRegister dst, Register src) {
  ldgr(dst, src);
}

void MacroAssembler::StubPrologue(StackFrame::Type type, Register base,
                                  int prologue_offset) {
  {
    ConstantPoolUnavailableScope constant_pool_unavailable(this);
    mov(r1, Operand(StackFrame::TypeToMarker(type)));
    PushCommonFrame(r1);
  }
}

void MacroAssembler::Prologue(Register base, int prologue_offset) {
  DCHECK(base != no_reg);
  PushStandardFrame(r3);
}

void MacroAssembler::DropArguments(Register count) {
  ShiftLeftU64(ip, count, Operand(kSystemPointerSizeLog2));
  lay(sp, MemOperand(sp, ip));
}

void MacroAssembler::DropArgumentsAndPushNewReceiver(Register argc,
                                                     Register receiver) {
  DCHECK(!AreAliased(argc, receiver));
  DropArguments(argc);
  push(receiver);
}

void MacroAssembler::EnterFrame(StackFrame::Type type,
                                bool load_constant_pool_pointer_reg) {
  ASM_CODE_COMMENT(this);
  // We create a stack frame with:
  //    Return Addr <-- old sp
  //    Old FP      <-- new fp
  //    CP
  //    type
  //    CodeObject  <-- new sp

  Register scratch = no_reg;
  if (!StackFrame::IsJavaScript(type)) {
    scratch = ip;
    mov(scratch, Operand(StackFrame::TypeToMarker(type)));
  }
  PushCommonFrame(scratch);
#if V8_ENABLE_WEBASSEMBLY
  if (type == StackFrame::WASM) Push(kWasmImplicitArgRegister);
#endif  // V8_ENABLE_WEBASSEMBLY
}

int MacroAssembler::LeaveFrame(StackFrame::Type type, int stack_adjustment) {
  ASM_CODE_COMMENT(this);
  // Drop the execution stack down to the frame pointer and restore
  // the caller frame pointer, return address and constant pool pointer.
  LoadU64(r14, MemOperand(fp, StandardFrameConstants::kCallerPCOffset));
  if (is_int20(StandardFrameConstants::kCallerSPOffset + stack_adjustment)) {
    lay(r1, MemOperand(fp, StandardFrameConstants::kCallerSPOffset +
                               stack_adjustment));
  } else {
    AddS64(r1, fp,
           Operand(StandardFrameConstants::kCallerSPOffset + stack_adjustment));
  }
  LoadU64(fp, MemOperand(fp, StandardFrameConstants::kCallerFPOffset));
  mov(sp, r1);
  int frame_ends = pc_offset();
  return frame_ends;
}

// ExitFrame layout (probably wrongish.. needs updating)
//
//  SP -> previousSP
//        LK reserved
//        sp_on_exit (for debug?)
// oldSP->prev SP
//        LK
//        <parameters on stack>

// Prior to calling EnterExitFrame, we've got a bunch of parameters
// on the stack that we need to wrap a real frame around.. so first
// we reserve a slot for LK and push the previous SP which is captured
// in the fp register (r11)
// Then - we buy a new frame

// r14
// oldFP <- newFP
// SP
// Floats
// gaps
// Args
// ABIRes <- newSP
void MacroAssembler::EnterExitFrame(Register scratch, int stack_space,
                                    StackFrame::Type frame_type) {
  DCHECK(frame_type == StackFrame::EXIT ||
         frame_type == StackFrame::BUILTIN_EXIT ||
         frame_type == StackFrame::API_ACCESSOR_EXIT ||
         frame_type == StackFrame::API_CALLBACK_EXIT);

  // Set up the frame structure on the stack.
  DCHECK_EQ(2 * kSystemPointerSize, ExitFrameConstants::kCallerSPDisplacement);
  DCHECK_EQ(1 * kSystemPointerSize, ExitFrameConstants::kCallerPCOffset);
  DCHECK_EQ(0 * kSystemPointerSize, ExitFrameConstants::kCallerFPOffset);

  using ER = ExternalReference;

  // This is an opportunity to build a frame to wrap
  // all of the pushes that have happened inside of V8
  // since we were called from C code
  mov(r1, Operand(StackFrame::TypeToMarker(frame_type)));
  PushCommonFrame(r1);
  // Reserve room for saved entry sp.
  lay(sp, MemOperand(fp, -ExitFrameConstants::kFixedFrameSizeFromFp));

  if (v8_flags.debug_code) {
    StoreU64(MemOperand(fp, ExitFrameConstants::kSPOffset), Operand::Zero(),
             r1);
  }

  // Save the frame pointer and the context in top.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, isolate());
  StoreU64(fp, ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  ER context_address = ER::Create(IsolateAddressId::kContextAddress, isolate());
  StoreU64(cp, ExternalReferenceAsOperand(context_address, no_reg));

  lay(sp, MemOperand(sp, -(stack_space + 1) * kSystemPointerSize));

  // Allocate and align the frame preparing for calling the runtime
  // function.
  const int frame_alignment = MacroAssembler::ActivationFrameAlignment();
  if (frame_alignment > 0) {
    DCHECK_EQ(frame_alignment, 8);
    ClearRightImm(sp, sp, Operand(3));  // equivalent to &= -8
  }

  lay(sp, MemOperand(sp, -kNumRequiredStackFrameSlots * kSystemPointerSize));
  StoreU64(MemOperand(sp), Operand::Zero(), r0);
  // Set the exit frame sp value to point just before the return address
  // location.
  lay(r1, MemOperand(sp, kStackFrameSPSlot * kSystemPointerSize));
  StoreU64(r1, MemOperand(fp, ExitFrameConstants::kSPOffset));
}

int MacroAssembler::ActivationFrameAlignment() {
#if !defined(USE_SIMULATOR)
  // Running on the real platform. Use the alignment as mandated by the local
  // environment.
  // Note: This will break if we ever start generating snapshots on one S390
  // platform for another S390 platform with a different alignment.
  return base::OS::ActivationFrameAlignment();
#else  // Simulated
  // If we are using the simulator then we should always align to the expected
  // alignment. As the simulator is used to generate snapshots we do not know
  // if the target platform will need alignment, so this is controlled from a
  // flag.
  return v8_flags.sim_stack_alignment;
#endif
}

void MacroAssembler::LeaveExitFrame(Register scratch) {
  using ER = ExternalReference;

  // Restore current context from top and clear it in debug mode.
  ER context_address = ER::Create(IsolateAddressId::kContextAddress, isolate());
  LoadU64(cp, ExternalReferenceAsOperand(context_address, no_reg));

#ifdef DEBUG
  mov(scratch, Operand(Context::kInvalidContext));
  StoreU64(scratch, ExternalReferenceAsOperand(context_address, no_reg));
#endif

  // Clear the top frame.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, isolate());
  mov(scratch, Operand::Zero());
  StoreU64(scratch, ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  // Tear down the exit frame, pop the arguments, and return.
  LeaveFrame(StackFrame::EXIT);
}

void MacroAssembler::MovFromFloatResult(const DoubleRegister dst) {
  Move(dst, d0);
}

void MacroAssembler::MovFromFloatParameter(const DoubleRegister dst) {
  Move(dst, d0);
}

MemOperand MacroAssembler::StackLimitAsMemOperand(StackLimitKind kind) {
  DCHECK(root_array_available());
  Isolate* isolate = this->isolate();
  ExternalReference limit =
      kind == StackLimitKind::kRealStackLimit
          ? ExternalReference::address_of_real_jslimit(isolate)
          : ExternalReference::address_of_jslimit(isolate);
  DCHECK(MacroAssembler::IsAddressableThroughRootRegister(isolate, limit));

  intptr_t offset =
      MacroAssembler::RootRegisterOffsetForExternalReference(isolate, limit);
  CHECK(is_int32(offset));
  return MemOperand(kRootRegister, offset);
}

void MacroAssembler::StackOverflowCheck(Register num_args, Register scratch,
                                        Label* stack_overflow) {
  // Check the stack for overflow. We are not trying to catch
  // interruptions (e.g. debug break and preemption) here, so the "real stack
  // limit" is checked.
  LoadU64(scratch, StackLimitAsMemOperand(StackLimitKind::kRealStackLimit));
  // Make scratch the space we have left. The stack might already be overflowed
  // here which will cause scratch to become negative.
  SubS64(scratch, sp, scratch);
  // Check if the arguments will overflow the stack.
  ShiftLeftU64(r0, num_args, Operand(kSystemPointerSizeLog2));
  CmpS64(scratch, r0);
  ble(stack_overflow);  // Signed comparison.
}

void MacroAssembler::InvokePrologue(Register expected_parameter_count,
                                    Register actual_parameter_count,
                                    Label* done, InvokeType type) {
  Label regular_invoke;

  //  r2: actual arguments count
  //  r3: function (passed through to callee)
  //  r4: expected arguments count

  DCHECK_EQ(actual_parameter_count, r2);
  DCHECK_EQ(expected_parameter_count, r4);

  // If overapplication or if the actual argument count is equal to the
  // formal parameter count, no need to push extra undefined values.
  SubS64(expected_parameter_count, expected_parameter_count,
         actual_parameter_count);
  ble(&regular_invoke);

  Label stack_overflow;
  Register scratch = r6;
  StackOverflowCheck(expected_parameter_count, scratch, &stack_overflow);

  // Underapplication. Move the arguments already in the stack, including the
  // receiver and the return address.
  {
    Label copy, check;
    Register num = r7, src = r8, dest = ip;  // r7 and r8 are context and root.
    mov(src, sp);
    // Update stack pointer.
    ShiftLeftU64(scratch, expected_parameter_count,
                 Operand(kSystemPointerSizeLog2));
    SubS64(sp, sp, scratch);
    mov(dest, sp);
    ltgr(num, actual_parameter_count);
    b(&check);
    bind(&copy);
    LoadU64(r0, MemOperand(src));
    lay(src, MemOperand(src, kSystemPointerSize));
    StoreU64(r0, MemOperand(dest));
    lay(dest, MemOperand(dest, kSystemPointerSize));
    SubS64(num, num, Operand(1));
    bind(&check);
    b(gt, &copy);
  }

  // Fill remaining expected arguments with undefined values.
  LoadRoot(scratch, RootIndex::kUndefinedValue);
  {
    Label loop;
    bind(&loop);
    StoreU64(scratch, MemOperand(ip));
    lay(ip, MemOperand(ip, kSystemPointerSize));
    SubS64(expected_parameter_count, expected_parameter_count, Operand(1));
    bgt(&loop);
  }
  b(&regular_invoke);

  bind(&stack_overflow);
  {
    FrameScope frame(
        this, has_frame() ? StackFrame::NO_FRAME_TYPE : StackFrame::INTERNAL);
    CallRuntime(Runtime::kThrowStackOverflow);
    bkpt(0);
  }

  bind(&regular_invoke);
}

void MacroAssembler::CheckDebugHook(Register fun, Register new_target,
                                    Register expected_parameter_count,
                                    Register actual_parameter_count) {
  Label skip_hook;

  ExternalReference debug_hook_active =
      ExternalReference::debug_hook_on_function_call_address(isolate());
  Move(r6, debug_hook_active);
  tm(MemOperand(r6), Operand(0xFF));
  beq(&skip_hook);

  {
    // Load receiver to pass it later to DebugOnFunctionCall hook.
    LoadReceiver(r6);
    FrameScope frame(
        this, has_frame() ? StackFrame::NO_FRAME_TYPE : StackFrame::INTERNAL);

    SmiTag(expected_parameter_count);
    Push(expected_parameter_count);

    SmiTag(actual_parameter_count);
    Push(actual_parameter_count);

    if (new_target.is_valid()) {
      Push(new_target);
    }
    Push(fun, fun, r6);
    CallRuntime(Runtime::kDebugOnFunctionCall);
    Pop(fun);
    if (new_target.is_valid()) {
      Pop(new_target);
    }

    Pop(actual_parameter_count);
    SmiUntag(actual_parameter_count);

    Pop(expected_parameter_count);
    SmiUntag(expected_parameter_count);
  }
  bind(&skip_hook);
}

void MacroAssembler::InvokeFunctionCode(Register function, Register new_target,
                                        Register expected_parameter_count,
                                        Register actual_parameter_count,
                                        InvokeType type) {
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());
  DCHECK_EQ(function, r3);
  DCHECK_IMPLIES(new_target.is_valid(), new_target == r5);

  // On function call, call into the debugger if necessary.
  CheckDebugHook(function, new_target, expected_parameter_count,
                 actual_parameter_count);

  // Clear the new.target register if not given.
  if (!new_target.is_valid()) {
    LoadRoot(r5, RootIndex::kUndefinedValue);
  }

  Label done;
  InvokePrologue(expected_parameter_count, actual_parameter_count, &done, type);
  // We call indirectly through the code field in the function to
  // allow recompilation to take effect without changing any of the
  // call sites.
  constexpr int unused_argument_count = 0;
  switch (type) {
    case InvokeType::kCall:
      CallJSFunction(function, unused_argument_count);
      break;
    case InvokeType::kJump:
      JumpJSFunction(function);
      break;
  }
  // Continue here if InvokePrologue does handle the invocation due to
  // mismatched parameter counts.
  bind(&done);
}

void MacroAssembler::InvokeFunctionWithNewTarget(
    Register fun, Register new_target, Register actual_parameter_count,
    InvokeType type) {
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());

  // Contract with called JS functions requires that function is passed in r3.
  DCHECK_EQ(fun, r3);

  Register expected_reg = r4;
  Register temp_reg = r6;
  LoadTaggedField(cp, FieldMemOperand(fun, JSFunction::kContextOffset));
  LoadTaggedField(temp_reg,
                  FieldMemOperand(fun, JSFunction::kSharedFunctionInfoOffset));
  LoadU16(expected_reg,
          FieldMemOperand(temp_reg,
                          SharedFunctionInfo::kFormalParameterCountOffset));

  InvokeFunctionCode(fun, new_target, expected_reg, actual_parameter_count,
                     type);
}

void MacroAssembler::InvokeFunction(Register function,
                                    Register expected_parameter_count,
                                    Register actual_parameter_count,
                                    InvokeType type) {
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());

  // Contract with called JS functions requires that function is passed in r3.
  DCHECK_EQ(function, r3);

  // Get the function and setup the context.
  LoadTaggedField(cp, FieldMemOperand(function, JSFunction::kContextOffset));

  InvokeFunctionCode(r3, no_reg, expected_parameter_count,
                     actual_parameter_count, type);
}

void MacroAssembler::PushStackHandler() {
  // Adjust this code if not the case.
  static_assert(StackHandlerConstants::kSize == 2 * kSystemPointerSize);
  static_assert(StackHandlerConstants::kNextOffset == 0 * kSystemPointerSize);

  // Link the current handler as the next handler.
  Move(r7,
       ExternalReference::Create(IsolateAddressId::kHandlerAddress, isolate()));

  // Buy the full stack frame for 5 slots.
  lay(sp, MemOperand(sp, -StackHandlerConstants::kSize));

  // Store padding.
  lghi(r0, Operand::Zero());
  StoreU64(r0, MemOperand(sp));  // Padding.

  // Copy the old handler into the next handler slot.
  MoveChar(MemOperand(sp, StackHandlerConstants::kNextOffset), MemOperand(r7),
           Operand(kSystemPointerSize));
  // Set this new handler as the current one.
  StoreU64(sp, MemOperand(r7));
}

void MacroAssembler::PopStackHandler() {
  static_assert(StackHandlerConstants::kSize == 2 * kSystemPointerSize);
  static_assert(StackHandlerConstants::kNextOffset == 0);

  // Pop the Next Handler into r3 and store it into Handler Address reference.
  Pop(r3);
  Move(ip,
       ExternalReference::Create(IsolateAddressId::kHandlerAddress, isolate()));
  StoreU64(r3, MemOperand(ip));

  Drop(1);  // Drop padding.
}

void MacroAssembler::IsObjectType(Register object, Register scratch1,
                                  Register scratch2, InstanceType type) {
  ASM_CODE_COMMENT(this);
  CompareObjectType(object, scratch1, scratch2, type);
}

void MacroAssembler::CompareObjectTypeRange(Register object, Register map,
                                            Register type_reg, Register scratch,
                                            InstanceType lower_limit,
                                            InstanceType upper_limit) {
  ASM_CODE_COMMENT(this);
  LoadMap(map, object);
  CompareInstanceTypeRange(map, type_reg, scratch, lower_limit, upper_limit);
}

void MacroAssembler::CompareRange(Register value, Register scratch,
                                  unsigned lower_limit, unsigned higher_limit) {
  ASM_CODE_COMMENT(this);
  DCHECK_LT(lower_limit, higher_limit);
  if (lower_limit != 0) {
    mov(scratch, value);
    slgfi(scratch, Operand(lower_limit));
    CmpU64(scratch, Operand(higher_limit - lower_limit));
  } else {
    CmpU64(value, Operand(higher_limit));
  }
}

void MacroAssembler::CompareInstanceTypeRange(Register map, Register type_reg,
                                              Register scratch,
                                              InstanceType lower_limit,
                                              InstanceType higher_limit) {
  DCHECK_LT(lower_limit, higher_limit);
  LoadU16(type_reg, FieldMemOperand(map, Map::kInstanceTypeOffset));
  CompareRange(type_reg, scratch, lower_limit, higher_limit);
}

void MacroAssembler::CompareRoot(Register obj, RootIndex index) {
  if (!base::IsInRange(index, RootIndex::kFirstStrongOrReadOnlyRoot,
                       RootIndex::kLastStrongOrReadOnlyRoot)) {
    // Some smi roots contain system pointer size values like stack limits.
    LoadRoot(r0, index);
    CmpU64(obj, r0);
    return;
  }
  return CompareTaggedRoot(obj, index);
}

void MacroAssembler::CompareTaggedRoot(Register obj, RootIndex index) {
  if (CanBeImmediate(index)) {
    CompareTagged(obj, Operand(ReadOnlyRootPtr(index)));
    return;
  }
  int32_t offset = RootRegisterOffsetForRootIndex(index);
#ifdef V8_TARGET_BIG_ENDIAN
  offset += (COMPRESS_POINTERS_BOOL ? kTaggedSize : 0);
#endif
  CompareTagged(obj, MemOperand(kRootRegister, offset));
}

void MacroAssembler::JumpIfIsInRange(Register value, Register scratch,
                                     unsigned lower_limit,
                                     unsigned higher_limit,
                                     Label* on_in_range) {
  CompareRange(value, scratch, lower_limit, higher_limit);
  ble(on_in_range);
}

void MacroAssembler::TruncateDoubleToI(Isolate* isolate, Zone* zone,
                                       Register result,
                                       DoubleRegister double_input,
                                       StubCallMode stub_mode) {
  Label done;

  TryInlineTruncateDoubleToI(result, double_input, &done);

  // If we fell through then inline version didn't succeed - call stub instead.
  push(r14);
  // Put input on stack.
  lay(sp, MemOperand(sp, -kDoubleSize));
  StoreF64(double_input, MemOperand(sp));

#if V8_ENABLE_WEBASSEMBLY
  if (stub_mode == StubCallMode::kCallWasmRuntimeStub) {
    Call(static_cast<Address>(Builtin::kDoubleToI), RelocInfo::WASM_STUB_CALL);
#else
  // For balance.
  if (false) {
#endif  // V8_ENABLE_WEBASSEMBLY
  } else {
    CallBuiltin(Builtin::kDoubleToI);
  }

  LoadU64(result, MemOperand(sp, 0));
  la(sp, MemOperand(sp, kDoubleSize));
  pop(r14);

  bind(&done);
}

void MacroAssembler::TryInlineTruncateDoubleToI(Register result,
                                                DoubleRegister double_input,
                                                Label* done) {
  ConvertDoubleToInt64(result, double_input);

  // Test for overflow
  TestIfInt32(result
"""


```