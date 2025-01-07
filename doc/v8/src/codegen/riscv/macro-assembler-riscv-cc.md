Response:
The user wants to understand the functionality of the `macro-assembler-riscv.cc` file in the V8 JavaScript engine. I need to:

1. **Identify the main purpose:** Based on the name and content (like `Push`, `Pop`, `CallRuntime`), this file seems to provide low-level assembly instruction generation for the RISC-V architecture. It's a "macro assembler," meaning it offers higher-level abstractions over raw assembly.

2. **List Key Functionalities:**  Scan the code for major functionalities. I see things like:
    * Stack manipulation (`PushCallerSaved`, `PopCallerSaved`)
    * Function calls (including optimized code paths)
    * Feedback vector handling for optimization
    * Root table access
    * Frame setup (`PushCommonFrame`, `PushStandardFrame`)
    * Write barrier implementation for garbage collection
    * Handling of sandboxed pointers (if enabled)
    * Basic arithmetic operations (with optimizations for immediate values)

3. **Check for Torque:** The filename doesn't end in `.tq`, so it's not a Torque file.

4. **Relate to JavaScript:**  This code is crucial for the performance of JavaScript. It's part of the compilation and execution pipeline. When V8 compiles JavaScript code, it uses the macro assembler to generate the actual machine instructions for the target architecture (RISC-V in this case).

5. **Provide JavaScript examples (if related):** Since this is about *how* JavaScript runs on RISC-V, an example would show a JavaScript construct and how the macro assembler helps implement it. A function call is a good example.

6. **Consider code logic and examples:**  While the code itself is low-level, some sections like the optimized code path selection have logic. I can create hypothetical scenarios.

7. **Think about common programming errors:** Since this deals with memory management and low-level operations, errors could involve incorrect stack usage or issues with the write barrier.

8. **Summarize the functionality:** Concisely describe the role of the file.

**Plan:**

* State the file's primary purpose.
* List the core functionalities observed in the provided snippet.
* Explicitly state it's not a Torque file.
* Explain the connection to JavaScript compilation and execution.
* Provide a JavaScript example illustrating a function call and the role of the macro assembler.
* Create a hypothetical scenario for the optimized code path.
* Give an example of a common programming error related to stack usage.
* Provide a concise summary.
这是 V8 引擎中用于 RISC-V 架构的宏汇编器源代码文件 (`macro-assembler-riscv.cc`) 的一部分。它的主要功能是提供一组高级的接口（称为“宏”）来生成 RISC-V 汇编指令。这使得 V8 编译器能够更容易、更清晰地生成针对 RISC-V 处理器的优化代码。

以下是根据提供的代码片段列举的功能：

1. **调用者保存寄存器管理:**
   - `RequiredStackSizeForCallerSaved`: 计算调用者需要保存的寄存器所需的栈空间大小。
   - `PushCallerSaved`: 将调用者保存的寄存器压入栈中。
   - `PopCallerSaved`: 从栈中弹出调用者保存的寄存器。

2. **尾调用优化支持 (Leaptiering 未启用时):**
   - `TailCallOptimizedCodeSlot`:  当存在优化后的代码时，执行尾调用的逻辑。这包括检查优化代码是否有效、是否需要反优化等。

3. **断言和调试支持:**
   - `AssertFeedbackCell`, `AssertFeedbackVector`: 在调试模式下，断言某个寄存器包含预期的反馈单元或反馈向量。
   - `AssertUnreachable`: 在调试模式下，标记代码为不可达。

4. **用优化代码替换闭包代码:**
   - `ReplaceClosureCodeWithOptimizedCode`: 将闭包对象中的代码指针替换为指向优化后代码的指针。

5. **生成返回已返回代码的尾调用:**
   - `GenerateTailCallToReturnedCode`: 生成一个尾调用，跳转到运行时函数返回的代码。

6. **反馈向量标志处理:**
   - `LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing`: 加载反馈向量的标志位，并检查是否需要进一步处理（例如，进行优化或记录执行）。
   - `LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing`: 加载反馈向量的标志位，如果需要处理则跳转到指定标签。
   - `OptimizeCodeOrTailCallOptimizedCodeSlot`:  根据反馈向量的标志位，决定是编译优化代码还是尾调用优化代码槽。

7. **加载 Isolate 字段和 Root 表:**
   - `LoadIsolateField`: 加载 Isolate 对象的指定字段。
   - `LoadRoot`, `LoadTaggedRoot`, `LoadCompressedTaggedRoot`: 从 Root 表加载根对象。

8. **帧操作:**
   - `PushCommonFrame`: 推入通用帧。
   - `PushStandardFrame`: 推入标准帧。

9. **Safepoint 寄存器栈索引:**
   - `SafepointRegisterStackIndex`: 获取 Safepoint 中寄存器的栈索引。

10. **记录写入屏障:**
    - `RecordWriteField`: 记录堆对象字段的写入操作，并处理写屏障，以维护垃圾回收器的正确性。
    - `RecordWrite`:  实际执行记录写入屏障的逻辑。
    - `CallEphemeronKeyBarrier`, `CallIndirectPointerBarrier`, `CallRecordWriteStubSaveRegisters`, `CallRecordWriteStub`: 调用不同类型的写入屏障。
    - `MoveObjectAndSlot`: 移动对象和槽地址到指定的寄存器。

11. **受信任指针和外部指针处理 (可能与沙箱环境有关):**
    - `LoadTrustedPointerField`, `StoreTrustedPointerField`: 加载和存储受信任的指针字段。
    - `ResolveIndirectPointerHandle`, `ResolveTrustedPointerHandle`, `ResolveCodePointerHandle`: 解析间接指针句柄。
    - `LoadCodeEntrypointViaCodePointer`: 通过代码指针加载代码入口点。
    - `LoadExternalPointerField`: 加载外部指针字段。

12. **寄存器保存和恢复:**
    - `MaybeSaveRegisters`: 如果寄存器列表不为空，则保存寄存器。
    - `MaybeRestoreRegisters`: 如果寄存器列表不为空，则恢复寄存器。

13. **沙箱指针处理 (V8_TARGET_ARCH_RISCV64 且 V8_ENABLE_SANDBOX 时):**
    - `DecodeSandboxedPointer`: 解码沙箱指针。
    - `LoadSandboxedPointerField`, `StoreSandboxedPointerField`: 加载和存储沙箱指针字段。

14. **32 位算术运算 (V8_TARGET_ARCH_RISCV64 时):**
    - `Add32`, `Sub32`: 执行 32 位加法和减法运算，并考虑指令压缩优化。

**关于 .tq 结尾:**

根据您的描述，如果 `v8/src/codegen/riscv/macro-assembler-riscv.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。Torque 是一种 V8 内部使用的领域特定语言，用于生成高效的 C++ 代码，通常用于实现内置函数和运行时功能。**但根据您提供的信息，该文件名为 `.cc`，因此它是一个 C++ 源代码文件，而不是 Torque 文件。**

**与 Javascript 的关系 (举例说明):**

`macro-assembler-riscv.cc` 的功能直接关系到 JavaScript 的执行。当 V8 编译 JavaScript 代码时，它会使用宏汇编器生成底层的 RISC-V 汇编指令，这些指令最终由 CPU 执行。

例如，考虑以下简单的 JavaScript 函数调用：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

当 V8 编译 `add` 函数时，`macro-assembler-riscv.cc` 中的宏会被用来生成类似以下的汇编代码片段（简化示例）：

* **函数入口:** 设置栈帧 (`PushStandardFrame`)。
* **参数传递:**  将参数 `a` 和 `b` 从寄存器或栈中加载到指定的寄存器。
* **加法运算:** 使用 RISC-V 的加法指令 (`addw`) 进行运算。这可能会用到 `MacroAssembler::Add32` 宏。
* **返回值处理:** 将结果存储到返回值寄存器。
* **函数出口:** 恢复栈帧 (`Pop`)，跳转回调用者 (`ret`).
* **调用 `add`:**  在调用 `add(5, 10)` 时，会使用宏来设置参数，执行 `call` 指令跳转到 `add` 函数的入口点。

**代码逻辑推理 (假设输入与输出):**

考虑 `PushCallerSaved` 函数。

**假设输入:**
- `fp_mode = SaveFPRegsMode::kSave` (需要保存浮点寄存器)
- `exclusion1 = t0`, `exclusion2 = no_reg`, `exclusion3 = no_reg` (排除 `t0` 寄存器)

**逻辑:**
1. `kJSCallerSaved` 包含一组通用的调用者保存寄存器。
2. 排除 `t0` 后，`list` 将包含 `kJSCallerSaved` 中除 `t0` 外的所有寄存器。
3. `MultiPush(list)` 会生成指令将 `list` 中的通用寄存器压入栈。
4. 由于 `fp_mode` 为 `kSave`，`MultiPushFPU(kCallerSavedFPU)` 会生成指令将浮点调用者保存寄存器压入栈。

**预期输出:**
生成的汇编代码会将 `kJSCallerSaved` 中除 `t0` 外的所有通用寄存器以及 `kCallerSavedFPU` 中的所有浮点寄存器压入栈。返回值为压入栈的总字节数。

**用户常见的编程错误 (举例说明):**

一个与 `macro-assembler-riscv.cc` 相关的用户常见编程错误可能发生在内联汇编或使用 V8 提供的低级 API 时，例如 **不正确地管理栈指针**。

**示例:**

假设用户尝试手动分配栈空间，但忘记在函数返回前恢复栈指针：

```c++
void MyFunction(MacroAssembler& masm) {
  // 错误示例：忘记恢复栈指针
  int stack_space = 16;
  masm.AddWord(sp, sp, Operand(-stack_space)); // 分配栈空间

  // ... 执行一些操作 ...

  // 忘记执行 masm.AddWord(sp, sp, Operand(stack_space));
  // 或者 masm.Pop(某些寄存器);
  masm.Ret();
}
```

**后果:** 当 `MyFunction` 返回时，栈指针指向错误的位置。这可能导致后续的函数调用覆盖不应该覆盖的内存，或者在返回时从错误的地址读取数据，最终导致程序崩溃或产生不可预测的行为。V8 的宏汇编器在内部管理栈，但如果用户尝试进行手动栈操作，就可能引入这类错误。

**功能归纳:**

`v8/src/codegen/riscv/macro-assembler-riscv.cc` 的主要功能是作为一个 RISC-V 架构的宏汇编器，提供了一组用于生成 RISC-V 汇编指令的高级接口。它封装了底层的汇编指令细节，使得 V8 编译器能够更方便、更高效地生成执行 JavaScript 代码所需的机器码，并支持诸如调用约定、栈管理、尾调用优化、垃圾回收屏障等关键功能。它是 V8 引擎将 JavaScript 代码转化为可在 RISC-V 处理器上执行的机器码的关键组成部分。

Prompt: 
```
这是目录为v8/src/codegen/riscv/macro-assembler-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/riscv/macro-assembler-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共9部分，请归纳一下它的功能

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits.h>  // For LONG_MIN, LONG_MAX.

#include <optional>

#include "src/base/bits.h"
#include "src/base/division-by-constant.h"
#include "src/builtins/builtins-inl.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/callable.h"
#include "src/codegen/code-factory.h"
#include "src/codegen/external-reference-table.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/register-configuration.h"
#include "src/debug/debug.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/frames-inl.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/init/bootstrapper.h"
#include "src/logging/counters.h"
#include "src/objects/heap-number.h"
#include "src/runtime/runtime.h"
#include "src/snapshot/snapshot.h"
#include "src/wasm/wasm-code-manager.h"

// Satisfy cpplint check, but don't include platform-specific header. It is
// included recursively via macro-assembler.h.
#if 0
#include "src/codegen/riscv/macro-assembler-riscv.h"
#endif

namespace v8 {
namespace internal {

static inline bool IsZero(const Operand& rt) {
  if (rt.is_reg()) {
    return rt.rm() == zero_reg;
  } else {
    return rt.immediate() == 0;
  }
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
    bytes += kCallerSavedFPU.Count() * kDoubleSize;
  }

  return bytes;
}

int MacroAssembler::PushCallerSaved(SaveFPRegsMode fp_mode, Register exclusion1,
                                    Register exclusion2, Register exclusion3) {
  int bytes = 0;

  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = kJSCallerSaved - exclusions;
  MultiPush(list);
  bytes += list.Count() * kSystemPointerSize;

  if (fp_mode == SaveFPRegsMode::kSave) {
    MultiPushFPU(kCallerSavedFPU);
    bytes += kCallerSavedFPU.Count() * kDoubleSize;
  }

  return bytes;
}

int MacroAssembler::PopCallerSaved(SaveFPRegsMode fp_mode, Register exclusion1,
                                   Register exclusion2, Register exclusion3) {
  int bytes = 0;
  if (fp_mode == SaveFPRegsMode::kSave) {
    MultiPopFPU(kCallerSavedFPU);
    bytes += kCallerSavedFPU.Count() * kDoubleSize;
  }

  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = kJSCallerSaved - exclusions;
  MultiPop(list);
  bytes += list.Count() * kSystemPointerSize;

  return bytes;
}

#define __ ACCESS_MASM(masm)
namespace {
#ifndef V8_ENABLE_LEAPTIERING
// Only used when leaptiering is disabled.
static void TailCallOptimizedCodeSlot(MacroAssembler* masm,
                                      Register optimized_code_entry,
                                      Register scratch1, Register scratch2) {
  // ----------- S t a t e -------------
  //  -- a0 : actual argument count
  //  -- a3 : new target (preserved for callee if needed, and caller)
  //  -- a1 : target function (preserved for callee if needed, and caller)
  // -----------------------------------
  ASM_CODE_COMMENT(masm);
  DCHECK(!AreAliased(optimized_code_entry, a1, a3, scratch1, scratch2));

  Label heal_optimized_code_slot;

  // If the optimized code is cleared, go to runtime to update the optimization
  // marker field.
  __ LoadWeakValue(optimized_code_entry, optimized_code_entry,
                   &heal_optimized_code_slot);

  // The entry references a CodeWrapper object. Unwrap it now.
  __ LoadCodePointerField(
      optimized_code_entry,
      FieldMemOperand(optimized_code_entry, CodeWrapper::kCodeOffset));

  // Check if the optimized code is marked for deopt. If it is, call the
  // runtime to clear it.
  __ JumpIfCodeIsMarkedForDeoptimization(optimized_code_entry, scratch1,
                                         &heal_optimized_code_slot);

  // Optimized code is good, get it into the closure and link the closure into
  // the optimized functions list, then tail call the optimized code.
  // The feedback vector is no longer used, so re-use it as a scratch
  // register.
  __ ReplaceClosureCodeWithOptimizedCode(optimized_code_entry, a1);

  static_assert(kJavaScriptCallCodeStartRegister == a2, "ABI mismatch");
  __ LoadCodeInstructionStart(a2, optimized_code_entry, kJSEntrypointTag);
  __ Jump(a2);

  // Optimized code slot contains deoptimized code or code is cleared and
  // optimized code marker isn't updated. Evict the code, update the marker
  // and re-enter the closure's code.
  __ bind(&heal_optimized_code_slot);
  __ GenerateTailCallToReturnedCode(Runtime::kHealOptimizedCodeSlot);
}
#endif  // V8_ENABLE_LEAPTIERING

}  // namespace
#ifdef V8_ENABLE_DEBUG_CODE
void MacroAssembler::AssertFeedbackCell(Register object, Register scratch) {
  if (v8_flags.debug_code) {
    GetObjectType(object, scratch, scratch);
    Assert(eq, AbortReason::kExpectedFeedbackCell, scratch,
           Operand(FEEDBACK_CELL_TYPE));
  }
}
void MacroAssembler::AssertFeedbackVector(Register object, Register scratch) {
  if (v8_flags.debug_code) {
    GetObjectType(object, scratch, scratch);
    Assert(eq, AbortReason::kExpectedFeedbackVector, scratch,
           Operand(FEEDBACK_VECTOR_TYPE));
  }
}
void MacroAssembler::AssertUnreachable(AbortReason reason) {
  if (v8_flags.debug_code) Abort(reason);
}
#endif  // V8_ENABLE_DEBUG_CODE

void MacroAssembler::ReplaceClosureCodeWithOptimizedCode(
    Register optimized_code, Register closure) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(optimized_code, closure));
#ifdef V8_ENABLE_LEAPTIERING
  UNREACHABLE();
#else
  StoreCodePointerField(optimized_code,
                        FieldMemOperand(closure, JSFunction::kCodeOffset));
  RecordWriteField(closure, JSFunction::kCodeOffset, optimized_code,
                   kRAHasNotBeenSaved, SaveFPRegsMode::kIgnore, SmiCheck::kOmit,
                   SlotDescriptor::ForCodePointerSlot());
#endif  // V8_ENABLE_LEAPTIERING
}

void MacroAssembler::GenerateTailCallToReturnedCode(
    Runtime::FunctionId function_id) {
  // ----------- S t a t e -------------
  //  -- a0 : actual argument count
  //  -- a1 : target function (preserved for callee)
  //  -- a3 : new target (preserved for callee)
  // -----------------------------------
  {
    FrameScope scope(this, StackFrame::INTERNAL);
    // Push a copy of the target function, the new target and the actual
    // argument count.
    // Push function as parameter to the runtime call.
    SmiTag(kJavaScriptCallArgCountRegister);
    Push(kJavaScriptCallTargetRegister, kJavaScriptCallNewTargetRegister,
         kJavaScriptCallArgCountRegister, kJavaScriptCallTargetRegister);

    CallRuntime(function_id, 1);
    // Use the return value before restoring a0
    LoadCodeInstructionStart(a2, a0, kJSEntrypointTag);
    // Restore target function, new target and actual argument count.
    Pop(kJavaScriptCallTargetRegister, kJavaScriptCallNewTargetRegister,
        kJavaScriptCallArgCountRegister);
    SmiUntag(kJavaScriptCallArgCountRegister);
  }

  static_assert(kJavaScriptCallCodeStartRegister == a2, "ABI mismatch");
  Jump(a2);
}

Condition MacroAssembler::LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing(
    Register flags, Register feedback_vector, Register result,
    CodeKind current_code_kind) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(flags, feedback_vector));
  DCHECK(CodeKindCanTierUp(current_code_kind));

  Lhu(flags, FieldMemOperand(feedback_vector, FeedbackVector::kFlagsOffset));
  uint32_t kFlagsMask = FeedbackVector::kFlagsTieringStateIsAnyRequested |
                        FeedbackVector::kFlagsMaybeHasTurbofanCode |
                        FeedbackVector::kFlagsLogNextExecution;
  if (current_code_kind != CodeKind::MAGLEV) {
    kFlagsMask |= FeedbackVector::kFlagsMaybeHasMaglevCode;
  }
  And(result, flags, Operand(kFlagsMask));
  return ne;
}

// Read off the flags in the feedback vector and check if there
// is optimized code or a tiering state that needs to be processed.
void MacroAssembler::LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
    Register flags, Register feedback_vector, CodeKind current_code_kind,
    Label* flags_need_processing) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(flags, feedback_vector));
  DCHECK(CodeKindCanTierUp(current_code_kind));
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Lhu(flags, FieldMemOperand(feedback_vector, FeedbackVector::kFlagsOffset));
  uint32_t flag_mask =
      FeedbackVector::FlagMaskForNeedsProcessingCheckFrom(current_code_kind);
  And(scratch, flags, Operand(flag_mask));
  Branch(flags_need_processing, ne, scratch, Operand(zero_reg));
}

void MacroAssembler::OptimizeCodeOrTailCallOptimizedCodeSlot(
    Register flags, Register feedback_vector) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(flags, feedback_vector));
#ifdef V8_ENABLE_LEAPTIERING
  // In the leaptiering case, we don't load optimized code from the feedback
  // vector so only need to call CompileOptimized or FunctionLogNextExecution
  // here. See also LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing above.
  Label needs_logging;
  {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    And(scratch, flags,
        Operand(FeedbackVector::kFlagsTieringStateIsAnyRequested));
    Branch(&needs_logging, eq, scratch, Operand(zero_reg));
  }
  GenerateTailCallToReturnedCode(Runtime::kCompileOptimized);
  bind(&needs_logging);
  GenerateTailCallToReturnedCode(Runtime::kFunctionLogNextExecution);
#else
  UseScratchRegisterScope temps(this);
  temps.Include(t0, t1);
  Label maybe_has_optimized_code, maybe_needs_logging;
  // Check if optimized code is available.
  {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    And(scratch, flags,
        Operand(FeedbackVector::kFlagsTieringStateIsAnyRequested));
    Branch(&maybe_needs_logging, eq, scratch, Operand(zero_reg),
           Label::Distance::kNear);
  }
  GenerateTailCallToReturnedCode(Runtime::kCompileOptimized);

  bind(&maybe_needs_logging);
  {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    And(scratch, flags, Operand(FeedbackVector::LogNextExecutionBit::kMask));
    Branch(&maybe_has_optimized_code, eq, scratch, Operand(zero_reg),
           Label::Distance::kNear);
  }

  GenerateTailCallToReturnedCode(Runtime::kFunctionLogNextExecution);

  bind(&maybe_has_optimized_code);
  Register optimized_code_entry = flags;
  LoadTaggedField(optimized_code_entry,
                  FieldMemOperand(feedback_vector,
                                  FeedbackVector::kMaybeOptimizedCodeOffset));
  TailCallOptimizedCodeSlot(this, optimized_code_entry, temps.Acquire(),
                            temps.Acquire());
#endif  // V8_ENABLE_LEAPTIERING
}

void MacroAssembler::LoadIsolateField(const Register& rd, IsolateFieldId id) {
  li(rd, ExternalReference::Create(id));
}

void MacroAssembler::LoadRoot(Register destination, RootIndex index) {
#if V8_TARGET_ARCH_RISCV64
  if (V8_STATIC_ROOTS_BOOL && RootsTable::IsReadOnly(index) &&
      is_int12(ReadOnlyRootPtr(index))) {
    DecompressTagged(destination, ReadOnlyRootPtr(index));
    return;
  }
#endif
  // Many roots have addresses that are too large to fit into addition immediate
  // operands. Evidence suggests that the extra instruction for decompression
  // costs us more than the load.
  LoadWord(destination,
           MemOperand(kRootRegister, RootRegisterOffsetForRootIndex(index)));
}

void MacroAssembler::LoadTaggedRoot(Register destination, RootIndex index) {
  if (V8_STATIC_ROOTS_BOOL && RootsTable::IsReadOnly(index) &&
      is_int12(ReadOnlyRootPtr(index))) {
    li(destination, (int32_t)ReadOnlyRootPtr(index));
    return;
  }
  LoadWord(destination,
           MemOperand(kRootRegister, RootRegisterOffsetForRootIndex(index)));
}
void MacroAssembler::LoadCompressedTaggedRoot(Register destination,
                                              RootIndex index) {
#ifdef V8_TARGET_ARCH_RISCV64
  Lwu(destination,
      MemOperand(kRootRegister, RootRegisterOffsetForRootIndex(index)));
#else
  LoadWord(destination,
           MemOperand(kRootRegister, RootRegisterOffsetForRootIndex(index)));
#endif
}

void MacroAssembler::PushCommonFrame(Register marker_reg) {
  if (marker_reg.is_valid()) {
    Push(ra, fp, marker_reg);
    AddWord(fp, sp, Operand(kSystemPointerSize));
  } else {
    Push(ra, fp);
    Mv(fp, sp);
  }
}

void MacroAssembler::PushStandardFrame(Register function_reg) {
  int offset = -StandardFrameConstants::kContextOffset;
  if (function_reg.is_valid()) {
    Push(ra, fp, cp, function_reg, kJavaScriptCallArgCountRegister);
    offset += 2 * kSystemPointerSize;
  } else {
    Push(ra, fp, cp, kJavaScriptCallArgCountRegister);
    offset += kSystemPointerSize;
  }
  AddWord(fp, sp, Operand(offset));
}

int MacroAssembler::SafepointRegisterStackIndex(int reg_code) {
  // The registers are pushed starting with the highest encoding,
  // which means that lowest encodings are closest to the stack pointer.
  return kSafepointRegisterStackIndexMap[reg_code];
}

// Clobbers object, dst, value, and ra, if (ra_status == kRAHasBeenSaved)
// The register 'object' contains a heap object pointer.  The heap object
// tag is shifted away.
void MacroAssembler::RecordWriteField(Register object, int offset,
                                      Register value, RAStatus ra_status,
                                      SaveFPRegsMode save_fp,
                                      SmiCheck smi_check, SlotDescriptor slot) {
  DCHECK(!AreAliased(object, value));
  // First, check if a write barrier is even needed. The tests below
  // catch stores of Smis.
  Label done;

  // Skip the barrier if writing a smi.
  if (smi_check == SmiCheck::kInline) {
    JumpIfSmi(value, &done);
  }

  // Although the object register is tagged, the offset is relative to the start
  // of the object, so offset must be a multiple of kTaggedSize.
  DCHECK(IsAligned(offset, kTaggedSize));

  if (v8_flags.debug_code) {
    Label ok;
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(!AreAliased(object, value, scratch));
    AddWord(scratch, object, offset - kHeapObjectTag);
    And(scratch, scratch, Operand(kTaggedSize - 1));
    BranchShort(&ok, eq, scratch, Operand(zero_reg));
    Abort(AbortReason::kUnalignedCellInWriteBarrier);
    bind(&ok);
  }

  RecordWrite(object, Operand(offset - kHeapObjectTag), value, ra_status,
              save_fp, SmiCheck::kOmit, slot);

  bind(&done);
}

void MacroAssembler::LoadTrustedPointerField(Register destination,
                                             MemOperand field_operand,
                                             IndirectPointerTag tag) {
#ifdef V8_ENABLE_SANDBOX
  LoadIndirectPointerField(destination, field_operand, tag);
#else
  LoadTaggedField(destination, field_operand);
#endif
}

void MacroAssembler::StoreTrustedPointerField(Register value,
                                              MemOperand dst_field_operand) {
#ifdef V8_ENABLE_SANDBOX
  StoreIndirectPointerField(value, dst_field_operand);
#else
  StoreTaggedField(value, dst_field_operand);
#endif
}

#ifdef V8_ENABLE_SANDBOX
void MacroAssembler::ResolveIndirectPointerHandle(Register destination,
                                                  Register handle,
                                                  IndirectPointerTag tag) {
  ASM_CODE_COMMENT(this);
  // The tag implies which pointer table to use.
  if (tag == kUnknownIndirectPointerTag) {
    // In this case we have to rely on the handle marking to determine which
    // pointer table to use.
    Label is_trusted_pointer_handle, done;
    DCHECK(!AreAliased(destination, handle));
    And(destination, handle, kCodePointerHandleMarker);
    Branch(&is_trusted_pointer_handle, eq, destination, Operand(zero_reg));
    ResolveCodePointerHandle(destination, handle);
    Branch(&done);
    bind(&is_trusted_pointer_handle);
    ResolveTrustedPointerHandle(destination, handle,
                                kUnknownIndirectPointerTag);
    bind(&done);
  } else if (tag == kCodeIndirectPointerTag) {
    ResolveCodePointerHandle(destination, handle);
  } else {
    ResolveTrustedPointerHandle(destination, handle, tag);
  }
}

void MacroAssembler::ResolveTrustedPointerHandle(Register destination,
                                                 Register handle,
                                                 IndirectPointerTag tag) {
  ASM_CODE_COMMENT(this);
  DCHECK_NE(tag, kCodeIndirectPointerTag);
  DCHECK(!AreAliased(handle, destination));

  Register table = destination;
  DCHECK(root_array_available_);
  LoadWord(table, MemOperand{kRootRegister,
                             IsolateData::trusted_pointer_table_offset()});
  SrlWord(handle, handle, kTrustedPointerHandleShift);
  CalcScaledAddress(destination, table, handle,
                    kTrustedPointerTableEntrySizeLog2);
  LoadWord(destination, MemOperand(destination, 0));
  // The LSB is used as marking bit by the trusted pointer table, so here we
  // have to set it using a bitwise OR as it may or may not be set.
  // Untag the pointer and remove the marking bit in one operation.
  Register tag_reg = handle;
  li(tag_reg, Operand(~(tag | kTrustedPointerTableMarkBit)));
  and_(destination, destination, tag_reg);
}

void MacroAssembler::ResolveCodePointerHandle(Register destination,
                                              Register handle) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(handle, destination));

  Register table = destination;
  li(table, ExternalReference::code_pointer_table_address());
  SrlWord(handle, handle, kCodePointerHandleShift);
  CalcScaledAddress(destination, table, handle, kCodePointerTableEntrySizeLog2);
  LoadWord(destination,
           MemOperand(destination, kCodePointerTableEntryCodeObjectOffset));
  // The LSB is used as marking bit by the code pointer table, so here we have
  // to set it using a bitwise OR as it may or may not be set.
  Or(destination, destination, Operand(kHeapObjectTag));
}

void MacroAssembler::LoadCodeEntrypointViaCodePointer(Register destination,
                                                      MemOperand field_operand,
                                                      CodeEntrypointTag tag) {
  DCHECK_NE(tag, kInvalidEntrypointTag);
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch, ExternalReference::code_pointer_table_address());
  Lwu(destination, field_operand);
  SrlWord(destination, destination, kCodePointerHandleShift);
  SllWord(destination, destination, kCodePointerTableEntrySizeLog2);
  AddWord(scratch, scratch, destination);
  LoadWord(destination, MemOperand(scratch, 0));
  if (tag != 0) {
    li(scratch, Operand(tag));
    xor_(destination, destination, scratch);
  }
}
#endif  // V8_ENABLE_SANDBOX

void MacroAssembler::LoadExternalPointerField(Register destination,
                                              MemOperand field_operand,
                                              ExternalPointerTag tag,
                                              Register isolate_root) {
  DCHECK(!AreAliased(destination, isolate_root));
  ASM_CODE_COMMENT(this);
#ifdef V8_ENABLE_SANDBOX
  DCHECK_NE(tag, kExternalPointerNullTag);
  DCHECK(!IsSharedExternalPointerType(tag));
  UseScratchRegisterScope temps(this);
  Register external_table = temps.Acquire();
  if (isolate_root == no_reg) {
    DCHECK(root_array_available_);
    isolate_root = kRootRegister;
  }
  LoadWord(external_table,
           MemOperand(isolate_root,
                      IsolateData::external_pointer_table_offset() +
                          Internals::kExternalPointerTableBasePointerOffset));
  Lwu(destination, field_operand);
  srli(destination, destination, kExternalPointerIndexShift);
  slli(destination, destination, kExternalPointerTableEntrySizeLog2);
  AddWord(external_table, external_table, destination);
  LoadWord(destination, MemOperand(external_table, 0));
  temps.Include(external_table);
  external_table = no_reg;
  And(destination, destination, Operand(~tag));
#else
  LoadWord(destination, field_operand);
#endif  // V8_ENABLE_SANDBOX
}

#ifdef V8_TARGET_ARCH_RISCV64
void MacroAssembler::LoadIndirectPointerField(Register destination,
                                              MemOperand field_operand,
                                              IndirectPointerTag tag) {
#ifdef V8_ENABLE_SANDBOX
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register handle = t6;
  DCHECK_NE(handle, destination);
  Lwu(handle, field_operand);

  ResolveIndirectPointerHandle(destination, handle, tag);
#else
  UNREACHABLE();
#endif  // V8_ENABLE_SANDBOX
}

void MacroAssembler::StoreIndirectPointerField(Register value,
                                               MemOperand dst_field_operand,
                                               Trapper&& trapper) {
#ifdef V8_ENABLE_SANDBOX
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Lw(scratch,
     FieldMemOperand(value, ExposedTrustedObject::kSelfIndirectPointerOffset));
  Sw(scratch, dst_field_operand, std::forward<Trapper>(trapper));
#else
  UNREACHABLE();
#endif  // V8_ENABLE_SANDBOX
}
#endif  // V8_TARGET_ARCH_RISCV64

void MacroAssembler::MaybeSaveRegisters(RegList registers) {
  if (registers.is_empty()) return;
  MultiPush(registers);
}

void MacroAssembler::MaybeRestoreRegisters(RegList registers) {
  if (registers.is_empty()) return;
  MultiPop(registers);
}

void MacroAssembler::CallEphemeronKeyBarrier(Register object, Operand offset,
                                             SaveFPRegsMode fp_mode) {
  ASM_CODE_COMMENT(this);
  RegList registers = WriteBarrierDescriptor::ComputeSavedRegisters(object);
  MaybeSaveRegisters(registers);

  Register object_parameter = WriteBarrierDescriptor::ObjectRegister();
  Register slot_address_parameter =
      WriteBarrierDescriptor::SlotAddressRegister();

  MoveObjectAndSlot(object_parameter, slot_address_parameter, object, offset);

  CallBuiltin(Builtins::EphemeronKeyBarrier(fp_mode));
  MaybeRestoreRegisters(registers);
}

void MacroAssembler::CallIndirectPointerBarrier(Register object, Operand offset,
                                                SaveFPRegsMode fp_mode,
                                                IndirectPointerTag tag) {
  ASM_CODE_COMMENT(this);
  RegList registers =
      IndirectPointerWriteBarrierDescriptor::ComputeSavedRegisters(object);
  MaybeSaveRegisters(registers);

  MoveObjectAndSlot(
      IndirectPointerWriteBarrierDescriptor::ObjectRegister(),
      IndirectPointerWriteBarrierDescriptor::SlotAddressRegister(), object,
      offset);
  li(IndirectPointerWriteBarrierDescriptor::IndirectPointerTagRegister(),
     Operand(tag));

  CallBuiltin(Builtins::IndirectPointerBarrier(fp_mode));
  MaybeRestoreRegisters(registers);
}

void MacroAssembler::CallRecordWriteStubSaveRegisters(Register object,
                                                      Operand offset,
                                                      SaveFPRegsMode fp_mode,
                                                      StubCallMode mode) {
  ASM_CODE_COMMENT(this);
  RegList registers = WriteBarrierDescriptor::ComputeSavedRegisters(object);
  MaybeSaveRegisters(registers);

  Register object_parameter = WriteBarrierDescriptor::ObjectRegister();
  Register slot_address_parameter =
      WriteBarrierDescriptor::SlotAddressRegister();

  MoveObjectAndSlot(object_parameter, slot_address_parameter, object, offset);

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
  if (mode == StubCallMode::kCallWasmRuntimeStub) {
    auto wasm_target =
        static_cast<Address>(wasm::WasmCode::GetRecordWriteBuiltin(fp_mode));
    Call(wasm_target, RelocInfo::WASM_STUB_CALL);
  } else {
    CallBuiltin(Builtins::RecordWrite(fp_mode));
  }
}

void MacroAssembler::MoveObjectAndSlot(Register dst_object, Register dst_slot,
                                       Register object, Operand offset) {
  ASM_CODE_COMMENT(this);
  DCHECK_NE(dst_object, dst_slot);
  // If `offset` is a register, it cannot overlap with `object`.
  DCHECK_IMPLIES(!offset.IsImmediate(), offset.rm() != object);

  // If the slot register does not overlap with the object register, we can
  // overwrite it.
  if (dst_slot != object) {
    AddWord(dst_slot, object, offset);
    mv(dst_object, object);
    return;
  }

  DCHECK_EQ(dst_slot, object);

  // If the destination object register does not overlap with the offset
  // register, we can overwrite it.
  if (offset.IsImmediate() || (offset.rm() != dst_object)) {
    mv(dst_object, dst_slot);
    AddWord(dst_slot, dst_slot, offset);
    return;
  }

  DCHECK_EQ(dst_object, offset.rm());

  // We only have `dst_slot` and `dst_object` left as distinct registers so we
  // have to swap them. We write this as a add+sub sequence to avoid using a
  // scratch register.
  AddWord(dst_slot, dst_slot, dst_object);
  SubWord(dst_object, dst_slot, dst_object);
}

// Clobbers object, address, value, and ra, if (ra_status == kRAHasBeenSaved)
// The register 'object' contains a heap object pointer.  The heap object
// tag is shifted away.
void MacroAssembler::RecordWrite(Register object, Operand offset,
                                 Register value, RAStatus ra_status,
                                 SaveFPRegsMode fp_mode, SmiCheck smi_check,
                                 SlotDescriptor slot) {
  DCHECK(!AreAliased(object, value));

  if (v8_flags.debug_code) {
    UseScratchRegisterScope temps(this);
    Register temp = temps.Acquire();
    DCHECK(!AreAliased(object, value, temp));
    AddWord(temp, object, offset);
#ifdef V8_TARGET_ARCH_RISCV64
    if (slot.contains_indirect_pointer()) {
      LoadIndirectPointerField(temp, MemOperand(temp, 0),
                               slot.indirect_pointer_tag());
    } else {
      DCHECK(slot.contains_direct_pointer());
      LoadTaggedField(temp, MemOperand(temp, 0));
    }
#else
    LoadTaggedField(temp, MemOperand(temp));
#endif
    Assert(eq, AbortReason::kWrongAddressOrValuePassedToRecordWrite, temp,
           Operand(value));
  }

  if (v8_flags.disable_write_barriers) {
    return;
  }

  // First, check if a write barrier is even needed. The tests below
  // catch stores of smis and stores into the young generation.
  Label done;

  if (smi_check == SmiCheck::kInline) {
    DCHECK_EQ(0, kSmiTag);
    JumpIfSmi(value, &done);
  }

  {
    UseScratchRegisterScope temps(this);
    CheckPageFlag(value, MemoryChunk::kPointersToHereAreInterestingMask,
                  eq,  // In RISC-V, it uses cc for a comparison with 0, so if
                       // no bits are set, and cc is eq, it will branch to done
                  &done);

    CheckPageFlag(object, MemoryChunk::kPointersFromHereAreInterestingMask,
                  eq,  // In RISC-V, it uses cc for a comparison with 0, so if
                       // no bits are set, and cc is eq, it will branch to done
                  &done);
  }
  // Record the actual write.
  if (ra_status == kRAHasNotBeenSaved) {
    push(ra);
  }
  Register slot_address = WriteBarrierDescriptor::SlotAddressRegister();
  DCHECK(!AreAliased(object, slot_address, value));
  // TODO(cbruni): Turn offset into int.
  if (slot.contains_direct_pointer()) {
    DCHECK(offset.IsImmediate());
    AddWord(slot_address, object, offset);
    CallRecordWriteStub(object, slot_address, fp_mode,
                        StubCallMode::kCallBuiltinPointer);
  } else {
    DCHECK(slot.contains_indirect_pointer());
    CallIndirectPointerBarrier(object, offset, fp_mode,
                               slot.indirect_pointer_tag());
  }
  if (ra_status == kRAHasNotBeenSaved) {
    pop(ra);
  }
  if (v8_flags.debug_code) li(slot_address, Operand(kZapValue));

  bind(&done);
}

// ---------------------------------------------------------------------------
// Instruction macros.
#if V8_TARGET_ARCH_RISCV64
void MacroAssembler::DecodeSandboxedPointer(Register value) {
  ASM_CODE_COMMENT(this);
#ifdef V8_ENABLE_SANDBOX
  srli(value, value, kSandboxedPointerShift);
  AddWord(value, value, kPtrComprCageBaseRegister);
#else
  UNREACHABLE();
#endif
}

void MacroAssembler::LoadSandboxedPointerField(
    Register destination, const MemOperand& field_operand) {
#ifdef V8_ENABLE_SANDBOX
  ASM_CODE_COMMENT(this);
  LoadWord(destination, field_operand);
  DecodeSandboxedPointer(destination);
#else
  UNREACHABLE();
#endif
}

void MacroAssembler::StoreSandboxedPointerField(
    Register value, const MemOperand& dst_field_operand) {
#ifdef V8_ENABLE_SANDBOX
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  SubWord(scratch, value, kPtrComprCageBaseRegister);
  slli(scratch, scratch, kSandboxedPointerShift);
  StoreWord(scratch, dst_field_operand);
#else
  UNREACHABLE();
#endif
}

void MacroAssembler::Add32(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    if (v8_flags.riscv_c_extension && (rd.code() == rs.code()) &&
        ((rd.code() & 0b11000) == 0b01000) &&
        ((rt.rm().code() & 0b11000) == 0b01000)) {
      c_addw(rd, rt.rm());
    } else {
      addw(rd, rs, rt.rm());
    }
  } else {
    if (v8_flags.riscv_c_extension && is_int6(rt.immediate()) &&
        (rd.code() == rs.code()) && (rd != zero_reg) &&
        !MustUseReg(rt.rmode())) {
      c_addiw(rd, static_cast<int8_t>(rt.immediate()));
    } else if (is_int12(rt.immediate()) && !MustUseReg(rt.rmode())) {
      addiw(rd, rs, static_cast<int32_t>(rt.immediate()));
    } else if ((-4096 <= rt.immediate() && rt.immediate() <= -2049) ||
               (2048 <= rt.immediate() && rt.immediate() <= 4094)) {
      addiw(rd, rs, rt.immediate() / 2);
      addiw(rd, rd, rt.immediate() - (rt.immediate() / 2));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      Li(scratch, rt.immediate());
      addw(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Sub32(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    if (v8_flags.riscv_c_extension && (rd.code() == rs.code()) &&
        ((rd.code() & 0b11000) == 0b01000) &&
        ((rt.rm().code() & 0b11000) == 0b01000)) {
      c_subw(rd, rt.rm());
    } else {
      subw(rd, rs, rt.rm());
    }
  } else {
    DCHECK(is_int32(rt.immediate()));
    if (v8_flags.riscv_c_extension && (rd.code() == rs.code()) &&
        (rd != zero_reg) && is_int6(-rt.immediate()) &&
        !MustUseReg(rt.rmode())) {
      c_addiw(
          rd,
          static_cast<int8_t>(
              -rt.immediate()));  // No c_subiw instr, use c_addiw(x, y, -imm).
    } else if (is_int12(-rt.immediate()) && !MustUseReg(rt.rmode())) {
      addiw(rd, rs,
            static_cast<int32_t>(
                -rt.immediate()));  // No subiw instr, use addiw(x, y, -imm).
    } else if ((-4096 <= -rt.immediate() && -rt.immediate() <= -2049) ||
               (2048 <= -rt.immediate() && -rt.immediate() <= 4094)) {
      addiw(rd, rs, -rt.immediate() / 2);
      addiw(rd, rd, -rt.immediate() - (-rt.immediate() / 2));
    } else {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      if (-rt.immediate() >> 12 == 0 && !MustUseReg(rt.rmode())) {
        // Use load -imm and addu when loading -imm generates one instruction.
        Li(scratch, -rt.immediate());
        addw(rd, rs, scratch);
      } else {
        // li handles the relocation.
        Li(scratch, rt.immediate());
        subw(rd, rs, s
"""


```