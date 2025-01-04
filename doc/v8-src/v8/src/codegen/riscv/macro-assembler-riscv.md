Response: The user wants to understand the functionality of the C++ code provided in the file `v8/src/codegen/riscv/macro-assembler-riscv.cc`. This is part 1 of a 5-part file. The request also asks for a JavaScript example if the C++ code relates to JavaScript functionality.

**Plan:**

1. **Analyze the C++ code:**  Focus on the class `MacroAssembler` and its methods within this snippet. Identify the core functionalities provided by these methods. Pay attention to the includes to understand the context (e.g., `assembler-inl.h`, `code-factory.h`).
2. **Identify JavaScript connection:**  Determine if the functionalities are related to how V8 executes JavaScript code. Look for concepts like stack management, function calls, optimization, and memory management.
3. **Formulate a summary:** Concisely describe the functionalities of this part of the `MacroAssembler`.
4. **Create a JavaScript example (if applicable):** If a connection to JavaScript is found, construct a simple JavaScript code snippet that demonstrates the functionality being implemented in the C++ code.
这个C++代码文件是V8 JavaScript引擎中用于RISC-V架构的`MacroAssembler`类的实现。 `MacroAssembler`是一个提供高级汇编指令的工具，它封装了底层的RISC-V指令，使得V8的codegen模块能够更容易地生成机器码。

在这个代码片段中，主要的功能可以归纳为以下几点：

1. **栈帧管理 (Stack Frame Management):**  提供了用于管理函数调用栈帧的方法，例如 `RequiredStackSizeForCallerSaved`, `PushCallerSaved`, `PopCallerSaved`, `PushCommonFrame`, `PushStandardFrame`。这些方法用于保存和恢复调用者保存的寄存器，以及建立标准的函数调用栈帧结构。

2. **尾调用优化 (Tail Call Optimization):**  包含与尾调用优化相关的逻辑，尽管在启用了Leaptiering优化的情况下，部分代码可能不会被使用 (`TailCallOptimizedCodeSlot` 函数及其条件编译)。尾调用优化能够避免不必要的栈帧创建，提高性能。

3. **代码优化和分层编译 (Code Optimization and Tiering):** 提供了与代码优化和分层编译相关的支持，例如 `LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing`, `LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing`, `OptimizeCodeOrTailCallOptimizedCodeSlot`, `ReplaceClosureCodeWithOptimizedCode`。 这些函数用于检查反馈向量（Feedback Vector）中的信息，判断是否需要进行代码优化，以及如何替换函数闭包中的代码。

4. **根对象访问 (Root Object Access):**  提供了加载预定义根对象（Root）的方法，例如 `LoadRoot`, `LoadTaggedRoot`, `LoadCompressedTaggedRoot`。根对象是V8堆中一些常用的、具有特殊用途的对象。

5. **写屏障 (Write Barrier):** 实现了写屏障机制，用于维护垃圾回收器的正确性。 相关函数有 `RecordWriteField`, `RecordWrite`, `CallRecordWriteStubSaveRegisters`, `CallRecordWriteStub`, `CallEphemeronKeyBarrier`, `CallIndirectPointerBarrier`, `MoveObjectAndSlot`。 写屏障确保当一个对象指向另一个可能需要被垃圾回收的对象时，垃圾回收器能够正确追踪。

6. **指令宏 (Instruction Macros):**  定义了许多封装RISC-V汇编指令的C++方法，例如 `AddWord`, `SubWord`, `Mul`, `Div`, `And`, `Or`, `Xor`, `Sll`, `Srl`,  `Li`, `Mv` 等等。 这些宏使得生成汇编代码更加方便和可读。  针对RISC-V64和RISC-V32架构可能存在不同的实现。

7. **条件断言 (Conditional Assertion):**  提供了一些用于调试的代码，例如 `AssertFeedbackCell`, `AssertFeedbackVector`, `AssertUnreachable`。 在debug模式下，这些断言可以帮助开发者尽早发现错误。

8. **沙箱支持 (Sandbox Support):**  包含一些与沙箱环境相关的代码，例如 `LoadSandboxedPointerField`, `StoreSandboxedPointerField`, `DecodeSandboxedPointer`,  `LoadIndirectPointerField`, `StoreIndirectPointerField`, `ResolveIndirectPointerHandle`, `ResolveTrustedPointerHandle`, `ResolveCodePointerHandle`, `LoadCodeEntrypointViaCodePointer`, `LoadExternalPointerField`。 这些功能用于在启用了沙箱的V8构建中处理指针。

**与JavaScript的关系及举例说明:**

`MacroAssembler`生成的机器码最终会执行JavaScript代码。 很多这里实现的功能都直接关联到JavaScript的运行时行为。

**例子 1:  栈帧管理 (`PushStandardFrame`)**

当JavaScript函数被调用时，V8会创建一个栈帧来存储函数的局部变量、参数以及控制信息。 `PushStandardFrame` 方法就用于在RISC-V架构上建立这样的栈帧。

```javascript
function foo(a, b) {
  let sum = a + b;
  return sum;
}

foo(1, 2);
```

当 `foo(1, 2)` 被调用时，`PushStandardFrame` (或类似功能的代码) 会被执行，将返回地址、帧指针、上下文等信息压入栈中，为函数 `foo` 的执行创建一个环境。

**例子 2: 代码优化和分层编译 (`OptimizeCodeOrTailCallOptimizedCodeSlot`, `ReplaceClosureCodeWithOptimizedCode`)**

V8会监控JavaScript代码的执行情况，对于频繁执行的代码会进行优化。 `OptimizeCodeOrTailCallOptimizedCodeSlot` 会检查是否已经有优化后的代码可用。 `ReplaceClosureCodeWithOptimizedCode`  会在优化完成后，将函数对象中指向未优化代码的指针替换为指向优化后代码的指针。

```javascript
function add(x, y) {
  return x + y;
}

for (let i = 0; i < 10000; i++) {
  add(i, i + 1); // 经过多次调用，add函数可能被优化
}
```

在这个例子中，`add` 函数在循环中被多次调用，V8可能会将其优化。 `OptimizeCodeOrTailCallOptimizedCodeSlot` 和 `ReplaceClosureCodeWithOptimizedCode` 参与了这个优化过程，确保后续调用能够执行优化后的机器码。

**例子 3: 写屏障 (`RecordWriteField`)**

当JavaScript中一个对象的一个属性被赋值为另一个对象时，可能需要执行写屏障来通知垃圾回收器这种对象间的引用关系。

```javascript
let obj1 = {};
let obj2 = { data: 10 };
obj1.ref = obj2; // 可能会触发写屏障
```

当执行 `obj1.ref = obj2;` 时，如果 `obj1` 和 `obj2` 处于不同的内存区域（例如，一个在老生代，一个在新生代），`RecordWriteField` (或相关的写屏障函数) 会被调用，记录这次写操作，以便垃圾回收器在回收内存时能够正确处理对象间的引用关系，避免悬挂指针。

总而言之，这个C++代码文件是V8引擎将JavaScript代码转换为RISC-V架构机器码的关键组成部分，它提供了构建这些机器码所需的各种低级操作和管理机制。

Prompt: 
```
这是目录为v8/src/codegen/riscv/macro-assembler-riscv.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共5部分，请归纳一下它的功能

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
        subw(rd, rs, scratch);
      }
    }
  }
}

void MacroAssembler::AddWord(Register rd, Register rs, const Operand& rt) {
  Add64(rd, rs, rt);
}

void MacroAssembler::SubWord(Register rd, Register rs, const Operand& rt) {
  Sub64(rd, rs, rt);
}

void MacroAssembler::Sub64(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    if (v8_flags.riscv_c_extension && (rd.code() == rs.code()) &&
        ((rd.code() & 0b11000) == 0b01000) &&
        ((rt.rm().code() & 0b11000) == 0b01000)) {
      c_sub(rd, rt.rm());
    } else {
      sub(rd, rs, rt.rm());
    }
  } else if (v8_flags.riscv_c_extension && (rd.code() == rs.code()) &&
             (rd != zero_reg) && is_int6(-rt.immediate()) &&
             (rt.immediate() != 0) && !MustUseReg(rt.rmode())) {
    c_addi(rd,
           static_cast<int8_t>(
               -rt.immediate()));  // No c_subi instr, use c_addi(x, y, -imm).

  } else if (v8_flags.riscv_c_extension && is_int10(-rt.immediate()) &&
             (rt.immediate() != 0) && ((rt.immediate() & 0xf) == 0) &&
             (rd.code() == rs.code()) && (rd == sp) &&
             !MustUseReg(rt.rmode())) {
    c_addi16sp(static_cast<int16_t>(-rt.immediate()));
  } else if (is_int12(-rt.immediate()) && !MustUseReg(rt.rmode())) {
    addi(rd, rs,
         static_cast<int32_t>(
             -rt.immediate()));  // No subi instr, use addi(x, y, -imm).
  } else if ((-4096 <= -rt.immediate() && -rt.immediate() <= -2049) ||
             (2048 <= -rt.immediate() && -rt.immediate() <= 4094)) {
    addi(rd, rs, -rt.immediate() / 2);
    addi(rd, rd, -rt.immediate() - (-rt.immediate() / 2));
  } else {
    int li_count = InstrCountForLi64Bit(rt.immediate());
    int li_neg_count = InstrCountForLi64Bit(-rt.immediate());
    if (li_neg_count < li_count && !MustUseReg(rt.rmode())) {
      // Use load -imm and add when loading -imm generates one instruction.
      DCHECK(rt.immediate() != std::numeric_limits<int32_t>::min());
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      li(scratch, Operand(-rt.immediate()));
      add(rd, rs, scratch);
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      li(scratch, rt);
      sub(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Add64(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    if (v8_flags.riscv_c_extension && (rd.code() == rs.code()) &&
        (rt.rm() != zero_reg) && (rs != zero_reg)) {
      c_add(rd, rt.rm());
    } else {
      add(rd, rs, rt.rm());
    }
  } else {
    if (v8_flags.riscv_c_extension && is_int6(rt.immediate()) &&
        (rd.code() == rs.code()) && (rd != zero_reg) && (rt.immediate() != 0) &&
        !MustUseReg(rt.rmode())) {
      c_addi(rd, static_cast<int8_t>(rt.immediate()));
    } else if (v8_flags.riscv_c_extension && is_int10(rt.immediate()) &&
               (rt.immediate() != 0) && ((rt.immediate() & 0xf) == 0) &&
               (rd.code() == rs.code()) && (rd == sp) &&
               !MustUseReg(rt.rmode())) {
      c_addi16sp(static_cast<int16_t>(rt.immediate()));
    } else if (v8_flags.riscv_c_extension &&
               ((rd.code() & 0b11000) == 0b01000) && (rs == sp) &&
               is_uint10(rt.immediate()) && (rt.immediate() != 0) &&
               !MustUseReg(rt.rmode())) {
      c_addi4spn(rd, static_cast<uint16_t>(rt.immediate()));
    } else if (is_int12(rt.immediate()) && !MustUseReg(rt.rmode())) {
      addi(rd, rs, static_cast<int32_t>(rt.immediate()));
    } else if ((-4096 <= rt.immediate() && rt.immediate() <= -2049) ||
               (2048 <= rt.immediate() && rt.immediate() <= 4094)) {
      addi(rd, rs, rt.immediate() / 2);
      addi(rd, rd, rt.immediate() - (rt.immediate() / 2));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      BlockTrampolinePoolScope block_trampoline_pool(this);
      li(scratch, rt);
      add(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Mul32(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    mulw(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    mulw(rd, rs, scratch);
  }
}

void MacroAssembler::Mulh32(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    mul(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    mul(rd, rs, scratch);
  }
  srai(rd, rd, 32);
}

void MacroAssembler::Mulhu32(Register rd, Register rs, const Operand& rt,
                             Register rsz, Register rtz) {
  slli(rsz, rs, 32);
  if (rt.is_reg()) {
    slli(rtz, rt.rm(), 32);
  } else {
    Li(rtz, rt.immediate() << 32);
  }
  mulhu(rd, rsz, rtz);
  srai(rd, rd, 32);
}

void MacroAssembler::Mul64(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    mul(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    mul(rd, rs, scratch);
  }
}

void MacroAssembler::Mulh64(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    mulh(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    mulh(rd, rs, scratch);
  }
}

void MacroAssembler::Mulhu64(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    mulhu(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    mulhu(rd, rs, scratch);
  }
}

void MacroAssembler::Div32(Register res, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    divw(res, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    divw(res, rs, scratch);
  }
}

void MacroAssembler::Mod32(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    remw(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    remw(rd, rs, scratch);
  }
}

void MacroAssembler::Modu32(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    remuw(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    remuw(rd, rs, scratch);
  }
}

void MacroAssembler::Div64(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    div(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    div(rd, rs, scratch);
  }
}

void MacroAssembler::Divu32(Register res, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    divuw(res, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    divuw(res, rs, scratch);
  }
}

void MacroAssembler::Divu64(Register res, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    divu(res, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    divu(res, rs, scratch);
  }
}

void MacroAssembler::Mod64(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    rem(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    rem(rd, rs, scratch);
  }
}

void MacroAssembler::Modu64(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    remu(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    remu(rd, rs, scratch);
  }
}
#elif V8_TARGET_ARCH_RISCV32
void MacroAssembler::AddWord(Register rd, Register rs, const Operand& rt) {
  Add32(rd, rs, rt);
}

void MacroAssembler::Add32(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    if (v8_flags.riscv_c_extension && (rd.code() == rs.code()) &&
        (rt.rm() != zero_reg) && (rs != zero_reg)) {
      c_add(rd, rt.rm());
    } else {
      add(rd, rs, rt.rm());
    }
  } else {
    if (v8_flags.riscv_c_extension && is_int6(rt.immediate()) &&
        (rd.code() == rs.code()) && (rd != zero_reg) && (rt.immediate() != 0) &&
        !MustUseReg(rt.rmode())) {
      c_addi(rd, static_cast<int8_t>(rt.immediate()));
    } else if (v8_flags.riscv_c_extension && is_int10(rt.immediate()) &&
               (rt.immediate() != 0) && ((rt.immediate() & 0xf) == 0) &&
               (rd.code() == rs.code()) && (rd == sp) &&
               !MustUseReg(rt.rmode())) {
      c_addi16sp(static_cast<int16_t>(rt.immediate()));
    } else if (v8_flags.riscv_c_extension &&
               ((rd.code() & 0b11000) == 0b01000) && (rs == sp) &&
               is_uint10(rt.immediate()) && (rt.immediate() != 0) &&
               !MustUseReg(rt.rmode())) {
      c_addi4spn(rd, static_cast<uint16_t>(rt.immediate()));
    } else if (is_int12(rt.immediate()) && !MustUseReg(rt.rmode())) {
      addi(rd, rs, static_cast<int32_t>(rt.immediate()));
    } else if ((-4096 <= rt.immediate() && rt.immediate() <= -2049) ||
               (2048 <= rt.immediate() && rt.immediate() <= 4094)) {
      addi(rd, rs, rt.immediate() / 2);
      addi(rd, rd, rt.immediate() - (rt.immediate() / 2));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      BlockTrampolinePoolScope block_trampoline_pool(this);
      li(scratch, rt);
      add(rd, rs, scratch);
    }
  }
}

void MacroAssembler::SubWord(Register rd, Register rs, const Operand& rt) {
  Sub32(rd, rs, rt);
}

void MacroAssembler::Sub32(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    if (v8_flags.riscv_c_extension && (rd.code() == rs.code()) &&
        ((rd.code() & 0b11000) == 0b01000) &&
        ((rt.rm().code() & 0b11000) == 0b01000)) {
      c_sub(rd, rt.rm());
    } else {
      sub(rd, rs, rt.rm());
    }
  } else if (v8_flags.riscv_c_extension && (rd.code() == rs.code()) &&
             (rd != zero_reg) && is_int6(-rt.immediate()) &&
             (rt.immediate() != 0) && !MustUseReg(rt.rmode())) {
    c_addi(rd,
           static_cast<int8_t>(
               -rt.immediate()));  // No c_subi instr, use c_addi(x, y, -imm).

  } else if (v8_flags.riscv_c_extension && is_int10(-rt.immediate()) &&
             (rt.immediate() != 0) && ((rt.immediate() & 0xf) == 0) &&
             (rd.code() == rs.code()) && (rd == sp) &&
             !MustUseReg(rt.rmode())) {
    c_addi16sp(static_cast<int16_t>(-rt.immediate()));
  } else if (is_int12(-rt.immediate()) && !MustUseReg(rt.rmode())) {
    addi(rd, rs,
         static_cast<int32_t>(
             -rt.immediate()));  // No subi instr, use addi(x, y, -imm).
  } else if ((-4096 <= -rt.immediate() && -rt.immediate() <= -2049) ||
             (2048 <= -rt.immediate() && -rt.immediate() <= 4094)) {
    addi(rd, rs, -rt.immediate() / 2);
    addi(rd, rd, -rt.immediate() - (-rt.immediate() / 2));
  } else {
    // RV32G todo: imm64 or imm32 here
    int li_count = InstrCountForLi64Bit(rt.immediate());
    int li_neg_count = InstrCountForLi64Bit(-rt.immediate());
    if (li_neg_count < li_count && !MustUseReg(rt.rmode())) {
      // Use load -imm and add when loading -imm generates one instruction.
      DCHECK(rt.immediate() != std::numeric_limits<int32_t>::min());
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      li(scratch, Operand(-rt.immediate()));
      add(rd, rs, scratch);
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      li(scratch, rt);
      sub(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Mul32(Register rd, Register rs, const Operand& rt) {
  Mul(rd, rs, rt);
}

void MacroAssembler::Mul(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    mul(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    mul(rd, rs, scratch);
  }
}

void MacroAssembler::Mulh(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    mulh(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    mulh(rd, rs, scratch);
  }
}

void MacroAssembler::Mulhu(Register rd, Register rs, const Operand& rt,
                           Register rsz, Register rtz) {
  if (rt.is_reg()) {
    mulhu(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    mulhu(rd, rs, scratch);
  }
}

void MacroAssembler::Div(Register res, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    div(res, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    div(res, rs, scratch);
  }
}

void MacroAssembler::Mod(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    rem(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    rem(rd, rs, scratch);
  }
}

void MacroAssembler::Modu(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    remu(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    remu(rd, rs, scratch);
  }
}

void MacroAssembler::Divu(Register res, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    divu(res, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    divu(res, rs, scratch);
  }
}

#endif

void MacroAssembler::And(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    if (v8_flags.riscv_c_extension && (rd.code() == rs.code()) &&
        ((rd.code() & 0b11000) == 0b01000) &&
        ((rt.rm().code() & 0b11000) == 0b01000)) {
      c_and(rd, rt.rm());
    } else {
      and_(rd, rs, rt.rm());
    }
  } else {
    if (v8_flags.riscv_c_extension && is_int6(rt.immediate()) &&
        !MustUseReg(rt.rmode()) && (rd.code() == rs.code()) &&
        ((rd.code() & 0b11000) == 0b01000)) {
      c_andi(rd, static_cast<int8_t>(rt.immediate()));
    } else if (is_int12(rt.immediate()) && !MustUseReg(rt.rmode())) {
      andi(rd, rs, static_cast<int32_t>(rt.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      Li(scratch, rt.immediate());
      and_(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Or(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    if (v8_flags.riscv_c_extension && (rd.code() == rs.code()) &&
        ((rd.code() & 0b11000) == 0b01000) &&
        ((rt.rm().code() & 0b11000) == 0b01000)) {
      c_or(rd, rt.rm());
    } else {
      or_(rd, rs, rt.rm());
    }
  } else {
    if (is_int12(rt.immediate()) && !MustUseReg(rt.rmode())) {
      ori(rd, rs, static_cast<int32_t>(rt.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      Li(scratch, rt.immediate());
      or_(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Xor(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    if (v8_flags.riscv_c_extension && (rd.code() == rs.code()) &&
        ((rd.code() & 0b11000) == 0b01000) &&
        ((rt.rm().code() & 0b11000) == 0b01000)) {
      c_xor(rd, rt.rm());
    } else {
      xor_(rd, rs, rt.rm());
    }
  } else {
    if (is_int12(rt.immediate()) && !MustUseReg(rt.rmode())) {
      xori(rd, rs, static_cast<int32_t>(rt.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      Li(scratch, rt.immediate());
      xor_(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Nor(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    or_(rd, rs, rt.rm());
    not_(rd, rd);
  } else {
    Or(rd, rs, rt);
    not_(rd, rd);
  }
}

void MacroAssembler::Neg(Register rs, const Operand& rt) {
  DCHECK(rt.is_reg());
  neg(rs, rt.rm());
}

void MacroAssembler::Seqz(Register rd, const Operand& rt) {
  if (rt.is_reg()) {
    seqz(rd, rt.rm());
  } else {
    li(rd, rt.immediate() == 0);
  }
}

void MacroAssembler::Snez(Register rd, const Operand& rt) {
  if (rt.is_reg()) {
    snez(rd, rt.rm());
  } else {
    li(rd, rt.immediate() != 0);
  }
}

void MacroAssembler::Seq(Register rd, Register rs, const Operand& rt) {
  if (rs == zero_reg) {
    Seqz(rd, rt);
  } else if (IsZero(rt)) {
    seqz(rd, rs);
  } else {
    SubWord(rd, rs, rt);
    seqz(rd, rd);
  }
}

void MacroAssembler::Sne(Register rd, Register rs, const Operand& rt) {
  if (rs == zero_reg) {
    Snez(rd, rt);
  } else if (IsZero(rt)) {
    snez(rd, rs);
  } else {
    SubWord(rd, rs, rt);
    snez(rd, rd);
  }
}

void MacroAssembler::Slt(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    slt(rd, rs, rt.rm());
  } else {
    if (is_int12(rt.immediate()) && !MustUseReg(rt.rmode())) {
      slti(rd, rs, static_cast<int32_t>(rt.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      BlockTrampolinePoolScope block_trampoline_pool(this);
      Li(scratch, rt.immediate());
      slt(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Sltu(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    sltu(rd, rs, rt.rm());
  } else {
    if (is_int12(rt.immediate()) && !MustUseReg(rt.rmode())) {
      sltiu(rd, rs, static_cast<int32_t>(rt.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      BlockTrampolinePoolScope block_trampoline_pool(this);
      Li(scratch, rt.immediate());
      sltu(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Sle(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    slt(rd, rt.rm(), rs);
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    BlockTrampolinePoolScope block_trampoline_pool(this);
    Li(scratch, rt.immediate());
    slt(rd, scratch, rs);
  }
  xori(rd, rd, 1);
}

void MacroAssembler::Sleu(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    sltu(rd, rt.rm(), rs);
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    BlockTrampolinePoolScope block_trampoline_pool(this);
    Li(scratch, rt.immediate());
    sltu(rd, scratch, rs);
  }
  xori(rd, rd, 1);
}

void MacroAssembler::Sge(Register rd, Register rs, const Operand& rt) {
  Slt(rd, rs, rt);
  xori(rd, rd, 1);
}

void MacroAssembler::Sgeu(Register rd, Register rs, const Operand& rt) {
  Sltu(rd, rs, rt);
  xori(rd, rd, 1);
}

void MacroAssembler::Sgt(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    slt(rd, rt.rm(), rs);
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    BlockTrampolinePoolScope block_trampoline_pool(this);
    Li(scratch, rt.immediate());
    slt(rd, scratch, rs);
  }
}

void MacroAssembler::Sgtu(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    sltu(rd, rt.rm(), rs);
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    BlockTrampolinePoolScope block_trampoline_pool(this);
    Li(scratch, rt.immediate());
    sltu(rd, scratch, rs);
  }
}

#if V8_TARGET_ARCH_RISCV64
void MacroAssembler::Sll32(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    sllw(rd, rs, rt.rm());
  } else {
    uint8_t shamt = static_cast<uint8_t>(rt.immediate());
    slliw(rd, rs, shamt);
  }
}

void MacroAssembler::Sra32(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    sraw(rd, rs, rt.rm());
  } else {
    uint8_t shamt = static_cast<uint8_t>(rt.immediate());
    sraiw(rd, rs, shamt);
  }
}

void MacroAssembler::Srl32(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    srlw(rd, rs, rt.rm());
  } else {
    uint8_t shamt = static_cast<uint8_t>(rt.immediate());
    srliw(rd, rs, shamt);
  }
}

void MacroAssembler::SraWord(Register rd, Register rs, const Operand& rt) {
  Sra64(rd, rs, rt);
}

void MacroAssembler::Sra64(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    sra(rd, rs, rt.rm());
  } else if (v8_flags.riscv_c_extension && (rd.code() == rs.code()) &&
             ((rd.code() & 0b11000) == 0b01000) && is_int6(rt.immediate())) {
    uint8_t shamt = static_cast<uint8_t>(rt.immediate());
    c_srai(rd, shamt);
  } else {
    uint8_t shamt = static_cast<uint8_t>(rt.immediate());
    srai(rd, rs, shamt);
  }
}

void MacroAssembler::SrlWord(Register rd, Register rs, const Operand& rt) {
  Srl64(rd, rs, rt);
}

void MacroAssembler::Srl64(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    srl(rd, rs, rt.rm());
  } else if (v8_flags.riscv_c_extension && (rd.code() == rs.code()) &&
             ((rd.code() & 0b11000) == 0b01000) && is_int6(rt.immediate())) {
    uint8_t shamt = static_cast<uint8_t>(rt.immediate());
    c_srli(rd, shamt);
  } else {
    uint8_t shamt = static_cast<uint8_t>(rt.immediate());
    srli(rd, rs, shamt);
  }
}

void MacroAssembler::SllWord(Register rd, Register rs, const Operand& rt) {
  Sll64(rd, rs, rt);
}

void MacroAssembler::Sll64(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    sll(rd, rs, rt.rm());
  } else {
    uint8_t shamt = static_cast<uint8_t>(rt.immediate());
    if (v8_flags.riscv_c_extension && (rd.code() == rs.code()) &&
        (rd != zero_reg) && (shamt != 0) && is_uint6(shamt)) {
      c_slli(rd, shamt);
    } else {
      slli(rd, rs, shamt);
    }
  }
}

void MacroAssembler::Ror(Register rd, Register rs, const Operand& rt) {
  if (CpuFeatures::IsSupported(ZBB)) {
    if (rt.is_reg()) {
      rorw(rd, rs, rt.rm());
    } else {
      int64_t ror_value = rt.immediate() % 32;
      if (ror_value < 0) {
        ror_value += 32;
      }
      roriw(rd, rs, ror_value);
    }
    return;
  }
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  BlockTrampolinePoolScope block_trampoline_pool(this);
  if (rt.is_reg()) {
    negw(scratch, rt.rm());
    sllw(scratch, rs, scratch);
    srlw(rd, rs, rt.rm());
    or_(rd, scratch, rd);
    sext_w(rd, rd);
  } else {
    int64_t ror_value = rt.immediate() % 32;
    if (ror_value == 0) {
      Mv(rd, rs);
      return;
    } else if (ror_value < 0) {
      ror_value += 32;
    }
    srliw(scratch, rs, ror_value);
    slliw(rd, rs, 32 - ror_value);
    or_(rd, scratch, rd);
    sext_w(rd, rd);
  }
}

void MacroAssembler::Dror(Register rd, Register rs, const Operand& rt) {
  if (CpuFeatures::IsSupported(ZBB)) {
    if (rt.is_reg()) {
      ror(rd, rs, rt.rm());
    } else {
      int64_t dror_value = rt.immediate() % 64;
      if (dror_value < 0) {
        dror_value += 64;
      }
      rori(rd, rs, dror_value);
    }
    return;
  }
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  BlockTrampolinePoolScope block_trampoline_pool(this);
  if (rt.is_reg()) {
    negw(scratch, rt.rm());
    sll(scratch, rs, scratch);
    srl(rd, rs, rt.rm());
    or_(rd, scratch, rd);
  } else {
    int64_t dror_value = rt.immediate() % 64;
    if (dror_value == 0) {
      Mv(rd, rs);
      return;
    } else if (dror_value < 0) {
      dror_value += 64;
    }
    srli(scratch, rs, dror_value);
    slli(rd, rs, 64 - dror_value);
    or_(rd, scratch, rd);
  }
}
#elif V8_TARGET_ARCH_RISCV32
void MacroAssembler::SllWord(Register rd, Register rs, const Operand& rt) {
  Sll32(rd, rs, rt);
}

void MacroAssembler::Sll32(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    sll(rd, rs, rt.rm());
  } else {
    uint8_t shamt = static_cast<uint8_t>(rt.immediate());
    slli(rd, rs, shamt);
  }
}

void MacroAssembler::SraWord(Register rd, Register rs, const Operand& rt) {
  Sra32(rd, rs, rt);
}

void MacroAssembler::Sra32(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    sra(rd, rs, rt.rm());
  } else {
    uint8_t shamt = static_cast<uint8_t>(rt.immediate());
    srai(rd, rs, shamt);
  }
}

void MacroAssembler::SrlWord(Register rd, Register rs, const Operand& rt) {
  Srl32(rd, rs, rt);
}

void MacroAssembler::Srl32(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    srl(rd, rs, rt.rm());
  } else {
    uint8_t shamt = static_cast<uint8_t>(rt.immediate());
    srli(rd, rs, shamt);
  }
}

void MacroAssembler::Ror(Register rd, Register rs, const Operand& rt) {
  if (CpuFeatures::IsSupported(ZBB)) {
    if (rt.is_reg()) {
      ror(rd, rs, rt.rm());
    } else {
      int32_t ror_value = rt.immediate() % 32;
      if (ror_value < 0) {
        ror_value += 32;
      }
      rori(rd, rs, ror_value);
    }
    return;
  }
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  BlockTrampolinePoolScope block_trampoline_pool(this);
  if (rt.is_reg()) {
    neg(scratch, rt.rm());
    sll(scratch, rs, scratch);
    srl(rd, rs, rt.rm());
    or_(rd, scratch, rd);
  } else {
    int32_t ror_value = rt.immediate() % 32;
    if (ror_value == 0) {
      Mv(rd, rs);
      return;
    } else if (ror_value < 0) {
      ror_value += 32;
    }
    srli(scratch, rs, ror_value);
    slli(rd, rs, 32 - ror_value);
    or_(rd, scratch, rd);
  }
}
#endif

void MacroAssembler::Li(Register rd, intptr_t imm) {
  if (v8_flags.riscv_c_extension && (rd != zero_reg) && is_int6(imm)) {
    c_li(rd, imm);
  } else {
    RV_li(rd, imm);
  }
}

void MacroAssembler::Mv(Register rd, const Operand& rt) {
  if (v8_flags.riscv_c_extension && (rd != zero_reg) && (rt.rm() != zero_reg)) {
    c_mv(rd, rt.rm());
  } else {
    mv(rd, rt.rm());
  }
}

void MacroAssembler::CalcScaledAddress(Register rd, Register rt, Register rs,
                                       uint8_t sa) {
  DCHECK(sa >= 1 && sa <= 31);
  if (CpuFeatures::IsSupported(ZBA)) {
    switch (sa) {
      case 1:
        sh1add(rd, rs, rt);
        return;
      case 2:
        sh2add(rd, rs, rt);
        return;
      case 3:
        sh3add(rd, rs, rt);
        return;
      default:
        break;
    }
  }
  UseScratchRegisterScope temps(this);
  Register tmp = rd == rt ? temps.Acquire() : rd;
  DCHECK(tmp != rt);
  slli(tmp, rs, sa);
  AddWord(rd, rt, tmp);
  return;
}

// ------------Pseudo-instructions-------------
// Change endianness

template <int NBYTES>
void MacroAssembler::ReverseBytesHelper(Register rd, Register rs, Register tmp1,
                                        Register tmp2) {
  DCHECK(tmp1 != tmp2);
  DCHECK((rs != tmp1) && (rs != tmp2));
  DCHECK((rd != tmp1) && (rd != tmp2));

  // ByteMask - maximum value, held in byte
  constexpr int ByteMask = (1 << kBitsPerByte) - 1;
  // tmp1 = rs[0]; take least byte
  // tmp1 = tmp1 << kBitsPerByte;
  // for (nbyte = 1; nbyte < NBYTES - 1; nbyte++) {
  //   tmp2 = rs[nbyte]; take n`th byte
  //   tmp1 = (tmp2 | tmp1) << kBitsPerByte; add n`th source byte to tmp1
  // }
  // rd[0] = rs[NBYTES-1]; take upper byte
  // rd[NBYTES-1 : 1] = tmp1[NBYTES-1 : 1]; fill other bytes
  andi(tmp1, rs, ByteMask);
  slli(tmp1, tmp1, kBitsPerByte);
  for (int nbyte = 1; nbyte < NBYTES - 1; nbyte++) {
    srli(tmp2, rs, nbyte * kBitsPerByte);
    andi(tmp2, tmp2, ByteMask);
    or_(tmp1, tmp1, tmp2);
    slli(tmp1, tmp1, kBitsPerByte);
  }
  srli(rd, rs, (NBYTES - 1) * kBitsPerByte);
  andi(rd, rd, ByteMask);
  or_(rd, tmp1, rd);
}

#if V8_TARGET_ARCH_RISCV64
void MacroAssembler::ByteSwap(Register rd, Register rs, int operand_size,
                              Register scratch) {
  DCHECK(operand_size == 4 || operand_size == 8);
  if (CpuFeatures::IsSupported(ZBB)) {
    rev8(rd, rs);
    if (operand_size == 4) {
      srai(rd, rd, 32);
    }
    return;
  }
  DCHECK_NE(scratch, rs);
  DCHECK_NE(scratch, rd);
  if (operand_size == 4) {
    UseScratchRegisterScope temps(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    DCHECK((rd != t6) && (rs != t6));
    Register x0 = temps.Acquire();
    Register x1 = temps.Acquire();
    if (scratch == no_reg) {
      ReverseBytesHelper<8>(rd, rs, x0, x1);
      srai(rd, rd, 32);
    } else {
      // Uint32_t x1 = 0x00FF00FF;
      // x0 = (x0 << 16 | x0 >> 16);
      // x0 = (((x0 & x1) << 8)  | ((x0 & (x1 << 8)) >> 8));
      Register x2 = scratch;
      li(x1, 0x00FF00FF);
      slliw(x0, rs, 16);
      srliw(rd, rs, 16);
      or_(x0, rd, x0);   // x0 <- x0 << 16 | x0 >> 16
      and_(x2, x0, x1);  // x2 <- x0 & 0x00FF00FF
      slliw(x2, x2, 8);  // x2 <- (x0 & x1) << 8
      slliw(x1, x1, 8);  // x1 <- 0xFF00FF00
      and_(rd, x0, x1);  // x0 & 0xFF00FF00
      srliw(rd, rd, 8);
      or_(rd, rd, x2);  // (((x0 & x1) << 8)  | ((x0 & (x1 << 8)) >> 8))
    }
  } else {
    UseScratchRegisterScope temps(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    DCHECK((rd != t6) && (rs != t6));
    Register x0 = temps.Acquire();
    Register x1 = temps.Acquire();
    if (scratch == no_reg) {
      ReverseBytesHelper<8>(rd, rs, x0, x1);
    } else {
      // uinx24_t x1 = 0x0000FFFF0000FFFFl;
      // uinx24_t x1 = 0x00FF00FF00FF00FFl;
      // x0 = (x0 << 32 | x0 >> 32);
      // x0 = (x0 & x1) << 16 | (x0 & (x1 << 16)) >> 16;
      // x0 = (x0 & x1) << 8  | (x0 & (x1 << 8)) >> 8;
      Register x2 = scratch;
      li(x1, 0x0000FFFF0000FFFFl);
      slli(x0, rs, 32);
      srli(rd, rs, 32);
      or_(x0, rd, x0);   // x0 <- x0 << 32 | x0 >> 32
      and_(x2, x0, x1);  // x2 <- x0 & 0x0000FFFF0000FFFF
      slli(x2, x2, 16);  // x2 <- (x0 & 0x0000FFFF0000FFFF) << 16
      slli(x1, x1, 16);  // x1 <- 0xFFFF0000FFFF0000
      and_(rd, x0, x1);  // rd <- x0 & 0xFFFF0000FFFF0000
      srli(rd, rd, 16);  // rd <- x0 & (x1 << 16)) >> 16
      or_(x0, rd, x2);   // (x0 & x1) << 16 | (x0 & (x1 << 16)) >> 16;
      li(x1, 0x00FF00FF00FF00FFl);
      and_(x2, x0, x1);  // x2 <- x0 & 0x00FF00FF00FF00FF
      slli(x2, x2, 8);   // x2 <- (x0 & x1) << 8
      slli(x1, x1, 8);   // x1 <- 0xFF00FF00FF00FF00
      and_(rd, x0, x1);
      srli(rd, rd, 8);  // rd <- (x0 & (x1 << 8)) >> 8
      or_(rd, rd, x2);  // (((x0 & x1) << 8)  | ((x0 & (x1 << 8)) >> 8))
    }
  }
}

#elif V8_TARGET_ARCH_RISCV32
void MacroAssembler::ByteSwap(Register rd, Register rs, int operand_size,
                              Register scratch) {
  if (CpuFeatures::IsSupported(ZBB)) {
    rev8(rd, rs);
    return;
  }
  DCHECK_NE(scratch, rs);
  DCHECK_NE(scratch, rd);
  UseScratchRegisterScope temps(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  DCHECK((rd != t6) && (rs != t6));
  Register x0 = temps.Acquire();
  Register x1 = temps.Acquire();
  if (scratch == no_reg) {
    ReverseBytesHelper<4>(rd, rs, x0, x1);
  } else {
    // Uint32_t x1 = 0x00FF00FF;
    // x0 = (x0 << 16 | x0 >> 16);
    // x0 = (((x0 & x1) << 8)  | ((x0 & (x1 << 8)) >> 8));
    Register x2 = scratch;
    li(x1, 0x00FF00FF);
    slli(x0, rs, 16);
    srli(rd, rs, 16);
    or_(x0, rd, x0);   // x0 <- x0 << 16 | x0 >> 16
    and_(x2, x0, x1);  // x2 <- x0 & 0x00FF00FF
    slli(x2, x2, 8);   // x2 <- (x0 & x1) << 8
 
"""


```