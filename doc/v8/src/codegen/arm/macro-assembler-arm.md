Response: The user wants a summary of the functionality of the C++ code in `v8/src/codegen/arm/macro-assembler-arm.cc`. The file seems to be part of the V8 JavaScript engine, specifically for the ARM architecture.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The file is named `macro-assembler-arm.cc`. This immediately suggests it's about generating machine code (assembly) at a higher level of abstraction (macro-assembler) for the ARM architecture.

2. **Scan the includes:** The included headers provide clues about the functionalities. Keywords like `codegen`, `assembler`, `objects`, `runtime`, `deoptimizer`, `builtins` are significant. This points towards code generation for various aspects of the JavaScript engine, including object manipulation, runtime calls, handling deoptimization, and calling built-in functions.

3. **Look at the `namespace`:** The code is within `namespace v8 { namespace internal {`. This confirms it's internal to the V8 engine.

4. **Analyze key methods and patterns:**  Skimming through the code, recurring patterns and method names reveal the main functionalities:
    * **Stack manipulation:** `PushCallerSaved`, `PopCallerSaved`, `RequiredStackSizeForCallerSaved`, `Push`, `Pop`, `Drop`, `EnforceStackAlignment`.
    * **Loading and storing data:** `LoadFromConstantsTable`, `LoadRootRelative`, `StoreRootRelative`, `LoadIsolateField`, `LoadCodeInstructionStart`.
    * **Jumping and calling:** `Jump`, `Call`, `TailCallBuiltin`, `CallBuiltin`, `CallCodeObject`, `JumpCodeObject`, `CallJSFunction`, `JumpJSFunction`, `CallRuntime`.
    * **Object manipulation:** `LoadMap`, `RecordWriteField`, `RecordWrite`.
    * **Frame management:** `PushCommonFrame`, `PushStandardFrame`, `EnterFrame`, `LeaveFrame`, `EnterExitFrame`, `LeaveExitFrame`.
    * **Floating-point operations:** Methods starting with `VFP` (Virtual Floating Point).
    * **NEON instructions:**  Methods involving `QwNeonRegister`, suggesting support for SIMD instructions.
    * **Stub and prologue/epilogue handling:** `StubPrologue`, `Prologue`.
    * **Comparisons:** `CompareObjectType`, `CompareInstanceType`, `CompareRoot`.

5. **Group functionalities into logical categories:** Based on the identified methods and patterns, group the functionalities into broader categories for a more structured summary. Good categories would be: stack management, data access, control flow (jumps and calls), object interaction, frame operations, floating-point/SIMD, and utility functions.

6. **Formulate the summary:**  Write a concise summary that covers the main categories of functionality. Emphasize the core purpose of the file: providing building blocks for generating ARM machine code within the V8 engine.

7. **Consider the JavaScript connection:** The prompt specifically asks about the relationship with JavaScript. While the C++ code *generates* code that *executes* JavaScript, the direct connection is through the *effects* of the generated code. Think about what these assembly instructions achieve in a JavaScript context: function calls, object property access, comparisons, etc.

8. **Create a JavaScript example:** Devise a simple JavaScript example that demonstrates concepts handled by the macro-assembler. Function calls, property access, and basic arithmetic are good choices. Then, explain how the macro-assembler might be involved in generating the underlying machine code for these operations. Focus on the mapping between the high-level JavaScript and the low-level operations the macro-assembler facilitates.

9. **Review and refine:** Read through the summary and example, ensuring clarity, accuracy, and conciseness. Make sure the language is accessible and avoids overly technical jargon where possible. For instance, instead of just saying "it manipulates the stack," explain *why* (saving/restoring registers, passing arguments).
这个C++源代码文件 `macro-assembler-arm.cc` 是 V8 JavaScript 引擎中针对 **ARM 架构** 的 **宏汇编器** 的实现。

它的主要功能是提供一组高级的 C++ 接口（"宏指令"）来生成底层的 **ARM 汇编指令**。  这些宏指令比直接编写汇编代码更方便、更易读，并且能更好地与 V8 引擎的其他部分集成。

具体来说，这个文件定义了 `MacroAssembler` 类，其中包含了各种方法，用于生成执行 JavaScript 代码所需的 ARM 汇编指令，例如：

* **栈操作:**  如 `Push`, `Pop`, `Drop`, `PushCallerSaved`, `PopCallerSaved`，用于在运行时管理栈空间，保存和恢复寄存器。
* **数据加载和存储:** 如 `LoadRoot`, `LoadFromConstantsTable`, `ldr`, `str` 等，用于从内存中加载数据到寄存器，或将寄存器中的数据存储到内存。这包括访问 V8 引擎的内部数据结构，如根对象表。
* **控制流:** 如 `Jump`, `Call`, `Ret`, `b`, `bl` 等，用于改变程序的执行顺序，实现跳转、函数调用和返回。这包括调用 JavaScript 函数、内置函数 (builtins) 和 C++ 运行时函数。
* **对象操作:** 如 `LoadMap`, `RecordWriteField`, `CompareObjectType` 等，用于访问和操作 JavaScript 对象。`RecordWriteField` 用于实现垃圾回收器的写屏障。
* **浮点运算:**  以 `VFP` 开头的方法，用于生成 ARM 的浮点指令。
* **SIMD 指令:** 以 `Neon` 开头的方法，用于生成 ARM 的 NEON SIMD 指令，用于加速向量化计算。
* **异常处理:**  `PushStackHandler`, `PopStackHandler` 用于管理异常处理栈。
* **调试支持:**  例如 `CallDebugOnFunctionCall` 用于在调试模式下插入断点。
* **帧管理:**  `PushCommonFrame`, `PushStandardFrame`, `EnterFrame`, `LeaveFrame` 等用于创建和销毁函数调用栈帧。

**它与 JavaScript 的功能有密切关系。**  V8 引擎将 JavaScript 代码编译成机器码执行，而 `macro-assembler-arm.cc` 中定义的宏汇编器正是用于生成这些针对 ARM 架构的机器码。

**JavaScript 例子：**

假设有以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

当 V8 引擎编译执行这段代码时，`macro-assembler-arm.cc` 中的方法可能会被用来生成类似以下的 ARM 汇编指令（这是一个高度简化的例子）：

1. **函数 `add` 的编译：**
   * **创建栈帧:** `PushStandardFrame` 宏可能会生成指令来保存 `fp` 和 `lr` 寄存器，并设置新的栈帧。
   * **访问参数:**  宏可能会生成指令从栈中加载参数 `a` 和 `b` 到寄存器中。
   * **执行加法:**  可能会使用 `add` 指令将两个寄存器中的值相加。
   * **返回值:**  可能会使用指令将结果存储到特定的寄存器中。
   * **恢复栈帧并返回:** `LeaveFrame` 宏可能会生成指令来恢复 `fp` 和 `lr`，并使用 `bx lr` 返回。

2. **调用 `add(5, 10)`：**
   * **准备参数:**  宏可能会生成指令将参数 `5` 和 `10` (可能以 Smi 的形式) 推入栈中。
   * **查找函数地址:**  宏可能会生成指令来查找 `add` 函数对应的机器码地址。
   * **调用函数:** `Call` 宏可能会生成 `bl` 指令来跳转到 `add` 函数的地址。
   * **接收返回值:**  宏可能会生成指令从特定的寄存器中获取 `add` 函数的返回值。

**更具体地，例如 `LoadRoot` 方法:**

在 JavaScript 中访问全局对象 `undefined`：

```javascript
console.log(undefined);
```

在 V8 内部，`undefined` 是一个特殊的根对象。当编译 `console.log(undefined)` 时，`MacroAssembler::LoadRoot` 方法可能会被调用来生成 ARM 指令，从根对象表中加载 `undefined` 对象的地址到寄存器中。  生成的汇编代码可能类似于：

```assembly
ldr  r0, [r8, #offset_of_undefined_in_root_table]  // r8 是根寄存器
```

**总结来说，`macro-assembler-arm.cc` 是 V8 引擎将 JavaScript 代码转换成可在 ARM 处理器上执行的机器码的关键组成部分。它提供了一层抽象，使得代码生成过程更加高效和可维护。**

Prompt: 
```
这是目录为v8/src/codegen/arm/macro-assembler-arm.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits.h>  // For LONG_MIN, LONG_MAX.

#if V8_TARGET_ARCH_ARM

#include "src/base/bits.h"
#include "src/base/division-by-constant.h"
#include "src/base/numbers/double.h"
#include "src/base/utils/random-number-generator.h"
#include "src/builtins/builtins-inl.h"
#include "src/codegen/assembler-inl.h"
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
#include "src/objects/objects-inl.h"
#include "src/runtime/runtime.h"
#include "src/snapshot/snapshot.h"

// Satisfy cpplint check, but don't include platform-specific header. It is
// included recursively via macro-assembler.h.
#if 0
#include "src/codegen/arm/macro-assembler-arm.h"
#endif

#define __ ACCESS_MASM(masm)

namespace v8 {
namespace internal {

int MacroAssembler::RequiredStackSizeForCallerSaved(SaveFPRegsMode fp_mode,
                                                    Register exclusion1,
                                                    Register exclusion2,
                                                    Register exclusion3) const {
  int bytes = 0;
  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = (kCallerSaved | lr) - exclusions;

  bytes += list.Count() * kPointerSize;

  if (fp_mode == SaveFPRegsMode::kSave) {
    bytes += DwVfpRegister::kNumRegisters * DwVfpRegister::kSizeInBytes;
  }

  return bytes;
}

int MacroAssembler::PushCallerSaved(SaveFPRegsMode fp_mode, Register exclusion1,
                                    Register exclusion2, Register exclusion3) {
  ASM_CODE_COMMENT(this);
  int bytes = 0;
  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = (kCallerSaved | lr) - exclusions;
  stm(db_w, sp, list);

  bytes += list.Count() * kPointerSize;

  if (fp_mode == SaveFPRegsMode::kSave) {
    SaveFPRegs(sp, lr);
    bytes += DwVfpRegister::kNumRegisters * DwVfpRegister::kSizeInBytes;
  }

  return bytes;
}

int MacroAssembler::PopCallerSaved(SaveFPRegsMode fp_mode, Register exclusion1,
                                   Register exclusion2, Register exclusion3) {
  ASM_CODE_COMMENT(this);
  int bytes = 0;
  if (fp_mode == SaveFPRegsMode::kSave) {
    RestoreFPRegs(sp, lr);
    bytes += DwVfpRegister::kNumRegisters * DwVfpRegister::kSizeInBytes;
  }

  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = (kCallerSaved | lr) - exclusions;
  ldm(ia_w, sp, list);

  bytes += list.Count() * kPointerSize;

  return bytes;
}

void MacroAssembler::LoadFromConstantsTable(Register destination,
                                            int constant_index) {
  DCHECK(RootsTable::IsImmortalImmovable(RootIndex::kBuiltinsConstantsTable));

  const uint32_t offset = OFFSET_OF_DATA_START(FixedArray) +
                          constant_index * kPointerSize - kHeapObjectTag;

  LoadRoot(destination, RootIndex::kBuiltinsConstantsTable);
  ldr(destination, MemOperand(destination, offset));
}

void MacroAssembler::LoadRootRelative(Register destination, int32_t offset) {
  ldr(destination, MemOperand(kRootRegister, offset));
}

void MacroAssembler::StoreRootRelative(int32_t offset, Register value) {
  str(value, MemOperand(kRootRegister, offset));
}

void MacroAssembler::LoadRootRegisterOffset(Register destination,
                                            intptr_t offset) {
  if (offset == 0) {
    Move(destination, kRootRegister);
  } else {
    add(destination, kRootRegister, Operand(offset));
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
        ldr(scratch,
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

void MacroAssembler::GetLabelAddress(Register dest, Label* target) {
  // This should be just a
  //    add(dest, pc, branch_offset(target));
  // but current implementation of Assembler::bind_to()/target_at_put() add
  // (InstructionStream::kHeaderSize - kHeapObjectTag) to a position of a label
  // in a "linked" state and thus making it usable only for mov_label_offset().
  // TODO(ishell): fix branch_offset() and re-implement
  // RegExpMacroAssemblerARM::PushBacktrack() without mov_label_offset().
  mov_label_offset(dest, target);
  // mov_label_offset computes offset of the |target| relative to the "current
  // InstructionStream object pointer" which is essentally pc_offset() of the
  // label added with (InstructionStream::kHeaderSize - kHeapObjectTag).
  // Compute "current InstructionStream object pointer" and add it to the
  // offset in |lr| register.
  int current_instr_code_object_relative_offset =
      pc_offset() + Instruction::kPcLoadDelta +
      (InstructionStream::kHeaderSize - kHeapObjectTag);
  add(dest, pc, dest);
  sub(dest, dest, Operand(current_instr_code_object_relative_offset));
}

void MacroAssembler::Jump(Register target, Condition cond) { bx(target, cond); }

void MacroAssembler::Jump(intptr_t target, RelocInfo::Mode rmode,
                          Condition cond) {
  mov(pc, Operand(target, rmode), LeaveCC, cond);
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

  // 'code' is always generated ARM code, never THUMB code
  Jump(static_cast<intptr_t>(code.address()), rmode, cond);
}

void MacroAssembler::Jump(const ExternalReference& reference) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Move(scratch, reference);
  Jump(scratch);
}

void MacroAssembler::Call(Register target, Condition cond) {
  // Block constant pool for the call instruction sequence.
  BlockConstPoolScope block_const_pool(this);
  blx(target, cond);
}

void MacroAssembler::Call(Address target, RelocInfo::Mode rmode, Condition cond,
                          TargetAddressStorageMode mode,
                          bool check_constant_pool) {
  // Check if we have to emit the constant pool before we block it.
  if (check_constant_pool) MaybeCheckConstPool();
  // Block constant pool for the call instruction sequence.
  BlockConstPoolScope block_const_pool(this);

  bool old_predictable_code_size = predictable_code_size();
  if (mode == NEVER_INLINE_TARGET_ADDRESS) {
    set_predictable_code_size(true);
  }

  // Use ip directly instead of using UseScratchRegisterScope, as we do not
  // preserve scratch registers across calls.

  // Call sequence on V7 or later may be :
  //  movw  ip, #... @ call address low 16
  //  movt  ip, #... @ call address high 16
  //  blx   ip
  //                      @ return address
  // Or for pre-V7 or values that may be back-patched
  // to avoid ICache flushes:
  //  ldr   ip, [pc, #...] @ call address
  //  blx   ip
  //                      @ return address

  mov(ip, Operand(target, rmode));
  blx(ip, cond);

  if (mode == NEVER_INLINE_TARGET_ADDRESS) {
    set_predictable_code_size(old_predictable_code_size);
  }
}

void MacroAssembler::Call(Handle<Code> code, RelocInfo::Mode rmode,
                          Condition cond, TargetAddressStorageMode mode,
                          bool check_constant_pool) {
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  DCHECK_IMPLIES(options().isolate_independent_code,
                 Builtins::IsIsolateIndependentBuiltin(*code));

  Builtin builtin = Builtin::kNoBuiltinId;
  if (isolate()->builtins()->IsBuiltinHandle(code, &builtin)) {
    CallBuiltin(builtin);
    return;
  }

  // 'code' is always generated ARM code, never THUMB code
  Call(code.address(), rmode, cond, mode);
}

void MacroAssembler::LoadEntryFromBuiltinIndex(Register builtin_index,
                                               Register target) {
  ASM_CODE_COMMENT(this);
  static_assert(kSystemPointerSize == 4);
  static_assert(kSmiShiftSize == 0);
  static_assert(kSmiTagSize == 1);
  static_assert(kSmiTag == 0);

  // The builtin_index register contains the builtin index as a Smi.
  mov(target,
      Operand(builtin_index, LSL, kSystemPointerSizeLog2 - kSmiTagSize));
  add(target, target, Operand(IsolateData::builtin_entry_table_offset()));
  ldr(target, MemOperand(kRootRegister, target));
}

void MacroAssembler::CallBuiltinByIndex(Register builtin_index,
                                        Register target) {
  LoadEntryFromBuiltinIndex(builtin_index, target);
  Call(target);
}

void MacroAssembler::LoadEntryFromBuiltin(Builtin builtin,
                                          Register destination) {
  ASM_CODE_COMMENT(this);
  ldr(destination, EntryFromBuiltinAsOperand(builtin));
}

MemOperand MacroAssembler::EntryFromBuiltinAsOperand(Builtin builtin) {
  ASM_CODE_COMMENT(this);
  DCHECK(root_array_available());
  return MemOperand(kRootRegister,
                    IsolateData::BuiltinEntrySlotOffset(builtin));
}

void MacroAssembler::CallBuiltin(Builtin builtin, Condition cond) {
  ASM_CODE_COMMENT_STRING(this, CommentForOffHeapTrampoline("call", builtin));
  // Use ip directly instead of using UseScratchRegisterScope, as we do not
  // preserve scratch registers across calls.
  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute: {
      mov(ip, Operand(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET));
      Call(ip, cond);
      break;
    }
    case BuiltinCallJumpMode::kPCRelative:
      UNREACHABLE();
    case BuiltinCallJumpMode::kIndirect:
      ldr(ip, EntryFromBuiltinAsOperand(builtin));
      Call(ip, cond);
      break;
    case BuiltinCallJumpMode::kForMksnapshot: {
      if (options().use_pc_relative_calls_and_jumps_for_mksnapshot) {
        Handle<Code> code = isolate()->builtins()->code_handle(builtin);
        int32_t code_target_index = AddCodeTarget(code);
        bl(code_target_index * kInstrSize, cond,
           RelocInfo::RELATIVE_CODE_TARGET);
      } else {
        ldr(ip, EntryFromBuiltinAsOperand(builtin));
        Call(ip, cond);
      }
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
      ldr(ip, EntryFromBuiltinAsOperand(builtin));
      Jump(ip, cond);
      break;
    case BuiltinCallJumpMode::kForMksnapshot: {
      if (options().use_pc_relative_calls_and_jumps_for_mksnapshot) {
        Handle<Code> code = isolate()->builtins()->code_handle(builtin);
        int32_t code_target_index = AddCodeTarget(code);
        b(code_target_index * kInstrSize, cond,
          RelocInfo::RELATIVE_CODE_TARGET);
      } else {
        ldr(ip, EntryFromBuiltinAsOperand(builtin));
        Jump(ip, cond);
      }
      break;
    }
  }
}

void MacroAssembler::LoadCodeInstructionStart(Register destination,
                                              Register code_object,
                                              CodeEntrypointTag tag) {
  ASM_CODE_COMMENT(this);
  ldr(destination, FieldMemOperand(code_object, Code::kInstructionStartOffset));
}

void MacroAssembler::CallCodeObject(Register code_object) {
  ASM_CODE_COMMENT(this);
  LoadCodeInstructionStart(code_object, code_object);
  Call(code_object);
}

void MacroAssembler::JumpCodeObject(Register code_object, JumpMode jump_mode) {
  ASM_CODE_COMMENT(this);
  DCHECK_EQ(JumpMode::kJump, jump_mode);
  LoadCodeInstructionStart(code_object, code_object);
  Jump(code_object);
}

void MacroAssembler::CallJSFunction(Register function_object,
                                    uint16_t argument_count) {
  DCHECK_WITH_MSG(!V8_ENABLE_LEAPTIERING_BOOL,
                  "argument_count is only used with Leaptiering");
  Register code = kJavaScriptCallCodeStartRegister;
  ldr(code, FieldMemOperand(function_object, JSFunction::kCodeOffset));
  CallCodeObject(code);
}

void MacroAssembler::JumpJSFunction(Register function_object,
                                    JumpMode jump_mode) {
  Register code = kJavaScriptCallCodeStartRegister;
  ldr(code, FieldMemOperand(function_object, JSFunction::kCodeOffset));
  JumpCodeObject(code, jump_mode);
}

void MacroAssembler::ResolveWasmCodePointer(Register target) {
#ifdef V8_ENABLE_WASM_CODE_POINTER_TABLE
  ExternalReference global_jump_table =
      ExternalReference::wasm_code_pointer_table();
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Move(scratch, global_jump_table);
  static_assert(sizeof(wasm::WasmCodePointerTableEntry) == 4);
  ldr(target, MemOperand(scratch, target, LSL, 2));
#endif
}

void MacroAssembler::CallWasmCodePointer(Register target,
                                         CallJumpMode call_jump_mode) {
  ResolveWasmCodePointer(target);
  if (call_jump_mode == CallJumpMode::kTailCall) {
    Jump(target);
  } else {
    Call(target);
  }
}

void MacroAssembler::StoreReturnAddressAndCall(Register target) {
  ASM_CODE_COMMENT(this);
  // This generates the final instruction sequence for calls to C functions
  // once an exit frame has been constructed.
  //
  // Note that this assumes the caller code (i.e. the InstructionStream object
  // currently being generated) is immovable or that the callee function cannot
  // trigger GC, since the callee function will return to it.

  // Compute the return address in lr to return to after the jump below. The pc
  // is already at '+ 8' from the current instruction; but return is after three
  // instructions, so add another 4 to pc to get the return address.
  Assembler::BlockConstPoolScope block_const_pool(this);
  add(lr, pc, Operand(4));
  str(lr, MemOperand(sp));
  Call(target);
}

void MacroAssembler::Ret(Condition cond) { bx(lr, cond); }

void MacroAssembler::Drop(int count, Condition cond) {
  if (count > 0) {
    add(sp, sp, Operand(count * kPointerSize), LeaveCC, cond);
  }
}

void MacroAssembler::Drop(Register count, Condition cond) {
  add(sp, sp, Operand(count, LSL, kPointerSizeLog2), LeaveCC, cond);
}

// Enforce alignment of sp.
void MacroAssembler::EnforceStackAlignment() {
  int frame_alignment = ActivationFrameAlignment();
  DCHECK(base::bits::IsPowerOfTwo(frame_alignment));

  uint32_t frame_alignment_mask = ~(static_cast<uint32_t>(frame_alignment) - 1);
  and_(sp, sp, Operand(frame_alignment_mask));
}

void MacroAssembler::TestCodeIsMarkedForDeoptimization(Register code,
                                                       Register scratch) {
  ldr(scratch, FieldMemOperand(code, Code::kFlagsOffset));
  tst(scratch, Operand(1 << Code::kMarkedForDeoptimizationBit));
}

Operand MacroAssembler::ClearedValue() const {
  return Operand(static_cast<int32_t>(i::ClearedValue(isolate()).ptr()));
}

void MacroAssembler::Call(Label* target) { bl(target); }

void MacroAssembler::Push(Handle<HeapObject> handle) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  mov(scratch, Operand(handle));
  push(scratch);
}

void MacroAssembler::Push(Tagged<Smi> smi) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  mov(scratch, Operand(smi));
  push(scratch);
}

void MacroAssembler::Push(Tagged<TaggedIndex> index) {
  // TaggedIndex is the same as Smi for 32 bit archs.
  Push(Smi::FromIntptr(index.value()));
}

void MacroAssembler::PushArray(Register array, Register size, Register scratch,
                               PushArrayOrder order) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register counter = scratch;
  Register tmp = temps.Acquire();
  DCHECK(!AreAliased(array, size, counter, tmp));
  Label loop, entry;
  if (order == PushArrayOrder::kReverse) {
    mov(counter, Operand(0));
    b(&entry);
    bind(&loop);
    ldr(tmp, MemOperand(array, counter, LSL, kSystemPointerSizeLog2));
    push(tmp);
    add(counter, counter, Operand(1));
    bind(&entry);
    cmp(counter, size);
    b(lt, &loop);
  } else {
    mov(counter, size);
    b(&entry);
    bind(&loop);
    ldr(tmp, MemOperand(array, counter, LSL, kSystemPointerSizeLog2));
    push(tmp);
    bind(&entry);
    sub(counter, counter, Operand(1), SetCC);
    b(ge, &loop);
  }
}

void MacroAssembler::Move(Register dst, Tagged<Smi> smi) {
  mov(dst, Operand(smi));
}

void MacroAssembler::Move(Register dst, Handle<HeapObject> value) {
  // TODO(jgruber,v8:8887): Also consider a root-relative load when generating
  // non-isolate-independent code. In many cases it might be cheaper than
  // embedding the relocatable value.
  if (root_array_available_ && options().isolate_independent_code) {
    IndirectLoadConstant(dst, value);
    return;
  }
  mov(dst, Operand(value));
}

void MacroAssembler::Move(Register dst, ExternalReference reference) {
  if (root_array_available()) {
    if (reference.IsIsolateFieldId()) {
      add(dst, kRootRegister, Operand(reference.offset_from_root_register()));
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
    mov(dst, src, LeaveCC, cond);
  }
}

void MacroAssembler::Move(SwVfpRegister dst, SwVfpRegister src,
                          Condition cond) {
  if (dst != src) {
    vmov(dst, src, cond);
  }
}

void MacroAssembler::Move(DwVfpRegister dst, DwVfpRegister src,
                          Condition cond) {
  if (dst != src) {
    vmov(dst, src, cond);
  }
}

void MacroAssembler::Move(QwNeonRegister dst, QwNeonRegister src) {
  if (dst != src) {
    vmov(dst, src);
  }
}

void MacroAssembler::MovePair(Register dst0, Register src0, Register dst1,
                              Register src1) {
  DCHECK_NE(dst0, dst1);
  if (dst0 != src1) {
    Move(dst0, src0);
    Move(dst1, src1);
  } else if (dst1 != src0) {
    // Swap the order of the moves to resolve the overlap.
    Move(dst1, src1);
    Move(dst0, src0);
  } else {
    // Worse case scenario, this is a swap.
    Swap(dst0, src0);
  }
}

void MacroAssembler::Swap(Register srcdst0, Register srcdst1) {
  DCHECK(srcdst0 != srcdst1);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  mov(scratch, srcdst0);
  mov(srcdst0, srcdst1);
  mov(srcdst1, scratch);
}

void MacroAssembler::Swap(DwVfpRegister srcdst0, DwVfpRegister srcdst1) {
  DCHECK(srcdst0 != srcdst1);
  DCHECK(VfpRegisterIsAvailable(srcdst0));
  DCHECK(VfpRegisterIsAvailable(srcdst1));

  if (CpuFeatures::IsSupported(NEON)) {
    vswp(srcdst0, srcdst1);
  } else {
    UseScratchRegisterScope temps(this);
    DwVfpRegister scratch = temps.AcquireD();
    vmov(scratch, srcdst0);
    vmov(srcdst0, srcdst1);
    vmov(srcdst1, scratch);
  }
}

void MacroAssembler::Swap(QwNeonRegister srcdst0, QwNeonRegister srcdst1) {
  DCHECK(srcdst0 != srcdst1);
  vswp(srcdst0, srcdst1);
}

void MacroAssembler::Mls(Register dst, Register src1, Register src2,
                         Register srcA, Condition cond) {
  if (CpuFeatures::IsSupported(ARMv7)) {
    CpuFeatureScope scope(this, ARMv7);
    mls(dst, src1, src2, srcA, cond);
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(srcA != scratch);
    mul(scratch, src1, src2, LeaveCC, cond);
    sub(dst, srcA, scratch, LeaveCC, cond);
  }
}

void MacroAssembler::And(Register dst, Register src1, const Operand& src2,
                         Condition cond) {
  if (!src2.IsRegister() && !src2.MustOutputRelocInfo(this) &&
      src2.immediate() == 0) {
    mov(dst, Operand::Zero(), LeaveCC, cond);
  } else if (!(src2.InstructionsRequired(this) == 1) &&
             !src2.MustOutputRelocInfo(this) &&
             CpuFeatures::IsSupported(ARMv7) &&
             base::bits::IsPowerOfTwo(src2.immediate() + 1)) {
    CpuFeatureScope scope(this, ARMv7);
    ubfx(dst, src1, 0,
         base::bits::WhichPowerOfTwo(static_cast<uint32_t>(src2.immediate()) +
                                     1),
         cond);
  } else {
    and_(dst, src1, src2, LeaveCC, cond);
  }
}

void MacroAssembler::Ubfx(Register dst, Register src1, int lsb, int width,
                          Condition cond) {
  DCHECK_LT(lsb, 32);
  if (!CpuFeatures::IsSupported(ARMv7) || predictable_code_size()) {
    int mask = (1u << (width + lsb)) - 1u - ((1u << lsb) - 1u);
    and_(dst, src1, Operand(mask), LeaveCC, cond);
    if (lsb != 0) {
      mov(dst, Operand(dst, LSR, lsb), LeaveCC, cond);
    }
  } else {
    CpuFeatureScope scope(this, ARMv7);
    ubfx(dst, src1, lsb, width, cond);
  }
}

void MacroAssembler::Sbfx(Register dst, Register src1, int lsb, int width,
                          Condition cond) {
  DCHECK_LT(lsb, 32);
  if (!CpuFeatures::IsSupported(ARMv7) || predictable_code_size()) {
    int mask = (1 << (width + lsb)) - 1 - ((1 << lsb) - 1);
    and_(dst, src1, Operand(mask), LeaveCC, cond);
    int shift_up = 32 - lsb - width;
    int shift_down = lsb + shift_up;
    if (shift_up != 0) {
      mov(dst, Operand(dst, LSL, shift_up), LeaveCC, cond);
    }
    if (shift_down != 0) {
      mov(dst, Operand(dst, ASR, shift_down), LeaveCC, cond);
    }
  } else {
    CpuFeatureScope scope(this, ARMv7);
    sbfx(dst, src1, lsb, width, cond);
  }
}

void MacroAssembler::Bfc(Register dst, Register src, int lsb, int width,
                         Condition cond) {
  DCHECK_LT(lsb, 32);
  if (!CpuFeatures::IsSupported(ARMv7) || predictable_code_size()) {
    int mask = (1 << (width + lsb)) - 1 - ((1 << lsb) - 1);
    bic(dst, src, Operand(mask));
  } else {
    CpuFeatureScope scope(this, ARMv7);
    Move(dst, src, cond);
    bfc(dst, lsb, width, cond);
  }
}

void MacroAssembler::LoadRoot(Register destination, RootIndex index,
                              Condition cond) {
  ldr(destination,
      MemOperand(kRootRegister, RootRegisterOffsetForRootIndex(index)), cond);
}

void MacroAssembler::RecordWriteField(Register object, int offset,
                                      Register value,
                                      LinkRegisterStatus lr_status,
                                      SaveFPRegsMode save_fp,
                                      SmiCheck smi_check) {
  ASM_CODE_COMMENT(this);
  // First, check if a write barrier is even needed. The tests below
  // catch stores of Smis.
  Label done;

  // Skip barrier if writing a smi.
  if (smi_check == SmiCheck::kInline) {
    JumpIfSmi(value, &done);
  }

  // Although the object register is tagged, the offset is relative to the start
  // of the object, so so offset must be a multiple of kPointerSize.
  DCHECK(IsAligned(offset, kPointerSize));

  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT_STRING(this, "Verify slot_address");
    Label ok;
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(!AreAliased(object, value, scratch));
    add(scratch, object, Operand(offset - kHeapObjectTag));
    tst(scratch, Operand(kPointerSize - 1));
    b(eq, &ok);
    stop();
    bind(&ok);
  }

  RecordWrite(object, Operand(offset - kHeapObjectTag), value, lr_status,
              save_fp, SmiCheck::kOmit);

  bind(&done);
}

void MacroAssembler::Zero(const MemOperand& dest) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();

  mov(scratch, Operand::Zero());
  str(scratch, dest);
}
void MacroAssembler::Zero(const MemOperand& dest1, const MemOperand& dest2) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();

  mov(scratch, Operand::Zero());
  str(scratch, dest1);
  str(scratch, dest2);
}

void MacroAssembler::MaybeSaveRegisters(RegList registers) {
  if (registers.is_empty()) return;
  ASM_CODE_COMMENT(this);
  stm(db_w, sp, registers);
}

void MacroAssembler::MaybeRestoreRegisters(RegList registers) {
  if (registers.is_empty()) return;
  ASM_CODE_COMMENT(this);
  ldm(ia_w, sp, registers);
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
  ASM_CODE_COMMENT(this);
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

void MacroAssembler::MoveObjectAndSlot(Register dst_object, Register dst_slot,
                                       Register object, Operand offset) {
  DCHECK_NE(dst_object, dst_slot);
  DCHECK(offset.IsRegister() || offset.IsImmediate());
  // If `offset` is a register, it cannot overlap with `object`.
  DCHECK_IMPLIES(offset.IsRegister(), offset.rm() != object);

  // If the slot register does not overlap with the object register, we can
  // overwrite it.
  if (dst_slot != object) {
    add(dst_slot, object, offset);
    Move(dst_object, object);
    return;
  }

  DCHECK_EQ(dst_slot, object);

  // If the destination object register does not overlap with the offset
  // register, we can overwrite it.
  if (!offset.IsRegister() || (offset.rm() != dst_object)) {
    Move(dst_object, dst_slot);
    add(dst_slot, dst_slot, offset);
    return;
  }

  DCHECK_EQ(dst_object, offset.rm());

  // We only have `dst_slot` and `dst_object` left as distinct registers so we
  // have to swap them. We write this as a add+sub sequence to avoid using a
  // scratch register.
  add(dst_slot, dst_slot, dst_object);
  sub(dst_object, dst_slot, dst_object);
}

// The register 'object' contains a heap object pointer. The heap object tag is
// shifted away. A scratch register also needs to be available.
void MacroAssembler::RecordWrite(Register object, Operand offset,
                                 Register value, LinkRegisterStatus lr_status,
                                 SaveFPRegsMode fp_mode, SmiCheck smi_check) {
  DCHECK(!AreAliased(object, value));
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT_STRING(this, "Verify slot_address");
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(!AreAliased(object, value, scratch));
    add(scratch, object, offset);
    ldr(scratch, MemOperand(scratch));
    cmp(scratch, value);
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

  CheckPageFlag(value, MemoryChunk::kPointersToHereAreInterestingMask, eq,
                &done);
  CheckPageFlag(object, MemoryChunk::kPointersFromHereAreInterestingMask, eq,
                &done);

  // Record the actual write.
  if (lr_status == kLRHasNotBeenSaved) {
    push(lr);
  }

  Register slot_address = WriteBarrierDescriptor::SlotAddressRegister();
  DCHECK(!AreAliased(object, value, slot_address));
  DCHECK(!offset.IsRegister());
  add(slot_address, object, offset);
  CallRecordWriteStub(object, slot_address, fp_mode);
  if (lr_status == kLRHasNotBeenSaved) {
    pop(lr);
  }

  if (v8_flags.debug_code) Move(slot_address, Operand(kZapValue));

  bind(&done);
}

void MacroAssembler::PushCommonFrame(Register marker_reg) {
  ASM_CODE_COMMENT(this);
  if (marker_reg.is_valid()) {
    if (marker_reg.code() > fp.code()) {
      stm(db_w, sp, {fp, lr});
      mov(fp, Operand(sp));
      Push(marker_reg);
    } else {
      stm(db_w, sp, {marker_reg, fp, lr});
      add(fp, sp, Operand(kPointerSize));
    }
  } else {
    stm(db_w, sp, {fp, lr});
    mov(fp, sp);
  }
}

void MacroAssembler::PushStandardFrame(Register function_reg) {
  ASM_CODE_COMMENT(this);
  DCHECK(!function_reg.is_valid() || function_reg.code() < cp.code());
  stm(db_w, sp, {function_reg, cp, fp, lr});
  int offset = -StandardFrameConstants::kContextOffset;
  offset += function_reg.is_valid() ? kPointerSize : 0;
  add(fp, sp, Operand(offset));
  Push(kJavaScriptCallArgCountRegister);
}

void MacroAssembler::VFPCanonicalizeNaN(const DwVfpRegister dst,
                                        const DwVfpRegister src,
                                        const Condition cond) {
  // Subtracting 0.0 preserves all inputs except for signalling NaNs, which
  // become quiet NaNs. We use vsub rather than vadd because vsub preserves -0.0
  // inputs: -0.0 + 0.0 = 0.0, but -0.0 - 0.0 = -0.0.
  vsub(dst, src, kDoubleRegZero, cond);
}

void MacroAssembler::VFPCompareAndSetFlags(const SwVfpRegister src1,
                                           const SwVfpRegister src2,
                                           const Condition cond) {
  // Compare and move FPSCR flags to the normal condition flags.
  VFPCompareAndLoadFlags(src1, src2, pc, cond);
}

void MacroAssembler::VFPCompareAndSetFlags(const SwVfpRegister src1,
                                           const float src2,
                                           const Condition cond) {
  // Compare and move FPSCR flags to the normal condition flags.
  VFPCompareAndLoadFlags(src1, src2, pc, cond);
}

void MacroAssembler::VFPCompareAndSetFlags(const DwVfpRegister src1,
                                           const DwVfpRegister src2,
                                           const Condition cond) {
  // Compare and move FPSCR flags to the normal condition flags.
  VFPCompareAndLoadFlags(src1, src2, pc, cond);
}

void MacroAssembler::VFPCompareAndSetFlags(const DwVfpRegister src1,
                                           const double src2,
                                           const Condition cond) {
  // Compare and move FPSCR flags to the normal condition flags.
  VFPCompareAndLoadFlags(src1, src2, pc, cond);
}

void MacroAssembler::VFPCompareAndLoadFlags(const SwVfpRegister src1,
                                            const SwVfpRegister src2,
                                            const Register fpscr_flags,
                                            const Condition cond) {
  // Compare and load FPSCR.
  vcmp(src1, src2, cond);
  vmrs(fpscr_flags, cond);
}

void MacroAssembler::VFPCompareAndLoadFlags(const SwVfpRegister src1,
                                            const float src2,
                                            const Register fpscr_flags,
                                            const Condition cond) {
  // Compare and load FPSCR.
  vcmp(src1, src2, cond);
  vmrs(fpscr_flags, cond);
}

void MacroAssembler::VFPCompareAndLoadFlags(const DwVfpRegister src1,
                                            const DwVfpRegister src2,
                                            const Register fpscr_flags,
                                            const Condition cond) {
  // Compare and load FPSCR.
  vcmp(src1, src2, cond);
  vmrs(fpscr_flags, cond);
}

void MacroAssembler::VFPCompareAndLoadFlags(const DwVfpRegister src1,
                                            const double src2,
                                            const Register fpscr_flags,
                                            const Condition cond) {
  // Compare and load FPSCR.
  vcmp(src1, src2, cond);
  vmrs(fpscr_flags, cond);
}

void MacroAssembler::VmovHigh(Register dst, DwVfpRegister src) {
  if (src.code() < 16) {
    const LowDwVfpRegister loc = LowDwVfpRegister::from_code(src.code());
    vmov(dst, loc.high());
  } else {
    vmov(NeonS32, dst, src, 1);
  }
}

void MacroAssembler::VmovHigh(DwVfpRegister dst, Register src) {
  if (dst.code() < 16) {
    const LowDwVfpRegister loc = LowDwVfpRegister::from_code(dst.code());
    vmov(loc.high(), src);
  } else {
    vmov(NeonS32, dst, 1, src);
  }
}

void MacroAssembler::VmovLow(Register dst, DwVfpRegister src) {
  if (src.code() < 16) {
    const LowDwVfpRegister loc = LowDwVfpRegister::from_code(src.code());
    vmov(dst, loc.low());
  } else {
    vmov(NeonS32, dst, src, 0);
  }
}

void MacroAssembler::VmovLow(DwVfpRegister dst, Register src) {
  if (dst.code() < 16) {
    const LowDwVfpRegister loc = LowDwVfpRegister::from_code(dst.code());
    vmov(loc.low(), src);
  } else {
    vmov(NeonS32, dst, 0, src);
  }
}

void MacroAssembler::VmovExtended(Register dst, int src_code) {
  DCHECK_LE(SwVfpRegister::kNumRegisters, src_code);
  DCHECK_GT(SwVfpRegister::kNumRegisters * 2, src_code);
  if (src_code & 0x1) {
    VmovHigh(dst, DwVfpRegister::from_code(src_code / 2));
  } else {
    VmovLow(dst, DwVfpRegister::from_code(src_code / 2));
  }
}

void MacroAssembler::VmovExtended(int dst_code, Register src) {
  DCHECK_LE(SwVfpRegister::kNumRegisters, dst_code);
  DCHECK_GT(SwVfpRegister::kNumRegisters * 2, dst_code);
  if (dst_code & 0x1) {
    VmovHigh(DwVfpRegister::from_code(dst_code / 2), src);
  } else {
    VmovLow(DwVfpRegister::from_code(dst_code / 2), src);
  }
}

void MacroAssembler::VmovExtended(int dst_code, int src_code) {
  if (src_code == dst_code) return;

  if (src_code < SwVfpRegister::kNumRegisters &&
      dst_code < SwVfpRegister::kNumRegisters) {
    // src and dst are both s-registers.
    vmov(SwVfpRegister::from_code(dst_code),
         SwVfpRegister::from_code(src_code));
    return;
  }
  DwVfpRegister dst_d_reg = DwVfpRegister::from_code(dst_code / 2);
  DwVfpRegister src_d_reg = DwVfpRegister::from_code(src_code / 2);
  int dst_offset = dst_code & 1;
  int src_offset = src_code & 1;
  if (CpuFeatures::IsSupported(NEON)) {
    UseScratchRegisterScope temps(this);
    DwVfpRegister scratch = temps.AcquireD();
    // On Neon we can shift and insert from d-registers.
    if (src_offset == dst_offset) {
      // Offsets are the same, use vdup to copy the source to the opposite lane.
      vdup(Neon32, scratch, src_d_reg, src_offset);
      // Here we are extending the lifetime of scratch.
      src_d_reg = scratch;
      src_offset = dst_offset ^ 1;
    }
    if (dst_offset) {
      if (dst_d_reg == src_d_reg) {
        vdup(Neon32, dst_d_reg, src_d_reg, 0);
      } else {
        vsli(Neon64, dst_d_reg, src_d_reg, 32);
      }
    } else {
      if (dst_d_reg == src_d_reg) {
        vdup(Neon32, dst_d_reg, src_d_reg, 1);
      } else {
        vsri(Neon64, dst_d_reg, src_d_reg, 32);
      }
    }
    return;
  }

  // Without Neon, use the scratch registers to move src and/or dst into
  // s-registers.
  UseScratchRegisterScope temps(this);
  LowDwVfpRegister d_scratch = temps.AcquireLowD();
  LowDwVfpRegister d_scratch2 = temps.AcquireLowD();
  int s_scratch_code = d_scratch.low().code();
  int s_scratch_code2 = d_scratch2.low().code();
  if (src_code < SwVfpRegister::kNumRegisters) {
    // src is an s-register, dst is not.
    vmov(d_scratch, dst_d_reg);
    vmov(SwVfpRegister::from_code(s_scratch_code + dst_offset),
         SwVfpRegister::from_code(src_code));
    vmov(dst_d_reg, d_scratch);
  } else if (dst_code < SwVfpRegister::kNumRegisters) {
    // dst is an s-register, src is not.
    vmov(d_scratch, src_d_reg);
    vmov(SwVfpRegister::from_code(dst_code),
         SwVfpRegister::from_code(s_scratch_code + src_offset));
  } else {
    // Neither src or dst are s-registers. Both scratch double registers are
    // available when there are 32 VFP registers.
    vmov(d_scratch, src_d_reg);
    vmov(d_scratch2, dst_d_reg);
    vmov(SwVfpRegister::from_code(s_scratch_code + dst_offset),
         SwVfpRegister::from_code(s_scratch_code2 + src_offset));
    vmov(dst_d_reg, d_scratch2);
  }
}

void MacroAssembler::VmovExtended(int dst_code, const MemOperand& src) {
  if (dst_code < SwVfpRegister::kNumRegisters) {
    vldr(SwVfpRegister::from_code(dst_code), src);
  } else {
    UseScratchRegisterScope temps(this);
    LowDwVfpRegister scratch = temps.AcquireLowD();
    // TODO(bbudge) If Neon supported, use load single lane form of vld1.
    int dst_s_code = scratch.low().code() + (dst_code & 1);
    vmov(scratch, DwVfpRegister::from_code(dst_code / 2));
    vldr(SwVfpRegister::from_code(dst_s_code), src);
    vmov(DwVfpRegister::from_code(dst_code / 2), scratch);
  }
}

void MacroAssembler::VmovExtended(const MemOperand& dst, int src_code) {
  if (src_code < SwVfpRegister::kNumRegisters) {
    vstr(SwVfpRegister::from_code(src_code), dst);
  } else {
    // TODO(bbudge) If Neon supported, use store single lane form of vst1.
    UseScratchRegisterScope temps(this);
    LowDwVfpRegister scratch = temps.AcquireLowD();
    int src_s_code = scratch.low().code() + (src_code & 1);
    vmov(scratch, DwVfpRegister::from_code(src_code / 2));
    vstr(SwVfpRegister::from_code(src_s_code), dst);
  }
}

void MacroAssembler::ExtractLane(Register dst, QwNeonRegister src,
                                 NeonDataType dt, int lane) {
  int size = NeonSz(dt);  // 0, 1, 2
  int byte = lane << size;
  int double_word = byte >> kDoubleSizeLog2;
  int double_byte = byte & (kDoubleSize - 1);
  int double_lane = double_byte >> size;
  DwVfpRegister double_source =
      DwVfpRegister::from_code(src.code() * 2 + double_word);
  vmov(dt, dst, double_source, double_lane);
}

void MacroAssembler::ExtractLane(Register dst, DwVfpRegister src,
                                 NeonDataType dt, int lane) {
  int size = NeonSz(dt);  // 0, 1, 2
  int byte = lane << size;
  int double_byte = byte & (kDoubleSize - 1);
  int double_lane = double_byte >> size;
  vmov(dt, dst, src, double_lane);
}

void MacroAssembler::ExtractLane(SwVfpRegister dst, QwNeonRegister src,
                                 int lane) {
  int s_code = src.code() * 4 + lane;
  VmovExtended(dst.code(), s_code);
}

void MacroAssembler::ExtractLane(DwVfpRegister dst, QwNeonRegister src,
                                 int lane) {
  DwVfpRegister double_dst = DwVfpRegister::from_code(src.code() * 2 + lane);
  vmov(dst, double_dst);
}

void MacroAssembler::ReplaceLane(QwNeonRegister dst, QwNeonRegister src,
                                 Register src_lane, NeonDataType dt, int lane) {
  Move(dst, src);
  int size = NeonSz(dt);  // 0, 1, 2
  int byte = lane << size;
  int double_word = byte >> kDoubleSizeLog2;
  int double_byte = byte & (kDoubleSize - 1);
  int double_lane = double_byte >> size;
  DwVfpRegister double_dst =
      DwVfpRegister::from_code(dst.code() * 2 + double_word);
  vmov(dt, double_dst, double_lane, src_lane);
}

void MacroAssembler::ReplaceLane(QwNeonRegister dst, QwNeonRegister src,
                                 SwVfpRegister src_lane, int lane) {
  Move(dst, src);
  int s_code = dst.code() * 4 + lane;
  VmovExtended(s_code, src_lane.code());
}

void MacroAssembler::ReplaceLane(QwNeonRegister dst, QwNeonRegister src,
                                 DwVfpRegister src_lane, int lane) {
  Move(dst, src);
  DwVfpRegister double_dst = DwVfpRegister::from_code(dst.code() * 2 + lane);
  vmov(double_dst, src_lane);
}

void MacroAssembler::LoadLane(NeonSize sz, NeonListOperand dst_list,
                              uint8_t lane, NeonMemOperand src) {
  if (sz == Neon64) {
    // vld1s is not valid for Neon64.
    vld1(Neon64, dst_list, src);
  } else {
    vld1s(sz, dst_list, lane, src);
  }
}

void MacroAssembler::StoreLane(NeonSize sz, NeonListOperand src_list,
                               uint8_t lane, NeonMemOperand dst) {
  if (sz == Neon64) {
    // vst1s is not valid for Neon64.
    vst1(Neon64, src_list, dst);
  } else {
    vst1s(sz, src_list, lane, dst);
  }
}

void MacroAssembler::LslPair(Register dst_low, Register dst_high,
                             Register src_low, Register src_high,
                             Register shift) {
  DCHECK(!AreAliased(dst_high, src_low));
  DCHECK(!AreAliased(dst_high, shift));
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();

  Label less_than_32;
  Label done;
  rsb(scratch, shift, Operand(32), SetCC);
  b(gt, &less_than_32);
  // If shift >= 32
  and_(scratch, shift, Operand(0x1F));
  lsl(dst_high, src_low, Operand(scratch));
  mov(dst_low, Operand(0));
  jmp(&done);
  bind(&less_than_32);
  // If shift < 32
  lsl(dst_high, src_high, Operand(shift));
  orr(dst_high, dst_high, Operand(src_low, LSR, scratch));
  lsl(dst_low, src_low, Operand(shift));
  bind(&done);
}

void MacroAssembler::LslPair(Register dst_low, Register dst_high,
                             Register src_low, Register src_high,
                             uint32_t shift) {
  DCHECK_GE(63, shift);
  DCHECK(!AreAliased(dst_high, src_low));

  if (shift == 0) {
    Move(dst_high, src_high);
    Move(dst_low, src_low);
  } else if (shift == 32) {
    Move(dst_high, src_low);
    Move(dst_low, Operand(0));
  } else if (shift >= 32) {
    shift &= 0x1F;
    lsl(dst_high, src_low, Operand(shift));
    mov(dst_low, Operand(0));
  } else {
    lsl(dst_high, src_high, Operand(shift));
    orr(dst_high, dst_high, Operand(src_low, LSR, 32 - shift));
    lsl(dst_low, src_low, Operand(shift));
  }
}

void MacroAssembler::LsrPair(Register dst_low, Register dst_high,
                             Register src_low, Register src_high,
                             Register shift) {
  DCHECK(!AreAliased(dst_low, src_high));
  DCHECK(!AreAliased(dst_low, shift));
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();

  Label less_than_32;
  Label done;
  rsb(scratch, shift, Operand(32), SetCC);
  b(gt, &less_than_32);
  // If shift >= 32
  and_(scratch, shift, Operand(0x1F));
  lsr(dst_low, src_high, Operand(scratch));
  mov(dst_high, Operand(0));
  jmp(&done);
  bind(&less_than_32);
  // If shift < 32

  lsr(dst_low, src_low, Operand(shift));
  orr(dst_low, dst_low, Operand(src_high, LSL, scratch));
  lsr(dst_high, src_high, Operand(shift));
  bind(&done);
}

void MacroAssembler::LsrPair(Register dst_low, Register dst_high,
                             Register src_low, Register src_high,
                             uint32_t shift) {
  DCHECK_GE(63, shift);
  DCHECK(!AreAliased(dst_low, src_high));

  if (shift == 32) {
    mov(dst_low, src_high);
    mov(dst_high, Operand(0));
  } else if (shift > 32) {
    shift &= 0x1F;
    lsr(dst_low, src_high, Operand(shift));
    mov(dst_high, Operand(0));
  } else if (shift == 0) {
    Move(dst_low, src_low);
    Move(dst_high, src_high);
  } else {
    lsr(dst_low, src_low, Operand(shift));
    orr(dst_low, dst_low, Operand(src_high, LSL, 32 - shift));
    lsr(dst_high, src_high, Operand(shift));
  }
}

void MacroAssembler::AsrPair(Register dst_low, Register dst_high,
                             Register src_low, Register src_high,
                             Register shift) {
  DCHECK(!AreAliased(dst_low, src_high));
  DCHECK(!AreAliased(dst_low, shift));
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();

  Label less_than_32;
  Label done;
  rsb(scratch, shift, Operand(32), SetCC);
  b(gt, &less_than_32);
  // If shift >= 32
  and_(scratch, shift, Operand(0x1F));
  asr(dst_low, src_high, Operand(scratch));
  asr(dst_high, src_high, Operand(31));
  jmp(&done);
  bind(&less_than_32);
  // If shift < 32
  lsr(dst_low, src_low, Operand(shift));
  orr(dst_low, dst_low, Operand(src_high, LSL, scratch));
  asr(dst_high, src_high, Operand(shift));
  bind(&done);
}

void MacroAssembler::AsrPair(Register dst_low, Register dst_high,
                             Register src_low, Register src_high,
                             uint32_t shift) {
  DCHECK_GE(63, shift);
  DCHECK(!AreAliased(dst_low, src_high));

  if (shift == 32) {
    mov(dst_low, src_high);
    asr(dst_high, src_high, Operand(31));
  } else if (shift > 32) {
    shift &= 0x1F;
    asr(dst_low, src_high, Operand(shift));
    asr(dst_high, src_high, Operand(31));
  } else if (shift == 0) {
    Move(dst_low, src_low);
    Move(dst_high, src_high);
  } else {
    lsr(dst_low, src_low, Operand(shift));
    orr(dst_low, dst_low, Operand(src_high, LSL, 32 - shift));
    asr(dst_high, src_high, Operand(shift));
  }
}

void MacroAssembler::StubPrologue(StackFrame::Type type) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  mov(scratch, Operand(StackFrame::TypeToMarker(type)));
  PushCommonFrame(scratch);
}

void MacroAssembler::Prologue() { PushStandardFrame(r1); }

void MacroAssembler::DropArguments(Register count) {
  add(sp, sp, Operand(count, LSL, kPointerSizeLog2), LeaveCC);
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
  // r0-r3: preserved
  UseScratchRegisterScope temps(this);
  Register scratch = no_reg;
  if (!StackFrame::IsJavaScript(type)) {
    scratch = temps.Acquire();
    mov(scratch, Operand(StackFrame::TypeToMarker(type)));
  }
  PushCommonFrame(scratch);
#if V8_ENABLE_WEBASSEMBLY
  if (type == StackFrame::WASM) Push(kWasmImplicitArgRegister);
#endif  // V8_ENABLE_WEBASSEMBLY
}

int MacroAssembler::LeaveFrame(StackFrame::Type type) {
  ASM_CODE_COMMENT(this);
  // r0: preserved
  // r1: preserved
  // r2: preserved

  // Drop the execution stack down to the frame pointer and restore
  // the caller frame pointer and return address.
  mov(sp, fp);
  int frame_ends = pc_offset();
  ldm(ia_w, sp, {fp, lr});
  return frame_ends;
}

#ifdef V8_OS_WIN
void MacroAssembler::AllocateStackSpace(Register bytes_scratch) {
  // "Functions that allocate 4 KB or more on the stack must ensure that each
  // page prior to the final page is touched in order." Source:
  // https://docs.microsoft.com/en-us/cpp/build/overview-of-arm-abi-conventions?view=vs-2019#stack
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  DwVfpRegister scratch = temps.AcquireD();
  Label check_offset;
  Label touch_next_page;
  jmp(&check_offset);
  bind(&touch_next_page);
  sub(sp, sp, Operand(kStackPageSize));
  // Just to touch the page, before we increment further.
  vldr(scratch, MemOperand(sp));
  sub(bytes_scratch, bytes_scratch, Operand(kStackPageSize));

  bind(&check_offset);
  cmp(bytes_scratch, Operand(kStackPageSize));
  b(gt, &touch_next_page);

  sub(sp, sp, bytes_scratch);
}

void MacroAssembler::AllocateStackSpace(int bytes) {
  ASM_CODE_COMMENT(this);
  DCHECK_GE(bytes, 0);
  UseScratchRegisterScope temps(this);
  DwVfpRegister scratch = no_dreg;
  while (bytes > kStackPageSize) {
    if (scratch == no_dreg) {
      scratch = temps.AcquireD();
    }
    sub(sp, sp, Operand(kStackPageSize));
    vldr(scratch, MemOperand(sp));
    bytes -= kStackPageSize;
  }
  if (bytes == 0) return;
  sub(sp, sp, Operand(bytes));
}
#endif

void MacroAssembler::EnterExitFrame(Register scratch, int stack_space,
                                    StackFrame::Type frame_type) {
  ASM_CODE_COMMENT(this);
  DCHECK(frame_type == StackFrame::EXIT ||
         frame_type == StackFrame::BUILTIN_EXIT ||
         frame_type == StackFrame::API_ACCESSOR_EXIT ||
         frame_type == StackFrame::API_CALLBACK_EXIT);

  using ER = ExternalReference;

  // Set up the frame structure on the stack.
  DCHECK_EQ(2 * kPointerSize, ExitFrameConstants::kCallerSPDisplacement);
  DCHECK_EQ(1 * kPointerSize, ExitFrameConstants::kCallerPCOffset);
  DCHECK_EQ(0 * kPointerSize, ExitFrameConstants::kCallerFPOffset);
  mov(scratch, Operand(StackFrame::TypeToMarker(frame_type)));
  PushCommonFrame(scratch);
  // Reserve room for saved entry sp.
  sub(sp, fp, Operand(ExitFrameConstants::kFixedFrameSizeFromFp));
  if (v8_flags.debug_code) {
    mov(scratch, Operand::Zero());
    str(scratch, MemOperand(fp, ExitFrameConstants::kSPOffset));
  }

  // Save the frame pointer and the context in top.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, isolate());
  str(fp, ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  ER context_address = ER::Create(IsolateAddressId::kContextAddress, isolate());
  str(cp, ExternalReferenceAsOperand(context_address, no_reg));

  // Reserve place for the return address and stack space and align the frame
  // preparing for calling the runtime function.
  AllocateStackSpace((stack_space + 1) * kPointerSize);
  EnforceStackAlignment();

  // Set the exit frame sp value to point just before the return address
  // location.
  add(scratch, sp, Operand(kPointerSize));
  str(scratch, MemOperand(fp, ExitFrameConstants::kSPOffset));
}

int MacroAssembler::ActivationFrameAlignment() {
#if V8_HOST_ARCH_ARM
  // Running on the real platform. Use the alignment as mandated by the local
  // environment.
  // Note: This will break if we ever start generating snapshots on one ARM
  // platform for another ARM platform with a different alignment.
  return base::OS::ActivationFrameAlignment();
#else   // V8_HOST_ARCH_ARM
  // If we are using the simulator then we should always align to the expected
  // alignment. As the simulator is used to generate snapshots we do not know
  // if the target platform will need alignment, so this is controlled from a
  // flag.
  return v8_flags.sim_stack_alignment;
#endif  // V8_HOST_ARCH_ARM
}

void MacroAssembler::LeaveExitFrame(Register scratch) {
  ASM_CODE_COMMENT(this);
  ConstantPoolUnavailableScope constant_pool_unavailable(this);

  using ER = ExternalReference;

  // Restore current context from top and clear it in debug mode.
  ER context_address = ER::Create(IsolateAddressId::kContextAddress, isolate());
  ldr(cp, ExternalReferenceAsOperand(context_address, no_reg));
#ifdef DEBUG
  mov(scratch, Operand(Context::kInvalidContext));
  str(scratch, ExternalReferenceAsOperand(context_address, no_reg));
#endif

  // Clear the top frame.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, isolate());
  mov(scratch, Operand::Zero());
  str(scratch, ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  // Tear down the exit frame, pop the arguments, and return.
  mov(sp, Operand(fp));
  ldm(ia_w, sp, {fp, lr});
}

void MacroAssembler::MovFromFloatResult(const DwVfpRegister dst) {
  if (use_eabi_hardfloat()) {
    Move(dst, d0);
  } else {
    vmov(dst, r0, r1);
  }
}

// On ARM this is just a synonym to make the purpose clear.
void MacroAssembler::MovFromFloatParameter(DwVfpRegister dst) {
  MovFromFloatResult(dst);
}

void MacroAssembler::LoadStackLimit(Register destination, StackLimitKind kind) {
  ASM_CODE_COMMENT(this);
  DCHECK(root_array_available());
  intptr_t offset = kind == StackLimitKind::kRealStackLimit
                        ? IsolateData::real_jslimit_offset()
                        : IsolateData::jslimit_offset();
  CHECK(is_int32(offset));
  ldr(destination, MemOperand(kRootRegister, offset));
}

void MacroAssembler::StackOverflowCheck(Register num_args, Register scratch,
                                        Label* stack_overflow) {
  ASM_CODE_COMMENT(this);
  // Check the stack for overflow. We are not trying to catch
  // interruptions (e.g. debug break and preemption) here, so the "real stack
  // limit" is checked.
  LoadStackLimit(scratch, StackLimitKind::kRealStackLimit);
  // Make scratch the space we have left. The stack might already be overflowed
  // here which will cause scratch to become negative.
  sub(scratch, sp, scratch);
  // Check if the arguments will overflow the stack.
  cmp(scratch, Operand(num_args, LSL, kPointerSizeLog2));
  b(le, stack_overflow);  // Signed comparison.
}

void MacroAssembler::InvokePrologue(Register expected_parameter_count,
                                    Register actual_parameter_count,
                                    Label* done, InvokeType type) {
  ASM_CODE_COMMENT(this);
  Label regular_invoke;
  //  r0: actual arguments count
  //  r1: function (passed through to callee)
  //  r2: expected arguments count
  DCHECK_EQ(actual_parameter_count, r0);
  DCHECK_EQ(expected_parameter_count, r2);

  // If overapplication or if the actual argument count is equal to the
  // formal parameter count, no need to push extra undefined values.
  sub(expected_parameter_count, expected_parameter_count,
      actual_parameter_count, SetCC);
  b(le, &regular_invoke);

  Label stack_overflow;
  Register scratch = r4;
  StackOverflowCheck(expected_parameter_count, scratch, &stack_overflow);

  // Underapplication. Move the arguments already in the stack, including the
  // receiver and the return address.
  {
    Label copy, check;
    Register num = r5, src = r6, dest = r9;  // r7 and r8 are context and root.
    mov(src, sp);
    // Update stack pointer.
    lsl(scratch, expected_parameter_count, Operand(kSystemPointerSizeLog2));
    AllocateStackSpace(scratch);
    mov(dest, sp);
    mov(num, actual_parameter_count);
    b(&check);
    bind(&copy);
    ldr(scratch, MemOperand(src, kSystemPointerSize, PostIndex));
    str(scratch, MemOperand(dest, kSystemPointerSize, PostIndex));
    sub(num, num, Operand(1), SetCC);
    bind(&check);
    b(gt, &copy);
  }

  // Fill remaining expected arguments with undefined values.
  LoadRoot(scratch, RootIndex::kUndefinedValue);
  {
    Label loop;
    bind(&loop);
    str(scratch, MemOperand(r9, kSystemPointerSize, PostIndex));
    sub(expected_parameter_count, expected_parameter_count, Operand(1), SetCC);
    b(gt, &loop);
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

void MacroAssembler::CallDebugOnFunctionCall(Register fun, Register new_target,
                                             Register expected_parameter_count,
                                             Register actual_parameter_count) {
  ASM_CODE_COMMENT(this);
  // Load receiver to pass it later to DebugOnFunctionCall hook.
  ldr(r4, ReceiverOperand());
  FrameScope frame(
      this, has_frame() ? StackFrame::NO_FRAME_TYPE : StackFrame::INTERNAL);

  SmiTag(expected_parameter_count);
  Push(expected_parameter_count);

  SmiTag(actual_parameter_count);
  Push(actual_parameter_count);

  if (new_target.is_valid()) {
    Push(new_target);
  }
  Push(fun);
  Push(fun);
  Push(r4);
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

void MacroAssembler::InvokeFunctionCode(Register function, Register new_target,
                                        Register expected_parameter_count,
                                        Register actual_parameter_count,
                                        InvokeType type) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());
  DCHECK_EQ(function, r1);
  DCHECK_IMPLIES(new_target.is_valid(), new_target == r3);

  // On function call, call into the debugger if necessary.
  Label debug_hook, continue_after_hook;
  {
    ExternalReference debug_hook_active =
        ExternalReference::debug_hook_on_function_call_address(isolate());
    Move(r4, debug_hook_active);
    ldrsb(r4, MemOperand(r4));
    cmp(r4, Operand(0));
    b(ne, &debug_hook);
  }
  bind(&continue_after_hook);

  // Clear the new.target register if not given.
  if (!new_target.is_valid()) {
    LoadRoot(r3, RootIndex::kUndefinedValue);
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
  b(&done);

  // Deferred debug hook.
  bind(&debug_hook);
  CallDebugOnFunctionCall(function, new_target, expected_parameter_count,
                          actual_parameter_count);
  b(&continue_after_hook);

  // Continue here if InvokePrologue does handle the invocation due to
  // mismatched parameter counts.
  bind(&done);
}

void MacroAssembler::InvokeFunctionWithNewTarget(
    Register fun, Register new_target, Register actual_parameter_count,
    InvokeType type) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());

  // Contract with called JS functions requires that function is passed in r1.
  DCHECK_EQ(fun, r1);

  Register expected_reg = r2;
  Register temp_reg = r4;

  ldr(temp_reg, FieldMemOperand(r1, JSFunction::kSharedFunctionInfoOffset));
  ldr(cp, FieldMemOperand(r1, JSFunction::kContextOffset));
  ldrh(expected_reg,
       FieldMemOperand(temp_reg,
                       SharedFunctionInfo::kFormalParameterCountOffset));

  InvokeFunctionCode(fun, new_target, expected_reg, actual_parameter_count,
                     type);
}

void MacroAssembler::InvokeFunction(Register function,
                                    Register expected_parameter_count,
                                    Register actual_parameter_count,
                                    InvokeType type) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());

  // Contract with called JS functions requires that function is passed in r1.
  DCHECK_EQ(function, r1);

  // Get the function and setup the context.
  ldr(cp, FieldMemOperand(r1, JSFunction::kContextOffset));

  InvokeFunctionCode(r1, no_reg, expected_parameter_count,
                     actual_parameter_count, type);
}

void MacroAssembler::PushStackHandler() {
  ASM_CODE_COMMENT(this);
  // Adjust this code if not the case.
  static_assert(StackHandlerConstants::kSize == 2 * kPointerSize);
  static_assert(StackHandlerConstants::kNextOffset == 0 * kPointerSize);

  Push(Smi::zero());  // Padding.
  // Link the current handler as the next handler.
  Move(r6,
       ExternalReference::Create(IsolateAddressId::kHandlerAddress, isolate()));
  ldr(r5, MemOperand(r6));
  push(r5);
  // Set this new handler as the current one.
  str(sp, MemOperand(r6));
}

void MacroAssembler::PopStackHandler() {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  static_assert(StackHandlerConstants::kNextOffset == 0);
  pop(r1);
  Move(scratch,
       ExternalReference::Create(IsolateAddressId::kHandlerAddress, isolate()));
  str(r1, MemOperand(scratch));
  add(sp, sp, Operand(StackHandlerConstants::kSize - kPointerSize));
}

void MacroAssembler::CompareObjectType(Register object, Register map,
                                       Register type_reg, InstanceType type) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  const Register temp = type_reg == no_reg ? temps.Acquire() : type_reg;

  LoadMap(map, object);
  CompareInstanceType(map, temp, type);
}

void MacroAssembler::CompareObjectTypeRange(Register object, Register map,
                                            Register type_reg, Register scratch,
                                            InstanceType lower_limit,
                                            InstanceType upper_limit) {
  ASM_CODE_COMMENT(this);
  LoadMap(map, object);
  CompareInstanceTypeRange(map, type_reg, scratch, lower_limit, upper_limit);
}

void MacroAssembler::CompareInstanceType(Register map, Register type_reg,
                                         InstanceType type) {
  ldrh(type_reg, FieldMemOperand(map, Map::kInstanceTypeOffset));
  cmp(type_reg, Operand(type));
}

void MacroAssembler::CompareRange(Register value, Register scratch,
                                  unsigned lower_limit, unsigned higher_limit) {
  ASM_CODE_COMMENT(this);
  DCHECK_LT(lower_limit, higher_limit);
  if (lower_limit != 0) {
    sub(scratch, value, Operand(lower_limit));
    cmp(scratch, Operand(higher_limit - lower_limit));
  } else {
    cmp(value, Operand(higher_limit));
  }
}
void MacroAssembler::CompareInstanceTypeRange(Register map, Register type_reg,
                                              Register scratch,
                                              InstanceType lower_limit,
                                              InstanceType higher_limit) {
  ASM_CODE_COMMENT(this);
  DCHECK_LT(lower_limit, higher_limit);
  ldrh(type_reg, FieldMemOperand(map, Map::kInstanceTypeOffset));
  CompareRange(type_reg, scratch, lower_limit, higher_limit);
}

void MacroAssembler::CompareTaggedRoot(Register obj, RootIndex index) {
  CompareRoot(obj, index);
}

void MacroAssembler::CompareRoot(Register obj, RootIndex index) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  DCHECK(obj != scratch);
  LoadRoot(scratch, index);
  cmp(obj, scratch);
}

void MacroAssembler::Ju
"""


```