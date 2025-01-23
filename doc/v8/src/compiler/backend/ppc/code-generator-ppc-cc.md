Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/backend/ppc/code-generator-ppc.cc`.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the file's purpose:** The file name `code-generator-ppc.cc` strongly suggests it's responsible for generating machine code for the PPC (PowerPC) architecture within the V8 compiler. The `backend` directory confirms this is part of the code generation pipeline.

2. **Scan for key classes and structures:**
    * `PPCOperandConverter`: This class seems crucial for handling operands of instructions, likely translating high-level instruction representations into PPC-specific operand formats. It includes methods like `InputImmediate`, `MemoryOperand`, and `SlotToMemOperand`, which are related to accessing data.
    * `OutOfLineRecordWrite`: This class appears to handle a specific task related to "record writes". The presence of `RecordWriteMode` suggests this is involved in maintaining the integrity of the V8 heap during memory updates, likely related to garbage collection.
    * Macros like `ASSEMBLE_BINOP`, `ASSEMBLE_FLOAT_UNOP_RC`, `ASSEMBLE_LOAD_INTEGER`, etc.: These are clearly helper macros for generating specific PPC instructions. They encapsulate common patterns in instruction generation.

3. **Analyze the functionality of key components:**
    * **`PPCOperandConverter`:**  Focus on the methods and their likely purpose: converting various types of inputs (registers, immediates, memory locations) into `Operand` and `MemOperand` objects suitable for PPC instructions. The `OutputRCBit` suggests it handles setting condition codes.
    * **`OutOfLineRecordWrite`:** The name and the `Generate()` method indicate this class generates code to perform record writes. The involvement of `CheckPageFlag`, `CallEphemeronKeyBarrier`, and `CallRecordWriteStubSaveRegisters` points towards interaction with the garbage collector's write barrier. The `OutOfLineCode` base class suggests this handles cases that aren't directly in the main instruction sequence.
    * **Macros:**  Recognize these as code generation shortcuts for common PPC instructions (arithmetic, comparisons, loads, stores, etc.). Note how they handle register and immediate operands.

4. **Look for architecture-specific details:**  The `#include` statements for `assembler-inl.h`, `macro-assembler.h`, and the presence of PPC-specific register names (like `r11`, `sp`, `fp`) confirm the architecture-specific nature of the code. The use of `cr0` for condition registers is another PPC detail.

5. **Identify any Javascript connection:** While this C++ code directly generates machine code, it's part of the V8 engine, which executes Javascript. The `OutOfLineRecordWrite` and its relation to the garbage collector are a key link, as efficient garbage collection is crucial for Javascript performance.

6. **Consider potential programming errors:** The `OutOfLineRecordWrite` highlights a common problem in garbage-collected environments: incorrect handling of memory writes that could break the garbage collector's assumptions about object reachability.

7. **Address specific instructions in the prompt:**
    * **`.tq` suffix:** The code explicitly checks for this and correctly concludes this file is not a Torque file.
    * **Javascript example:**  Focus on the consequence of the `OutOfLineRecordWrite`'s functionality. A simple object property assignment can trigger this mechanism.
    * **Code logic reasoning:**  The `OutOfLineRecordWrite` provides a good example. Assume an object, an offset, and a value; the output would be the generated assembly code for the write barrier.
    * **User programming errors:** Link the record write to potential heap corruption if the write barrier isn't handled correctly (though this is usually an internal V8 concern, it reflects the *purpose* of the code).

8. **Synthesize the summary:** Combine the observations into a concise summary that addresses the prompt's requirements. Organize the points logically, starting with the main function of the file and then elaborating on key details.

9. **Review and refine:** Ensure the summary is accurate, clear, and addresses all parts of the prompt. Check for any misinterpretations or missing information. For instance, initially, I might have focused too much on the individual macros. Realizing that `PPCOperandConverter` and `OutOfLineRecordWrite` are higher-level abstractions within the code generator is important for a good summary. Also, explicitly mentioning the connection to the garbage collector and heap integrity is crucial when discussing `OutOfLineRecordWrite`.
好的，根据你提供的V8源代码片段 `v8/src/compiler/backend/ppc/code-generator-ppc.cc`，以下是其功能的归纳：

**主要功能：**

`v8/src/compiler/backend/ppc/code-generator-ppc.cc` 文件的主要功能是 **为PowerPC (PPC) 架构生成机器代码**。它是V8 JavaScript引擎的编译器后端的一部分，负责将中间表示（由V8的优化编译器生成）转换为可以在PPC处理器上执行的实际机器指令。

**详细功能点：**

1. **PPC架构特定的指令生成:** 该文件包含了大量PPC架构特定的代码生成逻辑，例如：
    * 定义了 `PPCOperandConverter` 类，用于将通用的指令操作数转换为PPC架构特有的操作数格式，例如立即数、寄存器、内存地址等。
    * 包含了大量的宏定义（如 `ASSEMBLE_BINOP`, `ASSEMBLE_FLOAT_UNOP_RC`, `ASSEMBLE_LOAD_INTEGER` 等），这些宏封装了生成各种PPC指令的模式，简化了代码生成过程。
    * 实现了对PPC架构的浮点运算、整数运算、内存访问、比较、跳转等指令的生成。

2. **处理指令操作数:** `PPCOperandConverter` 类负责处理指令的输入和输出操作数，包括：
    * 将常量转换为PPC可以识别的立即数形式。
    * 处理寄存器操作数。
    * 处理内存操作数，包括不同的寻址模式（如基于寄存器偏移、立即数偏移等）。
    * 处理栈槽操作数。

3. **实现记录写入屏障 (Record Write Barrier):** `OutOfLineRecordWrite` 类用于生成处理对象属性写入时的记录写入屏障代码。这对于垃圾回收器 (Garbage Collector, GC) 跟踪对象引用至关重要。当一个对象的属性被写入另一个对象时，需要通知GC，以便GC能够正确地跟踪对象间的引用关系，防止悬挂指针。

4. **处理溢出和条件码:** 代码中涉及到对算术运算溢出的检测和处理，以及根据比较结果设置条件码。`OutputRCBit()` 方法和相关的宏用于控制是否设置PPC处理器的条件寄存器。

5. **支持原子操作:** 文件中包含对原子操作的支持（例如 `ASSEMBLE_ATOMIC_EXCHANGE`, `ASSEMBLE_ATOMIC_COMPARE_EXCHANGE`, `ASSEMBLE_ATOMIC_BINOP`），用于在多线程环境下安全地访问共享内存。

6. **处理WebAssembly (Wasm):**  代码中包含 `#if V8_ENABLE_WEBASSEMBLY` 相关的条件编译，表明该文件也参与了WebAssembly代码的生成过程。

7. **帧的构造和析构:** `AssembleDeconstructFrame()` 函数负责生成函数帧析构的代码，用于在函数返回时恢复栈状态。

**关于问题中的其他点：**

* **`.tq` 结尾:**  正如代码所示，该文件以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 V8 Torque 源代码。
* **与 JavaScript 功能的关系:**  该文件直接负责将 JavaScript 代码编译成可以在PPC架构上运行的机器码。例如，当我们执行 JavaScript 中的算术运算、对象属性访问等操作时，V8 的编译器就会调用这个文件中的代码来生成相应的PPC指令。

**JavaScript 示例 (与记录写入屏障相关):**

```javascript
let obj1 = { a: 1 };
let obj2 = {};

// 当执行 obj2.b = obj1; 时，可能会触发记录写入屏障
// 因为我们将一个对象 (obj1) 赋值给了另一个对象 (obj2) 的属性。
obj2.b = obj1;
```

在上述 JavaScript 代码中，`obj2.b = obj1;` 这个操作会在 V8 内部触发一系列的底层操作，其中就可能包括调用 `OutOfLineRecordWrite` 生成相应的机器码，以通知垃圾回收器 `obj2` 现在引用了 `obj1`。

**代码逻辑推理 (以 `OutOfLineRecordWrite` 为例):**

**假设输入:**

* `object`:  指向 `obj2` 的寄存器 (假设为 `r3`)
* `offset_immediate_`:  `obj2` 中属性 `b` 的偏移量 (假设为 8)
* `value_`: 指向 `obj1` 的寄存器 (假设为 `r4`)
* `mode_`: `RecordWriteMode::kValueIsObject` (表示写入的值是一个对象)

**可能的输出 (生成的 PPC 汇编代码片段，简化表示):**

```assembly
  // 检查 value_ (r4) 指向的页面的标记
  lwz  r0, MemoryChunk::kPointersToHereAreInterestingMaskOffset(r4)
  andi. r0, r0, MemoryChunk::kPointersToHereAreInterestingMask
  beq  exit_record_write  // 如果不需要写屏障则跳过

  // 计算目标地址 (object_ + offset_immediate_)
  addi r5, r3, 8

  // 保存 LR (如果需要)
  mflr r6
  stw  r6, [sp++]

  // 调用记录写入屏障函数
  bl CallRecordWriteStubSaveRegisters

  // 恢复 LR (如果需要)
  ldw  r6, [--sp]
  mtlr r6

exit_record_write:
  // ... 后续代码
```

**用户常见的编程错误 (与内存管理相关，虽然 `code-generator-ppc.cc` 主要关注代码生成，但记录写入屏障与其相关):**

在非垃圾回收的语言中，一个常见的错误是手动管理内存时忘记释放不再使用的对象，导致内存泄漏。在 JavaScript 中，V8 的垃圾回收器负责内存管理，但理解记录写入屏障有助于理解 V8 如何确保垃圾回收的正确性。如果 V8 的记录写入屏障机制出现问题，可能会导致对象被错误地回收，从而引发程序崩溃或数据损坏。这虽然不是直接由用户代码错误引起，但理解其作用有助于理解 JavaScript 运行时的底层机制。

**总结:**

`v8/src/compiler/backend/ppc/code-generator-ppc.cc` 是 V8 引擎中至关重要的一个组成部分，它负责将高级的 JavaScript 代码转化为底层的、可以在PowerPC架构上执行的机器指令。它涉及到对PPC架构的深入理解，以及对V8内部数据结构和运行机制的掌握。其中，记录写入屏障的实现确保了垃圾回收器能够正确地跟踪对象引用，维护内存的安全性。

### 提示词
```
这是目录为v8/src/compiler/backend/ppc/code-generator-ppc.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/ppc/code-generator-ppc.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/numbers/double.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/callable.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/optimized-compilation-info.h"
#include "src/compiler/backend/code-generator-impl.h"
#include "src/compiler/backend/code-generator.h"
#include "src/compiler/backend/gap-resolver.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/osr.h"
#include "src/heap/mutable-page-metadata.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-objects.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {
namespace compiler {

#define __ masm()->

#define kScratchReg r11

// Adds PPC-specific methods to convert InstructionOperands.
class PPCOperandConverter final : public InstructionOperandConverter {
 public:
  PPCOperandConverter(CodeGenerator* gen, Instruction* instr)
      : InstructionOperandConverter(gen, instr) {}

  size_t OutputCount() { return instr_->OutputCount(); }

  RCBit OutputRCBit() const {
    switch (instr_->flags_mode()) {
      case kFlags_branch:
      case kFlags_conditional_branch:
      case kFlags_deoptimize:
      case kFlags_set:
      case kFlags_conditional_set:
      case kFlags_trap:
      case kFlags_select:
        return SetRC;
      case kFlags_none:
        return LeaveRC;
    }
    UNREACHABLE();
  }

  bool CompareLogical() const {
    switch (instr_->flags_condition()) {
      case kUnsignedLessThan:
      case kUnsignedGreaterThanOrEqual:
      case kUnsignedLessThanOrEqual:
      case kUnsignedGreaterThan:
        return true;
      default:
        return false;
    }
    UNREACHABLE();
  }

  Operand InputImmediate(size_t index) {
    Constant constant = ToConstant(instr_->InputAt(index));
    switch (constant.type()) {
      case Constant::kInt32:
        return Operand(constant.ToInt32());
      case Constant::kFloat32:
        return Operand::EmbeddedNumber(constant.ToFloat32());
      case Constant::kFloat64:
        return Operand::EmbeddedNumber(constant.ToFloat64().value());
      case Constant::kInt64:
        return Operand(constant.ToInt64());
      case Constant::kExternalReference:
        return Operand(constant.ToExternalReference());
      case Constant::kCompressedHeapObject: {
        RootIndex root_index;
        if (gen_->isolate()->roots_table().IsRootHandle(constant.ToHeapObject(),
                                                        &root_index)) {
          CHECK(COMPRESS_POINTERS_BOOL);
          CHECK(V8_STATIC_ROOTS_BOOL || !gen_->isolate()->bootstrapper());
          Tagged_t ptr =
              MacroAssemblerBase::ReadOnlyRootPtr(root_index, gen_->isolate());
          return Operand(ptr);
        }
        return Operand(constant.ToHeapObject());
      }
      case Constant::kHeapObject:
      case Constant::kRpoNumber:
        break;
    }
    UNREACHABLE();
  }

  MemOperand MemoryOperand(AddressingMode* mode, size_t* first_index) {
    const size_t index = *first_index;
    AddressingMode addr_mode = AddressingModeField::decode(instr_->opcode());
    if (mode) *mode = addr_mode;
    switch (addr_mode) {
      case kMode_None:
        break;
      case kMode_MRI:
        *first_index += 2;
        return MemOperand(InputRegister(index + 0), InputInt64(index + 1));
      case kMode_MRR:
        *first_index += 2;
        return MemOperand(InputRegister(index + 0), InputRegister(index + 1));
      case kMode_Root:
        *first_index += 1;
        return MemOperand(kRootRegister, InputRegister(index));
    }
    UNREACHABLE();
  }

  MemOperand MemoryOperand(AddressingMode* mode = NULL,
                           size_t first_index = 0) {
    return MemoryOperand(mode, &first_index);
  }

  MemOperand ToMemOperand(InstructionOperand* op) const {
    DCHECK_NOT_NULL(op);
    DCHECK(op->IsStackSlot() || op->IsFPStackSlot());
    return SlotToMemOperand(AllocatedOperand::cast(op)->index());
  }

  MemOperand SlotToMemOperand(int slot) const {
    FrameOffset offset = frame_access_state()->GetFrameOffset(slot);
    return MemOperand(offset.from_stack_pointer() ? sp : fp, offset.offset());
  }
};

static inline bool HasRegisterInput(Instruction* instr, size_t index) {
  return instr->InputAt(index)->IsRegister();
}

namespace {

class OutOfLineRecordWrite final : public OutOfLineCode {
 public:
  OutOfLineRecordWrite(
      CodeGenerator* gen, Register object, Register offset, Register value,
      Register scratch0, Register scratch1, RecordWriteMode mode,
      StubCallMode stub_mode, UnwindingInfoWriter* unwinding_info_writer,
      IndirectPointerTag indirect_pointer_tag = kIndirectPointerNullTag)
      : OutOfLineCode(gen),
        object_(object),
        offset_(offset),
        offset_immediate_(0),
        value_(value),
        scratch0_(scratch0),
        scratch1_(scratch1),
        mode_(mode),
#if V8_ENABLE_WEBASSEMBLY
        stub_mode_(stub_mode),
#endif  // V8_ENABLE_WEBASSEMBLY
        must_save_lr_(!gen->frame_access_state()->has_frame()),
        unwinding_info_writer_(unwinding_info_writer),
        zone_(gen->zone()),
        indirect_pointer_tag_(indirect_pointer_tag) {
    DCHECK(!AreAliased(object, offset, scratch0, scratch1));
    DCHECK(!AreAliased(value, offset, scratch0, scratch1));
  }

  OutOfLineRecordWrite(
      CodeGenerator* gen, Register object, int32_t offset, Register value,
      Register scratch0, Register scratch1, RecordWriteMode mode,
      StubCallMode stub_mode, UnwindingInfoWriter* unwinding_info_writer,
      IndirectPointerTag indirect_pointer_tag = kIndirectPointerNullTag)
      : OutOfLineCode(gen),
        object_(object),
        offset_(no_reg),
        offset_immediate_(offset),
        value_(value),
        scratch0_(scratch0),
        scratch1_(scratch1),
        mode_(mode),
#if V8_ENABLE_WEBASSEMBLY
        stub_mode_(stub_mode),
#endif  // V8_ENABLE_WEBASSEMBLY
        must_save_lr_(!gen->frame_access_state()->has_frame()),
        unwinding_info_writer_(unwinding_info_writer),
        zone_(gen->zone()),
        indirect_pointer_tag_(indirect_pointer_tag) {
  }

  void Generate() final {
    ConstantPoolUnavailableScope constant_pool_unavailable(masm());
    // When storing an indirect pointer, the value will always be a
    // full/decompressed pointer.
    if (COMPRESS_POINTERS_BOOL &&
        mode_ != RecordWriteMode::kValueIsIndirectPointer) {
      __ DecompressTagged(value_, value_);
    }
    __ CheckPageFlag(value_, scratch0_,
                     MemoryChunk::kPointersToHereAreInterestingMask, eq,
                     exit());
    if (offset_ == no_reg) {
      __ addi(scratch1_, object_, Operand(offset_immediate_));
    } else {
      DCHECK_EQ(0, offset_immediate_);
      __ add(scratch1_, object_, offset_);
    }
    SaveFPRegsMode const save_fp_mode = frame()->DidAllocateDoubleRegisters()
                                            ? SaveFPRegsMode::kSave
                                            : SaveFPRegsMode::kIgnore;
    if (must_save_lr_) {
      // We need to save and restore lr if the frame was elided.
      __ mflr(scratch0_);
      __ Push(scratch0_);
      unwinding_info_writer_->MarkLinkRegisterOnTopOfStack(__ pc_offset());
    }
    if (mode_ == RecordWriteMode::kValueIsEphemeronKey) {
      __ CallEphemeronKeyBarrier(object_, scratch1_, save_fp_mode);
    } else if (mode_ == RecordWriteMode::kValueIsIndirectPointer) {
      DCHECK(IsValidIndirectPointerTag(indirect_pointer_tag_));
      __ CallIndirectPointerBarrier(object_, scratch1_, save_fp_mode,
                                    indirect_pointer_tag_);
#if V8_ENABLE_WEBASSEMBLY
    } else if (stub_mode_ == StubCallMode::kCallWasmRuntimeStub) {
      __ CallRecordWriteStubSaveRegisters(object_, scratch1_, save_fp_mode,
                                          StubCallMode::kCallWasmRuntimeStub);
#endif  // V8_ENABLE_WEBASSEMBLY
    } else {
      __ CallRecordWriteStubSaveRegisters(object_, scratch1_, save_fp_mode);
    }
    if (must_save_lr_) {
      // We need to save and restore lr if the frame was elided.
      __ Pop(scratch0_);
      __ mtlr(scratch0_);
      unwinding_info_writer_->MarkPopLinkRegisterFromTopOfStack(__ pc_offset());
    }
  }

 private:
  Register const object_;
  Register const offset_;
  int32_t const offset_immediate_;  // Valid if offset_ == no_reg.
  Register const value_;
  Register const scratch0_;
  Register const scratch1_;
  RecordWriteMode const mode_;
#if V8_ENABLE_WEBASSEMBLY
  StubCallMode stub_mode_;
#endif  // V8_ENABLE_WEBASSEMBLY
  bool must_save_lr_;
  UnwindingInfoWriter* const unwinding_info_writer_;
  Zone* zone_;
  IndirectPointerTag indirect_pointer_tag_;
};

Condition FlagsConditionToCondition(FlagsCondition condition, ArchOpcode op) {
  switch (condition) {
    case kEqual:
      return eq;
    case kNotEqual:
      return ne;
    case kSignedLessThan:
    case kUnsignedLessThan:
      return lt;
    case kSignedGreaterThanOrEqual:
    case kUnsignedGreaterThanOrEqual:
      return ge;
    case kSignedLessThanOrEqual:
    case kUnsignedLessThanOrEqual:
      return le;
    case kSignedGreaterThan:
    case kUnsignedGreaterThan:
      return gt;
    case kOverflow:
      // Overflow checked for add/sub only.
      switch (op) {
        case kPPC_Add32:
        case kPPC_Add64:
        case kPPC_Sub:
        case kPPC_AddWithOverflow32:
        case kPPC_SubWithOverflow32:
          return lt;
        default:
          break;
      }
      break;
    case kNotOverflow:
      switch (op) {
        case kPPC_Add32:
        case kPPC_Add64:
        case kPPC_Sub:
        case kPPC_AddWithOverflow32:
        case kPPC_SubWithOverflow32:
          return ge;
        default:
          break;
      }
      break;
    default:
      break;
  }
  UNREACHABLE();
}

}  // namespace

#define ASSEMBLE_FLOAT_UNOP_RC(asm_instr, round)                     \
  do {                                                               \
    __ asm_instr(i.OutputDoubleRegister(), i.InputDoubleRegister(0), \
                 i.OutputRCBit());                                   \
    if (round) {                                                     \
      __ frsp(i.OutputDoubleRegister(), i.OutputDoubleRegister());   \
    }                                                                \
  } while (0)

#define ASSEMBLE_FLOAT_BINOP_RC(asm_instr, round)                    \
  do {                                                               \
    __ asm_instr(i.OutputDoubleRegister(), i.InputDoubleRegister(0), \
                 i.InputDoubleRegister(1), i.OutputRCBit());         \
    if (round) {                                                     \
      __ frsp(i.OutputDoubleRegister(), i.OutputDoubleRegister());   \
    }                                                                \
  } while (0)

#define ASSEMBLE_BINOP(asm_instr_reg, asm_instr_imm)           \
  do {                                                         \
    if (HasRegisterInput(instr, 1)) {                          \
      __ asm_instr_reg(i.OutputRegister(), i.InputRegister(0), \
                       i.InputRegister(1));                    \
    } else {                                                   \
      __ asm_instr_imm(i.OutputRegister(), i.InputRegister(0), \
                       i.InputImmediate(1));                   \
    }                                                          \
  } while (0)

#define ASSEMBLE_BINOP_RC(asm_instr_reg, asm_instr_imm)        \
  do {                                                         \
    if (HasRegisterInput(instr, 1)) {                          \
      __ asm_instr_reg(i.OutputRegister(), i.InputRegister(0), \
                       i.InputRegister(1), i.OutputRCBit());   \
    } else {                                                   \
      __ asm_instr_imm(i.OutputRegister(), i.InputRegister(0), \
                       i.InputImmediate(1), i.OutputRCBit());  \
    }                                                          \
  } while (0)

#define ASSEMBLE_BINOP_INT_RC(asm_instr_reg, asm_instr_imm)    \
  do {                                                         \
    if (HasRegisterInput(instr, 1)) {                          \
      __ asm_instr_reg(i.OutputRegister(), i.InputRegister(0), \
                       i.InputRegister(1), i.OutputRCBit());   \
    } else {                                                   \
      __ asm_instr_imm(i.OutputRegister(), i.InputRegister(0), \
                       i.InputImmediate(1), i.OutputRCBit());  \
    }                                                          \
  } while (0)

#define ASSEMBLE_ADD_WITH_OVERFLOW()                                    \
  do {                                                                  \
    if (HasRegisterInput(instr, 1)) {                                   \
      __ AddAndCheckForOverflow(i.OutputRegister(), i.InputRegister(0), \
                                i.InputRegister(1), kScratchReg, r0);   \
    } else {                                                            \
      __ AddAndCheckForOverflow(i.OutputRegister(), i.InputRegister(0), \
                                i.InputInt32(1), kScratchReg, r0);      \
    }                                                                   \
  } while (0)

#define ASSEMBLE_SUB_WITH_OVERFLOW()                                    \
  do {                                                                  \
    if (HasRegisterInput(instr, 1)) {                                   \
      __ SubAndCheckForOverflow(i.OutputRegister(), i.InputRegister(0), \
                                i.InputRegister(1), kScratchReg, r0);   \
    } else {                                                            \
      __ AddAndCheckForOverflow(i.OutputRegister(), i.InputRegister(0), \
                                -i.InputInt32(1), kScratchReg, r0);     \
    }                                                                   \
  } while (0)

#define ASSEMBLE_ADD_WITH_OVERFLOW32()         \
  do {                                         \
    ASSEMBLE_ADD_WITH_OVERFLOW();              \
    __ extsw(kScratchReg, kScratchReg, SetRC); \
  } while (0)

#define ASSEMBLE_SUB_WITH_OVERFLOW32()         \
  do {                                         \
    ASSEMBLE_SUB_WITH_OVERFLOW();              \
    __ extsw(kScratchReg, kScratchReg, SetRC); \
  } while (0)

#define ASSEMBLE_COMPARE(cmp_instr, cmpl_instr)                        \
  do {                                                                 \
    const CRegister cr = cr0;                                          \
    if (HasRegisterInput(instr, 1)) {                                  \
      if (i.CompareLogical()) {                                        \
        __ cmpl_instr(i.InputRegister(0), i.InputRegister(1), cr);     \
      } else {                                                         \
        __ cmp_instr(i.InputRegister(0), i.InputRegister(1), cr);      \
      }                                                                \
    } else {                                                           \
      if (i.CompareLogical()) {                                        \
        __ cmpl_instr##i(i.InputRegister(0), i.InputImmediate(1), cr); \
      } else {                                                         \
        __ cmp_instr##i(i.InputRegister(0), i.InputImmediate(1), cr);  \
      }                                                                \
    }                                                                  \
    DCHECK_EQ(SetRC, i.OutputRCBit());                                 \
  } while (0)

#define ASSEMBLE_FLOAT_COMPARE(cmp_instr)                                 \
  do {                                                                    \
    const CRegister cr = cr0;                                             \
    __ cmp_instr(i.InputDoubleRegister(0), i.InputDoubleRegister(1), cr); \
    DCHECK_EQ(SetRC, i.OutputRCBit());                                    \
  } while (0)

#define ASSEMBLE_MODULO(div_instr, mul_instr)                        \
  do {                                                               \
    const Register scratch = kScratchReg;                            \
    __ div_instr(scratch, i.InputRegister(0), i.InputRegister(1));   \
    __ mul_instr(scratch, scratch, i.InputRegister(1));              \
    __ sub(i.OutputRegister(), i.InputRegister(0), scratch, LeaveOE, \
           i.OutputRCBit());                                         \
  } while (0)

#define ASSEMBLE_FLOAT_MODULO()                                             \
  do {                                                                      \
    FrameScope scope(masm(), StackFrame::MANUAL);                           \
    __ PrepareCallCFunction(0, 2, kScratchReg);                             \
    __ MovToFloatParameters(i.InputDoubleRegister(0),                       \
                            i.InputDoubleRegister(1));                      \
    __ CallCFunction(ExternalReference::mod_two_doubles_operation(), 0, 2); \
    __ MovFromFloatResult(i.OutputDoubleRegister());                        \
    DCHECK_EQ(LeaveRC, i.OutputRCBit());                                    \
  } while (0)

#define ASSEMBLE_IEEE754_UNOP(name)                                            \
  do {                                                                         \
    /* TODO(bmeurer): We should really get rid of this special instruction, */ \
    /* and generate a CallAddress instruction instead. */                      \
    FrameScope scope(masm(), StackFrame::MANUAL);                              \
    __ PrepareCallCFunction(0, 1, kScratchReg);                                \
    __ MovToFloatParameter(i.InputDoubleRegister(0));                          \
    __ CallCFunction(ExternalReference::ieee754_##name##_function(), 0, 1);    \
    /* Move the result in the double result register. */                       \
    __ MovFromFloatResult(i.OutputDoubleRegister());                           \
    DCHECK_EQ(LeaveRC, i.OutputRCBit());                                       \
  } while (0)

#define ASSEMBLE_IEEE754_BINOP(name)                                           \
  do {                                                                         \
    /* TODO(bmeurer): We should really get rid of this special instruction, */ \
    /* and generate a CallAddress instruction instead. */                      \
    FrameScope scope(masm(), StackFrame::MANUAL);                              \
    __ PrepareCallCFunction(0, 2, kScratchReg);                                \
    __ MovToFloatParameters(i.InputDoubleRegister(0),                          \
                            i.InputDoubleRegister(1));                         \
    __ CallCFunction(ExternalReference::ieee754_##name##_function(), 0, 2);    \
    /* Move the result in the double result register. */                       \
    __ MovFromFloatResult(i.OutputDoubleRegister());                           \
    DCHECK_EQ(LeaveRC, i.OutputRCBit());                                       \
  } while (0)

#define ASSEMBLE_LOAD_FLOAT(asm_instr, asm_instrp, asm_instrx) \
  do {                                                         \
    DoubleRegister result = i.OutputDoubleRegister();          \
    size_t index = 0;                                          \
    AddressingMode mode = kMode_None;                          \
    MemOperand operand = i.MemoryOperand(&mode, &index);       \
    bool is_atomic = i.InputInt32(index);                      \
    if (mode == kMode_MRI) {                                   \
      intptr_t offset = operand.offset();                      \
      if (is_int16(offset)) {                                  \
        __ asm_instr(result, operand);                         \
      } else {                                                 \
        CHECK(CpuFeatures::IsSupported(PPC_10_PLUS));          \
        __ asm_instrp(result, operand);                        \
      }                                                        \
    } else {                                                   \
      __ asm_instrx(result, operand);                          \
    }                                                          \
    if (is_atomic) __ lwsync();                                \
    DCHECK_EQ(LeaveRC, i.OutputRCBit());                       \
  } while (0)

#define ASSEMBLE_LOAD_INTEGER(asm_instr, asm_instrp, asm_instrx,   \
                              must_be_aligned)                     \
  do {                                                             \
    Register result = i.OutputRegister();                          \
    size_t index = 0;                                              \
    AddressingMode mode = kMode_None;                              \
    MemOperand operand = i.MemoryOperand(&mode, &index);           \
    bool is_atomic = i.InputInt32(index);                          \
    if (mode == kMode_MRI) {                                       \
      intptr_t offset = operand.offset();                          \
      bool misaligned = offset & 3;                                \
      if (is_int16(offset) && (!must_be_aligned || !misaligned)) { \
        __ asm_instr(result, operand);                             \
      } else {                                                     \
        CHECK(CpuFeatures::IsSupported(PPC_10_PLUS));              \
        __ asm_instrp(result, operand);                            \
      }                                                            \
    } else {                                                       \
      __ asm_instrx(result, operand);                              \
    }                                                              \
    if (is_atomic) __ lwsync();                                    \
    DCHECK_EQ(LeaveRC, i.OutputRCBit());                           \
  } while (0)

#define ASSEMBLE_LOAD_INTEGER_RR(asm_instr)              \
  do {                                                   \
    Register result = i.OutputRegister();                \
    size_t index = 0;                                    \
    AddressingMode mode = kMode_None;                    \
    MemOperand operand = i.MemoryOperand(&mode, &index); \
    DCHECK_EQ(mode, kMode_MRR);                          \
    bool is_atomic = i.InputInt32(index);                \
    __ asm_instr(result, operand);                       \
    if (is_atomic) __ lwsync();                          \
    DCHECK_EQ(LeaveRC, i.OutputRCBit());                 \
  } while (0)

#define ASSEMBLE_STORE_FLOAT(asm_instr, asm_instrp, asm_instrx) \
  do {                                                          \
    size_t index = 0;                                           \
    AddressingMode mode = kMode_None;                           \
    MemOperand operand = i.MemoryOperand(&mode, &index);        \
    DoubleRegister value = i.InputDoubleRegister(index);        \
    bool is_atomic = i.InputInt32(3);                           \
    if (is_atomic) __ lwsync();                                 \
    /* removed frsp as instruction-selector checked */          \
    /* value to be kFloat32 */                                  \
    if (mode == kMode_MRI) {                                    \
      intptr_t offset = operand.offset();                       \
      if (is_int16(offset)) {                                   \
        __ asm_instr(value, operand);                           \
      } else {                                                  \
        CHECK(CpuFeatures::IsSupported(PPC_10_PLUS));           \
        __ asm_instrp(value, operand);                          \
      }                                                         \
    } else {                                                    \
      __ asm_instrx(value, operand);                            \
    }                                                           \
    if (is_atomic) __ sync();                                   \
    DCHECK_EQ(LeaveRC, i.OutputRCBit());                        \
  } while (0)

#define ASSEMBLE_STORE_INTEGER(asm_instr, asm_instrp, asm_instrx,  \
                               must_be_aligned)                    \
  do {                                                             \
    size_t index = 0;                                              \
    AddressingMode mode = kMode_None;                              \
    MemOperand operand = i.MemoryOperand(&mode, &index);           \
    Register value = i.InputRegister(index);                       \
    bool is_atomic = i.InputInt32(index + 1);                      \
    if (is_atomic) __ lwsync();                                    \
    if (mode == kMode_MRI) {                                       \
      intptr_t offset = operand.offset();                          \
      bool misaligned = offset & 3;                                \
      if (is_int16(offset) && (!must_be_aligned || !misaligned)) { \
        __ asm_instr(value, operand);                              \
      } else {                                                     \
        CHECK(CpuFeatures::IsSupported(PPC_10_PLUS));              \
        __ asm_instrp(value, operand);                             \
      }                                                            \
    } else {                                                       \
      __ asm_instrx(value, operand);                               \
    }                                                              \
    if (is_atomic) __ sync();                                      \
    DCHECK_EQ(LeaveRC, i.OutputRCBit());                           \
  } while (0)

#define ASSEMBLE_STORE_INTEGER_RR(asm_instr)             \
  do {                                                   \
    size_t index = 0;                                    \
    AddressingMode mode = kMode_None;                    \
    MemOperand operand = i.MemoryOperand(&mode, &index); \
    DCHECK_EQ(mode, kMode_MRR);                          \
    Register value = i.InputRegister(index);             \
    bool is_atomic = i.InputInt32(index + 1);            \
    if (is_atomic) __ lwsync();                          \
    __ asm_instr(value, operand);                        \
    if (is_atomic) __ sync();                            \
    DCHECK_EQ(LeaveRC, i.OutputRCBit());                 \
  } while (0)

// TODO(mbrandy): fix paths that produce garbage in offset's upper 32-bits.
#define CleanUInt32(x) __ ClearLeftImm(x, x, Operand(32))

#if V8_ENABLE_WEBASSEMBLY
static inline bool is_wasm_on_be(bool IsWasm) {
#if V8_TARGET_BIG_ENDIAN
  return IsWasm;
#else
  return false;
#endif
}
#endif

#if V8_ENABLE_WEBASSEMBLY
#define MAYBE_REVERSE_IF_WASM(dst, src, op, scratch, reset) \
  if (is_wasm_on_be(info()->IsWasm())) {                    \
    __ op(dst, src, scratch);                               \
    if (reset) src = dst;                                   \
  }
#else
#define MAYBE_REVERSE_IF_WASM(dst, src, op, scratch, reset)
#endif

#define ASSEMBLE_ATOMIC_EXCHANGE(_type, reverse_op)                    \
  do {                                                                 \
    Register val = i.InputRegister(2);                                 \
    Register dst = i.OutputRegister();                                 \
    MAYBE_REVERSE_IF_WASM(ip, val, reverse_op, kScratchReg, true);     \
    __ AtomicExchange<_type>(                                          \
        MemOperand(i.InputRegister(0), i.InputRegister(1)), val, dst); \
    MAYBE_REVERSE_IF_WASM(dst, dst, reverse_op, kScratchReg, false);   \
  } while (false)

#define ASSEMBLE_ATOMIC_COMPARE_EXCHANGE(_type, reverse_op)                 \
  do {                                                                      \
    Register expected_val = i.InputRegister(2);                             \
    Register new_val = i.InputRegister(3);                                  \
    Register dst = i.OutputRegister();                                      \
    MAYBE_REVERSE_IF_WASM(ip, expected_val, reverse_op, kScratchReg, true); \
    MAYBE_REVERSE_IF_WASM(r0, new_val, reverse_op, kScratchReg, true);      \
    __ AtomicCompareExchange<_type>(                                        \
        MemOperand(i.InputRegister(0), i.InputRegister(1)), expected_val,   \
        new_val, dst, kScratchReg);                                         \
    MAYBE_REVERSE_IF_WASM(dst, dst, reverse_op, kScratchReg, false);        \
  } while (false)

#define ASSEMBLE_ATOMIC_BINOP_BYTE(bin_inst, _type)                          \
  do {                                                                       \
    auto bin_op = [&](Register dst, Register lhs, Register rhs) {            \
      if (std::is_signed<_type>::value) {                                    \
        __ extsb(dst, lhs);                                                  \
        __ bin_inst(dst, dst, rhs);                                          \
      } else {                                                               \
        __ bin_inst(dst, lhs, rhs);                                          \
      }                                                                      \
    };                                                                       \
    MemOperand dst_operand =                                                 \
        MemOperand(i.InputRegister(0), i.InputRegister(1));                  \
    __ AtomicOps<_type>(dst_operand, i.InputRegister(2), i.OutputRegister(), \
                        kScratchReg, bin_op);                                \
    break;                                                                   \
  } while (false)

#define ASSEMBLE_ATOMIC_BINOP(bin_inst, _type, reverse_op, scratch)           \
  do {                                                                        \
    auto bin_op = [&](Register dst, Register lhs, Register rhs) {             \
      Register _lhs = lhs;                                                    \
      MAYBE_REVERSE_IF_WASM(dst, _lhs, reverse_op, scratch, true);            \
      if (std::is_signed<_type>::value) {                                     \
        switch (sizeof(_type)) {                                              \
          case 1:                                                             \
            UNREACHABLE();                                                    \
            break;                                                            \
          case 2:                                                             \
            __ extsh(dst, _lhs);                                              \
            break;                                                            \
          case 4:                                                             \
            __ extsw(dst, _lhs);                                              \
            break;                                                            \
          case 8:                                                             \
            break;                                                            \
          default:                                                            \
            UNREACHABLE();                                                    \
        }                                                                     \
      }                                                                       \
      __ bin_inst(dst, _lhs, rhs);                                            \
      MAYBE_REVERSE_IF_WASM(dst, dst, reverse_op, scratch, false);            \
    };                                                                        \
    MemOperand dst_operand =                                                  \
        MemOperand(i.InputRegister(0), i.InputRegister(1));                   \
    __ AtomicOps<_type>(dst_operand, i.InputRegister(2), i.OutputRegister(),  \
                        kScratchReg, bin_op);                                 \
    MAYBE_REVERSE_IF_WASM(i.OutputRegister(), i.OutputRegister(), reverse_op, \
                          scratch, false);                                    \
    break;                                                                    \
  } while (false)

void CodeGenerator::AssembleDeconstructFrame() {
  __ LeaveFrame(StackFrame::MANUAL);
  unwinding_info_writer_.MarkFrameDeconstruct
```