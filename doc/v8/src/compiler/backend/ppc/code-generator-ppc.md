Response: The user wants me to summarize the functionality of the C++ code provided in the file `v8/src/compiler/backend/ppc/code-generator-ppc.cc`. This is the first part of a three-part file.

The code seems to be responsible for generating machine code for the PowerPC architecture within the V8 JavaScript engine's compiler. It defines a `CodeGenerator` class and related helper classes and functions to translate intermediate representation (IR) instructions into assembly instructions.

Here's a breakdown of the key functionalities I can identify in this first part:

1. **Operand Handling:**  The `PPCOperandConverter` class is responsible for converting instruction operands into a format suitable for assembly instructions. It handles different operand types like registers, immediates, and memory operands.
2. **Out-of-line Code Generation:** The `OutOfLineRecordWrite` class deals with generating code for record write operations that might require a write barrier (for garbage collection). This is handled separately to keep the main code generation flow cleaner.
3. **Condition Code Conversion:** The `FlagsConditionToCondition` function translates high-level condition codes (like `kEqual`, `kLessThan`) into the specific condition codes used by the PowerPC architecture.
4. **Assembly Instruction Emission:** The code uses macros (`ASSEMBLE_FLOAT_UNOP_RC`, `ASSEMBLE_BINOP`, etc.) to simplify the emission of various PowerPC assembly instructions. These macros handle common patterns in instruction generation.
5. **Support for Different Data Types:**  The code handles both integer (32-bit and 64-bit) and floating-point (single and double precision) operations.
6. **Memory Access:** It provides mechanisms for generating load and store instructions with different addressing modes. It also includes support for atomic memory operations.
7. **Function Calls:** The code includes logic for generating different kinds of function calls (direct calls, builtin calls, tail calls, C function calls).
8. **Frame Management:**  It includes functions for managing the stack frame, such as preparing and deconstructing frames, and handling tail calls.
9. **Deoptimization:** There's a mention of handling deoptimization, which is a process of reverting from optimized code to interpreted code.
10. **WebAssembly Support:**  The code includes conditional compilation for WebAssembly, suggesting it can generate code for WebAssembly modules as well.

Regarding the relationship with JavaScript, this code is a crucial part of how V8 executes JavaScript. The compiler takes the JavaScript code, translates it into an intermediate representation, and then this `code-generator-ppc.cc` file (along with its other parts) is responsible for turning that IR into actual machine code that the PowerPC processor can understand and run.

I need to come up with a JavaScript example that demonstrates the functionality of this C++ code indirectly. A simple arithmetic operation or function call in JavaScript would be a good example, as those operations would eventually be translated into the kind of machine code this file generates.
这个C++源代码文件是V8 JavaScript引擎中PowerPC架构的**代码生成器 (Code Generator)** 的一部分。 它的主要功能是将**中间表示 (Intermediate Representation, IR)** 的指令转换成**PowerPC汇编代码 (Assembly Code)**，以便最终生成可执行的机器码。

具体来说，这部分代码实现了以下核心功能：

1. **指令操作数转换 (Operand Conversion):** `PPCOperandConverter` 类负责将IR指令的操作数（例如，寄存器、立即数、内存地址）转换成PowerPC汇编指令可以接受的格式。
2. **处理需要特殊处理的代码块 (Out-of-Line Code):** `OutOfLineRecordWrite` 类用于生成处理**记录写入屏障 (record write barrier)** 的代码。当修改堆对象中的指针时，需要执行写入屏障来维护垃圾回收器的正确性。这部分代码被放在主代码生成流程之外，以保持代码的清晰。
3. **条件码转换 (Condition Code Conversion):** `FlagsConditionToCondition` 函数将IR指令中的条件标志（例如，等于、小于）转换成PowerPC架构的条件码。
4. **汇编指令生成宏 (Assembly Instruction Macros):** 定义了大量的宏（例如，`ASSEMBLE_FLOAT_UNOP_RC`, `ASSEMBLE_BINOP`），用于简化生成各种PowerPC汇编指令的过程。这些宏针对不同的指令类型和操作数提供了便利的抽象。
5. **支持不同的数据类型 (Data Type Support):**  代码可以处理整型（32位和64位）和浮点型（单精度和双精度）的操作。
6. **内存操作 (Memory Operations):**  提供了生成加载 (load) 和存储 (store) 指令的功能，支持不同的寻址模式。还包含了对原子内存操作的支持。
7. **函数调用 (Function Calls):**  实现了生成不同类型的函数调用指令，包括直接函数调用、内置函数调用、尾调用 (tail call) 和 C 函数调用。
8. **栈帧管理 (Stack Frame Management):**  包含了管理函数调用栈帧的相关逻辑，例如创建和销毁栈帧，以及处理尾调用时的栈调整。
9. **反优化 (Deoptimization):** 包含了处理代码反优化的逻辑。当优化后的代码执行遇到问题时，需要回退到未优化的代码执行。
10. **WebAssembly 支持 (WebAssembly Support):**  代码中包含了针对WebAssembly的条件编译，表明该代码生成器也支持为WebAssembly模块生成代码。

**它与JavaScript的功能的关系：**

这段C++代码的功能是V8引擎执行JavaScript代码的关键组成部分。当V8执行JavaScript代码时，会经历以下大致步骤：

1. **解析 (Parsing):** 将JavaScript源代码解析成抽象语法树 (Abstract Syntax Tree, AST)。
2. **编译 (Compilation):** 将AST转换成中间表示 (IR)。
3. **代码生成 (Code Generation):** **这个文件 (`code-generator-ppc.cc`) 的功能就在这里，它将IR指令转换成PowerPC架构的汇编代码。**
4. **执行 (Execution):**  处理器执行生成的机器码。

**JavaScript 举例说明:**

考虑以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
console.log(result);
```

当 V8 编译 `add` 函数时，`code-generator-ppc.cc` (以及其他相关文件) 会将 `a + b` 这个操作转换成相应的 PowerPC 汇编指令。 这可能涉及到：

*   将变量 `a` 和 `b` 的值加载到寄存器中 (使用类似 `ASSEMBLE_LOAD_INTEGER` 相关的宏)。
*   执行加法操作 (使用类似 `ASSEMBLE_BINOP` 或 `kPPC_Add32`, `kPPC_Add64` 相关的代码生成逻辑)。
*   将结果存储到另一个寄存器或内存位置。
*   生成函数返回的指令 (可能涉及栈帧的清理)。

对于 `console.log(result)` 这样的内置函数调用，`code-generator-ppc.cc` 也会生成相应的调用指令 (例如，使用 `kArchCallBuiltinPointer` 或 `kArchCallCodeObject` 相关的逻辑)。

**总结来说，`v8/src/compiler/backend/ppc/code-generator-ppc.cc` 的第一部分主要负责定义代码生成器的基础结构和核心功能，用于将高级的中间表示指令翻译成底层的PowerPC汇编指令，这是V8引擎将JavaScript代码转化为可执行机器码的关键步骤。**

### 提示词
```
这是目录为v8/src/compiler/backend/ppc/code-generator-ppc.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```
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
  unwinding_info_writer_.MarkFrameDeconstructed(__ pc_offset());
}

void CodeGenerator::AssemblePrepareTailCall() {
  if (frame_access_state()->has_frame()) {
    __ RestoreFrameStateForTailCall();
  }
  frame_access_state()->SetFrameAccessToSP();
}

namespace {

void FlushPendingPushRegisters(MacroAssembler* masm,
                               FrameAccessState* frame_access_state,
                               ZoneVector<Register>* pending_pushes) {
  switch (pending_pushes->size()) {
    case 0:
      break;
    case 1:
      masm->Push((*pending_pushes)[0]);
      break;
    case 2:
      masm->Push((*pending_pushes)[0], (*pending_pushes)[1]);
      break;
    case 3:
      masm->Push((*pending_pushes)[0], (*pending_pushes)[1],
                 (*pending_pushes)[2]);
      break;
    default:
      UNREACHABLE();
  }
  frame_access_state->IncreaseSPDelta(pending_pushes->size());
  pending_pushes->clear();
}

void AdjustStackPointerForTailCall(
    MacroAssembler* masm, FrameAccessState* state, int new_slot_above_sp,
    ZoneVector<Register>* pending_pushes = nullptr,
    bool allow_shrinkage = true) {
  int current_sp_offset = state->GetSPToFPSlotCount() +
                          StandardFrameConstants::kFixedSlotCountAboveFp;
  int stack_slot_delta = new_slot_above_sp - current_sp_offset;
  if (stack_slot_delta > 0) {
    if (pending_pushes != nullptr) {
      FlushPendingPushRegisters(masm, state, pending_pushes);
    }
    masm->AddS64(sp, sp, Operand(-stack_slot_delta * kSystemPointerSize), r0);
    state->IncreaseSPDelta(stack_slot_delta);
  } else if (allow_shrinkage && stack_slot_delta < 0) {
    if (pending_pushes != nullptr) {
      FlushPendingPushRegisters(masm, state, pending_pushes);
    }
    masm->AddS64(sp, sp, Operand(-stack_slot_delta * kSystemPointerSize), r0);
    state->IncreaseSPDelta(stack_slot_delta);
  }
}

}  // namespace

void CodeGenerator::AssembleTailCallBeforeGap(Instruction* instr,
                                              int first_unused_slot_offset) {
  ZoneVector<MoveOperands*> pushes(zone());
  GetPushCompatibleMoves(instr, kRegisterPush, &pushes);

  if (!pushes.empty() &&
      (LocationOperand::cast(pushes.back()->destination()).index() + 1 ==
       first_unused_slot_offset)) {
    PPCOperandConverter g(this, instr);
    ZoneVector<Register> pending_pushes(zone());
    for (auto move : pushes) {
      LocationOperand destination_location(
          LocationOperand::cast(move->destination()));
      InstructionOperand source(move->source());
      AdjustStackPointerForTailCall(
          masm(), frame_access_state(),
          destination_location.index() - pending_pushes.size(),
          &pending_pushes);
      // Pushes of non-register data types are not supported.
      DCHECK(source.IsRegister());
      LocationOperand source_location(LocationOperand::cast(source));
      pending_pushes.push_back(source_location.GetRegister());
      // TODO(arm): We can push more than 3 registers at once. Add support in
      // the macro-assembler for pushing a list of registers.
      if (pending_pushes.size() == 3) {
        FlushPendingPushRegisters(masm(), frame_access_state(),
                                  &pending_pushes);
      }
      move->Eliminate();
    }
    FlushPendingPushRegisters(masm(), frame_access_state(), &pending_pushes);
  }
  AdjustStackPointerForTailCall(masm(), frame_access_state(),
                                first_unused_slot_offset, nullptr, false);
}

void CodeGenerator::AssembleTailCallAfterGap(Instruction* instr,
                                             int first_unused_slot_offset) {
  AdjustStackPointerForTailCall(masm(), frame_access_state(),
                                first_unused_slot_offset);
}

// Check that {kJavaScriptCallCodeStartRegister} is correct.
void CodeGenerator::AssembleCodeStartRegisterCheck() {
  Register scratch = kScratchReg;
  __ ComputeCodeStartAddress(scratch);
  __ CmpS64(scratch, kJavaScriptCallCodeStartRegister);
  __ Assert(eq, AbortReason::kWrongFunctionCodeStart);
}

void CodeGenerator::BailoutIfDeoptimized() { __ BailoutIfDeoptimized(); }

// Assembles an instruction after register allocation, producing machine code.
CodeGenerator::CodeGenResult CodeGenerator::AssembleArchInstruction(
    Instruction* instr) {
  PPCOperandConverter i(this, instr);
  ArchOpcode opcode = ArchOpcodeField::decode(instr->opcode());

  switch (opcode) {
    case kArchCallCodeObject: {
      v8::internal::Assembler::BlockTrampolinePoolScope block_trampoline_pool(
          masm());
      if (HasRegisterInput(instr, 0)) {
        Register reg = i.InputRegister(0);
        DCHECK_IMPLIES(
            instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister),
            reg == kJavaScriptCallCodeStartRegister);
        __ CallCodeObject(reg);
      } else {
        __ Call(i.InputCode(0), RelocInfo::CODE_TARGET);
      }
      RecordCallPosition(instr);
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      frame_access_state()->ClearSPDelta();
      break;
    }
    case kArchCallBuiltinPointer: {
      DCHECK(!instr->InputAt(0)->IsImmediate());
      Register builtin_index = i.InputRegister(0);
      Register target =
          instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister)
              ? kJavaScriptCallCodeStartRegister
              : builtin_index;
      __ CallBuiltinByIndex(builtin_index, target);
      RecordCallPosition(instr);
      frame_access_state()->ClearSPDelta();
      break;
    }
#if V8_ENABLE_WEBASSEMBLY
    case kArchCallWasmFunction: {
      // We must not share code targets for calls to builtins for wasm code, as
      // they might need to be patched individually.
      if (instr->InputAt(0)->IsImmediate()) {
        Constant constant = i.ToConstant(instr->InputAt(0));
        Address wasm_code = static_cast<Address>(constant.ToInt64());
        __ Call(wasm_code, constant.rmode());
      } else {
        __ Call(i.InputRegister(0));
      }
      RecordCallPosition(instr);
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      frame_access_state()->ClearSPDelta();
      break;
    }
    case kArchTailCallWasm: {
      // We must not share code targets for calls to builtins for wasm code, as
      // they might need to be patched individually.
      if (instr->InputAt(0)->IsImmediate()) {
        Constant constant = i.ToConstant(instr->InputAt(0));
        Address wasm_code = static_cast<Address>(constant.ToInt64());
        __ Jump(wasm_code, constant.rmode());
      } else {
        __ Jump(i.InputRegister(0));
      }
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      frame_access_state()->ClearSPDelta();
      frame_access_state()->SetFrameAccessToDefault();
      break;
    }
#endif  // V8_ENABLE_WEBASSEMBLY
    case kArchTailCallCodeObject: {
      if (HasRegisterInput(instr, 0)) {
        Register reg = i.InputRegister(0);
        DCHECK_IMPLIES(
            instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister),
            reg == kJavaScriptCallCodeStartRegister);
        __ JumpCodeObject(reg);
      } else {
        // We cannot use the constant pool to load the target since
        // we've already restored the caller's frame.
        ConstantPoolUnavailableScope constant_pool_unavailable(masm());
        __ Jump(i.InputCode(0), RelocInfo::CODE_TARGET);
      }
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      frame_access_state()->ClearSPDelta();
      frame_access_state()->SetFrameAccessToDefault();
      break;
    }
    case kArchTailCallAddress: {
      CHECK(!instr->InputAt(0)->IsImmediate());
      Register reg = i.InputRegister(0);
      DCHECK_IMPLIES(
          instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister),
          reg == kJavaScriptCallCodeStartRegister);
      __ Jump(reg);
      frame_access_state()->ClearSPDelta();
      frame_access_state()->SetFrameAccessToDefault();
      break;
    }
    case kArchCallJSFunction: {
      v8::internal::Assembler::BlockTrampolinePoolScope block_trampoline_pool(
          masm());
      Register func = i.InputRegister(0);
      if (v8_flags.debug_code) {
        // Check the function's context matches the context argument.
        __ LoadTaggedField(
            kScratchReg, FieldMemOperand(func, JSFunction::kContextOffset), r0);
        __ CmpS64(cp, kScratchReg);
        __ Assert(eq, AbortReason::kWrongFunctionContext);
      }
      uint32_t num_arguments =
          i.InputUint32(instr->JSCallArgumentCountInputIndex());
      __ CallJSFunction(func, num_arguments, kScratchReg);
      RecordCallPosition(instr);
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      frame_access_state()->ClearSPDelta();
      break;
    }
    case kArchPrepareCallCFunction: {
      int const num_gp_parameters = ParamField::decode(instr->opcode());
      int const num_fp_parameters = FPParamField::decode(instr->opcode());
      __ PrepareCallCFunction(num_gp_parameters + num_fp_parameters,
                              kScratchReg);
      // Frame alignment requires using FP-relative frame addressing.
      frame_access_state()->SetFrameAccessToFP();
      break;
    }
    case kArchSaveCallerRegisters: {
      fp_mode_ =
          static_cast<SaveFPRegsMode>(MiscField::decode(instr->opcode()));
      DCHECK(fp_mode_ == SaveFPRegsMode::kIgnore ||
             fp_mode_ == SaveFPRegsMode::kSave);
      // kReturnRegister0 should have been saved before entering the stub.
      int bytes = __ PushCallerSaved(fp_mode_, ip, r0, kReturnRegister0);
      DCHECK(IsAligned(bytes, kSystemPointerSize));
      DCHECK_EQ(0, frame_access_state()->sp_delta());
      frame_access_state()->IncreaseSPDelta(bytes / kSystemPointerSize);
      DCHECK(!caller_registers_saved_);
      caller_registers_saved_ = true;
      break;
    }
    case kArchRestoreCallerRegisters: {
      DCHECK(fp_mode_ ==
             static_cast<SaveFPRegsMode>(MiscField::decode(instr->opcode())));
      DCHECK(fp_mode_ == SaveFPRegsMode::kIgnore ||
             fp_mode_ == SaveFPRegsMode::kSave);
      // Don't overwrite the returned value.
      int bytes = __ PopCallerSaved(fp_mode_, ip, r0, kReturnRegister0);
      frame_access_state()->IncreaseSPDelta(-(bytes / kSystemPointerSize));
      DCHECK_EQ(0, frame_access_state()->sp_delta());
      DCHECK(caller_registers_saved_);
      caller_registers_saved_ = false;
      break;
    }
    case kArchPrepareTailCall:
      AssemblePrepareTailCall();
      break;
    case kArchComment:
      __ RecordComment(reinterpret_cast<const char*>(i.InputInt64(0)),
                       SourceLocation());
      break;
    case kArchCallCFunctionWithFrameState:
    case kArchCallCFunction: {
      int const num_gp_parameters = ParamField::decode(instr->opcode());
      int const fp_param_field = FPParamField::decode(instr->opcode());
      int num_fp_parameters = fp_param_field;
      bool has_function_descriptor = false;
      SetIsolateDataSlots set_isolate_data_slots = SetIsolateDataSlots::kYes;
#if ABI_USES_FUNCTION_DESCRIPTORS
      // AIX/PPC64BE Linux uses a function descriptor
      int kNumFPParametersMask = kHasFunctionDescriptorBitMask - 1;
      num_fp_parameters = kNumFPParametersMask & fp_param_field;
      has_function_descriptor =
          (fp_param_field & kHasFunctionDescriptorBitMask) != 0;
#endif
#if V8_ENABLE_WEBASSEMBLY
      Label start_call;
      int start_pc_offset = 0;
      bool isWasmCapiFunction =
          linkage()->GetIncomingDescriptor()->IsWasmCapiFunction();
      if (isWasmCapiFunction) {
        __ mflr(r0);
        __ LoadPC(kScratchReg);
        __ bind(&start_call);
        start_pc_offset = __ pc_offset();
        // We are going to patch this instruction after emitting
        // CallCFunction, using a zero offset here as placeholder for now.
        // patch_pc_address assumes `addi` is used here to
        // add the offset to pc.
        __ addi(kScratchReg, kScratchReg, Operand::Zero());
        __ StoreU64(kScratchReg,
                    MemOperand(fp, WasmExitFrameConstants::kCallingPCOffset));
        __ mtlr(r0);
        set_isolate_data_slots = SetIsolateDataSlots::kNo;
      }
#endif  // V8_ENABLE_WEBASSEMBLY
      int pc_offset;
      if (instr->InputAt(0)->IsImmediate()) {
        ExternalReference ref = i.InputExternalReference(0);
        pc_offset =
            __ CallCFunction(ref, num_gp_parameters, num_fp_parameters,
                             set_isolate_data_slots, has_function_descriptor);
      } else {
        Register func = i.InputRegister(0);
        pc_offset =
            __ CallCFunction(func, num_gp_parameters, num_fp_parameters,
                             set_isolate_data_slots, has_function_descriptor);
      }
#if V8_ENABLE_WEBASSEMBLY
      if (isWasmCapiFunction) {
        int offset_since_start_call = pc_offset - start_pc_offset;
        // Here we are going to patch the `addi` instruction above to use the
        // correct offset.
        // LoadPC emits two instructions and pc is the address of its second
        // emitted instruction. Add one more to the offset to point to after the
        // Call.
        offset_since_start_call += kInstrSize;
        __ patch_pc_address(kScratchReg, start_pc_offset,
                            offset_since_start_call);
      }
#endif  // V8_ENABLE_WEBASSEMBLY
      RecordSafepoint(instr->reference_map(), pc_offset);

      bool const needs_frame_state =
          (opcode == kArchCallCFunctionWithFrameState);
      if (needs_frame_state) {
        RecordDeoptInfo(instr, pc_offset);
      }

      frame_access_state()->SetFrameAccessToDefault();
      // Ideally, we should decrement SP delta to match the change of stack
      // pointer in CallCFunction. However, for certain architectures (e.g.
      // ARM), there may be more strict alignment requirement, causing old SP
      // to be saved on the stack. In those cases, we can not calculate the SP
      // delta statically.
      frame_access_state()->ClearSPDelta();
      if (caller_registers_saved_) {
        // Need to re-sync SP delta introduced in kArchSaveCallerRegisters.
        // Here, we assume the sequence to be:
        //   kArchSaveCallerRegisters;
        //   kArchCallCFunction;
        //   kArchRestoreCallerRegisters;
        int bytes =
            __ RequiredStackSizeForCallerSaved(fp_mode_, kReturnRegister0);
        frame_access_state()->IncreaseSPDelta(bytes / kSystemPointerSize);
      }
      break;
    }
    case kArchJmp:
      AssembleArchJump(i.InputRpo(0));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kArchBinarySearchSwitch:
      AssembleArchBinarySearchSwitch(instr);
      break;
    case kArchTableSwitch:
      AssembleArchTableSwitch(instr);
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kArchAbortCSADcheck:
      DCHECK(i.InputRegister(0) == r4);
      {
        // We don't actually want to generate a pile of code for this, so just
        // claim there is a stack frame, without generating one.
        FrameScope scope(masm(), StackFrame::NO_FRAME_TYPE);
        __ CallBuiltin(Builtin::kAbortCSADcheck);
      }
      __ stop();
      break;
    case kArchDebugBreak:
      __ DebugBreak();
      break;
    case kArchNop:
    case kArchThrowTerminator:
      // don't emit code for nops.
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kArchDeoptimize: {
      DeoptimizationExit* exit =
          BuildTranslation(instr, -1, 0, 0, OutputFrameStateCombine::Ignore());
      __ b(exit->label());
      break;
    }
    case kArchRet:
      AssembleReturn(instr->InputAt(0));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kArchFramePointer:
      __ mr(i.OutputRegister(), fp);
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kArchParentFramePointer:
      if (frame_access_state()->has_frame()) {
        __ LoadU64(i.OutputRegister(), MemOperand(fp, 0));
      } else {
        __ mr(i.OutputRegister(), fp);
      }
      break;
#if V8_ENABLE_WEBASSEMBLY
    case kArchStackPointer:
      __ mr(i.OutputRegister(), sp);
      break;
    case kArchSetStackPointer: {
      DCHECK(instr->InputAt(0)->IsRegister());
      __ mr(sp, i.InputRegister(0));
      break;
    }
#endif  // V8_ENABLE_WEBASSEMBLY
    case kArchStackPointerGreaterThan: {
      // Potentially apply an offset to the current stack pointer before the
      // comparison to consider the size difference of an optimized frame versus
      // the contained unoptimized frames.

      Register lhs_register = sp;
      uint32_t offset;

      if (ShouldApplyOffsetToStackCheck(instr, &offset)) {
        lhs_register = i.TempRegister(0);
        __ SubS64(lhs_register, sp, Operand(offset), kScratchReg);
      }

      constexpr size_t kValueIndex = 0;
      DCHECK(instr->InputAt(kValueIndex)->IsRegister());
      __ CmpU64(lhs_register, i.InputRegister(kValueIndex), cr0);
      break;
    }
    case kArchStackCheckOffset:
      __ LoadSmiLiteral(i.OutputRegister(),
                        Smi::FromInt(GetStackCheckOffset()));
      break;
    case kArchTruncateDoubleToI:
      __ TruncateDoubleToI(isolate(), zone(), i.OutputRegister(),
                           i.InputDoubleRegister(0), DetermineStubCallMode());
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kArchStoreWithWriteBarrier: {
      RecordWriteMode mode = RecordWriteModeField::decode(instr->opcode());
      // Indirect pointer writes must use a different opcode.
      DCHECK_NE(mode, RecordWriteMode::kValueIsIndirectPointer);
      Register object = i.InputRegister(0);
      Register value = i.InputRegister(2);
      Register scratch0 = i.TempRegister(0);
      Register scratch1 = i.TempRegister(1);
      OutOfLineRecordWrite* ool;

      if (v8_flags.debug_code) {
        // Checking that |value| is not a cleared weakref: our write barrier
        // does not support that for now.
        __ CmpS64(value, Operand(kClearedWeakHeapObjectLower32), kScratchReg);
        __ Check(ne, AbortReason::kOperandIsCleared);
      }

      AddressingMode addressing_mode =
          AddressingModeField::decode(instr->opcode());
      if (addressing_mode == kMode_MRI) {
        int32_t offset = i.InputInt32(1);
        ool = zone()->New<OutOfLineRecordWrite>(
            this, object, offset, value, scratch0, scratch1, mode,
            DetermineStubCallMode(), &unwinding_info_writer_);
        __ StoreTaggedField(value, MemOperand(object, offset), r0);
      } else {
        DCHECK_EQ(kMode_MRR, addressing_mode);
        Register offset(i.InputRegister(1));
        ool = zone()->New<OutOfLineRecordWrite>(
            this, object, offset, value, scratch0, scratch1, mode,
            DetermineStubCallMode(), &unwinding_info_writer_);
        __ StoreTaggedField(value, MemOperand(object, offset), r0);
      }
      // Skip the write barrier if the value is a Smi. However, this is only
      // valid if the value isn't an indirect pointer. Otherwise the value will
      // be a pointer table index, which will always look like a Smi (but
      // actually reference a pointer in the pointer table).
      if (mode > RecordWriteMode::kValueIsIndirectPointer) {
        __ JumpIfSmi(value, ool->exit());
      }
      __ CheckPageFlag(object, scratch0,
                       MemoryChunk::kPointersFromHereAreInterestingMask, ne,
                       ool->entry());
      __ bind(ool->exit());
      break;
    }
    case kArchStoreIndirectWithWriteBarrier: {
      RecordWriteMode mode = RecordWriteModeField::decode(instr->opcode());
      Register scratch0 = i.TempRegister(0);
      Register scratch1 = i.TempRegister(1);
      OutOfLineRecordWrite* ool;
      DCHECK_EQ(mode, RecordWriteMode::kValueIsIndirectPointer);
      AddressingMode addressing_mode =
          AddressingModeField::decode(instr->opcode());
      Register object = i.InputRegister(0);
      Register value = i.InputRegister(2);
      IndirectPointerTag tag = static_cast<IndirectPointerTag>(i.InputInt64(3));
      DCHECK(IsValidIndirectPointerTag(tag));
      if (addressing_mode == kMode_MRI) {
        uint64_t offset = i.InputInt64(1);
        ool = zone()->New<OutOfLineRecordWrite>(
            this, object, offset, value, scratch0, scratch1, mode,
            DetermineStubCallMode(), &unwinding_info_writer_, tag);
        __ StoreIndirectPointerField(value, MemOperand(object, offset), r0);
      } else {
        DCHECK_EQ(addressing_mode, kMode_MRR);
        Register offset(i.InputRegister(1));
        ool = zone()->New<OutOfLineRecordWrite>(
            this, object, offset, value, scratch0, scratch1, mode,
            DetermineStubCallMode(), &unwinding_info_writer_, tag);
        __ StoreIndirectPointerField(value, MemOperand(object, offset), r0);
      }
      __ CheckPageFlag(object, scratch0,
                       MemoryChunk::kPointersFromHereAreInterestingMask, ne,
                       ool->entry());
      __ bind(ool->exit());
      break;
    }
    case kArchStackSlot: {
      FrameOffset offset =
          frame_access_state()->GetFrameOffset(i.InputInt32(0));
      __ AddS64(i.OutputRegister(), offset.from_stack_pointer() ? sp : fp,
                Operand(offset.offset()), r0);
      break;
    }
    case kPPC_Peek: {
      int reverse_slot = i.InputInt32(0);
      int offset =
          FrameSlotToFPOffset(frame()->GetTotalFrameSlotCount() - reverse_slot);
      if (instr->OutputAt(0)->IsFPRegister()) {
        LocationOperand* op = LocationOperand::cast(instr->OutputAt(0));
        if (op->representation() == MachineRepresentation::kFloat64) {
          __ LoadF64(i.OutputDoubleRegister(), MemOperand(fp, offset), r0);
        } else if (op->representation() == MachineRepresentation::kFloat32) {
          __ LoadF32(i.OutputFloatRegister(), MemOperand(fp, offset), r0);
        } else {
          DCHECK_EQ(MachineRepresentation::kSimd128, op->representation());
          __ LoadSimd128(i.OutputSimd128Register(), MemOperand(fp, offset),
                         kScratchReg);
        }
      } else {
        __ LoadU64(i.OutputRegister(), MemOperand(fp, offset), r0);
      }
      break;
    }
    case kPPC_Sync: {
      __ sync();
      break;
    }
    case kPPC_And:
      if (HasRegisterInput(instr, 1)) {
        __ and_(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
                i.OutputRCBit());
      } else {
        __ andi(i.OutputRegister(), i.InputRegister(0), i.InputImmediate(1));
      }
      break;
    case kPPC_AndComplement:
      __ andc(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
              i.OutputRCBit());
      break;
    case kPPC_Or:
      if (HasRegisterInput(instr, 1)) {
        __ orx(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
               i.OutputRCBit());
      } else {
        __ ori(i.OutputRegister(), i.InputRegister(0), i.InputImmediate(1));
        DCHECK_EQ(LeaveRC, i.OutputRCBit());
      }
      break;
    case kPPC_OrComplement:
      __ orc(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
             i.OutputRCBit());
      break;
    case kPPC_Xor:
      if (HasRegisterInput(instr, 1)) {
        __ xor_(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
                i.OutputRCBit());
      } else {
        __ xori(i.OutputRegister(), i.InputRegister(0), i.InputImmediate(1));
        DCHECK_EQ(LeaveRC, i.OutputRCBit());
      }
      break;
    case kPPC_ShiftLeft32:
      ASSEMBLE_BINOP_RC(ShiftLeftU32, ShiftLeftU32);
      break;
    case kPPC_ShiftLeft64:
      ASSEMBLE_BINOP_RC(ShiftLeftU64, ShiftLeftU64);
      break;
    case kPPC_ShiftRight32:
      ASSEMBLE_BINOP_RC(ShiftRightU32, ShiftRightU32);
      break;
    case kPPC_ShiftRight64:
      ASSEMBLE_BINOP_RC(ShiftRightU64, ShiftRightU64);
      break;
    case kPPC_ShiftRightAlg32:
      ASSEMBLE_BINOP_INT_RC(ShiftRightS32, ShiftRightS32);
      break;
    case kPPC_ShiftRightAlg64:
      ASSEMBLE_BINOP_INT_RC(ShiftRightS64, ShiftRightS64);
      break;
    case kPPC_RotRight32:
      if (HasRegisterInput(instr, 1)) {
        __ subfic(kScratchReg, i.InputRegister(1), Operand(32));
        __ rotlw(i.OutputRegister(), i.InputRegister(0), kScratchReg,
                 i.OutputRCBit());
      } else {
        int sh = i.InputInt32(1);
        __ rotrwi(i.OutputRegister(), i.InputRegister(0), sh, i.OutputRCBit());
      }
      break;
    case kPPC_RotRight64:
      if (HasRegisterInput(instr, 1)) {
        __ subfic(kScratchReg, i.InputRegister(1), Operand(64));
        __ rotld(i.OutputRegister(), i.InputRegister(0), kScratchReg,
                 i.OutputRCBit());
      } else {
        int sh = i.InputInt32(1);
        __ rotrdi(i.OutputRegister(), i.InputRegister(0), sh, i.OutputRCBit());
      }
      break;
    case kPPC_Not:
      __ notx(i.OutputRegister(), i.InputRegister(0), i.OutputRCBit());
      break;
    case kPPC_RotLeftAndMask32:
      __ rlwinm(i.OutputRegister(), i.InputRegister(0), i.InputInt32(1),
                31 - i.InputInt32(2), 31 - i.InputInt32(3), i.OutputRCBit());
      break;
    case kPPC_RotLeftAndClear64:
      __ rldic(i.OutputRegister(), i.InputRegister(0), i.InputInt32(1),
               63 - i.InputInt32(2), i.OutputRCBit());
      break;
    case kPPC_RotLeftAndClearLeft64:
      __ rldicl(i.OutputRegister(), i.InputRegister(0), i.InputInt32(1),
                63 - i.InputInt32(2), i.OutputRCBit());
      break;
    case kPPC_RotLeftAndClearRight64:
      __ rldicr(i.OutputRegister(), i.InputRegister(0), i.InputInt32(1),
                63 - i.InputInt32(2), i.OutputRCBit());
      break;
    case kPPC_Add32:
      if (FlagsModeField::decode(instr->opcode()) != kFlags_none) {
        ASSEMBLE_ADD_WITH_OVERFLOW();
      } else {
        if (HasRegisterInput(instr, 1)) {
          __ add(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
                 LeaveOE, i.OutputRCBit());
        } else {
          __ AddS64(i.OutputRegister(), i.InputRegister(0), i.InputImmediate(1),
                    r0, LeaveOE, i.OutputRCBit());
        }
        __ extsw(i.OutputRegister(), i.OutputRegister());
      }
      break;
    case kPPC_Add64:
      if (FlagsModeField::decode(instr->opcode()) != kFlags_none) {
        ASSEMBLE_ADD_WITH_OVERFLOW();
      } else {
        if (HasRegisterInput(instr, 1)) {
          __ add(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
                 LeaveOE, i.OutputRCBit());
        } else {
          __ AddS64(i.OutputRegister(), i.InputRegister(0), i.InputImmediate(1),
                    r0, LeaveOE, i.OutputRCBit());
        }
      }
      break;
    case kPPC_AddWithOverflow32:
      ASSEMBLE_ADD_WITH_OVERFLOW32();
      break;
    case kPPC_AddDouble:
      ASSEMBLE_FLOAT_BINOP_RC(fadd, MiscField::decode(instr->opcode()));
      break;
    case kPPC_Sub:
      if (FlagsModeField::decode(instr->opcode()) != kFlags_none) {
        ASSEMBLE_SUB_WITH_OVERFLOW();
      } else {
        if (HasRegisterInput(instr, 1)) {
          __ sub(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
                 LeaveOE, i.OutputRCBit());
        } else {
          __ SubS64(i.OutputRegister(), i.InputRegister(0), i.InputImmediate(1),
                    r0, LeaveOE, i.OutputRCBit());
        }
      }
      break;
    case kPPC_SubWithOverflow32:
      ASSEMBLE_SUB_WITH_OVERFLOW32();
      break;
    case kPPC_SubDouble:
      ASSEMBLE_FLOAT_BINOP_RC(fsub, MiscField::decode(instr->opcode()));
      break;
    case kPPC_Mul32:
      __ mullw(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
               LeaveOE, i.OutputRCBit());
      break;
    case kPPC_Mul64:
      __ mulld(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
               LeaveOE, i.OutputRCBit());
      break;
    case kPPC_Mul32WithHigh32:
      if (i.OutputRegister(0) == i.InputRegister(0) ||
          i.OutputRegister(0) == i.InputRegister(1) ||
          i.OutputRegister(1) == i.InputRegister(0) ||
          i.OutputRegister(1) == i.InputRegister(1)) {
        __ mullw(kScratchReg, i.InputRegister(0), i.InputRegister(1));  // low
        __ mulhw(i.OutputRegister(1), i.InputRegister(0),
                 i.InputRegister(1));  // high
        __ mr(i.OutputRegister(0), kScratchReg);
      } else {
        __ mullw(i.OutputRegister(0), i.InputRegister(0),
                 i.InputRegister(1));  // low
        __ mulhw(i.OutputRegister(1), i.InputRegister(0),
                 i.InputRegister(1));  // high
      }
      break;
    case kPPC_MulHighS64:
      __ mulhd(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
               i.OutputRCBit());
      break;
    case kPPC_MulHighU64:
      __ mulhdu(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
                i.OutputRCBit());
      break;
    case kPPC_MulHigh32:
      __ mulhw(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
               i.OutputRCBit());
      // High 32 bits are undefined and need to be cleared.
      CleanUInt32(i.OutputRegister());
      break;
    case kPPC_MulHighU32:
      __ mulhwu(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
                i.OutputRCBit());
      // High 32 bits are undefined and need to be cleared.
      CleanUInt32(i.OutputRegister());
      break;
    case kPPC_MulDouble:
      ASSEMBLE_FLOAT_BINOP_RC(fmul, MiscField::decode(instr->opcode()));
      break;
    case kPPC_Div32:
      __ divw(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Div64:
      __ divd(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_DivU32:
      __ divwu(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_DivU64:
      __ divdu(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_DivDouble:
      ASSEMBLE_FLOAT_BINOP_RC(fdiv, MiscField::decode(instr->opcode()));
      break;
    case kPPC_Mod32:
      if (CpuFeatures::IsSupported(PPC_9_PLUS)) {
        __ modsw(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        ASSEMBLE_MODULO(divw, mullw);
      }
      break;
    case kPPC_Mod64:
      if (CpuFeatures::IsSupported(PPC_9_PLUS)) {
        __ modsd(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        ASSEMBLE_MODULO(divd, mulld);
      }
      break;
    case kPPC_ModU32:
      if (CpuFeatures::IsSupported(PPC_9_PLUS)) {
        __ moduw(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        ASSEMBLE_MODULO(divwu, mullw);
      }
      break;
    case kPPC_ModU64:
      if (CpuFeatures::IsSupported(PPC_9_PLUS)) {
        __ modud(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        ASSEMBLE_MODULO(divdu, mulld);
      }
      break;
    case kPPC_ModDouble:
      // TODO(bmeurer): We should really get rid of this special instruction,
      // and generate a CallAddress instruction instead.
      ASSEMBLE_FLOAT_MODULO();
      break;
    case kIeee754Float64Acos:
      ASSEMBLE_IEEE754_UNOP(acos);
      break;
    case kIeee754Float64Acosh:
      ASSEMBLE_IEEE754_UNOP(acosh);
      break;
    case kIeee754Float64Asin:
      ASSEMBLE_IEEE754_UNOP(asin);
      break;
    case kIeee754Float64Asinh:
      ASSEMBLE_IEEE754_UNOP(asinh);
      break;
    case kIeee754Float64Atan:
      ASSEMBLE_IEEE754_UNOP(atan);
      break;
    case kIeee754Float64Atan2:
      ASSEMBLE_IEEE754_BINOP(atan2);
      break;
    case kIeee754Float64Atanh:
      ASSEMBLE_IEEE754_UNOP(atanh);
      break;
    case kIeee754Float64Tan:
      ASSEMBLE_IEEE754_UNOP(tan);
      break;
    case kIeee754Float64Tanh:
      ASSEMBLE_IEEE754_UNOP(tanh);
      break;
    case kIeee754Float64Cbrt:
      ASSEMBLE_IEEE754_UNOP(cbrt);
      break;
    case kIeee754Float64Sin:
      ASSEMBLE_IEEE754_UNOP(sin);
      break;
    case kIeee754Float64Sinh:
      ASSEMBLE_IEEE754_UNOP(sinh);
      break;
    case kIeee754Float64Cos:
      ASSEMBLE_IEEE754_UNOP(cos);
      break;
    case kIeee754Float64Cosh:
      ASSEMBLE_IEEE754_UNOP(cosh);
      break;
    case kIeee754Float64Exp:
      ASSEMBLE_IEEE754_UNOP(exp);
      break;
    case kIeee754Float64Expm1:
      ASSEMBLE_IEEE754_UNOP(expm1);
      break;
    case kIeee754Float64Log:
      ASSEMBLE_IEEE754_UNOP(log);
      break;
    case kIeee754Float64Log1p:
      ASSEMBLE_IEEE754_UNOP(log1p);
      break;
    case kIeee754Float64Log2:
      ASSEMBLE_IEEE754_UNOP(log2);
      break;
```