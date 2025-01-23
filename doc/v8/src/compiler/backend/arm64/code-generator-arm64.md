Response: The user wants a summary of the provided C++ code, specifically focusing on its functionality within the V8 JavaScript engine.

Here's a breakdown of how to approach this:

1. **Identify the Core Class:** The code defines a class `CodeGenerator` and related helper classes like `Arm64OperandConverter`. This suggests the primary function is generating machine code.

2. **Target Architecture:** The file name `code-generator-arm64.cc` and the inclusion of ARM64-specific headers (`assembler-arm64-inl.h`, `constants-arm64.h`, etc.) clearly indicate this code is for the ARM64 architecture.

3. **Integration with V8 Compiler:** The `#include` directives for files like `src/compiler/backend/code-generator-impl.h`, `src/compiler/backend/code-generator.h`, and `src/compiler/backend/instruction-codes.h` show this code is part of V8's compiler backend. It takes higher-level instructions and translates them into machine code.

4. **Operand Handling:** The `Arm64OperandConverter` class is responsible for converting abstract `InstructionOperand` objects into concrete ARM64 operands (registers, immediates, memory addresses).

5. **Instruction Assembly:** The `AssembleArchInstruction` method within `CodeGenerator` is a key function. It dispatches based on the `arch_opcode` and generates the corresponding ARM64 assembly instructions using the `MacroAssembler`.

6. **Specific Operations:** The code includes implementations for various operations, including:
    * Function calls (regular and tail calls)
    * Handling of builtin functions
    * Interaction with the C++ runtime
    * Stack frame management
    * Floating-point operations
    * Integer arithmetic and logic
    * Memory access (loads and stores, including write barriers for garbage collection)
    * Atomic operations
    * SIMD (NEON) instructions

7. **Relationship to JavaScript:** The code's role is to translate JavaScript code (represented in an intermediate representation) into executable machine code. It handles the low-level details of how JavaScript concepts (like function calls, object properties, arithmetic) are implemented on the ARM64 architecture.

8. **Example Construction (Mental Walkthrough):** To illustrate the connection with JavaScript, consider a simple JavaScript addition: `let x = a + b;`. The V8 compiler would:
    * Parse the JavaScript and create an Abstract Syntax Tree (AST).
    * Optimize the AST.
    * Generate intermediate instructions (potentially represented by the `Instruction` class used in this code).
    * The `CodeGenerator` would then take these instructions and, for the addition operation, might generate an `kArm64Add` instruction.
    * The `Arm64OperandConverter` would determine the ARM64 registers holding the values of `a` and `b` and the destination register for `x`.
    * The `MacroAssembler` would then emit the actual `add` assembly instruction.

Based on this thinking process, I can formulate the summary and the JavaScript example.
这个C++源代码文件 `code-generator-arm64.cc` 的主要功能是 **为V8 JavaScript引擎的TurboFan优化编译器生成ARM64架构的机器码**。

更具体地说，它的作用是：

1. **将编译器后端生成的与架构无关的指令 (Instruction) 转换为具体的ARM64汇编指令。**  它实现了 `CodeGenerator` 抽象基类，并提供了 ARM64 架构特有的代码生成逻辑。

2. **处理各种不同的指令类型，包括算术运算、逻辑运算、内存访问、函数调用、控制流等等。**  `AssembleArchInstruction` 函数是核心，它根据指令的操作码 (opcode) 分发到不同的代码生成逻辑。

3. **管理寄存器分配和使用。** 虽然寄存器分配不是这个文件的直接职责，但它需要根据已经分配好的寄存器来生成正确的汇编指令。`Arm64OperandConverter` 类负责将指令的操作数转换为ARM64汇编器可以理解的形式，包括寄存器、立即数和内存地址。

4. **处理与垃圾回收相关的写屏障 (Write Barrier)。**  当修改堆对象时，需要记录这些修改以供垃圾回收器使用。代码中包含 `OutOfLineRecordWrite` 类和相关的代码生成逻辑来插入写屏障。

5. **支持WebAssembly (如果 `V8_ENABLE_WEBASSEMBLY` 宏被定义)。** 代码中包含了对WebAssembly特定的函数调用和尾调用的处理。

**与 JavaScript 功能的关系：**

这个文件是 V8 引擎将 JavaScript 代码转换为可执行机器码的关键部分。当 V8 执行 JavaScript 代码时，TurboFan 优化编译器会将 JavaScript 代码编译成一系列的中间指令。然后，`code-generator-arm64.cc`  这个文件会将这些中间指令翻译成实际可以在 ARM64 处理器上运行的机器码。

**JavaScript 示例：**

假设有以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

当 V8 执行这段代码并使用 TurboFan 编译 `add` 函数时，`code-generator-arm64.cc` 会参与生成类似以下的 ARM64 汇编代码（这只是一个简化的概念性例子）：

```assembly
// ... 函数入口 ...

// 加载参数 a 到寄存器 x0
ldr x0, [fp, #offset_a]

// 加载参数 b 到寄存器 x1
ldr x1, [fp, #offset_b]

// 执行加法运算，结果存储在 x0
add x0, x0, x1

// 将结果返回
mov w0, w0  // 确保返回的是 32 位的值 (假设是整数)
// 或者如果 a 和 b 是浮点数
// fadd d0, d0, d1

// ... 函数返回 ...
```

在这个例子中，`code-generator-arm64.cc` 会负责生成 `ldr` (load register)、`add` (加法) 和 `mov` (移动) 等 ARM64 指令，这些指令对应了 JavaScript 代码中的加法运算和变量访问。它会根据变量的类型（整数或浮点数）选择合适的 ARM64 指令。

总而言之，`code-generator-arm64.cc` 是 V8 引擎将高级 JavaScript 代码转换为底层机器码的桥梁，使得 JavaScript 代码能够在 ARM64 架构的设备上高效运行。

### 提示词
```
这是目录为v8/src/compiler/backend/arm64/code-generator-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/codegen/arm64/assembler-arm64-inl.h"
#include "src/codegen/arm64/constants-arm64.h"
#include "src/codegen/arm64/macro-assembler-arm64-inl.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/machine-type.h"
#include "src/codegen/optimized-compilation-info.h"
#include "src/compiler/backend/code-generator-impl.h"
#include "src/compiler/backend/code-generator.h"
#include "src/compiler/backend/gap-resolver.h"
#include "src/compiler/backend/instruction-codes.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/osr.h"
#include "src/execution/frame-constants.h"
#include "src/heap/mutable-page-metadata.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-objects.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {
namespace compiler {

#define __ masm()->

// Adds Arm64-specific methods to convert InstructionOperands.
class Arm64OperandConverter final : public InstructionOperandConverter {
 public:
  Arm64OperandConverter(CodeGenerator* gen, Instruction* instr)
      : InstructionOperandConverter(gen, instr) {}

  DoubleRegister InputFloat32Register(size_t index) {
    return InputDoubleRegister(index).S();
  }

  DoubleRegister InputFloat64Register(size_t index) {
    return InputDoubleRegister(index);
  }

  DoubleRegister InputSimd128Register(size_t index) {
    return InputDoubleRegister(index).Q();
  }

  CPURegister InputFloat32OrZeroRegister(size_t index) {
    if (instr_->InputAt(index)->IsImmediate()) {
      DCHECK_EQ(0, base::bit_cast<int32_t>(InputFloat32(index)));
      return wzr;
    }
    DCHECK(instr_->InputAt(index)->IsFPRegister());
    return InputDoubleRegister(index).S();
  }

  DoubleRegister InputFloat32OrFPZeroRegister(size_t index) {
    if (instr_->InputAt(index)->IsImmediate()) {
      DCHECK_EQ(0, base::bit_cast<int32_t>(InputFloat32(index)));
      return fp_zero.S();
    }
    DCHECK(instr_->InputAt(index)->IsFPRegister());
    return InputDoubleRegister(index).S();
  }

  CPURegister InputFloat64OrZeroRegister(size_t index) {
    if (instr_->InputAt(index)->IsImmediate()) {
      DCHECK_EQ(0, base::bit_cast<int64_t>(InputDouble(index)));
      return xzr;
    }
    DCHECK(instr_->InputAt(index)->IsDoubleRegister());
    return InputDoubleRegister(index);
  }

  DoubleRegister InputFloat64OrFPZeroRegister(size_t index) {
    if (instr_->InputAt(index)->IsImmediate()) {
      DCHECK_EQ(0, base::bit_cast<int64_t>(InputDouble(index)));
      return fp_zero;
    }
    DCHECK(instr_->InputAt(index)->IsDoubleRegister());
    return InputDoubleRegister(index);
  }

  size_t OutputCount() { return instr_->OutputCount(); }

  DoubleRegister OutputFloat32Register(size_t index = 0) {
    return OutputDoubleRegister(index).S();
  }

  DoubleRegister OutputFloat64Register(size_t index = 0) {
    return OutputDoubleRegister(index);
  }

  DoubleRegister OutputSimd128Register() { return OutputDoubleRegister().Q(); }

  Register InputRegister32(size_t index) {
    return ToRegister(instr_->InputAt(index)).W();
  }

  Register InputOrZeroRegister32(size_t index) {
    DCHECK(instr_->InputAt(index)->IsRegister() ||
           (instr_->InputAt(index)->IsImmediate() && (InputInt32(index) == 0)));
    if (instr_->InputAt(index)->IsImmediate()) {
      return wzr;
    }
    return InputRegister32(index);
  }

  Register InputRegister64(size_t index) { return InputRegister(index); }

  Register InputOrZeroRegister64(size_t index) {
    DCHECK(instr_->InputAt(index)->IsRegister() ||
           (instr_->InputAt(index)->IsImmediate() && (InputInt64(index) == 0)));
    if (instr_->InputAt(index)->IsImmediate()) {
      return xzr;
    }
    return InputRegister64(index);
  }

  Operand InputOperand(size_t index) {
    return ToOperand(instr_->InputAt(index));
  }

  Operand InputOperand64(size_t index) { return InputOperand(index); }

  Operand InputOperand32(size_t index) {
    return ToOperand32(instr_->InputAt(index));
  }

  Register OutputRegister64(size_t index = 0) { return OutputRegister(index); }

  Register OutputRegister32(size_t index = 0) {
    return OutputRegister(index).W();
  }

  Register TempRegister32(size_t index) {
    return ToRegister(instr_->TempAt(index)).W();
  }

  Operand InputOperand2_32(size_t index) {
    switch (AddressingModeField::decode(instr_->opcode())) {
      case kMode_None:
        return InputOperand32(index);
      case kMode_Operand2_R_LSL_I:
        return Operand(InputRegister32(index), LSL, InputInt5(index + 1));
      case kMode_Operand2_R_LSR_I:
        return Operand(InputRegister32(index), LSR, InputInt5(index + 1));
      case kMode_Operand2_R_ASR_I:
        return Operand(InputRegister32(index), ASR, InputInt5(index + 1));
      case kMode_Operand2_R_ROR_I:
        return Operand(InputRegister32(index), ROR, InputInt5(index + 1));
      case kMode_Operand2_R_UXTB:
        return Operand(InputRegister32(index), UXTB);
      case kMode_Operand2_R_UXTH:
        return Operand(InputRegister32(index), UXTH);
      case kMode_Operand2_R_SXTB:
        return Operand(InputRegister32(index), SXTB);
      case kMode_Operand2_R_SXTH:
        return Operand(InputRegister32(index), SXTH);
      case kMode_Operand2_R_SXTW:
        return Operand(InputRegister32(index), SXTW);
      case kMode_MRI:
      case kMode_MRR:
      case kMode_Root:
        break;
    }
    UNREACHABLE();
  }

  Operand InputOperand2_64(size_t index) {
    switch (AddressingModeField::decode(instr_->opcode())) {
      case kMode_None:
        return InputOperand64(index);
      case kMode_Operand2_R_LSL_I:
        return Operand(InputRegister64(index), LSL, InputInt6(index + 1));
      case kMode_Operand2_R_LSR_I:
        return Operand(InputRegister64(index), LSR, InputInt6(index + 1));
      case kMode_Operand2_R_ASR_I:
        return Operand(InputRegister64(index), ASR, InputInt6(index + 1));
      case kMode_Operand2_R_ROR_I:
        return Operand(InputRegister64(index), ROR, InputInt6(index + 1));
      case kMode_Operand2_R_UXTB:
        return Operand(InputRegister64(index), UXTB);
      case kMode_Operand2_R_UXTH:
        return Operand(InputRegister64(index), UXTH);
      case kMode_Operand2_R_SXTB:
        return Operand(InputRegister64(index), SXTB);
      case kMode_Operand2_R_SXTH:
        return Operand(InputRegister64(index), SXTH);
      case kMode_Operand2_R_SXTW:
        return Operand(InputRegister64(index), SXTW);
      case kMode_MRI:
      case kMode_MRR:
      case kMode_Root:
        break;
    }
    UNREACHABLE();
  }

  MemOperand MemoryOperand(size_t index = 0) {
    switch (AddressingModeField::decode(instr_->opcode())) {
      case kMode_None:
      case kMode_Operand2_R_LSR_I:
      case kMode_Operand2_R_ASR_I:
      case kMode_Operand2_R_ROR_I:
      case kMode_Operand2_R_UXTB:
      case kMode_Operand2_R_UXTH:
      case kMode_Operand2_R_SXTB:
      case kMode_Operand2_R_SXTH:
      case kMode_Operand2_R_SXTW:
        break;
      case kMode_Root:
        return MemOperand(kRootRegister, InputInt64(index));
      case kMode_Operand2_R_LSL_I:
        return MemOperand(InputRegister(index + 0), InputRegister(index + 1),
                          LSL, InputInt32(index + 2));
      case kMode_MRI:
        return MemOperand(InputRegister(index + 0), InputInt32(index + 1));
      case kMode_MRR:
        return MemOperand(InputRegister(index + 0), InputRegister(index + 1));
    }
    UNREACHABLE();
  }

  Operand ToOperand(InstructionOperand* op) {
    if (op->IsRegister()) {
      return Operand(ToRegister(op));
    }
    return ToImmediate(op);
  }

  Operand ToOperand32(InstructionOperand* op) {
    if (op->IsRegister()) {
      return Operand(ToRegister(op).W());
    }
    return ToImmediate(op);
  }

  Operand ToImmediate(InstructionOperand* operand) {
    Constant constant = ToConstant(operand);
    switch (constant.type()) {
      case Constant::kInt32:
        return Operand(constant.ToInt32(), constant.rmode());
      case Constant::kInt64:
        return Operand(constant.ToInt64(), constant.rmode());
      case Constant::kFloat32:
        return Operand::EmbeddedNumber(constant.ToFloat32());
      case Constant::kFloat64:
        return Operand::EmbeddedNumber(constant.ToFloat64().value());
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
          CHECK(Assembler::IsImmAddSub(ptr));
          return Immediate(ptr);
        }

        return Operand(constant.ToHeapObject());
      }
      case Constant::kHeapObject:
        return Operand(constant.ToHeapObject());
      case Constant::kRpoNumber:
        UNREACHABLE();  // TODO(dcarney): RPO immediates on arm64.
    }
    UNREACHABLE();
  }

  MemOperand ToMemOperand(InstructionOperand* op, MacroAssembler* masm) const {
    DCHECK_NOT_NULL(op);
    DCHECK(op->IsStackSlot() || op->IsFPStackSlot());
    return SlotToMemOperand(AllocatedOperand::cast(op)->index(), masm);
  }

  MemOperand SlotToMemOperand(int slot, MacroAssembler* masm) const {
    FrameOffset offset = frame_access_state()->GetFrameOffset(slot);
    if (offset.from_frame_pointer()) {
      int from_sp = offset.offset() + frame_access_state()->GetSPToFPOffset();
      // Convert FP-offsets to SP-offsets if it results in better code.
      if (!frame_access_state()->FPRelativeOnly() &&
          (Assembler::IsImmLSUnscaled(from_sp) ||
           Assembler::IsImmLSScaled(from_sp, 3))) {
        offset = FrameOffset::FromStackPointer(from_sp);
      }
    }
    // Access below the stack pointer is not expected in arm64 and is actively
    // prevented at run time in the simulator.
    DCHECK_IMPLIES(offset.from_stack_pointer(), offset.offset() >= 0);
    return MemOperand(offset.from_stack_pointer() ? sp : fp, offset.offset());
  }
};

namespace {

class OutOfLineRecordWrite final : public OutOfLineCode {
 public:
  OutOfLineRecordWrite(
      CodeGenerator* gen, Register object, Operand offset, Register value,
      RecordWriteMode mode, StubCallMode stub_mode,
      UnwindingInfoWriter* unwinding_info_writer,
      IndirectPointerTag indirect_pointer_tag = kIndirectPointerNullTag)
      : OutOfLineCode(gen),
        object_(object),
        offset_(offset),
        value_(value),
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
    // When storing an indirect pointer, the value will always be a
    // full/decompressed pointer.
    if (COMPRESS_POINTERS_BOOL &&
        mode_ != RecordWriteMode::kValueIsIndirectPointer) {
      __ DecompressTagged(value_, value_);
    }

    // No need to check value page flags with the indirect pointer write barrier
    // because the value is always an ExposedTrustedObject.
    if (mode_ != RecordWriteMode::kValueIsIndirectPointer) {
      __ CheckPageFlag(value_, MemoryChunk::kPointersToHereAreInterestingMask,
                       eq, exit());
    }

    SaveFPRegsMode const save_fp_mode = frame()->DidAllocateDoubleRegisters()
                                            ? SaveFPRegsMode::kSave
                                            : SaveFPRegsMode::kIgnore;
    if (must_save_lr_) {
      // We need to save and restore lr if the frame was elided.
      __ Push<MacroAssembler::kSignLR>(lr, padreg);
      unwinding_info_writer_->MarkLinkRegisterOnTopOfStack(__ pc_offset(), sp);
    }
    if (mode_ == RecordWriteMode::kValueIsEphemeronKey) {
      __ CallEphemeronKeyBarrier(object_, offset_, save_fp_mode);
    } else if (mode_ == RecordWriteMode::kValueIsIndirectPointer) {
      // We must have a valid indirect pointer tag here. Otherwise, we risk not
      // invoking the correct write barrier, which may lead to subtle issues.
      CHECK(IsValidIndirectPointerTag(indirect_pointer_tag_));
      __ CallIndirectPointerBarrier(object_, offset_, save_fp_mode,
                                    indirect_pointer_tag_);
#if V8_ENABLE_WEBASSEMBLY
    } else if (stub_mode_ == StubCallMode::kCallWasmRuntimeStub) {
      // A direct call to a wasm runtime stub defined in this module.
      // Just encode the stub index. This will be patched when the code
      // is added to the native module and copied into wasm code space.
      __ CallRecordWriteStubSaveRegisters(object_, offset_, save_fp_mode,
                                          StubCallMode::kCallWasmRuntimeStub);
#endif  // V8_ENABLE_WEBASSEMBLY
    } else {
      __ CallRecordWriteStubSaveRegisters(object_, offset_, save_fp_mode);
    }
    if (must_save_lr_) {
      __ Pop<MacroAssembler::kAuthLR>(padreg, lr);
      unwinding_info_writer_->MarkPopLinkRegisterFromTopOfStack(__ pc_offset());
    }
  }

 private:
  Register const object_;
  Operand const offset_;
  Register const value_;
  RecordWriteMode const mode_;
#if V8_ENABLE_WEBASSEMBLY
  StubCallMode const stub_mode_;
#endif  // V8_ENABLE_WEBASSEMBLY
  bool must_save_lr_;
  UnwindingInfoWriter* const unwinding_info_writer_;
  Zone* zone_;
  IndirectPointerTag indirect_pointer_tag_;
};

Condition FlagsConditionToCondition(FlagsCondition condition) {
  switch (condition) {
    case kEqual:
      return eq;
    case kNotEqual:
      return ne;
    case kSignedLessThan:
      return lt;
    case kSignedGreaterThanOrEqual:
      return ge;
    case kSignedLessThanOrEqual:
      return le;
    case kSignedGreaterThan:
      return gt;
    case kUnsignedLessThan:
      return lo;
    case kUnsignedGreaterThanOrEqual:
      return hs;
    case kUnsignedLessThanOrEqual:
      return ls;
    case kUnsignedGreaterThan:
      return hi;
    case kFloatLessThanOrUnordered:
      return lt;
    case kFloatGreaterThanOrEqual:
      return ge;
    case kFloatLessThanOrEqual:
      return ls;
    case kFloatGreaterThanOrUnordered:
      return hi;
    case kFloatLessThan:
      return lo;
    case kFloatGreaterThanOrEqualOrUnordered:
      return hs;
    case kFloatLessThanOrEqualOrUnordered:
      return le;
    case kFloatGreaterThan:
      return gt;
    case kOverflow:
      return vs;
    case kNotOverflow:
      return vc;
    case kUnorderedEqual:
    case kUnorderedNotEqual:
    case kIsNaN:
    case kIsNotNaN:
      break;
    case kPositiveOrZero:
      return pl;
    case kNegative:
      return mi;
  }
  UNREACHABLE();
}

#if V8_ENABLE_WEBASSEMBLY
class WasmOutOfLineTrap : public OutOfLineCode {
 public:
  WasmOutOfLineTrap(CodeGenerator* gen, Instruction* instr)
      : OutOfLineCode(gen), gen_(gen), instr_(instr) {}
  void Generate() override {
    Arm64OperandConverter i(gen_, instr_);
    TrapId trap_id =
        static_cast<TrapId>(i.InputInt32(instr_->InputCount() - 1));
    GenerateCallToTrap(trap_id);
  }

 protected:
  CodeGenerator* gen_;

  void GenerateWithTrapId(TrapId trap_id) { GenerateCallToTrap(trap_id); }

 private:
  void GenerateCallToTrap(TrapId trap_id) {
    gen_->AssembleSourcePosition(instr_);
    __ Call(static_cast<Address>(trap_id), RelocInfo::WASM_STUB_CALL);
    ReferenceMap* reference_map = gen_->zone()->New<ReferenceMap>(gen_->zone());
    gen_->RecordSafepoint(reference_map);
    __ AssertUnreachable(AbortReason::kUnexpectedReturnFromWasmTrap);
  }

  Instruction* instr_;
};

void RecordTrapInfoIfNeeded(Zone* zone, CodeGenerator* codegen,
                            InstructionCode opcode, Instruction* instr,
                            int pc) {
  const MemoryAccessMode access_mode = AccessModeField::decode(opcode);
  if (access_mode == kMemoryAccessProtectedMemOutOfBounds ||
      access_mode == kMemoryAccessProtectedNullDereference) {
    codegen->RecordProtectedInstruction(pc);
  }
}
#else
void RecordTrapInfoIfNeeded(Zone* zone, CodeGenerator* codegen,
                            InstructionCode opcode, Instruction* instr,
                            int pc) {
  DCHECK_EQ(kMemoryAccessDirect, AccessModeField::decode(opcode));
}
#endif  // V8_ENABLE_WEBASSEMBLY

// Handles unary ops that work for float (scalar), double (scalar), or NEON.
template <typename Fn>
void EmitFpOrNeonUnop(MacroAssembler* masm, Fn fn, Instruction* instr,
                      Arm64OperandConverter i, VectorFormat scalar,
                      VectorFormat vector) {
  VectorFormat f = instr->InputAt(0)->IsSimd128Register() ? vector : scalar;

  VRegister output = VRegister::Create(i.OutputDoubleRegister().code(), f);
  VRegister input = VRegister::Create(i.InputDoubleRegister(0).code(), f);
  (masm->*fn)(output, input);
}

}  // namespace

#define ASSEMBLE_SHIFT(asm_instr, width)                                    \
  do {                                                                      \
    if (instr->InputAt(1)->IsRegister()) {                                  \
      __ asm_instr(i.OutputRegister##width(), i.InputRegister##width(0),    \
                   i.InputRegister##width(1));                              \
    } else {                                                                \
      uint32_t imm =                                                        \
          static_cast<uint32_t>(i.InputOperand##width(1).ImmediateValue()); \
      __ asm_instr(i.OutputRegister##width(), i.InputRegister##width(0),    \
                   imm % (width));                                          \
    }                                                                       \
  } while (0)

#define ASSEMBLE_ATOMIC_LOAD_INTEGER(asm_instr, reg)                     \
  do {                                                                   \
    __ Add(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));   \
    RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset()); \
    __ asm_instr(i.Output##reg(), i.TempRegister(0));                    \
  } while (0)

#define ASSEMBLE_ATOMIC_STORE_INTEGER(asm_instr, reg)                    \
  do {                                                                   \
    __ Add(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));   \
    RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset()); \
    __ asm_instr(i.Input##reg(2), i.TempRegister(0));                    \
  } while (0)

#define ASSEMBLE_ATOMIC_EXCHANGE_INTEGER(suffix, reg)                      \
  do {                                                                     \
    __ Add(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));     \
    if (CpuFeatures::IsSupported(LSE)) {                                   \
      CpuFeatureScope scope(masm(), LSE);                                  \
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset()); \
      __ Swpal##suffix(i.Input##reg(2), i.Output##reg(),                   \
                       MemOperand(i.TempRegister(0)));                     \
    } else {                                                               \
      Label exchange;                                                      \
      __ Bind(&exchange);                                                  \
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset()); \
      __ ldaxr##suffix(i.Output##reg(), i.TempRegister(0));                \
      __ stlxr##suffix(i.TempRegister32(1), i.Input##reg(2),               \
                       i.TempRegister(0));                                 \
      __ Cbnz(i.TempRegister32(1), &exchange);                             \
    }                                                                      \
  } while (0)

#define ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(suffix, ext, reg)         \
  do {                                                                     \
    __ Add(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));     \
    if (CpuFeatures::IsSupported(LSE)) {                                   \
      DCHECK_EQ(i.OutputRegister(), i.InputRegister(2));                   \
      CpuFeatureScope scope(masm(), LSE);                                  \
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset()); \
      __ Casal##suffix(i.Output##reg(), i.Input##reg(3),                   \
                       MemOperand(i.TempRegister(0)));                     \
    } else {                                                               \
      Label compareExchange;                                               \
      Label exit;                                                          \
      __ Bind(&compareExchange);                                           \
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset()); \
      __ ldaxr##suffix(i.Output##reg(), i.TempRegister(0));                \
      __ Cmp(i.Output##reg(), Operand(i.Input##reg(2), ext));              \
      __ B(ne, &exit);                                                     \
      __ stlxr##suffix(i.TempRegister32(1), i.Input##reg(3),               \
                       i.TempRegister(0));                                 \
      __ Cbnz(i.TempRegister32(1), &compareExchange);                      \
      __ Bind(&exit);                                                      \
    }                                                                      \
  } while (0)

#define ASSEMBLE_ATOMIC_SUB(suffix, reg)                                   \
  do {                                                                     \
    __ Add(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));     \
    if (CpuFeatures::IsSupported(LSE)) {                                   \
      CpuFeatureScope scope(masm(), LSE);                                  \
      UseScratchRegisterScope temps(masm());                               \
      Register scratch = temps.AcquireSameSizeAs(i.Input##reg(2));         \
      __ Neg(scratch, i.Input##reg(2));                                    \
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset()); \
      __ Ldaddal##suffix(scratch, i.Output##reg(),                         \
                         MemOperand(i.TempRegister(0)));                   \
    } else {                                                               \
      Label binop;                                                         \
      __ Bind(&binop);                                                     \
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset()); \
      __ ldaxr##suffix(i.Output##reg(), i.TempRegister(0));                \
      __ Sub(i.Temp##reg(1), i.Output##reg(), Operand(i.Input##reg(2)));   \
      __ stlxr##suffix(i.TempRegister32(2), i.Temp##reg(1),                \
                       i.TempRegister(0));                                 \
      __ Cbnz(i.TempRegister32(2), &binop);                                \
    }                                                                      \
  } while (0)

#define ASSEMBLE_ATOMIC_AND(suffix, reg)                                   \
  do {                                                                     \
    __ Add(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));     \
    if (CpuFeatures::IsSupported(LSE)) {                                   \
      CpuFeatureScope scope(masm(), LSE);                                  \
      UseScratchRegisterScope temps(masm());                               \
      Register scratch = temps.AcquireSameSizeAs(i.Input##reg(2));         \
      __ Mvn(scratch, i.Input##reg(2));                                    \
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset()); \
      __ Ldclral##suffix(scratch, i.Output##reg(),                         \
                         MemOperand(i.TempRegister(0)));                   \
    } else {                                                               \
      Label binop;                                                         \
      __ Bind(&binop);                                                     \
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset()); \
      __ ldaxr##suffix(i.Output##reg(), i.TempRegister(0));                \
      __ And(i.Temp##reg(1), i.Output##reg(), Operand(i.Input##reg(2)));   \
      __ stlxr##suffix(i.TempRegister32(2), i.Temp##reg(1),                \
                       i.TempRegister(0));                                 \
      __ Cbnz(i.TempRegister32(2), &binop);                                \
    }                                                                      \
  } while (0)

#define ASSEMBLE_ATOMIC_BINOP(suffix, bin_instr, lse_instr, reg)               \
  do {                                                                         \
    __ Add(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));         \
    if (CpuFeatures::IsSupported(LSE)) {                                       \
      CpuFeatureScope scope(masm(), LSE);                                      \
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());     \
      __ lse_instr##suffix(i.Input##reg(2), i.Output##reg(),                   \
                           MemOperand(i.TempRegister(0)));                     \
    } else {                                                                   \
      Label binop;                                                             \
      __ Bind(&binop);                                                         \
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());     \
      __ ldaxr##suffix(i.Output##reg(), i.TempRegister(0));                    \
      __ bin_instr(i.Temp##reg(1), i.Output##reg(), Operand(i.Input##reg(2))); \
      __ stlxr##suffix(i.TempRegister32(2), i.Temp##reg(1),                    \
                       i.TempRegister(0));                                     \
      __ Cbnz(i.TempRegister32(2), &binop);                                    \
    }                                                                          \
  } while (0)

#define ASSEMBLE_IEEE754_BINOP(name)                                        \
  do {                                                                      \
    FrameScope scope(masm(), StackFrame::MANUAL);                           \
    __ CallCFunction(ExternalReference::ieee754_##name##_function(), 0, 2); \
  } while (0)

#define ASSEMBLE_IEEE754_UNOP(name)                                         \
  do {                                                                      \
    FrameScope scope(masm(), StackFrame::MANUAL);                           \
    __ CallCFunction(ExternalReference::ieee754_##name##_function(), 0, 1); \
  } while (0)

// If shift value is an immediate, we can call asm_imm, taking the shift value
// modulo 2^width. Otherwise, emit code to perform the modulus operation, and
// call asm_shl.
#define ASSEMBLE_SIMD_SHIFT_LEFT(asm_imm, width, format, asm_shl, gp)       \
  do {                                                                      \
    if (instr->InputAt(1)->IsImmediate()) {                                 \
      __ asm_imm(i.OutputSimd128Register().format(),                        \
                 i.InputSimd128Register(0).format(), i.InputInt##width(1)); \
    } else {                                                                \
      UseScratchRegisterScope temps(masm());                                \
      VRegister tmp = temps.AcquireQ();                                     \
      Register shift = temps.Acquire##gp();                                 \
      constexpr int mask = (1 << width) - 1;                                \
      __ And(shift, i.InputRegister32(1), mask);                            \
      __ Dup(tmp.format(), shift);                                          \
      __ asm_shl(i.OutputSimd128Register().format(),                        \
                 i.InputSimd128Register(0).format(), tmp.format());         \
    }                                                                       \
  } while (0)

// If shift value is an immediate, we can call asm_imm, taking the shift value
// modulo 2^width. Otherwise, emit code to perform the modulus operation, and
// call asm_shl, passing in the negative shift value (treated as right shift).
#define ASSEMBLE_SIMD_SHIFT_RIGHT(asm_imm, width, format, asm_shl, gp)      \
  do {                                                                      \
    if (instr->InputAt(1)->IsImmediate()) {                                 \
      __ asm_imm(i.OutputSimd128Register().format(),                        \
                 i.InputSimd128Register(0).format(), i.InputInt##width(1)); \
    } else {                                                                \
      UseScratchRegisterScope temps(masm());                                \
      VRegister tmp = temps.AcquireQ();                                     \
      Register shift = temps.Acquire##gp();                                 \
      constexpr int mask = (1 << width) - 1;                                \
      __ And(shift, i.InputRegister32(1), mask);                            \
      __ Dup(tmp.format(), shift);                                          \
      __ Neg(tmp.format(), tmp.format());                                   \
      __ asm_shl(i.OutputSimd128Register().format(),                        \
                 i.InputSimd128Register(0).format(), tmp.format());         \
    }                                                                       \
  } while (0)

void CodeGenerator::AssembleDeconstructFrame() {
  __ Mov(sp, fp);
  __ Pop<MacroAssembler::kAuthLR>(fp, lr);

  unwinding_info_writer_.MarkFrameDeconstructed(__ pc_offset());
}

void CodeGenerator::AssemblePrepareTailCall() {
  if (frame_access_state()->has_frame()) {
    __ RestoreFPAndLR();
  }
  frame_access_state()->SetFrameAccessToSP();
}

namespace {

void AdjustStackPointerForTailCall(MacroAssembler* masm,
                                   FrameAccessState* state,
                                   int new_slot_above_sp,
                                   bool allow_shrinkage = true) {
  int current_sp_offset = state->GetSPToFPSlotCount() +
                          StandardFrameConstants::kFixedSlotCountAboveFp;
  int stack_slot_delta = new_slot_above_sp - current_sp_offset;
  DCHECK_EQ(stack_slot_delta % 2, 0);
  if (stack_slot_delta > 0) {
    masm->Claim(stack_slot_delta);
    state->IncreaseSPDelta(stack_slot_delta);
  } else if (allow_shrinkage && stack_slot_delta < 0) {
    masm->Drop(-stack_slot_delta);
    state->IncreaseSPDelta(stack_slot_delta);
  }
}

}  // namespace

void CodeGenerator::AssembleTailCallBeforeGap(Instruction* instr,
                                              int first_unused_slot_offset) {
  AdjustStackPointerForTailCall(masm(), frame_access_state(),
                                first_unused_slot_offset, false);
}

void CodeGenerator::AssembleTailCallAfterGap(Instruction* instr,
                                             int first_unused_slot_offset) {
  DCHECK_EQ(first_unused_slot_offset % 2, 0);
  AdjustStackPointerForTailCall(masm(), frame_access_state(),
                                first_unused_slot_offset);
  DCHECK(instr->IsTailCall());
  InstructionOperandConverter g(this, instr);
  int optional_padding_offset = g.InputInt32(instr->InputCount() - 2);
  if (optional_padding_offset % 2) {
    __ Poke(padreg, optional_padding_offset * kSystemPointerSize);
  }
}

// Check that {kJavaScriptCallCodeStartRegister} is correct.
void CodeGenerator::AssembleCodeStartRegisterCheck() {
  UseScratchRegisterScope temps(masm());
  Register scratch = temps.AcquireX();
  __ ComputeCodeStartAddress(scratch);
  __ cmp(scratch, kJavaScriptCallCodeStartRegister);
  __ Assert(eq, AbortReason::kWrongFunctionCodeStart);
}

#ifdef V8_ENABLE_LEAPTIERING
// Check that {kJavaScriptCallDispatchHandleRegister} is correct.
void CodeGenerator::AssembleDispatchHandleRegisterCheck() {
  DCHECK(linkage()->GetIncomingDescriptor()->IsJSFunctionCall());

  // We currently don't check this for JS builtins as those are sometimes
  // called directly (e.g. from other builtins) and not through the dispatch
  // table. This is fine as builtin functions don't use the dispatch handle,
  // but we could enable this check in the future if we make sure to pass the
  // kInvalidDispatchHandle whenever we do a direct call to a JS builtin.
  if (Builtins::IsBuiltinId(info()->builtin())) {
    return;
  }

  // For now, we only ensure that the register references a valid dispatch
  // entry with the correct parameter count. In the future, we may also be able
  // to check that the entry points back to this code.
  UseScratchRegisterScope temps(masm());
  Register actual_parameter_count = temps.AcquireX();
  Register scratch = temps.AcquireX();
  __ LoadParameterCountFromJSDispatchTable(
      actual_parameter_count, kJavaScriptCallDispatchHandleRegister, scratch);
  __ Mov(scratch, parameter_count_);
  __ cmp(actual_parameter_count, scratch);
  __ Assert(eq, AbortReason::kWrongFunctionDispatchHandle);
}
#endif  // V8_ENABLE_LEAPTIERING

void CodeGenerator::BailoutIfDeoptimized() { __ BailoutIfDeoptimized(); }

// Assembles an instruction after register allocation, producing machine code.
CodeGenerator::CodeGenResult CodeGenerator::AssembleArchInstruction(
    Instruction* instr) {
  Arm64OperandConverter i(this, instr);
  InstructionCode opcode = instr->opcode();
  ArchOpcode arch_opcode = ArchOpcodeField::decode(opcode);
  switch (arch_opcode) {
    case kArchCallCodeObject: {
      if (instr->InputAt(0)->IsImmediate()) {
        __ Call(i.InputCode(0), RelocInfo::CODE_TARGET);
      } else {
        Register reg = i.InputRegister(0);
        CodeEntrypointTag tag =
            i.InputCodeEntrypointTag(instr->CodeEnrypointTagInputIndex());
        DCHECK_IMPLIES(
            instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister),
            reg == kJavaScriptCallCodeStartRegister);
        __ CallCodeObject(reg, tag);
      }
      RecordCallPosition(instr);
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
      if (instr->InputAt(0)->IsImmediate()) {
        Constant constant = i.ToConstant(instr->InputAt(0));
        Address wasm_code = static_cast<Address>(constant.ToInt64());
        __ Call(wasm_code, constant.rmode());
      } else {
        Register target = i.InputRegister(0);
        __ Call(target);
      }
      RecordCallPosition(instr);
      frame_access_state()->ClearSPDelta();
      break;
    }
    case kArchTailCallWasm: {
      if (instr->InputAt(0)->IsImmediate()) {
        Constant constant = i.ToConstant(instr->InputAt(0));
        Address wasm_code = static_cast<Address>(constant.ToInt64());
        __ Jump(wasm_code, constant.rmode());
      } else {
        Register target = i.InputRegister(0);
        UseScratchRegisterScope temps(masm());
        temps.Exclude(x17);
        __ Mov(x17, target);
        __ Jump(x17);
      }
      unwinding_info_writer_.MarkBlockWillExit();
      frame_access_state()->ClearSPDelta();
      frame_access_state()->SetFrameAccessToDefault();
      break;
    }
#endif  // V8_ENABLE_WEBASSEMBLY
    case kArchTailCallCodeObject: {
      if (instr->InputAt(0)->IsImmediate()) {
        __ Jump(i.InputCode(0), RelocInfo::CODE_TARGET);
      } else {
        Register reg = i.InputRegister(0);
        CodeEntrypointTag tag =
            i.InputCodeEntrypointTag(instr->CodeEnrypointTagInputIndex());
        DCHECK_IMPLIES(
            instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister),
            reg == kJavaScriptCallCodeStartRegister);
        __ JumpCodeObject(reg, tag);
      }
      unwinding_info_writer_.MarkBlockWillExit();
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
      UseScratchRegisterScope temps(masm());
      temps.Exclude(x17);
      __ Mov(x17, reg);
      __ Jump(x17);
      unwinding_info_writer_.MarkBlockWillExit();
      frame_access_state()->ClearSPDelta();
      frame_access_state()->SetFrameAccessToDefault();
      break;
    }
    case kArchCallJSFunction: {
      Register func = i.InputRegister(0);
      if (v8_flags.debug_code) {
        // Check the function's context matches the context argument.
        UseScratchRegisterScope scope(masm());
        Register temp = scope.AcquireX();
        __ LoadTaggedField(temp,
                           FieldMemOperand(func, JSFunction::kContextOffset));
        __ cmp(cp, temp);
        __ Assert(eq, AbortReason::kWrongFunctionContext);
      }
      uint32_t num_arguments =
          i.InputUint32(instr->JSCallArgumentCountInputIndex());
      __ CallJSFunction(func, num_arguments);
      RecordCallPosition(instr);
      frame_access_state()->ClearSPDelta();
      break;
    }
    case kArchPrepareCallCFunction:
      // We don't need kArchPrepareCallCFunction on arm64 as the instruction
      // selector has already performed a Claim to reserve space on the stack.
      // Frame alignment is always 16 bytes, and the stack pointer is already
      // 16-byte aligned, therefore we do not need to align the stack pointer
      // by an unknown value, and it is safe to continue accessing the frame
      // via the stack pointer.
      UNREACHABLE();
    case kArchSaveCallerRegisters: {
      fp_mode_ =
          static_cast<SaveFPRegsMode>(MiscField::decode(instr->opcode()));
      DCHECK(fp_mode_ == SaveFPRegsMode::kIgnore ||
             fp_mode_ == SaveFPRegsMode::kSave);
      // kReturnRegister0 should have been saved before entering the stub.
      int bytes = __ PushCallerSaved(fp_mode_, kReturnRegister0);
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
      int bytes = __ PopCallerSaved(fp_mode_, kReturnRegister0);
      frame_access_state()->IncreaseSPDelta(-(bytes / kSystemPointerSize));
      DCHECK_EQ(0, frame_access_state()->sp_delta());
      DCHECK(caller_registers_saved_);
      caller_registers_saved_ = false;
      break;
    }
    case kArchPrepareTailCall:
      AssemblePrepareTailCall();
      break;
    case kArchCallCFunctionWithFrameState:
    case kArchCallCFunction: {
      int const num_gp_parameters = ParamField::decode(instr->opcode());
      int const num_fp_parameters = FPParamField::decode(instr->opcode());
      Label return_location;
      SetIsolateDataSlots set_isolate_data_slots = SetIsolateDataSlots::kYes;
#if V8_ENABLE_WEBASSEMBLY
      if (linkage()->GetIncomingDescriptor()->IsWasmCapiFunction()) {
        // Put the return address in a stack slot.
        __ StoreReturnAddressInWasmExitFrame(&return_location);
        set_isolate_data_slots = SetIsolateDataSlots::kNo;
      }
#endif  // V8_ENABLE_WEBASSEMBLY
      int pc_offset;
      if (instr->InputAt(0)->IsImmediate()) {
        ExternalReference ref = i.InputExternalReference(0);
        pc_offset = __ CallCFunction(ref, num_gp_parameters, num_fp_parameters,
                                     set_isolate_data_slots, &return_location);
      } else {
        Register func = i.InputRegister(0);
        pc_offset = __ CallCFunction(func, num_gp_parameters, num_fp_parameters,
                                     set_isolate_data_slots, &return_location);
      }
      RecordSafepoint(instr->reference_map(), pc_offset);

      bool const needs_frame_state =
          (arch_opcode == kArchCallCFunctionWithFrameState);
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
      break;
    case kArchTableSwitch:
      AssembleArchTableSwitch(instr);
      break;
    case kArchBinarySearchSwitch:
      AssembleArchBinarySearchSwitch(instr);
      break;
    case kArchAbortCSADcheck:
      DCHECK_EQ(i.InputRegister(0), x1);
      {
        // We don't actually want to generate a pile of code for this, so just
        // claim there is a stack frame, without generating one.
        FrameScope scope(masm(), StackFrame::NO_FRAME_TYPE);
        __ CallBuiltin(Builtin::kAbortCSADcheck);
      }
      __ Debug("kArchAbortCSADcheck", 0, BREAK);
      unwinding_info_writer_.MarkBlockWillExit();
      break;
    case kArchDebugBreak:
      __ DebugBreak();
      break;
    case kArchComment:
      __ RecordComment(reinterpret_cast<const char*>(i.InputInt64(0)));
      break;
    case kArchThrowTerminator:
      unwinding_info_writer_.MarkBlockWillExit();
      break;
    case kArchNop:
      // don't emit code for nops.
      break;
    case kArchDeoptimize: {
      DeoptimizationExit* exit =
          BuildTranslation(instr, -1, 0, 0, OutputFrameStateCombine::Ignore());
      __ B(exit->label());
      break;
    }
    case kArchRet:
      AssembleReturn(instr->InputAt(0));
      break;
    case kArchFramePointer:
      __ mov(i.OutputRegister(), fp);
      break;
    case kArchParentFramePointer:
      if (frame_access_state()->has_frame()) {
        __ ldr(i.OutputRegister(), MemOperand(fp, 0));
      } else {
        __ mov(i.OutputRegister(), fp);
      }
      break;
#if V8_ENABLE_WEBASSEMBLY
    case kArchStackPointer:
      // The register allocator expects an allocatable register for the output,
      // we cannot use sp directly.
      __ mov(i.OutputRegister(), sp);
      break;
    case kArchSetStackPointer: {
      DCHECK(instr->InputAt(0)->IsRegister());
      if (masm()->options().enable_simulator_code) {
        __ RecordComment("-- Set simulator stack limit --");
        DCHECK(__ TmpList()->IncludesAliasOf(kSimulatorHltArgument));
        __ LoadStackLimit(kSimulatorHltArgument,
                          StackLimitKind::kRealStackLimit);
        __ hlt(kImmExceptionIsSwitchStackLimit);
      }
      __ Mov(sp, i.InputRegister(0));
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
        __ Sub(lhs_register, sp, offset);
      }

      constexpr size_t kValueIndex = 0;
      DCHECK(instr->InputAt(kValueIndex)->IsRegister());
      __ Cmp(lhs_register, i.InputRegister(kValueIndex));
      break;
    }
    case kArchStackCheckOffset:
      __ Move(i.OutputRegister(), Smi::FromInt(GetStackCheckOffset()));
      break;
    case kArchTruncateDoubleToI:
      __ TruncateDoubleToI(isolate(), zone(), i.OutputRegister(),
                           i.InputDoubleRegister(0), DetermineStubCallMode(),
                           frame_access_state()->has_frame()
                               ? kLRHasBeenSaved
                               : kLRHasNotBeenSaved);

      break;
    case kArchStoreWithWriteBarrier: {
      RecordWriteMode mode = RecordWriteModeField::decode(instr->opcode());
      // Indirect pointer writes must use a different opcode.
      DCHECK_NE(mode, RecordWriteMode::kValueIsIndirectPointer);
      AddressingMode addressing_mode =
          AddressingModeField::decode(instr->opcode());
      Register object = i.InputRegister(0);
      Operand offset(0);
      if (addressing_mode == kMode_MRI) {
        offset = Operand(i.InputInt64(1));
      } else {
        DCHECK_EQ(addressing_mode, kMode_MRR);
        offset = Operand(i.InputRegister(1));
      }
      Register value = i.InputRegister(2);

      if (v8_flags.debug_code) {
        // Checking that |value| is not a cleared weakref: our write barrier
        // does not support that for now.
        __ cmp(value, Operand(kClearedWeakHeapObjectLower32));
        __ Check(ne, AbortReason::kOperandIsCleared);
      }

      auto ool = zone()->New<OutOfLineRecordWrite>(
          this, object, offset, value, mode, DetermineStubCallMode(),
          &unwinding_info_writer_);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ StoreTaggedField(value, MemOperand(object, offset));
      if (mode > RecordWriteMode::kValueIsIndirectPointer) {
        __ JumpIfSmi(value, ool->exit());
      }
      __ CheckPageFlag(object, MemoryChunk::kPointersFromHereAreInterestingMask,
                       ne, ool->entry());
      __ Bind(ool->exit());
      break;
    }
    case kArchAtomicStoreWithWriteBarrier: {
      DCHECK_EQ(AddressingModeField::decode(instr->opcode()), kMode_MRR);
      RecordWriteMode mode = RecordWriteModeField::decode(instr->opcode());
      // Indirect pointer writes must use a different opcode.
      DCHECK_NE(mode, RecordWriteMode::kValueIsIndirectPointer);
      Register object = i.InputRegister(0);
      Register offset = i.InputRegister(1);
      Register value = i.InputRegister(2);
      auto ool = zone()->New<OutOfLineRecordWrite>(
          this, object, offset, value, mode, DetermineStubCallMode(),
          &unwinding_info_writer_);
      __ AtomicStoreTaggedField(value, object, offset, i.TempRegister(0));
      // Skip the write barrier if the value is a Smi. However, this is only
      // valid if the value isn't an indirect pointer. Otherwise the value will
      // be a pointer table index, which will always look like a Smi (but
      // actually reference a pointer in the pointer table).
      if (mode > RecordWriteMode::kValueIsIndirectPointer) {
        __ JumpIfSmi(value, ool->exit());
      }
      __ CheckPageFlag(object, MemoryChunk::kPointersFromHereAreInterestingMask,
                       ne, ool->entry());
      __ Bind(ool->exit());
      break;
    }
    case kArchStoreIndirectWithWriteBarrier: {
      RecordWriteMode mode = RecordWriteModeField::decode(instr->opcode());
      DCHECK_EQ(mode, RecordWriteMode::kValueIsIndirectPointer);
      AddressingMode addressing_mode =
          AddressingModeField::decode(instr->opcode());
      Register object = i.InputRegister(0);
      Operand offset(0);
      if (addressing_mode == kMode_MRI) {
        offset = Operand(i.InputInt64(1));
      } else {
        DCHECK_EQ(addressing_mode, kMode_MRR);
        offset = Operand(i.InputRegister(1));
      }
      Register value = i.InputRegister(2);
      IndirectPointerTag tag = static_cast<IndirectPointerTag>(i.InputInt64(3));
      DCHECK(IsValidIndirectPointerTag(tag));

      auto ool = zone()->New<OutOfLineRecordWrite>(
          this, object, offset, value, mode, DetermineStubCallMode(),
          &unwinding_info_writer_, tag);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ StoreIndirectPointerField(value, MemOperand(object, offset));
      __ JumpIfMarking(ool->entry());
      __ Bind(ool->exit());
      break;
    }
    case kArchStackSlot: {
      FrameOffset offset =
          frame_access_state()->GetFrameOffset(i.InputInt32(0));
      Register base = offset.from_stack_pointer() ? sp : fp;
      __ Add(i.OutputRegister(0), base, Operand(offset.offset()));
      break;
    }
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
    case kIeee754Float64Atanh:
      ASSEMBLE_IEEE754_UNOP(atanh);
      break;
    case kIeee754Float64Atan2:
      ASSEMBLE_IEEE754_BINOP(atan2);
      break;
    case kIeee754Float64Cos:
      ASSEMBLE_IEEE754_UNOP(cos);
      break;
    case kIeee754Float64Cosh:
      ASSEMBLE_IEEE754_UNOP(cosh);
      break;
    case kIeee754Float64Cbrt:
      ASSEMBLE_IEEE754_UNOP(cbrt);
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
    case kIeee754Float64Log10:
      ASSEMBLE_IEEE754_UNOP(log10);
      break;
    case kIeee754Float64Pow:
      ASSEMBLE_IEEE754_BINOP(pow);
      break;
    case kIeee754Float64Sin:
      ASSEMBLE_IEEE754_UNOP(sin);
      break;
    case kIeee754Float64Sinh:
      ASSEMBLE_IEEE754_UNOP(sinh);
      break;
    case kIeee754Float64Tan:
      ASSEMBLE_IEEE754_UNOP(tan);
      break;
    case kIeee754Float64Tanh:
      ASSEMBLE_IEEE754_UNOP(tanh);
      break;
    case kArm64Float16RoundDown:
      EmitFpOrNeonUnop(masm(), &MacroAssembler::Frintm, instr, i, kFormatH,
                       kFormat8H);
      break;
    case kArm64Float32RoundDown:
      EmitFpOrNeonUnop(masm(), &MacroAssembler::Frintm, instr, i, kFormatS,
                       kFormat4S);
      break;
    case kArm64Float64RoundDown:
      EmitFpOrNeonUnop(masm(), &MacroAssembler::Frintm, instr, i, kFormatD,
                       kFormat2D);
      break;
    case kArm64Float16RoundUp:
      EmitFpOrNeonUnop(masm(), &MacroAssembler::Frintp, instr, i, kFormatH,
                       kFormat8H);
      break;
    case kArm64Float32RoundUp:
      EmitFpOrNeonUnop(masm(), &MacroAssembler::Frintp, instr, i, kFormatS,
                       kFormat4S);
      break;
    case kArm64Float64RoundUp:
      EmitFpOrNeonUnop(masm(), &MacroAssembler::Frintp, instr, i, kFormatD,
                       kFormat2D);
      break;
    case kArm64Float64RoundTiesAway:
      EmitFpOrNeonUnop(masm(), &MacroAssembler::Frinta, instr, i, kFormatD,
                       kFormat2D);
      break;
    case kArm64Float16RoundTruncate:
      EmitFpOrNeonUnop(masm(), &MacroAssembler::Frintz, instr, i, kFormatH,
                       kFormat8H);
      break;
    case kArm64Float32RoundTruncate:
      EmitFpOrNeonUnop(masm(), &MacroAssembler::Frintz, instr, i, kFormatS,
                       kFormat4S);
      break;
    case kArm64Float64RoundTruncate:
      EmitFpOrNeonUnop(masm(), &MacroAssembler::Frintz, instr, i, kFormatD,
                       kFormat2D);
      break;
    case kArm64Float16RoundTiesEven:
      EmitFpOrNeonUnop(masm(), &MacroAssembler::Frintn, instr, i, kFormatH,
                       kFormat8H);
      break;
    case kArm64Float32RoundTiesEven:
      EmitFpOrNeonUnop(masm(), &MacroAssembler::Frintn, instr, i, kFormatS,
                       kFormat4S);
      break;
    case kArm64Float64RoundTiesEven:
      EmitFpOrNeonUnop(masm(), &MacroAssembler::Frintn, instr, i, kFormatD,
                       kFormat2D);
      break;
    case kArm64Add:
      if (FlagsModeField::decode(opcode) != kFlags_none) {
        __ Adds(i.OutputRegister(), i.InputOrZeroRegister64(0),
                i.InputOperand2_64(1));
      } else {
        __ Add(i.OutputRegister(), i.InputOrZeroRegister64(0),
               i.InputOperand2_64(1));
      }
      break;
    case kArm64Add32:
      if (FlagsModeField::decode(opcode) != kFlags_none) {
        __ Adds(i.OutputRegister32(), i.InputOrZeroRegister32(0),
                i.InputOperand2_32(1));
      } else {
        __ Add(i.OutputRegister32(), i.InputOrZeroRegister32(0),
               i.InputOperand2_32(1));
      }
      break;
    case kArm64And:
      if (FlagsModeField::decode(opcode) != kFlags_none) {
        // The ands instruction only sets N and Z, so only the following
        // conditions make sense.
        DCHECK(FlagsConditionField::decode(opcode) == kEqual ||
               FlagsConditionField::decode(opcode) == kNotEqual ||
               FlagsConditionField::decode(opcode) == kPositiveOrZero ||
               FlagsConditionField::decode(opcode) == kNegative);
        __ Ands(i.OutputRegister(), i.InputOrZeroRegister64(0),
                i.InputOperand2_64(1));
      } else {
        __ And(i.OutputRegister(), i.InputOrZeroRegister64(0),
               i.InputOperand2_64(1));
      }
      break;
    case kArm64And32:
      if (FlagsModeField::decode(opcode) != kFlags_none) {
        // The ands instruction only sets N and Z, so only the following
        // conditions make sense.
        DCHECK(FlagsConditionField::decode(opcode) == kEqual ||
               FlagsConditionField::decode(opcode) == kNotEqual ||
               FlagsConditionField::decode(opcode) == kPositiveOrZero ||
               FlagsConditionField::decode(opcode) == kNegative);
        __ Ands(i.OutputRegister32(), i.InputOrZeroRegister32(0),
                i.InputOperand2_32(1));
      } else {
        __ And(i.OutputRegister32(), i.InputOrZeroRegister32(0),
               i.InputOperand2_32(1));
      }
      break;
    case kArm64Bic:
      __ Bic(i.OutputRegister(), i.InputOrZeroRegister64(0),
             i.InputOperand2_64(1));
      break;
    case kArm64Bic32:
      __ Bic(i.OutputRegister32(), i.InputOrZeroRegister32(0),
             i.InputOperand2_32(1));
      break;
    case kArm64Mul:
      __ Mul(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      break;
    case kArm64Smulh:
      __ Smulh(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      break;
    case kArm64Umulh:
      __ Umulh(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      break;
    case kArm64Mul32:
      __ Mul(i.OutputRegister32(), i.InputRegister32(0), i.InputRegister32(1));
      break;
#if V8_ENABLE_WEBASSEMBLY
    case kArm64Sadalp: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      VectorFormat dst_f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      VectorFormat src_f = VectorFormatHalfWidthDoubleLanes(dst_f);
      __ Sadalp(i.OutputSimd128Register().Format(dst_f),
                i.InputSimd128Register(1).Format(src_f));
      break;
    }
    case kArm64Saddlp: {
      VectorFormat dst_f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      VectorFormat src_f = VectorFormatHalfWidthDoubleLanes(dst_f);
      __ Saddlp(i.OutputSimd128Register().Format(dst_f),
                i.InputSimd128Register(0).Format(src_f));
      break;
    }
    case kArm64Uadalp: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      VectorFormat dst_f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      VectorFormat src_f = VectorFormatHalfWidthDoubleLanes(dst_f);
      __ Uadalp(i.OutputSimd128Register().Format(dst_f),
                i.InputSimd128Register(1).Format(src_f));
      break;
    }
    case kArm64Uaddlp: {
      VectorFormat dst_f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      VectorFormat src_f = VectorFormatHalfWidthDoubleLanes(dst_f);
      __ Uaddlp(i.OutputSimd128Register().Format(dst_f),
                i.InputSimd128Register(0).Format(src_f));
      break;
    }
    case kArm64ISplat: {
      VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      Register src = LaneSizeField::decode(opcode) == 64 ? i.InputRegister64(0)
                                                         : i.InputRegister32(0);
      __ Dup(i.OutputSimd128Register().Format(f), src);
      break;
    }
    case kArm64FSplat: {
      VectorFormat src_f =
          ScalarFormatFromLaneSize(LaneSizeField::decode(opcode));
      VectorFormat dst_f = VectorFormatFillQ(src_f);
      if (src_f == kFormatH) {
        __ Fcvt(i.OutputFloat32Register(0).H(), i.InputFloat32Register(0));
        __ Dup(i.OutputSimd128Register().Format(dst_f),
               i.OutputSimd128Register().Format(src_f), 0);
      } else {
        __ Dup(i.OutputSimd128Register().Format(dst_f),
               i.InputSimd128Register(0).Format(src_f), 0);
      }
      break;
    }
    case kArm64Smlal: {
      VectorFormat dst_f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      VectorFormat src_f = VectorFormatHalfWidth(dst_f);
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      __ Smlal(i.OutputSimd128Register().Format(dst_f),
               i.InputSimd128Register(1).Format(src_f),
               i.InputSimd128Register(2).Format(src_f));
      break;
    }
    case kArm64Smlal2: {
      VectorFormat dst_f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      VectorFormat src_f = VectorFormatHalfWidthDoubleLanes(dst_f);
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      __ Smlal2(i.OutputSimd128Register().Format(dst_f),
                i.InputSimd128Register(1).Format(src_f),
                i.InputSimd128Register(2).Format(src_f));
      break;
    }
    case kArm64Umlal: {
      VectorFormat dst_f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      VectorFormat src_f = VectorFormatHalfWidth(dst_f);
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      __ Umlal(i.OutputSimd128Register().Format(dst_f),
               i.InputSimd128Register(1).Format(src_f),
               i.InputSimd128Register(2).Format(src_f));
      break;
    }
    case kArm64Umlal2: {
      VectorFormat dst_f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      VectorFormat src_f = VectorFormatHalfWidthDoubleLanes(dst_f);
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      __ Umlal2(i.OutputSimd128Register().Format(dst_f),
                i.InputSimd128Register(1).Format(src_f),
                i.InputSimd128Register(2).Format(src_f));
      break;
    }
#endif  // V8_ENABLE_WEBASSEMBLY
    case kArm64Smull: {
      if (instr->InputAt(0)->IsRegister()) {
        __ Smull(i.OutputRegister(), i.InputRegister32(0),
                 i.InputRegister32(1));
      } else {
        DCHECK(instr->InputAt(0)->IsSimd128Register());
        VectorFormat dst_f = VectorFormatFillQ(LaneSizeField::decode(opcode));
        VectorFormat src_f = VectorFormatHalfWidth(dst_f);
        __ Smull(i.OutputSimd128Register().Format(dst_f),
                 i.InputSimd128Register(0).Format(src_f),
                 i.InputSimd128Register(1).Format(src_f));
      }
      break;
    }
    case kArm64Smull2: {
      VectorFormat dst_f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      VectorFormat src_f = VectorFormatHalfWidthDoubleLanes(dst_f);
      __ Smull2(i.OutputSimd128Register().Format(dst_f),
                i.InputSimd128Register(0).Format(src_f),
                i.InputSimd128Register(1).Format(src_f));
      break;
    }
    case kArm64Umull: {
      if (instr->InputAt(0)->IsRegister()) {
        __ Umull(i.OutputRegister(), i.InputRegister32(0),
                 i.InputRegister32(1));
      } else {
        DCHECK(instr->InputAt(0)->IsSimd128Register());
        VectorFormat dst_f = VectorFormatFillQ(LaneSizeField::decode(opcode));
        VectorFormat src_f = VectorFormatHalfWidth(dst_f);
        __ Umull(i.OutputSimd128Register().Format(dst_f),
                 i.InputSimd128Register(0).Format(src_f),
                 i.InputSimd128Register(1).Format(src_f));
      }
      break;
    }
    case kArm64Umull2: {
      VectorFormat dst_f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      VectorFormat src_f = VectorFormatHalfWidthDoubleLanes(dst_f);
      __ Umull2(i.OutputSimd128Register().Format(dst_f),
                i.InputSimd128Register(0).Format(src_f),
                i.InputSimd128Register(1).Format(src_f));
      break;
    }
    case kArm64Madd:
      __ Madd(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
              i.InputRegister(2));
      break;
    case kArm64Madd32:
      __ Madd(i.OutputRegister32(), i.InputRegister32(0), i.InputRegister32(1),
              i.InputRegister32(2));
      break;
    case kArm64Msub:
      __ Msub(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
              i.InputRegister(2));
      break;
    case kArm64Msub32:
      __ Msub(i.OutputRegister32(), i.InputRegister32(0), i.InputRegister32(1),
              i.InputRegister32(2));
      break;
    case kArm64Mneg:
      __ Mneg(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      break;
    case kArm64Mneg32:
      __ Mneg(i.OutputRegister32(), i.InputRegister32(0), i.InputRegister32(1));
      break;
    case kArm64Idiv:
      __ Sdiv(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      break;
    case kArm64Idiv32:
      __ Sdiv(i.OutputRegister32(), i.InputRegister32(0), i.InputRegister32(1));
      break;
    case kArm64Udiv:
      __ Udiv(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      break;
    case kArm64Udiv32:
      __ Udiv(i.OutputRegister32(), i.InputRegister32(0), i.InputRegister32(1));
      break;
    case kArm64Imod: {
      UseScratchRegisterScope scope(masm());
      Register temp = scope.AcquireX();
      __ Sdiv(temp, i.InputRegister(0), i.InputRegister(1));
      __ Msub(i.OutputRegister(), temp, i.InputRegister(1), i.InputRegister(0));
      break;
    }
    case kArm64Imod32: {
      UseScratchRegisterScope scope(masm());
      Register temp = scope.AcquireW();
      __ Sdiv(temp, i.InputRegister32(0), i.InputRegister32(1));
      __ Msub(i.OutputRegister32(), temp, i.InputRegister32(1),
              i.InputRegister32(0));
      break;
    }
    case kArm64Umod: {
      UseScratchRegisterScope scope(masm());
      Register temp = scope.AcquireX();
      __ Udiv(temp, i.InputRegister(0), i.InputRegister(1));
      __ Msub(i.OutputRegister(), temp, i.InputRegister(1), i.InputRegister(0));
      break;
    }
    case kArm64Umod32: {
      UseScratchRegisterScope scope(masm());
      Register temp = scope.AcquireW();
      __ Udiv(temp, i.InputRegister32(0), i.InputRegister32(1));
      __ Msub(i.OutputRegister32(), temp, i.InputRegister32(1),
              i.InputRegister32(0));
      break;
    }
    case kArm64Not:
      __ Mvn(i.OutputRegister(), i.InputOperand(0));
      break;
    case kArm64Not32:
      __ Mvn(i.OutputRegister32(), i.InputOperand32(0));
      break;
    case kArm64Or:
      __ Orr(i.OutputRegister(), i.InputOrZeroRegister64(0),
             i.InputOperand2_64(1));
      break;
    case kArm64Or32:
      __ Orr(i.OutputRegister32(), i.InputOrZeroRegister32(0),
             i.InputOperand2_32(1));
      break;
    case kArm64Orn:
      __ Orn(i.OutputRegister(), i.InputOrZeroRegister64(0),
             i.InputOperand2_64(1));
      break;
    case kArm64Orn32:
      __ Orn(i.OutputRegister32(), i.InputOrZeroRegister32(0),
             i.InputOperand2_32(1));
      break;
    case kAr
```