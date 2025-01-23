Response:
The user wants a summary of the provided C++ code snippet for the V8 JavaScript engine.
The code is located in `v8/src/compiler/backend/riscv/code-generator-riscv.cc`, suggesting it's responsible for generating RISC-V assembly code from a higher-level intermediate representation.

Here's a breakdown of how to approach the request:

1. **Identify the core purpose:** The filename and the presence of "CodeGenerator" strongly indicate this file deals with generating machine code for the RISC-V architecture within the V8 compiler.

2. **Analyze included headers:**  The included headers reveal key functionalities:
    - `assembler-inl.h`, `macro-assembler.h`:  Low-level assembly code generation.
    - `callable.h`:  Handling function calls.
    - `optimized-compilation-info.h`: Information about the compilation process.
    - `constants-riscv.h`: RISC-V specific constants.
    - `code-generator-impl.h`, `code-generator.h`: Base classes for code generation.
    - `gap-resolver.h`: Managing gaps in generated code (likely for patching).
    - `node-matchers.h`:  Pattern matching on the intermediate representation.
    - `osr.h`: On-stack replacement.
    - `mutable-page-metadata.h`:  Metadata related to memory management.

3. **Examine key classes and functions:**
    - `RiscvOperandConverter`:  Handles the conversion between instruction operands and RISC-V registers/memory locations. This is crucial for translating the IR into assembly.
    - `OutOfLineRecordWrite`:  Deals with write barriers, essential for garbage collection when writing to objects in the heap.
    - `FlagsConditionToConditionCmp`, `FlagsConditionToConditionTst`, `FlagsConditionToConditionCmpFPU`: Functions to translate high-level condition codes into RISC-V specific condition codes for branching and comparisons.
    - `WasmOutOfLineTrap`: Handles traps in WebAssembly code.
    - `AssembleDeconstructFrame`, `AssemblePrepareTailCall`: Functions for managing the call stack during function entry and exit, including optimizations like tail calls.
    - `AssembleArchSelect`: Placeholder for architecture-specific selection logic.
    - `AdjustStackPointerForTailCall`: Adjusts the stack pointer for tail calls.
    - `AssembleCodeStartRegisterCheck`, `BailoutIfDeoptimized`:  Runtime checks for code integrity and deoptimization.
    - `AssembleArchInstruction`:  The main function responsible for generating assembly instructions for different IR opcodes. The extensive `switch` statement within this function is where the core instruction generation logic resides. It handles a wide variety of operations (arithmetic, memory access, control flow, floating-point, SIMD, atomic operations).

4. **Consider specific patterns:** The `#define` macros for atomic operations and IEEE754 floating-point operations show how complex operations are mapped to sequences of assembly instructions or calls to external C++ functions. The RVV (RISC-V Vector Extension) macros highlight support for SIMD operations.

5. **Address the user's specific questions:**
    - **Functionality:**  Code generation for RISC-V.
    - **.tq extension:** The code has a `.cc` extension, not `.tq`, so it's standard C++, not Torque.
    - **Relationship to JavaScript:** This code is the *backend* of the compiler. It takes the optimized representation of JavaScript code and translates it into machine code that the RISC-V processor can execute.
    - **Code logic inference:** The `switch` statement in `AssembleArchInstruction` is the primary logic, mapping IR opcodes to assembly sequences.
    - **Common programming errors:**  While the C++ code itself is part of the V8 engine, it helps *avoid* errors in the *generated* code by correctly implementing the semantics of JavaScript operations. Incorrect code generation could lead to crashes, incorrect results, or security vulnerabilities.

6. **Synthesize the information into a concise summary.**

Based on this thought process, the generated summary should accurately reflect the role and key features of the provided code.
```cpp
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/codegen/assembler-inl.h"
#include "src/codegen/callable.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/optimized-compilation-info.h"
#include "src/codegen/riscv/constants-riscv.h"
#include "src/compiler/backend/code-generator-impl.h"
#include "src/compiler/backend/code-generator.h"
#include "src/compiler/backend/gap-resolver.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/osr.h"
#include "src/heap/mutable-page-metadata.h"

namespace v8 {
namespace internal {
namespace compiler {

#define __ masm()->

#define TRACE(...) PrintF(__VA_ARGS__)

// Adds RISC-V-specific methods to convert InstructionOperands.
class RiscvOperandConverter final : public InstructionOperandConverter {
 public:
  RiscvOperandConverter(CodeGenerator* gen, Instruction* instr)
      : InstructionOperandConverter(gen, instr) {}

  FloatRegister OutputSingleRegister(size_t index = 0) {
    return ToSingleRegister(instr_->OutputAt(index));
  }

  FloatRegister InputSingleRegister(size_t index) {
    return ToSingleRegister(instr_->InputAt(index));
  }

  FloatRegister ToSingleRegister(InstructionOperand* op) {
    // Single (Float) and Double register namespace is same on RISC-V,
    // both are typedefs of FPURegister.
    return ToDoubleRegister(op);
  }

  Register InputOrZeroRegister(size_t index) {
    if (instr_->InputAt(index)->IsImmediate()) {
      Constant constant = ToConstant(instr_->InputAt(index));
      switch (constant.type()) {
        case Constant::kInt32:
        case Constant::kInt64:
          DCHECK_EQ(0, InputInt32(index));
          break;
        case Constant::kFloat32:
          DCHECK_EQ(0, base::bit_cast<int32_t>(InputFloat32(index)));
          break;
        case Constant::kFloat64:
          DCHECK_EQ(0, base::bit_cast<int64_t>(InputDouble(index)));
          break;
        default:
          UNREACHABLE();
      }
      return zero_reg;
    }
    return InputRegister(index);
  }

  DoubleRegister InputOrZeroDoubleRegister(size_t index) {
    if (instr_->InputAt(index)->IsImmediate()) return kDoubleRegZero;

    return InputDoubleRegister(index);
  }

  DoubleRegister InputOrZeroSingleRegister(size_t index) {
    if (instr_->InputAt(index)->IsImmediate()) return kSingleRegZero;

    return InputSingleRegister(index);
  }

  Operand InputImmediate(size_t index) {
    Constant constant = ToConstant(instr_->InputAt(index));
    switch (constant.type()) {
      case Constant::kInt32:
        return Operand(constant.ToInt32());
      case Constant::kInt64:
        return Operand(constant.ToInt64());
      case Constant::kFloat32:
        return Operand::EmbeddedNumber(constant.ToFloat32());
      case Constant::kFloat64:
        return Operand::EmbeddedNumber(constant.ToFloat64().value());
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
      case Constant::kExternalReference:
      case Constant::kHeapObject:
        // TODO(plind): Maybe we should handle ExtRef & HeapObj here?
        //    maybe not done on arm due to const pool ??
        break;
      case Constant::kRpoNumber:
        UNREACHABLE();  // TODO(titzer): RPO immediates
    }
    UNREACHABLE();
  }

  Operand InputOperand(size_t index) {
    InstructionOperand* op = instr_->InputAt(index);
    if (op->IsRegister()) {
      return Operand(ToRegister(op));
    }
    return InputImmediate(index);
  }

  MemOperand MemoryOperand(size_t* first_index) {
    const size_t index = *first_index;
    switch (AddressingModeField::decode(instr_->opcode())) {
      case kMode_None:
        break;
      case kMode_MRI:
        *first_index += 2;
        return MemOperand(InputRegister(index + 0), InputInt32(index + 1));
      case kMode_Root:
        return MemOperand(kRootRegister, InputInt32(index));
      case kMode_MRR:
        // TODO(plind): r6 address mode, to be implemented ...
        UNREACHABLE();
    }
    UNREACHABLE();
  }

  MemOperand MemoryOperand(size_t index = 0) { return MemoryOperand(&index); }

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
      CodeGenerator* gen, Register object, Operand offset, Register value,
      RecordWriteMode mode, StubCallMode stub_mode,
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
        zone_(gen->zone()),
        indirect_pointer_tag_(indirect_pointer_tag) {
  }

  void Generate() final {
#ifdef V8_TARGET_ARCH_RISCV64
    // When storing an indirect pointer, the value will always be a
    // full/decompressed pointer.
    if (COMPRESS_POINTERS_BOOL &&
        mode_ != RecordWriteMode::kValueIsIndirectPointer) {
      __ DecompressTagged(value_, value_);
    }
#endif
    __ CheckPageFlag(value_, MemoryChunk::kPointersToHereAreInterestingMask, eq,
                     exit());

    SaveFPRegsMode const save_fp_mode = frame()->DidAllocateDoubleRegisters()
                                            ? SaveFPRegsMode::kSave
                                            : SaveFPRegsMode::kIgnore;
    if (must_save_lr_) {
      // We need to save and restore ra if the frame was elided.
      __ Push(ra);
    }
    if (mode_ == RecordWriteMode::kValueIsEphemeronKey) {
      __ CallEphemeronKeyBarrier(object_, offset_, save_fp_mode);
    } else if (mode_ == RecordWriteMode::kValueIsIndirectPointer) {
      DCHECK(IsValidIndirectPointerTag(indirect_pointer_tag_));
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
      __ Pop(ra);
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
  Zone* zone_;
  IndirectPointerTag indirect_pointer_tag_;
};

Condition FlagsConditionToConditionCmp(FlagsCondition condition) {
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
      return Uless;
    case kUnsignedGreaterThanOrEqual:
      return Ugreater_equal;
    case kUnsignedLessThanOrEqual:
      return Uless_equal;
    case kUnsignedGreaterThan:
      return Ugreater;
    case kUnorderedEqual:
    case kUnorderedNotEqual:
      break;
    default:
      break;
  }
  UNREACHABLE();
}

Condition FlagsConditionToConditionTst(FlagsCondition condition) {
  switch (condition) {
    case kNotEqual:
      return ne;
    case kEqual:
      return eq;
    default:
      break;
  }
  UNREACHABLE();
}
#if V8_TARGET_ARCH_RISCV64
Condition FlagsConditionToConditionOvf(FlagsCondition condition) {
  switch (condition) {
    case kOverflow:
      return ne;
    case kNotOverflow:
      return eq;
    default:
      break;
  }
  UNREACHABLE();
}
#endif

FPUCondition FlagsConditionToConditionCmpFPU(bool* predicate,
                                             FlagsCondition condition) {
  switch (condition) {
    case kEqual:
      *predicate = true;
      return EQ;
    case kNotEqual:
      *predicate = false;
      return EQ;
    case kUnsignedLessThan:
    case kFloatLessThan:
      *predicate = true;
      return LT;
    case kUnsignedGreaterThanOrEqual:
      *predicate = false;
      return LT;
    case kUnsignedLessThanOrEqual:
    case kFloatLessThanOrEqual:
      *predicate = true;
      return LE;
    case kUnsignedGreaterThan:
      *predicate = false;
      return LE;
    case kUnorderedEqual:
    case kUnorderedNotEqual:
      *predicate = true;
      break;
    case kFloatGreaterThan:
      *predicate = true;
      return GT;
    case kFloatGreaterThanOrEqual:
      *predicate = true;
      return GE;
    case kFloatLessThanOrUnordered:
      *predicate = true;
      return LT;
    case kFloatGreaterThanOrUnordered:
      *predicate = false;
      return LE;
    case kFloatGreaterThanOrEqualOrUnordered:
      *predicate = false;
      return LT;
    case kFloatLessThanOrEqualOrUnordered:
      *predicate = true;
      return LE;
    default:
      *predicate = true;
      break;
  }
  UNREACHABLE();
}

#if V8_ENABLE_WEBASSEMBLY
class WasmOutOfLineTrap : public OutOfLineCode {
 public:
  WasmOutOfLineTrap(CodeGenerator* gen, Instruction* instr)
      : OutOfLineCode(gen), gen_(gen), instr_(instr) {}
  void Generate() override {
    RiscvOperandConverter i(gen_, instr_);
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
    // A direct call to a wasm runtime stub defined in this module.
    // Just encode the stub index. This will be patched when the code
    // is added to the native module and copied into wasm code space.
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
}  // namespace

#define ASSEMBLE_ATOMIC_LOAD_INTEGER(asm_instr)                   \
  do {                                                            \
    __ asm_instr(i.OutputRegister(), i.MemoryOperand(), trapper); \
    __ sync();                                                    \
  } while (0)

#define ASSEMBLE_ATOMIC_STORE_INTEGER(asm_instr)                         \
  do {                                                                   \
    __ sync();                                                           \
    __ asm_instr(i.InputOrZeroRegister(0), i.MemoryOperand(1), trapper); \
    __ sync();                                                           \
  } while (0)

#define ASSEMBLE_ATOMIC_BINOP(load_linked, store_conditional, bin_instr)       \
  do {                                                                         \
    Label binop;                                                               \
    __ AddWord(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));     \
    __ sync();                                                                 \
    __ bind(&binop);                                                           \
    __ load_linked(i.OutputRegister(0), MemOperand(i.TempRegister(0), 0),      \
                   trapper);                                                   \
    __ bin_instr(i.TempRegister(1), i.OutputRegister(0),                       \
                 Operand(i.InputRegister(2)));                                 \
    __ store_conditional(i.TempRegister(1), MemOperand(i.TempRegister(0), 0)); \
    __ BranchShort(&binop, ne, i.TempRegister(1), Operand(zero_reg));          \
    __ sync();                                                                 \
  } while (0)

#define ASSEMBLE_ATOMIC64_LOGIC_BINOP(bin_instr, external)  \
  do {                                                      \
    FrameScope scope(masm(), StackFrame::MANUAL);           \
    __ AddWord(a0, i.InputRegister(0), i.InputRegister(1)); \
    __ PushCallerSaved(SaveFPRegsMode::kIgnore, a0, a1);    \
    __ PrepareCallCFunction(3, 0, kScratchReg);             \
    __ CallCFunction(ExternalReference::external(), 3, 0);  \
    __ PopCallerSaved(SaveFPRegsMode::kIgnore, a0, a1);     \
  } while (0)

#define ASSEMBLE_ATOMIC64_ARITH_BINOP(bin_instr, external)  \
  do {                                                      \
    FrameScope scope(masm(), StackFrame::MANUAL);           \
    __ AddWord(a0, i.InputRegister(0), i.InputRegister(1)); \
    __ PushCallerSaved(SaveFPRegsMode::kIgnore, a0, a1);    \
    __ PrepareCallCFunction(3, 0, kScratchReg);             \
    __ CallCFunction(ExternalReference::external(), 3, 0);  \
    __ PopCallerSaved(SaveFPRegsMode::kIgnore, a0, a1);     \
  } while (0)

#define ASSEMBLE_ATOMIC_BINOP_EXT(load_linked, store_conditional, sign_extend, \
                                  size, bin_instr, representation)             \
  do {                                                                         \
    Label binop;                                                               \
    __ AddWord(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));     \
    if (representation == 32) {                                                \
      __ And(i.TempRegister(3), i.TempRegister(0), 0x3);                       \
    } else {                                                                   \
      DCHECK_EQ(representation, 64);                                           \
      __ And(i.TempRegister(3), i.TempRegister(0), 0x7);                       \
    }                                                                          \
    __ SubWord(i.TempRegister(0), i.TempRegister(0),                           \
               Operand(i.TempRegister(3)));                                    \
    __ Sll32(i.TempRegister(3), i.TempRegister(3), 3);                         \
    __ sync();                                                                 \
    __ bind(&binop);                                                           \
    __ load_linked(i.TempRegister(1), MemOperand(i.TempRegister(0), 0),        \
                   trapper);                                                   \
    __ ExtractBits(i.OutputRegister(0), i.TempRegister(1), i.TempRegister(3),  \
                   size, sign_extend);                                         \
    __ bin_instr(i.TempRegister(2), i.OutputRegister(0),                       \
                 Operand(i.InputRegister(2)));                                 \
    __ InsertBits(i.TempRegister(1), i.TempRegister(2), i.TempRegister(3),     \
                  size);                                                       \
    __ store_conditional(i.TempRegister(1), MemOperand(i.TempRegister(0), 0)); \
    __ BranchShort(&binop, ne, i.TempRegister(1), Operand(zero_reg));          \
    __ sync();                                                                 \
  } while (0)

#define ASSEMBLE_ATOMIC_EXCHANGE_INTEGER(load_linked, store_conditional)       \
  do {                                                                         \
    Label exchange;                                                            \
    __ sync();                                                                 \
    __ bind(&exchange);                                                        \
    __ AddWord(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));     \
    __ load_linked(i.OutputRegister(0), MemOperand(i.TempRegister(0), 0),      \
                   trapper);                                                   \
    __ Move(i.TempRegister(1), i.InputRegister(2));                            \
    __ store_conditional(i.TempRegister(1), MemOperand(i.TempRegister(0), 0)); \
    __ BranchShort(&exchange, ne, i.TempRegister(1), Operand(zero_reg));       \
    __ sync();                                                                 \
  } while (0)

#define ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(                                  \
    load_linked, store_conditional, sign_extend, size, representation)         \
  do {                                                                         \
    Label exchange;                                                            \
    __ AddWord(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));     \
    if (representation == 32) {                                                \
      __ And(i.TempRegister(1), i.TempRegister(0), 0x3);                       \
    } else {                                                                   \
      DCHECK_EQ(representation, 64);                                           \
      __ And(i.TempRegister(1), i.TempRegister(0), 0x7);                       \
    }                                                                          \
    __ SubWord(i.TempRegister(0), i.TempRegister(0),                           \
               Operand(i.TempRegister(1)));                                    \
    __ Sll32(i.TempRegister(1), i.TempRegister(1), 3);                         \
    __ sync();                                                                 \
    __ bind(&exchange);                                                        \
    __ load_linked(i.TempRegister(2), MemOperand(i.TempRegister(0), 0),        \
                   trapper);                                                   \
    __ ExtractBits(i.OutputRegister(0), i.TempRegister(2), i.TempRegister(1),  \
                   size, sign_extend);                                         \
    __ InsertBits(i.TempRegister(2), i.InputRegister(2), i.TempRegister(1),    \
                  size);                                                       \
    __ store_conditional(i.TempRegister(2), MemOperand(i.TempRegister(0), 0)); \
    __ BranchShort(&exchange, ne, i.TempRegister(2), Operand(zero_reg));       \
    __ sync();                                                                 \
  } while (0)

#define ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(load_linked,                  \
                                                 store_conditional)            \
  do {                                                                         \
    Label compareExchange;                                                     \
    Label exit;                                                                \
    __ AddWord(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));     \
    __ sync();                                                                 \
    __ bind(&compareExchange);                                                 \
    __ load_linked(i.OutputRegister(0), MemOperand(i.TempRegister(0), 0),      \
                   trapper);                                                   \
    __ BranchShort(&exit, ne, i.InputRegister(2),                              \
                   Operand(i.OutputRegister(0)));                              \
    __ Move(i.TempRegister(2), i.InputRegister(3));                            \
    __ store_conditional(i.TempRegister(2), MemOperand(i.TempRegister(0), 0)); \
    __ BranchShort(&compareExchange, ne, i.TempRegister(2),                    \
                   Operand(zero_reg));                                         \
    __ bind(&exit);                                                            \
    __ sync();                                                                 \
  } while (0)

#define ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(                          \
    load_linked, store_conditional, sign_extend, size, representation)         \
  do {                                                                         \
    Label compareExchange;                                                     \
    Label exit;                                                                \
    __ AddWord(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));     \
    if (representation == 32) {                                                \
      __ And(i.TempRegister(1), i.TempRegister(0), 0x3);                       \
    } else {                                                                   \
      DCHECK_EQ(representation, 64);                                           \
      __ And(i.TempRegister(1), i.TempRegister(0), 0x7);                       \
    }                                                                          \
    __ SubWord(i.TempRegister(0), i.TempRegister(0),                           \
               Operand(i.TempRegister(1)));                                    \
    __ Sll32(i.TempRegister(1), i.TempRegister(1), 3);                         \
    __ sync();                                                                 \
    __ bind(&compareExchange);                                                 \
    __ load_linked(i.TempRegister(2), MemOperand(i.TempRegister(0), 0),        \
                   trapper);                                                   \
    __ ExtractBits(i.OutputRegister(0), i.TempRegister(2), i.TempRegister(1),  \
                   size, sign_extend);                                         \
    __ ExtractBits(i.InputRegister(2), i.InputRegister(2), 0, size,            \
                   sign_extend);                                               \
    __ BranchShort(&exit, ne, i.InputRegister(2),                              \
                   Operand(i.OutputRegister(0)));                              \
    __ InsertBits(i.TempRegister(2), i.InputRegister(3), i.TempRegister(1),    \
                  size);                                                       \
    __ store_conditional(i.TempRegister(2), MemOperand(i.TempRegister(0), 0)); \
    __ BranchShort(&compareExchange, ne, i.TempRegister(2),                    \
                   Operand(zero_reg));                                         \
    __ bind(&exit);                                                            \
    __ sync();                                                                 \
  } while (0)

#define ASSEMBLE_IEEE754_BINOP(name)                                        \
  do {                                                                      \
    FrameScope scope(masm(), StackFrame::MANUAL);                           \
    __ PrepareCallCFunction(0, 2, kScratchReg);                             \
    __ MovToFloatParameters(i.InputDoubleRegister(0),                       \
                            i.InputDoubleRegister(1));                      \
    __ CallCFunction(ExternalReference::ieee754_##name##_function(), 0, 2); \
    /* Move the result in the double result register. */                    \
    __ MovFromFloatResult(i.OutputDoubleRegister());                        \
  } while (0)

#define ASSEMBLE_IEEE754_UNOP(name)                                         \
  do {                                                                      \
    FrameScope scope(masm(), StackFrame::MANUAL);                           \
    __ PrepareCallCFunction(0, 1, kScratchReg);                             \
    __ MovToFloatParameter(i.InputDoubleRegister(0));                       \
    __ CallCFunction(ExternalReference::ieee754_##name##_function(), 0, 1); \
    /* Move the result in the double result register. */                    \
    __ MovFromFloatResult(i.OutputDoubleRegister());                        \
  } while (0)

#define ASSEMBLE_F64X2_ARITHMETIC_BINOP(op)                     \
  do {                                                          \
    __ op(i.OutputSimd128Register(), i.InputSimd128Register(0), \
          i.InputSimd128Register(1));                           \
  } while (0)

#define ASSEMBLE_RVV_BINOP_INTEGER(instr, OP)                   \
  case kRiscvI8x16##instr: {                                    \
    __ VU.set(kScratchReg, E8, m1);                             \
    __ OP(i.OutputSimd128Register(), i.InputSimd128Register(0), \
          i.InputSimd128Register(1));                           \
    break;                                                      \
  }                                                             \
  case kRiscvI16x8##instr: {                                    \
    __ VU.set(kScratchReg, E16, m1);                            \
    __ OP(i.OutputSimd128Register(), i.InputSimd128Register(0), \
          i.InputSimd128Register(1));                           \
    break;                                                      \
  }                                                             \
  case kRiscvI32x4##instr: {                                    \
    __ VU.set(kScratchReg, E32, m1);                            \
    __ OP(i.OutputSimd128Register(), i.InputSimd128Register(0), \
          i.InputSimd128Register(1));                           \
    break;                                                      \
  }

#define ASSEMBLE_RVV_UNOP_INTEGER_VR(instr, OP)           \
  case kRiscvI8x16##instr: {                              \
    __ VU.set(kScratchReg, E8, m1);                       \
    __ OP(i.OutputSimd128Register(), i.InputRegister(0)); \
    break;                                                \
  }                                                       \
  case kRiscvI16x8##instr: {                              \
    __ VU.set(kScratchReg, E16, m1);                      \
    __ OP(i.OutputSimd128Register(), i.InputRegister(0)); \
    break;                                                \
  }                                                       \
  case kRiscvI32x4##instr: {                              \
    __ VU.set(kScratchReg, E32, m1);                      \
    __ OP(i.OutputSimd128Register(), i.InputRegister(0)); \
    break;                                                \
  }

#define ASSEMBLE_RVV_UNOP_INTEGER_VV(instr, OP)                  \
  case kRiscvI8x16##instr: {                                     \
    __ VU.set(kScratchReg, E8, m1);                              \
    __ OP(i.OutputSimd128Register(), i.InputSimd128Register(0)); \
    break;                                                       \
  }                                                              \
  case kRiscvI16x
### 提示词
```
这是目录为v8/src/compiler/backend/riscv/code-generator-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/riscv/code-generator-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/codegen/assembler-inl.h"
#include "src/codegen/callable.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/optimized-compilation-info.h"
#include "src/codegen/riscv/constants-riscv.h"
#include "src/compiler/backend/code-generator-impl.h"
#include "src/compiler/backend/code-generator.h"
#include "src/compiler/backend/gap-resolver.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/osr.h"
#include "src/heap/mutable-page-metadata.h"

namespace v8 {
namespace internal {
namespace compiler {

#define __ masm()->

#define TRACE(...) PrintF(__VA_ARGS__)

// Adds RISC-V-specific methods to convert InstructionOperands.
class RiscvOperandConverter final : public InstructionOperandConverter {
 public:
  RiscvOperandConverter(CodeGenerator* gen, Instruction* instr)
      : InstructionOperandConverter(gen, instr) {}

  FloatRegister OutputSingleRegister(size_t index = 0) {
    return ToSingleRegister(instr_->OutputAt(index));
  }

  FloatRegister InputSingleRegister(size_t index) {
    return ToSingleRegister(instr_->InputAt(index));
  }

  FloatRegister ToSingleRegister(InstructionOperand* op) {
    // Single (Float) and Double register namespace is same on RISC-V,
    // both are typedefs of FPURegister.
    return ToDoubleRegister(op);
  }

  Register InputOrZeroRegister(size_t index) {
    if (instr_->InputAt(index)->IsImmediate()) {
      Constant constant = ToConstant(instr_->InputAt(index));
      switch (constant.type()) {
        case Constant::kInt32:
        case Constant::kInt64:
          DCHECK_EQ(0, InputInt32(index));
          break;
        case Constant::kFloat32:
          DCHECK_EQ(0, base::bit_cast<int32_t>(InputFloat32(index)));
          break;
        case Constant::kFloat64:
          DCHECK_EQ(0, base::bit_cast<int64_t>(InputDouble(index)));
          break;
        default:
          UNREACHABLE();
      }
      return zero_reg;
    }
    return InputRegister(index);
  }

  DoubleRegister InputOrZeroDoubleRegister(size_t index) {
    if (instr_->InputAt(index)->IsImmediate()) return kDoubleRegZero;

    return InputDoubleRegister(index);
  }

  DoubleRegister InputOrZeroSingleRegister(size_t index) {
    if (instr_->InputAt(index)->IsImmediate()) return kSingleRegZero;

    return InputSingleRegister(index);
  }

  Operand InputImmediate(size_t index) {
    Constant constant = ToConstant(instr_->InputAt(index));
    switch (constant.type()) {
      case Constant::kInt32:
        return Operand(constant.ToInt32());
      case Constant::kInt64:
        return Operand(constant.ToInt64());
      case Constant::kFloat32:
        return Operand::EmbeddedNumber(constant.ToFloat32());
      case Constant::kFloat64:
        return Operand::EmbeddedNumber(constant.ToFloat64().value());
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
      case Constant::kExternalReference:
      case Constant::kHeapObject:
        // TODO(plind): Maybe we should handle ExtRef & HeapObj here?
        //    maybe not done on arm due to const pool ??
        break;
      case Constant::kRpoNumber:
        UNREACHABLE();  // TODO(titzer): RPO immediates
    }
    UNREACHABLE();
  }

  Operand InputOperand(size_t index) {
    InstructionOperand* op = instr_->InputAt(index);
    if (op->IsRegister()) {
      return Operand(ToRegister(op));
    }
    return InputImmediate(index);
  }

  MemOperand MemoryOperand(size_t* first_index) {
    const size_t index = *first_index;
    switch (AddressingModeField::decode(instr_->opcode())) {
      case kMode_None:
        break;
      case kMode_MRI:
        *first_index += 2;
        return MemOperand(InputRegister(index + 0), InputInt32(index + 1));
      case kMode_Root:
        return MemOperand(kRootRegister, InputInt32(index));
      case kMode_MRR:
        // TODO(plind): r6 address mode, to be implemented ...
        UNREACHABLE();
    }
    UNREACHABLE();
  }

  MemOperand MemoryOperand(size_t index = 0) { return MemoryOperand(&index); }

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
      CodeGenerator* gen, Register object, Operand offset, Register value,
      RecordWriteMode mode, StubCallMode stub_mode,
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
        zone_(gen->zone()),
        indirect_pointer_tag_(indirect_pointer_tag) {
  }

  void Generate() final {
#ifdef V8_TARGET_ARCH_RISCV64
    // When storing an indirect pointer, the value will always be a
    // full/decompressed pointer.
    if (COMPRESS_POINTERS_BOOL &&
        mode_ != RecordWriteMode::kValueIsIndirectPointer) {
      __ DecompressTagged(value_, value_);
    }
#endif
    __ CheckPageFlag(value_, MemoryChunk::kPointersToHereAreInterestingMask, eq,
                     exit());

    SaveFPRegsMode const save_fp_mode = frame()->DidAllocateDoubleRegisters()
                                            ? SaveFPRegsMode::kSave
                                            : SaveFPRegsMode::kIgnore;
    if (must_save_lr_) {
      // We need to save and restore ra if the frame was elided.
      __ Push(ra);
    }
    if (mode_ == RecordWriteMode::kValueIsEphemeronKey) {
      __ CallEphemeronKeyBarrier(object_, offset_, save_fp_mode);
    } else if (mode_ == RecordWriteMode::kValueIsIndirectPointer) {
      DCHECK(IsValidIndirectPointerTag(indirect_pointer_tag_));
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
      __ Pop(ra);
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
  Zone* zone_;
  IndirectPointerTag indirect_pointer_tag_;
};

Condition FlagsConditionToConditionCmp(FlagsCondition condition) {
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
      return Uless;
    case kUnsignedGreaterThanOrEqual:
      return Ugreater_equal;
    case kUnsignedLessThanOrEqual:
      return Uless_equal;
    case kUnsignedGreaterThan:
      return Ugreater;
    case kUnorderedEqual:
    case kUnorderedNotEqual:
      break;
    default:
      break;
  }
  UNREACHABLE();
}

Condition FlagsConditionToConditionTst(FlagsCondition condition) {
  switch (condition) {
    case kNotEqual:
      return ne;
    case kEqual:
      return eq;
    default:
      break;
  }
  UNREACHABLE();
}
#if V8_TARGET_ARCH_RISCV64
Condition FlagsConditionToConditionOvf(FlagsCondition condition) {
  switch (condition) {
    case kOverflow:
      return ne;
    case kNotOverflow:
      return eq;
    default:
      break;
  }
  UNREACHABLE();
}
#endif

FPUCondition FlagsConditionToConditionCmpFPU(bool* predicate,
                                             FlagsCondition condition) {
  switch (condition) {
    case kEqual:
      *predicate = true;
      return EQ;
    case kNotEqual:
      *predicate = false;
      return EQ;
    case kUnsignedLessThan:
    case kFloatLessThan:
      *predicate = true;
      return LT;
    case kUnsignedGreaterThanOrEqual:
      *predicate = false;
      return LT;
    case kUnsignedLessThanOrEqual:
    case kFloatLessThanOrEqual:
      *predicate = true;
      return LE;
    case kUnsignedGreaterThan:
      *predicate = false;
      return LE;
    case kUnorderedEqual:
    case kUnorderedNotEqual:
      *predicate = true;
      break;
    case kFloatGreaterThan:
      *predicate = true;
      return GT;
    case kFloatGreaterThanOrEqual:
      *predicate = true;
      return GE;
    case kFloatLessThanOrUnordered:
      *predicate = true;
      return LT;
    case kFloatGreaterThanOrUnordered:
      *predicate = false;
      return LE;
    case kFloatGreaterThanOrEqualOrUnordered:
      *predicate = false;
      return LT;
    case kFloatLessThanOrEqualOrUnordered:
      *predicate = true;
      return LE;
    default:
      *predicate = true;
      break;
  }
  UNREACHABLE();
}

#if V8_ENABLE_WEBASSEMBLY
class WasmOutOfLineTrap : public OutOfLineCode {
 public:
  WasmOutOfLineTrap(CodeGenerator* gen, Instruction* instr)
      : OutOfLineCode(gen), gen_(gen), instr_(instr) {}
  void Generate() override {
    RiscvOperandConverter i(gen_, instr_);
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
    // A direct call to a wasm runtime stub defined in this module.
    // Just encode the stub index. This will be patched when the code
    // is added to the native module and copied into wasm code space.
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
}  // namespace

#define ASSEMBLE_ATOMIC_LOAD_INTEGER(asm_instr)                   \
  do {                                                            \
    __ asm_instr(i.OutputRegister(), i.MemoryOperand(), trapper); \
    __ sync();                                                    \
  } while (0)

#define ASSEMBLE_ATOMIC_STORE_INTEGER(asm_instr)                         \
  do {                                                                   \
    __ sync();                                                           \
    __ asm_instr(i.InputOrZeroRegister(0), i.MemoryOperand(1), trapper); \
    __ sync();                                                           \
  } while (0)

#define ASSEMBLE_ATOMIC_BINOP(load_linked, store_conditional, bin_instr)       \
  do {                                                                         \
    Label binop;                                                               \
    __ AddWord(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));     \
    __ sync();                                                                 \
    __ bind(&binop);                                                           \
    __ load_linked(i.OutputRegister(0), MemOperand(i.TempRegister(0), 0),      \
                   trapper);                                                   \
    __ bin_instr(i.TempRegister(1), i.OutputRegister(0),                       \
                 Operand(i.InputRegister(2)));                                 \
    __ store_conditional(i.TempRegister(1), MemOperand(i.TempRegister(0), 0)); \
    __ BranchShort(&binop, ne, i.TempRegister(1), Operand(zero_reg));          \
    __ sync();                                                                 \
  } while (0)

#define ASSEMBLE_ATOMIC64_LOGIC_BINOP(bin_instr, external)  \
  do {                                                      \
    FrameScope scope(masm(), StackFrame::MANUAL);           \
    __ AddWord(a0, i.InputRegister(0), i.InputRegister(1)); \
    __ PushCallerSaved(SaveFPRegsMode::kIgnore, a0, a1);    \
    __ PrepareCallCFunction(3, 0, kScratchReg);             \
    __ CallCFunction(ExternalReference::external(), 3, 0);  \
    __ PopCallerSaved(SaveFPRegsMode::kIgnore, a0, a1);     \
  } while (0)

#define ASSEMBLE_ATOMIC64_ARITH_BINOP(bin_instr, external)  \
  do {                                                      \
    FrameScope scope(masm(), StackFrame::MANUAL);           \
    __ AddWord(a0, i.InputRegister(0), i.InputRegister(1)); \
    __ PushCallerSaved(SaveFPRegsMode::kIgnore, a0, a1);    \
    __ PrepareCallCFunction(3, 0, kScratchReg);             \
    __ CallCFunction(ExternalReference::external(), 3, 0);  \
    __ PopCallerSaved(SaveFPRegsMode::kIgnore, a0, a1);     \
  } while (0)

#define ASSEMBLE_ATOMIC_BINOP_EXT(load_linked, store_conditional, sign_extend, \
                                  size, bin_instr, representation)             \
  do {                                                                         \
    Label binop;                                                               \
    __ AddWord(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));     \
    if (representation == 32) {                                                \
      __ And(i.TempRegister(3), i.TempRegister(0), 0x3);                       \
    } else {                                                                   \
      DCHECK_EQ(representation, 64);                                           \
      __ And(i.TempRegister(3), i.TempRegister(0), 0x7);                       \
    }                                                                          \
    __ SubWord(i.TempRegister(0), i.TempRegister(0),                           \
               Operand(i.TempRegister(3)));                                    \
    __ Sll32(i.TempRegister(3), i.TempRegister(3), 3);                         \
    __ sync();                                                                 \
    __ bind(&binop);                                                           \
    __ load_linked(i.TempRegister(1), MemOperand(i.TempRegister(0), 0),        \
                   trapper);                                                   \
    __ ExtractBits(i.OutputRegister(0), i.TempRegister(1), i.TempRegister(3),  \
                   size, sign_extend);                                         \
    __ bin_instr(i.TempRegister(2), i.OutputRegister(0),                       \
                 Operand(i.InputRegister(2)));                                 \
    __ InsertBits(i.TempRegister(1), i.TempRegister(2), i.TempRegister(3),     \
                  size);                                                       \
    __ store_conditional(i.TempRegister(1), MemOperand(i.TempRegister(0), 0)); \
    __ BranchShort(&binop, ne, i.TempRegister(1), Operand(zero_reg));          \
    __ sync();                                                                 \
  } while (0)

#define ASSEMBLE_ATOMIC_EXCHANGE_INTEGER(load_linked, store_conditional)       \
  do {                                                                         \
    Label exchange;                                                            \
    __ sync();                                                                 \
    __ bind(&exchange);                                                        \
    __ AddWord(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));     \
    __ load_linked(i.OutputRegister(0), MemOperand(i.TempRegister(0), 0),      \
                   trapper);                                                   \
    __ Move(i.TempRegister(1), i.InputRegister(2));                            \
    __ store_conditional(i.TempRegister(1), MemOperand(i.TempRegister(0), 0)); \
    __ BranchShort(&exchange, ne, i.TempRegister(1), Operand(zero_reg));       \
    __ sync();                                                                 \
  } while (0)

#define ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(                                  \
    load_linked, store_conditional, sign_extend, size, representation)         \
  do {                                                                         \
    Label exchange;                                                            \
    __ AddWord(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));     \
    if (representation == 32) {                                                \
      __ And(i.TempRegister(1), i.TempRegister(0), 0x3);                       \
    } else {                                                                   \
      DCHECK_EQ(representation, 64);                                           \
      __ And(i.TempRegister(1), i.TempRegister(0), 0x7);                       \
    }                                                                          \
    __ SubWord(i.TempRegister(0), i.TempRegister(0),                           \
               Operand(i.TempRegister(1)));                                    \
    __ Sll32(i.TempRegister(1), i.TempRegister(1), 3);                         \
    __ sync();                                                                 \
    __ bind(&exchange);                                                        \
    __ load_linked(i.TempRegister(2), MemOperand(i.TempRegister(0), 0),        \
                   trapper);                                                   \
    __ ExtractBits(i.OutputRegister(0), i.TempRegister(2), i.TempRegister(1),  \
                   size, sign_extend);                                         \
    __ InsertBits(i.TempRegister(2), i.InputRegister(2), i.TempRegister(1),    \
                  size);                                                       \
    __ store_conditional(i.TempRegister(2), MemOperand(i.TempRegister(0), 0)); \
    __ BranchShort(&exchange, ne, i.TempRegister(2), Operand(zero_reg));       \
    __ sync();                                                                 \
  } while (0)

#define ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(load_linked,                  \
                                                 store_conditional)            \
  do {                                                                         \
    Label compareExchange;                                                     \
    Label exit;                                                                \
    __ AddWord(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));     \
    __ sync();                                                                 \
    __ bind(&compareExchange);                                                 \
    __ load_linked(i.OutputRegister(0), MemOperand(i.TempRegister(0), 0),      \
                   trapper);                                                   \
    __ BranchShort(&exit, ne, i.InputRegister(2),                              \
                   Operand(i.OutputRegister(0)));                              \
    __ Move(i.TempRegister(2), i.InputRegister(3));                            \
    __ store_conditional(i.TempRegister(2), MemOperand(i.TempRegister(0), 0)); \
    __ BranchShort(&compareExchange, ne, i.TempRegister(2),                    \
                   Operand(zero_reg));                                         \
    __ bind(&exit);                                                            \
    __ sync();                                                                 \
  } while (0)

#define ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(                          \
    load_linked, store_conditional, sign_extend, size, representation)         \
  do {                                                                         \
    Label compareExchange;                                                     \
    Label exit;                                                                \
    __ AddWord(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));     \
    if (representation == 32) {                                                \
      __ And(i.TempRegister(1), i.TempRegister(0), 0x3);                       \
    } else {                                                                   \
      DCHECK_EQ(representation, 64);                                           \
      __ And(i.TempRegister(1), i.TempRegister(0), 0x7);                       \
    }                                                                          \
    __ SubWord(i.TempRegister(0), i.TempRegister(0),                           \
               Operand(i.TempRegister(1)));                                    \
    __ Sll32(i.TempRegister(1), i.TempRegister(1), 3);                         \
    __ sync();                                                                 \
    __ bind(&compareExchange);                                                 \
    __ load_linked(i.TempRegister(2), MemOperand(i.TempRegister(0), 0),        \
                   trapper);                                                   \
    __ ExtractBits(i.OutputRegister(0), i.TempRegister(2), i.TempRegister(1),  \
                   size, sign_extend);                                         \
    __ ExtractBits(i.InputRegister(2), i.InputRegister(2), 0, size,            \
                   sign_extend);                                               \
    __ BranchShort(&exit, ne, i.InputRegister(2),                              \
                   Operand(i.OutputRegister(0)));                              \
    __ InsertBits(i.TempRegister(2), i.InputRegister(3), i.TempRegister(1),    \
                  size);                                                       \
    __ store_conditional(i.TempRegister(2), MemOperand(i.TempRegister(0), 0)); \
    __ BranchShort(&compareExchange, ne, i.TempRegister(2),                    \
                   Operand(zero_reg));                                         \
    __ bind(&exit);                                                            \
    __ sync();                                                                 \
  } while (0)

#define ASSEMBLE_IEEE754_BINOP(name)                                        \
  do {                                                                      \
    FrameScope scope(masm(), StackFrame::MANUAL);                           \
    __ PrepareCallCFunction(0, 2, kScratchReg);                             \
    __ MovToFloatParameters(i.InputDoubleRegister(0),                       \
                            i.InputDoubleRegister(1));                      \
    __ CallCFunction(ExternalReference::ieee754_##name##_function(), 0, 2); \
    /* Move the result in the double result register. */                    \
    __ MovFromFloatResult(i.OutputDoubleRegister());                        \
  } while (0)

#define ASSEMBLE_IEEE754_UNOP(name)                                         \
  do {                                                                      \
    FrameScope scope(masm(), StackFrame::MANUAL);                           \
    __ PrepareCallCFunction(0, 1, kScratchReg);                             \
    __ MovToFloatParameter(i.InputDoubleRegister(0));                       \
    __ CallCFunction(ExternalReference::ieee754_##name##_function(), 0, 1); \
    /* Move the result in the double result register. */                    \
    __ MovFromFloatResult(i.OutputDoubleRegister());                        \
  } while (0)

#define ASSEMBLE_F64X2_ARITHMETIC_BINOP(op)                     \
  do {                                                          \
    __ op(i.OutputSimd128Register(), i.InputSimd128Register(0), \
          i.InputSimd128Register(1));                           \
  } while (0)

#define ASSEMBLE_RVV_BINOP_INTEGER(instr, OP)                   \
  case kRiscvI8x16##instr: {                                    \
    __ VU.set(kScratchReg, E8, m1);                             \
    __ OP(i.OutputSimd128Register(), i.InputSimd128Register(0), \
          i.InputSimd128Register(1));                           \
    break;                                                      \
  }                                                             \
  case kRiscvI16x8##instr: {                                    \
    __ VU.set(kScratchReg, E16, m1);                            \
    __ OP(i.OutputSimd128Register(), i.InputSimd128Register(0), \
          i.InputSimd128Register(1));                           \
    break;                                                      \
  }                                                             \
  case kRiscvI32x4##instr: {                                    \
    __ VU.set(kScratchReg, E32, m1);                            \
    __ OP(i.OutputSimd128Register(), i.InputSimd128Register(0), \
          i.InputSimd128Register(1));                           \
    break;                                                      \
  }

#define ASSEMBLE_RVV_UNOP_INTEGER_VR(instr, OP)           \
  case kRiscvI8x16##instr: {                              \
    __ VU.set(kScratchReg, E8, m1);                       \
    __ OP(i.OutputSimd128Register(), i.InputRegister(0)); \
    break;                                                \
  }                                                       \
  case kRiscvI16x8##instr: {                              \
    __ VU.set(kScratchReg, E16, m1);                      \
    __ OP(i.OutputSimd128Register(), i.InputRegister(0)); \
    break;                                                \
  }                                                       \
  case kRiscvI32x4##instr: {                              \
    __ VU.set(kScratchReg, E32, m1);                      \
    __ OP(i.OutputSimd128Register(), i.InputRegister(0)); \
    break;                                                \
  }

#define ASSEMBLE_RVV_UNOP_INTEGER_VV(instr, OP)                  \
  case kRiscvI8x16##instr: {                                     \
    __ VU.set(kScratchReg, E8, m1);                              \
    __ OP(i.OutputSimd128Register(), i.InputSimd128Register(0)); \
    break;                                                       \
  }                                                              \
  case kRiscvI16x8##instr: {                                     \
    __ VU.set(kScratchReg, E16, m1);                             \
    __ OP(i.OutputSimd128Register(), i.InputSimd128Register(0)); \
    break;                                                       \
  }                                                              \
  case kRiscvI32x4##instr: {                                     \
    __ VU.set(kScratchReg, E32, m1);                             \
    __ OP(i.OutputSimd128Register(), i.InputSimd128Register(0)); \
    break;                                                       \
  }                                                              \
  case kRiscvI64x2##instr: {                                     \
    __ VU.set(kScratchReg, E64, m1);                             \
    __ OP(i.OutputSimd128Register(), i.InputSimd128Register(0)); \
    break;                                                       \
  }

void CodeGenerator::AssembleDeconstructFrame() {
  __ Move(sp, fp);
  __ Pop(ra, fp);
}

void CodeGenerator::AssemblePrepareTailCall() {
  if (frame_access_state()->has_frame()) {
    __ LoadWord(ra, MemOperand(fp, StandardFrameConstants::kCallerPCOffset));
    __ LoadWord(fp, MemOperand(fp, StandardFrameConstants::kCallerFPOffset));
  }
  frame_access_state()->SetFrameAccessToSP();
}

void CodeGenerator::AssembleArchSelect(Instruction* instr,
                                       FlagsCondition condition) {
  UNIMPLEMENTED();
}

namespace {

void AdjustStackPointerForTailCall(MacroAssembler* masm,
                                   FrameAccessState* state,
                                   int new_slot_above_sp,
                                   bool allow_shrinkage = true) {
  int current_sp_offset = state->GetSPToFPSlotCount() +
                          StandardFrameConstants::kFixedSlotCountAboveFp;
  int stack_slot_delta = new_slot_above_sp - current_sp_offset;
  if (stack_slot_delta > 0) {
    masm->SubWord(sp, sp, stack_slot_delta * kSystemPointerSize);
    state->IncreaseSPDelta(stack_slot_delta);
  } else if (allow_shrinkage && stack_slot_delta < 0) {
    masm->AddWord(sp, sp, -stack_slot_delta * kSystemPointerSize);
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
  AdjustStackPointerForTailCall(masm(), frame_access_state(),
                                first_unused_slot_offset);
}

// Check that {kJavaScriptCallCodeStartRegister} is correct.
void CodeGenerator::AssembleCodeStartRegisterCheck() {
  __ ComputeCodeStartAddress(kScratchReg);
  __ Assert(eq, AbortReason::kWrongFunctionCodeStart,
            kJavaScriptCallCodeStartRegister, Operand(kScratchReg));
}

// Check if the code object is marked for deoptimization. If it is, then it
// jumps to the CompileLazyDeoptimizedCode builtin. In order to do this we need
// to:
//    1. read from memory the word that contains that bit, which can be found in
//       the flags in the referenced {Code} object;
//    2. test kMarkedForDeoptimizationBit in those flags; and
//    3. if it is not zero then it jumps to the builtin.
void CodeGenerator::BailoutIfDeoptimized() {
  int offset = InstructionStream::kCodeOffset - InstructionStream::kHeaderSize;
  __ LoadProtectedPointerField(
      kScratchReg, MemOperand(kJavaScriptCallCodeStartRegister, offset));
  __ Lw(kScratchReg, FieldMemOperand(kScratchReg, Code::kFlagsOffset));
  __ And(kScratchReg, kScratchReg,
         Operand(1 << Code::kMarkedForDeoptimizationBit));
  __ TailCallBuiltin(Builtin::kCompileLazyDeoptimizedCode, ne, kScratchReg,
                     Operand(zero_reg));
}

// Assembles an instruction after register allocation, producing machine code.
CodeGenerator::CodeGenResult CodeGenerator::AssembleArchInstruction(
    Instruction* instr) {
  RiscvOperandConverter i(this, instr);
  InstructionCode opcode = instr->opcode();
  ArchOpcode arch_opcode = ArchOpcodeField::decode(opcode);
  auto trappe
```