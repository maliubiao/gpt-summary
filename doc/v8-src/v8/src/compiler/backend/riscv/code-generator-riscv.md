Response: The user wants a summary of the provided C++ code. The code is part of the V8 JavaScript engine, specifically the RISC-V backend's code generator. I need to identify the main functionalities implemented in this code snippet.

Key elements in the code:

1. **Includes**: Standard V8 headers for code generation.
2. **Namespaces**:  `v8::internal::compiler`.
3. **Macros**:  `__` for assembler calls, `TRACE` for debugging.
4. **`RiscvOperandConverter` class**:  Handles the conversion of instruction operands to RISC-V specific types (registers, memory operands, immediates).
5. **`OutOfLineRecordWrite` class**:  Implements the logic for write barriers, which are crucial for garbage collection in JavaScript.
6. **Helper functions**:  Functions to convert `FlagsCondition` to RISC-V specific condition codes for comparisons and tests.
7. **`WasmOutOfLineTrap` class (conditional compilation)**: Handles out-of-line traps for WebAssembly.
8. **Atomic operation macros**:  `ASSEMBLE_ATOMIC_LOAD_INTEGER`, `ASSEMBLE_ATOMIC_STORE_INTEGER`, etc., define how atomic operations are generated.
9. **IEEE 754 operation macros**: `ASSEMBLE_IEEE754_BINOP`, `ASSEMBLE_IEEE754_UNOP` for floating-point operations.
10. **RVV operation macros (conditional compilation)**: `ASSEMBLE_RVV_BINOP_INTEGER`, etc., for RISC-V Vector extension instructions.
11. **`AssembleDeconstructFrame`**:  Code to tear down a stack frame.
12. **`AssemblePrepareTailCall`**: Code to prepare for a tail call optimization.
13. **`AssembleArchSelect`**: Placeholder for conditional selection (not implemented).
14. **`AdjustStackPointerForTailCall`**:  Helper for adjusting the stack pointer during tail calls.
15. **`AssembleTailCallBeforeGap`**, **`AssembleTailCallAfterGap`**:  Integration points for tail call stack adjustments.
16. **`AssembleCodeStartRegisterCheck`**:  Verification of the code start register.
17. **`BailoutIfDeoptimized`**: Checks for deoptimization flags.
18. **`AssembleArchInstruction`**: The central function that dispatches to different code generation logic based on the instruction's opcode. This section contains a large `switch` statement handling various RISC-V instructions.

Based on these observations, the primary function is to **translate intermediate representation (IR) instructions into actual RISC-V machine code**. This includes handling operand conversions, implementing garbage collection write barriers, generating code for various arithmetic, logical, memory access, control flow, and floating-point operations specific to the RISC-V architecture. The presence of WebAssembly-related code indicates it also plays a role in compiling WebAssembly code for RISC-V.

Regarding the relationship with JavaScript: The generated RISC-V code directly executes the logic of JavaScript functions. For example, arithmetic operations in JavaScript are translated into corresponding RISC-V instructions. Garbage collection, crucial for JavaScript's memory management, relies on the write barrier code generated here.

Example in JavaScript:

```javascript
function add(a, b) {
  return a + b;
}
```

The `kRiscvAdd32` or `kRiscvAdd64` cases in the `AssembleArchInstruction` function would be responsible for generating the RISC-V instruction that performs the addition operation for this JavaScript function. The `OutOfLineRecordWrite` class is related to how JavaScript objects are updated, ensuring the garbage collector is aware of these changes.
This C++ code file, `code-generator-riscv.cc`, is a crucial part of the V8 JavaScript engine's backend for the RISC-V architecture. Its primary function is **to generate RISC-V assembly code from a higher-level intermediate representation (IR) of JavaScript code**. This process is a key step in the just-in-time (JIT) compilation of JavaScript, allowing for efficient execution on RISC-V processors.

Here's a breakdown of its key functionalities based on the code snippet:

1. **Operand Conversion:** It provides a `RiscvOperandConverter` class to translate generic instruction operands into RISC-V specific operands like registers, immediate values, and memory addresses. This ensures that the generated assembly code uses the correct RISC-V syntax and addressing modes.

2. **Generating RISC-V Instructions:** The `AssembleArchInstruction` function (partially shown) is the heart of the code generator. It takes an IR instruction as input and, based on the instruction's opcode, emits the corresponding RISC-V assembly instructions using the `MacroAssembler` class. It handles a wide variety of operations, including:
    *   Function calls (direct and tail calls)
    *   Arithmetic and logical operations (integer and floating-point)
    *   Memory access (loads and stores)
    *   Comparisons and conditional branches
    *   Bit manipulation
    *   Floating-point conversions and mathematical functions
    *   Atomic operations
    *   Stack frame management

3. **Handling Write Barriers for Garbage Collection:** The `OutOfLineRecordWrite` class implements the logic for write barriers. These are essential for garbage collection in JavaScript. When the code modifies an object that might contain pointers to other objects, the write barrier ensures the garbage collector is informed about this change, preventing memory leaks and dangling pointers.

4. **Support for WebAssembly (Conditional):** The code includes conditional compilation blocks (`#if V8_ENABLE_WEBASSEMBLY`) that suggest it also handles the code generation for WebAssembly modules when targeting the RISC-V architecture. The `WasmOutOfLineTrap` class is an example of this.

5. **Tail Call Optimization:**  Functions like `AssemblePrepareTailCall`, `AdjustStackPointerForTailCall`, `AssembleTailCallBeforeGap`, and `AssembleTailCallAfterGap` are responsible for implementing tail call optimization, which can improve performance and reduce stack usage for certain function call patterns.

6. **Code Start and Deoptimization Checks:** The code includes mechanisms to verify the function's code start address and to bail out (deoptimize) if the code object has been marked for deoptimization.

**Relationship with JavaScript and Examples:**

This code directly translates JavaScript's operational semantics into machine code. Every time a JavaScript function is executed by the JIT compiler, code like this is used to generate the low-level RISC-V instructions.

Here are some conceptual JavaScript examples and how they might relate to the code:

**1. JavaScript Addition:**

```javascript
function add(x, y) {
  return x + y;
}
```

When this JavaScript function is compiled, the `AssembleArchInstruction` function would likely encounter an IR instruction representing the addition operation. This would lead to the emission of a RISC-V addition instruction, potentially using the `kRiscvAdd32` or `kRiscvAdd64` cases within the `switch` statement. The `RiscvOperandConverter` would be used to determine which registers hold the values of `x` and `y` and the register where the result should be stored.

**2. JavaScript Object Property Assignment:**

```javascript
let obj = {};
obj.name = "example";
```

When the assignment `obj.name = "example"` is compiled, the code generator would need to generate instructions to store the string "example" into the memory location corresponding to the `name` property of the `obj` object. If `obj` is a heap object, this operation might involve a write barrier, leveraging the `OutOfLineRecordWrite` class. The code would check if the object is in a memory space requiring write barriers and call the appropriate barrier function if necessary.

**3. JavaScript Function Call:**

```javascript
function greet(name) {
  console.log("Hello, " + name);
}

greet("World");
```

The call to `greet("World")` would be translated into a RISC-V call instruction. The `kArchCallJSFunction` case in `AssembleArchInstruction` would be responsible for generating the necessary assembly to set up the arguments, jump to the `greet` function's code, and handle the return.

In summary, `code-generator-riscv.cc` is the bridge between JavaScript's high-level concepts and the low-level execution capabilities of RISC-V processors. It ensures that JavaScript code can be run efficiently on these architectures by generating optimized machine code.

Prompt: 
```
这是目录为v8/src/compiler/backend/riscv/code-generator-riscv.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
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
  auto trapper = [this, opcode, instr](int offset) {
    RecordTrapInfoIfNeeded(zone(), this, opcode, instr, offset);
  };
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
    case kArchCallWasmFunction: {
      if (instr->InputAt(0)->IsImmediate()) {
        Constant constant = i.ToConstant(instr->InputAt(0));
        Address wasm_code = static_cast<Address>(constant.ToInt64());
        __ Call(wasm_code, constant.rmode());
      } else {
        __ AddWord(t6, i.InputOrZeroRegister(0), 0);
        __ Call(t6);
      }
      RecordCallPosition(instr);
      frame_access_state()->ClearSPDelta();
      break;
    }
    case kArchTailCallCodeObject: {
      if (instr->InputAt(0)->IsImmediate()) {
        __ Jump(i.InputCode(0), RelocInfo::CODE_TARGET);
      } else {
        Register reg = i.InputOrZeroRegister(0);
        CodeEntrypointTag tag =
            i.InputCodeEntrypointTag(instr->CodeEnrypointTagInputIndex());
        DCHECK_IMPLIES(
            instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister),
            reg == kJavaScriptCallCodeStartRegister);
        __ JumpCodeObject(reg, tag);
      }
      frame_access_state()->ClearSPDelta();
      frame_access_state()->SetFrameAccessToDefault();
      break;
    }
    case kArchTailCallWasm: {
      if (instr->InputAt(0)->IsImmediate()) {
        Constant constant = i.ToConstant(instr->InputAt(0));
        Address wasm_code = static_cast<Address>(constant.ToInt64());
        __ Jump(wasm_code, constant.rmode());
      } else {
        __ AddWord(kScratchReg, i.InputOrZeroRegister(0), 0);
        __ Jump(kScratchReg);
      }
      frame_access_state()->ClearSPDelta();
      frame_access_state()->SetFrameAccessToDefault();
      break;
    }
    case kArchTailCallAddress: {
      CHECK(!instr->InputAt(0)->IsImmediate());
      Register reg = i.InputOrZeroRegister(0);
      DCHECK_IMPLIES(
          instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister),
          reg == kJavaScriptCallCodeStartRegister);
      __ Jump(reg);
      frame_access_state()->ClearSPDelta();
      frame_access_state()->SetFrameAccessToDefault();
      break;
    }
    case kArchCallJSFunction: {
      Register func = i.InputOrZeroRegister(0);
      if (v8_flags.debug_code) {
        // Check the function's context matches the context argument.
        __ LoadTaggedField(kScratchReg,
                           FieldMemOperand(func, JSFunction::kContextOffset));
        __ Assert(eq, AbortReason::kWrongFunctionContext, cp,
                  Operand(kScratchReg));
      }
      uint32_t num_arguments =
          i.InputUint32(instr->JSCallArgumentCountInputIndex());
      __ CallJSFunction(func, num_arguments);
      RecordCallPosition(instr);
      frame_access_state()->ClearSPDelta();
      break;
    }
    case kArchPrepareCallCFunction: {
#ifdef V8_TARGET_ARCH_RISCV64
      int const num_gp_parameters = ParamField::decode(instr->opcode());
      int const num_fp_parameters = FPParamField::decode(instr->opcode());
      __ PrepareCallCFunction(num_gp_parameters, num_fp_parameters,
                              kScratchReg);
#else
      int const num_parameters = MiscField::decode(instr->opcode());
      __ PrepareCallCFunction(num_parameters, kScratchReg);
#endif
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
      bool isWasmCapiFunction =
          linkage()->GetIncomingDescriptor()->IsWasmCapiFunction();
      if (isWasmCapiFunction) {
        // Put the return address in a stack slot.
        __ LoadAddress(kScratchReg, &return_location,
                       RelocInfo::EXTERNAL_REFERENCE);
        __ StoreWord(kScratchReg,
                     MemOperand(fp, WasmExitFrameConstants::kCallingPCOffset));
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
    case kArchBinarySearchSwitch:
      AssembleArchBinarySearchSwitch(instr);
      break;
    case kArchTableSwitch:
      AssembleArchTableSwitch(instr);
      break;
    case kArchAbortCSADcheck:
      DCHECK(i.InputRegister(0) == a0);
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
    case kArchComment:
      __ RecordComment(reinterpret_cast<const char*>(i.InputInt64(0)),
                       SourceLocation());
      break;
    case kArchNop:
    case kArchThrowTerminator:
      // don't emit code for nops.
      break;
    case kArchDeoptimize: {
      DeoptimizationExit* exit =
          BuildTranslation(instr, -1, 0, 0, OutputFrameStateCombine::Ignore());
      __ Branch(exit->label());
      break;
    }
    case kArchRet:
      AssembleReturn(instr->InputAt(0));
      break;
#if V8_ENABLE_WEBASSEMBLY
    case kArchStackPointer:
      // The register allocator expects an allocatable register for the output,
      // we cannot use sp directly.
      __ Move(i.OutputRegister(), sp);
      break;
    case kArchSetStackPointer: {
      DCHECK(instr->InputAt(0)->IsRegister());
#ifdef V8_TARGET_ARCH_RISCV64
      if (masm()->options().enable_simulator_code) {
        __ RecordComment("-- Set simulator stack limit --");
        __ LoadStackLimit(kSimulatorBreakArgument,
                          StackLimitKind::kRealStackLimit);
        __ break_(kExceptionIsSwitchStackLimit);
      }
#endif
      __ Move(sp, i.InputRegister(0));
      break;
    }
#endif  // V8_ENABLE_WEBASSEMBLY
    case kArchStackPointerGreaterThan:
      // Pseudo-instruction used for cmp/branch. No opcode emitted here.
      break;
    case kArchStackCheckOffset:
      __ Move(i.OutputRegister(), Smi::FromInt(GetStackCheckOffset()));
      break;
    case kArchFramePointer:
      __ Move(i.OutputRegister(), fp);
      break;
    case kArchParentFramePointer:
      if (frame_access_state()->has_frame()) {
        __ LoadWord(i.OutputRegister(), MemOperand(fp, 0));
      } else {
        __ Move(i.OutputRegister(), fp);
      }
      break;
    case kArchTruncateDoubleToI:
      __ TruncateDoubleToI(isolate(), zone(), i.OutputRegister(),
                           i.InputDoubleRegister(0), DetermineStubCallMode());
      break;
    case kArchStoreWithWriteBarrier: {
      RecordWriteMode mode = RecordWriteModeField::decode(instr->opcode());
      // Indirect pointer writes must use a different opcode.
      DCHECK_NE(mode, RecordWriteMode::kValueIsIndirectPointer);
      Register object = i.InputRegister(0);
      Register offset = i.InputRegister(1);
      Register value = i.InputRegister(2);
      __ AddWord(kScratchReg, object, offset);
      auto ool = zone()->New<OutOfLineRecordWrite>(
          this, object, Operand(offset), value, mode, DetermineStubCallMode());
      __ StoreTaggedField(value, MemOperand(kScratchReg, 0), trapper);
      if (mode > RecordWriteMode::kValueIsIndirectPointer) {
        __ JumpIfSmi(value, ool->exit());
      }
      __ CheckPageFlag(object, MemoryChunk::kPointersFromHereAreInterestingMask,
                       ne, ool->entry());
      __ bind(ool->exit());
      break;
    }
    case kArchAtomicStoreWithWriteBarrier: {
#ifdef V8_TARGET_ARCH_RISCV64
      RecordWriteMode mode = RecordWriteModeField::decode(instr->opcode());
      // Indirect pointer writes must use a different opcode.
      DCHECK_NE(mode, RecordWriteMode::kValueIsIndirectPointer);
      Register object = i.InputRegister(0);
      Register offset = i.InputRegister(1);
      Register value = i.InputRegister(2);

      auto ool = zone()->New<OutOfLineRecordWrite>(
          this, object, Operand(offset), value, mode, DetermineStubCallMode());
      __ AddWord(kScratchReg, object, offset);
      __ AtomicStoreTaggedField(value, MemOperand(kScratchReg, 0));
      // Skip the write barrier if the value is a Smi. However, this is only
      // valid if the value isn't an indirect pointer. Otherwise the value will
      // be a pointer table index, which will always look like a Smi (but
      // actually reference a pointer in the pointer table).
      if (mode > RecordWriteMode::kValueIsIndirectPointer) {
        __ JumpIfSmi(value, ool->exit());
      }
      __ CheckPageFlag(object, MemoryChunk::kPointersFromHereAreInterestingMask,
                       ne, ool->entry());
      __ bind(ool->exit());
      break;
#else
      UNREACHABLE();
#endif
    }
    case kArchStoreIndirectWithWriteBarrier: {
#ifdef V8_TARGET_ARCH_RISCV64
      RecordWriteMode mode = RecordWriteModeField::decode(instr->opcode());
      DCHECK_EQ(mode, RecordWriteMode::kValueIsIndirectPointer);
      IndirectPointerTag tag = static_cast<IndirectPointerTag>(i.InputInt64(3));
      DCHECK(IsValidIndirectPointerTag(tag));
      Register object = i.InputRegister(0);
      Register offset = i.InputRegister(1);
      Register value = i.InputRegister(2);
      __ AddWord(kScratchReg, object, offset);
      auto ool = zone()->New<OutOfLineRecordWrite>(
          this, object, Operand(offset), value, mode, DetermineStubCallMode(),
          tag);
      __ StoreIndirectPointerField(value, MemOperand(kScratchReg, 0), trapper);
      __ CheckPageFlag(object, MemoryChunk::kPointersFromHereAreInterestingMask,
                       ne, ool->entry());
      __ bind(ool->exit());
      break;
#else
      UNREACHABLE();
#endif
    }
    case kArchStackSlot: {
      FrameOffset offset =
          frame_access_state()->GetFrameOffset(i.InputInt32(0));
      Register base_reg = offset.from_stack_pointer() ? sp : fp;
      __ AddWord(i.OutputRegister(), base_reg, Operand(offset.offset()));
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
    case kRiscvAdd32:
      __ Add32(i.OutputRegister(), i.InputOrZeroRegister(0), i.InputOperand(1));
      break;
    case kRiscvSub32:
      __ Sub32(i.OutputRegister(), i.InputOrZeroRegister(0), i.InputOperand(1));
      break;
    case kRiscvMul32:
      __ Mul32(i.OutputRegister(), i.InputOrZeroRegister(0), i.InputOperand(1));
      break;
    case kRiscvMulOvf32:
      __ MulOverflow32(i.OutputRegister(), i.InputOrZeroRegister(0),
                       i.InputOperand(1), kScratchReg);
      break;
#if V8_TARGET_ARCH_RISCV64
    case kRiscvAdd64:
      __ AddWord(i.OutputRegister(), i.InputOrZeroRegister(0),
                 i.InputOperand(1));
      break;
    case kRiscvAddOvf64:
      __ AddOverflow64(i.OutputRegister(), i.InputOrZeroRegister(0),
                       i.InputOperand(1), kScratchReg);
      break;
    case kRiscvSub64:
      __ Sub64(i.OutputRegister(), i.InputOrZeroRegister(0), i.InputOperand(1));
      break;
    case kRiscvSubOvf64:
      __ SubOverflow64(i.OutputRegister(), i.InputOrZeroRegister(0),
                       i.InputOperand(1), kScratchReg);
      break;
    case kRiscvMulHigh32:
      __ Mulh32(i.OutputRegister(), i.InputOrZeroRegister(0),
                i.InputOperand(1));
      break;
    case kRiscvMulHighU32:
      __ Mulhu32(i.OutputRegister(), i.InputOrZeroRegister(0),
                 i.InputOperand(1), kScratchReg, kScratchReg2);
      break;
    case kRiscvMulHigh64:
      __ Mulh64(i.OutputRegister(), i.InputOrZeroRegister(0),
                i.InputOperand(1));
      break;
    case kRiscvMulHighU64:
      __ Mulhu64(i.OutputRegister(), i.InputOrZeroRegister(0),
                 i.InputOperand(1));
      break;
    case kRiscvMulOvf64:
      __ MulOverflow64(i.OutputRegister(), i.InputOrZeroRegister(0),
                       i.InputOperand(1), kScratchReg);
      break;
    case kRiscvDiv32: {
      DCHECK_NE(i.OutputRegister(), i.InputRegister(1));
      __ Div32(i.OutputRegister(), i.InputOrZeroRegister(0), i.InputOperand(1));
      // Set ouput to zero if divisor == 0
      __ LoadZeroIfConditionZero(i.OutputRegister(), i.InputRegister(1));
      break;
    }
    case kRiscvDivU32: {
      DCHECK_NE(i.OutputRegister(), i.InputRegister(1));
      __ Divu32(i.OutputRegister(), i.InputOrZeroRegister(0),
                i.InputOperand(1));
      // Set ouput to zero if divisor == 0
      __ LoadZeroIfConditionZero(i.OutputRegister(), i.InputRegister(1));
      break;
    }
    case kRiscvMod32:
      __ Mod32(i.OutputRegister(), i.InputOrZeroRegister(0), i.InputOperand(1));
      break;
    case kRiscvModU32:
      __ Modu32(i.OutputRegister(), i.InputOrZeroRegister(0),
                i.InputOperand(1));
      break;
    case kRiscvMul64:
      __ Mul64(i.OutputRegister(), i.InputOrZeroRegister(0), i.InputOperand(1));
      break;
    case kRiscvDiv64: {
      DCHECK_NE(i.OutputRegister(), i.InputRegister(1));
      __ Div64(i.OutputRegister(), i.InputOrZeroRegister(0), i.InputOperand(1));
      // Set ouput to zero if divisor == 0
      __ LoadZeroIfConditionZero(i.OutputRegister(), i.InputRegister(1));
      break;
    }
    case kRiscvDivU64: {
      DCHECK_NE(i.OutputRegister(), i.InputRegister(1));
      __ Divu64(i.OutputRegister(), i.InputOrZeroRegister(0),
                i.InputOperand(1));
      // Set ouput to zero if divisor == 0
      __ LoadZeroIfConditionZero(i.OutputRegister(), i.InputRegister(1));
      break;
    }
    case kRiscvMod64:
      __ Mod64(i.OutputRegister(), i.InputOrZeroRegister(0), i.InputOperand(1));
      break;
    case kRiscvModU64:
      __ Modu64(i.OutputRegister(), i.InputOrZeroRegister(0),
                i.InputOperand(1));
      break;
#elif V8_TARGET_ARCH_RISCV32
    case kRiscvAddOvf:
      __ AddOverflow(i.OutputRegister(), i.InputOrZeroRegister(0),
                     i.InputOperand(1), kScratchReg);
      break;
    case kRiscvSubOvf:
      __ SubOverflow(i.OutputRegister(), i.InputOrZeroRegister(0),
                     i.InputOperand(1), kScratchReg);
      break;
    case kRiscvMulHigh32:
      __ Mulh(i.OutputRegister(), i.InputOrZeroRegister(0), i.InputOperand(1));
      break;
    case kRiscvMulHighU32:
      __ Mulhu(i.OutputRegister(), i.InputOrZeroRegister(0), i.InputOperand(1),
               kScratchReg, kScratchReg2);
      break;
    case kRiscvDiv32: {
      __ Div(i.OutputRegister(), i.InputOrZeroRegister(0), i.InputOperand(1));
      // Set ouput to zero if divisor == 0
      __ LoadZeroIfConditionZero(i.OutputRegister(), i.InputRegister(1));
      break;
    }
    case kRiscvDivU32: {
      __ Divu(i.OutputRegister(), i.InputOrZeroRegister(0), i.InputOperand(1));
      // Set ouput to zero if divisor == 0
      __ LoadZeroIfConditionZero(i.OutputRegister(), i.InputRegister(1));
      break;
    }
    case kRiscvMod32:
      __ Mod(i.OutputRegister(), i.InputOrZeroRegister(0), i.InputOperand(1));
      break;
    case kRiscvModU32:
      __ Modu(i.OutputRegister(), i.InputOrZeroRegister(0), i.InputOperand(1));
      break;
#endif
    case kRiscvAnd:
      __ And(i.OutputRegister(), i.InputOrZeroRegister(0), i.InputOperand(1));
      break;
    case kRiscvAnd32:
      __ And(i.OutputRegister(), i.InputOrZeroRegister(0), i.InputOperand(1));
      __ Sll32(i.OutputRegister(), i.OutputRegister(), 0x0);
      break;
    case kRiscvOr:
      __ Or(i.OutputRegister(), i.InputOrZeroRegister(0), i.InputOperand(1));
      break;
    case kRiscvOr32:
      __ Or(i.OutputRegister(), i.InputOrZeroRegister(0), i.InputOperand(1));
      __ Sll32(i.OutputRegister(), i.OutputRegister(), 0x0);
      break;
    case kRiscvXor:
      __ Xor(i.OutputRegister(), i.InputOrZeroRegister(0), i.InputOperand(1));
      break;
    case kRiscvXor32:
      __ Xor(i.OutputRegister(), i.InputOrZeroRegister(0), i.InputOperand(1));
      __ Sll32(i.OutputRegister(), i.OutputRegister(), 0x0);
      break;
    case kRiscvClz32:
      __ Clz32(i.OutputRegister(), i.InputOrZeroRegister(0));
      break;
#if V8_TARGET_ARCH_RISCV64
    case kRiscvClz64:
      __ Clz64(i.OutputRegister(), i.InputOrZeroRegister(0));
      break;
    case kRiscvCtz64: {
      Register src = i.InputRegister(0);
      Register dst = i.OutputRegister();
      __ Ctz64(dst, src);
    } break;
    case kRiscvPopcnt64: {
      Register src = i.InputRegister(0);
      Register dst = i.OutputRegister();
      __ Popcnt64(dst, src, kScratchReg);
    } break;
#endif
    case kRiscvCtz32: {
      Register src = i.InputRegister(0);
      Register dst = i.OutputRegister();
      __ Ctz32(dst, src);
    } break;
    case kRiscvPopcnt32: {
      Register src = i.InputRegister(0);
      Register dst = i.OutputRegister();
      __ Popcnt32(dst, src, kScratchReg);
    } break;
    case kRiscvShl32:
      if (instr->InputAt(1)->IsRegister()) {
        __ Sll32(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        int64_t imm = i.InputOperand(1).immediate();
        __ Sll32(i.OutputRegister(), i.InputRegister(0),
                 static_cast<uint16_t>(imm));
      }
      break;
    case kRiscvShr32:
      if (instr->InputAt(1)->IsRegister()) {
        __ Srl32(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        int64_t imm = i.InputOperand(1).immediate();
        __ Srl32(i.OutputRegister(), i.InputRegister(0),
                 static_cast<uint16_t>(imm));
      }
      break;
    case kRiscvSar32:
      if (instr->InputAt(1)->IsRegister()) {
        __ Sra32(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        int64_t imm = i.InputOperand(1).immediate();
        __ Sra32(i.OutputRegister(), i.InputRegister(0),
                 static_cast<uint16_t>(imm));
      }
      break;
#if V8_TARGET_ARCH_RISCV64
    case kRiscvZeroExtendWord: {
      __ ZeroExtendWord(i.OutputRegister(), i.InputRegister(0));
      break;
    }
    case kRiscvSignExtendWord: {
      __ SignExtendWord(i.OutputRegister(), i.InputRegister(0));
      break;
    }
    case kRiscvShl64:
      __ Sll64(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kRiscvShr64:
      __ Srl64(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kRiscvSar64:
      __ Sra64(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kRiscvRor64:
      __ Dror(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kRiscvTst64:
      __ And(kScratchReg, i.InputRegister(0), i.InputOperand(1));
      // Pseudo-instruction used for cmp/branch. No opcode emitted here.
      break;
#endif
    case kRiscvRev8:
      __ rev8(i.OutputRegister(), i.InputRegister(0));
      break;
    case kRiscvAndn:
      __ andn(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      break;
    case kRiscvOrn:
      __ orn(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      break;
    case kRiscvXnor:
      __ xnor(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      break;
    case kRiscvClz:
      __ clz(i.OutputRegister(), i.InputRegister(0));
      break;
    case kRiscvCtz:
      __ ctz(i.OutputRegister(), i.InputRegister(0));
      break;
    case kRiscvCpop:
      __ cpop(i.OutputRegister(), i.InputRegister(0));
      break;
#if V8_TARGET_ARCH_RISCV64
    case kRiscvClzw:
      __ clzw(i.OutputRegister(), i.InputRegister(0));
      break;
    case kRiscvCtzw:
      __ ctzw(i.OutputRegister(), i.InputRegister(0));
      break;
    case kRiscvCpopw:
      __ cpopw(i.OutputRegister(), i.InputRegister(0));
      break;
#endif
    case kRiscvMax:
      __ max(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      break;
    case kRiscvMaxu:
      __ maxu(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      break;
    case kRiscvMin:
      __ min(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      break;
    case kRiscvMinu:
      __ minu(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      break;
    case kRiscvSextb:
      __ sextb(i.OutputRegister(), i.InputRegister(0));
      break;
    case kRiscvSexth:
      __ sexth(i.OutputRegister(), i.InputRegister(0));
      break;
    case kRiscvZexth:
      __ zexth(i.OutputRegister(), i.InputRegister(0));
      break;
    case kRiscvTst32:
      __ And(kScratchReg, i.InputRegister(0), i.InputOperand(1));
      __ Sll32(kScratchReg, kScratchReg, 0x0);
      // Pseudo-instruction used for cmp/branch. No opcode emitted here.
      break;
    case kRiscvRor32:
      __ Ror(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kRiscvCmp:
#ifdef V8_TARGET_ARCH_RISCV64
    case kRiscvCmp32:
    case kRiscvCmpZero32:
#endif
      // Pseudo-instruction used for cmp/branch. No opcode emitted here.
      break;
    case kRiscvCmpZero:
      // Pseudo-instruction used for cmpzero/branch. No opcode emitted here.
      break;
    case kRiscvMov:
      // TODO(plind): Should we combine mov/li like this, or use separate instr?
      //    - Also see x64 ASSEMBLE_BINOP & RegisterOrOperandType
      if (HasRegisterInput(instr, 0)) {
        __ Move(i.OutputRegister(), i.InputRegister(0));
      } else {
        __ li(i.OutputRegister(), i.InputOperand(0));
      }
      break;

    case kRiscvCmpS: {
      FPURegister left = i.InputOrZeroSingleRegister(0);
      FPURegister right = i.InputOrZeroSingleRegister(1);
      bool predicate;
      FPUCondition cc =
          FlagsConditionToConditionCmpFPU(&predicate, instr->flags_condition());

      if ((left == kSingleRegZero || right == kSingleRegZero) &&
          !__ IsSingleZeroRegSet()) {
        __ LoadFPRImmediate(kSingleRegZero, 0.0f);
      }
      // compare result set to kScratchReg
      __ CompareF32(kScratchReg, cc, left, right);
    } break;
    case kRiscvAddS:
      // TODO(plind): add special case: combine mult & add.
      __ fadd_s(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1));
      break;
    case kRiscvSubS:
      __ fsub_s(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1));
      break;
    case kRiscvMulS:
      // TODO(plind): add special case: right op is -1.0, see arm port.
      __ fmul_s(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1));
      break;
    case kRiscvDivS:
      __ fdiv_s(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1));
      break;
    case kRiscvModS: {
      // TODO(bmeurer): We should really get rid of this special instruction,
      // and generate a CallAddress instruction instead.
      FrameScope scope(masm(), StackFrame::MANUAL);
      __ PrepareCallCFunction(0, 2, kScratchReg);
      __ MovToFloatParameters(i.InputDoubleRegister(0),
                              i.InputDoubleRegister(1));
      // TODO(balazs.kilvady): implement mod_two_floats_operation(isolate())
      __ CallCFunction(ExternalReference::mod_two_doubles_operation(), 0, 2);
      // Move the result in the double result register.
      __ MovFromFloatResult(i.OutputSingleRegister());
      break;
    }
    case kRiscvAbsS:
      __ fabs_s(i.OutputSingleRegister(), i.InputSingleRegister(0));
      break;
    case kRiscvNegS:
      __ Neg_s(i.OutputSingleRegister(), i.InputSingleRegister(0));
      break;
    case kRiscvSqrtS: {
      __ fsqrt_s(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kRiscvMaxS:
      __ fmax_s(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1));
      break;
    case kRiscvMinS:
      __ fmin_s(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1));
      break;
    case kRiscvCmpD: {
      FPURegister left = i.InputOrZeroDoubleRegister(0);
      FPURegister right = i.InputOrZeroDoubleRegister(1);
      bool predicate;
      FPUCondition cc =
          FlagsConditionToConditionCmpFPU(&predicate, instr->flags_condition());
      if ((left == kDoubleRegZero || right == kDoubleRegZero) &&
          !__ IsDoubleZeroRegSet()) {
        __ LoadFPRImmediate(kDoubleRegZero, 0.0);
      }
      // compare result set to kScratchReg
      __ CompareF64(kScratchReg, cc, left, right);
    } break;
#if V8_TARGET_ARCH_RISCV32
    case kRiscvAddPair:
      __ AddPair(i.OutputRegister(0), i.OutputRegister(1), i.InputRegister(0),
                 i.InputRegister(1), i.InputRegister(2), i.InputRegister(3),
                 kScratchReg, kScratchReg2);
      break;
    case kRiscvSubPair:
      __ SubPair(i.OutputRegister(0), i.OutputRegister(1), i.InputRegister(0),
                 i.InputRegister(1), i.InputRegister(2), i.InputRegister(3),
                 kScratchReg, kScratchReg2);
      break;
    case kRiscvAndPair:
      __ AndPair(i.OutputRegister(0), i.OutputRegister(1), i.InputRegister(0),
                 i.InputRegister(1), i.InputRegister(2), i.InputRegister(3));
      break;
    case kRiscvOrPair:
      __ OrPair(i.OutputRegister(0), i.OutputRegister(1), i.InputRegister(0),
                i.InputRegister(1), i.InputRegister(2), i.InputRegister(3));
      break;
    case kRiscvXorPair:
      __ XorPair(i.OutputRegister(0), i.OutputRegister(1), i.InputRegister(0),
                 i.InputRegister(1), i.InputRegister(2), i.InputRegister(3));
      break;
    case kRiscvMulPair:
      __ MulPair(i.OutputRegister(0), i.OutputRegister(1), i.InputRegister(0),
                 i.InputRegister(1), i.InputRegister(2), i.InputRegister(3),
                 kScratchReg, kScratchReg2);
      break;
    case kRiscvShlPair: {
      Register second_output =
          instr->OutputCount() >= 2 ? i.OutputRegister(1) : i.TempRegister(0);
      if (instr->InputAt(2)->IsRegister()) {
        __ ShlPair(i.OutputRegister(0), second_output, i.InputRegister(0),
                   i.InputRegister(1), i.InputRegister(2), kScratchReg,
                   kScratchReg2);
      } else {
        uint32_t imm = i.InputOperand(2).immediate();
        __ ShlPair(i.OutputRegister(0), second_output, i.InputRegister(0),
                   i.InputRegister(1), imm, kScratchReg, kScratchReg2);
      }
    } break;
    case kRiscvShrPair: {
      Register second_output =
          instr->OutputCount() >= 2 ? i.OutputRegister(1) : i.TempRegister(0);
      if (instr->InputAt(2)->IsRegister()) {
        __ ShrPair(i.OutputRegister(0), second_output, i.InputRegister(0),
                   i.InputRegister(1), i.InputRegister(2), kScratchReg,
                   kScratchReg2);
      } else {
        uint32_t imm = i.InputOperand(2).immediate();
        __ ShrPair(i.OutputRegister(0), second_output, i.InputRegister(0),
                   i.InputRegister(1), 
"""


```