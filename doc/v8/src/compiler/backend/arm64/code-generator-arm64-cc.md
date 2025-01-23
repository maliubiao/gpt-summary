Response:
My thinking process to arrive at the summary of `code-generator-arm64.cc` goes like this:

1. **Understand the File Path:** The path `v8/src/compiler/backend/arm64/code-generator-arm64.cc` immediately tells me several key things:
    * `v8`: This is part of the V8 JavaScript engine.
    * `compiler`: This code is involved in the compilation process, not runtime execution.
    * `backend`:  This is a backend component, meaning it's responsible for generating machine code for a specific architecture.
    * `arm64`: The target architecture is ARM64.
    * `code-generator`: The primary function of this file is to generate machine code instructions.
    * `.cc`: This is a C++ source file.

2. **Scan the Includes:** The `#include` directives reveal important dependencies and give clues about the file's responsibilities:
    * ARM64-specific headers (`assembler-arm64-inl.h`, `constants-arm64.h`, `macro-assembler-arm64-inl.h`): Confirms this is architecture-specific code generation.
    * General V8 compilation headers (`interface-descriptors-inl.h`, `machine-type.h`, `optimized-compilation-info.h`, `code-generator-impl.h`, `code-generator.h`, `gap-resolver.h`, `instruction-codes.h`, `node-matchers.h`, `osr.h`): Indicates it integrates with the broader V8 compilation pipeline.
    * Execution and heap headers (`frame-constants.h`, `heap/mutable-page-metadata.h`): Suggests interaction with runtime aspects like stack frames and garbage collection.
    * WebAssembly header (`wasm/wasm-linkage.h`, `wasm/wasm-objects.h`): Implies support for WebAssembly compilation on ARM64.

3. **Analyze the Namespaces:** The `namespace v8 { namespace internal { namespace compiler {` nesting is standard V8 practice for organizing compiler-related code.

4. **Examine Key Classes and Structures:**
    * `Arm64OperandConverter`:  This class clearly focuses on translating intermediate representation (IR) operands into ARM64-specific operands (registers, immediates, memory locations). It handles different data types (integers, floats, SIMD) and addressing modes.
    * `OutOfLineRecordWrite`: This suggests handling write barriers for garbage collection. The "out-of-line" part indicates this is code that's executed less frequently.
    * `WasmOutOfLineTrap` (conditional on `V8_ENABLE_WEBASSEMBLY`): This points to handling WebAssembly traps (runtime errors).
    * Helper functions like `FlagsConditionToCondition` and template functions like `EmitFpOrNeonUnop`: These provide utility for common code generation tasks.

5. **Look for Key Macros and Definitions:**
    * Macros like `ASSEMBLE_SHIFT`, `ASSEMBLE_ATOMIC_LOAD_INTEGER`, etc.: These are code generation patterns for specific ARM64 instructions. They simplify the process of emitting these instructions. The "ATOMIC" macros suggest support for concurrent operations.
    * Definitions for `AssembleDeconstructFrame`, `AssemblePrepareTailCall`, `AssembleTailCallBeforeGap`, `AssembleTailCallAfterGap`: These methods handle function call conventions and optimizations like tail calls.

6. **Identify Conditional Compilation:** The `#if V8_ENABLE_WEBASSEMBLY` blocks highlight support for WebAssembly, indicating that the code generator needs to handle both JavaScript and WebAssembly compilation.

7. **Infer Functionality Based on the Above:**  Combining the information gathered, I can deduce the main functions:
    * **ARM64 Specific Code Generation:** The core purpose is generating ARM64 assembly instructions.
    * **Instruction Translation:**  Converting a higher-level representation of instructions (likely from the V8 compiler's IR) into concrete ARM64 instructions.
    * **Operand Conversion:** Handling the specifics of how data is represented in instructions (registers, immediates, memory access).
    * **Support for Different Data Types:** Working with integers, floating-point numbers, and SIMD vectors.
    * **Memory Management (Write Barriers):** Implementing the necessary logic to ensure garbage collection correctness when writing to memory.
    * **Function Call Handling:** Generating code for function calls, including setting up and tearing down stack frames, and handling tail calls.
    * **WebAssembly Support:**  Generating code for WebAssembly constructs and handling WebAssembly-specific runtime errors (traps).
    * **Atomic Operations:**  Supporting atomic operations for concurrent programming.

8. **Structure the Summary:**  Organize the findings into logical categories like core functionality, key components, and conditional features. Use clear and concise language.

By following this systematic approach, I can effectively analyze the provided code snippet and generate a comprehensive summary of its functionality. The process involves understanding the context (file path), examining the building blocks (includes, classes, macros), and then inferring the overall purpose and capabilities of the code.
This is the first part of the `v8/src/compiler/backend/arm64/code-generator-arm64.cc` file. Based on the included headers and the code within this snippet, here's a summary of its functionality:

**Core Functionality:**

This C++ file implements the ARM64-specific code generator for the V8 JavaScript engine's optimizing compiler (TurboFan). Its primary role is to translate platform-independent intermediate representation (IR) instructions into concrete ARM64 machine code instructions.

**Key Components and Features highlighted in this part:**

* **`Arm64OperandConverter`:** A helper class that facilitates the conversion of generic instruction operands from the IR into ARM64-specific operands (registers, immediates, memory addresses). It handles different data types (32-bit and 64-bit integers, single and double-precision floats, and SIMD vectors). It also manages addressing modes and special cases like zero registers.
* **`OutOfLineRecordWrite`:**  A class for generating out-of-line code for record write barriers. These barriers are essential for the garbage collector to track object references and maintain memory safety when objects are modified. It handles different write modes, including ephemeron keys and indirect pointers, and also deals with saving and restoring the link register (`lr`) when a frame is not present.
* **Helper Functions for Conditions:** The `FlagsConditionToCondition` function converts high-level condition codes (like `kEqual`, `kSignedLessThan`) into the corresponding ARM64 conditional branch mnemonics (like `eq`, `lt`).
* **WebAssembly Support (Conditional):**  The code includes sections and classes (`WasmOutOfLineTrap`) specifically for handling WebAssembly compilation when `V8_ENABLE_WEBASSEMBLY` is defined. This suggests the code generator is responsible for generating ARM64 code for WebAssembly modules as well.
* **Macros for Instruction Generation:** A significant portion of the code uses macros (e.g., `ASSEMBLE_SHIFT`, `ASSEMBLE_ATOMIC_LOAD_INTEGER`, `ASSEMBLE_SIMD_SHIFT_LEFT`) to simplify the generation of common ARM64 instruction patterns. These macros abstract away some of the details of instruction encoding.
* **Handling Function Calls and Tail Calls:**  The functions `AssembleDeconstructFrame`, `AssemblePrepareTailCall`, `AssembleTailCallBeforeGap`, and `AssembleTailCallAfterGap` deal with the specifics of setting up and tearing down stack frames during function calls, including optimizations like tail call elimination.
* **Code Start Register Check:** `AssembleCodeStartRegisterCheck` performs a sanity check to ensure the `kJavaScriptCallCodeStartRegister` holds the expected value.
* **Dispatch Handle Register Check (Conditional):**  The presence of `AssembleDispatchHandleRegisterCheck` (though incomplete in this snippet) suggests there are mechanisms to verify the correctness of registers related to function dispatch, potentially in the context of optimized or tiered compilation.

**Is it a Torque file?**

No, `v8/src/compiler/backend/arm64/code-generator-arm64.cc` ends with `.cc`, which indicates it's a **C++ source file**. Torque source files typically have the `.tq` extension.

**Relationship to JavaScript Functionality:**

This file is **directly and fundamentally related to JavaScript functionality**. The code generator is the part of the compiler that transforms the optimized representation of JavaScript code into the actual machine instructions that the ARM64 processor will execute. Without the code generator, JavaScript code could not be run on ARM64 architectures.

**JavaScript Example:**

Consider a simple JavaScript function:

```javascript
function add(a, b) {
  return a + b;
}
```

The `code-generator-arm64.cc` file would be responsible for generating the ARM64 instructions to perform the following actions when this function is called:

1. **Load the values of `a` and `b` from their locations (registers or stack).**
2. **Perform the addition operation using an ARM64 addition instruction.**
3. **Store the result in a register designated for the return value.**
4. **Return from the function.**

More complex JavaScript operations, like object property access, function calls, and control flow, would also be translated into corresponding sequences of ARM64 instructions by this code generator.

**Code Logic Inference (Hypothetical):**

Let's consider a hypothetical instruction to add two 32-bit integer registers:

**Hypothetical Input Instruction:** `kArm64Add32`, output register `R1`, input registers `R2`, `R3`.

**Processing in `Arm64OperandConverter`:**

* `InputRegister32(0)` would return the ARM64 register corresponding to the IR operand `R2` (e.g., `w2`).
* `InputRegister32(1)` would return the ARM64 register corresponding to the IR operand `R3` (e.g., `w3`).
* `OutputRegister32()` would return the ARM64 register corresponding to the IR operand `R1` (e.g., `w1`).

**Generated ARM64 Assembly (within the `AssembleInstruction` method, which isn't shown here but would use the `Arm64OperandConverter`):**

```assembly
add w1, w2, w3  // Add the contents of w2 and w3, store the result in w1
```

**User Programming Errors (Illustrative):**

While this C++ code doesn't directly expose user-programmable interfaces, understanding its role can highlight potential consequences of user errors:

* **Incorrect Data Types:** If a JavaScript program attempts to perform an operation on incompatible data types (e.g., adding a number to an object without proper conversion), the generated ARM64 code might lead to unexpected behavior or runtime errors. The compiler tries to handle these situations, but dynamic typing can sometimes lead to surprises.
* **Memory Access Errors:**  If a JavaScript program tries to access memory outside of allocated bounds (e.g., accessing an array element with an out-of-range index), the generated code might result in a segmentation fault or other memory corruption issues. The code generator itself incorporates mechanisms (like the record write barrier) to help prevent such issues within the V8 engine's managed heap.
* **Infinite Loops or Excessive Recursion:** While the code generator doesn't directly *cause* these, the efficiency of the generated code can impact how quickly such errors manifest. A poorly optimized code generator might make these problems more noticeable due to slower execution.

**Summary of Part 1:**

This first part of `v8/src/compiler/backend/arm64/code-generator-arm64.cc` lays the groundwork for generating ARM64 machine code from the V8 compiler's intermediate representation. It defines key helper classes for operand conversion and managing write barriers, along with macros that streamline the process of emitting ARM64 instructions. It also includes conditional support for WebAssembly and handles aspects of function call setup and optimization. This code is crucial for enabling the execution of JavaScript (and WebAssembly) on ARM64-based systems.

### 提示词
```
这是目录为v8/src/compiler/backend/arm64/code-generator-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/arm64/code-generator-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
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
  DCHECK(linkage()->GetIncomingDescriptor()->IsJSFu
```