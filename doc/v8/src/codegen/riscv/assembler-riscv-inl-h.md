Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Initial Scan and Purpose Identification:**

   - The file name `assembler-riscv-inl.h` strongly suggests this is an inline header file for the RISC-V assembler within the V8 JavaScript engine. The `.inl` suffix is a convention for inline implementations.
   - The copyright notice confirms it's part of the V8 project and originally had Sun Microsystems involvement.
   - The `#ifndef` and `#define` guards (`V8_CODEGEN_RISCV_ASSEMBLER_RISCV_INL_H_`) are standard C++ header file protection against multiple inclusions.
   - The `#include` directives point to other V8 internal headers related to code generation (`assembler-arch.h`, `assembler.h`), debugging (`debug.h`), and object representation (`heap-layout-inl.h`, `heap-layout.h`, `objects-inl.h`). This reinforces the file's role in low-level code manipulation.
   - The `namespace v8 { namespace internal { ... }}` indicates this is within the internal implementation details of V8, not part of the public API.

2. **Core Functionality Deduction:**

   - The presence of `Assembler` class methods like `CheckBuffer()`, `GrowBuffer()`, `RelocateInternalReference()`, and `RelocateRelativeReference()` strongly indicates this file deals with managing a buffer of instructions during code generation.
   - The `RelocInfo` class and its associated methods (e.g., `target_address()`, `target_address_address()`, `apply()`, `set_target_object()`) are central to the process of relocation. Relocation is the process of adjusting addresses in generated code when it's loaded into memory, so this is a crucial part of dynamic code generation. The different `rmode_` (relocation mode) values suggest different types of targets (code, data, external references, etc.).
   - The handling of compressed pointers (`target_compressed_address_at`, `set_target_compressed_address_at`) is a performance optimization technique used in V8 to reduce memory usage.
   - The interaction with `ICacheFlushMode` suggests that the assembler is responsible for ensuring that changes to the generated code are reflected in the instruction cache of the processor.
   - Methods like `code_target_object_handle_at`, `compressed_embedded_object_handle_at`, and `relative_code_target_object_handle_at` indicate the assembler's ability to work with V8's internal representation of code and objects.
   - The handling of "special targets" and internal references further points towards the low-level nature of the code generation process.
   - The functions related to `constant32` (`target_constant32_at`, `set_target_constant32_at`) show how the assembler deals with embedding 32-bit constants into the generated code, likely using instruction sequences like `lui` and `addi`.

3. **Torque Check:**

   - The prompt specifically asks about `.tq` files. A quick scan reveals no mention of `.tq` or Torque. The filename ends in `.h`. Therefore, this is not a Torque file.

4. **JavaScript Relationship and Examples:**

   - The connection to JavaScript is through V8's role as the JavaScript engine. This code is part of the engine's internal machinery to convert JavaScript code into executable machine code for the RISC-V architecture.
   - The examples focus on high-level JavaScript constructs (function calls, object creation, accessing properties) and then explain *how* the assembler (this header file's code) is involved in generating the low-level RISC-V instructions to implement those constructs. This bridges the gap between the high-level language and the low-level implementation.

5. **Code Logic and Assumptions:**

   - The focus here is on the `target_constant32_at` and `set_target_constant32_at` functions.
   - **Assumption:** The code assumes the compiler will use a specific instruction sequence (`lui` followed by `addi`) to load a 32-bit constant.
   - **Input:**  An address `pc` pointing to the start of this instruction sequence.
   - **Output:** The 32-bit constant value embedded within those instructions.
   - The reverse logic is shown for setting the constant, demonstrating how the 32-bit value is split and inserted into the `lui` and `addi` instructions.

6. **Common Programming Errors:**

   - The errors identified relate to the complexities of low-level programming:
     - **Incorrect Relocation Modes:**  Setting the wrong relocation mode can lead to incorrect address calculations.
     - **Cache Incoherence:** Failing to flush the instruction cache after modifying code can result in the processor executing outdated instructions.
     - **Misunderstanding Instruction Encoding:** Incorrectly manipulating instruction bits can lead to crashes or unexpected behavior.

7. **Structure and Refinement:**

   - The thought process involves iteratively building an understanding of the file's purpose and functionality. Starting with the file name and includes, then diving into the key classes and methods, and finally connecting it back to JavaScript.
   - The examples are chosen to illustrate the connection between JavaScript and assembler functionality.
   - The assumptions and logic are made explicit to demonstrate how the code works at a lower level.
   - The common errors are highlighted to provide practical context.

Essentially, the process is a combination of:

- **Code Reading and Interpretation:** Understanding the C++ syntax and V8's conventions.
- **Domain Knowledge:** Knowing about assemblers, code generation, relocation, and instruction caches.
- **Contextual Awareness:** Understanding how this file fits within the larger V8 project.
- **Deductive Reasoning:**  Inferring functionality from the names and signatures of methods and classes.
- **Explanatory Communication:**  Presenting the information in a clear and organized way, suitable for someone trying to understand the code.
This header file, `v8/src/codegen/riscv/assembler-riscv-inl.h`, is a crucial part of the V8 JavaScript engine's code generation process for the RISC-V architecture. It defines **inline implementations** for the `Assembler` class, providing low-level primitives for emitting RISC-V machine code.

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Machine Code Emission:**  The primary function is to provide methods for generating RISC-V instructions. While the base `Assembler` class likely defines the interface, this `.inl.h` file provides the concrete implementations for many of those methods, often as inline functions for performance.

2. **Relocation Information Management:** It deals with `RelocInfo`, which stores information about locations in the generated code that need to be patched up later. This is essential for things like:
   - **Calling functions:**  The exact address of a function might not be known until link time or runtime. `RelocInfo` helps mark where the call instruction is and what the target is.
   - **Accessing data:**  Similar to function calls, the addresses of data objects might need to be resolved later.
   - **Embedding objects:**  V8 often embeds references to JavaScript objects directly in the generated code.

3. **Constant Pool Handling:**  It interacts with the constant pool, a section of memory where frequently used constants (like object addresses or function entry points) are stored. This allows the generated code to refer to these constants efficiently.

4. **CPU Feature Detection:**  The `CpuFeatures::SupportsOptimizer()` function checks if the necessary CPU features (like the FPU - Floating Point Unit) are present to enable certain optimizations.

5. **Buffer Management:** The `Assembler::CheckBuffer()` and potentially `GrowBuffer()` methods handle the allocation and resizing of the buffer used to store the generated machine code.

6. **Target Address Manipulation:**  Several functions (`target_address_at`, `set_target_address_at`, etc.) are responsible for reading and writing target addresses within the generated code, taking into account different relocation modes.

7. **Compressed Pointer Handling:**  V8 uses compressed pointers to save memory. This file includes functions to handle reading and writing compressed object pointers (`target_compressed_address_at`, `set_target_compressed_address_at`).

8. **Special Target Handling:**  It deals with "special targets," which might require custom handling during relocation or deserialization.

9. **Internal Reference Management:**  Functions like `set_target_internal_reference_encoded_at` manage references within the generated code itself.

**Is it a Torque file?**

No, `v8/src/codegen/riscv/assembler-riscv-inl.h` ends with `.h`, not `.tq`. Therefore, it is a **C++ header file**, not a V8 Torque source file. Torque files are typically named with a `.tq` extension.

**Relationship with JavaScript and Examples:**

This file is fundamental to V8's ability to execute JavaScript code. When V8 compiles JavaScript code, it uses the `Assembler` (and the inline implementations here) to generate the actual RISC-V machine instructions that the processor will execute.

Here are some examples of how the functionalities in this file relate to JavaScript:

**Example 1: Function Calls**

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

When V8 compiles the call to `add(5, 10)`, the `Assembler` (using methods defined in this header) will generate RISC-V instructions to:

- Push arguments (5 and 10) onto the stack or place them in registers.
- Generate a call instruction to the memory location where the compiled code for the `add` function resides.
- The `RelocInfo` mechanism would be used to record that this call instruction needs to be patched with the actual address of the `add` function.

**Example 2: Object Property Access**

```javascript
const obj = { x: 10 };
console.log(obj.x);
```

When accessing `obj.x`, the `Assembler` will generate instructions to:

- Load the address of the `obj` object.
- Calculate the offset of the `x` property within the object's structure.
- Load the value at that calculated memory address.
- If `obj` is newly created, the address of the `obj` object might not be known at compile time, and `RelocInfo` would be involved in resolving it.

**Example 3: Creating Objects**

```javascript
const newObj = {};
```

Creating a new object involves:

- Allocating memory for the object on the heap.
- Initializing the object's properties.
- The `Assembler` will generate instructions to perform this allocation and initialization, potentially using the constant pool to store references to the object's prototype or other metadata.

**Code Logic and Assumptions (Example: `target_constant32_at`)**

Let's look at the `target_constant32_at` function:

```c++
int32_t Assembler::target_constant32_at(Address pc) {
  Instruction* instr0 = Instruction::At((unsigned char*)pc);
  Instruction* instr1 = Instruction::At((unsigned char*)(pc + 1 * kInstrSize));

  // Interpret instructions for address generated by li: See listing in
  // Assembler::set_target_address_at() just below.
  if (IsLui(*reinterpret_cast<Instr*>(instr0)) &&
      IsAddi(*reinterpret_cast<Instr*>(instr1))) {
    // Assemble the 32bit value.
    int32_t constant32 = (int32_t)(instr0->Imm20UValue() << kImm20Shift) +
                         (int32_t)instr1->Imm12Value();
    return constant32;
  }
  // We should never get here, force a bad address if we do.
  UNREACHABLE();
}
```

**Assumption:** This code assumes that a 32-bit constant was loaded into memory using a specific sequence of two RISC-V instructions: `lui` (Load Upper Immediate) followed by `addi` (Add Immediate). This is a common way to load arbitrary 32-bit values because immediate fields in single RISC-V instructions are often limited.

**Input:** `pc` - an `Address` (memory location) pointing to the beginning of this two-instruction sequence.

**Output:** The 32-bit constant value that was loaded by those two instructions.

**Logic:**

1. It reads the two instructions at the given memory address `pc`.
2. It checks if the first instruction is a `lui` and the second is an `addi`.
3. If the instructions match the expected pattern:
   - It extracts the upper 20 bits of the constant from the `lui` instruction.
   - It extracts the lower 12 bits of the constant from the `addi` instruction.
   - It combines these parts to reconstruct the full 32-bit constant.
4. If the instructions don't match, it indicates an unexpected code sequence and calls `UNREACHABLE()`, which will likely trigger an assertion failure or crash in a debug build.

**User-Visible Programming Errors (Indirectly Related):**

While developers don't directly interact with this header file, errors in their JavaScript code can lead to situations where the assembler might encounter unexpected states or try to generate invalid code. Here are a few examples:

1. **Stack Overflow:**  Excessive recursion or deeply nested function calls can lead to a stack overflow. While this isn't directly an assembler error, the assembler is responsible for generating the code that manages the stack. A stack overflow will eventually crash the program.

2. **Type Errors:** Performing operations on values of incompatible types (e.g., adding a number and a string without explicit conversion) might lead to runtime errors. The assembler generates code to perform these operations, and type errors manifest during execution.

3. **Accessing Non-Existent Properties:** Trying to access a property that doesn't exist on an object will usually return `undefined`. The assembler generates the code to look up properties, and in cases where the property is missing, it handles returning `undefined`.

4. **Memory Leaks (Less Direct):**  While the assembler doesn't directly cause memory leaks, incorrect memory management in the V8 runtime (which relies on the generated code) can lead to leaks. For example, failing to properly release references to objects can prevent garbage collection.

**In summary, `v8/src/codegen/riscv/assembler-riscv-inl.h` is a low-level but essential component of the V8 engine. It provides the building blocks for converting JavaScript code into executable RISC-V machine code, handling relocation, constants, and other architecture-specific details.**

Prompt: 
```
这是目录为v8/src/codegen/riscv/assembler-riscv-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/riscv/assembler-riscv-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright (c) 1994-2006 Sun Microsystems Inc.
// All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// - Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// - Redistribution in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// - Neither the name of Sun Microsystems or the names of contributors may
// be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// The original source code covered by the above license above has been
// modified significantly by Google Inc.
// Copyright 2021 the V8 project authors. All rights reserved.

#ifndef V8_CODEGEN_RISCV_ASSEMBLER_RISCV_INL_H_
#define V8_CODEGEN_RISCV_ASSEMBLER_RISCV_INL_H_

#include "src/codegen/assembler-arch.h"
#include "src/codegen/assembler.h"
#include "src/debug/debug.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/heap-layout.h"
#include "src/objects/objects-inl.h"

namespace v8 {
namespace internal {

bool CpuFeatures::SupportsOptimizer() { return IsSupported(FPU); }

void Assembler::CheckBuffer() {
  if (buffer_space() <= kGap) {
    GrowBuffer();
  }
}

// -----------------------------------------------------------------------------
// WritableRelocInfo.

void WritableRelocInfo::apply(intptr_t delta) {
  if (IsInternalReference(rmode_) || IsInternalReferenceEncoded(rmode_)) {
    // Absolute code pointer inside code object moves with the code object.
    Assembler::RelocateInternalReference(rmode_, pc_, delta);
  } else {
    DCHECK(IsRelativeCodeTarget(rmode_) || IsNearBuiltinEntry(rmode_));
    Assembler::RelocateRelativeReference(rmode_, pc_, delta);
  }
}

Address RelocInfo::target_address() {
  DCHECK(IsCodeTargetMode(rmode_) || IsWasmCall(rmode_) ||
         IsNearBuiltinEntry(rmode_) || IsWasmStubCall(rmode_) ||
         IsExternalReference(rmode_));
  return Assembler::target_address_at(pc_, constant_pool_);
}

Address RelocInfo::target_address_address() {
  DCHECK(HasTargetAddressAddress());
  // Read the address of the word containing the target_address in an
  // instruction stream.
  // The only architecture-independent user of this function is the serializer.
  // The serializer uses it to find out how many raw bytes of instruction to
  // output before the next target.
  // For an instruction like LUI/ORI where the target bits are mixed into the
  // instruction bits, the size of the target will be zero, indicating that the
  // serializer should not step forward in memory after a target is resolved
  // and written. In this case the target_address_address function should
  // return the end of the instructions to be patched, allowing the
  // deserializer to deserialize the instructions as raw bytes and put them in
  // place, ready to be patched with the target. After jump optimization,
  // that is the address of the instruction that follows J/JAL/JR/JALR
  // instruction.
#ifdef V8_TARGET_ARCH_RISCV64
  return pc_ + Assembler::kInstructionsFor64BitConstant * kInstrSize;
#elif defined(V8_TARGET_ARCH_RISCV32)
  return pc_ + Assembler::kInstructionsFor32BitConstant * kInstrSize;
#endif
}

Address RelocInfo::constant_pool_entry_address() { UNREACHABLE(); }

int RelocInfo::target_address_size() {
  if (IsCodedSpecially()) {
    return Assembler::kSpecialTargetSize;
  } else {
    return kSystemPointerSize;
  }
}

void Assembler::set_target_compressed_address_at(
    Address pc, Address constant_pool, Tagged_t target,
    WritableJitAllocation* jit_allocation, ICacheFlushMode icache_flush_mode) {
  Assembler::set_target_address_at(pc, constant_pool,
                                   static_cast<Address>(target), jit_allocation,
                                   icache_flush_mode);
}

Tagged_t Assembler::target_compressed_address_at(Address pc,
                                                 Address constant_pool) {
  return static_cast<Tagged_t>(target_address_at(pc, constant_pool));
}

Address RelocInfo::wasm_indirect_call_target() const {
  DCHECK(rmode_ == WASM_INDIRECT_CALL_TARGET);
  return Assembler::target_address_at(pc_, constant_pool_);
}
void WritableRelocInfo::set_wasm_indirect_call_target(
    Address target, ICacheFlushMode icache_flush_mode) {
  DCHECK(rmode_ == RelocInfo::WASM_INDIRECT_CALL_TARGET);
  Assembler::set_target_address_at(pc_, constant_pool_, target,
                                   &jit_allocation_, icache_flush_mode);
}

Handle<Object> Assembler::code_target_object_handle_at(Address pc,
                                                       Address constant_pool) {
  int index =
      static_cast<int>(target_address_at(pc, constant_pool)) & 0xFFFFFFFF;
  return GetCodeTarget(index);
}

Handle<HeapObject> Assembler::compressed_embedded_object_handle_at(
    Address pc, Address const_pool) {
  return GetEmbeddedObject(target_compressed_address_at(pc, const_pool));
}

void Assembler::deserialization_set_special_target_at(
    Address instruction_payload, Tagged<Code> code, Address target) {
  set_target_address_at(instruction_payload,
                        !code.is_null() ? code->constant_pool() : kNullAddress,
                        target);
}

int Assembler::deserialization_special_target_size(
    Address instruction_payload) {
  return kSpecialTargetSize;
}

void Assembler::set_target_internal_reference_encoded_at(Address pc,
                                                         Address target) {
#ifdef V8_TARGET_ARCH_RISCV64
  set_target_value_at(pc, static_cast<uint64_t>(target));
#elif defined(V8_TARGET_ARCH_RISCV32)
  set_target_value_at(pc, static_cast<uint32_t>(target));
#endif
}

void Assembler::deserialization_set_target_internal_reference_at(
    Address pc, Address target, RelocInfo::Mode mode) {
  if (RelocInfo::IsInternalReferenceEncoded(mode)) {
    DCHECK(IsLui(instr_at(pc)));
    set_target_internal_reference_encoded_at(pc, target);
  } else {
    DCHECK(RelocInfo::IsInternalReference(mode));
    Memory<Address>(pc) = target;
  }
}

Tagged<HeapObject> RelocInfo::target_object(PtrComprCageBase cage_base) {
  DCHECK(IsCodeTarget(rmode_) || IsEmbeddedObjectMode(rmode_));
  if (IsCompressedEmbeddedObject(rmode_)) {
    return Cast<HeapObject>(
        Tagged<Object>(V8HeapCompressionScheme::DecompressTagged(
            cage_base,
            Assembler::target_compressed_address_at(pc_, constant_pool_))));
  } else {
    return Cast<HeapObject>(
        Tagged<Object>(Assembler::target_address_at(pc_, constant_pool_)));
  }
}

Handle<HeapObject> RelocInfo::target_object_handle(Assembler* origin) {
  if (IsCodeTarget(rmode_)) {
    return Cast<HeapObject>(
        origin->code_target_object_handle_at(pc_, constant_pool_));
  } else if (IsCompressedEmbeddedObject(rmode_)) {
    return origin->compressed_embedded_object_handle_at(pc_, constant_pool_);
  } else if (IsFullEmbeddedObject(rmode_)) {
    return Handle<HeapObject>(reinterpret_cast<Address*>(
        Assembler::target_address_at(pc_, constant_pool_)));
  } else {
    DCHECK(IsRelativeCodeTarget(rmode_));
    return origin->relative_code_target_object_handle_at(pc_);
  }
}

void WritableRelocInfo::set_target_object(Tagged<HeapObject> target,
                                          ICacheFlushMode icache_flush_mode) {
  DCHECK(IsCodeTarget(rmode_) || IsEmbeddedObjectMode(rmode_));
  if (IsCompressedEmbeddedObject(rmode_)) {
    DCHECK(COMPRESS_POINTERS_BOOL);
    // We must not compress pointers to objects outside of the main pointer
    // compression cage as we wouldn't be able to decompress them with the
    // correct cage base.
    DCHECK_IMPLIES(V8_ENABLE_SANDBOX_BOOL, !HeapLayout::InTrustedSpace(target));
    DCHECK_IMPLIES(V8_EXTERNAL_CODE_SPACE_BOOL,
                   !HeapLayout::InCodeSpace(target));
    Assembler::set_target_compressed_address_at(
        pc_, constant_pool_,
        V8HeapCompressionScheme::CompressObject(target.ptr()), &jit_allocation_,
        icache_flush_mode);
  } else {
    DCHECK(IsFullEmbeddedObject(rmode_));
    Assembler::set_target_address_at(pc_, constant_pool_, target.ptr(),
                                     &jit_allocation_, icache_flush_mode);
  }
}

Address RelocInfo::target_external_reference() {
  DCHECK(rmode_ == EXTERNAL_REFERENCE);
  return Assembler::target_address_at(pc_, constant_pool_);
}

void WritableRelocInfo::set_target_external_reference(
    Address target, ICacheFlushMode icache_flush_mode) {
  DCHECK(rmode_ == RelocInfo::EXTERNAL_REFERENCE);
  Assembler::set_target_address_at(pc_, constant_pool_, target,
                                   &jit_allocation_, icache_flush_mode);
}

Address RelocInfo::target_internal_reference() {
  if (IsInternalReference(rmode_)) {
    return Memory<Address>(pc_);
  } else {
    // Encoded internal references are j/jal instructions.
    DCHECK(IsInternalReferenceEncoded(rmode_));
    DCHECK(Assembler::IsLui(Assembler::instr_at(pc_ + 0 * kInstrSize)));
    Address address = Assembler::target_address_at(pc_);
    return address;
  }
}

Address RelocInfo::target_internal_reference_address() {
  DCHECK(IsInternalReference(rmode_) || IsInternalReferenceEncoded(rmode_));
  return pc_;
}

Handle<Code> Assembler::relative_code_target_object_handle_at(
    Address pc) const {
  Instr instr1 = Assembler::instr_at(pc);
  Instr instr2 = Assembler::instr_at(pc + kInstrSize);
  DCHECK(IsAuipc(instr1));
  DCHECK(IsJalr(instr2));
  int32_t code_target_index = BrachlongOffset(instr1, instr2);
  return Cast<Code>(GetEmbeddedObject(code_target_index));
}

Builtin Assembler::target_builtin_at(Address pc) {
  Instr instr1 = Assembler::instr_at(pc);
  Instr instr2 = Assembler::instr_at(pc + kInstrSize);
  DCHECK(IsAuipc(instr1));
  DCHECK(IsJalr(instr2));
  int32_t builtin_id = BrachlongOffset(instr1, instr2);
  DCHECK(Builtins::IsBuiltinId(builtin_id));
  return static_cast<Builtin>(builtin_id);
}

Builtin RelocInfo::target_builtin_at(Assembler* origin) {
  DCHECK(IsNearBuiltinEntry(rmode_));
  return Assembler::target_builtin_at(pc_);
}

Address RelocInfo::target_off_heap_target() {
  DCHECK(IsOffHeapTarget(rmode_));
  return Assembler::target_address_at(pc_, constant_pool_);
}

EnsureSpace::EnsureSpace(Assembler* assembler) { assembler->CheckBuffer(); }

int32_t Assembler::target_constant32_at(Address pc) {
  Instruction* instr0 = Instruction::At((unsigned char*)pc);
  Instruction* instr1 = Instruction::At((unsigned char*)(pc + 1 * kInstrSize));

  // Interpret instructions for address generated by li: See listing in
  // Assembler::set_target_address_at() just below.
  if (IsLui(*reinterpret_cast<Instr*>(instr0)) &&
      IsAddi(*reinterpret_cast<Instr*>(instr1))) {
    // Assemble the 32bit value.
    int32_t constant32 = (int32_t)(instr0->Imm20UValue() << kImm20Shift) +
                         (int32_t)instr1->Imm12Value();
    return constant32;
  }
  // We should never get here, force a bad address if we do.
  UNREACHABLE();
}

void Assembler::set_target_constant32_at(Address pc, uint32_t target,
                                         WritableJitAllocation* jit_allocation,
                                         ICacheFlushMode icache_flush_mode) {
  uint32_t* p = reinterpret_cast<uint32_t*>(pc);
#ifdef DEBUG
  // Check we have the result from a li macro-instruction.
  Instruction* instr0 = Instruction::At((unsigned char*)pc);
  Instruction* instr1 = Instruction::At((unsigned char*)(pc + 1 * kInstrSize));
  DCHECK(IsLui(*reinterpret_cast<Instr*>(instr0)) &&
         IsAddi(*reinterpret_cast<Instr*>(instr1)));
#endif
  int32_t high_20 = ((target + 0x800) >> 12);  // 20 bits
  int32_t low_12 = target & 0xfff;             // 12 bits
  *p = *p & 0xfff;
  *p = *p | ((int32_t)high_20 << 12);
  *(p + 1) = *(p + 1) & 0xfffff;
  *(p + 1) = *(p + 1) | ((int32_t)low_12 << 20);
  if (icache_flush_mode != SKIP_ICACHE_FLUSH) {
    FlushInstructionCache(pc, 2 * kInstrSize);
  }
  DCHECK_EQ(static_cast<uint32_t>(target_constant32_at(pc)), target);
}

uint32_t Assembler::uint32_constant_at(Address pc, Address constant_pool) {
  Instruction* instr0 = reinterpret_cast<Instruction*>(pc);
  Instruction* instr1 = reinterpret_cast<Instruction*>(pc + 1 * kInstrSize);
  CHECK(IsLui(*reinterpret_cast<Instr*>(instr0)));
  CHECK(IsAddi(*reinterpret_cast<Instr*>(instr1)));
  return target_constant32_at(pc);
}
void Assembler::set_uint32_constant_at(Address pc, Address constant_pool,
                                       uint32_t new_constant,
                                       WritableJitAllocation* jit_allocation,
                                       ICacheFlushMode icache_flush_mode) {
  Instruction* instr1 = reinterpret_cast<Instruction*>(pc);
  Instruction* instr2 = reinterpret_cast<Instruction*>(pc + 1 * kInstrSize);
  CHECK(IsLui(*reinterpret_cast<Instr*>(instr1)));
  CHECK(IsAddi(*reinterpret_cast<Instr*>(instr2)));
  set_target_constant32_at(pc, new_constant, jit_allocation, icache_flush_mode);
}

}  // namespace internal
}  // namespace v8

#endif  // V8_CODEGEN_RISCV_ASSEMBLER_RISCV_INL_H_

"""

```