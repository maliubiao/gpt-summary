Response:
Let's break down the thought process for analyzing this V8 header file.

1. **Initial Understanding of the File Path and Name:**

   - `v8/src/codegen/s390/assembler-s390-inl.h`: This immediately tells us several things:
     - It's part of the V8 JavaScript engine.
     - It's related to code generation (`codegen`).
     - It's specific to the s390 architecture (IBM mainframe).
     - The `.inl.h` suffix strongly suggests it's an inline header file, containing inline function definitions to be included in other compilation units.
     - `assembler-s390`: This likely deals with assembling machine code instructions for the s390.

2. **Copyright and License:**

   - The initial copyright block is from Sun Microsystems, indicating some origin or influence from older Java-related code. The subsequent Google Inc. copyright confirms its integration into V8. The BSD-style license allows for redistribution and modification under certain conditions. This is standard boilerplate and doesn't directly inform the file's *functionality* within V8, but it's important context.

3. **Header Guards:**

   - `#ifndef V8_CODEGEN_S390_ASSEMBLER_S390_INL_H_`, `#define V8_CODEGEN_S390_ASSEMBLER_S390_INL_H_`, and `#endif` are standard header guards to prevent multiple inclusions of the header file, which can cause compilation errors.

4. **Includes:**

   - `#include "src/codegen/assembler.h"`: This is a key inclusion. It signifies that this file extends or specializes the more general `assembler` functionality for the s390 architecture. The base `assembler` likely provides common assembly operations.
   - `#include "src/codegen/flush-instruction-cache.h"`:  Indicates that this code deals with ensuring that changes made to generated code are visible to the processor by flushing the instruction cache.
   - `#include "src/codegen/s390/assembler-s390.h"`:  Suggests a base assembler class specific to s390 that this inline header extends. This likely contains the class declarations.
   - `#include "src/debug/debug.h"`:  Implies the presence of debugging-related functionality or assertions.
   - `#include "src/objects/objects-inl.h"`:  This indicates interaction with V8's object model, particularly how objects are represented in memory.

5. **Namespace:**

   - `namespace v8 { namespace internal { ... } }`: This is V8's standard namespace organization. The `internal` namespace usually contains implementation details not meant for external consumption.

6. **`CpuFeatures::SupportsOptimizer()`:**

   - This simple function indicates whether the s390 architecture supports the V8 optimizer. Returning `true` suggests it does. This is a high-level feature check.

7. **`WritableRelocInfo::apply(intptr_t delta)`:**

   - This is where the core functionality starts to become apparent. `RelocInfo` likely holds information about *relocation entries* in generated code. Relocation is the process of adjusting addresses in machine code when it's loaded at a different location in memory.
   - `delta`: This parameter likely represents the offset by which the code segment has moved.
   - The logic within the `if/else if/else` block handles different types of relocations based on `rmode_` (relocation mode):
     - `IsInternalReference`:  Looks like adjusting addresses within a jump table.
     - `IsCodeTarget`:  Adjusting the target of a code branch instruction. The code manipulates instruction bits directly. The multiplication by 2 and division by 2 suggest dealing with halfwords (2-byte units) as the unit of displacement.
     - `IsInternalReferenceEncoded`: Dealing with a "mov sequence" where an address is loaded into a register. It uses helper functions like `Assembler::target_address_at` and `Assembler::set_target_address_at`.
   - **Key Insight:** This function is crucial for making generated code position-independent or for fixing up addresses after code movement.

8. **`RelocInfo::target_internal_reference()`, `target_internal_reference_address()`, `target_address()`, `target_address_address()`, `constant_pool_entry_address()`:**

   - These functions provide ways to access information related to the relocation entry, such as the target address, the address of the target address, and (though `UNREACHABLE()`) potential constant pool entries. The `DCHECK` statements are important for internal consistency checks during development.

9. **`Assembler::set_target_compressed_address_at()`, `RelocInfo::target_address_size()`, `Assembler::target_compressed_address_at()`:**

   - These functions suggest that V8 uses *compressed pointers* in some cases to save memory. The "compressed address" likely refers to a smaller representation of an address that needs to be decompressed before use.

10. **`Assembler::code_target_object_handle_at()`, `RelocInfo::target_object()`, `Assembler::compressed_embedded_object_handle_at()`, `RelocInfo::target_object_handle()`, `WritableRelocInfo::set_target_object()`:**

   - These functions deal with relocating references to V8 *objects* (specifically `HeapObject`s) within the generated code. This is fundamental to how V8 manages memory and object references. The distinction between compressed and full embedded objects is again visible here.

11. **`RelocInfo::target_external_reference()`, `WritableRelocInfo::set_target_external_reference()`:**

   - These handle relocations to *external* references, which are addresses outside the generated code, such as to system libraries or other parts of the V8 runtime.

12. **`RelocInfo::wasm_indirect_call_target()`, `WritableRelocInfo::set_wasm_indirect_call_target()`:**

   - These functions are specific to WebAssembly (Wasm) and how indirect calls are handled. The `#ifdef V8_ENABLE_WASM_CODE_POINTER_TABLE` suggests a conditional feature related to how Wasm code pointers are stored.

13. **`RelocInfo::target_builtin_at()`:**

   - `UNREACHABLE()` indicates this functionality isn't used for the s390 port in this particular context. Builtins are pre-compiled JavaScript functions or runtime routines.

14. **`RelocInfo::target_off_heap_target()`:**

   - This deals with targets located in memory outside the main V8 heap.

15. **`Operand::Operand(Register rm)`:**

   - This is a constructor for an `Operand` class, which likely represents operands to machine instructions (registers, immediate values, memory locations).

16. **`Assembler::target_address_at(Address pc, Address constant_pool)`:**

   - This is a crucial function for retrieving the target address from the generated code at a specific program counter (`pc`). It analyzes the instruction at `pc` to determine how the address is encoded. It handles cases like branch instructions (`BRASL`, `BRCL`) and the `IIHF`/`IILF` instruction sequence (used for loading 64-bit immediate values).

17. **`Assembler::deserialization_special_target_size()`, `deserialization_set_target_internal_reference_at()`:**

   - These functions are related to *deserialization*, the process of loading saved code or data back into memory.

18. **`Assembler::set_target_address_at(Address pc, Address constant_pool, Address target, ...)`:**

   - This is the counterpart to the retrieval function. It *sets* the target address at a given `pc` by modifying the instruction bits. It needs to handle different instruction formats and ensure that the instruction cache is flushed if necessary.

19. **`Assembler::uint32_constant_at()`, `set_uint32_constant_at()`:**

   - These functions are for reading and writing 32-bit constant values embedded within instructions, specifically looking for the `LGFI` instruction.

20. **Putting it all together and answering the prompt's questions:**

   - **Functionality:**  The file provides inline implementations for the `Assembler` class specific to the s390 architecture. This includes functions for:
     - Applying relocations to generated code.
     - Accessing and modifying target addresses and object references within instructions.
     - Handling different types of relocation (internal, code targets, external, Wasm).
     - Dealing with compressed pointers.
     - Reading and writing embedded constants.
     - Supporting code deserialization.
   - **`.tq` extension:** The file ends in `.h`, *not* `.tq`. So, it's not a Torque source file.
   - **Relationship to JavaScript:**  This code is fundamental to V8's ability to execute JavaScript. When V8 compiles JavaScript code, it generates machine code for the target architecture (in this case, s390). This file provides the low-level mechanisms for manipulating that generated code, especially for linking different parts of the code and referencing objects in memory.
   - **JavaScript Example:**  Consider a simple function call in JavaScript: `function foo() { return 1; } foo();`. When compiled, the call to `foo()` will result in a branch instruction in the generated s390 code. The `RelocInfo` and `Assembler` classes are involved in setting up the target address of that branch instruction. Similarly, accessing a variable will involve loading its value from memory, and the address of that memory location might be subject to relocation.
   - **Code Logic Reasoning:** The `WritableRelocInfo::apply()` and `Assembler::set_target_address_at()` functions contain the most interesting code logic. The conditional handling of different `rmode_` values and the bitwise manipulation of instructions to update addresses are key aspects.
   - **Common Programming Errors:**  A common error when working with assembly and relocation is calculating incorrect offsets or target addresses. For instance, forgetting to account for instruction lengths or using the wrong units (bytes vs. halfwords). Incorrectly setting instruction bits can lead to invalid opcodes and program crashes. Another error could be failing to flush the instruction cache after modifying code, leading to the processor executing stale instructions.

This detailed breakdown reflects a layered approach: understanding the file's context, examining its components piece by piece, and then synthesizing that information to answer the specific questions in the prompt.
The provided code snippet is a header file (`assembler-s390-inl.h`) in the V8 JavaScript engine, specifically for the s390 architecture. The `.inl.h` suffix indicates that it contains inline function definitions that are meant to be included in other compilation units.

Here's a breakdown of its functionality:

**Core Functionality: Low-Level Code Generation and Relocation for s390**

This file provides inline implementations for methods of the `Assembler` class, which is responsible for generating machine code instructions for the s390 architecture. It deals with:

* **Instruction Encoding:**  It contains logic for encoding specific s390 instructions, particularly those related to loading addresses and branching. You can see this in functions like `Assembler::target_address_at` and `Assembler::set_target_address_at`.
* **Relocation Information:**  It defines how to handle relocation information (`RelocInfo`). Relocation is the process of adjusting addresses in generated code when it's loaded at a different location in memory. This is crucial for code that needs to be position-independent or for patching code at runtime.
* **Target Address Management:** Functions like `RelocInfo::target_address()`, `RelocInfo::target_internal_reference()`, and their corresponding `set_` counterparts are used to get and set the target addresses of jumps, calls, and data references within the generated code.
* **Object References:** It handles how to embed references to V8 objects (like strings, functions, etc.) within the generated machine code. This includes support for compressed object pointers for memory efficiency.
* **External References:**  It manages references to external code or data outside the generated code, such as calls to system libraries.
* **WebAssembly Support:** It includes specific handling for WebAssembly (Wasm) related calls and code pointers.
* **Constant Pool Management:** It interacts with the constant pool, a section of memory used to store constant values referenced by the code.
* **Instruction Cache Flushing:** It utilizes `FlushInstructionCache` to ensure that modifications to the generated code are visible to the processor.

**Specific Features and Functions:**

* **`CpuFeatures::SupportsOptimizer()`:**  Indicates whether the s390 architecture supports the V8 optimizer. In this case, it returns `true`.
* **`WritableRelocInfo::apply(intptr_t delta)`:**  This is a crucial function for applying a delta (offset) to a relocation entry. It handles different types of relocations, such as internal references (jump table entries) and code targets (branch instructions).
* **`RelocInfo::target_internal_reference()` and `target_internal_reference_address()`:**  Retrieve the target address and the address of the target address for internal references.
* **`RelocInfo::target_address()` and `target_address_address()`:** Retrieve the target address and the address of the target address for code targets and other types of references.
* **`Assembler::set_target_compressed_address_at()` and `Assembler::target_compressed_address_at()`:**  Handle setting and getting compressed addresses, which are used to save memory.
* **`Assembler::code_target_object_handle_at()` and `RelocInfo::target_object()`:**  Deal with retrieving the V8 object referenced by a code target.
* **`RelocInfo::target_external_reference()` and `WritableRelocInfo::set_target_external_reference()`:** Manage external references.
* **`RelocInfo::wasm_indirect_call_target()` and `WritableRelocInfo::set_wasm_indirect_call_target()`:**  Handle WebAssembly indirect call targets.
* **`Assembler::target_address_at(Address pc, Address constant_pool)`:**  A key function that decodes the target address from the instruction at the given program counter (`pc`). It handles different s390 instruction formats for loading addresses (like the `IIHF`/`IILF` sequence).
* **`Assembler::set_target_address_at(Address pc, Address constant_pool, Address target, ...)`:**  Sets the target address in the instruction at the given program counter (`pc`). This involves modifying the instruction bits.
* **`Assembler::uint32_constant_at()` and `Assembler::set_uint32_constant_at()`:** Read and write 32-bit constant values embedded within instructions (specifically for the `LGFI` instruction).

**Is it a Torque source file?**

No, the file `v8/src/codegen/s390/assembler-s390-inl.h` ends with `.h`, not `.tq`. Therefore, it is a standard C++ header file containing inline function definitions, not a V8 Torque source file. Torque files are used for generating boilerplate code and type definitions within V8.

**Relationship to JavaScript and JavaScript Examples:**

This file is directly related to how V8 executes JavaScript code. When V8 compiles JavaScript code, it translates it into machine code specific to the target architecture (in this case, s390). This header file provides the tools and functions to build and manipulate that machine code.

Here's a conceptual JavaScript example to illustrate the connection (though you won't directly interact with this C++ code in your JavaScript):

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
console.log(result); // Output: 15
```

When V8 compiles this JavaScript code for s390:

1. **The `Assembler` class (with inline methods defined in this header) is used to generate the machine code instructions for the `add` function.** This includes instructions to:
   - Load the arguments `a` and `b` into registers.
   - Perform the addition operation.
   - Store the result.
   - Return from the function.
2. **When the `add(5, 10)` call is made, the generated machine code for `add` is executed.**
3. **The `RelocInfo` mechanism comes into play when dealing with function calls and data access.** For example, the address of the `console.log` function needs to be resolved and potentially relocated. Similarly, if the `add` function were to access global variables, their addresses would also need to be handled.

**Code Logic Reasoning (Example with `WritableRelocInfo::apply`)**

Let's consider the `WritableRelocInfo::apply(intptr_t delta)` function with a hypothetical scenario:

**Assumptions:**

* We have generated s390 machine code that includes a branch instruction (e.g., a jump to another part of the code).
* The initial target address of the branch instruction was `0x1000`.
* Due to code movement in memory, the entire code segment has been shifted by `delta = 0x200`.
* The `RelocInfo` object associated with this branch instruction has `rmode_` set to `IsCodeTarget(rmode_)`.

**Input:**

* `delta = 0x200`
* `pc_`: The address of the branch instruction in memory.
* The branch instruction at `pc_` initially encodes a jump to `0x1000`.

**Logic:**

The `apply` function, when `IsCodeTarget(rmode_)` is true, does the following:

1. **Reads the existing instruction bits:** It fetches the 6-byte instruction at `pc_`. Let's assume the relevant part of the instruction encoding the target address is initially `0x00001000`.
2. **Calculates the new displacement:**
   - It extracts the current displacement from the instruction (`0x00001000`).
   - It converts this to a signed 32-bit integer and multiplies it by 2 (because s390 branch displacements are in halfwords).
   - It subtracts the `delta` (`0x200`) from this displacement.
   - This calculation effectively adjusts the relative offset of the jump.
3. **Updates the instruction bits:**
   - It clears the original displacement part of the instruction.
   - It calculates the new displacement in halfwords by dividing the adjusted displacement by 2.
   - It writes the new displacement back into the instruction bits.
4. **Flushes the instruction cache:**  Ensures the processor fetches the updated instruction.

**Output:**

* The branch instruction at `pc_` will now encode a jump to `0x1000 + 0x200 = 0x1200`. The instruction bits at `pc_` will be modified to reflect this new target address.

**Common Programming Errors:**

This type of low-level code is prone to various errors that are often difficult to debug:

1. **Incorrect Offset Calculations:**  Forgetting to account for instruction lengths, alignment requirements, or the units of displacement (bytes vs. halfwords in the s390 case). For example, in the `apply` function, if the multiplication by 2 or division by 2 were missed, the jump target would be incorrect.
2. **Endianness Issues:**  While not explicitly shown in this snippet, when dealing with multi-byte instruction encodings, ensuring correct byte order (endianness) is crucial. Incorrect handling can lead to the processor interpreting instructions incorrectly.
3. **Instruction Format Errors:**  Mistakes in manipulating the bitfields of instructions can lead to invalid opcodes or incorrect operand values. For instance, writing to the wrong bits when setting the target address.
4. **Cache Coherency Problems:**  Forgetting to flush the instruction cache after modifying code can lead to the processor executing the old, incorrect instructions. This can cause unpredictable behavior and crashes.
5. **Register Allocation Errors:** (While not directly in this `.inl.h` file, it's related to the `Assembler` class) Incorrectly managing register usage can lead to data corruption or unexpected results.
6. **Off-by-One Errors:**  Common in loop conditions or when calculating memory addresses.
7. **Type Mismatches:**  Incorrectly casting between different integer types (e.g., signed vs. unsigned) can lead to unexpected behavior when performing arithmetic or bitwise operations.

**Example of a Common Error (Conceptual):**

Imagine in the `Assembler::set_target_address_at` function, a developer forgets to shift the new target address correctly when writing it into the instruction bits. This could result in the branch instruction jumping to a completely wrong memory location, leading to a crash or unpredictable behavior.

In summary, `v8/src/codegen/s390/assembler-s390-inl.h` is a vital piece of V8's code generation infrastructure for the s390 architecture. It provides the low-level building blocks for translating JavaScript into executable machine code and managing the complexities of code relocation and object references.

### 提示词
```
这是目录为v8/src/codegen/s390/assembler-s390-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/s390/assembler-s390-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright (c) 1994-2006 Sun Microsystems Inc.
// All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// - Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// - Redistribution in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the
// distribution.
//
// - Neither the name of Sun Microsystems or the names of contributors may
// be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
// OF THE POSSIBILITY OF SUCH DAMAGE.

// The original source code covered by the above license above has been modified
// significantly by Google Inc.
// Copyright 2014 the V8 project authors. All rights reserved.

#ifndef V8_CODEGEN_S390_ASSEMBLER_S390_INL_H_
#define V8_CODEGEN_S390_ASSEMBLER_S390_INL_H_

#include "src/codegen/assembler.h"
#include "src/codegen/flush-instruction-cache.h"
#include "src/codegen/s390/assembler-s390.h"
#include "src/debug/debug.h"
#include "src/objects/objects-inl.h"

namespace v8 {
namespace internal {

bool CpuFeatures::SupportsOptimizer() { return true; }

void WritableRelocInfo::apply(intptr_t delta) {
  // Absolute code pointer inside code object moves with the code object.
  if (IsInternalReference(rmode_)) {
    // Jump table entry
    Address target = Memory<Address>(pc_);
    jit_allocation_.WriteValue(pc_, target + delta);
  } else if (IsCodeTarget(rmode_)) {
    SixByteInstr instr =
        Instruction::InstructionBits(reinterpret_cast<const uint8_t*>(pc_));
    int32_t dis = static_cast<int32_t>(instr & 0xFFFFFFFF) * 2  // halfwords
                  - static_cast<int32_t>(delta);
    instr >>= 32;  // Clear the 4-byte displacement field.
    instr <<= 32;
    instr |= static_cast<uint32_t>(dis / 2);
    Instruction::SetInstructionBits<SixByteInstr>(
        reinterpret_cast<uint8_t*>(pc_), instr, &jit_allocation_);
  } else {
    // mov sequence
    DCHECK(IsInternalReferenceEncoded(rmode_));
    Address target = Assembler::target_address_at(pc_, constant_pool_);
    Assembler::set_target_address_at(pc_, constant_pool_, target + delta,
                                     &jit_allocation_, SKIP_ICACHE_FLUSH);
  }
}

Address RelocInfo::target_internal_reference() {
  if (IsInternalReference(rmode_)) {
    // Jump table entry
    return Memory<Address>(pc_);
  } else {
    // mov sequence
    DCHECK(IsInternalReferenceEncoded(rmode_));
    return Assembler::target_address_at(pc_, constant_pool_);
  }
}

Address RelocInfo::target_internal_reference_address() {
  DCHECK(IsInternalReference(rmode_) || IsInternalReferenceEncoded(rmode_));
  return pc_;
}

Address RelocInfo::target_address() {
  DCHECK(IsRelativeCodeTarget(rmode_) || IsCodeTarget(rmode_) ||
         IsWasmCall(rmode_) || IsWasmStubCall(rmode_));
  return Assembler::target_address_at(pc_, constant_pool_);
}

Address RelocInfo::target_address_address() {
  DCHECK(HasTargetAddressAddress());

  // Read the address of the word containing the target_address in an
  // instruction stream.
  // The only architecture-independent user of this function is the serializer.
  // The serializer uses it to find out how many raw bytes of instruction to
  // output before the next target.
  // For an instruction like LIS/ORI where the target bits are mixed into the
  // instruction bits, the size of the target will be zero, indicating that the
  // serializer should not step forward in memory after a target is resolved
  // and written.
  return pc_;
}

Address RelocInfo::constant_pool_entry_address() { UNREACHABLE(); }

void Assembler::set_target_compressed_address_at(
    Address pc, Address constant_pool, Tagged_t target,
    WritableJitAllocation* jit_allocation, ICacheFlushMode icache_flush_mode) {
  Assembler::set_target_address_at(pc, constant_pool,
                                   static_cast<Address>(target), jit_allocation,
                                   icache_flush_mode);
}

int RelocInfo::target_address_size() {
  if (IsCodedSpecially()) {
    return Assembler::kSpecialTargetSize;
  } else {
    return kSystemPointerSize;
  }
}

Tagged_t Assembler::target_compressed_address_at(Address pc,
                                                 Address constant_pool) {
  return static_cast<Tagged_t>(target_address_at(pc, constant_pool));
}

Handle<Object> Assembler::code_target_object_handle_at(Address pc) {
  SixByteInstr instr =
      Instruction::InstructionBits(reinterpret_cast<const uint8_t*>(pc));
  int index = instr & 0xFFFFFFFF;
  return GetCodeTarget(index);
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

Handle<HeapObject> Assembler::compressed_embedded_object_handle_at(
    Address pc, Address const_pool) {
  return GetEmbeddedObject(target_compressed_address_at(pc, const_pool));
}

Handle<HeapObject> RelocInfo::target_object_handle(Assembler* origin) {
  DCHECK(IsRelativeCodeTarget(rmode_) || IsCodeTarget(rmode_) ||
         IsEmbeddedObjectMode(rmode_));
  if (IsCodeTarget(rmode_) || IsRelativeCodeTarget(rmode_)) {
    return Cast<HeapObject>(origin->code_target_object_handle_at(pc_));
  } else {
    if (IsCompressedEmbeddedObject(rmode_)) {
      return origin->compressed_embedded_object_handle_at(pc_, constant_pool_);
    }
    return Handle<HeapObject>(reinterpret_cast<Address*>(
        Assembler::target_address_at(pc_, constant_pool_)));
  }
}

void WritableRelocInfo::set_target_object(Tagged<HeapObject> target,
                                          ICacheFlushMode icache_flush_mode) {
  DCHECK(IsCodeTarget(rmode_) || IsEmbeddedObjectMode(rmode_));
  if (IsCompressedEmbeddedObject(rmode_)) {
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

WasmCodePointer RelocInfo::wasm_indirect_call_target() const {
  DCHECK(rmode_ == WASM_INDIRECT_CALL_TARGET);
#ifdef V8_ENABLE_WASM_CODE_POINTER_TABLE
  return Assembler::uint32_constant_at(pc_, constant_pool_);
#else
  return Assembler::target_address_at(pc_, constant_pool_);
#endif
}

void WritableRelocInfo::set_wasm_indirect_call_target(
    WasmCodePointer target, ICacheFlushMode icache_flush_mode) {
  DCHECK(rmode_ == RelocInfo::WASM_INDIRECT_CALL_TARGET);
#ifdef V8_ENABLE_WASM_CODE_POINTER_TABLE
  Assembler::set_uint32_constant_at(pc_, constant_pool_, target,
                                    &jit_allocation_, icache_flush_mode);
#else
  Assembler::set_target_address_at(pc_, constant_pool_, target,
                                   &jit_allocation_, icache_flush_mode);
#endif
}

Builtin RelocInfo::target_builtin_at(Assembler* origin) { UNREACHABLE(); }

Address RelocInfo::target_off_heap_target() {
  DCHECK(IsOffHeapTarget(rmode_));
  return Assembler::target_address_at(pc_, constant_pool_);
}

// Operand constructors
Operand::Operand(Register rm) : rm_(rm), rmode_(RelocInfo::NO_INFO) {}

// Fetch the 32bit value from the FIXED_SEQUENCE IIHF / IILF
Address Assembler::target_address_at(Address pc, Address constant_pool) {
  // S390 Instruction!
  // We want to check for instructions generated by Asm::mov()
  Opcode op1 =
      Instruction::S390OpcodeValue(reinterpret_cast<const uint8_t*>(pc));
  SixByteInstr instr_1 =
      Instruction::InstructionBits(reinterpret_cast<const uint8_t*>(pc));

  if (BRASL == op1 || BRCL == op1) {
    int32_t dis = static_cast<int32_t>(instr_1 & 0xFFFFFFFF) * 2;
    return pc + dis;
  }

  int instr1_length =
      Instruction::InstructionLength(reinterpret_cast<const uint8_t*>(pc));
  Opcode op2 = Instruction::S390OpcodeValue(
      reinterpret_cast<const uint8_t*>(pc + instr1_length));
  SixByteInstr instr_2 = Instruction::InstructionBits(
      reinterpret_cast<const uint8_t*>(pc + instr1_length));
  // IIHF for hi_32, IILF for lo_32
  if (IIHF == op1 && IILF == op2) {
    return static_cast<Address>(((instr_1 & 0xFFFFFFFF) << 32) |
                                ((instr_2 & 0xFFFFFFFF)));
  }

  UNIMPLEMENTED();
  return 0;
}

int Assembler::deserialization_special_target_size(
    Address instruction_payload) {
  return kSpecialTargetSize;
}

void Assembler::deserialization_set_target_internal_reference_at(
    Address pc, Address target, RelocInfo::Mode mode) {
  if (RelocInfo::IsInternalReferenceEncoded(mode)) {
    set_target_address_at(pc, kNullAddress, target, nullptr, SKIP_ICACHE_FLUSH);
  } else {
    Memory<Address>(pc) = target;
  }
}

// This code assumes the FIXED_SEQUENCE of IIHF/IILF
void Assembler::set_target_address_at(Address pc, Address constant_pool,
                                      Address target,
                                      WritableJitAllocation* jit_allocation,
                                      ICacheFlushMode icache_flush_mode) {
  // Check for instructions generated by Asm::mov()
  Opcode op1 =
      Instruction::S390OpcodeValue(reinterpret_cast<const uint8_t*>(pc));
  SixByteInstr instr_1 =
      Instruction::InstructionBits(reinterpret_cast<const uint8_t*>(pc));
  bool patched = false;

  if (BRASL == op1 || BRCL == op1) {
    instr_1 >>= 32;  // Zero out the lower 32-bits
    instr_1 <<= 32;
    int32_t halfwords = (target - pc) / 2;  // number of halfwords
    instr_1 |= static_cast<uint32_t>(halfwords);
    Instruction::SetInstructionBits<SixByteInstr>(
        reinterpret_cast<uint8_t*>(pc), instr_1, jit_allocation);
    if (icache_flush_mode != SKIP_ICACHE_FLUSH) {
      FlushInstructionCache(pc, 6);
    }
    patched = true;
  } else {
    int instr1_length =
        Instruction::InstructionLength(reinterpret_cast<const uint8_t*>(pc));
    Opcode op2 = Instruction::S390OpcodeValue(
        reinterpret_cast<const uint8_t*>(pc + instr1_length));
    SixByteInstr instr_2 = Instruction::InstructionBits(
        reinterpret_cast<const uint8_t*>(pc + instr1_length));
    // IIHF for hi_32, IILF for lo_32
    if (IIHF == op1 && IILF == op2) {
      // IIHF
      instr_1 >>= 32;  // Zero out the lower 32-bits
      instr_1 <<= 32;
      instr_1 |= reinterpret_cast<uint64_t>(target) >> 32;

      Instruction::SetInstructionBits<SixByteInstr>(
          reinterpret_cast<uint8_t*>(pc), instr_1, jit_allocation);

      // IILF
      instr_2 >>= 32;
      instr_2 <<= 32;
      instr_2 |= reinterpret_cast<uint64_t>(target) & 0xFFFFFFFF;

      Instruction::SetInstructionBits<SixByteInstr>(
          reinterpret_cast<uint8_t*>(pc + instr1_length), instr_2,
          jit_allocation);
      if (icache_flush_mode != SKIP_ICACHE_FLUSH) {
        FlushInstructionCache(pc, 12);
      }
      patched = true;
    }
  }
  if (!patched) UNREACHABLE();
}

uint32_t Assembler::uint32_constant_at(Address pc, Address constant_pool) {
  Opcode op1 =
      Instruction::S390OpcodeValue(reinterpret_cast<const uint8_t*>(pc));
  // Set by MacroAssembler::mov.
  CHECK(op1 == LGFI);
  SixByteInstr instr_1 =
      Instruction::InstructionBits(reinterpret_cast<const uint8_t*>(pc));
  return static_cast<uint32_t>((instr_1 << 32) >> 32);
}

void Assembler::set_uint32_constant_at(Address pc, Address constant_pool,
                                       uint32_t new_constant,
                                       WritableJitAllocation* jit_allocation,
                                       ICacheFlushMode icache_flush_mode) {
  Opcode op1 =
      Instruction::S390OpcodeValue(reinterpret_cast<const uint8_t*>(pc));
  // Set by MacroAssembler::mov.
  CHECK(op1 == LGFI);
  SixByteInstr instr_1 =
      Instruction::InstructionBits(reinterpret_cast<const uint8_t*>(pc));
  instr_1 >>= 32;  // Zero out the lower 32-bits
  instr_1 <<= 32;
  instr_1 |= new_constant;
  Instruction::SetInstructionBits<SixByteInstr>(reinterpret_cast<uint8_t*>(pc),
                                                instr_1, jit_allocation);
  if (icache_flush_mode != SKIP_ICACHE_FLUSH) {
    FlushInstructionCache(pc, 6);
  }
}

}  // namespace internal
}  // namespace v8

#endif  // V8_CODEGEN_S390_ASSEMBLER_S390_INL_H_
```