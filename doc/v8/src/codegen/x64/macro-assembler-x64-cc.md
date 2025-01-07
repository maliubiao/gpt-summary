Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/x64/macro-assembler-x64.cc`. I need to extract the main responsibilities of this code.

Here's a breakdown of the code's functionalities:

1. **Assembler Interface:** This code provides a high-level interface (`MacroAssembler`) for generating x64 machine code within the V8 JavaScript engine. It builds upon a lower-level `Assembler` class.

2. **Memory Operations:** It offers methods for loading and storing data to/from registers and memory locations, including:
    * Loading from external references and the constant table.
    * Loading and storing roots (predefined, important objects).
    * Handling tagged values (V8's representation of JavaScript values).
    * Dealing with compressed pointers and sandboxed pointers (memory safety features).
    * Accessing object fields.

3. **Root Register Management:** It manages the `kRootRegister`, a special register that points to the root array, which contains important V8 objects and data. It offers efficient ways to access these roots.

4. **Function Calls:** It provides mechanisms for calling functions, including built-in functions and runtime stubs.

5. **Write Barriers:**  Crucially, it implements write barriers, which are essential for garbage collection. When an object pointer is updated, the write barrier ensures that the garbage collector is notified of this change.

6. **Code Generation Helpers:** It includes helper functions for common code generation tasks, such as comparing with roots, loading feedback vectors, and handling map packing.

7. **Platform-Specific:** This particular file is specific to the x64 architecture (`V8_TARGET_ARCH_X64`).

Regarding the user's specific questions:

* **`.tq` extension:** The code snippet is C++, not Torque, so it won't have a `.tq` extension.
* **JavaScript relationship:** This code is fundamental to the execution of JavaScript. It's the layer that translates higher-level V8 operations into actual machine instructions.
* **Code logic and examples:**  Many of the functions have inherent logic (e.g., loading a field involves calculating an offset). JavaScript examples would show scenarios that trigger these low-level operations (e.g., accessing an object property).
* **Common programming errors:**  While this is low-level code, errors could manifest as memory corruption or incorrect behavior in JavaScript.

**Plan for the response:**

1. State that the code is a C++ implementation of a macro-assembler for x64 within V8.
2. List its key functionalities based on the analysis above (memory operations, root register management, function calls, write barriers, etc.).
3. Confirm that it's not a Torque file.
4. Provide a brief JavaScript example illustrating how object property access relates to the code's memory operations.
5. Give a simplified hypothetical example of write barrier logic with input and output.
6. Provide an example of a common programming error related to incorrect memory management that this code helps to prevent.
这是V8 JavaScript引擎中用于x64架构的宏汇编器（MacroAssembler）的C++源代码。它提供了一组高级接口，用于生成x64机器码，这些机器码构成了V8执行JavaScript代码的基础。

以下是 `v8/src/codegen/x64/macro-assembler-x64.cc` 的功能归纳：

1. **提供x64架构的汇编指令抽象:**  `MacroAssembler` 类封装了底层的x64汇编指令，提供了更方便、更高级的接口来生成机器码。开发者可以使用诸如 `movq` (移动64位数据), `addq` (加法), `jmp` (跳转) 等指令，而无需直接操作原始的字节码。

2. **内存操作:**  提供了加载（Load）和存储（Store）数据到寄存器和内存的功能，包括：
    * 从外部引用加载数据 (`Load(Register destination, ExternalReference source)`)。
    * 存储数据到外部引用 (`Store(ExternalReference destination, Register source)`)。
    * 从常量表加载数据 (`LoadFromConstantsTable`)。
    * 加载根对象（Roots），这些是V8引擎预定义的、重要的对象，例如 `undefined`。(`LoadRoot`, `LoadTaggedRoot`)。
    * 加载和存储相对于根寄存器的地址 (`LoadRootRelative`, `StoreRootRelative`)。
    * 加载对象的字段 (`LoadTaggedField`)。

3. **根寄存器操作:**  V8使用一个特殊的寄存器（`kRootRegister`）来指向根对象数组。这个文件提供了便捷的方法来加载相对于根寄存器的偏移量，以及直接加载根对象。

4. **函数调用:** 提供了调用其他代码的功能，包括：
    * 调用内置函数 (`CallBuiltin`)。
    * 调用记录写入桩（Record Write Stub），这是垃圾回收机制的一部分，用于在指针更新时通知垃圾回收器。
    * 调用TSAN桩（ThreadSanitizer Stub），用于进行线程安全分析。

5. **处理Tagged指针:** JavaScript中的值通常以“Tagged”指针的形式表示，其中包含类型信息。这个文件提供了加载、存储和操作这些Tagged指针的方法，包括压缩指针和解压缩指针的处理 (`DecompressTagged`, `DecompressTaggedSigned`)。

6. **写屏障（Write Barriers）:**  实现了垃圾回收的写屏障机制。当堆中的一个对象被修改，并且修改涉及到一个指向另一个堆对象的指针时，就需要执行写屏障，以确保垃圾回收器能够正确地跟踪对象的引用关系。 (`RecordWriteField`, `RecordWrite`)。

7. **处理沙箱指针和外部指针:** 为了安全性和隔离性，V8使用了沙箱机制。这个文件提供了加载和存储沙箱指针以及外部指针的功能 (`EncodeSandboxedPointer`, `DecodeSandboxedPointer`, `LoadSandboxedPointerField`, `LoadExternalPointerField`)。

8. **处理间接指针:**  支持间接指针的加载和存储，这是一种更高级的指针管理机制。 (`LoadIndirectPointerField`, `StoreIndirectPointerField`)。

9. **代码入口:** 定义了代码的入口点 (`CodeEntry`)。

10. **辅助函数:** 提供了一些辅助函数，例如比较根对象 (`CompareRoot`, `CompareTaggedRoot`)，加载反馈向量 (`LoadFeedbackVector`) 等。

**关于你的问题：**

* **`.tq` 结尾:** `v8/src/codegen/x64/macro-assembler-x64.cc` 是一个 C++ 源文件，因此不会以 `.tq` 结尾。以 `.tq` 结尾的是 V8 的 Torque 语言源代码，Torque 是一种用于生成高效内置函数的领域特定语言。

* **与 JavaScript 的关系:**  `macro-assembler-x64.cc` 是 V8 引擎执行 JavaScript 代码的核心组成部分。当 V8 需要执行一段 JavaScript 代码时，它会将 JavaScript 代码编译成机器码，而 `MacroAssembler` 就是用来生成这些机器码的工具。

   **JavaScript 示例：**

   ```javascript
   const obj = { x: 10 };
   const y = obj.x;
   ```

   当执行 `const y = obj.x;` 时，V8 的代码生成器可能会使用 `MacroAssembler` 中的指令来完成以下操作（简化）：

   1. 将 `obj` 对象的地址加载到寄存器中。
   2. 计算 `x` 属性在 `obj` 对象中的偏移量。
   3. 使用计算出的偏移量从 `obj` 的内存位置加载 `x` 的值到另一个寄存器中。
   4. 将加载的值存储到变量 `y` 对应的内存位置。

* **代码逻辑推理:**  以 `LoadTaggedField` 函数为例，假设输入：

   * `destination` 寄存器： `rax`
   * `object` 寄存器（用于计算 `field_operand`）： `rbx`，其中 `rbx` 指向一个 JavaScript 对象。
   * `field_operand`： `FieldOperand(rbx, HeapObject::kMapOffset)`，表示加载对象的 Map 字段。

   **假设输入状态:**  寄存器 `rbx` 包含对象 `{'a': 1}` 的地址，该对象的 Map 位于对象的起始位置（`HeapObject::kMapOffset` 为 0）。假设 Map 的值是一个指向 Map 对象的压缩指针。

   **输出状态:**  执行 `LoadTaggedField(rax, FieldOperand(rbx, HeapObject::kMapOffset))` 后，寄存器 `rax` 将包含解压缩后的 Map 对象的地址。

   **代码逻辑:**

   ```c++
   void MacroAssembler::LoadTaggedField(Register destination,
                                        Operand field_operand) {
     if (COMPRESS_POINTERS_BOOL) {
       DecompressTagged(destination, field_operand); // 如果启用了指针压缩，则解压缩
     } else {
       mov_tagged(destination, field_operand);       // 否则，直接移动Tagged指针
     }
   }

   void MacroAssembler::DecompressTagged(Register destination,
                                         Operand field_operand) {
     ASM_CODE_COMMENT(this);
     movl(destination, field_operand);                // 将压缩后的值加载到目标寄存器的低32位
     addq(destination, kPtrComprCageBaseRegister);   // 加上 CageBase 地址进行解压缩
   }
   ```

* **用户常见的编程错误:** 虽然用户通常不会直接编写汇编代码，但 V8 引擎在生成机器码时需要处理各种情况。一个与内存管理相关的常见错误是 **悬 dangling 指针**。

   **示例 (C++ 层面理解):**

   假设一段 JavaScript 代码创建了一个对象，并且该对象被赋值给另一个对象的属性：

   ```javascript
   const obj1 = {};
   const obj2 = { data: obj1 };
   ```

   在 V8 的内部表示中，`obj2.data` 包含一个指向 `obj1` 的指针。 如果在没有通知垃圾回收器的情况下，直接修改 `obj2.data` 指向一块已经被释放的内存，就会产生悬 dangling 指针。

   `MacroAssembler` 中实现的 **写屏障** 功能就是为了防止这类错误。当修改 `obj2.data` 时，写屏障会检查新写入的值是否是一个指向堆中对象的指针，如果是，则会通知垃圾回收器，确保垃圾回收器能够正确地更新对象的引用关系，避免悬 dangling 指针的产生。

**总结一下它的功能：**

`v8/src/codegen/x64/macro-assembler-x64.cc` 是 V8 引擎中用于生成 x64 架构机器码的关键组件，它提供了操作寄存器、内存、根对象、Tagged 指针，以及实现垃圾回收写屏障等核心功能，是 V8 执行 JavaScript 代码的基础。它是 V8 代码生成器的重要组成部分，负责将高级的 V8 操作转化为底层的机器指令。

Prompt: 
```
这是目录为v8/src/codegen/x64/macro-assembler-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/x64/macro-assembler-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <climits>
#include <cstdint>

#if V8_TARGET_ARCH_X64

#include <optional>

#include "src/base/bits.h"
#include "src/base/division-by-constant.h"
#include "src/base/utils/random-number-generator.h"
#include "src/builtins/builtins-inl.h"
#include "src/codegen/callable.h"
#include "src/codegen/code-factory.h"
#include "src/codegen/cpu-features.h"
#include "src/codegen/external-reference-table.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/register-configuration.h"
#include "src/codegen/register.h"
#include "src/codegen/x64/assembler-x64.h"
#include "src/codegen/x64/register-x64.h"
#include "src/common/globals.h"
#include "src/debug/debug.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/frames-inl.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/init/bootstrapper.h"
#include "src/logging/counters.h"
#include "src/objects/instance-type-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/smi.h"
#include "src/sandbox/external-pointer.h"
#include "src/snapshot/snapshot.h"

// Satisfy cpplint check, but don't include platform-specific header. It is
// included recursively via macro-assembler.h.
#if 0
#include "src/codegen/x64/macro-assembler-x64.h"
#endif

#define __ ACCESS_MASM(masm)

namespace v8 {
namespace internal {

Operand StackArgumentsAccessor::GetArgumentOperand(int index) const {
  DCHECK_GE(index, 0);
  // arg[0] = rsp + kPCOnStackSize;
  // arg[i] = arg[0] + i * kSystemPointerSize;
  return Operand(rsp, kPCOnStackSize + index * kSystemPointerSize);
}

void MacroAssembler::CodeEntry() {
  endbr64();
}

void MacroAssembler::Load(Register destination, ExternalReference source) {
  if (root_array_available_ && options().enable_root_relative_access) {
    intptr_t delta = RootRegisterOffsetForExternalReference(isolate(), source);
    if (is_int32(delta)) {
      movq(destination, Operand(kRootRegister, static_cast<int32_t>(delta)));
      return;
    }
  }
  // Safe code.
  if (destination == rax && !options().isolate_independent_code) {
    load_rax(source);
  } else {
    movq(destination, ExternalReferenceAsOperand(source));
  }
}

void MacroAssembler::Store(ExternalReference destination, Register source) {
  if (root_array_available_ && options().enable_root_relative_access) {
    intptr_t delta =
        RootRegisterOffsetForExternalReference(isolate(), destination);
    if (is_int32(delta)) {
      movq(Operand(kRootRegister, static_cast<int32_t>(delta)), source);
      return;
    }
  }
  // Safe code.
  if (source == rax && !options().isolate_independent_code) {
    store_rax(destination);
  } else {
    movq(ExternalReferenceAsOperand(destination), source);
  }
}

void MacroAssembler::LoadFromConstantsTable(Register destination,
                                            int constant_index) {
  DCHECK(RootsTable::IsImmortalImmovable(RootIndex::kBuiltinsConstantsTable));
  LoadRoot(destination, RootIndex::kBuiltinsConstantsTable);
  LoadTaggedField(
      destination,
      FieldOperand(destination, FixedArray::OffsetOfElementAt(constant_index)));
}

void MacroAssembler::LoadRootRegisterOffset(Register destination,
                                            intptr_t offset) {
  DCHECK(is_int32(offset));
  if (offset == 0) {
    Move(destination, kRootRegister);
  } else {
    leaq(destination, Operand(kRootRegister, static_cast<int32_t>(offset)));
  }
}

void MacroAssembler::LoadRootRelative(Register destination, int32_t offset) {
  movq(destination, Operand(kRootRegister, offset));
}

void MacroAssembler::StoreRootRelative(int32_t offset, Register value) {
  movq(Operand(kRootRegister, offset), value);
}

void MacroAssembler::LoadAddress(Register destination,
                                 ExternalReference source) {
  if (root_array_available()) {
    if (source.IsIsolateFieldId()) {
      leaq(destination,
           Operand(kRootRegister, source.offset_from_root_register()));
      return;
    }
    if (options().enable_root_relative_access) {
      intptr_t delta =
          RootRegisterOffsetForExternalReference(isolate(), source);
      if (is_int32(delta)) {
        leaq(destination, Operand(kRootRegister, static_cast<int32_t>(delta)));
        return;
      }
    } else if (options().isolate_independent_code) {
      IndirectLoadExternalReference(destination, source);
      return;
    }
  }
  Move(destination, source);
}

Operand MacroAssembler::ExternalReferenceAsOperand(ExternalReference reference,
                                                   Register scratch) {
  if (root_array_available()) {
    if (reference.IsIsolateFieldId()) {
      return Operand(kRootRegister, reference.offset_from_root_register());
    }
    if (options().enable_root_relative_access) {
      int64_t delta =
          RootRegisterOffsetForExternalReference(isolate(), reference);
      if (is_int32(delta)) {
        return Operand(kRootRegister, static_cast<int32_t>(delta));
      }
    }
    if (options().isolate_independent_code) {
      if (IsAddressableThroughRootRegister(isolate(), reference)) {
        // Some external references can be efficiently loaded as an offset from
        // kRootRegister.
        intptr_t offset =
            RootRegisterOffsetForExternalReference(isolate(), reference);
        CHECK(is_int32(offset));
        return Operand(kRootRegister, static_cast<int32_t>(offset));
      } else {
        // Otherwise, do a memory load from the external reference table.
        movq(scratch, Operand(kRootRegister,
                              RootRegisterOffsetForExternalReferenceTableEntry(
                                  isolate(), reference)));
        return Operand(scratch, 0);
      }
    }
  }
  Move(scratch, reference);
  return Operand(scratch, 0);
}

void MacroAssembler::PushAddress(ExternalReference source) {
  LoadAddress(kScratchRegister, source);
  Push(kScratchRegister);
}

Operand MacroAssembler::RootAsOperand(RootIndex index) {
  DCHECK(root_array_available());
  return Operand(kRootRegister, RootRegisterOffsetForRootIndex(index));
}

void MacroAssembler::LoadTaggedRoot(Register destination, RootIndex index) {
  static_assert(!CanBeImmediate(RootIndex::kUndefinedValue) ||
                std::is_same<Tagged_t, uint32_t>::value);
  if (CanBeImmediate(index)) {
    mov_tagged(destination,
               Immediate(static_cast<uint32_t>(ReadOnlyRootPtr(index))));
    return;
  }
  DCHECK(root_array_available_);
  movq(destination, RootAsOperand(index));
}

void MacroAssembler::LoadRoot(Register destination, RootIndex index) {
  if (CanBeImmediate(index)) {
    DecompressTagged(destination,
                     static_cast<uint32_t>(ReadOnlyRootPtr(index)));
    return;
  }
  DCHECK(root_array_available_);
  movq(destination, RootAsOperand(index));
}

void MacroAssembler::PushRoot(RootIndex index) {
  DCHECK(root_array_available_);
  Push(RootAsOperand(index));
}

void MacroAssembler::CompareRoot(Register with, RootIndex index,
                                 ComparisonMode mode) {
  if (mode == ComparisonMode::kFullPointer ||
      !base::IsInRange(index, RootIndex::kFirstStrongOrReadOnlyRoot,
                       RootIndex::kLastStrongOrReadOnlyRoot)) {
    // Some smi roots contain system pointer size values like stack limits.
    cmpq(with, RootAsOperand(index));
    return;
  }
  CompareTaggedRoot(with, index);
}

void MacroAssembler::CompareTaggedRoot(Register with, RootIndex index) {
  AssertSmiOrHeapObjectInMainCompressionCage(with);
  if (CanBeImmediate(index)) {
    cmp_tagged(with, Immediate(static_cast<uint32_t>(ReadOnlyRootPtr(index))));
    return;
  }
  DCHECK(root_array_available_);
  // Some smi roots contain system pointer size values like stack limits.
  DCHECK(base::IsInRange(index, RootIndex::kFirstStrongOrReadOnlyRoot,
                         RootIndex::kLastStrongOrReadOnlyRoot));
  cmp_tagged(with, RootAsOperand(index));
}

void MacroAssembler::CompareRoot(Operand with, RootIndex index) {
  if (CanBeImmediate(index)) {
    cmp_tagged(with, Immediate(static_cast<uint32_t>(ReadOnlyRootPtr(index))));
    return;
  }
  DCHECK(root_array_available_);
  DCHECK(!with.AddressUsesRegister(kScratchRegister));
  if (base::IsInRange(index, RootIndex::kFirstStrongOrReadOnlyRoot,
                      RootIndex::kLastStrongOrReadOnlyRoot)) {
    mov_tagged(kScratchRegister, RootAsOperand(index));
    cmp_tagged(with, kScratchRegister);
  } else {
    // Some smi roots contain system pointer size values like stack limits.
    movq(kScratchRegister, RootAsOperand(index));
    cmpq(with, kScratchRegister);
  }
}

void MacroAssembler::LoadCompressedMap(Register destination, Register object) {
  CHECK(COMPRESS_POINTERS_BOOL);
  mov_tagged(destination, FieldOperand(object, HeapObject::kMapOffset));
}

void MacroAssembler::LoadMap(Register destination, Register object) {
  LoadTaggedField(destination, FieldOperand(object, HeapObject::kMapOffset));
#ifdef V8_MAP_PACKING
  UnpackMapWord(destination);
#endif
}

void MacroAssembler::LoadFeedbackVector(Register dst, Register closure,
                                        Label* fbv_undef,
                                        Label::Distance distance) {
  Label done;

  // Load the feedback vector from the closure.
  TaggedRegister feedback_cell(dst);
  LoadTaggedField(feedback_cell,
                  FieldOperand(closure, JSFunction::kFeedbackCellOffset));
  LoadTaggedField(dst, FieldOperand(feedback_cell, FeedbackCell::kValueOffset));

  // Check if feedback vector is valid.
  IsObjectType(dst, FEEDBACK_VECTOR_TYPE, rcx);
  j(equal, &done, Label::kNear);

  // Not valid, load undefined.
  LoadRoot(dst, RootIndex::kUndefinedValue);
  jmp(fbv_undef, distance);

  bind(&done);
}

void MacroAssembler::LoadTaggedField(Register destination,
                                     Operand field_operand) {
  if (COMPRESS_POINTERS_BOOL) {
    DecompressTagged(destination, field_operand);
  } else {
    mov_tagged(destination, field_operand);
  }
}

void MacroAssembler::LoadTaggedField(TaggedRegister destination,
                                     Operand field_operand) {
  LoadTaggedFieldWithoutDecompressing(destination.reg(), field_operand);
}

void MacroAssembler::LoadTaggedFieldWithoutDecompressing(
    Register destination, Operand field_operand) {
  mov_tagged(destination, field_operand);
}

#ifdef V8_MAP_PACKING
void MacroAssembler::UnpackMapWord(Register r) {
  // Clear the top two bytes (which may include metadata). Must be in sync with
  // MapWord::Unpack, and vice versa.
  shlq(r, Immediate(16));
  shrq(r, Immediate(16));
  xorq(r, Immediate(Internals::kMapWordXorMask));
}
#endif

void MacroAssembler::LoadTaggedSignedField(Register destination,
                                           Operand field_operand) {
  if (COMPRESS_POINTERS_BOOL) {
    DecompressTaggedSigned(destination, field_operand);
  } else {
    mov_tagged(destination, field_operand);
  }
}

void MacroAssembler::PushTaggedField(Operand field_operand, Register scratch) {
  if (COMPRESS_POINTERS_BOOL) {
    DCHECK(!field_operand.AddressUsesRegister(scratch));
    DecompressTagged(scratch, field_operand);
    Push(scratch);
  } else {
    Push(field_operand);
  }
}

void MacroAssembler::SmiUntagField(Register dst, Operand src) {
  SmiUntag(dst, src);
}

void MacroAssembler::SmiUntagFieldUnsigned(Register dst, Operand src) {
  SmiUntagUnsigned(dst, src);
}

void MacroAssembler::StoreTaggedField(Operand dst_field_operand,
                                      Immediate value) {
  if (COMPRESS_POINTERS_BOOL) {
    movl(dst_field_operand, value);
  } else {
    movq(dst_field_operand, value);
  }
}

void MacroAssembler::StoreTaggedField(Operand dst_field_operand,
                                      Register value) {
  if (COMPRESS_POINTERS_BOOL) {
    movl(dst_field_operand, value);
  } else {
    movq(dst_field_operand, value);
  }
}

void MacroAssembler::StoreTaggedSignedField(Operand dst_field_operand,
                                            Tagged<Smi> value) {
  if (SmiValuesAre32Bits()) {
    Move(kScratchRegister, value);
    movq(dst_field_operand, kScratchRegister);
  } else {
    StoreTaggedField(dst_field_operand, Immediate(value));
  }
}

void MacroAssembler::AtomicStoreTaggedField(Operand dst_field_operand,
                                            Register value) {
  if (COMPRESS_POINTERS_BOOL) {
    movl(kScratchRegister, value);
    xchgl(kScratchRegister, dst_field_operand);
  } else {
    movq(kScratchRegister, value);
    xchgq(kScratchRegister, dst_field_operand);
  }
}

void MacroAssembler::DecompressTaggedSigned(Register destination,
                                            Operand field_operand) {
  ASM_CODE_COMMENT(this);
  movl(destination, field_operand);
}

void MacroAssembler::DecompressTagged(Register destination,
                                      Operand field_operand) {
  ASM_CODE_COMMENT(this);
  movl(destination, field_operand);
  addq(destination, kPtrComprCageBaseRegister);
}

void MacroAssembler::DecompressTagged(Register destination, Register source) {
  ASM_CODE_COMMENT(this);
  movl(destination, source);
  addq(destination, kPtrComprCageBaseRegister);
}

void MacroAssembler::DecompressTagged(Register destination,
                                      Tagged_t immediate) {
  ASM_CODE_COMMENT(this);
  leaq(destination,
       Operand(kPtrComprCageBaseRegister, static_cast<int32_t>(immediate)));
}

void MacroAssembler::DecompressProtected(Register destination,
                                         Operand field_operand) {
#if V8_ENABLE_SANDBOX
  ASM_CODE_COMMENT(this);
  movl(destination, field_operand);
  DCHECK(root_array_available_);
  orq(destination,
      Operand{kRootRegister, IsolateData::trusted_cage_base_offset()});
#else
  UNREACHABLE();
#endif  // V8_ENABLE_SANDBOX
}

void MacroAssembler::RecordWriteField(Register object, int offset,
                                      Register value, Register slot_address,
                                      SaveFPRegsMode save_fp,
                                      SmiCheck smi_check,
                                      ReadOnlyCheck ro_check,
                                      SlotDescriptor slot) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(object, value, slot_address));
  // First, check if a write barrier is even needed. The tests below
  // catch stores of Smis and read-only objects.
  Label done;

#if V8_STATIC_ROOTS_BOOL
  if (ro_check == ReadOnlyCheck::kInline) {
    // Quick check for Read-only and small Smi values.
    static_assert(StaticReadOnlyRoot::kLastAllocatedRoot < kRegularPageSize);
    JumpIfUnsignedLessThan(value, kRegularPageSize, &done);
  }
#endif  // V8_STATIC_ROOTS_BOOL

  // Skip barrier if writing a smi.
  if (smi_check == SmiCheck::kInline) {
    JumpIfSmi(value, &done);
  }

  // Although the object register is tagged, the offset is relative to the start
  // of the object, so the offset must be a multiple of kTaggedSize.
  DCHECK(IsAligned(offset, kTaggedSize));

  leaq(slot_address, FieldOperand(object, offset));
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT_STRING(this, "Debug check slot_address");
    Label ok;
    testb(slot_address, Immediate(kTaggedSize - 1));
    j(zero, &ok, Label::kNear);
    int3();
    bind(&ok);
  }

  RecordWrite(object, slot_address, value, save_fp, SmiCheck::kOmit,
              ReadOnlyCheck::kOmit, slot);

  bind(&done);

  // Clobber clobbered input registers when running with the debug-code flag
  // turned on to provoke errors.
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT_STRING(this, "Zap scratch registers");
    Move(value, kZapValue, RelocInfo::NO_INFO);
    Move(slot_address, kZapValue, RelocInfo::NO_INFO);
  }
}

void MacroAssembler::EncodeSandboxedPointer(Register value) {
  ASM_CODE_COMMENT(this);
#ifdef V8_ENABLE_SANDBOX
  subq(value, kPtrComprCageBaseRegister);
  shlq(value, Immediate(kSandboxedPointerShift));
#else
  UNREACHABLE();
#endif
}

void MacroAssembler::DecodeSandboxedPointer(Register value) {
  ASM_CODE_COMMENT(this);
#ifdef V8_ENABLE_SANDBOX
  shrq(value, Immediate(kSandboxedPointerShift));
  addq(value, kPtrComprCageBaseRegister);
#else
  UNREACHABLE();
#endif
}

void MacroAssembler::LoadSandboxedPointerField(Register destination,
                                               Operand field_operand) {
  ASM_CODE_COMMENT(this);
  movq(destination, field_operand);
  DecodeSandboxedPointer(destination);
}

void MacroAssembler::StoreSandboxedPointerField(Operand dst_field_operand,
                                                Register value) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(value, kScratchRegister));
  DCHECK(!dst_field_operand.AddressUsesRegister(kScratchRegister));
  movq(kScratchRegister, value);
  EncodeSandboxedPointer(kScratchRegister);
  movq(dst_field_operand, kScratchRegister);
}

void MacroAssembler::LoadExternalPointerField(
    Register destination, Operand field_operand, ExternalPointerTag tag,
    Register scratch, IsolateRootLocation isolateRootLocation) {
  DCHECK(!AreAliased(destination, scratch));
#ifdef V8_ENABLE_SANDBOX
  DCHECK_NE(tag, kExternalPointerNullTag);
  DCHECK(!IsSharedExternalPointerType(tag));
  DCHECK(!field_operand.AddressUsesRegister(scratch));
  if (isolateRootLocation == IsolateRootLocation::kInRootRegister) {
    DCHECK(root_array_available_);
    // TODO(saelo): consider using an ExternalReference here.
    movq(scratch,
         Operand(kRootRegister,
                 IsolateData::external_pointer_table_offset() +
                     Internals::kExternalPointerTableBasePointerOffset));
  } else {
    DCHECK(isolateRootLocation == IsolateRootLocation::kInScratchRegister);
    movq(scratch,
         Operand(scratch,
                 IsolateData::external_pointer_table_offset() +
                     Internals::kExternalPointerTableBasePointerOffset));
  }
  movl(destination, field_operand);
  shrq(destination, Immediate(kExternalPointerIndexShift));
  static_assert(kExternalPointerTableEntrySize == 8);
  movq(destination, Operand(scratch, destination, times_8, 0));
  movq(scratch, Immediate64(~tag));
  andq(destination, scratch);
#else
  movq(destination, field_operand);
#endif  // V8_ENABLE_SANDBOX
}

void MacroAssembler::LoadTrustedPointerField(Register destination,
                                             Operand field_operand,
                                             IndirectPointerTag tag,
                                             Register scratch) {
#ifdef V8_ENABLE_SANDBOX
  LoadIndirectPointerField(destination, field_operand, tag, scratch);
#else
  LoadTaggedField(destination, field_operand);
#endif  // V8_ENABLE_SANDBOX
}

void MacroAssembler::StoreTrustedPointerField(Operand dst_field_operand,
                                              Register value) {
#ifdef V8_ENABLE_SANDBOX
  StoreIndirectPointerField(dst_field_operand, value);
#else
  StoreTaggedField(dst_field_operand, value);
#endif  // V8_ENABLE_SANDBOX
}

void MacroAssembler::LoadIndirectPointerField(Register destination,
                                              Operand field_operand,
                                              IndirectPointerTag tag,
                                              Register scratch) {
#ifdef V8_ENABLE_SANDBOX
  DCHECK(!AreAliased(destination, scratch));
  Register handle = scratch;
  movl(handle, field_operand);
  ResolveIndirectPointerHandle(destination, handle, tag);
#else
  UNREACHABLE();
#endif  // V8_ENABLE_SANDBOX
}

void MacroAssembler::StoreIndirectPointerField(Operand dst_field_operand,
                                               Register value) {
#ifdef V8_ENABLE_SANDBOX
  movl(kScratchRegister,
       FieldOperand(value, ExposedTrustedObject::kSelfIndirectPointerOffset));
  movl(dst_field_operand, kScratchRegister);
#else
  UNREACHABLE();
#endif  // V8_ENABLE_SANDBOX
}

#ifdef V8_ENABLE_SANDBOX
void MacroAssembler::ResolveIndirectPointerHandle(Register destination,
                                                  Register handle,
                                                  IndirectPointerTag tag) {
  // The tag implies which pointer table to use.
  if (tag == kUnknownIndirectPointerTag) {
    // In this case we have to rely on the handle marking to determine which
    // pointer table to use.
    Label is_trusted_pointer_handle, done;
    testl(handle, Immediate(kCodePointerHandleMarker));
    j(zero, &is_trusted_pointer_handle, Label::kNear);
    ResolveCodePointerHandle(destination, handle);
    jmp(&done, Label::kNear);
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
  DCHECK_NE(tag, kCodeIndirectPointerTag);
  DCHECK(!AreAliased(handle, destination));
  shrl(handle, Immediate(kTrustedPointerHandleShift));
  static_assert(kTrustedPointerTableEntrySize == 8);
  DCHECK(root_array_available_);
  movq(destination,
       Operand{kRootRegister, IsolateData::trusted_pointer_table_offset()});
  movq(destination, Operand{destination, handle, times_8, 0});
  // Untag the pointer and remove the marking bit in one operation.
  Register tag_reg = handle;
  movq(tag_reg, Immediate64(~(tag | kTrustedPointerTableMarkBit)));
  andq(destination, tag_reg);
}

void MacroAssembler::ResolveCodePointerHandle(Register destination,
                                              Register handle) {
  DCHECK(!AreAliased(handle, destination));
  Register table = destination;
  LoadAddress(table, ExternalReference::code_pointer_table_address());
  shrl(handle, Immediate(kCodePointerHandleShift));
  // The code pointer table entry size is 16 bytes, so we have to do an
  // explicit shift first (times_16 doesn't exist).
  shll(handle, Immediate(kCodePointerTableEntrySizeLog2));
  movq(destination,
       Operand(table, handle, times_1, kCodePointerTableEntryCodeObjectOffset));
  // The LSB is used as marking bit by the code pointer table, so here we have
  // to set it using a bitwise OR as it may or may not be set.
  orq(destination, Immediate(kHeapObjectTag));
}

void MacroAssembler::LoadCodeEntrypointViaCodePointer(Register destination,
                                                      Operand field_operand,
                                                      CodeEntrypointTag tag) {
  DCHECK(!AreAliased(destination, kScratchRegister));
  DCHECK(!field_operand.AddressUsesRegister(kScratchRegister));
  DCHECK_NE(tag, kInvalidEntrypointTag);
  LoadAddress(kScratchRegister,
              ExternalReference::code_pointer_table_address());
  movl(destination, field_operand);
  shrl(destination, Immediate(kCodePointerHandleShift));
  shll(destination, Immediate(kCodePointerTableEntrySizeLog2));
  movq(destination, Operand(kScratchRegister, destination, times_1, 0));
  if (tag != 0) {
    // Can this be improved?
    movq(kScratchRegister, Immediate64(tag));
    xorq(destination, kScratchRegister);
  }
}
#endif  // V8_ENABLE_SANDBOX

#ifdef V8_ENABLE_LEAPTIERING
void MacroAssembler::LoadEntrypointFromJSDispatchTable(
    Register destination, Register dispatch_handle) {
  DCHECK(!AreAliased(destination, dispatch_handle, kScratchRegister));
  LoadAddress(kScratchRegister, ExternalReference::js_dispatch_table_address());
  movq(destination, dispatch_handle);
  shrl(destination, Immediate(kJSDispatchHandleShift));
  shll(destination, Immediate(kJSDispatchTableEntrySizeLog2));
  movq(destination, Operand(kScratchRegister, destination, times_1,
                            JSDispatchEntry::kEntrypointOffset));
}

void MacroAssembler::LoadParameterCountFromJSDispatchTable(
    Register destination, Register dispatch_handle) {
  DCHECK(!AreAliased(destination, dispatch_handle, kScratchRegister));
  LoadAddress(kScratchRegister, ExternalReference::js_dispatch_table_address());
  movq(destination, dispatch_handle);
  shrl(destination, Immediate(kJSDispatchHandleShift));
  shll(destination, Immediate(kJSDispatchTableEntrySizeLog2));
  static_assert(JSDispatchEntry::kParameterCountMask == 0xffff);
  movzxwq(destination, Operand(kScratchRegister, destination, times_1,
                               JSDispatchEntry::kCodeObjectOffset));
}

void MacroAssembler::LoadEntrypointAndParameterCountFromJSDispatchTable(
    Register entrypoint, Register parameter_count, Register dispatch_handle) {
  DCHECK(!AreAliased(entrypoint, parameter_count, dispatch_handle,
                     kScratchRegister));
  LoadAddress(kScratchRegister, ExternalReference::js_dispatch_table_address());
  Register offset = parameter_count;
  movq(offset, dispatch_handle);
  shrl(offset, Immediate(kJSDispatchHandleShift));
  shll(offset, Immediate(kJSDispatchTableEntrySizeLog2));
  movq(entrypoint, Operand(kScratchRegister, offset, times_1,
                           JSDispatchEntry::kEntrypointOffset));
  static_assert(JSDispatchEntry::kParameterCountMask == 0xffff);
  movzxwq(parameter_count, Operand(kScratchRegister, offset, times_1,
                                   JSDispatchEntry::kCodeObjectOffset));
}
#endif

void MacroAssembler::LoadProtectedPointerField(Register destination,
                                               Operand field_operand) {
  DCHECK(root_array_available());
#ifdef V8_ENABLE_SANDBOX
  DecompressProtected(destination, field_operand);
#else
  LoadTaggedField(destination, field_operand);
#endif
}

void MacroAssembler::CallEphemeronKeyBarrier(Register object,
                                             Register slot_address,
                                             SaveFPRegsMode fp_mode) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(object, slot_address));
  RegList registers =
      WriteBarrierDescriptor::ComputeSavedRegisters(object, slot_address);
  PushAll(registers);

  Register object_parameter = WriteBarrierDescriptor::ObjectRegister();
  Register slot_address_parameter =
      WriteBarrierDescriptor::SlotAddressRegister();
  MovePair(slot_address_parameter, slot_address, object_parameter, object);

  CallBuiltin(Builtins::EphemeronKeyBarrier(fp_mode));
  PopAll(registers);
}

void MacroAssembler::CallIndirectPointerBarrier(Register object,
                                                Register slot_address,
                                                SaveFPRegsMode fp_mode,
                                                IndirectPointerTag tag) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(object, slot_address));
  // TODO(saelo) if necessary, we could introduce a "SaveRegisters version of
  // this function and make this code not save clobbered registers. It's
  // probably not currently worth the effort though since stores to indirect
  // pointer fields are fairly rare.
  RegList registers =
      IndirectPointerWriteBarrierDescriptor::ComputeSavedRegisters(
          object, slot_address);
  PushAll(registers);

  Register object_parameter =
      IndirectPointerWriteBarrierDescriptor::ObjectRegister();
  Register slot_address_parameter =
      IndirectPointerWriteBarrierDescriptor::SlotAddressRegister();
  MovePair(slot_address_parameter, slot_address, object_parameter, object);

  Register tag_parameter =
      IndirectPointerWriteBarrierDescriptor::IndirectPointerTagRegister();
  Move(tag_parameter, tag);

  CallBuiltin(Builtins::IndirectPointerBarrier(fp_mode));
  PopAll(registers);
}

void MacroAssembler::CallRecordWriteStubSaveRegisters(Register object,
                                                      Register slot_address,
                                                      SaveFPRegsMode fp_mode,
                                                      StubCallMode mode) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(object, slot_address));
  RegList registers =
      WriteBarrierDescriptor::ComputeSavedRegisters(object, slot_address);
  PushAll(registers);
  Register object_parameter = WriteBarrierDescriptor::ObjectRegister();
  Register slot_address_parameter =
      WriteBarrierDescriptor::SlotAddressRegister();
  MovePair(object_parameter, object, slot_address_parameter, slot_address);

  CallRecordWriteStub(object_parameter, slot_address_parameter, fp_mode, mode);
  PopAll(registers);
}

void MacroAssembler::CallRecordWriteStub(Register object, Register slot_address,
                                         SaveFPRegsMode fp_mode,
                                         StubCallMode mode) {
  ASM_CODE_COMMENT(this);
  // Use CallRecordWriteStubSaveRegisters if the object and slot registers
  // need to be caller saved.
  DCHECK_EQ(WriteBarrierDescriptor::ObjectRegister(), object);
  DCHECK_EQ(WriteBarrierDescriptor::SlotAddressRegister(), slot_address);
#if V8_ENABLE_WEBASSEMBLY
  if (mode == StubCallMode::kCallWasmRuntimeStub) {
    // Use {near_call} for direct Wasm call within a module.
    intptr_t wasm_target =
        static_cast<intptr_t>(wasm::WasmCode::GetRecordWriteBuiltin(fp_mode));
    near_call(wasm_target, RelocInfo::WASM_STUB_CALL);
#else
  if (false) {
#endif
  } else {
    CallBuiltin(Builtins::RecordWrite(fp_mode));
  }
}

#ifdef V8_IS_TSAN
void MacroAssembler::CallTSANStoreStub(Register address, Register value,
                                       SaveFPRegsMode fp_mode, int size,
                                       StubCallMode mode,
                                       std::memory_order order) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(address, value));
  TSANStoreDescriptor descriptor;
  RegList registers = descriptor.allocatable_registers();

  PushAll(registers);

  Register address_parameter(
      descriptor.GetRegisterParameter(TSANStoreDescriptor::kAddress));
  Register value_parameter(
      descriptor.GetRegisterParameter(TSANStoreDescriptor::kValue));

  // Prepare argument registers for calling GetTSANStoreStub.
  MovePair(address_parameter, address, value_parameter, value);

#if V8_ENABLE_WEBASSEMBLY
  if (mode != StubCallMode::kCallWasmRuntimeStub) {
    // JS functions and Wasm wrappers.
    CallBuiltin(CodeFactory::GetTSANStoreStub(fp_mode, size, order));
  } else {
    // Wasm functions should call builtins through their far jump table.
    auto wasm_target = static_cast<intptr_t>(
        wasm::WasmCode::GetTSANStoreBuiltin(fp_mode, size, order));
    near_call(wasm_target, RelocInfo::WASM_STUB_CALL);
  }
#else
  CallBuiltin(CodeFactory::GetTSANStoreStub(fp_mode, size, order));
#endif  // V8_ENABLE_WEBASSEMBLY

  PopAll(registers);
}

void MacroAssembler::CallTSANRelaxedLoadStub(Register address,
                                             SaveFPRegsMode fp_mode, int size,
                                             StubCallMode mode) {
  TSANLoadDescriptor descriptor;
  RegList registers = descriptor.allocatable_registers();

  PushAll(registers);

  Register address_parameter(
      descriptor.GetRegisterParameter(TSANLoadDescriptor::kAddress));

  // Prepare argument registers for calling TSANRelaxedLoad.
  Move(address_parameter, address);

#if V8_ENABLE_WEBASSEMBLY
  if (mode != StubCallMode::kCallWasmRuntimeStub) {
    // JS functions and Wasm wrappers.
    CallBuiltin(CodeFactory::GetTSANRelaxedLoadStub(fp_mode, size));
  } else {
    // Wasm functions should call builtins through their far jump table.
    auto wasm_target = static_cast<intptr_t>(
        wasm::WasmCode::GetTSANRelaxedLoadBuiltin(fp_mode, size));
    near_call(wasm_target, RelocInfo::WASM_STUB_CALL);
  }
#else
  CallBuiltin(CodeFactory::GetTSANRelaxedLoadStub(fp_mode, size));
#endif  // V8_ENABLE_WEBASSEMBLY

  PopAll(registers);
}
#endif  // V8_IS_TSAN

void MacroAssembler::RecordWrite(Register object, Register slot_address,
                                 Register value, SaveFPRegsMode fp_mode,
                                 SmiCheck smi_check, ReadOnlyCheck ro_check,
                                 SlotDescriptor slot) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(object, slot_address, value));
  AssertNotSmi(object);

  if (v8_flags.disable_write_barriers) {
    return;
  }

  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT_STRING(this, "Debug check slot_address");
    Label ok;
    if (slot.contains_indirect_pointer()) {
      Push(object); 
"""


```