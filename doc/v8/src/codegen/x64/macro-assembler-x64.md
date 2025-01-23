Response: The user wants a summary of the C++ source code file `v8/src/codegen/x64/macro-assembler-x64.cc`.
This is the first part of a larger file.
The file seems to define the `MacroAssembler` class for the x64 architecture in V8.
This class provides a high-level interface to generate machine code instructions.
It includes functionalities for:
- Loading and storing data from memory and registers.
- Performing arithmetic and logical operations.
- Branching and jumping.
- Calling functions (both C++ runtime and Javascript).
- Handling tagged values (Smi and HeapObject).
- Implementing write barriers for garbage collection.
- Dealing with different memory models (compressed pointers, sandboxed pointers).
- Floating-point operations.

Since the file name contains "codegen", it's related to the code generation process in V8, which directly influences how Javascript code is executed.

Let's try to identify specific functionalities and relate them to Javascript concepts.
这个C++源代码文件 `v8/src/codegen/x64/macro-assembler-x64.cc` 的主要功能是**为V8 JavaScript引擎的x64架构提供底层的汇编指令生成接口**。它是 `MacroAssembler` 类的具体实现，用于将高级操作转换成可以直接在x64处理器上执行的机器码。

更具体地说，这个文件的第1部分涵盖了以下功能：

1. **栈操作:** 提供了访问和操作栈上参数的方法 (`StackArgumentsAccessor`)。
2. **代码入口:** 定义了代码的起始点 (`CodeEntry`)。
3. **加载和存储数据:** 提供了从内存、外部引用和常量表中加载数据到寄存器，以及将寄存器中的数据存储到内存和外部引用的方法 (`Load`, `Store`, `LoadFromConstantsTable`)。
4. **根寄存器操作:** 提供了加载和存储相对于根寄存器的数据的方法，用于访问全局对象和V8内部数据结构 (`LoadRootRegisterOffset`, `LoadRootRelative`, `StoreRootRelative`, `LoadAddress`, `ExternalReferenceAsOperand`, `PushAddress`, `RootAsOperand`, `LoadTaggedRoot`, `LoadRoot`, `PushRoot`, `CompareRoot`, `CompareTaggedRoot`)。
5. **对象和字段操作:** 提供了加载和存储对象的字段的方法，包括处理压缩指针的情况 (`LoadCompressedMap`, `LoadMap`, `LoadFeedbackVector`, `LoadTaggedField`, `LoadTaggedFieldWithoutDecompressing`, `UnpackMapWord`, `LoadTaggedSignedField`, `PushTaggedField`, `SmiUntagField`, `SmiUntagFieldUnsigned`, `StoreTaggedField`, `StoreTaggedSignedField`, `AtomicStoreTaggedField`, `DecompressTaggedSigned`, `DecompressTagged`, `DecompressProtected`)。
6. **写屏障:** 实现了垃圾回收的写屏障机制，用于在修改对象引用时通知垃圾回收器 (`RecordWriteField`, `EncodeSandboxedPointer`, `DecodeSandboxedPointer`, `LoadSandboxedPointerField`, `StoreSandboxedPointerField`, `LoadExternalPointerField`, `LoadTrustedPointerField`, `StoreTrustedPointerField`, `LoadIndirectPointerField`, `StoreIndirectPointerField`, `ResolveIndirectPointerHandle`, `ResolveTrustedPointerHandle`, `ResolveCodePointerHandle`, `LoadCodeEntrypointViaCodePointer`, `LoadEntrypointFromJSDispatchTable`, `LoadParameterCountFromJSDispatchTable`, `LoadEntrypointAndParameterCountFromJSDispatchTable`, `LoadProtectedPointerField`, `CallEphemeronKeyBarrier`, `CallIndirectPointerBarrier`, `CallRecordWriteStubSaveRegisters`, `CallRecordWriteStub`, `CallTSANStoreStub`, `CallTSANRelaxedLoadStub`, `RecordWrite`).
7. **断言和检查:** 提供了在代码中进行条件检查和中断的方法 (`Check`, `SbxCheck`, `CheckStackAlignment`).
8. **栈对齐:** 提供了对齐栈指针的方法 (`AlignStackPointer`).
9. **中止执行:** 提供了中止程序执行并报告错误的方法 (`Abort`).
10. **调用运行时函数:** 提供了调用V8 C++运行时函数的方法 (`CallRuntime`, `TailCallRuntime`, `JumpToExternalReference`).
11. **尾调用优化代码:** 提供了尾调用已优化代码的机制 (`GenerateTailCallToReturnedCode`, `ReplaceClosureCodeWithOptimizedCode`).

**与JavaScript功能的联系及JavaScript示例:**

`MacroAssembler` 生成的汇编代码直接对应着JavaScript代码的执行。例如，当我们访问一个对象的属性时，`MacroAssembler` 中的加载字段操作会被使用；当我们调用一个函数时，`MacroAssembler` 中的调用指令会被使用；当发生垃圾回收时，`MacroAssembler` 中实现的写屏障会被触发。

以下是一些概念和 `MacroAssembler` 中功能的对应关系，并用简单的JavaScript例子说明：

**1. 对象属性访问:**

```javascript
const obj = { x: 10 };
const y = obj.x;
```

在底层，V8会生成类似 `LoadTaggedField` 的指令来加载 `obj` 对象的 `x` 属性值到寄存器。

**2. 函数调用:**

```javascript
function add(a, b) {
  return a + b;
}
const sum = add(5, 3);
```

V8会使用 `CallBuiltin` 或类似的指令来调用 `add` 函数对应的机器码。其中涉及到参数的传递（可能用到栈操作 `Push`）和返回值的处理。

**3. 垃圾回收 (写屏障):**

```javascript
const obj1 = { data: {} };
const obj2 = {};
obj1.data = obj2; // 这一步可能触发写屏障
```

当将 `obj2` 赋值给 `obj1.data` 时，如果 `obj1` 在旧生代，而 `obj2` 在新生代，就需要记录这次写操作，这就是 `RecordWriteField` 等写屏障相关功能的作用。

**4. 数字运算:**

```javascript
const a = 5;
const b = 2.5;
const result = a + b;
```

对于数字运算，`MacroAssembler` 会生成相应的算术指令，例如整数加法、浮点数加法等。对于浮点数，会用到 `Cvtlsi2sd` (整数转双精度浮点数) 或类似的浮点数操作指令。

**总结:**

`v8/src/codegen/x64/macro-assembler-x64.cc` 的第1部分是构建V8 JavaScript引擎在x64架构上执行代码的基础。它提供了一组底层的指令生成工具，使得V8可以将高级的JavaScript代码转化为处理器可以理解和执行的机器码。它涵盖了内存访问、数据操作、控制流、垃圾回收支持等关键功能，是 V8 代码生成器的核心组成部分。

### 提示词
```
这是目录为v8/src/codegen/x64/macro-assembler-x64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```
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
      Push(object);  // Use object register as scratch
      Register scratch = object;
      Push(slot_address);  // Use slot address register to load the value into
      Register value_in_slot = slot_address;
      LoadIndirectPointerField(value_in_slot, Operand(slot_address, 0),
                               slot.indirect_pointer_tag(), scratch);
      cmp_tagged(value, value_in_slot);
      // These pops don't affect the flag registers, so we can do them before
      // the conditional jump below.
      Pop(slot_address);
      Pop(object);
    } else {
      cmp_tagged(value, Operand(slot_address, 0));
    }
    j(equal, &ok, Label::kNear);
    int3();
    bind(&ok);
  }

  // First, check if a write barrier is even needed. The tests below
  // catch stores of smis and read-only objects, as well as stores into the
  // young generation.
  Label done;

#if V8_STATIC_ROOTS_BOOL
  if (ro_check == ReadOnlyCheck::kInline) {
    // Quick check for Read-only and small Smi values.
    static_assert(StaticReadOnlyRoot::kLastAllocatedRoot < kRegularPageSize);
    JumpIfUnsignedLessThan(value, kRegularPageSize, &done);
  }
#endif  // V8_STATIC_ROOTS_BOOL

  if (smi_check == SmiCheck::kInline) {
    // Skip barrier if writing a smi.
    JumpIfSmi(value, &done);
  }

  if (slot.contains_indirect_pointer()) {
    // The indirect pointer write barrier is only enabled during marking.
    JumpIfNotMarking(&done);
  } else {
#if V8_ENABLE_STICKY_MARK_BITS_BOOL
    DCHECK(!AreAliased(kScratchRegister, object, slot_address, value));
    Label stub_call;

    JumpIfMarking(&stub_call);

    // Save the slot_address in the xmm scratch register.
    movq(kScratchDoubleReg, slot_address);
    Register scratch0 = slot_address;
    CheckMarkBit(object, kScratchRegister, scratch0, carry, &done);
    CheckPageFlag(value, kScratchRegister, MemoryChunk::kIsInReadOnlyHeapMask,
                  not_zero, &done, Label::kFar);
    CheckMarkBit(value, kScratchRegister, scratch0, carry, &done);
    movq(slot_address, kScratchDoubleReg);
    bind(&stub_call);
#else   // !V8_ENABLE_STICKY_MARK_BITS_BOOL
    CheckPageFlag(value,
                  value,  // Used as scratch.
                  MemoryChunk::kPointersToHereAreInterestingMask, zero, &done,
                  Label::kNear);

    CheckPageFlag(object,
                  value,  // Used as scratch.
                  MemoryChunk::kPointersFromHereAreInterestingMask, zero, &done,
                  Label::kNear);
#endif  // !V8_ENABLE_STICKY_MARK_BITS_BOOL
  }

  if (slot.contains_direct_pointer()) {
    CallRecordWriteStub(object, slot_address, fp_mode,
                        StubCallMode::kCallBuiltinPointer);
  } else {
    DCHECK(slot.contains_indirect_pointer());
    CallIndirectPointerBarrier(object, slot_address, fp_mode,
                               slot.indirect_pointer_tag());
  }

  bind(&done);

  // Clobber clobbered registers when running with the debug-code flag
  // turned on to provoke errors.
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT_STRING(this, "Zap scratch registers");
    Move(slot_address, kZapValue, RelocInfo::NO_INFO);
    Move(value, kZapValue, RelocInfo::NO_INFO);
  }
}

void MacroAssembler::Check(Condition cc, AbortReason reason) {
  Label L;
  j(cc, &L, Label::kNear);
  Abort(reason);
  // Control will not return here.
  bind(&L);
}

void MacroAssembler::SbxCheck(Condition cc, AbortReason reason) {
  Check(cc, reason);
}

void MacroAssembler::CheckStackAlignment() {
  int frame_alignment = base::OS::ActivationFrameAlignment();
  int frame_alignment_mask = frame_alignment - 1;
  if (frame_alignment > kSystemPointerSize) {
    ASM_CODE_COMMENT(this);
    DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
    Label alignment_as_expected;
    testq(rsp, Immediate(frame_alignment_mask));
    j(zero, &alignment_as_expected, Label::kNear);
    // Abort if stack is not aligned.
    int3();
    bind(&alignment_as_expected);
  }
}

void MacroAssembler::AlignStackPointer() {
  const int kFrameAlignment = base::OS::ActivationFrameAlignment();
  if (kFrameAlignment > 0) {
    DCHECK(base::bits::IsPowerOfTwo(kFrameAlignment));
    DCHECK(is_int8(kFrameAlignment));
    andq(rsp, Immediate(-kFrameAlignment));
  }
}

void MacroAssembler::Abort(AbortReason reason) {
  ASM_CODE_COMMENT(this);
  if (v8_flags.code_comments) {
    const char* msg = GetAbortReason(reason);
    RecordComment("Abort message: ");
    RecordComment(msg);
  }

  // Avoid emitting call to builtin if requested.
  if (trap_on_abort()) {
    int3();
    return;
  }

  if (should_abort_hard()) {
    // We don't care if we constructed a frame. Just pretend we did.
    FrameScope assume_frame(this, StackFrame::NO_FRAME_TYPE);
    Move(kCArgRegs[0], static_cast<int>(reason));
    PrepareCallCFunction(1);
    LoadAddress(rax, ExternalReference::abort_with_reason());
    call(rax);
    return;
  }

  Move(rdx, Smi::FromInt(static_cast<int>(reason)));

  {
    // We don't actually want to generate a pile of code for this, so just
    // claim there is a stack frame, without generating one.
    FrameScope scope(this, StackFrame::NO_FRAME_TYPE);
    if (root_array_available()) {
      // Generate an indirect call via builtins entry table here in order to
      // ensure that the interpreter_entry_return_pc_offset is the same for
      // InterpreterEntryTrampoline and InterpreterEntryTrampolineForProfiling
      // when v8_flags.debug_code is enabled.
      Call(EntryFromBuiltinAsOperand(Builtin::kAbort));
    } else {
      CallBuiltin(Builtin::kAbort);
    }
  }

  // Control will not return here.
  int3();
}

void MacroAssembler::CallRuntime(const Runtime::Function* f,
                                 int num_arguments) {
  ASM_CODE_COMMENT(this);
  // If the expected number of arguments of the runtime function is
  // constant, we check that the actual number of arguments match the
  // expectation.
  CHECK(f->nargs < 0 || f->nargs == num_arguments);

  // TODO(1236192): Most runtime routines don't need the number of
  // arguments passed in because it is constant. At some point we
  // should remove this need and make the runtime routine entry code
  // smarter.
  Move(rax, num_arguments);
  LoadAddress(rbx, ExternalReference::Create(f));

  bool switch_to_central = options().is_wasm;
  CallBuiltin(Builtins::RuntimeCEntry(f->result_size, switch_to_central));
}

void MacroAssembler::TailCallRuntime(Runtime::FunctionId fid) {
  // ----------- S t a t e -------------
  //  -- rsp[0]                 : return address
  //  -- rsp[8]                 : argument num_arguments - 1
  //  ...
  //  -- rsp[8 * num_arguments] : argument 0 (receiver)
  //
  //  For runtime functions with variable arguments:
  //  -- rax                    : number of  arguments
  // -----------------------------------
  ASM_CODE_COMMENT(this);
  const Runtime::Function* function = Runtime::FunctionForId(fid);
  DCHECK_EQ(1, function->result_size);
  if (function->nargs >= 0) {
    Move(rax, function->nargs);
  }
  JumpToExternalReference(ExternalReference::Create(fid));
}

void MacroAssembler::JumpToExternalReference(const ExternalReference& ext,
                                             bool builtin_exit_frame) {
  ASM_CODE_COMMENT(this);
  // Set the entry point and jump to the C entry runtime stub.
  LoadAddress(rbx, ext);
  TailCallBuiltin(Builtins::CEntry(1, ArgvMode::kStack, builtin_exit_frame));
}

namespace {

#ifndef V8_ENABLE_LEAPTIERING
// Only used when leaptiering is disabled.
void TailCallOptimizedCodeSlot(MacroAssembler* masm,
                               Register optimized_code_entry, Register closure,
                               Register scratch1, Register scratch2,
                               JumpMode jump_mode) {
  // ----------- S t a t e -------------
  //  rax : actual argument count
  //  rdx : new target (preserved for callee if needed, and caller)
  //  rsi : current context, used for the runtime call
  //  rdi : target function (preserved for callee if needed, and caller)
  // -----------------------------------
  ASM_CODE_COMMENT(masm);
  DCHECK_EQ(closure, kJSFunctionRegister);
  DCHECK(!AreAliased(rax, rdx, closure, rsi, optimized_code_entry, scratch1,
                     scratch2));

  Label heal_optimized_code_slot;

  // If the optimized code is cleared, go to runtime to update the optimization
  // marker field.
  __ LoadWeakValue(optimized_code_entry, &heal_optimized_code_slot);

  // The entry references a CodeWrapper object. Unwrap it now.
  __ LoadCodePointerField(
      optimized_code_entry,
      FieldOperand(optimized_code_entry, CodeWrapper::kCodeOffset), scratch1);

  // Check if the optimized code is marked for deopt. If it is, call the
  // runtime to clear it.
  __ AssertCode(optimized_code_entry);
  __ TestCodeIsMarkedForDeoptimization(optimized_code_entry);
  __ j(not_zero, &heal_optimized_code_slot);

  // Optimized code is good, get it into the closure and link the closure into
  // the optimized functions list, then tail call the optimized code.
  __ ReplaceClosureCodeWithOptimizedCode(optimized_code_entry, closure,
                                         scratch1, scratch2);
  static_assert(kJavaScriptCallCodeStartRegister == rcx, "ABI mismatch");
  __ Move(rcx, optimized_code_entry);
  __ JumpCodeObject(rcx, kJSEntrypointTag, jump_mode);

  // Optimized code slot contains deoptimized code or code is cleared and
  // optimized code marker isn't updated. Evict the code, update the marker
  // and re-enter the closure's code.
  __ bind(&heal_optimized_code_slot);
  __ GenerateTailCallToReturnedCode(Runtime::kHealOptimizedCodeSlot, jump_mode);
}
#endif  // V8_ENABLE_LEAPTIERING

}  // namespace

#ifdef V8_ENABLE_DEBUG_CODE
void MacroAssembler::AssertFeedbackCell(Register object, Register scratch) {
  if (v8_flags.debug_code) {
    IsObjectType(object, FEEDBACK_CELL_TYPE, scratch);
    Assert(equal, AbortReason::kExpectedFeedbackCell);
  }
}
void MacroAssembler::AssertFeedbackVector(Register object, Register scratch) {
  if (v8_flags.debug_code) {
    IsObjectType(object, FEEDBACK_VECTOR_TYPE, scratch);
    Assert(equal, AbortReason::kExpectedFeedbackVector);
  }
}
#endif  // V8_ENABLE_DEBUG_CODE

void MacroAssembler::GenerateTailCallToReturnedCode(
    Runtime::FunctionId function_id, JumpMode jump_mode) {
  // ----------- S t a t e -------------
  //  -- rax : actual argument count (preserved for callee)
  //  -- rdx : new target (preserved for callee)
  //  -- rdi : target function (preserved for callee)
  //  -- r15 : dispatch handle (preserved for callee)
  // -----------------------------------
  ASM_CODE_COMMENT(this);
  {
    FrameScope scope(this, StackFrame::INTERNAL);
    // Push a copy of the target function, the new target, the actual argument
    // count, and the dispatch handle.
    Push(kJavaScriptCallTargetRegister);
    Push(kJavaScriptCallNewTargetRegister);
    SmiTag(kJavaScriptCallArgCountRegister);
    Push(kJavaScriptCallArgCountRegister);
#ifdef V8_ENABLE_LEAPTIERING
    // No need to SmiTag since dispatch handles always look like Smis.
    static_assert(kJSDispatchHandleShift > 0);
    Push(kJavaScriptCallDispatchHandleRegister);
#endif
    // Function is also the parameter to the runtime call.
    Push(kJavaScriptCallTargetRegister);

    CallRuntime(function_id, 1);
    movq(rcx, rax);

    // Restore target function, new target, actual argument count, and dispatch
    // handle.
#ifdef V8_ENABLE_LEAPTIERING
    Pop(kJavaScriptCallDispatchHandleRegister);
#endif
    Pop(kJavaScriptCallArgCountRegister);
    SmiUntagUnsigned(kJavaScriptCallArgCountRegister);
    Pop(kJavaScriptCallNewTargetRegister);
    Pop(kJavaScriptCallTargetRegister);
  }
  static_assert(kJavaScriptCallCodeStartRegister == rcx, "ABI mismatch");
  JumpCodeObject(rcx, kJSEntrypointTag, jump_mode);
}

void MacroAssembler::ReplaceClosureCodeWithOptimizedCode(
    Register optimized_code, Register closure, Register scratch1,
    Register slot_address) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(optimized_code, closure, scratch1, slot_address));
  DCHECK_EQ(closure, kJSFunctionRegister);

#ifdef V8_ENABLE_LEAPTIERING
  UNREACHABLE();
#else
  // Store the optimized code in the closure.
  AssertCode(optimized_code);
  StoreCodePointerField(FieldOperand(closure, JSFunction::kCodeOffset),
                        optimized_code);

  // Write barrier clobbers scratch1 below.
  Register value = scratch1;
  movq(value, optimized_code);

  RecordWriteField(closure, JSFunction::kCodeOffset, value, slot_address,
                   SaveFPRegsMode::kIgnore, SmiCheck::kOmit,
                   ReadOnlyCheck::kOmit, SlotDescriptor::ForCodePointerSlot());
#endif  // V8_ENABLE_LEAPTIERING
}

#ifndef V8_ENABLE_LEAPTIERING

// Read off the flags in the feedback vector and check if there
// is optimized code or a tiering state that needs to be processed.
Condition MacroAssembler::CheckFeedbackVectorFlagsNeedsProcessing(
    Register feedback_vector, CodeKind current_code_kind) {
  ASM_CODE_COMMENT(this);
  DCHECK(CodeKindCanTierUp(current_code_kind));
  uint32_t flag_mask =
      FeedbackVector::FlagMaskForNeedsProcessingCheckFrom(current_code_kind);
  testw(FieldOperand(feedback_vector, FeedbackVector::kFlagsOffset),
        Immediate(flag_mask));
  return not_zero;
}

void MacroAssembler::CheckFeedbackVectorFlagsAndJumpIfNeedsProcessing(
    Register feedback_vector, CodeKind current_code_kind,
    Label* flags_need_processing) {
  ASM_CODE_COMMENT(this);
  j(CheckFeedbackVectorFlagsNeedsProcessing(feedback_vector, current_code_kind),
    flags_need_processing);
}

void MacroAssembler::OptimizeCodeOrTailCallOptimizedCodeSlot(
    Register feedback_vector, Register closure, JumpMode jump_mode) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(feedback_vector, closure));

  Label maybe_has_optimized_code, maybe_needs_logging;
  // Check if optimized code is available.
  testw(FieldOperand(feedback_vector, FeedbackVector::kFlagsOffset),
        Immediate(FeedbackVector::kFlagsTieringStateIsAnyRequested));
  j(zero, &maybe_needs_logging);

  GenerateTailCallToReturnedCode(Runtime::kCompileOptimized, jump_mode);

  bind(&maybe_needs_logging);
  testw(FieldOperand(feedback_vector, FeedbackVector::kFlagsOffset),
        Immediate(FeedbackVector::LogNextExecutionBit::kMask));
  j(zero, &maybe_has_optimized_code);
  GenerateTailCallToReturnedCode(Runtime::kFunctionLogNextExecution, jump_mode);

  bind(&maybe_has_optimized_code);
  Register optimized_code_entry = kJavaScriptCallCodeStartRegister;
  LoadTaggedField(
      optimized_code_entry,
      FieldOperand(feedback_vector, FeedbackVector::kMaybeOptimizedCodeOffset));
  TailCallOptimizedCodeSlot(this, optimized_code_entry, closure, r9,
                            WriteBarrierDescriptor::SlotAddressRegister(),
                            jump_mode);
}

#endif  // !V8_ENABLE_LEAPTIERING

int MacroAssembler::RequiredStackSizeForCallerSaved(SaveFPRegsMode fp_mode,
                                                    Register exclusion) const {
  int bytes = 0;
  RegList saved_regs = kCallerSaved - exclusion;
  bytes += kSystemPointerSize * saved_regs.Count();

  // R12 to r15 are callee save on all platforms.
  if (fp_mode == SaveFPRegsMode::kSave) {
    bytes += kStackSavedSavedFPSize * kAllocatableDoubleRegisters.Count();
  }

  return bytes;
}

int MacroAssembler::PushCallerSaved(SaveFPRegsMode fp_mode,
                                    Register exclusion) {
  ASM_CODE_COMMENT(this);
  int bytes = 0;
  bytes += PushAll(kCallerSaved - exclusion);
  if (fp_mode == SaveFPRegsMode::kSave) {
    bytes += PushAll(kAllocatableDoubleRegisters);
  }

  return bytes;
}

int MacroAssembler::PopCallerSaved(SaveFPRegsMode fp_mode, Register exclusion) {
  ASM_CODE_COMMENT(this);
  int bytes = 0;
  if (fp_mode == SaveFPRegsMode::kSave) {
    bytes += PopAll(kAllocatableDoubleRegisters);
  }
  bytes += PopAll(kCallerSaved - exclusion);

  return bytes;
}

int MacroAssembler::PushAll(RegList registers) {
  int bytes = 0;
  for (Register reg : registers) {
    pushq(reg);
    bytes += kSystemPointerSize;
  }
  return bytes;
}

int MacroAssembler::PopAll(RegList registers) {
  int bytes = 0;
  for (Register reg : base::Reversed(registers)) {
    popq(reg);
    bytes += kSystemPointerSize;
  }
  return bytes;
}

int MacroAssembler::PushAll(DoubleRegList registers, int stack_slot_size) {
  if (registers.is_empty()) return 0;
  const int delta = stack_slot_size * registers.Count();
  AllocateStackSpace(delta);
  int slot = 0;
  for (XMMRegister reg : registers) {
    if (stack_slot_size == kDoubleSize) {
      Movsd(Operand(rsp, slot), reg);
    } else {
      DCHECK_EQ(stack_slot_size, 2 * kDoubleSize);
      Movdqu(Operand(rsp, slot), reg);
    }
    slot += stack_slot_size;
  }
  DCHECK_EQ(slot, delta);
  return delta;
}

int MacroAssembler::PopAll(DoubleRegList registers, int stack_slot_size) {
  if (registers.is_empty()) return 0;
  int slot = 0;
  for (XMMRegister reg : registers) {
    if (stack_slot_size == kDoubleSize) {
      Movsd(reg, Operand(rsp, slot));
    } else {
      DCHECK_EQ(stack_slot_size, 2 * kDoubleSize);
      Movdqu(reg, Operand(rsp, slot));
    }
    slot += stack_slot_size;
  }
  DCHECK_EQ(slot, stack_slot_size * registers.Count());
  addq(rsp, Immediate(slot));
  return slot;
}

void MacroAssembler::Movq(XMMRegister dst, Register src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    vmovq(dst, src);
  } else {
    movq(dst, src);
  }
}

void MacroAssembler::Movq(Register dst, XMMRegister src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    vmovq(dst, src);
  } else {
    movq(dst, src);
  }
}

void MacroAssembler::Pextrq(Register dst, XMMRegister src, int8_t imm8) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    vpextrq(dst, src, imm8);
  } else {
    CpuFeatureScope sse_scope(this, SSE4_1);
    pextrq(dst, src, imm8);
  }
}

void MacroAssembler::Cvtss2sd(XMMRegister dst, XMMRegister src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvtss2sd(dst, src, src);
  } else {
    cvtss2sd(dst, src);
  }
}

void MacroAssembler::Cvtss2sd(XMMRegister dst, Operand src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvtss2sd(dst, dst, src);
  } else {
    cvtss2sd(dst, src);
  }
}

void MacroAssembler::Cvtsd2ss(XMMRegister dst, XMMRegister src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvtsd2ss(dst, src, src);
  } else {
    cvtsd2ss(dst, src);
  }
}

void MacroAssembler::Cvtsd2ss(XMMRegister dst, Operand src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvtsd2ss(dst, dst, src);
  } else {
    cvtsd2ss(dst, src);
  }
}

void MacroAssembler::Cvtlsi2sd(XMMRegister dst, Register src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvtlsi2sd(dst, kScratchDoubleReg, src);
  } else {
    xorpd(dst, dst);
    cvtlsi2sd(dst, src);
  }
}

void MacroAssembler::Cvtlsi2sd(XMMRegister dst, Operand src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvtlsi2sd(dst, kScratchDoubleReg, src);
  } else {
    xorpd(dst, dst);
    cvtlsi2sd(dst, src);
  }
}

void MacroAssembler::Cvtlsi2ss(XMMRegister dst, Register src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvtlsi2ss(dst, kScratchDoubleReg, src);
  } else {
    xorps(dst, dst);
    cvtlsi2ss(dst, src);
  }
}

void MacroAssembler::Cvtlsi2ss(XMMRegister dst, Operand src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvtlsi2ss(dst, kScratchDoubleReg, src);
  } else {
    xorps(dst, dst);
    cvtlsi2ss(dst, src);
  }
}

void MacroAssembler::Cvtqsi2ss(XMMRegister dst, Register src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvtqsi2ss(dst, kScratchDoubleReg, src);
  } else {
    xorps(dst, dst);
    cvtqsi2ss(dst, src);
  }
}

void MacroAssembler::Cvtqsi2ss(XMMRegister dst, Operand src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvtqsi2ss(dst, kScratchDoubleReg, src);
  } else {
    xorps(dst, dst);
    cvtqsi2ss(dst, src);
  }
}

void MacroAssembler::Cvtqsi2sd(XMMRegister dst, Register src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvtqsi2sd(dst, kScratchDoubleReg, src);
  } else {
    xorpd(dst, dst);
    cvtqsi2sd(dst, src);
  }
}

void MacroAssembler::Cvtqsi2sd(XMMRegister dst, Operand src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvtqsi2sd(dst, kScratchDoubleReg, src);
  } else {
    xorpd(dst, dst);
    cvtqsi2sd(dst, src);
  }
}

void MacroAssembler::Cvtlui2ss(XMMRegister dst, Register src) {
  // Zero-extend the 32 bit value to 64 bit.
  movl(kScratchRegister, src);
  Cvtqsi2ss(dst, kScratchRegister);
}

void MacroAssembler::Cvtlui2ss(XMMRegister dst, Operand src) {
  // Zero-extend the 32 bit value to 64 bit.
  movl(kScratchRegister, src);
  Cvtqsi2ss(dst, kScratchRegister);
}

void MacroAssembler::Cvtlui2sd(XMMRegister dst, Register src) {
  // Zero-extend the 32 bit value to 64 bit.
  movl(kScratchRegister, src);
  Cvtqsi2sd(dst, kScratchRegister);
}

void MacroAssembler::Cvtlui2sd(XMMRegister dst, Operand src) {
  // Zero-extend the 32 bit value to 64 bit.
  movl(kScratchRegister, src);
  Cvtqsi2sd(dst, kScratchRegister);
}

void MacroAssembler::Cvtqui2ss(XMMRegister dst, Register src) {
  Label done;
  Cvtqsi2ss(dst, src);
  testq(src, src);
  j(positive, &done, Label::kNear);

  // Compute {src/2 | (src&1)} (retain the LSB to avoid rounding errors).
  if (src != kScratchRegister) movq(kScratchRegister, src);
  shrq(kScratchRegister, Immediate(1));
  // The LSB is shifted into CF. If it is set, set the LSB in {tmp}.
  Label msb_not_set;
  j(not_carry, &msb_not_set, Label::kNear);
  orq(kScratchRegister, Immediate(1));
  bind(&msb_not_set);
  Cvtqsi2ss(dst, kScratchRegister);
  Addss(dst, dst);
  bind(&done);
}

void MacroAssembler::Cvtqui2ss(XMMRegister dst, Operand src) {
  movq(kScratchRegister, src);
  Cvtqui2ss(dst, kScratchRegister);
}

void MacroAssembler::Cvtqui2sd(XMMRegister dst, Register src) {
  Label done;
  Cvtqsi2sd(dst, src);
  testq(src, src);
  j(positive, &done, Label::kNear);

  // Compute {src/2 | (src&1)} (retain the LSB to avoid rounding errors).
  if (src != kScratchRegister) movq(kScratchRegister, src);
  shrq(kScratchRegister, Immediate(1));
  // The LSB is shifted into CF. If it is set, set the LSB in {tmp}.
  Label msb_not_set;
  j(not_carry, &msb_not_set, Label::kNear);
  orq(kScratchRegister, Immediate(1));
  bind(&msb_not_set);
  Cvtqsi2sd(dst, kScratchRegister);
  Addsd(dst, dst);
  bind(&done);
}

void MacroAssembler::Cvtqui2sd(XMMRegister dst, Operand src) {
  movq(kScratchRegister, src);
  Cvtqui2sd(dst, kScratchRegister);
}

void MacroAssembler::Cvttss2si(Register dst, XMMRegister src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvttss2si(dst, src);
  } else {
    cvttss2si(dst, src);
  }
}

void MacroAssembler::Cvttss2si(Register dst, Operand src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvttss2si(dst, src);
  } else {
    cvttss2si(dst, src);
  }
}

void MacroAssembler::Cvttsd2si(Register dst, XMMRegister src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvttsd2si(dst, src);
  } else {
    cvttsd2si(dst, src);
  }
}

void MacroAssembler::Cvttsd2si(Register dst, Operand src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvttsd2si(dst, src);
  } else {
    cvttsd2si(dst, src);
  }
}

void MacroAssembler::Cvttss2siq(Register dst, XMMRegister src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvttss2siq(dst, src);
  } else {
    cvttss2siq(dst, src);
  }
}

void MacroAssembler::Cvttss2siq(Register dst, Operand src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvttss2siq(dst, src);
  } else {
    cvttss2siq(dst, src);
  }
}

void MacroAssembler::Cvttsd2siq(Register dst, XMMRegister src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvttsd2siq(dst, src);
  } else {
    cvttsd2siq(dst, src);
  }
}

void MacroAssembler::Cvttsd2siq(Register dst, Operand src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvttsd2siq(dst, src);
  } else {
    cvttsd2siq(dst, src);
  }
}

void MacroAssembler::Cvtpd2ph(XMMRegister dst, XMMRegister src, Register tmp) {
  ASM_CODE_COMMENT(this);
  CpuFeatureScope f16c_scope(this, F16C);
  CpuFeatureScope avx_scope(this, AVX);
  Register tmp2 = kScratchRegister;
  DCHECK_NE(tmp, tmp2);
  DCHECK_NE(dst, src);

  // Conversion algo from
  // https://github.com/tc39/proposal-float16array/issues/12#issuecomment-2256642971
  Label f32tof16;
  // Convert Float64 -> Float32.
  Cvtsd2ss(dst, src);
  vmovd(tmp, dst);
  // Mask off sign bit.
  andl(tmp, Immediate(kFP32WithoutSignMask));
  // Underflow to zero.
  cmpl(tmp, Immediate(kFP32MinFP16ZeroRepresentable));
  j(below, &f32tof16);
  // Overflow to infinity.
  cmpl(tmp, Immediate(kFP32MaxFP16Representable));
  j(above_equal, &f32tof16);
  // Detection of subnormal numbers.
  cmpl(tmp, Immediate(kFP32SubnormalThresholdOfFP16));
  setcc(above_equal, tmp2);
  movzxbl(tmp2, tmp2);
  // Compute 0x1000 for normal and 0x0000 for denormal numbers.
  shll(tmp2, Immediate(12));
  // Look at the last thirteen bits of the mantissa which will be shifted out
  // when converting from float32 to float16. (The round and sticky bits.)
  // Normal numbers: If the round bit is set and sticky bits are zero, then
  // adjust the float32 mantissa.
  // Denormal numbers: If all bits are zero, then adjust the mantissa.
  andl(tmp, Immediate(0x1fff));
  // Check round and sticky bits.
  cmpl(tmp, tmp2);
  j(not_equal, &f32tof16);

  // Adjust mantissa by -1/0/+1.
  Move(kScratchDoubleReg, static_cast<uint32_t>(1));
  psignd(kScratchDoubleReg, src);
  paddd(dst, kScratchDoubleReg);

  bind(&f32tof16);
  // Convert Float32 -> Float16.
  vcvtps2ph(dst, dst, 4);
}

namespace {
template <typename OperandOrXMMRegister, bool is_double>
void ConvertFloatToUint64(MacroAssembler* masm, Register dst,
                          OperandOrXMMRegister src, Label* fail) {
  Label success;
  // There does not exist a native float-to-uint instruction, so we have to use
  // a float-to-int, and postprocess the result.
  if (is_double) {
    masm->Cvttsd2siq(dst, src);
  } else {
    masm->Cvttss2siq(dst, src);
  }
  // If the result of the conversion is positive, we are already done.
  masm->testq(dst, dst);
  masm->j(positive, &success);
  // The result of the first conversion was negative, which means that the
  // input value was not within the positive int64 range. We subtract 2^63
  // and convert it again to see if it is within the uint64 range.
  if (is_double) {
    masm->Move(kScratchDoubleReg, -9223372036854775808.0);
    masm->Addsd(kScratchDoubleReg, src);
    masm->Cvttsd2siq(dst, kScratchDoubleReg);
  } else {
    masm->Move(kScratchDoubleReg, -9223372036854775808.0f);
    masm->Addss(kScratchDoubleReg, src);
    masm->Cvttss2siq(dst, kScratchDoubleReg);
  }
  masm->testq(dst, dst);
  // The only possible negative value here is 0x8000000000000000, which is
  // used on x64 to indicate an integer overflow.
  masm->j(negative, fail ? fail : &success);
  // The input value is within uint64 range and the second conversion worked
  // successfully, but we still have to undo the subtraction we did
  // earlier.
  masm->Move(kScratchRegister, 0x8000000000000000);
  masm->orq(dst, kScratchRegister);
  masm->bind(&success);
}

template <typename OperandOrXMMRegister, bool is_double>
void ConvertFloatToUint32(MacroAssembler* masm, Register dst,
                          OperandOrXMMRegister src, Label* fail) {
  Label success;
  // There does not exist a native float-to-uint instruction, so we have to use
  // a float-to-int, and postprocess the result.
  if (is_double) {
    masm->Cvttsd2si(dst, src);
  } else {
    masm->Cvttss2si(dst, src);
  }
  // If the result of the conversion is positive, we are already done.
  masm->testl(dst, dst);
  masm->j(positive, &success);
  // The result of the first conversion was negative, which means that the
  // input value was not within the positive int32 range. We subtract 2^31
  // and convert it again to see if it is within the uint32 range.
  if (is_double) {
    masm->Move(kScratchDoubleReg, -2147483648.0);
    masm->Addsd(kScratchDoubleReg, src);
    masm->Cvttsd2si(dst, kScratchDoubleReg);
  } else {
    masm->Move(kScratchDoubleReg, -2147483648.0f);
    masm->Addss(kScratchDoubleReg, src);
    masm->Cvttss2si(dst, kScratchDoubleReg);
  }
  masm->testl(dst, dst);
  // The only possible negative value here is 0x80000000, which is
  // used on x64 to indicate an integer overflow.
  masm->j(negative, fail ? fail : &success);
  // The input value is within uint32 range and the second conversion worked
  // successfully, but we still have to undo the subtraction we did
  // earlier.
  masm->Move(kScratchRegister, 0x80000000);
  masm->orl(dst, kScratchRegister);
  masm->bind(&success);
}
}  // namespace

void MacroAssembler::Cvttsd2uiq(Register dst, Operand src, Label* fail) {
  ConvertFloatToUint64<Operand, true>(this, dst, src, fail);
}

void MacroAssembler::Cvttsd2uiq(Register dst, XMMRegister src, Label* fail) {
  ConvertFloatToUint64<XMMRegister, true>(this, dst, src, fail);
}

void MacroAssembler::Cvttsd2ui(Register dst, Operand src, Label* fail) {
  ConvertFloatToUint32<Operand, true>(this, dst, src, fail);
}

void MacroAssembler::Cvttsd2ui(Register dst, XMMRegister src, Label* fail) {
  ConvertFloatToUint32<XMMRegister, true>(this, dst, src, fail);
}

void MacroAssembler::Cvttss2uiq(Register dst, Operand src, Label* fail) {
  ConvertFloatToUint64<Operand, false>(this, dst, src, fail);
}

void MacroAssembler::Cvttss2uiq(Register dst, XMMRegister src, Label* fail) {
  ConvertFloatToUint64<XMMRegister, false>(this, dst, src, fail);
}

void MacroAssembler::Cvttss2ui(Register dst, Operand src, Label* fail) {
  ConvertFloatToUint32<Operand, false>(this, dst, src, fail);
}

void MacroAssembler::Cvttss2ui(Register dst, XMMRegister src, Label* fail) {
  ConvertFloatToUint32<XMMRegister, false>(this, dst, src, fail);
}

void MacroAssembler::Cmpeqss(XMMRegister dst, XMMRegister src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    vcmpeqss(dst, src);
  } else {
    cmpeqss(dst, src);
  }
}

void MacroAssembler::Cmpeqsd(XMMRegister dst, XMMRegister src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    vcmpeqsd(dst, src);
  } else {
    cmpeqsd(dst, src);
  }
}

void MacroAssembler::S256Not(YMMRegister dst, YMMRegister src,
                             YMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  CpuFeatureScope avx2_scope(this, AVX2);
  if (dst == src) {
    vpcmpeqd(scratch, scratch, scratch);
    vpxor(dst, dst, scratch);
  } else {
    vpcmpeqd(dst, dst, dst);
    vpxor(dst, dst, src);
  }
}

void MacroAssembler::S256Select(YMMRegister dst, YMMRegister mask,
                                YMMRegister src1, YMMRegister src2,
                                YMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  CpuFeatureScope avx2_scope(this, AVX2);
  // v256.select = v256.or(v256.and(v1, c), v256.andnot(v2, c)).
  // pandn(x, y) = !x & y, so we have to flip the mask and input.
  vpandn(scratch, mask, src2);
  vpand(dst, src1, mask);
  vpor(dst, dst, scratch);
}

// ----------------------------------------------------------------------------
// Smi tagging, untagging and tag detection.

Register MacroAssembler::GetSmiConstant(Tagged<Smi> source) {
  Move(kScratchRegister, source);
  return kScratchRegister;
}

void MacroAssembler::Cmp(Register dst, int32_t src) {
  if (src == 0) {
    testl(dst, dst);
  } else {
    cmpl(dst, Immediate(src));
  }
}

void MacroAssembler::I64x4Mul(YMMRegister dst, YMMRegister lhs, YMMRegister rhs,
                              YMMRegister tmp1, YMMRegister tmp2) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(dst, tmp1, tmp2));
  DCHECK(!AreAliased(lhs, tmp1, tmp2));
  DCHECK(!AreAliased(rhs, tmp1, tmp2));
  DCHECK(CpuFeatures::IsSupported(AVX2));
  CpuFeatureScope avx_scope(this, AVX2);
  // 1. Multiply high dword of each qword of left with right.
  vpsrlq(t
```