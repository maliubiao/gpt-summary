Response: The user wants to understand the functionality of the C++ source code file `v8/src/maglev/x64/maglev-assembler-x64.cc`. I need to:

1. **Summarize the core functionalities** provided by this file. This likely involves low-level operations on the x64 architecture.
2. **Explain its relation to JavaScript**. This likely involves how these low-level operations support the execution of JavaScript code within the V8 engine.
3. **Provide illustrative JavaScript examples**. These examples should demonstrate scenarios where the functionalities described in the C++ code are used under the hood.

Based on the file name and the included headers, this file seems to be part of the Maglev compiler in V8, specifically for the x64 architecture. It likely provides assembler-level functionalities to generate machine code for Maglev's intermediate representation.

Key functionalities I expect to find are related to:

* **Memory allocation**:  `AllocateRaw`, `Allocate`.
* **String manipulation**: `LoadSingleCharacterString`, `StringFromCharCode`, `StringCharCodeOrCodePointAt`.
* **Type conversion**: `TruncateDoubleToInt32`, `TryTruncateDoubleToInt32`, `TryTruncateDoubleToUint32`, `TryChangeFloat64ToIndex`.
* **Function prologue/epilogue**: `OSRPrologue`, `Prologue`.
* **Deoptimization handling**: `MaybeEmitDeoptBuiltinsCall`.

The connection to JavaScript lies in how these low-level operations implement JavaScript language features. For instance, allocating memory is crucial for creating JavaScript objects and strings. String manipulation functions directly support JavaScript's string operations. Type conversions are necessary for handling different data types in JavaScript. Prologue and epilogue manage the call stack for JavaScript function calls. Deoptimization is a mechanism to fall back to the interpreter when optimized code encounters unexpected conditions.
这个C++源代码文件 `v8/src/maglev/x64/maglev-assembler-x64.cc` 是V8 JavaScript 引擎中 **Maglev 编译器** 的一部分，专门针对 **x64 架构**。它的主要功能是提供了一系列 **汇编器 (assembler)** 的方法，用于生成 **x64 架构的机器码**。这些方法封装了底层的 x64 指令，使得 Maglev 编译器可以将它的中间表示 (Maglev IR) 转换成可以在 x64 处理器上执行的本地代码。

**主要功能归纳如下:**

1. **内存分配 (`Allocate`)**: 提供了在堆上分配内存的方法，用于创建 JavaScript 对象和字符串。它考虑了不同的分配类型 (例如，新生代或老生代) 和对齐方式。
2. **字符串操作**:
   - **加载单字符字符串 (`LoadSingleCharacterString`)**: 从预先创建的单字符字符串表中加载对应的字符串对象。
   - **从字符码创建字符串 (`StringFromCharCode`)**: 根据给定的字符码创建 JavaScript 字符串。它优化了单字节字符码的情况，直接从字符码表加载，而对于双字节字符码则会分配新的双字节字符串。
   - **获取字符串的字符码或码点 (`StringCharCodeOrCodePointAt`)**:  实现了 `String.prototype.charCodeAt()` 和 `String.prototype.codePointAt()` 的部分功能，用于获取字符串指定位置的字符码或 Unicode 码点。它考虑了不同类型的字符串 (例如，SeqString, ConsString, SlicedString, ThinString) 的内部表示。
3. **类型转换**:
   - **截断 Double 到 Int32 (`TruncateDoubleToInt32`)**: 将双精度浮点数截断为 32 位整数。它处理了溢出的情况，如果直接截断导致溢出，则会调用运行时函数进行处理。
   - **尝试截断 Double 到 Int32/Uint32 (`TryTruncateDoubleToInt32`, `TryTruncateDoubleToUint32`)**: 尝试将双精度浮点数安全地截断为 32 位有符号或无符号整数，如果截断会丢失精度或超出范围则跳转到指定的失败标签。
   - **尝试转换 Float64 到 Index (`TryChangeFloat64ToIndex`)**: 尝试将双精度浮点数转换为有效的数组索引，如果转换不安全则跳转到失败标签。
4. **函数序言和尾声 (`OSRPrologue`, `Prologue`)**:  生成函数调用的序言代码，包括创建栈帧、保存寄存器、初始化栈槽等。`OSRPrologue` 用于 On-Stack Replacement (OSR) 时的特殊序言。
5. **去优化处理 (`MaybeEmitDeoptBuiltinsCall`)**:  为可能的去优化 (deoptimization) 调用生成代码，当优化的代码执行遇到无法处理的情况时，会跳转到解释器执行。

**与 JavaScript 功能的关系和 JavaScript 示例:**

这个文件中的功能是 V8 引擎执行 JavaScript 代码的基础。许多 JavaScript 的内置操作和语言特性都依赖于这些底层的汇编器方法。

**1. 内存分配:**

当你在 JavaScript 中创建一个新的对象或数组时，V8 引擎内部会调用类似的内存分配机制。

```javascript
const obj = {}; // 创建一个空对象
const arr = [1, 2, 3]; // 创建一个数组
const str = "hello"; // 创建一个字符串
```

在执行这些代码时，Maglev 编译器 (如果启用) 可能会使用 `MaglevAssembler::Allocate` 来分配存储这些对象、数组和字符串的内存。

**2. 字符串操作:**

JavaScript 中对字符串的操作，如获取字符码或根据字符码创建字符串，会间接使用这些汇编器方法。

```javascript
const str = "A";
const charCode = str.charCodeAt(0); // 获取字符 'A' 的字符码 (65)

const newStr = String.fromCharCode(66); // 根据字符码 66 创建字符串 "B"
```

当执行 `charCodeAt(0)` 时，Maglev 编译后的代码可能会使用 `MaglevAssembler::StringCharCodeOrCodePointAt` 来高效地获取字符码。同样，`String.fromCharCode()` 可能会使用 `MaglevAssembler::StringFromCharCode` 来创建新的字符串。

**3. 类型转换:**

JavaScript 是一种动态类型语言，经常需要在不同类型之间进行转换。

```javascript
const numStr = "3.14";
const num = parseInt(numStr); // 将字符串转换为整数 (3)
const floatNum = parseFloat(numStr); // 将字符串转换为浮点数 (3.14)

const bigNum = 2**32;
const truncatedNum = bigNum | 0; // 将大数截断为 32 位整数
```

当执行 `parseInt()` 或进行位运算时，Maglev 编译器生成的代码可能会使用 `MaglevAssembler::TruncateDoubleToInt32` 或 `MaglevAssembler::TryTruncateDoubleToInt32` 等方法来执行类型转换。

**4. 函数调用:**

JavaScript 函数的调用涉及到栈帧的创建和管理。

```javascript
function myFunction(a, b) {
  return a + b;
}

myFunction(1, 2);
```

当调用 `myFunction` 时，Maglev 编译器生成的代码会在函数入口处使用 `MaglevAssembler::Prologue` 来设置栈帧，保存参数等。

**总结:**

`v8/src/maglev/x64/maglev-assembler-x64.cc` 文件是 Maglev 编译器在 x64 架构上的代码生成器，它提供了一组底层的汇编指令封装，用于实现 JavaScript 语言的各种功能，例如内存管理、字符串操作、类型转换和函数调用等。理解这个文件的功能有助于深入理解 V8 引擎的内部工作原理以及 JavaScript 代码是如何被高效执行的。

Prompt: 
```
这是目录为v8/src/maglev/x64/maglev-assembler-x64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/logging.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/common/globals.h"
#include "src/compiler/backend/instruction.h"
#include "src/interpreter/bytecode-flags-and-tokens.h"
#include "src/maglev/maglev-assembler-inl.h"
#include "src/maglev/maglev-assembler.h"
#include "src/maglev/maglev-graph.h"
#include "src/maglev/maglev-ir.h"
#include "src/objects/heap-number.h"
#include "src/objects/instance-type-inl.h"

namespace v8 {
namespace internal {
namespace maglev {

#define __ masm->

namespace {
void LoadNewAllocationTop(MaglevAssembler* masm, Register new_top,
                          Register object, int size_in_bytes) {
  __ leaq(new_top, Operand(object, size_in_bytes));
}

void LoadNewAllocationTop(MaglevAssembler* masm, Register new_top,
                          Register object, Register size_in_bytes) {
  __ Move(new_top, object);
  __ addq(new_top, size_in_bytes);
}

template <typename T>
void AllocateRaw(MaglevAssembler* masm, Isolate* isolate,
                 RegisterSnapshot register_snapshot, Register object,
                 T size_in_bytes, AllocationType alloc_type,
                 AllocationAlignment alignment) {
  // TODO(victorgomes): Call the runtime for large object allocation.
  // TODO(victorgomes): Support double alignment.
  DCHECK_EQ(alignment, kTaggedAligned);
  if (v8_flags.single_generation) {
    alloc_type = AllocationType::kOld;
  }
  ExternalReference top = SpaceAllocationTopAddress(isolate, alloc_type);
  ExternalReference limit = SpaceAllocationLimitAddress(isolate, alloc_type);
  ZoneLabelRef done(masm);
  Register new_top = kScratchRegister;
  // Check if there is enough space.
  __ Move(object, __ ExternalReferenceAsOperand(top));
  LoadNewAllocationTop(masm, new_top, object, size_in_bytes);
  __ cmpq(new_top, __ ExternalReferenceAsOperand(limit));
  // Otherwise call runtime.
  __ JumpToDeferredIf(kUnsignedGreaterThanEqual, AllocateSlow<T>,
                      register_snapshot, object, AllocateBuiltin(alloc_type),
                      size_in_bytes, done);
  // Store new top and tag object.
  __ movq(__ ExternalReferenceAsOperand(top), new_top);
  __ addq(object, Immediate(kHeapObjectTag));
  __ bind(*done);
}
}  // namespace

void MaglevAssembler::Allocate(RegisterSnapshot register_snapshot,
                               Register object, int size_in_bytes,
                               AllocationType alloc_type,
                               AllocationAlignment alignment) {
  AllocateRaw(this, isolate_, register_snapshot, object, size_in_bytes,
              alloc_type, alignment);
}

void MaglevAssembler::Allocate(RegisterSnapshot register_snapshot,
                               Register object, Register size_in_bytes,
                               AllocationType alloc_type,
                               AllocationAlignment alignment) {
  AllocateRaw(this, isolate_, register_snapshot, object, size_in_bytes,
              alloc_type, alignment);
}

void MaglevAssembler::LoadSingleCharacterString(Register result,
                                                Register char_code,
                                                Register scratch) {
  AssertZeroExtended(char_code);
  if (v8_flags.debug_code) {
    cmpq(char_code, Immediate(String::kMaxOneByteCharCode));
    Assert(below_equal, AbortReason::kUnexpectedValue);
  }
  DCHECK_NE(char_code, scratch);
  Register table = scratch;
  LoadRoot(table, RootIndex::kSingleCharacterStringTable);
  LoadTaggedFieldByIndex(result, table, char_code, kTaggedSize,
                         OFFSET_OF_DATA_START(FixedArray));
}

void MaglevAssembler::StringFromCharCode(RegisterSnapshot register_snapshot,
                                         Label* char_code_fits_one_byte,
                                         Register result, Register char_code,
                                         Register scratch,
                                         CharCodeMaskMode mask_mode) {
  DCHECK_NE(char_code, scratch);
  ZoneLabelRef done(this);
  if (mask_mode == CharCodeMaskMode::kMustApplyMask) {
    andl(char_code, Immediate(0xFFFF));
  }
  cmpl(char_code, Immediate(String::kMaxOneByteCharCode));
  JumpToDeferredIf(
      above,
      [](MaglevAssembler* masm, RegisterSnapshot register_snapshot,
         ZoneLabelRef done, Register result, Register char_code,
         Register scratch) {
        // Be sure to save {char_code}. If it aliases with {result}, use
        // the scratch register.
        // TODO(victorgomes): This is probably not needed any more, because
        // we now ensure that results registers don't alias with inputs/temps.
        // Confirm, and drop this check.
        if (char_code == result) {
          // This is guaranteed to be true since we've already checked
          // char_code != scratch.
          DCHECK_NE(scratch, result);
          __ Move(scratch, char_code);
          char_code = scratch;
        }
        DCHECK(!register_snapshot.live_tagged_registers.has(char_code));
        register_snapshot.live_registers.set(char_code);
        __ AllocateTwoByteString(register_snapshot, result, 1);
        __ movw(FieldOperand(result, OFFSET_OF_DATA_START(SeqTwoByteString)),
                char_code);
        __ jmp(*done);
      },
      register_snapshot, done, result, char_code, scratch);
  if (char_code_fits_one_byte != nullptr) {
    bind(char_code_fits_one_byte);
  }
  LoadSingleCharacterString(result, char_code, scratch);
  bind(*done);
}

void MaglevAssembler::StringCharCodeOrCodePointAt(
    BuiltinStringPrototypeCharCodeOrCodePointAt::Mode mode,
    RegisterSnapshot& register_snapshot, Register result, Register string,
    Register index, Register scratch1, Register scratch2,
    Label* result_fits_one_byte) {
  ZoneLabelRef done(this);
  Label seq_string;
  Label cons_string;
  Label sliced_string;

  Label* deferred_runtime_call = MakeDeferredCode(
      [](MaglevAssembler* masm,
         BuiltinStringPrototypeCharCodeOrCodePointAt::Mode mode,
         RegisterSnapshot register_snapshot, ZoneLabelRef done, Register result,
         Register string, Register index) {
        DCHECK(!register_snapshot.live_registers.has(result));
        DCHECK(!register_snapshot.live_registers.has(string));
        DCHECK(!register_snapshot.live_registers.has(index));
        {
          SaveRegisterStateForCall save_register_state(masm, register_snapshot);
          __ Push(string);
          __ SmiTag(index);
          __ Push(index);
          __ Move(kContextRegister, masm->native_context().object());
          // This call does not throw nor can deopt.
          if (mode ==
              BuiltinStringPrototypeCharCodeOrCodePointAt::kCodePointAt) {
            __ CallRuntime(Runtime::kStringCodePointAt);
          } else {
            DCHECK_EQ(mode,
                      BuiltinStringPrototypeCharCodeOrCodePointAt::kCharCodeAt);
            __ CallRuntime(Runtime::kStringCharCodeAt);
          }
          save_register_state.DefineSafepoint();
          __ SmiUntag(kReturnRegister0);
          __ Move(result, kReturnRegister0);
        }
        __ jmp(*done);
      },
      mode, register_snapshot, done, result, string, index);

  // We might need to try more than one time for ConsString, SlicedString and
  // ThinString.
  Label loop;
  bind(&loop);

  if (v8_flags.debug_code) {
    // Check if {string} is a string.
    AssertNotSmi(string);
    LoadMap(scratch1, string);
    CmpInstanceTypeRange(scratch1, scratch1, FIRST_STRING_TYPE,
                         LAST_STRING_TYPE);
    Check(below_equal, AbortReason::kUnexpectedValue);

    movl(scratch1, FieldOperand(string, offsetof(String, length_)));
    cmpl(index, scratch1);
    Check(below, AbortReason::kUnexpectedValue);
  }

#if V8_STATIC_ROOTS_BOOL
  Register map = scratch1;
  LoadMapForCompare(map, string);
#else
  Register instance_type = scratch1;
  // Get instance type.
  LoadInstanceType(instance_type, string);
#endif

  {
#if V8_STATIC_ROOTS_BOOL
    using StringTypeRange = InstanceTypeChecker::kUniqueMapRangeOfStringType;
    // Check the string map ranges in dense increasing order, to avoid needing
    // to subtract away the lower bound.
    static_assert(StringTypeRange::kSeqString.first == 0);
    CompareInt32AndJumpIf(map, StringTypeRange::kSeqString.second,
                          kUnsignedLessThanEqual, &seq_string, Label::kNear);

    static_assert(StringTypeRange::kSeqString.second + Map::kSize ==
                  StringTypeRange::kExternalString.first);
    CompareInt32AndJumpIf(map, StringTypeRange::kExternalString.second,
                          kUnsignedLessThanEqual, deferred_runtime_call);
    // TODO(victorgomes): Add fast path for external strings.

    static_assert(StringTypeRange::kExternalString.second + Map::kSize ==
                  StringTypeRange::kConsString.first);
    CompareInt32AndJumpIf(map, StringTypeRange::kConsString.second,
                          kUnsignedLessThanEqual, &cons_string, Label::kNear);

    static_assert(StringTypeRange::kConsString.second + Map::kSize ==
                  StringTypeRange::kSlicedString.first);
    CompareInt32AndJumpIf(map, StringTypeRange::kSlicedString.second,
                          kUnsignedLessThanEqual, &sliced_string, Label::kNear);

    static_assert(StringTypeRange::kSlicedString.second + Map::kSize ==
                  StringTypeRange::kThinString.first);
    // No need to check for thin strings, they're the last string map.
    static_assert(StringTypeRange::kThinString.second ==
                  InstanceTypeChecker::kStringMapUpperBound);
    // Fallthrough to thin string.
#else
    // TODO(victorgomes): Add fast path for external strings.
    Register representation = kScratchRegister;
    movl(representation, instance_type);
    andl(representation, Immediate(kStringRepresentationMask));
    cmpl(representation, Immediate(kSeqStringTag));
    j(equal, &seq_string, Label::kNear);
    cmpl(representation, Immediate(kConsStringTag));
    j(equal, &cons_string, Label::kNear);
    cmpl(representation, Immediate(kSlicedStringTag));
    j(equal, &sliced_string, Label::kNear);
    cmpl(representation, Immediate(kThinStringTag));
    j(not_equal, deferred_runtime_call);
    // Fallthrough to thin string.
#endif
  }

  // Is a thin string.
  {
    LoadTaggedField(string, string, offsetof(ThinString, actual_));
    jmp(&loop, Label::kNear);
  }

  bind(&sliced_string);
  {
    Register offset = scratch1;
    LoadAndUntagTaggedSignedField(offset, string,
                                  offsetof(SlicedString, offset_));
    LoadTaggedField(string, string, offsetof(SlicedString, parent_));
    addl(index, offset);
    jmp(&loop, Label::kNear);
  }

  bind(&cons_string);
  {
    CompareRoot(FieldOperand(string, offsetof(ConsString, second_)),
                RootIndex::kempty_string);
    j(not_equal, deferred_runtime_call);
    LoadTaggedField(string, string, offsetof(ConsString, first_));
    jmp(&loop, Label::kNear);  // Try again with first string.
  }

  bind(&seq_string);
  {
    Label two_byte_string;
#if V8_STATIC_ROOTS_BOOL
    if (InstanceTypeChecker::kTwoByteStringMapBit == 0) {
      TestInt32AndJumpIfAllClear(map,
                                 InstanceTypeChecker::kStringMapEncodingMask,
                                 &two_byte_string, Label::kNear);
    } else {
      TestInt32AndJumpIfAnySet(map, InstanceTypeChecker::kStringMapEncodingMask,
                               &two_byte_string, Label::kNear);
    }
#else
    andl(instance_type, Immediate(kStringEncodingMask));
    cmpl(instance_type, Immediate(kTwoByteStringTag));
    j(equal, &two_byte_string, Label::kNear);
#endif
    // The result of one-byte string will be the same for both modes
    // (CharCodeAt/CodePointAt), since it cannot be the first half of a
    // surrogate pair.
    movzxbl(result, FieldOperand(string, index, times_1,
                                 OFFSET_OF_DATA_START(SeqOneByteString)));
    jmp(result_fits_one_byte);
    bind(&two_byte_string);

    if (mode == BuiltinStringPrototypeCharCodeOrCodePointAt::kCharCodeAt) {
      movzxwl(result, FieldOperand(string, index, times_2,
                                   OFFSET_OF_DATA_START(SeqTwoByteString)));
    } else {
      DCHECK_EQ(mode,
                BuiltinStringPrototypeCharCodeOrCodePointAt::kCodePointAt);
      Register string_backup = string;
      if (result == string) {
        string_backup = scratch2;
        movq(string_backup, string);
      }
      movzxwl(result, FieldOperand(string, index, times_2,
                                   OFFSET_OF_DATA_START(SeqTwoByteString)));

      Register first_code_point = scratch1;
      movl(first_code_point, result);
      andl(first_code_point, Immediate(0xfc00));
      cmpl(first_code_point, Immediate(0xd800));
      j(not_equal, *done);

      Register length = scratch1;
      StringLength(length, string_backup);
      incl(index);
      cmpl(index, length);
      j(greater_equal, *done);

      Register second_code_point = scratch1;
      movzxwl(second_code_point,
              FieldOperand(string_backup, index, times_2,
                           OFFSET_OF_DATA_START(SeqTwoByteString)));
      movl(scratch2, second_code_point);
      andl(scratch2, Immediate(0xfc00));
      cmpl(scratch2, Immediate(0xdc00));
      j(not_equal, *done);

      int surrogate_offset = 0x10000 - (0xd800 << 10) - 0xdc00;
      addl(second_code_point, Immediate(surrogate_offset));
      shll(result, Immediate(10));
      addl(result, second_code_point);
    }

    // Fallthrough.
  }

  bind(*done);

  if (v8_flags.debug_code) {
    // We make sure that the user of this macro is not relying in string and
    // index to not be clobbered.
    if (result != string) {
      movl(string, Immediate(0xdeadbeef));
    }
    if (result != index) {
      movl(index, Immediate(0xdeadbeef));
    }
  }
}

void MaglevAssembler::TruncateDoubleToInt32(Register dst, DoubleRegister src) {
  ZoneLabelRef done(this);

  Cvttsd2siq(dst, src);
  // Check whether the Cvt overflowed.
  cmpq(dst, Immediate(1));
  JumpToDeferredIf(
      overflow,
      [](MaglevAssembler* masm, DoubleRegister src, Register dst,
         ZoneLabelRef done) {
        // Push the double register onto the stack as an input argument.
        __ AllocateStackSpace(kDoubleSize);
        __ Movsd(MemOperand(rsp, 0), src);
        __ CallBuiltin(Builtin::kDoubleToI);
        // DoubleToI sets the result on the stack, pop the result off the stack.
        // Avoid using `pop` to not mix implicit and explicit rsp updates.
        __ movl(dst, MemOperand(rsp, 0));
        __ addq(rsp, Immediate(kDoubleSize));
        __ jmp(*done);
      },
      src, dst, done);
  bind(*done);
  // Zero extend the converted value to complete the truncation.
  movl(dst, dst);
}

void MaglevAssembler::TryTruncateDoubleToInt32(Register dst, DoubleRegister src,
                                               Label* fail) {
  // Truncating conversion of the input float64 value to an int32.
  Cvttpd2dq(kScratchDoubleReg, src);
  // Convert that int32 value back to float64.
  Cvtdq2pd(kScratchDoubleReg, kScratchDoubleReg);
  // Check that the result of the float64->int32->float64 is equal to the input
  // (i.e. that the conversion didn't truncate).
  Ucomisd(kScratchDoubleReg, src);
  JumpIf(parity_even, fail);
  JumpIf(not_equal, fail);

  // Move to general purpose register.
  Cvttsd2si(dst, src);

  // Check if {input} is -0.
  Label check_done;
  cmpl(dst, Immediate(0));
  j(not_equal, &check_done);

  // In case of 0, we need to check the high bits for the IEEE -0 pattern.
  Register high_word32_of_input = kScratchRegister;
  Pextrd(high_word32_of_input, src, 1);
  cmpl(high_word32_of_input, Immediate(0));
  JumpIf(less, fail);

  bind(&check_done);
}

void MaglevAssembler::TryTruncateDoubleToUint32(Register dst,
                                                DoubleRegister src,
                                                Label* fail) {
  DoubleRegister converted_back = kScratchDoubleReg;

  // Convert the input float64 value to int64.
  Cvttsd2siq(dst, src);
  // Truncate and zero extend to uint32.
  movl(dst, dst);
  // Convert that value back to float64.
  Cvtqsi2sd(converted_back, dst);
  // Check that the result of the float64->uint32->float64 is equal to the input
  // (i.e. that the conversion didn't truncate.
  Ucomisd(src, converted_back);
  JumpIf(parity_even, fail);
  JumpIf(not_equal, fail);

  // Check if {input} is -0.
  Label check_done;
  cmpl(dst, Immediate(0));
  j(not_equal, &check_done);

  // In case of 0, we need to check the high bits for the IEEE -0 pattern.
  Register high_word32_of_input = kScratchRegister;
  Pextrd(high_word32_of_input, src, 1);
  cmpl(high_word32_of_input, Immediate(0));
  JumpIf(less, fail);

  bind(&check_done);
}

void MaglevAssembler::TryChangeFloat64ToIndex(Register result,
                                              DoubleRegister value,
                                              Label* success, Label* fail) {
  // Truncating conversion of the input float64 value to an int32.
  Cvttpd2dq(kScratchDoubleReg, value);
  // Convert that int32 value back to float64.
  Cvtdq2pd(kScratchDoubleReg, kScratchDoubleReg);
  // Check that the result of the float64->int32->float64 is equal to
  // the input (i.e. that the conversion didn't truncate).
  Ucomisd(value, kScratchDoubleReg);
  JumpIf(parity_even, fail);
  JumpIf(kNotEqual, fail);

  // Move to general purpose register.
  Cvttsd2si(result, value);
  Jump(success);
}

void MaglevAssembler::OSRPrologue(Graph* graph) {
  DCHECK(graph->is_osr());
  CHECK(!graph->has_recursive_calls());

  uint32_t source_frame_size =
      graph->min_maglev_stackslots_for_unoptimized_frame_size();

  if (v8_flags.maglev_assert_stack_size && v8_flags.debug_code) {
    movq(kScratchRegister, rbp);
    subq(kScratchRegister, rsp);
    cmpq(kScratchRegister,
         Immediate(source_frame_size * kSystemPointerSize +
                   StandardFrameConstants::kFixedFrameSizeFromFp));
    Assert(equal, AbortReason::kOsrUnexpectedStackSize);
  }

  uint32_t target_frame_size =
      graph->tagged_stack_slots() + graph->untagged_stack_slots();
  CHECK_LE(source_frame_size, target_frame_size);

  if (source_frame_size < target_frame_size) {
    ASM_CODE_COMMENT_STRING(this, "Growing frame for OSR");
    Move(kScratchRegister, 0);
    uint32_t additional_tagged =
        source_frame_size < graph->tagged_stack_slots()
            ? graph->tagged_stack_slots() - source_frame_size
            : 0;
    for (size_t i = 0; i < additional_tagged; ++i) {
      pushq(kScratchRegister);
    }
    uint32_t size_so_far = source_frame_size + additional_tagged;
    CHECK_LE(size_so_far, target_frame_size);
    if (size_so_far < target_frame_size) {
      subq(rsp,
           Immediate((target_frame_size - size_so_far) * kSystemPointerSize));
    }
  }
}

void MaglevAssembler::Prologue(Graph* graph) {
  DCHECK(!graph->is_osr());

  CodeEntry();

  BailoutIfDeoptimized(rbx);

  if (graph->has_recursive_calls()) {
    BindJumpTarget(code_gen_state()->entry_label());
  }

#ifndef V8_ENABLE_LEAPTIERING
  // Tiering support.
  if (v8_flags.turbofan) {
    using D = MaglevOptimizeCodeOrTailCallOptimizedCodeSlotDescriptor;
    Register feedback_vector = D::GetRegisterParameter(D::kFeedbackVector);
    DCHECK(!AreAliased(feedback_vector, kJavaScriptCallArgCountRegister,
                       kJSFunctionRegister, kContextRegister,
                       kJavaScriptCallNewTargetRegister,
                       kJavaScriptCallDispatchHandleRegister));
    Move(feedback_vector,
         compilation_info()->toplevel_compilation_unit()->feedback().object());
    TailCallBuiltin(Builtin::kMaglevOptimizeCodeOrTailCallOptimizedCodeSlot,
                    CheckFeedbackVectorFlagsNeedsProcessing(feedback_vector,
                                                            CodeKind::MAGLEV));
  }
#endif  // !V8_ENABLE_LEAPTIERING

  EnterFrame(StackFrame::MAGLEV);
  // Save arguments in frame.
  // TODO(leszeks): Consider eliding this frame if we don't make any calls
  // that could clobber these registers.
  Push(kContextRegister);
  Push(kJSFunctionRegister);              // Callee's JS function.
  Push(kJavaScriptCallArgCountRegister);  // Actual argument count.

  // Initialize stack slots.
  if (graph->tagged_stack_slots() > 0) {
    ASM_CODE_COMMENT_STRING(this, "Initializing stack slots");
    // TODO(leszeks): Consider filling with xmm + movdqa instead.
    Move(rax, 0);

    // Magic value. Experimentally, an unroll size of 8 doesn't seem any
    // worse than fully unrolled pushes.
    const int kLoopUnrollSize = 8;
    int tagged_slots = graph->tagged_stack_slots();
    if (tagged_slots < 2 * kLoopUnrollSize) {
      // If the frame is small enough, just unroll the frame fill
      // completely.
      for (int i = 0; i < tagged_slots; ++i) {
        pushq(rax);
      }
    } else {
      // Extract the first few slots to round to the unroll size.
      int first_slots = tagged_slots % kLoopUnrollSize;
      for (int i = 0; i < first_slots; ++i) {
        pushq(rax);
      }
      Move(rbx, tagged_slots / kLoopUnrollSize);
      // We enter the loop unconditionally, so make sure we need to loop at
      // least once.
      DCHECK_GT(tagged_slots / kLoopUnrollSize, 0);
      Label loop;
      bind(&loop);
      for (int i = 0; i < kLoopUnrollSize; ++i) {
        pushq(rax);
      }
      decl(rbx);
      j(greater, &loop);
    }
  }
  if (graph->untagged_stack_slots() > 0) {
    // Extend rsp by the size of the remaining untagged part of the frame,
    // no need to initialise these.
    subq(rsp, Immediate(graph->untagged_stack_slots() * kSystemPointerSize));
  }
}

void MaglevAssembler::MaybeEmitDeoptBuiltinsCall(size_t eager_deopt_count,
                                                 Label* eager_deopt_entry,
                                                 size_t lazy_deopt_count,
                                                 Label* lazy_deopt_entry) {}

}  // namespace maglev
}  // namespace internal
}  // namespace v8

"""

```