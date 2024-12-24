Response: The user wants to understand the functionality of the C++ code provided, specifically focusing on its relation to JavaScript. To do this, I should:

1. **Analyze the C++ code:** Identify the core functionalities implemented in the `maglev-assembler-arm.cc` file. Look for functions related to memory allocation, stack management, string manipulation, type conversions, and interaction with the V8 runtime.
2. **Relate to JavaScript:** Connect these C++ functionalities to corresponding concepts and behaviors in JavaScript. Think about how JavaScript engines handle memory, function calls, string operations, and type conversions.
3. **Provide JavaScript examples:** Illustrate the connection between the C++ code and JavaScript using concrete examples. These examples should demonstrate the JavaScript features that rely on the C++ functionalities.
这个C++源代码文件 `v8/src/maglev/arm/maglev-assembler-arm.cc` 是 V8 JavaScript 引擎中 Maglev 编译器的 ARM 架构特定部分。它的主要功能是 **提供用于生成 ARM 汇编代码的工具和方法，这些代码是 Maglev 编译器将 JavaScript 代码编译成的目标代码**。

具体来说，这个文件定义了 `MaglevAssembler` 类的一些方法，这些方法封装了常见的 ARM 汇编指令序列，用于执行诸如：

* **内存分配 (`Allocate`)**:  用于在堆上分配新的对象。
* **函数调用和栈帧管理 (`Prologue`, `OSRPrologue`)**: 设置函数执行的栈帧，包括保存寄存器、分配栈空间等。`OSRPrologue` 特别处理了 On-Stack Replacement (OSR) 优化的情况。
* **字符串操作 (`LoadSingleCharacterString`, `StringFromCharCode`, `StringCharCodeOrCodePointAt`)**:  处理 JavaScript 字符串相关的操作，例如根据字符码创建字符串，或者获取字符串中指定位置的字符码或 Unicode 码点。
* **类型转换 (`TruncateDoubleToInt32`, `TryTruncateDoubleToInt32`, `TryTruncateDoubleToUint32`, `TryChangeFloat64ToIndex`)**:  在 JavaScript 中经常需要进行不同类型之间的转换，这些函数提供了将浮点数转换为整数等操作的汇编实现。
* **Deoptimization (`MaybeEmitDeoptBuiltinsCall`)**:  处理在优化代码执行过程中遇到无法继续优化的场景，需要返回到解释器执行的情况。
* **与 V8 运行时交互**:  例如，在内存分配空间不足时，会调用 V8 运行时进行处理。
* **Tiering 支持**:  支持 V8 的分层编译，即根据代码的执行频率和特性，逐步进行更激进的优化。

**与 JavaScript 的关系以及 JavaScript 示例**

这个 C++ 文件中的代码直接支持了 JavaScript 的各种功能。  当 V8 引擎执行 JavaScript 代码时，Maglev 编译器会将 JavaScript 代码翻译成由这些汇编指令组成的机器码。

以下是一些 JavaScript 功能以及它们可能如何与这个 C++ 文件中的功能相关联的示例：

**1. 对象创建和内存分配:**

```javascript
const obj = {}; // 创建一个空对象
const arr = [1, 2, 3]; // 创建一个数组
```

当执行这些 JavaScript 代码时，Maglev 编译器可能会调用 `MaglevAssembler::Allocate` 方法来在堆上为 `obj` 和 `arr` 分配内存空间。  C++ 代码中的 `AllocateRaw` 函数会处理具体的内存分配逻辑，包括检查空闲空间、更新堆顶指针等。

**2. 函数调用:**

```javascript
function add(a, b) {
  return a + b;
}

add(5, 10);
```

当调用 `add` 函数时，`MaglevAssembler::Prologue` 会被用来设置函数的栈帧。这包括保存必要的寄存器（如上下文 `kContextRegister` 和函数本身 `kJSFunctionRegister`），以及为局部变量分配栈空间。  `OSRPrologue` 则会在 On-Stack Replacement 发生时，调整栈帧大小。

**3. 字符串操作:**

```javascript
const str = "Hello";
const charCode = str.charCodeAt(1); // 获取索引为 1 的字符的 Unicode 码点
const newStr = String.fromCharCode(65); // 根据字符码创建字符串
```

`str.charCodeAt(1)` 的执行可能会涉及到 `MaglevAssembler::StringCharCodeOrCodePointAt` 方法，该方法会根据字符串的内部表示（例如，是否为连续存储的字符串、是否为拼接字符串等）来高效地获取指定位置的字符码。  `String.fromCharCode(65)` 的执行可能会使用 `MaglevAssembler::StringFromCharCode` 或 `MaglevAssembler::LoadSingleCharacterString` 来创建包含字符 'A' 的字符串对象。

**4. 类型转换:**

```javascript
const numStr = "123.45";
const num = parseInt(numStr); // 将字符串转换为整数
const floatNum = parseFloat(numStr); // 将字符串转换为浮点数
const intVal = Math.trunc(floatNum); // 将浮点数截断为整数
```

`parseInt` 和 `parseFloat` 的底层实现可能涉及到与 C++ 层的交互，但 `Math.trunc` 的 Maglev 编译版本可能会直接使用 `MaglevAssembler::TruncateDoubleToInt32` 或类似的函数，将 JavaScript 的双精度浮点数转换为 32 位整数。

**总结**

`v8/src/maglev/arm/maglev-assembler-arm.cc` 文件是 Maglev 编译器在 ARM 架构上生成高性能 JavaScript 执行代码的关键组成部分。它通过提供底层的汇编代码生成工具，使得 Maglev 能够有效地将高级的 JavaScript 代码转换为可以在 ARM 处理器上运行的机器码，从而实现 JavaScript 代码的快速执行。 JavaScript 的各种语言特性和运行时行为，例如对象创建、函数调用、字符串操作和类型转换，都在底层依赖于这样的汇编代码生成机制。

Prompt: 
```
这是目录为v8/src/maglev/arm/maglev-assembler-arm.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/codegen/interface-descriptors-inl.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/maglev/maglev-assembler-inl.h"
#include "src/maglev/maglev-graph.h"

namespace v8 {
namespace internal {
namespace maglev {

#define __ masm->

namespace {
void SubSizeAndTagObject(MaglevAssembler* masm, Register object,
                         Register size_in_bytes) {
  __ sub(object, object, size_in_bytes, LeaveCC);
  __ add(object, object, Operand(kHeapObjectTag), LeaveCC);
}

void SubSizeAndTagObject(MaglevAssembler* masm, Register object,
                         int size_in_bytes) {
  __ add(object, object, Operand(kHeapObjectTag - size_in_bytes), LeaveCC);
}

template <typename T>
void AllocateRaw(MaglevAssembler* masm, Isolate* isolate,
                 RegisterSnapshot register_snapshot, Register object,
                 T size_in_bytes, AllocationType alloc_type,
                 AllocationAlignment alignment) {
  // TODO(victorgomes): Call the runtime for large object allocation.
  // TODO(victorgomes): Support double alignment.
  DCHECK(masm->allow_allocate());
  DCHECK_EQ(alignment, kTaggedAligned);
  if (v8_flags.single_generation) {
    alloc_type = AllocationType::kOld;
  }
  ExternalReference top = SpaceAllocationTopAddress(isolate, alloc_type);
  ExternalReference limit = SpaceAllocationLimitAddress(isolate, alloc_type);
  ZoneLabelRef done(masm);
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.AcquireScratch();
  // We are a bit short on registers, so we use the same register for {object}
  // and {new_top}. Once we have defined {new_top}, we don't use {object} until
  // {new_top} is used for the last time. And there (at the end of this
  // function), we recover the original {object} from {new_top} by subtracting
  // {size_in_bytes}.
  Register new_top = object;
  // Check if there is enough space.
  __ ldr(object, __ ExternalReferenceAsOperand(top, scratch));
  __ add(new_top, object, Operand(size_in_bytes), LeaveCC);
  __ ldr(scratch, __ ExternalReferenceAsOperand(limit, scratch));
  __ cmp(new_top, scratch);
  // Otherwise call runtime.
  __ JumpToDeferredIf(kUnsignedGreaterThanEqual, AllocateSlow<T>,
                      register_snapshot, object, AllocateBuiltin(alloc_type),
                      size_in_bytes, done);
  // Store new top and tag object.
  __ Move(__ ExternalReferenceAsOperand(top, scratch), new_top);
  SubSizeAndTagObject(masm, object, size_in_bytes);
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

void MaglevAssembler::OSRPrologue(Graph* graph) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();

  DCHECK(graph->is_osr());
  CHECK(!graph->has_recursive_calls());

  uint32_t source_frame_size =
      graph->min_maglev_stackslots_for_unoptimized_frame_size();

  if (v8_flags.maglev_assert_stack_size && v8_flags.debug_code) {
    add(scratch, sp,
        Operand(source_frame_size * kSystemPointerSize +
                StandardFrameConstants::kFixedFrameSizeFromFp));
    cmp(scratch, fp);
    Assert(eq, AbortReason::kOsrUnexpectedStackSize);
  }

  uint32_t target_frame_size =
      graph->tagged_stack_slots() + graph->untagged_stack_slots();
  CHECK_LE(source_frame_size, target_frame_size);

  if (source_frame_size < target_frame_size) {
    ASM_CODE_COMMENT_STRING(this, "Growing frame for OSR");
    uint32_t additional_tagged =
        source_frame_size < graph->tagged_stack_slots()
            ? graph->tagged_stack_slots() - source_frame_size
            : 0;
    if (additional_tagged) {
      Move(scratch, 0);
    }
    for (size_t i = 0; i < additional_tagged; ++i) {
      Push(scratch);
    }
    uint32_t size_so_far = source_frame_size + additional_tagged;
    CHECK_LE(size_so_far, target_frame_size);
    if (size_so_far < target_frame_size) {
      sub(sp, sp,
          Operand((target_frame_size - size_so_far) * kSystemPointerSize));
    }
  }
}

void MaglevAssembler::Prologue(Graph* graph) {
  TemporaryRegisterScope temps(this);
  temps.Include({r4, r8});

  DCHECK(!graph->is_osr());

  BailoutIfDeoptimized();

  if (graph->has_recursive_calls()) {
    bind(code_gen_state()->entry_label());
  }

  // Tiering support.
  if (v8_flags.turbofan) {
    using D = MaglevOptimizeCodeOrTailCallOptimizedCodeSlotDescriptor;
    Register flags = D::GetRegisterParameter(D::kFlags);
    Register feedback_vector = D::GetRegisterParameter(D::kFeedbackVector);
    DCHECK(!AreAliased(flags, feedback_vector, kJavaScriptCallArgCountRegister,
                       kJSFunctionRegister, kContextRegister,
                       kJavaScriptCallNewTargetRegister));
    DCHECK(!temps.Available().has(flags));
    DCHECK(!temps.Available().has(feedback_vector));
    Move(feedback_vector,
         compilation_info()->toplevel_compilation_unit()->feedback().object());
    Condition needs_processing =
        LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing(flags, feedback_vector,
                                                         CodeKind::MAGLEV);
    // Tail call on Arm produces 3 instructions, so we emit that in deferred
    // code.
    JumpToDeferredIf(needs_processing, [](MaglevAssembler* masm) {
      __ TailCallBuiltin(
          Builtin::kMaglevOptimizeCodeOrTailCallOptimizedCodeSlot);
    });
  }

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
    TemporaryRegisterScope temps(this);
    Register scratch = temps.AcquireScratch();
    Move(scratch, 0);

    // Magic value. Experimentally, an unroll size of 8 doesn't seem any
    // worse than fully unrolled pushes.
    const int kLoopUnrollSize = 8;
    int tagged_slots = graph->tagged_stack_slots();
    if (tagged_slots < kLoopUnrollSize) {
      // If the frame is small enough, just unroll the frame fill
      // completely.
      for (int i = 0; i < tagged_slots; ++i) {
        Push(scratch);
      }
    } else {
      // Extract the first few slots to round to the unroll size.
      int first_slots = tagged_slots % kLoopUnrollSize;
      for (int i = 0; i < first_slots; ++i) {
        Push(scratch);
      }
      Register unroll_counter = temps.AcquireScratch();
      Move(unroll_counter, tagged_slots / kLoopUnrollSize);
      // We enter the loop unconditionally, so make sure we need to loop at
      // least once.
      DCHECK_GT(tagged_slots / kLoopUnrollSize, 0);
      Label loop;
      bind(&loop);
      for (int i = 0; i < kLoopUnrollSize; ++i) {
        Push(scratch);
      }
      sub(unroll_counter, unroll_counter, Operand(1), SetCC);
      b(kGreaterThan, &loop);
    }
  }
  if (graph->untagged_stack_slots() > 0) {
    // Extend rsp by the size of the remaining untagged part of the frame,
    // no need to initialise these.
    sub(sp, sp, Operand(graph->untagged_stack_slots() * kSystemPointerSize));
  }
}

void MaglevAssembler::MaybeEmitDeoptBuiltinsCall(size_t eager_deopt_count,
                                                 Label* eager_deopt_entry,
                                                 size_t lazy_deopt_count,
                                                 Label* lazy_deopt_entry) {
  CheckConstPool(true, false);
}

void MaglevAssembler::LoadSingleCharacterString(Register result,
                                                Register char_code,
                                                Register scratch) {
  DCHECK_NE(char_code, scratch);
  if (v8_flags.debug_code) {
    cmp(char_code, Operand(String::kMaxOneByteCharCode));
    Assert(kUnsignedLessThanEqual, AbortReason::kUnexpectedValue);
  }
  Register table = scratch;
  LoadRoot(table, RootIndex::kSingleCharacterStringTable);
  add(table, table, Operand(char_code, LSL, kTaggedSizeLog2));
  ldr(result, FieldMemOperand(table, OFFSET_OF_DATA_START(FixedArray)));
}

void MaglevAssembler::StringFromCharCode(RegisterSnapshot register_snapshot,
                                         Label* char_code_fits_one_byte,
                                         Register result, Register char_code,
                                         Register scratch,
                                         CharCodeMaskMode mask_mode) {
  AssertZeroExtended(char_code);
  DCHECK_NE(char_code, scratch);
  ZoneLabelRef done(this);
  if (mask_mode == CharCodeMaskMode::kMustApplyMask) {
    and_(char_code, char_code, Operand(0xFFFF));
  }
  cmp(char_code, Operand(String::kMaxOneByteCharCode));
  JumpToDeferredIf(
      kUnsignedGreaterThan,
      [](MaglevAssembler* masm, RegisterSnapshot register_snapshot,
         ZoneLabelRef done, Register result, Register char_code,
         Register scratch) {
        // Be sure to save {char_code}. If it aliases with {result}, use
        // the scratch register.
        // TODO(victorgomes): This is probably not needed any more, because
        // we now ensure that results registers don't alias with inputs/temps.
        // Confirm, and drop this check.
        if (char_code == result) {
          __ Move(scratch, char_code);
          char_code = scratch;
        }
        DCHECK_NE(char_code, result);
        DCHECK(!register_snapshot.live_tagged_registers.has(char_code));
        register_snapshot.live_registers.set(char_code);
        __ AllocateTwoByteString(register_snapshot, result, 1);
        __ strh(char_code, FieldMemOperand(
                               result, OFFSET_OF_DATA_START(SeqTwoByteString)));
        __ b(*done);
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
    Register index, Register instance_type, Register scratch2,
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
          __ SmiTag(index);
          __ Push(string, index);
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
        __ b(*done);
      },
      mode, register_snapshot, done, result, string, index);

  // We might need to try more than one time for ConsString, SlicedString and
  // ThinString.
  Label loop;
  bind(&loop);

  if (v8_flags.debug_code) {
    // Check if {string} is a string.
    AssertObjectTypeInRange(string, FIRST_STRING_TYPE, LAST_STRING_TYPE,
                            AbortReason::kUnexpectedValue);

    Register scratch = instance_type;
    ldr(scratch, FieldMemOperand(string, offsetof(String, length_)));
    cmp(index, scratch);
    Check(lo, AbortReason::kUnexpectedValue);
  }

  // Get instance type.
  LoadInstanceType(instance_type, string);

  {
    TemporaryRegisterScope temps(this);
    Register representation = temps.AcquireScratch();

    // TODO(victorgomes): Add fast path for external strings.
    and_(representation, instance_type, Operand(kStringRepresentationMask));
    cmp(representation, Operand(kSeqStringTag));
    b(eq, &seq_string);
    cmp(representation, Operand(kConsStringTag));
    b(eq, &cons_string);
    cmp(representation, Operand(kSlicedStringTag));
    b(eq, &sliced_string);
    cmp(representation, Operand(kThinStringTag));
    b(ne, deferred_runtime_call);
    // Fallthrough to thin string.
  }

  // Is a thin string.
  {
    ldr(string, FieldMemOperand(string, offsetof(ThinString, actual_)));
    b(&loop);
  }

  bind(&sliced_string);
  {
    TemporaryRegisterScope temps(this);
    Register offset = temps.AcquireScratch();

    LoadAndUntagTaggedSignedField(offset, string,
                                  offsetof(SlicedString, offset_));
    LoadTaggedField(string, string, offsetof(SlicedString, parent_));
    add(index, index, offset);
    b(&loop);
  }

  bind(&cons_string);
  {
    // Reuse {instance_type} register here, since CompareRoot requires a scratch
    // register as well.
    Register second_string = instance_type;
    ldr(second_string, FieldMemOperand(string, offsetof(ConsString, second_)));
    CompareRoot(second_string, RootIndex::kempty_string);
    b(ne, deferred_runtime_call);
    ldr(string, FieldMemOperand(string, offsetof(ConsString, first_)));
    b(&loop);  // Try again with first string.
  }

  bind(&seq_string);
  {
    Label two_byte_string;
    tst(instance_type, Operand(kOneByteStringTag));
    b(eq, &two_byte_string);
    // The result of one-byte string will be the same for both modes
    // (CharCodeAt/CodePointAt), since it cannot be the first half of a
    // surrogate pair.
    add(index, index,
        Operand(OFFSET_OF_DATA_START(SeqOneByteString) - kHeapObjectTag));
    ldrb(result, MemOperand(string, index));
    b(result_fits_one_byte);

    bind(&two_byte_string);
    // {instance_type} is unused from this point, so we can use as scratch.
    Register scratch = instance_type;
    lsl(scratch, index, Operand(1));
    add(scratch, scratch,
        Operand(OFFSET_OF_DATA_START(SeqTwoByteString) - kHeapObjectTag));

    if (mode == BuiltinStringPrototypeCharCodeOrCodePointAt::kCharCodeAt) {
      ldrh(result, MemOperand(string, scratch));
    } else {
      DCHECK_EQ(mode,
                BuiltinStringPrototypeCharCodeOrCodePointAt::kCodePointAt);
      Register string_backup = string;
      if (result == string) {
        string_backup = scratch2;
        Move(string_backup, string);
      }
      ldrh(result, MemOperand(string, scratch));

      Register first_code_point = scratch;
      and_(first_code_point, result, Operand(0xfc00));
      cmp(first_code_point, Operand(0xd800));
      b(ne, *done);

      Register length = scratch;
      ldr(length, FieldMemOperand(string_backup, offsetof(String, length_)));
      add(index, index, Operand(1));
      cmp(index, length);
      b(ge, *done);

      Register second_code_point = scratch;
      lsl(index, index, Operand(1));
      add(index, index,
          Operand(OFFSET_OF_DATA_START(SeqTwoByteString) - kHeapObjectTag));
      ldrh(second_code_point, MemOperand(string_backup, index));

      // {index} is not needed at this point.
      Register scratch2 = index;
      and_(scratch2, second_code_point, Operand(0xfc00));
      cmp(scratch2, Operand(0xdc00));
      b(ne, *done);

      int surrogate_offset = 0x10000 - (0xd800 << 10) - 0xdc00;
      add(second_code_point, second_code_point, Operand(surrogate_offset));
      lsl(result, result, Operand(10));
      add(result, result, second_code_point);
    }

    // Fallthrough.
  }

  bind(*done);

  if (v8_flags.debug_code) {
    // We make sure that the user of this macro is not relying in string and
    // index to not be clobbered.
    if (result != string) {
      Move(string, 0xdeadbeef);
    }
    if (result != index) {
      Move(index, 0xdeadbeef);
    }
  }
}

void MaglevAssembler::TruncateDoubleToInt32(Register dst, DoubleRegister src) {
  ZoneLabelRef done(this);
  Label* slow_path = MakeDeferredCode(
      [](MaglevAssembler* masm, DoubleRegister src, Register dst,
         ZoneLabelRef done) {
        __ push(lr);
        __ AllocateStackSpace(kDoubleSize);
        __ vstr(src, MemOperand(sp, 0));
        __ CallBuiltin(Builtin::kDoubleToI);
        __ ldr(dst, MemOperand(sp, 0));
        __ add(sp, sp, Operand(kDoubleSize));
        __ pop(lr);
        __ Jump(*done);
      },
      src, dst, done);
  TryInlineTruncateDoubleToI(dst, src, *done);
  Jump(slow_path);
  bind(*done);
}

void MaglevAssembler::TryTruncateDoubleToInt32(Register dst, DoubleRegister src,
                                               Label* fail) {
  UseScratchRegisterScope temps(this);
  LowDwVfpRegister low_double = temps.AcquireLowD();
  SwVfpRegister temp_vfps = low_double.low();
  DoubleRegister converted_back = low_double;
  Label done;

  // Convert the input float64 value to int32.
  vcvt_s32_f64(temp_vfps, src);
  vmov(dst, temp_vfps);

  // Convert that int32 value back to float64.
  vcvt_f64_s32(converted_back, temp_vfps);

  // Check that the result of the float64->int32->float64 is equal to the input
  // (i.e. that the conversion didn't truncate.
  VFPCompareAndSetFlags(src, converted_back);
  JumpIf(kNotEqual, fail);

  // Check if {input} is -0.
  tst(dst, dst);
  JumpIf(kNotEqual, &done);

  // In case of 0, we need to check the high bits for the IEEE -0 pattern.
  {
    Register high_word32_of_input = temps.Acquire();
    VmovHigh(high_word32_of_input, src);
    cmp(high_word32_of_input, Operand(0));
    JumpIf(kLessThan, fail);
  }

  bind(&done);
}

void MaglevAssembler::TryTruncateDoubleToUint32(Register dst,
                                                DoubleRegister src,
                                                Label* fail) {
  UseScratchRegisterScope temps(this);
  LowDwVfpRegister low_double = temps.AcquireLowD();
  SwVfpRegister temp_vfps = low_double.low();
  DoubleRegister converted_back = low_double;
  Label done;

  // Convert the input float64 value to uint32.
  vcvt_u32_f64(temp_vfps, src);
  vmov(dst, temp_vfps);

  // Convert that uint32 value back to float64.
  vcvt_f64_u32(converted_back, temp_vfps);

  // Check that the result of the float64->uint32->float64 is equal to the input
  // (i.e. that the conversion didn't truncate.
  VFPCompareAndSetFlags(src, converted_back);
  JumpIf(kNotEqual, fail);

  // Check if {input} is -0.
  tst(dst, dst);
  JumpIf(kNotEqual, &done);

  // In case of 0, we need to check the high bits for the IEEE -0 pattern.
  {
    Register high_word32_of_input = temps.Acquire();
    VmovHigh(high_word32_of_input, src);
    cmp(high_word32_of_input, Operand(0));
    JumpIf(kLessThan, fail);
  }

  bind(&done);
}

void MaglevAssembler::TryChangeFloat64ToIndex(Register result,
                                              DoubleRegister value,
                                              Label* success, Label* fail) {
  UseScratchRegisterScope temps(this);
  LowDwVfpRegister low_double = temps.AcquireLowD();
  SwVfpRegister temp_vfps = low_double.low();
  DoubleRegister converted_back = low_double;
  // Convert the input float64 value to int32.
  vcvt_s32_f64(temp_vfps, value);
  vmov(result, temp_vfps);
  // Convert that int32 value back to float64.
  vcvt_f64_s32(converted_back, temp_vfps);
  // Check that the result of the float64->int32->float64 is equal to
  // the input (i.e. that the conversion didn't truncate).
  VFPCompareAndSetFlags(value, converted_back);
  JumpIf(kNotEqual, fail);
  Jump(success);
}

}  // namespace maglev
}  // namespace internal
}  // namespace v8

"""

```