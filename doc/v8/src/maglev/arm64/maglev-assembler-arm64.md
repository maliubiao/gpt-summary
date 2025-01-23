Response: The user wants a summary of the functionality of the provided C++ code, which is a part of the V8 JavaScript engine. I need to identify the key responsibilities of the `MaglevAssembler` class within the `arm64` architecture context. The code seems to handle low-level operations related to memory allocation, function prologues/epilogues, deoptimization, and string manipulation, among other things. Since the request specifically asks about the relationship with JavaScript, I should try to find examples of how these assembler functions relate to common JavaScript operations.

Here's a breakdown of the code's functionality:

1. **Memory Allocation:** The code provides functions for allocating memory on the heap (`Allocate`). It distinguishes between different allocation types (e.g., old generation) and alignments.

2. **Function Prologue/Epilogue:** Functions like `OSRPrologue` and `Prologue` are responsible for setting up the function's execution environment, including stack frame management and handling optimized-for-OSR (On-Stack Replacement) scenarios.

3. **Deoptimization:** The `MaybeEmitDeoptBuiltinsCall` function deals with generating calls to deoptimization builtins, which are used when optimized code needs to revert to a less optimized state.

4. **String Operations:**  Several functions handle string-related operations:
    - `LoadSingleCharacterString`: Loads a single-character string from a pre-computed table.
    - `StringFromCharCode`: Creates a string from a character code.
    - `StringCharCodeOrCodePointAt`:  Retrieves the character code or code point at a specific index in a string, handling different string representations (e.g., SeqString, ConsString, SlicedString).

5. **Type Conversion:** Functions like `TruncateDoubleToInt32`, `TryTruncateDoubleToInt32`, and `TryTruncateDoubleToUint32` handle the conversion of floating-point numbers to integers, taking care of potential truncation and edge cases. `TryChangeFloat64ToIndex` seems related to converting floating-point numbers to valid array indices.

To illustrate the connection to JavaScript, I can pick a few of these functionalities and show how they manifest in JavaScript code. For example, string creation using `String.fromCharCode()`, accessing characters using bracket notation or `charCodeAt()`, and the behavior of `parseInt()` or bitwise operations that involve integer truncation.
这个C++源代码文件 `maglev-assembler-arm64.cc` 是 V8 JavaScript 引擎中 Maglev 编译器的 ARM64 架构特定部分，主要负责提供一套用于生成 ARM64 汇编指令的接口和工具函数。 它的功能可以归纳为：

1. **汇编指令生成:** 封装了 ARM64 汇编指令的操作，提供了诸如 `Mov`, `Add`, `Sub`, `Ldr`, `Str`, `Cmp`, `B` 等指令的 C++ 接口，使得 Maglev 编译器可以用更符合 C++ 习惯的方式生成底层的汇编代码。

2. **寄存器管理:**  提供 `TemporaryRegisterScope` 来管理临时寄存器的分配和释放，避免寄存器冲突。

3. **内存分配:** 提供了在 V8 堆上分配对象的函数 `Allocate`，支持不同类型的内存分配（例如老生代、新生代）和对齐方式。

4. **函数序言和尾声:** 包含了生成函数序言（`Prologue`，`OSRPrologue`）和尾声所需指令的逻辑，例如创建栈帧、保存寄存器等。`OSRPrologue` 特别处理了 On-Stack Replacement (OSR) 的场景。

5. **反优化 (Deoptimization):**  `MaybeEmitDeoptBuiltinsCall` 函数负责在需要时生成调用反优化入口点的代码。当优化后的代码执行出现问题时，会跳转到这些入口点恢复到未优化的状态。

6. **字符串操作:** 提供了一系列与字符串操作相关的汇编指令生成函数，例如：
    - `LoadSingleCharacterString`: 从预定义的字符缓存中加载单个字符的字符串。
    - `StringFromCharCode`: 根据字符编码创建字符串。
    - `StringCharCodeOrCodePointAt`: 获取字符串指定位置的字符编码或 Unicode 码点，并处理不同类型的字符串（例如，SeqString, ConsString, SlicedString）。

7. **类型转换:** 提供了将 JavaScript 中的双精度浮点数转换为 32 位整数的函数，例如 `TruncateDoubleToInt32`, `TryTruncateDoubleToInt32`, `TryTruncateDoubleToUint32`, `TryChangeFloat64ToIndex`。这些函数考虑了溢出、NaN 和 -0 等特殊情况。

**与 JavaScript 的关系以及 JavaScript 示例:**

这个文件中的代码虽然是底层的汇编指令生成，但直接服务于 V8 引擎执行 JavaScript 代码。 Maglev 编译器会将 JavaScript 代码编译成这些 ARM64 汇编指令，然后由 CPU 执行。

以下是一些 JavaScript 代码示例以及它们在 Maglev 编译器中可能如何使用 `maglev-assembler-arm64.cc` 中的功能：

**1. 内存分配:**

```javascript
const obj = { x: 1, y: 2 };
```

当 JavaScript 引擎执行这段代码时，需要在堆上为对象 `{ x: 1, y: 2 }` 分配内存。 `MaglevAssembler::Allocate` 函数会被调用，根据对象的大小和类型在堆上分配相应的空间。

**2. 函数调用:**

```javascript
function add(a, b) {
  return a + b;
}
add(5, 10);
```

当调用 `add` 函数时，`MaglevAssembler::Prologue` 会生成指令来设置函数的栈帧，包括保存必要的寄存器、分配局部变量空间等。 在函数执行完毕后，可能会有相应的尾声操作。

**3. 字符串操作:**

```javascript
const str = String.fromCharCode(65); // 'A'
const charCode = "Hello".charCodeAt(1); // 101 ('e')
```

- `String.fromCharCode(65)` 的执行会调用到 `MaglevAssembler::StringFromCharCode`，该函数会生成指令来创建一个包含字符 'A' 的字符串对象。它可能会利用 `LoadSingleCharacterString` 来优化常见字符的创建。

- `"Hello".charCodeAt(1)` 的执行会涉及到 `MaglevAssembler::StringCharCodeOrCodePointAt`，该函数会生成指令来读取字符串 "Hello" 中索引为 1 的字符的编码。它需要处理不同字符串的内部表示，例如直接存储字符的 `SeqString`。

**4. 类型转换:**

```javascript
const num = 3.14;
const intNum = parseInt(num); // 3
const index = Math.floor(2.9); // 2
```

- `parseInt(num)` 的执行可能会使用 `MaglevAssembler::TruncateDoubleToInt32` 或 `TryTruncateDoubleToInt32` 将双精度浮点数 `3.14` 转换为整数 `3`。

- `Math.floor(2.9)` 的实现也可能涉及到将浮点数转换为整数，可能会使用类似的转换函数。

**总结:**

`maglev-assembler-arm64.cc` 是 Maglev 编译器在 ARM64 架构下的 "翻译器"，它将 Maglev 编译器的抽象操作转化为实际的机器指令。它提供的功能是 V8 引擎执行 JavaScript 代码的基础，涵盖了内存管理、函数调用、字符串处理和类型转换等核心操作。 理解这个文件的作用有助于深入理解 JavaScript 引擎的底层工作原理。

### 提示词
```
这是目录为v8/src/maglev/arm64/maglev-assembler-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2022 the V8 project authors. All rights reserved.
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
  __ Sub(object, object, size_in_bytes);
  __ Add(object, object, kHeapObjectTag);
}

void SubSizeAndTagObject(MaglevAssembler* masm, Register object,
                         int size_in_bytes) {
  __ Add(object, object, kHeapObjectTag - size_in_bytes);
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
  __ Ldr(object, __ ExternalReferenceAsOperand(top, scratch));
  __ Add(new_top, object, size_in_bytes);
  __ Ldr(scratch, __ ExternalReferenceAsOperand(limit, scratch));
  __ Cmp(new_top, scratch);
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
  DCHECK(graph->is_osr());
  CHECK(!graph->has_recursive_calls());

  uint32_t source_frame_size =
      graph->min_maglev_stackslots_for_unoptimized_frame_size();

  static_assert(StandardFrameConstants::kFixedSlotCount % 2 == 1);
  if (source_frame_size % 2 == 0) source_frame_size++;

  if (v8_flags.maglev_assert_stack_size && v8_flags.debug_code) {
    TemporaryRegisterScope temps(this);
    Register scratch = temps.AcquireScratch();
    Add(scratch, sp,
        source_frame_size * kSystemPointerSize +
            StandardFrameConstants::kFixedFrameSizeFromFp);
    Cmp(scratch, fp);
    Assert(eq, AbortReason::kOsrUnexpectedStackSize);
  }

  uint32_t target_frame_size =
      graph->tagged_stack_slots() + graph->untagged_stack_slots();
  CHECK_EQ(target_frame_size % 2, 1);
  CHECK_LE(source_frame_size, target_frame_size);
  if (source_frame_size < target_frame_size) {
    ASM_CODE_COMMENT_STRING(this, "Growing frame for OSR");
    uint32_t additional_tagged =
        source_frame_size < graph->tagged_stack_slots()
            ? graph->tagged_stack_slots() - source_frame_size
            : 0;
    uint32_t additional_tagged_double =
        additional_tagged / 2 + additional_tagged % 2;
    for (size_t i = 0; i < additional_tagged_double; ++i) {
      Push(xzr, xzr);
    }
    uint32_t size_so_far = source_frame_size + additional_tagged_double * 2;
    CHECK_LE(size_so_far, target_frame_size);
    if (size_so_far < target_frame_size) {
      Sub(sp, sp,
          Immediate((target_frame_size - size_so_far) * kSystemPointerSize));
    }
  }
}

void MaglevAssembler::Prologue(Graph* graph) {
  TemporaryRegisterScope temps(this);
  //  We add two extra registers to the scope. Ideally we could add all the
  //  allocatable general registers, except Context, JSFunction, NewTarget and
  //  ArgCount. Unfortunately, OptimizeCodeOrTailCallOptimizedCodeSlot and
  //  LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing pick random registers and
  //  we could alias those.
  // TODO(victorgomes): Fix these builtins to either use the scope or pass the
  // used registers manually.
  temps.Include({x14, x15});

  DCHECK(!graph->is_osr());

  CallTarget();
  BailoutIfDeoptimized();

  if (graph->has_recursive_calls()) {
    BindCallTarget(code_gen_state()->entry_label());
  }

#ifndef V8_ENABLE_LEAPTIERING
  // Tiering support.
  if (v8_flags.turbofan) {
    using D = MaglevOptimizeCodeOrTailCallOptimizedCodeSlotDescriptor;
    Register flags = D::GetRegisterParameter(D::kFlags);
    Register feedback_vector = D::GetRegisterParameter(D::kFeedbackVector);
    DCHECK(!AreAliased(flags, feedback_vector, kJavaScriptCallArgCountRegister,
                       kJSFunctionRegister, kContextRegister,
                       kJavaScriptCallNewTargetRegister,
                       kJavaScriptCallDispatchHandleRegister));
    DCHECK(!temps.Available().has(flags));
    DCHECK(!temps.Available().has(feedback_vector));
    Move(feedback_vector,
         compilation_info()->toplevel_compilation_unit()->feedback().object());
    Condition needs_processing =
        LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing(flags, feedback_vector,
                                                         CodeKind::MAGLEV);
    TailCallBuiltin(Builtin::kMaglevOptimizeCodeOrTailCallOptimizedCodeSlot,
                    needs_processing);
  }
#endif  // !V8_ENABLE_LEAPTIERING

  EnterFrame(StackFrame::MAGLEV);

  // Save arguments in frame.
  // TODO(leszeks): Consider eliding this frame if we don't make any calls
  // that could clobber these registers.
  // Push the context and the JSFunction.
  Push(kContextRegister, kJSFunctionRegister);
  // Push the actual argument count and a _possible_ stack slot.
  Push(kJavaScriptCallArgCountRegister, xzr);
  int remaining_stack_slots = code_gen_state()->stack_slots() - 1;
  DCHECK_GE(remaining_stack_slots, 0);

  // Initialize stack slots.
  if (graph->tagged_stack_slots() > 0) {
    ASM_CODE_COMMENT_STRING(this, "Initializing stack slots");

    // If tagged_stack_slots is divisible by 2, we overshoot and allocate one
    // extra stack slot, otherwise we allocate exactly the right amount, since
    // one stack has already been allocated.
    int tagged_two_slots_count = graph->tagged_stack_slots() / 2;
    remaining_stack_slots -= 2 * tagged_two_slots_count;

    // Magic value. Experimentally, an unroll size of 8 doesn't seem any
    // worse than fully unrolled pushes.
    const int kLoopUnrollSize = 8;
    if (tagged_two_slots_count < kLoopUnrollSize) {
      for (int i = 0; i < tagged_two_slots_count; i++) {
        Push(xzr, xzr);
      }
    } else {
      TemporaryRegisterScope temps(this);
      Register count = temps.AcquireScratch();
      // Extract the first few slots to round to the unroll size.
      int first_slots = tagged_two_slots_count % kLoopUnrollSize;
      for (int i = 0; i < first_slots; ++i) {
        Push(xzr, xzr);
      }
      Move(count, tagged_two_slots_count / kLoopUnrollSize);
      // We enter the loop unconditionally, so make sure we need to loop at
      // least once.
      DCHECK_GT(tagged_two_slots_count / kLoopUnrollSize, 0);
      Label loop;
      bind(&loop);
      for (int i = 0; i < kLoopUnrollSize; ++i) {
        Push(xzr, xzr);
      }
      Subs(count, count, Immediate(1));
      B(&loop, gt);
    }
  }
  if (remaining_stack_slots > 0) {
    // Round up.
    remaining_stack_slots += (remaining_stack_slots % 2);
    // Extend sp by the size of the remaining untagged part of the frame,
    // no need to initialise these.
    Sub(sp, sp, Immediate(remaining_stack_slots * kSystemPointerSize));
  }
}

void MaglevAssembler::MaybeEmitDeoptBuiltinsCall(size_t eager_deopt_count,
                                                 Label* eager_deopt_entry,
                                                 size_t lazy_deopt_count,
                                                 Label* lazy_deopt_entry) {
  ForceConstantPoolEmissionWithoutJump();

  DCHECK_GE(Deoptimizer::kLazyDeoptExitSize, Deoptimizer::kEagerDeoptExitSize);
  size_t deopt_count = eager_deopt_count + lazy_deopt_count;
  CheckVeneerPool(
      false, false,
      static_cast<int>(deopt_count) * Deoptimizer::kLazyDeoptExitSize);

  TemporaryRegisterScope scope(this);
  Register scratch = scope.AcquireScratch();
  if (eager_deopt_count > 0) {
    Bind(eager_deopt_entry);
    LoadEntryFromBuiltin(Builtin::kDeoptimizationEntry_Eager, scratch);
    MacroAssembler::Jump(scratch);
  }
  if (lazy_deopt_count > 0) {
    Bind(lazy_deopt_entry);
    LoadEntryFromBuiltin(Builtin::kDeoptimizationEntry_Lazy, scratch);
    MacroAssembler::Jump(scratch);
  }
}

void MaglevAssembler::LoadSingleCharacterString(Register result,
                                                Register char_code,
                                                Register scratch) {
  DCHECK_NE(char_code, scratch);
  if (v8_flags.debug_code) {
    Cmp(char_code, Immediate(String::kMaxOneByteCharCode));
    Assert(ls, AbortReason::kUnexpectedValue);
  }
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
  AssertZeroExtended(char_code);
  DCHECK_NE(char_code, scratch);
  ZoneLabelRef done(this);
  if (mask_mode == CharCodeMaskMode::kMustApplyMask) {
    And(char_code, char_code, Immediate(0xFFFF));
  }
  Cmp(char_code, Immediate(String::kMaxOneByteCharCode));
  JumpToDeferredIf(
      hi,
      [](MaglevAssembler* masm, RegisterSnapshot register_snapshot,
         ZoneLabelRef done, Register result, Register char_code,
         Register scratch) {
        // Be sure to save {char_code}. If it aliases with {result}, use
        // the scratch register.
        // TODO(victorgomes): This is probably not needed any more, because
        // we now ensure that results registers don't alias with inputs/temps.
        // Confirm, and drop this check.
        if (char_code.Aliases(result)) {
          __ Move(scratch, char_code);
          char_code = scratch;
        }
        DCHECK(!char_code.Aliases(result));
        DCHECK(!register_snapshot.live_tagged_registers.has(char_code));
        register_snapshot.live_registers.set(char_code);
        __ AllocateTwoByteString(register_snapshot, result, 1);
        __ Strh(
            char_code.W(),
            FieldMemOperand(result, OFFSET_OF_DATA_START(SeqTwoByteString)));
        __ B(*done);
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
        __ jmp(*done);
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

    Ldr(scratch1.W(), FieldMemOperand(string, offsetof(String, length_)));
    Cmp(index.W(), scratch1.W());
    Check(lo, AbortReason::kUnexpectedValue);
  }

#if V8_STATIC_ROOTS_BOOL
  Register map = scratch1.W();
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
    TemporaryRegisterScope temps(this);
    Register representation = temps.AcquireScratch().W();

    // TODO(victorgomes): Add fast path for external strings.
    And(representation, instance_type.W(),
        Immediate(kStringRepresentationMask));
    CompareAndBranch(representation, Immediate(kSeqStringTag), kEqual,
                     &seq_string);
    CompareAndBranch(representation, Immediate(kConsStringTag), kEqual,
                     &cons_string);
    CompareAndBranch(representation, Immediate(kSlicedStringTag), kEqual,
                     &sliced_string);
    CompareAndBranch(representation, Immediate(kThinStringTag), kNotEqual,
                     deferred_runtime_call);
    // Fallthrough to thin string.
#endif
  }

  // Is a thin string.
  {
    LoadTaggedField(string, string, offsetof(ThinString, actual_));
    B(&loop);
  }

  bind(&sliced_string);
  {
    TemporaryRegisterScope temps(this);
    Register offset = temps.AcquireScratch();

    LoadAndUntagTaggedSignedField(offset, string,
                                  offsetof(SlicedString, offset_));
    LoadTaggedField(string, string, offsetof(SlicedString, parent_));
    Add(index, index, offset);
    B(&loop);
  }

  bind(&cons_string);
  {
    // Reuse {instance_type} register here, since CompareRoot requires a scratch
    // register as well.
    Register second_string = scratch1;
    LoadTaggedFieldWithoutDecompressing(second_string, string,
                                        offsetof(ConsString, second_));
    CompareRoot(second_string, RootIndex::kempty_string);
    B(deferred_runtime_call, ne);
    LoadTaggedField(string, string, offsetof(ConsString, first_));
    B(&loop);  // Try again with first string.
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
    TestAndBranchIfAllClear(instance_type, kOneByteStringTag, &two_byte_string);
#endif
    // The result of one-byte string will be the same for both modes
    // (CharCodeAt/CodePointAt), since it cannot be the first half of a
    // surrogate pair.
    Add(index, index, OFFSET_OF_DATA_START(SeqOneByteString) - kHeapObjectTag);
    Ldrb(result, MemOperand(string, index));
    B(result_fits_one_byte);

    bind(&two_byte_string);
    // {instance_type} is unused from this point, so we can use as scratch.
    Register scratch = scratch1;
    Lsl(scratch, index, 1);
    Add(scratch, scratch,
        OFFSET_OF_DATA_START(SeqTwoByteString) - kHeapObjectTag);

    if (mode == BuiltinStringPrototypeCharCodeOrCodePointAt::kCharCodeAt) {
      Ldrh(result, MemOperand(string, scratch));
    } else {
      DCHECK_EQ(mode,
                BuiltinStringPrototypeCharCodeOrCodePointAt::kCodePointAt);
      Register string_backup = string;
      if (result == string) {
        string_backup = scratch2;
        Mov(string_backup, string);
      }
      Ldrh(result, MemOperand(string, scratch));

      Register first_code_point = scratch;
      And(first_code_point.W(), result.W(), Immediate(0xfc00));
      CompareAndBranch(first_code_point, Immediate(0xd800), kNotEqual, *done);

      Register length = scratch;
      Ldr(length.W(),
          FieldMemOperand(string_backup, offsetof(String, length_)));
      Add(index.W(), index.W(), Immediate(1));
      CompareAndBranch(index, length, kGreaterThanEqual, *done);

      Register second_code_point = scratch;
      Lsl(index, index, 1);
      Add(index, index,
          OFFSET_OF_DATA_START(SeqTwoByteString) - kHeapObjectTag);
      Ldrh(second_code_point, MemOperand(string_backup, index));

      // {index} is not needed at this point.
      Register scratch2 = index;
      And(scratch2.W(), second_code_point.W(), Immediate(0xfc00));
      CompareAndBranch(scratch2, Immediate(0xdc00), kNotEqual, *done);

      int surrogate_offset = 0x10000 - (0xd800 << 10) - 0xdc00;
      Add(second_code_point, second_code_point, Immediate(surrogate_offset));
      Lsl(result, result, 10);
      Add(result, result, second_code_point);
    }

    // Fallthrough.
  }

  bind(*done);

  if (v8_flags.debug_code) {
    // We make sure that the user of this macro is not relying in string and
    // index to not be clobbered.
    if (result != string) {
      Mov(string, Immediate(0xdeadbeef));
    }
    if (result != index) {
      Mov(index, Immediate(0xdeadbeef));
    }
  }
}

void MaglevAssembler::TruncateDoubleToInt32(Register dst, DoubleRegister src) {
  if (CpuFeatures::IsSupported(JSCVT)) {
    Fjcvtzs(dst.W(), src);
    return;
  }

  ZoneLabelRef done(this);
  // Try to convert with an FPU convert instruction. It's trivial to compute
  // the modulo operation on an integer register so we convert to a 64-bit
  // integer.
  //
  // Fcvtzs will saturate to INT64_MIN (0x800...00) or INT64_MAX (0x7FF...FF)
  // when the double is out of range. NaNs and infinities will be converted to 0
  // (as ECMA-262 requires).
  Fcvtzs(dst.X(), src);

  // The values INT64_MIN (0x800...00) or INT64_MAX (0x7FF...FF) are not
  // representable using a double, so if the result is one of those then we know
  // that saturation occurred, and we need to manually handle the conversion.
  //
  // It is easy to detect INT64_MIN and INT64_MAX because adding or subtracting
  // 1 will cause signed overflow.
  Cmp(dst.X(), 1);
  Ccmp(dst.X(), -1, VFlag, vc);

  JumpToDeferredIf(
      vs,
      [](MaglevAssembler* masm, DoubleRegister src, Register dst,
         ZoneLabelRef done) {
        __ MacroAssembler::Push(xzr, src);
        __ CallBuiltin(Builtin::kDoubleToI);
        __ Ldr(dst.W(), MemOperand(sp, 0));
        DCHECK_EQ(xzr.SizeInBytes(), src.SizeInBytes());
        __ Drop(2);
        __ B(*done);
      },
      src, dst, done);

  Bind(*done);
  // Zero extend the converted value to complete the truncation.
  Mov(dst, Operand(dst.W(), UXTW));
}

void MaglevAssembler::TryTruncateDoubleToInt32(Register dst, DoubleRegister src,
                                               Label* fail) {
  TemporaryRegisterScope temps(this);
  DoubleRegister converted_back = temps.AcquireScratchDouble();

  // Convert the input float64 value to int32.
  Fcvtzs(dst.W(), src);
  // Convert that int32 value back to float64.
  Scvtf(converted_back, dst.W());
  // Check that the result of the float64->int32->float64 is equal to the input
  // (i.e. that the conversion didn't truncate.
  Fcmp(src, converted_back);
  JumpIf(ne, fail);

  // Check if {input} is -0.
  Label check_done;
  Cbnz(dst, &check_done);

  // In case of 0, we need to check for the IEEE 0 pattern (which is all zeros).
  Register input_bits = temps.AcquireScratch();
  Fmov(input_bits, src);
  Cbnz(input_bits, fail);

  Bind(&check_done);
}

void MaglevAssembler::TryTruncateDoubleToUint32(Register dst,
                                                DoubleRegister src,
                                                Label* fail) {
  TemporaryRegisterScope temps(this);
  DoubleRegister converted_back = temps.AcquireScratchDouble();

  // Convert the input float64 value to uint32.
  Fcvtzu(dst.W(), src);
  // Convert that uint32 value back to float64.
  Ucvtf(converted_back, dst);
  // Check that the result of the float64->uint32->float64 is equal to the input
  // (i.e. that the conversion didn't truncate.
  Fcmp(src, converted_back);
  JumpIf(ne, fail);

  // Check if {input} is -0.
  Label check_done;
  Cbnz(dst, &check_done);

  // In case of 0, we need to check for the IEEE 0 pattern (which is all zeros).
  Register input_bits = temps.AcquireScratch();
  Fmov(input_bits, src);
  Cbnz(input_bits, fail);

  Bind(&check_done);
}

void MaglevAssembler::TryChangeFloat64ToIndex(Register result,
                                              DoubleRegister value,
                                              Label* success, Label* fail) {
  TemporaryRegisterScope temps(this);
  DoubleRegister converted_back = temps.AcquireScratchDouble();
  // Convert the input float64 value to int32.
  Fcvtzs(result.W(), value);
  // Convert that int32 value back to float64.
  Scvtf(converted_back, result.W());
  // Check that the result of the float64->int32->float64 is equal to
  // the input (i.e. that the conversion didn't truncate).
  Fcmp(value, converted_back);
  JumpIf(kNotEqual, fail);
  Jump(success);
}

}  // namespace maglev
}  // namespace internal
}  // namespace v8
```