Response: Let's break down the thought process for analyzing this C++ file and generating the summary and JavaScript examples.

1. **Understand the Goal:** The request asks for a functional summary of a C++ file (`maglev-assembler-riscv.cc`) and wants to know its relationship to JavaScript, illustrating this with JavaScript examples.

2. **Initial Scan for Keywords and Structure:**  Read through the code, paying attention to:
    * **Includes:**  These reveal dependencies and the general area of the codebase. Seeing things like `"src/codegen/"`, `"src/deoptimizer/"`, `"src/maglev/"` strongly suggests this is related to code generation and optimization within V8's Maglev compiler. The `"riscv"` in the filename confirms the target architecture.
    * **Namespaces:** `v8::internal::maglev` confirms the Maglev context.
    * **Macros:** `#define __ masm->` is a common V8 pattern to shorten `masm->` calls, indicating the presence of an assembler object.
    * **Function Names:** Look for verbs like `Allocate`, `OSRPrologue`, `Prologue`, `Load`, `StringFromCharCode`, `TruncateDoubleToInt32`. These names hint at the actions the code performs.
    * **Data Types:**  `Register`, `DoubleRegister`, `Label`, `Operand` suggest low-level code manipulation and assembly concepts.
    * **Comments:**  Pay attention to comments like "Growing frame for OSR" or explanations of register usage. They offer valuable insights.
    * **Conditional Compilation:** `#if V8_STATIC_ROOTS_BOOL` indicates platform-specific or feature-dependent code.

3. **Identify Core Functionality:** Based on the keywords and function names, start grouping related functions:
    * **Memory Allocation:** `AllocateRaw`, `Allocate`, `SubSizeAndTagObject`. These clearly deal with allocating memory for objects on the heap.
    * **Stack Management:** `OSRPrologue`, `Prologue`, `EnterFrame`, `Push`, `Sub64`. These functions are responsible for setting up the execution stack for functions. The "OSR" in `OSRPrologue` stands for On-Stack Replacement, an optimization technique.
    * **Deoptimization:** `MaybeEmitDeoptBuiltinsCall`. This handles the process of reverting from optimized code back to the interpreter.
    * **String Manipulation:** `LoadSingleCharacterString`, `StringFromCharCode`, `StringCharCodeOrCodePointAt`. These are related to accessing and creating JavaScript strings.
    * **Type Checking:** `IsObjectType`. This checks the type of a JavaScript object.
    * **Number Conversion:** `TruncateDoubleToInt32`, `TryTruncateDoubleToInt32`, `TryTruncateDoubleToUint32`, `TryChangeFloat64ToIndex`. These handle conversions between floating-point numbers and integers.

4. **Connect to JavaScript:**  Think about how these low-level operations relate to high-level JavaScript concepts:
    * **Memory Allocation:**  JavaScript's dynamic nature requires allocating memory for objects and variables at runtime. The `Allocate` functions are directly involved in this.
    * **Stack Management:** When a JavaScript function is called, a stack frame is created to store local variables and execution context. `Prologue` and `OSRPrologue` are part of this process.
    * **Deoptimization:** When optimized code encounters a situation it can't handle (e.g., a type assumption is violated), it needs to "deoptimize" back to the interpreter.
    * **String Manipulation:** JavaScript has built-in string methods like `charCodeAt`, `codePointAt`, and string concatenation. The functions here provide the low-level implementation for these.
    * **Type Checking:** JavaScript is dynamically typed, so type checks are often performed at runtime. `IsObjectType` is an example of this.
    * **Number Conversion:** JavaScript automatically performs type conversions. The `TruncateDoubleToInt32` family of functions implements the underlying logic for converting floating-point numbers to integers.

5. **Formulate the Summary:**  Based on the identified functionalities, write a concise summary highlighting the core responsibilities of the file. Emphasize its role in code generation and optimization for the RISC-V architecture within the Maglev compiler.

6. **Create JavaScript Examples:** For each core functionality, devise simple JavaScript code snippets that would *implicitly* trigger the underlying C++ code. Focus on the *observable* behavior in JavaScript that corresponds to the low-level operations. For example:
    * **Allocation:**  Creating objects and arrays in JavaScript forces memory allocation.
    * **Stack Management:** Function calls inherently involve stack frame manipulation.
    * **String Manipulation:** Using string methods like `charCodeAt` directly relates to the C++ string functions.
    * **Type Checking:**  Using `typeof` or comparing object types will indirectly involve type checking in the engine.
    * **Number Conversion:**  Using `parseInt` or bitwise operators will trigger numeric conversions.

7. **Refine and Review:** Read through the summary and examples to ensure clarity, accuracy, and conciseness. Make sure the JavaScript examples are simple and effectively illustrate the connection. For instance, initially, I might have just put `new Object()` as an allocation example, but specifying `const obj = { key: 'value' };` is slightly more illustrative. Similarly, for type checking, using `instanceof` provides a clearer connection.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe focus heavily on the assembly instructions. **Correction:**  The request asks for *functionality*, so focus on the higher-level purpose of the code rather than getting bogged down in assembly details.
* **Initial examples:** Maybe use complex JavaScript examples. **Correction:** Keep the JavaScript examples simple and directly related to the described C++ functionality. The goal is to illustrate the connection, not to demonstrate advanced JavaScript features.
* **Connecting to JavaScript:**  Initially, it might be difficult to pinpoint the *exact* JavaScript code that calls a specific C++ function. **Correction:** Focus on the *general* JavaScript constructs that would necessitate the described low-level operations. Direct function mapping isn't always feasible or necessary for this kind of analysis.
* **Clarity of language:** Ensure the summary uses clear and accessible language, avoiding excessive technical jargon where possible.

By following this thought process, which involves scanning, identifying, connecting, and refining, one can effectively analyze a complex C++ file and explain its role in the context of a higher-level language like JavaScript.
这个C++源代码文件 `v8/src/maglev/riscv/maglev-assembler-riscv.cc` 是 **V8 JavaScript 引擎** 中 **Maglev 编译器** 的一部分，专门针对 **RISC-V 架构**。它定义了一个 `MaglevAssembler` 类，该类提供了一组用于生成 RISC-V 机器码的抽象接口。

**主要功能归纳:**

1. **RISC-V 汇编指令封装:**  `MaglevAssembler` 封装了底层的 RISC-V 汇编指令，提供了更高级别的 C++ 方法来生成这些指令。这使得 Maglev 编译器可以用一种更易于管理和理解的方式生成机器码，而无需直接编写汇编代码。  你可以看到很多 `__ AddWord()`, `__ SubWord()`, `__ Lw()`, `__ Sw()` 等类似汇编指令的调用。这里的 `__` 实际上是 `#define __ masm->`，表示调用 `MaglevAssembler` 对象 `masm` 的方法。

2. **对象内存分配:** 提供了 `Allocate` 系列方法，用于在堆上分配 JavaScript 对象所需的内存。这些方法考虑了不同的分配类型（例如，新生代、老年代）和对齐方式。

3. **函数序言和尾声:**  包含了 `Prologue` 和 `OSRPrologue` 方法，用于生成函数调用的标准序言代码，包括创建栈帧、保存寄存器等。`OSRPrologue` 专门用于 On-Stack Replacement (OSR) 优化，即在函数执行过程中从解释器切换到优化后的代码。

4. **去优化支持:**  `MaybeEmitDeoptBuiltinsCall` 方法用于在需要时生成调用去优化入口的代码。当优化后的代码遇到无法处理的情况时，需要回退到解释器执行。

5. **字符串操作:** 提供了 `LoadSingleCharacterString` 和 `StringFromCharCode` 等方法，用于高效地创建和访问 JavaScript 字符串。这些方法利用了 V8 内部的字符串表示。

6. **类型检查:** `IsObjectType` 方法用于检查 JavaScript 对象的类型。

7. **数值转换:**  提供了 `TruncateDoubleToInt32` 等方法，用于将 JavaScript 中的双精度浮点数转换为 32 位整数。

8. **内置函数调用:**  `TailCallBuiltin` 用于尾调用内置的 V8 函数。

**与 JavaScript 功能的关系及 JavaScript 示例:**

这个文件直接参与了将 JavaScript 代码编译成高效的机器码的过程。Maglev 编译器是 V8 的一个中间层编译器，它将 Abstract Syntax Tree (AST) 转换成机器码。  `MaglevAssembler` 正是 Maglev 编译器生成 RISC-V 机器码的关键工具。

以下是一些 JavaScript 代码示例，它们的操作可能会导致 `maglev-assembler-riscv.cc` 中的某些功能被调用：

**1. 对象创建和内存分配 (对应 `Allocate`):**

```javascript
const obj = { key: 'value' }; // 创建一个对象，需要分配内存
const arr = [1, 2, 3];        // 创建一个数组，也需要分配内存
```

当 Maglev 编译这段 JavaScript 代码时，会调用 `Allocate` 系列方法来在堆上为 `obj` 和 `arr` 分配内存。

**2. 函数调用 (对应 `Prologue`):**

```javascript
function add(a, b) {
  return a + b;
}

add(5, 10); // 调用函数
```

当 Maglev 编译 `add` 函数时，`Prologue` 方法会被调用，生成设置函数栈帧的代码，为局部变量和参数分配空间。

**3. 字符串操作 (对应 `StringFromCharCode` 等):**

```javascript
const charCode = 65;
const str = String.fromCharCode(charCode); // 从字符编码创建字符串 'A'

const text = "hello";
const char = text.charAt(0);             // 获取字符串的第一个字符 'h'
```

`String.fromCharCode()` 的实现可能会使用 `StringFromCharCode` 在内存中创建单字符字符串。`charAt()` 的实现可能涉及到访问字符串的内部表示，这与 `LoadSingleCharacterString` 等方法有关。

**4. 类型检查 (对应 `IsObjectType`):**

```javascript
const x = 10;
if (typeof x === 'number') {
  console.log('x is a number');
}

const obj = {};
if (obj instanceof Object) {
  console.log('obj is an object');
}
```

`typeof` 操作符和 `instanceof` 运算符在底层需要进行类型检查。当 Maglev 编译这些代码时，可能会使用 `IsObjectType` 来判断变量的类型。

**5. 数值转换 (对应 `TruncateDoubleToInt32`):**

```javascript
const floatNum = 3.14;
const intNum = parseInt(floatNum); // 将浮点数转换为整数 3

const result = floatNum | 0;      // 使用位运算将浮点数转换为整数 3
```

`parseInt()` 函数和位运算在将浮点数转换为整数时，在底层可能会调用 `TruncateDoubleToInt32` 或类似的函数来执行截断操作。

**总结:**

`v8/src/maglev/riscv/maglev-assembler-riscv.cc` 文件是 V8 引擎中 Maglev 编译器针对 RISC-V 架构的关键组成部分。它通过提供 C++ 接口来生成 RISC-V 机器码，实现了诸如内存分配、函数调用、字符串操作、类型检查和数值转换等 JavaScript 核心功能所需的底层操作。了解这个文件有助于深入理解 V8 如何将 JavaScript 代码高效地转换为机器码并在 RISC-V 架构上执行。

Prompt: 
```
这是目录为v8/src/maglev/riscv/maglev-assembler-riscv.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2024 the V8 project authors. All rights reserved.
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

void SubSizeAndTagObject(MaglevAssembler* masm, Register object,
                         Register size_in_bytes) {
  __ SubWord(object, object, Operand(size_in_bytes));
  __ AddWord(object, object, Operand(kHeapObjectTag));
}

void SubSizeAndTagObject(MaglevAssembler* masm, Register object,
                         int size_in_bytes) {
  __ AddWord(object, object, Operand(kHeapObjectTag - size_in_bytes));
}

template <typename T>
void AllocateRaw(MaglevAssembler* masm, Isolate* isolate,
                 RegisterSnapshot register_snapshot, Register object,
                 T size_in_bytes, AllocationType alloc_type,
                 AllocationAlignment alignment) {
  DCHECK(masm->allow_allocate());
  // TODO(victorgomes): Call the runtime for large object allocation.
  // TODO(victorgomes): Support double alignment.
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
  __ LoadWord(object, __ ExternalReferenceAsOperand(top, scratch));
  __ AddWord(new_top, object, Operand(size_in_bytes));
  __ LoadWord(scratch, __ ExternalReferenceAsOperand(limit, scratch));

  // Call runtime if new_top >= limit.
  __ MacroAssembler::Branch(
      __ MakeDeferredCode(
          [](MaglevAssembler* masm, RegisterSnapshot register_snapshot,
             Register object, AllocationType alloc_type, T size_in_bytes,
             ZoneLabelRef done) {
            AllocateSlow(masm, register_snapshot, object,
                         AllocateBuiltin(alloc_type), size_in_bytes, done);
          },
          register_snapshot, object, alloc_type, size_in_bytes, done),
      ge, new_top, Operand(scratch));

  // Store new top and tag object.
  __ Move(__ ExternalReferenceAsOperand(top, scratch), new_top);
  SubSizeAndTagObject(masm, object, size_in_bytes);
  __ bind(*done);
}

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

  if (v8_flags.maglev_assert_stack_size && v8_flags.debug_code) {
    MaglevAssembler::TemporaryRegisterScope temps(this);
    Register scratch = temps.AcquireScratch();
    int32_t expected_osr_stack_size =
        source_frame_size * kSystemPointerSize +
        StandardFrameConstants::kFixedFrameSizeFromFp;
    AddWord(scratch, sp, Operand(expected_osr_stack_size));
    MacroAssembler::Assert(eq, AbortReason::kOsrUnexpectedStackSize, scratch,
                           Operand(fp));
  }

  uint32_t target_frame_size =
      graph->tagged_stack_slots() + graph->untagged_stack_slots();
  // CHECK_EQ(target_frame_size % 2, 1);
  CHECK_LE(source_frame_size, target_frame_size);
  if (source_frame_size < target_frame_size) {
    ASM_CODE_COMMENT_STRING(this, "Growing frame for OSR");
    uint32_t additional_tagged =
        source_frame_size < graph->tagged_stack_slots()
            ? graph->tagged_stack_slots() - source_frame_size
            : 0;
    for (size_t i = 0; i < additional_tagged; ++i) {
      Push(zero_reg);
    }
    uint32_t size_so_far = source_frame_size + additional_tagged;
    CHECK_LE(size_so_far, target_frame_size);
    if (size_so_far < target_frame_size) {
      Sub64(sp, sp,
            Operand((target_frame_size - size_so_far) * kSystemPointerSize));
    }
  }
}

void MaglevAssembler::Prologue(Graph* graph) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  //  We add two extra registers to the scope. Ideally we could add all the
  //  allocatable general registers, except Context, JSFunction, NewTarget and
  //  ArgCount. Unfortunately, OptimizeCodeOrTailCallOptimizedCodeSlot and
  //  LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing pick random registers and
  //  we could alias those.
  // TODO(victorgomes): Fix these builtins to either use the scope or pass the
  // used registers manually.
  temps.Include({s7, s8});  // use register not overlapping with flags,
                            // feedback and so on
  DCHECK(!graph->is_osr());

  CallTarget();
  BailoutIfDeoptimized();

  if (graph->has_recursive_calls()) {
    BindCallTarget(code_gen_state()->entry_label());
  }

  // Tiering support.
  if (v8_flags.turbofan) {
    using D = MaglevOptimizeCodeOrTailCallOptimizedCodeSlotDescriptor;
    Register flags = D::GetRegisterParameter(D::kFlags);
    Register feedback_vector = D::GetRegisterParameter(D::kFeedbackVector);
    DCHECK(!AreAliased(
        flags, feedback_vector,
        kJavaScriptCallArgCountRegister,  // flags - t4, feedback - a6,
                                          // kJavaScriptCallArgCountRegister -
                                          // a0
        kJSFunctionRegister, kContextRegister,
        kJavaScriptCallNewTargetRegister));
    DCHECK(!temps.Available().has(flags));
    DCHECK(!temps.Available().has(feedback_vector));
    Move(feedback_vector,
         compilation_info()->toplevel_compilation_unit()->feedback().object());
    constexpr Register flag_reg = MaglevAssembler::GetFlagsRegister();
    Condition needs_processing =
        LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing(
            flags, feedback_vector, flag_reg, CodeKind::MAGLEV);
    TailCallBuiltin(Builtin::kMaglevOptimizeCodeOrTailCallOptimizedCodeSlot,
                    needs_processing, flag_reg, Operand(zero_reg));
  }

  EnterFrame(StackFrame::MAGLEV);
  // Save arguments in frame.
  // TODO(leszeks): Consider eliding this frame if we don't make any calls
  // that could clobber these registers.
  // Push the context and the JSFunction.
  Push(kContextRegister);
  Push(kJSFunctionRegister);
  // Push the actual argument count and a _possible_ stack slot.
  Push(kJavaScriptCallArgCountRegister);
  // Initialize stack slots.
  if (graph->tagged_stack_slots() > 0) {
    ASM_CODE_COMMENT_STRING(this, "Initializing stack slots");

    // Magic value. Experimentally, an unroll size of 8 doesn't seem any
    // worse than fully unrolled pushes.
    const int kLoopUnrollSize = 8;
    int tagged_slots = graph->tagged_stack_slots();

    if (tagged_slots < 2 * kLoopUnrollSize) {
      // If the frame is small enough, just unroll the frame fill
      // completely.
      for (int i = 0; i < tagged_slots; ++i) {
        Push(zero_reg);
      }
    } else {
      // Extract the first few slots to round to the unroll size.
      int first_slots = tagged_slots % kLoopUnrollSize;
      for (int i = 0; i < first_slots; ++i) {
        Push(zero_reg);
      }
      MaglevAssembler::TemporaryRegisterScope temps(this);
      Register count = temps.AcquireScratch();
      Move(count, tagged_slots / kLoopUnrollSize);
      // We enter the loop unconditionally, so make sure we need to loop at
      // least once.
      DCHECK_GT(tagged_slots / kLoopUnrollSize, 0);
      Label loop;
      bind(&loop);
      for (int i = 0; i < kLoopUnrollSize; ++i) {
        Push(zero_reg);
      }
      Sub64(count, count, Operand(1));
      MacroAssembler::Branch(&loop, gt, count, Operand(zero_reg), Label::kNear);
    }
  }
  if (graph->untagged_stack_slots() > 0) {
    // Extend sp by the size of the remaining untagged part of the frame,
    // no need to initialise these.
    Sub64(sp, sp, Operand(graph->untagged_stack_slots() * kSystemPointerSize));
  }
}

void MaglevAssembler::MaybeEmitDeoptBuiltinsCall(size_t eager_deopt_count,
                                                 Label* eager_deopt_entry,
                                                 size_t lazy_deopt_count,
                                                 Label* lazy_deopt_entry) {
  ForceConstantPoolEmissionWithoutJump();

  DCHECK_GE(Deoptimizer::kLazyDeoptExitSize, Deoptimizer::kEagerDeoptExitSize);

  MaglevAssembler::TemporaryRegisterScope scope(this);
  Register scratch = scope.AcquireScratch();
  if (eager_deopt_count > 0) {
    bind(eager_deopt_entry);
    LoadEntryFromBuiltin(Builtin::kDeoptimizationEntry_Eager, scratch);
    MacroAssembler::Jump(scratch);
  }
  if (lazy_deopt_count > 0) {
    bind(lazy_deopt_entry);
    LoadEntryFromBuiltin(Builtin::kDeoptimizationEntry_Lazy, scratch);
    MacroAssembler::Jump(scratch);
  }
}

void MaglevAssembler::LoadSingleCharacterString(Register result,
                                                Register char_code,
                                                Register scratch) {
  DCHECK_NE(char_code, scratch);
  if (v8_flags.debug_code) {
    MacroAssembler::Assert(less_equal, AbortReason::kUnexpectedValue, char_code,
                           Operand(String::kMaxOneByteCharCode));
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
    And(char_code, char_code, Operand(0xFFFF));
  }
  // Allocate two-bytes string if {char_code} doesn't fit one byte.
  MacroAssembler::Branch(  // FIXME: reimplement with JumpToDeferredIf
      MakeDeferredCode(
          [](MaglevAssembler* masm, RegisterSnapshot register_snapshot,
             ZoneLabelRef done, Register result, Register char_code,
             Register scratch) {
            MaglevAssembler::TemporaryRegisterScope temps(masm);
            // Ensure that {result} never aliases {scratch}, otherwise use
            // a temporary register to restore {result} at the end.
            const bool need_restore_result = (scratch == result);
            Register string =
                need_restore_result ? temps.AcquireScratch() : result;
            // Ensure that {char_code} never aliases {result}, otherwise use
            // the given {scratch} register.
            if (char_code == result) {
              __ Move(scratch, char_code);
              char_code = scratch;
            }
            DCHECK(char_code != string);
            DCHECK(scratch != string);
            DCHECK(!register_snapshot.live_tagged_registers.has(char_code));
            register_snapshot.live_registers.set(char_code);
            __ AllocateTwoByteString(register_snapshot, string, 1);
            __ And(scratch, char_code, Operand(0xFFFF));
            __ Sh(scratch, FieldMemOperand(
                               string, OFFSET_OF_DATA_START(SeqTwoByteString)));
            if (need_restore_result) {
              __ Move(result, string);
            }
            __ jmp(*done);
          },
          register_snapshot, done, result, char_code, scratch),
      Ugreater_equal, char_code, Operand(String::kMaxOneByteCharCode));

  if (char_code_fits_one_byte != nullptr) {
    bind(char_code_fits_one_byte);
  }
  LoadSingleCharacterString(result, char_code, scratch);
  bind(*done);
}
// Sets equality flag in pseudo flags reg.
void MaglevAssembler::IsObjectType(Register object, Register scratch1,
                                   Register scratch2, InstanceType type) {
  ASM_CODE_COMMENT(this);
  constexpr Register flags = MaglevAssembler::GetFlagsRegister();
#if V8_STATIC_ROOTS_BOOL
  if (InstanceTypeChecker::UniqueMapOfInstanceType(type)) {
    LoadCompressedMap(scratch1, object);
    CompareInstanceTypeWithUniqueCompressedMap(
        scratch1, scratch1 != scratch2 ? scratch2 : Register::no_reg(), type);
    return;
  }
#endif  // V8_STATIC_ROOTS_BOOL
  Label ConditionMet, Done;
  CompareObjectTypeAndJump(object, scratch1, scratch2, type, Condition::kEqual,
                           &ConditionMet, Label::kNear);
  Li(flags, 1);  // Condition is not met by default and
                 // flags is set after a scratch is used,
                 // so no harm if they are aliased.
  Jump(&Done, Label::kNear);
  bind(&ConditionMet);
  Mv(flags, zero_reg);  // Condition is met
  bind(&Done);
}

void MaglevAssembler::StringCharCodeOrCodePointAt(
    BuiltinStringPrototypeCharCodeOrCodePointAt::Mode mode,
    RegisterSnapshot& register_snapshot, Register result, Register string,
    Register index, Register instance_type, [[maybe_unused]] Register scratch2,
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
    Register scratch = instance_type;

    // Check if {string} is a string.
    AssertObjectTypeInRange(string, FIRST_STRING_TYPE, LAST_STRING_TYPE,
                            AbortReason::kUnexpectedValue);

    Lw(scratch, FieldMemOperand(string, offsetof(String, length_)));
    Check(kUnsignedLessThan, AbortReason::kUnexpectedValue, index,
          Operand(scratch));
  }

  // Get instance type.
  LoadInstanceType(instance_type, string);

  {
    MaglevAssembler::TemporaryRegisterScope temps(this);
    Register representation = temps.AcquireScratch();

    // TODO(victorgomes): Add fast path for external strings.
    And(representation, instance_type, Operand(kStringRepresentationMask));
    MacroAssembler::Branch(&seq_string, kEqual, representation,
                           Operand(kSeqStringTag), Label::kNear);
    MacroAssembler::Branch(&cons_string, kEqual, representation,
                           Operand(kConsStringTag), Label::kNear);
    MacroAssembler::Branch(&sliced_string, kEqual, representation,
                           Operand(kSlicedStringTag), Label::kNear);
    MacroAssembler::Branch(deferred_runtime_call, kNotEqual, representation,
                           Operand(kThinStringTag));
    // Fallthrough to thin string.
  }

  // Is a thin string.
  {
    LoadTaggedField(string, string, offsetof(ThinString, actual_));
    MacroAssembler::Branch(&loop, Label::kNear);
  }

  bind(&sliced_string);
  {
    MaglevAssembler::TemporaryRegisterScope temps(this);
    Register offset = temps.AcquireScratch();

    LoadAndUntagTaggedSignedField(offset, string,
                                  offsetof(SlicedString, offset_));
    LoadTaggedField(string, string, offsetof(SlicedString, parent_));
    Add32(index, index, Operand(offset));
    MacroAssembler::Branch(&loop, Label::kNear);
  }

  bind(&cons_string);
  {
    // Reuse {instance_type} register here, since CompareRoot requires a scratch
    // register as well.
    Register second_string = instance_type;
    LoadTaggedFieldWithoutDecompressing(second_string, string,
                                        offsetof(ConsString, second_));
    CompareRoot(second_string,
                RootIndex::kempty_string);  // Sets 1 to flag if not equal
    JumpIf(ne, deferred_runtime_call);      // Check the flag to not be equal 0
    LoadTaggedField(string, string, offsetof(ConsString, first_));
    MacroAssembler::Branch(&loop,
                           Label::kNear);  // Try again with first string.
  }

  bind(&seq_string);
  {
    Label two_byte_string;
    And(instance_type, instance_type, Operand(kStringEncodingMask));
    MacroAssembler::Branch(&two_byte_string, equal, instance_type,
                           Operand(kTwoByteStringTag), Label::kNear);
    // The result of one-byte string will be the same for both modes
    // (CharCodeAt/CodePointAt), since it cannot be the first half of a
    // surrogate pair.
    AddWord(result, string, Operand(index));
    Lbu(result, MemOperand(result, OFFSET_OF_DATA_START(SeqOneByteString) -
                                       kHeapObjectTag));
    MacroAssembler::Branch(result_fits_one_byte);

    bind(&two_byte_string);
    // {instance_type} is unused from this point, so we can use as scratch.
    Register scratch = instance_type;

    Register scaled_index = scratch;
    Sll32(scaled_index, index, Operand(1));
    AddWord(result, string, Operand(scaled_index));
    Lhu(result, MemOperand(result, OFFSET_OF_DATA_START(SeqTwoByteString) -
                                       kHeapObjectTag));

    if (mode == BuiltinStringPrototypeCharCodeOrCodePointAt::kCodePointAt) {
      Register first_code_point = scratch;
      And(first_code_point, result, Operand(0xfc00));
      MacroAssembler::Branch(*done, kNotEqual, first_code_point,
                             Operand(0xd800), Label::kNear);

      Register length = scratch;
      Lw(length, FieldMemOperand(string, offsetof(String, length_)));
      Add32(index, index, Operand(1));
      MacroAssembler::Branch(*done, kGreaterThanEqual, index, Operand(length),
                             Label::kNear);

      Register second_code_point = scratch;
      Sll32(second_code_point, index, Operand(1));
      AddWord(second_code_point, string, second_code_point);
      Lhu(second_code_point,
          MemOperand(second_code_point,
                     OFFSET_OF_DATA_START(SeqTwoByteString) - kHeapObjectTag));

      // {index} is not needed at this point.
      Register scratch2 = index;
      And(scratch2, second_code_point, Operand(0xfc00));
      MacroAssembler::Branch(*done, kNotEqual, scratch2, Operand(0xdc00),
                             Label::kNear);

      int surrogate_offset = 0x10000 - (0xd800 << 10) - 0xdc00;
      Add32(second_code_point, second_code_point, Operand(surrogate_offset));
      Sll32(result, result, Operand(10));
      Add32(result, result, Operand(second_code_point));
    }

    // Fallthrough.
  }

  bind(*done);

  if (v8_flags.debug_code) {
    // We make sure that the user of this macro is not relying in string and
    // index to not be clobbered.
    if (result != string) {
      Li(string, 0xdeadbeef);
    }
    if (result != index) {
      Li(index, 0xdeadbeef);
    }
  }
}

void MaglevAssembler::TruncateDoubleToInt32(Register dst, DoubleRegister src) {
  ZoneLabelRef done(this);
  Label* slow_path = MakeDeferredCode(
      [](MaglevAssembler* masm, DoubleRegister src, Register dst,
         ZoneLabelRef done) {
        __ push(ra);
        __ AllocateStackSpace(kDoubleSize);
        __ StoreDouble(src, MemOperand(sp, 0));
        __ CallBuiltin(Builtin::kDoubleToI);
        __ LoadWord(dst, MemOperand(sp, 0));
        __ AddWord(sp, sp, Operand(kDoubleSize));
        __ pop(ra);
        __ Jump(*done);
      },
      src, dst, done);
  TryInlineTruncateDoubleToI(dst, src, *done);
  Jump(slow_path);
  bind(*done);
  ZeroExtendWord(dst, dst);  // FIXME: is zero extension really needed here?
}

void MaglevAssembler::TryTruncateDoubleToInt32(Register dst, DoubleRegister src,
                                               Label* fail) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  DoubleRegister converted_back = temps.AcquireScratchDouble();
  Register rcmp = temps.AcquireScratch();

  // Convert the input float64 value to int32.
  Trunc_w_d(dst, src);
  // Convert that int32 value back to float64.
  Cvt_d_w(converted_back, dst);
  // Check that the result of the float64->int32->float64 is equal to the input
  // (i.e. that the conversion didn't truncate).
  CompareF64(rcmp, EQ, src, converted_back);  // rcmp is 0 if not equal
  MacroAssembler::Branch(
      fail, eq, rcmp, Operand(zero_reg));  // if we don't know branch distance
  // then lets use MacroAssembler::Branch, it will make sure we fit

  // Check if {input} is -0.
  Label check_done;
  BranchShort(&check_done, ne, dst, Operand(zero_reg));

  // In case of 0, we need to check for the IEEE 0 pattern (which is all zeros).
  MacroAssembler::Move(
      rcmp, src);  // FIXME: should we enable this in MaglevAssembler as well?

  MacroAssembler::Branch(fail, ne, rcmp, Operand(zero_reg));

  bind(&check_done);
}

void MaglevAssembler::TryTruncateDoubleToUint32(Register dst,
                                                DoubleRegister src,
                                                Label* fail) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  DoubleRegister converted_back = temps.AcquireScratchDouble();
  Register rcmp = temps.AcquireScratch();

  // Convert the input float64 value to uint32.
  Trunc_uw_d(dst, src);
  // Convert that uint32 value back to float64.
  Cvt_d_uw(converted_back, dst);
  // Check that the result of the float64->uint32->float64 is equal to the input
  // (i.e. that the conversion didn't truncate).
  CompareF64(rcmp, EQ, src, converted_back);  // rcmp is 0 if not equal
  MacroAssembler::Branch(fail, eq, rcmp, Operand(zero_reg));

  // Check if {input} is -0.
  Label check_done;
  BranchShort(&check_done, ne, dst, Operand(zero_reg));

  // In case of 0, we need to check for the IEEE 0 pattern (which is all zeros).
  MacroAssembler::Move(
      rcmp, src);  // FIXME: should we enable this in MaglevAssembler as well?

  MacroAssembler::Branch(fail, ne, rcmp, Operand(zero_reg));

  bind(&check_done);
}

void MaglevAssembler::TryChangeFloat64ToIndex(Register result,
                                              DoubleRegister value,
                                              Label* success, Label* fail) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  DoubleRegister converted_back = temps.AcquireScratchDouble();
  Register rcmp = temps.AcquireScratch();

  // Convert the input float64 value to int32.
  Trunc_w_d(result, value);
  // Convert that int32 value back to float64.
  Cvt_d_w(converted_back, result);
  // Check that the result of the float64->int32->float64 is equal to
  // the input (i.e. that the conversion didn't truncate).
  CompareF64(rcmp, EQ, value, converted_back);  // rcmp is 0 if not equal
  MacroAssembler::Branch(fail, eq, rcmp, Operand(zero_reg));
  Jump(success);
}

}  // namespace maglev
}  // namespace internal
}  // namespace v8

"""

```