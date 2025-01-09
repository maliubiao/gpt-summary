Response:
The user wants to understand the functionality of the provided C++ code snippet from V8's `maglev-assembler-s390.cc`. I need to analyze the code and explain its purpose within the V8 JavaScript engine.

Here's a breakdown of the thought process:

1. **Identify the file's location and name:** The file is `v8/src/maglev/s390/maglev-assembler-s390.cc`. This tells us it's part of the Maglev compiler for the s390 architecture. The `.cc` extension indicates it's C++ source code.

2. **Look for key V8 concepts:** The code includes headers like `interface-descriptors-inl.h`, `deoptimizer.h`, and `maglev-assembler-inl.h`. These point to core V8 functionalities like function call interfaces, deoptimization mechanisms, and the Maglev assembler itself.

3. **Analyze the namespaces:** The code resides within `v8::internal::maglev`. This confirms its relation to the Maglev compiler within V8's internal implementation.

4. **Examine the macros and helper functions:** The `#define __ masm->` is a common V8 pattern for simplifying assembler instruction emission. The `SubSizeAndTagObject` functions suggest operations related to object allocation and tagging in the V8 heap.

5. **Focus on the main class: `MaglevAssembler`:** The provided code defines several methods within the `MaglevAssembler` class. These methods likely correspond to common code generation tasks within the Maglev compiler for the s390 architecture.

6. **Analyze individual methods:**  I will go through each method and try to understand its purpose:
    * `AllocateRaw`:  This clearly deals with allocating raw memory in the V8 heap. The parameters suggest handling different allocation types and alignments. The logic involves checking for available space and potentially calling the runtime for slow-path allocation.
    * `Allocate`: These are wrappers around `AllocateRaw`, providing different ways to specify the size.
    * `OSRPrologue`:  This stands for On-Stack Replacement Prologue. It's related to optimizing code while the function is already running. The code seems to adjust the stack frame size.
    * `Prologue`: This is the standard function prologue, setting up the stack frame. It includes handling tiering (switching between different optimization levels) and initializing stack slots.
    * `MaybeEmitDeoptBuiltinsCall`:  This seems related to emitting calls to deoptimization builtins, likely based on the number of eager and lazy deoptimizations. However, the provided implementation is empty.
    * `LoadSingleCharacterString`: This function likely retrieves a single-character string object from a pre-allocated table based on a character code.
    * `StringFromCharCode`:  This function converts a character code to a string. It handles both one-byte and two-byte character encodings.
    * `StringCharCodeOrCodePointAt`:  This is a more complex function that retrieves the character code or code point at a specific index within a string. It handles different string representations (sequential, cons, sliced, thin).
    * `TruncateDoubleToInt32`, `TryTruncateDoubleToInt32`, `TryTruncateDoubleToUint32`, `TryChangeFloat64ToIndex`: These functions deal with converting floating-point numbers to integers, with different levels of precision and error handling. They seem to use inline assembly instructions for efficiency and fall back to runtime calls for more complex cases.

7. **Consider the file extension question:** The question asks about the `.tq` extension. I know that `.tq` files in V8 are related to Torque, V8's internal DSL for defining builtins. Since the file has a `.cc` extension, it's C++ code, not Torque.

8. **Think about JavaScript connections:** Several functions directly relate to JavaScript string manipulation (e.g., `StringFromCharCode`, `StringCharCodeOrCodePointAt`) and number conversions (e.g., the truncation functions).

9. **Look for potential errors and assumptions:** The allocation functions assume tagged alignment. The string functions make assumptions about string representations. The truncation functions deal with potential precision loss.

10. **Construct the answer:** Based on the analysis, I will structure the answer to cover the requested points: general functionality, the `.tq` question, JavaScript relevance with examples, code logic with assumptions, and common programming errors.
`v8/src/maglev/s390/maglev-assembler-s390.cc` is a C++ source file within the V8 JavaScript engine. It implements the **Maglev assembler** specifically for the **s390 architecture**. The Maglev assembler is a component of V8's Maglev compiler, which is a mid-tier optimizing compiler that sits between the baseline interpreter (Ignition) and the full optimizing compiler (TurboFan).

Here's a breakdown of its functionalities:

**Core Functionality:**

* **Code Generation for s390:** The primary responsibility of this file is to provide an abstraction layer over the raw s390 assembly instructions. It offers a higher-level C++ interface to generate machine code that the s390 processor can execute.
* **Maglev Compiler Integration:** It's a crucial part of the Maglev compiler pipeline for the s390 architecture. The Maglev compiler uses this assembler to translate its intermediate representation of JavaScript code into actual s390 machine instructions.
* **Register Allocation and Management:** While the core register allocation logic might reside in other parts of the Maglev compiler, this assembler provides mechanisms for using and managing s390 registers during code generation. You can see examples like `TemporaryRegisterScope` which helps manage the lifetime of temporary registers.
* **Instruction Emission:** It provides methods like `__ Move()`, `__ AddS64()`, `__ LoadU64()`, `__ CmpU64()`, `__ Push()`, `__ Pop()` etc., which correspond to specific s390 assembly instructions. The `__` macro simplifies the syntax for emitting these instructions.
* **Handling V8 Specific Concepts:**  It deals with V8's internal representations of objects, such as tagged pointers (using `kHeapObjectTag`), heap object layout, and root table access. Functions like `SubSizeAndTagObject` are examples of this.
* **Allocation Support:** It includes functions like `AllocateRaw` and `Allocate` to manage object allocation in the V8 heap. These functions interact with V8's memory management system to reserve space for new objects.
* **Function Prologue and Epilogue Generation:** The `Prologue` and potentially implied `Epilogue` functionality (though not explicitly shown in this snippet) handles the setup and teardown of function call frames on the stack, including saving registers and allocating local variables.
* **On-Stack Replacement (OSR):** The `OSRPrologue` function deals with the specific setup required when optimizing a function that is already executing on the stack.
* **Deoptimization Support:** While the `MaybeEmitDeoptBuiltinsCall` is currently empty in this snippet, in a complete implementation, it would likely handle the generation of code to transition back to a less optimized version of the code (the interpreter) when assumptions made by the compiler are violated.
* **String Operations:** It provides specialized functions for common string operations like `LoadSingleCharacterString`, `StringFromCharCode`, and `StringCharCodeOrCodePointAt`, optimizing these operations for the s390 architecture.
* **Number Conversions:** Functions like `TruncateDoubleToInt32`, `TryTruncateDoubleToInt32`, and `TryTruncateDoubleToUint32` handle the efficient conversion of floating-point numbers to integers, a frequent operation in JavaScript.

**Regarding the `.tq` extension:**

No, if `v8/src/maglev/s390/maglev-assembler-s390.cc` had a `.tq` extension, it would be a **Torque** source file. Torque is V8's domain-specific language for defining built-in functions and runtime code. Since it has a `.cc` extension, it's standard **C++** code.

**Relationship with JavaScript and Examples:**

This C++ code directly enables the execution of JavaScript code on the s390 architecture. When the Maglev compiler compiles a JavaScript function, it uses the `MaglevAssembler` to generate the low-level machine code that performs the actions defined by the JavaScript code.

Here are some examples of how the functions in this file relate to JavaScript features:

**1. Object Allocation:**

```javascript
// JavaScript
const obj = {};
```

The `Allocate` functions in the C++ code are responsible for allocating the memory needed to store the JavaScript object `obj` on the V8 heap. The Maglev compiler, when encountering the object literal `{}`, would use the assembler to emit instructions that call the appropriate allocation routines.

**2. String Creation:**

```javascript
// JavaScript
const str = String.fromCharCode(65); // 'A'
```

The `StringFromCharCode` function in the C++ code is used to efficiently create a string from a given character code. The Maglev compiler, when encountering `String.fromCharCode(65)`, would potentially use this assembler function to generate the s390 instructions to create the string "A".

**C++ Equivalent (Conceptual):**

```c++
// Conceptual C++ code within the Maglev compiler
Register result_reg;
Register char_code_reg;
// ... load 65 into char_code_reg ...
maglev_assembler->StringFromCharCode(/* ... register snapshot ..., */ result_reg, char_code_reg, /* ... */);
// result_reg now holds a pointer to the "A" string object
```

**3. String Character Access:**

```javascript
// JavaScript
const text = "Hello";
const charCode = text.charCodeAt(1); // 'e' -> 101
```

The `StringCharCodeOrCodePointAt` function in the C++ code handles retrieving the character code at a specific index within a string. When the Maglev compiler processes `text.charCodeAt(1)`, it might use this assembler function to generate the s390 instructions to access the character at index 1 and retrieve its code.

**C++ Equivalent (Conceptual):**

```c++
// Conceptual C++ code within the Maglev compiler
Register result_reg;
Register string_reg;
Register index_reg;
// ... load "Hello" into string_reg, 1 into index_reg ...
maglev_assembler->StringCharCodeOrCodePointAt(/* ... register snapshot ..., */ result_reg, string_reg, index_reg, /* ... */);
// result_reg now holds the character code 101
```

**4. Number Conversion:**

```javascript
// JavaScript
const num = 3.14;
const intVal = Math.trunc(num); // 3
```

The `TruncateDoubleToInt32` (or related functions) in the C++ code is used to efficiently truncate a floating-point number to an integer. When the Maglev compiler processes `Math.trunc(num)`, it might use these assembler functions to generate the s390 instructions to perform the truncation.

**Code Logic Inference (with Hypothetical Input/Output):**

Let's take the `StringFromCharCode` function as an example:

**Assumptions:**

* We have a MaglevAssembler instance (`masm`).
* We have a RegisterSnapshot (`register_snapshot`) representing the current register state.
* `result` is a register where the resulting string object will be placed.
* `char_code` is a register holding the character code (e.g., 65 for 'A').
* `scratch` is a temporary register available for use.
* `CharCodeMaskMode::kMustApplyMask` is used.

**Hypothetical Input:**

* `char_code` register contains the value `65`.

**Code Logic Flow:**

1. `AndP(char_code, char_code, Operand(0xFFFF));`:  The character code is masked with `0xFFFF`. In this case, 65 remains 65.
2. `CmpU32(char_code, Operand(String::kMaxOneByteCharCode));`: The character code (65) is compared with the maximum value for a one-byte character (typically 255).
3. `JumpToDeferredIf(kUnsignedGreaterThan, ...)`: Since 65 is not greater than 255, the jump is not taken.
4. `LoadSingleCharacterString(result, char_code, scratch);`: The function proceeds to load the single-character string from a pre-populated table based on the `char_code`.

**Hypothetical Output:**

* The `result` register will contain a pointer to a V8 string object representing the character 'A'.

**Common Programming Errors (and how this code helps prevent them or handles them):**

* **Incorrect Manual Memory Management:** Without an assembler like this, manually managing memory allocation and deallocation in a JIT compiler would be extremely error-prone (e.g., memory leaks, dangling pointers). The `Allocate` functions abstract away the low-level details of heap management within V8, reducing the chances of such errors.
* **Incorrect Instruction Sequencing:**  Generating correct and efficient machine code requires deep knowledge of the target architecture's instruction set. This assembler provides a higher-level API, ensuring that the emitted instructions are valid and in the correct order for the s390 architecture.
* **Register Conflicts:**  Manually managing register usage can lead to conflicts where the same register is inadvertently used for multiple purposes simultaneously. The `TemporaryRegisterScope` helps manage the lifetime of temporary registers, reducing the risk of such conflicts.
* **Type Errors in Low-Level Operations:** When dealing with raw memory and registers, it's easy to make type errors (e.g., treating a pointer as an integer). The assembler enforces certain type constraints at the C++ level, making it harder to introduce these errors.
* **Endianness Issues:**  The assembler handles the endianness of the s390 architecture, so the compiler developers don't have to worry about byte order when manipulating data in memory.
* **Deoptimization Bugs:** While the provided `MaybeEmitDeoptBuiltinsCall` is empty, a complete implementation would be crucial for handling deoptimization correctly. Incorrect deoptimization can lead to crashes or incorrect program behavior. This part of the assembler ensures that the necessary information is preserved to safely transition back to the interpreter.
* **Incorrect String Encoding Handling:** The `StringFromCharCode` and `StringCharCodeOrCodePointAt` functions encapsulate the logic for handling different string encodings (one-byte, two-byte, etc.). Without these abstractions, the compiler would need to implement these details directly, increasing the chance of errors related to encoding conversions and character representation. For example, forgetting to handle surrogate pairs in UTF-16 would lead to incorrect results when accessing certain Unicode characters.

In summary, `v8/src/maglev/s390/maglev-assembler-s390.cc` is a fundamental building block of V8's Maglev compiler for the s390 architecture. It provides a safe and efficient way to generate machine code, abstracting away the complexities of low-level assembly programming and ensuring that the generated code adheres to V8's internal object model and execution semantics.

Prompt: 
```
这是目录为v8/src/maglev/s390/maglev-assembler-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/s390/maglev-assembler-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

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
  __ SubS64(object, size_in_bytes);
  __ AddS64(object, Operand(kHeapObjectTag));
}

void SubSizeAndTagObject(MaglevAssembler* masm, Register object,
                         int size_in_bytes) {
  DCHECK(is_int20(kHeapObjectTag - size_in_bytes));
  __ lay(object, MemOperand(object, kHeapObjectTag - size_in_bytes));
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
  __ LoadU64(object, __ ExternalReferenceAsOperand(top, scratch));
  __ AddU64(object, size_in_bytes);
  __ LoadU64(scratch, __ ExternalReferenceAsOperand(limit, scratch));
  __ CmpU64(new_top, scratch);
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
    lgr(scratch, sp);
    lay(scratch,
        MemOperand(scratch, source_frame_size * kSystemPointerSize +
                                StandardFrameConstants::kFixedFrameSizeFromFp));
    CmpU64(scratch, fp);
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
      lay(sp, MemOperand(
                  sp, -(target_frame_size - size_so_far) * kSystemPointerSize));
    }
  }
}

void MaglevAssembler::Prologue(Graph* graph) {
  TemporaryRegisterScope temps(this);
  temps.Include({r6, r8});
  Register scratch = temps.AcquireScratch();
  DCHECK(!graph->is_osr());

  BailoutIfDeoptimized(scratch);

  if (graph->has_recursive_calls()) {
    bind(code_gen_state()->entry_label());
  }

  // Tiering support.
  if (v8_flags.turbofan) {
    using D = MaglevOptimizeCodeOrTailCallOptimizedCodeSlotDescriptor;
    Register flags = D::GetRegisterParameter(D::kFlags);
    Register feedback_vector = D::GetRegisterParameter(D::kFeedbackVector);
    DCHECK(!AreAliased(feedback_vector, kJavaScriptCallArgCountRegister,
                       kJSFunctionRegister, kContextRegister,
                       kJavaScriptCallNewTargetRegister));
    DCHECK(!temps.Available().has(flags));
    DCHECK(!temps.Available().has(feedback_vector));
    Move(feedback_vector,
         compilation_info()->toplevel_compilation_unit()->feedback().object());
    TailCallBuiltin(Builtin::kMaglevOptimizeCodeOrTailCallOptimizedCodeSlot,
                    LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing(
                        flags, feedback_vector, CodeKind::MAGLEV));
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
      SubS32(unroll_counter, Operand(1));
      bgt(&loop);
    }
  }
  if (graph->untagged_stack_slots() > 0) {
    // Extend rsp by the size of the remaining untagged part of the frame,
    // no need to initialise these.
    lay(sp,
        MemOperand(sp, -graph->untagged_stack_slots() * kSystemPointerSize));
  }
}

void MaglevAssembler::MaybeEmitDeoptBuiltinsCall(size_t eager_deopt_count,
                                                 Label* eager_deopt_entry,
                                                 size_t lazy_deopt_count,
                                                 Label* lazy_deopt_entry) {}

void MaglevAssembler::LoadSingleCharacterString(Register result,
                                                Register char_code,
                                                Register scratch) {
  DCHECK_NE(char_code, scratch);
  if (v8_flags.debug_code) {
    CmpU32(char_code, Operand(String::kMaxOneByteCharCode));
    Assert(le, AbortReason::kUnexpectedValue);
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
    AndP(char_code, char_code, Operand(0xFFFF));
  }
  CmpU32(char_code, Operand(String::kMaxOneByteCharCode));
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
        DCHECK(char_code != result);
        DCHECK(!register_snapshot.live_tagged_registers.has(char_code));
        register_snapshot.live_registers.set(char_code);
        __ AllocateTwoByteString(register_snapshot, result, 1);
        __ StoreU16(
            char_code,
            FieldMemOperand(result, OFFSET_OF_DATA_START(SeqTwoByteString)));
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

    LoadU32(scratch, FieldMemOperand(string, offsetof(String, length_)));
    CmpS32(index, scratch);
    Check(lt, AbortReason::kUnexpectedValue);
  }

  // Get instance type.
  LoadInstanceType(instance_type, string);

  {
    TemporaryRegisterScope temps(this);
    Register representation = temps.AcquireScratch();

    // TODO(victorgomes): Add fast path for external strings.
    And(representation, instance_type, Operand(kStringRepresentationMask));
    CmpS32(representation, Operand(kSeqStringTag));
    beq(&seq_string);
    And(representation, Operand(kConsStringTag));
    beq(&cons_string);
    CmpS32(representation, Operand(kSlicedStringTag));
    beq(&sliced_string);
    CmpS32(representation, Operand(kThinStringTag));
    bne(deferred_runtime_call);
    // Fallthrough to thin string.
  }

  // Is a thin string.
  {
    LoadTaggedField(string,
                    FieldMemOperand(string, offsetof(ThinString, actual_)));
    b(&loop);
  }

  bind(&sliced_string);
  {
    TemporaryRegisterScope temps(this);
    Register offset = temps.AcquireScratch();

    LoadAndUntagTaggedSignedField(offset, string,
                                  offsetof(SlicedString, offset_));
    LoadTaggedField(string, string, offsetof(SlicedString, parent_));
    AddS32(index, index, offset);
    b(&loop);
  }

  bind(&cons_string);
  {
    // Reuse {instance_type} register here, since CompareRoot requires a scratch
    // register as well.
    Register second_string = instance_type;
    LoadU64(second_string,
            FieldMemOperand(string, offsetof(ConsString, second_)));
    CompareRoot(second_string, RootIndex::kempty_string);
    bne(deferred_runtime_call);
    LoadTaggedField(string,
                    FieldMemOperand(string, offsetof(ConsString, first_)));
    b(&loop);  // Try again with first string.
  }

  bind(&seq_string);
  {
    Label two_byte_string;
    And(instance_type, Operand(kStringEncodingMask));
    CmpS32(instance_type, Operand(kTwoByteStringTag));
    beq(&two_byte_string);
    // The result of one-byte string will be the same for both modes
    // (CharCodeAt/CodePointAt), since it cannot be the first half of a
    // surrogate pair.
    // AndP(index, Operand(SeqOneByteString::kHeaderSize - kHeapObjectTag));
    LoadU8(result, FieldMemOperand(string, index,
                                   OFFSET_OF_DATA_START(SeqOneByteString)));
    b(result_fits_one_byte);

    bind(&two_byte_string);
    // {instance_type} is unused from this point, so we can use as scratch.
    Register scratch = instance_type;
    ShiftLeftU64(scratch, index, Operand(1));
    AddU64(scratch,
           Operand(OFFSET_OF_DATA_START(SeqTwoByteString) - kHeapObjectTag));

    if (mode == BuiltinStringPrototypeCharCodeOrCodePointAt::kCharCodeAt) {
      LoadU16(result, MemOperand(string, scratch));
    } else {
      DCHECK_EQ(mode,
                BuiltinStringPrototypeCharCodeOrCodePointAt::kCodePointAt);
      Register string_backup = string;
      if (result == string) {
        string_backup = scratch2;
        Move(string_backup, string);
      }
      LoadU16(result, MemOperand(string, scratch));

      Register first_code_point = scratch;
      And(first_code_point, result, Operand(0xfc00));
      CmpS32(first_code_point, Operand(0xd800));
      bne(*done);

      Register length = scratch;
      LoadU32(length, FieldMemOperand(string, offsetof(String, length_)));
      AddS32(index, index, Operand(1));
      CmpS32(index, length);
      bge(*done);

      Register second_code_point = scratch;
      ShiftLeftU32(index, index, Operand(1));
      AddU32(index,
             Operand(OFFSET_OF_DATA_START(SeqTwoByteString) - kHeapObjectTag));
      LoadU16(second_code_point, MemOperand(string_backup, index));

      // {index} is not needed at this point.
      Register scratch2 = index;
      And(scratch2, second_code_point, Operand(0xfc00));
      CmpS32(scratch2, Operand(0xdc00));
      bne(*done);

      int surrogate_offset = 0x10000 - (0xd800 << 10) - 0xdc00;
      AddS32(second_code_point, second_code_point, Operand(surrogate_offset));
      ShiftLeftU32(result, result, Operand(10));
      AddS32(result, result, second_code_point);
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
        __ push(r14);
        __ AllocateStackSpace(kDoubleSize);
        __ StoreF64(src, MemOperand(sp));
        __ CallBuiltin(Builtin::kDoubleToI);
        __ LoadU64(dst, MemOperand(sp));
        __ lay(sp, MemOperand(sp, kDoubleSize));
        __ pop(r14);
        __ Jump(*done);
      },
      src, dst, done);
  TryInlineTruncateDoubleToI(dst, src, *done);
  Jump(slow_path);
  bind(*done);
  // Zero extend the converted value to complete the truncation.
  LoadU32(dst, dst);
}

void MaglevAssembler::TryTruncateDoubleToInt32(Register dst, DoubleRegister src,
                                               Label* fail) {
  TemporaryRegisterScope temps(this);
  DoubleRegister temp = temps.AcquireScratchDouble();
  Label done;

  // Convert the input float64 value to int32.
  ConvertDoubleToInt32(dst, src);

  // Convert that int32 value back to float64.
  ConvertIntToDouble(temp, dst);

  // Check that the result of the float64->int32->float64 is equal to the input
  // (i.e. that the conversion didn't truncate.
  CmpF64(src, temp);
  JumpIf(ne, fail);

  // Check if {input} is -0.
  CmpS32(dst, Operand::Zero());
  JumpIf(ne, &done);

  // In case of 0, we need to check the high bits for the IEEE -0 pattern.
  {
    MovDoubleToInt64(r1, src);
    ShiftRightS64(r1, r1, Operand(63));
    CmpS64(r1, Operand(0));
    JumpIf(lt, fail);
  }

  bind(&done);
}

void MaglevAssembler::TryTruncateDoubleToUint32(Register dst,
                                                DoubleRegister src,
                                                Label* fail) {
  TemporaryRegisterScope temps(this);
  DoubleRegister temp = temps.AcquireScratchDouble();
  Label done;

  // Convert the input float64 value to uint32.
  ConvertDoubleToUnsignedInt32(dst, src);

  // Convert that uint32 value back to float64.
  ConvertUnsignedIntToDouble(temp, dst);

  // Check that the result of the float64->uint32->float64 is equal to the input
  // (i.e. that the conversion didn't truncate.
  CmpF64(src, temp);
  JumpIf(ne, fail);

  // Check if {input} is -0.
  CmpS32(dst, Operand::Zero());
  JumpIf(ne, &done);

  // In case of 0, we need to check the high bits for the IEEE -0 pattern.
  {
    MovDoubleToInt64(r1, src);
    ShiftRightS64(r1, r1, Operand(63));
    CmpS64(r1, Operand(0));
    JumpIf(lt, fail);
  }

  bind(&done);
}

void MaglevAssembler::TryChangeFloat64ToIndex(Register result,
                                              DoubleRegister value,
                                              Label* success, Label* fail) {
  TemporaryRegisterScope temps(this);
  DoubleRegister temp = temps.AcquireScratchDouble();
  // Convert the input float64 value to int32.
  ConvertDoubleToInt32(result, value);
  // Convert that int32 value back to float64.
  ConvertIntToDouble(temp, result);
  // Check that the result of the float64->int32->float64 is equal to
  // the input (i.e. that the conversion didn't truncate).
  CmpF64(value, temp);
  JumpIf(ne, fail);
  Jump(success);
}

}  // namespace maglev
}  // namespace internal
}  // namespace v8

"""

```