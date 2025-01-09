Response:
The user wants to understand the functionality of the provided C++ code snippet, which is a part of the V8 JavaScript engine, specifically the Maglev compiler for the RISC-V architecture.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Purpose:** The filename `maglev-assembler-riscv.cc` immediately suggests this code is responsible for generating RISC-V assembly instructions within the Maglev compiler. The "assembler" part is key.

2. **Examine Key Functions and Macros:** Look for prominent function definitions and preprocessor macros (`#define`). The `#define __ masm->` is a common pattern in V8's assembler code, simplifying the emission of assembly instructions.

3. **Group Functionality by Category:**  As you go through the functions, try to categorize them by the high-level operations they perform. Common compiler tasks include:
    * Memory allocation
    * Function prologue/epilogue
    * Deoptimization handling
    * String manipulation
    * Type checking
    * Number conversions

4. **Detail Individual Functionality:** For each identified category, describe the specific tasks performed by the functions. Pay attention to:
    * Function arguments and their types.
    * Registers used.
    * Interaction with other V8 components (e.g., `Isolate`, `Graph`, `Builtin`).
    * Conditional logic and branching.

5. **Address Specific User Queries:** Go back to the user's prompt and address each specific question:
    * **Functionality Listing:**  This is the main goal. Summarize the core capabilities.
    * **`.tq` Extension:** Explain that this file is C++, not Torque.
    * **Relationship to JavaScript:** Explain how these low-level operations relate to common JavaScript actions (e.g., object creation, function calls, string operations, type checks). Provide concrete JavaScript examples that would trigger the execution of this assembly code.
    * **Code Logic Reasoning (Input/Output):** For functions with clear transformations (like `SubSizeAndTagObject`), provide hypothetical register inputs and the expected output after the code executes.
    * **Common Programming Errors:** Think about scenarios where these low-level operations might fail due to programmer error in the JavaScript code. Type mismatches, invalid array indices, and incorrect string operations are good examples.

6. **Structure the Response:** Organize the information logically with clear headings and bullet points. This makes it easier for the user to read and understand.

7. **Refine and Clarify:** Review the generated response for clarity and accuracy. Ensure that technical terms are explained adequately or are commonly understood in the context of compiler development. For instance, explaining "heap object tag" and "allocation type" provides useful context.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus solely on the RISC-V assembly instructions.
* **Correction:** Realize the importance of connecting the low-level assembly generation to higher-level concepts in the Maglev compiler and how those relate back to JavaScript.
* **Initial thought:** List every single function in detail.
* **Correction:** Group functions by their purpose to provide a more thematic and understandable overview.
* **Initial thought:** Just state what the code *does*.
* **Correction:** Explain *why* the code does these things in the context of JavaScript execution and the Maglev compiler.
* **Initial thought:**  Assume the user has deep compiler knowledge.
* **Correction:**  Provide explanations and examples that are accessible to a wider audience, including those with a general understanding of programming and JavaScript.

By following this thought process, the generated response effectively addresses the user's request and provides a comprehensive understanding of the functionality of the provided V8 source code.
This C++ source file, `v8/src/maglev/riscv/maglev-assembler-riscv.cc`, is a crucial part of the **Maglev compiler** within the V8 JavaScript engine, specifically targeting the **RISC-V architecture**. It defines the `MaglevAssembler` class, which provides an interface for generating RISC-V assembly instructions.

Here's a breakdown of its functionalities:

**Core Functionality: Assembly Code Generation for Maglev on RISC-V**

* **Low-Level Instruction Emission:** The primary purpose is to offer a way to emit raw RISC-V assembly instructions. The `#define __ masm->` macro is a shorthand for calling methods on the internal `MacroAssembler` instance, which is responsible for the actual instruction encoding.
* **High-Level Assembly Helpers:** It provides higher-level helper functions that encapsulate common sequences of RISC-V instructions for Maglev's needs. These helpers make the code more readable and maintainable than directly writing raw assembly.

**Specific Functionalities Implemented in the Snippet:**

1. **Object Tagging and Size Manipulation:**
   * `SubSizeAndTagObject(MaglevAssembler* masm, Register object, Register size_in_bytes)`: Subtracts the `size_in_bytes` from the `object` register and then adds the `kHeapObjectTag`. This is a common operation in V8 to calculate the address of the object's data given the object's header.
   * `SubSizeAndTagObject(MaglevAssembler* masm, Register object, int size_in_bytes)`: Similar to the above, but takes an immediate `size_in_bytes` value.

2. **Object Allocation:**
   * `AllocateRaw`:  Implements the core logic for allocating raw memory for objects in the V8 heap. It handles:
     * Checking for available space in the current allocation space (using `SpaceAllocationTopAddress` and `SpaceAllocationLimitAddress`).
     * Forwarding to a slow-path runtime function (`AllocateSlow`) if there isn't enough space, which involves calling a built-in function.
     * Updating the allocation top pointer.
     * Tagging the allocated object.
   * `MaglevAssembler::Allocate`: Provides public interfaces to call `AllocateRaw` with either a register or an immediate for the size.

3. **On-Stack Replacement (OSR) Prologue:**
   * `OSRPrologue`:  Handles the setup when transitioning from unoptimized code to optimized Maglev code while the function is already on the stack (OSR). It ensures the stack frame is correctly sized and checks for consistency.

4. **Function Prologue:**
   * `Prologue`: Sets up the stack frame at the beginning of a Maglev-compiled function. This includes:
     * Handling tiering (potential optimization to TurboFan).
     * Saving callee-saved registers.
     * Pushing the context, function, and argument count onto the stack.
     * Initializing stack slots.

5. **Deoptimization Support:**
   * `MaybeEmitDeoptBuiltinsCall`: Emits calls to the deoptimization built-in functions for both eager and lazy deoptimization scenarios.

6. **String Manipulation:**
   * `LoadSingleCharacterString`:  Loads a single-character string from the single character string table based on a character code.
   * `StringFromCharCode`:  Creates a string from a given character code. It handles both one-byte and two-byte strings.
   * `StringCharCodeOrCodePointAt`:  Implements the logic for retrieving the character code or code point at a specific index within a string, handling different string representations (sequential, cons, sliced, thin).

7. **Type Checking:**
   * `IsObjectType`: Checks if an object's instance type matches a given type.

8. **Number Conversions:**
   * `TruncateDoubleToInt32`: Truncates a double-precision floating-point number to a 32-bit integer.
   * `TryTruncateDoubleToInt32`: Attempts to truncate a double to an int32, jumping to a failure label if the truncation loses information.
   * `TryTruncateDoubleToUint32`: Attempts to truncate a double to a uint32, jumping to a failure label if the truncation loses information.
   * `TryChangeFloat64ToIndex`: Attempts to convert a double to an index (integer), jumping to success or failure labels.

**Is it a Torque Source File?**

No, `v8/src/maglev/riscv/maglev-assembler-riscv.cc` ends with `.cc`, which is the standard extension for C++ source files in V8. If it were a Torque file, it would end with `.tq`.

**Relationship to JavaScript and Examples:**

This code directly supports the execution of JavaScript code. Many JavaScript operations rely on the low-level memory management, function calls, and type checks implemented here.

**JavaScript Examples:**

* **Object Creation:** When you create a new object in JavaScript (e.g., `const obj = {};`), the `Allocate` functions in this file (or similar ones in other architectures) are involved in allocating memory for that object on the heap.

   ```javascript
   const obj = {};
   ```

* **Function Calls:** When a JavaScript function is called, the `Prologue` function (or its equivalent) sets up the stack frame to store arguments and local variables.

   ```javascript
   function myFunction(a, b) {
     return a + b;
   }
   myFunction(1, 2);
   ```

* **String Operations:** Operations like getting a character code or creating a string from a character code use the functions like `StringCharCodeOrCodePointAt` and `StringFromCharCode`.

   ```javascript
   const str = "Hello";
   const charCode = str.charCodeAt(0); // Uses StringCharCodeOrCodePointAt
   const newStr = String.fromCharCode(65); // Uses StringFromCharCode
   ```

* **Type Checking:**  JavaScript's dynamic typing often requires runtime type checks. The `IsObjectType` function is an example of such a check performed at the assembly level.

   ```javascript
   function isArray(obj) {
     return Array.isArray(obj); // Internally might use a check similar to IsObjectType
   }
   isArray([1, 2, 3]);
   ```

* **Number Conversions:** When you perform operations that implicitly convert between different number types (e.g., double to integer), the truncation functions might be used.

   ```javascript
   const num = 3.14;
   const intNum = num | 0; // Bitwise OR with 0 often triggers integer conversion
   ```

**Code Logic Reasoning (Example: `SubSizeAndTagObject`)**

**Assumption:**  We have a register `r10` holding the address of an object's header, and `r11` holding the size of the object's data in bytes.

**Input:**
* `object` (Register `r10`): Let's say it contains the address `0x1000`.
* `size_in_bytes` (Register `r11`): Let's say it contains the value `16`.
* `kHeapObjectTag`: This is a constant defined in V8, typically `1`.

**Assembly Instructions Executed:**

```assembly
SubWord(r10, r10, Operand(r11));  // r10 = r10 - r11  => r10 = 0x1000 - 16 = 0xFEE8
AddWord(r10, r10, Operand(kHeapObjectTag)); // r10 = r10 + kHeapObjectTag => r10 = 0xFEE8 + 1 = 0xFEE9
```

**Output:**
* `object` (Register `r10`):  Will contain the address `0xFEE9`. This would typically be the starting address of the actual data within the heap-allocated object.

**Common Programming Errors (Related to the Code):**

These low-level functions are usually not directly manipulated by JavaScript developers. However, errors in JavaScript code can lead to these functions being called with unexpected values, potentially causing crashes or unexpected behavior.

* **Incorrect Type Assumptions:** If the Maglev compiler incorrectly assumes the type of a variable, it might use a function like `IsObjectType` incorrectly, leading to wrong branching and potential errors.

   ```javascript
   function process(input) {
     if (typeof input === 'number') { // Maglev might optimize based on this
       // ... treat as number
     } else {
       // ... treat as something else
     }
   }

   process("not a number"); // If Maglev aggressively inlined the 'typeof' check, errors could occur if assumptions are wrong.
   ```

* **Out-of-Bounds String Access:** Accessing a string character at an invalid index can lead to `StringCharCodeOrCodePointAt` being called with an index that goes beyond the string's length, potentially causing issues if bounds checks aren't handled correctly.

   ```javascript
   const str = "abc";
   const char = str.charAt(10); // This will return an empty string, but at the assembly level, it needs careful handling.
   ```

* **Memory Corruption (Indirect):** While developers don't directly call `AllocateRaw`, if there are bugs in the V8 engine itself or in native extensions, it could lead to incorrect size calculations or memory management, potentially causing `AllocateRaw` to allocate memory incorrectly and leading to crashes or security vulnerabilities.

In summary, `v8/src/maglev/riscv/maglev-assembler-riscv.cc` is a fundamental piece of the V8 engine for the RISC-V architecture. It bridges the gap between the Maglev compiler's intermediate representation and the actual RISC-V assembly instructions that the processor executes to run JavaScript code.

Prompt: 
```
这是目录为v8/src/maglev/riscv/maglev-assembler-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/riscv/maglev-assembler-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

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