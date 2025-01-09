Response:
Let's break down the request and the provided C++ code to generate a comprehensive answer.

**1. Understanding the Core Request:**

The request asks for a functional description of the `maglev-assembler-x64.cc` file, including:

*   Its purpose within the V8 architecture.
*   Identification as a Torque source (if its name ended in `.tq`).
*   Connection to JavaScript functionality with examples.
*   Code logic inference with hypothetical inputs and outputs.
*   Common programming errors it helps avoid or reveals.

**2. Initial Analysis of the C++ Code:**

*   **Header:** The initial comments and `#include` directives point to this being a core part of V8's compilation pipeline, specifically within the Maglev tier for x64 architecture. It interacts with low-level code generation (`codegen`, `compiler`), bytecode interpretation (`interpreter`), and object representation (`objects`).
*   **Namespace:** The code is within `v8::internal::maglev`, confirming its role in the Maglev compiler.
*   **Macros and Helpers:** The `__ masm->` macro suggests a wrapping of an underlying assembler. Helper functions like `LoadNewAllocationTop` and `AllocateRaw` hint at memory management and object allocation.
*   **Core Functionality:**  The presence of functions like `Allocate`, `LoadSingleCharacterString`, `StringFromCharCode`, `StringCharCodeOrCodePointAt`, and `TruncateDoubleToInt32` clearly indicates this code is involved in the runtime representation and manipulation of JavaScript strings and numbers.
*   **Control Flow:**  The use of `Label`s and conditional jumps (`JumpToDeferredIf`, `j`, etc.) demonstrates the assembly-level nature of the code and its role in generating conditional execution paths.
*   **OSR and Prologue:** Functions like `OSRPrologue` and `Prologue` are standard components of compiler-generated code, handling the setup of function calls and optimization.
*   **Deferred Operations:** The concept of `JumpToDeferredIf` and the lambda expressions within them indicate handling of slower, less common execution paths (e.g., when allocation fails or string manipulation requires more complex logic).

**3. Answering Each Part of the Request:**

*   **Functionality:** Based on the code analysis, the primary function is to generate x64 assembly code for the Maglev compiler. This involves object allocation, string manipulation (character code access, string creation), number conversion (truncation), and function prologue/OSR setup.

*   **.tq Check:** The filename ends in `.cc`, not `.tq`. Therefore, it is not a Torque source file.

*   **JavaScript Relationship:** This is where the connection needs to be made explicit. The C++ code handles operations that directly correspond to JavaScript language features. String manipulation (like `charCodeAt`, `codePointAt`, and creating strings from character codes) and number conversions are key examples.

    *   *Self-Correction:* Initially, I might think solely of low-level implementation. However, the request asks for *JavaScript examples*. So, the answer must include the *user-visible* JavaScript operations that these C++ functions underpin.

*   **Code Logic Inference:**  This requires selecting a specific function and tracing its logic with sample input. `StringFromCharCode` is a good candidate because it has clear conditional logic.

    *   *Thought Process:* What are the possible inputs?  A character code. What are the branches? Does it fit in a single byte?  What happens if it doesn't?  This leads to defining the "single-byte" and "two-byte" scenarios and their corresponding outputs (single-character string vs. two-byte string).

*   **Common Programming Errors:** This is about understanding how the low-level implementation helps prevent or expose errors. For instance, buffer overflows are relevant in the context of string manipulation and allocation. Type errors related to number conversions are another possibility.

    *   *Constraint Checklist & Confidence Score:*
        *   List functionality: Yes
        *   Torque check: Yes
        *   JavaScript relation: Yes
        *   JavaScript example: Yes
        *   Code logic inference: Yes
        *   Hypothetical input/output: Yes
        *   Common programming errors: Yes
        *   Confidence Score: 5/5 - I'm confident I can address all aspects.

**4. Structuring the Output:**

The output should be organized to address each point of the request clearly. Using headings and bullet points will enhance readability. The JavaScript examples should be simple and directly illustrate the C++ functionality. The code logic inference should present the assumed input, the steps of the function, and the resulting output. The common error examples should be relatable to typical JavaScript development mistakes.

**5. Refinement and Review:**

After drafting the initial answer, review it for accuracy, clarity, and completeness. Ensure the JavaScript examples are correct and directly relevant. Double-check the logic inference and the error examples. Make sure the language is accessible and avoids unnecessary jargon. For instance, when discussing memory allocation, use terms like "heap" and "object size" which are conceptually close to JavaScript developers' understanding.

By following this structured thought process, incorporating self-correction, and focusing on the specific requirements of the prompt, we can generate a comprehensive and accurate answer.
This C++ source file, `v8/src/maglev/x64/maglev-assembler-x64.cc`, is a crucial component of the **Maglev compiler** in the V8 JavaScript engine, specifically for the **x64 architecture**. It provides a high-level interface for generating machine code (assembly instructions) for the Maglev intermediate representation (IR).

Here's a breakdown of its functionalities:

**Core Functionality:**

1. **Assembly Code Generation:** It acts as an abstraction layer over the raw x64 assembly instructions. The `MaglevAssembler` class (and the `masm` pointer within it) provides methods that correspond to common assembly operations like moving data between registers and memory, arithmetic operations, comparisons, and control flow (jumps, labels).

2. **Object Allocation:**  It provides functions for allocating memory on the heap for JavaScript objects. The `Allocate` methods handle checking for available space in the current allocation chunk and potentially calling the runtime for more memory if needed. This is fundamental to creating new objects in JavaScript.

3. **String Manipulation:**  It includes functions specifically designed for efficient string operations, such as:
    *   `LoadSingleCharacterString`:  Retrieving a pre-existing single-character string object from a table. This optimizes the creation of common single-character strings.
    *   `StringFromCharCode`:  Creating a string from a given character code. It handles both one-byte and two-byte character encodings.
    *   `StringCharCodeOrCodePointAt`:  Extracting the character code or code point at a specific index within a string. It handles various string representations (sequential, cons, sliced, thin).

4. **Number Conversion:** It offers methods for converting JavaScript numbers (represented as doubles) to integers:
    *   `TruncateDoubleToInt32`:  Truncates a double to a 32-bit integer.
    *   `TryTruncateDoubleToInt32`:  Attempts to truncate a double to a 32-bit integer, jumping to a `fail` label if the conversion results in loss of precision or overflow.
    *   `TryTruncateDoubleToUint32`: Similar to the above but for unsigned 32-bit integers.
    *   `TryChangeFloat64ToIndex`:  Attempts to convert a double to a valid array index.

5. **Function Prologue and OSR (On-Stack Replacement):**
    *   `Prologue`: Generates the necessary assembly code at the beginning of a Maglev-compiled function. This includes setting up the stack frame, saving registers, and potentially handling tiering (moving to a more optimized compiler).
    *   `OSRPrologue`: Handles the special case of entering a Maglev-compiled function via OSR, where the execution starts in the middle of a function that was previously running in an interpreted or less optimized state.

6. **Deoptimization Handling:** The `MaybeEmitDeoptBuiltinsCall` function likely plays a role in generating code that allows the Maglev-compiled function to gracefully fall back to a less optimized state (e.g., the interpreter) if certain assumptions are violated.

**Is it a Torque source?**

No, `v8/src/maglev/x64/maglev-assembler-x64.cc` ends with `.cc`, which indicates it's a **C++ source file**. Torque source files typically have a `.tq` extension.

**Relationship to JavaScript and Examples:**

This file is deeply connected to JavaScript functionality because it's responsible for generating the low-level code that executes JavaScript. Many of the functions directly correspond to JavaScript operations.

**Examples:**

*   **String Creation:** The `StringFromCharCode` function is used when JavaScript code calls `String.fromCharCode()`:

    ```javascript
    const charCode = 65; // ASCII for 'A'
    const str = String.fromCharCode(charCode);
    console.log(str); // Output: "A"
    ```

    Internally, the Maglev compiler might use `StringFromCharCode` to generate the x64 instructions to allocate a string object and store the character 'A' within it.

*   **Accessing Character Codes:** The `StringCharCodeOrCodePointAt` function is used when you call `charCodeAt()` or `codePointAt()` on a string:

    ```javascript
    const text = "Hello";
    const charCode = text.charCodeAt(1); // Get the character code at index 1 ('e')
    console.log(charCode); // Output: 101

    const codePoint = text.codePointAt(0); // Get the code point at index 0 ('H')
    console.log(codePoint); // Output: 72
    ```

    The Maglev compiler would likely use `StringCharCodeOrCodePointAt` to generate the assembly instructions to access the underlying string data and retrieve the character code.

*   **Number Truncation:** The `TruncateDoubleToInt32` or `TryTruncateDoubleToInt32` functions are used in various JavaScript scenarios where a floating-point number needs to be converted to an integer:

    ```javascript
    const floatNum = 3.14;
    const intNum = Math.trunc(floatNum);
    console.log(intNum); // Output: 3

    const alsoInt = floatNum | 0; // Bitwise OR with 0 also truncates
    console.log(alsoInt); // Output: 3
    ```

    Maglev would employ these assembler functions to generate the efficient x64 instructions to perform the truncation.

**Code Logic Inference with Assumptions:**

Let's consider the `StringFromCharCode` function with assumptions:

**Assumptions:**

*   `register_snapshot`: Holds the state of registers before the call.
*   `result`: A register where the resulting string object will be placed.
*   `char_code`: A register containing the character code (e.g., 65 for 'A').
*   `scratch`: A temporary register for intermediate calculations.
*   `CharCodeMaskMode::kMustApplyMask`: We assume the character code might have extra bits and needs masking.

**Input:** `char_code` contains the value 65 (ASCII for 'A').

**Steps:**

1. `andl(char_code, Immediate(0xFFFF))`:  The character code is masked with `0xFFFF` (65535), ensuring it's within the valid range for a character code. In this case, 65 & 65535 = 65.
2. `cmpl(char_code, Immediate(String::kMaxOneByteCharCode))`: The character code (65) is compared with the maximum value for a one-byte character (likely 255). 65 is less than or equal to 255.
3. Since the character code fits in one byte, the code jumps to the label `char_code_fits_one_byte`.
4. `LoadSingleCharacterString(result, char_code, scratch)` is called. This function:
    *   Loads the `kSingleCharacterStringTable` root (a table of pre-existing single-character string objects) into the `scratch` register.
    *   Uses the `char_code` (65) as an index into this table to retrieve the already created string object for 'A'.
    *   Stores the retrieved string object in the `result` register.
5. The code jumps to the `done` label.

**Output:** The `result` register will contain a pointer to the heap object representing the JavaScript string "A".

**User-Common Programming Errors:**

This file's functionality is generally hidden from direct user interaction. However, the optimizations and checks within it can indirectly help with or expose certain programming errors:

1. **Incorrect String Length Calculations:**  When using string manipulation methods, incorrect assumptions about string lengths or index boundaries can lead to crashes or unexpected results. The checks within `StringCharCodeOrCodePointAt` (e.g., ensuring the index is within bounds) can help catch these issues early in the compilation process or during execution.

    ```javascript
    const str = "abc";
    // Potential error: accessing an out-of-bounds index
    const char = str.charAt(5); // This will return an empty string, but could lead to issues if not handled.
    ```

2. **Type Errors in Number Conversions:**  JavaScript's loose typing can sometimes lead to unexpected results when converting between numbers and other types. The `TryTruncateDoubleToInt32` functions, with their checks for precision loss, reflect the underlying complexities of these conversions. For example:

    ```javascript
    const largeFloat = 2**32 + 0.5;
    const intValue = largeFloat | 0; // Potential precision loss
    console.log(intValue); // Output might be unexpected due to truncation
    ```

3. **Memory Leaks (Less Directly):** While this file doesn't directly cause memory leaks in user code, the object allocation routines it contains are fundamental to V8's memory management. If there were issues in the allocation logic itself, it could contribute to memory problems within the engine. However, memory leaks are more often caused by holding onto object references unnecessarily in JavaScript code.

In summary, `v8/src/maglev/x64/maglev-assembler-x64.cc` is a vital piece of V8's Maglev compiler, responsible for generating efficient x64 assembly code for common JavaScript operations related to object allocation, string manipulation, and number conversions. It's not a Torque file but a core C++ component. While users don't interact with it directly, its functionality underpins the execution of JavaScript code and can indirectly influence how certain programming errors manifest.

Prompt: 
```
这是目录为v8/src/maglev/x64/maglev-assembler-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/x64/maglev-assembler-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

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