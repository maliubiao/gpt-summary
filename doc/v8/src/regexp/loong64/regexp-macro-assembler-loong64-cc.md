Response:
My goal is to analyze the provided C++ code snippet from V8's regular expression engine and summarize its functionality. Here's a breakdown of my thought process:

1. **Identify the Core File:** The filename `regexp-macro-assembler-loong64.cc` immediately tells me this is part of the regular expression implementation for the LOONG64 architecture. The `.cc` extension confirms it's C++ code.

2. **Recognize the Class:** The code defines a class `RegExpMacroAssemblerLOONG64`. The name strongly suggests it's responsible for generating machine code (assembling) for regular expression matching on the LOONG64 architecture. The "Macro" part might indicate it uses a higher-level abstraction over raw assembly instructions.

3. **Analyze the Includes:** The included headers provide clues about the class's dependencies and functionalities:
    * `regexp-macro-assembler-loong64.h`:  The corresponding header file, likely containing the class declaration.
    * `codegen/macro-assembler.h`:  Indicates that this class utilizes V8's `MacroAssembler` for generating machine code. This confirms the code generation aspect.
    * `heap/factory.h`:  Suggests interaction with V8's heap management, potentially for creating objects.
    * `logging/log.h`: Implies the presence of logging or debugging features within this code.
    * `objects/code-inl.h`: Points to the manipulation of V8's `Code` objects, which represent executable code.
    * `regexp/regexp-stack.h`:  Shows that this class interacts with a dedicated stack used for regular expression matching (backtracking).
    * `snapshot/embedded/embedded-data-inl.h`: Might be related to embedding data within the generated code.

4. **Examine Key Member Variables:** The member variables offer insights into the class's state and responsibilities:
    * `masm_`:  A `std::unique_ptr<MacroAssembler>`. This is the primary tool for generating assembly instructions.
    * `mode_`: Likely represents the matching mode (e.g., Latin1, UTF-16).
    * `num_registers_`, `num_saved_registers_`:  Indicate the management of registers for storing intermediate results and captured groups.
    * `entry_label_`, `start_label_`, `success_label_`, `backtrack_label_`, `exit_label_`, `internal_failure_label_`: These are labels within the generated assembly code, marking different execution points. They reveal the control flow of the generated code.

5. **Delve into the Constructor:** The constructor initializes the `MacroAssembler`, sets the mode, and allocates space for registers. The `jmp(&entry_label_)` suggests a delayed code generation pattern, where the main logic is written later. The binding of `internal_failure_label_` and the subsequent `li(a0, Operand(FAILURE))` and `Ret()` show how internal errors are handled.

6. **Scrutinize Key Methods:**  The methods within the class are the heart of its functionality. I'll go through some important ones:
    * `AdvanceCurrentPosition`, `AdvanceRegister`:  Methods for manipulating the current position in the input string and the values in the registers.
    * `Backtrack`: Implements the backtracking mechanism, a core concept in regular expression matching.
    * `Bind`:  Used to mark locations in the generated code.
    * `CheckCharacter`, `CheckCharacterGT`, `CheckCharacterLT`, `CheckAtStart`, `CheckNotAtStart`, etc.: A family of methods for performing checks against the current character in the input string. These are the building blocks of the regular expression matching logic.
    * `CheckNotBackReference`, `CheckNotBackReferenceIgnoreCase`: Handle backreferences, a powerful feature in regular expressions.
    * `Fail`:  Sets the return code to indicate a failed match.
    * `LoadRegExpStackPointerFromMemory`, `StoreRegExpStackPointerToMemory`, `PushRegExpBasePointer`, `PopRegExpBasePointer`:  Manage the regular expression stack.
    * `GetCode`:  The crucial method responsible for finalizing the generated code and creating the executable `Code` object. This is where the entry point and exit sequences are finalized. The detailed operations within this function (stack frame setup, register initialization, etc.) are key to understanding the execution environment.

7. **Infer Overall Functionality:** Based on the class name, member variables, and methods, I can conclude that `RegExpMacroAssemblerLOONG64` is responsible for:
    * **Generating machine code:** Specifically for regular expression matching on the LOONG64 architecture.
    * **Managing registers:** Allocating and using registers to store the current position, captured groups, and other intermediate values.
    * **Implementing core regex operations:** Providing methods for character matching, backtracking, backreferences, and handling different matching modes (case sensitivity, Unicode).
    * **Interacting with V8's runtime:** Utilizing components like the heap, code objects, and the regular expression stack.
    * **Handling control flow:** Using labels and jump instructions to implement the matching logic.

8. **Address Specific Questions:** Now, I can address the specific points raised in the prompt:
    * **Functionality Summary:** This is the main goal, which I've built up through the analysis above.
    * **Torque Source:** Check the filename extension. `.cc` means it's C++, not Torque.
    * **JavaScript Relationship:**  Explain how this C++ code is the underlying implementation of JavaScript's regular expression functionality. Give a simple JavaScript example.
    * **Code Logic Inference:** Choose a simple method like `CheckCharacter` and provide a hypothetical input and output based on its functionality.
    * **Common Programming Errors:** Think about potential issues related to regular expression complexity, backtracking, and incorrect usage of capture groups.
    * **Part 1 Summary:**  Reiterate the key functionalities identified in the analysis.

By following these steps, I can systematically analyze the C++ code and generate a comprehensive and accurate summary of its functionality. The process involves understanding the code's structure, dependencies, and the roles of its key components.
This C++ code snippet is the first part of the implementation of a regular expression macro assembler specifically for the LOONG64 architecture within the V8 JavaScript engine. Let's break down its functionalities:

**Core Functionality:**

1. **Code Generation for Regular Expressions:** The primary function of `RegExpMacroAssemblerLOONG64` is to generate low-level machine code (assembly instructions) that efficiently execute regular expression matching on LOONG64 processors. It acts as an intermediary between a higher-level representation of the regular expression and the actual executable code.

2. **Architecture-Specific Optimization:**  The "loong64" in the name signifies that this code is tailored for the specifics of the LOONG64 architecture. This includes register usage conventions, instruction selection, and optimization strategies that are effective on this particular processor.

3. **Register Management:** The code defines a specific register assignment convention (documented in the comments). This is crucial for ensuring consistent access to important data during the matching process, such as the current position in the input string, the currently loaded character, and the backtrack stack pointer.

4. **Stack Management:**  The code outlines the structure of the stack frame used during regular expression execution. This frame stores information needed for matching, including:
    * Function arguments (input string, start index, etc.)
    * Callee-saved registers
    * Frame marker
    * Capture registers (for storing matched substrings)
    * Backtrack information

5. **Implementing Regular Expression Operations:** The class provides a set of methods that correspond to common regular expression operations. These methods generate the necessary assembly instructions to perform actions like:
    * **Character Matching:** Checking if the current character matches a specific character or falls within a range.
    * **Position Checking:** Verifying if the current position is at the start or end of the input string.
    * **Backtracking:** Implementing the backtracking mechanism crucial for handling alternation and repetition in regular expressions. This involves pushing and popping code offsets onto a stack.
    * **Capture Group Management:**  Storing and retrieving the starting and ending positions of captured substrings.
    * **Backreferences:** Checking if a portion of the input matches a previously captured group.
    * **Character Class Handling:** Efficiently checking if a character belongs to a predefined character class (e.g., digits, whitespace, word characters).

6. **Preemption and Stack Overflow Checks:** The code includes mechanisms to check for JavaScript preemption (allowing the JavaScript engine to interrupt long-running regex executions) and stack overflow (preventing the regex execution from consuming too much stack space).

7. **Fallback Mechanism:** The `fallback_label_` suggests a mechanism to handle situations where the optimized assembly code cannot handle the regular expression (perhaps due to complexity). In such cases, the execution might fall back to a more general (and potentially slower) implementation.

**If `regexp-macro-assembler-loong64.cc` ended with `.tq`:**

If the file ended with `.tq`, it would indeed be a V8 Torque source file. Torque is V8's domain-specific language for generating optimized code, often for runtime functions and built-in objects. While it also generates C++, it's a higher-level abstraction than raw C++.

**Relationship to JavaScript:**

This C++ code is the **underlying implementation** of JavaScript's regular expression functionality when running on a LOONG64 architecture. When you use regular expressions in your JavaScript code, the V8 engine (if running on LOONG64) will eventually use code generated by this `RegExpMacroAssemblerLOONG64` class to perform the actual matching.

**JavaScript Example:**

```javascript
const regex = /ab*c/;
const str = "abbbcdefabc";
const match = str.match(regex);

if (match) {
  console.log("Match found:", match[0]); // Output: Match found: abbbc
}
```

When this JavaScript code is executed on V8 on a LOONG64 system, the engine will compile the regular expression `/ab*c/` and, at some point, use the `RegExpMacroAssemblerLOONG64` to generate machine code that efficiently searches for the pattern "a" followed by zero or more "b"s followed by "c" within the string "abbbcdefabc".

**Code Logic Inference (Example: `CheckCharacter`)**

Let's consider the `CheckCharacter` method:

```c++
void RegExpMacroAssemblerLOONG64::CheckCharacter(uint32_t c, Label* on_equal) {
  BranchOrBacktrack(on_equal, eq, current_character(), Operand(c));
}
```

* **Hypothesis:** This method checks if the currently loaded character (`current_character()`) is equal to a given character `c`. If they are equal, it jumps to the label `on_equal`; otherwise, it backtracks.

* **Assumptions:**
    * `current_character()` returns the currently loaded character from the input string.
    * `BranchOrBacktrack` is a macro that generates a conditional branch instruction. If the condition is false, it triggers a backtrack.

* **Input:**
    * `c`:  The character to compare against (e.g., the ASCII value of 'a').
    * `on_equal`: A label in the generated assembly code to jump to if the characters match.
    * The current character in the input string is 'a'.

* **Output (Generated Assembly Logic):** The `BranchOrBacktrack` macro would likely generate an assembly instruction similar to:
    ```assembly
    beq current_character_register, 'a', on_equal_label  // Branch if equal
    // Backtrack code here if not equal
    ```

**Common Programming Errors (Related to Regex and this Code):**

While developers don't directly interact with this C++ code, common errors in *writing regular expressions* can impact the efficiency and behavior of the code generated by this assembler:

1. **Catastrophic Backtracking:**  Regular expressions with nested quantifiers or alternations can lead to exponential backtracking, causing significant performance issues or even hanging the execution. For example, `/a*a*a*b/` on a long string without "b" will explore many unnecessary paths. V8's regex engine has safeguards, but overly complex regexes can still be problematic.

2. **Incorrect Use of Capture Groups:**  Misunderstanding how capture groups work or using too many capture groups can add overhead to the matching process. While capture groups are powerful, they require storing additional information.

3. **Forgetting to Escape Special Characters:**  Failing to escape characters with special meaning in regular expressions (like `.`, `*`, `+`, `?`, etc.) can lead to unexpected matching behavior.

4. **Inefficient Character Class Usage:**  Using overly broad or poorly constructed character classes can sometimes lead to less efficient matching compared to more specific patterns.

**Summary of Part 1 Functionality:**

The primary function of this first part of `v8/src/regexp/loong64/regexp-macro-assembler-loong64.cc` is to **lay the groundwork for generating architecture-specific machine code for regular expression matching on LOONG64 processors within the V8 engine.**  It defines the core structure, register conventions, stack layout, and provides the basic building blocks (methods) for implementing fundamental regular expression operations. This code sets the stage for the subsequent parts of the assembler, which will likely contain the more complex logic for handling various regex features and optimizations.

Prompt: 
```
这是目录为v8/src/regexp/loong64/regexp-macro-assembler-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/loong64/regexp-macro-assembler-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if V8_TARGET_ARCH_LOONG64

#include "src/regexp/loong64/regexp-macro-assembler-loong64.h"

#include "src/codegen/macro-assembler.h"
#include "src/heap/factory.h"
#include "src/logging/log.h"
#include "src/objects/code-inl.h"
#include "src/regexp/regexp-stack.h"
#include "src/snapshot/embedded/embedded-data-inl.h"

namespace v8 {
namespace internal {

/* clang-format off
 *
 * This assembler uses the following register assignment convention
 * - s0 : Unused.
 * - s1 : Pointer to current InstructionStream object including heap object tag.
 * - s2 : Current position in input, as negative offset from end of string.
 *        Please notice that this is the byte offset, not the character offset!
 * - s5 : Currently loaded character. Must be loaded using
 *        LoadCurrentCharacter before using any of the dispatch methods.
 * - s6 : Points to tip of backtrack stack
 * - s7 : End of input (points to byte after last character in input).
 * - fp : Frame pointer. Used to access arguments, local variables and
 *        RegExp registers.
 * - sp : Points to tip of C stack.
 *
 * The remaining registers are free for computations.
 * Each call to a public method should retain this convention.
 *
 * The stack will have the following structure:
 *
 *  - fp[80]  Isolate* isolate   (address of the current isolate)               kIsolateOffset
 *                                                                              kStackFrameHeaderOffset
 *  --- sp when called ---
 *  - fp[72]  ra                 Return from RegExp code (ra).                  kReturnAddressOffset
 *  - fp[64]  old-fp             Old fp, callee saved.
 *  - fp[0..63]  s0..s7          Callee-saved registers s0..s7.
 *  --- frame pointer ----
 *  - fp[-8]  frame marker
 *  - fp[-16] direct_call        (1 = direct call from JS, 0 = from runtime)    kDirectCallOffset
 *  - fp[-24] capture array size (may fit multiple sets of matches)             kNumOutputRegistersOffset
 *  - fp[-32] int* capture_array (int[num_saved_registers_], for output).       kRegisterOutputOffset
 *  - fp[-40] end of input       (address of end of string).                    kInputEndOffset
 *  - fp[-48] start of input     (address of first character in string).        kInputStartOffset
 *  - fp[-56] start index        (character index of start).                    kStartIndexOffset
 *  - fp[-64] void* input_string (location of a handle containing the string).  kInputStringOffset
 *  - fp[-72] success counter    (only for global regexps to count matches).    kSuccessfulCapturesOffset
 *  - fp[-80] Offset of location before start of input (effectively character   kStringStartMinusOneOffsetOffset
 *            position -1). Used to initialize capture registers to a
 *            non-position.
 *  --------- The following output registers are 32-bit values. ---------
 *  - fp[-88] register 0         (Only positions must be stored in the first    kRegisterZeroOffset
 *  -         register 1          num_saved_registers_ registers)
 *  -         ...
 *  -         register num_registers-1
 *  --- sp ---
 *
 * The first num_saved_registers_ registers are initialized to point to
 * "character -1" in the string (i.e., char_size() bytes before the first
 * character of the string). The remaining registers start out as garbage.
 *
 * The data up to the return address must be placed there by the calling
 * code and the remaining arguments are passed in registers, e.g. by calling the
 * code entry as cast to a function with the signature:
 * int (*match)(String input_string,
 *              int start_index,
 *              Address start,
 *              Address end,
 *              int* capture_output_array,
 *              int num_capture_registers,
 *              bool direct_call = false,
 *              Isolate* isolate);
 * The call is performed by NativeRegExpMacroAssembler::Execute()
 * (in regexp-macro-assembler.cc) via the GeneratedCode wrapper.
 *
 * clang-format on
 */

#define __ ACCESS_MASM(masm_)

RegExpMacroAssemblerLOONG64::RegExpMacroAssemblerLOONG64(Isolate* isolate,
                                                         Zone* zone, Mode mode,
                                                         int registers_to_save)
    : NativeRegExpMacroAssembler(isolate, zone),
      masm_(std::make_unique<MacroAssembler>(
          isolate, CodeObjectRequired::kYes,
          NewAssemblerBuffer(kInitialBufferSize))),
      no_root_array_scope_(masm_.get()),
      mode_(mode),
      num_registers_(registers_to_save),
      num_saved_registers_(registers_to_save),
      entry_label_(),
      start_label_(),
      success_label_(),
      backtrack_label_(),
      exit_label_(),
      internal_failure_label_() {
  DCHECK_EQ(0, registers_to_save % 2);
  __ jmp(&entry_label_);  // We'll write the entry code later.
  // If the code gets too big or corrupted, an internal exception will be
  // raised, and we will exit right away.
  __ bind(&internal_failure_label_);
  __ li(a0, Operand(FAILURE));
  __ Ret();
  __ bind(&start_label_);  // And then continue from here.
}

RegExpMacroAssemblerLOONG64::~RegExpMacroAssemblerLOONG64() {
  // Unuse labels in case we throw away the assembler without calling GetCode.
  entry_label_.Unuse();
  start_label_.Unuse();
  success_label_.Unuse();
  backtrack_label_.Unuse();
  exit_label_.Unuse();
  check_preempt_label_.Unuse();
  stack_overflow_label_.Unuse();
  internal_failure_label_.Unuse();
  fallback_label_.Unuse();
}

int RegExpMacroAssemblerLOONG64::stack_limit_slack_slot_count() {
  return RegExpStack::kStackLimitSlackSlotCount;
}

void RegExpMacroAssemblerLOONG64::AdvanceCurrentPosition(int by) {
  if (by != 0) {
    __ Add_d(current_input_offset(), current_input_offset(),
             Operand(by * char_size()));
  }
}

void RegExpMacroAssemblerLOONG64::AdvanceRegister(int reg, int by) {
  DCHECK_LE(0, reg);
  DCHECK_GT(num_registers_, reg);
  if (by != 0) {
    __ Ld_d(a0, register_location(reg));
    __ Add_d(a0, a0, Operand(by));
    __ St_d(a0, register_location(reg));
  }
}

void RegExpMacroAssemblerLOONG64::Backtrack() {
  CheckPreemption();
  if (has_backtrack_limit()) {
    Label next;
    __ Ld_d(a0, MemOperand(frame_pointer(), kBacktrackCountOffset));
    __ Add_d(a0, a0, Operand(1));
    __ St_d(a0, MemOperand(frame_pointer(), kBacktrackCountOffset));
    __ Branch(&next, ne, a0, Operand(backtrack_limit()));

    // Backtrack limit exceeded.
    if (can_fallback()) {
      __ jmp(&fallback_label_);
    } else {
      // Can't fallback, so we treat it as a failed match.
      Fail();
    }

    __ bind(&next);
  }
  // Pop Code offset from backtrack stack, add Code and jump to location.
  Pop(a0);
  __ Add_d(a0, a0, code_pointer());
  __ Jump(a0);
}

void RegExpMacroAssemblerLOONG64::Bind(Label* label) { __ bind(label); }

void RegExpMacroAssemblerLOONG64::CheckCharacter(uint32_t c, Label* on_equal) {
  BranchOrBacktrack(on_equal, eq, current_character(), Operand(c));
}

void RegExpMacroAssemblerLOONG64::CheckCharacterGT(base::uc16 limit,
                                                   Label* on_greater) {
  BranchOrBacktrack(on_greater, gt, current_character(), Operand(limit));
}

void RegExpMacroAssemblerLOONG64::CheckAtStart(int cp_offset,
                                               Label* on_at_start) {
  __ Ld_d(a1, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
  __ Add_d(a0, current_input_offset(),
           Operand(-char_size() + cp_offset * char_size()));
  BranchOrBacktrack(on_at_start, eq, a0, Operand(a1));
}

void RegExpMacroAssemblerLOONG64::CheckNotAtStart(int cp_offset,
                                                  Label* on_not_at_start) {
  __ Ld_d(a1, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
  __ Add_d(a0, current_input_offset(),
           Operand(-char_size() + cp_offset * char_size()));
  BranchOrBacktrack(on_not_at_start, ne, a0, Operand(a1));
}

void RegExpMacroAssemblerLOONG64::CheckCharacterLT(base::uc16 limit,
                                                   Label* on_less) {
  BranchOrBacktrack(on_less, lt, current_character(), Operand(limit));
}

void RegExpMacroAssemblerLOONG64::CheckGreedyLoop(Label* on_equal) {
  Label backtrack_non_equal;
  __ Ld_w(a0, MemOperand(backtrack_stackpointer(), 0));
  __ Branch(&backtrack_non_equal, ne, current_input_offset(), Operand(a0));
  __ Add_d(backtrack_stackpointer(), backtrack_stackpointer(),
           Operand(kIntSize));
  __ bind(&backtrack_non_equal);
  BranchOrBacktrack(on_equal, eq, current_input_offset(), Operand(a0));
}

void RegExpMacroAssemblerLOONG64::CheckNotBackReferenceIgnoreCase(
    int start_reg, bool read_backward, bool unicode, Label* on_no_match) {
  Label fallthrough;
  __ Ld_d(a0, register_location(start_reg));      // Index of start of capture.
  __ Ld_d(a1, register_location(start_reg + 1));  // Index of end of capture.
  __ Sub_d(a1, a1, a0);                           // Length of capture.

  // At this point, the capture registers are either both set or both cleared.
  // If the capture length is zero, then the capture is either empty or cleared.
  // Fall through in both cases.
  __ Branch(&fallthrough, eq, a1, Operand(zero_reg));

  if (read_backward) {
    __ Ld_d(t1, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
    __ Add_d(t1, t1, a1);
    BranchOrBacktrack(on_no_match, le, current_input_offset(), Operand(t1));
  } else {
    __ Add_d(t1, a1, current_input_offset());
    // Check that there are enough characters left in the input.
    BranchOrBacktrack(on_no_match, gt, t1, Operand(zero_reg));
  }

  if (mode_ == LATIN1) {
    Label success;
    Label fail;
    Label loop_check;

    // a0 - offset of start of capture.
    // a1 - length of capture.
    __ Add_d(a0, a0, Operand(end_of_input_address()));
    __ Add_d(a2, end_of_input_address(), Operand(current_input_offset()));
    if (read_backward) {
      __ Sub_d(a2, a2, Operand(a1));
    }
    __ Add_d(a1, a0, Operand(a1));

    // a0 - Address of start of capture.
    // a1 - Address of end of capture.
    // a2 - Address of current input position.

    Label loop;
    __ bind(&loop);
    __ Ld_bu(a3, MemOperand(a0, 0));
    __ addi_d(a0, a0, char_size());
    __ Ld_bu(a4, MemOperand(a2, 0));
    __ addi_d(a2, a2, char_size());

    __ Branch(&loop_check, eq, a4, Operand(a3));

    // Mismatch, try case-insensitive match (converting letters to lower-case).
    __ Or(a3, a3, Operand(0x20));  // Convert capture character to lower-case.
    __ Or(a4, a4, Operand(0x20));  // Also convert input character.
    __ Branch(&fail, ne, a4, Operand(a3));
    __ Sub_d(a3, a3, Operand('a'));
    __ Branch(&loop_check, ls, a3, Operand('z' - 'a'));
    // Latin-1: Check for values in range [224,254] but not 247.
    __ Sub_d(a3, a3, Operand(224 - 'a'));
    // Weren't Latin-1 letters.
    __ Branch(&fail, hi, a3, Operand(254 - 224));
    // Check for 247.
    __ Branch(&fail, eq, a3, Operand(247 - 224));

    __ bind(&loop_check);
    __ Branch(&loop, lt, a0, Operand(a1));
    __ jmp(&success);

    __ bind(&fail);
    GoTo(on_no_match);

    __ bind(&success);
    // Compute new value of character position after the matched part.
    __ Sub_d(current_input_offset(), a2, end_of_input_address());
    if (read_backward) {
      __ Ld_d(t1, register_location(start_reg));  // Index of start of capture.
      __ Ld_d(a2,
              register_location(start_reg + 1));  // Index of end of capture.
      __ Add_d(current_input_offset(), current_input_offset(), Operand(t1));
      __ Sub_d(current_input_offset(), current_input_offset(), Operand(a2));
    }
  } else {
    DCHECK(mode_ == UC16);

    int argument_count = 4;
    __ PrepareCallCFunction(argument_count, a2);

    // a0 - offset of start of capture.
    // a1 - length of capture.

    // Put arguments into arguments registers.
    // Parameters are
    //   a0: Address byte_offset1 - Address captured substring's start.
    //   a1: Address byte_offset2 - Address of current character position.
    //   a2: size_t byte_length - length of capture in bytes(!).
    //   a3: Isolate* isolate.

    // Address of start of capture.
    __ Add_d(a0, a0, Operand(end_of_input_address()));
    // Length of capture.
    __ mov(a2, a1);
    // Save length in callee-save register for use on return.
    __ mov(s3, a1);
    // Address of current input position.
    __ Add_d(a1, current_input_offset(), Operand(end_of_input_address()));
    if (read_backward) {
      __ Sub_d(a1, a1, Operand(s3));
    }
    // Isolate.
    __ li(a3, Operand(ExternalReference::isolate_address(masm_->isolate())));

    {
      AllowExternalCallThatCantCauseGC scope(masm_.get());
      ExternalReference function =
          unicode
              ? ExternalReference::re_case_insensitive_compare_unicode()
              : ExternalReference::re_case_insensitive_compare_non_unicode();
      CallCFunctionFromIrregexpCode(function, argument_count);
    }

    // Check if function returned non-zero for success or zero for failure.
    BranchOrBacktrack(on_no_match, eq, a0, Operand(zero_reg));
    // On success, increment position by length of capture.
    if (read_backward) {
      __ Sub_d(current_input_offset(), current_input_offset(), Operand(s3));
    } else {
      __ Add_d(current_input_offset(), current_input_offset(), Operand(s3));
    }
  }

  __ bind(&fallthrough);
}

void RegExpMacroAssemblerLOONG64::CheckNotBackReference(int start_reg,
                                                        bool read_backward,
                                                        Label* on_no_match) {
  Label fallthrough;

  // Find length of back-referenced capture.
  __ Ld_d(a0, register_location(start_reg));
  __ Ld_d(a1, register_location(start_reg + 1));
  __ Sub_d(a1, a1, a0);  // Length to check.

  // At this point, the capture registers are either both set or both cleared.
  // If the capture length is zero, then the capture is either empty or cleared.
  // Fall through in both cases.
  __ Branch(&fallthrough, eq, a1, Operand(zero_reg));

  if (read_backward) {
    __ Ld_d(t1, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
    __ Add_d(t1, t1, a1);
    BranchOrBacktrack(on_no_match, le, current_input_offset(), Operand(t1));
  } else {
    __ Add_d(t1, a1, current_input_offset());
    // Check that there are enough characters left in the input.
    BranchOrBacktrack(on_no_match, gt, t1, Operand(zero_reg));
  }

  // Compute pointers to match string and capture string.
  __ Add_d(a0, a0, Operand(end_of_input_address()));
  __ Add_d(a2, end_of_input_address(), Operand(current_input_offset()));
  if (read_backward) {
    __ Sub_d(a2, a2, Operand(a1));
  }
  __ Add_d(a1, a1, Operand(a0));

  Label loop;
  __ bind(&loop);
  if (mode_ == LATIN1) {
    __ Ld_bu(a3, MemOperand(a0, 0));
    __ addi_d(a0, a0, char_size());
    __ Ld_bu(a4, MemOperand(a2, 0));
    __ addi_d(a2, a2, char_size());
  } else {
    DCHECK(mode_ == UC16);
    __ Ld_hu(a3, MemOperand(a0, 0));
    __ addi_d(a0, a0, char_size());
    __ Ld_hu(a4, MemOperand(a2, 0));
    __ addi_d(a2, a2, char_size());
  }
  BranchOrBacktrack(on_no_match, ne, a3, Operand(a4));
  __ Branch(&loop, lt, a0, Operand(a1));

  // Move current character position to position after match.
  __ Sub_d(current_input_offset(), a2, end_of_input_address());
  if (read_backward) {
    __ Ld_d(t1, register_location(start_reg));  // Index of start of capture.
    __ Ld_d(a2, register_location(start_reg + 1));  // Index of end of capture.
    __ Add_d(current_input_offset(), current_input_offset(), Operand(t1));
    __ Sub_d(current_input_offset(), current_input_offset(), Operand(a2));
  }
  __ bind(&fallthrough);
}

void RegExpMacroAssemblerLOONG64::CheckNotCharacter(uint32_t c,
                                                    Label* on_not_equal) {
  BranchOrBacktrack(on_not_equal, ne, current_character(), Operand(c));
}

void RegExpMacroAssemblerLOONG64::CheckCharacterAfterAnd(uint32_t c,
                                                         uint32_t mask,
                                                         Label* on_equal) {
  __ And(a0, current_character(), Operand(mask));
  Operand rhs = (c == 0) ? Operand(zero_reg) : Operand(c);
  BranchOrBacktrack(on_equal, eq, a0, rhs);
}

void RegExpMacroAssemblerLOONG64::CheckNotCharacterAfterAnd(
    uint32_t c, uint32_t mask, Label* on_not_equal) {
  __ And(a0, current_character(), Operand(mask));
  Operand rhs = (c == 0) ? Operand(zero_reg) : Operand(c);
  BranchOrBacktrack(on_not_equal, ne, a0, rhs);
}

void RegExpMacroAssemblerLOONG64::CheckNotCharacterAfterMinusAnd(
    base::uc16 c, base::uc16 minus, base::uc16 mask, Label* on_not_equal) {
  DCHECK_GT(String::kMaxUtf16CodeUnit, minus);
  __ Sub_d(a0, current_character(), Operand(minus));
  __ And(a0, a0, Operand(mask));
  BranchOrBacktrack(on_not_equal, ne, a0, Operand(c));
}

void RegExpMacroAssemblerLOONG64::CheckCharacterInRange(base::uc16 from,
                                                        base::uc16 to,
                                                        Label* on_in_range) {
  __ Sub_d(a0, current_character(), Operand(from));
  // Unsigned lower-or-same condition.
  BranchOrBacktrack(on_in_range, ls, a0, Operand(to - from));
}

void RegExpMacroAssemblerLOONG64::CheckCharacterNotInRange(
    base::uc16 from, base::uc16 to, Label* on_not_in_range) {
  __ Sub_d(a0, current_character(), Operand(from));
  // Unsigned higher condition.
  BranchOrBacktrack(on_not_in_range, hi, a0, Operand(to - from));
}

void RegExpMacroAssemblerLOONG64::CallIsCharacterInRangeArray(
    const ZoneList<CharacterRange>* ranges) {
  static const int kNumArguments = 3;
  __ PrepareCallCFunction(kNumArguments, a0);

  __ mov(a0, current_character());
  __ li(a1, Operand(GetOrAddRangeArray(ranges)));
  __ li(a2, Operand(ExternalReference::isolate_address(isolate())));

  {
    // We have a frame (set up in GetCode), but the assembler doesn't know.
    FrameScope scope(masm_.get(), StackFrame::MANUAL);
    CallCFunctionFromIrregexpCode(
        ExternalReference::re_is_character_in_range_array(), kNumArguments);
  }

  __ li(code_pointer(), Operand(masm_->CodeObject()));
}

bool RegExpMacroAssemblerLOONG64::CheckCharacterInRangeArray(
    const ZoneList<CharacterRange>* ranges, Label* on_in_range) {
  CallIsCharacterInRangeArray(ranges);
  BranchOrBacktrack(on_in_range, ne, a0, Operand(zero_reg));
  return true;
}

bool RegExpMacroAssemblerLOONG64::CheckCharacterNotInRangeArray(
    const ZoneList<CharacterRange>* ranges, Label* on_not_in_range) {
  CallIsCharacterInRangeArray(ranges);
  BranchOrBacktrack(on_not_in_range, eq, a0, Operand(zero_reg));
  return true;
}

void RegExpMacroAssemblerLOONG64::CheckBitInTable(Handle<ByteArray> table,
                                                  Label* on_bit_set) {
  __ li(a0, Operand(table));
  if (mode_ != LATIN1 || kTableMask != String::kMaxOneByteCharCode) {
    __ And(a1, current_character(), Operand(kTableSize - 1));
    __ Add_d(a0, a0, a1);
  } else {
    __ Add_d(a0, a0, current_character());
  }

  __ Ld_bu(a0, FieldMemOperand(a0, OFFSET_OF_DATA_START(ByteArray)));
  BranchOrBacktrack(on_bit_set, ne, a0, Operand(zero_reg));
}

void RegExpMacroAssemblerLOONG64::SkipUntilBitInTable(
    int cp_offset, Handle<ByteArray> table, Handle<ByteArray> nibble_table,
    int advance_by) {
  // TODO(pthier): Optimize. Table can be loaded outside of the loop.
  Label cont, again;
  Bind(&again);
  LoadCurrentCharacter(cp_offset, &cont, true);
  CheckBitInTable(table, &cont);
  AdvanceCurrentPosition(advance_by);
  GoTo(&again);
  Bind(&cont);
}

bool RegExpMacroAssemblerLOONG64::CheckSpecialClassRanges(
    StandardCharacterSet type, Label* on_no_match) {
  // Range checks (c in min..max) are generally implemented by an unsigned
  // (c - min) <= (max - min) check.
  // TODO(jgruber): No custom implementation (yet): s(UC16), S(UC16).
  switch (type) {
    case StandardCharacterSet::kWhitespace:
      // Match space-characters.
      if (mode_ == LATIN1) {
        // One byte space characters are '\t'..'\r', ' ' and \u00a0.
        Label success;
        __ Branch(&success, eq, current_character(), Operand(' '));
        // Check range 0x09..0x0D.
        __ Sub_d(a0, current_character(), Operand('\t'));
        __ Branch(&success, ls, a0, Operand('\r' - '\t'));
        // \u00a0 (NBSP).
        BranchOrBacktrack(on_no_match, ne, a0, Operand(0x00A0 - '\t'));
        __ bind(&success);
        return true;
      }
      return false;
    case StandardCharacterSet::kNotWhitespace:
      // The emitted code for generic character classes is good enough.
      return false;
    case StandardCharacterSet::kDigit:
      // Match Latin1 digits ('0'..'9').
      __ Sub_d(a0, current_character(), Operand('0'));
      BranchOrBacktrack(on_no_match, hi, a0, Operand('9' - '0'));
      return true;
    case StandardCharacterSet::kNotDigit:
      // Match non Latin1-digits.
      __ Sub_d(a0, current_character(), Operand('0'));
      BranchOrBacktrack(on_no_match, ls, a0, Operand('9' - '0'));
      return true;
    case StandardCharacterSet::kNotLineTerminator: {
      // Match non-newlines (not 0x0A('\n'), 0x0D('\r'), 0x2028 and 0x2029).
      __ Xor(a0, current_character(), Operand(0x01));
      // See if current character is '\n'^1 or '\r'^1, i.e., 0x0B or 0x0C.
      __ Sub_d(a0, a0, Operand(0x0B));
      BranchOrBacktrack(on_no_match, ls, a0, Operand(0x0C - 0x0B));
      if (mode_ == UC16) {
        // Compare original value to 0x2028 and 0x2029, using the already
        // computed (current_char ^ 0x01 - 0x0B). I.e., check for
        // 0x201D (0x2028 - 0x0B) or 0x201E.
        __ Sub_d(a0, a0, Operand(0x2028 - 0x0B));
        BranchOrBacktrack(on_no_match, ls, a0, Operand(1));
      }
      return true;
    }
    case StandardCharacterSet::kLineTerminator: {
      // Match newlines (0x0A('\n'), 0x0D('\r'), 0x2028 and 0x2029).
      __ Xor(a0, current_character(), Operand(0x01));
      // See if current character is '\n'^1 or '\r'^1, i.e., 0x0B or 0x0C.
      __ Sub_d(a0, a0, Operand(0x0B));
      if (mode_ == LATIN1) {
        BranchOrBacktrack(on_no_match, hi, a0, Operand(0x0C - 0x0B));
      } else {
        Label done;
        BranchOrBacktrack(&done, ls, a0, Operand(0x0C - 0x0B));
        // Compare original value to 0x2028 and 0x2029, using the already
        // computed (current_char ^ 0x01 - 0x0B). I.e., check for
        // 0x201D (0x2028 - 0x0B) or 0x201E.
        __ Sub_d(a0, a0, Operand(0x2028 - 0x0B));
        BranchOrBacktrack(on_no_match, hi, a0, Operand(1));
        __ bind(&done);
      }
      return true;
    }
    case StandardCharacterSet::kWord: {
      if (mode_ != LATIN1) {
        // Table is 256 entries, so all Latin1 characters can be tested.
        BranchOrBacktrack(on_no_match, hi, current_character(), Operand('z'));
      }
      ExternalReference map = ExternalReference::re_word_character_map();
      __ li(a0, Operand(map));
      __ Add_d(a0, a0, current_character());
      __ Ld_bu(a0, MemOperand(a0, 0));
      BranchOrBacktrack(on_no_match, eq, a0, Operand(zero_reg));
      return true;
    }
    case StandardCharacterSet::kNotWord: {
      Label done;
      if (mode_ != LATIN1) {
        // Table is 256 entries, so all Latin1 characters can be tested.
        __ Branch(&done, hi, current_character(), Operand('z'));
      }
      ExternalReference map = ExternalReference::re_word_character_map();
      __ li(a0, Operand(map));
      __ Add_d(a0, a0, current_character());
      __ Ld_bu(a0, MemOperand(a0, 0));
      BranchOrBacktrack(on_no_match, ne, a0, Operand(zero_reg));
      if (mode_ != LATIN1) {
        __ bind(&done);
      }
      return true;
    }
    case StandardCharacterSet::kEverything:
      // Match any character.
      return true;
  }
}

void RegExpMacroAssemblerLOONG64::Fail() {
  __ li(a0, Operand(FAILURE));
  __ jmp(&exit_label_);
}

void RegExpMacroAssemblerLOONG64::LoadRegExpStackPointerFromMemory(
    Register dst) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_stack_pointer(isolate());
  __ li(dst, ref);
  __ Ld_d(dst, MemOperand(dst, 0));
}

void RegExpMacroAssemblerLOONG64::StoreRegExpStackPointerToMemory(
    Register src, Register scratch) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_stack_pointer(isolate());
  __ li(scratch, ref);
  __ St_d(src, MemOperand(scratch, 0));
}

void RegExpMacroAssemblerLOONG64::PushRegExpBasePointer(Register stack_pointer,
                                                        Register scratch) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ li(scratch, ref);
  __ Ld_d(scratch, MemOperand(scratch, 0));
  __ Sub_d(scratch, stack_pointer, scratch);
  __ St_d(scratch, MemOperand(frame_pointer(), kRegExpStackBasePointerOffset));
}

void RegExpMacroAssemblerLOONG64::PopRegExpBasePointer(
    Register stack_pointer_out, Register scratch) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ Ld_d(stack_pointer_out,
          MemOperand(frame_pointer(), kRegExpStackBasePointerOffset));
  __ li(scratch, ref);
  __ Ld_d(scratch, MemOperand(scratch, 0));
  __ Add_d(stack_pointer_out, stack_pointer_out, scratch);
  StoreRegExpStackPointerToMemory(stack_pointer_out, scratch);
}

Handle<HeapObject> RegExpMacroAssemblerLOONG64::GetCode(Handle<String> source,
                                                        RegExpFlags flags) {
  Label return_v0;
  if (0 /* todo masm_->has_exception()*/) {
    // If the code gets corrupted due to long regular expressions and lack of
    // space on trampolines, an internal exception flag is set. If this case
    // is detected, we will jump into exit sequence right away.
    //__ bind_to(&entry_label_, internal_failure_label_.pos());
  } else {
    // Finalize code - write the entry point code now we know how many
    // registers we need.

    // Entry code:
    __ bind(&entry_label_);

    // Tell the system that we have a stack frame.  Because the type is MANUAL,
    // no is generated.
    FrameScope scope(masm_.get(), StackFrame::MANUAL);

    // Emit code to start a new stack frame. In the following we push all
    // callee-save registers (these end up above the fp) and all register
    // arguments (in {a0,a1,a2,a3}, these end up below the fp).
    // TODO(plind): we save s0..s7, but ONLY use s3 here - use the regs
    // or dont save.
    RegList registers_to_retain = {s0, s1, s2, s3, s4, s5, s6, s7};

    __ MultiPush({ra}, {fp}, registers_to_retain);
    __ mov(frame_pointer(), sp);

    // Registers {a0,a1,a2,a3} are the first four arguments as per the C calling
    // convention, and must match our specified offsets (e.g. kInputEndOffset).
    //
    // a0: input_string
    // a1: start_offset
    // a2: input_start
    // a3: input_end
    RegList argument_registers = {a0, a1, a2, a3};
    argument_registers |= {a4, a5, a6, a7};

    // Also push the frame marker.
    __ li(kScratchReg, Operand(StackFrame::TypeToMarker(StackFrame::IRREGEXP)));
    static_assert(kFrameTypeOffset == kFramePointerOffset - kSystemPointerSize);
    static_assert(kInputEndOffset ==
                  kRegisterOutputOffset - kSystemPointerSize);
    static_assert(kInputStartOffset == kInputEndOffset - kSystemPointerSize);
    static_assert(kStartIndexOffset == kInputStartOffset - kSystemPointerSize);
    static_assert(kInputStringOffset == kStartIndexOffset - kSystemPointerSize);
    __ MultiPush(argument_registers | kScratchReg);

    static_assert(kSuccessfulCapturesOffset ==
                  kInputStringOffset - kSystemPointerSize);
    __ mov(a0, zero_reg);
    __ Push(a0);  // Make room for success counter and initialize it to 0.
    static_assert(kStringStartMinusOneOffset ==
                  kSuccessfulCapturesOffset - kSystemPointerSize);
    __ Push(a0);  // Make room for "string start - 1" constant.
    static_assert(kBacktrackCountOffset ==
                  kStringStartMinusOneOffset - kSystemPointerSize);
    __ Push(a0);  // The backtrack counter
    static_assert(kRegExpStackBasePointerOffset ==
                  kBacktrackCountOffset - kSystemPointerSize);
    __ Push(a0);  // The regexp stack base ptr.

    // Initialize backtrack stack pointer. It must not be clobbered from here
    // on. Note the backtrack_stackpointer is callee-saved.
    static_assert(backtrack_stackpointer() == s7);
    LoadRegExpStackPointerFromMemory(backtrack_stackpointer());

    // Store the regexp base pointer - we'll later restore it / write it to
    // memory when returning from this irregexp code object.
    PushRegExpBasePointer(backtrack_stackpointer(), a1);

    {
      // Check if we have space on the stack for registers.
      Label stack_limit_hit, stack_ok;

      ExternalReference stack_limit =
          ExternalReference::address_of_jslimit(masm_->isolate());
      Operand extra_space_for_variables(num_registers_ * kSystemPointerSize);

      __ li(a0, Operand(stack_limit));
      __ Ld_d(a0, MemOperand(a0, 0));
      __ Sub_d(a0, sp, a0);
      // Handle it if the stack pointer is already below the stack limit.
      __ Branch(&stack_limit_hit, le, a0, Operand(zero_reg));
      // Check if there is room for the variable number of registers above
      // the stack limit.
      __ Branch(&stack_ok, hs, a0, extra_space_for_variables);
      // Exit with OutOfMemory exception. There is not enough space on the stack
      // for our working registers.
      __ li(a0, Operand(EXCEPTION));
      __ jmp(&return_v0);

      __ bind(&stack_limit_hit);
      CallCheckStackGuardState(a0, extra_space_for_variables);
      // If returned value is non-zero, we exit with the returned value as
      // result.
      __ Branch(&return_v0, ne, a0, Operand(zero_reg));

      __ bind(&stack_ok);
    }

    // Allocate space on stack for registers.
    __ Sub_d(sp, sp, Operand(num_registers_ * kSystemPointerSize));
    // Load string end.
    __ Ld_d(end_of_input_address(),
            MemOperand(frame_pointer(), kInputEndOffset));
    // Load input start.
    __ Ld_d(a0, MemOperand(frame_pointer(), kInputStartOffset));
    // Find negative length (offset of start relative to end).
    __ Sub_d(current_input_offset(), a0, end_of_input_address());
    // Set a0 to address of char before start of the input string
    // (effectively string position -1).
    __ Ld_d(a1, MemOperand(frame_pointer(), kStartIndexOffset));
    __ Sub_d(a0, current_input_offset(), Operand(char_size()));
    __ slli_d(t1, a1, (mode_ == UC16) ? 1 : 0);
    __ Sub_d(a0, a0, t1);
    // Store this value in a local variable, for use when clearing
    // position registers.
    __ St_d(a0, MemOperand(frame_pointer(), kStringStartMinusOneOffset));

    // Initialize code pointer register
    __ li(code_pointer(), Operand(masm_->CodeObject()), CONSTANT_SIZE);

    Label load_char_start_regexp;
    {
      Label start_regexp;
      // Load newline if index is at start, previous character otherwise.
      __ Branch(&load_char_start_regexp, ne, a1, Operand(zero_reg));
      __ li(current_character(), Operand('\n'));
      __ jmp(&start_regexp);

      // Global regexp restarts matching here.
      __ bind(&load_char_start_regexp);
      // Load previous char as initial value of current character register.
      LoadCurrentCharacterUnchecked(-1, 1);
      __ bind(&start_regexp);
    }

    // Initialize on-stack registers.
    if (num_saved_registers_ > 0) {  // Always is, if generated from a regexp.
      // Fill saved registers with initial value = start offset - 1.
      if (num_saved_registers_ > 8) {
        // Address of register 0.
        __ Add_d(a1, frame_pointer(), Operand(kRegisterZeroOffset));
        __ li(a2, Operand(num_saved_registers_));
        Label init_loop;
        __ bind(&init_loop);
        __ St_d(a0, MemOperand(a1, 0));
        __ Add_d(a1, a1, Operand(-kSystemPointerSize));
        __ Sub_d(a2, a2, Operand(1));
        __ Branch(&init_loop, ne, a2, Operand(zero_reg));
      } else {
        for (int i = 0; i < num_saved_registers_; i++) {
          __ St_d(a0, register_location(i));
        }
      }
    }

    __ jmp(&start_label_);

    // Exit code:
    if (success_label_.is_linked()) {
      // Save captures when successful.
      __ bind(&success_label_);
      if (num_saved_registers_ > 0) {
        // Copy captures to output.
        __ Ld_d
"""


```