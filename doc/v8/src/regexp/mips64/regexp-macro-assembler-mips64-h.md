Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Identify the core purpose:** The filename `regexp-macro-assembler-mips64.h` immediately signals that this file is about regular expressions (`regexp`), assembly code generation (`macro-assembler`), and the MIPS64 architecture. The `.h` extension confirms it's a header file, likely defining a class interface.

2. **Examine the `include` directives:**  The includes provide essential context:
    * `"src/codegen/macro-assembler.h"`:  This indicates the class builds upon a more general-purpose macro assembler, suggesting it specializes it for regular expressions.
    * `"src/regexp/regexp-macro-assembler.h"`: This is a strong clue that the current file *implements* a base class or interface related to RegExp assembly generation, hinting at an inheritance structure.

3. **Analyze the class declaration:**
    * `class V8_EXPORT_PRIVATE RegExpMacroAssemblerMIPS : public NativeRegExpMacroAssembler`:  This confirms the inheritance relationship. `V8_EXPORT_PRIVATE` suggests this class is part of V8's internal implementation. The name `RegExpMacroAssemblerMIPS` reinforces its role.

4. **Categorize the public methods:**  Read through the public methods and group them by their apparent function:
    * **Constructor/Destructor:** `RegExpMacroAssemblerMIPS(...)`, `~RegExpMacroAssemblerMIPS()` - Standard lifecycle management.
    * **Stack Management:** `stack_limit_slack_slot_count()`, `PushBacktrack()`, `PopCurrentPosition()`, `PushCurrentPosition()`, `PushRegister()`, `PopRegister()`, `WriteStackPointerToRegister()`, `ReadStackPointerFromRegister()`. These clearly deal with managing the execution stack for backtracking and register storage.
    * **Position/Register Manipulation:** `AdvanceCurrentPosition()`, `AdvanceRegister()`, `SetCurrentPositionFromEnd()`, `SetRegister()`, `ClearRegisters()`, `WriteCurrentPositionToRegister()`, `ReadCurrentPositionFromRegister()`. These manipulate the current position within the input string and the values of registers used by the RegExp engine.
    * **Control Flow/Branching:** `Bind()`, `GoTo()`, `IfRegisterGE()`, `IfRegisterLT()`, `IfRegisterEqPos()`. These control the flow of execution within the generated assembly code.
    * **Character Matching/Checking:**  A large group focusing on comparing characters: `CheckAtStart()`, `CheckCharacter()`, `CheckCharacterAfterAnd()`, `CheckCharacterGT()`, `CheckCharacterLT()`, `CheckNotAtStart()`, `CheckNotBackReference()`, `CheckNotBackReferenceIgnoreCase()`, `CheckNotCharacter()`, `CheckNotCharacterAfterAnd()`, `CheckNotCharacterAfterMinusAnd()`, `CheckCharacterInRange()`, `CheckCharacterNotInRange()`, `CheckCharacterInRangeArray()`, `CheckCharacterNotInRangeArray()`, `CheckBitInTable()`, `SkipUntilBitInTable()`, `CheckSpecialClassRanges()`. This is a core part of RegExp matching.
    * **Result/Failure:** `Fail()`, `Succeed()`, `GetCode()`, `Implementation()`. These handle the outcome of the matching process and retrieving the generated code.
    * **Utility/Other:** `CanReadUnaligned()`, `print_regexp_frame_constants()`, `CheckStackGuardState()`. These are supporting functions.

5. **Examine the private members:**  These provide implementation details:
    * **Constants:**  `kFramePointerOffset`, `kStoredRegistersOffset`, etc. - These define the memory layout of the stack frame used during RegExp execution. Their detailed naming provides a lot of insight.
    * **Helper Functions:** `PushCallerSavedRegisters()`, `PopCallerSavedRegisters()`, `CallCFunctionFromIrregexpCode()`, `CheckPreemption()`, `CheckStackLimit()`, `CallCheckStackGuardState()`, `CallIsCharacterInRangeArray()`, `register_location()`. These encapsulate common code generation patterns.
    * **Registers:** `current_input_offset()`, `current_character()`, `end_of_input_address()`, `frame_pointer()`, `backtrack_stackpointer()`, `code_pointer()`. These define the specific MIPS64 registers used for key variables.
    * **Data Members:** `masm_`, `no_root_array_scope_`, `mode_`, `num_registers_`, `num_saved_registers_`. These represent the internal state of the assembler.
    * **Labels:** `entry_label_`, `start_label_`, etc. - These are used for branching within the generated assembly code.

6. **Infer Functionality based on method names and parameters:**  The method names are quite descriptive. For example, `AdvanceCurrentPosition(int by)` clearly advances the current position in the input string. `CheckCharacter(uint32_t c, Label* on_equal)` checks if the current character matches `c` and branches to `on_equal` if it does.

7. **Address the specific questions in the prompt:**

    * **Functionality Listing:**  Synthesize the categorized methods into a list of functionalities.
    * **`.tq` extension:** Explicitly state that the file does *not* have the `.tq` extension and therefore is *not* a Torque file.
    * **JavaScript relevance and examples:**  Connect the functionalities to how regular expressions are used in JavaScript. Provide simple JavaScript examples that would internally trigger these assembler instructions. Focus on matching, capturing, and backtracking.
    * **Code Logic Reasoning:**  Choose a straightforward method like `CheckCharacter` and illustrate its behavior with a simple input and expected output, making assumptions about the current state.
    * **Common Programming Errors:** Relate the assembler functionality to common RegExp mistakes like incorrect escaping, forgetting anchors, or overly complex expressions leading to stack overflow.

8. **Review and Refine:**  Read through the analysis, ensuring clarity, accuracy, and completeness. Make sure the JavaScript examples are relevant and the code logic reasoning is easy to follow. Double-check for any missed details or misinterpretations.

This structured approach, moving from high-level overview to specific details and then addressing the prompt's constraints, helps to comprehensively analyze and understand the purpose and functionality of the given C++ header file.This header file, `v8/src/regexp/mips64/regexp-macro-assembler-mips64.h`, defines the `RegExpMacroAssemblerMIPS` class in the V8 JavaScript engine. This class is responsible for **generating native MIPS64 assembly code for regular expression matching**. It's a crucial part of V8's implementation of regular expressions, aiming for performance by executing the matching logic directly in machine code.

Here's a breakdown of its functionalities:

**Core Functionality: Generating MIPS64 Assembly for RegExp Operations**

The class provides a high-level interface for emitting MIPS64 instructions that perform various operations needed for regular expression matching. Think of it as a builder that takes abstract RegExp operations and translates them into concrete assembly instructions.

**Key Functionalities Exposed by the Class:**

* **Stack Management for Backtracking:**
    * `PushBacktrack(Label* label)`: Pushes a label onto the backtrack stack. This is used for non-deterministic matching where the engine might need to try alternative paths.
    * `PopCurrentPosition()`: Pops the last saved input position from the stack.
    * `PushCurrentPosition()`: Pushes the current input position onto the stack.
    * `PushRegister(int register_index, StackCheckFlag check_stack_limit)`: Saves the value of a RegExp register onto the stack.
    * `PopRegister(int register_index)`: Restores the value of a RegExp register from the stack.

* **Input Position Manipulation:**
    * `AdvanceCurrentPosition(int by)`: Moves the current position in the input string forward by a specified amount.
    * `AdvanceRegister(int reg, int by)`: Adds a value to a specific RegExp register.
    * `SetCurrentPositionFromEnd(int by)`: Sets the current position relative to the end of the input string.
    * `WriteCurrentPositionToRegister(int reg, int cp_offset)`: Writes the current position (with an optional offset) to a register.
    * `ReadCurrentPositionFromRegister(int reg)`: Reads the current position from a register.

* **Control Flow and Branching:**
    * `Bind(Label* label)`: Defines a label in the generated code.
    * `GoTo(Label* label)`: Emits an unconditional jump to a label.
    * `Backtrack()`: Emits code to jump to the backtrack label, effectively trying the previous alternative.
    * `CheckGreedyLoop(Label* on_tos_equals_current_position)`: Optimizes for greedy loops by checking if the top of the backtrack stack equals the current position.
    * `IfRegisterGE(int reg, int comparand, Label* if_ge)`: Emits a conditional branch if a register's value is greater than or equal to a comparand.
    * `IfRegisterLT(int reg, int comparand, Label* if_lt)`: Emits a conditional branch if a register's value is less than a comparand.
    * `IfRegisterEqPos(int reg, Label* if_eq)`: Emits a conditional branch if a register's value equals the current input position.

* **Character Matching and Checking:**
    * `CheckAtStart(int cp_offset, Label* on_at_start)`: Checks if the current position (with an offset) is at the beginning of the input.
    * `CheckCharacter(uint32_t c, Label* on_equal)`: Checks if the character at the current position matches a given character.
    * `CheckCharacterAfterAnd(uint32_t c, uint32_t mask, Label* on_equal)`: Checks if the character after a bitwise AND operation with a mask matches a given character.
    * `CheckCharacterGT(base::uc16 limit, Label* on_greater)`: Checks if the character is greater than a given limit.
    * `CheckCharacterLT(base::uc16 limit, Label* on_less)`: Checks if the character is less than a given limit.
    * `CheckNotAtStart(int cp_offset, Label* on_not_at_start)`: Checks if the current position is NOT at the beginning.
    * `CheckNotBackReference(...)`: Checks if a backreference (a previously captured group) does NOT match the current input.
    * `CheckNotCharacter(...)`: Checks if the character does NOT match a given character.
    * `CheckCharacterInRange(...)`: Checks if the character falls within a specified range.
    * `CheckCharacterNotInRange(...)`: Checks if the character does NOT fall within a specified range.
    * `CheckCharacterInRangeArray(...)`: Checks against an array of character ranges.
    * `CheckBitInTable(...)`: Checks if a bit is set in a lookup table for the current character.
    * `SkipUntilBitInTable(...)`: Advances the current position until a character with a set bit in the table is found.
    * `CheckPosition(int cp_offset, Label* on_outside_input)`: Checks if a given offset from the current position is within the bounds of the input string.
    * `CheckSpecialClassRanges(StandardCharacterSet type, Label* on_no_match)`: Handles checks for character classes like `\d`, `\w`, etc.

* **Register Manipulation:**
    * `SetRegister(int register_index, int to)`: Sets the value of a specific RegExp register.
    * `ClearRegisters(int reg_from, int reg_to)`: Sets a range of registers to a default value.

* **Success and Failure:**
    * `Succeed()`: Emits code to indicate a successful match.
    * `Fail()`: Emits code to indicate a failed match.

* **Code Generation and Management:**
    * `GetCode(Handle<String> source, RegExpFlags flags)`:  Finalizes the generated assembly code, creating an executable code object.
    * `Implementation()`: Returns the specific implementation type (Irregexp in this case).

* **Stack Overflow Handling:**
    * `CheckStackGuardState(...)`: A static method used to check the stack guard and potentially fix the return address if the code object has been relocated due to garbage collection.

**Is it a Torque file?**

The filename ends with `.h`, not `.tq`. Therefore, **it is not a v8 Torque source code file.** It's a standard C++ header file. Torque files are used in V8 for a higher-level, more type-safe way to generate code, but this particular file deals directly with MIPS64 assembly instructions.

**Relationship to JavaScript Functionality with Examples:**

This file is directly related to the performance of JavaScript regular expressions. When you execute a regular expression in JavaScript, V8 (if optimizing) will often compile that regular expression into native machine code using classes like `RegExpMacroAssemblerMIPS`.

Here are some JavaScript examples and how they might relate to the functionalities in the header file:

**1. Simple Character Matching:**

```javascript
const regex = /a/;
const str = "banana";
regex.test(str); // Returns true
```

Internally, this might involve calls to:

* `LoadCurrentCharacterUnchecked()` to get the character at the current position.
* `CheckCharacter('a', on_equal_label)` to compare it with 'a'.
* `GoTo(on_equal_label)` if the characters match.

**2. Matching at the Beginning of a String:**

```javascript
const regex = /^b/;
const str = "banana";
regex.test(str); // Returns false
```

This would likely use:

* `CheckAtStart(0, on_at_start_label)` to verify the current position is at the start of the string.

**3. Matching a Character Range:**

```javascript
const regex = /[aeiou]/;
const str = "hello";
regex.test(str); // Returns true
```

This could involve:

* `LoadCurrentCharacterUnchecked()` to get the current character.
* `CheckCharacterInRange('a', 'u', on_in_range_label)` to check if the character is within the vowel range.

**4. Backtracking (for example, with quantifiers):**

```javascript
const regex = /a*b/;
const str = "aaab";
regex.test(str); // Returns true
```

This would heavily utilize the stack management functionalities:

* `PushCurrentPosition()` to save the current position before trying to match 'a'.
* `PushBacktrack(backtrack_label)` to remember where to go back if the subsequent match fails.
* If the 'b' doesn't match immediately after the 'a*' part, `Backtrack()` would be called, popping the saved position and trying a different number of 'a's.

**5. Capturing Groups:**

```javascript
const regex = /(.)(.)/;
const str = "ab";
const result = str.match(regex); // result will be ["ab", "a", "b"]
```

This involves register manipulation:

* When a capturing group matches, the starting and ending positions of the match are likely stored in RegExp registers using `SetRegister()`.
* Later, `WriteCurrentPositionToRegister()` might be used to store the captured substrings.

**Code Logic Reasoning Example:**

Let's consider the `CheckCharacter(uint32_t c, Label* on_equal)` function.

**Hypothetical Input:**

* `c`: The character to check for, say 'x' (ASCII value 120).
* `on_equal`: A label in the generated assembly code, let's call it `match_x_label`.
* The current input position points to the character 'y' in the input string.

**Code Logic:**

The `CheckCharacter` function would generate MIPS64 assembly instructions to:

1. Load the character at the current input position into a register.
2. Compare the loaded character with the value of `c` (120).
3. If the characters are equal, emit a conditional branch instruction to the `match_x_label`.
4. If the characters are not equal, execution continues to the next instruction (which would likely handle the "not equal" case).

**Hypothetical Output (Assembly Snippet - simplified):**

```assembly
  // Assume current input character is in register $t0
  lb $t0, 0($s2)  // Load byte from address in $s2 (hypothetically holds current input pointer)
  li $t1, 120      // Load immediate value 120 (ASCII 'x') into $t1
  beq $t0, $t1, match_x_label // Branch to match_x_label if $t0 == $t1
  // ... code for the "not equal" case ...
match_x_label:
  // ... code to execute if the characters match ...
```

**User-Related Programming Errors:**

Understanding the underlying assembly generation can help diagnose some common RegExp errors:

1. **Stack Overflow in Complex Regexes:** Overly complex regular expressions with many nested quantifiers and alternatives can lead to a large number of states to track, potentially overflowing the backtrack stack. This could manifest as a "Maximum call stack size exceeded" error in JavaScript (though the underlying reason in the RegExp engine might be stack exhaustion).

   * **Example:** `/((a+)+)+$/.test("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")` - This highly nested structure can cause excessive backtracking.

2. **Performance Issues with Unanchored Regexes:**  Forgetting to anchor a regex with `^` or `$` when you intend to match only at the beginning or end can lead to the engine trying to match the pattern at every possible starting position in the string, resulting in poor performance. The assembly code would involve repeatedly advancing the current position and trying the match again.

   * **Example:** `/pattern/`.test("some text with pattern inside") -  The engine will try to match "pattern" starting at every index.

3. **Incorrect Use of Backreferences:**  Errors in backreference syntax or logic can lead to unexpected matching behavior. The `CheckNotBackReference` family of functions are crucial for implementing backreferences, and errors in the RegExp pattern can lead to these checks failing when you expect them to succeed (or vice versa).

   * **Example:** `/(\w+), \1/`.test("word, wrongword") - The backreference `\1` should match the first captured group ("word"), but here it doesn't.

4. **Catastrophic Backtracking:** Certain regex patterns, especially those with overlapping optional parts, can cause exponential backtracking, leading to extremely long execution times. This is directly related to how the `PushBacktrack` and `Backtrack` mechanisms are used in the generated code.

   * **Example:** `/a*b*c*/.exec("aaaaaaaaaaaaaaaaaaaaaaaaaaaaac")` on a long string without a 'b' will cause the engine to try many combinations.

In summary, `v8/src/regexp/mips64/regexp-macro-assembler-mips64.h` is a foundational component for efficient regular expression execution in V8 on MIPS64 architectures. It provides the building blocks to translate abstract RegExp operations into low-level machine code, influencing the performance and behavior of JavaScript's regular expression features.

Prompt: 
```
这是目录为v8/src/regexp/mips64/regexp-macro-assembler-mips64.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/mips64/regexp-macro-assembler-mips64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2011 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_REGEXP_MIPS64_REGEXP_MACRO_ASSEMBLER_MIPS64_H_
#define V8_REGEXP_MIPS64_REGEXP_MACRO_ASSEMBLER_MIPS64_H_

#include "src/codegen/macro-assembler.h"
#include "src/regexp/regexp-macro-assembler.h"

namespace v8 {
namespace internal {

class V8_EXPORT_PRIVATE RegExpMacroAssemblerMIPS
    : public NativeRegExpMacroAssembler {
 public:
  RegExpMacroAssemblerMIPS(Isolate* isolate, Zone* zone, Mode mode,
                           int registers_to_save);
  ~RegExpMacroAssemblerMIPS() override;
  int stack_limit_slack_slot_count() override;
  void AdvanceCurrentPosition(int by) override;
  void AdvanceRegister(int reg, int by) override;
  void Backtrack() override;
  void Bind(Label* label) override;
  void CheckAtStart(int cp_offset, Label* on_at_start) override;
  void CheckCharacter(uint32_t c, Label* on_equal) override;
  void CheckCharacterAfterAnd(uint32_t c, uint32_t mask,
                              Label* on_equal) override;
  void CheckCharacterGT(base::uc16 limit, Label* on_greater) override;
  void CheckCharacterLT(base::uc16 limit, Label* on_less) override;
  // A "greedy loop" is a loop that is both greedy and with a simple
  // body. It has a particularly simple implementation.
  void CheckGreedyLoop(Label* on_tos_equals_current_position) override;
  void CheckNotAtStart(int cp_offset, Label* on_not_at_start) override;
  void CheckNotBackReference(int start_reg, bool read_backward,
                             Label* on_no_match) override;
  void CheckNotBackReferenceIgnoreCase(int start_reg, bool read_backward,
                                       bool unicode,
                                       Label* on_no_match) override;
  void CheckNotCharacter(uint32_t c, Label* on_not_equal) override;
  void CheckNotCharacterAfterAnd(uint32_t c, uint32_t mask,
                                 Label* on_not_equal) override;
  void CheckNotCharacterAfterMinusAnd(base::uc16 c, base::uc16 minus,
                                      base::uc16 mask,
                                      Label* on_not_equal) override;
  void CheckCharacterInRange(base::uc16 from, base::uc16 to,
                             Label* on_in_range) override;
  void CheckCharacterNotInRange(base::uc16 from, base::uc16 to,
                                Label* on_not_in_range) override;
  bool CheckCharacterInRangeArray(const ZoneList<CharacterRange>* ranges,
                                  Label* on_in_range) override;
  bool CheckCharacterNotInRangeArray(const ZoneList<CharacterRange>* ranges,
                                     Label* on_not_in_range) override;
  void CheckBitInTable(Handle<ByteArray> table, Label* on_bit_set) override;
  void SkipUntilBitInTable(int cp_offset, Handle<ByteArray> table,
                           Handle<ByteArray> nibble_table,
                           int advance_by) override;

  // Checks whether the given offset from the current position is before
  // the end of the string.
  void CheckPosition(int cp_offset, Label* on_outside_input) override;
  bool CheckSpecialClassRanges(StandardCharacterSet type,
                               Label* on_no_match) override;
  void Fail() override;
  Handle<HeapObject> GetCode(Handle<String> source, RegExpFlags flags) override;
  void GoTo(Label* label) override;
  void IfRegisterGE(int reg, int comparand, Label* if_ge) override;
  void IfRegisterLT(int reg, int comparand, Label* if_lt) override;
  void IfRegisterEqPos(int reg, Label* if_eq) override;
  IrregexpImplementation Implementation() override;
  void LoadCurrentCharacterUnchecked(int cp_offset,
                                     int character_count) override;
  void PopCurrentPosition() override;
  void PopRegister(int register_index) override;
  void PushBacktrack(Label* label) override;
  void PushCurrentPosition() override;
  void PushRegister(int register_index,
                    StackCheckFlag check_stack_limit) override;
  void ReadCurrentPositionFromRegister(int reg) override;
  void ReadStackPointerFromRegister(int reg) override;
  void SetCurrentPositionFromEnd(int by) override;
  void SetRegister(int register_index, int to) override;
  bool Succeed() override;
  void WriteCurrentPositionToRegister(int reg, int cp_offset) override;
  void ClearRegisters(int reg_from, int reg_to) override;
  void WriteStackPointerToRegister(int reg) override;
  bool CanReadUnaligned() const override;

  // Called from RegExp if the stack-guard is triggered.
  // If the code object is relocated, the return address is fixed before
  // returning.
  // {raw_code} is an Address because this is called via ExternalReference.
  static int64_t CheckStackGuardState(Address* return_address, Address raw_code,
                                      Address re_frame, uintptr_t extra_space);

  void print_regexp_frame_constants();

 private:
  // Offsets from frame_pointer() of function parameters and stored registers.
  static constexpr int kFramePointerOffset = 0;

  // Above the frame pointer - Stored registers and stack passed parameters.
  static constexpr int kStoredRegistersOffset = kFramePointerOffset;
  // Return address (stored from link register, read into pc on return).

  // TODO(plind): This 9 - is 8 s-regs (s0..s7) plus fp.

  static constexpr int kReturnAddressOffset =
      kStoredRegistersOffset + 9 * kSystemPointerSize;
  // Stack frame header.
  static constexpr int kStackFrameHeaderOffset = kReturnAddressOffset;

  // Below the frame pointer.
  static constexpr int kFrameTypeOffset =
      kFramePointerOffset - kSystemPointerSize;
  static_assert(kFrameTypeOffset ==
                CommonFrameConstants::kContextOrFrameTypeOffset);
  // Register parameters stored by setup code.
  static constexpr int kIsolateOffset = kFrameTypeOffset - kSystemPointerSize;
  static constexpr int kDirectCallOffset = kIsolateOffset - kSystemPointerSize;
  static constexpr int kNumOutputRegistersOffset =
      kDirectCallOffset - kSystemPointerSize;
  static constexpr int kRegisterOutputOffset =
      kNumOutputRegistersOffset - kSystemPointerSize;

  // Register parameters stored by setup code.
  static constexpr int kInputEndOffset =
      kRegisterOutputOffset - kSystemPointerSize;
  static constexpr int kInputStartOffset = kInputEndOffset - kSystemPointerSize;
  static constexpr int kStartIndexOffset =
      kInputStartOffset - kSystemPointerSize;
  static constexpr int kInputStringOffset =
      kStartIndexOffset - kSystemPointerSize;
  // When adding local variables remember to push space for them in
  // the frame in GetCode.
  static constexpr int kSuccessfulCapturesOffset =
      kInputStringOffset - kSystemPointerSize;
  static constexpr int kStringStartMinusOneOffset =
      kSuccessfulCapturesOffset - kSystemPointerSize;
  static constexpr int kBacktrackCountOffset =
      kStringStartMinusOneOffset - kSystemPointerSize;
  // Stores the initial value of the regexp stack pointer in a
  // position-independent representation (in case the regexp stack grows and
  // thus moves).
  static constexpr int kRegExpStackBasePointerOffset =
      kBacktrackCountOffset - kSystemPointerSize;

  // First register address. Following registers are below it on the stack.
  static constexpr int kRegisterZeroOffset =
      kRegExpStackBasePointerOffset - kSystemPointerSize;

  // Initial size of code buffer.
  static constexpr int kInitialBufferSize = 1024;

  void PushCallerSavedRegisters();
  void PopCallerSavedRegisters();

  void CallCFunctionFromIrregexpCode(ExternalReference function,
                                     int num_arguments);

  // Check whether preemption has been requested.
  void CheckPreemption();

  // Check whether we are exceeding the stack limit on the backtrack stack.
  void CheckStackLimit();


  // Generate a call to CheckStackGuardState.
  void CallCheckStackGuardState(Register scratch,
                                Operand extra_space = Operand(0));
  void CallIsCharacterInRangeArray(const ZoneList<CharacterRange>* ranges);

  // The ebp-relative location of a regexp register.
  MemOperand register_location(int register_index);

  // Register holding the current input position as negative offset from
  // the end of the string.
  static constexpr Register current_input_offset() { return s2; }

  // The register containing the current character after LoadCurrentCharacter.
  static constexpr Register current_character() { return s5; }

  // Register holding address of the end of the input string.
  static constexpr Register end_of_input_address() { return s6; }

  // Register holding the frame address. Local variables, parameters and
  // regexp registers are addressed relative to this.
  static constexpr Register frame_pointer() { return fp; }

  // The register containing the backtrack stack top. Provides a meaningful
  // name to the register.
  static constexpr Register backtrack_stackpointer() { return s7; }

  // Register holding pointer to the current code object.
  static constexpr Register code_pointer() { return s1; }

  // Byte size of chars in the string to match (decided by the Mode argument).
  inline int char_size() const { return static_cast<int>(mode_); }

  // Equivalent to a conditional branch to the label, unless the label
  // is nullptr, in which case it is a conditional Backtrack.
  void BranchOrBacktrack(Label* to,
                         Condition condition,
                         Register rs,
                         const Operand& rt);

  // Call and return internally in the generated code in a way that
  // is GC-safe (i.e., doesn't leave absolute code addresses on the stack)
  inline void SafeCall(Label* to,
                       Condition cond,
                       Register rs,
                       const Operand& rt);
  inline void SafeReturn();
  inline void SafeCallTarget(Label* name);

  // Pushes the value of a register on the backtrack stack. Decrements the
  // stack pointer by a word size and stores the register's value there.
  inline void Push(Register source);

  // Pops a value from the backtrack stack. Reads the word at the stack pointer
  // and increments it by a word size.
  inline void Pop(Register target);

  void LoadRegExpStackPointerFromMemory(Register dst);
  void StoreRegExpStackPointerToMemory(Register src, Register scratch);
  void PushRegExpBasePointer(Register stack_pointer, Register scratch);
  void PopRegExpBasePointer(Register stack_pointer_out, Register scratch);

  Isolate* isolate() const { return masm_->isolate(); }

  const std::unique_ptr<MacroAssembler> masm_;
  const NoRootArrayScope no_root_array_scope_;

  // Which mode to generate code for (Latin1 or UC16).
  const Mode mode_;

  // One greater than maximal register index actually used.
  int num_registers_;

  // Number of registers to output at the end (the saved registers
  // are always 0..num_saved_registers_-1).
  const int num_saved_registers_;

  // Labels used internally.
  Label entry_label_;
  Label start_label_;
  Label success_label_;
  Label backtrack_label_;
  Label exit_label_;
  Label check_preempt_label_;
  Label stack_overflow_label_;
  Label internal_failure_label_;
  Label fallback_label_;
};

}  // namespace internal
}  // namespace v8

#endif  // V8_REGEXP_MIPS64_REGEXP_MACRO_ASSEMBLER_MIPS64_H_

"""

```