Response:
Here's a breakdown of the thought process to analyze the provided C++ header file:

1. **Identify the Core Purpose:** The file name `regexp-macro-assembler-arm.h` strongly suggests it's related to regular expression processing (`regexp`) and low-level code generation (`macro-assembler`) specifically for the ARM architecture. The `v8` namespace confirms it's part of the V8 JavaScript engine.

2. **Recognize the Inheritance:** The class `RegExpMacroAssemblerARM` inherits from `NativeRegExpMacroAssembler`. This immediately tells us that this class *implements* the abstract interface defined by the base class for the ARM architecture. The base class likely defines common operations for all architectures, while this class provides the ARM-specific implementations.

3. **Analyze the Constructor and Destructor:**
    * The constructor `RegExpMacroAssemblerARM(Isolate* isolate, Zone* zone, Mode mode, int registers_to_save)` shows dependencies on `Isolate` (V8's isolated execution environment), `Zone` (memory management), `Mode` (likely Latin1/UTF-16), and the number of registers to preserve. This signals the class's role in a larger context.
    * The virtual destructor `~RegExpMacroAssemblerARM()` is standard practice for classes with inheritance, ensuring proper cleanup.

4. **Categorize Public Methods:** Group the public methods by their apparent function:
    * **Code Generation/Control Flow:**  `Bind`, `GoTo`, `Backtrack`, `Fail`, `Succeed`, `GetCode`, `AbortedCodeGeneration`. These methods are fundamental to building the generated machine code for the regex.
    * **Position Management:** `AdvanceCurrentPosition`, `SetCurrentPositionFromEnd`, `ReadCurrentPositionFromRegister`, `WriteCurrentPositionToRegister`, `PushCurrentPosition`, `PopCurrentPosition`. These handle tracking the current position within the input string.
    * **Register Manipulation:** `AdvanceRegister`, `SetRegister`, `PushRegister`, `PopRegister`, `ClearRegisters`, `ReadStackPointerFromRegister`, `WriteStackPointerToRegister`. These deal with storing and retrieving intermediate results in registers or on the stack.
    * **Character/String Matching:** `CheckCharacter`, `CheckCharacterAfterAnd`, `CheckCharacterGT`, `CheckCharacterLT`, `CheckNotCharacter`, `CheckNotCharacterAfterAnd`, `CheckNotCharacterAfterMinusAnd`, `CheckCharacterInRange`, `CheckCharacterNotInRange`, `CheckCharacterInRangeArray`, `CheckCharacterNotInRangeArray`, `CheckBitInTable`, `SkipUntilBitInTable`, `CheckNotBackReference`, `CheckNotBackReferenceIgnoreCase`, `CheckSpecialClassRanges`. These are the core logic for comparing characters or substrings against the input.
    * **Start/End of Input Checks:** `CheckAtStart`, `CheckNotAtStart`, `CheckPosition`. Methods for boundary conditions.
    * **Looping/Greedy Matching:** `CheckGreedyLoop`. Specific handling for certain regex patterns.
    * **Stack Management:** `PushBacktrack`. Related to managing the backtracking stack.
    * **Conditional Jumps:** `IfRegisterGE`, `IfRegisterLT`, `IfRegisterEqPos`. Control flow based on register values.
    * **Implementation Info:** `Implementation`. Returns an enum indicating the implementation type.
    * **Unchecked Character Loading:** `LoadCurrentCharacterUnchecked`. Potentially a performance optimization where bounds are assumed.
    * **Stack Guard:** `CheckStackGuardState`. A mechanism to prevent stack overflow during regex execution.

5. **Analyze Private Members:** Look at the private members and their roles:
    * **Constants:**  `kFramePointerOffset`, `kStoredRegistersOffset`, etc. These define the memory layout of the stack frame used during regex execution. Understanding these offsets is crucial for the assembler code.
    * **Helper Functions:** `CallCFunctionFromIrregexpCode`, `CheckPreemption`, `CheckStackLimit`, `CallCheckStackGuardState`, `CallIsCharacterInRangeArray`, `register_location`, `BranchOrBacktrack`, `SafeCall`, `SafeReturn`, `SafeCallTarget`, `Push`, `Pop`, `LoadRegExpStackPointerFromMemory`, `StoreRegExpStackPointerToMemory`, `PushRegExpBasePointer`, `PopRegExpBasePointer`. These are internal utilities for simplifying code generation and handling specific tasks.
    * **Registers:** `current_input_offset`, `current_character`, `end_of_input_address`, `frame_pointer`, `backtrack_stackpointer`, `code_pointer`. These constants define which ARM registers are used for specific purposes, a critical detail for ARM assembly.
    * **Data Members:** `masm_`, `no_root_array_scope_`, `mode_`, `num_registers_`, `num_saved_registers_`. State held by the assembler.
    * **Labels:** `entry_label_`, `start_label_`, etc. These are markers within the generated code, used for branching and control flow.

6. **Address Specific Questions from the Prompt:**
    * **Functionality Summary:** Synthesize the observations into a concise description.
    * **`.tq` Extension:**  Note that the file *is* a `.h` file, not `.tq`. Explain that `.tq` files are for Torque, a different V8 tool for generating C++.
    * **JavaScript Relationship:** Connect the methods to their corresponding JavaScript RegExp features (e.g., `CheckCharacter` relates to literal characters, `CheckCharacterInRange` to character sets, `CheckAtStart` to `^`, etc.). Provide illustrative JavaScript examples.
    * **Code Logic Inference:** Choose a simple method like `AdvanceCurrentPosition` and demonstrate how it likely works in terms of input and output.
    * **Common Programming Errors:** Think about how incorrect regex patterns or large inputs could lead to stack overflows or incorrect matching, and how this class tries to prevent those errors (e.g., stack limit checks).

7. **Refine and Organize:** Structure the analysis clearly with headings and bullet points for readability. Ensure accurate terminology and explanations.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this class directly executes regexps. **Correction:** Realized it's a *code generator* – it creates the machine code that will later execute.
* **Initial focus:**  Too much detail on individual methods. **Refinement:** Grouped methods by function to provide a higher-level understanding.
* **Overlooking private details:** Initially focused only on public methods. **Correction:**  Recognized the importance of private members for understanding the implementation.
* **Not connecting to JavaScript:** Initially described the C++ functionality in isolation. **Refinement:** Explicitly linked the methods to corresponding JavaScript regex features with examples.
* **Vague explanations:** Some initial explanations were too general. **Refinement:**  Provided more concrete examples and explanations, especially for the code logic inference.
This header file, `v8/src/regexp/arm/regexp-macro-assembler-arm.h`, defines the `RegExpMacroAssemblerARM` class. This class is a crucial part of V8's regular expression engine, specifically for generating ARM assembly code to efficiently execute regular expressions.

Here's a breakdown of its functionality:

**Core Functionality:**

* **Abstract Interface Implementation:** `RegExpMacroAssemblerARM` inherits from `NativeRegExpMacroAssembler`. This means it provides a concrete ARM-specific implementation for the abstract operations defined in the base class. These operations represent the fundamental steps involved in matching a regular expression against an input string.
* **ARM Assembly Code Generation:** The primary responsibility of this class is to emit ARM assembly instructions. Each method in this class corresponds to a specific low-level operation required for regex matching, such as checking characters, comparing registers, jumping to labels, etc.
* **State Management:** It manages the state required during regex matching, including the current position in the input string, the values of captured groups (registers), and the backtrack stack.
* **Optimization:** The ARM-specific implementation allows for optimizations tailored to the ARM architecture, leading to faster regex execution on ARM-based devices.
* **Stack Management:** It handles pushing and popping values from the backtrack stack, which is essential for implementing backtracking behavior in regular expressions (e.g., for quantifiers like `*`, `+`, `?`).
* **Handling Different Modes:** The constructor takes a `Mode` argument, likely indicating whether the input string is encoded in Latin-1 or UTF-16. This allows the assembler to generate appropriate instructions for handling different character sizes.
* **Stack Overflow Protection:** The `CheckStackGuardState` function and related methods are designed to prevent stack overflow errors during regex execution, which can happen with complex or deeply nested regular expressions.

**Detailed Functionality of Public Methods (Categorized):**

* **Control Flow:**
    * `Bind(Label* label)`: Defines a label in the generated code.
    * `GoTo(Label* label)`: Emits a jump instruction to the specified label.
    * `Backtrack()`: Emits instructions to initiate backtracking.
    * `Fail()`: Emits instructions to indicate a failed match.
    * `Succeed()`: Emits instructions to indicate a successful match.
* **Position Management:**
    * `AdvanceCurrentPosition(int by)`: Moves the current position in the input string forward.
    * `SetCurrentPositionFromEnd(int by)`: Sets the current position relative to the end of the string.
    * `ReadCurrentPositionFromRegister(int reg)`: Reads the current position from a register.
    * `WriteCurrentPositionToRegister(int reg, int cp_offset)`: Writes the current position to a register.
    * `PushCurrentPosition()`: Pushes the current position onto the backtrack stack.
    * `PopCurrentPosition()`: Pops the current position from the backtrack stack.
* **Register Management:**
    * `AdvanceRegister(int reg, int by)`: Increments or decrements the value of a register.
    * `SetRegister(int register_index, int to)`: Sets the value of a register.
    * `PushRegister(int register_index, StackCheckFlag check_stack_limit)`: Pushes the value of a register onto the backtrack stack.
    * `PopRegister(int register_index)`: Pops a value from the backtrack stack into a register.
    * `ClearRegisters(int reg_from, int reg_to)`: Sets a range of registers to a default value.
    * `ReadStackPointerFromRegister(int reg)`: Reads the backtrack stack pointer into a register.
    * `WriteStackPointerToRegister(int reg)`: Writes a value to the backtrack stack pointer.
* **Character Matching:**
    * `CheckCharacter(unsigned c, Label* on_equal)`: Checks if the current character matches a specific character.
    * `CheckCharacterAfterAnd(unsigned c, unsigned mask, Label* on_equal)`: Checks if the current character ANDed with a mask equals a specific value.
    * `CheckCharacterGT(base::uc16 limit, Label* on_greater)`: Checks if the current character is greater than a limit.
    * `CheckCharacterLT(base::uc16 limit, Label* on_less)`: Checks if the current character is less than a limit.
    * `CheckNotCharacter(unsigned c, Label* on_not_equal)`: Checks if the current character is not equal to a specific character.
    * `CheckCharacterInRange(base::uc16 from, base::uc16 to, Label* on_in_range)`: Checks if the current character is within a specified range.
    * `CheckCharacterNotInRange(base::uc16 from, base::uc16 to, Label* on_not_in_range)`: Checks if the current character is outside a specified range.
    * `CheckCharacterInRangeArray(...)`: Checks if the current character is in any of the ranges in an array.
    * `CheckCharacterNotInRangeArray(...)`: Checks if the current character is not in any of the ranges in an array.
    * `CheckBitInTable(...)`: Checks if a specific bit is set in a lookup table.
    * `SkipUntilBitInTable(...)`: Advances the current position until a specific bit is set in a lookup table.
    * `CheckSpecialClassRanges(...)`: Checks if the current character belongs to a predefined character class (e.g., digits, whitespace).
* **Backreference Handling:**
    * `CheckNotBackReference(...)`: Checks if the current match does not match a previously captured group.
    * `CheckNotBackReferenceIgnoreCase(...)`: Checks the same, ignoring case.
* **Start/End of Input Checks:**
    * `CheckAtStart(int cp_offset, Label* on_at_start)`: Checks if the current position is at the start of the input string (with an optional offset).
    * `CheckNotAtStart(int cp_offset, Label* on_not_at_start)`: Checks if the current position is not at the start of the input string.
    * `CheckPosition(int cp_offset, Label* on_outside_input)`: Checks if a given offset from the current position is within the bounds of the input string.
* **Looping:**
    * `CheckGreedyLoop(Label* on_tos_equals_current_position)`: Handles the logic for greedy loops in regular expressions.
* **Conditional Execution:**
    * `IfRegisterGE(int reg, int comparand, Label* if_ge)`: Jumps to a label if a register's value is greater than or equal to a comparand.
    * `IfRegisterLT(int reg, int comparand, Label* if_lt)`: Jumps to a label if a register's value is less than a comparand.
    * `IfRegisterEqPos(int reg, Label* if_eq)`: Jumps to a label if a register's value equals the current position.
* **Code Generation Output:**
    * `GetCode(Handle<String> source, RegExpFlags flags)`: Finalizes the generated assembly code and returns it as a `HeapObject`.
    * `AbortedCodeGeneration()`:  Indicates that code generation was aborted.
* **Stack Limit Check:**
    * `stack_limit_slack_slot_count()`: Returns the number of stack slots to leave free as slack for stack limit checks.
    * `CheckStackGuardState(...)`:  A static method called when the stack guard is triggered, used for handling potential stack overflows.
* **Other:**
    * `Implementation()`: Returns an enum indicating the specific implementation (likely `IrregexpImplementation::kARM`).
    * `LoadCurrentCharacterUnchecked(...)`: Loads the current character without performing bounds checks (for optimization).
    * `PushBacktrack(Label* label)`: Pushes a backtrack label onto the backtrack stack.

**Relationship to JavaScript and Examples:**

Yes, `RegExpMacroAssemblerARM` is directly related to the functionality of JavaScript's `RegExp` object. When you execute a regular expression in JavaScript, V8's regex engine (Irregexp) will use classes like `RegExpMacroAssemblerARM` to generate the low-level machine code that performs the matching.

Here are some examples of how the methods in this class relate to JavaScript regex features:

* **`CheckCharacter('a', ...)`:** This would be used when you have a literal character in your regex, like `/a/`.
   ```javascript
   const regex = /a/;
   regex.test("banana"); // Will use CheckCharacter to find 'a'
   ```

* **`CheckCharacterInRange('a', 'z', ...)`:** This corresponds to character sets like `[a-z]`.
   ```javascript
   const regex = /[a-z]/;
   regex.test("Banana"); // Will use CheckCharacterInRange
   ```

* **`CheckAtStart(0, ...)`:** This is used for the `^` anchor, matching the beginning of the string.
   ```javascript
   const regex = /^hello/;
   regex.test("hello world"); // Will use CheckAtStart
   ```

* **`CheckNotBackReference(1, false, ...)`:** This relates to backreferences like `\1`, matching the same text that was matched by the first capturing group.
   ```javascript
   const regex = /(.)a\1/;
   regex.test("aba"); // The \1 refers back to the 'a' captured by (.)
   ```

* **`CheckGreedyLoop(...)`:** This is used for quantifiers like `*`, `+`, and `{n,m}` which are "greedy" by default.
   ```javascript
   const regex = /a+/;
   regex.test("aaaa"); // Will use CheckGreedyLoop to match as many 'a's as possible
   ```

**Code Logic Inference (Example: `AdvanceCurrentPosition`):**

**Assumption:** The current position is maintained as an offset from the beginning of the input string.

**Input:**
* `by`: An integer representing the number of characters to advance.

**Likely Output (Generated Assembly):**

```assembly
// Assuming 'current_input_offset()' returns a register holding the current position
ADD  current_input_offset(), current_input_offset(), #by * char_size()
```

**Explanation:**
* `char_size()` would return the size of a character in bytes (1 for Latin-1, 2 for UTF-16).
* The instruction adds `by` times the character size to the register holding the current input offset, effectively moving the position forward.

**Common Programming Errors and How This Class Relates:**

* **Stack Overflow:** Complex regular expressions with many nested groups or quantifiers can lead to deep recursion and stack overflow. The `CheckStackGuardState` method is a mechanism to detect and potentially handle this. If a JavaScript regex causes a stack overflow, it's ultimately because the generated code (via `RegExpMacroAssemblerARM`) exceeded the stack limit during execution.
    ```javascript
    // Example of a potentially stack-overflowing regex (highly contrived)
    const regex = /^(a?){1000}b/;
    try {
      regex.test("aaaaaaaaaa...b"); // Many 'a's
    } catch (e) {
      console.error("Regex caused an error:", e); // Could be a stack overflow
    }
    ```
* **Incorrect Backreferences:**  Errors in using backreferences (e.g., referring to a non-existent group) can lead to unexpected matching behavior. The `CheckNotBackReference` methods ensure that the backreference matches the correct captured text. While this class generates the code, the logic of the regex itself is determined by the JavaScript developer.
    ```javascript
    const regex = /(a)(b)\2/; // \2 refers to the second captured group (b)
    console.log(regex.test("abb")); // true
    console.log(regex.test("aba")); // false - the second 'a' doesn't match 'b'
    ```
* **Performance Issues:** Inefficiently written regular expressions can be slow. While `RegExpMacroAssemblerARM` aims for efficient code generation, the structure of the regex itself plays a significant role. For instance, excessive backtracking can cause performance problems. This class helps by providing optimized primitives, but the developer needs to write good regex patterns.

In summary, `RegExpMacroAssemblerARM` is a fundamental building block in V8's regular expression engine, responsible for translating the abstract operations of regex matching into concrete ARM assembly instructions for efficient execution. It directly enables the functionality of JavaScript's `RegExp` object.

### 提示词
```
这是目录为v8/src/regexp/arm/regexp-macro-assembler-arm.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/arm/regexp-macro-assembler-arm.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_REGEXP_ARM_REGEXP_MACRO_ASSEMBLER_ARM_H_
#define V8_REGEXP_ARM_REGEXP_MACRO_ASSEMBLER_ARM_H_

#include "src/codegen/macro-assembler.h"
#include "src/regexp/regexp-macro-assembler.h"

namespace v8 {
namespace internal {

class V8_EXPORT_PRIVATE RegExpMacroAssemblerARM
    : public NativeRegExpMacroAssembler {
 public:
  RegExpMacroAssemblerARM(Isolate* isolate, Zone* zone, Mode mode,
                          int registers_to_save);
  ~RegExpMacroAssemblerARM() override;
  void AbortedCodeGeneration() override;
  int stack_limit_slack_slot_count() override;
  void AdvanceCurrentPosition(int by) override;
  void AdvanceRegister(int reg, int by) override;
  void Backtrack() override;
  void Bind(Label* label) override;
  void CheckAtStart(int cp_offset, Label* on_at_start) override;
  void CheckCharacter(unsigned c, Label* on_equal) override;
  void CheckCharacterAfterAnd(unsigned c, unsigned mask,
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
  void CheckNotCharacter(unsigned c, Label* on_not_equal) override;
  void CheckNotCharacterAfterAnd(unsigned c, unsigned mask,
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

  // Called from RegExp if the stack-guard is triggered.
  // If the code object is relocated, the return address is fixed before
  // returning.
  // {raw_code} is an Address because this is called via ExternalReference.
  static int CheckStackGuardState(Address* return_address, Address raw_code,
                                  Address re_frame, uintptr_t extra_space);

 private:
  // Offsets from frame_pointer() of function parameters and stored registers.
  static constexpr int kFramePointerOffset = 0;

  // Above the frame pointer - Stored registers and stack passed parameters.
  static constexpr int kStoredRegistersOffset = kFramePointerOffset;
  // Return address (stored from link register, read into pc on return).
  static constexpr int kReturnAddressOffset =
      kStoredRegistersOffset + 8 * kSystemPointerSize;
  // Stack parameters placed by caller.
  static constexpr int kRegisterOutputOffset =
      kReturnAddressOffset + kSystemPointerSize;
  static constexpr int kNumOutputRegistersOffset =
      kRegisterOutputOffset + kSystemPointerSize;
  static constexpr int kDirectCallOffset =
      kNumOutputRegistersOffset + kSystemPointerSize;
  static constexpr int kIsolateOffset = kDirectCallOffset + kSystemPointerSize;

  // Below the frame pointer - the stack frame type marker and locals.
  static constexpr int kFrameTypeOffset =
      kFramePointerOffset - kSystemPointerSize;
  static_assert(kFrameTypeOffset ==
                CommonFrameConstants::kContextOrFrameTypeOffset);
  // Register parameters stored by setup code.
  static constexpr int kInputEndOffset = kFrameTypeOffset - kSystemPointerSize;
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
  static constexpr int kRegExpCodeSize = 1024;

  static constexpr int kBacktrackConstantPoolSize = 4;

  void CallCFunctionFromIrregexpCode(ExternalReference function,
                                     int num_arguments);

  // Check whether preemption has been requested.
  void CheckPreemption();

  // Check whether we are exceeding the stack limit on the backtrack stack.
  void CheckStackLimit();

  void CallCheckStackGuardState(
      Operand extra_space_for_variables = Operand::Zero());
  void CallIsCharacterInRangeArray(const ZoneList<CharacterRange>* ranges);

  // The ebp-relative location of a regexp register.
  MemOperand register_location(int register_index);

  // Register holding the current input position as negative offset from
  // the end of the string.
  static constexpr Register current_input_offset() { return r6; }

  // The register containing the current character after LoadCurrentCharacter.
  static constexpr Register current_character() { return r7; }

  // Register holding address of the end of the input string.
  static constexpr Register end_of_input_address() { return r10; }

  // Register holding the frame address. Local variables, parameters and
  // regexp registers are addressed relative to this.
  static constexpr Register frame_pointer() { return fp; }

  // The register containing the backtrack stack top. Provides a meaningful
  // name to the register.
  static constexpr Register backtrack_stackpointer() { return r8; }

  // Register holding pointer to the current code object.
  static constexpr Register code_pointer() { return r5; }

  // Byte size of chars in the string to match (decided by the Mode argument)
  inline int char_size() const { return static_cast<int>(mode_); }

  // Equivalent to a conditional branch to the label, unless the label
  // is nullptr, in which case it is a conditional Backtrack.
  void BranchOrBacktrack(Condition condition, Label* to);

  // Call and return internally in the generated code in a way that
  // is GC-safe (i.e., doesn't leave absolute code addresses on the stack)
  inline void SafeCall(Label* to, Condition cond = al);
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
  // are always 0..num_saved_registers_-1)
  const int num_saved_registers_;

  // Labels used internally.
  Label entry_label_;
  Label start_label_;
  Label success_label_;
  Label backtrack_label_;
  Label exit_label_;
  Label check_preempt_label_;
  Label stack_overflow_label_;
  Label fallback_label_;
};

}  // namespace internal
}  // namespace v8

#endif  // V8_REGEXP_ARM_REGEXP_MACRO_ASSEMBLER_ARM_H_
```