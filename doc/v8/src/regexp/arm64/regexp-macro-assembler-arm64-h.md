Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Identify the Core Purpose:** The file name `regexp-macro-assembler-arm64.h` immediately suggests its primary role: assembling low-level ARM64 instructions for regular expression matching within the V8 JavaScript engine. The `RegExpMacroAssembler` part is key – it's responsible for taking high-level regexp operations and translating them into machine code. The `arm64` part specifies the target architecture.

2. **Analyze the Header Guards:** The `#ifndef`, `#define`, and `#endif` are standard C++ header guards, preventing multiple inclusions and compilation errors. This is a boilerplate check and doesn't reveal functionality.

3. **Include Directives:** Examine the `#include` directives.
    * `"src/base/strings.h"`: Suggests string manipulation utilities.
    * `"src/codegen/arm64/assembler-arm64.h"`: This is crucial. It confirms that this class uses the ARM64 assembler to generate code. This is the core mechanism for low-level instruction generation.
    * `"src/codegen/macro-assembler.h"`:  This likely provides a more general, architecture-independent interface for assembly, from which the ARM64-specific assembler might inherit or be based on.
    * `"src/regexp/regexp-macro-assembler.h"`:  This is another key include. It indicates this class *inherits* from or implements an interface defined by `NativeRegExpMacroAssembler`. This parent class probably defines the common interface for all regexp macro assemblers, regardless of the target architecture.

4. **Namespace Exploration:**  The code is within `namespace v8 { namespace internal { ... } }`. This is a common practice in large projects to organize code and avoid naming conflicts. It tells us this is an internal implementation detail of V8.

5. **Class Declaration:**  The main class `RegExpMacroAssemblerARM64` is declared, inheriting publicly from `NativeRegExpMacroAssembler`. The `V8_EXPORT_PRIVATE` macro suggests this class is intended for internal use within V8 and not part of the public API.

6. **Constructor and Destructor:** The constructor takes `Isolate*`, `Zone*`, `Mode`, and `int registers_to_save`. These parameters likely configure the assembler's environment (Isolate), memory management (Zone), matching mode (LATIN1/UC16), and register handling. The virtual destructor is standard practice for classes with virtual methods. `AbortedCodeGeneration` is a signal that something went wrong during assembly.

7. **Virtual Method Overrides - The Core Functionality:** This is where the real meat of the functionality lies. Each virtual method inherited from `NativeRegExpMacroAssembler` represents a specific operation in the regular expression matching process. Go through each one and try to understand its purpose based on its name:
    * **Positioning:** `AdvanceCurrentPosition`, `SetCurrentPositionFromEnd`, `ReadCurrentPositionFromRegister`, `WriteCurrentPositionToRegister`. These deal with manipulating the current position in the input string.
    * **Register Manipulation:** `AdvanceRegister`, `SetRegister`, `ClearRegisters`, `PushRegister`, `PopRegister`. These manage registers used to store captured groups or other intermediate values.
    * **Backtracking:** `Backtrack`, `PushBacktrack`, `PopCurrentPosition`, `PushCurrentPosition`. Essential for the backtracking nature of regular expression matching.
    * **Matching Characters:** `CheckCharacter`, `CheckCharacterAfterAnd`, `CheckCharacterGT`, `CheckCharacterLT`, `CheckCharacters`, `CheckNotCharacter`, `CheckNotCharacterAfterAnd`, `CheckNotCharacterAfterMinusAnd`, `CheckCharacterInRange`, `CheckCharacterNotInRange`, `CheckCharacterInRangeArray`, `CheckCharacterNotInRangeArray`. These are the core operations for comparing the current character with expected patterns.
    * **Start/End of String Checks:** `CheckAtStart`, `CheckNotAtStart`, `CheckPosition`. Handle anchors like `^` and `$`.
    * **Backreferences:** `CheckNotBackReference`, `CheckNotBackReferenceIgnoreCase`. Implement the ability to match previously captured groups.
    * **Greedy Loops:** `CheckGreedyLoop`. Optimization for certain types of loops.
    * **Character Classes:** `CheckBitInTable`, `SkipUntilBitInTable`, `SkipUntilBitInTableUseSimd`, `CheckSpecialClassRanges`. Handle character sets like `\d`, `\w`, etc.
    * **Control Flow:** `Bind`, `GoTo`, `IfRegisterGE`, `IfRegisterLT`, `IfRegisterEqPos`, `Fail`, `Succeed`, `BindJumpTarget`. Basic control flow mechanisms for the generated code.
    * **Code Generation:** `GetCode`. The method that likely finalizes the generated machine code.
    * **Stack Management:** `ReadStackPointerFromRegister`, `WriteStackPointerToRegister`. Explicit stack pointer manipulation.
    * **Implementation Details:** `Implementation`. Returns the specific regexp implementation being used.
    * **Unchecked Character Loading:** `LoadCurrentCharacterUnchecked`. Potentially for optimization when bounds are already known.

8. **Static Method:**  `CheckStackGuardState` is a static method, suggesting it's a utility function that doesn't operate on a specific instance of the class. Its purpose, related to stack limits and relocation, points to runtime safety and memory management.

9. **Private Members:** The private section reveals internal implementation details:
    * **Constants:** Offsets within the stack frame (`kFramePointerOffset`, `kReturnAddressOffset`, etc.). These are crucial for accessing local variables and parameters within the generated assembly code.
    * **Helper Methods:** `PushCachedRegisters`, `PopCachedRegisters`, `CallCFunctionFromIrregexpCode`, `CheckPreemption`, `CheckStackLimit`, `CallCheckStackGuardState`, `CallIsCharacterInRangeArray`. These encapsulate common sequences of assembly instructions or interactions with the V8 runtime.
    * **Inline Helpers:** `StoreRegister`, `GetRegister`, `GetCachedRegister`, `Push`, `Pop`, `SaveLinkRegister`, `RestoreLinkRegister`, `BranchOrBacktrack`, `CompareAndBranchOrBacktrack`, `CallIf`. Performance-critical operations often implemented as inline functions.
    * **Register Definitions:**  `current_input_offset()`, `current_character()`, `input_end()`, etc. These symbolic names make the assembly code generation more readable and maintainable.
    * **Data Members:** `masm_`, `no_root_array_scope_`, `mode_`, `num_registers_`, `num_saved_registers_`. These represent the state of the assembler. `masm_` is the actual ARM64 assembler instance.
    * **Labels:** `entry_label_`, `start_label_`, `success_label_`, etc. These represent jump targets within the generated code.

10. **Considering `.tq` extension:** The prompt mentions the `.tq` extension, indicating Torque. Since this file is `.h`, it's *not* a Torque file. Torque is a higher-level language for generating code within V8. If this were a `.tq` file, it would contain a more abstract representation of the regexp matching logic, and the Torque compiler would then generate the C++ code (including something similar to this header).

11. **JavaScript Relationship (and Example):**  The entire purpose of this class is to optimize regular expression execution in JavaScript. Any JavaScript code that uses regular expressions will, under the hood, potentially use code generated by this assembler. The example needs to demonstrate a regular expression.

12. **Code Logic Reasoning (Hypothetical):** Choose a simple method like `AdvanceCurrentPosition`. Think about what happens when this is called with a specific value.

13. **Common Programming Errors:**  Relate these errors to the *use* of regular expressions in JavaScript, as this C++ code is an implementation detail. Think about common mistakes developers make with regex syntax or logic.

By following these steps, we can systematically dissect the header file and understand its various components and their roles in the V8 regular expression engine.
This C++ header file, `regexp-macro-assembler-arm64.h`, defines the `RegExpMacroAssemblerARM64` class, which is a crucial part of V8's regular expression engine for the ARM64 architecture. It's responsible for **generating low-level ARM64 machine code to efficiently execute regular expressions**.

Here's a breakdown of its functionality:

**Core Functionality: Generating ARM64 Assembly for RegExp Matching**

The primary purpose of this class is to provide an interface for a higher-level regular expression compiler to emit ARM64 assembly instructions. It offers methods that correspond to fundamental operations needed for regular expression matching. Think of it as a builder pattern for ARM64 assembly code specifically tailored for regexps.

**Key Features and Methods:**

* **Control Flow:**
    * `Bind(Label* label)`: Defines a target location in the generated code.
    * `GoTo(Label* label)`: Generates an unconditional jump to a label.
    * `Backtrack()`: Generates code to return to a previous state in the matching process (essential for backtracking in regexps).
    * `Fail()`: Generates code to indicate a failed match.
    * `Succeed()`: Generates code to indicate a successful match.
    * `IfRegisterGE`, `IfRegisterLT`, `IfRegisterEqPos`: Conditional jumps based on register values, allowing for branching logic.
    * `BindJumpTarget`:  Similar to `Bind`, potentially with some internal management.

* **Character Matching:**
    * `CheckCharacter(unsigned c, Label* on_equal)`: Checks if the current character matches a specific character and jumps to `on_equal` if it does.
    * `CheckCharacterAfterAnd`, `CheckCharacterGT`, `CheckCharacterLT`, `CheckCharacters`:  More complex character matching conditions.
    * `CheckNotCharacter`, `CheckNotCharacterAfterAnd`, `CheckNotCharacterAfterMinusAnd`: Checks for characters that *don't* match.
    * `CheckCharacterInRange`, `CheckCharacterNotInRange`, `CheckCharacterInRangeArray`, `CheckCharacterNotInRangeArray`: Checks if the current character is within or outside a specified range or set of ranges.
    * `CheckBitInTable`, `SkipUntilBitInTable`, `SkipUntilBitInTableUseSimd`: Optimizations for character class matching using lookup tables.
    * `CheckSpecialClassRanges`: Handles matching against predefined character classes like `\d`, `\w`, etc.

* **Position Tracking and Manipulation:**
    * `AdvanceCurrentPosition(int by)`: Moves the current position in the input string forward.
    * `SetCurrentPositionFromEnd(int by)`: Sets the current position relative to the end of the input.
    * `ReadCurrentPositionFromRegister`, `WriteCurrentPositionToRegister`:  Reads and writes the current position to/from a register.
    * `CheckAtStart`, `CheckNotAtStart`, `CheckPosition`: Checks if the current position is at the beginning, not at the beginning, or within the bounds of the input string.

* **Register Management:**
    * `AdvanceRegister(int reg, int by)`: Increments a register value.
    * `SetRegister(int register_index, int to)`: Sets the value of a register.
    * `ClearRegisters(int reg_from, int reg_to)`: Clears a range of registers.
    * `PushRegister`, `PopRegister`:  Pushes and pops register values onto/from the stack.

* **Backtracking Stack Management:**
    * `PushBacktrack(Label* label)`: Pushes a backtrack state (represented by a label) onto the stack.
    * `PushCurrentPosition()`, `PopCurrentPosition()`:  Manages the current position on the backtrack stack.

* **Backreferences:**
    * `CheckNotBackReference`, `CheckNotBackReferenceIgnoreCase`: Checks if a captured group matches the current position (case-sensitive and case-insensitive).

* **Greedy Loop Optimization:**
    * `CheckGreedyLoop`:  Optimizes matching for simple greedy loops.

* **Code Generation and Execution:**
    * `GetCode(Handle<String> source, RegExpFlags flags)`:  Finalizes the generated assembly code and returns a compiled code object.
    * `Implementation()`: Returns the specific regexp implementation being used.

* **Stack Overflow Handling:**
    * `CheckStackGuardState`: A static method used for checking if the stack limit has been reached during execution, preventing stack overflow errors.

**Regarding the `.tq` extension:**

The header file `v8/src/regexp/arm64/regexp-macro-assembler-arm64.h` **does not** end with `.tq`. Therefore, it is **not** a V8 Torque source code file. It's a standard C++ header file.

Torque (`.tq`) is a higher-level language used within V8 to generate C++ code. If a file with a similar name ended in `.tq`, it would contain a more abstract description of the regular expression matching logic, and the Torque compiler would generate the corresponding C++ code (which might include a header file like this one).

**Relationship with JavaScript and Examples:**

This C++ code is fundamental to how JavaScript's regular expressions are executed efficiently on ARM64 architectures. When you use regular expressions in JavaScript, V8's compiler might generate machine code using the facilities provided by this class.

**JavaScript Example:**

```javascript
const text = "This is a test string with numbers like 123 and 456.";
const regex = /\d+/g; // Matches one or more digits globally

let match;
while ((match = regex.exec(text)) !== null) {
  console.log(`Found ${match[0]} at index ${match.index}.`);
}
```

**How this relates to the C++ header:**

When the V8 engine executes this JavaScript code, the regular expression `/\d+/g` is compiled. The `RegExpMacroAssemblerARM64` (or a similar class for other architectures) would be used to generate ARM64 machine code for the following kinds of operations (examples linked to the header file methods):

* **`CheckSpecialClassRanges(StandardCharacterSet::k цифра, ...)`:** To check if a character is a digit (`\d`).
* **`AdvanceCurrentPosition(1)`:** To move to the next character in the string.
* **`PushBacktrack(...)` and `Backtrack()`:**  To handle the "one or more" (`+`) quantifier, allowing the engine to backtrack if a longer sequence of digits fails to match later.
* **`SetRegister(...)`:** To store the captured groups (though this simple example has no explicit capturing groups).

**Code Logic Reasoning (Hypothetical Example):**

Let's consider the `CheckCharacter(unsigned c, Label* on_equal)` method.

**Hypothetical Input:**

* `c`: The character 'a' (ASCII value 97).
* `on_equal`: A label representing the code to jump to if the current character matches 'a'.
* The current position in the input string points to the character 'a'.

**Output (Generated ARM64 Assembly - Simplified):**

```assembly
    // Load the current character into a register (e.g., w22)
    ldrsw w22, [x26, w21, sxtw #2]  // Assuming input_start is x26, current_input_offset is w21

    // Compare the current character with 'a'
    cmp w22, #97

    // Conditional branch if equal
    beq <on_equal_label>
```

**Explanation:**

The generated code would load the character at the current position into a register, compare it with the ASCII value of 'a', and then conditionally branch to the `on_equal` label if they are equal.

**User-Visible Programming Errors:**

While this C++ code is an internal implementation detail, issues in the regular expression engine can manifest as unexpected behavior or performance problems in JavaScript. Here are some common programming errors users make with regular expressions that might be related to the underlying logic handled by this class:

1. **Incorrect Regular Expression Syntax:**
   ```javascript
   const text = "test";
   const regex = /[a-z/; // Missing closing bracket
   text.match(regex); // This will likely throw an error.
   ```
   The parsing and interpretation of the regular expression pattern happen before the code generation, but errors in the pattern will prevent the `RegExpMacroAssemblerARM64` from being used correctly.

2. **Catastrophic Backtracking:**
   ```javascript
   const text = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa";
   const regex = /(a+)+b/; // Nested quantifiers can lead to exponential backtracking
   text.match(regex); // This can take a very long time and potentially freeze the browser.
   ```
   The `PushBacktrack` and `Backtrack` mechanisms are crucial for handling quantifiers. Poorly constructed regexes with nested quantifiers can cause the backtracking algorithm to explore an enormous number of possibilities, leading to performance issues.

3. **Incorrect Use of Anchors:**
   ```javascript
   const text = "line1\nline2";
   const regex = /^line2$/; // Expecting to match "line2" on its own line
   text.match(regex); // Returns null because ^ and $ match the start/end of the *entire* string by default.
   ```
   The `CheckAtStart` and related methods ensure that anchors like `^` and `$` work correctly. Misunderstanding their behavior can lead to unexpected results.

4. **Overuse of Complex Regular Expressions:** While regular expressions are powerful, overly complex ones can be inefficient. The generated code from this assembler might become large and slow if the regex is extremely intricate. Sometimes, simpler string manipulation techniques might be more efficient.

In summary, `regexp-macro-assembler-arm64.h` is a vital component for efficient regular expression execution in V8 on ARM64. It provides the building blocks for generating low-level machine code that performs the complex pattern matching operations required by JavaScript regular expressions. While developers don't directly interact with this C++ code, its functionality directly impacts the performance and behavior of JavaScript regexes.

Prompt: 
```
这是目录为v8/src/regexp/arm64/regexp-macro-assembler-arm64.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/arm64/regexp-macro-assembler-arm64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_REGEXP_ARM64_REGEXP_MACRO_ASSEMBLER_ARM64_H_
#define V8_REGEXP_ARM64_REGEXP_MACRO_ASSEMBLER_ARM64_H_

#include "src/base/strings.h"
#include "src/codegen/arm64/assembler-arm64.h"
#include "src/codegen/macro-assembler.h"
#include "src/regexp/regexp-macro-assembler.h"

namespace v8 {
namespace internal {

class V8_EXPORT_PRIVATE RegExpMacroAssemblerARM64
    : public NativeRegExpMacroAssembler {
 public:
  RegExpMacroAssemblerARM64(Isolate* isolate, Zone* zone, Mode mode,
                            int registers_to_save);
  ~RegExpMacroAssemblerARM64() override;
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
  void CheckCharacters(base::Vector<const base::uc16> str, int cp_offset,
                       Label* on_failure, bool check_end_of_string);
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
  bool SkipUntilBitInTableUseSimd(int advance_by) override;

  // Checks whether the given offset from the current position is before
  // the end of the string.
  void CheckPosition(int cp_offset, Label* on_outside_input) override;
  bool CheckSpecialClassRanges(StandardCharacterSet type,
                               Label* on_no_match) override;
  void BindJumpTarget(Label* label = nullptr) override;
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
                                  Address re_frame, int start_offset,
                                  const uint8_t** input_start,
                                  const uint8_t** input_end,
                                  uintptr_t extra_space);

 private:
  static constexpr int kFramePointerOffset = 0;

  // Above the frame pointer - Stored registers and stack passed parameters.
  static constexpr int kReturnAddressOffset =
      kFramePointerOffset + kSystemPointerSize;
  // Callee-saved registers (x19-x28).
  static constexpr int kNumCalleeSavedRegisters = 10;
  static constexpr int kCalleeSavedRegistersOffset =
      kReturnAddressOffset + kSystemPointerSize;

  // Below the frame pointer - the stack frame type marker and locals.
  static constexpr int kFrameTypeOffset =
      kFramePointerOffset - kSystemPointerSize;
  static_assert(kFrameTypeOffset ==
                CommonFrameConstants::kContextOrFrameTypeOffset);
  static constexpr int kPaddingAfterFrameType = kSystemPointerSize;
  // Register parameters stored by setup code.
  static constexpr int kIsolateOffset =
      kFrameTypeOffset - kPaddingAfterFrameType - kSystemPointerSize;
  static constexpr int kDirectCallOffset = kIsolateOffset - kSystemPointerSize;
  // For the case of global regular expression, we have room to store at least
  // one set of capture results.  For the case of non-global regexp, we ignore
  // this value.
  static constexpr int kNumOutputRegistersOffset =
      kDirectCallOffset - kSystemPointerSize;
  static constexpr int kInputStringOffset =
      kNumOutputRegistersOffset - kSystemPointerSize;
  // When adding local variables remember to push space for them in
  // the frame in GetCode.
  static constexpr int kSuccessfulCapturesOffset =
      kInputStringOffset - kSystemPointerSize;
  static constexpr int kBacktrackCountOffset =
      kSuccessfulCapturesOffset - kSystemPointerSize;
  // Stores the initial value of the regexp stack pointer in a
  // position-independent representation (in case the regexp stack grows and
  // thus moves).
  static constexpr int kRegExpStackBasePointerOffset =
      kBacktrackCountOffset - kSystemPointerSize;
  // A padding slot to preserve alignment.
  static constexpr int kStackLocalPadding =
      kRegExpStackBasePointerOffset - kSystemPointerSize;
  static constexpr int kNumberOfStackLocals = 4;

  // First position register address on the stack. Following positions are
  // below it. A position is a 32 bit value.
  static constexpr int kFirstRegisterOnStackOffset =
      kStackLocalPadding - kWRegSize;
  // A capture is a 64 bit value holding two position.
  static constexpr int kFirstCaptureOnStackOffset =
      kStackLocalPadding - kXRegSize;

  static constexpr int kInitialBufferSize = 1024;

  // Registers x0 to x7 are used to store the first captures, they need to be
  // retained over calls to C++ code.
  void PushCachedRegisters();
  void PopCachedRegisters();

  // When initializing registers to a non-position value we can unroll
  // the loop. Set the limit of registers to unroll.
  static constexpr int kNumRegistersToUnroll = 16;

  // We are using x0 to x7 as a register cache. Each hardware register must
  // contain one capture, that is two 32 bit registers. We can cache at most
  // 16 registers.
  static constexpr int kNumCachedRegisters = 16;

  void CallCFunctionFromIrregexpCode(ExternalReference function,
                                     int num_arguments);

  // Check whether preemption has been requested.
  void CheckPreemption();

  // Check whether we are exceeding the stack limit on the backtrack stack.
  void CheckStackLimit();

  void CallCheckStackGuardState(Register scratch,
                                Operand extra_space = Operand(0));
  void CallIsCharacterInRangeArray(const ZoneList<CharacterRange>* ranges);

  // Location of a 32 bit position register.
  MemOperand register_location(int register_index);

  // Location of a 64 bit capture, combining two position registers.
  MemOperand capture_location(int register_index, Register scratch);

  // Register holding the current input position as negative offset from
  // the end of the string.
  static constexpr Register current_input_offset() { return w21; }

  // The register containing the current character after LoadCurrentCharacter.
  static constexpr Register current_character() { return w22; }

  // Register holding address of the end of the input string.
  static constexpr Register input_end() { return x25; }

  // Register holding address of the start of the input string.
  static constexpr Register input_start() { return x26; }

  // Register holding the offset from the start of the string where we should
  // start matching.
  static constexpr Register start_offset() { return w27; }

  // Pointer to the output array's first element.
  static constexpr Register output_array() { return x28; }

  // Register holding the frame address. Local variables, parameters and
  // regexp registers are addressed relative to this.
  static constexpr Register frame_pointer() { return fp; }

  // The register containing the backtrack stack top. Provides a meaningful
  // name to the register.
  static constexpr Register backtrack_stackpointer() { return x23; }

  // Register holding pointer to the current code object.
  static constexpr Register code_pointer() { return x20; }

  // Register holding the value used for clearing capture registers.
  static constexpr Register string_start_minus_one() { return w24; }
  // The top 32 bit of this register is used to store this value
  // twice. This is used for clearing more than one register at a time.
  static constexpr Register twice_non_position_value() { return x24; }

  // Byte size of chars in the string to match (decided by the Mode argument)
  int char_size() const { return static_cast<int>(mode_); }

  // Equivalent to a conditional branch to the label, unless the label
  // is nullptr, in which case it is a conditional Backtrack.
  void BranchOrBacktrack(Condition condition, Label* to);

  // Compares reg against immediate before calling BranchOrBacktrack.
  // It makes use of the Cbz and Cbnz instructions.
  void CompareAndBranchOrBacktrack(Register reg,
                                   int immediate,
                                   Condition condition,
                                   Label* to);

  inline void CallIf(Label* to, Condition condition);

  // Save and restore the link register on the stack in a way that
  // is GC-safe.
  inline void SaveLinkRegister();
  inline void RestoreLinkRegister();

  // Pushes the value of a register on the backtrack stack. Decrements the
  // stack pointer by a word size and stores the register's value there.
  inline void Push(Register source);

  // Pops a value from the backtrack stack. Reads the word at the stack pointer
  // and increments it by a word size.
  inline void Pop(Register target);

  // This state indicates where the register actually is.
  enum RegisterState {
    STACKED,     // Resides in memory.
    CACHED_LSW,  // Least Significant Word of a 64 bit hardware register.
    CACHED_MSW   // Most Significant Word of a 64 bit hardware register.
  };

  RegisterState GetRegisterState(int register_index) {
    DCHECK_LE(0, register_index);
    if (register_index >= kNumCachedRegisters) {
      return STACKED;
    } else {
      if ((register_index % 2) == 0) {
        return CACHED_LSW;
      } else {
        return CACHED_MSW;
      }
    }
  }

  // Store helper that takes the state of the register into account.
  inline void StoreRegister(int register_index, Register source);

  // Returns a hardware W register that holds the value of the capture
  // register.
  //
  // This function will try to use an existing cache register (w0-w7) for the
  // result. Otherwise, it will load the value into maybe_result.
  //
  // If the returned register is anything other than maybe_result, calling code
  // must not write to it.
  inline Register GetRegister(int register_index, Register maybe_result);

  // Returns the harware register (x0-x7) holding the value of the capture
  // register.
  // This assumes that the state of the register is not STACKED.
  inline Register GetCachedRegister(int register_index);

  void LoadRegExpStackPointerFromMemory(Register dst);
  void StoreRegExpStackPointerToMemory(Register src, Register scratch);
  void PushRegExpBasePointer(Register stack_pointer, Register scratch);
  void PopRegExpBasePointer(Register stack_pointer_out, Register scratch);

  Isolate* isolate() const { return masm_->isolate(); }

  const std::unique_ptr<MacroAssembler> masm_;
  const NoRootArrayScope no_root_array_scope_;

  // Which mode to generate code for (LATIN1 or UC16).
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

#endif  // V8_REGEXP_ARM64_REGEXP_MACRO_ASSEMBLER_ARM64_H_

"""

```