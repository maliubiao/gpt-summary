Response:
Let's break down the thought process for analyzing this C++ header file.

**1. Initial Understanding: What is this?**

The filename `regexp-macro-assembler-loong64.h` immediately suggests this is related to regular expressions (`regexp`) and assembly language generation (`macro-assembler`) specifically for the LoongArch 64-bit architecture (`loong64`). The `.h` extension indicates it's a header file, likely defining a class interface.

**2. Core Class Identification:**

The `class V8_EXPORT_PRIVATE RegExpMacroAssemblerLOONG64` is the central element. The inheritance from `NativeRegExpMacroAssembler` confirms its role in regular expression assembly. The `V8_EXPORT_PRIVATE` suggests it's part of V8's internal implementation.

**3. Purpose of the Class:**

The class name and inheritance clearly point to its function:  to provide a low-level interface for generating machine code for regular expression matching on the LoongArch64 architecture. This involves translating higher-level regexp operations into specific assembly instructions.

**4. Examining Public Methods - Functionality Extraction:**

The public methods provide the clearest picture of the class's capabilities. I'll go through them systematically, grouping related functions:

* **Construction/Destruction:** `RegExpMacroAssemblerLOONG64`, `~RegExpMacroAssemblerLOONG64`. Standard stuff for object lifecycle.
* **Basic Control Flow:** `Bind`, `GoTo`, `Backtrack`, `Fail`, `Succeed`. These directly relate to the control flow of the regexp matching engine. `Bind` defines labels, `GoTo` jumps, `Backtrack` signifies a failed match attempt, `Fail` and `Succeed` are terminal states.
* **Position Manipulation:** `AdvanceCurrentPosition`, `SetCurrentPositionFromEnd`, `ReadCurrentPositionFromRegister`, `WriteCurrentPositionToRegister`, `PushCurrentPosition`, `PopCurrentPosition`. These methods manage the current position within the input string.
* **Register Manipulation:** `AdvanceRegister`, `SetRegister`, `PushRegister`, `PopRegister`, `ClearRegisters`. These deal with storing and retrieving intermediate results and captured groups.
* **Character Checks:** This is a big group, fundamental to regexp matching. Look for patterns: `CheckCharacter`, `CheckCharacterAfterAnd`, `CheckCharacterGT`, `CheckCharacterLT`, `CheckNotCharacter`, `CheckNotCharacterAfterAnd`, `CheckNotCharacterAfterMinusAnd`, `CheckCharacterInRange`, `CheckCharacterNotInRange`, `CheckCharacterInRangeArray`, `CheckCharacterNotInRangeArray`, `CheckBitInTable`, `SkipUntilBitInTable`. They all revolve around verifying the current character against specific conditions.
* **Anchors:** `CheckAtStart`, `CheckNotAtStart`. Handling the `^` and `$` anchors.
* **Backreferences:** `CheckNotBackReference`, `CheckNotBackReferenceIgnoreCase`. Supporting the `\1`, `\2`, etc. syntax.
* **Greedy Loops:** `CheckGreedyLoop`. Optimized handling of common loop structures.
* **Position Checks:** `CheckPosition`. Verifying the current position against the string boundaries.
* **Character Classes:** `CheckSpecialClassRanges`. Handling predefined character classes like `\d`, `\w`, `\s`.
* **Code Generation:** `GetCode`. The crucial method for finalizing the generated assembly code.
* **Conditional Logic:** `IfRegisterGE`, `IfRegisterLT`, `IfRegisterEqPos`. Implementing conditional branching based on register values.
* **Implementation Details:** `Implementation`. Returns the specific implementation type.
* **Unchecked Character Load:** `LoadCurrentCharacterUnchecked`. Potentially for performance-critical sections where bounds checking is assumed.
* **Stack Management:** `ReadStackPointerFromRegister`, `WriteStackPointerToRegister`. Dealing with the backtrack stack.
* **Stack Guard:** `CheckStackGuardState`. Preventing stack overflows during complex regex matching.
* **Internal Utility:** `print_regexp_frame_constants`. Likely for debugging.

**5. Examining Private Members:**

The private members reveal internal implementation details:

* **Constants:**  `kFramePointerOffset`, `kStoredRegistersOffset`, etc. These define the layout of the stack frame used by the generated code.
* **Helper Functions:** `PushCallerSavedRegisters`, `PopCallerSavedRegisters`, `CallCFunctionFromIrregexpCode`, `CheckPreemption`, `CheckStackLimit`, `CallCheckStackGuardState`, `CallIsCharacterInRangeArray`. These are internal utility functions for code generation and runtime checks.
* **Register Definitions:** `current_input_offset`, `current_character`, `end_of_input_address`, `frame_pointer`, `backtrack_stackpointer`, `code_pointer`. These define the registers used for specific purposes.
* **Mode:** `mode_`. Indicates whether the regex operates on Latin-1 or UTF-16 strings.
* **Other Data:** `num_registers_`, `num_saved_registers_`. Tracking register usage.
* **Labels:** `entry_label_`, `start_label_`, etc. Labels used for control flow within the generated code.
* **Internal Objects:** `masm_`, `no_root_array_scope_`. `masm_` is the underlying macro assembler.

**6. Connecting to JavaScript (Conceptual):**

While this is low-level C++, it directly supports JavaScript's regular expression functionality. When you execute a JavaScript regex, V8 needs to compile it into machine code. This class is a key component in that compilation process for LoongArch64.

**7. Torque Consideration:**

The prompt asks about `.tq` files. The provided file *doesn't* end in `.tq`. Therefore, it's not a Torque file. If it *were*, it would indicate a higher-level, more type-safe way of generating the low-level C++ code.

**8. Code Logic Inference and Examples:**

For the more complex methods (especially the `Check...` methods), I started thinking about how they would be used in practice. For example, `CheckCharacter(uint32_t c, Label* on_equal)` is clearly used to check if the current character matches a specific character. This led to the JavaScript example: `/a/.test('abc')`.

Similarly, `CheckCharacterInRange` maps to character ranges in regexes like `[a-z]`.

**9. Common Programming Errors:**

The potential errors are related to the *complexity* of regular expressions themselves. Stack overflows from deeply nested or repeated patterns are a common issue that this class helps manage (through `CheckStackGuardState`). Incorrect backreferences are another source of errors.

**10. Review and Refinement:**

After the initial analysis, I reviewed the information, trying to organize it logically and ensure accuracy. I focused on explaining *what* each part does and *why* it's there in the context of regular expression compilation.

This iterative process of understanding the file's name, identifying the core class, analyzing its members, connecting it to JavaScript, and considering potential issues is how I arrived at the comprehensive explanation.
好的，让我们来分析一下 V8 源代码文件 `v8/src/regexp/loong64/regexp-macro-assembler-loong64.h` 的功能。

**功能概述**

`RegExpMacroAssemblerLOONG64` 类是 V8 引擎中用于为 LoongArch 64 位架构生成正则表达式匹配机器码的关键组件。它继承自 `NativeRegExpMacroAssembler`，提供了一组用于构建正则表达式匹配引擎所需底层操作的接口。

**核心功能点**

1. **机器码生成抽象层:**  `RegExpMacroAssemblerLOONG64` 提供了一种抽象的方式来生成特定于 LoongArch64 架构的机器码，而无需直接编写汇编代码。这使得正则表达式的实现更加可移植和易于维护。

2. **正则表达式操作指令:** 该类定义了许多方法，对应于正则表达式匹配过程中的各种基本操作，例如：
   * **位置管理:**  `AdvanceCurrentPosition`, `SetCurrentPositionFromEnd`, `ReadCurrentPositionFromRegister`, `WriteCurrentPositionToRegister`, `PushCurrentPosition`, `PopCurrentPosition` 用于操作和跟踪当前匹配在输入字符串中的位置。
   * **寄存器操作:** `AdvanceRegister`, `SetRegister`, `PushRegister`, `PopRegister`, `ClearRegisters` 用于管理和操作用于存储匹配状态和捕获组的寄存器。
   * **字符检查:**  `CheckCharacter`, `CheckCharacterAfterAnd`, `CheckCharacterGT`, `CheckCharacterLT`, `CheckNotCharacter`, `CheckNotCharacterAfterAnd`, `CheckCharacterInRange`, `CheckCharacterNotInRange`, `CheckBitInTable`, `SkipUntilBitInTable` 等方法用于检查当前字符是否满足特定条件。
   * **控制流:** `Bind`, `GoTo`, `Backtrack`, `Fail`, `Succeed` 用于控制匹配过程中的跳转、回溯和成功/失败状态。
   * **锚点:** `CheckAtStart`, `CheckNotAtStart` 用于检查是否位于字符串的开头或结尾。
   * **反向引用:** `CheckNotBackReference`, `CheckNotBackReferenceIgnoreCase` 用于处理正则表达式中的反向引用。
   * **循环:** `CheckGreedyLoop` 用于优化贪婪循环的匹配。
   * **特殊字符类:** `CheckSpecialClassRanges` 用于处理诸如 `\d`, `\w`, `\s` 等特殊字符类。
   * **堆栈管理:**  `PushBacktrack`, `PopCurrentPosition` 等用于管理回溯堆栈。

3. **架构特定性:**  类名中的 "LOONG64" 明确指出这是针对 LoongArch 64 位架构的实现。这意味着其内部实现会使用 LoongArch64 的指令集和寄存器约定。

4. **与 `NativeRegExpMacroAssembler` 的关系:**  继承自 `NativeRegExpMacroAssembler` 表明它遵循 V8 中正则表达式宏汇编器的通用接口。这允许 V8 的正则表达式引擎在不同的架构上使用不同的 `RegExpMacroAssembler` 实现。

5. **堆栈溢出保护:**  `CheckStackGuardState` 方法用于检测是否即将发生堆栈溢出，这在处理复杂的正则表达式时非常重要。

**关于文件后缀和 Torque**

你提到如果文件以 `.tq` 结尾，那么它将是 V8 Torque 源代码。这是正确的。Torque 是一种由 V8 开发的领域特定语言，用于生成 C++ 代码，特别是用于实现 V8 的内置函数和运行时代码。`v8/src/regexp/loong64/regexp-macro-assembler-loong64.h` 以 `.h` 结尾，因此它是一个 **C++ 头文件**，定义了 `RegExpMacroAssemblerLOONG64` 类的接口。其对应的实现文件通常是 `.cc` 文件。

**与 JavaScript 功能的关系及示例**

`RegExpMacroAssemblerLOONG64` 最终支持了 JavaScript 中 `RegExp` 对象的功能。当你创建一个正则表达式并在 JavaScript 中使用它进行匹配时，V8 引擎会将其编译成机器码，而 `RegExpMacroAssemblerLOONG64` 就是在 LoongArch64 架构上生成这些机器码的关键部分。

**JavaScript 示例：**

```javascript
const regex = /ab+c/g;
const str = 'abbc abc abbbbc';
let array;

while ((array = regex.exec(str)) !== null) {
  console.log(`发现匹配 ${array[0]}，位置在 ${array.index}。`);
}
```

在这个例子中，当 V8 执行 `regex.exec(str)` 时，它会使用内部的正则表达式引擎。在 LoongArch64 架构上，这个引擎会利用 `RegExpMacroAssemblerLOONG64` 生成的机器码来执行匹配操作。`RegExpMacroAssemblerLOONG64` 中定义的各种 `Check...` 方法对应了正则表达式中模式的匹配逻辑，例如：

* `/a/`:  可能会用到 `CheckCharacter` 来检查当前字符是否是 'a'。
* `/b+/`:  可能会用到循环结构，并可能涉及对字符 'b' 的多次 `CheckCharacter`。
* `/c/`:  可能会用到 `CheckCharacter` 来检查当前字符是否是 'c'。
* `/^...$/`: 可能会用到 `CheckAtStart` 和相关的结尾检查。

**代码逻辑推理及假设输入输出**

让我们以 `CheckCharacter(uint32_t c, Label* on_equal)` 方法为例进行简单的逻辑推理。

**假设输入：**

* `c`: 字符的 Unicode 值，例如，如果我们要检查字符 'a'，那么 `c` 的值可能是 97。
* `on_equal`: 一个标签（Label）的指针，表示如果当前输入的字符与 `c` 相等，则跳转到这个标签的位置继续执行。

**隐含输入：**

* 当前输入字符串的当前位置。
* 当前位置的字符。

**代码逻辑推理：**

`CheckCharacter` 方法的内部实现会生成 LoongArch64 汇编指令，用于：

1. **加载当前输入位置的字符。** 这可能涉及到从内存中读取字符。
2. **将加载的字符与 `c` 的值进行比较。**
3. **如果相等，则生成一个条件跳转指令，跳转到 `on_equal` 指向的代码位置。**
4. **如果不相等，则继续执行当前指令的下一条指令，这通常意味着匹配失败，可能会导致回溯。**

**假设情景与输出：**

假设我们正在匹配正则表达式 `/a/`，并且当前输入字符串是 "abc"，当前匹配位置在索引 0。

1. 调用 `CheckCharacter(97, &label_match_a)`，其中 97 是 'a' 的 Unicode 值。
2. 方法内部生成的汇编代码会加载字符串 "abc" 索引 0 的字符，即 'a'，其 Unicode 值为 97。
3. 比较 97 和 97，结果相等。
4. 生成跳转指令，程序执行流程跳转到 `label_match_a` 标记的代码位置。

如果当前匹配位置在索引 1，字符是 'b'：

1. 调用 `CheckCharacter(97, &label_match_a)`。
2. 方法内部生成的汇编代码会加载字符串 "abc" 索引 1 的字符，即 'b'，其 Unicode 值不是 97。
3. 比较 97 和 'b' 的 Unicode 值，结果不相等。
4. 不执行跳转，程序继续执行 `CheckCharacter` 之后的代码，这通常会导致回溯或者尝试其他匹配路径。

**用户常见的编程错误**

`RegExpMacroAssemblerLOONG64` 作为一个底层的代码生成器，其本身并不直接涉及用户的编程错误。然而，它支持的正则表达式功能非常强大，用户在使用 JavaScript 正则表达式时可能会犯以下错误，这些错误最终会通过 `RegExpMacroAssemblerLOONG64` 生成的机器码来体现：

1. **回溯陷阱 (Catastrophic Backtracking):**  编写的正则表达式在某些输入下可能导致指数级别的回溯，消耗大量时间和资源，甚至导致程序卡死。

   **示例：** `/a*b*c$/.test('aaaaaaaaaaaaaaaaaaaaac')`

   这个正则表达式在匹配失败时会进行大量的回溯尝试。

2. **不正确的量词使用：**  对量词（如 `*`, `+`, `?`, `{}`) 的理解不当，导致匹配结果与预期不符。

   **示例：**  期望匹配 "abc" 或 "abbc"，但使用了 `/ab*c/`，这也会匹配 "ac"。

3. **忘记转义特殊字符：** 在正则表达式中，某些字符具有特殊含义，需要进行转义才能按字面意义匹配。

   **示例：**  期望匹配字符串 "a.b"，但错误地使用了 `/a.b/`，`.` 会匹配任意字符。应该使用 `/a\.b/`。

4. **对捕获组的误用：**  不理解捕获组的工作方式，或者错误地使用了捕获组的索引。

   **示例：**  期望替换字符串中的某个部分，但捕获组的索引使用错误。

5. **边界条件处理不当：**  忽略了字符串的开头和结尾，或者在处理多行字符串时出现错误。

   **示例：**  使用 `/^.../` 期望匹配整个字符串，但忘记了 `$` 来匹配结尾。

了解 `RegExpMacroAssemblerLOONG64` 的功能可以帮助我们理解 V8 引擎是如何高效地执行正则表达式的，并且在遇到性能问题时，可以更好地分析和优化正则表达式。

Prompt: 
```
这是目录为v8/src/regexp/loong64/regexp-macro-assembler-loong64.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/loong64/regexp-macro-assembler-loong64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_REGEXP_LOONG64_REGEXP_MACRO_ASSEMBLER_LOONG64_H_
#define V8_REGEXP_LOONG64_REGEXP_MACRO_ASSEMBLER_LOONG64_H_

#include "src/codegen/macro-assembler.h"
#include "src/regexp/regexp-macro-assembler.h"

namespace v8 {
namespace internal {

class V8_EXPORT_PRIVATE RegExpMacroAssemblerLOONG64
    : public NativeRegExpMacroAssembler {
 public:
  RegExpMacroAssemblerLOONG64(Isolate* isolate, Zone* zone, Mode mode,
                              int registers_to_save);
  ~RegExpMacroAssemblerLOONG64() override;
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
  inline int char_size() { return static_cast<int>(mode_); }

  // Equivalent to a conditional branch to the label, unless the label
  // is nullptr, in which case it is a conditional Backtrack.
  void BranchOrBacktrack(Label* to, Condition condition, Register rs,
                         const Operand& rt);

  // Call and return internally in the generated code in a way that
  // is GC-safe (i.e., doesn't leave absolute code addresses on the stack)
  inline void SafeCall(Label* to, Condition cond, Register rs,
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

#endif  // V8_REGEXP_LOONG64_REGEXP_MACRO_ASSEMBLER_LOONG64_H_

"""

```