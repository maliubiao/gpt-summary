Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The user wants to understand the functionality of the provided C++ header file (`regexp-macro-assembler-riscv.h`). They also have specific sub-questions about Torque, JavaScript relation, code logic, and common programming errors.

2. **Initial Analysis of the Header File:**
    * **Filename and Path:** `v8/src/regexp/riscv/regexp-macro-assembler-riscv.h` strongly suggests this file is part of V8's regular expression engine and is specific to the RISC-V architecture.
    * **Copyright and License:**  Standard V8 copyright and BSD license information.
    * **Include Headers:** The included headers (`strings.h`, `assembler-arch.h`, `macro-assembler.h`, `regexp-macro-assembler.h`) provide clues about its purpose. It likely deals with low-level assembly code generation for regular expression matching. The `regexp-macro-assembler.h` suggests this is an architecture-specific implementation of a more general regular expression assembler.
    * **Namespace:** `v8::internal` indicates this is an internal V8 component.
    * **Class Declaration:** The core of the file is the `RegExpMacroAssemblerRISCV` class, inheriting from `NativeRegExpMacroAssembler`. This confirms it's a concrete implementation for RISC-V.
    * **Constructor and Destructor:**  Basic lifecycle management. The constructor takes an `Isolate`, `Zone`, `Mode`, and `registers_to_save`, which are common V8 concepts. `Mode` likely refers to Latin1/UTF-16 encoding.
    * **Public Methods (the bulk of the functionality):**  These methods provide a high-level interface for generating RISC-V assembly code for various regular expression operations. I'd group them mentally by their apparent function:
        * **Control Flow:** `Bind`, `GoTo`, `Backtrack`, `Fail`, `Succeed`.
        * **Position Management:** `AdvanceCurrentPosition`, `AdvanceRegister`, `CheckAtStart`, `CheckNotAtStart`, `SetCurrentPositionFromEnd`, `ReadCurrentPositionFromRegister`, `WriteCurrentPositionToRegister`, `PushCurrentPosition`, `PopCurrentPosition`.
        * **Character Matching:** `CheckCharacter`, `CheckCharacterAfterAnd`, `CheckCharacterGT`, `CheckCharacterLT`, `CheckNotCharacter`, `CheckNotCharacterAfterAnd`, `CheckNotCharacterAfterMinusAnd`, `CheckCharacterInRange`, `CheckCharacterNotInRange`, `CheckCharacterInRangeArray`, `CheckCharacterNotInRangeArray`, `CheckBitInTable`, `SkipUntilBitInTable`, `CheckSpecialClassRanges`.
        * **Backreferences:** `CheckNotBackReference`, `CheckNotBackReferenceIgnoreCase`.
        * **Register Manipulation:** `SetRegister`, `PopRegister`, `PushRegister`, `ClearRegisters`.
        * **Stack Manipulation:** `PushBacktrack`, `ReadStackPointerFromRegister`, `WriteStackPointerToRegister`.
        * **Looping:** `CheckGreedyLoop`.
        * **Comparison:** `IfRegisterGE`, `IfRegisterLT`, `IfRegisterEqPos`.
        * **Code Generation and Information:** `GetCode`, `Implementation`.
        * **Stack Guard:** `CheckStackGuardState`.
        * **Unaligned Access:** `CanReadUnaligned`.
    * **Private Members:** These are implementation details: constants (offsets), helper functions (`CallCFunctionFromIrregexpCode`, `PushCallerSavedRegisters`, etc.), registers used for specific purposes, and labels.

3. **Address the Specific Questions:**

    * **Functionality Listing:** Based on the public methods, I would categorize the functionality as:  *Regular Expression Matching*, *RISC-V Assembly Code Generation*, *Backtracking Management*, *Register Management*, *String Position Management*, *Character Class Checks*, and *Stack Management*.

    * **.tq Suffix and Torque:** I know that `.tq` files in V8 are related to Torque, V8's type-safe TypeScript-like language for generating C++. Since the filename ends in `.h`, it's a C++ header, *not* a Torque file.

    * **Relationship to JavaScript and Examples:** The file is crucial for implementing JavaScript's regular expressions on RISC-V. I would provide a simple JavaScript regex example and explain how the methods in this C++ file would be used under the hood to execute that regex on RISC-V. Focus on the connection between the *actions* in the regex (matching characters, repeating, anchoring) and the *methods* in the header.

    * **Code Logic Reasoning (Hypothetical Input/Output):**  Choose a simple method like `CheckCharacter` and illustrate how it works. Define a hypothetical input (a character and a label) and explain that if the current character matches, the code will branch to the provided label; otherwise, it will continue to the next instruction (implicitly, or backtrack).

    * **Common Programming Errors:** Think about how someone using *this* API (if it were directly exposed, though it's internal) or implementing regex engines in general might make mistakes. Examples include: incorrect register usage, stack overflow due to unbounded recursion (related to backtracking), and off-by-one errors in position tracking.

4. **Structure and Refine the Answer:** Organize the information logically with clear headings. Use bullet points for lists of functionalities. Ensure the JavaScript examples are concise and easy to understand. For the code logic, keep the hypothetical scenario simple. For common errors, provide concrete, relatable examples.

5. **Review and Iterate:** Read through the generated answer to make sure it's accurate, clear, and addresses all parts of the original request. Check for any ambiguities or areas that could be explained better. For example, I might initially forget to mention the significance of the private members or the meaning of `Mode`.

By following this structured approach, I can break down the complex information in the header file and provide a comprehensive and informative answer that addresses all the user's questions. The key is to connect the low-level details of the C++ code to the higher-level concepts of regular expressions and JavaScript execution.
好的，让我们来分析一下 `v8/src/regexp/riscv/regexp-macro-assembler-riscv.h` 这个 V8 源代码文件。

**功能列举:**

这个头文件定义了 `RegExpMacroAssemblerRISCV` 类，它是 `NativeRegExpMacroAssembler` 的一个 RISC-V 架构特定实现。它的主要功能是**为 V8 的正则表达式引擎生成 RISC-V 汇编代码**。更具体地说，它提供了一组用于构建正则表达式匹配过程的低级操作的接口。

以下是其主要功能的详细分类：

* **正则表达式匹配的核心操作:**
    * **字符匹配:**  `CheckCharacter`, `CheckCharacterAfterAnd`, `CheckCharacterGT`, `CheckCharacterLT`, `CheckCharacterInRange`, `CheckCharacterNotInRange`, `CheckBitInTable` 等方法用于检查当前输入字符是否满足特定条件。
    * **位置管理:** `AdvanceCurrentPosition`, `SetCurrentPositionFromEnd`, `ReadCurrentPositionFromRegister`, `WriteCurrentPositionToRegister` 等方法用于操作正则表达式匹配过程中的当前位置。
    * **锚点匹配:** `CheckAtStart`, `CheckNotAtStart` 用于检查是否位于字符串的开头。
    * **反向引用:** `CheckNotBackReference`, `CheckNotBackReferenceIgnoreCase` 用于检查当前匹配是否与之前捕获的子匹配相同。
    * **特殊字符类:** `CheckSpecialClassRanges` 用于处理诸如 `\d`, `\w`, `\s` 等预定义的字符类。

* **控制流操作:**
    * **分支和跳转:** `Bind`, `GoTo` 用于在生成的汇编代码中创建标签和跳转。
    * **回溯:** `Backtrack`, `PushBacktrack` 用于管理正则表达式匹配失败时的回溯机制。
    * **条件判断:** `IfRegisterGE`, `IfRegisterLT`, `IfRegisterEqPos` 用于基于寄存器值进行条件分支。
    * **成功和失败:** `Succeed`, `Fail` 表示正则表达式匹配的最终结果。

* **寄存器管理:**
    * `SetRegister`, `PushRegister`, `PopRegister`, `ClearRegisters` 用于操作用于存储匹配状态的寄存器。

* **堆栈管理:**
    * `PushCurrentPosition`, `PopCurrentPosition` 用于在堆栈上保存和恢复当前匹配位置。

* **性能优化相关的操作:**
    * `CheckGreedyLoop` 用于优化贪婪循环的匹配。
    * `SkipUntilBitInTable` 用于快速跳过不匹配的字符。

* **代码生成和管理:**
    * `GetCode` 用于生成最终的可执行汇编代码。
    * `Implementation` 返回当前实现的类型。

* **栈溢出保护:**
    * `CheckStackGuardState` 用于检测和处理正则表达式执行过程中的栈溢出。

* **架构相关的细节:**
    *  定义了 RISC-V 架构特定的寄存器使用约定和栈帧布局。
    * `CanReadUnaligned` 标识是否支持非对齐内存访问。

**关于 `.tq` 结尾:**

如果 `v8/src/regexp/riscv/regexp-macro-assembler-riscv.h` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。 Torque 是 V8 用于编写高效、类型安全的 C++ 代码的领域特定语言，尤其适用于运行时代码。 然而，根据您提供的文件名，它以 `.h` 结尾，因此它是一个 **C++ 头文件**。

**与 JavaScript 功能的关系及示例:**

`RegExpMacroAssemblerRISCV` 直接参与了 JavaScript 中 `RegExp` 对象的实现。当你在 JavaScript 中使用正则表达式进行匹配时，V8 的正则表达式引擎会根据不同的架构选择相应的 `RegExpMacroAssembler` 实现，例如 RISC-V 架构会使用 `RegExpMacroAssemblerRISCV`。

**JavaScript 示例:**

```javascript
const regex = /ab+c/g;
const str = 'abbc abbbbc abc';
let array;

while ((array = regex.exec(str)) !== null) {
  console.log(`发现匹配 ${array[0]}。索引位于 ${array.index}。`);
}
```

**C++ 代码背后的运作方式 (简化说明):**

当 V8 执行上述 JavaScript 代码时，对于正则表达式 `/ab+c/g`，`RegExpMacroAssemblerRISCV` 中的方法会被调用来生成 RISC-V 汇编代码，用于执行以下步骤（简化）：

1. **匹配 'a':** 生成汇编指令，使用 `CheckCharacter` 检查当前字符是否为 'a'。
2. **匹配 'b' 一次或多次:** 生成汇编指令，使用循环结构（可能涉及 `CheckCharacter` 和跳转指令）来匹配一个或多个 'b'。`CheckGreedyLoop` 可能会用于优化这个过程。
3. **匹配 'c':** 生成汇编指令，使用 `CheckCharacter` 检查当前字符是否为 'c'。
4. **全局匹配 (g flag):** 生成汇编指令来管理多次匹配，例如在找到一个匹配后，使用 `AdvanceCurrentPosition` 更新位置并继续搜索。
5. **记录匹配结果:**  使用寄存器来存储匹配的起始位置和长度。

**代码逻辑推理 (假设输入与输出):**

假设我们调用 `CheckCharacter('b', &on_equal)`，并且当前的输入字符是 'b'。

* **假设输入:**
    * 当前输入字符: 'b'
    * `c`: 'b' (要匹配的字符)
    * `on_equal`: 指向汇编代码中某个标签的指针。

* **预期输出:**
    * 生成的 RISC-V 汇编代码会比较当前输入字符和 'b'。
    * 如果相等，则会生成跳转到 `on_equal` 标签的指令。
    * 如果不相等，则会继续执行下一条指令（通常会导致回溯或尝试其他匹配路径）。

**用户常见的编程错误示例 (虽然用户通常不直接操作这个类):**

虽然普通 JavaScript 开发者不会直接使用 `RegExpMacroAssemblerRISCV`，但理解其背后的原理可以帮助理解正则表达式的一些常见错误：

1. **回溯失控 (Catastrophic Backtracking):**  编写了可能导致引擎进行大量无效回溯的正则表达式。例如，对于输入 "aaaaaaaaaaaaaaaaaaaaac"，正则表达式 `/a*b*c/` 在某些情况下可能会导致性能问题，因为 `a*` 和 `b*` 的组合会产生大量的匹配可能性。 `RegExpMacroAssemblerRISCV` 中的回溯机制如果设计不当或正则表达式过于复杂，可能会导致栈溢出 (虽然有 `CheckStackGuardState` 保护)。

   ```javascript
   const regex = /a*b*c/;
   const str = "aaaaaaaaaaaaaaaaaaaaac";
   regex.test(str); // 可能很慢
   ```

2. **忘记锚点导致意外匹配:** 没有使用 `^` 或 `$` 锚定正则表达式，导致在不期望的位置发生匹配。`CheckAtStart` 和相关的操作就用于处理这些锚点。

   ```javascript
   const regex = /abc/;
   const str = "123abcdef456";
   console.log(regex.test(str)); // true，即使 "abc" 不在字符串的开头或结尾
   ```

3. **对 Unicode 字符处理不当:** 在处理包含 Unicode 字符的字符串时，如果没有正确使用 Unicode 相关的正则表达式特性（例如 `u` 标志），可能会导致匹配失败或不符合预期。 `RegExpMacroAssemblerRISCV` 需要处理 Latin1 和 UC16 两种模式，这涉及到字符大小和编码的差异。

   ```javascript
   const regex = /^😊$/;
   const str = "😊";
   console.log(regex.test(str)); // 在没有 'u' 标志时可能为 false

   const unicodeRegex = /^😊$/u;
   console.log(unicodeRegex.test(str)); // true
   ```

总结来说，`v8/src/regexp/riscv/regexp-macro-assembler-riscv.h` 是 V8 引擎中一个关键的底层组件，负责将高级的正则表达式操作转化为可以在 RISC-V 架构上执行的机器码。理解它的功能有助于深入理解 JavaScript 正则表达式的执行原理和潜在的性能问题。

### 提示词
```
这是目录为v8/src/regexp/riscv/regexp-macro-assembler-riscv.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/riscv/regexp-macro-assembler-riscv.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_REGEXP_RISCV_REGEXP_MACRO_ASSEMBLER_RISCV_H_
#define V8_REGEXP_RISCV_REGEXP_MACRO_ASSEMBLER_RISCV_H_

#include "src/base/strings.h"
#include "src/codegen/assembler-arch.h"
#include "src/codegen/macro-assembler.h"
#include "src/regexp/regexp-macro-assembler.h"

namespace v8 {
namespace internal {

class V8_EXPORT_PRIVATE RegExpMacroAssemblerRISCV
    : public NativeRegExpMacroAssembler {
 public:
  RegExpMacroAssemblerRISCV(Isolate* isolate, Zone* zone, Mode mode,
                            int registers_to_save);
  ~RegExpMacroAssemblerRISCV() override;
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
#ifdef RISCV_HAS_NO_UNALIGNED
  bool CanReadUnaligned() const override;
#endif
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
  // Registers s1 to s8, fp, and ra.
  static constexpr int kStoredRegistersOffset = kFramePointerOffset;
  // Return address (stored from link register, read into pc on return).

  // This 9 is 8 s-regs (s1..s11) plus fp.
  static constexpr int kNumCalleeRegsToRetain = 12;
  static constexpr int kReturnAddressOffset =
      kStoredRegistersOffset + kNumCalleeRegsToRetain * kSystemPointerSize;

  // Stack frame header.
  static constexpr int kStackFrameHeaderOffset = kReturnAddressOffset;
  // Below the frame pointer - the stack frame type marker and locals.
  static constexpr int kFrameTypeOffset =
      kFramePointerOffset - kSystemPointerSize;
  static_assert(kFrameTypeOffset ==
                (V8_EMBEDDED_CONSTANT_POOL_BOOL
                     ? kSystemPointerSize +
                           CommonFrameConstants::kContextOrFrameTypeOffset
                     : CommonFrameConstants::kContextOrFrameTypeOffset));
  // Register parameters stored by setup code.
  static constexpr int kIsolateOffset = kFrameTypeOffset - kSystemPointerSize;
  static constexpr int kDirectCallOffset = kIsolateOffset - kSystemPointerSize;
  static constexpr int kNumOutputRegistersOffset =
      kDirectCallOffset - kSystemPointerSize;
  static constexpr int kRegisterOutputOffset =
      kNumOutputRegistersOffset - kSystemPointerSize;
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
  static constexpr int kNumberOfStackLocals = 4;
  // First register address. Following registers are below it on the stack.
  static constexpr int kRegisterZeroOffset =
      kRegExpStackBasePointerOffset - kSystemPointerSize;

  // Initial size of code buffer.
  static constexpr int kInitialBufferSize = 1024;

  void CallCFunctionFromIrregexpCode(ExternalReference function,
                                     int num_arguments);
  void PushCallerSavedRegisters();
  void PopCallerSavedRegisters();

  // Check whether preemption has been requested.
  void CheckPreemption();

  // Check whether we are exceeding the stack limit on the backtrack stack.
  void CheckStackLimit();

  void CallCheckStackGuardState(Register scratch,
                                Operand extra_space_for_variables = Operand(0));
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
  // s7 should not be used here because baseline sparkplug uses s7 as context
  // register.
  static constexpr Register backtrack_stackpointer() { return s8; }

  // Register holding pointer to the current code object.
  static constexpr Register code_pointer() { return s1; }

  // Byte size of chars in the string to match (decided by the Mode argument).
  inline int char_size() const { return static_cast<int>(mode_); }

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

#endif  // V8_REGEXP_RISCV_REGEXP_MACRO_ASSEMBLER_RISCV_H_
```