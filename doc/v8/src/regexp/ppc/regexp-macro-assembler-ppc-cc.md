Response:
The user wants to understand the functionality of the provided C++ code snippet from V8, specifically `v8/src/regexp/ppc/regexp-macro-assembler-ppc.cc`.

Here's a breakdown of the thought process to address the request:

1. **Identify the file type and purpose:** The `.cc` extension signifies a C++ source file. The path `v8/src/regexp/ppc/` strongly suggests it's part of V8's regular expression engine, specifically for the PowerPC 64-bit architecture. The `RegExpMacroAssemblerPPC` class name confirms this. The code assembles machine instructions for regular expression matching.

2. **Extract key functionalities from the code comments and structure:** The initial comments and register assignments are crucial. They detail:
    * **Register usage conventions:**  This is fundamental to understanding how the assembler works. Note registers like `r27` (current position), `r28` (current character), `r29` (backtrack stack), and `r31` (frame pointer).
    * **Stack frame layout:** This is essential for understanding how arguments, local variables, and capture registers are accessed.
    * **Function signature (implied):**  The comment mentions how the code is called, giving a hint of the expected arguments.

3. **Analyze individual methods:**  Go through the provided methods and deduce their purposes. Look for common regexp operations:
    * `AdvanceCurrentPosition`: Moving the input pointer.
    * `AdvanceRegister`:  Modifying capture group register values.
    * `Backtrack`:  Implementing backtracking in the regex engine.
    * `CheckCharacter`, `CheckCharacterGT`, `CheckCharacterLT`, etc.: Character matching and comparisons.
    * `CheckAtStart`, `CheckNotAtStart`: Checking the current position against the start of the input.
    * `CheckBackReference`, `CheckNotBackReference`: Handling backreferences.
    * `CheckGreedyLoop`: Optimization for greedy loops.
    * `CheckSpecialClassRanges`: Matching character classes like digits, whitespace, etc.
    * `Fail`:  Marking a match failure.
    * `Push`/`Pop` operations:  Manipulating the backtrack stack.
    * `GetCode`:  The finalization step that generates the executable code.

4. **Address specific points in the prompt:**
    * **File extension:** Explicitly state that `.cc` indicates C++ and not Torque.
    * **Relationship to JavaScript:** Explain that this code is *underlying* the JavaScript `RegExp` object. Provide a simple JavaScript example to illustrate a regular expression.
    * **Code logic reasoning:** Select a simple method (like `AdvanceCurrentPosition`) and provide a hypothetical input and output to demonstrate its behavior.
    * **Common programming errors:** Think about typical mistakes when working with regular expressions (e.g., incorrect escaping, misunderstanding greedy vs. non-greedy matching). However, given this is *assembler* code, focus on potential errors in *how the assembler is used* or how the underlying logic could lead to errors if the regexp itself is complex. Stack overflow and incorrect capture group handling are relevant here.
    * **Overall functionality (Part 1 summary):** Condense the findings into a concise summary.

5. **Structure the answer:** Organize the information logically with clear headings and bullet points for readability.

6. **Refine and review:** Ensure the explanation is accurate, clear, and addresses all aspects of the prompt. For instance, initially, I might just say "moves the input pointer."  Refining it would be "Moves the current position in the input string by a specified number of characters."

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus heavily on the assembly instructions.
* **Correction:** Realized the user needs a higher-level understanding of the *functionality*. While mentioning assembly details is okay, the focus should be on *what* the code does in the context of regex matching.
* **Initial thought:** Directly translate C++ code into JavaScript.
* **Correction:** The C++ code is *implementation*, not directly equivalent to JavaScript. The JavaScript example should showcase a *feature* that this C++ code helps implement.
* **Initial thought:** List *all* possible programming errors.
* **Correction:** Focus on errors that are conceptually linked to the assembler's role (stack, captures) or common regex pitfalls that the engine needs to handle.

By following these steps and engaging in self-correction, I arrived at the comprehensive answer provided previously.
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if V8_TARGET_ARCH_PPC64

#include "src/regexp/ppc/regexp-macro-assembler-ppc.h"

#include "src/codegen/macro-assembler.h"
#include "src/codegen/ppc/assembler-ppc-inl.h"
#include "src/heap/factory.h"
#include "src/logging/log.h"
#include "src/objects/code-inl.h"
#include "src/regexp/regexp-stack.h"
#include "src/snapshot/embedded/embedded-data-inl.h"

namespace v8 {
namespace internal {

/*
 * This assembler uses the following register assignment convention
 * - r25: Temporarily stores the index of capture start after a matching pass
 *        for a global regexp.
 * - r26: Pointer to current InstructionStream object including heap object tag.
 * - r27: Current position in input, as negative offset from end of string.
 *        Please notice that this is the byte offset, not the character offset!
 * - r28: Currently loaded character. Must be loaded using
 *        LoadCurrentCharacter before using any of the dispatch methods.
 * - r29: Points to tip of backtrack stack
 * - r30: End of input (points to byte after last character in input).
 * - r31: Frame pointer. Used to access arguments, local variables and
 *         RegExp registers.
 * - r12: IP register, used by assembler. Very volatile.
 * - r1/sp : Points to tip of C stack.
 *
 * The remaining registers are free for computations.
 * Each call to a public method should retain this convention.
 *
 * The stack will have the following structure
 *  - fp[44]  Address regexp     (address of the JSRegExp object; unused in
 *                                native code, passed to match signature of
 *                                the interpreter):
 *  - fp[40]  Isolate* isolate   (address of the current isolate)
 *  - fp[36]  lr save area (currently unused)
 *  - fp[32]  backchain    (currently unused)
 *  --- sp when called ---
 *  - fp[28]  return address     (lr).
 *  - fp[24]  old frame pointer  (r31).
 *  - fp[0..20]  backup of registers r25..r30
 *  --- frame pointer ----
 *  - fp[-4]  frame marker
 *  - fp[-8]  isolate
 *  - fp[-12]  direct_call        (if 1, direct call from JavaScript code,
 *                                if 0, call through the runtime system).
 *  - fp[-16]  stack_area_base    (high end of the memory area to use as
 *                                backtracking stack).
 *  - fp[-20] capture array size (may fit multiple sets of matches)
 *  - fp[-24] int* capture_array (int[num_saved_registers_], for output).
 *  - fp[-28] end of input       (address of end of string).
 *  - fp[-32] start of input     (address of first character in string).
 *  - fp[-36] start index        (character index of start).
 *  - fp[-40] void* input_string (location of a handle containing the string).
 *  - fp[-44] success counter    (only for global regexps to count matches).
 *  - fp[-48] Offset of location before start of input (effectively character
 *            string start - 1). Used to initialize capture registers to a
 *            non-position.
 *  - fp[-52] At start (if 1, we are starting at the start of the
 *    string, otherwise 0)
 *  - fp[-56] register 0         (Only positions must be stored in the first
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
 *              uint8_t* stack_area_base,
 *              bool direct_call = false,
 *              Isolate* isolate,
 *              Address regexp);
 * The call is performed by NativeRegExpMacroAssembler::Execute()
 * (in regexp-macro-assembler.cc) via the GeneratedCode wrapper.
 */

#define __ ACCESS_MASM(masm_)

const int RegExpMacroAssemblerPPC::kRegExpCodeSize;

RegExpMacroAssemblerPPC::RegExpMacroAssemblerPPC(Isolate* isolate, Zone* zone,
                                                 Mode mode,
                                                 int registers_to_save)
    : NativeRegExpMacroAssembler(isolate, zone),
      masm_(std::make_unique<MacroAssembler>(
          isolate, CodeObjectRequired::kYes,
          NewAssemblerBuffer(kRegExpCodeSize))),
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

  __ b(&entry_label_);  // We'll write the entry code later.
  // If the code gets too big or corrupted, an internal exception will be
  // raised, and we will exit right away.
  __ bind(&internal_failure_label_);
  __ li(r3, Operand(FAILURE));
  __ Ret();
  __ bind(&start_label_);  // And then continue from here.
}

RegExpMacroAssemblerPPC::~RegExpMacroAssemblerPPC() {
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

int RegExpMacroAssemblerPPC::stack_limit_slack_slot_count() {
  return RegExpStack::kStackLimitSlackSlotCount;
}

void RegExpMacroAssemblerPPC::AdvanceCurrentPosition(int by) {
  if (by != 0) {
    if (is_int16(by * char_size())) {
      __ addi(current_input_offset(), current_input_offset(),
              Operand(by * char_size()));
    } else {
      __ mov(r0, Operand(by * char_size()));
      __ add(current_input_offset(), r0, current_input_offset());
    }
  }
}

void RegExpMacroAssemblerPPC::AdvanceRegister(int reg, int by) {
  DCHECK_LE(0, reg);
  DCHECK_GT(num_registers_, reg);
  if (by != 0) {
    __ LoadU64(r3, register_location(reg), r0);
    __ mov(r0, Operand(by));
    __ add(r3, r3, r0);
    __ StoreU64(r3, register_location(reg), r0);
  }
}

void RegExpMacroAssemblerPPC::Backtrack() {
  CheckPreemption();
  if (has_backtrack_limit()) {
    Label next;
    __ LoadU64(r3, MemOperand(frame_pointer(), kBacktrackCountOffset), r0);
    __ addi(r3, r3, Operand(1));
    __ StoreU64(r3, MemOperand(frame_pointer(), kBacktrackCountOffset), r0);
    __ mov(r0, Operand(backtrack_limit()));
    __ CmpS64(r3, r0);
    __ bne(&next);

    // Backtrack limit exceeded.
    if (can_fallback()) {
      __ b(&fallback_label_);
    } else {
      // Can't fallback, so we treat it as a failed match.
      Fail();
    }

    __ bind(&next);
  }
  // Pop InstructionStream offset from backtrack stack, add InstructionStream
  // and jump to location.
  Pop(r3);
  __ add(r3, r3, code_pointer());
  __ Jump(r3);
}

void RegExpMacroAssemblerPPC::Bind(Label* label) { __ bind(label); }

void RegExpMacroAssemblerPPC::CheckCharacter(uint32_t c, Label* on_equal) {
  __ CmpU64(current_character(), Operand(c), r0);
  BranchOrBacktrack(eq, on_equal);
}

void RegExpMacroAssemblerPPC::CheckCharacterGT(base::uc16 limit,
                                               Label* on_greater) {
  __ CmpU64(current_character(), Operand(limit), r0);
  BranchOrBacktrack(gt, on_greater);
}

void RegExpMacroAssemblerPPC::CheckAtStart(int cp_offset, Label* on_at_start) {
  __ LoadU64(r4, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
  __ addi(r3, current_input_offset(),
          Operand(-char_size() + cp_offset * char_size()));
  __ CmpS64(r3, r4);
  BranchOrBacktrack(eq, on_at_start);
}

void RegExpMacroAssemblerPPC::CheckNotAtStart(int cp_offset,
                                              Label* on_not_at_start) {
  __ LoadU64(r4, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
  __ addi(r3, current_input_offset(),
          Operand(-char_size() + cp_offset * char_size()));
  __ CmpS64(r3, r4);
  BranchOrBacktrack(ne, on_not_at_start);
}

void RegExpMacroAssemblerPPC::CheckCharacterLT(base::uc16 limit,
                                               Label* on_less) {
  __ CmpU64(current_character(), Operand(limit), r0);
  BranchOrBacktrack(lt, on_less);
}

void RegExpMacroAssemblerPPC::CheckGreedyLoop(Label* on_equal) {
  Label backtrack_non_equal;
  __ LoadU64(r3, MemOperand(backtrack_stackpointer(), 0));
  __ CmpS64(current_input_offset(), r3);
  __ bne(&backtrack_non_equal);
  __ addi(backtrack_stackpointer(), backtrack_stackpointer(),
          Operand(kSystemPointerSize));

  __ bind(&backtrack_non_equal);
  BranchOrBacktrack(eq, on_equal);
}

void RegExpMacroAssemblerPPC::CheckNotBackReferenceIgnoreCase(
    int start_reg, bool read_backward, bool unicode, Label* on_no_match) {
  // ... (Implementation of case-insensitive backreference check)
}

void RegExpMacroAssemblerPPC::CheckNotBackReference(int start_reg,
                                                    bool read_backward,
                                                    Label* on_no_match) {
  // ... (Implementation of backreference check)
}

void RegExpMacroAssemblerPPC::CheckNotCharacter(unsigned c,
                                                Label* on_not_equal) {
  __ CmpU64(current_character(), Operand(c), r0);
  BranchOrBacktrack(ne, on_not_equal);
}

void RegExpMacroAssemblerPPC::CheckCharacterAfterAnd(uint32_t c, uint32_t mask,
                                                     Label* on_equal) {
  // ... (Implementation of check after AND operation)
}

void RegExpMacroAssemblerPPC::CheckNotCharacterAfterAnd(unsigned c,
                                                        unsigned mask,
                                                        Label* on_not_equal) {
  // ... (Implementation of check not after AND operation)
}

void RegExpMacroAssemblerPPC::CheckNotCharacterAfterMinusAnd(
    base::uc16 c, base::uc16 minus, base::uc16 mask, Label* on_not_equal) {
  // ... (Implementation of check not after minus and AND operation)
}

void RegExpMacroAssemblerPPC::CheckCharacterInRange(base::uc16 from,
                                                    base::uc16 to,
                                                    Label* on_in_range) {
  // ... (Implementation of character in range check)
}

void RegExpMacroAssemblerPPC::CheckCharacterNotInRange(base::uc16 from,
                                                       base::uc16 to,
                                                       Label* on_not_in_range) {
  // ... (Implementation of character not in range check)
}

void RegExpMacroAssemblerPPC::CallIsCharacterInRangeArray(
    const ZoneList<CharacterRange>* ranges) {
  // ... (Implementation of calling C function for range check)
}

bool RegExpMacroAssemblerPPC::CheckCharacterInRangeArray(
    const ZoneList<CharacterRange>* ranges, Label* on_in_range) {
  // ... (Implementation of character in range array check)
}

bool RegExpMacroAssemblerPPC::CheckCharacterNotInRangeArray(
    const ZoneList<CharacterRange>* ranges, Label* on_not_in_range) {
  // ... (Implementation of character not in range array check)
}

void RegExpMacroAssemblerPPC::CheckBitInTable(Handle<ByteArray> table,
                                              Label* on_bit_set) {
  // ... (Implementation of bit in table check)
}

void RegExpMacroAssemblerPPC::SkipUntilBitInTable(
    int cp_offset, Handle<ByteArray> table, Handle<ByteArray> nibble_table,
    int advance_by) {
  // ... (Implementation of skipping until bit in table)
}

bool RegExpMacroAssemblerPPC::CheckSpecialClassRanges(StandardCharacterSet type,
                                                      Label* on_no_match) {
  // ... (Implementation of checking special character class ranges)
}

void RegExpMacroAssemblerPPC::Fail() {
  __ li(r3, Operand(FAILURE));
  __ b(&exit_label_);
}

void RegExpMacroAssemblerPPC::LoadRegExpStackPointerFromMemory(Register dst) {
  // ... (Implementation of loading regexp stack pointer)
}

void RegExpMacroAssemblerPPC::StoreRegExpStackPointerToMemory(
    Register src, Register scratch) {
  // ... (Implementation of storing regexp stack pointer)
}

void RegExpMacroAssemblerPPC::PushRegExpBasePointer(Register stack_pointer,
                                                    Register scratch) {
  // ... (Implementation of pushing regexp base pointer)
}

void RegExpMacroAssemblerPPC::PopRegExpBasePointer(Register stack_pointer_out,
                                                   Register scratch) {
  // ... (Implementation of popping regexp base pointer)
}

Handle<HeapObject> RegExpMacroAssemblerPPC::GetCode(Handle<String> source,
                                                    RegExpFlags flags) {
  // ... (Implementation of getting the generated code)
}
```

### 功能列举

`v8/src/regexp/ppc/regexp-macro-assembler-ppc.cc` 是 V8 引擎中用于在 **PowerPC 64位架构** 上高效执行正则表达式匹配的关键组件。它的主要功能是：

1. **正则表达式的编译和代码生成:** 它负责将高级的正则表达式模式编译成底层的 PowerPC 64位机器码指令。
2. **状态管理:** 它维护正则表达式匹配过程中的各种状态，包括当前输入位置、捕获组的状态、回溯栈等。
3. **指令发射:**  它提供了一系列方法（例如 `__ addi`, `__ CmpU64`, `__ b` 等）来生成 PowerPC 汇编指令，这些指令构成了最终执行的正则表达式匹配代码。
4. **寄存器分配和约定:**  它定义了一套寄存器使用约定，明确了哪些寄存器用于存储哪些关键信息（例如，输入位置、当前字符、回溯栈指针等）。这对于保证代码的正确性和可维护性至关重要。
5. **栈帧管理:**  它负责设置和管理执行正则表达式匹配代码时的栈帧，包括保存和恢复寄存器、分配局部变量空间等。
6. **回溯支持:**  它实现了正则表达式匹配中的回溯机制，当匹配失败时，能够回退到之前的状态并尝试其他的匹配路径。
7. **捕获组处理:**  它支持正则表达式中的捕获组，能够记录匹配到的子字符串的位置信息。
8. **性能优化:**  通过直接生成机器码，避免了解释执行的开销，从而实现高性能的正则表达式匹配。
9. **与运行时环境交互:**  它与 V8 引擎的运行时环境进行交互，例如访问堆对象、调用 C++ 函数等。
10. **处理不同的正则表达式特性:** 它支持各种正则表达式特性，例如字符匹配、字符类、量词、断言、反向引用等。

### 文件类型判断

如果 `v8/src/regexp/ppc/regexp-macro-assembler-ppc.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。但根据您提供的文件扩展名 `.cc`，**它是一个 C++ 源代码文件**。 Torque 是一种 V8 内部使用的类型安全的语言，用于生成高效的 C++ 代码。

### 与 JavaScript 功能的关系

`v8/src/regexp/ppc/regexp-macro-assembler-ppc.cc` 中生成的机器码是 JavaScript 中 `RegExp` 对象的核心执行引擎。当你在 JavaScript 中创建一个正则表达式并使用其 `test()`, `exec()`, `match()`, `search()`, 或 `replace()` 方法时，V8 引擎会根据正则表达式的模式，最终调用这个 C++ 文件中生成的机器码来进行实际的匹配操作。

**JavaScript 示例:**

```javascript
const regex = /ab+c/g;
const str = 'abbcdefabhc';
let array;

while ((array = regex.exec(str)) !== null) {
  console.log(`Found ${array[0]}. Next starts at ${regex.lastIndex}.`);
  // Expected output: "Found abbc". "Next starts at 4."
  // Expected output: "Found abc". "Next starts at 10."
}
```

在这个例子中，当 `regex.exec(str)` 被调用时，V8 内部会使用类似于 `regexp-macro-assembler-ppc.cc` 的代码来执行正则表达式 `/ab+c/g` 在字符串 `str` 上的匹配。  `regexp-macro-assembler-ppc.cc` 负责生成高效的机器码来查找以 "a" 开头，后面跟着一个或多个 "b"，最后跟着 "c" 的子字符串。

### 代码逻辑推理

考虑 `AdvanceCurrentPosition(int by)` 方法：

**假设输入:**

* `current_input_offset()` 当前的值代表字符串中某个位置的字节偏移量（相对于字符串末尾的负偏移）。
* `by` 的值为 `2`，表示要向前移动 2 个字符的位置。
* `char_size()` 的值为 `1` （假设是 Latin-1 编码）。

**代码逻辑:**

```c++
void RegExpMacroAssemblerPPC::AdvanceCurrentPosition(int by) {
  if (by != 0) {
    if (is_int16(by * char_size())) {
      __ addi(current_input_offset(), current_input_offset(),
              Operand(by * char_size()));
    } else {
      __ mov(r0, Operand(by * char_size()));
      __ add(current_input_offset(), r0, current_input_offset());
    }
  }
}
```

1. `by` 不等于 0，所以进入 `if` 块。
2. `by * char_size()` 的值为 `2 * 1 = 2`。
3. `is_int16(2)` 返回 `true`，因为 2 可以用 16 位有符号整数表示。
4. 执行 `__ addi(current_input_offset(), current_input_offset(), Operand(2));` 这条 PowerPC 指令会将 `current_input_offset()` 寄存器的值加上 2。

**输出:**

* `current_input_offset()` 的值会增加 2，这意味着当前位置向前移动了 2 个字节（或 2 个字符，因为 `char_size()` 是 1）。由于 `current_input_offset()` 是负偏移，数值的增加实际上意味着更接近字符串的开头。

**假设输入 (UC16 编码):**

* `current_input_offset()` 当前的值代表字符串中某个位置的字节偏移量。
* `by` 的值为 `2`。
* `char_size()` 的值为 `2` （假设是 UC16 编码）。

**代码逻辑:**

1. `by` 不等于 0。
2. `by * char_size()` 的值为 `2 * 2 = 4`。
3. `is_int16(4)` 返回 `true`。
4. 执行 `__ addi(current_input_offset(), current_input_offset(), Operand(4));`

**输出:**

* `current_input_offset()` 的值会增加 4，向前移动了 4 个字节，相当于 2 个 UC16 字符。

### 用户常见的编程错误

涉及到底层汇编代码的错误通常不会是直接的 JavaScript 编程错误，而是与正则表达式模式的复杂性或使用方式有关，这些错误会导致底层引擎的行为出现问题。一些间接相关的常见编程错误包括：

1. **回溯失控 (Catastrophic Backtracking):**  编写的正则表达式在某些输入下会产生大量的回溯，导致性能急剧下降甚至程序无响应。例如，`/(a+)+b/` 在输入 `aaaa...` 时会发生。`RegExpMacroAssemblerPPC::Backtrack()` 方法的逻辑直接参与了回溯的处理。

   ```javascript
   const regex = /(a+)+b/;
   const str = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaac'; // 缺少 'b' 导致大量回溯
   const result = regex.test(str); // 可能耗时很长
   ```

2. **不正确的捕获组使用:** 误以为捕获组会捕获到预期的内容，或者混淆了捕获组的索引。尽管 `RegExpMacroAssemblerPPC` 负责管理捕获组的寄存器，但编程错误发生在正则表达式模式的设计和 JavaScript 代码对捕获结果的访问上。

   ```javascript
   const regex = /(\d{4})-(\d{2})-(\d{2})/;
   const str = '2023-10-27';
   const match = str.match(regex);
   console.log(match[0]); // "2023-10-27"
   console.log(match[1]); // "2023"
   console.log(match[2]); // "10"
   console.log(match[3]); // "27"
   // 错误地假设 match[4] 会存在
   ```

3. **对 Unicode 字符处理不当:** 在处理包含 Unicode 字符的字符串时，没有正确理解正则表达式的 Unicode 支持，导致匹配结果不符合预期。`RegExpMacroAssemblerPPC` 会根据 `mode_` （LATIN1 或 UC16）处理字符，错误的模式可能导致不正确的匹配。

   ```javascript
   const regex = /^é$/.test('é'); // 通常可以正确匹配
   const regex2 = /^É$/.test('é'); // 大小写不匹配，通常不匹配

   // 更复杂的情况，涉及到 Unicode 字符的属性
   const regex3 = /\p{L}/u.test('你好'); // 匹配任何语言的字母
   ```

4. **过度依赖前瞻/后顾断言:**  虽然功能强大，但过度使用或不当使用前瞻/后顾断言可能会降低正则表达式的性能，因为它们可能需要进行多次扫描。

### 功能归纳 (第1部分)

`v8/src/regexp/ppc/regexp-macro-assembler-ppc.cc` 的主要功能是作为 V8 引擎中 PowerPC 64位架构下正则表达式匹配的**代码生成器和执行引擎**。它负责将正则表达式模式编译成高效的机器码，并在运行时执行这些代码以完成字符串的匹配操作。该文件定义了底层的寄存器使用约定、栈帧结构以及用于生成各种正则表达式匹配指令的方法。它处理了包括字符匹配、边界检查、回溯、捕获组等核心的正则表达式功能，是 V8 实现高性能正则表达式的关键组成部分。

Prompt: 
```
这是目录为v8/src/regexp/ppc/regexp-macro-assembler-ppc.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/ppc/regexp-macro-assembler-ppc.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if V8_TARGET_ARCH_PPC64

#include "src/regexp/ppc/regexp-macro-assembler-ppc.h"

#include "src/codegen/macro-assembler.h"
#include "src/codegen/ppc/assembler-ppc-inl.h"
#include "src/heap/factory.h"
#include "src/logging/log.h"
#include "src/objects/code-inl.h"
#include "src/regexp/regexp-stack.h"
#include "src/snapshot/embedded/embedded-data-inl.h"

namespace v8 {
namespace internal {

/*
 * This assembler uses the following register assignment convention
 * - r25: Temporarily stores the index of capture start after a matching pass
 *        for a global regexp.
 * - r26: Pointer to current InstructionStream object including heap object tag.
 * - r27: Current position in input, as negative offset from end of string.
 *        Please notice that this is the byte offset, not the character offset!
 * - r28: Currently loaded character. Must be loaded using
 *        LoadCurrentCharacter before using any of the dispatch methods.
 * - r29: Points to tip of backtrack stack
 * - r30: End of input (points to byte after last character in input).
 * - r31: Frame pointer. Used to access arguments, local variables and
 *         RegExp registers.
 * - r12: IP register, used by assembler. Very volatile.
 * - r1/sp : Points to tip of C stack.
 *
 * The remaining registers are free for computations.
 * Each call to a public method should retain this convention.
 *
 * The stack will have the following structure
 *  - fp[44]  Address regexp     (address of the JSRegExp object; unused in
 *                                native code, passed to match signature of
 *                                the interpreter):
 *  - fp[40]  Isolate* isolate   (address of the current isolate)
 *  - fp[36]  lr save area (currently unused)
 *  - fp[32]  backchain    (currently unused)
 *  --- sp when called ---
 *  - fp[28]  return address     (lr).
 *  - fp[24]  old frame pointer  (r31).
 *  - fp[0..20]  backup of registers r25..r30
 *  --- frame pointer ----
 *  - fp[-4]  frame marker
 *  - fp[-8]  isolate
 *  - fp[-12]  direct_call        (if 1, direct call from JavaScript code,
 *                                if 0, call through the runtime system).
 *  - fp[-16]  stack_area_base    (high end of the memory area to use as
 *                                backtracking stack).
 *  - fp[-20] capture array size (may fit multiple sets of matches)
 *  - fp[-24] int* capture_array (int[num_saved_registers_], for output).
 *  - fp[-28] end of input       (address of end of string).
 *  - fp[-32] start of input     (address of first character in string).
 *  - fp[-36] start index        (character index of start).
 *  - fp[-40] void* input_string (location of a handle containing the string).
 *  - fp[-44] success counter    (only for global regexps to count matches).
 *  - fp[-48] Offset of location before start of input (effectively character
 *            string start - 1). Used to initialize capture registers to a
 *            non-position.
 *  - fp[-52] At start (if 1, we are starting at the start of the
 *    string, otherwise 0)
 *  - fp[-56] register 0         (Only positions must be stored in the first
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
 *              uint8_t* stack_area_base,
 *              bool direct_call = false,
 *              Isolate* isolate,
 *              Address regexp);
 * The call is performed by NativeRegExpMacroAssembler::Execute()
 * (in regexp-macro-assembler.cc) via the GeneratedCode wrapper.
 */

#define __ ACCESS_MASM(masm_)

const int RegExpMacroAssemblerPPC::kRegExpCodeSize;

RegExpMacroAssemblerPPC::RegExpMacroAssemblerPPC(Isolate* isolate, Zone* zone,
                                                 Mode mode,
                                                 int registers_to_save)
    : NativeRegExpMacroAssembler(isolate, zone),
      masm_(std::make_unique<MacroAssembler>(
          isolate, CodeObjectRequired::kYes,
          NewAssemblerBuffer(kRegExpCodeSize))),
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


  __ b(&entry_label_);  // We'll write the entry code later.
  // If the code gets too big or corrupted, an internal exception will be
  // raised, and we will exit right away.
  __ bind(&internal_failure_label_);
  __ li(r3, Operand(FAILURE));
  __ Ret();
  __ bind(&start_label_);  // And then continue from here.
}

RegExpMacroAssemblerPPC::~RegExpMacroAssemblerPPC() {
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

int RegExpMacroAssemblerPPC::stack_limit_slack_slot_count() {
  return RegExpStack::kStackLimitSlackSlotCount;
}

void RegExpMacroAssemblerPPC::AdvanceCurrentPosition(int by) {
  if (by != 0) {
    if (is_int16(by * char_size())) {
      __ addi(current_input_offset(), current_input_offset(),
              Operand(by * char_size()));
    } else {
      __ mov(r0, Operand(by * char_size()));
      __ add(current_input_offset(), r0, current_input_offset());
    }
  }
}


void RegExpMacroAssemblerPPC::AdvanceRegister(int reg, int by) {
  DCHECK_LE(0, reg);
  DCHECK_GT(num_registers_, reg);
  if (by != 0) {
    __ LoadU64(r3, register_location(reg), r0);
    __ mov(r0, Operand(by));
    __ add(r3, r3, r0);
    __ StoreU64(r3, register_location(reg), r0);
  }
}


void RegExpMacroAssemblerPPC::Backtrack() {
  CheckPreemption();
  if (has_backtrack_limit()) {
    Label next;
    __ LoadU64(r3, MemOperand(frame_pointer(), kBacktrackCountOffset), r0);
    __ addi(r3, r3, Operand(1));
    __ StoreU64(r3, MemOperand(frame_pointer(), kBacktrackCountOffset), r0);
    __ mov(r0, Operand(backtrack_limit()));
    __ CmpS64(r3, r0);
    __ bne(&next);

    // Backtrack limit exceeded.
    if (can_fallback()) {
      __ b(&fallback_label_);
    } else {
      // Can't fallback, so we treat it as a failed match.
      Fail();
    }

    __ bind(&next);
  }
  // Pop InstructionStream offset from backtrack stack, add InstructionStream
  // and jump to location.
  Pop(r3);
  __ add(r3, r3, code_pointer());
  __ Jump(r3);
}


void RegExpMacroAssemblerPPC::Bind(Label* label) { __ bind(label); }


void RegExpMacroAssemblerPPC::CheckCharacter(uint32_t c, Label* on_equal) {
  __ CmpU64(current_character(), Operand(c), r0);
  BranchOrBacktrack(eq, on_equal);
}

void RegExpMacroAssemblerPPC::CheckCharacterGT(base::uc16 limit,
                                               Label* on_greater) {
  __ CmpU64(current_character(), Operand(limit), r0);
  BranchOrBacktrack(gt, on_greater);
}

void RegExpMacroAssemblerPPC::CheckAtStart(int cp_offset, Label* on_at_start) {
  __ LoadU64(r4, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
  __ addi(r3, current_input_offset(),
          Operand(-char_size() + cp_offset * char_size()));
  __ CmpS64(r3, r4);
  BranchOrBacktrack(eq, on_at_start);
}

void RegExpMacroAssemblerPPC::CheckNotAtStart(int cp_offset,
                                              Label* on_not_at_start) {
  __ LoadU64(r4, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
  __ addi(r3, current_input_offset(),
          Operand(-char_size() + cp_offset * char_size()));
  __ CmpS64(r3, r4);
  BranchOrBacktrack(ne, on_not_at_start);
}

void RegExpMacroAssemblerPPC::CheckCharacterLT(base::uc16 limit,
                                               Label* on_less) {
  __ CmpU64(current_character(), Operand(limit), r0);
  BranchOrBacktrack(lt, on_less);
}

void RegExpMacroAssemblerPPC::CheckGreedyLoop(Label* on_equal) {
  Label backtrack_non_equal;
  __ LoadU64(r3, MemOperand(backtrack_stackpointer(), 0));
  __ CmpS64(current_input_offset(), r3);
  __ bne(&backtrack_non_equal);
  __ addi(backtrack_stackpointer(), backtrack_stackpointer(),
          Operand(kSystemPointerSize));

  __ bind(&backtrack_non_equal);
  BranchOrBacktrack(eq, on_equal);
}

void RegExpMacroAssemblerPPC::CheckNotBackReferenceIgnoreCase(
    int start_reg, bool read_backward, bool unicode, Label* on_no_match) {
  Label fallthrough;
  __ LoadU64(r3, register_location(start_reg),
             r0);  // Index of start of capture
  __ LoadU64(r4, register_location(start_reg + 1), r0);  // Index of end
  __ sub(r4, r4, r3, LeaveOE, SetRC);                  // Length of capture.

  // At this point, the capture registers are either both set or both cleared.
  // If the capture length is zero, then the capture is either empty or cleared.
  // Fall through in both cases.
  __ beq(&fallthrough, cr0);

  // Check that there are enough characters left in the input.
  if (read_backward) {
    __ LoadU64(r6, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
    __ add(r6, r6, r4);
    __ CmpS64(current_input_offset(), r6);
    BranchOrBacktrack(le, on_no_match);
  } else {
    __ add(r0, r4, current_input_offset(), LeaveOE, SetRC);
    BranchOrBacktrack(gt, on_no_match, cr0);
  }

  if (mode_ == LATIN1) {
    Label success;
    Label fail;
    Label loop_check;

    // r3 - offset of start of capture
    // r4 - length of capture
    __ add(r3, r3, end_of_input_address());
    __ add(r5, end_of_input_address(), current_input_offset());
    if (read_backward) {
      __ sub(r5, r5, r4);  // Offset by length when matching backwards.
    }
    __ add(r4, r3, r4);

    // r3 - Address of start of capture.
    // r4 - Address of end of capture
    // r5 - Address of current input position.

    Label loop;
    __ bind(&loop);
    __ lbz(r6, MemOperand(r3));
    __ addi(r3, r3, Operand(char_size()));
    __ lbz(r25, MemOperand(r5));
    __ addi(r5, r5, Operand(char_size()));
    __ CmpS64(r25, r6);
    __ beq(&loop_check);

    // Mismatch, try case-insensitive match (converting letters to lower-case).
    __ ori(r6, r6, Operand(0x20));  // Convert capture character to lower-case.
    __ ori(r25, r25, Operand(0x20));  // Also convert input character.
    __ CmpS64(r25, r6);
    __ bne(&fail);
    __ subi(r6, r6, Operand('a'));
    __ cmpli(r6, Operand('z' - 'a'));  // Is r6 a lowercase letter?
    __ ble(&loop_check);               // In range 'a'-'z'.
    // Latin-1: Check for values in range [224,254] but not 247.
    __ subi(r6, r6, Operand(224 - 'a'));
    __ cmpli(r6, Operand(254 - 224));
    __ bgt(&fail);                    // Weren't Latin-1 letters.
    __ cmpi(r6, Operand(247 - 224));  // Check for 247.
    __ beq(&fail);

    __ bind(&loop_check);
    __ CmpS64(r3, r4);
    __ blt(&loop);
    __ b(&success);

    __ bind(&fail);
    BranchOrBacktrack(al, on_no_match);

    __ bind(&success);
    // Compute new value of character position after the matched part.
    __ sub(current_input_offset(), r5, end_of_input_address());
    if (read_backward) {
      __ LoadU64(r3,
                 register_location(start_reg));  // Index of start of capture
      __ LoadU64(r4,
                 register_location(start_reg + 1));  // Index of end of capture
      __ add(current_input_offset(), current_input_offset(), r3);
      __ sub(current_input_offset(), current_input_offset(), r4);
    }
  } else {
    DCHECK(mode_ == UC16);
    int argument_count = 4;
    __ PrepareCallCFunction(argument_count, r5);

    // r3 - offset of start of capture
    // r4 - length of capture

    // Put arguments into arguments registers.
    // Parameters are
    //   r3: Address byte_offset1 - Address captured substring's start.
    //   r4: Address byte_offset2 - Address of current character position.
    //   r5: size_t byte_length - length of capture in bytes(!)
    //   r6: Isolate* isolate.

    // Address of start of capture.
    __ add(r3, r3, end_of_input_address());
    // Length of capture.
    __ mr(r5, r4);
    // Save length in callee-save register for use on return.
    __ mr(r25, r4);
    // Address of current input position.
    __ add(r4, current_input_offset(), end_of_input_address());
    if (read_backward) {
      __ sub(r4, r4, r25);
    }
    // Isolate.
    __ mov(r6, Operand(ExternalReference::isolate_address(isolate())));

    {
      AllowExternalCallThatCantCauseGC scope(masm_.get());
      ExternalReference function =
          unicode
              ? ExternalReference::re_case_insensitive_compare_unicode()
              : ExternalReference::re_case_insensitive_compare_non_unicode();
      CallCFunctionFromIrregexpCode(function, argument_count);
    }

    // Check if function returned non-zero for success or zero for failure.
    __ cmpi(r3, Operand::Zero());
    BranchOrBacktrack(eq, on_no_match);

    // On success, advance position by length of capture.
    if (read_backward) {
      __ sub(current_input_offset(), current_input_offset(), r25);
    } else {
      __ add(current_input_offset(), current_input_offset(), r25);
    }
  }

  __ bind(&fallthrough);
}

void RegExpMacroAssemblerPPC::CheckNotBackReference(int start_reg,
                                                    bool read_backward,
                                                    Label* on_no_match) {
  Label fallthrough;

  // Find length of back-referenced capture.
  __ LoadU64(r3, register_location(start_reg), r0);
  __ LoadU64(r4, register_location(start_reg + 1), r0);
  __ sub(r4, r4, r3, LeaveOE, SetRC);  // Length to check.

  // At this point, the capture registers are either both set or both cleared.
  // If the capture length is zero, then the capture is either empty or cleared.
  // Fall through in both cases.
  __ beq(&fallthrough, cr0);

  // Check that there are enough characters left in the input.
  if (read_backward) {
    __ LoadU64(r6, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
    __ add(r6, r6, r4);
    __ CmpS64(current_input_offset(), r6);
    BranchOrBacktrack(le, on_no_match);
  } else {
    __ add(r0, r4, current_input_offset(), LeaveOE, SetRC);
    BranchOrBacktrack(gt, on_no_match, cr0);
  }

  // r3 - offset of start of capture
  // r4 - length of capture
  __ add(r3, r3, end_of_input_address());
  __ add(r5, end_of_input_address(), current_input_offset());
  if (read_backward) {
    __ sub(r5, r5, r4);  // Offset by length when matching backwards.
  }
  __ add(r4, r4, r3);

  Label loop;
  __ bind(&loop);
  if (mode_ == LATIN1) {
    __ lbz(r6, MemOperand(r3));
    __ addi(r3, r3, Operand(char_size()));
    __ lbz(r25, MemOperand(r5));
    __ addi(r5, r5, Operand(char_size()));
  } else {
    DCHECK(mode_ == UC16);
    __ lhz(r6, MemOperand(r3));
    __ addi(r3, r3, Operand(char_size()));
    __ lhz(r25, MemOperand(r5));
    __ addi(r5, r5, Operand(char_size()));
  }
  __ CmpS64(r6, r25);
  BranchOrBacktrack(ne, on_no_match);
  __ CmpS64(r3, r4);
  __ blt(&loop);

  // Move current character position to position after match.
  __ sub(current_input_offset(), r5, end_of_input_address());
  if (read_backward) {
    __ LoadU64(r3, register_location(start_reg));  // Index of start of capture
    __ LoadU64(r4,
               register_location(start_reg + 1));  // Index of end of capture
    __ add(current_input_offset(), current_input_offset(), r3);
    __ sub(current_input_offset(), current_input_offset(), r4);
  }

  __ bind(&fallthrough);
}


void RegExpMacroAssemblerPPC::CheckNotCharacter(unsigned c,
                                                Label* on_not_equal) {
  __ CmpU64(current_character(), Operand(c), r0);
  BranchOrBacktrack(ne, on_not_equal);
}


void RegExpMacroAssemblerPPC::CheckCharacterAfterAnd(uint32_t c, uint32_t mask,
                                                     Label* on_equal) {
  __ mov(r0, Operand(mask));
  if (c == 0) {
    __ and_(r3, current_character(), r0, SetRC);
  } else {
    __ and_(r3, current_character(), r0);
    __ CmpU64(r3, Operand(c), r0, cr0);
  }
  BranchOrBacktrack(eq, on_equal, cr0);
}


void RegExpMacroAssemblerPPC::CheckNotCharacterAfterAnd(unsigned c,
                                                        unsigned mask,
                                                        Label* on_not_equal) {
  __ mov(r0, Operand(mask));
  if (c == 0) {
    __ and_(r3, current_character(), r0, SetRC);
  } else {
    __ and_(r3, current_character(), r0);
    __ CmpU64(r3, Operand(c), r0, cr0);
  }
  BranchOrBacktrack(ne, on_not_equal, cr0);
}

void RegExpMacroAssemblerPPC::CheckNotCharacterAfterMinusAnd(
    base::uc16 c, base::uc16 minus, base::uc16 mask, Label* on_not_equal) {
  DCHECK_GT(String::kMaxUtf16CodeUnit, minus);
  __ subi(r3, current_character(), Operand(minus));
  __ mov(r0, Operand(mask));
  __ and_(r3, r3, r0);
  __ CmpU64(r3, Operand(c), r0);
  BranchOrBacktrack(ne, on_not_equal);
}

void RegExpMacroAssemblerPPC::CheckCharacterInRange(base::uc16 from,
                                                    base::uc16 to,
                                                    Label* on_in_range) {
  __ mov(r0, Operand(from));
  __ sub(r3, current_character(), r0);
  __ CmpU64(r3, Operand(to - from), r0);
  BranchOrBacktrack(le, on_in_range);  // Unsigned lower-or-same condition.
}

void RegExpMacroAssemblerPPC::CheckCharacterNotInRange(base::uc16 from,
                                                       base::uc16 to,
                                                       Label* on_not_in_range) {
  __ mov(r0, Operand(from));
  __ sub(r3, current_character(), r0);
  __ CmpU64(r3, Operand(to - from), r0);
  BranchOrBacktrack(gt, on_not_in_range);  // Unsigned higher condition.
}

void RegExpMacroAssemblerPPC::CallIsCharacterInRangeArray(
    const ZoneList<CharacterRange>* ranges) {
  static const int kNumArguments = 2;
  __ PrepareCallCFunction(kNumArguments, r0);

  __ mr(r3, current_character());
  __ mov(r4, Operand(GetOrAddRangeArray(ranges)));

  {
    // We have a frame (set up in GetCode), but the assembler doesn't know.
    FrameScope scope(masm_.get(), StackFrame::MANUAL);
    CallCFunctionFromIrregexpCode(
        ExternalReference::re_is_character_in_range_array(), kNumArguments);
  }

  __ mov(code_pointer(), Operand(masm_->CodeObject()));
}

bool RegExpMacroAssemblerPPC::CheckCharacterInRangeArray(
    const ZoneList<CharacterRange>* ranges, Label* on_in_range) {
  CallIsCharacterInRangeArray(ranges);
  __ cmpi(r3, Operand::Zero());
  BranchOrBacktrack(ne, on_in_range);
  return true;
}

bool RegExpMacroAssemblerPPC::CheckCharacterNotInRangeArray(
    const ZoneList<CharacterRange>* ranges, Label* on_not_in_range) {
  CallIsCharacterInRangeArray(ranges);
  __ cmpi(r3, Operand::Zero());
  BranchOrBacktrack(eq, on_not_in_range);
  return true;
}

void RegExpMacroAssemblerPPC::CheckBitInTable(Handle<ByteArray> table,
                                              Label* on_bit_set) {
  __ mov(r3, Operand(table));
  if (mode_ != LATIN1 || kTableMask != String::kMaxOneByteCharCode) {
    __ andi(r4, current_character(), Operand(kTableSize - 1));
    __ addi(r4, r4, Operand(OFFSET_OF_DATA_START(ByteArray) - kHeapObjectTag));
  } else {
    __ addi(r4, current_character(),
            Operand(OFFSET_OF_DATA_START(ByteArray) - kHeapObjectTag));
  }
  __ lbzx(r3, MemOperand(r3, r4));
  __ cmpi(r3, Operand::Zero());
  BranchOrBacktrack(ne, on_bit_set);
}

void RegExpMacroAssemblerPPC::SkipUntilBitInTable(
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

bool RegExpMacroAssemblerPPC::CheckSpecialClassRanges(StandardCharacterSet type,
                                                      Label* on_no_match) {
  // Range checks (c in min..max) are generally implemented by an unsigned
  // (c - min) <= (max - min) check
  // TODO(jgruber): No custom implementation (yet): s(UC16), S(UC16).
  switch (type) {
    case StandardCharacterSet::kWhitespace:
      // Match space-characters.
      if (mode_ == LATIN1) {
        // One byte space characters are '\t'..'\r', ' ' and \u00a0.
        Label success;
        __ cmpi(current_character(), Operand(' '));
        __ beq(&success);
        // Check range 0x09..0x0D.
        __ subi(r3, current_character(), Operand('\t'));
        __ cmpli(r3, Operand('\r' - '\t'));
        __ ble(&success);
        // \u00a0 (NBSP).
        __ cmpi(r3, Operand(0x00A0 - '\t'));
        BranchOrBacktrack(ne, on_no_match);
        __ bind(&success);
        return true;
      }
      return false;
    case StandardCharacterSet::kNotWhitespace:
      // The emitted code for generic character classes is good enough.
      return false;
    case StandardCharacterSet::kDigit:
      // Match ASCII digits ('0'..'9')
      __ subi(r3, current_character(), Operand('0'));
      __ cmpli(r3, Operand('9' - '0'));
      BranchOrBacktrack(gt, on_no_match);
      return true;
    case StandardCharacterSet::kNotDigit:
      // Match non ASCII-digits
      __ subi(r3, current_character(), Operand('0'));
      __ cmpli(r3, Operand('9' - '0'));
      BranchOrBacktrack(le, on_no_match);
      return true;
    case StandardCharacterSet::kNotLineTerminator: {
      // Match non-newlines (not 0x0A('\n'), 0x0D('\r'), 0x2028 and 0x2029)
      __ xori(r3, current_character(), Operand(0x01));
      // See if current character is '\n'^1 or '\r'^1, i.e., 0x0B or 0x0C
      __ subi(r3, r3, Operand(0x0B));
      __ cmpli(r3, Operand(0x0C - 0x0B));
      BranchOrBacktrack(le, on_no_match);
      if (mode_ == UC16) {
        // Compare original value to 0x2028 and 0x2029, using the already
        // computed (current_char ^ 0x01 - 0x0B). I.e., check for
        // 0x201D (0x2028 - 0x0B) or 0x201E.
        __ subi(r3, r3, Operand(0x2028 - 0x0B));
        __ cmpli(r3, Operand(1));
        BranchOrBacktrack(le, on_no_match);
      }
      return true;
    }
    case StandardCharacterSet::kLineTerminator: {
      // Match newlines (0x0A('\n'), 0x0D('\r'), 0x2028 and 0x2029)
      __ xori(r3, current_character(), Operand(0x01));
      // See if current character is '\n'^1 or '\r'^1, i.e., 0x0B or 0x0C
      __ subi(r3, r3, Operand(0x0B));
      __ cmpli(r3, Operand(0x0C - 0x0B));
      if (mode_ == LATIN1) {
        BranchOrBacktrack(gt, on_no_match);
      } else {
        Label done;
        __ ble(&done);
        // Compare original value to 0x2028 and 0x2029, using the already
        // computed (current_char ^ 0x01 - 0x0B). I.e., check for
        // 0x201D (0x2028 - 0x0B) or 0x201E.
        __ subi(r3, r3, Operand(0x2028 - 0x0B));
        __ cmpli(r3, Operand(1));
        BranchOrBacktrack(gt, on_no_match);
        __ bind(&done);
      }
      return true;
    }
    case StandardCharacterSet::kWord: {
      if (mode_ != LATIN1) {
        // Table is 256 entries, so all Latin1 characters can be tested.
        __ cmpi(current_character(), Operand('z'));
        BranchOrBacktrack(gt, on_no_match);
      }
      ExternalReference map = ExternalReference::re_word_character_map();
      __ mov(r3, Operand(map));
      __ lbzx(r3, MemOperand(r3, current_character()));
      __ cmpli(r3, Operand::Zero());
      BranchOrBacktrack(eq, on_no_match);
      return true;
    }
    case StandardCharacterSet::kNotWord: {
      Label done;
      if (mode_ != LATIN1) {
        // Table is 256 entries, so all Latin1 characters can be tested.
        __ cmpli(current_character(), Operand('z'));
        __ bgt(&done);
      }
      ExternalReference map = ExternalReference::re_word_character_map();
      __ mov(r3, Operand(map));
      __ lbzx(r3, MemOperand(r3, current_character()));
      __ cmpli(r3, Operand::Zero());
      BranchOrBacktrack(ne, on_no_match);
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

void RegExpMacroAssemblerPPC::Fail() {
  __ li(r3, Operand(FAILURE));
  __ b(&exit_label_);
}

void RegExpMacroAssemblerPPC::LoadRegExpStackPointerFromMemory(Register dst) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_stack_pointer(isolate());
  __ mov(dst, Operand(ref));
  __ LoadU64(dst, MemOperand(dst));
}

void RegExpMacroAssemblerPPC::StoreRegExpStackPointerToMemory(
    Register src, Register scratch) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_stack_pointer(isolate());
  __ mov(scratch, Operand(ref));
  __ StoreU64(src, MemOperand(scratch));
}

void RegExpMacroAssemblerPPC::PushRegExpBasePointer(Register stack_pointer,
                                                    Register scratch) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ mov(scratch, Operand(ref));
  __ LoadU64(scratch, MemOperand(scratch));
  __ SubS64(scratch, stack_pointer, scratch);
  __ StoreU64(scratch,
              MemOperand(frame_pointer(), kRegExpStackBasePointerOffset));
}

void RegExpMacroAssemblerPPC::PopRegExpBasePointer(Register stack_pointer_out,
                                                   Register scratch) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ LoadU64(stack_pointer_out,
             MemOperand(frame_pointer(), kRegExpStackBasePointerOffset));
  __ mov(scratch, Operand(ref));
  __ LoadU64(scratch, MemOperand(scratch));
  __ AddS64(stack_pointer_out, stack_pointer_out, scratch);
  StoreRegExpStackPointerToMemory(stack_pointer_out, scratch);
}

Handle<HeapObject> RegExpMacroAssemblerPPC::GetCode(Handle<String> source,
                                                    RegExpFlags flags) {
  Label return_r3;

  if (masm_->has_exception()) {
    // If the code gets corrupted due to long regular expressions and lack of
    // space on trampolines, an internal exception flag is set. If this case
    // is detected, we will jump into exit sequence right away.
    __ bind_to(&entry_label_, internal_failure_label_.pos());
  } else {
    // Finalize code - write the entry point code now we know how many
    // registers we need.

    // Entry code:
    __ bind(&entry_label_);

    // Tell the system that we have a stack frame.  Because the type
    // is MANUAL, no is generated.
    FrameScope scope(masm_.get(), StackFrame::MANUAL);

    // Ensure register assigments are consistent with callee save mask
    DCHECK(kRegExpCalleeSaved.has(r25));
    DCHECK(kRegExpCalleeSaved.has(code_pointer()));
    DCHECK(kRegExpCalleeSaved.has(current_input_offset()));
    DCHECK(kRegExpCalleeSaved.has(current_character()));
    DCHECK(kRegExpCalleeSaved.has(backtrack_stackpointer()));
    DCHECK(kRegExpCalleeSaved.has(end_of_input_address()));
    DCHECK(kRegExpCalleeSaved.has(frame_pointer()));

    // Emit code to start a new stack frame. In the following we push all
    // callee-save registers (these end up above the fp) and all register
    // arguments (these end up below the fp).
    RegList registers_to_retain = kRegExpCalleeSaved;
    __ mflr(r0);
    __ push(r0);
    __ MultiPush(registers_to_retain);
    __ mr(frame_pointer(), sp);

    RegList argument_registers = {r3, r4, r5, r6, r7, r8, r9, r10};
    // Also push the frame marker.
    __ mov(r0, Operand(StackFrame::TypeToMarker(StackFrame::IRREGEXP)));
    __ push(r0);
    __ MultiPush(argument_registers);

    static_assert(kSuccessfulCapturesOffset ==
                  kInputStringOffset - kSystemPointerSize);
    __ li(r3, Operand::Zero());
    __ push(r3);  // Make room for success counter and initialize it to 0.
    static_assert(kStringStartMinusOneOffset ==
                  kSuccessfulCapturesOffset - kSystemPointerSize);
    __ push(r3);  // Make room for "string start - 1" constant.
    static_assert(kBacktrackCountOffset ==
                  kStringStartMinusOneOffset - kSystemPointerSize);
    __ push(r3);  // The backtrack counter.
    static_assert(kRegExpStackBasePointerOffset ==
                  kBacktrackCountOffset - kSystemPointerSize);
    __ push(r3);  // The regexp stack base ptr.

    // Initialize backtrack stack pointer. It must not be clobbered from here
    // on. Note the backtrack_stackpointer is callee-saved.
    static_assert(backtrack_stackpointer() == r29);
    LoadRegExpStackPointerFromMemory(backtrack_stackpointer());

    // Store the regexp base pointer - we'll later restore it / write it to
    // memory when returning from this irregexp code object.
    PushRegExpBasePointer(backtrack_stackpointer(), r4);

    {
      // Check if we have space on the stack for registers.
      Label stack_limit_hit, stack_ok;

      ExternalReference stack_limit =
          ExternalReference::address_of_jslimit(isolate());
      __ mov(r3, Operand(stack_limit));
      __ LoadU64(r3, MemOperand(r3));
      __ sub(r3, sp, r3, LeaveOE, SetRC);
      Operand extra_space_for_variables(num_registers_ * kSystemPointerSize);

      // Handle it if the stack pointer is already below the stack limit.
      __ ble(&stack_limit_hit, cr0);
      // Check if there is room for the variable number of registers above
      // the stack limit.
      __ CmpU64(r3, extra_space_for_variables, r0);
      __ bge(&stack_ok);
      // Exit with OutOfMemory exception. There is not enough space on the stack
      // for our working registers.
      __ li(r3, Operand(EXCEPTION));
      __ b(&return_r3);

      __ bind(&stack_limit_hit);
      CallCheckStackGuardState(r3, extra_space_for_variables);
      __ cmpi(r3, Operand::Zero());
      // If returned value is non-zero, we exit with the returned value as
      // result.
      __ bne(&return_r3);

      __ bind(&stack_ok);
    }

    // Allocate space on stack for registers.
    __ AddS64(sp, sp, Operand(-num_registers_ * kSystemPointerSize), r0);
    // Load string end.
    __ LoadU64(end_of_input_address(),
               MemOperand(frame_pointer(), kInputEndOffset));
    // Load input start.
    __ LoadU64(r3, MemOperand(frame_pointer(), kInputStartOffset));
    // Find negative length (offset of start relative to end).
    __ sub(current_input_offset(), r3, end_of_input_address());
    // Set r3 to address of char before start of the input string
    // (effectively string position -1).
    __ LoadU64(r4, MemOperand(frame_pointer(), kStartIndexOffset));
    __ subi(r3, current_input_offset(), Operand(char_size()));
    if (mode_ == UC16) {
      __ ShiftLeftU64(r0, r4, Operand(1));
      __ sub(r3, r3, r0);
    } else {
      __ sub(r3, r3, r4);
    }
    // Store this value in a local variable, for use when clearing
    // position registers.
    __ StoreU64(r3, MemOperand(frame_pointer(), kStringStartMinusOneOffset));

    // Initialize code pointer register
    __ mov(code_pointer(), Operand(masm_->CodeObject()));

    Label load_char_start_regexp;
    {
      Label start_regexp;
      // Load newline if index is at start, previous character otherwise.
      __ cmpi(r4, Operand::Zero());
      __ bne(&load_char_start_regexp);
      __ li(current_character(), Operand('\n'));
      __ b(&start_regexp);

      // Global regexp restarts matching here.
      __ bind(&load_char_start_regexp);
      // Load previous char as initial value of current character register.
      LoadCurrentCharacterUnchecked(-1, 1);
      __ bind(&start_regexp);
    }

    // Initialize on-stack registers.
    if (num_saved_registers_ > 0) {  // Always is, if generated from a regexp.
      // Fill saved registers with initial val
"""


```