Response:
The user wants a summary of the functionality of the provided C++ code snippet. The code is from `v8/src/regexp/x64/regexp-macro-assembler-x64.cc` and implements a regular expression macro assembler for the x64 architecture within the V8 JavaScript engine.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The file name and the initial comments clearly indicate this is a macro assembler for regular expressions on x64. The primary function is to generate machine code for regular expression matching.

2. **Extract key components and their roles:**
    * **Assembler (`masm_`):** The fundamental tool for emitting x64 instructions.
    * **Registers:** The comments meticulously detail register usage conventions. This is crucial information for understanding the assembler's operation.
    * **Stack Layout:** The description of the stack frame provides context for how arguments, local variables, and RegExp registers are managed.
    * **Methods:** The various `RegExpMacroAssemblerX64::` methods represent the core functionalities offered by the assembler (e.g., advancing position, checking characters, backtracking, handling backreferences, etc.).

3. **Group functionalities into logical categories:**  The methods can be categorized based on their purpose:
    * **Control Flow:** `Backtrack`, `Bind`, `Fail`, `BranchOrBacktrack`, `CheckPreemption`.
    * **Position Management:** `AdvanceCurrentPosition`, `CheckAtStart`, `CheckNotAtStart`.
    * **Character Matching:** `CheckCharacter`, `CheckNotCharacter`, `CheckCharacterInRange`, `CheckCharacterNotInRange`, `CheckSpecialClassRanges`, `CheckBitInTable`, `SkipUntilBitInTable`.
    * **Backreference Handling:** `CheckNotBackReference`, `CheckNotBackReferenceIgnoreCase`.
    * **Stack Operations:** `Push`, `Pop`, `LoadRegExpStackPointerFromMemory`, `StoreRegExpStackPointerToMemory`, `PushRegExpBasePointer`, `PopRegExpBasePointer`.
    * **Function Calls:** `CallCFunctionFromIrregexpCode`, `PushCallerSavedRegisters`, `PopCallerSavedRegisters`.
    * **Register Management:** `ReadPositionFromRegister`, `WritePositionToRegister`.

4. **Address the specific questions in the prompt:**
    * **`.tq` suffix:** The code is C++, not Torque.
    * **JavaScript relationship:** Explain that this code is *behind the scenes* when JavaScript regular expressions are executed. Provide a simple JavaScript regex example.
    * **Code logic inference:** Choose a simple method like `AdvanceCurrentPosition` and demonstrate its effect with input/output.
    * **Common programming errors:** Focus on errors related to assumptions about register contents or stack manipulation when directly interfacing with such low-level code (although users generally don't).
    * **Overall functionality (Part 1):** Summarize the core purpose as a code generator for RegExp matching on x64, highlighting the register conventions and stack layout.

5. **Refine the language:** Use clear and concise language. Explain technical terms where necessary. Structure the answer logically with headings and bullet points for readability.

6. **Review and verify:** Ensure the summary accurately reflects the code's functionality and addresses all parts of the prompt. Double-check register names and stack offsets for consistency with the provided code.

Self-Correction/Refinement during the process:

* Initially, I might just list all the methods. However, grouping them by functionality provides a better high-level understanding.
* The JavaScript example needs to be simple and directly related to the concept. A basic string search demonstrates the underlying regex engine's work.
* The "common programming errors" section is tricky since users don't directly interact with this code. Framing it as potential issues when extending or modifying the V8 engine is more accurate.
* Ensuring the summary explicitly mentions the x64 architecture is important given the file path.
这个C++源代码文件 `v8/src/regexp/x64/regexp-macro-assembler-x64.cc` 是 V8 JavaScript 引擎中用于 **x64 架构** 的 **正则表达式宏汇编器** 的实现。它的主要功能是 **生成针对 x64 架构优化的机器码**，用于执行 JavaScript 中的正则表达式匹配。

以下是其功能的详细列表：

**核心功能：生成 x64 机器码以执行正则表达式匹配**

* **寄存器分配约定：**  代码开头详细定义了各个 x64 寄存器的用途，例如 `rdx` 用于存储当前字符，`rdi` 用于存储当前输入位置，`rsi` 用于存储输入结束位置等等。  这些约定是生成正确机器码的基础。
* **栈帧布局：**  定义了执行正则表达式匹配时，C++ 栈上的数据布局，包括正则表达式对象地址、Isolate 指针、调用方式、捕获组数组、输入字符串信息、返回地址、寄存器备份等等。这对于访问和操作运行时数据至关重要。
* **宏指令：**  提供了一系列高级宏指令（封装了多个底层的 x64 指令），用于执行常见的正则表达式操作，例如：
    * **位置管理：** `AdvanceCurrentPosition`, `CheckAtStart`, `CheckNotAtStart`.
    * **字符匹配：** `CheckCharacter`, `CheckNotCharacter`, `CheckCharacterInRange`, `CheckCharacterNotInRange`, `CheckCharacterAfterAnd`, `CheckNotCharacterAfterAnd`, `CheckNotCharacterAfterMinusAnd`.
    * **特殊字符类匹配：** `CheckSpecialClassRanges` (例如，匹配空格、数字、单词字符等)。
    * **回溯：** `Backtrack`.
    * **控制流：** `Bind`, `BranchOrBacktrack`, `Fail`.
    * **捕获组处理：**  通过操作栈上的寄存器区域实现。
    * **反向引用：** `CheckNotBackReference`, `CheckNotBackReferenceIgnoreCase`.
    * **位表查找：** `CheckBitInTable`, `SkipUntilBitInTable`.
* **与 C++ 函数交互：**  提供了 `CallCFunctionFromIrregexpCode` 用于调用 C++ 函数，例如用于处理 Unicode 相关的比较。
* **栈操作：**  提供了管理正则表达式执行栈的函数，用于保存和恢复状态，例如 `Push`, `Pop`, `PushRegExpBasePointer`, `PopRegExpBasePointer`.
* **性能优化：**  针对 x64 架构进行了优化，例如使用了特定的指令和寄存器。

**关于代码类型：**

`v8/src/regexp/x64/regexp-macro-assembler-x64.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque 源代码。 Torque 源代码文件通常以 `.tq` 结尾。

**与 JavaScript 的关系：**

这个 C++ 文件的功能与 JavaScript 中的正则表达式功能 **密切相关**。当你在 JavaScript 中使用正则表达式进行匹配时，V8 引擎会：

1. **解析正则表达式：** 将 JavaScript 的正则表达式字符串解析成内部的表示形式。
2. **生成机器码：**  根据内部表示，调用 `RegExpMacroAssemblerX64` 或其他架构对应的宏汇编器，生成用于执行匹配的 x64 机器码。
3. **执行机器码：**  执行生成的机器码，在输入字符串上进行匹配操作。

**JavaScript 示例：**

```javascript
const text = "Hello World 123";
const regex = /W\w+d\s\d+/; // 匹配以 'W' 开头，后跟一个或多个单词字符，再跟 'd'，空格，最后是一个或多个数字

if (regex.test(text)) {
  console.log("匹配成功");
} else {
  console.log("匹配失败");
}

const matchResult = text.match(regex);
if (matchResult) {
  console.log("匹配结果:", matchResult[0]); // 输出 "World 123"
}
```

在这个例子中，当你执行 `regex.test(text)` 或 `text.match(regex)` 时，V8 引擎内部会使用类似于 `v8/src/regexp/x64/regexp-macro-assembler-x64.cc` 中的代码来生成并执行机器码，从而判断 `text` 是否匹配 `regex`，并提取匹配到的子字符串。

**代码逻辑推理示例：**

**假设输入：**

* `AdvanceCurrentPosition(3)` 被调用。
* 假设当前 `rdi` 的值为 -10（表示当前位置在字符串末尾往前 10 个字节）。
* `char_size()` 为 1 (Latin1 模式)。

**输出：**

* `rdi` 的值将变为 -7 (-10 + 3 * 1)。  当前位置向后移动了 3 个字节。

**假设输入：**

* `CheckCharacter('A', &on_equal)` 被调用。
* 假设当前 `rdx` 的值为 65 (字符 'A' 的 ASCII 码)。
* `on_equal` 是一个已定义的标签。

**输出：**

* 因为当前字符匹配 'A'，所以程序会跳转到 `on_equal` 标签所指向的代码位置。

**用户常见的编程错误（与此文件相关的，间接影响）：**

由于用户通常不直接编写或修改 V8 引擎的源代码，因此直接与此文件相关的编程错误较少。然而，用户在使用正则表达式时可能犯以下错误，这些错误会影响到 V8 引擎如何执行相关的机器码：

* **正则表达式语法错误：** 例如，括号不匹配，使用了无效的特殊字符等。这会导致正则表达式解析失败，从而无法生成有效的机器码。
  ```javascript
  const regex = /[a-z+/; // 缺少闭合方括号
  ```
* **过度复杂的正则表达式：**  编写过于复杂的正则表达式可能会导致回溯过多，影响性能，甚至导致堆栈溢出。 虽然宏汇编器本身处理了回溯，但用户编写的模式是根源。
  ```javascript
  const text = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const regex = /(a+)+b/; // 这个正则表达式会导致大量回溯
  ```
* **对 Unicode 字符的错误假设：** 在处理包含 Unicode 字符的字符串时，可能会因为对字符编码和长度的错误假设而导致正则表达式匹配不符合预期。  `RegExpMacroAssemblerX64` 针对 Latin1 和 UC16 模式有不同的处理，用户的正则表达式需要与之对应。

**总结（Part 1 的功能）：**

`v8/src/regexp/x64/regexp-macro-assembler-x64.cc` 的主要功能是 **作为 V8 JavaScript 引擎的一部分，为 x64 架构生成高效的机器码，用于执行 JavaScript 中的正则表达式匹配**。 它定义了寄存器使用约定、栈帧布局，并提供了一系列宏指令来简化生成机器码的过程，涵盖了字符匹配、位置管理、回溯、捕获组处理等核心的正则表达式操作。 虽然用户不直接操作此代码，但其实现直接影响了 JavaScript 正则表达式的执行效率和正确性。

Prompt: 
```
这是目录为v8/src/regexp/x64/regexp-macro-assembler-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/x64/regexp-macro-assembler-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if V8_TARGET_ARCH_X64

#include "src/regexp/x64/regexp-macro-assembler-x64.h"

#include "src/codegen/code-desc.h"
#include "src/codegen/macro-assembler.h"
#include "src/heap/factory.h"
#include "src/logging/log.h"
#include "src/objects/code-inl.h"
#include "src/regexp/regexp-macro-assembler.h"
#include "src/regexp/regexp-stack.h"

namespace v8 {
namespace internal {

/*
 * This assembler uses the following register assignment convention
 * - rdx : Currently loaded character(s) as Latin1 or UC16.  Must be loaded
 *         using LoadCurrentCharacter before using any of the dispatch methods.
 *         Temporarily stores the index of capture start after a matching pass
 *         for a global regexp.
 * - rdi : Current position in input, as negative offset from end of string.
 *         Please notice that this is the byte offset, not the character
 *         offset!  Is always a 32-bit signed (negative) offset, but must be
 *         maintained sign-extended to 64 bits, since it is used as index.
 * - rsi : End of input (points to byte after last character in input),
 *         so that rsi+rdi points to the current character.
 * - rbp : Frame pointer.  Used to access arguments, local variables and
 *         RegExp registers.
 * - rsp : Points to tip of C stack.
 * - rcx : Points to tip of backtrack stack.  The backtrack stack contains
 *         only 32-bit values.  Most are offsets from some base (e.g., character
 *         positions from end of string or code location from InstructionStream
 * pointer).
 * - r8  : InstructionStream object pointer.  Used to convert between absolute
 * and code-object-relative addresses.
 *
 * The registers rax, rbx, r9 and r11 are free to use for computations.
 * If changed to use r12+, they should be saved as callee-save registers.
 * The macro assembler special register r13 (kRootRegister) isn't special
 * during execution of RegExp code (it doesn't hold the value assumed when
 * creating JS code), so Root related macro operations can be used.
 *
 * xmm0 - xmm5 are free to use. On Windows, xmm6 - xmm15 are callee-saved and
 * therefore need to be saved/restored.
 *
 * Each call to a C++ method should retain these registers.
 *
 * The stack will have the following content, in some order, indexable from the
 * frame pointer (see, e.g., kDirectCallOffset):
 *    - Address regexp       (address of the JSRegExp object; unused in native
 *                            code, passed to match signature of interpreter)
 *    - Isolate* isolate     (address of the current isolate)
 *    - direct_call          (if 1, direct call from JavaScript code, if 0 call
 *                            through the runtime system)
 *    - capture array size   (may fit multiple sets of matches)
 *    - int* capture_array   (int[num_saved_registers_], for output).
 *    - end of input         (address of end of string)
 *    - start of input       (address of first character in string)
 *    - start index          (character index of start)
 *    - String input_string  (input string)
 *    - return address
 *    - backup of callee save registers (rbx, possibly rsi and rdi).
 *    - success counter      (only useful for global regexp to count matches)
 *    - Offset of location before start of input (effectively character
 *      string start - 1).  Used to initialize capture registers to a
 *      non-position.
 *    - At start of string (if 1, we are starting at the start of the
 *      string, otherwise 0)
 *    - register 0  rbp[-n]   (Only positions must be stored in the first
 *    - register 1  rbp[-n-8]  num_saved_registers_ registers)
 *    - ...
 *
 * The first num_saved_registers_ registers are initialized to point to
 * "character -1" in the string (i.e., char_size() bytes before the first
 * character of the string).  The remaining registers starts out uninitialized.
 *
 * The argument values must be provided by the calling code by calling the
 * code's entry address cast to a function pointer with the following signature:
 * int (*match)(String input_string,
 *              int start_index,
 *              Address start,
 *              Address end,
 *              int* capture_output_array,
 *              int num_capture_registers,
 *              bool direct_call = false,
 *              Isolate* isolate,
 *              Address regexp);
 */

#define __ ACCESS_MASM((&masm_))

const int RegExpMacroAssemblerX64::kRegExpCodeSize;

RegExpMacroAssemblerX64::RegExpMacroAssemblerX64(Isolate* isolate, Zone* zone,
                                                 Mode mode,
                                                 int registers_to_save)
    : NativeRegExpMacroAssembler(isolate, zone),
      masm_(isolate, CodeObjectRequired::kYes,
            NewAssemblerBuffer(kRegExpCodeSize)),
      no_root_array_scope_(&masm_),
      code_relative_fixup_positions_(zone),
      mode_(mode),
      num_registers_(registers_to_save),
      num_saved_registers_(registers_to_save),
      entry_label_(),
      start_label_(),
      success_label_(),
      backtrack_label_(),
      exit_label_() {
  DCHECK_EQ(0, registers_to_save % 2);
  __ CodeEntry();
  __ jmp(&entry_label_);   // We'll write the entry code when we know more.
  __ bind(&start_label_);  // And then continue from here.
}

RegExpMacroAssemblerX64::~RegExpMacroAssemblerX64() {
  // Unuse labels in case we throw away the assembler without calling GetCode.
  entry_label_.Unuse();
  start_label_.Unuse();
  success_label_.Unuse();
  backtrack_label_.Unuse();
  exit_label_.Unuse();
  check_preempt_label_.Unuse();
  stack_overflow_label_.Unuse();
  fallback_label_.Unuse();
}

int RegExpMacroAssemblerX64::stack_limit_slack_slot_count() {
  return RegExpStack::kStackLimitSlackSlotCount;
}

void RegExpMacroAssemblerX64::AdvanceCurrentPosition(int by) {
  if (by != 0) {
    __ addq(rdi, Immediate(by * char_size()));
  }
}


void RegExpMacroAssemblerX64::AdvanceRegister(int reg, int by) {
  DCHECK_LE(0, reg);
  DCHECK_GT(num_registers_, reg);
  if (by != 0) {
    __ addq(register_location(reg), Immediate(by));
  }
}


void RegExpMacroAssemblerX64::Backtrack() {
  CheckPreemption();
  if (has_backtrack_limit()) {
    Label next;
    __ incq(Operand(rbp, kBacktrackCountOffset));
    __ cmpq(Operand(rbp, kBacktrackCountOffset), Immediate(backtrack_limit()));
    __ j(not_equal, &next);

    // Backtrack limit exceeded.
    if (can_fallback()) {
      __ jmp(&fallback_label_);
    } else {
      // Can't fallback, so we treat it as a failed match.
      Fail();
    }

    __ bind(&next);
  }
  // Pop InstructionStream offset from backtrack stack, add InstructionStream
  // and jump to location.
  Pop(rbx);
  __ addq(rbx, code_object_pointer());

  // TODO(sroettger): This jump needs an endbr64 instruction but the code is
  // performance sensitive. Needs more thought how to do this in a fast way.
  __ jmp(rbx, /*notrack=*/true);
}


void RegExpMacroAssemblerX64::Bind(Label* label) {
  __ bind(label);
}


void RegExpMacroAssemblerX64::CheckCharacter(uint32_t c, Label* on_equal) {
  __ cmpl(current_character(), Immediate(c));
  BranchOrBacktrack(equal, on_equal);
}

void RegExpMacroAssemblerX64::CheckCharacterGT(base::uc16 limit,
                                               Label* on_greater) {
  __ cmpl(current_character(), Immediate(limit));
  BranchOrBacktrack(greater, on_greater);
}

void RegExpMacroAssemblerX64::CheckAtStart(int cp_offset, Label* on_at_start) {
  __ leaq(rax, Operand(rdi, -char_size() + cp_offset * char_size()));
  __ cmpq(rax, Operand(rbp, kStringStartMinusOneOffset));
  BranchOrBacktrack(equal, on_at_start);
}

void RegExpMacroAssemblerX64::CheckNotAtStart(int cp_offset,
                                              Label* on_not_at_start) {
  __ leaq(rax, Operand(rdi, -char_size() + cp_offset * char_size()));
  __ cmpq(rax, Operand(rbp, kStringStartMinusOneOffset));
  BranchOrBacktrack(not_equal, on_not_at_start);
}

void RegExpMacroAssemblerX64::CheckCharacterLT(base::uc16 limit,
                                               Label* on_less) {
  __ cmpl(current_character(), Immediate(limit));
  BranchOrBacktrack(less, on_less);
}

void RegExpMacroAssemblerX64::CheckGreedyLoop(Label* on_equal) {
  Label fallthrough;
  __ cmpl(rdi, Operand(backtrack_stackpointer(), 0));
  __ j(not_equal, &fallthrough);
  Drop();
  BranchOrBacktrack(on_equal);
  __ bind(&fallthrough);
}

void RegExpMacroAssemblerX64::CallCFunctionFromIrregexpCode(
    ExternalReference function, int num_arguments) {
  // Irregexp code must not set fast_c_call_caller_fp and fast_c_call_caller_pc
  // since
  //
  // 1. it may itself have been called using CallCFunction and nested calls are
  //    unsupported, and
  // 2. it may itself have been called directly from C where the frame pointer
  //    might not be set (-fomit-frame-pointer), and thus frame iteration would
  //    fail.
  //
  // See also: crbug.com/v8/12670#c17.
  __ CallCFunction(function, num_arguments, SetIsolateDataSlots::kNo);
}

// Push (pop) caller-saved registers used by irregexp.
void RegExpMacroAssemblerX64::PushCallerSavedRegisters() {
#ifndef V8_TARGET_OS_WIN
  // Callee-save in Microsoft 64-bit ABI, but not in AMD64 ABI.
  __ pushq(rsi);
  __ pushq(rdi);
#endif
  __ pushq(rcx);
}

void RegExpMacroAssemblerX64::PopCallerSavedRegisters() {
  __ popq(rcx);
#ifndef V8_TARGET_OS_WIN
  __ popq(rdi);
  __ popq(rsi);
#endif
}

void RegExpMacroAssemblerX64::CheckNotBackReferenceIgnoreCase(
    int start_reg, bool read_backward, bool unicode, Label* on_no_match) {
  Label fallthrough;
  ReadPositionFromRegister(rdx, start_reg);  // Offset of start of capture
  ReadPositionFromRegister(rbx, start_reg + 1);  // Offset of end of capture
  __ subq(rbx, rdx);                             // Length of capture.

  // -----------------------
  // rdx  = Start offset of capture.
  // rbx = Length of capture

  // At this point, the capture registers are either both set or both cleared.
  // If the capture length is zero, then the capture is either empty or cleared.
  // Fall through in both cases.
  __ j(equal, &fallthrough);

  // -----------------------
  // rdx - Start of capture
  // rbx - length of capture
  // Check that there are sufficient characters left in the input.
  if (read_backward) {
    __ movl(rax, Operand(rbp, kStringStartMinusOneOffset));
    __ addl(rax, rbx);
    __ cmpl(rdi, rax);
    BranchOrBacktrack(less_equal, on_no_match);
  } else {
    __ movl(rax, rdi);
    __ addl(rax, rbx);
    BranchOrBacktrack(greater, on_no_match);
  }

  if (mode_ == LATIN1) {
    Label loop_increment;
    if (on_no_match == nullptr) {
      on_no_match = &backtrack_label_;
    }

    __ leaq(r9, Operand(rsi, rdx, times_1, 0));
    __ leaq(r11, Operand(rsi, rdi, times_1, 0));
    if (read_backward) {
      __ subq(r11, rbx);  // Offset by length when matching backwards.
    }
    __ addq(rbx, r9);  // End of capture
    // ---------------------
    // r11 - current input character address
    // r9 - current capture character address
    // rbx - end of capture

    Label loop;
    __ bind(&loop);
    __ movzxbl(rdx, Operand(r9, 0));
    __ movzxbl(rax, Operand(r11, 0));
    // al - input character
    // dl - capture character
    __ cmpb(rax, rdx);
    __ j(equal, &loop_increment);

    // Mismatch, try case-insensitive match (converting letters to lower-case).
    // I.e., if or-ing with 0x20 makes values equal and in range 'a'-'z', it's
    // a match.
    __ orq(rax, Immediate(0x20));  // Convert match character to lower-case.
    __ orq(rdx, Immediate(0x20));  // Convert capture character to lower-case.
    __ cmpb(rax, rdx);
    __ j(not_equal, on_no_match);  // Definitely not equal.
    __ subb(rax, Immediate('a'));
    __ cmpb(rax, Immediate('z' - 'a'));
    __ j(below_equal, &loop_increment);  // In range 'a'-'z'.
    // Latin-1: Check for values in range [224,254] but not 247.
    __ subb(rax, Immediate(224 - 'a'));
    __ cmpb(rax, Immediate(254 - 224));
    __ j(above, on_no_match);  // Weren't Latin-1 letters.
    __ cmpb(rax, Immediate(247 - 224));  // Check for 247.
    __ j(equal, on_no_match);
    __ bind(&loop_increment);
    // Increment pointers into match and capture strings.
    __ addq(r11, Immediate(1));
    __ addq(r9, Immediate(1));
    // Compare to end of capture, and loop if not done.
    __ cmpq(r9, rbx);
    __ j(below, &loop);

    // Compute new value of character position after the matched part.
    __ movq(rdi, r11);
    __ subq(rdi, rsi);
    if (read_backward) {
      // Subtract match length if we matched backward.
      __ addq(rdi, register_location(start_reg));
      __ subq(rdi, register_location(start_reg + 1));
    }
  } else {
    DCHECK(mode_ == UC16);
    PushCallerSavedRegisters();

    static const int num_arguments = 4;
    __ PrepareCallCFunction(num_arguments);

    // Put arguments into parameter registers. Parameters are
    //   Address byte_offset1 - Address captured substring's start.
    //   Address byte_offset2 - Address of current character position.
    //   size_t byte_length - length of capture in bytes(!)
    //   Isolate* isolate.
#ifdef V8_TARGET_OS_WIN
    DCHECK(rcx == kCArgRegs[0]);
    DCHECK(rdx == kCArgRegs[1]);
    // Compute and set byte_offset1 (start of capture).
    __ leaq(rcx, Operand(rsi, rdx, times_1, 0));
    // Set byte_offset2.
    __ leaq(rdx, Operand(rsi, rdi, times_1, 0));
    if (read_backward) {
      __ subq(rdx, rbx);
    }
#else  // AMD64 calling convention
    DCHECK(rdi == kCArgRegs[0]);
    DCHECK(rsi == kCArgRegs[1]);
    // Compute byte_offset2 (current position = rsi+rdi).
    __ leaq(rax, Operand(rsi, rdi, times_1, 0));
    // Compute and set byte_offset1 (start of capture).
    __ leaq(rdi, Operand(rsi, rdx, times_1, 0));
    // Set byte_offset2.
    __ movq(rsi, rax);
    if (read_backward) {
      __ subq(rsi, rbx);
    }
#endif  // V8_TARGET_OS_WIN

    // Set byte_length.
    __ movq(kCArgRegs[2], rbx);
    // Isolate.
    __ LoadAddress(kCArgRegs[3], ExternalReference::isolate_address(isolate()));

    {
      AllowExternalCallThatCantCauseGC scope(&masm_);
      ExternalReference compare =
          unicode
              ? ExternalReference::re_case_insensitive_compare_unicode()
              : ExternalReference::re_case_insensitive_compare_non_unicode();
      CallCFunctionFromIrregexpCode(compare, num_arguments);
    }

    // Restore original values before reacting on result value.
    __ Move(code_object_pointer(), masm_.CodeObject());
    PopCallerSavedRegisters();

    // Check if function returned non-zero for success or zero for failure.
    __ testq(rax, rax);
    BranchOrBacktrack(zero, on_no_match);
    // On success, advance position by length of capture.
    // Requires that rbx is callee save (true for both Win64 and AMD64 ABIs).
    if (read_backward) {
      __ subq(rdi, rbx);
    } else {
      __ addq(rdi, rbx);
    }
  }
  __ bind(&fallthrough);
}

void RegExpMacroAssemblerX64::CheckNotBackReference(int start_reg,
                                                    bool read_backward,
                                                    Label* on_no_match) {
  Label fallthrough;

  // Find length of back-referenced capture.
  ReadPositionFromRegister(rdx, start_reg);  // Offset of start of capture
  ReadPositionFromRegister(rax, start_reg + 1);  // Offset of end of capture
  __ subq(rax, rdx);                             // Length to check.

  // At this point, the capture registers are either both set or both cleared.
  // If the capture length is zero, then the capture is either empty or cleared.
  // Fall through in both cases.
  __ j(equal, &fallthrough);

  // -----------------------
  // rdx - Start of capture
  // rax - length of capture
  // Check that there are sufficient characters left in the input.
  if (read_backward) {
    __ movl(rbx, Operand(rbp, kStringStartMinusOneOffset));
    __ addl(rbx, rax);
    __ cmpl(rdi, rbx);
    BranchOrBacktrack(less_equal, on_no_match);
  } else {
    __ movl(rbx, rdi);
    __ addl(rbx, rax);
    BranchOrBacktrack(greater, on_no_match);
  }

  // Compute pointers to match string and capture string
  __ leaq(rbx, Operand(rsi, rdi, times_1, 0));  // Start of match.
  if (read_backward) {
    __ subq(rbx, rax);  // Offset by length when matching backwards.
  }
  __ addq(rdx, rsi);                           // Start of capture.
  __ leaq(r9, Operand(rdx, rax, times_1, 0));  // End of capture

  // -----------------------
  // rbx - current capture character address.
  // rbx - current input character address .
  // r9 - end of input to match (capture length after rbx).

  Label loop;
  __ bind(&loop);
  if (mode_ == LATIN1) {
    __ movzxbl(rax, Operand(rdx, 0));
    __ cmpb(rax, Operand(rbx, 0));
  } else {
    DCHECK(mode_ == UC16);
    __ movzxwl(rax, Operand(rdx, 0));
    __ cmpw(rax, Operand(rbx, 0));
  }
  BranchOrBacktrack(not_equal, on_no_match);
  // Increment pointers into capture and match string.
  __ addq(rbx, Immediate(char_size()));
  __ addq(rdx, Immediate(char_size()));
  // Check if we have reached end of match area.
  __ cmpq(rdx, r9);
  __ j(below, &loop);

  // Success.
  // Set current character position to position after match.
  __ movq(rdi, rbx);
  __ subq(rdi, rsi);
  if (read_backward) {
    // Subtract match length if we matched backward.
    __ addq(rdi, register_location(start_reg));
    __ subq(rdi, register_location(start_reg + 1));
  }

  __ bind(&fallthrough);
}


void RegExpMacroAssemblerX64::CheckNotCharacter(uint32_t c,
                                                Label* on_not_equal) {
  __ cmpl(current_character(), Immediate(c));
  BranchOrBacktrack(not_equal, on_not_equal);
}


void RegExpMacroAssemblerX64::CheckCharacterAfterAnd(uint32_t c,
                                                     uint32_t mask,
                                                     Label* on_equal) {
  if (c == 0) {
    __ testl(current_character(), Immediate(mask));
  } else {
    __ Move(rax, mask);
    __ andq(rax, current_character());
    __ cmpl(rax, Immediate(c));
  }
  BranchOrBacktrack(equal, on_equal);
}


void RegExpMacroAssemblerX64::CheckNotCharacterAfterAnd(uint32_t c,
                                                        uint32_t mask,
                                                        Label* on_not_equal) {
  if (c == 0) {
    __ testl(current_character(), Immediate(mask));
  } else {
    __ Move(rax, mask);
    __ andq(rax, current_character());
    __ cmpl(rax, Immediate(c));
  }
  BranchOrBacktrack(not_equal, on_not_equal);
}

void RegExpMacroAssemblerX64::CheckNotCharacterAfterMinusAnd(
    base::uc16 c, base::uc16 minus, base::uc16 mask, Label* on_not_equal) {
  DCHECK_GT(String::kMaxUtf16CodeUnit, minus);
  __ leal(rax, Operand(current_character(), -minus));
  __ andl(rax, Immediate(mask));
  __ cmpl(rax, Immediate(c));
  BranchOrBacktrack(not_equal, on_not_equal);
}

void RegExpMacroAssemblerX64::CheckCharacterInRange(base::uc16 from,
                                                    base::uc16 to,
                                                    Label* on_in_range) {
  __ leal(rax, Operand(current_character(), -from));
  __ cmpl(rax, Immediate(to - from));
  BranchOrBacktrack(below_equal, on_in_range);
}

void RegExpMacroAssemblerX64::CheckCharacterNotInRange(base::uc16 from,
                                                       base::uc16 to,
                                                       Label* on_not_in_range) {
  __ leal(rax, Operand(current_character(), -from));
  __ cmpl(rax, Immediate(to - from));
  BranchOrBacktrack(above, on_not_in_range);
}

void RegExpMacroAssemblerX64::CallIsCharacterInRangeArray(
    const ZoneList<CharacterRange>* ranges) {
  PushCallerSavedRegisters();

  static const int kNumArguments = 2;
  __ PrepareCallCFunction(kNumArguments);

  __ Move(kCArgRegs[0], current_character());
  __ Move(kCArgRegs[1], GetOrAddRangeArray(ranges));

  {
    // We have a frame (set up in GetCode), but the assembler doesn't know.
    FrameScope scope(&masm_, StackFrame::MANUAL);
    CallCFunctionFromIrregexpCode(
        ExternalReference::re_is_character_in_range_array(), kNumArguments);
  }

  PopCallerSavedRegisters();
  __ Move(code_object_pointer(), masm_.CodeObject());
}

bool RegExpMacroAssemblerX64::CheckCharacterInRangeArray(
    const ZoneList<CharacterRange>* ranges, Label* on_in_range) {
  CallIsCharacterInRangeArray(ranges);
  __ testq(rax, rax);
  BranchOrBacktrack(not_zero, on_in_range);
  return true;
}

bool RegExpMacroAssemblerX64::CheckCharacterNotInRangeArray(
    const ZoneList<CharacterRange>* ranges, Label* on_not_in_range) {
  CallIsCharacterInRangeArray(ranges);
  __ testq(rax, rax);
  BranchOrBacktrack(zero, on_not_in_range);
  return true;
}

void RegExpMacroAssemblerX64::CheckBitInTable(
    Handle<ByteArray> table,
    Label* on_bit_set) {
  __ Move(rax, table);
  Register index = current_character();
  if (mode_ != LATIN1 || kTableMask != String::kMaxOneByteCharCode) {
    __ movq(rbx, current_character());
    __ andq(rbx, Immediate(kTableMask));
    index = rbx;
  }
  __ cmpb(FieldOperand(rax, index, times_1, OFFSET_OF_DATA_START(ByteArray)),
          Immediate(0));
  BranchOrBacktrack(not_equal, on_bit_set);
}

void RegExpMacroAssemblerX64::SkipUntilBitInTable(
    int cp_offset, Handle<ByteArray> table,
    Handle<ByteArray> nibble_table_array, int advance_by) {
  Label cont, scalar_repeat;

  const bool use_simd = SkipUntilBitInTableUseSimd(advance_by);
  if (use_simd) {
    DCHECK(!nibble_table_array.is_null());
    Label simd_repeat, found, scalar;
    static constexpr int kVectorSize = 16;
    const int kCharsPerVector = kVectorSize / char_size();

    // Fallback to scalar version if there are less than kCharsPerVector chars
    // left in the subject.
    // We subtract 1 because CheckPosition assumes we are reading 1 character
    // plus cp_offset. So the -1 is the the character that is assumed to be
    // read by default.
    CheckPosition(cp_offset + kCharsPerVector - 1, &scalar);

    // Load table and mask constants.
    // For a description of the table layout, check the comment on
    // BoyerMooreLookahead::GetSkipTable in regexp-compiler.cc.
    XMMRegister nibble_table = xmm0;
    __ Move(r11, nibble_table_array);
    __ Movdqu(nibble_table, FieldOperand(r11, OFFSET_OF_DATA_START(ByteArray)));
    XMMRegister nibble_mask = xmm1;
    __ Move(r11, 0x0f0f0f0f'0f0f0f0f);
    __ movq(nibble_mask, r11);
    __ Movddup(nibble_mask, nibble_mask);
    XMMRegister hi_nibble_lookup_mask = xmm2;
    __ Move(r11, 0x80402010'08040201);
    __ movq(hi_nibble_lookup_mask, r11);
    __ Movddup(hi_nibble_lookup_mask, hi_nibble_lookup_mask);

    Bind(&simd_repeat);
    // Load next characters into vector.
    XMMRegister input_vec = xmm3;
    __ Movdqu(input_vec, Operand(rsi, rdi, times_1, cp_offset));

    // Extract low nibbles.
    // lo_nibbles = input & 0x0f
    XMMRegister lo_nibbles = xmm4;
    if (CpuFeatures::IsSupported(AVX)) {
      __ Andps(lo_nibbles, nibble_mask, input_vec);
    } else {
      __ Movdqa(lo_nibbles, nibble_mask);
      __ Andps(lo_nibbles, lo_nibbles, input_vec);
    }
    // Extract high nibbles.
    // hi_nibbles = (input >> 4) & 0x0f
    __ Psrlw(input_vec, uint8_t{4});
    XMMRegister hi_nibbles = ReassignRegister(input_vec);
    __ Andps(hi_nibbles, hi_nibbles, nibble_mask);

    // Get rows of nibbles table based on low nibbles.
    // row = nibble_table[lo_nibbles]
    XMMRegister row = xmm5;
    __ Pshufb(row, nibble_table, lo_nibbles);

    // Check if high nibble is set in row.
    // bitmask = 1 << (hi_nibbles & 0x7)
    //         = hi_nibbles_lookup_mask[hi_nibbles] & 0x7
    // Note: The hi_nibbles & 0x7 part is implicitly executed, as pshufb sets
    // the result byte to zero if bit 7 is set in the source byte.
    XMMRegister bitmask = ReassignRegister(lo_nibbles);
    __ Pshufb(bitmask, hi_nibble_lookup_mask, hi_nibbles);

    // result = row & bitmask == bitmask
    XMMRegister result = ReassignRegister(row);
    __ Andps(result, result, bitmask);
    __ Pcmpeqb(result, result, bitmask);

    // Check if any bit is set.
    // Copy the most significant bit of each result byte to r11.
    __ Pmovmskb(r11, result);
    __ testl(r11, r11);
    __ j(not_zero, &found);

    // The maximum lookahead for boyer moore is less than vector size, so we can
    // ignore advance_by in the vectorized version.
    AdvanceCurrentPosition(kCharsPerVector);
    CheckPosition(cp_offset + kCharsPerVector - 1, &scalar);
    __ jmp(&simd_repeat);

    Bind(&found);
    // Extract position.
    __ bsfl(r11, r11);
    if (mode_ == UC16) {
      // Make sure that we skip an even number of bytes in 2-byte subjects.
      // Odd skips can happen if the higher byte produced a match.
      // False positives should be rare and are no problem in general, as the
      // following instructions will check for an exact match.
      __ andl(r11, Immediate(0xfffe));
    }
    __ addq(rdi, r11);
    __ jmp(&cont);
    Bind(&scalar);
  }

  // Scalar version.
  Register table_reg = r9;
  __ Move(table_reg, table);

  Bind(&scalar_repeat);
  CheckPosition(cp_offset, &cont);
  LoadCurrentCharacterUnchecked(cp_offset, 1);
  Register index = current_character();
  if (mode_ != LATIN1 || kTableMask != String::kMaxOneByteCharCode) {
    index = rbx;
    __ movq(index, current_character());
    __ andq(index, Immediate(kTableMask));
  }
  __ cmpb(
      FieldOperand(table_reg, index, times_1, OFFSET_OF_DATA_START(ByteArray)),
      Immediate(0));
  __ j(not_equal, &cont);
  AdvanceCurrentPosition(advance_by);
  __ jmp(&scalar_repeat);

  __ bind(&cont);
}

bool RegExpMacroAssemblerX64::SkipUntilBitInTableUseSimd(int advance_by) {
  // To use the SIMD variant we require SSSE3 as there is no shuffle equivalent
  // in older extensions.
  // In addition we only use SIMD instead of the scalar version if we advance by
  // 1 byte in each iteration. For higher values the scalar version performs
  // better.
  return v8_flags.regexp_simd && advance_by * char_size() == 1 &&
         CpuFeatures::IsSupported(SSSE3);
}

bool RegExpMacroAssemblerX64::CheckSpecialClassRanges(StandardCharacterSet type,
                                                      Label* on_no_match) {
  // Range checks (c in min..max) are generally implemented by an unsigned
  // (c - min) <= (max - min) check, using the sequence:
  //   leal(rax, Operand(current_character(), -min)) or sub(rax, Immediate(min))
  //   cmpl(rax, Immediate(max - min))
  // TODO(jgruber): No custom implementation (yet): s(UC16), S(UC16).
  switch (type) {
    case StandardCharacterSet::kWhitespace:
      // Match space-characters.
      if (mode_ == LATIN1) {
        // One byte space characters are '\t'..'\r', ' ' and \u00a0.
        Label success;
        __ cmpl(current_character(), Immediate(' '));
        __ j(equal, &success, Label::kNear);
        // Check range 0x09..0x0D.
        __ leal(rax, Operand(current_character(), -'\t'));
        __ cmpl(rax, Immediate('\r' - '\t'));
        __ j(below_equal, &success, Label::kNear);
        // \u00a0 (NBSP).
        __ cmpl(rax, Immediate(0x00A0 - '\t'));
        BranchOrBacktrack(not_equal, on_no_match);
        __ bind(&success);
        return true;
      }
      return false;
    case StandardCharacterSet::kNotWhitespace:
      // The emitted code for generic character classes is good enough.
      return false;
    case StandardCharacterSet::kDigit:
      // Match ASCII digits ('0'..'9').
      __ leal(rax, Operand(current_character(), -'0'));
      __ cmpl(rax, Immediate('9' - '0'));
      BranchOrBacktrack(above, on_no_match);
      return true;
    case StandardCharacterSet::kNotDigit:
      // Match non ASCII-digits.
      __ leal(rax, Operand(current_character(), -'0'));
      __ cmpl(rax, Immediate('9' - '0'));
      BranchOrBacktrack(below_equal, on_no_match);
      return true;
    case StandardCharacterSet::kNotLineTerminator: {
      // Match non-newlines (not 0x0A('\n'), 0x0D('\r'), 0x2028 and 0x2029).
      __ movl(rax, current_character());
      __ xorl(rax, Immediate(0x01));
      // See if current character is '\n'^1 or '\r'^1, i.e., 0x0B or 0x0C.
      __ subl(rax, Immediate(0x0B));
      __ cmpl(rax, Immediate(0x0C - 0x0B));
      BranchOrBacktrack(below_equal, on_no_match);
      if (mode_ == UC16) {
        // Compare original value to 0x2028 and 0x2029, using the already
        // computed (current_char ^ 0x01 - 0x0B). I.e., check for
        // 0x201D (0x2028 - 0x0B) or 0x201E.
        __ subl(rax, Immediate(0x2028 - 0x0B));
        __ cmpl(rax, Immediate(0x2029 - 0x2028));
        BranchOrBacktrack(below_equal, on_no_match);
      }
      return true;
    }
    case StandardCharacterSet::kLineTerminator: {
      // Match newlines (0x0A('\n'), 0x0D('\r'), 0x2028 and 0x2029).
      __ movl(rax, current_character());
      __ xorl(rax, Immediate(0x01));
      // See if current character is '\n'^1 or '\r'^1, i.e., 0x0B or 0x0C.
      __ subl(rax, Immediate(0x0B));
      __ cmpl(rax, Immediate(0x0C - 0x0B));
      if (mode_ == LATIN1) {
        BranchOrBacktrack(above, on_no_match);
      } else {
        Label done;
        BranchOrBacktrack(below_equal, &done);
        // Compare original value to 0x2028 and 0x2029, using the already
        // computed (current_char ^ 0x01 - 0x0B). I.e., check for
        // 0x201D (0x2028 - 0x0B) or 0x201E.
        __ subl(rax, Immediate(0x2028 - 0x0B));
        __ cmpl(rax, Immediate(0x2029 - 0x2028));
        BranchOrBacktrack(above, on_no_match);
        __ bind(&done);
      }
      return true;
    }
    case StandardCharacterSet::kWord: {
      if (mode_ != LATIN1) {
        // Table is 256 entries, so all Latin1 characters can be tested.
        __ cmpl(current_character(), Immediate('z'));
        BranchOrBacktrack(above, on_no_match);
      }
      __ Move(rbx, ExternalReference::re_word_character_map());
      DCHECK_EQ(0,
                word_character_map[0]);  // Character '\0' is not a word char.
      __ testb(Operand(rbx, current_character(), times_1, 0),
               current_character());
      BranchOrBacktrack(zero, on_no_match);
      return true;
    }
    case StandardCharacterSet::kNotWord: {
      Label done;
      if (mode_ != LATIN1) {
        // Table is 256 entries, so all Latin1 characters can be tested.
        __ cmpl(current_character(), Immediate('z'));
        __ j(above, &done);
      }
      __ Move(rbx, ExternalReference::re_word_character_map());
      DCHECK_EQ(0,
                word_character_map[0]);  // Character '\0' is not a word char.
      __ testb(Operand(rbx, current_character(), times_1, 0),
               current_character());
      BranchOrBacktrack(not_zero, on_no_match);
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

void RegExpMacroAssemblerX64::BindJumpTarget(Label* label) {
  Bind(label);
  // TODO(sroettger): There should be an endbr64 instruction here, but it needs
  // more thought how to avoid perf regressions.
}

void RegExpMacroAssemblerX64::Fail() {
  static_assert(FAILURE == 0);  // Return value for failure is zero.
  if (!global()) {
    __ Move(rax, FAILURE);
  }
  __ jmp(&exit_label_);
}

void RegExpMacroAssemblerX64::LoadRegExpStackPointerFromMemory(Register dst) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_stack_pointer(isolate());
  __ movq(dst, __ ExternalReferenceAsOperand(ref, dst));
}

void RegExpMacroAssemblerX64::StoreRegExpStackPointerToMemory(
    Register src, Register scratch) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_stack_pointer(isolate());
  __ movq(__ ExternalReferenceAsOperand(ref, scratch), src);
}

void RegExpMacroAssemblerX64::PushRegExpBasePointer(Register stack_pointer,
                                                    Register scratch) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ movq(scratch, __ ExternalReferenceAsOperand(ref, scratch));
  __ subq(scratch, stack_pointer);
  __ movq(Operand(rbp, kRegExpStackBasePointerOffset), scratch);
}

void RegExpMacroAssemblerX64::PopRegExpBasePointer(Register stack_pointer_out,
                                                   Register scratch) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_memory
"""


```