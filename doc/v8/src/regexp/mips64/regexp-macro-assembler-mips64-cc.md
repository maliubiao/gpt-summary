Response:
The user wants a summary of the provided C++ code snippet. I need to identify the key functionalities of the `regexp-macro-assembler-mips64.cc` file within the V8 JavaScript engine.

Here's a breakdown of the thought process:

1. **Identify the Core Purpose:** The file name and the namespace `v8::internal` and the subdirectory `regexp/mips64` clearly indicate this code is related to regular expression matching, specifically for the MIPS64 architecture. The class `RegExpMacroAssemblerMIPS` confirms this.

2. **Analyze the Included Headers:** The included headers provide clues about the functionalities:
    * `"src/regexp/mips64/regexp-macro-assembler-mips64.h"`:  The header file for this implementation, likely containing class declarations and other definitions.
    * `"src/codegen/macro-assembler.h"`:  Indicates the use of a macro assembler for generating machine code.
    * `"src/codegen/mips64/assembler-mips64-inl.h"`: MIPS64 specific assembly instructions.
    * `"src/heap/factory.h"`, `"src/logging/log.h"`, `"src/objects/code-inl.h"`:  Interaction with V8's heap, logging, and code objects.
    * `"src/regexp/regexp-stack.h"`:  Manages the stack used for backtracking in regular expression matching.
    * `"src/snapshot/embedded/embedded-data-inl.h"`: Potentially related to embedding data within the generated code.

3. **Examine the Register Assignment Convention:**  This section is crucial. It outlines how registers are used during regular expression matching. Key registers are assigned specific roles:
    * `s1`: Instruction stream.
    * `s2`: Current position in the input string.
    * `s5`: Currently loaded character.
    * `s6`: Backtrack stack pointer.
    * `s7`: End of input.
    * `fp`: Frame pointer (important for accessing arguments and local variables).
    * `sp`: Stack pointer.
    Understanding these assignments is fundamental to understanding the generated code's logic.

4. **Analyze the Stack Layout:** The description of the O32 and N64 stack frames reveals how arguments, local variables, and RegExp registers are organized on the stack. This is important for how the macro assembler accesses and manipulates data. Key data points stored on the stack include:
    * Isolate pointer.
    * Direct call flag.
    * Backtrack stack base.
    * Capture array information.
    * Input string details (start, end, index).
    * Success counter (for global regexps).
    * Capture registers.

5. **Review the Constructor and Destructor:** The constructor initializes the macro assembler, sets up initial labels, and handles potential internal failures. The destructor cleans up unused labels.

6. **Go Through the Public Methods:**  The methods within the class define the core operations of the regular expression macro assembler. Key functionalities include:
    * **Position Manipulation:** `AdvanceCurrentPosition`, `AdvanceRegister`.
    * **Backtracking:** `Backtrack`.
    * **Label Management:** `Bind`.
    * **Character Checking:** `CheckCharacter`, `CheckCharacterGT`, `CheckCharacterLT`, `CheckNotCharacter`, `CheckCharacterAfterAnd`, `CheckNotCharacterAfterAnd`, `CheckNotCharacterAfterMinusAnd`, `CheckCharacterInRange`, `CheckCharacterNotInRange`.
    * **Start/End of Input Checks:** `CheckAtStart`, `CheckNotAtStart`.
    * **Backreference Handling:** `CheckNotBackReference`, `CheckNotBackReferenceIgnoreCase`.
    * **Greedy Loop Check:** `CheckGreedyLoop`.
    * **Character Class Checks:** `CheckCharacterInRangeArray`, `CheckCharacterNotInRangeArray`, `CheckBitInTable`, `SkipUntilBitInTable`, `CheckSpecialClassRanges`.
    * **Failure:** `Fail`.
    * **Stack Management:** `LoadRegExpStackPointerFromMemory`, `StoreRegExpStackPointerToMemory`, `PushRegExpBasePointer`, `PopRegExpBasePointer`.
    * **Code Generation:** `GetCode`.

7. **Identify Key Concepts:** Several recurring themes emerge:
    * **Macro Assembler:** The code heavily relies on a macro assembler to generate MIPS64 machine code.
    * **Backtracking:**  A central mechanism for exploring different matching possibilities in regular expressions.
    * **Capture Registers:** Used to store the matched portions of the input string.
    * **Stack Management:** Careful manipulation of the stack is essential for managing state during matching.
    * **Performance Optimization:** The register assignments and stack layout are designed for efficiency.

8. **Synthesize the Information:** Combine the observations into a concise summary of the file's functionality. Emphasize the core responsibility of generating MIPS64 machine code for regular expression matching within the V8 engine. Highlight key aspects like register usage, stack management, and the various checking and manipulation operations.
这是 V8 JavaScript 引擎中用于在 MIPS64 架构上执行正则表达式匹配的宏汇编器源代码。

**功能归纳:**

这个文件 (`v8/src/regexp/mips64/regexp-macro-assembler-mips64.cc`) 的主要功能是：

1. **生成 MIPS64 架构的机器码:** 它使用宏汇编器 (`MacroAssembler`) 来生成用于执行正则表达式匹配的底层机器指令。这是 V8 执行正则表达式的核心部分，因为它将高级的正则表达式操作转化为 CPU 可以理解的指令。

2. **实现正则表达式匹配的各种操作:**  文件中包含大量的方法，对应于正则表达式匹配过程中的各种步骤和检查，例如：
    * **字符检查:** 检查当前字符是否与特定字符或字符范围匹配 (`CheckCharacter`, `CheckCharacterInRange` 等)。
    * **位置管理:** 维护和更新当前在输入字符串中的位置 (`AdvanceCurrentPosition`).
    * **回溯:**  实现正则表达式引擎的回溯机制，当匹配失败时返回到之前的状态 (`Backtrack`).
    * **捕获组管理:**  处理捕获组的开始和结束位置 (`AdvanceRegister`).
    * **边界条件检查:** 检查是否到达字符串的开始或结束 (`CheckAtStart`, `CheckNotAtStart`).
    * **反向引用:**  检查当前位置的字符串是否与之前捕获的组匹配 (`CheckNotBackReference`, `CheckNotBackReferenceIgnoreCase`).
    * **字符类检查:** 检查字符是否属于预定义的字符类（例如，数字、空格、单词字符等）(`CheckSpecialClassRanges`).
    * **栈管理:**  管理用于回溯的栈 (`Push`, `Pop`).
    * **性能优化:**  使用特定的 MIPS64 指令并优化常见的正则表达式操作。

3. **定义寄存器使用约定:** 文件开头详细说明了各个寄存器在正则表达式匹配过程中的作用，这对于理解生成的汇编代码至关重要。例如，`s2` 存储当前输入位置，`s5` 存储当前加载的字符，`s6` 指向回溯栈的栈顶。

4. **定义栈帧结构:**  描述了在调用正则表达式匹配代码时，栈的布局，包括参数、局部变量和正则表达式寄存器的存储位置。这对于正确地传递参数和访问数据至关重要。

5. **处理栈溢出和抢占:** 代码中包含了检查栈空间是否足够，以及处理 JavaScript 执行被抢占的情况。

**关于 .tq 结尾：**

如果 `v8/src/regexp/mips64/regexp-macro-assembler-mips64.cc` 以 `.tq` 结尾，那么它将是 **V8 Torque 源代码**。 Torque 是一种 V8 内部的领域特定语言，用于生成高效的 C++ 代码，通常用于实现内置函数和运行时代码。  当前的 `.cc` 结尾表明它是直接用 C++ 编写的。

**与 JavaScript 功能的关系 (示例):**

这个文件中的代码直接支撑了 JavaScript 中正则表达式的功能。当你执行一个正则表达式匹配操作时，V8 会编译该正则表达式，并可能使用这个文件中的宏汇编器来生成执行匹配的机器码。

**JavaScript 示例:**

```javascript
const regex = /ab+c/g;
const str = 'abbc abc abbbbc';
let array;

while ((array = regex.exec(str)) !== null) {
  console.log(`Found ${array[0]}. Next starts at ${regex.lastIndex}.`);
  // Expected output: "Found abbc. Next starts at 4."
  // Expected output: "Found abc. Next starts at 8."
  // Expected output: "Found abbbbc. Next starts at 15."
}
```

在这个例子中，当你调用 `regex.exec(str)` 时，V8 会使用其正则表达式引擎来执行匹配。  如果引擎决定使用基于 MIPS64 的优化代码，那么 `regexp-macro-assembler-mips64.cc` 中生成的机器码就会被调用来完成实际的匹配工作。  例如，当匹配 `b+` 时，该文件中的代码可能会生成循环指令来检查连续的 `b` 字符。

**代码逻辑推理 (假设输入与输出):**

假设我们有一个简单的正则表达式 `/a/` 和输入字符串 `"banana"`，并且我们从索引 1 开始匹配。

**假设输入:**

* 正则表达式: `/a/`
* 输入字符串: `"banana"`
* 起始索引: 1

**代码逻辑推理 (简化):**

1. **加载当前字符:**  代码会加载输入字符串索引 1 处的字符，即 `'a'`。
2. **字符检查:**  代码会执行 `CheckCharacter` 类似的操作，将加载的字符 `'a'` 与正则表达式中的字符 `'a'` 进行比较。
3. **匹配成功:** 由于字符匹配，匹配成功。
4. **更新位置:**  当前位置会移动到下一个字符的索引 (2)。
5. **输出 (可能的内部状态):** 捕获组 0 的起始位置为 1，结束位置为 2。

**用户常见的编程错误 (与正则表达式相关):**

一个常见的编程错误是 **忘记转义正则表达式中的特殊字符**。

**示例:**

```javascript
const str = "Is there a file named a.txt?";
const regex = /a.txt/; // 意图匹配 "a.txt"
const match = str.match(regex);
console.log(match); // 输出: ["a.txt", index: 21, input: "Is there a file named a.txt?", groups: undefined]
```

在这个例子中，`.` 在正则表达式中是一个特殊字符，表示匹配任意单个字符。用户可能希望匹配字面上的句点 `.`，但由于没有转义，正则表达式会匹配例如 "axt" 或 "a!txt"。  正确的写法应该是 `/a\.txt/`。  `regexp-macro-assembler-mips64.cc` 中生成的代码会忠实地执行这个（可能错误的）正则表达式。

**总结它的功能 (第 1 部分):**

`v8/src/regexp/mips64/regexp-macro-assembler-mips64.cc` 的主要功能是 **作为 V8 JavaScript 引擎的一部分，负责生成在 MIPS64 架构上高效执行正则表达式匹配的底层机器代码。** 它定义了寄存器使用约定、栈帧结构，并实现了各种用于字符检查、位置管理、回溯和捕获组处理的汇编级别的操作。 这个文件是 V8 正则表达式功能高性能实现的关键组成部分。

Prompt: 
```
这是目录为v8/src/regexp/mips64/regexp-macro-assembler-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/mips64/regexp-macro-assembler-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if V8_TARGET_ARCH_MIPS64

#include "src/regexp/mips64/regexp-macro-assembler-mips64.h"

#include "src/codegen/macro-assembler.h"
#include "src/codegen/mips64/assembler-mips64-inl.h"
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
 * TODO(plind): O32 documented here with intent of having single 32/64 codebase
 *              in the future.
 *
 * The O32 stack will have the following structure:
 *
 *  - fp[72]  Isolate* isolate   (address of the current isolate)
 *  - fp[68]  direct_call  (if 1, direct call from JavaScript code,
 *                          if 0, call through the runtime system).
 *  - fp[64]  stack_area_base (High end of the memory area to use as
 *                             backtracking stack).
 *  - fp[60]  capture array size (may fit multiple sets of matches)
 *  - fp[44..59]  MIPS O32 four argument slots
 *  - fp[40]  int* capture_array (int[num_saved_registers_], for output).
 *  --- sp when called ---
 *  - fp[36]  return address      (lr).
 *  - fp[32]  old frame pointer   (r11).
 *  - fp[0..31]  backup of registers s0..s7.
 *  --- frame pointer ----
 *  - fp[-4]  end of input       (address of end of string).
 *  - fp[-8]  start of input     (address of first character in string).
 *  - fp[-12] start index        (character index of start).
 *  - fp[-16] void* input_string (location of a handle containing the string).
 *  - fp[-20] success counter    (only for global regexps to count matches).
 *  - fp[-24] Offset of location before start of input (effectively character
 *            string start - 1). Used to initialize capture registers to a
 *            non-position.
 *  - fp[-28] At start (if 1, we are starting at the start of the
 *    string, otherwise 0)
 *  - fp[-32] register 0         (Only positions must be stored in the first
 *  -         register 1          num_saved_registers_ registers)
 *  -         ...
 *  -         register num_registers-1
 *  --- sp ---
 *
 *
 * The N64 stack will have the following structure:
 *
 *  - fp[80]  Isolate* isolate   (address of the current isolate)               kIsolate
 *                                                                              kStackFrameHeader
 *  --- sp when called ---
 *  - fp[72]  ra                 Return from RegExp code (ra).                  kReturnAddress
 *  - fp[64]  s9, old-fp         Old fp, callee saved(s9).
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
 *  - fp[-80] Offset of location before start of input (effectively character   kStringStartMinusOneOffset
 *            position -1). Used to initialize capture registers to a
 *            non-position.
 *  --------- The following output registers are 32-bit values. ---------
 *  - fp[-88] register 0         (Only positions must be stored in the first    kRegisterZero
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

RegExpMacroAssemblerMIPS::RegExpMacroAssemblerMIPS(Isolate* isolate, Zone* zone,
                                                   Mode mode,
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
  __ jmp(&entry_label_);   // We'll write the entry code later.
  // If the code gets too big or corrupted, an internal exception will be
  // raised, and we will exit right away.
  __ bind(&internal_failure_label_);
  __ li(v0, Operand(FAILURE));
  __ Ret();
  __ bind(&start_label_);  // And then continue from here.
}

RegExpMacroAssemblerMIPS::~RegExpMacroAssemblerMIPS() {
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

int RegExpMacroAssemblerMIPS::stack_limit_slack_slot_count() {
  return RegExpStack::kStackLimitSlackSlotCount;
}

void RegExpMacroAssemblerMIPS::AdvanceCurrentPosition(int by) {
  if (by != 0) {
    __ Daddu(current_input_offset(),
            current_input_offset(), Operand(by * char_size()));
  }
}


void RegExpMacroAssemblerMIPS::AdvanceRegister(int reg, int by) {
  DCHECK_LE(0, reg);
  DCHECK_GT(num_registers_, reg);
  if (by != 0) {
    __ Ld(a0, register_location(reg));
    __ Daddu(a0, a0, Operand(by));
    __ Sd(a0, register_location(reg));
  }
}


void RegExpMacroAssemblerMIPS::Backtrack() {
  CheckPreemption();
  if (has_backtrack_limit()) {
    Label next;
    __ Ld(a0, MemOperand(frame_pointer(), kBacktrackCountOffset));
    __ Daddu(a0, a0, Operand(1));
    __ Sd(a0, MemOperand(frame_pointer(), kBacktrackCountOffset));
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
  __ Daddu(a0, a0, code_pointer());
  __ Jump(a0);
}


void RegExpMacroAssemblerMIPS::Bind(Label* label) {
  __ bind(label);
}


void RegExpMacroAssemblerMIPS::CheckCharacter(uint32_t c, Label* on_equal) {
  BranchOrBacktrack(on_equal, eq, current_character(), Operand(c));
}

void RegExpMacroAssemblerMIPS::CheckCharacterGT(base::uc16 limit,
                                                Label* on_greater) {
  BranchOrBacktrack(on_greater, gt, current_character(), Operand(limit));
}

void RegExpMacroAssemblerMIPS::CheckAtStart(int cp_offset, Label* on_at_start) {
  __ Ld(a1, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
  __ Daddu(a0, current_input_offset(),
           Operand(-char_size() + cp_offset * char_size()));
  BranchOrBacktrack(on_at_start, eq, a0, Operand(a1));
}


void RegExpMacroAssemblerMIPS::CheckNotAtStart(int cp_offset,
                                               Label* on_not_at_start) {
  __ Ld(a1, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
  __ Daddu(a0, current_input_offset(),
           Operand(-char_size() + cp_offset * char_size()));
  BranchOrBacktrack(on_not_at_start, ne, a0, Operand(a1));
}

void RegExpMacroAssemblerMIPS::CheckCharacterLT(base::uc16 limit,
                                                Label* on_less) {
  BranchOrBacktrack(on_less, lt, current_character(), Operand(limit));
}

void RegExpMacroAssemblerMIPS::CheckGreedyLoop(Label* on_equal) {
  Label backtrack_non_equal;
  __ Lw(a0, MemOperand(backtrack_stackpointer(), 0));
  __ Branch(&backtrack_non_equal, ne, current_input_offset(), Operand(a0));
  __ Daddu(backtrack_stackpointer(),
          backtrack_stackpointer(),
          Operand(kIntSize));
  __ bind(&backtrack_non_equal);
  BranchOrBacktrack(on_equal, eq, current_input_offset(), Operand(a0));
}

void RegExpMacroAssemblerMIPS::CheckNotBackReferenceIgnoreCase(
    int start_reg, bool read_backward, bool unicode, Label* on_no_match) {
  Label fallthrough;
  __ Ld(a0, register_location(start_reg));      // Index of start of capture.
  __ Ld(a1, register_location(start_reg + 1));  // Index of end of capture.
  __ Dsubu(a1, a1, a0);  // Length of capture.

  // At this point, the capture registers are either both set or both cleared.
  // If the capture length is zero, then the capture is either empty or cleared.
  // Fall through in both cases.
  __ Branch(&fallthrough, eq, a1, Operand(zero_reg));

  if (read_backward) {
    __ Ld(t1, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
    __ Daddu(t1, t1, a1);
    BranchOrBacktrack(on_no_match, le, current_input_offset(), Operand(t1));
  } else {
    __ Daddu(t1, a1, current_input_offset());
    // Check that there are enough characters left in the input.
    BranchOrBacktrack(on_no_match, gt, t1, Operand(zero_reg));
  }

  if (mode_ == LATIN1) {
    Label success;
    Label fail;
    Label loop_check;

    // a0 - offset of start of capture.
    // a1 - length of capture.
    __ Daddu(a0, a0, Operand(end_of_input_address()));
    __ Daddu(a2, end_of_input_address(), Operand(current_input_offset()));
    if (read_backward) {
      __ Dsubu(a2, a2, Operand(a1));
    }
    __ Daddu(a1, a0, Operand(a1));

    // a0 - Address of start of capture.
    // a1 - Address of end of capture.
    // a2 - Address of current input position.

    Label loop;
    __ bind(&loop);
    __ Lbu(a3, MemOperand(a0, 0));
    __ daddiu(a0, a0, char_size());
    __ Lbu(a4, MemOperand(a2, 0));
    __ daddiu(a2, a2, char_size());

    __ Branch(&loop_check, eq, a4, Operand(a3));

    // Mismatch, try case-insensitive match (converting letters to lower-case).
    __ Or(a3, a3, Operand(0x20));  // Convert capture character to lower-case.
    __ Or(a4, a4, Operand(0x20));  // Also convert input character.
    __ Branch(&fail, ne, a4, Operand(a3));
    __ Dsubu(a3, a3, Operand('a'));
    __ Branch(&loop_check, ls, a3, Operand('z' - 'a'));
    // Latin-1: Check for values in range [224,254] but not 247.
    __ Dsubu(a3, a3, Operand(224 - 'a'));
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
    __ Dsubu(current_input_offset(), a2, end_of_input_address());
    if (read_backward) {
      __ Ld(t1, register_location(start_reg));  // Index of start of capture.
      __ Ld(a2, register_location(start_reg + 1));  // Index of end of capture.
      __ Daddu(current_input_offset(), current_input_offset(), Operand(t1));
      __ Dsubu(current_input_offset(), current_input_offset(), Operand(a2));
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
    __ Daddu(a0, a0, Operand(end_of_input_address()));
    // Length of capture.
    __ mov(a2, a1);
    // Save length in callee-save register for use on return.
    __ mov(s3, a1);
    // Address of current input position.
    __ Daddu(a1, current_input_offset(), Operand(end_of_input_address()));
    if (read_backward) {
      __ Dsubu(a1, a1, Operand(s3));
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
    BranchOrBacktrack(on_no_match, eq, v0, Operand(zero_reg));
    // On success, increment position by length of capture.
    if (read_backward) {
      __ Dsubu(current_input_offset(), current_input_offset(), Operand(s3));
    } else {
      __ Daddu(current_input_offset(), current_input_offset(), Operand(s3));
    }
  }

  __ bind(&fallthrough);
}

void RegExpMacroAssemblerMIPS::CheckNotBackReference(int start_reg,
                                                     bool read_backward,
                                                     Label* on_no_match) {
  Label fallthrough;

  // Find length of back-referenced capture.
  __ Ld(a0, register_location(start_reg));
  __ Ld(a1, register_location(start_reg + 1));
  __ Dsubu(a1, a1, a0);  // Length to check.

  // At this point, the capture registers are either both set or both cleared.
  // If the capture length is zero, then the capture is either empty or cleared.
  // Fall through in both cases.
  __ Branch(&fallthrough, eq, a1, Operand(zero_reg));

  if (read_backward) {
    __ Ld(t1, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
    __ Daddu(t1, t1, a1);
    BranchOrBacktrack(on_no_match, le, current_input_offset(), Operand(t1));
  } else {
    __ Daddu(t1, a1, current_input_offset());
    // Check that there are enough characters left in the input.
    BranchOrBacktrack(on_no_match, gt, t1, Operand(zero_reg));
  }

  // Compute pointers to match string and capture string.
  __ Daddu(a0, a0, Operand(end_of_input_address()));
  __ Daddu(a2, end_of_input_address(), Operand(current_input_offset()));
  if (read_backward) {
    __ Dsubu(a2, a2, Operand(a1));
  }
  __ Daddu(a1, a1, Operand(a0));

  Label loop;
  __ bind(&loop);
  if (mode_ == LATIN1) {
    __ Lbu(a3, MemOperand(a0, 0));
    __ daddiu(a0, a0, char_size());
    __ Lbu(a4, MemOperand(a2, 0));
    __ daddiu(a2, a2, char_size());
  } else {
    DCHECK(mode_ == UC16);
    __ Lhu(a3, MemOperand(a0, 0));
    __ daddiu(a0, a0, char_size());
    __ Lhu(a4, MemOperand(a2, 0));
    __ daddiu(a2, a2, char_size());
  }
  BranchOrBacktrack(on_no_match, ne, a3, Operand(a4));
  __ Branch(&loop, lt, a0, Operand(a1));

  // Move current character position to position after match.
  __ Dsubu(current_input_offset(), a2, end_of_input_address());
  if (read_backward) {
    __ Ld(t1, register_location(start_reg));      // Index of start of capture.
    __ Ld(a2, register_location(start_reg + 1));  // Index of end of capture.
    __ Daddu(current_input_offset(), current_input_offset(), Operand(t1));
    __ Dsubu(current_input_offset(), current_input_offset(), Operand(a2));
  }
  __ bind(&fallthrough);
}


void RegExpMacroAssemblerMIPS::CheckNotCharacter(uint32_t c,
                                                 Label* on_not_equal) {
  BranchOrBacktrack(on_not_equal, ne, current_character(), Operand(c));
}


void RegExpMacroAssemblerMIPS::CheckCharacterAfterAnd(uint32_t c,
                                                      uint32_t mask,
                                                      Label* on_equal) {
  __ And(a0, current_character(), Operand(mask));
  Operand rhs = (c == 0) ? Operand(zero_reg) : Operand(c);
  BranchOrBacktrack(on_equal, eq, a0, rhs);
}


void RegExpMacroAssemblerMIPS::CheckNotCharacterAfterAnd(uint32_t c,
                                                         uint32_t mask,
                                                         Label* on_not_equal) {
  __ And(a0, current_character(), Operand(mask));
  Operand rhs = (c == 0) ? Operand(zero_reg) : Operand(c);
  BranchOrBacktrack(on_not_equal, ne, a0, rhs);
}

void RegExpMacroAssemblerMIPS::CheckNotCharacterAfterMinusAnd(
    base::uc16 c, base::uc16 minus, base::uc16 mask, Label* on_not_equal) {
  DCHECK_GT(String::kMaxUtf16CodeUnit, minus);
  __ Dsubu(a0, current_character(), Operand(minus));
  __ And(a0, a0, Operand(mask));
  BranchOrBacktrack(on_not_equal, ne, a0, Operand(c));
}

void RegExpMacroAssemblerMIPS::CheckCharacterInRange(base::uc16 from,
                                                     base::uc16 to,
                                                     Label* on_in_range) {
  __ Dsubu(a0, current_character(), Operand(from));
  // Unsigned lower-or-same condition.
  BranchOrBacktrack(on_in_range, ls, a0, Operand(to - from));
}

void RegExpMacroAssemblerMIPS::CheckCharacterNotInRange(
    base::uc16 from, base::uc16 to, Label* on_not_in_range) {
  __ Dsubu(a0, current_character(), Operand(from));
  // Unsigned higher condition.
  BranchOrBacktrack(on_not_in_range, hi, a0, Operand(to - from));
}

void RegExpMacroAssemblerMIPS::CallIsCharacterInRangeArray(
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

bool RegExpMacroAssemblerMIPS::CheckCharacterInRangeArray(
    const ZoneList<CharacterRange>* ranges, Label* on_in_range) {
  CallIsCharacterInRangeArray(ranges);
  BranchOrBacktrack(on_in_range, ne, v0, Operand(zero_reg));
  return true;
}

bool RegExpMacroAssemblerMIPS::CheckCharacterNotInRangeArray(
    const ZoneList<CharacterRange>* ranges, Label* on_not_in_range) {
  CallIsCharacterInRangeArray(ranges);
  BranchOrBacktrack(on_not_in_range, eq, v0, Operand(zero_reg));
  return true;
}

void RegExpMacroAssemblerMIPS::CheckBitInTable(
    Handle<ByteArray> table,
    Label* on_bit_set) {
  __ li(a0, Operand(table));
  if (mode_ != LATIN1 || kTableMask != String::kMaxOneByteCharCode) {
    __ And(a1, current_character(), Operand(kTableSize - 1));
    __ Daddu(a0, a0, a1);
  } else {
    __ Daddu(a0, a0, current_character());
  }

  __ Lbu(a0, FieldMemOperand(a0, OFFSET_OF_DATA_START(ByteArray)));
  BranchOrBacktrack(on_bit_set, ne, a0, Operand(zero_reg));
}

void RegExpMacroAssemblerMIPS::SkipUntilBitInTable(
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

bool RegExpMacroAssemblerMIPS::CheckSpecialClassRanges(
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
        __ Dsubu(a0, current_character(), Operand('\t'));
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
      __ Dsubu(a0, current_character(), Operand('0'));
      BranchOrBacktrack(on_no_match, hi, a0, Operand('9' - '0'));
      return true;
    case StandardCharacterSet::kNotDigit:
      // Match non Latin1-digits.
      __ Dsubu(a0, current_character(), Operand('0'));
      BranchOrBacktrack(on_no_match, ls, a0, Operand('9' - '0'));
      return true;
    case StandardCharacterSet::kNotLineTerminator: {
      // Match non-newlines (not 0x0A('\n'), 0x0D('\r'), 0x2028 and 0x2029).
      __ Xor(a0, current_character(), Operand(0x01));
      // See if current character is '\n'^1 or '\r'^1, i.e., 0x0B or 0x0C.
      __ Dsubu(a0, a0, Operand(0x0B));
      BranchOrBacktrack(on_no_match, ls, a0, Operand(0x0C - 0x0B));
      if (mode_ == UC16) {
        // Compare original value to 0x2028 and 0x2029, using the already
        // computed (current_char ^ 0x01 - 0x0B). I.e., check for
        // 0x201D (0x2028 - 0x0B) or 0x201E.
        __ Dsubu(a0, a0, Operand(0x2028 - 0x0B));
        BranchOrBacktrack(on_no_match, ls, a0, Operand(1));
      }
      return true;
    }
    case StandardCharacterSet::kLineTerminator: {
      // Match newlines (0x0A('\n'), 0x0D('\r'), 0x2028 and 0x2029).
      __ Xor(a0, current_character(), Operand(0x01));
      // See if current character is '\n'^1 or '\r'^1, i.e., 0x0B or 0x0C.
      __ Dsubu(a0, a0, Operand(0x0B));
      if (mode_ == LATIN1) {
        BranchOrBacktrack(on_no_match, hi, a0, Operand(0x0C - 0x0B));
      } else {
        Label done;
        BranchOrBacktrack(&done, ls, a0, Operand(0x0C - 0x0B));
        // Compare original value to 0x2028 and 0x2029, using the already
        // computed (current_char ^ 0x01 - 0x0B). I.e., check for
        // 0x201D (0x2028 - 0x0B) or 0x201E.
        __ Dsubu(a0, a0, Operand(0x2028 - 0x0B));
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
      __ Daddu(a0, a0, current_character());
      __ Lbu(a0, MemOperand(a0, 0));
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
      __ Daddu(a0, a0, current_character());
      __ Lbu(a0, MemOperand(a0, 0));
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

void RegExpMacroAssemblerMIPS::Fail() {
  __ li(v0, Operand(FAILURE));
  __ jmp(&exit_label_);
}

void RegExpMacroAssemblerMIPS::LoadRegExpStackPointerFromMemory(Register dst) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_stack_pointer(isolate());
  __ li(dst, Operand(ref));
  __ Ld(dst, MemOperand(dst));
}

void RegExpMacroAssemblerMIPS::StoreRegExpStackPointerToMemory(
    Register src, Register scratch) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_stack_pointer(isolate());
  __ li(scratch, Operand(ref));
  __ Sd(src, MemOperand(scratch));
}

void RegExpMacroAssemblerMIPS::PushRegExpBasePointer(Register stack_pointer,
                                                     Register scratch) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ li(scratch, Operand(ref));
  __ Ld(scratch, MemOperand(scratch));
  __ Dsubu(scratch, stack_pointer, scratch);
  __ Sd(scratch, MemOperand(frame_pointer(), kRegExpStackBasePointerOffset));
}

void RegExpMacroAssemblerMIPS::PopRegExpBasePointer(Register stack_pointer_out,
                                                    Register scratch) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ Ld(stack_pointer_out,
        MemOperand(frame_pointer(), kRegExpStackBasePointerOffset));
  __ li(scratch, Operand(ref));
  __ Ld(scratch, MemOperand(scratch));
  __ Daddu(stack_pointer_out, stack_pointer_out, scratch);
  StoreRegExpStackPointerToMemory(stack_pointer_out, scratch);
}

Handle<HeapObject> RegExpMacroAssemblerMIPS::GetCode(Handle<String> source,
                                                     RegExpFlags flags) {
  Label return_v0;
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

    // Tell the system that we have a stack frame.  Because the type is MANUAL,
    // no is generated.
    FrameScope scope(masm_.get(), StackFrame::MANUAL);

    // Emit code to start a new stack frame. In the following we push all
    // callee-save registers (these end up above the fp) and all register
    // arguments (in {a0,a1,a2,a3}, these end up below the fp).
    // TODO(plind): we save s0..s7, but ONLY use s3 here - use the regs
    // or dont save.
    RegList registers_to_retain = {s0, s1, s2, s3, s4, s5, s6, s7, fp};

    __ MultiPush(registers_to_retain | ra);
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
    __ push(a0);  // Make room for success counter and initialize it to 0.
    static_assert(kStringStartMinusOneOffset ==
                  kSuccessfulCapturesOffset - kSystemPointerSize);
    __ push(a0);  // Make room for "string start - 1" constant.
    static_assert(kBacktrackCountOffset ==
                  kStringStartMinusOneOffset - kSystemPointerSize);
    __ push(a0);  // The backtrack counter
    static_assert(kRegExpStackBasePointerOffset ==
                  kBacktrackCountOffset - kSystemPointerSize);
    __ push(a0);  // The regexp stack base ptr.

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
      Operand extra_space_for_variables(num_registers_ * kPointerSize);

      __ li(a0, Operand(stack_limit));
      __ Ld(a0, MemOperand(a0));
      __ Dsubu(a0, sp, a0);
      // Handle it if the stack pointer is already below the stack limit.
      __ Branch(&stack_limit_hit, le, a0, Operand(zero_reg));
      // Check if there is room for the variable number of registers above
      // the stack limit.
      __ Branch(&stack_ok, hs, a0, extra_space_for_variables);
      // Exit with OutOfMemory exception. There is not enough space on the stack
      // for our working registers.
      __ li(v0, Operand(EXCEPTION));
      __ jmp(&return_v0);

      __ bind(&stack_limit_hit);
      CallCheckStackGuardState(a0, extra_space_for_variables);
      // If returned value is non-zero, we exit with the returned value as
      // result.
      __ Branch(&return_v0, ne, v0, Operand(zero_reg));

      __ bind(&stack_ok);
    }

    // Allocate space on stack for registers.
    __ Dsubu(sp, sp, Operand(num_registers_ * kPointerSize));
    // Load string end.
    __ Ld(end_of_input_address(), MemOperand(frame_pointer(), kInputEndOffset));
    // Load input start.
    __ Ld(a0, MemOperand(frame_pointer(), kInputStartOffset));
    // Find negative length (offset of start relative to end).
    __ Dsubu(current_input_offset(), a0, end_of_input_address());
    // Set a0 to address of char before start of the input string
    // (effectively string position -1).
    __ Ld(a1, MemOperand(frame_pointer(), kStartIndexOffset));
    __ Dsubu(a0, current_input_offset(), Operand(char_size()));
    __ dsll(t1, a1, (mode_ == UC16) ? 1 : 0);
    __ Dsubu(a0, a0, t1);
    // Store this value in a local variable, for use when clearing
    // position registers.
    __ Sd(a0, MemOperand(frame_pointer(), kStringStartMinusOneOffset));

    // Initialize code pointer register
    __ li(code_pointer(), Operand(masm_->CodeObject()), CONSTANT_SIZE);

    Label l
"""


```