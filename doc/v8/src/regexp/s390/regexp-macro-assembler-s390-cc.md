Response:
The user wants a summary of the provided C++ code snippet. The code is part of the V8 JavaScript engine and specifically deals with regular expression matching on the s390 architecture.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Purpose:** The file name `regexp-macro-assembler-s390.cc` immediately suggests that this code is responsible for assembling machine code for regular expression matching on the s390 architecture. The "macro assembler" part implies it provides a higher-level interface for generating these instructions.

2. **Analyze the Header Comments:** The initial comments provide essential context:
    * Copyright information.
    * Indication that the code is specific to the s390x architecture.
    * Includes of relevant V8 headers (assembler, heap objects, regexp components).

3. **Examine Register Assignments:** The detailed register assignment section is crucial. It reveals how the assembler uses various registers for specific purposes during regex matching (e.g., input position, current character, backtrack stack). This is key to understanding the code's logic.

4. **Understand the Stack Frame Structure:** The description of the stack frame layout is another vital piece of information. It shows how arguments, local variables, and regex registers are organized on the stack. This helps in understanding how the assembler accesses and manipulates data.

5. **Scan the Constructor (`RegExpMacroAssemblerS390::RegExpMacroAssemblerS390`)**: This reveals the basic initialization steps, such as creating a `MacroAssembler` instance, setting the mode (LATIN1 or UC16), and initializing labels.

6. **Look at Key Methods and Their Functionality:**  Go through the methods defined in the class and try to understand their purpose based on their names:
    * `AdvanceCurrentPosition`, `AdvanceRegister`: Manipulating the current position and register values.
    * `Backtrack`: Implementing backtracking logic.
    * `CheckCharacter`, `CheckCharacterGT`, `CheckCharacterLT`, etc.: Various character matching checks.
    * `CheckNotBackReference`, `CheckNotBackReferenceIgnoreCase`: Handling backreferences.
    * `CheckCharacterInRange`, `CheckCharacterNotInRange`, `CheckBitInTable`:  More complex character class checks.
    * `Fail`: Handling matching failures.
    * `LoadRegExpStackPointerFromMemory`, `StoreRegExpStackPointerToMemory`, `PushRegExpBasePointer`, `PopRegExpBasePointer`: Managing the regular expression stack.
    * `GetCode`:  Finalizing the generated code.

7. **Address Specific User Queries:**
    * **".tq" extension:** Explicitly check if the file extension is mentioned or implied. In this case, it's a `.cc` file.
    * **Relationship to JavaScript:**  The code is a low-level implementation detail of V8's regex engine. It's not directly written in JavaScript, but it's used to execute JavaScript regular expressions.
    * **Code Logic Inference:**  The numerous `Check...` methods suggest conditional logic based on character comparisons and other factors. The `Backtrack` method indicates a state-machine-like approach to matching. Specific input/output examples would require deep analysis of individual methods and their interactions.
    * **Common Programming Errors:** The code deals with low-level memory manipulation and complex control flow. Common errors in similar contexts could include buffer overflows, incorrect register usage, or faulty backtracking logic.

8. **Synthesize the Information:** Combine the gathered information into a concise summary, addressing each of the user's points. Focus on the core functionality and the role of the code within the V8 engine.

9. **Review and Refine:** Ensure the summary is clear, accurate, and addresses all parts of the user's request. Organize the information logically. For instance, start with the main purpose, then discuss register and stack usage, followed by the functions of key methods.

By following these steps, we can generate a comprehensive and informative summary like the one provided in the initial prompt's "thought process" example.
好的，根据您提供的v8源代码文件 `v8/src/regexp/s390/regexp-macro-assembler-s390.cc` 的内容，以下是其功能的归纳：

**功能归纳：**

`v8/src/regexp/s390/regexp-macro-assembler-s390.cc` 文件是 V8 JavaScript 引擎中专门为 s390 架构（包括 s390x）实现的正则表达式宏汇编器。它的主要功能是：

1. **生成特定于 s390 架构的机器码:**  它使用 V8 的宏汇编器 (`MacroAssembler`)，将正则表达式的操作（例如字符匹配、分支、回溯等）转化为可以在 s390 处理器上直接执行的机器指令。

2. **实现正则表达式匹配的核心逻辑:**  文件中包含了大量的代码，用于实现正则表达式匹配的各种操作，例如：
    * **加载和比较字符:** 从输入字符串中加载当前字符，并与指定的字符或字符范围进行比较。
    * **移动输入位置:**  在输入字符串中前进或后退。
    * **寄存器操作:**  管理和操作用于存储匹配状态、捕获组信息等的寄存器。
    * **回溯管理:**  实现正则表达式匹配失败时的回溯机制，通过操作栈来恢复之前的状态。
    * **捕获组处理:**  记录和保存匹配到的子字符串（捕获组）。
    * **边界检查:**  检查是否到达字符串的开头或结尾。
    * **预编译字符类支持:**  利用预先计算好的字符类表（例如，数字、字母、空格等）进行快速匹配。

3. **遵循特定的寄存器使用约定和栈帧结构:**  为了保证代码的正确性和与其他 V8 组件的互操作性，该文件定义了一套严格的寄存器使用约定和栈帧结构。这包括哪些寄存器用于存储输入位置、当前字符、回溯栈指针等等。

4. **处理不同匹配模式:**  支持不同的正则表达式匹配模式，例如区分大小写、Unicode 等。

5. **提供 C++ 接口供 V8 的其他部分调用:**  该文件定义了一个 C++ 类 `RegExpMacroAssemblerS390`，提供了各种方法来执行正则表达式匹配的各个步骤。V8 的其他组件（例如正则表达式编译器）可以使用这个类来生成用于匹配的机器码。

**关于其他问题的回答：**

* **`.tq` 结尾：**  根据您提供的信息，`v8/src/regexp/s390/regexp-macro-assembler-s390.cc` 以 `.cc` 结尾，**所以它不是一个 V8 Torque 源代码文件**。Torque 文件通常以 `.tq` 结尾。

* **与 JavaScript 的关系：**  `v8/src/regexp/s390/regexp-macro-assembler-s390.cc` 的功能与 JavaScript 的 `RegExp` 对象的功能密切相关。当你在 JavaScript 中使用正则表达式进行匹配时，V8 引擎会在底层使用类似这样的宏汇编器来生成高效的机器码执行匹配。

   **JavaScript 示例：**

   ```javascript
   const text = "Hello World 123";
   const regex = /W[a-z]+d \d+/; // 匹配以 "W" 开头，后跟小写字母，然后是 "d"，再跟一个或多个数字

   if (regex.test(text)) {
     console.log("匹配成功！");
   } else {
     console.log("匹配失败！");
   }

   const matchResult = text.match(regex);
   if (matchResult) {
     console.log("匹配结果:", matchResult[0]); // 输出 "World 123"
   }
   ```

   在这个例子中，当你执行 `regex.test(text)` 或 `text.match(regex)` 时，V8 引擎会编译 `regex` 并可能使用 `regexp-macro-assembler-s390.cc` (如果运行在 s390 架构上) 生成相应的机器码来执行匹配操作。

* **代码逻辑推理（假设输入与输出）：**

   假设我们调用 `CheckCharacter(72, &on_equal)`，其中 72 是字符 'H' 的 ASCII 码。

   **假设输入：**
   * 当前输入位置的字符是 'H'。

   **汇编代码逻辑：**
   ```assembly
   __ CmpU64(current_character(), Operand(72)); // 将当前字符与 72 进行比较
   BranchOrBacktrack(eq, on_equal);             // 如果相等，则跳转到 on_equal 标签
   ```

   **预期输出：**
   * 如果当前字符确实是 'H'，则程序会跳转到 `on_equal` 标签继续执行。
   * 如果当前字符不是 'H'，则会执行回溯操作 (因为 `BranchOrBacktrack` 在不满足条件时会进行回溯)。

* **用户常见的编程错误：**

   在与正则表达式相关的编程中，常见的错误包括：

   1. **回溯陷阱 (Catastrophic Backtracking):**  编写的正则表达式在某些输入下会导致大量的回溯，消耗大量 CPU 资源，使程序变得非常慢甚至崩溃。例如，对于字符串 "aaaaaaaaaaaaaaaaaaaaaaa!" 和正则表达式 `(a+)+b`。

   2. **忘记转义特殊字符:** 正则表达式中有一些特殊字符（例如 `.`、`*`、`+`、`?` 等），如果需要匹配这些字符本身，必须进行转义。例如，要匹配字符串中的点号 `.`，需要使用正则表达式 `\.`。

   3. **捕获组的误用或遗忘:**  不清楚捕获组的工作方式，或者忘记使用捕获组来提取需要的子字符串。

   4. **字符类和量词的混淆使用:**  例如，错误地使用 `.` 来匹配所有字符（包括换行符，除非启用了 `s` 修饰符），或者对量词 (`*`、`+`、`?`) 的理解有误。

**总结：**

总而言之，`v8/src/regexp/s390/regexp-macro-assembler-s390.cc` 是 V8 引擎中一个关键的组成部分，它负责为 s390 架构高效地实现 JavaScript 正则表达式的匹配功能。它通过生成底层的机器码指令来执行复杂的模式匹配操作，并遵循特定的架构约定。

### 提示词
```
这是目录为v8/src/regexp/s390/regexp-macro-assembler-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/s390/regexp-macro-assembler-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/init/v8.h"

#if V8_TARGET_ARCH_S390X

#include "src/codegen/macro-assembler.h"
#include "src/codegen/s390/assembler-s390-inl.h"
#include "src/heap/factory.h"
#include "src/logging/log.h"
#include "src/objects/code-inl.h"
#include "src/regexp/regexp-stack.h"
#include "src/regexp/s390/regexp-macro-assembler-s390.h"
#include "src/snapshot/embedded/embedded-data-inl.h"

namespace v8 {
namespace internal {

/*
 * This assembler uses the following register assignment convention
 * - r6: Temporarily stores the index of capture start after a matching pass
 *        for a global regexp.
 * - r7: Pointer to current InstructionStream object including heap object tag.
 * - r8: Current position in input, as negative offset from end of string.
 *        Please notice that this is the byte offset, not the character offset!
 * - r9: Currently loaded character. Must be loaded using
 *        LoadCurrentCharacter before using any of the dispatch methods.
 * - r13: Points to tip of backtrack stack
 * - r10: End of input (points to byte after last character in input).
 * - r11: Frame pointer. Used to access arguments, local variables and
 *         RegExp registers.
 * - r12: IP register, used by assembler. Very volatile.
 * - r15/sp : Points to tip of C stack.
 *
 * The remaining registers are free for computations.
 * Each call to a public method should retain this convention.
 *
 * The stack will have the following structure
 *  - fp[112]  Address regexp     (address of the JSRegExp object; unused in
 *                                native code, passed to match signature of
 *                                the interpreter)
 *  - fp[108] Isolate* isolate   (address of the current isolate)
 *  - fp[104] direct_call        (if 1, direct call from JavaScript code,
 *                                if 0, call through the runtime system).
 *  - fp[100] stack_area_base    (high end of the memory area to use as
 *                                backtracking stack).
 *  - fp[96]  capture array size (may fit multiple sets of matches)
 *  - fp[0..96] zLinux ABI register saving area
 *  --- sp when called ---
 *  --- frame pointer ----
 *  - fp [-4] frame marker
 *  - fp [-8] isolate
 *  - fp[-12] direct_call        (if 1, direct call from JavaScript code,
 *                                if 0, call through the runtime system).
 *  - fp[-16] stack_area_base    (high end of the memory area to use as
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

const int RegExpMacroAssemblerS390::kRegExpCodeSize;

RegExpMacroAssemblerS390::RegExpMacroAssemblerS390(Isolate* isolate, Zone* zone,
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
  __ mov(r2, Operand(FAILURE));
  __ Ret();
  __ bind(&start_label_);  // And then continue from here.
}

RegExpMacroAssemblerS390::~RegExpMacroAssemblerS390() {
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

int RegExpMacroAssemblerS390::stack_limit_slack_slot_count() {
  return RegExpStack::kStackLimitSlackSlotCount;
}

void RegExpMacroAssemblerS390::AdvanceCurrentPosition(int by) {
  if (by != 0) {
    __ AddS64(current_input_offset(), Operand(by * char_size()));
  }
}

void RegExpMacroAssemblerS390::AdvanceRegister(int reg, int by) {
  DCHECK_LE(0, reg);
  DCHECK_GT(num_registers_, reg);
  if (by != 0) {
    if (CpuFeatures::IsSupported(GENERAL_INSTR_EXT) && is_int8(by)) {
      __ agsi(register_location(reg), Operand(by));
    } else {
      __ LoadU64(r2, register_location(reg), r0);
      __ mov(r0, Operand(by));
      __ agr(r2, r0);
      __ StoreU64(r2, register_location(reg));
    }
  }
}

void RegExpMacroAssemblerS390::Backtrack() {
  CheckPreemption();
  if (has_backtrack_limit()) {
    Label next;
    __ LoadU64(r2, MemOperand(frame_pointer(), kBacktrackCountOffset), r0);
    __ AddS64(r2, r2, Operand(1));
    __ StoreU64(r2, MemOperand(frame_pointer(), kBacktrackCountOffset), r0);
    __ CmpU64(r2, Operand(backtrack_limit()));
    __ bne(&next);

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
  Pop(r2);
  __ AddS64(r2, code_pointer());
  __ b(r2);
}

void RegExpMacroAssemblerS390::Bind(Label* label) { __ bind(label); }

void RegExpMacroAssemblerS390::CheckCharacter(uint32_t c, Label* on_equal) {
  __ CmpU64(current_character(), Operand(c));
  BranchOrBacktrack(eq, on_equal);
}

void RegExpMacroAssemblerS390::CheckCharacterGT(base::uc16 limit,
                                                Label* on_greater) {
  __ CmpU64(current_character(), Operand(limit));
  BranchOrBacktrack(gt, on_greater);
}

void RegExpMacroAssemblerS390::CheckAtStart(int cp_offset, Label* on_at_start) {
  __ LoadU64(r3, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
  __ AddS64(r2, current_input_offset(),
            Operand(-char_size() + cp_offset * char_size()));
  __ CmpS64(r2, r3);
  BranchOrBacktrack(eq, on_at_start);
}

void RegExpMacroAssemblerS390::CheckNotAtStart(int cp_offset,
                                               Label* on_not_at_start) {
  __ LoadU64(r3, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
  __ AddS64(r2, current_input_offset(),
            Operand(-char_size() + cp_offset * char_size()));
  __ CmpS64(r2, r3);
  BranchOrBacktrack(ne, on_not_at_start);
}

void RegExpMacroAssemblerS390::CheckCharacterLT(base::uc16 limit,
                                                Label* on_less) {
  __ CmpU64(current_character(), Operand(limit));
  BranchOrBacktrack(lt, on_less);
}

void RegExpMacroAssemblerS390::CheckGreedyLoop(Label* on_equal) {
  Label backtrack_non_equal;
  __ CmpS64(current_input_offset(), MemOperand(backtrack_stackpointer(), 0));
  __ bne(&backtrack_non_equal);
  __ AddS64(backtrack_stackpointer(), Operand(kSystemPointerSize));

  BranchOrBacktrack(al, on_equal);
  __ bind(&backtrack_non_equal);
}

void RegExpMacroAssemblerS390::CheckNotBackReferenceIgnoreCase(
    int start_reg, bool read_backward, bool unicode, Label* on_no_match) {
  Label fallthrough;
  __ LoadU64(r2, register_location(start_reg));      // Index of start of
                                                     // capture
  __ LoadU64(r3, register_location(start_reg + 1));  // Index of end
  __ SubS64(r3, r3, r2);

  // At this point, the capture registers are either both set or both cleared.
  // If the capture length is zero, then the capture is either empty or cleared.
  // Fall through in both cases.
  __ beq(&fallthrough);

  // Check that there are enough characters left in the input.
  if (read_backward) {
    __ LoadU64(r5, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
    __ AddS64(r5, r5, r3);
    __ CmpS64(current_input_offset(), r5);
    BranchOrBacktrack(le, on_no_match);
  } else {
    __ AddS64(r0, r3, current_input_offset());
    BranchOrBacktrack(gt, on_no_match);
  }

  if (mode_ == LATIN1) {
    Label success;
    Label fail;
    Label loop_check;

    // r2 - offset of start of capture
    // r3 - length of capture
    __ AddS64(r2, end_of_input_address());
    __ AddS64(r4, current_input_offset(), end_of_input_address());
    if (read_backward) {
      __ SubS64(r4, r4, r3);  // Offset by length when matching backwards.
    }
    __ mov(r1, Operand::Zero());

    // r1 - Loop index
    // r2 - Address of start of capture.
    // r4 - Address of current input position.

    Label loop;
    __ bind(&loop);
    __ LoadU8(r5, MemOperand(r2, r1));
    __ LoadU8(r6, MemOperand(r4, r1));

    __ CmpS64(r6, r5);
    __ beq(&loop_check);

    // Mismatch, try case-insensitive match (converting letters to lower-case).
    __ Or(r5, Operand(0x20));  // Convert capture character to lower-case.
    __ Or(r6, Operand(0x20));  // Also convert input character.
    __ CmpS64(r6, r5);
    __ bne(&fail);
    __ SubS64(r5, Operand('a'));
    __ CmpU64(r5, Operand('z' - 'a'));       // Is r5 a lowercase letter?
    __ ble(&loop_check);                     // In range 'a'-'z'.
    // Latin-1: Check for values in range [224,254] but not 247.
    __ SubS64(r5, Operand(224 - 'a'));
    __ CmpU64(r5, Operand(254 - 224));
    __ bgt(&fail);                           // Weren't Latin-1 letters.
    __ CmpU64(r5, Operand(247 - 224));       // Check for 247.
    __ beq(&fail);

    __ bind(&loop_check);
    __ la(r1, MemOperand(r1, char_size()));
    __ CmpS64(r1, r3);
    __ blt(&loop);
    __ b(&success);

    __ bind(&fail);
    BranchOrBacktrack(al, on_no_match);

    __ bind(&success);
    // Compute new value of character position after the matched part.
    __ SubS64(current_input_offset(), r4, end_of_input_address());
    if (read_backward) {
      __ LoadU64(r2,
                 register_location(start_reg));  // Index of start of capture
      __ LoadU64(r3,
                 register_location(start_reg + 1));  // Index of end of capture
      __ AddS64(current_input_offset(), current_input_offset(), r2);
      __ SubS64(current_input_offset(), current_input_offset(), r3);
    }
    __ AddS64(current_input_offset(), r1);
  } else {
    DCHECK(mode_ == UC16);
    int argument_count = 4;
    __ PrepareCallCFunction(argument_count, r4);

    // r2 - offset of start of capture
    // r3 - length of capture

    // Put arguments into arguments registers.
    // Parameters are
    //   r2: Address byte_offset1 - Address captured substring's start.
    //   r3: Address byte_offset2 - Address of current character position.
    //   r4: size_t byte_length - length of capture in bytes(!)
    //   r5: Isolate* isolate.

    // Address of start of capture.
    __ AddS64(r2, end_of_input_address());
    // Length of capture.
    __ mov(r4, r3);
    // Save length in callee-save register for use on return.
    __ mov(r6, r3);
    // Address of current input position.
    __ AddS64(r3, current_input_offset(), end_of_input_address());
    if (read_backward) {
      __ SubS64(r3, r3, r6);
    }
// Isolate.
    __ mov(r5, Operand(ExternalReference::isolate_address(isolate())));

    {
      AllowExternalCallThatCantCauseGC scope(masm_.get());
      ExternalReference function =
          unicode
              ? ExternalReference::re_case_insensitive_compare_unicode()
              : ExternalReference::re_case_insensitive_compare_non_unicode();
      CallCFunctionFromIrregexpCode(function, argument_count);
    }

    // Check if function returned non-zero for success or zero for failure.
    __ CmpS64(r2, Operand::Zero());
    BranchOrBacktrack(eq, on_no_match);

    // On success, advance position by length of capture.
    if (read_backward) {
      __ SubS64(current_input_offset(), current_input_offset(), r6);
    } else {
      __ AddS64(current_input_offset(), current_input_offset(), r6);
    }
  }

  __ bind(&fallthrough);
}

void RegExpMacroAssemblerS390::CheckNotBackReference(int start_reg,
                                                     bool read_backward,
                                                     Label* on_no_match) {
  Label fallthrough;

  // Find length of back-referenced capture.
  __ LoadU64(r2, register_location(start_reg));
  __ LoadU64(r3, register_location(start_reg + 1));
  __ SubS64(r3, r3, r2);  // Length to check.

  // At this point, the capture registers are either both set or both cleared.
  // If the capture length is zero, then the capture is either empty or cleared.
  // Fall through in both cases.
  __ beq(&fallthrough);

  // Check that there are enough characters left in the input.
  if (read_backward) {
    __ LoadU64(r5, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
    __ AddS64(r5, r5, r3);
    __ CmpS64(current_input_offset(), r5);
    BranchOrBacktrack(le, on_no_match);
  } else {
    __ AddS64(r0, r3, current_input_offset());
    BranchOrBacktrack(gt, on_no_match, cr0);
  }

  // r2 - offset of start of capture
  // r3 - length of capture
  __ la(r2, MemOperand(r2, end_of_input_address()));
  __ la(r4, MemOperand(current_input_offset(), end_of_input_address()));
  if (read_backward) {
    __ SubS64(r4, r4, r3);  // Offset by length when matching backwards.
  }
  __ mov(r1, Operand::Zero());

  Label loop;
  __ bind(&loop);
  if (mode_ == LATIN1) {
    __ LoadU8(r5, MemOperand(r2, r1));
    __ LoadU8(r6, MemOperand(r4, r1));
  } else {
    DCHECK(mode_ == UC16);
    __ LoadU16(r5, MemOperand(r2, r1));
    __ LoadU16(r6, MemOperand(r4, r1));
  }
  __ la(r1, MemOperand(r1, char_size()));
  __ CmpS64(r5, r6);
  BranchOrBacktrack(ne, on_no_match);
  __ CmpS64(r1, r3);
  __ blt(&loop);

  // Move current character position to position after match.
  __ SubS64(current_input_offset(), r4, end_of_input_address());
  if (read_backward) {
    __ LoadU64(r2, register_location(start_reg));  // Index of start of capture
    __ LoadU64(r3,
               register_location(start_reg + 1));  // Index of end of capture
    __ AddS64(current_input_offset(), current_input_offset(), r2);
    __ SubS64(current_input_offset(), current_input_offset(), r3);
  }
  __ AddS64(current_input_offset(), r1);

  __ bind(&fallthrough);
}

void RegExpMacroAssemblerS390::CheckNotCharacter(unsigned c,
                                                 Label* on_not_equal) {
  __ CmpU64(current_character(), Operand(c));
  BranchOrBacktrack(ne, on_not_equal);
}

void RegExpMacroAssemblerS390::CheckCharacterAfterAnd(uint32_t c, uint32_t mask,
                                                      Label* on_equal) {
  __ AndP(r2, current_character(), Operand(mask));
  if (c != 0) {
    __ CmpU64(r2, Operand(c));
  }
  BranchOrBacktrack(eq, on_equal);
}

void RegExpMacroAssemblerS390::CheckNotCharacterAfterAnd(unsigned c,
                                                         unsigned mask,
                                                         Label* on_not_equal) {
  __ AndP(r2, current_character(), Operand(mask));
  if (c != 0) {
    __ CmpU64(r2, Operand(c));
  }
  BranchOrBacktrack(ne, on_not_equal);
}

void RegExpMacroAssemblerS390::CheckNotCharacterAfterMinusAnd(
    base::uc16 c, base::uc16 minus, base::uc16 mask, Label* on_not_equal) {
  DCHECK_GT(String::kMaxUtf16CodeUnit, minus);
  __ lay(r2, MemOperand(current_character(), -minus));
  __ And(r2, Operand(mask));
  if (c != 0) {
    __ CmpU64(r2, Operand(c));
  }
  BranchOrBacktrack(ne, on_not_equal);
}

void RegExpMacroAssemblerS390::CheckCharacterInRange(base::uc16 from,
                                                     base::uc16 to,
                                                     Label* on_in_range) {
  __ lay(r2, MemOperand(current_character(), -from));
  __ CmpU64(r2, Operand(to - from));
  BranchOrBacktrack(le, on_in_range);  // Unsigned lower-or-same condition.
}

void RegExpMacroAssemblerS390::CheckCharacterNotInRange(
    base::uc16 from, base::uc16 to, Label* on_not_in_range) {
  __ lay(r2, MemOperand(current_character(), -from));
  __ CmpU64(r2, Operand(to - from));
  BranchOrBacktrack(gt, on_not_in_range);  // Unsigned higher condition.
}

void RegExpMacroAssemblerS390::CallIsCharacterInRangeArray(
    const ZoneList<CharacterRange>* ranges) {
  static const int kNumArguments = 2;
  __ PrepareCallCFunction(kNumArguments, r0);

  __ mov(r2, current_character());
  __ mov(r3, Operand(GetOrAddRangeArray(ranges)));

  {
    // We have a frame (set up in GetCode), but the assembler doesn't know.
    FrameScope scope(masm_.get(), StackFrame::MANUAL);
    CallCFunctionFromIrregexpCode(
        ExternalReference::re_is_character_in_range_array(), kNumArguments);
  }

  __ mov(code_pointer(), Operand(masm_->CodeObject()));
}

bool RegExpMacroAssemblerS390::CheckCharacterInRangeArray(
    const ZoneList<CharacterRange>* ranges, Label* on_in_range) {
  CallIsCharacterInRangeArray(ranges);
  __ CmpS64(r2, Operand::Zero());
  BranchOrBacktrack(ne, on_in_range);
  return true;
}

bool RegExpMacroAssemblerS390::CheckCharacterNotInRangeArray(
    const ZoneList<CharacterRange>* ranges, Label* on_not_in_range) {
  CallIsCharacterInRangeArray(ranges);
  __ CmpS64(r2, Operand::Zero());
  BranchOrBacktrack(eq, on_not_in_range);
  return true;
}

void RegExpMacroAssemblerS390::CheckBitInTable(Handle<ByteArray> table,
                                               Label* on_bit_set) {
  __ mov(r2, Operand(table));
  Register index = current_character();
  if (mode_ != LATIN1 || kTableMask != String::kMaxOneByteCharCode) {
    __ AndP(r3, current_character(), Operand(kTableSize - 1));
    index = r3;
  }
  __ LoadU8(r2, MemOperand(r2, index,
                           (OFFSET_OF_DATA_START(ByteArray) - kHeapObjectTag)));
  __ CmpS64(r2, Operand::Zero());
  BranchOrBacktrack(ne, on_bit_set);
}

void RegExpMacroAssemblerS390::SkipUntilBitInTable(
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

bool RegExpMacroAssemblerS390::CheckSpecialClassRanges(
    StandardCharacterSet type, Label* on_no_match) {
  // Range checks (c in min..max) are generally implemented by an unsigned
  // (c - min) <= (max - min) check
  // TODO(jgruber): No custom implementation (yet): s(UC16), S(UC16).
  switch (type) {
    case StandardCharacterSet::kWhitespace:
      // Match space-characters.
      if (mode_ == LATIN1) {
        // One byte space characters are '\t'..'\r', ' ' and \u00a0.
        Label success;
        __ CmpS64(current_character(), Operand(' '));
        __ beq(&success);
        // Check range 0x09..0x0D.
        __ SubS64(r2, current_character(), Operand('\t'));
        __ CmpU64(r2, Operand('\r' - '\t'));
        __ ble(&success);
        // \u00a0 (NBSP).
        __ CmpU64(r2, Operand(0x00A0 - '\t'));
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
      __ SubS64(r2, current_character(), Operand('0'));
      __ CmpU64(r2, Operand('9' - '0'));
      BranchOrBacktrack(gt, on_no_match);
      return true;
    case StandardCharacterSet::kNotDigit:
      // Match non ASCII-digits
      __ SubS64(r2, current_character(), Operand('0'));
      __ CmpU64(r2, Operand('9' - '0'));
      BranchOrBacktrack(le, on_no_match);
      return true;
    case StandardCharacterSet::kNotLineTerminator: {
      // Match non-newlines (not 0x0A('\n'), 0x0D('\r'), 0x2028 and 0x2029)
      __ XorP(r2, current_character(), Operand(0x01));
      // See if current character is '\n'^1 or '\r'^1, i.e., 0x0B or 0x0C
      __ SubS64(r2, Operand(0x0B));
      __ CmpU64(r2, Operand(0x0C - 0x0B));
      BranchOrBacktrack(le, on_no_match);
      if (mode_ == UC16) {
        // Compare original value to 0x2028 and 0x2029, using the already
        // computed (current_char ^ 0x01 - 0x0B). I.e., check for
        // 0x201D (0x2028 - 0x0B) or 0x201E.
        __ SubS64(r2, Operand(0x2028 - 0x0B));
        __ CmpU64(r2, Operand(1));
        BranchOrBacktrack(le, on_no_match);
      }
      return true;
    }
    case StandardCharacterSet::kLineTerminator: {
      // Match newlines (0x0A('\n'), 0x0D('\r'), 0x2028 and 0x2029)
      __ XorP(r2, current_character(), Operand(0x01));
      // See if current character is '\n'^1 or '\r'^1, i.e., 0x0B or 0x0C
      __ SubS64(r2, Operand(0x0B));
      __ CmpU64(r2, Operand(0x0C - 0x0B));
      if (mode_ == LATIN1) {
        BranchOrBacktrack(gt, on_no_match);
      } else {
        Label done;
        __ ble(&done);
        // Compare original value to 0x2028 and 0x2029, using the already
        // computed (current_char ^ 0x01 - 0x0B). I.e., check for
        // 0x201D (0x2028 - 0x0B) or 0x201E.
        __ SubS64(r2, Operand(0x2028 - 0x0B));
        __ CmpU64(r2, Operand(1));
        BranchOrBacktrack(gt, on_no_match);
        __ bind(&done);
      }
      return true;
    }
    case StandardCharacterSet::kWord: {
      if (mode_ != LATIN1) {
        // Table is 1256 entries, so all LATIN1 characters can be tested.
        __ CmpS64(current_character(), Operand('z'));
        BranchOrBacktrack(gt, on_no_match);
      }
      ExternalReference map = ExternalReference::re_word_character_map();
      __ mov(r2, Operand(map));
      __ LoadU8(r2, MemOperand(r2, current_character()));
      __ CmpU64(r2, Operand::Zero());
      BranchOrBacktrack(eq, on_no_match);
      return true;
    }
    case StandardCharacterSet::kNotWord: {
      Label done;
      if (mode_ != LATIN1) {
        // Table is 256 entries, so all LATIN characters can be tested.
        __ CmpU64(current_character(), Operand('z'));
        __ bgt(&done);
      }
      ExternalReference map = ExternalReference::re_word_character_map();
      __ mov(r2, Operand(map));
      __ LoadU8(r2, MemOperand(r2, current_character()));
      __ CmpU64(r2, Operand::Zero());
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

void RegExpMacroAssemblerS390::Fail() {
  __ mov(r2, Operand(FAILURE));
  __ b(&exit_label_);
}

void RegExpMacroAssemblerS390::LoadRegExpStackPointerFromMemory(Register dst) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_stack_pointer(isolate());
  __ mov(dst, Operand(ref));
  __ LoadU64(dst, MemOperand(dst));
}

void RegExpMacroAssemblerS390::StoreRegExpStackPointerToMemory(
    Register src, Register scratch) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_stack_pointer(isolate());
  __ mov(scratch, Operand(ref));
  __ StoreU64(src, MemOperand(scratch));
}

void RegExpMacroAssemblerS390::PushRegExpBasePointer(Register stack_pointer,
                                                     Register scratch) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ mov(scratch, Operand(ref));
  __ LoadU64(scratch, MemOperand(scratch));
  __ SubS64(scratch, stack_pointer, scratch);
  __ StoreU64(scratch,
              MemOperand(frame_pointer(), kRegExpStackBasePointerOffset));
}

void RegExpMacroAssemblerS390::PopRegExpBasePointer(Register stack_pointer_out,
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

Handle<HeapObject> RegExpMacroAssemblerS390::GetCode(Handle<String> source,
                                                     RegExpFlags flags) {
  Label return_r2;

  // Finalize code - write the entry point code now we know how many
  // registers we need.

  // Entry code:
  __ bind(&entry_label_);

  // Tell the system that we have a stack frame.  Because the type
  // is MANUAL, no is generated.
  FrameScope scope(masm_.get(), StackFrame::MANUAL);

  // Ensure register assigments are consistent with callee save mask
  DCHECK(kRegExpCalleeSaved.has(r6));
  DCHECK(kRegExpCalleeSaved.has(code_pointer()));
  DCHECK(kRegExpCalleeSaved.has(current_input_offset()));
  DCHECK(kRegExpCalleeSaved.has(current_character()));
  DCHECK(kRegExpCalleeSaved.has(backtrack_stackpointer()));
  DCHECK(kRegExpCalleeSaved.has(end_of_input_address()));
  DCHECK(kRegExpCalleeSaved.has(frame_pointer()));

  // Emit code to start a new stack frame. In the following we push all
  // callee-save registers (these end up above the fp) and all register
  // arguments (these end up below the fp).
  //
  // zLinux ABI
  //    Incoming parameters:
  //          r2: input_string
  //          r3: start_index
  //          r4: start addr
  //          r5: end addr
  //          r6: capture output array
  //    Requires us to save the callee-preserved registers r6-r13
  //    General convention is to also save r14 (return addr) and
  //    sp/r15 as well in a single STM/STMG
#if V8_OS_ZOS
  // Move stack down by (12*8) to save r4..r15
  __ lay(r4, MemOperand(r4, -12 * kSystemPointerSize));

  // Store r4..r15 (sp) to stack
  __ StoreMultipleP(r4, sp, MemOperand(r4));
  __ mov(sp, r4);

  // Load C args from stack to registers
  __ LoadMultipleP(
      r5, r10,
      MemOperand(r4,
                 (12 * kSystemPointerSize) + kStackPointerBias +
                     (kXPLINKStackFrameExtraParamSlot * kSystemPointerSize)));

  // Shuffle XPLINK input arguments to LoZ ABI registers
  __ mov(r4, r3);
  __ mov(r3, r2);
  __ mov(r2, r1);
#else
  __ StoreMultipleP(r6, sp, MemOperand(sp, 6 * kSystemPointerSize));

  // Load stack parameters from caller stack frame
  __ LoadMultipleP(
      r7, r9, MemOperand(sp, kStackFrameExtraParamSlot * kSystemPointerSize));
#endif
  // r7 = capture array size
  // r8 = stack area base
  // r9 = direct call

  __ mov(frame_pointer(), sp);
  // Also push the frame marker.
  __ mov(r0, Operand(StackFrame::TypeToMarker(StackFrame::IRREGEXP)));
  __ push(r0);
#if V8_OS_ZOS
  // Store isolate address from r10 to expected stack address
  __ StoreU64(r10, MemOperand(frame_pointer(), kIsolateOffset));
#endif
  __ lay(sp, MemOperand(sp, -10 * kSystemPointerSize));

  static_assert(kSuccessfulCapturesOffset ==
                kInputStringOffset - kSystemPointerSize);
  __ mov(r1, Operand::Zero());  // success counter
  static_assert(kStringStartMinusOneOffset ==
                kSuccessfulCapturesOffset - kSystemPointerSize);
  __ mov(r0, r1);  // offset of location
  __ StoreMultipleP(r0, r9, MemOperand(sp, 0));
  static_assert(kBacktrackCountOffset ==
                kStringStartMinusOneOffset - kSystemPointerSize);
  __ Push(r1);  // The backtrack counter.
  static_assert(kRegExpStackBasePointerOffset ==
                kBacktrackCountOffset - kSystemPointerSize);
  __ push(r1);  // The regexp stack base ptr.

  // Initialize backtrack stack pointer. It must not be clobbered from here on.
  // Note the backtrack_stackpointer is callee-saved.
  static_assert(backtrack_stackpointer() == r13);
  LoadRegExpStackPointerFromMemory(backtrack_stackpointer());

  // Store the regexp base pointer - we'll later restore it / write it to
  // memory when returning from this irregexp code object.
  PushRegExpBasePointer(backtrack_stackpointer(), r3);

  {
    // Check if we have space on the stack for registers.
    Label stack_limit_hit, stack_ok;

    ExternalReference stack_limit =
        ExternalReference::address_of_jslimit(isolate());
    __ mov(r2, Operand(stack_limit));
    __ LoadU64(r2, MemOperand(r2));
    __ SubS64(r2, sp, r2);
    Operand extra_space_for_variables(num_registers_ * kSystemPointerSize);

    // Handle it if the stack pointer is already below the stack limit.
    __ ble(&stack_limit_hit);
    // Check if there is room for the variable number of registers above
    // the stack limit.
    __ CmpU64(r2, extra_space_for_variables);
    __ bge(&stack_ok);
    // Exit with OutOfMemory exception. There is not enough space on the stack
    // for our working registers.
    __ mov(r2, Operand(EXCEPTION));
    __ b(&return_r2);

    __ bind(&stack_limit_hit);
    CallCheckStackGuardState(r2, extra_space_for_variables);
    __ CmpS64(r2, Operand::Zero());
    // If returned value is non-zero, we exit with the returned value as result.
    __ bne(&return_r2);

    __ bind(&stack_ok);
  }

  // Allocate space on stack for registers.
  __ lay(sp, MemOperand(sp, (-num_registers_ * kSystemPointerSize)));
  // Load string end.
  __ LoadU64(end_of_input_address(),
             MemOperand(frame_pointer(), kInputEndOffset));
  // Load input start.
  __ LoadU64(r4, MemOperand(frame_pointer(), kInputStartOffset));
  // Find negative length (offset of start relative to end).
  __ SubS64(current_input_offset(), r4, end_of_input_address());
  __ LoadU64(r3, MemOperand(frame_pointer(), kStartIndexOffset));
  // Set r1 to address of char before start of the input string
  // (effectively string position -1).
  __ mov(r1, r4);
  __ SubS64(r1, current_input_offset(), Operand(char_size()));
  if (mode_ == UC16) {
    __ ShiftLeftU64(r0, r3, Operand(1));
    __ SubS64(r1, r1, r0);
  } else {
    __ SubS64(r1, r1, r3);
  }
  // Store this value in a local variable, for use when clearing
  // position registers.
  __ StoreU64(r1, MemOperand(frame_pointer(), kStringStartMinusOneOffset));

  // Initialize code pointer register
  __ mov(code_pointer(), Operand(masm_->CodeObject()));

  Label load_char_start_regexp;
  {
    Label start_regexp;
    // Load newline if index is at start, previous character otherwise.
    __ CmpS64(r3, Operand::Zero());
    __ bne(&load_char_start_regexp);
    __ mov(current_character(), Operand('\n'));
    __ b(&start_regexp);

    // Global regexp restarts matching here.
    __ bind(&load_char_start_regexp);
    //
```