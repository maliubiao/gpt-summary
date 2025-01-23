Response:
Let's break down the thought process for analyzing the provided C++ code snippet and answering the request.

**1. Initial Understanding of the Request:**

The request asks for a functional overview of a specific V8 source file (`regexp-macro-assembler-riscv.cc`). It also includes specific conditions to check for: Torque usage, relation to JavaScript, code logic (input/output), common programming errors, and finally, a concise summary of the file's purpose.

**2. Analyzing the File Name and Path:**

The path `v8/src/regexp/riscv/regexp-macro-assembler-riscv.cc` immediately tells us several things:

* **`v8`:**  This is part of the V8 JavaScript engine.
* **`src/regexp`:** This code is related to regular expression processing within V8.
* **`riscv`:**  This indicates the code is specifically for the RISC-V architecture.
* **`regexp-macro-assembler-riscv.cc`:**  This strongly suggests the file contains a macro assembler implementation for regular expressions on RISC-V. The `.cc` extension confirms it's C++ code.

**3. Reading the Header Comments and Includes:**

The initial comments provide valuable context:

* **Copyright and License:** Standard V8 boilerplate.
* **Register Assignment Convention:**  This is crucial information!  It outlines how specific RISC-V registers are used within the assembler. Understanding these conventions is key to understanding the generated code's logic. For example, `s2` representing the current position in the input string is important.
* **Stack Structure:**  This describes the layout of the stack frame when the generated regular expression code is executed. This is vital for understanding how arguments are passed, local variables are stored, and how the output registers are managed.

The `#include` directives reveal dependencies:

* **`assembler-inl.h`, `macro-assembler.h`:** These are core V8 components for generating machine code.
* **`log.h`:** For logging purposes.
* **`objects-inl.h`:**  Deals with V8's object model.
* **`regexp-macro-assembler.h`:**  The base class for this RISC-V specific implementation.
* **`regexp-stack.h`:**  Manages the stack used by the regular expression engine for backtracking.
* **`embedded-data-inl.h`:**  For accessing embedded data.
* **`unicode.h`:**  For handling Unicode characters.

**4. Examining the Class Definition:**

The code defines a class `RegExpMacroAssemblerRISCV` that inherits from `NativeRegExpMacroAssembler`. This reinforces the idea that this class is responsible for generating RISC-V assembly code for regular expression matching.

**5. Analyzing Key Methods:**

Scanning the public methods reveals the core functionalities:

* **Constructor:** Initializes the macro assembler, sets up initial labels, and handles potential internal failures.
* **Destructor:** Unuses labels.
* **`AdvanceCurrentPosition`, `AdvanceRegister`:**  Methods for manipulating the current position in the input string and the values in capture registers.
* **`Backtrack`:** Implements the backtracking mechanism, crucial for regular expression matching.
* **`Bind`:**  Associates labels with specific code locations.
* **`CheckCharacter` and related `Check...` methods:** A wide range of methods for checking character properties, comparing characters, and handling character classes. These are the building blocks for constructing complex regular expression matching logic. The different `Check...` variations (GT, LT, in range, not in range, etc.) hint at the variety of comparisons needed.
* **`CallIsCharacterInRangeArray`:**  Calls a C++ function to check if a character is within a given range.
* **`CheckNotBackReferenceIgnoreCase`, `CheckNotBackReference`:**  Handle backreferences, both case-sensitive and case-insensitive.
* **`Fail`:**  Indicates a failed match.
* **`LoadRegExpStackPointerFromMemory`, `StoreRegExpStackPointerToMemory`, `PushRegExpBasePointer`, `PopRegExpBasePointer`:** Methods for managing the regular expression stack.
* **`GetCode`:**  The crucial method that finalizes the assembly code generation and returns the compiled code.

**6. Addressing the Specific Questions:**

* **Functionality:** Based on the class name, includes, and methods, the primary function is generating RISC-V machine code for regular expression matching. It handles character comparisons, backtracking, and managing the execution context.
* **Torque:**  The request specifically asks about `.tq`. A quick scan of the filename and the code shows no `.tq` extension or any obvious signs of Torque usage. The code is clearly standard C++.
* **JavaScript Relationship:** The generated code is directly used by V8's regular expression engine, which is exposed to JavaScript. The execution flow involves JavaScript calling the RegExp methods, which eventually execute the generated machine code. The example provided in the answer demonstrates a simple JavaScript regex and explains how V8 would internally use this C++ code to execute it.
* **Code Logic (Input/Output):**  The register conventions and stack structure provide clues. The input is the string being matched, the starting index, and the output is an array of capture group positions. The `GetCode` method is where the final machine code is generated based on the regular expression pattern. The assumptions made in the example input/output are based on how regex capture groups work.
* **Common Programming Errors:**  The code itself is low-level, but potential errors in the *generated* code (due to errors in the higher-level regex compilation) could lead to stack overflows (due to excessive recursion or backtracking) or incorrect capture group results.
* **Summary:** Combine the key observations into a concise summary highlighting the file's role in V8's regex engine on RISC-V.

**7. Structuring the Answer:**

Organize the findings into logical sections, addressing each part of the request. Use clear and concise language. Provide code examples (both C++ and JavaScript) to illustrate the concepts. The provided "Thought Process" section itself becomes a meta-example of how to arrive at the answer.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Could this file contain the *interpreter* for regex?  **Correction:** The name "macro-assembler" strongly suggests code generation, not interpretation.
* **Considering Torque:**  Double-check the file extension and code content for any Torque-specific syntax. **Confirmation:**  It's standard C++.
* **JavaScript Example:** Ensure the example is simple and clearly demonstrates the connection to the C++ code's function (regex matching).
* **Input/Output Assumption:** Make it clear that the input/output example is an *illustration* of how the generated code would work, not a direct input/output of the C++ file itself.

By following this systematic analysis, combining code inspection with understanding of V8's architecture, we can effectively answer the request and provide a comprehensive overview of the `regexp-macro-assembler-riscv.cc` file.
这是对V8源代码文件 `v8/src/regexp/riscv/regexp-macro-assembler-riscv.cc` 的功能进行分析。

**功能归纳:**

`v8/src/regexp/riscv/regexp-macro-assembler-riscv.cc` 文件是 V8 JavaScript 引擎中，专门为 **RISC-V 架构** 实现的 **正则表达式宏汇编器**。它的核心功能是将高级的正则表达式操作（例如字符匹配、分支、循环、捕获组等）转换为底层的 **RISC-V 汇编指令序列**。

**详细功能列表:**

1. **目标架构特定:** 该文件中的代码是专门为 RISC-V 处理器架构编写的。它利用了 RISC-V 的指令集和寄存器。

2. **正则表达式编译的核心组成部分:**  它是 V8 正则表达式编译流程中的一个关键环节。当 V8 需要执行一个正则表达式时，它会将该正则表达式编译成可执行的机器码，而这个文件负责生成 RISC-V 架构的机器码。

3. **宏汇编器:**  它是一个“宏”汇编器，意味着它提供了一组高级的指令（宏），这些宏在内部会被展开成一系列底层的 RISC-V 汇编指令。这简化了正则表达式编译器的开发，使其不必直接处理复杂的底层指令。

4. **寄存器分配约定:** 文件开头定义了关键寄存器的用途，这对于理解生成的汇编代码至关重要。例如：
   - `s1`: 指向当前的 `InstructionStream` 对象。
   - `s2`: 当前输入中的位置（相对于字符串末尾的负偏移）。
   - `s5`: 当前加载的字符。
   - `s6`: 指向回溯栈的顶部。
   - `fp`: 帧指针，用于访问参数、局部变量和正则表达式寄存器。

5. **栈帧结构定义:**  文件中详细描述了执行正则表达式代码时的栈帧结构，包括参数、局部变量、保存的寄存器以及输出寄存器的布局。这对于理解函数调用和数据访问至关重要。

6. **提供用于生成汇编指令的方法:**  该文件实现了 `RegExpMacroAssembler` 抽象基类定义的接口，提供了各种用于生成特定汇编指令的方法，例如：
   - `AdvanceCurrentPosition`: 移动输入字符串的当前位置。
   - `CheckCharacter`: 检查当前字符是否匹配给定的字符。
   - `CheckAtStart`, `CheckNotAtStart`: 检查当前位置是否在字符串的开头。
   - `CheckCharacterInRange`, `CheckCharacterNotInRange`: 检查字符是否在或不在给定的范围内。
   - `Backtrack`: 实现回溯操作。
   - `Fail`:  表示匹配失败。
   - `LoadCurrentCharacter`: 加载当前字符。
   - `StorePosition`, `ReadPosition`: 存储和读取捕获组的位置。
   - `Push`, `Pop`: 操作回溯栈。
   - `CallCFunctionFromIrregexpCode`: 调用 C++ 函数。

7. **处理不同的匹配模式:**  代码中会根据正则表达式的模式（例如是否区分大小写，是否是 Unicode 模式）生成不同的汇编指令。

8. **管理回溯栈:**  正则表达式引擎使用回溯栈来处理分支和量词。该文件包含用于操作回溯栈的方法。

9. **处理捕获组:**  文件中包含用于存储和检索捕获组匹配位置的方法。

10. **性能优化:**  作为宏汇编器，它的目标是生成高效的机器码，以提高正则表达式的执行速度。

**关于 .tq 结尾:**

你提到的 `.tq` 结尾是 **V8 Torque** 语言的源代码文件扩展名。 **`v8/src/regexp/riscv/regexp-macro-assembler-riscv.cc` 以 `.cc` 结尾，因此它是一个标准的 C++ 源代码文件，而不是 Torque 文件。**  Torque 是一种用于生成 V8 内部代码的领域特定语言，它可以生成 C++ 代码或直接生成汇编代码。

**与 JavaScript 的关系和示例:**

该文件生成的 RISC-V 汇编代码是 V8 引擎执行 JavaScript 正则表达式的基础。当你在 JavaScript 中使用正则表达式时，V8 内部会使用这个文件来编译该正则表达式。

**JavaScript 示例:**

```javascript
const regex = /ab+c/g;
const str = 'abbc abbbc ac';
let array;

while ((array = regex.exec(str)) !== null) {
  console.log(`发现 ${array[0]}。索引为 ${regex.lastIndex - array[0].length}。`);
}
// 预期输出：
// 发现 abbc。索引为 0。
// 发现 abbbc。索引为 5。
```

**说明:**

当 V8 引擎执行上面的 JavaScript 代码时，它会：

1. **解析正则表达式 `/ab+c/g`。**
2. **分析正则表达式的结构，并确定需要生成的机器码。**
3. **调用 `v8/src/regexp/riscv/regexp-macro-assembler-riscv.cc` 中的方法来生成 RISC-V 汇编代码。**  例如，对于 `b+`，可能会生成一个循环指令序列；对于捕获组（如果存在），会生成存储匹配位置的指令。
4. **生成的汇编代码会被 V8 引擎执行，以在字符串 `str` 中查找匹配项。**
5. **`regex.exec(str)` 方法的执行依赖于底层编译后的机器码。**

**代码逻辑推理 (假设输入与输出):**

假设我们有以下简化的正则表达式和输入：

**正则表达式:** `/a/` (匹配字符 "a")

**假设输入字符串:** `"banana"`

当 V8 编译并执行这个正则表达式时，`regexp-macro-assembler-riscv.cc` (简化版本) 可能会生成如下逻辑的 RISC-V 汇编代码：

**假设生成的汇编逻辑:**

1. **初始化:** 将输入字符串的指针、起始位置等加载到指定的寄存器 (`s1`, `s2` 等)。
2. **循环遍历字符串:**  循环遍历输入字符串的每个字符。
3. **加载当前字符:** 将当前字符加载到 `s5` 寄存器。
4. **比较字符:** 将 `s5` 寄存器的值与字符 'a' 的 ASCII 值进行比较。
5. **匹配成功:** 如果匹配成功，将当前位置信息存储到输出寄存器，并跳转到成功标签。
6. **匹配失败:** 如果匹配失败，继续遍历下一个字符。
7. **结束:** 如果遍历完整个字符串，跳转到失败标签。

**假设输入:**

- 输入字符串指针（假设在寄存器 `r10` 中）：指向 "banana" 的内存地址。
- 当前位置（相对于字符串末尾的负偏移，假设在寄存器 `s2` 中）：初始值为字符串长度的负值。

**预期输出 (基于 JavaScript 的 `regex.exec` 行为):**

第一次匹配：

- 匹配到的子字符串: "a"
- 匹配的起始索引: 1 (相对于 "banana")

第二次匹配：

- 匹配到的子字符串: "a"
- 匹配的起始索引: 3

第三次匹配：

- 匹配到的子字符串: "a"
- 匹配的起始索引: 5

**用户常见的编程错误 (与生成的代码间接相关):**

虽然用户不会直接编写或修改 `regexp-macro-assembler-riscv.cc` 的代码，但他们在编写 JavaScript 正则表达式时可能犯的错误会影响到 V8 生成的机器码的行为，并可能导致性能问题或错误的结果。一些常见的错误包括：

1. **回溯失控 (Catastrophic Backtracking):**  编写了导致正则表达式引擎进行大量无效回溯的正则表达式，例如 `a*b*c*d*e*f*g*h*i*j*k` 匹配一个不包含这些字符的长字符串。这会导致生成的机器码执行效率极低，消耗大量 CPU 时间。

   **JavaScript 例子:**

   ```javascript
   const regex = /a*b*c*d*e*f*g*h*i*j*k/;
   const str = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxx"; // 长字符串，不包含 a-k
   const start = performance.now();
   regex.test(str); // 执行时间会很长
   const end = performance.now();
   console.log(`执行时间: ${end - start} 毫秒`);
   ```

2. **过度使用捕获组:**  过多的捕获组会增加内存消耗和执行时间，因为引擎需要存储每个捕获组的匹配位置。

   **JavaScript 例子:**

   ```javascript
   const regex = /(very)?(long)?(and)?(complex)?(pattern)?/;
   const str = "simple";
   regex.test(str);
   ```

3. **不必要的复杂性:**  使用过于复杂的正则表达式来完成简单的匹配任务，导致生成的机器码不必要的复杂。

4. **忘记转义特殊字符:**  在正则表达式中忘记转义具有特殊含义的字符（例如 `.`、`*`、`+` 等），导致匹配行为不符合预期。

   **JavaScript 例子:**

   ```javascript
   const regex = /file.txt/; // 期望匹配 "file.txt"，但 "." 会匹配任意字符
   const str = "fileatxt";
   console.log(regex.test(str)); // 输出 true，不是期望的结果

   const correctRegex = /file\.txt/;
   console.log(correctRegex.test(str)); // 输出 false
   ```

**总结:**

`v8/src/regexp/riscv/regexp-macro-assembler-riscv.cc` 是 V8 引擎中至关重要的组件，它负责将高级的正则表达式操作转换为底层的 RISC-V 汇编指令。理解其功能有助于深入了解 V8 如何执行 JavaScript 正则表达式以及如何进行性能优化。该文件本身是 C++ 代码，与 Torque 无关。用户虽然不直接操作此文件，但其编写的 JavaScript 正则表达式会直接影响到此文件生成的机器码的效率和行为。

### 提示词
```
这是目录为v8/src/regexp/riscv/regexp-macro-assembler-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/riscv/regexp-macro-assembler-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/regexp/riscv/regexp-macro-assembler-riscv.h"

#include "src/codegen/assembler-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/logging/log.h"
#include "src/objects/objects-inl.h"
#include "src/regexp/regexp-macro-assembler.h"
#include "src/regexp/regexp-stack.h"
#include "src/snapshot/embedded/embedded-data-inl.h"
#include "src/strings/unicode.h"

namespace v8 {
namespace internal {

/* clang-format off
 * This assembler uses the following register assignment convention
 * - s1 : Pointer to current InstructionStream object including heap object tag.
 * - s2 : Current position in input, as negative offset from end of string.
 *        Please notice that this is the byte offset, not the character offset!
 * - s5 : Currently loaded character. Must be loaded using
 *        LoadCurrentCharacter before using any of the dispatch methods.
 * - s6 : Points to tip of backtrack stack
 * - s8 : End of input (points to byte after last character in input).
 * - fp : Frame pointer. Used to access arguments, local variables and
 *        RegExp registers.
 * - sp : Points to tip of C stack.
 *
 * The remaining registers are free for computations.
 * Each call to a public method should retain this convention.
 *
 * The stack will have the following structure:
 *
 *                                                                              kStackFrameHeader
 *  --- sp when called ---
 *  - fp[72]  ra                  Return from RegExp code (ra).                  kReturnAddress
 *  - fp[64]  old-fp              Old fp, callee saved(s9).
 *  - fp[0..63]  s1..s11          Callee-saved registers fp..s11.
 *  --- frame pointer ----
 *  - fp[-8]  frame marker
 *  - fp[-16]  Isolate* isolate   (address of the current isolate)               kIsolate
 *  - fp[-24] direct_call        (1 = direct call from JS, 0 = from runtime)    kDirectCall
 *  - fp[-32] output_size (may fit multiple sets of matches)                    kNumOutputRegisters
 *  - fp[-40] int* output (int[num_saved_registers_], for output).              kRegisterOutput
 *  - fp[-48] end of input       (address of end of string).                    kInputEnd
 *  - fp[-56] start of input     (address of first character in string).        kInputStart
 *  - fp[-64] start index        (character index of start).                    kStartIndex
 *  - fp[-72] void* input_string (location of a handle containing the string).  kInputString
 *  - fp[-80] success counter    (only for global regexps to count matches).    kSuccessfulCaptures
 *  - fp[-88] Offset of location before start of input (effectively character   kStringStartMinusOne
 *            position -1). Used to initialize capture registers to a
 *            non-position.
 *  --------- The following output registers are 32-bit values. ---------
 *  - fp[-96] register 0         (Only positions must be stored in the first    kRegisterZero
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
 *              int* output,
 *              int output_size,
 *              bool direct_call = false,
 *              Isolate* isolate,
 *              Address regexp);
 * The call is performed by NativeRegExpMacroAssembler::Execute()
 * (in regexp-macro-assembler.cc) via the GeneratedCode wrapper.
 *
 * clang-format on
 */

#define __ ACCESS_MASM(masm_)

RegExpMacroAssemblerRISCV::RegExpMacroAssemblerRISCV(Isolate* isolate,
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

RegExpMacroAssemblerRISCV::~RegExpMacroAssemblerRISCV() {
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

int RegExpMacroAssemblerRISCV::stack_limit_slack_slot_count() {
  return RegExpStack::kStackLimitSlackSlotCount;
}

void RegExpMacroAssemblerRISCV::AdvanceCurrentPosition(int by) {
  if (by != 0) {
    __ AddWord(current_input_offset(), current_input_offset(),
               Operand(by * char_size()));
  }
}

void RegExpMacroAssemblerRISCV::AdvanceRegister(int reg, int by) {
  DCHECK_LE(0, reg);
  DCHECK_GT(num_registers_, reg);
  if (by != 0) {
    __ LoadWord(a0, register_location(reg));
    __ AddWord(a0, a0, Operand(by));
    __ StoreWord(a0, register_location(reg));
  }
}

void RegExpMacroAssemblerRISCV::Backtrack() {
  CheckPreemption();
  if (has_backtrack_limit()) {
    Label next;
    __ LoadWord(a0, MemOperand(frame_pointer(), kBacktrackCountOffset));
    __ AddWord(a0, a0, Operand(1));
    __ StoreWord(a0, MemOperand(frame_pointer(), kBacktrackCountOffset));
    __ BranchShort(&next, ne, a0, Operand(backtrack_limit()));

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
  __ AddWord(a0, a0, code_pointer());
  __ Jump(a0);
}

void RegExpMacroAssemblerRISCV::Bind(Label* label) { __ bind(label); }

void RegExpMacroAssemblerRISCV::CheckCharacter(uint32_t c, Label* on_equal) {
  BranchOrBacktrack(on_equal, eq, current_character(), Operand(c));
}

void RegExpMacroAssemblerRISCV::CheckCharacterGT(base::uc16 limit,
                                                 Label* on_greater) {
  BranchOrBacktrack(on_greater, gt, current_character(), Operand(limit));
}

void RegExpMacroAssemblerRISCV::CheckAtStart(int cp_offset,
                                             Label* on_at_start) {
  __ LoadWord(a1, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
  __ AddWord(a0, current_input_offset(),
             Operand(-char_size() + cp_offset * char_size()));
  BranchOrBacktrack(on_at_start, eq, a0, Operand(a1));
}

void RegExpMacroAssemblerRISCV::CheckNotAtStart(int cp_offset,
                                                Label* on_not_at_start) {
  __ LoadWord(a1, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
  __ AddWord(a0, current_input_offset(),
             Operand(-char_size() + cp_offset * char_size()));
  BranchOrBacktrack(on_not_at_start, ne, a0, Operand(a1));
}

void RegExpMacroAssemblerRISCV::CheckCharacterLT(base::uc16 limit,
                                                 Label* on_less) {
  BranchOrBacktrack(on_less, lt, current_character(), Operand(limit));
}

void RegExpMacroAssemblerRISCV::CheckGreedyLoop(Label* on_equal) {
  Label backtrack_non_equal;
  __ Lw(a0, MemOperand(backtrack_stackpointer(), 0));
  __ BranchShort(&backtrack_non_equal, ne, current_input_offset(), Operand(a0));
  __ AddWord(backtrack_stackpointer(), backtrack_stackpointer(),
             Operand(kIntSize));
  __ bind(&backtrack_non_equal);
  BranchOrBacktrack(on_equal, eq, current_input_offset(), Operand(a0));
}

void RegExpMacroAssemblerRISCV::CallIsCharacterInRangeArray(
    const ZoneList<CharacterRange>* ranges) {
  static const int kNumArguments = 3;
  __ PrepareCallCFunction(kNumArguments, a0);

  __ mv(a0, current_character());
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

bool RegExpMacroAssemblerRISCV::CheckCharacterInRangeArray(
    const ZoneList<CharacterRange>* ranges, Label* on_in_range) {
  CallIsCharacterInRangeArray(ranges);
  BranchOrBacktrack(on_in_range, ne, a0, Operand(zero_reg));
  return true;
}

bool RegExpMacroAssemblerRISCV::CheckCharacterNotInRangeArray(
    const ZoneList<CharacterRange>* ranges, Label* on_not_in_range) {
  CallIsCharacterInRangeArray(ranges);
  BranchOrBacktrack(on_not_in_range, eq, a0, Operand(zero_reg));
  return true;
}

void RegExpMacroAssemblerRISCV::CheckNotBackReferenceIgnoreCase(
    int start_reg, bool read_backward, bool unicode, Label* on_no_match) {
  Label fallthrough;
  __ LoadWord(a0, register_location(start_reg));  // Index of start of capture.
  __ LoadWord(a1,
              register_location(start_reg + 1));  // Index of end of capture.
  __ SubWord(a1, a1, a0);                         // Length of capture.

  // At this point, the capture registers are either both set or both cleared.
  // If the capture length is zero, then the capture is either empty or cleared.
  // Fall through in both cases.
  __ BranchShort(&fallthrough, eq, a1, Operand(zero_reg));

  if (read_backward) {
    __ LoadWord(t1, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
    __ AddWord(t1, t1, a1);
    BranchOrBacktrack(on_no_match, le, current_input_offset(), Operand(t1));
  } else {
    __ AddWord(t1, a1, current_input_offset());
    // Check that there are enough characters left in the input.
    BranchOrBacktrack(on_no_match, gt, t1, Operand(zero_reg));
  }

  if (mode_ == LATIN1) {
    Label success;
    Label fail;
    Label loop_check;

    // a0 - offset of start of capture.
    // a1 - length of capture.
    __ AddWord(a0, a0, Operand(end_of_input_address()));
    __ AddWord(a2, end_of_input_address(), Operand(current_input_offset()));
    if (read_backward) {
      __ SubWord(a2, a2, Operand(a1));
    }
    __ AddWord(a1, a0, Operand(a1));

    // a0 - Address of start of capture.
    // a1 - Address of end of capture.
    // a2 - Address of current input position.

    Label loop;
    __ bind(&loop);
    __ Lbu(a3, MemOperand(a0, 0));
    __ addi(a0, a0, char_size());
    __ Lbu(a4, MemOperand(a2, 0));
    __ addi(a2, a2, char_size());

    __ BranchShort(&loop_check, eq, a4, Operand(a3));

    // Mismatch, try case-insensitive match (converting letters to lower-case).
    __ Or(a3, a3, Operand(0x20));  // Convert capture character to lower-case.
    __ Or(a4, a4, Operand(0x20));  // Also convert input character.
    __ BranchShort(&fail, ne, a4, Operand(a3));
    __ SubWord(a3, a3, Operand('a'));
    __ BranchShort(&loop_check, Uless_equal, a3, Operand('z' - 'a'));
    // Latin-1: Check for values in range [224,254] but not 247.
    __ SubWord(a3, a3, Operand(224 - 'a'));
    // Weren't Latin-1 letters.
    __ BranchShort(&fail, Ugreater, a3, Operand(254 - 224));
    // Check for 247.
    __ BranchShort(&fail, eq, a3, Operand(247 - 224));

    __ bind(&loop_check);
    __ Branch(&loop, lt, a0, Operand(a1));
    __ jmp(&success);

    __ bind(&fail);
    GoTo(on_no_match);

    __ bind(&success);
    // Compute new value of character position after the matched part.
    __ SubWord(current_input_offset(), a2, end_of_input_address());
    if (read_backward) {
      __ LoadWord(t1,
                  register_location(start_reg));  // Index of start of capture.
      __ LoadWord(
          a2, register_location(start_reg + 1));  // Index of end of capture.
      __ AddWord(current_input_offset(), current_input_offset(), Operand(t1));
      __ SubWord(current_input_offset(), current_input_offset(), Operand(a2));
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
    __ AddWord(a0, a0, Operand(end_of_input_address()));
    // Length of capture.
    __ mv(a2, a1);
    // Save length in callee-save register for use on return.
    __ mv(s3, a1);
    // Address of current input position.
    __ AddWord(a1, current_input_offset(), Operand(end_of_input_address()));
    if (read_backward) {
      __ SubWord(a1, a1, Operand(s3));
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
      __ SubWord(current_input_offset(), current_input_offset(), Operand(s3));
    } else {
      __ AddWord(current_input_offset(), current_input_offset(), Operand(s3));
    }
  }

  __ bind(&fallthrough);
}

void RegExpMacroAssemblerRISCV::CheckNotBackReference(int start_reg,
                                                      bool read_backward,
                                                      Label* on_no_match) {
  Label fallthrough;

  // Find length of back-referenced capture.
  __ LoadWord(a0, register_location(start_reg));
  __ LoadWord(a1, register_location(start_reg + 1));
  __ SubWord(a1, a1, a0);  // Length to check.

  // At this point, the capture registers are either both set or both cleared.
  // If the capture length is zero, then the capture is either empty or cleared.
  // Fall through in both cases.
  __ BranchShort(&fallthrough, eq, a1, Operand(zero_reg));

  if (read_backward) {
    __ LoadWord(t1, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
    __ AddWord(t1, t1, a1);
    BranchOrBacktrack(on_no_match, le, current_input_offset(), Operand(t1));
  } else {
    __ AddWord(t1, a1, current_input_offset());
    // Check that there are enough characters left in the input.
    BranchOrBacktrack(on_no_match, gt, t1, Operand(zero_reg));
  }

  // Compute pointers to match string and capture string.
  __ AddWord(a0, a0, Operand(end_of_input_address()));
  __ AddWord(a2, end_of_input_address(), Operand(current_input_offset()));
  if (read_backward) {
    __ SubWord(a2, a2, Operand(a1));
  }
  __ AddWord(a1, a1, Operand(a0));

  Label loop;
  __ bind(&loop);
  if (mode_ == LATIN1) {
    __ Lbu(a3, MemOperand(a0, 0));
    __ addi(a0, a0, char_size());
    __ Lbu(a4, MemOperand(a2, 0));
    __ addi(a2, a2, char_size());
  } else {
    DCHECK(mode_ == UC16);
    __ Lhu(a3, MemOperand(a0, 0));
    __ addi(a0, a0, char_size());
    __ Lhu(a4, MemOperand(a2, 0));
    __ addi(a2, a2, char_size());
  }
  BranchOrBacktrack(on_no_match, ne, a3, Operand(a4));
  __ Branch(&loop, lt, a0, Operand(a1));

  // Move current character position to position after match.
  __ SubWord(current_input_offset(), a2, end_of_input_address());
  if (read_backward) {
    __ LoadWord(t1,
                register_location(start_reg));  // Index of start of capture.
    __ LoadWord(a2,
                register_location(start_reg + 1));  // Index of end of capture.
    __ AddWord(current_input_offset(), current_input_offset(), Operand(t1));
    __ SubWord(current_input_offset(), current_input_offset(), Operand(a2));
  }
  __ bind(&fallthrough);
}

void RegExpMacroAssemblerRISCV::CheckNotCharacter(uint32_t c,
                                                  Label* on_not_equal) {
  BranchOrBacktrack(on_not_equal, ne, current_character(), Operand(c));
}

void RegExpMacroAssemblerRISCV::CheckCharacterAfterAnd(uint32_t c,
                                                       uint32_t mask,
                                                       Label* on_equal) {
  __ And(a0, current_character(), Operand(mask));
  Operand rhs = (c == 0) ? Operand(zero_reg) : Operand(c);
  BranchOrBacktrack(on_equal, eq, a0, rhs);
}

void RegExpMacroAssemblerRISCV::CheckNotCharacterAfterAnd(uint32_t c,
                                                          uint32_t mask,
                                                          Label* on_not_equal) {
  __ And(a0, current_character(), Operand(mask));
  Operand rhs = (c == 0) ? Operand(zero_reg) : Operand(c);
  BranchOrBacktrack(on_not_equal, ne, a0, rhs);
}

void RegExpMacroAssemblerRISCV::CheckNotCharacterAfterMinusAnd(
    base::uc16 c, base::uc16 minus, base::uc16 mask, Label* on_not_equal) {
  DCHECK_GT(String::kMaxUtf16CodeUnit, minus);
  __ SubWord(a0, current_character(), Operand(minus));
  __ And(a0, a0, Operand(mask));
  BranchOrBacktrack(on_not_equal, ne, a0, Operand(c));
}

void RegExpMacroAssemblerRISCV::CheckCharacterInRange(base::uc16 from,
                                                      base::uc16 to,
                                                      Label* on_in_range) {
  __ SubWord(a0, current_character(), Operand(from));
  // Unsigned lower-or-same condition.
  BranchOrBacktrack(on_in_range, Uless_equal, a0, Operand(to - from));
}

void RegExpMacroAssemblerRISCV::CheckCharacterNotInRange(
    base::uc16 from, base::uc16 to, Label* on_not_in_range) {
  __ SubWord(a0, current_character(), Operand(from));
  // Unsigned higher condition.
  BranchOrBacktrack(on_not_in_range, Ugreater, a0, Operand(to - from));
}

void RegExpMacroAssemblerRISCV::CheckBitInTable(Handle<ByteArray> table,
                                                Label* on_bit_set) {
  __ li(a0, Operand(table));
  if (mode_ != LATIN1 || kTableMask != String::kMaxOneByteCharCode) {
    __ And(a1, current_character(), Operand(kTableSize - 1));
    __ AddWord(a0, a0, a1);
  } else {
    __ AddWord(a0, a0, current_character());
  }

  __ Lbu(a0, FieldMemOperand(a0, OFFSET_OF_DATA_START(ByteArray)));
  BranchOrBacktrack(on_bit_set, ne, a0, Operand(zero_reg));
}

void RegExpMacroAssemblerRISCV::SkipUntilBitInTable(
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

bool RegExpMacroAssemblerRISCV::CheckSpecialClassRanges(
    StandardCharacterSet type, Label* on_no_match) {
  // Range checks (c in min..max) are generally implemented by an unsigned
  // (c - min) <= (max - min) check.
  switch (type) {
    case StandardCharacterSet::kWhitespace:
      // Match space-characters.
      if (mode_ == LATIN1) {
        // One byte space characters are '\t'..'\r', ' ' and \u00a0.
        Label success;
        __ BranchShort(&success, eq, current_character(), Operand(' '));
        // Check range 0x09..0x0D.
        __ SubWord(a0, current_character(), Operand('\t'));
        __ BranchShort(&success, Uless_equal, a0, Operand('\r' - '\t'));
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
      __ SubWord(a0, current_character(), Operand('0'));
      BranchOrBacktrack(on_no_match, Ugreater, a0, Operand('9' - '0'));
      return true;
    case StandardCharacterSet::kNotDigit:
      // Match non Latin1-digits.
      __ SubWord(a0, current_character(), Operand('0'));
      BranchOrBacktrack(on_no_match, Uless_equal, a0, Operand('9' - '0'));
      return true;
    case StandardCharacterSet::kNotLineTerminator: {
      // Match non-newlines (not 0x0A('\n'), 0x0D('\r'), 0x2028 and 0x2029).
      __ Xor(a0, current_character(), Operand(0x01));
      // See if current character is '\n'^1 or '\r'^1, i.e., 0x0B or 0x0C.
      __ SubWord(a0, a0, Operand(0x0B));
      BranchOrBacktrack(on_no_match, Uless_equal, a0, Operand(0x0C - 0x0B));
      if (mode_ == UC16) {
        // Compare original value to 0x2028 and 0x2029, using the already
        // computed (current_char ^ 0x01 - 0x0B). I.e., check for
        // 0x201D (0x2028 - 0x0B) or 0x201E.
        __ SubWord(a0, a0, Operand(0x2028 - 0x0B));
        BranchOrBacktrack(on_no_match, Uless_equal, a0, Operand(1));
      }
      return true;
    }
    case StandardCharacterSet::kLineTerminator: {
      // Match newlines (0x0A('\n'), 0x0D('\r'), 0x2028 and 0x2029).
      __ Xor(a0, current_character(), Operand(0x01));
      // See if current character is '\n'^1 or '\r'^1, i.e., 0x0B or 0x0C.
      __ SubWord(a0, a0, Operand(0x0B));
      if (mode_ == LATIN1) {
        BranchOrBacktrack(on_no_match, Ugreater, a0, Operand(0x0C - 0x0B));
      } else {
        Label done;
        BranchOrBacktrack(&done, Uless_equal, a0, Operand(0x0C - 0x0B));
        // Compare original value to 0x2028 and 0x2029, using the already
        // computed (current_char ^ 0x01 - 0x0B). I.e., check for
        // 0x201D (0x2028 - 0x0B) or 0x201E.
        __ SubWord(a0, a0, Operand(0x2028 - 0x0B));
        BranchOrBacktrack(on_no_match, Ugreater, a0, Operand(1));
        __ bind(&done);
      }
      return true;
    }
    case StandardCharacterSet::kWord: {
      if (mode_ != LATIN1) {
        // Table is 256 entries, so all Latin1 characters can be tested.
        BranchOrBacktrack(on_no_match, Ugreater, current_character(),
                          Operand('z'));
      }
      ExternalReference map = ExternalReference::re_word_character_map();
      __ li(a0, Operand(map));
      __ AddWord(a0, a0, current_character());
      __ Lbu(a0, MemOperand(a0, 0));
      BranchOrBacktrack(on_no_match, eq, a0, Operand(zero_reg));
      return true;
    }
    case StandardCharacterSet::kNotWord: {
      Label done;
      if (mode_ != LATIN1) {
        // Table is 256 entries, so all Latin1 characters can be tested.
        __ BranchShort(&done, Ugreater, current_character(), Operand('z'));
      }
      ExternalReference map = ExternalReference::re_word_character_map();
      __ li(a0, Operand(map));
      __ AddWord(a0, a0, current_character());
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
    // No custom implementation (yet): s(UC16), S(UC16).
    default:
      return false;
  }
}

void RegExpMacroAssemblerRISCV::Fail() {
  __ li(a0, Operand(FAILURE));
  __ jmp(&exit_label_);
}

void RegExpMacroAssemblerRISCV::LoadRegExpStackPointerFromMemory(Register dst) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_stack_pointer(isolate());
  __ li(dst, Operand(ref));
  __ LoadWord(dst, MemOperand(dst));
}

void RegExpMacroAssemblerRISCV::StoreRegExpStackPointerToMemory(
    Register src, Register scratch) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_stack_pointer(isolate());
  __ li(scratch, Operand(ref));
  __ StoreWord(src, MemOperand(scratch));
}

void RegExpMacroAssemblerRISCV::PushRegExpBasePointer(Register stack_pointer,
                                                      Register scratch) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ li(scratch, Operand(ref));
  __ LoadWord(scratch, MemOperand(scratch));
  __ SubWord(scratch, stack_pointer, scratch);
  __ StoreWord(scratch,
               MemOperand(frame_pointer(), kRegExpStackBasePointerOffset));
}

void RegExpMacroAssemblerRISCV::PopRegExpBasePointer(Register stack_pointer_out,
                                                     Register scratch) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ LoadWord(stack_pointer_out,
              MemOperand(frame_pointer(), kRegExpStackBasePointerOffset));
  __ li(scratch, Operand(ref));
  __ LoadWord(scratch, MemOperand(scratch));
  __ AddWord(stack_pointer_out, stack_pointer_out, scratch);
  StoreRegExpStackPointerToMemory(stack_pointer_out, scratch);
}

Handle<HeapObject> RegExpMacroAssemblerRISCV::GetCode(Handle<String> source,
                                                      RegExpFlags flags) {
  Label return_a0;
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

    // Actually emit code to start a new stack frame.
    // Push arguments
    // Save callee-save registers.
    // Start new stack frame.
    // Store link register in existing stack-cell.
    // Order here should correspond to order of offset constants in header file.
    // TODO(plind): we save fp..s11, but ONLY use s3 here - use the regs
    // or dont save.
    RegList registers_to_retain = {fp, s1, s2, s3, s4,  s5,
                                   s6, s7, s8, s9, s10, s11};
    DCHECK(registers_to_retain.Count() == kNumCalleeRegsToRetain);

    // The remaining arguments are passed in registers, e.g.by calling the code
    // entry as cast to a function with the signature:
    //
    // *int(*match)(String input_string,      // a0
    //             int start_offset,          // a1
    //             uint8_t* input_start,      // a2
    //             uint8_t* input_end,        // a3
    //             int* output,               // a4
    //             int output_size,           // a5
    //             int call_origin,           // a6
    //             Isolate* isolate,          // a7
    //             Address regexp);           // on the stack
    RegList argument_registers = {a0, a1, a2, a3, a4, a5, a6, a7};

    // According to MultiPush implementation, registers will be pushed in the
    // order of ra, fp, then s8, ..., s1, and finally a7,...a0
    __ MultiPush(RegList{ra} | registers_to_retain);

    // Set frame pointer in space for it if this is not a direct call
    // from generated code.
    __ AddWord(frame_pointer(), sp, Operand(0));
    static_assert(kFrameTypeOffset == -kSystemPointerSize);
    __ li(kScratchReg, Operand(StackFrame::TypeToMarker(StackFrame::IRREGEXP)));
    __ push(kScratchReg);
    __ MultiPush(argument_registers);
    static_assert(kSuccessfulCapturesOffset ==
                  kInputStringOffset - kSystemPointerSize);
    __ mv(a0, zero_reg);
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
    static_assert(backtrack_stackpointer() == s8);
    LoadRegExpStackPointerFromMemory(backtrack_stackpointer());
    // Store the regexp base pointer - we'll later restore it / write it to
    // memory when returning from this irregexp code object.
    PushRegExpBasePointer(backtrack_stackpointer(), a1);

    {
      // Check if we have space on the stack for registers.
      Label stack_limit_hit, stack_ok;

      ExternalReference stack_limit =
          ExternalReference::address_of_jslimit(masm_->isolate());
      __ li(a0, Operand(stack_limit));
      __ LoadWord(a0, MemOperand(a0));
      __ SubWord(a0, sp, a0);
      Operand extra_space_for_variables(num_registers_ * kSystemPointerSize);
      // Handle it if the stack pointer is already below the stack limit.
      __ Branch(&stack_limit_hit, le, a0, Operand(zero_reg));
      // Check if there is room for the variable number of registers above
      // the stack limit.
      __ Branch(&stack_ok, uge, a0, extra_space_for_variables);
      // Exit with OutOfMemory exception. There is not enough space on the stack
      // for our working registers.
      __ li(a0, Operand(EXCEPTION));
      __ jmp(&return_a0);

      __ bind(&stack_limit_hit);
      CallCheckStackGuardState(a0, extra_space_for_variables);
      // If returned value is non-zero, we exit with the returned value as
      // result.
      __ Branch(&return_a0, ne, a0, Operand(zero_reg));

      __ bind(&stack_ok);
    }
    // Allocate space on stack for registers.
    __ SubWord(sp, sp, Operand(num_registers_ * kSystemPointerSize));
    // Load string end.
    __ LoadWord(end_of_input_address(),
                MemOperand(frame_pointer(), kInputEndOffset));
    // Load input start.
    __ LoadWord(a0, MemOperand(frame_pointer(), kInputStartOffset));
    // Find negative length (offset of start relative to end).
    __ SubWord(current_input_offset(), a0, end_of_input_address());
    // Set a0 to address of char before start of the input string
    // (effectively string position -1).
    __ LoadWord(a1, MemOperand(frame_pointer(), kStartIndexOffset));
    __ SubWord(a0, current_input_offset(), Operand(char_size()));
    __ slli(t1, a1, (mode_ == UC16) ? 1 : 0);
    __ SubWord(a0, a0, t1);
    // Store this value in a local variable, for use when clearing
    // position registers.
    __ StoreWord(a0, MemOperand(frame_pointer(), kStringStartMinusOneOffset));

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
```