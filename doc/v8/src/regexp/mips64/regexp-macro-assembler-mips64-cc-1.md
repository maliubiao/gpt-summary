Response:
The user wants to understand the functionality of the provided C++ code snippet from V8's `regexp-macro-assembler-mips64.cc` file. This file is responsible for generating MIPS64 assembly code for regular expression matching.

Here's a breakdown of the thought process to analyze the code and answer the user's request:

1. **Identify the Core Functionality:** The filename `regexp-macro-assembler-mips64.cc` strongly suggests that this code is part of V8's regular expression engine, specifically for the MIPS64 architecture. The "macro assembler" part indicates it provides an abstraction layer over raw assembly, making it easier to generate regexp matching code.

2. **Analyze the `GenerateCode` Function:** This is the primary function in the snippet and is responsible for generating the actual machine code for a given regular expression. The steps within this function are crucial for understanding the overall process.

3. **Deconstruct `GenerateCode`:**
    * **Initialization:** Setting up the execution environment, including labels for success, backtrack, etc., and initializing registers.
    * **Loading the First Character:** Handling the edge case of the beginning of the input string.
    * **Saving Registers:**  Managing the storage of captured groups.
    * **Main Matching Logic (Jump to `start_label_`):**  The actual regexp matching logic, which is not fully present in this snippet, is branched to here.
    * **Success Handling:**  If the regexp matches, this section handles capturing the matched substrings and potentially restarting the matching process for global regexps.
    * **Exit Code:** Returning the result of the matching process.
    * **Backtracking:**  Handling failed match attempts and trying alternative matching paths.
    * **Preemption Handling:**  Checking for interruptions or time limits.
    * **Stack Overflow Handling:**  Managing the backtrack stack size.
    * **Fallback:**  Potentially falling back to a different regexp implementation.
    * **Code Finalization:** Creating the final `Code` object.

4. **Examine Other Public Methods:** The other methods provide functionalities related to:
    * **Control Flow:** `GoTo`, branching instructions (`IfRegisterGE`, `IfRegisterLT`, `IfRegisterEqPos`).
    * **Stack Manipulation:** `PopCurrentPosition`, `PopRegister`, `PushBacktrack`, `PushCurrentPosition`, `PushRegister`.
    * **Register Management:** `ReadCurrentPositionFromRegister`, `WriteStackPointerToRegister`, `ReadStackPointerFromRegister`, `SetCurrentPositionFromEnd`, `SetRegister`, `ClearRegisters`.
    * **Success/Failure:** `Succeed`.
    * **Writing to Registers:** `WriteCurrentPositionToRegister`.
    * **Architecture Information:** `CanReadUnaligned`.

5. **Identify Key Concepts:**  Recognize terms like "backtrack," "capture registers," "global regexp," "stack overflow," "preemption," as these are fundamental to regular expression engines.

6. **Address Specific User Questions:**
    * **Functionality:** Summarize the core purpose as generating MIPS64 assembly code for regexp matching.
    * **`.tq` extension:** Explicitly state that this file is `.cc` and therefore not a Torque file.
    * **JavaScript Relationship:** Connect the C++ code to the JavaScript `RegExp` object and its `exec` and `test` methods, providing illustrative examples.
    * **Code Logic Inference:**  Choose a simple scenario (matching "ab" in "abc") and trace the likely register and memory manipulations. Highlight the role of registers like `current_input_offset`, capture registers, and the backtrack stack.
    * **Common Programming Errors:** Focus on issues related to capturing groups and global matching, as these are directly managed by this code.
    * **Overall Functionality (Part 2):**  Synthesize the detailed analysis into a concise summary of the file's role in the regexp matching process.

7. **Refine and Organize:** Present the information in a clear and structured manner, using headings, bullet points, and code examples where appropriate. Ensure the language is accessible and avoids overly technical jargon where possible. Emphasize the connection between the low-level assembly generation and the high-level JavaScript API.
好的，让我们来分析一下 `v8/src/regexp/mips64/regexp-macro-assembler-mips64.cc` 这个文件的功能。

**文件功能归纳:**

`v8/src/regexp/mips64/regexp-macro-assembler-mips64.cc` 是 V8 JavaScript 引擎中用于生成 **MIPS64 架构** 下执行正则表达式匹配的 **宏汇编器** 代码的文件。

**具体功能拆解:**

1. **生成机器码:**  该文件的核心功能是根据正则表达式的结构和操作，生成相应的 MIPS64 汇编指令。这些指令将被 CPU 执行，以完成字符串的匹配工作。

2. **正则表达式操作的抽象:** 它提供了一组高级的宏指令（由 C++ 代码实现），这些宏指令对应着正则表达式匹配过程中的各种操作，例如：
   - 加载字符 (`LoadCurrentCharacterUnchecked`)
   - 比较字符
   - 跳转 (`GoTo`)
   - 条件跳转 (`BranchOrBacktrack`, `IfRegisterGE`, `IfRegisterLT`, `IfRegisterEqPos`)
   - 寄存器操作 (`SetRegister`, `ReadCurrentPositionFromRegister`, `WriteCurrentPositionToRegister`)
   - 栈操作 (用于保存回溯信息和寄存器状态，如 `PushBacktrack`, `PushCurrentPosition`, `PopCurrentPosition`, `PushRegister`, `PopRegister`)
   - 调用 C++ 函数 (`CallCFunctionFromIrregexpCode`)
   - 检查栈溢出 (`CheckStackLimit`) 和抢占 (`CheckPreemption`)
   - 成功匹配和回溯 (`Succeed`, `Backtrack`)

3. **平台特定性:**  由于文件名中包含 "mips64"，很明显这个文件是专门为 MIPS64 架构设计的。这意味着它生成的汇编代码利用了 MIPS64 指令集的特性。

4. **与 `RegExpMacroAssembler` 基类的协作:**  这个 `.cc` 文件通常会继承一个通用的 `RegExpMacroAssembler` 基类（可能在 `v8/src/regexp/regexp-macro-assembler.h` 中定义）。基类定义了正则表达式匹配的通用接口，而 MIPS64 版本则负责实现这些接口，生成特定于 MIPS64 的代码。

**关于 `.tq` 结尾：**

根据您的描述，如果 `v8/src/regexp/mips64/regexp-macro-assembler-mips64.cc` 以 `.tq` 结尾，那么它将是 V8 的 **Torque** 源代码。 Torque 是一种用于生成高效 C++ 代码的领域特定语言，常用于 V8 的内部实现。 然而，根据您提供的文件名，它以 `.cc` 结尾，所以它是 **C++ 源代码**，而不是 Torque 源代码。

**与 JavaScript 功能的关系 (示例):**

`v8/src/regexp/mips64/regexp-macro-assembler-mips64.cc` 生成的代码直接支持 JavaScript 中的 `RegExp` 对象以及相关的字符串方法（如 `String.prototype.match()`, `String.prototype.search()`, `String.prototype.replace()` 等）。

**JavaScript 示例:**

```javascript
const regex = /ab+c/;
const str1 = 'abbc';
const str2 = 'adc';

console.log(regex.test(str1)); // 输出: true
console.log(regex.test(str2)); // 输出: false

const matchResult = str1.match(regex);
console.log(matchResult); // 输出: ['abbc', index: 0, input: 'abbc', groups: undefined]
```

当 JavaScript 引擎执行这些正则表达式操作时，V8 会根据正则表达式的模式，调用相应的 `RegExpMacroAssemblerMIPS` 方法来生成 MIPS64 机器码。这些机器码负责在 `str1` 和 `str2` 中查找与 `/ab+c/` 匹配的子字符串。

**代码逻辑推理 (假设输入与输出):**

假设我们有正则表达式 `/ab/` 和输入字符串 `"abc"`.

**假设输入:**

- 正则表达式模式: `/ab/`
- 输入字符串: `"abc"`
- 当前匹配位置 (初始): 0

**可能的代码逻辑 (简化):**

1. **加载第一个字符:**  从输入字符串的当前位置 (0) 加载字符 'a'。
2. **与模式的第一个字符比较:** 将加载的字符 'a' 与正则表达式的第一个字符 'a' 进行比较。如果匹配，则继续。
3. **加载下一个字符:** 从输入字符串的下一个位置 (1) 加载字符 'b'。
4. **与模式的第二个字符比较:** 将加载的字符 'b' 与正则表达式的第二个字符 'b' 进行比较。如果匹配，则匹配成功。
5. **输出:** 匹配成功，返回匹配的子字符串 "ab" 和其在输入字符串中的起始位置 0。

**假设输入:**

- 正则表达式模式: `/ab/`
- 输入字符串: `"acb"`
- 当前匹配位置 (初始): 0

**可能的代码逻辑 (简化):**

1. **加载第一个字符:** 从输入字符串的当前位置 (0) 加载字符 'a'。
2. **与模式的第一个字符比较:** 将加载的字符 'a' 与正则表达式的第一个字符 'a' 进行比较。匹配。
3. **加载下一个字符:** 从输入字符串的下一个位置 (1) 加载字符 'c'。
4. **与模式的第二个字符比较:** 将加载的字符 'c' 与正则表达式的第二个字符 'b' 进行比较。不匹配。
5. **回溯 (如果适用):** 如果正则表达式支持回溯（例如，包含 `*`, `+` 等量词），则可能会尝试其他匹配路径。在这个简单的例子中，没有其他路径可尝试。
6. **移动到下一个起始位置:** 将输入字符串的当前匹配位置移动到 1。
7. **重新开始匹配:** 从新的起始位置重复匹配过程。加载字符 'c'，与 'a' 不匹配。
8. **继续移动直到结束:**  继续移动起始位置直到字符串末尾。
9. **输出:** 匹配失败。

**涉及用户常见的编程错误 (示例):**

1. **捕获组的误用:** 用户可能期望捕获组会始终捕获到内容，但如果捕获组在可选的部分中，则可能不会被捕获。

   ```javascript
   const regex = /(a)?(b)/;
   const str = 'b';
   const match = str.match(regex);
   console.log(match); // 输出: ["b", undefined, "b", index: 0, input: "b", groups: undefined]
   // 注意第一个捕获组 (a) 是 undefined
   ```

   `regexp-macro-assembler-mips64.cc` 中的代码负责管理捕获组的寄存器，如果用户对捕获组的行为理解不当，可能会导致预期之外的结果。

2. **全局匹配时的状态管理错误:**  如果正则表达式带有 `g` 标志，则会在字符串中多次查找匹配项。用户可能错误地认为每次匹配都是独立的，而忽略了 `lastIndex` 属性的影响。

   ```javascript
   const regex = /a/g;
   const str = 'aba';
   console.log(regex.exec(str)); // 输出: ["a", index: 0, input: "aba", groups: undefined]
   console.log(regex.lastIndex);   // 输出: 1
   console.log(regex.exec(str)); // 输出: ["a", index: 2, input: "aba", groups: undefined]
   console.log(regex.lastIndex);   // 输出: 3
   console.log(regex.exec(str)); // 输出: null
   ```

   `regexp-macro-assembler-mips64.cc` 中的代码负责处理全局匹配的重启逻辑 (`global()` 部分的代码)，如果用户不理解全局匹配的工作方式，可能会遇到错误。

**第 2 部分功能归纳:**

您提供的代码片段是 `RegExpMacroAssemblerMIPS::GenerateCode` 方法的一部分，以及一些其他的成员方法。 这部分代码主要负责以下功能：

1. **正则表达式匹配的入口和初始化:**
   - 设置初始状态，例如加载起始字符，初始化寄存器。
   - 跳转到正则表达式匹配的核心逻辑 (`start_label_`)。

2. **成功匹配的处理:**
   - 当正则表达式匹配成功时 (`success_label_`) 执行的操作。
   - 将捕获组的信息保存到输出缓冲区中。
   - 如果是全局匹配 (`global()`)，则会处理重新开始匹配的逻辑，包括：
     - 更新成功匹配的计数器。
     - 检查是否有足够的输出空间存储更多的匹配结果。
     - 调整输出缓冲区的指针。
     - 特殊处理零长度匹配的情况，避免无限循环。
     - 跳转回加载字符并重新开始匹配。
   - 如果不是全局匹配，则设置返回值为成功 (`SUCCESS`).

3. **退出和返回:**
   - 定义了匹配完成后的退出点 (`exit_label_`, `return_v0`).
   - 恢复栈指针和寄存器状态。
   - 返回匹配结果（成功次数或 `SUCCESS` / `FAILURE` 等）。

4. **回溯处理:**
   - 定义了回溯的入口点 (`backtrack_label_`)，当匹配失败需要尝试其他路径时会跳转到这里。

5. **抢占处理:**
   - 定义了检查抢占的逻辑 (`check_preempt_label_`)，用于在长时间运行的正则表达式匹配过程中检查是否需要暂停执行。

6. **栈溢出处理:**
   - 定义了栈溢出时的处理逻辑 (`stack_overflow_label_`)，当回溯栈超出限制时会调用 `GrowStack` 尝试扩展栈空间。

7. **异常和回退处理:**
   - 定义了异常退出点 (`exit_with_exception`)。
   - 定义了回退到其他实现的逻辑 (`fallback_label_`).

8. **辅助方法:**
   - 提供了一系列辅助方法，用于执行具体的汇编指令，例如条件跳转、寄存器操作、栈操作等。这些方法是对 MIPS64 汇编指令的封装，使得生成代码更加方便。

**总结:**

`v8/src/regexp/mips64/regexp-macro-assembler-mips64.cc` 文件的核心职责是为 V8 JavaScript 引擎在 MIPS64 架构下高效地执行正则表达式匹配生成底层的机器代码。它通过提供一组抽象的宏指令，简化了汇编代码的生成过程，并处理了匹配过程中的各种细节，包括成功匹配、回溯、全局匹配、栈管理和异常处理等。 这段代码是 V8 正则表达式引擎在特定硬件架构上的关键组成部分。

Prompt: 
```
这是目录为v8/src/regexp/mips64/regexp-macro-assembler-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/mips64/regexp-macro-assembler-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
oad_char_start_regexp;
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
      // Fill saved registers with initial value = start offset - 1.
      if (num_saved_registers_ > 8) {
        // Address of register 0.
        __ Daddu(a1, frame_pointer(), Operand(kRegisterZeroOffset));
        __ li(a2, Operand(num_saved_registers_));
        Label init_loop;
        __ bind(&init_loop);
        __ Sd(a0, MemOperand(a1));
        __ Daddu(a1, a1, Operand(-kPointerSize));
        __ Dsubu(a2, a2, Operand(1));
        __ Branch(&init_loop, ne, a2, Operand(zero_reg));
      } else {
        for (int i = 0; i < num_saved_registers_; i++) {
          __ Sd(a0, register_location(i));
        }
      }
    }

    __ jmp(&start_label_);

    // Exit code:
    if (success_label_.is_linked()) {
      // Save captures when successful.
      __ bind(&success_label_);
      if (num_saved_registers_ > 0) {
        // Copy captures to output.
        __ Ld(a1, MemOperand(frame_pointer(), kInputStartOffset));
        __ Ld(a0, MemOperand(frame_pointer(), kRegisterOutputOffset));
        __ Ld(a2, MemOperand(frame_pointer(), kStartIndexOffset));
        __ Dsubu(a1, end_of_input_address(), a1);
        // a1 is length of input in bytes.
        if (mode_ == UC16) {
          __ dsrl(a1, a1, 1);
        }
        // a1 is length of input in characters.
        __ Daddu(a1, a1, Operand(a2));
        // a1 is length of string in characters.

        DCHECK_EQ(0, num_saved_registers_ % 2);
        // Always an even number of capture registers. This allows us to
        // unroll the loop once to add an operation between a load of a register
        // and the following use of that register.
        for (int i = 0; i < num_saved_registers_; i += 2) {
          __ Ld(a2, register_location(i));
          __ Ld(a3, register_location(i + 1));
          if (i == 0 && global_with_zero_length_check()) {
            // Keep capture start in a4 for the zero-length check later.
            __ mov(t3, a2);
          }
          if (mode_ == UC16) {
            __ dsra(a2, a2, 1);
            __ Daddu(a2, a2, a1);
            __ dsra(a3, a3, 1);
            __ Daddu(a3, a3, a1);
          } else {
            __ Daddu(a2, a1, Operand(a2));
            __ Daddu(a3, a1, Operand(a3));
          }
          // V8 expects the output to be an int32_t array.
          __ Sw(a2, MemOperand(a0));
          __ Daddu(a0, a0, kIntSize);
          __ Sw(a3, MemOperand(a0));
          __ Daddu(a0, a0, kIntSize);
        }
      }

      if (global()) {
        // Restart matching if the regular expression is flagged as global.
        __ Ld(a0, MemOperand(frame_pointer(), kSuccessfulCapturesOffset));
        __ Ld(a1, MemOperand(frame_pointer(), kNumOutputRegistersOffset));
        __ Ld(a2, MemOperand(frame_pointer(), kRegisterOutputOffset));
        // Increment success counter.
        __ Daddu(a0, a0, 1);
        __ Sd(a0, MemOperand(frame_pointer(), kSuccessfulCapturesOffset));
        // Capture results have been stored, so the number of remaining global
        // output registers is reduced by the number of stored captures.
        __ Dsubu(a1, a1, num_saved_registers_);
        // Check whether we have enough room for another set of capture results.
        __ mov(v0, a0);
        __ Branch(&return_v0, lt, a1, Operand(num_saved_registers_));

        __ Sd(a1, MemOperand(frame_pointer(), kNumOutputRegistersOffset));
        // Advance the location for output.
        __ Daddu(a2, a2, num_saved_registers_ * kIntSize);
        __ Sd(a2, MemOperand(frame_pointer(), kRegisterOutputOffset));

        // Restore the original regexp stack pointer value (effectively, pop the
        // stored base pointer).
        PopRegExpBasePointer(backtrack_stackpointer(), a2);

        Label reload_string_start_minus_one;

        if (global_with_zero_length_check()) {
          // Special case for zero-length matches.
          // t3: capture start index
          // Not a zero-length match, restart.
          __ Branch(&reload_string_start_minus_one, ne, current_input_offset(),
                    Operand(t3));
          // Offset from the end is zero if we already reached the end.
          __ Branch(&exit_label_, eq, current_input_offset(),
                    Operand(zero_reg));
          // Advance current position after a zero-length match.
          Label advance;
          __ bind(&advance);
          __ Daddu(current_input_offset(), current_input_offset(),
                   Operand((mode_ == UC16) ? 2 : 1));
          if (global_unicode()) CheckNotInSurrogatePair(0, &advance);
        }

        __ bind(&reload_string_start_minus_one);
        // Prepare a0 to initialize registers with its value in the next run.
        // Must be immediately before the jump to avoid clobbering.
        __ Ld(a0, MemOperand(frame_pointer(), kStringStartMinusOneOffset));

        __ Branch(&load_char_start_regexp);
      } else {
        __ li(v0, Operand(SUCCESS));
      }
    }
    // Exit and return v0.
    __ bind(&exit_label_);
    if (global()) {
      __ Ld(v0, MemOperand(frame_pointer(), kSuccessfulCapturesOffset));
    }

    __ bind(&return_v0);
    // Restore the original regexp stack pointer value (effectively, pop the
    // stored base pointer).
    PopRegExpBasePointer(backtrack_stackpointer(), a1);

    // Skip sp past regexp registers and local variables..
    __ mov(sp, frame_pointer());
    // Restore registers s0..s7 and return (restoring ra to pc).
    __ MultiPop(registers_to_retain | ra);
    __ Ret();

    // Backtrack code (branch target for conditional backtracks).
    if (backtrack_label_.is_linked()) {
      __ bind(&backtrack_label_);
      Backtrack();
    }

    Label exit_with_exception;

    // Preempt-code.
    if (check_preempt_label_.is_linked()) {
      SafeCallTarget(&check_preempt_label_);
      StoreRegExpStackPointerToMemory(backtrack_stackpointer(), a0);

      CallCheckStackGuardState(a0);
      // If returning non-zero, we should end execution with the given
      // result as return value.
      __ Branch(&return_v0, ne, v0, Operand(zero_reg));

      LoadRegExpStackPointerFromMemory(backtrack_stackpointer());

      // String might have moved: Reload end of string from frame.
      __ Ld(end_of_input_address(),
            MemOperand(frame_pointer(), kInputEndOffset));
      SafeReturn();
    }

    // Backtrack stack overflow code.
    if (stack_overflow_label_.is_linked()) {
      SafeCallTarget(&stack_overflow_label_);
      StoreRegExpStackPointerToMemory(backtrack_stackpointer(), a0);
      // Reached if the backtrack-stack limit has been hit.

      // Call GrowStack(isolate)
      static constexpr int kNumArguments = 1;
      __ PrepareCallCFunction(kNumArguments, a0);
      __ li(a0, Operand(ExternalReference::isolate_address(masm_->isolate())));
      ExternalReference grow_stack = ExternalReference::re_grow_stack();
      CallCFunctionFromIrregexpCode(grow_stack, kNumArguments);
      // If nullptr is returned, we have failed to grow the stack, and must exit
      // with a stack-overflow exception.
      __ Branch(&exit_with_exception, eq, v0, Operand(zero_reg));
      // Otherwise use return value as new stack pointer.
      __ mov(backtrack_stackpointer(), v0);
      SafeReturn();
    }

    if (exit_with_exception.is_linked()) {
      // If any of the code above needed to exit with an exception.
      __ bind(&exit_with_exception);
      // Exit with Result EXCEPTION(-1) to signal thrown exception.
      __ li(v0, Operand(EXCEPTION));
      __ jmp(&return_v0);
    }

    if (fallback_label_.is_linked()) {
      __ bind(&fallback_label_);
      __ li(v0, Operand(FALLBACK_TO_EXPERIMENTAL));
      __ jmp(&return_v0);
    }
  }

  CodeDesc code_desc;
  masm_->GetCode(isolate(), &code_desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate(), code_desc, CodeKind::REGEXP)
          .set_self_reference(masm_->CodeObject())
          .set_empty_source_position_table()
          .Build();
  LOG(masm_->isolate(),
      RegExpCodeCreateEvent(Cast<AbstractCode>(code), source, flags));
  return Cast<HeapObject>(code);
}

void RegExpMacroAssemblerMIPS::GoTo(Label* to) {
  if (to == nullptr) {
    Backtrack();
    return;
  }
  __ jmp(to);
  return;
}

void RegExpMacroAssemblerMIPS::IfRegisterGE(int reg,
                                            int comparand,
                                            Label* if_ge) {
  __ Ld(a0, register_location(reg));
  BranchOrBacktrack(if_ge, ge, a0, Operand(comparand));
}

void RegExpMacroAssemblerMIPS::IfRegisterLT(int reg,
                                            int comparand,
                                            Label* if_lt) {
  __ Ld(a0, register_location(reg));
  BranchOrBacktrack(if_lt, lt, a0, Operand(comparand));
}

void RegExpMacroAssemblerMIPS::IfRegisterEqPos(int reg,
                                               Label* if_eq) {
  __ Ld(a0, register_location(reg));
  BranchOrBacktrack(if_eq, eq, a0, Operand(current_input_offset()));
}

RegExpMacroAssembler::IrregexpImplementation
    RegExpMacroAssemblerMIPS::Implementation() {
  return kMIPSImplementation;
}

void RegExpMacroAssemblerMIPS::PopCurrentPosition() {
  Pop(current_input_offset());
}

void RegExpMacroAssemblerMIPS::PopRegister(int register_index) {
  Pop(a0);
  __ Sd(a0, register_location(register_index));
}

void RegExpMacroAssemblerMIPS::PushBacktrack(Label* label) {
  if (label->is_bound()) {
    int target = label->pos();
    __ li(a0,
          Operand(target + InstructionStream::kHeaderSize - kHeapObjectTag));
  } else {
    Assembler::BlockTrampolinePoolScope block_trampoline_pool(masm_.get());
    Label after_constant;
    __ Branch(&after_constant);
    int offset = masm_->pc_offset();
    int cp_offset = offset + InstructionStream::kHeaderSize - kHeapObjectTag;
    __ emit(0);
    masm_->label_at_put(label, offset);
    __ bind(&after_constant);
    if (is_int16(cp_offset)) {
      __ Lwu(a0, MemOperand(code_pointer(), cp_offset));
    } else {
      __ Daddu(a0, code_pointer(), cp_offset);
      __ Lwu(a0, MemOperand(a0, 0));
    }
  }
  Push(a0);
  CheckStackLimit();
}

void RegExpMacroAssemblerMIPS::PushCurrentPosition() {
  Push(current_input_offset());
}

void RegExpMacroAssemblerMIPS::PushRegister(int register_index,
                                            StackCheckFlag check_stack_limit) {
  __ Ld(a0, register_location(register_index));
  Push(a0);
  if (check_stack_limit) CheckStackLimit();
}

void RegExpMacroAssemblerMIPS::ReadCurrentPositionFromRegister(int reg) {
  __ Ld(current_input_offset(), register_location(reg));
}

void RegExpMacroAssemblerMIPS::WriteStackPointerToRegister(int reg) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ li(a0, Operand(ref));
  __ Ld(a0, MemOperand(a0));
  __ Dsubu(a0, backtrack_stackpointer(), a0);
  __ Sd(a0, register_location(reg));
}

void RegExpMacroAssemblerMIPS::ReadStackPointerFromRegister(int reg) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ li(a0, Operand(ref));
  __ Ld(a0, MemOperand(a0));
  __ Ld(backtrack_stackpointer(), register_location(reg));
  __ Daddu(backtrack_stackpointer(), backtrack_stackpointer(), Operand(a0));
}

void RegExpMacroAssemblerMIPS::SetCurrentPositionFromEnd(int by) {
  Label after_position;
  __ Branch(&after_position,
            ge,
            current_input_offset(),
            Operand(-by * char_size()));
  __ li(current_input_offset(), -by * char_size());
  // On RegExp code entry (where this operation is used), the character before
  // the current position is expected to be already loaded.
  // We have advanced the position, so it's safe to read backwards.
  LoadCurrentCharacterUnchecked(-1, 1);
  __ bind(&after_position);
}

void RegExpMacroAssemblerMIPS::SetRegister(int register_index, int to) {
  DCHECK(register_index >= num_saved_registers_);  // Reserved for positions!
  __ li(a0, Operand(to));
  __ Sd(a0, register_location(register_index));
}

bool RegExpMacroAssemblerMIPS::Succeed() {
  __ jmp(&success_label_);
  return global();
}

void RegExpMacroAssemblerMIPS::WriteCurrentPositionToRegister(int reg,
                                                              int cp_offset) {
  if (cp_offset == 0) {
    __ Sd(current_input_offset(), register_location(reg));
  } else {
    __ Daddu(a0, current_input_offset(), Operand(cp_offset * char_size()));
    __ Sd(a0, register_location(reg));
  }
}

void RegExpMacroAssemblerMIPS::ClearRegisters(int reg_from, int reg_to) {
  DCHECK(reg_from <= reg_to);
  __ Ld(a0, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
  for (int reg = reg_from; reg <= reg_to; reg++) {
    __ Sd(a0, register_location(reg));
  }
}

bool RegExpMacroAssemblerMIPS::CanReadUnaligned() const { return false; }

// Private methods:

void RegExpMacroAssemblerMIPS::CallCheckStackGuardState(Register scratch,
                                                        Operand extra_space) {
  DCHECK(!isolate()->IsGeneratingEmbeddedBuiltins());
  DCHECK(!masm_->options().isolate_independent_code);

  int stack_alignment = base::OS::ActivationFrameAlignment();

  // Align the stack pointer and save the original sp value on the stack.
  __ mov(scratch, sp);
  __ Dsubu(sp, sp, Operand(kPointerSize));
  DCHECK(base::bits::IsPowerOfTwo(stack_alignment));
  __ And(sp, sp, Operand(-stack_alignment));
  __ Sd(scratch, MemOperand(sp));

  // Extra space for variables to consider in stack check.
  __ li(a3, extra_space);
  // RegExp code frame pointer.
  __ mov(a2, frame_pointer());
  // InstructionStream of self.
  __ li(a1, Operand(masm_->CodeObject()), CONSTANT_SIZE);

  // We need to make room for the return address on the stack.
  DCHECK(IsAligned(stack_alignment, kPointerSize));
  __ Dsubu(sp, sp, Operand(stack_alignment));

  // a0 will point to the return address, placed by DirectCEntry.
  __ mov(a0, sp);

  ExternalReference stack_guard_check =
      ExternalReference::re_check_stack_guard_state();
  __ li(t9, Operand(stack_guard_check));

  EmbeddedData d = EmbeddedData::FromBlob();
  CHECK(Builtins::IsIsolateIndependent(Builtin::kDirectCEntry));
  Address entry = d.InstructionStartOf(Builtin::kDirectCEntry);
  __ li(kScratchReg, Operand(entry, RelocInfo::OFF_HEAP_TARGET));
  __ Call(kScratchReg);

  __ Ld(sp, MemOperand(sp, stack_alignment + kCArgsSlotsSize));

  __ li(code_pointer(), Operand(masm_->CodeObject()));
}

// Helper function for reading a value out of a stack frame.
template <typename T>
static T& frame_entry(Address re_frame, int frame_offset) {
  return reinterpret_cast<T&>(Memory<int32_t>(re_frame + frame_offset));
}

template <typename T>
static T* frame_entry_address(Address re_frame, int frame_offset) {
  return reinterpret_cast<T*>(re_frame + frame_offset);
}

int64_t RegExpMacroAssemblerMIPS::CheckStackGuardState(Address* return_address,
                                                       Address raw_code,
                                                       Address re_frame,
                                                       uintptr_t extra_space) {
  Tagged<InstructionStream> re_code =
      Cast<InstructionStream>(Tagged<Object>(raw_code));
  return NativeRegExpMacroAssembler::CheckStackGuardState(
      frame_entry<Isolate*>(re_frame, kIsolateOffset),
      static_cast<int>(frame_entry<int64_t>(re_frame, kStartIndexOffset)),
      static_cast<RegExp::CallOrigin>(
          frame_entry<int64_t>(re_frame, kDirectCallOffset)),
      return_address, re_code,
      frame_entry_address<Address>(re_frame, kInputStringOffset),
      frame_entry_address<const uint8_t*>(re_frame, kInputStartOffset),
      frame_entry_address<const uint8_t*>(re_frame, kInputEndOffset),
      extra_space);
}

MemOperand RegExpMacroAssemblerMIPS::register_location(int register_index) {
  DCHECK(register_index < (1<<30));
  if (num_registers_ <= register_index) {
    num_registers_ = register_index + 1;
  }
  return MemOperand(frame_pointer(),
                    kRegisterZeroOffset - register_index * kPointerSize);
}

void RegExpMacroAssemblerMIPS::CheckPosition(int cp_offset,
                                             Label* on_outside_input) {
  if (cp_offset >= 0) {
    BranchOrBacktrack(on_outside_input, ge, current_input_offset(),
                      Operand(-cp_offset * char_size()));
  } else {
    __ Ld(a1, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
    __ Daddu(a0, current_input_offset(), Operand(cp_offset * char_size()));
    BranchOrBacktrack(on_outside_input, le, a0, Operand(a1));
  }
}

void RegExpMacroAssemblerMIPS::BranchOrBacktrack(Label* to,
                                                 Condition condition,
                                                 Register rs,
                                                 const Operand& rt) {
  if (condition == al) {  // Unconditional.
    if (to == nullptr) {
      Backtrack();
      return;
    }
    __ jmp(to);
    return;
  }
  if (to == nullptr) {
    __ Branch(&backtrack_label_, condition, rs, rt);
    return;
  }
  __ Branch(to, condition, rs, rt);
}

void RegExpMacroAssemblerMIPS::SafeCall(Label* to,
                                        Condition cond,
                                        Register rs,
                                        const Operand& rt) {
  __ BranchAndLink(to, cond, rs, rt);
}

void RegExpMacroAssemblerMIPS::SafeReturn() {
  __ pop(ra);
  __ Daddu(t1, ra, Operand(masm_->CodeObject()));
  __ Jump(t1);
}

void RegExpMacroAssemblerMIPS::SafeCallTarget(Label* name) {
  __ bind(name);
  __ Dsubu(ra, ra, Operand(masm_->CodeObject()));
  __ push(ra);
}

void RegExpMacroAssemblerMIPS::Push(Register source) {
  DCHECK(source != backtrack_stackpointer());
  __ Daddu(backtrack_stackpointer(),
          backtrack_stackpointer(),
          Operand(-kIntSize));
  __ Sw(source, MemOperand(backtrack_stackpointer()));
}

void RegExpMacroAssemblerMIPS::Pop(Register target) {
  DCHECK(target != backtrack_stackpointer());
  __ Lw(target, MemOperand(backtrack_stackpointer()));
  __ Daddu(backtrack_stackpointer(), backtrack_stackpointer(), kIntSize);
}

void RegExpMacroAssemblerMIPS::CallCFunctionFromIrregexpCode(
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

void RegExpMacroAssemblerMIPS::CheckPreemption() {
  // Check for preemption.
  ExternalReference stack_limit =
      ExternalReference::address_of_jslimit(masm_->isolate());
  __ li(a0, Operand(stack_limit));
  __ Ld(a0, MemOperand(a0));
  SafeCall(&check_preempt_label_, ls, sp, Operand(a0));
}

void RegExpMacroAssemblerMIPS::CheckStackLimit() {
  ExternalReference stack_limit =
      ExternalReference::address_of_regexp_stack_limit_address(
          masm_->isolate());

  __ li(a0, Operand(stack_limit));
  __ Ld(a0, MemOperand(a0));
  SafeCall(&stack_overflow_label_, ls, backtrack_stackpointer(), Operand(a0));
}

void RegExpMacroAssemblerMIPS::LoadCurrentCharacterUnchecked(int cp_offset,
                                                             int characters) {
  Register offset = current_input_offset();
  if (cp_offset != 0) {
    // t3 is not being used to store the capture start index at this point.
    __ Daddu(t3, current_input_offset(), Operand(cp_offset * char_size()));
    offset = t3;
  }
  // We assume that we cannot do unaligned loads on MIPS, so this function
  // must only be used to load a single character at a time.
  DCHECK_EQ(1, characters);
  __ Daddu(t1, end_of_input_address(), Operand(offset));
  if (mode_ == LATIN1) {
    __ Lbu(current_character(), MemOperand(t1, 0));
  } else {
    DCHECK(mode_ == UC16);
    __ Lhu(current_character(), MemOperand(t1, 0));
  }
}

#undef __

}  // namespace internal
}  // namespace v8

#endif  // V8_TARGET_ARCH_MIPS64

"""


```