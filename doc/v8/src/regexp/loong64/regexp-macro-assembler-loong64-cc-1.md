Response:
The user wants a summary of the provided C++ code snippet from V8's `regexp-macro-assembler-loong64.cc`. The snippet is part of the code generation for regular expressions on the LOONG64 architecture.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Functionality:** The code snippet is within a larger class (`RegExpMacroAssemblerLOONG64`). This class is responsible for generating machine code (specifically LOONG64 assembly) to execute regular expressions. The function containing the snippet is `FinalizeCode`. This strongly suggests that the snippet is involved in generating the final code block for a successful regular expression match.

2. **Analyze the Code Blocks:**  Go through the code sequentially, understanding what each section does. Key operations observed are:
    * Loading input parameters from the stack frame (`frame_pointer()`). These include start and end of the input string, the starting index, and the output buffer.
    * Calculating the length of the matched input.
    * Iterating through captured groups (`num_saved_registers_`).
    * Storing capture group start and end indices in the output buffer. Notice the adjustments for `UC16` (UTF-16) encoding.
    * Handling global regular expressions: Checking if there's enough space for more matches, incrementing the success counter, and potentially restarting the match from the next position.
    * Handling non-global regular expressions: Setting the return value to indicate success.
    * Setting up the return sequence: Restoring the stack pointer and registers.
    * Handling backtrack, preemption, and stack overflow scenarios. These are separate code blocks with labels indicating their purpose.

3. **Identify Key Concepts:**  Several important concepts related to regular expression execution are present:
    * **Capture Groups:** The code iterates through and stores the positions of captured substrings.
    * **Global Matching:** The code handles the case where the `g` flag is set, requiring multiple matches.
    * **Backtracking:**  The `backtrack_label_` indicates support for backtracking, a fundamental mechanism in regex engines.
    * **Stack Management:** The code interacts with a "regexp stack" to store state during matching.
    * **Preemption and Stack Overflow:** The code includes checks for preemption (allowing other tasks to run) and stack overflow (preventing runaway recursion).
    * **Return Values:** The code sets specific return values to indicate success, failure, or other conditions.

4. **Relate to JavaScript (if applicable):**  Since this is part of V8, the regular expression engine used by Chrome and Node.js, the functionality directly relates to JavaScript's `RegExp` object and its methods like `exec`, `test`, `match`, `matchAll`, `replace`, and `replaceAll`. Think about how these methods would behave in cases with and without capture groups, and with the global flag.

5. **Consider User Errors:**  Think about common mistakes developers make when working with regular expressions that this code might be handling:
    * Incorrect handling of capture groups.
    * Forgetting the global flag when expecting multiple matches.
    * Writing overly complex regular expressions that could lead to excessive backtracking and potentially stack overflows.

6. **Structure the Answer:** Organize the findings into clear sections as requested by the prompt:
    * **Functionality:** Summarize the main purpose of the code.
    * **Torque:** Explain why it's not Torque code.
    * **JavaScript Relation:** Provide examples illustrating how the code's behavior manifests in JavaScript.
    * **Logic Inference:** Create a simple scenario with inputs and expected outputs.
    * **Common Errors:** Give practical examples of user mistakes.
    * **Overall Functionality (Summary):**  Reiterate the core purpose in concise terms, as this is the "Part 2" request.

7. **Refine and Elaborate:** Add detail and context to each section. For instance, when explaining the JavaScript relation, mention specific methods and how capture groups are accessed in JavaScript. When discussing logic inference, be precise with the input and output format.

By following these steps, a comprehensive and accurate answer addressing all parts of the user's request can be generated. The key is to understand the role of the code within the larger system and to connect the low-level assembly operations to higher-level programming concepts and common use cases.
```cpp
(a1, MemOperand(frame_pointer(), kInputStartOffset));
        __ Ld_d(a0, MemOperand(frame_pointer(), kRegisterOutputOffset));
        __ Ld_d(a2, MemOperand(frame_pointer(), kStartIndexOffset));
        __ Sub_d(a1, end_of_input_address(), a1);
        // a1 is length of input in bytes.
        if (mode_ == UC16) {
          __ srli_d(a1, a1, 1);
        }
        // a1 is length of input in characters.
        __ Add_d(a1, a1, Operand(a2));
        // a1 is length of string in characters.

        DCHECK_EQ(0, num_saved_registers_ % 2);
        // Always an even number of capture registers. This allows us to
        // unroll the loop once to add an operation between a load of a register
        // and the following use of that register.
        for (int i = 0; i < num_saved_registers_; i += 2) {
          __ Ld_d(a2, register_location(i));
          __ Ld_d(a3, register_location(i + 1));
          if (i == 0 && global_with_zero_length_check()) {
            // Keep capture start in a4 for the zero-length check later.
            __ mov(t3, a2);
          }
          if (mode_ == UC16) {
            __ srai_d(a2, a2, 1);
            __ Add_d(a2, a2, a1);
            __ srai_d(a3, a3, 1);
            __ Add_d(a3, a3, a1);
          } else {
            __ Add_d(a2, a1, Operand(a2));
            __ Add_d(a3, a1, Operand(a3));
          }
          // V8 expects the output to be an int32_t array.
          __ St_w(a2, MemOperand(a0, 0));
          __ Add_d(a0, a0, kIntSize);
          __ St_w(a3, MemOperand(a0, 0));
          __ Add_d(a0, a0, kIntSize);
        }
      }

      if (global()) {
        // Restart matching if the regular expression is flagged as global.
        __ Ld_d(a0, MemOperand(frame_pointer(), kSuccessfulCapturesOffset));
        __ Ld_d(a1, MemOperand(frame_pointer(), kNumOutputRegistersOffset));
        __ Ld_d(a2, MemOperand(frame_pointer(), kRegisterOutputOffset));
        // Increment success counter.
        __ Add_d(a0, a0, 1);
        __ St_d(a0, MemOperand(frame_pointer(), kSuccessfulCapturesOffset));
        // Capture results have been stored, so the number of remaining global
        // output registers is reduced by the number of stored captures.
        __ Sub_d(a1, a1, num_saved_registers_);
        // Check whether we have enough room for another set of capture results.
        //__ mov(v0, a0);
        __ Branch(&return_v0, lt, a1, Operand(num_saved_registers_));

        __ St_d(a1, MemOperand(frame_pointer(), kNumOutputRegistersOffset));
        // Advance the location for output.
        __ Add_d(a2, a2, num_saved_registers_ * kIntSize);
        __ St_d(a2, MemOperand(frame_pointer(), kRegisterOutputOffset));

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
          __ Add_d(current_input_offset(), current_input_offset(),
                   Operand((mode_ == UC16) ? 2 : 1));
          if (global_unicode()) CheckNotInSurrogatePair(0, &advance);
        }

        __ bind(&reload_string_start_minus_one);
        // Prepare a0 to initialize registers with its value in the next run.
        // Must be immediately before the jump to avoid clobbering.
        __ Ld_d(a0, MemOperand(frame_pointer(), kStringStartMinusOneOffset));

        __ Branch(&load_char_start_regexp);
      } else {
        __ li(a0, Operand(SUCCESS));
      }
    }
    // Exit and return v0.
    __ bind(&exit_label_);
    if (global()) {
      __ Ld_d(a0, MemOperand(frame_pointer(), kSuccessfulCapturesOffset));
    }

    __ bind(&return_v0);
    // Restore the original regexp stack pointer value (effectively, pop the
    // stored base pointer).
    PopRegExpBasePointer(backtrack_stackpointer(), a2);

    // Skip sp past regexp registers and local variables..
    __ mov(sp, frame_pointer());
    // Restore registers s0..s7 and return (restoring ra to pc).
    __ MultiPop({ra}, {fp}, registers_to_retain);
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
      // Put regexp engine registers on stack.
      StoreRegExpStackPointerToMemory(backtrack_stackpointer(), a1);

      CallCheckStackGuardState(a0);
      // If returning non-zero, we should end execution with the given
      // result as return value.
      __ Branch(&return_v0, ne, a0, Operand(zero_reg));

      LoadRegExpStackPointerFromMemory(backtrack_stackpointer());

      // String might have moved: Reload end of string from frame.
      __ Ld_d(end_of_input_address(),
              MemOperand(frame_pointer(), kInputEndOffset));

      SafeReturn();
    }

    // Backtrack stack overflow code.
    if (stack_overflow_label_.is_linked()) {
      SafeCallTarget(&stack_overflow_label_);
      StoreRegExpStackPointerToMemory(backtrack_stackpointer(), a1);
      // Reached if the backtrack-stack limit has been hit.

      // Call GrowStack(isolate).
      static const int kNumArguments = 1;
      __ PrepareCallCFunction(kNumArguments, a0);
      __ li(a0, Operand(ExternalReference::isolate_address(masm_->isolate())));
      ExternalReference grow_stack = ExternalReference::re_grow_stack();
      CallCFunctionFromIrregexpCode(grow_stack, kNumArguments);
      // If nullptr is returned, we have failed to grow the stack, and must exit
      // with a stack-overflow exception.
      __ Branch(&exit_with_exception, eq, a0, Operand(zero_reg));
      // Otherwise use return value as new stack pointer.
      __ mov(backtrack_stackpointer(), a0);
      SafeReturn();
    }

    if (exit_with_exception.is_linked()) {
      // If any of the code above needed to exit with an exception.
      __ bind(&exit_with_exception);
      // Exit with Result EXCEPTION(-1) to signal thrown exception.
      __ li(a0, Operand(EXCEPTION));
      __ jmp(&return_v0);
    }

    if (fallback_label_.is_linked()) {
      __ bind(&fallback_label_);
      __ li(a0, Operand(FALLBACK_TO_EXPERIMENTAL));
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
```

## 功能列举

这段 C++ 代码是 V8 引擎中 `RegExpMacroAssemblerLOONG64` 类的 `FinalizeCode` 方法的一部分。它的主要功能是：

1. **生成最终的正则表达式匹配成功后的机器码:** 当正则表达式匹配成功时，这段代码负责生成将匹配结果（包括捕获组信息）写入输出缓冲区的 LOONG64 汇编指令。

2. **处理捕获组:**
   - 它遍历所有捕获组 (`num_saved_registers_`)。
   - 从寄存器中加载每个捕获组的起始和结束位置。
   - 将这些位置信息转换为相对于输入字符串起始位置的字符索引。
   - 将这些索引以整数形式存储到预先分配的输出缓冲区中。

3. **处理全局匹配 (`global()`):**
   - 如果正则表达式设置了全局标志，匹配成功后，它会递增成功匹配的计数器。
   - 它会检查输出缓冲区是否还有空间存储更多的匹配结果。
   - 如果有空间，它会更新输出缓冲区的指针，准备进行下一次匹配。
   - 对于全局匹配中的零长度匹配，它会进行特殊处理，确保匹配位置在下一次迭代中前进。

4. **处理非全局匹配:**
   - 如果是非全局匹配，匹配成功后，它会设置返回值为 `SUCCESS`。

5. **生成返回代码:**
   - 它会生成代码来恢复调用前的状态（例如，弹出正则表达式栈基址）。
   - 将栈指针恢复到帧指针的位置。
   - 恢复之前保存的寄存器。
   - 执行返回指令。

6. **处理回溯 (`backtrack_label_`):**
   - 如果回溯标签被链接，表示需要生成回溯时的代码。

7. **处理抢占 (`check_preempt_label_`):**
   - 生成检查当前执行是否被抢占的代码。如果被抢占，则保存当前状态并安全返回。

8. **处理堆栈溢出 (`stack_overflow_label_`):**
   - 生成检查正则表达式栈是否溢出的代码。如果溢出，则尝试扩展堆栈。如果扩展失败，则抛出异常。

9. **处理异常和回退:**
   - 定义了处理异常和回退到实验性引擎的标签和逻辑。

10. **构建最终代码对象:**
    - 使用 `CodeDesc` 描述生成的机器码。
    - 创建 `Code` 对象，这是 V8 中可执行代码的表示。
    - 记录正则表达式代码创建事件。

## 关于 .tq 后缀

如果 `v8/src/regexp/loong64/regexp-macro-assembler-loong64.cc` 以 `.tq` 结尾，那么它的确是一个 **V8 Torque 源代码**。Torque 是 V8 用于生成高效内置函数和运行时代码的领域特定语言。但是，从您提供的代码片段来看，它使用的是底层的汇编指令（例如 `__ Ld_d`, `__ Add_d`, `__ jmp`），这表明它是一个 **C++ 源代码**，直接生成汇编代码，而不是 Torque 代码。

## 与 JavaScript 功能的关系

这段代码直接影响 JavaScript 中正则表达式的执行效率和功能。当 JavaScript 引擎执行一个正则表达式时，V8 会根据正则表达式的模式和标志生成对应的机器码，其中就可能包含这段代码生成的部分。

**JavaScript 示例：**

```javascript
const text = "abracadabra";
const regex = /a(b.?)a/g; // 包含捕获组且为全局匹配

let match;
while ((match = regex.exec(text)) !== null) {
  console.log(`Found match at index ${match.index}: ${match[0]}`);
  if (match.length > 1) {
    console.log(`  Captured group 1: ${match[1]}`);
  }
}
```

**解释：**

- 上述 JavaScript 代码定义了一个包含捕获组 `(b.?)` 并且带有全局标志 `g` 的正则表达式。
- 当 `regex.exec(text)` 被调用时，V8 的正则表达式引擎会尝试在 `text` 中找到匹配项。
- 如果找到匹配项，`FinalizeCode` 中生成的代码会负责：
    - 存储整个匹配项（例如 "abra"）。
    - 存储捕获组 `(b.?)` 匹配到的内容（例如 "br" 或 "b"）。
    - 因为是全局匹配，如果还有更多匹配项，引擎会继续查找。
- `match.index` 会给出匹配项的起始索引。
- `match[0]` 是整个匹配项。
- `match[1]` 是第一个捕获组匹配到的内容。

## 代码逻辑推理

**假设输入：**

- `text` (输入字符串): "test123test456"
- `regex` (正则表达式): /test(\d+)/
- 这是一个非全局匹配。

**执行流程 (简化):**

1. 引擎执行正则表达式，找到第一个匹配项 "test123"。
2. `FinalizeCode` 被调用。
3. `kInputStartOffset` 指向 "t"。
4. `kRegisterOutputOffset` 指向用于存储匹配结果的缓冲区。
5. `kStartIndexOffset` 是匹配开始的索引 (0)。
6. `num_saved_registers_` 为 2（捕获组的起始和结束位置）。
7. 代码会加载捕获组 `(\d+)` 匹配到的 "123" 在输入字符串中的起始和结束位置（假设存储在 `register_location(0)` 和 `register_location(1)`）。
8. 代码会将 "123" 的起始和结束索引相对于字符串起始位置计算出来，并存储到输出缓冲区中。
9. 因为是非全局匹配，代码会将返回值设置为 `SUCCESS`。

**预期输出 (写入输出缓冲区的内容):**

- 假设 "123" 的起始索引是 4，结束索引是 7。
- 输出缓冲区会存储两个整数：4 和 7。

## 用户常见的编程错误

1. **忘记全局标志导致只匹配第一个结果：**

   ```javascript
   const text = "apple banana apple";
   const regex = /apple/; // 没有全局标志 'g'
   const matches = text.match(regex);
   console.log(matches); // 输出: ['apple', index: 0, input: 'apple banana apple', groups: undefined]
   ```

   **问题：** 用户可能期望找到所有 "apple"，但由于缺少 `g` 标志，`match()` 方法只返回第一个匹配项。`FinalizeCode` 中处理全局匹配的部分就是为了解决这类情况。

2. **错误地假设捕获组的索引：**

   ```javascript
   const text = "colorless green ideas sleep furiously";
   const regex = /(.+?) (green) (.+?)/;
   const match = regex.exec(text);
   console.log(match[1]); // "colorless"
   console.log(match[2]); // "green"
   console.log(match[3]); // "ideas"
   ```

   **问题：** 用户需要清楚正则表达式中捕获组的顺序，才能正确访问 `match` 数组中的元素。如果捕获组的嵌套或顺序不符合预期，可能会导致获取到错误的匹配内容。`FinalizeCode` 正是按照捕获组在正则表达式中出现的顺序来存储其位置信息的。

3. **编写可能导致回溯失控的正则表达式：**

   ```javascript
   const text = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!";
   const regex = /(a+)+b/; // 可能会导致大量回溯
   const match = regex.exec(text); // 执行时间可能很长
   ```

   **问题：** 像 `(a+)+` 这样的结构可能会导致正则表达式引擎进行大量的回溯尝试，尤其是当输入字符串很长时，可能会导致性能问题甚至浏览器卡死。`FinalizeCode` 前面的代码负责执行匹配过程，而回溯机制是引擎的核心部分。

## 功能归纳 (第2部分)

这段代码片段是 V8 引擎中用于 **完成正则表达式成功匹配后处理的关键部分**。它的核心职责是：

- **提取并存储捕获组的位置信息** 到预定的输出缓冲区。
- **处理全局匹配的逻辑**，包括记录匹配次数、更新输出缓冲区指针以及为下一次匹配做准备。
- **生成最终的返回代码**，确保正则表达式执行的正确结束。
- **处理一些边缘情况**，如零长度匹配、抢占和堆栈溢出。

简而言之，这段代码负责将正则表达式匹配的抽象结果（哪些部分匹配了，哪些被捕获了）转换为 V8 可以理解和使用的数据结构，并为全局匹配的后续迭代做好准备。

### 提示词
```
这是目录为v8/src/regexp/loong64/regexp-macro-assembler-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/loong64/regexp-macro-assembler-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
(a1, MemOperand(frame_pointer(), kInputStartOffset));
        __ Ld_d(a0, MemOperand(frame_pointer(), kRegisterOutputOffset));
        __ Ld_d(a2, MemOperand(frame_pointer(), kStartIndexOffset));
        __ Sub_d(a1, end_of_input_address(), a1);
        // a1 is length of input in bytes.
        if (mode_ == UC16) {
          __ srli_d(a1, a1, 1);
        }
        // a1 is length of input in characters.
        __ Add_d(a1, a1, Operand(a2));
        // a1 is length of string in characters.

        DCHECK_EQ(0, num_saved_registers_ % 2);
        // Always an even number of capture registers. This allows us to
        // unroll the loop once to add an operation between a load of a register
        // and the following use of that register.
        for (int i = 0; i < num_saved_registers_; i += 2) {
          __ Ld_d(a2, register_location(i));
          __ Ld_d(a3, register_location(i + 1));
          if (i == 0 && global_with_zero_length_check()) {
            // Keep capture start in a4 for the zero-length check later.
            __ mov(t3, a2);
          }
          if (mode_ == UC16) {
            __ srai_d(a2, a2, 1);
            __ Add_d(a2, a2, a1);
            __ srai_d(a3, a3, 1);
            __ Add_d(a3, a3, a1);
          } else {
            __ Add_d(a2, a1, Operand(a2));
            __ Add_d(a3, a1, Operand(a3));
          }
          // V8 expects the output to be an int32_t array.
          __ St_w(a2, MemOperand(a0, 0));
          __ Add_d(a0, a0, kIntSize);
          __ St_w(a3, MemOperand(a0, 0));
          __ Add_d(a0, a0, kIntSize);
        }
      }

      if (global()) {
        // Restart matching if the regular expression is flagged as global.
        __ Ld_d(a0, MemOperand(frame_pointer(), kSuccessfulCapturesOffset));
        __ Ld_d(a1, MemOperand(frame_pointer(), kNumOutputRegistersOffset));
        __ Ld_d(a2, MemOperand(frame_pointer(), kRegisterOutputOffset));
        // Increment success counter.
        __ Add_d(a0, a0, 1);
        __ St_d(a0, MemOperand(frame_pointer(), kSuccessfulCapturesOffset));
        // Capture results have been stored, so the number of remaining global
        // output registers is reduced by the number of stored captures.
        __ Sub_d(a1, a1, num_saved_registers_);
        // Check whether we have enough room for another set of capture results.
        //__ mov(v0, a0);
        __ Branch(&return_v0, lt, a1, Operand(num_saved_registers_));

        __ St_d(a1, MemOperand(frame_pointer(), kNumOutputRegistersOffset));
        // Advance the location for output.
        __ Add_d(a2, a2, num_saved_registers_ * kIntSize);
        __ St_d(a2, MemOperand(frame_pointer(), kRegisterOutputOffset));

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
          __ Add_d(current_input_offset(), current_input_offset(),
                   Operand((mode_ == UC16) ? 2 : 1));
          if (global_unicode()) CheckNotInSurrogatePair(0, &advance);
        }

        __ bind(&reload_string_start_minus_one);
        // Prepare a0 to initialize registers with its value in the next run.
        // Must be immediately before the jump to avoid clobbering.
        __ Ld_d(a0, MemOperand(frame_pointer(), kStringStartMinusOneOffset));

        __ Branch(&load_char_start_regexp);
      } else {
        __ li(a0, Operand(SUCCESS));
      }
    }
    // Exit and return v0.
    __ bind(&exit_label_);
    if (global()) {
      __ Ld_d(a0, MemOperand(frame_pointer(), kSuccessfulCapturesOffset));
    }

    __ bind(&return_v0);
    // Restore the original regexp stack pointer value (effectively, pop the
    // stored base pointer).
    PopRegExpBasePointer(backtrack_stackpointer(), a2);

    // Skip sp past regexp registers and local variables..
    __ mov(sp, frame_pointer());
    // Restore registers s0..s7 and return (restoring ra to pc).
    __ MultiPop({ra}, {fp}, registers_to_retain);
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
      // Put regexp engine registers on stack.
      StoreRegExpStackPointerToMemory(backtrack_stackpointer(), a1);

      CallCheckStackGuardState(a0);
      // If returning non-zero, we should end execution with the given
      // result as return value.
      __ Branch(&return_v0, ne, a0, Operand(zero_reg));

      LoadRegExpStackPointerFromMemory(backtrack_stackpointer());

      // String might have moved: Reload end of string from frame.
      __ Ld_d(end_of_input_address(),
              MemOperand(frame_pointer(), kInputEndOffset));

      SafeReturn();
    }

    // Backtrack stack overflow code.
    if (stack_overflow_label_.is_linked()) {
      SafeCallTarget(&stack_overflow_label_);
      StoreRegExpStackPointerToMemory(backtrack_stackpointer(), a1);
      // Reached if the backtrack-stack limit has been hit.

      // Call GrowStack(isolate).
      static const int kNumArguments = 1;
      __ PrepareCallCFunction(kNumArguments, a0);
      __ li(a0, Operand(ExternalReference::isolate_address(masm_->isolate())));
      ExternalReference grow_stack = ExternalReference::re_grow_stack();
      CallCFunctionFromIrregexpCode(grow_stack, kNumArguments);
      // If nullptr is returned, we have failed to grow the stack, and must exit
      // with a stack-overflow exception.
      __ Branch(&exit_with_exception, eq, a0, Operand(zero_reg));
      // Otherwise use return value as new stack pointer.
      __ mov(backtrack_stackpointer(), a0);
      SafeReturn();
    }

    if (exit_with_exception.is_linked()) {
      // If any of the code above needed to exit with an exception.
      __ bind(&exit_with_exception);
      // Exit with Result EXCEPTION(-1) to signal thrown exception.
      __ li(a0, Operand(EXCEPTION));
      __ jmp(&return_v0);
    }

    if (fallback_label_.is_linked()) {
      __ bind(&fallback_label_);
      __ li(a0, Operand(FALLBACK_TO_EXPERIMENTAL));
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

void RegExpMacroAssemblerLOONG64::GoTo(Label* to) {
  if (to == nullptr) {
    Backtrack();
    return;
  }
  __ jmp(to);
  return;
}

void RegExpMacroAssemblerLOONG64::IfRegisterGE(int reg, int comparand,
                                               Label* if_ge) {
  __ Ld_d(a0, register_location(reg));
  BranchOrBacktrack(if_ge, ge, a0, Operand(comparand));
}

void RegExpMacroAssemblerLOONG64::IfRegisterLT(int reg, int comparand,
                                               Label* if_lt) {
  __ Ld_d(a0, register_location(reg));
  BranchOrBacktrack(if_lt, lt, a0, Operand(comparand));
}

void RegExpMacroAssemblerLOONG64::IfRegisterEqPos(int reg, Label* if_eq) {
  __ Ld_d(a0, register_location(reg));
  BranchOrBacktrack(if_eq, eq, a0, Operand(current_input_offset()));
}

RegExpMacroAssembler::IrregexpImplementation
RegExpMacroAssemblerLOONG64::Implementation() {
  return kLOONG64Implementation;
}

void RegExpMacroAssemblerLOONG64::PopCurrentPosition() {
  Pop(current_input_offset());
}

void RegExpMacroAssemblerLOONG64::PopRegister(int register_index) {
  Pop(a0);
  __ St_d(a0, register_location(register_index));
}

void RegExpMacroAssemblerLOONG64::PushBacktrack(Label* label) {
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
    //__ emit(0);
    __ nop();
    masm_->label_at_put(label, offset);
    __ bind(&after_constant);
    if (is_int12(cp_offset)) {
      __ Ld_wu(a0, MemOperand(code_pointer(), cp_offset));
    } else {
      __ Add_d(a0, code_pointer(), cp_offset);
      __ Ld_wu(a0, MemOperand(a0, 0));
    }
  }
  Push(a0);
  CheckStackLimit();
}

void RegExpMacroAssemblerLOONG64::PushCurrentPosition() {
  Push(current_input_offset());
}

void RegExpMacroAssemblerLOONG64::PushRegister(
    int register_index, StackCheckFlag check_stack_limit) {
  __ Ld_d(a0, register_location(register_index));
  Push(a0);
  if (check_stack_limit) CheckStackLimit();
}

void RegExpMacroAssemblerLOONG64::ReadCurrentPositionFromRegister(int reg) {
  __ Ld_d(current_input_offset(), register_location(reg));
}

void RegExpMacroAssemblerLOONG64::WriteStackPointerToRegister(int reg) {
  ExternalReference stack_top_address =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ li(a0, stack_top_address);
  __ Ld_d(a0, MemOperand(a0, 0));
  __ Sub_d(a0, backtrack_stackpointer(), a0);
  __ St_d(a0, register_location(reg));
}

void RegExpMacroAssemblerLOONG64::ReadStackPointerFromRegister(int reg) {
  ExternalReference stack_top_address =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ li(backtrack_stackpointer(), stack_top_address);
  __ Ld_d(backtrack_stackpointer(), MemOperand(backtrack_stackpointer(), 0));
  __ Ld_d(a0, register_location(reg));
  __ Add_d(backtrack_stackpointer(), backtrack_stackpointer(), Operand(a0));
}

void RegExpMacroAssemblerLOONG64::SetCurrentPositionFromEnd(int by) {
  Label after_position;
  __ Branch(&after_position, ge, current_input_offset(),
            Operand(-by * char_size()));
  __ li(current_input_offset(), -by * char_size());
  // On RegExp code entry (where this operation is used), the character before
  // the current position is expected to be already loaded.
  // We have advanced the position, so it's safe to read backwards.
  LoadCurrentCharacterUnchecked(-1, 1);
  __ bind(&after_position);
}

void RegExpMacroAssemblerLOONG64::SetRegister(int register_index, int to) {
  DCHECK(register_index >= num_saved_registers_);  // Reserved for positions!
  __ li(a0, Operand(to));
  __ St_d(a0, register_location(register_index));
}

bool RegExpMacroAssemblerLOONG64::Succeed() {
  __ jmp(&success_label_);
  return global();
}

void RegExpMacroAssemblerLOONG64::WriteCurrentPositionToRegister(
    int reg, int cp_offset) {
  if (cp_offset == 0) {
    __ St_d(current_input_offset(), register_location(reg));
  } else {
    __ Add_d(a0, current_input_offset(), Operand(cp_offset * char_size()));
    __ St_d(a0, register_location(reg));
  }
}

void RegExpMacroAssemblerLOONG64::ClearRegisters(int reg_from, int reg_to) {
  DCHECK(reg_from <= reg_to);
  __ Ld_d(a0, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
  for (int reg = reg_from; reg <= reg_to; reg++) {
    __ St_d(a0, register_location(reg));
  }
}

// Private methods:

void RegExpMacroAssemblerLOONG64::CallCheckStackGuardState(
    Register scratch, Operand extra_space) {
  DCHECK(!isolate()->IsGeneratingEmbeddedBuiltins());
  DCHECK(!masm_->options().isolate_independent_code);

  int stack_alignment = base::OS::ActivationFrameAlignment();

  // Align the stack pointer and save the original sp value on the stack.
  __ mov(scratch, sp);
  __ Sub_d(sp, sp, Operand(kSystemPointerSize));
  DCHECK(base::bits::IsPowerOfTwo(stack_alignment));
  __ And(sp, sp, Operand(-stack_alignment));
  __ St_d(scratch, MemOperand(sp, 0));

  // Extra space for variables.
  __ li(a3, extra_space);
  // RegExp code frame pointer.
  __ mov(a2, frame_pointer());
  // InstructionStream of self.
  __ li(a1, Operand(masm_->CodeObject()), CONSTANT_SIZE);

  // We need to make room for the return address on the stack.
  DCHECK(IsAligned(stack_alignment, kSystemPointerSize));
  __ Sub_d(sp, sp, Operand(stack_alignment));

  // a0 will point to the return address, placed by DirectCEntry.
  __ mov(a0, sp);

  ExternalReference stack_guard_check =
      ExternalReference::re_check_stack_guard_state();
  __ li(t7, Operand(stack_guard_check));

  EmbeddedData d = EmbeddedData::FromBlob();
  CHECK(Builtins::IsIsolateIndependent(Builtin::kDirectCEntry));
  Address entry = d.InstructionStartOf(Builtin::kDirectCEntry);
  __ li(kScratchReg, Operand(entry, RelocInfo::OFF_HEAP_TARGET));
  __ Call(kScratchReg);

  __ Ld_d(sp, MemOperand(sp, stack_alignment));

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

int64_t RegExpMacroAssemblerLOONG64::CheckStackGuardState(
    Address* return_address, Address raw_code, Address re_frame,
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

MemOperand RegExpMacroAssemblerLOONG64::register_location(int register_index) {
  DCHECK(register_index < (1 << 30));
  if (num_registers_ <= register_index) {
    num_registers_ = register_index + 1;
  }
  return MemOperand(frame_pointer(),
                    kRegisterZeroOffset - register_index * kSystemPointerSize);
}

void RegExpMacroAssemblerLOONG64::CheckPosition(int cp_offset,
                                                Label* on_outside_input) {
  if (cp_offset >= 0) {
    BranchOrBacktrack(on_outside_input, ge, current_input_offset(),
                      Operand(-cp_offset * char_size()));
  } else {
    __ Ld_d(a1, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
    __ Add_d(a0, current_input_offset(), Operand(cp_offset * char_size()));
    BranchOrBacktrack(on_outside_input, le, a0, Operand(a1));
  }
}

void RegExpMacroAssemblerLOONG64::BranchOrBacktrack(Label* to,
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

void RegExpMacroAssemblerLOONG64::SafeCall(Label* to, Condition cond,
                                           Register rs, const Operand& rt) {
  __ Branch(to, cond, rs, rt, true);
}

void RegExpMacroAssemblerLOONG64::SafeReturn() {
  __ Pop(ra);
  __ Add_d(t1, ra, Operand(masm_->CodeObject()));
  __ Jump(t1);
}

void RegExpMacroAssemblerLOONG64::SafeCallTarget(Label* name) {
  __ bind(name);
  __ Sub_d(ra, ra, Operand(masm_->CodeObject()));
  __ Push(ra);
}

void RegExpMacroAssemblerLOONG64::Push(Register source) {
  DCHECK(source != backtrack_stackpointer());
  __ Add_d(backtrack_stackpointer(), backtrack_stackpointer(),
           Operand(-kIntSize));
  __ St_w(source, MemOperand(backtrack_stackpointer(), 0));
}

void RegExpMacroAssemblerLOONG64::Pop(Register target) {
  DCHECK(target != backtrack_stackpointer());
  __ Ld_w(target, MemOperand(backtrack_stackpointer(), 0));
  __ Add_d(backtrack_stackpointer(), backtrack_stackpointer(), kIntSize);
}

void RegExpMacroAssemblerLOONG64::CallCFunctionFromIrregexpCode(
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

void RegExpMacroAssemblerLOONG64::CheckPreemption() {
  // Check for preemption.
  ExternalReference stack_limit =
      ExternalReference::address_of_jslimit(masm_->isolate());
  __ li(a0, Operand(stack_limit));
  __ Ld_d(a0, MemOperand(a0, 0));
  SafeCall(&check_preempt_label_, ls, sp, Operand(a0));
}

void RegExpMacroAssemblerLOONG64::CheckStackLimit() {
  ExternalReference stack_limit =
      ExternalReference::address_of_regexp_stack_limit_address(
          masm_->isolate());

  __ li(a0, Operand(stack_limit));
  __ Ld_d(a0, MemOperand(a0, 0));
  SafeCall(&stack_overflow_label_, ls, backtrack_stackpointer(), Operand(a0));
}

void RegExpMacroAssemblerLOONG64::LoadCurrentCharacterUnchecked(
    int cp_offset, int characters) {
  Register offset = current_input_offset();

  // If unaligned load/stores are not supported then this function must only
  // be used to load a single character at a time.
  if (!CanReadUnaligned()) {
    DCHECK_EQ(1, characters);
  }

  if (cp_offset != 0) {
    // t3 is not being used to store the capture start index at this point.
    __ Add_d(t3, current_input_offset(), Operand(cp_offset * char_size()));
    offset = t3;
  }

  if (mode_ == LATIN1) {
    if (characters == 4) {
      __ Ld_wu(current_character(), MemOperand(end_of_input_address(), offset));
    } else if (characters == 2) {
      __ Ld_hu(current_character(), MemOperand(end_of_input_address(), offset));
    } else {
      DCHECK_EQ(1, characters);
      __ Ld_bu(current_character(), MemOperand(end_of_input_address(), offset));
    }
  } else {
    DCHECK(mode_ == UC16);
    if (characters == 2) {
      __ Ld_wu(current_character(), MemOperand(end_of_input_address(), offset));
    } else {
      DCHECK_EQ(1, characters);
      __ Ld_hu(current_character(), MemOperand(end_of_input_address(), offset));
    }
  }
}

#undef __

}  // namespace internal
}  // namespace v8

#endif  // V8_TARGET_ARCH_LOONG64
```