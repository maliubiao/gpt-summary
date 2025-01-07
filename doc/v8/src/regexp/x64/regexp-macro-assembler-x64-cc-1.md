Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/regexp/x64/regexp-macro-assembler-x64.cc`. I need to analyze the code and identify its main responsibilities within the V8 JavaScript engine.

Here's a breakdown of the code's key aspects:

1. **RegExp Macro Assembler:** The name itself suggests it's involved in generating machine code for regular expression matching. The `X64` part indicates it's specifically for the x64 architecture.

2. **Stack Management:**  The code extensively manipulates a custom "regexp stack" using registers like `backtrack_stackpointer()`. This stack is used for backtracking during regex matching.

3. **Register Usage:**  It defines and uses several registers (e.g., `rdi`, `rsi`, `rax`, `rbp`) for specific purposes like storing the current position, input string, and temporary values.

4. **Code Generation:**  The code uses `MacroAssembler` (`masm_`) to emit x64 instructions. Labels and jumps are used for control flow within the generated code.

5. **Stack Frame Setup:**  It sets up a manual stack frame (`FrameScope`) specifically for regular expression execution.

6. **Parameter Handling:** It retrieves and stores parameters passed to the regex matching function (e.g., input string, start index).

7. **Backtracking:** The presence of `backtrack_label_` and functions like `PushBacktrack`, `Backtrack` indicate the implementation of a backtracking algorithm for regex matching.

8. **Global Regexps:**  The code handles global regular expressions, including restarting the matching process after a successful match.

9. **Stack Overflow Handling:** It includes checks for stack overflow and a mechanism to grow the stack if necessary.

10. **Preemption Handling:**  It checks for preemption to allow the JavaScript engine to interrupt long-running regex executions.

11. **Success and Failure:** It defines `success_label_` and uses return codes (e.g., `SUCCESS`, `EXCEPTION`) to signal the outcome of the matching process.

12. **Code Finalization:** The `GetCode` function compiles the generated code into a `Code` object that can be executed by V8.

13. **Integration with V8:**  It uses V8-specific types and functions like `Isolate`, `Handle`, `Factory`, and `ExternalReference`.

Based on this analysis, I can formulate a comprehensive summary of the code's functionality. I also need to address the user's specific points about `.tq` files, JavaScript examples, input/output, and common errors.
这是对V8源代码文件 `v8/src/regexp/x64/regexp-macro-assembler-x64.cc` 功能的总结，延续了前一部分的分析。

**归纳总结：RegExpMacroAssemblerX64 的功能**

`v8/src/regexp/x64/regexp-macro-assembler-x64.cc` 文件是 V8 引擎中用于为 x64 架构生成正则表达式匹配机器码的关键组件。它提供了一组高级接口，允许开发者（通常是 V8 内部的其他正则表达式组件）以一种抽象的方式构建复杂的正则表达式匹配逻辑，而无需直接编写汇编代码。

其核心功能可以归纳为以下几点：

1. **生成 x64 机器码：** 该类继承自 `RegExpMacroAssembler`，专注于为 x64 架构生成高效的机器码，用于执行正则表达式匹配。它使用 `MacroAssembler` 类 (`masm_`) 来实现指令的发射。

2. **管理正则表达式执行状态：**  它维护和操作正则表达式执行所需的各种状态信息，例如：
    * **当前匹配位置 (`rdi`)**
    * **输入字符串 (`rsi`)**
    * **捕获组寄存器**
    * **回溯栈 (`backtrack_stackpointer()`)**
    * **程序计数器（通过 label 实现）**

3. **实现正则表达式操作：**  它提供了各种方法来实现正则表达式的原子操作，例如：
    * **字符匹配：**  加载和比较字符。
    * **位置操作：**  移动、保存和恢复匹配位置。
    * **捕获组管理：**  保存和读取捕获组的起始和结束位置。
    * **分支和循环：**  实现正则表达式的 `|` (或) 和 `*`, `+`, `?` (量词) 等结构。
    * **断言：**  实现 `^`, `$`, `\b` 等断言。

4. **支持回溯：**  通过维护一个回溯栈，它实现了正则表达式匹配中的回溯机制。当匹配失败时，可以回退到之前的状态并尝试其他匹配路径。

5. **处理全局匹配：**  它支持全局正则表达式的匹配，允许在字符串中查找所有匹配项。

6. **处理栈溢出：**  它包含对正则表达式执行栈溢出的检测和处理机制，必要时可以扩展栈空间。

7. **处理引擎中断 (preemption)：** 它允许 V8 引擎在正则表达式执行时间过长时中断执行，以保证 JavaScript 的响应性。

8. **与 V8 引擎集成：**  它使用 V8 的内部数据结构和 API，例如 `Isolate`，`Handle`，`Code` 等，以便生成的机器码能够被 V8 引擎正确加载和执行。

9. **性能优化：** 通过直接生成机器码，避免了解释执行的开销，从而提高正则表达式的匹配性能。针对 x64 架构进行了优化。

**关于您提出的其他问题：**

* **`.tq` 结尾：**  如果 `v8/src/regexp/x64/regexp-macro-assembler-x64.cc` 以 `.tq` 结尾，那它将是 V8 的 Torque 源代码。Torque 是一种 V8 内部的类型化的汇编语言，用于生成高效的 C++ 代码。当前文件名以 `.cc` 结尾，表明它是标准的 C++ 源代码。

* **与 JavaScript 功能的关系及示例：**  `RegExpMacroAssemblerX64` 直接支持 JavaScript 的 `RegExp` 对象的功能。当在 JavaScript 中执行正则表达式匹配时，V8 会使用这个类来生成执行匹配的机器码。

   ```javascript
   const regex = /ab*c/;
   const str = 'abbbc';
   const result = str.match(regex);
   console.log(result); // 输出: [ 'abbbc', index: 0, input: 'abbbc', groups: undefined ]

   const globalRegex = /t(e)(st(\d?))/g;
   const string = 'this is a test1 and a test';
   let match;
   while ((match = globalRegex.exec(string)) !== null) {
     console.log(`Found ${match[0]} code:${match[1]} number:${match[3]}`);
     // 输出:
     // Found test1 code:e number:st1
     // Found test code:e number:st
   }
   ```
   在幕后，当 V8 执行 `regex.test(str)` 或 `str.match(regex)` 等操作时，就会用到 `RegExpMacroAssemblerX64` 生成的机器码。

* **代码逻辑推理 (假设输入与输出)：**

   假设有以下正则表达式片段对应的代码逻辑：

   ```c++
   Label match_a;
   __ movzxbl(current_character(), Operand(rsi, rdi, times_1, 0)); // 加载当前字符
   __ cmpl(current_character(), Immediate('a'));                 // 比较是否为 'a'
   BranchOrBacktrack(equal, &match_a);                           // 如果相等则跳转

   // ... 其他代码 ...

   __ bind(&match_a);
   // ... 处理匹配到 'a' 的情况 ...
   ```

   **假设输入：** 当前匹配位置 `rdi` 指向输入字符串 "apple" 中的 'a' 字符。

   **预期输出：**
   1. `current_character()` 寄存器将被设置为 'a' 的 ASCII 值。
   2. `cmpl` 指令会比较 `current_character()` 和 'a'，结果为相等。
   3. `BranchOrBacktrack` 指令会执行跳转到 `match_a` 标签。

* **用户常见的编程错误：**

   虽然用户通常不直接与 `RegExpMacroAssemblerX64` 交互，但其背后的逻辑与正则表达式本身密切相关。常见的正则表达式错误，会导致生成的机器码执行不符合预期：

   1. **回溯过多导致性能问题：**  复杂的正则表达式，尤其是包含嵌套量词（如 `(a+)*`）时，可能导致大量回溯，使匹配效率极低，甚至导致浏览器卡死。

      ```javascript
      const regex = /a*b*c*/.exec("aaaaaaaaaaaaaaaaaaaaaaaaaaaaac"); // 效率高
      const regexBad = /(a+)+b/.exec("aaaaaaaaaaaaaaaaaaaaaaaaaaaaab"); // 效率极低，回溯过多
      ```

   2. **忘记转义特殊字符：**  在正则表达式中，某些字符具有特殊含义（如 `.`，`*`，`+` 等）。如果想要匹配这些字符本身，需要进行转义。

      ```javascript
      const text = "This is a test.";
      const regexWrong = /test./.test(text); // 错误：. 匹配任意字符
      const regexCorrect = /test\./.test(text); // 正确：\. 匹配句点
      ```

   3. **对全局匹配的理解偏差：**  使用 `g` 标志进行全局匹配时，需要注意 `RegExp.exec()` 方法的行为，它会记住上次匹配的位置。

      ```javascript
      const regex = /test/g;
      const str = 'test test test';
      let match;
      while ((match = regex.exec(str)) !== null) {
        console.log(`Found ${match[0]} at ${match.index}`);
      }
      // 如果不理解 exec 的状态，可能会认为只会匹配到第一个 "test"
      ```

总而言之，`v8/src/regexp/x64/regexp-macro-assembler-x64.cc` 是 V8 引擎中实现高性能正则表达式匹配的关键底层组件，它将高级的正则表达式操作转化为可以在 x64 架构上高效执行的机器码。用户虽然不直接操作它，但其功能直接影响 JavaScript 中正则表达式的执行效率和行为。

Prompt: 
```
这是目录为v8/src/regexp/x64/regexp-macro-assembler-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/x64/regexp-macro-assembler-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
_top_address(isolate());
  __ movq(scratch, Operand(rbp, kRegExpStackBasePointerOffset));
  __ movq(stack_pointer_out,
          __ ExternalReferenceAsOperand(ref, stack_pointer_out));
  __ subq(stack_pointer_out, scratch);
  StoreRegExpStackPointerToMemory(stack_pointer_out, scratch);
}

Handle<HeapObject> RegExpMacroAssemblerX64::GetCode(Handle<String> source,
                                                    RegExpFlags flags) {
  Label return_rax;
  // Finalize code - write the entry point code now we know how many registers
  // we need.
  __ bind(&entry_label_);

  // Tell the system that we have a stack frame. Because the type is MANUAL, no
  // physical frame is generated.
  FrameScope scope(&masm_, StackFrame::MANUAL);

  // Actually emit code to start a new stack frame. This pushes the frame type
  // marker into the stack slot at kFrameTypeOffset.
  static_assert(kFrameTypeOffset == -1 * kSystemPointerSize);
  __ EnterFrame(StackFrame::IRREGEXP);

  // Save parameters and callee-save registers. Order here should correspond
  //  to order of kBackup_ebx etc.
#ifdef V8_TARGET_OS_WIN
  // MSVC passes arguments in rcx, rdx, r8, r9, with backing stack slots.
  // Store register parameters in pre-allocated stack slots.
  __ movq(Operand(rbp, kInputStringOffset), kCArgRegs[0]);
  __ movq(Operand(rbp, kStartIndexOffset),
          kCArgRegs[1]);  // Passed as int32 in edx.
  __ movq(Operand(rbp, kInputStartOffset), kCArgRegs[2]);
  __ movq(Operand(rbp, kInputEndOffset), kCArgRegs[3]);

  static_assert(kNumCalleeSaveRegisters == 3);
  static_assert(kBackupRsiOffset == -2 * kSystemPointerSize);
  static_assert(kBackupRdiOffset == -3 * kSystemPointerSize);
  static_assert(kBackupRbxOffset == -4 * kSystemPointerSize);
  __ pushq(rsi);
  __ pushq(rdi);
  __ pushq(rbx);
#else
  // GCC passes arguments in rdi, rsi, rdx, rcx, r8, r9 (and then on stack).
  // Push register parameters on stack for reference.
  static_assert(kInputStringOffset == -2 * kSystemPointerSize);
  static_assert(kStartIndexOffset == -3 * kSystemPointerSize);
  static_assert(kInputStartOffset == -4 * kSystemPointerSize);
  static_assert(kInputEndOffset == -5 * kSystemPointerSize);
  static_assert(kRegisterOutputOffset == -6 * kSystemPointerSize);
  static_assert(kNumOutputRegistersOffset == -7 * kSystemPointerSize);
  __ pushq(kCArgRegs[0]);
  __ pushq(kCArgRegs[1]);
  __ pushq(kCArgRegs[2]);
  __ pushq(kCArgRegs[3]);
  __ pushq(r8);
  __ pushq(r9);

  static_assert(kNumCalleeSaveRegisters == 1);
  static_assert(kBackupRbxOffset == -8 * kSystemPointerSize);
  __ pushq(rbx);
#endif

  static_assert(kSuccessfulCapturesOffset ==
                kLastCalleeSaveRegister - kSystemPointerSize);
  __ Push(Immediate(0));  // Number of successful matches in a global regexp.
  static_assert(kStringStartMinusOneOffset ==
                kSuccessfulCapturesOffset - kSystemPointerSize);
  __ Push(Immediate(0));  // Make room for "string start - 1" constant.
  static_assert(kBacktrackCountOffset ==
                kStringStartMinusOneOffset - kSystemPointerSize);
  __ Push(Immediate(0));  // The backtrack counter.
  static_assert(kRegExpStackBasePointerOffset ==
                kBacktrackCountOffset - kSystemPointerSize);
  __ Push(Immediate(0));  // The regexp stack base ptr.

  // Initialize backtrack stack pointer. It must not be clobbered from here on.
  // Note the backtrack_stackpointer is *not* callee-saved.
  static_assert(backtrack_stackpointer() == rcx);
  LoadRegExpStackPointerFromMemory(backtrack_stackpointer());

  // Store the regexp base pointer - we'll later restore it / write it to
  // memory when returning from this irregexp code object.
  PushRegExpBasePointer(backtrack_stackpointer(), kScratchRegister);

  {
    // Check if we have space on the stack for registers.
    Label stack_limit_hit, stack_ok;

    ExternalReference stack_limit =
        ExternalReference::address_of_jslimit(isolate());
    __ movq(r9, rsp);
    __ Move(kScratchRegister, stack_limit);
    __ subq(r9, Operand(kScratchRegister, 0));
    Immediate extra_space_for_variables(num_registers_ * kSystemPointerSize);

    // Handle it if the stack pointer is already below the stack limit.
    __ j(below_equal, &stack_limit_hit);
    // Check if there is room for the variable number of registers above
    // the stack limit.
    __ cmpq(r9, extra_space_for_variables);
    __ j(above_equal, &stack_ok);
    // Exit with OutOfMemory exception. There is not enough space on the stack
    // for our working registers.
    __ Move(rax, EXCEPTION);
    __ jmp(&return_rax);

    __ bind(&stack_limit_hit);
    __ Move(code_object_pointer(), masm_.CodeObject());
    __ pushq(backtrack_stackpointer());
    // CallCheckStackGuardState preserves no registers beside rbp and rsp.
    CallCheckStackGuardState(extra_space_for_variables);
    __ popq(backtrack_stackpointer());
    __ testq(rax, rax);
    // If returned value is non-zero, we exit with the returned value as result.
    __ j(not_zero, &return_rax);

    __ bind(&stack_ok);
  }

  // Allocate space on stack for registers.
  __ AllocateStackSpace(num_registers_ * kSystemPointerSize);
  // Load string length.
  __ movq(rsi, Operand(rbp, kInputEndOffset));
  // Load input position.
  __ movq(rdi, Operand(rbp, kInputStartOffset));
  // Set up rdi to be negative offset from string end.
  __ subq(rdi, rsi);
  // Set rax to address of char before start of the string
  // (effectively string position -1).
  __ movq(rbx, Operand(rbp, kStartIndexOffset));
  __ negq(rbx);
  __ leaq(rax, Operand(rdi, rbx, CharSizeScaleFactor(), -char_size()));
  // Store this value in a local variable, for use when clearing
  // position registers.
  __ movq(Operand(rbp, kStringStartMinusOneOffset), rax);

  // Initialize code object pointer.
  __ Move(code_object_pointer(), masm_.CodeObject());

  Label load_char_start_regexp;  // Execution restarts here for global regexps.
  {
    Label start_regexp;

    // Load newline if index is at start, previous character otherwise.
    __ cmpl(Operand(rbp, kStartIndexOffset), Immediate(0));
    __ j(not_equal, &load_char_start_regexp, Label::kNear);
    __ Move(current_character(), '\n');
    __ jmp(&start_regexp, Label::kNear);

    // Global regexp restarts matching here.
    __ bind(&load_char_start_regexp);
    // Load previous char as initial value of current character register.
    LoadCurrentCharacterUnchecked(-1, 1);

    __ bind(&start_regexp);
  }

  // Initialize on-stack registers.
  if (num_saved_registers_ > 0) {
    // Fill saved registers with initial value = start offset - 1
    // Fill in stack push order, to avoid accessing across an unwritten
    // page (a problem on Windows).
    if (num_saved_registers_ > 8) {
      __ Move(r9, kRegisterZeroOffset);
      Label init_loop;
      __ bind(&init_loop);
      __ movq(Operand(rbp, r9, times_1, 0), rax);
      __ subq(r9, Immediate(kSystemPointerSize));
      __ cmpq(r9, Immediate(kRegisterZeroOffset -
                            num_saved_registers_ * kSystemPointerSize));
      __ j(greater, &init_loop);
    } else {  // Unroll the loop.
      for (int i = 0; i < num_saved_registers_; i++) {
        __ movq(register_location(i), rax);
      }
    }
  }

  __ jmp(&start_label_);

  // Exit code:
  if (success_label_.is_linked()) {
    // Save captures when successful.
    __ bind(&success_label_);
    if (num_saved_registers_ > 0) {
      // copy captures to output
      __ movq(rdx, Operand(rbp, kStartIndexOffset));
      __ movq(rbx, Operand(rbp, kRegisterOutputOffset));
      __ movq(rcx, Operand(rbp, kInputEndOffset));
      __ subq(rcx, Operand(rbp, kInputStartOffset));
      if (mode_ == UC16) {
        __ leaq(rcx, Operand(rcx, rdx, CharSizeScaleFactor(), 0));
      } else {
        __ addq(rcx, rdx);
      }
      for (int i = 0; i < num_saved_registers_; i++) {
        __ movq(rax, register_location(i));
        if (i == 0 && global_with_zero_length_check()) {
          // Keep capture start in rdx for the zero-length check later.
          __ movq(rdx, rax);
        }
        __ addq(rax, rcx);  // Convert to index from start, not end.
        if (mode_ == UC16) {
          __ sarq(rax, Immediate(1));  // Convert byte index to character index.
        }
        __ movl(Operand(rbx, i * kIntSize), rax);
      }
    }

    if (global()) {
      // Restart matching if the regular expression is flagged as global.
      // Increment success counter.
      __ incq(Operand(rbp, kSuccessfulCapturesOffset));
      // Capture results have been stored, so the number of remaining global
      // output registers is reduced by the number of stored captures.
      __ movsxlq(rcx, Operand(rbp, kNumOutputRegistersOffset));
      __ subq(rcx, Immediate(num_saved_registers_));
      // Check whether we have enough room for another set of capture results.
      __ cmpq(rcx, Immediate(num_saved_registers_));
      __ j(less, &exit_label_);

      __ movq(Operand(rbp, kNumOutputRegistersOffset), rcx);
      // Advance the location for output.
      __ addq(Operand(rbp, kRegisterOutputOffset),
              Immediate(num_saved_registers_ * kIntSize));

      // Restore the original regexp stack pointer value (effectively, pop the
      // stored base pointer).
      PopRegExpBasePointer(backtrack_stackpointer(), kScratchRegister);

      Label reload_string_start_minus_one;

      if (global_with_zero_length_check()) {
        // Special case for zero-length matches.
        // rdx: capture start index
        __ cmpq(rdi, rdx);
        // Not a zero-length match, restart.
        __ j(not_equal, &reload_string_start_minus_one);
        // rdi (offset from the end) is zero if we already reached the end.
        __ testq(rdi, rdi);
        __ j(zero, &exit_label_, Label::kNear);
        // Advance current position after a zero-length match.
        Label advance;
        __ bind(&advance);
        if (mode_ == UC16) {
          __ addq(rdi, Immediate(2));
        } else {
          __ incq(rdi);
        }
        if (global_unicode()) CheckNotInSurrogatePair(0, &advance);
      }

      __ bind(&reload_string_start_minus_one);
      // Prepare rax to initialize registers with its value in the next run.
      // Must be immediately before the jump to avoid clobbering.
      __ movq(rax, Operand(rbp, kStringStartMinusOneOffset));

      __ jmp(&load_char_start_regexp);
    } else {
      __ Move(rax, SUCCESS);
    }
  }

  __ bind(&exit_label_);
  if (global()) {
    // Return the number of successful captures.
    __ movq(rax, Operand(rbp, kSuccessfulCapturesOffset));
  }

  __ bind(&return_rax);
  // Restore the original regexp stack pointer value (effectively, pop the
  // stored base pointer).
  PopRegExpBasePointer(backtrack_stackpointer(), kScratchRegister);

#ifdef V8_TARGET_OS_WIN
  // Restore callee save registers.
  __ leaq(rsp, Operand(rbp, kLastCalleeSaveRegister));
  static_assert(kNumCalleeSaveRegisters == 3);
  static_assert(kBackupRsiOffset == -2 * kSystemPointerSize);
  static_assert(kBackupRdiOffset == -3 * kSystemPointerSize);
  static_assert(kBackupRbxOffset == -4 * kSystemPointerSize);
  __ popq(rbx);
  __ popq(rdi);
  __ popq(rsi);
#else
  // Restore callee save register.
  static_assert(kNumCalleeSaveRegisters == 1);
  __ movq(rbx, Operand(rbp, kBackupRbxOffset));
#endif

  __ LeaveFrame(StackFrame::IRREGEXP);
  __ ret(0);

  // Backtrack code (branch target for conditional backtracks).
  if (backtrack_label_.is_linked()) {
    __ bind(&backtrack_label_);
    Backtrack();
  }

  Label exit_with_exception;

  // Preempt-code.
  if (check_preempt_label_.is_linked()) {
    SafeCallTarget(&check_preempt_label_);

    __ pushq(rdi);

    StoreRegExpStackPointerToMemory(backtrack_stackpointer(), kScratchRegister);

    CallCheckStackGuardState();
    __ testq(rax, rax);
    // If returning non-zero, we should end execution with the given
    // result as return value.
    __ j(not_zero, &return_rax);

    // Restore registers.
    __ Move(code_object_pointer(), masm_.CodeObject());
    __ popq(rdi);

    LoadRegExpStackPointerFromMemory(backtrack_stackpointer());

    // String might have moved: Reload esi from frame.
    __ movq(rsi, Operand(rbp, kInputEndOffset));
    SafeReturn();
  }

  // Backtrack stack overflow code.
  if (stack_overflow_label_.is_linked()) {
    SafeCallTarget(&stack_overflow_label_);
    // Reached if the backtrack-stack limit has been hit.

    PushCallerSavedRegisters();

    // Call GrowStack(isolate).

    StoreRegExpStackPointerToMemory(backtrack_stackpointer(), kScratchRegister);

    static constexpr int kNumArguments = 1;
    __ PrepareCallCFunction(kNumArguments);
    __ LoadAddress(kCArgRegs[0], ExternalReference::isolate_address(isolate()));

    ExternalReference grow_stack = ExternalReference::re_grow_stack();
    CallCFunctionFromIrregexpCode(grow_stack, kNumArguments);
    // If nullptr is returned, we have failed to grow the stack, and must exit
    // with a stack-overflow exception.
    __ testq(rax, rax);
    __ j(equal, &exit_with_exception);
    PopCallerSavedRegisters();
    // Otherwise use return value as new stack pointer.
    __ movq(backtrack_stackpointer(), rax);
    // Restore saved registers and continue.
    __ Move(code_object_pointer(), masm_.CodeObject());
    SafeReturn();
  }

  if (exit_with_exception.is_linked()) {
    // If any of the code above needed to exit with an exception.
    __ bind(&exit_with_exception);
    // Exit with Result EXCEPTION(-1) to signal thrown exception.
    __ Move(rax, EXCEPTION);
    __ jmp(&return_rax);
  }

  if (fallback_label_.is_linked()) {
    __ bind(&fallback_label_);
    __ Move(rax, FALLBACK_TO_EXPERIMENTAL);
    __ jmp(&return_rax);
  }

  FixupCodeRelativePositions();

  CodeDesc code_desc;
  Isolate* isolate = this->isolate();
  masm_.GetCode(isolate, &code_desc);
  Handle<Code> code = Factory::CodeBuilder(isolate, code_desc, CodeKind::REGEXP)
                          .set_self_reference(masm_.CodeObject())
                          .set_empty_source_position_table()
                          .Build();
  PROFILE(isolate,
          RegExpCodeCreateEvent(Cast<AbstractCode>(code), source, flags));
  return Cast<HeapObject>(code);
}

void RegExpMacroAssemblerX64::GoTo(Label* to) { BranchOrBacktrack(to); }

void RegExpMacroAssemblerX64::IfRegisterGE(int reg,
                                           int comparand,
                                           Label* if_ge) {
  __ cmpq(register_location(reg), Immediate(comparand));
  BranchOrBacktrack(greater_equal, if_ge);
}


void RegExpMacroAssemblerX64::IfRegisterLT(int reg,
                                           int comparand,
                                           Label* if_lt) {
  __ cmpq(register_location(reg), Immediate(comparand));
  BranchOrBacktrack(less, if_lt);
}


void RegExpMacroAssemblerX64::IfRegisterEqPos(int reg,
                                              Label* if_eq) {
  __ cmpq(rdi, register_location(reg));
  BranchOrBacktrack(equal, if_eq);
}


RegExpMacroAssembler::IrregexpImplementation
    RegExpMacroAssemblerX64::Implementation() {
  return kX64Implementation;
}


void RegExpMacroAssemblerX64::PopCurrentPosition() {
  Pop(rdi);
}


void RegExpMacroAssemblerX64::PopRegister(int register_index) {
  Pop(rax);
  __ movq(register_location(register_index), rax);
}


void RegExpMacroAssemblerX64::PushBacktrack(Label* label) {
  Push(label);
  CheckStackLimit();
}


void RegExpMacroAssemblerX64::PushCurrentPosition() {
  Push(rdi);
}


void RegExpMacroAssemblerX64::PushRegister(int register_index,
                                           StackCheckFlag check_stack_limit) {
  __ movq(rax, register_location(register_index));
  Push(rax);
  if (check_stack_limit) CheckStackLimit();
}

void RegExpMacroAssemblerX64::ReadCurrentPositionFromRegister(int reg) {
  __ movq(rdi, register_location(reg));
}


void RegExpMacroAssemblerX64::ReadPositionFromRegister(Register dst, int reg) {
  __ movq(dst, register_location(reg));
}

// Preserves a position-independent representation of the stack pointer in reg:
// reg = top - sp.
void RegExpMacroAssemblerX64::WriteStackPointerToRegister(int reg) {
  ExternalReference stack_top_address =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ movq(rax, __ ExternalReferenceAsOperand(stack_top_address, rax));
  __ subq(rax, backtrack_stackpointer());
  __ movq(register_location(reg), rax);
}

void RegExpMacroAssemblerX64::ReadStackPointerFromRegister(int reg) {
  ExternalReference stack_top_address =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ movq(backtrack_stackpointer(),
          __ ExternalReferenceAsOperand(stack_top_address,
                                        backtrack_stackpointer()));
  __ subq(backtrack_stackpointer(), register_location(reg));
}

void RegExpMacroAssemblerX64::SetCurrentPositionFromEnd(int by) {
  Label after_position;
  __ cmpq(rdi, Immediate(-by * char_size()));
  __ j(greater_equal, &after_position, Label::kNear);
  __ Move(rdi, -by * char_size());
  // On RegExp code entry (where this operation is used), the character before
  // the current position is expected to be already loaded.
  // We have advanced the position, so it's safe to read backwards.
  LoadCurrentCharacterUnchecked(-1, 1);
  __ bind(&after_position);
}


void RegExpMacroAssemblerX64::SetRegister(int register_index, int to) {
  DCHECK(register_index >= num_saved_registers_);  // Reserved for positions!
  __ movq(register_location(register_index), Immediate(to));
}


bool RegExpMacroAssemblerX64::Succeed() {
  __ jmp(&success_label_);
  return global();
}


void RegExpMacroAssemblerX64::WriteCurrentPositionToRegister(int reg,
                                                             int cp_offset) {
  if (cp_offset == 0) {
    __ movq(register_location(reg), rdi);
  } else {
    __ leaq(rax, Operand(rdi, cp_offset * char_size()));
    __ movq(register_location(reg), rax);
  }
}


void RegExpMacroAssemblerX64::ClearRegisters(int reg_from, int reg_to) {
  DCHECK(reg_from <= reg_to);
  __ movq(rax, Operand(rbp, kStringStartMinusOneOffset));
  for (int reg = reg_from; reg <= reg_to; reg++) {
    __ movq(register_location(reg), rax);
  }
}

// Private methods:

void RegExpMacroAssemblerX64::CallCheckStackGuardState(Immediate extra_space) {
  // This function call preserves no register values. Caller should
  // store anything volatile in a C call or overwritten by this function.
  static const int num_arguments = 4;
  __ PrepareCallCFunction(num_arguments);
#ifdef V8_TARGET_OS_WIN
  // Fourth argument: Extra space for variables.
  __ movq(kCArgRegs[3], extra_space);
  // Second argument: InstructionStream of self. (Do this before overwriting
  // r8 (kCArgRegs[2])).
  __ movq(kCArgRegs[1], code_object_pointer());
  // Third argument: RegExp code frame pointer.
  __ movq(kCArgRegs[2], rbp);
  // First argument: Next address on the stack (will be address of
  // return address).
  __ leaq(kCArgRegs[0], Operand(rsp, -kSystemPointerSize));
#else
  // Fourth argument: Extra space for variables.
  __ movq(kCArgRegs[3], extra_space);
  // Third argument: RegExp code frame pointer.
  __ movq(kCArgRegs[2], rbp);
  // Second argument: InstructionStream of self.
  __ movq(kCArgRegs[1], code_object_pointer());
  // First argument: Next address on the stack (will be address of
  // return address).
  __ leaq(kCArgRegs[0], Operand(rsp, -kSystemPointerSize));
#endif
  ExternalReference stack_check =
      ExternalReference::re_check_stack_guard_state();
  CallCFunctionFromIrregexpCode(stack_check, num_arguments);
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

int RegExpMacroAssemblerX64::CheckStackGuardState(Address* return_address,
                                                  Address raw_code,
                                                  Address re_frame,
                                                  uintptr_t extra_space) {
  Tagged<InstructionStream> re_code =
      Cast<InstructionStream>(Tagged<Object>(raw_code));
  return NativeRegExpMacroAssembler::CheckStackGuardState(
      frame_entry<Isolate*>(re_frame, kIsolateOffset),
      frame_entry<int>(re_frame, kStartIndexOffset),
      static_cast<RegExp::CallOrigin>(
          frame_entry<int>(re_frame, kDirectCallOffset)),
      return_address, re_code,
      frame_entry_address<Address>(re_frame, kInputStringOffset),
      frame_entry_address<const uint8_t*>(re_frame, kInputStartOffset),
      frame_entry_address<const uint8_t*>(re_frame, kInputEndOffset),
      extra_space);
}

Operand RegExpMacroAssemblerX64::register_location(int register_index) {
  DCHECK(register_index < (1<<30));
  if (num_registers_ <= register_index) {
    num_registers_ = register_index + 1;
  }
  return Operand(rbp,
                 kRegisterZeroOffset - register_index * kSystemPointerSize);
}


void RegExpMacroAssemblerX64::CheckPosition(int cp_offset,
                                            Label* on_outside_input) {
  if (cp_offset >= 0) {
    __ cmpl(rdi, Immediate(-cp_offset * char_size()));
    BranchOrBacktrack(greater_equal, on_outside_input);
  } else {
    __ leaq(rax, Operand(rdi, cp_offset * char_size()));
    __ cmpq(rax, Operand(rbp, kStringStartMinusOneOffset));
    BranchOrBacktrack(less_equal, on_outside_input);
  }
}

void RegExpMacroAssemblerX64::BranchOrBacktrack(Label* to) {
  if (to == nullptr) {
    Backtrack();
    return;
  }
  __ jmp(to);
}

void RegExpMacroAssemblerX64::BranchOrBacktrack(Condition condition,
                                                Label* to) {
  __ j(condition, to ? to : &backtrack_label_);
}

void RegExpMacroAssemblerX64::SafeCall(Label* to) {
  __ call(to);
}


void RegExpMacroAssemblerX64::SafeCallTarget(Label* label) {
  __ bind(label);
  __ subq(Operand(rsp, 0), code_object_pointer());
}


void RegExpMacroAssemblerX64::SafeReturn() {
  __ addq(Operand(rsp, 0), code_object_pointer());
  __ ret(0);
}


void RegExpMacroAssemblerX64::Push(Register source) {
  DCHECK(source != backtrack_stackpointer());
  // Notice: This updates flags, unlike normal Push.
  __ subq(backtrack_stackpointer(), Immediate(kIntSize));
  __ movl(Operand(backtrack_stackpointer(), 0), source);
}


void RegExpMacroAssemblerX64::Push(Immediate value) {
  // Notice: This updates flags, unlike normal Push.
  __ subq(backtrack_stackpointer(), Immediate(kIntSize));
  __ movl(Operand(backtrack_stackpointer(), 0), value);
}


void RegExpMacroAssemblerX64::FixupCodeRelativePositions() {
  for (int position : code_relative_fixup_positions_) {
    // The position succeeds a relative label offset from position.
    // Patch the relative offset to be relative to the InstructionStream object
    // pointer instead.
    int patch_position = position - kIntSize;
    int offset = masm_.long_at(patch_position);
    masm_.long_at_put(
        patch_position,
        offset + position + InstructionStream::kHeaderSize - kHeapObjectTag);
  }
  code_relative_fixup_positions_.Rewind(0);
}


void RegExpMacroAssemblerX64::Push(Label* backtrack_target) {
  __ subq(backtrack_stackpointer(), Immediate(kIntSize));
  __ movl(Operand(backtrack_stackpointer(), 0), backtrack_target);
  MarkPositionForCodeRelativeFixup();
}


void RegExpMacroAssemblerX64::Pop(Register target) {
  DCHECK(target != backtrack_stackpointer());
  __ movsxlq(target, Operand(backtrack_stackpointer(), 0));
  // Notice: This updates flags, unlike normal Pop.
  __ addq(backtrack_stackpointer(), Immediate(kIntSize));
}


void RegExpMacroAssemblerX64::Drop() {
  __ addq(backtrack_stackpointer(), Immediate(kIntSize));
}


void RegExpMacroAssemblerX64::CheckPreemption() {
  // Check for preemption.
  Label no_preempt;
  ExternalReference stack_limit =
      ExternalReference::address_of_jslimit(isolate());
  __ load_rax(stack_limit);
  __ cmpq(rsp, rax);
  __ j(above, &no_preempt);

  SafeCall(&check_preempt_label_);

  __ bind(&no_preempt);
}


void RegExpMacroAssemblerX64::CheckStackLimit() {
  Label no_stack_overflow;
  ExternalReference stack_limit =
      ExternalReference::address_of_regexp_stack_limit_address(isolate());
  __ load_rax(stack_limit);
  __ cmpq(backtrack_stackpointer(), rax);
  __ j(above, &no_stack_overflow);

  SafeCall(&stack_overflow_label_);

  __ bind(&no_stack_overflow);
}


void RegExpMacroAssemblerX64::LoadCurrentCharacterUnchecked(int cp_offset,
                                                            int characters) {
  if (mode_ == LATIN1) {
    if (characters == 4) {
      __ movl(current_character(), Operand(rsi, rdi, times_1, cp_offset));
    } else if (characters == 2) {
      __ movzxwl(current_character(), Operand(rsi, rdi, times_1, cp_offset));
    } else {
      DCHECK_EQ(1, characters);
      __ movzxbl(current_character(), Operand(rsi, rdi, times_1, cp_offset));
    }
  } else {
    DCHECK(mode_ == UC16);
    if (characters == 2) {
      __ movl(current_character(),
              Operand(rsi, rdi, times_1, cp_offset * sizeof(base::uc16)));
    } else {
      DCHECK_EQ(1, characters);
      __ movzxwl(current_character(),
                 Operand(rsi, rdi, times_1, cp_offset * sizeof(base::uc16)));
    }
  }
}

#undef __

}  // namespace internal
}  // namespace v8

#endif  // V8_TARGET_ARCH_X64

"""


```