Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/regexp/arm64/regexp-macro-assembler-arm64.cc`.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the core purpose:** The file name itself gives a strong hint: `regexp-macro-assembler-arm64.cc`. This suggests the code is responsible for generating machine code instructions specifically for regular expression matching on ARM64 architecture. The `MacroAssembler` part indicates it's a low-level code generation tool.

2. **Scan for key function names and patterns:**  Look for recurring patterns and function names that reveal the code's actions. Keywords like `Load`, `Store`, `Push`, `Pop`, `Get`, `Set`, `If`, `GoTo`, `Call`, `Check`, and labels (`Bind`) are important.

3. **Focus on the `RegExpMacroAssemblerARM64` class:** The code snippet is within this class. Its methods define the operations that can be performed during regular expression matching.

4. **Group related functionalities:**  Observe the code and group related functions. For instance, there's a set of functions dealing with the "RegExp stack pointer" and "RegExp base pointer". Another group handles pushing and popping data, and yet another deals with conditional jumps and comparisons.

5. **Analyze specific function functionalities:**
    * **Stack management:** `LoadRegExpStackPointerFromMemory`, `StoreRegExpStackPointerToMemory`, `PushRegExpBasePointer`, `PopRegExpBasePointer` clearly manage a dedicated stack for the regular expression engine.
    * **Code generation entry point:** `GetCode` is likely the main function to generate the actual machine code for the regular expression. Notice the setup of the stack frame, handling of arguments, and allocation of registers.
    * **Control flow:** `GoTo`, `IfRegisterGE`, `IfRegisterLT`, `IfRegisterEqPos` are about controlling the flow of execution within the generated code.
    * **Position management:**  `PopCurrentPosition`, `PushCurrentPosition`, `ReadCurrentPositionFromRegister`, `WriteStackPointerToRegister`, `ReadStackPointerFromRegister`, `SetCurrentPositionFromEnd`, `WriteCurrentPositionToRegister` manipulate the current matching position in the input string.
    * **Register management:** `PopRegister`, `PushRegister`, `SetRegister`, `ClearRegisters` handle the storage and retrieval of intermediate results in registers and on the stack.
    * **Backtracking:** `PushBacktrack` is crucial for implementing the backtracking mechanism in regular expression matching.
    * **Success and failure:** `Succeed` and the use of labels like `success_label_`, `backtrack_label_`, `exit_label_` show how the matching process concludes.
    * **Stack overflow and preemption handling:**  The `CheckStackLimit`, `CheckPreemption`, `CallCheckStackGuardState`, and the handling of `stack_overflow_label_` and `check_preempt_label_` indicate mechanisms to prevent stack exhaustion and handle interruptions.

6. **Consider the context of regular expression matching:**  Relate the identified functionalities back to the general process of regular expression matching: iterating through the input, comparing characters, storing capture groups, backtracking on failures, and managing the state.

7. **Address the specific questions in the prompt:**
    * **Functionality:**  Summarize the observed functionalities as listed above.
    * **`.tq` extension:**  The code is C++, so it's not a Torque file.
    * **JavaScript relationship:** Regular expressions are a fundamental part of JavaScript. The generated machine code directly executes when a JavaScript regular expression is used. Provide a simple `match()` example.
    * **Code logic inference:**  Choose a relatively simple function like `PushBacktrack` and explain its logic with an example.
    * **Common programming errors:**  Think about errors related to stack usage in low-level code or incorrect register handling.

8. **Structure the summary:** Organize the information logically with clear headings and bullet points.

9. **Review and refine:**  Read through the summary to ensure accuracy, clarity, and completeness, addressing all aspects of the user's request. Pay attention to the "part 2 of 3" instruction and provide a concise summary of the functions described in this specific snippet.
这是 `v8/src/regexp/arm64/regexp-macro-assembler-arm64.cc` 源代码的第二部分，它主要负责实现正则表达式匹配过程中一些底层的操作，例如管理栈，处理程序控制流，读写寄存器和内存等。

**功能归纳:**

这部分代码主要提供了以下功能：

1. **正则表达式栈管理:**
   - `LoadRegExpStackPointerFromMemory`: 从内存中加载正则表达式栈顶指针。
   - `StoreRegExpStackPointerToMemory`: 将正则表达式栈顶指针存储到内存中。
   - `PushRegExpBasePointer`: 将当前的正则表达式栈基指针压入栈中。
   - `PopRegExpBasePointer`: 从栈中弹出并恢复正则表达式栈基指针。

2. **生成正则表达式匹配代码的入口:**
   - `GetCode`:  这是生成最终可执行的正则表达式匹配代码的关键函数。它负责设置栈帧，初始化寄存器，分配栈空间，并调用相应的指令来执行匹配逻辑。

3. **程序控制流操作:**
   - `GoTo`:  无条件跳转到指定的标签。
   - `IfRegisterGE`:  如果指定的寄存器的值大于等于给定的比较值，则跳转到指定的标签。
   - `IfRegisterLT`:  如果指定的寄存器的值小于给定的比较值，则跳转到指定的标签。
   - `IfRegisterEqPos`: 如果指定的寄存器的值等于当前输入位置，则跳转到指定的标签。

4. **获取当前架构的实现:**
   - `Implementation`: 返回当前宏汇编器的实现类型，这里是 `kARM64Implementation`。

5. **操作当前匹配位置:**
   - `PopCurrentPosition`: 从栈中弹出并恢复当前的输入位置。
   - `PushCurrentPosition`: 将当前的输入位置压入栈中。
   - `ReadCurrentPositionFromRegister`: 从指定的寄存器读取当前输入位置。
   - `WriteStackPointerToRegister`: 将当前正则表达式栈指针的偏移量写入指定的寄存器。
   - `ReadStackPointerFromRegister`: 从指定的寄存器读取正则表达式栈指针的偏移量并更新栈指针。
   - `SetCurrentPositionFromEnd`: 将当前位置设置为相对于输入字符串末尾的偏移量。
   - `WriteCurrentPositionToRegister`: 将当前输入位置（可能加上偏移量）写入指定的寄存器。

6. **操作通用寄存器:**
   - `PopRegister`: 从栈中弹出一个值并存储到指定的寄存器中。
   - `PushRegister`: 将指定的寄存器的值压入栈中。
   - `SetRegister`: 将指定的寄存器的值设置为一个常量。
   - `ClearRegisters`: 将指定范围内的寄存器清零。

7. **回溯操作:**
   - `PushBacktrack`: 将回溯点的地址压入栈中。

8. **成功匹配处理:**
   - `Succeed`:  表示匹配成功，跳转到成功标签。

9. **栈溢出和抢占检查:**
   - `CheckStackGuardState`:  调用 C++ 函数检查栈溢出和抢占状态。
   - `CheckPosition`: 检查当前位置是否在输入字符串的有效范围内。
   - `CallCheckStackGuardState`:  生成调用 `CheckStackGuardState` 函数的代码。
   - `CheckPreemption`: 检查是否需要进行抢占。
   - `CheckStackLimit`: 检查正则表达式栈是否溢出。

10. **底层栈操作:**
    - `Push`: 将一个 32 位寄存器的值压入正则表达式栈。
    - `Pop`: 从正则表达式栈弹出一个值到 32 位寄存器。

11. **获取寄存器:**
    - `GetCachedRegister`: 获取缓存的寄存器。
    - `GetRegister`: 获取指定索引的寄存器，如果该寄存器在栈上，则从栈中加载。

12. **存储寄存器:**
    - `StoreRegister`: 将指定寄存器的值存储到指定索引的位置，可能在缓存中或栈上。

13. **调用和返回:**
    - `CallIf`:  根据条件决定是否调用指定的标签。
    - `RestoreLinkRegister`: 恢复链接寄存器。
    - `SaveLinkRegister`: 保存链接寄存器。
    - `CallCFunctionFromIrregexpCode`:  生成从正则表达式代码调用 C 函数的代码。

**关于您的问题:**

* **如果 `v8/src/regexp/arm64/regexp-macro-assembler-arm64.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码。**
   - 源代码的文件名是 `.cc`，表示它是 C++ 源代码，而不是 Torque 源代码。Torque 源代码通常以 `.tq` 结尾。

* **如果它与 javascript 的功能有关系，请用 javascript 举例说明。**
   - 这个 C++ 文件是 V8 引擎的一部分，V8 引擎负责执行 JavaScript 代码。其中的 `RegExpMacroAssemblerARM64` 类专门用于为 JavaScript 中的正则表达式生成 ARM64 架构的机器码。当你在 JavaScript 中使用正则表达式时，例如：

     ```javascript
     const regex = /ab+c/;
     const str = 'abbcdef';
     const result = str.match(regex);
     console.log(result); // 输出: ["abbc"]
     ```

     V8 引擎会在底层使用 `RegExpMacroAssemblerARM64` (在 ARM64 架构上) 来编译这个正则表达式 `/ab+c/`，生成高效的机器码来执行匹配操作。`str.match(regex)` 的执行最终会调用到这里生成的机器码。

* **如果有代码逻辑推理，请给出假设输入与输出。**
   - 考虑 `PushBacktrack` 函数：

     **假设输入:**  `label` 指向代码中的一个标签，例如 `&loop_start;`。

     **代码逻辑:**  `PushBacktrack` 会计算出标签 `loop_start` 相对于代码起始位置的偏移量，并将这个偏移量压入正则表达式栈中。如果标签已经绑定（即其地址已知），则直接计算偏移量。否则，会先获取标签的地址，再计算偏移量。

     **输出:**  正则表达式栈的栈顶会增加一个字（32 位），其值为标签 `loop_start` 的偏移量。这个偏移量在后续的回溯操作中会被用来跳转回该标签的位置。

* **如果涉及用户常见的编程错误，请举例说明。**
   - 虽然用户不直接编写这里的 C++ 代码，但理解其背后的机制可以帮助理解正则表达式的一些性能问题。例如，如果正则表达式过于复杂，导致大量的回溯，那么 `PushBacktrack` 和 `Pop` 等操作会被频繁调用，可能会导致性能下降甚至栈溢出。

     一个可能导致大量回溯的 JavaScript 正则表达式示例：

     ```javascript
     const regex = /a*b*c*/; // 对于像 "aaaaaaaaaabbbbbbbbbbccccccccccd" 这样的输入，会导致大量回溯。
     const str = "aaaaaaaaaabbbbbbbbbbccccccccccd";
     const result = str.match(regex);
     ```

     在这个例子中，`a*`, `b*`, `c*` 都是贪婪匹配，当匹配失败时，引擎会尝试减少匹配的数量，导致回溯。在 `RegExpMacroAssemblerARM64.cc` 中，`PushBacktrack` 会被用来记录这些回溯点。

**总结这部分的功能:**

这部分 `RegExpMacroAssemblerARM64.cc` 代码是 V8 引擎中用于在 ARM64 架构上实现高效正则表达式匹配的关键组成部分。它提供了管理正则表达式栈、控制程序流程、操作寄存器和内存、处理回溯以及进行栈溢出和抢占检查等底层功能，为 JavaScript 中正则表达式的执行提供了基础支持。

### 提示词
```
这是目录为v8/src/regexp/arm64/regexp-macro-assembler-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/arm64/regexp-macro-assembler-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_stack_pointer(isolate());
  __ Mov(dst, ref);
  __ Ldr(dst, MemOperand(dst));
}

void RegExpMacroAssemblerARM64::StoreRegExpStackPointerToMemory(
    Register src, Register scratch) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_stack_pointer(isolate());
  __ Mov(scratch, ref);
  __ Str(src, MemOperand(scratch));
}

void RegExpMacroAssemblerARM64::PushRegExpBasePointer(Register stack_pointer,
                                                      Register scratch) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ Mov(scratch, ref);
  __ Ldr(scratch, MemOperand(scratch));
  __ Sub(scratch, stack_pointer, scratch);
  __ Str(scratch, MemOperand(frame_pointer(), kRegExpStackBasePointerOffset));
}

void RegExpMacroAssemblerARM64::PopRegExpBasePointer(Register stack_pointer_out,
                                                     Register scratch) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ Ldr(stack_pointer_out,
         MemOperand(frame_pointer(), kRegExpStackBasePointerOffset));
  __ Mov(scratch, ref);
  __ Ldr(scratch, MemOperand(scratch));
  __ Add(stack_pointer_out, stack_pointer_out, scratch);
  StoreRegExpStackPointerToMemory(stack_pointer_out, scratch);
}

Handle<HeapObject> RegExpMacroAssemblerARM64::GetCode(Handle<String> source,
                                                      RegExpFlags flags) {
  Label return_w0;
  // Finalize code - write the entry point code now we know how many
  // registers we need.

  // Entry code:
  __ Bind(&entry_label_);

  // Arguments on entry:
  // x0:  String   input
  // x1:  int      start_offset
  // x2:  uint8_t*    input_start
  // x3:  uint8_t*    input_end
  // x4:  int*     output array
  // x5:  int      output array size
  // x6:  int      direct_call
  // x7:  Isolate* isolate
  //
  // sp[0]:  secondary link/return address used by native call

  // Tell the system that we have a stack frame.  Because the type is MANUAL, no
  // code is generated.
  FrameScope scope(masm_.get(), StackFrame::MANUAL);

  // Stack frame setup.
  // Push callee-saved registers.
  const CPURegList registers_to_retain = kCalleeSaved;
  DCHECK_EQ(registers_to_retain.Count(), kNumCalleeSavedRegisters);
  __ PushCPURegList(registers_to_retain);
  static_assert(kFrameTypeOffset == kFramePointerOffset - kSystemPointerSize);
  __ EnterFrame(StackFrame::IRREGEXP);
  // Only push the argument registers that we need.
  static_assert(kIsolateOffset ==
                kFrameTypeOffset - kPaddingAfterFrameType - kSystemPointerSize);
  static_assert(kDirectCallOffset == kIsolateOffset - kSystemPointerSize);
  static_assert(kNumOutputRegistersOffset ==
                kDirectCallOffset - kSystemPointerSize);
  static_assert(kInputStringOffset ==
                kNumOutputRegistersOffset - kSystemPointerSize);
  __ PushCPURegList(CPURegList{x0, x5, x6, x7});

  // Initialize callee-saved registers.
  __ Mov(start_offset(), w1);
  __ Mov(input_start(), x2);
  __ Mov(input_end(), x3);
  __ Mov(output_array(), x4);

  // Make sure the stack alignment will be respected.
  const int alignment = masm_->ActivationFrameAlignment();
  DCHECK_EQ(alignment % 16, 0);
  const int align_mask = (alignment / kWRegSize) - 1;

  // Make room for stack locals.
  static constexpr int kWRegPerXReg = kXRegSize / kWRegSize;
  DCHECK_EQ(kNumberOfStackLocals * kWRegPerXReg,
            ((kNumberOfStackLocals * kWRegPerXReg) + align_mask) & ~align_mask);
  __ Claim(kNumberOfStackLocals * kWRegPerXReg);

  // Initialize backtrack stack pointer. It must not be clobbered from here on.
  // Note the backtrack_stackpointer is callee-saved.
  static_assert(backtrack_stackpointer() == x23);
  LoadRegExpStackPointerFromMemory(backtrack_stackpointer());

  // Store the regexp base pointer - we'll later restore it / write it to
  // memory when returning from this irregexp code object.
  PushRegExpBasePointer(backtrack_stackpointer(), x11);

  // Set the number of registers we will need to allocate, that is:
  //   - (num_registers_ - kNumCachedRegisters) (W registers)
  const int num_stack_registers =
      std::max(0, num_registers_ - kNumCachedRegisters);
  const int num_wreg_to_allocate =
      (num_stack_registers + align_mask) & ~align_mask;

  {
    // Check if we have space on the stack.
    Label stack_limit_hit, stack_ok;

    ExternalReference stack_limit =
        ExternalReference::address_of_jslimit(isolate());
    __ Mov(x10, stack_limit);
    __ Ldr(x10, MemOperand(x10));
    __ Subs(x10, sp, x10);
    Operand extra_space_for_variables(num_wreg_to_allocate * kWRegSize);

    // Handle it if the stack pointer is already below the stack limit.
    __ B(ls, &stack_limit_hit);

    // Check if there is room for the variable number of registers above
    // the stack limit.
    __ Cmp(x10, extra_space_for_variables);
    __ B(hs, &stack_ok);

    // Exit with OutOfMemory exception. There is not enough space on the stack
    // for our working registers.
    __ Mov(w0, EXCEPTION);
    __ B(&return_w0);

    __ Bind(&stack_limit_hit);
    CallCheckStackGuardState(x10, extra_space_for_variables);
    // If returned value is non-zero, we exit with the returned value as result.
    __ Cbnz(w0, &return_w0);

    __ Bind(&stack_ok);
  }

  // Allocate space on stack.
  __ Claim(num_wreg_to_allocate, kWRegSize);

  // Initialize success_counter and kBacktrackCountOffset with 0.
  __ Str(wzr, MemOperand(frame_pointer(), kSuccessfulCapturesOffset));
  __ Str(wzr, MemOperand(frame_pointer(), kBacktrackCountOffset));

  // Find negative length (offset of start relative to end).
  __ Sub(x10, input_start(), input_end());
  if (v8_flags.debug_code) {
    // Check that the size of the input string chars is in range.
    __ Neg(x11, x10);
    __ Cmp(x11, SeqTwoByteString::kMaxCharsSize);
    __ Check(ls, AbortReason::kInputStringTooLong);
  }
  __ Mov(current_input_offset(), w10);

  // The non-position value is used as a clearing value for the
  // capture registers, it corresponds to the position of the first character
  // minus one.
  __ Sub(string_start_minus_one(), current_input_offset(), char_size());
  __ Sub(string_start_minus_one(), string_start_minus_one(),
         Operand(start_offset(), LSL, (mode_ == UC16) ? 1 : 0));
  // We can store this value twice in an X register for initializing
  // on-stack registers later.
  __ Orr(twice_non_position_value(), string_start_minus_one().X(),
         Operand(string_start_minus_one().X(), LSL, kWRegSizeInBits));

  // Initialize code pointer register.
  __ Mov(code_pointer(), Operand(masm_->CodeObject()));

  Label load_char_start_regexp;
  {
    Label start_regexp;
    // Load newline if index is at start, previous character otherwise.
    __ Cbnz(start_offset(), &load_char_start_regexp);
    __ Mov(current_character(), '\n');
    __ B(&start_regexp);

    // Global regexp restarts matching here.
    __ Bind(&load_char_start_regexp);
    // Load previous char as initial value of current character register.
    LoadCurrentCharacterUnchecked(-1, 1);
    __ Bind(&start_regexp);
  }

  // Initialize on-stack registers.
  if (num_saved_registers_ > 0) {
    ClearRegisters(0, num_saved_registers_ - 1);
  }

  // Execute.
  __ B(&start_label_);

  if (backtrack_label_.is_linked()) {
    __ Bind(&backtrack_label_);
    Backtrack();
  }

  if (success_label_.is_linked()) {
    Register first_capture_start = w15;

    // Save captures when successful.
    __ Bind(&success_label_);

    if (num_saved_registers_ > 0) {
      // V8 expects the output to be an int32_t array.
      Register capture_start = w12;
      Register capture_end = w13;
      Register input_length = w14;

      // Copy captures to output.

      // Get string length.
      __ Sub(x10, input_end(), input_start());
      if (v8_flags.debug_code) {
        // Check that the size of the input string chars is in range.
        __ Cmp(x10, SeqTwoByteString::kMaxCharsSize);
        __ Check(ls, AbortReason::kInputStringTooLong);
      }
      // input_start has a start_offset offset on entry. We need to include
      // it when computing the length of the whole string.
      if (mode_ == UC16) {
        __ Add(input_length, start_offset(), Operand(w10, LSR, 1));
      } else {
        __ Add(input_length, start_offset(), w10);
      }

      // Copy the results to the output array from the cached registers first.
      for (int i = 0; (i < num_saved_registers_) && (i < kNumCachedRegisters);
           i += 2) {
        __ Mov(capture_start.X(), GetCachedRegister(i));
        __ Lsr(capture_end.X(), capture_start.X(), kWRegSizeInBits);
        if ((i == 0) && global_with_zero_length_check()) {
          // Keep capture start for the zero-length check later.
          // Note this only works when we have at least one cached register
          // pair (otherwise we'd never reach this branch).
          static_assert(kNumCachedRegisters > 0);
          __ Mov(first_capture_start, capture_start);
        }
        // Offsets need to be relative to the start of the string.
        if (mode_ == UC16) {
          __ Add(capture_start, input_length, Operand(capture_start, ASR, 1));
          __ Add(capture_end, input_length, Operand(capture_end, ASR, 1));
        } else {
          __ Add(capture_start, input_length, capture_start);
          __ Add(capture_end, input_length, capture_end);
        }
        // The output pointer advances for a possible global match.
        __ Stp(capture_start, capture_end,
               MemOperand(output_array(), kSystemPointerSize, PostIndex));
      }

      // Only carry on if there are more than kNumCachedRegisters capture
      // registers.
      int num_registers_left_on_stack =
          num_saved_registers_ - kNumCachedRegisters;
      if (num_registers_left_on_stack > 0) {
        Register base = x10;
        // There are always an even number of capture registers. A couple of
        // registers determine one match with two offsets.
        DCHECK_EQ(0, num_registers_left_on_stack % 2);
        __ Add(base, frame_pointer(), kFirstCaptureOnStackOffset);

        // We can unroll the loop here, we should not unroll for less than 2
        // registers.
        static_assert(kNumRegistersToUnroll > 2);
        if (num_registers_left_on_stack <= kNumRegistersToUnroll) {
          for (int i = 0; i < num_registers_left_on_stack / 2; i++) {
            __ Ldp(capture_end, capture_start,
                   MemOperand(base, -kSystemPointerSize, PostIndex));
            // Offsets need to be relative to the start of the string.
            if (mode_ == UC16) {
              __ Add(capture_start, input_length,
                     Operand(capture_start, ASR, 1));
              __ Add(capture_end, input_length, Operand(capture_end, ASR, 1));
            } else {
              __ Add(capture_start, input_length, capture_start);
              __ Add(capture_end, input_length, capture_end);
            }
            // The output pointer advances for a possible global match.
            __ Stp(capture_start, capture_end,
                   MemOperand(output_array(), kSystemPointerSize, PostIndex));
          }
        } else {
          Label loop;
          __ Mov(x11, num_registers_left_on_stack);

          __ Bind(&loop);
          __ Ldp(capture_end, capture_start,
                 MemOperand(base, -kSystemPointerSize, PostIndex));
          if (mode_ == UC16) {
            __ Add(capture_start, input_length, Operand(capture_start, ASR, 1));
            __ Add(capture_end, input_length, Operand(capture_end, ASR, 1));
          } else {
            __ Add(capture_start, input_length, capture_start);
            __ Add(capture_end, input_length, capture_end);
          }
          // The output pointer advances for a possible global match.
          __ Stp(capture_start, capture_end,
                 MemOperand(output_array(), kSystemPointerSize, PostIndex));
          __ Sub(x11, x11, 2);
          __ Cbnz(x11, &loop);
        }
      }
    }

    if (global()) {
      Register success_counter = w0;
      Register output_size = x10;
      // Restart matching if the regular expression is flagged as global.

      // Increment success counter.
      __ Ldr(success_counter,
             MemOperand(frame_pointer(), kSuccessfulCapturesOffset));
      __ Add(success_counter, success_counter, 1);
      __ Str(success_counter,
             MemOperand(frame_pointer(), kSuccessfulCapturesOffset));

      // Capture results have been stored, so the number of remaining global
      // output registers is reduced by the number of stored captures.
      __ Ldr(output_size,
             MemOperand(frame_pointer(), kNumOutputRegistersOffset));
      __ Sub(output_size, output_size, num_saved_registers_);
      // Check whether we have enough room for another set of capture results.
      __ Cmp(output_size, num_saved_registers_);
      __ B(lt, &return_w0);

      // The output pointer is already set to the next field in the output
      // array.
      // Update output size on the frame before we restart matching.
      __ Str(output_size,
             MemOperand(frame_pointer(), kNumOutputRegistersOffset));

      // Restore the original regexp stack pointer value (effectively, pop the
      // stored base pointer).
      PopRegExpBasePointer(backtrack_stackpointer(), x11);

      if (global_with_zero_length_check()) {
        // Special case for zero-length matches.
        __ Cmp(current_input_offset(), first_capture_start);
        // Not a zero-length match, restart.
        __ B(ne, &load_char_start_regexp);
        // Offset from the end is zero if we already reached the end.
        __ Cbz(current_input_offset(), &return_w0);
        // Advance current position after a zero-length match.
        Label advance;
        __ bind(&advance);
        __ Add(current_input_offset(), current_input_offset(),
               Operand((mode_ == UC16) ? 2 : 1));
        if (global_unicode()) CheckNotInSurrogatePair(0, &advance);
      }

      __ B(&load_char_start_regexp);
    } else {
      __ Mov(w0, SUCCESS);
    }
  }

  if (exit_label_.is_linked()) {
    // Exit and return w0.
    __ Bind(&exit_label_);
    if (global()) {
      __ Ldr(w0, MemOperand(frame_pointer(), kSuccessfulCapturesOffset));
    }
  }

  __ Bind(&return_w0);
  // Restore the original regexp stack pointer value (effectively, pop the
  // stored base pointer).
  PopRegExpBasePointer(backtrack_stackpointer(), x11);

  __ LeaveFrame(StackFrame::IRREGEXP);
  __ PopCPURegList(registers_to_retain);
  __ Ret();

  Label exit_with_exception;
  if (check_preempt_label_.is_linked()) {
    __ Bind(&check_preempt_label_);

    StoreRegExpStackPointerToMemory(backtrack_stackpointer(), x10);

    SaveLinkRegister();
    PushCachedRegisters();
    CallCheckStackGuardState(x10);
    // Returning from the regexp code restores the stack (sp <- fp)
    // so we don't need to drop the link register from it before exiting.
    __ Cbnz(w0, &return_w0);
    // Reset the cached registers.
    PopCachedRegisters();

    LoadRegExpStackPointerFromMemory(backtrack_stackpointer());

    RestoreLinkRegister();
    __ Ret();
  }

  if (stack_overflow_label_.is_linked()) {
    __ Bind(&stack_overflow_label_);

    StoreRegExpStackPointerToMemory(backtrack_stackpointer(), x10);

    SaveLinkRegister();
    PushCachedRegisters();
    // Call GrowStack(isolate).
    static constexpr int kNumArguments = 1;
    __ Mov(x0, ExternalReference::isolate_address(isolate()));
    CallCFunctionFromIrregexpCode(ExternalReference::re_grow_stack(),
                                  kNumArguments);
    // If return nullptr, we have failed to grow the stack, and must exit with
    // a stack-overflow exception.  Returning from the regexp code restores the
    // stack (sp <- fp) so we don't need to drop the link register from it
    // before exiting.
    __ Cbz(w0, &exit_with_exception);
    // Otherwise use return value as new stack pointer.
    __ Mov(backtrack_stackpointer(), x0);
    PopCachedRegisters();
    RestoreLinkRegister();
    __ Ret();
  }

  if (exit_with_exception.is_linked()) {
    __ Bind(&exit_with_exception);
    __ Mov(w0, EXCEPTION);
    __ B(&return_w0);
  }

  if (fallback_label_.is_linked()) {
    __ Bind(&fallback_label_);
    __ Mov(w0, FALLBACK_TO_EXPERIMENTAL);
    __ B(&return_w0);
  }

  CodeDesc code_desc;
  masm_->GetCode(isolate(), &code_desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate(), code_desc, CodeKind::REGEXP)
          .set_self_reference(masm_->CodeObject())
          .set_empty_source_position_table()
          .Build();
  PROFILE(masm_->isolate(),
          RegExpCodeCreateEvent(Cast<AbstractCode>(code), source, flags));
  return Cast<HeapObject>(code);
}

void RegExpMacroAssemblerARM64::GoTo(Label* to) {
  BranchOrBacktrack(al, to);
}

void RegExpMacroAssemblerARM64::IfRegisterGE(int reg, int comparand,
                                             Label* if_ge) {
  Register to_compare = GetRegister(reg, w10);
  CompareAndBranchOrBacktrack(to_compare, comparand, ge, if_ge);
}


void RegExpMacroAssemblerARM64::IfRegisterLT(int reg, int comparand,
                                             Label* if_lt) {
  Register to_compare = GetRegister(reg, w10);
  CompareAndBranchOrBacktrack(to_compare, comparand, lt, if_lt);
}


void RegExpMacroAssemblerARM64::IfRegisterEqPos(int reg, Label* if_eq) {
  Register to_compare = GetRegister(reg, w10);
  __ Cmp(to_compare, current_input_offset());
  BranchOrBacktrack(eq, if_eq);
}

RegExpMacroAssembler::IrregexpImplementation
    RegExpMacroAssemblerARM64::Implementation() {
  return kARM64Implementation;
}


void RegExpMacroAssemblerARM64::PopCurrentPosition() {
  Pop(current_input_offset());
}


void RegExpMacroAssemblerARM64::PopRegister(int register_index) {
  Pop(w10);
  StoreRegister(register_index, w10);
}


void RegExpMacroAssemblerARM64::PushBacktrack(Label* label) {
  if (label->is_bound()) {
    int target = label->pos();
    __ Mov(w10, target + InstructionStream::kHeaderSize - kHeapObjectTag);
  } else {
    __ Adr(x10, label, MacroAssembler::kAdrFar);
    __ Sub(x10, x10, code_pointer());
    if (v8_flags.debug_code) {
      __ Cmp(x10, kWRegMask);
      // The code offset has to fit in a W register.
      __ Check(ls, AbortReason::kOffsetOutOfRange);
    }
  }
  Push(w10);
  CheckStackLimit();
}


void RegExpMacroAssemblerARM64::PushCurrentPosition() {
  Push(current_input_offset());
}


void RegExpMacroAssemblerARM64::PushRegister(int register_index,
                                             StackCheckFlag check_stack_limit) {
  Register to_push = GetRegister(register_index, w10);
  Push(to_push);
  if (check_stack_limit) CheckStackLimit();
}


void RegExpMacroAssemblerARM64::ReadCurrentPositionFromRegister(int reg) {
  RegisterState register_state = GetRegisterState(reg);
  switch (register_state) {
    case STACKED:
      __ Ldr(current_input_offset(), register_location(reg));
      break;
    case CACHED_LSW:
      __ Mov(current_input_offset(), GetCachedRegister(reg).W());
      break;
    case CACHED_MSW:
      __ Lsr(current_input_offset().X(), GetCachedRegister(reg),
             kWRegSizeInBits);
      break;
    default:
      UNREACHABLE();
  }
}

void RegExpMacroAssemblerARM64::WriteStackPointerToRegister(int reg) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ Mov(x10, ref);
  __ Ldr(x10, MemOperand(x10));
  __ Sub(x10, backtrack_stackpointer(), x10);
  if (v8_flags.debug_code) {
    __ Cmp(x10, Operand(w10, SXTW));
    // The stack offset needs to fit in a W register.
    __ Check(eq, AbortReason::kOffsetOutOfRange);
  }
  StoreRegister(reg, w10);
}

void RegExpMacroAssemblerARM64::ReadStackPointerFromRegister(int reg) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  Register read_from = GetRegister(reg, w10);
  __ Mov(x11, ref);
  __ Ldr(x11, MemOperand(x11));
  __ Add(backtrack_stackpointer(), x11, Operand(read_from, SXTW));
}

void RegExpMacroAssemblerARM64::SetCurrentPositionFromEnd(int by) {
  Label after_position;
  __ Cmp(current_input_offset(), -by * char_size());
  __ B(ge, &after_position);
  __ Mov(current_input_offset(), -by * char_size());
  // On RegExp code entry (where this operation is used), the character before
  // the current position is expected to be already loaded.
  // We have advanced the position, so it's safe to read backwards.
  LoadCurrentCharacterUnchecked(-1, 1);
  __ Bind(&after_position);
}


void RegExpMacroAssemblerARM64::SetRegister(int register_index, int to) {
  DCHECK(register_index >= num_saved_registers_);  // Reserved for positions!
  Register set_to = wzr;
  if (to != 0) {
    set_to = w10;
    __ Mov(set_to, to);
  }
  StoreRegister(register_index, set_to);
}


bool RegExpMacroAssemblerARM64::Succeed() {
  __ B(&success_label_);
  return global();
}


void RegExpMacroAssemblerARM64::WriteCurrentPositionToRegister(int reg,
                                                               int cp_offset) {
  Register position = current_input_offset();
  if (cp_offset != 0) {
    position = w10;
    __ Add(position, current_input_offset(), cp_offset * char_size());
  }
  StoreRegister(reg, position);
}


void RegExpMacroAssemblerARM64::ClearRegisters(int reg_from, int reg_to) {
  DCHECK(reg_from <= reg_to);
  int num_registers = reg_to - reg_from + 1;

  // If the first capture register is cached in a hardware register but not
  // aligned on a 64-bit one, we need to clear the first one specifically.
  if ((reg_from < kNumCachedRegisters) && ((reg_from % 2) != 0)) {
    StoreRegister(reg_from, string_start_minus_one());
    num_registers--;
    reg_from++;
  }

  // Clear cached registers in pairs as far as possible.
  while ((num_registers >= 2) && (reg_from < kNumCachedRegisters)) {
    DCHECK(GetRegisterState(reg_from) == CACHED_LSW);
    __ Mov(GetCachedRegister(reg_from), twice_non_position_value());
    reg_from += 2;
    num_registers -= 2;
  }

  if ((num_registers % 2) == 1) {
    StoreRegister(reg_from, string_start_minus_one());
    num_registers--;
    reg_from++;
  }

  if (num_registers > 0) {
    // If there are some remaining registers, they are stored on the stack.
    DCHECK_LE(kNumCachedRegisters, reg_from);

    // Move down the indexes of the registers on stack to get the correct offset
    // in memory.
    reg_from -= kNumCachedRegisters;
    reg_to -= kNumCachedRegisters;
    // We should not unroll the loop for less than 2 registers.
    static_assert(kNumRegistersToUnroll > 2);
    // We position the base pointer to (reg_from + 1).
    int base_offset =
        kFirstRegisterOnStackOffset - kWRegSize - (kWRegSize * reg_from);
    if (num_registers > kNumRegistersToUnroll) {
      Register base = x10;
      __ Add(base, frame_pointer(), base_offset);

      Label loop;
      __ Mov(x11, num_registers);
      __ Bind(&loop);
      __ Str(twice_non_position_value(),
             MemOperand(base, -kSystemPointerSize, PostIndex));
      __ Sub(x11, x11, 2);
      __ Cbnz(x11, &loop);
    } else {
      for (int i = reg_from; i <= reg_to; i += 2) {
        __ Str(twice_non_position_value(),
               MemOperand(frame_pointer(), base_offset));
        base_offset -= kWRegSize * 2;
      }
    }
  }
}

// Helper function for reading a value out of a stack frame.
template <typename T>
static T& frame_entry(Address re_frame, int frame_offset) {
  return *reinterpret_cast<T*>(re_frame + frame_offset);
}


template <typename T>
static T* frame_entry_address(Address re_frame, int frame_offset) {
  return reinterpret_cast<T*>(re_frame + frame_offset);
}

int RegExpMacroAssemblerARM64::CheckStackGuardState(
    Address* return_address, Address raw_code, Address re_frame,
    int start_index, const uint8_t** input_start, const uint8_t** input_end,
    uintptr_t extra_space) {
  Tagged<InstructionStream> re_code =
      Cast<InstructionStream>(Tagged<Object>(raw_code));
  return NativeRegExpMacroAssembler::CheckStackGuardState(
      frame_entry<Isolate*>(re_frame, kIsolateOffset), start_index,
      static_cast<RegExp::CallOrigin>(
          frame_entry<int>(re_frame, kDirectCallOffset)),
      return_address, re_code,
      frame_entry_address<Address>(re_frame, kInputStringOffset), input_start,
      input_end, extra_space);
}

void RegExpMacroAssemblerARM64::CheckPosition(int cp_offset,
                                              Label* on_outside_input) {
  if (cp_offset >= 0) {
    CompareAndBranchOrBacktrack(current_input_offset(),
                                -cp_offset * char_size(), ge, on_outside_input);
  } else {
    __ Add(w12, current_input_offset(), Operand(cp_offset * char_size()));
    __ Cmp(w12, string_start_minus_one());
    BranchOrBacktrack(le, on_outside_input);
  }
}


// Private methods:

void RegExpMacroAssemblerARM64::CallCheckStackGuardState(Register scratch,
                                                         Operand extra_space) {
  DCHECK(!isolate()->IsGeneratingEmbeddedBuiltins());
  DCHECK(!masm_->options().isolate_independent_code);

  // Allocate space on the stack to store the return address. The
  // CheckStackGuardState C++ function will override it if the code
  // moved. Allocate extra space for 2 arguments passed by pointers.
  // AAPCS64 requires the stack to be 16 byte aligned.
  int alignment = masm_->ActivationFrameAlignment();
  DCHECK_EQ(alignment % 16, 0);
  int align_mask = (alignment / kXRegSize) - 1;
  int xreg_to_claim = (3 + align_mask) & ~align_mask;

  __ Claim(xreg_to_claim);

  __ Mov(x6, extra_space);
  // CheckStackGuardState needs the end and start addresses of the input string.
  __ Poke(input_end(), 2 * kSystemPointerSize);
  __ Add(x5, sp, 2 * kSystemPointerSize);
  __ Poke(input_start(), kSystemPointerSize);
  __ Add(x4, sp, kSystemPointerSize);

  __ Mov(w3, start_offset());
  // RegExp code frame pointer.
  __ Mov(x2, frame_pointer());
  // InstructionStream of self.
  __ Mov(x1, Operand(masm_->CodeObject()));

  // We need to pass a pointer to the return address as first argument.
  // DirectCEntry will place the return address on the stack before calling so
  // the stack pointer will point to it.
  __ Mov(x0, sp);

  DCHECK_EQ(scratch, x10);
  ExternalReference check_stack_guard_state =
      ExternalReference::re_check_stack_guard_state();
  __ Mov(scratch, check_stack_guard_state);

  __ CallBuiltin(Builtin::kDirectCEntry);

  // The input string may have been moved in memory, we need to reload it.
  __ Peek(input_start(), kSystemPointerSize);
  __ Peek(input_end(), 2 * kSystemPointerSize);

  __ Drop(xreg_to_claim);

  // Reload the InstructionStream pointer.
  __ Mov(code_pointer(), Operand(masm_->CodeObject()));
}

void RegExpMacroAssemblerARM64::BranchOrBacktrack(Condition condition,
                                                  Label* to) {
  if (condition == al) {  // Unconditional.
    if (to == nullptr) {
      Backtrack();
      return;
    }
    __ B(to);
    return;
  }
  if (to == nullptr) {
    to = &backtrack_label_;
  }
  __ B(condition, to);
}

void RegExpMacroAssemblerARM64::CompareAndBranchOrBacktrack(Register reg,
                                                            int immediate,
                                                            Condition condition,
                                                            Label* to) {
  if ((immediate == 0) && ((condition == eq) || (condition == ne))) {
    if (to == nullptr) {
      to = &backtrack_label_;
    }
    if (condition == eq) {
      __ Cbz(reg, to);
    } else {
      __ Cbnz(reg, to);
    }
  } else {
    __ Cmp(reg, immediate);
    BranchOrBacktrack(condition, to);
  }
}

void RegExpMacroAssemblerARM64::CallCFunctionFromIrregexpCode(
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

void RegExpMacroAssemblerARM64::CheckPreemption() {
  // Check for preemption.
  ExternalReference stack_limit =
      ExternalReference::address_of_jslimit(isolate());
  __ Mov(x10, stack_limit);
  __ Ldr(x10, MemOperand(x10));
  __ Cmp(sp, x10);
  CallIf(&check_preempt_label_, ls);
}


void RegExpMacroAssemblerARM64::CheckStackLimit() {
  ExternalReference stack_limit =
      ExternalReference::address_of_regexp_stack_limit_address(isolate());
  __ Mov(x10, stack_limit);
  __ Ldr(x10, MemOperand(x10));
  __ Cmp(backtrack_stackpointer(), x10);
  CallIf(&stack_overflow_label_, ls);
}


void RegExpMacroAssemblerARM64::Push(Register source) {
  DCHECK(source.Is32Bits());
  DCHECK_NE(source, backtrack_stackpointer());
  __ Str(source,
         MemOperand(backtrack_stackpointer(),
                    -static_cast<int>(kWRegSize),
                    PreIndex));
}


void RegExpMacroAssemblerARM64::Pop(Register target) {
  DCHECK(target.Is32Bits());
  DCHECK_NE(target, backtrack_stackpointer());
  __ Ldr(target,
         MemOperand(backtrack_stackpointer(), kWRegSize, PostIndex));
}


Register RegExpMacroAssemblerARM64::GetCachedRegister(int register_index) {
  DCHECK_GT(kNumCachedRegisters, register_index);
  return Register::Create(register_index / 2, kXRegSizeInBits);
}


Register RegExpMacroAssemblerARM64::GetRegister(int register_index,
                                                Register maybe_result) {
  DCHECK(maybe_result.Is32Bits());
  DCHECK_LE(0, register_index);
  if (num_registers_ <= register_index) {
    num_registers_ = register_index + 1;
  }
  Register result = NoReg;
  RegisterState register_state = GetRegisterState(register_index);
  switch (register_state) {
    case STACKED:
      __ Ldr(maybe_result, register_location(register_index));
      result = maybe_result;
      break;
    case CACHED_LSW:
      result = GetCachedRegister(register_index).W();
      break;
    case CACHED_MSW:
      __ Lsr(maybe_result.X(), GetCachedRegister(register_index),
             kWRegSizeInBits);
      result = maybe_result;
      break;
    default:
      UNREACHABLE();
  }
  DCHECK(result.Is32Bits());
  return result;
}


void RegExpMacroAssemblerARM64::StoreRegister(int register_index,
                                              Register source) {
  DCHECK(source.Is32Bits());
  DCHECK_LE(0, register_index);
  if (num_registers_ <= register_index) {
    num_registers_ = register_index + 1;
  }

  RegisterState register_state = GetRegisterState(register_index);
  switch (register_state) {
    case STACKED:
      __ Str(source, register_location(register_index));
      break;
    case CACHED_LSW: {
      Register cached_register = GetCachedRegister(register_index);
      if (source != cached_register.W()) {
        __ Bfi(cached_register, source.X(), 0, kWRegSizeInBits);
      }
      break;
    }
    case CACHED_MSW: {
      Register cached_register = GetCachedRegister(register_index);
      __ Bfi(cached_register, source.X(), kWRegSizeInBits, kWRegSizeInBits);
      break;
    }
    default:
      UNREACHABLE();
  }
}


void RegExpMacroAssemblerARM64::CallIf(Label* to, Condition condition) {
  Label skip_call;
  if (condition != al) __ B(&skip_call, NegateCondition(condition));
  __ Bl(to);
  __ Bind(&skip_call);
}


void RegExpMacroAssemblerARM64::RestoreLinkRegister() {
  // TODO(v8:10026): Remove when we stop compacting for code objects that are
  // active on the call stack.
  __ Pop<MacroAssembler::kAuthLR>(padreg, lr);
  __ Add(lr, lr, Operand(masm_->CodeObject()));
}


void RegExpMacroAssemblerARM64::SaveLinkRegister() {
  __ Sub(lr, lr, Operand(masm_->CodeObject()));
  __ Push<MacroAssembler::kSignLR>(lr, padreg);
}


MemOperand RegExpMacroAssemblerARM64::register_location(int register_index) {
  DCHECK(register_index < (1<<30));
  DCHECK_LE(kNumCachedRegisters, register_index);
  if (num_registers_ <= register_index) {
    num_registers_ = register_index + 1;
  }
  register_index -= kNumCachedRegisters;
  int offset = kFirstRegisterOnStackOffset - register_index * kWRegSize;
  return MemOperand(frame_pointer(), offset);
}
```