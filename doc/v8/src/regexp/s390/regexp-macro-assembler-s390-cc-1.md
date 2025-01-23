Response:
The user wants to understand the functionality of the provided C++ code snippet from V8. I need to analyze the code and explain what it does.

Here's a breakdown of the code's main sections:

1. **Initialization:** Sets up the initial state for regular expression matching.
2. **Register Handling:** Manages on-stack registers for storing captured groups.
3. **Success Handling:**  Executes when a match is found, saving captures and handling global flag.
4. **Exit:**  Returns the result of the matching process.
5. **Backtracking:**  Handles failed match attempts and tries alternative paths.
6. **Preemption Check:**  Ensures the script doesn't run for too long.
7. **Stack Overflow Handling:**  Manages situations where the backtrack stack exceeds its limit.
8. **Helper Functions:** Various utility functions for stack manipulation, register access, and conditional branching.

Based on this analysis, I can now formulate a detailed explanation.
这是V8 JavaScript引擎中用于在s390架构上执行正则表达式匹配的汇编代码生成器的一部分。它负责生成底层的机器码指令，这些指令会被CPU执行以完成正则表达式的匹配工作。

以下是其功能的详细列表：

1. **正则表达式匹配的入口点:**  代码定义了正则表达式匹配的起始逻辑。它首先加载前一个字符作为当前字符的初始值，并绑定到 `start_regexp` 标签。

2. **初始化寄存器:**  代码会初始化用于存储捕获组信息的寄存器。如果存在需要保存的寄存器（通常由正则表达式生成），它会将这些寄存器填充一个初始值（起始偏移量 - 1）。

3. **成功匹配处理:** 当正则表达式匹配成功时，代码会跳转到 `success_label_`。在这里，它会将捕获到的子字符串的起始和结束位置存储到输出缓冲区中。
    - 它计算输入字符串的长度。
    - 它将捕获寄存器中的值（表示捕获的起始位置）加上输入字符串的起始位置，得到捕获的实际位置。
    - 它将这些位置存储到预先分配的输出缓冲区中。
    - 如果正则表达式带有全局 (`/g`) 标志，它会更新成功匹配的计数器，并检查是否有足够的空间存储更多的匹配结果。如果有，它会准备进行下一次匹配尝试。

4. **全局匹配的重启:** 如果正则表达式是全局的，并且匹配成功，代码会跳转回 `load_char_start_regexp` 以尝试在剩余的输入中查找更多的匹配项。  对于零长度的匹配，它会特别处理，避免无限循环。

5. **退出代码:**  当匹配完成（成功或失败）后，代码会跳转到 `exit_label_` 或 `return_r2`。对于全局匹配，它会将成功匹配的次数作为结果返回。

6. **回溯处理:** 如果匹配过程中遇到无法继续匹配的情况，代码会跳转到 `backtrack_label_`，执行回溯逻辑，尝试其他的匹配路径。

7. **抢占检查:**  代码包含 `check_preempt_label_`，用于检查JavaScript执行是否应该暂停（例如，由于执行时间过长）。如果需要暂停，它会保存当前状态并返回。

8. **堆栈溢出处理:** `stack_overflow_label_` 用于处理回溯堆栈溢出的情况。当回溯堆栈达到其限制时，代码会尝试扩展堆栈。如果扩展失败，则抛出堆栈溢出异常。

9. **回退到实验性代码:** `fallback_label_` 允许在某些情况下回退到实验性的正则表达式实现。

10. **生成机器码:** 代码的最后部分使用 `masm_->GetCode` 生成最终的可执行机器码。

**关于 `.tq` 结尾:**

如果 `v8/src/regexp/s390/regexp-macro-assembler-s390.cc` 以 `.tq` 结尾，那 **是的，它将是一个 V8 Torque 源代码文件**。 Torque 是一种 V8 特有的语言，用于生成高效的 C++ 代码，通常用于实现 V8 的内置函数和一些性能关键的部分，包括正则表达式。

**与 JavaScript 的关系及示例:**

这段代码直接服务于 JavaScript 中的正则表达式功能。当你在 JavaScript 中使用正则表达式进行匹配时，V8 引擎会使用类似这样的代码来执行底层的匹配操作。

**JavaScript 示例:**

```javascript
const regex = /ab?c/g;
const text = "ac abc abbc";
let match;

while ((match = regex.exec(text)) !== null) {
  console.log(`找到匹配项：${match[0]}，起始位置：${match.index}`);
}
```

在这个例子中，当你执行 `regex.exec(text)` 时，V8 引擎内部会调用类似 `RegExpMacroAssemblerS390` 中生成的机器码来查找 `text` 中与正则表达式 `/ab?c/g` 匹配的子字符串。

**代码逻辑推理和假设输入/输出:**

假设输入的正则表达式是 `/a(b)c/`，输入字符串是 `"xyzabc"`。

- **假设输入:**
    - 正则表达式: `/a(b)c/`
    - 输入字符串: `"xyzabc"`
    - 当前匹配位置（初始）：3 (指向 'a')

- **代码逻辑推理:**
    1. 代码会尝试匹配字符 'a'。
    2. 如果匹配成功，它会尝试匹配字符 'b'，并将 'b' 捕获到第一个捕获组。
    3. 如果 'b' 也匹配成功，它会尝试匹配字符 'c'。
    4. 如果 'c' 也匹配成功，则整个正则表达式匹配成功。

- **假设输出（成功匹配）:**
    - 匹配的子字符串: `"abc"`
    - 捕获组 1: `"b"`
    - 匹配的起始位置: 3

**用户常见的编程错误:**

1. **不理解全局匹配的行为:**  忘记在全局正则表达式中使用 `exec` 方法的循环，导致只找到第一个匹配项。

   ```javascript
   const regex = /test/g;
   const text = "test1 test2";
   const match = regex.exec(text); // 只会找到 "test1"
   console.log(match);
   ```

2. **错误的捕获组索引:**  访问不存在的捕获组，导致返回 `undefined`。

   ```javascript
   const regex = /(a)(b)/;
   const text = "ab";
   const match = regex.exec(text);
   console.log(match[2]); // 正确的索引是 1 和 2
   console.log(match[3]); // 错误，没有第三个捕获组，返回 undefined
   ```

3. **回溯过多导致性能问题:**  编写了导致大量回溯的复杂正则表达式，例如嵌套的可选组或重复组，在长字符串上可能会导致性能问题甚至卡死。

   ```javascript
   const regex = /a*b*c*/; // 容易产生大量回溯
   const text = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab";
   regex.test(text); // 可能需要很长时间
   ```

**归纳功能 (第2部分):**

作为第2部分，这段代码主要关注的是 **正则表达式匹配成功后的处理** 以及 **错误处理和控制流管理**。它处理了以下关键方面：

- **捕获组的存储和输出:**  将匹配到的捕获组信息写入到指定的内存区域，以便 JavaScript 可以访问这些信息。
- **全局匹配的迭代:**  实现了全局正则表达式的循环匹配逻辑，确保能够找到所有匹配项。
- **异常处理:**  处理了诸如堆栈溢出和抢占等可能发生的异常情况，并提供了相应的处理机制。
- **控制流管理:**  使用标签和跳转指令来控制正则表达式匹配过程中的各种状态转换，例如成功、失败、回溯等。

总而言之，这段代码是 V8 引擎中用于高效执行正则表达式匹配的核心组件之一，它直接影响着 JavaScript 中正则表达式功能的性能和正确性。

### 提示词
```
这是目录为v8/src/regexp/s390/regexp-macro-assembler-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/s390/regexp-macro-assembler-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
Load previous char as initial value of current character register.
    LoadCurrentCharacterUnchecked(-1, 1);
    __ bind(&start_regexp);
  }

  // Initialize on-stack registers.
  if (num_saved_registers_ > 0) {  // Always is, if generated from a regexp.
    // Fill saved registers with initial value = start offset - 1
    if (num_saved_registers_ > 8) {
      // One slot beyond address of register 0.
      __ lay(r3, MemOperand(frame_pointer(),
                            kRegisterZeroOffset + kSystemPointerSize));
      __ mov(r4, Operand(num_saved_registers_));
      Label init_loop;
      __ bind(&init_loop);
      __ StoreU64(r1, MemOperand(r3, -kSystemPointerSize));
      __ lay(r3, MemOperand(r3, -kSystemPointerSize));
      __ BranchOnCount(r4, &init_loop);
    } else {
      for (int i = 0; i < num_saved_registers_; i++) {
        __ StoreU64(r1, register_location(i));
      }
    }
  }

  __ b(&start_label_);

  // Exit code:
  if (success_label_.is_linked()) {
    // Save captures when successful.
    __ bind(&success_label_);
    if (num_saved_registers_ > 0) {
      // copy captures to output
      __ LoadU64(r0, MemOperand(frame_pointer(), kInputStartOffset));
      __ LoadU64(r2, MemOperand(frame_pointer(), kRegisterOutputOffset));
      __ LoadU64(r4, MemOperand(frame_pointer(), kStartIndexOffset));
      __ SubS64(r0, end_of_input_address(), r0);
      // r0 is length of input in bytes.
      if (mode_ == UC16) {
        __ ShiftRightU64(r0, r0, Operand(1));
      }
      // r0 is length of input in characters.
      __ AddS64(r0, r4);
      // r0 is length of string in characters.

      DCHECK_EQ(0, num_saved_registers_ % 2);
      // Always an even number of capture registers. This allows us to
      // unroll the loop once to add an operation between a load of a register
      // and the following use of that register.
      __ lay(r2, MemOperand(r2, num_saved_registers_ * kIntSize));
      for (int i = 0; i < num_saved_registers_;) {
        if ((false) && i < num_saved_registers_ - 4) {
          // TODO(john.yan): Can be optimized by SIMD instructions
          __ LoadMultipleP(r3, r6, register_location(i + 3));
          if (mode_ == UC16) {
            __ ShiftRightS64(r3, r3, Operand(1));
            __ ShiftRightS64(r4, r4, Operand(1));
            __ ShiftRightS64(r5, r5, Operand(1));
            __ ShiftRightS64(r6, r6, Operand(1));
          }
          __ AddS64(r3, r0);
          __ AddS64(r4, r0);
          __ AddS64(r5, r0);
          __ AddS64(r6, r0);
          __ StoreU32(
              r3, MemOperand(r2, -(num_saved_registers_ - i - 3) * kIntSize));
          __ StoreU32(
              r4, MemOperand(r2, -(num_saved_registers_ - i - 2) * kIntSize));
          __ StoreU32(
              r5, MemOperand(r2, -(num_saved_registers_ - i - 1) * kIntSize));
          __ StoreU32(r6,
                      MemOperand(r2, -(num_saved_registers_ - i) * kIntSize));
          i += 4;
        } else {
          __ LoadMultipleP(r3, r4, register_location(i + 1));
          if (mode_ == UC16) {
            __ ShiftRightS64(r3, r3, Operand(1));
            __ ShiftRightS64(r4, r4, Operand(1));
          }
          __ AddS64(r3, r0);
          __ AddS64(r4, r0);
          __ StoreU32(
              r3, MemOperand(r2, -(num_saved_registers_ - i - 1) * kIntSize));
          __ StoreU32(r4,
                      MemOperand(r2, -(num_saved_registers_ - i) * kIntSize));
          i += 2;
        }
      }
      if (global_with_zero_length_check()) {
        // Keep capture start in r6 for the zero-length check later.
        __ LoadU64(r6, register_location(0));
      }
    }

    if (global()) {
      // Restart matching if the regular expression is flagged as global.
      __ LoadU64(r2, MemOperand(frame_pointer(), kSuccessfulCapturesOffset));
      __ LoadU64(r3, MemOperand(frame_pointer(), kNumOutputRegistersOffset));
      __ LoadU64(r4, MemOperand(frame_pointer(), kRegisterOutputOffset));
      // Increment success counter.
      __ AddS64(r2, Operand(1));
      __ StoreU64(r2, MemOperand(frame_pointer(), kSuccessfulCapturesOffset));
      // Capture results have been stored, so the number of remaining global
      // output registers is reduced by the number of stored captures.
      __ SubS64(r3, Operand(num_saved_registers_));
      // Check whether we have enough room for another set of capture results.
      __ CmpS64(r3, Operand(num_saved_registers_));
      __ blt(&return_r2);

      __ StoreU64(r3, MemOperand(frame_pointer(), kNumOutputRegistersOffset));
      // Advance the location for output.
      __ AddS64(r4, Operand(num_saved_registers_ * kIntSize));
      __ StoreU64(r4, MemOperand(frame_pointer(), kRegisterOutputOffset));

      // Restore the original regexp stack pointer value (effectively, pop the
      // stored base pointer).
      PopRegExpBasePointer(backtrack_stackpointer(), r4);

      Label reload_string_start_minus_one;

      if (global_with_zero_length_check()) {
        // Special case for zero-length matches.
        // r6: capture start index
        __ CmpS64(current_input_offset(), r6);
        // Not a zero-length match, restart.
        __ bne(&reload_string_start_minus_one);
        // Offset from the end is zero if we already reached the end.
        __ CmpS64(current_input_offset(), Operand::Zero());
        __ beq(&exit_label_);
        // Advance current position after a zero-length match.
        Label advance;
        __ bind(&advance);
        __ AddS64(current_input_offset(), Operand((mode_ == UC16) ? 2 : 1));
        if (global_unicode()) CheckNotInSurrogatePair(0, &advance);
      }

      __ bind(&reload_string_start_minus_one);
      // Prepare r1 to initialize registers with its value in the next run.
      // Must be immediately before the jump to avoid clobbering.
      __ LoadU64(r1, MemOperand(frame_pointer(), kStringStartMinusOneOffset));

      __ b(&load_char_start_regexp);
    } else {
      __ mov(r2, Operand(SUCCESS));
    }
  }

  // Exit and return r2
  __ bind(&exit_label_);
  if (global()) {
    __ LoadU64(r2, MemOperand(frame_pointer(), kSuccessfulCapturesOffset));
  }

  __ bind(&return_r2);
  // Restore the original regexp stack pointer value (effectively, pop the
  // stored base pointer).
  PopRegExpBasePointer(backtrack_stackpointer(), r4);

  // Skip sp past regexp registers and local variables..
  __ mov(sp, frame_pointer());
#if V8_OS_ZOS
  // XPLINK uses r3 as the return register
  __ mov(r3, r2);
  // Restore registers r4..r15
  __ LoadMultipleP(r4, sp, MemOperand(sp));
  // Shrink stack
  __ lay(r4, MemOperand(r4, 12 * kSystemPointerSize));
  __ b(r7);
#else
  // Restore registers r6..r15.
  __ LoadMultipleP(r6, sp, MemOperand(sp, 6 * kSystemPointerSize));

  __ b(r14);
#endif

  // Backtrack code (branch target for conditional backtracks).
  if (backtrack_label_.is_linked()) {
    __ bind(&backtrack_label_);
    Backtrack();
  }

  Label exit_with_exception;

  // Preempt-code
  if (check_preempt_label_.is_linked()) {
    SafeCallTarget(&check_preempt_label_);

    StoreRegExpStackPointerToMemory(backtrack_stackpointer(), r3);

    CallCheckStackGuardState(r2);
    __ CmpS64(r2, Operand::Zero());
    // If returning non-zero, we should end execution with the given
    // result as return value.
    __ bne(&return_r2);

    LoadRegExpStackPointerFromMemory(backtrack_stackpointer());

    // String might have moved: Reload end of string from frame.
    __ LoadU64(end_of_input_address(),
               MemOperand(frame_pointer(), kInputEndOffset));
    SafeReturn();
  }

  // Backtrack stack overflow code.
  if (stack_overflow_label_.is_linked()) {
    SafeCallTarget(&stack_overflow_label_);
    // Reached if the backtrack-stack limit has been hit.

    // Call GrowStack(isolate).

    StoreRegExpStackPointerToMemory(backtrack_stackpointer(), r3);

    static constexpr int kNumArguments = 1;
    __ PrepareCallCFunction(kNumArguments, r2);
    __ mov(r2, Operand(ExternalReference::isolate_address(isolate())));
    ExternalReference grow_stack = ExternalReference::re_grow_stack();
    CallCFunctionFromIrregexpCode(grow_stack, kNumArguments);
    // If nullptr is returned, we have failed to grow the stack, and must exit
    // with a stack-overflow exception.
    __ CmpS64(r2, Operand::Zero());
    __ beq(&exit_with_exception);
    // Otherwise use return value as new stack pointer.
    __ mov(backtrack_stackpointer(), r2);
    // Restore saved registers and continue.
    SafeReturn();
  }

  if (exit_with_exception.is_linked()) {
    // If any of the code above needed to exit with an exception.
    __ bind(&exit_with_exception);
    // Exit with Result EXCEPTION(-1) to signal thrown exception.
    __ mov(r2, Operand(EXCEPTION));
    __ b(&return_r2);
  }

  if (fallback_label_.is_linked()) {
    __ bind(&fallback_label_);
    __ mov(r2, Operand(FALLBACK_TO_EXPERIMENTAL));
    __ b(&return_r2);
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

void RegExpMacroAssemblerS390::GoTo(Label* to) { BranchOrBacktrack(al, to); }

void RegExpMacroAssemblerS390::IfRegisterGE(int reg, int comparand,
                                            Label* if_ge) {
  __ LoadU64(r2, register_location(reg), r0);
  __ CmpS64(r2, Operand(comparand));
  BranchOrBacktrack(ge, if_ge);
}

void RegExpMacroAssemblerS390::IfRegisterLT(int reg, int comparand,
                                            Label* if_lt) {
  __ LoadU64(r2, register_location(reg), r0);
  __ CmpS64(r2, Operand(comparand));
  BranchOrBacktrack(lt, if_lt);
}

void RegExpMacroAssemblerS390::IfRegisterEqPos(int reg, Label* if_eq) {
  __ LoadU64(r2, register_location(reg), r0);
  __ CmpS64(r2, current_input_offset());
  BranchOrBacktrack(eq, if_eq);
}

RegExpMacroAssembler::IrregexpImplementation
RegExpMacroAssemblerS390::Implementation() {
  return kS390Implementation;
}

void RegExpMacroAssemblerS390::PopCurrentPosition() {
  Pop(current_input_offset());
}

void RegExpMacroAssemblerS390::PopRegister(int register_index) {
  Pop(r2);
  __ StoreU64(r2, register_location(register_index));
}

void RegExpMacroAssemblerS390::PushBacktrack(Label* label) {
  if (label->is_bound()) {
    int target = label->pos();
    __ mov(r2,
           Operand(target + InstructionStream::kHeaderSize - kHeapObjectTag));
  } else {
    masm_->load_label_offset(r2, label);
  }
  Push(r2);
  CheckStackLimit();
}

void RegExpMacroAssemblerS390::PushCurrentPosition() {
  Push(current_input_offset());
}

void RegExpMacroAssemblerS390::PushRegister(int register_index,
                                            StackCheckFlag check_stack_limit) {
  __ LoadU64(r2, register_location(register_index), r0);
  Push(r2);
  if (check_stack_limit) CheckStackLimit();
}

void RegExpMacroAssemblerS390::ReadCurrentPositionFromRegister(int reg) {
  __ LoadU64(current_input_offset(), register_location(reg), r0);
}

void RegExpMacroAssemblerS390::WriteStackPointerToRegister(int reg) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ mov(r3, Operand(ref));
  __ LoadU64(r3, MemOperand(r3));
  __ SubS64(r2, backtrack_stackpointer(), r3);
  __ StoreU64(r2, register_location(reg));
}

void RegExpMacroAssemblerS390::ReadStackPointerFromRegister(int reg) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ mov(r2, Operand(ref));
  __ LoadU64(r2, MemOperand(r2));
  __ LoadU64(backtrack_stackpointer(), register_location(reg), r0);
  __ AddS64(backtrack_stackpointer(), backtrack_stackpointer(), r2);
}

void RegExpMacroAssemblerS390::SetCurrentPositionFromEnd(int by) {
  Label after_position;
  __ CmpS64(current_input_offset(), Operand(-by * char_size()));
  __ bge(&after_position);
  __ mov(current_input_offset(), Operand(-by * char_size()));
  // On RegExp code entry (where this operation is used), the character before
  // the current position is expected to be already loaded.
  // We have advanced the position, so it's safe to read backwards.
  LoadCurrentCharacterUnchecked(-1, 1);
  __ bind(&after_position);
}

void RegExpMacroAssemblerS390::SetRegister(int register_index, int to) {
  DCHECK(register_index >= num_saved_registers_);  // Reserved for positions!
  __ mov(r2, Operand(to));
  __ StoreU64(r2, register_location(register_index));
}

bool RegExpMacroAssemblerS390::Succeed() {
  __ b(&success_label_);
  return global();
}

void RegExpMacroAssemblerS390::WriteCurrentPositionToRegister(int reg,
                                                              int cp_offset) {
  if (cp_offset == 0) {
    __ StoreU64(current_input_offset(), register_location(reg));
  } else {
    __ AddS64(r2, current_input_offset(), Operand(cp_offset * char_size()));
    __ StoreU64(r2, register_location(reg));
  }
}

void RegExpMacroAssemblerS390::ClearRegisters(int reg_from, int reg_to) {
  DCHECK(reg_from <= reg_to);
  __ LoadU64(r2, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
  for (int reg = reg_from; reg <= reg_to; reg++) {
    __ StoreU64(r2, register_location(reg));
  }
}

// Private methods:

void RegExpMacroAssemblerS390::CallCheckStackGuardState(Register scratch,
                                                        Operand extra_space) {
  DCHECK(!isolate()->IsGeneratingEmbeddedBuiltins());
  DCHECK(!masm_->options().isolate_independent_code);

  static constexpr int num_arguments = 4;
  __ PrepareCallCFunction(num_arguments, scratch);
  // Extra space for variables to consider in stack check.
  __ mov(kCArgRegs[3], extra_space);
  // RegExp code frame pointer.
  __ mov(kCArgRegs[2], frame_pointer());
  // InstructionStream of self.
  __ mov(kCArgRegs[1], Operand(masm_->CodeObject()));
  // r2 becomes return address pointer.
  __ lay(r2, MemOperand(sp, kStackFrameRASlot * kSystemPointerSize));
  ExternalReference stack_guard_check =
      ExternalReference::re_check_stack_guard_state();

  __ mov(ip, Operand(stack_guard_check));

#if V8_OS_ZOS
  // Shuffle input arguments
  __ mov(r1, r2);
  __ mov(r2, r3);
  __ mov(r3, r4);

  // XPLINK treats r7 as voliatile return register, but r14 as preserved
  // Since Linux is the other way around, perserve r7 value in r14 across
  // the call.
  __ mov(r14, r7);
  const int stack_slots = kXPLINKStackFrameExtraParamSlot + num_arguments;
  __ lay(r4, MemOperand(sp, -((stack_slots * kSystemPointerSize) +
                              kStackPointerBias)));
  __ StoreMultipleP(
      r5, r6,
      MemOperand(r4, kStackPointerBias +
                         kXPLINKStackFrameExtraParamSlot * kSystemPointerSize));

  // Obtain code entry based on function pointer
  __ LoadMultipleP(r5, r6, MemOperand(ip));

  // Call function
  __ StoreReturnAddressAndCall(r6);

  __ LoadMultipleP(
      r5, r6,
      MemOperand(r4, kStackPointerBias +
                         kXPLINKStackFrameExtraParamSlot * kSystemPointerSize));

  // Restore original r7
  __ mov(r7, r14);

  // Shuffle the result
  __ mov(r2, r3);
#else
  __ StoreReturnAddressAndCall(ip);
#endif

  if (base::OS::ActivationFrameAlignment() > kSystemPointerSize) {
    __ LoadU64(
        sp, MemOperand(sp, (kNumRequiredStackFrameSlots * kSystemPointerSize)));
  } else {
    __ la(sp,
          MemOperand(sp, (kNumRequiredStackFrameSlots * kSystemPointerSize)));
  }

  __ mov(code_pointer(), Operand(masm_->CodeObject()));
}

// Helper function for reading a value out of a stack frame.
template <typename T>
static T& frame_entry(Address re_frame, int frame_offset) {
  DCHECK_EQ(kSystemPointerSize, sizeof(T));
  return reinterpret_cast<T&>(Memory<uint64_t>(re_frame + frame_offset));
}

template <typename T>
static T* frame_entry_address(Address re_frame, int frame_offset) {
  return reinterpret_cast<T*>(re_frame + frame_offset);
}

int RegExpMacroAssemblerS390::CheckStackGuardState(Address* return_address,
                                                   Address raw_code,
                                                   Address re_frame,
                                                   uintptr_t extra_space) {
  Tagged<InstructionStream> re_code =
      Cast<InstructionStream>(Tagged<Object>(raw_code));
  return NativeRegExpMacroAssembler::CheckStackGuardState(
      frame_entry<Isolate*>(re_frame, kIsolateOffset),
      frame_entry<intptr_t>(re_frame, kStartIndexOffset),
      static_cast<RegExp::CallOrigin>(
          frame_entry<intptr_t>(re_frame, kDirectCallOffset)),
      return_address, re_code,
      frame_entry_address<Address>(re_frame, kInputStringOffset),
      frame_entry_address<const uint8_t*>(re_frame, kInputStartOffset),
      frame_entry_address<const uint8_t*>(re_frame, kInputEndOffset),
      extra_space);
}

MemOperand RegExpMacroAssemblerS390::register_location(int register_index) {
  DCHECK(register_index < (1 << 30));
  if (num_registers_ <= register_index) {
    num_registers_ = register_index + 1;
  }
  return MemOperand(frame_pointer(),
                    kRegisterZeroOffset - register_index * kSystemPointerSize);
}

void RegExpMacroAssemblerS390::CheckPosition(int cp_offset,
                                             Label* on_outside_input) {
  if (cp_offset >= 0) {
    __ CmpS64(current_input_offset(), Operand(-cp_offset * char_size()));
    BranchOrBacktrack(ge, on_outside_input);
  } else {
    __ LoadU64(r3, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
    __ AddS64(r2, current_input_offset(), Operand(cp_offset * char_size()));
    __ CmpS64(r2, r3);
    BranchOrBacktrack(le, on_outside_input);
  }
}

void RegExpMacroAssemblerS390::BranchOrBacktrack(Condition condition, Label* to,
                                                 CRegister cr) {
  if (condition == al) {  // Unconditional.
    if (to == nullptr) {
      Backtrack();
      return;
    }
    __ b(to);
    return;
  }
  if (to == nullptr) {
    __ b(condition, &backtrack_label_);
    return;
  }
  __ b(condition, to);
}

void RegExpMacroAssemblerS390::SafeCall(Label* to, Condition cond,
                                        CRegister cr) {
  Label skip;
  __ b(NegateCondition(cond), &skip);
  __ b(r14, to);
  __ bind(&skip);
}

void RegExpMacroAssemblerS390::SafeReturn() {
  __ pop(r14);
  __ mov(ip, Operand(masm_->CodeObject()));
  __ AddS64(r14, ip);
  __ Ret();
}

void RegExpMacroAssemblerS390::SafeCallTarget(Label* name) {
  __ bind(name);
  __ mov(r0, r14);
  __ mov(ip, Operand(masm_->CodeObject()));
  __ SubS64(r0, r0, ip);
  __ push(r0);
}

void RegExpMacroAssemblerS390::Push(Register source) {
  DCHECK(source != backtrack_stackpointer());
  __ lay(backtrack_stackpointer(),
         MemOperand(backtrack_stackpointer(), -kSystemPointerSize));
  __ StoreU64(source, MemOperand(backtrack_stackpointer()));
}

void RegExpMacroAssemblerS390::Pop(Register target) {
  DCHECK(target != backtrack_stackpointer());
  __ LoadU64(target, MemOperand(backtrack_stackpointer()));
  __ la(backtrack_stackpointer(),
        MemOperand(backtrack_stackpointer(), kSystemPointerSize));
}

void RegExpMacroAssemblerS390::CallCFunctionFromIrregexpCode(
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
  __ CallCFunction(function, num_arguments, ABI_USES_FUNCTION_DESCRIPTORS,
                   SetIsolateDataSlots::kNo);
}

void RegExpMacroAssemblerS390::CheckPreemption() {
  // Check for preemption.
  ExternalReference stack_limit =
      ExternalReference::address_of_jslimit(isolate());
  __ mov(r2, Operand(stack_limit));
  __ CmpU64(sp, MemOperand(r2));
  SafeCall(&check_preempt_label_, le);
}

void RegExpMacroAssemblerS390::CheckStackLimit() {
  ExternalReference stack_limit =
      ExternalReference::address_of_regexp_stack_limit_address(isolate());
  __ mov(r2, Operand(stack_limit));
  __ CmpU64(backtrack_stackpointer(), MemOperand(r2));
  SafeCall(&stack_overflow_label_, le);
}

void RegExpMacroAssemblerS390::CallCFunctionUsingStub(
    ExternalReference function, int num_arguments) {
  // Must pass all arguments in registers. The stub pushes on the stack.
  DCHECK_GE(8, num_arguments);
  __ mov(code_pointer(), Operand(function));
  Label ret;
  __ larl(r14, &ret);
  __ StoreU64(r14, MemOperand(sp, kStackFrameRASlot * kSystemPointerSize));
  __ b(code_pointer());
  __ bind(&ret);
  if (base::OS::ActivationFrameAlignment() > kSystemPointerSize) {
    __ LoadU64(
        sp, MemOperand(sp, (kNumRequiredStackFrameSlots * kSystemPointerSize)));
  } else {
    __ la(sp,
          MemOperand(sp, (kNumRequiredStackFrameSlots * kSystemPointerSize)));
  }
  __ mov(code_pointer(), Operand(masm_->CodeObject()));
}


void RegExpMacroAssemblerS390::LoadCurrentCharacterUnchecked(int cp_offset,
                                                             int characters) {
  if (mode_ == LATIN1) {
    // using load reverse for big-endian platforms
    if (characters == 4) {
      __ LoadU32LE(current_character(),
                   MemOperand(current_input_offset(), end_of_input_address(),
                              cp_offset * char_size()));
    } else if (characters == 2) {
      __ LoadU16LE(current_character(),
                   MemOperand(current_input_offset(), end_of_input_address(),
                              cp_offset * char_size()));
    } else {
      DCHECK_EQ(1, characters);
      __ LoadU8(current_character(),
                MemOperand(current_input_offset(), end_of_input_address(),
                           cp_offset * char_size()));
    }
  } else {
    DCHECK(mode_ == UC16);
    if (characters == 2) {
      __ LoadU32(current_character(),
                MemOperand(current_input_offset(), end_of_input_address(),
                           cp_offset * char_size()));
#if !V8_TARGET_LITTLE_ENDIAN
      // need to swap the order of the characters for big-endian platforms
      __ rll(current_character(), current_character(), Operand(16));
#endif
    } else {
      DCHECK_EQ(1, characters);
      __ LoadU16(
          current_character(),
                MemOperand(current_input_offset(), end_of_input_address(),
                           cp_offset * char_size()));
    }
  }
}

#undef __

}  // namespace internal
}  // namespace v8

#endif  // V8_TARGET_ARCH_S390X
```