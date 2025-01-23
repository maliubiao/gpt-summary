Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of V8's regular expression engine for the RISC-V architecture.

Here's a breakdown of how to address the request:

1. **Identify the Core Purpose:** The code is within a `RegExpMacroAssemblerRISCV` class. This strongly suggests it's responsible for generating RISC-V assembly code for regular expression matching.

2. **Analyze Key Sections:** Go through the code snippet and identify the main blocks and their apparent functions. Look for keywords, function names, and comments that provide clues.

3. **Relate to Regular Expression Concepts:** Connect the identified functionalities to common regex operations like matching, capturing, backtracking, and handling global flags.

4. **Address Specific Instructions:**  The prompt asks about `.tq` files (Torque). Confirm that this file is C++ and not Torque.

5. **JavaScript Relevance:** Consider how this low-level code relates to JavaScript's `RegExp` object and its methods. Provide a simple JavaScript example to illustrate the connection.

6. **Code Logic and Examples:** Look for areas with clear logic and provide hypothetical inputs and outputs to demonstrate the code's behavior (e.g., how capture registers are handled).

7. **Common Programming Errors:**  Think about typical mistakes developers might make when working with regular expressions and how this code might be involved (e.g., stack overflow with complex regexes).

8. **Summarize the Functionality:**  Condense the findings into a clear and concise summary, addressing all parts of the user's request.
```cpp
      // Fill saved registers with initial value = start offset - 1.
      if (num_saved_registers_ > 8) {
        // Address of register 0.
        __ AddWord(a1, frame_pointer(), Operand(kRegisterZeroOffset));
        __ li(a2, Operand(num_saved_registers_));
        Label init_loop;
        __ bind(&init_loop);
        __ StoreWord(a0, MemOperand(a1));
        __ AddWord(a1, a1, Operand(-kSystemPointerSize));
        __ SubWord(a2, a2, Operand(1));
        __ Branch(&init_loop, ne, a2, Operand(zero_reg));
      } else {
        for (int i = 0; i < num_saved_registers_; i++) {
          __ StoreWord(a0, register_location(i));
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
        __ LoadWord(a1, MemOperand(frame_pointer(), kInputStartOffset));
        __ LoadWord(a0, MemOperand(frame_pointer(), kRegisterOutputOffset));
        __ LoadWord(a2, MemOperand(frame_pointer(), kStartIndexOffset));
        __ SubWord(a1, end_of_input_address(), a1);
        // a1 is length of input in bytes.
        if (mode_ == UC16) {
          __ srli(a1, a1, 1);
        }
        // a1 is length of input in characters.
        __ AddWord(a1, a1, Operand(a2));
        // a1 is length of string in characters.

        DCHECK_EQ(0, num_saved_registers_ % 2);
        // Always an even number of capture registers. This allows us to
        // unroll the loop once to add an operation between a load of a
        // register and the following use of that register.
        for (int i = 0; i < num_saved_registers_; i += 2) {
          __ LoadWord(a2, register_location(i));
          __ LoadWord(a3, register_location(i + 1));
          if (i == 0 && global_with_zero_length_check()) {
            // Keep capture start in a4 for the zero-length check later.
            __ mv(s3, a2);
          }
          if (mode_ == UC16) {
            __ srai(a2, a2, 1);
            __ AddWord(a2, a2, a1);
            __ srai(a3, a3, 1);
            __ AddWord(a3, a3, a1);
          } else {
            __ AddWord(a2, a1, Operand(a2));
            __ AddWord(a3, a1, Operand(a3));
          }
          // V8 expects the output to be an int32_t array.
          __ Sw(a2, MemOperand(a0));
          __ AddWord(a0, a0, kIntSize);
          __ Sw(a3, MemOperand(a0));
          __ AddWord(a0, a0, kIntSize);
        }
      }

      if (global()) {
        // Restart matching if the regular expression is flagged as global.
        __ LoadWord(a0, MemOperand(frame_pointer(), kSuccessfulCapturesOffset));
        __ LoadWord(a1, MemOperand(frame_pointer(), kNumOutputRegistersOffset));
        __ LoadWord(a2, MemOperand(frame_pointer(), kRegisterOutputOffset));
        // Increment success counter.
        __ AddWord(a0, a0, 1);
        __ StoreWord(a0,
                     MemOperand(frame_pointer(), kSuccessfulCapturesOffset));
        // Capture results have been stored, so the number of remaining global
        // output registers is reduced by the number of stored captures.
        __ SubWord(a1, a1, num_saved_registers_);
        // Check whether we have enough room for another set of capture results.
        __ Branch(&return_a0, lt, a1, Operand(num_saved_registers_));

        __ StoreWord(a1,
                     MemOperand(frame_pointer(), kNumOutputRegistersOffset));
        // Advance the location for output.
        __ AddWord(a2, a2, num_saved_registers_ * kIntSize);
        __ StoreWord(a2, MemOperand(frame_pointer(), kRegisterOutputOffset));

        // Restore the original regexp stack pointer value (effectively, pop the
        // stored base pointer).
        PopRegExpBasePointer(backtrack_stackpointer(), a2);

        Label reload_string_start_minus_one;

        if (global_with_zero_length_check()) {
          // Special case for zero-length matches.
          // s3: capture start index
          // Not a zero-length match, restart.
          __ Branch(&reload_string_start_minus_one, ne, current_input_offset(),
                    Operand(s3));
          // Offset from the end is zero if we already reached the end.
          __ Branch(&exit_label_, eq, current_input_offset(),
                    Operand(zero_reg));
          // Advance current position after a zero-length match.
          Label advance;
          __ bind(&advance);
          __ AddWord(current_input_offset(), current_input_offset(),
                     Operand((mode_ == UC16) ? 2 : 1));
          if (global_unicode()) CheckNotInSurrogatePair(0, &advance);
        }

        __ bind(&reload_string_start_minus_one);
        // Prepare a0 to initialize registers with its value in the next run.
        // Must be immediately before the jump to avoid clobbering.
        __ LoadWord(a0,
                    MemOperand(frame_pointer(), kStringStartMinusOneOffset));

        __ Branch(&load_char_start_regexp);
      } else {
        __ li(a0, Operand(SUCCESS));
      }
    }
    // Exit and return a0.
    __ bind(&exit_label_);
    if (global()) {
      __ LoadWord(a0, MemOperand(frame_pointer(), kSuccessfulCapturesOffset));
    }

    __ bind(&return_a0);
    // Restore the original regexp stack pointer value (effectively, pop the
    // stored base pointer).
    PopRegExpBasePointer(backtrack_stackpointer(), a1);
    // Skip sp past regexp registers and local variables..
    __ mv(sp, frame_pointer());

    // Restore registers fp..s11 and return (restoring ra to pc).
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
      StoreRegExpStackPointerToMemory(backtrack_stackpointer(), a1);
      // Put regexp engine registers on stack.
      CallCheckStackGuardState(a0);
      // If returning non-zero, we should end execution with the given
      // result as return value.
      __ Branch(&return_a0, ne, a0, Operand(zero_reg));
      LoadRegExpStackPointerFromMemory(backtrack_stackpointer());
      // String might have moved: Reload end of string from frame.
      __ LoadWord(end_of_input_address(),
                  MemOperand(frame_pointer(), kInputEndOffset));
      SafeReturn();
    }

    // Backtrack stack overflow code.
    if (stack_overflow_label_.is_linked()) {
      SafeCallTarget(&stack_overflow_label_);
      // Call GrowStack(isolate).
      StoreRegExpStackPointerToMemory(backtrack_stackpointer(), a1);

      static constexpr int kNumArguments = 1;
      __ PrepareCallCFunction(kNumArguments, 0, a0);
      __ li(a0, ExternalReference::isolate_address(isolate()));
      ExternalReference grow_stack = ExternalReference::re_grow_stack();
      CallCFunctionFromIrregexpCode(grow_stack, kNumArguments);
      // If nullptr is returned, we have failed to grow the stack, and must exit
      // with a stack-overflow exception.
      __ BranchShort(&exit_with_exception, eq, a0, Operand(zero_reg));
      // Otherwise use return value as new stack pointer.
      __ mv(backtrack_stackpointer(), a0);
      // Restore saved registers and continue.
      SafeReturn();
    }

    if (exit_with_exception.is_linked()) {
      // If any of the code above needed to exit with an exception.
      __ bind(&exit_with_exception);
      // Exit with Result EXCEPTION(-1) to signal thrown exception.
      __ li(a0, Operand(EXCEPTION));
      __ jmp(&return_a0);
    }

    if (fallback_label_.is_linked()) {
      __ bind(&fallback_label_);
      __ li(a0, Operand(FALLBACK_TO_EXPERIMENTAL));
      __ jmp(&return_a0);
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

void RegExpMacroAssemblerRISCV::GoTo(Label* to) {
  if (to == nullptr) {
    Backtrack();
    return;
  }
  __ jmp(to);
  return;
}

void RegExpMacroAssemblerRISCV::IfRegisterGE(int reg, int comparand,
                                             Label* if_ge) {
  __ LoadWord(a0, register_location(reg));
  BranchOrBacktrack(if_ge, ge, a0, Operand(comparand));
}

void RegExpMacroAssemblerRISCV::IfRegisterLT(int reg, int comparand,
                                             Label* if_lt) {
  __ LoadWord(a0, register_location(reg));
  BranchOrBacktrack(if_lt, lt, a0, Operand(comparand));
}

void RegExpMacroAssemblerRISCV::IfRegisterEqPos(int reg, Label* if_eq) {
  __ LoadWord(a0, register_location(reg));
  BranchOrBacktrack(if_eq, eq, a0, Operand(current_input_offset()));
}

RegExpMacroAssembler::IrregexpImplementation
RegExpMacroAssemblerRISCV::Implementation() {
  return kRISCVImplementation;
}

void RegExpMacroAssemblerRISCV::PopCurrentPosition() {
  Pop(current_input_offset());
}

void RegExpMacroAssemblerRISCV::PopRegister(int register_index) {
  Pop(a0);
  __ StoreWord(a0, register_location(register_index));
}

void RegExpMacroAssemblerRISCV::PushBacktrack(Label* label) {
  if (label->is_bound()) {
    int target = label->pos();
    __ li(a0,
          Operand(target + InstructionStream::kHeaderSize - kHeapObjectTag));
  } else {
    Assembler::BlockTrampolinePoolScope block_trampoline_pool(masm_.get());
    Label after_constant;
    __ BranchShort(&after_constant);
    int offset = masm_->pc_offset();
    int cp_offset = offset + InstructionStream::kHeaderSize - kHeapObjectTag;
    __ emit(0);
    masm_->label_at_put(label, offset);
    __ bind(&after_constant);
    if (is_int16(cp_offset)) {
      __ Load32U(a0, MemOperand(code_pointer(), cp_offset));
    } else {
      __ AddWord(a0, code_pointer(), cp_offset);
      __ Load32U(a0, MemOperand(a0, 0));
    }
  }
  Push(a0);
  CheckStackLimit();
}

void RegExpMacroAssemblerRISCV::PushCurrentPosition() {
  Push(current_input_offset());
}

void RegExpMacroAssemblerRISCV::PushRegister(int register_index,
                                             StackCheckFlag check_stack_limit) {
  __ LoadWord(a0, register_location(register_index));
  Push(a0);
  if (check_stack_limit) CheckStackLimit();
}

void RegExpMacroAssemblerRISCV::ReadCurrentPositionFromRegister(int reg) {
  __ LoadWord(current_input_offset(), register_location(reg));
}

void RegExpMacroAssemblerRISCV::WriteStackPointerToRegister(int reg) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ li(a0, ref);
  __ LoadWord(a0, MemOperand(a0));
  __ SubWord(a0, backtrack_stackpointer(), a0);
  __ Sw(a0, register_location(reg));
}

void RegExpMacroAssemblerRISCV::ReadStackPointerFromRegister(int reg) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ li(a1, ref);
  __ LoadWord(a1, MemOperand(a1));
  __ Lw(backtrack_stackpointer(), register_location(reg));
  __ AddWord(backtrack_stackpointer(), backtrack_stackpointer(), a1);
}

void RegExpMacroAssemblerRISCV::SetCurrentPositionFromEnd(int by) {
  Label after_position;
  __ BranchShort(&after_position, ge, current_input_offset(),
                 Operand(-by * char_size()));
  __ li(current_input_offset(), -by * char_size());
  // On RegExp code entry (where this operation is used), the character before
  // the current position is expected to be already loaded.
  // We have advanced the position, so it's safe to read backwards.
  LoadCurrentCharacterUnchecked(-1, 1);
  __ bind(&after_position);
}

void RegExpMacroAssemblerRISCV::SetRegister(int register_index, int to) {
  DCHECK(register_index >= num_saved_registers_);  // Reserved for positions!
  __ li(a0, Operand(to));
  __ StoreWord(a0, register_location(register_index));
}

bool RegExpMacroAssemblerRISCV::Succeed() {
  __ jmp(&success_label_);
  return global();
}

void RegExpMacroAssemblerRISCV::WriteCurrentPositionToRegister(int reg,
                                                               int cp_offset) {
  if (cp_offset == 0) {
    __ StoreWord(current_input_offset(), register_location(reg));
  } else {
    __ AddWord(a0, current_input_offset(), Operand(cp_offset * char_size()));
    __ StoreWord(a0, register_location(reg));
  }
}

void RegExpMacroAssemblerRISCV::ClearRegisters(int reg_from, int reg_to) {
  DCHECK(reg_from <= reg_to);
  __ LoadWord(a0, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
  for (int reg = reg_from; reg <= reg_to; reg++) {
    __ StoreWord(a0, register_location(reg));
  }
}
#ifdef RISCV_HAS_NO_UNALIGNED
bool RegExpMacroAssemblerRISCV::CanReadUnaligned() const { return false; }
#endif
// Private methods:

void RegExpMacroAssemblerRISCV::CallCheckStackGuardState(Register scratch,
                                                         Operand extra_space) {
  DCHECK(!isolate()->IsGeneratingEmbeddedBuiltins());
  DCHECK(!masm_->options().isolate_independent_code);

  int stack_alignment = base::OS::ActivationFrameAlignment();

  // Align the stack pointer and save the original sp value on the stack.
  __ mv(scratch, sp);
  __ SubWord(sp, sp, Operand(kSystemPointerSize));
  DCHECK(base::bits::IsPowerOfTwo(stack_alignment));
  __ And(sp, sp, Operand(-stack_alignment));
  __ StoreWord(scratch, MemOperand(sp));

  __ li(a3, extra_space);
  __ mv(a2, frame_pointer());
  // InstructionStream of self.
  __ li(a1, Operand(masm_->CodeObject()), CONSTANT_SIZE);

  // We need to make room for the return address on the stack.
  DCHECK(IsAligned(stack_alignment, kSystemPointerSize));
  __ SubWord(sp, sp, Operand(stack_alignment));

  // The stack pointer now points to cell where the return address will be
  // written. Arguments are in registers, meaning we treat the return address as
  // argument 5. Since DirectCEntry will handle allocating space for the C
  // argument slots, we don't need to care about that here. This is how the
  // stack will look (sp meaning the value of sp at this moment):
  // [sp + 3] - empty slot if needed for alignment.
  // [sp + 2] - saved sp.
  // [sp + 1] - second word reserved for return value.
  // [sp + 0] - first word reserved for return value.

  // a0 will point to the return address, placed by DirectCEntry.
  __ mv(a0, sp);

  ExternalReference stack_guard_check =
      ExternalReference::re_check_stack_guard_state();
  __ li(t6, Operand(stack_guard_check));

  EmbeddedData d = EmbeddedData::FromBlob();
  CHECK(Builtins::IsIsolateIndependent(Builtin::kDirectCEntry));
  Address entry = d.InstructionStartOf(Builtin::kDirectCEntry);
  __ li(kScratchReg, Operand(entry, RelocInfo::OFF_HEAP_TARGET));
  __ Call(kScratchReg);

  // DirectCEntry allocated space for the C argument slots so we have to
  // drop them with the return address from the stack with loading saved sp.
  // At this point stack must look:
  // [sp + 7] - empty slot if needed for alignment.
  // [sp + 6] - saved sp.
  // [sp + 5] - second word reserved for return value.
  // [sp + 4] - first word reserved for return value.
  // [sp + 3] - C argument slot.
  // [sp + 2] - C argument slot.
  // [sp + 1] - C argument slot.
  // [sp + 0] - C argument slot.
  __ LoadWord(sp, MemOperand(sp, stack_alignment + kCArgsSlotsSize));

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

int64_t RegExpMacroAssemblerRISCV::CheckStackGuardState(Address* return_address,
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

MemOperand RegExpMacroAssemblerRISCV::register_location(int register_index) {
  DCHECK(register_index < (1 << 30));
  if (num_registers_ <= register_index) {
    num_registers_ = register_index + 1;
  }
  return MemOperand(frame_pointer(),
                    kRegisterZeroOffset - register_index * kSystemPointerSize);
}

void RegExpMacroAssemblerRISCV::CheckPosition(int cp_offset,
                                              Label* on_outside_input) {
  if (cp_offset >= 0) {
    BranchOrBacktrack(on_outside_input, ge, current_input_offset(),
                      Operand(-cp_offset * char_size()));
  } else {
    __ LoadWord(a1, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
    __ AddWord(a0, current_input_offset(), Operand(cp_offset * char_size()));
    BranchOrBacktrack(on_outside_input, le, a0, Operand(a1));
  }
}

void RegExpMacroAssemblerRISCV::BranchOrBacktrack(Label* to,
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

void RegExpMacroAssemblerRISCV::SafeCall(Label* to, Condition cond, Register rs,
                                         const Operand& rt) {
  __ BranchAndLink(to, cond, rs, rt);
}

void RegExpMacroAssemblerRISCV::SafeReturn() {
  __ pop(ra);
  __ AddWord(t1, ra, Operand(masm_->CodeObject()));
  __ Jump(t1);
}

void RegExpMacroAssemblerRISCV::SafeCallTarget(Label* name) {
  __ bind(name);
  __ SubWord(ra, ra, Operand(masm_->CodeObject()));
  __ push(ra);
}

void RegExpMacroAssemblerRISCV::Push(Register source) {
  DCHECK(source != backtrack_stackpointer());
  __ AddWord(backtrack_stackpointer(), backtrack_stackpointer(),
             Operand(-kIntSize));
  __ Sw(source, MemOperand(backtrack_stackpointer()));
}

void RegExpMacroAssemblerRISCV::Pop(Register target) {
  DCHECK(target != backtrack_stackpointer());
  __ Lw(target, MemOperand(backtrack_stackpointer()));
  __ AddWord(backtrack_stackpointer(), backtrack_stackpointer(), kIntSize);
}

void RegExpMacroAssemblerRISCV::CheckPreemption() {
  // Check for preemption.
  ExternalReference stack_limit =
      ExternalReference::address_of_jslimit(masm_->isolate());
  __ li(a0, Operand(stack_limit));
  __ LoadWord(a0, MemOperand(a0));
  SafeCall(&check_preempt_label_, Uless_equal, sp, Operand(a0));
}

void RegExpMacroAssemblerRISCV::CheckStackLimit() {
  ExternalReference stack_limit =
      ExternalReference::address_of_regexp_stack_limit_address(
          masm_->isolate());

  __ li(a0, Operand(stack_limit));
  __ LoadWord(a0, MemOperand(a0));
  SafeCall(&stack_overflow_label_, Uless_equal, backtrack_stackpointer(),
           Operand(a0));
}

void RegExpMacroAssemblerRISCV::LoadCurrentCharacterUnchecked(int cp_offset,
                                                              int characters) {
  Register offset = current_input_offset();
  if (cp_offset != 0) {
    // kScratchReg2 is not being used to store the capture start index at this
    // point.
    __ AddWord(kScratchReg2, current_input_offset(),
               Operand(cp_offset * char_size()));
    offset = kScratchReg2;
  }
  // If unaligned load/stores are not supported then this function must only
  // be used to load a single character at a time.
  if (!CanReadUnaligned()) {
    DCHECK_EQ(1, characters);
  }

  if (mode_ == LATIN1) {
    if (characters == 4) {
      __ AddWord(kScratchReg, end_of_input_address(), offset);
      __ Load32U(current_character(), MemOperand(kScratchReg));
    } else if (characters == 2) {
      __ AddWord(kScratchReg, end_of_input_address(), offset);
      __ Lhu(current_character(), MemOperand(kScratchReg));
    } else {
      DCHECK_EQ(1, characters);
      __ AddWord(kScratchReg, end_of_input_address(), offset);
      __ Lbu(current_character(), MemOperand(kScratchReg));
    }
  } else {
    DCHECK_EQ(UC16, mode_);
    if (characters == 2) {
      __ AddWord(kScratchReg, end_of_input_address(), offset);
      __ Load32U(current_character(), MemOperand(kScratchReg));
    } else {
      DCHECK_EQ(1, characters);
      __ AddWord(kScratchReg, end_of_input_address(), offset);
      __ Lhu(current_character(), MemOperand(kScratchReg));
    }
  }
}

void RegExpMacroAssemblerRISCV::CallCFunctionFromIrregexpCode(
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
#undef __

}  // namespace internal
}  // namespace v8
```

## 功能归纳 (第 2 部分)

这是 `v8/src/regexp/riscv/regexp-macro-assembler-riscv.cc` 源代码的第二部分，主要负责实现正则表达式匹配过程中的核心功能，特别是关于**成功匹配和回溯处理**。

**主要功能:**

1. **处理成功匹配 (`success_label_`):**
   - **保存捕获组信息:** 当正则表达式匹配成功时，这段代码负责将捕获组的起始和结束位置信息存储到预先分配的输出缓冲区中。
   - **处理 Unicode 编码:**  根据字符串的编码方式 (UC16 或 LATIN1) 调整捕获组位置的计算。
   - **处理全局匹配 (`global()`):**
     - 如果正则表达式设置了 `global` 标志，匹配成功后不会立即返回，而是会尝试从当前匹配位置之后继续匹配。
     - 它会更新成功匹配的计数器，并检查是否有足够的输出缓冲区空间来存储下一轮匹配的捕获组信息。
     - 特殊处理零长度匹配，避免无限循环。
     - 恢复之前的正则表达式栈指针，准备进行下一轮匹配。

2. **处理退出 (`exit_label_`, `return_a0`):**
   - 无论匹配成功与否，最终都会跳转到退出标签。
   - 对于全局匹配，返回的是成功匹配的次数。
   - 恢复正则表达式栈指针和寄存器状态，然后返回。

3. **处理回溯 (`backtrack_label_`):**
   - 当匹配失败需要回溯时，会跳转到 `backtrack_label_`。
   - 调用 `Backtrack()` 函数执行具体的回溯逻辑（这部分代码在第一部分）。

4. **处理抢占 (`check_preempt_label_`):**
   - 定期检查 JavaScript 执行是否被抢占（例如，时间片到期）。
   - 如果发生抢占，会保存当前正则表达式的状态，并调用 C++ 函数 `CheckStackGuardState` 来处理。
   - 如果 `CheckStackGuardState` 返回非零值，则直接返回该值，否则恢复状态并继续执行。

5. **处理栈溢出 (`stack_overflow_label_`):**
   - 检查正则表达式的栈是否溢出（用于存储回溯点）。
   - 如果栈溢出，会调用 `GrowStack` 函数尝试扩展栈空间。
   - 如果栈扩展失败，则抛出栈溢出异常。

6. **处理异常和回退 (`exit_with_exception`, `fallback_label_`):**
   - `exit_with_exception`: 用于在发生错误时返回异常结果。
   - `fallback_label_`: 用于在某些情况下回退到其他的正则表达式引擎实现。

7. **提供指令级别的操作:**  定义了许多用于生成 RISC-V 汇编指令的辅助函数，用于实现正则表达式的各种操作，例如：
   - `GoTo`: 无条件跳转。
   - `IfRegisterGE`, `IfRegisterLT`, `IfRegisterEqPos`:  条件跳转，基于寄存器值的比较。
   - `PushBacktrack`, `PopCurrentPosition`, `PushRegister`, `PopRegister`:  操作正则表达式的回溯栈。
   - `SetCurrentPositionFromEnd`, `SetRegister`:  设置寄存器值。
   - `WriteCurrentPositionToRegister`, `ReadCurrentPositionFromRegister`:  读写当前匹配位置。
   - `ClearRegisters`: 清空指定范围的寄存器。
   - `LoadCurrentCharacterUnchecked`:  从输入字符串中加载字符。
   - `CheckStackLimit`, `CheckPreemption`:  进行栈限制和抢占检查。

**关于 .tq 文件和 JavaScript 关系:**

- `v8/src/regexp/riscv/regexp-macro-assembler-riscv.cc` **不是**以 `.tq` 结尾，因此它是一个 **C++** 源代码文件，而不是 V8 Torque 代码。
- 它与 JavaScript 的 `RegExp` 对象的功能密切相关。当你在 JavaScript 中使用正则表达式（例如，通过 `String.prototype.match()`, `RegExp.prototype.exec()` 等方法），V8 引擎会编译这个正则表达式并使用类似这样的 `RegExpMacroAssemblerRISCV` 类生成底层的 RISC-V 汇编代码来执行匹配。

**JavaScript 示例:**

```javascript
const regex = /ab?c/g;
const text = "ac abc abbc";
let match;

while ((match = regex.exec(text)) !== null) {
  console.log(`找到匹配项: ${match[0]}, 索引: ${match.index}`);
  if (match.length > 1) {
    console.log("捕获组:", match.slice(1));
  }
}
```

在这个例子中，`RegExpMacroAssemblerRISCV` 的代码会被用来生成执行 `regex.exec(text)` 匹配操作的 RISC-V 指令。它会处理查找 "ac" 或 "abc" 模式，并由于 `g` 标志的存在，会多次执行匹配直到找不到更多匹配项。如果正则表达式中有括号 `()` 定义了捕获组，`RegExpMacroAssemblerRISCV` 的代码也会负责存储和提供这些捕获组的信息。

**代码逻辑推理 (假设输入与输出):**

假设有以下正则表达式和输入：

- **正则表达式:** `/a(b*)c/` (匹配 "a" 后面跟零个或多个 "b"，最后跟 "c")
- **输入字符串:** `"abbc"`

当匹配到 `"abbc"` 时，`success_label_` 部分的代码会执行以下操作：

- `num_saved_registers_` 将是 2 (因为有一个捕
### 提示词
```
这是目录为v8/src/regexp/riscv/regexp-macro-assembler-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/riscv/regexp-macro-assembler-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Fill saved registers with initial value = start offset - 1.
      if (num_saved_registers_ > 8) {
        // Address of register 0.
        __ AddWord(a1, frame_pointer(), Operand(kRegisterZeroOffset));
        __ li(a2, Operand(num_saved_registers_));
        Label init_loop;
        __ bind(&init_loop);
        __ StoreWord(a0, MemOperand(a1));
        __ AddWord(a1, a1, Operand(-kSystemPointerSize));
        __ SubWord(a2, a2, Operand(1));
        __ Branch(&init_loop, ne, a2, Operand(zero_reg));
      } else {
        for (int i = 0; i < num_saved_registers_; i++) {
          __ StoreWord(a0, register_location(i));
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
        __ LoadWord(a1, MemOperand(frame_pointer(), kInputStartOffset));
        __ LoadWord(a0, MemOperand(frame_pointer(), kRegisterOutputOffset));
        __ LoadWord(a2, MemOperand(frame_pointer(), kStartIndexOffset));
        __ SubWord(a1, end_of_input_address(), a1);
        // a1 is length of input in bytes.
        if (mode_ == UC16) {
          __ srli(a1, a1, 1);
        }
        // a1 is length of input in characters.
        __ AddWord(a1, a1, Operand(a2));
        // a1 is length of string in characters.

        DCHECK_EQ(0, num_saved_registers_ % 2);
        // Always an even number of capture registers. This allows us to
        // unroll the loop once to add an operation between a load of a
        // register and the following use of that register.
        for (int i = 0; i < num_saved_registers_; i += 2) {
          __ LoadWord(a2, register_location(i));
          __ LoadWord(a3, register_location(i + 1));
          if (i == 0 && global_with_zero_length_check()) {
            // Keep capture start in a4 for the zero-length check later.
            __ mv(s3, a2);
          }
          if (mode_ == UC16) {
            __ srai(a2, a2, 1);
            __ AddWord(a2, a2, a1);
            __ srai(a3, a3, 1);
            __ AddWord(a3, a3, a1);
          } else {
            __ AddWord(a2, a1, Operand(a2));
            __ AddWord(a3, a1, Operand(a3));
          }
          // V8 expects the output to be an int32_t array.
          __ Sw(a2, MemOperand(a0));
          __ AddWord(a0, a0, kIntSize);
          __ Sw(a3, MemOperand(a0));
          __ AddWord(a0, a0, kIntSize);
        }
      }

      if (global()) {
        // Restart matching if the regular expression is flagged as global.
        __ LoadWord(a0, MemOperand(frame_pointer(), kSuccessfulCapturesOffset));
        __ LoadWord(a1, MemOperand(frame_pointer(), kNumOutputRegistersOffset));
        __ LoadWord(a2, MemOperand(frame_pointer(), kRegisterOutputOffset));
        // Increment success counter.
        __ AddWord(a0, a0, 1);
        __ StoreWord(a0,
                     MemOperand(frame_pointer(), kSuccessfulCapturesOffset));
        // Capture results have been stored, so the number of remaining global
        // output registers is reduced by the number of stored captures.
        __ SubWord(a1, a1, num_saved_registers_);
        // Check whether we have enough room for another set of capture results.
        __ Branch(&return_a0, lt, a1, Operand(num_saved_registers_));

        __ StoreWord(a1,
                     MemOperand(frame_pointer(), kNumOutputRegistersOffset));
        // Advance the location for output.
        __ AddWord(a2, a2, num_saved_registers_ * kIntSize);
        __ StoreWord(a2, MemOperand(frame_pointer(), kRegisterOutputOffset));

        // Restore the original regexp stack pointer value (effectively, pop the
        // stored base pointer).
        PopRegExpBasePointer(backtrack_stackpointer(), a2);

        Label reload_string_start_minus_one;

        if (global_with_zero_length_check()) {
          // Special case for zero-length matches.
          // s3: capture start index
          // Not a zero-length match, restart.
          __ Branch(&reload_string_start_minus_one, ne, current_input_offset(),
                    Operand(s3));
          // Offset from the end is zero if we already reached the end.
          __ Branch(&exit_label_, eq, current_input_offset(),
                    Operand(zero_reg));
          // Advance current position after a zero-length match.
          Label advance;
          __ bind(&advance);
          __ AddWord(current_input_offset(), current_input_offset(),
                     Operand((mode_ == UC16) ? 2 : 1));
          if (global_unicode()) CheckNotInSurrogatePair(0, &advance);
        }

        __ bind(&reload_string_start_minus_one);
        // Prepare a0 to initialize registers with its value in the next run.
        // Must be immediately before the jump to avoid clobbering.
        __ LoadWord(a0,
                    MemOperand(frame_pointer(), kStringStartMinusOneOffset));

        __ Branch(&load_char_start_regexp);
      } else {
        __ li(a0, Operand(SUCCESS));
      }
    }
    // Exit and return a0.
    __ bind(&exit_label_);
    if (global()) {
      __ LoadWord(a0, MemOperand(frame_pointer(), kSuccessfulCapturesOffset));
    }

    __ bind(&return_a0);
    // Restore the original regexp stack pointer value (effectively, pop the
    // stored base pointer).
    PopRegExpBasePointer(backtrack_stackpointer(), a1);
    // Skip sp past regexp registers and local variables..
    __ mv(sp, frame_pointer());

    // Restore registers fp..s11 and return (restoring ra to pc).
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
      StoreRegExpStackPointerToMemory(backtrack_stackpointer(), a1);
      // Put regexp engine registers on stack.
      CallCheckStackGuardState(a0);
      // If returning non-zero, we should end execution with the given
      // result as return value.
      __ Branch(&return_a0, ne, a0, Operand(zero_reg));
      LoadRegExpStackPointerFromMemory(backtrack_stackpointer());
      // String might have moved: Reload end of string from frame.
      __ LoadWord(end_of_input_address(),
                  MemOperand(frame_pointer(), kInputEndOffset));
      SafeReturn();
    }

    // Backtrack stack overflow code.
    if (stack_overflow_label_.is_linked()) {
      SafeCallTarget(&stack_overflow_label_);
      // Call GrowStack(isolate).
      StoreRegExpStackPointerToMemory(backtrack_stackpointer(), a1);

      static constexpr int kNumArguments = 1;
      __ PrepareCallCFunction(kNumArguments, 0, a0);
      __ li(a0, ExternalReference::isolate_address(isolate()));
      ExternalReference grow_stack = ExternalReference::re_grow_stack();
      CallCFunctionFromIrregexpCode(grow_stack, kNumArguments);
      // If nullptr is returned, we have failed to grow the stack, and must exit
      // with a stack-overflow exception.
      __ BranchShort(&exit_with_exception, eq, a0, Operand(zero_reg));
      // Otherwise use return value as new stack pointer.
      __ mv(backtrack_stackpointer(), a0);
      // Restore saved registers and continue.
      SafeReturn();
    }

    if (exit_with_exception.is_linked()) {
      // If any of the code above needed to exit with an exception.
      __ bind(&exit_with_exception);
      // Exit with Result EXCEPTION(-1) to signal thrown exception.
      __ li(a0, Operand(EXCEPTION));
      __ jmp(&return_a0);
    }

    if (fallback_label_.is_linked()) {
      __ bind(&fallback_label_);
      __ li(a0, Operand(FALLBACK_TO_EXPERIMENTAL));
      __ jmp(&return_a0);
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

void RegExpMacroAssemblerRISCV::GoTo(Label* to) {
  if (to == nullptr) {
    Backtrack();
    return;
  }
  __ jmp(to);
  return;
}

void RegExpMacroAssemblerRISCV::IfRegisterGE(int reg, int comparand,
                                             Label* if_ge) {
  __ LoadWord(a0, register_location(reg));
  BranchOrBacktrack(if_ge, ge, a0, Operand(comparand));
}

void RegExpMacroAssemblerRISCV::IfRegisterLT(int reg, int comparand,
                                             Label* if_lt) {
  __ LoadWord(a0, register_location(reg));
  BranchOrBacktrack(if_lt, lt, a0, Operand(comparand));
}

void RegExpMacroAssemblerRISCV::IfRegisterEqPos(int reg, Label* if_eq) {
  __ LoadWord(a0, register_location(reg));
  BranchOrBacktrack(if_eq, eq, a0, Operand(current_input_offset()));
}

RegExpMacroAssembler::IrregexpImplementation
RegExpMacroAssemblerRISCV::Implementation() {
  return kRISCVImplementation;
}

void RegExpMacroAssemblerRISCV::PopCurrentPosition() {
  Pop(current_input_offset());
}

void RegExpMacroAssemblerRISCV::PopRegister(int register_index) {
  Pop(a0);
  __ StoreWord(a0, register_location(register_index));
}

void RegExpMacroAssemblerRISCV::PushBacktrack(Label* label) {
  if (label->is_bound()) {
    int target = label->pos();
    __ li(a0,
          Operand(target + InstructionStream::kHeaderSize - kHeapObjectTag));
  } else {
    Assembler::BlockTrampolinePoolScope block_trampoline_pool(masm_.get());
    Label after_constant;
    __ BranchShort(&after_constant);
    int offset = masm_->pc_offset();
    int cp_offset = offset + InstructionStream::kHeaderSize - kHeapObjectTag;
    __ emit(0);
    masm_->label_at_put(label, offset);
    __ bind(&after_constant);
    if (is_int16(cp_offset)) {
      __ Load32U(a0, MemOperand(code_pointer(), cp_offset));
    } else {
      __ AddWord(a0, code_pointer(), cp_offset);
      __ Load32U(a0, MemOperand(a0, 0));
    }
  }
  Push(a0);
  CheckStackLimit();
}

void RegExpMacroAssemblerRISCV::PushCurrentPosition() {
  Push(current_input_offset());
}

void RegExpMacroAssemblerRISCV::PushRegister(int register_index,
                                             StackCheckFlag check_stack_limit) {
  __ LoadWord(a0, register_location(register_index));
  Push(a0);
  if (check_stack_limit) CheckStackLimit();
}

void RegExpMacroAssemblerRISCV::ReadCurrentPositionFromRegister(int reg) {
  __ LoadWord(current_input_offset(), register_location(reg));
}

void RegExpMacroAssemblerRISCV::WriteStackPointerToRegister(int reg) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ li(a0, ref);
  __ LoadWord(a0, MemOperand(a0));
  __ SubWord(a0, backtrack_stackpointer(), a0);
  __ Sw(a0, register_location(reg));
}

void RegExpMacroAssemblerRISCV::ReadStackPointerFromRegister(int reg) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ li(a1, ref);
  __ LoadWord(a1, MemOperand(a1));
  __ Lw(backtrack_stackpointer(), register_location(reg));
  __ AddWord(backtrack_stackpointer(), backtrack_stackpointer(), a1);
}

void RegExpMacroAssemblerRISCV::SetCurrentPositionFromEnd(int by) {
  Label after_position;
  __ BranchShort(&after_position, ge, current_input_offset(),
                 Operand(-by * char_size()));
  __ li(current_input_offset(), -by * char_size());
  // On RegExp code entry (where this operation is used), the character before
  // the current position is expected to be already loaded.
  // We have advanced the position, so it's safe to read backwards.
  LoadCurrentCharacterUnchecked(-1, 1);
  __ bind(&after_position);
}

void RegExpMacroAssemblerRISCV::SetRegister(int register_index, int to) {
  DCHECK(register_index >= num_saved_registers_);  // Reserved for positions!
  __ li(a0, Operand(to));
  __ StoreWord(a0, register_location(register_index));
}

bool RegExpMacroAssemblerRISCV::Succeed() {
  __ jmp(&success_label_);
  return global();
}

void RegExpMacroAssemblerRISCV::WriteCurrentPositionToRegister(int reg,
                                                               int cp_offset) {
  if (cp_offset == 0) {
    __ StoreWord(current_input_offset(), register_location(reg));
  } else {
    __ AddWord(a0, current_input_offset(), Operand(cp_offset * char_size()));
    __ StoreWord(a0, register_location(reg));
  }
}

void RegExpMacroAssemblerRISCV::ClearRegisters(int reg_from, int reg_to) {
  DCHECK(reg_from <= reg_to);
  __ LoadWord(a0, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
  for (int reg = reg_from; reg <= reg_to; reg++) {
    __ StoreWord(a0, register_location(reg));
  }
}
#ifdef RISCV_HAS_NO_UNALIGNED
bool RegExpMacroAssemblerRISCV::CanReadUnaligned() const { return false; }
#endif
// Private methods:

void RegExpMacroAssemblerRISCV::CallCheckStackGuardState(Register scratch,
                                                         Operand extra_space) {
  DCHECK(!isolate()->IsGeneratingEmbeddedBuiltins());
  DCHECK(!masm_->options().isolate_independent_code);

  int stack_alignment = base::OS::ActivationFrameAlignment();

  // Align the stack pointer and save the original sp value on the stack.
  __ mv(scratch, sp);
  __ SubWord(sp, sp, Operand(kSystemPointerSize));
  DCHECK(base::bits::IsPowerOfTwo(stack_alignment));
  __ And(sp, sp, Operand(-stack_alignment));
  __ StoreWord(scratch, MemOperand(sp));

  __ li(a3, extra_space);
  __ mv(a2, frame_pointer());
  // InstructionStream of self.
  __ li(a1, Operand(masm_->CodeObject()), CONSTANT_SIZE);

  // We need to make room for the return address on the stack.
  DCHECK(IsAligned(stack_alignment, kSystemPointerSize));
  __ SubWord(sp, sp, Operand(stack_alignment));

  // The stack pointer now points to cell where the return address will be
  // written. Arguments are in registers, meaning we treat the return address as
  // argument 5. Since DirectCEntry will handle allocating space for the C
  // argument slots, we don't need to care about that here. This is how the
  // stack will look (sp meaning the value of sp at this moment):
  // [sp + 3] - empty slot if needed for alignment.
  // [sp + 2] - saved sp.
  // [sp + 1] - second word reserved for return value.
  // [sp + 0] - first word reserved for return value.

  // a0 will point to the return address, placed by DirectCEntry.
  __ mv(a0, sp);

  ExternalReference stack_guard_check =
      ExternalReference::re_check_stack_guard_state();
  __ li(t6, Operand(stack_guard_check));

  EmbeddedData d = EmbeddedData::FromBlob();
  CHECK(Builtins::IsIsolateIndependent(Builtin::kDirectCEntry));
  Address entry = d.InstructionStartOf(Builtin::kDirectCEntry);
  __ li(kScratchReg, Operand(entry, RelocInfo::OFF_HEAP_TARGET));
  __ Call(kScratchReg);

  // DirectCEntry allocated space for the C argument slots so we have to
  // drop them with the return address from the stack with loading saved sp.
  // At this point stack must look:
  // [sp + 7] - empty slot if needed for alignment.
  // [sp + 6] - saved sp.
  // [sp + 5] - second word reserved for return value.
  // [sp + 4] - first word reserved for return value.
  // [sp + 3] - C argument slot.
  // [sp + 2] - C argument slot.
  // [sp + 1] - C argument slot.
  // [sp + 0] - C argument slot.
  __ LoadWord(sp, MemOperand(sp, stack_alignment + kCArgsSlotsSize));

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

int64_t RegExpMacroAssemblerRISCV::CheckStackGuardState(Address* return_address,
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

MemOperand RegExpMacroAssemblerRISCV::register_location(int register_index) {
  DCHECK(register_index < (1 << 30));
  if (num_registers_ <= register_index) {
    num_registers_ = register_index + 1;
  }
  return MemOperand(frame_pointer(),
                    kRegisterZeroOffset - register_index * kSystemPointerSize);
}

void RegExpMacroAssemblerRISCV::CheckPosition(int cp_offset,
                                              Label* on_outside_input) {
  if (cp_offset >= 0) {
    BranchOrBacktrack(on_outside_input, ge, current_input_offset(),
                      Operand(-cp_offset * char_size()));
  } else {
    __ LoadWord(a1, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
    __ AddWord(a0, current_input_offset(), Operand(cp_offset * char_size()));
    BranchOrBacktrack(on_outside_input, le, a0, Operand(a1));
  }
}

void RegExpMacroAssemblerRISCV::BranchOrBacktrack(Label* to,
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

void RegExpMacroAssemblerRISCV::SafeCall(Label* to, Condition cond, Register rs,
                                         const Operand& rt) {
  __ BranchAndLink(to, cond, rs, rt);
}

void RegExpMacroAssemblerRISCV::SafeReturn() {
  __ pop(ra);
  __ AddWord(t1, ra, Operand(masm_->CodeObject()));
  __ Jump(t1);
}

void RegExpMacroAssemblerRISCV::SafeCallTarget(Label* name) {
  __ bind(name);
  __ SubWord(ra, ra, Operand(masm_->CodeObject()));
  __ push(ra);
}

void RegExpMacroAssemblerRISCV::Push(Register source) {
  DCHECK(source != backtrack_stackpointer());
  __ AddWord(backtrack_stackpointer(), backtrack_stackpointer(),
             Operand(-kIntSize));
  __ Sw(source, MemOperand(backtrack_stackpointer()));
}

void RegExpMacroAssemblerRISCV::Pop(Register target) {
  DCHECK(target != backtrack_stackpointer());
  __ Lw(target, MemOperand(backtrack_stackpointer()));
  __ AddWord(backtrack_stackpointer(), backtrack_stackpointer(), kIntSize);
}

void RegExpMacroAssemblerRISCV::CheckPreemption() {
  // Check for preemption.
  ExternalReference stack_limit =
      ExternalReference::address_of_jslimit(masm_->isolate());
  __ li(a0, Operand(stack_limit));
  __ LoadWord(a0, MemOperand(a0));
  SafeCall(&check_preempt_label_, Uless_equal, sp, Operand(a0));
}

void RegExpMacroAssemblerRISCV::CheckStackLimit() {
  ExternalReference stack_limit =
      ExternalReference::address_of_regexp_stack_limit_address(
          masm_->isolate());

  __ li(a0, Operand(stack_limit));
  __ LoadWord(a0, MemOperand(a0));
  SafeCall(&stack_overflow_label_, Uless_equal, backtrack_stackpointer(),
           Operand(a0));
}

void RegExpMacroAssemblerRISCV::LoadCurrentCharacterUnchecked(int cp_offset,
                                                              int characters) {
  Register offset = current_input_offset();
  if (cp_offset != 0) {
    // kScratchReg2 is not being used to store the capture start index at this
    // point.
    __ AddWord(kScratchReg2, current_input_offset(),
               Operand(cp_offset * char_size()));
    offset = kScratchReg2;
  }
  // If unaligned load/stores are not supported then this function must only
  // be used to load a single character at a time.
  if (!CanReadUnaligned()) {
    DCHECK_EQ(1, characters);
  }

  if (mode_ == LATIN1) {
    if (characters == 4) {
      __ AddWord(kScratchReg, end_of_input_address(), offset);
      __ Load32U(current_character(), MemOperand(kScratchReg));
    } else if (characters == 2) {
      __ AddWord(kScratchReg, end_of_input_address(), offset);
      __ Lhu(current_character(), MemOperand(kScratchReg));
    } else {
      DCHECK_EQ(1, characters);
      __ AddWord(kScratchReg, end_of_input_address(), offset);
      __ Lbu(current_character(), MemOperand(kScratchReg));
    }
  } else {
    DCHECK_EQ(UC16, mode_);
    if (characters == 2) {
      __ AddWord(kScratchReg, end_of_input_address(), offset);
      __ Load32U(current_character(), MemOperand(kScratchReg));
    } else {
      DCHECK_EQ(1, characters);
      __ AddWord(kScratchReg, end_of_input_address(), offset);
      __ Lhu(current_character(), MemOperand(kScratchReg));
    }
  }
}

void RegExpMacroAssemblerRISCV::CallCFunctionFromIrregexpCode(
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
#undef __

}  // namespace internal
}  // namespace v8
```