Response:
The user wants to understand the functionality of the provided C++ code snippet from V8's `regexp-macro-assembler-ia32.cc`. They've also provided constraints on how the explanation should be structured, including:

1. **Listing Functionality:**  A high-level overview of what the code does.
2. **Torque Check:** Determining if the file is a Torque file (it's not).
3. **JavaScript Relation:**  If there's a connection to JavaScript, provide a JavaScript example.
4. **Logic Inference:**  Demonstrate code logic with input and output examples.
5. **Common Errors:** Highlight typical programming mistakes related to this code.
6. **Summary:**  A concise summary of the code's purpose.

Let's break down the code and address each point:

*   **Code Analysis:** The code contains assembly instructions (`__ mov`, `__ add`, `__ cmp`, `__ jmp`, etc.) targeting the IA-32 architecture. It's part of a class `RegExpMacroAssemblerIA32`, suggesting it's responsible for generating machine code for regular expression matching on IA-32. The code deals with registers (e.g., `eax`, `ebp`, `esp`, `edi`), memory operands, and labels. It handles both global and non-global regular expressions, captures, backtracking, stack management, and preemption checks.

*   **Torque Check:** The filename ends in `.cc`, not `.tq`, so it's not a Torque file.

*   **JavaScript Relation:** This code is the low-level implementation of regular expression matching in V8. When you use regular expressions in JavaScript, this kind of code (or its architecture-specific equivalent) is executed.

*   **Logic Inference:** Let's focus on the `Success()` function as a simple example. If `global()` is true, it jumps to `success_label_`; otherwise, it sets `eax` to `SUCCESS`.

*   **Common Errors:** Since this is low-level code generation, common errors are less about direct user code and more about potential bugs in the assembler itself, leading to incorrect instruction sequences. However, thinking from a *user's perspective* who might be interacting with the *effects* of this code, exceeding stack limits in complex regexes is a possibility.

*   **Summary:** The code snippet is responsible for generating IA-32 assembly instructions to implement the core logic of regular expression matching within the V8 JavaScript engine. It manages state, handles backtracking, captures, and integrates with the overall V8 execution environment.

Now, let's formulate the answers based on these observations.
这是 `v8/src/regexp/ia32/regexp-macro-assembler-ia32.cc` 文件的一部分，它属于 V8 JavaScript 引擎中负责 **IA-32 架构**的 **正则表达式宏汇编器**的实现。

**功能列举:**

这段代码的主要功能是处理正则表达式匹配成功后的收尾工作，并根据正则表达式是否是全局匹配进行不同的处理。具体来说，它执行以下操作：

1. **保存捕获组信息:** 将匹配到的捕获组的起始和结束位置信息存储到预先分配的输出缓冲区中。
2. **处理全局匹配:**
    *   如果正则表达式是全局的 (`global()` 返回 true)：
        *   增加成功捕获的计数器。
        *   检查是否有足够的空间存储更多的捕获结果。
        *   如果空间足够，则更新输出缓冲区的指针，并跳转回正则表达式匹配的起始位置 (`load_char_start_regexp`)，以便进行下一次匹配。
        *   对于零长度匹配的情况，会进行特殊处理，避免无限循环。
    *   如果正则表达式不是全局的：
        *   将返回值设置为成功 (`SUCCESS`)。
3. **处理非全局匹配的成功:** 如果是非全局匹配，则将寄存器 `eax` 设置为表示成功的状态。
4. **退出和返回:**
    *   恢复之前保存的寄存器 (`ebx`, `edi`, `esi`)。
    *   恢复栈指针 (`esp`)。
    *   返回结果，通常存储在 `eax` 中。
5. **处理回溯:** 如果需要回溯（即匹配失败，需要尝试其他可能的匹配路径），则跳转到 `backtrack_label_` 标签处执行回溯逻辑。
6. **处理抢占 (Preemption):**  检查是否需要暂停当前执行，例如因为 JavaScript 堆栈溢出等原因。如果是，则保存当前状态并调用 C++ 函数进行处理。
7. **处理堆栈溢出:** 如果回溯栈溢出，则调用 C++ 函数 `GrowStack` 来尝试扩展栈空间。
8. **处理异常:** 如果在执行过程中发生异常，则设置返回值为异常状态 (`EXCEPTION`)。
9. **处理回退 (Fallback):** 如果需要回退到其他实现方式（例如实验性的实现），则设置相应的返回值 (`FALLBACK_TO_EXPERIMENTAL`)。
10. **生成代码:**  在函数结尾，将生成的机器码信息封装到 `CodeDesc` 并最终创建 `Code` 对象。

**Torque 检查:**

`v8/src/regexp/ia32/regexp-macro-assembler-ia32.cc` 的文件扩展名是 `.cc`，而不是 `.tq`。因此，**它不是一个 V8 Torque 源代码文件**。Torque 文件通常用于定义类型和生成一些样板代码。这个 `.cc` 文件包含的是手写的汇编代码生成逻辑。

**与 JavaScript 的关系 (举例):**

这段代码是 JavaScript 正则表达式功能的底层实现。当你使用 JavaScript 中的 `String.prototype.match()` 或 `RegExp.prototype.exec()` 等方法进行正则匹配时，V8 引擎最终会执行类似于这里生成的机器码。

**JavaScript 示例:**

```javascript
const str = "abracadabra";
const regexGlobal = /a/g;
const regexNonGlobal = /a/;

let matchGlobal;
let globalMatches = [];
while ((matchGlobal = regexGlobal.exec(str)) !== null) {
  globalMatches.push({
    index: matchGlobal.index,
    match: matchGlobal[0]
  });
}
console.log("Global matches:", globalMatches);
// 输出: Global matches: [ { index: 0, match: 'a' }, { index: 3, match: 'a' }, { index: 5, match: 'a' }, { index: 7, match: 'a' }, { index: 10, match: 'a' } ]

const matchNonGlobal = regexNonGlobal.exec(str);
console.log("Non-global match:", matchNonGlobal);
// 输出: Non-global match: [ 'a', index: 0, input: 'abracadabra', groups: undefined ]
```

在这个例子中：

*   当使用全局正则表达式 `/a/g` 时，会多次执行类似这段代码的逻辑，每次匹配成功后会更新状态，并尝试继续匹配，直到字符串末尾。 这对应了代码中 `if (global())` 分支的处理。
*   当使用非全局正则表达式 `/a/` 时，只会执行一次匹配，匹配成功后便返回结果，这对应了代码中 `else` 分支的处理。

**代码逻辑推理 (假设输入与输出):**

**假设输入:**

*   `mode_` 为 `LATIN1` (单字节字符)。
*   `global()` 返回 `true` (全局匹配)。
*   正则表达式匹配成功，捕获了两个组，分别从字符串的索引 1 和 3 开始，长度均为 1。
*   `num_saved_registers_` 为 2 (用于存储两个捕获组的起始和结束位置)。
*   当前的输出缓冲区有足够的空间存储新的捕获结果。
*   `edi` 指向当前匹配结束的位置相对于字符串末尾的偏移量。
*   `ecx` 存储剩余的全局输出寄存器数量。

**预期输出 (部分):**

*   捕获组的信息将被存储到输出缓冲区中。例如，如果输出缓冲区起始地址在 `ebx` 中，那么 `Operand(ebx, 0 * kSystemPointerSize)` 将存储第一个捕获组的起始位置（字符串索引 1），`Operand(ebx, 1 * kSystemPointerSize)` 将存储其结束位置（字符串索引 2），以此类推。
*   `Operand(ebp, kSuccessfulCapturesOffset)` 的值会增加 1。
*   `ecx` 的值会减去 `num_saved_registers_` (2)。
*   `Operand(ebp, kRegisterOutputOffset)` 的值会增加 `num_saved_registers_ * kSystemPointerSize`。
*   如果不是零长度匹配，程序会跳转回 `load_char_start_regexp` 标签，准备进行下一次匹配。

**涉及用户常见的编程错误 (举例):**

虽然用户不会直接编写这里的汇编代码，但与这段代码功能相关的用户常见编程错误包括：

1. **在全局匹配中期望只返回第一个匹配结果:** 用户可能错误地认为全局匹配的行为与非全局匹配相同，只返回第一个匹配项。正确的做法是使用循环（如上面的 JavaScript 示例）来获取所有匹配项。
2. **忘记处理全局匹配的 `null` 返回值:** 在全局匹配中，如果没有更多匹配项，`RegExp.prototype.exec()` 会返回 `null`。用户需要检查这个返回值，以避免无限循环。
3. **编写可能导致无限循环的正则表达式:** 特别是在全局匹配中，如果正则表达式可以匹配零长度的字符串，并且没有正确地推进匹配位置，可能会导致无限循环。代码中的 `global_with_zero_length_check()` 部分正是为了处理这类情况。例如，正则表达式 `/a*/g` 在匹配空字符串时就可能出现问题。

**这是第2部分，共2部分，请归纳一下它的功能:**

这段代码是 V8 JavaScript 引擎中用于 IA-32 架构的正则表达式宏汇编器的一部分，**负责处理正则表达式成功匹配后的收尾工作，特别是对于全局匹配，它会更新状态并准备进行下一次匹配。对于非全局匹配，它会设置成功返回值。此外，它还处理回溯、抢占、堆栈溢出和异常等情况，并最终生成可执行的机器码。** 它的核心作用是确保正则表达式匹配过程的正确性和高效性，并与 JavaScript 的执行环境进行必要的交互。

### 提示词
```
这是目录为v8/src/regexp/ia32/regexp-macro-assembler-ia32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/ia32/regexp-macro-assembler-ia32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
d(ebp, kInputStartOffset));
      if (mode_ == UC16) {
        __ lea(ecx, Operand(ecx, edx, times_2, 0));
      } else {
        __ add(ecx, edx);
      }
      for (int i = 0; i < num_saved_registers_; i++) {
        __ mov(eax, register_location(i));
        if (i == 0 && global_with_zero_length_check()) {
          // Keep capture start in edx for the zero-length check later.
          __ mov(edx, eax);
        }
        // Convert to index from start of string, not end.
        __ add(eax, ecx);
        if (mode_ == UC16) {
          __ sar(eax, 1);  // Convert byte index to character index.
        }
        __ mov(Operand(ebx, i * kSystemPointerSize), eax);
      }
    }

    if (global()) {
      // Restart matching if the regular expression is flagged as global.
      // Increment success counter.
      __ inc(Operand(ebp, kSuccessfulCapturesOffset));
      // Capture results have been stored, so the number of remaining global
      // output registers is reduced by the number of stored captures.
      __ mov(ecx, Operand(ebp, kNumOutputRegistersOffset));
      __ sub(ecx, Immediate(num_saved_registers_));
      // Check whether we have enough room for another set of capture results.
      __ cmp(ecx, Immediate(num_saved_registers_));
      __ j(less, &exit_label_);

      __ mov(Operand(ebp, kNumOutputRegistersOffset), ecx);
      // Advance the location for output.
      __ add(Operand(ebp, kRegisterOutputOffset),
             Immediate(num_saved_registers_ * kSystemPointerSize));

      // Restore the original regexp stack pointer value (effectively, pop the
      // stored base pointer).
      PopRegExpBasePointer(backtrack_stackpointer(), ebx);

      Label reload_string_start_minus_one;

      if (global_with_zero_length_check()) {
        // Special case for zero-length matches.
        // edx: capture start index
        __ cmp(edi, edx);
        // Not a zero-length match, restart.
        __ j(not_equal, &reload_string_start_minus_one);
        // edi (offset from the end) is zero if we already reached the end.
        __ test(edi, edi);
        __ j(zero, &exit_label_, Label::kNear);
        // Advance current position after a zero-length match.
        Label advance;
        __ bind(&advance);
        if (mode_ == UC16) {
          __ add(edi, Immediate(2));
        } else {
          __ inc(edi);
        }
        if (global_unicode()) CheckNotInSurrogatePair(0, &advance);
      }

      __ bind(&reload_string_start_minus_one);
      // Prepare eax to initialize registers with its value in the next run.
      // Must be immediately before the jump to avoid clobbering.
      __ mov(eax, Operand(ebp, kStringStartMinusOneOffset));

      __ jmp(&load_char_start_regexp);
    } else {
      __ mov(eax, Immediate(SUCCESS));
    }
  }

  __ bind(&exit_label_);
  if (global()) {
    // Return the number of successful captures.
    __ mov(eax, Operand(ebp, kSuccessfulCapturesOffset));
  }

  __ bind(&return_eax);
  // Restore the original regexp stack pointer value (effectively, pop the
  // stored base pointer).
  PopRegExpBasePointer(backtrack_stackpointer(), ebx);

  // Skip esp past regexp registers.
  __ lea(esp, Operand(ebp, kLastCalleeSaveRegisterOffset));
  // Restore callee-save registers.
  static_assert(kNumCalleeSaveRegisters == 3);
  static_assert(kBackupEsiOffset == -2 * kSystemPointerSize);
  static_assert(kBackupEdiOffset == -3 * kSystemPointerSize);
  static_assert(kBackupEbxOffset == -4 * kSystemPointerSize);
  __ pop(ebx);
  __ pop(edi);
  __ pop(esi);

  __ LeaveFrame(StackFrame::IRREGEXP);
  __ ret(0);

  // Backtrack code (branch target for conditional backtracks).
  if (backtrack_label_.is_linked()) {
    __ bind(&backtrack_label_);
    Backtrack();
  }

  Label exit_with_exception;

  // Preempt-code
  if (check_preempt_label_.is_linked()) {
    SafeCallTarget(&check_preempt_label_);

    StoreRegExpStackPointerToMemory(backtrack_stackpointer(), edi);

    __ push(edi);

    CallCheckStackGuardState(ebx);
    __ or_(eax, eax);
    // If returning non-zero, we should end execution with the given
    // result as return value.
    __ j(not_zero, &return_eax);

    __ pop(edi);

    LoadRegExpStackPointerFromMemory(backtrack_stackpointer());

    // String might have moved: Reload esi from frame.
    __ mov(esi, Operand(ebp, kInputEndOffset));
    SafeReturn();
  }

  // Backtrack stack overflow code.
  if (stack_overflow_label_.is_linked()) {
    SafeCallTarget(&stack_overflow_label_);
    // Reached if the backtrack-stack limit has been hit.

    // Save registers before calling C function.
    __ push(esi);
    __ push(edi);

    StoreRegExpStackPointerToMemory(backtrack_stackpointer(), edi);

    // Call GrowStack(isolate).
    static const int kNumArguments = 1;
    __ PrepareCallCFunction(kNumArguments, ebx);
    __ mov(Operand(esp, 0 * kSystemPointerSize),
           Immediate(ExternalReference::isolate_address(isolate())));
    CallCFunctionFromIrregexpCode(ExternalReference::re_grow_stack(),
                                  kNumArguments);
    // If return nullptr, we have failed to grow the stack, and
    // must exit with a stack-overflow exception.
    __ or_(eax, eax);
    __ j(equal, &exit_with_exception);
    // Otherwise use return value as new stack pointer.
    __ mov(backtrack_stackpointer(), eax);
    // Restore saved registers and continue.
    __ pop(edi);
    __ pop(esi);
    SafeReturn();
  }

  if (exit_with_exception.is_linked()) {
    // If any of the code above needed to exit with an exception.
    __ bind(&exit_with_exception);
    // Exit with Result EXCEPTION(-1) to signal thrown exception.
    __ mov(eax, EXCEPTION);
    __ jmp(&return_eax);
  }

  if (fallback_label_.is_linked()) {
    __ bind(&fallback_label_);
    __ mov(eax, FALLBACK_TO_EXPERIMENTAL);
    __ jmp(&return_eax);
  }

  CodeDesc code_desc;
  masm_->GetCode(masm_->isolate(), &code_desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate(), code_desc, CodeKind::REGEXP)
          .set_self_reference(masm_->CodeObject())
          .set_empty_source_position_table()
          .Build();
  PROFILE(masm_->isolate(),
          RegExpCodeCreateEvent(Cast<AbstractCode>(code), source, flags));
  return Cast<HeapObject>(code);
}

void RegExpMacroAssemblerIA32::GoTo(Label* to) { BranchOrBacktrack(to); }

void RegExpMacroAssemblerIA32::IfRegisterGE(int reg,
                                            int comparand,
                                            Label* if_ge) {
  __ cmp(register_location(reg), Immediate(comparand));
  BranchOrBacktrack(greater_equal, if_ge);
}


void RegExpMacroAssemblerIA32::IfRegisterLT(int reg,
                                            int comparand,
                                            Label* if_lt) {
  __ cmp(register_location(reg), Immediate(comparand));
  BranchOrBacktrack(less, if_lt);
}


void RegExpMacroAssemblerIA32::IfRegisterEqPos(int reg,
                                               Label* if_eq) {
  __ cmp(edi, register_location(reg));
  BranchOrBacktrack(equal, if_eq);
}


RegExpMacroAssembler::IrregexpImplementation
    RegExpMacroAssemblerIA32::Implementation() {
  return kIA32Implementation;
}


void RegExpMacroAssemblerIA32::PopCurrentPosition() {
  Pop(edi);
}


void RegExpMacroAssemblerIA32::PopRegister(int register_index) {
  Pop(eax);
  __ mov(register_location(register_index), eax);
}


void RegExpMacroAssemblerIA32::PushBacktrack(Label* label) {
  Push(Immediate::CodeRelativeOffset(label));
  CheckStackLimit();
}


void RegExpMacroAssemblerIA32::PushCurrentPosition() {
  Push(edi);
}


void RegExpMacroAssemblerIA32::PushRegister(int register_index,
                                            StackCheckFlag check_stack_limit) {
  __ mov(eax, register_location(register_index));
  Push(eax);
  if (check_stack_limit) CheckStackLimit();
}


void RegExpMacroAssemblerIA32::ReadCurrentPositionFromRegister(int reg) {
  __ mov(edi, register_location(reg));
}

void RegExpMacroAssemblerIA32::WriteStackPointerToRegister(int reg) {
  ExternalReference stack_top_address =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ mov(eax, __ ExternalReferenceAsOperand(stack_top_address, eax));
  __ sub(eax, backtrack_stackpointer());
  __ mov(register_location(reg), eax);
}

void RegExpMacroAssemblerIA32::ReadStackPointerFromRegister(int reg) {
  ExternalReference stack_top_address =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ mov(backtrack_stackpointer(),
         __ ExternalReferenceAsOperand(stack_top_address,
                                       backtrack_stackpointer()));
  __ sub(backtrack_stackpointer(), register_location(reg));
}

void RegExpMacroAssemblerIA32::SetCurrentPositionFromEnd(int by)  {
  Label after_position;
  __ cmp(edi, -by * char_size());
  __ j(greater_equal, &after_position, Label::kNear);
  __ mov(edi, -by * char_size());
  // On RegExp code entry (where this operation is used), the character before
  // the current position is expected to be already loaded.
  // We have advanced the position, so it's safe to read backwards.
  LoadCurrentCharacterUnchecked(-1, 1);
  __ bind(&after_position);
}


void RegExpMacroAssemblerIA32::SetRegister(int register_index, int to) {
  DCHECK(register_index >= num_saved_registers_);  // Reserved for positions!
  __ mov(register_location(register_index), Immediate(to));
}


bool RegExpMacroAssemblerIA32::Succeed() {
  __ jmp(&success_label_);
  return global();
}


void RegExpMacroAssemblerIA32::WriteCurrentPositionToRegister(int reg,
                                                              int cp_offset) {
  if (cp_offset == 0) {
    __ mov(register_location(reg), edi);
  } else {
    __ lea(eax, Operand(edi, cp_offset * char_size()));
    __ mov(register_location(reg), eax);
  }
}


void RegExpMacroAssemblerIA32::ClearRegisters(int reg_from, int reg_to) {
  DCHECK(reg_from <= reg_to);
  __ mov(eax, Operand(ebp, kStringStartMinusOneOffset));
  for (int reg = reg_from; reg <= reg_to; reg++) {
    __ mov(register_location(reg), eax);
  }
}

// Private methods:

void RegExpMacroAssemblerIA32::CallCheckStackGuardState(Register scratch,
                                                        Immediate extra_space) {
  static const int num_arguments = 4;
  __ PrepareCallCFunction(num_arguments, scratch);
  // Extra space for variables.
  __ mov(Operand(esp, 3 * kSystemPointerSize), extra_space);
  // RegExp code frame pointer.
  __ mov(Operand(esp, 2 * kSystemPointerSize), ebp);
  // InstructionStream of self.
  __ mov(Operand(esp, 1 * kSystemPointerSize), Immediate(masm_->CodeObject()));
  // Next address on the stack (will be address of return address).
  __ lea(eax, Operand(esp, -kSystemPointerSize));
  __ mov(Operand(esp, 0 * kSystemPointerSize), eax);
  ExternalReference check_stack_guard =
      ExternalReference::re_check_stack_guard_state();
  CallCFunctionFromIrregexpCode(check_stack_guard, num_arguments);
}

Operand RegExpMacroAssemblerIA32::StaticVariable(const ExternalReference& ext) {
  return Operand(ext.address(), RelocInfo::EXTERNAL_REFERENCE);
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

int RegExpMacroAssemblerIA32::CheckStackGuardState(Address* return_address,
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

Operand RegExpMacroAssemblerIA32::register_location(int register_index) {
  DCHECK(register_index < (1<<30));
  if (num_registers_ <= register_index) {
    num_registers_ = register_index + 1;
  }
  return Operand(ebp,
                 kRegisterZeroOffset - register_index * kSystemPointerSize);
}


void RegExpMacroAssemblerIA32::CheckPosition(int cp_offset,
                                             Label* on_outside_input) {
  if (cp_offset >= 0) {
    __ cmp(edi, -cp_offset * char_size());
    BranchOrBacktrack(greater_equal, on_outside_input);
  } else {
    __ lea(eax, Operand(edi, cp_offset * char_size()));
    __ cmp(eax, Operand(ebp, kStringStartMinusOneOffset));
    BranchOrBacktrack(less_equal, on_outside_input);
  }
}

void RegExpMacroAssemblerIA32::BranchOrBacktrack(Label* to) {
  if (to == nullptr) {
    Backtrack();
    return;
  }
  __ jmp(to);
}

void RegExpMacroAssemblerIA32::BranchOrBacktrack(Condition condition,
                                                 Label* to) {
  __ j(condition, to ? to : &backtrack_label_);
}

void RegExpMacroAssemblerIA32::SafeCall(Label* to) {
  Label return_to;
  __ push(Immediate::CodeRelativeOffset(&return_to));
  __ jmp(to);
  __ bind(&return_to);
}


void RegExpMacroAssemblerIA32::SafeReturn() {
  __ pop(ebx);
  __ add(ebx, Immediate(masm_->CodeObject()));
  __ jmp(ebx);
}


void RegExpMacroAssemblerIA32::SafeCallTarget(Label* name) {
  __ bind(name);
}


void RegExpMacroAssemblerIA32::Push(Register source) {
  DCHECK(source != backtrack_stackpointer());
  // Notice: This updates flags, unlike normal Push.
  __ sub(backtrack_stackpointer(), Immediate(kSystemPointerSize));
  __ mov(Operand(backtrack_stackpointer(), 0), source);
}


void RegExpMacroAssemblerIA32::Push(Immediate value) {
  // Notice: This updates flags, unlike normal Push.
  __ sub(backtrack_stackpointer(), Immediate(kSystemPointerSize));
  __ mov(Operand(backtrack_stackpointer(), 0), value);
}


void RegExpMacroAssemblerIA32::Pop(Register target) {
  DCHECK(target != backtrack_stackpointer());
  __ mov(target, Operand(backtrack_stackpointer(), 0));
  // Notice: This updates flags, unlike normal Pop.
  __ add(backtrack_stackpointer(), Immediate(kSystemPointerSize));
}


void RegExpMacroAssemblerIA32::CheckPreemption() {
  // Check for preemption.
  Label no_preempt;
  ExternalReference stack_limit =
      ExternalReference::address_of_jslimit(isolate());
  __ cmp(esp, StaticVariable(stack_limit));
  __ j(above, &no_preempt);

  SafeCall(&check_preempt_label_);

  __ bind(&no_preempt);
}


void RegExpMacroAssemblerIA32::CheckStackLimit() {
  Label no_stack_overflow;
  ExternalReference stack_limit =
      ExternalReference::address_of_regexp_stack_limit_address(isolate());
  __ cmp(backtrack_stackpointer(), StaticVariable(stack_limit));
  __ j(above, &no_stack_overflow);

  SafeCall(&stack_overflow_label_);

  __ bind(&no_stack_overflow);
}


void RegExpMacroAssemblerIA32::LoadCurrentCharacterUnchecked(int cp_offset,
                                                             int characters) {
  if (mode_ == LATIN1) {
    if (characters == 4) {
      __ mov(current_character(), Operand(esi, edi, times_1, cp_offset));
    } else if (characters == 2) {
      __ movzx_w(current_character(), Operand(esi, edi, times_1, cp_offset));
    } else {
      DCHECK_EQ(1, characters);
      __ movzx_b(current_character(), Operand(esi, edi, times_1, cp_offset));
    }
  } else {
    DCHECK(mode_ == UC16);
    if (characters == 2) {
      __ mov(current_character(),
             Operand(esi, edi, times_1, cp_offset * sizeof(base::uc16)));
    } else {
      DCHECK_EQ(1, characters);
      __ movzx_w(current_character(),
                 Operand(esi, edi, times_1, cp_offset * sizeof(base::uc16)));
    }
  }
}


#undef __

}  // namespace internal
}  // namespace v8

#endif  // V8_TARGET_ARCH_IA32
```