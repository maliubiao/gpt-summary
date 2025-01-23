Response:
The user wants a summary of the provided C++ code snippet from `v8/src/regexp/arm/regexp-macro-assembler-arm.cc`.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the file's purpose:** The filename strongly suggests this file is part of V8's regular expression engine and specifically targets the ARM architecture. The `RegExpMacroAssemblerARM` class name reinforces this. The `.cc` extension confirms it's C++ source code.

2. **Recognize the code's core functionality:** The code contains methods like `GoTo`, `IfRegisterGE`, `PushBacktrack`, `LoadCurrentCharacterUnchecked`, etc. These indicate the file implements a low-level assembler for regular expression matching on ARM. It's about generating machine code instructions.

3. **Identify key data structures and concepts:**  The code mentions `registers`, `stack`, `backtrack`, `input offset`, `capture groups`, `global flag`, `unicode`, and `Latin1`. These are fundamental concepts in regular expression processing and the implementation reflects how these are handled at a low level.

4. **Infer the compilation context:** The code uses V8-specific constructs like `Operand`, `MemOperand`, `Label`, `ExternalReference`, and interacts with the V8 isolate. This indicates it's part of V8's internal workings and involved in compiling regular expressions into executable code.

5. **Address specific questions from the prompt:**
    * **File extension:** The prompt asks about `.tq`. The code is `.cc`, so it's C++, not Torque.
    * **Relationship to JavaScript:** Regular expressions are a core JavaScript feature. This code is directly responsible for implementing the matching logic for JavaScript regular expressions on ARM.
    * **Code logic and examples:**  The code contains branching, stack manipulation, and register operations. To illustrate, we can pick a simple method like `IfRegisterGE` and explain its purpose and how it relates to conditional matching. We can provide a basic JavaScript regex that would involve such a comparison.
    * **Common programming errors:** Since this is low-level code, common user errors aren't directly within *this* code. However, user errors in *regular expressions themselves* (like incorrect syntax or unintended behavior) are relevant as this code executes the compiled form of those regexes.
    * **Global flag handling:**  The code explicitly deals with the `global()` flag, demonstrating how multiple matches are handled.

6. **Structure the summary:**  Organize the findings into logical sections:
    * Overall function of the file.
    * Confirmation of C++ and not Torque.
    * Connection to JavaScript.
    * Example of code logic with input/output (even a conceptual one at this level is sufficient).
    * Examples of user-level programming errors (related to regexes).
    * Summary of the functionality seen in the provided snippet (focusing on the success path and global matching).

7. **Refine and add details:** Ensure the language is clear, concise, and accurate. Add details about register usage, stack operations, and the handling of different regex flags (like global and Unicode). Emphasize the low-level nature of the code and its role in performance.

By following these steps, we can generate a comprehensive and informative summary that addresses the user's request effectively.
这是 `v8/src/regexp/arm/regexp-macro-assembler-arm.cc` 文件的第二部分，该文件是 V8 引擎中用于在 ARM 架构上执行正则表达式匹配的核心组件。它使用汇编语言宏来生成优化的机器代码，用于执行各种正则表达式操作。

**功能归纳 (基于提供的代码片段):**

这部分代码主要处理正则表达式匹配成功后的逻辑，以及一些错误处理和控制流相关的操作。具体功能可以归纳为：

1. **处理匹配成功:**
   - 将捕获组的信息（起始和结束位置）存储到预先分配的输出缓冲区中。
   - 区分 Unicode (UC16) 和 Latin1 编码，并相应地调整指针步长。
   - 如果正则表达式具有全局标志 (`global()`)，则进行后续处理以查找更多匹配项：
     - 增加成功匹配计数器。
     - 检查输出缓冲区是否还有空间存储新的捕获组信息。
     - 如果有空间，则更新输出缓冲区的指针，并跳转回正则表达式匹配的起始位置 (`load_char_start_regexp`) 以寻找下一个匹配。
     - 对于零长度匹配的全局正则表达式，会进行特殊处理，避免无限循环。如果当前位置与上次匹配的起始位置相同，则会将当前位置向前移动一个或两个字符（取决于编码）。
   - 如果正则表达式没有全局标志，则设置返回值 `r0` 为 `SUCCESS`。

2. **处理匹配结束:**
   - 设置 `exit_label_`，作为成功或非全局匹配结束时的跳转目标。
   - 如果是全局匹配，则将成功匹配的次数加载到 `r0` 作为返回值。
   - 恢复正则表达式栈指针 (`backtrack_stackpointer()`)。
   - 恢复寄存器 `r4` 到 `r11`，并返回 (通过加载 `lr` 到 `pc`)。

3. **回溯 (Backtrack):**
   - 定义了 `backtrack_label_`，作为回溯操作的目标。当匹配失败或需要尝试其他匹配路径时，会跳转到这里执行 `Backtrack()` 函数。

4. **抢占检查 (Preempt-code):**
   - 定义了 `check_preempt_label_`，用于检查 JavaScript 执行是否被中断（例如，因为执行时间过长）。
   - 如果需要进行抢占检查：
     - 将正则表达式栈指针保存到内存中。
     - 调用 `CallCheckStackGuardState()` 函数来检查堆栈状态。
     - 如果堆栈溢出或需要进行其他处理，则根据返回值进行相应的跳转。
     - 重新加载正则表达式栈指针。
     - 重新加载输入字符串的结束地址，因为字符串可能在抢占期间被移动。

5. **回溯栈溢出处理 (Backtrack stack overflow code):**
   - 定义了 `stack_overflow_label_`，当回溯栈溢出时跳转到这里。
   - 调用 `GrowStack()` 函数尝试扩展回溯栈。
   - 如果扩展失败，则跳转到 `exit_with_exception`。
   - 如果扩展成功，则使用新的栈指针并恢复执行。

6. **异常退出 (Exit with exception):**
   - 定义了 `exit_with_exception`，用于处理正则表达式执行过程中遇到的错误，例如栈溢出。
   - 设置返回值 `r0` 为 `EXCEPTION (-1)`。

7. **回退到解释器 (Fallback):**
   - 定义了 `fallback_label_`，用于在某些情况下回退到更通用的正则表达式解释器。
   - 设置返回值 `r0` 为 `FALLBACK_TO_EXPERIMENTAL`。

8. **代码生成:**
   - 使用 `masm_->GetCode()` 获取生成的机器码。
   - 创建 `Code` 对象并进行性能分析。

**关于文件类型和 JavaScript 关系：**

- 你提供的代码片段是 `.cc` 文件，这意味着它是 **C++ 源代码**，而不是 Torque 源代码（`.tq`）。
- 这个文件与 JavaScript 的功能有直接关系。V8 引擎负责执行 JavaScript 代码，而正则表达式是 JavaScript 语言的核心特性之一。`regexp-macro-assembler-arm.cc` 文件中的代码负责将 JavaScript 正则表达式编译成高效的 ARM 机器码，并在执行时进行匹配操作。

**JavaScript 示例 (与捕获组和全局匹配相关):**

```javascript
const regex = /(\w+)\s(\w+)/g;
const text = "John Doe, Jane Smith";
let match;
let captures = [];

while ((match = regex.exec(text)) !== null) {
  captures.push({
    fullMatch: match[0],
    group1: match[1],
    group2: match[2],
    index: match.index,
  });
}

console.log(captures);
// 输出:
// [
//   { fullMatch: 'John Doe', group1: 'John', group2: 'Doe', index: 0 },
//   { fullMatch: 'Jane Smith', group1: 'Jane', group2: 'Smith', index: 10 }
// ]
```

在这个例子中：

- `(\w+)\s(\w+)` 定义了两个捕获组。`regexp-macro-assembler-arm.cc` 中的代码会负责记录这两个捕获组在匹配成功时的起始和结束位置。
- `g` 标志表示全局匹配。代码中的 `if (global())` 分支就是处理这种情况，它会循环查找所有匹配项。

**代码逻辑推理 (假设输入与输出):**

假设我们有以下输入：

- **正则表达式:** `/ab*/` (匹配 "a" 后面跟着零个或多个 "b")，全局匹配 (`g` 标志)。
- **输入字符串:** `"abbc"`
- **初始状态:**  匹配从字符串的开头开始。

**执行流程 (简化):**

1. **第一次匹配:**
   - 代码尝试匹配 "ab*" 从字符串的开头。
   - 成功匹配 `"abb"`。
   - `current_input_offset()` 指向 'c'。
   - 代码会将 `"abb"` 的起始和结束位置（0 和 2）存储到输出缓冲区。
   - 由于是全局匹配，会检查输出缓冲区是否还有空间。
   - 如果有空间，则更新输出缓冲区指针，并将当前匹配位置更新到 'c' 的位置。
   - 跳转回 `load_char_start_regexp`，准备下一次匹配。

2. **第二次匹配:**
   - 代码尝试从 'c' 的位置开始匹配。
   - 无法匹配 "ab*"。
   - 代码会进行回溯（跳转到 `backtrack_label_`，尽管在这个简单例子中可能不会执行复杂的 Backtrack 操作）。

3. **最终结果:**
   - 由于没有更多的匹配项，代码会执行到 `exit_label_`。
   - `r0` 将包含成功匹配的次数 (1)。
   - 输出缓冲区将包含第一次匹配的捕获组信息。

**用户常见的编程错误 (与正则表达式相关):**

虽然 `regexp-macro-assembler-arm.cc` 是底层实现，但它执行的是由用户编写的正则表达式编译后的代码。用户常见的错误包括：

- **错误的正则表达式语法:** 例如，忘记转义特殊字符，括号不匹配等。这会在正则表达式编译阶段被 V8 捕获，而不是在这个汇编器中。
- **意外的贪婪或非贪婪匹配:**  例如，`/.*/` 会贪婪地匹配尽可能多的字符，可能导致性能问题或匹配到错误的结果。
  ```javascript
  const text = "<a><b></a>";
  const greedy = /<.*>/;
  const nonGreedy = /<.*?>/;

  console.log(text.match(greedy)[0]);   // 输出: "<a><b></a>"
  console.log(text.match(nonGreedy)[0]); // 输出: "<a>"
  ```
- **忘记全局匹配标志 (`g`):**  导致 `regex.exec()` 只返回第一个匹配项。
  ```javascript
  const text = "apple banana apple";
  const regexWithoutGlobal = /apple/;
  const regexWithGlobal = /apple/g;

  console.log(text.match(regexWithoutGlobal)); // 输出: ['apple', index: 0, input: 'apple banana apple', groups: undefined]
  console.log(text.match(regexWithGlobal));    // 输出: ['apple', 'apple']
  ```
- **在循环中使用字面量正则表达式:**  如果正则表达式中没有变量，在循环中重复创建相同的正则表达式对象是没有效率的。应该在循环外部创建。
- **回溯陷阱:**  某些复杂的正则表达式可能会导致大量的回溯操作，导致性能急剧下降（被称为 "灾难性回溯"）。例如，`/a+b+c+d+e+f+g+h+i/`.test("aaaaaaaaaaaaaaaaaaaa");

总而言之，`v8/src/regexp/arm/regexp-macro-assembler-arm.cc` 的这部分代码负责处理正则表达式匹配成功后的关键步骤，包括存储捕获信息、处理全局匹配、错误处理和控制流管理，是 V8 引擎正则表达式功能在 ARM 架构上的核心实现。

### 提示词
```
这是目录为v8/src/regexp/arm/regexp-macro-assembler-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/arm/regexp-macro-assembler-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
if (mode_ == UC16) {
          __ add(r2, r1, Operand(r2, ASR, 1));
          __ add(r3, r1, Operand(r3, ASR, 1));
        } else {
          __ add(r2, r1, Operand(r2));
          __ add(r3, r1, Operand(r3));
        }
        __ str(r2, MemOperand(r0, kSystemPointerSize, PostIndex));
        __ str(r3, MemOperand(r0, kSystemPointerSize, PostIndex));
      }
    }

    if (global()) {
      // Restart matching if the regular expression is flagged as global.
      __ ldr(r0, MemOperand(frame_pointer(), kSuccessfulCapturesOffset));
      __ ldr(r1, MemOperand(frame_pointer(), kNumOutputRegistersOffset));
      __ ldr(r2, MemOperand(frame_pointer(), kRegisterOutputOffset));
      // Increment success counter.
      __ add(r0, r0, Operand(1));
      __ str(r0, MemOperand(frame_pointer(), kSuccessfulCapturesOffset));
      // Capture results have been stored, so the number of remaining global
      // output registers is reduced by the number of stored captures.
      __ sub(r1, r1, Operand(num_saved_registers_));
      // Check whether we have enough room for another set of capture results.
      __ cmp(r1, Operand(num_saved_registers_));
      __ b(lt, &return_r0);

      __ str(r1, MemOperand(frame_pointer(), kNumOutputRegistersOffset));
      // Advance the location for output.
      __ add(r2, r2, Operand(num_saved_registers_ * kSystemPointerSize));
      __ str(r2, MemOperand(frame_pointer(), kRegisterOutputOffset));

      // Restore the original regexp stack pointer value (effectively, pop the
      // stored base pointer).
      PopRegExpBasePointer(backtrack_stackpointer(), r2);

      Label reload_string_start_minus_one;

      if (global_with_zero_length_check()) {
        // Special case for zero-length matches.
        // r4: capture start index
        __ cmp(current_input_offset(), r4);
        // Not a zero-length match, restart.
        __ b(ne, &reload_string_start_minus_one);
        // Offset from the end is zero if we already reached the end.
        __ cmp(current_input_offset(), Operand::Zero());
        __ b(eq, &exit_label_);
        // Advance current position after a zero-length match.
        Label advance;
        __ bind(&advance);
        __ add(current_input_offset(), current_input_offset(),
               Operand((mode_ == UC16) ? 2 : 1));
        if (global_unicode()) CheckNotInSurrogatePair(0, &advance);
      }

      __ bind(&reload_string_start_minus_one);
      // Prepare r0 to initialize registers with its value in the next run.
      // Must be immediately before the jump to avoid clobbering.
      __ ldr(r0, MemOperand(frame_pointer(), kStringStartMinusOneOffset));

      __ b(&load_char_start_regexp);
    } else {
      __ mov(r0, Operand(SUCCESS));
    }
  }

  // Exit and return r0
  __ bind(&exit_label_);
  if (global()) {
    __ ldr(r0, MemOperand(frame_pointer(), kSuccessfulCapturesOffset));
  }

  __ bind(&return_r0);
  // Restore the original regexp stack pointer value (effectively, pop the
  // stored base pointer).
  PopRegExpBasePointer(backtrack_stackpointer(), r2);

  // Skip sp past regexp registers and local variables..
  __ mov(sp, frame_pointer());
  // Restore registers r4..r11 and return (restoring lr to pc).
  __ ldm(ia_w, sp, registers_to_retain | pc);

  // Backtrack code (branch target for conditional backtracks).
  if (backtrack_label_.is_linked()) {
    __ bind(&backtrack_label_);
    Backtrack();
  }

  Label exit_with_exception;

  // Preempt-code.
  if (check_preempt_label_.is_linked()) {
    SafeCallTarget(&check_preempt_label_);

    StoreRegExpStackPointerToMemory(backtrack_stackpointer(), r1);

    CallCheckStackGuardState();
    __ cmp(r0, Operand::Zero());
    // If returning non-zero, we should end execution with the given
    // result as return value.
    __ b(ne, &return_r0);

    LoadRegExpStackPointerFromMemory(backtrack_stackpointer());

    // String might have moved: Reload end of string from frame.
    __ ldr(end_of_input_address(),
           MemOperand(frame_pointer(), kInputEndOffset));
    SafeReturn();
  }

  // Backtrack stack overflow code.
  if (stack_overflow_label_.is_linked()) {
    SafeCallTarget(&stack_overflow_label_);
    // Reached if the backtrack-stack limit has been hit.

    // Call GrowStack(isolate).

    StoreRegExpStackPointerToMemory(backtrack_stackpointer(), r1);

    static constexpr int kNumArguments = 1;
    __ PrepareCallCFunction(kNumArguments);
    __ mov(r0, Operand(ExternalReference::isolate_address(isolate())));
    ExternalReference grow_stack = ExternalReference::re_grow_stack();
    CallCFunctionFromIrregexpCode(grow_stack, kNumArguments);
    // If nullptr is returned, we have failed to grow the stack, and must exit
    // with a stack-overflow exception.
    __ cmp(r0, Operand::Zero());
    __ b(eq, &exit_with_exception);
    // Otherwise use return value as new stack pointer.
    __ mov(backtrack_stackpointer(), r0);
    // Restore saved registers and continue.
    SafeReturn();
  }

  if (exit_with_exception.is_linked()) {
    // If any of the code above needed to exit with an exception.
    __ bind(&exit_with_exception);
    // Exit with Result EXCEPTION(-1) to signal thrown exception.
    __ mov(r0, Operand(EXCEPTION));
    __ jmp(&return_r0);
  }

  if (fallback_label_.is_linked()) {
    __ bind(&fallback_label_);
    __ mov(r0, Operand(FALLBACK_TO_EXPERIMENTAL));
    __ jmp(&return_r0);
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

void RegExpMacroAssemblerARM::GoTo(Label* to) {
  BranchOrBacktrack(al, to);
}


void RegExpMacroAssemblerARM::IfRegisterGE(int reg,
                                           int comparand,
                                           Label* if_ge) {
  __ ldr(r0, register_location(reg));
  __ cmp(r0, Operand(comparand));
  BranchOrBacktrack(ge, if_ge);
}


void RegExpMacroAssemblerARM::IfRegisterLT(int reg,
                                           int comparand,
                                           Label* if_lt) {
  __ ldr(r0, register_location(reg));
  __ cmp(r0, Operand(comparand));
  BranchOrBacktrack(lt, if_lt);
}


void RegExpMacroAssemblerARM::IfRegisterEqPos(int reg,
                                              Label* if_eq) {
  __ ldr(r0, register_location(reg));
  __ cmp(r0, Operand(current_input_offset()));
  BranchOrBacktrack(eq, if_eq);
}


RegExpMacroAssembler::IrregexpImplementation
    RegExpMacroAssemblerARM::Implementation() {
  return kARMImplementation;
}


void RegExpMacroAssemblerARM::PopCurrentPosition() {
  Pop(current_input_offset());
}


void RegExpMacroAssemblerARM::PopRegister(int register_index) {
  Pop(r0);
  __ str(r0, register_location(register_index));
}


void RegExpMacroAssemblerARM::PushBacktrack(Label* label) {
  __ mov_label_offset(r0, label);
  Push(r0);
  CheckStackLimit();
}


void RegExpMacroAssemblerARM::PushCurrentPosition() {
  Push(current_input_offset());
}


void RegExpMacroAssemblerARM::PushRegister(int register_index,
                                           StackCheckFlag check_stack_limit) {
  __ ldr(r0, register_location(register_index));
  Push(r0);
  if (check_stack_limit) CheckStackLimit();
}


void RegExpMacroAssemblerARM::ReadCurrentPositionFromRegister(int reg) {
  __ ldr(current_input_offset(), register_location(reg));
}

void RegExpMacroAssemblerARM::WriteStackPointerToRegister(int reg) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ mov(r1, Operand(ref));
  __ ldr(r1, MemOperand(r1));
  __ sub(r0, backtrack_stackpointer(), r1);
  __ str(r0, register_location(reg));
}

void RegExpMacroAssemblerARM::ReadStackPointerFromRegister(int reg) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ mov(r0, Operand(ref));
  __ ldr(r0, MemOperand(r0));
  __ ldr(backtrack_stackpointer(), register_location(reg));
  __ add(backtrack_stackpointer(), backtrack_stackpointer(), r0);
}

void RegExpMacroAssemblerARM::SetCurrentPositionFromEnd(int by) {
  Label after_position;
  __ cmp(current_input_offset(), Operand(-by * char_size()));
  __ b(ge, &after_position);
  __ mov(current_input_offset(), Operand(-by * char_size()));
  // On RegExp code entry (where this operation is used), the character before
  // the current position is expected to be already loaded.
  // We have advanced the position, so it's safe to read backwards.
  LoadCurrentCharacterUnchecked(-1, 1);
  __ bind(&after_position);
}


void RegExpMacroAssemblerARM::SetRegister(int register_index, int to) {
  DCHECK(register_index >= num_saved_registers_);  // Reserved for positions!
  __ mov(r0, Operand(to));
  __ str(r0, register_location(register_index));
}


bool RegExpMacroAssemblerARM::Succeed() {
  __ jmp(&success_label_);
  return global();
}


void RegExpMacroAssemblerARM::WriteCurrentPositionToRegister(int reg,
                                                             int cp_offset) {
  if (cp_offset == 0) {
    __ str(current_input_offset(), register_location(reg));
  } else {
    __ add(r0, current_input_offset(), Operand(cp_offset * char_size()));
    __ str(r0, register_location(reg));
  }
}


void RegExpMacroAssemblerARM::ClearRegisters(int reg_from, int reg_to) {
  DCHECK(reg_from <= reg_to);
  __ ldr(r0, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
  for (int reg = reg_from; reg <= reg_to; reg++) {
    __ str(r0, register_location(reg));
  }
}

// Private methods:

void RegExpMacroAssemblerARM::CallCheckStackGuardState(Operand extra_space) {
  DCHECK(!isolate()->IsGeneratingEmbeddedBuiltins());
  DCHECK(!masm_->options().isolate_independent_code);

  __ PrepareCallCFunction(4);

  // Extra space for variables to consider in stack check.
  __ mov(kCArgRegs[3], extra_space);
  // RegExp code frame pointer.
  __ mov(kCArgRegs[2], frame_pointer());
  // InstructionStream of self.
  __ mov(kCArgRegs[1], Operand(masm_->CodeObject()));

  // We need to make room for the return address on the stack.
  int stack_alignment = base::OS::ActivationFrameAlignment();
  DCHECK(IsAligned(stack_alignment, kSystemPointerSize));
  __ AllocateStackSpace(stack_alignment);

  // r0 will point to the return address, placed by DirectCEntry.
  __ mov(r0, sp);

  ExternalReference stack_guard_check =
      ExternalReference::re_check_stack_guard_state();
  __ mov(ip, Operand(stack_guard_check));

  EmbeddedData d = EmbeddedData::FromBlob();
  Address entry = d.InstructionStartOf(Builtin::kDirectCEntry);
  __ mov(lr, Operand(entry, RelocInfo::OFF_HEAP_TARGET));
  __ Call(lr);

  // Drop the return address from the stack.
  __ add(sp, sp, Operand(stack_alignment));

  DCHECK_NE(0, stack_alignment);
  __ ldr(sp, MemOperand(sp, 0));

  __ mov(code_pointer(), Operand(masm_->CodeObject()));
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

int RegExpMacroAssemblerARM::CheckStackGuardState(Address* return_address,
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

MemOperand RegExpMacroAssemblerARM::register_location(int register_index) {
  DCHECK(register_index < (1<<30));
  if (num_registers_ <= register_index) {
    num_registers_ = register_index + 1;
  }
  return MemOperand(frame_pointer(),
                    kRegisterZeroOffset - register_index * kSystemPointerSize);
}


void RegExpMacroAssemblerARM::CheckPosition(int cp_offset,
                                            Label* on_outside_input) {
  if (cp_offset >= 0) {
    __ cmp(current_input_offset(), Operand(-cp_offset * char_size()));
    BranchOrBacktrack(ge, on_outside_input);
  } else {
    __ ldr(r1, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
    __ add(r0, current_input_offset(), Operand(cp_offset * char_size()));
    __ cmp(r0, r1);
    BranchOrBacktrack(le, on_outside_input);
  }
}


void RegExpMacroAssemblerARM::BranchOrBacktrack(Condition condition,
                                                Label* to) {
  if (condition == al) {  // Unconditional.
    if (to == nullptr) {
      Backtrack();
      return;
    }
    __ jmp(to);
    return;
  }
  if (to == nullptr) {
    __ b(condition, &backtrack_label_);
    return;
  }
  __ b(condition, to);
}


void RegExpMacroAssemblerARM::SafeCall(Label* to, Condition cond) {
  __ bl(to, cond);
}


void RegExpMacroAssemblerARM::SafeReturn() {
  __ pop(lr);
  __ add(pc, lr, Operand(masm_->CodeObject()));
}


void RegExpMacroAssemblerARM::SafeCallTarget(Label* name) {
  __ bind(name);
  __ sub(lr, lr, Operand(masm_->CodeObject()));
  __ push(lr);
}


void RegExpMacroAssemblerARM::Push(Register source) {
  DCHECK(source != backtrack_stackpointer());
  __ str(source,
         MemOperand(backtrack_stackpointer(), kSystemPointerSize, NegPreIndex));
}


void RegExpMacroAssemblerARM::Pop(Register target) {
  DCHECK(target != backtrack_stackpointer());
  __ ldr(target,
         MemOperand(backtrack_stackpointer(), kSystemPointerSize, PostIndex));
}

void RegExpMacroAssemblerARM::CallCFunctionFromIrregexpCode(
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

void RegExpMacroAssemblerARM::CheckPreemption() {
  // Check for preemption.
  ExternalReference stack_limit =
      ExternalReference::address_of_jslimit(isolate());
  __ mov(r0, Operand(stack_limit));
  __ ldr(r0, MemOperand(r0));
  __ cmp(sp, r0);
  SafeCall(&check_preempt_label_, ls);
}


void RegExpMacroAssemblerARM::CheckStackLimit() {
  ExternalReference stack_limit =
      ExternalReference::address_of_regexp_stack_limit_address(isolate());
  __ mov(r0, Operand(stack_limit));
  __ ldr(r0, MemOperand(r0));
  __ cmp(backtrack_stackpointer(), Operand(r0));
  SafeCall(&stack_overflow_label_, ls);
}


void RegExpMacroAssemblerARM::LoadCurrentCharacterUnchecked(int cp_offset,
                                                            int characters) {
  Register offset = current_input_offset();
  if (cp_offset != 0) {
    // r4 is not being used to store the capture start index at this point.
    __ add(r4, current_input_offset(), Operand(cp_offset * char_size()));
    offset = r4;
  }
  // The ldr, str, ldrh, strh instructions can do unaligned accesses, if the CPU
  // and the operating system running on the target allow it.
  // If unaligned load/stores are not supported then this function must only
  // be used to load a single character at a time.
  if (!CanReadUnaligned()) {
    DCHECK_EQ(1, characters);
  }

  if (mode_ == LATIN1) {
    if (characters == 4) {
      __ ldr(current_character(), MemOperand(end_of_input_address(), offset));
    } else if (characters == 2) {
      __ ldrh(current_character(), MemOperand(end_of_input_address(), offset));
    } else {
      DCHECK_EQ(1, characters);
      __ ldrb(current_character(), MemOperand(end_of_input_address(), offset));
    }
  } else {
    DCHECK(mode_ == UC16);
    if (characters == 2) {
      __ ldr(current_character(), MemOperand(end_of_input_address(), offset));
    } else {
      DCHECK_EQ(1, characters);
      __ ldrh(current_character(), MemOperand(end_of_input_address(), offset));
    }
  }
}


#undef __

}  // namespace internal
}  // namespace v8

#endif  // V8_TARGET_ARCH_ARM
```