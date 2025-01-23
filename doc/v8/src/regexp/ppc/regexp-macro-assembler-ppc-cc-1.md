Response:
Let's break down the thought process for analyzing this V8 code snippet.

1. **Initial Scan for Keywords and Structure:**  I first skimmed the code, looking for recognizable patterns and keywords. Things that jumped out were:
    * `RegExpMacroAssemblerPPC` (obvious class name)
    * `__` (indicating assembly instructions)
    * `Label`, `bind`, `b` (label definition and branching, common in assembly)
    * `Push`, `Pop` (stack operations)
    * `LoadU64`, `StoreU64` (memory access)
    * `MemOperand` (describing memory locations)
    * `if`, `else`, `for` (control flow, even in assembly generation)
    * `global()`, `UC16`, `LATIN1` (properties and data types related to regular expressions)
    * `kRegisterZeroOffset`, `kInputStartOffset` (constants likely related to frame layout)
    * `success_label_`, `backtrack_label_`, `exit_label_` (control flow labels for different outcomes)
    * `CallCFunction`, `ExternalReference` (interaction with C++ code)
    * `CheckStackLimit`, `CheckPreemption` (safety checks)

2. **Identify Core Functionality Blocks:**  Based on the keywords, I started to group related code. I saw blocks related to:
    * **Initialization:** Setting up the initial state (register zeroing).
    * **Success Handling:** What happens when the regex matches.
    * **Global Matching:**  Looping for multiple matches in a global regex.
    * **Backtracking:**  Handling failed matches and trying alternatives.
    * **Stack Management:** Pushing and popping values, checking limits.
    * **Character Loading:** Accessing characters from the input string.
    * **Error/Exception Handling:**  Stack overflow, preemption.
    * **C++ Interop:** Calling C++ functions.

3. **Focus on the `GenerateCode` Method (Implicitly):**  The structure of the code, with the creation of labels and the final `GetCode` call, strongly suggests this is part of a code generation process. The main logic within the snippet is the core of the generated assembly code for regex matching.

4. **Infer the Overall Purpose:** Combining the class name and the identified functionality, it became clear that this code is responsible for generating machine code (specifically for the PPC architecture) to execute regular expressions.

5. **Analyze Key Sections in Detail:** I then looked closer at important blocks:
    * **Register Saving/Restoring:** The beginning of the `GenerateCode` function saves registers. This is essential to maintain the state of the calling code.
    * **Success Logic:** The code under `success_label_` clearly deals with storing captured groups and restarting the match for global regexes.
    * **Backtracking Logic:** The `backtrack_label_` is the target for failed matches, indicating a return to a previous state.
    * **Stack Operations:**  The `Push` and `Pop` methods are crucial for managing the backtracking stack.
    * **Character Access:** The `LoadCurrentCharacterUnchecked` method shows how the code accesses characters in the input string, taking into account encoding (LATIN1/UC16).

6. **Connect to Regular Expression Concepts:** I started relating the code to standard regex concepts:
    * **Capturing Groups:** The `num_saved_registers_` and the loop storing values into `kRegisterOutputOffset` are clearly related to capturing parentheses in regexes.
    * **Global Flag:** The logic within the `global()` block handles the iteration for global matches.
    * **Backtracking:**  The `Backtrack()` call and the `backtrack_label_` are direct implementations of regex backtracking.

7. **Consider JavaScript Interaction:** I thought about how this assembly code would be used from JavaScript. The core function is matching a string against a pattern.

8. **Address Specific Prompts:**  I then went through the specific questions in the prompt:
    * **Functionality:** Summarize the identified core functionalities.
    * **`.tq` extension:**  Recognize that this is not a Torque file.
    * **JavaScript Example:**  Provide a simple JavaScript regex example that this code would help execute.
    * **Logic Reasoning:** Devise a simple scenario (input and regex) and trace the likely execution flow through the generated code (though without the *actual* generated assembly, this is high-level).
    * **Common Errors:**  Think about common regex mistakes that this code would either handle correctly or potentially lead to performance issues (like catastrophic backtracking).
    * **Overall Summary:** Condense the main points into a concise conclusion.

9. **Refine and Organize:**  Finally, I organized the information logically, using clear language and providing code examples where appropriate. I made sure to address all parts of the prompt.

Essentially, the process involves a combination of code reading, pattern recognition, knowledge of assembly language concepts (even at a high level of abstraction with macros), and understanding of how regular expressions work. It's like reverse-engineering the purpose of the code by examining its structure and actions.
这是对V8源代码文件 `v8/src/regexp/ppc/regexp-macro-assembler-ppc.cc` 的功能描述。

**功能归纳:**

`v8/src/regexp/ppc/regexp-macro-assembler-ppc.cc` 文件是 V8 引擎中用于为 **PPC64 (PowerPC 64-bit) 架构** 生成正则表达式匹配机器码的关键组件。它提供了一组宏和函数，用于构建执行正则表达式匹配的汇编代码。

**具体功能点:**

1. **正则表达式编译目标:**  它是 V8 正则表达式引擎的一个后端，专门为 PPC64 架构生成优化的机器码。这意味着当 JavaScript 引擎需要在 PPC64 平台上执行正则表达式时，会使用这个文件中的代码来生成实际的执行指令。

2. **汇编代码生成:**  文件中包含了大量的宏 (`__`)，这些宏封装了 PPC64 汇编指令。通过调用这些宏，代码可以生成用于执行各种正则表达式操作的汇编代码，例如：
    * **字符匹配:**  加载、比较输入字符串中的字符。
    * **状态管理:**  维护正则表达式匹配的状态，例如当前匹配位置、捕获组信息。
    * **控制流:**  实现分支、循环等控制结构，用于处理正则表达式中的不同部分（例如，量词、分组）。
    * **回溯:**  在匹配失败时，回溯到之前的状态并尝试其他可能的匹配路径。
    * **捕获组处理:**  记录和存储匹配到的捕获组信息。
    * **堆栈管理:**  使用堆栈来保存回溯信息和寄存器状态。
    * **函数调用:**  调用 C++ 辅助函数，例如用于栈溢出处理和抢占检查。

3. **平台特定优化:**  由于它是 PPC64 架构特定的，因此它会利用该架构的指令集和特性进行优化，以提高正则表达式匹配的性能。

4. **与上层接口交互:**  该文件实现了 `RegExpMacroAssembler` 抽象类的接口，这是一个更通用的正则表达式汇编器接口。这允许 V8 的正则表达式引擎在不关心具体架构的情况下，使用统一的接口来生成不同平台的机器码。

5. **支持各种正则表达式特性:**  生成的汇编代码能够处理 JavaScript 正则表达式的各种特性，包括：
    * 字面量字符匹配
    * 字符类
    * 量词 (*, +, ?, {n}, {n,}, {n,m})
    * 分组和捕获
    * 断言 (例如, ^, $, \b, \B)
    * Unicode 支持

**关于 .tq 结尾:**

如果 `v8/src/regexp/ppc/regexp-macro-assembler-ppc.cc` 以 `.tq` 结尾，那么它的确是一个 V8 Torque 源代码文件。Torque 是 V8 用来生成高效的内置函数和运行时代码的语言。 然而，根据你提供的文件名，它是 `.cc` 结尾，这表明它是一个 C++ 源文件，包含了手写的汇编代码生成逻辑。

**与 JavaScript 功能的关系 (JavaScript 示例):**

这个 C++ 文件直接影响 JavaScript 中正则表达式的执行效率。当你使用 JavaScript 的 `RegExp` 对象进行匹配操作时，V8 引擎会根据平台选择相应的 `RegExpMacroAssembler` 实现来生成机器码并执行。

```javascript
const regex = /ab+c/g;
const str = 'abbc abc abbbc';
let array;

while ((array = regex.exec(str)) !== null) {
  console.log(`发现匹配 ${array[0]}。索引位置 ${regex.lastIndex - array[0].length}。`);
}
// 预期输出:
// 发现匹配 abbc。索引位置 0。
// 发现匹配 abc。索引位置 5。
// 发现匹配 abbbc。索引位置 9。
```

在这个例子中，当你调用 `regex.exec(str)` 时，V8 内部会使用 `regexp-macro-assembler-ppc.cc` (在 PPC64 平台上) 生成执行 `/ab+c/g` 这个正则表达式匹配的机器码。生成的代码负责遍历字符串 `str`，查找符合模式 `ab+c` 的子串，并处理全局匹配标志 `g`。

**代码逻辑推理 (假设输入与输出):**

假设有以下 JavaScript 代码和 PPC64 平台：

```javascript
const regex = /a(b*)c/;
const str = "abbbc";
const match = str.match(regex);
console.log(match[0]); // 输出 "abbbc"
console.log(match[1]); // 输出 "bbb"
```

当执行 `str.match(regex)` 时，`regexp-macro-assembler-ppc.cc` 生成的机器码会执行以下类似步骤（简化描述）：

1. **从字符串起始位置开始:** 扫描输入字符串 "abbbc"。
2. **匹配 'a':**  找到第一个字符 'a' 并匹配成功。
3. **匹配 '(b*)':**  尝试匹配零个或多个 'b'。由于后面有 'b'，会连续匹配三个 'b'。这部分会被捕获到第一个捕获组。
4. **匹配 'c':** 匹配到接下来的字符 'c'。
5. **匹配成功:**  整个正则表达式匹配成功。
6. **存储捕获组:**  生成的机器码会将捕获到的 "bbb" 存储起来。
7. **返回结果:**  `str.match(regex)` 返回一个数组，其中包含匹配到的完整字符串 "abbbc" 和捕获到的子串 "bbb"。

**用户常见的编程错误:**

尽管 `regexp-macro-assembler-ppc.cc` 是 V8 内部的实现细节，用户在使用正则表达式时的一些常见错误可能会在执行阶段触发这里生成的代码，并可能导致性能问题或意外结果。例如：

* **回溯失控 (Catastrophic Backtracking):**  编写了导致正则表达式引擎进行大量无效回溯的模式。例如：`/(a+)+b/` 在输入 "aaaaaaaaac" 这样的字符串时，会进行指数级别的回溯。虽然底层的汇编代码会尝试执行，但性能会急剧下降。

* **忘记转义特殊字符:**  例如，想要匹配字面量 `.`，却写成了 `/./`，这会匹配任何字符。生成的汇编代码会按照错误的意图执行。

* **不必要的捕获组:**  使用了过多的捕获组，即使不需要提取这些子匹配。这会增加生成代码的复杂性和执行时的开销。

**功能归纳 (第二部分):**

这部分代码主要关注正则表达式匹配成功和失败时的 **退出流程** 以及一些 **辅助功能**。

1. **匹配成功处理 (`success_label_`):**
   - **保存捕获组:** 如果正则表达式有捕获组，这段代码负责将匹配到的子串的起始和结束位置存储到预先分配的内存区域 (`kRegisterOutputOffset`)。它会根据字符编码 (UC16 或 LATIN1) 调整偏移量。
   - **处理全局匹配 (`global()`):**
     - 如果正则表达式是全局的，它会更新成功匹配的计数器 (`kSuccessfulCapturesOffset`)。
     - 它会检查是否有足够的空间存储更多的匹配结果。
     - 如果是零长度匹配，并且是全局匹配，它会特殊处理以避免无限循环，会尝试将匹配位置向前移动。
     - 准备下一次匹配的起始位置。
   - **非全局匹配:** 如果不是全局匹配，则设置返回值为成功状态 (`SUCCESS`).

2. **退出和返回 (`exit_label_`, `return_r3`):**
   - **恢复堆栈:**  弹出之前保存的基指针，恢复堆栈状态。
   - **恢复寄存器:** 弹出之前保存的寄存器 (`registers_to_retain`).
   - **返回结果:** 将匹配结果状态 (例如, `SUCCESS`, `FAILURE`, `EXCEPTION`) 存储在寄存器 `r3` 中，并通过 `blr` 指令返回。

3. **回溯 (`backtrack_label_`):**  如果匹配失败，程序会跳转到 `backtrack_label_`，并调用 `Backtrack()` 函数（在其他地方定义），该函数负责从堆栈中恢复之前的状态并尝试其他的匹配路径。

4. **抢占检查 (`check_preempt_label_`):**  V8 引擎会定期检查是否需要暂停 JavaScript 执行。这段代码在执行正则表达式匹配的过程中，会检查是否发生了抢占，如果发生，会保存当前状态并返回。

5. **栈溢出处理 (`stack_overflow_label_`):**  如果正则表达式匹配导致堆栈溢出（例如，由于深度嵌套或复杂的回溯），程序会跳转到 `stack_overflow_label_`，调用 `GrowStack` 尝试扩展堆栈。如果扩展失败，则抛出异常。

6. **异常处理 (`exit_with_exception`):** 如果在执行过程中发生了异常，程序会跳转到这里，设置返回值为 `EXCEPTION`。

7. **回退到实验性实现 (`fallback_label_`):**  在某些情况下，如果当前优化的代码无法处理，可能会回退到更通用的（可能更慢的）正则表达式实现。

8. **辅助函数:**  代码中还包含一些辅助函数，例如：
   - `GoTo`: 无条件跳转。
   - `IfRegisterGE`, `IfRegisterLT`, `IfRegisterEqPos`:  基于寄存器值进行条件分支。
   - `PopCurrentPosition`, `PopRegister`, `PushBacktrack`, `PushCurrentPosition`, `PushRegister`:  堆栈操作。
   - `ReadCurrentPositionFromRegister`, `WriteStackPointerToRegister`, `ReadStackPointerFromRegister`:  在寄存器和内存之间读写状态信息。
   - `SetCurrentPositionFromEnd`, `SetRegister`, `ClearRegisters`:  设置寄存器值。
   - `Succeed`: 设置匹配成功并跳转到成功标签。
   - `WriteCurrentPositionToRegister`: 将当前位置写入寄存器。
   - `CheckStackGuardState`:  检查堆栈保护状态。
   - `CallCFunctionFromIrregexpCode`:  调用 C++ 函数。
   - `CheckPosition`: 检查当前位置是否超出输入边界。
   - `BranchOrBacktrack`:  根据条件进行分支或回溯。
   - `SafeCall`, `SafeReturn`, `SafeCallTarget`:  安全的函数调用和返回机制。
   - `Push`, `Pop`:  底层堆栈操作。
   - `CheckPreemption`, `CheckStackLimit`:  检查抢占和堆栈限制。
   - `LoadCurrentCharacterUnchecked`:  从输入字符串中加载字符。

总的来说，这部分代码负责处理正则表达式匹配的最终结果、错误情况，以及提供一些底层的操作来辅助匹配过程。它确保了在 PPC64 架构上高效且安全地执行正则表达式匹配。

### 提示词
```
这是目录为v8/src/regexp/ppc/regexp-macro-assembler-ppc.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/ppc/regexp-macro-assembler-ppc.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
ue = start offset - 1
      if (num_saved_registers_ > 8) {
        // One slot beyond address of register 0.
        __ addi(r4, frame_pointer(),
                Operand(kRegisterZeroOffset + kSystemPointerSize));
        __ mov(r5, Operand(num_saved_registers_));
        __ mtctr(r5);
        Label init_loop;
        __ bind(&init_loop);
        __ StoreU64WithUpdate(r3, MemOperand(r4, -kSystemPointerSize));
        __ bdnz(&init_loop);
      } else {
        for (int i = 0; i < num_saved_registers_; i++) {
          __ StoreU64(r3, register_location(i), r0);
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
        __ LoadU64(r4, MemOperand(frame_pointer(), kInputStartOffset));
        __ LoadU64(r3, MemOperand(frame_pointer(), kRegisterOutputOffset));
        __ LoadU64(r5, MemOperand(frame_pointer(), kStartIndexOffset));
        __ sub(r4, end_of_input_address(), r4);
        // r4 is length of input in bytes.
        if (mode_ == UC16) {
          __ ShiftRightU64(r4, r4, Operand(1));
        }
        // r4 is length of input in characters.
        __ add(r4, r4, r5);
        // r4 is length of string in characters.

        DCHECK_EQ(0, num_saved_registers_ % 2);
        // Always an even number of capture registers. This allows us to
        // unroll the loop once to add an operation between a load of a register
        // and the following use of that register.
        for (int i = 0; i < num_saved_registers_; i += 2) {
          __ LoadU64(r5, register_location(i), r0);
          __ LoadU64(r6, register_location(i + 1), r0);
          if (i == 0 && global_with_zero_length_check()) {
            // Keep capture start in r25 for the zero-length check later.
            __ mr(r25, r5);
          }
          if (mode_ == UC16) {
            __ ShiftRightS64(r5, r5, Operand(1));
            __ add(r5, r4, r5);
            __ ShiftRightS64(r6, r6, Operand(1));
            __ add(r6, r4, r6);
          } else {
            __ add(r5, r4, r5);
            __ add(r6, r4, r6);
          }
          __ stw(r5, MemOperand(r3));
          __ addi(r3, r3, Operand(kIntSize));
          __ stw(r6, MemOperand(r3));
          __ addi(r3, r3, Operand(kIntSize));
        }
      }

      if (global()) {
        // Restart matching if the regular expression is flagged as global.
        __ LoadU64(r3, MemOperand(frame_pointer(), kSuccessfulCapturesOffset));
        __ LoadU64(r4, MemOperand(frame_pointer(), kNumOutputRegistersOffset));
        __ LoadU64(r5, MemOperand(frame_pointer(), kRegisterOutputOffset));
        // Increment success counter.
        __ addi(r3, r3, Operand(1));
        __ StoreU64(r3, MemOperand(frame_pointer(), kSuccessfulCapturesOffset));
        // Capture results have been stored, so the number of remaining global
        // output registers is reduced by the number of stored captures.
        __ subi(r4, r4, Operand(num_saved_registers_));
        // Check whether we have enough room for another set of capture results.
        __ cmpi(r4, Operand(num_saved_registers_));
        __ blt(&return_r3);

        __ StoreU64(r4, MemOperand(frame_pointer(), kNumOutputRegistersOffset));
        // Advance the location for output.
        __ addi(r5, r5, Operand(num_saved_registers_ * kIntSize));
        __ StoreU64(r5, MemOperand(frame_pointer(), kRegisterOutputOffset));

        // Restore the original regexp stack pointer value (effectively, pop the
        // stored base pointer).
        PopRegExpBasePointer(backtrack_stackpointer(), r5);

        Label reload_string_start_minus_one;

        if (global_with_zero_length_check()) {
          // Special case for zero-length matches.
          // r25: capture start index
          __ CmpS64(current_input_offset(), r25);
          // Not a zero-length match, restart.
          __ bne(&reload_string_start_minus_one);
          // Offset from the end is zero if we already reached the end.
          __ cmpi(current_input_offset(), Operand::Zero());
          __ beq(&exit_label_);
          // Advance current position after a zero-length match.
          Label advance;
          __ bind(&advance);
          __ addi(current_input_offset(), current_input_offset(),
                  Operand((mode_ == UC16) ? 2 : 1));
          if (global_unicode()) CheckNotInSurrogatePair(0, &advance);
        }

        __ bind(&reload_string_start_minus_one);
        // Prepare r3 to initialize registers with its value in the next run.
        // Must be immediately before the jump to avoid clobbering.
        __ LoadU64(r3, MemOperand(frame_pointer(), kStringStartMinusOneOffset));

        __ b(&load_char_start_regexp);
      } else {
        __ li(r3, Operand(SUCCESS));
      }
    }

    // Exit and return r3
    __ bind(&exit_label_);
    if (global()) {
      __ LoadU64(r3, MemOperand(frame_pointer(), kSuccessfulCapturesOffset));
    }

    __ bind(&return_r3);
    // Restore the original regexp stack pointer value (effectively, pop the
    // stored base pointer).
    PopRegExpBasePointer(backtrack_stackpointer(), r5);

    // Skip sp past regexp registers and local variables..
    __ mr(sp, frame_pointer());
    // Restore registers r25..r31 and return (restoring lr to pc).
    __ MultiPop(registers_to_retain);
    __ pop(r0);
    __ mtlr(r0);
    __ blr();

    // Backtrack code (branch target for conditional backtracks).
    if (backtrack_label_.is_linked()) {
      __ bind(&backtrack_label_);
      Backtrack();
    }

    Label exit_with_exception;

    // Preempt-code
    if (check_preempt_label_.is_linked()) {
      SafeCallTarget(&check_preempt_label_);

      StoreRegExpStackPointerToMemory(backtrack_stackpointer(), r4);

      CallCheckStackGuardState(r3);
      __ cmpi(r3, Operand::Zero());
      // If returning non-zero, we should end execution with the given
      // result as return value.
      __ bne(&return_r3);

      LoadRegExpStackPointerFromMemory(backtrack_stackpointer());

      // String might have moved: Reload end of string from frame.
      __ LoadU64(end_of_input_address(),
                 MemOperand(frame_pointer(), kInputEndOffset));
      SafeReturn();
    }

    // Backtrack stack overflow code.
    if (stack_overflow_label_.is_linked()) {
      SafeCallTarget(&stack_overflow_label_);

      // Call GrowStack(isolate).

      StoreRegExpStackPointerToMemory(backtrack_stackpointer(), r4);

      static constexpr int kNumArguments = 1;
      __ PrepareCallCFunction(kNumArguments, r3);
      __ mov(r3, Operand(ExternalReference::isolate_address(isolate())));
      ExternalReference grow_stack = ExternalReference::re_grow_stack();
      CallCFunctionFromIrregexpCode(grow_stack, kNumArguments);
      // If nullptr is returned, we have failed to grow the stack, and must exit
      // with a stack-overflow exception.
      __ cmpi(r3, Operand::Zero());
      __ beq(&exit_with_exception);
      // Otherwise use return value as new stack pointer.
      __ mr(backtrack_stackpointer(), r3);
      // Restore saved registers and continue.
      SafeReturn();
    }

    if (exit_with_exception.is_linked()) {
      // If any of the code above needed to exit with an exception.
      __ bind(&exit_with_exception);
      // Exit with Result EXCEPTION(-1) to signal thrown exception.
      __ li(r3, Operand(EXCEPTION));
      __ b(&return_r3);
    }

    if (fallback_label_.is_linked()) {
      __ bind(&fallback_label_);
      __ li(r3, Operand(FALLBACK_TO_EXPERIMENTAL));
      __ b(&return_r3);
    }
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

void RegExpMacroAssemblerPPC::GoTo(Label* to) { BranchOrBacktrack(al, to); }


void RegExpMacroAssemblerPPC::IfRegisterGE(int reg, int comparand,
                                           Label* if_ge) {
  __ LoadU64(r3, register_location(reg), r0);
  __ CmpS64(r3, Operand(comparand), r0);
  BranchOrBacktrack(ge, if_ge);
}


void RegExpMacroAssemblerPPC::IfRegisterLT(int reg, int comparand,
                                           Label* if_lt) {
  __ LoadU64(r3, register_location(reg), r0);
  __ CmpS64(r3, Operand(comparand), r0);
  BranchOrBacktrack(lt, if_lt);
}


void RegExpMacroAssemblerPPC::IfRegisterEqPos(int reg, Label* if_eq) {
  __ LoadU64(r3, register_location(reg), r0);
  __ CmpS64(r3, current_input_offset());
  BranchOrBacktrack(eq, if_eq);
}


RegExpMacroAssembler::IrregexpImplementation
RegExpMacroAssemblerPPC::Implementation() {
  return kPPCImplementation;
}


void RegExpMacroAssemblerPPC::PopCurrentPosition() {
  Pop(current_input_offset());
}


void RegExpMacroAssemblerPPC::PopRegister(int register_index) {
  Pop(r3);
  __ StoreU64(r3, register_location(register_index), r0);
}


void RegExpMacroAssemblerPPC::PushBacktrack(Label* label) {
  __ mov_label_offset(r3, label);
  Push(r3);
  CheckStackLimit();
}


void RegExpMacroAssemblerPPC::PushCurrentPosition() {
  Push(current_input_offset());
}


void RegExpMacroAssemblerPPC::PushRegister(int register_index,
                                           StackCheckFlag check_stack_limit) {
  __ LoadU64(r3, register_location(register_index), r0);
  Push(r3);
  if (check_stack_limit) CheckStackLimit();
}


void RegExpMacroAssemblerPPC::ReadCurrentPositionFromRegister(int reg) {
  __ LoadU64(current_input_offset(), register_location(reg), r0);
}

void RegExpMacroAssemblerPPC::WriteStackPointerToRegister(int reg) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ mov(r4, Operand(ref));
  __ LoadU64(r4, MemOperand(r4));
  __ SubS64(r3, backtrack_stackpointer(), r4);
  __ StoreU64(r3, register_location(reg), r0);
}

void RegExpMacroAssemblerPPC::ReadStackPointerFromRegister(int reg) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ mov(r3, Operand(ref));
  __ LoadU64(r3, MemOperand(r3));
  __ LoadU64(backtrack_stackpointer(), register_location(reg), r0);
  __ AddS64(backtrack_stackpointer(), backtrack_stackpointer(), r3);
}

void RegExpMacroAssemblerPPC::SetCurrentPositionFromEnd(int by) {
  Label after_position;
  __ CmpS64(current_input_offset(), Operand(-by * char_size()), r0);
  __ bge(&after_position);
  __ mov(current_input_offset(), Operand(-by * char_size()));
  // On RegExp code entry (where this operation is used), the character before
  // the current position is expected to be already loaded.
  // We have advanced the position, so it's safe to read backwards.
  LoadCurrentCharacterUnchecked(-1, 1);
  __ bind(&after_position);
}


void RegExpMacroAssemblerPPC::SetRegister(int register_index, int to) {
  DCHECK(register_index >= num_saved_registers_);  // Reserved for positions!
  __ mov(r3, Operand(to));
  __ StoreU64(r3, register_location(register_index), r0);
}


bool RegExpMacroAssemblerPPC::Succeed() {
  __ b(&success_label_);
  return global();
}


void RegExpMacroAssemblerPPC::WriteCurrentPositionToRegister(int reg,
                                                             int cp_offset) {
  if (cp_offset == 0) {
    __ StoreU64(current_input_offset(), register_location(reg), r0);
  } else {
    __ mov(r0, Operand(cp_offset * char_size()));
    __ add(r3, current_input_offset(), r0);
    __ StoreU64(r3, register_location(reg), r0);
  }
}


void RegExpMacroAssemblerPPC::ClearRegisters(int reg_from, int reg_to) {
  DCHECK(reg_from <= reg_to);
  __ LoadU64(r3, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
  for (int reg = reg_from; reg <= reg_to; reg++) {
    __ StoreU64(r3, register_location(reg), r0);
  }
}

// Private methods:

void RegExpMacroAssemblerPPC::CallCheckStackGuardState(Register scratch,
                                                       Operand extra_space) {
  DCHECK(!isolate()->IsGeneratingEmbeddedBuiltins());
  DCHECK(!masm_->options().isolate_independent_code);

  int frame_alignment = masm_->ActivationFrameAlignment();
  int stack_space = kNumRequiredStackFrameSlots;
  int stack_passed_arguments = 1;  // space for return address pointer

  // The following stack manipulation logic is similar to
  // PrepareCallCFunction.  However, we need an extra slot on the
  // stack to house the return address parameter.
  if (frame_alignment > kSystemPointerSize) {
    // Make stack end at alignment and make room for stack arguments
    // -- preserving original value of sp.
    __ mr(scratch, sp);
    __ addi(sp, sp,
            Operand(-(stack_passed_arguments + 1) * kSystemPointerSize));
    DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
    __ ClearRightImm(sp, sp,
                     Operand(base::bits::WhichPowerOfTwo(frame_alignment)));
    __ StoreU64(scratch,
                MemOperand(sp, stack_passed_arguments * kSystemPointerSize));
  } else {
    // Make room for stack arguments
    stack_space += stack_passed_arguments;
  }

  // Allocate frame with required slots to make ABI work.
  __ li(r0, Operand::Zero());
  __ StoreU64WithUpdate(r0, MemOperand(sp, -stack_space * kSystemPointerSize));

  // Extra space for variables to consider in stack check.
  __ mov(kCArgRegs[3], extra_space);
  // RegExp code frame pointer.
  __ mr(kCArgRegs[2], frame_pointer());
  // InstructionStream of self.
  __ mov(kCArgRegs[1], Operand(masm_->CodeObject()));
  // r3 will point to the return address, placed by DirectCEntry.
  __ addi(r3, sp, Operand(kStackFrameExtraParamSlot * kSystemPointerSize));

  ExternalReference stack_guard_check =
      ExternalReference::re_check_stack_guard_state();
  __ mov(ip, Operand(stack_guard_check));

  EmbeddedData d = EmbeddedData::FromBlob();
  Address entry = d.InstructionStartOf(Builtin::kDirectCEntry);
  __ mov(r0, Operand(entry, RelocInfo::OFF_HEAP_TARGET));
  __ Call(r0);

  // Restore the stack pointer
  stack_space = kNumRequiredStackFrameSlots + stack_passed_arguments;
  if (frame_alignment > kSystemPointerSize) {
    __ LoadU64(sp, MemOperand(sp, stack_space * kSystemPointerSize));
  } else {
    __ addi(sp, sp, Operand(stack_space * kSystemPointerSize));
  }

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

int RegExpMacroAssemblerPPC::CheckStackGuardState(Address* return_address,
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

MemOperand RegExpMacroAssemblerPPC::register_location(int register_index) {
  DCHECK(register_index < (1 << 30));
  if (num_registers_ <= register_index) {
    num_registers_ = register_index + 1;
  }
  return MemOperand(frame_pointer(),
                    kRegisterZeroOffset - register_index * kSystemPointerSize);
}

void RegExpMacroAssemblerPPC::CallCFunctionFromIrregexpCode(
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

void RegExpMacroAssemblerPPC::CheckPosition(int cp_offset,
                                            Label* on_outside_input) {
  if (cp_offset >= 0) {
    __ CmpS64(current_input_offset(), Operand(-cp_offset * char_size()), r0);
    BranchOrBacktrack(ge, on_outside_input);
  } else {
    __ LoadU64(r4, MemOperand(frame_pointer(), kStringStartMinusOneOffset));
    __ addi(r3, current_input_offset(), Operand(cp_offset * char_size()));
    __ CmpS64(r3, r4);
    BranchOrBacktrack(le, on_outside_input);
  }
}


void RegExpMacroAssemblerPPC::BranchOrBacktrack(Condition condition, Label* to,
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
    __ b(condition, &backtrack_label_, cr);
    return;
  }
  __ b(condition, to, cr);
}


void RegExpMacroAssemblerPPC::SafeCall(Label* to, Condition cond,
                                       CRegister cr) {
  __ b(cond, to, cr, SetLK);
}


void RegExpMacroAssemblerPPC::SafeReturn() {
  __ pop(r0);
  __ mov(ip, Operand(masm_->CodeObject()));
  __ add(r0, r0, ip);
  __ mtlr(r0);
  __ blr();
}


void RegExpMacroAssemblerPPC::SafeCallTarget(Label* name) {
  __ bind(name);
  __ mflr(r0);
  __ mov(ip, Operand(masm_->CodeObject()));
  __ sub(r0, r0, ip);
  __ push(r0);
}


void RegExpMacroAssemblerPPC::Push(Register source) {
  DCHECK(source != backtrack_stackpointer());
  __ StoreU64WithUpdate(
      source, MemOperand(backtrack_stackpointer(), -kSystemPointerSize));
}


void RegExpMacroAssemblerPPC::Pop(Register target) {
  DCHECK(target != backtrack_stackpointer());
  __ LoadU64(target, MemOperand(backtrack_stackpointer()));
  __ addi(backtrack_stackpointer(), backtrack_stackpointer(),
          Operand(kSystemPointerSize));
}


void RegExpMacroAssemblerPPC::CheckPreemption() {
  // Check for preemption.
  ExternalReference stack_limit =
      ExternalReference::address_of_jslimit(isolate());
  __ mov(r3, Operand(stack_limit));
  __ LoadU64(r3, MemOperand(r3));
  __ CmpU64(sp, r3);
  SafeCall(&check_preempt_label_, le);
}


void RegExpMacroAssemblerPPC::CheckStackLimit() {
  ExternalReference stack_limit =
      ExternalReference::address_of_regexp_stack_limit_address(isolate());
  __ mov(r3, Operand(stack_limit));
  __ LoadU64(r3, MemOperand(r3));
  __ CmpU64(backtrack_stackpointer(), r3);
  SafeCall(&stack_overflow_label_, le);
}


void RegExpMacroAssemblerPPC::LoadCurrentCharacterUnchecked(int cp_offset,
                                                            int characters) {
  Register offset = current_input_offset();
  if (cp_offset != 0) {
    // r25 is not being used to store the capture start index at this point.
    if (is_int16(cp_offset * char_size())) {
      __ addi(r25, current_input_offset(), Operand(cp_offset * char_size()));
    } else {
      __ mov(r25, Operand(cp_offset * char_size()));
      __ add(r25, r25, current_input_offset());
    }
    offset = r25;
  }
  // The lwz, stw, lhz, sth instructions can do unaligned accesses, if the CPU
  // and the operating system running on the target allow it.
  // We assume we don't want to do unaligned loads on PPC, so this function
  // must only be used to load a single character at a time.

  __ add(current_character(), end_of_input_address(), offset);
#if V8_TARGET_LITTLE_ENDIAN
  if (mode_ == LATIN1) {
    if (characters == 4) {
      __ lwz(current_character(), MemOperand(current_character()));
    } else if (characters == 2) {
      __ lhz(current_character(), MemOperand(current_character()));
    } else {
      DCHECK_EQ(1, characters);
      __ lbz(current_character(), MemOperand(current_character()));
    }
  } else {
    DCHECK(mode_ == UC16);
    if (characters == 2) {
      __ lwz(current_character(), MemOperand(current_character()));
    } else {
      DCHECK_EQ(1, characters);
      __ lhz(current_character(), MemOperand(current_character()));
    }
  }
#else
  if (mode_ == LATIN1) {
    if (characters == 4) {
      __ lwbrx(current_character(), MemOperand(r0, current_character()));
    } else if (characters == 2) {
      __ lhbrx(current_character(), MemOperand(r0, current_character()));
    } else {
      DCHECK_EQ(1, characters);
      __ lbz(current_character(), MemOperand(current_character()));
    }
  } else {
    DCHECK(mode_ == UC16);
    if (characters == 2) {
      __ lwz(current_character(), MemOperand(current_character()));
      __ rlwinm(current_character(), current_character(), 16, 0, 31);
    } else {
      DCHECK_EQ(1, characters);
      __ lhz(current_character(), MemOperand(current_character()));
    }
  }
#endif
}

#undef __

}  // namespace internal
}  // namespace v8

#endif  //  V8_TARGET_ARCH_PPC64
```