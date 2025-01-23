Response:
My thinking process to analyze the provided assembly code snippet goes like this:

1. **Identify the Architecture and Context:** The filename `builtins-s390.cc` clearly indicates this is assembly code for the s390 architecture within the V8 JavaScript engine. The `builtins` directory suggests these are fundamental, pre-compiled code routines.

2. **Recognize the Function:** The code starts with a function definition: `void Builtins::Generate_JSEntryVariant(MacroAssembler* masm, StackFrame::Type type, Builtin entry_trampoline)`. This immediately tells me it's generating code for a specific entry point into JavaScript execution. The `StackFrame::Type` and `Builtin entry_trampoline` parameters suggest variations in how the entry is set up.

3. **Break Down the Code Blocks:** I'll go through the code block by block, trying to understand the purpose of each section. I look for common assembly patterns and V8-specific idioms.

    * **Stack Manipulation:**  The initial `__ StoreU64(r0, MemOperand(ip));` and `__ push(r9);` are standard stack operations. The subsequent calculations involving `EntryFrameConstants` indicate the setup of a new stack frame.

    * **Pointer Compression:** The `#ifdef V8_COMPRESS_POINTERS_IN_SHARED_CAGE` block deals with pointer compression, a V8 optimization. It loads the cage base register.

    * **Frame Pointer Setup:**  `__ lay(fp, MemOperand(sp, -EntryFrameConstants::kNextFastCallFramePCOffset));` sets up the frame pointer.

    * **JSEntrySP Handling:** The section dealing with `js_entry_sp` checks if this is the outermost JavaScript call and sets the `js_entry_sp` accordingly. This is crucial for tracking the JavaScript call stack.

    * **Invoke and Handler:** The code jumps to an `invoke` label and sets up a `handler_entry`. This strongly suggests exception handling. The `PushStackHandler` and `PopStackHandler` further confirm this.

    * **Function Invocation:** The `__ CallBuiltin(entry_trampoline);` line is the core of the function call. The `entry_trampoline` is passed as a parameter, allowing for different entry points.

    * **Exception Handling:** The `handler_entry` block stores the exception and sets up a return for failure.

    * **Stack Frame Unwinding:**  The code after the `exit` label restores the stack frame, pops saved registers, and prepares for the return. This involves loading callee-saved registers and floating-point registers.

    * **Return:** Finally, the `__ b(r14);` (or `__ b(r3);` on z/OS) performs the actual return.

4. **Identify Key Functionality:** Based on the code blocks, I can infer the main functions:

    * **Setting up the JavaScript entry frame.**
    * **Handling outermost vs. inner JavaScript calls.**
    * **Implementing a try-catch mechanism using stack handlers.**
    * **Calling the actual JavaScript function via a trampoline.**
    * **Handling exceptions thrown during the JavaScript call.**
    * **Restoring the stack frame after the call.**

5. **Connect to JavaScript Concepts:** The code interacts directly with how JavaScript functions are called. The `receiver`, arguments, and `new.target` are all standard JavaScript concepts. The exception handling mechanism maps to JavaScript's `try...catch` blocks.

6. **Consider `.tq` Files:** The prompt mentions `.tq` files. Since this file is `.cc`, it's not a Torque file. Torque files are a higher-level way of generating assembly in V8.

7. **Infer Potential Errors:** The code involves manual stack manipulation, which is prone to errors. Incorrect offsets, missing pushes/pops, or incorrect register usage can lead to crashes or incorrect behavior. Stack overflows are also explicitly handled.

8. **Address the "Part 2 of 5" Instruction:** The prompt explicitly asks to summarize the function of this specific part. This part focuses on the `JSEntryVariant` function, which is a generalized entry point.

9. **Construct the Summary:**  Finally, I synthesize the information gathered into a concise summary, addressing all the points raised in the prompt:

    *  Mentioning the file name and its role as a V8 builtin.
    *  Explaining the purpose of `Generate_JSEntryVariant`.
    *  Listing the key functionalities identified in step 4.
    *  Explaining the lack of `.tq` extension and its implications.
    *  Connecting to JavaScript functionality with examples (even though the provided code doesn't directly execute JS).
    *  Illustrating potential programming errors related to stack manipulation.

This systematic approach, breaking down the code into smaller, understandable parts, helps in grasping the overall functionality and its connection to the broader V8 engine and JavaScript execution.
目录 `v8/src/builtins/s390/builtins-s390.cc` 是 V8 JavaScript 引擎中针对 s390 架构的内置函数实现代码。

**功能归纳 (基于提供的代码片段):**

这部分代码主要实现了 JavaScript 代码进入 V8 引擎时的入口函数 `Generate_JSEntryVariant` 及其相关的辅助函数。 它的核心功能是**建立 JavaScript 执行的初始栈帧，处理异常，并调用实际的 JavaScript 代码执行逻辑**。

**具体功能拆解:**

1. **`Generate_JSEntryVariant(MacroAssembler* masm, StackFrame::Type type, Builtin entry_trampoline)`:**
   - **作为 JavaScript 代码的入口点:**  当 C++ 代码需要调用 JavaScript 函数时，会通过这个函数进入 V8 的执行环境。
   - **设置初始栈帧:** 它负责在栈上分配空间，保存必要的寄存器（如返回地址、帧指针等），并设置栈帧类型 (通过 `StackFrame::Type` 参数区分是普通调用还是构造函数调用)。
   - **处理指针压缩 (可选):**  如果启用了指针压缩，会初始化指针压缩的基地址寄存器。
   - **区分最外层和内部 JavaScript 调用:**  它会检查当前是否是最外层的 JavaScript 调用，并设置 `js_entry_sp` (JavaScript Entry Stack Pointer) 用于跟踪 JavaScript 的调用栈。
   - **建立异常处理机制:** 它会设置一个假的 try-catch 结构，以便在 JavaScript 代码执行过程中发生异常时能够捕获。
   - **调用 JavaScript 执行跳板 (trampoline):**  通过 `entry_trampoline` 参数指定的内置函数（例如 `kJSEntryTrampoline` 或 `kJSConstructEntryTrampoline`）来实际执行 JavaScript 代码。
   - **处理异常返回:** 如果 JavaScript 代码执行过程中抛出异常，控制权会返回到 `handler_entry` 标签处，这里会将异常信息存储起来并返回失败标记。
   - **恢复栈帧:**  在 JavaScript 代码执行完毕后（无论成功还是异常），它会恢复之前保存的寄存器，清理栈帧，并返回到调用方。

2. **`Generate_JSEntry(MacroAssembler* masm)`:** 调用 `Generate_JSEntryVariant`，用于生成普通函数调用的入口代码，使用 `Builtin::kJSEntryTrampoline` 作为执行跳板。

3. **`Generate_JSConstructEntry(MacroAssembler* masm)`:**  调用 `Generate_JSEntryVariant`，用于生成构造函数调用的入口代码，使用 `Builtin::kJSConstructEntryTrampoline` 作为执行跳板。

4. **`Generate_JSRunMicrotasksEntry(MacroAssembler* masm)`:** 调用 `Generate_JSEntryVariant`，用于生成执行微任务的入口代码，使用 `Builtin::kRunMicrotasksTrampoline` 作为执行跳板。

**关于 `.tq` 结尾：**

代码以 `.cc` 结尾，所以它不是 V8 Torque 源代码。 Torque 是一种 V8 内部的 DSL (Domain Specific Language)，用于更安全、更易于维护的方式生成汇编代码。 如果文件以 `.tq` 结尾，那么它的确是 Torque 源代码。

**与 JavaScript 功能的关系及示例：**

`v8/src/builtins/s390/builtins-s390.cc` 中 `Generate_JSEntryVariant` 实现的功能是 JavaScript 代码执行的基石。 任何 JavaScript 函数的调用最终都会通过这些入口点进入 V8 的执行流程。

**JavaScript 示例:**

```javascript
function myFunction(a, b) {
  return a + b;
}

myFunction(5, 3); // 当执行这行代码时，V8 内部会调用相应的 JSEntry 函数
```

在这个例子中，当 JavaScript 引擎执行 `myFunction(5, 3)` 时，会触发一个从 C++ 到 JavaScript 的调用。  `Generate_JSEntry` 或类似的函数会被调用，它会：

1. 设置栈帧，准备执行环境。
2. 将 `myFunction`、`5` 和 `3` 等参数传递给 JavaScript 执行逻辑。
3. 执行 `myFunction` 内部的 `return a + b;` 代码。
4. 将结果返回给 C++ 调用方。

**代码逻辑推理 (假设输入与输出):**

假设我们有一个简单的 JavaScript 函数：

```javascript
function add(x, y) {
  return x + y;
}
```

**假设输入 (当从 C++ 调用 `add(2, 3)` 时):**

* **`masm`:** 指向当前 MacroAssembler 对象的指针。
* **`type`:**  `StackFrame::ENTRY` (因为是普通函数调用)。
* **`entry_trampoline`:** 指向 `Builtin::kJSEntryTrampoline` 的枚举值。
* **寄存器状态 (简化):**
    * `r0`: 指向某些需要存储的数据 (根据代码来看)。
    * `ip`:  可能指向某些内存地址。
    * `sp`: 当前栈顶指针。
    * 其他寄存器可能包含函数对象、接收者、参数等信息。

**可能的输出 (执行 `Generate_JSEntryVariant` 后的状态变化):**

* **栈状态:**
    * 新的栈帧被分配，包含了返回地址、帧指针、函数参数等信息。
    * 如果是最外层调用，`js_entry_sp` 会被设置。
    * 异常处理相关的栈结构会被建立。
* **寄存器状态:**
    * `fp`: 指向新的栈帧的基地址。
    * `scrach` (r8):  可能被用来存储帧类型信息。
    * 其他寄存器可能被用来传递参数给 `entry_trampoline`。
* **控制流:** 程序会跳转到 `invoke` 标签，然后通过 `__ CallBuiltin(entry_trampoline);` 跳转到 `kJSEntryTrampoline` 的实现。

**用户常见的编程错误 (与这类代码相关的潜在风险，并非指使用这段内置函数的错误):**

由于这段代码是 V8 引擎的内部实现，普通 JavaScript 开发者不会直接编写或修改它。 然而，理解其背后的概念有助于理解 V8 的工作原理，并避免一些可能导致性能问题或错误的 JavaScript 代码模式：

1. **栈溢出:**  如果 JavaScript 代码中存在无限递归或者调用栈过深，可能会导致栈溢出。  `Generate_JSEntryVariant` 中虽然没有直接处理 JavaScript 级别的栈溢出，但它会设置好栈帧，为后续的栈溢出检测和处理奠定基础。
2. **类型错误:** JavaScript 是一种动态类型语言，类型错误可能在运行时发生。 当 JavaScript 代码抛出类型错误等异常时，`Generate_JSEntryVariant` 中设置的异常处理机制会捕获这些错误。
3. **内存泄漏 (间接相关):** 虽然这段代码本身不直接涉及内存分配和释放，但如果 JavaScript 代码创建了大量对象但没有及时释放，可能会导致内存泄漏。 理解 V8 的执行入口有助于理解对象生命周期管理的重要性。

**功能归纳:**

总而言之，`v8/src/builtins/s390/builtins-s390.cc` 的这部分代码是 s390 架构下 V8 引擎中用于处理 JavaScript 代码入口的关键组件。 它负责搭建 JavaScript 执行所需的栈环境，处理潜在的异常，并将控制权转移到实际的 JavaScript 代码执行逻辑。 它是 V8 引擎能够执行 JavaScript 代码的基础。

### 提示词
```
这是目录为v8/src/builtins/s390/builtins-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/s390/builtins-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
__ StoreU64(r0, MemOperand(ip));
  __ push(r9);

#ifdef V8_COMPRESS_POINTERS_IN_SHARED_CAGE
  // Initialize the pointer cage base register.
  __ LoadRootRelative(kPtrComprCageBaseRegister,
                      IsolateData::cage_base_offset());
#endif

  Register scrach = r8;

  // Set up frame pointer for the frame to be pushed.
  __ lay(fp, MemOperand(sp, -EntryFrameConstants::kNextFastCallFramePCOffset));
  pushed_stack_space +=
      EntryFrameConstants::kNextFastCallFramePCOffset - kSystemPointerSize;

  // If this is the outermost JS call, set js_entry_sp value.
  Label non_outermost_js;
  ExternalReference js_entry_sp = ExternalReference::Create(
      IsolateAddressId::kJSEntrySPAddress, masm->isolate());
  __ Move(r7, js_entry_sp);
  __ LoadAndTestP(scrach, MemOperand(r7));
  __ bne(&non_outermost_js, Label::kNear);
  __ StoreU64(fp, MemOperand(r7));
  __ mov(scrach, Operand(StackFrame::OUTERMOST_JSENTRY_FRAME));
  Label cont;
  __ b(&cont, Label::kNear);
  __ bind(&non_outermost_js);
  __ mov(scrach, Operand(StackFrame::INNER_JSENTRY_FRAME));

  __ bind(&cont);
  __ push(scrach);  // frame-type

  // Jump to a faked try block that does the invoke, with a faked catch
  // block that sets the exception.
  __ b(&invoke, Label::kNear);

  __ bind(&handler_entry);

  // Store the current pc as the handler offset. It's used later to create the
  // handler table.
  masm->isolate()->builtins()->SetJSEntryHandlerOffset(handler_entry.pos());

  // Caught exception: Store result (exception) in the exception
  // field in the JSEnv and return a failure sentinel.  Coming in here the
  // fp will be invalid because the PushStackHandler below sets it to 0 to
  // signal the existence of the JSEntry frame.
  __ Move(scrach, ExternalReference::Create(IsolateAddressId::kExceptionAddress,
                                            masm->isolate()));

  __ StoreU64(r2, MemOperand(scrach));
  __ LoadRoot(r2, RootIndex::kException);
  __ b(&exit, Label::kNear);

  // Invoke: Link this frame into the handler chain.
  __ bind(&invoke);
  // Must preserve r2-r6.
  __ PushStackHandler();
  // If an exception not caught by another handler occurs, this handler
  // returns control to the code after the b(&invoke) above, which
  // restores all kCalleeSaved registers (including cp and fp) to their
  // saved values before returning a failure to C.

  // Invoke the function by calling through JS entry trampoline builtin.
  // Notice that we cannot store a reference to the trampoline code directly in
  // this stub, because runtime stubs are not traversed when doing GC.

  // Invoke the function by calling through JS entry trampoline builtin and
  // pop the faked function when we return.
  USE(pushed_stack_space);
  DCHECK_EQ(kPushedStackSpace, pushed_stack_space);
  __ CallBuiltin(entry_trampoline);

  // Unlink this frame from the handler chain.
  __ PopStackHandler();
  __ bind(&exit);  // r2 holds result

  // Check if the current stack frame is marked as the outermost JS frame.
  Label non_outermost_js_2;
  __ pop(r7);
  __ CmpS64(r7, Operand(StackFrame::OUTERMOST_JSENTRY_FRAME));
  __ bne(&non_outermost_js_2, Label::kNear);
  __ mov(scrach, Operand::Zero());
  __ Move(r7, js_entry_sp);
  __ StoreU64(scrach, MemOperand(r7));
  __ bind(&non_outermost_js_2);

  // Restore the top frame descriptors from the stack.
  __ pop(r5);
  __ LoadIsolateField(scrach, IsolateFieldId::kFastCCallCallerPC);
  __ StoreU64(r5, MemOperand(scrach));

  __ pop(r5);
  __ LoadIsolateField(scrach, IsolateFieldId::kFastCCallCallerFP);
  __ StoreU64(r5, MemOperand(scrach));

  __ pop(r5);
  __ Move(scrach, ExternalReference::Create(IsolateAddressId::kCEntryFPAddress,
                                            masm->isolate()));
  __ StoreU64(r5, MemOperand(scrach));

  // Reset the stack to the callee saved registers.
  __ lay(sp, MemOperand(sp, -EntryFrameConstants::kNextExitFrameFPOffset));

  // Reload callee-saved preserved regs, return address reg (r14) and sp
  __ LoadMultipleP(r6, sp, MemOperand(sp, 0));
  __ la(sp, MemOperand(sp, 10 * kSystemPointerSize));

  // 64bit ABI requires f8 to f15 be saved
  __ ld(d8, MemOperand(sp));
  __ ld(d9, MemOperand(sp, 1 * kDoubleSize));
  __ ld(d10, MemOperand(sp, 2 * kDoubleSize));
  __ ld(d11, MemOperand(sp, 3 * kDoubleSize));
  __ ld(d12, MemOperand(sp, 4 * kDoubleSize));
  __ ld(d13, MemOperand(sp, 5 * kDoubleSize));
  __ ld(d14, MemOperand(sp, 6 * kDoubleSize));
  __ ld(d15, MemOperand(sp, 7 * kDoubleSize));
  __ la(sp, MemOperand(sp, 8 * kDoubleSize));

#if V8_OS_ZOS
  // On z/OS, the return register is r3
  __ mov(r3, r2);
  // Restore r4 - r15 from Stack
  __ LoadMultipleP(r4, sp, MemOperand(sp, kStackPointerBias));
  __ b(r7);
#else
  __ b(r14);
#endif
}

}  // namespace

void Builtins::Generate_JSEntry(MacroAssembler* masm) {
  Generate_JSEntryVariant(masm, StackFrame::ENTRY, Builtin::kJSEntryTrampoline);
}

void Builtins::Generate_JSConstructEntry(MacroAssembler* masm) {
  Generate_JSEntryVariant(masm, StackFrame::CONSTRUCT_ENTRY,
                          Builtin::kJSConstructEntryTrampoline);
}

void Builtins::Generate_JSRunMicrotasksEntry(MacroAssembler* masm) {
  Generate_JSEntryVariant(masm, StackFrame::ENTRY,
                          Builtin::kRunMicrotasksTrampoline);
}

static void Generate_JSEntryTrampolineHelper(MacroAssembler* masm,
                                             bool is_construct) {
  // Called from Generate_JS_Entry
  // r3: new.target
  // r4: function
  // r5: receiver
  // r6: argc
  // [fp + kPushedStackSpace + 20 * kSystemPointerSize]: argv
  // r0,r2,r7-r8, cp may be clobbered

  __ mov(r2, r6);
  // Load argv from the stack.
  __ LoadU64(
      r6, MemOperand(fp, kPushedStackSpace + EntryFrameConstants::kArgvOffset));

  // r2: argc
  // r3: new.target
  // r4: function
  // r5: receiver
  // r6: argv

  // Enter an internal frame.
  {
    // FrameScope ends up calling MacroAssembler::EnterFrame here
    FrameScope scope(masm, StackFrame::INTERNAL);

    // Setup the context (we need to use the caller context from the isolate).
    ExternalReference context_address = ExternalReference::Create(
        IsolateAddressId::kContextAddress, masm->isolate());
    __ Move(cp, context_address);
    __ LoadU64(cp, MemOperand(cp));

    // Push the function
    __ Push(r4);

    // Check if we have enough stack space to push all arguments.
    Label enough_stack_space, stack_overflow;
    __ mov(r7, r2);
    __ StackOverflowCheck(r7, r1, &stack_overflow);
    __ b(&enough_stack_space);
    __ bind(&stack_overflow);
    __ CallRuntime(Runtime::kThrowStackOverflow);
    // Unreachable code.
    __ bkpt(0);

    __ bind(&enough_stack_space);

    // Copy arguments to the stack from argv to sp.
    // The arguments are actually placed in reverse order on sp
    // compared to argv (i.e. arg1 is highest memory in sp).
    // r2: argc
    // r3: function
    // r5: new.target
    // r6: argv, i.e. points to first arg
    // r7: scratch reg to hold scaled argc
    // r8: scratch reg to hold arg handle
    Generate_PushArguments(masm, r6, r2, r1, ArgumentsElementType::kHandle);

    // Push the receiver.
    __ Push(r5);

    // Setup new.target, argc and function.
    __ mov(r5, r3);
    __ mov(r3, r4);
    // r2: argc
    // r3: function
    // r5: new.target

    // Initialize all JavaScript callee-saved registers, since they will be seen
    // by the garbage collector as part of handlers.
    __ LoadRoot(r4, RootIndex::kUndefinedValue);
    __ mov(r6, r4);
    __ mov(r7, r6);
    __ mov(r8, r6);

    // Invoke the code.
    Builtin builtin = is_construct ? Builtin::kConstruct : Builtins::Call();
    __ CallBuiltin(builtin);

    // Exit the JS frame and remove the parameters (except function), and
    // return.
  }
  __ b(r14);

  // r2: result
}

void Builtins::Generate_JSEntryTrampoline(MacroAssembler* masm) {
  Generate_JSEntryTrampolineHelper(masm, false);
}

void Builtins::Generate_JSConstructEntryTrampoline(MacroAssembler* masm) {
  Generate_JSEntryTrampolineHelper(masm, true);
}

void Builtins::Generate_RunMicrotasksTrampoline(MacroAssembler* masm) {
  // This expects two C++ function parameters passed by Invoke() in
  // execution.cc.
  //   r2: root_register_value
  //   r3: microtask_queue

  __ mov(RunMicrotasksDescriptor::MicrotaskQueueRegister(), r3);
  __ TailCallBuiltin(Builtin::kRunMicrotasks);
}

static void LeaveInterpreterFrame(MacroAssembler* masm, Register scratch1,
                                  Register scratch2) {
  Register params_size = scratch1;
  // Get the size of the formal parameters + receiver (in bytes).
  __ LoadU64(params_size,
             MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ LoadU16(params_size,
             FieldMemOperand(params_size, BytecodeArray::kParameterSizeOffset));

  Register actual_params_size = scratch2;
  // Compute the size of the actual parameters + receiver (in bytes).
  __ LoadU64(actual_params_size,
             MemOperand(fp, StandardFrameConstants::kArgCOffset));

  // If actual is bigger than formal, then we should use it to free up the stack
  // arguments.
  Label corrected_args_count;
  __ CmpS64(params_size, actual_params_size);
  __ bge(&corrected_args_count);
  __ mov(params_size, actual_params_size);
  __ bind(&corrected_args_count);

  // Leave the frame (also dropping the register file).
  __ LeaveFrame(StackFrame::INTERPRETED);

  __ DropArguments(params_size);
}

// Advance the current bytecode offset. This simulates what all bytecode
// handlers do upon completion of the underlying operation. Will bail out to a
// label if the bytecode (without prefix) is a return bytecode. Will not advance
// the bytecode offset if the current bytecode is a JumpLoop, instead just
// re-executing the JumpLoop to jump to the correct bytecode.
static void AdvanceBytecodeOffsetOrReturn(MacroAssembler* masm,
                                          Register bytecode_array,
                                          Register bytecode_offset,
                                          Register bytecode, Register scratch1,
                                          Register scratch2, Label* if_return) {
  Register bytecode_size_table = scratch1;
  Register scratch3 = bytecode;

  // The bytecode offset value will be increased by one in wide and extra wide
  // cases. In the case of having a wide or extra wide JumpLoop bytecode, we
  // will restore the original bytecode. In order to simplify the code, we have
  // a backup of it.
  Register original_bytecode_offset = scratch2;
  DCHECK(!AreAliased(bytecode_array, bytecode_offset, bytecode_size_table,
                     bytecode, original_bytecode_offset));
  __ Move(bytecode_size_table,
          ExternalReference::bytecode_size_table_address());
  __ Move(original_bytecode_offset, bytecode_offset);

  // Check if the bytecode is a Wide or ExtraWide prefix bytecode.
  Label process_bytecode, extra_wide;
  static_assert(0 == static_cast<int>(interpreter::Bytecode::kWide));
  static_assert(1 == static_cast<int>(interpreter::Bytecode::kExtraWide));
  static_assert(2 == static_cast<int>(interpreter::Bytecode::kDebugBreakWide));
  static_assert(3 ==
                static_cast<int>(interpreter::Bytecode::kDebugBreakExtraWide));
  __ CmpS64(bytecode, Operand(0x3));
  __ bgt(&process_bytecode);
  __ tmll(bytecode, Operand(0x1));
  __ bne(&extra_wide);

  // Load the next bytecode and update table to the wide scaled table.
  __ AddS64(bytecode_offset, bytecode_offset, Operand(1));
  __ LoadU8(bytecode, MemOperand(bytecode_array, bytecode_offset));
  __ AddS64(bytecode_size_table, bytecode_size_table,
            Operand(kByteSize * interpreter::Bytecodes::kBytecodeCount));
  __ b(&process_bytecode);

  __ bind(&extra_wide);
  // Load the next bytecode and update table to the extra wide scaled table.
  __ AddS64(bytecode_offset, bytecode_offset, Operand(1));
  __ LoadU8(bytecode, MemOperand(bytecode_array, bytecode_offset));
  __ AddS64(bytecode_size_table, bytecode_size_table,
            Operand(2 * kByteSize * interpreter::Bytecodes::kBytecodeCount));

  // Load the size of the current bytecode.
  __ bind(&process_bytecode);

  // Bailout to the return label if this is a return bytecode.
#define JUMP_IF_EQUAL(NAME)                                             \
  __ CmpS64(bytecode,                                                   \
            Operand(static_cast<int>(interpreter::Bytecode::k##NAME))); \
  __ beq(if_return);
  RETURN_BYTECODE_LIST(JUMP_IF_EQUAL)
#undef JUMP_IF_EQUAL

  // If this is a JumpLoop, re-execute it to perform the jump to the beginning
  // of the loop.
  Label end, not_jump_loop;
  __ CmpS64(bytecode,
            Operand(static_cast<int>(interpreter::Bytecode::kJumpLoop)));
  __ bne(&not_jump_loop);
  // We need to restore the original bytecode_offset since we might have
  // increased it to skip the wide / extra-wide prefix bytecode.
  __ Move(bytecode_offset, original_bytecode_offset);
  __ b(&end);

  __ bind(&not_jump_loop);
  // Otherwise, load the size of the current bytecode and advance the offset.
  __ LoadU8(scratch3, MemOperand(bytecode_size_table, bytecode));
  __ AddS64(bytecode_offset, bytecode_offset, scratch3);

  __ bind(&end);
}

// static
void Builtins::Generate_BaselineOutOfLinePrologue(MacroAssembler* masm) {
  // UseScratchRegisterScope temps(masm);
  // Need a few extra registers
  // temps.Include(r8, r9);

  auto descriptor =
      Builtins::CallInterfaceDescriptorFor(Builtin::kBaselineOutOfLinePrologue);
  Register closure = descriptor.GetRegisterParameter(
      BaselineOutOfLinePrologueDescriptor::kClosure);
  // Load the feedback cell and vector from the closure.
  Register feedback_cell = r6;
  Register feedback_vector = ip;
  __ LoadTaggedField(feedback_cell,
                     FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
  __ LoadTaggedField(
      feedback_vector,
      FieldMemOperand(feedback_cell, FeedbackCell::kValueOffset));
  __ AssertFeedbackVector(feedback_vector, r1);

  // Check for an tiering state.
  Label flags_need_processing;
  Register flags = r8;
  {
    __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
        flags, feedback_vector, CodeKind::BASELINE, &flags_need_processing);
  }

  {
    UseScratchRegisterScope temps(masm);
    ResetFeedbackVectorOsrUrgency(masm, feedback_vector, r1);
  }

  // Increment invocation count for the function.
  {
    Register invocation_count = r1;
    __ LoadU32(invocation_count,
               FieldMemOperand(feedback_vector,
                               FeedbackVector::kInvocationCountOffset));
    __ AddU32(invocation_count, Operand(1));
    __ StoreU32(invocation_count,
                FieldMemOperand(feedback_vector,
                                FeedbackVector::kInvocationCountOffset));
  }

  FrameScope frame_scope(masm, StackFrame::MANUAL);
  {
    ASM_CODE_COMMENT_STRING(masm, "Frame Setup");
    // Normally the first thing we'd do here is Push(lr, fp), but we already
    // entered the frame in BaselineCompiler::Prologue, as we had to use the
    // value lr before the call to this BaselineOutOfLinePrologue builtin.

    Register callee_context = descriptor.GetRegisterParameter(
        BaselineOutOfLinePrologueDescriptor::kCalleeContext);
    Register callee_js_function = descriptor.GetRegisterParameter(
        BaselineOutOfLinePrologueDescriptor::kClosure);
    ResetJSFunctionAge(masm, callee_js_function, r1, r0);
    __ Push(callee_context, callee_js_function);
    DCHECK_EQ(callee_js_function, kJavaScriptCallTargetRegister);
    DCHECK_EQ(callee_js_function, kJSFunctionRegister);

    Register argc = descriptor.GetRegisterParameter(
        BaselineOutOfLinePrologueDescriptor::kJavaScriptCallArgCount);
    // We'll use the bytecode for both code age/OSR resetting, and pushing onto
    // the frame, so load it into a register.
    Register bytecodeArray = descriptor.GetRegisterParameter(
        BaselineOutOfLinePrologueDescriptor::kInterpreterBytecodeArray);

    __ Push(argc, bytecodeArray);

    if (v8_flags.debug_code) {
      Register scratch = r1;
      __ CompareObjectType(feedback_vector, scratch, scratch,
                           FEEDBACK_VECTOR_TYPE);
      __ Assert(eq, AbortReason::kExpectedFeedbackVector);
    }
    __ Push(feedback_cell);
    __ Push(feedback_vector);
  }

  Label call_stack_guard;
  Register frame_size = descriptor.GetRegisterParameter(
      BaselineOutOfLinePrologueDescriptor::kStackFrameSize);
  {
    ASM_CODE_COMMENT_STRING(masm, "Stack/interrupt check");
    // Stack check. This folds the checks for both the interrupt stack limit
    // check and the real stack limit into one by just checking for the
    // interrupt limit. The interrupt limit is either equal to the real stack
    // limit or tighter. By ensuring we have space until that limit after
    // building the frame we can quickly precheck both at once.

    Register sp_minus_frame_size = r1;
    Register interrupt_limit = r0;
    __ SubS64(sp_minus_frame_size, sp, frame_size);
    __ LoadStackLimit(interrupt_limit, StackLimitKind::kInterruptStackLimit);
    __ CmpU64(sp_minus_frame_size, interrupt_limit);
    __ blt(&call_stack_guard);
  }

  // Do "fast" return to the caller pc in lr.
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
  __ Ret();

  __ bind(&flags_need_processing);
  {
    ASM_CODE_COMMENT_STRING(masm, "Optimized marker check");

    // Drop the frame created by the baseline call.
    __ Pop(r14, fp);
    __ OptimizeCodeOrTailCallOptimizedCodeSlot(flags, feedback_vector);
    __ Trap();
  }

  __ bind(&call_stack_guard);
  {
    ASM_CODE_COMMENT_STRING(masm, "Stack/interrupt call");
    FrameScope frame_scope(masm, StackFrame::INTERNAL);
    // Save incoming new target or generator
    __ Push(kJavaScriptCallNewTargetRegister);
    __ SmiTag(frame_size);
    __ Push(frame_size);
    __ CallRuntime(Runtime::kStackGuardWithGap);
    __ Pop(kJavaScriptCallNewTargetRegister);
  }

  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
  __ Ret();
}

// static
void Builtins::Generate_BaselineOutOfLinePrologueDeopt(MacroAssembler* masm) {
  // We're here because we got deopted during BaselineOutOfLinePrologue's stack
  // check. Undo all its frame creation and call into the interpreter instead.

  // Drop the feedback vector, the bytecode offset (was the feedback vector but
  // got replaced during deopt) and bytecode array.
  __ Drop(3);

  // Context, closure, argc.
  __ Pop(kContextRegister, kJavaScriptCallTargetRegister,
         kJavaScriptCallArgCountRegister);

  // Drop frame pointer
  __ LeaveFrame(StackFrame::BASELINE);

  // Enter the interpreter.
  __ TailCallBuiltin(Builtin::kInterpreterEntryTrampoline);
}

// Generate code for entering a JS function with the interpreter.
// On entry to the function the receiver and arguments have been pushed on the
// stack left to right.
//
// The live registers are:
//   o r2: actual argument count
//   o r3: the JS function object being called.
//   o r5: the incoming new target or generator object
//   o cp: our context
//   o pp: the caller's constant pool pointer (if enabled)
//   o fp: the caller's frame pointer
//   o sp: stack pointer
//   o lr: return address
//
// The function builds an interpreter frame.  See InterpreterFrameConstants in
// frame-constants.h for its layout.
void Builtins::Generate_InterpreterEntryTrampoline(
    MacroAssembler* masm, InterpreterEntryTrampolineMode mode) {
  Register closure = r3;

  // Get the bytecode array from the function object and load it into
  // kInterpreterBytecodeArrayRegister.
  __ LoadTaggedField(
      r6, FieldMemOperand(closure, JSFunction::kSharedFunctionInfoOffset));
  ResetSharedFunctionInfoAge(masm, r6, ip);

  // The bytecode array could have been flushed from the shared function info,
  // if so, call into CompileLazy.
  Label is_baseline, compile_lazy;
  GetSharedFunctionInfoBytecodeOrBaseline(masm, r6,
                                          kInterpreterBytecodeArrayRegister, ip,
                                          &is_baseline, &compile_lazy);

  Label push_stack_frame;
  Register feedback_vector = r4;
  __ LoadFeedbackVector(feedback_vector, closure, r6, &push_stack_frame);

#ifndef V8_JITLESS
  // If feedback vector is valid, check for optimized code and update invocation
  // count.

  Register flags = r6;
  Label flags_need_processing;
  __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
      flags, feedback_vector, CodeKind::INTERPRETED_FUNCTION,
      &flags_need_processing);

    ResetFeedbackVectorOsrUrgency(masm, feedback_vector, r1);

  // Increment invocation count for the function.
  __ LoadS32(r1, FieldMemOperand(feedback_vector,
                                 FeedbackVector::kInvocationCountOffset));
  __ AddS64(r1, r1, Operand(1));
  __ StoreU32(r1, FieldMemOperand(feedback_vector,
                                  FeedbackVector::kInvocationCountOffset));

  // Open a frame scope to indicate that there is a frame on the stack.  The
  // MANUAL indicates that the scope shouldn't actually generate code to set up
  // the frame (that is done below).

#else
  // Note: By omitting the above code in jitless mode we also disable:
  // - kFlagsLogNextExecution: only used for logging/profiling; and
  // - kInvocationCountOffset: only used for tiering heuristics and code
  //   coverage.
#endif  // !V8_JITLESS

  __ bind(&push_stack_frame);
  FrameScope frame_scope(masm, StackFrame::MANUAL);
  __ PushStandardFrame(closure);

  // Load the initial bytecode offset.
  __ mov(kInterpreterBytecodeOffsetRegister,
         Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));

  // Push bytecode array and Smi tagged bytecode array offset.
  __ SmiTag(r0, kInterpreterBytecodeOffsetRegister);
  __ Push(kInterpreterBytecodeArrayRegister, r0, feedback_vector);

  // Allocate the local and temporary register file on the stack.
  Label stack_overflow;
  {
    // Load frame size (word) from the BytecodeArray object.
    __ LoadU32(r4, FieldMemOperand(kInterpreterBytecodeArrayRegister,
                                   BytecodeArray::kFrameSizeOffset));

    // Do a stack check to ensure we don't go over the limit.
    __ SubS64(r8, sp, r4);
    __ CmpU64(r8, __ StackLimitAsMemOperand(StackLimitKind::kRealStackLimit));
    __ blt(&stack_overflow);

    // If ok, push undefined as the initial value for all register file entries.
    // TODO(rmcilroy): Consider doing more than one push per loop iteration.
    Label loop, no_args;
    __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
    __ ShiftRightU64(r4, r4, Operand(kSystemPointerSizeLog2));
    __ LoadAndTestP(r4, r4);
    __ beq(&no_args);
    __ mov(r1, r4);
    __ bind(&loop);
    __ push(kInterpreterAccumulatorRegister);
    __ SubS64(r1, Operand(1));
    __ bne(&loop);
    __ bind(&no_args);
  }

  // If the bytecode array has a valid incoming new target or generator object
  // register, initialize it with incoming value which was passed in r5.
  Label no_incoming_new_target_or_generator_register;
  __ LoadS32(r8,
             FieldMemOperand(
                 kInterpreterBytecodeArrayRegister,
                 BytecodeArray::kIncomingNewTargetOrGeneratorRegisterOffset));
  __ CmpS64(r8, Operand::Zero());
  __ beq(&no_incoming_new_target_or_generator_register);
  __ ShiftLeftU64(r8, r8, Operand(kSystemPointerSizeLog2));
  __ StoreU64(r5, MemOperand(fp, r8));
  __ bind(&no_incoming_new_target_or_generator_register);

  // Perform interrupt stack check.
  // TODO(solanes): Merge with the real stack limit check above.
  Label stack_check_interrupt, after_stack_check_interrupt;
  __ LoadU64(r0,
             __ StackLimitAsMemOperand(StackLimitKind::kInterruptStackLimit));
  __ CmpU64(sp, r0);
  __ blt(&stack_check_interrupt);
  __ bind(&after_stack_check_interrupt);

  // The accumulator is already loaded with undefined.

  // Load the dispatch table into a register and dispatch to the bytecode
  // handler at the current bytecode offset.
  Label do_dispatch;
  __ bind(&do_dispatch);
  __ Move(
      kInterpreterDispatchTableRegister,
      ExternalReference::interpreter_dispatch_table_address(masm->isolate()));

  __ LoadU8(r5, MemOperand(kInterpreterBytecodeArrayRegister,
                           kInterpreterBytecodeOffsetRegister));
  __ ShiftLeftU64(r5, r5, Operand(kSystemPointerSizeLog2));
  __ LoadU64(kJavaScriptCallCodeStartRegister,
             MemOperand(kInterpreterDispatchTableRegister, r5));
  __ Call(kJavaScriptCallCodeStartRegister);

  __ RecordComment("--- InterpreterEntryReturnPC point ---");
  if (mode == InterpreterEntryTrampolineMode::kDefault) {
    masm->isolate()->heap()->SetInterpreterEntryReturnPCOffset(
        masm->pc_offset());
  } else {
    DCHECK_EQ(mode, InterpreterEntryTrampolineMode::kForProfiling);
    // Both versions must be the same up to this point otherwise the builtins
    // will not be interchangable.
    CHECK_EQ(
        masm->isolate()->heap()->interpreter_entry_return_pc_offset().value(),
        masm->pc_offset());
  }

  // Any returns to the entry trampoline are either due to the return bytecode
  // or the interpreter tail calling a builtin and then a dispatch.

  // Get bytecode array and bytecode offset from the stack frame.
  __ LoadU64(kInterpreterBytecodeArrayRegister,
             MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ LoadU64(kInterpreterBytecodeOffsetRegister,
             MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ SmiUntag(kInterpreterBytecodeOffsetRegister);

  // Either return, or advance to the next bytecode and dispatch.
  Label do_return;
  __ LoadU8(r3, MemOperand(kInterpreterBytecodeArrayRegister,
                           kInterpreterBytecodeOffsetRegister));
  AdvanceBytecodeOffsetOrReturn(masm, kInterpreterBytecodeArrayRegister,
                                kInterpreterBytecodeOffsetRegister, r3, r4, r5,
                                &do_return);
  __ b(&do_dispatch);

  __ bind(&do_return);
  // The return value is in r2.
  LeaveInterpreterFrame(masm, r4, r6);
  __ Ret();

  __ bind(&stack_check_interrupt);
  // Modify the bytecode offset in the stack to be kFunctionEntryBytecodeOffset
  // for the call to the StackGuard.
  __ mov(kInterpreterBytecodeOffsetRegister,
         Operand(Smi::FromInt(BytecodeArray::kHeaderSize - kHeapObjectTag +
                              kFunctionEntryBytecodeOffset)));
  __ StoreU64(kInterpreterBytecodeOffsetRegister,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ CallRuntime(Runtime::kStackGuard);

  // After the call, restore the bytecode array, bytecode offset and accumulator
  // registers again. Also, restore the bytecode offset in the stack to its
  // previous value.
  __ LoadU64(kInterpreterBytecodeArrayRegister,
             MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ mov(kInterpreterBytecodeOffsetRegister,
         Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);

  __ SmiTag(r0, kInterpreterBytecodeOffsetRegister);
  __ StoreU64(r0,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

  __ jmp(&after_stack_check_interrupt);

#ifndef V8_JITLESS
  __ bind(&flags_need_processing);
  __ OptimizeCodeOrTailCallOptimizedCodeSlot(flags, feedback_vector);

  __ bind(&is_baseline);
  {
    // Load the feedback vector from the closure.
    __ LoadTaggedField(
        feedback_vector,
        FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
    __ LoadTaggedField(
        feedback_vector,
        FieldMemOperand(feedback_vector, FeedbackCell::kValueOffset));

    Label install_baseline_code;
    // Check if feedback vector is valid. If not, call prepare for baseline to
    // allocate it.
    __ LoadTaggedField(
        ip, FieldMemOperand(feedback_vector, HeapObject::kMapOffset));
    __ LoadU16(ip, FieldMemOperand(ip, Map::kInstanceTypeOffset));
    __ CmpS32(ip, Operand(FEEDBACK_VECTOR_TYPE));
    __ b(ne, &install_baseline_code);

    // Check for an tiering state.
    __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
        flags, feedback_vector, CodeKind::BASELINE, &flags_need_processing);

#ifndef V8_ENABLE_LEAPTIERING
    // TODO(olivf, 42204201): This fastcase is difficult to support with the
    // sandbox as it requires getting write access to the dispatch table. See
    // `JSFunction::UpdateCode`. We might want to remove it for all
    // configurations as it does not seem to be performance sensitive.

    // Load the baseline code into the closure.
    __ mov(r4, kInterpreterBytecodeArrayRegister);
    static_assert(kJavaScriptCallCodeStartRegister == r4, "ABI mismatch");
    __ ReplaceClosureCodeWithOptimizedCode(r4, closure, ip, r1);
    __ JumpCodeObject(r4);

#endif  // V8_ENABLE_LEAPTIERING

    __ bind(&install_baseline_code);
    __ GenerateTailCallToReturnedCode(Runtime::kInstallBaselineCode);
  }
#endif  // !V8_JITLESS

  __ bind(&compile_lazy);
  __ GenerateTailCallToReturnedCode(Runtime::kCompileLazy);

  __ bind(&stack_overflow);
  __ CallRuntime(Runtime::kThrowStackOverflow);
  __ bkpt(0);  // Should not return.
}

static void GenerateInterpreterPushArgs(MacroAssembler* masm, Register num_args,
                                        Register start_address,
                                        Register scratch) {
  ASM_CODE_COMMENT(masm);
  __ SubS64(scratch, num_args, Operand(1));
  __ ShiftLeftU64(scratch, scratch, Operand(kSystemPointerSizeLog2));
  __ SubS64(start_address, start_address, scratch);
  // Push the arguments.
  __ PushArray(start_address, num_args, r1, scratch,
               MacroAssembler::PushArrayOrder::kReverse);
}

// static
void Builtins::Generate_InterpreterPushArgsThenCallImpl(
    MacroAssembler* masm, ConvertReceiverMode receiver_mode,
    InterpreterPushArgsMode mode) {
  DCHECK(mode != InterpreterPushArgsMode::kArrayFunction);
  // ----------- S t a t e -------------
  //  -- r2 : the number of arguments
  //  -- r4 : the address of the first argument to be pushed. Subsequent
  //          arguments should be consecutive above this, in the same order as
  //          they are to be pushed onto the stack.
  //  -- r3 : the target to call (can be any Object).
  // -----------------------------------
  Label stack_overflow;
  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // The spread argument should not be pushed.
    __ SubS64(r2, r2, Operand(1));
  }

  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    __ SubS64(r5, r2, Operand(kJSArgcReceiverSlots));
  } else {
    __ mov(r5, r2);
  }

  __ StackOverflowCheck(r5, ip, &stack_overflow);

  // Push the arguments.
  GenerateInterpreterPushArgs(masm, r5, r4, r6);

  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    __ PushRoot(RootIndex::kUndefinedValue);
  }

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Pass the spread in the register r2.
    // r2 already points to the penultimate argument, the spread
    // lies in the next interpreter register.
    __ LoadU64(r4, MemOperand(r4, -kSystemPointerSize));
  }

  // Call the target.
  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    __ TailCallBuiltin(Builtin::kCallWithSpread);
  } else {
    __ TailCallBuiltin(Builtins::Call(receiver_mode));
  }

  __ bind(&stack_overflow);
  {
    __ TailCallRuntime(Runtime::kThrowStackOverflow);
    // Unreachable Code.
    __ bkpt(0);
  }
}

// static
void Builtins::Generate_InterpreterPushArgsThenConstructImpl(
    MacroAssembler* masm, InterpreterPushArgsMode mode) {
  // ----------- S t a t e -------------
  // -- r2 : argument count
  // -- r5 : new target
  // -- r3 : constructor to call
  // -- r4 : allocation site feedback if available, undefined otherwise.
  // -- r6 : address of the first argument
  // -----------------------------------
  Label stack_overflow;
  __ StackOverflowCheck(r2, ip, &stack_overflow);

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // The spread argument should not be pushed.
    __ SubS64(r2, r2, Operand(1));
  }

  Register argc_without_receiver = ip;
  __ SubS64(argc_without_receiver, r2, Operand(kJSArgcReceiverSlots));
  // Push the arguments. r4 and r5 will be modified.
  GenerateInterpreterPushArgs(masm, argc_without_receiver, r6, r7);

  // Push a slot for the receiver to be constructed.
  __ mov(r0, Operand::Zero());
  __ push(r0);

  if (mode == InterpreterPushArgsMode::kWithFi
```