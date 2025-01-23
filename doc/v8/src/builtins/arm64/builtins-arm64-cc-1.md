Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/builtins/arm64/builtins-arm64.cc`.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Purpose:** The filename and the code within suggest this file contains built-in functions for the ARM64 architecture in V8. Built-ins are low-level, performance-critical functions.

2. **Analyze Individual Functions:**  Go through each defined function and understand its role. Look for keywords and patterns:
    * `Generate_JSEntry`, `Generate_JSConstructEntry`, `Generate_JSRunMicrotasksEntry`: These seem to be entry points for JavaScript execution, likely handling function calls and constructor calls. The "Trampoline" suffix suggests a setup or jump mechanism.
    * `Generate_JSEntryTrampolineHelper`: This is a helper function for the above entry points, dealing with argument setup and calling the actual function. Pay attention to stack manipulation (`__Claim`, `__Poke`, `__Str`).
    * `Generate_RunMicrotasksTrampoline`: This deals with running microtasks, which are asynchronous tasks in JavaScript.
    * `LeaveInterpreterFrame`: This function handles exiting the interpreter, cleaning up the stack.
    * `AdvanceBytecodeOffsetOrReturn`:  This is related to the interpreter's execution cycle, advancing to the next instruction or returning. Keywords like "bytecode" are key.
    * `ResetSharedFunctionInfoAge`, `ResetJSFunctionAge`, `ResetFeedbackVectorOsrUrgency`: These functions are related to optimizing code execution. They seem to reset counters or flags associated with functions and feedback vectors.
    * `Generate_BaselineOutOfLinePrologue`:  This is for a specific optimization tier called "Baseline". The "Prologue" means it's the setup code at the beginning of a function. It handles stack checks and invocation counting.
    * `Generate_BaselineOutOfLinePrologueDeopt`: This is the reverse of the prologue, handling deoptimization back to the interpreter.
    * `Generate_InterpreterEntryTrampoline`:  This is the main entry point for executing JavaScript code in the interpreter. It sets up the interpreter frame, handles stack checks, and dispatches to bytecode handlers.
    * `GenerateInterpreterPushArgs`, `Generate_InterpreterPushArgsThenCallImpl`: These functions deal with preparing arguments for a function call within the interpreter. They handle pushing arguments onto the stack.

3. **Group Related Functions:**  Notice that some functions are clearly related:
    * `Generate_JSEntry`, `Generate_JSConstructEntry`, `Generate_JSRunMicrotasksEntry`, and `Generate_JSEntryTrampolineHelper` form a group around entering JavaScript execution.
    * `Generate_BaselineOutOfLinePrologue` and `Generate_BaselineOutOfLinePrologueDeopt` are related to the Baseline optimization tier.
    * `GenerateInterpreterPushArgs` and `Generate_InterpreterPushArgsThenCallImpl` deal with argument handling in the interpreter.

4. **Identify Key Concepts:**  Several important V8 concepts appear repeatedly:
    * **Stack Frames:**  The code heavily manipulates the stack, indicating frame setup and teardown for different execution contexts (entry, internal, interpreted, baseline).
    * **Bytecode:**  The interpreter executes bytecode, and functions like `AdvanceBytecodeOffsetOrReturn` are central to this.
    * **Feedback Vectors:** These are used for optimization, collecting information about how code is executed.
    * **Optimization Tiers:** The code mentions "Baseline," implying different levels of optimization in V8.
    * **Trampolines:** These are small pieces of code used to jump to the actual implementation after some setup.
    * **Runtime Functions:** The code calls `Runtime::k...` functions, which are built-in C++ functions that perform specific tasks.
    * **Stack Checks:** The code includes checks for stack overflow.

5. **Synthesize the Summary:** Combine the information gathered to create a concise overview. Focus on the major functionalities and the relationships between them. Use clear and understandable language, avoiding overly technical jargon where possible. Mention the architecture-specific nature of the code.

6. **Address Specific Instructions:**
    * **.tq extension:**  Note that the file is `.cc`, so it's C++, not Torque.
    * **JavaScript relationship:** Explain how the built-ins relate to JavaScript execution (handling function calls, constructors, etc.). Provide a simple JavaScript example.
    * **Code Logic Inference:** Select a function with clear input/output and provide an example. `Generate_JSEntryTrampolineHelper` is a good choice.
    * **Common Programming Errors:** Think about common errors related to function calls and stack management. Stack overflow is a natural fit.
    * **Part 2 of 7:** Acknowledge this context.

7. **Refine and Organize:** Review the summary for clarity, accuracy, and completeness. Structure it logically with headings and bullet points. Ensure all parts of the prompt are addressed.
这是对 `v8/src/builtins/arm64/builtins-arm64.cc` 源代码的功能归纳，基于提供的代码片段。

**功能归纳:**

这段代码是 V8 JavaScript 引擎在 ARM64 架构上的内置函数实现的一部分。它主要负责处理 JavaScript 代码执行的入口、框架建立、参数传递、以及解释器和优化代码之间的切换。

具体来说，这段代码实现了以下关键功能：

1. **JavaScript 代码入口点 (`Generate_JSEntry`, `Generate_JSConstructEntry`, `Generate_JSRunMicrotasksEntry`):**
   - 定义了 JavaScript 函数调用的标准入口流程，区分了普通函数调用、构造函数调用和运行微任务的入口。
   - 这些入口函数会调用 `Generate_JSEntryVariant` 来进行通用的入口设置。

2. **JavaScript 入口辅助函数 (`Generate_JSEntryTrampolineHelper`):**
   - 负责在进入 JavaScript 函数执行之前进行一系列准备工作，包括：
     - 建立内部帧 (`StackFrame::INTERNAL`).
     - 设置上下文。
     - 在栈上为参数和函数对象分配空间。
     - 将接收者、函数对象和参数复制到栈上。
     - 初始化 JavaScript Callee-saved 寄存器。
     - 调用实际的 JavaScript 函数 (`Builtin::kConstruct` 或 `Builtins::Call()`).
   - 执行完毕后，清理栈帧并返回。

3. **微任务执行入口 (`Generate_RunMicrotasksTrampoline`):**
   - 设置运行微任务所需的参数，并调用 `Builtin::kRunMicrotasks` 内置函数。

4. **解释器帧的离开 (`LeaveInterpreterFrame`):**
   - 清理解释器执行过程中建立的栈帧，包括根据实际参数数量或形式参数数量释放栈空间。

5. **字节码偏移的推进 (`AdvanceBytecodeOffsetOrReturn`):**
   - 在解释器执行过程中，负责将当前的字节码偏移量向前移动，模拟执行完一个字节码指令后的状态。
   - 如果当前字节码是返回指令，则跳转到指定的返回标签。
   - 对于 `JumpLoop` 指令，会重新执行以实现循环跳转。
   - 考虑了 `Wide` 和 `ExtraWide` 前缀字节码的情况。

6. **优化相关的功能 (`ResetSharedFunctionInfoAge`, `ResetJSFunctionAge`, `ResetFeedbackVectorOsrUrgency`):**
   - 提供了一些辅助函数，用于重置与优化相关的状态，例如共享函数信息的年龄、JS 函数的年龄以及反馈向量的 OSR 紧急状态。这些操作通常在进入或退出不同执行模式时进行。

7. **Baseline 代码的入口和退出 (`Generate_BaselineOutOfLinePrologue`, `Generate_BaselineOutOfLinePrologueDeopt`):**
   - `Generate_BaselineOutOfLinePrologue`:  定义了进入 Baseline 代码（一种轻量级的优化代码）的流程，包括：
     - 检查反馈向量的状态。
     - 递增函数的调用计数。
     - 设置栈帧 (`StackFrame::MANUAL`).
     - 执行栈溢出检查。
   - `Generate_BaselineOutOfLinePrologueDeopt`:  定义了从 Baseline 代码回退到解释器的流程，通常是因为栈溢出检查失败。它会清理 Baseline 代码建立的栈帧，并跳转到解释器入口。

8. **解释器入口 (`Generate_InterpreterEntryTrampoline`):**
   - 定义了进入 JavaScript 解释器的流程，包括：
     - 获取字节码数组。
     - 检查是否需要编译 (lazy compilation)。
     - 加载反馈向量。
     - 递增函数的调用计数。
     - 建立解释器栈帧 (`StackFrame::MANUAL`).
     - 初始化字节码偏移量。
     - 分配局部变量和临时变量空间。
     - 执行栈溢出检查和中断检查。
     - 跳转到字节码分发器开始执行字节码。
     - 处理解释器返回的情况。

9. **解释器参数压栈 (`GenerateInterpreterPushArgs`, `Generate_InterpreterPushArgsThenCallImpl`):**
   - `GenerateInterpreterPushArgs`:  负责将调用 JavaScript 函数的参数压入栈中，支持处理剩余参数（spread syntax）。
   - `Generate_InterpreterPushArgsThenCallImpl`: 在参数压栈之后，负责调用目标函数。

**与 JavaScript 功能的关系和示例:**

这段代码直接关系到 JavaScript 函数的调用和执行。例如，`Generate_JSEntryTrampolineHelper` 处理了 JavaScript 函数被调用时的参数传递：

```javascript
function myFunction(a, b) {
  console.log(a + b);
}

myFunction(1, 2);
```

当 `myFunction(1, 2)` 被调用时，V8 引擎会调用相应的内置函数（如 `Generate_JSEntryTrampolineHelper`），该函数会将 `1` 和 `2` 这两个参数以及 `myFunction` 本身和接收者（在这里是全局对象）放入栈中，以便后续的 JavaScript 代码能够访问这些参数。

**代码逻辑推理示例:**

**假设输入：**

- `is_construct` 为 `true` (表示这是一个构造函数调用)
- `x1` (new.target) 指向一个新创建的对象。
- `x2` (function) 指向构造函数对象。
- `x3` (receiver) 指向将要成为 `this` 的对象（通常是新创建的对象）。
- `x4` (argc) 的值为 `2` (表示有两个参数)。
- `x5` (argv) 指向参数数组的起始地址，其中包含参数的值。

**输出：**

- 栈上会分配足够的空间来存放接收者、函数对象和两个参数。
- 接收者对象会被压入栈底。
- 构造函数对象会被压入接收者对象之上。
- 两个参数会按照相反的顺序被压入栈中。
- JavaScript Callee-saved 寄存器会被初始化为 `undefined`。
- 最后会调用 `Builtin::kConstruct`，并将控制权交给构造函数的代码执行。

**用户常见的编程错误示例:**

在与这段代码相关的层面，用户常见的编程错误可能不会直接体现在 C++ 代码中，而是体现在 JavaScript 代码的编写上，这些错误可能会触发到这些内置函数的执行流程：

1. **栈溢出:**  如果 JavaScript 代码中存在无限递归的函数调用，可能会导致栈空间耗尽，最终触发 `Generate_BaselineOutOfLinePrologue` 或 `Generate_InterpreterEntryTrampoline` 中的栈溢出检查，并可能抛出 `StackOverflowError`。

   ```javascript
   function recursiveFunction() {
     recursiveFunction(); // 无终止条件的递归
   }

   recursiveFunction(); // 可能导致栈溢出
   ```

2. **参数传递错误:**  虽然内置函数会处理参数的传递，但如果 JavaScript 代码调用函数时传递了错误数量或类型的参数，可能会导致程序行为不符合预期。例如，一个函数期望接收两个数字参数，但调用时只传递了一个字符串参数。

   ```javascript
   function add(a, b) {
     return a + b;
   }

   console.log(add(5)); // 参数数量错误
   console.log(add("hello", 5)); // 参数类型错误
   ```

**总结:**

这段 `builtins-arm64.cc` 代码是 V8 引擎在 ARM64 架构上执行 JavaScript 代码的核心组成部分，它负责处理函数调用的入口、参数传递、栈帧管理、以及解释器和优化代码之间的切换。理解这段代码的功能有助于深入了解 V8 引擎的内部工作机制和 JavaScript 代码的执行过程。

### 提示词
```
这是目录为v8/src/builtins/arm64/builtins-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/arm64/builtins-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
Restore the top frame descriptors from the stack.
    __ Mov(x12, ExternalReference::Create(IsolateAddressId::kCEntryFPAddress,
                                          masm->isolate()));
    __ Str(c_entry_fp, MemOperand(x12));
  }

  // Reset the stack to the callee saved registers.
  static_assert(
      EntryFrameConstants::kFixedFrameSize % (2 * kSystemPointerSize) == 0,
      "Size of entry frame is not a multiple of 16 bytes");
  // fast_c_call_caller_fp and fast_c_call_caller_pc have already been popped.
  int drop_count =
      (EntryFrameConstants::kFixedFrameSize / kSystemPointerSize) - 2;
  __ Drop(drop_count);
  // Restore the callee-saved registers and return.
  __ PopCalleeSavedRegisters();
  __ Ret();
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

// Input:
//   x1: new.target.
//   x2: function.
//   x3: receiver.
//   x4: argc.
//   x5: argv.
// Output:
//   x0: result.
static void Generate_JSEntryTrampolineHelper(MacroAssembler* masm,
                                             bool is_construct) {
  Register new_target = x1;
  Register function = x2;
  Register receiver = x3;
  Register argc = x4;
  Register argv = x5;
  Register scratch = x10;
  Register slots_to_claim = x11;

  {
    // Enter an internal frame.
    FrameScope scope(masm, StackFrame::INTERNAL);

    // Setup the context (we need to use the caller context from the isolate).
    __ Mov(scratch, ExternalReference::Create(IsolateAddressId::kContextAddress,
                                              masm->isolate()));
    __ Ldr(cp, MemOperand(scratch));

    // Claim enough space for the arguments and the function, including an
    // optional slot of padding.
    constexpr int additional_slots = 2;
    __ Add(slots_to_claim, argc, additional_slots);
    __ Bic(slots_to_claim, slots_to_claim, 1);

    // Check if we have enough stack space to push all arguments.
    Label enough_stack_space, stack_overflow;
    __ StackOverflowCheck(slots_to_claim, &stack_overflow);
    __ B(&enough_stack_space);

    __ Bind(&stack_overflow);
    __ CallRuntime(Runtime::kThrowStackOverflow);
    __ Unreachable();

    __ Bind(&enough_stack_space);
    __ Claim(slots_to_claim);

    // Store padding (which might be overwritten).
    __ SlotAddress(scratch, slots_to_claim);
    __ Str(padreg, MemOperand(scratch, -kSystemPointerSize));

    // Store receiver on the stack.
    __ Poke(receiver, 0);
    // Store function on the stack.
    __ SlotAddress(scratch, argc);
    __ Str(function, MemOperand(scratch));

    // Copy arguments to the stack in a loop, in reverse order.
    // x4: argc.
    // x5: argv.
    Label loop, done;

    // Skip the argument set up if we have no arguments.
    __ Cmp(argc, JSParameterCount(0));
    __ B(eq, &done);

    // scratch has been set to point to the location of the function, which
    // marks the end of the argument copy.
    __ SlotAddress(x0, 1);  // Skips receiver.
    __ Bind(&loop);
    // Load the handle.
    __ Ldr(x11, MemOperand(argv, kSystemPointerSize, PostIndex));
    // Dereference the handle.
    __ Ldr(x11, MemOperand(x11));
    // Poke the result into the stack.
    __ Str(x11, MemOperand(x0, kSystemPointerSize, PostIndex));
    // Loop if we've not reached the end of copy marker.
    __ Cmp(x0, scratch);
    __ B(lt, &loop);

    __ Bind(&done);

    __ Mov(x0, argc);
    __ Mov(x3, new_target);
    __ Mov(x1, function);
    // x0: argc.
    // x1: function.
    // x3: new.target.

    // Initialize all JavaScript callee-saved registers, since they will be seen
    // by the garbage collector as part of handlers.
    // The original values have been saved in JSEntry.
    __ LoadRoot(x19, RootIndex::kUndefinedValue);
    __ Mov(x20, x19);
    __ Mov(x21, x19);
    __ Mov(x22, x19);
    __ Mov(x23, x19);
    __ Mov(x24, x19);
    __ Mov(x25, x19);
#ifndef V8_COMPRESS_POINTERS
    __ Mov(x28, x19);
#endif
    // Don't initialize the reserved registers.
    // x26 : root register (kRootRegister).
    // x27 : context pointer (cp).
    // x28 : pointer cage base register (kPtrComprCageBaseRegister).
    // x29 : frame pointer (fp).

    Builtin builtin = is_construct ? Builtin::kConstruct : Builtins::Call();
    __ CallBuiltin(builtin);

    // Exit the JS internal frame and remove the parameters (except function),
    // and return.
  }

  // Result is in x0. Return.
  __ Ret();
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
  //   x0: root_register_value
  //   x1: microtask_queue

  __ Mov(RunMicrotasksDescriptor::MicrotaskQueueRegister(), x1);
  __ TailCallBuiltin(Builtin::kRunMicrotasks);
}

static void LeaveInterpreterFrame(MacroAssembler* masm, Register scratch1,
                                  Register scratch2) {
  ASM_CODE_COMMENT(masm);
  Register params_size = scratch1;
  // Get the size of the formal parameters + receiver (in bytes).
  __ Ldr(params_size,
         MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ Ldrh(params_size.W(),
          FieldMemOperand(params_size, BytecodeArray::kParameterSizeOffset));

  Register actual_params_size = scratch2;
  // Compute the size of the actual parameters + receiver (in bytes).
  __ Ldr(actual_params_size,
         MemOperand(fp, StandardFrameConstants::kArgCOffset));

  // If actual is bigger than formal, then we should use it to free up the stack
  // arguments.
  __ Cmp(params_size, actual_params_size);
  __ Csel(params_size, actual_params_size, params_size, kLessThan);

  // Leave the frame (also dropping the register file).
  __ LeaveFrame(StackFrame::INTERPRETED);

  // Drop receiver + arguments.
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
  ASM_CODE_COMMENT(masm);
  Register bytecode_size_table = scratch1;

  // The bytecode offset value will be increased by one in wide and extra wide
  // cases. In the case of having a wide or extra wide JumpLoop bytecode, we
  // will restore the original bytecode. In order to simplify the code, we have
  // a backup of it.
  Register original_bytecode_offset = scratch2;
  DCHECK(!AreAliased(bytecode_array, bytecode_offset, bytecode_size_table,
                     bytecode, original_bytecode_offset));

  __ Mov(bytecode_size_table, ExternalReference::bytecode_size_table_address());
  __ Mov(original_bytecode_offset, bytecode_offset);

  // Check if the bytecode is a Wide or ExtraWide prefix bytecode.
  Label process_bytecode, extra_wide;
  static_assert(0 == static_cast<int>(interpreter::Bytecode::kWide));
  static_assert(1 == static_cast<int>(interpreter::Bytecode::kExtraWide));
  static_assert(2 == static_cast<int>(interpreter::Bytecode::kDebugBreakWide));
  static_assert(3 ==
                static_cast<int>(interpreter::Bytecode::kDebugBreakExtraWide));
  __ Cmp(bytecode, Operand(0x3));
  __ B(hi, &process_bytecode);
  __ Tst(bytecode, Operand(0x1));
  // The code to load the next bytecode is common to both wide and extra wide.
  // We can hoist them up here since they do not modify the flags after Tst.
  __ Add(bytecode_offset, bytecode_offset, Operand(1));
  __ Ldrb(bytecode, MemOperand(bytecode_array, bytecode_offset));
  __ B(ne, &extra_wide);

  // Update table to the wide scaled table.
  __ Add(bytecode_size_table, bytecode_size_table,
         Operand(kByteSize * interpreter::Bytecodes::kBytecodeCount));
  __ B(&process_bytecode);

  __ Bind(&extra_wide);
  // Update table to the extra wide scaled table.
  __ Add(bytecode_size_table, bytecode_size_table,
         Operand(2 * kByteSize * interpreter::Bytecodes::kBytecodeCount));

  __ Bind(&process_bytecode);

// Bailout to the return label if this is a return bytecode.
#define JUMP_IF_EQUAL(NAME)                                              \
  __ Cmp(x1, Operand(static_cast<int>(interpreter::Bytecode::k##NAME))); \
  __ B(if_return, eq);
  RETURN_BYTECODE_LIST(JUMP_IF_EQUAL)
#undef JUMP_IF_EQUAL

  // If this is a JumpLoop, re-execute it to perform the jump to the beginning
  // of the loop.
  Label end, not_jump_loop;
  __ Cmp(bytecode, Operand(static_cast<int>(interpreter::Bytecode::kJumpLoop)));
  __ B(ne, &not_jump_loop);
  // We need to restore the original bytecode_offset since we might have
  // increased it to skip the wide / extra-wide prefix bytecode.
  __ Mov(bytecode_offset, original_bytecode_offset);
  __ B(&end);

  __ bind(&not_jump_loop);
  // Otherwise, load the size of the current bytecode and advance the offset.
  __ Ldrb(scratch1.W(), MemOperand(bytecode_size_table, bytecode));
  __ Add(bytecode_offset, bytecode_offset, scratch1);

  __ Bind(&end);
}

namespace {

void ResetSharedFunctionInfoAge(MacroAssembler* masm, Register sfi) {
  __ Strh(wzr, FieldMemOperand(sfi, SharedFunctionInfo::kAgeOffset));
}

void ResetJSFunctionAge(MacroAssembler* masm, Register js_function,
                        Register scratch) {
  const Register shared_function_info(scratch);
  __ LoadTaggedField(
      shared_function_info,
      FieldMemOperand(js_function, JSFunction::kSharedFunctionInfoOffset));
  ResetSharedFunctionInfoAge(masm, shared_function_info);
}

void ResetFeedbackVectorOsrUrgency(MacroAssembler* masm,
                                   Register feedback_vector, Register scratch) {
  DCHECK(!AreAliased(feedback_vector, scratch));
  __ Ldrb(scratch,
          FieldMemOperand(feedback_vector, FeedbackVector::kOsrStateOffset));
  __ And(scratch, scratch, Operand(~FeedbackVector::OsrUrgencyBits::kMask));
  __ Strb(scratch,
          FieldMemOperand(feedback_vector, FeedbackVector::kOsrStateOffset));
}

}  // namespace

// static
void Builtins::Generate_BaselineOutOfLinePrologue(MacroAssembler* masm) {
  UseScratchRegisterScope temps(masm);
  // Need a few extra registers
  temps.Include(CPURegList(kXRegSizeInBits, {x12, x13, x14, x15}));

  auto descriptor =
      Builtins::CallInterfaceDescriptorFor(Builtin::kBaselineOutOfLinePrologue);
  Register closure = descriptor.GetRegisterParameter(
      BaselineOutOfLinePrologueDescriptor::kClosure);
  // Load the feedback cell and vector from the closure.
  Register feedback_cell = temps.AcquireX();
  Register feedback_vector = temps.AcquireX();
  Register scratch = temps.AcquireX();
  __ LoadTaggedField(feedback_cell,
                     FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
  __ LoadTaggedField(
      feedback_vector,
      FieldMemOperand(feedback_cell, FeedbackCell::kValueOffset));
  __ AssertFeedbackVector(feedback_vector, scratch);

#ifndef V8_ENABLE_LEAPTIERING
  // Check the tiering state.
  Label flags_need_processing;
  Register flags = temps.AcquireW();
  __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
      flags, feedback_vector, CodeKind::BASELINE, &flags_need_processing);
#endif  // !V8_ENABLE_LEAPTIERING

  {
    UseScratchRegisterScope temps(masm);
    ResetFeedbackVectorOsrUrgency(masm, feedback_vector, temps.AcquireW());
  }

  // Increment invocation count for the function.
  {
    UseScratchRegisterScope temps(masm);
    Register invocation_count = temps.AcquireW();
    __ Ldr(invocation_count,
           FieldMemOperand(feedback_vector,
                           FeedbackVector::kInvocationCountOffset));
    __ Add(invocation_count, invocation_count, Operand(1));
    __ Str(invocation_count,
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
    {
      UseScratchRegisterScope temps(masm);
      ResetJSFunctionAge(masm, callee_js_function, temps.AcquireX());
    }
    __ Push(callee_context, callee_js_function);
    DCHECK_EQ(callee_js_function, kJavaScriptCallTargetRegister);
    DCHECK_EQ(callee_js_function, kJSFunctionRegister);

    Register argc = descriptor.GetRegisterParameter(
        BaselineOutOfLinePrologueDescriptor::kJavaScriptCallArgCount);
    // We'll use the bytecode for both code age/OSR resetting, and pushing onto
    // the frame, so load it into a register.
    Register bytecode_array = descriptor.GetRegisterParameter(
        BaselineOutOfLinePrologueDescriptor::kInterpreterBytecodeArray);
    __ Push(argc, bytecode_array, feedback_cell, feedback_vector);
    __ AssertFeedbackVector(feedback_vector, scratch);
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
    UseScratchRegisterScope temps(masm);

    Register sp_minus_frame_size = temps.AcquireX();
    __ Sub(sp_minus_frame_size, sp, frame_size);
    Register interrupt_limit = temps.AcquireX();
    __ LoadStackLimit(interrupt_limit, StackLimitKind::kInterruptStackLimit);
    __ Cmp(sp_minus_frame_size, interrupt_limit);
    __ B(lo, &call_stack_guard);
  }

  // Do "fast" return to the caller pc in lr.
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
  __ Ret();

#ifndef V8_ENABLE_LEAPTIERING
  __ bind(&flags_need_processing);
  {
    ASM_CODE_COMMENT_STRING(masm, "Optimized marker check");
    // Drop the frame created by the baseline call.
    __ Pop<MacroAssembler::kAuthLR>(fp, lr);
    __ OptimizeCodeOrTailCallOptimizedCodeSlot(flags, feedback_vector);
    __ Trap();
  }
#endif  // !V8_ENABLE_LEAPTIERING

  __ bind(&call_stack_guard);
  {
    ASM_CODE_COMMENT_STRING(masm, "Stack/interrupt call");
    Register new_target = descriptor.GetRegisterParameter(
        BaselineOutOfLinePrologueDescriptor::kJavaScriptCallNewTarget);

    FrameScope frame_scope(masm, StackFrame::INTERNAL);
    // Save incoming new target or generator
    Register maybe_dispatch_handle = V8_ENABLE_LEAPTIERING_BOOL
                                         ? kJavaScriptCallDispatchHandleRegister
                                         : padreg;
    // No need to SmiTag as dispatch handles always look like Smis.
    static_assert(kJSDispatchHandleShift > 0);
    __ Push(maybe_dispatch_handle, new_target);
    __ SmiTag(frame_size);
    __ PushArgument(frame_size);
    __ CallRuntime(Runtime::kStackGuardWithGap);
    __ Pop(new_target, maybe_dispatch_handle);
  }
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
  __ Ret();
}

// static
void Builtins::Generate_BaselineOutOfLinePrologueDeopt(MacroAssembler* masm) {
  // We're here because we got deopted during BaselineOutOfLinePrologue's stack
  // check. Undo all its frame creation and call into the interpreter instead.

  // Drop the feedback vector and the bytecode offset (was the feedback vector
  // but got replaced during deopt).
  __ Drop(2);

  // Bytecode array, argc, Closure, Context.
  __ Pop(padreg, kJavaScriptCallArgCountRegister, kJavaScriptCallTargetRegister,
         kContextRegister);

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
//   - x0: actual argument count
//   - x1: the JS function object being called.
//   - x3: the incoming new target or generator object
//   - x4: the dispatch handle through which we were called
//   - cp: our context.
//   - fp: our caller's frame pointer.
//   - lr: return address.
//
// The function builds an interpreter frame. See InterpreterFrameConstants in
// frame-constants.h for its layout.
void Builtins::Generate_InterpreterEntryTrampoline(
    MacroAssembler* masm, InterpreterEntryTrampolineMode mode) {
  Register closure = x1;

  // Get the bytecode array from the function object and load it into
  // kInterpreterBytecodeArrayRegister.
  Register sfi = x5;
  __ LoadTaggedField(
      sfi, FieldMemOperand(closure, JSFunction::kSharedFunctionInfoOffset));
  ResetSharedFunctionInfoAge(masm, sfi);

  // The bytecode array could have been flushed from the shared function info,
  // if so, call into CompileLazy.
  Label is_baseline, compile_lazy;
  GetSharedFunctionInfoBytecodeOrBaseline(masm, sfi,
                                          kInterpreterBytecodeArrayRegister,
                                          x11, &is_baseline, &compile_lazy);

#ifdef V8_ENABLE_LEAPTIERING
  // Validate the parameter count. This protects against an attacker swapping
  // the bytecode (or the dispatch handle) such that the parameter count of the
  // dispatch entry doesn't match the one of the BytecodeArray.
  // TODO(saelo): instead of this validation step, it would probably be nicer
  // if we could store the BytecodeArray directly in the dispatch entry and
  // load it from there. Then we can easily guarantee that the parameter count
  // of the entry matches the parameter count of the bytecode.
  Register dispatch_handle = kJavaScriptCallDispatchHandleRegister;
  __ LoadParameterCountFromJSDispatchTable(x6, dispatch_handle, x7);
  __ Ldrh(x7, FieldMemOperand(kInterpreterBytecodeArrayRegister,
                              BytecodeArray::kParameterSizeOffset));
  __ Cmp(x6, x7);
  __ SbxCheck(eq, AbortReason::kJSSignatureMismatch);
#endif  // V8_ENABLE_LEAPTIERING

  Label push_stack_frame;
  Register feedback_vector = x2;
  __ LoadFeedbackVector(feedback_vector, closure, x7, &push_stack_frame);

#ifndef V8_JITLESS
#ifndef V8_ENABLE_LEAPTIERING
  // If feedback vector is valid, check for optimized code and update invocation
  // count.
  Label flags_need_processing;
  Register flags = w7;
  __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
      flags, feedback_vector, CodeKind::INTERPRETED_FUNCTION,
      &flags_need_processing);
#endif  // !V8_ENABLE_LEAPTIERING

  ResetFeedbackVectorOsrUrgency(masm, feedback_vector, w7);

  // Increment invocation count for the function.
  __ Ldr(w10, FieldMemOperand(feedback_vector,
                              FeedbackVector::kInvocationCountOffset));
  __ Add(w10, w10, Operand(1));
  __ Str(w10, FieldMemOperand(feedback_vector,
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

  __ Bind(&push_stack_frame);
  FrameScope frame_scope(masm, StackFrame::MANUAL);
  __ Push<MacroAssembler::kSignLR>(lr, fp);
  __ mov(fp, sp);
  __ Push(cp, closure);

  // Load the initial bytecode offset.
  __ Mov(kInterpreterBytecodeOffsetRegister,
         Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));

  // Push actual argument count, bytecode array, Smi tagged bytecode array
  // offset and the feedback vector.
  __ SmiTag(x6, kInterpreterBytecodeOffsetRegister);
  __ Push(kJavaScriptCallArgCountRegister, kInterpreterBytecodeArrayRegister);
  __ Push(x6, feedback_vector);

  // Allocate the local and temporary register file on the stack.
  Label stack_overflow;
  {
    // Load frame size from the BytecodeArray object.
    __ Ldr(w11, FieldMemOperand(kInterpreterBytecodeArrayRegister,
                                BytecodeArray::kFrameSizeOffset));
    __ Ldrh(w12, FieldMemOperand(kInterpreterBytecodeArrayRegister,
                                 BytecodeArray::kMaxArgumentsOffset));
    __ Add(w12, w11, Operand(w12, LSL, kSystemPointerSizeLog2));

    // Do a stack check to ensure we don't go over the limit.
    __ Sub(x10, sp, Operand(x12));
    {
      UseScratchRegisterScope temps(masm);
      Register scratch = temps.AcquireX();
      __ LoadStackLimit(scratch, StackLimitKind::kRealStackLimit);
      __ Cmp(x10, scratch);
    }
    __ B(lo, &stack_overflow);

    // If ok, push undefined as the initial value for all register file entries.
    // Note: there should always be at least one stack slot for the return
    // register in the register file.
    Label loop_header;
    __ Lsr(x11, x11, kSystemPointerSizeLog2);
    // Round up the number of registers to a multiple of 2, to align the stack
    // to 16 bytes.
    __ Add(x11, x11, 1);
    __ Bic(x11, x11, 1);
    __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
    __ PushMultipleTimes(kInterpreterAccumulatorRegister, x11);
    __ Bind(&loop_header);
  }

  // If the bytecode array has a valid incoming new target or generator object
  // register, initialize it with incoming value which was passed in x3.
  Label no_incoming_new_target_or_generator_register;
  __ Ldrsw(x10,
           FieldMemOperand(
               kInterpreterBytecodeArrayRegister,
               BytecodeArray::kIncomingNewTargetOrGeneratorRegisterOffset));
  __ Cbz(x10, &no_incoming_new_target_or_generator_register);
  __ Str(x3, MemOperand(fp, x10, LSL, kSystemPointerSizeLog2));
  __ Bind(&no_incoming_new_target_or_generator_register);

  // Perform interrupt stack check.
  // TODO(solanes): Merge with the real stack limit check above.
  Label stack_check_interrupt, after_stack_check_interrupt;
  __ LoadStackLimit(x10, StackLimitKind::kInterruptStackLimit);
  __ Cmp(sp, x10);
  __ B(lo, &stack_check_interrupt);
  __ Bind(&after_stack_check_interrupt);

  // The accumulator is already loaded with undefined.

  // Load the dispatch table into a register and dispatch to the bytecode
  // handler at the current bytecode offset.
  Label do_dispatch;
  __ bind(&do_dispatch);
  __ Mov(
      kInterpreterDispatchTableRegister,
      ExternalReference::interpreter_dispatch_table_address(masm->isolate()));
  __ Ldrb(x23, MemOperand(kInterpreterBytecodeArrayRegister,
                          kInterpreterBytecodeOffsetRegister));
  __ Mov(x1, Operand(x23, LSL, kSystemPointerSizeLog2));
  __ Ldr(kJavaScriptCallCodeStartRegister,
         MemOperand(kInterpreterDispatchTableRegister, x1));
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

  __ JumpTarget();

  // Get bytecode array and bytecode offset from the stack frame.
  __ Ldr(kInterpreterBytecodeArrayRegister,
         MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ SmiUntag(kInterpreterBytecodeOffsetRegister,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

  // Either return, or advance to the next bytecode and dispatch.
  Label do_return;
  __ Ldrb(x1, MemOperand(kInterpreterBytecodeArrayRegister,
                         kInterpreterBytecodeOffsetRegister));
  AdvanceBytecodeOffsetOrReturn(masm, kInterpreterBytecodeArrayRegister,
                                kInterpreterBytecodeOffsetRegister, x1, x2, x3,
                                &do_return);
  __ B(&do_dispatch);

  __ bind(&do_return);
  // The return value is in x0.
  LeaveInterpreterFrame(masm, x2, x5);
  __ Ret();

  __ bind(&stack_check_interrupt);
  // Modify the bytecode offset in the stack to be kFunctionEntryBytecodeOffset
  // for the call to the StackGuard.
  __ Mov(kInterpreterBytecodeOffsetRegister,
         Operand(Smi::FromInt(BytecodeArray::kHeaderSize - kHeapObjectTag +
                              kFunctionEntryBytecodeOffset)));
  __ Str(kInterpreterBytecodeOffsetRegister,
         MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ CallRuntime(Runtime::kStackGuard);

  // After the call, restore the bytecode array, bytecode offset and accumulator
  // registers again. Also, restore the bytecode offset in the stack to its
  // previous value.
  __ Ldr(kInterpreterBytecodeArrayRegister,
         MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ Mov(kInterpreterBytecodeOffsetRegister,
         Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);

  __ SmiTag(x10, kInterpreterBytecodeOffsetRegister);
  __ Str(x10, MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

  __ jmp(&after_stack_check_interrupt);

#ifndef V8_JITLESS
#ifndef V8_ENABLE_LEAPTIERING
  __ bind(&flags_need_processing);
  __ OptimizeCodeOrTailCallOptimizedCodeSlot(flags, feedback_vector);
#endif  // !V8_ENABLE_LEAPTIERING

  __ bind(&is_baseline);
  {
#ifndef V8_ENABLE_LEAPTIERING
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
        x7, FieldMemOperand(feedback_vector, HeapObject::kMapOffset));
    __ Ldrh(x7, FieldMemOperand(x7, Map::kInstanceTypeOffset));
    __ Cmp(x7, FEEDBACK_VECTOR_TYPE);
    __ B(ne, &install_baseline_code);

    // Check the tiering state.
    __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
        flags, feedback_vector, CodeKind::BASELINE, &flags_need_processing);

    // TODO(olivf, 42204201): This fastcase is difficult to support with the
    // sandbox as it requires getting write access to the dispatch table. See
    // `JSFunction::UpdateCode`. We might want to remove it for all
    // configurations as it does not seem to be performance sensitive.

    // Load the baseline code into the closure.
    __ Move(x2, kInterpreterBytecodeArrayRegister);
    static_assert(kJavaScriptCallCodeStartRegister == x2, "ABI mismatch");
    __ ReplaceClosureCodeWithOptimizedCode(x2, closure);
    __ JumpCodeObject(x2, kJSEntrypointTag);

    __ bind(&install_baseline_code);
#endif  // !V8_ENABLE_LEAPTIERING

    __ GenerateTailCallToReturnedCode(Runtime::kInstallBaselineCode);
  }
#endif  // !V8_JITLESS

  __ bind(&compile_lazy);
  __ GenerateTailCallToReturnedCode(Runtime::kCompileLazy);
  __ Unreachable();  // Should not return.

  __ bind(&stack_overflow);
  __ CallRuntime(Runtime::kThrowStackOverflow);
  __ Unreachable();  // Should not return.
}

static void GenerateInterpreterPushArgs(MacroAssembler* masm, Register num_args,
                                        Register first_arg_index,
                                        Register spread_arg_out,
                                        ConvertReceiverMode receiver_mode,
                                        InterpreterPushArgsMode mode) {
  ASM_CODE_COMMENT(masm);
  Register last_arg_addr = x10;
  Register stack_addr = x11;
  Register slots_to_claim = x12;
  Register slots_to_copy = x13;

  DCHECK(!AreAliased(num_args, first_arg_index, last_arg_addr, stack_addr,
                     slots_to_claim, slots_to_copy));
  // spread_arg_out may alias with the first_arg_index input.
  DCHECK(!AreAliased(spread_arg_out, last_arg_addr, stack_addr, slots_to_claim,
                     slots_to_copy));

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Exclude final spread from slots to claim and the number of arguments.
    __ Sub(num_args, num_args, 1);
  }

  // Round up to an even number of slots.
  __ Add(slots_to_claim, num_args, 1);
  __ Bic(slots_to_claim, slots_to_claim, 1);

  __ Claim(slots_to_claim);
  {
    // Store padding, which may be overwritten.
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.AcquireX();
    __ Sub(scratch, slots_to_claim, 1);
    __ Poke(padreg, Operand(scratch, LSL, kSystemPointerSizeLog2));
  }

  const bool skip_receiver =
      receiver_mode == ConvertReceiverMode::kNullOrUndefined;
  if (skip_receiver) {
    __ Sub(slots_to_copy, num_args, kJSArgcReceiverSlots);
  } else {
    __ Mov(slots_to_copy, num_args);
  }
  __ SlotAddress(stack_addr, skip_receiver ? 1 : 0);

  __ Sub(last_arg_addr, first_arg_index,
         Operand(slots_to_copy, LSL, kSystemPointerSizeLog2));
  __ Add(last_arg_addr, last_arg_addr, kSystemPointerSize);

  // Load the final spread argument into spread_arg_out, if necessary.
  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    __ Ldr(spread_arg_out, MemOperand(last_arg_addr, -kSystemPointerSize));
  }

  __ CopyDoubleWords(stack_addr, last_arg_addr, slots_to_copy,
                     MacroAssembler::kDstLessThanSrcAndReverse);

  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    // Store "undefined" as the receiver arg if we need to.
    Register receiver = x14;
    __ LoadRoot(receiver, RootIndex::kUndefinedValue);
    __ Poke(receiver, 0);
  }
}

// static
void Builtins::Generate_InterpreterPushArgsThenCallImpl(
    MacroAssembler* masm, ConvertReceiverMode receiver_mode,
    InterpreterPushArgsMode mode) {
  DCHECK(mode != InterpreterPushArgsMode::kArrayFunction);
  // ----------- S t a t e -------------
  //  -- x0 : the number of arguments
  //  -- x2 : the address of the first argument to be pushed. Subsequent
  //          arguments should be consecutive above this, in the same order as
  //          they are to be pushed onto the stack.
  //  -- x1 : the target to call (can be any Object).
  // -----------------------------------

  // Push the arguments. num_args may be updated according to mode.
  // spread_arg_out will be updated to contain the last spread argument, when
  // mode == InterpreterPushArgsMode::kWithFinalSpread.
  Register num_args = x0;
  Register first_arg_index = x2;
  Register spread_arg_out =
      (mode == InterpreterPushArgsMode::kWithFinalSpread) ? x2 : no_reg;
  GenerateInterpreterPushArgs(masm, num_args, first_a
```