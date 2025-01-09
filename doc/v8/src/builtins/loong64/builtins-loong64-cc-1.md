Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/builtins/loong64/builtins-loong64.cc`. This is the second part of a six-part code block.

Here's a breakdown of the request and how to address it:

1. **List the functionalities:** Analyze the code and identify the high-level tasks it performs. This involves looking at function names, code structures, and interactions with V8 internals.
2. **Torque source check:** Check if the filename ends with `.tq`. If not, state that it's not a Torque source.
3. **Relationship to JavaScript:** Determine if the code directly relates to executing JavaScript code. If so, provide a JavaScript example that would trigger the functionality.
4. **Code logic reasoning (input/output):** If the code performs specific logical operations (like bytecode advancement), provide hypothetical inputs and expected outputs.
5. **Common programming errors:** If the code handles or prevents common programming errors, illustrate those errors with examples.
6. **Summarize the functionality (for part 2):**  Synthesize the identified functionalities into a concise summary for this specific code segment.

**Detailed Code Analysis and Planning:**

* **`AdvanceBytecodeOffsetOrReturn`:**  This function seems to handle advancing the bytecode offset in the interpreter or returning from a function call. It takes the current bytecode, offset, and other registers as input. A likely JavaScript scenario is a function call within another function.
* **`ResetSharedFunctionInfoAge` and `ResetJSFunctionAge`:** These functions deal with resetting the "age" of SharedFunctionInfo and JSFunction objects. This is likely related to optimization and garbage collection in V8. There isn't a direct JavaScript equivalent that triggers this, as it's an internal V8 mechanism.
* **`ResetFeedbackVectorOsrUrgency`:** This function manipulates the OSR (On-Stack Replacement) urgency in a FeedbackVector. This is part of V8's optimization pipeline. No direct JavaScript trigger.
* **`Builtins::Generate_BaselineOutOfLinePrologue`:** This function appears to generate assembly code for the prologue of a baseline-compiled function when it's called "out-of-line". It handles feedback vectors, invocation counts, and stack checks. A JavaScript example would be calling a function that gets baseline compiled.
* **`Builtins::Generate_BaselineOutOfLinePrologueDeopt`:** This function generates code for handling deoptimization from the baseline out-of-line prologue, likely reverting to the interpreter. This is an internal V8 optimization mechanism.
* **`Builtins::Generate_InterpreterEntryTrampoline`:** This is a crucial function for entering the interpreter. It sets up the interpreter frame, handles stack checks, loads bytecode, and dispatches to bytecode handlers. Any JavaScript function call that is not optimized will go through this.
* **`GenerateInterpreterPushArgs`:**  This utility function pushes arguments onto the stack in the correct order for interpreter calls. Any function call in JavaScript will utilize this.
* **`Builtins::Generate_InterpreterPushArgsThenCallImpl`:** Generates code for calling a function via the interpreter after pushing arguments. This covers normal function calls and calls with spread syntax.
* **`Builtins::Generate_InterpreterPushArgsThenConstructImpl`:**  Generates code for constructor calls in the interpreter after pushing arguments.
* **`Builtins::Generate_ConstructForwardAllArgsImpl`:** Handles forwarding arguments during constructor calls, potentially from a superclass constructor.
* **`Builtins::Generate_InterpreterPushArgsThenFastConstructFunction`:** Generates code for a faster path for constructor calls when certain conditions are met.
* **`Generate_InterpreterEnterBytecode`:**  This function sets up the environment for executing bytecode within the interpreter.

**Output Structure Plan:**

The output will follow the user's instructions, listing functionalities, checking for Torque, providing JavaScript examples where applicable, explaining code logic with examples, showing common errors, and finally summarizing the functionality of this specific part.
这是 `v8/src/builtins/loong64/builtins-loong64.cc` 源代码的第 2 部分，它主要负责生成 LoongArch64 架构下 V8 引擎的内置函数（builtins）的汇编代码，这些内置函数与 JavaScript 的执行密切相关。

**功能列表:**

1. **`AdvanceBytecodeOffsetOrReturn`**:  此函数生成汇编代码，用于在解释器中根据当前字节码的大小来前进字节码偏移量。如果当前字节码是 `JumpLoop`，它会跳转到循环的开始，否则会计算并更新下一个字节码的偏移量。
2. **`ResetSharedFunctionInfoAge`**: 生成汇编代码，将 `SharedFunctionInfo` 对象的 `age` 字段重置为零。`age` 字段用于跟踪函数的执行次数，以便进行优化。
3. **`ResetJSFunctionAge`**: 生成汇编代码，获取 `JSFunction` 对象的 `SharedFunctionInfo` 并调用 `ResetSharedFunctionInfoAge` 来重置其 `age`。
4. **`ResetFeedbackVectorOsrUrgency`**: 生成汇编代码，重置 `FeedbackVector` 对象的 OSR (On-Stack Replacement) 紧急程度标志。`FeedbackVector` 用于收集函数的运行时反馈信息，以进行优化。
5. **`Builtins::Generate_BaselineOutOfLinePrologue`**: 生成汇编代码，用于基线编译（Baseline Compilation）函数的外部 prologue。这个 prologue 负责设置栈帧，检查反馈向量的状态，并递增函数的调用计数。
6. **`Builtins::Generate_BaselineOutOfLinePrologueDeopt`**: 生成汇编代码，用于处理从基线编译外部 prologue 中反优化（deoptimization）的情况。它会清理 prologue 创建的栈帧，并跳转到解释器入口。
7. **`Builtins::Generate_InterpreterEntryTrampoline`**: 生成汇编代码，作为进入 JavaScript 函数解释器的入口点。它负责设置解释器栈帧，加载字节码，检查是否需要优化，并跳转到相应的字节码处理程序。
8. **`GenerateInterpreterPushArgs`**: 生成汇编代码，将函数参数压入栈中，为解释器调用做准备。
9. **`Builtins::Generate_InterpreterPushArgsThenCallImpl`**: 生成汇编代码，用于在将参数压入栈后通过解释器调用函数。它处理不同类型的接收者（receiver）绑定和 spread 语法。
10. **`Builtins::Generate_InterpreterPushArgsThenConstructImpl`**: 生成汇编代码，用于在将参数压入栈后通过解释器调用构造函数。
11. **`Builtins::Generate_ConstructForwardAllArgsImpl`**: 生成汇编代码，用于在构造函数调用中转发所有参数。
12. **`NewImplicitReceiver`**: 生成汇编代码，用于创建一个隐式的接收者对象，这通常发生在调用派生类的构造函数时。
13. **`Builtins::Generate_InterpreterPushArgsThenFastConstructFunction`**: 生成汇编代码，用于一种优化的构造函数调用路径，在满足特定条件时使用，例如当调用的是一个内置函数时。
14. **`Generate_InterpreterEnterBytecode`**: 生成汇编代码，用于进入解释器的字节码执行阶段。它设置返回地址，加载分发表格，并跳转到相应的字节码。

**Torque 源代码检查:**

`v8/src/builtins/loong64/builtins-loong64.cc` 的文件名以 `.cc` 结尾，而不是 `.tq`。因此，它不是一个 V8 Torque 源代码。它是一个使用汇编宏的 C++ 源代码。

**与 JavaScript 功能的关系及示例:**

这些内置函数直接支持 JavaScript 的各种核心功能。以下是一些示例：

* **函数调用:** `Builtins::Generate_InterpreterEntryTrampoline`, `Builtins::Generate_InterpreterPushArgsThenCallImpl` 等函数负责 JavaScript 函数的调用过程。

```javascript
function foo(a, b) {
  return a + b;
}

foo(1, 2); // 这个调用会触发解释器入口以及参数压栈等操作。
```

* **构造函数调用:** `Builtins::Generate_InterpreterPushArgsThenConstructImpl`, `Builtins::Generate_InterpreterPushArgsThenFastConstructFunction` 等函数负责 `new` 关键字的执行。

```javascript
class MyClass {
  constructor(value) {
    this.value = value;
  }
}

const obj = new MyClass(5); // 这个构造函数调用会触发相应的内置函数。
```

* **类继承:** `NewImplicitReceiver` 和 `Builtins::Generate_ConstructForwardAllArgsImpl` 与 JavaScript 的类继承机制有关。

```javascript
class Base {
  constructor(x) {
    this.x = x;
  }
}

class Derived extends Base {
  constructor(x, y) {
    super(x); // super() 调用会涉及参数转发。
    this.y = y;
  }
}

const derivedObj = new Derived(10, 20);
```

**代码逻辑推理 (假设输入与输出):**

以 `AdvanceBytecodeOffsetOrReturn` 为例：

**假设输入:**

* `bytecode` 寄存器包含当前正在执行的字节码的值 (例如，代表 `LdaSmi` 的字节码)。
* `bytecode_offset` 寄存器包含当前字节码的偏移量 (例如，10)。
* `bytecode_size_table` 寄存器指向字节码大小查找表。

**输出:**

* 如果 `bytecode` 代表的不是 `JumpLoop`，`bytecode_offset` 寄存器将被更新为下一个字节码的偏移量。例如，如果 `LdaSmi` 的大小是 1，那么 `bytecode_offset` 将变为 11。
* 如果 `bytecode` 代表的是 `JumpLoop`，则会跳转到 `end` 标签，并且 `bytecode_offset` 的值保持不变 (或者恢复到 `original_bytecode_offset`)。

**涉及用户常见的编程错误:**

* **栈溢出:**  代码中多次出现 `__ StackOverflowCheck` 和跳转到 `stack_overflow` 标签。用户编写的可能导致无限递归的 JavaScript 代码会触发这种错误。

```javascript
function recursiveFunction() {
  recursiveFunction(); // 缺少终止条件，导致无限递归
}

recursiveFunction(); // 这会导致栈溢出
```

* **调用非构造函数:** `Builtins::Generate_InterpreterPushArgsThenFastConstructFunction` 中检查了目标是否为构造函数，并在不是构造函数时跳转到 `non_constructor` 标签。用户尝试 `new` 一个普通函数或对象时会触发此错误。

```javascript
function normalFunction() {
  return 5;
}

const obj = new normalFunction(); // TypeError: normalFunction is not a constructor
```

**归纳一下它的功能 (第 2 部分):**

这部分代码主要定义了 LoongArch64 架构下 V8 引擎中与 JavaScript 函数调用和构造过程密切相关的内置函数的汇编代码生成逻辑。它涵盖了从解释器入口、参数处理、栈帧设置、到基线编译的 prologue 和 deoptimization 等关键环节。这些内置函数是 V8 引擎执行 JavaScript 代码的基础。

Prompt: 
```
这是目录为v8/src/builtins/loong64/builtins-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/loong64/builtins-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能

"""
MP_IF_EQUAL)
#undef JUMP_IF_EQUAL

  // If this is a JumpLoop, re-execute it to perform the jump to the beginning
  // of the loop.
  Label end, not_jump_loop;
  __ Branch(&not_jump_loop, ne, bytecode,
            Operand(static_cast<int>(interpreter::Bytecode::kJumpLoop)));
  // We need to restore the original bytecode_offset since we might have
  // increased it to skip the wide / extra-wide prefix bytecode.
  __ Move(bytecode_offset, original_bytecode_offset);
  __ jmp(&end);

  __ bind(&not_jump_loop);
  // Otherwise, load the size of the current bytecode and advance the offset.
  __ Add_d(scratch2, bytecode_size_table, bytecode);
  __ Ld_b(scratch2, MemOperand(scratch2, 0));
  __ Add_d(bytecode_offset, bytecode_offset, scratch2);

  __ bind(&end);
}

namespace {

void ResetSharedFunctionInfoAge(MacroAssembler* masm, Register sfi) {
  __ St_h(zero_reg, FieldMemOperand(sfi, SharedFunctionInfo::kAgeOffset));
}

void ResetJSFunctionAge(MacroAssembler* masm, Register js_function,
                        Register scratch) {
  __ LoadTaggedField(
      scratch,
      FieldMemOperand(js_function, JSFunction::kSharedFunctionInfoOffset));
  ResetSharedFunctionInfoAge(masm, scratch);
}

void ResetFeedbackVectorOsrUrgency(MacroAssembler* masm,
                                   Register feedback_vector, Register scratch) {
  DCHECK(!AreAliased(feedback_vector, scratch));
  __ Ld_bu(scratch,
           FieldMemOperand(feedback_vector, FeedbackVector::kOsrStateOffset));
  __ And(scratch, scratch, Operand(~FeedbackVector::OsrUrgencyBits::kMask));
  __ St_b(scratch,
          FieldMemOperand(feedback_vector, FeedbackVector::kOsrStateOffset));
}

}  // namespace

// static
void Builtins::Generate_BaselineOutOfLinePrologue(MacroAssembler* masm) {
  UseScratchRegisterScope temps(masm);
  temps.Include({s1, s2, s3});
  temps.Exclude({t7});
  auto descriptor =
      Builtins::CallInterfaceDescriptorFor(Builtin::kBaselineOutOfLinePrologue);
  Register closure = descriptor.GetRegisterParameter(
      BaselineOutOfLinePrologueDescriptor::kClosure);
  // Load the feedback cell and vector from the closure.
  Register feedback_cell = temps.Acquire();
  Register feedback_vector = temps.Acquire();
  __ LoadTaggedField(feedback_cell,
                     FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
  __ LoadTaggedField(
      feedback_vector,
      FieldMemOperand(feedback_cell, FeedbackCell::kValueOffset));
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    __ AssertFeedbackVector(feedback_vector, scratch);
  }
  // Check for an tiering state.
  Label flags_need_processing;
  Register flags = no_reg;
  {
    UseScratchRegisterScope temps(masm);
    flags = temps.Acquire();
    // flags will be used only in |flags_need_processing|
    // and outside it can be reused.
    __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
        flags, feedback_vector, CodeKind::BASELINE, &flags_need_processing);
  }
  {
    UseScratchRegisterScope temps(masm);
    ResetFeedbackVectorOsrUrgency(masm, feedback_vector, temps.Acquire());
  }
  // Increment invocation count for the function.
  {
    UseScratchRegisterScope temps(masm);
    Register invocation_count = temps.Acquire();
    __ Ld_w(invocation_count,
            FieldMemOperand(feedback_vector,
                            FeedbackVector::kInvocationCountOffset));
    __ Add_w(invocation_count, invocation_count, Operand(1));
    __ St_w(invocation_count,
            FieldMemOperand(feedback_vector,
                            FeedbackVector::kInvocationCountOffset));
  }

  FrameScope frame_scope(masm, StackFrame::MANUAL);
  {
    ASM_CODE_COMMENT_STRING(masm, "Frame Setup");
    // Normally the first thing we'd do here is Push(ra, fp), but we already
    // entered the frame in BaselineCompiler::Prologue, as we had to use the
    // value ra before the call to this BaselineOutOfLinePrologue builtin.
    Register callee_context = descriptor.GetRegisterParameter(
        BaselineOutOfLinePrologueDescriptor::kCalleeContext);
    Register callee_js_function = descriptor.GetRegisterParameter(
        BaselineOutOfLinePrologueDescriptor::kClosure);
    {
      UseScratchRegisterScope temps(masm);
      ResetJSFunctionAge(masm, callee_js_function, temps.Acquire());
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

    {
      UseScratchRegisterScope temps(masm);
      Register invocation_count = temps.Acquire();
      __ AssertFeedbackVector(feedback_vector, invocation_count);
    }
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
    Register sp_minus_frame_size = temps.Acquire();
    __ Sub_d(sp_minus_frame_size, sp, frame_size);
    Register interrupt_limit = temps.Acquire();
    __ LoadStackLimit(interrupt_limit,
                      MacroAssembler::StackLimitKind::kInterruptStackLimit);
    __ Branch(&call_stack_guard, Uless, sp_minus_frame_size,
              Operand(interrupt_limit));
  }

  // Do "fast" return to the caller pc in ra.
  // TODO(v8:11429): Document this frame setup better.
  __ Ret();

  __ bind(&flags_need_processing);
  {
    ASM_CODE_COMMENT_STRING(masm, "Optimized marker check");
    UseScratchRegisterScope temps(masm);
    temps.Exclude(flags);
    // Ensure the flags is not allocated again.
    // Drop the frame created by the baseline call.
    __ Pop(ra, fp);
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
  __ Ret();
  temps.Exclude({s1, s2, s3});
}

// static
void Builtins::Generate_BaselineOutOfLinePrologueDeopt(MacroAssembler* masm) {
  // We're here because we got deopted during BaselineOutOfLinePrologue's stack
  // check. Undo all its frame creation and call into the interpreter instead.

  // Drop the feedback vector, the bytecode offset (was the feedback vector
  // but got replaced during deopt) and bytecode array.
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
//   o a0 : actual argument count
//   o a1: the JS function object being called.
//   o a3: the incoming new target or generator object
//   o a4: the dispatch handle through which we were called
//   o cp: our context
//   o fp: the caller's frame pointer
//   o sp: stack pointer
//   o ra: return address
//
// The function builds an interpreter frame.  See InterpreterFrameConstants in
// frame-constants.h for its layout.
void Builtins::Generate_InterpreterEntryTrampoline(
    MacroAssembler* masm, InterpreterEntryTrampolineMode mode) {
  Register closure = a1;

  // Get the bytecode array from the function object and load it into
  // kInterpreterBytecodeArrayRegister.
  Register sfi = a5;
  __ LoadTaggedField(
      sfi, FieldMemOperand(closure, JSFunction::kSharedFunctionInfoOffset));
  ResetSharedFunctionInfoAge(masm, sfi);


  // The bytecode array could have been flushed from the shared function info,
  // if so, call into CompileLazy.
  Label is_baseline, compile_lazy;
  GetSharedFunctionInfoBytecodeOrBaseline(
      masm, sfi, kInterpreterBytecodeArrayRegister, kScratchReg, &is_baseline,
      &compile_lazy);

  Label push_stack_frame;
  Register feedback_vector = a2;
  __ LoadFeedbackVector(feedback_vector, closure, a5, &push_stack_frame);

#ifndef V8_JITLESS
  // If feedback vector is valid, check for optimized code and update invocation
  // count.

  // Check the tiering state.
  Label flags_need_processing;
  Register flags = a5;
  __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
      flags, feedback_vector, CodeKind::INTERPRETED_FUNCTION,
      &flags_need_processing);

  ResetFeedbackVectorOsrUrgency(masm, feedback_vector, a5);

  // Increment invocation count for the function.
  __ Ld_w(a5, FieldMemOperand(feedback_vector,
                              FeedbackVector::kInvocationCountOffset));
  __ Add_w(a5, a5, Operand(1));
  __ St_w(a5, FieldMemOperand(feedback_vector,
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

  // Load initial bytecode offset.
  __ li(kInterpreterBytecodeOffsetRegister,
        Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));

  // Push bytecode array, Smi tagged bytecode array offset and the feedback
  // vector.
  __ SmiTag(a5, kInterpreterBytecodeOffsetRegister);
  __ Push(kInterpreterBytecodeArrayRegister, a5, feedback_vector);

  // Allocate the local and temporary register file on the stack.
  Label stack_overflow;
  {
    // Load frame size (word) from the BytecodeArray object.
    __ Ld_w(a5, FieldMemOperand(kInterpreterBytecodeArrayRegister,
                                BytecodeArray::kFrameSizeOffset));

    // Do a stack check to ensure we don't go over the limit.
    __ Sub_d(a6, sp, Operand(a5));
    __ LoadStackLimit(a2, MacroAssembler::StackLimitKind::kRealStackLimit);
    __ Branch(&stack_overflow, lo, a6, Operand(a2));

    // If ok, push undefined as the initial value for all register file entries.
    Label loop_header;
    Label loop_check;
    __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
    __ Branch(&loop_check);
    __ bind(&loop_header);
    // TODO(rmcilroy): Consider doing more than one push per loop iteration.
    __ Push(kInterpreterAccumulatorRegister);
    // Continue loop if not done.
    __ bind(&loop_check);
    __ Sub_d(a5, a5, Operand(kSystemPointerSize));
    __ Branch(&loop_header, ge, a5, Operand(zero_reg));
  }

  // If the bytecode array has a valid incoming new target or generator object
  // register, initialize it with incoming value which was passed in a3.
  Label no_incoming_new_target_or_generator_register;
  __ Ld_w(a5, FieldMemOperand(
                  kInterpreterBytecodeArrayRegister,
                  BytecodeArray::kIncomingNewTargetOrGeneratorRegisterOffset));
  __ Branch(&no_incoming_new_target_or_generator_register, eq, a5,
            Operand(zero_reg));
  __ Alsl_d(a5, a5, fp, kSystemPointerSizeLog2, t7);
  __ St_d(a3, MemOperand(a5, 0));
  __ bind(&no_incoming_new_target_or_generator_register);

  // Perform interrupt stack check.
  // TODO(solanes): Merge with the real stack limit check above.
  Label stack_check_interrupt, after_stack_check_interrupt;
  __ LoadStackLimit(a5, MacroAssembler::StackLimitKind::kInterruptStackLimit);
  __ Branch(&stack_check_interrupt, lo, sp, Operand(a5));
  __ bind(&after_stack_check_interrupt);

  // The accumulator is already loaded with undefined.

  // Load the dispatch table into a register and dispatch to the bytecode
  // handler at the current bytecode offset.
  Label do_dispatch;
  __ bind(&do_dispatch);
  __ li(kInterpreterDispatchTableRegister,
        ExternalReference::interpreter_dispatch_table_address(masm->isolate()));
  __ Add_d(t5, kInterpreterBytecodeArrayRegister,
           kInterpreterBytecodeOffsetRegister);
  __ Ld_bu(a7, MemOperand(t5, 0));
  __ Alsl_d(kScratchReg, a7, kInterpreterDispatchTableRegister,
            kSystemPointerSizeLog2, t7);
  __ Ld_d(kJavaScriptCallCodeStartRegister, MemOperand(kScratchReg, 0));
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
  __ Ld_d(kInterpreterBytecodeArrayRegister,
          MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ Ld_d(kInterpreterBytecodeOffsetRegister,
          MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ SmiUntag(kInterpreterBytecodeOffsetRegister);

  // Either return, or advance to the next bytecode and dispatch.
  Label do_return;
  __ Add_d(a1, kInterpreterBytecodeArrayRegister,
           kInterpreterBytecodeOffsetRegister);
  __ Ld_bu(a1, MemOperand(a1, 0));
  AdvanceBytecodeOffsetOrReturn(masm, kInterpreterBytecodeArrayRegister,
                                kInterpreterBytecodeOffsetRegister, a1, a2, a3,
                                a5, &do_return);
  __ jmp(&do_dispatch);

  __ bind(&do_return);
  // The return value is in a0.
  LeaveInterpreterFrame(masm, t0, t1);
  __ Jump(ra);

  __ bind(&stack_check_interrupt);
  // Modify the bytecode offset in the stack to be kFunctionEntryBytecodeOffset
  // for the call to the StackGuard.
  __ li(kInterpreterBytecodeOffsetRegister,
        Operand(Smi::FromInt(BytecodeArray::kHeaderSize - kHeapObjectTag +
                             kFunctionEntryBytecodeOffset)));
  __ St_d(kInterpreterBytecodeOffsetRegister,
          MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ CallRuntime(Runtime::kStackGuard);

  // After the call, restore the bytecode array, bytecode offset and accumulator
  // registers again. Also, restore the bytecode offset in the stack to its
  // previous value.
  __ Ld_d(kInterpreterBytecodeArrayRegister,
          MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ li(kInterpreterBytecodeOffsetRegister,
        Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);

  __ SmiTag(a5, kInterpreterBytecodeOffsetRegister);
  __ St_d(a5, MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

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
        t0, FieldMemOperand(feedback_vector, HeapObject::kMapOffset));
    __ Ld_hu(t0, FieldMemOperand(t0, Map::kInstanceTypeOffset));
    __ Branch(&install_baseline_code, ne, t0, Operand(FEEDBACK_VECTOR_TYPE));

    // Check for an tiering state.
    __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
        flags, feedback_vector, CodeKind::BASELINE, &flags_need_processing);

#ifndef V8_ENABLE_LEAPTIERING
    // TODO(loong64, 42204201): This fastcase is difficult to support with the
    // sandbox as it requires getting write access to the dispatch table. See
    // `JSFunction::UpdateCode`. We might want to remove it for all
    // configurations as it does not seem to be performance sensitive.

    // Load the baseline code into the closure.
    __ Move(a2, kInterpreterBytecodeArrayRegister);
    static_assert(kJavaScriptCallCodeStartRegister == a2, "ABI mismatch");
    __ ReplaceClosureCodeWithOptimizedCode(a2, closure);
    __ JumpCodeObject(a2, kJSEntrypointTag);
#endif  // V8_ENABLE_LEAPTIERING

    __ bind(&install_baseline_code);
    __ GenerateTailCallToReturnedCode(Runtime::kInstallBaselineCode);
  }
#endif  // !V8_JITLESS

  __ bind(&compile_lazy);
  __ GenerateTailCallToReturnedCode(Runtime::kCompileLazy);
  // Unreachable code.
  __ break_(0xCC);

  __ bind(&stack_overflow);
  __ CallRuntime(Runtime::kThrowStackOverflow);
  // Unreachable code.
  __ break_(0xCC);
}

static void GenerateInterpreterPushArgs(MacroAssembler* masm, Register num_args,
                                        Register start_address,
                                        Register scratch, Register scratch2) {
  // Find the address of the last argument.
  __ Sub_d(scratch, num_args, Operand(1));
  __ slli_d(scratch, scratch, kSystemPointerSizeLog2);
  __ Sub_d(start_address, start_address, scratch);

  // Push the arguments.
  __ PushArray(start_address, num_args, scratch, scratch2,
               MacroAssembler::PushArrayOrder::kReverse);
}

// static
void Builtins::Generate_InterpreterPushArgsThenCallImpl(
    MacroAssembler* masm, ConvertReceiverMode receiver_mode,
    InterpreterPushArgsMode mode) {
  DCHECK(mode != InterpreterPushArgsMode::kArrayFunction);
  // ----------- S t a t e -------------
  //  -- a0 : the number of arguments
  //  -- a2 : the address of the first argument to be pushed. Subsequent
  //          arguments should be consecutive above this, in the same order as
  //          they are to be pushed onto the stack.
  //  -- a1 : the target to call (can be any Object).
  // -----------------------------------
  Label stack_overflow;
  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // The spread argument should not be pushed.
    __ Sub_d(a0, a0, Operand(1));
  }

  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    __ Sub_d(a3, a0, Operand(kJSArgcReceiverSlots));
  } else {
    __ mov(a3, a0);
  }

  __ StackOverflowCheck(a3, a4, t0, &stack_overflow);

  // This function modifies a2, t0 and a4.
  GenerateInterpreterPushArgs(masm, a3, a2, a4, t0);

  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    __ PushRoot(RootIndex::kUndefinedValue);
  }

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Pass the spread in the register a2.
    // a2 already points to the penultime argument, the spread
    // is below that.
    __ Ld_d(a2, MemOperand(a2, -kSystemPointerSize));
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
    // Unreachable code.
    __ break_(0xCC);
  }
}

// static
void Builtins::Generate_InterpreterPushArgsThenConstructImpl(
    MacroAssembler* masm, InterpreterPushArgsMode mode) {
  // ----------- S t a t e -------------
  // -- a0 : argument count
  // -- a3 : new target
  // -- a1 : constructor to call
  // -- a2 : allocation site feedback if available, undefined otherwise.
  // -- a4 : address of the first argument
  // -----------------------------------
  Label stack_overflow;
  __ StackOverflowCheck(a0, a5, t0, &stack_overflow);

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // The spread argument should not be pushed.
    __ Sub_d(a0, a0, Operand(1));
  }

  Register argc_without_receiver = a6;
  __ Sub_d(argc_without_receiver, a0, Operand(kJSArgcReceiverSlots));

  // Push the arguments, This function modifies t0, a4 and a5.
  GenerateInterpreterPushArgs(masm, argc_without_receiver, a4, a5, t0);

  // Push a slot for the receiver.
  __ Push(zero_reg);

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Pass the spread in the register a2.
    // a4 already points to the penultimate argument, the spread
    // lies in the next interpreter register.
    __ Ld_d(a2, MemOperand(a4, -kSystemPointerSize));
  } else {
    __ AssertUndefinedOrAllocationSite(a2, t0);
  }

  if (mode == InterpreterPushArgsMode::kArrayFunction) {
    __ AssertFunction(a1);

    // Tail call to the function-specific construct stub (still in the caller
    // context at this point).
    __ TailCallBuiltin(Builtin::kArrayConstructorImpl);
  } else if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Call the constructor with a0, a1, and a3 unmodified.
    __ TailCallBuiltin(Builtin::kConstructWithSpread);
  } else {
    DCHECK_EQ(InterpreterPushArgsMode::kOther, mode);
    // Call the constructor with a0, a1, and a3 unmodified.
    __ TailCallBuiltin(Builtin::kConstruct);
  }

  __ bind(&stack_overflow);
  {
    __ TailCallRuntime(Runtime::kThrowStackOverflow);
    // Unreachable code.
    __ break_(0xCC);
  }
}

// static
void Builtins::Generate_ConstructForwardAllArgsImpl(
    MacroAssembler* masm, ForwardWhichFrame which_frame) {
  // ----------- S t a t e -------------
  // -- a3 : new target
  // -- a1 : constructor to call
  // -----------------------------------
  Label stack_overflow;

  // Load the frame pointer into a4.
  switch (which_frame) {
    case ForwardWhichFrame::kCurrentFrame:
      __ Move(a4, fp);
      break;
    case ForwardWhichFrame::kParentFrame:
      __ Ld_d(a4, MemOperand(fp, StandardFrameConstants::kCallerFPOffset));
      break;
  }

  // Load the argument count into a0.
  __ Ld_d(a0, MemOperand(a4, StandardFrameConstants::kArgCOffset));
  __ StackOverflowCheck(a0, a5, t0, &stack_overflow);

  // Point a4 to the base of the argument list to forward, excluding the
  // receiver.
  __ Add_d(a4, a4,
           Operand((StandardFrameConstants::kFixedSlotCountAboveFp + 1) *
                   kSystemPointerSize));

  // Copy arguments on the stack. a5 and t0 are scratch registers.
  Register argc_without_receiver = a6;
  __ Sub_d(argc_without_receiver, a0, Operand(kJSArgcReceiverSlots));
  __ PushArray(a4, argc_without_receiver, a5, t0);

  // Push a slot for the receiver.
  __ Push(zero_reg);

  // Call the constructor with a0, a1, and a3 unmodified.
  __ TailCallBuiltin(Builtin::kConstruct);

  __ bind(&stack_overflow);
  {
    __ TailCallRuntime(Runtime::kThrowStackOverflow);
    __ break_(0xCC);
  }
}

namespace {

void NewImplicitReceiver(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  // -- a0 : the number of arguments
  // -- a1 : constructor to call (checked to be a JSFunction)
  // -- a3 : new target
  //
  //  Stack:
  //  -- Implicit Receiver
  //  -- [arguments without receiver]
  //  -- Implicit Receiver
  //  -- Context
  //  -- FastConstructMarker
  //  -- FramePointer
  // -----------------------------------
  Register implicit_receiver = a4;

  // Save live registers.
  __ SmiTag(a0);
  __ Push(a0, a1, a3);
  __ CallBuiltin(Builtin::kFastNewObject);
  // Save result.
  __ Move(implicit_receiver, a0);
  // Restore live registers.
  __ Pop(a0, a1, a3);
  __ SmiUntag(a0);

  // Patch implicit receiver (in arguments)
  __ StoreReceiver(implicit_receiver);
  // Patch second implicit (in construct frame)
  __ St_d(implicit_receiver,
          MemOperand(fp, FastConstructFrameConstants::kImplicitReceiverOffset));

  // Restore context.
  __ Ld_d(cp, MemOperand(fp, FastConstructFrameConstants::kContextOffset));
}

}  // namespace

// static
void Builtins::Generate_InterpreterPushArgsThenFastConstructFunction(
    MacroAssembler* masm) {
  // ----------- S t a t e -------------
  // -- a0 : argument count
  // -- a1 : constructor to call (checked to be a JSFunction)
  // -- a3 : new target
  // -- a4 : address of the first argument
  // -- cp : context pointer
  // -----------------------------------
  __ AssertFunction(a1);

  // Check if target has a [[Construct]] internal method.
  Label non_constructor;
  __ LoadMap(a2, a1);
  __ Ld_bu(a2, FieldMemOperand(a2, Map::kBitFieldOffset));
  __ And(a2, a2, Operand(Map::Bits1::IsConstructorBit::kMask));
  __ Branch(&non_constructor, eq, a2, Operand(zero_reg));

  // Add a stack check before pushing arguments.
  Label stack_overflow;
  __ StackOverflowCheck(a0, a2, a5, &stack_overflow);

  // Enter a construct frame.
  FrameScope scope(masm, StackFrame::MANUAL);
  __ EnterFrame(StackFrame::FAST_CONSTRUCT);

  // Implicit receiver stored in the construct frame.
  __ LoadRoot(a2, RootIndex::kTheHoleValue);
  __ Push(cp, a2);

  // Push arguments + implicit receiver.
  Register argc_without_receiver = a7;
  __ Sub_d(argc_without_receiver, a0, Operand(kJSArgcReceiverSlots));
  GenerateInterpreterPushArgs(masm, argc_without_receiver, a4, a5, a6);
  __ Push(a2);

  // Check if it is a builtin call.
  Label builtin_call;
  __ LoadTaggedField(
      a2, FieldMemOperand(a1, JSFunction::kSharedFunctionInfoOffset));
  __ Ld_wu(a2, FieldMemOperand(a2, SharedFunctionInfo::kFlagsOffset));
  __ And(a5, a2, Operand(SharedFunctionInfo::ConstructAsBuiltinBit::kMask));
  __ Branch(&builtin_call, ne, a5, Operand(zero_reg));

  // Check if we need to create an implicit receiver.
  Label not_create_implicit_receiver;
  __ DecodeField<SharedFunctionInfo::FunctionKindBits>(a2);
  __ JumpIfIsInRange(
      a2, static_cast<uint32_t>(FunctionKind::kDefaultDerivedConstructor),
      static_cast<uint32_t>(FunctionKind::kDerivedConstructor),
      &not_create_implicit_receiver);
  NewImplicitReceiver(masm);
  __ bind(&not_create_implicit_receiver);

  // Call the function.
  __ InvokeFunctionWithNewTarget(a1, a3, a0, InvokeType::kCall);

  // ----------- S t a t e -------------
  //  -- a0     constructor result
  //
  //  Stack:
  //  -- Implicit Receiver
  //  -- Context
  //  -- FastConstructMarker
  //  -- FramePointer
  // -----------------------------------

  // Store offset of return address for deoptimizer.
  masm->isolate()->heap()->SetConstructStubInvokeDeoptPCOffset(
      masm->pc_offset());

  // If the result is an object (in the ECMA sense), we should get rid
  // of the receiver and use the result; see ECMA-262 section 13.2.2-7
  // on page 74.
  Label use_receiver, do_throw, leave_and_return, check_receiver;

  // If the result is undefined, we jump out to using the implicit receiver.
  __ JumpIfNotRoot(a0, RootIndex::kUndefinedValue, &check_receiver);

  // Throw away the result of the constructor invocation and use the
  // on-stack receiver as the result.
  __ bind(&use_receiver);
  __ Ld_d(a0,
          MemOperand(fp, FastConstructFrameConstants::kImplicitReceiverOffset));
  __ JumpIfRoot(a0, RootIndex::kTheHoleValue, &do_throw);

  __ bind(&leave_and_return);
  // Leave construct frame.
  __ LeaveFrame(StackFrame::FAST_CONSTRUCT);
  __ Ret();

  // Otherwise we do a smi check and fall through to check if the return value
  // is a valid receiver.
  __ bind(&check_receiver);

  // If the result is a smi, it is *not* an object in the ECMA sense.
  __ JumpIfSmi(a0, &use_receiver);

  // Check if the type of the result is not an object in the ECMA sense.
  __ JumpIfJSAnyIsNotPrimitive(a0, a4, &leave_and_return);
  __ Branch(&use_receiver);

  __ bind(&builtin_call);
  // TODO(victorgomes): Check the possibility to turn this into a tailcall.
  __ InvokeFunctionWithNewTarget(a1, a3, a0, InvokeType::kCall);
  __ LeaveFrame(StackFrame::FAST_CONSTRUCT);
  __ Ret();

  __ bind(&do_throw);
  // Restore the context from the frame.
  __ Ld_d(cp, MemOperand(fp, FastConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowConstructorReturnedNonObject);
  // Unreachable code.
  __ break_(0xCC);

  __ bind(&stack_overflow);
  __ TailCallRuntime(Runtime::kThrowStackOverflow);
  // Unreachable code.
  __ break_(0xCC);

  // Called Construct on an Object that doesn't have a [[Construct]] internal
  // method.
  __ bind(&non_constructor);
  __ TailCallBuiltin(Builtin::kConstructedNonConstructable);
}

static void Generate_InterpreterEnterBytecode(MacroAssembler* masm) {
  // Set the return address to the correct point in the interpreter entry
  // trampoline.
  Label builtin_trampoline, trampoline_loaded;
  Tagged<Smi> interpreter_entry_return_pc_offset(
      masm->isolate()->heap()->interpreter_entry_return_pc_offset());
  DCHECK_NE(interpreter_entry_return_pc_offset, Smi::zero());

  // If the SFI function_data is an InterpreterData, the function will have a
  // custom copy of the interpreter entry trampoline for profiling. If so,
  // get the custom trampoline, otherwise grab the entry address of the global
  // trampoline.
  __ Ld_d(t0, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ LoadTaggedField(
      t0, FieldMemOperand(t0, JSFunction::kSharedFunctionInfoOffset));
  __ LoadTrustedPointerField(
      t0, FieldMemOperand(t0, SharedFunctionInfo::kTrustedFunctionDataOffset),
      kUnknownIndirectPointerTag);
  __ JumpIfObjectType(&builtin_trampoline, ne, t0, INTERPRETER_DATA_TYPE,
                      kInterpreterDispatchTableRegister);

  __ LoadProtectedPointerField(
      t0, FieldMemOperand(t0, InterpreterData::kInterpreterTrampolineOffset));
  __ LoadCodeInstructionStart(t0, t0, kJSEntrypointTag);
  __ Branch(&trampoline_loaded);

  __ bind(&builtin_trampoline);
  __ li(t0, ExternalReference::
                address_of_interpreter_entry_trampoline_instruction_start(
                    masm->isolate()));
  __ Ld_d(t0, MemOperand(t0, 0));

  __ bind(&trampoline_loaded);
  __ Add_d(ra, t0, Operand(interpreter_entry_return_pc_offset.value()));

  // Initialize the dispatch table register.
  __ li(kInterpreterDispatchTableRegister,
        ExternalReference::interpreter_dispatch_table_address(masm->isolate()));

  // Get the bytecode array pointer from the frame.
  __ Ld_d(kInterpreterBytecodeArrayRegister,
          MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));

  if (v8_flags.debug_code) {
    // Check function data field is actually a BytecodeArray object.
    __ SmiTst(kInterpreterBytecodeArrayRegister, kScratchReg);
    __ Assert(ne,
              AbortReason::kFunctionDataShouldBeBytecodeArrayOnInterpreterEntry,
              kScratchReg, Operand(zero_reg));
    __ GetObjectType(kInterpreterBytecodeArrayRegister, a1, a1);
    __ Assert(eq,
              AbortReason::kFunctionDataShouldBeBytecodeArrayOnInterpreterEntry,
              a1, Operand(BYTECODE_ARRAY_TYPE));
  }

  // Get the target bytecode offset from the frame.
  __ SmiUntag(kInterpreterBytecodeOffsetRegister,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

  if (v8_flags.debug_code) {
    Label okay;
    __ Branch(&okay, ge, kInterpreterBytecodeOffsetRegister,
              Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));
    // Unreachable code.
    __ break_(0xCC);
    __ bind(&okay);
  }

  // Dispatch to the target bytecode.
  __ Add_d(a1, kInterpreterBytecodeArrayRegister,
           kInterpreterBytecodeOffsetRegister);
  __ Ld_bu(a7, MemOperand(a1, 0));

"""


```