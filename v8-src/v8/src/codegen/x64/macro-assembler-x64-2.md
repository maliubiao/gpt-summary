Response: The user wants a summary of the functionality of the provided C++ code snippet. This is the third part of a larger file. The code is part of V8's x64 macro assembler. It seems to contain low-level operations for code generation. I should look for keywords and patterns to identify the main categories of functions.

Based on the function names and operations, I see:
- Assertions and checks for object types (functions, callable functions, bound functions, generator objects). These are likely used for debugging and enforcing type constraints.
- Counter manipulation (increment/decrement). These are probably related to performance monitoring or statistics.
- Function invocation (InvokeFunction, InvokeFunctionCode, InvokePrologue). This is a core part of executing JavaScript code.
- Stack manipulation (StackOverflowCheck, AllocateStackSpace, EnterFrame, LeaveFrame). These are essential for managing the call stack.
- Interaction with C++ functions (EnterExitFrame, LeaveExitFrame, CallCFunction, PrepareCallCFunction). This allows V8 to interact with native code.
- Memory management related operations (LoadWeakValue, MemoryChunkHeaderFromObject, CheckPageFlag, CheckMarkBit). These are crucial for garbage collection and memory safety.
- Operations related to optimized code (TryLoadOptimizedOsrCode, BailoutIfDeoptimized, CallForDeoptimization). This indicates support for optimizing JavaScript execution.
- Debugging and error handling (Trap, DebugBreak).
- Calling API functions (CallApiFunctionAndReturn).

Considering that this is the *third part* of the file, the earlier parts likely dealt with more fundamental assembly operations and register manipulations. This part seems to focus on higher-level operations built on top of those primitives.

Regarding the connection to JavaScript, the function invocation, type assertions, and interaction with C++ APIs are directly related to how JavaScript code is executed within V8.

I can provide JavaScript examples that would lead to the execution of some of these functions. For instance, calling a function in JavaScript would trigger the `InvokeFunction` family of functions. Assertions relate to JavaScript type checking. Calling native C++ methods from JavaScript would use `CallCFunction`.
这是V8 JavaScript引擎中用于x64架构的代码生成器（MacroAssembler）的C++源代码文件的一部分。**这部分代码主要负责实现一些高级的、与JavaScript执行密切相关的操作和辅助功能。**

概括来说，这部分代码的功能包括：

1. **类型断言和检查:**  提供了一系列用于在生成代码中插入断言的函数，以确保操作的对象符合预期的类型。这在调试和验证代码的正确性方面非常重要。例如，`AssertFunction`、`AssertCallableFunction`、`AssertBoundFunction`、`AssertGeneratorObject` 等函数用于检查寄存器中存储的对象是否为特定类型的JavaScript对象。

2. **性能计数器操作:** 提供了递增和递减性能计数器的功能 (`EmitIncrementCounter`, `EmitDecrementCounter`)，用于在运行时收集性能数据。

3. **函数调用:** 实现了JavaScript函数的调用机制 (`InvokeFunction`, `InvokeFunctionCode`, `InvokePrologue`)，包括处理参数、设置调用栈、以及在需要时调用调试钩子。这部分代码负责在x64架构上执行JavaScript函数调用。

4. **堆栈管理:**  提供了用于堆栈操作的函数，如堆栈溢出检查 (`StackOverflowCheck`)、分配堆栈空间 (`AllocateStackSpace`)、进入和离开函数调用栈帧 (`EnterFrame`, `LeaveFrame`) 等。这些是函数调用和执行的基础。

5. **与C++函数的交互:**  提供了与C++函数进行交互的功能 (`EnterExitFrame`, `LeaveExitFrame`, `CallCFunction`, `PrepareCallCFunction`)。这使得JavaScript可以调用V8引擎或外部C++代码。

6. **弱引用加载:** 提供了加载弱引用的功能 (`LoadWeakValue`)，用于处理可能被垃圾回收的对象。

7. **优化代码加载:**  提供了尝试加载优化过的代码的机制 (`TryLoadOptimizedOsrCode`)，这是V8引擎进行性能优化的关键部分。

8. **代码去优化处理:** 提供了在代码需要去优化时执行的操作 (`BailoutIfDeoptimized`, `CallForDeoptimization`)。

9. **调试辅助:** 提供了用于插入断点 (`Trap`, `DebugBreak`) 的功能。

10. **调用API函数:**  提供了调用V8 C++ API 函数的机制 (`CallApiFunctionAndReturn`)，用于执行由JavaScript调用的原生函数。

11. **内存管理相关的辅助功能:** 提供了访问内存块头信息、检查页标志位、检查标记位等功能，这些都与垃圾回收机制密切相关。

**与JavaScript的功能关系及示例:**

这部分代码直接参与了JavaScript代码的执行过程。以下是一些JavaScript示例，以及它们可能如何与这些C++函数关联：

**1. 函数调用:**

```javascript
function myFunction(a, b) {
  return a + b;
}

myFunction(1, 2);
```

当调用 `myFunction(1, 2)` 时，V8会生成相应的机器码，其中会调用 `InvokeFunction` 或 `InvokeFunctionCode`  来执行函数。`InvokePrologue` 会处理参数的传递和堆栈的设置。

**2. 类型检查:**

```javascript
function process(arg) {
  if (typeof arg === 'function') {
    arg();
  } else {
    console.log('Argument is not a function');
  }
}

process(() => console.log('Hello'));
```

在编译 `process` 函数时，V8可能会在 `if` 语句处插入类似 `AssertCallableFunction` 的检查，以确保 `arg` 在运行时确实是一个函数，从而进行优化或在调试时提供错误信息。

**3. 调用原生C++方法:**

```javascript
// 假设在C++中注册了一个名为 'myNativeFunction' 的函数
const result = myNativeFunction(10);
```

当JavaScript调用 `myNativeFunction` 时，V8会通过 `CallCFunction` 或 `CallApiFunctionAndReturn` 将调用桥接到C++代码。`EnterExitFrame` 和 `LeaveExitFrame` 会管理从JavaScript到C++的调用栈帧的切换。

**4. 性能监控:**

虽然开发者通常不直接调用性能计数器操作，但V8内部会使用 `EmitIncrementCounter` 等函数来记录各种事件，用于性能分析和优化。

**总结:**

这部分 `macro-assembler-x64.cc` 代码是V8引擎在x64架构上执行JavaScript代码的关键组成部分。它提供了一组用于生成高效、安全且可调试的机器码的构建块，涵盖了函数调用、类型检查、堆栈管理、与C++的交互以及性能监控等核心功能。 这些底层操作支撑着JavaScript代码的正常执行和优化。

Prompt: 
```
这是目录为v8/src/codegen/x64/macro-assembler-x64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
eason::kOperandIsASmiAndNotAFunction);
  Push(object);
  LoadMap(object, object);
  CmpInstanceTypeRange(object, object, FIRST_JS_FUNCTION_TYPE,
                       LAST_JS_FUNCTION_TYPE);
  Pop(object);
  Check(below_equal, AbortReason::kOperandIsNotAFunction);
}

void MacroAssembler::AssertCallableFunction(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  testb(object, Immediate(kSmiTagMask));
  Check(not_equal, AbortReason::kOperandIsASmiAndNotAFunction);
  Push(object);
  LoadMap(object, object);
  CmpInstanceTypeRange(object, object, FIRST_CALLABLE_JS_FUNCTION_TYPE,
                       LAST_CALLABLE_JS_FUNCTION_TYPE);
  Pop(object);
  Check(below_equal, AbortReason::kOperandIsNotACallableFunction);
}

void MacroAssembler::AssertBoundFunction(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  testb(object, Immediate(kSmiTagMask));
  Check(not_equal, AbortReason::kOperandIsASmiAndNotABoundFunction);
  Push(object);
  IsObjectType(object, JS_BOUND_FUNCTION_TYPE, object);
  Pop(object);
  Check(equal, AbortReason::kOperandIsNotABoundFunction);
}

void MacroAssembler::AssertGeneratorObject(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  testb(object, Immediate(kSmiTagMask));
  Check(not_equal, AbortReason::kOperandIsASmiAndNotAGeneratorObject);

  // Load map
  Register map = object;
  Push(object);
  LoadMap(map, object);

  // Check if JSGeneratorObject
  CmpInstanceTypeRange(map, kScratchRegister, FIRST_JS_GENERATOR_OBJECT_TYPE,
                       LAST_JS_GENERATOR_OBJECT_TYPE);
  // Restore generator object to register and perform assertion
  Pop(object);
  Check(below_equal, AbortReason::kOperandIsNotAGeneratorObject);
}

void MacroAssembler::AssertUndefinedOrAllocationSite(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  Label done_checking;
  AssertNotSmi(object);
  Cmp(object, isolate()->factory()->undefined_value());
  j(equal, &done_checking);
  Register map = object;
  Push(object);
  LoadMap(map, object);
  Cmp(map, isolate()->factory()->allocation_site_map());
  Pop(object);
  Assert(equal, AbortReason::kExpectedUndefinedOrCell);
  bind(&done_checking);
}

void MacroAssembler::AssertJSAny(Register object, Register map_tmp,
                                 AbortReason abort_reason) {
  if (!v8_flags.debug_code) return;

  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(object, map_tmp));
  Label ok;

  Label::Distance dist = DEBUG_BOOL ? Label::kFar : Label::kNear;

  JumpIfSmi(object, &ok, dist);

  LoadMap(map_tmp, object);
  CmpInstanceType(map_tmp, LAST_NAME_TYPE);
  j(below_equal, &ok, dist);

  CmpInstanceType(map_tmp, FIRST_JS_RECEIVER_TYPE);
  j(above_equal, &ok, dist);

  CompareRoot(map_tmp, RootIndex::kHeapNumberMap);
  j(equal, &ok, dist);

  CompareRoot(map_tmp, RootIndex::kBigIntMap);
  j(equal, &ok, dist);

  CompareRoot(object, RootIndex::kUndefinedValue);
  j(equal, &ok, dist);

  CompareRoot(object, RootIndex::kTrueValue);
  j(equal, &ok, dist);

  CompareRoot(object, RootIndex::kFalseValue);
  j(equal, &ok, dist);

  CompareRoot(object, RootIndex::kNullValue);
  j(equal, &ok, dist);

  Abort(abort_reason);

  bind(&ok);
}

void MacroAssembler::Assert(Condition cc, AbortReason reason) {
  if (v8_flags.debug_code) Check(cc, reason);
}

void MacroAssembler::AssertUnreachable(AbortReason reason) {
  if (v8_flags.debug_code) Abort(reason);
}
#endif  // V8_ENABLE_DEBUG_CODE

void MacroAssembler::LoadWeakValue(Register in_out, Label* target_if_cleared) {
  cmpl(in_out, Immediate(kClearedWeakHeapObjectLower32));
  j(equal, target_if_cleared);

  andq(in_out, Immediate(~static_cast<int32_t>(kWeakHeapObjectMask)));
}

void MacroAssembler::EmitIncrementCounter(StatsCounter* counter, int value) {
  DCHECK_GT(value, 0);
  if (v8_flags.native_code_counters && counter->Enabled()) {
    ASM_CODE_COMMENT(this);
    Operand counter_operand =
        ExternalReferenceAsOperand(ExternalReference::Create(counter));
    // This operation has to be exactly 32-bit wide in case the external
    // reference table redirects the counter to a uint32_t dummy_stats_counter_
    // field.
    if (value == 1) {
      incl(counter_operand);
    } else {
      addl(counter_operand, Immediate(value));
    }
  }
}

void MacroAssembler::EmitDecrementCounter(StatsCounter* counter, int value) {
  DCHECK_GT(value, 0);
  if (v8_flags.native_code_counters && counter->Enabled()) {
    ASM_CODE_COMMENT(this);
    Operand counter_operand =
        ExternalReferenceAsOperand(ExternalReference::Create(counter));
    // This operation has to be exactly 32-bit wide in case the external
    // reference table redirects the counter to a uint32_t dummy_stats_counter_
    // field.
    if (value == 1) {
      decl(counter_operand);
    } else {
      subl(counter_operand, Immediate(value));
    }
  }
}

#ifdef V8_ENABLE_LEAPTIERING
void MacroAssembler::InvokeFunction(
    Register function, Register new_target, Register actual_parameter_count,
    InvokeType type, ArgumentAdaptionMode argument_adaption_mode) {
  ASM_CODE_COMMENT(this);
  DCHECK_EQ(function, rdi);
  LoadTaggedField(rsi, FieldOperand(function, JSFunction::kContextOffset));
  InvokeFunctionCode(rdi, new_target, actual_parameter_count, type,
                     argument_adaption_mode);
}

void MacroAssembler::InvokeFunctionCode(
    Register function, Register new_target, Register actual_parameter_count,
    InvokeType type, ArgumentAdaptionMode argument_adaption_mode) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());
  DCHECK_EQ(function, rdi);
  DCHECK_IMPLIES(new_target.is_valid(), new_target == rdx);

  Register dispatch_handle = kJavaScriptCallDispatchHandleRegister;
  movl(dispatch_handle,
       FieldOperand(function, JSFunction::kDispatchHandleOffset));

  AssertFunction(function);

  // On function call, call into the debugger if necessary.
  Label debug_hook, continue_after_hook;
  {
    ExternalReference debug_hook_active =
        ExternalReference::debug_hook_on_function_call_address(isolate());
    Operand debug_hook_active_operand =
        ExternalReferenceAsOperand(debug_hook_active);
    cmpb(debug_hook_active_operand, Immediate(0));
    j(not_equal, &debug_hook);
  }
  bind(&continue_after_hook);

  // Clear the new.target register if not given.
  if (!new_target.is_valid()) {
    LoadRoot(rdx, RootIndex::kUndefinedValue);
  }

  if (argument_adaption_mode == ArgumentAdaptionMode::kAdapt) {
    Register expected_parameter_count = rbx;
    LoadParameterCountFromJSDispatchTable(expected_parameter_count,
                                          dispatch_handle);
    InvokePrologue(expected_parameter_count, actual_parameter_count, type);
  }

  // We call indirectly through the code field in the function to
  // allow recompilation to take effect without changing any of the
  // call sites.
  static_assert(kJavaScriptCallCodeStartRegister == rcx, "ABI mismatch");
  LoadEntrypointFromJSDispatchTable(rcx, dispatch_handle);
  switch (type) {
    case InvokeType::kCall:
      call(rcx);
      break;
    case InvokeType::kJump:
      jmp(rcx);
      break;
  }
  Label done;
  jmp(&done, Label::kNear);

  // Deferred debug hook.
  bind(&debug_hook);
  CallDebugOnFunctionCall(function, new_target, dispatch_handle,
                          actual_parameter_count);
  jmp(&continue_after_hook);

  bind(&done);
}
#else
void MacroAssembler::InvokeFunction(Register function, Register new_target,
                                    Register actual_parameter_count,
                                    InvokeType type) {
  ASM_CODE_COMMENT(this);
  LoadTaggedField(
      rbx, FieldOperand(function, JSFunction::kSharedFunctionInfoOffset));
  movzxwq(rbx,
          FieldOperand(rbx, SharedFunctionInfo::kFormalParameterCountOffset));

  InvokeFunction(function, new_target, rbx, actual_parameter_count, type);
}

void MacroAssembler::InvokeFunction(Register function, Register new_target,
                                    Register expected_parameter_count,
                                    Register actual_parameter_count,
                                    InvokeType type) {
  DCHECK_EQ(function, rdi);
  LoadTaggedField(rsi, FieldOperand(function, JSFunction::kContextOffset));
  InvokeFunctionCode(rdi, new_target, expected_parameter_count,
                     actual_parameter_count, type);
}

void MacroAssembler::InvokeFunctionCode(Register function, Register new_target,
                                        Register expected_parameter_count,
                                        Register actual_parameter_count,
                                        InvokeType type) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());
  DCHECK_EQ(function, rdi);
  DCHECK_IMPLIES(new_target.is_valid(), new_target == rdx);

  AssertFunction(function);

  // On function call, call into the debugger if necessary.
  Label debug_hook, continue_after_hook;
  {
    ExternalReference debug_hook_active =
        ExternalReference::debug_hook_on_function_call_address(isolate());
    Operand debug_hook_active_operand =
        ExternalReferenceAsOperand(debug_hook_active);
    cmpb(debug_hook_active_operand, Immediate(0));
    j(not_equal, &debug_hook);
  }
  bind(&continue_after_hook);

  // Clear the new.target register if not given.
  if (!new_target.is_valid()) {
    LoadRoot(rdx, RootIndex::kUndefinedValue);
  }

  Label done;
  InvokePrologue(expected_parameter_count, actual_parameter_count, type);
  // We call indirectly through the code field in the function to
  // allow recompilation to take effect without changing any of the
  // call sites.
  static_assert(kJavaScriptCallCodeStartRegister == rcx, "ABI mismatch");
  constexpr int unused_argument_count = 0;
  switch (type) {
    case InvokeType::kCall:
      CallJSFunction(function, unused_argument_count);
      break;
    case InvokeType::kJump:
      JumpJSFunction(function);
      break;
  }
  jmp(&done, Label::kNear);

  // Deferred debug hook.
  bind(&debug_hook);
  CallDebugOnFunctionCall(function, new_target, expected_parameter_count,
                          actual_parameter_count);
  jmp(&continue_after_hook);

  bind(&done);
}
#endif  // V8_ENABLE_LEAPTIERING

Operand MacroAssembler::StackLimitAsOperand(StackLimitKind kind) {
  DCHECK(root_array_available());
  intptr_t offset = kind == StackLimitKind::kRealStackLimit
                        ? IsolateData::real_jslimit_offset()
                        : IsolateData::jslimit_offset();

  CHECK(is_int32(offset));
  return Operand(kRootRegister, static_cast<int32_t>(offset));
}

void MacroAssembler::StackOverflowCheck(
    Register num_args, Label* stack_overflow,
    Label::Distance stack_overflow_distance) {
  ASM_CODE_COMMENT(this);
  DCHECK_NE(num_args, kScratchRegister);
  // Check the stack for overflow. We are not trying to catch
  // interruptions (e.g. debug break and preemption) here, so the "real stack
  // limit" is checked.
  movq(kScratchRegister, rsp);
  // Make kScratchRegister the space we have left. The stack might already be
  // overflowed here which will cause kScratchRegister to become negative.
  subq(kScratchRegister, StackLimitAsOperand(StackLimitKind::kRealStackLimit));
  // TODO(victorgomes): Use ia32 approach with leaq, since it requires less
  // instructions.
  sarq(kScratchRegister, Immediate(kSystemPointerSizeLog2));
  // Check if the arguments will overflow the stack.
  cmpq(kScratchRegister, num_args);
  // Signed comparison.
  // TODO(victorgomes):  Save some bytes in the builtins that use stack checks
  // by jumping to a builtin that throws the exception.
  j(less_equal, stack_overflow, stack_overflow_distance);
}

void MacroAssembler::InvokePrologue(Register expected_parameter_count,
                                    Register actual_parameter_count,
                                    InvokeType type) {
    ASM_CODE_COMMENT(this);
    if (expected_parameter_count == actual_parameter_count) {
      Move(rax, actual_parameter_count);
      return;
    }
    Label regular_invoke;

    // If overapplication or if the actual argument count is equal to the
    // formal parameter count, no need to push extra undefined values.
    subq(expected_parameter_count, actual_parameter_count);
    j(less_equal, &regular_invoke, Label::kFar);

    Label stack_overflow;
    StackOverflowCheck(expected_parameter_count, &stack_overflow);

    // Underapplication. Move the arguments already in the stack, including the
    // receiver and the return address.
    {
      Label copy, check;
      Register src = r8, dest = rsp, num = r9, current = r11;
      movq(src, rsp);
      leaq(kScratchRegister,
           Operand(expected_parameter_count, times_system_pointer_size, 0));
      AllocateStackSpace(kScratchRegister);
      // Extra words are for the return address (if a jump).
      int extra_words =
          type == InvokeType::kCall ? 0 : kReturnAddressStackSlotCount;

      leaq(num, Operand(rax, extra_words));  // Number of words to copy.
      Move(current, 0);
      // Fall-through to the loop body because there are non-zero words to copy.
      bind(&copy);
      movq(kScratchRegister,
           Operand(src, current, times_system_pointer_size, 0));
      movq(Operand(dest, current, times_system_pointer_size, 0),
           kScratchRegister);
      incq(current);
      bind(&check);
      cmpq(current, num);
      j(less, &copy);
      leaq(r8, Operand(rsp, num, times_system_pointer_size, 0));
    }
    // Fill remaining expected arguments with undefined values.
    LoadRoot(kScratchRegister, RootIndex::kUndefinedValue);
    {
      Label loop;
      bind(&loop);
      decq(expected_parameter_count);
      movq(Operand(r8, expected_parameter_count, times_system_pointer_size, 0),
           kScratchRegister);
      j(greater, &loop, Label::kNear);
    }
    jmp(&regular_invoke);

    bind(&stack_overflow);
    {
      FrameScope frame(
          this, has_frame() ? StackFrame::NO_FRAME_TYPE : StackFrame::INTERNAL);
      CallRuntime(Runtime::kThrowStackOverflow);
      int3();  // This should be unreachable.
    }
    bind(&regular_invoke);
}

void MacroAssembler::CallDebugOnFunctionCall(
    Register fun, Register new_target,
    Register expected_parameter_count_or_dispatch_handle,
    Register actual_parameter_count) {
  ASM_CODE_COMMENT(this);
  // Load receiver to pass it later to DebugOnFunctionCall hook.
  // Receiver is located on top of the stack if we have a frame (usually a
  // construct frame), or after the return address if we do not yet have a
  // frame.
  movq(kScratchRegister, Operand(rsp, has_frame() ? 0 : kSystemPointerSize));

  FrameScope frame(
      this, has_frame() ? StackFrame::NO_FRAME_TYPE : StackFrame::INTERNAL);

  SmiTag(expected_parameter_count_or_dispatch_handle);
  Push(expected_parameter_count_or_dispatch_handle);

  SmiTag(actual_parameter_count);
  Push(actual_parameter_count);
  SmiUntag(actual_parameter_count);

  if (new_target.is_valid()) {
    Push(new_target);
  }
  Push(fun);
  Push(fun);
  Push(kScratchRegister);
  CallRuntime(Runtime::kDebugOnFunctionCall);
  Pop(fun);
  if (new_target.is_valid()) {
    Pop(new_target);
  }
  Pop(actual_parameter_count);
  SmiUntag(actual_parameter_count);
  Pop(expected_parameter_count_or_dispatch_handle);
  SmiUntag(expected_parameter_count_or_dispatch_handle);
}

void MacroAssembler::StubPrologue(StackFrame::Type type) {
  ASM_CODE_COMMENT(this);
  pushq(rbp);  // Caller's frame pointer.
  movq(rbp, rsp);
  Push(Immediate(StackFrame::TypeToMarker(type)));
}

void MacroAssembler::Prologue() {
  ASM_CODE_COMMENT(this);
  pushq(rbp);  // Caller's frame pointer.
  movq(rbp, rsp);
  Push(kContextRegister);                 // Callee's context.
  Push(kJSFunctionRegister);              // Callee's JS function.
  Push(kJavaScriptCallArgCountRegister);  // Actual argument count.
}

void MacroAssembler::EnterFrame(StackFrame::Type type) {
  ASM_CODE_COMMENT(this);
  pushq(rbp);
  movq(rbp, rsp);
  if (!StackFrame::IsJavaScript(type)) {
    static_assert(CommonFrameConstants::kContextOrFrameTypeOffset ==
                  -kSystemPointerSize);
    Push(Immediate(StackFrame::TypeToMarker(type)));
  }
#if V8_ENABLE_WEBASSEMBLY
  if (type == StackFrame::WASM) Push(kWasmImplicitArgRegister);
#endif  // V8_ENABLE_WEBASSEMBLY
}

void MacroAssembler::LeaveFrame(StackFrame::Type type) {
  ASM_CODE_COMMENT(this);
  // TODO(v8:11429): Consider passing BASELINE instead, and checking for
  // IsJSFrame or similar. Could then unify with manual frame leaves in the
  // interpreter too.
  if (v8_flags.debug_code && !StackFrame::IsJavaScript(type)) {
    cmpq(Operand(rbp, CommonFrameConstants::kContextOrFrameTypeOffset),
         Immediate(StackFrame::TypeToMarker(type)));
    Check(equal, AbortReason::kStackFrameTypesMustMatch);
  }
  movq(rsp, rbp);
  popq(rbp);
}

#if defined(V8_TARGET_OS_WIN) || defined(V8_TARGET_OS_MACOS)
void MacroAssembler::AllocateStackSpace(Register bytes_scratch) {
  ASM_CODE_COMMENT(this);
  // On Windows and on macOS, we cannot increment the stack size by more than
  // one page (minimum page size is 4KB) without accessing at least one byte on
  // the page. Check this:
  // https://msdn.microsoft.com/en-us/library/aa227153(v=vs.60).aspx.
  Label check_offset;
  Label touch_next_page;
  jmp(&check_offset);
  bind(&touch_next_page);
  subq(rsp, Immediate(kStackPageSize));
  // Just to touch the page, before we increment further.
  movb(Operand(rsp, 0), Immediate(0));
  subq(bytes_scratch, Immediate(kStackPageSize));

  bind(&check_offset);
  cmpq(bytes_scratch, Immediate(kStackPageSize));
  j(greater_equal, &touch_next_page);

  subq(rsp, bytes_scratch);
}

void MacroAssembler::AllocateStackSpace(int bytes) {
  ASM_CODE_COMMENT(this);
  DCHECK_GE(bytes, 0);
  while (bytes >= kStackPageSize) {
    subq(rsp, Immediate(kStackPageSize));
    movb(Operand(rsp, 0), Immediate(0));
    bytes -= kStackPageSize;
  }
  if (bytes == 0) return;
  subq(rsp, Immediate(bytes));
}
#endif

void MacroAssembler::EnterExitFrame(int extra_slots,
                                    StackFrame::Type frame_type,
                                    Register c_function) {
  ASM_CODE_COMMENT(this);
  DCHECK(frame_type == StackFrame::EXIT ||
         frame_type == StackFrame::BUILTIN_EXIT ||
         frame_type == StackFrame::API_ACCESSOR_EXIT ||
         frame_type == StackFrame::API_CALLBACK_EXIT);

  // Set up the frame structure on the stack.
  // All constants are relative to the frame pointer of the exit frame.
  DCHECK_EQ(kFPOnStackSize + kPCOnStackSize,
            ExitFrameConstants::kCallerSPDisplacement);
  DCHECK_EQ(kFPOnStackSize, ExitFrameConstants::kCallerPCOffset);
  DCHECK_EQ(0 * kSystemPointerSize, ExitFrameConstants::kCallerFPOffset);
  pushq(rbp);
  movq(rbp, rsp);

  Push(Immediate(StackFrame::TypeToMarker(frame_type)));
  DCHECK_EQ(-2 * kSystemPointerSize, ExitFrameConstants::kSPOffset);
  Push(Immediate(0));  // Saved entry sp, patched below.

  DCHECK(!AreAliased(rbp, kContextRegister, c_function));
  using ER = ExternalReference;
  Store(ER::Create(IsolateAddressId::kCEntryFPAddress, isolate()), rbp);
  Store(ER::Create(IsolateAddressId::kContextAddress, isolate()),
        kContextRegister);
  Store(ER::Create(IsolateAddressId::kCFunctionAddress, isolate()), c_function);

#ifdef V8_TARGET_OS_WIN
  // Note this is only correct under the assumption that the caller hasn't
  // considered home stack slots already.
  // TODO(jgruber): This is a bit hacky since the caller in most cases still
  // needs to know about the home stack slots in order to address reserved
  // slots. Consider moving this fully into caller code.
  extra_slots += kWindowsHomeStackSlots;
#endif
  AllocateStackSpace(extra_slots * kSystemPointerSize);

  AlignStackPointer();

  // Patch the saved entry sp.
  movq(Operand(rbp, ExitFrameConstants::kSPOffset), rsp);
}

void MacroAssembler::LeaveExitFrame() {
  ASM_CODE_COMMENT(this);

  leave();

  // Restore the current context from top and clear it in debug mode.
  ExternalReference context_address =
      ExternalReference::Create(IsolateAddressId::kContextAddress, isolate());
  Operand context_operand = ExternalReferenceAsOperand(context_address);
  movq(rsi, context_operand);
#ifdef DEBUG
  Move(context_operand, Context::kInvalidContext);
#endif

  // Clear the top frame.
  ExternalReference c_entry_fp_address =
      ExternalReference::Create(IsolateAddressId::kCEntryFPAddress, isolate());
  Operand c_entry_fp_operand = ExternalReferenceAsOperand(c_entry_fp_address);
  Move(c_entry_fp_operand, 0);
}

void MacroAssembler::LoadNativeContextSlot(Register dst, int index) {
  ASM_CODE_COMMENT(this);
  // Load native context.
  LoadMap(dst, rsi);
  LoadTaggedField(
      dst,
      FieldOperand(dst, Map::kConstructorOrBackPointerOrNativeContextOffset));
  // Load value from native context.
  LoadTaggedField(dst, Operand(dst, Context::SlotOffset(index)));
}

void MacroAssembler::TryLoadOptimizedOsrCode(Register scratch_and_result,
                                             CodeKind min_opt_level,
                                             Register feedback_vector,
                                             FeedbackSlot slot,
                                             Label* on_result,
                                             Label::Distance distance) {
  ASM_CODE_COMMENT(this);
  Label fallthrough, on_mark_deopt;
  LoadTaggedField(
      scratch_and_result,
      FieldOperand(feedback_vector,
                   FeedbackVector::OffsetOfElementAt(slot.ToInt())));
  LoadWeakValue(scratch_and_result, &fallthrough);

  // Is it marked_for_deoptimization? If yes, clear the slot.
  {
    // The entry references a CodeWrapper object. Unwrap it now.
    LoadCodePointerField(
        scratch_and_result,
        FieldOperand(scratch_and_result, CodeWrapper::kCodeOffset),
        kScratchRegister);

    TestCodeIsMarkedForDeoptimization(scratch_and_result);

    if (min_opt_level == CodeKind::TURBOFAN_JS) {
      j(not_zero, &on_mark_deopt, Label::Distance::kNear);

      TestCodeIsTurbofanned(scratch_and_result);
      j(not_zero, on_result, distance);
      jmp(&fallthrough);
    } else {
      DCHECK_EQ(min_opt_level, CodeKind::MAGLEV);
      j(equal, on_result, distance);
    }

    bind(&on_mark_deopt);
    StoreTaggedField(
        FieldOperand(feedback_vector,
                     FeedbackVector::OffsetOfElementAt(slot.ToInt())),
        ClearedValue());
  }

  bind(&fallthrough);
  Move(scratch_and_result, 0);
}

int MacroAssembler::ArgumentStackSlotsForCFunctionCall(int num_arguments) {
  DCHECK_GE(num_arguments, 0);
#ifdef V8_TARGET_OS_WIN
  return std::max(num_arguments, kWindowsHomeStackSlots);
#else
  return std::max(num_arguments - kRegisterPassedArguments, 0);
#endif
}

void MacroAssembler::PrepareCallCFunction(int num_arguments) {
  ASM_CODE_COMMENT(this);
  int frame_alignment = base::OS::ActivationFrameAlignment();
  DCHECK_NE(frame_alignment, 0);
  DCHECK_GE(num_arguments, 0);

  // Make stack end at alignment and allocate space for arguments and old rsp.
  movq(kScratchRegister, rsp);
  DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
  int argument_slots_on_stack =
      ArgumentStackSlotsForCFunctionCall(num_arguments);
  AllocateStackSpace((argument_slots_on_stack + 1) * kSystemPointerSize);
  andq(rsp, Immediate(-frame_alignment));
  movq(Operand(rsp, argument_slots_on_stack * kSystemPointerSize),
       kScratchRegister);
}

int MacroAssembler::CallCFunction(ExternalReference function, int num_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  // Note: The "CallCFunction" code comment will be generated by the other
  // CallCFunction method called below.
  LoadAddress(rax, function);
  return CallCFunction(rax, num_arguments, set_isolate_data_slots,
                       return_location);
}

int MacroAssembler::CallCFunction(Register function, int num_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  ASM_CODE_COMMENT(this);
  DCHECK_LE(num_arguments, kMaxCParameters);
  DCHECK(has_frame());
  // Check stack alignment.
  if (v8_flags.debug_code) {
    CheckStackAlignment();
  }

  // Save the frame pointer and PC so that the stack layout remains iterable,
  // even without an ExitFrame which normally exists between JS and C frames.
  Label get_pc;

  if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
    DCHECK(!AreAliased(kScratchRegister, function));
    leaq(kScratchRegister, Operand(&get_pc, 0));

    CHECK(root_array_available());
    movq(ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerPC),
         kScratchRegister);
    movq(ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP), rbp);
  }

  call(function);
  int call_pc_offset = pc_offset();
  bind(&get_pc);
  if (return_location) bind(return_location);

  if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
    // We don't unset the PC; the FP is the source of truth.
    movq(ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP),
         Immediate(0));
  }

  DCHECK_NE(base::OS::ActivationFrameAlignment(), 0);
  DCHECK_GE(num_arguments, 0);
  int argument_slots_on_stack =
      ArgumentStackSlotsForCFunctionCall(num_arguments);
  movq(rsp, Operand(rsp, argument_slots_on_stack * kSystemPointerSize));

  return call_pc_offset;
}

void MacroAssembler::MemoryChunkHeaderFromObject(Register object,
                                                 Register header) {
  constexpr intptr_t alignment_mask =
      MemoryChunk::GetAlignmentMaskForAssembler();
  if (header == object) {
    andq(header, Immediate(~alignment_mask));
  } else {
    movq(header, Immediate(~alignment_mask));
    andq(header, object);
  }
}

void MacroAssembler::CheckPageFlag(Register object, Register scratch, int mask,
                                   Condition cc, Label* condition_met,
                                   Label::Distance condition_met_distance) {
  ASM_CODE_COMMENT(this);
  DCHECK(cc == zero || cc == not_zero);
  MemoryChunkHeaderFromObject(object, scratch);
  if (mask < (1 << kBitsPerByte)) {
    testb(Operand(scratch, MemoryChunk::FlagsOffset()),
          Immediate(static_cast<uint8_t>(mask)));
  } else {
    testl(Operand(scratch, MemoryChunk::FlagsOffset()), Immediate(mask));
  }
  j(cc, condition_met, condition_met_distance);
}

void MacroAssembler::JumpIfMarking(Label* is_marking,
                                   Label::Distance condition_met_distance) {
  testb(Operand(kRootRegister, IsolateData::is_marking_flag_offset()),
        Immediate(static_cast<uint8_t>(1)));
  j(not_zero, is_marking, condition_met_distance);
}

void MacroAssembler::JumpIfNotMarking(Label* not_marking,
                                      Label::Distance condition_met_distance) {
  testb(Operand(kRootRegister, IsolateData::is_marking_flag_offset()),
        Immediate(static_cast<uint8_t>(1)));
  j(zero, not_marking, condition_met_distance);
}

void MacroAssembler::CheckMarkBit(Register object, Register scratch0,
                                  Register scratch1, Condition cc,
                                  Label* condition_met,
                                  Label::Distance condition_met_distance) {
  ASM_CODE_COMMENT(this);
  DCHECK(cc == carry || cc == not_carry);
  DCHECK(!AreAliased(object, scratch0, scratch1));

  // Computing cell.
  MemoryChunkHeaderFromObject(object, scratch0);
#ifdef V8_ENABLE_SANDBOX
  movl(scratch0, Operand(scratch0, MemoryChunk::MetadataIndexOffset()));
  andl(scratch0, Immediate(MemoryChunk::kMetadataPointerTableSizeMask));
  shll(scratch0, Immediate(kSystemPointerSizeLog2));
  LoadAddress(scratch1,
              ExternalReference::memory_chunk_metadata_table_address());
  movq(scratch0, Operand(scratch1, scratch0, times_1, 0));
#else   // !V8_ENABLE_SANDBOX
  movq(scratch0, Operand(scratch0, MemoryChunk::MetadataOffset()));
#endif  // !V8_ENABLE_SANDBOX
  if (v8_flags.debug_code) {
    Push(object);
    movq(scratch1, Operand(scratch0, MemoryChunkMetadata::AreaStartOffset()));
    MemoryChunkHeaderFromObject(scratch1, scratch1);
    MemoryChunkHeaderFromObject(object, object);
    cmpq(object, scratch1);
    Check(equal, AbortReason::kMetadataAreaStartDoesNotMatch);
    Pop(object);
  }
  addq(scratch0, Immediate(MutablePageMetadata::MarkingBitmapOffset()));

  movq(scratch1, object);
  andq(scratch1, Immediate(MemoryChunk::GetAlignmentMaskForAssembler()));
  // It's important not to fold the next two shifts.
  shrq(scratch1, Immediate(kTaggedSizeLog2 + MarkingBitmap::kBitsPerCellLog2));
  shlq(scratch1, Immediate(kBitsPerByteLog2));
  addq(scratch0, scratch1);

  // Computing mask.
  movq(scratch1, object);
  andq(scratch1, Immediate(MemoryChunk::GetAlignmentMaskForAssembler()));
  shrq(scratch1, Immediate(kTaggedSizeLog2));
  andq(scratch1, Immediate(MarkingBitmap::kBitIndexMask));
  btq(Operand(scratch0, 0), scratch1);

  j(cc, condition_met, condition_met_distance);
}

void MacroAssembler::ComputeCodeStartAddress(Register dst) {
  Label current;
  bind(&current);
  int pc = pc_offset();
  // Load effective address to get the address of the current instruction.
  leaq(dst, Operand(&current, -pc));
}

// Check if the code object is marked for deoptimization. If it is, then it
// jumps to the CompileLazyDeoptimizedCode builtin. In order to do this we need
// to:
//    1. read from memory the word that contains that bit, which can be found in
//       the flags in the referenced {Code} object;
//    2. test kMarkedForDeoptimizationBit in those flags; and
//    3. if it is not zero then it jumps to the builtin.
void MacroAssembler::BailoutIfDeoptimized(Register scratch) {
  int offset = InstructionStream::kCodeOffset - InstructionStream::kHeaderSize;
  LoadProtectedPointerField(scratch,
                            Operand(kJavaScriptCallCodeStartRegister, offset));
  TestCodeIsMarkedForDeoptimization(scratch);
  TailCallBuiltin(Builtin::kCompileLazyDeoptimizedCode, not_zero);
}

void MacroAssembler::CallForDeoptimization(Builtin target, int, Label* exit,
                                           DeoptimizeKind kind, Label* ret,
                                           Label*) {
  ASM_CODE_COMMENT(this);
  // Note: Assembler::call is used here on purpose to guarantee fixed-size
  // exits even on Atom CPUs; see MacroAssembler::Call for Atom-specific
  // performance tuning which emits a different instruction sequence.
  call(EntryFromBuiltinAsOperand(target));
  DCHECK_EQ(SizeOfCodeGeneratedSince(exit),
            (kind == DeoptimizeKind::kLazy) ? Deoptimizer::kLazyDeoptExitSize
                                            : Deoptimizer::kEagerDeoptExitSize);
}

void MacroAssembler::Trap() { int3(); }
void MacroAssembler::DebugBreak() { int3(); }

// Calls an API function. Allocates HandleScope, extracts returned value
// from handle and propagates exceptions. Clobbers C argument registers
// and C caller-saved registers. Restores context. On return removes
//   (*argc_operand + slots_to_drop_on_return) * kSystemPointerSize
// (GCed, includes the call JS arguments space and the additional space
// allocated for the fast call).
void CallApiFunctionAndReturn(MacroAssembler* masm, bool with_profiling,
                              Register function_address,
                              ExternalReference thunk_ref, Register thunk_arg,
                              int slots_to_drop_on_return,
                              MemOperand* argc_operand,
                              MemOperand return_value_operand) {
  ASM_CODE_COMMENT(masm);
  Label propagate_exception;
  Label delete_allocated_handles;
  Label leave_exit_frame;

  using ER = ExternalReference;

  Isolate* isolate = masm->isolate();
  MemOperand next_mem_op = __ ExternalReferenceAsOperand(
      ER::handle_scope_next_address(isolate), no_reg);
  MemOperand limit_mem_op = __ ExternalReferenceAsOperand(
      ER::handle_scope_limit_address(isolate), no_reg);
  MemOperand level_mem_op = __ ExternalReferenceAsOperand(
      ER::handle_scope_level_address(isolate), no_reg);

  Register return_value = rax;
  Register scratch = kCArgRegs[3];

  // Allocate HandleScope in callee-saved registers.
  // We will need to restore the HandleScope after the call to the API function,
  // by allocating it in callee-saved registers it'll be preserved by C code.
  Register prev_next_address_reg = r12;
  Register prev_limit_reg = r15;

  // C arguments (kCArgRegs[0/1]) are expected to be initialized outside, so
  // this function must not corrupt them. kScratchRegister might be used
  // implicitly by the macro assembler.
  DCHECK(!AreAliased(kCArgRegs[0], kCArgRegs[1],  // C args
                     return_value, scratch, kScratchRegister,
                     prev_next_address_reg, prev_limit_reg));
  // function_address and thunk_arg might overlap but this function must not
  // corrupted them until the call is made (i.e. overlap with return_value is
  // fine).
  DCHECK(!AreAliased(function_address,  // incoming parameters
                     scratch, kScratchRegister, prev_next_address_reg,
                     prev_limit_reg));
  DCHECK(!AreAliased(thunk_arg,  // incoming parameters
                     scratch, kScratchRegister, prev_next_address_reg,
                     prev_limit_reg));
  {
    ASM_CODE_COMMENT_STRING(masm,
                            "Allocate HandleScope in callee-save registers.");
    __ movq(prev_next_address_reg, next_mem_op);
    __ movq(prev_limit_reg, limit_mem_op);
    __ addl(level_mem_op, Immediate(1));
  }

  Label profiler_or_side_effects_check_enabled, done_api_call;
  if (with_profiling) {
    __ RecordComment("Check if profiler or side effects check is enabled");
    __ cmpb(__ ExternalReferenceAsOperand(IsolateFieldId::kExecutionMode),
            Immediate(0));
    __ j(not_zero, &profiler_or_side_effects_check_enabled);
#ifdef V8_RUNTIME_CALL_STATS
    __ RecordComment("Check if RCS is enabled");
    __ Move(scratch, ER::address_of_runtime_stats_flag());
    __ cmpl(Operand(scratch, 0), Immediate(0));
    __ j(not_zero, &profiler_or_side_effects_check_enabled);
#endif  // V8_RUNTIME_CALL_STATS
  }

  __ RecordComment("Call the api function directly.");
  __ call(function_address);
  __ bind(&done_api_call);

  __ RecordComment("Load the value from ReturnValue");
  __ movq(return_value, return_value_operand);

  {
    ASM_CODE_COMMENT_STRING(
        masm,
        "No more valid handles (the result handle was the last one)."
        "Restore previous handle scope.");
    __ subl(level_mem_op, Immediate(1));
    __ Assert(above_equal, AbortReason::kInvalidHandleScopeLevel);
    __ movq(next_mem_op, prev_next_address_reg);
    __ cmpq(prev_limit_reg, limit_mem_op);
    __ j(not_equal, &delete_allocated_handles);
  }

  __ RecordComment("Leave the API exit frame.");
  __ bind(&leave_exit_frame);

  Register argc_reg = prev_limit_reg;
  if (argc_operand != nullptr) {
    __ movq(argc_reg, *argc_operand);
  }
  __ LeaveExitFrame();

  {
    ASM_CODE_COMMENT_STRING(masm,
                            "Check if the function scheduled an exception.");
    __ CompareRoot(
        __ ExternalReferenceAsOperand(ER::exception_address(isolate), no_reg),
        RootIndex::kTheHoleValue);
    __ j(not_equal, &propagate_exception);
  }

  __ AssertJSAny(return_value, scratch,
                 AbortReason::kAPICallReturnedInvalidObject);

  if (argc_operand == nullptr) {
    DCHECK_NE(slots_to_drop_on_return, 0);
    __ ret(slots_to_drop_on_return * kSystemPointerSize);
  } else {
    __ PopReturnAddressTo(scratch);
    // {argc_operand} was loaded into {argc_reg} above.
    __ leaq(rsp, Operand(rsp, argc_reg, times_system_pointer_size,
                         slots_to_drop_on_return * kSystemPointerSize));
    // Push and ret (instead of jmp) to keep the RSB and the CET shadow stack
    // balanced.
    __ PushReturnAddressFrom(scratch);
    __ ret(0);
  }
  if (with_profiling) {
    ASM_CODE_COMMENT_STRING(masm, "Call the api function via thunk wrapper.");
    // Call the api function via thunk wrapper.
    __ bind(&profiler_or_side_effects_check_enabled);
    // Additional parameter is the address of the actual callback function.
    if (thunk_arg.is_valid()) {
      MemOperand thunk_arg_mem_op = __ ExternalReferenceAsOperand(
          IsolateFieldId::kApiCallbackThunkArgument);
      __ movq(thunk_arg_mem_op, thunk_arg);
    }
    __ Call(thunk_ref);
    __ jmp(&done_api_call);
  }
  __ RecordComment("An exception was thrown. Propagate it.");
  __ bind(&propagate_exception);
  __ TailCallRuntime(Runtime::kPropagateException);
  {
    ASM_CODE_COMMENT_STRING(
        masm, "HandleScope limit has changed. Delete allocated extensions.");
    __ bind(&delete_allocated_handles);
    __ movq(limit_mem_op, prev_limit_reg);
    // Save the return value in a callee-save register.
    Register saved_result = prev_limit_reg;
    __ movq(saved_result, return_value);
    __ LoadAddress(kCArgRegs[0], ER::isolate_address());
    __ Call(ER::delete_handle_scope_extensions());
    __ movq(return_value, saved_result);
    __ jmp(&leave_exit_frame);
  }
}

}  // namespace internal
}  // namespace v8

#undef __

#endif  // V8_TARGET_ARCH_X64

"""


```