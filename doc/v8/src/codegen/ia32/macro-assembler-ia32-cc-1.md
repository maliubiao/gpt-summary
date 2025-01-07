Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/ia32/macro-assembler-ia32.cc`. This is part 2 of 3.

Here's a breakdown of the code's responsibilities:

1. **Assertions and Checks:**  The code includes functions for asserting conditions during debugging. These are used to verify assumptions about the state of the program.
2. **Stack Frame Management:** Several functions deal with setting up and tearing down stack frames (prologue, epilogue, entering/leaving frames). This is essential for managing function calls and local variables.
3. **Argument Handling:** Functions for dropping arguments from the stack and handling new receivers during calls are present.
4. **Stack Manipulation:**  Functions for allocating and deallocating space on the stack, as well as pushing and popping values.
5. **Runtime Calls:** Mechanisms for calling into the V8 runtime system are defined. This includes both regular calls and tail calls.
6. **Stack Overflow Checks:**  Code to detect and handle potential stack overflow situations.
7. **Function Invocation:**  Functions for invoking JavaScript functions, handling parameter counts, and potentially invoking debug hooks.
8. **Global Object Access:**  A function to load the global proxy object.
9. **Return Operations:**  Functions for returning from function calls.
10. **Data Movement:**  Functions for moving data between registers, memory locations, and immediate values. This includes specialized handling for different data types (integers, floats).
11. **Bit Manipulation:** Functions for bitwise operations like counting leading zeros, trailing zeros, and set bits (if the CPU supports the instructions).
12. **Weak References:**  A function to load weak values, checking if they have been cleared.
13. **Counters:**  Functions to increment and decrement performance counters.
14. **Aborting:**  A function to trigger an abort if an error condition is detected.
15. **C Function Calls:** Functions to prepare for and execute calls to C functions.

Considering this is part 2 of 3, the summary should focus on the core functionalities implemented in this specific section and avoid going into details that might be covered in other parts.
这段代码是 `v8/src/codegen/ia32/macro-assembler-ia32.cc` 的一部分，主要提供了一系列用于生成 IA-32 汇编代码的宏指令。这些宏指令封装了常见的汇编操作，使得在 V8 引擎中生成汇编代码更加方便和可读。

**功能归纳：**

这段代码的主要功能是提供用于断言检查、栈帧管理、参数处理、运行时函数调用、栈操作以及数据移动的宏指令，用于在 IA-32 架构上生成 V8 引擎的汇编代码。

**具体功能点：**

*   **断言和检查 (Assertions and Checks):** 提供了一系列 `Assert...` 和 `Check` 函数，用于在调试模式下验证代码的假设条件。
*   **栈帧管理 (Stack Frame Management):** 提供了 `StubPrologue`、`Prologue`、`EnterFrame`、`LeaveFrame`、`EnterExitFrame`、`LeaveExitFrame` 等函数，用于创建和销毁不同类型的栈帧，这是函数调用和执行的基础。
*   **参数处理 (Argument Handling):** 提供了 `DropArguments`、`DropArgumentsAndPushNewReceiver` 等函数，用于在函数调用前后调整栈上的参数。
*   **运行时调用 (Runtime Calls):** 提供了 `CallRuntime` 和 `TailCallRuntime` 函数，用于调用 V8 的运行时函数，这些函数实现了 JavaScript 的一些内置功能。
*   **栈操作 (Stack Operations):** 提供了 `Push`、`Pop`、`AllocateStackSpace` 等函数，用于直接操作栈，例如压入数据、弹出数据和分配栈空间。
*   **函数调用 (Function Invocation):** 提供了 `InvokePrologue`、`InvokeFunctionCode` 和 `InvokeFunction` 函数，用于调用 JavaScript 函数，包括处理参数数量不匹配的情况以及调用调试钩子。
*   **全局对象访问 (Global Object Access):** 提供了 `LoadGlobalProxy` 和 `LoadNativeContextSlot` 函数，用于加载全局代理对象和本地上下文槽。
*   **返回操作 (Return Operations):** 提供了 `Ret` 函数，用于从函数调用中返回。
*   **数据移动 (Data Movement):** 提供了 `Move` 函数的多个重载版本，用于在寄存器、内存和立即数之间移动数据。
*   **位操作 (Bit Manipulation):** 提供了 `Lzcnt`、`Tzcnt`、`Popcnt` 等函数，用于执行位操作（如果 CPU 支持相应的指令）。
*   **弱引用 (Weak References):** 提供了 `LoadWeakValue` 函数，用于加载弱引用对象的值。
*   **性能计数器 (Performance Counters):** 提供了 `EmitIncrementCounter` 和 `EmitDecrementCounter` 函数，用于更新性能计数器。
*   **中止 (Abort):** 提供了 `Abort` 函数，用于在发生错误时中止程序执行。
*   **C 函数调用 (C Function Calls):** 提供了 `PrepareCallCFunction` 和 `CallCFunction` 函数，用于调用 C++ 函数。

**与 JavaScript 功能的关系：**

这段代码中的宏指令直接服务于 V8 引擎执行 JavaScript 代码的过程。例如：

*   **栈帧管理**是执行任何 JavaScript 函数的基础，用于保存局部变量和调用信息。
*   **参数处理**确保在调用 JavaScript 函数时，参数能够正确传递。
*   **运行时调用**使得 JavaScript 代码能够调用 V8 引擎提供的内置函数，例如 `Array.push` 或 `console.log` 等。
*   **函数调用**的宏指令实现了 JavaScript 函数的调用机制。

**JavaScript 示例：**

假设在 JavaScript 中有如下代码：

```javascript
function add(a, b) {
  return a + b;
}

add(5, 10);
```

当 V8 引擎执行 `add(5, 10)` 时，`macro-assembler-ia32.cc` 中的一些宏指令可能会被用于生成对应的汇编代码，例如：

*   `Prologue()` 用于建立 `add` 函数的栈帧。
*   `Move()` 用于将参数 `a` 和 `b` 从栈上加载到寄存器中。
*   可能会调用一个运行时函数来实现加法操作。
*   `Ret()` 用于返回结果。
*   `InvokeFunction()` 用于调用 `add` 函数。

**代码逻辑推理（假设输入与输出）：**

假设输入的是一个需要调用 JavaScript 函数 `foo(x, y)` 的场景，且 `x` 和 `y` 已经分别存在于寄存器 `eax` 和 `ebx` 中，函数对象 `foo` 存在于寄存器 `edi` 中。

输出的汇编代码可能包含以下步骤（使用了这段代码中定义的宏指令）：

1. `Push(eax)`  // 将参数 x 压入栈
2. `Push(ebx)`  // 将参数 y 压入栈
3. `Move(ecx, Immediate(2))` // 设置参数个数为 2
4. `InvokeFunction(edi, no_reg, ecx, InvokeType::kCall)` // 调用函数 foo

**用户常见的编程错误：**

涉及到栈操作和函数调用时，常见的编程错误包括：

*   **栈溢出 (Stack Overflow):**  如果递归调用过深，或者在栈上分配了过多的局部变量，可能导致栈空间不足。这段代码中的 `StackOverflowCheck` 可以帮助检测这种错误。
*   **参数传递错误:** 调用函数时传递的参数数量或类型不正确。这段代码中的 `InvokePrologue` 用于处理参数数量不匹配的情况。
*   **寄存器使用冲突:** 在汇编代码中错误地使用了某些被其他操作占用的寄存器。V8 的代码生成器需要仔细管理寄存器的使用。

**总结：**

这段 `v8/src/codegen/ia32/macro-assembler-ia32.cc` 代码片段是 V8 引擎在 IA-32 架构上生成高效汇编代码的关键组成部分，它封装了底层的汇编指令，提供了高层次的抽象，用于实现 JavaScript 的各种语言特性和运行时功能。它通过提供各种宏指令，简化了代码生成过程，并包含了必要的调试和错误处理机制。

Prompt: 
```
这是目录为v8/src/codegen/ia32/macro-assembler-ia32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/ia32/macro-assembler-ia32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
orObject);

  {
    Push(object);
    Register map = object;

    LoadMap(map, object);

    // Check if JSGeneratorObject
    CmpInstanceTypeRange(map, map, map, FIRST_JS_GENERATOR_OBJECT_TYPE,
                         LAST_JS_GENERATOR_OBJECT_TYPE);
    Pop(object);
  }

  Check(below_equal, AbortReason::kOperandIsNotAGeneratorObject);
}

void MacroAssembler::AssertUndefinedOrAllocationSite(Register object,
                                                     Register scratch) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    Label done_checking;
    AssertNotSmi(object);
    CompareRoot(object, scratch, RootIndex::kUndefinedValue);
    j(equal, &done_checking);
    LoadRoot(scratch, RootIndex::kAllocationSiteWithWeakNextMap);
    cmp(FieldOperand(object, 0), scratch);
    Assert(equal, AbortReason::kExpectedUndefinedOrCell);
    bind(&done_checking);
  }
}

void MacroAssembler::AssertNotSmi(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    test(object, Immediate(kSmiTagMask));
    Check(not_equal, AbortReason::kOperandIsASmi);
  }
}

void MacroAssembler::AssertJSAny(Register object, Register map_tmp,
                                 AbortReason abort_reason) {
  if (!v8_flags.debug_code) return;

  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(object, map_tmp));
  Label ok;

  JumpIfSmi(object, &ok, Label::kNear);

  mov(map_tmp, FieldOperand(object, HeapObject::kMapOffset));

  CmpInstanceType(map_tmp, LAST_NAME_TYPE);
  j(below_equal, &ok, Label::kNear);

  CmpInstanceType(map_tmp, FIRST_JS_RECEIVER_TYPE);
  j(above_equal, &ok, Label::kNear);

  CompareRoot(map_tmp, RootIndex::kHeapNumberMap);
  j(equal, &ok, Label::kNear);

  CompareRoot(map_tmp, RootIndex::kBigIntMap);
  j(equal, &ok, Label::kNear);

  CompareRoot(object, RootIndex::kUndefinedValue);
  j(equal, &ok, Label::kNear);

  CompareRoot(object, RootIndex::kTrueValue);
  j(equal, &ok, Label::kNear);

  CompareRoot(object, RootIndex::kFalseValue);
  j(equal, &ok, Label::kNear);

  CompareRoot(object, RootIndex::kNullValue);
  j(equal, &ok, Label::kNear);

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

void MacroAssembler::StubPrologue(StackFrame::Type type) {
  ASM_CODE_COMMENT(this);
  push(ebp);  // Caller's frame pointer.
  mov(ebp, esp);
  push(Immediate(StackFrame::TypeToMarker(type)));
}

void MacroAssembler::Prologue() {
  ASM_CODE_COMMENT(this);
  push(ebp);  // Caller's frame pointer.
  mov(ebp, esp);
  push(kContextRegister);                 // Callee's context.
  push(kJSFunctionRegister);              // Callee's JS function.
  push(kJavaScriptCallArgCountRegister);  // Actual argument count.
}

void MacroAssembler::DropArguments(Register count) {
  lea(esp, Operand(esp, count, times_system_pointer_size, 0));
}

void MacroAssembler::DropArguments(Register count, Register scratch) {
  DCHECK(!AreAliased(count, scratch));
  PopReturnAddressTo(scratch);
  DropArguments(count);
  PushReturnAddressFrom(scratch);
}

void MacroAssembler::DropArgumentsAndPushNewReceiver(Register argc,
                                                     Register receiver,
                                                     Register scratch) {
  DCHECK(!AreAliased(argc, receiver, scratch));
  PopReturnAddressTo(scratch);
  DropArguments(argc);
  Push(receiver);
  PushReturnAddressFrom(scratch);
}

void MacroAssembler::DropArgumentsAndPushNewReceiver(Register argc,
                                                     Operand receiver,
                                                     Register scratch) {
  DCHECK(!AreAliased(argc, scratch));
  DCHECK(!receiver.is_reg(scratch));
  PopReturnAddressTo(scratch);
  DropArguments(argc);
  Push(receiver);
  PushReturnAddressFrom(scratch);
}

void MacroAssembler::EnterFrame(StackFrame::Type type) {
  ASM_CODE_COMMENT(this);
  push(ebp);
  mov(ebp, esp);
  if (!StackFrame::IsJavaScript(type)) {
    Push(Immediate(StackFrame::TypeToMarker(type)));
  }
#if V8_ENABLE_WEBASSEMBLY
  if (type == StackFrame::WASM) Push(kWasmImplicitArgRegister);
#endif  // V8_ENABLE_WEBASSEMBLY
}

void MacroAssembler::LeaveFrame(StackFrame::Type type) {
  ASM_CODE_COMMENT(this);
  if (v8_flags.debug_code && !StackFrame::IsJavaScript(type)) {
    cmp(Operand(ebp, CommonFrameConstants::kContextOrFrameTypeOffset),
        Immediate(StackFrame::TypeToMarker(type)));
    Check(equal, AbortReason::kStackFrameTypesMustMatch);
  }
  leave();
}

#ifdef V8_OS_WIN
void MacroAssembler::AllocateStackSpace(Register bytes_scratch) {
  ASM_CODE_COMMENT(this);
  // In windows, we cannot increment the stack size by more than one page
  // (minimum page size is 4KB) without accessing at least one byte on the
  // page. Check this:
  // https://msdn.microsoft.com/en-us/library/aa227153(v=vs.60).aspx.
  Label check_offset;
  Label touch_next_page;
  jmp(&check_offset);
  bind(&touch_next_page);
  sub(esp, Immediate(kStackPageSize));
  // Just to touch the page, before we increment further.
  mov(Operand(esp, 0), Immediate(0));
  sub(bytes_scratch, Immediate(kStackPageSize));

  bind(&check_offset);
  cmp(bytes_scratch, kStackPageSize);
  j(greater_equal, &touch_next_page);

  sub(esp, bytes_scratch);
}

void MacroAssembler::AllocateStackSpace(int bytes) {
  ASM_CODE_COMMENT(this);
  DCHECK_GE(bytes, 0);
  while (bytes >= kStackPageSize) {
    sub(esp, Immediate(kStackPageSize));
    mov(Operand(esp, 0), Immediate(0));
    bytes -= kStackPageSize;
  }
  if (bytes == 0) return;
  sub(esp, Immediate(bytes));
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
  DCHECK_EQ(+2 * kSystemPointerSize, ExitFrameConstants::kCallerSPDisplacement);
  DCHECK_EQ(+1 * kSystemPointerSize, ExitFrameConstants::kCallerPCOffset);
  DCHECK_EQ(0 * kSystemPointerSize, ExitFrameConstants::kCallerFPOffset);
  push(ebp);
  mov(ebp, esp);

  push(Immediate(StackFrame::TypeToMarker(frame_type)));
  DCHECK_EQ(-2 * kSystemPointerSize, ExitFrameConstants::kSPOffset);
  push(Immediate(0));  // Saved entry sp, patched below.

  // Save the frame pointer and the context in top.
  DCHECK(!AreAliased(ebp, kContextRegister, c_function));
  using ER = ExternalReference;
  ER r0 = ER::Create(IsolateAddressId::kCEntryFPAddress, isolate());
  mov(ExternalReferenceAsOperand(r0, no_reg), ebp);
  ER r1 = ER::Create(IsolateAddressId::kContextAddress, isolate());
  mov(ExternalReferenceAsOperand(r1, no_reg), kContextRegister);
  static_assert(edx == kRuntimeCallFunctionRegister);
  ER r2 = ER::Create(IsolateAddressId::kCFunctionAddress, isolate());
  mov(ExternalReferenceAsOperand(r2, no_reg), c_function);

  AllocateStackSpace(extra_slots * kSystemPointerSize);

  // Get the required frame alignment for the OS.
  const int kFrameAlignment = base::OS::ActivationFrameAlignment();
  if (kFrameAlignment > 0) {
    DCHECK(base::bits::IsPowerOfTwo(kFrameAlignment));
    and_(esp, -kFrameAlignment);
  }

  // Patch the saved entry sp.
  mov(Operand(ebp, ExitFrameConstants::kSPOffset), esp);
}

void MacroAssembler::LeaveExitFrame(Register scratch) {
  ASM_CODE_COMMENT(this);

  leave();

  // Clear the top frame.
  ExternalReference c_entry_fp_address =
      ExternalReference::Create(IsolateAddressId::kCEntryFPAddress, isolate());
  mov(ExternalReferenceAsOperand(c_entry_fp_address, scratch), Immediate(0));

  // Restore the current context from top and clear it in debug mode.
  ExternalReference context_address =
      ExternalReference::Create(IsolateAddressId::kContextAddress, isolate());
  mov(esi, ExternalReferenceAsOperand(context_address, scratch));

#ifdef DEBUG
  push(eax);
  mov(ExternalReferenceAsOperand(context_address, eax),
      Immediate(Context::kInvalidContext));
  pop(eax);
#endif
}

void MacroAssembler::PushStackHandler(Register scratch) {
  ASM_CODE_COMMENT(this);
  // Adjust this code if not the case.
  static_assert(StackHandlerConstants::kSize == 2 * kSystemPointerSize);
  static_assert(StackHandlerConstants::kNextOffset == 0);

  push(Immediate(0));  // Padding.

  // Link the current handler as the next handler.
  ExternalReference handler_address =
      ExternalReference::Create(IsolateAddressId::kHandlerAddress, isolate());
  push(ExternalReferenceAsOperand(handler_address, scratch));

  // Set this new handler as the current one.
  mov(ExternalReferenceAsOperand(handler_address, scratch), esp);
}

void MacroAssembler::PopStackHandler(Register scratch) {
  ASM_CODE_COMMENT(this);
  static_assert(StackHandlerConstants::kNextOffset == 0);
  ExternalReference handler_address =
      ExternalReference::Create(IsolateAddressId::kHandlerAddress, isolate());
  pop(ExternalReferenceAsOperand(handler_address, scratch));
  add(esp, Immediate(StackHandlerConstants::kSize - kSystemPointerSize));
}

void MacroAssembler::CallRuntime(const Runtime::Function* f,
                                 int num_arguments) {
  ASM_CODE_COMMENT(this);
  // If the expected number of arguments of the runtime function is
  // constant, we check that the actual number of arguments match the
  // expectation.
  CHECK(f->nargs < 0 || f->nargs == num_arguments);

  // TODO(1236192): Most runtime routines don't need the number of
  // arguments passed in because it is constant. At some point we
  // should remove this need and make the runtime routine entry code
  // smarter.
  Move(kRuntimeCallArgCountRegister, Immediate(num_arguments));
  Move(kRuntimeCallFunctionRegister, Immediate(ExternalReference::Create(f)));
  CallBuiltin(Builtins::RuntimeCEntry(f->result_size));
}

void MacroAssembler::TailCallRuntime(Runtime::FunctionId fid) {
  // ----------- S t a t e -------------
  //  -- esp[0]                 : return address
  //  -- esp[8]                 : argument num_arguments - 1
  //  ...
  //  -- esp[8 * num_arguments] : argument 0 (receiver)
  //
  //  For runtime functions with variable arguments:
  //  -- eax                    : number of  arguments
  // -----------------------------------
  ASM_CODE_COMMENT(this);
  const Runtime::Function* function = Runtime::FunctionForId(fid);
  DCHECK_EQ(1, function->result_size);
  if (function->nargs >= 0) {
    // TODO(1236192): Most runtime routines don't need the number of
    // arguments passed in because it is constant. At some point we
    // should remove this need and make the runtime routine entry code
    // smarter.
    Move(kRuntimeCallArgCountRegister, Immediate(function->nargs));
  }
  JumpToExternalReference(ExternalReference::Create(fid));
}

void MacroAssembler::JumpToExternalReference(const ExternalReference& ext,
                                             bool builtin_exit_frame) {
  ASM_CODE_COMMENT(this);
  // Set the entry point and jump to the C entry runtime stub.
  Move(kRuntimeCallFunctionRegister, Immediate(ext));
  TailCallBuiltin(Builtins::CEntry(1, ArgvMode::kStack, builtin_exit_frame));
}

Operand MacroAssembler::StackLimitAsOperand(StackLimitKind kind) {
  DCHECK(root_array_available());
  intptr_t offset = kind == StackLimitKind::kRealStackLimit
                        ? IsolateData::real_jslimit_offset()
                        : IsolateData::jslimit_offset();

  CHECK(is_int32(offset));
  return Operand(kRootRegister, static_cast<int32_t>(offset));
}

void MacroAssembler::CompareStackLimit(Register with, StackLimitKind kind) {
  ASM_CODE_COMMENT(this);
  cmp(with, StackLimitAsOperand(kind));
}

void MacroAssembler::StackOverflowCheck(Register num_args, Register scratch,
                                        Label* stack_overflow,
                                        bool include_receiver) {
  ASM_CODE_COMMENT(this);
  DCHECK_NE(num_args, scratch);
  // Check the stack for overflow. We are not trying to catch
  // interruptions (e.g. debug break and preemption) here, so the "real stack
  // limit" is checked.
  ExternalReference real_stack_limit =
      ExternalReference::address_of_real_jslimit(isolate());
  // Compute the space that is left as a negative number in scratch. If
  // we already overflowed, this will be a positive number.
  mov(scratch, ExternalReferenceAsOperand(real_stack_limit, scratch));
  sub(scratch, esp);
  // TODO(victorgomes): Remove {include_receiver} and always require one extra
  // word of the stack space.
  lea(scratch, Operand(scratch, num_args, times_system_pointer_size, 0));
  if (include_receiver) {
    add(scratch, Immediate(kSystemPointerSize));
  }
  // See if we overflowed, i.e. scratch is positive.
  cmp(scratch, Immediate(0));
  // TODO(victorgomes):  Save some bytes in the builtins that use stack checks
  // by jumping to a builtin that throws the exception.
  j(greater, stack_overflow);  // Signed comparison.
}

void MacroAssembler::InvokePrologue(Register expected_parameter_count,
                                    Register actual_parameter_count,
                                    Label* done, InvokeType type) {
  if (expected_parameter_count == actual_parameter_count) return;
  ASM_CODE_COMMENT(this);
  DCHECK_EQ(actual_parameter_count, eax);
  DCHECK_EQ(expected_parameter_count, ecx);
  Label regular_invoke;

  // If overapplication or if the actual argument count is equal to the
  // formal parameter count, no need to push extra undefined values.
  sub(expected_parameter_count, actual_parameter_count);
  j(less_equal, &regular_invoke, Label::kFar);

  // We need to preserve edx, edi, esi and ebx.
  movd(xmm0, edx);
  movd(xmm1, edi);
  movd(xmm2, esi);
  movd(xmm3, ebx);

  Label stack_overflow;
  StackOverflowCheck(expected_parameter_count, edx, &stack_overflow);

  Register scratch = esi;

  // Underapplication. Move the arguments already in the stack, including the
  // receiver and the return address.
  {
    Label copy, check;
    Register src = edx, dest = esp, num = edi, current = ebx;
    mov(src, esp);
    lea(scratch,
        Operand(expected_parameter_count, times_system_pointer_size, 0));
    AllocateStackSpace(scratch);
    // Extra words are the receiver (if not already included in argc) and the
    // return address (if a jump).
    int extra_words = type == InvokeType::kCall ? 0 : 1;
    lea(num, Operand(eax, extra_words));  // Number of words to copy.
    Move(current, 0);
    // Fall-through to the loop body because there are non-zero words to copy.
    bind(&copy);
    mov(scratch, Operand(src, current, times_system_pointer_size, 0));
    mov(Operand(dest, current, times_system_pointer_size, 0), scratch);
    inc(current);
    bind(&check);
    cmp(current, num);
    j(less, &copy);
    lea(edx, Operand(esp, num, times_system_pointer_size, 0));
  }

    // Fill remaining expected arguments with undefined values.
    movd(ebx, xmm3);  // Restore root.
    LoadRoot(scratch, RootIndex::kUndefinedValue);
    {
      Label loop;
      bind(&loop);
      dec(expected_parameter_count);
      mov(Operand(edx, expected_parameter_count, times_system_pointer_size, 0),
          scratch);
      j(greater, &loop, Label::kNear);
    }

    // Restore remaining registers.
    movd(esi, xmm2);
    movd(edi, xmm1);
    movd(edx, xmm0);

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

void MacroAssembler::CallDebugOnFunctionCall(Register fun, Register new_target,
                                             Register expected_parameter_count,
                                             Register actual_parameter_count) {
  ASM_CODE_COMMENT(this);

  // We have no available register. So we spill the root register (ebx) and
  // recover it later.
  movd(xmm0, kRootRegister);

  // Load receiver to pass it later to DebugOnFunctionCall hook.
  // Receiver is located on top of the stack if we have a frame (usually a
  // construct frame), or after the return address if we do not yet have a
  // frame.
  Register receiver = kRootRegister;
  mov(receiver, Operand(esp, has_frame() ? 0 : kSystemPointerSize));

  FrameScope frame(
      this, has_frame() ? StackFrame::NO_FRAME_TYPE : StackFrame::INTERNAL);

  SmiTag(expected_parameter_count);
  Push(expected_parameter_count);

  SmiTag(actual_parameter_count);
  Push(actual_parameter_count);
  SmiUntag(actual_parameter_count);

  if (new_target.is_valid()) {
    Push(new_target);
  }
  Push(fun);
  Push(fun);
  Push(receiver);

  // Recover root register.
  movd(kRootRegister, xmm0);

  CallRuntime(Runtime::kDebugOnFunctionCall);
  Pop(fun);
  if (new_target.is_valid()) {
    Pop(new_target);
  }
  Pop(actual_parameter_count);
  SmiUntag(actual_parameter_count);

  Pop(expected_parameter_count);
  SmiUntag(expected_parameter_count);
}

void MacroAssembler::InvokeFunctionCode(Register function, Register new_target,
                                        Register expected_parameter_count,
                                        Register actual_parameter_count,
                                        InvokeType type) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());
  DCHECK_EQ(function, edi);
  DCHECK_IMPLIES(new_target.is_valid(), new_target == edx);
  DCHECK(expected_parameter_count == ecx || expected_parameter_count == eax);
  DCHECK_EQ(actual_parameter_count, eax);

  // On function call, call into the debugger if necessary.
  Label debug_hook, continue_after_hook;
  {
    ExternalReference debug_hook_active =
        ExternalReference::debug_hook_on_function_call_address(isolate());
    push(eax);
    cmpb(ExternalReferenceAsOperand(debug_hook_active, eax), Immediate(0));
    pop(eax);
    j(not_equal, &debug_hook);
  }
  bind(&continue_after_hook);

  // Clear the new.target register if not given.
  if (!new_target.is_valid()) {
    Move(edx, isolate()->factory()->undefined_value());
  }

  Label done;
  InvokePrologue(expected_parameter_count, actual_parameter_count, &done, type);
  // We call indirectly through the code field in the function to
  // allow recompilation to take effect without changing any of the
  // call sites.
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

void MacroAssembler::InvokeFunction(Register fun, Register new_target,
                                    Register actual_parameter_count,
                                    InvokeType type) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK(type == InvokeType::kJump || has_frame());

  DCHECK(fun == edi);
  mov(ecx, FieldOperand(edi, JSFunction::kSharedFunctionInfoOffset));
  mov(esi, FieldOperand(edi, JSFunction::kContextOffset));
  movzx_w(ecx,
          FieldOperand(ecx, SharedFunctionInfo::kFormalParameterCountOffset));

  InvokeFunctionCode(edi, new_target, ecx, actual_parameter_count, type);
}

void MacroAssembler::LoadGlobalProxy(Register dst) {
  LoadNativeContextSlot(dst, Context::GLOBAL_PROXY_INDEX);
}

void MacroAssembler::LoadNativeContextSlot(Register destination, int index) {
  ASM_CODE_COMMENT(this);
  // Load the native context from the current context.
  LoadMap(destination, esi);
  mov(destination,
      FieldOperand(destination,
                   Map::kConstructorOrBackPointerOrNativeContextOffset));
  // Load the function from the native context.
  mov(destination, Operand(destination, Context::SlotOffset(index)));
}

void MacroAssembler::Ret() { ret(0); }

void MacroAssembler::Ret(int bytes_dropped, Register scratch) {
  if (is_uint16(bytes_dropped)) {
    ret(bytes_dropped);
  } else {
    pop(scratch);
    add(esp, Immediate(bytes_dropped));
    push(scratch);
    ret(0);
  }
}

void MacroAssembler::Push(Immediate value) {
  if (root_array_available()) {
    if (value.is_external_reference()) {
      ExternalReference reference = value.external_reference();
      if (reference.IsIsolateFieldId()) {
        push(kRootRegister);
        add(Operand(esp, 0), Immediate(reference.offset_from_root_register()));
        return;
      }
      if (options().isolate_independent_code) {
        push(kRootRegister);
        add(Operand(esp, 0), Immediate(RootRegisterOffsetForExternalReference(
                                 isolate(), reference)));
        return;
      }
    }
    if (value.is_embedded_object()) {
      Push(HeapObjectAsOperand(value.embedded_object()));
      return;
    }
  }
  push(value);
}

void MacroAssembler::Drop(int stack_elements) {
  if (stack_elements > 0) {
    add(esp, Immediate(stack_elements * kSystemPointerSize));
  }
}

void MacroAssembler::Move(Register dst, Register src) {
  if (dst != src) {
    mov(dst, src);
  }
}

void MacroAssembler::Move(Register dst, const Immediate& src) {
  if (!src.is_heap_number_request() && src.is_zero()) {
    xor_(dst, dst);  // Shorter than mov of 32-bit immediate 0.
  } else if (src.is_external_reference()) {
    LoadAddress(dst, src.external_reference());
  } else {
    mov(dst, src);
  }
}

namespace {
bool ShouldUsePushPopForMove(bool root_array_available,
                             bool isolate_independent_code,
                             const Immediate& src) {
  if (root_array_available) {
    if (src.is_external_reference() &&
        src.external_reference().IsIsolateFieldId()) {
      return true;
    }
    if (isolate_independent_code) {
      if (src.is_external_reference()) return true;
      if (src.is_embedded_object()) return true;
      if (src.is_heap_number_request()) return true;
    }
  }
  return false;
}
}  // namespace

void MacroAssembler::Move(Operand dst, const Immediate& src) {
  // Since there's no scratch register available, take a detour through the
  // stack.
  if (ShouldUsePushPopForMove(root_array_available(),
                              options().isolate_independent_code, src)) {
    Push(src);
    pop(dst);
  } else if (src.is_embedded_object()) {
    mov(dst, src.embedded_object());
  } else {
    mov(dst, src);
  }
}

void MacroAssembler::Move(Register dst, Operand src) { mov(dst, src); }

void MacroAssembler::Move(Register dst, Handle<HeapObject> src) {
  if (root_array_available() && options().isolate_independent_code) {
    IndirectLoadConstant(dst, src);
    return;
  }
  mov(dst, src);
}

void MacroAssembler::Move(XMMRegister dst, uint32_t src) {
  if (src == 0) {
    pxor(dst, dst);
  } else {
    unsigned cnt = base::bits::CountPopulation(src);
    unsigned nlz = base::bits::CountLeadingZeros32(src);
    unsigned ntz = base::bits::CountTrailingZeros32(src);
    if (nlz + cnt + ntz == 32) {
      pcmpeqd(dst, dst);
      if (ntz == 0) {
        psrld(dst, 32 - cnt);
      } else {
        pslld(dst, 32 - cnt);
        if (nlz != 0) psrld(dst, nlz);
      }
    } else {
      push(eax);
      mov(eax, Immediate(src));
      movd(dst, Operand(eax));
      pop(eax);
    }
  }
}

void MacroAssembler::Move(XMMRegister dst, uint64_t src) {
  if (src == 0) {
    pxor(dst, dst);
  } else {
    uint32_t lower = static_cast<uint32_t>(src);
    uint32_t upper = static_cast<uint32_t>(src >> 32);
    unsigned cnt = base::bits::CountPopulation(src);
    unsigned nlz = base::bits::CountLeadingZeros64(src);
    unsigned ntz = base::bits::CountTrailingZeros64(src);
    if (nlz + cnt + ntz == 64) {
      pcmpeqd(dst, dst);
      if (ntz == 0) {
        psrlq(dst, 64 - cnt);
      } else {
        psllq(dst, 64 - cnt);
        if (nlz != 0) psrlq(dst, nlz);
      }
    } else if (lower == 0) {
      Move(dst, upper);
      psllq(dst, 32);
    } else if (CpuFeatures::IsSupported(SSE4_1)) {
      CpuFeatureScope scope(this, SSE4_1);
      push(eax);
      Move(eax, Immediate(lower));
      movd(dst, Operand(eax));
      if (upper != lower) {
        Move(eax, Immediate(upper));
      }
      pinsrd(dst, Operand(eax), 1);
      pop(eax);
    } else {
      push(Immediate(upper));
      push(Immediate(lower));
      movsd(dst, Operand(esp, 0));
      add(esp, Immediate(kDoubleSize));
    }
  }
}

void MacroAssembler::PextrdPreSse41(Register dst, XMMRegister src,
                                    uint8_t imm8) {
  if (imm8 == 0) {
    Movd(dst, src);
    return;
  }
  // Without AVX or SSE, we can only have 64-bit values in xmm registers.
  // We don't have an xmm scratch register, so move the data via the stack. This
  // path is rarely required, so it's acceptable to be slow.
  DCHECK_LT(imm8, 2);
  AllocateStackSpace(kDoubleSize);
  movsd(Operand(esp, 0), src);
  mov(dst, Operand(esp, imm8 * kUInt32Size));
  add(esp, Immediate(kDoubleSize));
}

void MacroAssembler::PinsrdPreSse41(XMMRegister dst, Operand src, uint8_t imm8,
                                    uint32_t* load_pc_offset) {
  // Without AVX or SSE, we can only have 64-bit values in xmm registers.
  // We don't have an xmm scratch register, so move the data via the stack. This
  // path is rarely required, so it's acceptable to be slow.
  DCHECK_LT(imm8, 2);
  AllocateStackSpace(kDoubleSize);
  // Write original content of {dst} to the stack.
  movsd(Operand(esp, 0), dst);
  // Overwrite the portion specified in {imm8}.
  if (src.is_reg_only()) {
    mov(Operand(esp, imm8 * kUInt32Size), src.reg());
  } else {
    movss(dst, src);
    movss(Operand(esp, imm8 * kUInt32Size), dst);
  }
  // Load back the full value into {dst}.
  movsd(dst, Operand(esp, 0));
  add(esp, Immediate(kDoubleSize));
}

void MacroAssembler::Lzcnt(Register dst, Operand src) {
  if (CpuFeatures::IsSupported(LZCNT)) {
    CpuFeatureScope scope(this, LZCNT);
    lzcnt(dst, src);
    return;
  }
  Label not_zero_src;
  bsr(dst, src);
  j(not_zero, &not_zero_src, Label::kNear);
  mov(dst, 63);  // 63^31 == 32
  bind(&not_zero_src);
  xor_(dst, Immediate(31));  // for x in [0..31], 31^x == 31-x.
}

void MacroAssembler::Tzcnt(Register dst, Operand src) {
  if (CpuFeatures::IsSupported(BMI1)) {
    CpuFeatureScope scope(this, BMI1);
    tzcnt(dst, src);
    return;
  }
  Label not_zero_src;
  bsf(dst, src);
  j(not_zero, &not_zero_src, Label::kNear);
  mov(dst, 32);  // The result of tzcnt is 32 if src = 0.
  bind(&not_zero_src);
}

void MacroAssembler::Popcnt(Register dst, Operand src) {
  if (CpuFeatures::IsSupported(POPCNT)) {
    CpuFeatureScope scope(this, POPCNT);
    popcnt(dst, src);
    return;
  }
  FATAL("no POPCNT support");
}

void MacroAssembler::LoadWeakValue(Register in_out, Label* target_if_cleared) {
  ASM_CODE_COMMENT(this);
  cmp(in_out, Immediate(kClearedWeakHeapObjectLower32));
  j(equal, target_if_cleared);

  and_(in_out, Immediate(~kWeakHeapObjectMask));
}

void MacroAssembler::EmitIncrementCounter(StatsCounter* counter, int value,
                                          Register scratch) {
  DCHECK_GT(value, 0);
  if (v8_flags.native_code_counters && counter->Enabled()) {
    ASM_CODE_COMMENT(this);
    Operand operand =
        ExternalReferenceAsOperand(ExternalReference::Create(counter), scratch);
    if (value == 1) {
      inc(operand);
    } else {
      add(operand, Immediate(value));
    }
  }
}

void MacroAssembler::EmitDecrementCounter(StatsCounter* counter, int value,
                                          Register scratch) {
  DCHECK_GT(value, 0);
  if (v8_flags.native_code_counters && counter->Enabled()) {
    ASM_CODE_COMMENT(this);
    Operand operand =
        ExternalReferenceAsOperand(ExternalReference::Create(counter), scratch);
    if (value == 1) {
      dec(operand);
    } else {
      sub(operand, Immediate(value));
    }
  }
}

void MacroAssembler::Check(Condition cc, AbortReason reason) {
  Label L;
  j(cc, &L);
  Abort(reason);
  // will not return here
  bind(&L);
}

void MacroAssembler::CheckStackAlignment() {
  ASM_CODE_COMMENT(this);
  int frame_alignment = base::OS::ActivationFrameAlignment();
  int frame_alignment_mask = frame_alignment - 1;
  if (frame_alignment > kSystemPointerSize) {
    DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
    Label alignment_as_expected;
    test(esp, Immediate(frame_alignment_mask));
    j(zero, &alignment_as_expected);
    // Abort if stack is not aligned.
    int3();
    bind(&alignment_as_expected);
  }
}

void MacroAssembler::AlignStackPointer() {
  const int kFrameAlignment = base::OS::ActivationFrameAlignment();
  if (kFrameAlignment > 0) {
    DCHECK(base::bits::IsPowerOfTwo(kFrameAlignment));
    DCHECK(is_int8(kFrameAlignment));
    and_(esp, Immediate(-kFrameAlignment));
  }
}

void MacroAssembler::Abort(AbortReason reason) {
  if (v8_flags.code_comments) {
    const char* msg = GetAbortReason(reason);
    RecordComment("Abort message: ");
    RecordComment(msg);
  }

  // Avoid emitting call to builtin if requested.
  if (trap_on_abort()) {
    int3();
    return;
  }

  if (should_abort_hard()) {
    // We don't care if we constructed a frame. Just pretend we did.
    FrameScope assume_frame(this, StackFrame::NO_FRAME_TYPE);
    PrepareCallCFunction(1, eax);
    mov(Operand(esp, 0), Immediate(static_cast<int>(reason)));
    CallCFunction(ExternalReference::abort_with_reason(), 1);
    return;
  }

  Move(edx, Smi::FromInt(static_cast<int>(reason)));

  {
    // We don't actually want to generate a pile of code for this, so just
    // claim there is a stack frame, without generating one.
    FrameScope scope(this, StackFrame::NO_FRAME_TYPE);
    if (root_array_available()) {
      // Generate an indirect call via builtins entry table here in order to
      // ensure that the interpreter_entry_return_pc_offset is the same for
      // InterpreterEntryTrampoline and InterpreterEntryTrampolineForProfiling
      // when v8_flags.debug_code is enabled.
      Call(EntryFromBuiltinAsOperand(Builtin::kAbort));
    } else {
      CallBuiltin(Builtin::kAbort);
    }
  }

  // will not return here
  int3();
}

void MacroAssembler::PrepareCallCFunction(int num_arguments, Register scratch) {
  ASM_CODE_COMMENT(this);
  int frame_alignment = base::OS::ActivationFrameAlignment();
  if (frame_alignment != 0) {
    // Make stack end at alignment and make room for num_arguments words
    // and the original value of esp.
    mov(scratch, esp);
    AllocateStackSpace((num_arguments + 1) * kSystemPointerSize);
    AlignStackPointer();
    mov(Operand(esp, num_arguments * kSystemPointerSize), scratch);
  } else {
    AllocateStackSpace(num_arguments * kSystemPointerSize);
  }
}

int MacroAssembler::CallCFunction(ExternalReference function, int num_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  // Note: The "CallCFunction" code comment will be generated by the other
  // CallCFunction method called below.
  // Trashing eax is ok as it will be the return value.
  Move(eax, Immediate(function));
  return CallCFunction(eax, num_arguments, set_isolate_data_slots,
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

  Label get_pc;

  if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
    // Save the frame pointer and PC so that the stack layout remains iterable,
    // even without an ExitFrame which normally exists between JS and C frames.
    // Find two caller-saved scratch registers.
    Register pc_scratch = eax;
    Register scratch = ecx;
    if (function == eax) pc_scratch = edx;
    if (function == ecx) scratch = edx;
    LoadLabelAddress(pc_scratch, &get_pc);

    // The root 
"""


```