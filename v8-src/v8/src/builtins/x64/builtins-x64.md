Response: The user wants me to analyze a C++ source code file from the V8 project.
The file is located at `v8/src/builtins/x64/builtins-x64.cc`.
The goal is to summarize the functionality of this file.
Since this is part 1 of 4, the summary should focus on the functionalities present in this part.
The user also wants to know the relationship between this C++ code and JavaScript and wants examples.

Let's break down the code section by section:

* **Includes**: This section includes various header files from the V8 project, indicating functionalities related to API calls, code generation, deoptimization, execution frames, heap management, object manipulation, and WebAssembly.
* **`Builtins::Generate_Adaptor`**: This function seems to generate code for adapting function calls, likely when transitioning between JavaScript and native code.
* **Helper functions for argument handling**: `Generate_PushArguments` handles pushing arguments onto the stack, potentially with dereferencing.
* **`Generate_JSBuiltinsConstructStubHelper`**: This function appears to set up the execution environment for calling JavaScript constructors.
* **`Generate_CallToAdaptShadowStackForDeopt`**: This function seems related to shadow stack management, likely for security purposes during deoptimization.
* **`Builtins::Generate_JSConstructStubGeneric`**: This function implements the generic logic for handling JavaScript constructor calls, including object allocation and argument handling.
* **`Builtins::Generate_JSBuiltinsConstructStub`**: This function calls the helper function for constructor stubs.
* **`Builtins::Generate_ConstructedNonConstructable`**: This function deals with errors when trying to construct a non-constructable object.
* **`Generate_JSEntryVariant`**: This function generates code for entering the V8 engine from native code, setting up the execution frame and handling exceptions.
* **`Builtins::Generate_JSEntry`**, **`Builtins::Generate_JSConstructEntry`**, **`Builtins::Generate_JSRunMicrotasksEntry`**: These functions call the `Generate_JSEntryVariant` with different stack frame types.
* **`Generate_JSEntryTrampolineHelper`**: This function appears to handle the transition from native C++ calls to JavaScript function execution.
* **`Builtins::Generate_JSEntryTrampoline`**, **`Builtins::Generate_JSConstructEntryTrampoline`**: These functions call the trampoline helper for regular and constructor calls.
* **`Builtins::Generate_RunMicrotasksTrampoline`**: This function seems to initiate the execution of microtasks.
* **Assertion and checking functions**: `AssertCodeIsBaselineAllowClobber`, `AssertCodeIsBaseline`, `CheckSharedFunctionInfoBytecodeOrBaseline`, `GetSharedFunctionInfoBytecodeOrBaseline` are used for internal checks related to code kinds and shared function information.
* **`Builtins::Generate_ResumeGeneratorTrampoline`**: This function handles the resumption of JavaScript generator functions.
* **`LeaveInterpreterFrame`**: This function handles the cleanup when exiting an interpreter frame.
* **`AdvanceBytecodeOffsetOrReturn`**: This function simulates the advancement of the bytecode offset during interpreter execution.
* **Helper functions for resetting function age**: `ResetSharedFunctionInfoAge`, `ResetJSFunctionAge`, `ResetFeedbackVectorOsrUrgency`.
* **`Builtins::Generate_InterpreterEntryTrampoline`**: This is a crucial function that sets up the environment for executing JavaScript code within the interpreter.
* **`GenerateInterpreterPushArgs`**: This function pushes arguments onto the stack for interpreter calls.
* **`Builtins::Generate_InterpreterPushArgsThenCallImpl`**: This function pushes arguments and then calls a JavaScript function within the interpreter.
* **`Builtins::Generate_InterpreterPushArgsThenConstructImpl`**: This function pushes arguments and then calls a JavaScript constructor within the interpreter.
* **`Builtins::Generate_ConstructForwardAllArgsImpl`**: This function handles forwarding arguments when calling a constructor.
* **`NewImplicitReceiver`**: This helper function creates an implicit receiver object for constructor calls.
* **`Builtins::Generate_InterpreterPushArgsThenFastConstructFunction`**: This function seems to be an optimized path for constructing objects using the interpreter.

**Overall functionality:**

This part of the `builtins-x64.cc` file in V8 defines the low-level implementation (in x64 assembly) of various built-in functions and mechanisms for the V8 JavaScript engine. It covers essential aspects of:

1. **Function Calls and Adaptors**: Handling transitions between JavaScript and native code.
2. **Constructor Calls**: Implementing the logic for invoking JavaScript constructors, including object allocation and argument setup.
3. **Entry Points**: Defining how the V8 engine is entered from native code for regular function calls, constructor calls, and microtask execution.
4. **Trampolines**: Setting up intermediate execution points for different call scenarios (e.g., entering the interpreter).
5. **Interpreter Execution**: Implementing the entry and argument setup for executing JavaScript bytecode within the V8 interpreter.
6. **Generator Functions**: Handling the resumption of generator function execution.
7. **Stack Management**: Implementing checks for stack overflow and managing the stack frame during function calls.
8. **Deoptimization Support**: Including mechanisms for adapting the shadow stack during deoptimization.

**Relationship with JavaScript and examples:**

This C++ code directly implements the underlying mechanics for executing JavaScript code. The functions in this file are called when JavaScript code invokes built-in functionalities or when the engine needs to transition between different execution states (e.g., from native code to JavaScript or when resuming a generator).

Here are some JavaScript examples that relate to the functionalities in this part of the C++ code:

*   **Function Calls**:

    ```javascript
    function myFunction(a, b) {
      return a + b;
    }
    myFunction(1, 2); // The C++ code in this file helps manage this call.
    ```

    The `Builtins::Generate_Adaptor`, `Generate_JSEntry`, and `Generate_JSEntryTrampoline` functions are involved in setting up and executing this function call.

*   **Constructor Calls**:

    ```javascript
    class MyClass {
      constructor(value) {
        this.value = value;
      }
    }
    const instance = new MyClass(5); // The C++ code handles the 'new' operation.
    ```

    The `Builtins::Generate_JSConstructStubGeneric`, `Builtins::Generate_JSBuiltinsConstructStub`, and `Builtins::Generate_InterpreterPushArgsThenFastConstructFunction` are relevant here.

*   **Generator Functions**:

    ```javascript
    function* myGenerator() {
      yield 1;
      yield 2;
    }
    const gen = myGenerator();
    gen.next(); // { value: 1, done: false }
    gen.next(); // { value: 2, done: false }
    ```

    The `Builtins::Generate_ResumeGeneratorTrampoline` function is invoked when `gen.next()` is called to resume the generator's execution.

*   **Interpreter Execution**:

    When JavaScript code is not optimized and runs in the interpreter, functions like `Builtins::Generate_InterpreterEntryTrampoline`, `Builtins::Generate_InterpreterPushArgsThenCallImpl`, and `Builtins::Generate_InterpreterPushArgsThenConstructImpl` are used to set up and execute the bytecode.

*   **Error Handling (Non-constructable)**:

    ```javascript
    const obj = {};
    try {
      new obj(); // Error: obj is not a constructor
    } catch (e) {
      console.error(e);
    }
    ```

    The `Builtins::Generate_ConstructedNonConstructable` function is involved in throwing this error.

In essence, this C++ file provides the foundational, architecture-specific (x64) implementation for many core JavaScript language features and the V8 engine's execution model. It bridges the gap between the high-level JavaScript code and the underlying machine instructions.
这是目录为 `v8/src/builtins/x64/builtins-x64.cc` 的一个 C++ 源代码文件的一部分。这个文件专门为 x64 架构定义了 V8 JavaScript 引擎的内置函数（builtins）。

**该部分的主要功能可以归纳为：**

1. **定义了函数调用和构造函数的入口点：**  它包含了 `Adaptor`、`JSConstructStubGeneric`、`JSBuiltinsConstructStub` 等函数，这些函数负责在 C++ 层面上接收 JavaScript 的函数调用和构造函数调用，并设置执行环境。
2. **处理了从 C++ 到 JavaScript 的调用：**  `Generate_JSEntry` 和相关的 `Generate_JSEntryVariant`、`Generate_JSEntryTrampoline` 等函数定义了从原生 C++ 代码进入 V8 JavaScript 执行环境的步骤，包括设置栈帧、保存寄存器、处理异常等。
3. **实现了 JavaScript 生成器 (Generator) 的恢复逻辑：** `Generate_ResumeGeneratorTrampoline` 函数负责在 `yield` 之后恢复生成器的执行状态。
4. **定义了解释器入口和执行流程的关键部分：**  `Generate_InterpreterEntryTrampoline` 函数是 V8 解释器的入口点，负责设置解释器栈帧、加载字节码、分发执行等核心操作。
5. **实现了在解释器中调用和构造 JavaScript 函数的逻辑：** `Generate_InterpreterPushArgsThenCallImpl` 和 `Generate_InterpreterPushArgsThenConstructImpl` 函数负责在解释器环境下将参数压栈，并调用或构造 JavaScript 函数。
6. **提供了优化构造函数调用的机制：** `Generate_InterpreterPushArgsThenFastConstructFunction` 函数实现了一种更快速的构造函数调用方式。
7. **包含了用于内部检查和断言的辅助函数：** 例如 `AssertCodeIsBaseline` 等，用于在开发和调试阶段验证代码的状态。
8. **处理了栈溢出等异常情况：**  在多个关键路径上都有对栈溢出的检查和处理。

**与 JavaScript 功能的关系及 JavaScript 示例：**

这个 C++ 文件中的代码是 V8 引擎执行 JavaScript 代码的底层实现。它直接对应于 JavaScript 语言的一些核心概念和操作。

*   **函数调用：**  当 JavaScript 中调用一个函数时，例如：

    ```javascript
    function add(a, b) {
      return a + b;
    }
    add(1, 2);
    ```

    `Builtins::Generate_Adaptor`、`Generate_JSEntry`、`Generate_JSEntryTrampoline` 以及解释器相关的 `Generate_InterpreterEntryTrampoline` 和 `Generate_InterpreterPushArgsThenCallImpl` 等函数都会参与到这个调用的执行过程中。

*   **构造函数调用：** 当使用 `new` 关键字创建对象时，例如：

    ```javascript
    class MyClass {
      constructor(value) {
        this.value = value;
      }
    }
    const obj = new MyClass(5);
    ```

    `Builtins::Generate_JSConstructStubGeneric`、`Builtins::Generate_JSBuiltinsConstructStub` 以及 `Generate_InterpreterPushArgsThenConstructImpl` 或 `Generate_InterpreterPushArgsThenFastConstructFunction` 等函数会处理这个构造过程。

*   **生成器函数：** 当使用生成器函数时，例如：

    ```javascript
    function* myGenerator() {
      yield 1;
      yield 2;
    }
    const gen = myGenerator();
    gen.next(); // { value: 1, done: false }
    gen.next(); // { value: 2, done: false }
    ```

    每次调用 `gen.next()` 时，`Builtins::Generate_ResumeGeneratorTrampoline` 函数会被调用来恢复生成器的执行。

*   **从 C++ 调用 JavaScript：**  V8 提供了 API 允许 C++ 代码执行 JavaScript 代码。`Generate_JSEntry` 系列函数就负责处理这种从 C++ 进入 JavaScript 执行环境的情况。

*   **解释器执行：** 当 JavaScript 代码没有被即时编译 (JIT) 或者处于某些需要解释执行的状态时，`Generate_InterpreterEntryTrampoline`  会作为入口，配合其他解释器相关的函数来执行 JavaScript 字节码。

总而言之，这个 C++ 文件中的代码是 V8 引擎的核心组成部分，它以机器码的形式实现了 JavaScript 语言的关键运行时机制。它直接响应 JavaScript 代码的执行，并在底层驱动着 JavaScript 代码的运行。

Prompt: 
```
这是目录为v8/src/builtins/x64/builtins-x64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if V8_TARGET_ARCH_X64

#include "src/api/api-arguments.h"
#include "src/base/bits-iterator.h"
#include "src/base/iterator.h"
#include "src/builtins/builtins-descriptors.h"
#include "src/builtins/builtins-inl.h"
#include "src/codegen/code-factory.h"
#include "src/codegen/interface-descriptors-inl.h"
// For interpreter_entry_return_pc_offset. TODO(jkummerow): Drop.
#include "src/codegen/macro-assembler-inl.h"
#include "src/codegen/register-configuration.h"
#include "src/codegen/x64/assembler-x64.h"
#include "src/common/globals.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/frame-constants.h"
#include "src/execution/frames.h"
#include "src/heap/heap-inl.h"
#include "src/logging/counters.h"
#include "src/objects/cell.h"
#include "src/objects/code.h"
#include "src/objects/debug-objects.h"
#include "src/objects/foreign.h"
#include "src/objects/heap-number.h"
#include "src/objects/js-generator.h"
#include "src/objects/objects-inl.h"
#include "src/objects/smi.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/baseline/liftoff-assembler-defs.h"
#include "src/wasm/object-access.h"
#include "src/wasm/stacks.h"
#include "src/wasm/wasm-constants.h"
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-objects.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

#define __ ACCESS_MASM(masm)

void Builtins::Generate_Adaptor(MacroAssembler* masm,
                                int formal_parameter_count, Address address) {
  __ CodeEntry();

  __ LoadAddress(kJavaScriptCallExtraArg1Register,
                 ExternalReference::Create(address));
  __ TailCallBuiltin(
      Builtins::AdaptorWithBuiltinExitFrame(formal_parameter_count));
}

namespace {

constexpr int kReceiverOnStackSize = kSystemPointerSize;

enum class ArgumentsElementType {
  kRaw,    // Push arguments as they are.
  kHandle  // Dereference arguments before pushing.
};

void Generate_PushArguments(MacroAssembler* masm, Register array, Register argc,
                            Register scratch,
                            ArgumentsElementType element_type) {
  DCHECK(!AreAliased(array, argc, scratch, kScratchRegister));
  Register counter = scratch;
  Label loop, entry;
  __ leaq(counter, Operand(argc, -kJSArgcReceiverSlots));
  __ jmp(&entry);
  __ bind(&loop);
  Operand value(array, counter, times_system_pointer_size, 0);
  if (element_type == ArgumentsElementType::kHandle) {
    __ movq(kScratchRegister, value);
    value = Operand(kScratchRegister, 0);
  }
  __ Push(value);
  __ bind(&entry);
  __ decq(counter);
  __ j(greater_equal, &loop, Label::kNear);
}

void Generate_JSBuiltinsConstructStubHelper(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- rax: number of arguments
  //  -- rdi: constructor function
  //  -- rdx: new target
  //  -- rsi: context
  // -----------------------------------

  Label stack_overflow;
  __ StackOverflowCheck(rax, &stack_overflow, Label::kFar);

  // Enter a construct frame.
  {
    FrameScope scope(masm, StackFrame::CONSTRUCT);

    // Preserve the incoming parameters on the stack.
    __ Push(rsi);
    __ Push(rax);

    // TODO(victorgomes): When the arguments adaptor is completely removed, we
    // should get the formal parameter count and copy the arguments in its
    // correct position (including any undefined), instead of delaying this to
    // InvokeFunction.

    // Set up pointer to first argument (skip receiver).
    __ leaq(rbx, Operand(rbp, StandardFrameConstants::kFixedFrameSizeAboveFp +
                                  kSystemPointerSize));
    // Copy arguments to the expression stack.
    // rbx: Pointer to start of arguments.
    // rax: Number of arguments.
    Generate_PushArguments(masm, rbx, rax, rcx, ArgumentsElementType::kRaw);
    // The receiver for the builtin/api call.
    __ PushRoot(RootIndex::kTheHoleValue);

    // Call the function.
    // rax: number of arguments (untagged)
    // rdi: constructor function
    // rdx: new target
    __ InvokeFunction(rdi, rdx, rax, InvokeType::kCall);

    // Restore arguments count from the frame.
    __ movq(rbx, Operand(rbp, ConstructFrameConstants::kLengthOffset));

    // Leave construct frame.
  }

  // Remove caller arguments from the stack and return.
  __ DropArguments(rbx, rcx);

  __ ret(0);

  __ bind(&stack_overflow);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kThrowStackOverflow);
    __ int3();  // This should be unreachable.
  }
}

}  // namespace

// This code needs to be present in all continuations pushed onto the
// stack during the deoptimization process. It is part of a scheme to ensure
// that the return address immediately after the call to
// Builtin::kAdaptShadowStackForDeopt is present on the hardware shadow stack.
// Below, you'll see that this call is unconditionally jumped over. However,
// during deoptimization, the address of the call is jumped to directly
// and executed. The end result being that later, returning to that address
// after the call will be successful because the user stack and the
// shadow stack will be found to match perfectly.
void Generate_CallToAdaptShadowStackForDeopt(MacroAssembler* masm,
                                             bool add_jump) {
#ifdef V8_ENABLE_CET_SHADOW_STACK
  ASM_CODE_COMMENT(masm);
  Label post_adapt_shadow_stack;
  if (add_jump) __ jmp(&post_adapt_shadow_stack, Label::kNear);
  const auto saved_pc_offset = masm->pc_offset();
  __ Call(Operand(kRootRegister, IsolateData::BuiltinEntrySlotOffset(
                                     Builtin::kAdaptShadowStackForDeopt)));
  CHECK_EQ(Deoptimizer::kAdaptShadowStackOffsetToSubtract,
           masm->pc_offset() - saved_pc_offset);
  if (add_jump) __ bind(&post_adapt_shadow_stack);
#endif  // V8_ENABLE_CET_SHADOW_STACK
}

// The construct stub for ES5 constructor functions and ES6 class constructors.
void Builtins::Generate_JSConstructStubGeneric(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- rax: number of arguments (untagged)
  //  -- rdi: constructor function
  //  -- rdx: new target
  //  -- rsi: context
  //  -- sp[...]: constructor arguments
  // -----------------------------------

  FrameScope scope(masm, StackFrame::MANUAL);
  // Enter a construct frame.
  __ EnterFrame(StackFrame::CONSTRUCT);
  Label post_instantiation_deopt_entry, not_create_implicit_receiver;

  // Preserve the incoming parameters on the stack.
  __ Push(rsi);
  __ Push(rax);
  __ Push(rdi);
  __ PushRoot(RootIndex::kTheHoleValue);
  __ Push(rdx);

  // ----------- S t a t e -------------
  //  --         sp[0*kSystemPointerSize]: new target
  //  --         sp[1*kSystemPointerSize]: padding
  //  -- rdi and sp[2*kSystemPointerSize]: constructor function
  //  --         sp[3*kSystemPointerSize]: argument count
  //  --         sp[4*kSystemPointerSize]: context
  // -----------------------------------

  const TaggedRegister shared_function_info(rbx);
  __ LoadTaggedField(shared_function_info,
                     FieldOperand(rdi, JSFunction::kSharedFunctionInfoOffset));
  __ movl(rbx,
          FieldOperand(shared_function_info, SharedFunctionInfo::kFlagsOffset));
  __ DecodeField<SharedFunctionInfo::FunctionKindBits>(rbx);
  __ JumpIfIsInRange(
      rbx, static_cast<uint32_t>(FunctionKind::kDefaultDerivedConstructor),
      static_cast<uint32_t>(FunctionKind::kDerivedConstructor),
      &not_create_implicit_receiver, Label::kNear);

  // If not derived class constructor: Allocate the new receiver object.
  __ CallBuiltin(Builtin::kFastNewObject);
  __ jmp(&post_instantiation_deopt_entry, Label::kNear);

  // Else: use TheHoleValue as receiver for constructor call
  __ bind(&not_create_implicit_receiver);
  __ LoadRoot(rax, RootIndex::kTheHoleValue);

  // ----------- S t a t e -------------
  //  -- rax                          implicit receiver
  //  -- Slot 4 / sp[0*kSystemPointerSize]  new target
  //  -- Slot 3 / sp[1*kSystemPointerSize]  padding
  //  -- Slot 2 / sp[2*kSystemPointerSize]  constructor function
  //  -- Slot 1 / sp[3*kSystemPointerSize]  number of arguments
  //  -- Slot 0 / sp[4*kSystemPointerSize]  context
  // -----------------------------------
  __ bind(&post_instantiation_deopt_entry);

  // Restore new target.
  __ Pop(rdx);

  // Push the allocated receiver to the stack.
  __ Push(rax);

  // We need two copies because we may have to return the original one
  // and the calling conventions dictate that the called function pops the
  // receiver. The second copy is pushed after the arguments, we saved in r8
  // since rax needs to store the number of arguments before
  // InvokingFunction.
  __ movq(r8, rax);

  // Set up pointer to first argument (skip receiver).
  __ leaq(rbx, Operand(rbp, StandardFrameConstants::kFixedFrameSizeAboveFp +
                                kSystemPointerSize));

  // Restore constructor function and argument count.
  __ movq(rdi, Operand(rbp, ConstructFrameConstants::kConstructorOffset));
  __ movq(rax, Operand(rbp, ConstructFrameConstants::kLengthOffset));

  // Check if we have enough stack space to push all arguments.
  // Argument count in rax.
  Label stack_overflow;
  __ StackOverflowCheck(rax, &stack_overflow);

  // TODO(victorgomes): When the arguments adaptor is completely removed, we
  // should get the formal parameter count and copy the arguments in its
  // correct position (including any undefined), instead of delaying this to
  // InvokeFunction.

  // Copy arguments to the expression stack.
  // rbx: Pointer to start of arguments.
  // rax: Number of arguments.
  Generate_PushArguments(masm, rbx, rax, rcx, ArgumentsElementType::kRaw);

  // Push implicit receiver.
  __ Push(r8);

  // Call the function.
  __ InvokeFunction(rdi, rdx, rax, InvokeType::kCall);

  // If the result is an object (in the ECMA sense), we should get rid
  // of the receiver and use the result; see ECMA-262 section 13.2.2-7
  // on page 74.
  Label use_receiver, do_throw, leave_and_return, check_result;

  // If the result is undefined, we'll use the implicit receiver. Otherwise we
  // do a smi check and fall through to check if the return value is a valid
  // receiver.
  __ JumpIfNotRoot(rax, RootIndex::kUndefinedValue, &check_result,
                   Label::kNear);

  // Throw away the result of the constructor invocation and use the
  // on-stack receiver as the result.
  __ bind(&use_receiver);
  __ movq(rax, Operand(rsp, 0 * kSystemPointerSize));
  __ JumpIfRoot(rax, RootIndex::kTheHoleValue, &do_throw, Label::kNear);

  __ bind(&leave_and_return);
  // Restore the arguments count.
  __ movq(rbx, Operand(rbp, ConstructFrameConstants::kLengthOffset));
  __ LeaveFrame(StackFrame::CONSTRUCT);
  // Remove caller arguments from the stack and return.
  __ DropArguments(rbx, rcx);
  __ ret(0);

  // If the result is a smi, it is *not* an object in the ECMA sense.
  __ bind(&check_result);
  __ JumpIfSmi(rax, &use_receiver, Label::kNear);

  // Check if the type of the result is not an object in the ECMA sense.
  __ JumpIfJSAnyIsNotPrimitive(rax, rcx, &leave_and_return, Label::kNear);
  __ jmp(&use_receiver);

  __ bind(&do_throw);
  // Restore context from the frame.
  __ movq(rsi, Operand(rbp, ConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowConstructorReturnedNonObject);
  // We don't return here.
  __ int3();

  __ bind(&stack_overflow);
  // Restore the context from the frame.
  __ movq(rsi, Operand(rbp, ConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowStackOverflow);
  // This should be unreachable.
  __ int3();

  // Since the address below is returned into instead of being called directly,
  // special code to get that address on the shadow stack is necessary to avoid
  // a security exception.
  Generate_CallToAdaptShadowStackForDeopt(masm, false);
  // Deoptimizer enters here.
  masm->isolate()->heap()->SetConstructStubCreateDeoptPCOffset(
      masm->pc_offset());
  __ jmp(&post_instantiation_deopt_entry, Label::kNear);
}

void Builtins::Generate_JSBuiltinsConstructStub(MacroAssembler* masm) {
  Generate_JSBuiltinsConstructStubHelper(masm);
}

void Builtins::Generate_ConstructedNonConstructable(MacroAssembler* masm) {
  FrameScope scope(masm, StackFrame::INTERNAL);
  __ Push(rdi);
  __ CallRuntime(Runtime::kThrowConstructedNonConstructable);
}

namespace {

// Called with the native C calling convention. The corresponding function
// signature is either:
//   using JSEntryFunction = GeneratedCode<Address(
//       Address root_register_value, Address new_target, Address target,
//       Address receiver, intptr_t argc, Address** argv)>;
// or
//   using JSEntryFunction = GeneratedCode<Address(
//       Address root_register_value, MicrotaskQueue* microtask_queue)>;
void Generate_JSEntryVariant(MacroAssembler* masm, StackFrame::Type type,
                             Builtin entry_trampoline) {
  Label invoke, handler_entry, exit;
  Label not_outermost_js, not_outermost_js_2;

  {
    NoRootArrayScope uninitialized_root_register(masm);

    // Set up the frame.
    //
    // Note: at this point we are entering V8-generated code from C++ and thus
    // rbp can be an arbitrary value (-fomit-frame-pointer). Since V8 still
    // needs to know where the next interesting frame is for the purpose of
    // stack walks, we instead push the stored EXIT frame fp
    // (IsolateAddressId::kCEntryFPAddress) below to a dedicated slot.
    __ pushq(rbp);
    __ movq(rbp, rsp);

    // Push the stack frame type.
    __ Push(Immediate(StackFrame::TypeToMarker(type)));
    // Reserve a slot for the context. It is filled after the root register has
    // been set up.
    __ AllocateStackSpace(kSystemPointerSize);
    // Save callee-saved registers (X64/X32/Win64 calling conventions).
    __ pushq(r12);
    __ pushq(r13);
    __ pushq(r14);
    __ pushq(r15);
#ifdef V8_TARGET_OS_WIN
    __ pushq(rdi);  // Only callee save in Win64 ABI, argument in AMD64 ABI.
    __ pushq(rsi);  // Only callee save in Win64 ABI, argument in AMD64 ABI.
#endif
    __ pushq(rbx);

#ifdef V8_TARGET_OS_WIN
    // On Win64 XMM6-XMM15 are callee-save.
    __ AllocateStackSpace(EntryFrameConstants::kXMMRegistersBlockSize);
    __ movdqu(Operand(rsp, EntryFrameConstants::kXMMRegisterSize * 0), xmm6);
    __ movdqu(Operand(rsp, EntryFrameConstants::kXMMRegisterSize * 1), xmm7);
    __ movdqu(Operand(rsp, EntryFrameConstants::kXMMRegisterSize * 2), xmm8);
    __ movdqu(Operand(rsp, EntryFrameConstants::kXMMRegisterSize * 3), xmm9);
    __ movdqu(Operand(rsp, EntryFrameConstants::kXMMRegisterSize * 4), xmm10);
    __ movdqu(Operand(rsp, EntryFrameConstants::kXMMRegisterSize * 5), xmm11);
    __ movdqu(Operand(rsp, EntryFrameConstants::kXMMRegisterSize * 6), xmm12);
    __ movdqu(Operand(rsp, EntryFrameConstants::kXMMRegisterSize * 7), xmm13);
    __ movdqu(Operand(rsp, EntryFrameConstants::kXMMRegisterSize * 8), xmm14);
    __ movdqu(Operand(rsp, EntryFrameConstants::kXMMRegisterSize * 9), xmm15);
    static_assert(EntryFrameConstants::kCalleeSaveXMMRegisters == 10);
    static_assert(EntryFrameConstants::kXMMRegistersBlockSize ==
                  EntryFrameConstants::kXMMRegisterSize *
                      EntryFrameConstants::kCalleeSaveXMMRegisters);
#endif

    // Initialize the root register.
    // C calling convention. The first argument is passed in kCArgRegs[0].
    __ movq(kRootRegister, kCArgRegs[0]);

#ifdef V8_COMPRESS_POINTERS
    // Initialize the pointer cage base register.
    __ LoadRootRelative(kPtrComprCageBaseRegister,
                        IsolateData::cage_base_offset());
#endif
  }

  // Save copies of the top frame descriptor on the stack.
  ExternalReference c_entry_fp = ExternalReference::Create(
      IsolateAddressId::kCEntryFPAddress, masm->isolate());

  {
    // Keep this static_assert to preserve a link between the offset constant
    // and the code location it refers to.
#ifdef V8_TARGET_OS_WIN
    static_assert(EntryFrameConstants::kNextExitFrameFPOffset ==
                  -3 * kSystemPointerSize + -7 * kSystemPointerSize -
                      EntryFrameConstants::kXMMRegistersBlockSize);
#else
    static_assert(EntryFrameConstants::kNextExitFrameFPOffset ==
                  -3 * kSystemPointerSize + -5 * kSystemPointerSize);
#endif  // V8_TARGET_OS_WIN
    Operand c_entry_fp_operand = masm->ExternalReferenceAsOperand(c_entry_fp);
    __ Push(c_entry_fp_operand);

    // Clear c_entry_fp, now we've pushed its previous value to the stack.
    // If the c_entry_fp is not already zero and we don't clear it, the
    // StackFrameIteratorForProfiler will assume we are executing C++ and miss
    // the JS frames on top.
    // Do the same for the fast C call fp and pc.
    __ Move(c_entry_fp_operand, 0);

    Operand fast_c_call_fp_operand =
        masm->ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP);
    Operand fast_c_call_pc_operand =
        masm->ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerPC);
    __ Push(fast_c_call_fp_operand);
    __ Move(fast_c_call_fp_operand, 0);

    __ Push(fast_c_call_pc_operand);
    __ Move(fast_c_call_pc_operand, 0);
  }

  // Store the context address in the previously-reserved slot.
  ExternalReference context_address = ExternalReference::Create(
      IsolateAddressId::kContextAddress, masm->isolate());
  __ Load(kScratchRegister, context_address);
  static constexpr int kOffsetToContextSlot = -2 * kSystemPointerSize;
  __ movq(Operand(rbp, kOffsetToContextSlot), kScratchRegister);

  // If this is the outermost JS call, set js_entry_sp value.
  ExternalReference js_entry_sp = ExternalReference::Create(
      IsolateAddressId::kJSEntrySPAddress, masm->isolate());
  __ Load(rax, js_entry_sp);
  __ testq(rax, rax);
  __ j(not_zero, &not_outermost_js);
  __ Push(Immediate(StackFrame::OUTERMOST_JSENTRY_FRAME));
  __ movq(rax, rbp);
  __ Store(js_entry_sp, rax);
  Label cont;
  __ jmp(&cont);
  __ bind(&not_outermost_js);
  __ Push(Immediate(StackFrame::INNER_JSENTRY_FRAME));
  __ bind(&cont);

  // Jump to a faked try block that does the invoke, with a faked catch
  // block that sets the exception.
  __ jmp(&invoke);
  __ BindExceptionHandler(&handler_entry);

  // Store the current pc as the handler offset. It's used later to create the
  // handler table.
  masm->isolate()->builtins()->SetJSEntryHandlerOffset(handler_entry.pos());

  // Caught exception: Store result (exception) in the exception
  // field in the JSEnv and return a failure sentinel.
  ExternalReference exception = ExternalReference::Create(
      IsolateAddressId::kExceptionAddress, masm->isolate());
  __ Store(exception, rax);
  __ LoadRoot(rax, RootIndex::kException);
  __ jmp(&exit);

  // Invoke: Link this frame into the handler chain.
  __ bind(&invoke);
  __ PushStackHandler();

  // Invoke the function by calling through JS entry trampoline builtin and
  // pop the faked function when we return.
  __ CallBuiltin(entry_trampoline);

  // Unlink this frame from the handler chain.
  __ PopStackHandler();

  __ bind(&exit);
  // Check if the current stack frame is marked as the outermost JS frame.
  __ Pop(rbx);
  __ cmpq(rbx, Immediate(StackFrame::OUTERMOST_JSENTRY_FRAME));
  __ j(not_equal, &not_outermost_js_2);
  __ Move(kScratchRegister, js_entry_sp);
  __ movq(Operand(kScratchRegister, 0), Immediate(0));
  __ bind(&not_outermost_js_2);

  // Restore the top frame descriptor from the stack.
  {
    Operand fast_c_call_pc_operand =
        masm->ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerPC);
    __ Pop(fast_c_call_pc_operand);

    Operand fast_c_call_fp_operand =
        masm->ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP);
    __ Pop(fast_c_call_fp_operand);

    Operand c_entry_fp_operand = masm->ExternalReferenceAsOperand(c_entry_fp);
    __ Pop(c_entry_fp_operand);
  }

  // Restore callee-saved registers (X64 conventions).
#ifdef V8_TARGET_OS_WIN
  // On Win64 XMM6-XMM15 are callee-save
  __ movdqu(xmm6, Operand(rsp, EntryFrameConstants::kXMMRegisterSize * 0));
  __ movdqu(xmm7, Operand(rsp, EntryFrameConstants::kXMMRegisterSize * 1));
  __ movdqu(xmm8, Operand(rsp, EntryFrameConstants::kXMMRegisterSize * 2));
  __ movdqu(xmm9, Operand(rsp, EntryFrameConstants::kXMMRegisterSize * 3));
  __ movdqu(xmm10, Operand(rsp, EntryFrameConstants::kXMMRegisterSize * 4));
  __ movdqu(xmm11, Operand(rsp, EntryFrameConstants::kXMMRegisterSize * 5));
  __ movdqu(xmm12, Operand(rsp, EntryFrameConstants::kXMMRegisterSize * 6));
  __ movdqu(xmm13, Operand(rsp, EntryFrameConstants::kXMMRegisterSize * 7));
  __ movdqu(xmm14, Operand(rsp, EntryFrameConstants::kXMMRegisterSize * 8));
  __ movdqu(xmm15, Operand(rsp, EntryFrameConstants::kXMMRegisterSize * 9));
  __ addq(rsp, Immediate(EntryFrameConstants::kXMMRegistersBlockSize));
#endif

  __ popq(rbx);
#ifdef V8_TARGET_OS_WIN
  // Callee save on in Win64 ABI, arguments/volatile in AMD64 ABI.
  __ popq(rsi);
  __ popq(rdi);
#endif
  __ popq(r15);
  __ popq(r14);
  __ popq(r13);
  __ popq(r12);
  __ addq(rsp, Immediate(2 * kSystemPointerSize));  // remove markers

  // Restore frame pointer and return.
  __ popq(rbp);
  __ ret(0);
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
  // Expects six C++ function parameters.
  // - Address root_register_value
  // - Address new_target (tagged Object pointer)
  // - Address function (tagged JSFunction pointer)
  // - Address receiver (tagged Object pointer)
  // - intptr_t argc
  // - Address** argv (pointer to array of tagged Object pointers)
  // (see Handle::Invoke in execution.cc).

  // Open a C++ scope for the FrameScope.
  {
    // Platform specific argument handling. After this, the stack contains
    // an internal frame and the pushed function and receiver, and
    // register rax and rbx holds the argument count and argument array,
    // while rdi holds the function pointer, rsi the context, and rdx the
    // new.target.

    // MSVC parameters in:
    // rcx        : root_register_value
    // rdx        : new_target
    // r8         : function
    // r9         : receiver
    // [rsp+0x20] : argc
    // [rsp+0x28] : argv
    //
    // GCC parameters in:
    // rdi : root_register_value
    // rsi : new_target
    // rdx : function
    // rcx : receiver
    // r8  : argc
    // r9  : argv

    __ movq(rdi, kCArgRegs[2]);
    __ Move(rdx, kCArgRegs[1]);
    // rdi : function
    // rdx : new_target

    // Clear the context before we push it when entering the internal frame.
    __ Move(rsi, 0);

    // Enter an internal frame.
    FrameScope scope(masm, StackFrame::INTERNAL);

    // Setup the context (we need to use the caller context from the isolate).
    ExternalReference context_address = ExternalReference::Create(
        IsolateAddressId::kContextAddress, masm->isolate());
    __ movq(rsi, masm->ExternalReferenceAsOperand(context_address));

    // Push the function onto the stack.
    __ Push(rdi);

#ifdef V8_TARGET_OS_WIN
    // Load the previous frame pointer to access C arguments on stack
    __ movq(kScratchRegister, Operand(rbp, 0));
    // Load the number of arguments and setup pointer to the arguments.
    __ movq(rax, Operand(kScratchRegister, EntryFrameConstants::kArgcOffset));
    __ movq(rbx, Operand(kScratchRegister, EntryFrameConstants::kArgvOffset));
#else   // V8_TARGET_OS_WIN
    // Load the number of arguments and setup pointer to the arguments.
    __ movq(rax, r8);
    __ movq(rbx, r9);
    __ movq(r9, kCArgRegs[3]);  // Temporarily saving the receiver.
#endif  // V8_TARGET_OS_WIN

    // Current stack contents:
    // [rsp + kSystemPointerSize]     : Internal frame
    // [rsp]                          : function
    // Current register contents:
    // rax : argc
    // rbx : argv
    // rsi : context
    // rdi : function
    // rdx : new.target
    // r9  : receiver

    // Check if we have enough stack space to push all arguments.
    // Argument count in rax.
    Label enough_stack_space, stack_overflow;
    __ StackOverflowCheck(rax, &stack_overflow, Label::kNear);
    __ jmp(&enough_stack_space, Label::kNear);

    __ bind(&stack_overflow);
    __ CallRuntime(Runtime::kThrowStackOverflow);
    // This should be unreachable.
    __ int3();

    __ bind(&enough_stack_space);

    // Copy arguments to the stack.
    // Register rbx points to array of pointers to handle locations.
    // Push the values of these handles.
    // rbx: Pointer to start of arguments.
    // rax: Number of arguments.
    Generate_PushArguments(masm, rbx, rax, rcx, ArgumentsElementType::kHandle);

    // Push the receiver.
    __ Push(r9);

    // Invoke the builtin code.
    Builtin builtin = is_construct ? Builtin::kConstruct : Builtins::Call();
    __ CallBuiltin(builtin);

    // Exit the internal frame. Notice that this also removes the empty
    // context and the function left on the stack by the code
    // invocation.
  }

  __ ret(0);
}

void Builtins::Generate_JSEntryTrampoline(MacroAssembler* masm) {
  Generate_JSEntryTrampolineHelper(masm, false);
}

void Builtins::Generate_JSConstructEntryTrampoline(MacroAssembler* masm) {
  Generate_JSEntryTrampolineHelper(masm, true);
}

void Builtins::Generate_RunMicrotasksTrampoline(MacroAssembler* masm) {
  // kCArgRegs[1]: microtask_queue
  __ movq(RunMicrotasksDescriptor::MicrotaskQueueRegister(), kCArgRegs[1]);
  __ TailCallBuiltin(Builtin::kRunMicrotasks);
}

static void AssertCodeIsBaselineAllowClobber(MacroAssembler* masm,
                                             Register code, Register scratch) {
  // Verify that the code kind is baseline code via the CodeKind.
  __ movl(scratch, FieldOperand(code, Code::kFlagsOffset));
  __ DecodeField<Code::KindField>(scratch);
  __ cmpl(scratch, Immediate(static_cast<int>(CodeKind::BASELINE)));
  __ Assert(equal, AbortReason::kExpectedBaselineData);
}

static void AssertCodeIsBaseline(MacroAssembler* masm, Register code,
                                 Register scratch) {
  DCHECK(!AreAliased(code, scratch));
  return AssertCodeIsBaselineAllowClobber(masm, code, scratch);
}

static void CheckSharedFunctionInfoBytecodeOrBaseline(MacroAssembler* masm,
                                                      Register data,
                                                      Register scratch,
                                                      Label* is_baseline,
                                                      Label* is_bytecode) {
#if V8_STATIC_ROOTS_BOOL
  __ IsObjectTypeFast(data, CODE_TYPE, scratch);
#else
  __ CmpObjectType(data, CODE_TYPE, scratch);
#endif  // V8_STATIC_ROOTS_BOOL
  if (v8_flags.debug_code) {
    Label not_baseline;
    __ j(not_equal, &not_baseline);
    AssertCodeIsBaseline(masm, data, scratch);
    __ j(equal, is_baseline);
    __ bind(&not_baseline);
  } else {
    __ j(equal, is_baseline);
  }

#if V8_STATIC_ROOTS_BOOL
  // Scratch1 already contains the compressed map.
  __ CompareInstanceTypeWithUniqueCompressedMap(scratch, INTERPRETER_DATA_TYPE);
#else
  // Scratch1 already contains the instance type.
  __ CmpInstanceType(scratch, INTERPRETER_DATA_TYPE);
#endif  // V8_STATIC_ROOTS_BOOL
  __ j(not_equal, is_bytecode, Label::kNear);
}

static void GetSharedFunctionInfoBytecodeOrBaseline(
    MacroAssembler* masm, Register sfi, Register bytecode, Register scratch1,
    Label* is_baseline, Label* is_unavailable) {
  ASM_CODE_COMMENT(masm);
  Label done;

  Register data = bytecode;
  __ LoadTrustedPointerField(
      data, FieldOperand(sfi, SharedFunctionInfo::kTrustedFunctionDataOffset),
      kUnknownIndirectPointerTag, scratch1);

  if (V8_JITLESS_BOOL) {
    __ IsObjectType(data, INTERPRETER_DATA_TYPE, scratch1);
    __ j(not_equal, &done, Label::kNear);
  } else {
    CheckSharedFunctionInfoBytecodeOrBaseline(masm, data, scratch1, is_baseline,
                                              &done);
  }

  __ LoadProtectedPointerField(
      bytecode, FieldOperand(data, InterpreterData::kBytecodeArrayOffset));

  __ bind(&done);
  __ IsObjectType(bytecode, BYTECODE_ARRAY_TYPE, scratch1);
  __ j(not_equal, is_unavailable);
}

// static
void Builtins::Generate_ResumeGeneratorTrampoline(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- rax    : the value to pass to the generator
  //  -- rdx    : the JSGeneratorObject to resume
  //  -- rsp[0] : return address
  // -----------------------------------

  // Store input value into generator object.
  __ StoreTaggedField(
      FieldOperand(rdx, JSGeneratorObject::kInputOrDebugPosOffset), rax);
  Register object = WriteBarrierDescriptor::ObjectRegister();
  __ Move(object, rdx);
  __ RecordWriteField(object, JSGeneratorObject::kInputOrDebugPosOffset, rax,
                      WriteBarrierDescriptor::SlotAddressRegister(),
                      SaveFPRegsMode::kIgnore);
  // Check that rdx is still valid, RecordWrite might have clobbered it.
  __ AssertGeneratorObject(rdx);

  // Load suspended function and context.
  __ LoadTaggedField(rdi,
                     FieldOperand(rdx, JSGeneratorObject::kFunctionOffset));
  __ LoadTaggedField(rsi, FieldOperand(rdi, JSFunction::kContextOffset));

  // Flood function if we are stepping.
  Label prepare_step_in_if_stepping, prepare_step_in_suspended_generator;
  Label stepping_prepared;
  ExternalReference debug_hook =
      ExternalReference::debug_hook_on_function_call_address(masm->isolate());
  Operand debug_hook_operand = masm->ExternalReferenceAsOperand(debug_hook);
  __ cmpb(debug_hook_operand, Immediate(0));
  __ j(not_equal, &prepare_step_in_if_stepping);

  // Flood function if we need to continue stepping in the suspended generator.
  ExternalReference debug_suspended_generator =
      ExternalReference::debug_suspended_generator_address(masm->isolate());
  Operand debug_suspended_generator_operand =
      masm->ExternalReferenceAsOperand(debug_suspended_generator);
  __ cmpq(rdx, debug_suspended_generator_operand);
  __ j(equal, &prepare_step_in_suspended_generator);
  __ bind(&stepping_prepared);

  // Check the stack for overflow. We are not trying to catch interruptions
  // (i.e. debug break and preemption) here, so check the "real stack limit".
  Label stack_overflow;
  __ cmpq(rsp, __ StackLimitAsOperand(StackLimitKind::kRealStackLimit));
  __ j(below, &stack_overflow);

  // ----------- S t a t e -------------
  //  -- rdx    : the JSGeneratorObject to resume
  //  -- rdi    : generator function
  //  -- rsi    : generator context
  // -----------------------------------

  Register decompr_scratch1 = COMPRESS_POINTERS_BOOL ? r8 : no_reg;
  Register argc = kJavaScriptCallArgCountRegister;
  Register index = r9;
  Register return_address = r11;
  Register params_array = rbx;

  __ PopReturnAddressTo(return_address);

  // Compute actual arguments count value as a formal parameter count without
  // receiver, loaded from the dispatch table entry or shared function info.
#if V8_ENABLE_LEAPTIERING
  static_assert(kJavaScriptCallCodeStartRegister == rcx, "ABI mismatch");
  static_assert(kJavaScriptCallDispatchHandleRegister == r15, "ABI mismatch");
  __ movl(r15, FieldOperand(rdi, JSFunction::kDispatchHandleOffset));
  __ LoadEntrypointAndParameterCountFromJSDispatchTable(rcx, argc, r15);
#else
  __ LoadTaggedField(argc,
                     FieldOperand(rdi, JSFunction::kSharedFunctionInfoOffset));
  __ movzxwq(argc, FieldOperand(
                       argc, SharedFunctionInfo::kFormalParameterCountOffset));
#endif  // V8_ENABLE_LEAPTIERING

  // Сopy the function arguments from the generator object's register file.
  {
    Label push_arguments, done_loop, loop;

#if V8_ENABLE_LEAPTIERING
    // In case the formal parameter count is kDontAdaptArgumentsSentinel the
    // actual arguments count should be set accordingly.
    static_assert(kDontAdaptArgumentsSentinel < JSParameterCount(0));
    __ cmpl(argc, Immediate(JSParameterCount(0)));
    __ j(kGreaterThan, &push_arguments, Label::kNear);
    __ movl(argc, Immediate(JSParameterCount(0)));
    __ jmp(&done_loop, Label::kNear);
#else
    // Generator functions are always created from user code and thus the
    // formal parameter count is never equal to kDontAdaptArgumentsSentinel,
    // which is used only for certain non-generator builtin functions.
#endif  // V8_ENABLE_LEAPTIERING

    __ bind(&push_arguments);
    __ LoadTaggedField(
        params_array,
        FieldOperand(rdx, JSGeneratorObject::kParametersAndRegistersOffset));

    // Exclude receiver.
    __ leal(index, Operand(argc, -1));

    __ bind(&loop);
    __ decl(index);
    __ j(kLessThan, &done_loop, Label::kNear);
    __ PushTaggedField(FieldOperand(params_array, index, times_tagged_size,
                                    OFFSET_OF_DATA_START(FixedArray)),
                       decompr_scratch1);
    __ jmp(&loop);
    __ bind(&done_loop);

    // Push the receiver.
    __ PushTaggedField(FieldOperand(rdx, JSGeneratorObject::kReceiverOffset),
                       decompr_scratch1);
  }

  // Underlying function needs to have bytecode available.
  if (v8_flags.debug_code) {
    Label is_baseline, is_unavailable, ok;
    Register scratch = ReassignRegister(params_array);
    __ LoadTaggedField(
        scratch, FieldOperand(rdi, JSFunction::kSharedFunctionInfoOffset));
    GetSharedFunctionInfoBytecodeOrBaseline(masm, scratch, scratch,
                                            kScratchRegister, &is_baseline,
                                            &is_unavailable);
    __ jmp(&ok);

    __ bind(&is_unavailable);
    __ Abort(AbortReason::kMissingBytecodeArray);

    __ bind(&is_baseline);
    __ IsObjectType(scratch, CODE_TYPE, scratch);
    __ Assert(equal, AbortReason::kMissingBytecodeArray);

    __ bind(&ok);
  }

  // Resume (Ignition/TurboFan) generator object.
  {
    __ PushReturnAddressFrom(return_address);
    // We abuse new.target both to indicate that this is a resume call and to
    // pass in the generator object.  In ordinary calls, new.target is always
    // undefined because generator functions are non-constructable.
    static_assert(kJavaScriptCallCodeStartRegister == rcx, "ABI mismatch");
#if V8_ENABLE_LEAPTIERING
    // Actual arguments count and code start are already initialized above.
    __ jmp(rcx);
#else
    // Actual arguments count is already initialized above.
    __ JumpJSFunction(rdi);
#endif  // V8_ENABLE_LEAPTIERING
  }

  __ bind(&prepare_step_in_if_stepping);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ Push(rdx);
    __ Push(rdi);
    // Push hole as receiver since we do not use it for stepping.
    __ PushRoot(RootIndex::kTheHoleValue);
    __ CallRuntime(Runtime::kDebugOnFunctionCall);
    __ Pop(rdx);
    __ LoadTaggedField(rdi,
                       FieldOperand(rdx, JSGeneratorObject::kFunctionOffset));
  }
  __ jmp(&stepping_prepared);

  __ bind(&prepare_step_in_suspended_generator);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ Push(rdx);
    __ CallRuntime(Runtime::kDebugPrepareStepInSuspendedGenerator);
    __ Pop(rdx);
    __ LoadTaggedField(rdi,
                       FieldOperand(rdx, JSGeneratorObject::kFunctionOffset));
  }
  __ jmp(&stepping_prepared);

  __ bind(&stack_overflow);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kThrowStackOverflow);
    __ int3();  // This should be unreachable.
  }
}

static void LeaveInterpreterFrame(MacroAssembler* masm, Register scratch1,
                                  Register scratch2) {
  ASM_CODE_COMMENT(masm);
  Register params_size = scratch1;
  // Get the size of the formal parameters (in bytes).
  __ movq(params_size,
          Operand(rbp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ movzxwl(params_size,
             FieldOperand(params_size, BytecodeArray::kParameterSizeOffset));

  Register actual_params_size = scratch2;
  // Compute the size of the actual parameters (in bytes).
  __ movq(actual_params_size,
          Operand(rbp, StandardFrameConstants::kArgCOffset));

  // If actual is bigger than formal, then we should use it to free up the stack
  // arguments.
  __ cmpq(params_size, actual_params_size);
  __ cmovq(kLessThan, params_size, actual_params_size);

  // Leave the frame (also dropping the register file).
  __ leave();

  // Drop receiver + arguments.
  __ DropArguments(params_size, scratch2);
}

// Tail-call |function_id| if |actual_state| == |expected_state|
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
  DCHECK(!AreAliased(bytecode_array, bytecode_offset, bytecode,
                     bytecode_size_table, original_bytecode_offset));

  __ movq(original_bytecode_offset, bytecode_offset);

  __ Move(bytecode_size_table,
          ExternalReference::bytecode_size_table_address());

  // Check if the bytecode is a Wide or ExtraWide prefix bytecode.
  Label process_bytecode, extra_wide;
  static_assert(0 == static_cast<int>(interpreter::Bytecode::kWide));
  static_assert(1 == static_cast<int>(interpreter::Bytecode::kExtraWide));
  static_assert(2 == static_cast<int>(interpreter::Bytecode::kDebugBreakWide));
  static_assert(3 ==
                static_cast<int>(interpreter::Bytecode::kDebugBreakExtraWide));
  __ cmpb(bytecode, Immediate(0x3));
  __ j(above, &process_bytecode, Label::kNear);
  // The code to load the next bytecode is common to both wide and extra wide.
  // We can hoist them up here. incl has to happen before testb since it
  // modifies the ZF flag.
  __ incl(bytecode_offset);
  __ testb(bytecode, Immediate(0x1));
  __ movzxbq(bytecode, Operand(bytecode_array, bytecode_offset, times_1, 0));
  __ j(not_equal, &extra_wide, Label::kNear);

  // Update table to the wide scaled table.
  __ addq(bytecode_size_table,
          Immediate(kByteSize * interpreter::Bytecodes::kBytecodeCount));
  __ jmp(&process_bytecode, Label::kNear);

  __ bind(&extra_wide);
  // Update table to the extra wide scaled table.
  __ addq(bytecode_size_table,
          Immediate(2 * kByteSize * interpreter::Bytecodes::kBytecodeCount));

  __ bind(&process_bytecode);

// Bailout to the return label if this is a return bytecode.
#define JUMP_IF_EQUAL(NAME)                                             \
  __ cmpb(bytecode,                                                     \
          Immediate(static_cast<int>(interpreter::Bytecode::k##NAME))); \
  __ j(equal, if_return, Label::kFar);
  RETURN_BYTECODE_LIST(JUMP_IF_EQUAL)
#undef JUMP_IF_EQUAL

  // If this is a JumpLoop, re-execute it to perform the jump to the beginning
  // of the loop.
  Label end, not_jump_loop;
  __ cmpb(bytecode,
          Immediate(static_cast<int>(interpreter::Bytecode::kJumpLoop)));
  __ j(not_equal, &not_jump_loop, Label::kNear);
  // We need to restore the original bytecode_offset since we might have
  // increased it to skip the wide / extra-wide prefix bytecode.
  __ movq(bytecode_offset, original_bytecode_offset);
  __ jmp(&end, Label::kNear);

  __ bind(&not_jump_loop);
  // Otherwise, load the size of the current bytecode and advance the offset.
  __ movzxbl(kScratchRegister,
             Operand(bytecode_size_table, bytecode, times_1, 0));
  __ addl(bytecode_offset, kScratchRegister);

  __ bind(&end);
}

namespace {

void ResetSharedFunctionInfoAge(MacroAssembler* masm, Register sfi) {
  __ movw(FieldOperand(sfi, SharedFunctionInfo::kAgeOffset), Immediate(0));
}

void ResetJSFunctionAge(MacroAssembler* masm, Register js_function) {
  const Register shared_function_info(kScratchRegister);
  __ LoadTaggedField(
      shared_function_info,
      FieldOperand(js_function, JSFunction::kSharedFunctionInfoOffset));
  ResetSharedFunctionInfoAge(masm, shared_function_info);
}

void ResetFeedbackVectorOsrUrgency(MacroAssembler* masm,
                                   Register feedback_vector, Register scratch) {
  __ movb(scratch,
          FieldOperand(feedback_vector, FeedbackVector::kOsrStateOffset));
  __ andb(scratch, Immediate(~FeedbackVector::OsrUrgencyBits::kMask));
  __ movb(FieldOperand(feedback_vector, FeedbackVector::kOsrStateOffset),
          scratch);
}

}  // namespace

// Generate code for entering a JS function with the interpreter.
// On entry to the function the receiver and arguments have been pushed on the
// stack left to right.
//
// The live registers are:
//   o rax: actual argument count
//   o rdi: the JS function object being called
//   o rdx: the incoming new target or generator object
//   o rsi: our context
//   o rbp: the caller's frame pointer
//   o rsp: stack pointer (pointing to return address)
//
// The function builds an interpreter frame. See InterpreterFrameConstants in
// frame-constants.h for its layout.
void Builtins::Generate_InterpreterEntryTrampoline(
    MacroAssembler* masm, InterpreterEntryTrampolineMode mode) {
  Register closure = rdi;

  // Get the bytecode array from the function object and load it into
  // kInterpreterBytecodeArrayRegister.
  const Register shared_function_info(r11);
  __ LoadTaggedField(
      shared_function_info,
      FieldOperand(closure, JSFunction::kSharedFunctionInfoOffset));
  ResetSharedFunctionInfoAge(masm, shared_function_info);

  // The bytecode array could have been flushed from the shared function info,
  // if so, call into CompileLazy.
  Label is_baseline, compile_lazy;
  GetSharedFunctionInfoBytecodeOrBaseline(
      masm, shared_function_info, kInterpreterBytecodeArrayRegister,
      kScratchRegister, &is_baseline, &compile_lazy);

#ifdef V8_ENABLE_LEAPTIERING
  // Validate the parameter count. This protects against an attacker swapping
  // the bytecode (or the dispatch handle) such that the parameter count of the
  // dispatch entry doesn't match the one of the BytecodeArray.
  // TODO(saelo): instead of this validation step, it would probably be nicer
  // if we could store the BytecodeArray directly in the dispatch entry and
  // load it from there. Then we can easily guarantee that the parameter count
  // of the entry matches the parameter count of the bytecode.
  Register dispatch_handle = kJavaScriptCallDispatchHandleRegister;
  __ LoadParameterCountFromJSDispatchTable(r8, dispatch_handle);
  __ cmpw(r8, FieldOperand(kInterpreterBytecodeArrayRegister,
                           BytecodeArray::kParameterSizeOffset));
  __ SbxCheck(equal, AbortReason::kJSSignatureMismatch);
#endif  // V8_ENABLE_LEAPTIERING

  Label push_stack_frame;
  Register feedback_vector = rbx;
  __ LoadFeedbackVector(feedback_vector, closure, &push_stack_frame,
                        Label::kNear);

#ifndef V8_JITLESS
#ifndef V8_ENABLE_LEAPTIERING
  // If feedback vector is valid, check for optimized code and update invocation
  // count.
  Label flags_need_processing;
  __ CheckFeedbackVectorFlagsAndJumpIfNeedsProcessing(
      feedback_vector, CodeKind::INTERPRETED_FUNCTION, &flags_need_processing);
#endif  // !V8_ENABLE_LEAPTIERING

  ResetFeedbackVectorOsrUrgency(masm, feedback_vector, kScratchRegister);

  // Increment invocation count for the function.
  __ incl(
      FieldOperand(feedback_vector, FeedbackVector::kInvocationCountOffset));

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
  __ pushq(rbp);  // Caller's frame pointer.
  __ movq(rbp, rsp);
  __ Push(kContextRegister);                 // Callee's context.
  __ Push(kJavaScriptCallTargetRegister);    // Callee's JS function.
  __ Push(kJavaScriptCallArgCountRegister);  // Actual argument count.

  // Load initial bytecode offset.
  __ Move(kInterpreterBytecodeOffsetRegister,
          BytecodeArray::kHeaderSize - kHeapObjectTag);

  // Push bytecode array and Smi tagged bytecode offset.
  __ Push(kInterpreterBytecodeArrayRegister);
  __ SmiTag(rcx, kInterpreterBytecodeOffsetRegister);
  __ Push(rcx);

  // Push feedback vector.
  __ Push(feedback_vector);

  // Allocate the local and temporary register file on the stack.
  Label stack_overflow;
  {
    // Load frame size from the BytecodeArray object.
    __ movl(rcx, FieldOperand(kInterpreterBytecodeArrayRegister,
                              BytecodeArray::kFrameSizeOffset));

    // Do a stack check to ensure we don't go over the limit.
    __ movq(rax, rsp);
    __ subq(rax, rcx);
    __ cmpq(rax, __ StackLimitAsOperand(StackLimitKind::kRealStackLimit));
    __ j(below, &stack_overflow);

    // If ok, push undefined as the initial value for all register file entries.
    Label loop_header;
    Label loop_check;
    __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
    __ jmp(&loop_check, Label::kNear);
    __ bind(&loop_header);
    // TODO(rmcilroy): Consider doing more than one push per loop iteration.
    __ Push(kInterpreterAccumulatorRegister);
    // Continue loop if not done.
    __ bind(&loop_check);
    __ subq(rcx, Immediate(kSystemPointerSize));
    __ j(greater_equal, &loop_header, Label::kNear);
  }

  // If the bytecode array has a valid incoming new target or generator object
  // register, initialize it with incoming value which was passed in rdx.
  Label no_incoming_new_target_or_generator_register;
  __ movsxlq(
      rcx,
      FieldOperand(kInterpreterBytecodeArrayRegister,
                   BytecodeArray::kIncomingNewTargetOrGeneratorRegisterOffset));
  __ testl(rcx, rcx);
  __ j(zero, &no_incoming_new_target_or_generator_register, Label::kNear);
  __ movq(Operand(rbp, rcx, times_system_pointer_size, 0), rdx);
  __ bind(&no_incoming_new_target_or_generator_register);

  // Perform interrupt stack check.
  // TODO(solanes): Merge with the real stack limit check above.
  Label stack_check_interrupt, after_stack_check_interrupt;
  __ cmpq(rsp, __ StackLimitAsOperand(StackLimitKind::kInterruptStackLimit));
  __ j(below, &stack_check_interrupt);
  __ bind(&after_stack_check_interrupt);

  // The accumulator is already loaded with undefined.

  // Load the dispatch table into a register and dispatch to the bytecode
  // handler at the current bytecode offset.
  Label do_dispatch;
  __ bind(&do_dispatch);
  __ Move(
      kInterpreterDispatchTableRegister,
      ExternalReference::interpreter_dispatch_table_address(masm->isolate()));
  __ movzxbq(kScratchRegister,
             Operand(kInterpreterBytecodeArrayRegister,
                     kInterpreterBytecodeOffsetRegister, times_1, 0));
  __ movq(kJavaScriptCallCodeStartRegister,
          Operand(kInterpreterDispatchTableRegister, kScratchRegister,
                  times_system_pointer_size, 0));

  // X64 has this location as the interpreter_entry_return_offset for CET
  // shadow stack rather than after `call`. InterpreterEnterBytecode will
  // jump to this location and call kJavaScriptCallCodeStartRegister, which
  // will form the valid shadow stack.
  __ RecordComment("--- InterpreterEntryPC point ---");
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
  __ call(kJavaScriptCallCodeStartRegister);

  // Any returns to the entry trampoline are either due to the return bytecode
  // or the interpreter tail calling a builtin and then a dispatch.

  // Get bytecode array and bytecode offset from the stack frame.
  __ movq(kInterpreterBytecodeArrayRegister,
          Operand(rbp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ SmiUntagUnsigned(
      kInterpreterBytecodeOffsetRegister,
      Operand(rbp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

  // Either return, or advance to the next bytecode and dispatch.
  Label do_return;
  __ movzxbq(rbx, Operand(kInterpreterBytecodeArrayRegister,
                          kInterpreterBytecodeOffsetRegister, times_1, 0));
  AdvanceBytecodeOffsetOrReturn(masm, kInterpreterBytecodeArrayRegister,
                                kInterpreterBytecodeOffsetRegister, rbx, rcx,
                                r8, &do_return);
  __ jmp(&do_dispatch);

  __ bind(&do_return);
  // The return value is in rax.
  LeaveInterpreterFrame(masm, rbx, rcx);
  __ ret(0);

  __ bind(&stack_check_interrupt);
  // Modify the bytecode offset in the stack to be kFunctionEntryBytecodeOffset
  // for the call to the StackGuard.
  __ Move(Operand(rbp, InterpreterFrameConstants::kBytecodeOffsetFromFp),
          Smi::FromInt(BytecodeArray::kHeaderSize - kHeapObjectTag +
                       kFunctionEntryBytecodeOffset));
  __ CallRuntime(Runtime::kStackGuard);

  // After the call, restore the bytecode array, bytecode offset and accumulator
  // registers again. Also, restore the bytecode offset in the stack to its
  // previous value.
  __ movq(kInterpreterBytecodeArrayRegister,
          Operand(rbp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ Move(kInterpreterBytecodeOffsetRegister,
          BytecodeArray::kHeaderSize - kHeapObjectTag);
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);

  __ SmiTag(rcx, kInterpreterBytecodeArrayRegister);
  __ movq(Operand(rbp, InterpreterFrameConstants::kBytecodeOffsetFromFp), rcx);

  __ jmp(&after_stack_check_interrupt);

  __ bind(&compile_lazy);
  __ GenerateTailCallToReturnedCode(Runtime::kCompileLazy);
  __ int3();  // Should not return.

#ifndef V8_JITLESS
#ifndef V8_ENABLE_LEAPTIERING
  __ bind(&flags_need_processing);
  __ OptimizeCodeOrTailCallOptimizedCodeSlot(feedback_vector, closure,
                                             JumpMode::kJump);
#endif  // !V8_ENABLE_LEAPTIERING

  __ bind(&is_baseline);
  {
#ifndef V8_ENABLE_LEAPTIERING
    // Load the feedback vector from the closure.
    TaggedRegister feedback_cell(feedback_vector);
    __ LoadTaggedField(feedback_cell,
                       FieldOperand(closure, JSFunction::kFeedbackCellOffset));
    __ LoadTaggedField(feedback_vector,
                       FieldOperand(feedback_cell, FeedbackCell::kValueOffset));

    Label install_baseline_code;
    // Check if feedback vector is valid. If not, call prepare for baseline to
    // allocate it.
    __ IsObjectType(feedback_vector, FEEDBACK_VECTOR_TYPE, rcx);
    __ j(not_equal, &install_baseline_code);

    // Check the tiering state.
    __ CheckFeedbackVectorFlagsAndJumpIfNeedsProcessing(
        feedback_vector, CodeKind::BASELINE, &flags_need_processing);

    // TODO(olivf, 42204201): This fastcase is difficult to support with the
    // sandbox as it requires getting write access to the dispatch table. See
    // `JSFunction::UpdateCode`. We might want to remove it for all
    // configurations as it does not seem to be performance sensitive.

    // Load the baseline code into the closure.
    __ Move(rcx, kInterpreterBytecodeArrayRegister);
    static_assert(kJavaScriptCallCodeStartRegister == rcx, "ABI mismatch");
    __ ReplaceClosureCodeWithOptimizedCode(
        rcx, closure, kInterpreterBytecodeArrayRegister,
        WriteBarrierDescriptor::SlotAddressRegister());
    __ JumpCodeObject(rcx, kJSEntrypointTag);

    __ bind(&install_baseline_code);
#endif  // !V8_ENABLE_LEAPTIERING

    __ GenerateTailCallToReturnedCode(Runtime::kInstallBaselineCode);
  }
#endif  // !V8_JITLESS

  __ bind(&stack_overflow);
  __ CallRuntime(Runtime::kThrowStackOverflow);
  __ int3();  // Should not return.
}

static void GenerateInterpreterPushArgs(MacroAssembler* masm, Register num_args,
                                        Register start_address,
                                        Register scratch) {
  ASM_CODE_COMMENT(masm);
  // Find the argument with lowest address.
  __ movq(scratch, num_args);
  __ negq(scratch);
  __ leaq(start_address,
          Operand(start_address, scratch, times_system_pointer_size,
                  kSystemPointerSize));
  // Push the arguments.
  __ PushArray(start_address, num_args, scratch,
               MacroAssembler::PushArrayOrder::kReverse);
}

// static
void Builtins::Generate_InterpreterPushArgsThenCallImpl(
    MacroAssembler* masm, ConvertReceiverMode receiver_mode,
    InterpreterPushArgsMode mode) {
  DCHECK(mode != InterpreterPushArgsMode::kArrayFunction);
  // ----------- S t a t e -------------
  //  -- rax : the number of arguments
  //  -- rbx : the address of the first argument to be pushed. Subsequent
  //           arguments should be consecutive above this, in the same order as
  //           they are to be pushed onto the stack.
  //  -- rdi : the target to call (can be any Object).
  // -----------------------------------
  Label stack_overflow;

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // The spread argument should not be pushed.
    __ decl(rax);
  }

  __ movl(rcx, rax);
  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    __ decl(rcx);  // Exclude receiver.
  }

  // Add a stack check before pushing arguments.
  __ StackOverflowCheck(rcx, &stack_overflow);

  // Pop return address to allow tail-call after pushing arguments.
  __ PopReturnAddressTo(kScratchRegister);

  // rbx and rdx will be modified.
  GenerateInterpreterPushArgs(masm, rcx, rbx, rdx);

  // Push "undefined" as the receiver arg if we need to.
  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    __ PushRoot(RootIndex::kUndefinedValue);
  }

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Pass the spread in the register rbx.
    // rbx already points to the penultime argument, the spread
    // is below that.
    __ movq(rbx, Operand(rbx, -kSystemPointerSize));
  }

  // Call the target.
  __ PushReturnAddressFrom(kScratchRegister);  // Re-push return address.

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    __ TailCallBuiltin(Builtin::kCallWithSpread);
  } else {
    __ TailCallBuiltin(Builtins::Call(receiver_mode));
  }

  // Throw stack overflow exception.
  __ bind(&stack_overflow);
  {
    __ TailCallRuntime(Runtime::kThrowStackOverflow);
    // This should be unreachable.
    __ int3();
  }
}

// static
void Builtins::Generate_InterpreterPushArgsThenConstructImpl(
    MacroAssembler* masm, InterpreterPushArgsMode mode) {
  // ----------- S t a t e -------------
  //  -- rax : the number of arguments
  //  -- rdx : the new target (either the same as the constructor or
  //           the JSFunction on which new was invoked initially)
  //  -- rdi : the constructor to call (can be any Object)
  //  -- rbx : the allocation site feedback if available, undefined otherwise
  //  -- rcx : the address of the first argument to be pushed. Subsequent
  //           arguments should be consecutive above this, in the same order as
  //           they are to be pushed onto the stack.
  // -----------------------------------
  Label stack_overflow;

  // Add a stack check before pushing arguments.
  __ StackOverflowCheck(rax, &stack_overflow);

  // Pop return address to allow tail-call after pushing arguments.
  __ PopReturnAddressTo(kScratchRegister);

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // The spread argument should not be pushed.
    __ decl(rax);
  }

  // rcx and r8 will be modified.
  Register argc_without_receiver = r11;
  __ leaq(argc_without_receiver, Operand(rax, -kJSArgcReceiverSlots));
  GenerateInterpreterPushArgs(masm, argc_without_receiver, rcx, r8);

  // Push slot for the receiver to be constructed.
  __ Push(Immediate(0));

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Pass the spread in the register rbx.
    __ movq(rbx, Operand(rcx, -kSystemPointerSize));
    // Push return address in preparation for the tail-call.
    __ PushReturnAddressFrom(kScratchRegister);
  } else {
    __ PushReturnAddressFrom(kScratchRegister);
    __ AssertUndefinedOrAllocationSite(rbx);
  }

  if (mode == InterpreterPushArgsMode::kArrayFunction) {
    // Tail call to the array construct stub (still in the caller
    // context at this point).
    __ AssertFunction(rdi);
    // Jump to the constructor function (rax, rbx, rdx passed on).
    __ TailCallBuiltin(Builtin::kArrayConstructorImpl);
  } else if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Call the constructor (rax, rdx, rdi passed on).
    __ TailCallBuiltin(Builtin::kConstructWithSpread);
  } else {
    DCHECK_EQ(InterpreterPushArgsMode::kOther, mode);
    // Call the constructor (rax, rdx, rdi passed on).
    __ TailCallBuiltin(Builtin::kConstruct);
  }

  // Throw stack overflow exception.
  __ bind(&stack_overflow);
  {
    __ TailCallRuntime(Runtime::kThrowStackOverflow);
    // This should be unreachable.
    __ int3();
  }
}

// static
void Builtins::Generate_ConstructForwardAllArgsImpl(
    MacroAssembler* masm, ForwardWhichFrame which_frame) {
  // ----------- S t a t e -------------
  //  -- rdx : the new target (either the same as the constructor or
  //           the JSFunction on which new was invoked initially)
  //  -- rdi : the constructor to call (can be any Object)
  // -----------------------------------
  Label stack_overflow;

  // Load the frame pointer into rcx.
  switch (which_frame) {
    case ForwardWhichFrame::kCurrentFrame:
      __ movq(rcx, rbp);
      break;
    case ForwardWhichFrame::kParentFrame:
      __ movq(rcx, Operand(rbp, StandardFrameConstants::kCallerFPOffset));
      break;
  }

  // Load the argument count into rax.
  __ movq(rax, Operand(rcx, StandardFrameConstants::kArgCOffset));

  // Add a stack check before copying arguments.
  __ StackOverflowCheck(rax, &stack_overflow);

  // Pop return address to allow tail-call after forwarding arguments.
  __ PopReturnAddressTo(kScratchRegister);

  // Point rcx to the base of the argument list to forward, excluding the
  // receiver.
  __ addq(rcx, Immediate((StandardFrameConstants::kFixedSlotCountAboveFp + 1) *
                         kSystemPointerSize));

  // Copy the arguments on the stack. r8 is a scratch register.
  Register argc_without_receiver = r11;
  __ leaq(argc_without_receiver, Operand(rax, -kJSArgcReceiverSlots));
  __ PushArray(rcx, argc_without_receiver, r8);

  // Push slot for the receiver to be constructed.
  __ Push(Immediate(0));

  __ PushReturnAddressFrom(kScratchRegister);

  // Call the constructor (rax, rdx, rdi passed on).
  __ TailCallBuiltin(Builtin::kConstruct);

  // Throw stack overflow exception.
  __ bind(&stack_overflow);
  {
    __ TailCallRuntime(Runtime::kThrowStackOverflow);
    // This should be unreachable.
    __ int3();
  }
}

namespace {

void NewImplicitReceiver(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- rax : the number of arguments
  //  -- rdx : the new target
  //  -- rdi : the constructor to call (checked to be a JSFunction)
  //
  //  Stack:
  //  -- Implicit Receiver
  //  -- [arguments without receiver]
  //  -- Implicit Receiver
  //  -- Context
  //  -- FastConstructMarker
  //  -- FramePointer
  // -----------------------------------
  Register implicit_receiver = rcx;

  // Save live registers.
  __ SmiTag(rax);
  __ Push(rax);  // Number of arguments
  __ Push(rdx);  // NewTarget
  __ Push(rdi);  // Target
  __ CallBuiltin(Builtin::kFastNewObject);
  // Save result.
  __ movq(implicit_receiver, rax);
  // Restore live registers.
  __ Pop(rdi);
  __ Pop(rdx);
  __ Pop(rax);
  __ SmiUntagUnsigned(rax);

  // Patch implicit receiver (in arguments)
  __ movq(Operand(rsp, 0 /* first argument */), implicit_receiver);
  // Patch second implicit (in construct frame)
  __ movq(Operand(rbp, FastConstructFrameConstants::kImplicitReceiverOffset),
          implicit_receiver);

  // Restore context.
  __ movq(rsi, Operand(rbp, FastConstructFrameConstants::kContextOffset));
}

}  // namespace

// static
void Builtins::Generate_InterpreterPushArgsThenFastConstructFunction(
    MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- rax : the number of arguments
  //  -- rdx : the new target
  //  -- rdi : the constructor to call (checked to be a JSFunction)
  //  -- rcx : the address of the first argument to be pushed. Subsequent
  //           arguments should be consecutive above this, in the same order as
  //           they are to be pushed onto the stack.
  // -----------------------------------
  __ AssertFunction(rdi);

  // Check if target has a [[Construct]] internal method.
  Label non_constructor;
  __ LoadMap(kScratchRegister, rdi);
  __ testb(FieldOperand(kScratchRegister, Map::kBitFieldOffset),
           Immediate(Map::Bits1::IsConstructorBit::kMask));
  __ j(zero, &non_constructor);

  // Add a stack check before pushing arguments.
  Label stack_overflow;
  __ StackOverflowCheck(rax, &stack_overflow);

  // Enter a construct frame.
  FrameScope scope(masm, StackFrame::MANUAL);
  __ EnterFrame(StackFrame::FAST_CONSTRUCT);
  __ Push(rsi);
  // Implicit receiver stored in the construct frame.
  __ PushRoot(RootIndex::kTheHoleValue);

  // Push arguments + implicit receiver.
  Register argc_without_receiver = r11;
  __ leaq(argc_without_receiver, Operand(rax, -kJSArgcReceiverSlots));
  GenerateInterpreterPushArgs(masm, argc_without_receiver, rcx, r12);
  // Implicit receiver as part of the arguments (patched later if needed).
  __ PushRoot(RootIndex::kTheHoleValue);

  // Check if it is a builtin call.
  Label builtin_call;
  const TaggedRegister shared_function_info(kScratchRegister);
  __ LoadTaggedField(shared_function_info,
                     FieldOperand(rdi, JSFunction::kSharedFunctionInfoOffset));
  __ testl(FieldOperand(shared_function_info, SharedFunctionInfo::kFlagsOffset),
           Immediate(SharedFunctionInfo::ConstructAsBuiltinBit::kMask));
  __ j(not_zero, &builtin_call);

  // Check if we need to create an implicit receiver.
  Label not_create_implicit_receiver;
  __ movl(kScratchRegister,
          FieldOperand(shared_function_info, SharedFunctionInfo::kFlagsOffset));
  __ DecodeField<SharedFunctionInfo::FunctionKindBits>(kScratchRegister);
  __ JumpIfIsInRange(
      kScratchRegister,
      static_cast<uint32_t>(FunctionKind::kDefaultDerivedConstructor),
      static_cast<uint32_t>(FunctionKind::kDerivedConstructor),
      &not_create_implicit_receiver, Label::kNear);
  NewImplicitReceiver(masm);
  __ bind(&not_create_implicit_receiver);

  // Call the function.
  __ InvokeFunction(rdi, rdx, rax, InvokeType::kCall);

  // ----------- S t a t e -------------
  //  -- rax     constructor result
  //
  //  Stack:
  //  -- Implicit Receiver
  //  -- Context
  //  -- FastConstructMarker
  //  -- FramePointer
  // -----------------------------------

  Label deopt_entry;
  __ bind(&deopt_entry);

  // If the result is an object (in the ECMA sense), we should get rid
  // of the receiver and use the result; see ECMA-262 section 13.2.2-7
  // on page 74.
  Label use_receiver, do_throw, leave_and_return, check_result;

  // If the result is undefined, we'll use the implicit receiver. Otherwise we
  // do a smi check and fall through to check if the return value is a valid
  // receiver.
  __ JumpIfNotRo
"""


```