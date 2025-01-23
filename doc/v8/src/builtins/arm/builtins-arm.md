Response: The user wants a summary of the C++ source code file `v8/src/builtins/arm/builtins-arm.cc`.
The file seems to contain architecture-specific implementations of built-in functions for the ARM architecture in the V8 JavaScript engine.

Here's a breakdown of the file's structure and functionalities:

1. **Includes**: The file includes various V8 headers related to API interaction, built-ins, code generation, debugging, deoptimization, execution frames, heap management, logging, and objects. The presence of `#if V8_ENABLE_WEBASSEMBLY` indicates support for WebAssembly as well.
2. **Namespace**: The code resides within the `v8::internal` namespace.
3. **Macros**: A macro `__` is defined for accessing the `MacroAssembler`.
4. **`Generate_Adaptor`**:  Generates code for an adaptor function, likely used to bridge between JavaScript and C++ code.
5. **Helper Functions**:  Several helper functions like `Generate_PushArguments` are defined to perform common assembly tasks, like pushing arguments onto the stack.
6. **Construct Stubs**: Functions like `Generate_JSBuiltinsConstructStubHelper`, `Generate_JSConstructStubGeneric`, and `Generate_JSBuiltinsConstructStub` handle the construction of JavaScript objects. These involve creating a new object, calling the constructor function, and handling the return value.
7. **Generator Trampoline**:  `Generate_ResumeGeneratorTrampoline` deals with resuming paused JavaScript generator functions.
8. **Non-Constructable Check**: `Generate_ConstructedNonConstructable` throws an error when a non-constructor is called with `new`.
9. **Entry Variants**: `Generate_JSEntryVariant` creates different entry points for calling JavaScript functions from C++, handling stack frame setup, exception handling, and calling the actual trampoline.
10. **Entry Trampolines**: `Generate_JSEntryTrampoline`, `Generate_JSConstructEntryTrampoline`, and `Generate_RunMicrotasksTrampoline` are the actual entry points called from C++, responsible for setting up the JavaScript execution environment.
11. **Interpreter Support**: Functions like `LeaveInterpreterFrame`, `AdvanceBytecodeOffsetOrReturn`, `Generate_InterpreterEntryTrampoline`, `Generate_InterpreterPushArgsThenCallImpl`, `Generate_InterpreterPushArgsThenConstructImpl`, `Generate_ConstructForwardAllArgsImpl`, `Generate_InterpreterPushArgsThenFastConstructFunction`, and `Generate_InterpreterEnterBytecode` are crucial for the V8 interpreter. They handle frame setup, bytecode dispatch, argument pushing, and calling functions within the interpreter.
12. **Baseline Compilation**: `Generate_BaselineOutOfLinePrologue` and `Generate_BaselineOutOfLinePrologueDeopt` are related to the baseline compiler, a lightweight optimizing compiler in V8. They handle function prologue and deoptimization scenarios.

In summary, this file provides low-level, architecture-specific implementations for various core functionalities of the V8 JavaScript engine on ARM, including function calls, object construction, generator execution, and interpreter support.

Regarding the relationship with JavaScript, the code in this file *implements* the behavior of JavaScript features. For example, the constructor stubs are invoked when you use the `new` keyword in JavaScript. The generator trampoline is involved when you use `function*` to define a generator. The interpreter-related code executes the bytecode generated from your JavaScript code.
这个C++源代码文件 `builtins-arm.cc` 是 V8 JavaScript 引擎中 **ARM 架构** 特有的内置函数 (builtins) 的实现。它的主要功能是：

**为 ARM 架构下的 V8 引擎提供高效的、底层的实现代码，来支持 JavaScript 的各种核心功能。**

具体来说，这个文件的代码负责处理以下几个关键方面：

1. **函数调用 (Function Calls):**
   - **`Generate_Adaptor`**:  创建适配器函数，用于在 C++ 和 JavaScript 之间传递控制和参数。
   - **`Generate_JSEntryVariant` 和相关的 `Generate_JSEntryTrampoline` 等**:  定义了从 C++ 代码进入 JavaScript 执行环境的入口点，负责设置栈帧、保存寄存器、处理异常等。
   - **`Generate_ResumeGeneratorTrampoline`**: 处理 JavaScript 生成器函数的恢复执行。
   - **`Builtins::Generate_Call` (通过 `Generate_InterpreterPushArgsThenCallImpl`)**:  实现了 JavaScript 函数的调用机制。

2. **对象构造 (Object Construction):**
   - **`Generate_JSBuiltinsConstructStubHelper` 和 `Generate_JSConstructStubGeneric`**:  实现了 JavaScript 构造函数的调用流程，包括创建新对象、调用构造函数、处理返回值等。
   - **`Generate_InterpreterPushArgsThenConstructImpl` 和 `Generate_InterpreterPushArgsThenFastConstructFunction`**:  在解释器环境下处理构造函数的调用。

3. **解释器支持 (Interpreter Support):**
   - **`Generate_InterpreterEntryTrampoline`**:  定义了解释器入口点，负责设置解释器栈帧、加载字节码、分发执行等。
   - **`LeaveInterpreterFrame` 和 `AdvanceBytecodeOffsetOrReturn`**:  辅助解释器执行，负责离开解释器栈帧和更新字节码偏移量。
   - **`Generate_InterpreterPushArgsThenCallImpl` 和 `Generate_InterpreterPushArgsThenConstructImpl`**:  在解释器环境下处理函数和构造函数的参数传递和调用。
   - **`Generate_InterpreterEnterBytecode`**:  负责进入解释器执行字节码。

4. **优化编译支持 (Optimized Compilation Support):**
   - **`Generate_BaselineOutOfLinePrologue` 和 `Generate_BaselineOutOfLinePrologueDeopt`**:  与基线编译器 (Baseline Compiler) 相关，处理函数序言和去优化的情况。

**与 JavaScript 功能的关系以及 JavaScript 示例：**

这个文件中的代码是支撑 JavaScript 功能的基础。当你在 JavaScript 中执行某些操作时，V8 引擎会在底层调用这些内置函数。

**示例 1: 函数调用**

```javascript
function greet(name) {
  console.log("Hello, " + name + "!");
}

greet("World");
```

当 JavaScript 引擎执行 `greet("World")` 时，V8 会调用类似于 `Builtins::Generate_Call` (在 ARM 架构下通过 `Generate_InterpreterPushArgsThenCallImpl` 实现) 的内置函数。这个内置函数会负责设置调用栈，传递参数，并将控制权转移到 `greet` 函数的代码。

**示例 2: 对象构造**

```javascript
class Person {
  constructor(name) {
    this.name = name;
  }
}

const person = new Person("Alice");
```

当执行 `new Person("Alice")` 时，V8 会调用 `Builtins::Generate_JSConstructStubGeneric` 或其相关的函数。这个内置函数会：
- 分配一个新的 `Person` 对象。
- 调用 `Person` 类的 `constructor` 方法。
- 将新创建的对象返回。

**示例 3: 生成器函数**

```javascript
function* numberGenerator() {
  yield 1;
  yield 2;
  yield 3;
}

const generator = numberGenerator();
console.log(generator.next()); // { value: 1, done: false }
console.log(generator.next()); // { value: 2, done: false }
```

当生成器函数 `numberGenerator` 被调用时，V8 会创建生成器对象。每次调用 `generator.next()` 时，`Builtins::Generate_ResumeGeneratorTrampoline` 会被调用，它负责恢复生成器的执行状态，直到遇到下一个 `yield` 语句。

**总结**

`builtins-arm.cc` 文件是 V8 引擎在 ARM 架构下的 "发动机" 的一部分。它包含了实现 JavaScript 核心功能的低级代码，这些代码在 JavaScript 代码执行的幕后默默工作，保证了 JavaScript 代码能够被正确高效地执行。

### 提示词
```
这是目录为v8/src/builtins/arm/builtins-arm.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if V8_TARGET_ARCH_ARM

#include "src/api/api-arguments.h"
#include "src/builtins/builtins-descriptors.h"
#include "src/builtins/builtins-inl.h"
#include "src/codegen/code-factory.h"
#include "src/codegen/interface-descriptors-inl.h"
// For interpreter_entry_return_pc_offset. TODO(jkummerow): Drop.
#include "src/codegen/macro-assembler-inl.h"
#include "src/codegen/register-configuration.h"
#include "src/debug/debug.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/frame-constants.h"
#include "src/execution/frames.h"
#include "src/heap/heap-inl.h"
#include "src/logging/counters.h"
#include "src/objects/cell.h"
#include "src/objects/foreign.h"
#include "src/objects/heap-number.h"
#include "src/objects/js-generator.h"
#include "src/objects/objects-inl.h"
#include "src/objects/smi.h"
#include "src/runtime/runtime.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/baseline/liftoff-assembler-defs.h"
#include "src/wasm/object-access.h"
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-objects.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

#define __ ACCESS_MASM(masm)

void Builtins::Generate_Adaptor(MacroAssembler* masm,
                                int formal_parameter_count, Address address) {
#if defined(__thumb__)
  // Thumb mode builtin.
  DCHECK_EQ(1, reinterpret_cast<uintptr_t>(
                   ExternalReference::Create(address).address()) &
                   1);
#endif
  __ Move(kJavaScriptCallExtraArg1Register, ExternalReference::Create(address));
  __ TailCallBuiltin(
      Builtins::AdaptorWithBuiltinExitFrame(formal_parameter_count));
}

namespace {

enum class ArgumentsElementType {
  kRaw,    // Push arguments as they are.
  kHandle  // Dereference arguments before pushing.
};

void Generate_PushArguments(MacroAssembler* masm, Register array, Register argc,
                            Register scratch,
                            ArgumentsElementType element_type) {
  DCHECK(!AreAliased(array, argc, scratch));
  UseScratchRegisterScope temps(masm);
  Register counter = scratch;
  Register value = temps.Acquire();
  Label loop, entry;
  __ sub(counter, argc, Operand(kJSArgcReceiverSlots));
  __ b(&entry);
  __ bind(&loop);
  __ ldr(value, MemOperand(array, counter, LSL, kSystemPointerSizeLog2));
  if (element_type == ArgumentsElementType::kHandle) {
    __ ldr(value, MemOperand(value));
  }
  __ push(value);
  __ bind(&entry);
  __ sub(counter, counter, Operand(1), SetCC);
  __ b(ge, &loop);
}

void Generate_JSBuiltinsConstructStubHelper(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r0     : number of arguments
  //  -- r1     : constructor function
  //  -- r3     : new target
  //  -- cp     : context
  //  -- lr     : return address
  //  -- sp[...]: constructor arguments
  // -----------------------------------

  Register scratch = r2;

  Label stack_overflow;

  __ StackOverflowCheck(r0, scratch, &stack_overflow);

  // Enter a construct frame.
  {
    FrameAndConstantPoolScope scope(masm, StackFrame::CONSTRUCT);

    // Preserve the incoming parameters on the stack.
    __ Push(cp, r0);

    // TODO(victorgomes): When the arguments adaptor is completely removed, we
    // should get the formal parameter count and copy the arguments in its
    // correct position (including any undefined), instead of delaying this to
    // InvokeFunction.

    // Set up pointer to first argument (skip receiver).
    __ add(
        r4, fp,
        Operand(StandardFrameConstants::kCallerSPOffset + kSystemPointerSize));
    // Copy arguments and receiver to the expression stack.
    // r4: Pointer to start of arguments.
    // r0: Number of arguments.
    Generate_PushArguments(masm, r4, r0, r5, ArgumentsElementType::kRaw);
    // The receiver for the builtin/api call.
    __ PushRoot(RootIndex::kTheHoleValue);

    // Call the function.
    // r0: number of arguments (untagged)
    // r1: constructor function
    // r3: new target
    __ InvokeFunctionWithNewTarget(r1, r3, r0, InvokeType::kCall);

    // Restore context from the frame.
    __ ldr(cp, MemOperand(fp, ConstructFrameConstants::kContextOffset));
    // Restore arguments count from the frame.
    __ ldr(scratch, MemOperand(fp, ConstructFrameConstants::kLengthOffset));
    // Leave construct frame.
  }

  // Remove caller arguments from the stack and return.
  __ DropArguments(scratch);
  __ Jump(lr);

  __ bind(&stack_overflow);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kThrowStackOverflow);
    __ bkpt(0);  // Unreachable code.
  }
}

}  // namespace

// The construct stub for ES5 constructor functions and ES6 class constructors.
void Builtins::Generate_JSConstructStubGeneric(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  --      r0: number of arguments (untagged)
  //  --      r1: constructor function
  //  --      r3: new target
  //  --      cp: context
  //  --      lr: return address
  //  -- sp[...]: constructor arguments
  // -----------------------------------

  FrameScope scope(masm, StackFrame::MANUAL);
  // Enter a construct frame.
  Label post_instantiation_deopt_entry, not_create_implicit_receiver;
  __ EnterFrame(StackFrame::CONSTRUCT);

  // Preserve the incoming parameters on the stack.
  __ LoadRoot(r4, RootIndex::kTheHoleValue);
  __ Push(cp, r0, r1, r4, r3);

  // ----------- S t a t e -------------
  //  --        sp[0*kPointerSize]: new target
  //  --        sp[1*kPointerSize]: padding
  //  -- r1 and sp[2*kPointerSize]: constructor function
  //  --        sp[3*kPointerSize]: number of arguments
  //  --        sp[4*kPointerSize]: context
  // -----------------------------------

  __ ldr(r4, FieldMemOperand(r1, JSFunction::kSharedFunctionInfoOffset));
  __ ldr(r4, FieldMemOperand(r4, SharedFunctionInfo::kFlagsOffset));
  __ DecodeField<SharedFunctionInfo::FunctionKindBits>(r4);
  __ JumpIfIsInRange(
      r4, r4, static_cast<uint32_t>(FunctionKind::kDefaultDerivedConstructor),
      static_cast<uint32_t>(FunctionKind::kDerivedConstructor),
      &not_create_implicit_receiver);

  // If not derived class constructor: Allocate the new receiver object.
  __ CallBuiltin(Builtin::kFastNewObject);
  __ b(&post_instantiation_deopt_entry);

  // Else: use TheHoleValue as receiver for constructor call
  __ bind(&not_create_implicit_receiver);
  __ LoadRoot(r0, RootIndex::kTheHoleValue);

  // ----------- S t a t e -------------
  //  --                          r0: receiver
  //  -- Slot 3 / sp[0*kPointerSize]: new target
  //  -- Slot 2 / sp[1*kPointerSize]: constructor function
  //  -- Slot 1 / sp[2*kPointerSize]: number of arguments
  //  -- Slot 0 / sp[3*kPointerSize]: context
  // -----------------------------------
  // Deoptimizer enters here.
  masm->isolate()->heap()->SetConstructStubCreateDeoptPCOffset(
      masm->pc_offset());
  __ bind(&post_instantiation_deopt_entry);

  // Restore new target.
  __ Pop(r3);

  // Push the allocated receiver to the stack.
  __ Push(r0);
  // We need two copies because we may have to return the original one
  // and the calling conventions dictate that the called function pops the
  // receiver. The second copy is pushed after the arguments, we saved in r6
  // since r0 needs to store the number of arguments before
  // InvokingFunction.
  __ mov(r6, r0);

  // Set up pointer to first argument (skip receiver).
  __ add(r4, fp,
         Operand(StandardFrameConstants::kCallerSPOffset + kSystemPointerSize));

  // Restore constructor function and argument count.
  __ ldr(r1, MemOperand(fp, ConstructFrameConstants::kConstructorOffset));
  __ ldr(r0, MemOperand(fp, ConstructFrameConstants::kLengthOffset));

  Label stack_overflow;
  __ StackOverflowCheck(r0, r5, &stack_overflow);

  // TODO(victorgomes): When the arguments adaptor is completely removed, we
  // should get the formal parameter count and copy the arguments in its
  // correct position (including any undefined), instead of delaying this to
  // InvokeFunction.

  // Copy arguments to the expression stack.
  // r4: Pointer to start of argument.
  // r0: Number of arguments.
  Generate_PushArguments(masm, r4, r0, r5, ArgumentsElementType::kRaw);

  // Push implicit receiver.
  __ Push(r6);

  // Call the function.
  __ InvokeFunctionWithNewTarget(r1, r3, r0, InvokeType::kCall);

  // If the result is an object (in the ECMA sense), we should get rid
  // of the receiver and use the result; see ECMA-262 section 13.2.2-7
  // on page 74.
  Label use_receiver, do_throw, leave_and_return, check_receiver;

  // If the result is undefined, we jump out to using the implicit receiver.
  __ JumpIfNotRoot(r0, RootIndex::kUndefinedValue, &check_receiver);

  // Otherwise we do a smi check and fall through to check if the return value
  // is a valid receiver.

  // Throw away the result of the constructor invocation and use the
  // on-stack receiver as the result.
  __ bind(&use_receiver);
  __ ldr(r0, MemOperand(sp, 0 * kPointerSize));
  __ JumpIfRoot(r0, RootIndex::kTheHoleValue, &do_throw);

  __ bind(&leave_and_return);
  // Restore arguments count from the frame.
  __ ldr(r1, MemOperand(fp, ConstructFrameConstants::kLengthOffset));
  // Leave construct frame.
  __ LeaveFrame(StackFrame::CONSTRUCT);

  // Remove caller arguments from the stack and return.
  __ DropArguments(r1);
  __ Jump(lr);

  __ bind(&check_receiver);
  // If the result is a smi, it is *not* an object in the ECMA sense.
  __ JumpIfSmi(r0, &use_receiver);

  // If the type of the result (stored in its map) is less than
  // FIRST_JS_RECEIVER_TYPE, it is not an object in the ECMA sense.
  static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
  __ CompareObjectType(r0, r4, r5, FIRST_JS_RECEIVER_TYPE);
  __ b(ge, &leave_and_return);
  __ b(&use_receiver);

  __ bind(&do_throw);
  // Restore the context from the frame.
  __ ldr(cp, MemOperand(fp, ConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowConstructorReturnedNonObject);
  __ bkpt(0);

  __ bind(&stack_overflow);
  // Restore the context from the frame.
  __ ldr(cp, MemOperand(fp, ConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowStackOverflow);
  // Unreachable code.
  __ bkpt(0);
}

void Builtins::Generate_JSBuiltinsConstructStub(MacroAssembler* masm) {
  Generate_JSBuiltinsConstructStubHelper(masm);
}

static void AssertCodeIsBaseline(MacroAssembler* masm, Register code,
                                 Register scratch) {
  DCHECK(!AreAliased(code, scratch));
  // Verify that the code kind is baseline code via the CodeKind.
  __ ldr(scratch, FieldMemOperand(code, Code::kFlagsOffset));
  __ DecodeField<Code::KindField>(scratch);
  __ cmp(scratch, Operand(static_cast<int>(CodeKind::BASELINE)));
  __ Assert(eq, AbortReason::kExpectedBaselineData);
}

static void GetSharedFunctionInfoBytecodeOrBaseline(
    MacroAssembler* masm, Register sfi, Register bytecode, Register scratch1,
    Label* is_baseline, Label* is_unavailable) {
  ASM_CODE_COMMENT(masm);
  Label done;

  Register data = bytecode;
  __ ldr(data,
         FieldMemOperand(sfi, SharedFunctionInfo::kTrustedFunctionDataOffset));

  __ LoadMap(scratch1, data);
  __ ldrh(scratch1, FieldMemOperand(scratch1, Map::kInstanceTypeOffset));

#ifndef V8_JITLESS
  __ cmp(scratch1, Operand(CODE_TYPE));
  if (v8_flags.debug_code) {
    Label not_baseline;
    __ b(ne, &not_baseline);
    AssertCodeIsBaseline(masm, data, scratch1);
    __ b(eq, is_baseline);
    __ bind(&not_baseline);
  } else {
    __ b(eq, is_baseline);
  }
#endif  // !V8_JITLESS

  __ cmp(scratch1, Operand(BYTECODE_ARRAY_TYPE));
  __ b(eq, &done);

  __ cmp(scratch1, Operand(INTERPRETER_DATA_TYPE));
  __ b(ne, is_unavailable);
  __ ldr(data, FieldMemOperand(data, InterpreterData::kBytecodeArrayOffset));

  __ bind(&done);
}

// static
void Builtins::Generate_ResumeGeneratorTrampoline(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r0 : the value to pass to the generator
  //  -- r1 : the JSGeneratorObject to resume
  //  -- lr : return address
  // -----------------------------------
  // Store input value into generator object.
  __ str(r0, FieldMemOperand(r1, JSGeneratorObject::kInputOrDebugPosOffset));
  __ RecordWriteField(r1, JSGeneratorObject::kInputOrDebugPosOffset, r0,
                      kLRHasNotBeenSaved, SaveFPRegsMode::kIgnore);
  // Check that r1 is still valid, RecordWrite might have clobbered it.
  __ AssertGeneratorObject(r1);

  // Load suspended function and context.
  __ ldr(r4, FieldMemOperand(r1, JSGeneratorObject::kFunctionOffset));
  __ ldr(cp, FieldMemOperand(r4, JSFunction::kContextOffset));

  Label prepare_step_in_if_stepping, prepare_step_in_suspended_generator;
  Label stepping_prepared;
  Register scratch = r5;

  // Flood function if we are stepping.
  ExternalReference debug_hook =
      ExternalReference::debug_hook_on_function_call_address(masm->isolate());
  __ Move(scratch, debug_hook);
  __ ldrsb(scratch, MemOperand(scratch));
  __ cmp(scratch, Operand(0));
  __ b(ne, &prepare_step_in_if_stepping);

  // Flood function if we need to continue stepping in the suspended
  // generator.
  ExternalReference debug_suspended_generator =
      ExternalReference::debug_suspended_generator_address(masm->isolate());
  __ Move(scratch, debug_suspended_generator);
  __ ldr(scratch, MemOperand(scratch));
  __ cmp(scratch, Operand(r1));
  __ b(eq, &prepare_step_in_suspended_generator);
  __ bind(&stepping_prepared);

  // Check the stack for overflow. We are not trying to catch interruptions
  // (i.e. debug break and preemption) here, so check the "real stack limit".
  Label stack_overflow;
  __ LoadStackLimit(scratch, StackLimitKind::kRealStackLimit);
  __ cmp(sp, scratch);
  __ b(lo, &stack_overflow);

  // ----------- S t a t e -------------
  //  -- r1    : the JSGeneratorObject to resume
  //  -- r4    : generator function
  //  -- cp    : generator context
  //  -- lr    : return address
  //  -- sp[0] : generator receiver
  // -----------------------------------

  // Copy the function arguments from the generator object's register file.
  __ ldr(r3, FieldMemOperand(r4, JSFunction::kSharedFunctionInfoOffset));
  __ ldrh(r3,
          FieldMemOperand(r3, SharedFunctionInfo::kFormalParameterCountOffset));
  __ sub(r3, r3, Operand(kJSArgcReceiverSlots));
  __ ldr(r2,
         FieldMemOperand(r1, JSGeneratorObject::kParametersAndRegistersOffset));
  {
    Label done_loop, loop;
    __ bind(&loop);
    __ sub(r3, r3, Operand(1), SetCC);
    __ b(lt, &done_loop);
    __ add(scratch, r2, Operand(r3, LSL, kTaggedSizeLog2));
    __ ldr(scratch, FieldMemOperand(scratch, OFFSET_OF_DATA_START(FixedArray)));
    __ Push(scratch);
    __ b(&loop);
    __ bind(&done_loop);

    // Push receiver.
    __ ldr(scratch, FieldMemOperand(r1, JSGeneratorObject::kReceiverOffset));
    __ Push(scratch);
  }

  // Underlying function needs to have bytecode available.
  if (v8_flags.debug_code) {
    Label is_baseline, is_unavailable, ok;
    __ ldr(r3, FieldMemOperand(r4, JSFunction::kSharedFunctionInfoOffset));
    GetSharedFunctionInfoBytecodeOrBaseline(masm, r3, r3, r0, &is_baseline,
                                            &is_unavailable);
    __ jmp(&ok);

    __ bind(&is_unavailable);
    __ Abort(AbortReason::kMissingBytecodeArray);

    __ bind(&is_baseline);
    __ CompareObjectType(r3, r3, r3, CODE_TYPE);
    __ Assert(eq, AbortReason::kMissingBytecodeArray);

    __ bind(&ok);
  }

  // Resume (Ignition/TurboFan) generator object.
  {
    __ ldr(r0, FieldMemOperand(r4, JSFunction::kSharedFunctionInfoOffset));
    __ ldrh(r0, FieldMemOperand(
                    r0, SharedFunctionInfo::kFormalParameterCountOffset));
    // We abuse new.target both to indicate that this is a resume call and to
    // pass in the generator object.  In ordinary calls, new.target is always
    // undefined because generator functions are non-constructable.
    __ Move(r3, r1);
    __ Move(r1, r4);
    __ JumpJSFunction(r1);
  }

  __ bind(&prepare_step_in_if_stepping);
  {
    FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);
    __ Push(r1, r4);
    // Push hole as receiver since we do not use it for stepping.
    __ PushRoot(RootIndex::kTheHoleValue);
    __ CallRuntime(Runtime::kDebugOnFunctionCall);
    __ Pop(r1);
    __ ldr(r4, FieldMemOperand(r1, JSGeneratorObject::kFunctionOffset));
  }
  __ b(&stepping_prepared);

  __ bind(&prepare_step_in_suspended_generator);
  {
    FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);
    __ Push(r1);
    __ CallRuntime(Runtime::kDebugPrepareStepInSuspendedGenerator);
    __ Pop(r1);
    __ ldr(r4, FieldMemOperand(r1, JSGeneratorObject::kFunctionOffset));
  }
  __ b(&stepping_prepared);

  __ bind(&stack_overflow);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kThrowStackOverflow);
    __ bkpt(0);  // This should be unreachable.
  }
}

void Builtins::Generate_ConstructedNonConstructable(MacroAssembler* masm) {
  FrameScope scope(masm, StackFrame::INTERNAL);
  __ push(r1);
  __ CallRuntime(Runtime::kThrowConstructedNonConstructable);
}

namespace {

// Total size of the stack space pushed by JSEntryVariant.
// JSEntryTrampoline uses this to access on stack arguments passed to
// JSEntryVariant.
constexpr int kPushedStackSpace =
    kNumCalleeSaved * kPointerSize - kPointerSize /* FP */ +
    kNumDoubleCalleeSaved * kDoubleSize +
    7 * kPointerSize /* r5, r6, r7, r8, r9, fp, lr */ +
    EntryFrameConstants::kNextFastCallFramePCOffset;

// Assert that the EntryFrameConstants are in sync with the builtin.
static_assert(kPushedStackSpace ==
                  EntryFrameConstants::kDirectCallerSPOffset +
                      5 * kPointerSize /* r5, r6, r7, r8, r9*/ +
                      EntryFrameConstants::kNextFastCallFramePCOffset,
              "Pushed stack space and frame constants do not match. See "
              "frame-constants-arm.h");

// Called with the native C calling convention. The corresponding function
// signature is either:
//
//   using JSEntryFunction = GeneratedCode<Address(
//       Address root_register_value, Address new_target, Address target,
//       Address receiver, intptr_t argc, Address** argv)>;
// or
//   using JSEntryFunction = GeneratedCode<Address(
//       Address root_register_value, MicrotaskQueue* microtask_queue)>;
void Generate_JSEntryVariant(MacroAssembler* masm, StackFrame::Type type,
                             Builtin entry_trampoline) {
  // The register state is either:
  //   r0:                            root_register_value
  //   r1:                            code entry
  //   r2:                            function
  //   r3:                            receiver
  //   [sp + 0 * kSystemPointerSize]: argc
  //   [sp + 1 * kSystemPointerSize]: argv
  // or
  //   r0: root_register_value
  //   r1: microtask_queue
  // Preserve all but r0 and pass them to entry_trampoline.
  Label invoke, handler_entry, exit;
  const RegList kCalleeSavedWithoutFp = kCalleeSaved - fp;

  // Update |pushed_stack_space| when we manipulate the stack.
  int pushed_stack_space = EntryFrameConstants::kNextFastCallFramePCOffset;
  {
    NoRootArrayScope no_root_array(masm);

    // Called from C, so do not pop argc and args on exit (preserve sp)
    // No need to save register-passed args
    // Save callee-saved registers (incl. cp), but without fp
    __ stm(db_w, sp, kCalleeSavedWithoutFp);
    pushed_stack_space +=
        kNumCalleeSaved * kPointerSize - kPointerSize /* FP */;

    // Save callee-saved vfp registers.
    __ vstm(db_w, sp, kFirstCalleeSavedDoubleReg, kLastCalleeSavedDoubleReg);
    pushed_stack_space += kNumDoubleCalleeSaved * kDoubleSize;

    // Set up the reserved register for 0.0.
    __ vmov(kDoubleRegZero, base::Double(0.0));

    // Initialize the root register.
    // C calling convention. The first argument is passed in r0.
    __ mov(kRootRegister, r0);
  }

  // r0: root_register_value

  // Push a frame with special values setup to mark it as an entry frame.
  // Clear c_entry_fp, now we've pushed its previous value to the stack.
  // If the c_entry_fp is not already zero and we don't clear it, the
  // StackFrameIteratorForProfiler will assume we are executing C++ and miss the
  // JS frames on top.
  __ mov(r9, Operand::Zero());
  __ Move(r4, ExternalReference::Create(IsolateAddressId::kCEntryFPAddress,
                                        masm->isolate()));
  __ ldr(r7, MemOperand(r4));
  __ str(r9, MemOperand(r4));

  __ LoadIsolateField(r4, IsolateFieldId::kFastCCallCallerFP);
  __ ldr(r6, MemOperand(r4));
  __ str(r9, MemOperand(r4));

  __ LoadIsolateField(r4, IsolateFieldId::kFastCCallCallerPC);
  __ ldr(r5, MemOperand(r4));
  __ str(r9, MemOperand(r4));

  __ mov(r9, Operand(StackFrame::TypeToMarker(type)));
  __ mov(r8, Operand(StackFrame::TypeToMarker(type)));
  __ stm(db_w, sp, {r5, r6, r7, r8, r9, fp, lr});
  pushed_stack_space += 7 * kPointerSize /* r5, r6, r7, r8, r9, fp, lr */;

  Register scratch = r6;

  // Set up frame pointer for the frame to be pushed.
  __ add(fp, sp, Operand(-EntryFrameConstants::kNextFastCallFramePCOffset));

  // If this is the outermost JS call, set js_entry_sp value.
  Label non_outermost_js;
  ExternalReference js_entry_sp = ExternalReference::Create(
      IsolateAddressId::kJSEntrySPAddress, masm->isolate());
  __ Move(r5, js_entry_sp);
  __ ldr(scratch, MemOperand(r5));
  __ cmp(scratch, Operand::Zero());
  __ b(ne, &non_outermost_js);
  __ str(fp, MemOperand(r5));
  __ mov(scratch, Operand(StackFrame::OUTERMOST_JSENTRY_FRAME));
  Label cont;
  __ b(&cont);
  __ bind(&non_outermost_js);
  __ mov(scratch, Operand(StackFrame::INNER_JSENTRY_FRAME));
  __ bind(&cont);
  __ push(scratch);

  // Jump to a faked try block that does the invoke, with a faked catch
  // block that sets the exception.
  __ jmp(&invoke);

  // Block literal pool emission whilst taking the position of the handler
  // entry. This avoids making the assumption that literal pools are always
  // emitted after an instruction is emitted, rather than before.
  {
    Assembler::BlockConstPoolScope block_const_pool(masm);
    __ bind(&handler_entry);

    // Store the current pc as the handler offset. It's used later to create the
    // handler table.
    masm->isolate()->builtins()->SetJSEntryHandlerOffset(handler_entry.pos());

    // Caught exception: Store result (exception) in the exception
    // field in the JSEnv and return a failure sentinel.  Coming in here the
    // fp will be invalid because the PushStackHandler below sets it to 0 to
    // signal the existence of the JSEntry frame.
    __ Move(scratch, ExternalReference::Create(
                         IsolateAddressId::kExceptionAddress, masm->isolate()));
  }
  __ str(r0, MemOperand(scratch));
  __ LoadRoot(r0, RootIndex::kException);
  __ b(&exit);

  // Invoke: Link this frame into the handler chain.
  __ bind(&invoke);
  // Must preserve r0-r4, r5-r6 are available.
  __ PushStackHandler();
  // If an exception not caught by another handler occurs, this handler
  // returns control to the code after the bl(&invoke) above, which
  // restores all kCalleeSaved registers (including cp and fp) to their
  // saved values before returning a failure to C.
  //
  // Invoke the function by calling through JS entry trampoline builtin and
  // pop the faked function when we return.
  DCHECK_EQ(kPushedStackSpace, pushed_stack_space);
  USE(pushed_stack_space);
  __ CallBuiltin(entry_trampoline);

  // Unlink this frame from the handler chain.
  __ PopStackHandler();

  __ bind(&exit);  // r0 holds result
  // Check if the current stack frame is marked as the outermost JS frame.
  Label non_outermost_js_2;
  __ pop(r5);
  __ cmp(r5, Operand(StackFrame::OUTERMOST_JSENTRY_FRAME));
  __ b(ne, &non_outermost_js_2);
  __ mov(r6, Operand::Zero());
  __ Move(r5, js_entry_sp);
  __ str(r6, MemOperand(r5));
  __ bind(&non_outermost_js_2);

  // Restore the top frame descriptors from the stack.
  __ ldm(ia_w, sp, {r3, r4, r5});
  __ LoadIsolateField(scratch, IsolateFieldId::kFastCCallCallerFP);
  __ str(r4, MemOperand(scratch));

  __ LoadIsolateField(scratch, IsolateFieldId::kFastCCallCallerPC);
  __ str(r3, MemOperand(scratch));

  __ Move(scratch, ExternalReference::Create(IsolateAddressId::kCEntryFPAddress,
                                             masm->isolate()));
  __ str(r5, MemOperand(scratch));

  // Reset the stack to the callee saved registers.
  __ add(sp, sp,
         Operand(-EntryFrameConstants::kNextExitFrameFPOffset -
                 kSystemPointerSize /* already popped the exit frame FP */));

  __ ldm(ia_w, sp, {fp, lr});

  // Restore callee-saved vfp registers.
  __ vldm(ia_w, sp, kFirstCalleeSavedDoubleReg, kLastCalleeSavedDoubleReg);

  __ ldm(ia_w, sp, kCalleeSavedWithoutFp);

  __ mov(pc, lr);

  // Emit constant pool.
  __ CheckConstPool(true, false);
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
  // r0:                                                root_register_value
  // r1:                                                new.target
  // r2:                                                function
  // r3:                                                receiver
  // [fp + kPushedStackSpace + 0 * kSystemPointerSize]: argc
  // [fp + kPushedStackSpace + 1 * kSystemPointerSize]: argv
  // r5-r6, r8 and cp may be clobbered

  __ ldr(r0,
         MemOperand(fp, kPushedStackSpace + EntryFrameConstants::kArgcOffset));
  __ ldr(r4,
         MemOperand(fp, kPushedStackSpace + EntryFrameConstants::kArgvOffset));

  // r1: new.target
  // r2: function
  // r3: receiver
  // r0: argc
  // r4: argv

  // Enter an internal frame.
  {
    FrameScope scope(masm, StackFrame::INTERNAL);

    // Setup the context (we need to use the caller context from the isolate).
    ExternalReference context_address = ExternalReference::Create(
        IsolateAddressId::kContextAddress, masm->isolate());
    __ Move(cp, context_address);
    __ ldr(cp, MemOperand(cp));

    // Push the function.
    __ Push(r2);

    // Check if we have enough stack space to push all arguments + receiver.
    // Clobbers r5.
    Label enough_stack_space, stack_overflow;
    __ mov(r6, r0);
    __ StackOverflowCheck(r6, r5, &stack_overflow);
    __ b(&enough_stack_space);
    __ bind(&stack_overflow);
    __ CallRuntime(Runtime::kThrowStackOverflow);
    // Unreachable code.
    __ bkpt(0);

    __ bind(&enough_stack_space);

    // Copy arguments to the stack.
    // r1: new.target
    // r2: function
    // r3: receiver
    // r0: argc
    // r4: argv, i.e. points to first arg
    Generate_PushArguments(masm, r4, r0, r5, ArgumentsElementType::kHandle);

    // Push the receiver.
    __ Push(r3);

    // Setup new.target and function.
    __ mov(r3, r1);
    __ mov(r1, r2);
    // r0: argc
    // r1: function
    // r3: new.target

    // Initialize all JavaScript callee-saved registers, since they will be seen
    // by the garbage collector as part of handlers.
    __ LoadRoot(r4, RootIndex::kUndefinedValue);
    __ mov(r2, r4);
    __ mov(r5, r4);
    __ mov(r6, r4);
    __ mov(r8, r4);
    __ mov(r9, r4);

    // Invoke the code.
    Builtin builtin = is_construct ? Builtin::kConstruct : Builtins::Call();
    __ CallBuiltin(builtin);

    // Exit the JS frame and remove the parameters (except function), and
    // return.
    // Respect ABI stack constraint.
  }
  __ Jump(lr);

  // r0: result
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
  //   r0: root_register_value
  //   r1: microtask_queue

  __ mov(RunMicrotasksDescriptor::MicrotaskQueueRegister(), r1);
  __ TailCallBuiltin(Builtin::kRunMicrotasks);
}

static void LeaveInterpreterFrame(MacroAssembler* masm, Register scratch1,
                                  Register scratch2) {
  ASM_CODE_COMMENT(masm);
  Register params_size = scratch1;
  // Get the size of the formal parameters + receiver (in bytes).
  __ ldr(params_size,
         MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ ldrh(params_size,
          FieldMemOperand(params_size, BytecodeArray::kParameterSizeOffset));

  Register actual_params_size = scratch2;
  // Compute the size of the actual parameters + receiver (in bytes).
  __ ldr(actual_params_size,
         MemOperand(fp, StandardFrameConstants::kArgCOffset));

  // If actual is bigger than formal, then we should use it to free up the stack
  // arguments.
  __ cmp(params_size, actual_params_size);
  __ mov(params_size, actual_params_size, LeaveCC, kLessThan);

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

  __ Move(bytecode_size_table,
          ExternalReference::bytecode_size_table_address());
  __ Move(original_bytecode_offset, bytecode_offset);

  // Check if the bytecode is a Wide or ExtraWide prefix bytecode.
  Label process_bytecode;
  static_assert(0 == static_cast<int>(interpreter::Bytecode::kWide));
  static_assert(1 == static_cast<int>(interpreter::Bytecode::kExtraWide));
  static_assert(2 == static_cast<int>(interpreter::Bytecode::kDebugBreakWide));
  static_assert(3 ==
                static_cast<int>(interpreter::Bytecode::kDebugBreakExtraWide));
  __ cmp(bytecode, Operand(0x3));
  __ b(hi, &process_bytecode);
  __ tst(bytecode, Operand(0x1));
  // Load the next bytecode.
  __ add(bytecode_offset, bytecode_offset, Operand(1));
  __ ldrb(bytecode, MemOperand(bytecode_array, bytecode_offset));

  // Update table to the wide scaled table.
  __ add(bytecode_size_table, bytecode_size_table,
         Operand(kByteSize * interpreter::Bytecodes::kBytecodeCount));
  // Conditionally update table to the extra wide scaled table. We are taking
  // advantage of the fact that the extra wide follows the wide one.
  __ add(bytecode_size_table, bytecode_size_table,
         Operand(kByteSize * interpreter::Bytecodes::kBytecodeCount), LeaveCC,
         ne);

  __ bind(&process_bytecode);

  // Bailout to the return label if this is a return bytecode.

  // Create cmp, cmpne, ..., cmpne to check for a return bytecode.
  Condition flag = al;
#define JUMP_IF_EQUAL(NAME)                                                   \
  __ cmp(bytecode, Operand(static_cast<int>(interpreter::Bytecode::k##NAME)), \
         flag);                                                               \
  flag = ne;
  RETURN_BYTECODE_LIST(JUMP_IF_EQUAL)
#undef JUMP_IF_EQUAL

  __ b(if_return, eq);

  // If this is a JumpLoop, re-execute it to perform the jump to the beginning
  // of the loop.
  Label end, not_jump_loop;
  __ cmp(bytecode, Operand(static_cast<int>(interpreter::Bytecode::kJumpLoop)));
  __ b(ne, &not_jump_loop);
  // We need to restore the original bytecode_offset since we might have
  // increased it to skip the wide / extra-wide prefix bytecode.
  __ Move(bytecode_offset, original_bytecode_offset);
  __ b(&end);

  __ bind(&not_jump_loop);
  // Otherwise, load the size of the current bytecode and advance the offset.
  __ ldrb(scratch1, MemOperand(bytecode_size_table, bytecode));
  __ add(bytecode_offset, bytecode_offset, scratch1);

  __ bind(&end);
}

namespace {

void ResetSharedFunctionInfoAge(MacroAssembler* masm, Register sfi,
                                Register scratch) {
  DCHECK(!AreAliased(sfi, scratch));
  __ mov(scratch, Operand(0));
  __ strh(scratch, FieldMemOperand(sfi, SharedFunctionInfo::kAgeOffset));
}

void ResetJSFunctionAge(MacroAssembler* masm, Register js_function,
                        Register scratch1, Register scratch2) {
  __ Move(scratch1,
          FieldMemOperand(js_function, JSFunction::kSharedFunctionInfoOffset));
  ResetSharedFunctionInfoAge(masm, scratch1, scratch2);
}

void ResetFeedbackVectorOsrUrgency(MacroAssembler* masm,
                                   Register feedback_vector, Register scratch) {
  DCHECK(!AreAliased(feedback_vector, scratch));
  __ ldrb(scratch,
          FieldMemOperand(feedback_vector, FeedbackVector::kOsrStateOffset));
  __ and_(scratch, scratch, Operand(~FeedbackVector::OsrUrgencyBits::kMask));
  __ strb(scratch,
          FieldMemOperand(feedback_vector, FeedbackVector::kOsrStateOffset));
}

}  // namespace

// static
void Builtins::Generate_BaselineOutOfLinePrologue(MacroAssembler* masm) {
  UseScratchRegisterScope temps(masm);
  // Need a few extra registers
  temps.Include({r4, r5, r8, r9});

  auto descriptor =
      Builtins::CallInterfaceDescriptorFor(Builtin::kBaselineOutOfLinePrologue);
  Register closure = descriptor.GetRegisterParameter(
      BaselineOutOfLinePrologueDescriptor::kClosure);
  // Load the feedback cell and vector from the closure.
  Register feedback_cell = temps.Acquire();
  Register feedback_vector = temps.Acquire();
  __ ldr(feedback_cell,
         FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
  __ ldr(feedback_vector,
         FieldMemOperand(feedback_cell, FeedbackCell::kValueOffset));
  {
    UseScratchRegisterScope temps(masm);
    Register temporary = temps.Acquire();
    __ AssertFeedbackVector(feedback_vector, temporary);
  }

  // Check the tiering state.
  Label flags_need_processing;
  Register flags = no_reg;
  {
    UseScratchRegisterScope temps(masm);
    // flags will be used only in |flags_need_processing|
    // and outside it can be reused.
    flags = temps.Acquire();
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
    __ ldr(invocation_count,
           FieldMemOperand(feedback_vector,
                           FeedbackVector::kInvocationCountOffset));
    __ add(invocation_count, invocation_count, Operand(1));
    __ str(invocation_count,
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
      ResetJSFunctionAge(masm, callee_js_function, temps.Acquire(),
                         temps.Acquire());
    }
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
      UseScratchRegisterScope temps(masm);
      Register scratch = temps.Acquire();
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
    UseScratchRegisterScope temps(masm);

    Register sp_minus_frame_size = temps.Acquire();
    __ sub(sp_minus_frame_size, sp, frame_size);
    Register interrupt_limit = temps.Acquire();
    __ LoadStackLimit(interrupt_limit, StackLimitKind::kInterruptStackLimit);
    __ cmp(sp_minus_frame_size, interrupt_limit);
    __ b(&call_stack_guard, lo);
  }

  // Do "fast" return to the caller pc in lr.
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
  __ Ret();

  __ bind(&flags_need_processing);
  {
    ASM_CODE_COMMENT_STRING(masm, "Optimized marker check");
    UseScratchRegisterScope temps(masm);
    // Ensure the flags is not allocated again.
    temps.Exclude(flags);

    // Drop the frame created by the baseline call.
    __ ldm(ia_w, sp, {fp, lr});
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
//   o r0: actual argument count
//   o r1: the JS function object being called.
//   o r3: the incoming new target or generator object
//   o cp: our context
//   o fp: the caller's frame pointer
//   o sp: stack pointer
//   o lr: return address
//
// The function builds an interpreter frame. See InterpreterFrameConstants in
// frame-constants.h for its layout.
void Builtins::Generate_InterpreterEntryTrampoline(
    MacroAssembler* masm, InterpreterEntryTrampolineMode mode) {
  Register closure = r1;

  // Get the bytecode array from the function object and load it into
  // kInterpreterBytecodeArrayRegister.
  __ ldr(r4, FieldMemOperand(closure, JSFunction::kSharedFunctionInfoOffset));
  ResetSharedFunctionInfoAge(masm, r4, r8);

  // The bytecode array could have been flushed from the shared function info,
  // if so, call into CompileLazy.
  Label is_baseline, compile_lazy;
  GetSharedFunctionInfoBytecodeOrBaseline(masm, r4,
                                          kInterpreterBytecodeArrayRegister, r8,
                                          &is_baseline, &compile_lazy);

  Label push_stack_frame;
  Register feedback_vector = r2;
  __ LoadFeedbackVector(feedback_vector, closure, r4, &push_stack_frame);

#ifndef V8_JITLESS
  // If feedback vector is valid, check for optimized code and update invocation
  // count.
  Register flags = r4;
  Label flags_need_processing;
  __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
      flags, feedback_vector, CodeKind::INTERPRETED_FUNCTION,
      &flags_need_processing);

  ResetFeedbackVectorOsrUrgency(masm, feedback_vector, r4);

  // Increment invocation count for the function.
  __ ldr(r9, FieldMemOperand(feedback_vector,
                             FeedbackVector::kInvocationCountOffset));
  __ add(r9, r9, Operand(1));
  __ str(r9, FieldMemOperand(feedback_vector,
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
  __ SmiTag(r4, kInterpreterBytecodeOffsetRegister);
  __ Push(kInterpreterBytecodeArrayRegister, r4, feedback_vector);

  // Allocate the local and temporary register file on the stack.
  Label stack_overflow;
  {
    // Load frame size from the BytecodeArray object.
    __ ldr(r4, FieldMemOperand(kInterpreterBytecodeArrayRegister,
                               BytecodeArray::kFrameSizeOffset));

    // Do a stack check to ensure we don't go over the limit.
    __ sub(r9, sp, Operand(r4));
    __ LoadStackLimit(r2, StackLimitKind::kRealStackLimit);
    __ cmp(r9, Operand(r2));
    __ b(lo, &stack_overflow);

    // If ok, push undefined as the initial value for all register file entries.
    Label loop_header;
    Label loop_check;
    __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
    __ b(&loop_check, al);
    __ bind(&loop_header);
    // TODO(rmcilroy): Consider doing more than one push per loop iteration.
    __ push(kInterpreterAccumulatorRegister);
    // Continue loop if not done.
    __ bind(&loop_check);
    __ sub(r4, r4, Operand(kPointerSize), SetCC);
    __ b(&loop_header, ge);
  }

  // If the bytecode array has a valid incoming new target or generator object
  // register, initialize it with incoming value which was passed in r3.
  __ ldr(r9, FieldMemOperand(
                 kInterpreterBytecodeArrayRegister,
                 BytecodeArray::kIncomingNewTargetOrGeneratorRegisterOffset));
  __ cmp(r9, Operand::Zero());
  __ str(r3, MemOperand(fp, r9, LSL, kPointerSizeLog2), ne);

  // Perform interrupt stack check.
  // TODO(solanes): Merge with the real stack limit check above.
  Label stack_check_interrupt, after_stack_check_interrupt;
  __ LoadStackLimit(r4, StackLimitKind::kInterruptStackLimit);
  __ cmp(sp, r4);
  __ b(lo, &stack_check_interrupt);
  __ bind(&after_stack_check_interrupt);

  // The accumulator is already loaded with undefined.

  // Load the dispatch table into a register and dispatch to the bytecode
  // handler at the current bytecode offset.
  Label do_dispatch;
  __ bind(&do_dispatch);
  __ Move(
      kInterpreterDispatchTableRegister,
      ExternalReference::interpreter_dispatch_table_address(masm->isolate()));
  __ ldrb(r4, MemOperand(kInterpreterBytecodeArrayRegister,
                         kInterpreterBytecodeOffsetRegister));
  __ ldr(
      kJavaScriptCallCodeStartRegister,
      MemOperand(kInterpreterDispatchTableRegister, r4, LSL, kPointerSizeLog2));
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
  __ ldr(kInterpreterBytecodeArrayRegister,
         MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ ldr(kInterpreterBytecodeOffsetRegister,
         MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ SmiUntag(kInterpreterBytecodeOffsetRegister);

  // Either return, or advance to the next bytecode and dispatch.
  Label do_return;
  __ ldrb(r1, MemOperand(kInterpreterBytecodeArrayRegister,
                         kInterpreterBytecodeOffsetRegister));
  AdvanceBytecodeOffsetOrReturn(masm, kInterpreterBytecodeArrayRegister,
                                kInterpreterBytecodeOffsetRegister, r1, r2, r3,
                                &do_return);
  __ jmp(&do_dispatch);

  __ bind(&do_return);
  // The return value is in r0.
  LeaveInterpreterFrame(masm, r2, r4);
  __ Jump(lr);

  __ bind(&stack_check_interrupt);
  // Modify the bytecode offset in the stack to be kFunctionEntryBytecodeOffset
  // for the call to the StackGuard.
  __ mov(kInterpreterBytecodeOffsetRegister,
         Operand(Smi::FromInt(BytecodeArray::kHeaderSize - kHeapObjectTag +
                              kFunctionEntryBytecodeOffset)));
  __ str(kInterpreterBytecodeOffsetRegister,
         MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ CallRuntime(Runtime::kStackGuard);

  // After the call, restore the bytecode array, bytecode offset and accumulator
  // registers again. Also, restore the bytecode offset in the stack to its
  // previous value.
  __ ldr(kInterpreterBytecodeArrayRegister,
         MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ mov(kInterpreterBytecodeOffsetRegister,
         Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);

  __ SmiTag(r4, kInterpreterBytecodeOffsetRegister);
  __ str(r4, MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

  __ jmp(&after_stack_check_interrupt);

#ifndef V8_JITLESS
  __ bind(&flags_need_processing);
  __ OptimizeCodeOrTailCallOptimizedCodeSlot(flags, feedback_vector);

  __ bind(&is_baseline);
  {
    // Load the feedback vector from the closure.
    __ ldr(feedback_vector,
           FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
    __ ldr(feedback_vector,
           FieldMemOperand(feedback_vector, FeedbackCell::kValueOffset));

    Label install_baseline_code;
    // Check if feedback vector is valid. If not, call prepare for baseline to
    // allocate it.
    __ ldr(r8, FieldMemOperand(feedback_vector, HeapObject::kMapOffset));
    __ ldrh(r8, FieldMemOperand(r8, Map::kInstanceTypeOffset));
    __ cmp(r8, Operand(FEEDBACK_VECTOR_TYPE));
    __ b(ne, &install_baseline_code);

    // Check the tiering state.
    __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
        flags, feedback_vector, CodeKind::BASELINE, &flags_need_processing);

    // oad the baseline code into the closure.
    __ mov(r2, kInterpreterBytecodeArrayRegister);
    static_assert(kJavaScriptCallCodeStartRegister == r2, "ABI mismatch");
    __ ReplaceClosureCodeWithOptimizedCode(r2, closure);
    __ JumpCodeObject(r2);

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
  // Find the argument with lowest address.
  __ sub(scratch, num_args, Operand(1));
  __ mov(scratch, Operand(scratch, LSL, kSystemPointerSizeLog2));
  __ sub(start_address, start_address, scratch);
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
  //  -- r0 : the number of arguments
  //  -- r2 : the address of the first argument to be pushed. Subsequent
  //          arguments should be consecutive above this, in the same order as
  //          they are to be pushed onto the stack.
  //  -- r1 : the target to call (can be any Object).
  // -----------------------------------
  Label stack_overflow;

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // The spread argument should not be pushed.
    __ sub(r0, r0, Operand(1));
  }

  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    __ sub(r3, r0, Operand(kJSArgcReceiverSlots));
  } else {
    __ mov(r3, r0);
  }

  __ StackOverflowCheck(r3, r4, &stack_overflow);

  // Push the arguments. r2 and r4 will be modified.
  GenerateInterpreterPushArgs(masm, r3, r2, r4);

  // Push "undefined" as the receiver arg if we need to.
  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    __ PushRoot(RootIndex::kUndefinedValue);
  }

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Pass the spread in the register r2.
    // r2 already points to the penultimate argument, the spread
    // lies in the next interpreter register.
    __ sub(r2, r2, Operand(kSystemPointerSize));
    __ ldr(r2, MemOperand(r2));
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
    __ bkpt(0);
  }
}

// static
void Builtins::Generate_InterpreterPushArgsThenConstructImpl(
    MacroAssembler* masm, InterpreterPushArgsMode mode) {
  // ----------- S t a t e -------------
  // -- r0 : argument count
  // -- r3 : new target
  // -- r1 : constructor to call
  // -- r2 : allocation site feedback if available, undefined otherwise.
  // -- r4 : address of the first argument
  // -----------------------------------
  Label stack_overflow;

  __ StackOverflowCheck(r0, r6, &stack_overflow);

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // The spread argument should not be pushed.
    __ sub(r0, r0, Operand(1));
  }

  Register argc_without_receiver = r6;
  __ sub(argc_without_receiver, r0, Operand(kJSArgcReceiverSlots));
  // Push the arguments. r4 and r5 will be modified.
  GenerateInterpreterPushArgs(masm, argc_without_receiver, r4, r5);

  // Push a slot for the receiver to be constructed.
  __ mov(r5, Operand::Zero());
  __ push(r5);

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Pass the spread in the register r2.
    // r4 already points to the penultimate argument, the spread
    // lies in the next interpreter register.
    __ sub(r4, r4, Operand(kSystemPointerSize));
    __ ldr(r2, MemOperand(r4));
  } else {
    __ AssertUndefinedOrAllocationSite(r2, r5);
  }

  if (mode == InterpreterPushArgsMode::kArrayFunction) {
    __ AssertFunction(r1);

    // Tail call to the array construct stub (still in the caller
    // context at this point).
    __ TailCallBuiltin(Builtin::kArrayConstructorImpl);
  } else if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Call the constructor with r0, r1, and r3 unmodified.
    __ TailCallBuiltin(Builtin::kConstructWithSpread);
  } else {
    DCHECK_EQ(InterpreterPushArgsMode::kOther, mode);
    // Call the constructor with r0, r1, and r3 unmodified.
    __ TailCallBuiltin(Builtin::kConstruct);
  }

  __ bind(&stack_overflow);
  {
    __ TailCallRuntime(Runtime::kThrowStackOverflow);
    // Unreachable code.
    __ bkpt(0);
  }
}

// static
void Builtins::Generate_ConstructForwardAllArgsImpl(
    MacroAssembler* masm, ForwardWhichFrame which_frame) {
  // ----------- S t a t e -------------
  // -- r3 : new target
  // -- r1 : constructor to call
  // -----------------------------------
  Label stack_overflow;

  // Load the frame pointer into r4.
  switch (which_frame) {
    case ForwardWhichFrame::kCurrentFrame:
      __ mov(r4, fp);
      break;
    case ForwardWhichFrame::kParentFrame:
      __ ldr(r4, MemOperand(fp, StandardFrameConstants::kCallerFPOffset));
      break;
  }

  // Load the argument count into r0.
  __ ldr(r0, MemOperand(r4, StandardFrameConstants::kArgCOffset));

  __ StackOverflowCheck(r0, r6, &stack_overflow);

  // Point r4 to the base of the argument list to forward, excluding the
  // receiver.
  __ add(r4, r4,
         Operand((StandardFrameConstants::kFixedSlotCountAboveFp + 1) *
                 kSystemPointerSize));

  // Copy arguments on the stack. r5 is a scratch register.
  Register argc_without_receiver = r6;
  __ sub(argc_without_receiver, r0, Operand(kJSArgcReceiverSlots));
  __ PushArray(r4, argc_without_receiver, r5);

  // Push a slot for the receiver to be constructed.
  __ mov(r5, Operand::Zero());
  __ push(r5);

  // Call the constructor with r0, r1, and r3 unmodified.
  __ TailCallBuiltin(Builtin::kConstruct);

  __ bind(&stack_overflow);
  {
    __ TailCallRuntime(Runtime::kThrowStackOverflow);
    // Unreachable code.
    __ bkpt(0);
  }
}

namespace {

void NewImplicitReceiver(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  // -- r0 : argument count
  // -- r1 : constructor to call (checked to be a JSFunction)
  // -- r3 : new target
  //
  //  Stack:
  //  -- Implicit Receiver
  //  -- [arguments without receiver]
  //  -- Implicit Receiver
  //  -- Context
  //  -- FastConstructMarker
  //  -- FramePointer
  // -----------------------------------
  Register implicit_receiver = r4;

  // Save live registers.
  __ SmiTag(r0);
  __ Push(r0, r1, r3);
  __ CallBuiltin(Builtin::kFastNewObject);
  // Save result.
  __ Move(implicit_receiver, r0);
  // Restore live registers.
  __ Pop(r0, r1, r3);
  __ SmiUntag(r0);

  // Patch implicit receiver (in arguments)
  __ str(implicit_receiver, MemOperand(sp, 0 * kPointerSize));
  // Patch second implicit (in construct frame)
  __ str(implicit_receiver,
         MemOperand(fp, FastConstructFrameConstants::kImplicitReceiverOffset));

  // Restore context.
  __ ldr(cp, MemOperand(fp, FastConstructFrameConstants::kContextOffset));
}

}  // namespace

// static
void Builtins::Generate_InterpreterPushArgsThenFastConstructFunction(
    MacroAssembler* masm) {
  // ----------- S t a t e -------------
  // -- r0 : argument count
  // -- r1 : constructor to call (checked to be a JSFunction)
  // -- r3 : new target
  // -- r4 : address of the first argument
  // -- cp/r7 : context pointer
  // -----------------------------------
  __ AssertFunction(r1);

  // Check if target has a [[Construct]] internal method.
  Label non_constructor;
  __ LoadMap(r2, r1);
  __ ldrb(r2, FieldMemOperand(r2, Map::kBitFieldOffset));
  __ tst(r2, Operand(Map::Bits1::IsConstructorBit::kMask));
  __ b(eq, &non_constructor);

  // Add a stack check before pushing arguments.
  Label stack_overflow;
  __ StackOverflowCheck(r0, r2, &stack_overflow);

  // Enter a construct frame.
  FrameScope scope(masm, StackFrame::MANUAL);
  __ EnterFrame(StackFrame::FAST_CONSTRUCT);
  // Implicit receiver stored in the construct frame.
  __ LoadRoot(r2, RootIndex::kTheHoleValue);
  __ Push(cp, r2);

  // Push arguments + implicit receiver.
  Register argc_without_receiver = r6;
  __ sub(argc_without_receiver, r0, Operand(kJSArgcReceiverSlots));
  // Push the arguments. r4 and r5 will be modified.
  GenerateInterpreterPushArgs(masm, argc_without_receiver, r4, r5);
  // Implicit receiver as part of the arguments (patched later if needed).
  __ push(r2);

  // Check if it is a builtin call.
  Label builtin_call;
  __ ldr(r2, FieldMemOperand(r1, JSFunction::kSharedFunctionInfoOffset));
  __ ldr(r2, FieldMemOperand(r2, SharedFunctionInfo::kFlagsOffset));
  __ tst(r2, Operand(SharedFunctionInfo::ConstructAsBuiltinBit::kMask));
  __ b(ne, &builtin_call);

  // Check if we need to create an implicit receiver.
  Label not_create_implicit_receiver;
  __ DecodeField<SharedFunctionInfo::FunctionKindBits>(r2);
  __ JumpIfIsInRange(
      r2, r2, static_cast<uint32_t>(FunctionKind::kDefaultDerivedConstructor),
      static_cast<uint32_t>(FunctionKind::kDerivedConstructor),
      &not_create_implicit_receiver);
  NewImplicitReceiver(masm);
  __ bind(&not_create_implicit_receiver);

  // Call the function.
  __ InvokeFunctionWithNewTarget(r1, r3, r0, InvokeType::kCall);

  // ----------- S t a t e -------------
  //  -- r0     constructor result
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
  __ JumpIfNotRoot(r0, RootIndex::kUndefinedValue, &check_receiver);

  // Otherwise we do a smi check and fall through to check if the return value
  // is a valid receiver.

  // Throw away the result of the constructor invocation and use the
  // on-stack receiver as the result.
  __ bind(&use_receiver);
  __ ldr(r0,
         MemOperand(fp, FastConstructFrameConstants::kImplicitReceiverOffset));
  __ JumpIfRoot(r0, RootIndex::kTheHoleValue, &do_throw);

  __ bind(&leave_and_return);
  // Leave construct frame.
  __ LeaveFrame(StackFrame::CONSTRUCT);
  __ Jump(lr);

  __ bind(&check_receiver);
  // If the result is a smi, it is *not* an object in the ECMA sense.
  __ JumpIfSmi(r0, &use_receiver);

  // If the type of the result (stored in its map) is less than
  // FIRST_JS_RECEIVER_TYPE, it is not an object in the ECMA sense.
  static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
  __ CompareObjectType(r0, r4, r5, FIRST_JS_RECEIVER_TYPE);
  __ b(ge, &leave_and_return);
  __ b(&use_receiver);

  __ bind(&builtin_call);
  // TODO(victorgomes): Check the possibility to turn this into a tailcall.
  __ InvokeFunctionWithNewTarget(r1, r3, r0, InvokeType::kCall);
  __ LeaveFrame(StackFrame::FAST_CONSTRUCT);
  __ Jump(lr);

  __ bind(&do_throw);
  // Restore the context from the frame.
  __ ldr(cp, MemOperand(fp, FastConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowConstructorReturnedNonObject);
  __ bkpt(0);

  __ bind(&stack_overflow);
  // Restore the context from the frame.
  __ TailCallRuntime(Runtime::kThrowStackOverflow);
  // Unreachable code.
  __ bkpt(0);

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
  __ ldr(r2, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ ldr(r2, FieldMemOperand(r2, JSFunction::kSharedFunctionInfoOffset));
  __ ldr(r2,
         FieldMemOperand(r2, SharedFunctionInfo::kTrustedFunctionDataOffset));
  __ CompareObjectType(r2, kInterpreterDispatchTableRegister,
                       kInterpreterDispatchTableRegister,
                       INTERPRETER_DATA_TYPE);
  __ b(ne, &builtin_trampoline);

  __ ldr(r2,
         FieldMemOperand(r2, InterpreterData::kInterpreterTrampolineOffset));
  __ LoadCodeInstructionStart(r2, r2);
  __ b(&trampoline_loaded);

  __ bind(&builtin_trampoline);
  __ Move(r2, ExternalReference::
                  address_of_interpreter_entry_trampoline_instruction_start(
                      masm->isolate()));
  __ ldr(r2, MemOperand(r2));

  __ bind(&trampoline_loaded);
  __ add(lr, r2, Operand(interpreter_entry_return_pc_offset.value()));

  // Initialize the dispatch table register.
  __ Move(
      kInterpreterDispatchTableRegister,
      ExternalReference::interpreter_dispatch_table_address(masm->isolate()));

  // Get the bytecode array pointer from the frame.
  __ ldr(kInterpreterBytecodeArrayRegister,
         MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));

  if (v8_flags.debug_code) {
    // Check function data field is actually a BytecodeArray object.
    __ SmiTst(kInterpreterBytecodeArrayRegister);
    __ Assert(
        ne, AbortReason::kFunctionDataShouldBeBytecodeArrayOnInterpreterEntry);
    __ CompareObjectType(kInterpreterBytecodeArrayRegister, r1, no_reg,
                         BYTECODE_ARRAY_TYPE);
    __ Assert(
        eq, AbortReason::kFunctionDataShouldBeBytecodeArrayOnInterpreterEntry);
  }

  // Get the target bytecode offset from the frame.
  __ ldr(kInterpreterBytecodeOffsetRegister,
         MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ SmiUntag(kInterpreterBytecodeOffsetRegister);

  if (v8_flags.debug_code) {
    Label okay;
    __ cmp(kInterpreterBytecodeOffsetRegister,
           Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));
    __ b(ge, &okay);
    __ bkpt(0);
    __ bind(&okay);
  }

  // Dispatch to the target bytecode.
  UseScratchRegisterScope temps(masm);
  Register scratch = temps.Acquire();
  __ ldrb(scratch, MemOperand(kInterpreterBytecodeArrayRegister,
                              kInterpreterBytecodeOffsetRegister));
  __ ldr(kJavaScriptCallCodeStartRegister,
         MemOpera
```