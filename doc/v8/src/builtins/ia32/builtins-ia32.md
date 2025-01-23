Response: My thinking process to summarize the provided C++ code snippet goes like this:

1. **Identify the File and Location:** The prompt clearly states the file is `v8/src/builtins/ia32/builtins-ia32.cc`. This immediately tells me the code is part of V8 (the JavaScript engine in Chrome and Node.js), specifically dealing with built-in functions for the IA-32 (x86) architecture. The "builtins" part is crucial; it signifies low-level, performance-critical functions often directly related to JavaScript language features.

2. **Scan for Key Namespaces and Macros:**  I notice the `v8::internal` namespace, which is common in V8's internals. The `#define __ ACCESS_MASM(masm)` is a very strong indicator that the code is heavily using assembly generation through a `MacroAssembler` (likely `masm`). This means the functions are implemented using machine code for the IA-32 architecture.

3. **Look at the Included Headers:** The `#include` directives offer clues about the functionalities the code interacts with:
    * `api/api-arguments.h`:  Deals with arguments passed to API calls.
    * `base/bits-iterator.h`, `base/iterator.h`: Utility classes for iteration.
    * `builtins/builtins-descriptors.h`, `builtins/builtins-inl.h`: Definitions and inline functions related to built-ins.
    * `codegen/*`:  Components related to code generation, optimization, and dealing with different code representations (e.g., bytecode, machine code). This confirms the assembly generation aspect.
    * `debug/*`, `deoptimizer/*`: Features for debugging and handling deoptimization (when optimized code needs to fall back to simpler execution).
    * `execution/*`, `heap/*`, `logging/*`, `objects/*`:  Core V8 components for managing execution frames, the JavaScript heap, logging, and different types of JavaScript objects.
    * `wasm/*`: WebAssembly support, indicating some of these built-ins might be relevant to WebAssembly execution.

4. **Examine the Defined Functions:** I start reading through the defined functions, paying attention to their names and what they seem to be doing:
    * `Generate_Adaptor`:  Seems to create an intermediary function to call a given address.
    * `Generate_PushArguments`:  A utility function to push arguments onto the stack, potentially handling different argument types (raw vs. handles). This is a very common low-level operation.
    * `Generate_JSBuiltinsConstructStubHelper`, `Generate_JSConstructStubGeneric`, `Generate_JSBuiltinsConstructStub`: These clearly relate to the `new` keyword and object construction in JavaScript. The different variations likely handle different scenarios (generic, optimized).
    * `Generate_ConstructedNonConstructable`:  Deals with the error case when `new` is called on a non-constructor.
    * `Generate_JSEntryVariant`, `Generate_JSEntry`, `Generate_JSConstructEntry`, `Generate_JSRunMicrotasksEntry`: These functions seem to be the entry points for JavaScript execution, handling different types of calls (regular, constructor, microtasks). The "Entry" naming is significant.
    * `Generate_JSEntryTrampolineHelper`, `Generate_JSEntryTrampoline`, `Generate_JSConstructEntryTrampoline`, `Generate_RunMicrotasksTrampoline`:  "Trampoline" functions often act as intermediary jumps to the actual implementation. These likely set up the environment for executing JavaScript code.
    * `GetSharedFunctionInfoBytecode`, `AssertCodeIsBaseline`, `GetSharedFunctionInfoBytecodeOrBaseline`: Functions related to retrieving the underlying code (bytecode or compiled machine code) associated with a JavaScript function.
    * `Generate_ResumeGeneratorTrampoline`: Specific to generator functions and how they are resumed.
    * `LeaveInterpreterFrame`, `AdvanceBytecodeOffsetOrReturn`: Functions related to the interpreter, V8's bytecode execution engine. "LeaveFrame" suggests cleaning up the stack, and "AdvanceBytecodeOffset" suggests moving to the next instruction.
    * `ResetSharedFunctionInfoAge`, `ResetJSFunctionAge`, `ResetFeedbackVectorOsrUrgency`:  Functions related to internal state management, likely for optimization and garbage collection.
    * `Generate_InterpreterEntryTrampoline`:  The main entry point for executing JavaScript code through the interpreter. This is a very important function.
    * `Generate_InterpreterPushArgs`, `Generate_InterpreterPushArgsThenCallImpl`, `Generate_InterpreterPushZeroAndArgsAndReturnAddress`, `Generate_InterpreterPushArgsThenConstructImpl`: Functions responsible for pushing arguments onto the stack before a function call (both regular calls and constructor calls). The "Impl" suffix often means these are the core implementation logic.
    * `Generate_ConstructForwardAllArgsImpl`:  Deals with forwarding arguments when one constructor calls another.
    * `NewImplicitReceiver`:  Creates the initial object when `new` is used without an explicit receiver.
    * `Generate_InterpreterPushArgsThenFastConstructFunction`: An optimized path for constructing objects.
    * `Generate_InterpreterEnterBytecode`:  The final step in entering the interpreter, setting up the execution environment.

5. **Identify Major Themes:**  As I go through the functions, several key themes emerge:
    * **Built-in Function Implementation:** This file is about implementing fundamental JavaScript functionalities at a low level.
    * **IA-32 Architecture Specifics:** The `ia32` in the filename and the direct use of assembly instructions (`MacroAssembler`) confirm this.
    * **Stack Manipulation:**  Many functions are involved in pushing and popping arguments and managing call frames on the stack. This is essential for function calls in any architecture.
    * **Function Calls (Regular and Constructor):**  A significant portion of the code deals with setting up and executing both regular function calls and constructor calls (`new` keyword).
    * **Interpreter Integration:** Several functions are explicitly related to the interpreter, managing bytecode execution.
    * **Optimization Considerations:**  Functions related to feedback vectors and baseline code hint at the optimization strategies employed by V8.
    * **Error Handling:**  Functions like `Generate_ConstructedNonConstructable` and stack overflow checks demonstrate the need for handling error conditions.
    * **Entry Points:**  The "Entry" and "Trampoline" functions mark the boundaries between C++ code and JavaScript execution.

6. **Synthesize the Summary:** Based on the above observations, I can now formulate a concise summary:

    * This C++ file implements built-in JavaScript functions for the IA-32 architecture within the V8 engine.
    * It focuses on low-level operations like stack manipulation, argument passing, and managing the execution environment for JavaScript functions.
    * Key functionalities include handling regular and constructor calls, managing entry points to JavaScript execution, integrating with the V8 interpreter (bytecode execution), and supporting optimization mechanisms.
    * The code heavily uses assembly generation (`MacroAssembler`) for performance.

7. **Illustrate with JavaScript Examples:** To connect this to JavaScript, I consider the core functionalities identified:

    * **Function Calls:**  A simple function call demonstrates the underlying mechanisms the built-ins are setting up.
    * **Constructor Calls:** Using the `new` keyword directly relates to the `JSConstructStub` functions.
    * **Interpreter Entry:** Any JavaScript code execution starts by entering the interpreter (or a compiled version), making a basic script a relevant example.
    * **Error Handling:**  Calling `new` on a non-function triggers the `ConstructedNonConstructable` logic.

By following these steps, I can systematically analyze the C++ code and generate a comprehensive and accurate summary, including relevant JavaScript examples. The iterative process of examining the code, identifying themes, and then synthesizing the information is crucial.
这个C++源代码文件 `builtins-ia32.cc` 是 **V8 JavaScript 引擎** 中专门为 **IA-32 (x86) 架构** 实现 **内置函数 (builtins)** 的代码。它是 V8 引擎中执行 JavaScript 代码的核心组成部分。

**主要功能归纳:**

1. **提供 JavaScript 内置函数的底层实现:**  这个文件包含了许多 JavaScript 语言内置的全局函数和构造函数的底层实现，例如 `Object`, `Function`, `Array`, `Date`, 以及一些操作符的行为等。这些实现是用高度优化的 IA-32 汇编代码编写的，以确保性能。

2. **处理函数调用和构造:** 代码中包含了处理 JavaScript 函数调用 (包括普通函数调用和构造函数调用) 的逻辑。这包括设置调用栈帧、传递参数、执行函数体以及处理返回值等。

3. **支持解释器 (Interpreter):**  文件内包含了与 V8 的解释器 Ignition 相关的代码，例如 `InterpreterEntryTrampoline`，它负责在解释器中执行 JavaScript 代码。

4. **支持代码优化和入口:**  代码中涉及到一些与代码优化相关的逻辑，例如检查优化状态、跳转到已编译的代码等。`JSEntry` 和 `JSConstructEntry` 等函数是 JavaScript 代码执行的入口点。

5. **处理异常和错误:**  代码中包含一些处理异常和错误情况的逻辑，例如栈溢出检查。

6. **支持生成器 (Generators):**  `ResumeGeneratorTrampoline` 函数处理生成器函数的恢复执行。

7. **参数处理:** 包含了处理函数调用参数的逻辑，例如将参数压入栈中。

**与 JavaScript 功能的关系及 JavaScript 示例:**

这个文件中的 C++ 代码直接支撑着许多 JavaScript 的核心功能。你所编写的每一个 JavaScript 程序，其执行过程都离不开这些内置函数的底层实现。

**以下是一些 JavaScript 功能与 `builtins-ia32.cc` 中代码的关联示例:**

**1. 函数调用:**

```javascript
function greet(name) {
  console.log("Hello, " + name + "!");
}

greet("World");
```

当 `greet("World")` 被调用时，V8 引擎会通过类似于 `Builtins::Generate_JSEntryTrampoline` 或 `Builtins::Generate_InterpreterEntryTrampoline` 这样的函数来设置执行环境，并将参数 `"World"` 传递给 `greet` 函数的底层实现。

**2. 对象创建 (使用 `new` 关键字):**

```javascript
function Person(name) {
  this.name = name;
}

const person = new Person("Alice");
console.log(person.name);
```

当执行 `new Person("Alice")` 时，V8 引擎会调用类似于 `Builtins::Generate_JSConstructStubGeneric` 或 `Builtins::Generate_JSBuiltinsConstructStub` 这样的函数来创建新的 `Person` 对象并调用构造函数。

**3. 数组创建:**

```javascript
const numbers = [1, 2, 3];
const moreNumbers = new Array(4, 5, 6);
```

无论是使用字面量 `[]` 还是 `new Array()`, V8 都会调用相应的内置函数（可能涉及到 `Builtins::Generate_JSConstructStubGeneric` 或专门的数组构造函数实现）来创建和初始化数组对象。

**4. 使用内置对象的方法:**

```javascript
const text = "hello";
console.log(text.toUpperCase());
```

当调用 `text.toUpperCase()` 时，V8 引擎会查找字符串对象的 `toUpperCase` 方法，并执行其在 `builtins-ia32.cc` 或相关文件中的底层实现。

**5. 生成器函数:**

```javascript
function* count() {
  yield 1;
  yield 2;
  yield 3;
}

const generator = count();
console.log(generator.next()); // { value: 1, done: false }
```

当生成器函数被调用和迭代时，`Builtins::Generate_ResumeGeneratorTrampoline` 这样的函数负责处理生成器状态的保存和恢复。

**总结:**

`v8/src/builtins/ia32/builtins-ia32.cc` 是 V8 引擎在 IA-32 架构上的核心组成部分，它包含了大量用优化的汇编代码实现的 JavaScript 内置功能，直接支撑着 JavaScript 代码的执行。理解这个文件的功能有助于深入了解 JavaScript 引擎的底层工作原理。

### 提示词
```
这是目录为v8/src/builtins/ia32/builtins-ia32.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if V8_TARGET_ARCH_IA32

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
  __ Move(kJavaScriptCallExtraArg1Register,
          Immediate(ExternalReference::Create(address)));
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
                            Register scratch1, Register scratch2,
                            ArgumentsElementType element_type) {
  DCHECK(!AreAliased(array, argc, scratch1, scratch2));
  Register counter = scratch1;
  Label loop, entry;
  __ lea(counter, Operand(argc, -kJSArgcReceiverSlots));
  __ jmp(&entry);
  __ bind(&loop);
  Operand value(array, counter, times_system_pointer_size, 0);
  if (element_type == ArgumentsElementType::kHandle) {
    DCHECK(scratch2 != no_reg);
    __ mov(scratch2, value);
    value = Operand(scratch2, 0);
  }
  __ Push(value);
  __ bind(&entry);
  __ dec(counter);
  __ j(greater_equal, &loop, Label::kNear);
}

void Generate_JSBuiltinsConstructStubHelper(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- eax: number of arguments
  //  -- edi: constructor function
  //  -- edx: new target
  //  -- esi: context
  // -----------------------------------

  Label stack_overflow;

  __ StackOverflowCheck(eax, ecx, &stack_overflow);

  // Enter a construct frame.
  {
    FrameScope scope(masm, StackFrame::CONSTRUCT);

    // Preserve the incoming parameters on the stack.
    __ push(esi);
    __ push(eax);

    // TODO(victorgomes): When the arguments adaptor is completely removed, we
    // should get the formal parameter count and copy the arguments in its
    // correct position (including any undefined), instead of delaying this to
    // InvokeFunction.

    // Set up pointer to first argument (skip receiver).
    __ lea(esi, Operand(ebp, StandardFrameConstants::kFixedFrameSizeAboveFp +
                                 kSystemPointerSize));
    // Copy arguments to the expression stack.
    // esi: Pointer to start of arguments.
    // eax: Number of arguments.
    Generate_PushArguments(masm, esi, eax, ecx, no_reg,
                           ArgumentsElementType::kRaw);
    // The receiver for the builtin/api call.
    __ PushRoot(RootIndex::kTheHoleValue);

    // Call the function.
    // eax: number of arguments (untagged)
    // edi: constructor function
    // edx: new target
    // Reload context from the frame.
    __ mov(esi, Operand(ebp, ConstructFrameConstants::kContextOffset));
    __ InvokeFunction(edi, edx, eax, InvokeType::kCall);

    // Restore context from the frame.
    __ mov(esi, Operand(ebp, ConstructFrameConstants::kContextOffset));
    // Restore arguments count from the frame.
    __ mov(edx, Operand(ebp, ConstructFrameConstants::kLengthOffset));
    // Leave construct frame.
  }

  // Remove caller arguments from the stack and return.
  __ DropArguments(edx, ecx);
  __ ret(0);

  __ bind(&stack_overflow);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kThrowStackOverflow);
    __ int3();  // This should be unreachable.
  }
}

}  // namespace

// The construct stub for ES5 constructor functions and ES6 class constructors.
void Builtins::Generate_JSConstructStubGeneric(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- eax: number of arguments (untagged)
  //  -- edi: constructor function
  //  -- edx: new target
  //  -- esi: context
  //  -- sp[...]: constructor arguments
  // -----------------------------------

  FrameScope scope(masm, StackFrame::MANUAL);
  // Enter a construct frame.
  __ EnterFrame(StackFrame::CONSTRUCT);

  Label post_instantiation_deopt_entry, not_create_implicit_receiver;

  // Preserve the incoming parameters on the stack.
  __ Push(esi);
  __ Push(eax);
  __ Push(edi);
  __ PushRoot(RootIndex::kTheHoleValue);
  __ Push(edx);

  // ----------- S t a t e -------------
  //  --         sp[0*kSystemPointerSize]: new target
  //  --         sp[1*kSystemPointerSize]: padding
  //  -- edi and sp[2*kSystemPointerSize]: constructor function
  //  --         sp[3*kSystemPointerSize]: argument count
  //  --         sp[4*kSystemPointerSize]: context
  // -----------------------------------

  __ mov(eax, FieldOperand(edi, JSFunction::kSharedFunctionInfoOffset));
  __ mov(eax, FieldOperand(eax, SharedFunctionInfo::kFlagsOffset));
  __ DecodeField<SharedFunctionInfo::FunctionKindBits>(eax);
  __ JumpIfIsInRange(
      eax, static_cast<uint32_t>(FunctionKind::kDefaultDerivedConstructor),
      static_cast<uint32_t>(FunctionKind::kDerivedConstructor), ecx,
      &not_create_implicit_receiver, Label::kNear);

  // If not derived class constructor: Allocate the new receiver object.
  __ CallBuiltin(Builtin::kFastNewObject);
  __ jmp(&post_instantiation_deopt_entry, Label::kNear);

  // Else: use TheHoleValue as receiver for constructor call
  __ bind(&not_create_implicit_receiver);
  __ LoadRoot(eax, RootIndex::kTheHoleValue);

  // ----------- S t a t e -------------
  //  --                         eax: implicit receiver
  //  -- Slot 4 / sp[0*kSystemPointerSize]: new target
  //  -- Slot 3 / sp[1*kSystemPointerSize]: padding
  //  -- Slot 2 / sp[2*kSystemPointerSize]: constructor function
  //  -- Slot 1 / sp[3*kSystemPointerSize]: number of arguments
  //  -- Slot 0 / sp[4*kSystemPointerSize]: context
  // -----------------------------------
  // Deoptimizer enters here.
  masm->isolate()->heap()->SetConstructStubCreateDeoptPCOffset(
      masm->pc_offset());
  __ bind(&post_instantiation_deopt_entry);

  // Restore new target.
  __ Pop(edx);

  // Push the allocated receiver to the stack.
  __ Push(eax);

  // We need two copies because we may have to return the original one
  // and the calling conventions dictate that the called function pops the
  // receiver. The second copy is pushed after the arguments, we saved in xmm0
  // since eax needs to store the number of arguments before
  // InvokingFunction.
  __ movd(xmm0, eax);

  // Set up pointer to first argument (skip receiver).
  __ lea(edi, Operand(ebp, StandardFrameConstants::kFixedFrameSizeAboveFp +
                               kSystemPointerSize));

  // Restore argument count.
  __ mov(eax, Operand(ebp, ConstructFrameConstants::kLengthOffset));

  // Check if we have enough stack space to push all arguments.
  // Argument count in eax. Clobbers ecx.
  Label stack_overflow;
  __ StackOverflowCheck(eax, ecx, &stack_overflow);

  // TODO(victorgomes): When the arguments adaptor is completely removed, we
  // should get the formal parameter count and copy the arguments in its
  // correct position (including any undefined), instead of delaying this to
  // InvokeFunction.

  // Copy arguments to the expression stack.
  // edi: Pointer to start of arguments.
  // eax: Number of arguments.
  Generate_PushArguments(masm, edi, eax, ecx, no_reg,
                         ArgumentsElementType::kRaw);

  // Push implicit receiver.
  __ movd(ecx, xmm0);
  __ Push(ecx);

  // Restore and and call the constructor function.
  __ mov(edi, Operand(ebp, ConstructFrameConstants::kConstructorOffset));
  __ InvokeFunction(edi, edx, eax, InvokeType::kCall);

  // If the result is an object (in the ECMA sense), we should get rid
  // of the receiver and use the result; see ECMA-262 section 13.2.2-7
  // on page 74.

  Label check_result, use_receiver, do_throw, leave_and_return;
  // If the result is undefined, we jump out to using the implicit receiver.
  __ JumpIfNotRoot(eax, RootIndex::kUndefinedValue, &check_result,
                   Label::kNear);

  // Throw away the result of the constructor invocation and use the
  // on-stack receiver as the result.
  __ bind(&use_receiver);
  __ mov(eax, Operand(esp, 0 * kSystemPointerSize));
  __ JumpIfRoot(eax, RootIndex::kTheHoleValue, &do_throw);

  __ bind(&leave_and_return);
  // Restore arguments count from the frame.
  __ mov(edx, Operand(ebp, ConstructFrameConstants::kLengthOffset));
  __ LeaveFrame(StackFrame::CONSTRUCT);

  // Remove caller arguments from the stack and return.
  __ DropArguments(edx, ecx);
  __ ret(0);

  // Otherwise we do a smi check and fall through to check if the return value
  // is a valid receiver.
  __ bind(&check_result);

  // If the result is a smi, it is *not* an object in the ECMA sense.
  __ JumpIfSmi(eax, &use_receiver, Label::kNear);

  // If the type of the result (stored in its map) is less than
  // FIRST_JS_RECEIVER_TYPE, it is not an object in the ECMA sense.
  static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
  __ CmpObjectType(eax, FIRST_JS_RECEIVER_TYPE, ecx);
  __ j(above_equal, &leave_and_return, Label::kNear);
  __ jmp(&use_receiver, Label::kNear);

  __ bind(&do_throw);
  // Restore context from the frame.
  __ mov(esi, Operand(ebp, ConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowConstructorReturnedNonObject);
  // This should be unreachable.
  __ int3();

  __ bind(&stack_overflow);
  // Restore context from the frame.
  __ mov(esi, Operand(ebp, ConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowStackOverflow);
  // This should be unreachable.
  __ int3();
}

void Builtins::Generate_JSBuiltinsConstructStub(MacroAssembler* masm) {
  Generate_JSBuiltinsConstructStubHelper(masm);
}

void Builtins::Generate_ConstructedNonConstructable(MacroAssembler* masm) {
  FrameScope scope(masm, StackFrame::INTERNAL);
  __ push(edi);
  __ CallRuntime(Runtime::kThrowConstructedNonConstructable);
}

namespace {

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
  Label invoke, handler_entry, exit;
  Label not_outermost_js, not_outermost_js_2;

  {
    NoRootArrayScope uninitialized_root_register(masm);

    // Set up frame.
    __ push(ebp);
    __ mov(ebp, esp);

    // Push marker in two places.
    __ push(Immediate(StackFrame::TypeToMarker(type)));
    // Reserve a slot for the context. It is filled after the root register has
    // been set up.
    __ AllocateStackSpace(kSystemPointerSize);
    // Save callee-saved registers (C calling conventions).
    __ push(edi);
    __ push(esi);
    __ push(ebx);

    // Initialize the root register based on the given Isolate* argument.
    // C calling convention. The first argument is passed on the stack.
    __ mov(kRootRegister,
           Operand(ebp, EntryFrameConstants::kRootRegisterValueOffset));
  }

  // Save copies of the top frame descriptor on the stack.
  ExternalReference c_entry_fp = ExternalReference::Create(
      IsolateAddressId::kCEntryFPAddress, masm->isolate());
  __ push(__ ExternalReferenceAsOperand(c_entry_fp, edi));

  __ push(__ ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));

  __ push(__ ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerPC));

  // Clear c_entry_fp, now we've pushed its previous value to the stack.
  // If the c_entry_fp is not already zero and we don't clear it, the
  // StackFrameIteratorForProfiler will assume we are executing C++ and miss the
  // JS frames on top.
  __ mov(__ ExternalReferenceAsOperand(c_entry_fp, edi), Immediate(0));
  __ mov(__ ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP),
         Immediate(0));
  __ mov(__ ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerPC),
         Immediate(0));

  // Store the context address in the previously-reserved slot.
  ExternalReference context_address = ExternalReference::Create(
      IsolateAddressId::kContextAddress, masm->isolate());
  __ mov(edi, __ ExternalReferenceAsOperand(context_address, edi));
  static constexpr int kOffsetToContextSlot = -2 * kSystemPointerSize;
  __ mov(Operand(ebp, kOffsetToContextSlot), edi);

  // If this is the outermost JS call, set js_entry_sp value.
  ExternalReference js_entry_sp = ExternalReference::Create(
      IsolateAddressId::kJSEntrySPAddress, masm->isolate());
  __ cmp(__ ExternalReferenceAsOperand(js_entry_sp, edi), Immediate(0));
  __ j(not_equal, &not_outermost_js, Label::kNear);
  __ mov(__ ExternalReferenceAsOperand(js_entry_sp, edi), ebp);
  __ push(Immediate(StackFrame::OUTERMOST_JSENTRY_FRAME));
  __ jmp(&invoke, Label::kNear);
  __ bind(&not_outermost_js);
  __ push(Immediate(StackFrame::INNER_JSENTRY_FRAME));

  // Jump to a faked try block that does the invoke, with a faked catch
  // block that sets the exception.
  __ jmp(&invoke);
  __ bind(&handler_entry);

  // Store the current pc as the handler offset. It's used later to create the
  // handler table.
  masm->isolate()->builtins()->SetJSEntryHandlerOffset(handler_entry.pos());

  // Caught exception: Store result (exception) in the exception
  // field in the JSEnv and return a failure sentinel.
  ExternalReference exception = ExternalReference::Create(
      IsolateAddressId::kExceptionAddress, masm->isolate());
  __ mov(__ ExternalReferenceAsOperand(exception, edi), eax);

  __ Move(eax, masm->isolate()->factory()->exception());
  __ jmp(&exit);

  // Invoke: Link this frame into the handler chain.
  __ bind(&invoke);
  __ PushStackHandler(edi);

  // Invoke the function by calling through JS entry trampoline builtin and
  // pop the faked function when we return.
  __ CallBuiltin(entry_trampoline);

  // Unlink this frame from the handler chain.
  __ PopStackHandler(edi);

  __ bind(&exit);

  // Check if the current stack frame is marked as the outermost JS frame.
  __ pop(edi);
  __ cmp(edi, Immediate(StackFrame::OUTERMOST_JSENTRY_FRAME));
  __ j(not_equal, &not_outermost_js_2);
  __ mov(__ ExternalReferenceAsOperand(js_entry_sp, edi), Immediate(0));
  __ bind(&not_outermost_js_2);

  // Restore the top frame descriptor from the stack.
  __ pop(__ ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerPC));
  __ pop(__ ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));
  __ pop(__ ExternalReferenceAsOperand(c_entry_fp, edi));

  // Restore callee-saved registers (C calling conventions).
  __ pop(ebx);
  __ pop(esi);
  __ pop(edi);
  __ add(esp, Immediate(2 * kSystemPointerSize));  // remove markers

  // Restore frame pointer and return.
  __ pop(ebp);
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
  {
    FrameScope scope(masm, StackFrame::INTERNAL);

    const Register scratch1 = edx;
    const Register scratch2 = edi;

    // Setup the context (we need to use the caller context from the isolate).
    ExternalReference context_address = ExternalReference::Create(
        IsolateAddressId::kContextAddress, masm->isolate());
    __ mov(esi, __ ExternalReferenceAsOperand(context_address, scratch1));

    // Load the previous frame pointer (edx) to access C arguments
    __ mov(scratch1, Operand(ebp, 0));

    // Push the function.
    __ push(Operand(scratch1, EntryFrameConstants::kFunctionArgOffset));

    // Load the number of arguments and setup pointer to the arguments.
    __ mov(eax, Operand(scratch1, EntryFrameConstants::kArgcOffset));
    __ mov(scratch1, Operand(scratch1, EntryFrameConstants::kArgvOffset));

    // Check if we have enough stack space to push all arguments.
    // Argument count in eax. Clobbers ecx.
    Label enough_stack_space, stack_overflow;
    __ StackOverflowCheck(eax, ecx, &stack_overflow);
    __ jmp(&enough_stack_space);

    __ bind(&stack_overflow);
    __ CallRuntime(Runtime::kThrowStackOverflow);
    // This should be unreachable.
    __ int3();

    __ bind(&enough_stack_space);

    // Copy arguments to the stack.
    // scratch1 (edx): Pointer to start of arguments.
    // eax: Number of arguments.
    Generate_PushArguments(masm, scratch1, eax, ecx, scratch2,
                           ArgumentsElementType::kHandle);

    // Load the previous frame pointer to access C arguments
    __ mov(scratch2, Operand(ebp, 0));

    // Push the receiver onto the stack.
    __ push(Operand(scratch2, EntryFrameConstants::kReceiverArgOffset));

    // Get the new.target and function from the frame.
    __ mov(edx, Operand(scratch2, EntryFrameConstants::kNewTargetArgOffset));
    __ mov(edi, Operand(scratch2, EntryFrameConstants::kFunctionArgOffset));

    // Invoke the code.
    Builtin builtin = is_construct ? Builtin::kConstruct : Builtins::Call();
    __ CallBuiltin(builtin);

    // Exit the internal frame. Notice that this also removes the empty.
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
  // This expects two C++ function parameters passed by Invoke() in
  // execution.cc.
  //   r1: microtask_queue
  __ mov(RunMicrotasksDescriptor::MicrotaskQueueRegister(),
         Operand(ebp, EntryFrameConstants::kMicrotaskQueueArgOffset));
  __ TailCallBuiltin(Builtin::kRunMicrotasks);
}

static void GetSharedFunctionInfoBytecode(MacroAssembler* masm,
                                          Register sfi_data,
                                          Register scratch1) {
  Label done;

  __ CmpObjectType(sfi_data, INTERPRETER_DATA_TYPE, scratch1);
  __ j(not_equal, &done, Label::kNear);
  __ mov(sfi_data,
         FieldOperand(sfi_data, InterpreterData::kBytecodeArrayOffset));

  __ bind(&done);
}

static void AssertCodeIsBaseline(MacroAssembler* masm, Register code,
                                 Register scratch) {
  DCHECK(!AreAliased(code, scratch));
  // Verify that the code kind is baseline code via the CodeKind.
  __ mov(scratch, FieldOperand(code, Code::kFlagsOffset));
  __ DecodeField<Code::KindField>(scratch);
  __ cmp(scratch, Immediate(static_cast<int>(CodeKind::BASELINE)));
  __ Assert(equal, AbortReason::kExpectedBaselineData);
}

static void GetSharedFunctionInfoBytecodeOrBaseline(
    MacroAssembler* masm, Register sfi, Register bytecode, Register scratch1,
    Label* is_baseline, Label* is_unavailable) {
  ASM_CODE_COMMENT(masm);
  Label done;

  Register data = bytecode;
  __ mov(data,
         FieldOperand(sfi, SharedFunctionInfo::kTrustedFunctionDataOffset));

  __ LoadMap(scratch1, data);

#ifndef V8_JITLESS
  __ CmpInstanceType(scratch1, CODE_TYPE);
  if (v8_flags.debug_code) {
    Label not_baseline;
    __ j(not_equal, &not_baseline);
    AssertCodeIsBaseline(masm, data, scratch1);
    __ j(equal, is_baseline);
    __ bind(&not_baseline);
  } else {
    __ j(equal, is_baseline);
  }
#endif  // !V8_JITLESS

  __ CmpInstanceType(scratch1, BYTECODE_ARRAY_TYPE);
  __ j(equal, &done, Label::kNear);

  __ CmpInstanceType(scratch1, INTERPRETER_DATA_TYPE);
  __ j(not_equal, is_unavailable);
  __ mov(data, FieldOperand(data, InterpreterData::kBytecodeArrayOffset));

  __ bind(&done);
}

// static
void Builtins::Generate_ResumeGeneratorTrampoline(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- eax    : the value to pass to the generator
  //  -- edx    : the JSGeneratorObject to resume
  //  -- esp[0] : return address
  // -----------------------------------
  // Store input value into generator object.
  __ mov(FieldOperand(edx, JSGeneratorObject::kInputOrDebugPosOffset), eax);
  Register object = WriteBarrierDescriptor::ObjectRegister();
  __ mov(object, edx);
  __ RecordWriteField(object, JSGeneratorObject::kInputOrDebugPosOffset, eax,
                      WriteBarrierDescriptor::SlotAddressRegister(),
                      SaveFPRegsMode::kIgnore);
  // Check that edx is still valid, RecordWrite might have clobbered it.
  __ AssertGeneratorObject(edx);

  // Load suspended function and context.
  __ mov(edi, FieldOperand(edx, JSGeneratorObject::kFunctionOffset));
  __ mov(esi, FieldOperand(edi, JSFunction::kContextOffset));

  // Flood function if we are stepping.
  Label prepare_step_in_if_stepping, prepare_step_in_suspended_generator;
  Label stepping_prepared;
  ExternalReference debug_hook =
      ExternalReference::debug_hook_on_function_call_address(masm->isolate());
  __ cmpb(__ ExternalReferenceAsOperand(debug_hook, ecx), Immediate(0));
  __ j(not_equal, &prepare_step_in_if_stepping);

  // Flood function if we need to continue stepping in the suspended generator.
  ExternalReference debug_suspended_generator =
      ExternalReference::debug_suspended_generator_address(masm->isolate());
  __ cmp(edx, __ ExternalReferenceAsOperand(debug_suspended_generator, ecx));
  __ j(equal, &prepare_step_in_suspended_generator);
  __ bind(&stepping_prepared);

  // Check the stack for overflow. We are not trying to catch interruptions
  // (i.e. debug break and preemption) here, so check the "real stack limit".
  Label stack_overflow;
  __ CompareStackLimit(esp, StackLimitKind::kRealStackLimit);
  __ j(below, &stack_overflow);

  // Pop return address.
  __ PopReturnAddressTo(eax);

  // ----------- S t a t e -------------
  //  -- eax    : return address
  //  -- edx    : the JSGeneratorObject to resume
  //  -- edi    : generator function
  //  -- esi    : generator context
  // -----------------------------------

  {
    __ movd(xmm0, ebx);

    // Copy the function arguments from the generator object's register file.
    __ mov(ecx, FieldOperand(edi, JSFunction::kSharedFunctionInfoOffset));
    __ movzx_w(ecx, FieldOperand(
                        ecx, SharedFunctionInfo::kFormalParameterCountOffset));
    __ dec(ecx);  // Exclude receiver.
    __ mov(ebx,
           FieldOperand(edx, JSGeneratorObject::kParametersAndRegistersOffset));
    {
      Label done_loop, loop;
      __ bind(&loop);
      __ dec(ecx);
      __ j(less, &done_loop);
      __ Push(FieldOperand(ebx, ecx, times_tagged_size,
                           OFFSET_OF_DATA_START(FixedArray)));
      __ jmp(&loop);
      __ bind(&done_loop);
    }

    // Push receiver.
    __ Push(FieldOperand(edx, JSGeneratorObject::kReceiverOffset));

    // Restore registers.
    __ mov(edi, FieldOperand(edx, JSGeneratorObject::kFunctionOffset));
    __ movd(ebx, xmm0);
  }

  // Underlying function needs to have bytecode available.
  if (v8_flags.debug_code) {
    Label is_baseline, is_unavailable, ok;
    __ mov(ecx, FieldOperand(edi, JSFunction::kSharedFunctionInfoOffset));
    __ Push(eax);
    GetSharedFunctionInfoBytecodeOrBaseline(masm, ecx, ecx, eax, &is_baseline,
                                            &is_unavailable);
    __ Pop(eax);
    __ jmp(&ok);

    __ bind(&is_unavailable);
    __ Abort(AbortReason::kMissingBytecodeArray);

    __ bind(&is_baseline);
    __ Pop(eax);
    __ CmpObjectType(ecx, CODE_TYPE, ecx);
    __ Assert(equal, AbortReason::kMissingBytecodeArray);

    __ bind(&ok);
  }

  // Resume (Ignition/TurboFan) generator object.
  {
    __ PushReturnAddressFrom(eax);
    __ mov(eax, FieldOperand(edi, JSFunction::kSharedFunctionInfoOffset));
    __ movzx_w(eax, FieldOperand(
                        eax, SharedFunctionInfo::kFormalParameterCountOffset));
    // We abuse new.target both to indicate that this is a resume call and to
    // pass in the generator object.  In ordinary calls, new.target is always
    // undefined because generator functions are non-constructable.
    __ JumpJSFunction(edi);
  }

  __ bind(&prepare_step_in_if_stepping);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ Push(edx);
    __ Push(edi);
    // Push hole as receiver since we do not use it for stepping.
    __ PushRoot(RootIndex::kTheHoleValue);
    __ CallRuntime(Runtime::kDebugOnFunctionCall);
    __ Pop(edx);
    __ mov(edi, FieldOperand(edx, JSGeneratorObject::kFunctionOffset));
  }
  __ jmp(&stepping_prepared);

  __ bind(&prepare_step_in_suspended_generator);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ Push(edx);
    __ CallRuntime(Runtime::kDebugPrepareStepInSuspendedGenerator);
    __ Pop(edx);
    __ mov(edi, FieldOperand(edx, JSGeneratorObject::kFunctionOffset));
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
  __ mov(params_size,
         Operand(ebp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ movzx_w(params_size,
             FieldOperand(params_size, BytecodeArray::kParameterSizeOffset));

  Register actual_params_size = scratch2;
  // Compute the size of the actual parameters (in bytes).
  __ mov(actual_params_size, Operand(ebp, StandardFrameConstants::kArgCOffset));

  // If actual is bigger than formal, then we should use it to free up the stack
  // arguments.
  __ cmp(params_size, actual_params_size);
  __ cmov(kLessThan, params_size, actual_params_size);

  // Leave the frame (also dropping the register file).
  __ leave();

  // Drop receiver + arguments.
  __ DropArguments(params_size, scratch2);
}

// Advance the current bytecode offset. This simulates what all bytecode
// handlers do upon completion of the underlying operation. Will bail out to a
// label if the bytecode (without prefix) is a return bytecode. Will not advance
// the bytecode offset if the current bytecode is a JumpLoop, instead just
// re-executing the JumpLoop to jump to the correct bytecode.
static void AdvanceBytecodeOffsetOrReturn(MacroAssembler* masm,
                                          Register bytecode_array,
                                          Register bytecode_offset,
                                          Register scratch1, Register scratch2,
                                          Register scratch3, Label* if_return) {
  ASM_CODE_COMMENT(masm);
  Register bytecode_size_table = scratch1;
  Register bytecode = scratch2;

  // The bytecode offset value will be increased by one in wide and extra wide
  // cases. In the case of having a wide or extra wide JumpLoop bytecode, we
  // will restore the original bytecode. In order to simplify the code, we have
  // a backup of it.
  Register original_bytecode_offset = scratch3;
  DCHECK(!AreAliased(bytecode_array, bytecode_offset, bytecode_size_table,
                     bytecode, original_bytecode_offset));
  __ Move(bytecode_size_table,
          Immediate(ExternalReference::bytecode_size_table_address()));

  // Load the current bytecode.
  __ movzx_b(bytecode, Operand(bytecode_array, bytecode_offset, times_1, 0));
  __ Move(original_bytecode_offset, bytecode_offset);

  // Check if the bytecode is a Wide or ExtraWide prefix bytecode.
  Label process_bytecode, extra_wide;
  static_assert(0 == static_cast<int>(interpreter::Bytecode::kWide));
  static_assert(1 == static_cast<int>(interpreter::Bytecode::kExtraWide));
  static_assert(2 == static_cast<int>(interpreter::Bytecode::kDebugBreakWide));
  static_assert(3 ==
                static_cast<int>(interpreter::Bytecode::kDebugBreakExtraWide));
  __ cmp(bytecode, Immediate(0x3));
  __ j(above, &process_bytecode, Label::kNear);
  // The code to load the next bytecode is common to both wide and extra wide.
  // We can hoist them up here. inc has to happen before test since it
  // modifies the ZF flag.
  __ inc(bytecode_offset);
  __ test(bytecode, Immediate(0x1));
  __ movzx_b(bytecode, Operand(bytecode_array, bytecode_offset, times_1, 0));
  __ j(not_equal, &extra_wide, Label::kNear);

  // Load the next bytecode and update table to the wide scaled table.
  __ add(bytecode_size_table,
         Immediate(kByteSize * interpreter::Bytecodes::kBytecodeCount));
  __ jmp(&process_bytecode, Label::kNear);

  __ bind(&extra_wide);
  // Update table to the extra wide scaled table.
  __ add(bytecode_size_table,
         Immediate(2 * kByteSize * interpreter::Bytecodes::kBytecodeCount));

  __ bind(&process_bytecode);

// Bailout to the return label if this is a return bytecode.
#define JUMP_IF_EQUAL(NAME)                                            \
  __ cmp(bytecode,                                                     \
         Immediate(static_cast<int>(interpreter::Bytecode::k##NAME))); \
  __ j(equal, if_return);
  RETURN_BYTECODE_LIST(JUMP_IF_EQUAL)
#undef JUMP_IF_EQUAL

  // If this is a JumpLoop, re-execute it to perform the jump to the beginning
  // of the loop.
  Label end, not_jump_loop;
  __ cmp(bytecode,
         Immediate(static_cast<int>(interpreter::Bytecode::kJumpLoop)));
  __ j(not_equal, &not_jump_loop, Label::kNear);
  // If this is a wide or extra wide JumpLoop, we need to restore the original
  // bytecode_offset since we might have increased it to skip the wide /
  // extra-wide prefix bytecode.
  __ Move(bytecode_offset, original_bytecode_offset);
  __ jmp(&end, Label::kNear);

  __ bind(&not_jump_loop);
  // Otherwise, load the size of the current bytecode and advance the offset.
  __ movzx_b(bytecode_size_table,
             Operand(bytecode_size_table, bytecode, times_1, 0));
  __ add(bytecode_offset, bytecode_size_table);

  __ bind(&end);
}

namespace {

void ResetSharedFunctionInfoAge(MacroAssembler* masm, Register sfi) {
  __ mov_w(FieldOperand(sfi, SharedFunctionInfo::kAgeOffset), Immediate(0));
}

void ResetJSFunctionAge(MacroAssembler* masm, Register js_function,
                        Register scratch) {
  const Register shared_function_info(scratch);
  __ Move(shared_function_info,
          FieldOperand(js_function, JSFunction::kSharedFunctionInfoOffset));
  ResetSharedFunctionInfoAge(masm, shared_function_info);
}

void ResetFeedbackVectorOsrUrgency(MacroAssembler* masm,
                                   Register feedback_vector, Register scratch) {
  __ mov_b(scratch,
           FieldOperand(feedback_vector, FeedbackVector::kOsrStateOffset));
  __ and_(scratch, Immediate(~FeedbackVector::OsrUrgencyBits::kMask));
  __ mov_b(FieldOperand(feedback_vector, FeedbackVector::kOsrStateOffset),
           scratch);
}

}  // namespace

// Generate code for entering a JS function with the interpreter.
// On entry to the function the receiver and arguments have been pushed on the
// stack left to right.
//
// The live registers are:
//   o eax: actual argument count
//   o edi: the JS function object being called
//   o edx: the incoming new target or generator object
//   o esi: our context
//   o ebp: the caller's frame pointer
//   o esp: stack pointer (pointing to return address)
//
// The function builds an interpreter frame. See InterpreterFrameConstants in
// frame-constants.h for its layout.
void Builtins::Generate_InterpreterEntryTrampoline(
    MacroAssembler* masm, InterpreterEntryTrampolineMode mode) {
  __ movd(xmm0, eax);  // Spill actual argument count.

  __ mov(ecx, FieldOperand(edi, JSFunction::kSharedFunctionInfoOffset));

  // The bytecode array could have been flushed from the shared function info,
  // if so, call into CompileLazy.
  Label is_baseline, compile_lazy;
  GetSharedFunctionInfoBytecodeOrBaseline(masm, ecx, ecx, eax, &is_baseline,
                                          &compile_lazy);

  Label push_stack_frame;
  Register feedback_vector = ecx;
  Register closure = edi;
  Register scratch = eax;
  __ LoadFeedbackVector(feedback_vector, closure, scratch, &push_stack_frame,
                        Label::kNear);

#ifndef V8_JITLESS
  // If feedback vector is valid, check for optimized code and update invocation
  // count. Load the optimization state from the feedback vector and re-use the
  // register.
  Label flags_need_processing;
  Register flags = ecx;
  XMMRegister saved_feedback_vector = xmm1;
  __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
      flags, saved_feedback_vector, CodeKind::INTERPRETED_FUNCTION,
      &flags_need_processing);

  // Reload the feedback vector.
  __ movd(feedback_vector, saved_feedback_vector);

  ResetFeedbackVectorOsrUrgency(masm, feedback_vector, scratch);

  // Increment the invocation count.
  __ inc(FieldOperand(feedback_vector, FeedbackVector::kInvocationCountOffset));

  // Open a frame scope to indicate that there is a frame on the stack.  The
  // MANUAL indicates that the scope shouldn't actually generate code to set
  // up the frame (that is done below).
#else
  // Note: By omitting the above code in jitless mode we also disable:
  // - kFlagsLogNextExecution: only used for logging/profiling; and
  // - kInvocationCountOffset: only used for tiering heuristics and code
  //   coverage.
#endif  // !V8_JITLESS

  __ bind(&push_stack_frame);
  FrameScope frame_scope(masm, StackFrame::MANUAL);
  __ push(ebp);  // Caller's frame pointer.
  __ mov(ebp, esp);
  __ push(kContextRegister);               // Callee's context.
  __ push(kJavaScriptCallTargetRegister);  // Callee's JS function.
  __ movd(kJavaScriptCallArgCountRegister, xmm0);
  __ push(kJavaScriptCallArgCountRegister);  // Actual argument count.

  // Get the bytecode array from the function object and load it into
  // kInterpreterBytecodeArrayRegister.
  __ mov(eax, FieldOperand(edi, JSFunction::kSharedFunctionInfoOffset));
  ResetSharedFunctionInfoAge(masm, eax);
  __ mov(kInterpreterBytecodeArrayRegister,
         FieldOperand(eax, SharedFunctionInfo::kTrustedFunctionDataOffset));
  GetSharedFunctionInfoBytecode(masm, kInterpreterBytecodeArrayRegister, eax);

  // Check function data field is actually a BytecodeArray object.
  if (v8_flags.debug_code) {
    __ AssertNotSmi(kInterpreterBytecodeArrayRegister);
    __ CmpObjectType(kInterpreterBytecodeArrayRegister, BYTECODE_ARRAY_TYPE,
                     eax);
    __ Assert(
        equal,
        AbortReason::kFunctionDataShouldBeBytecodeArrayOnInterpreterEntry);
  }

  // Push bytecode array.
  __ push(kInterpreterBytecodeArrayRegister);
  // Push Smi tagged initial bytecode array offset.
  __ push(Immediate(Smi::FromInt(BytecodeArray::kHeaderSize - kHeapObjectTag)));
  __ push(feedback_vector);

  // Allocate the local and temporary register file on the stack.
  Label stack_overflow;
  {
    // Load frame size from the BytecodeArray object.
    Register frame_size = ecx;
    __ mov(frame_size, FieldOperand(kInterpreterBytecodeArrayRegister,
                                    BytecodeArray::kFrameSizeOffset));

    // Do a stack check to ensure we don't go over the limit.
    __ mov(eax, esp);
    __ sub(eax, frame_size);
    __ CompareStackLimit(eax, StackLimitKind::kRealStackLimit);
    __ j(below, &stack_overflow);

    // If ok, push undefined as the initial value for all register file entries.
    Label loop_header;
    Label loop_check;
    __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
    __ jmp(&loop_check);
    __ bind(&loop_header);
    // TODO(rmcilroy): Consider doing more than one push per loop iteration.
    __ push(kInterpreterAccumulatorRegister);
    // Continue loop if not done.
    __ bind(&loop_check);
    __ sub(frame_size, Immediate(kSystemPointerSize));
    __ j(greater_equal, &loop_header);
  }

  // If the bytecode array has a valid incoming new target or generator object
  // register, initialize it with incoming value which was passed in edx.
  Label no_incoming_new_target_or_generator_register;
  __ mov(ecx, FieldOperand(
                  kInterpreterBytecodeArrayRegister,
                  BytecodeArray::kIncomingNewTargetOrGeneratorRegisterOffset));
  __ test(ecx, ecx);
  __ j(zero, &no_incoming_new_target_or_generator_register);
  __ mov(Operand(ebp, ecx, times_system_pointer_size, 0), edx);
  __ bind(&no_incoming_new_target_or_generator_register);

  // Perform interrupt stack check.
  // TODO(solanes): Merge with the real stack limit check above.
  Label stack_check_interrupt, after_stack_check_interrupt;
  __ CompareStackLimit(esp, StackLimitKind::kInterruptStackLimit);
  __ j(below, &stack_check_interrupt);
  __ bind(&after_stack_check_interrupt);

  // The accumulator is already loaded with undefined.

  __ mov(kInterpreterBytecodeOffsetRegister,
         Immediate(BytecodeArray::kHeaderSize - kHeapObjectTag));

  // Load the dispatch table into a register and dispatch to the bytecode
  // handler at the current bytecode offset.
  Label do_dispatch;
  __ bind(&do_dispatch);
  __ Move(kInterpreterDispatchTableRegister,
          Immediate(ExternalReference::interpreter_dispatch_table_address(
              masm->isolate())));
  __ movzx_b(ecx, Operand(kInterpreterBytecodeArrayRegister,
                          kInterpreterBytecodeOffsetRegister, times_1, 0));
  __ mov(kJavaScriptCallCodeStartRegister,
         Operand(kInterpreterDispatchTableRegister, ecx,
                 times_system_pointer_size, 0));
  __ call(kJavaScriptCallCodeStartRegister);

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
  __ mov(kInterpreterBytecodeArrayRegister,
         Operand(ebp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ mov(kInterpreterBytecodeOffsetRegister,
         Operand(ebp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ SmiUntag(kInterpreterBytecodeOffsetRegister);

  // Either return, or advance to the next bytecode and dispatch.
  Label do_return;
  __ Push(eax);
  AdvanceBytecodeOffsetOrReturn(masm, kInterpreterBytecodeArrayRegister,
                                kInterpreterBytecodeOffsetRegister, ecx,
                                kInterpreterDispatchTableRegister, eax,
                                &do_return);
  __ Pop(eax);
  __ jmp(&do_dispatch);

  __ bind(&do_return);
  __ Pop(eax);
  // The return value is in eax.
  LeaveInterpreterFrame(masm, edx, ecx);
  __ ret(0);

  __ bind(&stack_check_interrupt);
  // Modify the bytecode offset in the stack to be kFunctionEntryBytecodeOffset
  // for the call to the StackGuard.
  __ mov(Operand(ebp, InterpreterFrameConstants::kBytecodeOffsetFromFp),
         Immediate(Smi::FromInt(BytecodeArray::kHeaderSize - kHeapObjectTag +
                                kFunctionEntryBytecodeOffset)));
  __ CallRuntime(Runtime::kStackGuard);

  // After the call, restore the bytecode array, bytecode offset and accumulator
  // registers again. Also, restore the bytecode offset in the stack to its
  // previous value.
  __ mov(kInterpreterBytecodeArrayRegister,
         Operand(ebp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ mov(kInterpreterBytecodeOffsetRegister,
         Immediate(BytecodeArray::kHeaderSize - kHeapObjectTag));
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);

  // It's ok to clobber kInterpreterBytecodeOffsetRegister since we are setting
  // it again after continuing.
  __ SmiTag(kInterpreterBytecodeOffsetRegister);
  __ mov(Operand(ebp, InterpreterFrameConstants::kBytecodeOffsetFromFp),
         kInterpreterBytecodeOffsetRegister);

  __ jmp(&after_stack_check_interrupt);

#ifndef V8_JITLESS
  __ bind(&flags_need_processing);
  {
    // Restore actual argument count.
    __ movd(eax, xmm0);
    __ OptimizeCodeOrTailCallOptimizedCodeSlot(flags, xmm1);
  }

  __ bind(&compile_lazy);
  // Restore actual argument count.
  __ movd(eax, xmm0);
  __ GenerateTailCallToReturnedCode(Runtime::kCompileLazy);

  __ bind(&is_baseline);
  {
    __ movd(xmm2, ecx);  // Save baseline data.
    // Load the feedback vector from the closure.
    __ mov(feedback_vector,
           FieldOperand(closure, JSFunction::kFeedbackCellOffset));
    __ mov(feedback_vector,
           FieldOperand(feedback_vector, FeedbackCell::kValueOffset));

    Label install_baseline_code;
    // Check if feedback vector is valid. If not, call prepare for baseline to
    // allocate it.
    __ LoadMap(eax, feedback_vector);
    __ CmpInstanceType(eax, FEEDBACK_VECTOR_TYPE);
    __ j(not_equal, &install_baseline_code);

    // Check the tiering state.
    __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
        flags, xmm1, CodeKind::BASELINE, &flags_need_processing);

    // Load the baseline code into the closure.
    __ movd(ecx, xmm2);
    static_assert(kJavaScriptCallCodeStartRegister == ecx, "ABI mismatch");
    __ push(edx);  // Spill.
    __ push(ecx);
    __ Push(xmm0, eax);  // Save the argument count (currently in xmm0).
    __ ReplaceClosureCodeWithOptimizedCode(ecx, closure, eax, ecx);
    __ pop(eax);  // Restore the argument count.
    __ pop(ecx);
    __ pop(edx);
    __ JumpCodeObject(ecx);

    __ bind(&install_baseline_code);
    __ movd(eax, xmm0);  // Recover argument count.
    __ GenerateTailCallToReturnedCode(Runtime::kInstallBaselineCode);
  }
#endif  // !V8_JITLESS

  __ bind(&stack_overflow);
  __ CallRuntime(Runtime::kThrowStackOverflow);
  __ int3();  // Should not return.
}

static void GenerateInterpreterPushArgs(MacroAssembler* masm,
                                        Register array_limit,
                                        Register start_address) {
  // ----------- S t a t e -------------
  //  -- start_address : Pointer to the last argument in the args array.
  //  -- array_limit : Pointer to one before the first argument in the
  //                   args array.
  // -----------------------------------
  ASM_CODE_COMMENT(masm);
  Label loop_header, loop_check;
  __ jmp(&loop_check);
  __ bind(&loop_header);
  __ Push(Operand(array_limit, 0));
  __ bind(&loop_check);
  __ add(array_limit, Immediate(kSystemPointerSize));
  __ cmp(array_limit, start_address);
  __ j(below_equal, &loop_header, Label::kNear);
}

// static
void Builtins::Generate_InterpreterPushArgsThenCallImpl(
    MacroAssembler* masm, ConvertReceiverMode receiver_mode,
    InterpreterPushArgsMode mode) {
  DCHECK(mode != InterpreterPushArgsMode::kArrayFunction);
  // ----------- S t a t e -------------
  //  -- eax : the number of arguments
  //  -- ecx : the address of the first argument to be pushed. Subsequent
  //           arguments should be consecutive above this, in the same order as
  //           they are to be pushed onto the stack.
  //  -- edi : the target to call (can be any Object).
  // -----------------------------------

  const Register scratch = edx;
  const Register argv = ecx;

  Label stack_overflow;
  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // The spread argument should not be pushed.
    __ dec(eax);
  }

  // Add a stack check before pushing the arguments.
  __ StackOverflowCheck(eax, scratch, &stack_overflow, true);
  __ movd(xmm0, eax);  // Spill number of arguments.

  // Compute the expected number of arguments.
  __ mov(scratch, eax);
  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    __ dec(scratch);  // Exclude receiver.
  }

  // Pop return address to allow tail-call after pushing arguments.
  __ PopReturnAddressTo(eax);

  // Find the address of the last argument.
  __ shl(scratch, kSystemPointerSizeLog2);
  __ neg(scratch);
  __ add(scratch, argv);

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    __ movd(xmm1, scratch);
    GenerateInterpreterPushArgs(masm, scratch, argv);
    // Pass the spread in the register ecx.
    __ movd(ecx, xmm1);
    __ mov(ecx, Operand(ecx, 0));
  } else {
    GenerateInterpreterPushArgs(masm, scratch, argv);
  }

  // Push "undefined" as the receiver arg if we need to.
  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    __ PushRoot(RootIndex::kUndefinedValue);
  }

  __ PushReturnAddressFrom(eax);
  __ movd(eax, xmm0);  // Restore number of arguments.

  // Call the target.
  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    __ TailCallBuiltin(Builtin::kCallWithSpread);
  } else {
    __ TailCallBuiltin(Builtins::Call(receiver_mode));
  }

  __ bind(&stack_overflow);
  {
    __ TailCallRuntime(Runtime::kThrowStackOverflow);

    // This should be unreachable.
    __ int3();
  }
}

namespace {

// This function modifies start_addr, and only reads the contents of num_args
// register. scratch1 and scratch2 are used as temporary registers.
void Generate_InterpreterPushZeroAndArgsAndReturnAddress(
    MacroAssembler* masm, Register num_args, Register start_addr,
    Register scratch1, Register scratch2, int num_slots_to_move,
    Label* stack_overflow) {
  // We have to move return address and the temporary registers above it
  // before we can copy arguments onto the stack. To achieve this:
  // Step 1: Increment the stack pointer by num_args + 1 for receiver (if it is
  // not included in argc already). Step 2: Move the return address and values
  // around it to the top of stack. Step 3: Copy the arguments into the correct
  // locations.
  //  current stack    =====>    required stack layout
  // |             |            | return addr   | (2) <-- esp (1)
  // |             |            | addtl. slot   |
  // |             |            | arg N         | (3)
  // |             |            | ....          |
  // |             |            | arg 1         |
  // | return addr | <-- esp    | arg 0         |
  // | addtl. slot |            | receiver slot |

  // Check for stack overflow before we increment the stack pointer.
  __ StackOverflowCheck(num_args, scratch1, stack_overflow, true);

  // Step 1 - Update the stack pointer.

  __ lea(scratch1, Operand(num_args, times_system_pointer_size, 0));
  __ AllocateStackSpace(scratch1);

  // Step 2 move return_address and slots around it to the correct locations.
  // Move from top to bottom, otherwise we may overwrite when num_args = 0 or 1,
  // basically when the source and destination overlap. We at least need one
  // extra slot for receiver, so no extra checks are required to avoid copy.
  for (int i = 0; i < num_slots_to_move + 1; i++) {
    __ mov(scratch1, Operand(esp, num_args, times_system_pointer_size,
                             i * kSystemPointerSize));
    __ mov(Operand(esp, i * kSystemPointerSize), scratch1);
  }

  // Step 3 copy arguments to correct locations.
  // Slot meant for receiver contains return address. Reset it so that
  // we will not incorrectly interpret return address as an object.
  __ mov(Operand(esp, (num_slots_to_move + 1) * kSystemPointerSize),
         Immediate(0));
  __ mov(scratch1, Immediate(0));

  Label loop_header, loop_check;
  __ jmp(&loop_check);
  __ bind(&loop_header);
  __ mov(scratch2, Operand(start_addr, 0));
  __ mov(Operand(esp, scratch1, times_system_pointer_size,
                 (num_slots_to_move + 1) * kSystemPointerSize),
         scratch2);
  __ sub(start_addr, Immediate(kSystemPointerSize));
  __ bind(&loop_check);
  __ inc(scratch1);
  __ cmp(scratch1, eax);
  __ j(less, &loop_header, Label::kNear);
}

}  // anonymous namespace

// static
void Builtins::Generate_InterpreterPushArgsThenConstructImpl(
    MacroAssembler* masm, InterpreterPushArgsMode mode) {
  // ----------- S t a t e -------------
  //  -- eax     : the number of arguments
  //  -- ecx     : the address of the first argument to be pushed. Subsequent
  //               arguments should be consecutive above this, in the same order
  //               as they are to be pushed onto the stack.
  //  -- esp[0]  : return address
  //  -- esp[4]  : allocation site feedback (if available or undefined)
  //  -- esp[8]  : the new target
  //  -- esp[12] : the constructor
  // -----------------------------------
  Label stack_overflow;

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // The spread argument should not be pushed.
    __ dec(eax);
  }

  // Push arguments and move return address and stack spill slots to the top of
  // stack. The eax register is readonly. The ecx register will be modified. edx
  // and edi are used as scratch registers.
  Generate_InterpreterPushZeroAndArgsAndReturnAddress(
      masm, eax, ecx, edx, edi,
      InterpreterPushArgsThenConstructDescriptor::GetStackParameterCount(),
      &stack_overflow);

  // Call the appropriate constructor. eax and ecx already contain intended
  // values, remaining registers still need to be initialized from the stack.

  if (mode == InterpreterPushArgsMode::kArrayFunction) {
    // Tail call to the array construct stub (still in the caller context at
    // this point).

    __ movd(xmm0, eax);  // Spill number of arguments.
    __ PopReturnAddressTo(eax);
    __ Pop(kJavaScriptCallExtraArg1Register);
    __ Pop(kJavaScriptCallNewTargetRegister);
    __ Pop(kJavaScriptCallTargetRegister);
    __ PushReturnAddressFrom(eax);

    __ AssertFunction(kJavaScriptCallTargetRegister, eax);
    __ AssertUndefinedOrAllocationSite(kJavaScriptCallExtraArg1Register, eax);

    __ movd(eax, xmm0);  // Reload number of arguments.
    __ TailCallBuiltin(Builtin::kArrayConstructorImpl);
  } else if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    __ movd(xmm0, eax);  // Spill number of arguments.
    __ PopReturnAddressTo(eax);
    __ Drop(1);  // The allocation site is unused.
    __ Pop(kJavaScriptCallNewTargetRegister);
    __ Pop(kJavaScriptCallTargetRegister);
    // Pass the spread in the register ecx, overwriting ecx.
    __ mov(ecx, Operand(ecx, 0));
    __ PushReturnAddressFrom(eax);
    __ movd(eax, xmm0);  // Reload number of arguments.
    __ TailCallBuiltin(Builtin::kConstructWithSpread);
  } else {
    DCHECK_EQ(InterpreterPushArgsMode::kOther, mode);
    __ PopReturnAddressTo(ecx);
    __ Drop(1);  // The allocation site is unused.
    __ Pop(kJavaScriptCallNewTargetRegister);
    __ Pop(kJavaScriptCallTargetRegister);
    __ PushReturnAddressFrom(ecx);

    __ TailCallBuiltin(Builtin::kConstruct);
  }

  __ bind(&stack_overflow);
  __ TailCallRuntime(Runtime::kThrowStackOverflow);
  __ int3();
}

namespace {
void LoadFramePointer(MacroAssembler* masm, Register to,
                      Builtins::ForwardWhichFrame which_frame) {
  switch (which_frame) {
    case Builtins::ForwardWhichFrame::kCurrentFrame:
      __ mov(to, ebp);
      break;
    case Builtins::ForwardWhichFrame::kParentFrame:
      __ mov(to, Operand(ebp, StandardFrameConstants::kCallerFPOffset));
      break;
  }
}
}  // namespace

// static
void Builtins::Generate_ConstructForwardAllArgsImpl(
    MacroAssembler* masm, ForwardWhichFrame which_frame) {
  // ----------- S t a t e -------------
  //  -- edx     : the new target
  //  -- edi     : the constructor
  //  -- esp[0]  : return address
  // -----------------------------------
  Label stack_overflow;

  // Load the frame into ecx.
  LoadFramePointer(masm, ecx, which_frame);

  // Load the argument count into eax.
  __ mov(eax, Operand(ecx, StandardFrameConstants::kArgCOffset));

  // The following stack surgery is performed to forward arguments from the
  // interpreted frame.
  //
  //  current stack    =====>    required stack layout
  // |             |            | saved new target  | (2)
  // |             |            | saved constructor | (2)
  // |             |            | return addr       | (3) <-- esp (1)
  // |             |            | arg N             | (5)
  // |             |            | ....              | (5)
  // |             |            | arg 0             | (5)
  // | return addr | <-- esp    | 0 (receiver)      | (4)
  //
  // The saved new target and constructor are popped to their respective
  // registers before calling the Construct builtin.

  // Step 1
  //
  // Update the stack pointer, using ecx as a scratch register.
  __ StackOverflowCheck(eax, ecx, &stack_overflow, true);
  __ lea(ecx, Operand(eax, times_system_pointer_size, 0));
  __ AllocateStackSpace(ecx);

  // Step 2
  //
  // Save the new target and constructor on the stack so they can be used as
  // scratch registers.
  __ Push(edi);
  __ Push(edx);

  // Step 3
  //
  // Move the return address. Stack address computations have to be offset by
  // the saved constructor and new target on the stack.
  constexpr int spilledConstructorAndNewTargetOffset = 2 * kSystemPointerSize;
  __ mov(edx, Operand(esp, eax, times_system_pointer_size,
                      spilledConstructorAndNewTargetOffset));
  __ mov(Operand(esp, spilledConstructorAndNewTargetOffset), edx);

  // Step 4
  // Push a 0 for the receiver to be allocated.
  __ mov(
      Operand(esp, kSystemPointerSize + spilledConstructorAndNewTargetOffset),
      Immediate(0));

  // Step 5
  //
  // Forward the arguments from the frame.

  // First reload the frame pointer into ecx.
  LoadFramePointer(masm, ecx, which_frame);

  // Point ecx to the base of the arguments, excluding the receiver.
  __ add(ecx, Immediate((StandardFrameConstants::kFixedSlotCountAboveFp + 1) *
                        kSystemPointerSize));
  {
    // Copy the arguments.
    Register counter = edx;
    Register scratch = edi;

    Label loop, entry;
    __ mov(counter, eax);
    __ jmp(&entry);
    __ bind(&loop);
    // The source frame's argument is offset by -kSystemPointerSize because the
    // counter with an argument count inclusive of the receiver.
    __ mov(scratch, Operand(ecx, counter, times_system_pointer_size,
                            -kSystemPointerSize));
    // Similarly, the target frame's argument is offset by +kSystemPointerSize
    // because we pushed a 0 for the receiver to be allocated.
    __ mov(Operand(esp, counter, times_system_pointer_size,
                   kSystemPointerSize + spilledConstructorAndNewTargetOffset),
           scratch);
    __ bind(&entry);
    __ dec(counter);
    __ j(greater_equal, &loop, Label::kNear);
  }

  // Pop the saved constructor and new target, then call the appropriate
  // constructor. eax already contains the argument count.
  __ Pop(kJavaScriptCallNewTargetRegister);
  __ Pop(kJavaScriptCallTargetRegister);
  __ TailCallBuiltin(Builtin::kConstruct);

  __ bind(&stack_overflow);
  {
    __ TailCallRuntime(Runtime::kThrowStackOverflow);
    __ int3();
  }
}

namespace {

void NewImplicitReceiver(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  // -- eax : argument count
  // -- edi : constructor to call
  // -- edx : new target (checked to be a JSFunction)
  //
  //  Stack:
  //  -- Implicit Receiver
  //  -- [arguments without receiver]
  //  -- Implicit Receiver
  //  -- Context
  //  -- FastConstructMarker
  //  -- FramePointer

  Register implicit_receiver = ecx;

  // Save live registers.
  __ SmiTag(eax);
  __ Push(eax);  // Number of arguments
  __ Push(edx);  // NewTarget
  __ Push(edi);  // Target
  __ CallBuiltin(Builtin::kFastNewObject);
  // Save result.
  __ mov(implicit_receiver, eax);
  // Restore live registers.
  __ Pop(edi);
  __ Pop(edx);
  __ Pop(eax);
  __ SmiUntag(eax);

  // Patch implicit receiver (in arguments)
  __ mov(Operand(esp, 0 /* first argument */), implicit_receiver);
  // Patch second implicit (in construct frame)
  __ mov(Operand(ebp, FastConstructFrameConstants::kImplicitReceiverOffset),
         implicit_receiver);

  // Restore context.
  __ mov(esi, Operand(ebp, FastConstructFrameConstants::kContextOffset));
}

}  // namespace

// static
void Builtins::Generate_InterpreterPushArgsThenFastConstructFunction(
    MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- eax     : the number of arguments
  //  -- ecx     : the address of the first argument to be pushed. Subsequent
  //               arguments should be consecutive above this, in the same order
  //               as they are to be pushed onto the stack.
  //  -- esi     : the context
  //  -- esp[0]  : return address
  //  -- esp[4]  : allocation site feedback (if available or undefined)
  //  -- esp[8]  : the new target
  //  -- esp[12] : the constructor (checked to be a JSFunction)
  // -----------------------------------

  // Load constructor.
  __ mov(edi, Operand(esp, 3 * kSystemPointerSize));
  __ AssertFunction(edi, edx);

  // Check if target has a [[Construct]] internal method.
  Label non_constructor;
  // Load constructor.
  __ LoadMap(edx, edi);
  __ test_b(FieldOperand(edx, Map::kBitFieldOffset),
            Immediate(Map::Bits1::IsConstructorBit::kMask));
  __ j(zero, &non_constructor);

  // Add a stack check before pushing arguments.
  Label stack_overflow;
  __ StackOverflowCheck(eax, edx, &stack_overflow, true);

  // Spill number of arguments.
  __ movd(xmm0, eax);

  // Load NewTarget.
  __ mov(edx, Operand(esp, 2 * kSystemPointerSize));

  // Drop stub arguments from the stack.
  __ PopReturnAddressTo(eax);
  __ Drop(3);  // The allocation site is unused.
  __ PushReturnAddressFrom(eax);

  // Enter a construct frame.
  FrameScope scope(masm, StackFrame::MANUAL);
  __ EnterFrame(StackFrame::FAST_CONSTRUCT);
  __ Push(esi);
  // Implicit receiver stored in the construct frame.
  __ PushRoot(RootIndex::kTheHoleValue);

  // Push arguments + implicit receiver
  __ movd(eax, xmm0);  // Recover number of arguments.
  // Find the address of the last argument.
  __ lea(esi, Operand(eax, times_system_pointer_size,
                      -kJSArgcReceiverSlots * kSystemPointerSize));
  __ neg(esi);
  __ add(esi, ecx);
  GenerateInterpreterPushArgs(masm, esi, ecx);
  __ PushRoot(RootIndex::kTheHoleValue);

  // Restore context.
  __ mov(esi, Operand(ebp, FastConstructFrameConstants::kContextOffset));

  // Check if it is a builtin call.
  Label builtin_call;
  __ mov(ecx, FieldOperand(edi, JSFunction::kSharedFunctionInfoOffset));
  __ test(FieldOperand(ecx, SharedFunctionInfo::kFlagsOffset),
          Immediate(SharedFunctionInfo::ConstructAsBuiltinBit::kMask));
  __ j(not_zero, &builtin_call);

  // Check if we need to create an implicit receiver.
  Label not_create_implicit_receiver;
  __ mov(ecx, FieldOperand(ecx, SharedFunctionInfo::kFlagsOffset));
  __ DecodeField<SharedFunctionInfo::FunctionKindBits>(ecx);
  __ JumpIfIsInRange(
      ecx, static_cast<uint32_t>(FunctionKind::kDefaultDerivedConstructor),
      static_cast<uint32_t>(FunctionKind::kDerivedConstructor), ecx,
      &not_create_implicit_receiver, Label::kNear);
  NewImplicitReceiver(masm);
  __ bind(&not_create_implicit_receiver);

  // Call the constructor.
  __ InvokeFunction(edi, edx, eax, InvokeType::kCall);

  // ----------- S t a t e -------------
  //  -- eax     constructor result
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

  Label check_result, use_receiver, do_throw, leave_and_return;
  // If the result is undefined, we jump out to using the implicit receiver.
  __ JumpIfNotRoot(eax, RootIndex::kUndefinedValue, &check_result,
                   Label::kNear);

  // Throw away the result of the constructor invocation and use the
  // on-stack receiver as the result.
  __ bind(&use_receiver);
  __ mov(eax, Operand(esp, 0 * kSystemPointerSize));
  __ JumpIfRoot(eax, RootIndex::kTheHoleValue, &do_throw);

  __ bind(&leave_and_return);
  __ LeaveFrame(StackFrame::FAST_CONSTRUCT);
  __ ret(0);

  // Otherwise we do a smi check and fall through to check if the return value
  // is a valid receiver.
  __ bind(&check_result);

  // If the result is a smi, it is *not* an object in the ECMA sense.
  __ JumpIfSmi(eax, &use_receiver, Label::kNear);

  // If the type of the result (stored in its map) is less than
  // FIRST_JS_RECEIVER_TYPE, it is not an object in the ECMA sense.
  static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
  __ CmpObjectType(eax, FIRST_JS_RECEIVER_TYPE, ecx);
  __ j(above_equal, &leave_and_return, Label::kNear);
  __ jmp(&use_receiver, Label::kNear);

  __ bind(&do_throw);
  // Restore context from the frame.
  __ mov(esi, Operand(ebp, ConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowConstructorReturnedNonObject);
  // This should be unreachable.
  __ int3();

  __ bind(&builtin_call);
  __ InvokeFunction(edi, edx, eax, InvokeType::kCall);
  __ LeaveFrame(StackFrame::FAST_CONSTRUCT);
  __ ret(0);

  // Called Construct on an Object that doesn't have a [[Construct]] internal
  // method.
  __ bind(&non_constructor);
  __ TailCallBuiltin(Builtin::kConstructedNonConstructable);

  // Throw stack overflow exception.
  __ bind(&stack_overflow);
  __ TailCallRuntime(Runtime::kThrowStackOverflow);
  // This should be unreachable.
  __ int3();
}

static void Generate_InterpreterEnterBytecode(MacroAssembler* masm) {
  // Set the return address to the correct point in the interpreter entry
  // trampoline.
  Label builtin_trampoline, trampoline_loaded;
  Tagged<Smi> interpreter_entry_return_pc_offset(
      masm->isolate()->heap()->interpreter_entry_return_pc_offset());
  DCHECK_NE(interpreter_entry_return_pc_offset, Smi::zero());

  static constexpr Register scratch = ecx;

  // If the SFI function_data is an InterpreterData, the function will have a
  // custom copy of the interpreter entry trampoline for profiling. If so,
  // get the custom trampoline, otherwise grab the entry address of the global
  // trampoline.
  __ mov(scratch, Operand(ebp, StandardFrameConstants::kFunctionOffset));
  __ mov(scratch, FieldOperand(scratch, JSFunction::kSharedFunctionInfoOffset));
  __ mov(scratch,
         FieldOperand(scratch, SharedFunctionInfo::kTrustedFunctionDataOffset));
  __ Push(eax);
  __ CmpObjectType(scratch, INTERPRETER_DATA_TYPE, eax);
  __ j(not_equal, &builtin_trampoline, Label::kNear);

  __ mov(scratch,
         FieldOperand(scratch, InterpreterData::kInterpreterTrampolineOffset));
  __ LoadCodeInstructionStart(scratch, scratch);
  __ jmp(&trampoline_loaded, Label::kNear);

  __ bind(&builtin_trampoline);
  __ mov(scratch,
         __ ExternalReferenceAsOperand(
             ExternalReference::
                 address_of_interpreter_entry_trampoline_instruction_start(
                     masm->isolate()),
             scratch));

  __ bind(&trampoline_loaded);
  __ Pop(eax);
  __ add(scratch, Immediate(interpreter_entry_return_pc_offset.value()));
  __ push(scratch);

  // Initialize the dispatch
```