Response:
The user wants a summary of the provided C++ code snippet, which is part of the V8 JavaScript engine. I need to analyze the code and identify its main functionalities.

Here's a breakdown of the code's functionalities:

1. **Architecture-Specific Builtins:** The code is located in `v8/src/builtins/x64/builtins-x64.cc`, indicating it contains architecture-specific (x64) implementations of built-in JavaScript functions.
2. **Adaptor Functions:**  The `Generate_Adaptor` function suggests it's involved in adapting or wrapping function calls, likely bridging between different calling conventions or levels of the V8 engine.
3. **Argument Handling:**  Functions like `Generate_PushArguments` indicate logic for managing and manipulating arguments passed to functions.
4. **Constructor Stubs:** The `Generate_JSBuiltinsConstructStubHelper` and `Generate_JSConstructStubGeneric` functions are related to the execution of JavaScript constructors, including object creation and method invocation.
5. **Deoptimization Support:**  The `Generate_CallToAdaptShadowStackForDeopt` function points to mechanisms for handling deoptimization, a process where optimized code falls back to a less optimized version.
6. **JSEntry Points:** The `Generate_JSEntryVariant`, `Generate_JSEntry`, `Generate_JSConstructEntry`, and `Generate_JSRunMicrotasksEntry` functions are crucial entry points for executing JavaScript code within the V8 engine. They handle setting up the execution environment, managing stack frames, and handling exceptions.
7. **Trampolines:** The `Generate_JSEntryTrampoline`, `Generate_JSConstructEntryTrampoline`, and `Generate_RunMicrotasksTrampoline` functions act as intermediate steps, routing control flow to the actual built-in implementations.
8. **Baseline Code Handling:** Functions like `AssertCodeIsBaseline`, `CheckSharedFunctionInfoBytecodeOrBaseline`, and `GetSharedFunctionInfoBytecodeOrBaseline` deal with identifying and accessing baseline (less optimized) code for functions.
9. **Generator Function Resumption:** The `Generate_ResumeGeneratorTrampoline` function is responsible for resuming the execution of JavaScript generator functions.

Based on this analysis, I can summarize the functionality of this code snippet.
```javascript
// 假设我们有一个简单的 JavaScript 函数
function add(a, b) {
  return a + b;
}

// 当我们调用这个函数时，V8 引擎会执行相应的 built-in 代码来处理函数调用。
let result = add(5, 3);
console.log(result); // 输出 8

// 对于构造函数，例如：
function MyClass(value) {
  this.value = value;
}

let instance = new MyClass(10);
console.log(instance.value); // 输出 10

// V8 会调用特定的 built-in 代码来处理 `new` 关键字，
// 包括创建新对象，设置原型链，并调用构造函数。
```

根据提供的 V8 源代码 `v8/src/builtins/x64/builtins-x64.cc` 的第 1 部分，其主要功能可以归纳如下：

1. **提供 x64 架构特定的内置函数实现:**  这个文件专门为 x64 架构提供了 V8 引擎内置函数的底层实现。这意味着它包含了用汇编语言或其他底层技术编写的代码，用于执行诸如函数调用、对象构造等核心 JavaScript 操作。

2. **定义了多种调用适配器 (`Generate_Adaptor`):**  `Generate_Adaptor` 函数用于生成适配器代码，这可能用于在不同调用约定或执行上下文之间进行桥接。例如，当从外部 C++ 代码调用 JavaScript 函数时，或者在不同的 V8 内部调用机制之间进行转换时。

3. **实现了参数压栈 (`Generate_PushArguments`):**  `Generate_PushArguments` 函数负责将函数参数压入栈中，这是函数调用过程中的一个关键步骤。它处理了不同类型的参数，包括原始值和句柄。

4. **提供了 JavaScript 构造函数的桩代码 (`Generate_JSBuiltinsConstructStubHelper`, `Generate_JSConstructStubGeneric`):**  这些函数实现了 JavaScript 构造函数的调用逻辑。它们负责创建新的对象实例，设置原型链，并调用构造函数本身。`Generate_JSConstructStubGeneric` 还处理了派生类构造函数的特殊情况。

5. **支持去优化 (`Generate_CallToAdaptShadowStackForDeopt`):**  `Generate_CallToAdaptShadowStackForDeopt` 函数与 V8 的去优化机制相关。当优化的代码不再有效时（例如，由于类型发生了变化），V8 需要回退到非优化的代码。这个函数确保在去优化过程中，硬件影子栈的状态是正确的。

6. **定义了 JavaScript 代码的入口点 (`Generate_JSEntryVariant`, `Generate_JSEntry`, `Generate_JSConstructEntry`, `Generate_JSRunMicrotasksEntry`):**  这些函数是执行 JavaScript 代码的入口点。它们负责设置执行环境，包括创建栈帧、保存寄存器、处理异常等。`Generate_JSEntry` 用于普通的函数调用，`Generate_JSConstructEntry` 用于构造函数调用，`Generate_JSRunMicrotasksEntry` 用于执行微任务。

7. **实现了 JavaScript 调用和构造的跳转桩 (`Generate_JSEntryTrampoline`, `Generate_JSConstructEntryTrampoline`):** 这些函数作为跳转桩，用于在 C++ 代码调用 JavaScript 代码时进行初步的处理和环境设置，然后跳转到实际的内置函数实现。

8. **处理 Baseline 代码 (`AssertCodeIsBaseline`, `CheckSharedFunctionInfoBytecodeOrBaseline`, `GetSharedFunctionInfoBytecodeOrBaseline`):** 这部分代码涉及到 V8 的分层编译机制。Baseline 代码是一种相对快速但未完全优化的代码。这些函数用于检查和获取函数的 Baseline 代码或字节码。

9. **实现了生成器函数的恢复 (`Generate_ResumeGeneratorTrampoline`):**  这个函数负责在 JavaScript 生成器函数暂停后恢复其执行。它处理了输入值的传递、上下文的恢复以及栈的调整。

**假设输入与输出（`Generate_PushArguments`）:**

假设有一个 JavaScript 函数调用 `foo(1, 'hello', {a: 1})`。当 V8 执行这个调用时，`Generate_PushArguments` 可能会被调用来将参数压入栈。

*   **假设输入:**
    *   `array` 寄存器指向包含参数的数组（例如，一个存储了 `1` 的 Smi，`'hello'` 的 HeapObject，以及 `{a: 1}` 的 HeapObject 的数组）。
    *   `argc` 寄存器包含参数的数量，这里是 3。
    *   `scratch` 寄存器可用作临时寄存器。
    *   `element_type` 为 `ArgumentsElementType::kRaw`（假设我们直接推送参数值）。

*   **预期输出:**
    栈顶会依次压入：`{a: 1}` 的指针, `'hello'` 的指针, `1` 的 Smi 值。栈指针 `rsp` 会相应地向下移动。

**用户常见的编程错误 (与构造函数相关):**

一个常见的错误是在没有使用 `new` 关键字的情况下调用构造函数：

```javascript
function Person(name) {
  this.name = name;
}

// 错误地调用构造函数
let person = Person("Alice");
console.log(person); // 输出 undefined，因为 this 指向了全局对象（在非严格模式下）
console.log(window.name); // 输出 "Alice" (非严格模式下)

// 正确的调用方式
let correctPerson = new Person("Bob");
console.log(correctPerson.name); // 输出 "Bob"
```

在这个例子中，`Generate_JSConstructStubGeneric` 负责处理 `new` 关键字的调用，确保正确创建对象实例。如果用户忘记使用 `new`，`this` 的指向会出错，导致意想不到的结果。V8 的 built-in 代码会针对这些情况进行处理，但错误的用法仍然会导致逻辑错误。

总结来说，`v8/src/builtins/x64/builtins-x64.cc` 的第一部分定义了 x64 架构下 V8 引擎中一些核心的内置函数实现，涵盖了函数调用、对象构造、去优化支持、JavaScript 代码入口、Baseline 代码处理以及生成器函数的恢复等关键功能。这些底层实现对于 V8 引擎执行 JavaScript 代码至关重要。

### 提示词
```
这是目录为v8/src/builtins/x64/builtins-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/x64/builtins-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
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
    __ cmpl(argc, Immediate(JSPara
```