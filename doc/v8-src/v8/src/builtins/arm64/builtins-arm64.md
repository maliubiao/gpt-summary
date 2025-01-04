Response: The user wants a summary of the C++ source code file `v8/src/builtins/arm64/builtins-arm64.cc`.
The file seems to contain implementations of built-in functions for the ARM64 architecture in the V8 JavaScript engine.

The request is for the first part of a four-part summary.

Looking at the includes, the file deals with various aspects of V8 internals:
- API interaction (`api-arguments.h`)
- Built-in function handling (`builtins-descriptors.h`, `builtins-inl.h`)
- Code generation (`code-factory.h`, `interface-descriptors-inl.h`, `macro-assembler-inl.h`)
- Debugging (`debug.h`)
- Deoptimization (`deoptimizer.h`)
- Execution frames (`frame-constants.h`, `frames.h`)
- Heap management (`heap-inl.h`)
- Logging (`counters.h`)
- Object representation (`objects/`)
- Runtime functions (`runtime/runtime.h`)
- WebAssembly support (if enabled) (`wasm/`)
- Unwinding information on Windows (`diagnostics/unwinding-info-win64.h`)

The code defines a namespace `v8::internal` and uses a macro `__` to access the `MacroAssembler`.

The functions defined in this part seem to be low-level implementations related to:
- Adapting arguments for function calls (`Generate_Adaptor`).
- Constructing JavaScript objects (`Generate_JSBuiltinsConstructStubHelper`, `Generate_JSConstructStubGeneric`, `Generate_JSBuiltinsConstructStub`).
- Handling calls to non-constructable objects (`Generate_ConstructedNonConstructable`).
- Asserting the type of code objects.
- Resuming generator functions (`Generate_ResumeGeneratorTrampoline`).
- Entering JavaScript code from native code (`Generate_JSEntryVariant`, `Generate_JSEntry`, `Generate_JSConstructEntry`, `Generate_JSRunMicrotasksEntry`, `Generate_JSEntryTrampolineHelper`, `Generate_JSEntryTrampoline`, `Generate_JSConstructEntryTrampoline`, `Generate_RunMicrotasksTrampoline`).
- Leaving interpreter frames.
- Advancing the bytecode offset in the interpreter.
- Resetting function age for optimization purposes.
- Handling baseline code execution (`Generate_BaselineOutOfLinePrologue`, `Generate_BaselineOutOfLinePrologueDeopt`).
- Entering the interpreter (`Generate_InterpreterEntryTrampoline`).
- Pushing arguments for interpreter calls (`GenerateInterpreterPushArgs`).
这个C++源代码文件是V8 JavaScript引擎中针对ARM64架构的内置函数（builtins）实现。它的主要功能是 **提供底层汇编代码，用于实现JavaScript的核心功能和优化**。

更具体地说，在这第一部分中，它包含了以下方面的功能：

1. **函数调用适配器 (`Generate_Adaptor`)**:  用于在C++和JavaScript函数之间进行桥接，处理参数和调用约定。

2. **构造函数调用桩 (`Generate_JSBuiltinsConstructStubHelper`, `Generate_JSConstructStubGeneric`, `Generate_JSBuiltinsConstructStub`)**: 实现了JavaScript中 `new` 关键字的功能，用于创建新的对象实例。它处理了包括分配内存、调用构造函数等步骤。

3. **处理不可构造的调用 (`Generate_ConstructedNonConstructable`)**: 当尝试使用 `new` 关键字调用一个不可构造的函数时，会抛出错误。

4. **代码类型断言**: 包含用于断言代码对象类型的辅助函数 (`AssertCodeIsBaselineAllowClobber`, `AssertCodeIsBaseline`).

5. **生成器恢复入口 (`Generate_ResumeGeneratorTrampoline`)**:  当一个JavaScript生成器函数通过 `yield` 暂停后，再次调用 `next()` 或 `return()` 时，会通过这个入口点恢复执行。

6. **JavaScript入口点 (`Generate_JSEntryVariant`, `Generate_JSEntry`, `Generate_JSConstructEntry`, `Generate_JSRunMicrotasksEntry`)**: 这些函数定义了从C++代码进入JavaScript代码执行的入口点，负责设置调用栈、处理异常等。`Generate_JSEntry` 用于普通函数调用， `Generate_JSConstructEntry` 用于构造函数调用， `Generate_JSRunMicrotasksEntry` 用于执行微任务队列。

7. **JavaScript入口跳板 (`Generate_JSEntryTrampolineHelper`, `Generate_JSEntryTrampoline`, `Generate_JSConstructEntryTrampoline`)**:  这些是实际执行JavaScript调用的跳板代码，负责在调用目标函数前将参数压入栈中。

8. **微任务执行跳板 (`Generate_RunMicrotasksTrampoline`)**: 用于触发执行 JavaScript 的微任务队列。

9. **离开解释器帧 (`LeaveInterpreterFrame`)**:  在解释器执行完成后，清理栈帧并返回。

10. **推进字节码偏移 (`AdvanceBytecodeOffsetOrReturn`)**:  在解释器执行完一条字节码指令后，计算下一条指令的地址。

11. **重置函数年龄 (`ResetSharedFunctionInfoAge`, `ResetJSFunctionAge`, `ResetFeedbackVectorOsrUrgency`)**: 这些函数用于重置函数的调用次数或优化状态，影响V8的优化决策。

12. **Baseline 代码序言 (`Generate_BaselineOutOfLinePrologue`, `Generate_BaselineOutOfLinePrologueDeopt`)**:  实现了 Baseline 编译代码的入口和退出逻辑，Baseline 是一种轻量级的优化编译。

13. **解释器入口跳板 (`Generate_InterpreterEntryTrampoline`)**:  当JavaScript代码需要通过解释器执行时，会跳转到这个入口点。它负责设置解释器执行所需的栈帧和寄存器状态。

14. **解释器参数压栈 (`GenerateInterpreterPushArgs`)**:  在通过解释器调用函数前，将参数压入栈中。

**与 JavaScript 功能的关系 (举例说明):**

这个文件中的代码直接支撑着JavaScript语言的许多核心特性。例如：

**1. 对象创建 (`new` 关键字):**

```javascript
function Person(name) {
  this.name = name;
}

const person = new Person("Alice");
console.log(person.name); // 输出 "Alice"
```

当执行 `new Person("Alice")` 时，V8引擎会调用 `Generate_JSBuiltinsConstructStub` 中生成的汇编代码，来完成以下操作：
- 分配 `Person` 实例所需的内存。
- 调用 `Person` 函数，并将新分配的对象作为 `this` 绑定到函数中。
- 返回新创建的对象。

**2. 函数调用:**

```javascript
function greet(name) {
  console.log("Hello, " + name + "!");
}

greet("Bob");
```

当调用 `greet("Bob")` 时，V8引擎会根据函数的类型和状态，可能通过 `Generate_JSEntryTrampoline` 或 `Generate_InterpreterEntryTrampoline` 进入函数执行。

**3. 生成器函数:**

```javascript
function* counter() {
  yield 1;
  yield 2;
}

const gen = counter();
console.log(gen.next()); // 输出 { value: 1, done: false }
console.log(gen.next()); // 输出 { value: 2, done: false }
console.log(gen.next()); // 输出 { value: undefined, done: true }
```

当调用 `gen.next()` 来恢复生成器执行时，`Generate_ResumeGeneratorTrampoline` 中生成的代码会被执行，它会恢复生成器的状态，并将控制权转移回生成器函数。

总而言之，这个文件是V8引擎实现JavaScript语言功能的基石，它包含了大量底层的、性能关键的代码，用于支持JavaScript的各种语法和语义。

Prompt: 
```
这是目录为v8/src/builtins/arm64/builtins-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if V8_TARGET_ARCH_ARM64

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
#include "src/objects/instance-type.h"
#include "src/objects/js-generator.h"
#include "src/objects/objects-inl.h"
#include "src/objects/smi.h"
#include "src/runtime/runtime.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/baseline/liftoff-assembler-defs.h"
#include "src/wasm/object-access.h"
#include "src/wasm/stacks.h"
#include "src/wasm/wasm-constants.h"
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-objects.h"
#endif  // V8_ENABLE_WEBASSEMBLY

#if defined(V8_OS_WIN)
#include "src/diagnostics/unwinding-info-win64.h"
#endif  // V8_OS_WIN

namespace v8 {
namespace internal {

#define __ ACCESS_MASM(masm)

namespace {
constexpr int kReceiverOnStackSize = kSystemPointerSize;
}  // namespace

void Builtins::Generate_Adaptor(MacroAssembler* masm,
                                int formal_parameter_count, Address address) {
  __ CodeEntry();

  __ Mov(kJavaScriptCallExtraArg1Register, ExternalReference::Create(address));
  __ TailCallBuiltin(
      Builtins::AdaptorWithBuiltinExitFrame(formal_parameter_count));
}

namespace {

void Generate_JSBuiltinsConstructStubHelper(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- x0     : number of arguments
  //  -- x1     : constructor function
  //  -- x3     : new target
  //  -- cp     : context
  //  -- lr     : return address
  //  -- sp[...]: constructor arguments
  // -----------------------------------

  ASM_LOCATION("Builtins::Generate_JSConstructStubHelper");
  Label stack_overflow;

  __ StackOverflowCheck(x0, &stack_overflow);

  // Enter a construct frame.
  {
    FrameScope scope(masm, StackFrame::CONSTRUCT);
    Label already_aligned;
    Register argc = x0;

    if (v8_flags.debug_code) {
      // Check that FrameScope pushed the context on to the stack already.
      __ Peek(x2, 0);
      __ Cmp(x2, cp);
      __ Check(eq, AbortReason::kUnexpectedValue);
    }

    // Push number of arguments.
    __ Push(argc, padreg);

    // Round up to maintain alignment.
    Register slot_count = x2;
    Register slot_count_without_rounding = x12;
    __ Add(slot_count_without_rounding, argc, 1);
    __ Bic(slot_count, slot_count_without_rounding, 1);
    __ Claim(slot_count);

    // Preserve the incoming parameters on the stack.
    __ LoadRoot(x4, RootIndex::kTheHoleValue);

    // Compute a pointer to the slot immediately above the location on the
    // stack to which arguments will be later copied.
    __ SlotAddress(x2, argc);

    // Store padding, if needed.
    __ Tbnz(slot_count_without_rounding, 0, &already_aligned);
    __ Str(padreg, MemOperand(x2));
    __ Bind(&already_aligned);

    // TODO(victorgomes): When the arguments adaptor is completely removed, we
    // should get the formal parameter count and copy the arguments in its
    // correct position (including any undefined), instead of delaying this to
    // InvokeFunction.

    // Copy arguments to the expression stack.
    {
      Register count = x2;
      Register dst = x10;
      Register src = x11;
      __ SlotAddress(dst, 0);
      // Poke the hole (receiver).
      __ Str(x4, MemOperand(dst));
      __ Add(dst, dst, kSystemPointerSize);  // Skip receiver.
      __ Add(src, fp,
             StandardFrameConstants::kCallerSPOffset +
                 kSystemPointerSize);  // Skip receiver.
      __ Sub(count, argc, kJSArgcReceiverSlots);
      __ CopyDoubleWords(dst, src, count);
    }

    // ----------- S t a t e -------------
    //  --                           x0: number of arguments (untagged)
    //  --                           x1: constructor function
    //  --                           x3: new target
    // If argc is odd:
    //  --     sp[0*kSystemPointerSize]: the hole (receiver)
    //  --     sp[1*kSystemPointerSize]: argument 1
    //  --             ...
    //  -- sp[(n-1)*kSystemPointerSize]: argument (n - 1)
    //  -- sp[(n+0)*kSystemPointerSize]: argument n
    //  -- sp[(n+1)*kSystemPointerSize]: padding
    //  -- sp[(n+2)*kSystemPointerSize]: padding
    //  -- sp[(n+3)*kSystemPointerSize]: number of arguments
    //  -- sp[(n+4)*kSystemPointerSize]: context (pushed by FrameScope)
    // If argc is even:
    //  --     sp[0*kSystemPointerSize]: the hole (receiver)
    //  --     sp[1*kSystemPointerSize]: argument 1
    //  --             ...
    //  -- sp[(n-1)*kSystemPointerSize]: argument (n - 1)
    //  -- sp[(n+0)*kSystemPointerSize]: argument n
    //  -- sp[(n+1)*kSystemPointerSize]: padding
    //  -- sp[(n+2)*kSystemPointerSize]: number of arguments
    //  -- sp[(n+3)*kSystemPointerSize]: context (pushed by FrameScope)
    // -----------------------------------

    // Call the function.
    __ InvokeFunctionWithNewTarget(x1, x3, argc, InvokeType::kCall);

    // Restore the context from the frame.
    __ Ldr(cp, MemOperand(fp, ConstructFrameConstants::kContextOffset));
    // Restore arguments count from the frame. Use fp relative
    // addressing to avoid the circular dependency between padding existence and
    // argc parity.
    __ Ldr(x1, MemOperand(fp, ConstructFrameConstants::kLengthOffset));
    // Leave construct frame.
  }

  // Remove caller arguments from the stack and return.
  __ DropArguments(x1);
  __ Ret();

  __ Bind(&stack_overflow);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kThrowStackOverflow);
    __ Unreachable();
  }
}

}  // namespace

// The construct stub for ES5 constructor functions and ES6 class constructors.
void Builtins::Generate_JSConstructStubGeneric(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- x0     : number of arguments
  //  -- x1     : constructor function
  //  -- x3     : new target
  //  -- lr     : return address
  //  -- cp     : context pointer
  //  -- sp[...]: constructor arguments
  // -----------------------------------

  ASM_LOCATION("Builtins::Generate_JSConstructStubGeneric");

  FrameScope scope(masm, StackFrame::MANUAL);
  // Enter a construct frame.
  __ EnterFrame(StackFrame::CONSTRUCT);
  Label post_instantiation_deopt_entry, not_create_implicit_receiver;

  if (v8_flags.debug_code) {
    // Check that FrameScope pushed the context on to the stack already.
    __ Peek(x2, 0);
    __ Cmp(x2, cp);
    __ Check(eq, AbortReason::kUnexpectedValue);
  }

  // Preserve the incoming parameters on the stack.
  __ Push(x0, x1, padreg, x3);

  // ----------- S t a t e -------------
  //  --        sp[0*kSystemPointerSize]: new target
  //  --        sp[1*kSystemPointerSize]: padding
  //  -- x1 and sp[2*kSystemPointerSize]: constructor function
  //  --        sp[3*kSystemPointerSize]: number of arguments
  //  --        sp[4*kSystemPointerSize]: context (pushed by FrameScope)
  // -----------------------------------

  __ LoadTaggedField(
      x4, FieldMemOperand(x1, JSFunction::kSharedFunctionInfoOffset));
  __ Ldr(w4, FieldMemOperand(x4, SharedFunctionInfo::kFlagsOffset));
  __ DecodeField<SharedFunctionInfo::FunctionKindBits>(w4);
  __ JumpIfIsInRange(
      w4, static_cast<uint32_t>(FunctionKind::kDefaultDerivedConstructor),
      static_cast<uint32_t>(FunctionKind::kDerivedConstructor),
      &not_create_implicit_receiver);

  // If not derived class constructor: Allocate the new receiver object.
  __ CallBuiltin(Builtin::kFastNewObject);

  __ B(&post_instantiation_deopt_entry);

  // Else: use TheHoleValue as receiver for constructor call
  __ Bind(&not_create_implicit_receiver);
  __ LoadRoot(x0, RootIndex::kTheHoleValue);

  // ----------- S t a t e -------------
  //  --                                x0: receiver
  //  -- Slot 4 / sp[0*kSystemPointerSize]: new target
  //  -- Slot 3 / sp[1*kSystemPointerSize]: padding
  //  -- Slot 2 / sp[2*kSystemPointerSize]: constructor function
  //  -- Slot 1 / sp[3*kSystemPointerSize]: number of arguments
  //  -- Slot 0 / sp[4*kSystemPointerSize]: context
  // -----------------------------------
  // Deoptimizer enters here.
  masm->isolate()->heap()->SetConstructStubCreateDeoptPCOffset(
      masm->pc_offset());

  __ Bind(&post_instantiation_deopt_entry);

  // Restore new target from the top of the stack.
  __ Peek(x3, 0 * kSystemPointerSize);

  // Restore constructor function and argument count.
  __ Ldr(x1, MemOperand(fp, ConstructFrameConstants::kConstructorOffset));
  __ Ldr(x12, MemOperand(fp, ConstructFrameConstants::kLengthOffset));

  // Copy arguments to the expression stack. The called function pops the
  // receiver along with its arguments, so we need an extra receiver on the
  // stack, in case we have to return it later.

  // Overwrite the new target with a receiver.
  __ Poke(x0, 0);

  // Push two further copies of the receiver. One will be popped by the called
  // function. The second acts as padding if the number of arguments plus
  // receiver is odd - pushing receiver twice avoids branching. It also means
  // that we don't have to handle the even and odd cases specially on
  // InvokeFunction's return, as top of stack will be the receiver in either
  // case.
  __ Push(x0, x0);

  // ----------- S t a t e -------------
  //  --                              x3: new target
  //  --                             x12: number of arguments (untagged)
  //  --        sp[0*kSystemPointerSize]: implicit receiver (overwrite if argc
  //  odd)
  //  --        sp[1*kSystemPointerSize]: implicit receiver
  //  --        sp[2*kSystemPointerSize]: implicit receiver
  //  --        sp[3*kSystemPointerSize]: padding
  //  -- x1 and sp[4*kSystemPointerSize]: constructor function
  //  --        sp[5*kSystemPointerSize]: number of arguments
  //  --        sp[6*kSystemPointerSize]: context
  // -----------------------------------

  // Round the number of arguments down to the next even number, and claim
  // slots for the arguments. If the number of arguments was odd, the last
  // argument will overwrite one of the receivers pushed above.
  Register argc_without_receiver = x11;
  __ Sub(argc_without_receiver, x12, kJSArgcReceiverSlots);
  __ Bic(x10, x12, 1);

  // Check if we have enough stack space to push all arguments.
  Label stack_overflow;
  __ StackOverflowCheck(x10, &stack_overflow);
  __ Claim(x10);

  // TODO(victorgomes): When the arguments adaptor is completely removed, we
  // should get the formal parameter count and copy the arguments in its
  // correct position (including any undefined), instead of delaying this to
  // InvokeFunction.

  // Copy the arguments.
  {
    Register count = x2;
    Register dst = x10;
    Register src = x11;
    __ Mov(count, argc_without_receiver);
    __ Poke(x0, 0);          // Add the receiver.
    __ SlotAddress(dst, 1);  // Skip receiver.
    __ Add(src, fp,
           StandardFrameConstants::kCallerSPOffset + kSystemPointerSize);
    __ CopyDoubleWords(dst, src, count);
  }

  // Call the function.
  __ Mov(x0, x12);
  __ InvokeFunctionWithNewTarget(x1, x3, x0, InvokeType::kCall);

  // If the result is an object (in the ECMA sense), we should get rid
  // of the receiver and use the result; see ECMA-262 section 13.2.2-7
  // on page 74.
  Label use_receiver, do_throw, leave_and_return, check_receiver;

  // If the result is undefined, we jump out to using the implicit receiver.
  __ CompareRoot(x0, RootIndex::kUndefinedValue);
  __ B(ne, &check_receiver);

  // Throw away the result of the constructor invocation and use the
  // on-stack receiver as the result.
  __ Bind(&use_receiver);
  __ Peek(x0, 0 * kSystemPointerSize);
  __ CompareRoot(x0, RootIndex::kTheHoleValue);
  __ B(eq, &do_throw);

  __ Bind(&leave_and_return);
  // Restore arguments count from the frame.
  __ Ldr(x1, MemOperand(fp, ConstructFrameConstants::kLengthOffset));
  // Leave construct frame.
  __ LeaveFrame(StackFrame::CONSTRUCT);
  // Remove caller arguments from the stack and return.
  __ DropArguments(x1);
  __ Ret();

  // Otherwise we do a smi check and fall through to check if the return value
  // is a valid receiver.
  __ bind(&check_receiver);

  // If the result is a smi, it is *not* an object in the ECMA sense.
  __ JumpIfSmi(x0, &use_receiver);

  // Check if the type of the result is not an object in the ECMA sense.
  __ JumpIfJSAnyIsNotPrimitive(x0, x4, &leave_and_return);
  __ B(&use_receiver);

  __ Bind(&do_throw);
  // Restore the context from the frame.
  __ Ldr(cp, MemOperand(fp, ConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowConstructorReturnedNonObject);
  __ Unreachable();

  __ Bind(&stack_overflow);
  // Restore the context from the frame.
  __ Ldr(cp, MemOperand(fp, ConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowStackOverflow);
  __ Unreachable();
}
void Builtins::Generate_JSBuiltinsConstructStub(MacroAssembler* masm) {
  Generate_JSBuiltinsConstructStubHelper(masm);
}

void Builtins::Generate_ConstructedNonConstructable(MacroAssembler* masm) {
  FrameScope scope(masm, StackFrame::INTERNAL);
  __ PushArgument(x1);
  __ CallRuntime(Runtime::kThrowConstructedNonConstructable);
  __ Unreachable();
}

static void AssertCodeIsBaselineAllowClobber(MacroAssembler* masm,
                                             Register code, Register scratch) {
  // Verify that the code kind is baseline code via the CodeKind.
  __ Ldr(scratch, FieldMemOperand(code, Code::kFlagsOffset));
  __ DecodeField<Code::KindField>(scratch);
  __ Cmp(scratch, Operand(static_cast<int>(CodeKind::BASELINE)));
  __ Assert(eq, AbortReason::kExpectedBaselineData);
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
  __ IsObjectTypeFast(data, scratch, CODE_TYPE);
#else
  __ CompareObjectType(data, scratch, scratch, CODE_TYPE);
#endif  // V8_STATIC_ROOTS_BOOL
  if (v8_flags.debug_code) {
    Label not_baseline;
    __ B(ne, &not_baseline);
    AssertCodeIsBaseline(masm, data, scratch);
    __ B(eq, is_baseline);
    __ Bind(&not_baseline);
  } else {
    __ B(eq, is_baseline);
  }

#if V8_STATIC_ROOTS_BOOL
  // scratch already contains the compressed map.
  __ CompareInstanceTypeWithUniqueCompressedMap(scratch, Register::no_reg(),
                                                INTERPRETER_DATA_TYPE);
#else
  // scratch already contains the instance type.
  __ Cmp(scratch, INTERPRETER_DATA_TYPE);
#endif  // V8_STATIC_ROOTS_BOOL
  __ B(ne, is_bytecode);
}

// TODO(v8:11429): Add a path for "not_compiled" and unify the two uses under
// the more general dispatch.
static void GetSharedFunctionInfoBytecodeOrBaseline(
    MacroAssembler* masm, Register sfi, Register bytecode, Register scratch1,
    Label* is_baseline, Label* is_unavailable) {
  DCHECK(!AreAliased(bytecode, scratch1));
  ASM_CODE_COMMENT(masm);
  Label done;

  Register data = bytecode;
  __ LoadTrustedPointerField(
      data,
      FieldMemOperand(sfi, SharedFunctionInfo::kTrustedFunctionDataOffset),
      kUnknownIndirectPointerTag);

  if (V8_JITLESS_BOOL) {
    __ IsObjectType(data, scratch1, scratch1, INTERPRETER_DATA_TYPE);
    __ B(ne, &done);
  } else {
    CheckSharedFunctionInfoBytecodeOrBaseline(masm, data, scratch1, is_baseline,
                                              &done);
  }

  __ LoadProtectedPointerField(
      bytecode, FieldMemOperand(data, InterpreterData::kBytecodeArrayOffset));

  __ Bind(&done);
  __ IsObjectType(bytecode, scratch1, scratch1, BYTECODE_ARRAY_TYPE);
  __ B(ne, is_unavailable);
}

// static
void Builtins::Generate_ResumeGeneratorTrampoline(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- x0 : the value to pass to the generator
  //  -- x1 : the JSGeneratorObject to resume
  //  -- lr : return address
  // -----------------------------------

  // Store input value into generator object.
  __ StoreTaggedField(
      x0, FieldMemOperand(x1, JSGeneratorObject::kInputOrDebugPosOffset));
  __ RecordWriteField(x1, JSGeneratorObject::kInputOrDebugPosOffset, x0,
                      kLRHasNotBeenSaved, SaveFPRegsMode::kIgnore);
  // Check that x1 is still valid, RecordWrite might have clobbered it.
  __ AssertGeneratorObject(x1);

  // Load suspended function and context.
  __ LoadTaggedField(x5,
                     FieldMemOperand(x1, JSGeneratorObject::kFunctionOffset));
  __ LoadTaggedField(cp, FieldMemOperand(x5, JSFunction::kContextOffset));

  // Flood function if we are stepping.
  Label prepare_step_in_if_stepping, prepare_step_in_suspended_generator;
  Label stepping_prepared;
  ExternalReference debug_hook =
      ExternalReference::debug_hook_on_function_call_address(masm->isolate());
  __ Mov(x10, debug_hook);
  __ Ldrsb(x10, MemOperand(x10));
  __ CompareAndBranch(x10, Operand(0), ne, &prepare_step_in_if_stepping);

  // Flood function if we need to continue stepping in the suspended generator.
  ExternalReference debug_suspended_generator =
      ExternalReference::debug_suspended_generator_address(masm->isolate());
  __ Mov(x10, debug_suspended_generator);
  __ Ldr(x10, MemOperand(x10));
  __ CompareAndBranch(x10, Operand(x1), eq,
                      &prepare_step_in_suspended_generator);
  __ Bind(&stepping_prepared);

  // Check the stack for overflow. We are not trying to catch interruptions
  // (i.e. debug break and preemption) here, so check the "real stack limit".
  Label stack_overflow;
  __ LoadStackLimit(x10, StackLimitKind::kRealStackLimit);
  __ Cmp(sp, x10);
  __ B(lo, &stack_overflow);

  Register argc = kJavaScriptCallArgCountRegister;

  // Compute actual arguments count value as a formal parameter count without
  // receiver, loaded from the dispatch table entry or shared function info.
#if V8_ENABLE_LEAPTIERING
  Register dispatch_handle = kJavaScriptCallDispatchHandleRegister;
  Register code = kJavaScriptCallCodeStartRegister;
  Register scratch = x20;
  __ Ldr(dispatch_handle.W(),
         FieldMemOperand(x5, JSFunction::kDispatchHandleOffset));
  __ LoadEntrypointAndParameterCountFromJSDispatchTable(
      code, argc, dispatch_handle, scratch);

  // In case the formal parameter count is kDontAdaptArgumentsSentinel the
  // actual arguments count should be set accordingly.
  static_assert(kDontAdaptArgumentsSentinel < JSParameterCount(0));
  __ Cmp(argc, Operand(JSParameterCount(0)));
  __ Csel(argc, argc, Operand(JSParameterCount(0)), kGreaterThan);
#else
  __ LoadTaggedField(
      argc, FieldMemOperand(x5, JSFunction::kSharedFunctionInfoOffset));
  __ Ldrh(argc.W(), FieldMemOperand(
                        argc, SharedFunctionInfo::kFormalParameterCountOffset));

  // Generator functions are always created from user code and thus the
  // formal parameter count is never equal to kDontAdaptArgumentsSentinel,
  // which is used only for certain non-generator builtin functions.
#endif  // V8_ENABLE_LEAPTIERING

  // Claim slots for arguments and receiver (rounded up to a multiple of two).
  static_assert(JSParameterCount(0) == 1);  // argc includes receiver
  __ Add(x11, argc, 1);
  __ Bic(x11, x11, 1);
  __ Claim(x11);

  // Store padding (which might be replaced by the last argument).
  __ Sub(x11, x11, 1);
  __ Poke(padreg, Operand(x11, LSL, kSystemPointerSizeLog2));

  // Poke receiver into highest claimed slot.
  __ LoadTaggedField(x6,
                     FieldMemOperand(x1, JSGeneratorObject::kReceiverOffset));
  __ Poke(x6, __ ReceiverOperand());

  // ----------- S t a t e -------------
  //  -- x0                       : actual arguments count
  //  -- x1                       : the JSGeneratorObject to resume
  //  -- x2                       : target code object (leaptiering only)
  //  -- x4                       : dispatch handle (leaptiering only)
  //  -- x5                       : generator function
  //  -- cp                       : generator context
  //  -- lr                       : return address
  //  -- sp[0 .. arg count]       : claimed for receiver and args
  // -----------------------------------

  // Copy the function arguments from the generator object's register file.
  {
    Label loop, done;
    __ Sub(x10, argc, kJSArgcReceiverSlots);
    __ Cbz(x10, &done);
    __ LoadTaggedField(
        x6,
        FieldMemOperand(x1, JSGeneratorObject::kParametersAndRegistersOffset));

    __ SlotAddress(x12, x10);
    __ Add(x6, x6, Operand(x10, LSL, kTaggedSizeLog2));
    __ Add(x6, x6, Operand(OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag));
    __ Bind(&loop);
    __ Sub(x10, x10, 1);
    __ LoadTaggedField(x11, MemOperand(x6, -kTaggedSize, PreIndex));
    __ Str(x11, MemOperand(x12, -kSystemPointerSize, PostIndex));
    __ Cbnz(x10, &loop);
    __ Bind(&done);
  }

  // Underlying function needs to have bytecode available.
  if (v8_flags.debug_code) {
    Label ok, is_baseline, is_unavailable;
    Register sfi = x10;
    Register bytecode = x10;
    Register scratch = x11;
    __ LoadTaggedField(
        sfi, FieldMemOperand(x5, JSFunction::kSharedFunctionInfoOffset));
    GetSharedFunctionInfoBytecodeOrBaseline(masm, sfi, bytecode, scratch,
                                            &is_baseline, &is_unavailable);
    __ B(&ok);

    __ Bind(&is_unavailable);
    __ Abort(AbortReason::kMissingBytecodeArray);

    __ Bind(&is_baseline);
    __ IsObjectType(bytecode, scratch, scratch, CODE_TYPE);
    __ Assert(eq, AbortReason::kMissingBytecodeArray);

    __ Bind(&ok);
  }

  // Resume (Ignition/TurboFan) generator object.
  {
    // We abuse new.target both to indicate that this is a resume call and to
    // pass in the generator object.  In ordinary calls, new.target is always
    // undefined because generator functions are non-constructable.
    __ Mov(x3, x1);  // new.target
    __ Mov(x1, x5);  // target
#if V8_ENABLE_LEAPTIERING
    // We jump through x17 here because for Branch Identification (BTI) we use
    // "Call" (`bti c`) rather than "Jump" (`bti j`) landing pads for
    // tail-called code. See TailCallBuiltin for more information.
    DCHECK_NE(code, x17);
    __ Mov(x17, code);
    // Actual arguments count and code start are already initialized above.
    __ Jump(x17);
#else
    // Actual arguments count is already initialized above.
    __ JumpJSFunction(x1);
#endif  // V8_ENABLE_LEAPTIERING
  }

  __ Bind(&prepare_step_in_if_stepping);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    // Push hole as receiver since we do not use it for stepping.
    __ LoadRoot(x6, RootIndex::kTheHoleValue);
    __ Push(x1, padreg, x5, x6);
    __ CallRuntime(Runtime::kDebugOnFunctionCall);
    __ Pop(padreg, x1);
    __ LoadTaggedField(x5,
                       FieldMemOperand(x1, JSGeneratorObject::kFunctionOffset));
  }
  __ B(&stepping_prepared);

  __ Bind(&prepare_step_in_suspended_generator);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ Push(x1, padreg);
    __ CallRuntime(Runtime::kDebugPrepareStepInSuspendedGenerator);
    __ Pop(padreg, x1);
    __ LoadTaggedField(x5,
                       FieldMemOperand(x1, JSGeneratorObject::kFunctionOffset));
  }
  __ B(&stepping_prepared);

  __ bind(&stack_overflow);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kThrowStackOverflow);
    __ Unreachable();  // This should be unreachable.
  }
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
//
// Input is either:
//   x0: root_register_value.
//   x1: new_target.
//   x2: target.
//   x3: receiver.
//   x4: argc.
//   x5: argv.
// or
//   x0: root_register_value.
//   x1: microtask_queue.
// Output:
//   x0: result.
void Generate_JSEntryVariant(MacroAssembler* masm, StackFrame::Type type,
                             Builtin entry_trampoline) {
  Label invoke, handler_entry, exit;

  {
    NoRootArrayScope no_root_array(masm);

#if defined(V8_OS_WIN)
    // In order to allow Windows debugging tools to reconstruct a call stack, we
    // must generate information describing how to recover at least fp, sp, and
    // pc for the calling frame. Here, JSEntry registers offsets to
    // xdata_encoder which then emits the offset values as part of the unwind
    // data accordingly.
    win64_unwindinfo::XdataEncoder* xdata_encoder = masm->GetXdataEncoder();
    if (xdata_encoder) {
      xdata_encoder->onFramePointerAdjustment(
          EntryFrameConstants::kDirectCallerFPOffset,
          EntryFrameConstants::kDirectCallerSPOffset);
    }
#endif

    __ PushCalleeSavedRegisters();

    // Set up the reserved register for 0.0.
    __ Fmov(fp_zero, 0.0);

    // Initialize the root register.
    // C calling convention. The first argument is passed in x0.
    __ Mov(kRootRegister, x0);

#ifdef V8_COMPRESS_POINTERS
    // Initialize the pointer cage base register.
    __ LoadRootRelative(kPtrComprCageBaseRegister,
                        IsolateData::cage_base_offset());
#endif
  }

  // Set up fp. It points to the {fp, lr} pair pushed as the last step in
  // PushCalleeSavedRegisters.
  static_assert(
      EntryFrameConstants::kCalleeSavedRegisterBytesPushedAfterFpLrPair == 0);
  static_assert(EntryFrameConstants::kOffsetToCalleeSavedRegisters == 0);
  __ Mov(fp, sp);

  // Build an entry frame (see layout below).

  // Push frame type markers.
  __ Mov(x12, StackFrame::TypeToMarker(type));
  __ Push(x12, xzr);

  __ Mov(x11, ExternalReference::Create(IsolateAddressId::kCEntryFPAddress,
                                        masm->isolate()));
  __ Ldr(x10, MemOperand(x11));  // x10 = C entry FP.

  // Clear c_entry_fp, now we've loaded its value to be pushed on the stack.
  // If the c_entry_fp is not already zero and we don't clear it, the
  // StackFrameIteratorForProfiler will assume we are executing C++ and miss the
  // JS frames on top.
  __ Str(xzr, MemOperand(x11));

  // Set js_entry_sp if this is the outermost JS call.
  Label done;
  ExternalReference js_entry_sp = ExternalReference::Create(
      IsolateAddressId::kJSEntrySPAddress, masm->isolate());
  __ Mov(x12, js_entry_sp);
  __ Ldr(x11, MemOperand(x12));  // x11 = previous JS entry SP.

  // Select between the inner and outermost frame marker, based on the JS entry
  // sp. We assert that the inner marker is zero, so we can use xzr to save a
  // move instruction.
  DCHECK_EQ(StackFrame::INNER_JSENTRY_FRAME, 0);
  __ Cmp(x11, 0);  // If x11 is zero, this is the outermost frame.
  // x11 = JS entry frame marker.
  __ Csel(x11, xzr, StackFrame::OUTERMOST_JSENTRY_FRAME, ne);
  __ B(ne, &done);
  __ Str(fp, MemOperand(x12));

  __ Bind(&done);

  __ LoadIsolateField(x9, IsolateFieldId::kFastCCallCallerFP);
  __ Ldr(x7, MemOperand(x9));
  __ Str(xzr, MemOperand(x9));
  __ LoadIsolateField(x9, IsolateFieldId::kFastCCallCallerPC);
  __ Ldr(x8, MemOperand(x9));
  __ Str(xzr, MemOperand(x9));
  __ Push(x10, x11, x7, x8);

  // The frame set up looks like this:
  // sp[0] : fast api call pc.
  // sp[1] : fast api call fp.
  // sp[2] : JS entry frame marker.
  // sp[3] : C entry FP.
  // sp[4] : stack frame marker (0).
  // sp[5] : stack frame marker (type).
  // sp[6] : saved fp   <- fp points here.
  // sp[7] : saved lr
  // sp[8,26) : other saved registers

  // Jump to a faked try block that does the invoke, with a faked catch
  // block that sets the exception.
  __ B(&invoke);

  // Prevent the constant pool from being emitted between the record of the
  // handler_entry position and the first instruction of the sequence here.
  // There is no risk because Assembler::Emit() emits the instruction before
  // checking for constant pool emission, but we do not want to depend on
  // that.
  {
    Assembler::BlockPoolsScope block_pools(masm);

    // Store the current pc as the handler offset. It's used later to create the
    // handler table.
    __ BindExceptionHandler(&handler_entry);
    masm->isolate()->builtins()->SetJSEntryHandlerOffset(handler_entry.pos());

    // Caught exception: Store result (exception) in the exception
    // field in the JSEnv and return a failure sentinel. Coming in here the
    // fp will be invalid because UnwindAndFindHandler sets it to 0 to
    // signal the existence of the JSEntry frame.
    __ Mov(x10, ExternalReference::Create(IsolateAddressId::kExceptionAddress,
                                          masm->isolate()));
  }
  __ Str(x0, MemOperand(x10));
  __ LoadRoot(x0, RootIndex::kException);
  __ B(&exit);

  // Invoke: Link this frame into the handler chain.
  __ Bind(&invoke);

  // Push new stack handler.
  static_assert(StackHandlerConstants::kSize == 2 * kSystemPointerSize,
                "Unexpected offset for StackHandlerConstants::kSize");
  static_assert(StackHandlerConstants::kNextOffset == 0 * kSystemPointerSize,
                "Unexpected offset for StackHandlerConstants::kNextOffset");

  // Link the current handler as the next handler.
  __ Mov(x11, ExternalReference::Create(IsolateAddressId::kHandlerAddress,
                                        masm->isolate()));
  __ Ldr(x10, MemOperand(x11));
  __ Push(padreg, x10);

  // Set this new handler as the current one.
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.AcquireX();
    __ Mov(scratch, sp);
    __ Str(scratch, MemOperand(x11));
  }

  // If an exception not caught by another handler occurs, this handler
  // returns control to the code after the B(&invoke) above, which
  // restores all callee-saved registers (including cp and fp) to their
  // saved values before returning a failure to C.
  //
  // Invoke the function by calling through JS entry trampoline builtin and
  // pop the faked function when we return.
  __ CallBuiltin(entry_trampoline);

  // Pop the stack handler and unlink this frame from the handler chain.
  static_assert(StackHandlerConstants::kNextOffset == 0 * kSystemPointerSize,
                "Unexpected offset for StackHandlerConstants::kNextOffset");
  __ Pop(x10, padreg);
  __ Mov(x11, ExternalReference::Create(IsolateAddressId::kHandlerAddress,
                                        masm->isolate()));
  __ Drop(StackHandlerConstants::kSlotCount - 2);
  __ Str(x10, MemOperand(x11));

  __ Bind(&exit);
  // x0 holds the result.
  // The stack pointer points to the top of the entry frame pushed on entry from
  // C++ (at the beginning of this stub):
  // sp[0] : fast api call pc.
  // sp[1] : fast api call fp.
  // sp[2] : JS entry frame marker.
  // sp[3] : C entry FP.
  // sp[4] : stack frame marker (0).
  // sp[5] : stack frame marker (type).
  // sp[6] : saved fp   <- fp points here.
  // sp[7] : saved lr
  // sp[8,26) : other saved registers

  __ Pop(x10, x11);
  __ LoadIsolateField(x8, IsolateFieldId::kFastCCallCallerPC);
  __ Str(x10, MemOperand(x8));
  __ LoadIsolateField(x9, IsolateFieldId::kFastCCallCallerFP);
  __ Str(x11, MemOperand(x9));

  // Check if the current stack frame is marked as the outermost JS frame.
  Label non_outermost_js_2;
  {
    Register c_entry_fp = x11;
    __ PeekPair(x10, c_entry_fp, 0);
    __ Cmp(x10, StackFrame::OUTERMOST_JSENTRY_FRAME);
    __ B(ne, &non_outermost_js_2);
    __ Mov(x12, js_entry_sp);
    __ Str(xzr, MemOperand(x12));
    __ Bind(&non_outermost_js_2);

    // Restore the top frame descriptors from the stack.
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
"""


```