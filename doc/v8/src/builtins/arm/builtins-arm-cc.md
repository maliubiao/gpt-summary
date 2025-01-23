Response:
The user wants a summary of the functionality of the provided C++ code.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the file's purpose:** The path `v8/src/builtins/arm/builtins-arm.cc` immediately suggests this file contains implementations of built-in functions for the ARM architecture within the V8 JavaScript engine. The `.cc` extension confirms it's C++ code.

2. **High-level overview:**  Built-in functions are the core operations and functionalities that JavaScript relies on (e.g., `Array.push`, `console.log`, function calls, object creation, etc.). This file likely provides the low-level, optimized implementations of these operations for ARM processors.

3. **Scan for keywords and structures:** Look for recurring patterns and important data structures:
    * `#if V8_TARGET_ARCH_ARM`:  Confirms architecture-specific code.
    * `Builtins::Generate_...`: This strongly indicates functions that generate machine code for specific built-in operations.
    * `MacroAssembler`:  V8's class for emitting machine code instructions.
    * `FrameScope`, `StackFrame`: Indicate manipulation of the call stack.
    * `Registers` (like `r0`, `r1`, `cp`, `lr`, `sp`):  ARM CPU registers being used.
    * `Runtime::k...`: Calls to V8's runtime functions for operations that are not handled directly in the builtins.
    * `JSFunction`, `JSGeneratorObject`, `SharedFunctionInfo`:  V8's internal object representations.
    * `Builtin::k...`: Enums representing different built-in functions.
    * `Generate_PushArguments`: A helper function for pushing arguments onto the stack.
    *  Mentions of "construct", "call", "adaptor", "generator", "entry", "trampoline":  These highlight key categories of built-in implementations.

4. **Group functionalities:** Based on the keywords and structures, categorize the built-in implementations:
    * **Adaptor:**  Handles transitions between different calling conventions.
    * **Constructor Stubs:**  Implement the `new` operator and object creation.
    * **Generator Functions:** Manage the execution of JavaScript generator functions (pause and resume).
    * **Entry/Trampoline Functions:**  Handle entering and exiting JavaScript execution from native code.
    * **Interpreter Support:**  Provides logic for the V8 interpreter (advancing bytecode).

5. **Address specific questions:**
    * **`.tq` extension:** The code itself doesn't end in `.tq`, so it's not Torque code.
    * **Relationship to JavaScript:** Emphasize that these builtins *implement* JavaScript features.
    * **JavaScript examples:**  Provide simple JavaScript code snippets that would trigger the functionalities implemented in this file. Focus on `new`, function calls, and generator functions.
    * **Code Logic Reasoning (Hypothetical):** Choose a relatively straightforward example, like `Generate_PushArguments`. Define hypothetical input registers and describe the expected stack modifications.
    * **Common Programming Errors:** Relate common errors to the functionality, such as incorrect `this` binding in constructors or stack overflow in recursive calls.

6. **Summarize (Instruction #6):** Concisely restate the main purpose of the file as providing low-level implementations of core JavaScript functionalities for the ARM architecture.

7. **Review and refine:** Ensure the explanation is clear, accurate, and addresses all aspects of the prompt. Use precise language and avoid jargon where possible, or explain it if necessary. For instance, briefly explain what "built-in functions" are in the context of a JavaScript engine.
好的，让我们来分析一下 `v8/src/builtins/arm/builtins-arm.cc` 这个文件的功能。

**功能归纳:**

总的来说，`v8/src/builtins/arm/builtins-arm.cc` 文件是 V8 JavaScript 引擎中针对 **ARM 架构** 的 **内置函数 (builtins)** 的实现代码。它包含了用汇编语言编写的、用于执行 JavaScript 核心操作的底层代码。

**具体功能列举:**

1. **调用适配器 (Adaptor):**
   - `Builtins::Generate_Adaptor`:  生成一个适配器，用于在 C++ 函数和 JavaScript 函数之间进行调用转换。这包括处理参数传递、堆栈管理等。

2. **参数压栈辅助 (PushArguments):**
   - `Generate_PushArguments`:  这是一个辅助函数，用于将参数从数组或堆栈上压入到当前的执行堆栈中，为后续的函数调用做准备。它可以处理原始参数和句柄类型的参数。

3. **构造函数桩 (Constructor Stubs):**
   - `Builtins::Generate_JSBuiltinsConstructStubHelper`:  生成用于 ES5 构造函数和 ES6 类构造函数的通用构造函数桩的辅助代码。它负责创建新对象、调用构造函数等。
   - `Builtins::Generate_JSConstructStubGeneric`: 生成更详细的构造函数桩代码，包括处理继承的构造函数调用 (`super()`)、创建隐式接收者（`this`）等逻辑。
   - `Builtins::Generate_JSBuiltinsConstructStub`:  调用辅助函数生成构造函数桩。

4. **恢复生成器 (Resume Generator):**
   - `Builtins::Generate_ResumeGeneratorTrampoline`:  生成一个入口点，用于恢复一个暂停的 JavaScript 生成器函数。它负责将输入值传递给生成器，恢复其状态，并继续执行。

5. **非构造函数调用错误处理 (ConstructedNonConstructable):**
   - `Builtins::Generate_ConstructedNonConstructable`:  当尝试使用 `new` 运算符调用一个非构造函数时，会生成抛出错误的机器码。

6. **JSEntry 变体 (JSEntry Variant):**
   - `Generate_JSEntryVariant`: 生成进入 V8 引擎执行 JavaScript 代码的入口点。它处理堆栈帧的设置、异常处理、以及调用实际的 JavaScript 代码。它有不同的变体，用于普通调用 (`JSEntry`) 和构造函数调用 (`JSConstructEntry`) 以及运行微任务 (`JSRunMicrotasksEntry`)。

7. **JSEntry 桩 (JSEntry Trampoline):**
   - `Builtins::Generate_JSEntryTrampolineHelper`:  生成 `JSEntry` 入口点的辅助代码，负责从 C++ 层传递参数到 JavaScript 层，并调用 JavaScript 函数。
   - `Builtins::Generate_JSEntryTrampoline`:  生成用于普通函数调用的 `JSEntry` 桩。
   - `Builtins::Generate_JSConstructEntryTrampoline`: 生成用于构造函数调用的 `JSEntry` 桩。
   - `Builtins::Generate_RunMicrotasksTrampoline`: 生成用于运行微任务的入口点。

8. **解释器框架处理 (Interpreter Frame Handling):**
   - `LeaveInterpreterFrame`:  生成退出解释器框架的代码，负责清理堆栈。
   - `AdvanceBytecodeOffsetOrReturn`: 生成代码，用于在解释器中推进字节码偏移量，模拟字节码执行过程。如果遇到返回字节码，则跳转到指定的标签。

**关于文件后缀和 JavaScript 关系:**

- **文件后缀:**  `v8/src/builtins/arm/builtins-arm.cc` 的后缀是 `.cc`，这意味着它是一个 **C++ 源代码文件**。如果它的后缀是 `.tq`，那么它才是一个 V8 Torque 源代码文件。Torque 是一种用于生成 builtins 的领域特定语言。

- **与 JavaScript 的关系:**  这个文件中的代码 **直接关系到 JavaScript 的功能**。它实现了 JavaScript 语言的核心特性，例如函数调用、对象创建、生成器等。当 JavaScript 代码执行到这些操作时，V8 引擎会调用这里定义的底层机器码来完成。

**JavaScript 示例:**

```javascript
// 函数调用 (触发 Builtins::Generate_JSEntryTrampoline)
function myFunction(a, b) {
  return a + b;
}
myFunction(1, 2);

// 构造函数调用 (触发 Builtins::Generate_JSConstructStubGeneric)
function MyClass(value) {
  this.value = value;
}
const instance = new MyClass(10);

// 生成器函数调用 (触发 Builtins::Generate_ResumeGeneratorTrampoline)
function* myGenerator() {
  yield 1;
  yield 2;
}
const generator = myGenerator();
generator.next();
generator.next();
```

**代码逻辑推理 (以 `Generate_PushArguments` 为例):**

**假设输入:**

- `array` 寄存器指向一个包含参数的内存地址。
- `argc` 寄存器包含参数的个数（包括接收者）。
- 堆栈上已经为参数预留了空间。

**输出:**

- 参数 (从最后一个到第一个) 被依次压入到当前的执行堆栈中。

**代码逻辑:**

1. 计算实际参数的个数 (`argc` 减去接收者的槽位 `kJSArgcReceiverSlots`)。
2. 循环遍历参数数组，从后往前 (高索引到低索引)。
3. 从 `array` 指向的内存中加载参数值。
4. 如果 `element_type` 是 `kHandle`，则解引用参数值（因为此时数组中存储的是句柄）。
5. 将参数值压入堆栈。

**用户常见的编程错误 (与构造函数相关):**

```javascript
// 1. 在构造函数中忘记使用 'new' 关键字
function MyClass(value) {
  this.value = value; // 'this' 将指向全局对象 (非严格模式) 或 undefined (严格模式)
}
MyClass(10); // 常见错误，不会创建 MyClass 的实例

// 2. 尝试调用非构造函数
const obj = {};
// const instance = new obj(); // TypeError: obj is not a constructor

// 3. 在派生类的构造函数中忘记调用 super()
class Parent {
  constructor(value) {
    this.parentValue = value;
  }
}

class Child extends Parent {
  constructor(childValue) {
    // super(childValue); // 忘记调用 super()，会导致 'this' 未初始化
    this.childValue = childValue;
  }
}

// const childInstance = new Child(5); // ReferenceError: Must call super constructor in derived class before accessing 'this' or returning from derived constructor
```

**第1部分功能归纳:**

`v8/src/builtins/arm/builtins-arm.cc` 的第 1 部分主要包含了以下功能：

- **基础的 builtins 框架:**  定义了用于生成和管理内置函数的结构。
- **函数调用和构造函数调用的底层实现:** 包括适配器、参数处理、对象创建等核心逻辑。
- **生成器函数的恢复机制:** 提供了恢复暂停的生成器函数的能力。
- **错误处理机制:**  处理诸如尝试构造不可构造对象等错误情况。
- **进入和退出 V8 执行环境的入口点 (`JSEntry`):**  处理从 C++ 代码进入 JavaScript 代码的流程。
- **解释器执行的基础支持:**  提供了在解释器中执行字节码的基本操作。

总而言之，这个文件的第一部分奠定了 ARM 架构上执行 JavaScript 代码的关键基础，涵盖了函数调用、对象创建和控制流管理等核心方面。

### 提示词
```
这是目录为v8/src/builtins/arm/builtins-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/arm/builtins-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
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
#define JUMP_IF_EQUAL(NAME)
```