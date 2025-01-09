Response:
The user wants a summary of the functionality of the provided C++ code. The code is part of the V8 JavaScript engine and specifically for the MIPS64 architecture.

Here's a breakdown of how to approach this:

1. **Identify the file's purpose:** The file is named `builtins-mips64.cc` and resides in a directory related to built-in functions for the `mips64` architecture. This suggests it contains implementations of core JavaScript functionalities optimized for this architecture.

2. **Scan for key function names and macros:** Look for function definitions starting with `Builtins::Generate_`. These are the entry points for different built-in functionalities. Also, pay attention to macros like `__` which is an alias for `ACCESS_MASM(masm)`, indicating the use of a MacroAssembler for generating assembly code.

3. **Analyze individual `Generate_` functions:**  Briefly describe the purpose of each function based on its name and the operations it performs. Look for common patterns like stack frame manipulation, argument handling, function calls, and object creation.

4. **Check for architecture-specific details:** Note the `#if V8_TARGET_ARCH_MIPS64` which confirms the architecture specificity. Also, look for MIPS64-specific instructions or register names.

5. **Address the `.tq` question:** The prompt mentions `.tq` files, which are related to V8's Torque language. The current file is `.cc`, so it's C++ not Torque.

6. **Look for JavaScript relationships:**  Identify functions that clearly relate to JavaScript concepts like function calls, constructors, generators, and microtasks.

7. **Consider code logic and examples:**  Where the code performs specific actions like pushing arguments or checking stack overflow, think about the context in a JavaScript program.

8. **Identify potential programming errors:** Look for areas where the code handles errors or checks for invalid states, which could be related to common programming mistakes.

9. **Synthesize the information:** Group the functionalities into broader categories and summarize the overall purpose of the file.

**Constraint Checklist & Confidence Score:**

* 列举一下它的功能: Yes. Will list the functionalities implemented in the file.
* 如果v8/src/builtins/mips64/builtins-mips64.cc以.tq结尾，那它是个v8 torque源代码: Yes. Will state that this file is not `.tq`.
* 如果它与javascript的功能有关系，请用javascript举例说明: Yes. Will provide JavaScript examples where applicable.
* 如果有代码逻辑推理，请给出假设输入与输出: Yes. Will provide simple examples where the code flow is clear.
* 如果涉及用户常见的编程错误，请举例说明: Yes. Will provide examples of common JavaScript errors related to the code's functionality.
* 这是第1部分，共5部分，请归纳一下它的功能: Yes. Will provide a summary of the file's functionality as the first part.

Confidence Score: 5/5

**Mental Sandbox Simulation:**

I'll mentally walk through some of the functions. `Generate_Adaptor` looks like a bridge between native code and JavaScript. `Generate_JSConstructStubGeneric` clearly handles object construction. `Generate_ResumeGeneratorTrampoline` is for resuming generator functions. The `Generate_JSEntry` family of functions are entry points for JavaScript execution. The code uses a MacroAssembler, so it's generating assembly instructions directly. The inclusion of WebAssembly related headers indicates support for WASM.

The key takeaway is that this file contains low-level, architecture-specific implementations of essential JavaScript built-in functionalities.
这个C++源代码文件 `v8/src/builtins/mips64/builtins-mips64.cc` 是V8 JavaScript引擎的一部分，专门为MIPS64架构定义和实现了内置函数（builtins）。这些内置函数是用汇编语言编写的，提供了JavaScript代码执行所需的底层操作。

**主要功能归纳:**

1. **内置函数入口点 (Builtin Entry Points):**  它定义了许多内置函数的入口点，这些函数是V8引擎预先实现好的，用于执行各种核心的JavaScript操作。这些函数可以通过JavaScript代码直接或间接地调用。

2. **架构优化 (Architecture Optimization):** 由于文件名中包含 "mips64"，表明这些内置函数的实现是针对MIPS64架构进行了优化的，利用了该架构的特性以提高性能。

3. **核心JavaScript功能实现 (Core JavaScript Functionality):**  文件中包含了很多与JavaScript核心功能相关的实现，例如：
    * **函数调用和构造 (Function Calls and Construction):**  例如 `Generate_Adaptor`, `Generate_JSConstructStubGeneric`, `Generate_JSBuiltinsConstructStub` 等函数负责处理JavaScript函数的调用和对象构造过程。
    * **生成器 (Generators):** `Generate_ResumeGeneratorTrampoline` 负责处理生成器函数的恢复执行。
    * **异常处理 (Exception Handling):**  JSEntry相关的函数涉及到try-catch机制的设置。
    * **微任务 (Microtasks):** `Generate_JSRunMicrotasksEntry` 和 `Generate_RunMicrotasksTrampoline` 用于处理JavaScript的微任务队列。
    * **栈溢出检查 (Stack Overflow Checks):** `Generate_CheckStackOverflow` 用于在函数调用前检查是否有足够的栈空间。
    * **与解释器交互 (Interaction with Interpreter):** `LeaveInterpreterFrame` 和 `AdvanceBytecodeOffsetOrReturn` 与V8的字节码解释器有关，用于在解释执行过程中管理栈帧和指令指针。

4. **与运行时 (Runtime) 的交互:** 文件中调用了 `Runtime::k...` 形式的函数，这些是V8运行时的C++函数，提供了更高级别的操作，例如抛出异常、分配内存等。

**关于 `.tq` 结尾:**

如果 `v8/src/builtins/mips64/builtins-mips64.cc` 以 `.tq` 结尾，那么它将是 V8 的 Torque 源代码。Torque 是一种 V8 内部使用的领域特定语言，用于定义和生成内置函数的 C++ 代码。当前的这个文件是 `.cc` 结尾，所以它是直接用 C++ 和汇编编写的。

**与 JavaScript 功能的关系及示例:**

这个文件中的代码直接支撑着许多 JavaScript 的核心功能。以下是一些示例：

* **函数调用:**  `Generate_Adaptor` 和 `Generate_JSEntryTrampoline` 处理从 C++ 或其他底层代码到 JavaScript 函数的调用。
    ```javascript
    function myFunction(a, b) {
      return a + b;
    }
    myFunction(1, 2); // 当调用这个函数时，V8引擎会使用相应的内置函数入口。
    ```

* **对象构造:** `Generate_JSConstructStubGeneric` 负责处理 `new` 关键字的操作。
    ```javascript
    function MyClass(value) {
      this.value = value;
    }
    const instance = new MyClass(5); // 当使用 new 关键字时，会触发构造函数的调用。
    ```

* **生成器:** `Generate_ResumeGeneratorTrampoline` 用于在生成器函数中使用 `yield` 暂停后恢复执行。
    ```javascript
    function* myGenerator() {
      yield 1;
      yield 2;
    }
    const gen = myGenerator();
    gen.next(); // 第一次调用 next() 会执行到第一个 yield。
    gen.next(); // 第二次调用 next() 会从上次暂停的地方恢复执行。
    ```

* **抛出异常:**  当 JavaScript 代码中发生错误时，例如调用不可构造的函数，会调用 `Runtime::kThrowConstructedNonConstructable`。
    ```javascript
    const obj = {};
    try {
      new obj(); // TypeError: obj is not a constructor
    } catch (e) {
      console.error(e);
    }
    ```

**代码逻辑推理及示例:**

`Generate_PushArguments` 函数负责将参数从栈上的某个位置复制到另一个位置。

**假设输入:**
* `array`:  指向参数起始位置的寄存器 (栈地址)。
* `argc`: 参数个数的寄存器。
* 栈上存储了 `argc` 个参数。

**输出:**
* 参数被依次压入当前栈顶。

**JavaScript 示例:** 当调用一个函数时，`Generate_PushArguments` 会被用来将传递给函数的参数推入栈中，以便被调用函数访问。

**用户常见的编程错误及示例:**

* **栈溢出 (Stack Overflow):**  如果递归调用过深，或者函数调用链过长，可能会导致栈溢出。`Generate_CheckStackOverflow` 的目的就是在底层检测这种潜在的错误。
    ```javascript
    function recursiveFunction() {
      recursiveFunction(); // 没有终止条件的递归调用
    }
    try {
      recursiveFunction(); // 可能导致 RangeError: Maximum call stack size exceeded
    } catch (e) {
      console.error(e);
    }
    ```

* **尝试 `new` 一个非构造函数:**  JavaScript 中只有函数可以作为构造函数使用 `new` 关键字调用。尝试 `new` 一个普通对象或原始值会导致错误，这会触发类似 `Generate_ConstructedNonConstructable` 的内置函数。

**功能归纳 (针对第 1 部分):**

这部分代码主要负责定义和实现 V8 JavaScript 引擎在 MIPS64 架构下的基础内置函数，涵盖了函数调用、对象构造、生成器处理、栈管理等核心功能。它提供了 JavaScript 代码执行的关键底层支持，并包含了对常见运行时错误的检查和处理机制。 这段代码是性能关键型的，因为它直接参与了 JavaScript 代码的执行流程。

Prompt: 
```
这是目录为v8/src/builtins/mips64/builtins-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/mips64/builtins-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if V8_TARGET_ARCH_MIPS64

#include "src/api/api-arguments.h"
#include "src/builtins/builtins-inl.h"
#include "src/codegen/code-factory.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/debug/debug.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/frame-constants.h"
#include "src/execution/frames.h"
#include "src/logging/counters.h"
// For interpreter_entry_return_pc_offset. TODO(jkummerow): Drop.
#include "src/codegen/macro-assembler-inl.h"
#include "src/codegen/mips64/constants-mips64.h"
#include "src/codegen/register-configuration.h"
#include "src/heap/heap-inl.h"
#include "src/objects/cell.h"
#include "src/objects/foreign.h"
#include "src/objects/heap-number.h"
#include "src/objects/js-generator.h"
#include "src/objects/objects-inl.h"
#include "src/objects/smi.h"
#include "src/runtime/runtime.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/baseline/liftoff-assembler-defs.h"
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-objects.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

#define __ ACCESS_MASM(masm)

void Builtins::Generate_Adaptor(MacroAssembler* masm,
                                int formal_parameter_count, Address address) {
  __ li(kJavaScriptCallExtraArg1Register, ExternalReference::Create(address));
  __ TailCallBuiltin(
      Builtins::AdaptorWithBuiltinExitFrame(formal_parameter_count));
}

namespace {

enum class ArgumentsElementType {
  kRaw,    // Push arguments as they are.
  kHandle  // Dereference arguments before pushing.
};

void Generate_PushArguments(MacroAssembler* masm, Register array, Register argc,
                            Register scratch, Register scratch2,
                            ArgumentsElementType element_type) {
  DCHECK(!AreAliased(array, argc, scratch));
  Label loop, entry;
  __ Dsubu(scratch, argc, Operand(kJSArgcReceiverSlots));
  __ Branch(&entry);
  __ bind(&loop);
  __ Dlsa(scratch2, array, scratch, kSystemPointerSizeLog2);
  __ Ld(scratch2, MemOperand(scratch2));
  if (element_type == ArgumentsElementType::kHandle) {
    __ Ld(scratch2, MemOperand(scratch2));
  }
  __ push(scratch2);
  __ bind(&entry);
  __ Daddu(scratch, scratch, Operand(-1));
  __ Branch(&loop, greater_equal, scratch, Operand(zero_reg));
}

void Generate_JSBuiltinsConstructStubHelper(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- a0     : number of arguments
  //  -- a1     : constructor function
  //  -- a3     : new target
  //  -- cp     : context
  //  -- ra     : return address
  //  -- sp[...]: constructor arguments
  // -----------------------------------

  // Enter a construct frame.
  {
    FrameScope scope(masm, StackFrame::CONSTRUCT);

    // Preserve the incoming parameters on the stack.
    __ Push(cp, a0);

    // Set up pointer to first argument (skip receiver).
    __ Daddu(
        t2, fp,
        Operand(StandardFrameConstants::kCallerSPOffset + kSystemPointerSize));
    // Copy arguments and receiver to the expression stack.
    // t2: Pointer to start of arguments.
    // a0: Number of arguments.
    Generate_PushArguments(masm, t2, a0, t3, t0, ArgumentsElementType::kRaw);
    // The receiver for the builtin/api call.
    __ PushRoot(RootIndex::kTheHoleValue);

    // Call the function.
    // a0: number of arguments (untagged)
    // a1: constructor function
    // a3: new target
    __ InvokeFunctionWithNewTarget(a1, a3, a0, InvokeType::kCall);

    // Restore context from the frame.
    __ Ld(cp, MemOperand(fp, ConstructFrameConstants::kContextOffset));
    // Restore arguments count from the frame.
    __ Ld(t3, MemOperand(fp, ConstructFrameConstants::kLengthOffset));
    // Leave construct frame.
  }

  // Remove caller arguments from the stack and return.
  __ DropArguments(t3);
  __ Ret();
}

}  // namespace

// The construct stub for ES5 constructor functions and ES6 class constructors.
void Builtins::Generate_JSConstructStubGeneric(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  --      a0: number of arguments (untagged)
  //  --      a1: constructor function
  //  --      a3: new target
  //  --      cp: context
  //  --      ra: return address
  //  -- sp[...]: constructor arguments
  // -----------------------------------

  // Enter a construct frame.
  FrameScope scope(masm, StackFrame::MANUAL);
  Label post_instantiation_deopt_entry, not_create_implicit_receiver;
  __ EnterFrame(StackFrame::CONSTRUCT);

  // Preserve the incoming parameters on the stack.
  __ Push(cp, a0, a1);
  __ PushRoot(RootIndex::kUndefinedValue);
  __ Push(a3);

  // ----------- S t a t e -------------
  //  --        sp[0*kSystemPointerSize]: new target
  //  --        sp[1*kSystemPointerSize]: padding
  //  -- a1 and sp[2*kSystemPointerSize]: constructor function
  //  --        sp[3*kSystemPointerSize]: number of arguments
  //  --        sp[4*kSystemPointerSize]: context
  // -----------------------------------

  __ Ld(t2, FieldMemOperand(a1, JSFunction::kSharedFunctionInfoOffset));
  __ lwu(t2, FieldMemOperand(t2, SharedFunctionInfo::kFlagsOffset));
  __ DecodeField<SharedFunctionInfo::FunctionKindBits>(t2);
  __ JumpIfIsInRange(
      t2, static_cast<uint32_t>(FunctionKind::kDefaultDerivedConstructor),
      static_cast<uint32_t>(FunctionKind::kDerivedConstructor),
      &not_create_implicit_receiver);

  // If not derived class constructor: Allocate the new receiver object.
  __ CallBuiltin(Builtin::kFastNewObject);
  __ Branch(&post_instantiation_deopt_entry);

  // Else: use TheHoleValue as receiver for constructor call
  __ bind(&not_create_implicit_receiver);
  __ LoadRoot(v0, RootIndex::kTheHoleValue);

  // ----------- S t a t e -------------
  //  --                          v0: receiver
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
  __ Pop(a3);

  // Push the allocated receiver to the stack.
  __ Push(v0);

  // We need two copies because we may have to return the original one
  // and the calling conventions dictate that the called function pops the
  // receiver. The second copy is pushed after the arguments, we saved in a6
  // since v0 will store the return value of callRuntime.
  __ mov(a6, v0);

  // Set up pointer to last argument.
  __ Daddu(t2, fp, Operand(StandardFrameConstants::kCallerSPOffset +
                           kSystemPointerSize));

  // ----------- S t a t e -------------
  //  --                 a3: new target
  //  -- sp[0*kSystemPointerSize]: implicit receiver
  //  -- sp[1*kSystemPointerSize]: implicit receiver
  //  -- sp[2*kSystemPointerSize]: padding
  //  -- sp[3*kSystemPointerSize]: constructor function
  //  -- sp[4*kSystemPointerSize]: number of arguments
  //  -- sp[5*kSystemPointerSize]: context
  // -----------------------------------

  // Restore constructor function and argument count.
  __ Ld(a1, MemOperand(fp, ConstructFrameConstants::kConstructorOffset));
  __ Ld(a0, MemOperand(fp, ConstructFrameConstants::kLengthOffset));

  Label stack_overflow;
  __ StackOverflowCheck(a0, t0, t1, &stack_overflow);

  // TODO(victorgomes): When the arguments adaptor is completely removed, we
  // should get the formal parameter count and copy the arguments in its
  // correct position (including any undefined), instead of delaying this to
  // InvokeFunction.

  // Copy arguments and receiver to the expression stack.
  // t2: Pointer to start of argument.
  // a0: Number of arguments.
  Generate_PushArguments(masm, t2, a0, t0, t1, ArgumentsElementType::kRaw);
  // We need two copies because we may have to return the original one
  // and the calling conventions dictate that the called function pops the
  // receiver. The second copy is pushed after the arguments,
  __ Push(a6);

  // Call the function.
  __ InvokeFunctionWithNewTarget(a1, a3, a0, InvokeType::kCall);

  // If the result is an object (in the ECMA sense), we should get rid
  // of the receiver and use the result; see ECMA-262 section 13.2.2-7
  // on page 74.
  Label use_receiver, do_throw, leave_and_return, check_receiver;

  // If the result is undefined, we jump out to using the implicit receiver.
  __ JumpIfNotRoot(v0, RootIndex::kUndefinedValue, &check_receiver);

  // Otherwise we do a smi check and fall through to check if the return value
  // is a valid receiver.

  // Throw away the result of the constructor invocation and use the
  // on-stack receiver as the result.
  __ bind(&use_receiver);
  __ Ld(v0, MemOperand(sp, 0 * kSystemPointerSize));
  __ JumpIfRoot(v0, RootIndex::kTheHoleValue, &do_throw);

  __ bind(&leave_and_return);
  // Restore arguments count from the frame.
  __ Ld(a1, MemOperand(fp, ConstructFrameConstants::kLengthOffset));
  // Leave construct frame.
  __ LeaveFrame(StackFrame::CONSTRUCT);

  // Remove caller arguments from the stack and return.
  __ DropArguments(a1);
  __ Ret();

  __ bind(&check_receiver);
  __ JumpIfSmi(v0, &use_receiver);

  // If the type of the result (stored in its map) is less than
  // FIRST_JS_RECEIVER_TYPE, it is not an object in the ECMA sense.
  __ GetObjectType(v0, t2, t2);
  static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
  __ Branch(&leave_and_return, greater_equal, t2,
            Operand(FIRST_JS_RECEIVER_TYPE));
  __ Branch(&use_receiver);

  __ bind(&do_throw);
  // Restore the context from the frame.
  __ Ld(cp, MemOperand(fp, ConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowConstructorReturnedNonObject);
  __ break_(0xCC);

  __ bind(&stack_overflow);
  // Restore the context from the frame.
  __ Ld(cp, MemOperand(fp, ConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowStackOverflow);
  __ break_(0xCC);
}

void Builtins::Generate_JSBuiltinsConstructStub(MacroAssembler* masm) {
  Generate_JSBuiltinsConstructStubHelper(masm);
}

static void AssertCodeIsBaseline(MacroAssembler* masm, Register code,
                                 Register scratch) {
  DCHECK(!AreAliased(code, scratch));
  // Verify that the code kind is baseline code via the CodeKind.
  __ Ld(scratch, FieldMemOperand(code, Code::kFlagsOffset));
  __ DecodeField<Code::KindField>(scratch);
  __ Assert(eq, AbortReason::kExpectedBaselineData, scratch,
            Operand(static_cast<int>(CodeKind::BASELINE)));
}

// TODO(v8:11429): Add a path for "not_compiled" and unify the two uses under
// the more general dispatch.
static void GetSharedFunctionInfoBytecodeOrBaseline(
    MacroAssembler* masm, Register sfi, Register bytecode, Register scratch1,
    Label* is_baseline, Label* is_unavailable) {
  Label done;

  Register data = bytecode;
  __ Ld(data,
        FieldMemOperand(sfi, SharedFunctionInfo::kTrustedFunctionDataOffset));


  __ GetObjectType(data, scratch1, scratch1);

#ifndef V8_JITLESS
  if (v8_flags.debug_code) {
    Label not_baseline;
    __ Branch(&not_baseline, ne, scratch1, Operand(CODE_TYPE));
    AssertCodeIsBaseline(masm, data, scratch1);
    __ Branch(is_baseline);
    __ bind(&not_baseline);
  } else {
    __ Branch(is_baseline, eq, scratch1, Operand(CODE_TYPE));
  }
#endif  // !V8_JITLESS

  __ Branch(&done, eq, scratch1, Operand(BYTECODE_ARRAY_TYPE));

  __ Branch(is_unavailable, ne, scratch1, Operand(INTERPRETER_DATA_TYPE));
  __ Ld(data, FieldMemOperand(data, InterpreterData::kBytecodeArrayOffset));
  __ bind(&done);
}

// static
void Builtins::Generate_ResumeGeneratorTrampoline(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- v0 : the value to pass to the generator
  //  -- a1 : the JSGeneratorObject to resume
  //  -- ra : return address
  // -----------------------------------
  // Store input value into generator object.
  __ Sd(v0, FieldMemOperand(a1, JSGeneratorObject::kInputOrDebugPosOffset));
  __ RecordWriteField(a1, JSGeneratorObject::kInputOrDebugPosOffset, v0, a3,
                      kRAHasNotBeenSaved, SaveFPRegsMode::kIgnore);
  // Check that a1 is still valid, RecordWrite might have clobbered it.
  __ AssertGeneratorObject(a1);

  // Load suspended function and context.
  __ Ld(a4, FieldMemOperand(a1, JSGeneratorObject::kFunctionOffset));
  __ Ld(cp, FieldMemOperand(a4, JSFunction::kContextOffset));

  // Flood function if we are stepping.
  Label prepare_step_in_if_stepping, prepare_step_in_suspended_generator;
  Label stepping_prepared;
  ExternalReference debug_hook =
      ExternalReference::debug_hook_on_function_call_address(masm->isolate());
  __ li(a5, debug_hook);
  __ Lb(a5, MemOperand(a5));
  __ Branch(&prepare_step_in_if_stepping, ne, a5, Operand(zero_reg));

  // Flood function if we need to continue stepping in the suspended generator.
  ExternalReference debug_suspended_generator =
      ExternalReference::debug_suspended_generator_address(masm->isolate());
  __ li(a5, debug_suspended_generator);
  __ Ld(a5, MemOperand(a5));
  __ Branch(&prepare_step_in_suspended_generator, eq, a1, Operand(a5));
  __ bind(&stepping_prepared);

  // Check the stack for overflow. We are not trying to catch interruptions
  // (i.e. debug break and preemption) here, so check the "real stack limit".
  Label stack_overflow;
  __ LoadStackLimit(kScratchReg,
                    MacroAssembler::StackLimitKind::kRealStackLimit);
  __ Branch(&stack_overflow, lo, sp, Operand(kScratchReg));

  // ----------- S t a t e -------------
  //  -- a1    : the JSGeneratorObject to resume
  //  -- a4    : generator function
  //  -- cp    : generator context
  //  -- ra    : return address
  // -----------------------------------

  // Push holes for arguments to generator function. Since the parser forced
  // context allocation for any variables in generators, the actual argument
  // values have already been copied into the context and these dummy values
  // will never be used.
  __ Ld(a3, FieldMemOperand(a4, JSFunction::kSharedFunctionInfoOffset));
  __ Lhu(a3,
         FieldMemOperand(a3, SharedFunctionInfo::kFormalParameterCountOffset));
  __ Dsubu(a3, a3, Operand(kJSArgcReceiverSlots));
  __ Ld(t1,
        FieldMemOperand(a1, JSGeneratorObject::kParametersAndRegistersOffset));
  {
    Label done_loop, loop;
    __ bind(&loop);
    __ Dsubu(a3, a3, Operand(1));
    __ Branch(&done_loop, lt, a3, Operand(zero_reg));
    __ Dlsa(kScratchReg, t1, a3, kSystemPointerSizeLog2);
    __ Ld(kScratchReg,
          FieldMemOperand(kScratchReg, OFFSET_OF_DATA_START(FixedArray)));
    __ Push(kScratchReg);
    __ Branch(&loop);
    __ bind(&done_loop);
    // Push receiver.
    __ Ld(kScratchReg, FieldMemOperand(a1, JSGeneratorObject::kReceiverOffset));
    __ Push(kScratchReg);
  }

  // Underlying function needs to have bytecode available.
  if (v8_flags.debug_code) {
    Label is_baseline, is_unavailable, ok;
    __ Ld(a3, FieldMemOperand(a4, JSFunction::kSharedFunctionInfoOffset));
    GetSharedFunctionInfoBytecodeOrBaseline(masm, a3, a3, a0, &is_baseline,
                                            &is_unavailable);
    __ jmp(&ok);

    __ bind(&is_unavailable);
    __ Abort(AbortReason::kMissingBytecodeArray);

    __ bind(&is_baseline);
    __ GetObjectType(a3, a3, a3);
    __ Assert(eq, AbortReason::kMissingBytecodeArray, a3, Operand(CODE_TYPE));

    __ bind(&ok);
  }

  // Resume (Ignition/TurboFan) generator object.
  {
    __ Ld(a0, FieldMemOperand(a4, JSFunction::kSharedFunctionInfoOffset));
    __ Lhu(a0, FieldMemOperand(
                   a0, SharedFunctionInfo::kFormalParameterCountOffset));
    // We abuse new.target both to indicate that this is a resume call and to
    // pass in the generator object.  In ordinary calls, new.target is always
    // undefined because generator functions are non-constructable.
    __ Move(a3, a1);
    __ Move(a1, a4);
    __ JumpJSFunction(a1);
  }

  __ bind(&prepare_step_in_if_stepping);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ Push(a1, a4);
    // Push hole as receiver since we do not use it for stepping.
    __ PushRoot(RootIndex::kTheHoleValue);
    __ CallRuntime(Runtime::kDebugOnFunctionCall);
    __ Pop(a1);
  }
  __ Branch(USE_DELAY_SLOT, &stepping_prepared);
  __ Ld(a4, FieldMemOperand(a1, JSGeneratorObject::kFunctionOffset));

  __ bind(&prepare_step_in_suspended_generator);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ Push(a1);
    __ CallRuntime(Runtime::kDebugPrepareStepInSuspendedGenerator);
    __ Pop(a1);
  }
  __ Branch(USE_DELAY_SLOT, &stepping_prepared);
  __ Ld(a4, FieldMemOperand(a1, JSGeneratorObject::kFunctionOffset));

  __ bind(&stack_overflow);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kThrowStackOverflow);
    __ break_(0xCC);  // This should be unreachable.
  }
}

void Builtins::Generate_ConstructedNonConstructable(MacroAssembler* masm) {
  FrameScope scope(masm, StackFrame::INTERNAL);
  __ Push(a1);
  __ CallRuntime(Runtime::kThrowConstructedNonConstructable);
}

// Clobbers scratch1 and scratch2; preserves all other registers.
static void Generate_CheckStackOverflow(MacroAssembler* masm, Register argc,
                                        Register scratch1, Register scratch2) {
  // Check the stack for overflow. We are not trying to catch
  // interruptions (e.g. debug break and preemption) here, so the "real stack
  // limit" is checked.
  Label okay;
  __ LoadStackLimit(scratch1, MacroAssembler::StackLimitKind::kRealStackLimit);
  // Make a2 the space we have left. The stack might already be overflowed
  // here which will cause r2 to become negative.
  __ dsubu(scratch1, sp, scratch1);
  // Check if the arguments will overflow the stack.
  __ dsll(scratch2, argc, kSystemPointerSizeLog2);
  __ Branch(&okay, gt, scratch1, Operand(scratch2));  // Signed comparison.

  // Out of stack space.
  __ CallRuntime(Runtime::kThrowStackOverflow);

  __ bind(&okay);
}

namespace {

// Called with the native C calling convention. The corresponding function
// signature is either:
//
//   using JSEntryFunction = GeneratedCode<Address(
//       Address root_register_value, Address new_target, Address target,
//       Address receiver, intptr_t argc, Address** args)>;
// or
//   using JSEntryFunction = GeneratedCode<Address(
//       Address root_register_value, MicrotaskQueue* microtask_queue)>;
void Generate_JSEntryVariant(MacroAssembler* masm, StackFrame::Type type,
                             Builtin entry_trampoline) {
  Label invoke, handler_entry, exit;

  {
    NoRootArrayScope no_root_array(masm);

    // TODO(plind): unify the ABI description here.
    // Registers:
    //  either
    //   a0: root register value
    //   a1: entry address
    //   a2: function
    //   a3: receiver
    //   a4: argc
    //   a5: argv
    //  or
    //   a0: root register value
    //   a1: microtask_queue
    //
    // Stack:
    // 0 arg slots on mips64 (4 args slots on mips)

    // Save callee saved registers on the stack.
    __ MultiPush(kCalleeSaved | ra);

    // Save callee-saved FPU registers.
    __ MultiPushFPU(kCalleeSavedFPU);
    // Set up the reserved register for 0.0.
    __ Move(kDoubleRegZero, 0.0);

    // Initialize the root register.
    // C calling convention. The first argument is passed in a0.
    __ mov(kRootRegister, a0);
  }

  // a1: entry address
  // a2: function
  // a3: receiver
  // a4: argc
  // a5: argv

  // We build an EntryFrame.
  __ li(s1, Operand(-1));  // Push a bad frame pointer to fail if it is used.
  __ li(s2, Operand(StackFrame::TypeToMarker(type)));
  __ li(s3, Operand(StackFrame::TypeToMarker(type)));
  ExternalReference c_entry_fp = ExternalReference::Create(
      IsolateAddressId::kCEntryFPAddress, masm->isolate());
  __ li(s5, c_entry_fp);
  __ Ld(s4, MemOperand(s5));
  __ Push(s1, s2, s3, s4);

  // Clear c_entry_fp, now we've pushed its previous value to the stack.
  // If the c_entry_fp is not already zero and we don't clear it, the
  // StackFrameIteratorForProfiler will assume we are executing C++ and miss the
  // JS frames on top.
  __ Sd(zero_reg, MemOperand(s5));

  __ LoadIsolateField(s1, IsolateFieldId::kFastCCallCallerFP);
  __ Ld(s2, MemOperand(s1, 0));
  __ Sd(zero_reg, MemOperand(s1, 0));
  __ LoadIsolateField(s1, IsolateFieldId::kFastCCallCallerPC);
  __ Ld(s3, MemOperand(s1, 0));
  __ Sd(zero_reg, MemOperand(s1, 0));
  __ Push(s2, s3);

  // Set up frame pointer for the frame to be pushed.
  __ daddiu(fp, sp, -EntryFrameConstants::kNextFastCallFramePCOffset);

  // Registers:
  //  either
  //   a1: entry address
  //   a2: function
  //   a3: receiver
  //   a4: argc
  //   a5: argv
  //  or
  //   a1: microtask_queue
  //
  // Stack:
  // fast api call pc   |
  // fast api call fp   |
  // C entry FP         |
  // function slot      | entry frame
  // context slot       |
  // bad fp (0xFF...F)  |
  // callee saved registers + ra

  // If this is the outermost JS call, set js_entry_sp value.
  Label non_outermost_js;
  ExternalReference js_entry_sp = ExternalReference::Create(
      IsolateAddressId::kJSEntrySPAddress, masm->isolate());
  __ li(s1, js_entry_sp);
  __ Ld(s2, MemOperand(s1));
  __ Branch(&non_outermost_js, ne, s2, Operand(zero_reg));
  __ Sd(fp, MemOperand(s1));
  __ li(s3, Operand(StackFrame::OUTERMOST_JSENTRY_FRAME));
  Label cont;
  __ b(&cont);
  __ nop();  // Branch delay slot nop.
  __ bind(&non_outermost_js);
  __ li(s3, Operand(StackFrame::INNER_JSENTRY_FRAME));
  __ bind(&cont);
  __ push(s3);

  // Jump to a faked try block that does the invoke, with a faked catch
  // block that sets the exception.
  __ jmp(&invoke);
  __ bind(&handler_entry);

  // Store the current pc as the handler offset. It's used later to create the
  // handler table.
  masm->isolate()->builtins()->SetJSEntryHandlerOffset(handler_entry.pos());

  // Caught exception: Store result (exception) in the exception
  // field in the JSEnv and return a failure sentinel.  Coming in here the
  // fp will be invalid because the PushStackHandler below sets it to 0 to
  // signal the existence of the JSEntry frame.
  __ li(s1, ExternalReference::Create(IsolateAddressId::kExceptionAddress,
                                      masm->isolate()));
  __ Sd(v0, MemOperand(s1));  // We come back from 'invoke'. result is in v0.
  __ LoadRoot(v0, RootIndex::kException);
  __ b(&exit);  // b exposes branch delay slot.
  __ nop();     // Branch delay slot nop.

  // Invoke: Link this frame into the handler chain.
  __ bind(&invoke);
  __ PushStackHandler();
  // If an exception not caught by another handler occurs, this handler
  // returns control to the code after the bal(&invoke) above, which
  // restores all kCalleeSaved registers (including cp and fp) to their
  // saved values before returning a failure to C.
  //
  // Registers:
  //  either
  //   a0: root register value
  //   a1: entry address
  //   a2: function
  //   a3: receiver
  //   a4: argc
  //   a5: argv
  //  or
  //   a0: root register value
  //   a1: microtask_queue
  //
  // Stack:
  // handler frame
  // entry frame
  // fast api call pc
  // fast api call fp
  // C entry FP
  // function slot
  // context slot
  // bad fp (0xFF...F)
  // callee saved registers + ra

  // Invoke the function by calling through JS entry trampoline builtin and
  // pop the faked function when we return.
  __ CallBuiltin(entry_trampoline);

  // Unlink this frame from the handler chain.
  __ PopStackHandler();

  __ bind(&exit);  // v0 holds result
  // Check if the current stack frame is marked as the outermost JS frame.
  Label non_outermost_js_2;
  __ pop(a5);
  __ Branch(&non_outermost_js_2, ne, a5,
            Operand(StackFrame::OUTERMOST_JSENTRY_FRAME));
  __ li(a5, js_entry_sp);
  __ Sd(zero_reg, MemOperand(a5));
  __ bind(&non_outermost_js_2);

  // Restore the top frame descriptors from the stack.
  __ Pop(a4, a5);
  __ LoadIsolateField(a6, IsolateFieldId::kFastCCallCallerFP);
  __ Sd(a4, MemOperand(a6, 0));
  __ LoadIsolateField(a6, IsolateFieldId::kFastCCallCallerPC);
  __ Sd(a5, MemOperand(a6, 0));

  __ pop(a5);
  __ li(a4, ExternalReference::Create(IsolateAddressId::kCEntryFPAddress,
                                      masm->isolate()));
  __ Sd(a5, MemOperand(a4));

  // Reset the stack to the callee saved registers.
  __ daddiu(sp, sp, -EntryFrameConstants::kNextExitFrameFPOffset);

  // Restore callee-saved fpu registers.
  __ MultiPopFPU(kCalleeSavedFPU);

  // Restore callee saved registers from the stack.
  __ MultiPop(kCalleeSaved | ra);
  // Return.
  __ Jump(ra);
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
  // ----------- S t a t e -------------
  //  -- a1: new.target
  //  -- a2: function
  //  -- a3: receiver_pointer
  //  -- a4: argc
  //  -- a5: argv
  // -----------------------------------

  // Enter an internal frame.
  {
    FrameScope scope(masm, StackFrame::INTERNAL);

    // Setup the context (we need to use the caller context from the isolate).
    ExternalReference context_address = ExternalReference::Create(
        IsolateAddressId::kContextAddress, masm->isolate());
    __ li(cp, context_address);
    __ Ld(cp, MemOperand(cp));

    // Push the function onto the stack.
    __ Push(a2);

    // Check if we have enough stack space to push all arguments.
    __ mov(a6, a4);
    Generate_CheckStackOverflow(masm, a6, a0, s2);

    // Copy arguments to the stack.
    // a4: argc
    // a5: argv, i.e. points to first arg
    Generate_PushArguments(masm, a5, a4, s1, s2, ArgumentsElementType::kHandle);

    // Push the receive.
    __ Push(a3);

    // a0: argc
    // a1: function
    // a3: new.target
    __ mov(a3, a1);
    __ mov(a1, a2);
    __ mov(a0, a4);

    // Initialize all JavaScript callee-saved registers, since they will be seen
    // by the garbage collector as part of handlers.
    __ LoadRoot(a4, RootIndex::kUndefinedValue);
    __ mov(a5, a4);
    __ mov(s1, a4);
    __ mov(s2, a4);
    __ mov(s3, a4);
    __ mov(s4, a4);
    __ mov(s5, a4);
    // s6 holds the root address. Do not clobber.
    // s7 is cp. Do not init.

    // Invoke the code.
    Builtin builtin = is_construct ? Builtin::kConstruct : Builtins::Call();
    __ CallBuiltin(builtin);

    // Leave internal frame.
  }
  __ Jump(ra);
}

void Builtins::Generate_JSEntryTrampoline(MacroAssembler* masm) {
  Generate_JSEntryTrampolineHelper(masm, false);
}

void Builtins::Generate_JSConstructEntryTrampoline(MacroAssembler* masm) {
  Generate_JSEntryTrampolineHelper(masm, true);
}

void Builtins::Generate_RunMicrotasksTrampoline(MacroAssembler* masm) {
  // a1: microtask_queue
  __ mov(RunMicrotasksDescriptor::MicrotaskQueueRegister(), a1);
  __ TailCallBuiltin(Builtin::kRunMicrotasks);
}

static void LeaveInterpreterFrame(MacroAssembler* masm, Register scratch1,
                                  Register scratch2) {
  Register params_size = scratch1;

  // Get the size of the formal parameters + receiver (in bytes).
  __ Ld(params_size,
        MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ Lhu(params_size,
         FieldMemOperand(params_size, BytecodeArray::kParameterSizeOffset));

  Register actual_params_size = scratch2;
  // Compute the size of the actual parameters + receiver (in bytes).
  __ Ld(actual_params_size,
        MemOperand(fp, StandardFrameConstants::kArgCOffset));

  // If actual is bigger than formal, then we should use it to free up the stack
  // arguments.
  __ slt(t2, params_size, actual_params_size);
  __ movn(params_size, actual_params_size, t2);

  // Leave the frame (also dropping the register file).
  __ LeaveFrame(StackFrame::INTERPRETED);

  // Drop arguments.
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
                                          Register scratch2, Register scratch3,
                                          Label* if_return) {
  Register bytecode_size_table = scratch1;

  // The bytecode offset value will be increased by one in wide and extra wide
  // cases. In the case of having a wide or extra wide JumpLoop bytecode, we
  // will restore the original bytecode. In order to simplify the code, we have
  // a backup of it.
  Register original_bytecode_offset = scratch3;
  DCHECK(!AreAliased(bytecode_array, bytecode_offset, bytecode,
                     bytecode_size_table, original_bytecode_offset));
  __ Move(original_bytecode_offset, bytecode_offset);
  __ li(bytecode_size_table, ExternalReference::bytecode_size_table_address());

  // Check if the bytecode is a Wide or ExtraWide prefix bytecode.
  Label process_bytecode, extra_wide;
  static_assert(0 == static_cast<int>(interpreter::Bytecode::kWide));
  static_assert(1 == static_cast<int>(interpreter::Bytecode::kExtraWide));
  static_assert(2 == static_cast<int>(interpreter::Bytecode::kDebugBreakWide));
  static_assert(3 ==
                static_cast<int>(interpreter::Bytecode::kDebugBreakExtraWide));
  __ Branch(&process_bytecode, hi, bytecode, Operand(3));
  __ And(scratch2, bytecode, Operand(1));
  __ Branch(&extra_wide, ne, scratch2, Operand(zero_reg));

  // Load the next bytecode and update table to the wide scaled table.
  __ Daddu(bytecode_offset, bytecode_offset, Operand(1));
  __ Daddu(scratch2, bytecode_array, bytecode_offset);
  __ Lbu(bytecode, MemOperand(scratch2));
  __ Daddu(bytecode_size_table, bytecode_size_table,
           Operand(kByteSize * interpreter::Bytecodes::kBytecodeCount));
  __ jmp(&process_bytecode);

  __ bind(&extra_wide);
  // Load the next bytecode and update table to the extra wide scaled table.
  __ Daddu(bytecode_offset, bytecode_offset, Operand(1));
  __ Daddu(scratch2, bytecode_array, bytecode_offset);
  __ Lbu(bytecode, MemOperand(scratch2));
  __ Daddu(bytecode_size_table, bytecode_size_table,
           Operand(2 * kByteSize * interpreter::Bytecodes::kBytecodeCount));

  __ bind(&process_bytecode);

// Bailout to the return label if this is a return bytecode.
#define JUMP_IF_EQUAL(NAME)          \
  __ Branch(if_return, eq, bytecode, \
            Operand(static_cast<int>(interpreter::Bytecode::k##NAME)));
  RETURN_BYTECODE_LIST(JUMP_IF_EQUAL)
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
  __ Daddu(scratch2, bytecode_size_table, bytecode);
  __ Lb(scratch2, MemOperand(scratch2));
  __ Daddu(bytecode_offset, bytecode_offset, scratch2);

  __ bind(&end);
}

namespace {

void ResetSharedFunctionInfoAge(MacroAssembler* masm, Register sfi) {
  __ Sh(zero_reg, FieldMemOperand(sfi, SharedFunctionInfo::kAgeOffset));
}

void ResetJSFunctionAg
"""


```