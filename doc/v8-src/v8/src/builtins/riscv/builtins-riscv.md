Response: The user wants a summary of the C++ source code file `v8/src/builtins/riscv/builtins-riscv.cc`.
This is the first part of a three-part file.

The file seems to define built-in functions for the RISC-V architecture within the V8 JavaScript engine. It includes code generation for various scenarios, such as:

- Function calls and constructions
- Handling arguments
- Stack frame management
- Generator functions
- Exception handling
- Interaction with the interpreter and baseline compiler
- Optimizations

Since it's part 1 of 3, it likely handles foundational built-ins and mechanisms.

Let's break down the key components and their likely functions based on the code:

- **`Builtins::Generate_Adaptor`**:  Likely creates a bridge between JavaScript and C++ functions.
- **`Generate_PushArguments`**:  A helper function for managing arguments passed to functions.
- **`Generate_JSBuiltinsConstructStubHelper` and `Builtins::Generate_JSConstructStubGeneric`**: Handle the process of constructing JavaScript objects.
- **`Builtins::Generate_JSBuiltinsConstructStub`**:  A specific construct stub.
- **`GetSharedFunctionInfoBytecodeOrBaseline`**:  Retrieves either the bytecode or baseline code for a function. This hints at the tiered compilation approach in V8.
- **`Builtins::Generate_ResumeGeneratorTrampoline`**:  Manages the resumption of JavaScript generator functions.
- **`Builtins::Generate_ConstructedNonConstructable`**: Handles errors when `new` is used on a non-constructor.
- **`Generate_CheckStackOverflow`**:  Ensures sufficient stack space.
- **`Generate_JSEntryVariant`, `Builtins::Generate_JSEntry`, `Builtins::Generate_JSConstructEntry`, `Builtins::Generate_JSRunMicrotasksEntry`**:  Entry points for JavaScript execution from C++, handling different call types.
- **`Generate_JSEntryTrampolineHelper`, `Builtins::Generate_JSEntryTrampoline`, `Builtins::Generate_JSConstructEntryTrampoline`, `Builtins::Generate_RunMicrotasksTrampoline`**: Trampolines to set up the environment before actual JavaScript execution.
- **`LeaveInterpreterFrame`**:  Cleans up the stack after interpreter execution.
- **`AdvanceBytecodeOffsetOrReturn`**:  Manages the progression of the interpreter through bytecode.
- **`ResetSharedFunctionInfoAge`, `ResetJSFunctionAge`, `ResetFeedbackVectorOsrUrgency`**:  Functions related to V8's optimization and tiering system.
- **`Builtins::Generate_BaselineOutOfLinePrologueDeopt`, `Builtins::Generate_BaselineOutOfLinePrologue`**:  Code related to V8's baseline compiler and handling deoptimization.
- **`Builtins::Generate_InterpreterEntryTrampoline`**:  The main entry point for executing JavaScript code using the interpreter.
- **`GenerateInterpreterPushArgs`, `Builtins::Generate_InterpreterPushArgsThenCallImpl`, `Builtins::Generate_InterpreterPushArgsThenConstructImpl`**:  Functions for preparing and executing calls and constructions within the interpreter.
- **`Builtins::Generate_ConstructForwardAllArgsImpl`**:  Handles forwarding arguments during construction.
- **`NewImplicitReceiver`**:  Creates an implicit receiver object for constructors.
- **`Builtins::Generate_InterpreterPushArgsThenFastConstructFunction`**:  A fast path for constructing functions within the interpreter.
- **`Generate_InterpreterEnterBytecode`**:  Sets up the environment to begin interpreting bytecode.

Based on this analysis, the core function of this part of the file is to provide the foundational building blocks for executing JavaScript code on the RISC-V architecture within V8, including handling function calls, object construction, and the entry point into the interpreter.
这个C++源代码文件 `v8/src/builtins/riscv/builtins-riscv.cc` 的**第1部分**主要定义了 V8 JavaScript 引擎在 RISC-V 架构上的**内置函数 (builtins)** 的代码生成逻辑。 这些内置函数是 V8 虚拟机执行 JavaScript 代码的关键组成部分，它们通常是用汇编语言实现的，用于执行一些底层的、性能敏感的操作。

具体来说，这部分代码涵盖了以下功能：

1. **函数调用适配器 (Adaptor)**:  `Builtins::Generate_Adaptor` 用于生成将 JavaScript 调用桥接到 C++ 函数的适配器代码。

2. **参数处理 (Argument Handling)**: 提供了 `Generate_PushArguments` 这样的辅助函数，用于将参数从内存或寄存器推入栈中，为函数调用做准备。

3. **对象构造 (Object Construction)**: 包含了多种用于创建 JavaScript 对象的代码生成逻辑，例如 `Generate_JSBuiltinsConstructStubHelper` 和 `Builtins::Generate_JSConstructStubGeneric`，分别处理不同类型的构造函数调用。

4. **函数信息获取 (Function Information Retrieval)**:  `GetSharedFunctionInfoBytecodeOrBaseline` 负责获取函数的字节码或基线代码，这是 V8 进行代码执行和优化的基础。

5. **生成器函数恢复 (Generator Function Resumption)**: `Builtins::Generate_ResumeGeneratorTrampoline` 用于生成恢复执行暂停的 JavaScript 生成器函数的代码。

6. **构造不可构造对象错误处理 (Non-Constructable Error Handling)**: `Builtins::Generate_ConstructedNonConstructable` 处理尝试使用 `new` 运算符调用非构造函数时抛出的错误。

7. **栈溢出检查 (Stack Overflow Check)**: `Generate_CheckStackOverflow` 用于在函数调用前检查是否有足够的栈空间。

8. **JavaScript 入口 (JavaScript Entry Points)**:  定义了多种 JavaScript 代码的入口点，例如 `Builtins::Generate_JSEntry` (标准调用) 和 `Builtins::Generate_JSConstructEntry` (构造函数调用)，以及用于运行微任务的入口 `Builtins::Generate_JSRunMicrotasksEntry`。这些入口点负责设置执行环境，并将控制权转移到 JavaScript 代码。

9. **JavaScript 入口跳板 (JavaScript Entry Trampolines)**:  提供了 `Builtins::Generate_JSEntryTrampoline` 和 `Builtins::Generate_JSConstructEntryTrampoline` 等跳板函数，用于在进入实际的 JavaScript 代码执行之前进行必要的设置，例如创建栈帧、保存寄存器等。

10. **解释器框架管理 (Interpreter Frame Management)**:  `LeaveInterpreterFrame` 负责在解释器执行完成后清理栈帧。

11. **字节码偏移推进 (Bytecode Offset Advancement)**: `AdvanceBytecodeOffsetOrReturn` 用于在解释器执行完一条字节码指令后，更新字节码的偏移量，以便执行下一条指令。

12. **代码老化和优化 (Code Aging and Optimization)**:  包含了一些用于重置函数或反馈向量状态的函数，例如 `ResetSharedFunctionInfoAge` 和 `ResetFeedbackVectorOsrUrgency`，这与 V8 的代码优化和分层编译机制有关。

13. **基线编译 (Baseline Compilation)**: `Builtins::Generate_BaselineOutOfLinePrologueDeopt` 和 `Builtins::Generate_BaselineOutOfLinePrologue` 涉及 V8 基线编译器的代码生成和反优化处理。

14. **解释器入口跳板 (Interpreter Entry Trampoline)**:  `Builtins::Generate_InterpreterEntryTrampoline` 是 V8 解释器的主要入口点，负责设置解释器执行环境，并跳转到相应的字节码进行执行。

15. **解释器参数传递 (Interpreter Argument Passing)**: 提供了 `GenerateInterpreterPushArgs` 以及相关的 `Builtins::Generate_InterpreterPushArgsThenCallImpl` 和 `Builtins::Generate_InterpreterPushArgsThenConstructImpl`，用于在解释器中进行函数调用和对象构造时传递参数。

16. **快速构造函数调用 (Fast Function Construction)**:  `Builtins::Generate_InterpreterPushArgsThenFastConstructFunction` 提供了一种优化的方式来构造函数对象。

**与 JavaScript 的关系及示例:**

这部分代码直接关系到 JavaScript 代码的执行。例如，当你在 JavaScript 中调用一个函数或者使用 `new` 关键字创建一个对象时，V8 引擎最终会执行这里定义的相应的内置函数。

**JavaScript 示例:**

```javascript
function myFunction(a, b) {
  return a + b;
}

let myObject = new myFunction(1, 2); // 这里会涉及到对象构造相关的内置函数

myFunction(3, 4); // 这里会涉及到函数调用相关的内置函数
```

**具体到代码中的功能，可以举例说明：**

- 当 JavaScript 引擎需要调用 `myFunction(3, 4)` 时，`Builtins::Generate_JSEntryTrampoline` 可能会被调用来设置执行环境，然后跳转到实际的函数代码（可能是解释器执行，也可能是编译后的代码）。
- 当执行 `let myObject = new myFunction(1, 2)` 时，`Builtins::Generate_JSConstructStubGeneric` 或 `Builtins::Generate_InterpreterPushArgsThenFastConstructFunction` 等函数会被调用来创建新的对象实例。
- 如果 `myFunction` 是一个生成器函数，当调用 `myFunction().next()` 时，`Builtins::Generate_ResumeGeneratorTrampoline` 会被调用来恢复生成器的执行。

总而言之，这部分代码是 V8 引擎在 RISC-V 架构上实现 JavaScript 核心功能的基石，它定义了执行 JavaScript 代码所需的关键底层操作。

Prompt: 
```
这是目录为v8/src/builtins/riscv/builtins-riscv.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/api/api-arguments.h"
#include "src/builtins/builtins-descriptors.h"
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
#include "src/wasm/object-access.h"
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-objects.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

#define __ ACCESS_MASM(masm)

void Builtins::Generate_Adaptor(MacroAssembler* masm,
                                int formal_parameter_count, Address address) {
  ASM_CODE_COMMENT(masm);
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
  ASM_CODE_COMMENT(masm);
  DCHECK(!AreAliased(array, argc, scratch));
  Label loop, entry;
  __ SubWord(scratch, argc, Operand(kJSArgcReceiverSlots));
  __ Branch(&entry);
  __ bind(&loop);
  __ CalcScaledAddress(scratch2, array, scratch, kSystemPointerSizeLog2);
  __ LoadWord(scratch2, MemOperand(scratch2));
  if (element_type == ArgumentsElementType::kHandle) {
    __ LoadWord(scratch2, MemOperand(scratch2));
  }
  __ push(scratch2);
  __ bind(&entry);
  __ AddWord(scratch, scratch, Operand(-1));
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
    __ AddWord(
        t2, fp,
        Operand(StandardFrameConstants::kCallerSPOffset + kSystemPointerSize));
    // t2: Pointer to start of arguments.
    // a0: Number of arguments.
    {
      UseScratchRegisterScope temps(masm);
      temps.Include(t0);
      Generate_PushArguments(masm, t2, a0, temps.Acquire(), temps.Acquire(),
                             ArgumentsElementType::kRaw);
    }
    // The receiver for the builtin/api call.
    __ PushRoot(RootIndex::kTheHoleValue);

    // Call the function.
    // a0: number of arguments (untagged)
    // a1: constructor function
    // a3: new target
    __ InvokeFunctionWithNewTarget(a1, a3, a0, InvokeType::kCall);

    // Restore context from the frame.
    __ LoadWord(cp, MemOperand(fp, ConstructFrameConstants::kContextOffset));
    // Restore arguments count from the frame.
    __ LoadWord(kScratchReg,
                MemOperand(fp, ConstructFrameConstants::kLengthOffset));
    // Leave construct frame.
  }

  // Remove caller arguments from the stack and return.
  __ DropArguments(kScratchReg);
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
  UseScratchRegisterScope temps(masm);
  temps.Include(t0, t1);
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
  {
    UseScratchRegisterScope temps(masm);
    Register func_info = temps.Acquire();
    __ LoadTaggedField(
        func_info, FieldMemOperand(a1, JSFunction::kSharedFunctionInfoOffset));
    __ Load32U(func_info,
               FieldMemOperand(func_info, SharedFunctionInfo::kFlagsOffset));
    __ DecodeField<SharedFunctionInfo::FunctionKindBits>(func_info);
    __ JumpIfIsInRange(
        func_info,
        static_cast<uint32_t>(FunctionKind::kDefaultDerivedConstructor),
        static_cast<uint32_t>(FunctionKind::kDerivedConstructor),
        &not_create_implicit_receiver);
    // If not derived class constructor: Allocate the new receiver object.
    __ CallBuiltin(Builtin::kFastNewObject);
    __ BranchShort(&post_instantiation_deopt_entry);

    // Else: use TheHoleValue as receiver for constructor call
    __ bind(&not_create_implicit_receiver);
    __ LoadRoot(a0, RootIndex::kTheHoleValue);
  }
  // ----------- S t a t e -------------
  //  --                          a0: receiver
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
  __ Push(a0);

  // We need two copies because we may have to return the original one
  // and the calling conventions dictate that the called function pops the
  // receiver. The second copy is pushed after the arguments, we saved in a6
  // since a0 will store the return value of callRuntime.
  __ Move(a6, a0);

  // Set up pointer to first argument (skip receiver)..
  __ AddWord(
      t2, fp,
      Operand(StandardFrameConstants::kCallerSPOffset + kSystemPointerSize));

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
  __ LoadWord(a1, MemOperand(fp, ConstructFrameConstants::kConstructorOffset));
  __ LoadWord(a0, MemOperand(fp, ConstructFrameConstants::kLengthOffset));

  Label stack_overflow;
  {
    UseScratchRegisterScope temps(masm);
    __ StackOverflowCheck(a0, temps.Acquire(), temps.Acquire(),
                          &stack_overflow);
  }
  // TODO(victorgomes): When the arguments adaptor is completely removed, we
  // should get the formal parameter count and copy the arguments in its
  // correct position (including any undefined), instead of delaying this to
  // InvokeFunction.

  // Copy arguments and receiver to the expression stack.
  // t2: Pointer to start of argument.
  // a0: Number of arguments.
  {
    UseScratchRegisterScope temps(masm);
    Generate_PushArguments(masm, t2, a0, temps.Acquire(), temps.Acquire(),
                           ArgumentsElementType::kRaw);
  }
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
  __ JumpIfNotRoot(a0, RootIndex::kUndefinedValue, &check_receiver);

  // Otherwise we do a smi check and fall through to check if the return value
  // is a valid receiver.

  // Throw away the result of the constructor invocation and use the
  // on-stack receiver as the result.
  __ bind(&use_receiver);
  __ LoadWord(a0, MemOperand(sp, 0 * kSystemPointerSize));
  __ JumpIfRoot(a0, RootIndex::kTheHoleValue, &do_throw);

  __ bind(&leave_and_return);
  // Restore  arguments count from the frame.
  __ LoadWord(a1, MemOperand(fp, ConstructFrameConstants::kLengthOffset));
  // Leave construct frame.
  __ LeaveFrame(StackFrame::CONSTRUCT);

  // Remove caller arguments from the stack and return.
  __ DropArguments(a1);
  __ Ret();

  __ bind(&check_receiver);
  __ JumpIfSmi(a0, &use_receiver);

  // If the type of the result (stored in its map) is less than
  // FIRST_JS_RECEIVER_TYPE, it is not an object in the ECMA sense.
  {
    UseScratchRegisterScope temps(masm);
    Register map = temps.Acquire(), type = temps.Acquire();
    __ GetObjectType(a0, map, type);

    static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
    __ Branch(&leave_and_return, greater_equal, type,
              Operand(FIRST_JS_RECEIVER_TYPE));
    __ Branch(&use_receiver);
  }
  __ bind(&do_throw);
  // Restore the context from the frame.
  __ LoadWord(cp, MemOperand(fp, ConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowConstructorReturnedNonObject);
  __ break_(0xCC);

  __ bind(&stack_overflow);
  // Restore the context from the frame.
  __ LoadWord(cp, MemOperand(fp, ConstructFrameConstants::kContextOffset));
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
  __ LoadWord(scratch, FieldMemOperand(code, Code::kFlagsOffset));
  __ DecodeField<Code::KindField>(scratch);
  __ Assert(eq, AbortReason::kExpectedBaselineData, scratch,
            Operand(static_cast<int64_t>(CodeKind::BASELINE)));
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
  __ LoadProtectedPointerField(
      bytecode, FieldMemOperand(data, InterpreterData::kBytecodeArrayOffset));
  __ bind(&done);
}

// static
void Builtins::Generate_ResumeGeneratorTrampoline(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- a0 : the value to pass to the generator
  //  -- a1 : the JSGeneratorObject to resume
  //  -- ra : return address
  // -----------------------------------
  // Store input value into generator object.
  __ StoreTaggedField(
      a0, FieldMemOperand(a1, JSGeneratorObject::kInputOrDebugPosOffset));
  __ RecordWriteField(a1, JSGeneratorObject::kInputOrDebugPosOffset, a0,
                      kRAHasNotBeenSaved, SaveFPRegsMode::kIgnore);
  // Check that a1 is still valid, RecordWrite might have clobbered it.
  __ AssertGeneratorObject(a1);

  // Load suspended function and context.
  __ LoadTaggedField(a4,
                     FieldMemOperand(a1, JSGeneratorObject::kFunctionOffset));
  __ LoadTaggedField(cp, FieldMemOperand(a4, JSFunction::kContextOffset));

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
  __ LoadWord(a5, MemOperand(a5));
  __ Branch(&prepare_step_in_suspended_generator, eq, a1, Operand(a5));
  __ bind(&stepping_prepared);

  // Check the stack for overflow. We are not trying to catch interruptions
  // (i.e. debug break and preemption) here, so check the "real stack limit".
  Label stack_overflow;
  __ LoadStackLimit(kScratchReg, StackLimitKind::kRealStackLimit);
  __ Branch(&stack_overflow, Uless, sp, Operand(kScratchReg));

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
  __ LoadTaggedField(
      a3, FieldMemOperand(a4, JSFunction::kSharedFunctionInfoOffset));
  __ Lhu(a3,
         FieldMemOperand(a3, SharedFunctionInfo::kFormalParameterCountOffset));
  __ SubWord(a3, a3, Operand(kJSArgcReceiverSlots));
  __ LoadTaggedField(
      t1,
      FieldMemOperand(a1, JSGeneratorObject::kParametersAndRegistersOffset));
  {
    Label done_loop, loop;
    __ bind(&loop);
    __ SubWord(a3, a3, Operand(1));
    __ Branch(&done_loop, lt, a3, Operand(zero_reg), Label::Distance::kNear);
    __ CalcScaledAddress(kScratchReg, t1, a3, kTaggedSizeLog2);
    __ LoadTaggedField(
        kScratchReg,
        FieldMemOperand(kScratchReg, OFFSET_OF_DATA_START(FixedArray)));
    __ Push(kScratchReg);
    __ Branch(&loop);
    __ bind(&done_loop);
    // Push receiver.
    __ LoadTaggedField(kScratchReg,
                       FieldMemOperand(a1, JSGeneratorObject::kReceiverOffset));
    __ Push(kScratchReg);
  }

  // Underlying function needs to have bytecode available.
  if (v8_flags.debug_code) {
    Label ok, is_baseline, is_unavailable;
    Register sfi = a3;
    Register bytecode = a3;
    __ LoadTaggedField(
        sfi, FieldMemOperand(a4, JSFunction::kSharedFunctionInfoOffset));
    GetSharedFunctionInfoBytecodeOrBaseline(masm, sfi, bytecode, t5,
                                            &is_baseline, &is_unavailable);
    __ Branch(&ok);
    __ bind(&is_unavailable);
    __ Abort(AbortReason::kMissingBytecodeArray);
    __ bind(&is_baseline);
    __ GetObjectType(bytecode, t5, t5);
    __ Assert(eq, AbortReason::kMissingBytecodeArray, t5, Operand(CODE_TYPE));
    __ bind(&ok);
  }

  // Resume (Ignition/TurboFan) generator object.
  {
    __ LoadTaggedField(
        a0, FieldMemOperand(a4, JSFunction::kSharedFunctionInfoOffset));
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
  __ LoadTaggedField(a4,
                     FieldMemOperand(a1, JSGeneratorObject::kFunctionOffset));
  __ Branch(&stepping_prepared);

  __ bind(&prepare_step_in_suspended_generator);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ Push(a1);
    __ CallRuntime(Runtime::kDebugPrepareStepInSuspendedGenerator);
    __ Pop(a1);
  }
  __ LoadTaggedField(a4,
                     FieldMemOperand(a1, JSGeneratorObject::kFunctionOffset));
  __ Branch(&stepping_prepared);

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
  __ LoadStackLimit(scratch1, StackLimitKind::kRealStackLimit);
  // Make a2 the space we have left. The stack might already be overflowed
  // here which will cause r2 to become negative.
  __ SubWord(scratch1, sp, scratch1);
  // Check if the arguments will overflow the stack.
  __ SllWord(scratch2, argc, kSystemPointerSizeLog2);
  __ Branch(&okay, gt, scratch1, Operand(scratch2),
            Label::Distance::kNear);  // Signed comparison.

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

    // Save callee saved registers on the stack.
    __ MultiPush(kCalleeSaved | ra);

    // Save callee-saved FPU registers.
    __ MultiPushFPU(kCalleeSavedFPU);
    // Set up the reserved register for 0.0.
    __ LoadFPRImmediate(kDoubleRegZero, 0.0);
    __ LoadFPRImmediate(kSingleRegZero, 0.0f);

    // Initialize the root register.
    // C calling convention. The first argument is passed in a0.
    __ Move(kRootRegister, a0);

#ifdef V8_COMPRESS_POINTERS
    // Initialize the pointer cage base register.
    __ LoadRootRelative(kPtrComprCageBaseRegister,
                        IsolateData::cage_base_offset());
#endif
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
  __ LoadWord(s4, MemOperand(s5));
  __ Push(s1, s2, s3, s4);
  // Clear c_entry_fp, now we've pushed its previous value to the stack.
  // If the c_entry_fp is not already zero and we don't clear it, the
  // StackFrameIteratorForProfiler will assume we are executing C++ and miss the
  // JS frames on top.
  __ StoreWord(zero_reg, MemOperand(s5));

  __ LoadIsolateField(s1, IsolateFieldId::kFastCCallCallerFP);
  __ LoadWord(s2, MemOperand(s1, 0));
  __ StoreWord(zero_reg, MemOperand(s1, 0));

  __ LoadIsolateField(s1, IsolateFieldId::kFastCCallCallerPC);
  __ LoadWord(s3, MemOperand(s1, 0));
  __ StoreWord(zero_reg, MemOperand(s1, 0));
  __ Push(s2, s3);
  // Set up frame pointer for the frame to be pushed.
  __ AddWord(fp, sp, -EntryFrameConstants::kNextFastCallFramePCOffset);
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
  // fast api call pc
  // fast api call fp
  // caller fp          |
  // function slot      | entry frame
  // context slot       |
  // bad fp (0xFF...F)  |
  // callee saved registers + ra

  // If this is the outermost JS call, set js_entry_sp value.
  Label non_outermost_js;
  ExternalReference js_entry_sp = ExternalReference::Create(
      IsolateAddressId::kJSEntrySPAddress, masm->isolate());
  __ li(s1, js_entry_sp);
  __ LoadWord(s2, MemOperand(s1));
  __ Branch(&non_outermost_js, ne, s2, Operand(zero_reg),
            Label::Distance::kNear);
  __ StoreWord(fp, MemOperand(s1));
  __ li(s3, Operand(StackFrame::OUTERMOST_JSENTRY_FRAME));
  Label cont;
  __ Branch(&cont);
  __ bind(&non_outermost_js);
  __ li(s3, Operand(StackFrame::INNER_JSENTRY_FRAME));
  __ bind(&cont);
  __ push(s3);

  // Jump to a faked try block that does the invoke, with a faked catch
  // block that sets the exception.
  __ BranchShort(&invoke);
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
  __ StoreWord(a0,
               MemOperand(s1));  // We come back from 'invoke'. result is in a0.
  __ LoadRoot(a0, RootIndex::kException);
  __ BranchShort(&exit);

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
  // fast api call pc.
  // fast api call fp.
  // JS entry frame marker
  // caller fp          |
  // function slot      | entry frame
  // context slot       |
  // bad fp (0xFF...F)  |
  // handler frame
  // entry frame
  // callee saved registers + ra
  // [ O32: 4 args slots]
  // args
  //
  // Invoke the function by calling through JS entry trampoline builtin and
  // pop the faked function when we return.
  __ CallBuiltin(entry_trampoline);

  // Unlink this frame from the handler chain.
  __ PopStackHandler();

  __ bind(&exit);  // a0 holds result
  // Check if the current stack frame is marked as the outermost JS frame.

  Label non_outermost_js_2;
  __ pop(a5);
  __ Branch(&non_outermost_js_2, ne, a5,
            Operand(StackFrame::OUTERMOST_JSENTRY_FRAME),
            Label::Distance::kNear);
  __ li(a5, js_entry_sp);
  __ StoreWord(zero_reg, MemOperand(a5));
  __ bind(&non_outermost_js_2);

  __ Pop(s2, s3);
  __ LoadIsolateField(s1, IsolateFieldId::kFastCCallCallerFP);
  __ StoreWord(s2, MemOperand(s1, 0));
  __ LoadIsolateField(s1, IsolateFieldId::kFastCCallCallerPC);
  __ StoreWord(s3, MemOperand(s1, 0));
  // Restore the top frame descriptors from the stack.
  __ pop(a5);
  __ li(a4, ExternalReference::Create(IsolateAddressId::kCEntryFPAddress,
                                      masm->isolate()));
  __ StoreWord(a5, MemOperand(a4));

  // Reset the stack to the callee saved registers.
  __ AddWord(sp, sp, -EntryFrameConstants::kNextExitFrameFPOffset);

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
    __ LoadWord(cp, MemOperand(cp));

    // Push the function onto the stack.
    __ Push(a2);

    // Check if we have enough stack space to push all arguments.
    __ mv(a6, a4);
    Generate_CheckStackOverflow(masm, a6, a0, s2);

    // Copy arguments to the stack.
    // a4: argc
    // a5: argv, i.e. points to first arg
    {
      UseScratchRegisterScope temps(masm);
      Generate_PushArguments(masm, a5, a4, temps.Acquire(), temps.Acquire(),
                             ArgumentsElementType::kHandle);
    }
    // Push the receive.
    __ Push(a3);

    // a0: argc
    // a1: function
    // a3: new.target
    __ Move(a3, a1);
    __ Move(a1, a2);
    __ Move(a0, a4);

    // Initialize all JavaScript callee-saved registers, since they will be seen
    // by the garbage collector as part of handlers.
    __ LoadRoot(a4, RootIndex::kUndefinedValue);
    __ Move(a5, a4);
    __ Move(s1, a4);
    __ Move(s2, a4);
    __ Move(s3, a4);
    __ Move(s4, a4);
    __ Move(s5, a4);
    __ Move(s8, a4);
    __ Move(s9, a4);
    __ Move(s10, a4);
#ifndef V8_COMPRESS_POINTERS
    __ Move(s11, a4);
#endif
    // s6 holds the root address. Do not clobber.
    // s7 is cp. Do not init.
    // s11 is pointer cage base register (kPointerCageBaseRegister).

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
  __ Move(RunMicrotasksDescriptor::MicrotaskQueueRegister(), a1);
  __ TailCallBuiltin(Builtin::kRunMicrotasks);
}

static void LeaveInterpreterFrame(MacroAssembler* masm, Register scratch1,
                                  Register scratch2) {
  ASM_CODE_COMMENT(masm);
  Register params_size = scratch1;

  // Get the size of the formal parameters + receiver (in bytes).
  __ LoadWord(params_size,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ Lhu(params_size,
         FieldMemOperand(params_size, BytecodeArray::kParameterSizeOffset));

  Register actual_params_size = scratch2;
  Label L1;
  // Compute the size of the actual parameters + receiver (in bytes).
  __ LoadWord(actual_params_size,
              MemOperand(fp, StandardFrameConstants::kArgCOffset));
  // If actual is bigger than formal, then we should use it to free up the stack
  // arguments.
  __ Branch(&L1, le, actual_params_size, Operand(params_size),
            Label::Distance::kNear);
  __ Move(params_size, actual_params_size);
  __ bind(&L1);

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
                                          Register scratch2, Register scratch3,
                                          Label* if_return) {
  ASM_CODE_COMMENT(masm);
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
  __ Branch(&process_bytecode, Ugreater, bytecode, Operand(3),
            Label::Distance::kNear);
  __ And(scratch2, bytecode, Operand(1));
  __ Branch(&extra_wide, ne, scratch2, Operand(zero_reg),
            Label::Distance::kNear);

  // Load the next bytecode and update table to the wide scaled table.
  __ AddWord(bytecode_offset, bytecode_offset, Operand(1));
  __ AddWord(scratch2, bytecode_array, bytecode_offset);
  __ Lbu(bytecode, MemOperand(scratch2));
  __ AddWord(bytecode_size_table, bytecode_size_table,
             Operand(kByteSize * interpreter::Bytecodes::kBytecodeCount));
  __ BranchShort(&process_bytecode);

  __ bind(&extra_wide);
  // Load the next bytecode and update table to the extra wide scaled table.
  __ AddWord(bytecode_offset, bytecode_offset, Operand(1));
  __ AddWord(scratch2, bytecode_array, bytecode_offset);
  __ Lbu(bytecode, MemOperand(scratch2));
  __ AddWord(bytecode_size_table, bytecode_size_table,
             Operand(2 * kByteSize * interpreter::Bytecodes::kBytecodeCount));

  __ bind(&process_bytecode);

// Bailout to the return label if this is a return bytecode.
#define JUMP_IF_EQUAL(NAME)          \
  __ Branch(if_return, eq, bytecode, \
            Operand(static_cast<int64_t>(interpreter::Bytecode::k##NAME)));
  RETURN_BYTECODE_LIST(JUMP_IF_EQUAL)
#undef JUMP_IF_EQUAL

  // If this is a JumpLoop, re-execute it to perform the jump to the beginning
  // of the loop.
  Label end, not_jump_loop;
  __ Branch(&not_jump_loop, ne, bytecode,
            Operand(static_cast<int64_t>(interpreter::Bytecode::kJumpLoop)),
            Label::Distance::kNear);
  // We need to restore the original bytecode_offset since we might have
  // increased it to skip the wide / extra-wide prefix bytecode.
  __ Move(bytecode_offset, original_bytecode_offset);
  __ BranchShort(&end);

  __ bind(&not_jump_loop);
  // Otherwise, load the size of the current bytecode and advance the offset.
  __ AddWord(scratch2, bytecode_size_table, bytecode);
  __ Lb(scratch2, MemOperand(scratch2));
  __ AddWord(bytecode_offset, bytecode_offset, scratch2);

  __ bind(&end);
}

namespace {
void ResetSharedFunctionInfoAge(MacroAssembler* masm, Register sfi) {
  __ Sh(zero_reg, FieldMemOperand(sfi, SharedFunctionInfo::kAgeOffset));
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
  __ Lbu(scratch,
         FieldMemOperand(feedback_vector, FeedbackVector::kOsrStateOffset));
  __ And(scratch, scratch, Operand(~FeedbackVector::OsrUrgencyBits::kMask));
  __ Sb(scratch,
        FieldMemOperand(feedback_vector, FeedbackVector::kOsrStateOffset));
}

}  // namespace

// static
void Builtins::Generate_BaselineOutOfLinePrologueDeopt(MacroAssembler* masm) {
  // We're here because we got deopted during BaselineOutOfLinePrologue's stack
  // check. Undo all its frame creation and call into the interpreter instead.

  // Drop bytecode offset (was the feedback vector but got replaced during
  // deopt) and bytecode array.
  __ AddWord(sp, sp, Operand(3 * kSystemPointerSize));

  // Context, closure, argc.
  __ Pop(kContextRegister, kJavaScriptCallTargetRegister,
         kJavaScriptCallArgCountRegister);

  // Drop frame pointer
  __ LeaveFrame(StackFrame::BASELINE);

  // Enter the interpreter.
  __ TailCallBuiltin(Builtin::kInterpreterEntryTrampoline);
}

void Builtins::Generate_BaselineOutOfLinePrologue(MacroAssembler* masm) {
  UseScratchRegisterScope temps(masm);
  temps.Include({kScratchReg, kScratchReg2, s1});
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
    UseScratchRegisterScope temp(masm);
    Register type = temps.Acquire();
    __ AssertFeedbackVector(feedback_vector, type);
  }

  // Check for an tiering state.
  Label flags_need_processing;
  Register flags = temps.Acquire();
  __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
      flags, feedback_vector, CodeKind::BASELINE, &flags_need_processing);
  {
    UseScratchRegisterScope temps(masm);
    ResetFeedbackVectorOsrUrgency(masm, feedback_vector, temps.Acquire());
  }
  // Increment invocation count for the function.
  {
    UseScratchRegisterScope temps(masm);
    Register invocation_count = temps.Acquire();
    __ Lw(invocation_count,
          FieldMemOperand(feedback_vector,
                          FeedbackVector::kInvocationCountOffset));
    __ Add32(invocation_count, invocation_count, Operand(1));
    __ Sw(invocation_count,
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
    // Baseline code frames store the feedback vector where interpreter would
    // store the bytecode offset.
    {
      UseScratchRegisterScope temp(masm);
      Register type = temps.Acquire();
      __ AssertFeedbackVector(feedback_vector, type);
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
    __ SubWord(sp_minus_frame_size, sp, frame_size);
    Register interrupt_limit = temps.Acquire();
    __ LoadStackLimit(interrupt_limit, StackLimitKind::kInterruptStackLimit);
    __ Branch(&call_stack_guard, Uless, sp_minus_frame_size,
              Operand(interrupt_limit));
  }

  // Do "fast" return to the caller pc in lr.
  // TODO(v8:11429): Document this frame setup better.
  __ Ret();

  __ bind(&flags_need_processing);
  {
    ASM_CODE_COMMENT_STRING(masm, "Optimized marker check");
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
  temps.Exclude({kScratchReg, kScratchReg2, s1});
}

// Generate code for entering a JS function with the interpreter.
// On entry to the function the receiver and arguments have been pushed on the
// stack left to right.
//
// The live registers are:
//   o a0 : actual argument count
//   o a1: the JS function object being called.
//   o a3: the incoming new target or generator object
//   o cp: our context
//   o fp: the caller's frame pointer
//   o sp: stack pointer
//   o ra: return address
//
// The function builds an interpreter frame.  See InterpreterFrameConstants in
// frames-constants.h for its layout.
void Builtins::Generate_InterpreterEntryTrampoline(
    MacroAssembler* masm, InterpreterEntryTrampolineMode mode) {
  Register closure = a1;
  // Get the bytecode array from the function object and load it into
  // kInterpreterBytecodeArrayRegister.
  Register sfi = a4;
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
  __ LoadFeedbackVector(feedback_vector, closure, a4, &push_stack_frame);

#ifndef V8_JITLESS
  // If feedback vector is valid, check for optimized code and update invocation
  // count.

  // Check the tiering state.
  Label flags_need_processing;
  Register flags = a4;
  __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
      flags, feedback_vector, CodeKind::INTERPRETED_FUNCTION,
      &flags_need_processing);
  ResetFeedbackVectorOsrUrgency(masm, feedback_vector, a4);

  // Increment invocation count for the function.
  __ Lw(a4, FieldMemOperand(feedback_vector,
                            FeedbackVector::kInvocationCountOffset));
  __ Add32(a4, a4, Operand(1));
  __ Sw(a4, FieldMemOperand(feedback_vector,
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

  // Push bytecode array, Smi tagged bytecode array offset, and the feedback
  // vector.
  __ SmiTag(a4, kInterpreterBytecodeOffsetRegister);
  __ Push(kInterpreterBytecodeArrayRegister, a4, feedback_vector);

  // Allocate the local and temporary register file on the stack.
  Label stack_overflow;
  {
    // Load frame size (word) from the BytecodeArray object.
    __ Lw(a4, FieldMemOperand(kInterpreterBytecodeArrayRegister,
                              BytecodeArray::kFrameSizeOffset));

    // Do a stack check to ensure we don't go over the limit.
    __ SubWord(a5, sp, Operand(a4));
    __ LoadStackLimit(a2, StackLimitKind::kRealStackLimit);
    __ Branch(&stack_overflow, Uless, a5, Operand(a2));

    // If ok, push undefined as the initial value for all register file entries.
    Label loop_header;
    Label loop_check;
    __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
    __ BranchShort(&loop_check);
    __ bind(&loop_header);
    // TODO(rmcilroy): Consider doing more than one push per loop iteration.
    __ push(kInterpreterAccumulatorRegister);
    // Continue loop if not done.
    __ bind(&loop_check);
    __ SubWord(a4, a4, Operand(kSystemPointerSize));
    __ Branch(&loop_header, ge, a4, Operand(zero_reg));
  }

  // If the bytecode array has a valid incoming new target or generator object
  // register, initialize it with incoming value which was passed in a3.
  Label no_incoming_new_target_or_generator_register;
  __ Lw(a5, FieldMemOperand(
                kInterpreterBytecodeArrayRegister,
                BytecodeArray::kIncomingNewTargetOrGeneratorRegisterOffset));
  __ Branch(&no_incoming_new_target_or_generator_register, eq, a5,
            Operand(zero_reg), Label::Distance::kNear);
  __ CalcScaledAddress(a5, fp, a5, kSystemPointerSizeLog2);
  __ StoreWord(a3, MemOperand(a5));
  __ bind(&no_incoming_new_target_or_generator_register);

  // Perform interrupt stack check.
  // TODO(solanes): Merge with the real stack limit check above.
  Label stack_check_interrupt, after_stack_check_interrupt;
  __ LoadStackLimit(a5, StackLimitKind::kInterruptStackLimit);
  __ Branch(&stack_check_interrupt, Uless, sp, Operand(a5),
            Label::Distance::kNear);
  __ bind(&after_stack_check_interrupt);

  // Load the dispatch table into a register and dispatch to the bytecode
  // handler at the current bytecode offset.
  Label do_dispatch;
  __ bind(&do_dispatch);
  __ li(kInterpreterDispatchTableRegister,
        ExternalReference::interpreter_dispatch_table_address(masm->isolate()));
  __ AddWord(a1, kInterpreterBytecodeArrayRegister,
             kInterpreterBytecodeOffsetRegister);
  __ Lbu(a7, MemOperand(a1));
  __ CalcScaledAddress(kScratchReg, kInterpreterDispatchTableRegister, a7,
                       kSystemPointerSizeLog2);
  __ LoadWord(kJavaScriptCallCodeStartRegister, MemOperand(kScratchReg));
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
  __ LoadWord(kInterpreterBytecodeArrayRegister,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ LoadWord(kInterpreterBytecodeOffsetRegister,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ SmiUntag(kInterpreterBytecodeOffsetRegister);

  // Either return, or advance to the next bytecode and dispatch.
  Label do_return;
  __ AddWord(a1, kInterpreterBytecodeArrayRegister,
             kInterpreterBytecodeOffsetRegister);
  __ Lbu(a1, MemOperand(a1));
  AdvanceBytecodeOffsetOrReturn(masm, kInterpreterBytecodeArrayRegister,
                                kInterpreterBytecodeOffsetRegister, a1, a2, a3,
                                a4, &do_return);
  __ Branch(&do_dispatch);

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
  __ StoreWord(
      kInterpreterBytecodeOffsetRegister,
      MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ CallRuntime(Runtime::kStackGuard);

  // After the call, restore the bytecode array, bytecode offset and accumulator
  // registers again. Also, restore the bytecode offset in the stack to its
  // previous value.
  __ LoadWord(kInterpreterBytecodeArrayRegister,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ li(kInterpreterBytecodeOffsetRegister,
        Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);

  __ SmiTag(a5, kInterpreterBytecodeOffsetRegister);
  __ StoreWord(
      a5, MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

  __ Branch(&after_stack_check_interrupt);

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
    __ Lhu(t0, FieldMemOperand(t0, Map::kInstanceTypeOffset));
    __ Branch(&install_baseline_code, ne, t0, Operand(FEEDBACK_VECTOR_TYPE));

    // Check for an tiering state.
    __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
        flags, feedback_vector, CodeKind::BASELINE, &flags_need_processing);

#ifndef V8_ENABLE_LEAPTIERING
    // TODO(olivf, 42204201): This fastcase is difficult to support with the
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
                                        Register scratch) {
  ASM_CODE_COMMENT(masm);
  // Find the address of the last argument.
  __ SubWord(scratch, num_args, Operand(1));
  __ SllWord(scratch, scratch, kSystemPointerSizeLog2);
  __ SubWord(start_address, start_address, scratch);

  // Push the arguments.
  __ PushArray(start_address, num_args,
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
    __ SubWord(a0, a0, Operand(1));
  }

  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    __ SubWord(a3, a0, Operand(kJSArgcReceiverSlots));
  } else {
    __ Move(a3, a0);
  }
  __ StackOverflowCheck(a3, a4, t0, &stack_overflow);

  // This function modifies a2 and a4.
  GenerateInterpreterPushArgs(masm, a3, a2, a4);
  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    __ PushRoot(RootIndex::kUndefinedValue);
  }

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Pass the spread in the register a2.
    // a2 already points to the penultime argument, the spread
    // is below that.
    __ LoadWord(a2, MemOperand(a2, -kSystemPointerSize));
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
    __ SubWord(a0, a0, Operand(1));
  }
  Register argc_without_receiver = a6;
  __ SubWord(argc_without_receiver, a0, Operand(kJSArgcReceiverSlots));
  // Push the arguments, This function modifies a4 and a5.
  GenerateInterpreterPushArgs(masm, argc_without_receiver, a4, a5);

  // Push a slot for the receiver.
  __ push(zero_reg);

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Pass the spread in the register a2.
    // a4 already points to the penultimate argument, the spread
    // lies in the next interpreter register.
    __ LoadWord(a2, MemOperand(a4, -kSystemPointerSize));
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
      __ LoadWord(a4, MemOperand(fp, StandardFrameConstants::kCallerFPOffset));
      break;
  }

  // Load the argument count into a0.
  __ LoadWord(a0, MemOperand(a4, StandardFrameConstants::kArgCOffset));
  __ StackOverflowCheck(a0, a5, t0, &stack_overflow);

  // Point a4 to the base of the argument list to forward, excluding the
  // receiver.
  __ AddWord(a4, a4,
             Operand((StandardFrameConstants::kFixedSlotCountAboveFp + 1) *
                     kSystemPointerSize));

  // Copy arguments on the stack. a5 is a scratch register.
  Register argc_without_receiver = a6;
  __ SubWord(argc_without_receiver, a0, Operand(kJSArgcReceiverSlots));
  __ PushArray(a4, argc_without_receiver);

  // Push a slot for the receiver.
  __ push(zero_reg);

  // Call the constructor with a0, a1, and a3 unmodified.
  __ TailCallBuiltin(Builtin::kConstruct);

  __ bind(&stack_overflow);
  {
    __ TailCallRuntime(Runtime::kThrowStackOverflow);
    // Unreachable code.
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
  __ mv(implicit_receiver, a0);
  __ Pop(a0, a1, a3);
  __ SmiUntag(a0);

  // Patch implicit receiver (in arguments)
  __ StoreReceiver(implicit_receiver);
  // Patch second implicit (in construct frame)
  __ StoreWord(
      implicit_receiver,
      MemOperand(fp, FastConstructFrameConstants::kImplicitReceiverOffset));

  // Restore context.
  __ LoadWord(cp, MemOperand(fp, FastConstructFrameConstants::kContextOffset));
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
  __ Lbu(a2, FieldMemOperand(a2, Map::kBitFieldOffset));
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
  __ SubWord(argc_without_receiver, a0, Operand(kJSArgcReceiverSlots));
  GenerateInterpreterPushArgs(masm, argc_without_receiver, a4, a5);
  __ Push(a2);

  // Check if it is a builtin call.
  Label builtin_call;
  __ LoadTaggedField(
      a2, FieldMemOperand(a1, JSFunction::kSharedFunctionInfoOffset));
  __ Load32U(a2, FieldMemOperand(a2, SharedFunctionInfo::kFlagsOffset));
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
  //  -- x0     constructor result
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
  __ LoadWord(
      a0, MemOperand(fp, FastConstructFrameConstants::kImplicitReceiverOffset));
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
  __ LoadWord(cp, MemOperand(fp, FastConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowConstructorReturnedNonObject);
  // Unreachable code.
  __ Trap();

  __ bind(&stack_overflow);
  __ TailCallRuntime(Runtime::kThrowStackOverflow);
  // Unreachable code.
  __ Trap();

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
  __ LoadWord(t0, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ LoadTaggedField(
      t0, FieldMemOperand(t0, JSFunction::kSharedFunctionInfoOffset));
  __ LoadTrustedPointerField(
      t0, FieldMemOperand(t0, SharedFunctionInfo::kTrustedFunctionDataOffset),
      kUnknownIndirectPointerTag);
  __ GetObjectType(t0, kInterpreterDispatchTableRegister,
                   kInterpreterDispatchTableRegister);
  __ Branch(&builtin_trampoline, ne, kInterpreterDispatchTableRegister,
            Operand(INTERPRETER_DATA_TYPE), Label::Distance::kNear);

  __ LoadProtectedPointerField(
      t0, FieldMemOperand(t0, InterpreterData::kInterpreterTrampolineOffset));
  __ LoadCodeInstructionStart(t0, t0, kJSEntrypointTag);
  __ BranchShort(&trampoline_loaded);

  __ bind(&builtin_trampoline);
  __ li(t0, ExternalReference::
                address_of_interpreter_entry_trampoline_instruction_start(
                    masm->isolate()));
  __ LoadWord(t0, MemOperand(t0));

  __ bind(&trampoline_loaded);
  __ AddWord(ra, t0, Operand(interpreter_entry_return_pc_offset.value()));

  // Initialize the dispatch table register.
  __ li(kInterpreterDispatchTableRegister,
        ExternalReference::interpre
"""


```