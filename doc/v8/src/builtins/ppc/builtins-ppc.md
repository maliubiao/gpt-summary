Response: The user wants a summary of the C++ source code file `v8/src/builtins/ppc/builtins-ppc.cc`.
The file seems to contain architecture-specific implementations of built-in functions for the PPC64 architecture in the V8 JavaScript engine.

I need to identify the key functionalities implemented in this code, focusing on:
1. **Built-in function implementations**: Look for function definitions within the `v8::internal::Builtins` namespace.
2. **Interaction with JavaScript**: Identify any parts of the code that directly relate to or affect JavaScript execution (e.g., handling function calls, object construction, generator execution, exception handling).
3. **PPC64 specifics**: While summarizing, note that this code is specific to the PPC64 architecture.

I will go through the code snippet and categorize the functions and their functionalities.
这个C++源代码文件是V8 JavaScript引擎针对PPC64架构的内置函数实现。它定义了在PPC64架构上执行JavaScript代码时所需的底层操作，涵盖了函数调用、构造函数、生成器、异常处理、以及与解释器和优化编译器的交互等关键部分。

具体来说，这个文件中的代码实现了以下功能：

1. **启动和进入执行流程**:
   - `Generate_BaselineOrInterpreterEntry`:  根据当前的状态（是否存在基线代码），选择进入基线代码或解释器执行。
   - `Generate_OSREntry`:  在进行栈上替换 (OSR) 时，跳转到优化代码的入口点。
   - `Generate_JSEntryVariant`, `Generate_JSEntry`, `Generate_JSConstructEntry`, `Generate_JSRunMicrotasksEntry`:  定义了从C++进入JavaScript执行环境的入口点，包括标准调用、构造调用和运行微任务。
   - `Generate_JSEntryTrampoline`, `Generate_JSConstructEntryTrampoline`, `Generate_RunMicrotasksTrampoline`:  实现了JavaScript入口点的跳转逻辑，负责设置上下文、传递参数并调用JavaScript代码。
   - `Generate_InterpreterEntryTrampoline`:  定义了解释器入口点的逻辑，负责设置解释器帧、加载字节码、并分发执行。

2. **函数调用和构造**:
   - `Generate_Adaptor`:  用于连接C++函数和JavaScript函数调用。
   - `Generate_JSBuiltinsConstructStubHelper`, `Builtins::Generate_JSBuiltinsConstructStub`: 实现了构造函数调用的桩代码，负责创建对象、调用构造函数并处理返回值。
   - `Builtins::Generate_JSConstructStubGeneric`:  通用的构造函数桩代码，处理包括派生类构造函数的情况。
   - `Builtins::Generate_ConstructedNonConstructable`:  处理尝试构造一个不可构造对象时抛出异常。
   - `Builtins::Generate_InterpreterPushArgsThenCallImpl`, `Builtins::Generate_InterpreterPushArgsThenConstructImpl`:  用于在解释器中准备参数并调用或构造函数。
   - `Builtins::Generate_ConstructForwardAllArgsImpl`:  在构造函数中转发所有参数。

3. **生成器 (Generator) 的支持**:
   - `Builtins::Generate_ResumeGeneratorTrampoline`:  用于恢复执行暂停的生成器对象，包括设置输入值、加载上下文和跳转到生成器函数。

4. **优化和反优化 (Optimization and Deoptimization)**:
   - `OnStackReplacement`:  处理栈上替换 (OSR) 的逻辑，当满足优化条件时，从解释器或基线代码切换到优化后的代码。
   - `Builtins::Generate_BaselineOutOfLinePrologue`:  基线代码的序言，负责检查优化状态、递增调用计数等。
   - `Builtins::Generate_BaselineOutOfLinePrologueDeopt`:  在基线代码序言中发生反优化时的处理逻辑。

5. **解释器支持**:
   - `LeaveInterpreterFrame`:  负责清理解释器帧。
   - `AdvanceBytecodeOffsetOrReturn`:  用于在解释器中推进字节码偏移量，模拟字节码处理器的行为。

6. **其他辅助功能**:
   - `AssertCodeIsBaseline`:  断言给定的代码对象是基线代码。
   - `CheckSharedFunctionInfoBytecodeOrBaseline`, `GetSharedFunctionInfoBytecodeOrBaseline`:  检查并获取`SharedFunctionInfo`中的字节码或基线代码。
   - `ResetSharedFunctionInfoAge`, `ResetJSFunctionAge`, `ResetFeedbackVectorOsrUrgency`:  用于重置与优化相关的状态。
   - `Generate_PushArguments`:  将参数推入栈中。

**与 JavaScript 的关系及示例**:

这个文件直接关系到 JavaScript 代码的执行。它提供的内置函数是JavaScript运行时环境的基础，例如，当你调用一个函数或者使用 `new` 关键字创建一个对象时，V8引擎就会使用这里定义的底层机制。

**JavaScript 示例**:

1. **函数调用**: 当你调用一个普通的 JavaScript 函数时，例如 `myFunction(arg1, arg2)`，V8 引擎最终会调用到类似 `Builtins::Generate_JSEntryTrampoline` 中定义的逻辑来执行 `myFunction` 的代码。

2. **构造函数**:  当你使用 `new` 关键字调用一个函数，例如 `new MyClass(param1)`，V8 引擎会调用类似 `Builtins::Generate_JSConstructStubGeneric` 中定义的逻辑来创建 `MyClass` 的实例。

   ```javascript
   function myFunction(a, b) {
       console.log(a + b);
   }

   function MyClass(value) {
       this.value = value;
   }

   myFunction(1, 2); // 最终会调用到类似 Generate_JSEntryTrampoline 的逻辑
   const obj = new MyClass(5); // 最终会调用到类似 Generate_JSConstructStubGeneric 的逻辑
   ```

3. **生成器**: 当你使用 `function*` 定义一个生成器函数并调用 `next()` 方法时，V8 引擎会使用 `Builtins::Generate_ResumeGeneratorTrampoline` 来恢复生成器的执行。

   ```javascript
   function* myGenerator() {
       yield 1;
       yield 2;
   }

   const gen = myGenerator();
   console.log(gen.next()); // { value: 1, done: false } -  Generate_ResumeGeneratorTrampoline 会被调用
   console.log(gen.next()); // { value: 2, done: false } -  Generate_ResumeGeneratorTrampoline 会被调用
   ```

总而言之，`builtins-ppc.cc` 文件是 V8 引擎在 PPC64 架构上执行 JavaScript 代码的核心组成部分，它实现了连接 JavaScript 代码和底层机器指令的关键功能。

### 提示词
```
这是目录为v8/src/builtins/ppc/builtins-ppc.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if V8_TARGET_ARCH_PPC64

#include "src/api/api-arguments.h"
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
namespace {

static void AssertCodeIsBaseline(MacroAssembler* masm, Register code,
                                 Register scratch) {
  DCHECK(!AreAliased(code, scratch));
  // Verify that the code kind is baseline code via the CodeKind.
  __ LoadU32(scratch, FieldMemOperand(code, Code::kFlagsOffset));
  __ DecodeField<Code::KindField>(scratch);
  __ CmpS64(scratch, Operand(static_cast<int>(CodeKind::BASELINE)), r0);
  __ Assert(eq, AbortReason::kExpectedBaselineData);
}

static void CheckSharedFunctionInfoBytecodeOrBaseline(MacroAssembler* masm,
                                                      Register data,
                                                      Register scratch,
                                                      Label* is_baseline,
                                                      Label* is_bytecode) {
  DCHECK(!AreAliased(r0, scratch));

#if V8_STATIC_ROOTS_BOOL
  __ IsObjectTypeFast(data, scratch, CODE_TYPE, r0);
#else
  __ CompareObjectType(data, scratch, scratch, CODE_TYPE);
#endif  // V8_STATIC_ROOTS_BOOL
  if (v8_flags.debug_code) {
    Label not_baseline;
    __ b(ne, &not_baseline);
    AssertCodeIsBaseline(masm, data, scratch);
    __ b(eq, is_baseline);
    __ bind(&not_baseline);
  } else {
    __ b(eq, is_baseline);
  }

#if V8_STATIC_ROOTS_BOOL
  // scratch already contains the compressed map.
  __ CompareInstanceTypeWithUniqueCompressedMap(scratch, Register::no_reg(),
                                                INTERPRETER_DATA_TYPE);
#else
  // scratch already contains the instance type.
  __ CmpU64(scratch, Operand(INTERPRETER_DATA_TYPE), r0);
#endif  // V8_STATIC_ROOTS_BOOL
  __ b(ne, is_bytecode);
}

static void GetSharedFunctionInfoBytecodeOrBaseline(
    MacroAssembler* masm, Register sfi, Register bytecode, Register scratch1,
    Label* is_baseline, Label* is_unavailable) {
  USE(GetSharedFunctionInfoBytecodeOrBaseline);
  DCHECK(!AreAliased(bytecode, scratch1));
  ASM_CODE_COMMENT(masm);
  Label done;
  Register data = bytecode;
  __ LoadTrustedPointerField(
      data,
      FieldMemOperand(sfi, SharedFunctionInfo::kTrustedFunctionDataOffset),
      kUnknownIndirectPointerTag, r0);

  if (V8_JITLESS_BOOL) {
    __ IsObjectType(data, scratch1, scratch1, INTERPRETER_DATA_TYPE);
    __ b(ne, &done);
  } else {
    CheckSharedFunctionInfoBytecodeOrBaseline(masm, data, scratch1, is_baseline,
                                              &done);
  }

  __ LoadTrustedPointerField(
      bytecode, FieldMemOperand(data, InterpreterData::kBytecodeArrayOffset),
      kBytecodeArrayIndirectPointerTag, scratch1);

  __ bind(&done);
  __ IsObjectType(bytecode, scratch1, scratch1, BYTECODE_ARRAY_TYPE);
  __ b(ne, is_unavailable);
}

void Generate_OSREntry(MacroAssembler* masm, Register entry_address,
                       intptr_t offset) {
  __ AddS64(ip, entry_address, Operand(offset), r0);
  __ mtlr(ip);

  // "return" to the OSR entry point of the function.
  __ Ret();
}

void ResetSharedFunctionInfoAge(MacroAssembler* masm, Register sfi,
                                Register scratch) {
  DCHECK(!AreAliased(sfi, scratch));
  __ mov(scratch, Operand(0));
  __ StoreU16(scratch, FieldMemOperand(sfi, SharedFunctionInfo::kAgeOffset),
              no_reg);
}

void ResetJSFunctionAge(MacroAssembler* masm, Register js_function,
                        Register scratch1, Register scratch2) {
  __ LoadTaggedField(
      scratch1,
      FieldMemOperand(js_function, JSFunction::kSharedFunctionInfoOffset),
      scratch2);
  ResetSharedFunctionInfoAge(masm, scratch1, scratch2);
}

void ResetFeedbackVectorOsrUrgency(MacroAssembler* masm,
                                   Register feedback_vector, Register scratch1,
                                   Register scratch2) {
  DCHECK(!AreAliased(feedback_vector, scratch1));
  __ LoadU8(scratch1,
            FieldMemOperand(feedback_vector, FeedbackVector::kOsrStateOffset),
            scratch2);
  __ andi(
      scratch1, scratch1,
      Operand(static_cast<uint8_t>(~FeedbackVector::OsrUrgencyBits::kMask)));
  __ StoreU8(scratch1,
             FieldMemOperand(feedback_vector, FeedbackVector::kOsrStateOffset),
             scratch2);
}

// Restarts execution either at the current or next (in execution order)
// bytecode. If there is baseline code on the shared function info, converts an
// interpreter frame into a baseline frame and continues execution in baseline
// code. Otherwise execution continues with bytecode.
void Generate_BaselineOrInterpreterEntry(MacroAssembler* masm,
                                         bool next_bytecode,
                                         bool is_osr = false) {
  Label start;
  __ bind(&start);

  // Get function from the frame.
  Register closure = r4;
  __ LoadU64(closure, MemOperand(fp, StandardFrameConstants::kFunctionOffset),
             r0);

  // Get the InstructionStream object from the shared function info.
  Register code_obj = r9;
  __ LoadTaggedField(
      code_obj, FieldMemOperand(closure, JSFunction::kSharedFunctionInfoOffset),
      r0);

  if (is_osr) {
    ResetSharedFunctionInfoAge(masm, code_obj, r6);
  }

  __ LoadTrustedPointerField(
      code_obj,
      FieldMemOperand(code_obj, SharedFunctionInfo::kTrustedFunctionDataOffset),
      kUnknownIndirectPointerTag, r0);

  // Check if we have baseline code. For OSR entry it is safe to assume we
  // always have baseline code.
  if (!is_osr) {
    Label start_with_baseline;
    __ IsObjectType(code_obj, r6, r6, CODE_TYPE);
    __ b(eq, &start_with_baseline);

    // Start with bytecode as there is no baseline code.
    Builtin builtin = next_bytecode ? Builtin::kInterpreterEnterAtNextBytecode
                                    : Builtin::kInterpreterEnterAtBytecode;
    __ TailCallBuiltin(builtin);

    // Start with baseline code.
    __ bind(&start_with_baseline);
  } else if (v8_flags.debug_code) {
    __ IsObjectType(code_obj, r6, r6, CODE_TYPE);
    __ Assert(eq, AbortReason::kExpectedBaselineData);
  }

  if (v8_flags.debug_code) {
    AssertCodeIsBaseline(masm, code_obj, r6);
  }

  // Load the feedback cell and vector.
  Register feedback_cell = r5;
  Register feedback_vector = ip;
  __ LoadTaggedField(feedback_cell,
                     FieldMemOperand(closure, JSFunction::kFeedbackCellOffset),
                     r0);
  __ LoadTaggedField(feedback_vector,
                     FieldMemOperand(feedback_cell, FeedbackCell::kValueOffset),
                     r0);

  Label install_baseline_code;
  // Check if feedback vector is valid. If not, call prepare for baseline to
  // allocate it.
  __ IsObjectType(feedback_vector, r6, r6, FEEDBACK_VECTOR_TYPE);
  __ b(ne, &install_baseline_code);

  // Save BytecodeOffset from the stack frame.
  __ LoadU64(kInterpreterBytecodeOffsetRegister,
             MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ SmiUntag(kInterpreterBytecodeOffsetRegister);
  // Replace bytecode offset with feedback cell.
  static_assert(InterpreterFrameConstants::kBytecodeOffsetFromFp ==
                BaselineFrameConstants::kFeedbackCellFromFp);
  __ StoreU64(feedback_cell,
              MemOperand(fp, BaselineFrameConstants::kFeedbackCellFromFp));
  feedback_cell = no_reg;
  // Update feedback vector cache.
  static_assert(InterpreterFrameConstants::kFeedbackVectorFromFp ==
                BaselineFrameConstants::kFeedbackVectorFromFp);
  __ StoreU64(feedback_vector,
              MemOperand(fp, InterpreterFrameConstants::kFeedbackVectorFromFp));
  feedback_vector = no_reg;

  // Compute baseline pc for bytecode offset.
  ExternalReference get_baseline_pc_extref;
  if (next_bytecode || is_osr) {
    get_baseline_pc_extref =
        ExternalReference::baseline_pc_for_next_executed_bytecode();
  } else {
    get_baseline_pc_extref =
        ExternalReference::baseline_pc_for_bytecode_offset();
  }
  Register get_baseline_pc = r6;
  __ Move(get_baseline_pc, get_baseline_pc_extref);

  // If the code deoptimizes during the implicit function entry stack interrupt
  // check, it will have a bailout ID of kFunctionEntryBytecodeOffset, which is
  // not a valid bytecode offset.
  // TODO(pthier): Investigate if it is feasible to handle this special case
  // in TurboFan instead of here.
  Label valid_bytecode_offset, function_entry_bytecode;
  if (!is_osr) {
    __ CmpS64(kInterpreterBytecodeOffsetRegister,
              Operand(BytecodeArray::kHeaderSize - kHeapObjectTag +
                      kFunctionEntryBytecodeOffset),
              r0);
    __ b(eq, &function_entry_bytecode);
  }

  __ SubS64(kInterpreterBytecodeOffsetRegister,
            kInterpreterBytecodeOffsetRegister,
            Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));

  __ bind(&valid_bytecode_offset);
  // Get bytecode array from the stack frame.
  __ LoadU64(kInterpreterBytecodeArrayRegister,
             MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  // Save the accumulator register, since it's clobbered by the below call.
  __ Push(kInterpreterAccumulatorRegister);
  __ Push(code_obj);
  {
    __ mr(kCArgRegs[0], code_obj);
    __ mr(kCArgRegs[1], kInterpreterBytecodeOffsetRegister);
    __ mr(kCArgRegs[2], kInterpreterBytecodeArrayRegister);
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ PrepareCallCFunction(4, 0, ip);
    __ CallCFunction(get_baseline_pc, 3, 0);
  }
  __ Pop(code_obj);
  __ LoadCodeInstructionStart(code_obj, code_obj);
  __ AddS64(code_obj, code_obj, kReturnRegister0);
  __ Pop(kInterpreterAccumulatorRegister);

  if (is_osr) {
    Generate_OSREntry(masm, code_obj, 0);
  } else {
    __ Jump(code_obj);
  }
  __ Trap();  // Unreachable.

  if (!is_osr) {
    __ bind(&function_entry_bytecode);
    // If the bytecode offset is kFunctionEntryOffset, get the start address of
    // the first bytecode.
    __ mov(kInterpreterBytecodeOffsetRegister, Operand(0));
    if (next_bytecode) {
      __ Move(get_baseline_pc,
              ExternalReference::baseline_pc_for_bytecode_offset());
    }
    __ b(&valid_bytecode_offset);
  }

  __ bind(&install_baseline_code);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ Push(kInterpreterAccumulatorRegister);
    __ Push(closure);
    __ CallRuntime(Runtime::kInstallBaselineCode, 1);
    __ Pop(kInterpreterAccumulatorRegister);
  }
  // Retry from the start after installing baseline code.
  __ b(&start);
}

}  // namespace

void Builtins::Generate_Adaptor(MacroAssembler* masm,
                                int formal_parameter_count, Address address) {
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
  Label loop, done;
  __ subi(scratch, argc, Operand(kJSArgcReceiverSlots));
  __ cmpi(scratch, Operand::Zero());
  __ beq(&done);
  __ mtctr(scratch);
  __ ShiftLeftU64(scratch, scratch, Operand(kSystemPointerSizeLog2));
  __ add(scratch, array, scratch);

  __ bind(&loop);
  __ LoadU64WithUpdate(ip, MemOperand(scratch, -kSystemPointerSize));
  if (element_type == ArgumentsElementType::kHandle) {
    __ LoadU64(ip, MemOperand(ip));
  }
  __ push(ip);
  __ bdnz(&loop);
  __ bind(&done);
}

void Generate_JSBuiltinsConstructStubHelper(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r3     : number of arguments
  //  -- r4     : constructor function
  //  -- r6     : new target
  //  -- cp     : context
  //  -- lr     : return address
  //  -- sp[...]: constructor arguments
  // -----------------------------------

  Register scratch = r5;

  Label stack_overflow;

  __ StackOverflowCheck(r3, scratch, &stack_overflow);
  // Enter a construct frame.
  {
    FrameAndConstantPoolScope scope(masm, StackFrame::CONSTRUCT);

    // Preserve the incoming parameters on the stack.

    __ Push(cp, r3);

    // TODO(victorgomes): When the arguments adaptor is completely removed, we
    // should get the formal parameter count and copy the arguments in its
    // correct position (including any undefined), instead of delaying this to
    // InvokeFunction.

    // Set up pointer to first argument (skip receiver).
    __ addi(
        r7, fp,
        Operand(StandardFrameConstants::kCallerSPOffset + kSystemPointerSize));
    // Copy arguments and receiver to the expression stack.
    // r7: Pointer to start of arguments.
    // r3: Number of arguments.
    Generate_PushArguments(masm, r7, r3, r8, ArgumentsElementType::kRaw);

    // The receiver for the builtin/api call.
    __ PushRoot(RootIndex::kTheHoleValue);

    // Call the function.
    // r3: number of arguments (untagged)
    // r4: constructor function
    // r6: new target
    {
      ConstantPoolUnavailableScope constant_pool_unavailable(masm);
      __ InvokeFunctionWithNewTarget(r4, r6, r3, InvokeType::kCall);
    }

    // Restore context from the frame.
    __ LoadU64(cp, MemOperand(fp, ConstructFrameConstants::kContextOffset));
    // Restore arguments count from the frame.
    __ LoadU64(scratch, MemOperand(fp, ConstructFrameConstants::kLengthOffset));

    // Leave construct frame.
  }
  // Remove caller arguments from the stack and return.
  __ DropArguments(scratch);
  __ blr();

  __ bind(&stack_overflow);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kThrowStackOverflow);
    __ bkpt(0);  // Unreachable code.
  }
}

enum class OsrSourceTier {
  kInterpreter,
  kBaseline,
};

void OnStackReplacement(MacroAssembler* masm, OsrSourceTier source,
                        Register maybe_target_code) {
  Label jump_to_optimized_code;
  {
    // If maybe_target_code is not null, no need to call into runtime. A
    // precondition here is: if maybe_target_code is an InstructionStream
    // object, it must NOT be marked_for_deoptimization (callers must ensure
    // this).
    __ CmpSmiLiteral(maybe_target_code, Smi::zero(), r0);
    __ bne(&jump_to_optimized_code);
  }

  ASM_CODE_COMMENT(masm);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kCompileOptimizedOSR);
  }

  // If the code object is null, just return to the caller.
  __ CmpSmiLiteral(r3, Smi::zero(), r0);
  __ bne(&jump_to_optimized_code);
  __ Ret();

  __ bind(&jump_to_optimized_code);
  DCHECK_EQ(maybe_target_code, r3);  // Already in the right spot.

  // OSR entry tracing.
  {
    Label next;
    __ Move(r4, ExternalReference::address_of_log_or_trace_osr());
    __ LoadU8(r4, MemOperand(r4));
    __ andi(r0, r4, Operand(0xFF));  // Mask to the LSB.
    __ beq(&next, cr0);

    {
      FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);
      __ Push(r3);  // Preserve the code object.
      __ CallRuntime(Runtime::kLogOrTraceOptimizedOSREntry, 0);
      __ Pop(r3);
    }

    __ bind(&next);
  }

  if (source == OsrSourceTier::kInterpreter) {
    // Drop the handler frame that is be sitting on top of the actual
    // JavaScript frame. This is the case then OSR is triggered from bytecode.
    __ LeaveFrame(StackFrame::STUB);
  }

  // Load deoptimization data from the code object.
  // <deopt_data> = <code>[#deoptimization_data_offset]
  __ LoadTaggedField(
      r4, FieldMemOperand(r3, Code::kDeoptimizationDataOrInterpreterDataOffset),
      r0);

  {
    ConstantPoolUnavailableScope constant_pool_unavailable(masm);

    if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
      __ LoadConstantPoolPointerRegisterFromCodeTargetAddress(r3, r0, ip);
    }

    __ LoadCodeInstructionStart(r3, r3);

    // Load the OSR entrypoint offset from the deoptimization data.
    // <osr_offset> = <deopt_data>[#header_size + #osr_pc_offset]
    __ SmiUntag(r4,
                FieldMemOperand(r4, FixedArray::OffsetOfElementAt(
                                        DeoptimizationData::kOsrPcOffsetIndex)),
                LeaveRC, r0);

    // Compute the target address = code start + osr_offset
    __ add(r0, r3, r4);

    // And "return" to the OSR entry point of the function.
    __ mtlr(r0);
    __ blr();
  }
}

}  // namespace

// The construct stub for ES5 constructor functions and ES6 class constructors.
void Builtins::Generate_JSConstructStubGeneric(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  --      r3: number of arguments (untagged)
  //  --      r4: constructor function
  //  --      r6: new target
  //  --      cp: context
  //  --      lr: return address
  //  -- sp[...]: constructor arguments
  // -----------------------------------

  FrameScope scope(masm, StackFrame::MANUAL);
  // Enter a construct frame.
  Label post_instantiation_deopt_entry, not_create_implicit_receiver;
  __ EnterFrame(StackFrame::CONSTRUCT);

  // Preserve the incoming parameters on the stack.
  __ Push(cp, r3, r4);
  __ PushRoot(RootIndex::kUndefinedValue);
  __ Push(r6);

  // ----------- S t a t e -------------
  //  --        sp[0*kSystemPointerSize]: new target
  //  --        sp[1*kSystemPointerSize]: padding
  //  -- r4 and sp[2*kSystemPointerSize]: constructor function
  //  --        sp[3*kSystemPointerSize]: number of arguments
  //  --        sp[4*kSystemPointerSize]: context
  // -----------------------------------

  __ LoadTaggedField(
      r7, FieldMemOperand(r4, JSFunction::kSharedFunctionInfoOffset), r0);
  __ lwz(r7, FieldMemOperand(r7, SharedFunctionInfo::kFlagsOffset));
  __ DecodeField<SharedFunctionInfo::FunctionKindBits>(r7);
  __ JumpIfIsInRange(
      r7, r0, static_cast<uint32_t>(FunctionKind::kDefaultDerivedConstructor),
      static_cast<uint32_t>(FunctionKind::kDerivedConstructor),
      &not_create_implicit_receiver);

  // If not derived class constructor: Allocate the new receiver object.
  __ CallBuiltin(Builtin::kFastNewObject);
  __ b(&post_instantiation_deopt_entry);

  // Else: use TheHoleValue as receiver for constructor call
  __ bind(&not_create_implicit_receiver);
  __ LoadRoot(r3, RootIndex::kTheHoleValue);

  // ----------- S t a t e -------------
  //  --                          r3: receiver
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
  __ Pop(r6);

  // Push the allocated receiver to the stack.
  __ Push(r3);
  // We need two copies because we may have to return the original one
  // and the calling conventions dictate that the called function pops the
  // receiver. The second copy is pushed after the arguments, we saved in r6
  // since r0 needs to store the number of arguments before
  // InvokingFunction.
  __ mr(r9, r3);

  // Set up pointer to first argument (skip receiver).
  __ addi(
      r7, fp,
      Operand(StandardFrameConstants::kCallerSPOffset + kSystemPointerSize));

  // ----------- S t a t e -------------
  //  --                 r6: new target
  //  -- sp[0*kSystemPointerSize]: implicit receiver
  //  -- sp[1*kSystemPointerSize]: implicit receiver
  //  -- sp[2*kSystemPointerSize]: padding
  //  -- sp[3*kSystemPointerSize]: constructor function
  //  -- sp[4*kSystemPointerSize]: number of arguments
  //  -- sp[5*kSystemPointerSize]: context
  // -----------------------------------

  // Restore constructor function and argument count.
  __ LoadU64(r4, MemOperand(fp, ConstructFrameConstants::kConstructorOffset));
  __ LoadU64(r3, MemOperand(fp, ConstructFrameConstants::kLengthOffset));

  Label stack_overflow;
  __ StackOverflowCheck(r3, r8, &stack_overflow);

  // Copy arguments to the expression stack.
  // r7: Pointer to start of argument.
  // r3: Number of arguments.
  Generate_PushArguments(masm, r7, r3, r8, ArgumentsElementType::kRaw);

  // Push implicit receiver.
  __ Push(r9);

  // Call the function.
  {
    ConstantPoolUnavailableScope constant_pool_unavailable(masm);
    __ InvokeFunctionWithNewTarget(r4, r6, r3, InvokeType::kCall);
  }

  // If the result is an object (in the ECMA sense), we should get rid
  // of the receiver and use the result; see ECMA-262 section 13.2.2-7
  // on page 74.
  Label use_receiver, do_throw, leave_and_return, check_receiver;

  // If the result is undefined, we jump out to using the implicit receiver.
  __ JumpIfNotRoot(r3, RootIndex::kUndefinedValue, &check_receiver);

  // Otherwise we do a smi check and fall through to check if the return value
  // is a valid receiver.

  // Throw away the result of the constructor invocation and use the
  // on-stack receiver as the result.
  __ bind(&use_receiver);
  __ LoadU64(r3, MemOperand(sp));
  __ JumpIfRoot(r3, RootIndex::kTheHoleValue, &do_throw);

  __ bind(&leave_and_return);
  // Restore arguments count from the frame.
  __ LoadU64(r4, MemOperand(fp, ConstructFrameConstants::kLengthOffset));
  // Leave construct frame.
  __ LeaveFrame(StackFrame::CONSTRUCT);

  // Remove caller arguments from the stack and return.
  __ DropArguments(r4);
  __ blr();

  __ bind(&check_receiver);
  // If the result is a smi, it is *not* an object in the ECMA sense.
  __ JumpIfSmi(r3, &use_receiver);

  // If the type of the result (stored in its map) is less than
  // FIRST_JS_RECEIVER_TYPE, it is not an object in the ECMA sense.
  static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
  __ CompareObjectType(r3, r7, r7, FIRST_JS_RECEIVER_TYPE);
  __ bge(&leave_and_return);
  __ b(&use_receiver);

  __ bind(&do_throw);
  // Restore the context from the frame.
  __ LoadU64(cp, MemOperand(fp, ConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowConstructorReturnedNonObject);
  __ bkpt(0);

  __ bind(&stack_overflow);
  // Restore the context from the frame.
  __ LoadU64(cp, MemOperand(fp, ConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowStackOverflow);
  // Unreachable code.
  __ bkpt(0);
}

void Builtins::Generate_JSBuiltinsConstructStub(MacroAssembler* masm) {
  Generate_JSBuiltinsConstructStubHelper(masm);
}

// static
void Builtins::Generate_ResumeGeneratorTrampoline(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r3 : the value to pass to the generator
  //  -- r4 : the JSGeneratorObject to resume
  //  -- lr : return address
  // -----------------------------------
  // Store input value into generator object.
  __ StoreTaggedField(
      r3, FieldMemOperand(r4, JSGeneratorObject::kInputOrDebugPosOffset), r0);
  __ RecordWriteField(r4, JSGeneratorObject::kInputOrDebugPosOffset, r3, r6,
                      kLRHasNotBeenSaved, SaveFPRegsMode::kIgnore);
  // Check that r4 is still valid, RecordWrite might have clobbered it.
  __ AssertGeneratorObject(r4);

  // Load suspended function and context.
  __ LoadTaggedField(
      r7, FieldMemOperand(r4, JSGeneratorObject::kFunctionOffset), r0);
  __ LoadTaggedField(cp, FieldMemOperand(r7, JSFunction::kContextOffset), r0);

  // Flood function if we are stepping.
  Label prepare_step_in_if_stepping, prepare_step_in_suspended_generator;
  Label stepping_prepared;
  Register scratch = r8;
  ExternalReference debug_hook =
      ExternalReference::debug_hook_on_function_call_address(masm->isolate());
  __ Move(scratch, debug_hook);
  __ LoadU8(scratch, MemOperand(scratch), r0);
  __ extsb(scratch, scratch);
  __ CmpSmiLiteral(scratch, Smi::zero(), r0);
  __ bne(&prepare_step_in_if_stepping);

  // Flood function if we need to continue stepping in the suspended generator.

  ExternalReference debug_suspended_generator =
      ExternalReference::debug_suspended_generator_address(masm->isolate());

  __ Move(scratch, debug_suspended_generator);
  __ LoadU64(scratch, MemOperand(scratch));
  __ CmpS64(scratch, r4);
  __ beq(&prepare_step_in_suspended_generator);
  __ bind(&stepping_prepared);

  // Check the stack for overflow. We are not trying to catch interruptions
  // (i.e. debug break and preemption) here, so check the "real stack limit".
  Label stack_overflow;
  __ LoadStackLimit(scratch, StackLimitKind::kRealStackLimit, r0);
  __ CmpU64(sp, scratch);
  __ blt(&stack_overflow);

  // ----------- S t a t e -------------
  //  -- r4    : the JSGeneratorObject to resume
  //  -- r7    : generator function
  //  -- cp    : generator context
  //  -- lr    : return address
  // -----------------------------------

  // Copy the function arguments from the generator object's register file.
  __ LoadTaggedField(
      r6, FieldMemOperand(r7, JSFunction::kSharedFunctionInfoOffset), r0);
  __ LoadU16(
      r6, FieldMemOperand(r6, SharedFunctionInfo::kFormalParameterCountOffset));
  __ subi(r6, r6, Operand(kJSArgcReceiverSlots));
  __ LoadTaggedField(
      r5, FieldMemOperand(r4, JSGeneratorObject::kParametersAndRegistersOffset),
      r0);
  {
    Label done_loop, loop;
    __ bind(&loop);
    __ subi(r6, r6, Operand(1));
    __ cmpi(r6, Operand::Zero());
    __ blt(&done_loop);
    __ ShiftLeftU64(r10, r6, Operand(kTaggedSizeLog2));
    __ add(scratch, r5, r10);
    __ LoadTaggedField(
        scratch, FieldMemOperand(scratch, OFFSET_OF_DATA_START(FixedArray)),
        r0);
    __ Push(scratch);
    __ b(&loop);
    __ bind(&done_loop);

    // Push receiver.
    __ LoadTaggedField(
        scratch, FieldMemOperand(r4, JSGeneratorObject::kReceiverOffset), r0);
    __ Push(scratch);
  }

  // Underlying function needs to have bytecode available.
  if (v8_flags.debug_code) {
    Label ok, is_baseline, is_unavailable;
    Register sfi = r6;
    Register bytecode = r6;
    __ LoadTaggedField(
        sfi, FieldMemOperand(r7, JSFunction::kSharedFunctionInfoOffset), r0);
    GetSharedFunctionInfoBytecodeOrBaseline(masm, sfi, bytecode, ip,
                                            &is_baseline, &is_unavailable);
    __ b(&ok);

    __ bind(&is_unavailable);
    __ Abort(AbortReason::kMissingBytecodeArray);

    __ bind(&is_baseline);
    __ IsObjectType(bytecode, ip, ip, CODE_TYPE);
    __ Assert(eq, AbortReason::kMissingBytecodeArray);

    __ bind(&ok);
  }

  // Resume (Ignition/TurboFan) generator object.
  {
    __ LoadTaggedField(
        r3, FieldMemOperand(r7, JSFunction::kSharedFunctionInfoOffset), r0);
    __ LoadU16(r3, FieldMemOperand(
                       r3, SharedFunctionInfo::kFormalParameterCountOffset));
    // We abuse new.target both to indicate that this is a resume call and to
    // pass in the generator object.  In ordinary calls, new.target is always
    // undefined because generator functions are non-constructable.
    __ mr(r6, r4);
    __ mr(r4, r7);
    __ JumpJSFunction(r4, r0);
  }

  __ bind(&prepare_step_in_if_stepping);
  {
    FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);
    __ Push(r4, r7);
    // Push hole as receiver since we do not use it for stepping.
    __ PushRoot(RootIndex::kTheHoleValue);
    __ CallRuntime(Runtime::kDebugOnFunctionCall);
    __ Pop(r4);
    __ LoadTaggedField(
        r7, FieldMemOperand(r4, JSGeneratorObject::kFunctionOffset), r0);
  }
  __ b(&stepping_prepared);

  __ bind(&prepare_step_in_suspended_generator);
  {
    FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);
    __ Push(r4);
    __ CallRuntime(Runtime::kDebugPrepareStepInSuspendedGenerator);
    __ Pop(r4);
    __ LoadTaggedField(
        r7, FieldMemOperand(r4, JSGeneratorObject::kFunctionOffset), r0);
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
  FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);
  __ push(r4);
  __ CallRuntime(Runtime::kThrowConstructedNonConstructable);
  __ Trap();  // Unreachable.
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
  // The register state is either:
  //   r3: root_register_value
  //   r4: code entry
  //   r5: function
  //   r6: receiver
  //   r7: argc
  //   r8: argv
  // or
  //   r3: root_register_value
  //   r4: microtask_queue

  Label invoke, handler_entry, exit;

  {
    NoRootArrayScope no_root_array(masm);

    // PPC LINUX ABI:
    // preserve LR in pre-reserved slot in caller's frame
    __ mflr(r0);
    __ StoreU64(r0, MemOperand(sp, kStackFrameLRSlot * kSystemPointerSize));

    // Save callee saved registers on the stack.
    __ MultiPush(kCalleeSaved);

    // Save callee-saved double registers.
    __ MultiPushDoubles(kCalleeSavedDoubles);
    // Set up the reserved register for 0.0.
    __ LoadDoubleLiteral(kDoubleRegZero, base::Double(0.0), r0);

    // Initialize the root register.
    // C calling convention. The first argument is passed in r3.
    __ mr(kRootRegister, r3);

#ifdef V8_COMPRESS_POINTERS
    // Initialize the pointer cage base register.
    __ LoadRootRelative(kPtrComprCageBaseRegister,
                        IsolateData::cage_base_offset());
#endif
  }

  // Push a frame with special values setup to mark it as an entry frame.
  // r4: code entry
  // r5: function
  // r6: receiver
  // r7: argc
  // r8: argv
  // Clear c_entry_fp, now we've pushed its previous value to the stack.
  // If the c_entry_fp is not already zero and we don't clear it, the
  // StackFrameIteratorForProfiler will assume we are executing C++ and miss the
  // JS frames on top.
  __ li(r0, Operand(-1));  // Push a bad frame pointer to fail if it is used.
  __ push(r0);
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    __ li(kConstantPoolRegister, Operand::Zero());
    __ push(kConstantPoolRegister);
  }
  __ mov(r0, Operand(StackFrame::TypeToMarker(type)));
  __ push(r0);
  __ push(r0);

  __ mov(r0, Operand::Zero());
  __ Move(ip, ExternalReference::Create(IsolateAddressId::kCEntryFPAddress,
                                        masm->isolate()));
  __ LoadU64(r3, MemOperand(ip));
  __ StoreU64(r0, MemOperand(ip));
  __ push(r3);

  __ LoadIsolateField(ip, IsolateFieldId::kFastCCallCallerFP);
  __ LoadU64(r3, MemOperand(ip));
  __ StoreU64(r0, MemOperand(ip));
  __ push(r3);

  __ LoadIsolateField(ip, IsolateFieldId::kFastCCallCallerPC);
  __ LoadU64(r3, MemOperand(ip));
  __ StoreU64(r0, MemOperand(ip));
  __ push(r3);

  Register scratch = r9;
  // Set up frame pointer for the frame to be pushed.
  __ addi(fp, sp, Operand(-EntryFrameConstants::kNextFastCallFramePCOffset));

  // If this is the outermost JS call, set js_entry_sp value.
  Label non_outermost_js;
  ExternalReference js_entry_sp =
      ExternalReference::Create(IsolateAddressId::kJSEntrySPAddress,
                                masm->isolate());
  __ Move(r3, js_entry_sp);
  __ LoadU64(scratch, MemOperand(r3));
  __ cmpi(scratch, Operand::Zero());
  __ bne(&non_outermost_js);
  __ StoreU64(fp, MemOperand(r3));
  __ mov(scratch, Operand(StackFrame::OUTERMOST_JSENTRY_FRAME));
  Label cont;
  __ b(&cont);
  __ bind(&non_outermost_js);
  __ mov(scratch, Operand(StackFrame::INNER_JSENTRY_FRAME));
  __ bind(&cont);
  __ push(scratch);  // frame-type

  // Jump to a faked try block that does the invoke, with a faked catch
  // block that sets the exception.
  __ b(&invoke);

  // Block literal pool emission whilst taking the position of the handler
  // entry. This avoids making the assumption that literal pools are always
  // emitted after an instruction is emitted, rather than before.
  {
    ConstantPoolUnavailableScope constant_pool_unavailable(masm);
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

  __ StoreU64(r3, MemOperand(scratch));
  __ LoadRoot(r3, RootIndex::kException);
  __ b(&exit);

  // Invoke: Link this frame into the handler chain.
  __ bind(&invoke);
  // Must preserve r4-r8.
  __ PushStackHandler();
  // If an exception not caught by another handler occurs, this handler
  // returns control to the code after the b(&invoke) above, which
  // restores all kCalleeSaved registers (including cp and fp) to their
  // saved values before returning a failure to C.

  // Invoke the function by calling through JS entry trampoline builtin.
  // Notice that we cannot store a reference to the trampoline code directly in
  // this stub, because runtime stubs are not traversed when doing GC.

  // Invoke the function by calling through JS entry trampoline builtin and
  // pop the faked function when we return.
  __ CallBuiltin(entry_trampoline);

  // Unlink this frame from the handler chain.
  __ PopStackHandler();

  __ bind(&exit);  // r3 holds result
  // Check if the current stack frame is marked as the outermost JS frame.
  Label non_outermost_js_2;
  __ pop(r8);
  __ cmpi(r8, Operand(StackFrame::OUTERMOST_JSENTRY_FRAME));
  __ bne(&non_outermost_js_2);
  __ mov(scratch, Operand::Zero());
  __ Move(r8, js_entry_sp);
  __ StoreU64(scratch, MemOperand(r8));
  __ bind(&non_outermost_js_2);

  // Restore the top frame descriptors from the stack.
  __ pop(r6);
  __ LoadIsolateField(scratch, IsolateFieldId::kFastCCallCallerPC);
  __ StoreU64(r6, MemOperand(scratch));

  __ pop(r6);
  __ LoadIsolateField(scratch, IsolateFieldId::kFastCCallCallerFP);
  __ StoreU64(r6, MemOperand(scratch));

  __ pop(r6);
  __ Move(scratch, ExternalReference::Create(IsolateAddressId::kCEntryFPAddress,
                                             masm->isolate()));
  __ StoreU64(r6, MemOperand(scratch));

  // Reset the stack to the callee saved registers.
  __ addi(sp, sp, Operand(-EntryFrameConstants::kNextExitFrameFPOffset));

  // Restore callee-saved double registers.
  __ MultiPopDoubles(kCalleeSavedDoubles);

  // Restore callee-saved registers.
  __ MultiPop(kCalleeSaved);

  // Return
  __ LoadU64(r0, MemOperand(sp, kStackFrameLRSlot * kSystemPointerSize));
  __ mtlr(r0);
  __ blr();
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
  // r4: new.target
  // r5: function
  // r6: receiver
  // r7: argc
  // r8: argv
  // r0,r3,r9, cp may be clobbered

  // Enter an internal frame.
  {
    FrameScope scope(masm, StackFrame::INTERNAL);

    // Setup the context (we need to use the caller context from the isolate).
    ExternalReference context_address = ExternalReference::Create(
        IsolateAddressId::kContextAddress, masm->isolate());
    __ Move(cp, context_address);
    __ LoadU64(cp, MemOperand(cp));

    // Push the function.
    __ Push(r5);

    // Check if we have enough stack space to push all arguments.
    Label enough_stack_space, stack_overflow;
    __ mr(r3, r7);
    __ StackOverflowCheck(r3, r9, &stack_overflow);
    __ b(&enough_stack_space);
    __ bind(&stack_overflow);
    __ CallRuntime(Runtime::kThrowStackOverflow);
    // Unreachable code.
    __ bkpt(0);

    __ bind(&enough_stack_space);

    // Copy arguments to the stack.
    // r4: function
    // r7: argc
    // r8: argv, i.e. points to first arg
    Generate_PushArguments(masm, r8, r7, r9, ArgumentsElementType::kHandle);

    // Push the receiver.
    __ Push(r6);

    // r3: argc
    // r4: function
    // r6: new.target
    __ mr(r3, r7);
    __ mr(r6, r4);
    __ mr(r4, r5);

    // Initialize all JavaScript callee-saved registers, since they will be seen
    // by the garbage collector as part of handlers.
    __ LoadRoot(r7, RootIndex::kUndefinedValue);
    __ mr(r8, r7);
    __ mr(r14, r7);
    __ mr(r15, r7);
    __ mr(r16, r7);
    __ mr(r17, r7);

    // Invoke the code.
    Builtin builtin = is_construct ? Builtin::kConstruct : Builtins::Call();
    __ CallBuiltin(builtin);

    // Exit the JS frame and remove the parameters (except function), and
    // return.
  }
  __ blr();

  // r3: result
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
  //   r3: root_register_value
  //   r4: microtask_queue

  __ mr(RunMicrotasksDescriptor::MicrotaskQueueRegister(), r4);
  __ TailCallBuiltin(Builtin::kRunMicrotasks);
}

static void LeaveInterpreterFrame(MacroAssembler* masm, Register scratch1,
                                  Register scratch2) {
  Register params_size = scratch1;
  // Get the size of the formal parameters + receiver (in bytes).
  __ LoadU64(params_size,
             MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ LoadU16(params_size,
             FieldMemOperand(params_size, BytecodeArray::kParameterSizeOffset));

  Register actual_params_size = scratch2;
  // Compute the size of the actual parameters + receiver (in bytes).
  __ LoadU64(actual_params_size,
             MemOperand(fp, StandardFrameConstants::kArgCOffset));

  // If actual is bigger than formal, then we should use it to free up the stack
  // arguments.
  Label corrected_args_count;
  __ CmpS64(params_size, actual_params_size);
  __ bge(&corrected_args_count);
  __ mr(params_size, actual_params_size);
  __ bind(&corrected_args_count);
  // Leave the frame (also dropping the register file).
  __ LeaveFrame(StackFrame::INTERPRETED);

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
  Register bytecode_size_table = scratch1;
  Register scratch3 = bytecode;

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
  Label process_bytecode, extra_wide;
  static_assert(0 == static_cast<int>(interpreter::Bytecode::kWide));
  static_assert(1 == static_cast<int>(interpreter::Bytecode::kExtraWide));
  static_assert(2 == static_cast<int>(interpreter::Bytecode::kDebugBreakWide));
  static_assert(3 ==
                static_cast<int>(interpreter::Bytecode::kDebugBreakExtraWide));
  __ cmpi(bytecode, Operand(0x3));
  __ bgt(&process_bytecode);
  __ andi(r0, bytecode, Operand(0x1));
  __ bne(&extra_wide, cr0);

  // Load the next bytecode and update table to the wide scaled table.
  __ addi(bytecode_offset, bytecode_offset, Operand(1));
  __ lbzx(bytecode, MemOperand(bytecode_array, bytecode_offset));
  __ addi(bytecode_size_table, bytecode_size_table,
          Operand(kByteSize * interpreter::Bytecodes::kBytecodeCount));
  __ b(&process_bytecode);

  __ bind(&extra_wide);
  // Load the next bytecode and update table to the extra wide scaled table.
  __ addi(bytecode_offset, bytecode_offset, Operand(1));
  __ lbzx(bytecode, MemOperand(bytecode_array, bytecode_offset));
  __ addi(bytecode_size_table, bytecode_size_table,
          Operand(2 * kByteSize * interpreter::Bytecodes::kBytecodeCount));

  // Load the size of the current bytecode.
  __ bind(&process_bytecode);

  // Bailout to the return label if this is a return bytecode.
#define JUMP_IF_EQUAL(NAME)                                           \
  __ cmpi(bytecode,                                                   \
          Operand(static_cast<int>(interpreter::Bytecode::k##NAME))); \
  __ beq(if_return);
  RETURN_BYTECODE_LIST(JUMP_IF_EQUAL)
#undef JUMP_IF_EQUAL

  // If this is a JumpLoop, re-execute it to perform the jump to the beginning
  // of the loop.
  Label end, not_jump_loop;
  __ cmpi(bytecode,
          Operand(static_cast<int>(interpreter::Bytecode::kJumpLoop)));
  __ bne(&not_jump_loop);
  // We need to restore the original bytecode_offset since we might have
  // increased it to skip the wide / extra-wide prefix bytecode.
  __ Move(bytecode_offset, original_bytecode_offset);
  __ b(&end);

  __ bind(&not_jump_loop);
  // Otherwise, load the size of the current bytecode and advance the offset.
  __ lbzx(scratch3, MemOperand(bytecode_size_table, bytecode));
  __ add(bytecode_offset, bytecode_offset, scratch3);

  __ bind(&end);
}

// static
void Builtins::Generate_BaselineOutOfLinePrologue(MacroAssembler* masm) {
  auto descriptor =
      Builtins::CallInterfaceDescriptorFor(Builtin::kBaselineOutOfLinePrologue);
  Register closure = descriptor.GetRegisterParameter(
      BaselineOutOfLinePrologueDescriptor::kClosure);
  // Load the feedback cell and vector from the closure.
  Register feedback_cell = r7;
  Register feedback_vector = ip;
  __ LoadTaggedField(feedback_cell,
                     FieldMemOperand(closure, JSFunction::kFeedbackCellOffset),
                     r0);
  __ LoadTaggedField(feedback_vector,
                     FieldMemOperand(feedback_cell, FeedbackCell::kValueOffset),
                     r0);
  __ AssertFeedbackVector(feedback_vector, r11);

  // Check for an tiering state.
  Label flags_need_processing;
  Register flags = r10;
  {
    __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
        flags, feedback_vector, CodeKind::BASELINE, &flags_need_processing);
  }

  { ResetFeedbackVectorOsrUrgency(masm, feedback_vector, r11, r0); }

  // Increment invocation count for the function.
  {
    Register invocation_count = r11;
    __ LoadU32(invocation_count,
               FieldMemOperand(feedback_vector,
                               FeedbackVector::kInvocationCountOffset),
               r0);
    __ AddS32(invocation_count, invocation_count, Operand(1));
    __ StoreU32(invocation_count,
                FieldMemOperand(feedback_vector,
                                FeedbackVector::kInvocationCountOffset),
                r0);
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
    ResetJSFunctionAge(masm, callee_js_function, r11, r0);
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
      Register scratch = r11;
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

    Register sp_minus_frame_size = r11;
    Register interrupt_limit = r0;
    __ SubS64(sp_minus_frame_size, sp, frame_size);
    __ LoadStackLimit(interrupt_limit, StackLimitKind::kInterruptStackLimit,
                      r0);
    __ CmpU64(sp_minus_frame_size, interrupt_limit);
    __ blt(&call_stack_guard);
  }

  // Do "fast" return to the caller pc in lr.
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
  __ Ret();

  __ bind(&flags_need_processing);
  {
    ASM_CODE_COMMENT_STRING(masm, "Optimized marker check");

    // Drop the frame created by the baseline call.
    if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
      __ Pop(r0, fp, kConstantPoolRegister);
    } else {
      __ Pop(r0, fp);
    }
    __ mtlr(r0);
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
//   o r3: actual argument count
//   o r4: the JS function object being called.
//   o r6: the incoming new target or generator object
//   o cp: our context
//   o pp: the caller's constant pool pointer (if enabled)
//   o fp: the caller's frame pointer
//   o sp: stack pointer
//   o lr: return address
//
// The function builds an interpreter frame.  See InterpreterFrameConstants in
// frame-constants.h for its layout.
void Builtins::Generate_InterpreterEntryTrampoline(
    MacroAssembler* masm, InterpreterEntryTrampolineMode mode) {
  Register closure = r4;

  // Get the bytecode array from the function object and load it into
  // kInterpreterBytecodeArrayRegister.
  Register sfi = r7;
  __ LoadTaggedField(
      sfi, FieldMemOperand(closure, JSFunction::kSharedFunctionInfoOffset), r0);
  ResetSharedFunctionInfoAge(masm, sfi, ip);

  // The bytecode array could have been flushed from the shared function info,
  // if so, call into CompileLazy.
  Label is_baseline, compile_lazy;
  GetSharedFunctionInfoBytecodeOrBaseline(masm, sfi,
                                          kInterpreterBytecodeArrayRegister, ip,
                                          &is_baseline, &compile_lazy);

  Label push_stack_frame;
  Register feedback_vector = r5;
  __ LoadFeedbackVector(feedback_vector, closure, r7, &push_stack_frame);

#ifndef V8_JITLESS
  // If feedback vector is valid, check for optimized code and update invocation
  // count.

  Register flags = r7;
  Label flags_need_processing;
  __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
      flags, feedback_vector, CodeKind::INTERPRETED_FUNCTION,
      &flags_need_processing);

    ResetFeedbackVectorOsrUrgency(masm, feedback_vector, ip, r0);

  // Increment invocation count for the function.
  __ LoadU32(
      r8,
      FieldMemOperand(feedback_vector, FeedbackVector::kInvocationCountOffset),
      r0);
  __ addi(r8, r8, Operand(1));
  __ StoreU32(
      r8,
      FieldMemOperand(feedback_vector, FeedbackVector::kInvocationCountOffset),
      r0);

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
  __ mov(kInterpreterBytecodeOffsetRegister,
         Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));

  // Push bytecode array and Smi tagged bytecode array offset.
  __ SmiTag(r7, kInterpreterBytecodeOffsetRegister);
  __ Push(kInterpreterBytecodeArrayRegister, r7, feedback_vector);

  // Allocate the local and temporary register file on the stack.
  Label stack_overflow;
  {
    // Load frame size (word) from the BytecodeArray object.
    __ lwz(r5, FieldMemOperand(kInterpreterBytecodeArrayRegister,
                               BytecodeArray::kFrameSizeOffset));

    // Do a stack check to ensure we don't go over the limit.
    __ sub(r8, sp, r5);
    __ LoadStackLimit(ip, StackLimitKind::kRealStackLimit, r0);
    __ CmpU64(r8, ip);
    __ blt(&stack_overflow);

    // If ok, push undefined as the initial value for all register file entries.
    // TODO(rmcilroy): Consider doing more than one push per loop iteration.
    Label loop, no_args;
    __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
    __ ShiftRightU64(r5, r5, Operand(kSystemPointerSizeLog2), SetRC);
    __ beq(&no_args, cr0);
    __ mtctr(r5);
    __ bind(&loop);
    __ push(kInterpreterAccumulatorRegister);
    __ bdnz(&loop);
    __ bind(&no_args);
  }

  // If the bytecode array has a valid incoming new target or generator object
  // register, initialize it with incoming value which was passed in r6.
  Label no_incoming_new_target_or_generator_register;
  __ LoadS32(r8,
             FieldMemOperand(
                 kInterpreterBytecodeArrayRegister,
                 BytecodeArray::kIncomingNewTargetOrGeneratorRegisterOffset),
             r0);
  __ cmpi(r8, Operand::Zero());
  __ beq(&no_incoming_new_target_or_generator_register);
  __ ShiftLeftU64(r8, r8, Operand(kSystemPointerSizeLog2));
  __ StoreU64(r6, MemOperand(fp, r8));
  __ bind(&no_incoming_new_target_or_generator_register);

  // Perform interrupt stack check.
  // TODO(solanes): Merge with the real stack limit check above.
  Label stack_check_interrupt, after_stack_check_interrupt;
  __ LoadStackLimit(ip, StackLimitKind::kInterruptStackLimit, r0);
  __ CmpU64(sp, ip);
  __ blt(&stack_check_interrupt);
  __ bind(&after_stack_check_interrupt);

  // The accumulator is already loaded with undefined.

  // Load the dispatch table into a register and dispatch to the bytecode
  // handler at the current bytecode offset.
  Label do_dispatch;
  __ bind(&do_dispatch);
  __ Move(
      kInterpreterDispatchTableRegister,
      ExternalReference::interpreter_dispatch_table_address(masm->isolate()));
  __ lbzx(r6, MemOperand(kInterpreterBytecodeArrayRegister,
                         kInterpreterBytecodeOffsetRegister));
  __ ShiftLeftU64(r6, r6, Operand(kSystemPointerSizeLog2));
  __ LoadU64(kJavaScriptCallCodeStartRegister,
             MemOperand(kInterpreterDispatchTableRegister, r6));
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
  __ LoadU64(kInterpreterBytecodeArrayRegister,
             MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ LoadU64(kInterpreterBytecodeOffsetRegister,
             MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ SmiUntag(kInterpreterBytecodeOffsetRegister);

  // Either return, or advance to the next bytecode and dispatch.
  Label do_return;
  __ lbzx(r4, MemOperand(kInterpreterBytecodeArrayRegister,
                         kInterpreterBytecodeOffsetRegister));
  AdvanceBytecodeOffsetOrReturn(masm, kInterpreterBytecodeArrayRegister,
                                kInterpreterBytecodeOffsetRegister, r4, r5, r6,
                                &do_return);
  __ b(&do_dispatch);

  __ bind(&do_return);
  // The return value is in r3.
  LeaveInterpreterFrame(masm, r5, r7);
  __ blr();

  __ bind(&stack_check_interrupt);
  // Modify the bytecode offset in the stack to be kFunctionEntryBytecodeOffset
  // for the call to the StackGuard.
  __ mov(kInterpreterBytecodeOffsetRegister,
         Operand(Smi::FromInt(BytecodeArray::kHeaderSize - kHeapObjectTag +
                              kFunctionEntryBytecodeOffset)));
  __ StoreU64(kInterpreterBytecodeOffsetRegister,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ CallRuntime(Runtime::kStackGuard);

  // After the call, restore the bytecode array, bytecode offset and accumulator
  // registers again. Also, restore the bytecode offset in the stack to its
  // previous value.
  __ LoadU64(kInterpreterBytecodeArrayRegister,
             MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ mov(kInterpreterBytecodeOffsetRegister,
         Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);

  __ SmiTag(r0, kInterpreterBytecodeOffsetRegister);
  __ StoreU64(r0,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

  __ jmp(&after_stack_check_interrupt);

#ifndef V8_JITLESS
  __ bind(&flags_need_processing);
  __ OptimizeCodeOrTailCallOptimizedCodeSlot(flags, feedback_vector);

  __ bind(&is_baseline);
  {
    // Load the feedback vector from the closure.
    __ LoadTaggedField(
        feedback_vector,
        FieldMemOperand(closure, JSFunction::kFeedbackCellOffset), r0);
    __ LoadTaggedField(
        feedback_vector,
        FieldMemOperand(feedback_vector, FeedbackCell::kValueOffset), r0);

    Label install_baseline_code;
    // Check if feedback vector is valid. If not, call prepare for baseline to
    // allocate it.
    __ LoadTaggedField(
        ip, FieldMemOperand(feedback_vector, HeapObject::kMapOffset), r0);
    __ LoadU16(ip, FieldMemOperand(ip, Map::kInstanceTypeOffset));
    __ CmpS32(ip, Operand(FEEDBACK_VECTOR_TYPE), r0);
    __ b(ne, &install_baseline_code);

    // Check for an tiering state.
    __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
        flags, feedback_vector, CodeKind::BASELINE, &flags_need_processing);

#ifndef V8_ENABLE_LEAPTIERING
    // TODO(olivf, 42204201): This fastcase is difficult to support with the
    // sandbox as it requires getting write access to the dispatch table. See
    // `JSFunction::UpdateCode`. We might want to remove it for all
    // configurations as it does not seem to be performance sensitive.

    // Load the baseline code into the closure.
    __ mr(r5, kInterpreterBytecodeArrayRegister);
    static_assert(kJavaScriptCallCodeStartRegister == r5, "ABI mismatch");
    __ ReplaceClosureCodeWithOptimizedCode(r5, closure, ip, r7);
    __ JumpCodeObject(r5);

#endif  // V8_ENABLE_LEAPTIERING

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
  __ subi(scratch, num_args, Operand(1));
  __ ShiftLeftU64(scratch, scratch, Operand(kSystemPointerSizeLog2));
  __ sub(start_address, start_address, scratch);
  // Push the arguments.
  __ PushArray(start_address, num_args, scratch, r0,
               MacroAssembler::PushArrayOrder::kReverse);
}

// static
void Builtins::Generate_InterpreterPushArgsThenCallImpl(
    MacroAssembler* masm, ConvertReceiverMode receiver_mode,
    InterpreterPushArgsMode mode) {
  DCHECK(mode != InterpreterPushArgsMode::kArrayFunction);
  // ----------- S t a t e -------------
  //  -- r3 : the number of arguments
  //  -- r5 : the address of the first argument to be pushed. Subsequent
  //          arguments should be consecutive above this, in the same order as
  //          they are to be pushed onto the stack.
  //  -- r4 : the target to call (can be any Object).
  // -----------------------------------
  Label stack_overflow;

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // The spread argument should not be pushed.
    __ subi(r3, r3, Operand(1));
  }

  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    __ subi(r6, r3, Operand(kJSArgcReceiverSlots));
  } else {
    __ mr(r6, r3);
  }

  __ StackOverflowCheck(r6, ip, &stack_overflow);

  // Push the arguments.
  GenerateInterpreterPushArgs(masm, r6, r5, r7);

  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    __ PushRoot(RootIndex::kUndefinedValue);
  }

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Pass the spread in the register r3.
    // r2 already points to the penultimate argument, the spread
    // lies in the next interpreter register.
    __ LoadU64(r5, MemOperand(r5, -kSystemPointerSize));
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
    // Unreachable Code.
    __ bkpt(0);
  }
}

// static
void Builtins::Generate_InterpreterPushArgsThenConstructImpl(
    MacroAssembler* masm, InterpreterPushArgsMode mode) {
  // ----------- S t a t e -------------
  // -- r3 : argument count
  // -- r6 : new target
  // -- r4 : constructor to call
  // -- r5 : allocation site feedback if available, undefined otherwise.
  // -- r7 : address of the first argument
  // -----------------------------------
  Label stack_overflow;
  __ StackOverflowCheck(r3, ip, &stack_overflow);

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // The spread argument should not be pushed.
    __ subi(r3, r3, Operand(1));
  }

  Register argc_without_receiver = ip;
  __ subi(argc_without_receiver, r3, Operand(kJSArgcReceiverSlots));

  // Push the arguments.
  GenerateInterpreterPushArgs(masm, argc_without_receiver, r7, r8);

  // Push a slot for the receiver to be constructed.
  __ li(r0, Operand::Zero());
  __ push(r0);

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Pass the spread in the register r2.
    // r4 already points to the penultimate argument, the spread
    // lies in the next interpreter register.
    __ subi(r7, r7, Operand(kSystemPointerSize));
    __ LoadU64(r5, MemOperand(r7));
  } else {
    __ AssertUndefinedOrAllocationSite(r5, r8);
  }

  if (mode == InterpreterPushArgsMode::kArrayFunction) {
    __ AssertFunction(r4);

    // Tail call to the array construct stub (still in the caller
    // context at this point).
    __ TailCallBuiltin(Builtin::kArrayConstructorImpl);
  } else if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Call the constructor with r3, r4, and r6 unmodified.
    __ TailCallBuiltin(Builtin::kConstructWithSpread);
  } else {
    DCHECK_EQ(InterpreterPushArgsMode::kOther, mode);
    // Call the constructor with r3, r4, and r6 unmodified.
    __ TailCallBuiltin(Builtin::kConstruct);
  }

  __ bind(&stack_overflow);
  {
    __ TailCallRuntime(Runtime::kThrowStackOverflow);
    // Unreachable Code.
    __ bkpt(0);
  }
}

// static
void Builtins::Generate_ConstructForwardAllArgsImpl(
    MacroAssembler* masm, ForwardWhichFrame which_frame) {
  // ----------- S t a t e -------------
  // -- r6 : new target
  // -- r4 : constructor to call
  // -----------------------------------
  Label stack_overflow;

  // Load the frame pointer into r7.
  switch (which_frame) {
    case ForwardWhichFrame::kCurrentFrame:
      __ Move(r7, fp);
      break;
    case ForwardWhichFrame::kParentFrame:
      __ LoadU64(r7, MemOperand(fp,
```