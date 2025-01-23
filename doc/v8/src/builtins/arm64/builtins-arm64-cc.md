Response:
The user wants to understand the functionality of the ARM64 builtins file in V8. I need to go through the provided code snippet and identify the key functions and their purposes. I should pay attention to the preprocessor directives (like `#if V8_TARGET_ARCH_ARM64`) and the various namespaces.

Here's a breakdown of the code and its functionality:

1. **Includes:** The file includes various V8 headers related to API calls, builtins, code generation, debugging, deoptimization, execution frames, heap management, logging, object representation, runtime functions, and (optionally) WebAssembly.

2. **Namespaces:** The code resides within the `v8::internal` namespace.

3. **Macros:** The `__` macro is defined to simplify access to the `MacroAssembler`.

4. **`Generate_Adaptor`:** This function seems to create an adaptor between JavaScript calls and C++ functions. It sets up the necessary arguments and tail-calls a built-in function.

5. **`Generate_JSBuiltinsConstructStubHelper`:** This is a crucial function for handling the `new` operator in JavaScript. It manages the construction frame, argument copying, and calling the constructor function.

6. **`Generate_JSConstructStubGeneric`:** This function provides a more generic implementation for the construct stub, including handling derived class constructors and the logic for returning the constructed object.

7. **`Generate_ConstructedNonConstructable`:** This function is likely called when `new` is used on a non-constructable object, throwing an error.

8. **Assertion Functions:** `AssertCodeIsBaselineAllowClobber` and `AssertCodeIsBaseline` are helper functions to ensure that the code being executed is baseline code (from the interpreter or a non-optimizing compiler).

9. **`CheckSharedFunctionInfoBytecodeOrBaseline` and `GetSharedFunctionInfoBytecodeOrBaseline`:** These functions are involved in determining whether a function has bytecode (from the interpreter) or baseline code associated with it.

10. **`Generate_ResumeGeneratorTrampoline`:** This function handles the resumption of generator functions. It sets up the necessary state, copies arguments, and jumps to the generator's code.

11. **`Generate_JSEntryVariant`:** This is a core function responsible for entering the V8 engine from native C++ code. It sets up the stack frame, handles exceptions, and calls the JavaScript function.
```javascript
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
    // pass in the generator object. In ordinary calls, new.target is always
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
          Entry
### 提示词
```
这是目录为v8/src/builtins/arm64/builtins-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/arm64/builtins-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
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

    //
```