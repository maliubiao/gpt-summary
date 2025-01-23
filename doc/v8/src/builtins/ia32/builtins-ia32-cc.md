Response:
The user wants a summary of the functionality of the provided C++ code snippet.
The code is located in `v8/src/builtins/ia32/builtins-ia32.cc`, suggesting it contains architecture-specific (IA32) implementations of built-in functions for the V8 JavaScript engine.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The file name `builtins-ia32.cc` immediately points to built-in function implementations for the IA32 architecture.

2. **Scan for key function names and patterns:** Look for function definitions, particularly those starting with `Builtins::Generate_`. These functions are likely the entry points for different built-in functionalities.

3. **Analyze individual `Generate_` functions:** For each such function, try to understand its purpose based on its name and the code it contains.
    * `Generate_Adaptor`: Likely deals with adapting function calls, potentially bridging between JavaScript and native code.
    * `Generate_PushArguments`:  Seems to be a helper for pushing arguments onto the stack.
    * `Generate_JSBuiltinsConstructStubHelper` and `Generate_JSConstructStubGeneric`:  Clearly related to the `construct` operation in JavaScript (creating new objects). The "Generic" version likely handles the standard case, while the "Helper" might be a shared utility.
    * `Generate_ConstructedNonConstructable`: Handles errors when trying to construct something that isn't a constructor.
    * `Generate_JSEntryVariant`, `Generate_JSEntry`, `Generate_JSConstructEntry`, `Generate_JSRunMicrotasksEntry`:  These appear to be entry points into the JavaScript execution environment from native code. The "Variant" likely provides a template for the others. They manage stack frames, contexts, and call the actual JavaScript code.
    * `Generate_JSEntryTrampoline` and `Generate_JSConstructEntryTrampoline`: These seem to be intermediate steps (trampolines) when entering JavaScript execution, possibly setting up arguments and calling the core functionality.
    * `Generate_RunMicrotasksTrampoline`:  Specifically handles the execution of microtasks.
    * `Generate_ResumeGeneratorTrampoline`: Deals with resuming the execution of JavaScript generator functions.
    * `LeaveInterpreterFrame`: Focuses on cleaning up the stack after interpreter execution.
    * `AdvanceBytecodeOffsetOrReturn`: Crucial for the interpreter, responsible for moving to the next instruction.
    * `ResetSharedFunctionInfoAge` and `ResetJSFunctionAge`: Likely related to optimization and garbage collection, resetting the "age" of functions.
    * `ResetFeedbackVectorOsrUrgency`: Also related to optimization, specifically influencing "OSR" (On-Stack Replacement).

4. **Identify helper functions and data structures:** Look for smaller, non-`Generate_` functions, enums, and constants. These provide supporting functionality.
    * `ArgumentsElementType`: An enum defining how arguments are pushed.
    * `kReceiverOnStackSize`: A constant defining the size of the receiver on the stack.
    *  The anonymous namespace containing `Generate_PushArguments` and `Generate_JSBuiltinsConstructStubHelper`.
    * `GetSharedFunctionInfoBytecode`, `AssertCodeIsBaseline`, `GetSharedFunctionInfoBytecodeOrBaseline`: Helpers related to accessing and verifying bytecode or baseline code associated with functions.

5. **Look for conditional compilation:** The `#if V8_TARGET_ARCH_IA32` and `#if V8_ENABLE_WEBASSEMBLY` directives indicate that this file is specific to the IA32 architecture and includes WebAssembly-related code if that feature is enabled.

6. **Infer relationships and flows:** Try to connect the different `Generate_` functions and helpers. For example, the `JSConstructStubGeneric` likely uses `Generate_PushArguments`. The `JSEntry` functions probably call into the trampolines.

7. **Consider JavaScript interaction:**  Think about how these low-level built-ins relate to JavaScript code. Constructors, function calls, generators, and microtasks are all core JavaScript concepts.

8. **Address the specific prompts:**
    * **`.tq` extension:** Explicitly state that this is not a Torque file.
    * **JavaScript examples:** Provide relevant JavaScript code snippets to illustrate the functionality of the built-ins (e.g., `new`, function calls, `yield`).
    * **Logic examples:** Create simple scenarios with inputs and expected outputs to demonstrate the behavior of certain built-ins (e.g., a constructor call).
    * **Common errors:** Point out typical programming mistakes related to the covered concepts (e.g., calling a non-constructor with `new`).

9. **Structure the summary:** Organize the findings logically, grouping related functionalities together. Start with a high-level overview and then delve into specifics.

10. **Review and refine:** Read through the generated summary to ensure accuracy, clarity, and completeness. Check for any inconsistencies or missing information. Make sure the JavaScript examples and logic examples are clear and relevant. Ensure the explanation of potential errors is understandable.

By following these steps, a comprehensive and accurate summary of the C++ code's functionality can be generated, addressing all the user's specific requirements.
```cpp
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
      Label done
### 提示词
```
这是目录为v8/src/builtins/ia32/builtins-ia32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/ia32/builtins-ia32.cc以.tq结尾，那它是个v8 torque源代码，
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
  __ mov_b(FieldOperand(feedback_vector, Feed
```