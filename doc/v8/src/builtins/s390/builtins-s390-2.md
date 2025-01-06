Response: The user wants to understand the functionality of the provided C++ code snippet, which is part of the V8 JavaScript engine for the s390 architecture. This is the third part of the code. The goal is to summarize its purpose and, if it relates to JavaScript, provide a JavaScript example illustrating the connection.

The code contains several functions within the `v8::internal::Builtins` namespace for the s390 architecture. Looking at the function names, we can infer their roles:

- `Generate_DoubleToInt32`:  Likely handles the conversion of a double-precision floating-point number to a 32-bit integer. This could involve handling overflow and different ranges of exponents.
- `Generate_CallApiCallbackImpl`: Deals with calling C++ functions from JavaScript, a key part of V8's extension mechanism. It sets up the necessary arguments and context for the C++ function.
- `Generate_CallApiGetter`:  Specifically handles calling C++ getter functions associated with JavaScript properties. It prepares arguments for the getter callback.
- `Generate_DirectCEntry`: Marked as unused, so we can ignore it.
- `Generate_DeoptimizationEntry`:  This is crucial for optimizing JavaScript execution. When the engine detects that an optimized function is no longer beneficial or safe, it "deoptimizes" and returns to a less optimized but more reliable version. This function handles the process of switching back. There are separate entries for eager and lazy deoptimization.
- `Generate_InterpreterOnStackReplacement`, `Generate_BaselineOnStackReplacement`, `Generate_BaselineOrInterpreterEnterAtBytecode`, `Generate_BaselineOrInterpreterEnterAtNextBytecode`, `Generate_InterpreterOnStackReplacement_ToBaseline`: These functions relate to "on-stack replacement" (OSR), a technique to switch between different versions of a function (e.g., interpreted, baseline-compiled, optimized) while the function is actively executing. This enables performance improvements during runtime.
- `Generate_RestartFrameTrampoline`:  Likely used when a stack frame needs to be restarted, possibly after deoptimization or an exception.

Based on these observations, the main functionalities appear to be:

1. **Type Conversion:** Handling the specific conversion of double-precision floating-point numbers to integers on the s390 architecture, including overflow checks.
2. **API Integration:** Facilitating communication between JavaScript and C++ code through callbacks and property accessors.
3. **Deoptimization:** Managing the process of reverting from optimized code to less optimized code when needed.
4. **On-Stack Replacement (OSR):**  Enabling dynamic switching between different compilation tiers of a function while it's running.
5. **Frame Management:**  Supporting the management and potential restarting of execution frames.

Since the code heavily involves calling C++ functions and handling conversions related to JavaScript number types, there are clear connections to JavaScript functionality.
This C++ code snippet, part 3 of 3 for `v8/src/builtins/s390/builtins-s390.cc`, focuses on implementing specific built-in functions and mechanisms for the s390 architecture within the V8 JavaScript engine. Specifically, it handles:

1. **Conversion from Double to Integer:** The `Generate_DoubleToInt32` function implements a fast path for converting double-precision floating-point numbers to 32-bit integers. It handles potential overflow scenarios and utilizes bit manipulation to perform the conversion efficiently.

2. **Calling API Callbacks:** The `Generate_CallApiCallbackImpl` function is responsible for setting up and executing calls to C++ functions that are exposed to JavaScript. This involves preparing the arguments, context, and handling the transition between JavaScript and native code. It supports different modes for optimized and generic calls.

3. **Calling API Getters:** The `Generate_CallApiGetter` function handles calls to C++ getter functions associated with JavaScript properties. It prepares the `PropertyCallbackInfo` object with necessary information like the receiver, holder, and property name before invoking the getter.

4. **Deoptimization Entry Points:** The `Generate_DeoptimizationEntry_Eager` and `Generate_DeoptimizationEntry_Lazy` functions define the entry points for deoptimization. Deoptimization is a crucial mechanism in V8 where the engine reverts from optimized code back to a less optimized (or interpreted) version when certain conditions are met. This function saves the current state, prepares for the transition, and then jumps to the deoptimizer.

5. **On-Stack Replacement (OSR):** The functions `Generate_InterpreterOnStackReplacement`, `Generate_BaselineOnStackReplacement`, `Generate_BaselineOrInterpreterEnterAtBytecode`, `Generate_BaselineOrInterpreterEnterAtNextBytecode`, and `Generate_InterpreterOnStackReplacement_ToBaseline` are all related to On-Stack Replacement (OSR). OSR allows the V8 engine to switch between different "tiers" of compiled code (e.g., interpreter, baseline compiler, optimizing compiler) while a function is actively running. This can happen when a function becomes hot (OSR to a more optimized version) or when assumptions made by the optimizer are invalidated (OSR back to a less optimized version).

6. **Restarting Frames:** The `Generate_RestartFrameTrampoline` function handles the logic for restarting an interpreted stack frame, typically after deoptimization or some other event that requires re-executing the function.

**Relationship to JavaScript and Examples:**

These built-in functions directly support the execution of JavaScript code. Here are some examples of how they relate:

**1. Double to Integer Conversion:**

```javascript
let floatNumber = 123.456;
let integerNumber = parseInt(floatNumber); // or Math.trunc(floatNumber), Math.floor(), Math.ceil(), etc.
console.log(integerNumber); // Output: 123
```

The `Generate_DoubleToInt32` function (or a similar low-level routine it might call) is responsible for the underlying implementation of `parseInt` or other methods that convert floating-point numbers to integers. It handles the s390-specific instructions for this conversion.

**2. Calling API Callbacks (e.g., using Node.js addons):**

```javascript
// In a Node.js addon (C++ code)
Napi::Value MyFunction(const Napi::CallbackInfo& info) {
  // ... perform some native operations ...
  return Napi::String::New(info.Env(), "Hello from C++!");
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set("myFunction", Napi::Function::New(env, MyFunction));
  return exports;
}

NODE_API_MODULE(addon, Init)

// In JavaScript
const addon = require('./addon');
console.log(addon.myFunction()); // Output: Hello from C++!
```

When `addon.myFunction()` is called in JavaScript, the V8 engine uses mechanisms like `Generate_CallApiCallbackImpl` to transition into the native C++ code (`MyFunction`). This involves setting up the call stack, passing arguments, and handling the return value.

**3. Calling API Getters (e.g., defining custom property getters):**

```javascript
const obj = {
  _x: 10,
  get x() {
    console.log("Getter for x called!");
    return this._x;
  }
};

console.log(obj.x); // Output: "Getter for x called!" and then 10
```

When `obj.x` is accessed, and `x` is defined with a `get` accessor, V8 uses functions like `Generate_CallApiGetter` to invoke the underlying getter function (which could be implemented in C++ if you were defining a native object).

**4. Deoptimization (internal V8 process, less directly observable in simple scripts):**

Deoptimization happens internally. You might trigger it by:

* **Changing object shapes:** Dynamically adding or deleting properties in ways that invalidate optimizations.
* **Type confusion:** Using variables in ways that violate type assumptions made by the optimizer.

While you don't directly call deoptimization functions, the performance characteristics of your JavaScript code are heavily influenced by how effectively V8 can optimize and when it needs to deoptimize.

**5. On-Stack Replacement (also internal):**

OSR is also an internal optimization. V8 will automatically try to upgrade "hot" functions to more optimized versions while they are running. You won't directly interact with OSR functions in your JavaScript code.

In summary, this code snippet provides the low-level building blocks within the V8 engine for the s390 architecture that enable key JavaScript functionalities like type conversions, interaction with native code, and dynamic optimization through deoptimization and on-stack replacement.

Prompt: 
```
这是目录为v8/src/builtins/s390/builtins-s390.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
pe hard_abort(masm);  // Avoid calls to Abort.

  // Immediate values for this stub fit in instructions, so it's safe to use ip.
  Register scratch = GetRegisterThatIsNotOneOf(result_reg);
  Register scratch_low = GetRegisterThatIsNotOneOf(result_reg, scratch);
  Register scratch_high =
      GetRegisterThatIsNotOneOf(result_reg, scratch, scratch_low);
  DoubleRegister double_scratch = kScratchDoubleReg;

  __ Push(result_reg, scratch);
  // Account for saved regs.
  int argument_offset = 2 * kSystemPointerSize;

  // Load double input.
  __ LoadF64(double_scratch, MemOperand(sp, argument_offset));

  // Do fast-path convert from double to int.
  __ ConvertDoubleToInt64(result_reg, double_scratch);

  // Test for overflow
  __ TestIfInt32(result_reg);
  __ beq(&fastpath_done, Label::kNear);

  __ Push(scratch_high, scratch_low);
  // Account for saved regs.
  argument_offset += 2 * kSystemPointerSize;

  __ LoadU32(scratch_high,
             MemOperand(sp, argument_offset + Register::kExponentOffset));
  __ LoadU32(scratch_low,
             MemOperand(sp, argument_offset + Register::kMantissaOffset));

  __ ExtractBitMask(scratch, scratch_high, HeapNumber::kExponentMask);
  // Load scratch with exponent - 1. This is faster than loading
  // with exponent because Bias + 1 = 1024 which is a *S390* immediate value.
  static_assert(HeapNumber::kExponentBias + 1 == 1024);
  __ SubS64(scratch, Operand(HeapNumber::kExponentBias + 1));
  // If exponent is greater than or equal to 84, the 32 less significant
  // bits are 0s (2^84 = 1, 52 significant bits, 32 uncoded bits),
  // the result is 0.
  // Compare exponent with 84 (compare exponent - 1 with 83).
  __ CmpS64(scratch, Operand(83));
  __ bge(&out_of_range, Label::kNear);

  // If we reach this code, 31 <= exponent <= 83.
  // So, we don't have to handle cases where 0 <= exponent <= 20 for
  // which we would need to shift right the high part of the mantissa.
  // Scratch contains exponent - 1.
  // Load scratch with 52 - exponent (load with 51 - (exponent - 1)).
  __ mov(r0, Operand(51));
  __ SubS64(scratch, r0, scratch);
  __ CmpS64(scratch, Operand::Zero());
  __ ble(&only_low, Label::kNear);
  // 21 <= exponent <= 51, shift scratch_low and scratch_high
  // to generate the result.
  __ ShiftRightU32(scratch_low, scratch_low, scratch);
  // Scratch contains: 52 - exponent.
  // We needs: exponent - 20.
  // So we use: 32 - scratch = 32 - 52 + exponent = exponent - 20.
  __ mov(r0, Operand(32));
  __ SubS64(scratch, r0, scratch);
  __ ExtractBitMask(result_reg, scratch_high, HeapNumber::kMantissaMask);
  // Set the implicit 1 before the mantissa part in scratch_high.
  static_assert(HeapNumber::kMantissaBitsInTopWord >= 16);
  __ mov(r0, Operand(1 << ((HeapNumber::kMantissaBitsInTopWord)-16)));
  __ ShiftLeftU64(r0, r0, Operand(16));
  __ OrP(result_reg, result_reg, r0);
  __ ShiftLeftU32(r0, result_reg, scratch);
  __ OrP(result_reg, scratch_low, r0);
  __ b(&negate, Label::kNear);

  __ bind(&out_of_range);
  __ mov(result_reg, Operand::Zero());
  __ b(&done, Label::kNear);

  __ bind(&only_low);
  // 52 <= exponent <= 83, shift only scratch_low.
  // On entry, scratch contains: 52 - exponent.
  __ lcgr(scratch, scratch);
  __ ShiftLeftU32(result_reg, scratch_low, scratch);

  __ bind(&negate);
  // If input was positive, scratch_high ASR 31 equals 0 and
  // scratch_high LSR 31 equals zero.
  // New result = (result eor 0) + 0 = result.
  // If the input was negative, we have to negate the result.
  // Input_high ASR 31 equals 0xFFFFFFFF and scratch_high LSR 31 equals 1.
  // New result = (result eor 0xFFFFFFFF) + 1 = 0 - result.
  __ ShiftRightS32(r0, scratch_high, Operand(31));
  __ lgfr(r0, r0);
  __ ShiftRightU64(r0, r0, Operand(32));
  __ XorP(result_reg, r0);
  __ ShiftRightU32(r0, scratch_high, Operand(31));
  __ AddS64(result_reg, r0);

  __ bind(&done);
  __ Pop(scratch_high, scratch_low);
  argument_offset -= 2 * kSystemPointerSize;

  __ bind(&fastpath_done);
  __ StoreU64(result_reg, MemOperand(sp, argument_offset));
  __ Pop(result_reg, scratch);

  __ Ret();
}

void Builtins::Generate_CallApiCallbackImpl(MacroAssembler* masm,
                                            CallApiCallbackMode mode) {
  // ----------- S t a t e -------------
  // CallApiCallbackMode::kOptimizedNoProfiling/kOptimized modes:
  //  -- r4                  : api function address
  // Both modes:
  //  -- r4                  : arguments count (not including the receiver)
  //  -- r5                  : FunctionTemplateInfo
  //  -- r2                  : holder
  //  -- cp
  //  -- sp[0]               : receiver
  //  -- sp[8]               : first argument
  //  -- ...
  //  -- sp[(argc) * 8]      : last argument
  // -----------------------------------

  Register function_callback_info_arg = kCArgRegs[0];

  Register api_function_address = no_reg;
  Register argc = no_reg;
  Register func_templ = no_reg;
  Register holder = no_reg;
  Register topmost_script_having_context = no_reg;
  Register scratch = r6;

  switch (mode) {
    case CallApiCallbackMode::kGeneric:
      argc = CallApiCallbackGenericDescriptor::ActualArgumentsCountRegister();
      topmost_script_having_context = CallApiCallbackGenericDescriptor::
          TopmostScriptHavingContextRegister();
      func_templ =
          CallApiCallbackGenericDescriptor::FunctionTemplateInfoRegister();
      holder = CallApiCallbackGenericDescriptor::HolderRegister();
      break;

    case CallApiCallbackMode::kOptimizedNoProfiling:
    case CallApiCallbackMode::kOptimized:
      // Caller context is always equal to current context because we don't
      // inline Api calls cross-context.
      topmost_script_having_context = kContextRegister;
      api_function_address =
          CallApiCallbackOptimizedDescriptor::ApiFunctionAddressRegister();
      argc = CallApiCallbackOptimizedDescriptor::ActualArgumentsCountRegister();
      func_templ =
          CallApiCallbackOptimizedDescriptor::FunctionTemplateInfoRegister();
      holder = CallApiCallbackOptimizedDescriptor::HolderRegister();
      break;
  }
  DCHECK(!AreAliased(api_function_address, topmost_script_having_context, argc,
                     holder, func_templ, scratch));

  using FCA = FunctionCallbackArguments;
  using ER = ExternalReference;
  using FC = ApiCallbackExitFrameConstants;

  static_assert(FCA::kArgsLength == 6);
  static_assert(FCA::kNewTargetIndex == 5);
  static_assert(FCA::kTargetIndex == 4);
  static_assert(FCA::kReturnValueIndex == 3);
  static_assert(FCA::kContextIndex == 2);
  static_assert(FCA::kIsolateIndex == 1);
  static_assert(FCA::kHolderIndex == 0);

  // Set up FunctionCallbackInfo's implicit_args on the stack as follows:
  //
  // Target state:
  //   sp[1 * kSystemPointerSize]: kHolder   <= FCA::implicit_args_
  //   sp[2 * kSystemPointerSize]: kIsolate
  //   sp[3 * kSystemPointerSize]: kContext
  //   sp[4 * kSystemPointerSize]: undefined (kReturnValue)
  //   sp[5 * kSystemPointerSize]: kTarget
  //   sp[6 * kSystemPointerSize]: undefined (kNewTarget)
  // Existing state:
  //   sp[7 * kSystemPointerSize]:            <= FCA:::values_

  __ StoreRootRelative(IsolateData::topmost_script_having_context_offset(),
                       topmost_script_having_context);

  if (mode == CallApiCallbackMode::kGeneric) {
    api_function_address = ReassignRegister(topmost_script_having_context);
  }

  // Reserve space on the stack.
  __ lay(sp, MemOperand(sp, -(FCA::kArgsLength * kSystemPointerSize)));

  // kHolder.
  __ StoreU64(holder, MemOperand(sp, FCA::kHolderIndex * kSystemPointerSize));

  // kIsolate.
  __ Move(scratch, ER::isolate_address());
  __ StoreU64(scratch, MemOperand(sp, FCA::kIsolateIndex * kSystemPointerSize));

  // kContext
  __ StoreU64(cp, MemOperand(sp, FCA::kContextIndex * kSystemPointerSize));

  // kReturnValue.
  __ LoadRoot(scratch, RootIndex::kUndefinedValue);
  __ StoreU64(scratch,
              MemOperand(sp, FCA::kReturnValueIndex * kSystemPointerSize));

  // kTarget.
  __ StoreU64(func_templ,
              MemOperand(sp, FCA::kTargetIndex * kSystemPointerSize));

  // kNewTarget.
  __ StoreU64(scratch,
              MemOperand(sp, FCA::kNewTargetIndex * kSystemPointerSize));

  FrameScope frame_scope(masm, StackFrame::MANUAL);
  if (mode == CallApiCallbackMode::kGeneric) {
    __ LoadU64(
        api_function_address,
        FieldMemOperand(func_templ,
                        FunctionTemplateInfo::kMaybeRedirectedCallbackOffset));
  }
  __ EnterExitFrame(scratch, FC::getExtraSlotsCountFrom<ExitFrameConstants>(),
                    StackFrame::API_CALLBACK_EXIT);

  MemOperand argc_operand = MemOperand(fp, FC::kFCIArgcOffset);
  {
    ASM_CODE_COMMENT_STRING(masm, "Initialize v8::FunctionCallbackInfo");
    // FunctionCallbackInfo::length_.
    // TODO(ishell): pass JSParameterCount(argc) to simplify things on the
    // caller end.
    __ StoreU64(argc, argc_operand);

    // FunctionCallbackInfo::implicit_args_.
    __ AddS64(scratch, fp, Operand(FC::kImplicitArgsArrayOffset));
    __ StoreU64(scratch, MemOperand(fp, FC::kFCIImplicitArgsOffset));

    // FunctionCallbackInfo::values_ (points at JS arguments on the stack).
    __ AddS64(scratch, fp, Operand(FC::kFirstArgumentOffset));
    __ StoreU64(scratch, MemOperand(fp, FC::kFCIValuesOffset));
  }

  __ RecordComment("v8::FunctionCallback's argument.");
  __ AddS64(function_callback_info_arg, fp,
            Operand(FC::kFunctionCallbackInfoOffset));

  DCHECK(!AreAliased(api_function_address, function_callback_info_arg));

  ExternalReference thunk_ref = ER::invoke_function_callback(mode);
  Register no_thunk_arg = no_reg;

  MemOperand return_value_operand = MemOperand(fp, FC::kReturnValueOffset);
  static constexpr int kSlotsToDropOnReturn =
      FC::kFunctionCallbackInfoArgsLength + kJSArgcReceiverSlots;

  const bool with_profiling =
      mode != CallApiCallbackMode::kOptimizedNoProfiling;
  CallApiFunctionAndReturn(masm, with_profiling, api_function_address,
                           thunk_ref, no_thunk_arg, kSlotsToDropOnReturn,
                           &argc_operand, return_value_operand);
}

void Builtins::Generate_CallApiGetter(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- cp                  : context
  //  -- r3                  : receiver
  //  -- r5                  : accessor info
  //  -- r2                  : holder
  // -----------------------------------

  // Build v8::PropertyCallbackInfo::args_ array on the stack and push property
  // name below the exit frame to make GC aware of them.
  using PCA = PropertyCallbackArguments;
  using ER = ExternalReference;
  using FC = ApiAccessorExitFrameConstants;

  static_assert(PCA::kPropertyKeyIndex == 0);
  static_assert(PCA::kShouldThrowOnErrorIndex == 1);
  static_assert(PCA::kHolderIndex == 2);
  static_assert(PCA::kIsolateIndex == 3);
  static_assert(PCA::kHolderV2Index == 4);
  static_assert(PCA::kReturnValueIndex == 5);
  static_assert(PCA::kDataIndex == 6);
  static_assert(PCA::kThisIndex == 7);
  static_assert(PCA::kArgsLength == 8);

  // Set up v8::PropertyCallbackInfo's (PCI) args_ on the stack as follows:
  // Target state:
  //   sp[0 * kSystemPointerSize]: name                      <= PCI::args_
  //   sp[1 * kSystemPointerSize]: kShouldThrowOnErrorIndex
  //   sp[2 * kSystemPointerSize]: kHolderIndex
  //   sp[3 * kSystemPointerSize]: kIsolateIndex
  //   sp[4 * kSystemPointerSize]: kHolderV2Index
  //   sp[5 * kSystemPointerSize]: kReturnValueIndex
  //   sp[6 * kSystemPointerSize]: kDataIndex
  //   sp[7 * kSystemPointerSize]: kThisIndex / receiver

  Register name_arg = kCArgRegs[0];
  Register property_callback_info_arg = kCArgRegs[1];

  Register api_function_address = r4;
  Register receiver = ApiGetterDescriptor::ReceiverRegister();
  Register holder = ApiGetterDescriptor::HolderRegister();
  Register callback = ApiGetterDescriptor::CallbackRegister();
  Register scratch = r6;
  Register smi_zero = r7;

  DCHECK(!AreAliased(receiver, holder, callback, scratch, smi_zero));

  __ LoadTaggedField(scratch,
                     FieldMemOperand(callback, AccessorInfo::kDataOffset), r1);
  __ Push(receiver, scratch);
  __ LoadRoot(scratch, RootIndex::kUndefinedValue);
  __ Move(smi_zero, Smi::zero());
  __ Push(scratch, smi_zero);  // kReturnValueIndex, kHolderV2Index
  __ Move(scratch, ER::isolate_address());
  __ Push(scratch, holder);
  __ LoadTaggedField(name_arg,
                     FieldMemOperand(callback, AccessorInfo::kNameOffset), r1);
  static_assert(kDontThrow == 0);
  __ Push(smi_zero, name_arg);  // should_throw_on_error -> kDontThrow, name

  __ RecordComment("Load api_function_address");
  __ LoadU64(
      api_function_address,
      FieldMemOperand(callback, AccessorInfo::kMaybeRedirectedGetterOffset));

  FrameScope frame_scope(masm, StackFrame::MANUAL);
  __ EnterExitFrame(scratch, FC::getExtraSlotsCountFrom<ExitFrameConstants>(),
                    StackFrame::API_ACCESSOR_EXIT);

  __ RecordComment("Create v8::PropertyCallbackInfo object on the stack.");
  // property_callback_info_arg = v8::PropertyCallbackInfo&
  __ AddS64(property_callback_info_arg, fp, Operand(FC::kArgsArrayOffset));

  DCHECK(!AreAliased(api_function_address, property_callback_info_arg, name_arg,
                     callback, scratch));

#ifdef V8_ENABLE_DIRECT_HANDLE
  // name_arg = Local<Name>(name), name value was pushed to GC-ed stack space.
  // |name_arg| is already initialized above.
#else
  // name_arg = Local<Name>(&name), which is &args_array[kPropertyKeyIndex].
  static_assert(PCA::kPropertyKeyIndex == 0);
  __ mov(name_arg, property_callback_info_arg);
#endif

  ExternalReference thunk_ref = ER::invoke_accessor_getter_callback();
  // Pass AccessorInfo to thunk wrapper in case profiler or side-effect
  // checking is enabled.
  Register thunk_arg = callback;

  MemOperand return_value_operand = MemOperand(fp, FC::kReturnValueOffset);
  static constexpr int kSlotsToDropOnReturn =
      FC::kPropertyCallbackInfoArgsLength;
  MemOperand* const kUseStackSpaceConstant = nullptr;

  const bool with_profiling = true;
  CallApiFunctionAndReturn(masm, with_profiling, api_function_address,
                           thunk_ref, thunk_arg, kSlotsToDropOnReturn,
                           kUseStackSpaceConstant, return_value_operand);
}

void Builtins::Generate_DirectCEntry(MacroAssembler* masm) {
  // Unused.
  __ stop();
}

namespace {

// This code tries to be close to ia32 code so that any changes can be
// easily ported.
void Generate_DeoptimizationEntry(MacroAssembler* masm,
                                  DeoptimizeKind deopt_kind) {
  Isolate* isolate = masm->isolate();

  // Save all the registers onto the stack
  const int kNumberOfRegisters = Register::kNumRegisters;

  RegList restored_regs = kJSCallerSaved | kCalleeSaved;

  const int kDoubleRegsSize = kDoubleSize * DoubleRegister::kNumRegisters;

  // Save all double registers before messing with them.
  __ lay(sp, MemOperand(sp, -kDoubleRegsSize));
  const RegisterConfiguration* config = RegisterConfiguration::Default();
  for (int i = 0; i < config->num_allocatable_double_registers(); ++i) {
    int code = config->GetAllocatableDoubleCode(i);
    const DoubleRegister dreg = DoubleRegister::from_code(code);
    int offset = code * kDoubleSize;
    __ StoreF64(dreg, MemOperand(sp, offset));
  }

  // Push all GPRs onto the stack
  __ lay(sp, MemOperand(sp, -kNumberOfRegisters * kSystemPointerSize));
  __ StoreMultipleP(r0, sp, MemOperand(sp));  // Save all 16 registers

  __ Move(r1, ExternalReference::Create(IsolateAddressId::kCEntryFPAddress,
                                        isolate));
  __ StoreU64(fp, MemOperand(r1));

  static constexpr int kSavedRegistersAreaSize =
      (kNumberOfRegisters * kSystemPointerSize) + kDoubleRegsSize;

  // Get the address of the location in the code object (r5)(return
  // address for lazy deoptimization) and compute the fp-to-sp delta in
  // register r6.
  __ mov(r4, r14);
  __ la(r5, MemOperand(sp, kSavedRegistersAreaSize));
  __ SubS64(r5, fp, r5);

  // Allocate a new deoptimizer object.
  // Pass six arguments in r2 to r7.
  __ PrepareCallCFunction(5, r7);
  __ mov(r2, Operand::Zero());
  Label context_check;
  __ LoadU64(r3,
             MemOperand(fp, CommonFrameConstants::kContextOrFrameTypeOffset));
  __ JumpIfSmi(r3, &context_check);
  __ LoadU64(r2, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ bind(&context_check);
  __ mov(r3, Operand(static_cast<int>(deopt_kind)));
  // r4: code address or 0 already loaded.
  // r5: Fp-to-sp delta already loaded.
  // Parm6: isolate is passed on the stack.
  __ Move(r6, ExternalReference::isolate_address());
  __ StoreU64(r6,
              MemOperand(sp, kStackFrameExtraParamSlot * kSystemPointerSize));

  // Call Deoptimizer::New().
  {
    AllowExternalCallThatCantCauseGC scope(masm);
    __ CallCFunction(ExternalReference::new_deoptimizer_function(), 5);
  }

  // Preserve "deoptimizer" object in register r2 and get the input
  // frame descriptor pointer to r3 (deoptimizer->input_);
  __ LoadU64(r3, MemOperand(r2, Deoptimizer::input_offset()));

  // Copy core registers into FrameDescription::registers_[kNumRegisters].
  // DCHECK_EQ(Register::kNumRegisters, kNumberOfRegisters);
  // __ mvc(MemOperand(r3, FrameDescription::registers_offset()),
  //        MemOperand(sp), kNumberOfRegisters * kSystemPointerSize);
  // Copy core registers into FrameDescription::registers_[kNumRegisters].
  // TODO(john.yan): optimize the following code by using mvc instruction
  DCHECK_EQ(Register::kNumRegisters, kNumberOfRegisters);
  for (int i = 0; i < kNumberOfRegisters; i++) {
    int offset =
        (i * kSystemPointerSize) + FrameDescription::registers_offset();
    __ LoadU64(r4, MemOperand(sp, i * kSystemPointerSize));
    __ StoreU64(r4, MemOperand(r3, offset));
  }

  int simd128_regs_offset = FrameDescription::simd128_registers_offset();
  // Copy double registers to
  // double_registers_[DoubleRegister::kNumRegisters]
  for (int i = 0; i < config->num_allocatable_double_registers(); ++i) {
    int code = config->GetAllocatableDoubleCode(i);
    int dst_offset = code * kSimd128Size + simd128_regs_offset;
    int src_offset =
        code * kDoubleSize + kNumberOfRegisters * kSystemPointerSize;
    // TODO(joransiu): MVC opportunity
    __ LoadF64(d0, MemOperand(sp, src_offset));
    __ StoreF64(d0, MemOperand(r3, dst_offset));
  }

  // Mark the stack as not iterable for the CPU profiler which won't be able to
  // walk the stack without the return address.
  {
    UseScratchRegisterScope temps(masm);
    Register is_iterable = temps.Acquire();
    Register zero = r6;
    __ LoadIsolateField(is_iterable, IsolateFieldId::kStackIsIterable);
    __ lhi(zero, Operand(0));
    __ StoreU8(zero, MemOperand(is_iterable));
  }

  // Remove the saved registers from the stack.
  __ la(sp, MemOperand(sp, kSavedRegistersAreaSize));

  // Compute a pointer to the unwinding limit in register r4; that is
  // the first stack slot not part of the input frame.
  __ LoadU64(r4, MemOperand(r3, FrameDescription::frame_size_offset()));
  __ AddS64(r4, sp);

  // Unwind the stack down to - but not including - the unwinding
  // limit and copy the contents of the activation frame to the input
  // frame description.
  __ la(r5, MemOperand(r3, FrameDescription::frame_content_offset()));
  Label pop_loop;
  Label pop_loop_header;
  __ b(&pop_loop_header, Label::kNear);
  __ bind(&pop_loop);
  __ pop(r6);
  __ StoreU64(r6, MemOperand(r5, 0));
  __ la(r5, MemOperand(r5, kSystemPointerSize));
  __ bind(&pop_loop_header);
  __ CmpS64(r4, sp);
  __ bne(&pop_loop);

  // Compute the output frame in the deoptimizer.
  __ push(r2);  // Preserve deoptimizer object across call.
  // r2: deoptimizer object; r3: scratch.
  __ PrepareCallCFunction(1, r3);
  // Call Deoptimizer::ComputeOutputFrames().
  {
    AllowExternalCallThatCantCauseGC scope(masm);
    __ CallCFunction(ExternalReference::compute_output_frames_function(), 1);
  }
  __ pop(r2);  // Restore deoptimizer object (class Deoptimizer).

  __ LoadU64(sp, MemOperand(r2, Deoptimizer::caller_frame_top_offset()));

  // Replace the current (input) frame with the output frames.
  Label outer_push_loop, inner_push_loop, outer_loop_header, inner_loop_header;
  // Outer loop state: r6 = current "FrameDescription** output_",
  // r3 = one past the last FrameDescription**.
  __ LoadU32(r3, MemOperand(r2, Deoptimizer::output_count_offset()));
  __ LoadU64(r6,
             MemOperand(r2, Deoptimizer::output_offset()));  // r6 is output_.
  __ ShiftLeftU64(r3, r3, Operand(kSystemPointerSizeLog2));
  __ AddS64(r3, r6, r3);
  __ b(&outer_loop_header, Label::kNear);

  __ bind(&outer_push_loop);
  // Inner loop state: r4 = current FrameDescription*, r5 = loop index.
  __ LoadU64(r4, MemOperand(r6, 0));  // output_[ix]
  __ LoadU64(r5, MemOperand(r4, FrameDescription::frame_size_offset()));
  __ b(&inner_loop_header, Label::kNear);

  __ bind(&inner_push_loop);
  __ SubS64(r5, Operand(sizeof(intptr_t)));
  __ AddS64(r8, r4, r5);
  __ LoadU64(r8, MemOperand(r8, FrameDescription::frame_content_offset()));
  __ push(r8);

  __ bind(&inner_loop_header);
  __ CmpS64(r5, Operand::Zero());
  __ bne(&inner_push_loop);  // test for gt?

  __ AddS64(r6, r6, Operand(kSystemPointerSize));
  __ bind(&outer_loop_header);
  __ CmpS64(r6, r3);
  __ blt(&outer_push_loop);

  __ LoadU64(r3, MemOperand(r2, Deoptimizer::input_offset()));
  for (int i = 0; i < config->num_allocatable_double_registers(); ++i) {
    int code = config->GetAllocatableDoubleCode(i);
    const DoubleRegister dreg = DoubleRegister::from_code(code);
    int src_offset = code * kSimd128Size + simd128_regs_offset;
    __ ld(dreg, MemOperand(r3, src_offset));
  }

  // Push pc and continuation from the last output frame.
  __ LoadU64(r8, MemOperand(r4, FrameDescription::pc_offset()));
  __ push(r8);
  __ LoadU64(r8, MemOperand(r4, FrameDescription::continuation_offset()));
  __ push(r8);

  // Restore the registers from the last output frame.
  __ mov(r1, r4);
  for (int i = kNumberOfRegisters - 1; i > 0; i--) {
    int offset =
        (i * kSystemPointerSize) + FrameDescription::registers_offset();
    if ((restored_regs.bits() & (1 << i)) != 0) {
      __ LoadU64(ToRegister(i), MemOperand(r1, offset));
    }
  }

  {
    UseScratchRegisterScope temps(masm);
    Register is_iterable = temps.Acquire();
    Register one = r6;
    __ push(one);  // Save the value from the output FrameDescription.
    __ LoadIsolateField(is_iterable, IsolateFieldId::kStackIsIterable);
    __ lhi(one, Operand(1));
    __ StoreU8(one, MemOperand(is_iterable));
    __ pop(one);  // Restore the value from the output FrameDescription.
  }

  {
    __ pop(ip);  // get continuation, leave pc on stack
    __ pop(r14);
    Label end;
    __ CmpU64(ip, Operand::Zero());
    __ beq(&end);
    __ Jump(ip);
    __ bind(&end);
    __ Ret();
  }

  __ stop();
}

}  // namespace

void Builtins::Generate_DeoptimizationEntry_Eager(MacroAssembler* masm) {
  Generate_DeoptimizationEntry(masm, DeoptimizeKind::kEager);
}

void Builtins::Generate_DeoptimizationEntry_Lazy(MacroAssembler* masm) {
  Generate_DeoptimizationEntry(masm, DeoptimizeKind::kLazy);
}

void Builtins::Generate_InterpreterOnStackReplacement(MacroAssembler* masm) {
  using D = OnStackReplacementDescriptor;
  static_assert(D::kParameterCount == 1);
  OnStackReplacement(masm, OsrSourceTier::kInterpreter,
                     D::MaybeTargetCodeRegister());
}

void Builtins::Generate_BaselineOnStackReplacement(MacroAssembler* masm) {
  using D = OnStackReplacementDescriptor;
  static_assert(D::kParameterCount == 1);

  __ LoadU64(kContextRegister,
             MemOperand(fp, BaselineFrameConstants::kContextOffset));
  OnStackReplacement(masm, OsrSourceTier::kBaseline,
                     D::MaybeTargetCodeRegister());
}

void Builtins::Generate_BaselineOrInterpreterEnterAtBytecode(
    MacroAssembler* masm) {
  Generate_BaselineOrInterpreterEntry(masm, false);
}

void Builtins::Generate_BaselineOrInterpreterEnterAtNextBytecode(
    MacroAssembler* masm) {
  Generate_BaselineOrInterpreterEntry(masm, true);
}

void Builtins::Generate_InterpreterOnStackReplacement_ToBaseline(
    MacroAssembler* masm) {
  Generate_BaselineOrInterpreterEntry(masm, false, true);
}

void Builtins::Generate_RestartFrameTrampoline(MacroAssembler* masm) {
  // Frame is being dropped:
  // - Look up current function on the frame.
  // - Leave the frame.
  // - Restart the frame by calling the function.

  __ LoadU64(r3, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ LoadU64(r2, MemOperand(fp, StandardFrameConstants::kArgCOffset));
  __ LeaveFrame(StackFrame::INTERPRETED);

  // The arguments are already in the stack (including any necessary padding),
  // we should not try to massage the arguments again.
  __ mov(r4, Operand(kDontAdaptArgumentsSentinel));
  __ InvokeFunction(r3, r4, r2, InvokeType::kJump);
}

#undef __

}  // namespace internal
}  // namespace v8

#endif  // V8_TARGET_ARCH_S390X

"""


```