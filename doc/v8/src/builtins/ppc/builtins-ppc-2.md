Response: The user wants a summary of the C++ source code file `v8/src/builtins/ppc/builtins-ppc.cc`.
This is the third part of a three-part file.
The goal is to understand the functionality of this part and illustrate its connection to JavaScript using examples if applicable.

The code contains several functions related to the execution of JavaScript code on the PPC architecture within the V8 JavaScript engine.

Here's a breakdown of the functions in this part:

1. `Generate_NumberToString_Bignum`: Converts a Bignum to a string.
2. `Generate_NumberToString_PowerOfTen`: Converts a power of ten to a string.
3. `Generate_NumberToString_Precise`: Converts a number to a string with precision.
4. `Generate_DoubleToInteger`: Converts a double-precision floating-point number to an integer.
5. `Generate_CallApiCallbackImpl`: Handles calls to API callbacks from C++ to JavaScript.
6. `Generate_CallApiGetter`: Handles calls to API getters.
7. `Generate_DirectCEntry`: Handles direct calls to C++ functions.
8. `Generate_DeoptimizationEntry`: Handles deoptimization from optimized code back to interpreted code.
9. `Generate_DeoptimizationEntry_Eager`: Handles eager deoptimization.
10. `Generate_DeoptimizationEntry_Lazy`: Handles lazy deoptimization.
11. `Generate_BaselineOrInterpreterEnterAtBytecode`: Enters baseline or interpreter code at a specific bytecode offset.
12. `Generate_BaselineOrInterpreterEnterAtNextBytecode`: Enters baseline or interpreter code at the next bytecode.
13. `Generate_InterpreterOnStackReplacement_ToBaseline`: Handles on-stack replacement from interpreter to baseline.
14. `Generate_RestartFrameTrampoline`: Restarts an interpreted frame.

Many of these functions are deeply intertwined with the internal workings of V8 and how it executes JavaScript code on the PPC architecture. The API callback and getter functions directly relate to how native C++ code can interact with JavaScript objects. Deoptimization is crucial for handling situations where optimized code needs to fall back to a less optimized but more general form.
这个C++源代码文件（`v8/src/builtins/ppc/builtins-ppc.cc` 的第 3 部分）主要包含了在 PowerPC (PPC) 架构上执行 JavaScript 代码时使用的一些底层 built-in 函数的实现。这些 built-in 函数是 V8 引擎的一部分，用于执行特定的操作，通常是性能关键型的或者需要直接操作底层硬件或内存的操作。

**主要功能归纳:**

1. **数字类型转换:** 包含了将数字类型转换为字符串 (`Generate_NumberToString_Bignum`, `Generate_NumberToString_PowerOfTen`, `Generate_NumberToString_Precise`) 以及将双精度浮点数转换为整数 (`Generate_DoubleToInteger`) 的功能。这些功能是 JavaScript 中数字操作的基础。
2. **API 回调处理:** 提供了处理从 C++ 调用到 JavaScript 的 API 回调 (`Generate_CallApiCallbackImpl`) 和 API getter (`Generate_CallApiGetter`) 的机制。这使得 C++ 扩展可以与 JavaScript 代码进行交互。
3. **直接 C 函数调用:** 实现了直接调用 C++ 函数的入口点 (`Generate_DirectCEntry`)。这通常用于调用 V8 引擎内部的 C++ 函数或外部的 C++ 扩展。
4. **代码去优化 (Deoptimization):** 包含了处理代码去优化的入口点 (`Generate_DeoptimizationEntry`, `Generate_DeoptimizationEntry_Eager`, `Generate_DeoptimizationEntry_Lazy`)。当 V8 的优化编译器生成的代码不再有效时（例如，由于类型推断错误），需要回退到解释器或基线编译器执行。这些函数负责保存当前状态，并跳转到合适的入口点。
5. **基线编译器/解释器入口:** 提供了进入基线编译器或解释器执行代码的入口点 (`Generate_BaselineOrInterpreterEnterAtBytecode`, `Generate_BaselineOrInterpreterEnterAtNextBytecode`, `Generate_InterpreterOnStackReplacement_ToBaseline`)。
6. **帧重启:** 提供了重启解释器帧的机制 (`Generate_RestartFrameTrampoline`)。

**与 JavaScript 的关系及示例:**

这个文件中的函数虽然是用 C++ 编写的，但它们直接支持 JavaScript 的执行。以下是一些 JavaScript 功能与这些 built-in 函数相关的例子：

1. **数字类型转换:**

    ```javascript
    let num = 123.45;
    let str1 = num.toString(); // 内部可能调用 Generate_NumberToString_Precise
    let str2 = (10**20).toString(); // 内部可能调用 Generate_NumberToString_PowerOfTen
    let bigNum = 123n;
    let str3 = bigNum.toString(); // 内部可能调用 Generate_NumberToString_Bignum

    let floatNum = 3.1415926;
    let intNum = Math.floor(floatNum); // 内部可能调用 Generate_DoubleToInteger
    ```

2. **API 回调处理:**

    ```javascript
    // 假设有一个 C++ 扩展定义了一个名为 'myFunction' 的函数
    // 并通过 FunctionTemplate 注册到 JavaScript 中

    function jsCallback(arg) {
      console.log("JavaScript callback called with:", arg);
      return arg * 2;
    }

    // C++ 代码中设置了一个回调函数
    // template->SetCallHandler(MyFunctionCallback);

    // 在 JavaScript 中调用该函数时，会触发 Generate_CallApiCallbackImpl
    let result = myFunction(10, jsCallback);
    ```

3. **API Getter:**

    ```javascript
    // 假设一个 C++ 扩展定义了一个名为 'myProperty' 的属性的 getter

    // C++ 代码中设置了 getter
    // accessor->SetGetter(MyPropertyGetter);

    let obj = {};
    // 当访问 obj.myProperty 时，会触发 Generate_CallApiGetter
    console.log(obj.myProperty);
    ```

4. **代码去优化 (Deoptimization):**

    ```javascript
    function potentiallyUnstableFunction(x) {
      if (typeof x === 'number') {
        return x + 1; // 优化器可能假设 x 总是数字
      } else {
        return x.toUpperCase(); // 如果 x 不是数字，优化后的代码可能需要回退
      }
    }

    potentiallyUnstableFunction(5); // 初始几次调用，V8 可能对其进行优化
    potentiallyUnstableFunction("hello"); // 之后调用传入非数字，可能触发去优化
    ```

5. **基线编译器/解释器入口:**

    当你首次执行一个 JavaScript 函数时，它通常会由解释器执行。随着执行次数的增加，V8 可能会选择使用基线编译器或更高级的优化编译器来提高性能。`Generate_BaselineOrInterpreterEnterAtBytecode` 和 `Generate_BaselineOrInterpreterEnterAtNextBytecode` 就是在这些场景下被调用的。

**总结:**

总而言之，`v8/src/builtins/ppc/builtins-ppc.cc` 的第 3 部分包含了在 PPC 架构上实现 JavaScript 核心功能的底层代码。这些 built-in 函数是 V8 引擎的关键组成部分，它们使得 JavaScript 代码能够在特定的硬件平台上高效地运行，并提供了 JavaScript 与底层系统交互的桥梁。虽然开发者通常不会直接与这些 C++ 代码交互，但它们的存在和正确性对于 JavaScript 引擎的性能和功能至关重要。

Prompt: 
```
这是目录为v8/src/builtins/ppc/builtins-ppc.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
 bits, 32 uncoded bits),
  // the result is 0.
  // Compare exponent with 84 (compare exponent - 1 with 83).
  __ cmpi(scratch, Operand(83));
  __ bge(&out_of_range);

  // If we reach this code, 31 <= exponent <= 83.
  // So, we don't have to handle cases where 0 <= exponent <= 20 for
  // which we would need to shift right the high part of the mantissa.
  // Scratch contains exponent - 1.
  // Load scratch with 52 - exponent (load with 51 - (exponent - 1)).
  __ subfic(scratch, scratch, Operand(51));
  __ cmpi(scratch, Operand::Zero());
  __ ble(&only_low);
  // 21 <= exponent <= 51, shift scratch_low and scratch_high
  // to generate the result.
  __ srw(scratch_low, scratch_low, scratch);
  // Scratch contains: 52 - exponent.
  // We needs: exponent - 20.
  // So we use: 32 - scratch = 32 - 52 + exponent = exponent - 20.
  __ subfic(scratch, scratch, Operand(32));
  __ ExtractBitMask(result_reg, scratch_high, HeapNumber::kMantissaMask);
  // Set the implicit 1 before the mantissa part in scratch_high.
  static_assert(HeapNumber::kMantissaBitsInTopWord >= 16);
  __ oris(result_reg, result_reg,
          Operand(1 << ((HeapNumber::kMantissaBitsInTopWord)-16)));
  __ ShiftLeftU32(r0, result_reg, scratch);
  __ orx(result_reg, scratch_low, r0);
  __ b(&negate);

  __ bind(&out_of_range);
  __ mov(result_reg, Operand::Zero());
  __ b(&done);

  __ bind(&only_low);
  // 52 <= exponent <= 83, shift only scratch_low.
  // On entry, scratch contains: 52 - exponent.
  __ neg(scratch, scratch);
  __ ShiftLeftU32(result_reg, scratch_low, scratch);

  __ bind(&negate);
  // If input was positive, scratch_high ASR 31 equals 0 and
  // scratch_high LSR 31 equals zero.
  // New result = (result eor 0) + 0 = result.
  // If the input was negative, we have to negate the result.
  // Input_high ASR 31 equals 0xFFFFFFFF and scratch_high LSR 31 equals 1.
  // New result = (result eor 0xFFFFFFFF) + 1 = 0 - result.
  __ srawi(r0, scratch_high, 31);
  __ srdi(r0, r0, Operand(32));
  __ xor_(result_reg, result_reg, r0);
  __ srwi(r0, scratch_high, Operand(31));
  __ add(result_reg, result_reg, r0);

  __ bind(&done);
  __ Pop(scratch_high, scratch_low);
  // Account for saved regs.
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
  //  -- r5                  : arguments count (not including the receiver)
  //  -- r6                  : FunctionTemplateInfo
  //  -- r3                  : holder
  //  -- cp                  : context
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
  Register scratch = r7;

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
  __ subi(sp, sp, Operand(FCA::kArgsLength * kSystemPointerSize));

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
    __ LoadExternalPointerField(
        api_function_address,
        FieldMemOperand(func_templ,
                        FunctionTemplateInfo::kMaybeRedirectedCallbackOffset),
        kFunctionTemplateInfoCallbackTag, no_reg, scratch);
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

  __ RecordComment("v8::FunctionCallback's argument");
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
  //  -- r4                  : receiver
  //  -- r6                  : accessor info
  //  -- r3                  : holder
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

  Register api_function_address = r5;
  Register receiver = ApiGetterDescriptor::ReceiverRegister();
  Register holder = ApiGetterDescriptor::HolderRegister();
  Register callback = ApiGetterDescriptor::CallbackRegister();
  Register scratch = r7;
  Register smi_zero = r8;

  DCHECK(!AreAliased(receiver, holder, callback, scratch, smi_zero));

  __ LoadTaggedField(scratch,
                     FieldMemOperand(callback, AccessorInfo::kDataOffset), r0);
  __ Push(receiver, scratch);  // kThisIndex, kDataIndex
  __ LoadRoot(scratch, RootIndex::kUndefinedValue);
  __ Move(smi_zero, Smi::zero());
  __ Push(scratch, smi_zero);  // kReturnValueIndex, kHolderV2Index
  __ Move(scratch, ER::isolate_address());
  __ Push(scratch, holder);  // kIsolateIndex, kHolderIndex

  __ LoadTaggedField(name_arg,
                     FieldMemOperand(callback, AccessorInfo::kNameOffset), r0);
  static_assert(kDontThrow == 0);
  __ Push(smi_zero, name_arg);  // should_throw_on_error -> kDontThrow, name

  __ RecordComment("Load api_function_address");
  __ LoadExternalPointerField(
      api_function_address,
      FieldMemOperand(callback, AccessorInfo::kMaybeRedirectedGetterOffset),
      kAccessorInfoGetterTag, no_reg, scratch);

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
  __ mr(name_arg, property_callback_info_arg);
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
  UseScratchRegisterScope temps(masm);
  Register temp2 = temps.Acquire();
  // Place the return address on the stack, making the call
  // GC safe. The RegExp backend also relies on this.
  __ mflr(r0);
  __ StoreU64(r0,
              MemOperand(sp, kStackFrameExtraParamSlot * kSystemPointerSize));

  if (ABI_USES_FUNCTION_DESCRIPTORS) {
    // AIX/PPC64BE Linux use a function descriptor;
    __ LoadU64(ToRegister(ABI_TOC_REGISTER),
               MemOperand(temp2, kSystemPointerSize));
    __ LoadU64(temp2, MemOperand(temp2, 0));  // Instruction address
  }

  __ Call(temp2);  // Call the C++ function.
  __ LoadU64(r0,
             MemOperand(sp, kStackFrameExtraParamSlot * kSystemPointerSize));
  __ mtlr(r0);
  __ blr();
}

namespace {

// This code tries to be close to ia32 code so that any changes can be
// easily ported.
void Generate_DeoptimizationEntry(MacroAssembler* masm,
                                  DeoptimizeKind deopt_kind) {
  Isolate* isolate = masm->isolate();

  // Unlike on ARM we don't save all the registers, just the useful ones.
  // For the rest, there are gaps on the stack, so the offsets remain the same.
  const int kNumberOfRegisters = Register::kNumRegisters;

  RegList restored_regs = kJSCallerSaved | kCalleeSaved;
  RegList saved_regs = restored_regs | sp;

  const int kDoubleRegsSize = kDoubleSize * DoubleRegister::kNumRegisters;

  // Save all double registers before messing with them.
  __ subi(sp, sp, Operand(kDoubleRegsSize));
  const RegisterConfiguration* config = RegisterConfiguration::Default();
  for (int i = 0; i < config->num_allocatable_double_registers(); ++i) {
    int code = config->GetAllocatableDoubleCode(i);
    const DoubleRegister dreg = DoubleRegister::from_code(code);
    int offset = code * kDoubleSize;
    __ stfd(dreg, MemOperand(sp, offset));
  }

  // Push saved_regs (needed to populate FrameDescription::registers_).
  // Leave gaps for other registers.
  __ subi(sp, sp, Operand(kNumberOfRegisters * kSystemPointerSize));
  for (int16_t i = kNumberOfRegisters - 1; i >= 0; i--) {
    if ((saved_regs.bits() & (1 << i)) != 0) {
      __ StoreU64(ToRegister(i), MemOperand(sp, kSystemPointerSize * i));
    }
  }
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    __ Move(scratch, ExternalReference::Create(
                         IsolateAddressId::kCEntryFPAddress, isolate));
    __ StoreU64(fp, MemOperand(scratch));
  }
  const int kSavedRegistersAreaSize =
      (kNumberOfRegisters * kSystemPointerSize) + kDoubleRegsSize;

  // Get the address of the location in the code object (r6) (return
  // address for lazy deoptimization) and compute the fp-to-sp delta in
  // register r7.
  __ mflr(r5);
  __ addi(r6, sp, Operand(kSavedRegistersAreaSize));
  __ sub(r6, fp, r6);

  // Allocate a new deoptimizer object.
  // Pass six arguments in r3 to r8.
  __ PrepareCallCFunction(5, r8);
  __ li(r3, Operand::Zero());
  Label context_check;
  __ LoadU64(r4,
             MemOperand(fp, CommonFrameConstants::kContextOrFrameTypeOffset));
  __ JumpIfSmi(r4, &context_check);
  __ LoadU64(r3, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ bind(&context_check);
  __ li(r4, Operand(static_cast<int>(deopt_kind)));
  // r5: code address or 0 already loaded.
  // r6: Fp-to-sp delta already loaded.
  __ Move(r7, ExternalReference::isolate_address());
  // Call Deoptimizer::New().
  {
    AllowExternalCallThatCantCauseGC scope(masm);
    __ CallCFunction(ExternalReference::new_deoptimizer_function(), 5);
  }

  // Preserve "deoptimizer" object in register r3 and get the input
  // frame descriptor pointer to r4 (deoptimizer->input_);
  __ LoadU64(r4, MemOperand(r3, Deoptimizer::input_offset()));

  // Copy core registers into FrameDescription::registers_[kNumRegisters].
  DCHECK_EQ(Register::kNumRegisters, kNumberOfRegisters);
  for (int i = 0; i < kNumberOfRegisters; i++) {
    int offset =
        (i * kSystemPointerSize) + FrameDescription::registers_offset();
    __ LoadU64(r5, MemOperand(sp, i * kSystemPointerSize));
    __ StoreU64(r5, MemOperand(r4, offset));
  }

  int simd128_regs_offset = FrameDescription::simd128_registers_offset();
  // Copy double registers to
  // double_registers_[DoubleRegister::kNumRegisters]
  for (int i = 0; i < config->num_allocatable_double_registers(); ++i) {
    int code = config->GetAllocatableDoubleCode(i);
    int dst_offset = code * kSimd128Size + simd128_regs_offset;
    int src_offset =
        code * kDoubleSize + kNumberOfRegisters * kSystemPointerSize;
    __ lfd(d0, MemOperand(sp, src_offset));
    __ stfd(d0, MemOperand(r4, dst_offset));
  }

  // Mark the stack as not iterable for the CPU profiler which won't be able to
  // walk the stack without the return address.
  {
    UseScratchRegisterScope temps(masm);
    Register is_iterable = temps.Acquire();
    Register zero = r7;
    __ LoadIsolateField(is_iterable, IsolateFieldId::kStackIsIterable);
    __ li(zero, Operand(0));
    __ stb(zero, MemOperand(is_iterable));
  }

  // Remove the saved registers from the stack.
  __ addi(sp, sp, Operand(kSavedRegistersAreaSize));

  // Compute a pointer to the unwinding limit in register r5; that is
  // the first stack slot not part of the input frame.
  __ LoadU64(r5, MemOperand(r4, FrameDescription::frame_size_offset()));
  __ add(r5, r5, sp);

  // Unwind the stack down to - but not including - the unwinding
  // limit and copy the contents of the activation frame to the input
  // frame description.
  __ addi(r6, r4, Operand(FrameDescription::frame_content_offset()));
  Label pop_loop;
  Label pop_loop_header;
  __ b(&pop_loop_header);
  __ bind(&pop_loop);
  __ pop(r7);
  __ StoreU64(r7, MemOperand(r6, 0));
  __ addi(r6, r6, Operand(kSystemPointerSize));
  __ bind(&pop_loop_header);
  __ CmpS64(r5, sp);
  __ bne(&pop_loop);

  // Compute the output frame in the deoptimizer.
  __ push(r3);  // Preserve deoptimizer object across call.
  // r3: deoptimizer object; r4: scratch.
  __ PrepareCallCFunction(1, r4);
  // Call Deoptimizer::ComputeOutputFrames().
  {
    AllowExternalCallThatCantCauseGC scope(masm);
    __ CallCFunction(ExternalReference::compute_output_frames_function(), 1);
  }
  __ pop(r3);  // Restore deoptimizer object (class Deoptimizer).

  __ LoadU64(sp, MemOperand(r3, Deoptimizer::caller_frame_top_offset()));

  // Replace the current (input) frame with the output frames.
  Label outer_push_loop, inner_push_loop, outer_loop_header, inner_loop_header;
  // Outer loop state: r7 = current "FrameDescription** output_",
  // r4 = one past the last FrameDescription**.
  __ lwz(r4, MemOperand(r3, Deoptimizer::output_count_offset()));
  __ LoadU64(r7,
             MemOperand(r3, Deoptimizer::output_offset()));  // r7 is output_.
  __ ShiftLeftU64(r4, r4, Operand(kSystemPointerSizeLog2));
  __ add(r4, r7, r4);
  __ b(&outer_loop_header);

  __ bind(&outer_push_loop);
  // Inner loop state: r5 = current FrameDescription*, r6 = loop index.
  __ LoadU64(r5, MemOperand(r7, 0));  // output_[ix]
  __ LoadU64(r6, MemOperand(r5, FrameDescription::frame_size_offset()));
  __ b(&inner_loop_header);

  __ bind(&inner_push_loop);
  __ addi(r6, r6, Operand(-sizeof(intptr_t)));
  __ add(r9, r5, r6);
  __ LoadU64(r9, MemOperand(r9, FrameDescription::frame_content_offset()));
  __ push(r9);

  __ bind(&inner_loop_header);
  __ cmpi(r6, Operand::Zero());
  __ bne(&inner_push_loop);  // test for gt?

  __ addi(r7, r7, Operand(kSystemPointerSize));
  __ bind(&outer_loop_header);
  __ CmpS64(r7, r4);
  __ blt(&outer_push_loop);

  __ LoadU64(r4, MemOperand(r3, Deoptimizer::input_offset()));
  for (int i = 0; i < config->num_allocatable_double_registers(); ++i) {
    int code = config->GetAllocatableDoubleCode(i);
    const DoubleRegister dreg = DoubleRegister::from_code(code);
    int src_offset = code * kSimd128Size + simd128_regs_offset;
    __ lfd(dreg, MemOperand(r4, src_offset));
  }

  // Push pc, and continuation from the last output frame.
  __ LoadU64(r9, MemOperand(r5, FrameDescription::pc_offset()));
  __ push(r9);
  __ LoadU64(r9, MemOperand(r5, FrameDescription::continuation_offset()));
  __ push(r9);

  // Restore the registers from the last output frame.
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    DCHECK(!(restored_regs.has(scratch)));
    __ mr(scratch, r5);
    for (int i = kNumberOfRegisters - 1; i >= 0; i--) {
      int offset =
          (i * kSystemPointerSize) + FrameDescription::registers_offset();
      if ((restored_regs.bits() & (1 << i)) != 0) {
        __ LoadU64(ToRegister(i), MemOperand(scratch, offset));
      }
    }
  }

  {
    UseScratchRegisterScope temps(masm);
    Register is_iterable = temps.Acquire();
    Register one = r7;
    __ push(one);  // Save the value from the output FrameDescription.
    __ LoadIsolateField(is_iterable, IsolateFieldId::kStackIsIterable);
    __ li(one, Operand(1));
    __ stb(one, MemOperand(is_iterable));
    __ pop(one);  // Restore the value from the output FrameDescription.
  }

  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    __ pop(scratch);  // get continuation, leave pc on stack
    __ pop(r0);
    __ mtlr(r0);
    Label end;
    __ CmpU64(scratch, Operand::Zero(), r0);
    __ beq(&end);
    __ Jump(scratch);
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

void Builtins::Generate_BaselineOrInterpreterEnterAtBytecode(
    MacroAssembler* masm) {
  // Implement on this platform, https://crrev.com/c/2695591.
  Generate_BaselineOrInterpreterEntry(masm, false);
}

void Builtins::Generate_BaselineOrInterpreterEnterAtNextBytecode(
    MacroAssembler* masm) {
  // Implement on this platform, https://crrev.com/c/2695591.
  Generate_BaselineOrInterpreterEntry(masm, true);
}

void Builtins::Generate_InterpreterOnStackReplacement_ToBaseline(
    MacroAssembler* masm) {
  // Implement on this platform, https://crrev.com/c/2800112.
  Generate_BaselineOrInterpreterEntry(masm, false, true);
}

void Builtins::Generate_RestartFrameTrampoline(MacroAssembler* masm) {
  // Frame is being dropped:
  // - Look up current function on the frame.
  // - Leave the frame.
  // - Restart the frame by calling the function.

  __ LoadU64(r4, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ LoadU64(r3, MemOperand(fp, StandardFrameConstants::kArgCOffset));
  __ LeaveFrame(StackFrame::INTERPRETED);

  // The arguments are already in the stack (including any necessary padding),
  // we should not try to massage the arguments again.
  __ mov(r5, Operand(kDontAdaptArgumentsSentinel));
  __ InvokeFunction(r4, r5, r3, InvokeType::kJump);
}

#undef __
}  // namespace internal
}  // namespace v8

#endif  // V8_TARGET_ARCH_PPC64

"""


```