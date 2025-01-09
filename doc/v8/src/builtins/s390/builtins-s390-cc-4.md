Response:
Let's break down the thought process for analyzing this V8 builtins code.

1. **Understanding the Context:** The first and most crucial step is recognizing what this file *is*. The path `v8/src/builtins/s390/builtins-s390.cc` immediately tells us several things:
    * It's part of the V8 JavaScript engine.
    * It contains "builtins," which are fundamental, often performance-critical, functions.
    * It's specific to the "s390" architecture (likely IBM System z).
    * It's a `.cc` file, meaning it's C++ code, likely using assembly for optimization.

2. **Initial Scan for Clues:**  Quickly skim the code looking for recognizable patterns and keywords. Things that jump out are:
    * Assembly instructions (`__ Push`, `__ LoadF64`, `__ ConvertDoubleToInt64`, etc.). The `__` prefix is a strong indicator of V8's macro assembler.
    * Function names like `Generate_DoubleToInt64`, `Generate_CallApiCallbackImpl`, `Generate_CallApiGetter`, `Generate_DeoptimizationEntry`, `Generate_InterpreterOnStackReplacement`, etc. The `Generate_` prefix suggests these functions *generate* assembly code for the corresponding operations.
    * Comments explaining the state of registers and the stack at various points. This is invaluable for understanding the purpose of the code.
    * Constants like `kSystemPointerSize`, `kDoubleSize`, and offsets within structures (e.g., `HeapNumber::kExponentMask`). This shows interaction with V8's internal data structures.
    * Calls to C++ helper functions within V8 (e.g., `CallApiFunctionAndReturn`).
    * The presence of `static_assert` which are compile-time checks.

3. **Analyzing Key Functions (Top-Down Approach):**  Start by examining the most prominent functions.

    * **`Generate_DoubleToInt64`:** The name is self-explanatory. The assembly code reveals a fast path for simple conversions and a more complex path to handle potential overflow and different exponent ranges. The bit manipulation suggests dealing with the IEEE 754 representation of doubles.

    * **`Generate_CallApiCallbackImpl`:** This deals with calling user-defined JavaScript functions from native (C++) code. The comments about the stack layout and the steps to set up `FunctionCallbackInfo` are key to understanding its role. The various `CallApiCallbackMode` options indicate different scenarios for these calls.

    * **`Generate_CallApiGetter`:** Similar to the callback, but specifically for calling getter functions defined in JavaScript. The setup of `PropertyCallbackArguments` is the focus here.

    * **`Generate_DeoptimizationEntry`:** This is a crucial part of V8's optimization strategy. When optimized code can no longer continue (e.g., due to type assumptions failing), it needs to "deoptimize" back to a less optimized version. This function handles the process of saving the current state and transitioning back. The separate `Eager` and `Lazy` variants hint at different trigger conditions for deoptimization.

    * **`Generate_InterpreterOnStackReplacement` and related functions:** These are about "on-stack replacement" (OSR). This is a technique where V8 can switch from interpreting bytecode to running optimized code (or vice-versa) while the function is already executing.

4. **Identifying Core Functionality:** Based on the analysis of the individual functions, we can start to group them by their purpose:
    * **Type Conversion:** `Generate_DoubleToInt64`
    * **Interfacing with JavaScript:** `Generate_CallApiCallbackImpl`, `Generate_CallApiGetter`
    * **Optimization and Deoptimization:** `Generate_DeoptimizationEntry_Eager`, `Generate_DeoptimizationEntry_Lazy`, `Generate_InterpreterOnStackReplacement`, `Generate_BaselineOnStackReplacement`, `Generate_BaselineOrInterpreterEnterAtBytecode`, `Generate_BaselineOrInterpreterEnterAtNextBytecode`, `Generate_InterpreterOnStackReplacement_ToBaseline`
    * **Internal Control Flow:** `Generate_RestartFrameTrampoline`

5. **Connecting to JavaScript:** Now, relate the C++ code to the JavaScript features it supports. The API callback and getter functions directly correspond to how native code interacts with JavaScript objects. Deoptimization and OSR are invisible to the JavaScript programmer but are fundamental to V8's performance.

6. **Considering `.tq`:** The question about `.tq` files introduces Torque. While this specific file is `.cc`, the prompt correctly points out that `.tq` files are another way to define builtins in V8. They offer a higher-level, type-safe way to write these functions, which are then compiled to C++ (and eventually assembly). If this file *were* `.tq`, the source would look very different (more like TypeScript with specific V8 extensions).

7. **Illustrative JavaScript Examples:**  For the API callback and getter, providing simple JavaScript examples makes the connection concrete. Demonstrating how a native function or an accessor defined in JavaScript would trigger the corresponding C++ builtins clarifies their purpose.

8. **Hypothetical Inputs and Outputs:**  For `Generate_DoubleToInt64`, providing input doubles and their expected integer outputs (including edge cases like overflow and negative numbers) demonstrates the function's behavior.

9. **Common Programming Errors:**  Relate the code to common JavaScript errors. For instance, using `parseInt` with non-numeric strings or numbers outside the safe integer range connects to the overflow handling in `Generate_DoubleToInt64`. Incorrectly setting up API callbacks or accessors in native modules would relate to `Generate_CallApiCallbackImpl` and `Generate_CallApiGetter`.

10. **Final Summary (as requested in part 5):**  Synthesize the findings into a concise overview of the file's role in V8, highlighting the key areas of functionality. Emphasize the performance-critical nature of these builtins for the s390 architecture.

By following these steps – understanding the context, scanning for clues, analyzing key functions, connecting to JavaScript, and providing examples – we can effectively dissect and explain the purpose of a complex V8 builtins file. The order might not be strictly linear; sometimes, understanding a specific assembly snippet helps clarify the purpose of a larger function. The key is to iterate and build up a comprehensive understanding.
这是一个V8 JavaScript引擎源代码文件，专门针对s390架构（IBM System z）的构建。作为第五部分，它汇总了之前讨论的功能。

**总而言之，`v8/src/builtins/s390/builtins-s390.cc` 文件的主要功能是为 s390 架构的 V8 引擎实现各种内置函数（builtins）。这些内置函数是 JavaScript 引擎执行 JavaScript 代码时频繁调用的底层操作，为了保证性能，通常会使用汇编语言进行高度优化。**

更具体地说，根据提供的代码片段，这个文件包含以下功能：

1. **`Generate_DoubleToInt64`:**  实现将 JavaScript 的双精度浮点数（double）快速转换为 64 位整数的内置函数。它包含快速路径优化和处理溢出情况的逻辑。

2. **`Generate_CallApiCallbackImpl`:**  实现从 C++ 代码调用 JavaScript 函数（通常是通过 Node.js 的原生模块或 V8 嵌入 API）的回调机制。它负责设置调用 JavaScript 函数所需的上下文和参数。

3. **`Generate_CallApiGetter`:**  实现当访问 JavaScript 对象的属性时，如果该属性定义了 getter 函数，则调用该 getter 函数的机制。它负责设置 `PropertyCallbackInfo` 对象，以便 getter 函数可以访问属性的上下文信息。

4. **`Generate_DirectCEntry`:**  这个函数目前是空的 (`__ stop();`)，可能在未来的版本中会被使用，或者在当前的 s390 实现中没有特定的直接 C 入口需求。

5. **`Generate_DeoptimizationEntry_Eager` 和 `Generate_DeoptimizationEntry_Lazy`:** 实现了 V8 的反优化（deoptimization）入口点。当优化的代码（例如，由 Crankshaft 或 TurboFan 生成的代码）无法继续执行时，需要回退到解释器执行。这两个函数分别处理 eager（立即）和 lazy（延迟）的反优化。

6. **`Generate_InterpreterOnStackReplacement` 和相关函数:**  实现了栈上替换 (On-Stack Replacement, OSR) 的机制。OSR 允许 V8 在函数执行过程中从解释器切换到优化的代码，或者从一种优化代码切换到另一种优化代码，而无需重新启动函数调用。这里包括了从解释器到优化代码（Baseline）的 OSR，以及进入解释器或 Baseline 代码的入口点。

7. **`Generate_RestartFrameTrampoline`:**  实现了一个用于重启帧的跳转点。这通常用于在调试或错误处理等场景下，需要重新执行某个函数帧的情况。

**关于 `.tq` 文件：**

如果 `v8/src/builtins/s390/builtins-s390.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。 Torque 是一种 V8 内部的领域特定语言，用于更安全、更易于维护地定义内置函数。 Torque 代码会被编译成 C++ 代码。

**与 JavaScript 功能的关系及示例：**

这些内置函数直接支持 JavaScript 的核心功能。

* **`Generate_DoubleToInt64`**:  与 JavaScript 中的 `parseInt()`、`Math.floor()`、类型转换等操作相关。

   ```javascript
   // JavaScript 调用 parseInt 时，底层可能会用到 DoubleToInt64
   let numStr = "123.45";
   let intValue = parseInt(numStr); // 123

   let floatNum = 987.65;
   let roundedDown = Math.floor(floatNum); // 987

   let doubleValue = 1e10;
   let intFromDouble = doubleValue | 0; // 使用位运算进行类型转换，也可能涉及 DoubleToInt64
   ```

* **`Generate_CallApiCallbackImpl`**: 当你使用 Node.js 的原生模块或 V8 嵌入 API 时，C++ 代码中调用 JavaScript 函数就会用到这个。

   ```javascript
   // Node.js 原生模块示例 (假设有这样的原生模块)
   // native_module.cc (C++ 代码)
   // ... 定义了一个可以调用 JavaScript 函数的回调函数
   void CallJavaScriptFunction(v8::Local<v8::Function> callback) {
     // ... 设置参数
     callback->Call(context, receiver, argc, argv); // 底层会用到 CallApiCallbackImpl
   }

   // test.js (JavaScript 代码)
   const nativeModule = require('./native_module');
   nativeModule.someFunction(function(err, result) {
     console.log(result);
   });
   ```

* **`Generate_CallApiGetter`**:  当访问对象属性时，如果该属性有 getter 定义，就会触发。

   ```javascript
   const obj = {
     _value: 10,
     get value() {
       return this._value * 2;
     }
   };

   console.log(obj.value); // 访问 value 属性会调用 getter，底层用到 CallApiGetter
   ```

* **`Generate_DeoptimizationEntry_*` 和 `Generate_InterpreterOnStackReplacement`**: 这些是 V8 内部的优化和反优化机制，对 JavaScript 开发者是透明的，但直接影响代码的执行效率。

**代码逻辑推理（`Generate_DoubleToInt64` 示例）：**

假设输入一个 JavaScript 的双精度浮点数 `123.7`。

* **假设输入：** 存储在内存中的双精度浮点数 `123.7` 的 IEEE 754 表示。
* **过程：**
    1. 代码首先尝试快速路径转换 (`__ ConvertDoubleToInt64`)。
    2. 检查结果是否为 32 位整数 (`__ TestIfInt32`). 对于 `123.7`，快速路径可能可以处理。
    3. 如果快速路径失败（例如，数字太大或太小），则进入慢速路径。
    4. 从内存中加载双精度数的指数和尾数部分 (`__ LoadU32`)。
    5. 提取指数并进行比较，判断是否溢出或需要进行移位操作。
    6. 根据指数的值，对尾数进行移位和组合，得到整数部分。
    7. 处理符号位。
* **预期输出：** 64 位整数 `123`。

假设输入一个超出 32 位整数范围的浮点数，例如 `2147483648.0` (2的31次方)。

* **假设输入：**  `2147483648.0` 的双精度表示。
* **过程：**
    1. 快速路径转换会检测到溢出。
    2. 进入慢速路径。
    3. 指数检查会确定该数字很大。
    4. 代码可能会直接返回 0 或执行特定的溢出处理逻辑。
* **预期输出：** 根据代码逻辑，对于超出范围的情况，可能会返回 `0`。

**用户常见的编程错误示例：**

* **使用 `parseInt` 解析非数字字符串：**

   ```javascript
   let text = "hello";
   let num = parseInt(text); // NaN (Not a Number)
   ```
   尽管 `parseInt` 会尝试转换，但对于完全非数字的字符串，它会返回 `NaN`。底层的转换逻辑不会成功得到一个有意义的整数。

* **将超出安全整数范围的数字转换为整数：**

   ```javascript
   let largeNumber = 9007199254740992; // 大于 Number.MAX_SAFE_INTEGER
   let intValue = parseInt(largeNumber); // 9007199254740992 (可能丢失精度)
   let intValue2 = largeNumber | 0;      // 0 (位运算转换可能会产生意外结果)
   ```
   JavaScript 的 `Number` 类型可以表示大整数，但在进行整数转换时，可能会丢失精度或产生意外的结果，这与 `Generate_DoubleToInt64` 中处理溢出的逻辑有关。

* **在 API 回调中错误地处理参数或上下文：** 如果原生模块传递了错误类型的参数给 JavaScript 回调，或者 JavaScript 回调试图访问不存在的上下文，可能会导致错误。这与 `Generate_CallApiCallbackImpl` 的正确参数设置密切相关。

**总结 (第五部分的功能归纳):**

`v8/src/builtins/s390/builtins-s390.cc` 是 V8 引擎中针对 s390 架构的关键组成部分，它通过汇编代码高效地实现了多种内置函数，这些函数支撑着 JavaScript 的核心功能，包括类型转换、与原生代码的交互（通过 API 回调和 getter）、以及优化和反优化执行流程。 这个文件是保证 V8 引擎在 s390 架构上高性能运行的基础。

Prompt: 
```
这是目录为v8/src/builtins/s390/builtins-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/s390/builtins-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共5部分，请归纳一下它的功能

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