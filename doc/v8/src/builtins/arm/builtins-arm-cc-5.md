Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the V8 JavaScript engine source code for the ARM architecture.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the file's purpose:** The file `v8/src/builtins/arm/builtins-arm.cc` suggests it contains implementations of built-in functions specifically for the ARM architecture. The name "builtins" is a strong indicator of this.

2. **Analyze individual functions:**  Go through each function (`Generate_...`) and determine its role. Look for keywords, comments, and function names that give clues about its functionality.

    * `Generate_CallApiCallback`:  The name and comments strongly suggest it's related to calling C++ functions from JavaScript via the V8 API.
    * `Generate_CallApiGetter`:  Similar to the above, but specifically for calling getter functions defined in C++.
    * `Generate_DirectCEntry`: The comments highlight its purpose for making GC-safe calls to C++ functions.
    * `Generate_MemCopyUint8Uint8`: The name clearly indicates a memory copy operation for unsigned 8-bit integers.
    * `Generate_DeoptimizationEntry`: The name and internal logic (saving registers, calling `Deoptimizer::New()`) point to handling deoptimization, a process of reverting from optimized code to less optimized code.
    * `Generate_DeoptimizationEntry_Eager` and `Generate_DeoptimizationEntry_Lazy`:  These seem to be specific types of deoptimization.
    * `Generate_BaselineOrInterpreterEntry`: This function appears to manage the transition between baseline (optimized) and interpreter (non-optimized) code execution.
    * `Generate_InterpreterOnStackReplacement_ToBaseline`: This is a specialized case of the previous function, specifically for upgrading from interpreter to baseline during execution.
    * `Generate_RestartFrameTrampoline`: The comments explain its role in restarting a function call after a frame has been dropped.

3. **Determine if it's Torque:** The prompt explicitly asks about Torque. The filename ends in `.cc`, *not* `.tq`, so it's not a Torque file.

4. **Identify JavaScript relevance:**  For each function, consider if it directly interacts with or supports JavaScript functionality. Most of these functions do:

    * API callbacks and getters are used to expose C++ functionality to JavaScript.
    * Deoptimization and baseline/interpreter entry are crucial parts of the JavaScript execution pipeline.
    * Even `MemCopyUint8Uint8` could be used internally by JavaScript for string or buffer manipulation.

5. **Provide JavaScript examples:** For functions with clear JavaScript connections, create simple examples to illustrate their use:

    * `CallApiCallback`: Demonstrate calling a JavaScript function that uses a native C++ callback.
    * `CallApiGetter`: Show accessing a JavaScript property that uses a native C++ getter.

6. **Consider code logic and assumptions:**  For functions with internal logic, analyze the steps and make educated guesses about input and output. For example, in `MemCopyUint8Uint8`, the input would be pointers to source and destination memory and the number of bytes, and the output would be the modified destination memory. However, the code itself doesn't explicitly take "input" in the way a standard function might in a higher-level language. The registers are pre-loaded with the necessary values.

7. **Identify common programming errors:** Think about potential errors related to the functionality:

    * API callbacks: Incorrect argument handling, memory management issues in the C++ callback.
    * Deoptimization:  While the user doesn't directly trigger this, understanding the concept helps.

8. **Synthesize a summary:** Combine the information gathered about each function to provide a high-level overview of the file's purpose. Emphasize the role of these built-ins in bridging the gap between JavaScript and the underlying C++ implementation.

9. **Address the "Part 6 of 6" instruction:**  Since this is the final part, emphasize the concluding nature of the functionality within the larger context of V8's built-ins for the ARM architecture.

10. **Review and refine:** Read through the generated answer to ensure clarity, accuracy, and completeness. Check if all parts of the prompt have been addressed. For instance, double-check the Torque question and the explanation of why it's not a Torque file. Ensure the JavaScript examples are correct and easy to understand. Ensure the assumptions for input/output are reasonable given the context of assembly-level operations within V8.
这是 V8 JavaScript 引擎中为 ARM 架构实现的内置函数（built-ins）的源代码文件。它包含了一些底层的、性能关键的操作，用于支持 JavaScript 代码的执行。

**功能列表:**

1. **`Generate_CallApiCallback`**:  用于调用由 JavaScript API (例如 Node.js 的原生模块) 提供的 C++ 函数。它负责设置调用 C++ 函数所需的栈帧和参数，并将结果返回给 JavaScript。

2. **`Generate_CallApiGetter`**: 用于调用由 JavaScript API 提供的 C++ getter 函数。当 JavaScript 代码访问一个由 C++ 代码定义的属性的 getter 时，会调用此函数。它与 `Generate_CallApiCallback` 类似，但专门针对属性访问的 getter 方法。

3. **`Generate_DirectCEntry`**: 提供一个直接调用 C++ 函数的入口点，主要用于那些可能会触发垃圾回收的调用。通过将返回地址存储在栈上，它确保了在垃圾回收期间调用者代码的安全移动。

4. **`Generate_MemCopyUint8Uint8`**: 实现一个高效的内存复制操作，用于复制 unsigned 8 位整数（字节）。这通常用于处理字符串或 ArrayBuffer 等数据。

5. **`Generate_DeoptimizationEntry_Eager` 和 `Generate_DeoptimizationEntry_Lazy`**:  处理代码的反优化（deoptimization）过程。当 V8 的优化编译器（TurboFan）生成的优化代码不再有效时（例如，由于类型假设失效），需要回退到解释器或基线编译器执行。这两个函数分别处理 eager（立即）和 lazy（延迟）的反优化。

6. **`Generate_BaselineOrInterpreterEnterAtBytecode` 和 `Generate_BaselineOrInterpreterEnterAtNextBytecode`**:  处理从解释器切换到基线编译器生成的代码的入口。基线编译器是 V8 的一个轻量级优化器。这些函数负责检查是否存在基线代码，并跳转到相应的入口点。`...AtNextBytecode` 版本用于在执行下一条字节码时进入基线代码。

7. **`Generate_InterpreterOnStackReplacement_ToBaseline`**:  处理栈上替换 (OSR, On-Stack Replacement) 到基线代码的过程。当解释器执行的代码被认为值得优化时，V8 可以在运行时将解释器栈帧替换为基线代码的栈帧，从而实现性能提升。

8. **`Generate_RestartFrameTrampoline`**:  用于重启一个栈帧。当一个栈帧被丢弃后，这个桩函数可以用来重新调用该函数。

**关于是否为 Torque 源代码:**

文件 `v8/src/builtins/arm/builtins-arm.cc` 的扩展名是 `.cc`，根据您提供的规则，它**不是**一个 Torque 源代码。Torque 源代码的文件扩展名应该是 `.tq`。

**与 JavaScript 功能的关系及 JavaScript 示例:**

这些内置函数是 V8 引擎执行 JavaScript 代码的基础。以下是一些与 JavaScript 功能相关的示例：

1. **`Generate_CallApiCallback`**: 当你在 Node.js 中使用原生模块时，例如：

   ```javascript
   // native_module.cc (C++ 代码)
   #include <node_api.h>

   napi_value MyFunction(napi_env env, napi_callback_info info) {
     // ... 一些 C++ 逻辑 ...
     return nullptr;
   }

   napi_value Init(napi_env env, napi_value exports) {
     napi_value fn;
     napi_create_function(env, "myFunction", NAPI_AUTO_LENGTH, MyFunction, nullptr, &fn);
     napi_set_named_property(env, exports, "myFunction", fn);
     return exports;
   }

   NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
   ```

   ```javascript
   // index.js
   const nativeModule = require('./build/Release/native_module');
   nativeModule.myFunction(); // 调用 C++ 函数
   ```

   当 `nativeModule.myFunction()` 被调用时，V8 内部会使用 `Generate_CallApiCallback` 来执行 C++ 函数 `MyFunction`。

2. **`Generate_CallApiGetter`**:  当你在 JavaScript 中访问一个由 C++ 代码定义并带有 getter 的属性时：

   ```javascript
   // my_object.cc (C++ 代码)
   #include <v8.h>

   using namespace v8;

   void MyGetter(Local<String> property,
                 const PropertyCallbackInfo<Value>& info) {
     Isolate* isolate = info.GetIsolate();
     info.GetReturnValue().Set(String::NewFromUtf8(isolate, "Hello from C++").ToLocalChecked());
   }

   Local<ObjectTemplate> CreateMyObjectTemplate(Isolate* isolate) {
     Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
     templ->SetAccessor(String::NewFromUtf8(isolate, "myProperty").ToLocalChecked(), MyGetter);
     return templ;
   }
   ```

   ```javascript
   // index.js
   // ... (假设你已经创建了 C++ 对象并暴露给 JavaScript)
   console.log(myObject.myProperty); // 访问带有 getter 的属性
   ```

   访问 `myObject.myProperty` 时，V8 会调用 `Generate_CallApiGetter` 来执行 C++ 函数 `MyGetter`。

3. **`Generate_DeoptimizationEntry_Eager` / `Generate_DeoptimizationEntry_Lazy`**: 这通常发生在 V8 优化了某段代码，但运行时发现之前的假设不成立时。例如：

   ```javascript
   function add(a, b) {
     return a + b;
   }

   // 假设 V8 优化了 add 函数，认为 a 和 b 始终是数字
   add(1, 2); // 优化后的执行

   add("hello", "world"); // 之前的类型假设失效，触发反优化
   ```

   当 `add("hello", "world")` 被调用时，如果 V8 之前将 `add` 函数优化为只处理数字类型，那么它会进行反优化，并可能进入 `Generate_DeoptimizationEntry_Lazy` 来回退到解释器执行。

4. **`Generate_BaselineOrInterpreterEnterAtBytecode`**:

   ```javascript
   function count(n) {
     let sum = 0;
     for (let i = 0; i < n; i++) {
       sum += i;
     }
     return sum;
   }

   count(10); // 最初可能由解释器执行
   count(1000); // 如果循环执行多次，V8 可能会生成基线代码，并通过此函数进入基线代码执行
   ```

   当 `count` 函数被多次调用时，V8 可能会决定使用基线编译器对其进行优化。在后续的调用中，V8 会使用 `Generate_BaselineOrInterpreterEnterAtBytecode` 来进入基线代码执行，以提高性能。

**代码逻辑推理、假设输入与输出:**

以 `Generate_MemCopyUint8Uint8` 为例：

**假设输入:**

* `dest` 寄存器包含目标内存的起始地址。
* `src` 寄存器包含源内存的起始地址。
* `chars` 寄存器包含要复制的字节数。

**代码逻辑:**

该函数使用循环来每次复制 4 个字节（一个字），然后处理剩余的 1、2 或 3 个字节。它使用了 `bic` (位清除) 指令来计算可以按字复制的字节数，并使用 `ldrh` (加载半字) 和 `ldrb` (加载字节) 指令来处理剩余的字节。

**假设输出:**

目标内存地址 (`dest` 指向的内存区域) 将包含从源内存地址 (`src` 指向的内存区域) 复制的 `chars` 个字节的数据。

**用户常见的编程错误:**

1. **在 API 回调中处理参数错误:** 用户在编写 C++ API 回调函数时，可能会忘记检查 JavaScript 传递的参数类型和数量，导致程序崩溃或行为异常。

   ```c++
   // 错误示例：假设 JavaScript 总是传递一个数字
   napi_value MyCallback(napi_env env, napi_callback_info info) {
     size_t argc = 1;
     napi_value args[1];
     napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
     double value;
     napi_get_value_double(env, args[0], &value); // 如果参数不是数字会出错
     // ...
     return nullptr;
   }
   ```

   **正确做法:** 应该检查参数类型：

   ```c++
   napi_value MyCallback(napi_env env, napi_callback_info info) {
     size_t argc = 1;
     napi_value args[1];
     napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
     if (argc < 1) {
       napi_throw_type_error(env, nullptr, "Expected one argument");
       return nullptr;
     }
     napi_valuetype type;
     napi_typeof(env, args[0], &type);
     if (type != napi_number) {
       napi_throw_type_error(env, nullptr, "Argument must be a number");
       return nullptr;
     }
     double value;
     napi_get_value_double(env, args[0], &value);
     // ...
     return nullptr;
   }
   ```

2. **在内存复制中出现缓冲区溢出:**  在手动进行内存操作时，如果目标缓冲区不够大，复制的数据可能会超出其边界，导致内存损坏。

   ```c++
   // 假设在 C++ API 回调中处理字符串
   napi_value MyStringCopy(napi_env env, napi_callback_info info) {
     size_t argc = 2;
     napi_value args[2];
     napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

     size_t length;
     char* buffer = nullptr;
     napi_get_value_string_utf8(env, args[0], nullptr, 0, &length);
     buffer = new char[length + 1]; // 分配缓冲区
     napi_get_value_string_utf8(env, args[0], buffer, length + 1, &length);

     size_t dest_length;
     napi_get_value_int64(env, args[1], (int64_t*)&dest_length); // 获取目标缓冲区大小 (错误)

     char dest_buffer[10]; // 固定大小的目标缓冲区 (潜在溢出)
     memcpy(dest_buffer, buffer, length); // 如果 length > 9，则会溢出
     dest_buffer[length] = '\0';

     delete[] buffer;
     return nullptr;
   }
   ```

   **正确做法:**  应该确保目标缓冲区足够大，或者使用更安全的字符串处理方法。

**第 6 部分，共 6 部分，功能归纳:**

`v8/src/builtins/arm/builtins-arm.cc` 文件是 V8 JavaScript 引擎中 ARM 架构的**核心内置函数实现**。它包含了用于：

* **与 C++ 代码交互**:  调用 JavaScript API 提供的 C++ 函数和 getter。
* **底层操作**:  执行高效的内存复制。
* **代码优化与反优化**:  管理从解释器到基线代码的切换，以及在优化失效时回退到非优化代码。
* **栈帧管理**:  处理栈帧的创建、销毁和重启。

这些内置函数是 V8 引擎执行 JavaScript 代码的关键组成部分，它们直接影响着 JavaScript 代码的性能和与原生代码的交互能力。作为架构特定的实现，它们充分利用了 ARM 架构的特性来提供高效的执行。

Prompt: 
```
这是目录为v8/src/builtins/arm/builtins-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/arm/builtins-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共6部分，请归纳一下它的功能

"""
         StackFrame::API_CALLBACK_EXIT);

  MemOperand argc_operand = MemOperand(fp, FC::kFCIArgcOffset);
  {
    ASM_CODE_COMMENT_STRING(masm, "Initialize v8::FunctionCallbackInfo");
    // FunctionCallbackInfo::length_.
    // TODO(ishell): pass JSParameterCount(argc) to simplify things on the
    // caller end.
    __ str(argc, argc_operand);

    // FunctionCallbackInfo::implicit_args_.
    __ add(scratch, fp, Operand(FC::kImplicitArgsArrayOffset));
    __ str(scratch, MemOperand(fp, FC::kFCIImplicitArgsOffset));

    // FunctionCallbackInfo::values_ (points at JS arguments on the stack).
    __ add(scratch, fp, Operand(FC::kFirstArgumentOffset));
    __ str(scratch, MemOperand(fp, FC::kFCIValuesOffset));
  }

  __ RecordComment("v8::FunctionCallback's argument.");
  __ add(function_callback_info_arg, fp,
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
  //  -- r1                  : receiver
  //  -- r3                  : accessor info
  //  -- r0                  : holder
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

  Register api_function_address = r2;
  Register receiver = ApiGetterDescriptor::ReceiverRegister();
  Register holder = ApiGetterDescriptor::HolderRegister();
  Register callback = ApiGetterDescriptor::CallbackRegister();
  Register scratch = r4;
  Register smi_zero = r5;

  DCHECK(!AreAliased(receiver, holder, callback, scratch, smi_zero));

  __ ldr(scratch, FieldMemOperand(callback, AccessorInfo::kDataOffset));
  __ Push(receiver, scratch);  // kThisIndex, kDataIndex
  __ LoadRoot(scratch, RootIndex::kUndefinedValue);
  __ Move(smi_zero, Smi::zero());
  __ Push(scratch, smi_zero);  // kReturnValueIndex, kHolderV2Index
  __ Move(scratch, ER::isolate_address());
  __ Push(scratch, holder);  // kIsolateIndex, kHolderIndex

  __ ldr(name_arg, FieldMemOperand(callback, AccessorInfo::kNameOffset));
  static_assert(kDontThrow == 0);
  __ Push(smi_zero, name_arg);  // should_throw_on_error -> kDontThrow, name

  __ RecordComment("Load api_function_address");
  __ ldr(api_function_address,
         FieldMemOperand(callback, AccessorInfo::kMaybeRedirectedGetterOffset));

  FrameScope frame_scope(masm, StackFrame::MANUAL);
  __ EnterExitFrame(scratch, FC::getExtraSlotsCountFrom<ExitFrameConstants>(),
                    StackFrame::API_ACCESSOR_EXIT);

  __ RecordComment("Create v8::PropertyCallbackInfo object on the stack.");
  // property_callback_info_arg = v8::PropertyCallbackInfo&
  __ add(property_callback_info_arg, fp, Operand(FC::kArgsArrayOffset));

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
  // The sole purpose of DirectCEntry is for movable callers (e.g. any general
  // purpose InstructionStream object) to be able to call into C functions that
  // may trigger GC and thus move the caller.
  //
  // DirectCEntry places the return address on the stack (updated by the GC),
  // making the call GC safe. The irregexp backend relies on this.

  __ str(lr, MemOperand(sp, 0));  // Store the return address.
  __ blx(ip);                     // Call the C++ function.
  __ ldr(pc, MemOperand(sp, 0));  // Return to calling code.
}

void Builtins::Generate_MemCopyUint8Uint8(MacroAssembler* masm) {
  Register dest = r0;
  Register src = r1;
  Register chars = r2;
  Register temp1 = r3;
  Label less_4;

  {
    UseScratchRegisterScope temps(masm);
    Register temp2 = temps.Acquire();
    Label loop;

    __ bic(temp2, chars, Operand(0x3), SetCC);
    __ b(&less_4, eq);
    __ add(temp2, dest, temp2);

    __ bind(&loop);
    __ ldr(temp1, MemOperand(src, 4, PostIndex));
    __ str(temp1, MemOperand(dest, 4, PostIndex));
    __ cmp(dest, temp2);
    __ b(&loop, ne);
  }

  __ bind(&less_4);
  __ mov(chars, Operand(chars, LSL, 31), SetCC);
  // bit0 => Z (ne), bit1 => C (cs)
  __ ldrh(temp1, MemOperand(src, 2, PostIndex), cs);
  __ strh(temp1, MemOperand(dest, 2, PostIndex), cs);
  __ ldrb(temp1, MemOperand(src), ne);
  __ strb(temp1, MemOperand(dest), ne);
  __ Ret();
}

namespace {

// This code tries to be close to ia32 code so that any changes can be
// easily ported.
void Generate_DeoptimizationEntry(MacroAssembler* masm,
                                  DeoptimizeKind deopt_kind) {
  Isolate* isolate = masm->isolate();

  // Note: This is an overapproximation; we always reserve space for 32 double
  // registers, even though the actual CPU may only support 16. In the latter
  // case, SaveFPRegs and RestoreFPRegs still use 32 stack slots, but only fill
  // 16.
  static constexpr int kDoubleRegsSize =
      kDoubleSize * DwVfpRegister::kNumRegisters;

  // Save all allocatable VFP registers before messing with them.
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    __ SaveFPRegs(sp, scratch);
  }

  // Save all general purpose registers before messing with them.
  static constexpr int kNumberOfRegisters = Register::kNumRegisters;
  static_assert(kNumberOfRegisters == 16);

  // Everything but pc, lr and ip which will be saved but not restored.
  RegList restored_regs = kJSCallerSaved | kCalleeSaved | RegList{ip};

  // Push all 16 registers (needed to populate FrameDescription::registers_).
  // TODO(v8:1588): Note that using pc with stm is deprecated, so we should
  // perhaps handle this a bit differently.
  __ stm(db_w, sp, restored_regs | RegList{sp, lr, pc});

  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    __ Move(scratch, ExternalReference::Create(
                         IsolateAddressId::kCEntryFPAddress, isolate));
    __ str(fp, MemOperand(scratch));
  }

  static constexpr int kSavedRegistersAreaSize =
      (kNumberOfRegisters * kPointerSize) + kDoubleRegsSize;

  // Get the address of the location in the code object (r3) (return
  // address for lazy deoptimization) and compute the fp-to-sp delta in
  // register r4.
  __ mov(r2, lr);
  __ add(r3, sp, Operand(kSavedRegistersAreaSize));
  __ sub(r3, fp, r3);

  // Allocate a new deoptimizer object.
  // Pass four arguments in r0 to r3 and fifth argument on stack.
  __ PrepareCallCFunction(5);
  __ mov(r0, Operand(0));
  Label context_check;
  __ ldr(r1, MemOperand(fp, CommonFrameConstants::kContextOrFrameTypeOffset));
  __ JumpIfSmi(r1, &context_check);
  __ ldr(r0, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ bind(&context_check);
  __ mov(r1, Operand(static_cast<int>(deopt_kind)));
  // r2: code address or 0 already loaded.
  // r3: Fp-to-sp delta already loaded.
  __ Move(r4, ExternalReference::isolate_address());
  __ str(r4, MemOperand(sp, 0 * kPointerSize));  // Isolate.
  // Call Deoptimizer::New().
  {
    AllowExternalCallThatCantCauseGC scope(masm);
    __ CallCFunction(ExternalReference::new_deoptimizer_function(), 5);
  }

  // Preserve "deoptimizer" object in register r0 and get the input
  // frame descriptor pointer to r1 (deoptimizer->input_);
  __ ldr(r1, MemOperand(r0, Deoptimizer::input_offset()));

  // Copy core registers into FrameDescription::registers_.
  DCHECK_EQ(Register::kNumRegisters, kNumberOfRegisters);
  for (int i = 0; i < kNumberOfRegisters; i++) {
    int offset = (i * kPointerSize) + FrameDescription::registers_offset();
    __ ldr(r2, MemOperand(sp, i * kPointerSize));
    __ str(r2, MemOperand(r1, offset));
  }

  // Copy simd128 / double registers to the FrameDescription.
  static constexpr int kSimd128RegsOffset =
      FrameDescription::simd128_registers_offset();
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    Register src_location = r4;
    __ add(src_location, sp, Operand(kNumberOfRegisters * kPointerSize));
    __ RestoreFPRegs(src_location, scratch);

    Register dst_location = r4;
    __ add(dst_location, r1, Operand(kSimd128RegsOffset));
    __ SaveFPRegsToHeap(dst_location, scratch);
  }

  // Mark the stack as not iterable for the CPU profiler which won't be able to
  // walk the stack without the return address.
  {
    UseScratchRegisterScope temps(masm);
    Register is_iterable = temps.Acquire();
    Register zero = r4;
    __ LoadIsolateField(is_iterable, IsolateFieldId::kStackIsIterable);
    __ mov(zero, Operand(0));
    __ strb(zero, MemOperand(is_iterable));
  }

  // Remove the saved registers from the stack.
  __ add(sp, sp, Operand(kSavedRegistersAreaSize));

  // Compute a pointer to the unwinding limit in register r2; that is
  // the first stack slot not part of the input frame.
  __ ldr(r2, MemOperand(r1, FrameDescription::frame_size_offset()));
  __ add(r2, r2, sp);

  // Unwind the stack down to - but not including - the unwinding
  // limit and copy the contents of the activation frame to the input
  // frame description.
  __ add(r3, r1, Operand(FrameDescription::frame_content_offset()));
  Label pop_loop;
  Label pop_loop_header;
  __ b(&pop_loop_header);
  __ bind(&pop_loop);
  __ pop(r4);
  __ str(r4, MemOperand(r3, 0));
  __ add(r3, r3, Operand(sizeof(uint32_t)));
  __ bind(&pop_loop_header);
  __ cmp(r2, sp);
  __ b(ne, &pop_loop);

  // Compute the output frame in the deoptimizer.
  __ push(r0);  // Preserve deoptimizer object across call.
  // r0: deoptimizer object; r1: scratch.
  __ PrepareCallCFunction(1);
  // Call Deoptimizer::ComputeOutputFrames().
  {
    AllowExternalCallThatCantCauseGC scope(masm);
    __ CallCFunction(ExternalReference::compute_output_frames_function(), 1);
  }
  __ pop(r0);  // Restore deoptimizer object (class Deoptimizer).

  __ ldr(sp, MemOperand(r0, Deoptimizer::caller_frame_top_offset()));

  // Replace the current (input) frame with the output frames.
  Label outer_push_loop, inner_push_loop, outer_loop_header, inner_loop_header;
  // Outer loop state: r4 = current "FrameDescription** output_",
  // r1 = one past the last FrameDescription**.
  __ ldr(r1, MemOperand(r0, Deoptimizer::output_count_offset()));
  __ ldr(r4, MemOperand(r0, Deoptimizer::output_offset()));  // r4 is output_.
  __ add(r1, r4, Operand(r1, LSL, 2));
  __ jmp(&outer_loop_header);
  __ bind(&outer_push_loop);
  // Inner loop state: r2 = current FrameDescription*, r3 = loop index.
  __ ldr(r2, MemOperand(r4, 0));  // output_[ix]
  __ ldr(r3, MemOperand(r2, FrameDescription::frame_size_offset()));
  __ jmp(&inner_loop_header);
  __ bind(&inner_push_loop);
  __ sub(r3, r3, Operand(sizeof(uint32_t)));
  __ add(r6, r2, Operand(r3));
  __ ldr(r6, MemOperand(r6, FrameDescription::frame_content_offset()));
  __ push(r6);
  __ bind(&inner_loop_header);
  __ cmp(r3, Operand::Zero());
  __ b(ne, &inner_push_loop);  // test for gt?
  __ add(r4, r4, Operand(kPointerSize));
  __ bind(&outer_loop_header);
  __ cmp(r4, r1);
  __ b(lt, &outer_push_loop);

  __ ldr(r1, MemOperand(r0, Deoptimizer::input_offset()));

  // State:
  // r1: Deoptimizer::input_ (FrameDescription*).
  // r2: The last output FrameDescription pointer (FrameDescription*).

  // Restore double registers from the output frame description.
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    Register src_location = r6;
    __ add(src_location, r2, Operand(kSimd128RegsOffset));
    __ RestoreFPRegsFromHeap(src_location, scratch);
  }

  // Push pc and continuation from the last output frame.
  __ ldr(r6, MemOperand(r2, FrameDescription::pc_offset()));
  __ push(r6);
  __ ldr(r6, MemOperand(r2, FrameDescription::continuation_offset()));
  __ push(r6);

  // Push the registers from the last output frame.
  for (int i = kNumberOfRegisters - 1; i >= 0; i--) {
    int offset = (i * kPointerSize) + FrameDescription::registers_offset();
    __ ldr(r6, MemOperand(r2, offset));
    __ push(r6);
  }

  // Restore the registers from the stack.
  __ ldm(ia_w, sp, restored_regs);  // all but pc registers.

  {
    UseScratchRegisterScope temps(masm);
    Register is_iterable = temps.Acquire();
    Register one = r4;
    __ push(one);  // Save the value from the output FrameDescription.
    __ LoadIsolateField(is_iterable, IsolateFieldId::kStackIsIterable);
    __ mov(one, Operand(1));
    __ strb(one, MemOperand(is_iterable));
    __ pop(one);  // Restore the value from the output FrameDescription.
  }

  // Remove sp, lr and pc.
  __ Drop(3);
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    __ pop(scratch);  // get continuation, leave pc on stack
    __ pop(lr);
    Label end;
    __ cmp(scratch, Operand::Zero());
    __ b(eq, &end);
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

namespace {

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
  Register closure = r1;
  __ ldr(closure, MemOperand(fp, StandardFrameConstants::kFunctionOffset));

  // Get the InstructionStream object from the shared function info.
  Register code_obj = r4;
  __ ldr(code_obj,
         FieldMemOperand(closure, JSFunction::kSharedFunctionInfoOffset));

  if (is_osr) {
    ResetSharedFunctionInfoAge(masm, code_obj, r3);
  }

  __ ldr(code_obj,
         FieldMemOperand(code_obj,
                         SharedFunctionInfo::kTrustedFunctionDataOffset));

  // Check if we have baseline code. For OSR entry it is safe to assume we
  // always have baseline code.
  if (!is_osr) {
    Label start_with_baseline;
    __ CompareObjectType(code_obj, r3, r3, CODE_TYPE);
    __ b(eq, &start_with_baseline);

    // Start with bytecode as there is no baseline code.
    Builtin builtin = next_bytecode ? Builtin::kInterpreterEnterAtNextBytecode
                                    : Builtin::kInterpreterEnterAtBytecode;
    __ TailCallBuiltin(builtin);

    // Start with baseline code.
    __ bind(&start_with_baseline);
  } else if (v8_flags.debug_code) {
    __ CompareObjectType(code_obj, r3, r3, CODE_TYPE);
    __ Assert(eq, AbortReason::kExpectedBaselineData);
  }

  if (v8_flags.debug_code) {
    AssertCodeIsBaseline(masm, code_obj, r3);
  }

  // Load the feedback cell and vector.
  Register feedback_cell = r2;
  Register feedback_vector = r9;
  __ ldr(feedback_cell,
         FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
  __ ldr(feedback_vector,
         FieldMemOperand(feedback_cell, FeedbackCell::kValueOffset));

  Label install_baseline_code;
  // Check if feedback vector is valid. If not, call prepare for baseline to
  // allocate it.
  __ CompareObjectType(feedback_vector, r3, r3, FEEDBACK_VECTOR_TYPE);
  __ b(ne, &install_baseline_code);

  // Save BytecodeOffset from the stack frame.
  __ ldr(kInterpreterBytecodeOffsetRegister,
         MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ SmiUntag(kInterpreterBytecodeOffsetRegister);
  // Replace bytecode offset with feedback cell.
  static_assert(InterpreterFrameConstants::kBytecodeOffsetFromFp ==
                BaselineFrameConstants::kFeedbackCellFromFp);
  __ str(feedback_cell,
         MemOperand(fp, BaselineFrameConstants::kFeedbackCellFromFp));
  feedback_cell = no_reg;
  // Update feedback vector cache.
  static_assert(InterpreterFrameConstants::kFeedbackVectorFromFp ==
                BaselineFrameConstants::kFeedbackVectorFromFp);
  __ str(feedback_vector,
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
  Register get_baseline_pc = r3;
  __ Move(get_baseline_pc, get_baseline_pc_extref);

  // If the code deoptimizes during the implicit function entry stack interrupt
  // check, it will have a bailout ID of kFunctionEntryBytecodeOffset, which is
  // not a valid bytecode offset.
  // TODO(pthier): Investigate if it is feasible to handle this special case
  // in TurboFan instead of here.
  Label valid_bytecode_offset, function_entry_bytecode;
  if (!is_osr) {
    __ cmp(kInterpreterBytecodeOffsetRegister,
           Operand(BytecodeArray::kHeaderSize - kHeapObjectTag +
                   kFunctionEntryBytecodeOffset));
    __ b(eq, &function_entry_bytecode);
  }

  __ sub(kInterpreterBytecodeOffsetRegister, kInterpreterBytecodeOffsetRegister,
         Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));

  __ bind(&valid_bytecode_offset);
  // Get bytecode array from the stack frame.
  __ ldr(kInterpreterBytecodeArrayRegister,
         MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  // Save the accumulator register, since it's clobbered by the below call.
  __ Push(kInterpreterAccumulatorRegister);
  {
    __ mov(kCArgRegs[0], code_obj);
    __ mov(kCArgRegs[1], kInterpreterBytecodeOffsetRegister);
    __ mov(kCArgRegs[2], kInterpreterBytecodeArrayRegister);
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ PrepareCallCFunction(3, 0);
    __ CallCFunction(get_baseline_pc, 3, 0);
  }
  __ LoadCodeInstructionStart(code_obj, code_obj);
  __ add(code_obj, code_obj, kReturnRegister0);
  __ Pop(kInterpreterAccumulatorRegister);

  if (is_osr) {
    Generate_OSREntry(masm, code_obj);
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

  __ ldr(r1, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ ldr(r0, MemOperand(fp, StandardFrameConstants::kArgCOffset));
  __ LeaveFrame(StackFrame::INTERNAL);

  // The arguments are already in the stack (including any necessary padding),
  // we should not try to massage the arguments again.
  __ mov(r2, Operand(kDontAdaptArgumentsSentinel));
  __ InvokeFunction(r1, r2, r0, InvokeType::kJump);
}

#undef __

}  // namespace internal
}  // namespace v8

#endif  // V8_TARGET_ARCH_ARM

"""


```