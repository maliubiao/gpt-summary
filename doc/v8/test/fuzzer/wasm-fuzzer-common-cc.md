Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Initial Skim and Identify Key Areas:**  The first thing I do is quickly scan the code, looking for recognizable keywords and patterns. I see `#include`, `namespace v8::internal::wasm::fuzzing`, function definitions, comments, and names like `CompileReferenceModule`, `ExecuteAgainstReference`, `GenerateTestCase`, and `FuzzWasmModule`. This tells me it's related to WebAssembly fuzzing within the V8 JavaScript engine.

2. **Focus on the Core Functionality (`FuzzWasmModule`):** The name `FuzzWasmModule` strongly suggests this is the entry point for the fuzzing process. I'd pay close attention to its arguments (`data`, `require_valid`) and what it does. I notice it involves:
    * Getting the V8 isolate and context.
    * Clearing type canonicalizer data (important for managing Wasm types).
    * Enabling experimental Wasm features.
    * Using `GenerateModule` (likely a separate function generating the Wasm module).
    * Validating the generated module using `GetWasmEngine()->SyncValidate`.
    * Potentially generating a test case (`GenerateTestCase`).
    * Compiling the module using `GetWasmEngine()->SyncCompile`.
    * Executing the module against a reference implementation (`ExecuteAgainstReference`).

3. **Analyze Supporting Functions:**  Once I understand the main function, I examine the helper functions it calls:
    * **`CompileReferenceModule`:** This seems crucial for creating a "gold standard" execution of the Wasm module using Liftoff, V8's baseline compiler. This suggests a comparison-based fuzzing strategy. The function compiles *all* functions with Liftoff.
    * **`ExecuteAgainstReference`:** This function is the heart of the comparison. It compiles the fuzzed module and the reference module. It then instantiates and executes the "main" function of both, comparing the results (return value and exceptions). It also handles potential issues like infinite loops and OOM errors.
    * **`GenerateTestCase`:**  This function is responsible for printing the generated Wasm module in a human-readable format, likely for debugging or creating standalone test cases.
    * **`CompileTimeImportsForFuzzing`:** This seems to define the set of JavaScript imports the fuzzer can use when generating Wasm modules.
    * **`InstantiateDummyModule`:**  Likely used for setup or pre-populating some internal V8 state before the main fuzzing loop.
    * **`EnableExperimentalWasmFeatures`:**  This function is essential for maximizing the coverage of the fuzzer by enabling various experimental Wasm features in V8.

4. **Identify Key Data Structures and Concepts:** As I read through the code, I note down important data structures and concepts:
    * `WasmModuleObject`: Represents a compiled Wasm module.
    * `WasmInstanceObject`: Represents an instantiated Wasm module.
    * `NativeModule`: Internal representation of a Wasm module within V8.
    * `FunctionSig`: Represents the signature of a Wasm function.
    * `ModuleWireBytes`:  Represents the raw byte code of a Wasm module.
    * Liftoff, TurboFan, Turboshaft: V8's different Wasm compilers.
    * `CompileTimeImports`:  Represents the imported JavaScript functions/objects.
    * Fuzzing terminology: "reference execution," "max steps," "nondeterminism."

5. **Infer the Purpose and Functionality:** Based on the analysis above, I can deduce the main purpose of `wasm-fuzzer-common.cc`:  It provides common functionalities and helper functions for fuzzing WebAssembly modules within the V8 engine. The core idea is to generate random (potentially invalid) Wasm modules, compile them, and execute them, comparing their behavior against a known-good reference execution. This helps identify bugs and crashes in V8's Wasm implementation.

6. **Address Specific Questions:**  Now I can address the specific questions from the prompt:
    * **Functionality Listing:**  I'd list the key functions and their roles as described above.
    * **`.tq` Check:**  It's a C++ file, not a Torque file.
    * **JavaScript Relation:** The `CompileTimeImportsForFuzzing` function clearly indicates a connection to JavaScript. The imports allow interaction between Wasm and JS. I can construct a simple JavaScript example using `TextDecoder` or `TextEncoder`.
    * **Code Logic Reasoning:**  The `ExecuteAgainstReference` function provides a good example for logic reasoning. I'd explain the comparison logic, the handling of errors, and the role of `max_steps` and `nondeterminism`.
    * **Common Programming Errors:** I'd think about common Wasm errors that could arise during generation or execution, such as type mismatches, out-of-bounds access, or stack overflows. The `ExecuteAgainstReference` function's error handling also gives clues about potential issues.

7. **Refine and Structure:** Finally, I organize my findings into a clear and structured answer, using headings, bullet points, and code examples where appropriate. I ensure I've addressed all parts of the original prompt.

This iterative process of skimming, focusing, analyzing, inferring, and then refining helps in understanding complex codebases like this one.
这个 C++ 源代码文件 `v8/test/fuzzer/wasm-fuzzer-common.cc` 是 V8 JavaScript 引擎中用于 WebAssembly (Wasm) 模糊测试的通用代码库。它包含了一系列辅助函数和类，用于生成、编译、执行和验证 Wasm 模块，以及将它们的行为与参考实现进行比较。

以下是它的主要功能：

1. **提供编译时导入:** `CompileTimeImportsForFuzzing()` 函数定义了在模糊测试期间可以使用的 JavaScript 模块的导入项。目前，它包含了 `kJsString` (JavaScript 字符串), `kTextDecoder`, 和 `kTextEncoder`。这意味着模糊测试生成的 Wasm 模块可以导入并使用这些 JavaScript 功能。

2. **编译参考模块:** `CompileReferenceModule()` 函数用于编译一个 Wasm 模块，并使用 Liftoff 编译器（V8 的一个基线编译器）编译所有函数。这个模块被认为是“参考”实现，其行为将被用来比较模糊测试生成的模块的行为。该函数还处理在 Liftoff 执行期间更新最大步数计数器和不确定性标志。

3. **针对参考实现执行:** `ExecuteAgainstReference()` 函数是模糊测试的核心部分。它的作用是：
    *  编译一个给定的 Wasm 模块对象 (`module_object`)。
    *  使用 `CompileReferenceModule()` 编译相同的 Wasm 字节码，得到一个“参考”模块。
    *  实例化这两个模块。
    *  尝试调用两个模块的 "main" 导出函数。
    *  比较两个模块的执行结果（返回值和抛出的异常）。
    *  处理潜在的无限循环、内存溢出等情况。
    *  如果参考实现抛出异常或达到最大执行步数或存在不确定性，则不会执行测试模块。
    *  如果执行没有问题，则会对测试模块进行分层编译 (TierUpAllForTesting)，以检查优化编译器是否会遇到问题。

4. **生成测试用例:** `GenerateTestCase()` 函数用于将一个 Wasm 模块的字节码反汇编成人类可读的格式，并将其输出到标准输出。这对于调试和理解模糊测试生成的模块非常有用。它可以指示模块是否应该成功编译。

5. **实例化虚拟模块:** `InstantiateDummyModule()` 函数用于创建一个简单的 Wasm 模块实例。这可能是为了预热 V8 的 Wasm 子系统或者用于一些初始化的目的。

6. **启用实验性 Wasm 特性:** `EnableExperimentalWasmFeatures()` 函数用于在模糊测试期间启用 V8 中尚未正式发布的实验性 Wasm 特性。这有助于发现与新特性相关的 bug。

7. **Wasm 执行模糊测试器:** `WasmExecutionFuzzer::FuzzWasmModule()` 函数是模糊测试的入口点。它接收一段字节数组作为输入，并尝试将其解析为 Wasm 模块。它的主要步骤包括：
    *  获取 V8 的 Isolate 和 Context。
    *  清理类型规范化器的数据。
    *  启用实验性 Wasm 特性。
    *  使用 `GenerateModule()` 函数（未在此文件中定义，但很可能在其他地方）生成 Wasm 模块的二进制表示。
    *  使用 `GetWasmEngine()->SyncValidate()` 验证生成的模块是否合法。
    *  如果设置了 `v8_flags.wasm_fuzzer_gen_test`，则调用 `GenerateTestCase()` 输出测试用例。
    *  使用 `GetWasmEngine()->SyncCompile()` 编译模块。
    *  根据 `require_valid` 标志检查编译结果是否符合预期。
    *  如果模块有效，则调用 `ExecuteAgainstReference()` 将其与参考实现进行比较。

**关于 .tq 结尾:**

`v8/test/fuzzer/wasm-fuzzer-common.cc` 以 `.cc` 结尾，这表明它是一个 **C++** 源代码文件，而不是 Torque 源代码文件。Torque 源代码文件通常以 `.tq` 结尾。

**与 JavaScript 的关系:**

这个文件与 JavaScript 有着密切的关系，因为它测试的是 V8 JavaScript 引擎的 WebAssembly 实现。Wasm 模块可以在 JavaScript 环境中加载和执行，并且可以与 JavaScript 代码进行互操作。

**JavaScript 示例:**

```javascript
// 假设一个由模糊测试生成的 WASM 模块导出了一个名为 'add' 的函数，
// 该函数接收两个整数并返回它们的和。

// 加载 WASM 模块
fetch('your_wasm_module.wasm')
  .then(response => response.arrayBuffer())
  .then(bytes => WebAssembly.instantiate(bytes))
  .then(results => {
    const instance = results.instance;

    // 调用 WASM 模块导出的 'add' 函数
    const result = instance.exports.add(5, 10);
    console.log(result); // 输出 15

    // 如果 WASM 模块导入了 JavaScript 的 TextDecoder
    const decoder = new TextDecoder();
    // ... WASM 代码可能会调用导入的 TextDecoder 来解码数据
  });
```

**代码逻辑推理:**

**假设输入:** 一个有效的 Wasm 模块的字节数组，其中导出了一个名为 "main" 的函数，该函数接收两个 i32 类型的参数并返回一个 i32 类型的值。假设 "main" 函数的实现是将两个输入参数相加。

**`CompileReferenceModule` 的输出:**  一个编译后的 `WasmModuleObject`，其中 "main" 函数已使用 Liftoff 编译器编译。

**`ExecuteAgainstReference` 的假设流程:**

1. `ExecuteAgainstReference` 接收到编译后的模糊测试模块对象。
2. 它使用 `CompileReferenceModule` 编译相同的 Wasm 字节码，得到参考模块。
3. 两个模块都被成功实例化。
4. `ExecuteAgainstReference` 尝试获取两个模块导出的名为 "main" 的函数。
5. 它创建默认参数（例如，两个 0）传递给 "main" 函数。
6. 它调用参考模块的 "main" 函数，得到结果 (假设为 0)。
7. 它调用模糊测试模块的 "main" 函数。
8. 如果没有异常抛出，并且参考模块和模糊测试模块的返回值相同 (都为 0)，则 `ExecuteAgainstReference` 不会报错。

**如果输入的 Wasm 模块的 "main" 函数实现是返回两个输入参数的乘积:**

*   参考模块的 "main" 函数使用 Liftoff 编译，当输入为 0 和 0 时，返回 0。
*   模糊测试模块的 "main" 函数当输入为 0 和 0 时，返回 0。
*   `ExecuteAgainstReference` 会认为执行结果一致。

**如果输入的 Wasm 模块的 "main" 函数实现导致除零错误:**

*   参考模块的 "main" 函数在执行时可能会抛出一个异常。
*   模糊测试模块的 "main" 函数在执行时也会抛出相同的异常。
*   `ExecuteAgainstReference` 会检测到异常匹配。

**涉及用户常见的编程错误:**

1. **类型不匹配:** 用户在手动编写 Wasm 模块时，可能会错误地假设函数的参数或返回类型，导致与 JavaScript 代码交互时出现类型错误。
    ```javascript
    // JavaScript 调用期望返回数字的 WASM 函数，但 WASM 函数返回了字符串
    const result = instance.exports.myFunction();
    console.log(result + 1); // 可能会得到 "string1" 这样的结果，而不是数字加法
    ```

2. **内存访问越界:** Wasm 模块可以直接操作内存，如果计算的索引超出内存边界，会导致运行时错误。模糊测试旨在发现这类错误。
    ```c++
    // WASM 代码（C/C++ 编译到 WASM）
    int array[10];
    int index = 15; // 越界访问
    array[index] = 10; // 这会导致内存错误
    ```

3. **堆栈溢出:**  递归调用过深的 Wasm 函数可能导致堆栈溢出。
    ```c++
    // WASM 代码
    int recursiveFunction(int n) {
      if (n <= 0) return 0;
      return recursiveFunction(n - 1) + 1; // 如果初始 n 很大，可能导致堆栈溢出
    }
    ```

4. **未处理的导入错误:** 如果 Wasm 模块声明了导入项，但在实例化时没有提供相应的导入，会导致实例化失败。
    ```javascript
    // WASM 模块声明需要导入一个名为 'myLog' 的 JavaScript 函数
    // 但实例化时没有提供这个导入
    WebAssembly.instantiate(bytes, {}).catch(error => {
      console.error("Instantiation failed:", error); // 可能会看到关于缺失导入的错误
    });
    ```

5. **逻辑错误导致不确定性:**  在多线程或涉及浮点运算的 Wasm 代码中，细微的逻辑错误可能导致结果的不确定性。模糊测试通过多次运行相同的输入，可以帮助发现这种不确定性。

总而言之，`v8/test/fuzzer/wasm-fuzzer-common.cc` 是 V8 引擎中用于强化 WebAssembly 实现的关键组成部分，它通过生成和执行各种可能的 Wasm 模块，并与参考实现进行比较，来帮助发现潜在的 bug 和安全漏洞。

### 提示词
```
这是目录为v8/test/fuzzer/wasm-fuzzer-common.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/fuzzer/wasm-fuzzer-common.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "test/fuzzer/wasm-fuzzer-common.h"

#include "include/v8-context.h"
#include "include/v8-exception.h"
#include "include/v8-isolate.h"
#include "include/v8-local-handle.h"
#include "include/v8-metrics.h"
#include "src/execution/isolate.h"
#include "src/utils/ostreams.h"
#include "src/wasm/baseline/liftoff-compiler.h"
#include "src/wasm/compilation-environment-inl.h"
#include "src/wasm/function-body-decoder-impl.h"
#include "src/wasm/module-compiler.h"
#include "src/wasm/module-decoder-impl.h"
#include "src/wasm/module-instantiate.h"
#include "src/wasm/string-builder-multiline.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-feature-flags.h"
#include "src/wasm/wasm-module-builder.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-objects-inl.h"
#include "src/wasm/wasm-opcodes-inl.h"
#include "src/zone/accounting-allocator.h"
#include "src/zone/zone.h"
#include "test/common/flag-utils.h"
#include "test/common/wasm/wasm-module-runner.h"
#include "test/fuzzer/fuzzer-support.h"
#include "tools/wasm/mjsunit-module-disassembler-impl.h"

namespace v8::internal::wasm::fuzzing {

namespace {

void CompileAllFunctionsForReferenceExecution(NativeModule* native_module,
                                              int32_t* max_steps,
                                              int32_t* nondeterminism) {
  const WasmModule* module = native_module->module();
  WasmCodeRefScope code_ref_scope;
  CompilationEnv env = CompilationEnv::ForModule(native_module);
  ModuleWireBytes wire_bytes_accessor{native_module->wire_bytes()};
  for (size_t i = module->num_imported_functions; i < module->functions.size();
       ++i) {
    auto& func = module->functions[i];
    base::Vector<const uint8_t> func_code =
        wire_bytes_accessor.GetFunctionBytes(&func);
    constexpr bool kIsShared = false;
    FunctionBody func_body(func.sig, func.code.offset(), func_code.begin(),
                           func_code.end(), kIsShared);
    auto result =
        ExecuteLiftoffCompilation(&env, func_body,
                                  LiftoffOptions{}
                                      .set_func_index(func.func_index)
                                      .set_for_debugging(kForDebugging)
                                      .set_max_steps(max_steps)
                                      .set_nondeterminism(nondeterminism));
    if (!result.succeeded()) {
      FATAL(
          "Liftoff compilation failed on a valid module. Run with "
          "--trace-wasm-decoder (in a debug build) to see why.");
    }
    native_module->PublishCode(native_module->AddCompiledCode(result));
  }
}

}  // namespace

CompileTimeImports CompileTimeImportsForFuzzing() {
  CompileTimeImports result;
  result.Add(CompileTimeImport::kJsString);
  result.Add(CompileTimeImport::kTextDecoder);
  result.Add(CompileTimeImport::kTextEncoder);
  return result;
}

// Compile a baseline module. We pass a pointer to a max step counter and a
// nondeterminsm flag that are updated during execution by Liftoff.
Handle<WasmModuleObject> CompileReferenceModule(
    Isolate* isolate, base::Vector<const uint8_t> wire_bytes,
    int32_t* max_steps, int32_t* nondeterminism) {
  // Create the native module.
  std::shared_ptr<NativeModule> native_module;
  constexpr bool kNoVerifyFunctions = false;
  auto enabled_features = WasmEnabledFeatures::FromIsolate(isolate);
  WasmDetectedFeatures detected_features;
  ModuleResult module_res =
      DecodeWasmModule(enabled_features, wire_bytes, kNoVerifyFunctions,
                       ModuleOrigin::kWasmOrigin, &detected_features);
  CHECK(module_res.ok());
  std::shared_ptr<WasmModule> module = std::move(module_res).value();
  CHECK_NOT_NULL(module);
  CompileTimeImports compile_imports = CompileTimeImportsForFuzzing();
  WasmError imports_error = ValidateAndSetBuiltinImports(
      module.get(), wire_bytes, compile_imports, &detected_features);
  CHECK(!imports_error.has_error());  // The module was compiled before.
  native_module = GetWasmEngine()->NewNativeModule(
      isolate, enabled_features, detected_features,
      CompileTimeImportsForFuzzing(), module, 0);
  native_module->SetWireBytes(base::OwnedVector<uint8_t>::Of(wire_bytes));
  // The module is known to be valid as this point (it was compiled by the
  // caller before).
  module->set_all_functions_validated();

  // The value is -3 so that it is different than the compilation ID of actual
  // compilations, different than the sentinel value of the CompilationState
  // (-1) and the value used by native module deserialization (-2).
  const int dummy_fuzzing_compilation_id = -3;
  native_module->compilation_state()->set_compilation_id(
      dummy_fuzzing_compilation_id);
  InitializeCompilationForTesting(native_module.get());

  // Compile all functions with Liftoff.
  CompileAllFunctionsForReferenceExecution(native_module.get(), max_steps,
                                           nondeterminism);

  // Create the module object.
  constexpr base::Vector<const char> kNoSourceUrl;
  DirectHandle<Script> script =
      GetWasmEngine()->GetOrCreateScript(isolate, native_module, kNoSourceUrl);
  TypeCanonicalizer::PrepareForCanonicalTypeId(isolate,
                                               module->MaxCanonicalTypeIndex());
  return WasmModuleObject::New(isolate, std::move(native_module), script);
}

void ExecuteAgainstReference(Isolate* isolate,
                             Handle<WasmModuleObject> module_object,
                             int32_t max_executed_instructions) {
  // We do not instantiate the module if there is a start function, because a
  // start function can contain an infinite loop which we cannot handle.
  if (module_object->module()->start_function_index >= 0) return;

  int32_t max_steps = max_executed_instructions;
  int32_t nondeterminism = 0;

  HandleScope handle_scope(isolate);  // Avoid leaking handles.
  Zone reference_module_zone(isolate->allocator(), "wasm reference module");
  Handle<WasmModuleObject> module_ref = CompileReferenceModule(
      isolate, module_object->native_module()->wire_bytes(), &max_steps,
      &nondeterminism);
  Handle<WasmInstanceObject> instance_ref;

  // Try to instantiate the reference instance, return if it fails.
  {
    ErrorThrower thrower(isolate, "ExecuteAgainstReference");
    if (!GetWasmEngine()
             ->SyncInstantiate(isolate, &thrower, module_ref, {},
                               {})  // no imports & memory
             .ToHandle(&instance_ref)) {
      isolate->clear_exception();
      thrower.Reset();  // Ignore errors.
      return;
    }
  }

  // Get the "main" exported function. Do nothing if it does not exist.
  Handle<WasmExportedFunction> main_function;
  if (!testing::GetExportedFunction(isolate, instance_ref, "main")
           .ToHandle(&main_function)) {
    return;
  }

  struct OomCallbackData {
    Isolate* isolate;
    bool heap_limit_reached{false};
    size_t initial_limit{0};
  };
  OomCallbackData oom_callback_data{isolate};
  auto heap_limit_callback = [](void* raw_data, size_t current_limit,
                                size_t initial_limit) -> size_t {
    OomCallbackData* data = reinterpret_cast<OomCallbackData*>(raw_data);
    data->heap_limit_reached = true;
    data->isolate->TerminateExecution();
    data->initial_limit = initial_limit;
    // Return a slightly raised limit, just to make it to the next
    // interrupt check point, where execution will terminate.
    return initial_limit * 1.25;
  };
  isolate->heap()->AddNearHeapLimitCallback(heap_limit_callback,
                                            &oom_callback_data);

  Tagged<WasmExportedFunctionData> func_data =
      main_function->shared()->wasm_exported_function_data();
  const FunctionSig* sig = func_data->instance_data()
                               ->module()
                               ->functions[func_data->function_index()]
                               .sig;
  base::OwnedVector<Handle<Object>> compiled_args =
      testing::MakeDefaultArguments(isolate, sig);
  std::unique_ptr<const char[]> exception_ref;
  int32_t result_ref = testing::CallWasmFunctionForTesting(
      isolate, instance_ref, "main", compiled_args.as_vector(), &exception_ref);
  bool execute = true;
  // Reached max steps, do not try to execute the test module as it might
  // never terminate.
  if (max_steps < 0) execute = false;
  // If there is nondeterminism, we cannot guarantee the behavior of the test
  // module, and in particular it may not terminate.
  if (nondeterminism != 0) execute = false;
  // Similar to max steps reached, also discard modules that need too much
  // memory.
  isolate->heap()->RemoveNearHeapLimitCallback(heap_limit_callback,
                                               oom_callback_data.initial_limit);
  if (oom_callback_data.heap_limit_reached) {
    execute = false;
    isolate->CancelTerminateExecution();
  }

  if (exception_ref) {
    if (strcmp(exception_ref.get(),
               "RangeError: Maximum call stack size exceeded") == 0) {
      // There was a stack overflow, which may happen nondeterministically. We
      // cannot guarantee the behavior of the test module, and in particular it
      // may not terminate.
      execute = false;
    }
  }
  if (!execute) {
    // Before discarding the module, see if Turbofan runs into any DCHECKs.
    TierUpAllForTesting(isolate, instance_ref->trusted_data(isolate));
    return;
  }

  // Instantiate a fresh instance for the actual (non-ref) execution.
  Handle<WasmInstanceObject> instance;
  {
    ErrorThrower thrower(isolate, "ExecuteAgainstReference (second)");
    // We instantiated before, so the second instantiation must also succeed.
    if (!GetWasmEngine()
             ->SyncInstantiate(isolate, &thrower, module_object, {},
                               {})  // no imports & memory
             .ToHandle(&instance)) {
      DCHECK(thrower.error());
      // The only reason to fail the second instantiation should be OOM.
      if (strstr(thrower.error_msg(), "Out of memory")) {
        // The initial memory size might be too large for instantiation
        // (especially on 32 bit systems), therefore do not treat it as a fuzzer
        // failure.
        return;
      }
      FATAL("Second instantiation failed unexpectedly: %s",
            thrower.error_msg());
    }
    DCHECK(!thrower.error());
  }

  std::unique_ptr<const char[]> exception;
  int32_t result = testing::CallWasmFunctionForTesting(
      isolate, instance, "main", compiled_args.as_vector(), &exception);

  if ((exception_ref != nullptr) != (exception != nullptr)) {
    FATAL("Exception mismatch! Expected: <%s>; got: <%s>",
          exception_ref ? exception_ref.get() : "<no exception>",
          exception ? exception.get() : "<no exception>");
  }

  if (!exception) {
    CHECK_EQ(result_ref, result);
  }
}

void GenerateTestCase(Isolate* isolate, ModuleWireBytes wire_bytes,
                      bool compiles) {
  // Libfuzzer sometimes runs a test twice (for detecting memory leaks), and in
  // this case we do not want multiple outputs by this function.
  // Similarly if we explicitly execute the same test multiple times (via
  // `-runs=N`).
  static std::atomic<bool> did_output_before{false};
  if (did_output_before.exchange(true)) return;

  constexpr bool kVerifyFunctions = false;
  auto enabled_features = WasmEnabledFeatures::FromIsolate(isolate);
  WasmDetectedFeatures unused_detected_features;
  ModuleResult module_res = DecodeWasmModule(
      enabled_features, wire_bytes.module_bytes(), kVerifyFunctions,
      ModuleOrigin::kWasmOrigin, &unused_detected_features);
  CHECK_WITH_MSG(module_res.ok(), module_res.error().message().c_str());
  WasmModule* module = module_res.value().get();
  CHECK_NOT_NULL(module);

  AccountingAllocator allocator;
  Zone zone(&allocator, "constant expression zone");

  MultiLineStringBuilder out;
  NamesProvider names(module, wire_bytes.module_bytes());
  MjsunitModuleDis disassembler(out, module, &names, wire_bytes, &allocator,
                                !compiles);
  disassembler.PrintModule();
  const bool offsets = false;  // Not supported by MjsunitModuleDis.
  StdoutStream os;
  out.WriteTo(os, offsets);
  os.flush();
}

namespace {
std::vector<uint8_t> CreateDummyModuleWireBytes(Zone* zone) {
  // Build a simple module with a few types to pre-populate the type
  // canonicalizer.
  WasmModuleBuilder builder(zone);
  const bool is_final = true;
  builder.AddRecursiveTypeGroup(0, 2);
  builder.AddArrayType(zone->New<ArrayType>(kWasmF32, true), is_final);
  StructType::Builder struct_builder(zone, 2);
  struct_builder.AddField(kWasmI64, false);
  struct_builder.AddField(kWasmExternRef, false);
  builder.AddStructType(struct_builder.Build(), !is_final);
  FunctionSig::Builder sig_builder(zone, 1, 0);
  sig_builder.AddReturn(kWasmI32);
  builder.AddSignature(sig_builder.Get(), is_final);
  ZoneBuffer buffer{zone};
  builder.WriteTo(&buffer);
  return std::vector<uint8_t>(buffer.begin(), buffer.end());
}
}  // namespace

Handle<WasmInstanceObject> InstantiateDummyModule(Isolate* isolate,
                                                  Zone* zone) {
  testing::SetupIsolateForWasmModule(isolate);

  // Cache (and leak) the wire bytes, so they don't need to be rebuilt on each
  // run.
  static const std::vector<uint8_t> wire_bytes =
      CreateDummyModuleWireBytes(zone);

  ErrorThrower thrower(isolate, "WasmFuzzerCompileDummyModule");
  Handle<WasmModuleObject> module_object =
      GetWasmEngine()
          ->SyncCompile(isolate, WasmEnabledFeatures(),
                        CompileTimeImportsForFuzzing(), &thrower,
                        ModuleWireBytes(base::VectorOf(wire_bytes)))
          .ToHandleChecked();

  Handle<WasmInstanceObject> instance =
      GetWasmEngine()
          ->SyncInstantiate(isolate, &thrower, module_object, {}, {})
          .ToHandleChecked();
  CHECK_WITH_MSG(!thrower.error(), thrower.error_msg());
  return instance;
}

void EnableExperimentalWasmFeatures(v8::Isolate* isolate) {
  struct EnableExperimentalWasmFeatures {
    explicit EnableExperimentalWasmFeatures(v8::Isolate* isolate) {
      // Enable all staged features.
#define ENABLE_STAGED_FEATURES(feat, ...) \
  v8_flags.experimental_wasm_##feat = true;
      FOREACH_WASM_STAGING_FEATURE_FLAG(ENABLE_STAGED_FEATURES)
#undef ENABLE_STAGED_FEATURES

      // Enable non-staged experimental features or other experimental flags
      // that we also want to fuzz, e.g., new optimizations.
      // Note: If you add a Wasm feature here, you will also have to add the
      // respective flag(s) to the mjsunit/wasm/generate-random-module.js test,
      // otherwise that fails on an unsupported feature.
      // You may also want to add the flag(s) to the JS file header in
      // `PrintModule()` of `mjsunit-module-disassembler-impl.h`, to make bugs
      // easier to reproduce with generated mjsunit test cases.

      // See https://crbug.com/335082212.
      v8_flags.wasm_inlining_call_indirect = true;

      // Enforce implications from enabling features.
      FlagList::EnforceFlagImplications();

      // Last, install any conditional features. Implications are handled
      // implicitly.
      isolate->InstallConditionalFeatures(isolate->GetCurrentContext());
    }
  };
  // The compiler will properly synchronize the constructor call.
  static EnableExperimentalWasmFeatures one_time_enable_experimental_features(
      isolate);
}

void WasmExecutionFuzzer::FuzzWasmModule(base::Vector<const uint8_t> data,
                                         bool require_valid) {
  v8_fuzzer::FuzzerSupport* support = v8_fuzzer::FuzzerSupport::Get();
  v8::Isolate* isolate = support->GetIsolate();

  // Strictly enforce the input size limit. Note that setting "max_len" on the
  // fuzzer target is not enough, since different fuzzers are used and not all
  // respect that limit.
  if (data.size() > max_input_size()) return;

  Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);

  v8::Isolate::Scope isolate_scope(isolate);

  // Clear recursive groups: The fuzzer creates random types in every run. These
  // are saved as recursive groups as part of the type canonicalizer, but types
  // from previous runs just waste memory.
  GetTypeCanonicalizer()->EmptyStorageForTesting();
  TypeCanonicalizer::ClearWasmCanonicalTypesForTesting(i_isolate);

  // Clear any exceptions from a prior run.
  if (i_isolate->has_exception()) {
    i_isolate->clear_exception();
  }

  v8::HandleScope handle_scope(isolate);
  v8::Context::Scope context_scope(support->GetContext());

  // We explicitly enable staged WebAssembly features here to increase fuzzer
  // coverage. For libfuzzer fuzzers it is not possible that the fuzzer enables
  // the flag by itself.
  EnableExperimentalWasmFeatures(isolate);

  v8::TryCatch try_catch(isolate);
  HandleScope scope(i_isolate);

  AccountingAllocator allocator;
  Zone zone(&allocator, ZONE_NAME);

  ZoneBuffer buffer(&zone);

  // The first byte specifies some internal configuration, like which function
  // is compiled with which compiler, and other flags.
  uint8_t configuration_byte = data.empty() ? 0 : data[0];
  if (!data.empty()) data += 1;

  // Derive the compiler configuration for the first four functions from the
  // configuration byte, to choose for each function between:
  // 0: TurboFan
  // 1: Liftoff
  // 2: Liftoff for debugging
  // 3: Turboshaft
  uint8_t tier_mask = 0;
  uint8_t debug_mask = 0;
  uint8_t turboshaft_mask = 0;
  for (int i = 0; i < 4; ++i, configuration_byte /= 4) {
    int compiler_config = configuration_byte % 4;
    tier_mask |= (compiler_config == 0) << i;
    debug_mask |= (compiler_config == 2) << i;
    turboshaft_mask |= (compiler_config == 3) << i;
  }
  // Enable tierup for all turboshaft functions.
  tier_mask |= turboshaft_mask;

  if (!GenerateModule(i_isolate, &zone, data, &buffer)) {
    return;
  }

  testing::SetupIsolateForWasmModule(i_isolate);

  ModuleWireBytes wire_bytes(buffer.begin(), buffer.end());

  auto enabled_features = WasmEnabledFeatures::FromIsolate(i_isolate);

  bool valid = GetWasmEngine()->SyncValidate(
      i_isolate, enabled_features, CompileTimeImportsForFuzzing(), wire_bytes);

  if (v8_flags.wasm_fuzzer_gen_test) {
    GenerateTestCase(i_isolate, wire_bytes, valid);
  }

  FlagScope<bool> eager_compile(&v8_flags.wasm_lazy_compilation, false);
  // We want to keep dynamic tiering enabled because that changes the code
  // Liftoff generates as well as optimizing compilers' behavior (especially
  // around inlining). We switch it to synchronous mode to avoid the
  // nondeterminism of background jobs finishing at random times.
  FlagScope<bool> sync_tier_up(&v8_flags.wasm_sync_tier_up, true);
  // The purpose of setting the tier mask (which affects the initial
  // compilation of each function) is to deterministically test a combination
  // of Liftoff and Turbofan.
  FlagScope<int> tier_mask_scope(&v8_flags.wasm_tier_mask_for_testing,
                                 tier_mask);
  FlagScope<int> debug_mask_scope(&v8_flags.wasm_debug_mask_for_testing,
                                  debug_mask);
  FlagScope<int> turboshaft_mask_scope(
      &v8_flags.wasm_turboshaft_mask_for_testing, turboshaft_mask);

  ErrorThrower thrower(i_isolate, "WasmFuzzerSyncCompile");
  MaybeHandle<WasmModuleObject> compiled_module = GetWasmEngine()->SyncCompile(
      i_isolate, enabled_features, CompileTimeImportsForFuzzing(), &thrower,
      wire_bytes);
  CHECK_EQ(valid, !compiled_module.is_null());
  CHECK_EQ(!valid, thrower.error());
  if (require_valid && !valid) {
    FATAL("Generated module should validate, but got: %s", thrower.error_msg());
  }
  thrower.Reset();

  if (valid) {
    ExecuteAgainstReference(i_isolate, compiled_module.ToHandleChecked(),
                            kDefaultMaxFuzzerExecutedInstructions);
  }
}

}  // namespace v8::internal::wasm::fuzzing
```