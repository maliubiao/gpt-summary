Response:
Let's break down the thought process to analyze the given C++ code.

1. **Understand the Request:** The request asks for the functionality of `v8/src/wasm/function-compiler.cc`, specifically looking for:
    * Its main purpose.
    * Whether it's Torque code (it's not, as indicated by the `.cc` extension).
    * Connections to JavaScript functionality (and examples).
    * Code logic with hypothetical inputs and outputs.
    * Common programming errors it might relate to.

2. **Initial Code Scan (Keywords and Structure):** Quickly scan the code for important keywords and structural elements:
    * `#include`: Indicates dependencies on other V8 components. Notice `wasm`, `compiler`, `codegen`, `objects`, suggesting a compilation-related file within the WebAssembly part of V8.
    * `namespace v8::internal::wasm`: Confirms the WebAssembly context.
    * Class names: `WasmCompilationUnit`, `JSToWasmWrapperCompilationUnit`. These are likely the core components.
    * Method names: `ExecuteCompilation`, `ExecuteFunctionCompilation`, `CompileWasmFunction`, `CompileJSToWasmWrapper`, `Execute`, `Finalize`. These hint at the steps involved in compiling WebAssembly functions and wrappers.
    * `switch (tier_)`: Suggests different compilation strategies or levels. The `ExecutionTier` enum is mentioned.
    * Mentions of `Liftoff`, `TurboFan`, `Turboshaft`: These are V8's different WebAssembly compilers.
    * `Counters`, `WasmDetectedFeatures`, `CompilationEnv`: These look like supporting data structures for the compilation process.

3. **Focus on `WasmCompilationUnit`:** This class seems central to compiling WebAssembly functions *within* the WebAssembly module.

    * **`ExecuteCompilation`:** This looks like the main entry point for compiling a function. It takes a `CompilationEnv`, `WireBytesStorage`, `Counters`, and `WasmDetectedFeatures`. It calls `ExecuteFunctionCompilation` and updates counters.
    * **`ExecuteFunctionCompilation`:** This is where the actual compilation logic resides. It retrieves the function body, checks for validation, and then uses a `switch` statement based on the `tier_` to choose the compiler (`Liftoff`, `TurboFan`, `Turboshaft`).
    * **`CompileWasmFunction` (static):**  This appears to be a helper function to initiate the compilation of a given `WasmFunction`. It sets up the `WasmCompilationUnit` and `CompilationEnv`.

4. **Focus on `JSToWasmWrapperCompilationUnit`:** This class seems responsible for creating wrappers that allow JavaScript code to call WebAssembly functions.

    * **Constructor:** It creates a `CompilationJob` (either `TurbofanCompilationJob` or `TurboshaftCompilationJob`). The `wasm_jitless` flag is relevant here.
    * **`Execute`:** Executes the compilation job.
    * **`Finalize`:**  Finalizes the compilation, gets the compiled code, and stores it in a cache (`js_to_wasm_wrappers`).
    * **`CompileJSToWasmWrapper` (static):** A helper to synchronously compile a JSToWasm wrapper.

5. **Identify Key Functionality:** Based on the analysis above, the primary functionalities are:
    * Compiling individual WebAssembly functions using different tiers (Liftoff, TurboFan, Turboshaft).
    * Creating wrappers that allow JavaScript to call WebAssembly functions.

6. **Address Specific Questions from the Request:**

    * **Functionality:** Summarize the findings from steps 3-5.
    * **Torque:** Explicitly state that `.cc` indicates C++, not Torque.
    * **Relationship to JavaScript:** The `JSToWasmWrapperCompilationUnit` directly connects to JavaScript. Think about *why* these wrappers are needed: to bridge the gap between JS and WASM's different calling conventions and data types. This leads to the example of calling a WASM function from JS.
    * **Code Logic and I/O:**  Focus on the core compilation process within `ExecuteFunctionCompilation`.
        * **Input:**  A `WasmFunction` (defined by its index, code, and signature) and the compilation tier.
        * **Process:** Validation, then selection of a compiler based on the tier.
        * **Output:**  A `WasmCompilationResult` containing the compiled code and metadata.
    * **Common Programming Errors:**  Think about what could go wrong in this compilation process, especially from a *user's* perspective when writing WebAssembly or interacting with it from JavaScript. Examples include:
        * **Mismatched signatures:**  The JavaScript calling a WASM function with incorrect argument types. This is directly related to the purpose of the wrappers.
        * **Invalid WebAssembly:** While the compiler *should* catch this, it's a fundamental error that `ValidateFunctionBody` handles. If validation fails *before* compilation, that's an error.

7. **Refine and Structure the Answer:**  Organize the information logically, using clear headings and bullet points. Provide code examples where requested (JavaScript example). Ensure the explanation is understandable without deep knowledge of V8 internals. For the "assumptions" in the code logic, be clear about what aspects of the process are being illustrated. For programming errors, focus on user-level mistakes.

8. **Review and Verify:**  Read through the generated answer to ensure accuracy and completeness. Double-check that all aspects of the request have been addressed. For example, ensure the explanation of Liftoff, TurboFan, and Turboshaft is included.

This systematic approach allows for a comprehensive understanding of the code and effectively answers the given request. The key is to start broad, then narrow the focus to the most important parts of the code, and finally relate those parts back to the specific questions asked.
好的，让我们来分析一下 `v8/src/wasm/function-compiler.cc` 这个 V8 源代码文件的功能。

**主要功能概述:**

`v8/src/wasm/function-compiler.cc` 负责将 WebAssembly 函数编译成本地机器码。它定义了用于管理和执行 WebAssembly 函数编译过程的类和方法。  这个文件是 V8 中 WebAssembly 编译管道的核心组成部分。

**具体功能点:**

1. **`WasmCompilationUnit` 类:**
   - **封装单个 WebAssembly 函数的编译任务。**  每个 `WasmCompilationUnit` 实例负责编译一个特定的 WebAssembly 函数。
   - **`ExecuteCompilation` 方法:**  作为编译的入口点，它协调整个编译过程。
   - **`ExecuteFunctionCompilation` 方法:**  实际执行 WebAssembly 函数的编译。它会根据配置选择不同的编译层级（`ExecutionTier`），例如：
     - **Liftoff:**  一个快速的、单趟的基线编译器，用于快速启动执行。
     - **TurboFan:**  V8 的优化编译器，可以生成高性能的机器码。
     - **Turboshaft:**  V8 新一代的优化编译器。
   - **处理编译结果:** 存储编译生成的代码、重定位信息、去优化数据等。
   - **统计编译指标:**  如果启用了计数器，它会记录生成的代码大小、重定位大小等信息。
   - **处理函数验证:** 在编译前确保函数已经通过验证（除非某些特定情况下，例如延迟验证）。

2. **`JSToWasmWrapperCompilationUnit` 类:**
   - **负责生成 JavaScript 调用 WebAssembly 函数的包装器代码。** 当 JavaScript 代码需要调用一个 WebAssembly 导出的函数时，V8 需要生成一段桥接代码来处理参数转换和调用约定。
   - **`Execute` 方法:**  执行包装器代码的编译。
   - **`Finalize` 方法:**  完成编译，将生成的代码存储起来，并将其添加到缓存中。
   - **使用 `CompilationJob`:**  这个类内部使用了 V8 的通用编译任务框架 (`CompilationJob`) 来执行编译工作。它可以利用 TurboFan 或 Turboshaft 来编译这些包装器。

3. **`CompileWasmFunction` 静态方法:**
   - 提供一个方便的入口点，用于编译一个指定的 WebAssembly 函数。
   - 它创建 `WasmCompilationUnit` 实例，设置编译环境，并执行编译。
   - 编译成功后，它将生成的代码发布到 `NativeModule` 中。

**关于文件扩展名和 Torque:**

- `v8/src/wasm/function-compiler.cc` 的扩展名是 `.cc`，这表明它是一个 **C++ 源代码文件**。
- 如果文件以 `.tq` 结尾，那它才是 V8 Torque 源代码。Torque 是一种 V8 自研的用于生成高效 C++ 代码的领域特定语言。

**与 JavaScript 的关系及示例:**

`v8/src/wasm/function-compiler.cc`  与 JavaScript 的功能有着直接的联系，因为它负责编译 WebAssembly 代码，而 WebAssembly 经常在 JavaScript 环境中运行。  `JSToWasmWrapperCompilationUnit` 就是一个明显的例子，它专门处理 JavaScript 调用 WebAssembly 的场景。

**JavaScript 示例:**

```javascript
// 假设有一个名为 'myModule.wasm' 的 WebAssembly 模块，导出一个名为 'add' 的函数

async function loadAndRunWasm() {
  const response = await fetch('myModule.wasm');
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.instantiate(buffer);

  // 调用 WebAssembly 导出的 'add' 函数
  const result = module.instance.exports.add(5, 3);
  console.log(result); // 输出: 8
}

loadAndRunWasm();
```

在这个例子中，当你调用 `module.instance.exports.add(5, 3)` 时，V8 内部就需要用到 `JSToWasmWrapperCompilationUnit` 生成的包装器代码。这个包装器会将 JavaScript 的参数 (5 和 3) 转换为 WebAssembly 函数可以接受的格式，并调用编译后的 WebAssembly `add` 函数。

**代码逻辑推理 (假设输入与输出):**

假设我们有一个简单的 WebAssembly 函数，它接受两个 i32 类型的参数并返回它们的和：

**WebAssembly (WAT 格式):**

```wat
(module
  (func (export "add") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.add
  )
)
```

**假设输入 (对于 `WasmCompilationUnit::ExecuteFunctionCompilation`):**

- `env`: 一个指向 `CompilationEnv` 结构的指针，包含了编译所需的模块信息、特性开关等。
- `wire_bytes_storage`:  存储 WebAssembly 字节码的结构。
- `tier_`: `ExecutionTier::kTurbofan` (假设我们选择使用 TurboFan 编译)。
- `func_index_`:  这个函数的索引，假设为 0。
- `func_body`:  包含了函数字节码的起始和结束位置。

**可能的输出 (简化描述):**

- `result.succeeded()`: `true` (假设编译成功)。
- `result.code_desc`: 一个描述生成的机器码的数据结构，包括：
    - `instr_size`: 生成的指令大小 (例如：几十到几百字节，取决于具体的机器码)。
    - `reloc_size`: 重定位信息的大小 (可能为 0 或较小的值)。
- `result.code_object`: 一个指向生成的 `Code` 对象的指针，这个对象包含了实际的机器码。

**代码逻辑推理步骤 (简化):**

1. `ExecuteFunctionCompilation` 被调用。
2. 根据 `func_index_` 获取函数体。
3. 检查函数是否已经验证，如果没有，则进行验证。
4. 由于 `tier_` 是 `kTurbofan`，代码会进入 `case ExecutionTier::kTurbofan` 分支。
5. 创建 `compiler::WasmCompilationData` 对象，包含函数体信息。
6. 调用 `compiler::ExecuteTurbofanWasmCompilation`，将函数编译成优化后的机器码。
7. 编译成功，生成包含机器码和元数据的 `WasmCompilationResult`。

**涉及用户常见的编程错误 (与 JavaScript 交互时):**

1. **类型不匹配:**  这是与 `JSToWasmWrapperCompilationUnit` 最相关的错误。
   - **错误示例:**  WebAssembly 函数期望接收整数，但 JavaScript 传递了浮点数或字符串。
   ```javascript
   // WebAssembly 'add' 函数期望两个整数
   module.instance.exports.add(5.5, 'hello'); // 错误：类型不匹配
   ```
   `JSToWasmWrapperCompilationUnit` 生成的包装器会尝试进行类型转换，但如果无法转换，或者类型差异过大，就会导致错误。

2. **导出的函数名错误:**
   - **错误示例:**  在 JavaScript 中尝试调用一个不存在的导出函数名。
   ```javascript
   module.instance.exports.addition(5, 3); // 错误：'addition' 可能未导出或拼写错误
   ```
   这不是 `function-compiler.cc` 直接处理的错误，但与模块的导出信息有关，而编译过程会记录这些信息。

3. **参数数量错误:**
   - **错误示例:**  传递给 WebAssembly 函数的参数数量与函数定义不符。
   ```javascript
   // WebAssembly 'add' 函数期望两个参数
   module.instance.exports.add(5); // 错误：缺少一个参数
   module.instance.exports.add(5, 3, 1); // 错误：参数过多
   ```
   包装器代码会检查参数数量，并在不匹配时抛出错误。

4. **WebAssembly 模块加载或实例化失败:**
   - 这不是 `function-compiler.cc` 的错误，但如果 WebAssembly 模块本身有语法错误或无法加载，那么编译过程就无法进行。

总而言之，`v8/src/wasm/function-compiler.cc` 是 V8 中 WebAssembly 功能的关键部分，它负责将 WebAssembly 代码转化为可以在 V8 引擎中执行的本地机器码，并且特别关注与 JavaScript 的互操作性。 它的设计支持多种编译层级，以在启动速度和执行性能之间取得平衡。

Prompt: 
```
这是目录为v8/src/wasm/function-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/function-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/function-compiler.h"

#include <optional>

#include "src/codegen/compiler.h"
#include "src/codegen/optimized-compilation-info.h"
#include "src/compiler/turboshaft/wasm-turboshaft-compiler.h"
#include "src/compiler/wasm-compiler.h"
#include "src/handles/handles-inl.h"
#include "src/logging/counters-scopes.h"
#include "src/logging/log.h"
#include "src/objects/code-inl.h"
#include "src/wasm/baseline/liftoff-compiler.h"
#include "src/wasm/compilation-environment-inl.h"
#include "src/wasm/turboshaft-graph-interface.h"
#include "src/wasm/wasm-code-manager.h"
#include "src/wasm/wasm-debug.h"
#include "src/wasm/wasm-engine.h"

namespace v8::internal::wasm {

WasmCompilationResult WasmCompilationUnit::ExecuteCompilation(
    CompilationEnv* env, const WireBytesStorage* wire_bytes_storage,
    Counters* counters, WasmDetectedFeatures* detected) {
  DCHECK_GE(func_index_, static_cast<int>(env->module->num_imported_functions));
  WasmCompilationResult result =
      ExecuteFunctionCompilation(env, wire_bytes_storage, counters, detected);

  if (result.succeeded() && counters) {
    counters->wasm_generated_code_size()->Increment(
        result.code_desc.instr_size);
    counters->wasm_reloc_size()->Increment(result.code_desc.reloc_size);
    counters->wasm_deopt_data_size()->Increment(
        static_cast<int>(result.deopt_data.size()));
  }

  result.func_index = func_index_;

  return result;
}

WasmCompilationResult WasmCompilationUnit::ExecuteFunctionCompilation(
    CompilationEnv* env, const WireBytesStorage* wire_bytes_storage,
    Counters* counters, WasmDetectedFeatures* detected) {
  const WasmFunction* func = &env->module->functions[func_index_];
  base::Vector<const uint8_t> code = wire_bytes_storage->GetCode(func->code);
  bool is_shared = env->module->type(func->sig_index).is_shared;
  wasm::FunctionBody func_body{func->sig, func->code.offset(), code.begin(),
                               code.end(), is_shared};

  std::optional<TimedHistogramScope> wasm_compile_function_time_scope;
  std::optional<TimedHistogramScope> wasm_compile_huge_function_time_scope;
  if (counters && base::TimeTicks::IsHighResolution()) {
    if (func_body.end - func_body.start >= 100 * KB) {
      auto huge_size_histogram = SELECT_WASM_COUNTER(
          counters, env->module->origin, wasm, huge_function_size_bytes);
      huge_size_histogram->AddSample(
          static_cast<int>(func_body.end - func_body.start));
      wasm_compile_huge_function_time_scope.emplace(
          counters->wasm_compile_huge_function_time());
    }
    auto timed_histogram = SELECT_WASM_COUNTER(counters, env->module->origin,
                                               wasm_compile, function_time);
    wasm_compile_function_time_scope.emplace(timed_histogram);
  }

  // Before executing compilation, make sure that the function was validated.
  // Both Liftoff and TurboFan compilation do not perform validation, so can
  // only run on valid functions.
  if (V8_UNLIKELY(!env->module->function_was_validated(func_index_))) {
    // This code path can only be reached in
    // - eager compilation mode,
    // - with lazy validation,
    // - with PGO (which compiles some functions eagerly), or
    // - with compilation hints (which also compiles some functions eagerly).
    DCHECK(!v8_flags.wasm_lazy_compilation || v8_flags.wasm_lazy_validation ||
           v8_flags.experimental_wasm_pgo_from_file ||
           v8_flags.experimental_wasm_compilation_hints);
    Zone validation_zone{GetWasmEngine()->allocator(), ZONE_NAME};
    if (ValidateFunctionBody(&validation_zone, env->enabled_features,
                             env->module, detected, func_body)
            .failed()) {
      return {};
    }
    env->module->set_function_validated(func_index_);
  }

  if (v8_flags.trace_wasm_compiler) {
    PrintF("Compiling wasm function %d with %s\n", func_index_,
           ExecutionTierToString(tier_));
  }

  WasmCompilationResult result;
  int declared_index = declared_function_index(env->module, func_index_);

  switch (tier_) {
    case ExecutionTier::kNone:
#if V8_ENABLE_DRUMBRAKE
    case ExecutionTier::kInterpreter:
#endif  // V8_ENABLE_DRUMBRAKE
      UNREACHABLE();

    case ExecutionTier::kLiftoff: {
      // The --wasm-tier-mask-for-testing flag can force functions to be
      // compiled with TurboFan, and the --wasm-debug-mask-for-testing can force
      // them to be compiled for debugging, see documentation.
      bool try_liftoff = true;
      if (V8_UNLIKELY(v8_flags.wasm_tier_mask_for_testing != 0)) {
        bool must_use_liftoff =
            v8_flags.liftoff_only ||
            for_debugging_ != ForDebugging::kNotForDebugging;
        bool tiering_requested =
            declared_index < 32 &&
            (v8_flags.wasm_tier_mask_for_testing & (1 << declared_index));
        if (!must_use_liftoff && tiering_requested) try_liftoff = false;
      }

      if (V8_LIKELY(try_liftoff)) {
        auto options = LiftoffOptions{}
                           .set_func_index(func_index_)
                           .set_for_debugging(for_debugging_)
                           .set_counters(counters)
                           .set_detected_features(detected);
        // We do not use the debug side table, we only (optionally) pass it to
        // cover different code paths in Liftoff for testing.
        std::unique_ptr<DebugSideTable> unused_debug_sidetable;
        if (V8_UNLIKELY(declared_index < 32 &&
                        (v8_flags.wasm_debug_mask_for_testing &
                         (1 << declared_index)) != 0) &&
            // Do not overwrite the debugging setting when performing a
            // deoptimization.
            (!v8_flags.wasm_deopt ||
             env->deopt_location_kind == LocationKindForDeopt::kNone)) {
          options.set_debug_sidetable(&unused_debug_sidetable);
          if (!for_debugging_) options.set_for_debugging(kForDebugging);
        }
        result = ExecuteLiftoffCompilation(env, func_body, options);
        if (result.succeeded()) break;
      }

      // If --liftoff-only, do not fall back to turbofan, even if compilation
      // failed.
      if (v8_flags.liftoff_only) break;

      // If Liftoff failed, fall back to TurboFan.
      // TODO(wasm): We could actually stop or remove the tiering unit for this
      // function to avoid compiling it twice with TurboFan.
      [[fallthrough]];
    }
    case ExecutionTier::kTurbofan: {
      compiler::WasmCompilationData data(func_body);
      data.func_index = func_index_;
      data.wire_bytes_storage = wire_bytes_storage;
      bool use_turboshaft = v8_flags.turboshaft_wasm;
      if (declared_index < 32 && ((v8_flags.wasm_turboshaft_mask_for_testing &
                                   (1 << declared_index)) != 0)) {
        use_turboshaft = true;
      }
      if (use_turboshaft) {
        result = compiler::turboshaft::ExecuteTurboshaftWasmCompilation(
            env, data, detected);
      } else {
        result = compiler::ExecuteTurbofanWasmCompilation(env, data, counters,
                                                          detected);
      }
      // In exceptional cases it can happen that compilation requests for
      // debugging end up being executed by Turbofan, e.g. if Liftoff bails out
      // because of unsupported features or the --wasm-tier-mask-for-testing is
      // set. In that case we set the for_debugging field for the TurboFan
      // result to match the requested for_debugging_.
      result.for_debugging = for_debugging_;
      break;
    }
  }

  DCHECK(result.succeeded());
  return result;
}

// static
void WasmCompilationUnit::CompileWasmFunction(Counters* counters,
                                              NativeModule* native_module,
                                              WasmDetectedFeatures* detected,
                                              const WasmFunction* function,
                                              ExecutionTier tier) {
  ModuleWireBytes wire_bytes(native_module->wire_bytes());
  bool is_shared = native_module->module()->type(function->sig_index).is_shared;
  FunctionBody function_body{function->sig, function->code.offset(),
                             wire_bytes.start() + function->code.offset(),
                             wire_bytes.start() + function->code.end_offset(),
                             is_shared};

  DCHECK_LE(native_module->num_imported_functions(), function->func_index);
  DCHECK_LT(function->func_index, native_module->num_functions());
  WasmCompilationUnit unit(function->func_index, tier, kNotForDebugging);
  CompilationEnv env = CompilationEnv::ForModule(native_module);
  WasmCompilationResult result = unit.ExecuteCompilation(
      &env, native_module->compilation_state()->GetWireBytesStorage().get(),
      counters, detected);
  if (result.succeeded()) {
    WasmCodeRefScope code_ref_scope;
    AssumptionsJournal* assumptions = result.assumptions.get();
    native_module->PublishCode(native_module->AddCompiledCode(result),
                               assumptions->empty() ? nullptr : assumptions);
  } else {
    native_module->compilation_state()->SetError();
  }
}

JSToWasmWrapperCompilationUnit::JSToWasmWrapperCompilationUnit(
    Isolate* isolate, const CanonicalSig* sig, CanonicalTypeIndex sig_index)
    : isolate_(isolate),
      sig_(sig),
      sig_index_(sig_index),
      job_(v8_flags.wasm_jitless
               ? nullptr
               : compiler::NewJSToWasmCompilationJob(isolate, sig)) {
  if (!v8_flags.wasm_jitless) {
    OptimizedCompilationInfo* info =
        v8_flags.turboshaft_wasm_wrappers
            ? static_cast<compiler::turboshaft::TurboshaftCompilationJob*>(
                  job_.get())
                  ->compilation_info()
            : static_cast<TurbofanCompilationJob*>(job_.get())
                  ->compilation_info();
    if (info->trace_turbo_graph()) {
      // Make sure that code tracer is initialized on the main thread if tracing
      // is enabled.
      isolate->GetCodeTracer();
    }
  }
}

JSToWasmWrapperCompilationUnit::~JSToWasmWrapperCompilationUnit() = default;

void JSToWasmWrapperCompilationUnit::Execute() {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.wasm.detailed"),
               "wasm.CompileJSToWasmWrapper");
  if (!v8_flags.wasm_jitless) {
    CompilationJob::Status status = job_->ExecuteJob(nullptr);
    CHECK_EQ(status, CompilationJob::SUCCEEDED);
  }
}

Handle<Code> JSToWasmWrapperCompilationUnit::Finalize() {
#if V8_ENABLE_DRUMBRAKE
  if (v8_flags.wasm_jitless) {
    return isolate_->builtins()->code_handle(
        Builtin::kGenericJSToWasmInterpreterWrapper);
  }
#endif  // V8_ENABLE_DRUMBRAKE

  CompilationJob::Status status = job_->FinalizeJob(isolate_);
  CHECK_EQ(status, CompilationJob::SUCCEEDED);
  OptimizedCompilationInfo* info =
      v8_flags.turboshaft_wasm_wrappers
          ? static_cast<compiler::turboshaft::TurboshaftCompilationJob*>(
                job_.get())
                ->compilation_info()
          : static_cast<TurbofanCompilationJob*>(job_.get())
                ->compilation_info();
  Handle<Code> code = info->code();
  if (isolate_->IsLoggingCodeCreation()) {
    Handle<String> name = isolate_->factory()->NewStringFromAsciiChecked(
        info->GetDebugName().get());
    PROFILE(isolate_, CodeCreateEvent(LogEventListener::CodeTag::kStub,
                                      Cast<AbstractCode>(code), name));
  }
  // We should always have checked the cache before compiling a wrapper.
  Tagged<WeakFixedArray> cache = isolate_->heap()->js_to_wasm_wrappers();
  DCHECK(cache->get(sig_index_.index).IsCleared());
  // Install the compiled wrapper in the cache now.
  cache->set(sig_index_.index, MakeWeak(code->wrapper()));
  Counters* counters = isolate_->counters();
  counters->wasm_generated_code_size()->Increment(code->body_size());
  counters->wasm_reloc_size()->Increment(code->relocation_size());
  counters->wasm_compiled_export_wrapper()->Increment(1);
  return code;
}

// static
Handle<Code> JSToWasmWrapperCompilationUnit::CompileJSToWasmWrapper(
    Isolate* isolate, const CanonicalSig* sig, CanonicalTypeIndex sig_index) {
  // Run the compilation unit synchronously.
  JSToWasmWrapperCompilationUnit unit(isolate, sig, sig_index);
  unit.Execute();
  return unit.Finalize();
}

}  // namespace v8::internal::wasm

"""

```