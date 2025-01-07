Response:
Let's break down the request and the provided C++ header file.

**Request Analysis:**

The request asks for several things regarding the provided `v8/src/wasm/module-compiler.h` file:

1. **Functionality:**  A summary of what the code does.
2. **Torque:** Check if the file extension is `.tq` (it's `.h`). If so, explain its relation to Torque.
3. **JavaScript Relationship:** If the code interacts with JavaScript, provide JavaScript examples.
4. **Code Logic Reasoning:**  Present scenarios with hypothetical inputs and outputs.
5. **Common Programming Errors:**  Illustrate potential errors related to the code.

**File Analysis (High-Level):**

The header file clearly deals with WebAssembly module compilation within the V8 JavaScript engine. The presence of namespaces like `v8::wasm` and classes/functions related to "module," "compile," "native module," and "streaming" strongly points to this. The `#if !V8_ENABLE_WEBASSEMBLY` guard confirms this is specific to WebAssembly functionality.

**Mental Sandbox - Deconstructing the Code:**

* **Includes:** The included headers (`atomic`, `functional`, `memory`, etc.) suggest the code involves asynchronous operations, callbacks, and memory management, which is typical for a compiler. The V8-specific includes (`include/v8-metrics.h`, `src/common/globals.h`, `src/wasm/...`) confirm its integration within the V8 engine.
* **`CompileToNativeModule`:** This function looks like the core compilation entry point. It takes various parameters related to the isolate (V8 instance), features, imports, the module itself, and even profiling information. The return type `std::shared_ptr<NativeModule>` suggests it produces a compiled, executable representation of the Wasm module.
* **`ValidateAndSetBuiltinImports`:** This hints at a validation step to ensure the imported functions and variables are correctly specified and compatible.
* **`CompileImportWrapperForTest`:**  This function seems to handle the creation of wrapper code for imported functions, possibly for optimization or integration with the JavaScript environment. The "ForTest" suffix suggests it might be used in testing scenarios.
* **`CompileLazy` and `ThrowLazyCompilationError`:** This indicates support for lazy compilation, where functions are only compiled when they are first called. This is a common optimization technique.
* **`TriggerTierUp` and `TierUpNowForTesting`:** These functions relate to tiered compilation. V8 likely starts with a faster but less optimized compilation and then, based on usage, "tiers up" to a more optimized version using TurboFan.
* **`AsyncCompileJob`:**  This class is a central component for asynchronous compilation. The various nested classes (`DecodeModule`, `PrepareAndStartCompile`, `FinishCompilation`, `Fail`) represent the stages of this asynchronous process. The presence of `foreground_task_runner_` and `background_task_manager_` reinforces the asynchronous nature.
* **`PublishDetectedFeatures`:**  This function likely reports which WebAssembly features are used in the compiled module, potentially for telemetry or optimization purposes.

**Constraint Checklist & Confidence Score:**

1. List functionality? Yes.
2. Check for `.tq`? Yes.
3. JavaScript relationship?  Likely yes, needs examples.
4. Code logic reasoning?  Yes, can provide hypothetical scenarios.
5. Common programming errors? Yes, can identify potential pitfalls.

Confidence Score: 4/5 (Slight uncertainty on the exact JavaScript interaction details without more context).

**Strategizing the Response:**

1. **Functionality Summary:** Start with a high-level description of the file's purpose (Wasm module compilation). Then, go through the key functions and classes, explaining their roles.
2. **Torque Check:** Explicitly state that the file is `.h` and therefore not a Torque file. Briefly explain what Torque is and its relation to V8 if the extension were `.tq`.
3. **JavaScript Relationship:** Focus on how WebAssembly interacts with JavaScript. Mention the `WebAssembly` global object and how to fetch, compile, and instantiate Wasm modules. Connect this to the compilation process described in the header.
4. **Code Logic Reasoning:** Choose a simple scenario, like compiling a basic Wasm module. Describe the input (Wasm bytecode) and the expected output (a `NativeModule` or a `WasmModuleObject`). For lazy compilation, show how a function might initially be uncompiled and then compiled on the first call.
5. **Common Errors:** Focus on errors developers might encounter when working with WebAssembly, such as invalid Wasm bytecode, incorrect import definitions, or issues with asynchronous compilation.

Strategizing complete. Proceeding with response generation.
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if !V8_ENABLE_WEBASSEMBLY
#error This header should only be included if WebAssembly is enabled.
#endif  // !V8_ENABLE_WEBASSEMBLY

#ifndef V8_WASM_MODULE_COMPILER_H_
#define V8_WASM_MODULE_COMPILER_H_

#include <atomic>
#include <functional>
#include <memory>
#include <optional>

#include "include/v8-metrics.h"
#include "src/base/platform/time.h"
#include "src/common/globals.h"
#include "src/tasks/cancelable-task.h"
#include "src/wasm/compilation-environment.h"
#include "src/wasm/wasm-features.h"
#include "src/wasm/wasm-import-wrapper-cache.h"
#include "src/wasm/wasm-module.h"

namespace v8 {

namespace base {
template <typename T>
class Vector;
}  // namespace base

namespace internal {

class JSArrayBuffer;
class JSPromise;
class Counters;
class WasmModuleObject;
class WasmInstanceObject;
class WasmTrustedInstanceData;

namespace wasm {

struct CompilationEnv;
class CompilationResultResolver;
class ErrorThrower;
class ModuleCompiler;
class NativeModule;
class ProfileInformation;
class StreamingDecoder;
class WasmCode;
struct WasmModule;

V8_EXPORT_PRIVATE
std::shared_ptr<NativeModule> CompileToNativeModule(
    Isolate* isolate, WasmEnabledFeatures enabled_features,
    WasmDetectedFeatures detected_features, CompileTimeImports compile_imports,
    ErrorThrower* thrower, std::shared_ptr<const WasmModule> module,
    ModuleWireBytes wire_bytes, int compilation_id,
    v8::metrics::Recorder::ContextId context_id, ProfileInformation* pgo_info);

V8_EXPORT_PRIVATE WasmError ValidateAndSetBuiltinImports(
    const WasmModule* module, base::Vector<const uint8_t> wire_bytes,
    const CompileTimeImports& imports, WasmDetectedFeatures* detected);

// Compiles the wrapper for this (kind, sig) pair and sets the corresponding
// cache entry. Assumes the key already exists in the cache but has not been
// compiled yet.
V8_EXPORT_PRIVATE
WasmCode* CompileImportWrapperForTest(Isolate* isolate,
                                      NativeModule* native_module,
                                      ImportCallKind kind,
                                      const CanonicalSig* sig,
                                      CanonicalTypeIndex type_index,
                                      int expected_arity, Suspend suspend);

// Triggered by the WasmCompileLazy builtin. The return value indicates whether
// compilation was successful. Lazy compilation can fail only if validation is
// also lazy.
bool CompileLazy(Isolate*, Tagged<WasmTrustedInstanceData>, int func_index);

// Throws the compilation error after failed lazy compilation.
void ThrowLazyCompilationError(Isolate* isolate,
                               const NativeModule* native_module,
                               int func_index);

// Trigger tier-up of a particular function to TurboFan. If tier-up was already
// triggered, we instead increase the priority with exponential back-off.
V8_EXPORT_PRIVATE void TriggerTierUp(Isolate*, Tagged<WasmTrustedInstanceData>,
                                     int func_index);
// Synchronous version of the above.
V8_EXPORT_PRIVATE void TierUpNowForTesting(Isolate*,
                                           Tagged<WasmTrustedInstanceData>,
                                           int func_index);
// Same, but all functions.
V8_EXPORT_PRIVATE void TierUpAllForTesting(Isolate*,
                                           Tagged<WasmTrustedInstanceData>);

V8_EXPORT_PRIVATE void InitializeCompilationForTesting(
    NativeModule* native_module);

// Publish a set of detected features in a given isolate. If this is the initial
// compilation, also the "kWasmModuleCompilation" use counter is incremented to
// serve as a baseline for the other detected features.
void PublishDetectedFeatures(WasmDetectedFeatures, Isolate*,
                             bool is_initial_compilation);

// Encapsulates all the state and steps of an asynchronous compilation.
// An asynchronous compile job consists of a number of tasks that are executed
// as foreground and background tasks. Any phase that touches the V8 heap or
// allocates on the V8 heap (e.g. creating the module object) must be a
// foreground task. All other tasks (e.g. decoding and validating, the majority
// of the work of compilation) can be background tasks.
// TODO(wasm): factor out common parts of this with the synchronous pipeline.
class AsyncCompileJob {
 public:
  AsyncCompileJob(Isolate* isolate, WasmEnabledFeatures enabled_features,
                  CompileTimeImports compile_imports,
                  base::OwnedVector<const uint8_t> bytes,
                  DirectHandle<Context> context,
                  DirectHandle<NativeContext> incumbent_context,
                  const char* api_method_name,
                  std::shared_ptr<CompilationResultResolver> resolver,
                  int compilation_id);
  ~AsyncCompileJob();

  void Start();

  std::shared_ptr<StreamingDecoder> CreateStreamingDecoder();

  void Abort();
  void CancelPendingForegroundTask();

  Isolate* isolate() const { return isolate_; }

  Handle<NativeContext> context() const { return native_context_; }
  v8::metrics::Recorder::ContextId context_id() const { return context_id_; }

 private:
  class CompileTask;
  class CompileStep;
  class CompilationStateCallback;

  // States of the AsyncCompileJob.
  // Step 1 (async). Decodes the wasm module.
  // --> Fail on decoding failure,
  // --> PrepareAndStartCompile on success.
  class DecodeModule;

  // Step 2 (sync). Prepares runtime objects and starts background compilation.
  // --> finish directly on native module cache hit,
  // --> finish directly on validation error,
  // --> trigger eager compilation, if any; FinishCompile is triggered when
  // done.
  class PrepareAndStartCompile;

  // Step 3 (sync). Compilation finished. Finalize the module and resolve the
  // promise.
  class FinishCompilation;

  // Step 4 (sync). Decoding, validation or compilation failed. Reject the
  // promise.
  class Fail;

  friend class AsyncStreamingProcessor;

  // Decrements the number of outstanding finishers. The last caller of this
  // function should finish the asynchronous compilation, see the comment on
  // {outstanding_finishers_}.
  V8_WARN_UNUSED_RESULT bool DecrementAndCheckFinisherCount() {
    DCHECK_LT(0, outstanding_finishers_.load());
    return outstanding_finishers_.fetch_sub(1) == 1;
  }

  void CreateNativeModule(std::shared_ptr<const WasmModule> module,
                          size_t code_size_estimate);
  // Return true for cache hit, false for cache miss.
  bool GetOrCreateNativeModule(std::shared_ptr<const WasmModule> module,
                               size_t code_size_estimate);
  void PrepareRuntimeObjects();

  void FinishCompile(bool is_after_cache_hit);

  void Failed();

  void AsyncCompileSucceeded(Handle<WasmModuleObject> result);

  void FinishSuccessfully();

  void StartForegroundTask();
  void ExecuteForegroundTaskImmediately();

  void StartBackgroundTask();

  enum UseExistingForegroundTask : bool {
    kUseExistingForegroundTask = true,
    kAssertNoExistingForegroundTask = false
  };
  // Switches to the compilation step {Step} and starts a foreground task to
  // execute it. Most of the time we know that there cannot be a running
  // foreground task. If there might be one, then pass
  // kUseExistingForegroundTask to avoid spawning a second one.
  template <typename Step,
            UseExistingForegroundTask = kAssertNoExistingForegroundTask,
            typename... Args>
  void DoSync(Args&&... args);

  // Switches to the compilation step {Step} and immediately executes that step.
  template <typename Step, typename... Args>
  void DoImmediately(Args&&... args);

  // Switches to the compilation step {Step} and starts a background task to
  // execute it.
  template <typename Step, typename... Args>
  void DoAsync(Args&&... args);

  // Switches to the compilation step {Step} but does not start a task to
  // execute it.
  template <typename Step, typename... Args>
  void NextStep(Args&&... args);

  Isolate* const isolate_;
  const char* const api_method_name_;
  const WasmEnabledFeatures enabled_features_;
  WasmDetectedFeatures detected_features_;
  CompileTimeImports compile_imports_;
  const DynamicTiering dynamic_tiering_;
  base::TimeTicks start_time_;
  // Copy of the module wire bytes, moved into the {native_module_} on its
  // creation.
  base::OwnedVector<const uint8_t> bytes_copy_;
  // Reference to the wire bytes (held in {bytes_copy_} or as part of
  // {native_module_}).
  ModuleWireBytes wire_bytes_;
  IndirectHandle<NativeContext> native_context_;
  IndirectHandle<NativeContext> incumbent_context_;
  v8::metrics::Recorder::ContextId context_id_;
  v8::metrics::WasmModuleDecoded metrics_event_;
  const std::shared_ptr<CompilationResultResolver> resolver_;

  IndirectHandle<WasmModuleObject> module_object_;
  std::shared_ptr<NativeModule> native_module_;

  std::unique_ptr<CompileStep> step_;
  CancelableTaskManager background_task_manager_;

  std::shared_ptr<v8::TaskRunner> foreground_task_runner_;

  // For async compilation the AsyncCompileJob is the only finisher. For
  // streaming compilation also the AsyncStreamingProcessor has to finish before
  // compilation can be finished.
  std::atomic<int32_t> outstanding_finishers_{1};

  // A reference to a pending foreground task, or {nullptr} if none is pending.
  CompileTask* pending_foreground_task_ = nullptr;

  // The AsyncCompileJob owns the StreamingDecoder because the StreamingDecoder
  // contains data which is needed by the AsyncCompileJob for streaming
  // compilation. The AsyncCompileJob does not actively use the
  // StreamingDecoder.
  std::shared_ptr<StreamingDecoder> stream_;

  // The compilation id to identify trace events linked to this compilation.
  const int compilation_id_;
};

}  // namespace wasm
}  // namespace internal
}  // namespace v8

#endif  // V8_WASM_MODULE_COMPILER_H_
```

### 功能列举

`v8/src/wasm/module-compiler.h` 文件定义了 V8 中 WebAssembly 模块编译器的接口和主要数据结构。它的主要功能包括：

1. **定义 WebAssembly 模块编译的入口点:**  例如 `CompileToNativeModule` 函数，它是将 WebAssembly 字节码编译成本地机器码的核心函数。
2. **处理编译过程中的各个阶段:**  包括验证、解码、优化和代码生成。
3. **支持同步和异步编译:**  `AsyncCompileJob` 类封装了异步编译的状态和步骤。
4. **管理编译过程中的依赖和上下文:**  例如，通过 `CompileTimeImports` 处理导入，通过 `Isolate` 提供 V8 引擎的上下文。
5. **实现懒加载编译:**  `CompileLazy` 函数允许在首次调用时才编译 WebAssembly 函数。
6. **支持分层编译（Tier-Up）:**  `TriggerTierUp` 系列函数允许将 WebAssembly 函数从较快的但可能不太优化的版本升级到更优化的 TurboFan 版本。
7. **处理 WebAssembly 模块的验证:** `ValidateAndSetBuiltinImports` 函数用于验证导入是否符合规范。
8. **管理导入函数的包装器:** `CompileImportWrapperForTest` 用于编译 JavaScript 导入函数的包装器。
9. **收集和发布编译相关的指标:**  通过 `v8::metrics::Recorder` 和 `PublishDetectedFeatures` 收集和报告编译过程中的信息。
10. **支持流式编译:**  `StreamingDecoder` 和 `AsyncCompileJob` 的交互支持在接收 WebAssembly 字节码的同时进行编译。
11. **处理编译错误:**  通过 `ErrorThrower` 报告编译过程中出现的错误。
12. **与 V8 引擎的其他部分交互:**  例如，使用 `Isolate` 来访问 V8 的堆和执行上下文。

### 是否为 Torque 源代码

`v8/src/wasm/module-compiler.h` 文件的扩展名是 `.h`，表示这是一个 C++ 头文件。因此，它不是一个 V8 Torque 源代码。

如果 `v8/src/wasm/module-compiler.h` 以 `.tq` 结尾，那么它才是一个 V8 Torque 源代码。Torque 是一种 V8 内部使用的类型安全的 DSL (领域特定语言)，用于生成 C++ 代码。它主要用于实现内置函数和运行时代码，可以提供更好的类型安全性和性能。

### 与 JavaScript 的关系及示例

`v8/src/wasm/module-compiler.h` 中定义的功能是 WebAssembly 在 V8 引擎中运行的基础。JavaScript 通过 `WebAssembly` 全局对象与 WebAssembly 进行交互。这个头文件中定义的编译过程直接影响了 JavaScript 中加载和执行 WebAssembly 模块的方式。

**JavaScript 示例:**

```javascript
// WebAssembly 模块的字节码 (简化示例)
const wasmCode = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // wasm 标识和版本
  0x01, 0x07, 0x01, 0x60, 0x00, 0x01, 0x7f,       // 类型定义: () => [i32]
  0x03, 0x02, 0x01, 0x00,                         // 函数定义: 函数索引 0 使用类型索引 0
  0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x41, 0x0a, 0x0b // 函数体: local.get 0; i32.const 10; end
]);

// 创建 WebAssembly 模块
WebAssembly.compile(wasmCode)
  .then(module => {
    console.log("WebAssembly 模块编译成功", module);
    // 实例化模块
    return WebAssembly.instantiate(module);
  })
  .then(instance => {
    console.log("WebAssembly 模块实例化成功", instance);
    // 调用导出的函数
    const result = instance.exports.addTen(5); // 假设导出了一个名为 addTen 的函数
    console.log("WebAssembly 函数调用结果:", result); // 输出: 15
  })
  .catch(error => {
    console.error("WebAssembly 编译或实例化失败:", error);
  });
```

**说明:**

* `WebAssembly.compile(wasmCode)`: 这个 JavaScript 方法在 V8 内部会触发 `v8/src/wasm/module-compiler.h` 中定义的编译过程。V8 会使用 `CompileToNativeModule` 或 `AsyncCompileJob` 来处理字节码，生成可执行的 `NativeModule`。
* `WebAssembly.instantiate(module)`:  实例化过程会创建 `WasmInstanceObject`，并将编译后的代码与 JavaScript 环境连接起来。
* 编译失败会导致 JavaScript Promise rejection，这与 `ErrorThrower` 的功能相关。
* 懒加载编译和分层编译在 JavaScript 中是透明的，V8 会根据需要自动进行优化。

### 代码逻辑推理

**假设输入:**

* **`wasmCode` (字节码):**  一个简单的 WebAssembly 模块，包含一个将输入的整数加 10 并返回的函数。
  ```wasm
  (module
    (func $addTen (param $p i32) (result i32)
      local.get $p
      i32.const 10
      i32.add
    )
    (export "addTen" (func $addTen))
  )
  ```
  对应的字节码（简化）：`[0x00, 0x61, 0x73, 0x6d, ..., 0x20, 0x00, 0x41, 0x0a, 0x6a, 0x0b]`
* **`enabled_features`:**  启用了基本 WebAssembly 功能。
* **`compile_imports`:**  没有导入的函数或变量。

**编译过程 (基于 `CompileToNativeModule`):**

1. **解码:** `CompileToNativeModule` 内部会调用解码器解析 `wasmCode`，生成抽象语法树 (AST) 或类似的中间表示。
2. **验证:**  验证器会检查模块的结构和指令是否符合 WebAssembly 规范。
3. **编译:**  编译器将中间表示转换为目标架构的机器码。这可能涉及多种优化步骤。
4. **生成 `NativeModule`:**  编译后的机器码和元数据会被封装到一个 `NativeModule` 对象中。

**输出:**

* **`NativeModule` 对象:**  包含编译后的 `addTen` 函数的机器码，以及模块的元数据，例如导出的函数列表。

**懒加载编译场景 (基于 `CompileLazy`):**

**假设输入:**

* **`wasmInstanceData`:**  一个已经实例化的 WebAssembly 模块的内部数据，其中 `addTen` 函数尚未编译。
* **`func_index`:**  `addTen` 函数在模块中的索引 (例如，0)。

**过程:**

1. **调用 `addTen`:**  JavaScript 代码首次调用 `instance.exports.addTen(5)`。
2. **触发 `CompileLazy`:** V8 发现 `addTen` 尚未编译，触发 `CompileLazy`。
3. **编译 `addTen`:**  `CompileLazy` 负责编译 `addTen` 函数。
4. **成功:** 如果编译成功，`CompileLazy` 返回 `true`。

**输出:**

* `CompileLazy` 返回 `true`。
* `addTen` 函数被编译，后续调用将直接执行编译后的代码。

**编译失败场景:**

**假设输入:**

* **`wasmCode` (错误字节码):**  包含语法错误的 WebAssembly 字节码。

**过程:**

1. **`CompileToNativeModule` 调用解码器。**
2. **解码器遇到语法错误。**
3. **`ErrorThrower` 报告错误。**

**输出:**

* `CompileToNativeModule` 返回一个表示编译失败的状态或空指针。
* 在 JavaScript 端，`WebAssembly.compile(badWasmCode)` 的 Promise 会被 reject，并带有描述错误的 `Error` 对象。

### 用户常见的编程错误

1. **无效的 WebAssembly 字节码:**  最常见的错误是提供了格式不正确或违反 WebAssembly 规范的字节码。这会导致编译过程中的解码或验证阶段失败。
   ```javascript
   const badWasmCode = new Uint8Array([0, 0, 0, 0]); // 完全无效的字节码
   WebAssembly.compile(badWasmCode).catch(err => console.error("编译失败:", err));
   ```

2. **导入不匹配:**  如果 WebAssembly 模块声明了导入，但在实例化时提供的导入对象与声明不匹配（例如，函数签名不一致，导入的模块或名称不存在），则会导致实例化失败。
   ```javascript
   const wasmCodeWithImport = new Uint8Array([...]); // 包含导入的 wasm 代码
   WebAssembly.compile(wasmCodeWithImport)
     .then(module => WebAssembly.instantiate(module, {
       env: {
         // 错误的导入函数签名
         imported_func: (a) => "wrong return type"
       }
     }))
     .catch(err => console.error("实例化失败:", err));
   ```

3. **异步编译处理不当:**  `WebAssembly.compile` 和 `WebAssembly.instantiate` 返回 Promise，需要正确处理异步结果。忘记使用 `.then()` 或 `.catch()` 可能导致未捕获的错误。

4. **尝试在不支持 WebAssembly 的环境中运行:**  如果在较旧的浏览器或非浏览器环境中尝试使用 `WebAssembly` 对象，会导致运行时错误。

5. **混淆同步和异步 API:**  虽然 `WebAssembly.compileStreaming` 和 `WebAssembly.instantiateStreaming` 提供流式编译，但直接使用 `WebAssembly.compile` 和 `WebAssembly.instantiate` 仍然是异步的。混淆这些 API 的使用可能导致意外的行为。

6. **内存管理错误（高级场景）：**  在涉及到 WebAssembly 的内存共享或 Typed Arrays 操作时，可能会出现内存访问越界或其他内存管理错误。虽然这些错误通常在 WebAssembly 代码内部发生，但错误的 JavaScript 绑定也可能导致问题。

理解 `v8/src/wasm/module-compiler.h` 中定义的功能有助于开发者更好地理解 WebAssembly 在 V8 引擎中的工作原理，并能更有效地调试和优化 WebAssembly 应用。

Prompt: 
```
这是目录为v8/src/wasm/module-compiler.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/module-compiler.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if !V8_ENABLE_WEBASSEMBLY
#error This header should only be included if WebAssembly is enabled.
#endif  // !V8_ENABLE_WEBASSEMBLY

#ifndef V8_WASM_MODULE_COMPILER_H_
#define V8_WASM_MODULE_COMPILER_H_

#include <atomic>
#include <functional>
#include <memory>
#include <optional>

#include "include/v8-metrics.h"
#include "src/base/platform/time.h"
#include "src/common/globals.h"
#include "src/tasks/cancelable-task.h"
#include "src/wasm/compilation-environment.h"
#include "src/wasm/wasm-features.h"
#include "src/wasm/wasm-import-wrapper-cache.h"
#include "src/wasm/wasm-module.h"

namespace v8 {

namespace base {
template <typename T>
class Vector;
}  // namespace base

namespace internal {

class JSArrayBuffer;
class JSPromise;
class Counters;
class WasmModuleObject;
class WasmInstanceObject;
class WasmTrustedInstanceData;

namespace wasm {

struct CompilationEnv;
class CompilationResultResolver;
class ErrorThrower;
class ModuleCompiler;
class NativeModule;
class ProfileInformation;
class StreamingDecoder;
class WasmCode;
struct WasmModule;

V8_EXPORT_PRIVATE
std::shared_ptr<NativeModule> CompileToNativeModule(
    Isolate* isolate, WasmEnabledFeatures enabled_features,
    WasmDetectedFeatures detected_features, CompileTimeImports compile_imports,
    ErrorThrower* thrower, std::shared_ptr<const WasmModule> module,
    ModuleWireBytes wire_bytes, int compilation_id,
    v8::metrics::Recorder::ContextId context_id, ProfileInformation* pgo_info);

V8_EXPORT_PRIVATE WasmError ValidateAndSetBuiltinImports(
    const WasmModule* module, base::Vector<const uint8_t> wire_bytes,
    const CompileTimeImports& imports, WasmDetectedFeatures* detected);

// Compiles the wrapper for this (kind, sig) pair and sets the corresponding
// cache entry. Assumes the key already exists in the cache but has not been
// compiled yet.
V8_EXPORT_PRIVATE
WasmCode* CompileImportWrapperForTest(Isolate* isolate,
                                      NativeModule* native_module,
                                      ImportCallKind kind,
                                      const CanonicalSig* sig,
                                      CanonicalTypeIndex type_index,
                                      int expected_arity, Suspend suspend);

// Triggered by the WasmCompileLazy builtin. The return value indicates whether
// compilation was successful. Lazy compilation can fail only if validation is
// also lazy.
bool CompileLazy(Isolate*, Tagged<WasmTrustedInstanceData>, int func_index);

// Throws the compilation error after failed lazy compilation.
void ThrowLazyCompilationError(Isolate* isolate,
                               const NativeModule* native_module,
                               int func_index);

// Trigger tier-up of a particular function to TurboFan. If tier-up was already
// triggered, we instead increase the priority with exponential back-off.
V8_EXPORT_PRIVATE void TriggerTierUp(Isolate*, Tagged<WasmTrustedInstanceData>,
                                     int func_index);
// Synchronous version of the above.
V8_EXPORT_PRIVATE void TierUpNowForTesting(Isolate*,
                                           Tagged<WasmTrustedInstanceData>,
                                           int func_index);
// Same, but all functions.
V8_EXPORT_PRIVATE void TierUpAllForTesting(Isolate*,
                                           Tagged<WasmTrustedInstanceData>);

V8_EXPORT_PRIVATE void InitializeCompilationForTesting(
    NativeModule* native_module);

// Publish a set of detected features in a given isolate. If this is the initial
// compilation, also the "kWasmModuleCompilation" use counter is incremented to
// serve as a baseline for the other detected features.
void PublishDetectedFeatures(WasmDetectedFeatures, Isolate*,
                             bool is_initial_compilation);

// Encapsulates all the state and steps of an asynchronous compilation.
// An asynchronous compile job consists of a number of tasks that are executed
// as foreground and background tasks. Any phase that touches the V8 heap or
// allocates on the V8 heap (e.g. creating the module object) must be a
// foreground task. All other tasks (e.g. decoding and validating, the majority
// of the work of compilation) can be background tasks.
// TODO(wasm): factor out common parts of this with the synchronous pipeline.
class AsyncCompileJob {
 public:
  AsyncCompileJob(Isolate* isolate, WasmEnabledFeatures enabled_features,
                  CompileTimeImports compile_imports,
                  base::OwnedVector<const uint8_t> bytes,
                  DirectHandle<Context> context,
                  DirectHandle<NativeContext> incumbent_context,
                  const char* api_method_name,
                  std::shared_ptr<CompilationResultResolver> resolver,
                  int compilation_id);
  ~AsyncCompileJob();

  void Start();

  std::shared_ptr<StreamingDecoder> CreateStreamingDecoder();

  void Abort();
  void CancelPendingForegroundTask();

  Isolate* isolate() const { return isolate_; }

  Handle<NativeContext> context() const { return native_context_; }
  v8::metrics::Recorder::ContextId context_id() const { return context_id_; }

 private:
  class CompileTask;
  class CompileStep;
  class CompilationStateCallback;

  // States of the AsyncCompileJob.
  // Step 1 (async). Decodes the wasm module.
  // --> Fail on decoding failure,
  // --> PrepareAndStartCompile on success.
  class DecodeModule;

  // Step 2 (sync). Prepares runtime objects and starts background compilation.
  // --> finish directly on native module cache hit,
  // --> finish directly on validation error,
  // --> trigger eager compilation, if any; FinishCompile is triggered when
  // done.
  class PrepareAndStartCompile;

  // Step 3 (sync). Compilation finished. Finalize the module and resolve the
  // promise.
  class FinishCompilation;

  // Step 4 (sync). Decoding, validation or compilation failed. Reject the
  // promise.
  class Fail;

  friend class AsyncStreamingProcessor;

  // Decrements the number of outstanding finishers. The last caller of this
  // function should finish the asynchronous compilation, see the comment on
  // {outstanding_finishers_}.
  V8_WARN_UNUSED_RESULT bool DecrementAndCheckFinisherCount() {
    DCHECK_LT(0, outstanding_finishers_.load());
    return outstanding_finishers_.fetch_sub(1) == 1;
  }

  void CreateNativeModule(std::shared_ptr<const WasmModule> module,
                          size_t code_size_estimate);
  // Return true for cache hit, false for cache miss.
  bool GetOrCreateNativeModule(std::shared_ptr<const WasmModule> module,
                               size_t code_size_estimate);
  void PrepareRuntimeObjects();

  void FinishCompile(bool is_after_cache_hit);

  void Failed();

  void AsyncCompileSucceeded(Handle<WasmModuleObject> result);

  void FinishSuccessfully();

  void StartForegroundTask();
  void ExecuteForegroundTaskImmediately();

  void StartBackgroundTask();

  enum UseExistingForegroundTask : bool {
    kUseExistingForegroundTask = true,
    kAssertNoExistingForegroundTask = false
  };
  // Switches to the compilation step {Step} and starts a foreground task to
  // execute it. Most of the time we know that there cannot be a running
  // foreground task. If there might be one, then pass
  // kUseExistingForegroundTask to avoid spawning a second one.
  template <typename Step,
            UseExistingForegroundTask = kAssertNoExistingForegroundTask,
            typename... Args>
  void DoSync(Args&&... args);

  // Switches to the compilation step {Step} and immediately executes that step.
  template <typename Step, typename... Args>
  void DoImmediately(Args&&... args);

  // Switches to the compilation step {Step} and starts a background task to
  // execute it.
  template <typename Step, typename... Args>
  void DoAsync(Args&&... args);

  // Switches to the compilation step {Step} but does not start a task to
  // execute it.
  template <typename Step, typename... Args>
  void NextStep(Args&&... args);

  Isolate* const isolate_;
  const char* const api_method_name_;
  const WasmEnabledFeatures enabled_features_;
  WasmDetectedFeatures detected_features_;
  CompileTimeImports compile_imports_;
  const DynamicTiering dynamic_tiering_;
  base::TimeTicks start_time_;
  // Copy of the module wire bytes, moved into the {native_module_} on its
  // creation.
  base::OwnedVector<const uint8_t> bytes_copy_;
  // Reference to the wire bytes (held in {bytes_copy_} or as part of
  // {native_module_}).
  ModuleWireBytes wire_bytes_;
  IndirectHandle<NativeContext> native_context_;
  IndirectHandle<NativeContext> incumbent_context_;
  v8::metrics::Recorder::ContextId context_id_;
  v8::metrics::WasmModuleDecoded metrics_event_;
  const std::shared_ptr<CompilationResultResolver> resolver_;

  IndirectHandle<WasmModuleObject> module_object_;
  std::shared_ptr<NativeModule> native_module_;

  std::unique_ptr<CompileStep> step_;
  CancelableTaskManager background_task_manager_;

  std::shared_ptr<v8::TaskRunner> foreground_task_runner_;

  // For async compilation the AsyncCompileJob is the only finisher. For
  // streaming compilation also the AsyncStreamingProcessor has to finish before
  // compilation can be finished.
  std::atomic<int32_t> outstanding_finishers_{1};

  // A reference to a pending foreground task, or {nullptr} if none is pending.
  CompileTask* pending_foreground_task_ = nullptr;

  // The AsyncCompileJob owns the StreamingDecoder because the StreamingDecoder
  // contains data which is needed by the AsyncCompileJob for streaming
  // compilation. The AsyncCompileJob does not actively use the
  // StreamingDecoder.
  std::shared_ptr<StreamingDecoder> stream_;

  // The compilation id to identify trace events linked to this compilation.
  const int compilation_id_;
};

}  // namespace wasm
}  // namespace internal
}  // namespace v8

#endif  // V8_WASM_MODULE_COMPILER_H_

"""

```