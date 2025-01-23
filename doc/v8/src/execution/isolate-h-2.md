Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/execution/isolate.h`.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The header file is part of the `Isolate` class in V8. An `Isolate` in V8 represents an isolated instance of the JavaScript engine. Therefore, the functions listed likely control various aspects of this isolated environment.

2. **Categorize the functions:**  Group similar functionalities together. Looking at the function names, some obvious categories emerge:
    * Concurrency and Parallelism (e.g., `concurrent_recompilation_enabled`, `AbortConcurrentOptimization`)
    * Compilation and Optimization (e.g., `IncreaseConcurrentOptimizationPriority`, `optimizing_compile_dispatcher`)
    * Statistics and Tracing (e.g., `GetTurboStatistics`, `GetCodeTracer`, `DumpAndResetStats`)
    * Random Number Generation (e.g., `random_number_generator`, `GenerateIdentityHash`)
    * Module Loading (e.g., `NextModuleAsyncEvaluationOrdinal`)
    * Callbacks (e.g., `AddCallCompletedCallback`, `SetPromiseRejectCallback`)
    * Symbols and Usage Counters (e.g., `SymbolFor`, `CountUsage`)
    * Script Management (e.g., `GetNextScriptId`)
    * Promise Hooks (e.g., `SetHasContextPromiseHooks`, `RunPromiseHook`)
    * Context Management (e.g., `AddDetachedContext`, `DetachGlobal`)
    * Embedded Builtins (e.g., `IsGeneratingEmbeddedBuiltins`, `HashIsolateForEmbeddedBlob`)
    * ArrayBuffer Allocation (e.g., `set_array_buffer_allocator`)
    * Task Management (e.g., `cancelable_task_manager`)
    * Compilation Infrastructure Access (e.g., `compiler_cache`, `lazy_compile_dispatcher`)
    * Dynamic Module Imports (e.g., `SetHostImportModuleDynamicallyCallback`)
    * Stack Trace Handling (e.g., `SetPrepareStackTraceCallback`)
    * Crash Reporting (e.g., `SetAddCrashKeyCallback`, `AddCrashKey`)
    * Performance Tuning and Modes (e.g., `SetRAILMode`, `SetIsLoading`, `SetPriority`, `EfficiencyModeEnabled`, `BatterySaverModeEnabled`)
    * Atomics Wait (e.g., `set_allow_atomics_wait`)
    * WebAssembly (e.g., `AddSharedWasmMemory`)
    * Long Tasks (e.g., `UpdateLongTaskStats`)
    * Memory Management (e.g., `AddCodeMemoryChunk`, `RemoveCodeMemoryChunk`)
    * External Pointers and Tables (e.g., `external_pointer_table`)
    * Shared Spaces (related to multi-isolate setups)
    * Error Handling (e.g., `ReportExceptionFunctionCallback`, `SetExceptionPropagationCallback`)

3. **Summarize each category:** Provide a concise explanation of what each group of functions does.

4. **Address specific points from the prompt:**
    * **`.tq` extension:** State that if the file ended in `.tq`, it would be Torque code.
    * **JavaScript relation:** Explain how the functionalities relate to JavaScript features. Provide JavaScript examples where relevant.
    * **Code logic and assumptions:**  For functions that involve conditional logic or state changes, provide simple "if/then" scenarios.
    * **Common programming errors:** Point out potential mistakes developers might make when interacting with these features (though this might be more relevant for the *usage* of these functions from the C++ API rather than the internal implementation).
    * **Overall summary:** Combine the category summaries into a high-level overview of the `Isolate`'s responsibilities.

5. **Structure the output:** Organize the information clearly using headings and bullet points.

**Self-Correction/Refinement:**

* Initially, I might focus too much on the low-level C++ details. The prompt asks for the *functionality*, so framing it in terms of what these features *do* for the JavaScript engine is crucial.
* When providing JavaScript examples, ensure they are simple and directly illustrate the concept.
*  For "assumptions and outputs," focus on illustrating the core logic without getting bogged down in implementation specifics.
* Double-check that all the points from the prompt are addressed.
这是 `v8/src/execution/isolate.h` 源代码的第三部分，延续了前两部分的内容，继续定义了 `v8::internal::Isolate` 类中的各种方法和成员。 这一部分主要关注于 V8 引擎的**并发、编译、统计、模块、回调、性能监控、内存管理、WebAssembly 集成以及错误处理**等方面。

以下是对这部分代码功能的归纳：

**核心功能概览:**

* **并发控制和优化编译:**  管理并发编译任务的调度和优先级，可以主动终止正在进行的并发优化。
* **性能统计与追踪:** 提供收集和输出代码性能统计数据（TurboFan, Maglev），以及代码追踪信息的功能。
* **随机数生成:** 提供获取和使用随机数生成器的接口，用于引擎内部的随机化操作。
* **模块加载:**  管理异步模块的加载顺序，确保依赖关系正确的模块先执行。
* **回调机制:**  提供多种回调函数注册和触发机制，用于在特定事件发生时通知外部环境或执行自定义逻辑，例如函数调用完成、Promise 状态变更等。
* **符号和使用计数:**  提供创建和管理 Symbol 的功能，以及记录 V8 引擎特性的使用情况，用于分析和优化。
* **脚本 ID 管理:**  为每个脚本分配唯一的 ID。
* **Promise Hook:** 提供 Promise Hook 机制，允许在 Promise 状态改变时执行自定义逻辑，用于调试和监控。
* **上下文管理:**  管理已分离的上下文，并在 GC 后进行检查。
* **全局对象分离:**  提供将环境与其外部全局对象分离的功能。
* **嵌入式 Builtins:**  支持生成和管理嵌入式 Builtins，提高启动性能。
* **短调用优化:**  支持对嵌入式 Builtins 进行短调用优化。
* **ArrayBuffer 分配:**  管理 ArrayBuffer 的分配器。
* **任务管理:**  提供可取消的任务管理器接口。
* **编译器缓存访问:** 提供访问 PerIsolateCompilerCache 的接口。
* **惰性编译:**  提供惰性编译调度器的访问接口。
* **动态模块导入:**  支持宿主环境自定义动态模块导入的行为。
* **PrepareStackTrace 回调:**  允许宿主环境自定义堆栈跟踪信息的格式。
* **崩溃键值添加:**  提供在崩溃时添加自定义键值对的功能，用于调试。
* **ETW 会话过滤 (Windows):**  支持根据 URL 过滤 ETW 追踪会话。
* **加载状态管理:**  跟踪 Isolate 的加载状态。
* **优先级管理:**  设置和获取 Isolate 的优先级，影响其资源分配。
* **效率模式和省电模式:**  支持效率模式和省电模式，在不同场景下优化性能或功耗。
* **Atomics.wait 允许:**  控制是否允许使用 `Atomics.wait`。
* **析构函数注册:**  允许注册在 Isolate 销毁时调用的析构函数。
* **元素删除计数:**  记录元素删除的次数。
* **WebAssembly 集成:**  支持添加共享的 WebAssembly 内存对象。
* **空闲状态管理:**  标记 Isolate 是否处于空闲状态。
* **代码内存管理:**  管理代码内存块的添加和移除。
* **性能指标记录:**  提供记录性能指标的上下文 ID 的功能。
* **长任务统计:**  更新和获取长任务的统计信息。
* **本地 Isolate 和 Heap 访问:**  提供访问主线程本地 Isolate 和 Heap 的接口。
* **压缩指针表:**  在启用指针压缩的情况下，提供访问外部指针表和 C++ 堆指针表的接口。
* **沙箱支持:**  在启用沙箱的情况下，提供访问受信任指针表的接口。
* **Continuation 保留的 Embedder 数据地址:** 提供访问 Continuation 保留的 Embedder 数据的地址。
* **共享空间支持:**  管理共享空间相关的 Isolate 和数据。
* **全局安全点:**  提供访问全局安全点的接口。
* **WebAssembly 执行计时器:** 提供 WebAssembly 执行计时器的访问接口。
* **共享数据所有权:**  指示 Isolate 是否拥有可共享的数据。
* **字符串表所有权:** 指示 Isolate 是否拥有字符串表。
* **模拟器数据:**  提供访问模拟器数据的接口（在 `USE_SIMULATOR` 宏定义下）。
* **WebAssembly 栈管理:**  管理 WebAssembly 的栈。
* **局部变量阻塞列表缓存:**  缓存局部变量阻塞列表，用于调试。
* **静态根验证:**  验证静态根对象。
* **快照 RO 分配:**  支持在快照期间启用只读分配。
* **异步等待队列:**  管理异步等待队列的节点。
* **异常报告回调:**  提供报告异常的回调函数。
* **异常传播回调:**  允许设置异常传播回调函数。
* **Wasm SIMD256 RE-VEC (测试):** 提供为测试设置 WasmRevecVerifier 的接口。

**与 JavaScript 的关系及示例:**

很多功能都直接或间接地影响 JavaScript 的执行。 例如：

* **`concurrent_recompilation_enabled()` 和 `AbortConcurrentOptimization()`:**  这与 V8 的优化编译器（如 TurboFan 和 Maglev）在后台编译 JavaScript 代码有关。这提高了 JavaScript 代码的执行速度。用户无法直接控制，但其存在提升了 JavaScript 的性能。
* **`AddCallCompletedCallback()` 和 `FireCallCompletedCallback()`:**  可以用于监控 JavaScript 函数的执行完成。

```javascript
// JavaScript 示例 (无法直接访问 C++ 回调，但概念上相关)
function myFunction() {
  console.log("函数执行");
}

// 假设 V8 内部使用了类似的回调机制，在 myFunction 执行完成后，
// 可能会触发一个 C++ 的回调，用于记录或处理函数执行完成事件。
myFunction();
```

* **`SetPromiseRejectCallback()` 和 `ReportPromiseReject()`:**  用于处理未处理的 Promise 拒绝。

```javascript
// JavaScript 示例
const myPromise = new Promise((resolve, reject) => {
  reject("Promise 拒绝了！");
});

myPromise.catch(error => {
  console.error("捕获到 Promise 拒绝:", error);
  // V8 内部可能会使用 ReportPromiseReject 来记录或处理这个拒绝。
});
```

* **`SetHostImportModuleDynamicallyCallback()` 和 `RunHostImportModuleDynamicallyCallback()`:**  允许宿主环境自定义 `import()` 语法的行为。

```javascript
// JavaScript 示例
// 当执行到以下代码时，如果设置了宿主回调，V8 会调用该回调。
import('./my-module.js').then(module => {
  module.doSomething();
});
```

* **`SetPrepareStackTraceCallback()` 和 `RunPrepareStackTraceCallback()`:**  允许自定义 `console.trace()` 或 `Error.stack` 的输出格式。

```javascript
// JavaScript 示例
Error.prepareStackTrace = function(err, stack) {
  return "自定义堆栈信息: " + stack.join('\n');
};

try {
  throw new Error("Something went wrong");
} catch (e) {
  console.log(e.stack); // 输出会被自定义的 prepareStackTrace 函数修改。
}
```

* **`EfficiencyModeEnabled()` 和 `BatterySaverModeEnabled()`:**  这些模式会影响 V8 执行 JavaScript 代码的方式，例如可能降低优化程度以节省资源。

**代码逻辑推理和假设输入/输出:**

* **`NextOptimizationId()`:**
    * **假设输入:** 多次调用 `NextOptimizationId()`。
    * **输出:** 每次调用返回一个递增的整数 ID，用于唯一标识优化任务。如果达到 `Smi` 的最大值，则会循环回 0。
    * **代码逻辑:** 使用原子操作保证线程安全地生成唯一的优化 ID。

* **`NextModuleAsyncEvaluationOrdinal()`:**
    * **假设输入:** 多个异步模块被加载。
    * **输出:** 每次调用返回一个递增的无符号整数，表示异步模块的加载顺序。
    * **代码逻辑:**  使用原子自增来分配异步模块的评估序号。

**用户常见的编程错误 (与此部分代码相关的):**

* **不理解异步模块加载顺序:**  如果开发者不理解异步模块的加载顺序由 `NextModuleAsyncEvaluationOrdinal()` 决定，可能会在有副作用的代码中遇到意想不到的执行顺序问题。
* **Promise Hook 使用不当:**  过度使用或在不恰当的时机使用 Promise Hook 可能会引入性能问题或导致意外的副作用。
* **误用性能优化模式:**  不了解效率模式或省电模式的含义，盲目启用可能会导致性能下降。

**总结:**

这部分 `v8/src/execution/isolate.h` 代码主要定义了 `v8::internal::Isolate` 类中用于**管理 V8 引擎的并发、编译优化、性能监控、模块加载、事件回调、性能模式以及与外部环境交互**的关键方法。这些功能是 V8 引擎高效、稳定运行的基础，同时也为宿主环境提供了定制和扩展 V8 功能的接口。  虽然开发者通常不直接操作这些 C++ 接口，但理解它们有助于深入了解 V8 的内部工作原理以及 JavaScript 的执行过程。

### 提示词
```
这是目录为v8/src/execution/isolate.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/isolate.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
ULL(maglev_concurrent_dispatcher_);
    return maglev_concurrent_dispatcher_;
  }
#endif  // V8_ENABLE_MAGLEV

  bool concurrent_recompilation_enabled() {
    // Thread is only available with flag enabled.
    DCHECK(optimizing_compile_dispatcher_ == nullptr ||
           v8_flags.concurrent_recompilation);
    return optimizing_compile_dispatcher_ != nullptr;
  }

  void IncreaseConcurrentOptimizationPriority(
      CodeKind kind, Tagged<SharedFunctionInfo> function);

  OptimizingCompileDispatcher* optimizing_compile_dispatcher() {
    DCHECK_NOT_NULL(optimizing_compile_dispatcher_);
    return optimizing_compile_dispatcher_;
  }
  // Flushes all pending concurrent optimization jobs from the optimizing
  // compile dispatcher's queue.
  void AbortConcurrentOptimization(BlockingBehavior blocking_behavior);

  int id() const { return id_; }

  bool was_locker_ever_used() const {
    return was_locker_ever_used_.load(std::memory_order_relaxed);
  }
  void set_was_locker_ever_used() {
    was_locker_ever_used_.store(true, std::memory_order_relaxed);
  }

  std::shared_ptr<CompilationStatistics> GetTurboStatistics();
#ifdef V8_ENABLE_MAGLEV
  std::shared_ptr<CompilationStatistics> GetMaglevStatistics();
#endif
  CodeTracer* GetCodeTracer();

  void DumpAndResetStats();
  void DumpAndResetBuiltinsProfileData();

  void* stress_deopt_count_address() { return &stress_deopt_count_; }

  void set_force_slow_path(bool v) { force_slow_path_ = v; }
  bool force_slow_path() const { return force_slow_path_; }
  bool* force_slow_path_address() { return &force_slow_path_; }

  bool jitless() const { return jitless_; }

  base::RandomNumberGenerator* random_number_generator();

  base::RandomNumberGenerator* fuzzer_rng();

  // Generates a random number that is non-zero when masked
  // with the provided mask.
  int GenerateIdentityHash(uint32_t mask);

  int NextOptimizationId() {
    int id = next_optimization_id_.load();
    while (true) {
      int next_id = id + 1;
      if (!Smi::IsValid(next_id)) next_id = 0;
      if (next_optimization_id_.compare_exchange_strong(id, next_id)) {
        return id;
      }
    }
  }

  // ES#sec-async-module-execution-fulfilled step 10
  //
  // According to the spec, modules that depend on async modules (i.e. modules
  // with top-level await) must be evaluated in order in which their
  // [[AsyncEvaluation]] flags were set to true. V8 tracks this global total
  // order with next_module_async_evaluation_ordinal_. Each module that sets its
  // [[AsyncEvaluation]] to true grabs the next ordinal.
  unsigned NextModuleAsyncEvaluationOrdinal() {
    // For simplicity, V8 allows this ordinal to overflow. Overflow will result
    // in incorrect module loading behavior for module graphs with top-level
    // await.
    return next_module_async_evaluation_ordinal_++;
  }

  void AddCallCompletedCallback(CallCompletedCallback callback);
  void RemoveCallCompletedCallback(CallCompletedCallback callback);
  void FireCallCompletedCallback(MicrotaskQueue* microtask_queue) {
    if (!thread_local_top()->CallDepthIsZero()) return;
    FireCallCompletedCallbackInternal(microtask_queue);
  }

  void AddBeforeCallEnteredCallback(BeforeCallEnteredCallback callback);
  void RemoveBeforeCallEnteredCallback(BeforeCallEnteredCallback callback);
  inline void FireBeforeCallEnteredCallback();

  void SetPromiseRejectCallback(PromiseRejectCallback callback);
  void ReportPromiseReject(Handle<JSPromise> promise, Handle<Object> value,
                           v8::PromiseRejectEvent event);

  void SetTerminationOnExternalTryCatch();

  Handle<Symbol> SymbolFor(RootIndex dictionary_index, Handle<String> name,
                           bool private_symbol);

  void SetUseCounterCallback(v8::Isolate::UseCounterCallback callback);
  void CountUsage(v8::Isolate::UseCounterFeature feature);
  // Count multiple usages at once; cheaper than calling the {CountUsage}
  // separately for each feature.
  void CountUsage(base::Vector<const v8::Isolate::UseCounterFeature> features);

  static std::string GetTurboCfgFileName(Isolate* isolate);

  int GetNextScriptId();

  uint32_t next_unique_sfi_id() const {
    return next_unique_sfi_id_.load(std::memory_order_relaxed);
  }
  uint32_t GetAndIncNextUniqueSfiId() {
    return next_unique_sfi_id_.fetch_add(1, std::memory_order_relaxed);
  }

#ifdef V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS
  void SetHasContextPromiseHooks(bool context_promise_hook) {
    promise_hook_flags_ = PromiseHookFields::HasContextPromiseHook::update(
        promise_hook_flags_, context_promise_hook);
    PromiseHookStateUpdated();
  }
#endif  // V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS

  bool HasContextPromiseHooks() const {
    return PromiseHookFields::HasContextPromiseHook::decode(
        promise_hook_flags_);
  }

  Address promise_hook_flags_address() {
    return reinterpret_cast<Address>(&promise_hook_flags_);
  }

  Address promise_hook_address() {
    return reinterpret_cast<Address>(&promise_hook_);
  }

  Address async_event_delegate_address() {
    return reinterpret_cast<Address>(&async_event_delegate_);
  }

  Address javascript_execution_assert_address() {
    return reinterpret_cast<Address>(&javascript_execution_assert_);
  }

  void IncrementJavascriptExecutionCounter() {
    javascript_execution_counter_++;
  }

  Address handle_scope_implementer_address() {
    return reinterpret_cast<Address>(&handle_scope_implementer_);
  }

  void SetAtomicsWaitCallback(v8::Isolate::AtomicsWaitCallback callback,
                              void* data);
  void RunAtomicsWaitCallback(v8::Isolate::AtomicsWaitEvent event,
                              Handle<JSArrayBuffer> array_buffer,
                              size_t offset_in_bytes, int64_t value,
                              double timeout_in_ms,
                              AtomicsWaitWakeHandle* stop_handle);

  void SetPromiseHook(PromiseHook hook);
  void RunPromiseHook(PromiseHookType type, Handle<JSPromise> promise,
                      Handle<Object> parent);
  void RunAllPromiseHooks(PromiseHookType type, Handle<JSPromise> promise,
                          Handle<Object> parent);
  void UpdatePromiseHookProtector();
  void PromiseHookStateUpdated();

  void AddDetachedContext(Handle<Context> context);
  void CheckDetachedContextsAfterGC();

  // Detach the environment from its outer global object.
  void DetachGlobal(Handle<Context> env);

  std::vector<Tagged<Object>>* startup_object_cache() {
    return &startup_object_cache_;
  }

  // With a shared heap, this cache is shared among all isolates. Otherwise this
  // object cache is per-Isolate like the startup object cache. TODO(372493838):
  // This cache can only contain strings. Update name to reflect this.
  std::vector<Tagged<Object>>* shared_heap_object_cache() {
    if (OwnsStringTables()) {
      return &shared_heap_object_cache_;
    } else {
      return &shared_space_isolate()->shared_heap_object_cache_;
    }
  }

  bool IsGeneratingEmbeddedBuiltins() const {
    return builtins_constants_table_builder() != nullptr;
  }

  BuiltinsConstantsTableBuilder* builtins_constants_table_builder() const {
    return builtins_constants_table_builder_;
  }

  // Hashes bits of the Isolate that are relevant for embedded builtins. In
  // particular, the embedded blob requires builtin InstructionStream object
  // layout and the builtins constants table to remain unchanged from
  // build-time.
  size_t HashIsolateForEmbeddedBlob();

  static const uint8_t* CurrentEmbeddedBlobCode();
  static uint32_t CurrentEmbeddedBlobCodeSize();
  static const uint8_t* CurrentEmbeddedBlobData();
  static uint32_t CurrentEmbeddedBlobDataSize();
  static bool CurrentEmbeddedBlobIsBinaryEmbedded();

  // These always return the same result as static methods above, but don't
  // access the global atomic variable (and thus *might be* slightly faster).
  const uint8_t* embedded_blob_code() const;
  uint32_t embedded_blob_code_size() const;
  const uint8_t* embedded_blob_data() const;
  uint32_t embedded_blob_data_size() const;

  // Returns true if short builtin calls optimization is enabled for the
  // Isolate.
  bool is_short_builtin_calls_enabled() const {
    return V8_SHORT_BUILTIN_CALLS_BOOL && is_short_builtin_calls_enabled_;
  }

  // Returns a region from which it's possible to make pc-relative (short)
  // calls/jumps to embedded builtins or empty region if there's no embedded
  // blob or if pc-relative calls are not supported.
  static base::AddressRegion GetShortBuiltinsCallRegion();

  void set_array_buffer_allocator(v8::ArrayBuffer::Allocator* allocator) {
    array_buffer_allocator_ = allocator;
  }
  v8::ArrayBuffer::Allocator* array_buffer_allocator() const {
    return array_buffer_allocator_;
  }

  void set_array_buffer_allocator_shared(
      std::shared_ptr<v8::ArrayBuffer::Allocator> allocator) {
    array_buffer_allocator_shared_ = std::move(allocator);
  }
  std::shared_ptr<v8::ArrayBuffer::Allocator> array_buffer_allocator_shared()
      const {
    return array_buffer_allocator_shared_;
  }

  FutexWaitListNode* futex_wait_list_node() { return &futex_wait_list_node_; }

  CancelableTaskManager* cancelable_task_manager() {
    return cancelable_task_manager_;
  }

  const AstStringConstants* ast_string_constants() const {
    return ast_string_constants_;
  }

  interpreter::Interpreter* interpreter() const { return interpreter_; }

  compiler::PerIsolateCompilerCache* compiler_cache() const {
    return compiler_cache_;
  }
  void set_compiler_utils(compiler::PerIsolateCompilerCache* cache,
                          Zone* zone) {
    compiler_cache_ = cache;
    compiler_zone_ = zone;
  }

  AccountingAllocator* allocator() { return allocator_; }

  LazyCompileDispatcher* lazy_compile_dispatcher() const {
    return lazy_compile_dispatcher_.get();
  }

  bool IsInCreationContext(Tagged<JSObject> object, uint32_t index);

  void ClearKeptObjects();

  void SetHostImportModuleDynamicallyCallback(
      HostImportModuleDynamicallyCallback callback);
  void SetHostImportModuleWithPhaseDynamicallyCallback(
      HostImportModuleWithPhaseDynamicallyCallback callback);
  MaybeHandle<JSPromise> RunHostImportModuleDynamicallyCallback(
      MaybeHandle<Script> maybe_referrer, Handle<Object> specifier,
      ModuleImportPhase phase,
      MaybeHandle<Object> maybe_import_options_argument);

  void SetHostInitializeImportMetaObjectCallback(
      HostInitializeImportMetaObjectCallback callback);
  MaybeHandle<JSObject> RunHostInitializeImportMetaObjectCallback(
      Handle<SourceTextModule> module);

  void SetHostCreateShadowRealmContextCallback(
      HostCreateShadowRealmContextCallback callback);
  MaybeHandle<NativeContext> RunHostCreateShadowRealmContextCallback();

  void RegisterEmbeddedFileWriter(EmbeddedFileWriterInterface* writer) {
    embedded_file_writer_ = writer;
  }

  int LookupOrAddExternallyCompiledFilename(const char* filename);
  const char* GetExternallyCompiledFilename(int index) const;
  int GetExternallyCompiledFilenameCount() const;
  // PrepareBuiltinSourcePositionMap is necessary in order to preserve the
  // builtin source positions before the corresponding code objects are
  // replaced with trampolines. Those source positions are used to
  // annotate the builtin blob with debugging information.
  void PrepareBuiltinSourcePositionMap();

#if defined(V8_OS_WIN64)
  void SetBuiltinUnwindData(
      Builtin builtin,
      const win64_unwindinfo::BuiltinUnwindInfo& unwinding_info);
#endif  // V8_OS_WIN64

  void SetPrepareStackTraceCallback(PrepareStackTraceCallback callback);
  MaybeHandle<Object> RunPrepareStackTraceCallback(Handle<NativeContext>,
                                                   Handle<JSObject> Error,
                                                   Handle<JSArray> sites);
  bool HasPrepareStackTraceCallback() const;

  void SetAddCrashKeyCallback(AddCrashKeyCallback callback);
  void AddCrashKey(CrashKeyId id, const std::string& value) {
    if (add_crash_key_callback_) {
      add_crash_key_callback_(id, value);
    }
  }

#if defined(V8_OS_WIN) && defined(V8_ENABLE_ETW_STACK_WALKING)
  // Specifies the callback called when an ETW tracing session starts.
  void SetFilterETWSessionByURLCallback(FilterETWSessionByURLCallback callback);
  bool RunFilterETWSessionByURLCallback(const std::string& payload);
#endif  // V8_OS_WIN && V8_ENABLE_ETW_STACK_WALKING

  // Deprecated: prefer SetIsLoading.
  void SetRAILMode(RAILMode rail_mode);

  void SetIsLoading(bool is_loading);

  bool is_loading() const { return is_loading_.load(); }

  void set_code_coverage_mode(debug::CoverageMode coverage_mode) {
    code_coverage_mode_.store(coverage_mode, std::memory_order_relaxed);
  }
  debug::CoverageMode code_coverage_mode() const {
    return code_coverage_mode_.load(std::memory_order_relaxed);
  }

  // Deprecated: prefer SetIsLoading.
  void UpdateLoadStartTime();

  void SetPriority(v8::Isolate::Priority priority);

  v8::Isolate::Priority priority() { return priority_; }
  bool is_backgrounded() {
    return priority_ == v8::Isolate::Priority::kBestEffort;
  }

  // When efficiency mode is enabled we can favor single core throughput without
  // latency requirements. Any decision based on this flag must be quickly
  // reversible as we have to expect to migrate out of efficiency mode on short
  // notice. E.g., it would not be advisable to generate worse code in
  // efficiency mode. The decision when to enable efficiency mode is steered by
  // the embedder. Currently the only signal (potentially) being considered is
  // if an isolate is in foreground or background mode.
  bool EfficiencyModeEnabled() {
    if (V8_UNLIKELY(v8_flags.efficiency_mode.value().has_value())) {
      return *v8_flags.efficiency_mode.value();
    }
    return priority_ != v8::Isolate::Priority::kUserBlocking;
  }

  // This is a temporary api until we use it by default.
  bool EfficiencyModeEnabledForTiering() {
    return v8_flags.efficiency_mode_for_tiering_heuristics &&
           EfficiencyModeEnabled();
  }

  // In battery saver mode we optimize to reduce total cpu cycles spent. Battery
  // saver mode is opt-in by the embedder. As with efficiency mode we must
  // expect that the mode is toggled off again and we should be able to ramp up
  // quickly after that.
  bool BatterySaverModeEnabled() {
    if (V8_UNLIKELY(v8_flags.battery_saver_mode.value().has_value())) {
      return *v8_flags.battery_saver_mode.value();
    }
    return V8_UNLIKELY(battery_saver_mode_enabled_);
  }

  PRINTF_FORMAT(2, 3) void PrintWithTimestamp(const char* format, ...);

  void set_allow_atomics_wait(bool set) { allow_atomics_wait_ = set; }
  bool allow_atomics_wait() { return allow_atomics_wait_; }

  // Register a finalizer to be called at isolate teardown.
  void RegisterManagedPtrDestructor(ManagedPtrDestructor* finalizer);

  // Removes a previously-registered shared object finalizer.
  void UnregisterManagedPtrDestructor(ManagedPtrDestructor* finalizer);

  size_t elements_deletion_counter() { return elements_deletion_counter_; }
  void set_elements_deletion_counter(size_t value) {
    elements_deletion_counter_ = value;
  }

#if V8_ENABLE_WEBASSEMBLY
  void AddSharedWasmMemory(Handle<WasmMemoryObject> memory_object);
#endif  // V8_ENABLE_WEBASSEMBLY

  const v8::Context::BackupIncumbentScope* top_backup_incumbent_scope() const {
    return thread_local_top()->top_backup_incumbent_scope_;
  }
  void set_top_backup_incumbent_scope(
      const v8::Context::BackupIncumbentScope* top_backup_incumbent_scope) {
    thread_local_top()->top_backup_incumbent_scope_ =
        top_backup_incumbent_scope;
  }

  void SetIdle(bool is_idle);

  // Changing various modes can cause differences in generated bytecode which
  // interferes with lazy source positions, so this should be called immediately
  // before such a mode change to ensure that this cannot happen.
  void CollectSourcePositionsForAllBytecodeArrays();

  void AddCodeMemoryChunk(MutablePageMetadata* chunk);
  void RemoveCodeMemoryChunk(MutablePageMetadata* chunk);
  void AddCodeRange(Address begin, size_t length_in_bytes);

  bool RequiresCodeRange() const;

  static Address load_from_stack_count_address(const char* function_name);
  static Address store_to_stack_count_address(const char* function_name);

  v8::metrics::Recorder::ContextId GetOrRegisterRecorderContextId(
      DirectHandle<NativeContext> context);
  MaybeLocal<v8::Context> GetContextFromRecorderContextId(
      v8::metrics::Recorder::ContextId id);

  void UpdateLongTaskStats();
  v8::metrics::LongTaskStats* GetCurrentLongTaskStats();

  LocalIsolate* main_thread_local_isolate() {
    return main_thread_local_isolate_.get();
  }

  Isolate* AsIsolate() { return this; }
  LocalIsolate* AsLocalIsolate() { return main_thread_local_isolate(); }
  Isolate* GetMainThreadIsolateUnsafe() { return this; }

  LocalHeap* main_thread_local_heap();
  LocalHeap* CurrentLocalHeap();

#ifdef V8_COMPRESS_POINTERS
  ExternalPointerTable& external_pointer_table() {
    return isolate_data_.external_pointer_table_;
  }

  const ExternalPointerTable& external_pointer_table() const {
    return isolate_data_.external_pointer_table_;
  }

  Address external_pointer_table_address() {
    return reinterpret_cast<Address>(&isolate_data_.external_pointer_table_);
  }

  ExternalPointerTable& shared_external_pointer_table() {
    return *isolate_data_.shared_external_pointer_table_;
  }

  const ExternalPointerTable& shared_external_pointer_table() const {
    return *isolate_data_.shared_external_pointer_table_;
  }

  ExternalPointerTable::Space* shared_external_pointer_space() {
    return shared_external_pointer_space_;
  }

  Address shared_external_pointer_table_address_address() {
    return reinterpret_cast<Address>(
        &isolate_data_.shared_external_pointer_table_);
  }

  CppHeapPointerTable& cpp_heap_pointer_table() {
    return isolate_data_.cpp_heap_pointer_table_;
  }

  const CppHeapPointerTable& cpp_heap_pointer_table() const {
    return isolate_data_.cpp_heap_pointer_table_;
  }

#endif  // V8_COMPRESS_POINTERS

#ifdef V8_ENABLE_SANDBOX
  TrustedPointerTable& trusted_pointer_table() {
    return isolate_data_.trusted_pointer_table_;
  }

  const TrustedPointerTable& trusted_pointer_table() const {
    return isolate_data_.trusted_pointer_table_;
  }

  Address trusted_pointer_table_base_address() const {
    return isolate_data_.trusted_pointer_table_.base_address();
  }

  TrustedPointerTable& shared_trusted_pointer_table() {
    return *isolate_data_.shared_trusted_pointer_table_;
  }

  const TrustedPointerTable& shared_trusted_pointer_table() const {
    return *isolate_data_.shared_trusted_pointer_table_;
  }

  TrustedPointerTable::Space* shared_trusted_pointer_space() {
    return shared_trusted_pointer_space_;
  }

  Address shared_trusted_pointer_table_base_address() {
    return reinterpret_cast<Address>(
        &isolate_data_.shared_trusted_pointer_table_);
  }
#endif  // V8_ENABLE_SANDBOX

  Address continuation_preserved_embedder_data_address() {
    return reinterpret_cast<Address>(
        &isolate_data_.continuation_preserved_embedder_data_);
  }

  struct PromiseHookFields {
    using HasContextPromiseHook = base::BitField<bool, 0, 1>;
    using HasIsolatePromiseHook = HasContextPromiseHook::Next<bool, 1>;
    using HasAsyncEventDelegate = HasIsolatePromiseHook::Next<bool, 1>;
    using IsDebugActive = HasAsyncEventDelegate::Next<bool, 1>;
  };

  // Returns true when this isolate contains the shared spaces.
  bool is_shared_space_isolate() const { return is_shared_space_isolate_; }

  // Returns the isolate that owns the shared spaces.
  Isolate* shared_space_isolate() const {
    DCHECK(has_shared_space());
    Isolate* isolate = shared_space_isolate_.value();
    DCHECK(has_shared_space());
    return isolate;
  }

  // Returns true when this isolate supports allocation in shared spaces.
  bool has_shared_space() const { return shared_space_isolate_.value(); }

  GlobalSafepoint* global_safepoint() const { return global_safepoint_.get(); }

#if V8_ENABLE_DRUMBRAKE
  void initialize_wasm_execution_timer();

  wasm::WasmExecutionTimer* wasm_execution_timer() const {
    return wasm_execution_timer_.get();
  }
#endif  // V8_ENABLE_DRUMBRAKE

  bool owns_shareable_data() { return owns_shareable_data_; }

  bool log_object_relocation() const { return log_object_relocation_; }

  // TODO(pthier): Unify with owns_shareable_data() once the flag
  // --shared-string-table is removed.
  bool OwnsStringTables() const {
    return !v8_flags.shared_string_table || is_shared_space_isolate();
  }

#if USE_SIMULATOR
  SimulatorData* simulator_data() { return simulator_data_; }
#endif

#ifdef V8_ENABLE_WEBASSEMBLY
  bool IsOnCentralStack();
  std::vector<std::unique_ptr<wasm::StackMemory>>& wasm_stacks() {
    return wasm_stacks_;
  }
  // Update the thread local's Stack object so that it is aware of the new stack
  // start and the inactive stacks.
  void UpdateCentralStackInfo();

  void SyncStackLimit();

  // To be called when returning from {stack}, or when an exception crosses the
  // stack boundary. This updates the {StackMemory} object and the global
  // {wasm_stacks_} list. This does *not* update the ActiveContinuation root and
  // the stack limit.
  void RetireWasmStack(wasm::StackMemory* stack);
#else
  bool IsOnCentralStack() { return true; }
#endif

  // Access to the global "locals block list cache". Caches outer-stack
  // allocated variables per ScopeInfo for debug-evaluate.
  // We also store a strong reference to the outer ScopeInfo to keep all
  // blocklists along a scope chain alive.
  void LocalsBlockListCacheSet(Handle<ScopeInfo> scope_info,
                               Handle<ScopeInfo> outer_scope_info,
                               Handle<StringSet> locals_blocklist);
  // Returns either `TheHole` or `StringSet`.
  Tagged<Object> LocalsBlockListCacheGet(Handle<ScopeInfo> scope_info);

  void VerifyStaticRoots();

  class EnableRoAllocationForSnapshotScope final {
   public:
    explicit EnableRoAllocationForSnapshotScope(Isolate* isolate)
        : isolate_(isolate) {
      CHECK(!isolate_->enable_ro_allocation_for_snapshot_);
      isolate_->enable_ro_allocation_for_snapshot_ = true;
    }

    ~EnableRoAllocationForSnapshotScope() {
      CHECK(isolate_->enable_ro_allocation_for_snapshot_);
      isolate_->enable_ro_allocation_for_snapshot_ = false;
    }

   private:
    Isolate* const isolate_;
  };

  bool enable_ro_allocation_for_snapshot() const {
    return enable_ro_allocation_for_snapshot_;
  }

  void set_battery_saver_mode_enabled(bool battery_saver_mode_enabled) {
    battery_saver_mode_enabled_ = battery_saver_mode_enabled;
  }

  std::list<std::unique_ptr<detail::WaiterQueueNode>>&
  async_waiter_queue_nodes();

  void ReportExceptionFunctionCallback(
      DirectHandle<JSReceiver> receiver,
      DirectHandle<FunctionTemplateInfo> function,
      v8::ExceptionContext callback_kind);
  void ReportExceptionPropertyCallback(Handle<JSReceiver> holder,
                                       Handle<Name> name,
                                       v8::ExceptionContext callback_kind);
  void SetExceptionPropagationCallback(ExceptionPropagationCallback callback);

#ifdef V8_ENABLE_WASM_SIMD256_REVEC
  void set_wasm_revec_verifier_for_test(
      compiler::turboshaft::WasmRevecVerifier* verifier) {
    wasm_revec_verifier_for_test_ = verifier;
  }

  compiler::turboshaft::WasmRevecVerifier* wasm_revec_verifier_for_test()
      const {
    return wasm_revec_verifier_for_test_;
  }
#endif  // V8_ENABLE_WASM_SIMD256_REVEC

 private:
  explicit Isolate(IsolateGroup* isolate_group);
  ~Isolate();

  static Isolate* Allocate(IsolateGroup* isolate_group);

  bool Init(SnapshotData* startup_snapshot_data,
            SnapshotData* read_only_snapshot_data,
            SnapshotData* shared_heap_snapshot_data, bool can_rehash);

  void CheckIsolateLayout();

  void InitializeCodeRanges();
  void AddCodeMemoryRange(MemoryRange range);

  // See IsolateForSandbox.
  Isolate* ForSandbox() { return this; }

  static void RemoveContextIdCallback(const v8::WeakCallbackInfo<void>& data);

  void FireCallCompletedCallbackInternal(MicrotaskQueue* microtask_queue);

  class ThreadDataTable {
   public:
    ThreadDataTable() = default;

    PerIsolateThreadData* Lookup(ThreadId thread_id);
    void Insert(PerIsolateThreadData* data);
    void Remove(PerIsolateThreadData* data);
    void RemoveAllThreads();

   private:
    struct Hasher {
      std::size_t operator()(const ThreadId& t) const {
        return std::hash<int>()(t.ToInteger());
      }
    };

    std::unordered_map<ThreadId, PerIsolateThreadData*, Hasher> table_;
  };

  // These items form a stack synchronously with threads Enter'ing and Exit'ing
  // the Isolate. The top of the stack points to a thread which is currently
  // running the Isolate. When the stack is empty, the Isolate is considered
  // not entered by any thread and can be Disposed.
  // If the same thread enters the Isolate more than once, the entry_count_
  // is incremented rather then a new item pushed to the stack.
  class EntryStackItem {
   public:
    EntryStackItem(PerIsolateThreadData* previous_thread_data,
                   Isolate* previous_isolate, EntryStackItem* previous_item)
        : entry_count(1),
          previous_thread_data(previous_thread_data),
          previous_isolate(previous_isolate),
          previous_item(previous_item) {}
    EntryStackItem(const EntryStackItem&) = delete;
    EntryStackItem& operator=(const EntryStackItem&) = delete;

    int entry_count;
    PerIsolateThreadData* previous_thread_data;
    Isolate* previous_isolate;
    EntryStackItem* previous_item;
  };

  void Deinit();

  static void SetIsolateThreadLocals(Isolate* isolate,
                                     PerIsolateThreadData* data);

  void FillCache();

  // Propagate exception message to the v8::TryCatch.
  // If there is no external try-catch or message was successfully propagated,
  // then return true.
  bool PropagateExceptionToExternalTryCatch(ExceptionHandlerType top_handler);

  // Checks if the exception happened in any of the Api callback and call
  // the |exception_propagation_callback_|.
  void NotifyExceptionPropagationCallback();

  bool HasIsolatePromiseHooks() const {
    return PromiseHookFields::HasIsolatePromiseHook::decode(
        promise_hook_flags_);
  }

  bool HasAsyncEventDelegate() const {
    return PromiseHookFields::HasAsyncEventDelegate::decode(
        promise_hook_flags_);
  }

  const char* RAILModeName(RAILMode rail_mode) const {
    switch (rail_mode) {
      case PERFORMANCE_RESPONSE:
        return "RESPONSE";
      case PERFORMANCE_ANIMATION:
        return "ANIMATION";
      case PERFORMANCE_IDLE:
        return "IDLE";
      case PERFORMANCE_LOAD:
        return "LOAD";
    }
    return "";
  }

  void AddCrashKeysForIsolateAndHeapPointers();

#if V8_ENABLE_WEBASSEMBLY
  bool IsOnCentralStack(Address addr);
#else
  bool IsOnCentralStack(Address addr) { return true; }
#endif

  // This class contains a collection of data accessible from both C++ runtime
  // and compiled code (including assembly stubs, builtins, interpreter bytecode
  // handlers and optimized code).
  IsolateData isolate_data_;

  // Set to true if this isolate is used as main isolate with a shared space.
  bool is_shared_space_isolate_{false};

  IsolateGroup* isolate_group_;
  Heap heap_;
  ReadOnlyHeap* read_only_heap_ = nullptr;

  // These are guaranteed empty when !OwnsStringTables().
  std::unique_ptr<StringTable> string_table_;
  std::unique_ptr<StringForwardingTable> string_forwarding_table_;

  const int id_;
  std::atomic<EntryStackItem*> entry_stack_ = nullptr;
  int stack_trace_nesting_level_ = 0;
  std::atomic<bool> was_locker_ever_used_{false};
  StringStream* incomplete_message_ = nullptr;
  Address isolate_addresses_[kIsolateAddressCount + 1] = {};
  Bootstrapper* bootstrapper_ = nullptr;
  TieringManager* tiering_manager_ = nullptr;
  CompilationCache* compilation_cache_ = nullptr;
  std::shared_ptr<Counters> async_counters_;
  base::RecursiveMutex break_access_;
  base::SharedMutex feedback_vector_access_;
  base::SharedMutex internalized_string_access_;
  base::SharedMutex full_transition_array_access_;
  base::SharedMutex shared_function_info_access_;
  base::SharedMutex map_updater_access_;
  base::SharedMutex boilerplate_migration_access_;
  V8FileLogger* v8_file_logger_ = nullptr;
  StubCache* load_stub_cache_ = nullptr;
  StubCache* store_stub_cache_ = nullptr;
  StubCache* define_own_stub_cache_ = nullptr;
  Deoptimizer* current_deoptimizer_ = nullptr;
  bool deoptimizer_lazy_throw_ = false;
  MaterializedObjectStore* materialized_object_store_ = nullptr;
  bool capture_stack_trace_for_uncaught_exceptions_ = false;
  int stack_trace_for_uncaught_exceptions_frame_limit_ = 0;
  StackTrace::StackTraceOptions stack_trace_for_uncaught_exceptions_options_ =
      StackTrace::kOverview;
  DescriptorLookupCache* descriptor_lookup_cache_ = nullptr;
  HandleScopeImplementer* handle_scope_implementer_ = nullptr;
  UnicodeCache* unicode_cache_ = nullptr;
  AccountingAllocator* allocator_ = nullptr;
  InnerPointerToCodeCache* inner_pointer_to_code_cache_ = nullptr;
  GlobalHandles* global_handles_ = nullptr;
  TracedHandles traced_handles_;
  EternalHandles* eternal_handles_ = nullptr;
  ThreadManager* thread_manager_ = nullptr;
  bigint::Processor* bigint_processor_ = nullptr;
  RuntimeState runtime_state_;
  Builtins builtins_;
  SetupIsolateDelegate* setup_delegate_ = nullptr;
#if defined(DEBUG) || defined(VERIFY_HEAP)
  std::atomic<int> num_active_deserializers_;
#endif
#ifndef V8_INTL_SUPPORT
  unibrow::Mapping<unibrow::Ecma262UnCanonicalize> jsregexp_uncanonicalize_;
  unibrow::Mapping<unibrow::CanonicalizationRange> jsregexp_canonrange_;
  unibrow::Mapping<unibrow::Ecma262Canonicalize>
      regexp_macro_assembler_canonicalize_;
#endif  // !V8_INTL_SUPPORT
  RegExpStack* regexp_stack_ = nullptr;
  std::vector<int> regexp_indices_;
  DateCache* date_cache_ = nullptr;
  base::RandomNumberGenerator* random_number_generator_ = nullptr;
  base::RandomNumberGenerator* fuzzer_rng_ = nullptr;
  std::atomic<bool> is_loading_{false};
  v8::Isolate::AtomicsWaitCallback atomics_wait_callback_ = nullptr;
  void* atomics_wait_callback_data_ = nullptr;
  PromiseHook promise_hook_ = nullptr;
  HostImportModuleDynamicallyCallback host_import_module_dynamically_callback_ =
      nullptr;
  HostImportModuleWithPhaseDynamicallyCallback
      host_import_module_with_phase_dynamically_callback_ = nullptr;
  std::atomic<debug::CoverageMode> code_coverage_mode_{
      debug::CoverageMode::kBestEffort};

  std::atomic<bool> battery_saver_mode_enabled_ = false;

  // Helper function for RunHostImportModuleDynamicallyCallback.
  // Unpacks import attributes, if present, from the second argument to dynamic
  // import() and returns them in a FixedArray, sorted by code point order of
  // the keys, in the form [key1, value1, key2, value2, ...]. Returns an empty
  // MaybeHandle if an error was thrown.  In this case, the host callback should
  // not be called and instead the caller should use the exception to
  // reject the import() call's Promise.
  MaybeHandle<FixedArray> GetImportAttributesFromArgument(
      MaybeHandle<Object> maybe_import_options_argument);

  HostInitializeImportMetaObjectCallback
      host_initialize_import_meta_object_callback_ = nullptr;
  HostCreateShadowRealmContextCallback
      host_create_shadow_realm_context_callback_ = nullptr;

#ifdef V8_INTL_SUPPORT
  std::string default_locale_;

  // The cache stores the most recently accessed {locales,obj} pair for each
  // cache type.
  struct ICUObjectCacheEntry {
    std::string locales;
    std::shared_ptr<icu::UMemory> obj;

    ICUObjectCacheEntry() = default;
    ICUObjectCacheEntry(std::string locales, std::shared_ptr<icu::UMemory> obj)
        : locales(locales), obj(std::move(obj)) {}
  };

  ICUObjectCacheEntry icu_object_cache_[kICUObjectCacheTypeCount];
#endif  // V8_INTL_SUPPORT

  // Whether the isolate has been created for snapshotting.
  bool serializer_enabled_ = false;

  // True if fatal error has been signaled for this isolate.
  bool has_fatal_error_ = false;

  // True if this isolate was initialized from a snapshot.
  bool initialized_from_snapshot_ = false;

  // True if short builtin calls optimization is enabled.
  bool is_short_builtin_calls_enabled_ = false;

  // The isolate current's priority. This flag is used
```