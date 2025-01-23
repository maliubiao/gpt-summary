Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/wasm/module-compiler.cc`. They also have some specific requests related to Torque, JavaScript examples, logic inference, common programming errors, and the context of this snippet within a larger codebase.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The filename `module-compiler.cc` strongly suggests that this code is responsible for compiling WebAssembly modules within V8. The code itself confirms this, as it deals with decoding, validating, and generating native code for WebAssembly.

2. **Break down the code into logical sections:** The snippet contains several classes and functions. The main entry points and key components seem to be:
    * `GetOrCompileNewNativeModule`:  A function to retrieve or create a compiled module.
    * `CompileToNativeModule`: A higher-level function calling the previous one and handling logging.
    * `AsyncCompileJob`: A class for asynchronous compilation of WebAssembly modules.
    * `ValidateFunctionsStreamingJobData` and `ValidateFunctionsStreamingJob`: Components for validating function bodies during streaming compilation.
    * `AsyncStreamingProcessor`: A class for handling the streaming decoding and compilation process.
    *  Nested classes within `AsyncCompileJob` like `DecodeModule`, `PrepareAndStartCompile`, and `FinishCompilation`: Representing the stages of asynchronous compilation.

3. **Summarize the functionality of each section:**
    * `GetOrCompileNewNativeModule`:  Checks the cache, and if not found, compiles a new module.
    * `CompileToNativeModule`:  Wraps the compilation process and logs the results.
    * `AsyncCompileJob`:  Manages the asynchronous compilation process, including decoding, validation, code generation, and caching. It handles both foreground and background tasks.
    * `ValidateFunctionsStreamingJobData` and `ValidateFunctionsStreamingJob`: Enable parallel validation of function bodies as they are streamed in. This optimizes the compilation process.
    * `AsyncStreamingProcessor`: Handles the incoming bytes of a WebAssembly module in a streaming fashion, triggering different compilation steps.
    * The nested classes within `AsyncCompileJob`: Each represents a specific phase in the asynchronous compilation pipeline.

4. **Address specific user requests:**
    * **Torque:** The code does *not* end in `.tq`, so it's not Torque.
    * **JavaScript relationship:** WebAssembly is a target for compilation from other languages, but it's also tightly integrated with JavaScript in the browser. The `WebAssembly.compile()` function in JavaScript directly triggers this kind of compilation process. Provide a concise example.
    * **Logic inference:** The `GetOrCompileNewNativeModule` function has a clear if/else logic based on cache hits. Illustrate with a simple input and output scenario.
    * **Common programming errors:**  Asynchronous programming can be tricky. Highlight potential issues like race conditions (though the code tries to mitigate them with atomics), and unhandled errors.
    * **Part 4 of 6:** This suggests the context is a multi-stage compilation pipeline. The current part seems to focus on the initial stages of compilation, especially the asynchronous aspect and streaming.

5. **Synthesize the information into a clear and organized summary:** Structure the answer with headings and bullet points to make it easy to read.

6. **Review and refine:** Ensure the language is accurate and avoids jargon where possible. Double-check that all user requests have been addressed. For example, initially, I might have focused too much on the individual functions, but the `AsyncCompileJob` is clearly a central component, so emphasizing its role is important. Also, ensure the JavaScript example is relevant and easy to understand.
好的，这是对 `v8/src/wasm/module-compiler.cc` 代码片段的功能归纳：

**功能归纳:**

这段代码是 V8 引擎中 WebAssembly 模块编译器的核心部分，主要负责将 WebAssembly 字节码编译成可执行的本地机器码。它涵盖了同步和异步两种编译模式，并且特别关注了异步流式编译的实现。

**核心功能点:**

1. **获取或编译 NativeModule:**  `GetOrCompileNewNativeModule` 函数负责从缓存中查找已编译的模块，如果找不到则创建一个新的 `NativeModule` 并进行编译。
2. **同步编译:** `CompileToNativeModule` 函数是对 `GetOrCompileNewNativeModule` 的封装，它在同步上下文中执行编译，并负责记录编译相关的指标。
3. **异步编译框架:** `AsyncCompileJob` 类是实现 WebAssembly 模块异步编译的核心。它管理着编译的各个阶段，包括模块的解码、验证、代码生成以及与缓存的交互。
4. **流式编译:**  `AsyncStreamingProcessor` 类和相关的 `ValidateFunctionsStreamingJobData` 和 `ValidateFunctionsStreamingJob` 结构体和类实现了 WebAssembly 模块的流式编译。这意味着可以在模块下载完成之前就开始编译，提高加载速度。
5. **编译阶段管理:** `AsyncCompileJob` 使用内部的 `CompileStep` 子类（如 `DecodeModule`, `PrepareAndStartCompile`, `FinishCompilation`）来组织异步编译的不同阶段，并使用任务队列和回调机制来驱动编译流程。
6. **模块缓存:** 代码中涉及到与 V8 的 WebAssembly 引擎 (`GetWasmEngine()`) 交互，进行模块的缓存查找和更新，以避免重复编译。
7. **特性检测和发布:** 代码会检测 WebAssembly 模块中使用的特性 (`WasmDetectedFeatures`)，并在编译完成后将其发布到当前的 isolate 中。
8. **错误处理:** 代码中使用了 `ErrorThrower` 来处理编译过程中遇到的错误，并在异步编译失败时进行相应的处理和错误报告。
9. **性能指标收集:** 代码中包含对编译耗时、代码大小等性能指标的记录，用于性能分析和优化。

**针对你的问题:**

* **`.tq` 结尾:**  `v8/src/wasm/module-compiler.cc` 以 `.cc` 结尾，因此它是一个 C++ 源代码文件，而不是 Torque 源代码。
* **与 JavaScript 的关系:**  WebAssembly 的主要使用场景之一就是在 JavaScript 环境中运行。JavaScript 可以通过 `WebAssembly.compile()` 或 `WebAssembly.instantiate()` 函数来触发 WebAssembly 模块的编译。

   ```javascript
   // 假设 wasmCode 是一个包含 WebAssembly 字节码的 ArrayBuffer
   const wasmCode = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, ...]);

   WebAssembly.compile(wasmCode)
     .then(module => {
       console.log("WebAssembly 模块编译成功:", module);
       // 可以使用 module 创建实例
       return WebAssembly.instantiate(module);
     })
     .then(instance => {
       console.log("WebAssembly 实例创建成功:", instance);
       // 调用导出的 WebAssembly 函数
       const result = instance.exports.exported_function();
       console.log("WebAssembly 函数调用结果:", result);
     })
     .catch(error => {
       console.error("WebAssembly 编译或实例化失败:", error);
     });
   ```

* **代码逻辑推理:** `GetOrCompileNewNativeModule` 函数的核心逻辑是检查缓存。

   **假设输入:**
   * `isolate`: 当前 V8 隔离区对象。
   * `enabled_features`: 启用的 WebAssembly 特性。
   * `detected_features`: 检测到的 WebAssembly 特性。
   * `compile_imports`: 编译时导入的信息。
   * `thrower`: 错误抛出器。
   * `module`: WebAssembly 模块的抽象表示。
   * `wire_bytes`: 原始的 WebAssembly 字节码。
   * `compilation_id`: 编译 ID。
   * `context_id`: 上下文 ID。
   * `pgo_info`: PGO 信息 (可能为空)。

   **情景 1 (缓存命中):**  假设 V8 的 WebAssembly 引擎的缓存中已经存在与当前 `module` 和 `wire_bytes` 匹配的 `NativeModule`。
   **预期输出:**  函数会直接从缓存中返回已存在的 `NativeModule`，而不会执行编译过程。

   **情景 2 (缓存未命中):** 假设缓存中不存在匹配的 `NativeModule`。
   **预期输出:** 函数会创建一个新的 `NativeModule`，然后调用 `CompileNativeModule` 进行编译，最终将新编译的模块放入缓存并返回。

* **用户常见的编程错误:**  在使用异步 WebAssembly 编译时，一个常见的错误是在编译完成之前尝试访问模块的导出项。

   ```javascript
   const wasmCode = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, ...]);

   WebAssembly.compile(wasmCode)
     .then(module => {
       // 错误的做法：直接尝试使用 module，但实例化可能是异步的
       // const instance = WebAssembly.instance(module); // 'instance' is not a function
       // const result = instance.exports.exported_function();

       // 正确的做法：等待实例化完成
       return WebAssembly.instantiate(module);
     })
     .then(instance => {
       const result = instance.exports.exported_function();
       console.log("结果:", result);
     })
     .catch(error => {
       console.error("错误:", error);
     });

   // 另一种常见的错误是没有正确处理编译失败的情况，导致程序异常。
   ```

总之，这段代码是 V8 引擎中负责高效编译 WebAssembly 模块的关键组成部分，它支持同步和异步编译，并特别优化了流式编译的性能。它与 JavaScript 的 `WebAssembly` API 紧密相关，使得 JavaScript 能够利用 WebAssembly 提供的性能优势。

### 提示词
```
这是目录为v8/src/wasm/module-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/module-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
ate->counters(), module->origin, wasm_compile, module_time));
  }

  const bool include_liftoff =
      module->origin == kWasmOrigin && v8_flags.liftoff;
  size_t code_size_estimate =
      wasm::WasmCodeManager::EstimateNativeModuleCodeSize(
          module.get(), include_liftoff,
          DynamicTiering{v8_flags.wasm_dynamic_tiering.value()});
  native_module = GetWasmEngine()->NewNativeModule(
      isolate, enabled_features, detected_features, std::move(compile_imports),
      module, code_size_estimate);
  native_module->SetWireBytes(std::move(wire_bytes_copy));
  native_module->compilation_state()->set_compilation_id(compilation_id);

  if (!v8_flags.wasm_jitless) {
    // Compile / validate the new module.
    CompileNativeModule(isolate, context_id, thrower, native_module, pgo_info);
  }

  if (thrower->error()) {
    GetWasmEngine()->UpdateNativeModuleCache(true, std::move(native_module),
                                             isolate);
    return {};
  }

  // Finally, put the new module in the cache; this can return the passed
  // NativeModule pointer, or another one (for a previously cached module).
  return GetWasmEngine()->UpdateNativeModuleCache(false, native_module,
                                                  isolate);
}

}  // namespace

std::shared_ptr<NativeModule> CompileToNativeModule(
    Isolate* isolate, WasmEnabledFeatures enabled_features,
    WasmDetectedFeatures detected_features, CompileTimeImports compile_imports,
    ErrorThrower* thrower, std::shared_ptr<const WasmModule> module,
    ModuleWireBytes wire_bytes, int compilation_id,
    v8::metrics::Recorder::ContextId context_id, ProfileInformation* pgo_info) {
  std::shared_ptr<NativeModule> native_module = GetOrCompileNewNativeModule(
      isolate, enabled_features, detected_features, std::move(compile_imports),
      thrower, module, wire_bytes, compilation_id, context_id, pgo_info);
  if (!native_module) return {};

  // Ensure that the code objects are logged before returning.
  GetWasmEngine()->LogOutstandingCodesForIsolate(isolate);

  // Now publish all detected features of this module in the current isolate.
  PublishDetectedFeatures(
      native_module->compilation_state()->detected_features(), isolate, true);

  return native_module;
}

AsyncCompileJob::AsyncCompileJob(
    Isolate* isolate, WasmEnabledFeatures enabled_features,
    CompileTimeImports compile_imports, base::OwnedVector<const uint8_t> bytes,
    DirectHandle<Context> context,
    DirectHandle<NativeContext> incumbent_context, const char* api_method_name,
    std::shared_ptr<CompilationResultResolver> resolver, int compilation_id)
    : isolate_(isolate),
      api_method_name_(api_method_name),
      enabled_features_(enabled_features),
      compile_imports_(std::move(compile_imports)),
      dynamic_tiering_(DynamicTiering{v8_flags.wasm_dynamic_tiering.value()}),
      start_time_(base::TimeTicks::Now()),
      bytes_copy_(std::move(bytes)),
      wire_bytes_(bytes_copy_.as_vector()),
      resolver_(std::move(resolver)),
      compilation_id_(compilation_id) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.wasm.detailed"),
               "wasm.AsyncCompileJob");
  CHECK(v8_flags.wasm_async_compilation);
  CHECK(!v8_flags.jitless || v8_flags.wasm_jitless);
  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate);
  v8::Platform* platform = V8::GetCurrentPlatform();
  foreground_task_runner_ = platform->GetForegroundTaskRunner(v8_isolate);
  native_context_ =
      isolate->global_handles()->Create(context->native_context());
  incumbent_context_ = isolate->global_handles()->Create(*incumbent_context);
  DCHECK(IsNativeContext(*native_context_));
  context_id_ = isolate->GetOrRegisterRecorderContextId(native_context_);
  metrics_event_.async = true;
}

void AsyncCompileJob::Start() {
  DoAsync<DecodeModule>(isolate_->counters(),
                        isolate_->metrics_recorder());  // --
}

void AsyncCompileJob::Abort() {
  // Removing this job will trigger the destructor, which will cancel all
  // compilation.
  GetWasmEngine()->RemoveCompileJob(this);
}

// {ValidateFunctionsStreamingJobData} holds information that is shared between
// the {AsyncStreamingProcessor} and the {ValidateFunctionsStreamingJob}. It
// lives in the {AsyncStreamingProcessor} and is updated from both classes.
struct ValidateFunctionsStreamingJobData {
  struct Unit {
    // {func_index == -1} represents an "invalid" unit.
    int func_index = -1;
    base::Vector<const uint8_t> code;

    // Check whether the unit is valid.
    operator bool() const {
      DCHECK_LE(-1, func_index);
      return func_index >= 0;
    }
  };

  void Initialize(int num_declared_functions) {
    DCHECK_NULL(units);
    units = base::OwnedVector<Unit>::NewForOverwrite(num_declared_functions);
    // Initially {next == end}.
    next_available_unit.store(units.begin(), std::memory_order_relaxed);
    end_of_available_units.store(units.begin(), std::memory_order_relaxed);
  }

  void AddUnit(int declared_func_index, base::Vector<const uint8_t> code,
               JobHandle* job_handle) {
    DCHECK_NOT_NULL(units);
    // Write new unit to {*end}, then increment {end}. There is only one thread
    // adding new units, so no further synchronization needed.
    Unit* ptr = end_of_available_units.load(std::memory_order_relaxed);
    // Check invariant: {next <= end}.
    DCHECK_LE(next_available_unit.load(std::memory_order_relaxed), ptr);
    *ptr++ = {declared_func_index, code};
    // Use release semantics, so whoever loads this pointer (using acquire
    // semantics) sees all our previous stores.
    end_of_available_units.store(ptr, std::memory_order_release);
    size_t total_units_added = ptr - units.begin();
    // Periodically notify concurrency increase. This has overhead, so avoid
    // calling it too often. As long as threads are still running they will
    // continue processing new units anyway, and if background threads validate
    // faster than we can add units, then only notifying after increasingly long
    // delays is the right thing to do to avoid too many small validation tasks.
    // We notify on each power of two after 16 units, and every 16k units (just
    // to have *some* upper limit and avoiding to pile up too many units).
    // Additionally, notify after receiving the last unit of the module.
    if ((total_units_added >= 16 &&
         base::bits::IsPowerOfTwo(total_units_added)) ||
        (total_units_added % (16 * 1024)) == 0 || ptr == units.end()) {
      job_handle->NotifyConcurrencyIncrease();
    }
  }

  size_t NumOutstandingUnits() const {
    Unit* next = next_available_unit.load(std::memory_order_relaxed);
    Unit* end = end_of_available_units.load(std::memory_order_relaxed);
    DCHECK_LE(next, end);
    return end - next;
  }

  // Retrieve one unit to validate; returns an "invalid" unit if nothing is in
  // the queue.
  Unit GetUnit() {
    // Use an acquire load to synchronize with the store in {AddUnit}. All units
    // before this {end} are fully initialized and ready to execute.
    Unit* end = end_of_available_units.load(std::memory_order_acquire);
    Unit* next = next_available_unit.load(std::memory_order_relaxed);
    while (next < end) {
      if (next_available_unit.compare_exchange_weak(
              next, next + 1, std::memory_order_relaxed)) {
        return *next;
      }
      // Otherwise retry with updated {next} pointer.
    }
    return {};
  }

  void UpdateDetectedFeatures(WasmDetectedFeatures new_detected_features) {
    WasmDetectedFeatures old_features =
        detected_features.load(std::memory_order_relaxed);
    while (!detected_features.compare_exchange_weak(
        old_features, old_features | new_detected_features,
        std::memory_order_relaxed)) {
      // Retry with updated {old_features}.
    }
  }

  base::OwnedVector<Unit> units;
  std::atomic<Unit*> next_available_unit;
  std::atomic<Unit*> end_of_available_units;
  std::atomic<bool> found_error{false};
  std::atomic<WasmDetectedFeatures> detected_features;
};

class ValidateFunctionsStreamingJob final : public JobTask {
 public:
  ValidateFunctionsStreamingJob(const WasmModule* module,
                                WasmEnabledFeatures enabled_features,
                                ValidateFunctionsStreamingJobData* data)
      : module_(module), enabled_features_(enabled_features), data_(data) {}

  void Run(JobDelegate* delegate) override {
    TRACE_EVENT0("v8.wasm", "wasm.ValidateFunctionsStreaming");
    using Unit = ValidateFunctionsStreamingJobData::Unit;
    Zone validation_zone{GetWasmEngine()->allocator(), ZONE_NAME};
    WasmDetectedFeatures detected_features;
    while (Unit unit = data_->GetUnit()) {
      validation_zone.Reset();
      DecodeResult result = ValidateSingleFunction(
          &validation_zone, module_, unit.func_index, unit.code,
          enabled_features_, &detected_features);

      if (result.failed()) {
        data_->found_error.store(true, std::memory_order_relaxed);
        break;
      }
      // After validating one function, check if we should yield.
      if (delegate->ShouldYield()) break;
    }

    data_->UpdateDetectedFeatures(detected_features);
  }

  size_t GetMaxConcurrency(size_t worker_count) const override {
    return worker_count + data_->NumOutstandingUnits();
  }

 private:
  const WasmModule* const module_;
  const WasmEnabledFeatures enabled_features_;
  ValidateFunctionsStreamingJobData* data_;
};

class AsyncStreamingProcessor final : public StreamingProcessor {
 public:
  explicit AsyncStreamingProcessor(AsyncCompileJob* job);

  bool ProcessModuleHeader(base::Vector<const uint8_t> bytes) override;

  bool ProcessSection(SectionCode section_code,
                      base::Vector<const uint8_t> bytes,
                      uint32_t offset) override;

  bool ProcessCodeSectionHeader(int num_functions,
                                uint32_t functions_mismatch_error_offset,
                                std::shared_ptr<WireBytesStorage>,
                                int code_section_start,
                                int code_section_length) override;

  bool ProcessFunctionBody(base::Vector<const uint8_t> bytes,
                           uint32_t offset) override;

  void OnFinishedChunk() override;

  void OnFinishedStream(base::OwnedVector<const uint8_t> bytes,
                        bool after_error) override;

  void OnAbort() override;

  bool Deserialize(base::Vector<const uint8_t> wire_bytes,
                   base::Vector<const uint8_t> module_bytes) override;

 private:
  void CommitCompilationUnits();

  ModuleDecoder decoder_;
  AsyncCompileJob* job_;
  std::unique_ptr<CompilationUnitBuilder> compilation_unit_builder_;
  int num_functions_ = 0;
  bool prefix_cache_hit_ = false;
  bool before_code_section_ = true;
  ValidateFunctionsStreamingJobData validate_functions_job_data_;
  std::unique_ptr<JobHandle> validate_functions_job_handle_;

  // Running hash of the wire bytes up to code section size, but excluding the
  // code section itself. Used by the {NativeModuleCache} to detect potential
  // duplicate modules.
  size_t prefix_hash_ = 0;
};

std::shared_ptr<StreamingDecoder> AsyncCompileJob::CreateStreamingDecoder() {
  DCHECK_NULL(stream_);
  stream_ = StreamingDecoder::CreateAsyncStreamingDecoder(
      std::make_unique<AsyncStreamingProcessor>(this));
  return stream_;
}

AsyncCompileJob::~AsyncCompileJob() {
  // Note: This destructor always runs on the foreground thread of the isolate.
  background_task_manager_.CancelAndWait();
  // If initial compilation did not finish yet we can abort it.
  if (native_module_) {
    Impl(native_module_->compilation_state())
        ->CancelCompilation(CompilationStateImpl::kCancelInitialCompilation);
  }
  // Tell the streaming decoder that the AsyncCompileJob is not available
  // anymore.
  if (stream_) stream_->NotifyCompilationDiscarded();
  CancelPendingForegroundTask();
  isolate_->global_handles()->Destroy(native_context_.location());
  isolate_->global_handles()->Destroy(incumbent_context_.location());
  if (!module_object_.is_null()) {
    isolate_->global_handles()->Destroy(module_object_.location());
  }
}

void AsyncCompileJob::CreateNativeModule(
    std::shared_ptr<const WasmModule> module, size_t code_size_estimate) {
  // Embedder usage count for declared shared memories.
  const bool has_shared_memory =
      std::any_of(module->memories.begin(), module->memories.end(),
                  [](auto& memory) { return memory.is_shared; });
  if (has_shared_memory) {
    isolate_->CountUsage(v8::Isolate::UseCounterFeature::kWasmSharedMemory);
  }

  // Create the module object and populate with compiled functions and
  // information needed at instantiation time.

  native_module_ = GetWasmEngine()->NewNativeModule(
      isolate_, enabled_features_, detected_features_,
      std::move(compile_imports_), std::move(module), code_size_estimate);
  native_module_->SetWireBytes(std::move(bytes_copy_));
  native_module_->compilation_state()->set_compilation_id(compilation_id_);
}

bool AsyncCompileJob::GetOrCreateNativeModule(
    std::shared_ptr<const WasmModule> module, size_t code_size_estimate) {
  native_module_ = GetWasmEngine()->MaybeGetNativeModule(
      module->origin, wire_bytes_.module_bytes(), compile_imports_, isolate_);
  if (native_module_ == nullptr) {
    CreateNativeModule(std::move(module), code_size_estimate);
    return false;
  }
  return true;
}

void AsyncCompileJob::PrepareRuntimeObjects() {
  // Create heap objects for script and module bytes to be stored in the
  // module object. Asm.js is not compiled asynchronously.
  DCHECK(module_object_.is_null());
  auto source_url =
      stream_ ? base::VectorOf(stream_->url()) : base::Vector<const char>();
  auto script =
      GetWasmEngine()->GetOrCreateScript(isolate_, native_module_, source_url);
  DirectHandle<WasmModuleObject> module_object =
      WasmModuleObject::New(isolate_, native_module_, script);

  module_object_ = isolate_->global_handles()->Create(*module_object);
}

// This function assumes that it is executed in a HandleScope, and that a
// context is set on the isolate.
void AsyncCompileJob::FinishCompile(bool is_after_cache_hit) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.wasm.detailed"),
               "wasm.FinishAsyncCompile");
  if (stream_) {
    stream_->NotifyNativeModuleCreated(native_module_);
  }
  const WasmModule* module = native_module_->module();
  auto compilation_state = Impl(native_module_->compilation_state());

  // Update the compilation state with feature detected during module decoding
  // and (potentially) validation. We will publish all features below, in the
  // current isolate, so ignore the return value here.
  USE(compilation_state->UpdateDetectedFeatures(detected_features_));

  // If experimental PGO via files is enabled, load profile information now that
  // we have all wire bytes and know that the module is valid.
  if (V8_UNLIKELY(v8_flags.experimental_wasm_pgo_from_file)) {
    std::unique_ptr<ProfileInformation> pgo_info =
        LoadProfileFromFile(module, native_module_->wire_bytes());
    if (pgo_info) {
      compilation_state->ApplyPgoInfoLate(pgo_info.get());
    }
  }

  bool is_after_deserialization = !module_object_.is_null();
  if (!is_after_deserialization) {
    PrepareRuntimeObjects();
  }

  // Measure duration of baseline compilation or deserialization from cache.
  if (base::TimeTicks::IsHighResolution()) {
    base::TimeDelta duration = base::TimeTicks::Now() - start_time_;
    int duration_usecs = static_cast<int>(duration.InMicroseconds());
    isolate_->counters()->wasm_streaming_finish_wasm_module_time()->AddSample(
        duration_usecs);

    if (is_after_cache_hit || is_after_deserialization) {
      v8::metrics::WasmModuleCompiled event{
          true,                                     // async
          true,                                     // streamed
          is_after_cache_hit,                       // cached
          is_after_deserialization,                 // deserialized
          v8_flags.wasm_lazy_compilation,           // lazy
          !compilation_state->failed(),             // success
          native_module_->turbofan_code_size(),     // code_size_in_bytes
          native_module_->liftoff_bailout_count(),  // liftoff_bailout_count
          duration.InMicroseconds()};               // wall_clock_duration_in_us
      isolate_->metrics_recorder()->DelayMainThreadEvent(event, context_id_);
    }
  }

  DCHECK(!isolate_->context().is_null());
  // Finish the wasm script now and make it public to the debugger.
  DirectHandle<Script> script(module_object_->script(), isolate_);
  auto sourcemap_symbol =
      module->debug_symbols[WasmDebugSymbols::Type::SourceMap];
  if (script->type() == Script::Type::kWasm &&
      sourcemap_symbol.type != WasmDebugSymbols::Type::None &&
      !sourcemap_symbol.external_url.is_empty()) {
    ModuleWireBytes wire_bytes(native_module_->wire_bytes());
    MaybeHandle<String> src_map_str = isolate_->factory()->NewStringFromUtf8(
        wire_bytes.GetNameOrNull(sourcemap_symbol.external_url),
        AllocationType::kOld);
    script->set_source_mapping_url(*src_map_str.ToHandleChecked());
  }
  {
    TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.wasm.detailed"),
                 "wasm.Debug.OnAfterCompile");
    isolate_->debug()->OnAfterCompile(script);
  }

  // Publish the detected features in this isolate, once initial compilation
  // is done. Validate should have detected all features, unless lazy validation
  // is enabled.
  PublishDetectedFeatures(compilation_state->detected_features(), isolate_,
                          true);

  // We might need debug code for the module, if the debugger was enabled while
  // streaming compilation was running. Since handling this while compiling via
  // streaming is tricky, we just remove all code which may have been generated,
  // and compile debug code lazily.
  if (native_module_->IsInDebugState()) {
    WasmCodeRefScope ref_scope;
    native_module_->RemoveCompiledCode(
        NativeModule::RemoveFilter::kRemoveNonDebugCode);
  }

  // Finally, log all generated code (it does not matter if this happens
  // repeatedly in case the script is shared).
  native_module_->LogWasmCodes(isolate_, module_object_->script());

  FinishSuccessfully();
}

void AsyncCompileJob::Failed() {
  // {job} keeps the {this} pointer alive.
  std::unique_ptr<AsyncCompileJob> job =
      GetWasmEngine()->RemoveCompileJob(this);

  // Revalidate the whole module to produce a deterministic error message.
  constexpr bool kValidate = true;
  WasmDetectedFeatures unused_detected_features;
  ModuleResult result =
      DecodeWasmModule(enabled_features_, wire_bytes_.module_bytes(), kValidate,
                       kWasmOrigin, &unused_detected_features);
  ErrorThrower thrower(isolate_, api_method_name_);
  if (result.failed()) {
    thrower.CompileFailed(std::move(result).error());
  } else {
    // The only possible reason why {result} might be okay is if the failure
    // was due to compile-time imports checking.
    CHECK(!job->compile_imports_.empty());
    WasmError error = ValidateAndSetBuiltinImports(
        result.value().get(), wire_bytes_.module_bytes(), job->compile_imports_,
        &unused_detected_features);
    CHECK(error.has_error());
    thrower.CompileError("%s", error.message().c_str());
  }
  resolver_->OnCompilationFailed(thrower.Reify());
}

class AsyncCompileJob::CompilationStateCallback
    : public CompilationEventCallback {
 public:
  explicit CompilationStateCallback(AsyncCompileJob* job) : job_(job) {}

  void call(CompilationEvent event) override {
    // This callback is only being called from a foreground task.
    switch (event) {
      case CompilationEvent::kFinishedBaselineCompilation:
        DCHECK(!last_event_.has_value());
        if (job_->DecrementAndCheckFinisherCount()) {
          // Install the native module in the cache, or reuse a conflicting one.
          // If we get a conflicting module, wait until we are back in the
          // main thread to update {job_->native_module_} to avoid a data race.
          std::shared_ptr<NativeModule> cached_native_module =
              GetWasmEngine()->UpdateNativeModuleCache(
                  false, job_->native_module_, job_->isolate_);
          if (cached_native_module == job_->native_module_) {
            // There was no cached module.
            cached_native_module = nullptr;
          }
          job_->DoSync<FinishCompilation>(std::move(cached_native_module));
        }
        break;
      case CompilationEvent::kFinishedCompilationChunk:
        DCHECK(CompilationEvent::kFinishedBaselineCompilation == last_event_ ||
               CompilationEvent::kFinishedCompilationChunk == last_event_);
        break;
      case CompilationEvent::kFailedCompilation:
        DCHECK(!last_event_.has_value());
        if (job_->DecrementAndCheckFinisherCount()) {
          // Don't update {job_->native_module_} to avoid data races with other
          // compilation threads. Use a copy of the shared pointer instead.
          GetWasmEngine()->UpdateNativeModuleCache(true, job_->native_module_,
                                                   job_->isolate_);
          job_->DoSync<Fail>();
        }
        break;
    }
#ifdef DEBUG
    last_event_ = event;
#endif
  }

 private:
  AsyncCompileJob* job_;
#ifdef DEBUG
  // This will be modified by different threads, but they externally
  // synchronize, so no explicit synchronization (currently) needed here.
  std::optional<CompilationEvent> last_event_;
#endif
};

// A closure to run a compilation step (either as foreground or background
// task) and schedule the next step(s), if any.
class AsyncCompileJob::CompileStep {
 public:
  virtual ~CompileStep() = default;

  void Run(AsyncCompileJob* job, bool on_foreground) {
    if (on_foreground) {
      HandleScope scope(job->isolate_);
      SaveAndSwitchContext saved_context(job->isolate_, *job->native_context_);
      RunInForeground(job);
    } else {
      RunInBackground(job);
    }
  }

  virtual void RunInForeground(AsyncCompileJob*) { UNREACHABLE(); }
  virtual void RunInBackground(AsyncCompileJob*) { UNREACHABLE(); }
};

class AsyncCompileJob::CompileTask : public CancelableTask {
 public:
  CompileTask(AsyncCompileJob* job, bool on_foreground)
      // We only manage the background tasks with the {CancelableTaskManager} of
      // the {AsyncCompileJob}. Foreground tasks are managed by the system's
      // {CancelableTaskManager}. Background tasks cannot spawn tasks managed by
      // their own task manager.
      : CancelableTask(on_foreground ? job->isolate_->cancelable_task_manager()
                                     : &job->background_task_manager_),
        job_(job),
        on_foreground_(on_foreground) {}

  ~CompileTask() override {
    if (job_ != nullptr && on_foreground_) ResetPendingForegroundTask();
  }

  void RunInternal() final {
    if (!job_) return;
    if (on_foreground_) ResetPendingForegroundTask();
    job_->step_->Run(job_, on_foreground_);
    // After execution, reset {job_} such that we don't try to reset the pending
    // foreground task when the task is deleted.
    job_ = nullptr;
  }

  void Cancel() {
    DCHECK_NOT_NULL(job_);
    job_ = nullptr;
  }

 private:
  // {job_} will be cleared to cancel a pending task.
  AsyncCompileJob* job_;
  bool on_foreground_;

  void ResetPendingForegroundTask() const {
    DCHECK_EQ(this, job_->pending_foreground_task_);
    job_->pending_foreground_task_ = nullptr;
  }
};

void AsyncCompileJob::StartForegroundTask() {
  DCHECK_NULL(pending_foreground_task_);

  auto new_task = std::make_unique<CompileTask>(this, true);
  pending_foreground_task_ = new_task.get();
  foreground_task_runner_->PostTask(std::move(new_task));
}

void AsyncCompileJob::ExecuteForegroundTaskImmediately() {
  DCHECK_NULL(pending_foreground_task_);

  auto new_task = std::make_unique<CompileTask>(this, true);
  pending_foreground_task_ = new_task.get();
  new_task->Run();
}

void AsyncCompileJob::CancelPendingForegroundTask() {
  if (!pending_foreground_task_) return;
  pending_foreground_task_->Cancel();
  pending_foreground_task_ = nullptr;
}

void AsyncCompileJob::StartBackgroundTask() {
  auto task = std::make_unique<CompileTask>(this, false);

  // If --wasm-num-compilation-tasks=0 is passed, do only spawn foreground
  // tasks. This is used to make timing deterministic.
  if (v8_flags.wasm_num_compilation_tasks > 0) {
    V8::GetCurrentPlatform()->CallBlockingTaskOnWorkerThread(std::move(task));
  } else {
    foreground_task_runner_->PostTask(std::move(task));
  }
}

template <typename Step,
          AsyncCompileJob::UseExistingForegroundTask use_existing_fg_task,
          typename... Args>
void AsyncCompileJob::DoSync(Args&&... args) {
  NextStep<Step>(std::forward<Args>(args)...);
  if (use_existing_fg_task && pending_foreground_task_ != nullptr) return;
  StartForegroundTask();
}

template <typename Step, typename... Args>
void AsyncCompileJob::DoImmediately(Args&&... args) {
  NextStep<Step>(std::forward<Args>(args)...);
  ExecuteForegroundTaskImmediately();
}

template <typename Step, typename... Args>
void AsyncCompileJob::DoAsync(Args&&... args) {
  NextStep<Step>(std::forward<Args>(args)...);
  StartBackgroundTask();
}

template <typename Step, typename... Args>
void AsyncCompileJob::NextStep(Args&&... args) {
  step_.reset(new Step(std::forward<Args>(args)...));
}

//==========================================================================
// Step 1: (async) Decode the module.
//==========================================================================
class AsyncCompileJob::DecodeModule : public AsyncCompileJob::CompileStep {
 public:
  explicit DecodeModule(Counters* counters,
                        std::shared_ptr<metrics::Recorder> metrics_recorder)
      : counters_(counters), metrics_recorder_(std::move(metrics_recorder)) {}

  void RunInBackground(AsyncCompileJob* job) override {
    ModuleResult result;
    {
      DisallowHandleAllocation no_handle;
      DisallowGarbageCollection no_gc;
      // Decode the module bytes.
      TRACE_COMPILE("(1) Decoding module...\n");
      TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.wasm.detailed"),
                   "wasm.DecodeModule");
      auto enabled_features = job->enabled_features_;
      result = DecodeWasmModule(
          enabled_features, job->wire_bytes_.module_bytes(), false, kWasmOrigin,
          counters_, metrics_recorder_, job->context_id(),
          DecodingMethod::kAsync, &job->detected_features_);

      // Validate lazy functions here if requested.
      if (result.ok() && !v8_flags.wasm_lazy_validation) {
        const WasmModule* module = result.value().get();
        if (WasmError validation_error = ValidateFunctions(
                module, job->wire_bytes_.module_bytes(), job->enabled_features_,
                kOnlyLazyFunctions, &job->detected_features_)) {
          result = ModuleResult{std::move(validation_error)};
        }
      }
      if (result.ok()) {
        const WasmModule* module = result.value().get();
        if (WasmError error = ValidateAndSetBuiltinImports(
                module, job->wire_bytes_.module_bytes(), job->compile_imports_,
                &job->detected_features_)) {
          result = ModuleResult{std::move(error)};
        }
      }
    }
    if (result.failed()) {
      // Decoding failure; reject the promise and clean up.
      job->DoSync<Fail>();
    } else {
      // Decode passed.
      std::shared_ptr<WasmModule> module = std::move(result).value();
      const bool include_liftoff = v8_flags.liftoff;
      size_t code_size_estimate =
          wasm::WasmCodeManager::EstimateNativeModuleCodeSize(
              module.get(), include_liftoff, job->dynamic_tiering_);
      job->DoSync<PrepareAndStartCompile>(
          std::move(module), true /* start_compilation */,
          true /* lazy_functions_are_validated */, code_size_estimate);
    }
  }

 private:
  Counters* const counters_;
  std::shared_ptr<metrics::Recorder> metrics_recorder_;
};

//==========================================================================
// Step 2 (sync): Create heap-allocated data and start compilation.
//==========================================================================
class AsyncCompileJob::PrepareAndStartCompile : public CompileStep {
 public:
  PrepareAndStartCompile(std::shared_ptr<const WasmModule> module,
                         bool start_compilation,
                         bool lazy_functions_are_validated,
                         size_t code_size_estimate)
      : module_(std::move(module)),
        start_compilation_(start_compilation),
        lazy_functions_are_validated_(lazy_functions_are_validated),
        code_size_estimate_(code_size_estimate) {}

 private:
  void RunInForeground(AsyncCompileJob* job) override {
    TRACE_COMPILE("(2) Prepare and start compile...\n");

    const bool streaming = job->wire_bytes_.length() == 0;
    if (streaming) {
      // Streaming compilation already checked for cache hits.
      job->CreateNativeModule(module_, code_size_estimate_);
    } else if (job->GetOrCreateNativeModule(std::move(module_),
                                            code_size_estimate_)) {
      job->FinishCompile(true);
      return;
    } else if (!lazy_functions_are_validated_) {
      // If we are not streaming and did not get a cache hit, we might have hit
      // the path where the streaming decoder got a prefix cache hit, but the
      // module then turned out to be invalid, and we are running it through
      // non-streaming decoding again. In this case, function bodies have not
      // been validated yet (would have happened in the {DecodeModule} phase
      // if we would not come via the non-streaming path). Thus do this now.
      // Note that we only need to validate lazily compiled functions, others
      // will be validated during eager compilation.
      DCHECK(start_compilation_);
      if (!v8_flags.wasm_lazy_validation &&
          ValidateFunctions(*job->native_module_, kOnlyLazyFunctions)
              .has_error()) {
        job->Failed();
        return;
      }
    }

    // Make sure all compilation tasks stopped running. Decoding (async step)
    // is done.
    job->background_task_manager_.CancelAndWait();

    CompilationStateImpl* compilation_state =
        Impl(job->native_module_->compilation_state());
    compilation_state->AddCallback(
        std::make_unique<CompilationStateCallback>(job));
    if (base::TimeTicks::IsHighResolution()) {
      auto compile_mode = job->stream_ == nullptr
                              ? CompilationTimeCallback::kAsync
                              : CompilationTimeCallback::kStreaming;
      compilation_state->AddCallback(std::make_unique<CompilationTimeCallback>(
          job->isolate_->async_counters(), job->isolate_->metrics_recorder(),
          job->context_id_, job->native_module_, compile_mode));
    }

    if (start_compilation_) {
      // TODO(13209): Use PGO for async compilation, if available.
      constexpr ProfileInformation* kNoProfileInformation = nullptr;
      std::unique_ptr<CompilationUnitBuilder> builder = InitializeCompilation(
          job->isolate(), job->native_module_.get(), kNoProfileInformation);
      compilation_state->InitializeCompilationUnits(std::move(builder));
      // In single-threaded mode there are no worker tasks that will do the
      // compilation. We call {WaitForCompilationEvent} here so that the main
      // thread participates and finishes the compilation.
      if (v8_flags.wasm_num_compilation_tasks == 0 || v8_flags.wasm_jitless) {
        compilation_state->WaitForCompilationEvent(
            CompilationEvent::kFinishedBaselineCompilation);
      }
    }
  }

  const std::shared_ptr<const WasmModule> module_;
  const bool start_compilation_;
  const bool lazy_functions_are_validated_;
  const size_t code_size_estimate_;
};

//==========================================================================
// Step 3 (sync): Compilation finished.
//==========================================================================
class AsyncCompileJob::FinishCompilation : public CompileStep {
 public:
  explicit FinishCompilation(std::shared_ptr<NativeModule> cached_native_module)
      : cached_native_module_(std::move(cached_native_module)) {}

 private:
  void RunInForeground(AsyncCompileJob* job) override {
    TRACE_COMPILE("(3) Compilation finished\n");
    if
```