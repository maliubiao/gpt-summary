Response: The user wants me to summarize the functionality of the C++ code provided, which is the third part of a file named `module-compiler.cc`. I should also explain its relation to JavaScript and provide a JavaScript example if applicable.

Based on the code snippets, I can see these key components:

1. **`AsyncCompileJob`**: This class seems to manage the asynchronous compilation process of a WebAssembly module. It has different states (`Start`, `PrepareAndStartCompile`, `Finalize`, `Fail`) represented by inner classes. It also handles caching of compiled modules.
2. **`AsyncStreamingProcessor`**: This class handles the streaming compilation of a WebAssembly module. It processes the module header, sections, and function bodies incrementally. It interacts with the `AsyncCompileJob` to trigger compilation steps and manage the compilation process. It also deals with a prefix cache for optimization.
3. **`CompilationStateImpl`**: This class manages the compilation state of a WebAssembly module, including tracking compilation progress for different tiers (Baseline, TopTier), managing compilation units, handling callbacks for compilation events, and managing background compilation jobs. It also seems to handle applying PGO (Profile-Guided Optimization) information.
4. **Background Compilation**: The code mentions `BackgroundCompileJob`, indicating that compilation is performed on background threads.
5. **Caching**:  The code extensively talks about caching (`cached_native_module_`, `NativeModuleCache`, `prefix_cache_hit_`), suggesting that the compiler attempts to reuse previously compiled modules to improve performance.
6. **Tiering**: The presence of "Baseline" and "TopTier" compilation suggests tiered compilation, where a module is initially compiled with a faster but less optimized compiler (Baseline) and later recompiled with a more optimizing compiler (TopTier).
7. **Lazy Compilation/Validation**: The code mentions flags like `v8_flags.wasm_lazy_compilation` and `v8_flags.wasm_lazy_validation`, suggesting support for delaying the compilation or validation of function bodies until they are needed.
8. **PGO**: The code mentions "ProfileInformation" and applying PGO information, indicating support for optimizing the compiled code based on runtime profiles.
9. **Callbacks**: The `CompilationStateImpl` uses callbacks to notify when different compilation events occur (e.g., baseline compilation finished, compilation failed).

**Relationship to JavaScript**:

The functionalities described in this code directly support the execution of WebAssembly modules within a JavaScript environment. When JavaScript code attempts to load and instantiate a WebAssembly module (using the `WebAssembly` API), the V8 engine utilizes components like these to compile the WebAssembly bytecode into native machine code. The asynchronous and streaming aspects allow the compilation to happen in the background, preventing blocking of the main JavaScript thread. Caching ensures that subsequent loads of the same module are faster. Tiered compilation allows for quick initial execution and later optimization.

**JavaScript Example**:

A simple JavaScript example demonstrating the interaction would be the loading and instantiation of a WebAssembly module:

```javascript
async function loadWasmModule(url) {
  const response = await fetch(url);
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer); // This triggers the compilation process in C++
  const instance = await WebAssembly.instantiate(module);
  return instance;
}

loadWasmModule('./my_wasm_module.wasm').then(instance => {
  // Use the WebAssembly instance
  console.log(instance.exports.add(5, 3));
});
```

In this example, the `WebAssembly.compile(buffer)` call in JavaScript initiates the WebAssembly compilation process. The C++ code in `module-compiler.cc` (including the parts in this file) handles the actual compilation, potentially using asynchronous compilation, streaming, caching, and tiered compilation as described in the provided C++ code. The `WebAssembly.instantiate(module)` call might trigger the finalization steps after compilation is complete.
这是 `v8/src/wasm/module-compiler.cc` 文件的第三部分代码，它主要负责 **WebAssembly 模块的异步编译和流式编译的后处理以及模块编译状态的管理**。

具体来说，这部分代码涵盖了以下功能：

**1. 异步编译任务的最终阶段 (AsyncCompileJob)**：

*   **`AsyncCompileJob::Finalize`**:  在异步编译成功后，这个步骤负责最终确定并发布生成的模块。如果之前有缓存的本地模块，则会直接使用缓存。
*   **`AsyncCompileJob::Fail`**:  处理异步编译失败的情况。

**2. 异步编译成功的后续处理 (AsyncCompileJob::FinishSuccessfully)**：

*   在编译成功后，通知 `resolver_` （通常是 JavaScript Promise 的 resolver），并将生成的 `module_object_` 传递给它，从而让 JavaScript 代码可以访问编译后的模块。
*   从 `WasmEngine` 中移除当前的编译任务。

**3. 异步流式处理器的实现 (AsyncStreamingProcessor)**：

*   **`AsyncStreamingProcessor` 构造函数**: 初始化解码器和其他必要的成员变量。
*   **`ProcessModuleHeader`**: 处理模块的头部信息。
*   **`ProcessSection`**: 处理模块的各个 section，除了 code section。它会累积 section 的哈希值，用于后续的缓存查找。
*   **`ProcessCodeSectionHeader`**:  开始处理 code section。它会检查函数数量，并根据是否命中前缀缓存来决定是否立即开始编译。如果未命中缓存，则会触发 `AsyncCompileJob::PrepareAndStartCompile` 来开始编译。
*   **`ProcessFunctionBody`**: 处理单个函数体。如果命中了前缀缓存，则仅进行解码，不进行编译。否则，会将函数体添加到编译任务中。它还包含了对函数体进行后台验证的逻辑（如果 `wasm_lazy_validation` 启用）。
*   **`CommitCompilationUnits`**:  提交累积的编译单元。
*   **`OnFinishedChunk`**: 在接收到一个数据块后执行的操作，通常会提交编译单元。
*   **`OnFinishedStream`**:  当整个流式数据处理完毕后执行的操作。
    *   它会完成解码，检查是否有错误。
    *   如果启用了后台验证，则会等待验证完成并检查是否有错误。
    *   它会记录编译相关的性能指标。
    *   如果发生错误，会清理缓存并调用 `job_->Failed()`。
    *   如果没有错误，则会检查是否命中了前缀缓存。
        *   如果命中了，则会重新开始一个同步的、非流式的编译过程，期望从缓存中获取模块。
        *   如果没有命中，则会创建本地模块（如果 code section 不存在），并调用 `job_->FinishCompile()` 完成编译。
*   **`OnAbort`**: 处理流式处理被中止的情况，会取消后台验证任务并清理缓存。
*   **`Deserialize`**:  处理模块反序列化的情况，直接从字节流创建模块对象。

**4. 模块编译状态的管理 (CompilationStateImpl)**：

*   **`CompilationStateImpl` 构造函数**: 初始化编译状态。
*   **`InitCompileJob`**: 初始化后台编译任务（Baseline 和 TopTier）。
*   **`CancelCompilation`**: 取消编译过程。
*   **`cancelled`**: 查询编译是否被取消。
*   **`ApplyCompilationHintToInitialProgress`**:  应用编译提示来调整初始的编译进度。
*   **`ApplyPgoInfoToInitialProgress` 和 `ApplyPgoInfoLate`**:  应用 PGO (Profile-Guided Optimization) 信息来指导编译。
*   **`InitializeCompilationProgress`**: 初始化模块的编译进度，包括根据编译提示和 PGO 信息设置每个函数的初始编译状态。
*   **`AddCompilationUnitInternal`**: 将一个函数添加到相应的编译队列中。
*   **`InitializeCompilationUnits`**: 根据当前的编译进度，初始化所有的编译单元。
*   **`AddCompilationUnit`**: 添加一个编译单元。
*   **`InitializeCompilationProgressAfterDeserialization`**: 在反序列化后初始化编译进度，区分懒加载和急加载的函数。
*   **`AddCallback`**: 添加编译事件的回调函数。
*   **`CommitCompilationUnits`**: 提交编译单元到后台编译任务。
*   **`CommitTopTierCompilationUnit` 和 `AddTopTierPriorityCompilationUnit`**:  提交 TopTier 编译单元。
*   **`GetQueueForCompileTask` 和 `GetNextCompilationUnit`**:  获取编译任务队列和下一个编译单元。
*   **`OnFinishedUnits`**: 当一部分编译单元完成后被调用，更新编译进度并触发相应的回调。
*   **`TriggerOutstandingCallbacks` 和 `TriggerCallbacks`**: 检查并触发待处理的回调函数。
*   **`TriggerCachingAfterTimeout`**:  在一个延迟后触发代码缓存。
*   **`OnCompilationStopped`**:  当编译停止时被调用，用于处理一些编译完成后的操作。
*   **`UpdateDetectedFeatures`**: 更新检测到的 WebAssembly 特性。
*   **`PublishCompilationResults` 和 `PublishCode`**:  发布编译结果。
*   **`SchedulePublishCompilationResults`**: 调度发布编译结果的操作。
*   **`NumOutstandingCompilations`**:  获取待处理的编译单元数量。
*   **`SetError`**:  设置编译错误状态。
*   **`WaitForCompilationEvent`**:  等待特定的编译事件完成。
*   **`TierUpAllFunctions`**:  将所有函数都升级到 TopTier 编译。
*   **`CompileImportWrapperForTest`**:  为测试编译 import wrapper。

**与 JavaScript 的功能关系**：

这段 C++ 代码是 V8 引擎中负责将 WebAssembly 字节码编译成可执行机器码的核心部分。当 JavaScript 代码使用 `WebAssembly.compile()` 或 `WebAssembly.instantiateStreaming()` 加载和实例化 WebAssembly 模块时，V8 引擎内部会调用这些 C++ 代码来完成编译过程。

*   **`WebAssembly.compile()`**:  可能会触发 `AsyncCompileJob` 的同步或异步编译流程。
*   **`WebAssembly.instantiateStreaming()`**: 会使用 `AsyncStreamingProcessor` 来进行流式编译，允许在模块下载完成之前就开始编译。
*   **编译优化**:  `CompilationStateImpl` 中处理的编译提示和 PGO 信息都是为了更好地优化生成的机器码，提高 WebAssembly 模块的执行效率，这最终会影响 JavaScript 中调用 WebAssembly 函数的性能。
*   **异步性**:  异步编译保证了编译过程不会阻塞 JavaScript 的主线程，提高了用户体验。
*   **缓存**: 缓存机制使得重复加载相同的 WebAssembly 模块变得更快，这对于经常使用的模块非常重要。
*   **分层编译 (Tiered Compilation)**：通过 Baseline 和 TopTier 编译，可以先快速生成可执行代码，然后逐步优化，平衡了启动速度和峰值性能。

**JavaScript 示例**：

```javascript
// 假设 my_module.wasm 是一个 WebAssembly 文件

// 使用 fetch 获取 wasm 模块
fetch('my_module.wasm')
  .then(response => response.arrayBuffer())
  .then(buffer => {
    // 使用 WebAssembly.compile 进行编译 (可能触发 AsyncCompileJob)
    return WebAssembly.compile(buffer);
  })
  .then(module => {
    // 使用 WebAssembly.instantiate 实例化模块
    const instance = WebAssembly.instantiate(module);
    return instance;
  })
  .then(instance => {
    // 调用 wasm 导出的函数
    const result = instance.exports.add(5, 3);
    console.log(result); // 输出 8
  });

// 使用流式编译加载和实例化 wasm 模块 (触发 AsyncStreamingProcessor)
WebAssembly.instantiateStreaming(fetch('my_module.wasm'))
  .then(result => {
    // 调用 wasm 导出的函数
    const result = result.instance.exports.add(10, 2);
    console.log(result); // 输出 12
  });
```

在这个 JavaScript 示例中，`WebAssembly.compile()` 和 `WebAssembly.instantiateStreaming()` 的底层实现会调用这段 C++ 代码来完成 WebAssembly 模块的编译和实例化过程。`CompilationStateImpl` 负责管理编译的状态，确保编译的顺利进行。

Prompt: 
```
这是目录为v8/src/wasm/module-compiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
 (cached_native_module_) {
      job->native_module_ = cached_native_module_;
    }
    // Then finalize and publish the generated module.
    job->FinishCompile(cached_native_module_ != nullptr);
  }

  std::shared_ptr<NativeModule> cached_native_module_;
};

//==========================================================================
// Step 4 (sync): Decoding or compilation failed.
//==========================================================================
class AsyncCompileJob::Fail : public CompileStep {
 private:
  void RunInForeground(AsyncCompileJob* job) override {
    TRACE_COMPILE("(4) Async compilation failed.\n");
    // {job_} is deleted in {Failed}, therefore the {return}.
    return job->Failed();
  }
};

void AsyncCompileJob::FinishSuccessfully() {
  TRACE_COMPILE("(4) Finish module...\n");
  {
    TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.wasm.detailed"),
                 "wasm.OnCompilationSucceeded");
    // We have to make sure that an "incumbent context" is available in case
    // the module's start function calls out to Blink.
    Local<v8::Context> backup_incumbent_context =
        Utils::ToLocal(incumbent_context_);
    v8::Context::BackupIncumbentScope incumbent(backup_incumbent_context);
    resolver_->OnCompilationSucceeded(module_object_);
  }
  GetWasmEngine()->RemoveCompileJob(this);
}

AsyncStreamingProcessor::AsyncStreamingProcessor(AsyncCompileJob* job)
    : decoder_(job->enabled_features_, &job->detected_features_),
      job_(job),
      compilation_unit_builder_(nullptr) {}

// Process the module header.
bool AsyncStreamingProcessor::ProcessModuleHeader(
    base::Vector<const uint8_t> bytes) {
  TRACE_STREAMING("Process module header...\n");
  decoder_.DecodeModuleHeader(bytes);
  if (!decoder_.ok()) return false;
  prefix_hash_ = GetWireBytesHash(bytes);
  return true;
}

// Process all sections except for the code section.
bool AsyncStreamingProcessor::ProcessSection(SectionCode section_code,
                                             base::Vector<const uint8_t> bytes,
                                             uint32_t offset) {
  TRACE_STREAMING("Process section %d ...\n", section_code);
  if (compilation_unit_builder_) {
    // We reached a section after the code section, we do not need the
    // compilation_unit_builder_ anymore.
    CommitCompilationUnits();
    compilation_unit_builder_.reset();
  }
  if (before_code_section_) {
    // Combine section hashes until code section.
    prefix_hash_ = base::hash_combine(prefix_hash_, GetWireBytesHash(bytes));
  }
  if (section_code == SectionCode::kUnknownSectionCode) {
    size_t bytes_consumed = ModuleDecoder::IdentifyUnknownSection(
        &decoder_, bytes, offset, &section_code);
    if (!decoder_.ok()) return false;
    if (section_code == SectionCode::kUnknownSectionCode) {
      // Skip unknown sections that we do not know how to handle.
      return true;
    }
    // Remove the unknown section tag from the payload bytes.
    offset += bytes_consumed;
    bytes = bytes.SubVector(bytes_consumed, bytes.size());
  }
  decoder_.DecodeSection(section_code, bytes, offset);
  return decoder_.ok();
}

// Start the code section.
bool AsyncStreamingProcessor::ProcessCodeSectionHeader(
    int num_functions, uint32_t functions_mismatch_error_offset,
    std::shared_ptr<WireBytesStorage> wire_bytes_storage,
    int code_section_start, int code_section_length) {
  DCHECK_LE(0, code_section_length);
  before_code_section_ = false;
  TRACE_STREAMING("Start the code section with %d functions...\n",
                  num_functions);
  prefix_hash_ = base::hash_combine(prefix_hash_,
                                    static_cast<uint32_t>(code_section_length));
  if (!decoder_.CheckFunctionsCount(static_cast<uint32_t>(num_functions),
                                    functions_mismatch_error_offset)) {
    return false;
  }

  decoder_.StartCodeSection({static_cast<uint32_t>(code_section_start),
                             static_cast<uint32_t>(code_section_length)});

  if (!GetWasmEngine()->GetStreamingCompilationOwnership(
          prefix_hash_, job_->compile_imports_)) {
    // Known prefix, wait until the end of the stream and check the cache.
    prefix_cache_hit_ = true;
    return true;
  }

  // Execute the PrepareAndStartCompile step immediately and not in a separate
  // task.
  int num_imported_functions =
      static_cast<int>(decoder_.module()->num_imported_functions);
  DCHECK_EQ(kWasmOrigin, decoder_.module()->origin);
  const bool include_liftoff = v8_flags.liftoff;
  size_t code_size_estimate =
      wasm::WasmCodeManager::EstimateNativeModuleCodeSize(
          num_functions, num_imported_functions, code_section_length,
          include_liftoff, job_->dynamic_tiering_);
  job_->DoImmediately<AsyncCompileJob::PrepareAndStartCompile>(
      decoder_.shared_module(),
      // start_compilation: false; triggered when we receive the bodies.
      false,
      // lazy_functions_are_validated: false (bodies not received yet).
      false, code_size_estimate);

  auto* compilation_state = Impl(job_->native_module_->compilation_state());
  compilation_state->SetWireBytesStorage(std::move(wire_bytes_storage));
  DCHECK_EQ(job_->native_module_->module()->origin, kWasmOrigin);

  // Set outstanding_finishers_ to 2, because both the AsyncCompileJob and the
  // AsyncStreamingProcessor have to finish.
  job_->outstanding_finishers_.store(2);
  // TODO(13209): Use PGO for streaming compilation, if available.
  constexpr ProfileInformation* kNoProfileInformation = nullptr;
  compilation_unit_builder_ = InitializeCompilation(
      job_->isolate(), job_->native_module_.get(), kNoProfileInformation);
  return true;
}

// Process a function body.
bool AsyncStreamingProcessor::ProcessFunctionBody(
    base::Vector<const uint8_t> bytes, uint32_t offset) {
  TRACE_STREAMING("Process function body %d ...\n", num_functions_);
  uint32_t func_index =
      decoder_.module()->num_imported_functions + num_functions_;
  ++num_functions_;
  // In case of {prefix_cache_hit} we still need the function body to be
  // decoded. Otherwise a later cache miss cannot be handled.
  decoder_.DecodeFunctionBody(func_index, static_cast<uint32_t>(bytes.length()),
                              offset);

  if (prefix_cache_hit_) {
    // Don't compile yet if we might have a cache hit.
    return true;
  }

  const WasmModule* module = decoder_.module();
  auto enabled_features = job_->enabled_features_;
  DCHECK_EQ(module->origin, kWasmOrigin);
  const bool lazy_module = v8_flags.wasm_lazy_compilation;
  CompileStrategy strategy =
      GetCompileStrategy(module, enabled_features, func_index, lazy_module);
  CHECK_IMPLIES(v8_flags.wasm_jitless, !v8_flags.wasm_lazy_validation);
  bool validate_lazily_compiled_function =
      v8_flags.wasm_jitless ||
      (!v8_flags.wasm_lazy_validation &&
       (strategy == CompileStrategy::kLazy ||
        strategy == CompileStrategy::kLazyBaselineEagerTopTier));
  if (validate_lazily_compiled_function) {
    // {bytes} is part of a section buffer owned by the streaming decoder. The
    // streaming decoder is held alive by the {AsyncCompileJob}, so we can just
    // use the {bytes} vector as long as the {AsyncCompileJob} is still running.
    if (!validate_functions_job_handle_) {
      validate_functions_job_data_.Initialize(module->num_declared_functions);
      validate_functions_job_handle_ = V8::GetCurrentPlatform()->CreateJob(
          TaskPriority::kUserVisible,
          std::make_unique<ValidateFunctionsStreamingJob>(
              module, enabled_features, &validate_functions_job_data_));
    }
    validate_functions_job_data_.AddUnit(func_index, bytes,
                                         validate_functions_job_handle_.get());
  }

  auto* compilation_state = Impl(job_->native_module_->compilation_state());
  compilation_state->AddCompilationUnit(compilation_unit_builder_.get(),
                                        func_index);
  return true;
}

void AsyncStreamingProcessor::CommitCompilationUnits() {
  DCHECK(compilation_unit_builder_);
  compilation_unit_builder_->Commit();
}

void AsyncStreamingProcessor::OnFinishedChunk() {
  TRACE_STREAMING("FinishChunk...\n");
  if (compilation_unit_builder_) CommitCompilationUnits();
}

// Finish the processing of the stream.
void AsyncStreamingProcessor::OnFinishedStream(
    base::OwnedVector<const uint8_t> bytes, bool after_error) {
  TRACE_STREAMING("Finish stream...\n");
  ModuleResult module_result = decoder_.FinishDecoding();
  if (module_result.failed()) after_error = true;

  if (validate_functions_job_handle_) {
    // Wait for background validation to finish, then check if a validation
    // error was found.
    // TODO(13447): Do not block here; register validation as another finisher
    // instead.
    validate_functions_job_handle_->Join();
    validate_functions_job_handle_.reset();
    if (validate_functions_job_data_.found_error) after_error = true;
    job_->detected_features_ |=
        validate_functions_job_data_.detected_features.load(
            std::memory_order_relaxed);
  }

  job_->wire_bytes_ = ModuleWireBytes(bytes.as_vector());
  job_->bytes_copy_ = std::move(bytes);

  if (!after_error) {
    WasmDetectedFeatures detected_imports_features;
    if (WasmError error = ValidateAndSetBuiltinImports(
            module_result.value().get(), job_->wire_bytes_.module_bytes(),
            job_->compile_imports_, &detected_imports_features)) {
      after_error = true;
    } else {
      job_->detected_features_ |= detected_imports_features;
    }
  }

  // Record event metrics.
  auto duration = base::TimeTicks::Now() - job_->start_time_;
  job_->metrics_event_.success = !after_error;
  job_->metrics_event_.streamed = true;
  job_->metrics_event_.module_size_in_bytes = job_->wire_bytes_.length();
  job_->metrics_event_.function_count = num_functions_;
  job_->metrics_event_.wall_clock_duration_in_us = duration.InMicroseconds();
  job_->isolate_->metrics_recorder()->DelayMainThreadEvent(job_->metrics_event_,
                                                           job_->context_id_);

  if (after_error) {
    if (job_->native_module_ && job_->native_module_->wire_bytes().empty()) {
      // Clean up the temporary cache entry.
      GetWasmEngine()->StreamingCompilationFailed(prefix_hash_,
                                                  job_->compile_imports_);
    }
    // Calling {Failed} will invalidate the {AsyncCompileJob} and delete {this}.
    job_->Failed();
    return;
  }

  std::shared_ptr<WasmModule> module = std::move(module_result).value();

  // At this point we identified the module as valid (except maybe for function
  // bodies, if lazy validation is enabled).
  // This DCHECK could be considered slow, but it only happens once per async
  // module compilation, and we only re-decode the module structure, without
  // validating function bodies. Overall this does not add a lot of overhead.
#ifdef DEBUG
  WasmDetectedFeatures detected_module_features;
  DCHECK(DecodeWasmModule(job_->enabled_features_,
                          job_->bytes_copy_.as_vector(),
                          /* validate functions */ false, kWasmOrigin,
                          &detected_module_features)
             .ok());
  // Module decoding should not detect any new features.
  DCHECK(job_->detected_features_.contains_all(detected_module_features));
#endif

  DCHECK_EQ(NativeModuleCache::PrefixHash(job_->wire_bytes_.module_bytes()),
            prefix_hash_);
  if (prefix_cache_hit_) {
    // Restart as an asynchronous, non-streaming compilation. Most likely
    // {PrepareAndStartCompile} will get the native module from the cache.
    const bool include_liftoff = v8_flags.liftoff;
    size_t code_size_estimate =
        wasm::WasmCodeManager::EstimateNativeModuleCodeSize(
            module.get(), include_liftoff, job_->dynamic_tiering_);
    job_->DoSync<AsyncCompileJob::PrepareAndStartCompile>(
        std::move(module), true /* start_compilation */,
        false /* lazy_functions_are_validated_ */, code_size_estimate);
    return;
  }

  // We have to open a HandleScope and prepare the Context for
  // CreateNativeModule, PrepareRuntimeObjects and FinishCompile as this is a
  // callback from the embedder.
  HandleScope scope(job_->isolate_);
  SaveAndSwitchContext saved_context(job_->isolate_, *job_->native_context_);

  // Record the size of the wire bytes and the number of functions. In
  // synchronous and asynchronous (non-streaming) compilation, this happens in
  // {DecodeWasmModule}.
  auto* module_size_histogram =
      job_->isolate_->counters()->wasm_wasm_module_size_bytes();
  module_size_histogram->AddSample(job_->wire_bytes_.module_bytes().length());
  auto* num_functions_histogram =
      job_->isolate_->counters()->wasm_functions_per_wasm_module();
  num_functions_histogram->AddSample(static_cast<int>(num_functions_));

  const bool has_code_section = job_->native_module_ != nullptr;
  bool cache_hit = false;
  if (!has_code_section) {
    // We are processing a WebAssembly module without code section. Create the
    // native module now (would otherwise happen in {PrepareAndStartCompile} or
    // {ProcessCodeSectionHeader}).
    constexpr size_t kCodeSizeEstimate = 0;
    cache_hit =
        job_->GetOrCreateNativeModule(std::move(module), kCodeSizeEstimate);
  } else {
    job_->native_module_->SetWireBytes(std::move(job_->bytes_copy_));
  }
  const bool needs_finish = job_->DecrementAndCheckFinisherCount();
  DCHECK_IMPLIES(!has_code_section, needs_finish);
  if (needs_finish) {
    const bool failed = job_->native_module_->compilation_state()->failed();
    if (!cache_hit) {
      auto* prev_native_module = job_->native_module_.get();
      job_->native_module_ = GetWasmEngine()->UpdateNativeModuleCache(
          failed, std::move(job_->native_module_), job_->isolate_);
      cache_hit = prev_native_module != job_->native_module_.get();
    }
    // We finally call {Failed} or {FinishCompile}, which will invalidate the
    // {AsyncCompileJob} and delete {this}.
    if (failed) {
      job_->Failed();
    } else {
      job_->FinishCompile(cache_hit);
    }
  }
}

void AsyncStreamingProcessor::OnAbort() {
  TRACE_STREAMING("Abort stream...\n");
  if (validate_functions_job_handle_) {
    validate_functions_job_handle_->Cancel();
    validate_functions_job_handle_.reset();
  }
  if (job_->native_module_ && job_->native_module_->wire_bytes().empty()) {
    // Clean up the temporary cache entry.
    GetWasmEngine()->StreamingCompilationFailed(prefix_hash_,
                                                job_->compile_imports_);
  }
  // {Abort} invalidates the {AsyncCompileJob}, which in turn deletes {this}.
  job_->Abort();
}

bool AsyncStreamingProcessor::Deserialize(
    base::Vector<const uint8_t> module_bytes,
    base::Vector<const uint8_t> wire_bytes) {
  TRACE_EVENT0("v8.wasm", "wasm.Deserialize");
  std::optional<TimedHistogramScope> time_scope;
  if (base::TimeTicks::IsHighResolution()) {
    time_scope.emplace(job_->isolate()->counters()->wasm_deserialization_time(),
                       job_->isolate());
  }
  // DeserializeNativeModule and FinishCompile assume that they are executed in
  // a HandleScope, and that a context is set on the isolate.
  HandleScope scope(job_->isolate_);
  SaveAndSwitchContext saved_context(job_->isolate_, *job_->native_context_);

  MaybeHandle<WasmModuleObject> result = DeserializeNativeModule(
      job_->isolate_, module_bytes, wire_bytes, job_->compile_imports_,
      base::VectorOf(job_->stream_->url()));

  if (result.is_null()) return false;

  job_->module_object_ =
      job_->isolate_->global_handles()->Create(*result.ToHandleChecked());
  job_->native_module_ = job_->module_object_->shared_native_module();
  job_->wire_bytes_ = ModuleWireBytes(job_->native_module_->wire_bytes());
  // Calling {FinishCompile} deletes the {AsyncCompileJob} and {this}.
  job_->FinishCompile(false);
  return true;
}

CompilationStateImpl::CompilationStateImpl(
    const std::shared_ptr<NativeModule>& native_module,
    std::shared_ptr<Counters> async_counters, DynamicTiering dynamic_tiering,
    WasmDetectedFeatures detected_features)
    : native_module_(native_module.get()),
      native_module_weak_(std::move(native_module)),
      async_counters_(std::move(async_counters)),
      compilation_unit_queues_(native_module->num_functions()),
      dynamic_tiering_(dynamic_tiering),
      detected_features_(detected_features) {}

void CompilationStateImpl::InitCompileJob() {
  DCHECK_NULL(baseline_compile_job_);
  DCHECK_NULL(top_tier_compile_job_);
  // Create the job, but don't spawn workers yet. This will happen on
  // {NotifyConcurrencyIncrease}.
  baseline_compile_job_ = V8::GetCurrentPlatform()->CreateJob(
      TaskPriority::kUserVisible,
      std::make_unique<BackgroundCompileJob>(
          native_module_weak_, async_counters_, CompilationTier::kBaseline));
  top_tier_compile_job_ = V8::GetCurrentPlatform()->CreateJob(
      TaskPriority::kUserVisible,
      std::make_unique<BackgroundCompileJob>(
          native_module_weak_, async_counters_, CompilationTier::kTopTier));
}

void CompilationStateImpl::CancelCompilation(
    CompilationStateImpl::CancellationPolicy cancellation_policy) {
  base::MutexGuard callbacks_guard(&callbacks_mutex_);

  if (cancellation_policy == kCancelInitialCompilation &&
      finished_events_.contains(
          CompilationEvent::kFinishedBaselineCompilation)) {
    // Initial compilation already finished; cannot be cancelled.
    return;
  }

  // std::memory_order_relaxed is sufficient because no other state is
  // synchronized with |compile_cancelled_|.
  compile_cancelled_.store(true, std::memory_order_relaxed);

  // No more callbacks after abort.
  callbacks_.clear();
}

bool CompilationStateImpl::cancelled() const {
  return compile_cancelled_.load(std::memory_order_relaxed);
}

void CompilationStateImpl::ApplyCompilationHintToInitialProgress(
    const WasmCompilationHint& hint, size_t hint_idx) {
  // Get old information.
  uint8_t& progress = compilation_progress_[hint_idx];
  ExecutionTier old_baseline_tier = RequiredBaselineTierField::decode(progress);
  ExecutionTier old_top_tier = RequiredTopTierField::decode(progress);

  // Compute new information.
  ExecutionTier new_baseline_tier =
      ApplyHintToExecutionTier(hint.baseline_tier, old_baseline_tier);
  ExecutionTier new_top_tier =
      ApplyHintToExecutionTier(hint.top_tier, old_top_tier);
  switch (hint.strategy) {
    case WasmCompilationHintStrategy::kDefault:
      // Be careful not to switch from lazy to non-lazy.
      if (old_baseline_tier == ExecutionTier::kNone) {
        new_baseline_tier = ExecutionTier::kNone;
      }
      if (old_top_tier == ExecutionTier::kNone) {
        new_top_tier = ExecutionTier::kNone;
      }
      break;
    case WasmCompilationHintStrategy::kLazy:
      new_baseline_tier = ExecutionTier::kNone;
      new_top_tier = ExecutionTier::kNone;
      break;
    case WasmCompilationHintStrategy::kEager:
      // Nothing to do, use the encoded (new) tiers.
      break;
    case WasmCompilationHintStrategy::kLazyBaselineEagerTopTier:
      new_baseline_tier = ExecutionTier::kNone;
      break;
  }

  progress = RequiredBaselineTierField::update(progress, new_baseline_tier);
  progress = RequiredTopTierField::update(progress, new_top_tier);

  // Update counter for outstanding baseline units.
  outstanding_baseline_units_ += (new_baseline_tier != ExecutionTier::kNone) -
                                 (old_baseline_tier != ExecutionTier::kNone);
}

void CompilationStateImpl::ApplyPgoInfoToInitialProgress(
    ProfileInformation* pgo_info) {
  // Functions that were executed in the profiling run are eagerly compiled to
  // Liftoff.
  const WasmModule* module = native_module_->module();
  for (int func_index : pgo_info->executed_functions()) {
    uint8_t& progress =
        compilation_progress_[declared_function_index(module, func_index)];
    ExecutionTier old_baseline_tier =
        RequiredBaselineTierField::decode(progress);
    // If the function is already marked for eager compilation, we are good.
    if (old_baseline_tier != ExecutionTier::kNone) continue;

    // Set the baseline tier to Liftoff, so we eagerly compile to Liftoff.
    // TODO(13288): Compile Liftoff code in the background, if lazy compilation
    // is enabled.
    progress =
        RequiredBaselineTierField::update(progress, ExecutionTier::kLiftoff);
    ++outstanding_baseline_units_;
  }

  // Functions that were tiered up during PGO generation are eagerly compiled to
  // TurboFan (in the background, not blocking instantiation).
  for (int func_index : pgo_info->tiered_up_functions()) {
    uint8_t& progress =
        compilation_progress_[declared_function_index(module, func_index)];
    ExecutionTier old_baseline_tier =
        RequiredBaselineTierField::decode(progress);
    ExecutionTier old_top_tier = RequiredTopTierField::decode(progress);
    // If the function is already marked for eager or background compilation to
    // TurboFan, we are good.
    if (old_baseline_tier == ExecutionTier::kTurbofan) continue;
    if (old_top_tier == ExecutionTier::kTurbofan) continue;

    // Set top tier to TurboFan, so we eagerly trigger compilation in the
    // background.
    progress = RequiredTopTierField::update(progress, ExecutionTier::kTurbofan);
  }
}

void CompilationStateImpl::ApplyPgoInfoLate(ProfileInformation* pgo_info) {
  TRACE_EVENT0("v8.wasm", "wasm.ApplyPgoInfo");
  const WasmModule* module = native_module_->module();
  CompilationUnitBuilder builder{native_module_};

  base::MutexGuard guard(&callbacks_mutex_);
  // Functions that were executed in the profiling run are eagerly compiled to
  // Liftoff (in the background).
  for (int func_index : pgo_info->executed_functions()) {
    uint8_t& progress =
        compilation_progress_[declared_function_index(module, func_index)];
    ExecutionTier old_baseline_tier =
        RequiredBaselineTierField::decode(progress);
    // If the function is already marked for eager compilation, we are good.
    if (old_baseline_tier != ExecutionTier::kNone) continue;

    // If we already compiled Liftoff or TurboFan code, we are also good.
    ExecutionTier reached_tier = ReachedTierField::decode(progress);
    if (reached_tier >= ExecutionTier::kLiftoff) continue;

    // Set the baseline tier to Liftoff and schedule a compilation unit.
    progress =
        RequiredBaselineTierField::update(progress, ExecutionTier::kLiftoff);
    // Add this as a "top tier unit" since it does not contribute to initial
    // compilation ("baseline finished" might already be triggered).
    // TODO(clemensb): Rename "baseline finished" to "initial compile finished".
    // TODO(clemensb): Avoid scheduling both a Liftoff and a TurboFan unit, or
    // prioritize Liftoff when executing the units.
    builder.AddTopTierUnit(func_index, ExecutionTier::kLiftoff);
  }

  // Functions that were tiered up during PGO generation are eagerly compiled to
  // TurboFan in the background.
  for (int func_index : pgo_info->tiered_up_functions()) {
    uint8_t& progress =
        compilation_progress_[declared_function_index(module, func_index)];
    ExecutionTier old_baseline_tier =
        RequiredBaselineTierField::decode(progress);
    ExecutionTier old_top_tier = RequiredTopTierField::decode(progress);
    // If the function is already marked for eager or background compilation to
    // TurboFan, we are good.
    if (old_baseline_tier == ExecutionTier::kTurbofan) continue;
    if (old_top_tier == ExecutionTier::kTurbofan) continue;

    // If we already compiled TurboFan code, we are also good.
    ExecutionTier reached_tier = ReachedTierField::decode(progress);
    if (reached_tier == ExecutionTier::kTurbofan) continue;

    // Set top tier to TurboFan and schedule a compilation unit.
    progress = RequiredTopTierField::update(progress, ExecutionTier::kTurbofan);
    builder.AddTopTierUnit(func_index, ExecutionTier::kTurbofan);
  }
  builder.Commit();
}

void CompilationStateImpl::InitializeCompilationProgress(
    ProfileInformation* pgo_info) {
  DCHECK(!failed());

  base::MutexGuard guard(&callbacks_mutex_);

  if (!v8_flags.wasm_jitless) {
    auto* module = native_module_->module();

    DCHECK_EQ(0, outstanding_baseline_units_);

    // Compute the default compilation progress for all functions, and set it.
    const ExecutionTierPair default_tiers = GetDefaultTiersPerModule(
        native_module_, dynamic_tiering_, native_module_->IsInDebugState(),
        IsLazyModule(module));
    const uint8_t default_progress =
        RequiredBaselineTierField::encode(default_tiers.baseline_tier) |
        RequiredTopTierField::encode(default_tiers.top_tier) |
        ReachedTierField::encode(ExecutionTier::kNone);
    compilation_progress_.assign(module->num_declared_functions,
                                 default_progress);
    if (default_tiers.baseline_tier != ExecutionTier::kNone) {
      outstanding_baseline_units_ += module->num_declared_functions;
    }

    // Apply compilation hints, if enabled.
    if (native_module_->enabled_features().has_compilation_hints()) {
      size_t num_hints = std::min(module->compilation_hints.size(),
                                  size_t{module->num_declared_functions});
      for (size_t hint_idx = 0; hint_idx < num_hints; ++hint_idx) {
        const auto& hint = module->compilation_hints[hint_idx];
        ApplyCompilationHintToInitialProgress(hint, hint_idx);
      }
    }

    // Transform --wasm-eager-tier-up-function, if given, into a fake
    // compilation hint.
    if (V8_UNLIKELY(
            v8_flags.wasm_eager_tier_up_function >= 0 &&
            static_cast<uint32_t>(v8_flags.wasm_eager_tier_up_function) >=
                module->num_imported_functions &&
            static_cast<uint32_t>(v8_flags.wasm_eager_tier_up_function) <
                module->functions.size())) {
      uint32_t func_idx =
          v8_flags.wasm_eager_tier_up_function - module->num_imported_functions;
      WasmCompilationHint hint{WasmCompilationHintStrategy::kEager,
                               WasmCompilationHintTier::kOptimized,
                               WasmCompilationHintTier::kOptimized};
      ApplyCompilationHintToInitialProgress(hint, func_idx);
    }
  }

  // Apply PGO information, if available.
  if (pgo_info) ApplyPgoInfoToInitialProgress(pgo_info);

  // Trigger callbacks if module needs no baseline or top tier compilation. This
  // can be the case for an empty or fully lazy module.
  TriggerOutstandingCallbacks();
}

void CompilationStateImpl::AddCompilationUnitInternal(
    CompilationUnitBuilder* builder, int function_index,
    uint8_t function_progress) {
  ExecutionTier required_baseline_tier =
      CompilationStateImpl::RequiredBaselineTierField::decode(
          function_progress);
  ExecutionTier required_top_tier =
      CompilationStateImpl::RequiredTopTierField::decode(function_progress);
  ExecutionTier reached_tier =
      CompilationStateImpl::ReachedTierField::decode(function_progress);

  if (reached_tier < required_baseline_tier) {
    builder->AddBaselineUnit(function_index, required_baseline_tier);
  }
  if (reached_tier < required_top_tier &&
      required_baseline_tier != required_top_tier) {
    builder->AddTopTierUnit(function_index, required_top_tier);
  }
}

void CompilationStateImpl::InitializeCompilationUnits(
    std::unique_ptr<CompilationUnitBuilder> builder) {
  if (!v8_flags.wasm_jitless) {
    int offset = native_module_->module()->num_imported_functions;
    {
      base::MutexGuard guard(&callbacks_mutex_);

      for (size_t i = 0, e = compilation_progress_.size(); i < e; ++i) {
        uint8_t function_progress = compilation_progress_[i];
        int func_index = offset + static_cast<int>(i);
        AddCompilationUnitInternal(builder.get(), func_index,
                                   function_progress);
      }
    }
  }
  builder->Commit();
}

void CompilationStateImpl::AddCompilationUnit(CompilationUnitBuilder* builder,
                                              int func_index) {
  int offset = native_module_->module()->num_imported_functions;
  int progress_index = func_index - offset;
  uint8_t function_progress = 0;
  if (!v8_flags.wasm_jitless) {
    // TODO(ahaas): This lock may cause overhead. If so, we could get rid of the
    // lock as follows:
    // 1) Make compilation_progress_ an array of atomic<uint8_t>, and access it
    // lock-free.
    // 2) Have a copy of compilation_progress_ that we use for initialization.
    // 3) Just re-calculate the content of compilation_progress_.
    base::MutexGuard guard(&callbacks_mutex_);
    function_progress = compilation_progress_[progress_index];
  }
  AddCompilationUnitInternal(builder, func_index, function_progress);
}

void CompilationStateImpl::InitializeCompilationProgressAfterDeserialization(
    base::Vector<const int> lazy_functions,
    base::Vector<const int> eager_functions) {
  TRACE_EVENT2("v8.wasm", "wasm.CompilationAfterDeserialization",
               "num_lazy_functions", lazy_functions.size(),
               "num_eager_functions", eager_functions.size());
  std::optional<TimedHistogramScope> lazy_compile_time_scope;
  if (base::TimeTicks::IsHighResolution()) {
    lazy_compile_time_scope.emplace(
        counters()->wasm_compile_after_deserialize());
  }

  auto* module = native_module_->module();
  {
    base::MutexGuard guard(&callbacks_mutex_);
    DCHECK(compilation_progress_.empty());

    // Initialize the compilation progress as if everything was
    // TurboFan-compiled.
    constexpr uint8_t kProgressAfterTurbofanDeserialization =
        RequiredBaselineTierField::encode(ExecutionTier::kTurbofan) |
        RequiredTopTierField::encode(ExecutionTier::kTurbofan) |
        ReachedTierField::encode(ExecutionTier::kTurbofan);
    compilation_progress_.assign(module->num_declared_functions,
                                 kProgressAfterTurbofanDeserialization);

    // Update compilation state for lazy functions.
    constexpr uint8_t kProgressForLazyFunctions =
        RequiredBaselineTierField::encode(ExecutionTier::kNone) |
        RequiredTopTierField::encode(ExecutionTier::kNone) |
        ReachedTierField::encode(ExecutionTier::kNone);
    for (auto func_index : lazy_functions) {
      compilation_progress_[declared_function_index(module, func_index)] =
          kProgressForLazyFunctions;
    }

    // Update compilation state for eagerly compiled functions.
    constexpr bool kNotLazy = false;
    ExecutionTierPair default_tiers =
        GetDefaultTiersPerModule(native_module_, dynamic_tiering_,
                                 native_module_->IsInDebugState(), kNotLazy);
    uint8_t progress_for_eager_functions =
        RequiredBaselineTierField::encode(default_tiers.baseline_tier) |
        RequiredTopTierField::encode(default_tiers.top_tier) |
        ReachedTierField::encode(ExecutionTier::kNone);
    for (auto func_index : eager_functions) {
      // Check that {func_index} is not contained in {lazy_functions}.
      DCHECK_EQ(
          compilation_progress_[declared_function_index(module, func_index)],
          kProgressAfterTurbofanDeserialization);
      compilation_progress_[declared_function_index(module, func_index)] =
          progress_for_eager_functions;
    }
    DCHECK_NE(ExecutionTier::kNone, default_tiers.baseline_tier);
    outstanding_baseline_units_ += eager_functions.size();

    // Baseline compilation is done if we do not have any Liftoff functions to
    // compile.
    if (eager_functions.empty() || v8_flags.wasm_lazy_compilation) {
      finished_events_.Add(CompilationEvent::kFinishedBaselineCompilation);
    }
  }
  auto builder = std::make_unique<CompilationUnitBuilder>(native_module_);
  InitializeCompilationUnits(std::move(builder));
  if (!v8_flags.wasm_lazy_compilation) {
    WaitForCompilationEvent(CompilationEvent::kFinishedBaselineCompilation);
  }
}

void CompilationStateImpl::AddCallback(
    std::unique_ptr<CompilationEventCallback> callback) {
  base::MutexGuard callbacks_guard(&callbacks_mutex_);
  // Immediately trigger events that already happened.
  for (auto event : {CompilationEvent::kFinishedBaselineCompilation,
                     CompilationEvent::kFailedCompilation}) {
    if (finished_events_.contains(event)) {
      callback->call(event);
    }
  }
  constexpr base::EnumSet<CompilationEvent> kFinalEvents{
      CompilationEvent::kFailedCompilation};
  if (!finished_events_.contains_any(kFinalEvents)) {
    callbacks_.emplace_back(std::move(callback));
  }
}

void CompilationStateImpl::CommitCompilationUnits(
    base::Vector<WasmCompilationUnit> baseline_units,
    base::Vector<WasmCompilationUnit> top_tier_units) {
  base::MutexGuard guard{&mutex_};
  if (!baseline_units.empty() || !top_tier_units.empty()) {
    compilation_unit_queues_.AddUnits(baseline_units, top_tier_units,
                                      native_module_->module());
  }
  if (!baseline_units.empty()) {
    DCHECK(baseline_compile_job_->IsValid());
    baseline_compile_job_->NotifyConcurrencyIncrease();
  }
  if (!top_tier_units.empty()) {
    DCHECK(top_tier_compile_job_->IsValid());
    top_tier_compile_job_->NotifyConcurrencyIncrease();
  }
}

void CompilationStateImpl::CommitTopTierCompilationUnit(
    WasmCompilationUnit unit) {
  CommitCompilationUnits({}, {&unit, 1});
}

void CompilationStateImpl::AddTopTierPriorityCompilationUnit(
    WasmCompilationUnit unit, size_t priority) {
  compilation_unit_queues_.AddTopTierPriorityUnit(unit, priority);
  // We should not have a {CodeSpaceWriteScope} open at this point, as
  // {NotifyConcurrencyIncrease} can spawn new threads which could inherit PKU
  // permissions (which would be a security issue).
  top_tier_compile_job_->NotifyConcurrencyIncrease();
}

CompilationUnitQueues::Queue* CompilationStateImpl::GetQueueForCompileTask(
    int task_id) {
  return compilation_unit_queues_.GetQueueForTask(task_id);
}

std::optional<WasmCompilationUnit> CompilationStateImpl::GetNextCompilationUnit(
    CompilationUnitQueues::Queue* queue, CompilationTier tier) {
  return compilation_unit_queues_.GetNextUnit(queue, tier);
}

void CompilationStateImpl::OnFinishedUnits(
    base::Vector<WasmCode*> code_vector) {
  TRACE_EVENT1(TRACE_DISABLED_BY_DEFAULT("v8.wasm.detailed"),
               "wasm.OnFinishedUnits", "units", code_vector.size());

  base::MutexGuard guard(&callbacks_mutex_);

  // Assume an order of execution tiers that represents the quality of their
  // generated code.
  static_assert(ExecutionTier::kNone < ExecutionTier::kLiftoff &&
                    ExecutionTier::kLiftoff < ExecutionTier::kTurbofan,
                "Assume an order on execution tiers");

  if (!v8_flags.wasm_jitless) {
    DCHECK_EQ(compilation_progress_.size(),
              native_module_->module()->num_declared_functions);
  }

  bool has_top_tier_code = false;

  for (size_t i = 0; i < code_vector.size(); i++) {
    WasmCode* code = code_vector[i];
    DCHECK_NOT_NULL(code);
    DCHECK_LT(code->index(), native_module_->num_functions());

    has_top_tier_code |= code->tier() == ExecutionTier::kTurbofan;

    if (code->index() <
        static_cast<int>(native_module_->num_imported_functions())) {
      // Import wrapper.
      DCHECK_EQ(code->tier(), ExecutionTier::kTurbofan);
      outstanding_baseline_units_--;
    } else {
      // Function.
      DCHECK_NE(code->tier(), ExecutionTier::kNone);

      // Read function's compilation progress.
      // This view on the compilation progress may differ from the actually
      // compiled code. Any lazily compiled function does not contribute to the
      // compilation progress but may publish code to the code manager.
      int slot_index =
          declared_function_index(native_module_->module(), code->index());
      uint8_t function_progress = compilation_progress_[slot_index];
      ExecutionTier required_baseline_tier =
          RequiredBaselineTierField::decode(function_progress);
      ExecutionTier reached_tier = ReachedTierField::decode(function_progress);

      // Check whether required baseline or top tier are reached.
      if (reached_tier < required_baseline_tier &&
          required_baseline_tier <= code->tier()) {
        DCHECK_GT(outstanding_baseline_units_, 0);
        outstanding_baseline_units_--;
      }
      if (code->tier() == ExecutionTier::kTurbofan) {
        bytes_since_last_chunk_ += code->instructions().size();
      }

      // Update function's compilation progress.
      if (code->tier() > reached_tier) {
        compilation_progress_[slot_index] = ReachedTierField::update(
            compilation_progress_[slot_index], code->tier());
      }
      // Allow another top tier compilation if deopts are enabled and the
      // currently installed code object is a liftoff object.
      // Ideally, this would be done only if the code->tier() ==
      // ExeuctionTier::Liftoff as the code object for which we run this
      // function should be the same as the one installed on the native_module.
      // This is unfortunately not the case as installing a code object on the
      // native module and updating the compilation_progress_ and the
      // CompilationUnitQueues::top_tier_compiled_ are not synchronized.
      // Note: GetCode() acquires the NativeModule::allocation_mutex_, so this
      // could cause deadlocks if any other place acquires
      // NativeModule::allocation_mutex_ first and then
      // CompilationStateImpl::callbacks_mutex_!
      const bool is_liftoff = code->tier() == ExecutionTier::kLiftoff;
      auto published_code_is_liftoff = [this](int index) {
        WasmCode* code = native_module_->GetCode(index);
        if (code == nullptr) return false;
        return code->is_liftoff();
      };
      if (v8_flags.wasm_deopt &&
          (is_liftoff || published_code_is_liftoff(code->index()))) {
        compilation_progress_[slot_index] = ReachedTierField::update(
            compilation_progress_[slot_index], ExecutionTier::kLiftoff);
        compilation_unit_queues_.AllowAnotherTopTierJob(code->index());
      }
      DCHECK_LE(0, outstanding_baseline_units_);
    }
  }

  // Update the {last_top_tier_compilation_timestamp_} if it is set (i.e. a
  // delayed task has already been spawned).
  if (has_top_tier_code && !last_top_tier_compilation_timestamp_.IsNull()) {
    last_top_tier_compilation_timestamp_ = base::TimeTicks::Now();
  }

  TriggerOutstandingCallbacks();
}

namespace {
class TriggerCodeCachingAfterTimeoutTask : public v8::Task {
 public:
  explicit TriggerCodeCachingAfterTimeoutTask(
      std::weak_ptr<NativeModule> native_module)
      : native_module_(std::move(native_module)) {}

  void Run() override {
    if (std::shared_ptr<NativeModule> native_module = native_module_.lock()) {
      Impl(native_module->compilation_state())->TriggerCachingAfterTimeout();
    }
  }

 private:
  const std::weak_ptr<NativeModule> native_module_;
};
}  // namespace

void CompilationStateImpl::TriggerOutstandingCallbacks() {
  callbacks_mutex_.AssertHeld();

  base::EnumSet<CompilationEvent> triggered_events;
  if (outstanding_baseline_units_ == 0) {
    triggered_events.Add(CompilationEvent::kFinishedBaselineCompilation);
  }

  // For dynamic tiering, trigger "compilation chunk finished" after a new chunk
  // of size {v8_flags.wasm_caching_threshold}.
  if (dynamic_tiering_ &&
      static_cast<size_t>(v8_flags.wasm_caching_threshold) <=
          bytes_since_last_chunk_) {
    // Trigger caching immediately if there is no timeout or the hard threshold
    // was reached.
    if (v8_flags.wasm_caching_timeout_ms <= 0 ||
        static_cast<size_t>(v8_flags.wasm_caching_hard_threshold) <=
            bytes_since_last_chunk_) {
      triggered_events.Add(CompilationEvent::kFinishedCompilationChunk);
      bytes_since_last_chunk_ = 0;
    } else if (last_top_tier_compilation_timestamp_.IsNull()) {
      // Trigger a task after the given timeout; that task will only trigger
      // caching if no new code was added until then. Otherwise, it will
      // re-schedule itself.
      V8::GetCurrentPlatform()->CallDelayedOnWorkerThread(
          std::make_unique<TriggerCodeCachingAfterTimeoutTask>(
              native_module_weak_),
          1e-3 * v8_flags.wasm_caching_timeout_ms);

      // Set the timestamp (will be updated by {OnFinishedUnits} if more
      // top-tier compilation finished before the delayed task is being run).
      last_top_tier_compilation_timestamp_ = base::TimeTicks::Now();
    }
  }

  if (compile_failed_.load(std::memory_order_relaxed)) {
    // *Only* trigger the "failed" event.
    triggered_events =
        base::EnumSet<CompilationEvent>({CompilationEvent::kFailedCompilation});
  }

  TriggerCallbacks(triggered_events);
}

void CompilationStateImpl::TriggerCallbacks(
    base::EnumSet<CompilationEvent> events) {
  if (events.empty()) return;

  // Don't trigger past events again.
  events -= finished_events_;
  // There can be multiple compilation chunks, thus do not store this.
  finished_events_ |= events - CompilationEvent::kFinishedCompilationChunk;

  for (auto event :
       {std::make_pair(CompilationEvent::kFailedCompilation,
                       "wasm.CompilationFailed"),
        std::make_pair(CompilationEvent::kFinishedBaselineCompilation,
                       "wasm.BaselineFinished"),
        std::make_pair(CompilationEvent::kFinishedCompilationChunk,
                       "wasm.CompilationChunkFinished")}) {
    if (!events.contains(event.first)) continue;
    DCHECK_NE(compilation_id_, kInvalidCompilationID);
    TRACE_EVENT1("v8.wasm", event.second, "id", compilation_id_);
    for (auto& callback : callbacks_) {
      callback->call(event.first);
    }
  }

  if (outstanding_baseline_units_ == 0) {
    auto new_end = std::remove_if(
        callbacks_.begin(), callbacks_.end(), [](const auto& callback) {
          return callback->release_after_final_event();
        });
    callbacks_.erase(new_end, callbacks_.end());
  }
}

void CompilationStateImpl::TriggerCachingAfterTimeout() {
  base::MutexGuard guard{&callbacks_mutex_};

  // It can happen that we reached the hard threshold while waiting for the
  // timeout to expire. In that case, {bytes_since_last_chunk_} might be zero
  // and there is nothing new to cache.
  if (bytes_since_last_chunk_ == 0) return;

  DCHECK(!last_top_tier_compilation_timestamp_.IsNull());
  base::TimeTicks caching_time =
      last_top_tier_compilation_timestamp_ +
      base::TimeDelta::FromMilliseconds(v8_flags.wasm_caching_timeout_ms);
  base::TimeDelta time_until_caching = caching_time - base::TimeTicks::Now();
  // If we are still half a millisecond or more away from the timeout,
  // reschedule the task. Otherwise, call the caching callback.
  if (time_until_caching >= base::TimeDelta::FromMicroseconds(500)) {
    int ms_remaining =
        static_cast<int>(time_until_caching.InMillisecondsRoundedUp());
    DCHECK_LE(1, ms_remaining);
    V8::GetCurrentPlatform()->CallDelayedOnWorkerThread(
        std::make_unique<TriggerCodeCachingAfterTimeoutTask>(
            native_module_weak_),
        ms_remaining);
    return;
  }

  TriggerCallbacks({CompilationEvent::kFinishedCompilationChunk});
  last_top_tier_compilation_timestamp_ = {};
  bytes_since_last_chunk_ = 0;
}

void CompilationStateImpl::OnCompilationStopped(
    WasmDetectedFeatures detected_features) {
  WasmDetectedFeatures new_detected_features =
      UpdateDetectedFeatures(detected_features);
  if (new_detected_features.empty()) return;

  // New detected features can only happen during eager compilation or if lazy
  // validation is enabled.
  // The exceptions are currently stringref and imported strings, which are only
  // detected on top-tier compilation.
  DCHECK(!v8_flags.wasm_lazy_compilation || v8_flags.wasm_lazy_validation ||
         (new_detected_features -
          WasmDetectedFeatures{{WasmDetectedFeature::stringref,
                                WasmDetectedFeature::imported_strings_utf8,
                                WasmDetectedFeature::imported_strings}})
             .empty());
  // TODO(clemensb): Fix reporting of late detected features (relevant for lazy
  // validation and for stringref).
}

WasmDetectedFeatures CompilationStateImpl::UpdateDetectedFeatures(
    WasmDetectedFeatures detected_features) {
  WasmDetectedFeatures old_features =
      detected_features_.load(std::memory_order_relaxed);
  while (!detected_features_.compare_exchange_weak(
      old_features, old_features | detected_features,
      std::memory_order_relaxed)) {
    // Retry with updated {old_features}.
  }
  return detected_features - old_features;
}

void CompilationStateImpl::PublishCompilationResults(
    std::vector<std::unique_ptr<WasmCode>> unpublished_code) {
  if (unpublished_code.empty()) return;

#if DEBUG
  // We don't compile import wrappers eagerly.
  for (const auto& code : unpublished_code) {
    int func_index = code->index();
    DCHECK_LE(native_module_->num_imported_functions(), func_index);
    DCHECK_LT(func_index, native_module_->num_functions());
  }
#endif
  PublishCode(base::VectorOf(unpublished_code));
}

std::vector<WasmCode*> CompilationStateImpl::PublishCode(
    base::Vector<std::unique_ptr<WasmCode>> code) {
  WasmCodeRefScope code_ref_scope;
  std::vector<WasmCode*> published_code =
      native_module_->PublishCode(std::move(code));
  // Defer logging code in case wire bytes were not fully received yet.
  if (native_module_->log_code() && native_module_->HasWireBytes()) {
    GetWasmEngine()->LogCode(base::VectorOf(published_code));
  }

  OnFinishedUnits(base::VectorOf(published_code));
  return published_code;
}

void CompilationStateImpl::SchedulePublishCompilationResults(
    std::vector<std::unique_ptr<WasmCode>> unpublished_code,
    CompilationTier tier) {
  PublishState& state = publish_state_[tier];
  {
    base::MutexGuard guard(&state.mutex_);
    if (state.publisher_running_) {
      // Add new code to the queue and return.
      state.publish_queue_.reserve(state.publish_queue_.size() +
                                   unpublished_code.size());
      for (auto& c : unpublished_code) {
        state.publish_queue_.emplace_back(std::move(c));
      }
      return;
    }
    state.publisher_running_ = true;
  }
  while (true) {
    PublishCompilationResults(std::move(unpublished_code));
    unpublished_code.clear();

    // Keep publishing new code that came in.
    base::MutexGuard guard(&state.mutex_);
    DCHECK(state.publisher_running_);
    if (state.publish_queue_.empty()) {
      state.publisher_running_ = false;
      return;
    }
    unpublished_code.swap(state.publish_queue_);
  }
}

size_t CompilationStateImpl::NumOutstandingCompilations(
    CompilationTier tier) const {
  return compilation_unit_queues_.GetSizeForTier(tier);
}

void CompilationStateImpl::SetError() {
  compile_cancelled_.store(true, std::memory_order_relaxed);
  if (compile_failed_.exchange(true, std::memory_order_relaxed)) {
    return;  // Already failed before.
  }

  base::MutexGuard callbacks_guard(&callbacks_mutex_);
  TriggerOutstandingCallbacks();
  callbacks_.clear();
}

void CompilationStateImpl::WaitForCompilationEvent(
    CompilationEvent expect_event) {
  switch (expect_event) {
    case CompilationEvent::kFinishedBaselineCompilation:
      if (baseline_compile_job_->IsValid()) baseline_compile_job_->Join();
      break;
    default:
      // Waiting on other CompilationEvent doesn't make sense.
      UNREACHABLE();
  }
#ifdef DEBUG
  base::EnumSet<CompilationEvent> events{expect_event,
                                         CompilationEvent::kFailedCompilation};
  base::MutexGuard guard(&callbacks_mutex_);
  DCHECK(finished_events_.contains_any(events));
#endif
}

void CompilationStateImpl::TierUpAllFunctions() {
  const WasmModule* module = native_module_->module();
  uint32_t num_wasm_functions = module->num_declared_functions;
  WasmCodeRefScope code_ref_scope;
  CompilationUnitBuilder builder(native_module_);
  for (uint32_t i = 0; i < num_wasm_functions; ++i) {
    int func_index = module->num_imported_functions + i;
    WasmCode* code = native_module_->GetCode(func_index);
    if (!code || !code->is_turbofan()) {
      builder.AddTopTierUnit(func_index, ExecutionTier::kTurbofan);
    }
  }
  builder.Commit();

  // Join the compilation, until no compilation units are left anymore.
  class DummyDelegate final : public JobDelegate {
    bool ShouldYield() override { return false; }
    bool IsJoiningThread() const override { return true; }
    void NotifyConcurrencyIncrease() override { UNIMPLEMENTED(); }
    uint8_t GetTaskId() override { return kMainTaskId; }
  };

  DummyDelegate delegate;
  ExecuteCompilationUnits(native_module_weak_, async_counters_.get(), &delegate,
                          CompilationTier::kTopTier);

  // We cannot wait for other compilation threads to finish, so we explicitly
  // compile all functions which are not yet available as TurboFan code.
  for (uint32_t i = 0; i < num_wasm_functions; ++i) {
    uint32_t func_index = module->num_imported_functions + i;
    WasmCode* code = native_module_->GetCode(func_index);
    if (!code || !code->is_turbofan()) {
      wasm::GetWasmEngine()->CompileFunction(async_counters_.get(),
                                             native_module_, func_index,
                                             wasm::ExecutionTier::kTurbofan);
    }
  }
}

WasmCode* CompileImportWrapperForTest(Isolate* isolate,
                                      NativeModule* native_module,
                                      ImportCallKind kind,
                                      const CanonicalSig* sig,
                                      CanonicalTypeIndex type_index,
                                      int expected_arity, Suspend suspend) {
  bool source_positions = is_asmjs_module(native_module->module());
  if (v8_flags.wasm_jitless) {
    WasmImportWrapperCache::ModificationScope cache_scope(
        GetWasmImportWrapperCache());
    WasmImportWrapperCache::CacheKey key(kind, type_index, expected_arity,
                                         suspend);
    DCHECK_NULL(cache_scope[key]);
    return nullptr;
  }

  return GetWasmImportWrapperCache()->CompileWasmImportCallWrapper(
      isolate, kind, sig, type_index, source_positions, expected_arity,
      suspend);
}

}  // namespace v8::internal::wasm

#undef TRACE_COMPILE
#undef TRACE_STREAMING
#undef TRACE_LAZY

"""


```