Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/wasm/module-compiler.cc`. I need to identify the key components and their roles in the WebAssembly compilation process. The user also provided specific instructions related to file extensions, JavaScript examples, code logic, common errors, and the context of this being part 5 of 6.

Here's a breakdown of the code and my thought process:

1. **Identify Core Classes:** The code defines several classes related to asynchronous compilation: `AsyncCompileJob`, `AsyncStreamingProcessor`, and `CompilationStateImpl`.

2. **`AsyncCompileJob`:** This seems to be the central class managing the asynchronous compilation process. It has different states represented by nested classes like `PrepareAndStartCompile`, `CompileInForeground`, and `Fail`. It handles caching, finalizing the module, and managing the compilation steps.

3. **`AsyncStreamingProcessor`:** This class deals with processing the WebAssembly module in a streaming fashion. It decodes the module sections, handles function bodies, and interacts with the `AsyncCompileJob`. Key methods include `ProcessModuleHeader`, `ProcessSection`, `ProcessCodeSectionHeader`, `ProcessFunctionBody`, and `OnFinishedStream`.

4. **`CompilationStateImpl`:** This class manages the state of the compilation process for a given module. It handles compilation hints, PGO information, and keeps track of the compilation progress of individual functions. It also manages background compilation jobs.

5. **Compilation Flow:**  The code depicts a multi-stage asynchronous compilation process, including:
    * **Streaming:** Processing the module in chunks as it arrives.
    * **Background Compilation:**  Offloading compilation tasks to background threads.
    * **Caching:**  Checking for and utilizing cached native modules.
    * **Tiering:**  Compiling functions to different tiers of optimization.
    * **Validation:**  Validating the WebAssembly module and individual functions.

6. **Key Functionalities to List:** Based on the class names and methods, the core functionalities are likely:
    * Asynchronous compilation of WebAssembly modules.
    * Streaming compilation for faster initial loading.
    * Management of different compilation tiers (Liftoff, Baseline, TurboFan).
    * Handling compilation hints and Profile-Guided Optimization (PGO).
    * Caching of compiled modules.
    * Background compilation of functions.
    * Validation of WebAssembly code.

7. **Address Specific Instructions:**
    * **`.tq` extension:** The code is `.cc`, so it's not a Torque source file.
    * **JavaScript Relation:** The compilation process directly enables JavaScript to execute WebAssembly. I can provide a simple example of loading and running a WebAssembly module in JavaScript.
    * **Code Logic Reasoning:**  The `AsyncStreamingProcessor` logic, especially handling `prefix_cache_hit_`, demonstrates a clear conditional flow. I can create a hypothetical input and output scenario for this.
    * **Common Errors:**  Asynchronous compilation and streaming can lead to issues like network errors or corrupted downloads. Validation failures are also common.
    * **Part 5 of 6:**  This suggests that this part likely focuses on the asynchronous and streaming aspects of the compilation pipeline, building upon previous steps like parsing and decoding.

8. **Synthesize the Summary:**  Combine the identified functionalities and address the specific instructions to create a comprehensive summary. Emphasize the asynchronous and streaming nature of the processes described in this particular code segment.

9. **Review and Refine:** Check the summary for accuracy, clarity, and completeness, ensuring all user instructions are addressed. Make sure the JavaScript example and code logic scenario are clear and relevant.
这是 `v8/src/wasm/module-compiler.cc` 源代码的第五部分，主要关注 **WebAssembly 模块的异步和流式编译**。它定义了用于管理异步编译任务和流式处理 WebAssembly 字节码的类。

**主要功能归纳：**

1. **异步编译管理 (`AsyncCompileJob`)：**
   -  负责启动、跟踪和完成 WebAssembly 模块的异步编译过程。
   -  管理编译过程中的不同阶段，例如准备编译、前台编译、后台编译和失败处理。
   -  处理编译结果的缓存和发布。
   -  与 `WasmEngine` 交互以管理编译任务。

2. **异步流式处理 (`AsyncStreamingProcessor`)：**
   -  用于增量地处理 WebAssembly 字节码流，允许在模块完全下载之前就开始编译。
   -  解析模块头和各个 section。
   -  处理代码 section，启动编译任务。
   -  解码函数体并将其添加到编译队列。
   -  处理流的完成和中止事件。
   -  支持基于模块前缀哈希的缓存机制，以避免重复编译。
   -  如果启用，支持后台验证函数。
   -  处理反序列化已编译的模块。

3. **编译状态管理 (`CompilationStateImpl`)：**
   -  维护模块的编译状态，例如已编译的 tier、需要的 tier 等。
   -  管理后台编译任务（Baseline 和 TopTier）。
   -  处理编译提示（Compilation Hints）和 PGO (Profile-Guided Optimization) 信息。
   -  跟踪需要编译的函数单元。
   -  在反序列化后初始化编译状态。
   -  管理编译完成的回调。

**功能列举：**

* **启动异步编译：** `AsyncCompileJob` 负责接收编译请求并启动异步编译流程。
* **流式解码：** `AsyncStreamingProcessor` 逐步解码 WebAssembly 模块的字节码。
* **代码 section 处理：**  `AsyncStreamingProcessor::ProcessCodeSectionHeader` 标志着代码 section 的开始，并触发编译准备工作。
* **函数体处理：** `AsyncStreamingProcessor::ProcessFunctionBody` 解码单个函数体，并决定是否立即编译或放入后台编译队列。
* **缓存查找：**  基于模块字节码的前缀哈希进行缓存查找，如果找到匹配的模块，则直接使用缓存。
* **后台编译调度：** `CompilationStateImpl` 管理后台 Baseline 和 TopTier 编译任务，将函数分配到不同的编译队列。
* **编译提示应用：** `CompilationStateImpl::ApplyCompilationHintToInitialProgress` 根据模块提供的编译提示调整函数的编译策略。
* **PGO 信息应用：** `CompilationStateImpl::ApplyPgoInfoToInitialProgress` 和 `CompilationStateImpl::ApplyPgoInfoLate`  根据性能分析数据调整编译策略，例如优先编译热点函数。
* **编译完成通知：**  通过回调机制通知编译完成或失败。
* **反序列化处理：** `AsyncStreamingProcessor::Deserialize` 用于加载和使用已序列化的 WebAssembly 模块。

**关于文件扩展名：**

`v8/src/wasm/module-compiler.cc` 以 `.cc` 结尾，因此它是 **C++ 源代码文件**，而不是 Torque 源代码文件。Torque 源代码文件通常以 `.tq` 结尾。

**与 JavaScript 功能的关系及举例：**

`v8/src/wasm/module-compiler.cc` 的核心功能是编译 WebAssembly 模块，这是 JavaScript 中使用 WebAssembly 的基础。JavaScript 通过 `WebAssembly` API 加载和实例化 WebAssembly 模块。

```javascript
// 假设已经获取了 wasm 模块的字节码 (wasmBytes)
WebAssembly.instantiate(wasmBytes)
  .then(result => {
    const wasmModule = result.module;
    const wasmInstance = result.instance;
    // 调用 wasm 模块导出的函数
    const exportedFunction = wasmInstance.exports.myFunction;
    const resultFromWasm = exportedFunction(10, 20);
    console.log("Result from WebAssembly:", resultFromWasm);
  })
  .catch(error => {
    console.error("Error instantiating WebAssembly module:", error);
  });
```

在这个例子中，`WebAssembly.instantiate(wasmBytes)` 内部会调用 V8 的 WebAssembly 编译流程，而 `module-compiler.cc` 中的代码就参与了这个编译过程，将 wasm 的字节码转换成可执行的代码。

**代码逻辑推理 (假设输入与输出)：**

**假设输入：**

* 一个包含有效 WebAssembly 模块字节码的 `base::Vector<const uint8_t>`。
* `AsyncCompileJob` 已经创建并初始化。
* `AsyncStreamingProcessor` 接收到模块的第一个 chunk，包含模块头。

**输出：**

* `AsyncStreamingProcessor::ProcessModuleHeader` 返回 `true`，表示模块头解析成功。
* `decoder_.ok()` 返回 `true`，表示解码器状态良好。
* `prefix_hash_` 被计算出来。

**如果后续接收到代码 section 的 header：**

**假设输入：**

* `num_functions` 为 5。
* `code_section_length` 为 1000。

**输出：**

* `AsyncStreamingProcessor::ProcessCodeSectionHeader` 返回 `true`。
* `prefix_hash_` 被更新，包含代码 section 的长度信息。
* 如果没有缓存命中 (`prefix_cache_hit_` 为 `false`)，则会调用 `job_->DoImmediately<AsyncCompileJob::PrepareAndStartCompile>` 启动编译准备工作。
* `job_->outstanding_finishers_` 被设置为 2。

**用户常见的编程错误：**

* **不完整的 WebAssembly 模块下载：** 用户可能在模块下载完成之前尝试实例化它，这会导致编译错误。流式编译可以部分缓解这个问题，但仍然需要在接收到必要的 section 后才能完成编译。
* **模块格式错误：** 提供的字节码可能不是有效的 WebAssembly 模块，例如 header 损坏或 section 结构不正确。这会被解码器检测到，导致 `decoder_.ok()` 返回 `false`。
* **导入依赖问题：**  WebAssembly 模块可能依赖 JavaScript 提供的导入，如果在实例化时未能正确提供这些导入，会导致链接错误。`ValidateAndSetBuiltinImports` 尝试验证这些导入。

**示例：不完整的 WebAssembly 模块下载**

```javascript
fetch('my-module.wasm')
  .then(response => response.body)
  .then(readableStream => {
    const reader = readableStream.getReader();
    let receivedChunks = [];

    function read() {
      reader.read().then(({ done, value }) => {
        if (done) {
          // 尝试在所有 chunk 下载完成前实例化 (错误的做法)
          WebAssembly.instantiate(new Uint8Array(receivedChunks.flat()))
            .then(module => console.log("Module instantiated (potentially incomplete)!"))
            .catch(error => console.error("Instantiation error:", error));
          return;
        }
        receivedChunks.push(value);
        read();
      });
    }
    read();
  });
```

在这个错误示例中，代码尝试在所有模块 chunk 下载完成之前就使用 `WebAssembly.instantiate`，这可能会导致编译失败，尤其是在非流式编译的情况下。流式编译允许部分编译，但仍然需要一定的完整性才能成功。

总而言之，这部分代码是 V8 WebAssembly 引擎中负责高效、异步地将 WebAssembly 字节码转换为可执行代码的关键组成部分，它利用流式处理和后台编译来提升性能和用户体验。

### 提示词
```
这是目录为v8/src/wasm/module-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/module-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
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
  if (!finished_events_.contains_any(kFina
```