Response:
The user wants a summary of the functionalities of the provided C++ code snippet from `v8/src/wasm/wasm-engine.cc`.

Here's a breakdown of the code's main tasks:

1. **Compilation Management:** The code deals with compiling WebAssembly modules, including synchronous, asynchronous, and streaming compilation.
2. **Debugging Support:** It handles entering and leaving debugging states for WebAssembly, managing breakpoints, and removing compiled code based on debug status.
3. **Script Integration:** It creates `v8::Script` objects for WebAssembly modules, including setting the source URL and source map URL.
4. **Module Management:** It manages a cache of `NativeModule` objects, which represent compiled WebAssembly modules.
5. **Code Logging:** It provides mechanisms for logging generated WebAssembly code, which can be used for profiling or debugging.
6. **Memory Management:** It tracks memory usage related to WebAssembly and provides methods for flushing Liftoff code.
7. **Concurrency:** It uses mutexes to protect shared data structures and manages asynchronous compilation jobs.
8. **Isolate Management:** It tracks which isolates are using which `NativeModule` objects.

I will go through the code snippet and extract the key functionalities, relating them to JavaScript concepts where applicable.
这是 v8 源代码文件 `v8/src/wasm/wasm-engine.cc` 的一部分，它负责 WebAssembly 引擎的核心功能。以下是这段代码的功能归纳：

**主要功能：WebAssembly 模块的编译和管理**

这段代码主要处理 WebAssembly 模块的编译流程，并管理编译后的模块及其相关的生命周期。

**功能点详解：**

1. **同步和异步编译:**
   -  `CompileModule`:  这个函数是编译 WebAssembly 模块的入口点。
   -  它会根据 `v8_flags.wasm_test_streaming` 和 `v8_flags.wasm_async_compilation` 的设置，选择同步、异步或流式编译。
   -  **同步编译:**  如果不需要流式或异步编译，它会调用 `SyncCompile` 直接编译模块。
   -  **异步编译:**  如果启用了异步编译，它会创建 `AsyncCompileJob` 并启动异步编译流程。
   -  **流式编译:** 如果启用了流式编译，它会创建 `StreamingDecoder` 来逐步接收和编译模块的字节码。
   -  **JavaScript 关联:** 在 JavaScript 中，`WebAssembly.compile()` 方法会触发这里的编译流程。

   ```javascript
   // JavaScript 示例：同步编译
   fetch('module.wasm')
     .then(response => response.arrayBuffer())
     .then(bytes => WebAssembly.compile(bytes))
     .then(module => {
       console.log('Wasm 模块编译成功:', module);
     });

   // JavaScript 示例：异步编译（通常由浏览器内部处理，用户无需直接操作）
   // WebAssembly.compileStreaming() 可能会使用异步编译
   ```

2. **流式编译的模拟:**
   - 代码中有一段模拟流式编译的逻辑，即使在 `v8_flags.wasm_test_streaming` 为 true 时也会执行。
   - 它会将模块的字节码分割成多个小的 `ranges`，然后逐个传递给 `StreamingDecoder`，模拟网络传输的场景。

3. **模块字节码的复制:**
   - 在异步编译的情况下，为了防止用户程序在编译过程中修改原始字节码，代码会创建模块字节码的副本 (`base::OwnedVector<const uint8_t> copy`)。

4. **异步编译任务的管理:**
   - `CreateAsyncCompileJob`:  创建异步编译任务。
   - `StartStreamingCompilation`: 启动流式编译，如果启用异步编译，也会创建一个 `AsyncCompileJob`。

5. **函数级别的编译:**
   - `CompileFunction`: 编译 WebAssembly 模块中的单个函数。这通常用于优化，例如在需要时才编译特定函数。
   - **JavaScript 关联:**  虽然用户不能直接调用编译单个函数，但 JavaScript 引擎内部会根据执行情况进行函数的优化编译。

6. **调试支持:**
   - `EnterDebuggingForIsolate`:  当进入调试模式时，会标记相关的 `NativeModule` 并移除非调试代码。
   - `LeaveDebuggingForIsolate`: 当退出调试模式时，会取消标记并可能重新编译代码。
   - 这些功能确保在调试状态下可以正确地单步执行和检查 WebAssembly 代码。

7. **创建 WebAssembly Script 对象:**
   -  `CreateWasmScript`:  创建一个 `v8::Script` 对象来表示 WebAssembly 模块。
   -  它会设置脚本的 URL（基于模块名称或哈希值）、源码映射 URL 以及关联的 `NativeModule`。
   -  **JavaScript 关联:**  `v8::Script` 对象在 V8 中代表一个可执行的脚本，包括 JavaScript 和 WebAssembly。

8. **导入 NativeModule:**
   - `ImportNativeModule`:  将编译好的 `NativeModule` 导入到 V8 中，并创建对应的 `WasmModuleObject`。
   -  它还会创建或获取与该模块关联的 `v8::Script` 对象。
   -  **JavaScript 关联:** 当 JavaScript 代码实例化一个 WebAssembly 模块时，会使用到这个函数。

   ```javascript
   // JavaScript 示例：实例化一个编译好的 WebAssembly 模块
   fetch('module.wasm')
     .then(response => response.arrayBuffer())
     .then(bytes => WebAssembly.compile(bytes))
     .then(module => WebAssembly.instantiate(module))
     .then(instance => {
       console.log('Wasm 模块实例化成功:', instance);
     });
   ```

**假设输入与输出（以异步编译为例）：**

**假设输入:**

- `isolate`: 当前 V8 隔离区 (Isolate) 的指针。
- `enabled`:  启用的 WebAssembly 特性。
- `compile_imports`: 编译时的导入信息。
- `bytes`: 包含 WebAssembly 模块字节码的 `ModuleWireBytes` 对象。
- `resolver`: 用于处理编译结果的回调对象。
- `compilation_id`:  编译任务的唯一标识符。

**预期输出:**

- 创建一个 `AsyncCompileJob` 对象，并将其添加到 `async_compile_jobs_` 列表中。
- 异步编译任务开始执行。
- 当编译成功时，`resolver->OnCompilationSucceeded` 会被调用，传递编译后的 `WasmModuleObject`。
- 当编译失败时，`resolver->OnCompilationFailed` 会被调用，传递错误信息。

**用户常见的编程错误（虽然这段代码不是用户直接编写）：**

- **提供的字节码不完整或损坏:**  如果传递给 `CompileModule` 的 `bytes` 对象包含无效的 WebAssembly 字节码，会导致编译失败。这在 JavaScript 中通常表现为 `WebAssembly.compile()` 或 `WebAssembly.instantiate()` 抛出异常。

   ```javascript
   // JavaScript 示例：提供错误的字节码
   const invalidBytes = new Uint8Array([0, 1, 2, 3]);
   WebAssembly.compile(invalidBytes)
     .catch(error => {
       console.error('编译失败:', error); // 可能会输出 "CompileError: ... "
     });
   ```

- **在异步编译过程中修改原始字节码:** 虽然这段 C++ 代码通过复制字节码来避免这个问题，但在概念上，用户不应该在传递给 `WebAssembly.compile()` 或 `WebAssembly.compileStreaming()` 后修改原始的 `ArrayBuffer`。

**总结这段代码的功能:**

这段 `v8/src/wasm/wasm-engine.cc` 的代码片段负责 WebAssembly 模块的编译和初步管理。它处理同步、异步和流式编译，支持调试，并创建 V8 引擎中表示 WebAssembly 模块的对象。它的核心目标是将 WebAssembly 字节码转换为 V8 可以执行的代码结构。

### 提示词
```
这是目录为v8/src/wasm/wasm-engine.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-engine.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
current modification.
      std::unique_ptr<uint8_t[]> copy(new uint8_t[bytes.length()]);
      memcpy(copy.get(), bytes.start(), bytes.length());
      ModuleWireBytes bytes_copy(copy.get(), copy.get() + bytes.length());
      module_object = SyncCompile(isolate, enabled, std::move(compile_imports),
                                  &thrower, bytes_copy);
    } else {
      // The wire bytes are not shared, OK to use them directly.
      module_object = SyncCompile(isolate, enabled, std::move(compile_imports),
                                  &thrower, bytes);
    }
    if (thrower.error()) {
      resolver->OnCompilationFailed(thrower.Reify());
      return;
    }
    Handle<WasmModuleObject> module = module_object.ToHandleChecked();
    resolver->OnCompilationSucceeded(module);
    return;
  }

  if (v8_flags.wasm_test_streaming) {
    std::shared_ptr<StreamingDecoder> streaming_decoder =
        StartStreamingCompilation(isolate, enabled, std::move(compile_imports),
                                  handle(isolate->context(), isolate),
                                  api_method_name_for_errors,
                                  std::move(resolver));

    auto* rng = isolate->random_number_generator();
    base::SmallVector<base::Vector<const uint8_t>, 16> ranges;
    if (!bytes.module_bytes().empty()) ranges.push_back(bytes.module_bytes());
    // Split into up to 16 ranges (2^4).
    for (int round = 0; round < 4; ++round) {
      for (auto it = ranges.begin(); it != ranges.end(); ++it) {
        auto range = *it;
        if (range.size() < 2 || !rng->NextBool()) continue;  // Do not split.
        // Choose split point within [1, range.size() - 1].
        static_assert(kV8MaxWasmModuleSize <= kMaxInt);
        size_t split_point =
            1 + rng->NextInt(static_cast<int>(range.size() - 1));
        // Insert first sub-range *before* {it} and make {it} point after it.
        it = ranges.insert(it, range.SubVector(0, split_point)) + 1;
        *it = range.SubVectorFrom(split_point);
      }
    }
    for (auto range : ranges) {
      streaming_decoder->OnBytesReceived(range);
    }
    streaming_decoder->Finish();
    return;
  }
  // Make a copy of the wire bytes in case the user program changes them
  // during asynchronous compilation.
  base::OwnedVector<const uint8_t> copy =
      base::OwnedVector<const uint8_t>::Of(bytes.module_bytes());

  AsyncCompileJob* job = CreateAsyncCompileJob(
      isolate, enabled, std::move(compile_imports), std::move(copy),
      isolate->native_context(), api_method_name_for_errors,
      std::move(resolver), compilation_id);
  job->Start();
}

std::shared_ptr<StreamingDecoder> WasmEngine::StartStreamingCompilation(
    Isolate* isolate, WasmEnabledFeatures enabled,
    CompileTimeImports compile_imports, Handle<Context> context,
    const char* api_method_name,
    std::shared_ptr<CompilationResultResolver> resolver) {
  int compilation_id = next_compilation_id_.fetch_add(1);
  TRACE_EVENT1("v8.wasm", "wasm.StartStreamingCompilation", "id",
               compilation_id);
  if (v8_flags.wasm_async_compilation) {
    AsyncCompileJob* job = CreateAsyncCompileJob(
        isolate, enabled, std::move(compile_imports), {}, context,
        api_method_name, std::move(resolver), compilation_id);
    return job->CreateStreamingDecoder();
  }
  return StreamingDecoder::CreateSyncStreamingDecoder(
      isolate, enabled, std::move(compile_imports), context, api_method_name,
      std::move(resolver));
}

void WasmEngine::CompileFunction(Counters* counters,
                                 NativeModule* native_module,
                                 uint32_t function_index, ExecutionTier tier) {
  DCHECK(!v8_flags.wasm_jitless);

  // Note we assume that "one-off" compilations can discard detected features.
  WasmDetectedFeatures detected;
  WasmCompilationUnit::CompileWasmFunction(
      counters, native_module, &detected,
      &native_module->module()->functions[function_index], tier);
}

void WasmEngine::EnterDebuggingForIsolate(Isolate* isolate) {
  if (v8_flags.wasm_jitless) return;

  std::vector<std::shared_ptr<NativeModule>> native_modules;
  // {mutex_} gets taken both here and in {RemoveCompiledCode} in
  // {AddPotentiallyDeadCode}. Therefore {RemoveCompiledCode} has to be
  // called outside the lock.
  {
    base::MutexGuard lock(&mutex_);
    if (isolates_[isolate]->keep_in_debug_state) return;
    isolates_[isolate]->keep_in_debug_state = true;
    for (auto* native_module : isolates_[isolate]->native_modules) {
      DCHECK_EQ(1, native_modules_.count(native_module));
      if (auto shared_ptr = native_modules_[native_module]->weak_ptr.lock()) {
        native_modules.emplace_back(std::move(shared_ptr));
      }
      native_module->SetDebugState(kDebugging);
    }
  }
  WasmCodeRefScope ref_scope;
  for (auto& native_module : native_modules) {
    native_module->RemoveCompiledCode(
        NativeModule::RemoveFilter::kRemoveNonDebugCode);
  }
}

void WasmEngine::LeaveDebuggingForIsolate(Isolate* isolate) {
  // Only trigger recompilation after releasing the mutex, otherwise we risk
  // deadlocks because of lock inversion. The bool tells whether the module
  // needs recompilation for tier up.
  std::vector<std::pair<std::shared_ptr<NativeModule>, bool>> native_modules;
  {
    base::MutexGuard lock(&mutex_);
    isolates_[isolate]->keep_in_debug_state = false;
    auto can_remove_debug_code = [this](NativeModule* native_module) {
      DCHECK_EQ(1, native_modules_.count(native_module));
      for (auto* isolate : native_modules_[native_module]->isolates) {
        DCHECK_EQ(1, isolates_.count(isolate));
        if (isolates_[isolate]->keep_in_debug_state) return false;
      }
      return true;
    };
    for (auto* native_module : isolates_[isolate]->native_modules) {
      DCHECK_EQ(1, native_modules_.count(native_module));
      auto shared_ptr = native_modules_[native_module]->weak_ptr.lock();
      if (!shared_ptr) continue;  // The module is not used any more.
      if (!native_module->IsInDebugState()) continue;
      // Only start tier-up if no other isolate needs this module in tiered
      // down state.
      bool remove_debug_code = can_remove_debug_code(native_module);
      if (remove_debug_code) native_module->SetDebugState(kNotDebugging);
      native_modules.emplace_back(std::move(shared_ptr), remove_debug_code);
    }
  }
  for (auto& entry : native_modules) {
    auto& native_module = entry.first;
    bool remove_debug_code = entry.second;
    // Remove all breakpoints set by this isolate.
    if (native_module->HasDebugInfo()) {
      native_module->GetDebugInfo()->RemoveIsolate(isolate);
    }
    if (remove_debug_code) {
      WasmCodeRefScope ref_scope;
      native_module->RemoveCompiledCode(
          NativeModule::RemoveFilter::kRemoveDebugCode);
    }
  }
}

namespace {
Handle<Script> CreateWasmScript(Isolate* isolate,
                                std::shared_ptr<NativeModule> native_module,
                                base::Vector<const char> source_url) {
  base::Vector<const uint8_t> wire_bytes = native_module->wire_bytes();

  // The source URL of the script is
  // - the original source URL if available (from the streaming API),
  // - wasm://wasm/<module name>-<hash> if a module name has been set, or
  // - wasm://wasm/<hash> otherwise.
  const WasmModule* module = native_module->module();
  Handle<String> url_str;
  if (!source_url.empty()) {
    url_str = isolate->factory()
                  ->NewStringFromUtf8(source_url, AllocationType::kOld)
                  .ToHandleChecked();
  } else {
    // Limit the printed hash to 8 characters.
    uint32_t hash = static_cast<uint32_t>(GetWireBytesHash(wire_bytes));
    base::EmbeddedVector<char, 32> buffer;
    if (module->name.is_empty()) {
      // Build the URL in the form "wasm://wasm/<hash>".
      int url_len = SNPrintF(buffer, "wasm://wasm/%08x", hash);
      DCHECK(url_len >= 0 && url_len < buffer.length());
      url_str = isolate->factory()
                    ->NewStringFromUtf8(buffer.SubVector(0, url_len),
                                        AllocationType::kOld)
                    .ToHandleChecked();
    } else {
      // Build the URL in the form "wasm://wasm/<module name>-<hash>".
      int hash_len = SNPrintF(buffer, "-%08x", hash);
      DCHECK(hash_len >= 0 && hash_len < buffer.length());
      Handle<String> prefix =
          isolate->factory()->NewStringFromStaticChars("wasm://wasm/");
      Handle<String> module_name =
          WasmModuleObject::ExtractUtf8StringFromModuleBytes(
              isolate, wire_bytes, module->name, kNoInternalize);
      Handle<String> hash_str =
          isolate->factory()
              ->NewStringFromUtf8(buffer.SubVector(0, hash_len))
              .ToHandleChecked();
      // Concatenate the three parts.
      url_str = isolate->factory()
                    ->NewConsString(prefix, module_name)
                    .ToHandleChecked();
      url_str = isolate->factory()
                    ->NewConsString(url_str, hash_str)
                    .ToHandleChecked();
    }
  }
  DirectHandle<PrimitiveHeapObject> source_map_url =
      isolate->factory()->undefined_value();
  if (module->debug_symbols[WasmDebugSymbols::Type::SourceMap].type !=
      WasmDebugSymbols::Type::None) {
    auto source_map_symbols =
        module->debug_symbols[WasmDebugSymbols::Type::SourceMap];
    base::Vector<const char> external_url =
        ModuleWireBytes(wire_bytes)
            .GetNameOrNull(source_map_symbols.external_url);
    MaybeHandle<String> src_map_str = isolate->factory()->NewStringFromUtf8(
        external_url, AllocationType::kOld);
    source_map_url = src_map_str.ToHandleChecked();
  }

  // Use the given shared {NativeModule}, but increase its reference count by
  // allocating a new {Managed<T>} that the {Script} references.
  size_t code_size_estimate = native_module->committed_code_space();
  size_t memory_estimate =
      code_size_estimate +
      wasm::WasmCodeManager::EstimateNativeModuleMetaDataSize(module);
  DirectHandle<Managed<wasm::NativeModule>> managed_native_module =
      Managed<wasm::NativeModule>::From(isolate, memory_estimate,
                                        std::move(native_module));

  Handle<Script> script =
      isolate->factory()->NewScript(isolate->factory()->undefined_value());
  {
    DisallowGarbageCollection no_gc;
    Tagged<Script> raw_script = *script;
    raw_script->set_compilation_state(Script::CompilationState::kCompiled);
    raw_script->set_context_data(isolate->native_context()->debug_context_id());
    raw_script->set_name(*url_str);
    raw_script->set_type(Script::Type::kWasm);
    raw_script->set_source_mapping_url(*source_map_url);
    raw_script->set_line_ends(ReadOnlyRoots(isolate).empty_fixed_array(),
                              SKIP_WRITE_BARRIER);
    raw_script->set_wasm_managed_native_module(*managed_native_module);
    raw_script->set_wasm_breakpoint_infos(
        ReadOnlyRoots(isolate).empty_fixed_array(), SKIP_WRITE_BARRIER);
    raw_script->set_wasm_weak_instance_list(
        ReadOnlyRoots(isolate).empty_weak_array_list(), SKIP_WRITE_BARRIER);

    // For correct exception handling (in particular, the onunhandledrejection
    // callback), we must set the origin options from the nearest calling JS
    // frame.
    // Considering all Wasm modules as shared across origins isn't a privacy
    // issue, because in order to instantiate and use them, a site needs to
    // already have access to their wire bytes anyway.
    static constexpr bool kIsSharedCrossOrigin = true;
    static constexpr bool kIsOpaque = false;
    static constexpr bool kIsWasm = true;
    static constexpr bool kIsModule = false;
    raw_script->set_origin_options(ScriptOriginOptions(
        kIsSharedCrossOrigin, kIsOpaque, kIsWasm, kIsModule));
  }

  return script;
}
}  // namespace

Handle<WasmModuleObject> WasmEngine::ImportNativeModule(
    Isolate* isolate, std::shared_ptr<NativeModule> shared_native_module,
    base::Vector<const char> source_url) {
  NativeModule* native_module = shared_native_module.get();
  ModuleWireBytes wire_bytes(native_module->wire_bytes());
  DirectHandle<Script> script =
      GetOrCreateScript(isolate, shared_native_module, source_url);
  native_module->LogWasmCodes(isolate, *script);
  Handle<WasmModuleObject> module_object =
      WasmModuleObject::New(isolate, std::move(shared_native_module), script);
  {
    base::MutexGuard lock(&mutex_);
    DCHECK_EQ(1, isolates_.count(isolate));
    IsolateInfo* isolate_info = isolates_.find(isolate)->second.get();
    isolate_info->native_modules.insert(native_module);
    DCHECK_EQ(1, native_modules_.count(native_module));
    native_modules_[native_module]->isolates.insert(isolate);
    if (isolate_info->log_codes && !native_module->log_code()) {
      EnableCodeLogging(native_module);
    }
  }

  // Finish the Wasm script now and make it public to the debugger.
  isolate->debug()->OnAfterCompile(script);
  return module_object;
}

std::pair<size_t, size_t> WasmEngine::FlushLiftoffCode() {
  // Keep the NativeModules alive until after the destructor of the
  // `WasmCodeRefScope`, which still needs to access the code and the
  // NativeModule.
  std::vector<std::shared_ptr<NativeModule>> native_modules_with_dead_code;
  WasmCodeRefScope ref_scope;
  base::MutexGuard guard(&mutex_);
  size_t removed_code_size = 0;
  size_t removed_metadata_size = 0;
  for (auto& [native_module, info] : native_modules_) {
    std::shared_ptr<NativeModule> shared = info->weak_ptr.lock();
    if (!shared) continue;  // The NativeModule is dying anyway.
    auto [code_size, metadata_size] = native_module->RemoveCompiledCode(
        NativeModule::RemoveFilter::kRemoveLiftoffCode);
    DCHECK_EQ(code_size == 0, metadata_size == 0);
    if (code_size == 0) continue;
    native_modules_with_dead_code.emplace_back(std::move(shared));
    removed_code_size += code_size;
    removed_metadata_size += metadata_size;
  }
  return {removed_code_size, removed_metadata_size};
}

size_t WasmEngine::GetLiftoffCodeSizeForTesting() {
  base::MutexGuard guard(&mutex_);
  size_t codesize_liftoff = 0;
  for (auto& [native_module, info] : native_modules_) {
    codesize_liftoff += native_module->SumLiftoffCodeSizeForTesting();
  }
  return codesize_liftoff;
}

std::shared_ptr<CompilationStatistics>
WasmEngine::GetOrCreateTurboStatistics() {
  base::MutexGuard guard(&mutex_);
  if (compilation_stats_ == nullptr) {
    compilation_stats_.reset(new CompilationStatistics());
  }
  return compilation_stats_;
}

void WasmEngine::DumpAndResetTurboStatistics() {
  base::MutexGuard guard(&mutex_);
  if (compilation_stats_ != nullptr) {
    StdoutStream os;
    os << AsPrintableStatistics{"Turbofan Wasm", *compilation_stats_, false}
       << std::endl;
  }
  compilation_stats_.reset();
}

void WasmEngine::DumpTurboStatistics() {
  base::MutexGuard guard(&mutex_);
  if (compilation_stats_ != nullptr) {
    StdoutStream os;
    os << AsPrintableStatistics{"Turbofan Wasm", *compilation_stats_, false}
       << std::endl;
  }
}

CodeTracer* WasmEngine::GetCodeTracer() {
  base::MutexGuard guard(&mutex_);
  if (code_tracer_ == nullptr) code_tracer_.reset(new CodeTracer(-1));
  return code_tracer_.get();
}

AsyncCompileJob* WasmEngine::CreateAsyncCompileJob(
    Isolate* isolate, WasmEnabledFeatures enabled,
    CompileTimeImports compile_imports, base::OwnedVector<const uint8_t> bytes,
    DirectHandle<Context> context, const char* api_method_name,
    std::shared_ptr<CompilationResultResolver> resolver, int compilation_id) {
  DirectHandle<NativeContext> incumbent_context =
      isolate->GetIncumbentContext();
  AsyncCompileJob* job = new AsyncCompileJob(
      isolate, enabled, std::move(compile_imports), std::move(bytes), context,
      incumbent_context, api_method_name, std::move(resolver), compilation_id);
  // Pass ownership to the unique_ptr in {async_compile_jobs_}.
  base::MutexGuard guard(&mutex_);
  async_compile_jobs_[job] = std::unique_ptr<AsyncCompileJob>(job);
  return job;
}

std::unique_ptr<AsyncCompileJob> WasmEngine::RemoveCompileJob(
    AsyncCompileJob* job) {
  base::MutexGuard guard(&mutex_);
  auto item = async_compile_jobs_.find(job);
  DCHECK(item != async_compile_jobs_.end());
  std::unique_ptr<AsyncCompileJob> result = std::move(item->second);
  async_compile_jobs_.erase(item);
  return result;
}

bool WasmEngine::HasRunningCompileJob(Isolate* isolate) {
  base::MutexGuard guard(&mutex_);
  DCHECK_EQ(1, isolates_.count(isolate));
  for (auto& entry : async_compile_jobs_) {
    if (entry.first->isolate() == isolate) return true;
  }
  return false;
}

void WasmEngine::DeleteCompileJobsOnContext(Handle<Context> context) {
  // Under the mutex get all jobs to delete. Then delete them without holding
  // the mutex, such that deletion can reenter the WasmEngine.
  std::vector<std::unique_ptr<AsyncCompileJob>> jobs_to_delete;
  {
    base::MutexGuard guard(&mutex_);
    for (auto it = async_compile_jobs_.begin();
         it != async_compile_jobs_.end();) {
      if (!it->first->context().is_identical_to(context)) {
        ++it;
        continue;
      }
      jobs_to_delete.push_back(std::move(it->second));
      it = async_compile_jobs_.erase(it);
    }
  }
}

void WasmEngine::DeleteCompileJobsOnIsolate(Isolate* isolate) {
  // Under the mutex get all jobs to delete. Then delete them without holding
  // the mutex, such that deletion can reenter the WasmEngine.
  std::vector<std::unique_ptr<AsyncCompileJob>> jobs_to_delete;
  std::vector<std::weak_ptr<NativeModule>> modules_in_isolate;
  {
    base::MutexGuard guard(&mutex_);
    for (auto it = async_compile_jobs_.begin();
         it != async_compile_jobs_.end();) {
      if (it->first->isolate() != isolate) {
        ++it;
        continue;
      }
      jobs_to_delete.push_back(std::move(it->second));
      it = async_compile_jobs_.erase(it);
    }
    DCHECK_EQ(1, isolates_.count(isolate));
    auto* isolate_info = isolates_[isolate].get();
    for (auto* native_module : isolate_info->native_modules) {
      DCHECK_EQ(1, native_modules_.count(native_module));
      modules_in_isolate.emplace_back(native_modules_[native_module]->weak_ptr);
    }
  }

  // All modules that have not finished initial compilation yet cannot be
  // shared with other isolates. Hence we cancel their compilation. In
  // particular, this will cancel wrapper compilation which is bound to this
  // isolate (this would be a UAF otherwise).
  for (auto& weak_module : modules_in_isolate) {
    if (auto shared_module = weak_module.lock()) {
      shared_module->compilation_state()->CancelInitialCompilation();
    }
  }
}

void WasmEngine::AddIsolate(Isolate* isolate) {
  const bool log_code = WasmCode::ShouldBeLogged(isolate);
  // Create the IsolateInfo.
  {
    // Create the IsolateInfo outside the mutex to reduce the size of the
    // critical section and to avoid lock-order-inversion issues.
    auto isolate_info = std::make_unique<IsolateInfo>(isolate, log_code);
    base::MutexGuard guard(&mutex_);
    DCHECK_EQ(0, isolates_.count(isolate));
    isolates_.emplace(isolate, std::move(isolate_info));
  }
  if (log_code) {
    // Log existing wrappers (which are shared across isolates).
    GetWasmImportWrapperCache()->LogForIsolate(isolate);
  }

  // Install sampling GC callback.
  // TODO(v8:7424): For now we sample module sizes in a GC callback. This will
  // bias samples towards apps with high memory pressure. We should switch to
  // using sampling based on regular intervals independent of the GC.
  auto callback = [](v8::Isolate* v8_isolate, v8::GCType type,
                     v8::GCCallbackFlags flags, void* data) {
    Isolate* isolate = reinterpret_cast<Isolate*>(v8_isolate);
    Counters* counters = isolate->counters();
    WasmEngine* engine = GetWasmEngine();
    {
      base::MutexGuard lock(&engine->mutex_);
      DCHECK_EQ(1, engine->isolates_.count(isolate));
      for (auto* native_module : engine->isolates_[isolate]->native_modules) {
        native_module->SampleCodeSize(counters);
      }
    }
    // Also sample overall metadata size (this includes the metadata size of
    // individual NativeModules; we are summing that up twice, which could be
    // improved performance-wise).
    // The engine-wide metadata also includes global storage e.g. for the type
    // canonicalizer.
    Histogram* metadata_histogram = counters->wasm_engine_metadata_size_kb();
    if (metadata_histogram->Enabled()) {
      size_t engine_meta_data = engine->EstimateCurrentMemoryConsumption();
      metadata_histogram->AddSample(static_cast<int>(engine_meta_data / KB));
    }
  };
  isolate->heap()->AddGCEpilogueCallback(callback, v8::kGCTypeMarkSweepCompact,
                                         nullptr);

#ifdef V8_ENABLE_WASM_GDB_REMOTE_DEBUGGING
  if (gdb_server_) {
    gdb_server_->AddIsolate(isolate);
  }
#endif  // V8_ENABLE_WASM_GDB_REMOTE_DEBUGGING
}

void WasmEngine::RemoveIsolate(Isolate* isolate) {
#ifdef V8_ENABLE_WASM_GDB_REMOTE_DEBUGGING
  if (gdb_server_) {
    gdb_server_->RemoveIsolate(isolate);
  }
#endif  // V8_ENABLE_WASM_GDB_REMOTE_DEBUGGING

  // Keep a WasmCodeRefScope which dies after the {mutex_} is released, to avoid
  // deadlock when code actually dies, as that requires taking the {mutex_}.
  // Also, keep the NativeModules themselves alive. The isolate is shutting
  // down, so the heap will not do that any more.
  std::map<NativeModule*, std::shared_ptr<NativeModule>>
      native_modules_with_code_to_log;
  WasmCodeRefScope code_ref_scope_for_dead_code;

  base::MutexGuard guard(&mutex_);

  // Lookup the IsolateInfo; do not remove it yet (that happens below).
  auto isolates_it = isolates_.find(isolate);
  DCHECK_NE(isolates_.end(), isolates_it);
  IsolateInfo* isolate_info = isolates_it->second.get();

  // Remove the isolate from the per-native-module info, and other cleanup.
  for (auto* native_module : isolate_info->native_modules) {
    DCHECK_EQ(1, native_modules_.count(native_module));
    NativeModuleInfo* native_module_info =
        native_modules_.find(native_module)->second.get();

    // Check that the {NativeModule::log_code_} field has the expected value,
    // and update if the dying isolate was the last one with code logging
    // enabled.
    auto has_isolate_with_code_logging = [this, native_module_info] {
      return std::any_of(native_module_info->isolates.begin(),
                         native_module_info->isolates.end(),
                         [this](Isolate* isolate) {
                           return isolates_.find(isolate)->second->log_codes;
                         });
    };
    DCHECK_EQ(native_module->log_code(), has_isolate_with_code_logging());
    DCHECK_EQ(1, native_module_info->isolates.count(isolate));
    native_module_info->isolates.erase(isolate);
    if (native_module->log_code() && !has_isolate_with_code_logging()) {
      DisableCodeLogging(native_module);
    }

    // Remove any debug code and other info for this isolate.
    if (native_module->HasDebugInfo()) {
      native_module->GetDebugInfo()->RemoveIsolate(isolate);
    }
  }

  // Abort any outstanding GC.
  if (current_gc_info_) {
    if (RemoveIsolateFromCurrentGC(isolate)) PotentiallyFinishCurrentGC();
  }

  // Clear the {code_to_log} vector.
  for (auto& [script_id, code_to_log] : isolate_info->code_to_log) {
    for (WasmCode* code : code_to_log.code) {
      if (!native_modules_with_code_to_log.count(code->native_module())) {
        std::shared_ptr<NativeModule> shared_native_module =
            native_modules_[code->native_module()]->weak_ptr.lock();
        if (!shared_native_module) {
          // The module is dying already; there's no need to decrement the ref
          // count and add the code to the WasmCodeRefScope.
          continue;
        }
        native_modules_with_code_to_log.insert(std::make_pair(
            code->native_module(), std::move(shared_native_module)));
      }
      // Keep a reference in the {code_ref_scope_for_dead_code} such that the
      // code cannot become dead immediately.
      WasmCodeRefScope::AddRef(code);
      code->DecRefOnLiveCode();
    }
  }
  isolate_info->code_to_log.clear();

  // Finally remove the {IsolateInfo} for this isolate.
  isolates_.erase(isolates_it);
}

void WasmEngine::LogCode(base::Vector<WasmCode*> code_vec) {
  if (code_vec.empty()) return;
  NativeModule* native_module = code_vec[0]->native_module();
  if (!native_module->log_code()) return;
  using TaskToSchedule =
      std::pair<std::shared_ptr<v8::TaskRunner>, std::unique_ptr<LogCodesTask>>;
  std::vector<TaskToSchedule> to_schedule;
  {
    base::MutexGuard guard(&mutex_);
    DCHECK_EQ(1, native_modules_.count(native_module));
    NativeModuleInfo* native_module_info =
        native_modules_.find(native_module)->second.get();
    for (Isolate* isolate : native_module_info->isolates) {
      DCHECK_EQ(1, isolates_.count(isolate));
      IsolateInfo* info = isolates_[isolate].get();
      if (info->log_codes == false) continue;

      auto script_it = info->scripts.find(native_module);
      // If the script does not yet exist, logging will happen later. If the
      // weak handle is cleared already, we also don't need to log any more.
      if (script_it == info->scripts.end()) continue;

      // If there is no code scheduled to be logged already in that isolate,
      // then schedule a new task and also set an interrupt to log the newly
      // added code as soon as possible.
      if (info->code_to_log.empty()) {
        isolate->stack_guard()->RequestLogWasmCode();
        to_schedule.emplace_back(info->foreground_task_runner,
                                 std::make_unique<LogCodesTask>(isolate));
      }

      WeakScriptHandle& weak_script_handle = script_it->second;
      auto& log_entry = info->code_to_log[weak_script_handle.script_id()];
      if (!log_entry.source_url) {
        log_entry.source_url = weak_script_handle.source_url();
      }
      log_entry.code.insert(log_entry.code.end(), code_vec.begin(),
                            code_vec.end());

      // Increment the reference count for the added {log_entry.code} entries.
      for (WasmCode* code : code_vec) {
        DCHECK_EQ(native_module, code->native_module());
        code->IncRef();
      }
    }
  }
  for (auto& [runner, task] : to_schedule) {
    runner->PostTask(std::move(task));
  }
}

bool WasmEngine::LogWrapperCode(WasmCode* code) {
  // Wrappers don't belong to any particular NativeModule.
  DCHECK_NULL(code->native_module());
  // Fast path:
  if (!num_modules_with_code_logging_.load(std::memory_order_relaxed)) {
    return false;
  }

  using TaskToSchedule =
      std::pair<std::shared_ptr<v8::TaskRunner>, std::unique_ptr<LogCodesTask>>;
  std::vector<TaskToSchedule> to_schedule;
  bool did_trigger_code_logging = false;
  {
    base::MutexGuard guard(&mutex_);
    for (const auto& entry : isolates_) {
      Isolate* isolate = entry.first;
      IsolateInfo* info = entry.second.get();
      if (info->log_codes == false) continue;
      did_trigger_code_logging = true;

      // If this is the first code to log in that isolate, request an interrupt
      // to log the newly added code as soon as possible.
      if (info->code_to_log.empty()) {
        isolate->stack_guard()->RequestLogWasmCode();
        to_schedule.emplace_back(info->foreground_task_runner,
                                 std::make_unique<LogCodesTask>(isolate));
      }

      constexpr int kNoScriptId = -1;
      auto& log_entry = info->code_to_log[kNoScriptId];
      log_entry.code.push_back(code);

      // Increment the reference count for the added {log_entry.code} entry.
      // TODO(jkummerow): It might be nice to have a custom smart pointer
      // that manages updating the refcount for the WasmCode it holds.
      code->IncRef();
    }
    DCHECK_EQ(did_trigger_code_logging, num_modules_with_code_logging_.load(
                                            std::memory_order_relaxed) > 0);
  }
  for (auto& [runner, task] : to_schedule) {
    runner->PostTask(std::move(task));
  }

  return did_trigger_code_logging;
}

void WasmEngine::EnableCodeLogging(Isolate* isolate) {
  base::MutexGuard guard(&mutex_);
  auto it = isolates_.find(isolate);
  DCHECK_NE(isolates_.end(), it);
  IsolateInfo* info = it->second.get();
  if (info->log_codes) return;
  info->log_codes = true;
  // Also set {NativeModule::log_code_} for all native modules currently used by
  // this isolate.
  for (NativeModule* native_module : info->native_modules) {
    if (!native_module->log_code()) EnableCodeLogging(native_module);
  }
}

void WasmEngine::EnableCodeLogging(NativeModule* native_module) {
  // The caller should hold the mutex.
  mutex_.AssertHeld();
  DCHECK(!native_module->log_code());
  native_module->EnableCodeLogging();
  num_modules_with_code_logging_.fetch_add(1, std::memory_order_relaxed);
  // Check the accuracy of {num_modules_with_code_logging_}.
  DCHECK_EQ(
      num_modules_with_code_logging_.load(std::memory_order_relaxed),
      std::count_if(
          native_modules_.begin(), native_modules_.end(),
          [](std::pair<NativeModule* const, std::unique_ptr<NativeModuleInfo>>&
                 pair) { return pair.first->log_code(); }));
}

void WasmEngine::DisableCodeLogging(NativeModule* native_module) {
  // The caller should hold the mutex.
  mutex_.AssertHeld();
  DCHECK(native_module->log_code());
  native_module->DisableCodeLogging();
  num_modules_with_code_logging_.fetch_sub(1, std::memory_order_relaxed);
  // Check the accuracy of {num_modules_with_code_logging_}.
  DCHECK_EQ(
      num_modules_with_code_logging_.load(std::memory_order_relaxed),
      std::count_if(
          native_modules_.begin(), native_modules_.end(),
          [](std::pair<NativeModule* const, std::unique_ptr<NativeModuleInfo>>&
                 pair) { return pair.first->log_code(); }));
}

void WasmEngine::LogOutstandingCodesForIsolate(Isolate* isolate) {
  // Under the mutex, get the vector of wasm code to log. Then log and decrement
  // the ref count without holding the mutex.
  std::unordered_map<int, IsolateInfo::CodeToLogPerScript> code_to_log;
  {
    base::MutexGuard guard(&mutex_);
    DCHECK_EQ(1, isolates_.count(isolate));
    code_to_log.swap(isolates_[isolate]->code_to_log);
  }

  // Check again whether we still need to log code.
  bool should_log = WasmCode::ShouldBeLogged(isolate);

  TRACE_EVENT0("v8.wasm", "wasm.LogCode");
  for (auto& [script_id, code_to_log] : code_to_log) {
    for (WasmCode* code : code_to_log.code) {
      if (should_log) {
        const char* source_url = code_to_log.source_url.get();
        // The source URL can be empty for eval()'ed scripts.
        if (!source_url) source_url = "";
        code->LogCode(isolate, source_url, script_id);
      }
    }
    WasmCode::DecrementRefCount(base::VectorOf(code_to_log.code));
  }
}

std::shared_ptr<NativeModule> WasmEngine::NewNativeModule(
    Isolate* isolate, WasmEnabledFeatures enabled_features,
    WasmDetectedFeatures detected_features, CompileTimeImports compile_imports,
    std::shared_ptr<const WasmModule> module, size_t code_size_estimate) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.wasm.detailed"),
               "wasm.NewNativeModule");
#ifdef V8_ENABLE_WASM_GDB_REMOTE_DEBUGGING
  if (v8_flags.wasm_gdb_remote && !gdb_server_) {
    gdb_server_ = gdb_server::GdbServer::Create();
    gdb_server_->AddIsolate(isolate);
  }
#endif  // V8_ENABLE_WASM_GDB_REMOTE_DEBUGGING

  // Initialize the import wrapper cache if that hasn't happened yet.
  GetWasmImportWrapperCache()->LazyInitialize(isolate);

  std::shared_ptr<NativeModule> native_module =
      GetWasmCodeManager()->NewNativeModule(
          isolate, enabled_features, detected_features,
          std::move(compile_imports), code_size_estimate, std::move(module));
  base::MutexGuard lock(&mutex_);
  if (V8_UNLIKELY(v8_flags.experimental_wasm_pgo_to_file)) {
    if (!native_modules_kept_alive_for_pgo) {
      native_modules_kept_alive_for_pgo =
          new std::vector<std::shared_ptr<NativeModule>>;
    }
    native_modules_kept_alive_for_pgo->emplace_back(native_module);
  }
  auto [iterator, inserted] = native_modules_.insert(std::make_pair(
      native_module.get(), std::make_unique<NativeModuleInfo>(native_module)));
  DCHECK(inserted);
  NativeModuleInfo* native_module_info = iterator->second.get();
  native_module_info->isolates.insert(isolate);
  DCHECK_EQ(1, isolates_.count(isolate));
  IsolateInfo* isolate_info = isolate
```