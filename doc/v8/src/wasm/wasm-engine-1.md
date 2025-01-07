Response: The user has provided the second part of a C++ source code file and is asking for a summary of its functionality, along with JavaScript examples illustrating any connections to JavaScript. This is the continuation of the file described in the first part.

Based on the code, the main functions seem to revolve around managing WebAssembly modules and their compiled code, focusing on caching, garbage collection, and interaction with JavaScript isolates.

Here's a breakdown of the code's key areas:

1. **Native Module Management:**  Functions like `MaybeGetNativeModule`, `UpdateNativeModuleCache`, `FreeNativeModule` deal with retrieving, updating, and releasing cached WebAssembly modules (`NativeModule`). This involves a cache (`native_module_cache_`) and tracking which isolates are using each module.

2. **Garbage Collection for Wasm Code:** A significant portion of the code implements a garbage collection mechanism specifically for WebAssembly code. This includes:
    *   Tracking potentially dead code (`AddPotentiallyDeadCode`).
    *   Initiating garbage collection cycles (`TriggerGC`).
    *   Reporting live code from isolates during GC (`ReportLiveCodeForGC`, `ReportLiveCodeFromStackForGC`).
    *   Freeing dead code (`FreeDeadCode`, `FreeDeadCodeLocked`).
    *   Using a `CurrentGCInfo` struct to manage the state of a GC cycle.

3. **Integration with JavaScript Isolates:** The code manages the association between WebAssembly modules and JavaScript isolates (`Isolate`). It tracks which isolates use which modules and handles actions like setting debug state and enabling code logging per isolate. The `GetOrCreateScript` function links a native module to a JavaScript `Script` object.

4. **Streaming Compilation Ownership:**  The `GetStreamingCompilationOwnership` and `StreamingCompilationFailed` functions likely handle scenarios where a module is being compiled in the background while being streamed.

5. **Memory Management and Statistics:** The `EstimateCurrentMemoryConsumption` function provides an estimate of the memory used by the `WasmEngine`. Counters are used to track module loading and GC activity.

6. **Global Wasm State:** The `GlobalWasmState` struct and related functions (`InitializeOncePerProcess`, `GlobalTearDown`, `GetWasmEngine`, `GetWasmCodeManager`, `GetWasmImportWrapperCache`) manage process-wide WebAssembly resources.

7. **Configuration Limits:** Functions like `max_mem32_pages`, `max_mem64_pages`, `max_table_init_entries`, and `max_module_size` define and retrieve limits related to WebAssembly memory, tables, and module sizes, potentially influenced by command-line flags.

**Relationship to JavaScript:**

The functions in this part of the code directly support the execution of WebAssembly within a JavaScript environment. The key connection points are:

*   **Module Loading and Caching:** When JavaScript code uses `WebAssembly.instantiate` or `WebAssembly.compile`, the V8 engine (which includes this C++ code) will check the cache (`native_module_cache_`) for a compiled module. If found, it's reused, improving performance.
*   **Isolate Integration:** Each JavaScript "realm" or global context runs within an isolate. This code manages the association of WebAssembly modules with these isolates, allowing multiple independent JavaScript environments to use the same underlying compiled WebAssembly code (if caching is in effect).
*   **Garbage Collection of Wasm:** When a WebAssembly module or its associated code is no longer reachable from JavaScript, the garbage collection mechanisms implemented here will reclaim the memory used by that code.
*   **Script Objects:** The `GetOrCreateScript` function creates a JavaScript `Script` object that represents the WebAssembly module. This allows the JavaScript debugger and profiler to interact with the WebAssembly code.
*   **Error Handling:** The `UpdateNativeModuleCache` function handles cases where compilation errors occur.

**JavaScript Examples:**

1. **Module Instantiation and Caching:**

    ```javascript
    const wasmCode = await fetch('my_module.wasm').then(response =>
      response.arrayBuffer()
    );
    const module1 = await WebAssembly.instantiate(wasmCode);
    const module2 = await WebAssembly.instantiate(wasmCode); // Likely a cache hit

    console.log(module1.instance.exports.add(5, 3));
    console.log(module2.instance.exports.add(10, 2));
    ```

    In this example, when `WebAssembly.instantiate` is called the second time with the same `wasmCode`, the `WasmEngine::MaybeGetNativeModule` function (from this C++ file) will likely find the compiled module in the cache and return it, avoiding recompilation.

2. **Garbage Collection:**

    ```javascript
    let instance = null;
    async function loadAndRun() {
      const wasmCode = await fetch('my_module.wasm').then(response =>
        response.arrayBuffer()
      );
      const module = await WebAssembly.instantiate(wasmCode);
      instance = module.instance;
      console.log(instance.exports.add(7, 1));
    }

    loadAndRun();
    instance = null; // Make the WebAssembly instance unreachable

    // Later, the V8 garbage collector (triggered by memory pressure or other events)
    // will potentially invoke the WasmEngine's GC functions to free the
    // memory used by the 'my_module.wasm' code if it's no longer referenced.
    ```

    Here, setting `instance` to `null` makes the WebAssembly module eligible for garbage collection. The `WasmEngine`'s GC logic, especially functions like `AddPotentiallyDeadCode` and `TriggerGC`, will eventually be involved in reclaiming the memory.

3. **Debugging:**

    When using the JavaScript debugger on WebAssembly code, the `WasmEngine`'s debug state management (using `SetDebugState`) comes into play. Setting breakpoints or stepping through WebAssembly code in the debugger relies on this functionality.

    ```javascript
    // In a debugger context:
    // Set a breakpoint in the WebAssembly module's 'add' function.
    // When the 'add' function is called from JavaScript, the debugger will stop
    // at the breakpoint, thanks to the WasmEngine's debugging support.
    console.log(module1.instance.exports.add(2, 8));
    ```

This second part of the `wasm-engine.cc` file focuses on the lifecycle management of compiled WebAssembly modules, including caching and garbage collection, and its tight integration with the JavaScript execution environment within V8 isolates.

这是 `v8/src/wasm/wasm-engine.cc` 文件的第二部分，它主要负责 WebAssembly 模块的生命周期管理，包括缓存、垃圾回收以及与 JavaScript 隔离（Isolate）的集成。

以下是本部分代码的主要功能归纳：

**1. 原生模块（NativeModule）的管理和缓存：**

*   **`MaybeGetNativeModule`**: 尝试从缓存中获取已编译的 WebAssembly 模块。如果找到，则将其与当前的 JavaScript 隔离关联。如果模块启用了调试或代码日志记录，则会进行相应的设置。
*   **`UpdateNativeModuleCache`**: 更新原生模块的缓存。这通常发生在模块编译成功或失败后。它也会处理将模块与当前 JavaScript 隔离关联，并根据隔离的设置更新模块的调试状态和代码日志记录。
*   **`FreeNativeModule`**: 释放原生模块占用的资源。这包括从缓存中移除模块，解除与所有关联的 JavaScript 隔离的关联，并清理相关的代码对象。

**2. WebAssembly 代码的垃圾回收 (GC)：**

*   **`AddPotentiallyDeadCode`**:  将可能不再使用的 WebAssembly 代码添加到待回收的集合中。当潜在的垃圾代码达到一定阈值时，可能会触发垃圾回收。
*   **`ReportLiveCodeForGC`**:  JavaScript 隔离报告在 GC 期间仍然存活的 WebAssembly 代码。
*   **`ReportLiveCodeFromStackForGC`**: 扫描 JavaScript 隔离的调用栈，找出仍然被引用的 WebAssembly 代码。这对于确定哪些代码需要保留至关重要。
*   **`FreeDeadCode` 和 `FreeDeadCodeLocked`**:  实际释放不再使用的 WebAssembly 代码和导入包装器。
*   **`TriggerGC`**: 触发 WebAssembly 代码的垃圾回收过程。
*   **`RemoveIsolateFromCurrentGC`**:  当一个 JavaScript 隔离完成其 WebAssembly 代码的存活报告后，将其从当前的 GC 流程中移除。
*   **`PotentiallyFinishCurrentGC`**:  检查当前的 WebAssembly 代码垃圾回收是否可以完成，并释放不再使用的代码。

**3. 与 JavaScript 隔离的集成：**

*   **跟踪模块与隔离的关联**:  代码维护了哪些 JavaScript 隔离正在使用哪些 WebAssembly 模块。
*   **调试状态和代码日志**:  根据 JavaScript 隔离的设置，启用或禁用 WebAssembly 模块的调试状态和代码日志记录。
*   **`GetOrCreateScript`**: 为给定的 WebAssembly 模块创建一个 JavaScript `Script` 对象，并将其与 JavaScript 隔离关联。这使得 JavaScript 能够引用和管理 WebAssembly 模块。

**4. 流式编译管理：**

*   **`GetStreamingCompilationOwnership`**:  检查是否可以获取特定 WebAssembly 模块的流式编译所有权。
*   **`StreamingCompilationFailed`**:  当流式编译失败时通知引擎。

**5. 内存管理和统计：**

*   **`EstimateCurrentMemoryConsumption`**:  估算 `WasmEngine` 当前的内存消耗。
*   **性能计数器**: 代码中使用了计数器来跟踪 WebAssembly 模块的加载和 GC 活动。

**6. 全局 WebAssembly 状态：**

*   **`InitializeOncePerProcess`**:  在进程启动时初始化全局的 WebAssembly 状态。
*   **`GlobalTearDown`**:  在进程关闭时清理全局的 WebAssembly 状态。
*   **`GetWasmEngine`、`GetWasmCodeManager`、`GetWasmImportWrapperCache`**:  提供对全局 WebAssembly 引擎、代码管理器和导入包装器缓存的访问。

**7. 配置限制：**

*   **`max_mem32_pages`、`max_mem64_pages`、`max_table_init_entries`、`max_module_size`**:  定义和获取 WebAssembly 内存页数、表初始化条目和模块大小的限制。

**与 JavaScript 的关系以及示例：**

这段 C++ 代码是 V8 引擎中负责执行 WebAssembly 的核心部分。它与 JavaScript 的交互主要体现在以下方面：

*   **模块加载和实例化**: 当 JavaScript 代码使用 `WebAssembly.instantiate` 或 `WebAssembly.compile` 加载 WebAssembly 模块时，这段 C++ 代码会负责编译或从缓存中加载模块，并将其与当前的 JavaScript 隔离关联。

    ```javascript
    // JavaScript 代码
    async function loadWasm() {
      const response = await fetch('my_module.wasm');
      const buffer = await response.arrayBuffer();
Prompt: 
```
这是目录为v8/src/wasm/wasm-engine.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
s_.find(isolate)->second.get();
  isolate_info->native_modules.insert(native_module.get());
  if (isolate_info->keep_in_debug_state) {
    native_module->SetDebugState(kDebugging);
  }
  if (isolate_info->log_codes) {
    EnableCodeLogging(native_module.get());
  }

  // Record memory protection key support.
  if (!isolate_info->pku_support_sampled) {
    isolate_info->pku_support_sampled = true;
    auto* histogram =
        isolate->counters()->wasm_memory_protection_keys_support();
    bool has_mpk = WasmCodeManager::HasMemoryProtectionKeySupport();
    histogram->AddSample(has_mpk ? 1 : 0);
  }

  isolate->counters()->wasm_modules_per_isolate()->AddSample(
      static_cast<int>(isolate_info->native_modules.size()));
  isolate->counters()->wasm_modules_per_engine()->AddSample(
      static_cast<int>(native_modules_.size()));
  return native_module;
}

std::shared_ptr<NativeModule> WasmEngine::MaybeGetNativeModule(
    ModuleOrigin origin, base::Vector<const uint8_t> wire_bytes,
    const CompileTimeImports& compile_imports, Isolate* isolate) {
  TRACE_EVENT1("v8.wasm", "wasm.GetNativeModuleFromCache", "wire_bytes",
               wire_bytes.size());
  std::shared_ptr<NativeModule> native_module =
      native_module_cache_.MaybeGetNativeModule(origin, wire_bytes,
                                                compile_imports);
  bool remove_all_code = false;
  if (native_module) {
    TRACE_EVENT0("v8.wasm", "CacheHit");
    base::MutexGuard guard(&mutex_);
    auto& native_module_info = native_modules_[native_module.get()];
    if (!native_module_info) {
      native_module_info = std::make_unique<NativeModuleInfo>(native_module);
    }
    native_module_info->isolates.insert(isolate);
    auto* isolate_data = isolates_[isolate].get();
    isolate_data->native_modules.insert(native_module.get());
    if (isolate_data->keep_in_debug_state && !native_module->IsInDebugState()) {
      remove_all_code = true;
      native_module->SetDebugState(kDebugging);
    }
    if (isolate_data->log_codes && !native_module->log_code()) {
      EnableCodeLogging(native_module.get());
    }
  }
  if (remove_all_code) {
    WasmCodeRefScope ref_scope;
    native_module->RemoveCompiledCode(
        NativeModule::RemoveFilter::kRemoveNonDebugCode);
  }
  return native_module;
}

std::shared_ptr<NativeModule> WasmEngine::UpdateNativeModuleCache(
    bool has_error, std::shared_ptr<NativeModule> native_module,
    Isolate* isolate) {
  // Keep the previous pointer, but as a `void*`, because we only want to use it
  // later to compare pointers, and never need to dereference it.
  void* prev = native_module.get();
  native_module =
      native_module_cache_.Update(std::move(native_module), has_error);
  if (prev == native_module.get()) return native_module;
  bool remove_all_code = false;
  {
    base::MutexGuard guard(&mutex_);
    DCHECK_EQ(1, native_modules_.count(native_module.get()));
    native_modules_[native_module.get()]->isolates.insert(isolate);
    DCHECK_EQ(1, isolates_.count(isolate));
    auto* isolate_data = isolates_[isolate].get();
    isolate_data->native_modules.insert(native_module.get());
    if (isolate_data->keep_in_debug_state && !native_module->IsInDebugState()) {
      remove_all_code = true;
      native_module->SetDebugState(kDebugging);
    }
    if (isolate_data->log_codes && !native_module->log_code()) {
      EnableCodeLogging(native_module.get());
    }
  }
  if (remove_all_code) {
    WasmCodeRefScope ref_scope;
    native_module->RemoveCompiledCode(
        NativeModule::RemoveFilter::kRemoveNonDebugCode);
  }
  return native_module;
}

bool WasmEngine::GetStreamingCompilationOwnership(
    size_t prefix_hash, const CompileTimeImports& compile_imports) {
  TRACE_EVENT0("v8.wasm", "wasm.GetStreamingCompilationOwnership");
  if (native_module_cache_.GetStreamingCompilationOwnership(prefix_hash,
                                                            compile_imports)) {
    return true;
  }
  // This is only a marker, not for tracing execution time. There should be a
  // later "wasm.GetNativeModuleFromCache" event for trying to get the module
  // from the cache.
  TRACE_EVENT0("v8.wasm", "CacheHit");
  return false;
}

void WasmEngine::StreamingCompilationFailed(
    size_t prefix_hash, const CompileTimeImports& compile_imports) {
  native_module_cache_.StreamingCompilationFailed(prefix_hash, compile_imports);
}

void WasmEngine::FreeNativeModule(NativeModule* native_module) {
  base::MutexGuard guard(&mutex_);
  auto module = native_modules_.find(native_module);
  DCHECK_NE(native_modules_.end(), module);
  auto part_of_native_module = [native_module](WasmCode* code) {
    return code->native_module() == native_module;
  };
  for (Isolate* isolate : module->second->isolates) {
    DCHECK_EQ(1, isolates_.count(isolate));
    IsolateInfo* info = isolates_[isolate].get();
    DCHECK_EQ(1, info->native_modules.count(native_module));
    info->native_modules.erase(native_module);
    info->scripts.erase(native_module);

    // Flush the Wasm code lookup cache, since it may refer to some
    // code within native modules that we are going to release (if a
    // Managed<wasm::NativeModule> object is no longer referenced).
    GetWasmCodeManager()->FlushCodeLookupCache(isolate);

    // If there are {WasmCode} objects of the deleted {NativeModule}
    // outstanding to be logged in this isolate, remove them. Decrementing the
    // ref count is not needed, since the {NativeModule} dies anyway.
    for (auto& log_entry : info->code_to_log) {
      std::vector<WasmCode*>& code = log_entry.second.code;
      auto new_end =
          std::remove_if(code.begin(), code.end(), part_of_native_module);
      code.erase(new_end, code.end());
    }
    // Now remove empty entries in {code_to_log}.
    for (auto it = info->code_to_log.begin(), end = info->code_to_log.end();
         it != end;) {
      if (it->second.code.empty()) {
        it = info->code_to_log.erase(it);
      } else {
        ++it;
      }
    }
  }
  // If there is a GC running which has references to code contained in the
  // deleted {NativeModule}, remove those references.
  if (current_gc_info_) {
    for (auto it = current_gc_info_->dead_code.begin(),
              end = current_gc_info_->dead_code.end();
         it != end;) {
      if ((*it)->native_module() == native_module) {
        it = current_gc_info_->dead_code.erase(it);
      } else {
        ++it;
      }
    }
    TRACE_CODE_GC("Native module %p died, reducing dead code objects to %zu.\n",
                  native_module, current_gc_info_->dead_code.size());
  }
  // If any code objects are currently tracked as dead or near-dead, remove
  // references belonging to the NativeModule that's being deleted.
  std::erase_if(dead_code_, part_of_native_module);
  std::erase_if(potentially_dead_code_, part_of_native_module);

  if (native_module->log_code()) DisableCodeLogging(native_module);

  native_module_cache_.Erase(native_module);
  native_modules_.erase(module);
}

void WasmEngine::ReportLiveCodeForGC(Isolate* isolate,
                                     base::Vector<WasmCode*> live_code) {
  TRACE_EVENT0("v8.wasm", "wasm.ReportLiveCodeForGC");
  TRACE_CODE_GC("Isolate %d reporting %zu live code objects.\n", isolate->id(),
                live_code.size());
  base::MutexGuard guard(&mutex_);
  // This report might come in late (note that we trigger both a stack guard and
  // a foreground task). In that case, ignore it.
  if (current_gc_info_ == nullptr) return;
  if (!RemoveIsolateFromCurrentGC(isolate)) return;
  isolate->counters()->wasm_module_num_triggered_code_gcs()->AddSample(
      current_gc_info_->gc_sequence_index);
  for (WasmCode* code : live_code) current_gc_info_->dead_code.erase(code);
  PotentiallyFinishCurrentGC();
}

namespace {
void ReportLiveCodeFromFrameForGC(
    Isolate* isolate, StackFrame* frame,
    std::unordered_set<wasm::WasmCode*>& live_wasm_code) {
  if (frame->type() == StackFrame::WASM) {
    WasmFrame* wasm_frame = WasmFrame::cast(frame);
    WasmCode* code = wasm_frame->wasm_code();
    live_wasm_code.insert(code);
#if V8_TARGET_ARCH_X64
    if (code->for_debugging()) {
      Address osr_target =
          base::Memory<Address>(wasm_frame->fp() - kOSRTargetOffset);
      if (osr_target) {
        WasmCode* osr_code =
            GetWasmCodeManager()->LookupCode(isolate, osr_target);
        DCHECK_NOT_NULL(osr_code);
        live_wasm_code.insert(osr_code);
      }
    }
#endif
  } else if (frame->type() == StackFrame::WASM_TO_JS) {
    live_wasm_code.insert(static_cast<WasmToJsFrame*>(frame)->wasm_code());
  }
}
}  // namespace

void WasmEngine::ReportLiveCodeFromStackForGC(Isolate* isolate) {
  wasm::WasmCodeRefScope code_ref_scope;
  std::unordered_set<wasm::WasmCode*> live_wasm_code;

  for (const std::unique_ptr<StackMemory>& stack : isolate->wasm_stacks()) {
    if (stack->IsActive()) {
      // The active stack's jump buffer does not match the current state, use
      // the thread info below instead.
      continue;
    }
    for (StackFrameIterator it(isolate, stack.get()); !it.done();
         it.Advance()) {
      StackFrame* const frame = it.frame();
      ReportLiveCodeFromFrameForGC(isolate, frame, live_wasm_code);
    }
  }

  for (StackFrameIterator it(isolate, isolate->thread_local_top(),
                             StackFrameIterator::FirstStackOnly{});
       !it.done(); it.Advance()) {
    StackFrame* const frame = it.frame();
    ReportLiveCodeFromFrameForGC(isolate, frame, live_wasm_code);
  }

  CheckNoArchivedThreads(isolate);

  // Flush the code lookup cache, since it may refer to some code we
  // are going to release.
  GetWasmCodeManager()->FlushCodeLookupCache(isolate);

  ReportLiveCodeForGC(
      isolate, base::OwnedVector<WasmCode*>::Of(live_wasm_code).as_vector());
}

bool WasmEngine::AddPotentiallyDeadCode(WasmCode* code) {
  base::MutexGuard guard(&mutex_);
  if (dead_code_.contains(code)) return false;  // Code is already dead.
  auto added = potentially_dead_code_.insert(code);
  if (!added.second) return false;  // An entry already existed.
  new_potentially_dead_code_size_ += code->instructions().size();
  if (v8_flags.wasm_code_gc) {
    // Trigger a GC if 64kB plus 10% of committed code are potentially dead.
    size_t dead_code_limit =
        v8_flags.stress_wasm_code_gc
            ? 0
            : 64 * KB + GetWasmCodeManager()->committed_code_space() / 10;
    if (new_potentially_dead_code_size_ > dead_code_limit) {
      bool inc_gc_count =
          num_code_gcs_triggered_ < std::numeric_limits<int8_t>::max();
      if (current_gc_info_ == nullptr) {
        if (inc_gc_count) ++num_code_gcs_triggered_;
        TRACE_CODE_GC(
            "Triggering GC (potentially dead: %zu bytes; limit: %zu bytes).\n",
            new_potentially_dead_code_size_, dead_code_limit);
        TriggerGC(num_code_gcs_triggered_);
      } else if (current_gc_info_->next_gc_sequence_index == 0) {
        if (inc_gc_count) ++num_code_gcs_triggered_;
        TRACE_CODE_GC(
            "Scheduling another GC after the current one (potentially dead: "
            "%zu bytes; limit: %zu bytes).\n",
            new_potentially_dead_code_size_, dead_code_limit);
        current_gc_info_->next_gc_sequence_index = num_code_gcs_triggered_;
        DCHECK_NE(0, current_gc_info_->next_gc_sequence_index);
      }
    }
  }
  return true;
}

void WasmEngine::FreeDeadCode(const DeadCodeMap& dead_code,
                              std::vector<WasmCode*>& dead_wrappers) {
  base::MutexGuard guard(&mutex_);
  FreeDeadCodeLocked(dead_code, dead_wrappers);
}

void WasmEngine::FreeDeadCodeLocked(const DeadCodeMap& dead_code,
                                    std::vector<WasmCode*>& dead_wrappers) {
  TRACE_EVENT0("v8.wasm", "wasm.FreeDeadCode");
  mutex_.AssertHeld();
  for (auto& dead_code_entry : dead_code) {
    NativeModule* native_module = dead_code_entry.first;
    const std::vector<WasmCode*>& code_vec = dead_code_entry.second;
    TRACE_CODE_GC("Freeing %zu code object%s of module %p.\n", code_vec.size(),
                  code_vec.size() == 1 ? "" : "s", native_module);
    for (WasmCode* code : code_vec) {
      DCHECK(dead_code_.contains(code));
      dead_code_.erase(code);
    }
    native_module->FreeCode(base::VectorOf(code_vec));
  }
  if (dead_wrappers.size()) {
    TRACE_CODE_GC("Freeing %zu wrapper%s.\n", dead_wrappers.size(),
                  dead_wrappers.size() == 1 ? "" : "s");
    for (WasmCode* code : dead_wrappers) {
      DCHECK(dead_code_.contains(code));
      dead_code_.erase(code);
    }
    GetWasmImportWrapperCache()->Free(dead_wrappers);
  }
}

Handle<Script> WasmEngine::GetOrCreateScript(
    Isolate* isolate, const std::shared_ptr<NativeModule>& native_module,
    base::Vector<const char> source_url) {
  {
    base::MutexGuard guard(&mutex_);
    DCHECK_EQ(1, isolates_.count(isolate));
    auto& scripts = isolates_[isolate]->scripts;
    auto it = scripts.find(native_module.get());
    if (it != scripts.end()) {
      Handle<Script> weak_global_handle = it->second.handle();
      if (weak_global_handle.is_null()) {
        scripts.erase(it);
      } else {
        return Handle<Script>::New(*weak_global_handle, isolate);
      }
    }
  }
  // Temporarily release the mutex to let the GC collect native modules.
  auto script = CreateWasmScript(isolate, native_module, source_url);
  {
    base::MutexGuard guard(&mutex_);
    DCHECK_EQ(1, isolates_.count(isolate));
    auto& scripts = isolates_[isolate]->scripts;
    DCHECK_EQ(0, scripts.count(native_module.get()));
    scripts.emplace(native_module.get(), WeakScriptHandle(script, isolate));
    return script;
  }
}

std::shared_ptr<OperationsBarrier>
WasmEngine::GetBarrierForBackgroundCompile() {
  return operations_barrier_;
}

void WasmEngine::TriggerGC(int8_t gc_sequence_index) {
  mutex_.AssertHeld();
  DCHECK_NULL(current_gc_info_);
  DCHECK(v8_flags.wasm_code_gc);
  new_potentially_dead_code_size_ = 0;
  current_gc_info_.reset(new CurrentGCInfo(gc_sequence_index));
  // Add all potentially dead code to this GC, and trigger a GC task in each
  // known isolate. We can't limit the isolates to those that contributed
  // potentially-dead WasmCode objects, because wrappers don't point back
  // at a NativeModule or Isolate.
  for (WasmCode* code : potentially_dead_code_) {
    current_gc_info_->dead_code.insert(code);
  }
  for (const auto& entry : isolates_) {
    Isolate* isolate = entry.first;
    auto& gc_task = current_gc_info_->outstanding_isolates[isolate];
    if (!gc_task) {
      auto new_task = std::make_unique<WasmGCForegroundTask>(isolate);
      gc_task = new_task.get();
      DCHECK_EQ(1, isolates_.count(isolate));
      isolates_[isolate]->foreground_task_runner->PostTask(std::move(new_task));
    }
    isolate->stack_guard()->RequestWasmCodeGC();
  }
  TRACE_CODE_GC(
      "Starting GC (nr %d). Number of potentially dead code objects: %zu\n",
      current_gc_info_->gc_sequence_index, current_gc_info_->dead_code.size());
  // Ensure that there are outstanding isolates that will eventually finish this
  // GC. If there are no outstanding isolates, we finish the GC immediately.
  PotentiallyFinishCurrentGC();
  DCHECK(current_gc_info_ == nullptr ||
         !current_gc_info_->outstanding_isolates.empty());
}

bool WasmEngine::RemoveIsolateFromCurrentGC(Isolate* isolate) {
  mutex_.AssertHeld();
  DCHECK_NOT_NULL(current_gc_info_);
  return current_gc_info_->outstanding_isolates.erase(isolate) != 0;
}

void WasmEngine::PotentiallyFinishCurrentGC() {
  mutex_.AssertHeld();
  TRACE_CODE_GC(
      "Remaining dead code objects: %zu; outstanding isolates: %zu.\n",
      current_gc_info_->dead_code.size(),
      current_gc_info_->outstanding_isolates.size());

  // If there are more outstanding isolates, return immediately.
  if (!current_gc_info_->outstanding_isolates.empty()) return;

  // All remaining code in {current_gc_info->dead_code} is really dead.
  // Move it from the set of potentially dead code to the set of dead code,
  // and decrement its ref count.
  size_t num_freed = 0;
  DeadCodeMap dead_code;
  std::vector<WasmCode*> dead_wrappers;
  for (WasmCode* code : current_gc_info_->dead_code) {
    DCHECK(potentially_dead_code_.contains(code));
    potentially_dead_code_.erase(code);
    DCHECK(!dead_code_.contains(code));
    dead_code_.insert(code);
    if (code->DecRefOnDeadCode()) {
      NativeModule* native_module = code->native_module();
      if (native_module) {
        dead_code[native_module].push_back(code);
      } else {
        dead_wrappers.push_back(code);
      }
      ++num_freed;
    }
  }

  FreeDeadCodeLocked(dead_code, dead_wrappers);

  TRACE_CODE_GC("Found %zu dead code objects, freed %zu.\n",
                current_gc_info_->dead_code.size(), num_freed);
  USE(num_freed);

  int8_t next_gc_sequence_index = current_gc_info_->next_gc_sequence_index;
  current_gc_info_.reset();
  if (next_gc_sequence_index != 0) TriggerGC(next_gc_sequence_index);
}

size_t WasmEngine::EstimateCurrentMemoryConsumption() const {
  UPDATE_WHEN_CLASS_CHANGES(WasmEngine, 808);
  UPDATE_WHEN_CLASS_CHANGES(IsolateInfo, 168);
  UPDATE_WHEN_CLASS_CHANGES(NativeModuleInfo, 56);
  UPDATE_WHEN_CLASS_CHANGES(CurrentGCInfo, 96);
  size_t result = sizeof(WasmEngine);
  result += type_canonicalizer_.EstimateCurrentMemoryConsumption();
  {
    base::MutexGuard lock(&mutex_);
    result += ContentSize(async_compile_jobs_);
    result += async_compile_jobs_.size() * sizeof(AsyncCompileJob);
    result += ContentSize(potentially_dead_code_);
    result += ContentSize(dead_code_);

    // TODO(14106): Do we care about {compilation_stats_}?
    // TODO(14106): Do we care about {code_tracer_}?

    result += ContentSize(isolates_);
    result += isolates_.size() * sizeof(IsolateInfo);
    for (const auto& [isolate, isolate_info] : isolates_) {
      result += ContentSize(isolate_info->native_modules);
      result += ContentSize(isolate_info->scripts);
      result += ContentSize(isolate_info->code_to_log);
    }

    result += ContentSize(native_modules_);
    result += native_modules_.size() * sizeof(NativeModuleInfo);
    for (const auto& [native_module, native_module_info] : native_modules_) {
      result += native_module->EstimateCurrentMemoryConsumption();
      result += ContentSize(native_module_info->isolates);
    }

    if (current_gc_info_) {
      result += sizeof(CurrentGCInfo);
      result += ContentSize(current_gc_info_->outstanding_isolates);
      result += ContentSize(current_gc_info_->dead_code);
    }
  }
  if (v8_flags.trace_wasm_offheap_memory) {
    PrintF("WasmEngine: %zu\n", result);
  }
  return result;
}

int WasmEngine::GetDeoptsExecutedCount() const {
  return deopts_executed_.load(std::memory_order::relaxed);
}

int WasmEngine::IncrementDeoptsExecutedCount() {
  int previous_value = deopts_executed_.fetch_add(1, std::memory_order_relaxed);
  return previous_value + 1;
}

namespace {

struct GlobalWasmState {
  // Note: The order of fields is important here, as the WasmEngine's destructor
  // must run first. It contains a barrier which ensures that background threads
  // finished, and that has to happen before the WasmCodeManager gets destroyed.
  WasmCodeManager code_manager;
  WasmImportWrapperCache import_wrapper_cache;
  WasmEngine engine;
};

GlobalWasmState* global_wasm_state = nullptr;

}  // namespace

// static
void WasmEngine::InitializeOncePerProcess() {
  DCHECK_NULL(global_wasm_state);
  global_wasm_state = new GlobalWasmState();

#ifdef V8_ENABLE_DRUMBRAKE
  if (v8_flags.wasm_jitless) {
    WasmInterpreter::InitializeOncePerProcess();
  }
#endif  // V8_ENABLE_DRUMBRAKE

  GetProcessWideWasmCodePointerTable()->Initialize();
}

// static
void WasmEngine::GlobalTearDown() {
#ifdef V8_ENABLE_DRUMBRAKE
  if (v8_flags.wasm_jitless) {
    WasmInterpreter::GlobalTearDown();
  }
#endif  // V8_ENABLE_DRUMBRAKE

  // Note: This can be called multiple times in a row (see
  // test-api/InitializeAndDisposeMultiple). This is fine, as
  // {global_wasm_state} will be nullptr then.
  delete global_wasm_state;
  global_wasm_state = nullptr;

  GetProcessWideWasmCodePointerTable()->TearDown();
}

WasmEngine* GetWasmEngine() {
  DCHECK_NOT_NULL(global_wasm_state);
  return &global_wasm_state->engine;
}

WasmCodeManager* GetWasmCodeManager() {
  DCHECK_NOT_NULL(global_wasm_state);
  return &global_wasm_state->code_manager;
}

WasmImportWrapperCache* GetWasmImportWrapperCache() {
  DCHECK_NOT_NULL(global_wasm_state);
  return &global_wasm_state->import_wrapper_cache;
}

// {max_mem_pages} is declared in wasm-limits.h.
uint32_t max_mem32_pages() {
  static_assert(
      kV8MaxWasmMemory32Pages * kWasmPageSize <= JSArrayBuffer::kMaxByteLength,
      "Wasm memories must not be bigger than JSArrayBuffers");
  static_assert(kV8MaxWasmMemory32Pages <= kMaxUInt32);
  return std::min(uint32_t{kV8MaxWasmMemory32Pages},
                  v8_flags.wasm_max_mem_pages.value());
}

uint32_t max_mem64_pages() {
  static_assert(
      kV8MaxWasmMemory64Pages * kWasmPageSize <= JSArrayBuffer::kMaxByteLength,
      "Wasm memories must not be bigger than JSArrayBuffers");
  static_assert(kV8MaxWasmMemory64Pages <= kMaxUInt32);
  return std::min(uint32_t{kV8MaxWasmMemory64Pages},
                  v8_flags.wasm_max_mem_pages.value());
}

// {max_table_init_entries} is declared in wasm-limits.h.
uint32_t max_table_init_entries() {
  return std::min(uint32_t{kV8MaxWasmTableInitEntries},
                  v8_flags.wasm_max_table_size.value());
}

// {max_module_size} is declared in wasm-limits.h.
size_t max_module_size() {
  // Clamp the value of --wasm-max-module-size between 16 and the maximum
  // that the implementation supports.
  constexpr size_t kMin = 16;
  constexpr size_t kMax = kV8MaxWasmModuleSize;
  static_assert(kMin <= kV8MaxWasmModuleSize);
  return std::clamp(v8_flags.wasm_max_module_size.value(), kMin, kMax);
}

#undef TRACE_CODE_GC

}  // namespace v8::internal::wasm

"""


```