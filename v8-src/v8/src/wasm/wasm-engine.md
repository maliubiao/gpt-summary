Response: The user wants to understand the functionality of the C++ code snippet from `v8/src/wasm/wasm-engine.cc`. The request asks for a summary of the code's purpose and how it relates to JavaScript, with a JavaScript example if applicable.

**Plan:**

1. **High-Level Overview:** Read through the code to get a general idea of the components and their interactions. Focus on class names, function names, and included headers to identify key functionalities.
2. **Identify Core Responsibilities:** Pinpoint the main tasks performed by this file. Look for patterns in the code and connections between different parts.
3. **Analyze Key Classes:** Understand the roles of major classes like `WasmEngine`, `NativeModuleCache`, `NativeModule`, `IsolateInfo`, and related task classes.
4. **Trace Function Calls:**  Follow the execution flow in important functions like `SyncCompile`, `AsyncCompile`, `SyncInstantiate`, and how they interact with other components.
5. **Look for JavaScript Interactions:**  Identify areas where the code interacts with JavaScript concepts or the V8 runtime environment. This might involve handling JavaScript objects, triggering callbacks, or managing the execution context.
6. **Formulate a Summary:** Concisely describe the file's functionality, highlighting its role in the WebAssembly execution process within V8.
7. **Construct a JavaScript Example (if applicable):** Create a simple JavaScript snippet that demonstrates the functionality described in the code, focusing on the user-facing aspects of WebAssembly compilation and instantiation.

**Observations during the analysis:**

* The file manages the lifecycle of WebAssembly modules and their interaction with V8 isolates.
* It handles both synchronous and asynchronous compilation and instantiation.
* It includes a cache for native WebAssembly modules to improve performance.
* It manages per-isolate information related to WebAssembly, including scripts and logging.
* It deals with code garbage collection for WebAssembly.
* It interacts with debugging and profiling functionalities.

**Relationship with JavaScript:**

The code directly supports the WebAssembly JavaScript API (`WebAssembly.compile`, `WebAssembly.instantiate`). It's the engine that powers the execution of WebAssembly code within the JavaScript environment provided by V8.
This C++ code snippet is a part of the `wasm-engine.cc` file in the V8 JavaScript engine, and it primarily focuses on the core management and functionality of WebAssembly modules within V8. Here's a breakdown of its key responsibilities:

**Core Functionalities:**

1. **Native Module Management:**
   - It handles the creation, caching, and lifetime management of `NativeModule` objects. `NativeModule` encapsulates the compiled WebAssembly code and associated metadata.
   - It includes a `NativeModuleCache` to store and reuse compiled modules based on their byte code and import configurations, improving performance by avoiding redundant compilations.
   - It manages the association between `NativeModule`s and V8 `Isolate`s (isolated JavaScript execution environments).

2. **WebAssembly Compilation and Instantiation:**
   - It provides functions for both synchronous (`SyncCompile`) and asynchronous (`AsyncCompile`) compilation of WebAssembly modules from their bytecode.
   - It handles the instantiation process (`SyncInstantiate`, `AsyncInstantiate`), linking the compiled module with imports and creating a WebAssembly instance.
   - It supports the compilation of translated asm.js code to WebAssembly (`SyncCompileTranslatedAsmJs`).

3. **Integration with JavaScript:**
   - It creates `Script` objects for WebAssembly modules, linking them to the `NativeModule`. This allows the JavaScript debugger and profiler to interact with WebAssembly code.
   - It manages the interaction between WebAssembly and JavaScript imports.
   - It handles the creation of `WasmModuleObject` and `WasmInstanceObject`, which are the JavaScript representations of WebAssembly modules and instances, respectively.

4. **Code Logging and Debugging:**
   - It includes mechanisms for logging generated WebAssembly code for performance analysis and debugging purposes.
   - It supports entering and leaving debugging states for WebAssembly modules.

5. **Garbage Collection of WebAssembly Code:**
   - It implements a garbage collection mechanism specifically for WebAssembly code (`WasmCode`), ensuring that unused code is reclaimed.
   - It tracks potentially dead code and uses a foreground task to scan the stack for live code during garbage collection.

6. **Asynchronous Operations:**
   - It utilizes tasks and task runners to handle asynchronous compilation and instantiation operations, preventing blocking of the main JavaScript thread.

7. **PGO (Profile-Guided Optimization) Support:**
   - It includes support for loading profile information for WebAssembly modules, enabling profile-guided optimization.

**Relationship with JavaScript (with JavaScript Example):**

This C++ code is the underlying engine that powers the WebAssembly functionality exposed to JavaScript. When you use the `WebAssembly` API in JavaScript, this C++ code is responsible for the heavy lifting of compiling and instantiating the WebAssembly module.

**JavaScript Example:**

```javascript
// Example of compiling and instantiating a WebAssembly module in JavaScript

const wasmCode = Uint8Array.from([
  0, 97, 115, 109, 1, 0, 0, 0, 1, 7, 1, 96, 0, 1, 127, 3, 2, 1, 0, 7, 7, 1, 3,
  100, 111, 117, 0, 0, 10, 6, 1, 4, 0, 0, 65, 0, 11
]);

// Asynchronous compilation
WebAssembly.compile(wasmCode)
  .then(module => {
    console.log("WebAssembly module compiled successfully:", module);

    // Instantiation
    const instance = new WebAssembly.Instance(module);
    console.log("WebAssembly instance created:", instance);

    // Calling an exported function (if the module had one)
    // console.log(instance.exports.myFunction());
  })
  .catch(error => {
    console.error("Error compiling or instantiating WebAssembly:", error);
  });

// Synchronous compilation (less common in real-world scenarios for larger modules)
try {
  const moduleSync = new WebAssembly.Module(wasmCode);
  console.log("WebAssembly module compiled synchronously:", moduleSync);
  const instanceSync = new WebAssembly.Instance(moduleSync);
  console.log("WebAssembly instance created synchronously:", instanceSync);
} catch (error) {
  console.error("Error compiling or instantiating WebAssembly synchronously:", error);
}
```

**Explanation of the JavaScript example's connection to the C++ code:**

- **`WebAssembly.compile(wasmCode)`:** This JavaScript function call triggers the `AsyncCompile` function in the C++ code. The C++ code will decode and compile the `wasmCode` asynchronously on a background thread.
- **`new WebAssembly.Module(wasmCode)`:** This JavaScript constructor triggers the `SyncCompile` function in the C++ code. The C++ code will decode and compile the `wasmCode` on the current thread.
- **`new WebAssembly.Instance(module, importObject)`:** This JavaScript constructor triggers the `SyncInstantiate` or `AsyncInstantiate` function in the C++ code. The C++ code will link the compiled `module` with the provided `importObject` (if any) and create a runnable WebAssembly instance.

In essence, the C++ code in `wasm-engine.cc` is the "engine" behind the JavaScript `WebAssembly` API, handling the low-level details of WebAssembly module processing within the V8 environment. It manages the compiled code, memory, and execution context for WebAssembly, allowing it to seamlessly integrate with JavaScript.

Prompt: 
```
这是目录为v8/src/wasm/wasm-engine.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/wasm-engine.h"

#include <optional>

#include "src/base/functional.h"
#include "src/base/platform/time.h"
#include "src/base/small-vector.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/debug/debug.h"
#include "src/diagnostics/code-tracer.h"
#include "src/diagnostics/compilation-statistics.h"
#include "src/execution/frames.h"
#include "src/execution/v8threads.h"
#include "src/handles/global-handles-inl.h"
#include "src/logging/counters.h"
#include "src/logging/metrics.h"
#include "src/objects/heap-number.h"
#include "src/objects/managed-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/objects.h"
#include "src/objects/primitive-heap-object.h"
#include "src/utils/ostreams.h"
#include "src/wasm/function-compiler.h"
#include "src/wasm/module-compiler.h"
#include "src/wasm/module-decoder.h"
#include "src/wasm/module-instantiate.h"
#include "src/wasm/pgo.h"
#include "src/wasm/stacks.h"
#include "src/wasm/std-object-sizes.h"
#include "src/wasm/streaming-decoder.h"
#include "src/wasm/wasm-code-pointer-table.h"
#include "src/wasm/wasm-debug.h"
#include "src/wasm/wasm-limits.h"
#include "src/wasm/wasm-objects-inl.h"

#if V8_ENABLE_DRUMBRAKE
#include "src/wasm/interpreter/wasm-interpreter-inl.h"
#endif  // V8_ENABLE_DRUMBRAKE

#ifdef V8_ENABLE_WASM_GDB_REMOTE_DEBUGGING
#include "src/debug/wasm/gdb-server/gdb-server.h"
#endif  // V8_ENABLE_WASM_GDB_REMOTE_DEBUGGING

namespace v8::internal::wasm {

#define TRACE_CODE_GC(...)                                             \
  do {                                                                 \
    if (v8_flags.trace_wasm_code_gc) PrintF("[wasm-gc] " __VA_ARGS__); \
  } while (false)

// This class exists in order to solve a shutdown ordering problem.
// The basic situation is that the process-global WasmEngine has, for each
// Isolate that it knows about, a map from NativeModule to Script, using
// WeakScriptHandles to make sure that the NativeModules, which are shared
// across the process, don't keep the (Isolate-specific) Scripts alive.
// In the other direction, the Scripts keep the NativeModule alive, IOW
// usually the Scripts die first, and the WeakScriptHandles are cleared
// before being freed.
// In case of asm.js modules and in case of Isolate shutdown, it can happen
// that the NativeModule dies first, so the WeakScriptHandles are no longer
// needed and should be destroyed. That can only happen on the main thread of
// the Isolate they belong to, whereas the last thread that releases a
// NativeModule might be any other thread, so we post a
// ClearWeakScriptHandleTask to that isolate's foreground task runner.
// In case of Isolate shutdown at an inconvenient moment, this task runner can
// destroy all waiting tasks; and *afterwards* global handles are freed, which
// writes to the memory location backing the handle, so this bit of memory must
// not be owned by (and die with) the ClearWeakScriptHandleTask.
// The solution is this class here: its instances form a linked list owned by
// the Isolate to which the referenced Scripts belong. Its name refers to the
// fact that it stores global handles that used to have a purpose but are now
// just waiting for the right thread to destroy them.
// If the ClearWeakScriptHandleTask gets to run (i.e. in the regular case),
// it destroys the weak global handle and then the WasmOrphanedGlobalHandle
// container, removing it from the isolate's list.
// If the ClearWeakScriptHandleTask is destroyed before it runs, the isolate's
// list of WasmOrphanedGlobalHandles isn't modified, so the indirection cell
// is still around when all remaining global handles are freed; nevertheless
// it won't leak because the Isolate owns it and will free it.
class WasmOrphanedGlobalHandle {
 public:
  WasmOrphanedGlobalHandle() = default;

  void InitializeLocation(std::unique_ptr<Address*> location) {
    location_ = std::move(location);
  }

  static void Destroy(WasmOrphanedGlobalHandle* that) {
    // Destroy the global handle if it still exists.
    Address** location = that->location_.get();
    if (location) GlobalHandles::Destroy(*location);
    that->location_.reset();
    // Unlink and free the container.
    *that->prev_ptr_ = that->next_;
    if (that->next_ != nullptr) that->next_->prev_ptr_ = that->prev_ptr_;
    // This function could be a non-static method, but then the next line
    // would read "delete this", which is UB.
    delete that;
  }

 private:
  friend class WasmEngine;

  // This is a doubly linked list with a twist: the {next_} pointer is just
  // what you would expect, whereas {prev_ptr_} points at the slot inside
  // the previous element that's pointing at the current element. The purpose
  // of this design is to make it possible for the previous element to be
  // the {Isolate::wasm_orphaned_handle_} field, without requiring any
  // special-casing in the insert and delete operations.
  WasmOrphanedGlobalHandle* next_ = nullptr;
  WasmOrphanedGlobalHandle** prev_ptr_ = nullptr;
  std::unique_ptr<Address*> location_;
};

// static
WasmOrphanedGlobalHandle* WasmEngine::NewOrphanedGlobalHandle(
    WasmOrphanedGlobalHandle** pointer) {
  // No need for additional locking: this is only ever called indirectly
  // from {WasmEngine::ClearWeakScriptHandle()}, which holds the engine-wide
  // {mutex_}.
  WasmOrphanedGlobalHandle* orphan = new WasmOrphanedGlobalHandle();
  orphan->next_ = *pointer;
  orphan->prev_ptr_ = pointer;
  if (orphan->next_ != nullptr) orphan->next_->prev_ptr_ = &orphan->next_;
  *pointer = orphan;
  return orphan;
}

// static
void WasmEngine::FreeAllOrphanedGlobalHandles(WasmOrphanedGlobalHandle* start) {
  // This is meant to be called from ~Isolate, so we no longer care about
  // maintaining invariants: the only task is to free memory to prevent leaks.
  while (start != nullptr) {
    WasmOrphanedGlobalHandle* next = start->next_;
    delete start;
    start = next;
  }
}

// A task to log a set of {WasmCode} objects in an isolate. It does not own any
// data itself, since it is owned by the platform, so lifetime is not really
// bound to the wasm engine.
class WasmEngine::LogCodesTask : public CancelableTask {
  friend class WasmEngine;

 public:
  explicit LogCodesTask(Isolate* isolate)
      : CancelableTask(isolate), isolate_(isolate) {}

  void RunInternal() override {
    GetWasmEngine()->LogOutstandingCodesForIsolate(isolate_);
  }

 private:
  Isolate* const isolate_;
};

namespace {
void CheckNoArchivedThreads(Isolate* isolate) {
  class ArchivedThreadsVisitor : public ThreadVisitor {
    void VisitThread(Isolate* isolate, ThreadLocalTop* top) override {
      // Archived threads are rarely used, and not combined with Wasm at the
      // moment. Implement this and test it properly once we have a use case for
      // that.
      FATAL("archived threads in combination with wasm not supported");
    }
  } archived_threads_visitor;
  isolate->thread_manager()->IterateArchivedThreads(&archived_threads_visitor);
}

class WasmGCForegroundTask : public CancelableTask {
 public:
  explicit WasmGCForegroundTask(Isolate* isolate)
      : CancelableTask(isolate->cancelable_task_manager()), isolate_(isolate) {}

  void RunInternal() final {
    // The stack can contain live frames, for instance when this is invoked
    // during a pause or a breakpoint.
    GetWasmEngine()->ReportLiveCodeFromStackForGC(isolate_);
  }

 private:
  Isolate* isolate_;
};

class ClearWeakScriptHandleTask : public CancelableTask {
 public:
  explicit ClearWeakScriptHandleTask(Isolate* isolate,
                                     std::unique_ptr<Address*> location)
      : CancelableTask(isolate->cancelable_task_manager()) {
    handle_ = isolate->NewWasmOrphanedGlobalHandle();
    handle_->InitializeLocation(std::move(location));
  }

  // We don't override the destructor, because there is nothing to do:
  // if the task is deleted before it was run, then everything is shutting
  // down anyway, so destroying the GlobalHandle is no longer relevant (and
  // it might well be too late to do that safely).

  void RunInternal() override {
    WasmOrphanedGlobalHandle::Destroy(handle_);
    handle_ = nullptr;
  }

 private:
  // This is owned by the Isolate to ensure correct shutdown ordering.
  WasmOrphanedGlobalHandle* handle_;
};

class WeakScriptHandle {
 public:
  WeakScriptHandle(DirectHandle<Script> script, Isolate* isolate)
      : script_id_(script->id()), isolate_(isolate) {
    DCHECK(IsString(script->name()) || IsUndefined(script->name()));
    if (IsString(script->name())) {
      source_url_ = Cast<String>(script->name())->ToCString();
    }
    auto global_handle =
        script->GetIsolate()->global_handles()->Create(*script);
    location_ = std::make_unique<Address*>(global_handle.location());
    GlobalHandles::MakeWeak(location_.get());
  }

  ~WeakScriptHandle() {
    // Usually the destructor of this class is called after the weak callback,
    // because the Script keeps the NativeModule alive. In that case,
    // {location_} is already cleared, and there is nothing to do.
    if (location_ == nullptr || *location_ == nullptr) return;
    // For asm.js modules, the Script usually outlives the NativeModule.
    // We must destroy the GlobalHandle before freeing the memory that's
    // backing {location_}, so that when the Script does die eventually, there
    // is no lingering weak GlobalHandle that would try to clear {location_}.
    // We can't do that from arbitrary threads, so we must post a task to the
    // main thread.
    GetWasmEngine()->ClearWeakScriptHandle(isolate_, std::move(location_));
  }

  WeakScriptHandle(WeakScriptHandle&&) V8_NOEXCEPT = default;

  Handle<Script> handle() const { return Handle<Script>(*location_); }

  // Called by ~IsolateInfo. When the Isolate is shutting down, cleaning
  // up properly is both no longer necessary and no longer safe to do.
  void Clear() { location_.reset(); }

  int script_id() const { return script_id_; }

  const std::shared_ptr<const char[]>& source_url() const {
    return source_url_;
  }

 private:
  // Store the location in a unique_ptr so that its address stays the same even
  // when this object is moved/copied.
  std::unique_ptr<Address*> location_;

  // Store the script ID independent of the weak handle, such that it's always
  // available.
  int script_id_;

  // Similar for the source URL. We cannot dereference the Handle from arbitrary
  // threads, but we need the URL available for code logging.
  // The shared pointer is kept alive by unlogged code, even if this entry is
  // collected in the meantime.
  // TODO(chromium:1132260): Revisit this for huge URLs.
  std::shared_ptr<const char[]> source_url_;

  // The Isolate that the handled script belongs to.
  Isolate* isolate_;
};

// If PGO data is being collected, keep all native modules alive, so repeated
// runs of a benchmark (with different configuration) all use the same module.
// This vector is protected by the global WasmEngine's mutex, but not defined in
// the header because it's a private implementation detail.
std::vector<std::shared_ptr<NativeModule>>* native_modules_kept_alive_for_pgo;

}  // namespace

std::shared_ptr<NativeModule> NativeModuleCache::MaybeGetNativeModule(
    ModuleOrigin origin, base::Vector<const uint8_t> wire_bytes,
    const CompileTimeImports& compile_imports) {
  if (!v8_flags.wasm_native_module_cache) return nullptr;
  if (origin != kWasmOrigin) return nullptr;
  base::MutexGuard lock(&mutex_);
  size_t prefix_hash = PrefixHash(wire_bytes);
  NativeModuleCache::Key key{prefix_hash, compile_imports, wire_bytes};
  while (true) {
    auto it = map_.find(key);
    if (it == map_.end()) {
      // Even though this exact key is not in the cache, there might be a
      // matching prefix hash indicating that a streaming compilation is
      // currently compiling a module with the same prefix. {OnFinishedStream}
      // happens on the main thread too, so waiting for streaming compilation to
      // finish would create a deadlock. Instead, compile the module twice and
      // handle the conflict in {UpdateNativeModuleCache}.

      // Insert a {nullopt} entry to let other threads know that this
      // {NativeModule} is already being created on another thread.
      [[maybe_unused]] auto [iterator, inserted] =
          map_.emplace(key, std::nullopt);
      DCHECK(inserted);
      return nullptr;
    }
    if (it->second.has_value()) {
      if (auto shared_native_module = it->second.value().lock()) {
        DCHECK_EQ(
            shared_native_module->compile_imports().compare(compile_imports),
            0);
        DCHECK_EQ(shared_native_module->wire_bytes(), wire_bytes);
        return shared_native_module;
      }
    }
    // TODO(11858): This deadlocks in predictable mode, because there is only a
    // single thread.
    cache_cv_.Wait(&mutex_);
  }
}

bool NativeModuleCache::GetStreamingCompilationOwnership(
    size_t prefix_hash, const CompileTimeImports& compile_imports) {
  if (!v8_flags.wasm_native_module_cache) return true;
  base::MutexGuard lock(&mutex_);
  auto it = map_.lower_bound(Key{prefix_hash, compile_imports, {}});
  if (it != map_.end() && it->first.prefix_hash == prefix_hash) {
    DCHECK_IMPLIES(!it->first.bytes.empty(),
                   PrefixHash(it->first.bytes) == prefix_hash);
    return false;
  }
  Key key{prefix_hash, compile_imports, {}};
  DCHECK_EQ(0, map_.count(key));
  map_.emplace(key, std::nullopt);
  return true;
}

void NativeModuleCache::StreamingCompilationFailed(
    size_t prefix_hash, const CompileTimeImports& compile_imports) {
  if (!v8_flags.wasm_native_module_cache) return;
  base::MutexGuard lock(&mutex_);
  Key key{prefix_hash, compile_imports, {}};
  map_.erase(key);
  cache_cv_.NotifyAll();
}

std::shared_ptr<NativeModule> NativeModuleCache::Update(
    std::shared_ptr<NativeModule> native_module, bool error) {
  DCHECK_NOT_NULL(native_module);
  if (!v8_flags.wasm_native_module_cache) return native_module;
  if (native_module->module()->origin != kWasmOrigin) return native_module;
  base::Vector<const uint8_t> wire_bytes = native_module->wire_bytes();
  DCHECK(!wire_bytes.empty());
  size_t prefix_hash = PrefixHash(native_module->wire_bytes());
  base::MutexGuard lock(&mutex_);
  const CompileTimeImports& compile_imports = native_module->compile_imports();
  map_.erase(Key{prefix_hash, compile_imports, {}});
  const Key key{prefix_hash, compile_imports, wire_bytes};
  auto it = map_.find(key);
  if (it != map_.end()) {
    if (it->second.has_value()) {
      auto conflicting_module = it->second.value().lock();
      if (conflicting_module != nullptr) {
        DCHECK_EQ(conflicting_module->wire_bytes(), wire_bytes);
        // This return might delete {native_module} if we were the last holder.
        // That in turn can call {NativeModuleCache::Erase}, which takes the
        // mutex. This is not a problem though, since the {MutexGuard} above is
        // released before the {native_module}, per the definition order.
        return conflicting_module;
      }
    }
    map_.erase(it);
  }
  if (!error) {
    // The key now points to the new native module's owned copy of the bytes,
    // so that it stays valid until the native module is freed and erased from
    // the map.
    [[maybe_unused]] auto [iterator, inserted] = map_.emplace(
        key, std::optional<std::weak_ptr<NativeModule>>(native_module));
    DCHECK(inserted);
  }
  cache_cv_.NotifyAll();
  return native_module;
}

void NativeModuleCache::Erase(NativeModule* native_module) {
  if (!v8_flags.wasm_native_module_cache) return;
  if (native_module->module()->origin != kWasmOrigin) return;
  // Happens in some tests where bytes are set directly.
  if (native_module->wire_bytes().empty()) return;
  base::MutexGuard lock(&mutex_);
  size_t prefix_hash = PrefixHash(native_module->wire_bytes());
  map_.erase(Key{prefix_hash, native_module->compile_imports(),
                 native_module->wire_bytes()});
  cache_cv_.NotifyAll();
}

// static
size_t NativeModuleCache::PrefixHash(base::Vector<const uint8_t> wire_bytes) {
  // Compute the hash as a combined hash of the sections up to the code section
  // header, to mirror the way streaming compilation does it.
  Decoder decoder(wire_bytes.begin(), wire_bytes.end());
  decoder.consume_bytes(8, "module header");
  size_t hash = GetWireBytesHash(wire_bytes.SubVector(0, 8));
  SectionCode section_id = SectionCode::kUnknownSectionCode;
  while (decoder.ok() && decoder.more()) {
    section_id = static_cast<SectionCode>(decoder.consume_u8());
    uint32_t section_size = decoder.consume_u32v("section size");
    if (section_id == SectionCode::kCodeSectionCode) {
      hash = base::hash_combine(hash, section_size);
      break;
    }
    const uint8_t* payload_start = decoder.pc();
    decoder.consume_bytes(section_size, "section payload");
    size_t section_hash =
        GetWireBytesHash(base::VectorOf(payload_start, section_size));
    hash = base::hash_combine(hash, section_hash);
  }
  return hash;
}

struct WasmEngine::CurrentGCInfo {
  explicit CurrentGCInfo(int8_t gc_sequence_index)
      : gc_sequence_index(gc_sequence_index) {
    DCHECK_NE(0, gc_sequence_index);
  }

  // Set of isolates that did not scan their stack yet for used WasmCode, and
  // their scheduled foreground task.
  std::unordered_map<Isolate*, WasmGCForegroundTask*> outstanding_isolates;

  // Set of dead code. Filled with all potentially dead code on initialization.
  // Code that is still in-use is removed by the individual isolates.
  std::unordered_set<WasmCode*> dead_code;

  // The number of GCs triggered in the native module that triggered this GC.
  // This is stored in the histogram for each participating isolate during
  // execution of that isolate's foreground task.
  const int8_t gc_sequence_index;

  // If during this GC, another GC was requested, we skipped that other GC (we
  // only run one GC at a time). Remember though to trigger another one once
  // this one finishes. {next_gc_sequence_index} is 0 if no next GC is needed,
  // and >0 otherwise. It stores the {num_code_gcs_triggered} of the native
  // module which triggered the next GC.
  int8_t next_gc_sequence_index = 0;

  // The start time of this GC; used for tracing and sampled via {Counters}.
  // Can be null ({TimeTicks::IsNull()}) if timer is not high resolution.
  base::TimeTicks start_time;
};

struct WasmEngine::IsolateInfo {
  IsolateInfo(Isolate* isolate, bool log_code)
      : log_codes(log_code), async_counters(isolate->async_counters()) {
    v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate);
    v8::Platform* platform = V8::GetCurrentPlatform();
    foreground_task_runner = platform->GetForegroundTaskRunner(v8_isolate);
  }

  ~IsolateInfo() {
    // Before destructing, the {WasmEngine} must have cleared outstanding code
    // to log.
    DCHECK_EQ(0, code_to_log.size());

    // We need the {~WeakScriptHandle} destructor in {scripts} to behave
    // differently depending on whether the Isolate is in the process of
    // being destroyed. That's the only situation where we would run the
    // {~IsolateInfo} destructor, and in that case, we can no longer post
    // the task that would destroy the {WeakScriptHandle}'s {GlobalHandle};
    // whereas if only individual entries of {scripts} get deleted, then
    // we can and should post such tasks.
    for (auto& [native_module, script_handle] : scripts) {
      script_handle.Clear();
    }
  }

  // All native modules that are being used by this Isolate.
  std::unordered_set<NativeModule*> native_modules;

  // Scripts created for each native module in this isolate.
  std::unordered_map<NativeModule*, WeakScriptHandle> scripts;

  // Caches whether code needs to be logged on this isolate.
  bool log_codes;

  // Maps script ID to vector of code objects that still need to be logged, and
  // the respective source URL.
  struct CodeToLogPerScript {
    std::vector<WasmCode*> code;
    std::shared_ptr<const char[]> source_url;
  };
  std::unordered_map<int, CodeToLogPerScript> code_to_log;

  // The foreground task runner of the isolate (can be called from background).
  std::shared_ptr<v8::TaskRunner> foreground_task_runner;

  const std::shared_ptr<Counters> async_counters;

  // Keep new modules in debug state.
  bool keep_in_debug_state = false;

  // Keep track whether we already added a sample for PKU support (we only want
  // one sample per Isolate).
  bool pku_support_sampled = false;
};

void WasmEngine::ClearWeakScriptHandle(Isolate* isolate,
                                       std::unique_ptr<Address*> location) {
  // This function is designed for one targeted use case, which always
  // acquires a lock on {mutex_} before calling here.
  mutex_.AssertHeld();
  IsolateInfo* isolate_info = isolates_[isolate].get();
  std::shared_ptr<TaskRunner> runner = isolate_info->foreground_task_runner;
  runner->PostTask(std::make_unique<ClearWeakScriptHandleTask>(
      isolate, std::move(location)));
}

struct WasmEngine::NativeModuleInfo {
  explicit NativeModuleInfo(std::weak_ptr<NativeModule> native_module)
      : weak_ptr(std::move(native_module)) {}

  // Weak pointer, to gain back a shared_ptr if needed.
  std::weak_ptr<NativeModule> weak_ptr;

  // Set of isolates using this NativeModule.
  std::unordered_set<Isolate*> isolates;
};

WasmEngine::WasmEngine() : call_descriptors_(&allocator_) {}

WasmEngine::~WasmEngine() {
#ifdef V8_ENABLE_WASM_GDB_REMOTE_DEBUGGING
  // Synchronize on the GDB-remote thread, if running.
  gdb_server_.reset();
#endif  // V8_ENABLE_WASM_GDB_REMOTE_DEBUGGING

  // Free all modules that were kept alive for collecting PGO. This is to avoid
  // memory leaks.
  if (V8_UNLIKELY(native_modules_kept_alive_for_pgo)) {
    delete native_modules_kept_alive_for_pgo;
  }

  operations_barrier_->CancelAndWait();

  // All code should have been deleted already, but wrappers managed by the
  // WasmImportWrapperCache are placed in {potentially_dead_code_} when they
  // are no longer referenced, and we don't want to wait for the next
  // Wasm Code GC cycle to remove them from that set.
  for (WasmCode* code : potentially_dead_code_) {
    code->DcheckRefCountIsOne();
    // The actual instructions will get thrown out when the global
    // WasmImportWrapperCache's {code_allocator_} frees its memory region.
    // Here we just pacify LSan.
    delete code;
  }

  // All AsyncCompileJobs have been canceled.
  DCHECK(async_compile_jobs_.empty());
  // All Isolates have been deregistered.
  DCHECK(isolates_.empty());
  // All NativeModules did die.
  DCHECK(native_modules_.empty());
  // Native module cache does not leak.
  DCHECK(native_module_cache_.empty());
}

bool WasmEngine::SyncValidate(Isolate* isolate, WasmEnabledFeatures enabled,
                              CompileTimeImports compile_imports,
                              ModuleWireBytes bytes) {
  TRACE_EVENT0("v8.wasm", "wasm.SyncValidate");
  if (bytes.length() == 0) return false;

  WasmDetectedFeatures unused_detected_features;
  auto result = DecodeWasmModule(
      enabled, bytes.module_bytes(), true, kWasmOrigin, isolate->counters(),
      isolate->metrics_recorder(),
      isolate->GetOrRegisterRecorderContextId(isolate->native_context()),
      DecodingMethod::kSync, &unused_detected_features);
  if (result.failed()) return false;
  WasmError error =
      ValidateAndSetBuiltinImports(result.value().get(), bytes.module_bytes(),
                                   compile_imports, &unused_detected_features);
  return !error.has_error();
}

MaybeHandle<AsmWasmData> WasmEngine::SyncCompileTranslatedAsmJs(
    Isolate* isolate, ErrorThrower* thrower, ModuleWireBytes bytes,
    DirectHandle<Script> script,
    base::Vector<const uint8_t> asm_js_offset_table_bytes,
    DirectHandle<HeapNumber> uses_bitset, LanguageMode language_mode) {
  int compilation_id = next_compilation_id_.fetch_add(1);
  TRACE_EVENT1("v8.wasm", "wasm.SyncCompileTranslatedAsmJs", "id",
               compilation_id);
  ModuleOrigin origin = language_mode == LanguageMode::kSloppy
                            ? kAsmJsSloppyOrigin
                            : kAsmJsStrictOrigin;
  // TODO(leszeks): If we want asm.js in UKM, we should figure out a way to pass
  // the context id in here.
  v8::metrics::Recorder::ContextId context_id =
      v8::metrics::Recorder::ContextId::Empty();
  WasmDetectedFeatures detected_features;
  ModuleResult result = DecodeWasmModule(
      WasmEnabledFeatures::ForAsmjs(), bytes.module_bytes(), false, origin,
      isolate->counters(), isolate->metrics_recorder(), context_id,
      DecodingMethod::kSync, &detected_features);
  if (result.failed()) {
    // This happens once in a while when we have missed some limit check
    // in the asm parser. Output an error message to help diagnose, but crash.
    std::cout << result.error().message();
    UNREACHABLE();
  }

  result.value()->asm_js_offset_information =
      std::make_unique<AsmJsOffsetInformation>(asm_js_offset_table_bytes);

  // Transfer ownership of the WasmModule to the {Managed<WasmModule>} generated
  // in {CompileToNativeModule}.
  constexpr ProfileInformation* kNoProfileInformation = nullptr;
  std::shared_ptr<NativeModule> native_module = CompileToNativeModule(
      isolate, WasmEnabledFeatures::ForAsmjs(), detected_features,
      CompileTimeImports{}, thrower, std::move(result).value(), bytes,
      compilation_id, context_id, kNoProfileInformation);
  if (!native_module) return {};

  native_module->LogWasmCodes(isolate, *script);
  {
    // Register the script with the isolate. We do this unconditionally for
    // consistency; it is in particular required for logging lazy-compiled code.
    base::MutexGuard guard(&mutex_);
    DCHECK_EQ(1, isolates_.count(isolate));
    auto& scripts = isolates_[isolate]->scripts;
    // If the same asm.js module is instantiated repeatedly, then we
    // deduplicate the NativeModule, so the script exists already.
    if (scripts.count(native_module.get()) == 0) {
      scripts.emplace(native_module.get(), WeakScriptHandle(script, isolate));
    }
  }

  return AsmWasmData::New(isolate, std::move(native_module), uses_bitset);
}

Handle<WasmModuleObject> WasmEngine::FinalizeTranslatedAsmJs(
    Isolate* isolate, DirectHandle<AsmWasmData> asm_wasm_data,
    DirectHandle<Script> script) {
  std::shared_ptr<NativeModule> native_module =
      asm_wasm_data->managed_native_module()->get();
  Handle<WasmModuleObject> module_object =
      WasmModuleObject::New(isolate, std::move(native_module), script);
  return module_object;
}

MaybeHandle<WasmModuleObject> WasmEngine::SyncCompile(
    Isolate* isolate, WasmEnabledFeatures enabled_features,
    CompileTimeImports compile_imports, ErrorThrower* thrower,
    ModuleWireBytes bytes) {
  int compilation_id = next_compilation_id_.fetch_add(1);
  TRACE_EVENT1("v8.wasm", "wasm.SyncCompile", "id", compilation_id);
  v8::metrics::Recorder::ContextId context_id =
      isolate->GetOrRegisterRecorderContextId(isolate->native_context());
  std::shared_ptr<WasmModule> module;
  WasmDetectedFeatures detected_features;
  {
    // Normally modules are validated in {CompileToNativeModule} but in jitless
    // mode the only opportunity of validatiom is during decoding.
    bool validate_module = v8_flags.wasm_jitless;
    ModuleResult result = DecodeWasmModule(
        enabled_features, bytes.module_bytes(), validate_module, kWasmOrigin,
        isolate->counters(), isolate->metrics_recorder(), context_id,
        DecodingMethod::kSync, &detected_features);
    if (result.failed()) {
      thrower->CompileFailed(result.error());
      return {};
    }
    module = std::move(result).value();
    if (WasmError error =
            ValidateAndSetBuiltinImports(module.get(), bytes.module_bytes(),
                                         compile_imports, &detected_features)) {
      thrower->CompileError("%s @+%u", error.message().c_str(), error.offset());
      return {};
    }
  }

  // If experimental PGO via files is enabled, load profile information now.
  std::unique_ptr<ProfileInformation> pgo_info;
  if (V8_UNLIKELY(v8_flags.experimental_wasm_pgo_from_file)) {
    pgo_info = LoadProfileFromFile(module.get(), bytes.module_bytes());
  }

  // Transfer ownership of the WasmModule to the {Managed<WasmModule>} generated
  // in {CompileToNativeModule}.
  std::shared_ptr<NativeModule> native_module = CompileToNativeModule(
      isolate, enabled_features, detected_features, std::move(compile_imports),
      thrower, std::move(module), bytes, compilation_id, context_id,
      pgo_info.get());
  if (!native_module) return {};

#ifdef DEBUG
  // Ensure that code GC will check this isolate for live code.
  {
    base::MutexGuard lock(&mutex_);
    DCHECK_EQ(1, isolates_.count(isolate));
    DCHECK_EQ(1, isolates_[isolate]->native_modules.count(native_module.get()));
    DCHECK_EQ(1, native_modules_.count(native_module.get()));
    DCHECK_EQ(1, native_modules_[native_module.get()]->isolates.count(isolate));
  }
#endif

  constexpr base::Vector<const char> kNoSourceUrl;
  DirectHandle<Script> script =
      GetOrCreateScript(isolate, native_module, kNoSourceUrl);

  native_module->LogWasmCodes(isolate, *script);

  // Create the compiled module object and populate with compiled functions
  // and information needed at instantiation time. This object needs to be
  // serializable. Instantiation may occur off a deserialized version of this
  // object.
  Handle<WasmModuleObject> module_object =
      WasmModuleObject::New(isolate, std::move(native_module), script);

  // Finish the Wasm script now and make it public to the debugger.
  isolate->debug()->OnAfterCompile(script);
  return module_object;
}

MaybeHandle<WasmInstanceObject> WasmEngine::SyncInstantiate(
    Isolate* isolate, ErrorThrower* thrower,
    Handle<WasmModuleObject> module_object, MaybeHandle<JSReceiver> imports,
    MaybeHandle<JSArrayBuffer> memory) {
  TRACE_EVENT0("v8.wasm", "wasm.SyncInstantiate");
  return InstantiateToInstanceObject(isolate, thrower, module_object, imports,
                                     memory);
}

void WasmEngine::AsyncInstantiate(
    Isolate* isolate, std::unique_ptr<InstantiationResultResolver> resolver,
    Handle<WasmModuleObject> module_object, MaybeHandle<JSReceiver> imports) {
  ErrorThrower thrower(isolate, "WebAssembly.instantiate()");
  TRACE_EVENT0("v8.wasm", "wasm.AsyncInstantiate");
  // Instantiate a TryCatch so that caught exceptions won't progagate out.
  // They will still be set as exceptions on the isolate.
  // TODO(clemensb): Avoid TryCatch, use Execution::TryCall internally to invoke
  // start function and report thrown exception explicitly via out argument.
  v8::TryCatch catcher(reinterpret_cast<v8::Isolate*>(isolate));
  catcher.SetVerbose(false);
  catcher.SetCaptureMessage(false);

  MaybeHandle<WasmInstanceObject> instance_object = SyncInstantiate(
      isolate, &thrower, module_object, imports, Handle<JSArrayBuffer>::null());

  if (!instance_object.is_null()) {
    resolver->OnInstantiationSucceeded(instance_object.ToHandleChecked());
    return;
  }

  if (isolate->has_exception()) {
    thrower.Reset();
    if (isolate->is_execution_terminating()) return;
    // The JS code executed during instantiation has thrown an exception.
    // We have to move the exception to the promise chain.
    Handle<Object> exception(isolate->exception(), isolate);
    DCHECK(!IsHole(*exception));
    isolate->clear_exception();
    resolver->OnInstantiationFailed(exception);
  } else {
    DCHECK(thrower.error());
    resolver->OnInstantiationFailed(thrower.Reify());
  }
}

void WasmEngine::AsyncCompile(
    Isolate* isolate, WasmEnabledFeatures enabled,
    CompileTimeImports compile_imports,
    std::shared_ptr<CompilationResultResolver> resolver, ModuleWireBytes bytes,
    bool is_shared, const char* api_method_name_for_errors) {
  int compilation_id = next_compilation_id_.fetch_add(1);
  TRACE_EVENT1("v8.wasm", "wasm.AsyncCompile", "id", compilation_id);
  if (!v8_flags.wasm_async_compilation || v8_flags.wasm_jitless) {
    // Asynchronous compilation disabled; fall back on synchronous compilation.
    ErrorThrower thrower(isolate, api_method_name_for_errors);
    MaybeHandle<WasmModuleObject> module_object;
    if (is_shared) {
      // Make a copy of the wire bytes to avoid concurrent modification.
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
"""


```