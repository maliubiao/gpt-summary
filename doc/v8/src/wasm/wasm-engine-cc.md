Response:
The user wants a summary of the functionality of the provided C++ code, `v8/src/wasm/wasm-engine.cc`. I need to extract the key responsibilities and operations performed by this file. I should also check if the file extension was `.tq` (it's `.cc`, so it's not Torque) and see if any functionality relates to JavaScript. If there's any logical code flow, I need to provide an example with input and output. Finally, I need to point out common user programming errors if applicable.

Here's a breakdown of the code's functions:

1. **Handles Native Modules:** Manages the lifecycle and caching of compiled WebAssembly modules (NativeModule).
2. **Compilation:**  Initiates and manages both synchronous and asynchronous compilation of WebAssembly modules.
3. **Instantiation:**  Handles the instantiation of WebAssembly modules into instances.
4. **Caching:** Implements a cache for NativeModules to avoid redundant compilations.
5. **Garbage Collection:** Participates in garbage collection by tracking live WebAssembly code.
6. **Script Integration:**  Connects WebAssembly modules to JavaScript `Script` objects for debugging and logging.
7. **Error Handling:** Uses `ErrorThrower` to report compilation and instantiation errors to JavaScript.
8. **Asm.js Support:** Handles the compilation and integration of asm.js modules.
9. **PGO (Profile-Guided Optimization):** Supports loading and using profile information for optimization.
10. **Debugging:** Integrates with the V8 debugger.
11. **Logging and Metrics:**  Logs compilation activity and collects performance metrics.
12. **Thread Management:**  Uses tasks and task runners for asynchronous operations and to handle cross-thread communication safely.

Relating to JavaScript:  The compilation and instantiation processes directly result in JavaScript objects (`WasmModuleObject`, `WasmInstanceObject`). The integration with `Script` objects is also a JavaScript concept.

Example of a common programming error:  Incorrectly handling imports or providing incompatible imports during instantiation.

Now I can structure the answer based on these observations.
```cpp
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
  TRACE_EVENT1("v8.wasm", "wasm.SyncCompile", "id", compilation
### 提示词
```
这是目录为v8/src/wasm/wasm-engine.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-engine.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
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
      // Make a copy of the wire bytes to avoid con
```