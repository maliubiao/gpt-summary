Response: The user wants a summary of the functionality of the C++ code in `v8/src/execution/isolate.cc`. This is the 5th part of a larger file. The summary should also highlight connections to JavaScript and provide JavaScript examples if possible.

**Breakdown of the provided code:**

1. **Promise Handling:** Functions like `OnPromiseAfter`, `OnStackTraceCaptured`, `OnTerminationDuringRunMicrotasks`, `SetPromiseRejectCallback`, and `ReportPromiseReject` suggest management of asynchronous operations via Promises.
2. **Use Counters:** `SetUseCounterCallback` and `CountUsage` indicate a mechanism for tracking the usage of specific JavaScript features.
3. **Detached Contexts:** `AddDetachedContext` and `CheckDetachedContextsAfterGC` deal with cleaning up contexts that are no longer actively used, possibly related to garbage collection.
4. **Global Object Detachment:** `DetachGlobal` suggests a way to disconnect the global object from its context.
5. **Performance Monitoring:** `UpdateLoadStartTime`, `SetRAILMode`, `SetIsLoading`, and `SetPriority` are likely related to performance optimizations and tracking different execution phases.
6. **Script Management:** `GetNextScriptId` is for assigning unique identifiers to scripts.
7. **Debugging and Tracing:** `GetTurboCfgFileName` hints at configurations for the TurboFan compiler, and `PrintWithTimestamp` is for logging.
8. **Stack Overflow and Termination:** `StackLimitCheck` is clearly involved in detecting and handling stack overflow errors and termination requests.
9. **Context Switching:** `SaveContext`, `SaveAndSwitchContext`, and `AssertNoContextChange` (in debug mode) are about managing the current execution context.
10. **Code Memory Management:**  `AddCodeMemoryRange`, `AddCodeMemoryChunk`, and `RemoveCodeMemoryChunk` deal with tracking memory used for compiled code.
11. **Metrics and Long Tasks:** `GetOrRegisterRecorderContextId`, `GetContextFromRecorderContextId`, `UpdateLongTaskStats`, and `GetCurrentLongTaskStats` are for collecting performance metrics, specifically related to long-running tasks.
12. **Local Heap:** `main_thread_local_heap` and `CurrentLocalHeap` relate to managing memory heaps for different threads.
13. **Wasm Integration:** `initialize_wasm_execution_timer` and `DefaultWasmAsyncResolvePromiseCallback` are specific to WebAssembly integration.
14. **Stack Access Counting:** `load_from_stack_count_address` and `store_to_stack_count_address` are likely used for debugging or performance analysis by tracking stack accesses.
15. **Scope Blocklist Caching:** `LocalsBlockListCacheSet` and `LocalsBlockListCacheGet` suggest an optimization related to managing local variable blocklists within scopes.
16. **Asynchronous Waiter Queue:** `async_waiter_queue_nodes` likely manages a queue of tasks waiting for asynchronous operations.
17. **Builtin Function Dispatch:** `InitializeBuiltinJSDispatchTable` is for setting up the mechanism to call built-in JavaScript functions efficiently.
18. **Internationalization (Intl):** The presence of `#ifdef V8_INTL_SUPPORT` and functions like `DefaultLocale`, `ResetDefaultLocale`, and `get_cached_icu_object` indicate support for internationalization features.

**Connecting to JavaScript:**

Many of these features directly support JavaScript functionality. For example, the promise handling code is fundamental to JavaScript's asynchronous programming model. Use counters track the usage of JavaScript features. Context management is crucial for the correct execution of JavaScript code within different scopes. The Wasm integration allows JavaScript to interact with WebAssembly modules.

**JavaScript Examples:**

* **Promises:**
  ```javascript
  const myPromise = new Promise((resolve, reject) => {
    setTimeout(() => {
      resolve("Promise resolved!");
    }, 1000);
  });

  myPromise.then(result => {
    console.log(result); // This part relates to the "OnPromiseAfter" functionality
  });
  ```
* **`async`/`await` (built on Promises):**
  ```javascript
  async function fetchData() {
    try {
      const response = await fetch('https://example.com/data');
      const data = await response.json();
      return data;
    } catch (error) {
      // This relates to promise rejection and potentially the "ReportPromiseReject" function
      console.error("Error fetching data:", error);
    }
  }

  fetchData();
  ```
* **Internationalization (Intl):**
  ```javascript
  const dateFormatter = new Intl.DateTimeFormat('en-US');
  console.log(dateFormatter.format(new Date())); // This utilizes the ICU library handled by the Intl-related code
  ```
* **WebAssembly:**
  ```javascript
  fetch('module.wasm')
    .then(response => response.arrayBuffer())
    .then(bytes => WebAssembly.instantiate(bytes))
    .then(results => {
      results.instance.exports.exported_function(); // Interaction with WASM is handled by the WASM-related parts
    });
  ```
这个C++代码文件（`v8/src/execution/isolate.cc` 的第5部分）主要负责 **V8 引擎中 `Isolate` 对象的生命周期管理和一些核心功能的实现，特别是与异步操作、性能监控、内存管理以及与 JavaScript 功能的对接方面**。

这是该文件的最后一部分，它涵盖了以下关键功能：

**1. 异步操作和 Promise 处理的收尾工作:**

* **`DefaultWasmAsyncResolvePromiseCallback`:**  这是一个默认的回调函数，用于在 WebAssembly 异步操作完成后解析或拒绝 Promise。
* **`async_waiter_queue_nodes_`:** 维护一个异步等待队列的节点列表，用于管理异步操作的等待者。

**2. 内置 JavaScript 函数的初始化:**

* **`InitializeBuiltinJSDispatchTable`:**  负责初始化内置 JavaScript 函数的调度表，这是一个性能关键的优化，允许快速调用内置函数。

**3. 辅助调试和性能分析的功能:**

* **`load_from_stack_count_address` 和 `store_to_stack_count_address`:**  提供函数地址，用于统计特定函数中堆栈的加载和存储操作次数，这通常用于性能分析和调试。

**4. 作用域局部变量阻塞列表的缓存:**

* **`LocalsBlockListCacheSet` 和 `LocalsBlockListCacheGet`:**  用于缓存作用域的局部变量阻塞列表，这是一个优化，可以避免在每次访问作用域时都重新计算阻塞列表。

**5. WebAssembly 集成:**

* **`initialize_wasm_execution_timer` (在 `V8_ENABLE_DRUMBRAKE` 宏定义下):**  初始化 WebAssembly 执行时间计时器，用于性能分析。

**与 JavaScript 功能的关系及举例:**

这个文件中的许多功能都直接或间接地支持着 JavaScript 的运行。

* **Promise 处理:**  `DefaultWasmAsyncResolvePromiseCallback` 直接与 JavaScript 的 `Promise` 对象交互，用于处理异步 WebAssembly 模块的执行结果。

  ```javascript
  // JavaScript 示例：使用 WebAssembly 的异步操作和 Promise
  WebAssembly.instantiateStreaming(fetch('module.wasm'))
    .then(result => {
      const wasm_exports = result.instance.exports;
      // 假设 wasm_exports 中有一个返回 Promise 的异步函数
      wasm_exports.asyncFunction().then(value => {
        console.log("WebAssembly 异步操作完成:", value);
      });
    });
  ```

* **内置函数调度:** `InitializeBuiltinJSDispatchTable` 确保了像 `Array.prototype.map` 或 `console.log` 这样的内置 JavaScript 函数能够被高效地调用。

  ```javascript
  // JavaScript 示例：调用内置函数
  const numbers = [1, 2, 3];
  const doubled = numbers.map(n => n * 2); // map 是一个内置函数
  console.log(doubled); // console.log 也是一个内置函数
  ```

* **作用域和局部变量:** `LocalsBlockListCacheSet` 和 `LocalsBlockListCacheGet` 优化了 JavaScript 引擎处理作用域和局部变量的方式，例如在闭包中访问外部变量时。

  ```javascript
  // JavaScript 示例：闭包和局部变量
  function outerFunction() {
    const outerVariable = 10;
    return function innerFunction() {
      console.log(outerVariable); // innerFunction 访问了 outerFunction 的局部变量
    }
  }

  const myInnerFunction = outerFunction();
  myInnerFunction();
  ```

总而言之，这个代码文件的最后部分涵盖了 `Isolate` 对象生命周期中一些关键的收尾工作和优化，以及与 JavaScript 异步编程模型、内置函数执行和作用域管理等核心功能紧密相关的实现细节。这些功能共同确保了 V8 引擎能够高效、稳定地执行 JavaScript 代码。

Prompt: 
```
这是目录为v8/src/execution/isolate.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第5部分，共5部分，请归纳一下它的功能

"""
value());
  if (HasAsyncEventDelegate()) {
    if (promise->has_async_task_id()) {
      async_event_delegate_->AsyncEventOccurred(
          debug::kDebugDidHandle, promise->async_task_id(), false);
    }
  }
}

void Isolate::OnStackTraceCaptured(Handle<StackTraceInfo> stack_trace) {
  if (HasAsyncEventDelegate()) {
    async_event_delegate_->AsyncEventOccurred(debug::kDebugStackTraceCaptured,
                                              stack_trace->id(), false);
  }
}

void Isolate::OnTerminationDuringRunMicrotasks() {
  DCHECK(is_execution_terminating());
  // This performs cleanup for when RunMicrotasks (in
  // builtins-microtask-queue-gen.cc) is aborted via a termination exception.
  // This has to be kept in sync with the code in said file. Currently this
  // includes:
  //
  //  (1) Resetting the |current_microtask| slot on the Isolate to avoid leaking
  //      memory (and also to keep |current_microtask| not being undefined as an
  //      indicator that we're currently pumping the microtask queue).
  //  (2) Empty the promise stack to avoid leaking memory.
  //  (3) If the |current_microtask| is a promise reaction or resolve thenable
  //      job task, then signal the async event delegate and debugger that the
  //      microtask finished running.
  //

  // Reset the |current_microtask| global slot.
  DirectHandle<Microtask> current_microtask(
      Cast<Microtask>(heap()->current_microtask()), this);
  heap()->set_current_microtask(ReadOnlyRoots(this).undefined_value());

  if (IsPromiseReactionJobTask(*current_microtask)) {
    auto promise_reaction_job_task =
        Cast<PromiseReactionJobTask>(current_microtask);
    Handle<HeapObject> promise_or_capability(
        promise_reaction_job_task->promise_or_capability(), this);
    if (IsPromiseCapability(*promise_or_capability)) {
      promise_or_capability = handle(
          Cast<PromiseCapability>(promise_or_capability)->promise(), this);
    }
    if (IsJSPromise(*promise_or_capability)) {
      OnPromiseAfter(Cast<JSPromise>(promise_or_capability));
    }
  } else if (IsPromiseResolveThenableJobTask(*current_microtask)) {
    auto promise_resolve_thenable_job_task =
        Cast<PromiseResolveThenableJobTask>(current_microtask);
    Handle<JSPromise> promise_to_resolve(
        promise_resolve_thenable_job_task->promise_to_resolve(), this);
    OnPromiseAfter(promise_to_resolve);
  }

  SetTerminationOnExternalTryCatch();
}

void Isolate::SetPromiseRejectCallback(PromiseRejectCallback callback) {
  promise_reject_callback_ = callback;
}

void Isolate::ReportPromiseReject(Handle<JSPromise> promise,
                                  Handle<Object> value,
                                  v8::PromiseRejectEvent event) {
  if (promise_reject_callback_ == nullptr) return;
  promise_reject_callback_(v8::PromiseRejectMessage(
      v8::Utils::PromiseToLocal(promise), event, v8::Utils::ToLocal(value)));
}

void Isolate::SetUseCounterCallback(v8::Isolate::UseCounterCallback callback) {
  DCHECK(!use_counter_callback_);
  use_counter_callback_ = callback;
}

void Isolate::CountUsage(v8::Isolate::UseCounterFeature feature) {
  CountUsage(base::VectorOf({feature}));
}

void Isolate::CountUsage(
    base::Vector<const v8::Isolate::UseCounterFeature> features) {
  // The counter callback
  // - may cause the embedder to call into V8, which is not generally possible
  //   during GC.
  // - requires a current native context, which may not always exist.
  // TODO(jgruber): Consider either removing the native context requirement in
  // blink, or passing it to the callback explicitly.
  if (heap_.gc_state() == Heap::NOT_IN_GC && !context().is_null()) {
    DCHECK(IsContext(context()));
    DCHECK(IsNativeContext(context()->native_context()));
    if (use_counter_callback_) {
      HandleScope handle_scope(this);
      for (auto feature : features) {
        use_counter_callback_(reinterpret_cast<v8::Isolate*>(this), feature);
      }
    }
  } else {
    heap_.IncrementDeferredCounts(features);
  }
}

int Isolate::GetNextScriptId() { return heap()->NextScriptId(); }

// static
std::string Isolate::GetTurboCfgFileName(Isolate* isolate) {
  if (const char* filename = v8_flags.trace_turbo_cfg_file) return filename;
  std::ostringstream os;
  os << "turbo-" << base::OS::GetCurrentProcessId() << "-";
  if (isolate != nullptr) {
    os << isolate->id();
  } else {
    os << "any";
  }
  os << ".cfg";
  return os.str();
}

// Heap::detached_contexts tracks detached contexts as pairs
// (the context, number of GC since the context was detached).
void Isolate::AddDetachedContext(Handle<Context> context) {
  HandleScope scope(this);
  Handle<WeakArrayList> detached_contexts = factory()->detached_contexts();
  detached_contexts = WeakArrayList::AddToEnd(
      this, detached_contexts, MaybeObjectDirectHandle::Weak(context),
      Smi::zero());
  heap()->set_detached_contexts(*detached_contexts);
}

void Isolate::CheckDetachedContextsAfterGC() {
  HandleScope scope(this);
  DirectHandle<WeakArrayList> detached_contexts =
      factory()->detached_contexts();
  int length = detached_contexts->length();
  if (length == 0) return;
  int new_length = 0;
  for (int i = 0; i < length; i += 2) {
    Tagged<MaybeObject> context = detached_contexts->Get(i);
    DCHECK(context.IsWeakOrCleared());
    if (!context.IsCleared()) {
      int mark_sweeps = detached_contexts->Get(i + 1).ToSmi().value();
      detached_contexts->Set(new_length, context);
      detached_contexts->Set(new_length + 1, Smi::FromInt(mark_sweeps + 1));
      new_length += 2;
    }
  }
  detached_contexts->set_length(new_length);
  while (new_length < length) {
    detached_contexts->Set(new_length, Smi::zero());
    ++new_length;
  }

  if (v8_flags.trace_detached_contexts) {
    PrintF("%d detached contexts are collected out of %d\n",
           length - new_length, length);
    for (int i = 0; i < new_length; i += 2) {
      Tagged<MaybeObject> context = detached_contexts->Get(i);
      int mark_sweeps = detached_contexts->Get(i + 1).ToSmi().value();
      DCHECK(context.IsWeakOrCleared());
      if (mark_sweeps > 3) {
        PrintF("detached context %p\n survived %d GCs (leak?)\n",
               reinterpret_cast<void*>(context.ptr()), mark_sweeps);
      }
    }
  }
}

void Isolate::DetachGlobal(Handle<Context> env) {
  counters()->errors_thrown_per_context()->AddSample(
      env->native_context()->GetErrorsThrown());

  ReadOnlyRoots roots(this);
  DirectHandle<JSGlobalProxy> global_proxy(env->global_proxy(), this);
  // NOTE: Turbofan's JSNativeContextSpecialization and Maglev depend on
  // DetachGlobal causing a map change.
  JSObject::ForceSetPrototype(this, global_proxy, factory()->null_value());
  // Detach the global object from the native context by making its map
  // contextless (use the global metamap instead of the contextful one).
  global_proxy->map()->set_map(this, roots.meta_map());
  global_proxy->map()->set_constructor_or_back_pointer(roots.null_value(),
                                                       kRelaxedStore);
  if (v8_flags.track_detached_contexts) AddDetachedContext(env);
  DCHECK(global_proxy->IsDetached());

  env->native_context()->set_microtask_queue(this, nullptr);
}

void Isolate::UpdateLoadStartTime() { heap()->UpdateLoadStartTime(); }

void Isolate::SetRAILMode(RAILMode rail_mode) {
  bool is_loading = rail_mode == PERFORMANCE_LOAD;
  bool was_loading = is_loading_.exchange(is_loading);
  if (is_loading && !was_loading) {
    heap()->NotifyLoadingStarted();
  }
  if (!is_loading && was_loading) {
    heap()->NotifyLoadingEnded();
  }
  if (v8_flags.trace_rail) {
    PrintIsolate(this, "RAIL mode: %s\n", RAILModeName(rail_mode));
  }
}

void Isolate::SetIsLoading(bool is_loading) {
  is_loading_.store(is_loading);
  if (is_loading) {
    heap()->NotifyLoadingStarted();
  } else {
    heap()->NotifyLoadingEnded();
  }
  if (v8_flags.trace_rail) {
    // TODO(crbug.com/373688984): Switch to a trace flag for loading state.
    PrintIsolate(this, "RAIL mode: %s\n", is_loading ? "LOAD" : "ANIMATION");
  }
}

void Isolate::SetPriority(v8::Isolate::Priority priority) {
  priority_ = priority;
  heap()->tracer()->UpdateCurrentEventPriority(priority_);
  if (priority_ == v8::Isolate::Priority::kBestEffort) {
    heap()->ActivateMemoryReducerIfNeeded();
  }
}

void Isolate::PrintWithTimestamp(const char* format, ...) {
  base::OS::Print("[%d:%p] %8.0f ms: ", base::OS::GetCurrentProcessId(),
                  static_cast<void*>(this), time_millis_since_init());
  va_list arguments;
  va_start(arguments, format);
  base::OS::VPrint(format, arguments);
  va_end(arguments);
}

void Isolate::SetIdle(bool is_idle) {
  StateTag state = current_vm_state();
  if (js_entry_sp() != kNullAddress) return;
  DCHECK(state == EXTERNAL || state == IDLE);
  if (is_idle) {
    set_current_vm_state(IDLE);
  } else if (state == IDLE) {
    set_current_vm_state(EXTERNAL);
  }
}

void Isolate::CollectSourcePositionsForAllBytecodeArrays() {
  if (!initialized_) return;

  HandleScope scope(this);
  std::vector<Handle<SharedFunctionInfo>> sfis;
  {
    HeapObjectIterator iterator(heap());
    for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
         obj = iterator.Next()) {
      if (!IsSharedFunctionInfo(obj)) continue;
      Tagged<SharedFunctionInfo> sfi = Cast<SharedFunctionInfo>(obj);
      // If the script is a Smi, then the SharedFunctionInfo is in
      // the process of being deserialized.
      Tagged<Object> script = sfi->raw_script(kAcquireLoad);
      if (IsSmi(script)) {
        DCHECK_EQ(script, Smi::uninitialized_deserialization_value());
        continue;
      }
      if (!sfi->CanCollectSourcePosition(this)) continue;
      sfis.push_back(Handle<SharedFunctionInfo>(sfi, this));
    }
  }
  for (auto sfi : sfis) {
    SharedFunctionInfo::EnsureSourcePositionsAvailable(this, sfi);
  }
}

#ifdef V8_INTL_SUPPORT

namespace {

std::string GetStringFromLocales(Isolate* isolate,
                                 DirectHandle<Object> locales) {
  if (IsUndefined(*locales, isolate)) return "";
  return std::string(Cast<String>(*locales)->ToCString().get());
}

bool StringEqualsLocales(Isolate* isolate, const std::string& str,
                         Handle<Object> locales) {
  if (IsUndefined(*locales, isolate)) return str.empty();
  return Cast<String>(locales)->IsEqualTo(
      base::VectorOf(str.c_str(), str.length()));
}

}  // namespace

const std::string& Isolate::DefaultLocale() {
  if (default_locale_.empty()) {
    icu::Locale default_locale;
    // Translate ICU's fallback locale to a well-known locale.
    if (strcmp(default_locale.getName(), "en_US_POSIX") == 0 ||
        strcmp(default_locale.getName(), "c") == 0) {
      set_default_locale("en-US");
    } else {
      // Set the locale
      set_default_locale(default_locale.isBogus()
                             ? "und"
                             : Intl::ToLanguageTag(default_locale).FromJust());
    }
    DCHECK(!default_locale_.empty());
  }
  return default_locale_;
}

void Isolate::ResetDefaultLocale() {
  default_locale_.clear();
  clear_cached_icu_objects();
  // We inline fast paths assuming certain locales. Since this path is rarely
  // taken, we deoptimize everything to keep things simple.
  Deoptimizer::DeoptimizeAll(this);
}

icu::UMemory* Isolate::get_cached_icu_object(ICUObjectCacheType cache_type,
                                             Handle<Object> locales) {
  const ICUObjectCacheEntry& entry =
      icu_object_cache_[static_cast<int>(cache_type)];
  return StringEqualsLocales(this, entry.locales, locales) ? entry.obj.get()
                                                           : nullptr;
}

void Isolate::set_icu_object_in_cache(ICUObjectCacheType cache_type,
                                      DirectHandle<Object> locales,
                                      std::shared_ptr<icu::UMemory> obj) {
  icu_object_cache_[static_cast<int>(cache_type)] = {
      GetStringFromLocales(this, locales), std::move(obj)};
}

void Isolate::clear_cached_icu_object(ICUObjectCacheType cache_type) {
  icu_object_cache_[static_cast<int>(cache_type)] = ICUObjectCacheEntry{};
}

void Isolate::clear_cached_icu_objects() {
  for (int i = 0; i < kICUObjectCacheTypeCount; i++) {
    clear_cached_icu_object(static_cast<ICUObjectCacheType>(i));
  }
}

#endif  // V8_INTL_SUPPORT

bool StackLimitCheck::HandleStackOverflowAndTerminationRequest() {
  DCHECK(InterruptRequested());
  if (V8_UNLIKELY(HasOverflowed())) {
    isolate_->StackOverflow();
    return true;
  }
  if (V8_UNLIKELY(isolate_->stack_guard()->HasTerminationRequest())) {
    isolate_->TerminateExecution();
    return true;
  }
  return false;
}

bool StackLimitCheck::JsHasOverflowed(uintptr_t gap) const {
  StackGuard* stack_guard = isolate_->stack_guard();
#ifdef USE_SIMULATOR
  // The simulator uses a separate JS stack.
  Address jssp_address = Simulator::current(isolate_)->get_sp();
  uintptr_t jssp = static_cast<uintptr_t>(jssp_address);
  if (jssp - gap < stack_guard->real_jslimit()) return true;
#endif  // USE_SIMULATOR
  return GetCurrentStackPosition() - gap < stack_guard->real_climit();
}

bool StackLimitCheck::WasmHasOverflowed(uintptr_t gap) const {
  StackGuard* stack_guard = isolate_->stack_guard();
  auto sp = isolate_->thread_local_top()->secondary_stack_sp_;
  auto limit = isolate_->thread_local_top()->secondary_stack_limit_;
  if (sp == 0) {
#ifdef USE_SIMULATOR
    // The simulator uses a separate JS stack.
    // Use it if code is executed on the central stack.
    Address jssp_address = Simulator::current(isolate_)->get_sp();
    uintptr_t jssp = static_cast<uintptr_t>(jssp_address);
    if (jssp - gap < stack_guard->real_jslimit()) return true;
#endif  // USE_SIMULATOR
    sp = GetCurrentStackPosition();
    limit = stack_guard->real_climit();
  }
  return sp - gap < limit;
}

SaveContext::SaveContext(Isolate* isolate) : isolate_(isolate) {
  if (!isolate->context().is_null()) {
    context_ = Handle<Context>(isolate->context(), isolate);
  }
  if (!isolate->topmost_script_having_context().is_null()) {
    topmost_script_having_context_ =
        Handle<Context>(isolate->topmost_script_having_context(), isolate);
  }
}

SaveContext::~SaveContext() {
  isolate_->set_context(context_.is_null() ? Tagged<Context>() : *context_);
  isolate_->set_topmost_script_having_context(
      topmost_script_having_context_.is_null()
          ? Tagged<Context>()
          : *topmost_script_having_context_);
}

SaveAndSwitchContext::SaveAndSwitchContext(Isolate* isolate,
                                           Tagged<Context> new_context)
    : SaveContext(isolate) {
  isolate->set_context(new_context);
}

#ifdef DEBUG
AssertNoContextChange::AssertNoContextChange(Isolate* isolate)
    : isolate_(isolate),
      context_(isolate->context(), isolate),
      topmost_script_having_context_(isolate->topmost_script_having_context(),
                                     isolate) {}

namespace {

bool Overlapping(const MemoryRange& a, const MemoryRange& b) {
  uintptr_t a1 = reinterpret_cast<uintptr_t>(a.start);
  uintptr_t a2 = a1 + a.length_in_bytes;
  uintptr_t b1 = reinterpret_cast<uintptr_t>(b.start);
  uintptr_t b2 = b1 + b.length_in_bytes;
  // Either b1 or b2 are in the [a1, a2) range.
  return (a1 <= b1 && b1 < a2) || (a1 <= b2 && b2 < a2);
}

}  // anonymous namespace

#endif  // DEBUG

void Isolate::AddCodeMemoryRange(MemoryRange range) {
  base::MutexGuard guard(&code_pages_mutex_);
  std::vector<MemoryRange>* old_code_pages = GetCodePages();
  DCHECK_NOT_NULL(old_code_pages);
#ifdef DEBUG
  auto overlapping = [range](const MemoryRange& a) {
    return Overlapping(range, a);
  };
  DCHECK_EQ(old_code_pages->end(),
            std::find_if(old_code_pages->begin(), old_code_pages->end(),
                         overlapping));
#endif

  std::vector<MemoryRange>* new_code_pages;
  if (old_code_pages == &code_pages_buffer1_) {
    new_code_pages = &code_pages_buffer2_;
  } else {
    new_code_pages = &code_pages_buffer1_;
  }

  // Copy all existing data from the old vector to the new vector and insert the
  // new page.
  new_code_pages->clear();
  new_code_pages->reserve(old_code_pages->size() + 1);
  std::merge(old_code_pages->begin(), old_code_pages->end(), &range, &range + 1,
             std::back_inserter(*new_code_pages),
             [](const MemoryRange& a, const MemoryRange& b) {
               return a.start < b.start;
             });

  // Atomically switch out the pointer
  SetCodePages(new_code_pages);
}

// |chunk| is either a Page or an executable LargePage.
void Isolate::AddCodeMemoryChunk(MutablePageMetadata* chunk) {
  // We only keep track of individual code pages/allocations if we are on arm32,
  // because on x64 and arm64 we have a code range which makes this unnecessary.
#if defined(V8_TARGET_ARCH_ARM)
  void* new_page_start = reinterpret_cast<void*>(chunk->area_start());
  size_t new_page_size = chunk->area_size();

  MemoryRange new_range{new_page_start, new_page_size};

  AddCodeMemoryRange(new_range);
#endif  // !defined(V8_TARGET_ARCH_ARM)
}

void Isolate::AddCodeRange(Address begin, size_t length_in_bytes) {
  AddCodeMemoryRange(
      MemoryRange{reinterpret_cast<void*>(begin), length_in_bytes});
}

bool Isolate::RequiresCodeRange() const {
  return kPlatformRequiresCodeRange && !jitless_;
}

v8::metrics::Recorder::ContextId Isolate::GetOrRegisterRecorderContextId(
    DirectHandle<NativeContext> context) {
  if (serializer_enabled_) return v8::metrics::Recorder::ContextId::Empty();
  i::Tagged<i::Object> id = context->recorder_context_id();
  if (IsNullOrUndefined(id)) {
    CHECK_LT(last_recorder_context_id_, i::Smi::kMaxValue);
    context->set_recorder_context_id(
        i::Smi::FromIntptr(++last_recorder_context_id_));
    v8::HandleScope handle_scope(reinterpret_cast<v8::Isolate*>(this));
    auto result = recorder_context_id_map_.emplace(
        std::piecewise_construct,
        std::forward_as_tuple(last_recorder_context_id_),
        std::forward_as_tuple(reinterpret_cast<v8::Isolate*>(this),
                              ToApiHandle<v8::Context>(context)));
    result.first->second.SetWeak(
        reinterpret_cast<void*>(last_recorder_context_id_),
        RemoveContextIdCallback, v8::WeakCallbackType::kParameter);
    return v8::metrics::Recorder::ContextId(last_recorder_context_id_);
  } else {
    DCHECK(IsSmi(id));
    return v8::metrics::Recorder::ContextId(
        static_cast<uintptr_t>(i::Smi::ToInt(id)));
  }
}

MaybeLocal<v8::Context> Isolate::GetContextFromRecorderContextId(
    v8::metrics::Recorder::ContextId id) {
  auto result = recorder_context_id_map_.find(id.id_);
  if (result == recorder_context_id_map_.end() || result->second.IsEmpty())
    return MaybeLocal<v8::Context>();
  return result->second.Get(reinterpret_cast<v8::Isolate*>(this));
}

void Isolate::UpdateLongTaskStats() {
  if (last_long_task_stats_counter_ != isolate_data_.long_task_stats_counter_) {
    last_long_task_stats_counter_ = isolate_data_.long_task_stats_counter_;
    long_task_stats_ = v8::metrics::LongTaskStats{};
  }
}

v8::metrics::LongTaskStats* Isolate::GetCurrentLongTaskStats() {
  UpdateLongTaskStats();
  return &long_task_stats_;
}

void Isolate::RemoveContextIdCallback(const v8::WeakCallbackInfo<void>& data) {
  Isolate* isolate = reinterpret_cast<Isolate*>(data.GetIsolate());
  uintptr_t context_id = reinterpret_cast<uintptr_t>(data.GetParameter());
  isolate->recorder_context_id_map_.erase(context_id);
}

LocalHeap* Isolate::main_thread_local_heap() {
  return main_thread_local_isolate()->heap();
}

LocalHeap* Isolate::CurrentLocalHeap() {
  LocalHeap* local_heap = LocalHeap::Current();
  if (local_heap) return local_heap;
  DCHECK_EQ(ThreadId::Current(), thread_id());
  return main_thread_local_heap();
}

// |chunk| is either a Page or an executable LargePage.
void Isolate::RemoveCodeMemoryChunk(MutablePageMetadata* chunk) {
  // We only keep track of individual code pages/allocations if we are on arm32,
  // because on x64 and arm64 we have a code range which makes this unnecessary.
#if defined(V8_TARGET_ARCH_ARM)
  void* removed_page_start = reinterpret_cast<void*>(chunk->area_start());
  std::vector<MemoryRange>* old_code_pages = GetCodePages();
  DCHECK_NOT_NULL(old_code_pages);

  std::vector<MemoryRange>* new_code_pages;
  if (old_code_pages == &code_pages_buffer1_) {
    new_code_pages = &code_pages_buffer2_;
  } else {
    new_code_pages = &code_pages_buffer1_;
  }

  // Copy all existing data from the old vector to the new vector except the
  // removed page.
  new_code_pages->clear();
  new_code_pages->reserve(old_code_pages->size() - 1);
  std::remove_copy_if(old_code_pages->begin(), old_code_pages->end(),
                      std::back_inserter(*new_code_pages),
                      [removed_page_start](const MemoryRange& range) {
                        return range.start == removed_page_start;
                      });
  DCHECK_EQ(old_code_pages->size(), new_code_pages->size() + 1);
  // Atomically switch out the pointer
  SetCodePages(new_code_pages);
#endif  // !defined(V8_TARGET_ARCH_ARM)
}

#if V8_ENABLE_DRUMBRAKE
void Isolate::initialize_wasm_execution_timer() {
  DCHECK(v8_flags.wasm_enable_exec_time_histograms &&
         v8_flags.slow_histograms && !v8_flags.wasm_jitless);
  wasm_execution_timer_ =
      std::make_unique<wasm::WasmExecutionTimer>(this, false);
}
#endif  // V8_ENABLE_DRUMBRAKE

#undef TRACE_ISOLATE

// static
Address Isolate::load_from_stack_count_address(const char* function_name) {
  DCHECK_NOT_NULL(function_name);
  if (!stack_access_count_map) {
    stack_access_count_map = new MapOfLoadsAndStoresPerFunction{};
  }
  auto& map = *stack_access_count_map;
  std::string name(function_name);
  // It is safe to return the address of std::map values.
  // Only iterators and references to the erased elements are invalidated.
  return reinterpret_cast<Address>(&map[name].first);
}

// static
Address Isolate::store_to_stack_count_address(const char* function_name) {
  DCHECK_NOT_NULL(function_name);
  if (!stack_access_count_map) {
    stack_access_count_map = new MapOfLoadsAndStoresPerFunction{};
  }
  auto& map = *stack_access_count_map;
  std::string name(function_name);
  // It is safe to return the address of std::map values.
  // Only iterators and references to the erased elements are invalidated.
  return reinterpret_cast<Address>(&map[name].second);
}

void Isolate::LocalsBlockListCacheSet(Handle<ScopeInfo> scope_info,
                                      Handle<ScopeInfo> outer_scope_info,
                                      Handle<StringSet> locals_blocklist) {
  Handle<EphemeronHashTable> cache;
  if (IsEphemeronHashTable(heap()->locals_block_list_cache())) {
    cache = handle(Cast<EphemeronHashTable>(heap()->locals_block_list_cache()),
                   this);
  } else {
    CHECK(IsUndefined(heap()->locals_block_list_cache()));
    constexpr int kInitialCapacity = 8;
    cache = EphemeronHashTable::New(this, kInitialCapacity);
  }
  DCHECK(IsEphemeronHashTable(*cache));

  Handle<Object> value;
  if (!outer_scope_info.is_null()) {
    value = factory()->NewTuple2(outer_scope_info, locals_blocklist,
                                 AllocationType::kYoung);
  } else {
    value = locals_blocklist;
  }

  CHECK(!value.is_null());
  cache = EphemeronHashTable::Put(cache, scope_info, value);
  heap()->set_locals_block_list_cache(*cache);
}

Tagged<Object> Isolate::LocalsBlockListCacheGet(Handle<ScopeInfo> scope_info) {
  DisallowGarbageCollection no_gc;

  if (!IsEphemeronHashTable(heap()->locals_block_list_cache())) {
    return ReadOnlyRoots(this).the_hole_value();
  }

  Tagged<Object> maybe_value =
      Cast<EphemeronHashTable>(heap()->locals_block_list_cache())
          ->Lookup(scope_info);
  if (IsTuple2(maybe_value)) return Cast<Tuple2>(maybe_value)->value2();

  CHECK(IsStringSet(maybe_value) || IsTheHole(maybe_value));
  return maybe_value;
}

std::list<std::unique_ptr<detail::WaiterQueueNode>>&
Isolate::async_waiter_queue_nodes() {
  return async_waiter_queue_nodes_;
}

void DefaultWasmAsyncResolvePromiseCallback(
    v8::Isolate* isolate, v8::Local<v8::Context> context,
    v8::Local<v8::Promise::Resolver> resolver, v8::Local<v8::Value> result,
    WasmAsyncSuccess success) {
  MicrotasksScope microtasks_scope(context,
                                   MicrotasksScope::kDoNotRunMicrotasks);

  Maybe<bool> ret = success == WasmAsyncSuccess::kSuccess
                        ? resolver->Resolve(context, result)
                        : resolver->Reject(context, result);
  // It's guaranteed that no exceptions will be thrown by these
  // operations, but execution might be terminating.
  CHECK(ret.IsJust() ? ret.FromJust() : isolate->IsExecutionTerminating());
}

// Mutex used to ensure that the dispatch table entries for builtins are only
// initialized once.
base::LazyMutex read_only_dispatch_entries_mutex_ = LAZY_MUTEX_INITIALIZER;

void Isolate::InitializeBuiltinJSDispatchTable() {
#ifdef V8_ENABLE_LEAPTIERING
  // Ideally these entries would be created when the read only heap is
  // initialized. However, since builtins are deserialized later, we need to
  // patch it up here. Also, we need a mutex so the shared read only heaps space
  // is not initialized multiple times. This must be blocking as no isolate
  // should be allowed to proceed until the table is initialized.
  base::MutexGuard guard(read_only_dispatch_entries_mutex_.Pointer());
  auto jdt = GetProcessWideJSDispatchTable();
  if (jdt->PreAllocatedEntryNeedsInitialization(
          read_only_heap_->js_dispatch_table_space(),
          builtin_dispatch_handle(JSBuiltinDispatchHandleRoot::Idx::kFirst))) {
    JSDispatchTable::UnsealReadOnlySegmentScope unseal_scope(jdt);
    for (JSBuiltinDispatchHandleRoot::Idx idx =
             JSBuiltinDispatchHandleRoot::kFirst;
         idx < JSBuiltinDispatchHandleRoot::kCount;
         idx = static_cast<JSBuiltinDispatchHandleRoot::Idx>(
             static_cast<int>(idx) + 1)) {
      Builtin builtin = JSBuiltinDispatchHandleRoot::to_builtin(idx);
      DCHECK(Builtins::IsIsolateIndependent(builtin));
      Tagged<Code> code = builtins_.code(builtin);
      DCHECK(code->entrypoint_tag() == CodeEntrypointTag::kJSEntrypointTag);
      JSDispatchHandle handle = builtin_dispatch_handle(builtin);
      // TODO(olivf, 40931165): It might be more robust to get the static
      // parameter count of this builtin.
      int parameter_count = code->parameter_count();
      jdt->InitializePreAllocatedEntry(
          read_only_heap_->js_dispatch_table_space(), handle, code,
          parameter_count);
    }
  }
#endif
}

}  // namespace internal
}  // namespace v8

"""


```