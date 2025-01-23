Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/api/api.cc`.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Class:** The code heavily features the `Isolate` class. This immediately suggests the file deals with the concept of an isolate in V8.

2. **Recognize the Bridging Role:**  Notice the consistent pattern of `reinterpret_cast<i::Isolate*>(this)` and accessing members like `i_isolate->heap()`, `i_isolate->stack_guard()`, etc. This indicates that the `v8::Isolate` class is a public API that delegates to the internal `i::Isolate` implementation. The file `api.cc` likely serves as a bridge between the public C++ API and the internal V8 engine.

3. **Group Functionality by Area:** Go through each function and categorize its purpose. Look for keywords and patterns:
    * **Memory Management:**  `AttachCppHeap`, `DetachCppHeap`, `GetCppHeap`, `SetGetExternallyAllocatedMemoryInBytesCallback`, `GetHeapStatistics`, `GetHeapSpaceStatistics`, `AdjustAmountOfExternalAllocatedMemory`, `LowMemoryNotification`, `MemoryPressureNotification`.
    * **Execution Control:** `TerminateExecution`, `IsExecutionTerminating`, `CancelTerminateExecution`, `RequestInterrupt`, `HasPendingBackgroundTasks`.
    * **Garbage Collection:** `RequestGarbageCollectionForTesting`.
    * **Isolate Lifecycle:** `GetCurrent`, `TryGetCurrent`, `IsCurrent`, `Allocate`, `Initialize`, `New`, `Dispose`, `Enter`, `Exit`.
    * **Snapshot Management:** The `Initialize` function dealing with `snapshot_blob`.
    * **Error Handling:** `SetFatalErrorHandler`, `SetOOMErrorHandler`, `DisallowJavascriptExecutionScope`, `AllowJavascriptExecutionScope`.
    * **Callbacks and Hooks:**  A large number of `Set...Callback` functions, such as `SetAbortOnUncaughtExceptionCallback`, `SetHostImportModuleDynamicallyCallback`, `SetPromiseHook`, etc.
    * **Microtasks:** `PerformMicrotaskCheckpoint`, `EnqueueMicrotask`, `SetMicrotasksPolicy`, `AddMicrotasksCompletedCallback`.
    * **Debugging and Profiling:** `DumpAndResetStats`, `GetStackTraceLimit`, `GetStackSample`, `SetJitCodeEventHandler`.
    * **Counters and Metrics:** `SetCounterFunction`, `SetCreateHistogramFunction`, `SetAddHistogramSampleFunction`, `SetMetricsRecorder`, `SetUseCounterCallback`.
    * **WebAssembly (Conditional):**  The `#if V8_ENABLE_WEBASSEMBLY` blocks.
    * **Continuation Preservation (Conditional):** `#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA`.

4. **Address Specific Questions:**
    * **`.tq` extension:** Explicitly state that the file does *not* have a `.tq` extension and is therefore not a Torque file.
    * **JavaScript Relation:** Focus on functions that directly impact JavaScript execution, like setting callbacks for promises, exceptions, dynamic imports, and microtasks. Provide concrete JavaScript examples to illustrate these connections.
    * **Code Logic Reasoning:** Identify functions with straightforward input/output behavior (e.g., setting and getting callbacks, checking boolean flags) and provide simple examples.
    * **Common Programming Errors:** Think about how users might misuse the provided API functions, such as disposing of an active isolate or forgetting to handle asynchronous operations.

5. **Summarize the Overall Functionality:** Combine the categorized functionalities into a concise summary, emphasizing the role of `v8::Isolate` as the central point of interaction with a V8 instance. Highlight its responsibilities in managing memory, execution, callbacks, and other core aspects.

6. **Address the "Part 13 of 15" Context:** Acknowledge the sequential nature implied by the numbering and suggest that this file likely focuses on the core `Isolate` functionality, setting the stage for higher-level APIs covered in other parts.

7. **Review and Refine:** Read through the generated answer to ensure clarity, accuracy, and completeness. Check for any inconsistencies or missing information. For example, initially, I might have missed the connection between `RequestInterrupt` and JavaScript, but upon review, I'd realize it's a mechanism to break JavaScript execution.
```cpp
ate*>(this);
  i_isolate->heap()->AttachCppHeap(cpp_heap);
}

void Isolate::DetachCppHeap() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->heap()->DetachCppHeap();
}

CppHeap* Isolate::GetCppHeap() const {
  const i::Isolate* i_isolate = reinterpret_cast<const i::Isolate*>(this);
  return i_isolate->heap()->cpp_heap();
}

void Isolate::SetGetExternallyAllocatedMemoryInBytesCallback(
    GetExternallyAllocatedMemoryInBytesCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->heap()->SetGetExternallyAllocatedMemoryInBytesCallback(callback);
}

void Isolate::TerminateExecution() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->stack_guard()->RequestTerminateExecution();
}

bool Isolate::IsExecutionTerminating() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
#ifdef DEBUG
  // This method might be called on a thread that's not bound to any Isolate
  // and thus pointer compression schemes might have cage base value unset.
  // Read-only roots accessors contain type DCHECKs which require access to
  // V8 heap in order to check the object type. So, allow heap access here
  // to let the checks work.
  i::PtrComprCageAccessScope ptr_compr_cage_access_scope(i_isolate);
#endif  // DEBUG
  return i_isolate->is_execution_terminating();
}

void Isolate::CancelTerminateExecution() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->stack_guard()->ClearTerminateExecution();
  i_isolate->CancelTerminateExecution();
}

void Isolate::RequestInterrupt(InterruptCallback callback, void* data) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->RequestInterrupt(callback, data);
}

bool Isolate::HasPendingBackgroundTasks() {
#if V8_ENABLE_WEBASSEMBLY
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  return i::wasm::GetWasmEngine()->HasRunningCompileJob(i_isolate);
#else
  return false;
#endif  // V8_ENABLE_WEBASSEMBLY
}

void Isolate::RequestGarbageCollectionForTesting(GarbageCollectionType type) {
  Utils::ApiCheck(i::v8_flags.expose_gc,
                  "v8::Isolate::RequestGarbageCollectionForTesting",
                  "Must use --expose-gc");
  if (type == kMinorGarbageCollection) {
    reinterpret_cast<i::Isolate*>(this)->heap()->CollectGarbage(
        i::NEW_SPACE, i::GarbageCollectionReason::kTesting,
        kGCCallbackFlagForced);
  } else {
    DCHECK_EQ(kFullGarbageCollection, type);
    reinterpret_cast<i::Isolate*>(this)->heap()->PreciseCollectAllGarbage(
        i::GCFlag::kNoFlags, i::GarbageCollectionReason::kTesting,
        kGCCallbackFlagForced);
  }
}

void Isolate::RequestGarbageCollectionForTesting(GarbageCollectionType type,
                                                 StackState stack_state) {
  std::optional<i::EmbedderStackStateScope> stack_scope;
  if (type == kFullGarbageCollection) {
    stack_scope.emplace(reinterpret_cast<i::Isolate*>(this)->heap(),
                        i::EmbedderStackStateOrigin::kExplicitInvocation,
                        stack_state);
  }
  RequestGarbageCollectionForTesting(type);
}

Isolate* Isolate::GetCurrent() {
  i::Isolate* i::Isolate::Current();
  return reinterpret_cast<Isolate*>(i_isolate);
}

Isolate* Isolate::TryGetCurrent() {
  i::Isolate* i::Isolate::TryGetCurrent();
  return reinterpret_cast<Isolate*>(i_isolate);
}

bool Isolate::IsCurrent() const {
  return reinterpret_cast<const i::Isolate*>(this)->IsCurrent();
}

// static
Isolate* Isolate::Allocate() {
  return reinterpret_cast<Isolate*>(i::Isolate::New());
}

Isolate::CreateParams::CreateParams() = default;

Isolate::CreateParams::~CreateParams() = default;

// static
// This is separate so that tests can provide a different |isolate|.
void Isolate::Initialize(Isolate* v8_isolate,
                         const v8::Isolate::CreateParams& params) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  TRACE_EVENT_CALL_STATS_SCOPED(i_isolate, "v8", "V8.IsolateInitialize");
  if (auto allocator = params.array_buffer_allocator_shared) {
    CHECK(params.array_buffer_allocator == nullptr ||
          params.array_buffer_allocator == allocator.get());
    i_isolate->set_array_buffer_allocator(allocator.get());
    i_isolate->set_array_buffer_allocator_shared(std::move(allocator));
  } else {
    CHECK_NOT_NULL(params.array_buffer_allocator);
    i_isolate->set_array_buffer_allocator(params.array_buffer_allocator);
  }
  if (params.snapshot_blob != nullptr) {
    i_isolate->set_snapshot_blob(params.snapshot_blob);
  } else {
    i_isolate->set_snapshot_blob(i::Snapshot::DefaultSnapshotBlob());
  }

  if (params.fatal_error_callback) {
    v8_isolate->SetFatalErrorHandler(params.fatal_error_callback);
  }

#if __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif
  if (params.oom_error_callback) {
    v8_isolate->SetOOMErrorHandler(params.oom_error_callback);
  }
#if __clang__
#pragma clang diagnostic pop
#endif

  if (params.counter_lookup_callback) {
    v8_isolate->SetCounterFunction(params.counter_lookup_callback);
  }

  if (params.create_histogram_callback) {
    v8_isolate->SetCreateHistogramFunction(params.create_histogram_callback);
  }

  if (params.add_histogram_sample_callback) {
    v8_isolate->SetAddHistogramSampleFunction(
        params.add_histogram_sample_callback);
  }

  i_isolate->set_api_external_references(params.external_references);
  i_isolate->set_allow_atomics_wait(params.allow_atomics_wait);

  i_isolate->heap()->ConfigureHeap(params.constraints, params.cpp_heap);
  if (params.constraints.stack_limit() != nullptr) {
    uintptr_t limit =
        reinterpret_cast<uintptr_t>(params.constraints.stack_limit());
    i_isolate->stack_guard()->SetStackLimit(limit);
  }

  // TODO(v8:2487): Once we got rid of Isolate::Current(), we can remove this.
  Isolate::Scope isolate_scope(v8_isolate);
  if (i_isolate->snapshot_blob() == nullptr) {
    FATAL(
        "V8 snapshot blob was not set during initialization. This can mean "
        "that the snapshot blob file is corrupted or missing.");
  }
  if (!i::Snapshot::Initialize(i_isolate)) {
    // If snapshot data was provided and we failed to deserialize it must
    // have been corrupted.
    FATAL(
        "Failed to deserialize the V8 snapshot blob. This can mean that the "
        "snapshot blob file is corrupted or missing.");
  }

  {
    // Set up code event handlers. Needs to be after i::Snapshot::Initialize
    // because that is where we add the isolate to WasmEngine.
    auto code_event_handler = params.code_event_handler;
    if (code_event_handler) {
      v8_isolate->SetJitCodeEventHandler(kJitCodeEventEnumExisting,
                                         code_event_handler);
    }
  }

  i_isolate->set_embedder_wrapper_type_index(
      params.embedder_wrapper_type_index);
  i_isolate->set_embedder_wrapper_object_index(
      params.embedder_wrapper_object_index);

  if (!i::V8::GetCurrentPlatform()
           ->GetForegroundTaskRunner(v8_isolate)
           ->NonNestableTasksEnabled()) {
    FATAL(
        "The current platform's foreground task runner does not have "
        "non-nestable tasks enabled. The embedder must provide one.");
  }
}

Isolate* Isolate::New(const Isolate::CreateParams& params) {
  Isolate* v8_isolate = Allocate();
  Initialize(v8_isolate, params);
  return v8_isolate;
}

void Isolate::Dispose() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  if (!Utils::ApiCheck(!i_isolate->IsInUse(), "v8::Isolate::Dispose()",
                       "Disposing the isolate that is entered by a thread")) {
    return;
  }
  i::Isolate::Delete(i_isolate);
}

void Isolate::DumpAndResetStats() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
#ifdef DEBUG
  // This method might be called on a thread that's not bound to any Isolate
  // and thus pointer compression schemes might have cage base value unset.
  // Read-only roots accessors contain type DCHECKs which require access to
  // V8 heap in order to check the object type. So, allow heap access here
  // to let the checks work.
  i::PtrComprCageAccessScope ptr_compr_cage_access_scope(i_isolate);
#endif  // DEBUG
  i_isolate->DumpAndResetStats();
}

void Isolate::DiscardThreadSpecificMetadata() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->DiscardPerThreadDataForThisThread();
}

void Isolate::Enter() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->Enter();
}

void Isolate::Exit() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->Exit();
}

void Isolate::SetAbortOnUncaughtExceptionCallback(
    AbortOnUncaughtExceptionCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetAbortOnUncaughtExceptionCallback(callback);
}

void Isolate::SetHostImportModuleDynamicallyCallback(
    HostImportModuleDynamicallyCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetHostImportModuleDynamicallyCallback(callback);
}

void Isolate::SetHostImportModuleWithPhaseDynamicallyCallback(
    HostImportModuleWithPhaseDynamicallyCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetHostImportModuleWithPhaseDynamicallyCallback(callback);
}

void Isolate::SetHostInitializeImportMetaObjectCallback(
    HostInitializeImportMetaObjectCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetHostInitializeImportMetaObjectCallback(callback);
}

void Isolate::SetHostCreateShadowRealmContextCallback(
    HostCreateShadowRealmContextCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetHostCreateShadowRealmContextCallback(callback);
}

void Isolate::SetPrepareStackTraceCallback(PrepareStackTraceCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetPrepareStackTraceCallback(callback);
}

int Isolate::GetStackTraceLimit() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  int stack_trace_limit = 0;
  if (!i_isolate->GetStackTraceLimit(i_isolate, &stack_trace_limit)) {
    return i::v8_flags.stack_trace_limit;
  }
  return stack_trace_limit;
}

Isolate::DisallowJavascriptExecutionScope::DisallowJavascriptExecutionScope(
    Isolate* v8_isolate,
    Isolate::DisallowJavascriptExecutionScope::OnFailure on_failure)
    : v8_isolate_(v8_isolate), on_failure_(on_failure) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  switch (on_failure_) {
    case CRASH_ON_FAILURE:
      i::DisallowJavascriptExecution::Open(i_isolate, &was_execution_allowed_);
      break;
    case THROW_ON_FAILURE:
      i::ThrowOnJavascriptExecution::Open(i_isolate, &was_execution_allowed_);
      break;
    case DUMP_ON_FAILURE:
      i::DumpOnJavascriptExecution::Open(i_isolate, &was_execution_allowed_);
      break;
  }
}

Isolate::DisallowJavascriptExecutionScope::~DisallowJavascriptExecutionScope() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate_);
  switch (on_failure_) {
    case CRASH_ON_FAILURE:
      i::DisallowJavascriptExecution::Close(i_isolate, was_execution_allowed_);
      break;
    case THROW_ON_FAILURE:
      i::ThrowOnJavascriptExecution::Close(i_isolate, was_execution_allowed_);
      break;
    case DUMP_ON_FAILURE:
      i::DumpOnJavascriptExecution::Close(i_isolate, was_execution_allowed_);
      break;
  }
}

Isolate::AllowJavascriptExecutionScope::AllowJavascriptExecutionScope(
    Isolate* v8_isolate)
    : v8_isolate_(v8_isolate) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  i::AllowJavascriptExecution::Open(i_isolate, &was_execution_allowed_assert_);
  i::NoThrowOnJavascriptExecution::Open(i_isolate,
                                        &was_execution_allowed_throws_);
  i::NoDumpOnJavascriptExecution::Open(i_isolate, &was_execution_allowed_dump_);
}

Isolate::AllowJavascriptExecutionScope::~AllowJavascriptExecutionScope() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate_);
  i::AllowJavascriptExecution::Close(i_isolate, was_execution_allowed_assert_);
  i::NoThrowOnJavascriptExecution::Close(i_isolate,
                                         was_execution_allowed_throws_);
  i::NoDumpOnJavascriptExecution::Close(i_isolate, was_execution_allowed_dump_);
}

Isolate::SuppressMicrotaskExecutionScope::SuppressMicrotaskExecutionScope(
    Isolate* v8_isolate, MicrotaskQueue* microtask_queue)
    : i_isolate_(reinterpret_cast<i::Isolate*>(v8_isolate)),
      microtask_queue_(microtask_queue
                           ? static_cast<i::MicrotaskQueue*>(microtask_queue)
                           : i_isolate_->default_microtask_queue()) {
  i_isolate_->thread_local_top()->IncrementCallDepth<true>(this);
  microtask_queue_->IncrementMicrotasksSuppressions();
}

Isolate::SuppressMicrotaskExecutionScope::~SuppressMicrotaskExecutionScope() {
  microtask_queue_->DecrementMicrotasksSuppressions();
  i_isolate_->thread_local_top()->DecrementCallDepth(this);
}

i::ValueHelper::InternalRepresentationType Isolate::GetDataFromSnapshotOnce(
    size_t index) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  auto list = i::Cast<i::FixedArray>(i_isolate->heap()->serialized_objects());
  return GetSerializedDataFromFixedArray(i_isolate, list, index);
}

Local<Value> Isolate::GetContinuationPreservedEmbedderData() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  return ToApiHandle<Object>(i::direct_handle(
      i_isolate->isolate_data()->continuation_preserved_embedder_data(),
      i_isolate));
#else   // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  return v8::Undefined(reinterpret_cast<v8::Isolate*>(i_isolate));
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
}

void Isolate::SetContinuationPreservedEmbedderData(Local<Value> data) {
#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  if (data.IsEmpty())
    data = v8::Undefined(reinterpret_cast<v8::Isolate*>(this));
  i_isolate->isolate_data()->set_continuation_preserved_embedder_data(
      *Utils::OpenDirectHandle(*data));
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
}

void Isolate::GetHeapStatistics(HeapStatistics* heap_statistics) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i::Heap* heap = i_isolate->heap();

  heap->FreeMainThreadLinearAllocationAreas();

  // The order of acquiring memory statistics is important here. We query in
  // this order because of concurrent allocation: 1) used memory 2) comitted
  // physical memory 3) committed memory. Therefore the condition used <=
  // committed physical <= committed should hold.
  heap_statistics->used_global_handles_size_ = heap->UsedGlobalHandlesSize();
  heap_statistics->total_global_handles_size_ = heap->TotalGlobalHandlesSize();
  DCHECK_LE(heap_statistics->used_global_handles_size_,
            heap_statistics->total_global_handles_size_);

  heap_statistics->used_heap_size_ = heap->SizeOfObjects();
  heap_statistics->total_physical_size_ = heap->CommittedPhysicalMemory();
  heap_statistics->total_heap_size_ = heap->CommittedMemory();

  heap_statistics->total_available_size_ = heap->Available();

  if (!i::ReadOnlyHeap::IsReadOnlySpaceShared()) {
    i::ReadOnlySpace* ro_space = heap->read_only_space();
    heap_statistics->used_heap_size_ += ro_space->Size();
    heap_statistics->total_physical_size_ +=
        ro_space->CommittedPhysicalMemory();
    heap_statistics->total_heap_size_ += ro_space->CommittedMemory();
  }

  // TODO(dinfuehr): Right now used <= committed physical does not hold. Fix
  // this and add DCHECK.
  DCHECK_LE(heap_statistics->used_heap_size_,
            heap_statistics->total_heap_size_);

  heap_statistics->total_heap_size_executable_ =
      heap->CommittedMemoryExecutable();
  heap_statistics->heap_size_limit_ = heap->MaxReserved();
  // TODO(7424): There is no public API for the {WasmEngine} yet. Once such an
  // API becomes available we should report the malloced memory separately. For
  // now we just add the values, thereby over-approximating the peak slightly.
  heap_statistics->malloced_memory_ =
      i_isolate->allocator()->GetCurrentMemoryUsage() +
      i_isolate->string_table()->GetCurrentMemoryUsage();
  // On 32-bit systems backing_store_bytes() might overflow size_t temporarily
  // due to concurrent array buffer sweeping.
  heap_statistics->external_memory_ =
      i_isolate->heap()->backing_store_bytes() < SIZE_MAX
          ? static_cast<size_t>(i_isolate->heap()->backing_store_bytes())
          : SIZE_MAX;
  heap_statistics->peak_malloced_memory_ =
      i_isolate->allocator()->GetMaxMemoryUsage();
  heap_statistics->number_of_native_contexts_ = heap->NumberOfNativeContexts();
  heap_statistics->number_of_detached_contexts_ =
      heap->NumberOfDetachedContexts();
  heap_statistics->does_zap_garbage_ = i::heap::ShouldZapGarbage();

#if V8_ENABLE_WEBASSEMBLY
  heap_statistics->malloced_memory_ +=
      i::wasm::GetWasmEngine()->allocator()->GetCurrentMemoryUsage();
  heap_statistics->peak_malloced_memory_ +=
      i::wasm::GetWasmEngine()->allocator()->GetMaxMemoryUsage();
#endif  // V8_ENABLE_WEBASSEMBLY
}

size_t Isolate::NumberOfHeapSpaces() {
  return i::LAST_SPACE - i::FIRST_SPACE + 1;
}

bool Isolate::GetHeapSpaceStatistics(HeapSpaceStatistics* space_statistics,
                                     size_t index) {
  if (!space_statistics) return false;
  if (!i::Heap::IsValidAllocationSpace(static_cast<i::AllocationSpace>(index)))
    return false;

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i::Heap* heap = i_isolate->heap();

  heap->FreeMainThreadLinearAllocationAreas();

  i::AllocationSpace allocation_space = static_cast<i::AllocationSpace>(index);
  space_statistics->space_name_ = i::ToString(allocation_space);

  if (allocation_space == i::RO_SPACE) {
    if (i::ReadOnlyHeap::IsReadOnlySpaceShared()) {
      // RO_SPACE memory is accounted for elsewhere when ReadOnlyHeap is shared.
      space_statistics->space_size_ = 0;
      space_statistics->space_used_size_ = 0;
      space_statistics->space_available_size_ = 0;
      space_statistics->physical_space_size_ = 0;
    } else {
      i::ReadOnlySpace* space = heap->read_only_space();
      space_statistics->space_size_ = space->CommittedMemory();
      space_statistics->space_used_size_ = space->Size();
      space_statistics->space_available_size_ = 0;
      space_statistics->physical_space_size_ = space->CommittedPhysicalMemory();
    }
  } else {
    i::Space* space = heap->space(static_cast<int>(index));
    space_statistics->space_size_ = space ? space->CommittedMemory() : 0;
    space_statistics->space_used_size_ = space ? space->SizeOfObjects() : 0;
    space_statistics->space_available_size_ = space ? space->Available() : 0;
    space_statistics->physical_space_size_ =
        space ? space->CommittedPhysicalMemory() : 0;
  }
  return true;
}

size_t Isolate::NumberOfTrackedHeapObjectTypes() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i::Heap* heap = i_isolate->heap();
  return heap->NumberOfTrackedHeapObjectTypes();
}

bool Isolate::GetHeapObjectStatisticsAtLastGC(
    HeapObjectStatistics* object_statistics, size_t type_index) {
  if (!object_statistics) return false;
  if (V8_LIKELY(!i::TracingFlags::is_gc_stats_enabled())) return false;

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i::Heap* heap = i_isolate->heap();
  if (type_index >= heap->NumberOfTrackedHeapObjectTypes()) return false;

  const char* object_type;
  const char* object_sub_type;
  size_t object_count = heap->ObjectCountAtLastGC(type_index);
  size_t object_size = heap->ObjectSizeAtLastGC(type_index);
  if (!heap->GetObjectTypeName(type_index, &object_type, &object_sub_type)) {
    // There should be no objects counted when the type is unknown.
    DCHECK_EQ(object_count, 0U);
    DCHECK_EQ(object_size, 0U);
    return false;
  }

  object_statistics->object_type_ = object_type;
  object_statistics->object_sub_type_ = object_sub_type;
  object_statistics->object_count_ = object_count;
  object_statistics->object_size_ = object_size;
  return true;
}

bool Isolate::GetHeapCodeAndMetadataStatistics(
    HeapCodeStatistics* code_statistics) {
  if (!code_statistics) return false;

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->heap()->CollectCodeStatistics();

  code_statistics->code_and_metadata_size_ =
      i_isolate->code_and_metadata_size();
  code_statistics->bytecode_and_metadata_size_ =
      i_isolate->bytecode_and_metadata_size();
  code_statistics->external_script_source_size_ =
      i_isolate->external_script_source_size();
  code_statistics->cpu_profiler_metadata_size_ =
      i::CpuProfiler::GetAllProfilersMemorySize(i_isolate);

  return true;
}

bool Isolate::MeasureMemory(std::unique_ptr<MeasureMemoryDelegate> delegate,
                            MeasureMemoryExecution execution) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  return i_isolate->heap()->MeasureMemory(std::move(delegate), execution);
}

std::unique_ptr<MeasureMemoryDelegate> MeasureMemoryDelegate::Default(
    Isolate* v8_isolate, Local<Context> context,
    Local<Promise::Resolver> promise_resolver, MeasureMemoryMode mode) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  return i_isolate->heap()->CreateDefaultMeasureMemoryDelegate(
      context, promise_resolver, mode);
}

void Isolate::GetStackSample(const RegisterState& state, void** frames,
                             size_t frames_limit, SampleInfo* sample_info) {
  RegisterState regs = state;
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  if (i::TickSample::GetStackSample(i_isolate, &regs,
                                    i::TickSample::kSkipCEntryFrame, frames,
                                    frames_limit, sample_info)) {
    return;
  }
  sample_info->frames_count = 0;
  sample_info->vm_state = OTHER;
  sample_info->external_callback_entry = nullptr;
}

int64_t Isolate::AdjustAmountOfExternalAllocatedMemory(
    int64_t change_in_bytes) {
  // Try to check for unreasonably large or small values from the embedder.
  static constexpr int64_t kMaxReasonableBytes = int64_t(1) << 60;
  static constexpr int64_t kMinReasonableBytes = -kMaxReasonableBytes;
  static_assert(kMaxReasonableBytes >= i::JSArrayBuffer::kMaxByteLength);
  CHECK(kMinReasonableBytes <= change_in_bytes &&
        change_in_bytes < kMaxReasonableBytes);

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  const uint64_t amount =
      i_isolate->heap()->UpdateExternalMemory(change_in_bytes);

  if (change_in_bytes <= 0) {
    return amount;
  }

  if (amount > i_isolate->heap()->external_memory_limit_for_interrupt()) {
    HandleExternalMemoryInterrupt();
  }
  return amount;
}

void Isolate::SetEventLogger(LogEventCallback that) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->set_event_logger(that);
}

void Isolate::AddBeforeCallEnteredCallback(BeforeCallEnteredCallback callback) {
  if (callback == nullptr) return;
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->AddBeforeCallEnteredCallback(callback);
}

void Isolate::RemoveBeforeCallEnteredCallback(
    BeforeCallEnteredCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->RemoveBeforeCallEnteredCallback(callback);
}

void Isolate::AddCallCompletedCallback(CallCompletedCallback callback) {
  if (callback == nullptr) return;
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->AddCallCompletedCallback(callback);
}

void Isolate::RemoveCallCompletedCallback(CallCompletedCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->RemoveCallCompletedCallback(callback);
}

void Isolate::AtomicsWaitWakeHandle::Wake() {
  reinterpret_cast<i::AtomicsWaitWakeHandle*>(this)->Wake();
}

void Isolate::SetAtomicsWaitCallback(AtomicsWaitCallback callback, void* data) {
  i::Isolate* i_isolate = reinterpret_cast<i::
### 提示词
```
这是目录为v8/src/api/api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/api/api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第13部分，共15部分，请归纳一下它的功能
```

### 源代码
```cpp
ate*>(this);
  i_isolate->heap()->AttachCppHeap(cpp_heap);
}

void Isolate::DetachCppHeap() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->heap()->DetachCppHeap();
}

CppHeap* Isolate::GetCppHeap() const {
  const i::Isolate* i_isolate = reinterpret_cast<const i::Isolate*>(this);
  return i_isolate->heap()->cpp_heap();
}

void Isolate::SetGetExternallyAllocatedMemoryInBytesCallback(
    GetExternallyAllocatedMemoryInBytesCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->heap()->SetGetExternallyAllocatedMemoryInBytesCallback(callback);
}

void Isolate::TerminateExecution() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->stack_guard()->RequestTerminateExecution();
}

bool Isolate::IsExecutionTerminating() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
#ifdef DEBUG
  // This method might be called on a thread that's not bound to any Isolate
  // and thus pointer compression schemes might have cage base value unset.
  // Read-only roots accessors contain type DCHECKs which require access to
  // V8 heap in order to check the object type. So, allow heap access here
  // to let the checks work.
  i::PtrComprCageAccessScope ptr_compr_cage_access_scope(i_isolate);
#endif  // DEBUG
  return i_isolate->is_execution_terminating();
}

void Isolate::CancelTerminateExecution() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->stack_guard()->ClearTerminateExecution();
  i_isolate->CancelTerminateExecution();
}

void Isolate::RequestInterrupt(InterruptCallback callback, void* data) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->RequestInterrupt(callback, data);
}

bool Isolate::HasPendingBackgroundTasks() {
#if V8_ENABLE_WEBASSEMBLY
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  return i::wasm::GetWasmEngine()->HasRunningCompileJob(i_isolate);
#else
  return false;
#endif  // V8_ENABLE_WEBASSEMBLY
}

void Isolate::RequestGarbageCollectionForTesting(GarbageCollectionType type) {
  Utils::ApiCheck(i::v8_flags.expose_gc,
                  "v8::Isolate::RequestGarbageCollectionForTesting",
                  "Must use --expose-gc");
  if (type == kMinorGarbageCollection) {
    reinterpret_cast<i::Isolate*>(this)->heap()->CollectGarbage(
        i::NEW_SPACE, i::GarbageCollectionReason::kTesting,
        kGCCallbackFlagForced);
  } else {
    DCHECK_EQ(kFullGarbageCollection, type);
    reinterpret_cast<i::Isolate*>(this)->heap()->PreciseCollectAllGarbage(
        i::GCFlag::kNoFlags, i::GarbageCollectionReason::kTesting,
        kGCCallbackFlagForced);
  }
}

void Isolate::RequestGarbageCollectionForTesting(GarbageCollectionType type,
                                                 StackState stack_state) {
  std::optional<i::EmbedderStackStateScope> stack_scope;
  if (type == kFullGarbageCollection) {
    stack_scope.emplace(reinterpret_cast<i::Isolate*>(this)->heap(),
                        i::EmbedderStackStateOrigin::kExplicitInvocation,
                        stack_state);
  }
  RequestGarbageCollectionForTesting(type);
}

Isolate* Isolate::GetCurrent() {
  i::Isolate* i_isolate = i::Isolate::Current();
  return reinterpret_cast<Isolate*>(i_isolate);
}

Isolate* Isolate::TryGetCurrent() {
  i::Isolate* i_isolate = i::Isolate::TryGetCurrent();
  return reinterpret_cast<Isolate*>(i_isolate);
}

bool Isolate::IsCurrent() const {
  return reinterpret_cast<const i::Isolate*>(this)->IsCurrent();
}

// static
Isolate* Isolate::Allocate() {
  return reinterpret_cast<Isolate*>(i::Isolate::New());
}

Isolate::CreateParams::CreateParams() = default;

Isolate::CreateParams::~CreateParams() = default;

// static
// This is separate so that tests can provide a different |isolate|.
void Isolate::Initialize(Isolate* v8_isolate,
                         const v8::Isolate::CreateParams& params) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  TRACE_EVENT_CALL_STATS_SCOPED(i_isolate, "v8", "V8.IsolateInitialize");
  if (auto allocator = params.array_buffer_allocator_shared) {
    CHECK(params.array_buffer_allocator == nullptr ||
          params.array_buffer_allocator == allocator.get());
    i_isolate->set_array_buffer_allocator(allocator.get());
    i_isolate->set_array_buffer_allocator_shared(std::move(allocator));
  } else {
    CHECK_NOT_NULL(params.array_buffer_allocator);
    i_isolate->set_array_buffer_allocator(params.array_buffer_allocator);
  }
  if (params.snapshot_blob != nullptr) {
    i_isolate->set_snapshot_blob(params.snapshot_blob);
  } else {
    i_isolate->set_snapshot_blob(i::Snapshot::DefaultSnapshotBlob());
  }

  if (params.fatal_error_callback) {
    v8_isolate->SetFatalErrorHandler(params.fatal_error_callback);
  }

#if __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif
  if (params.oom_error_callback) {
    v8_isolate->SetOOMErrorHandler(params.oom_error_callback);
  }
#if __clang__
#pragma clang diagnostic pop
#endif

  if (params.counter_lookup_callback) {
    v8_isolate->SetCounterFunction(params.counter_lookup_callback);
  }

  if (params.create_histogram_callback) {
    v8_isolate->SetCreateHistogramFunction(params.create_histogram_callback);
  }

  if (params.add_histogram_sample_callback) {
    v8_isolate->SetAddHistogramSampleFunction(
        params.add_histogram_sample_callback);
  }

  i_isolate->set_api_external_references(params.external_references);
  i_isolate->set_allow_atomics_wait(params.allow_atomics_wait);

  i_isolate->heap()->ConfigureHeap(params.constraints, params.cpp_heap);
  if (params.constraints.stack_limit() != nullptr) {
    uintptr_t limit =
        reinterpret_cast<uintptr_t>(params.constraints.stack_limit());
    i_isolate->stack_guard()->SetStackLimit(limit);
  }

  // TODO(v8:2487): Once we got rid of Isolate::Current(), we can remove this.
  Isolate::Scope isolate_scope(v8_isolate);
  if (i_isolate->snapshot_blob() == nullptr) {
    FATAL(
        "V8 snapshot blob was not set during initialization. This can mean "
        "that the snapshot blob file is corrupted or missing.");
  }
  if (!i::Snapshot::Initialize(i_isolate)) {
    // If snapshot data was provided and we failed to deserialize it must
    // have been corrupted.
    FATAL(
        "Failed to deserialize the V8 snapshot blob. This can mean that the "
        "snapshot blob file is corrupted or missing.");
  }

  {
    // Set up code event handlers. Needs to be after i::Snapshot::Initialize
    // because that is where we add the isolate to WasmEngine.
    auto code_event_handler = params.code_event_handler;
    if (code_event_handler) {
      v8_isolate->SetJitCodeEventHandler(kJitCodeEventEnumExisting,
                                         code_event_handler);
    }
  }

  i_isolate->set_embedder_wrapper_type_index(
      params.embedder_wrapper_type_index);
  i_isolate->set_embedder_wrapper_object_index(
      params.embedder_wrapper_object_index);

  if (!i::V8::GetCurrentPlatform()
           ->GetForegroundTaskRunner(v8_isolate)
           ->NonNestableTasksEnabled()) {
    FATAL(
        "The current platform's foreground task runner does not have "
        "non-nestable tasks enabled. The embedder must provide one.");
  }
}

Isolate* Isolate::New(const Isolate::CreateParams& params) {
  Isolate* v8_isolate = Allocate();
  Initialize(v8_isolate, params);
  return v8_isolate;
}

void Isolate::Dispose() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  if (!Utils::ApiCheck(!i_isolate->IsInUse(), "v8::Isolate::Dispose()",
                       "Disposing the isolate that is entered by a thread")) {
    return;
  }
  i::Isolate::Delete(i_isolate);
}

void Isolate::DumpAndResetStats() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
#ifdef DEBUG
  // This method might be called on a thread that's not bound to any Isolate
  // and thus pointer compression schemes might have cage base value unset.
  // Read-only roots accessors contain type DCHECKs which require access to
  // V8 heap in order to check the object type. So, allow heap access here
  // to let the checks work.
  i::PtrComprCageAccessScope ptr_compr_cage_access_scope(i_isolate);
#endif  // DEBUG
  i_isolate->DumpAndResetStats();
}

void Isolate::DiscardThreadSpecificMetadata() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->DiscardPerThreadDataForThisThread();
}

void Isolate::Enter() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->Enter();
}

void Isolate::Exit() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->Exit();
}

void Isolate::SetAbortOnUncaughtExceptionCallback(
    AbortOnUncaughtExceptionCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetAbortOnUncaughtExceptionCallback(callback);
}

void Isolate::SetHostImportModuleDynamicallyCallback(
    HostImportModuleDynamicallyCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetHostImportModuleDynamicallyCallback(callback);
}

void Isolate::SetHostImportModuleWithPhaseDynamicallyCallback(
    HostImportModuleWithPhaseDynamicallyCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetHostImportModuleWithPhaseDynamicallyCallback(callback);
}

void Isolate::SetHostInitializeImportMetaObjectCallback(
    HostInitializeImportMetaObjectCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetHostInitializeImportMetaObjectCallback(callback);
}

void Isolate::SetHostCreateShadowRealmContextCallback(
    HostCreateShadowRealmContextCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetHostCreateShadowRealmContextCallback(callback);
}

void Isolate::SetPrepareStackTraceCallback(PrepareStackTraceCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetPrepareStackTraceCallback(callback);
}

int Isolate::GetStackTraceLimit() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  int stack_trace_limit = 0;
  if (!i_isolate->GetStackTraceLimit(i_isolate, &stack_trace_limit)) {
    return i::v8_flags.stack_trace_limit;
  }
  return stack_trace_limit;
}

Isolate::DisallowJavascriptExecutionScope::DisallowJavascriptExecutionScope(
    Isolate* v8_isolate,
    Isolate::DisallowJavascriptExecutionScope::OnFailure on_failure)
    : v8_isolate_(v8_isolate), on_failure_(on_failure) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  switch (on_failure_) {
    case CRASH_ON_FAILURE:
      i::DisallowJavascriptExecution::Open(i_isolate, &was_execution_allowed_);
      break;
    case THROW_ON_FAILURE:
      i::ThrowOnJavascriptExecution::Open(i_isolate, &was_execution_allowed_);
      break;
    case DUMP_ON_FAILURE:
      i::DumpOnJavascriptExecution::Open(i_isolate, &was_execution_allowed_);
      break;
  }
}

Isolate::DisallowJavascriptExecutionScope::~DisallowJavascriptExecutionScope() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate_);
  switch (on_failure_) {
    case CRASH_ON_FAILURE:
      i::DisallowJavascriptExecution::Close(i_isolate, was_execution_allowed_);
      break;
    case THROW_ON_FAILURE:
      i::ThrowOnJavascriptExecution::Close(i_isolate, was_execution_allowed_);
      break;
    case DUMP_ON_FAILURE:
      i::DumpOnJavascriptExecution::Close(i_isolate, was_execution_allowed_);
      break;
  }
}

Isolate::AllowJavascriptExecutionScope::AllowJavascriptExecutionScope(
    Isolate* v8_isolate)
    : v8_isolate_(v8_isolate) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  i::AllowJavascriptExecution::Open(i_isolate, &was_execution_allowed_assert_);
  i::NoThrowOnJavascriptExecution::Open(i_isolate,
                                        &was_execution_allowed_throws_);
  i::NoDumpOnJavascriptExecution::Open(i_isolate, &was_execution_allowed_dump_);
}

Isolate::AllowJavascriptExecutionScope::~AllowJavascriptExecutionScope() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate_);
  i::AllowJavascriptExecution::Close(i_isolate, was_execution_allowed_assert_);
  i::NoThrowOnJavascriptExecution::Close(i_isolate,
                                         was_execution_allowed_throws_);
  i::NoDumpOnJavascriptExecution::Close(i_isolate, was_execution_allowed_dump_);
}

Isolate::SuppressMicrotaskExecutionScope::SuppressMicrotaskExecutionScope(
    Isolate* v8_isolate, MicrotaskQueue* microtask_queue)
    : i_isolate_(reinterpret_cast<i::Isolate*>(v8_isolate)),
      microtask_queue_(microtask_queue
                           ? static_cast<i::MicrotaskQueue*>(microtask_queue)
                           : i_isolate_->default_microtask_queue()) {
  i_isolate_->thread_local_top()->IncrementCallDepth<true>(this);
  microtask_queue_->IncrementMicrotasksSuppressions();
}

Isolate::SuppressMicrotaskExecutionScope::~SuppressMicrotaskExecutionScope() {
  microtask_queue_->DecrementMicrotasksSuppressions();
  i_isolate_->thread_local_top()->DecrementCallDepth(this);
}

i::ValueHelper::InternalRepresentationType Isolate::GetDataFromSnapshotOnce(
    size_t index) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  auto list = i::Cast<i::FixedArray>(i_isolate->heap()->serialized_objects());
  return GetSerializedDataFromFixedArray(i_isolate, list, index);
}

Local<Value> Isolate::GetContinuationPreservedEmbedderData() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  return ToApiHandle<Object>(i::direct_handle(
      i_isolate->isolate_data()->continuation_preserved_embedder_data(),
      i_isolate));
#else   // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  return v8::Undefined(reinterpret_cast<v8::Isolate*>(i_isolate));
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
}

void Isolate::SetContinuationPreservedEmbedderData(Local<Value> data) {
#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  if (data.IsEmpty())
    data = v8::Undefined(reinterpret_cast<v8::Isolate*>(this));
  i_isolate->isolate_data()->set_continuation_preserved_embedder_data(
      *Utils::OpenDirectHandle(*data));
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
}

void Isolate::GetHeapStatistics(HeapStatistics* heap_statistics) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i::Heap* heap = i_isolate->heap();

  heap->FreeMainThreadLinearAllocationAreas();

  // The order of acquiring memory statistics is important here. We query in
  // this order because of concurrent allocation: 1) used memory 2) comitted
  // physical memory 3) committed memory. Therefore the condition used <=
  // committed physical <= committed should hold.
  heap_statistics->used_global_handles_size_ = heap->UsedGlobalHandlesSize();
  heap_statistics->total_global_handles_size_ = heap->TotalGlobalHandlesSize();
  DCHECK_LE(heap_statistics->used_global_handles_size_,
            heap_statistics->total_global_handles_size_);

  heap_statistics->used_heap_size_ = heap->SizeOfObjects();
  heap_statistics->total_physical_size_ = heap->CommittedPhysicalMemory();
  heap_statistics->total_heap_size_ = heap->CommittedMemory();

  heap_statistics->total_available_size_ = heap->Available();

  if (!i::ReadOnlyHeap::IsReadOnlySpaceShared()) {
    i::ReadOnlySpace* ro_space = heap->read_only_space();
    heap_statistics->used_heap_size_ += ro_space->Size();
    heap_statistics->total_physical_size_ +=
        ro_space->CommittedPhysicalMemory();
    heap_statistics->total_heap_size_ += ro_space->CommittedMemory();
  }

  // TODO(dinfuehr): Right now used <= committed physical does not hold. Fix
  // this and add DCHECK.
  DCHECK_LE(heap_statistics->used_heap_size_,
            heap_statistics->total_heap_size_);

  heap_statistics->total_heap_size_executable_ =
      heap->CommittedMemoryExecutable();
  heap_statistics->heap_size_limit_ = heap->MaxReserved();
  // TODO(7424): There is no public API for the {WasmEngine} yet. Once such an
  // API becomes available we should report the malloced memory separately. For
  // now we just add the values, thereby over-approximating the peak slightly.
  heap_statistics->malloced_memory_ =
      i_isolate->allocator()->GetCurrentMemoryUsage() +
      i_isolate->string_table()->GetCurrentMemoryUsage();
  // On 32-bit systems backing_store_bytes() might overflow size_t temporarily
  // due to concurrent array buffer sweeping.
  heap_statistics->external_memory_ =
      i_isolate->heap()->backing_store_bytes() < SIZE_MAX
          ? static_cast<size_t>(i_isolate->heap()->backing_store_bytes())
          : SIZE_MAX;
  heap_statistics->peak_malloced_memory_ =
      i_isolate->allocator()->GetMaxMemoryUsage();
  heap_statistics->number_of_native_contexts_ = heap->NumberOfNativeContexts();
  heap_statistics->number_of_detached_contexts_ =
      heap->NumberOfDetachedContexts();
  heap_statistics->does_zap_garbage_ = i::heap::ShouldZapGarbage();

#if V8_ENABLE_WEBASSEMBLY
  heap_statistics->malloced_memory_ +=
      i::wasm::GetWasmEngine()->allocator()->GetCurrentMemoryUsage();
  heap_statistics->peak_malloced_memory_ +=
      i::wasm::GetWasmEngine()->allocator()->GetMaxMemoryUsage();
#endif  // V8_ENABLE_WEBASSEMBLY
}

size_t Isolate::NumberOfHeapSpaces() {
  return i::LAST_SPACE - i::FIRST_SPACE + 1;
}

bool Isolate::GetHeapSpaceStatistics(HeapSpaceStatistics* space_statistics,
                                     size_t index) {
  if (!space_statistics) return false;
  if (!i::Heap::IsValidAllocationSpace(static_cast<i::AllocationSpace>(index)))
    return false;

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i::Heap* heap = i_isolate->heap();

  heap->FreeMainThreadLinearAllocationAreas();

  i::AllocationSpace allocation_space = static_cast<i::AllocationSpace>(index);
  space_statistics->space_name_ = i::ToString(allocation_space);

  if (allocation_space == i::RO_SPACE) {
    if (i::ReadOnlyHeap::IsReadOnlySpaceShared()) {
      // RO_SPACE memory is accounted for elsewhere when ReadOnlyHeap is shared.
      space_statistics->space_size_ = 0;
      space_statistics->space_used_size_ = 0;
      space_statistics->space_available_size_ = 0;
      space_statistics->physical_space_size_ = 0;
    } else {
      i::ReadOnlySpace* space = heap->read_only_space();
      space_statistics->space_size_ = space->CommittedMemory();
      space_statistics->space_used_size_ = space->Size();
      space_statistics->space_available_size_ = 0;
      space_statistics->physical_space_size_ = space->CommittedPhysicalMemory();
    }
  } else {
    i::Space* space = heap->space(static_cast<int>(index));
    space_statistics->space_size_ = space ? space->CommittedMemory() : 0;
    space_statistics->space_used_size_ = space ? space->SizeOfObjects() : 0;
    space_statistics->space_available_size_ = space ? space->Available() : 0;
    space_statistics->physical_space_size_ =
        space ? space->CommittedPhysicalMemory() : 0;
  }
  return true;
}

size_t Isolate::NumberOfTrackedHeapObjectTypes() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i::Heap* heap = i_isolate->heap();
  return heap->NumberOfTrackedHeapObjectTypes();
}

bool Isolate::GetHeapObjectStatisticsAtLastGC(
    HeapObjectStatistics* object_statistics, size_t type_index) {
  if (!object_statistics) return false;
  if (V8_LIKELY(!i::TracingFlags::is_gc_stats_enabled())) return false;

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i::Heap* heap = i_isolate->heap();
  if (type_index >= heap->NumberOfTrackedHeapObjectTypes()) return false;

  const char* object_type;
  const char* object_sub_type;
  size_t object_count = heap->ObjectCountAtLastGC(type_index);
  size_t object_size = heap->ObjectSizeAtLastGC(type_index);
  if (!heap->GetObjectTypeName(type_index, &object_type, &object_sub_type)) {
    // There should be no objects counted when the type is unknown.
    DCHECK_EQ(object_count, 0U);
    DCHECK_EQ(object_size, 0U);
    return false;
  }

  object_statistics->object_type_ = object_type;
  object_statistics->object_sub_type_ = object_sub_type;
  object_statistics->object_count_ = object_count;
  object_statistics->object_size_ = object_size;
  return true;
}

bool Isolate::GetHeapCodeAndMetadataStatistics(
    HeapCodeStatistics* code_statistics) {
  if (!code_statistics) return false;

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->heap()->CollectCodeStatistics();

  code_statistics->code_and_metadata_size_ =
      i_isolate->code_and_metadata_size();
  code_statistics->bytecode_and_metadata_size_ =
      i_isolate->bytecode_and_metadata_size();
  code_statistics->external_script_source_size_ =
      i_isolate->external_script_source_size();
  code_statistics->cpu_profiler_metadata_size_ =
      i::CpuProfiler::GetAllProfilersMemorySize(i_isolate);

  return true;
}

bool Isolate::MeasureMemory(std::unique_ptr<MeasureMemoryDelegate> delegate,
                            MeasureMemoryExecution execution) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  return i_isolate->heap()->MeasureMemory(std::move(delegate), execution);
}

std::unique_ptr<MeasureMemoryDelegate> MeasureMemoryDelegate::Default(
    Isolate* v8_isolate, Local<Context> context,
    Local<Promise::Resolver> promise_resolver, MeasureMemoryMode mode) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  return i_isolate->heap()->CreateDefaultMeasureMemoryDelegate(
      context, promise_resolver, mode);
}

void Isolate::GetStackSample(const RegisterState& state, void** frames,
                             size_t frames_limit, SampleInfo* sample_info) {
  RegisterState regs = state;
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  if (i::TickSample::GetStackSample(i_isolate, &regs,
                                    i::TickSample::kSkipCEntryFrame, frames,
                                    frames_limit, sample_info)) {
    return;
  }
  sample_info->frames_count = 0;
  sample_info->vm_state = OTHER;
  sample_info->external_callback_entry = nullptr;
}

int64_t Isolate::AdjustAmountOfExternalAllocatedMemory(
    int64_t change_in_bytes) {
  // Try to check for unreasonably large or small values from the embedder.
  static constexpr int64_t kMaxReasonableBytes = int64_t(1) << 60;
  static constexpr int64_t kMinReasonableBytes = -kMaxReasonableBytes;
  static_assert(kMaxReasonableBytes >= i::JSArrayBuffer::kMaxByteLength);
  CHECK(kMinReasonableBytes <= change_in_bytes &&
        change_in_bytes < kMaxReasonableBytes);

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  const uint64_t amount =
      i_isolate->heap()->UpdateExternalMemory(change_in_bytes);

  if (change_in_bytes <= 0) {
    return amount;
  }

  if (amount > i_isolate->heap()->external_memory_limit_for_interrupt()) {
    HandleExternalMemoryInterrupt();
  }
  return amount;
}

void Isolate::SetEventLogger(LogEventCallback that) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->set_event_logger(that);
}

void Isolate::AddBeforeCallEnteredCallback(BeforeCallEnteredCallback callback) {
  if (callback == nullptr) return;
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->AddBeforeCallEnteredCallback(callback);
}

void Isolate::RemoveBeforeCallEnteredCallback(
    BeforeCallEnteredCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->RemoveBeforeCallEnteredCallback(callback);
}

void Isolate::AddCallCompletedCallback(CallCompletedCallback callback) {
  if (callback == nullptr) return;
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->AddCallCompletedCallback(callback);
}

void Isolate::RemoveCallCompletedCallback(CallCompletedCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->RemoveCallCompletedCallback(callback);
}

void Isolate::AtomicsWaitWakeHandle::Wake() {
  reinterpret_cast<i::AtomicsWaitWakeHandle*>(this)->Wake();
}

void Isolate::SetAtomicsWaitCallback(AtomicsWaitCallback callback, void* data) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetAtomicsWaitCallback(callback, data);
}

void Isolate::SetPromiseHook(PromiseHook hook) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetPromiseHook(hook);
}

void Isolate::SetPromiseRejectCallback(PromiseRejectCallback callback) {
  if (callback == nullptr) return;
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetPromiseRejectCallback(callback);
}

void Isolate::SetExceptionPropagationCallback(
    ExceptionPropagationCallback callback) {
  if (callback == nullptr) return;
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetExceptionPropagationCallback(callback);
}

void Isolate::PerformMicrotaskCheckpoint() {
  DCHECK_NE(MicrotasksPolicy::kScoped, GetMicrotasksPolicy());
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->default_microtask_queue()->PerformCheckpoint(this);
}

void Isolate::EnqueueMicrotask(Local<Function> v8_function) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  auto function = Utils::OpenHandle(*v8_function);
  i::Handle<i::NativeContext> handler_context;
  if (!i::JSReceiver::GetContextForMicrotask(function).ToHandle(
          &handler_context))
    handler_context = i_isolate->native_context();
  MicrotaskQueue* microtask_queue = handler_context->microtask_queue();
  if (microtask_queue) microtask_queue->EnqueueMicrotask(this, v8_function);
}

void Isolate::EnqueueMicrotask(MicrotaskCallback callback, void* data) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->default_microtask_queue()->EnqueueMicrotask(this, callback, data);
}

void Isolate::SetMicrotasksPolicy(MicrotasksPolicy policy) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->default_microtask_queue()->set_microtasks_policy(policy);
}

MicrotasksPolicy Isolate::GetMicrotasksPolicy() const {
  i::Isolate* i_isolate =
      reinterpret_cast<i::Isolate*>(const_cast<Isolate*>(this));
  return i_isolate->default_microtask_queue()->microtasks_policy();
}

void Isolate::AddMicrotasksCompletedCallback(
    MicrotasksCompletedCallbackWithData callback, void* data) {
  DCHECK(callback);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->default_microtask_queue()->AddMicrotasksCompletedCallback(callback,
                                                                       data);
}

void Isolate::RemoveMicrotasksCompletedCallback(
    MicrotasksCompletedCallbackWithData callback, void* data) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->default_microtask_queue()->RemoveMicrotasksCompletedCallback(
      callback, data);
}

void Isolate::SetUseCounterCallback(UseCounterCallback callback) {
  reinterpret_cast<i::Isolate*>(this)->SetUseCounterCallback(callback);
}

void Isolate::SetCounterFunction(CounterLookupCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->counters()->ResetCounterFunction(callback);
}

void Isolate::SetCreateHistogramFunction(CreateHistogramCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->counters()->ResetCreateHistogramFunction(callback);
}

void Isolate::SetAddHistogramSampleFunction(
    AddHistogramSampleCallback callback) {
  reinterpret_cast<i::Isolate*>(this)
      ->counters()
      ->SetAddHistogramSampleFunction(callback);
}

void Isolate::SetMetricsRecorder(
    const std::shared_ptr<metrics::Recorder>& metrics_recorder) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->metrics_recorder()->SetEmbedderRecorder(i_isolate,
                                                     metrics_recorder);
}

void Isolate::SetAddCrashKeyCallback(AddCrashKeyCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetAddCrashKeyCallback(callback);
}

void Isolate::LowMemoryNotification() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  {
    i::NestedTimedHistogramScope idle_notification_scope(
        i_isolate->counters()->gc_low_memory_notification());
    TRACE_EVENT0("v8", "V8.GCLowMemoryNotification");
#ifdef DEBUG
    // This method might be called on a thread that's not bound to any Isolate
    // and thus pointer compression schemes might have cage base value unset.
    // Read-only roots accessors contain type DCHECKs which require access to
    // V8 heap in order to check the object type. So, allow heap access here
    // to let the checks work.
    i::PtrComprCageAccessScope ptr_compr_cage_access_scope(i_isolate);
#endif  // DEBUG
    i_isolate->heap()->CollectAllAvailableGarbage(
        i::GarbageCollectionReason::kLowMemoryNotification);
  }
}

int Isolate::ContextDisposedNotification(bool dependant_context) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
#if V8_ENABLE_WEBASSEMBLY
  if (!dependant_context) {
    if (!i_isolate->context().is_null()) {
      // We left the current context, we can abort all WebAssembly compilations
      // of that context.
      // A handle scope for the native context.
      i::HandleScope handle_scope(i_isolate);
      i::wasm::GetWasmEngine()->DeleteCompileJobsOnContext(
          i_isolate->native_context());
    }
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  i_isolate->AbortConcurrentOptimization(i::BlockingBehavior::kDontBlock);
  // TODO(ahaas): move other non-heap activity out of the heap call.
  return i_isolate->heap()->NotifyContextDisposed(dependant_context);
}

void Isolate::IsolateInForegroundNotification() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  return i_isolate->SetPriority(Priority::kUserBlocking);
}

void Isolate::IsolateInBackgroundNotification() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  return i_isolate->SetPriority(Priority::kBestEffort);
}

void Isolate::SetPriority(Priority priority) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  return i_isolate->SetPriority(priority);
}

void Isolate::MemoryPressureNotification(MemoryPressureLevel level) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  bool on_isolate_thread =
      i_isolate->was_locker_ever_used()
          ? i_isolate->thread_manager()->IsLockedByCurrentThread()
          : i::ThreadId::Current() == i_isolate->thread_id();
  i_isolate->heap()->MemoryPressureNotification(level, on_isolate_thread);
}

void Isolate::SetBatterySaverMode(bool battery_saver_mode_enabled) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->set_battery_saver_mode_enabled(battery_saver_mode_enabled);
}

void Isolate::ClearCachesForTesting() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->AbortConcurrentOptimization(i::BlockingBehavior::kBlock);
  i_isolate->ClearSerializerData();
  i_isolate->compilation_cache()->Clear();
}

void Isolate::SetRAILMode(RAILMode rail_mode) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetRAILMode(rail_mode);
}

void Isolate::UpdateLoadStartTime() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->UpdateLoadStartTime();
}

void Isolate::SetIsLoading(bool is_loading) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetIsLoading(is_loading);
}

void Isolate::IncreaseHeapLimitForDebugging() {
  // No-op.
}

void Isolate::RestoreOriginalHeapLimit() {
  // No-op.
}

bool Isolate::IsHeapLimitIncreasedForDebugging() { return false; }

void Isolate::SetJitCodeEventHandler(JitCodeEventOptions options,
                                     JitCodeEventHandler event_handler) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  // Ensure that logging is initialized for our isolate.
  i_isolate->InitializeLoggingAndCounters();
  i_isolate->v8_file_logger()->SetCodeEventHandler(options, event_handler);
}

void Isolate::SetStackLimit(uintptr_t stack_limit) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  CHECK(stack_limit);
  i_isolate->stack_guard()->SetStackLimit(stack_limit);
}

void Isolate::GetCodeRange(void** start, size_t* length_in_bytes) {
  i::Isolate* i_isolate
```