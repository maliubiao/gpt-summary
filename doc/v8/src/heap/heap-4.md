Response: The user wants a summary of the C++ source code file `v8/src/heap/heap.cc`.
This is the 5th part of a 5-part series, suggesting that the previous parts covered other aspects of the heap management in V8. This part likely focuses on specific functionalities not covered earlier.

I need to identify the main functionalities implemented in this code snippet and explain their purpose. If any of these functionalities relate to JavaScript, I need to illustrate that with a simple JavaScript example.

Looking at the code, I can identify the following functionalities:

1. **Detached Contexts:**  Functions to retrieve and count detached contexts.
2. **Object Migration:** A function to determine if an object can be migrated between memory spaces.
3. **Embedder Allocation Counter:**  Retrieving the allocation size from the embedder's heap (if it exists).
4. **Object Statistics:**  Functions to create and manage object statistics.
5. **GC-Safe Operations:** Functions to safely access `Map` and `Code` objects during garbage collection.
6. **Code Location:** Functions to find the `Code` object corresponding to a given memory address.
7. **Counters:** Incrementing object counters.
8. **Stress Scavenge:** Checking if scavenge is being stressed.
9. **Marking Flags:** Setting and accessing flags related to garbage collection marking.
10. **Strong Roots:** Managing strong roots using `StrongRootAllocatorBase`.
11. **Allocation Timeout:** Setting an allocation timeout.
12. **Sweeping:**  Functions to ensure garbage collection sweeping is completed.
13. **Loading Notifications:** Functions to notify the heap about the start and end of loading operations and to update allocation limits.
14. **ID Generation:** Functions to generate unique IDs for scripts, debugging, and stack traces.
15. **Embedder Stack State:** Managing the state of the embedder's stack.
16. **C++ Heap Integration:**  Integration with a separate C++ heap.
17. **Code Page Protection:**  Managing write protection for code pages (primarily for debugging).

Now, let's see which of these have direct connections to JavaScript.

*   **Detached Contexts:**  Detached contexts are related to iframes or closed windows in a browser, which are JavaScript concepts.
*   **Object Migration:** This is an internal mechanism, but it affects how JavaScript objects are managed in memory.
*   **GC-Safe Operations:**  These are crucial for the correctness of garbage collection while JavaScript code is running.
*   **Code Location:** Finding the `Code` object is fundamental to executing JavaScript functions.
*   **Marking Flags & Sweeping:** These are core parts of the garbage collection process, which directly manages the memory used by JavaScript objects.
*   **Loading Notifications & Allocation Limits:** These relate to the initial setup and resource management when a JavaScript application starts.
*   **ID Generation (Script ID):**  Script IDs are used to identify JavaScript code.

I'll choose **Detached Contexts** and **Code Location** to illustrate with JavaScript examples, as they have more direct and understandable connections.
这是 `v8/src/heap/heap.cc` 文件的第五部分，主要负责 V8 堆的以下功能：

**1. 管理已分离的上下文 (Detached Contexts):**

*   **功能:** 提供访问和统计与已分离的全局对象关联的上下文（例如，已关闭的 iframe 或窗口）。当一个全局对象不再被使用，但其关联的上下文可能仍然持有某些资源时，这些上下文会被标记为“已分离”。
*   **与 JavaScript 的关系:** 当在 JavaScript 中关闭一个窗口或 iframe 时，与之关联的全局对象会变为不可访问。V8 需要跟踪这些已分离的上下文，以便在适当的时候回收它们所占用的资源。

    ```javascript
    // 在浏览器环境中
    let newWindow = window.open();
    // ... 在 newWindow 中执行一些操作 ...
    newWindow.close(); // 关闭窗口，与之关联的上下文会变成 detached
    ```

**2. 控制对象的迁移 (Object Migration):**

*   **功能:**  定义了对象在垃圾回收过程中是否以及在何种条件下可以从一个内存空间迁移到另一个内存空间。这涉及到不同的内存区域，例如新生代 (new-space)、老生代 (old-space) 等。
*   **与 JavaScript 的关系:**  JavaScript 对象的生命周期和大小会影响它们在堆中的位置以及是否会被迁移。例如，新创建的、生命周期较短的对象通常位于新生代，而存活时间较长的对象可能会被提升到老生代。

    ```javascript
    function createShortLivedObject() {
      return {}; // 新创建的对象，很可能分配在新生代
    }

    let longLivedObject = {}; //  生命周期较长的对象，可能被提升到老生代

    // 多次调用 createShortLivedObject 可能会触发新生代垃圾回收，
    // 这期间 shortLivedObject 会被回收，而 longLivedObject 可能会被迁移。
    for (let i = 0; i < 1000; i++) {
      createShortLivedObject();
    }
    ```

**3. 获取嵌入器分配计数器 (Embedder Allocation Counter):**

*   **功能:** 如果 V8 被嵌入到其他应用程序中（例如 Node.js 或 Chrome），可以获取嵌入器自身分配的内存大小。
*   **与 JavaScript 的关系:**  虽然 JavaScript 本身不直接操作嵌入器的内存，但了解嵌入器的内存使用情况有助于分析整体应用程序的内存占用。

**4. 创建对象统计信息 (Create Object Stats):**

*   **功能:**  用于收集和跟踪堆中对象的统计信息，例如不同类型对象的数量。这主要用于性能分析和调试。
*   **与 JavaScript 的关系:**  这些统计信息反映了 JavaScript 代码运行时创建的各种对象（例如，对象、数组、函数等）的分布情况。

**5. 提供 GC 安全的操作 (GC Safe Operations):**

*   **功能:** 提供在垃圾回收期间安全访问堆对象的 `Map` 和 `Code` 的方法。这避免了在对象被移动或回收时出现悬挂指针等问题。
*   **与 JavaScript 的关系:**  当 JavaScript 代码运行时，垃圾回收器可能会同时运行。这些安全操作确保了 V8 内部操作的原子性和一致性，避免了程序崩溃。

**6. 查找代码对象 (Find Code For Inner Pointer):**

*   **功能:**  根据给定的内存地址，找到对应的 `Code` 对象。`Code` 对象包含了编译后的 JavaScript 代码。
*   **与 JavaScript 的关系:**  当 JavaScript 引擎需要执行一段 JavaScript 代码时，它需要找到该代码对应的 `Code` 对象。

    ```javascript
    function myFunction() {
      console.log("Hello");
    }

    myFunction(); // 当调用 myFunction 时，V8 需要找到 myFunction 对应的编译后的代码
    ```

**7. 管理标记标志 (Marking Flags):**

*   **功能:**  设置和获取用于指示垃圾回收标记阶段是否正在进行的标志。
*   **与 JavaScript 的关系:**  这些标志是垃圾回收器内部状态的一部分，影响着 JavaScript 对象的内存管理。

**8. 管理强根 (Strong Roots):**

*   **功能:**  提供一种机制来注册和管理“强根”，这些根对象不会被垃圾回收器回收，即使没有其他对象引用它们。
*   **与 JavaScript 的关系:**  JavaScript 引擎的内部对象和一些重要的全局对象会被注册为强根，以确保它们在程序运行期间始终存在。

**9. 控制垃圾回收的完成 (Ensure Sweeping Completed):**

*   **功能:**  确保垃圾回收的清扫阶段完成。清扫阶段负责回收不再使用的内存。
*   **与 JavaScript 的关系:**  垃圾回收的清扫阶段直接影响着 JavaScript 程序的内存使用和性能。

**10. 通知加载开始和结束 (Notify Loading Started/Ended):**

*   **功能:**  在 V8 加载脚本时通知堆，并可以在加载完成后重新计算内存限制。
*   **与 JavaScript 的关系:**  这与 JavaScript 代码的初始化和执行过程有关。

**11. 生成 ID (NextScriptId, NextDebuggingId, NextStackTraceId):**

*   **功能:**  为脚本、调试信息和堆栈跟踪生成唯一的 ID。
*   **与 JavaScript 的关系:**  这些 ID 用于在调试和性能分析工具中标识不同的代码段和执行过程。

**12. 管理嵌入器堆栈状态 (Embedder Stack State):**

*   **功能:**  允许嵌入器（例如 Node.js）管理 V8 的堆栈状态。
*   **与 JavaScript 的关系:**  当 JavaScript 调用嵌入器的 API 时，需要正确管理堆栈状态。

**总结:**

这部分 `v8/src/heap/heap.cc` 代码主要关注 V8 堆的内部管理，包括跟踪已分离的上下文、控制对象迁移、提供 GC 安全的操作、查找代码对象以及管理垃圾回收的各个阶段。这些功能虽然是底层的实现细节，但直接影响着 JavaScript 程序的内存管理、性能和运行时的正确性。 例如，理解对象迁移可以帮助我们理解 JavaScript 对象的生命周期，而 GC 安全的操作则保证了 JavaScript 代码执行期间垃圾回收的安全性。

### 提示词
```
这是目录为v8/src/heap/heap.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第5部分，共5部分，请归纳一下它的功能
```

### 源代码
```
ontext>(context);
    result.push_back(Cast<WeakArrayList>(native_context->retained_maps()));
    context = native_context->next_context_link();
  }
  return result;
}

size_t Heap::NumberOfDetachedContexts() {
  // The detached_contexts() array has two entries per detached context.
  return detached_contexts()->length() / 2;
}

bool Heap::AllowedToBeMigrated(Tagged<Map> map, Tagged<HeapObject> object,
                               AllocationSpace dst) {
  // Object migration is governed by the following rules:
  //
  // 1) Objects in new-space can be migrated to the old space
  //    that matches their target space or they stay in new-space.
  // 2) Objects in old-space stay in the same space when migrating.
  // 3) Fillers (two or more words) can migrate due to left-trimming of
  //    fixed arrays in new-space or old space.
  // 4) Fillers (one word) can never migrate, they are skipped by
  //    incremental marking explicitly to prevent invalid pattern.
  //
  // Since this function is used for debugging only, we do not place
  // asserts here, but check everything explicitly.
  if (map == ReadOnlyRoots(this).one_pointer_filler_map()) {
    return false;
  }
  InstanceType type = map->instance_type();
  MutablePageMetadata* chunk = MutablePageMetadata::FromHeapObject(object);
  AllocationSpace src = chunk->owner_identity();
  switch (src) {
    case NEW_SPACE:
      return dst == NEW_SPACE || dst == OLD_SPACE;
    case OLD_SPACE:
      return dst == OLD_SPACE;
    case CODE_SPACE:
      return dst == CODE_SPACE && type == INSTRUCTION_STREAM_TYPE;
    case SHARED_SPACE:
      return dst == SHARED_SPACE;
    case TRUSTED_SPACE:
      return dst == TRUSTED_SPACE;
    case SHARED_TRUSTED_SPACE:
      return dst == SHARED_TRUSTED_SPACE;
    case LO_SPACE:
    case CODE_LO_SPACE:
    case NEW_LO_SPACE:
    case SHARED_LO_SPACE:
    case TRUSTED_LO_SPACE:
    case SHARED_TRUSTED_LO_SPACE:
    case RO_SPACE:
      return false;
  }
  UNREACHABLE();
}

size_t Heap::EmbedderAllocationCounter() const {
  return cpp_heap_ ? CppHeap::From(cpp_heap_)->allocated_size() : 0;
}

void Heap::CreateObjectStats() {
  if (V8_LIKELY(!TracingFlags::is_gc_stats_enabled())) return;
  if (!live_object_stats_) {
    live_object_stats_.reset(new ObjectStats(this));
  }
  if (!dead_object_stats_) {
    dead_object_stats_.reset(new ObjectStats(this));
  }
}

Tagged<Map> Heap::GcSafeMapOfHeapObject(Tagged<HeapObject> object) {
  PtrComprCageBase cage_base(isolate());
  MapWord map_word = object->map_word(cage_base, kRelaxedLoad);
  if (map_word.IsForwardingAddress()) {
    return map_word.ToForwardingAddress(object)->map(cage_base);
  }
  return map_word.ToMap();
}

Tagged<GcSafeCode> Heap::GcSafeGetCodeFromInstructionStream(
    Tagged<HeapObject> instruction_stream, Address inner_pointer) {
  Tagged<InstructionStream> istream =
      UncheckedCast<InstructionStream>(instruction_stream);
  DCHECK(!istream.is_null());
  DCHECK(GcSafeInstructionStreamContains(istream, inner_pointer));
  return UncheckedCast<GcSafeCode>(istream->raw_code(kAcquireLoad));
}

bool Heap::GcSafeInstructionStreamContains(
    Tagged<InstructionStream> instruction_stream, Address addr) {
  Tagged<Map> map = GcSafeMapOfHeapObject(instruction_stream);
  DCHECK_EQ(map, ReadOnlyRoots(this).instruction_stream_map());

  Builtin builtin_lookup_result =
      OffHeapInstructionStream::TryLookupCode(isolate(), addr);
  if (Builtins::IsBuiltinId(builtin_lookup_result)) {
    // Builtins don't have InstructionStream objects.
    DCHECK(!Builtins::IsBuiltinId(
        instruction_stream->code(kAcquireLoad)->builtin_id()));
    return false;
  }

  Address start = instruction_stream.address();
  Address end = start + instruction_stream->SizeFromMap(map);
  return start <= addr && addr < end;
}

std::optional<Tagged<InstructionStream>>
Heap::GcSafeTryFindInstructionStreamForInnerPointer(Address inner_pointer) {
  std::optional<Address> start =
      ThreadIsolation::StartOfJitAllocationAt(inner_pointer);
  if (start.has_value()) {
    return UncheckedCast<InstructionStream>(HeapObject::FromAddress(*start));
  }

  return {};
}

std::optional<Tagged<GcSafeCode>> Heap::GcSafeTryFindCodeForInnerPointer(
    Address inner_pointer) {
  Builtin maybe_builtin =
      OffHeapInstructionStream::TryLookupCode(isolate(), inner_pointer);
  if (Builtins::IsBuiltinId(maybe_builtin)) {
    return Cast<GcSafeCode>(isolate()->builtins()->code(maybe_builtin));
  }

  std::optional<Tagged<InstructionStream>> maybe_istream =
      GcSafeTryFindInstructionStreamForInnerPointer(inner_pointer);
  if (!maybe_istream) return {};

  return GcSafeGetCodeFromInstructionStream(*maybe_istream, inner_pointer);
}

Tagged<Code> Heap::FindCodeForInnerPointer(Address inner_pointer) {
  return GcSafeFindCodeForInnerPointer(inner_pointer)->UnsafeCastToCode();
}

Tagged<GcSafeCode> Heap::GcSafeFindCodeForInnerPointer(Address inner_pointer) {
  std::optional<Tagged<GcSafeCode>> maybe_code =
      GcSafeTryFindCodeForInnerPointer(inner_pointer);
  // Callers expect that the code object is found.
  CHECK(maybe_code.has_value());
  return UncheckedCast<GcSafeCode>(maybe_code.value());
}

std::optional<Tagged<Code>> Heap::TryFindCodeForInnerPointerForPrinting(
    Address inner_pointer) {
  if (InSpaceSlow(inner_pointer, i::CODE_SPACE) ||
      InSpaceSlow(inner_pointer, i::CODE_LO_SPACE) ||
      i::OffHeapInstructionStream::PcIsOffHeap(isolate(), inner_pointer)) {
    std::optional<Tagged<GcSafeCode>> maybe_code =
        GcSafeTryFindCodeForInnerPointer(inner_pointer);
    if (maybe_code.has_value()) {
      return maybe_code.value()->UnsafeCastToCode();
    }
  }
  return {};
}

#ifdef DEBUG
void Heap::IncrementObjectCounters() {
  isolate_->counters()->objs_since_last_full()->Increment();
  isolate_->counters()->objs_since_last_young()->Increment();
}
#endif  // DEBUG

bool Heap::IsStressingScavenge() {
  return v8_flags.stress_scavenge > 0 && new_space();
}

void Heap::SetIsMarkingFlag(bool value) {
  isolate()->isolate_data()->is_marking_flag_ = value;
}

uint8_t* Heap::IsMarkingFlagAddress() {
  return &isolate()->isolate_data()->is_marking_flag_;
}

void Heap::SetIsMinorMarkingFlag(bool value) {
  isolate()->isolate_data()->is_minor_marking_flag_ = value;
}

uint8_t* Heap::IsMinorMarkingFlagAddress() {
  return &isolate()->isolate_data()->is_minor_marking_flag_;
}

StrongRootAllocatorBase::StrongRootAllocatorBase(LocalHeap* heap)
    : StrongRootAllocatorBase(heap->heap()) {}
StrongRootAllocatorBase::StrongRootAllocatorBase(Isolate* isolate)
    : StrongRootAllocatorBase(isolate->heap()) {}
StrongRootAllocatorBase::StrongRootAllocatorBase(v8::Isolate* isolate)
    : StrongRootAllocatorBase(reinterpret_cast<Isolate*>(isolate)) {}
StrongRootAllocatorBase::StrongRootAllocatorBase(LocalIsolate* isolate)
    : StrongRootAllocatorBase(isolate->heap()) {}

// StrongRootBlocks are allocated as a block of addresses, prefixed with a
// StrongRootsEntry pointer:
//
//   | StrongRootsEntry*
//   | Address 1
//   | ...
//   | Address N
//
// The allocate method registers the range "Address 1" to "Address N" with the
// heap as a strong root array, saves that entry in StrongRootsEntry*, and
// returns a pointer to Address 1.
Address* StrongRootAllocatorBase::allocate_impl(size_t n) {
  void* block = base::Malloc(sizeof(StrongRootsEntry*) + n * sizeof(Address));

  StrongRootsEntry** header = reinterpret_cast<StrongRootsEntry**>(block);
  Address* ret = reinterpret_cast<Address*>(reinterpret_cast<char*>(block) +
                                            sizeof(StrongRootsEntry*));

  memset(ret, kNullAddress, n * sizeof(Address));
  *header = heap()->RegisterStrongRoots(
      "StrongRootAllocator", FullObjectSlot(ret), FullObjectSlot(ret + n));

  return ret;
}

void StrongRootAllocatorBase::deallocate_impl(Address* p, size_t n) noexcept {
  // The allocate method returns a pointer to Address 1, so the deallocate
  // method has to offset that pointer back by sizeof(StrongRootsEntry*).
  void* block = reinterpret_cast<char*>(p) - sizeof(StrongRootsEntry*);
  StrongRootsEntry** header = reinterpret_cast<StrongRootsEntry**>(block);

  heap()->UnregisterStrongRoots(*header);

  base::Free(block);
}

#ifdef V8_ENABLE_ALLOCATION_TIMEOUT
void Heap::set_allocation_timeout(int allocation_timeout) {
  heap_allocator_->SetAllocationTimeout(allocation_timeout);
}
#endif  // V8_ENABLE_ALLOCATION_TIMEOUT

void Heap::FinishSweepingIfOutOfWork() {
  if (sweeper()->major_sweeping_in_progress() &&
      sweeper()->UsingMajorSweeperTasks() &&
      !sweeper()->AreMajorSweeperTasksRunning()) {
    // At this point we know that all concurrent sweeping tasks have run
    // out of work and quit: all pages are swept. The main thread still needs
    // to complete sweeping though.
    DCHECK_IMPLIES(!delay_sweeper_tasks_for_testing_,
                   !sweeper()->HasUnsweptPagesForMajorSweeping());
    EnsureSweepingCompleted(SweepingForcedFinalizationMode::kV8Only);
  }
  if (cpp_heap()) {
    // Ensure that sweeping is also completed for the C++ managed heap, if one
    // exists and it's out of work.
    CppHeap::From(cpp_heap())->FinishSweepingIfOutOfWork();
  }
}

void Heap::EnsureSweepingCompleted(SweepingForcedFinalizationMode mode) {
  CompleteArrayBufferSweeping(this);

  if (sweeper()->sweeping_in_progress()) {
    bool was_minor_sweeping_in_progress = minor_sweeping_in_progress();
    bool was_major_sweeping_in_progress = major_sweeping_in_progress();
    sweeper()->EnsureMajorCompleted();

    if (was_major_sweeping_in_progress) {
      TRACE_GC_EPOCH_WITH_FLOW(tracer(), GCTracer::Scope::MC_COMPLETE_SWEEPING,
                               ThreadKind::kMain,
                               sweeper_->GetTraceIdForFlowEvent(
                                   GCTracer::Scope::MC_COMPLETE_SWEEPING),
                               TRACE_EVENT_FLAG_FLOW_IN);
      old_space()->RefillFreeList();
      code_space()->RefillFreeList();
      if (shared_space()) {
        shared_space()->RefillFreeList();
      }

      trusted_space()->RefillFreeList();
    }

    if (!v8_flags.sticky_mark_bits && v8_flags.minor_ms && use_new_space() &&
        was_minor_sweeping_in_progress) {
      TRACE_GC_EPOCH_WITH_FLOW(
          tracer(), GCTracer::Scope::MINOR_MS_COMPLETE_SWEEPING,
          ThreadKind::kMain,
          sweeper_->GetTraceIdForFlowEvent(
              GCTracer::Scope::MINOR_MS_COMPLETE_SWEEPING),
          TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
      paged_new_space()->paged_space()->RefillFreeList();
    }

    tracer()->NotifyFullSweepingCompleted();

#ifdef VERIFY_HEAP
    if (v8_flags.verify_heap) {
      EvacuationVerifier verifier(this);
      verifier.Run();
    }
#endif
  }

  if (mode == SweepingForcedFinalizationMode::kUnifiedHeap && cpp_heap()) {
    // Ensure that sweeping is also completed for the C++ managed heap, if one
    // exists.
    CppHeap::From(cpp_heap())->FinishSweepingIfRunning();
    DCHECK(!CppHeap::From(cpp_heap())->sweeper().IsSweepingInProgress());
  }

  DCHECK_IMPLIES(
      mode == SweepingForcedFinalizationMode::kUnifiedHeap || !cpp_heap(),
      !tracer()->IsSweepingInProgress());

  if (v8_flags.external_memory_accounted_in_global_limit) {
    if (!using_initial_limit()) {
      auto new_limits = ComputeNewAllocationLimits(this);
      SetOldGenerationAndGlobalAllocationLimit(
          new_limits.old_generation_allocation_limit,
          new_limits.global_allocation_limit);
    }
  }
}

void Heap::EnsureYoungSweepingCompleted() {
  if (!sweeper()->minor_sweeping_in_progress()) return;
  DCHECK(!v8_flags.sticky_mark_bits);

  TRACE_GC_EPOCH_WITH_FLOW(
      tracer(), GCTracer::Scope::MINOR_MS_COMPLETE_SWEEPING, ThreadKind::kMain,
      sweeper_->GetTraceIdForFlowEvent(
          GCTracer::Scope::MINOR_MS_COMPLETE_SWEEPING),
      TRACE_EVENT_FLAG_FLOW_IN);

  sweeper()->EnsureMinorCompleted();
  paged_new_space()->paged_space()->RefillFreeList();

  tracer()->NotifyYoungSweepingCompleted();
}

void Heap::NotifyLoadingStarted() {
  if (v8_flags.update_allocation_limits_after_loading) {
    update_allocation_limits_after_loading_ = true;
  }
  UpdateLoadStartTime();
}

void Heap::NotifyLoadingEnded() {
  RecomputeLimitsAfterLoadingIfNeeded();
  if (auto* job = incremental_marking()->incremental_marking_job()) {
    // The task will start incremental marking (if needed not already started)
    // and advance marking if incremental marking is active.
    job->ScheduleTask(TaskPriority::kUserVisible);
  }
}

void Heap::UpdateLoadStartTime() {
  load_start_time_ms_.store(MonotonicallyIncreasingTimeInMs(),
                            std::memory_order_relaxed);
}

int Heap::NextScriptId() {
  FullObjectSlot last_script_id_slot(&roots_table()[RootIndex::kLastScriptId]);
  Tagged<Smi> last_id = Cast<Smi>(last_script_id_slot.Relaxed_Load());
  Tagged<Smi> new_id, last_id_before_cas;
  do {
    if (last_id.value() == Smi::kMaxValue) {
      static_assert(v8::UnboundScript::kNoScriptId == 0);
      new_id = Smi::FromInt(1);
    } else {
      new_id = Smi::FromInt(last_id.value() + 1);
    }

    // CAS returns the old value on success, and the current value in the slot
    // on failure. Therefore, we want to break if the returned value matches the
    // old value (last_id), and keep looping (with the new last_id value) if it
    // doesn't.
    last_id_before_cas = last_id;
    last_id =
        Cast<Smi>(last_script_id_slot.Relaxed_CompareAndSwap(last_id, new_id));
  } while (last_id != last_id_before_cas);

  return new_id.value();
}

int Heap::NextDebuggingId() {
  int last_id = last_debugging_id().value();
  if (last_id == DebugInfo::DebuggingIdBits::kMax) {
    last_id = DebugInfo::kNoDebuggingId;
  }
  last_id++;
  set_last_debugging_id(Smi::FromInt(last_id));
  return last_id;
}

int Heap::NextStackTraceId() {
  int last_id = last_stack_trace_id().value();
  if (last_id == Smi::kMaxValue) {
    last_id = 0;
  }
  last_id++;
  set_last_stack_trace_id(Smi::FromInt(last_id));
  return last_id;
}

EmbedderStackStateScope::EmbedderStackStateScope(
    Heap* heap, EmbedderStackStateOrigin origin, StackState stack_state)
    : heap_(heap),
      old_stack_state_(heap_->embedder_stack_state_),
      old_origin_(heap->embedder_stack_state_origin_) {
  // Explicit scopes take precedence over implicit scopes.
  if (origin == EmbedderStackStateOrigin::kExplicitInvocation ||
      heap_->embedder_stack_state_origin_ !=
          EmbedderStackStateOrigin::kExplicitInvocation) {
    heap_->embedder_stack_state_ = stack_state;
    heap_->embedder_stack_state_origin_ = origin;
  }
}

EmbedderStackStateScope::~EmbedderStackStateScope() {
  heap_->embedder_stack_state_ = old_stack_state_;
  heap_->embedder_stack_state_origin_ = old_origin_;
}

CppClassNamesAsHeapObjectNameScope::CppClassNamesAsHeapObjectNameScope(
    v8::CppHeap* heap)
    : scope_(std::make_unique<cppgc::internal::ClassNameAsHeapObjectNameScope>(
          *CppHeap::From(heap))) {}

CppClassNamesAsHeapObjectNameScope::~CppClassNamesAsHeapObjectNameScope() =
    default;

#if V8_HEAP_USE_PTHREAD_JIT_WRITE_PROTECT || \
    V8_HEAP_USE_PKU_JIT_WRITE_PROTECT || V8_HEAP_USE_BECORE_JIT_WRITE_PROTECT

CodePageMemoryModificationScopeForDebugging::
    CodePageMemoryModificationScopeForDebugging(Heap* heap,
                                                VirtualMemory* reservation,
                                                base::AddressRegion region)
    : rwx_write_scope_("Write access for zapping.") {
#if !defined(DEBUG) && !defined(VERIFY_HEAP) && !defined(USE_SIMULATOR)
  UNREACHABLE();
#endif
}

CodePageMemoryModificationScopeForDebugging::
    CodePageMemoryModificationScopeForDebugging(MemoryChunkMetadata* chunk)
    : rwx_write_scope_("Write access for zapping.") {
#if !defined(DEBUG) && !defined(VERIFY_HEAP) && !defined(USE_SIMULATOR)
  UNREACHABLE();
#endif
}

CodePageMemoryModificationScopeForDebugging::
    ~CodePageMemoryModificationScopeForDebugging() {}

#else  // V8_HEAP_USE_PTHREAD_JIT_WRITE_PROTECT ||
       // V8_HEAP_USE_PKU_JIT_WRITE_PROTECT ||
       // V8_HEAP_USE_BECORE_JIT_WRITE_PROTECT

CodePageMemoryModificationScopeForDebugging::
    CodePageMemoryModificationScopeForDebugging(Heap* heap,
                                                VirtualMemory* reservation,
                                                base::AddressRegion region) {
#if !defined(DEBUG) && !defined(VERIFY_HEAP) && !defined(USE_SIMULATOR)
  UNREACHABLE();
#endif
}

CodePageMemoryModificationScopeForDebugging::
    CodePageMemoryModificationScopeForDebugging(MemoryChunkMetadata* chunk) {
#if !defined(DEBUG) && !defined(VERIFY_HEAP) && !defined(USE_SIMULATOR)
  UNREACHABLE();
#endif
}

CodePageMemoryModificationScopeForDebugging::
    ~CodePageMemoryModificationScopeForDebugging() {}

#endif

#include "src/objects/object-macros-undef.h"

}  // namespace internal
}  // namespace v8
```