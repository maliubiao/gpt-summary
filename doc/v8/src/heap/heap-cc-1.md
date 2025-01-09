Response:
The user wants to understand the functionality of a specific part of the `v8/src/heap/heap.cc` file. This is the second of nine parts.

Here's a breakdown of how to approach this:

1. **Identify the key functionalities:** Scan the provided code snippet for major actions and data structures. Look for keywords like `if`, `else if`, `for`, function calls, and data member accesses.

2. **Analyze the conditional logic:** Pay close attention to the `if` and `else if` conditions, especially those involving `v8_flags`. These flags often control debugging or experimental features.

3. **Focus on the methods:**  Understand what each method (`AllocationEvent`, `MoveEvent`, `UpdateAllocationsHash`, `PrintAllocationsHash`, `AddHeapObjectAllocationTracker`, `RemoveHeapObjectAllocationTracker`, `UpdateRetainersMapAfterScavenge`, `IncrementDeferredCounts`, `GarbageCollectionPrologue`, `GarbageCollectionPrologueInSafepoint`, `NewSpaceAllocationCounter`, `SizeOfObjects`, `TotalGlobalHandlesSize`, `UsedGlobalHandlesSize`, `AddAllocationObserversToAllSpaces`, `RemoveAllocationObserversFromAllSpaces`, `PublishMainThreadPendingAllocations`, `DeoptMarkedAllocationSites`, `GetGCTypeFromGarbageCollector`, `GarbageCollectionEpilogueInSafepoint`, `GarbageCollectionEpilogue`, `GCCallbacksScope`, `HandleGCRequest`, `ScheduleMinorGCTaskIfNeeded`, `StartMinorMSIncrementalMarkingIfNeeded`, `CollectAllGarbage`, `CompareWords`, `ReportDuplicates`, `CollectAllAvailableGarbage`, `PreciseCollectAllGarbage`, `HandleExternalMemoryInterrupt`, `external_memory_limit_for_interrupt`, `external_memory_soft_limit`, `DevToolsTraceEventScope`, `InvokeExternalCallbacks`, `GlobalMemorySizeFromV8Size`, `SetOldGenerationAndGlobalMaximumSize`, `SetOldGenerationAndGlobalAllocationLimit`, `ResetOldGenerationAndGlobalAllocationLimit`, `CollectGarbage`) does.

4. **Connect to broader concepts:** Relate the specific code to general garbage collection concepts like allocation tracking, object movement, heap statistics, GC triggers, and different GC types.

5. **Address the specific instructions:**
    * **.tq suffix:** Explain that this snippet isn't Torque, it's C++.
    * **JavaScript relation:**  Find areas where the code directly impacts JavaScript execution or memory management. Provide simple JS examples.
    * **Logic inference:** Create a simple scenario with hypothetical inputs and outputs based on the code's behavior.
    * **Common errors:** Identify potential programming errors related to the functionalities described.
    * **Summarize functionality:**  Condense the findings into a concise summary.

**Mental Walkthrough:**

* The first part of the snippet deals with tracking allocations and object movements. The `AllocationEvent` and `MoveEvent` methods seem to record information about these events, potentially for debugging or analysis based on the `v8_flags`. The hashing mechanism suggests a way to summarize allocation patterns.
* The section on `HeapObjectAllocationTracker` indicates a mechanism to observe heap object allocations, with the ability to enable/disable inline allocation.
* `UpdateRetainersMapAfterScavenge` is clearly related to the Scavenger garbage collector and updating references after a scavenge cycle.
* The `GarbageCollectionPrologue` and `GarbageCollectionEpilogue` methods are crucial for understanding the setup and cleanup phases of garbage collection, including updating statistics and triggering callbacks.
* The code mentions different garbage collection types (Mark-Sweep-Compact, Scavenger, Minor Mark-Sweep).
* There's logic for handling different GC requests and scheduling minor GCs.
* The `CollectAllGarbage` and related methods initiate and manage full garbage collections.
* The code addresses external memory pressure and its impact on garbage collection.
* There are functionalities for setting heap limits and managing allocation limits.

By following these steps, we can systematically understand the provided code snippet and address all the user's instructions.
这是v8源代码文件 `v8/src/heap/heap.cc` 的第二部分，主要关注以下几个核心功能：

**1. HeapObject分配追踪 (Heap Object Allocation Tracking):**

*   **`AllocationEvent` 和 `MoveEvent` 方法:** 这两个方法用于记录堆上对象的分配和移动事件。它们在特定 `v8_flags` 开启时被调用，用于调试、性能分析或fuzzing。
    *   `AllocationEvent` 记录新分配的对象地址和大小。
    *   `MoveEvent` 记录对象从一个地址移动到另一个地址的信息。
*   **`UpdateAllocationsHash` 方法:**  这些方法计算一个基于分配事件的哈希值。这可以用于在多次运行中比较分配模式是否一致，特别是在 `v8_flags.verify_predictable` 开启时。
*   **`PrintAllocationsHash` 方法:**  打印当前的分配计数和哈希值，同样受 `v8_flags.dump_allocations_digest_at_alloc` 控制。
*   **`HeapObjectAllocationTracker` 类和相关的 `AddHeapObjectAllocationTracker` / `RemoveHeapObjectAllocationTracker` 方法:**  这是一个用于注册和注销堆对象分配追踪器的机制。追踪器的存在会影响内联分配的启用。

**如果 v8/src/heap/heap.cc 以 .tq 结尾**

这个文件实际是以 `.cc` 结尾，所以它是一个 C++ 源代码文件，而不是 Torque 源代码。Torque 文件通常用于定义内置函数和类型。

**与 JavaScript 的功能关系**

这部分代码直接关系到 V8 引擎的内存管理和垃圾回收机制，而这些是 JavaScript 代码运行的基础。当 JavaScript 代码创建对象时，V8 的堆分配器会调用类似 `AllocationEvent` 的机制来分配内存。当发生垃圾回收时，对象可能会被移动，触发 `MoveEvent`。

**JavaScript 示例:**

```javascript
// 当执行以下代码时，V8 内部会进行内存分配，可能会触发 AllocationEvent
let obj = { a: 1, b: 'hello' };

// 当垃圾回收发生，并且 obj 被移动到新的内存地址时，可能会触发 MoveEvent
// (JavaScript 代码层面无法直接观察到这个过程)
```

**代码逻辑推理**

假设 `v8_flags.verify_predictable` 为 true，并且设置了 `v8_flags.dump_allocations_digest_at_alloc = 10`。

**假设输入:**

1. 分配了一个大小为 32 字节的对象，地址为 `0x12345000`。
2. 分配了一个大小为 64 字节的对象，地址为 `0x12345020`。
3. ...
4. 第 10 次分配发生，对象地址为 `0x12345100`，大小为 128 字节。

**预期输出:**

当第 10 次分配发生时，`PrintAllocationsHash` 会被调用，输出类似于：

```
### Allocations = 10, hash = 0xABCDEF01
```

哈希值 `0xABCDEF01` 是根据前 10 次分配的地址和大小计算出来的。

**用户常见的编程错误**

这部分 C++ 代码是 V8 引擎的内部实现，用户通常不会直接与之交互。然而，理解其背后的原理可以帮助开发者避免一些 JavaScript 编程中的内存相关错误：

*   **创建大量临时对象:**  虽然 JavaScript 有垃圾回收，但创建过多的临时对象仍然会给垃圾回收器带来压力，可能导致性能下降。V8 的分配追踪机制可以帮助分析这种场景。

    ```javascript
    // 避免在循环中创建大量临时对象
    function processData(data) {
      for (let i = 0; i < data.length; i++) {
        // 错误示例：每次迭代都创建一个新对象
        let temp = { index: i, value: data[i] };
        console.log(temp);
      }
    }

    // 优化示例：重复使用对象或避免不必要的对象创建
    function processDataOptimized(data) {
      let temp = {};
      for (let i = 0; i < data.length; i++) {
        temp.index = i;
        temp.value = data[i];
        console.log(temp);
      }
    }
    ```

*   **内存泄漏（在某些非 V8 管理的环境中）：** 虽然 V8 会自动管理 JavaScript 对象的内存，但在与外部资源（例如，通过 Native API）交互时，不正确的资源管理可能会导致内存泄漏。理解 V8 的内存管理有助于诊断这类问题。

**第 2 部分功能归纳**

这部分 `v8/src/heap/heap.cc` 代码主要实现了以下功能：

*   **跟踪堆对象的分配和移动事件:**  允许在特定条件下记录对象分配和移动的详细信息，用于调试和分析。
*   **计算分配哈希:** 提供了一种机制来生成基于分配模式的哈希值，用于比较不同运行中的分配行为。
*   **管理堆对象分配追踪器:**  允许注册和注销用于监控堆对象分配的追踪器。
*   **处理垃圾回收的序言和终结 (Prologue and Epilogue):** 定义了垃圾回收开始和结束时需要执行的操作，包括更新统计信息、触发回调等。
*   **管理垃圾回收请求:**  处理各种触发垃圾回收的条件和请求。
*   **调度次要垃圾回收任务:**  负责安排执行新生代垃圾回收的任务。
*   **启动次要标记扫描的增量标记:**  在满足条件时启动并发的次要标记扫描过程。
*   **执行不同类型的垃圾回收:**  提供了触发和执行全量垃圾回收和新生代垃圾回收的机制。
*   **处理外部内存中断:**  响应外部内存压力，触发垃圾回收以释放内存。
*   **设置和管理堆大小限制:**  允许设置老生代和全局内存的最大值和分配限制。

总的来说，这部分代码是 V8 引擎堆管理和垃圾回收核心功能的重要组成部分，它提供了监控、控制和执行内存回收的关键机制。

Prompt: 
```
这是目录为v8/src/heap/heap.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/heap.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共9部分，请归纳一下它的功能

"""
 UpdateAllocationsHash(HeapObject::FromAddress(addr));
      UpdateAllocationsHash(size);

      if (allocations_count_ % v8_flags.dump_allocations_digest_at_alloc == 0) {
        PrintAllocationsHash();
      }
    } else if (v8_flags.fuzzer_gc_analysis) {
      allocations_count_.fetch_add(1, std::memory_order_relaxed);
    } else if (v8_flags.trace_allocation_stack_interval > 0) {
      allocations_count_.fetch_add(1, std::memory_order_relaxed);
      if (allocations_count_ % v8_flags.trace_allocation_stack_interval == 0) {
        heap_->isolate()->PrintStack(stdout, Isolate::kPrintStackConcise);
      }
    }
  }

  void MoveEvent(Address source, Address target, int size) final {
    if (v8_flags.verify_predictable) {
      allocations_count_.fetch_add(1, std::memory_order_relaxed);
      // Advance synthetic time by making a time request.
      heap_->MonotonicallyIncreasingTimeInMs();

      UpdateAllocationsHash(HeapObject::FromAddress(source));
      UpdateAllocationsHash(HeapObject::FromAddress(target));
      UpdateAllocationsHash(size);

      if (allocations_count_ % v8_flags.dump_allocations_digest_at_alloc == 0) {
        PrintAllocationsHash();
      }
    } else if (v8_flags.fuzzer_gc_analysis) {
      allocations_count_.fetch_add(1, std::memory_order_relaxed);
    }
  }

  void UpdateObjectSizeEvent(Address, int) final {}

 private:
  void UpdateAllocationsHash(Tagged<HeapObject> object) {
    Address object_address = object.address();
    MemoryChunk* memory_chunk = MemoryChunk::FromAddress(object_address);
    AllocationSpace allocation_space =
        MutablePageMetadata::cast(memory_chunk->Metadata())->owner_identity();

    static_assert(kSpaceTagSize + kPageSizeBits <= 32);
    uint32_t value =
        static_cast<uint32_t>(memory_chunk->Offset(object_address)) |
        (static_cast<uint32_t>(allocation_space) << kPageSizeBits);

    UpdateAllocationsHash(value);
  }

  void UpdateAllocationsHash(uint32_t value) {
    const uint16_t c1 = static_cast<uint16_t>(value);
    const uint16_t c2 = static_cast<uint16_t>(value >> 16);
    raw_allocations_hash_ =
        StringHasher::AddCharacterCore(raw_allocations_hash_, c1);
    raw_allocations_hash_ =
        StringHasher::AddCharacterCore(raw_allocations_hash_, c2);
  }

  void PrintAllocationsHash() {
    uint32_t hash = StringHasher::GetHashCore(raw_allocations_hash_);
    PrintF("\n### Allocations = %zu, hash = 0x%08x\n",
           allocations_count_.load(std::memory_order_relaxed), hash);
  }

  Heap* const heap_;
  // Count of all allocations performed through C++ bottlenecks. This needs to
  // be atomic as objects are moved in parallel in the GC which counts as
  // allocations.
  std::atomic<size_t> allocations_count_{0};
  // Running hash over allocations performed.
  uint32_t raw_allocations_hash_ = 0;
};

void Heap::AddHeapObjectAllocationTracker(
    HeapObjectAllocationTracker* tracker) {
  if (allocation_trackers_.empty() && v8_flags.inline_new) {
    DisableInlineAllocation();
  }
  allocation_trackers_.push_back(tracker);
  if (allocation_trackers_.size() == 1) {
    isolate_->UpdateLogObjectRelocation();
  }
}

void Heap::RemoveHeapObjectAllocationTracker(
    HeapObjectAllocationTracker* tracker) {
  allocation_trackers_.erase(std::remove(allocation_trackers_.begin(),
                                         allocation_trackers_.end(), tracker),
                             allocation_trackers_.end());
  if (allocation_trackers_.empty()) {
    isolate_->UpdateLogObjectRelocation();
  }
  if (allocation_trackers_.empty() && v8_flags.inline_new) {
    EnableInlineAllocation();
  }
}

void UpdateRetainersMapAfterScavenge(
    UnorderedHeapObjectMap<Tagged<HeapObject>>* map) {
  // This is only used for Scavenger.
  DCHECK(!v8_flags.minor_ms);

  UnorderedHeapObjectMap<Tagged<HeapObject>> updated_map;

  for (auto pair : *map) {
    Tagged<HeapObject> object = pair.first;
    Tagged<HeapObject> retainer = pair.second;

    if (Heap::InFromPage(object)) {
      MapWord map_word = object->map_word(kRelaxedLoad);
      if (!map_word.IsForwardingAddress()) continue;
      object = map_word.ToForwardingAddress(object);
    }

    if (Heap::InFromPage(retainer)) {
      MapWord map_word = retainer->map_word(kRelaxedLoad);
      if (!map_word.IsForwardingAddress()) continue;
      retainer = map_word.ToForwardingAddress(retainer);
    }

    updated_map[object] = retainer;
  }

  *map = std::move(updated_map);
}

void Heap::IncrementDeferredCounts(
    base::Vector<const v8::Isolate::UseCounterFeature> features) {
  deferred_counters_.insert(deferred_counters_.end(), features.begin(),
                            features.end());
}

void Heap::GarbageCollectionPrologue(
    GarbageCollectionReason gc_reason,
    const v8::GCCallbackFlags gc_callback_flags) {
  TRACE_GC(tracer(), GCTracer::Scope::HEAP_PROLOGUE);

  is_current_gc_forced_ = gc_callback_flags & v8::kGCCallbackFlagForced ||
                          current_gc_flags_ & GCFlag::kForced ||
                          force_gc_on_next_allocation_;
  is_current_gc_for_heap_profiler_ =
      gc_reason == GarbageCollectionReason::kHeapProfiler;
  if (force_gc_on_next_allocation_) force_gc_on_next_allocation_ = false;

#ifdef V8_ENABLE_ALLOCATION_TIMEOUT
  heap_allocator_->UpdateAllocationTimeout();
#endif  // V8_ENABLE_ALLOCATION_TIMEOUT

  // There may be an allocation memento behind objects in new space. Upon
  // evacuation of a non-full new space (or if we are on the last page) there
  // may be uninitialized memory behind top. We fill the remainder of the page
  // with a filler.
  if (use_new_space()) {
    DCHECK_NOT_NULL(minor_gc_job());
    minor_gc_job()->CancelTaskIfScheduled();
  }

  // Reset GC statistics.
  promoted_objects_size_ = 0;
  previous_new_space_surviving_object_size_ = new_space_surviving_object_size_;
  new_space_surviving_object_size_ = 0;
  nodes_died_in_new_space_ = 0;
  nodes_copied_in_new_space_ = 0;
  nodes_promoted_ = 0;

  UpdateMaximumCommitted();

#ifdef DEBUG
  DCHECK(!AllowGarbageCollection::IsAllowed());
  DCHECK_EQ(gc_state(), NOT_IN_GC);

  if (v8_flags.gc_verbose) Print();
#endif  // DEBUG
}

void Heap::GarbageCollectionPrologueInSafepoint() {
  TRACE_GC(tracer(), GCTracer::Scope::HEAP_PROLOGUE_SAFEPOINT);
  gc_count_++;
  new_space_allocation_counter_ = NewSpaceAllocationCounter();
}

size_t Heap::NewSpaceAllocationCounter() const {
  size_t counter = new_space_allocation_counter_;
  if (new_space_) {
    DCHECK(!allocator()->new_space_allocator()->IsLabValid());
    counter += new_space()->AllocatedSinceLastGC();
  }
  return counter;
}

size_t Heap::SizeOfObjects() {
  size_t total = 0;

  for (SpaceIterator it(this); it.HasNext();) {
    total += it.Next()->SizeOfObjects();
  }
  return total;
}

size_t Heap::TotalGlobalHandlesSize() {
  return isolate_->global_handles()->TotalSize() +
         isolate_->traced_handles()->total_size_bytes();
}

size_t Heap::UsedGlobalHandlesSize() {
  return isolate_->global_handles()->UsedSize() +
         isolate_->traced_handles()->used_size_bytes();
}

void Heap::AddAllocationObserversToAllSpaces(
    AllocationObserver* observer, AllocationObserver* new_space_observer) {
  DCHECK(observer && new_space_observer);
  FreeMainThreadLinearAllocationAreas();
  allocator()->AddAllocationObserver(observer, new_space_observer);
}

void Heap::RemoveAllocationObserversFromAllSpaces(
    AllocationObserver* observer, AllocationObserver* new_space_observer) {
  DCHECK(observer && new_space_observer);
  allocator()->RemoveAllocationObserver(observer, new_space_observer);
}

void Heap::PublishMainThreadPendingAllocations() {
  allocator()->PublishPendingAllocations();
}

void Heap::DeoptMarkedAllocationSites() {
  // TODO(hpayer): If iterating over the allocation sites list becomes a
  // performance issue, use a cache data structure in heap instead.

  ForeachAllocationSite(
      allocation_sites_list(), [this](Tagged<AllocationSite> site) {
        if (site->deopt_dependent_code()) {
          DependentCode::MarkCodeForDeoptimization(
              isolate_, site,
              DependentCode::kAllocationSiteTenuringChangedGroup);
          site->set_deopt_dependent_code(false);
        }
      });

  Deoptimizer::DeoptimizeMarkedCode(isolate_);
}

static GCType GetGCTypeFromGarbageCollector(GarbageCollector collector) {
  switch (collector) {
    case GarbageCollector::MARK_COMPACTOR:
      return kGCTypeMarkSweepCompact;
    case GarbageCollector::SCAVENGER:
      return kGCTypeScavenge;
    case GarbageCollector::MINOR_MARK_SWEEPER:
      return kGCTypeMinorMarkSweep;
    default:
      UNREACHABLE();
  }
}

void Heap::GarbageCollectionEpilogueInSafepoint(GarbageCollector collector) {
  TRACE_GC(tracer(), GCTracer::Scope::HEAP_EPILOGUE_SAFEPOINT);

  {
    // Allows handle derefs for all threads/isolates from this thread.
    AllowHandleUsageOnAllThreads allow_all_handle_derefs;
    safepoint()->IterateLocalHeaps([](LocalHeap* local_heap) {
      local_heap->InvokeGCEpilogueCallbacksInSafepoint(
          GCCallbacksInSafepoint::GCType::kLocal);
    });

    if (collector == GarbageCollector::MARK_COMPACTOR &&
        isolate()->is_shared_space_isolate()) {
      isolate()->global_safepoint()->IterateClientIsolates([](Isolate* client) {
        client->heap()->safepoint()->IterateLocalHeaps(
            [](LocalHeap* local_heap) {
              local_heap->InvokeGCEpilogueCallbacksInSafepoint(
                  GCCallbacksInSafepoint::GCType::kShared);
            });
      });
    }
  }

#define UPDATE_COUNTERS_FOR_SPACE(space)                \
  isolate_->counters()->space##_bytes_available()->Set( \
      static_cast<int>(space()->Available()));          \
  isolate_->counters()->space##_bytes_committed()->Set( \
      static_cast<int>(space()->CommittedMemory()));    \
  isolate_->counters()->space##_bytes_used()->Set(      \
      static_cast<int>(space()->SizeOfObjects()));
#define UPDATE_FRAGMENTATION_FOR_SPACE(space)                          \
  if (space()->CommittedMemory() > 0) {                                \
    isolate_->counters()->external_fragmentation_##space()->AddSample( \
        static_cast<int>(100 - (space()->SizeOfObjects() * 100.0) /    \
                                   space()->CommittedMemory()));       \
  }
#define UPDATE_COUNTERS_AND_FRAGMENTATION_FOR_SPACE(space) \
  UPDATE_COUNTERS_FOR_SPACE(space)                         \
  UPDATE_FRAGMENTATION_FOR_SPACE(space)

  if (new_space()) {
    UPDATE_COUNTERS_FOR_SPACE(new_space)
  }

  UPDATE_COUNTERS_AND_FRAGMENTATION_FOR_SPACE(old_space)
  UPDATE_COUNTERS_AND_FRAGMENTATION_FOR_SPACE(code_space)

  UPDATE_COUNTERS_AND_FRAGMENTATION_FOR_SPACE(lo_space)
#undef UPDATE_COUNTERS_FOR_SPACE
#undef UPDATE_FRAGMENTATION_FOR_SPACE
#undef UPDATE_COUNTERS_AND_FRAGMENTATION_FOR_SPACE

#ifdef DEBUG
  if (v8_flags.print_global_handles) isolate_->global_handles()->Print();
  if (v8_flags.print_handles) PrintHandles();
  if (v8_flags.check_handle_count) CheckHandleCount();
#endif

  // Young generation GCs only run with  memory reducing flags during
  // interleaved GCs.
  DCHECK_IMPLIES(
      v8_flags.separate_gc_phases && IsYoungGenerationCollector(collector),
      !ShouldReduceMemory());
  if (collector == GarbageCollector::MARK_COMPACTOR) {
    memory_pressure_level_.store(MemoryPressureLevel::kNone,
                                 std::memory_order_relaxed);

    if (v8_flags.stress_marking > 0) {
      stress_marking_percentage_ = NextStressMarkingLimit();
    }
    // Discard memory if the GC was requested to reduce memory.
    if (ShouldReduceMemory()) {
      memory_allocator_->pool()->ReleasePooledChunks();
#if V8_ENABLE_WEBASSEMBLY
      isolate_->stack_pool().ReleaseFinishedStacks();
#endif
    }
  }

  // Remove CollectionRequested flag from main thread state, as the collection
  // was just performed.
  safepoint()->AssertActive();
  LocalHeap::ThreadState old_state =
      main_thread_local_heap()->state_.ClearCollectionRequested();

  CHECK(old_state.IsRunning());

  // Resume all threads waiting for the GC.
  collection_barrier_->ResumeThreadsAwaitingCollection();
}

void Heap::GarbageCollectionEpilogue(GarbageCollector collector) {
  TRACE_GC(tracer(), GCTracer::Scope::HEAP_EPILOGUE);
  AllowGarbageCollection for_the_rest_of_the_epilogue;

  UpdateMaximumCommitted();

  isolate_->counters()->alive_after_last_gc()->Set(
      static_cast<int>(SizeOfObjects()));

  if (CommittedMemory() > 0) {
    isolate_->counters()->external_fragmentation_total()->AddSample(
        static_cast<int>(100 - (SizeOfObjects() * 100.0) / CommittedMemory()));

    isolate_->counters()->heap_sample_total_committed()->AddSample(
        static_cast<int>(CommittedMemory() / KB));
    isolate_->counters()->heap_sample_total_used()->AddSample(
        static_cast<int>(SizeOfObjects() / KB));
    isolate_->counters()->heap_sample_code_space_committed()->AddSample(
        static_cast<int>(code_space()->CommittedMemory() / KB));

    isolate_->counters()->heap_sample_maximum_committed()->AddSample(
        static_cast<int>(MaximumCommittedMemory() / KB));
  }

#ifdef DEBUG
  ReportStatisticsAfterGC();
  if (v8_flags.code_stats) ReportCodeStatistics("After GC");
#endif  // DEBUG

  last_gc_time_ = MonotonicallyIncreasingTimeInMs();
}

GCCallbacksScope::GCCallbacksScope(Heap* heap) : heap_(heap) {
  heap_->gc_callbacks_depth_++;
}

GCCallbacksScope::~GCCallbacksScope() { heap_->gc_callbacks_depth_--; }

bool GCCallbacksScope::CheckReenter() const {
  return heap_->gc_callbacks_depth_ == 1;
}

void Heap::HandleGCRequest() {
  if (IsStressingScavenge() && stress_scavenge_observer_->HasRequestedGC()) {
    CollectGarbage(NEW_SPACE, GarbageCollectionReason::kTesting);
    stress_scavenge_observer_->RequestedGCDone();
  } else if (HighMemoryPressure()) {
    CheckMemoryPressure();
  } else if (CollectionRequested()) {
    CheckCollectionRequested();
  } else if (incremental_marking()->MajorCollectionRequested()) {
    CollectAllGarbage(current_gc_flags_,
                      GarbageCollectionReason::kFinalizeMarkingViaStackGuard,
                      current_gc_callback_flags_);
  } else if (minor_mark_sweep_collector()->gc_finalization_requsted()) {
    CollectGarbage(NEW_SPACE,
                   GarbageCollectionReason::kFinalizeConcurrentMinorMS);
  }
}

void Heap::ScheduleMinorGCTaskIfNeeded() {
  DCHECK_NOT_NULL(minor_gc_job_);
  minor_gc_job_->ScheduleTask();
}

namespace {
size_t MinorMSConcurrentMarkingTrigger(Heap* heap) {
  size_t young_capacity = 0;
  if (v8_flags.sticky_mark_bits) {
    // TODO(333906585): Adjust parameters.
    young_capacity = heap->sticky_space()->Capacity() -
                     heap->sticky_space()->old_objects_size();
  } else {
    young_capacity = heap->new_space()->TotalCapacity();
  }
  return young_capacity * v8_flags.minor_ms_concurrent_marking_trigger / 100;
}
}  // namespace

void Heap::StartMinorMSIncrementalMarkingIfNeeded() {
  if (incremental_marking()->IsMarking()) return;
  if (v8_flags.concurrent_minor_ms_marking && !IsTearingDown() &&
      incremental_marking()->CanAndShouldBeStarted() &&
      V8_LIKELY(!v8_flags.gc_global)) {
    size_t usable_capacity = 0;
    size_t new_space_size = 0;
    if (v8_flags.sticky_mark_bits) {
      // TODO(333906585): Adjust parameters.
      usable_capacity =
          sticky_space()->Capacity() - sticky_space()->old_objects_size();
      new_space_size = sticky_space()->young_objects_size();
    } else {
      usable_capacity = paged_new_space()->paged_space()->UsableCapacity();
      new_space_size = new_space()->Size();
    }
    if ((usable_capacity >=
         v8_flags.minor_ms_min_new_space_capacity_for_concurrent_marking_mb *
             MB) &&
        (new_space_size >= MinorMSConcurrentMarkingTrigger(this)) &&
        ShouldUseBackgroundThreads()) {
      StartIncrementalMarking(GCFlag::kNoFlags, GarbageCollectionReason::kTask,
                              kNoGCCallbackFlags,
                              GarbageCollector::MINOR_MARK_SWEEPER);
      // Schedule a task for finalizing the GC if needed.
      ScheduleMinorGCTaskIfNeeded();
    }
  }
}

void Heap::CollectAllGarbage(GCFlags gc_flags,
                             GarbageCollectionReason gc_reason,
                             const v8::GCCallbackFlags gc_callback_flags) {
  current_gc_flags_ = gc_flags;
  CollectGarbage(OLD_SPACE, gc_reason, gc_callback_flags);
  DCHECK_EQ(GCFlags(GCFlag::kNoFlags), current_gc_flags_);
}

namespace {

intptr_t CompareWords(int size, Tagged<HeapObject> a, Tagged<HeapObject> b) {
  int slots = size / kTaggedSize;
  DCHECK_EQ(a->Size(), size);
  DCHECK_EQ(b->Size(), size);
  Tagged_t* slot_a = reinterpret_cast<Tagged_t*>(a.address());
  Tagged_t* slot_b = reinterpret_cast<Tagged_t*>(b.address());
  for (int i = 0; i < slots; i++) {
    if (*slot_a != *slot_b) {
      return *slot_a - *slot_b;
    }
    slot_a++;
    slot_b++;
  }
  return 0;
}

void ReportDuplicates(int size, std::vector<Tagged<HeapObject>>* objects) {
  if (objects->empty()) return;

  sort(objects->begin(), objects->end(),
       [size](Tagged<HeapObject> a, Tagged<HeapObject> b) {
         intptr_t c = CompareWords(size, a, b);
         if (c != 0) return c < 0;
         return a < b;
       });

  std::vector<std::pair<int, Tagged<HeapObject>>> duplicates;
  Tagged<HeapObject> current = (*objects)[0];
  int count = 1;
  for (size_t i = 1; i < objects->size(); i++) {
    if (CompareWords(size, current, (*objects)[i]) == 0) {
      count++;
    } else {
      if (count > 1) {
        duplicates.push_back(std::make_pair(count - 1, current));
      }
      count = 1;
      current = (*objects)[i];
    }
  }
  if (count > 1) {
    duplicates.push_back(std::make_pair(count - 1, current));
  }

  int threshold = v8_flags.trace_duplicate_threshold_kb * KB;

  sort(duplicates.begin(), duplicates.end());
  for (auto it = duplicates.rbegin(); it != duplicates.rend(); ++it) {
    int duplicate_bytes = it->first * size;
    if (duplicate_bytes < threshold) break;
    PrintF("%d duplicates of size %d each (%dKB)\n", it->first, size,
           duplicate_bytes / KB);
    PrintF("Sample object: ");
    Print(it->second);
    PrintF("============================\n");
  }
}
}  // anonymous namespace

void Heap::CollectAllAvailableGarbage(GarbageCollectionReason gc_reason) {
  // Min and max number of attempts for GC. The method will continue with more
  // GCs until the root set is stable.
  static constexpr int kMaxNumberOfAttempts = 7;
  static constexpr int kMinNumberOfAttempts = 2;

  // Returns the number of roots. We assume stack layout is stable but global
  // roots could change between GCs due to finalizers and weak callbacks.
  const auto num_roots = [this]() {
    size_t js_roots = 0;
    js_roots += isolate()->global_handles()->handles_count();
    js_roots += isolate()->eternal_handles()->handles_count();
    size_t cpp_roots = 0;
    if (auto* cpp_heap = CppHeap::From(cpp_heap_)) {
      cpp_roots += cpp_heap->GetStrongPersistentRegion().NodesInUse();
      cpp_roots +=
          cpp_heap->GetStrongCrossThreadPersistentRegion().NodesInUse();
    }
    return js_roots + cpp_roots;
  };

  if (gc_reason == GarbageCollectionReason::kLastResort) {
    InvokeNearHeapLimitCallback();
  }
  RCS_SCOPE(isolate(), RuntimeCallCounterId::kGC_Custom_AllAvailableGarbage);

  // The optimizing compiler may be unnecessarily holding on to memory.
  isolate()->AbortConcurrentOptimization(BlockingBehavior::kDontBlock);
  isolate()->ClearSerializerData();
  isolate()->compilation_cache()->Clear();

  const GCFlags gc_flags =
      GCFlag::kReduceMemoryFootprint |
      (gc_reason == GarbageCollectionReason::kLowMemoryNotification
           ? GCFlag::kForced
           : GCFlag::kNoFlags);
  for (int attempt = 0; attempt < kMaxNumberOfAttempts; attempt++) {
    const size_t roots_before = num_roots();
    current_gc_flags_ = gc_flags;
    CollectGarbage(OLD_SPACE, gc_reason, kNoGCCallbackFlags);
    DCHECK_EQ(GCFlags(GCFlag::kNoFlags), current_gc_flags_);
    if ((roots_before == num_roots()) &&
        ((attempt + 1) >= kMinNumberOfAttempts)) {
      break;
    }
  }

  EagerlyFreeExternalMemoryAndWasmCode();

  if (v8_flags.trace_duplicate_threshold_kb) {
    std::map<int, std::vector<Tagged<HeapObject>>> objects_by_size;
    PagedSpaceIterator spaces(this);
    for (PagedSpace* space = spaces.Next(); space != nullptr;
         space = spaces.Next()) {
      PagedSpaceObjectIterator it(this, space);
      for (Tagged<HeapObject> obj = it.Next(); !obj.is_null();
           obj = it.Next()) {
        objects_by_size[obj->Size()].push_back(obj);
      }
    }
    {
      LargeObjectSpaceObjectIterator it(lo_space());
      for (Tagged<HeapObject> obj = it.Next(); !obj.is_null();
           obj = it.Next()) {
        objects_by_size[obj->Size()].push_back(obj);
      }
    }
    for (auto it = objects_by_size.rbegin(); it != objects_by_size.rend();
         ++it) {
      ReportDuplicates(it->first, &it->second);
    }
  }

  if (gc_reason == GarbageCollectionReason::kLastResort &&
      v8_flags.heap_snapshot_on_oom) {
    isolate()->heap_profiler()->WriteSnapshotToDiskAfterGC();
  }
}

void Heap::PreciseCollectAllGarbage(GCFlags gc_flags,
                                    GarbageCollectionReason gc_reason,
                                    const GCCallbackFlags gc_callback_flags) {
  if (!incremental_marking()->IsStopped()) {
    FinalizeIncrementalMarkingAtomically(gc_reason);
  }
  CollectAllGarbage(gc_flags, gc_reason, gc_callback_flags);
}

void Heap::HandleExternalMemoryInterrupt() {
  const GCCallbackFlags kGCCallbackFlagsForExternalMemory =
      static_cast<GCCallbackFlags>(
          kGCCallbackFlagSynchronousPhantomCallbackProcessing |
          kGCCallbackFlagCollectAllExternalMemory);
  uint64_t current = external_memory();
  if (current > external_memory_hard_limit()) {
    TRACE_EVENT2("devtools.timeline,v8", "V8.ExternalMemoryPressure",
                 "external_memory_mb", static_cast<int>((current) / MB),
                 "external_memory_hard_limit_mb",
                 static_cast<int>((external_memory_hard_limit()) / MB));
    CollectAllGarbage(
        GCFlag::kReduceMemoryFootprint,
        GarbageCollectionReason::kExternalMemoryPressure,
        static_cast<GCCallbackFlags>(kGCCallbackFlagCollectAllAvailableGarbage |
                                     kGCCallbackFlagsForExternalMemory));
    return;
  }
  if (v8_flags.external_memory_accounted_in_global_limit) {
    // Under `external_memory_accounted_in_global_limit`, external interrupt
    // only triggers a check to allocation limits.
    external_memory_.UpdateLimitForInterrupt(current);
    StartIncrementalMarkingIfAllocationLimitIsReached(
        main_thread_local_heap(), GCFlagsForIncrementalMarking(),
        kGCCallbackFlagsForExternalMemory);
    return;
  }
  uint64_t soft_limit = external_memory_.soft_limit();
  if (current <= soft_limit) {
    return;
  }
  TRACE_EVENT2("devtools.timeline,v8", "V8.ExternalMemoryPressure",
               "external_memory_mb", static_cast<int>((current) / MB),
               "external_memory_soft_limit_mb",
               static_cast<int>((soft_limit) / MB));
  if (incremental_marking()->IsStopped()) {
    if (incremental_marking()->CanAndShouldBeStarted()) {
      StartIncrementalMarking(GCFlagsForIncrementalMarking(),
                              GarbageCollectionReason::kExternalMemoryPressure,
                              kGCCallbackFlagsForExternalMemory);
    } else {
      CollectAllGarbage(i::GCFlag::kNoFlags,
                        GarbageCollectionReason::kExternalMemoryPressure,
                        kGCCallbackFlagsForExternalMemory);
    }
  } else {
    // Incremental marking is turned on and has already been started.
    current_gc_callback_flags_ = static_cast<GCCallbackFlags>(
        current_gc_callback_flags_ | kGCCallbackFlagsForExternalMemory);
    incremental_marking()->AdvanceAndFinalizeIfNecessary();
  }
}

uint64_t Heap::external_memory_limit_for_interrupt() {
  return external_memory_.limit_for_interrupt();
}

uint64_t Heap::external_memory_soft_limit() {
  return external_memory_.soft_limit();
}

Heap::DevToolsTraceEventScope::DevToolsTraceEventScope(Heap* heap,
                                                       const char* event_name,
                                                       const char* event_type)
    : heap_(heap), event_name_(event_name) {
  TRACE_EVENT_BEGIN2("devtools.timeline,v8", event_name_, "usedHeapSizeBefore",
                     heap_->SizeOfObjects(), "type", event_type);
}

Heap::DevToolsTraceEventScope::~DevToolsTraceEventScope() {
  TRACE_EVENT_END1("devtools.timeline,v8", event_name_, "usedHeapSizeAfter",
                   heap_->SizeOfObjects());
}

namespace {

template <typename Callback>
void InvokeExternalCallbacks(Isolate* isolate, Callback callback) {
  DCHECK(!AllowJavascriptExecution::IsAllowed(isolate));
  AllowGarbageCollection allow_gc;
  // Temporary override any embedder stack state as callbacks may create
  // their own state on the stack and recursively trigger GC.
  EmbedderStackStateScope embedder_scope(
      isolate->heap(), EmbedderStackStateOrigin::kExplicitInvocation,
      StackState::kMayContainHeapPointers);
  VMState<EXTERNAL> callback_state(isolate);

  callback();
}

size_t GlobalMemorySizeFromV8Size(size_t v8_size) {
  const size_t kGlobalMemoryToV8Ratio = 2;
  return std::min(static_cast<uint64_t>(std::numeric_limits<size_t>::max()),
                  static_cast<uint64_t>(v8_size) * kGlobalMemoryToV8Ratio);
}

}  // anonymous namespace

void Heap::SetOldGenerationAndGlobalMaximumSize(
    size_t max_old_generation_size) {
  max_old_generation_size_.store(max_old_generation_size,
                                 std::memory_order_relaxed);
  max_global_memory_size_ = GlobalMemorySizeFromV8Size(max_old_generation_size);
}

void Heap::SetOldGenerationAndGlobalAllocationLimit(
    size_t new_old_generation_allocation_limit,
    size_t new_global_allocation_limit) {
  CHECK_GE(new_global_allocation_limit, new_old_generation_allocation_limit);
#if defined(V8_USE_PERFETTO)
  TRACE_COUNTER(TRACE_DISABLED_BY_DEFAULT("v8.gc"), V8HeapTrait::kName,
                new_old_generation_allocation_limit);
  TRACE_COUNTER(TRACE_DISABLED_BY_DEFAULT("v8.gc"), GlobalMemoryTrait::kName,
                new_global_allocation_limit);
#endif
  old_generation_allocation_limit_.store(new_old_generation_allocation_limit,
                                         std::memory_order_relaxed);
  global_allocation_limit_.store(new_global_allocation_limit,
                                 std::memory_order_relaxed);
}

void Heap::ResetOldGenerationAndGlobalAllocationLimit() {
  SetOldGenerationAndGlobalAllocationLimit(
      initial_old_generation_size_,
      GlobalMemorySizeFromV8Size(initial_old_generation_size_));
  set_using_initial_limit(true);
}

void Heap::CollectGarbage(AllocationSpace space,
                          GarbageCollectionReason gc_reason,
                          const v8::GCCallbackFlags gc_callback_flags) {
  if (V8_UNLIKELY(!deserialization_complete_)) {
    // During isolate initialization heap always grows. GC is only requested
    // if a new page allocation fails. In such a case we should crash with
    // an out-of-memory instead of performing GC because the prologue/epilogue
    // callbacks may see objects that are not yet deserialized.
    CHECK(always_allocate());
    FatalProcessOutOfMemory("GC during deserialization");
  }

  // CollectGarbage consists of three parts:
  // 1. The prologue part which may execute callbacks. These callbacks may
  // allocate and trigger another garbage collection.
  // 2. The main garbage collection phase.
  // 3. The epilogue part which may execute callbacks. These callbacks may
  // allocate and trigger another garbage collection

  // Part 1: Invoke all callbacks which should happen before the actual garbage
  // collection is triggered. Note that these callbacks may trigger another
  // garbage collection since they may allocate.

  // JS execution is not allowed in any of the callbacks.
  DisallowJavascriptExecution no_js(isolate());

  DCHECK(AllowGarbageCollection::IsAllowed());
  // TODO(chromium:1523607): Ensure this for standalone cppgc as well.
  CHECK_IMPLIES(!v8_flags.allow_allocation_in_fast_api_call,
                !isolate()->InFastCCall());

  const char* collector_reason = nullptr;
  const GarbageCollector collector =
      SelectGarbageCollector(space, gc_reason, &collector_reason);
  current_or_last_garbage_collector_ = collector;
  DCHECK_IMPLIES(v8_flags.minor_ms && IsYoungGenerationCollector(collector),
                 !ShouldReduceMemory());

  if (collector == GarbageCollector::MARK_COMPACTOR &&
      incremental_marking()->IsMinorMarking()) {
    const GCFlags gc_flags = current_gc_flags_;
    // Minor GCs should not be memory reducing.
    current_gc_flags_ &= ~GCFlag::kReduceMemoryFootprint;
    CollectGarbage(NEW_SPACE,
                   GarbageCollectionReason::kFinalizeConcurrentMinorMS);
    current_gc_flags_ = gc_flags;
  }

  const GCType gc_type = GetGCTypeFromGarbageCollector(collector);

  // Prologue callbacks. These callbacks may trigger GC themselves and thus
  // cannot be related exactly to garbage collection cycles.
  //
  // GCTracer scopes are managed by callees.
  InvokeExternalCallbacks(isolate(), [this, gc_callback_flags, gc_type]() {
    // Ensure that all pending phantom callbacks are invoked.
    isolate()->global_handles()->InvokeSecondPassPhantomCallbacks();

    // Prologue callbacks registered with Heap.
    CallGCPrologueCallbacks(gc_type, gc_callback_flags,
                            GCTracer::Scope::HEAP_EXTERNAL_PROLOGUE);
  });

  // The main garbage collection phase.
  //
  // We need a stack marker at the top of all entry points to allow
  // deterministic passes over the stack. E.g., a verifier that should only
  // find a subset of references of the marker.
  //
  // TODO(chromium:1056170): Consider adding a component that keeps track
  // of relevant GC stack regions where interesting pointers can be found.
  stack().SetMarkerIfNeededAndCallback([this, collector, gc_reason,
                                        collector_reason, gc_callback_flags]() {
    DisallowGarbageCollection no_gc_during_gc;

    size_t committed_memory_before =
        collector == GarbageCollector::MARK_COMPACTOR
            ? CommittedOldGenerationMemory()
            : 0;

    tracer()->StartObservablePause(base::TimeTicks::Now());
    VMState<GC> state(isolate());
    DevToolsTraceEventScope devtools_trace_event_scope(
        this, IsYoungGenerationCollector(collector) ? "MinorGC" : "MajorGC",
        ToString(gc_reason));

    GarbageCollectionPrologue(gc_reason, gc_callback_flags);
    {
      GCTracer::RecordGCPhasesInfo record_gc_phases_info(this, collector,
                                                         gc_reason);
      std::optional<TimedHistogramScope> histogram_timer_scope;
      std::optional<OptionalTimedHistogramScope> histogram_timer_priority_scope;
      TRACE_EVENT0("v8", record_gc_phases_info.trace_event_name());
      if (record_gc_phases_info.type_timer()) {
        histogram_timer_scope.emplace(record_gc_phases_info.type_timer(),
                                      isolate_);
      }
      if (record_gc_phases_info.type_priority_timer()) {
        histogram_timer_priority_scope.emplace(
            record_gc_phases_info.type_priority_timer(), isolate_,
            OptionalTimedHistogramScopeMode::TAKE_TIME);
      }

      PerformGarbageCollection(collector, gc_reason, collector_reason);

      // Clear flags describing the current GC now that the current GC is
      // complete. Do this before GarbageCollectionEpilogue() since that could
      // trigger another unforced GC.
      is_current_gc_forced_ = false;
      is_current_gc_for_heap_profiler_ = false;

      if (collector == GarbageCollector::MARK_COMPACTOR ||
          collector == GarbageCollector::SCAVENGER) {
        tracer()->RecordGCPhasesHistograms(record_gc_phases_info.mode());
      }
      if ((collector == GarbageCollector::MARK_COMPACTOR ||
           collector == GarbageCollector::MINOR_MARK_SWEEPER) &&
          cpp_heap()) {
        CppHeap::From(cpp_heap())->FinishAtomicSweepingIfRunning();
      }
    }

    GarbageCollectionEpilogue(collector);
    if (collector == GarbageCollector::MARK_COMPACTOR &&
        v8_flags.track_detached_contexts) {
      isolate()->CheckDetachedContextsAfterGC();
    }

    if (collector == G
"""


```