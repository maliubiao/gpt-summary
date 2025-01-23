Response:
The user wants a summary of the provided C++ code snippet from `v8/src/heap/heap.h`.
This is part 3 of a 4-part series, so the summary should focus on the functionalities exposed in this specific part.
The user also asks about specific properties of the code, including:
- Whether it would be a Torque file if it had a `.tq` extension.
- Whether any functionality relates to Javascript and an example.
- Any code logic with example input and output.
- Common programming errors related to the functionality.

Based on the provided code, this section of `heap.h` primarily focuses on:
- **Garbage Collection Control and Execution:** Triggering, managing different GC types (MarkCompact, MinorMarkSweep, Scavenge), and related operations like prologs, epilogs, and statistics.
- **Memory Management and Limits:**  Setting, getting, and adjusting heap limits (old generation, global), resizing spaces, and managing memory pressure.
- **Allocation:** Raw and typed object allocation, including handling allocation failures and retries.
- **Internal Utilities:** Functions for managing weak references, external strings, and other internal bookkeeping.

Let's break down each of the user's points:

1. **`.tq` extension:** Yes, if `v8/src/heap/heap.h` ended with `.tq`, it would be a V8 Torque source file. Torque is V8's domain-specific language for defining built-in functions.

2. **Relationship to Javascript:**  The entire `heap.h` file is fundamental to Javascript execution in V8. It manages the memory where Javascript objects reside. The allocation and garbage collection mechanisms directly impact how Javascript code runs.

3. **Code logic with input/output:**  The `IsYoungOrOld` function is a simple example of code logic.

4. **Common programming errors:**  Relating directly to this header file, a common error would be mismanaging external memory that V8 isn't aware of, leading to premature garbage collection and crashes if those external resources are still needed.

Now, let's synthesize these points into a concise summary of the provided code snippet.
这是 `v8/src/heap/heap.h` 源代码的第三部分，主要涵盖了堆内存管理的多个关键功能，特别是在垃圾回收（GC）、内存分配和内部状态管理方面。

**功能归纳:**

1. **垃圾回收控制与执行:**
   - 提供了多种触发和执行垃圾回收的函数，包括全局的 `MarkCompact` (全量标记压缩)，局部的 `MinorMarkSweep` (新生代标记清除) 和 `Scavenge` (新生代垃圾回收)。
   - 包含垃圾回收过程中的钩子函数，例如 `GarbageCollectionPrologue` 和 `GarbageCollectionEpilogue`，允许在 GC 前后执行特定的操作。
   - 提供了与垃圾回收相关的辅助功能，例如暂停和恢复并发线程 (`PauseConcurrentThreadsInClients`, `ResumeConcurrentThreadsInClients`)，以及进行堆验证 (`PerformHeapVerification`)。

2. **内存分配管理:**
   - 提供了多种内存分配的函数，例如 `AllocateRaw` (分配原始内存)，`AllocateMap` (分配 Map 对象)，`Allocate` (基于 Map 分配对象) 等。
   - 允许指定分配类型 (`AllocationType`) 和分配来源 (`AllocationOrigin`)。
   - 提供了处理分配失败和重试的机制 (`AllocateRawWith`)。

3. **堆大小和限制管理:**
   - 提供了获取和设置堆大小限制的函数，例如 `old_generation_allocation_limit`, `global_allocation_limit`, `max_old_generation_size` 等。
   - 允许动态调整新生代大小 (`ExpandNewSpaceSize`, `ReduceNewSpaceSize`)。
   - 提供了根据内存压力调整堆大小和触发 GC 的机制 (`ActivateMemoryReducerIfNeededOnMainThread`, `CollectGarbageOnMemoryPressure`)。

4. **内部对象和数据结构管理:**
   - 提供了创建特定内部对象的函数，例如只读对象 (`CreateReadOnlyObjects`) 和内部访问器信息对象 (`CreateInternalAccessorInfoObjects`)。
   - 涉及到管理弱引用 (`ProcessAllWeakReferences`) 和处理 NativeContexts (`ProcessNativeContexts`) 等。
   - 包含用于管理外部字符串表 (`UpdateYoungReferencesInExternalStringTable`, `UpdateReferencesInExternalStringTable`) 的函数。

5. **GC 统计和性能监控:**
   - 提供了记录和报告垃圾回收统计信息的函数 (`ReportStatisticsAfterGC`)。
   - 包含用于判断 Mark-Compact 是否低效的逻辑 (`IsIneffectiveMarkCompact`, `CheckIneffectiveMarkCompact`)。
   - 可以计算 Mutator 利用率 (`ComputeMutatorUtilization`)。

6. **其他辅助功能:**
   - 提供了刷新字符串缓存 (`FlushNumberStringCache`) 和记录调试信息的环形缓冲区 (`AddToRingBuffer`, `GetFromRingBuffer`)。
   - 包含用于处理内存压力回调 (`InvokeNearHeapLimitCallback`) 和增量标记回调 (`InvokeIncrementalMarkingPrologueCallbacks`, `InvokeIncrementalMarkingEpilogueCallbacks`) 的函数。

**关于其他问题:**

* **`.tq` 结尾:**  如果 `v8/src/heap/heap.h` 以 `.tq` 结尾，那么它确实会是一个 V8 Torque 源代码文件。Torque 是 V8 用于定义内置函数和类型的领域特定语言。

* **与 Javascript 的关系及示例:**  `v8/src/heap/heap.h` 中定义的功能与 Javascript 的运行息息相关。Javascript 对象的创建、内存管理和垃圾回收都由这里的代码控制。

   **Javascript 示例:**

   ```javascript
   let myObject = {}; //  当执行这行代码时，V8 的堆内存管理机制会被调用来为这个对象分配内存。

   // 假设一段时间后，myObject 不再被使用
   myObject = null;

   // V8 的垃圾回收器（由 heap.h 中的代码实现）会在适当的时候回收之前为 myObject 分配的内存。
   ```

* **代码逻辑推理 (假设输入与输出):**

   考虑 `IsYoungOrOld` 函数：

   ```c++
   static inline bool IsYoungOrOld(AllocationType allocation) {
     return AllocationType::kYoung == allocation ||
            AllocationType::kOld == allocation;
   }
   ```

   **假设输入:**
   - `allocation = AllocationType::kYoung`
   - `allocation = AllocationType::kOld`
   - `allocation = AllocationType::kMap`

   **输出:**
   - 当 `allocation` 为 `AllocationType::kYoung` 时，输出为 `true`。
   - 当 `allocation` 为 `AllocationType::kOld` 时，输出为 `true`。
   - 当 `allocation` 为 `AllocationType::kMap` 时，输出为 `false`。

* **用户常见的编程错误:**

   与这部分 `heap.h` 相关的常见编程错误通常发生在 C++ 扩展或嵌入 V8 的场景中，涉及手动管理外部内存，而 V8 的垃圾回收器并不知情。

   **C++ 示例:**

   ```c++
   #include <v8.h>
   #include <stdlib.h>

   void CreateExternalData(const v8::FunctionCallbackInfo<v8::Value>& args) {
     v8::Isolate* isolate = args.GetIsolate();
     v8::HandleScope handle_scope(isolate);

     // 分配一块外部内存，V8 的 GC 不知道这块内存的存在
     void* external_memory = malloc(1024);

     // 创建一个指向这块内存的外部数据对象
     v8::Local<v8::External> external = v8::External::New(isolate, external_memory);

     args.GetReturnValue().Set(external);
   }

   void FreeExternalData(const v8::FunctionCallbackInfo<v8::Value>& args) {
     if (args.Length() > 0 && args[0]->IsExternal()) {
       v8::Local<v8::External> external = args[0].As<v8::External>();
       void* external_memory = external->Value();
       // 手动释放外部内存
       free(external_memory); // 正确的做法
     }
   }

   int main() {
     // ... 初始化 V8 ...

     v8::Isolate::Scope isolate_scope(isolate);
     v8::HandleScope handle_scope(isolate);
     v8::Local<v8::Context> context = v8::Context::New(isolate);
     v8::Context::Scope context_scope(context);

     // ... 将 CreateExternalData 和 FreeExternalData 注册到 Javascript ...

     // 在 Javascript 中创建外部数据
     // let data = CreateExternalData();

     // 错误示例：如果在 Javascript 中释放对 data 的引用，但没有调用 FreeExternalData，
     // 那么 V8 的 GC 会回收 data 对象本身，但外部内存仍然泄漏。
     // data = null;

     // 正确的做法是在 Javascript 中不再使用 data 后，显式调用 FreeExternalData
     // FreeExternalData(data);

     // ... 清理 V8 ...
     return 0;
   }
   ```

   **常见错误:**  忘记在不再需要时手动释放通过 `malloc` 或其他方式分配的外部内存，导致内存泄漏。V8 的垃圾回收器只能管理 V8 堆内的对象，无法追踪和释放外部内存。

总的来说，这部分 `v8/src/heap/heap.h` 定义了 V8 堆内存管理的核心接口，控制着对象的生命周期和内存分配策略，是 V8 引擎高效运行的关键组成部分。

### 提示词
```
这是目录为v8/src/heap/heap.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/heap.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
ationType allocation) {
    return AllocationType::kYoung == allocation ||
           AllocationType::kOld == allocation;
  }

#define ROOT_ACCESSOR(type, name, CamelName) \
  inline void set_##name(Tagged<type> value);
  ROOT_LIST(ROOT_ACCESSOR)
#undef ROOT_ACCESSOR

  int NumberOfScavengeTasks();

  // Checks whether a global GC is necessary
  GarbageCollector SelectGarbageCollector(AllocationSpace space,
                                          GarbageCollectionReason gc_reason,
                                          const char** reason) const;

  // Make all LABs of all threads iterable.
  void MakeLinearAllocationAreasIterable();

  // Enables/Disables black allocation in shared LABs when not using black
  // allocated pages.
  void MarkSharedLinearAllocationAreasBlack();
  void UnmarkSharedLinearAllocationAreas();

  // Free shared LABs and reset freelists.
  void FreeSharedLinearAllocationAreasAndResetFreeLists();

  // Performs garbage collection in a safepoint.
  void PerformGarbageCollection(GarbageCollector collector,
                                GarbageCollectionReason gc_reason,
                                const char* collector_reason);

  void PerformHeapVerification();
  std::vector<Isolate*> PauseConcurrentThreadsInClients(
      GarbageCollector collector);
  void ResumeConcurrentThreadsInClients(std::vector<Isolate*> paused_clients);

  // For static-roots builds, pads the object to the required size.
  void StaticRootsEnsureAllocatedSize(DirectHandle<HeapObject> obj,
                                      int required);
  bool CreateEarlyReadOnlyMapsAndObjects();
  bool CreateImportantReadOnlyObjects();
  bool CreateLateReadOnlyNonJSReceiverMaps();
  bool CreateLateReadOnlyJSReceiverMaps();
  bool CreateReadOnlyObjects();

  void CreateInternalAccessorInfoObjects();
  void CreateInitialMutableObjects();

  enum class VerifyNoSlotsRecorded { kYes, kNo };

  // Creates a filler object in the specified memory area. This method is the
  // internal method used by all CreateFillerObjectAtXXX-methods.
  void CreateFillerObjectAtRaw(const WritableFreeSpace& free_space,
                               ClearFreedMemoryMode clear_memory_mode,
                               ClearRecordedSlots clear_slots_mode,
                               VerifyNoSlotsRecorded verify_no_slots_recorded);

  // Deopts all code that contains allocation instruction which are tenured or
  // not tenured. Moreover it clears the pretenuring allocation site statistics.
  void ResetAllAllocationSitesDependentCode(AllocationType allocation);

  // Evaluates local pretenuring for the old space and calls
  // ResetAllTenuredAllocationSitesDependentCode if too many objects died in
  // the old space.
  void EvaluateOldSpaceLocalPretenuring(uint64_t size_of_objects_before_gc);

  // Record statistics after garbage collection.
  void ReportStatisticsAfterGC();

  // Flush the number to string cache.
  void FlushNumberStringCache();

  void ActivateMemoryReducerIfNeededOnMainThread();

  void ShrinkOldGenerationAllocationLimitIfNotConfigured();

  double ComputeMutatorUtilization(const char* tag, double mutator_speed,
                                   double gc_speed);
  bool HasLowYoungGenerationAllocationRate();
  bool HasLowOldGenerationAllocationRate();
  bool HasLowEmbedderAllocationRate();

  enum class ResizeNewSpaceMode { kShrink, kGrow, kNone };
  ResizeNewSpaceMode ShouldResizeNewSpace();
  void ExpandNewSpaceSize();
  void ReduceNewSpaceSize();

  void PrintMaxMarkingLimitReached();
  void PrintMaxNewSpaceSizeReached();

  int NextStressMarkingLimit();

  void AddToRingBuffer(const char* string);
  void GetFromRingBuffer(char* buffer);

  void CompactRetainedMaps(Tagged<WeakArrayList> retained_maps);

  void CollectGarbageOnMemoryPressure();

  void EagerlyFreeExternalMemoryAndWasmCode();

  bool InvokeNearHeapLimitCallback();

  void InvokeIncrementalMarkingPrologueCallbacks();
  void InvokeIncrementalMarkingEpilogueCallbacks();

  // Casts a heap object to an InstructionStream, DCHECKs that the
  // inner_pointer is within the object, and returns the attached Code object.
  Tagged<GcSafeCode> GcSafeGetCodeFromInstructionStream(
      Tagged<HeapObject> instruction_stream, Address inner_pointer);
  // Returns the map of a HeapObject. Can be used during garbage collection,
  // i.e. it supports a forwarded map.
  Tagged<Map> GcSafeMapOfHeapObject(Tagged<HeapObject> object);

  // ===========================================================================
  // Actual GC. ================================================================
  // ===========================================================================

  // Code that should be run before and after each GC.  Includes
  // some reporting/verification activities when compiled with DEBUG set.
  void GarbageCollectionPrologue(GarbageCollectionReason gc_reason,
                                 const v8::GCCallbackFlags gc_callback_flags);
  void GarbageCollectionPrologueInSafepoint();
  void GarbageCollectionEpilogue(GarbageCollector collector);
  void GarbageCollectionEpilogueInSafepoint(GarbageCollector collector);

  // Performs a major collection in the whole heap.
  void MarkCompact();
  // Performs a minor collection of just the young generation.
  void MinorMarkSweep();

  // Code to be run before and after mark-compact.
  void MarkCompactPrologue();
  void MarkCompactEpilogue();

  // Performs a minor collection in new generation.
  void Scavenge();

  void UpdateYoungReferencesInExternalStringTable(
      ExternalStringTableUpdaterCallback updater_func);

  void UpdateReferencesInExternalStringTable(
      ExternalStringTableUpdaterCallback updater_func);

  void ProcessAllWeakReferences(WeakObjectRetainer* retainer);
  void ProcessNativeContexts(WeakObjectRetainer* retainer);
  void ProcessAllocationSites(WeakObjectRetainer* retainer);
  void ProcessDirtyJSFinalizationRegistries(WeakObjectRetainer* retainer);
  void ProcessWeakListRoots(WeakObjectRetainer* retainer);

  // ===========================================================================
  // GC statistics. ============================================================
  // ===========================================================================

  inline size_t OldGenerationSpaceAvailable() {
    uint64_t bytes = OldGenerationConsumedBytes();
    if (!v8_flags.external_memory_accounted_in_global_limit) {
      // TODO(chromium:42203776): When not accounting external memory properly
      // in the global limit, just add allocated external bytes towards the
      // regular old gen bytes. This is historic behavior.
      bytes += AllocatedExternalMemorySinceMarkCompact();
    }

    if (old_generation_allocation_limit() <= bytes) return 0;
    return old_generation_allocation_limit() - static_cast<size_t>(bytes);
  }

  void UpdateTotalGCTime(base::TimeDelta duration);

  bool IsIneffectiveMarkCompact(size_t old_generation_size,
                                double mutator_utilization);
  void CheckIneffectiveMarkCompact(size_t old_generation_size,
                                   double mutator_utilization);
  void ReportIneffectiveMarkCompactIfNeeded();

  inline void IncrementExternalBackingStoreBytes(ExternalBackingStoreType type,
                                                 size_t amount);

  inline void DecrementExternalBackingStoreBytes(ExternalBackingStoreType type,
                                                 size_t amount);

  // ===========================================================================
  // Growing strategy. =========================================================
  // ===========================================================================

  MemoryReducer* memory_reducer() { return memory_reducer_.get(); }

  // For some webpages NotifyLoadingEnded() is never called.
  // This constant limits the effect of load time on GC.
  // The value is arbitrary and chosen as the largest load time observed in
  // v8 browsing benchmarks.
  static const int kMaxLoadTimeMs = 7000;

  V8_EXPORT_PRIVATE bool ShouldOptimizeForLoadTime() const;
  void NotifyLoadingStarted();
  void NotifyLoadingEnded();
  void UpdateLoadStartTime();

  size_t old_generation_allocation_limit() const {
    return old_generation_allocation_limit_.load(std::memory_order_relaxed);
  }

  size_t global_allocation_limit() const {
    return global_allocation_limit_.load(std::memory_order_relaxed);
  }

  bool using_initial_limit() const {
    return using_initial_limit_.load(std::memory_order_relaxed);
  }

  void set_using_initial_limit(bool value) {
    using_initial_limit_.store(value, std::memory_order_relaxed);
  }

  size_t max_old_generation_size() const {
    return max_old_generation_size_.load(std::memory_order_relaxed);
  }

  size_t min_old_generation_size() const { return min_old_generation_size_; }

  // Sets max_old_generation_size_ and computes the new global heap limit from
  // it.
  void SetOldGenerationAndGlobalMaximumSize(size_t max_old_generation_size);

  // Sets allocation limits for both old generation and the global heap.
  void SetOldGenerationAndGlobalAllocationLimit(
      size_t new_old_generation_allocation_limit,
      size_t new_global_allocation_limit);

  void ResetOldGenerationAndGlobalAllocationLimit();

  bool always_allocate() { return always_allocate_scope_count_ != 0; }

  bool ShouldExpandOldGenerationOnSlowAllocation(LocalHeap* local_heap,
                                                 AllocationOrigin origin);
  bool ShouldExpandYoungGenerationOnSlowAllocation(size_t allocation_size);

  HeapGrowingMode CurrentHeapGrowingMode();

  double PercentToOldGenerationLimit() const;
  double PercentToGlobalMemoryLimit() const;
  enum class IncrementalMarkingLimit {
    kNoLimit,
    kSoftLimit,
    kHardLimit,
    kFallbackForEmbedderLimit
  };
  IncrementalMarkingLimit IncrementalMarkingLimitReached();

  bool ShouldStressCompaction() const;

  size_t GlobalMemoryAvailable();

  void RecomputeLimits(GarbageCollector collector, base::TimeTicks time);
  void RecomputeLimitsAfterLoadingIfNeeded();
  struct LimitsCompuatationResult {
    size_t old_generation_allocation_limit;
    size_t global_allocation_limit;
  };
  static LimitsCompuatationResult ComputeNewAllocationLimits(Heap* heap);

  // ===========================================================================
  // GC Tasks. =================================================================
  // ===========================================================================

  void ScheduleMinorGCTaskIfNeeded();
  V8_EXPORT_PRIVATE void StartMinorMSIncrementalMarkingIfNeeded();
  bool MinorMSSizeTaskTriggerReached() const;

  MinorGCJob* minor_gc_job() { return minor_gc_job_.get(); }

  // ===========================================================================
  // Allocation methods. =======================================================
  // ===========================================================================

  // Allocates a JS Map in the heap.
  V8_WARN_UNUSED_RESULT AllocationResult
  AllocateMap(AllocationType allocation_type, InstanceType instance_type,
              int instance_size,
              ElementsKind elements_kind = TERMINAL_FAST_ELEMENTS_KIND,
              int inobject_properties = 0);

  // Allocate an uninitialized object.  The memory is non-executable if the
  // hardware and OS allow.  This is the single choke-point for allocations
  // performed by the runtime and should not be bypassed (to extend this to
  // inlined allocations, use the Heap::DisableInlineAllocation() support).
  V8_WARN_UNUSED_RESULT V8_INLINE AllocationResult
  AllocateRaw(int size_in_bytes, AllocationType allocation,
              AllocationOrigin origin = AllocationOrigin::kRuntime,
              AllocationAlignment alignment = kTaggedAligned);

  // This method will try to allocate objects quickly (AllocationType::kYoung)
  // otherwise it falls back to a slower path indicated by the mode.
  enum AllocationRetryMode { kLightRetry, kRetryOrFail };
  template <AllocationRetryMode mode>
  V8_WARN_UNUSED_RESULT V8_INLINE Tagged<HeapObject> AllocateRawWith(
      int size, AllocationType allocation,
      AllocationOrigin origin = AllocationOrigin::kRuntime,
      AllocationAlignment alignment = kTaggedAligned);

  // Call AllocateRawWith with kRetryOrFail. Matches the method in LocalHeap.
  V8_WARN_UNUSED_RESULT inline Address AllocateRawOrFail(
      int size, AllocationType allocation,
      AllocationOrigin origin = AllocationOrigin::kRuntime,
      AllocationAlignment alignment = kTaggedAligned);

  // Allocates a heap object based on the map.
  V8_WARN_UNUSED_RESULT AllocationResult Allocate(DirectHandle<Map> map,
                                                  AllocationType allocation);

  // Allocates a partial map for bootstrapping.
  V8_WARN_UNUSED_RESULT AllocationResult
  AllocatePartialMap(InstanceType instance_type, int instance_size);

  void FinalizePartialMap(Tagged<Map> map);

  void set_force_oom(bool value) { force_oom_ = value; }
  void set_force_gc_on_next_allocation() {
    force_gc_on_next_allocation_ = true;
  }

  // Helper for IsPendingAllocation.
  inline bool IsPendingAllocationInternal(Tagged<HeapObject> object);

#ifdef DEBUG
  V8_EXPORT_PRIVATE void IncrementObjectCounters();
#endif  // DEBUG

  std::vector<Handle<NativeContext>> FindAllNativeContexts();
  std::vector<Tagged<WeakArrayList>> FindAllRetainedMaps();
  MemoryMeasurement* memory_measurement() { return memory_measurement_.get(); }

  AllocationType allocation_type_for_in_place_internalizable_strings() const {
    return allocation_type_for_in_place_internalizable_strings_;
  }

  bool IsStressingScavenge();

  void SetIsMarkingFlag(bool value);
  void SetIsMinorMarkingFlag(bool value);

  size_t PromotedSinceLastGC() {
    size_t old_generation_size = OldGenerationSizeOfObjects();
    return old_generation_size > old_generation_size_at_last_gc_
               ? old_generation_size - old_generation_size_at_last_gc_
               : 0;
  }

  ExternalMemoryAccounting external_memory_;

  // This can be calculated directly from a pointer to the heap; however, it is
  // more expedient to get at the isolate directly from within Heap methods.
  Isolate* isolate_ = nullptr;

  HeapAllocator* heap_allocator_ = nullptr;

  // These limits are initialized in Heap::ConfigureHeap based on the resource
  // constraints and flags.
  size_t code_range_size_ = 0;
  size_t max_semi_space_size_ = 0;
  size_t initial_semispace_size_ = 0;
  // Full garbage collections can be skipped if the old generation size
  // is below this threshold.
  size_t min_old_generation_size_ = 0;
  // If the old generation size exceeds this limit, then V8 will
  // crash with out-of-memory error.
  std::atomic<size_t> max_old_generation_size_{0};
  // TODO(mlippautz): Clarify whether this should take some embedder
  // configurable limit into account.
  size_t min_global_memory_size_ = 0;
  size_t max_global_memory_size_ = 0;

  size_t initial_max_old_generation_size_ = 0;
  size_t initial_max_old_generation_size_threshold_ = 0;
  size_t initial_old_generation_size_ = 0;

  // Before the first full GC the old generation allocation limit is considered
  // to be *not* configured (unless initial limits were provided by the
  // embedder, see below). In this mode V8 starts with a very large old
  // generation allocation limit initially. Minor GCs may then shrink this
  // initial limit down until the first full GC computes a proper old generation
  // allocation limit in Heap::RecomputeLimits. The old generation allocation
  // limit is then considered to be configured for all subsequent GCs. After the
  // first full GC this field is only ever reset for top context disposals.
  std::atomic<bool> using_initial_limit_ = true;

  // True if initial limits were provided by the embedder.
  bool initial_limit_overwritten_ = false;

  size_t maximum_committed_ = 0;
  size_t old_generation_capacity_after_bootstrap_ = 0;

  // Backing store bytes (array buffers and external strings).
  // Use uint64_t counter since the counter could overflow the 32-bit range
  // temporarily on 32-bit.
  std::atomic<uint64_t> backing_store_bytes_{0};

  // For keeping track of how much data has survived
  // scavenge since last new space expansion.
  size_t survived_since_last_expansion_ = 0;

  // This is not the depth of nested AlwaysAllocateScope's but rather a single
  // count, as scopes can be acquired from multiple tasks (read: threads).
  std::atomic<size_t> always_allocate_scope_count_{0};

  // Stores the memory pressure level that set by MemoryPressureNotification
  // and reset by a mark-compact garbage collection.
  std::atomic<v8::MemoryPressureLevel> memory_pressure_level_;

  std::vector<std::pair<v8::NearHeapLimitCallback, void*>>
      near_heap_limit_callbacks_;

  // For keeping track of context disposals.
  int contexts_disposed_ = 0;

  // Spaces owned by this heap through space_.
  NewSpace* new_space_ = nullptr;
  OldSpace* old_space_ = nullptr;
  CodeSpace* code_space_ = nullptr;
  SharedSpace* shared_space_ = nullptr;
  OldLargeObjectSpace* lo_space_ = nullptr;
  CodeLargeObjectSpace* code_lo_space_ = nullptr;
  NewLargeObjectSpace* new_lo_space_ = nullptr;
  SharedLargeObjectSpace* shared_lo_space_ = nullptr;
  ReadOnlySpace* read_only_space_ = nullptr;
  TrustedSpace* trusted_space_ = nullptr;
  SharedTrustedSpace* shared_trusted_space_ = nullptr;
  TrustedLargeObjectSpace* trusted_lo_space_ = nullptr;
  SharedTrustedLargeObjectSpace* shared_trusted_lo_space_ = nullptr;

  // Either pointer to owned shared spaces or pointer to unowned shared spaces
  // in another isolate.
  PagedSpace* shared_allocation_space_ = nullptr;
  OldLargeObjectSpace* shared_lo_allocation_space_ = nullptr;
  SharedTrustedSpace* shared_trusted_allocation_space_ = nullptr;
  SharedTrustedLargeObjectSpace* shared_trusted_lo_allocation_space_ = nullptr;

  // Map from the space id to the space.
  std::unique_ptr<Space> space_[LAST_SPACE + 1];

#ifdef V8_COMPRESS_POINTERS
  // The spaces in the ExternalPointerTable containing entries owned by objects
  // in this heap.
  ExternalPointerTable::Space young_external_pointer_space_;
  ExternalPointerTable::Space old_external_pointer_space_;
  // Likewise but for slots in host objects in ReadOnlySpace.
  ExternalPointerTable::Space read_only_external_pointer_space_;
  // Space in the ExternalPointerTable containing entries owned by objects in
  // this heap. The entries exclusively point to CppHeap objects.
  CppHeapPointerTable::Space cpp_heap_pointer_space_;
#endif  // V8_COMPRESS_POINTERS

#ifdef V8_ENABLE_SANDBOX
  // Likewise, but for the trusted pointer table.
  TrustedPointerTable::Space trusted_pointer_space_;

  // The space in the process-wide code pointer table managed by this heap.
  CodePointerTable::Space code_pointer_space_;

  // The space in the process-wide JSDispatchTable managed by this heap.
  JSDispatchTable::Space js_dispatch_table_space_;
#endif  // V8_ENABLE_SANDBOX

  LocalHeap* main_thread_local_heap_ = nullptr;

  std::atomic<HeapState> gc_state_{NOT_IN_GC};

  // Starts marking when stress_marking_percentage_% of the marking start limit
  // is reached.
  int stress_marking_percentage_ = 0;

  // Observer that can cause early scavenge start.
  StressScavengeObserver* stress_scavenge_observer_ = nullptr;

  // The maximum percent of the marking limit reached without causing marking.
  // This is tracked when specifying --fuzzer-gc-analysis.
  std::atomic<double> max_marking_limit_reached_ = 0.0;

  // How many mark-sweep collections happened.
  unsigned int ms_count_ = 0;

  // How many gc happened.
  unsigned int gc_count_ = 0;

  // The number of Mark-Compact garbage collections that are considered as
  // ineffective. See IsIneffectiveMarkCompact() predicate.
  int consecutive_ineffective_mark_compacts_ = 0;

  static const uintptr_t kMmapRegionMask = 0xFFFFFFFFu;
  uintptr_t mmap_region_base_ = 0;

  // For post mortem debugging.
  int remembered_unmapped_pages_index_ = 0;
  Address remembered_unmapped_pages_[kRememberedUnmappedPages];

  // Limit that triggers a global GC on the next (normally caused) GC.  This
  // is checked when we have already decided to do a GC to help determine
  // which collector to invoke, before expanding a paged space in the old
  // generation and on every allocation in large object space.
  std::atomic<size_t> old_generation_allocation_limit_{0};
  std::atomic<size_t> global_allocation_limit_{0};

  // Weak list heads, threaded through the objects.
  // List heads are initialized lazily and contain the undefined_value at start.
  // {native_contexts_list_} is an Address instead of an Object to allow the use
  // of atomic accessors.
  std::atomic<Address> native_contexts_list_;
  Tagged<Object> allocation_sites_list_ = Smi::zero();
  Tagged<Object> dirty_js_finalization_registries_list_ = Smi::zero();
  // Weak list tails.
  Tagged<Object> dirty_js_finalization_registries_list_tail_ = Smi::zero();

  GCCallbacks gc_prologue_callbacks_;
  GCCallbacks gc_epilogue_callbacks_;

  GetExternallyAllocatedMemoryInBytesCallback external_memory_callback_;

  base::SmallVector<v8::Isolate::UseCounterFeature, 8> deferred_counters_;

  size_t promoted_objects_size_ = 0;
  double promotion_ratio_ = 0.0;
  double promotion_rate_ = 0.0;
  size_t new_space_surviving_object_size_ = 0;
  size_t previous_new_space_surviving_object_size_ = 0;
  double new_space_surviving_rate_ = 0.0;
  int nodes_died_in_new_space_ = 0;
  int nodes_copied_in_new_space_ = 0;
  int nodes_promoted_ = 0;

  // Total time spent in GC.
  base::TimeDelta total_gc_time_ms_;

  // Last time a garbage collection happened.
  double last_gc_time_ = 0.0;

  std::unique_ptr<GCTracer> tracer_;
  std::unique_ptr<Sweeper> sweeper_;
  std::unique_ptr<MarkCompactCollector> mark_compact_collector_;
  std::unique_ptr<MinorMarkSweepCollector> minor_mark_sweep_collector_;
  std::unique_ptr<ScavengerCollector> scavenger_collector_;
  std::unique_ptr<ArrayBufferSweeper> array_buffer_sweeper_;

  std::unique_ptr<MemoryAllocator> memory_allocator_;
  std::unique_ptr<IncrementalMarking> incremental_marking_;
  std::unique_ptr<ConcurrentMarking> concurrent_marking_;
  std::unique_ptr<MemoryMeasurement> memory_measurement_;
  std::unique_ptr<MemoryReducer> memory_reducer_;
  std::unique_ptr<ObjectStats> live_object_stats_;
  std::unique_ptr<ObjectStats> dead_object_stats_;
  std::unique_ptr<MinorGCJob> minor_gc_job_;
  std::unique_ptr<AllocationObserver> minor_gc_task_observer_;
  std::unique_ptr<AllocationObserver> stress_concurrent_allocation_observer_;
  std::unique_ptr<AllocationTrackerForDebugging>
      allocation_tracker_for_debugging_;
  std::unique_ptr<EphemeronRememberedSet> ephemeron_remembered_set_;

  std::shared_ptr<v8::TaskRunner> task_runner_;

  // This object controls virtual space reserved for code on the V8 heap. This
  // is only valid for 64-bit architectures where kPlatformRequiresCodeRange.
  //
  // Owned by the isolate group when V8_COMPRESS_POINTERS, otherwise owned by
  // the heap.
#ifdef V8_COMPRESS_POINTERS
  CodeRange* code_range_ = nullptr;
#else
  std::unique_ptr<CodeRange> code_range_;
#endif

  // The process-wide virtual space reserved for trusted objects in the V8 heap.
  // Only used when the sandbox is enabled.
#if V8_ENABLE_SANDBOX
  TrustedRange* trusted_range_ = nullptr;
#endif

  // V8 configuration where V8 owns the heap which is either created or passed
  // in during Isolate initialization.
  std::unique_ptr<CppHeap> owning_cpp_heap_;
  // Deprecated API where the heap is owned by the embedder. This field is
  // always set, independent of which CppHeap configuration (owned, unowned) is
  // used. As soon as Isolate::AttachCppHeap() is removed, this field should
  // also be removed and we should exclusively rely on the owning version.
  v8::CppHeap* cpp_heap_ = nullptr;
  EmbedderRootsHandler* embedder_roots_handler_ =
      nullptr;  // Owned by the embedder.

  StackState embedder_stack_state_ = StackState::kMayContainHeapPointers;
  std::optional<EmbedderStackStateOrigin> embedder_stack_state_origin_;

  StrongRootsEntry* strong_roots_head_ = nullptr;
  base::Mutex strong_roots_mutex_;

  base::Mutex heap_expansion_mutex_;

  bool need_to_remove_stress_concurrent_allocation_observer_ = false;

  // This counter is increased before each GC and never reset.
  // To account for the bytes allocated since the last GC, use the
  // NewSpaceAllocationCounter() function.
  size_t new_space_allocation_counter_ = 0;

  // This counter is increased before each GC and never reset. To
  // account for the bytes allocated since the last GC, use the
  // OldGenerationAllocationCounter() function.
  size_t old_generation_allocation_counter_at_last_gc_ = 0;

  // The size of objects in old generation after the last MarkCompact GC.
  size_t old_generation_size_at_last_gc_{0};

  // The wasted bytes in old generation after the last MarkCompact GC.
  size_t old_generation_wasted_at_last_gc_{0};

  // The size of embedder memory after the last MarkCompact GC.
  size_t embedder_size_at_last_gc_ = 0;

  char trace_ring_buffer_[kTraceRingBufferSize];

  // If it's not full then the data is from 0 to ring_buffer_end_.  If it's
  // full then the data is from ring_buffer_end_ to the end of the buffer and
  // from 0 to ring_buffer_end_.
  bool ring_buffer_full_ = false;
  size_t ring_buffer_end_ = 0;

  // Flag is set when the heap has been configured.  The heap can be repeatedly
  // configured through the API until it is set up.
  bool configured_ = false;

  // Currently set GC flags that are respected by all GC components.
  GCFlags current_gc_flags_ = GCFlag::kNoFlags;
  // Currently set GC callback flags that are used to pass information between
  // the embedder and V8's GC.
  GCCallbackFlags current_gc_callback_flags_ =
      GCCallbackFlags::kNoGCCallbackFlags;

  std::unique_ptr<IsolateSafepoint> safepoint_;

  bool is_current_gc_forced_ = false;
  bool is_current_gc_for_heap_profiler_ = false;
  GarbageCollector current_or_last_garbage_collector_ =
      GarbageCollector::SCAVENGER;

  ExternalStringTable external_string_table_;

  const AllocationType allocation_type_for_in_place_internalizable_strings_;

  base::Mutex relocation_mutex_;

  std::unique_ptr<CollectionBarrier> collection_barrier_;

  int ignore_local_gc_requests_depth_ = 0;

  int gc_callbacks_depth_ = 0;

  bool deserialization_complete_ = false;

  int max_regular_code_object_size_ = 0;

  bool inline_allocation_enabled_ = true;

  int pause_allocation_observers_depth_ = 0;

  // Used for testing purposes.
  bool force_oom_ = false;
  bool force_gc_on_next_allocation_ = false;
  bool delay_sweeper_tasks_for_testing_ = false;

  std::vector<HeapObjectAllocationTracker*> allocation_trackers_;

  bool is_finalization_registry_cleanup_task_posted_ = false;

  MarkingState marking_state_;
  NonAtomicMarkingState non_atomic_marking_state_;

  PretenuringHandler pretenuring_handler_;

  // This field is used only when not running with MinorMS.
  ResizeNewSpaceMode resize_new_space_mode_ = ResizeNewSpaceMode::kNone;

  std::unique_ptr<MemoryBalancer> mb_;

  // Time that the embedder started loading resources.
  std::atomic<double> load_start_time_ms_{0};

  bool update_allocation_limits_after_loading_ = false;
  // Full GC may trigger during loading due to overshooting allocation limits.
  // In such cases we may want to update the limits again once loading is
  // actually finished.
  bool is_full_gc_during_loading_ = false;

  // Classes in "heap" can be friends.
  friend class ActivateMemoryReducerTask;
  friend class AlwaysAllocateScope;
  friend class ArrayBufferCollector;
  friend class ArrayBufferSweeper;
  friend class ConcurrentMarking;
  friend class ConservativeTracedHandlesMarkingVisitor;
  friend class CppHeap;
  friend class EmbedderStackStateScope;
  friend class EvacuateVisitorBase;
  friend class GCCallbacksScope;
  friend class GCTracer;
  friend class HeapAllocator;
  friend class HeapObjectIterator;
  friend class HeapVerifier;
  friend class IgnoreLocalGCRequests;
  friend class IncrementalMarking;
  friend class IncrementalMarkingJob;
  friend class LargeObjectSpace;
  friend class LocalHeap;
  friend class MarkingBarrier;
  friend class OldLargeObjectSpace;
  template <typename ConcreteVisitor>
  friend class MarkingVisitorBase;
  friend class MarkCompactCollector;
  friend class MemoryBalancer;
  friend class MinorGCJob;
  friend class MinorGCTaskObserver;
  friend class MinorMarkSweepCollector;
  friend class MinorMSIncrementalMarkingTaskObserver;
  friend class NewLargeObjectSpace;
  friend class NewSpace;
  friend class ObjectStatsCollector;
  friend class PageMetadata;
  friend class PagedNewSpaceAllocatorPolicy;
  friend class PagedSpaceAllocatorPolicy;
  friend class PagedSpaceBase;
  friend class PagedSpaceForNewSpace;
  friend class PauseAllocationObserversScope;
  friend class PretenuringHandler;
  friend class ReadOnlyRoots;
  friend class DisableConservativeStackScanningScopeForTesting;
  friend class Scavenger;
  friend class ScavengerCollector;
  friend class ScheduleMinorGCTaskObserver;
  friend class SemiSpaceNewSpace;
  friend class SemiSpaceNewSpaceAllocatorPolicy;
  friend class StressConcurrentAllocationObserver;
  friend class Space;
  friend class SpaceWithLinearArea;
  friend class Sweeper;
  friend class UnifiedHeapMarkingState;
  friend class heap::TestMemoryAllocatorScope;

  // The allocator interface.
  friend class Factory;
  friend class LocalFactory;
  template <typename IsolateT>
  friend class Deserializer;

  // The Isolate constructs us.
  friend class Isolate;

  // Used in cctest.
  friend class heap::HeapTester;
  FRIEND_TEST(SpacesTest, InlineAllocationObserverCadence);
  FRIEND_TEST(SpacesTest, AllocationObserver);
  friend class HeapInternalsBase;
};

#define DECL_RIGHT_TRIM(T)                                        \
  extern template EXPORT_TEMPLATE_DECLARE(V8_EXPORT_PRIVATE) void \
  Heap::RightTrimArray<T>(Tagged<T> object, int new_capacity,     \
                          int old_capacity);
RIGHT_TRIMMABLE_ARRAY_LIST(DECL_RIGHT_TRIM)
#undef DECL_RIGHT_TRIM

class HeapStats {
 public:
  static const int kStartMarker = 0xDECADE00;
  static const int kEndMarker = 0xDECADE01;

  intptr_t* start_marker;                  //  0
  size_t* ro_space_size;                   //  1
  size_t* ro_space_capacity;               //  2
  size_t* new_space_size;                  //  3
  size_t* new_space_capacity;              //  4
  size_t* old_space_size;                  //  5
  size_t* old_space_capacity;              //  6
  size_t* code_space_size;                 //  7
  size_t* code_space_capacity;             //  8
  size_t* map_space_size;                  //  9
  size_t* map_space_capacity;              // 10
  size_t* lo_space_size;                   // 11
  size_t* code_lo_space_size;              // 12
  size_t* global_handle_count;             // 13
  size_t* weak_global_handle_count;        // 14
  size_t* pending_global_handle_count;     // 15
  size_t* near_death_global_handle_count;  // 16
  size_t* free_global_handle_count;        // 17
  size_t* memory_allocator_size;           // 18
  size_t* memory_allocator_capacity;       // 19
  size_t* malloced_memory;                 // 20
  size_t* malloced_peak_memory;            // 21
  size_t* objects_per_type;                // 22
  size_t* size_per_type;                   // 23
  int* os_error;                           // 24
  char* last_few_messages;                 // 25
  char* js_stacktrace;                     // 26
  intptr_t* end_marker;                    // 27
};

// Disables GC for all allocations. It should not be used
// outside heap, deserializer, and isolate bootstrap.
// Use AlwaysAllocateScopeForTesting in tests.
class V8_NODISCARD AlwaysAllocateScope {
 public:
  inline ~AlwaysAllocateScope();

 private:
  friend class AlwaysAllocateScopeForTesting;
  friend class Evacuator;
  friend class Heap;
  friend class HeapAllocator;
  friend class Isolate;
  // TODO(1445003): Remove this after investigating the crash.
  friend class GlobalBackingStoreRegistry;

  explicit inline AlwaysAllocateScope(Heap* heap);
  Heap* heap_;
};

class V8_NODISCARD GCCallbacksScope final {
 public:
  explicit GCCallbacksScope(Heap* heap);
  ~GCCallbacksScope();

  bool CheckReenter() const;

 private:
  Heap* const heap_;
};

class V8_NODISCARD AlwaysAllocateScopeForTesting {
 public:
  explicit inline AlwaysAllocateScopeForTesting
```