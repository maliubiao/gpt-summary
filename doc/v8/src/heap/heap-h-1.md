Response:
The user wants a summary of the functionality of the provided C++ header file `v8/src/heap/heap.h`.

To achieve this, I need to analyze the public methods and data members declared in the header. I will categorize these functionalities and provide a concise description for each category.

Here's a breakdown of the functionalities I can identify:

1. **Garbage Collection:**  Methods for triggering and managing different types of garbage collection (major, minor, shared, incremental, concurrent).
2. **Memory Management:**  Methods for tracking memory usage, setting heap limits, querying heap statistics, and interacting with external memory.
3. **Object Iteration:** Methods for iterating over different categories of objects in the heap (roots, weak roots, smis, builtins, stack roots).
4. **Remembered Set:**  Methods for managing the remembered set, which is used for incremental garbage collection.
5. **Incremental Marking:** Methods for starting, finalizing, and managing incremental marking.
6. **Concurrent Marking:** Methods for accessing and interacting with the concurrent marking mechanism.
7. **Object Layout Changes:** Methods for notifying the garbage collector about changes in object layout and size.
8. **Deoptimization Support:** Methods related to deoptimization, potentially setting offsets for deoptimization targets.
9. **Unified Heap (C++) Support:** Methods for attaching and detaching C++ heaps.
10. **Stack Information:** Methods for setting and retrieving stack information.
11. **Embedder Roots:** Methods for handling embedder-specific roots.
12. **External String Table:** Methods for registering, updating, and finalizing external strings.
13. **Space Checking:** Methods for checking the memory space where an object resides.
14. **Object Statistics:** Methods for tracking and retrieving statistics about object types and counts.
15. **Code Statistics:** Methods for collecting statistics about code objects.
16. **GC Statistics:** Methods for accessing various garbage collection related statistics (memory limits, committed memory, object sizes, etc.).
17. **GC Callbacks:** Methods for adding and removing callbacks that are invoked before and after garbage collection.
18. **Allocation:** Methods for allocating memory and creating filler objects.
19. **Allocation Tracking:** Methods for observing and tracking object allocations.
20. **Stack Frame Support:** Methods for finding Code objects from memory addresses.
21. **Sweeping:** Methods for managing the sweeping phase of garbage collection.
22. **Debugging and Verification:** Methods (often under `#ifdef DEBUG`) for verifying heap integrity and printing statistics.
23. **Utility Methods:** Miscellaneous utility functions like getting random memory addresses and calculating cache sizes.
24. **Internal State Access:**  Methods for accessing internal state like marking state and pretenuring handler.

Given that this is part 2 of 4, I should focus on the functionality covered in this specific snippet and acknowledge that it's a continuation.
这是 `v8/src/heap/heap.h` 文件的第二部分，它延续了第一部分关于 V8 堆管理的功能定义。 总结一下这部分代码的功能：

**核心功能延续与扩展：**

这部分代码继续定义了 V8 引擎中关于堆内存管理的核心功能，主要集中在以下几个方面：

1. **垃圾回收 (Garbage Collection) 的具体操作和控制：**
   - 提供了触发不同类型垃圾回收的函数，包括针对共享堆的回收 (`CollectGarbageShared`) 和从其他线程请求回收 (`CollectGarbageFromAnyThread`)。
   - 引入了处理外部内存压力的机制 (`HandleExternalMemoryInterrupt`)，当外部内存压力过大时，会触发垃圾回收。
   - 允许设置一个回调函数，用于获取外部已分配内存的大小 (`SetGetExternallyAllocatedMemoryInBytesCallback`)。
   - 定义了处理通过栈保护机制请求垃圾回收的函数 (`HandleGCRequest`)。

2. **根对象遍历 (Iterate Roots)：**
   - 提供了一系列用于遍历堆中不同类型根对象的函数，这些根对象是垃圾回收的起始点，包括强根、弱根、SMI 根、全局句柄、内置对象和栈上的根。
   - 区分了主 Isolate 和客户端 Isolate 的根遍历模式 (`IterateRootsMode`)。
   - 特别指出，这些方法不遍历只读根，只读根的遍历通常用于序列化、反序列化或堆验证。

3. **记录集 API (Remembered Set API)：**
   - 提供了用于查询增量标记状态的接口 (`IsMarkingFlagAddress`, `IsMinorMarkingFlagAddress`)。
   - 允许清除指定范围内的已记录槽 (`ClearRecordedSlotRange`)。
   - 提供了从代码中向记录集插入条目的静态方法 (`InsertIntoRememberedSetFromCode`)。
   - 在调试模式下，可以验证指定范围内没有已记录的槽 (`VerifySlotRangeHasNoRecordedSlots`)。

4. **增量标记 API (Incremental Marking API)：**
   - 提供了启动增量标记的函数 (`StartIncrementalMarking`, `StartIncrementalMarkingOnInterrupt`, `StartIncrementalMarkingIfAllocationLimitIsReached`)，允许指定垃圾回收标志和原因。
   - 允许同步完成增量标记 (`FinalizeIncrementalMarkingAtomically`)。
   - 提供了完成不同类型清理（Full 和 Young）的函数 (`CompleteSweepingFull`, `CompleteSweepingYoung`)。
   - 确保特定对象的页面的清理已完成 (`EnsureSweepingCompletedForObject`)。
   - 提供了访问 `IncrementalMarking` 对象的接口。

5. **并发标记 API (Concurrent Marking API)：**
   - 提供了访问 `ConcurrentMarking` 对象的接口.
   - 定义了当对象布局发生潜在不安全更改时通知垃圾回收器的函数 (`NotifyObjectLayoutChange`, `NotifyObjectLayoutChangeDone`)，以便进行必要的同步。
   - 提供了当对象大小发生变化时通知垃圾回收器的函数 (`NotifyObjectSizeChange`)。

**与 JavaScript 功能的关系：**

这些功能直接影响 JavaScript 的内存管理和执行效率。例如：

- **垃圾回收机制** 确保不再被引用的 JavaScript 对象能够被回收，释放内存，防止内存泄漏，从而保证 JavaScript 程序的稳定运行。
- **根对象遍历** 是垃圾回收的第一步，识别所有可达的对象，这是判断对象是否可以回收的基础。
- **记录集和增量/并发标记** 是为了优化垃圾回收过程，减少主线程的停顿时间，提高 JavaScript 应用的响应速度。 当 JavaScript 代码创建大量对象或者对象之间存在复杂的引用关系时，高效的垃圾回收机制尤为重要。

**代码逻辑推理 (示例):**

假设有一个 JavaScript 变量 `myObject`，它引用了一个很大的对象，并且在某个时刻，这个变量不再被使用：

**假设输入:**

1. `myObject` 不再被任何 JavaScript 代码引用。
2. 垃圾回收器开始执行。

**输出:**

1. 通过**根对象遍历**，`myObject` 引用的对象将不再被标记为可达。
2. 在垃圾回收的**清理**阶段，`myObject` 引用的对象所占用的内存将被释放，以便后续分配新的对象。

**用户常见的编程错误：**

1. **意外的全局变量:** 在 JavaScript 中创建未声明的变量会使其成为全局变量，全局变量通常在页面关闭前不会被回收，容易造成内存泄漏。

   ```javascript
   function myFunction() {
     // 错误：没有使用 var、let 或 const 声明
     myGlobalVar = { data: 'some data' };
   }
   myFunction();
   ```

2. **闭包引起的内存泄漏:** 当闭包捕获了外部作用域的变量，并且这个闭包长期存在时，即使外部作用域已经不再需要这些变量，它们也可能无法被回收。

   ```javascript
   function createCounter() {
     let count = 0;
     return function() {
       console.log(++count);
     };
   }

   const counter = createCounter();
   // 如果 counter 长期存在，那么 count 变量也会一直存在，即使外部的 createCounter 函数已经执行完毕。
   ```

3. **忘记取消事件监听器或定时器:** 如果创建了事件监听器或定时器，但在不再需要时没有取消它们，这些监听器和定时器可能会持有对其他对象的引用，阻止这些对象被回收。

   ```javascript
   const myElement = document.getElementById('myElement');
   myElement.addEventListener('click', function() {
     // ... some action ...
   });

   // 如果 myElement 被移除但监听器没有被移除，可能会导致内存泄漏。
   ```

**归纳一下这部分的功能:**

总而言之，`v8/src/heap/heap.h` 的第二部分主要定义了 V8 引擎中负责**垃圾回收的具体执行流程和优化策略**的接口。它涵盖了触发和控制不同类型的垃圾回收、遍历堆内存中的根对象以确定可达性、以及通过记录集、增量标记和并发标记等技术来提升垃圾回收效率，减少对 JavaScript 执行的影响。 这些机制是 V8 引擎高效管理内存，防止内存泄漏，并提供流畅 JavaScript 执行体验的关键组成部分。

### 提示词
```
这是目录为v8/src/heap/heap.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/heap.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
callback_flags = kNoGCCallbackFlags);

  // Performs garbage collection operation for the shared heap.
  V8_EXPORT_PRIVATE bool CollectGarbageShared(
      LocalHeap* local_heap, GarbageCollectionReason gc_reason);

  // Requests garbage collection from some other thread.
  V8_EXPORT_PRIVATE bool CollectGarbageFromAnyThread(
      LocalHeap* local_heap,
      GarbageCollectionReason gc_reason =
          GarbageCollectionReason::kBackgroundAllocationFailure);

  // Reports and external memory pressure event, either performs a major GC or
  // completes incremental marking in order to free external resources.
  void HandleExternalMemoryInterrupt();

  using GetExternallyAllocatedMemoryInBytesCallback =
      v8::Isolate::GetExternallyAllocatedMemoryInBytesCallback;

  void SetGetExternallyAllocatedMemoryInBytesCallback(
      GetExternallyAllocatedMemoryInBytesCallback callback) {
    external_memory_callback_ = callback;
  }

  // Invoked when GC was requested via the stack guard.
  void HandleGCRequest();

  // ===========================================================================
  // Iterators. ================================================================
  // ===========================================================================

  // In the case of shared GC, kMainIsolate is used for the main isolate and
  // kClientIsolate for the (other) client isolates.
  enum class IterateRootsMode { kMainIsolate, kClientIsolate };

  // None of these methods iterate over the read-only roots. To do this use
  // ReadOnlyRoots::Iterate. Read-only root iteration is not necessary for
  // garbage collection and is usually only performed as part of
  // (de)serialization or heap verification.

  // Iterates over the strong roots and the weak roots.
  void IterateRoots(
      RootVisitor* v, base::EnumSet<SkipRoot> options,
      IterateRootsMode roots_mode = IterateRootsMode::kMainIsolate);
  void IterateRootsIncludingClients(RootVisitor* v,
                                    base::EnumSet<SkipRoot> options);

  // Iterates over entries in the smi roots list.  Only interesting to the
  // serializer/deserializer, since GC does not care about smis.
  void IterateSmiRoots(RootVisitor* v);
  // Iterates over weak string tables.
  void IterateWeakRoots(RootVisitor* v, base::EnumSet<SkipRoot> options);
  void IterateWeakGlobalHandles(RootVisitor* v);
  void IterateBuiltins(RootVisitor* v);

  void IterateStackRoots(RootVisitor* v);

  void IterateConservativeStackRoots(
      RootVisitor* v,
      IterateRootsMode roots_mode = IterateRootsMode::kMainIsolate);

  // ===========================================================================
  // Remembered set API. =======================================================
  // ===========================================================================

  // Used for query incremental marking status in generated code.
  uint8_t* IsMarkingFlagAddress();
  uint8_t* IsMinorMarkingFlagAddress();

  void ClearRecordedSlotRange(Address start, Address end);
  static int InsertIntoRememberedSetFromCode(MutablePageMetadata* chunk,
                                             size_t slot_offset);

#ifdef DEBUG
  void VerifySlotRangeHasNoRecordedSlots(Address start, Address end);
#endif

  // ===========================================================================
  // Incremental marking API. ==================================================
  // ===========================================================================

  GCFlags GCFlagsForIncrementalMarking() {
    return ShouldOptimizeForMemoryUsage() ? GCFlag::kReduceMemoryFootprint
                                          : GCFlag::kNoFlags;
  }

  // Starts incremental marking assuming incremental marking is currently
  // stopped.
  V8_EXPORT_PRIVATE void StartIncrementalMarking(
      GCFlags gc_flags, GarbageCollectionReason gc_reason,
      GCCallbackFlags gc_callback_flags = GCCallbackFlags::kNoGCCallbackFlags,
      GarbageCollector collector = GarbageCollector::MARK_COMPACTOR);

  V8_EXPORT_PRIVATE void StartIncrementalMarkingOnInterrupt();

  V8_EXPORT_PRIVATE void StartIncrementalMarkingIfAllocationLimitIsReached(
      LocalHeap* local_heap, GCFlags gc_flags,
      GCCallbackFlags gc_callback_flags = GCCallbackFlags::kNoGCCallbackFlags);

  // Synchronously finalizes incremental marking.
  V8_EXPORT_PRIVATE void FinalizeIncrementalMarkingAtomically(
      GarbageCollectionReason gc_reason);

  V8_EXPORT_PRIVATE void CompleteSweepingFull();
  void CompleteSweepingYoung();

  // Ensures that sweeping is finished for that object's page.
  void EnsureSweepingCompletedForObject(Tagged<HeapObject> object);

  IncrementalMarking* incremental_marking() const {
    return incremental_marking_.get();
  }

  // ===========================================================================
  // Concurrent marking API. ===================================================
  // ===========================================================================

  ConcurrentMarking* concurrent_marking() const {
    return concurrent_marking_.get();
  }

  // The runtime uses this function to notify potentially unsafe object layout
  // changes that require special synchronization with the concurrent marker.
  // By default recorded slots in the object are invalidated. Pass
  // InvalidateRecordedSlots::kNo if this is not necessary or to perform this
  // manually.
  // If the object contains external pointer slots, then these need to be
  // invalidated as well if a GC marker may have observed them previously. To
  // do this, pass HasExernalPointerSlots::kYes.
  void NotifyObjectLayoutChange(
      Tagged<HeapObject> object, const DisallowGarbageCollection&,
      InvalidateRecordedSlots invalidate_recorded_slots,
      InvalidateExternalPointerSlots invalidate_external_pointer_slots,
      int new_size = 0);
  V8_EXPORT_PRIVATE static void NotifyObjectLayoutChangeDone(
      Tagged<HeapObject> object);

  // The runtime uses this function to inform the GC of object size changes. The
  // GC will fill this area with a filler object and might clear recorded slots
  // in that area.
  void NotifyObjectSizeChange(Tagged<HeapObject>, int old_size, int new_size,
                              ClearRecordedSlots clear_recorded_slots);

  // ===========================================================================
  // Deoptimization support API. ===============================================
  // ===========================================================================

  // Setters for code offsets of well-known deoptimization targets.
  void SetConstructStubCreateDeoptPCOffset(int pc_offset);
  void SetConstructStubInvokeDeoptPCOffset(int pc_offset);
  void SetDeoptPCOffsetAfterAdaptShadowStack(int pc_offset);
  void SetInterpreterEntryReturnPCOffset(int pc_offset);

  void DeoptMarkedAllocationSites();

  // ===========================================================================
  // Unified heap (C++) support. ===============================================
  // ===========================================================================

  V8_EXPORT_PRIVATE void AttachCppHeap(v8::CppHeap* cpp_heap);
  V8_EXPORT_PRIVATE void DetachCppHeap();

  v8::CppHeap* cpp_heap() const { return cpp_heap_; }

  std::optional<StackState> overridden_stack_state() const;

  // Set stack information from the stack of the current thread.
  V8_EXPORT_PRIVATE void SetStackStart();

  // Stack information of the main thread.
  V8_EXPORT_PRIVATE ::heap::base::Stack& stack();
  V8_EXPORT_PRIVATE const ::heap::base::Stack& stack() const;

  // ===========================================================================
  // Embedder roots optimizations. =============================================
  // ===========================================================================

  V8_EXPORT_PRIVATE
  void SetEmbedderRootsHandler(EmbedderRootsHandler* handler);

  EmbedderRootsHandler* GetEmbedderRootsHandler() const;

  // ===========================================================================
  // External string table API. ================================================
  // ===========================================================================

  // Registers an external string.
  inline void RegisterExternalString(Tagged<String> string);

  // Called when a string's resource is changed. The size of the payload is sent
  // as argument of the method.
  V8_EXPORT_PRIVATE void UpdateExternalString(Tagged<String> string,
                                              size_t old_payload,
                                              size_t new_payload);

  // Finalizes an external string by deleting the associated external
  // data and clearing the resource pointer.
  inline void FinalizeExternalString(Tagged<String> string);

  static Tagged<String> UpdateYoungReferenceInExternalStringTableEntry(
      Heap* heap, FullObjectSlot pointer);

  // ===========================================================================
  // Methods checking/returning the space of a given object/address. ===========
  // ===========================================================================

  // Returns whether the object resides in new space.
  static inline bool InFromPage(Tagged<Object> object);
  static inline bool InFromPage(Tagged<MaybeObject> object);
  static inline bool InFromPage(Tagged<HeapObject> heap_object);
  static inline bool InToPage(Tagged<Object> object);
  static inline bool InToPage(Tagged<MaybeObject> object);
  static inline bool InToPage(Tagged<HeapObject> heap_object);

  // Returns whether the object resides in old space.
  inline bool InOldSpace(Tagged<Object> object);

  // Checks whether an address/object is in the non-read-only heap (including
  // auxiliary area and unused area). Use IsValidHeapObject if checking both
  // heaps is required.
  V8_EXPORT_PRIVATE bool Contains(Tagged<HeapObject> value) const;
  // Same as above, but checks whether the object resides in any of the code
  // spaces.
  V8_EXPORT_PRIVATE bool ContainsCode(Tagged<HeapObject> value) const;

  // Checks whether an address/object is in the non-read-only heap (including
  // auxiliary area and unused area). Use IsValidHeapObject if checking both
  // heaps is required.
  V8_EXPORT_PRIVATE bool SharedHeapContains(Tagged<HeapObject> value) const;

  // Returns whether the object must be in the shared old space.
  V8_EXPORT_PRIVATE bool MustBeInSharedOldSpace(Tagged<HeapObject> value);

  // Checks whether an address/object in a space.
  // Currently used by tests, serialization and heap verification only.
  V8_EXPORT_PRIVATE bool InSpace(Tagged<HeapObject> value,
                                 AllocationSpace space) const;

  // Slow methods that can be used for verification as they can also be used
  // with off-heap Addresses.
  V8_EXPORT_PRIVATE bool InSpaceSlow(Address addr, AllocationSpace space) const;

  static inline Heap* FromWritableHeapObject(Tagged<HeapObject> obj);

  // ===========================================================================
  // Object statistics tracking. ===============================================
  // ===========================================================================

  // Returns the number of buckets used by object statistics tracking during a
  // major GC. Note that the following methods fail gracefully when the bounds
  // are exceeded though.
  size_t NumberOfTrackedHeapObjectTypes();

  // Returns object statistics about count and size at the last major GC.
  // Objects are being grouped into buckets that roughly resemble existing
  // instance types.
  size_t ObjectCountAtLastGC(size_t index);
  size_t ObjectSizeAtLastGC(size_t index);

  // Retrieves names of buckets used by object statistics tracking.
  bool GetObjectTypeName(size_t index, const char** object_type,
                         const char** object_sub_type);

  // The total number of native contexts object on the heap.
  size_t NumberOfNativeContexts();
  // The total number of native contexts that were detached but were not
  // garbage collected yet.
  size_t NumberOfDetachedContexts();

  // ===========================================================================
  // Code statistics.
  // ==========================================================
  // ===========================================================================

  // Collect code (Code and BytecodeArray objects) statistics.
  void CollectCodeStatistics();

  // ===========================================================================
  // GC statistics. ============================================================
  // ===========================================================================

  // Returns the maximum amount of memory reserved for the heap.
  V8_EXPORT_PRIVATE size_t MaxReserved() const;
  size_t MaxSemiSpaceSize() { return max_semi_space_size_; }
  size_t InitialSemiSpaceSize() { return initial_semispace_size_; }
  size_t MaxOldGenerationSize() { return max_old_generation_size(); }

  // Limit on the max old generation size imposed by the underlying allocator.
  V8_EXPORT_PRIVATE static size_t AllocatorLimitOnMaxOldGenerationSize();

  V8_EXPORT_PRIVATE static size_t HeapSizeFromPhysicalMemory(
      uint64_t physical_memory);
  V8_EXPORT_PRIVATE static void GenerationSizesFromHeapSize(
      size_t heap_size, size_t* young_generation_size,
      size_t* old_generation_size);
  V8_EXPORT_PRIVATE static size_t YoungGenerationSizeFromOldGenerationSize(
      size_t old_generation_size);
  V8_EXPORT_PRIVATE static size_t YoungGenerationSizeFromSemiSpaceSize(
      size_t semi_space_size);
  V8_EXPORT_PRIVATE static size_t SemiSpaceSizeFromYoungGenerationSize(
      size_t young_generation_size);
  V8_EXPORT_PRIVATE static size_t MinYoungGenerationSize();
  V8_EXPORT_PRIVATE static size_t MinOldGenerationSize();
  V8_EXPORT_PRIVATE static size_t MaxOldGenerationSize(
      uint64_t physical_memory);

  // Returns the capacity of the heap in bytes w/o growing. Heap grows when
  // more spaces are needed until it reaches the limit.
  size_t Capacity();

  // Returns the capacity of the old generation.
  V8_EXPORT_PRIVATE size_t OldGenerationCapacity() const;

  base::Mutex* heap_expansion_mutex() { return &heap_expansion_mutex_; }

  // Returns the amount of memory currently held alive by the pool.
  size_t CommittedMemoryOfPool();

  // Returns the amount of memory currently committed for the heap.
  size_t CommittedMemory();

  // Returns the amount of memory currently committed for the old space.
  size_t CommittedOldGenerationMemory();

  // Returns the amount of executable memory currently committed for the heap.
  size_t CommittedMemoryExecutable();

  // Returns the amount of physical memory currently committed for the heap.
  size_t CommittedPhysicalMemory();

  // Returns the maximum amount of memory ever committed for the heap.
  size_t MaximumCommittedMemory() { return maximum_committed_; }

  // Updates the maximum committed memory for the heap. Should be called
  // whenever a space grows.
  void UpdateMaximumCommitted();

  // Returns the available bytes in space w/o growing.
  // Heap doesn't guarantee that it can allocate an object that requires
  // all available bytes. Check MaxHeapObjectSize() instead.
  size_t Available();

  // Returns size of all objects residing in the heap.
  V8_EXPORT_PRIVATE size_t SizeOfObjects();

  // Returns size of all global handles in the heap.
  V8_EXPORT_PRIVATE size_t TotalGlobalHandlesSize();

  // Returns size of all allocated/used global handles in the heap.
  V8_EXPORT_PRIVATE size_t UsedGlobalHandlesSize();

  void UpdateSurvivalStatistics(int start_new_space_size);

  inline void IncrementPromotedObjectsSize(size_t object_size) {
    promoted_objects_size_ += object_size;
  }
  inline size_t promoted_objects_size() { return promoted_objects_size_; }

  inline void IncrementNewSpaceSurvivingObjectSize(size_t object_size) {
    new_space_surviving_object_size_ += object_size;
  }
  inline size_t new_space_surviving_object_size() {
    return new_space_surviving_object_size_;
  }

  inline size_t SurvivedYoungObjectSize() {
    return promoted_objects_size_ + new_space_surviving_object_size_;
  }

  inline void IncrementNodesDiedInNewSpace(int count) {
    nodes_died_in_new_space_ += count;
  }

  inline void IncrementNodesCopiedInNewSpace() { nodes_copied_in_new_space_++; }

  inline void IncrementNodesPromoted() { nodes_promoted_++; }

  inline void IncrementYoungSurvivorsCounter(size_t survived) {
    survived_since_last_expansion_ += survived;
  }

  V8_EXPORT_PRIVATE size_t NewSpaceAllocationCounter() const;

  void SetNewSpaceAllocationCounterForTesting(size_t new_value) {
    new_space_allocation_counter_ = new_value;
  }

  void UpdateOldGenerationAllocationCounter() {
    old_generation_allocation_counter_at_last_gc_ =
        OldGenerationAllocationCounter();
  }

  size_t OldGenerationAllocationCounter() {
    return old_generation_allocation_counter_at_last_gc_ +
           PromotedSinceLastGC();
  }

  size_t EmbedderAllocationCounter() const;

  // This should be used only for testing.
  void set_old_generation_allocation_counter_at_last_gc(size_t new_value) {
    old_generation_allocation_counter_at_last_gc_ = new_value;
  }

  int gc_count() const { return gc_count_; }

  bool is_current_gc_forced() const { return is_current_gc_forced_; }

  GarbageCollector current_or_last_garbage_collector() const {
    return current_or_last_garbage_collector_;
  }

  // Returns whether the currently in-progress GC should avoid increasing the
  // ages on any objects that live for a set number of collections.
  bool ShouldCurrentGCKeepAgesUnchanged() const {
    return is_current_gc_forced_ || is_current_gc_for_heap_profiler_;
  }

  // Returns the size of objects residing in non-new spaces.
  // Excludes external memory held by those objects.
  V8_EXPORT_PRIVATE size_t OldGenerationSizeOfObjects() const;

  // Returns the amount of wasted bytes in non-new spaces.
  V8_EXPORT_PRIVATE size_t OldGenerationWastedBytes() const;

  // Returns the amount of bytes in non-new spaces not availalbe for allocation,
  // including bytes allocated and wasted.
  V8_EXPORT_PRIVATE size_t OldGenerationConsumedBytes() const;

  // Returns the size of objects residing in new spaces.
  // Excludes external memory held by those objects.
  V8_EXPORT_PRIVATE size_t YoungGenerationSizeOfObjects() const;

  // Returns the amount of wasted bytes in new spaces.
  V8_EXPORT_PRIVATE size_t YoungGenerationWastedBytes() const;

  // Returns the amount of bytes in new space not availalbe for allocation,
  // including bytes allocated and wasted.
  V8_EXPORT_PRIVATE size_t YoungGenerationConsumedBytes() const;

  // Returns the size of objects held by the EmbedderHeapTracer.
  V8_EXPORT_PRIVATE size_t EmbedderSizeOfObjects() const;

  // Returns the global size of objects (embedder + V8 non-new spaces).
  V8_EXPORT_PRIVATE size_t GlobalSizeOfObjects() const;

  // Returns the global amount of wasted bytes.
  V8_EXPORT_PRIVATE size_t GlobalWastedBytes() const;

  // Returns the global amount of bytes not availalbe for allocation, including
  // bytes allocated and wasted.
  V8_EXPORT_PRIVATE size_t GlobalConsumedBytes() const;

  // Returns the size of objects in old generation after the last MarkCompact
  // GC.
  V8_EXPORT_PRIVATE size_t OldGenerationConsumedBytesAtLastGC() const;

  // Returns the global amount of bytes after the last MarkCompact GC.
  V8_EXPORT_PRIVATE size_t GlobalConsumedBytesAtLastGC() const;

  // We allow incremental marking to overshoot the V8 and global allocation
  // limit for performance reasons. If the overshoot is too large then we are
  // more eager to finalize incremental marking.
  bool AllocationLimitOvershotByLargeMargin() const;

  // Return the maximum size objects can be before having to allocate them as
  // large objects. This takes into account allocating in the code space for
  // which the size of the allocatable space per V8 page may depend on the OS
  // page size at runtime. You may use kMaxRegularHeapObjectSize as a constant
  // instead if you know the allocation isn't in the code spaces.
  inline V8_EXPORT_PRIVATE int MaxRegularHeapObjectSize(
      AllocationType allocation);

  // ===========================================================================
  // Prologue/epilogue callback methods.========================================
  // ===========================================================================

  void AddGCPrologueCallback(v8::Isolate::GCCallbackWithData callback,
                             GCType gc_type_filter, void* data);
  void RemoveGCPrologueCallback(v8::Isolate::GCCallbackWithData callback,
                                void* data);

  void AddGCEpilogueCallback(v8::Isolate::GCCallbackWithData callback,
                             GCType gc_type_filter, void* data);
  void RemoveGCEpilogueCallback(v8::Isolate::GCCallbackWithData callback,
                                void* data);

  void CallGCPrologueCallbacks(GCType gc_type, GCCallbackFlags flags,
                               GCTracer::Scope::ScopeId scope_id);
  void CallGCEpilogueCallbacks(GCType gc_type, GCCallbackFlags flags,
                               GCTracer::Scope::ScopeId scope_id);

  // ===========================================================================
  // Allocation methods. =======================================================
  // ===========================================================================

  // Creates a filler object and returns a heap object immediately after it.
  V8_EXPORT_PRIVATE Tagged<HeapObject> PrecedeWithFiller(
      Tagged<HeapObject> object, int filler_size);

  // Creates a filler object and returns a heap object immediately after it.
  // Unlike `PrecedeWithFiller` this method will not perform slot verification
  // since this would race on background threads.
  V8_EXPORT_PRIVATE Tagged<HeapObject> PrecedeWithFillerBackground(
      Tagged<HeapObject> object, int filler_size);

  // Creates a filler object if needed for alignment and returns a heap object
  // immediately after it. If any space is left after the returned object,
  // another filler object is created so the over allocated memory is iterable.
  V8_WARN_UNUSED_RESULT Tagged<HeapObject> AlignWithFillerBackground(
      Tagged<HeapObject> object, int object_size, int allocation_size,
      AllocationAlignment alignment);

  // Allocate an external backing store with the given allocation callback.
  // If the callback fails (indicated by a nullptr result) then this function
  // will re-try the allocation after performing GCs. This is useful for
  // external backing stores that may be retained by (unreachable) V8 objects
  // such as ArrayBuffers, ExternalStrings, etc.
  //
  // The function may also proactively trigger GCs even if the allocation
  // callback does not fail to keep the memory usage low.
  V8_EXPORT_PRIVATE void* AllocateExternalBackingStore(
      const std::function<void*(size_t)>& allocate, size_t byte_length);

  // ===========================================================================
  // Allocation tracking. ======================================================
  // ===========================================================================

  // Adds {new_space_observer} to new space and {observer} to any other space.
  void AddAllocationObserversToAllSpaces(
      AllocationObserver* observer, AllocationObserver* new_space_observer);

  // Removes {new_space_observer} from new space and {observer} from any other
  // space.
  void RemoveAllocationObserversFromAllSpaces(
      AllocationObserver* observer, AllocationObserver* new_space_observer);

  // Check if the given object was recently allocated and its fields may appear
  // as uninitialized to background threads.
  // This predicate may be invoked from a background thread.
  inline bool IsPendingAllocation(Tagged<HeapObject> object);
  inline bool IsPendingAllocation(Tagged<Object> object);

  // Notifies that all previously allocated objects are properly initialized
  // and ensures that IsPendingAllocation returns false for them. This function
  // may be invoked only on the main thread.
  V8_EXPORT_PRIVATE void PublishMainThreadPendingAllocations();

  // ===========================================================================
  // Heap object allocation tracking. ==========================================
  // ===========================================================================

  V8_EXPORT_PRIVATE void AddHeapObjectAllocationTracker(
      HeapObjectAllocationTracker* tracker);
  V8_EXPORT_PRIVATE void RemoveHeapObjectAllocationTracker(
      HeapObjectAllocationTracker* tracker);
  bool has_heap_object_allocation_tracker() const {
    return !allocation_trackers_.empty();
  }

  // ===========================================================================
  // Stack frame support. ======================================================
  // ===========================================================================

  // Searches for a Code object by the given interior pointer.
  V8_EXPORT_PRIVATE Tagged<Code> FindCodeForInnerPointer(Address inner_pointer);
  // Use the GcSafe family of functions if called while GC is in progress.
  Tagged<GcSafeCode> GcSafeFindCodeForInnerPointer(Address inner_pointer);
  std::optional<Tagged<GcSafeCode>> GcSafeTryFindCodeForInnerPointer(
      Address inner_pointer);
  std::optional<Tagged<InstructionStream>>
  GcSafeTryFindInstructionStreamForInnerPointer(Address inner_pointer);
  // Only intended for use from the `jco` gdb macro.
  std::optional<Tagged<Code>> TryFindCodeForInnerPointerForPrinting(
      Address inner_pointer);

  // Returns true if {addr} is contained within {instruction_stream} and false
  // otherwise. Mostly useful for debugging.
  bool GcSafeInstructionStreamContains(
      Tagged<InstructionStream> instruction_stream, Address addr);

  // ===========================================================================
  // Sweeping. =================================================================
  // ===========================================================================

  bool sweeping_in_progress() const { return sweeper_->sweeping_in_progress(); }
  bool sweeping_in_progress_for_space(AllocationSpace space) const {
    return sweeper_->sweeping_in_progress_for_space(space);
  }
  bool minor_sweeping_in_progress() const {
    return sweeper_->minor_sweeping_in_progress();
  }
  bool major_sweeping_in_progress() const {
    return sweeper_->major_sweeping_in_progress();
  }

  void FinishSweepingIfOutOfWork();

  enum class SweepingForcedFinalizationMode { kUnifiedHeap, kV8Only };

  // Ensures that sweeping is finished.
  //
  // Note: Can only be called safely from main thread.
  V8_EXPORT_PRIVATE void EnsureSweepingCompleted(
      SweepingForcedFinalizationMode mode);
  void EnsureYoungSweepingCompleted();

  // =============================================================================

#ifdef V8_ENABLE_ALLOCATION_TIMEOUT
  void V8_EXPORT_PRIVATE set_allocation_timeout(int allocation_timeout);
#endif  // V8_ENABLE_ALLOCATION_TIMEOUT

#ifdef DEBUG
  void VerifyCountersAfterSweeping();
  void VerifyCountersBeforeConcurrentSweeping(GarbageCollector collector);
  void VerifyCommittedPhysicalMemory();

  void Print();
  void PrintHandles();

  // Report code statistics.
  void ReportCodeStatistics(const char* title);
#endif  // DEBUG
  void* GetRandomMmapAddr() {
    void* result = v8::internal::GetRandomMmapAddr();
#if V8_TARGET_ARCH_X64
#if V8_OS_DARWIN
    // The Darwin kernel [as of macOS 10.12.5] does not clean up page
    // directory entries [PDE] created from mmap or mach_vm_allocate, even
    // after the region is destroyed. Using a virtual address space that is
    // too large causes a leak of about 1 wired [can never be paged out] page
    // per call to mmap(). The page is only reclaimed when the process is
    // killed. Confine the hint to a 32-bit section of the virtual address
    // space. See crbug.com/700928.
    uintptr_t offset = reinterpret_cast<uintptr_t>(result) & kMmapRegionMask;
    result = reinterpret_cast<void*>(mmap_region_base_ + offset);
#endif  // V8_OS_DARWIN
#endif  // V8_TARGET_ARCH_X64
    return result;
  }

  // Calculates the nof entries for the full sized number to string cache.
  inline int MaxNumberToStringCacheSize() const;

  // Ensure that we have swept all spaces in such a way that we can iterate
  // over all objects.
  V8_EXPORT_PRIVATE void MakeHeapIterable();

  V8_EXPORT_PRIVATE void Unmark();
  V8_EXPORT_PRIVATE void DeactivateMajorGCInProgressFlag();

  // Free all LABs in the heap.
  V8_EXPORT_PRIVATE void FreeLinearAllocationAreas();

  // Frees all LABs owned by the main thread.
  V8_EXPORT_PRIVATE void FreeMainThreadLinearAllocationAreas();

  V8_EXPORT_PRIVATE bool CanPromoteYoungAndExpandOldGeneration(
      size_t size) const;
  V8_EXPORT_PRIVATE bool CanExpandOldGeneration(size_t size) const;

  // Checks whether OldGenerationCapacity() can be expanded by `size` bytes and
  // still fits into `max_old_generation_size_`.
  V8_EXPORT_PRIVATE bool IsOldGenerationExpansionAllowed(
      size_t size, const base::MutexGuard& expansion_mutex_witness) const;

  bool ShouldReduceMemory() const {
    return current_gc_flags_ & GCFlag::kReduceMemoryFootprint;
  }

  MarkingState* marking_state() { return &marking_state_; }

  NonAtomicMarkingState* non_atomic_marking_state() {
    return &non_atomic_marking_state_;
  }

  PretenuringHandler* pretenuring_handler() { return &pretenuring_handler_; }

  bool IsInlineAllocationEnabled() const { return inline_allocation_enabled_; }

  // Returns the amount of external memory registered since last global gc.
  V8_EXPORT_PRIVATE uint64_t AllocatedExternalMemorySinceMarkCompact() const;

  std::shared_ptr<v8::TaskRunner> GetForegroundTaskRunner(
      TaskPriority priority = TaskPriority::kUserBlocking) const;

  bool ShouldUseBackgroundThreads() const;
  bool ShouldUseIncrementalMarking() const;

  HeapAllocator* allocator() { return heap_allocator_; }
  const HeapAllocator* allocator() const { return heap_allocator_; }

  bool use_new_space() const {
    DCHECK_IMPLIES(new_space(), !v8_flags.sticky_mark_bits);
    return new_space() || v8_flags.sticky_mark_bits;
  }

 private:
  class AllocationTrackerForDebugging;

  using ExternalStringTableUpdaterCallback =
      Tagged<String> (*)(Heap* heap, FullObjectSlot pointer);

  // External strings table is a place where all external strings are
  // registered.  We need to keep track of such strings to properly
  // finalize them.
  class ExternalStringTable {
   public:
    explicit ExternalStringTable(Heap* heap) : heap_(heap) {}
    ExternalStringTable(const ExternalStringTable&) = delete;
    ExternalStringTable& operator=(const ExternalStringTable&) = delete;

    // Registers an external string.
    inline void AddString(Tagged<String> string);
    bool Contains(Tagged<String> string);

    void IterateAll(RootVisitor* v);
    void IterateYoung(RootVisitor* v);
    void PromoteYoung();

    // Restores internal invariant and gets rid of collected strings. Must be
    // called after each Iterate*() that modified the strings.
    void CleanUpAll();
    void CleanUpYoung();

    // Finalize all registered external strings and clear tables.
    void TearDown();

    void UpdateYoungReferences(
        Heap::ExternalStringTableUpdaterCallback updater_func);
    void UpdateReferences(
        Heap::ExternalStringTableUpdaterCallback updater_func);

    bool HasYoung() const { return !young_strings_.empty(); }

   private:
    void Verify();
    void VerifyYoung();

    Heap* const heap_;

    // To speed up scavenge collections young string are kept separate from old
    // strings.
    std::vector<TaggedBase> young_strings_;
    std::vector<TaggedBase> old_strings_;
    // Used to protect access with --shared-string-table.
    base::Mutex mutex_;
  };

  static const int kInitialEvalCacheSize = 64;
  static const int kInitialNumberStringCacheSize = 256;

  static const int kRememberedUnmappedPages = 128;

  static const int kYoungSurvivalRateHighThreshold = 90;
  static const int kYoungSurvivalRateAllowedDeviation = 15;
  static const int kOldSurvivalRateLowThreshold = 10;

  static const int kMaxMarkCompactsInIdleRound = 7;

  Heap();
  ~Heap();

  Heap(const Heap&) = delete;
  Heap& operator=(const Heap&) = delete;

  static bool IsRegularObjectAllocation(Alloc
```