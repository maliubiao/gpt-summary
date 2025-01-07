Response:
The user wants to understand the functionality of the given C++ code snippet from `v8/test/cctest/heap/test-heap.cc`. I need to analyze each test case and describe its purpose. I should also check if any of these tests relate to JavaScript functionality and provide examples if they do. The user also asked to identify potential programming errors the tests might be uncovering and illustrate with examples. Finally, I need to summarize the overall functionality of this part of the test suite.

**Plan:**

1. **Iterate through each `TEST` or `HEAP_TEST` block.**
2. **For each test:**
   - Describe its purpose based on the test name and the code within it.
   - Check if it's related to JavaScript concepts. If so, provide a JavaScript example.
   - Look for code logic that can be explained with input/output examples.
   - Identify any common programming errors the test might be guarding against.
3. **Check if any tests would be Torque files if they had a `.tq` extension.** (In this snippet, there are no indications of Torque usage).
4. **Summarize the overall functionality of the provided code.**
这是 V8 源代码 `v8/test/cctest/heap/test-heap.cc` 的第 8 部分，主要包含了一系列针对 V8 堆管理的测试用例。这些测试用例涵盖了堆的各种功能，包括：

**主要功能归纳:**

* **数组裁剪 (Array Trimming):** 测试了 `RightTrimArray` 方法在不同场景下的正确性，包括标记过的堆页和黑分配页。
* **内存压力通知 (Memory Pressure Notification):** 验证了内存压力通知是否能触发垃圾回收，并测试了在增量标记期间的行为。
* **年轻代大对象分配 (Young Generation Large Object Allocation):**  测试了大对象在年轻代分配后的晋升过程，分别针对 Scavenge (Minor GC) 和 Mark-Compact (Major GC)。
* **释放未使用的 Lo 空间内存 (Uncommit Unused Large Object Memory):** 验证了对大对象进行裁剪后，未使用的物理内存能够被释放。
* **记忆集 (Remembered Sets):**  详细测试了记忆集的插入、删除和清理功能，包括跨代指针的记录和在垃圾回收过程中的维护。具体测试了：
    * 写屏障时插入记忆集 (`RememberedSet_InsertOnWriteBarrier`)
    * 在大页中插入记忆集 (`RememberedSet_InsertInLargePage`)
    * 在 Scavenge 期间移除过时的记忆集 (`RememberedSet_RemoveStaleOnScavenge`)
    * 老生代到老生代的记忆集 (`RememberedSet_OldToOld`)
    * 移除记忆集中的指定范围 (`RememberedSetRemoveRange`)
* **回归测试 (Regression Tests):**  包含了一些针对特定 Bug 的回归测试，例如 `Regress618958` 和 `Regress779503`，确保之前修复的问题不会再次出现。
* **增量标记 (Incremental Marking):**  多个测试用例涉及到增量标记的场景，验证了在这种模式下堆管理的正确性，包括：
    * 确保分配时的写屏障 (`RegressMissingWriteBarrierInAllocate`)
    * 检查 Mark-Compact 的 epoch 计数器 (`MarkCompactEpochCounter`)
* **内存溢出 (Out of Memory):**  测试了在内存不足的情况下 V8 的行为，包括触发 OOM 回调和检测无效的垃圾回收。
* **哈希种子重新初始化 (ReinitializeStringHashSeed):** 测试了在创建新的 Isolate 时，字符串哈希种子能否正确初始化。

**详细功能列举:**

1. **`TEST(RightTrimFixedArray)`:**
   - **功能:** 测试在已标记的堆页上对 `FixedArray` 进行右裁剪的功能。
   - **代码逻辑推理:**
     - **假设输入:**  一个已分配且被标记的 `FixedArray`。
     - **输出:**  裁剪后，被裁剪掉的部分会被填充 `FreeSpace` 或 `Filler` 对象，且这些对象未被标记。多次裁剪会正确更新 `FixedArray` 的容量，并保持裁剪区域未标记。
   - **用户常见的编程错误:**  手动管理内存时，可能错误地认为裁剪后的内存仍然属于数组，导致访问越界。
   - **JavaScript 示例:**  虽然 C++ 代码直接操作堆，但这个功能与 JavaScript 数组的 `slice` 或修改 `length` 属性有关，例如：
     ```javascript
     let arr = [1, 2, 3, 4, 5];
     arr.length = 3; // 相当于右裁剪
     console.log(arr); // 输出: [1, 2, 3]
     ```

2. **`TEST(RightTrimFixedArrayWithBlackAllocatedPages)`:**
   - **功能:** 测试在黑分配页上对 `FixedArray` 进行右裁剪的功能，特别关注 `BLACK_ALLOCATED` 标志的处理。
   - **代码逻辑推理:**
     - **假设输入:** 一个在黑分配页上分配的 `FixedArray`。
     - **输出:** 第一次少量裁剪不应影响页面的 `BLACK_ALLOCATED` 标志。 Major GC 后，该标志会被清除。对于在 `LO_SPACE` 分配的大数组，裁剪不会设置 `BLACK_ALLOCATED` 标志。
   - **与 JavaScript 的关系:**  与 JavaScript 数组的动态大小调整有关。
   - **用户常见的编程错误:**  不理解黑分配页的含义，可能在增量标记阶段错误地修改了本应被视为已完成标记的对象。

3. **`TEST(Regress618958)`:**
   - **功能:** 回归测试，验证内存压力通知在增量标记启用时的行为。
   - **代码逻辑推理:**  测试内存压力通知是否能触发一次或两次 Full GC，或者触发一次 Full GC 并启动增量标记。

4. **`TEST(YoungGenerationLargeObjectAllocationScavenge)`:**
   - **功能:** 测试大对象在年轻代分配后，经过 Scavenge (Minor GC) 后的晋升行为。
   - **与 JavaScript 的关系:**  涉及 JavaScript 中创建的大型对象，例如大型数组或字符串。
   - **JavaScript 示例:**
     ```javascript
     let largeArray = new Array(200000); // 可能被分配为大对象
     largeArray[0] = 123.456;
     // 触发 Minor GC 后，largeArray 应该晋升到老年代
     ```

5. **`TEST(YoungGenerationLargeObjectAllocationMarkCompact)`:**
   - **功能:** 测试大对象在年轻代分配后，经过 Mark-Compact (Major GC) 后的晋升行为。
   - **与 JavaScript 的关系:**  同上。

6. **`TEST(YoungGenerationLargeObjectAllocationReleaseScavenger)`:**
   - **功能:** 测试在年轻代分配大量大对象后，经过 Scavenge 后，年轻代大对象空间是否被正确释放。

7. **`TEST(UncommitUnusedLargeObjectMemory)`:**
   - **功能:** 测试裁剪大对象后，未使用的物理内存是否会被取消提交。
   - **与 JavaScript 的关系:**  当 JavaScript 创建非常大的对象并随后缩减其大小时，V8 可能会尝试释放不再需要的内存。

8. **`TEST(RememberedSet_InsertOnWriteBarrier)`:**
   - **功能:** 测试在写屏障时，是否正确地将跨代指针插入到记忆集中。
   - **代码逻辑推理:**  分配一个老年代对象，并在其中引用年轻代对象。记忆集应该记录这些跨代指针。
   - **与 JavaScript 的关系:**  当 JavaScript 中一个老对象引用一个新对象时，会触发写屏障，记忆集用于记录这些引用，以便 GC 可以正确处理。
   - **JavaScript 示例:**
     ```javascript
     let oldObject = {}; // 假设分配在老年代
     let youngObject = {}; // 假设分配在年轻代
     oldObject.ref = youngObject; // 触发写屏障
     ```

9. **`TEST(RememberedSet_InsertInLargePage)`:**
   - **功能:** 测试在大型页面的对象中插入跨代指针时，记忆集是否正确工作。

10. **`TEST(RememberedSet_RemoveStaleOnScavenge)`:**
    - **功能:** 测试在 Scavenge 过程中，记忆集中指向被回收的年轻代对象的条目是否被正确移除。
    - **代码逻辑推理:** 创建一个老年代数组，其中包含指向年轻代对象的指针。在 Scavenge 后，这些指针要么被提升到老年代，要么被回收，记忆集应该相应更新。

11. **`TEST(RememberedSet_OldToOld)`:**
    - **功能:** 测试老年代到老年代的记忆集在 Full GC 期间的创建和使用。这个记忆集是临时的，用于跟踪老年代对象之间的引用，以支持压缩。
    - **与 JavaScript 的关系:**  当老年代对象之间存在引用，且发生压缩 GC 时，需要使用这种记忆集。

12. **`TEST(RememberedSetRemoveRange)`:**
    - **功能:** 测试从记忆集中移除指定范围的条目的功能。

13. **`HEAP_TEST(Regress670675)`:**
    - **功能:** 回归测试，与增量标记有关，可能测试了在分配大量对象时增量标记的正确性。

14. **`HEAP_TEST(RegressMissingWriteBarrierInAllocate)`:**
    - **功能:** 回归测试，确保在分配对象时，即使在黑分配模式下，也正确执行了写屏障，以维护对象图的完整性。
    - **用户常见的编程错误:**  在底层内存操作中，如果跳过写屏障，可能导致对象图的引用关系不正确，GC 可能过早回收应该存活的对象。

15. **`HEAP_TEST(MarkCompactEpochCounter)`:**
    - **功能:** 测试 Mark-Compact 垃圾回收器的 epoch 计数器是否在每次 Mark-Compact GC 后递增。

16. **`UNINITIALIZED_TEST(ReinitializeStringHashSeed)`:**
    - **功能:** 测试在创建新的 Isolate 时，字符串哈希种子是否被正确重新初始化。
    - **与 JavaScript 的关系:**  哈希种子影响 JavaScript 字符串的哈希值，这在例如 `Map` 和 `Set` 的实现中很重要。

17. **`UNINITIALIZED_TEST(OutOfMemory)`:**
    - **功能:** 测试在内存溢出时，V8 的 OOM 回调是否被触发，并且堆的大小是否在预期范围内。

18. **`UNINITIALIZED_TEST(OutOfMemoryIneffectiveGC)`:**
    - **功能:** 测试 V8 是否能检测到无效的垃圾回收（即 GC 后内存回收很少），这通常发生在接近堆限制时。

19. **`UNINITIALIZED_TEST(OutOfMemoryIneffectiveGCRunningJS)`:**
    - **功能:** 测试在运行 JavaScript 代码时发生内存溢出，并且检测到无效 GC 的情况。

20. **`HEAP_TEST(Regress779503)`:**
    - **功能:** 回归测试，确保 Scavenger 不会在其正在处理的页面上分配对象，以避免覆盖正在扫描的槽。

21. **`UNINITIALIZED_TEST(OutOfMemorySmallObjects)`:**
    - **功能:** 测试在分配小对象导致内存溢出时，OOM 回调的触发和堆大小的检查。

22. **`UNINITIALIZED_TEST(OutOfMemoryLargeObjects)`:**
    - **功能:** 测试在分配大对象导致内存溢出时，OOM 回调的触发和堆大小的检查。

23. **`UNINITIALIZED_TEST(RestoreHeapLimit)`:**
    - **功能:**  测试在设置新的堆限制后，又恢复到初始堆限制的功能。

**关于 `.tq` 结尾：**

如果 `v8/test/cctest/heap/test-heap.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。Torque 是一种 V8 自有的类型化中间语言，用于实现 V8 内部的一些关键操作，尤其是内置函数。当前的这个文件是 `.cc`，所以是 C++ 源代码。

总而言之，这个代码片段是 V8 堆管理功能的一组详尽的测试，涵盖了对象分配、垃圾回收的各个阶段（包括 Scavenge 和 Mark-Compact）、内存压力处理、以及一些边缘情况和回归测试。这些测试对于确保 V8 的内存管理机制的正确性和健壮性至关重要。

Prompt: 
```
这是目录为v8/test/cctest/heap/test-heap.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/heap/test-heap.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共9部分，请归纳一下它的功能

"""
rking_state = heap->non_atomic_marking_state();
  CHECK(marking_state->IsMarked(*array));
  CHECK(page->marking_bitmap()->AllBitsSetInRange(
      MarkingBitmap::AddressToIndex(start_address),
      MarkingBitmap::LimitAddressToIndex(end_address)));
  CHECK(heap->old_space()->Contains(*array));

  // Trim it once by one word to check that the trimmed area gets unmarked.
  Address previous = end_address - kTaggedSize;
  isolate->heap()->RightTrimArray(*array, 99, 100);

  Tagged<HeapObject> filler = HeapObject::FromAddress(previous);
  CHECK(IsFreeSpaceOrFiller(filler));

  // Trim 10 times by one, two, and three word.
  for (int i = 1; i <= 3; i++) {
    for (int j = 0; j < 10; j++) {
      previous -= kTaggedSize * i;
      int old_capacity = array->capacity();
      int new_capacity = old_capacity - i;
      isolate->heap()->RightTrimArray(*array, new_capacity, old_capacity);
      filler = HeapObject::FromAddress(previous);
      CHECK(IsFreeSpaceOrFiller(filler));
      CHECK(marking_state->IsUnmarked(filler));
    }
  }

  heap::InvokeAtomicMajorGC(heap);
}

TEST(RightTrimFixedArrayWithBlackAllocatedPages) {
  if (!v8_flags.black_allocated_pages) return;
  if (!v8_flags.incremental_marking) return;
  v8_flags.stress_concurrent_allocation = false;  // For SimulateFullSpace.
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Heap* heap = CcTest::heap();
  Isolate* isolate = CcTest::i_isolate();
  heap::InvokeMajorGC(heap);

  i::IncrementalMarking* marking = heap->incremental_marking();
  if (heap->sweeping_in_progress()) {
    heap->EnsureSweepingCompleted(
        Heap::SweepingForcedFinalizationMode::kV8Only);
  }
  CHECK(marking->IsMarking() || marking->IsStopped());
  if (marking->IsStopped()) {
    heap->StartIncrementalMarking(i::GCFlag::kNoFlags,
                                  i::GarbageCollectionReason::kTesting);
  }
  CHECK(marking->IsMarking());
  CHECK(marking->black_allocation());

  // Ensure that we allocate a new page, set up a bump pointer area, and
  // perform the allocation in a black area.
  heap::SimulateFullSpace(heap->old_space());
  isolate->factory()->NewFixedArray(10, AllocationType::kOld);

  // Allocate the fixed array that will be trimmed later.
  DirectHandle<FixedArray> array =
      isolate->factory()->NewFixedArray(100, AllocationType::kOld);
  Address start_address = array->address();
  Address end_address = start_address + array->Size();
  PageMetadata* page = PageMetadata::FromAddress(start_address);
  CHECK(page->Chunk()->IsFlagSet(MemoryChunk::BLACK_ALLOCATED));
  CHECK(heap->old_space()->Contains(*array));

  // Trim it once by one word, which shouldn't affect the BLACK_ALLOCATED flag.
  Address previous = end_address - kTaggedSize;
  isolate->heap()->RightTrimArray(*array, 99, 100);

  Tagged<HeapObject> filler = HeapObject::FromAddress(previous);
  CHECK(IsFreeSpaceOrFiller(filler));
  CHECK(page->Chunk()->IsFlagSet(MemoryChunk::BLACK_ALLOCATED));

  heap::InvokeAtomicMajorGC(heap);
  CHECK(!page->Chunk()->IsFlagSet(MemoryChunk::BLACK_ALLOCATED));

  heap->StartIncrementalMarking(i::GCFlag::kNoFlags,
                                i::GarbageCollectionReason::kTesting);

  // Allocate the large fixed array that will be trimmed later.
  array = isolate->factory()->NewFixedArray(200000, AllocationType::kOld);
  start_address = array->address();
  end_address = start_address + array->Size();
  CHECK(heap->lo_space()->Contains(*array));
  page = PageMetadata::FromAddress(start_address);
  CHECK(!page->Chunk()->IsFlagSet(MemoryChunk::BLACK_ALLOCATED));

  heap::InvokeAtomicMajorGC(heap);
  CHECK(!page->Chunk()->IsFlagSet(MemoryChunk::BLACK_ALLOCATED));
}

TEST(Regress618958) {
  if (!v8_flags.incremental_marking) return;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Heap* heap = CcTest::heap();
  bool isolate_is_locked = true;
  CcTest::isolate()->AdjustAmountOfExternalAllocatedMemory(100 * MB);
  int mark_sweep_count_before = heap->ms_count();
  heap->MemoryPressureNotification(MemoryPressureLevel::kCritical,
                                   isolate_is_locked);
  int mark_sweep_count_after = heap->ms_count();
  int mark_sweeps_performed = mark_sweep_count_after - mark_sweep_count_before;
  // The memory pressuer handler either performed two GCs or performed one and
  // started incremental marking.
  CHECK(mark_sweeps_performed == 2 ||
        (mark_sweeps_performed == 1 &&
         !heap->incremental_marking()->IsStopped()));
}

TEST(YoungGenerationLargeObjectAllocationScavenge) {
  if (v8_flags.minor_ms) return;
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Heap* heap = CcTest::heap();
  Isolate* isolate = heap->isolate();
  if (!isolate->serializer_enabled()) return;

  // TODO(hpayer): Update the test as soon as we have a tenure limit for LO.
  DirectHandle<FixedArray> array_small =
      isolate->factory()->NewFixedArray(200000);
  MemoryChunk* chunk = MemoryChunk::FromHeapObject(*array_small);
  CHECK_EQ(NEW_LO_SPACE,
           MutablePageMetadata::cast(chunk->Metadata())->owner_identity());
  CHECK(chunk->IsFlagSet(MemoryChunk::LARGE_PAGE));
  CHECK(chunk->IsFlagSet(MemoryChunk::TO_PAGE));

  DirectHandle<Object> number = isolate->factory()->NewHeapNumber(123.456);
  array_small->set(0, *number);

  heap::InvokeMinorGC(heap);

  // After the first young generation GC array_small will be in the old
  // generation large object space.
  chunk = MemoryChunk::FromHeapObject(*array_small);
  CHECK_EQ(LO_SPACE,
           MutablePageMetadata::cast(chunk->Metadata())->owner_identity());
  CHECK(!chunk->InYoungGeneration());

  heap::InvokeMemoryReducingMajorGCs(heap);
}

TEST(YoungGenerationLargeObjectAllocationMarkCompact) {
  if (v8_flags.minor_ms) return;
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Heap* heap = CcTest::heap();
  Isolate* isolate = heap->isolate();
  if (!isolate->serializer_enabled()) return;

  // TODO(hpayer): Update the test as soon as we have a tenure limit for LO.
  DirectHandle<FixedArray> array_small =
      isolate->factory()->NewFixedArray(200000);
  MemoryChunk* chunk = MemoryChunk::FromHeapObject(*array_small);
  CHECK_EQ(NEW_LO_SPACE,
           MutablePageMetadata::cast(chunk->Metadata())->owner_identity());
  CHECK(chunk->IsFlagSet(MemoryChunk::LARGE_PAGE));
  CHECK(chunk->IsFlagSet(MemoryChunk::TO_PAGE));

  DirectHandle<Object> number = isolate->factory()->NewHeapNumber(123.456);
  array_small->set(0, *number);

  heap::InvokeMajorGC(heap);

  // After the first full GC array_small will be in the old generation
  // large object space.
  chunk = MemoryChunk::FromHeapObject(*array_small);
  CHECK_EQ(LO_SPACE,
           MutablePageMetadata::cast(chunk->Metadata())->owner_identity());
  CHECK(!chunk->InYoungGeneration());

  heap::InvokeMemoryReducingMajorGCs(heap);
}

TEST(YoungGenerationLargeObjectAllocationReleaseScavenger) {
  if (v8_flags.minor_ms) return;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Heap* heap = CcTest::heap();
  Isolate* isolate = heap->isolate();
  if (!isolate->serializer_enabled()) return;

  {
    HandleScope new_scope(isolate);
    for (int i = 0; i < 10; i++) {
      DirectHandle<FixedArray> array_small =
          isolate->factory()->NewFixedArray(20000);
      MemoryChunk* chunk = MemoryChunk::FromHeapObject(*array_small);
      CHECK_EQ(NEW_LO_SPACE,
               MutablePageMetadata::cast(chunk->Metadata())->owner_identity());
      CHECK(chunk->IsFlagSet(MemoryChunk::TO_PAGE));
    }
  }

  heap::InvokeMinorGC(heap);
  CHECK(isolate->heap()->new_lo_space()->IsEmpty());
  CHECK_EQ(0, isolate->heap()->new_lo_space()->Size());
  CHECK_EQ(0, isolate->heap()->new_lo_space()->SizeOfObjects());
  CHECK(isolate->heap()->lo_space()->IsEmpty());
  CHECK_EQ(0, isolate->heap()->lo_space()->Size());
  CHECK_EQ(0, isolate->heap()->lo_space()->SizeOfObjects());
}

TEST(UncommitUnusedLargeObjectMemory) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Heap* heap = CcTest::heap();
  Isolate* isolate = heap->isolate();

  DirectHandle<FixedArray> array =
      isolate->factory()->NewFixedArray(200000, AllocationType::kOld);
  MemoryChunk* chunk = MemoryChunk::FromHeapObject(*array);
  CHECK_EQ(MutablePageMetadata::cast(chunk->Metadata())->owner_identity(),
           LO_SPACE);

  intptr_t size_before = array->Size();
  size_t committed_memory_before =
      MutablePageMetadata::cast(chunk->Metadata())->CommittedPhysicalMemory();

  array->RightTrim(isolate, 1);
  CHECK(array->Size() < size_before);

  heap::InvokeMajorGC(heap);
  CHECK(
      MutablePageMetadata::cast(chunk->Metadata())->CommittedPhysicalMemory() <
      committed_memory_before);
  size_t shrinked_size = RoundUp(
      (array->address() - chunk->address()) + array->Size(), CommitPageSize());
  CHECK_EQ(
      shrinked_size,
      MutablePageMetadata::cast(chunk->Metadata())->CommittedPhysicalMemory());
}

template <RememberedSetType direction>
static size_t GetRememberedSetSize(Tagged<HeapObject> obj) {
  size_t count = 0;
  auto chunk = MutablePageMetadata::FromHeapObject(obj);
  RememberedSet<direction>::Iterate(
      chunk,
      [&count](MaybeObjectSlot slot) {
        count++;
        return KEEP_SLOT;
      },
      SlotSet::KEEP_EMPTY_BUCKETS);
  return count;
}

TEST(RememberedSet_InsertOnWriteBarrier) {
  if (v8_flags.single_generation) return;
  v8_flags.stress_concurrent_allocation = false;  // For SealCurrentObjects.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();
  heap::SealCurrentObjects(heap);
  HandleScope scope(isolate);

  // Allocate an object in old space.
  DirectHandle<FixedArray> arr =
      factory->NewFixedArray(3, AllocationType::kOld);

  // Add into 'arr' references to young objects.
  {
    HandleScope scope_inner(isolate);
    DirectHandle<Object> number = factory->NewHeapNumber(42);
    arr->set(0, *number);
    arr->set(1, *number);
    arr->set(2, *number);
    DirectHandle<Object> number_other = factory->NewHeapNumber(24);
    arr->set(2, *number_other);
  }
  // Remembered sets track *slots* pages with cross-generational pointers, so
  // must have recorded three of them each exactly once.
  CHECK_EQ(3, GetRememberedSetSize<OLD_TO_NEW>(*arr));
}

TEST(RememberedSet_InsertInLargePage) {
  if (v8_flags.single_generation) return;
  v8_flags.stress_concurrent_allocation = false;  // For SealCurrentObjects.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();
  heap::SealCurrentObjects(heap);
  HandleScope scope(isolate);

  // Allocate an object in Large space.
  const int count = std::max(FixedArray::kMaxRegularLength + 1, 128 * KB);
  DirectHandle<FixedArray> arr =
      factory->NewFixedArray(count, AllocationType::kOld);
  CHECK(heap->lo_space()->Contains(*arr));
  CHECK_EQ(0, GetRememberedSetSize<OLD_TO_NEW>(*arr));

  // Create OLD_TO_NEW references from the large object so that the
  // corresponding slots end up in different SlotSets.
  {
    HandleScope short_lived(isolate);
    DirectHandle<Object> number = factory->NewHeapNumber(42);
    arr->set(0, *number);
    arr->set(count - 1, *number);
  }
  CHECK_EQ(2, GetRememberedSetSize<OLD_TO_NEW>(*arr));
}

TEST(RememberedSet_RemoveStaleOnScavenge) {
  if (v8_flags.single_generation || v8_flags.stress_incremental_marking) return;
  v8_flags.stress_concurrent_allocation = false;  // For SealCurrentObjects.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();
  heap::SealCurrentObjects(heap);
  HandleScope scope(isolate);

  // Allocate an object in old space and add into it references to young.
  DirectHandle<FixedArray> arr =
      factory->NewFixedArray(3, AllocationType::kOld);
  {
    HandleScope scope_inner(isolate);
    DirectHandle<Object> number = factory->NewHeapNumber(42);
    arr->set(0, *number);  // will be trimmed away
    arr->set(1, *number);  // will be replaced with #undefined
    arr->set(2, *number);  // will be promoted into old
  }
  CHECK_EQ(3, GetRememberedSetSize<OLD_TO_NEW>(*arr));

  arr->set(1, ReadOnlyRoots(CcTest::heap()).undefined_value());
  DirectHandle<FixedArrayBase> tail(heap->LeftTrimFixedArray(*arr, 1), isolate);

  // None of the actions above should have updated the remembered set.
  CHECK_EQ(3, GetRememberedSetSize<OLD_TO_NEW>(*tail));

  // Run GC to promote the remaining young object and fixup the stale entries in
  // the remembered set.
  heap::EmptyNewSpaceUsingGC(heap);
  CHECK_EQ(0, GetRememberedSetSize<OLD_TO_NEW>(*tail));
}

// The OLD_TO_OLD remembered set is created temporary by GC and is cleared at
// the end of the pass. There is no way to observe it so the test only checks
// that compaction has happened and otherwise relies on code's self-validation.
TEST(RememberedSet_OldToOld) {
  if (v8_flags.stress_incremental_marking) return;
  v8_flags.stress_concurrent_allocation = false;  // For SealCurrentObjects.
  ManualGCScope manual_gc_scope;
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();
  heap::SealCurrentObjects(heap);
  HandleScope scope(isolate);

  IndirectHandle<FixedArray> arr =
      factory->NewFixedArray(10, AllocationType::kOld);
  {
    HandleScope short_lived(isolate);
    factory->NewFixedArray(100, AllocationType::kOld);
  }
  IndirectHandle<Object> ref =
      factory->NewFixedArray(100, AllocationType::kOld);
  arr->set(0, *ref);

  // To force compaction of the old space, fill it with garbage and start a new
  // page (so that the page with 'arr' becomes subject to compaction).
  {
    HandleScope short_lived(isolate);
    heap::SimulateFullSpace(heap->old_space());
    factory->NewFixedArray(100, AllocationType::kOld);
  }

  heap::ForceEvacuationCandidate(PageMetadata::FromHeapObject(*arr));
  const auto prev_location = *arr;

  {
    // This GC pass will evacuate the page with 'arr'/'ref' so it will have to
    // create OLD_TO_OLD remembered set to track the reference.
    // We need to invoke GC without stack, otherwise no compaction is performed.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMajorGC(heap);
  }
  CHECK_NE(prev_location.ptr(), arr->ptr());
}

TEST(RememberedSetRemoveRange) {
  if (v8_flags.single_generation) return;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Heap* heap = CcTest::heap();
  Isolate* isolate = heap->isolate();

  DirectHandle<FixedArray> array = isolate->factory()->NewFixedArray(
      PageMetadata::kPageSize / kTaggedSize, AllocationType::kOld);
  MutablePageMetadata* chunk = MutablePageMetadata::FromHeapObject(*array);
  CHECK_EQ(chunk->owner_identity(), LO_SPACE);
  Address start = array->address();
  // Maps slot to boolean indicator of whether the slot should be in the set.
  std::map<Address, bool> slots;
  slots[start + 0] = true;
  slots[start + kTaggedSize] = true;
  slots[start + PageMetadata::kPageSize - kTaggedSize] = true;
  slots[start + PageMetadata::kPageSize] = true;
  slots[start + PageMetadata::kPageSize + kTaggedSize] = true;
  slots[chunk->area_end() - kTaggedSize] = true;

  for (auto x : slots) {
    RememberedSet<OLD_TO_NEW>::Insert<AccessMode::ATOMIC>(
        chunk, chunk->Offset(x.first));
  }

  RememberedSet<OLD_TO_NEW>::Iterate(
      chunk,
      [&slots](MaybeObjectSlot slot) {
        CHECK(slots[slot.address()]);
        return KEEP_SLOT;
      },
      SlotSet::FREE_EMPTY_BUCKETS);

  RememberedSet<OLD_TO_NEW>::RemoveRange(chunk, start, start + kTaggedSize,
                                         SlotSet::FREE_EMPTY_BUCKETS);
  slots[start] = false;
  RememberedSet<OLD_TO_NEW>::Iterate(
      chunk,
      [&slots](MaybeObjectSlot slot) {
        CHECK(slots[slot.address()]);
        return KEEP_SLOT;
      },
      SlotSet::FREE_EMPTY_BUCKETS);

  RememberedSet<OLD_TO_NEW>::RemoveRange(chunk, start + kTaggedSize,
                                         start + PageMetadata::kPageSize,
                                         SlotSet::FREE_EMPTY_BUCKETS);
  slots[start + kTaggedSize] = false;
  slots[start + PageMetadata::kPageSize - kTaggedSize] = false;
  RememberedSet<OLD_TO_NEW>::Iterate(
      chunk,
      [&slots](MaybeObjectSlot slot) {
        CHECK(slots[slot.address()]);
        return KEEP_SLOT;
      },
      SlotSet::FREE_EMPTY_BUCKETS);

  RememberedSet<OLD_TO_NEW>::RemoveRange(
      chunk, start, start + PageMetadata::kPageSize + kTaggedSize,
      SlotSet::FREE_EMPTY_BUCKETS);
  slots[start + PageMetadata::kPageSize] = false;
  RememberedSet<OLD_TO_NEW>::Iterate(
      chunk,
      [&slots](MaybeObjectSlot slot) {
        CHECK(slots[slot.address()]);
        return KEEP_SLOT;
      },
      SlotSet::FREE_EMPTY_BUCKETS);

  RememberedSet<OLD_TO_NEW>::RemoveRange(chunk, chunk->area_end() - kTaggedSize,
                                         chunk->area_end(),
                                         SlotSet::FREE_EMPTY_BUCKETS);
  slots[chunk->area_end() - kTaggedSize] = false;
  RememberedSet<OLD_TO_NEW>::Iterate(
      chunk,
      [&slots](MaybeObjectSlot slot) {
        CHECK(slots[slot.address()]);
        return KEEP_SLOT;
      },
      SlotSet::FREE_EMPTY_BUCKETS);
}

HEAP_TEST(Regress670675) {
  if (!v8_flags.incremental_marking) return;
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Heap* heap = CcTest::heap();
  Isolate* isolate = heap->isolate();
  heap::InvokeMajorGC(heap);

  if (heap->sweeping_in_progress()) {
    heap->EnsureSweepingCompleted(
        Heap::SweepingForcedFinalizationMode::kV8Only);
  }
  heap->tracer()->StopFullCycleIfNeeded();
  i::IncrementalMarking* marking = CcTest::heap()->incremental_marking();
  if (marking->IsStopped()) {
    IsolateSafepointScope safepoint_scope(heap);
    heap->tracer()->StartCycle(
        GarbageCollector::MARK_COMPACTOR, GarbageCollectionReason::kTesting,
        "collector cctest", GCTracer::MarkingType::kIncremental);
    marking->Start(GarbageCollector::MARK_COMPACTOR,
                   i::GarbageCollectionReason::kTesting);
  }
  size_t array_length = 128 * KB;
  size_t n = heap->OldGenerationSpaceAvailable() / array_length;
  for (size_t i = 0; i < n + 60; i++) {
    {
      HandleScope inner_scope(isolate);
      isolate->factory()->NewFixedArray(static_cast<int>(array_length),
                                        AllocationType::kOld);
    }
    if (marking->IsStopped()) break;
    marking->AdvanceForTesting(v8::base::TimeDelta::FromMillisecondsD(0.1));
  }
  DCHECK(marking->IsStopped());
}

HEAP_TEST(RegressMissingWriteBarrierInAllocate) {
  if (!v8_flags.incremental_marking) return;
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  LocalContext env;
  v8::HandleScope scope(CcTest::isolate());
  Heap* heap = CcTest::heap();
  Isolate* isolate = heap->isolate();
  heap::InvokeMajorGC(heap);
  heap::SimulateIncrementalMarking(heap, false);
  DirectHandle<Map> map;
  {
    AlwaysAllocateScopeForTesting always_allocate(heap);
    map = isolate->factory()->NewContextfulMapForCurrentContext(
        JS_OBJECT_TYPE, JSObject::kHeaderSize);
  }
  CHECK(heap->incremental_marking()->black_allocation());
  DirectHandle<JSObject> object;
  {
    AlwaysAllocateScopeForTesting always_allocate(heap);
    object = direct_handle(Cast<JSObject>(isolate->factory()->NewForTest(
                               map, AllocationType::kOld)),
                           isolate);
  }
  // Initialize backing stores to ensure object is valid.
  ReadOnlyRoots roots(isolate);
  object->set_raw_properties_or_hash(roots.empty_property_array(),
                                     SKIP_WRITE_BARRIER);
  object->set_elements(roots.empty_fixed_array(), SKIP_WRITE_BARRIER);

  // The object is black. If Factory::New sets the map without write-barrier,
  // then the map is white and will be freed prematurely.
  heap::SimulateIncrementalMarking(heap, true);
  heap::InvokeMajorGC(heap);
  if (heap->sweeping_in_progress()) {
    heap->EnsureSweepingCompleted(
        Heap::SweepingForcedFinalizationMode::kV8Only);
  }
  CHECK(IsMap(object->map()));
}

HEAP_TEST(MarkCompactEpochCounter) {
  if (!v8_flags.incremental_marking) return;
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Heap* heap = CcTest::heap();
  unsigned epoch0 = heap->mark_compact_collector()->epoch();
  heap::InvokeMajorGC(heap);
  unsigned epoch1 = heap->mark_compact_collector()->epoch();
  CHECK_EQ(epoch0 + 1, epoch1);
  heap::SimulateIncrementalMarking(heap, true);
  heap::InvokeMajorGC(heap);
  unsigned epoch2 = heap->mark_compact_collector()->epoch();
  CHECK_EQ(epoch1 + 1, epoch2);
  heap::InvokeMinorGC(heap);
  unsigned epoch3 = heap->mark_compact_collector()->epoch();
  CHECK_EQ(epoch2, epoch3);
}

UNINITIALIZED_TEST(ReinitializeStringHashSeed) {
  // Enable rehashing and create an isolate and context.
  i::v8_flags.rehash_snapshot = true;
  for (int i = 1; i < 3; i++) {
    i::v8_flags.hash_seed = 1337 * i;
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
    v8::Isolate* isolate = v8::Isolate::New(create_params);
    {
      v8::Isolate::Scope isolate_scope(isolate);
      CHECK_EQ(static_cast<uint64_t>(1337 * i),
               HashSeed(reinterpret_cast<i::Isolate*>(isolate)));
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      CHECK(!context.IsEmpty());
      v8::Context::Scope context_scope(context);
    }
    isolate->Dispose();
  }
}

const int kHeapLimit = 100 * MB;
Isolate* oom_isolate = nullptr;

void OOMCallback(const char* location, const OOMDetails&) {
  Heap* heap = oom_isolate->heap();
  size_t kSlack = heap->new_space() ? heap->MaxSemiSpaceSize() : 0;
  CHECK_LE(heap->OldGenerationCapacity(), kHeapLimit + kSlack);
  base::OS::ExitProcess(0);
}

UNINITIALIZED_TEST(OutOfMemory) {
  if (v8_flags.stress_incremental_marking) return;
#ifdef VERIFY_HEAP
  if (v8_flags.verify_heap) return;
#endif
  v8_flags.max_old_space_size = kHeapLimit / MB;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  v8::Isolate::Scope isolate_scope(isolate);
  Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);
  oom_isolate = i_isolate;
  isolate->SetOOMErrorHandler(OOMCallback);
  {
    PtrComprCageAccessScope ptr_compr_cage_access_scope(i_isolate);
    Factory* factory = i_isolate->factory();
    HandleScope handle_scope(i_isolate);
    while (true) {
      factory->NewFixedArray(100);
    }
  }
}

UNINITIALIZED_TEST(OutOfMemoryIneffectiveGC) {
  if (!v8_flags.detect_ineffective_gcs_near_heap_limit) return;
  if (v8_flags.stress_incremental_marking ||
      v8_flags.stress_concurrent_allocation)
    return;
#ifdef VERIFY_HEAP
  if (v8_flags.verify_heap) return;
#endif

  v8_flags.max_old_space_size = kHeapLimit / MB;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);
  oom_isolate = i_isolate;
  isolate->SetOOMErrorHandler(OOMCallback);
  Factory* factory = i_isolate->factory();
  Heap* heap = i_isolate->heap();
  {
    v8::Isolate::Scope isolate_scope(isolate);
    PtrComprCageAccessScope ptr_compr_cage_access_scope(i_isolate);
    heap::InvokeMajorGC(heap);

    HandleScope scope(i_isolate);
    while (heap->OldGenerationSizeOfObjects() <
           heap->MaxOldGenerationSize() * 0.9) {
      factory->NewFixedArray(100, AllocationType::kOld);
    }
    {
      int initial_ms_count = heap->ms_count();
      int ineffective_ms_start = initial_ms_count;
      while (heap->ms_count() < initial_ms_count + 10) {
        HandleScope inner_scope(i_isolate);
        factory->NewFixedArray(30000, AllocationType::kOld);
        if (heap->tracer()->AverageMarkCompactMutatorUtilization() >= 0.3) {
          ineffective_ms_start = heap->ms_count() + 1;
        }
      }
      int consecutive_ineffective_ms = heap->ms_count() - ineffective_ms_start;
      CHECK_IMPLIES(
          consecutive_ineffective_ms >= 4,
          heap->tracer()->AverageMarkCompactMutatorUtilization() >= 0.3);
    }
  }
  isolate->Dispose();
}

UNINITIALIZED_TEST(OutOfMemoryIneffectiveGCRunningJS) {
  if (!v8_flags.detect_ineffective_gcs_near_heap_limit) return;
  if (v8_flags.stress_incremental_marking) return;

  v8_flags.max_old_space_size = 10;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);
  oom_isolate = i_isolate;

  isolate->SetOOMErrorHandler(OOMCallback);

  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);
  v8::Context::New(isolate)->Enter();

  // Test that source positions are not collected as part of a failing GC, which
  // will fail as allocation is disallowed. If the test works, this should call
  // OOMCallback and terminate without crashing.
  CompileRun(R"javascript(
      var array = [];
      for(var i = 20000; i < 40000; ++i) {
        array.push(new Array(i));
      }
      )javascript");

  FATAL("Should not get here as OOMCallback should be called");
}

HEAP_TEST(Regress779503) {
  // The following regression test ensures that the Scavenger does not allocate
  // over invalid slots. More specific, the Scavenger should not sweep a page
  // that it currently processes because it might allocate over the currently
  // processed slot.
  if (v8_flags.single_generation) return;
  v8_flags.stress_concurrent_allocation = false;  // For SealCurrentObjects.
  const int kArraySize = 2048;
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = CcTest::heap();
  heap::SealCurrentObjects(heap);
  {
    HandleScope handle_scope(isolate);
    // The byte array filled with kHeapObjectTag ensures that we cannot read
    // from the slot again and interpret it as heap value. Doing so will crash.
    DirectHandle<ByteArray> byte_array =
        isolate->factory()->NewByteArray(kArraySize);
    CHECK(HeapLayout::InYoungGeneration(*byte_array));
    for (int i = 0; i < kArraySize; i++) {
      byte_array->set(i, kHeapObjectTag);
    }

    {
      HandleScope new_scope(isolate);
      // The FixedArray in old space serves as space for slots.
      DirectHandle<FixedArray> fixed_array =
          isolate->factory()->NewFixedArray(kArraySize, AllocationType::kOld);
      CHECK(!HeapLayout::InYoungGeneration(*fixed_array));
      for (int i = 0; i < kArraySize; i++) {
        fixed_array->set(i, *byte_array);
      }
    }
    // Delay sweeper tasks to allow the scavenger to sweep the page it is
    // currently scavenging.
    heap->delay_sweeper_tasks_for_testing_ = true;
    heap::InvokeMajorGC(heap);
    CHECK(!HeapLayout::InYoungGeneration(*byte_array));
  }
  // Scavenging and sweeping the same page will crash as slots will be
  // overridden.
  heap::InvokeMinorGC(heap);
  heap->delay_sweeper_tasks_for_testing_ = false;
}

struct OutOfMemoryState {
  Heap* heap;
  bool oom_triggered;
  size_t old_generation_capacity_at_oom;
  size_t memory_allocator_size_at_oom;
  size_t new_space_capacity_at_oom;
  size_t new_lo_space_size_at_oom;
  size_t current_heap_limit;
  size_t initial_heap_limit;
};

size_t NearHeapLimitCallback(void* raw_state, size_t current_heap_limit,
                             size_t initial_heap_limit) {
  OutOfMemoryState* state = static_cast<OutOfMemoryState*>(raw_state);
  Heap* heap = state->heap;
  state->oom_triggered = true;
  state->old_generation_capacity_at_oom = heap->OldGenerationCapacity();
  state->memory_allocator_size_at_oom = heap->memory_allocator()->Size();
  state->new_space_capacity_at_oom =
      heap->new_space() ? heap->new_space()->Capacity() : 0;
  state->new_lo_space_size_at_oom =
      heap->new_lo_space() ? heap->new_lo_space()->Size() : 0;
  state->current_heap_limit = current_heap_limit;
  state->initial_heap_limit = initial_heap_limit;
  return initial_heap_limit + 100 * MB;
}

size_t MemoryAllocatorSizeFromHeapCapacity(size_t capacity) {
  // Size to capacity factor.
  double factor = PageMetadata::kPageSize * 1.0 /
                  MemoryChunkLayout::AllocatableMemoryInDataPage();
  // Some tables (e.g. deoptimization table) are allocated directly with the
  // memory allocator. Allow some slack to account for them.
  size_t slack = 5 * MB;
  return static_cast<size_t>(capacity * factor) + slack;
}

UNINITIALIZED_TEST(OutOfMemorySmallObjects) {
  if (v8_flags.stress_incremental_marking) return;
#ifdef VERIFY_HEAP
  if (v8_flags.verify_heap) return;
#endif
  const size_t kOldGenerationLimit = 50 * MB;
  v8_flags.max_old_space_size = kOldGenerationLimit / MB;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);
  Heap* heap = i_isolate->heap();
  Factory* factory = i_isolate->factory();
  OutOfMemoryState state;
  state.heap = heap;
  state.oom_triggered = false;
  heap->AddNearHeapLimitCallback(NearHeapLimitCallback, &state);
  {
    PtrComprCageAccessScope ptr_compr_cage_access_scope(i_isolate);

    v8::Isolate::Scope isolate_scope(isolate);
    HandleScope handle_scope(i_isolate);
    while (!state.oom_triggered) {
      factory->NewFixedArray(100);
    }
  }
  CHECK_LE(state.old_generation_capacity_at_oom,
           kOldGenerationLimit + heap->MaxSemiSpaceSize());
  CHECK_LE(kOldGenerationLimit,
           state.old_generation_capacity_at_oom + heap->MaxSemiSpaceSize());
  CHECK_LE(
      state.memory_allocator_size_at_oom,
      MemoryAllocatorSizeFromHeapCapacity(state.old_generation_capacity_at_oom +
                                          2 * state.new_space_capacity_at_oom));
  isolate->Dispose();
}

UNINITIALIZED_TEST(OutOfMemoryLargeObjects) {
  if (v8_flags.stress_incremental_marking) return;
#ifdef VERIFY_HEAP
  if (v8_flags.verify_heap) return;
#endif
  const size_t kOldGenerationLimit = 50 * MB;
  v8_flags.max_old_space_size = kOldGenerationLimit / MB;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);
  Heap* heap = i_isolate->heap();
  Factory* factory = i_isolate->factory();
  OutOfMemoryState state;
  state.heap = heap;
  state.oom_triggered = false;
  heap->AddNearHeapLimitCallback(NearHeapLimitCallback, &state);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    PtrComprCageAccessScope ptr_compr_cage_access_scope(i_isolate);
    const int kFixedArrayLength = 1000000;
    {
      HandleScope handle_scope(i_isolate);
      while (!state.oom_triggered) {
        factory->NewFixedArray(kFixedArrayLength);
      }
    }
    CHECK_LE(state.old_generation_capacity_at_oom,
             kOldGenerationLimit + state.new_space_capacity_at_oom +
                 state.new_lo_space_size_at_oom +
                 FixedArray::SizeFor(kFixedArrayLength));
    CHECK_LE(kOldGenerationLimit, state.old_generation_capacity_at_oom +
                                      state.new_space_capacity_at_oom +
                                      state.new_lo_space_size_at_oom +
                                      FixedArray::SizeFor(kFixedArrayLength));
    CHECK_LE(state.memory_allocator_size_at_oom,
             MemoryAllocatorSizeFromHeapCapacity(
                 state.old_generation_capacity_at_oom +
                 2 * state.new_space_capacity_at_oom +
                 state.new_lo_space_size_at_oom));
  }
  isolate->Dispose();
}

UNINITIALIZED_TEST(RestoreHeapLimit) {
  if (v8_flags.stress_incremental_marking) return;
#ifdef VERIFY_HEAP
  if (v8_flags.verify_heap) return;
#endif
  ManualGCScope manual_gc_scope;
  const siz
"""


```