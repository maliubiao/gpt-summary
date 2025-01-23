Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from `v8/src/heap/sweeper.cc`. I need to analyze the code and explain its purpose within the V8 garbage collection process.

Here's a breakdown of the thought process:

1. **Identify the core class:** The code is part of the `Sweeper` class. The name itself suggests its primary role is to "sweep" memory.

2. **Recognize the context:** The code deals with heap management (`v8/src/heap`) and garbage collection. The presence of terms like "minor sweeping," "major sweeping," "promoted pages," "free space," and "remembered sets" reinforces this.

3. **Break down the functionality by methods:** Go through the methods and understand what each one does:
    * `FinishMinorJobs`, `EnsureMinorCompleted`:  Related to completing minor garbage collection sweeps.
    * `AreMinorSweeperTasksRunning`, `AreMajorSweeperTasksRunning`, `UsingMajorSweeperTasks`: Checking the status of sweeper tasks.
    * `FreeAndProcessFreedMemory`:  The core of freeing memory and potentially zeroing it or discarding it.
    * `ComputeDiscardMemoryArea`, `ZeroOrDiscardUnusedMemory`:  Helper functions for managing unused memory regions.
    * `CleanupRememberedSetEntriesForFreedMemory`, `CleanupTypedSlotsInFreeMemory`:  Maintaining the integrity of remembered sets and typed slots after freeing memory.
    * `ClearMarkBitsAndHandleLivenessStatistics`:  Resetting mark bits and updating page statistics.
    * `RawSweep`: The main function performing the sweeping process on a single page.
    * `IsIteratingPromotedPages`, `ContributeAndWaitForPromotedPagesIteration`, `NotifyPromotedPageIterationFinished`: Managing the iteration of pages that have been promoted from young generation.
    * `ConcurrentMinorSweepingPageCount`, `ConcurrentMajorSweepingPageCount`:  Getting the number of pages being swept concurrently.
    * `ParallelSweepSpace`, `EnsurePageIsSwept`, `WaitForPageToBeSwept`, `TryRemoveSweepingPageSafe`, `TryRemovePromotedPageSafe`:  Managing the parallel execution of sweeping tasks and ensuring pages are swept.
    * `AddPage`, `AddNewSpacePage`, `AddPageImpl`, `AddPromotedPage`: Adding pages to be swept.
    * `PrepareToBeSweptPage`, `PrepareToBeIteratedPromotedPage`: Setting up a page for sweeping or iteration.
    * `GetSweepingPageSafe`, `GetPromotedPageSafe`:  Retrieving pages to be swept.
    * `GetTracingScope`:  For performance tracing.
    * `IsSweepingDoneForSpace`, `AddSweptPage`, `ShouldRefillFreelistForSpace`:  Tracking the progress of sweeping.
    * `SweepEmptyNewSpacePage`: Handling empty pages in the young generation.
    * `PauseMajorSweepingScope`:  A utility for temporarily pausing major sweeping.
    * `GetTraceIdForFlowEvent`:  Getting trace IDs for flow events.
    * `HasUnsweptPagesForMajorSweeping`: (DEBUG) Checking for unswept pages.

4. **Identify key data structures:** Note the use of `sweeping_list_`, `sweeping_list_for_promoted_page_iteration_`, `swept_list_`, `minor_sweeping_state_`, and `major_sweeping_state_`. These help in understanding the organization and state of the sweeping process.

5. **Determine the scope of responsibility:** The `Sweeper` is responsible for reclaiming dead objects' memory in various heap spaces during garbage collection. It operates both concurrently and in the main thread.

6. **Address specific instructions from the prompt:**
    * **Functionality Listing:**  List the identified functionalities in clear, concise points.
    * **Torque:** The prompt provides the information that `.tq` indicates Torque. Since the file ends in `.cc`, it's not Torque.
    * **JavaScript Relation:** Think about how sweeping relates to JavaScript. JavaScript's garbage collection is an implementation detail, but sweeping is a part of it. Illustrate with a simple JavaScript example where objects become unreachable and are subject to garbage collection.
    * **Code Logic Reasoning:** Select a simpler function like `FreeAndProcessFreedMemory` and explain its input, process, and output. Make a reasonable assumption for the input values.
    * **Common Programming Errors:** Consider errors that relate to memory management, such as memory leaks or dangling pointers (although these are less directly caused by the sweeper itself, but are the *result* of incorrect object lifecycle management that the sweeper addresses).
    * **Overall Functionality (Part 2):** Synthesize the detailed analysis into a high-level summary of the `Sweeper`'s role.

7. **Structure the response:** Organize the information logically with clear headings and bullet points for readability.

8. **Review and refine:** Ensure the explanation is accurate, comprehensive, and addresses all aspects of the prompt. Double-check the code logic reasoning and examples for clarity and correctness.
## v8/src/heap/sweeper.cc 功能列表

这个 C++ 源代码文件 `v8/src/heap/sweeper.cc` 实现了 V8 引擎中负责 **堆内存清理（Sweeping）** 的核心功能。  Sweeping 是垃圾回收（Garbage Collection, GC）过程中的一个重要阶段，它的主要任务是回收在标记阶段被识别为不可达（不再被使用的）对象的内存空间。

具体来说，`v8/src/heap/sweeper.cc` 的功能包括：

* **管理不同内存空间的清理工作:**  针对新生代（New Space）、老生代（Old Space）、代码空间（Code Space）、共享空间（Shared Space）等不同的堆内存空间，协调和执行清理操作。
* **维护待清理页面的列表:**  `sweeping_list_` 等数据结构用于存储需要进行清理的内存页面的信息。
* **执行实际的内存释放操作:**  `FreeAndProcessFreedMemory` 函数负责将不可达对象占用的内存释放回操作系统或 V8 的空闲列表。
* **处理已释放内存的后续操作:**  例如，可以使用 `AtomicZapBlock` 填充已释放的内存以帮助调试，或者使用 `ZeroOrDiscardUnusedMemory` 将大块的未使用内存归还给操作系统，从而减少内存占用。
* **清理 Remembered Sets 中的条目:**  Remembered Sets 用于记录跨代或跨空间的指针引用。当内存被释放时，需要清理指向这些已释放内存的 Remembered Sets 条目，以避免悬挂指针。相关函数有 `CleanupRememberedSetEntriesForFreedMemory`。
* **清理类型化槽（Typed Slots）中的条目:**  类型化槽存储了带有类型信息的指针。释放内存时，需要清理指向已释放内存的类型化槽，相关函数有 `CleanupTypedSlotsInFreeMemory`。
* **清除标记位:**  在清理完成后，需要清除内存页面的标记位，以便进行下一次垃圾回收。相关函数是 `ClearMarkBitsAndHandleLivenessStatistics`。
* **支持并发清理:**  代码中涉及到 `minor_sweeping_state_` 和 `major_sweeping_state_`，以及 `TryRemoveSweepingPageSafe` 等函数，表明 Sweeper 支持并发执行清理任务，以减少 GC 造成的应用停顿。
* **管理晋升页面的迭代:**  对于从新生代晋升到老生代的页面，可能需要进行特殊的迭代处理，相关函数有 `AddPromotedPage` 和 `ContributeAndWaitForPromotedPagesIteration`。
* **处理新生代空页:**  `SweepEmptyNewSpacePage` 专门处理新生代的空页面，可以直接释放并归还。
* **跟踪清理进度:**  通过 `IsSweepingDoneForSpace` 等函数可以检查特定内存空间的清理是否完成。
* **性能统计和跟踪:**  使用 `GCTracer` 进行性能跟踪，例如 `GetTracingScope` 和 `GetTraceIdForFlowEvent`。

## 关于文件后缀名和 Torque

如果 `v8/src/heap/sweeper.cc` 以 `.tq` 结尾，那么它确实是一个 **V8 Torque 源代码** 文件。 Torque 是 V8 开发的一种类型化的中间语言，用于生成高效的 C++ 代码。

由于当前提供的代码片段是以 `.cc` 结尾，所以它是一个 **C++ 源代码** 文件。

## 与 JavaScript 的关系

`v8/src/heap/sweeper.cc` 的功能与 JavaScript 的 **垃圾回收机制** 直接相关。当 JavaScript 代码创建对象时，V8 会在堆内存中分配空间。当这些对象不再被 JavaScript 代码引用时，垃圾回收器会识别并回收它们占用的内存。 Sweeper 就是这个回收过程中的关键组件，负责将不再使用的内存释放出来，供新的对象分配使用。

**JavaScript 示例：**

```javascript
function createObjects() {
  let obj1 = { data: "这是一个对象" };
  let obj2 = { ref: obj1 };
  let obj3 = { value: 123 };

  // ... 一段时间后 ...

  // obj1 和 obj2 仍然可达，不会被回收
  console.log(obj2.ref.data);

  // 解除 obj3 的引用
  obj3 = null;

  // 此时 obj3 指向的对象变得不可达，可能会被垃圾回收器回收，
  // Sweeper 组件会负责释放其占用的内存。
}

createObjects();
```

在这个例子中，当 `obj3 = null` 执行后，原来 `obj3` 引用的对象变得不可达。在未来的垃圾回收周期中，标记阶段会识别出这个对象不再被引用，而 Sweeper 组件会负责将该对象占用的内存空间释放出来。

## 代码逻辑推理 (假设输入与输出)

让我们以 `FreeAndProcessFreedMemory` 函数为例进行代码逻辑推理。

**假设输入：**

* `free_start`: 内存块起始地址 `0x1000`
* `free_end`: 内存块结束地址 `0x10A0`
* `page`: 指向包含此内存块的 `PageMetadata` 对象的指针
* `space`: 指向包含此内存块的 `Space` 对象的指针
* `free_space_treatment_mode`: `FreeSpaceTreatmentMode::kZapFreeSpace` (填充已释放内存)
* `should_reduce_memory`: `true`

**代码逻辑推理：**

1. **检查边界:** `CHECK_GT(free_end, free_start)` 确保 `free_end` 大于 `free_start`，即要释放的内存块大小大于 0。
2. **计算大小:** `size_t size = static_cast<size_t>(free_end - free_start);` 计算要释放的内存块大小，这里是 `0x10A0 - 0x1000 = 160` 字节。
3. **处理释放空间:**
   * 如果 `free_space_treatment_mode` 是 `kZapFreeSpace`，则使用 `AtomicZapBlock(free_start, size)` 将从 `0x1000` 开始的 `160` 字节内存填充为特定的 "zap" 值（用于调试）。
4. **实际释放内存:** `reinterpret_cast<PagedSpaceBase*>(space)->FreeDuringSweep(free_start, size);`  调用 `PagedSpaceBase` 对象的 `FreeDuringSweep` 方法，将从 `0x1000` 开始的 `160` 字节内存释放回该 `space` 的空闲列表。 `freed_bytes` 将会记录实际释放的字节数。
5. **减少内存占用 (如果需要):**  由于 `should_reduce_memory` 为 `true`，会调用 `ZeroOrDiscardUnusedMemory(page, free_start, size)`，尝试将释放的内存区域归还给操作系统。这通常针对较大的内存块，可能会涉及系统调用。
6. **清理标记位图:** 如果启用了 `v8_flags.sticky_mark_bits`，则会清除释放内存区域对应的标记位图中的位。
7. **返回释放字节数:** 函数最终返回 `freed_bytes`。

**假设输出：**

* 函数返回的 `freed_bytes` 值为 `160`。
* 从 `0x1000` 到 `0x10A0` 的内存区域被填充了 "zap" 值。
* 该内存区域被添加到 `space` 的空闲列表中。
* 如果释放的内存块足够大，并且操作系统支持，该内存区域可能已被归还给操作系统。

## 涉及用户常见的编程错误

Sweeper 本身是 V8 引擎的内部组件，用户一般不会直接操作它。但是，Sweeper 的存在是为了解决用户在 JavaScript 编程中容易犯的与 **内存管理** 相关的错误，最常见的就是 **内存泄漏**。

**常见编程错误示例 (导致需要 Sweeper 清理)：**

```javascript
let globalArray = [];

function createLeakingObject() {
  let obj = { data: new Array(1000000) }; // 创建一个占用大量内存的对象
  globalArray.push(obj); // 将对象添加到全局数组，导致无法被回收
}

for (let i = 0; i < 100; i++) {
  createLeakingObject();
}

// 即使 createLeakingObject 函数执行完毕，
// 创建的许多大对象仍然被 globalArray 引用，无法被回收，
// 最终会导致内存占用不断增加。
```

在这个例子中，即使 `createLeakingObject` 函数的局部变量 `obj` 超出了作用域，由于 `obj` 被添加到了全局数组 `globalArray` 中，仍然存在引用指向这些对象。 这就导致这些对象占用的内存无法被垃圾回收器回收，从而造成内存泄漏。 Sweeper 的作用就是清理那些 **不再被 JavaScript 代码引用** 的对象所占用的内存。

另一个常见的错误是 **意外地保持对不再需要的对象的引用**，例如闭包中的变量引用：

```javascript
function createClosure() {
  let largeData = new Array(1000000);
  return function() {
    console.log("Closure executed");
    // 即使 largeData 在外部已经不再需要，
    // 由于闭包的存在，largeData 仍然会被引用，无法被回收。
    console.log(largeData.length);
  };
}

let myClosure = createClosure();
myClosure();

// 即使 myClosure 之后不再使用，
// largeData 仍然可能因为闭包而被保留在内存中。
```

虽然 Sweeper 无法阻止用户编写导致内存泄漏的代码，但它是 V8 引擎中回收这些泄漏内存的关键组成部分，保证了 JavaScript 应用程序能够持续运行，而不会因为无限制的内存增长而崩溃。

## 第 2 部分功能归纳

总而言之，`v8/src/heap/sweeper.cc` 的核心功能是 **实现 V8 垃圾回收机制中的内存清理阶段**。它负责：

* **识别并释放不可达对象占用的内存空间。**
* **管理不同内存空间的清理流程。**
* **维护清理过程中的数据结构，例如待清理页面列表。**
* **处理已释放内存的后续操作，例如填充或归还操作系统。**
* **维护 Remembered Sets 和类型化槽的正确性。**
* **支持并发清理以提高性能。**
* **与 V8 的其他垃圾回收组件协同工作，完成整个内存回收过程。**

这个组件对于 V8 引擎的稳定性和性能至关重要，它确保了 JavaScript 应用程序可以有效地管理内存，避免因内存泄漏而导致的问题。

### 提示词
```
这是目录为v8/src/heap/sweeper.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/sweeper.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
ate_.JoinSweeping();
  // All jobs are done but we still remain in sweeping state here.
  DCHECK(minor_sweeping_in_progress());

  CHECK(sweeping_list_[GetSweepSpaceIndex(kNewSpace)].empty());
  DCHECK(IsSweepingDoneForSpace(kNewSpace));

  DCHECK_EQ(promoted_pages_for_iteration_count_,
            iterated_promoted_pages_count_);
  CHECK(sweeping_list_for_promoted_page_iteration_.empty());
}

void Sweeper::EnsureMinorCompleted() {
  if (!minor_sweeping_in_progress()) return;

  DCHECK(!minor_sweeping_state_.should_reduce_memory());
  FinishMinorJobs();
  minor_sweeping_state_.FinishSweeping();

  promoted_pages_for_iteration_count_ = 0;
  iterated_promoted_pages_count_ = 0;
}

bool Sweeper::AreMinorSweeperTasksRunning() const {
  return minor_sweeping_state_.HasActiveJob();
}

bool Sweeper::AreMajorSweeperTasksRunning() const {
  return major_sweeping_state_.HasActiveJob();
}

bool Sweeper::UsingMajorSweeperTasks() const {
  return major_sweeping_state_.HasValidJob();
}

V8_INLINE size_t Sweeper::FreeAndProcessFreedMemory(
    Address free_start, Address free_end, PageMetadata* page, Space* space,
    FreeSpaceTreatmentMode free_space_treatment_mode,
    bool should_reduce_memory) {
  CHECK_GT(free_end, free_start);
  size_t freed_bytes = 0;
  size_t size = static_cast<size_t>(free_end - free_start);
  if (free_space_treatment_mode == FreeSpaceTreatmentMode::kZapFreeSpace) {
    CodePageMemoryModificationScopeForDebugging memory_modification_scope(page);
    AtomicZapBlock(free_start, size);
  }
  freed_bytes = reinterpret_cast<PagedSpaceBase*>(space)->FreeDuringSweep(
      free_start, size);
  if (should_reduce_memory) {
    ZeroOrDiscardUnusedMemory(page, free_start, size);
  }

  if (v8_flags.sticky_mark_bits) {
    // Clear the bitmap, since fillers or slack may still be marked from black
    // allocation.
    page->marking_bitmap()->ClearRange<AccessMode::NON_ATOMIC>(
        MarkingBitmap::AddressToIndex(free_start),
        MarkingBitmap::AddressToIndex(free_end));
  }

  return freed_bytes;
}

// static
std::optional<base::AddressRegion> Sweeper::ComputeDiscardMemoryArea(
    Address start, Address end) {
  const size_t page_size = MemoryAllocator::GetCommitPageSize();
  const Address discard_start = RoundUp(start, page_size);
  const Address discard_end = RoundDown(end, page_size);

  if (discard_start < discard_end) {
    return base::AddressRegion(discard_start, discard_end - discard_start);
  } else {
    return {};
  }
}

void Sweeper::ZeroOrDiscardUnusedMemory(PageMetadata* page, Address addr,
                                        size_t size) {
  if (size < FreeSpace::kSize) {
    return;
  }

  const Address unused_start = addr + FreeSpace::kSize;
  DCHECK(page->ContainsLimit(unused_start));
  const Address unused_end = addr + size;
  DCHECK(page->ContainsLimit(unused_end));

  std::optional<RwxMemoryWriteScope> scope;
  if (page->Chunk()->executable()) {
    scope.emplace("For zeroing unused memory.");
  }
  const std::optional<base::AddressRegion> discard_area =
      ComputeDiscardMemoryArea(unused_start, unused_end);

#if !defined(V8_OS_WIN)
  constexpr bool kDiscardEmptyPages = true;
#else
  // Discarding memory on Windows does not decommit the memory and does not
  // contribute to reduce the memory footprint. On the other hand, these
  // calls become expensive the more memory is allocated in the system and
  // can result in hangs. Thus, it is better to not discard on Windows.
  constexpr bool kDiscardEmptyPages = false;
#endif  // !defined(V8_OS_WIN)

  if (kDiscardEmptyPages && discard_area) {
    {
      v8::PageAllocator* page_allocator =
          heap_->memory_allocator()->page_allocator(page->owner_identity());
      DiscardSealedMemoryScope discard_scope("Discard unused memory");
      CHECK(page_allocator->DiscardSystemPages(
          reinterpret_cast<void*>(discard_area->begin()),
          discard_area->size()));
    }

    if (v8_flags.zero_unused_memory) {
      // Now zero unused memory right before and after the discarded OS pages to
      // help with OS page compression.
      memset(reinterpret_cast<void*>(unused_start), 0,
             discard_area->begin() - unused_start);
      memset(reinterpret_cast<void*>(discard_area->end()), 0,
             unused_end - discard_area->end());
    }
  } else if (v8_flags.zero_unused_memory) {
    // Unused memory does not span a full OS page. Simply clear all of the
    // unused memory. This helps with OS page compression.
    memset(reinterpret_cast<void*>(unused_start), 0, unused_end - unused_start);
  }
}

V8_INLINE void Sweeper::CleanupRememberedSetEntriesForFreedMemory(
    Address free_start, Address free_end, PageMetadata* page,
    bool record_free_ranges, TypedSlotSet::FreeRangesMap* free_ranges_map,
    SweepingMode sweeping_mode) {
  DCHECK_LE(free_start, free_end);
  if (sweeping_mode == SweepingMode::kEagerDuringGC) {
    // New space and in consequence the old-to-new remembered set is always
    // empty after a full GC, so we do not need to remove from it after the full
    // GC. However, we wouldn't even be allowed to do that, since the main
    // thread then owns the old-to-new remembered set. Removing from it from a
    // sweeper thread would race with the main thread.
    RememberedSet<OLD_TO_NEW>::RemoveRange(page, free_start, free_end,
                                           SlotSet::KEEP_EMPTY_BUCKETS);
    RememberedSet<OLD_TO_NEW_BACKGROUND>::RemoveRange(
        page, free_start, free_end, SlotSet::KEEP_EMPTY_BUCKETS);

    // While we only add old-to-old slots on live objects, we can still end up
    // with old-to-old slots in free memory with e.g. right-trimming of objects.
    RememberedSet<OLD_TO_OLD>::RemoveRange(page, free_start, free_end,
                                           SlotSet::KEEP_EMPTY_BUCKETS);
    RememberedSet<TRUSTED_TO_TRUSTED>::RemoveRange(page, free_start, free_end,
                                                   SlotSet::KEEP_EMPTY_BUCKETS);
  } else {
    DCHECK_NULL(page->slot_set<OLD_TO_OLD>());
    DCHECK_NULL(page->slot_set<TRUSTED_TO_TRUSTED>());
  }

  // Old-to-shared isn't reset after a full GC, so needs to be cleaned both
  // during and after a full GC.
  RememberedSet<OLD_TO_SHARED>::RemoveRange(page, free_start, free_end,
                                            SlotSet::KEEP_EMPTY_BUCKETS);
  RememberedSet<TRUSTED_TO_SHARED_TRUSTED>::RemoveRange(
      page, free_start, free_end, SlotSet::KEEP_EMPTY_BUCKETS);

  if (record_free_ranges) {
    MemoryChunk* chunk = page->Chunk();
    free_ranges_map->insert(std::pair<uint32_t, uint32_t>(
        static_cast<uint32_t>(chunk->Offset(free_start)),
        static_cast<uint32_t>(chunk->Offset(free_end))));
  }
}

void Sweeper::CleanupTypedSlotsInFreeMemory(
    PageMetadata* page, const TypedSlotSet::FreeRangesMap& free_ranges_map,
    SweepingMode sweeping_mode) {
  // No support for typed trusted-to-shared-trusted pointers.
  DCHECK_NULL(page->typed_slot_set<TRUSTED_TO_SHARED_TRUSTED>());

  if (sweeping_mode == SweepingMode::kEagerDuringGC) {
    page->ClearTypedSlotsInFreeMemory<OLD_TO_NEW>(free_ranges_map);

    // Typed old-to-old slot sets are only ever recorded in live code objects.
    // Also code objects are never right-trimmed, so there cannot be any slots
    // in a free range.
    page->AssertNoTypedSlotsInFreeMemory<OLD_TO_OLD>(free_ranges_map);
    page->ClearTypedSlotsInFreeMemory<OLD_TO_SHARED>(free_ranges_map);
    return;
  }

  DCHECK_EQ(sweeping_mode, SweepingMode::kLazyOrConcurrent);

  // After a full GC there are no old-to-new typed slots. The main thread
  // could create new slots but not in a free range.
  page->AssertNoTypedSlotsInFreeMemory<OLD_TO_NEW>(free_ranges_map);
  DCHECK_NULL(page->typed_slot_set<OLD_TO_OLD>());
  page->ClearTypedSlotsInFreeMemory<OLD_TO_SHARED>(free_ranges_map);
}

void Sweeper::ClearMarkBitsAndHandleLivenessStatistics(PageMetadata* page,
                                                       size_t live_bytes) {
  if (!v8_flags.sticky_mark_bits) {
    page->marking_bitmap()->Clear<AccessMode::NON_ATOMIC>();
  }
  // Keep the old live bytes counter of the page until RefillFreeList, where
  // the space size is refined.
  // The allocated_bytes() counter is precisely the total size of objects.
  DCHECK_EQ(live_bytes, page->allocated_bytes());
}

void Sweeper::RawSweep(PageMetadata* p,
                       FreeSpaceTreatmentMode free_space_treatment_mode,
                       SweepingMode sweeping_mode, bool should_reduce_memory) {
  DCHECK_NOT_NULL(p);
  Space* space = p->owner();
  DCHECK_NOT_NULL(space);
  DCHECK(space->identity() == OLD_SPACE || space->identity() == CODE_SPACE ||
         space->identity() == SHARED_SPACE ||
         space->identity() == TRUSTED_SPACE ||
         space->identity() == SHARED_TRUSTED_SPACE ||
         (space->identity() == NEW_SPACE && v8_flags.minor_ms));
  DCHECK(!p->Chunk()->IsEvacuationCandidate());
  DCHECK(!p->SweepingDone());
  DCHECK(!p->Chunk()->IsFlagSet(MemoryChunk::BLACK_ALLOCATED));
  DCHECK_IMPLIES(space->identity() == NEW_SPACE,
                 !heap_->incremental_marking()->IsMinorMarking());
  DCHECK_IMPLIES(space->identity() != NEW_SPACE,
                 !heap_->incremental_marking()->IsMajorMarking());

  // Phase 1: Prepare the page for sweeping.

  std::optional<ActiveSystemPages> active_system_pages_after_sweeping;
  if (should_reduce_memory) {
    // Only decrement counter when we discard unused system pages.
    active_system_pages_after_sweeping = ActiveSystemPages();
    active_system_pages_after_sweeping->Init(
        sizeof(MemoryChunk), MemoryAllocator::GetCommitPageSizeBits(),
        PageMetadata::kPageSize);
  }

  // Phase 2: Free the non-live memory and clean-up the regular remembered set
  // entires.

  // Liveness and freeing statistics.
  size_t live_bytes = 0;

  // Promoted pages have no interesting remebered sets yet.
  bool record_free_ranges = (p->typed_slot_set<OLD_TO_NEW>() != nullptr ||
                             p->typed_slot_set<OLD_TO_OLD>() != nullptr ||
                             p->typed_slot_set<OLD_TO_SHARED>() != nullptr) ||
                            DEBUG_BOOL;

  // The free ranges map is used for filtering typed slots.
  TypedSlotSet::FreeRangesMap free_ranges_map;

  // Iterate over the page using the live objects and free the memory before
  // the given live object.
  Address free_start = p->area_start();

  for (auto [object, size] : LiveObjectRange(p)) {
    DCHECK(marking_state_->IsMarked(object));
    Address free_end = object.address();
    if (free_end != free_start) {
      FreeAndProcessFreedMemory(free_start, free_end, p, space,
                                free_space_treatment_mode,
                                should_reduce_memory);
      CleanupRememberedSetEntriesForFreedMemory(
          free_start, free_end, p, record_free_ranges, &free_ranges_map,
          sweeping_mode);
    }
    live_bytes += size;
    free_start = free_end + size;

    if (active_system_pages_after_sweeping) {
      MemoryChunk* chunk = p->Chunk();
      active_system_pages_after_sweeping->Add(
          chunk->Offset(free_end), chunk->Offset(free_start),
          MemoryAllocator::GetCommitPageSizeBits());
    }
  }

  // If there is free memory after the last live object also free that.
  Address free_end = p->area_end();
  if (free_end != free_start) {
    FreeAndProcessFreedMemory(free_start, free_end, p, space,
                              free_space_treatment_mode, should_reduce_memory);
    CleanupRememberedSetEntriesForFreedMemory(free_start, free_end, p,
                                              record_free_ranges,
                                              &free_ranges_map, sweeping_mode);
  }

  // Phase 3: Post process the page.
  p->ReleaseSlotSet(SURVIVOR_TO_EXTERNAL_POINTER);
  CleanupTypedSlotsInFreeMemory(p, free_ranges_map, sweeping_mode);
  ClearMarkBitsAndHandleLivenessStatistics(p, live_bytes);

  if (active_system_pages_after_sweeping) {
    // Decrement accounted memory for discarded memory.
    PagedSpaceBase* paged_space = static_cast<PagedSpaceBase*>(p->owner());
    paged_space->ReduceActiveSystemPages(p,
                                         *active_system_pages_after_sweeping);
  }
}

bool Sweeper::IsIteratingPromotedPages() const {
  return promoted_page_iteration_in_progress_.load(std::memory_order_acquire);
}

void Sweeper::ContributeAndWaitForPromotedPagesIteration() {
  main_thread_local_sweeper_.ContributeAndWaitForPromotedPagesIteration();
}

void Sweeper::NotifyPromotedPageIterationFinished(MutablePageMetadata* chunk) {
  if (++iterated_promoted_pages_count_ == promoted_pages_for_iteration_count_) {
    NotifyPromotedPagesIterationFinished();
  }
  chunk->set_concurrent_sweeping_state(
      PageMetadata::ConcurrentSweepingState::kDone);
  base::MutexGuard guard(&mutex_);
  cv_page_swept_.NotifyAll();
}

void Sweeper::NotifyPromotedPagesIterationFinished() {
  DCHECK_EQ(iterated_promoted_pages_count_,
            promoted_pages_for_iteration_count_);
  base::MutexGuard guard(&promoted_pages_iteration_notification_mutex_);
  promoted_page_iteration_in_progress_.store(false, std::memory_order_release);
  promoted_pages_iteration_notification_variable_.NotifyAll();
}

size_t Sweeper::ConcurrentMinorSweepingPageCount() {
  DCHECK(minor_sweeping_in_progress());
  base::MutexGuard guard(&mutex_);
  return sweeping_list_for_promoted_page_iteration_.size() +
         sweeping_list_[GetSweepSpaceIndex(NEW_SPACE)].size();
}

size_t Sweeper::ConcurrentMajorSweepingPageCount() {
  DCHECK(major_sweeping_in_progress());
  base::MutexGuard guard(&mutex_);
  size_t count = 0;
  for (int i = 0; i < kNumberOfSweepingSpaces; i++) {
    if (i == GetSweepSpaceIndex(NEW_SPACE)) continue;
    count += sweeping_list_[i].size();
  }
  return count;
}

bool Sweeper::ParallelSweepSpace(AllocationSpace identity,
                                 SweepingMode sweeping_mode,
                                 uint32_t max_pages) {
  DCHECK_IMPLIES(identity == NEW_SPACE, heap_->IsMainThread());
  return main_thread_local_sweeper_.ParallelSweepSpace(identity, sweeping_mode,
                                                       max_pages);
}

void Sweeper::EnsurePageIsSwept(PageMetadata* page) {
  DCHECK(heap_->IsMainThread());

  auto concurrent_sweeping_state = page->concurrent_sweeping_state();
  DCHECK_IMPLIES(!sweeping_in_progress(),
                 concurrent_sweeping_state ==
                     PageMetadata::ConcurrentSweepingState::kDone);
  if (concurrent_sweeping_state ==
      PageMetadata::ConcurrentSweepingState::kDone) {
    DCHECK(page->SweepingDone());
    return;
  }

  AllocationSpace space = page->owner_identity();
  DCHECK(IsValidSweepingSpace(space));

  auto scope_id = GetTracingScope(space, true);
  TRACE_GC_EPOCH_WITH_FLOW(
      heap_->tracer(), scope_id, ThreadKind::kMain,
      GetTraceIdForFlowEvent(scope_id),
      TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  if ((concurrent_sweeping_state ==
       PageMetadata::ConcurrentSweepingState::kPendingSweeping) &&
      TryRemoveSweepingPageSafe(space, page)) {
    // Page was successfully removed and can now be swept.
    main_thread_local_sweeper_.ParallelSweepPage(
        page, space, SweepingMode::kLazyOrConcurrent);

  } else if ((concurrent_sweeping_state ==
              PageMetadata::ConcurrentSweepingState::kPendingIteration) &&
             TryRemovePromotedPageSafe(page)) {
    // Page was successfully removed and can now be iterated.
    main_thread_local_sweeper_.ParallelIteratePromotedPage(page);
  } else {
    // Some sweeper task already took ownership of that page, wait until
    // sweeping is finished.
    WaitForPageToBeSwept(page);
  }

  CHECK(page->SweepingDone());
}

void Sweeper::WaitForPageToBeSwept(PageMetadata* page) {
  DCHECK(heap_->IsMainThread());
  DCHECK(sweeping_in_progress());

  base::MutexGuard guard(&mutex_);
  while (!page->SweepingDone()) {
    cv_page_swept_.Wait(&mutex_);
  }
}

bool Sweeper::TryRemoveSweepingPageSafe(AllocationSpace space,
                                        PageMetadata* page) {
  base::MutexGuard guard(&mutex_);
  DCHECK(IsValidSweepingSpace(space));
  int space_index = GetSweepSpaceIndex(space);
  SweepingList& sweeping_list = sweeping_list_[space_index];
  SweepingList::iterator position =
      std::find(sweeping_list.begin(), sweeping_list.end(), page);
  if (position == sweeping_list.end()) return false;
  sweeping_list.erase(position);
  if (sweeping_list.empty()) {
    has_sweeping_work_[GetSweepSpaceIndex(space)].store(
        false, std::memory_order_release);
  }
  return true;
}

bool Sweeper::TryRemovePromotedPageSafe(MutablePageMetadata* chunk) {
  base::MutexGuard guard(&mutex_);
  auto position =
      std::find(sweeping_list_for_promoted_page_iteration_.begin(),
                sweeping_list_for_promoted_page_iteration_.end(), chunk);
  if (position == sweeping_list_for_promoted_page_iteration_.end())
    return false;
  sweeping_list_for_promoted_page_iteration_.erase(position);
  return true;
}

void Sweeper::AddPage(AllocationSpace space, PageMetadata* page) {
  DCHECK_NE(NEW_SPACE, space);
  AddPageImpl(space, page);
}

void Sweeper::AddNewSpacePage(PageMetadata* page) {
  DCHECK_EQ(NEW_SPACE, page->owner_identity());
  DCHECK_LE(page->AgeInNewSpace(), v8_flags.minor_ms_max_page_age);
  size_t live_bytes = page->live_bytes();
  heap_->IncrementNewSpaceSurvivingObjectSize(live_bytes);
  heap_->IncrementYoungSurvivorsCounter(live_bytes);
  AddPageImpl(NEW_SPACE, page);
  page->IncrementAgeInNewSpace();
}

void Sweeper::AddPageImpl(AllocationSpace space, PageMetadata* page) {
  DCHECK(heap_->IsMainThread());
  DCHECK(!page->Chunk()->IsFlagSet(MemoryChunk::BLACK_ALLOCATED));
  DCHECK(IsValidSweepingSpace(space));
  DCHECK_IMPLIES(v8_flags.concurrent_sweeping && (space != NEW_SPACE),
                 !major_sweeping_state_.HasValidJob());
  DCHECK_IMPLIES(v8_flags.concurrent_sweeping,
                 !minor_sweeping_state_.HasValidJob());
  PrepareToBeSweptPage(space, page);
  DCHECK_EQ(PageMetadata::ConcurrentSweepingState::kPendingSweeping,
            page->concurrent_sweeping_state());
  sweeping_list_[GetSweepSpaceIndex(space)].push_back(page);
  has_sweeping_work_[GetSweepSpaceIndex(space)].store(
      true, std::memory_order_release);
}

void Sweeper::AddPromotedPage(MutablePageMetadata* chunk) {
  DCHECK(heap_->IsMainThread());
  DCHECK(chunk->owner_identity() == OLD_SPACE ||
         chunk->owner_identity() == LO_SPACE);
  DCHECK_IMPLIES(v8_flags.concurrent_sweeping,
                 !minor_sweeping_state_.HasValidJob());
  size_t live_bytes = chunk->live_bytes();
  DCHECK_GE(chunk->area_size(), live_bytes);
  heap_->IncrementPromotedObjectsSize(live_bytes);
  heap_->IncrementYoungSurvivorsCounter(live_bytes);
  DCHECK_EQ(PageMetadata::ConcurrentSweepingState::kDone,
            chunk->concurrent_sweeping_state());
  if (!chunk->Chunk()->IsLargePage()) {
    PrepareToBeIteratedPromotedPage(static_cast<PageMetadata*>(chunk));
  } else {
    chunk->set_concurrent_sweeping_state(
        PageMetadata::ConcurrentSweepingState::kPendingIteration);
  }
  DCHECK_EQ(PageMetadata::ConcurrentSweepingState::kPendingIteration,
            chunk->concurrent_sweeping_state());
  // This method is called only from the main thread while sweeping tasks have
  // not yet started, thus a mutex is not needed.
  sweeping_list_for_promoted_page_iteration_.push_back(chunk);
  promoted_pages_for_iteration_count_++;
}

namespace {
void VerifyPreparedPage(PageMetadata* page) {
#ifdef DEBUG
  DCHECK_GE(page->area_size(), static_cast<size_t>(page->live_bytes()));
  DCHECK_EQ(PageMetadata::ConcurrentSweepingState::kDone,
            page->concurrent_sweeping_state());
  page->ForAllFreeListCategories([page](FreeListCategory* category) {
    DCHECK(!category->is_linked(page->owner()->free_list()));
  });
#endif  // DEBUG
}
}  // namespace

void Sweeper::PrepareToBeSweptPage(AllocationSpace space, PageMetadata* page) {
  VerifyPreparedPage(page);
  page->set_concurrent_sweeping_state(
      PageMetadata::ConcurrentSweepingState::kPendingSweeping);
  PagedSpaceBase* paged_space;
  if (space == NEW_SPACE) {
    DCHECK(v8_flags.minor_ms);
    paged_space = heap_->paged_new_space()->paged_space();
  } else {
    paged_space = heap_->paged_space(space);
  }

  paged_space->IncreaseAllocatedBytes(page->live_bytes(), page);

  // Set the allocated_bytes_ counter to area_size and clear the wasted_memory_
  // counter. The free operations during sweeping will decrease allocated_bytes_
  // to actual live bytes and keep track of wasted_memory_.
  page->ResetAllocationStatistics();
}

void Sweeper::PrepareToBeIteratedPromotedPage(PageMetadata* page) {
  DCHECK(!page->Chunk()->IsFlagSet(MemoryChunk::BLACK_ALLOCATED));
  DCHECK_EQ(OLD_SPACE, page->owner_identity());
  VerifyPreparedPage(page);
  page->set_concurrent_sweeping_state(
      PageMetadata::ConcurrentSweepingState::kPendingIteration);
  // Account the whole page as allocated since it won't be in the free list.
  // TODO(v8:12612): Consider accounting for wasted bytes when checking old gen
  // size against old gen allocation limit, and treat previously unallocated
  // memory as wasted rather than allocated.
  page->ResetAllocationStatisticsForPromotedPage();
  PagedSpace* space = static_cast<PagedSpace*>(page->owner());
  space->IncreaseAllocatedBytes(page->allocated_bytes(), page);
  space->free_list()->increase_wasted_bytes(page->wasted_memory());
}

PageMetadata* Sweeper::GetSweepingPageSafe(AllocationSpace space) {
  base::MutexGuard guard(&mutex_);
  DCHECK(IsValidSweepingSpace(space));
  int space_index = GetSweepSpaceIndex(space);
  PageMetadata* page = nullptr;
  SweepingList& sweeping_list = sweeping_list_[space_index];
  if (!sweeping_list.empty()) {
    page = sweeping_list.back();
    sweeping_list.pop_back();
  }
  if (sweeping_list.empty()) {
    has_sweeping_work_[GetSweepSpaceIndex(space)].store(
        false, std::memory_order_release);
  }
  return page;
}

MutablePageMetadata* Sweeper::GetPromotedPageSafe() {
  base::MutexGuard guard(&mutex_);
  MutablePageMetadata* chunk = nullptr;
  if (!sweeping_list_for_promoted_page_iteration_.empty()) {
    chunk = sweeping_list_for_promoted_page_iteration_.back();
    sweeping_list_for_promoted_page_iteration_.pop_back();
  }
  return chunk;
}

GCTracer::Scope::ScopeId Sweeper::GetTracingScope(AllocationSpace space,
                                                  bool is_joining_thread) {
  if (space == NEW_SPACE) {
    return is_joining_thread ? GCTracer::Scope::MINOR_MS_SWEEP
                             : GCTracer::Scope::MINOR_MS_BACKGROUND_SWEEPING;
  }
  return is_joining_thread ? GCTracer::Scope::MC_SWEEP
                           : GCTracer::Scope::MC_BACKGROUND_SWEEPING;
}

bool Sweeper::IsSweepingDoneForSpace(AllocationSpace space) const {
  return !has_sweeping_work_[GetSweepSpaceIndex(space)].load(
      std::memory_order_acquire);
}

void Sweeper::AddSweptPage(PageMetadata* page, AllocationSpace identity) {
  base::MutexGuard guard(&mutex_);
  page->set_concurrent_sweeping_state(
      PageMetadata::ConcurrentSweepingState::kDone);
  swept_list_[GetSweepSpaceIndex(identity)].push_back(page);
  has_swept_pages_[GetSweepSpaceIndex(identity)].store(
      true, std::memory_order_release);
  cv_page_swept_.NotifyAll();
}

bool Sweeper::ShouldRefillFreelistForSpace(AllocationSpace space) const {
  DCHECK_IMPLIES(space == NEW_SPACE, v8_flags.minor_ms);
  return has_swept_pages_[GetSweepSpaceIndex(space)].load(
      std::memory_order_acquire);
}

void Sweeper::SweepEmptyNewSpacePage(PageMetadata* page) {
  DCHECK(v8_flags.minor_ms);
  DCHECK_EQ(kNewSpace, page->owner_identity());
  DCHECK_EQ(0, page->live_bytes());
  DCHECK(page->marking_bitmap()->IsClean());
  DCHECK(heap_->IsMainThread());
  DCHECK(heap_->tracer()->IsInAtomicPause());
  DCHECK_EQ(PageMetadata::ConcurrentSweepingState::kDone,
            page->concurrent_sweeping_state());

  PagedSpaceBase* paged_space = nullptr;
  if (v8_flags.sticky_mark_bits) {
    paged_space = heap_->sticky_space();
  } else {
    paged_space = PagedNewSpace::From(heap_->new_space())->paged_space();
  }

  Address start = page->area_start();
  size_t size = page->area_size();

  if (heap::ShouldZapGarbage()) {
    static constexpr Tagged_t kZapTagged = static_cast<Tagged_t>(kZapValue);
    const size_t size_in_tagged = size / kTaggedSize;
    Tagged_t* current_addr = reinterpret_cast<Tagged_t*>(start);
    for (size_t i = 0; i < size_in_tagged; ++i) {
      base::AsAtomicPtr(current_addr++)
          ->store(kZapTagged, std::memory_order_relaxed);
    }
  }

  page->ResetAllocationStatistics();
  page->ResetAgeInNewSpace();
  page->ReleaseSlotSet(SURVIVOR_TO_EXTERNAL_POINTER);
  page->Chunk()->ClearFlagNonExecutable(MemoryChunk::NEVER_ALLOCATE_ON_PAGE);
  paged_space->FreeDuringSweep(start, size);
  paged_space->IncreaseAllocatedBytes(0, page);
  paged_space->RelinkFreeListCategories(page);

  if (heap_->ShouldReduceMemory()) {
    ZeroOrDiscardUnusedMemory(page, start, size);
    // Only decrement counter when we discard unused system pages.
    ActiveSystemPages active_system_pages_after_sweeping;
    active_system_pages_after_sweeping.Init(
        sizeof(MemoryChunk), MemoryAllocator::GetCommitPageSizeBits(),
        PageMetadata::kPageSize);
    // Decrement accounted memory for discarded memory.
    paged_space->ReduceActiveSystemPages(page,
                                         active_system_pages_after_sweeping);
  }
}

Sweeper::PauseMajorSweepingScope::PauseMajorSweepingScope(Sweeper* sweeper)
    : sweeper_(sweeper),
      resume_on_exit_(sweeper->AreMajorSweeperTasksRunning()) {
  DCHECK(v8_flags.minor_ms);
  DCHECK_IMPLIES(resume_on_exit_, v8_flags.concurrent_sweeping);
  sweeper_->major_sweeping_state_.Pause();
}

Sweeper::PauseMajorSweepingScope::~PauseMajorSweepingScope() {
  if (resume_on_exit_) {
    sweeper_->major_sweeping_state_.Resume();
  }
}

uint64_t Sweeper::GetTraceIdForFlowEvent(
    GCTracer::Scope::ScopeId scope_id) const {
  return GCTracer::Scope::NeedsYoungEpoch(scope_id)
             ? minor_sweeping_state_.trace_id()
             : major_sweeping_state_.trace_id();
}

#if DEBUG
bool Sweeper::HasUnsweptPagesForMajorSweeping() const {
  DCHECK(heap_->IsMainThread());
  DCHECK(!AreMajorSweeperTasksRunning());
  bool has_unswept_pages = false;
  ForAllSweepingSpaces([this, &has_unswept_pages](AllocationSpace space) {
    DCHECK_EQ(IsSweepingDoneForSpace(space),
              sweeping_list_[GetSweepSpaceIndex(space)].empty());
    if (space == NEW_SPACE) return;
    if (!sweeping_list_[GetSweepSpaceIndex(space)].empty())
      has_unswept_pages = true;
  });
  return has_unswept_pages;
}
#endif  // DEBUG

}  // namespace internal
}  // namespace v8
```