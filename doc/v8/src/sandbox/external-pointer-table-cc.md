Response:
Let's break down the thought process to analyze the provided C++ code for `external-pointer-table.cc`.

**1. Initial Code Examination & Goal Identification:**

The first step is to skim the code and identify the main data structures and functions. Keywords like `ExternalPointerTable`, `Space`, `Segment`, `Evacuation`, `Compaction`, `Sweep`, and `Freelist` jump out. The file header mentions "sandbox" and "external pointers."  This suggests the code manages pointers that reside outside the V8 heap, likely for interaction with native code or other external resources.

The core goal seems to be managing a table of these external pointers efficiently, handling memory management (allocation, deallocation), and dealing with garbage collection and compaction.

**2. Section-by-Section Analysis (Top-Down):**

* **Includes:**  The included headers (`execution/isolate.h`, `heap/read-only-spaces.h`, etc.) provide clues about the context within V8. `isolate.h` relates to V8's isolated execution environments, `heap` to memory management, and `sandbox` to security boundaries.

* **Namespace:** The code is within `v8::internal`, indicating it's part of V8's internal implementation.

* **`SetUpFromReadOnlyArtifacts`:** This function is clearly about initializing the table from some pre-existing, read-only data. The loop iterates through `artifacts->external_pointer_registry()`, suggesting a persistent store of external pointers. The `AllocateAndInitializeEntry` function hints at the allocation process.

* **`SegmentsIterator`:**  This template class is interesting. The comments clearly describe its purpose: to iterate over segments in reverse address order, potentially from multiple sets. This is crucial for building the freelist. The use of `std::set` implies segments are kept sorted. The `Data` template parameter suggests associating extra information with each segment set.

* **`EvacuateAndSweepAndCompact`:** This is a central, complex function. The name strongly suggests it performs garbage collection-related operations: evacuation (moving live data), sweeping (identifying dead data), and compaction (reducing fragmentation). The locking mechanisms (`base::MutexGuard`) indicate thread safety concerns. The special marker for the freelist (`kEntryAllocationIsForbiddenMarker`) is a debugging aid. The interaction with `SegmentsIterator` becomes clearer here – it's used to process segments during the sweep. The logic around `EvacuationEntry` and `ResolveEvacuationEntryDuringSweeping` is key to understanding how the table handles moving entries. The handling of `from_space` suggests a generational garbage collection approach.

* **`SweepAndCompact` and `Sweep`:** These are simpler wrappers around `EvacuateAndSweepAndCompact`, indicating different stages or variations of the garbage collection process.

* **`ResolveEvacuationEntryDuringSweeping`:** This function details the actual movement of an entry during evacuation. The checks and assertions reinforce the invariants of the compaction algorithm.

* **`UpdateAllEvacuationEntries`:** This function seems to update the locations of evacuation entries, likely as part of the compaction process before the actual move happens.

* **Conditional Compilation (`#ifdef V8_COMPRESS_POINTERS`):** The entire file is conditionally compiled, implying this feature is optional or has specific build requirements.

**3. Inferring Functionality and Relationships:**

Based on the code and comments:

* **Core Function:**  Manages a table of external pointers used by V8.
* **Memory Management:** Allocates and deallocates entries in the table using segments and a freelist.
* **Garbage Collection:** Implements sweep and compaction to reclaim unused entries and reduce fragmentation. Supports evacuation, which involves moving live entries.
* **Evacuation Entries:** A mechanism to track entries that need to be moved during compaction.
* **Read-Only Support:**  Can be initialized from read-only artifacts.
* **Thread Safety:** Uses mutexes to protect shared data structures.

**4. Considering JavaScript Interaction (Hypothetical):**

Since the code deals with *external* pointers, the most likely JavaScript interaction is through mechanisms that involve calling native C++ code. This could be through:

* **Native Extensions (Addons):** Node.js addons written in C++ can hold pointers to external resources and potentially register them in this table.
* **Foreign Function Interface (FFI):**  Some JavaScript environments allow direct calls to C/C++ functions. This could involve passing or receiving external pointers.
* **Internal V8 APIs:**  Certain internal V8 features might use this table to manage pointers to objects outside the JavaScript heap.

**5. Code Logic Reasoning and Examples:**

Focus on the `EvacuateAndSweepAndCompact` function. Let's consider a simplified scenario:

* **Hypothetical Input:** A `Space` with two segments. Segment A has live entries at indices 0 and 2, marked. Segment B has a dead entry at index 5 (not marked). Compaction is triggered.
* **Process:**
    1. The `SegmentsIterator` processes segments in reverse order (B then A).
    2. For Segment B, entry 5 is not marked, so it's added to the freelist.
    3. For Segment A, entries 0 and 2 are marked. Their mark bits are cleared.
    4. The freelist is updated.
* **Hypothetical Output:** The freelist now contains index 5. The mark bits of entries 0 and 2 in Segment A are cleared.

**6. Common Programming Errors:**

Think about how a *user* (writing native extensions or using FFI) could misuse the external pointer table:

* **Dangling Pointers:** A native extension registers an external pointer but then deletes the underlying resource without informing V8. The table still holds the pointer, but it's now invalid.
* **Memory Leaks:**  A native extension allocates memory, registers the pointer, but never unregisters it or frees the memory when the JavaScript object referencing it is garbage collected.
* **Incorrect Tagging:**  If the external pointer table uses tags to identify the type of external pointer, providing the wrong tag could lead to incorrect interpretation or crashes.
* **Race Conditions (if manual registration is involved):** If a native extension tries to register or unregister a pointer concurrently with V8's garbage collection, it could lead to data corruption.

**7. Refining Explanations and Examples:**

After the initial analysis, review and refine the explanations to be clearer and more concise. Ensure the JavaScript examples are relevant and easy to understand. For the logic reasoning, make sure the input and output are clearly defined.

This iterative process of examining the code, inferring functionality, considering use cases, and refining explanations leads to a comprehensive understanding of the `external-pointer-table.cc` file.
好的，让我们来分析一下 `v8/src/sandbox/external-pointer-table.cc` 这个文件。

**功能概要:**

`v8/src/sandbox/external-pointer-table.cc` 的主要功能是管理一个用于存储外部指针的表格。这些外部指针通常指向 V8 堆之外的内存，例如 C++ 对象或数据。这个表格的设计目标是安全且高效地管理这些指针，尤其是在垃圾回收 (GC) 期间。

更具体地说，它负责：

1. **存储和检索外部指针:** 提供一种机制来注册、存储和查找外部指针及其关联的元数据（例如，一个标签）。
2. **内存管理:**  管理用于存储这些指针的内存，包括分配和回收空间。它使用了“段”（Segments）的概念来组织内存。
3. **垃圾回收集成:**  在 V8 的垃圾回收过程中发挥关键作用。它需要能够识别哪些外部指针仍然被 JavaScript 对象引用，哪些可以被安全地清理。这涉及到标记（Marking）、清除（Sweeping）和压缩（Compaction）等操作。
4. **处理疏散（Evacuation）:** 当需要移动外部指针表中的条目（通常是为了压缩空间）时，它负责更新指向这些条目的引用。
5. **只读区域支持:**  可以从只读的工件中初始化外部指针表，这对于启动性能很重要。
6. **线程安全:**  使用互斥锁等机制来保证在多线程环境中的安全性。

**它不是 Torque 代码:**

文件名以 `.cc` 结尾，这表明它是 C++ 源代码文件，而不是 Torque 源代码文件。Torque 文件通常以 `.tq` 结尾。

**与 JavaScript 的关系:**

`external-pointer-table.cc` 与 JavaScript 的功能有密切关系，因为它允许 JavaScript 代码安全地与外部的 C++ 代码或数据进行交互。  以下是一些可能的联系：

1. **Native 扩展 (Addons):**  Node.js 的 C++ 插件可以使用 V8 的 API 来创建持有外部指针的 JavaScript 对象。`external-pointer-table.cc` 可能用于管理这些外部指针的生命周期。
2. **Foreign Function Interface (FFI):** 一些 JavaScript 环境允许直接调用 C/C++ 函数。在这些场景下，外部指针可能需要在 JavaScript 和本地代码之间传递，`external-pointer-table.cc` 可能参与其中。
3. **内部 V8 功能:**  V8 内部的一些功能可能需要管理指向外部资源的指针，例如 WebAssembly 的实例或某些嵌入式 API。

**JavaScript 示例 (概念性):**

虽然 JavaScript 代码本身不能直接操作 `external-pointer-table.cc` 的内容，但我们可以设想一个使用场景，并通过一个简化的 JavaScript 例子来说明其背后的概念：

```javascript
// 假设我们有一个 C++ 插件，它创建了一个持有外部资源的 JavaScript 对象

const myAddon = require('./my_addon');

// myAddon.createExternalObject() 可能会在 C++ 层面创建一个对象，
// 并将其指针注册到 external-pointer-table 中
const externalObject = myAddon.createExternalObject();

// JavaScript 可以使用这个对象，但实际上它背后关联着 C++ 的资源
externalObject.someMethod();

// 当 externalObject 不再被引用时，V8 的垃圾回收器需要知道
// 与之关联的外部指针，以便进行清理 (可能由 C++ 插件完成，或者通过 finalizer 等机制)
```

在这个例子中，`external-pointer-table.cc` 在幕后帮助 V8 管理 `externalObject` 背后的 C++ 资源的指针。当 JavaScript 引擎进行垃圾回收时，它需要知道 `externalObject` 持有一个外部指针，并且需要采取相应的措施来避免内存泄漏或悬挂指针。

**代码逻辑推理 (假设输入与输出):**

让我们关注 `EvacuateAndSweepAndCompact` 函数，这是一个关键的垃圾回收相关函数。

**假设输入:**

* `space`: 指向 `ExternalPointerTable::Space` 对象的指针，表示要进行垃圾回收的空间。
* `from_space`: 可选的指针，指向另一个 `Space` 对象，用于支持分代垃圾回收。
* `counters`: 指向性能计数器的指针。

假设 `space` 中包含以下条目（简化表示，只关注索引和是否标记）：

| 索引 | 是否标记 |
|---|---|
| 0 | 是 |
| 1 | 否 |
| 2 | 是 |
| 3 | 否 |
| 4 | 是 |

并且假设 `space` 的 `freelist_head_` 指向空闲列表的头部，最初可能指向某个索引或者表示空闲列表为空。

**代码逻辑推理:**

1. **锁定空间:** 获取 `space` 的互斥锁，防止并发修改。
2. **禁止分配:** 设置 `freelist_head_` 为 `kEntryAllocationIsForbiddenMarker`，防止在清理过程中分配新的条目。
3. **创建迭代器:** 创建 `SegmentsIterator` 来遍历 `space` 中的段。
4. **完成压缩 (如果需要):** 调用 `FinishCompaction` 来处理任何正在进行的压缩操作。
5. **处理 `from_space` (如果存在):** 如果 `from_space` 存在，也会对其进行处理，将其段添加到迭代器中，并将其失效的字段合并到 `space` 中。
6. **遍历段:** 使用 `SegmentsIterator` 从高地址到低地址遍历段。
7. **遍历条目:** 对于每个段，从高索引到低索引遍历条目。
8. **处理疏散条目:** 如果条目是疏散条目，则解析它，将旧条目的内容复制到新位置，并更新指向该条目的句柄。
9. **处理普通条目:**
   - 如果条目未被标记（`!payload.HasMarkBitSet()`），则认为它是垃圾，将其加入空闲列表（调用 `AddToFreelist`）。
   - 如果条目被标记，则清除其标记位。
10. **释放空段:** 如果一个段完全为空或者所有存活的条目都被疏散出去，则释放该段。
11. **合并段:** 将 `from_space` 的段合并到 `space` 中。
12. **更新空闲列表:** 根据清理后的结果更新 `space` 的 `freelist_head_` 和长度。
13. **更新计数器:** 更新存活的外部指针数量。

**假设输出:**

假设清理后，只有索引 0 和 4 的条目是存活的（标记位已清除），索引 1 和 3 是垃圾。那么：

* `space` 的 `freelist_head_` 将指向索引 1，索引 1 的条目将指向索引 3，索引 3 的条目将表示空闲列表的结束。
* 索引 0 和 4 的条目的标记位将被清除。
* 性能计数器将被更新，反映存活的外部指针数量为 2。

**用户常见的编程错误示例:**

如果用户（通常是编写 Native 扩展的开发者）不正确地使用外部指针，可能会导致以下错误：

1. **悬挂指针 (Dangling Pointer):**
   ```c++
   // C++ 代码
   void* externalData = malloc(1024);
   v8::Local<v8::External> external = v8::External::New(isolate, externalData);
   // ... 将 external 对象传递给 JavaScript ...
   free(externalData); // 错误：在 JavaScript 可能还在使用时释放了内存
   ```
   如果 JavaScript 代码仍然持有对 `external` 对象的引用，并且尝试访问它，就会访问到已经被释放的内存，导致崩溃或未定义行为。`external-pointer-table.cc` 试图通过 GC 来管理这些指针的生命周期，但前提是用户正确地将其关联到 JavaScript 对象。

2. **内存泄漏 (Memory Leak):**
   ```c++
   // C++ 代码
   void* externalData = malloc(1024);
   v8::Local<v8::External> external = v8::External::New(isolate, externalData);
   // ... 将 external 对象传递给 JavaScript，但忘记在不再需要时释放 externalData ...
   ```
   如果 `externalData` 没有被正确地释放，即使相关的 JavaScript 对象被垃圾回收，这块外部内存仍然会被占用，导致内存泄漏。 通常需要使用 finalizer 或其他机制来确保在 JavaScript 对象被回收时，相应的外部资源也被释放。

3. **不正确的标签或元数据管理:**  如果外部指针表使用标签来区分不同类型的外部资源，用户可能错误地设置或理解这些标签，导致后续操作的错误解释或处理。

4. **在错误的线程访问:**  如果外部指针表的操作不是完全线程安全的，或者用户在不正确的线程上访问或修改与外部指针相关的状态，可能会导致竞争条件和数据损坏。V8 的代码中使用了互斥锁来尝试避免这种情况，但用户仍然需要遵循正确的并发编程实践。

总而言之，`v8/src/sandbox/external-pointer-table.cc` 是 V8 中一个关键的组件，负责安全有效地管理外部指针，这对于 V8 与本地代码的集成至关重要。理解其功能和工作原理有助于开发者编写更健壮的 Native 扩展和使用 FFI。

### 提示词
```
这是目录为v8/src/sandbox/external-pointer-table.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/sandbox/external-pointer-table.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/sandbox/external-pointer-table.h"

#include "src/execution/isolate.h"
#include "src/heap/read-only-spaces.h"
#include "src/logging/counters.h"
#include "src/sandbox/external-pointer-table-inl.h"

#ifdef V8_COMPRESS_POINTERS

namespace v8 {
namespace internal {

void ExternalPointerTable::SetUpFromReadOnlyArtifacts(
    Space* read_only_space, const ReadOnlyArtifacts* artifacts) {
  UnsealReadOnlySegmentScope unseal_scope(this);
  for (const auto& registry_entry : artifacts->external_pointer_registry()) {
    ExternalPointerHandle handle = AllocateAndInitializeEntry(
        read_only_space, registry_entry.value, registry_entry.tag);
    CHECK_EQ(handle, registry_entry.handle);
  }
}

// An iterator over a set of sets of segments that returns a total ordering of
// segments in highest to lowest address order.  This lets us easily build a
// sorted singly-linked freelist.
//
// When given a single set of segments, it's the same as iterating over
// std::set<Segment> in reverse order.
//
// With multiple segment sets, we still produce a total order.  Sets are
// annotated so that we can associate some data with their segments.  This is
// useful when evacuating the young ExternalPointerTable::Space into the old
// generation in a major collection, as both spaces could have been compacting,
// with different starts to the evacuation area.
template <typename Segment, typename Data>
class SegmentsIterator {
  using iterator = typename std::set<Segment>::reverse_iterator;
  using const_iterator = typename std::set<Segment>::const_reverse_iterator;

 public:
  SegmentsIterator() = default;

  void AddSegments(const std::set<Segment>& segments, Data data) {
    streams_.emplace_back(segments.rbegin(), segments.rend(), data);
  }

  std::optional<std::pair<Segment, Data>> Next() {
    int stream = -1;
    int min_stream = -1;
    std::optional<std::pair<Segment, Data>> result;
    for (auto [iter, end, data] : streams_) {
      stream++;
      if (iter != end) {
        Segment segment = *iter;
        if (!result || result.value().first < segment) {
          min_stream = stream;
          result.emplace(segment, data);
        }
      }
    }
    if (result) {
      streams_[min_stream].iter++;
      return result;
    }
    return {};
  }

 private:
  struct Stream {
    iterator iter;
    const_iterator end;
    Data data;

    Stream(iterator iter, const_iterator end, Data data)
        : iter(iter), end(end), data(data) {}
  };

  std::vector<Stream> streams_;
};

uint32_t ExternalPointerTable::EvacuateAndSweepAndCompact(Space* space,
                                                          Space* from_space,
                                                          Counters* counters) {
  DCHECK(space->BelongsTo(this));
  DCHECK(!space->is_internal_read_only_space());

  DCHECK_IMPLIES(from_space, from_space->BelongsTo(this));
  DCHECK_IMPLIES(from_space, !from_space->is_internal_read_only_space());

  // Lock the space. Technically this is not necessary since no other thread can
  // allocate entries at this point, but some of the methods we call on the
  // space assert that the lock is held.
  base::MutexGuard guard(&space->mutex_);
  // Same for the invalidated fields mutex.
  base::MutexGuard invalidated_fields_guard(&space->invalidated_fields_mutex_);

  // There must not be any entry allocations while the table is being swept as
  // that would not be safe. Set the freelist to this special marker value to
  // easily catch any violation of this requirement.
  space->freelist_head_.store(kEntryAllocationIsForbiddenMarker,
                              std::memory_order_relaxed);

  SegmentsIterator<Segment, CompactionResult> segments_iter;
  Histogram* counter = counters->external_pointer_table_compaction_outcome();
  CompactionResult space_compaction = FinishCompaction(space, counter);
  segments_iter.AddSegments(space->segments_, space_compaction);

  // If from_space is present, take its segments and add them to the sweep
  // iterator.  Wait until after the sweep to actually give from_space's
  // segments to the other space, to avoid invalidating the iterator.
  std::set<Segment> from_space_segments;
  if (from_space) {
    base::MutexGuard from_space_guard(&from_space->mutex_);
    base::MutexGuard from_space_invalidated_fields_guard(
        &from_space->invalidated_fields_mutex_);

    std::swap(from_space->segments_, from_space_segments);
    DCHECK(from_space->segments_.empty());

    CompactionResult from_space_compaction =
        FinishCompaction(from_space, counter);
    segments_iter.AddSegments(from_space_segments, from_space_compaction);

    FreelistHead empty_freelist;
    from_space->freelist_head_.store(empty_freelist, std::memory_order_relaxed);

    for (Address field : from_space->invalidated_fields_)
      space->invalidated_fields_.push_back(field);
    from_space->ClearInvalidatedFields();
  }

  // Sweep top to bottom and rebuild the freelist from newly dead and
  // previously freed entries while also clearing the marking bit on live
  // entries and resolving evacuation entries table when compacting the table.
  // This way, the freelist ends up sorted by index which already makes the
  // table somewhat self-compacting and is required for the compaction
  // algorithm so that evacuated entries are evacuated to the start of a space.
  // This method must run either on the mutator thread or while the mutator is
  // stopped.
  uint32_t current_freelist_head = 0;
  uint32_t current_freelist_length = 0;
  auto AddToFreelist = [&](uint32_t entry_index) {
    at(entry_index).MakeFreelistEntry(current_freelist_head);
    current_freelist_head = entry_index;
    current_freelist_length++;
  };

  std::vector<Segment> segments_to_deallocate;
  while (auto current = segments_iter.Next()) {
    Segment segment = current->first;
    CompactionResult compaction = current->second;

    bool segment_will_be_evacuated =
        compaction.success &&
        segment.first_entry() >= compaction.start_of_evacuation_area;

    // Remember the state of the freelist before this segment in case this
    // segment turns out to be completely empty and we deallocate it.
    uint32_t previous_freelist_head = current_freelist_head;
    uint32_t previous_freelist_length = current_freelist_length;

    // Process every entry in this segment, again going top to bottom.
    for (uint32_t i = segment.last_entry(); i >= segment.first_entry(); i--) {
      auto payload = at(i).GetRawPayload();
      if (payload.ContainsEvacuationEntry()) {
        // Segments that will be evacuated cannot contain evacuation entries
        // into which other entries would be evacuated.
        DCHECK(!segment_will_be_evacuated);

        // An evacuation entry contains the address of the external pointer
        // field that owns the entry that is to be evacuated.
        Address handle_location =
            payload.ExtractEvacuationEntryHandleLocation();

        // The evacuation entry may be invalidated by the Scavenger that has
        // freed the object.
        if (handle_location == kNullAddress) {
          AddToFreelist(i);
          continue;
        }

        // The external pointer field may have been invalidated in the meantime
        // (for example if the host object has been in-place converted to a
        // different type of object). In that case, the field no longer
        // contains an external pointer handle and we therefore cannot evacuate
        // the old entry. This is fine as the entry is guaranteed to be dead.
        if (space->FieldWasInvalidated(handle_location)) {
          // In this case, we must, however, free the evacuation entry.
          // Otherwise, we would be left with effectively a stale evacuation
          // entry that we'd try to process again during the next GC.
          AddToFreelist(i);
          continue;
        }

        // Resolve the evacuation entry: take the pointer to the handle from the
        // evacuation entry, copy the entry to its new location, and finally
        // update the handle to point to the new entry.
        //
        // While we now know that the entry being evacuated is free, we don't
        // add it to (the start of) the freelist because that would immediately
        // cause new fragmentation when the next entry is allocated. Instead, we
        // assume that the segments out of which entries are evacuated will all
        // be decommitted anyway after this loop, which is usually the case
        // unless compaction was already aborted during marking.
        ResolveEvacuationEntryDuringSweeping(
            i, reinterpret_cast<ExternalPointerHandle*>(handle_location),
            compaction.start_of_evacuation_area);

        // The entry must now contain an external pointer and be unmarked as
        // the entry that was evacuated must have been processed already (it
        // is in an evacuated segment, which are processed first as they are
        // at the end of the space). This will have cleared the marking bit.
        DCHECK(at(i).HasExternalPointer(kAnyExternalPointerTag));
        DCHECK(!at(i).GetRawPayload().HasMarkBitSet());
      } else if (!payload.HasMarkBitSet()) {
        FreeManagedResourceIfPresent(i);
        AddToFreelist(i);
      } else {
        auto new_payload = payload;
        new_payload.ClearMarkBit();
        at(i).SetRawPayload(new_payload);
      }

      // We must have resolved all evacuation entries. Otherwise, we'll try to
      // process them again during the next GC, which would cause problems.
      DCHECK(!at(i).HasEvacuationEntry());
    }

    // If a segment is completely empty, or if all live entries will be
    // evacuated out of it at the end of this loop, free the segment.
    // Note: for segments that will be evacuated, we could avoid building up a
    // freelist, but it's probably not worth the effort.
    uint32_t free_entries = current_freelist_length - previous_freelist_length;
    bool segment_is_empty = free_entries == kEntriesPerSegment;
    if (segment_is_empty || segment_will_be_evacuated) {
      segments_to_deallocate.push_back(segment);
      // Restore the state of the freelist before this segment.
      current_freelist_head = previous_freelist_head;
      current_freelist_length = previous_freelist_length;
    }
  }

  space->segments_.merge(from_space_segments);

  // We cannot deallocate the segments during the above loop, so do it now.
  for (auto segment : segments_to_deallocate) {
#ifdef DEBUG
    // There should not be any live entries in the segments we are freeing.
    // TODO(saelo): we should be able to assert here that we're not freeing any
    // entries here. Otherwise, we'd have to FreeManagedResourceIfPresent.
    // for (uint32_t i = segment.last_entry(); i >= segment.first_entry(); i--)
    // {
    //  CHECK(!at(i).HasExternalPointer(kAnyExternalPointerTag));
    //}
#endif
    FreeTableSegment(segment);
    space->segments_.erase(segment);
  }

  space->ClearInvalidatedFields();

  FreelistHead new_freelist(current_freelist_head, current_freelist_length);
  space->freelist_head_.store(new_freelist, std::memory_order_release);
  DCHECK_EQ(space->freelist_length(), current_freelist_length);

  uint32_t num_live_entries = space->capacity() - current_freelist_length;
  counters->external_pointers_count()->AddSample(num_live_entries);
  return num_live_entries;
}

uint32_t ExternalPointerTable::SweepAndCompact(Space* space,
                                               Counters* counters) {
  return EvacuateAndSweepAndCompact(space, nullptr, counters);
}

uint32_t ExternalPointerTable::Sweep(Space* space, Counters* counters) {
  DCHECK(!space->IsCompacting());
  return SweepAndCompact(space, counters);
}

void ExternalPointerTable::ResolveEvacuationEntryDuringSweeping(
    uint32_t new_index, ExternalPointerHandle* handle_location,
    uint32_t start_of_evacuation_area) {
  // We must have a valid handle here. If this fails, it might mean that an
  // object with external pointers was in-place converted to another type of
  // object without informing the external pointer table.
  ExternalPointerHandle old_handle = *handle_location;
  CHECK(IsValidHandle(old_handle));

  uint32_t old_index = HandleToIndex(old_handle);
  ExternalPointerHandle new_handle = IndexToHandle(new_index);

  // The compaction algorithm always moves an entry from the evacuation area to
  // the front of the table. These DCHECKs verify this invariant.
  DCHECK_GE(old_index, start_of_evacuation_area);
  DCHECK_LT(new_index, start_of_evacuation_area);
  auto& new_entry = at(new_index);
  at(old_index).Evacuate(new_entry, EvacuateMarkMode::kLeaveUnmarked);
  *handle_location = new_handle;

  // If this entry references a managed resource, update the resource to
  // reference the new entry.
  if (Address addr = at(new_index).ExtractManagedResourceOrNull()) {
    ManagedResource* resource = reinterpret_cast<ManagedResource*>(addr);
    DCHECK_EQ(resource->ept_entry_, old_handle);
    resource->ept_entry_ = new_handle;
  }
}

void ExternalPointerTable::UpdateAllEvacuationEntries(
    Space* space, std::function<Address(Address)> function) {
  DCHECK(space->BelongsTo(this));
  DCHECK(!space->is_internal_read_only_space());

  if (!space->IsCompacting()) return;

  // Lock the space. Technically this is not necessary since no other thread can
  // allocate entries at this point, but some of the methods we call on the
  // space assert that the lock is held.
  base::MutexGuard guard(&space->mutex_);
  // Same for the invalidated fields mutex.
  base::MutexGuard invalidated_fields_guard(&space->invalidated_fields_mutex_);

  const uint32_t start_of_evacuation_area =
      space->start_of_evacuation_area_.load(std::memory_order_relaxed);

  // Iterate until the start of evacuation area.
  for (auto& segment : space->segments_) {
    if (segment.first_entry() == start_of_evacuation_area) return;
    for (uint32_t i = segment.first_entry(); i < segment.last_entry() + 1;
         ++i) {
      ExternalPointerTableEntry& entry = at(i);
      ExternalPointerTableEntry::Payload payload = entry.GetRawPayload();
      if (!payload.ContainsEvacuationEntry()) {
        continue;
      }
      Address new_location =
          function(payload.ExtractEvacuationEntryHandleLocation());
      entry.MakeEvacuationEntry(new_location);
    }
  }
}

}  // namespace internal
}  // namespace v8

#endif  // V8_COMPRESS_POINTERS
```