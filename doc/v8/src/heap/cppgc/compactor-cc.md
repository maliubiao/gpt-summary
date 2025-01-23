Response:
Let's break down the thought process for analyzing this C++ code. The goal is to understand the functionality of `v8/src/heap/cppgc/compactor.cc`. Here's a possible internal monologue and steps:

1. **Initial Skim and Core Idea Identification:**  The filename "compactor.cc" and the namespace "cppgc" (likely C++ Garbage Collection) strongly suggest this code is responsible for compacting the heap. The comments at the top confirm this. The term "compaction" implies rearranging live objects to reduce fragmentation.

2. **Identify Key Classes and Structures:** Start looking for class definitions. `MovableReferences` and `CompactionState` stand out. Let's analyze them:
    * `MovableReferences`: The name hints at managing references to objects that might move. The comments confirm this, mentioning "slots" and adjusting them after objects move. It seems like this class tracks pointers that need updating during compaction. The use of `unordered_map` and `map` suggests managing these references efficiently.
    * `CompactionState`: This seems to encapsulate the state of the compaction process for a given space. It likely handles the allocation of new locations for moved objects and manages the available pages.

3. **Follow the Control Flow (Top-Down):**  Start with the main `Compactor` class:
    * **Constructor:** It initializes by identifying compactable spaces in the heap.
    * **`ShouldCompact()`:** This function determines if compaction is necessary based on free list size and potentially testing flags. This is a key decision-making point.
    * **`InitializeIfShouldCompact()`:** If compaction is decided, it sets up the necessary data structures (`CompactionWorklists`).
    * **`CancelIfShouldNotCompact()`:** Allows canceling compaction if the conditions change.
    * **`CompactSpacesIfEnabled()`:** This is the heart of the compaction process. It uses `MovableReferences` to track pointers, iterates through compactable spaces, and calls `CompactSpace`. It also handles the cleanup of `compaction_worklists_`.
    * **`EnableForNextGCForTesting()`:** A testing utility to force compaction.

4. **Dive Deeper into Key Functions:** Now focus on the core compaction logic:
    * **`CompactSpace()`:** This function iterates through the pages of a compactable space and calls `CompactPage` for each. It also clears the free list.
    * **`CompactPage()`:** This is where the actual object movement happens. It iterates through objects on a page. If an object is live, it calls `compaction_state.RelocateObject()`. It also handles freeing dead objects.
    * **`CompactionState::RelocateObject()`:** This function allocates space for the object on the current compaction page, copies the object, and calls `movable_references_.Relocate()` to update the pointers to it. It manages moving to the next page if the current one is full.
    * **`MovableReferences::AddOrFilter()`:**  Registers a pointer that needs updating if the target object moves. It filters out slots in dead objects.
    * **`MovableReferences::Relocate()`:** Updates a single pointer to an object's new location. It also calls move listeners if they exist.
    * **`MovableReferences::RelocateInteriorReferences()`:**  Handles pointers *within* an object that has moved.

5. **Look for Helper Functions and Constants:** Identify supporting code:
    * **`kFreeListSizeThreshold`:**  The trigger point for compaction.
    * **`UpdateHeapResidency()`:** Calculates the total free space in compactable spaces.

6. **Relate to JavaScript (If Applicable):** Consider how this C++ code might affect JavaScript. Compaction improves memory locality, which can lead to faster access to objects, potentially speeding up JavaScript execution. Fragmentation reduction also allows allocating larger objects more easily. The move listeners are a crucial link to informing the JavaScript VM about object movements.

7. **Consider Error Scenarios and Assumptions:**  Think about potential issues:
    * **Dangling Pointers:**  The `MovableReferences` class is critical for preventing dangling pointers. If a pointer isn't updated correctly, it could lead to crashes.
    * **Concurrent Modification:** Compaction needs to be done carefully to avoid conflicts with mutator threads (the JavaScript execution). The comments indicate this runs on the mutator thread during `AtomicPhaseEpilogue`.
    * **Performance Overhead:** Compaction itself takes time. The `ShouldCompact()` logic aims to balance the benefits of compaction against its cost.

8. **Structure the Answer:**  Organize the findings into logical sections: functionality, Torque relevance, JavaScript relation, code logic, and common errors.

9. **Review and Refine:**  Read through the answer to ensure accuracy, clarity, and completeness. Check if all aspects of the prompt have been addressed. For example, ensure the JavaScript example is relevant and illustrative.

This systematic approach helps in understanding complex C++ code by breaking it down into manageable parts and focusing on the interactions between different components. The key is to start with the high-level purpose and gradually delve into the implementation details.
根据您提供的 v8 源代码 `v8/src/heap/cppgc/compactor.cc`，我可以列举一下它的功能：

**主要功能:**

* **堆内存压缩 (Heap Compaction):**  `compactor.cc` 的核心功能是对 C++ 垃圾回收器 (cppgc) 管理的堆内存进行压缩。  压缩是指将仍然存活的对象移动到一起，从而减少内存碎片，释放未使用的空间。这有助于提高内存利用率和程序性能。

**详细功能拆解:**

1. **判断是否需要压缩 (`ShouldCompact`)**:
   - 根据配置（如标记类型、堆栈状态）和当前堆的空闲列表大小来判断是否应该执行压缩操作。
   - 如果空闲列表的大小超过预定义的阈值 (`kFreeListSizeThreshold`)，则认为需要进行压缩。
   - 还有一个测试用的标志 (`enable_for_next_gc_for_testing_`) 可以强制启用压缩。

2. **初始化压缩 (`InitializeIfShouldCompact`)**:
   - 如果决定进行压缩，则会初始化 `CompactionWorklists`，这是一个用于管理压缩过程中的工作项的数据结构，例如需要更新的指针（槽）。

3. **取消压缩 (`CancelIfShouldNotCompact`)**:
   - 如果已经初始化了压缩，但后来发现不需要进行压缩（例如，堆的状态发生了变化），则会取消压缩操作。

4. **执行压缩 (`CompactSpacesIfEnabled`)**:
   - 这是实际执行压缩的核心函数。
   - **收集需要更新的引用 (`MovableReferences`)**:  它会遍历 `CompactionWorklists` 中的 `movable_slots_worklist`，收集所有指向可能移动的对象的指针（称为“槽”）。`MovableReferences` 类负责跟踪这些引用，并在对象移动后更新它们。
   - **遍历可压缩空间 (`CompactSpace`)**:  遍历所有被标记为可压缩的内存空间 (`NormalPageSpace`)。
   - **压缩页面 (`CompactPage`)**:  对于每个页面，执行以下操作：
     - 清空页面的对象起始位图。
     - 遍历页面上的所有对象。
     - 如果对象是存活的（已标记）：
       - 取消标记对象（除非启用了粘性位）。
       - 使用 `CompactionState` 将对象移动到新的位置。
       - 更新 `MovableReferences` 中指向该对象的指针。
     - 如果对象是死亡的（未标记）：
       - 执行对象的终结器 (finalizer)。
       - 释放对象的内存。
   - **管理压缩状态 (`CompactionState`)**:  `CompactionState` 类负责维护压缩过程中的状态，例如当前正在写入的页面、已使用的字节数等。它还负责将压缩后的页面返回到空间，并将剩余的可用页面释放回系统。
   - **更新堆驻留大小 (`UpdateHeapResidency`)**:  计算当前堆中可用的空闲空间大小。

5. **`MovableReferences` 类**:
   - 维护指向可移动对象的指针的映射。
   - `AddOrFilter`: 添加需要跟踪的指针，并过滤掉指向死亡对象的指针。
   - `Relocate`: 当对象移动时，更新指向该对象的指针的值。同时处理内部指针的情况。
   - `RelocateInteriorReferences`: 更新移动对象内部的指针。

6. **`CompactionState` 类**:
   - 管理单个内存空间的压缩状态。
   - `AddPage`:  添加一个页面到压缩状态中。
   - `RelocateObject`: 将一个存活的对象移动到新的位置，并更新相关的引用。
   - `FinishCompactingSpace`: 完成整个空间的压缩。
   - `FinishCompactingPage`: 完成单个页面的压缩。

**关于 .tq 结尾：**

`v8/src/heap/cppgc/compactor.cc` **不是**以 `.tq` 结尾，所以它不是一个 V8 Torque 源代码文件。Torque 文件通常用于定义 V8 的内置函数和类型系统。

**与 JavaScript 的功能关系：**

`v8/src/heap/cppgc/compactor.cc` 的功能直接影响 JavaScript 的性能和内存管理。

* **减少内存碎片:** 压缩操作通过整理堆内存，减少了内存碎片，使得 V8 能够更有效地分配和管理 JavaScript 对象。这有助于防止因内存碎片导致的内存分配失败和性能下降。
* **提高缓存效率:**  将经常一起访问的对象移动到相邻的内存区域，可以提高 CPU 缓存的命中率，从而加速 JavaScript 代码的执行。
* **支持高效的垃圾回收:**  压缩是垃圾回收过程中的一个重要步骤，可以为后续的垃圾回收周期创造更好的条件。

**JavaScript 示例说明（概念性）：**

虽然 `compactor.cc` 是 C++ 代码，但其效果可以在 JavaScript 中观察到。例如，在长时间运行的 JavaScript 应用中，如果没有内存压缩，可能会出现以下情况：

```javascript
let arr = [];
for (let i = 0; i < 10000; i++) {
  arr.push(new Array(1000)); // 分配一些小的数组
}

// 模拟一些对象被释放
for (let i = 0; i < 5000; i++) {
  arr[i] = null;
}

// 尝试分配一个较大的对象
let largeObject = new Array(1000000);
```

在没有压缩的情况下，即使释放了一些小数组，堆内存中可能仍然存在很多小的空洞（碎片），导致无法分配 `largeObject` 所需的连续内存空间，或者分配效率较低。而内存压缩的目标就是整理这些碎片，使得可以更容易地分配像 `largeObject` 这样的大对象。

**代码逻辑推理（假设输入与输出）：**

假设我们有一个 `NormalPageSpace`，其中包含一些存活和死亡的对象。

**假设输入:**

* 一个 `NormalPageSpace` 包含以下对象（简化表示，只关注起始地址和大小）：
    * 对象 A (存活): 地址 0x1000, 大小 100
    * 空闲块: 地址 0x1064, 大小 50
    * 对象 B (死亡): 地址 0x1098, 大小 80
    * 对象 C (存活): 地址 0x1100, 大小 120
* `kFreeListSizeThreshold` 为 100KB。
* 当前空闲列表大小大于 100KB。

**预期输出（部分）:**

1. **`ShouldCompact` 返回 `true`:** 因为空闲列表大小超过阈值。
2. **`CompactSpace` 被调用:** 对该 `NormalPageSpace` 进行压缩。
3. **`CompactPage` 被调用:** 处理页面上的对象。
4. **对象 B 被终结并释放:** 因为它是死亡的。
5. **对象 A 和 C 被移动到一起:** 例如，可能移动到页面的起始位置：
   - 对象 A' (移动后): 地址 0x2000, 大小 100
   - 对象 C' (移动后): 地址 0x2064, 大小 120
6. **指向对象 A 和 C 的指针被更新:** `MovableReferences` 负责更新所有指向原来地址 0x1000 和 0x1100 的指针，使它们指向新的地址 0x2000 和 0x2064。
7. **内存碎片减少:** 原来的空闲块和对象 B 占据的空间被释放或合并，为后续分配更大的连续空间提供可能。

**用户常见的编程错误（与压缩相关性较低，但与内存管理相关）：**

内存压缩本身是 V8 内部的机制，用户一般不会直接与之交互。然而，用户的编程错误会导致更多的内存碎片，从而可能触发更频繁的压缩操作，或者使压缩效果不佳。常见的编程错误包括：

* **内存泄漏:**  创建对象后没有释放引用，导致对象一直存活，无法被垃圾回收和压缩。
   ```javascript
   let leakedData;
   function createLeak() {
     leakedData = new Array(1000000); // 全局变量，引用不会被释放
   }
   createLeak();
   ```
* **频繁创建和销毁小对象:**  虽然单个小对象内存占用不大，但频繁地创建和销毁会产生大量的内存碎片。
   ```javascript
   for (let i = 0; i < 100000; i++) {
     let temp = {}; // 每次循环都创建和销毁小对象
   }
   ```
* **持有不必要的对象引用:**  即使对象本身不再使用，如果仍然有变量或数据结构持有对它的引用，垃圾回收器就无法回收它。

理解 `v8/src/heap/cppgc/compactor.cc` 的功能有助于开发者认识到 V8 如何管理内存，从而编写更高效、更少产生内存碎片的 JavaScript 代码。

### 提示词
```
这是目录为v8/src/heap/cppgc/compactor.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/cppgc/compactor.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/cppgc/compactor.h"

#include <map>
#include <numeric>
#include <unordered_map>
#include <unordered_set>

#include "include/cppgc/macros.h"
#include "src/heap/cppgc/compaction-worklists.h"
#include "src/heap/cppgc/globals.h"
#include "src/heap/cppgc/heap-base.h"
#include "src/heap/cppgc/heap-page.h"
#include "src/heap/cppgc/heap-space.h"
#include "src/heap/cppgc/memory.h"
#include "src/heap/cppgc/object-poisoner.h"
#include "src/heap/cppgc/raw-heap.h"
#include "src/heap/cppgc/stats-collector.h"

namespace cppgc {
namespace internal {

namespace {
// Freelist size threshold that must be exceeded before compaction
// should be considered.
static constexpr size_t kFreeListSizeThreshold = 512 * kKB;

// The real worker behind heap compaction, recording references to movable
// objects ("slots".) When the objects end up being compacted and moved,
// relocate() will adjust the slots to point to the new location of the
// object along with handling references for interior pointers.
//
// The MovableReferences object is created and maintained for the lifetime
// of one heap compaction-enhanced GC.
class MovableReferences final {
  using MovableReference = CompactionWorklists::MovableReference;

 public:
  explicit MovableReferences(HeapBase& heap)
      : heap_(heap), heap_has_move_listeners_(heap.HasMoveListeners()) {}

  // Adds a slot for compaction. Filters slots in dead objects.
  void AddOrFilter(MovableReference*);

  // Relocates a backing store |from| -> |to|.
  void Relocate(Address from, Address to, size_t size_including_header);

  // Relocates interior slots in a backing store that is moved |from| -> |to|.
  void RelocateInteriorReferences(Address from, Address to, size_t size);

  // Updates the collection of callbacks from the item pushed the worklist by
  // marking visitors.
  void UpdateCallbacks();

 private:
  HeapBase& heap_;

  // Map from movable reference (value) to its slot. Upon moving an object its
  // slot pointing to it requires updating. Movable reference should currently
  // have only a single movable reference to them registered.
  std::unordered_map<MovableReference, MovableReference*> movable_references_;

  // Map of interior slots to their final location. Needs to be an ordered map
  // as it is used to walk through slots starting at a given memory address.
  // Requires log(n) lookup to make the early bailout reasonably fast.
  //
  // - The initial value for a given key is nullptr.
  // - Upon moving an object this value is adjusted accordingly.
  std::map<MovableReference*, Address> interior_movable_references_;

  const bool heap_has_move_listeners_;

#if DEBUG
  // The following two collections are used to allow refer back from a slot to
  // an already moved object.
  std::unordered_set<const void*> moved_objects_;
  std::unordered_map<MovableReference*, MovableReference>
      interior_slot_to_object_;
#endif  // DEBUG
};

void MovableReferences::AddOrFilter(MovableReference* slot) {
  const BasePage* slot_page = BasePage::FromInnerAddress(&heap_, slot);
  CHECK_NOT_NULL(slot_page);

  const void* value = *slot;
  if (!value) return;

  // All slots and values are part of Oilpan's heap.
  // - Slots may be contained within dead objects if e.g. the write barrier
  //   registered the slot while backing itself has not been marked live in
  //   time. Slots in dead objects are filtered below.
  // - Values may only be contained in or point to live objects.

  const HeapObjectHeader& slot_header =
      slot_page->ObjectHeaderFromInnerAddress(slot);
  // Filter the slot since the object that contains the slot is dead.
  if (!slot_header.IsMarked()) return;

  const BasePage* value_page = BasePage::FromInnerAddress(&heap_, value);
  CHECK_NOT_NULL(value_page);

  // The following cases are not compacted and do not require recording:
  // - Compactable object on large pages.
  // - Compactable object on non-compactable spaces.
  if (value_page->is_large() || !value_page->space().is_compactable()) return;

  // Slots must reside in and values must point to live objects at this
  // point. |value| usually points to a separate object but can also point
  // to the an interior pointer in the same object storage which is why the
  // dynamic header lookup is required.
  const HeapObjectHeader& value_header =
      value_page->ObjectHeaderFromInnerAddress(value);
  CHECK(value_header.IsMarked());

  // Slots may have been recorded already but must point to the same value.
  auto reference_it = movable_references_.find(value);
  if (V8_UNLIKELY(reference_it != movable_references_.end())) {
    CHECK_EQ(slot, reference_it->second);
    return;
  }

  // Add regular movable reference.
  movable_references_.emplace(value, slot);

  // Check whether the slot itself resides on a page that is compacted.
  if (V8_LIKELY(!slot_page->space().is_compactable())) return;

  CHECK_EQ(interior_movable_references_.end(),
           interior_movable_references_.find(slot));
  interior_movable_references_.emplace(slot, nullptr);
#if DEBUG
  interior_slot_to_object_.emplace(slot, slot_header.ObjectStart());
#endif  // DEBUG
}

void MovableReferences::Relocate(Address from, Address to,
                                 size_t size_including_header) {
#if DEBUG
  moved_objects_.insert(from);
#endif  // DEBUG

  if (V8_UNLIKELY(heap_has_move_listeners_)) {
    heap_.CallMoveListeners(from - sizeof(HeapObjectHeader),
                            to - sizeof(HeapObjectHeader),
                            size_including_header);
  }

  // Interior slots always need to be processed for moved objects.
  // Consider an object A with slot A.x pointing to value B where A is
  // allocated on a movable page itself. When B is finally moved, it needs to
  // find the corresponding slot A.x. Object A may be moved already and the
  // memory may have been freed, which would result in a crash.
  if (!interior_movable_references_.empty()) {
    const HeapObjectHeader& header = HeapObjectHeader::FromObject(to);
    const size_t size = header.ObjectSize();
    RelocateInteriorReferences(from, to, size);
  }

  auto it = movable_references_.find(from);
  // This means that there is no corresponding slot for a live object.
  // This may happen because a mutator may change the slot to point to a
  // different object because e.g. incremental marking marked an object
  // as live that was later on replaced.
  if (it == movable_references_.end()) {
    return;
  }

  // If the object is referenced by a slot that is contained on a compacted
  // area itself, check whether it can be updated already.
  MovableReference* slot = it->second;
  auto interior_it = interior_movable_references_.find(slot);
  if (interior_it != interior_movable_references_.end()) {
    MovableReference* slot_location =
        reinterpret_cast<MovableReference*>(interior_it->second);
    if (!slot_location) {
      interior_it->second = to;
#if DEBUG
      // Check that the containing object has not been moved yet.
      auto reverse_it = interior_slot_to_object_.find(slot);
      DCHECK_NE(interior_slot_to_object_.end(), reverse_it);
      DCHECK_EQ(moved_objects_.end(), moved_objects_.find(reverse_it->second));
#endif  // DEBUG
    } else {
      slot = slot_location;
    }
  }

  // Compaction is atomic so slot should not be updated during compaction.
  DCHECK_EQ(from, *slot);

  // Update the slots new value.
  *slot = to;
}

void MovableReferences::RelocateInteriorReferences(Address from, Address to,
                                                   size_t size) {
  // |from| is a valid address for a slot.
  auto interior_it = interior_movable_references_.lower_bound(
      reinterpret_cast<MovableReference*>(from));
  if (interior_it == interior_movable_references_.end()) return;
  DCHECK_GE(reinterpret_cast<Address>(interior_it->first), from);

  size_t offset = reinterpret_cast<Address>(interior_it->first) - from;
  while (offset < size) {
    if (!interior_it->second) {
      // Update the interior reference value, so that when the object the slot
      // is pointing to is moved, it can re-use this value.
      Address reference = to + offset;
      interior_it->second = reference;

      // If the |slot|'s content is pointing into the region [from, from +
      // size) we are dealing with an interior pointer that does not point to
      // a valid HeapObjectHeader. Such references need to be fixed up
      // immediately.
      Address& reference_contents = *reinterpret_cast<Address*>(reference);
      if (reference_contents > from && reference_contents < (from + size)) {
        reference_contents = reference_contents - from + to;
      }
    }

    interior_it++;
    if (interior_it == interior_movable_references_.end()) return;
    offset = reinterpret_cast<Address>(interior_it->first) - from;
  }
}

class CompactionState final {
  CPPGC_STACK_ALLOCATED();
  using Pages = std::vector<NormalPage*>;

 public:
  CompactionState(NormalPageSpace* space, MovableReferences& movable_references)
      : space_(space), movable_references_(movable_references) {}

  void AddPage(NormalPage* page) {
    DCHECK_EQ(space_, &page->space());
    // If not the first page, add |page| onto the available pages chain.
    if (!current_page_)
      current_page_ = page;
    else
      available_pages_.push_back(page);
  }

  void RelocateObject(const NormalPage* page, const Address header,
                      size_t size) {
    // Allocate and copy over the live object.
    Address compact_frontier =
        current_page_->PayloadStart() + used_bytes_in_current_page_;
    if (compact_frontier + size > current_page_->PayloadEnd()) {
      // Can't fit on current page. Add remaining onto the freelist and advance
      // to next available page.
      ReturnCurrentPageToSpace();

      current_page_ = available_pages_.back();
      available_pages_.pop_back();
      used_bytes_in_current_page_ = 0;
      compact_frontier = current_page_->PayloadStart();
    }
    if (V8_LIKELY(compact_frontier != header)) {
      // Use a non-overlapping copy, if possible.
      if (current_page_ == page)
        memmove(compact_frontier, header, size);
      else
        memcpy(compact_frontier, header, size);
      movable_references_.Relocate(header + sizeof(HeapObjectHeader),
                                   compact_frontier + sizeof(HeapObjectHeader),
                                   size);
    }
    current_page_->object_start_bitmap().SetBit(compact_frontier);
    used_bytes_in_current_page_ += size;
    DCHECK_LE(used_bytes_in_current_page_, current_page_->PayloadSize());
  }

  void FinishCompactingSpace() {
    // If the current page hasn't been allocated into, add it to the available
    // list, for subsequent release below.
    if (used_bytes_in_current_page_ == 0) {
      available_pages_.push_back(current_page_);
    } else {
      ReturnCurrentPageToSpace();
    }

    // Return remaining available pages back to the backend.
    for (NormalPage* page : available_pages_) {
      SetMemoryInaccessible(page->PayloadStart(), page->PayloadSize());
      NormalPage::Destroy(page, FreeMemoryHandling::kDiscardWherePossible);
    }
  }

  void FinishCompactingPage(NormalPage* page) {
#if DEBUG || defined(V8_USE_MEMORY_SANITIZER) || \
    defined(V8_USE_ADDRESS_SANITIZER)
    // Zap the unused portion, until it is either compacted into or freed.
    if (current_page_ != page) {
      ZapMemory(page->PayloadStart(), page->PayloadSize());
    } else {
      ZapMemory(page->PayloadStart() + used_bytes_in_current_page_,
                page->PayloadSize() - used_bytes_in_current_page_);
    }
#endif
    page->object_start_bitmap().MarkAsFullyPopulated();
  }

 private:
  void ReturnCurrentPageToSpace() {
    DCHECK_EQ(space_, &current_page_->space());
    space_->AddPage(current_page_);
    if (used_bytes_in_current_page_ != current_page_->PayloadSize()) {
      // Put the remainder of the page onto the free list.
      size_t freed_size =
          current_page_->PayloadSize() - used_bytes_in_current_page_;
      Address payload = current_page_->PayloadStart();
      Address free_start = payload + used_bytes_in_current_page_;
      SetMemoryInaccessible(free_start, freed_size);
      space_->free_list().Add({free_start, freed_size});
      current_page_->object_start_bitmap().SetBit(free_start);
    }
  }

  NormalPageSpace* space_;
  MovableReferences& movable_references_;
  // Page into which compacted object will be written to.
  NormalPage* current_page_ = nullptr;
  // Offset into |current_page_| to the next free address.
  size_t used_bytes_in_current_page_ = 0;
  // Additional pages in the current space that can be used as compaction
  // targets. Pages that remain available at the compaction can be released.
  Pages available_pages_;
};

void CompactPage(NormalPage* page, CompactionState& compaction_state,
                 StickyBits sticky_bits) {
  compaction_state.AddPage(page);

  page->object_start_bitmap().Clear();

  for (Address header_address = page->PayloadStart();
       header_address < page->PayloadEnd();) {
    HeapObjectHeader* header =
        reinterpret_cast<HeapObjectHeader*>(header_address);
    size_t size = header->AllocatedSize();
    DCHECK_GT(size, 0u);
    DCHECK_LT(size, kPageSize);

    if (header->IsFree()) {
      // Unpoison the freelist entry so that we can compact into it as wanted.
      ASAN_UNPOISON_MEMORY_REGION(header_address, size);
      header_address += size;
      continue;
    }

    if (!header->IsMarked()) {
      // Compaction is currently launched only from AtomicPhaseEpilogue, so it's
      // guaranteed to be on the mutator thread - no need to postpone
      // finalization.
      header->Finalize();

      // As compaction is under way, leave the freed memory accessible
      // while compacting the rest of the page. We just zap the payload
      // to catch out other finalizers trying to access it.
#if DEBUG || defined(V8_USE_MEMORY_SANITIZER) || \
    defined(V8_USE_ADDRESS_SANITIZER)
      ZapMemory(header, size);
#endif
      header_address += size;
      continue;
    }

    // Object is marked.
#if defined(CPPGC_YOUNG_GENERATION)
    if (sticky_bits == StickyBits::kDisabled) header->Unmark();
#else   // !defined(CPPGC_YOUNG_GENERATION)
    header->Unmark();
#endif  // !defined(CPPGC_YOUNG_GENERATION)

    // Potentially unpoison the live object as well as it is the source of
    // the copy.
    ASAN_UNPOISON_MEMORY_REGION(header->ObjectStart(), header->ObjectSize());
    compaction_state.RelocateObject(page, header_address, size);
    header_address += size;
  }

  compaction_state.FinishCompactingPage(page);
}

void CompactSpace(NormalPageSpace* space, MovableReferences& movable_references,
                  StickyBits sticky_bits) {
  using Pages = NormalPageSpace::Pages;

#ifdef V8_USE_ADDRESS_SANITIZER
  UnmarkedObjectsPoisoner().Traverse(*space);
#endif  // V8_USE_ADDRESS_SANITIZER

  DCHECK(space->is_compactable());

  space->free_list().Clear();

  // Compaction generally follows Jonker's algorithm for fast garbage
  // compaction. Compaction is performed in-place, sliding objects down over
  // unused holes for a smaller heap page footprint and improved locality. A
  // "compaction pointer" is consequently kept, pointing to the next available
  // address to move objects down to. It will belong to one of the already
  // compacted pages for this space, but as compaction proceeds, it will not
  // belong to the same page as the one being currently compacted.
  //
  // The compaction pointer is represented by the
  // |(current_page_, used_bytes_in_current_page_)| pair, with
  // |used_bytes_in_current_page_| being the offset into |current_page_|, making
  // up the next available location. When the compaction of an arena page causes
  // the compaction pointer to exhaust the current page it is compacting into,
  // page compaction will advance the current page of the compaction
  // pointer, as well as the allocation point.
  //
  // By construction, the page compaction can be performed without having
  // to allocate any new pages. So to arrange for the page compaction's
  // supply of freed, available pages, we chain them together after each
  // has been "compacted from". The page compaction will then reuse those
  // as needed, and once finished, the chained, available pages can be
  // released back to the OS.
  //
  // To ease the passing of the compaction state when iterating over an
  // arena's pages, package it up into a |CompactionState|.

  Pages pages = space->RemoveAllPages();
  if (pages.empty()) return;

  CompactionState compaction_state(space, movable_references);
  for (BasePage* page : pages) {
    page->ResetMarkedBytes();
    // Large objects do not belong to this arena.
    CompactPage(NormalPage::From(page), compaction_state, sticky_bits);
  }

  compaction_state.FinishCompactingSpace();
  // Sweeping will verify object start bitmap of compacted space.
}

size_t UpdateHeapResidency(const std::vector<NormalPageSpace*>& spaces) {
  return std::accumulate(spaces.cbegin(), spaces.cend(), 0u,
                         [](size_t acc, const NormalPageSpace* space) {
                           DCHECK(space->is_compactable());
                           if (!space->size()) return acc;
                           return acc + space->free_list().Size();
                         });
}

}  // namespace

Compactor::Compactor(RawHeap& heap) : heap_(heap) {
  for (auto& space : heap_) {
    if (!space->is_compactable()) continue;
    DCHECK_EQ(&heap, space->raw_heap());
    compactable_spaces_.push_back(static_cast<NormalPageSpace*>(space.get()));
  }
}

bool Compactor::ShouldCompact(GCConfig::MarkingType marking_type,
                              StackState stack_state) const {
  if (compactable_spaces_.empty() ||
      (marking_type == GCConfig::MarkingType::kAtomic &&
       stack_state == StackState::kMayContainHeapPointers)) {
    // The following check ensures that tests that want to test compaction are
    // not interrupted by garbage collections that cannot use compaction.
    DCHECK(!enable_for_next_gc_for_testing_);
    return false;
  }

  if (enable_for_next_gc_for_testing_) {
    return true;
  }

  size_t free_list_size = UpdateHeapResidency(compactable_spaces_);

  return free_list_size > kFreeListSizeThreshold;
}

void Compactor::InitializeIfShouldCompact(GCConfig::MarkingType marking_type,
                                          StackState stack_state) {
  DCHECK(!is_enabled_);

  if (!ShouldCompact(marking_type, stack_state)) return;

  compaction_worklists_ = std::make_unique<CompactionWorklists>();

  is_enabled_ = true;
  is_cancelled_ = false;
}

void Compactor::CancelIfShouldNotCompact(GCConfig::MarkingType marking_type,
                                         StackState stack_state) {
  if (!is_enabled_ || ShouldCompact(marking_type, stack_state)) return;

  is_cancelled_ = true;
  is_enabled_ = false;
}

Compactor::CompactableSpaceHandling Compactor::CompactSpacesIfEnabled() {
  if (is_cancelled_ && compaction_worklists_) {
    compaction_worklists_->movable_slots_worklist()->Clear();
    compaction_worklists_.reset();
  }
  if (!is_enabled_) return CompactableSpaceHandling::kSweep;

  StatsCollector::EnabledScope stats_scope(heap_.heap()->stats_collector(),
                                           StatsCollector::kAtomicCompact);

  MovableReferences movable_references(*heap_.heap());

  CompactionWorklists::MovableReferencesWorklist::Local local(
      *compaction_worklists_->movable_slots_worklist());
  CompactionWorklists::MovableReference* slot;
  while (local.Pop(&slot)) {
    movable_references.AddOrFilter(slot);
  }
  compaction_worklists_.reset();

  const StickyBits sticky_bits = heap_.heap()->sticky_bits();

  for (NormalPageSpace* space : compactable_spaces_) {
    CompactSpace(space, movable_references, sticky_bits);
  }

  enable_for_next_gc_for_testing_ = false;
  is_enabled_ = false;
  return CompactableSpaceHandling::kIgnore;
}

void Compactor::EnableForNextGCForTesting() {
  DCHECK_NULL(heap_.heap()->marker());
  enable_for_next_gc_for_testing_ = true;
}

}  // namespace internal
}  // namespace cppgc
```