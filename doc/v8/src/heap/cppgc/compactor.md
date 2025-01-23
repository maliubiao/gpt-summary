Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript example.

1. **Understand the Goal:** The primary goal is to understand what the C++ code does and how it relates to JavaScript (specifically V8's JavaScript engine). This involves identifying the core functionality, key data structures, and interactions with other parts of the engine.

2. **Initial Scan for Keywords and Concepts:** Quickly read through the code, looking for recurring terms and familiar garbage collection concepts. Keywords like `compactor`, `heap`, `page`, `slot`, `relocate`, `free list`, `mark`, `sweep`, `move listeners`, `sticky bits`, `compaction worklists` immediately stand out. These provide initial clues about the code's purpose.

3. **Identify the Main Class:** The `Compactor` class seems to be the central entity. Focus on its methods: `ShouldCompact`, `InitializeIfShouldCompact`, `CancelIfShouldNotCompact`, `CompactSpacesIfEnabled`, `EnableForNextGCForTesting`. These methods suggest a lifecycle for compaction: deciding whether to compact, initializing the process, potentially canceling, and finally performing the compaction.

4. **Focus on Key Helper Classes:** Notice the nested `MovableReferences` class. This appears crucial. Its methods like `AddOrFilter`, `Relocate`, and `RelocateInteriorReferences` suggest it manages the process of updating pointers when objects are moved during compaction. The `CompactionState` class seems responsible for managing the state during the actual compaction process, handling page allocation and object movement.

5. **Trace the Compaction Process:**  Follow the execution flow of `CompactSpacesIfEnabled`.
    * It creates a `MovableReferences` object.
    * It processes `movable_slots_worklist` to identify slots that need updating.
    * It iterates through `compactable_spaces_`.
    * For each space, it calls `CompactSpace`.
    * `CompactSpace` iterates through pages and calls `CompactPage`.
    * `CompactPage` identifies live objects and uses `compaction_state.RelocateObject` to move them.
    * `MovableReferences` is used within `RelocateObject` to update pointers.

6. **Understand the "Why":**  Compaction is a garbage collection technique. Why is it needed? The comments mention "smaller heap page footprint and improved locality."  This clarifies that the goal is to reduce memory fragmentation and improve performance by grouping live objects together.

7. **Connect to JavaScript:** How does this relate to JavaScript?
    * **Memory Management:** JavaScript engines perform automatic garbage collection. This C++ code is part of V8, a prominent JavaScript engine. The compaction process directly impacts how JavaScript objects are managed in memory.
    * **Object References:** JavaScript objects hold references to other objects. When compaction moves objects, these references need to be updated. This is precisely what the `MovableReferences` class handles.
    * **Performance:** Compaction aims to improve the performance of JavaScript applications by reducing fragmentation and improving cache locality.

8. **Formulate the Summary:** Based on the understanding gained, summarize the key functionalities:
    * Purpose: Defragment the heap by moving live objects.
    * Key classes: `Compactor`, `MovableReferences`, `CompactionState`.
    * Workflow: Identifying movable references, relocating objects, updating pointers.
    * Triggering: Based on free list size or testing.

9. **Create a JavaScript Example:**  The challenge is to illustrate the *effect* of compaction from a JavaScript perspective, without directly exposing the C++ implementation details. Focus on the idea of references and how they remain valid even after objects move.
    *  Create a scenario with interconnected objects.
    *  Simulate the *concept* of moving objects (without actually doing the C++ memory manipulation).
    *  Demonstrate that references still point to the correct objects after the simulated "move."  This highlights the role of the C++ compactor in ensuring the integrity of these references. A simple way to simulate the "move" is to just change the value of a property and observe that accessing it through another object works.

10. **Refine and Iterate:** Review the summary and the JavaScript example. Ensure clarity, accuracy, and conciseness. For instance, initially, I might have focused too much on the low-level details of page management. Refinement would involve emphasizing the core concept of object relocation and reference updating. The JavaScript example needs to be simple and effectively illustrate the concept. Adding comments in both the summary and the example enhances understanding.

This iterative process of reading, identifying key components, understanding the "why," connecting to JavaScript, and refining the explanation leads to the well-structured summary and illustrative JavaScript example.这个C++源代码文件 `compactor.cc` 位于 V8 引擎的 `heap/cppgc` 目录下，它的主要功能是实现 **堆内存的压缩（Compaction）**。  具体来说，它负责在垃圾回收过程中整理堆内存，将存活的对象移动到一起，从而减少内存碎片，提高内存利用率和程序性能。

**核心功能归纳:**

1. **决定是否进行压缩 (ShouldCompact):**  `Compactor` 类会根据堆的当前状态（例如，空闲列表的大小）以及垃圾回收的类型和栈状态来判断是否需要进行内存压缩。

2. **管理可移动对象引用 (MovableReferences):**  这是一个内部类，负责记录指向可移动对象的引用（称为 "slots"）。当对象被移动后，这个类会负责更新这些引用，确保它们仍然指向对象的新位置。  这包括：
   - `AddOrFilter`:  添加需要更新的槽位，并过滤掉指向已死亡对象的槽位。
   - `Relocate`:  当一个对象从旧地址移动到新地址时，更新指向该对象的槽位。
   - `RelocateInteriorReferences`: 处理对象内部的指针引用。

3. **管理压缩状态 (CompactionState):**  这是一个内部类，负责在压缩过程中跟踪当前的状态，例如：
   - 管理用于存放移动后对象的页面。
   - 将存活的对象从旧位置复制到新位置。
   - 更新对象的起始位图。
   - 处理页面之间的切换。

4. **压缩单个页面 (CompactPage):**  负责压缩单个内存页面的功能，遍历页面上的对象，将存活的对象移动到新的位置。

5. **压缩整个空间 (CompactSpace):**  负责压缩整个内存空间的功能，它会处理空间内的所有页面，并调用 `CompactPage` 来压缩每个页面。

6. **更新堆驻留信息 (UpdateHeapResidency):**  计算堆的空闲列表大小，用于判断是否需要进行压缩。

**与 JavaScript 功能的关系及 JavaScript 示例:**

这个 C++ 代码是 V8 引擎的一部分，直接影响着 JavaScript 程序的内存管理和性能。 JavaScript 代码本身无法直接调用或感知这些底层的 C++ 实现细节。 然而，内存压缩的目的是为了优化 JavaScript 程序的运行效率。

当 JavaScript 代码创建大量的对象，并且这些对象经历分配和释放后，堆内存可能会变得碎片化。 这会导致即使有足够的总内存，也可能因为没有连续的内存块而无法分配新的大对象，或者降低内存访问效率。  V8 的垃圾回收机制中的压缩步骤就是为了解决这个问题。

**JavaScript 层面的体现 (概念性示例):**

虽然 JavaScript 无法直接控制内存压缩，但我们可以通过观察内存使用和性能来间接感受到其影响。

```javascript
// 模拟创建大量对象并释放，导致内存碎片
let objects = [];
for (let i = 0; i < 10000; i++) {
  objects.push({ data: new Array(100).fill(i) });
}
objects = []; // 释放所有对象，但内存可能存在碎片

// 再次分配一个较大的对象
let largeObject = new Array(1000000).fill(0);

// 在没有内存压缩的情况下，即使之前释放了很多小对象，
// 如果堆内存碎片化严重，分配 largeObject 可能仍然会遇到问题
// 或者访问效率会下降。

// 内存压缩的作用就是整理这些碎片，使得后续分配更容易，
// 并且对象在内存中排列更紧凑，提高访问速度。
```

**更具体的 JavaScript 例子来体现引用的更新:**

假设在 JavaScript 中有两个对象 `objA` 和 `objB`，`objA` 的一个属性指向 `objB`。 当 V8 的垃圾回收器进行内存压缩时，`objB` 的内存地址可能会发生变化。  `compactor.cc` 中的 `MovableReferences` 机制确保 `objA` 中指向 `objB` 的引用会被更新，使得 JavaScript 代码仍然能够正常访问 `objB`。

```javascript
let objB = { value: 10 };
let objA = { refToB: objB };

console.log(objA.refToB.value); // 输出 10

// 模拟 V8 垃圾回收器进行内存压缩，objB 的内存地址可能被改变
// (JavaScript 代码无法直接模拟，这里只是概念性表示)

// 压缩后，objA.refToB 仍然指向 objB 的新位置
console.log(objA.refToB.value); // 仍然输出 10，因为引用已被更新
```

**总结:**

`v8/src/heap/cppgc/compactor.cc` 文件中的代码是 V8 引擎中负责堆内存压缩的关键部分。 它通过移动存活对象和更新引用来整理内存，减少碎片，从而提高 JavaScript 程序的内存利用率和执行效率。  虽然 JavaScript 代码本身无法直接操作这些底层的压缩过程，但内存压缩的结果会直接影响 JavaScript 程序的性能和内存行为。

### 提示词
```
这是目录为v8/src/heap/cppgc/compactor.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
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