Response:
Let's break down the thought process for analyzing the C++ code and generating the response.

1. **Understanding the Goal:** The request asks for an explanation of the `remembered-set.cc` file in V8's `cppgc` (C++ garbage collection) component. It also has specific instructions about how to present the information (Torque, JavaScript relevance, logic, errors).

2. **Initial Code Scan (Keywords and Structure):**  The first step is a quick scan of the code for key terms and structural elements:
    * `Copyright`, `#include`: Standard C++ header.
    * `#if defined(CPPGC_YOUNG_GENERATION)`:  Indicates this code is specific to the young generation garbage collection within `cppgc`. This is a crucial piece of context.
    * `namespace cppgc`, `namespace internal`:  Namespaces for organization.
    * `class OldToNewRememberedSet`: The central class. The name itself is highly suggestive – it deals with remembering things related to moving from "old" to "new" generations.
    * `std::set`:  Used extensively, suggesting the storage of unique pointers or values.
    * `AddSlot`, `AddUncompressedSlot`, `AddSourceObject`, `AddWeakCallback`, `AddInConstructionObjectToBeRetraced`: These methods clearly indicate the functions of the remembered set – to record different kinds of "remembered" information.
    * `Invalidate...`: Methods for removing entries, implying managing the lifetime of remembered information.
    * `Visit...`:  Methods for iterating and processing the remembered information, likely during garbage collection.
    * `Reset`, `IsEmpty`: Standard lifecycle management.

3. **Inferring the Core Functionality (Hypotheses):** Based on the keywords and class names, the central hypothesis emerges:  The `OldToNewRememberedSet` is a mechanism to track pointers from older generations of the heap to objects in the younger generation. This is a standard technique in generational garbage collection to optimize the process. Without this information, a full garbage collection would be needed every time, which is less efficient.

4. **Detailed Analysis of Key Methods:** Now, go deeper into the key methods:
    * **`AddSlot(void* slot)`:**  The name suggests tracking individual memory locations (slots). The interaction with `SlotSet` and the `#if defined(DEBUG)` block are noted for later discussion. The use of compressed pointers is also observed.
    * **`AddUncompressedSlot(void* uncompressed_slot)`:** A similar function but for uncompressed pointers. The existence of both compressed and uncompressed versions is important.
    * **`AddSourceObject(HeapObjectHeader& hoh)`:**  Tracks entire objects (represented by their headers). This is likely for cases where the entire object needs to be considered.
    * **`AddWeakCallback(WeakCallbackItem item)`:** Deals with weak references and associated callbacks. This is standard GC functionality.
    * **`InvalidateRememberedSlotsInRange(void* begin, void* end)`:**  Crucial for handling object deallocation. When an old-generation object is freed, pointers to young-generation objects it held need to be invalidated.
    * **`Visit(Visitor& visitor, ...)`:** The heart of the GC process. It iterates through the remembered information and uses a `Visitor` pattern to process the referenced objects. The distinction between compressed and uncompressed slots is re-emphasized. The revisiting of "in-construction" objects is a noteworthy detail.
    * **`Reset()`:**  Clears the remembered set.

5. **Addressing Specific Instructions:**

    * **Torque:** The code does *not* have a `.tq` extension, so this is a straightforward "no."
    * **JavaScript Relevance:** This requires connecting the C++ GC mechanism to JavaScript concepts. The key link is how JavaScript objects are managed in memory. The `cppgc` is directly responsible for this. Therefore, the remembered set indirectly affects how JavaScript objects with cross-generational references are handled during garbage collection. An example involving an older object holding a reference to a newer object is needed.
    * **Logic Inference:** Focus on a key method like `InvalidateRememberedSlotsInRange`. Create a simple scenario with memory addresses to illustrate how the sets are updated.
    * **Common Programming Errors:** Think about what problems developers might face related to memory management and how this system helps prevent them. Dangling pointers are a prime example. Explain how the remembered set helps avoid accessing freed memory.

6. **Structuring the Output:** Organize the information logically, starting with a high-level summary and then drilling down into specifics. Use clear headings and bullet points. Ensure all parts of the request are addressed.

7. **Refinement and Review:** Read through the generated response to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For example, explicitly state *why* a remembered set is necessary in generational GC.

**Self-Correction Example during the Process:**

Initially, I might focus too much on the low-level details of `SlotSet`. However, the request asks for the *functionality* of the file. Therefore, I need to shift the emphasis to the *purpose* of the remembered set within the broader GC context. The `SlotSet` is an implementation detail; the key is what the `OldToNewRememberedSet` *achieves*. Similarly, while compressed pointers are mentioned, the core concept of tracking cross-generational references is more important for a general understanding. The depth of technical detail should align with the intended audience (someone trying to understand the purpose of this file).
好的，让我们来分析一下 `v8/src/heap/cppgc/remembered-set.cc` 这个文件。

**1. 文件功能概述**

`v8/src/heap/cppgc/remembered-set.cc` 文件实现了 `OldToNewRememberedSet` 类，这个类是 `cppgc` (V8 的 C++ garbage collector) 中用于**记录和管理从老生代对象指向新生代对象的指针**的数据结构。这是实现**分代垃圾回收 (Generational Garbage Collection)** 的关键组成部分。

更具体地说，它的功能包括：

* **记录跨代指针：** 当一个老生代 (old generation) 的对象持有一个指向新生代 (young generation) 对象的指针时，这个指针会被记录在 remembered set 中。
* **支持压缩和非压缩指针：**  代码中区分了 `CompressedPointer` 和普通指针，说明 remembered set 需要处理这两种类型的指针。
* **失效（Invalidate）记录：** 当新生代对象被回收或老生代对象被修改时，相关的 remembered set 记录需要被移除或更新，以避免悬空指针。
* **在垃圾回收期间使用：**  在新生代垃圾回收过程中，垃圾回收器会遍历 remembered set，找到所有指向新生代对象的来自老生代的指针，并将这些老生代对象标记为存活，从而避免错误地回收新生代对象。
* **支持弱回调：**  除了记录普通的对象指针，remembered set 还能管理与老生代对象关联的弱回调 (WeakCallback)。
* **处理正在构造的对象：**  它还需要处理在垃圾回收开始时仍在构造中的对象，确保这些对象及其引用的新生代对象被正确处理。

**2. 关于 .tq 扩展名**

如果 `v8/src/heap/cppgc/remembered-set.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**文件。 Torque 是 V8 用来生成高效 JavaScript 内置函数和运行时代码的领域特定语言。 然而，根据你提供的文件内容，它以 `.cc` 结尾，因此是 **C++ 源代码**。

**3. 与 JavaScript 的关系**

`remembered-set.cc` 中的功能直接关系到 JavaScript 的垃圾回收机制。  在 V8 中，JavaScript 堆内存被划分为不同的代 (generations)，新生代主要存放新创建的对象，老生代存放经过多次垃圾回收后仍然存活的对象。

为了优化垃圾回收性能，通常只对新生代进行频繁的垃圾回收 (Minor GC)。 然而，如果老生代对象持有对新生代对象的引用，那么在只回收新生代时，需要一种机制来确保这些被老生代引用的新生代对象不会被错误地回收。  `OldToNewRememberedSet` 正是为此目的而设计的。

**JavaScript 示例：**

```javascript
// 假设 oldGenObject 是一个已经存在于老生代的 JavaScript 对象
let oldGenObject = {};

// 创建一个新的 JavaScript 对象，它会分配到新生代
let youngGenObject = { data: 123 };

// 老生代对象持有对新生代对象的引用
oldGenObject.reference = youngGenObject;

// 在 cppgc 的 remembered-set 中，会记录从 oldGenObject 到 youngGenObject 的引用。

// 当进行新生代垃圾回收时，垃圾回收器会检查 remembered-set，
// 发现 oldGenObject 引用了 youngGenObject，
// 因此 youngGenObject 不会被回收，即使它本身可能没有其他来自新生代的引用。

// 如果没有 remembered-set，只进行新生代回收，youngGenObject 可能会被错误地回收，
// 导致 oldGenObject.reference 指向已被释放的内存，引发错误。
```

**4. 代码逻辑推理**

**假设输入：**

* 存在一个老生代对象 `oldObject`，其内存地址为 `0x1000`。
* 存在一个新生代对象 `youngObject`，其内存地址为 `0x2000`。
* `oldObject` 的某个成员变量指向 `youngObject`，该成员变量的地址为 `0x1008`，其值为 `0x2000`。

**执行 `OldToNewRememberedSet::AddSlot(void* slot)`：**

当 V8 的写屏障 (write barrier) 检测到从 `oldObject` 到 `youngObject` 的指针写入时，会调用 `AddSlot`，并将 `0x1008` 作为参数传入。

**内部逻辑：**

1. `BasePage::FromInnerAddress(&heap_, slot)`:  根据 `0x1008` 找到 `oldObject` 所在的内存页。
2. `source_page->GetOrAllocateSlotSet()`: 获取或创建与该内存页关联的 `SlotSet`。
3. `slot_offset = reinterpret_cast<uintptr_t>(slot) - reinterpret_cast<uintptr_t>(source_page)`: 计算 `0x1008` 相对于页起始地址的偏移量。
4. `slot_set.Insert<SlotSet::AccessMode::NON_ATOMIC>(static_cast<size_t>(slot_offset))`: 将该偏移量插入到 `SlotSet` 中。

**输出（Remembered Set 的状态）：**

Remembered Set 中会记录老生代对象所在的页以及指向新生代对象的指针槽位的偏移量。  具体来说，与 `oldObject` 所在的页关联的 `SlotSet` 将包含一个记录，表明在该页的某个偏移位置（对应于 `0x1008`）存在一个指向新生代的指针。

**执行新生代垃圾回收时：**

垃圾回收器会遍历 remembered set。对于记录的每个槽位（例如，偏移量对应于 `0x1008`），垃圾回收器会读取该位置的值 (`0x2000`)，并标记 `youngObject` 为存活，即使 `youngObject` 没有其他来自新生代的引用。

**5. 用户常见的编程错误**

与 `remembered-set.cc` 功能相关的用户常见编程错误主要涉及内存管理和对象生命周期：

* **悬空指针 (Dangling Pointers)：** 这是 remembered set 旨在解决的核心问题。  如果老生代对象持有一个指向已经被回收的新生代对象的指针，那么访问该指针会导致程序崩溃或未定义行为。 remembered set 确保在新生代回收时，所有来自老生代的引用都被考虑在内。

   **错误示例 (C++ 模拟):**

   ```c++
   class Young {
   public:
       int data;
   };

   class Old {
   public:
       Young* ptr;
   };

   // ... (假设 old_object 是老生代对象， young_object 是新生代对象)

   Old* old_object = new Old();
   Young* young_object = new Young();
   old_object->ptr = young_object;

   // ... (新生代垃圾回收发生，但 remembered set 没有正确工作或不存在)

   // young_object 可能被回收

   // 错误：访问悬空指针
   std::cout << old_object->ptr->data << std::endl;
   ```

* **内存泄漏 (Memory Leaks)：** 虽然 remembered set 主要关注避免过早回收，但在某些复杂情况下，如果 remembered set 的管理不当，或者存在循环引用等问题，可能间接导致某些对象无法被回收，从而引发内存泄漏。但这通常不是 remembered set 本身的问题，而是垃圾回收器整体策略或用户代码逻辑的问题。

* **在析构函数或生命周期管理中出错：** 如果用户自定义的 C++ 对象具有复杂的生命周期管理，并且没有正确处理跨代指针的更新或失效，可能会导致 remembered set 的信息不准确，进而影响垃圾回收的正确性。

总而言之，`v8/src/heap/cppgc/remembered-set.cc` 文件是 V8 中实现高效分代垃圾回收的关键基础设施，它通过维护从老生代到新生代的指针信息，确保新生代垃圾回收的正确性和性能。理解其功能有助于理解 V8 的内存管理机制。

Prompt: 
```
这是目录为v8/src/heap/cppgc/remembered-set.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/cppgc/remembered-set.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if defined(CPPGC_YOUNG_GENERATION)

#include "src/heap/cppgc/remembered-set.h"

#include <algorithm>

#include "include/cppgc/member.h"
#include "include/cppgc/visitor.h"
#include "src/heap/base/basic-slot-set.h"
#include "src/heap/cppgc/heap-base.h"
#include "src/heap/cppgc/heap-object-header.h"
#include "src/heap/cppgc/heap-page.h"
#include "src/heap/cppgc/heap-visitor.h"
#include "src/heap/cppgc/marking-state.h"

namespace cppgc {
namespace internal {

namespace {

enum class SlotType { kCompressed, kUncompressed };

void EraseFromSet(std::set<void*>& set, void* begin, void* end) {
  // TODO(1029379): The 2 binary walks can be optimized with a custom algorithm.
  auto from = set.lower_bound(begin), to = set.lower_bound(end);
  set.erase(from, to);
}

// TODO(1029379): Make the implementation functions private functions of
// OldToNewRememberedSet to avoid parameter passing.
void InvalidateCompressedRememberedSlots(
    const HeapBase& heap, void* begin, void* end,
    std::set<void*>& remembered_slots_for_verification) {
  DCHECK_LT(begin, end);

  BasePage* page = BasePage::FromInnerAddress(&heap, begin);
  DCHECK_NOT_NULL(page);
  // The input range must reside within the same page.
  DCHECK_EQ(page, BasePage::FromInnerAddress(
                      &heap, reinterpret_cast<void*>(
                                 reinterpret_cast<uintptr_t>(end) - 1)));

  auto* slot_set = page->slot_set();
  if (!slot_set) return;

  const size_t buckets_size = SlotSet::BucketsForSize(page->AllocatedSize());

  const uintptr_t page_start = reinterpret_cast<uintptr_t>(page);
  const uintptr_t ubegin = reinterpret_cast<uintptr_t>(begin);
  const uintptr_t uend = reinterpret_cast<uintptr_t>(end);

  slot_set->RemoveRange(ubegin - page_start, uend - page_start, buckets_size,
                        SlotSet::EmptyBucketMode::FREE_EMPTY_BUCKETS);
#if DEBUG
  EraseFromSet(remembered_slots_for_verification, begin, end);
#endif  // DEBUG
}

void InvalidateUncompressedRememberedSlots(
    std::set<void*>& slots, void* begin, void* end,
    std::set<void*>& remembered_slots_for_verification) {
  EraseFromSet(slots, begin, end);
#if DEBUG
  EraseFromSet(remembered_slots_for_verification, begin, end);
#endif  // DEBUG
#if defined(ENABLE_SLOW_DCHECKS)
  // Check that no remembered slots are referring to the freed area.
  DCHECK(std::none_of(slots.begin(), slots.end(), [begin, end](void* slot) {
    void* value = nullptr;
    value = *reinterpret_cast<void**>(slot);
    return begin <= value && value < end;
  }));
#endif  // defined(ENABLE_SLOW_DCHECKS)
}

// Visit remembered set that was recorded in the generational barrier.
template <SlotType slot_type>
void VisitSlot(const HeapBase& heap, const BasePage& page, Address slot,
               MutatorMarkingState& marking_state,
               const std::set<void*>& slots_for_verification) {
#if defined(DEBUG)
  DCHECK_EQ(BasePage::FromInnerAddress(&heap, slot), &page);
  DCHECK_NE(slots_for_verification.end(), slots_for_verification.find(slot));
#endif  // defined(DEBUG)

  // Slot must always point to a valid, not freed object.
  auto& slot_header = page.ObjectHeaderFromInnerAddress(slot);
  // The age checking in the generational barrier is imprecise, since a card
  // may have mixed young/old objects. Check here precisely if the object is
  // old.
  if (slot_header.IsYoung()) return;

#if defined(CPPGC_POINTER_COMPRESSION)
  void* value = nullptr;
  if constexpr (slot_type == SlotType::kCompressed) {
    value = CompressedPointer::Decompress(*reinterpret_cast<uint32_t*>(slot));
  } else {
    value = *reinterpret_cast<void**>(slot);
  }
#else   // !defined(CPPGC_POINTER_COMPRESSION)
  void* value = *reinterpret_cast<void**>(slot);
#endif  // !defined(CPPGC_POINTER_COMPRESSION)

  // Slot could be updated to nullptr or kSentinelPointer by the mutator.
  if (value == kSentinelPointer || value == nullptr) return;

#if defined(DEBUG)
  // Check that the slot can not point to a freed object.
  HeapObjectHeader& header =
      BasePage::FromPayload(value)->ObjectHeaderFromInnerAddress(value);
  DCHECK(!header.IsFree());
#endif  // defined(DEBUG)

  marking_state.DynamicallyMarkAddress(static_cast<Address>(value));
}

class CompressedSlotVisitor : HeapVisitor<CompressedSlotVisitor> {
  friend class HeapVisitor<CompressedSlotVisitor>;

 public:
  CompressedSlotVisitor(HeapBase& heap, MutatorMarkingState& marking_state,
                        const std::set<void*>& slots_for_verification)
      : heap_(heap),
        marking_state_(marking_state),
        remembered_slots_for_verification_(slots_for_verification) {}

  size_t Run() {
    Traverse(heap_.raw_heap());
    return objects_visited_;
  }

 private:
  heap::base::SlotCallbackResult VisitCompressedSlot(Address slot) {
    DCHECK(current_page_);
    VisitSlot<SlotType::kCompressed>(heap_, *current_page_, slot,
                                     marking_state_,
                                     remembered_slots_for_verification_);
    ++objects_visited_;
    return heap::base::KEEP_SLOT;
  }

  void VisitSlotSet(SlotSet* slot_set) {
    DCHECK(current_page_);

    if (!slot_set) return;

    const uintptr_t page_start = reinterpret_cast<uintptr_t>(current_page_);
    const size_t buckets_size =
        SlotSet::BucketsForSize(current_page_->AllocatedSize());

    slot_set->Iterate(
        page_start, 0, buckets_size,
        [this](SlotSet::Address slot) {
          return VisitCompressedSlot(reinterpret_cast<Address>(slot));
        },
        SlotSet::EmptyBucketMode::FREE_EMPTY_BUCKETS);
  }

  bool VisitNormalPage(NormalPage& page) {
    current_page_ = &page;
    VisitSlotSet(page.slot_set());
    return true;
  }

  bool VisitLargePage(LargePage& page) {
    current_page_ = &page;
    VisitSlotSet(page.slot_set());
    return true;
  }

  HeapBase& heap_;
  MutatorMarkingState& marking_state_;
  BasePage* current_page_ = nullptr;

  const std::set<void*>& remembered_slots_for_verification_;
  size_t objects_visited_ = 0u;
};

class SlotRemover : HeapVisitor<SlotRemover> {
  friend class HeapVisitor<SlotRemover>;

 public:
  explicit SlotRemover(HeapBase& heap) : heap_(heap) {}

  void Run() { Traverse(heap_.raw_heap()); }

 private:
  bool VisitNormalPage(NormalPage& page) {
    page.ResetSlotSet();
    return true;
  }

  bool VisitLargePage(LargePage& page) {
    page.ResetSlotSet();
    return true;
  }

  HeapBase& heap_;
};

// Visit remembered set that was recorded in the generational barrier.
void VisitRememberedSlots(
    HeapBase& heap, MutatorMarkingState& mutator_marking_state,
    const std::set<void*>& remembered_uncompressed_slots,
    const std::set<void*>& remembered_slots_for_verification) {
  size_t objects_visited = 0;
  {
    CompressedSlotVisitor slot_visitor(heap, mutator_marking_state,
                                       remembered_slots_for_verification);
    objects_visited += slot_visitor.Run();
  }
  for (void* uncompressed_slot : remembered_uncompressed_slots) {
    auto* page = BasePage::FromInnerAddress(&heap, uncompressed_slot);
    DCHECK(page);
    VisitSlot<SlotType::kUncompressed>(
        heap, *page, static_cast<Address>(uncompressed_slot),
        mutator_marking_state, remembered_slots_for_verification);
    ++objects_visited;
  }
  DCHECK_EQ(remembered_slots_for_verification.size(), objects_visited);
  USE(objects_visited);
}

// Visits source objects that were recorded in the generational barrier for
// slots.
void VisitRememberedSourceObjects(
    const std::set<HeapObjectHeader*>& remembered_source_objects,
    Visitor& visitor) {
  for (HeapObjectHeader* source_hoh : remembered_source_objects) {
    DCHECK(source_hoh);
    // The age checking in the generational barrier is imprecise, since a card
    // may have mixed young/old objects. Check here precisely if the object is
    // old.
    if (source_hoh->IsYoung()) continue;

    const TraceCallback trace_callback =
        GlobalGCInfoTable::GCInfoFromIndex(source_hoh->GetGCInfoIndex()).trace;

    // Process eagerly to avoid reaccounting.
    trace_callback(&visitor, source_hoh->ObjectStart());
  }
}

// Revisit in-construction objects from previous GCs. We must do it to make
// sure that we don't miss any initializing pointer writes if a previous GC
// happened while an object was in-construction.
void RevisitInConstructionObjects(
    std::set<HeapObjectHeader*>& remembered_in_construction_objects,
    Visitor& visitor, ConservativeTracingVisitor& conservative_visitor) {
  for (HeapObjectHeader* hoh : remembered_in_construction_objects) {
    DCHECK(hoh);
    // The object must be marked on previous GC.
    DCHECK(hoh->IsMarked());

    if (hoh->template IsInConstruction<AccessMode::kNonAtomic>()) {
      conservative_visitor.TraceConservatively(*hoh);
    } else {
      // If the object is fully constructed, trace precisely.
      const TraceCallback trace_callback =
          GlobalGCInfoTable::GCInfoFromIndex(hoh->GetGCInfoIndex()).trace;
      trace_callback(&visitor, hoh->ObjectStart());
    }
  }
}

}  // namespace

void OldToNewRememberedSet::AddSlot(void* slot) {
  DCHECK(heap_.generational_gc_supported());

  BasePage* source_page = BasePage::FromInnerAddress(&heap_, slot);
  DCHECK(source_page);

  auto& slot_set = source_page->GetOrAllocateSlotSet();

  const uintptr_t slot_offset = reinterpret_cast<uintptr_t>(slot) -
                                reinterpret_cast<uintptr_t>(source_page);

  slot_set.Insert<SlotSet::AccessMode::NON_ATOMIC>(
      static_cast<size_t>(slot_offset));

#if defined(DEBUG)
  remembered_slots_for_verification_.insert(slot);
#endif  // defined(DEBUG)
}

void OldToNewRememberedSet::AddUncompressedSlot(void* uncompressed_slot) {
  DCHECK(heap_.generational_gc_supported());
  remembered_uncompressed_slots_.insert(uncompressed_slot);
#if defined(DEBUG)
  remembered_slots_for_verification_.insert(uncompressed_slot);
#endif  // defined(DEBUG)
}

void OldToNewRememberedSet::AddSourceObject(HeapObjectHeader& hoh) {
  DCHECK(heap_.generational_gc_supported());
  remembered_source_objects_.insert(&hoh);
}

void OldToNewRememberedSet::AddWeakCallback(WeakCallbackItem item) {
  DCHECK(heap_.generational_gc_supported());
  // TODO(1029379): WeakCallbacks are also executed for weak collections.
  // Consider splitting weak-callbacks in custom weak callbacks and ones for
  // collections.
  remembered_weak_callbacks_.insert(item);
}

void OldToNewRememberedSet::AddInConstructionObjectToBeRetraced(
    HeapObjectHeader& hoh) {
  DCHECK(heap_.generational_gc_supported());
  remembered_in_construction_objects_.current.insert(&hoh);
}

void OldToNewRememberedSet::InvalidateRememberedSlotsInRange(void* begin,
                                                             void* end) {
  DCHECK(heap_.generational_gc_supported());
  InvalidateCompressedRememberedSlots(heap_, begin, end,
                                      remembered_slots_for_verification_);
  InvalidateUncompressedRememberedSlots(remembered_uncompressed_slots_, begin,
                                        end,
                                        remembered_slots_for_verification_);
}

void OldToNewRememberedSet::InvalidateRememberedSourceObject(
    HeapObjectHeader& header) {
  DCHECK(heap_.generational_gc_supported());
  remembered_source_objects_.erase(&header);
}

void OldToNewRememberedSet::Visit(
    Visitor& visitor, ConservativeTracingVisitor& conservative_visitor,
    MutatorMarkingState& marking_state) {
  DCHECK(heap_.generational_gc_supported());
  VisitRememberedSlots(heap_, marking_state, remembered_uncompressed_slots_,
                       remembered_slots_for_verification_);
  VisitRememberedSourceObjects(remembered_source_objects_, visitor);
  RevisitInConstructionObjects(remembered_in_construction_objects_.previous,
                               visitor, conservative_visitor);
}

void OldToNewRememberedSet::ExecuteCustomCallbacks(LivenessBroker broker) {
  DCHECK(heap_.generational_gc_supported());
  for (const auto& callback : remembered_weak_callbacks_) {
    callback.callback(broker, callback.parameter);
  }
}

void OldToNewRememberedSet::ReleaseCustomCallbacks() {
  DCHECK(heap_.generational_gc_supported());
  remembered_weak_callbacks_.clear();
}

void OldToNewRememberedSet::Reset() {
  DCHECK(heap_.generational_gc_supported());
  SlotRemover slot_remover(heap_);
  slot_remover.Run();
  remembered_uncompressed_slots_.clear();
  remembered_source_objects_.clear();
#if DEBUG
  remembered_slots_for_verification_.clear();
#endif  // DEBUG
  remembered_in_construction_objects_.Reset();
  // Custom weak callbacks is alive across GCs.
}

bool OldToNewRememberedSet::IsEmpty() const {
  // TODO(1029379): Add visitor to check if empty.
  return remembered_uncompressed_slots_.empty() &&
         remembered_source_objects_.empty() &&
         remembered_weak_callbacks_.empty();
}

void OldToNewRememberedSet::RememberedInConstructionObjects::Reset() {
  // Make sure to keep the still-in-construction objects in the remembered set,
  // as otherwise, being marked, the marker won't be able to observe them.
  std::copy_if(previous.begin(), previous.end(),
               std::inserter(current, current.begin()),
               [](const HeapObjectHeader* h) {
                 return h->template IsInConstruction<AccessMode::kNonAtomic>();
               });
  previous = std::move(current);
  current.clear();
}

}  // namespace internal
}  // namespace cppgc

#endif  // defined(CPPGC_YOUNG_GENERATION)

"""

```