Response:
My thought process for analyzing the C++ header file `v8/src/heap/mutable-page-metadata.h` and generating the response involved the following steps:

1. **Understanding the Goal:** The primary goal was to describe the functionality of the header file, explain its potential connection to JavaScript, provide code logic examples (if applicable), and highlight common programming errors related to the concepts it represents.

2. **Initial Scan and Keyword Recognition:** I quickly scanned the header file, looking for key terms and structures. Words like "heap," "page," "metadata," "memory," "slot," "marking," "sweeping," "allocation," "mutex," and "atomic" immediately signaled that this file is crucial for memory management within the V8 JavaScript engine. The presence of `namespace v8::internal` confirmed this was an internal V8 component.

3. **Identifying the Core Class:** The `MutablePageMetadata` class is clearly the central element of the file. I noted its inheritance from `MemoryChunkMetadata`, suggesting a hierarchical structure related to memory management.

4. **Analyzing Key Members and Methods:** I systematically went through the members and methods of `MutablePageMetadata`, grouping them by functionality:

    * **Page State and Sweeping:** The `ConcurrentSweepingState` enum and related methods (`set_concurrent_sweeping_state`, `concurrent_sweeping_state`, `SweepingDone`) indicated functionality related to garbage collection's sweeping phase.

    * **Memory Management Basics:** `kPageSize`, `FromAddress`, `FromHeapObject`, the constructor, `InitialFlags`, `size()`, `area_start()`, `area_end()` pointed to fundamental aspects of managing memory regions (pages/chunks).

    * **Remembered Sets:** The `RememberedSetType` enum and the `slot_set_` and `typed_slot_set_` members along with their accessors (`slot_set()`, `typed_slot_set()`, `AllocateSlotSet`, `ReleaseSlotSet`, etc.) were clearly related to tracking inter-object references, a key part of garbage collection.

    * **Concurrency Control:** The `mutex_` and `shared_mutex_` members highlighted the importance of thread safety and concurrent access to page metadata.

    * **Allocation Tracking:** Methods like `IncreaseAllocatedLabSize`, `DecreaseAllocatedLabSize`, `AllocatedLabSize`, `ResetAllocationStatistics`, and `ResetAllocationStatisticsForPromotedPage` indicated mechanisms for tracking memory allocation within the page.

    * **Marking and Liveness:** The `MarkingProgressTracker`, `live_bytes_`, `SetLiveBytes`, `IncrementLiveBytesAtomically`, `ClearLiveness`, and `marking_bitmap_` members were directly related to the marking phase of garbage collection, identifying live objects.

    * **External Backing Store:** The `external_backing_store_bytes_` and related methods suggested tracking memory used outside the main V8 heap but associated with the page.

    * **List Integration:** The `list_node_` member and the `owner()` method indicated the integration of pages into lists managed by the heap.

5. **Inferring Functionality from Names:** Method and variable names were generally descriptive, aiding in understanding their purpose. For example, `SetOldGenerationPageFlags` and `SetYoungGenerationPageFlags` clearly relate to categorizing pages based on object age.

6. **Considering the ".h" Extension:**  The `.h` extension confirmed that this is a C++ header file, containing declarations but generally not the full implementation. The prompt's question about ".tq" was a distractor in this case, as the extension was clearly ".h".

7. **Connecting to JavaScript (Conceptual):**  While the header is C++, I considered how these low-level memory management concepts impact JavaScript:

    * **Garbage Collection:** The entire file revolves around supporting V8's garbage collector. JavaScript's automatic memory management relies on these underlying mechanisms.
    * **Memory Efficiency:**  The careful tracking of memory, live objects, and inter-object references directly affects the performance and memory consumption of JavaScript applications.
    * **Performance Optimization:**  Features like remembered sets and concurrent sweeping are optimizations to reduce GC pauses and improve overall responsiveness.

8. **Generating Examples (JavaScript and Code Logic):**

    * **JavaScript:** I focused on demonstrating how the *effects* of this low-level code are visible in JavaScript, particularly through garbage collection. The examples showed how creating and discarding objects triggers GC and how memory usage can be observed (though direct manipulation of V8 internals from JavaScript is not possible).

    * **Code Logic:**  I chose a relatively simple example involving the `concurrent_sweeping_state`. This allowed me to illustrate the atomic nature of the state and how it might be used to coordinate sweeping threads. I provided hypothetical input and output to make the example concrete.

9. **Identifying Common Programming Errors (Related Concepts):** I thought about common mistakes JavaScript developers make that are related to memory management, even if they don't directly interact with `MutablePageMetadata`:

    * **Memory Leaks:**  Failure to release references can lead to objects being kept alive longer than necessary, increasing memory usage.
    * **Performance Issues:** Excessive object creation or inefficient data structures can put pressure on the garbage collector.
    * **Understanding GC:** Lack of awareness about how garbage collection works can lead to unexpected behavior or performance bottlenecks.

10. **Structuring the Response:**  I organized the information into clear sections based on the prompt's requirements: Functionality, Torque, JavaScript relation, Code Logic, and Common Errors. I used bullet points and clear language to make the information easy to understand.

11. **Refinement and Review:** I reviewed the generated response to ensure accuracy, clarity, and completeness. I made sure the explanations were accessible to someone who might not be deeply familiar with V8's internals. I double-checked that the examples were relevant and illustrative.

By following these steps, I was able to dissect the C++ header file, understand its purpose within the V8 engine, and relate it to the broader context of JavaScript execution and memory management.
好的，让我们来分析一下 `v8/src/heap/mutable-page-metadata.h` 这个 V8 源代码文件。

**功能列举:**

`v8/src/heap/mutable-page-metadata.h` 定义了 `MutablePageMetadata` 类，该类是 V8 堆中管理可变内存页元数据的核心结构。它的主要功能包括：

1. **表示内存页的元数据:**  `MutablePageMetadata` 存储了关于一个特定内存页的重要信息，这些信息在垃圾回收（GC）和内存管理过程中至关重要。这包括：
    * **页的状态:** 例如，`ConcurrentSweepingState` 枚举定义了页在并发清理过程中的状态（完成、等待清理、正在清理等）。
    * **页的大小:**  `kPageSize` 常量定义了页面的大小。
    * **所属空间:**  指向拥有此页的 `Space` 对象的指针。
    * **内存区域:** 页面的起始地址 (`area_start`) 和结束地址 (`area_end`)。
    * **槽位集合 (Slot Sets):** 用于记录跨页的对象引用，用于垃圾回收的标记和清除阶段。不同类型的 `SlotSet` 对应不同类型的跨页引用（例如，老生代指向新生代、老生代指向老生代等）。
    * **标记位图 (Marking Bitmap):** 用于在垃圾回收的标记阶段记录对象的标记状态。
    * **外部后备存储 (External Backing Store):**  跟踪与此内存块关联的堆外内存使用情况。
    * **分配信息:**  记录了页面的已分配大小 (`allocated_bytes_`) 和浪费的内存 (`wasted_memory_`)。
    * **LAB 大小 (Allocation Lab Size):** 记录了新空间页面上分配的 LAB (Local Allocation Buffer) 的大小。
    * **新生代存活年龄 (Age in New Space):**  记录了页面在新空间中存活的年轻代 GC 次数。
    * **并发清理状态 (Concurrent Sweeping State):** 指示页面是否已完成并发清理，或正处于清理的哪个阶段。
    * **锁 (Mutexes):**  用于保护元数据在并发访问时的安全。

2. **支持垃圾回收:** `MutablePageMetadata` 提供了 GC 过程所需的关键信息和机制：
    * **记录跨页引用:**  通过 `SlotSet` 和 `TypedSlotSet` 跟踪对象间的引用关系，帮助 GC 识别可达对象。
    * **管理并发清理:** `ConcurrentSweepingState` 和相关的原子操作用于协调并发清理线程。
    * **跟踪标记进度:** `MarkingProgressTracker` 用于跟踪大型对象在并发标记过程中的进度。
    * **记录存活字节数:** `live_byte_count_` 记录了页面上的存活对象大小。

3. **管理内存分配:** 虽然不直接负责分配，但 `MutablePageMetadata` 维护了与分配相关的统计信息，例如 `allocated_lab_size_`。

4. **提供辅助方法:**  类中包含了一些辅助方法，用于获取或设置页面的各种属性，例如：
    * `FromAddress(Address a)`:  从地址获取 `MutablePageMetadata` 指针。
    * `FromHeapObject(Tagged<HeapObject> o)`: 从堆对象获取 `MutablePageMetadata` 指针。
    * `SetOldGenerationPageFlags()`, `SetYoungGenerationPageFlags()`: 设置页面的代龄标志。
    * `AllocateSlotSet()`, `ReleaseSlotSet()`: 分配和释放槽位集合。

**关于 `.tq` 结尾:**

如果 `v8/src/heap/mutable-page-metadata.h` 以 `.tq` 结尾，那么它确实是一个 **V8 Torque 源代码文件**。 Torque 是 V8 用来生成高效的 C++ 代码的领域特定语言。  然而，根据您提供的文件名，它以 `.h` 结尾，这意味着它是一个 **C++ 头文件**。

**与 JavaScript 的功能关系及示例:**

`MutablePageMetadata` 在幕后支持着 JavaScript 的内存管理。JavaScript 开发者通常不需要直接操作这个类，但它的工作直接影响着 JavaScript 程序的性能和内存使用。

* **垃圾回收：** 当 JavaScript 引擎执行垃圾回收时，它会遍历堆中的内存页。`MutablePageMetadata` 提供了关于每个页面的信息，例如哪些对象是活动的，哪些对象可以被回收，以及对象之间的引用关系。

* **内存分配：** 当 JavaScript 代码创建新对象时，V8 引擎会在堆中找到合适的内存页进行分配。`MutablePageMetadata` 帮助 V8 管理这些页面的分配状态。

**JavaScript 示例（概念性）：**

虽然无法直接在 JavaScript 中访问 `MutablePageMetadata`，但我们可以通过 JavaScript 的行为来理解其背后的原理。

```javascript
// 创建一些对象
let obj1 = { data: new Array(10000) };
let obj2 = { ref: obj1 };
let obj3 = { data: "一些字符串" };

// 将 obj1 设置为 null，使其变得不可达（除了被 obj2 引用）
obj1 = null;

// 执行某些操作，可能触发垃圾回收
for (let i = 0; i < 1000000; i++) {
  // ... 一些计算 ...
}

// 再次创建对象
let obj4 = { moreData: new Array(5000) };

// ... 更多操作 ...
```

在这个例子中：

* 当 `obj1` 被设置为 `null` 时，如果没有任何其他对象引用它，垃圾回收器最终会识别出它可以被回收。 `MutablePageMetadata` 中与 `obj1` 所在内存页相关的信息会更新。
* `obj2` 仍然引用着最初的 `obj1` 指向的对象。垃圾回收器需要通过 `SlotSet` 等机制来跟踪这种跨对象的引用，以确保被引用的对象不会被错误地回收。
* 新对象的创建可能会导致新的内存页被分配和管理，相应的 `MutablePageMetadata` 实例也会被创建或更新。

**代码逻辑推理及假设输入与输出:**

假设我们有一个 `MutablePageMetadata` 实例 `page_metadata`，它代表一个老生代内存页。

**假设输入:**

* `page_metadata->concurrent_sweeping_state()` 返回 `ConcurrentSweepingState::kPendingSweeping` (表示该页正在等待并发清理)。
* 垃圾回收器决定开始清理该页。

**代码逻辑 (简化):**

在垃圾回收器的某个组件中，可能会有类似这样的逻辑：

```c++
// 假设 page_metadata 是一个 MutablePageMetadata*
if (page_metadata->concurrent_sweeping_state() ==
    MutablePageMetadata::ConcurrentSweepingState::kPendingSweeping) {
  // 获取锁以安全地修改状态
  base::MutexGuard guard(page_metadata->mutex());
  page_metadata->set_concurrent_sweeping_state(
      MutablePageMetadata::ConcurrentSweepingState::kInProgress);
  // ... 开始清理该页面的操作 ...
}
```

**输出:**

* `page_metadata->concurrent_sweeping_state()` 将变为 `ConcurrentSweepingState::kInProgress`。
* 清理线程开始处理该内存页。

**用户常见的编程错误及示例:**

虽然 JavaScript 开发者不直接操作 `MutablePageMetadata`，但与内存管理相关的常见错误会影响 V8 引擎对这些元数据的使用效率。

1. **内存泄漏：**  在 JavaScript 中，如果不再需要的对象仍然被引用，就会发生内存泄漏。这会导致 V8 引擎认为这些对象仍然是活动的，即使它们实际上已经没用了，从而增加了内存压力。

   ```javascript
   let leakyArray = [];
   function createLeak() {
     let largeObject = new Array(1000000);
     leakyArray.push(largeObject); // 将 largeObject 添加到全局数组，导致无法被回收
   }

   setInterval(createLeak, 100); // 每 100 毫秒创建一个泄漏
   ```

   在这种情况下，`leakyArray` 会一直持有对 `largeObject` 的引用，阻止垃圾回收器回收这些内存，即使这些对象可能不再被使用。这会影响 V8 引擎对相关内存页的 `MutablePageMetadata` 的管理，因为它认为这些内存仍然在使用中。

2. **意外地保持对不再需要对象的引用：**  闭包有时会意外地捕获并保持对大型对象的引用，即使这些对象在逻辑上已经不再需要。

   ```javascript
   function outerFunction() {
     let largeData = new Array(1000000);
     return function innerFunction() {
       console.log("Inner function executed");
       // 即使 innerFunction 自身并不需要 largeData，它仍然保持了对 largeData 的引用
     };
   }

   let inner = outerFunction();
   // ... 在不再需要 outerFunction 的 largeData 之后，仍然持有 inner 的引用 ...
   ```

   即使 `outerFunction` 的 `largeData` 在 `outerFunction` 执行完毕后可能就不再需要了，但 `innerFunction` 的闭包仍然会保持对它的引用，阻止垃圾回收器回收相关内存页。

3. **创建大量临时对象：**  频繁创建和销毁大量临时对象会给垃圾回收器带来压力，影响性能。虽然 `MutablePageMetadata` 负责管理这些对象所在的内存页，但过多的临时对象会增加 GC 的频率和开销。

   ```javascript
   for (let i = 0; i < 1000000; i++) {
     let tempObject = { value: i }; // 每次循环都创建一个新对象
     // ... 对 tempObject 进行一些操作 ...
   }
   ```

   在这种情况下，每次循环都会创建一个新的 `tempObject`，这些对象很快就会变得不可达并需要被回收。频繁的创建和回收操作会影响垃圾回收器的效率。

总而言之，`v8/src/heap/mutable-page-metadata.h` 定义的 `MutablePageMetadata` 类是 V8 堆内存管理的关键组成部分，它存储和管理着每个可变内存页的元数据，为垃圾回收和内存分配提供了必要的基础设施。理解其功能有助于我们更好地理解 V8 引擎的内部运作机制。

### 提示词
```
这是目录为v8/src/heap/mutable-page-metadata.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/mutable-page-metadata.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_HEAP_MUTABLE_PAGE_METADATA_H_
#define V8_HEAP_MUTABLE_PAGE_METADATA_H_

#include <atomic>

#include "src/base/macros.h"
#include "src/base/platform/mutex.h"
#include "src/common/globals.h"
#include "src/heap/base/active-system-pages.h"
#include "src/heap/list.h"
#include "src/heap/marking.h"
#include "src/heap/memory-chunk-layout.h"
#include "src/heap/memory-chunk-metadata.h"
#include "src/heap/slot-set.h"

namespace v8 {
namespace internal {

class FreeListCategory;
class SlotSet;
class Space;

using ActiveSystemPages = ::heap::base::ActiveSystemPages;

enum RememberedSetType {
  OLD_TO_NEW,
  OLD_TO_NEW_BACKGROUND,
  OLD_TO_OLD,
  OLD_TO_SHARED,
  TRUSTED_TO_CODE,
  TRUSTED_TO_TRUSTED,
  TRUSTED_TO_SHARED_TRUSTED,
  SURVIVOR_TO_EXTERNAL_POINTER,
  NUMBER_OF_REMEMBERED_SET_TYPES
};

// MutablePageMetadata represents a memory region owned by a specific space.
// It is divided into the header and the body. Chunk start is always
// 1MB aligned. Start of the body is aligned so it can accommodate
// any heap object.
class MutablePageMetadata : public MemoryChunkMetadata {
 public:
  // |kDone|: The page state when sweeping is complete or sweeping must not be
  //   performed on that page. Sweeper threads that are done with their work
  //   will set this value and not touch the page anymore.
  // |kPendingSweeping|: This page is ready for parallel sweeping.
  // |kPendingIteration|: This page is ready for parallel promoted page
  // iteration. |kInProgress|: This page is currently swept by a sweeper thread.
  enum class ConcurrentSweepingState : intptr_t {
    kDone,
    kPendingSweeping,
    kPendingIteration,
    kInProgress,
  };

  // Page size in bytes.  This must be a multiple of the OS page size.
  static const int kPageSize = kRegularPageSize;

  static PageAllocator::Permission GetCodeModificationPermission() {
    return v8_flags.jitless ? PageAllocator::kReadWrite
                            : PageAllocator::kReadWriteExecute;
  }

  static inline void MoveExternalBackingStoreBytes(
      ExternalBackingStoreType type, MutablePageMetadata* from,
      MutablePageMetadata* to, size_t amount);

  // Only works if the pointer is in the first kPageSize of the MemoryChunk.
  V8_INLINE static MutablePageMetadata* FromAddress(Address a);

  // Only works if the object is in the first kPageSize of the MemoryChunk.
  V8_INLINE static MutablePageMetadata* FromHeapObject(Tagged<HeapObject> o);

  static MutablePageMetadata* cast(MemoryChunkMetadata* metadata) {
    SLOW_DCHECK(!metadata || !metadata->Chunk()->InReadOnlySpace());
    return static_cast<MutablePageMetadata*>(metadata);
  }

  static const MutablePageMetadata* cast(const MemoryChunkMetadata* metadata) {
    SLOW_DCHECK(!metadata->Chunk()->InReadOnlySpace());
    return static_cast<const MutablePageMetadata*>(metadata);
  }

  MutablePageMetadata(Heap* heap, BaseSpace* space, size_t size,
                      Address area_start, Address area_end,
                      VirtualMemory reservation, PageSize page_size);

  MemoryChunk::MainThreadFlags InitialFlags(Executability executable) const;

  size_t BucketsInSlotSet() const { return SlotSet::BucketsForSize(size()); }

  V8_INLINE void SetOldGenerationPageFlags(MarkingMode marking_mode);
  void SetYoungGenerationPageFlags(MarkingMode marking_mode) {
    return Chunk()->SetYoungGenerationPageFlags(marking_mode);
  }

  base::Mutex* mutex() const { return mutex_; }
  base::SharedMutex* shared_mutex() const { return shared_mutex_; }

  void set_concurrent_sweeping_state(ConcurrentSweepingState state) {
    concurrent_sweeping_ = state;
  }

  ConcurrentSweepingState concurrent_sweeping_state() {
    return static_cast<ConcurrentSweepingState>(concurrent_sweeping_.load());
  }

  bool SweepingDone() const {
    return concurrent_sweeping_ == ConcurrentSweepingState::kDone;
  }

  template <RememberedSetType type, AccessMode access_mode = AccessMode::ATOMIC>
  SlotSet* slot_set() {
    if constexpr (access_mode == AccessMode::ATOMIC)
      return base::AsAtomicPointer::Acquire_Load(&slot_set_[type]);
    return slot_set_[type];
  }

  template <RememberedSetType type, AccessMode access_mode = AccessMode::ATOMIC>
  const SlotSet* slot_set() const {
    return const_cast<MutablePageMetadata*>(this)
        ->slot_set<type, access_mode>();
  }

  template <RememberedSetType type, AccessMode access_mode = AccessMode::ATOMIC>
  TypedSlotSet* typed_slot_set() {
    if constexpr (access_mode == AccessMode::ATOMIC)
      return base::AsAtomicPointer::Acquire_Load(&typed_slot_set_[type]);
    return typed_slot_set_[type];
  }

  template <RememberedSetType type, AccessMode access_mode = AccessMode::ATOMIC>
  const TypedSlotSet* typed_slot_set() const {
    return const_cast<MutablePageMetadata*>(this)
        ->typed_slot_set<type, access_mode>();
  }

  template <RememberedSetType type>
  bool ContainsSlots() const {
    return slot_set<type>() != nullptr || typed_slot_set<type>() != nullptr;
  }
  bool ContainsAnySlots() const;

  V8_EXPORT_PRIVATE SlotSet* AllocateSlotSet(RememberedSetType type);
  // Not safe to be called concurrently.
  void ReleaseSlotSet(RememberedSetType type);
  TypedSlotSet* AllocateTypedSlotSet(RememberedSetType type);
  // Not safe to be called concurrently.
  void ReleaseTypedSlotSet(RememberedSetType type);

  template <RememberedSetType type>
  SlotSet* ExtractSlotSet() {
    SlotSet* slot_set = slot_set_[type];
    // Conditionally reset to nullptr (instead of e.g. using std::exchange) to
    // avoid data races when transitioning from nullptr to nullptr.
    if (slot_set) {
      slot_set_[type] = nullptr;
    }
    return slot_set;
  }

  template <RememberedSetType type>
  TypedSlotSet* ExtractTypedSlotSet() {
    TypedSlotSet* typed_slot_set = typed_slot_set_[type];
    // Conditionally reset to nullptr (instead of e.g. using std::exchange) to
    // avoid data races when transitioning from nullptr to nullptr.
    if (typed_slot_set) {
      typed_slot_set_[type] = nullptr;
    }
    return typed_slot_set;
  }

  int ComputeFreeListsLength();

  // Approximate amount of physical memory committed for this chunk.
  V8_EXPORT_PRIVATE size_t CommittedPhysicalMemory() const;

  class MarkingProgressTracker& MarkingProgressTracker() {
    return marking_progress_tracker_;
  }
  const class MarkingProgressTracker& MarkingProgressTracker() const {
    return marking_progress_tracker_;
  }

  inline void IncrementExternalBackingStoreBytes(ExternalBackingStoreType type,
                                                 size_t amount);

  inline void DecrementExternalBackingStoreBytes(ExternalBackingStoreType type,
                                                 size_t amount);

  size_t ExternalBackingStoreBytes(ExternalBackingStoreType type) const {
    return external_backing_store_bytes_[static_cast<int>(type)];
  }

  Space* owner() const {
    return reinterpret_cast<Space*>(MemoryChunkMetadata::owner());
  }

  // Gets the chunk's allocation space, potentially dealing with a null owner_
  // (like read-only chunks have).
  inline AllocationSpace owner_identity() const;

  heap::ListNode<MutablePageMetadata>& list_node() { return list_node_; }
  const heap::ListNode<MutablePageMetadata>& list_node() const {
    return list_node_;
  }

  PossiblyEmptyBuckets* possibly_empty_buckets() {
    return &possibly_empty_buckets_;
  }

  // Release memory allocated by the chunk, except that which is needed by
  // read-only space chunks.
  void ReleaseAllocatedMemoryNeededForWritableChunk();

  void IncreaseAllocatedLabSize(size_t bytes) { allocated_lab_size_ += bytes; }
  void DecreaseAllocatedLabSize(size_t bytes) {
    DCHECK_GE(allocated_lab_size_, bytes);
    allocated_lab_size_ -= bytes;
  }
  size_t AllocatedLabSize() const { return allocated_lab_size_; }

  void IncrementAgeInNewSpace() { age_in_new_space_++; }
  void ResetAgeInNewSpace() { age_in_new_space_ = 0; }
  size_t AgeInNewSpace() const { return age_in_new_space_; }

  void ResetAllocationStatistics() {
    MemoryChunkMetadata::ResetAllocationStatistics();
    allocated_lab_size_ = 0;
  }

  void ResetAllocationStatisticsForPromotedPage() {
    DCHECK_NE(0, live_bytes());
    allocated_bytes_ = live_bytes();
    wasted_memory_ = area_size() - allocated_bytes_;
    allocated_lab_size_ = 0;
  }

  MarkingBitmap* marking_bitmap() {
    DCHECK(!Chunk()->InReadOnlySpace());
    return &marking_bitmap_;
  }

  const MarkingBitmap* marking_bitmap() const {
    DCHECK(!Chunk()->InReadOnlySpace());
    return &marking_bitmap_;
  }

  size_t live_bytes() const {
    return live_byte_count_.load(std::memory_order_relaxed);
  }

  void SetLiveBytes(size_t value) {
    DCHECK_IMPLIES(V8_COMPRESS_POINTERS_8GB_BOOL,
                   ::IsAligned(value, kObjectAlignment8GbHeap));
    live_byte_count_.store(value, std::memory_order_relaxed);
  }

  void IncrementLiveBytesAtomically(intptr_t diff) {
    DCHECK_IMPLIES(V8_COMPRESS_POINTERS_8GB_BOOL,
                   ::IsAligned(diff, kObjectAlignment8GbHeap));
    live_byte_count_.fetch_add(diff, std::memory_order_relaxed);
  }

  void ClearLiveness();

  bool IsLargePage() {
    // The active_system_pages_ will be nullptr for large pages, so we uses
    // that here instead of (for example) adding another enum member. See also
    // the constructor where this field is set.
    return active_system_pages_ == nullptr;
  }

 protected:
  // Release all memory allocated by the chunk. Should be called when memory
  // chunk is about to be freed.
  void ReleaseAllAllocatedMemory();

  template <RememberedSetType type, AccessMode access_mode = AccessMode::ATOMIC>
  void set_slot_set(SlotSet* slot_set) {
    if (access_mode == AccessMode::ATOMIC) {
      base::AsAtomicPointer::Release_Store(&slot_set_[type], slot_set);
      return;
    }
    slot_set_[type] = slot_set;
  }

  template <RememberedSetType type, AccessMode access_mode = AccessMode::ATOMIC>
  void set_typed_slot_set(TypedSlotSet* typed_slot_set) {
    if (access_mode == AccessMode::ATOMIC) {
      base::AsAtomicPointer::Release_Store(&typed_slot_set_[type],
                                           typed_slot_set);
      return;
    }
    typed_slot_set_[type] = typed_slot_set;
  }

  // A single slot set for small pages (of size kPageSize) or an array of slot
  // set for large pages. In the latter case the number of entries in the array
  // is ceil(size() / kPageSize).
  SlotSet* slot_set_[NUMBER_OF_REMEMBERED_SET_TYPES] = {nullptr};
  // A single slot set for small pages (of size kPageSize) or an array of slot
  // set for large pages. In the latter case the number of entries in the array
  // is ceil(size() / kPageSize).
  TypedSlotSet* typed_slot_set_[NUMBER_OF_REMEMBERED_SET_TYPES] = {nullptr};

  // Used by the marker to keep track of the scanning progress in large objects
  // that have a progress tracker and are scanned in increments and
  // concurrently.
  class MarkingProgressTracker marking_progress_tracker_;

  // Count of bytes marked black on page. With sticky mark-bits, the counter
  // represents the size of the old objects allocated on the page. This is
  // handy, since this counter is then used when starting sweeping to set the
  // approximate allocated size on the space (before it gets refined due to
  // right/left-trimming or slack tracking).
  std::atomic<intptr_t> live_byte_count_{0};

  base::Mutex* mutex_;
  base::SharedMutex* shared_mutex_;
  base::Mutex* page_protection_change_mutex_;

  std::atomic<ConcurrentSweepingState> concurrent_sweeping_{
      ConcurrentSweepingState::kDone};

  // Tracks off-heap memory used by this memory chunk.
  std::atomic<size_t> external_backing_store_bytes_[static_cast<int>(
      ExternalBackingStoreType::kNumValues)] = {0};

  heap::ListNode<MutablePageMetadata> list_node_;

  FreeListCategory** categories_ = nullptr;

  PossiblyEmptyBuckets possibly_empty_buckets_;

  ActiveSystemPages* active_system_pages_;

  // Counts overall allocated LAB size on the page since the last GC. Used
  // only for new space pages.
  size_t allocated_lab_size_ = 0;

  // Counts the number of young gen GCs that a page survived in new space. This
  // counter is reset to 0 whenever the page is empty.
  size_t age_in_new_space_ = 0;

  MarkingBitmap marking_bitmap_;

 private:
  static constexpr intptr_t MarkingBitmapOffset() {
    return offsetof(MutablePageMetadata, marking_bitmap_);
  }

  static constexpr intptr_t SlotSetOffset(
      RememberedSetType remembered_set_type) {
    return offsetof(MutablePageMetadata, slot_set_) +
           sizeof(void*) * remembered_set_type;
  }

  // For ReleaseAllAllocatedMemory().
  friend class MemoryAllocator;
  // For set_typed_slot_set().
  template <RememberedSetType>
  friend class RememberedSet;
  // For MarkingBitmapOffset().
  friend class CodeStubAssembler;
  friend class MacroAssembler;
  friend class MarkingBitmap;
  friend class TestWithBitmap;
  // For SlotSetOffset().
  friend class WriteBarrierCodeStubAssembler;
};

}  // namespace internal

namespace base {
// Define special hash function for chunk pointers, to be used with std data
// structures, e.g. std::unordered_set<MutablePageMetadata*,
// base::hash<MutablePageMetadata*>
template <>
struct hash<i::MutablePageMetadata*> : hash<i::MemoryChunkMetadata*> {};
template <>
struct hash<const i::MutablePageMetadata*>
    : hash<const i::MemoryChunkMetadata*> {};
}  // namespace base

}  // namespace v8

#endif  // V8_HEAP_MUTABLE_PAGE_METADATA_H_
```