Response:
The user provided a C++ source code file `sweeper.cc` from the V8 project. They are asking for a breakdown of its functionality.

Here's a thought process to analyze the code and answer the user's request:

1. **Identify the core purpose:** The filename `sweeper.cc` strongly suggests that this file is responsible for the "sweeping" phase of garbage collection within the cppgc (C++ garbage collector) component of V8. Sweeping is the process of reclaiming memory occupied by objects that are no longer reachable.

2. **Scan for key classes and functions:** Look for prominent classes and their methods. This provides a high-level overview of the components and their interactions. Notable classes include:
    * `Sweeper` (the overall class, not shown in the provided snippet, but implied by the filename).
    * `DeadlineChecker`: Manages time constraints for sweeping tasks.
    * `ObjectStartBitmapVerifier`:  Ensures the integrity of the object start bitmap, crucial for object layout.
    * `FreeHandlerBase`, `DiscardingFreeHandler`, `RegularFreeHandler`: Handle the process of adding freed memory back to free lists, with options for discarding memory.
    * `ThreadSafeStack`: A utility for managing pages to be swept, ensuring thread safety.
    * `SweepingState`:  Stores the state of sweeping for a given space.
    * `InlinedFinalizationBuilder`, `DeferredFinalizationBuilder`: Manage the finalization of objects and the creation of free list entries, with different strategies for immediate vs. deferred processing.
    * `SweepFinalizer`: Responsible for the final stages of sweeping, including running finalizers and merging free lists.
    * `MutatorThreadSweeper`:  Performs sweeping from the main JavaScript thread.
    * `ConcurrentSweepTask`: A task executed on background threads for concurrent sweeping.
    * `PrepareForSweepVisitor`:  Prepares the heap for the sweeping phase.

3. **Analyze the main workflows:**  Try to understand the sequence of operations. Based on the class names, a possible workflow emerges:
    * **Preparation:** `PrepareForSweepVisitor` sets up the data structures and moves pages.
    * **Concurrent Sweeping:** `ConcurrentSweepTask` runs in the background, processing pages and identifying dead objects.
    * **Mutator Thread Sweeping:** `MutatorThreadSweeper` runs on the main thread, assisting with sweeping and finalization.
    * **Finalization:** `SweepFinalizer` performs finalization tasks, running object finalizers and merging free lists.

4. **Examine individual class functionalities:**  Go deeper into the purpose of each class and its methods. For example:
    * `DeadlineChecker`:  The `Check()` method determines if a time limit has been exceeded.
    * `FreeHandler`: The `Free()` method adds a block to the free list. The discarding version may decommit memory.
    * `InlinedFinalizationBuilder` directly finalizes objects and adds them to the free list during the sweep.
    * `DeferredFinalizationBuilder` collects information about finalizable objects and free blocks for later processing.

5. **Identify interactions between classes:**  Note how different classes collaborate. For instance, `ConcurrentSweepTask` uses `DeferredFinalizationBuilder`, and `SweepFinalizer` processes the results.

6. **Address specific questions in the prompt:**
    * **Functionality Listing:** Based on the analysis, list the key functions.
    * **`.tq` extension:** The provided code is `.cc`, not `.tq`. So, it's C++, not Torque.
    * **JavaScript relationship:**  Sweeping is a core garbage collection function. While this C++ code directly implements the mechanism, its purpose is to manage memory for JavaScript objects. A simple JavaScript example would be creating objects that eventually become unreachable.
    * **Code logic inference:**  Focus on key algorithms like how `SweepNormalPage` identifies live and dead objects using the mark bits and object start bitmap.
    * **Common programming errors:**  Relate to memory management issues that garbage collection aims to prevent (e.g., memory leaks, use-after-free).

7. **Structure the answer:** Organize the findings into logical sections, addressing each point in the user's prompt.

8. **Refine and review:** Ensure the answer is clear, concise, and accurately reflects the code's functionality. Pay attention to the "Part 1 of 2" indication and focus on summarizing the functionality presented in the provided snippet. Avoid speculating too much about parts not included.

By following this process, we can systematically analyze the C++ code and generate a comprehensive answer to the user's request.
这是对 V8 源代码文件 `v8/src/heap/cppgc/sweeper.cc` 的功能进行分析的第 1 部分。根据您提供的代码片段，我们可以归纳出以下功能：

**主要功能：负责执行 cppgc 垃圾回收的 "清除" (Sweeping) 阶段。**

清除阶段的主要目标是回收在标记阶段被确定为不可达的对象的内存。这个阶段涉及遍历堆中的对象，识别未标记的对象，并将其占用的内存添加到空闲列表或进行其他处理。

**具体功能点 (基于提供的代码片段):**

1. **管理清除任务的优先级:** 定义了不同优先级的任务常量 (`kBackgroundBoostedPriority`, `kBackgroundRegularPriority`, `kForegroundRegularPriority`, `kForegroundLowPriority`)，用于在不同场景下执行清除任务。

2. **实现清除的截止时间检查:** `DeadlineChecker` 类用于检查清除操作是否超过了预定的时间限制，以避免长时间阻塞主线程。

3. **区分不同清除模式:**  `MutatorThreadSweepingMode` 枚举定义了在主 JavaScript 线程中执行清除的不同模式，例如只清理终结器 (finalizers) 或清理所有。

4. **验证对象起始位图 (Object Start Bitmap):** `ObjectStartBitmapVerifier` 类用于在调试模式下验证对象起始位图的正确性，确保位图与实际的对象布局一致。这有助于检测内存管理中的错误。

5. **处理空闲内存块:** 定义了抽象基类 `FreeHandlerBase` 和其具体实现 `DiscardingFreeHandler` 和 `RegularFreeHandler`。
    * `RegularFreeHandler` 将释放的内存块添加到空闲列表，以便后续分配使用。
    * `DiscardingFreeHandler` 除了添加到空闲列表外，还可以选择将部分未使用的内存页解除映射 (discard)，以减少内存占用。

6. **实现线程安全的栈:** `ThreadSafeStack` 类提供了一个线程安全的栈数据结构，用于管理待清除的页面。这使得并发清除操作成为可能。

7. **管理清除状态:** `SweepingState` 结构体用于存储特定空间 (Space) 的清除状态，包括待清除的页面、已清除但包含待终结对象的页面、缓存的空闲列表等信息。

8. **执行对象取消标记:** `StickyUnmark` 函数负责取消对象的标记位，以便在下一次垃圾回收周期中可以被重新标记。

9. **构建对象终结器和空闲列表项:** 定义了 `InlinedFinalizationBuilderBase` 基类和其派生类 `InlinedFinalizationBuilder` 和 `DeferredFinalizationBuilder`。
    * `InlinedFinalizationBuilder`: 在清除过程中立即执行对象的终结器，并将释放的内存块添加到空闲列表。
    * `DeferredFinalizationBuilder`:  延迟执行对象的终结器，先收集需要终结的对象和释放的内存块信息，供后续处理。

10. **清除普通页面 (Normal Page):** `SweepNormalPage` 函数模板负责清除普通页面，它遍历页面中的对象，识别未标记的对象并执行终结器 (如果需要)，将释放的内存添加到空闲列表，并更新页面的元数据。

11. **管理清除终结器:** `SweepFinalizer` 类负责在并发清除之后执行最终的清理操作，包括调用对象的终结器、回收空页、以及将空闲列表合并到空间的空闲列表中。

12. **主线程清除器:** `MutatorThreadSweeper` 类负责在主 JavaScript 线程中执行清除操作。它可以根据截止时间和大小限制来执行清除和终结操作。

13. **并发清除任务:** `ConcurrentSweepTask` 类表示一个在后台线程中执行的并发清除任务。它负责遍历页面并进行清除操作，并将需要终结的对象信息收集起来。

14. **准备清除阶段:** `PrepareForSweepVisitor` 类负责在清除阶段开始前进行准备工作，例如清空空闲列表、将页面移动到本地状态、以及标记未标记的对象以进行清理。

**与 JavaScript 功能的关系:**

虽然这段代码是 C++ 实现，但它直接关系到 JavaScript 的内存管理。垃圾回收是 JavaScript 引擎的核心功能之一，用于自动释放不再使用的对象所占用的内存，避免内存泄漏。`sweeper.cc` 中的代码负责执行垃圾回收过程中的清除阶段，这是回收这些不再使用的 JavaScript 对象所占用内存的关键步骤。

**如果 `v8/src/heap/cppgc/sweeper.cc` 以 `.tq` 结尾:**

如果文件以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码** 文件。Torque 是一种 V8 特有的类型化中间语言，用于生成高效的 C++ 代码。在这种情况下，上述的某些功能可能会以 Torque 的语法来实现，并最终被编译成 C++ 代码。

**代码逻辑推理 (假设输入与输出):**

假设有一个 `NormalPage` 包含以下对象 (假设已完成标记阶段)：

* 对象 A：已标记，大小 32 字节，起始地址 `0x1000`
* 对象 B：未标记，大小 16 字节，起始地址 `0x1020`
* 对象 C：已标记，大小 48 字节，起始地址 `0x1030`

使用 `SweepNormalPage` 函数进行清除，可能的输出（取决于具体的 `FinalizationBuilder`）：

* 对象 B 因为未标记，会被识别出来。
* 如果使用 `InlinedFinalizationBuilder`，对象 B 的终结器会被立即调用（如果存在），并且从 `0x1020` 开始的 16 字节内存会被添加到空闲列表。
* 对象 A 和对象 C 因为已标记，会取消其标记位。
* 最终，该页面的空闲列表可能会包含一个大小为 16 字节的空闲块 (从 `0x1020` 开始)。

**用户常见的编程错误:**

这段代码主要处理 V8 内部的内存管理，与用户直接编写 JavaScript 代码的错误关联性较弱。但是，用户在编写 C++ 代码并使用 cppgc 时，可能会遇到以下编程错误，而清除阶段会尝试处理这些错误：

* **内存泄漏:**  虽然 cppgc 可以自动回收大部分不再使用的内存，但在某些情况下（例如，持有指向不再需要对象的引用），仍然可能发生逻辑上的内存泄漏。清除阶段会回收那些真正不可达的对象，但无法解决逻辑上的引用问题。
* **资源泄漏:** 如果对象持有外部资源（例如文件句柄、网络连接），即使对象本身被回收，资源也可能没有被正确释放。终结器机制旨在解决这个问题，但用户需要正确实现终结器。
* **悬 dangling 指针 (在 C++ 中使用 cppgc):**  虽然 cppgc 负责管理对象的生命周期，但在某些复杂的场景下，如果用户直接操作原始指针，可能会出现悬 dangling 指针的问题。清除阶段不会直接修复这些问题，但它可以帮助回收相关的内存。

**总结 `v8/src/heap/cppgc/sweeper.cc` 的功能 (第 1 部分):**

总而言之，`v8/src/heap/cppgc/sweeper.cc` 的主要功能是 **实现 cppgc 垃圾回收的清除阶段**。它负责识别和回收不可达对象占用的内存，管理空闲列表，并处理对象的终结操作。该文件定义了多个关键的类和数据结构，用于管理清除任务的优先级、截止时间、不同模式，并支持并发清除。它与 JavaScript 的内存管理密切相关，负责回收不再使用的 JavaScript 对象所占用的内存。

Prompt: 
```
这是目录为v8/src/heap/cppgc/sweeper.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/cppgc/sweeper.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/cppgc/sweeper.h"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include "include/cppgc/platform.h"
#include "src/base/platform/mutex.h"
#include "src/base/platform/time.h"
#include "src/heap/cppgc/free-list.h"
#include "src/heap/cppgc/globals.h"
#include "src/heap/cppgc/heap-base.h"
#include "src/heap/cppgc/heap-config.h"
#include "src/heap/cppgc/heap-object-header.h"
#include "src/heap/cppgc/heap-page.h"
#include "src/heap/cppgc/heap-space.h"
#include "src/heap/cppgc/heap-visitor.h"
#include "src/heap/cppgc/memory.h"
#include "src/heap/cppgc/object-poisoner.h"
#include "src/heap/cppgc/object-start-bitmap.h"
#include "src/heap/cppgc/page-memory.h"
#include "src/heap/cppgc/raw-heap.h"
#include "src/heap/cppgc/stats-collector.h"
#include "src/heap/cppgc/task-handle.h"

namespace cppgc::internal {

namespace {

constexpr TaskPriority kBackgroundBoostedPriority = TaskPriority::kUserBlocking;
constexpr TaskPriority kBackgroundRegularPriority = TaskPriority::kUserVisible;
constexpr TaskPriority kForegroundRegularPriority = TaskPriority::kUserBlocking;
constexpr TaskPriority kForegroundLowPriority = TaskPriority::kUserVisible;

class DeadlineChecker final {
 public:
  explicit DeadlineChecker(v8::base::TimeTicks end) : end_(end) {}

  bool Check() {
    return V8_UNLIKELY(++count_ % kInterval == 0) &&
           (end_ < v8::base::TimeTicks::Now());
  }

 private:
  static constexpr size_t kInterval = 4;

  const v8::base::TimeTicks end_;
  size_t count_ = 0;
};

enum class MutatorThreadSweepingMode {
  kOnlyFinalizers,
  kAll,
};

constexpr const char* ToString(MutatorThreadSweepingMode sweeping_mode) {
  switch (sweeping_mode) {
    case MutatorThreadSweepingMode::kAll:
      return "all";
    case MutatorThreadSweepingMode::kOnlyFinalizers:
      return "only-finalizers";
  }
}

class ObjectStartBitmapVerifier final
    : private HeapVisitor<ObjectStartBitmapVerifier> {
  friend class HeapVisitor<ObjectStartBitmapVerifier>;

 public:
  void Verify(RawHeap& heap) {
#if DEBUG
    Traverse(heap);
#endif  // DEBUG
  }
  void Verify(NormalPage& page) {
#if DEBUG
    Traverse(page);
#endif  // DEBUG
  }

 private:
  bool VisitNormalPage(NormalPage& page) {
    // Remember bitmap and reset previous pointer.
    bitmap_ = &page.object_start_bitmap();
    prev_ = nullptr;
    return false;
  }

  bool VisitHeapObjectHeader(HeapObjectHeader& header) {
    if (header.IsLargeObject()) return true;

    auto* raw_header = reinterpret_cast<ConstAddress>(&header);
    CHECK(bitmap_->CheckBit<AccessMode::kAtomic>(raw_header));
    if (prev_) {
      // No other bits in the range [prev_, raw_header) should be set.
      CHECK_EQ(prev_, bitmap_->FindHeader<AccessMode::kAtomic>(raw_header - 1));
    }
    prev_ = &header;
    return true;
  }

  PlatformAwareObjectStartBitmap* bitmap_ = nullptr;
  HeapObjectHeader* prev_ = nullptr;
};

class FreeHandlerBase {
 public:
  virtual ~FreeHandlerBase() = default;
  virtual void FreeFreeList(
      std::vector<FreeList::Block>& unfinalized_free_list) = 0;
};

class DiscardingFreeHandler : public FreeHandlerBase {
 public:
  DiscardingFreeHandler(PageAllocator& page_allocator, FreeList& free_list,
                        BasePage& page)
      : page_allocator_(page_allocator), free_list_(free_list), page_(page) {}

  void Free(FreeList::Block block) {
    const auto unused_range = free_list_.AddReturningUnusedBounds(block);
    const uintptr_t aligned_begin_unused =
        RoundUp(reinterpret_cast<uintptr_t>(unused_range.first),
                page_allocator_.CommitPageSize());
    const uintptr_t aligned_end_unused =
        RoundDown(reinterpret_cast<uintptr_t>(unused_range.second),
                  page_allocator_.CommitPageSize());
    if (aligned_begin_unused < aligned_end_unused) {
      const size_t discarded_size = aligned_end_unused - aligned_begin_unused;
      page_allocator_.DiscardSystemPages(
          reinterpret_cast<void*>(aligned_begin_unused),
          aligned_end_unused - aligned_begin_unused);
      page_.IncrementDiscardedMemory(discarded_size);
      page_.space()
          .raw_heap()
          ->heap()
          ->stats_collector()
          ->IncrementDiscardedMemory(discarded_size);
    }
  }

  void FreeFreeList(std::vector<FreeList::Block>& unfinalized_free_list) final {
    for (auto entry : unfinalized_free_list) {
      Free(std::move(entry));
    }
  }

 private:
  PageAllocator& page_allocator_;
  FreeList& free_list_;
  BasePage& page_;
};

class RegularFreeHandler : public FreeHandlerBase {
 public:
  RegularFreeHandler(PageAllocator& page_allocator, FreeList& free_list,
                     BasePage& page)
      : free_list_(free_list) {}

  void Free(FreeList::Block block) { free_list_.Add(std::move(block)); }

  void FreeFreeList(std::vector<FreeList::Block>& unfinalized_free_list) final {
    for (auto entry : unfinalized_free_list) {
      Free(std::move(entry));
    }
  }

 private:
  FreeList& free_list_;
};

template <typename T>
class ThreadSafeStack {
 public:
  ThreadSafeStack() = default;

  void Push(T t) {
    v8::base::LockGuard<v8::base::Mutex> lock(&mutex_);
    vector_.push_back(std::move(t));
    is_empty_.store(false, std::memory_order_relaxed);
  }

  std::optional<T> Pop() {
    v8::base::LockGuard<v8::base::Mutex> lock(&mutex_);
    if (vector_.empty()) {
      is_empty_.store(true, std::memory_order_relaxed);
      return std::nullopt;
    }
    T top = std::move(vector_.back());
    vector_.pop_back();
    // std::move is redundant but is needed to avoid the bug in gcc-7.
    return std::move(top);
  }

  template <typename It>
  void Insert(It begin, It end) {
    v8::base::LockGuard<v8::base::Mutex> lock(&mutex_);
    vector_.insert(vector_.end(), begin, end);
    is_empty_.store(false, std::memory_order_relaxed);
  }

  bool IsEmpty() const { return is_empty_.load(std::memory_order_relaxed); }

 private:
  mutable v8::base::Mutex mutex_;
  std::vector<T> vector_;
  std::atomic<bool> is_empty_{true};
};

struct SweepingState {
  struct SweptPageState {
    BasePage* page = nullptr;
#if defined(CPPGC_CAGED_HEAP)
    // The list of unfinalized objects may be extremely big. To save on space,
    // if cage is enabled, the list of unfinalized objects is stored inlined in
    // HeapObjectHeader.
    HeapObjectHeader* unfinalized_objects_head = nullptr;
#else   // !defined(CPPGC_CAGED_HEAP)
    std::vector<HeapObjectHeader*> unfinalized_objects;
#endif  // !defined(CPPGC_CAGED_HEAP)
    FreeList cached_free_list;
    std::vector<FreeList::Block> unfinalized_free_list;
    bool is_empty = false;
    size_t largest_new_free_list_entry = 0;
  };

  ThreadSafeStack<BasePage*> unswept_pages;
  ThreadSafeStack<SweptPageState> swept_unfinalized_pages;
};

using SpaceStates = std::vector<SweepingState>;

void StickyUnmark(HeapObjectHeader* header, StickyBits sticky_bits) {
#if defined(CPPGC_YOUNG_GENERATION)
  // Young generation in Oilpan uses sticky mark bits.
  if (sticky_bits == StickyBits::kDisabled)
    header->Unmark<AccessMode::kAtomic>();
#else   // !defined(CPPGC_YOUNG_GENERATION)
  header->Unmark<AccessMode::kAtomic>();
#endif  // !defined(CPPGC_YOUNG_GENERATION)
}

class InlinedFinalizationBuilderBase {
 public:
  struct ResultType {
    bool is_empty = false;
    size_t largest_new_free_list_entry = 0;
  };

 protected:
  ResultType result_;
};

// Builder that finalizes objects and adds freelist entries right away.
template <typename FreeHandler>
class InlinedFinalizationBuilder final : public InlinedFinalizationBuilderBase,
                                         public FreeHandler {
 public:
  InlinedFinalizationBuilder(BasePage& page, PageAllocator& page_allocator)
      : FreeHandler(page_allocator,
                    NormalPageSpace::From(page.space()).free_list(), page) {}

  void AddFinalizer(HeapObjectHeader* header, size_t size) {
    header->Finalize();
    SetMemoryInaccessible(header, size);
  }

  void AddFreeListEntry(Address start, size_t size) {
    FreeHandler::Free({start, size});
    result_.largest_new_free_list_entry =
        std::max(result_.largest_new_free_list_entry, size);
  }

  ResultType&& GetResult(bool is_empty) {
    result_.is_empty = is_empty;
    return std::move(result_);
  }
};

// Builder that produces results for deferred processing.
template <typename FreeHandler>
class DeferredFinalizationBuilder final : public FreeHandler {
 public:
  using ResultType = SweepingState::SweptPageState;

  DeferredFinalizationBuilder(BasePage& page, PageAllocator& page_allocator)
      : FreeHandler(page_allocator, result_.cached_free_list, page) {
    result_.page = &page;
  }

  void AddFinalizer(HeapObjectHeader* header, size_t size) {
    if (header->IsFinalizable()) {
#if defined(CPPGC_CAGED_HEAP)
      if (!current_unfinalized_) {
        DCHECK_NULL(result_.unfinalized_objects_head);
        current_unfinalized_ = header;
        result_.unfinalized_objects_head = header;
      } else {
        current_unfinalized_->SetNextUnfinalized(header);
        current_unfinalized_ = header;
      }
#else   // !defined(CPPGC_CAGED_HEAP)
      result_.unfinalized_objects.push_back({header});
#endif  // !defined(CPPGC_CAGED_HEAP)
      found_finalizer_ = true;
    } else {
      SetMemoryInaccessible(header, size);
    }
  }

  void AddFreeListEntry(Address start, size_t size) {
    if (found_finalizer_) {
      result_.unfinalized_free_list.push_back({start, size});
    } else {
      FreeHandler::Free({start, size});
    }
    result_.largest_new_free_list_entry =
        std::max(result_.largest_new_free_list_entry, size);
    found_finalizer_ = false;
  }

  ResultType&& GetResult(bool is_empty) {
    result_.is_empty = is_empty;
    return std::move(result_);
  }

 private:
  ResultType result_;
  HeapObjectHeader* current_unfinalized_ = nullptr;
  bool found_finalizer_ = false;
};

template <typename FinalizationBuilder>
typename FinalizationBuilder::ResultType SweepNormalPage(
    NormalPage* page, PageAllocator& page_allocator, StickyBits sticky_bits) {
  constexpr auto kAtomicAccess = AccessMode::kAtomic;
  FinalizationBuilder builder(*page, page_allocator);

  PlatformAwareObjectStartBitmap& bitmap = page->object_start_bitmap();

  size_t live_bytes = 0;

  Address start_of_gap = page->PayloadStart();

  const auto clear_bit_if_coalesced_entry = [&bitmap,
                                             &start_of_gap](Address address) {
    if (address != start_of_gap) {
      // Clear only if not the first freed entry.
      bitmap.ClearBit<AccessMode::kAtomic>(address);
    } else {
      // Otherwise check that the bit is set.
      DCHECK(bitmap.CheckBit<AccessMode::kAtomic>(address));
    }
  };

  for (Address begin = page->PayloadStart(), end = page->PayloadEnd();
       begin != end;) {
    DCHECK(bitmap.CheckBit<AccessMode::kAtomic>(begin));
    HeapObjectHeader* header = reinterpret_cast<HeapObjectHeader*>(begin);
    const size_t size = header->AllocatedSize();
    // Check if this is a free list entry.
    if (header->IsFree<kAtomicAccess>()) {
      SetMemoryInaccessible(header, std::min(kFreeListEntrySize, size));
      // This prevents memory from being discarded in configurations where
      // `CheckMemoryIsInaccessibleIsNoop()` is false.
      CheckMemoryIsInaccessible(header, size);
      clear_bit_if_coalesced_entry(begin);
      begin += size;
      continue;
    }
    // Check if object is not marked (not reachable).
    if (!header->IsMarked<kAtomicAccess>()) {
      builder.AddFinalizer(header, size);
      clear_bit_if_coalesced_entry(begin);
      begin += size;
      continue;
    }
    // The object is alive.
    const Address header_address = reinterpret_cast<Address>(header);
    if (start_of_gap != header_address) {
      const size_t new_free_list_entry_size =
          static_cast<size_t>(header_address - start_of_gap);
      builder.AddFreeListEntry(start_of_gap, new_free_list_entry_size);
      DCHECK(bitmap.CheckBit<AccessMode::kAtomic>(start_of_gap));
    }
    StickyUnmark(header, sticky_bits);
    begin += size;
    start_of_gap = begin;
    live_bytes += size;
  }

  const bool is_empty = live_bytes == 0;
  CHECK_EQ(is_empty, page->marked_bytes() == 0);
  CHECK_IMPLIES(is_empty, start_of_gap == page->PayloadStart());

  // Empty pages are not added to the free list directly here. The free list is
  // either added later on or the page is destroyed.
  if (!is_empty && start_of_gap != page->PayloadEnd()) {
    builder.AddFreeListEntry(
        start_of_gap, static_cast<size_t>(page->PayloadEnd() - start_of_gap));
    DCHECK(bitmap.CheckBit<AccessMode::kAtomic>(start_of_gap));
  }
  page->SetAllocatedBytesAtLastGC(live_bytes);
  page->ResetMarkedBytes(sticky_bits == StickyBits::kDisabled ? 0 : live_bytes);
  return builder.GetResult(is_empty);
}

constexpr BaseSpace* kSweepWithoutSpaceAssignment = nullptr;

enum class EmptyPageHandling {
  kDestroy,
  kReturn,
};

// SweepFinalizer is responsible for heap/space/page finalization. Finalization
// is defined as a step following concurrent sweeping which:
// - calls finalizers;
// - returns (unmaps) empty pages;
// - merges freelists to the space's freelist.
class SweepFinalizer final {
  using FreeMemoryHandling = SweepingConfig::FreeMemoryHandling;

 public:
  SweepFinalizer(cppgc::Platform* platform, StatsCollector* stats_collector,
                 BaseSpace* space, size_t* unused_destroyed_normal_pages,
                 FreeMemoryHandling free_memory_handling,
                 EmptyPageHandling empty_page_handling_type)
      : platform_(platform),
        stats_collector_(stats_collector),
        space_(space),
        unused_destroyed_normal_pages_(unused_destroyed_normal_pages),
        free_memory_handling_(free_memory_handling),
        empty_page_handling_(empty_page_handling_type) {}

  // Finalizes all space states, irrespective of deadlines and sizes.
  void Finalize(SpaceStates& states) {
    for (SweepingState& state : states) {
      Finalize(state);
    }
  }

  void Finalize(SweepingState& state) {
    while (auto page_state = state.swept_unfinalized_pages.Pop()) {
      FinalizePage(&*page_state);
    }
  }

  // Finalizes a given SweepingState with a deadline and size. Only returns
  // true if a single memory block of at least `size` bytes was returned to the
  // free list and false otherwise.
  bool FinalizeWithDeadlineAndSize(StatsCollector::ScopeId scope_id,
                                   SweepingState& state,
                                   v8::base::TimeTicks deadline, size_t size) {
    if (state.swept_unfinalized_pages.IsEmpty()) {
      return false;
    }
    StatsCollector::DisabledScope finalize_scope(stats_collector_, scope_id);
    DeadlineChecker deadline_check(deadline);
    while (auto page_state = state.swept_unfinalized_pages.Pop()) {
      FinalizePage(&*page_state);
      if (size <= largest_consecutive_block_) {
        return true;
      }
      if (deadline_check.Check()) {
        break;
      }
    }
    return false;
  }

  // Finalizes a given SweepingState with a deadline. Returns false if the
  // deadline exceeded and true if all pages are finalized.
  bool FinalizeWithDeadline(StatsCollector::ScopeId scope_id,
                            SweepingState& state,
                            v8::base::TimeTicks deadline) {
    if (state.swept_unfinalized_pages.IsEmpty()) {
      return true;
    }
    StatsCollector::DisabledScope finalize_scope(stats_collector_, scope_id);
    DeadlineChecker deadline_check(deadline);
    while (auto page_state = state.swept_unfinalized_pages.Pop()) {
      FinalizePage(&*page_state);
      if (deadline_check.Check()) {
        return false;
      }
    }
    return true;
  }

 private:
  void FinalizePage(SweepingState::SweptPageState* page_state) {
    DCHECK(page_state);
    DCHECK(page_state->page);
    BasePage* page = page_state->page;

    // Call finalizers.
    const auto finalize_header = [](HeapObjectHeader* header) {
      const size_t size = header->AllocatedSize();
      header->Finalize();
      SetMemoryInaccessible(header, size);
    };
#if defined(CPPGC_CAGED_HEAP)
#if defined(CPPGC_POINTER_COMPRESSION)
    const uint64_t cage_base = CageBaseGlobal::Get();
#else
    const uint64_t cage_base = CagedHeapBase::GetBase();
#endif
    HeapObjectHeader* next_unfinalized = nullptr;

    for (auto* unfinalized_header = page_state->unfinalized_objects_head;
         unfinalized_header; unfinalized_header = next_unfinalized) {
      next_unfinalized = unfinalized_header->GetNextUnfinalized(cage_base);
      finalize_header(unfinalized_header);
    }
#else   // !defined(CPPGC_CAGED_HEAP)
    for (HeapObjectHeader* unfinalized_header :
         page_state->unfinalized_objects) {
      finalize_header(unfinalized_header);
    }
#endif  // !defined(CPPGC_CAGED_HEAP)

    // Unmap page if empty.
    if (page_state->is_empty) {
      DCHECK_IMPLIES(page->is_large(),
                     empty_page_handling_ == EmptyPageHandling::kDestroy);
      if (empty_page_handling_ == EmptyPageHandling::kDestroy) {
        if (!page->is_large()) {
          (*unused_destroyed_normal_pages_)++;
        } else {
          // Normal pages are added to the page pool when destroyed and thus
          // cannot be used for a large page allocation.
          largest_consecutive_block_ = std::max(
              LargePage::From(page)->PayloadSize(), largest_consecutive_block_);
        }
        BasePage::Destroy(page, free_memory_handling_);
        return;
      }

      // Otherwise, we currently sweep on allocation. Reinitialize the empty
      // page and return it right away.
      auto* normal_page = NormalPage::From(page);

      // If a space has been assigned to the finalizer, then repurpose empty
      // pages for that space. Otherwise just retain the current space for an
      // empty page.
      if (space_) {
        normal_page->ChangeOwner(*space_);
      }

      page_state->cached_free_list.Clear();
      page_state->cached_free_list.Add(
          {normal_page->PayloadStart(), normal_page->PayloadSize()});

      page_state->unfinalized_free_list.clear();
      page_state->largest_new_free_list_entry = normal_page->PayloadSize();
    }
    // We either swept a non-empty page for which the space should already match
    // or we swept an empty page for which the owner was changed.
    DCHECK_IMPLIES(space_, space_ == &page->space());
    DCHECK(!page->is_large());

    // Merge freelists without finalizers.
    FreeList& space_freelist = NormalPageSpace::From(page->space()).free_list();
    space_freelist.Append(std::move(page_state->cached_free_list));

    // Merge freelist with finalizers.
    if (!page_state->unfinalized_free_list.empty()) {
      std::unique_ptr<FreeHandlerBase> handler =
          (free_memory_handling_ == FreeMemoryHandling::kDiscardWherePossible)
              ? std::unique_ptr<FreeHandlerBase>(new DiscardingFreeHandler(
                    *platform_->GetPageAllocator(), space_freelist, *page))
              : std::unique_ptr<FreeHandlerBase>(new RegularFreeHandler(
                    *platform_->GetPageAllocator(), space_freelist, *page));
      handler->FreeFreeList(page_state->unfinalized_free_list);
    }

    largest_consecutive_block_ = std::max(
        page_state->largest_new_free_list_entry, largest_consecutive_block_);

    // After the page was fully finalized and freelists have been merged, verify
    // that the bitmap is consistent.
    ObjectStartBitmapVerifier().Verify(static_cast<NormalPage&>(*page));

    // Add the page to the space.
    page->space().AddPage(page);
  }

  cppgc::Platform* platform_;
  StatsCollector* stats_collector_;
  BaseSpace* space_;
  size_t* unused_destroyed_normal_pages_;
  // Largest consecutive block of memory. This is the largest free list entry
  // for normal pages and the largest page size for large objects.
  size_t largest_consecutive_block_ = 0;
  const FreeMemoryHandling free_memory_handling_;
  const EmptyPageHandling empty_page_handling_;
};

class MutatorThreadSweeper final : private HeapVisitor<MutatorThreadSweeper> {
  friend class HeapVisitor<MutatorThreadSweeper>;

  using FreeMemoryHandling = SweepingConfig::FreeMemoryHandling;

 public:
  MutatorThreadSweeper(HeapBase* heap, cppgc::Platform* platform,
                       StatsCollector* stats_collector, BaseSpace* space,
                       size_t* unused_destroyed_normal_pages,
                       FreeMemoryHandling free_memory_handling,
                       EmptyPageHandling empty_page_handling)
      : platform_(platform),
        stats_collector_(stats_collector),
        space_(space),
        unused_destroyed_normal_pages_(unused_destroyed_normal_pages),
        free_memory_handling_(free_memory_handling),
        empty_page_handling_(empty_page_handling),
        sticky_bits_(heap->sticky_bits()) {}

  static void SweepLiveLargePage(LargePage& page, StickyBits sticky_bits) {
    HeapObjectHeader* header = page.ObjectHeader();
    CHECK(header->IsMarked());
    StickyUnmark(header, sticky_bits);
    if (sticky_bits == StickyBits::kDisabled) {
      page.ResetMarkedBytes();
    }
    page.space().AddPage(&page);
  }

  void Sweep(SpaceStates& states) {
    for (SweepingState& state : states) {
      Sweep(state);
    }
  }

  void Sweep(SweepingState& state) {
    while (auto page = state.unswept_pages.Pop()) {
      SweepPage(**page);
    }
  }

  void SweepPage(BasePage& page) { Traverse(page); }

  // Returns true if out of work. This implies that sweeping is done only if
  // `sweeping_mode` is kAll.
  bool FinalizeAndSweepWithDeadline(StatsCollector::ScopeId scope_id,
                                    SweepingState& state,
                                    v8::base::TimeTicks deadline,
                                    MutatorThreadSweepingMode sweeping_mode) {
    // First, prioritize finalization of pages that were swept concurrently.
    SweepFinalizer finalizer(
        platform_, stats_collector_, space_, unused_destroyed_normal_pages_,
        free_memory_handling_, EmptyPageHandling::kDestroy);
    if (!finalizer.FinalizeWithDeadline(scope_id, state, deadline)) {
      return false;
    }

    if (sweeping_mode != MutatorThreadSweepingMode::kOnlyFinalizers) {
      // Help out the concurrent sweeper.
      if (!SweepSpaceWithDeadline(&state, deadline)) {
        return false;
      }
    }
    return true;
  }

  bool SweepWithDeadlineAndSize(StatsCollector::ScopeId scope_id,
                                SweepingState& state,
                                v8::base::TimeTicks deadline, size_t size) {
    if (state.unswept_pages.IsEmpty()) {
      return false;
    }
    StatsCollector::DisabledScope sweep_scope(stats_collector_, scope_id);
    DeadlineChecker deadline_check(deadline);
    while (auto page = state.unswept_pages.Pop()) {
      SweepPage(**page);
      if (size <= largest_consecutive_block_) {
        return true;
      }
      if (deadline_check.Check()) {
        break;
      }
    }
    return false;
  }

 private:
  bool SweepSpaceWithDeadline(SweepingState* state,
                              v8::base::TimeTicks deadline) {
    DeadlineChecker deadline_check(deadline);
    while (auto page = state->unswept_pages.Pop()) {
      Traverse(**page);
      if (deadline_check.Check()) {
        return false;
      }
    }

    return true;
  }

  bool VisitNormalPage(NormalPage& page) {
    if (free_memory_handling_ == FreeMemoryHandling::kDiscardWherePossible) {
      page.ResetDiscardedMemory();
    }
    const auto result =
        (free_memory_handling_ == FreeMemoryHandling::kDiscardWherePossible)
            ? SweepNormalPage<
                  InlinedFinalizationBuilder<DiscardingFreeHandler>>(
                  &page, *platform_->GetPageAllocator(), sticky_bits_)
            : SweepNormalPage<InlinedFinalizationBuilder<RegularFreeHandler>>(
                  &page, *platform_->GetPageAllocator(), sticky_bits_);
    if (result.is_empty &&
        empty_page_handling_ == EmptyPageHandling::kDestroy) {
      NormalPage::Destroy(&page, free_memory_handling_);
      (*unused_destroyed_normal_pages_)++;
    } else {
      if (space_) {
        DCHECK_IMPLIES(!result.is_empty, space_ == &page.space());
        page.ChangeOwner(*space_);
      }
      auto& target_space = NormalPageSpace::From(page.space());
      target_space.AddPage(&page);
      if (result.is_empty) {
        target_space.free_list().Add({page.PayloadStart(), page.PayloadSize()});
      }
      // The page was eagerly finalized and all the freelist have been merged.
      // Verify that the bitmap is consistent with headers.
      ObjectStartBitmapVerifier().Verify(page);
      largest_consecutive_block_ =
          std::max(result.is_empty ? page.PayloadSize()
                                   : result.largest_new_free_list_entry,
                   largest_consecutive_block_);
    }
    return true;
  }

  bool VisitLargePage(LargePage& page) {
    HeapObjectHeader* header = page.ObjectHeader();
    CHECK(!header->IsMarked());
    DCHECK_EQ(page.marked_bytes(), 0u);
    header->Finalize();
    largest_consecutive_block_ =
        std::max(page.PayloadSize(), largest_consecutive_block_);
    LargePage::Destroy(&page);
    return true;
  }

  cppgc::Platform* platform_;
  StatsCollector* stats_collector_;
  // Largest consecutive block of memory. This is the largest free list entry
  // for normal pages and the largest page size for large objects.
  size_t largest_consecutive_block_ = 0;
  BaseSpace* space_;
  size_t* unused_destroyed_normal_pages_;
  const FreeMemoryHandling free_memory_handling_;
  const EmptyPageHandling empty_page_handling_;
  const StickyBits sticky_bits_;
};

class ConcurrentSweepTask final : public cppgc::JobTask,
                                  private HeapVisitor<ConcurrentSweepTask> {
  friend class HeapVisitor<ConcurrentSweepTask>;

  using FreeMemoryHandling = SweepingConfig::FreeMemoryHandling;

 public:
  ConcurrentSweepTask(Platform* platform, HeapBase& heap,
                      SpaceStates* space_states,
                      SweepingState* empty_normal_pages,
                      SweepingState* empty_large_pages,
                      FreeMemoryHandling free_memory_handling)
      : heap_(heap),
        page_allocator_(*platform->GetPageAllocator()),
        space_states_(space_states),
        empty_normal_pages_(empty_normal_pages),
        empty_large_pages_(empty_large_pages),
        free_memory_handling_(free_memory_handling),
        sticky_bits_(heap.sticky_bits()) {}

  void Run(cppgc::JobDelegate* delegate) final {
    StatsCollector::EnabledConcurrentScope stats_scope(
        heap_.stats_collector(), StatsCollector::kConcurrentSweep);

    // Sweep empty normal pages first. These pages can be reused across all
    // regular spaces.
    if (!SweepStateOrYield(delegate, *empty_normal_pages_)) return;
    for (SweepingState& state : *space_states_) {
      if (!SweepStateOrYield(delegate, state)) return;
    }
    // Sweep empty large pages last. They generally cannot be reused.
    // TODO(mlippautz): We could split them into pages that can be split up for
    // normal pages.
    if (!SweepStateOrYield(delegate, *empty_large_pages_)) return;

    is_completed_.store(true, std::memory_order_relaxed);
  }

  size_t GetMaxConcurrency(size_t /* active_worker_count */) const final {
    return is_completed_.load(std::memory_order_relaxed) ? 0 : 1;
  }

 private:
  // Returns true if sweeping completed, or false if it yielded.
  bool SweepStateOrYield(cppgc::JobDelegate* delegate, SweepingState& state) {
    current_sweeping_state_ = &state;
    while (auto page = state.unswept_pages.Pop()) {
      Traverse(**page);
      if (delegate->ShouldYield()) {
        return false;
      }
    }
    current_sweeping_state_ = nullptr;
    return true;
  }

  bool VisitNormalPage(NormalPage& page) {
    if (free_memory_handling_ == FreeMemoryHandling::kDiscardWherePossible) {
      page.ResetDiscardedMemory();
    }
    SweepingState::SweptPageState sweep_result =
        (free_memory_handling_ == FreeMemoryHandling::kDiscardWherePossible)
            ? SweepNormalPage<
                  DeferredFinalizationBuilder<DiscardingFreeHandler>>(
                  &page, page_allocator_, sticky_bits_)
            : SweepNormalPage<DeferredFinalizationBuilder<RegularFreeHandler>>(
                  &page, page_allocator_, sticky_bits_);
    current_sweeping_state_->swept_unfinalized_pages.Push(
        std::move(sweep_result));
    return true;
  }

  bool VisitLargePage(LargePage& page) {
    HeapObjectHeader* header = page.ObjectHeader();
    CHECK(!header->IsMarked());
    DCHECK_EQ(page.marked_bytes(), 0u);
#if defined(CPPGC_CAGED_HEAP)
    HeapObjectHeader* const unfinalized_objects =
        header->IsFinalizable() ? page.ObjectHeader() : nullptr;
#else   // !defined(CPPGC_CAGED_HEAP)
    std::vector<HeapObjectHeader*> unfinalized_objects;
    if (header->IsFinalizable()) {
      unfinalized_objects.push_back(page.ObjectHeader());
    }
#endif  // !defined(CPPGC_CAGED_HEAP)
    // Avoid directly destroying large pages here as counter updates and
    // backend access in BasePage::Destroy() are not concurrency safe.
    current_sweeping_state_->swept_unfinalized_pages.Push(
        {&page, std::move(unfinalized_objects), {}, {}, true});
    return true;
  }

  HeapBase& heap_;
  PageAllocator& page_allocator_;
  SpaceStates* const space_states_;
  SweepingState* const empty_normal_pages_;
  SweepingState* const empty_large_pages_;
  SweepingState* current_sweeping_state_ = nullptr;
  std::atomic_bool is_completed_{false};
  const FreeMemoryHandling free_memory_handling_;
  const StickyBits sticky_bits_;
};

// This visitor starts sweeping.
//
// Normal spaces:
// - Clears free lists.
// - Moves all pages to local state (SpaceStates).
// - ASAN: Poisons all unmarked object payloads.
//
// Large spaces:
// - Directly sweeps live objects and returns pages to the space.
// - Moves dead objects to local state (SpaceStates).
// - ASAN: Poisons all unmarked object payloads.
class PrepareForSweepVisitor final
    : protected HeapVisitor<PrepareForSweepVisitor> {
  friend class HeapVisitor<PrepareForSweepVisitor>;
  using CompactableSpaceHandling = SweepingConfig::CompactableSpaceHandling;

 public:
  PrepareForSweepVisitor(HeapBase* heap, SpaceStates* space_states,
                         SweepingState* empty_normal_pages,
                         SweepingState* empty_large_pages,
                         CompactableSpaceHandling compactable_space_handling)
      : heap_(heap),
        space_states_(space_states),
        empty_normal_pages_(empty_normal_pages),
        empty_large_pages_(empty_large_pages),
        compactable_space_handling_(compactable_space_handling) {}

  void Run(RawHeap& raw_heap) {
    *space_states_ = SpaceStates(raw_heap.size());
    Traverse(raw_heap);
  }

 protected:
  bool VisitNormalPageSpace(NormalPageSpace& space) {
    if ((compactable_space_handling_ == CompactableSpaceHandling::kIgnore) &&
        space.is_compactable()) {
      return true;
    }

    CHECK(!space.linear_allocation_buffer().size());
    space.free_list().Clear();
#ifdef V8_USE_ADDRESS_SANITIZER
    UnmarkedObjectsPoisoner().Traverse(space);
#endif  // V8_USE_ADDRESS_SANITIZER

    BaseSpace::Pages space_pages = space.RemoveAllPages();
    std::sort(space_pages.begin(), space_pages.end(),
              [](const BasePage* a, const BasePage* b) {
                return a->marked_bytes() < b->marked_bytes();
              });
    auto first_non_empty_page = std::find_if(
        space_pages.begin(), space_pages.end(),
        [](const BasePage* page) { return page->marked_bytes() != 0; });
    empty_normal_pages_->unswept_pages.Insert(space_pages.begin(),
                                              first_non_empty_page);
    (*space_states_)[space.index()].unswept_pages.Insert(first_non_empty_page,
                                                         space_pages.end());

    return true;
  }

  bool VisitLargePageSpace(LargePageSpace& space) {
#ifdef V8_USE_ADDRESS_SANITIZER
    UnmarkedObjectsPoisoner().Traverse(space);
#endif  // V8_USE_ADDRESS_SANITIZER

    BaseSpace::Pages space_pages = space.RemoveAllPages();
    for (BasePage* page : space_pages) {
#ifdef DEBUG
      const auto* header = LargePage:
"""


```