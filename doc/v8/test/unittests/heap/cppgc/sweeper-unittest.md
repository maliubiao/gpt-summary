Response:
My thought process for analyzing the C++ code and generating the explanation went through these steps:

1. **Understand the Core Purpose:** The filename `sweeper-unittest.cc` immediately suggests that the code is testing the functionality of a "sweeper" component within the `cppgc` heap management system. Unit tests verify individual components in isolation.

2. **Identify Key Classes and Data Structures:** I scanned the includes and the body of the test class (`SweeperTest`) to pinpoint the central classes being tested. Key classes include:
    * `Sweeper`: The main class under test.
    * `Heap`:  The heap manager that the sweeper operates on.
    * `HeapObjectHeader`: Metadata associated with each allocated object.
    * `BasePage`, `NormalPage`, `LargePage`: Represent different memory pages managed by the heap.
    * `FreeList`:  Data structure used to track available memory within pages.
    * `GCed`: A template class representing garbage-collected objects.
    * `Persistent`, `CrossThreadPersistent`, `WeakCrossThreadPersistent`: Smart pointers for managing object lifetimes.
    * `StatsCollector`: Tracks heap statistics.

3. **Analyze Test Cases (Focus on `TEST_F` macros):** I went through each `TEST_F` function to understand the specific scenario it's designed to test. I looked for:
    * **What is being set up?** (Object allocations, marking, etc.)
    * **What action is being performed?** (`Sweep()`, `PreciseGC()`, allocations after GC)
    * **What is being asserted?** (`EXPECT_EQ`, `EXPECT_NE`, `EXPECT_TRUE`, `EXPECT_FALSE`)

4. **Infer Functionality from Test Cases:** By examining the test cases, I could deduce the following functionalities of the sweeper:
    * **Garbage Collection:** The core function is to identify and reclaim unmarked (garbage) objects.
    * **Sweeping Unmarked Objects:** Tests like `SweepUnmarkedNormalObject` and `SweepUnmarkedLargeObject` directly verify this.
    * **Preserving Marked Objects:** Tests like `DontSweepMarkedNormalObject` and `DontSweepMarkedLargeObject` confirm that live objects are not collected.
    * **Handling Different Object Sizes:** Tests involving `kLargeObjectSizeThreshold` indicate the sweeper handles both normal and large objects.
    * **Free List Management:**  `CoalesceFreeListEntries` shows the sweeper manages the free list by merging adjacent free blocks.
    * **Lazy Sweeping:** Tests like `LazySweepingDuringAllocation` demonstrate the sweeper can perform incremental cleanup during allocation.
    * **Interaction with Finalizers:** `AllocationDuringFinalizationIsNotSwept` explores scenarios involving object destructors.
    * **Cross-Thread Pointers:** Tests like `CrossThreadPersistentCanBeClearedFromOtherThread` and `WeakCrossThreadPersistentCanBeClearedFromOtherThread` highlight the sweeper's handling of cross-heap references.
    * **Memory Discarding:** `DiscardingNormalPageMemory` tests the ability to release unused memory pages.

5. **Consider Edge Cases and Error Scenarios:** The tests implicitly cover potential errors:
    * **Incorrectly sweeping live objects:**  The "Don't Sweep Marked" tests prevent this.
    * **Memory corruption:** Implicitly tested by the successful allocation and deallocation scenarios.
    * **Reentrancy issues:** `SweepDoesNotTriggerRecursiveGC` addresses this.

6. **Look for JavaScript Relevance (if any):**  I considered if the tested concepts have direct parallels in JavaScript's garbage collection. While the C++ implementation is low-level, the *concept* of garbage collection (identifying and reclaiming unused memory) is fundamental to JavaScript.

7. **Code Logic Inference:**  The test cases provide input and expected output for various scenarios. For example, marking an object as live (`MarkObject`) should prevent its destruction during a sweep.

8. **Identify Common Programming Errors:**  Based on the functionality, I considered common mistakes related to memory management:
    * **Memory leaks:** The sweeper aims to prevent this. Forgetting to unmark objects in C++ (if manual marking were used) would be an example.
    * **Use-after-free:** The sweeper's correctness is crucial to avoid this.

9. **Structure the Explanation:** I organized the information into clear sections: Functionality, No Torque, JavaScript Relevance, Code Logic Inference, and Common Programming Errors. I used bullet points and examples to make the explanation easy to understand.

10. **Refine and Clarify:**  I reviewed my initial analysis to ensure accuracy and clarity, adding details where necessary (e.g., explaining the `GCed` template, clarifying the purpose of `MarkObject`).
这个 C++ 代码文件 `v8/test/unittests/heap/cppgc/sweeper-unittest.cc` 是 V8 引擎中 `cppgc`（C++ Garbage Collection）组件的单元测试，专门用于测试 `Sweeper` 类的功能。

**主要功能列举:**

这个文件包含了多个单元测试，用于验证 `Sweeper` 类的各种功能，包括：

1. **清理未标记的普通对象:**  测试 `Sweeper` 能否正确地识别并清理在垃圾回收标记阶段未被标记的普通大小的对象。
2. **不清理已标记的普通对象:** 测试 `Sweeper` 能否正确地保留在垃圾回收标记阶段被标记的普通大小的对象。
3. **清理未标记的大对象:** 测试 `Sweeper` 能否正确地识别并清理未被标记的大对象。
4. **不清理已标记的大对象:** 测试 `Sweeper` 能否正确地保留被标记的大对象。
5. **清理同一页上的多个对象:** 测试 `Sweeper` 能否处理同一内存页上的多个需要清理的对象。
6. **清理所有 Arena 中的对象:** 测试 `Sweeper` 能否遍历并清理不同大小对象分配的内存区域（Arenas）。
7. **清理单个空间中的多个页面:** 测试 `Sweeper` 能否处理分布在同一内存空间的不同页面上的需要清理的对象。
8. **合并空闲列表条目:** 测试 `Sweeper` 在清理对象后，能否将相邻的空闲内存块合并成更大的空闲块，以提高内存分配效率。
9. **扫描不会触发递归 GC:** 测试 `Sweeper` 的清理操作不会触发新的垃圾回收周期，避免潜在的递归调用问题。
10. **取消对象标记:** 测试 `Sweeper` 在清理后，能够取消被清理对象的标记位，以便后续的垃圾回收周期能够正确处理。
11. **分配期间的延迟清理 (Lazy Sweeping):** 测试 `Sweeper` 是否可以在内存分配时执行延迟清理，回收部分未使用的内存。
12. **延迟清理普通页面:**  类似于上面的延迟清理，但更专注于普通大小对象所在的页面。
13. **终结器执行期间的分配不被清理:** 测试在对象析构函数（终结器）中分配的新对象不会被当前的清理过程清理掉。
14. **丢弃普通页面内存:** 测试 `Sweeper` 是否能够丢弃普通页面中未使用的内存，将其返还给操作系统。
15. **跨线程持久句柄可以从其他线程清除:** 测试跨线程持久句柄（`CrossThreadPersistent`）所引用的对象即使在其他线程被回收，清理器也能正确处理。
16. **弱跨线程持久句柄可以从其他线程清除:**  测试弱跨线程持久句柄（`WeakCrossThreadPersistent`）的类似功能。
17. **分配时获取最后一个空闲列表条目:** 测试在延迟清理后进行分配，分配器是否能够使用清理后产生的最后一个空闲内存块。

**关于 Torque 源代码:**

`v8/test/unittests/heap/cppgc/sweeper-unittest.cc`  **不是**以 `.tq` 结尾，因此它是一个 **C++** 源代码文件，而不是 v8 的 Torque 源代码。Torque 文件通常用于定义 V8 内部的运行时函数和类型。

**与 JavaScript 的功能关系:**

`cppgc` 是 V8 引擎中用于管理 C++ 对象的垃圾回收器。JavaScript 的垃圾回收机制（通常基于标记-清除或类似算法）负责回收不再被 JavaScript 代码引用的对象。虽然 `sweeper-unittest.cc` 直接测试的是 C++ 层的垃圾回收，但其最终目的是为了支持 JavaScript 的内存管理。

当 JavaScript 代码创建对象时，V8 内部可能会创建一些与之关联的 C++ 对象。`cppgc` 负责管理这些 C++ 对象的生命周期。`Sweeper` 组件是 `cppgc` 的核心部分，负责回收这些不再需要的 C++ 对象，从而避免内存泄漏，保证 V8 引擎的稳定性和性能。

**JavaScript 示例说明:**

虽然不能直接用 JavaScript 代码来演示 `Sweeper` 的功能（因为它是 C++ 内部实现），但可以从概念上理解其作用。

```javascript
// JavaScript 代码示例

let obj1 = {}; // 创建一个 JavaScript 对象
let obj2 = {};

obj1.ref = obj2; // obj1 引用 obj2

obj2 = null; // 解除 obj2 的引用

// 在 JavaScript 垃圾回收周期中，如果 obj2 不再被其他对象引用，
// 垃圾回收器会回收 obj2 占用的内存。

// cppgc 的 Sweeper 负责回收 V8 内部可能与 obj1 和 obj2 关联的 C++ 对象。
```

在这个例子中，当 `obj2 = null` 后，如果 `obj2` 不再被其他 JavaScript 对象引用，JavaScript 垃圾回收器最终会回收它。同时，V8 内部的 `cppgc` 的 `Sweeper` 可能会负责清理与 `obj2` 关联的 C++ 对象（例如，对象属性的内部表示）。

**代码逻辑推理 (假设输入与输出):**

考虑 `TEST_F(SweeperTest, SweepUnmarkedNormalObject)` 这个测试：

**假设输入:**

1. 在堆上分配了一个 `GCed<8>` 类型的对象。
2. 该对象在标记阶段 **没有** 被标记。

**代码逻辑:**

1. `Sweep()` 方法被调用。
2. `Sweeper` 会遍历堆，找到未标记的对象。
3. 对于找到的未标记对象，`Sweeper` 会调用其析构函数。

**预期输出:**

1. 全局变量 `g_destructor_callcount` 的值变为 `1u`，表示 `GCed` 对象的析构函数被调用了一次。

**涉及用户常见的编程错误 (C++ 方面):**

虽然 `cppgc` 旨在简化 C++ 内存管理，但仍然可能存在一些与手动内存管理相关的常见错误，`cppgc` 可以帮助避免或减轻这些错误的影响：

1. **内存泄漏:**  用户手动 `new` 了对象，但忘记 `delete`。 `cppgc` 会自动回收不再引用的对象，减少内存泄漏的风险。

    ```c++
    // 容易导致内存泄漏的 C++ 代码 (如果不用 cppgc 管理)
    void foo() {
      int* ptr = new int[10];
      // ... 忘记 delete[] ptr;
    }
    ```

    在 `cppgc` 中，使用 `MakeGarbageCollected` 分配的对象会自动被跟踪和回收。

2. **悬挂指针 (Dangling Pointers):**  `delete` 了对象，但仍然持有指向该内存的指针。

    ```c++
    // 容易导致悬挂指针的 C++ 代码
    int* ptr = new int(5);
    int* another_ptr = ptr;
    delete ptr;
    // another_ptr 现在是一个悬挂指针
    ```

    `cppgc` 通过垃圾回收机制，避免了手动 `delete` 带来的悬挂指针问题。当对象被回收时，用户不再持有指向它的有效指针（通过 `Persistent` 等智能指针管理）。

3. **双重释放 (Double Free):**  对同一块内存执行多次 `delete`。

    ```c++
    // 容易导致双重释放的 C++ 代码
    int* ptr = new int(5);
    delete ptr;
    delete ptr; // 错误！
    ```

    `cppgc` 的垃圾回收机制避免了手动 `delete`，因此不会出现双重释放的问题。

总而言之，`v8/test/unittests/heap/cppgc/sweeper-unittest.cc` 是 V8 引擎中测试 C++ 垃圾回收器核心组件的关键文件，确保了 V8 内部 C++ 对象的内存管理正确可靠，从而间接地支持了 JavaScript 的高效运行。

### 提示词
```
这是目录为v8/test/unittests/heap/cppgc/sweeper-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/heap/cppgc/sweeper-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/cppgc/sweeper.h"

#include <algorithm>

#include "include/cppgc/allocation.h"
#include "include/cppgc/cross-thread-persistent.h"
#include "include/cppgc/persistent.h"
#include "src/heap/cppgc/globals.h"
#include "src/heap/cppgc/heap-object-header.h"
#include "src/heap/cppgc/heap-page.h"
#include "src/heap/cppgc/heap-visitor.h"
#include "src/heap/cppgc/heap.h"
#include "src/heap/cppgc/object-view.h"
#include "src/heap/cppgc/page-memory.h"
#include "src/heap/cppgc/stats-collector.h"
#include "test/unittests/heap/cppgc/tests.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace cppgc {
namespace internal {

namespace {

size_t g_destructor_callcount;

template <size_t Size>
class GCed : public GarbageCollected<GCed<Size>> {
 public:
  virtual ~GCed() { ++g_destructor_callcount; }

  virtual void Trace(cppgc::Visitor*) const {}

 private:
  char array[Size];
};

class SweeperTest : public testing::TestWithHeap {
 public:
  SweeperTest() { g_destructor_callcount = 0; }

  void Sweep() {
    Heap* heap = Heap::From(GetHeap());
    ResetLinearAllocationBuffers();
    Sweeper& sweeper = heap->sweeper();
    // Pretend do finish marking as StatsCollector verifies that Notify*
    // methods are called in the right order.
    heap->stats_collector()->NotifyMarkingStarted(
        CollectionType::kMajor, GCConfig::MarkingType::kAtomic,
        GCConfig::IsForcedGC::kNotForced);
    heap->stats_collector()->NotifyMarkingCompleted(0);
    const SweepingConfig sweeping_config{
        SweepingConfig::SweepingType::kAtomic,
        SweepingConfig::CompactableSpaceHandling::kSweep};
    sweeper.Start(sweeping_config);
    sweeper.FinishIfRunning();
  }

  void MarkObject(void* payload) {
    HeapObjectHeader& header = HeapObjectHeader::FromObject(payload);
    header.TryMarkAtomic();
    BasePage* page = BasePage::FromPayload(&header);
    page->IncrementMarkedBytes(page->is_large()
                                   ? LargePage::From(page)->PayloadSize()
                                   : header.AllocatedSize());
  }

  PageBackend* GetBackend() { return Heap::From(GetHeap())->page_backend(); }
};

}  // namespace

TEST_F(SweeperTest, SweepUnmarkedNormalObject) {
  constexpr size_t kObjectSize = 8;
  using Type = GCed<kObjectSize>;

  MakeGarbageCollected<Type>(GetAllocationHandle());

  EXPECT_EQ(0u, g_destructor_callcount);

  Sweep();

  EXPECT_EQ(1u, g_destructor_callcount);
}

TEST_F(SweeperTest, DontSweepMarkedNormalObject) {
  constexpr size_t kObjectSize = 8;
  using Type = GCed<kObjectSize>;

  auto* object = MakeGarbageCollected<Type>(GetAllocationHandle());
  MarkObject(object);
  BasePage* page = BasePage::FromPayload(object);
  BaseSpace& space = page->space();

  EXPECT_EQ(0u, g_destructor_callcount);

  Sweep();

  EXPECT_EQ(0u, g_destructor_callcount);
  // Check that page is returned back to the space.
  EXPECT_NE(space.end(), std::find(space.begin(), space.end(), page));
  EXPECT_NE(nullptr, GetBackend()->Lookup(reinterpret_cast<Address>(object)));
}

TEST_F(SweeperTest, SweepUnmarkedLargeObject) {
  constexpr size_t kObjectSize = kLargeObjectSizeThreshold * 2;
  using Type = GCed<kObjectSize>;

  auto* object = MakeGarbageCollected<Type>(GetAllocationHandle());
  BasePage* page = BasePage::FromPayload(object);
  BaseSpace& space = page->space();

  EXPECT_EQ(0u, g_destructor_callcount);

  Sweep();

  EXPECT_EQ(1u, g_destructor_callcount);
  // Check that page is gone.
  EXPECT_EQ(space.end(), std::find(space.begin(), space.end(), page));
  EXPECT_EQ(nullptr, GetBackend()->Lookup(reinterpret_cast<Address>(object)));
}

TEST_F(SweeperTest, DontSweepMarkedLargeObject) {
  constexpr size_t kObjectSize = kLargeObjectSizeThreshold * 2;
  using Type = GCed<kObjectSize>;

  auto* object = MakeGarbageCollected<Type>(GetAllocationHandle());
  MarkObject(object);
  BasePage* page = BasePage::FromPayload(object);
  BaseSpace& space = page->space();

  EXPECT_EQ(0u, g_destructor_callcount);

  Sweep();

  EXPECT_EQ(0u, g_destructor_callcount);
  // Check that page is returned back to the space.
  EXPECT_NE(space.end(), std::find(space.begin(), space.end(), page));
  EXPECT_NE(nullptr, GetBackend()->Lookup(reinterpret_cast<Address>(object)));
}

TEST_F(SweeperTest, SweepMultipleObjectsOnPage) {
  constexpr size_t kObjectSize = 8;
  using Type = GCed<kObjectSize>;
  const size_t kNumberOfObjects =
      NormalPage::PayloadSize() / (sizeof(Type) + sizeof(HeapObjectHeader));

  for (size_t i = 0; i < kNumberOfObjects; ++i) {
    MakeGarbageCollected<Type>(GetAllocationHandle());
  }

  EXPECT_EQ(0u, g_destructor_callcount);

  Sweep();

  EXPECT_EQ(kNumberOfObjects, g_destructor_callcount);
}

TEST_F(SweeperTest, SweepObjectsOnAllArenas) {
  MakeGarbageCollected<GCed<1>>(GetAllocationHandle());
  MakeGarbageCollected<GCed<32>>(GetAllocationHandle());
  MakeGarbageCollected<GCed<64>>(GetAllocationHandle());
  MakeGarbageCollected<GCed<128>>(GetAllocationHandle());
  MakeGarbageCollected<GCed<2 * kLargeObjectSizeThreshold>>(
      GetAllocationHandle());

  EXPECT_EQ(0u, g_destructor_callcount);

  Sweep();

  EXPECT_EQ(5u, g_destructor_callcount);
}

TEST_F(SweeperTest, SweepMultiplePagesInSingleSpace) {
  MakeGarbageCollected<GCed<2 * kLargeObjectSizeThreshold>>(
      GetAllocationHandle());
  MakeGarbageCollected<GCed<2 * kLargeObjectSizeThreshold>>(
      GetAllocationHandle());
  MakeGarbageCollected<GCed<2 * kLargeObjectSizeThreshold>>(
      GetAllocationHandle());

  EXPECT_EQ(0u, g_destructor_callcount);

  Sweep();

  EXPECT_EQ(3u, g_destructor_callcount);
}

TEST_F(SweeperTest, CoalesceFreeListEntries) {
  constexpr size_t kObjectSize = 32;
  using Type = GCed<kObjectSize>;

  auto* object1 = MakeGarbageCollected<Type>(GetAllocationHandle());
  auto* object2 = MakeGarbageCollected<Type>(GetAllocationHandle());
  auto* object3 = MakeGarbageCollected<Type>(GetAllocationHandle());
  auto* object4 = MakeGarbageCollected<Type>(GetAllocationHandle());

  MarkObject(object1);
  MarkObject(object4);

  Address object2_start =
      reinterpret_cast<Address>(&HeapObjectHeader::FromObject(object2));
  Address object3_end =
      reinterpret_cast<Address>(&HeapObjectHeader::FromObject(object3)) +
      HeapObjectHeader::FromObject(object3).AllocatedSize();

  const BasePage* page = BasePage::FromPayload(object2);
  const FreeList& freelist = NormalPageSpace::From(page->space()).free_list();

  const FreeList::Block coalesced_block = {
      object2_start, static_cast<size_t>(object3_end - object2_start)};

  EXPECT_EQ(0u, g_destructor_callcount);
  EXPECT_FALSE(freelist.ContainsForTesting(coalesced_block));

  Sweep();

  EXPECT_EQ(2u, g_destructor_callcount);
  EXPECT_TRUE(freelist.ContainsForTesting(coalesced_block));
}

namespace {

class GCInDestructor final : public GarbageCollected<GCInDestructor> {
 public:
  explicit GCInDestructor(Heap* heap) : heap_(heap) {}
  ~GCInDestructor() {
    // Instead of directly calling GC, allocations should be supported here as
    // well.
    heap_->CollectGarbage(internal::GCConfig::ConservativeAtomicConfig());
  }
  void Trace(Visitor*) const {}

 private:
  Heap* heap_;
};

}  // namespace

TEST_F(SweeperTest, SweepDoesNotTriggerRecursiveGC) {
  auto* internal_heap = internal::Heap::From(GetHeap());
  size_t saved_epoch = internal_heap->epoch();
  MakeGarbageCollected<GCInDestructor>(GetAllocationHandle(), internal_heap);
  PreciseGC();
  EXPECT_EQ(saved_epoch + 1, internal_heap->epoch());
}

TEST_F(SweeperTest, UnmarkObjects) {
  auto* normal_object = MakeGarbageCollected<GCed<32>>(GetAllocationHandle());
  auto* large_object =
      MakeGarbageCollected<GCed<kLargeObjectSizeThreshold * 2>>(
          GetAllocationHandle());

  auto& normal_object_header = HeapObjectHeader::FromObject(normal_object);
  auto& large_object_header = HeapObjectHeader::FromObject(large_object);

  MarkObject(normal_object);
  MarkObject(large_object);

  EXPECT_TRUE(normal_object_header.IsMarked());
  EXPECT_TRUE(large_object_header.IsMarked());

  Sweep();

  if (Heap::From(GetHeap())->generational_gc_supported()) {
    EXPECT_TRUE(normal_object_header.IsMarked());
    EXPECT_TRUE(large_object_header.IsMarked());
  } else {
    EXPECT_FALSE(normal_object_header.IsMarked());
    EXPECT_FALSE(large_object_header.IsMarked());
  }
}

TEST_F(SweeperTest, LazySweepingDuringAllocation) {
  // The test allocates objects in such a way that the object with its header is
  // power of two. This is to make sure that if there is some padding at the end
  // of the page, it will go to a different freelist bucket. To get that,
  // subtract vptr and object-header-size from a power-of-two.
  static constexpr size_t kGCObjectSize =
      256 - sizeof(void*) - sizeof(HeapObjectHeader);
  using GCedObject = GCed<kGCObjectSize>;
  static_assert(v8::base::bits::IsPowerOfTwo(sizeof(GCedObject) +
                                             sizeof(HeapObjectHeader)));

  static const size_t kObjectsPerPage =
      NormalPage::PayloadSize() /
      (sizeof(GCedObject) + sizeof(HeapObjectHeader));
  // This test expects each page contain at least 2 objects.
  DCHECK_LT(2u, kObjectsPerPage);
  PreciseGC();
  std::vector<Persistent<GCedObject>> first_page;
  first_page.push_back(MakeGarbageCollected<GCedObject>(GetAllocationHandle()));
  GCedObject* expected_address_on_first_page =
      MakeGarbageCollected<GCedObject>(GetAllocationHandle());
  for (size_t i = 2; i < kObjectsPerPage; ++i) {
    first_page.push_back(
        MakeGarbageCollected<GCedObject>(GetAllocationHandle()));
  }
  std::vector<Persistent<GCedObject>> second_page;
  second_page.push_back(
      MakeGarbageCollected<GCedObject>(GetAllocationHandle()));
  GCedObject* expected_address_on_second_page =
      MakeGarbageCollected<GCedObject>(GetAllocationHandle());
  for (size_t i = 2; i < kObjectsPerPage; ++i) {
    second_page.push_back(
        MakeGarbageCollected<GCedObject>(GetAllocationHandle()));
  }
  testing::TestPlatform::DisableBackgroundTasksScope no_concurrent_sweep_scope(
      GetPlatformHandle().get());
  g_destructor_callcount = 0;
  static constexpr GCConfig config = {
      CollectionType::kMajor, StackState::kNoHeapPointers,
      GCConfig::MarkingType::kAtomic,
      GCConfig::SweepingType::kIncrementalAndConcurrent};
  Heap::From(GetHeap())->CollectGarbage(config);
  // Incremental sweeping is active and the space should have two pages with
  // no room for an additional GCedObject. Allocating a new GCedObject should
  // trigger sweeping. All objects other than the 2nd object on each page are
  // marked. Lazy sweeping on allocation should reclaim the object on one of
  // the pages and reuse its memory. The object on the other page should remain
  // un-reclaimed. To confirm: the newly object will be allcoated at one of the
  // expected addresses and the GCedObject destructor is only called once.
  GCedObject* new_object1 =
      MakeGarbageCollected<GCedObject>(GetAllocationHandle());
  EXPECT_EQ(1u, g_destructor_callcount);
  EXPECT_TRUE((new_object1 == expected_address_on_first_page) ||
              (new_object1 == expected_address_on_second_page));
  // Allocating again should reclaim the other unmarked object and reuse its
  // memory. The destructor will be called again and the new object will be
  // allocated in one of the expected addresses but not the same one as before.
  GCedObject* new_object2 =
      MakeGarbageCollected<GCedObject>(GetAllocationHandle());
  EXPECT_EQ(2u, g_destructor_callcount);
  EXPECT_TRUE((new_object2 == expected_address_on_first_page) ||
              (new_object2 == expected_address_on_second_page));
  EXPECT_NE(new_object1, new_object2);
}

TEST_F(SweeperTest, LazySweepingNormalPages) {
  using GCedObject = GCed<sizeof(size_t)>;
  EXPECT_EQ(0u, g_destructor_callcount);
  PreciseGC();
  EXPECT_EQ(0u, g_destructor_callcount);
  MakeGarbageCollected<GCedObject>(GetAllocationHandle());
  static constexpr GCConfig config = {
      CollectionType::kMajor, StackState::kNoHeapPointers,
      GCConfig::MarkingType::kAtomic,
      // Sweeping type must not include concurrent as that could lead to the
      // concurrent sweeper holding onto pages in rare cases which delays
      // reclamation of objects.
      GCConfig::SweepingType::kIncremental};
  Heap::From(GetHeap())->CollectGarbage(config);
  EXPECT_EQ(0u, g_destructor_callcount);
  MakeGarbageCollected<GCedObject>(GetAllocationHandle());
  EXPECT_EQ(1u, g_destructor_callcount);
  PreciseGC();
  EXPECT_EQ(2u, g_destructor_callcount);
}

namespace {
class AllocatingFinalizer : public GarbageCollected<AllocatingFinalizer> {
 public:
  static size_t destructor_callcount_;
  explicit AllocatingFinalizer(AllocationHandle& allocation_handle)
      : allocation_handle_(allocation_handle) {}
  ~AllocatingFinalizer() {
    MakeGarbageCollected<GCed<sizeof(size_t)>>(allocation_handle_);
    ++destructor_callcount_;
  }
  void Trace(Visitor*) const {}

 private:
  AllocationHandle& allocation_handle_;
};
size_t AllocatingFinalizer::destructor_callcount_ = 0;
}  // namespace

TEST_F(SweeperTest, AllocationDuringFinalizationIsNotSwept) {
  AllocatingFinalizer::destructor_callcount_ = 0;
  g_destructor_callcount = 0;
  MakeGarbageCollected<AllocatingFinalizer>(GetAllocationHandle(),
                                            GetAllocationHandle());
  PreciseGC();
  EXPECT_LT(0u, AllocatingFinalizer::destructor_callcount_);
  EXPECT_EQ(0u, g_destructor_callcount);
}

TEST_F(SweeperTest, DiscardingNormalPageMemory) {
  if (!Sweeper::CanDiscardMemory()) return;

  // Test ensures that free list payload is discarded and accounted for on page
  // level.
  auto* holder = MakeGarbageCollected<GCed<1>>(GetAllocationHandle());
  ConservativeMemoryDiscardingGC();
  auto* page = NormalPage::FromPayload(holder);
  // Assume the `holder` object is the first on the page for simplifying exact
  // discarded count.
  ASSERT_EQ(static_cast<void*>(page->PayloadStart() + sizeof(HeapObjectHeader)),
            holder);
  // No other object on the page is live.
  Address free_list_payload_start =
      page->PayloadStart() +
      HeapObjectHeader::FromObject(holder).AllocatedSize() +
      sizeof(kFreeListEntrySize);
  uintptr_t start =
      RoundUp(reinterpret_cast<uintptr_t>(free_list_payload_start),
              GetPlatform().GetPageAllocator()->CommitPageSize());
  uintptr_t end = RoundDown(reinterpret_cast<uintptr_t>(page->PayloadEnd()),
                            GetPlatform().GetPageAllocator()->CommitPageSize());
  EXPECT_GT(end, start);
  EXPECT_EQ(page->discarded_memory(), end - start);
  USE(holder);
}

namespace {

class Holder final : public GarbageCollected<Holder> {
 public:
  static size_t destructor_callcount;

  void Trace(Visitor*) const {}

  ~Holder() {
    EXPECT_FALSE(ref);
    EXPECT_FALSE(weak_ref);
    destructor_callcount++;
  }

  cppgc::subtle::CrossThreadPersistent<GCed<1>> ref;
  cppgc::subtle::WeakCrossThreadPersistent<GCed<1>> weak_ref;
};

// static
size_t Holder::destructor_callcount;

}  // namespace

TEST_F(SweeperTest, CrossThreadPersistentCanBeClearedFromOtherThread) {
  Holder::destructor_callcount = 0;
  auto* holder = MakeGarbageCollected<Holder>(GetAllocationHandle());

  auto remote_heap = cppgc::Heap::Create(GetPlatformHandle());
  // The case below must be able to clear both, the CTP and WCTP.
  holder->ref =
      MakeGarbageCollected<GCed<1>>(remote_heap->GetAllocationHandle());
  holder->weak_ref =
      MakeGarbageCollected<GCed<1>>(remote_heap->GetAllocationHandle());

  testing::TestPlatform::DisableBackgroundTasksScope no_concurrent_sweep_scope(
      GetPlatformHandle().get());
  Heap::From(GetHeap())->CollectGarbage(
      {CollectionType::kMajor, StackState::kNoHeapPointers,
       GCConfig::MarkingType::kAtomic,
       GCConfig::SweepingType::kIncrementalAndConcurrent});
  // `holder` is unreachable (as the stack is not scanned) and will be
  // reclaimed. Its payload memory is generally poisoned at this point. The
  // CrossThreadPersistent slot should be unpoisoned.

  // Terminate the remote heap which should also clear `holder->ref`. The slot
  // for `ref` should have been unpoisoned by the GC.
  Heap::From(remote_heap.get())->Terminate();

  // Finish the sweeper which will find the CrossThreadPersistent in cleared
  // state.
  Heap::From(GetHeap())->sweeper().FinishIfRunning();
  EXPECT_EQ(1u, Holder::destructor_callcount);
}

TEST_F(SweeperTest, WeakCrossThreadPersistentCanBeClearedFromOtherThread) {
  Holder::destructor_callcount = 0;
  auto* holder = MakeGarbageCollected<Holder>(GetAllocationHandle());

  auto remote_heap = cppgc::Heap::Create(GetPlatformHandle());
  holder->weak_ref =
      MakeGarbageCollected<GCed<1>>(remote_heap->GetAllocationHandle());

  testing::TestPlatform::DisableBackgroundTasksScope no_concurrent_sweep_scope(
      GetPlatformHandle().get());
  static constexpr GCConfig config = {
      CollectionType::kMajor, StackState::kNoHeapPointers,
      GCConfig::MarkingType::kAtomic,
      GCConfig::SweepingType::kIncrementalAndConcurrent};
  Heap::From(GetHeap())->CollectGarbage(config);
  // `holder` is unreachable (as the stack is not scanned) and will be
  // reclaimed. Its payload memory is generally poisoned at this point. The
  // WeakCrossThreadPersistent slot should be unpoisoned during clearing.

  // GC in the remote heap should also clear `holder->weak_ref`. The slot for
  // `weak_ref` should be unpoisoned by the GC.
  Heap::From(remote_heap.get())
      ->CollectGarbage({CollectionType::kMajor, StackState::kNoHeapPointers,
                        GCConfig::MarkingType::kAtomic,
                        GCConfig::SweepingType::kAtomic});

  // Finish the sweeper which will find the CrossThreadPersistent in cleared
  // state.
  Heap::From(GetHeap())->sweeper().FinishIfRunning();
  EXPECT_EQ(1u, Holder::destructor_callcount);
}

TEST_F(SweeperTest, SweepOnAllocationTakeLastFreeListEntry) {
  // The test allocates the following layout:
  // |--object-A--|-object-B-|--object-A--|---free-space---|
  // Objects A are reachable, whereas object B is not. sizeof(B) is smaller than
  // that of A. The test starts garbage-collection with lazy sweeping, then
  // tries to allocate object A, expecting the allocation to end up on the same
  // page at the free-space.
  using GCedA = GCed<256>;
  using GCedB = GCed<240>;

  PreciseGC();

  // Allocate the layout.
  Persistent<GCedA> a1 = MakeGarbageCollected<GCedA>(GetAllocationHandle());
  MakeGarbageCollected<GCedB>(GetAllocationHandle());
  Persistent<GCedA> a2 = MakeGarbageCollected<GCedA>(GetAllocationHandle());
  ConstAddress free_space_start =
      ObjectView<>(HeapObjectHeader::FromObject(a2.Get())).End();

  // Start the GC without sweeping.
  testing::TestPlatform::DisableBackgroundTasksScope no_concurrent_sweep_scope(
      GetPlatformHandle().get());
  static constexpr GCConfig config = {
      CollectionType::kMajor, StackState::kNoHeapPointers,
      GCConfig::MarkingType::kAtomic,
      GCConfig::SweepingType::kIncrementalAndConcurrent};
  Heap::From(GetHeap())->CollectGarbage(config);

  // Allocate and sweep.
  const GCedA* allocated_after_sweeping =
      MakeGarbageCollected<GCedA>(GetAllocationHandle());
  EXPECT_EQ(free_space_start,
            reinterpret_cast<ConstAddress>(
                &HeapObjectHeader::FromObject(allocated_after_sweeping)));
}

}  // namespace internal
}  // namespace cppgc
```