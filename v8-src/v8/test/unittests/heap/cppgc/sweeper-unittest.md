Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript analogy.

1. **Understand the Goal:** The core request is to understand the functionality of the C++ code (`sweeper-unittest.cc`) and relate it to JavaScript garbage collection concepts.

2. **Initial Scan for Keywords:** Look for prominent terms related to memory management and garbage collection. Words like "sweeper," "GC," "GarbageCollected," "allocation," "free list," "marking," "sweep," "destructor," "page," and "heap" immediately stand out. These provide a strong indication of the file's purpose.

3. **Identify the Core Class Under Test:** The `SweeperTest` class name is a dead giveaway that this file contains unit tests for a `Sweeper` class. This class is likely the central component being examined.

4. **Analyze the Test Cases:**  Go through each `TEST_F` function within `SweeperTest`. Each test case typically isolates a specific aspect of the `Sweeper`'s functionality. Summarize the intent of each test:
    * `SweepUnmarkedNormalObject`: Checks if unmarked normal objects are swept (deleted).
    * `DontSweepMarkedNormalObject`: Checks if marked normal objects are *not* swept.
    * `SweepUnmarkedLargeObject`: Checks sweeping of large objects.
    * `DontSweepMarkedLargeObject`: Checks not sweeping marked large objects.
    * `SweepMultipleObjectsOnPage`:  Verifies sweeping multiple objects on the same memory page.
    * `SweepObjectsOnAllArenas`: Checks sweeping across different memory allocation areas (arenas).
    * `SweepMultiplePagesInSingleSpace`:  Checks sweeping across multiple memory pages.
    * `CoalesceFreeListEntries`:  Examines the merging of freed memory blocks.
    * `SweepDoesNotTriggerRecursiveGC`: Ensures sweeping doesn't initiate another garbage collection cycle.
    * `UnmarkObjects`: Verifies that objects are unmarked after sweeping (in non-generational GC).
    * `LazySweepingDuringAllocation`: Tests if sweeping happens during allocation to reclaim memory.
    * `LazySweepingNormalPages`: Specifically tests lazy sweeping of normal-sized pages.
    * `AllocationDuringFinalizationIsNotSwept`:  Confirms that objects created during finalization aren't immediately swept.
    * `DiscardingNormalPageMemory`: Checks if memory occupied by free lists is correctly tracked as discarded.
    * `CrossThreadPersistentCanBeClearedFromOtherThread`: Tests interaction with cross-thread persistent references.
    * `WeakCrossThreadPersistentCanBeClearedFromOtherThread`: Tests interaction with weak cross-thread persistent references.
    * `SweepOnAllocationTakeLastFreeListEntry`: Checks if allocation reuses the last free block on a page after sweeping.

5. **Identify Helper Functions and Data Structures:** Note the `GCed` template class, which represents garbage-collected objects. Pay attention to helper methods like `Sweep()`, `MarkObject()`, and the global counter `g_destructor_callcount`. These provide insights into how the tests are structured and how the `Sweeper`'s effects are observed.

6. **Infer the `Sweeper`'s Role:** Based on the tests, deduce the core responsibilities of the `Sweeper`:
    * Identify and reclaim (sweep) unmarked garbage-collected objects.
    * Leave marked objects untouched.
    * Handle both normal and large objects.
    * Manage free memory within pages (coalescing).
    * Integrate with the overall garbage collection process (marking phase, lazy sweeping).
    * Interact with cross-thread references.

7. **Relate to JavaScript GC:** Think about how JavaScript's garbage collection works. Key concepts like marking, sweeping, and object finalization are present in both. Consider the differences as well (e.g., the specifics of cross-thread persistence might not have a direct JavaScript equivalent).

8. **Formulate the Summary:**  Combine the findings into a concise description of the file's purpose and the `Sweeper`'s functionality.

9. **Create the JavaScript Analogy:**  Find a simplified JavaScript scenario that demonstrates the core idea of sweeping: removing unreachable objects. Focus on the concepts of reachability and object destruction. A simple example with objects and nulling references is sufficient. Explain the analogy clearly, highlighting the similarities and differences. Specifically, mention that C++ offers more control (manual marking) whereas JavaScript's GC is more automated.

10. **Review and Refine:** Read through the summary and analogy to ensure clarity, accuracy, and completeness. Check for any technical jargon that might need further explanation. Make sure the JavaScript example is easy to understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the file is about general heap management.
* **Correction:** The presence of "sweeper" strongly suggests it's specifically about the *sweeping* phase of garbage collection.

* **Initial thought:**  Just list all the test names.
* **Refinement:** Summarize the *purpose* of each test to convey a deeper understanding.

* **Initial thought:**  Focus only on the similarities between C++ and JavaScript GC.
* **Refinement:**  Acknowledge the differences in control and implementation to provide a more nuanced comparison.

By following these steps and engaging in this kind of iterative analysis, you can effectively understand the functionality of complex code and relate it to familiar concepts in other languages.
这个C++源代码文件 `sweeper-unittest.cc` 是 V8 JavaScript 引擎中 `cppgc` 组件的单元测试文件，专门用于测试 `Sweeper` 类的功能。 `Sweeper` 类负责垃圾回收过程中的 **清除 (sweeping)** 阶段。

**功能归纳:**

该文件的主要功能是测试 `cppgc::internal::Sweeper` 类的各种场景和行为，以确保其能够正确地识别和回收不再使用的内存。 具体来说，测试涵盖以下方面：

1. **基本清除功能:**
   - 测试清除未标记的普通对象和大型对象，验证它们是否会被正确地析构和回收。
   - 测试保留已标记的普通对象和大型对象，验证它们是否不会被错误地回收。

2. **页面级别的清除:**
   - 测试清除单个页面上的多个对象。
   - 测试清除跨越多个内存区域 (arenas) 的对象。
   - 测试清除单个内存区域中的多个页面上的对象。

3. **空闲列表管理:**
   - 测试清除操作后，相邻的空闲内存块是否会被合并 (coalesce) 到空闲列表中，以便后续的内存分配。

4. **避免递归垃圾回收:**
   - 测试在对象的析构函数中触发垃圾回收时，清除器是否能正确处理，避免无限递归。

5. **取消标记 (Unmarking):**
   - 测试清除操作是否会取消已标记的对象，以便在下一次垃圾回收周期中重新标记 (在非分代垃圾回收中)。

6. **延迟清除 (Lazy Sweeping):**
   - 测试在内存分配时触发延迟清除，以回收部分内存，避免立即进行完整的清除。这有助于提高分配性能。
   - 测试延迟清除对普通大小内存页面的影响。

7. **终结器 (Finalizer) 处理:**
   - 测试在终结器执行期间分配的对象是否不会被立即清除。

8. **释放内存 (Discarding Memory):**
   - 测试清除器是否能够释放空闲列表占用的内存，并正确地统计释放的内存量。

9. **跨线程持久化引用 (Cross-Thread Persistent) 的处理:**
   - 测试从其他线程清除跨线程持久化引用和弱跨线程持久化引用的能力。

10. **在分配时使用最后的空闲列表条目:**
    - 测试在内存分配时，清除器能否正确使用清除后留下的最后一个空闲内存块。

**与 JavaScript 的功能关系及 JavaScript 示例:**

`cppgc` 是 V8 引擎中用于管理 C++ 对象的垃圾回收机制，它与 JavaScript 的垃圾回收密切相关，因为 V8 引擎本身是用 C++ 编写的，并且需要管理其内部的 C++ 对象。

`Sweeper` 的功能对应于 JavaScript 垃圾回收中的 **清除 (sweeping)** 阶段。 在 JavaScript 中，垃圾回收器会标记不再被引用的对象，然后在清除阶段，这些被标记为垃圾的对象所占用的内存会被回收。

**JavaScript 示例:**

```javascript
// 假设我们有一些 JavaScript 对象
let obj1 = { data: "一些数据" };
let obj2 = { ref: obj1 };
let obj3 = { data: "另一个对象" };

// obj1 和 obj2 相互引用，它们是可达的，不会被回收
// obj3 没有被任何可达对象引用，它是不可达的，可以被回收

// ... 一段时间后 ...

// 将 obj2 对 obj1 的引用移除
obj2.ref = null;

// 此时，obj1 仍然被全局作用域的 obj1 变量引用，是可达的
// obj3 仍然是不可达的

// ... 垃圾回收器运行时 ...

// 清除阶段会将不可达的 obj3 所占用的内存回收

// 我们可以显式触发垃圾回收 (在某些环境中，不推荐)
if (global.gc) {
  global.gc();
}

// 此时，如果垃圾回收器运行，obj3 所占用的内存应该已经被回收。
// obj1 和 obj2 仍然存在 (取决于具体的引用关系)
```

**对应关系解释:**

- **未标记的对象被清除:** 就像 JavaScript 中没有被引用的对象会被垃圾回收器清除一样。在 `SweeperTest` 中，未被 `MarkObject` 标记的对象会被清除器回收。
- **已标记的对象被保留:**  类似于 JavaScript 中仍然被引用的对象不会被垃圾回收器清除。在测试中，被 `MarkObject` 标记的对象不会被清除器回收。
- **内存回收:** `Sweeper` 的核心目标是回收不再使用的 C++ 对象的内存，这与 JavaScript 垃圾回收器的目标一致。

**总结:**

`sweeper-unittest.cc` 是对 V8 引擎中负责 C++ 对象内存回收的 `Sweeper` 类进行严格测试的单元测试文件。它确保了 `Sweeper` 能够正确地识别和回收垃圾内存，这对于 V8 引擎的性能和稳定性至关重要，并间接地影响着 JavaScript 程序的执行效率和内存管理。 该测试文件模拟了各种内存分配和回收的场景，以验证 `Sweeper` 在不同情况下的行为是否符合预期。

Prompt: 
```
这是目录为v8/test/unittests/heap/cppgc/sweeper-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
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

"""

```