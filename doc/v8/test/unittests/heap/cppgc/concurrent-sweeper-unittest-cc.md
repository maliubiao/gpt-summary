Response:
Let's break down the thought process to analyze the provided C++ code and generate the requested information.

**1. Understanding the Core Request:**

The fundamental request is to understand the purpose and functionality of the given C++ test file. Keywords like "功能 (functionality)", "列举 (enumerate)", and specific instructions regarding `.tq` files, JavaScript relevance, logic inference, and common programming errors point towards a comprehensive analysis.

**2. Initial Code Scan and High-Level Interpretation:**

My first step was to quickly scan the code for keywords and structure. I noticed:

* **Includes:**  Headers like `<algorithm>`, `<set>`, `<vector>`, and especially those starting with `"include/cppgc/"` and `"src/heap/cppgc/"` strongly suggest this is related to a garbage collection system (cppgc). The presence of `"test/unittests/heap/cppgc/"` confirms it's a test file. The inclusion of `"testing/gtest/include/gtest/gtest.h"` indicates the use of Google Test for unit testing.
* **Namespaces:** `cppgc::internal` clearly places this code within the internal implementation details of the cppgc library.
* **Global Variable:** `g_destructor_callcount` suggests tracking destructor calls, likely for testing finalization.
* **Templates:** `Finalizable<Size>` and `NonFinalizable<Size>` indicate parameterized types, differentiating objects that require finalization from those that don't. The `Size` parameter likely relates to object size.
* **Test Class:** `ConcurrentSweeperTest` using `testing::TestWithHeap` clearly marks this as a unit test suite focused on a "ConcurrentSweeper."
* **Methods:**  Methods like `StartSweeping`, `WaitForConcurrentSweeping`, `FinishSweeping` strongly hint at the core functionality being tested: concurrent garbage collection sweeping. Other methods like `CheckFreeListEntries`, `PageInBackend`, `FreeListContains`, and `MarkObject` appear to be helper functions for verification and setup.
* **Test Cases:**  `TEST_F(ConcurrentSweeperTest, ...)` blocks define individual test cases, each focusing on a specific aspect of the concurrent sweeper.

**3. Deeper Dive into Key Components:**

After the initial scan, I focused on understanding the core components:

* **`Finalizable` and `NonFinalizable`:**  I recognized the distinction and how it relates to garbage collection. `Finalizable` objects have destructors that need to be called during garbage collection, while `NonFinalizable` objects don't. The size variations (Normal and Large) likely test how the sweeper handles different object sizes and page types.
* **`ConcurrentSweeperTest`:** I identified its role as the test fixture, setting up the heap environment and providing helper functions to control and inspect the sweeper's behavior.
* **`StartSweeping`, `WaitForConcurrentSweeping`, `FinishSweeping`:** These are the key methods for controlling the concurrent sweeper. They simulate the start, waiting period, and completion of a sweeping phase.
* **Test Cases:** I started analyzing the individual test cases, noting their names and what they seemed to be testing:
    * `BackgroundSweepOfNormalPage`/`LargePage`:  Testing the basic background sweeping of non-finalizable objects.
    * `DeferredFinalizationOfNormalPage`/`LargePage`: Testing the delayed destruction (finalization) of finalizable objects.
    * `DestroyLargePageOnMainThread`: Testing the destruction of large pages.
    * `IncrementalSweeping`: Testing the incremental sweeping functionality.
    * `SweepOnAllocationReturnEmptyPage`: Testing a specific optimization related to allocating on previously swept pages.

**4. Addressing Specific Requirements:**

Now, I tackled each of the specific requirements from the prompt:

* **功能 (Functionality):**  Based on the code structure and test case names, I concluded the primary function is to test the concurrent sweeper component of the cppgc garbage collector. I listed the key aspects being tested.
* **`.tq` Check:** I checked for the file extension. Since it's `.cc`, it's not a Torque file.
* **JavaScript Relation:** I considered the role of garbage collection in JavaScript. Since cppgc is a C++ garbage collector used by V8 (the JavaScript engine), there's a direct relationship. I used the analogy of JavaScript garbage collection to explain the concepts. I focused on the automatic memory management aspect and the role of finalizers.
* **Logic Inference (Hypothetical Input/Output):**  I chose a simple test case (`BackgroundSweepOfNormalPage`) and walked through a simplified version of its logic, predicting the state of objects and the free list after sweeping. This required understanding the basic principles of marking and sweeping.
* **Common Programming Errors:**  I thought about common memory management errors in languages with manual memory management (like C++) and how a garbage collector helps prevent them. I also considered potential issues that *could* arise in a system with finalizers, like relying on their immediate execution.

**5. Refinement and Organization:**

Finally, I organized my findings into a clear and structured response, addressing each point in the prompt. I used clear language and provided examples where necessary. I made sure to emphasize the connection to JavaScript and explain the purpose of each test case.

Essentially, the process involved a top-down approach: starting with a high-level understanding of the code's purpose and then drilling down into the details of individual components and test cases. It also involved connecting the specific C++ code to broader concepts of garbage collection and its relevance to JavaScript.
这个文件 `v8/test/unittests/heap/cppgc/concurrent-sweeper-unittest.cc` 是 V8 JavaScript 引擎中 cppgc（C++ garbage collector）组件的单元测试文件，专门用于测试并发垃圾回收的清除（sweeping）阶段的功能。

**功能列举:**

这个文件的主要功能是测试 cppgc 的并发清除器（ConcurrentSweeper）在各种场景下的行为，包括：

1. **非终结对象（Non-finalizable objects）的后台清除:**
   - 测试并发清除器是否能在后台线程正确地清除不再被引用的非终结对象。
   - 测试清除后，这些对象的内存是否会被添加到空闲列表（free list）中。
   - 测试大型非终结对象的清除，以及相关页面的处理。

2. **终结对象（Finalizable objects）的延迟终结（Deferred finalization）:**
   - 测试并发清除器是否会跳过终结对象的立即清除，而是将其放入一个待终结的队列中。
   - 测试终结对象的析构函数是否会在主线程的后续阶段被调用。
   - 测试大型终结对象的延迟终结和相关页面的处理。

3. **并发清除与标记的交互:**
   - 测试在并发清除过程中，已标记的对象是否保持标记状态（在非分代 GC 中可能会被取消标记）。

4. **增量清除（Incremental sweeping）:**
   - 测试增量清除器的功能，它允许清除操作分批进行，不会阻塞主线程太久。

5. **在分配时清除（Sweep on allocation）:**
   - 测试在分配新对象时，如果遇到之前被完全清除的页面，是否能正确地重用这些页面。

6. **大型页面的管理:**
   - 测试大型对象所占用的页面的分配、清除和回收。
   - 尤其关注在并发环境下的线程安全性，例如避免在后台线程并发销毁大型页面时出现问题。

**关于文件扩展名 `.tq`:**

`v8/test/unittests/heap/cppgc/concurrent-sweeper-unittest.cc` 的扩展名是 `.cc`，这意味着它是一个 **C++ 源代码文件**。如果文件名以 `.tq` 结尾，那么它才是 V8 Torque 的源代码。

**与 JavaScript 的关系:**

这个 C++ 文件测试的是 V8 引擎的底层垃圾回收机制 cppgc。虽然这个文件本身不是 JavaScript 代码，但它直接关系到 JavaScript 的内存管理和性能。JavaScript 开发者不需要直接接触这些 C++ 代码，但 cppgc 的正确性直接影响到 JavaScript 程序的稳定性和效率。

**JavaScript 举例说明:**

在 JavaScript 中，我们创建的对象最终会被 V8 的垃圾回收器回收。cppgc 的并发清除器负责在后台默默地清理不再使用的 C++ 对象，这些 C++ 对象可能对应着 JavaScript 引擎内部的各种数据结构。

```javascript
// JavaScript 代码
let obj1 = {};
let obj2 = { ref: obj1 };
let obj3 = {};

// ... 一段时间后，obj1 不再被引用
obj2.ref = {}; // obj1 现在是垃圾

// ... 一段时间后，obj2 也不再被引用
obj2 = null;

// ... 一段时间后，obj3 也不再被引用
obj3 = null;

// V8 的 cppgc 并发清除器会在后台运行，回收 obj1, obj2, obj3 占用的内存。
```

在这个例子中，当 `obj1`、`obj2` 和 `obj3` 不再被引用时，cppgc 的并发清除器会检测到这些对象成为了垃圾，并在后台线程执行清除操作，释放它们占用的内存。`v8/test/unittests/heap/cppgc/concurrent-sweeper-unittest.cc` 中的测试就覆盖了这种场景，确保并发清除器能够正确地回收这些不再使用的对象。

**代码逻辑推理 (假设输入与输出):**

以 `TEST_F(ConcurrentSweeperTest, BackgroundSweepOfNormalPage)` 这个测试用例为例：

**假设输入:**

1. 创建了一个 `NormalNonFinalizable` 类型的对象 `unmarked_object`，它没有被标记为存活。
2. 创建了一个 `NormalNonFinalizable` 类型的对象 `marked_object`，它被标记为存活。
3. 这两个对象被分配在同一个内存页上。
4. 启动并发清除器。

**预期输出:**

1. 并发清除完成后，`unmarked_object` 所在的内存页中的该对象会被添加到空闲列表中，可以被重新分配。
2. `marked_object` 因为被标记为存活，所以不会被清除。
3. 如果启用了分代垃圾回收，`marked_object` 会保持标记状态；否则，它的标记可能会被移除。

**用户常见的编程错误:**

虽然 JavaScript 开发者不需要直接处理 cppgc，但与垃圾回收相关的常见编程错误也适用于理解这个测试的意义：

1. **内存泄漏 (Memory Leaks):** 在 C++ 中，如果对象没有被正确地释放，就会导致内存泄漏。cppgc 的作用就是自动回收不再使用的 C++ 对象，从而减少内存泄漏的风险。测试用例确保并发清除器能够识别并回收这些未引用的对象。

   ```c++
   // C++ 示例 (模拟内存泄漏)
   void allocate_memory() {
     int* ptr = new int[1000];
     // ... 没有 delete[] ptr;
   }

   // 在 cppgc 中，如果 GarbageCollected 对象不再被引用，cppgc 会负责回收其内存。
   ```

2. **访问已释放的内存 (Use-after-free):**  这是一个严重的错误，发生在访问已经被释放的内存时。cppgc 通过确保对象在被回收后无法被访问来避免这类问题。测试用例间接地验证了这一点，例如，确保在对象被清除后，其内存可以被安全地重用。

3. **依赖终结器的执行时机 (Relying on finalizers):**  在 JavaScript 中，我们可能会使用 `finalizationRegistry` 来注册对象被回收时的回调。然而，不能保证终结器会立即执行。同样地，在 cppgc 中，终结对象的析构函数也是延迟执行的。如果程序逻辑依赖于终结器的立即执行，可能会导致问题。测试用例 `DeferredFinalizationOfNormalPage` 和 `DeferredFinalizationOfLargePage` 就强调了终结是延迟发生的。

   ```javascript
   // JavaScript 示例
   let registry = new FinalizationRegistry(heldValue => {
     console.log('对象被回收了', heldValue);
   });

   let obj = {};
   registry.register(obj, 'my-object');
   obj = null; // obj 变为垃圾

   // 不能保证 "对象被回收了 my-object" 会立即打印出来。
   ```

总而言之，`v8/test/unittests/heap/cppgc/concurrent-sweeper-unittest.cc` 是一个关键的测试文件，用于确保 V8 引擎的并发垃圾回收机制能够正确、高效地工作，从而保障 JavaScript 程序的内存安全和性能。它涵盖了多种场景，包括不同类型的对象、不同大小的对象以及并发环境下的行为。

### 提示词
```
这是目录为v8/test/unittests/heap/cppgc/concurrent-sweeper-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/heap/cppgc/concurrent-sweeper-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <set>
#include <vector>

#include "include/cppgc/allocation.h"
#include "include/cppgc/platform.h"
#include "include/v8-platform.h"
#include "src/heap/cppgc/globals.h"
#include "src/heap/cppgc/heap-object-header.h"
#include "src/heap/cppgc/heap-page.h"
#include "src/heap/cppgc/heap-space.h"
#include "src/heap/cppgc/heap-visitor.h"
#include "src/heap/cppgc/page-memory.h"
#include "src/heap/cppgc/raw-heap.h"
#include "src/heap/cppgc/stats-collector.h"
#include "src/heap/cppgc/sweeper.h"
#include "test/unittests/heap/cppgc/test-platform.h"
#include "test/unittests/heap/cppgc/tests.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace cppgc {
namespace internal {

namespace {

size_t g_destructor_callcount;

template <size_t Size>
class Finalizable : public GarbageCollected<Finalizable<Size>> {
 public:
  Finalizable() : creation_thread_{v8::base::OS::GetCurrentThreadId()} {}

  virtual ~Finalizable() {
    ++g_destructor_callcount;
    EXPECT_EQ(creation_thread_, v8::base::OS::GetCurrentThreadId());
  }

  virtual void Trace(cppgc::Visitor*) const {}

 private:
  char array_[Size];
  int creation_thread_;
};

using NormalFinalizable = Finalizable<32>;
using LargeFinalizable = Finalizable<kLargeObjectSizeThreshold * 2>;

template <size_t Size>
class NonFinalizable : public GarbageCollected<NonFinalizable<Size>> {
 public:
  virtual void Trace(cppgc::Visitor*) const {}

 private:
  char array_[Size];
  int padding_to_make_size_the_same_as_finalizible_;
};

using NormalNonFinalizable = NonFinalizable<32>;
using LargeNonFinalizable = NonFinalizable<kLargeObjectSizeThreshold * 2>;

}  // namespace

class ConcurrentSweeperTest : public testing::TestWithHeap {
 public:
  ConcurrentSweeperTest() { g_destructor_callcount = 0; }

  void StartSweeping() {
    Heap* heap = Heap::From(GetHeap());
    ResetLinearAllocationBuffers();
    // Pretend do finish marking as StatsCollector verifies that Notify*
    // methods are called in the right order.
    heap->stats_collector()->NotifyMarkingStarted(
        CollectionType::kMajor, GCConfig::MarkingType::kAtomic,
        GCConfig::IsForcedGC::kNotForced);
    heap->stats_collector()->NotifyMarkingCompleted(0);
    Sweeper& sweeper = heap->sweeper();
    const SweepingConfig sweeping_config{
        SweepingConfig::SweepingType::kIncrementalAndConcurrent,
        SweepingConfig::CompactableSpaceHandling::kSweep};
    sweeper.Start(sweeping_config);
  }

  void WaitForConcurrentSweeping() {
    Heap* heap = Heap::From(GetHeap());
    Sweeper& sweeper = heap->sweeper();
    sweeper.WaitForConcurrentSweepingForTesting();
  }

  void FinishSweeping() {
    Heap* heap = Heap::From(GetHeap());
    Sweeper& sweeper = heap->sweeper();
    sweeper.FinishIfRunning();
  }

  const RawHeap& GetRawHeap() const {
    const Heap* heap = Heap::From(GetHeap());
    return heap->raw_heap();
  }

  void CheckFreeListEntries(const std::vector<void*>& objects) {
    const Heap* heap = Heap::From(GetHeap());
    const PageBackend* backend = heap->page_backend();

    for (auto* object : objects) {
      // The corresponding page could be removed.
      if (!backend->Lookup(static_cast<ConstAddress>(object))) continue;

      const auto* header =
          BasePage::FromPayload(object)->TryObjectHeaderFromInnerAddress(
              object);
      // TryObjectHeaderFromInnerAddress returns nullptr for freelist entries.
      EXPECT_EQ(nullptr, header);
    }
  }

  bool PageInBackend(const BasePage* page) {
    const Heap* heap = Heap::From(GetHeap());
    const PageBackend* backend = heap->page_backend();
    return backend->Lookup(reinterpret_cast<ConstAddress>(page));
  }

  bool FreeListContains(const BaseSpace& space,
                        const std::vector<void*>& objects) {
    const Heap* heap = Heap::From(GetHeap());
    const PageBackend* backend = heap->page_backend();
    const auto& freelist = NormalPageSpace::From(space).free_list();

    for (void* object : objects) {
      // The corresponding page could be removed.
      if (!backend->Lookup(static_cast<ConstAddress>(object))) continue;

      if (!freelist.ContainsForTesting({object, 0})) return false;
    }

    return true;
  }

  void MarkObject(void* payload) {
    HeapObjectHeader& header = HeapObjectHeader::FromObject(payload);
    header.TryMarkAtomic();
    BasePage* page = BasePage::FromPayload(&header);
    page->IncrementMarkedBytes(page->is_large()
                                   ? LargePage::From(page)->PayloadSize()
                                   : header.AllocatedSize());
  }
};

TEST_F(ConcurrentSweeperTest, BackgroundSweepOfNormalPage) {
  // Non finalizable objects are swept right away.
  using GCedType = NormalNonFinalizable;

  auto* unmarked_object = MakeGarbageCollected<GCedType>(GetAllocationHandle());
  auto* marked_object = MakeGarbageCollected<GCedType>(GetAllocationHandle());
  MarkObject(marked_object);

  auto* page = BasePage::FromPayload(unmarked_object);
  auto& space = page->space();

  // The test requires objects to be allocated on the same page;
  ASSERT_EQ(page, BasePage::FromPayload(marked_object));

  StartSweeping();

  // Wait for concurrent sweeping to finish.
  WaitForConcurrentSweeping();

  const auto& hoh = HeapObjectHeader::FromObject(marked_object);
  if (Heap::From(GetHeap())->generational_gc_supported()) {
    // Check that the marked object is still marked.
    EXPECT_TRUE(hoh.IsMarked());
  } else {
    // Check that the marked object was unmarked.
    EXPECT_FALSE(hoh.IsMarked());
  }

  // Check that free list entries are created right away for non-finalizable
  // objects, but not immediately returned to the space's freelist.
  CheckFreeListEntries({unmarked_object});
  EXPECT_FALSE(FreeListContains(space, {unmarked_object}));

  FinishSweeping();

  // Check that finalizable objects are swept and put into the freelist of the
  // corresponding space.
  EXPECT_TRUE(FreeListContains(space, {unmarked_object}));
}

TEST_F(ConcurrentSweeperTest, BackgroundSweepOfLargePage) {
  // Non finalizable objects are swept right away but the page is only returned
  // from the main thread.
  using GCedType = LargeNonFinalizable;

  auto* unmarked_object = MakeGarbageCollected<GCedType>(GetAllocationHandle());
  auto* marked_object = MakeGarbageCollected<GCedType>(GetAllocationHandle());
  MarkObject(marked_object);

  auto* unmarked_page = BasePage::FromPayload(unmarked_object);
  auto* marked_page = BasePage::FromPayload(marked_object);
  auto& space = unmarked_page->space();

  ASSERT_EQ(&space, &marked_page->space());

  StartSweeping();

  // Wait for concurrent sweeping to finish.
  WaitForConcurrentSweeping();

  const auto& hoh = HeapObjectHeader::FromObject(marked_object);
  if (Heap::From(GetHeap())->generational_gc_supported()) {
    // Check that the marked object is still marked.
    EXPECT_TRUE(hoh.IsMarked());
  } else {
    // Check that the marked object was unmarked.
    EXPECT_FALSE(hoh.IsMarked());
  }

  // The page should not have been removed on the background threads.
  EXPECT_TRUE(PageInBackend(unmarked_page));

  FinishSweeping();

  // Check that free list entries are created right away for non-finalizable
  // objects, but not immediately returned to the space's freelist.
  EXPECT_FALSE(PageInBackend(unmarked_page));

  // Check that marked pages are returned to space right away.
  EXPECT_NE(space.end(), std::find(space.begin(), space.end(), marked_page));
}

TEST_F(ConcurrentSweeperTest, DeferredFinalizationOfNormalPage) {
  static constexpr size_t kNumberOfObjects = 10;
  // Finalizable types are left intact by concurrent sweeper.
  using GCedType = NormalFinalizable;

  std::set<BasePage*> pages;
  std::vector<void*> objects;

  BaseSpace* space = nullptr;
  for (size_t i = 0; i < kNumberOfObjects; ++i) {
    auto* object = MakeGarbageCollected<GCedType>(GetAllocationHandle());
    objects.push_back(object);
    auto* page = BasePage::FromPayload(object);
    pages.insert(page);
    if (!space) space = &page->space();
  }

  StartSweeping();

  // Wait for concurrent sweeping to finish.
  WaitForConcurrentSweeping();

  // Check that pages are not returned right away.
  for (auto* page : pages) {
    EXPECT_EQ(space->end(), std::find(space->begin(), space->end(), page));
  }
  // Check that finalizable objects are left intact in pages.
  EXPECT_FALSE(FreeListContains(*space, objects));
  // No finalizers have been executed.
  EXPECT_EQ(0u, g_destructor_callcount);

  FinishSweeping();

  // Check that finalizable objects are swept and turned into freelist entries.
  CheckFreeListEntries(objects);
  // Check that space's freelist contains these entries.
  EXPECT_TRUE(FreeListContains(*space, objects));
  // Check that finalizers have been executed.
  EXPECT_EQ(kNumberOfObjects, g_destructor_callcount);
}

TEST_F(ConcurrentSweeperTest, DeferredFinalizationOfLargePage) {
  using GCedType = LargeFinalizable;

  auto* object = MakeGarbageCollected<GCedType>(GetAllocationHandle());

  auto* page = BasePage::FromPayload(object);
  auto& space = page->space();

  StartSweeping();

  // Wait for concurrent sweeping to finish.
  WaitForConcurrentSweeping();

  // Check that the page is not returned to the space.
  EXPECT_EQ(space.end(), std::find(space.begin(), space.end(), page));
  // Check that no destructors have been executed yet.
  EXPECT_EQ(0u, g_destructor_callcount);

  FinishSweeping();

  // Check that the destructor was executed.
  EXPECT_EQ(1u, g_destructor_callcount);
  // Check that page was unmapped.
  EXPECT_FALSE(PageInBackend(page));
}

TEST_F(ConcurrentSweeperTest, DestroyLargePageOnMainThread) {
  // This test fails with TSAN when large pages are destroyed concurrently
  // without proper support by the backend.
  using GCedType = LargeNonFinalizable;

  auto* object = MakeGarbageCollected<GCedType>(GetAllocationHandle());
  auto* page = BasePage::FromPayload(object);

  StartSweeping();

  // Allocating another large object should not race here.
  MakeGarbageCollected<GCedType>(GetAllocationHandle());

  // Wait for concurrent sweeping to finish.
  WaitForConcurrentSweeping();

  FinishSweeping();

  // Check that page was unmapped.
  EXPECT_FALSE(PageInBackend(page));
}

TEST_F(ConcurrentSweeperTest, IncrementalSweeping) {
  testing::TestPlatform::DisableBackgroundTasksScope disable_concurrent_sweeper(
      &GetPlatform());

  auto task_runner =
      GetPlatform().GetForegroundTaskRunner(TaskPriority::kUserBlocking);

  // Create two unmarked objects.
  MakeGarbageCollected<NormalFinalizable>(GetAllocationHandle());
  MakeGarbageCollected<LargeFinalizable>(GetAllocationHandle());

  // Create two marked objects.
  auto* marked_normal_object =
      MakeGarbageCollected<NormalFinalizable>(GetAllocationHandle());
  auto* marked_large_object =
      MakeGarbageCollected<LargeFinalizable>(GetAllocationHandle());

  auto& marked_normal_header =
      HeapObjectHeader::FromObject(marked_normal_object);
  auto& marked_large_header = HeapObjectHeader::FromObject(marked_large_object);

  MarkObject(marked_normal_object);
  MarkObject(marked_large_object);

  StartSweeping();

  EXPECT_EQ(0u, g_destructor_callcount);
  EXPECT_TRUE(marked_normal_header.IsMarked());
  // Live large objects are eagerly swept.
  if (Heap::From(GetHeap())->generational_gc_supported()) {
    EXPECT_TRUE(marked_large_header.IsMarked());
  } else {
    EXPECT_FALSE(marked_large_header.IsMarked());
  }

  // Wait for incremental sweeper to finish.
  GetPlatform().RunAllForegroundTasks();

  EXPECT_EQ(2u, g_destructor_callcount);

  if (Heap::From(GetHeap())->generational_gc_supported()) {
    EXPECT_TRUE(marked_normal_header.IsMarked());
    EXPECT_TRUE(marked_large_header.IsMarked());
  } else {
    EXPECT_FALSE(marked_normal_header.IsMarked());
    EXPECT_FALSE(marked_large_header.IsMarked());
  }

  FinishSweeping();
}

TEST_F(ConcurrentSweeperTest, SweepOnAllocationReturnEmptyPage) {
  PreciseGC();

  // First, allocate the full page of finalizable objects.
  const size_t objects_to_allocated =
      NormalPage::PayloadSize() /
      (sizeof(HeapObjectHeader) + sizeof(NormalFinalizable));
  auto* first_obj =
      MakeGarbageCollected<NormalFinalizable>(GetAllocationHandle());
  auto* finalizable_page =
      NormalPage::FromInnerAddress(&HeapBase::From(GetHeapHandle()), first_obj);
  for (size_t i = 1; i < objects_to_allocated; ++i) {
    MakeGarbageCollected<NormalFinalizable>(GetAllocationHandle());
  }

  // Then, allocate a new unfinalizable object on a fresh page. We do that so
  // that the sweeper on allocation doesn't allocate a new page.
  auto* non_finalizable =
      MakeGarbageCollected<NormalNonFinalizable>(GetAllocationHandle());
  auto* non_finalizable_page = NormalPage::FromInnerAddress(
      &HeapBase::From(GetHeapHandle()), non_finalizable);
  ASSERT_NE(finalizable_page, non_finalizable_page);

  // Start the GC without sweeping.
  static constexpr GCConfig config = {
      CollectionType::kMajor, StackState::kNoHeapPointers,
      GCConfig::MarkingType::kAtomic,
      GCConfig::SweepingType::kIncrementalAndConcurrent};
  Heap::From(GetHeap())->CollectGarbage(config);

  WaitForConcurrentSweeping();

  // Allocate and sweep.
  auto* allocated_after_sweeping =
      MakeGarbageCollected<NormalFinalizable>(GetAllocationHandle());
  // Check that the empty page of finalizable objects was returned.
  EXPECT_EQ(finalizable_page,
            NormalPage::FromInnerAddress(&HeapBase::From(GetHeapHandle()),
                                         allocated_after_sweeping));
}

}  // namespace internal
}  // namespace cppgc
```