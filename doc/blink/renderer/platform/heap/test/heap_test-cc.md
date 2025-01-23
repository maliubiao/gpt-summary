Response:
The user wants a summary of the functionality of the provided C++ code file, which is a test file for the Blink rendering engine's heap management. I need to identify the core purpose of the tests and highlight any connections to JavaScript, HTML, and CSS. I also need to look for logical reasoning that can be expressed with input/output examples, and common usage errors that the tests might be designed to catch. Finally, I need to explicitly state that this is part 1 of a 4-part request.

Here's a breakdown of the steps:

1. **Identify the main goal of the file:** The filename `heap_test.cc` strongly suggests it's for testing the heap management system in Blink.

2. **Analyze the included headers:**  Headers like `GarbageCollected.h`, `Visitor.h`, `heap_deque.h`, `heap_hash_map.h`, `cross_thread_persistent.h`, and `prefinalizer.h` confirm this. They indicate testing of garbage collection, different heap data structures, and cross-thread object persistence.

3. **Examine the test classes and methods:**  Look for `TEST_F` macros which define individual test cases. Note the kinds of operations being tested (allocation, deallocation, data structure manipulation, threading, etc.). Pay attention to tests that use `EXPECT_DEATH_IF_SUPPORTED`, as these likely test error conditions.

4. **Look for connections to web technologies:** While this is a low-level test file, consider how heap management relates to the lifecycle of JavaScript objects, DOM nodes (related to HTML), and style rules (related to CSS). Garbage collection in Blink directly affects how JavaScript objects are managed.

5. **Identify logical reasoning:**  Some tests might have clear input-output behavior, like testing the insertion and retrieval of elements in a hash map. Formulate simple examples.

6. **Find common usage errors:** Tests that use `EXPECT_DEATH_IF_SUPPORTED` often highlight potential programming errors, especially around memory management. Look for patterns.

7. **Summarize the functionality:**  Combine the findings into a concise description of what the test file does.

8. **Address the "part 1 of 4" requirement:** Make sure the summary explicitly mentions this.
这个文件 `blink/renderer/platform/heap/test/heap_test.cc` 是 Chromium Blink 引擎中用于测试堆（heap）管理功能的代码。它的主要目的是验证 Blink 的垃圾回收机制、堆数据结构以及相关工具的正确性和健壮性。

**以下是它的功能归纳：**

1. **基础垃圾回收测试:**  它包含了对基本垃圾回收功能的测试，例如对象的创建、追踪（tracing）、以及最终的回收（destruction）。
2. **堆数据结构测试:**  它测试了各种基于堆实现的集合数据结构，例如 `HeapVector` (堆向量)、`HeapDeque` (堆双端队列)、`HeapHashSet` (堆哈希集合)、`HeapHashMap` (堆哈希映射) 等。测试内容包括插入、删除、查找、迭代等基本操作，以及容量管理、内存占用等。
3. **跨线程持久化对象测试 (`CrossThreadPersistent`):**  测试了跨线程持久化对象的功能，确保对象可以在不同的线程之间安全访问和管理，并在合适的时机被清理。
4. **预终结器（Prefinalizer）测试:**  测试了预终结器机制，这是一种在垃圾回收真正发生之前执行特定清理逻辑的机制。测试了在预终结器执行期间的各种操作，特别是涉及到对象复活（resurrection）的情况，以及对堆数据结构进行操作的限制。
5. **线程安全测试:**  包含了多线程环境下的堆操作测试，例如并发地创建和销毁对象，验证堆管理的线程安全性。
6. **内存分配和管理测试:**  测试了内存分配失败的情况 (在 DCHECK 开启时)，以及对大型数据结构（如大型 `HeapHashMap` 和 `HeapVector`) 的分配能力。
7. **对象大小和内存占用测试:**  通过 `GetOverallObjectSize()` 等函数，测试了不同操作后堆的内存占用变化，用于验证内存管理的正确性。
8. **弱引用测试 (`WeakMember`):**  通过 `ThreadedWeaknessTester` 进行了弱引用相关的测试，验证了当被引用的对象被回收后，弱引用会自动失效。

**它与 javascript, html, css 的功能的关系：**

这个测试文件虽然不直接操作 JavaScript、HTML 或 CSS 的代码，但它测试的堆管理功能是 Blink 引擎运行这些高级功能的基础。

* **JavaScript:**  JavaScript 对象的生命周期由 Blink 的垃圾回收机制管理。这个文件测试的正是管理这些 JavaScript 对象（在 Blink 内部表示）的内存分配和回收机制。例如，当 JavaScript 创建一个对象时，Blink 会在堆上分配内存。当该对象不再被引用时，垃圾回收器会回收这部分内存。`heap_test.cc` 中的测试确保了这个过程的正确性。
    * **举例说明:**  测试中创建和销毁 `IntWrapper` 等对象，可以类比于 JavaScript 中创建和销毁普通对象。对 `HeapHashMap` 的测试可以关联到 JavaScript 中 `Map` 对象的实现，`HeapVector` 的测试可以关联到 JavaScript 中 `Array` 对象的实现。
* **HTML:**  HTML 文档的 DOM 树中的节点也是由 Blink 的堆管理的。每个 DOM 节点都是一个 C++ 对象，需要被正确地分配和回收。
    * **举例说明:**  虽然测试中没有直接创建 DOM 节点，但 `LinkedObject` 类可能模拟了 DOM 节点之间的引用关系。测试垃圾回收器如何处理这些相互引用的对象，对于确保 HTML 页面在不再需要时能够被完全清理至关重要。
* **CSS:**  CSS 样式规则以及计算后的样式信息也存储在 Blink 的堆上。
    * **举例说明:**  测试中对大型数据结构（如 `LargeHashMap` 和 `LargeVector`）的分配，可以关联到存储大量 CSS 规则或样式属性值的场景。

**逻辑推理的假设输入与输出举例：**

* **假设输入 (针对 `HashMapOfMembers` 测试):**  创建两个 `IntWrapper` 对象，值都为 1，分别命名为 `one` 和 `another_one`。将 `one` 作为键和值插入到 `HeapHashMap` 中。然后尝试将 `another_one` 作为键，`one` 作为值插入到同一个 `HeapHashMap` 中。
* **输出:**  `HeapHashMap` 的大小应该为 2，因为 `one` 和 `another_one` 是不同的对象，即使它们的值相同。测试会验证 `map->size()` 是否等于 2，并且 `map->Contains(one)` 和 `map->Contains(another_one)` 都返回 `true`。
* **逻辑推理:**  这个测试验证了 `HeapHashMap` 基于对象身份（指针地址）而非对象值进行键的区分。

**涉及用户或者编程常见的使用错误举例：**

* **忘记删除不再使用的对象引用 (导致内存泄漏):**  虽然 C++ 具有自动内存管理（通过垃圾回收），但在 Blink 这样的复杂系统中，不正确的对象引用管理仍然可能导致内存泄漏。测试中通过创建和销毁对象，并检查析构函数的调用次数 (`IntWrapper::destructor_calls_`) 来验证对象是否被正确回收，可以帮助发现这类问题。
* **在预终结器中进行不允许的操作:**  预终结器是在垃圾回收的特定阶段执行的，对它可以执行的操作有限制，例如不能导致新的内存分配来扩展某些数据结构。`PreFinalizerVectorBackingExpandForbidden` 和 `PreFinalizerHashTableBackingExpandForbidden` 这两个测试就是为了捕获在预终结器中尝试扩展 `HeapVector` 和 `HeapHashMap` 的 backing store 的错误行为。
    * **举例说明:**  程序员可能错误地在预终结器中调用 `vector_.push_back()` 或 `map_.insert()`，期望在对象即将被回收时添加一些清理信息。但是，这可能会干扰垃圾回收过程。这些测试会触发 `EXPECT_DEATH_IF_SUPPORTED`，表明这是一个不应该发生的错误。
* **跨线程访问已释放的对象:**  `ThreadedHeapTester` 测试了跨线程持久化对象，确保在对象被回收后，其他线程不能再访问它。这可以避免悬挂指针等问题。

**这是第1部分，共4部分，请归纳一下它的功能:**

总而言之，`blink/renderer/platform/heap/test/heap_test.cc` 的第 1 部分主要 **涵盖了 Blink 堆管理的核心功能测试**，包括基础的垃圾回收、各种堆数据结构的正确性、跨线程对象管理以及预终结器的行为。它通过各种单元测试来验证这些机制的正确性和健壮性，并尝试捕获常见的内存管理错误。这些测试对于确保 Blink 引擎的稳定性和性能至关重要，因为堆管理是其运行 JavaScript、处理 HTML 和 CSS 的基础。

### 提示词
```
这是目录为blink/renderer/platform/heap/test/heap_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "base/synchronization/lock.h"
#include "base/test/bind.h"
#include "base/test/scoped_feature_list.h"
#include "build/build_config.h"
#include "gin/public/v8_platform.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_deque.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_hash_counted_set.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_hash_map.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_hash_set.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_linked_hash_set.h"
#include "third_party/blink/renderer/platform/heap/cross_thread_persistent.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/heap_test_objects.h"
#include "third_party/blink/renderer/platform/heap/heap_test_platform.h"
#include "third_party/blink/renderer/platform/heap/heap_test_utilities.h"
#include "third_party/blink/renderer/platform/heap/prefinalizer.h"
#include "third_party/blink/renderer/platform/heap/self_keep_alive.h"
#include "third_party/blink/renderer/platform/heap/visitor.h"
#include "third_party/blink/renderer/platform/scheduler/public/non_main_thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/hash_traits.h"
#include "v8/include/cppgc/internal/api-constants.h"

namespace blink {

namespace {

class HeapTest : public TestSupportingGC {};

class HeapDeathTest : public TestSupportingGC {};

class IntWrapper : public GarbageCollected<IntWrapper> {
 public:
  virtual ~IntWrapper() {
    destructor_calls_.fetch_add(1, std::memory_order_relaxed);
  }

  static std::atomic_int destructor_calls_;
  void Trace(Visitor* visitor) const {}

  int Value() const { return x_; }

  bool operator==(const IntWrapper& other) const {
    return other.Value() == Value();
  }

  unsigned GetHash() { return WTF::GetHash(x_); }

  IntWrapper(int x) : x_(x) {}

 private:
  IntWrapper() = delete;
  int x_;
};
std::atomic_int IntWrapper::destructor_calls_{0};

struct IntWrapperHashTraits : GenericHashTraits<IntWrapper> {
  static unsigned GetHash(const IntWrapper& key) {
    return WTF::HashInt(static_cast<uint32_t>(key.Value()));
  }
};

static_assert(WTF::IsTraceable<IntWrapper>::value,
              "IsTraceable<> template failed to recognize trace method.");
static_assert(WTF::IsTraceable<HeapVector<IntWrapper>>::value,
              "HeapVector<IntWrapper> must be traceable.");
static_assert(WTF::IsTraceable<HeapDeque<IntWrapper>>::value,
              "HeapDeque<IntWrapper> must be traceable.");
static_assert(
    WTF::IsTraceable<HeapHashSet<IntWrapper, IntWrapperHashTraits>>::value,
    "HeapHashSet<IntWrapper> must be traceable.");
static_assert(WTF::IsTraceable<HeapHashMap<int, Member<IntWrapper>>>::value,
              "HeapHashMap<int, IntWrapper> must be traceable.");

}  // namespace

#if DCHECK_IS_ON()
// Following 3 tests check for allocation failures. These failures happen
// only when DCHECK is on.

namespace {
class PreFinalizerBackingShrinkForbidden final
    : public GarbageCollected<PreFinalizerBackingShrinkForbidden> {
  USING_PRE_FINALIZER(PreFinalizerBackingShrinkForbidden, Dispose);

 public:
  PreFinalizerBackingShrinkForbidden() {
    for (int i = 0; i < 32; ++i) {
      vector_.push_back(MakeGarbageCollected<IntWrapper>(i));
    }
    EXPECT_LT(31ul, vector_.capacity());

    for (int i = 0; i < 32; ++i) {
      map_.insert(i + 1, MakeGarbageCollected<IntWrapper>(i + 1));
    }
    EXPECT_LT(31ul, map_.Capacity());
  }

  void Dispose() {
    // Remove all elements except one so that vector_ will try to shrink.
    for (int i = 1; i < 32; ++i) {
      vector_.pop_back();
    }
    // Check that vector_ hasn't shrunk.
    EXPECT_LT(31ul, vector_.capacity());
    // Just releasing the backing is allowed.
    vector_.clear();
    EXPECT_EQ(0ul, vector_.capacity());

    // Remove elements so that map_ will try to shrink.
    for (int i = 0; i < 32; ++i) {
      map_.erase(i + 1);
    }
    // Check that map_ hasn't shrunk.
    EXPECT_LT(31ul, map_.Capacity());
    // Just releasing the backing is allowed.
    map_.clear();
    EXPECT_EQ(0ul, map_.Capacity());
  }

  void Trace(Visitor* visitor) const {
    visitor->Trace(vector_);
    visitor->Trace(map_);
  }

 private:
  HeapVector<Member<IntWrapper>> vector_;
  HeapHashMap<int, Member<IntWrapper>> map_;
};
}  // namespace

TEST_F(HeapTest, PreFinalizerBackingShrinkForbidden) {
  MakeGarbageCollected<PreFinalizerBackingShrinkForbidden>();
  PreciselyCollectGarbage();
}

namespace {
class PreFinalizerVectorBackingExpandForbidden final
    : public GarbageCollected<PreFinalizerVectorBackingExpandForbidden> {
  USING_PRE_FINALIZER(PreFinalizerVectorBackingExpandForbidden, Dispose);

 public:
  PreFinalizerVectorBackingExpandForbidden() {
    vector_.push_back(MakeGarbageCollected<IntWrapper>(1));
  }

  void Dispose() { EXPECT_DEATH_IF_SUPPORTED(Test(), ""); }

  void Test() {
    // vector_'s backing will need to expand.
    for (int i = 0; i < 32; ++i) {
      vector_.push_back(nullptr);
    }
  }

  void Trace(Visitor* visitor) const { visitor->Trace(vector_); }

 private:
  HeapVector<Member<IntWrapper>> vector_;
};
}  // namespace

TEST_F(HeapDeathTest, PreFinalizerVectorBackingExpandForbidden) {
  MakeGarbageCollected<PreFinalizerVectorBackingExpandForbidden>();
  TestSupportingGC::PreciselyCollectGarbage();
}

namespace {
class PreFinalizerHashTableBackingExpandForbidden final
    : public GarbageCollected<PreFinalizerHashTableBackingExpandForbidden> {
  USING_PRE_FINALIZER(PreFinalizerHashTableBackingExpandForbidden, Dispose);

 public:
  PreFinalizerHashTableBackingExpandForbidden() {
    map_.insert(123, MakeGarbageCollected<IntWrapper>(123));
  }

  void Dispose() { EXPECT_DEATH_IF_SUPPORTED(Test(), ""); }

  void Test() {
    // map_'s backing will need to expand.
    for (int i = 1; i < 32; ++i) {
      map_.insert(i, nullptr);
    }
  }

  void Trace(Visitor* visitor) const { visitor->Trace(map_); }

 private:
  HeapHashMap<int, Member<IntWrapper>> map_;
};
}  // namespace

TEST_F(HeapDeathTest, PreFinalizerHashTableBackingExpandForbidden) {
  MakeGarbageCollected<PreFinalizerHashTableBackingExpandForbidden>();
  TestSupportingGC::PreciselyCollectGarbage();
}

namespace {
class HeapTestResurrectingPreFinalizer
    : public GarbageCollected<HeapTestResurrectingPreFinalizer> {
  USING_PRE_FINALIZER(HeapTestResurrectingPreFinalizer, Dispose);

 public:
  enum TestType {
    kHeapVectorMember,
    kHeapHashSetMember,
    kHeapHashSetWeakMember
  };

  class GlobalStorage : public GarbageCollected<GlobalStorage> {
   public:
    GlobalStorage() {
      // Reserve storage upfront to avoid allocations during pre-finalizer
      // insertion.
      vector_member.reserve(32);
      hash_set_member.ReserveCapacityForSize(32);
      hash_set_weak_member.ReserveCapacityForSize(32);
    }

    void Trace(Visitor* visitor) const {
      visitor->Trace(vector_member);
      visitor->Trace(hash_set_member);
      visitor->Trace(hash_set_weak_member);
    }

    HeapVector<Member<LinkedObject>> vector_member;
    HeapHashSet<Member<LinkedObject>> hash_set_member;
    HeapHashSet<WeakMember<LinkedObject>> hash_set_weak_member;
  };

  HeapTestResurrectingPreFinalizer(TestType test_type,
                                   GlobalStorage* storage,
                                   LinkedObject* object_that_dies)
      : test_type_(test_type),
        storage_(storage),
        object_that_dies_(object_that_dies) {}

  void Trace(Visitor* visitor) const {
    visitor->Trace(storage_);
    visitor->Trace(object_that_dies_);
  }

 private:
  void Dispose() { EXPECT_DEATH_IF_SUPPORTED(Test(), ""); }

  void Test() {
    switch (test_type_) {
      case TestType::kHeapVectorMember:
        storage_->vector_member.push_back(object_that_dies_);
        break;
      case TestType::kHeapHashSetMember:
        storage_->hash_set_member.insert(object_that_dies_);
        break;
      case TestType::kHeapHashSetWeakMember:
        storage_->hash_set_weak_member.insert(object_that_dies_);
        break;
    }
  }

  TestType test_type_;
  Member<GlobalStorage> storage_;
  Member<LinkedObject> object_that_dies_;
};
}  // namespace

TEST_F(HeapDeathTest, DiesOnResurrectedHeapVectorMember) {
  Persistent<HeapTestResurrectingPreFinalizer::GlobalStorage> storage(
      MakeGarbageCollected<HeapTestResurrectingPreFinalizer::GlobalStorage>());
  MakeGarbageCollected<HeapTestResurrectingPreFinalizer>(
      HeapTestResurrectingPreFinalizer::kHeapVectorMember, storage.Get(),
      MakeGarbageCollected<LinkedObject>());
  TestSupportingGC::PreciselyCollectGarbage();
}

TEST_F(HeapDeathTest, DiesOnResurrectedHeapHashSetMember) {
  Persistent<HeapTestResurrectingPreFinalizer::GlobalStorage> storage(
      MakeGarbageCollected<HeapTestResurrectingPreFinalizer::GlobalStorage>());
  MakeGarbageCollected<HeapTestResurrectingPreFinalizer>(
      HeapTestResurrectingPreFinalizer::kHeapHashSetMember, storage.Get(),
      MakeGarbageCollected<LinkedObject>());
  TestSupportingGC::PreciselyCollectGarbage();
}

TEST_F(HeapDeathTest, DiesOnResurrectedHeapHashSetWeakMember) {
  Persistent<HeapTestResurrectingPreFinalizer::GlobalStorage> storage(
      MakeGarbageCollected<HeapTestResurrectingPreFinalizer::GlobalStorage>());
  MakeGarbageCollected<HeapTestResurrectingPreFinalizer>(
      HeapTestResurrectingPreFinalizer::kHeapHashSetWeakMember, storage.Get(),
      MakeGarbageCollected<LinkedObject>());
  TestSupportingGC::PreciselyCollectGarbage();
}
#endif  // DCHECK_IS_ON()

namespace {
class ThreadedTesterBase {
 protected:
  static void Test(ThreadedTesterBase* tester) {
    HeapTestingPlatformAdapter platform_for_threads(gin::V8Platform::Get());
    std::unique_ptr<NonMainThread> threads[kNumberOfThreads];
    for (auto& thread : threads) {
      thread = NonMainThread::CreateThread(
          ThreadCreationParams(ThreadType::kTestThread)
              .SetThreadNameForTest("blink gc testing thread"));
      PostCrossThreadTask(
          *thread->GetTaskRunner(), FROM_HERE,
          CrossThreadBindOnce(ThreadFunc, CrossThreadUnretained(tester),
                              CrossThreadUnretained(&platform_for_threads)));
    }
    tester->done_.Wait();
    delete tester;
  }

  virtual void RunThread() = 0;

 protected:
  static const int kNumberOfThreads = 10;
  static const int kGcPerThread = 5;
  static const int kNumberOfAllocations = 50;

  virtual ~ThreadedTesterBase() = default;

  inline bool Done() const {
    return gc_count_.load(std::memory_order_acquire) >=
           kNumberOfThreads * kGcPerThread;
  }

  std::atomic_int gc_count_{0};

 private:
  static void ThreadFunc(ThreadedTesterBase* tester, v8::Platform* platform) {
    ThreadState::AttachCurrentThreadForTesting(platform);
    tester->RunThread();
    ThreadState::DetachCurrentThread();
    if (!tester->threads_to_finish_.Decrement())
      tester->done_.Signal();
  }

  base::AtomicRefCount threads_to_finish_{kNumberOfThreads};
  base::WaitableEvent done_;
};

// Needed to give this variable a definition (the initializer above is only a
// declaration), so that subclasses can use it.
const int ThreadedTesterBase::kNumberOfThreads;

class ThreadedHeapTester : public ThreadedTesterBase {
 public:
  static void Test() { ThreadedTesterBase::Test(new ThreadedHeapTester); }

  ~ThreadedHeapTester() override {
    // Verify that the threads cleared their CTPs when
    // terminating, preventing access to a finalized heap.
    for (auto& global_int_wrapper : cross_persistents_) {
      DCHECK(global_int_wrapper.get());
      EXPECT_FALSE(global_int_wrapper.get()->Get());
    }
  }

 protected:
  using GlobalIntWrapperPersistent = CrossThreadPersistent<IntWrapper>;

  base::Lock lock_;
  Vector<std::unique_ptr<GlobalIntWrapperPersistent>> cross_persistents_;

  std::unique_ptr<GlobalIntWrapperPersistent> CreateGlobalPersistent(
      int value) {
    return std::make_unique<GlobalIntWrapperPersistent>(
        MakeGarbageCollected<IntWrapper>(value));
  }

  void AddGlobalPersistent() {
    base::AutoLock lock(lock_);
    cross_persistents_.push_back(CreateGlobalPersistent(0x2a2a2a2a));
  }

  void RunThread() override {
    // Add a cross-thread persistent from this thread; the test object
    // verifies that it will have been cleared out after the threads
    // have all detached, running their termination GCs while doing so.
    AddGlobalPersistent();

    int gc_count = 0;
    while (!Done()) {
      {
        Persistent<IntWrapper> wrapper;

        std::unique_ptr<GlobalIntWrapperPersistent> global_persistent =
            CreateGlobalPersistent(0x0ed0cabb);

        for (int i = 0; i < kNumberOfAllocations; i++) {
          wrapper = MakeGarbageCollected<IntWrapper>(0x0bbac0de);
          if (!(i % 10)) {
            global_persistent = CreateGlobalPersistent(0x0ed0cabb);
          }
          test::YieldCurrentThread();
        }

        if (gc_count < kGcPerThread) {
          TestSupportingGC::PreciselyCollectGarbage();
          gc_count++;
          gc_count_.fetch_add(1, std::memory_order_release);
        }

        TestSupportingGC::PreciselyCollectGarbage();
        EXPECT_EQ(wrapper->Value(), 0x0bbac0de);
        EXPECT_EQ((*global_persistent)->Value(), 0x0ed0cabb);
      }
      test::YieldCurrentThread();
    }
  }
};
}  // namespace

TEST_F(HeapTest, Threading) {
  ThreadedHeapTester::Test();
}

namespace {
class ThreadMarker {
  DISALLOW_NEW();

 public:
  ThreadMarker() : creating_thread_(reinterpret_cast<ThreadState*>(0)) {}
  explicit ThreadMarker(unsigned i)
      : creating_thread_(ThreadState::Current()), num_(i) {}
  explicit ThreadMarker(WTF::HashTableDeletedValueType deleted)
      : creating_thread_(reinterpret_cast<ThreadState*>(-1)) {}
  ~ThreadMarker() {
    EXPECT_TRUE((creating_thread_ == ThreadState::Current()) ||
                (creating_thread_ == reinterpret_cast<ThreadState*>(0)) ||
                (creating_thread_ == reinterpret_cast<ThreadState*>(-1)));
  }
  bool IsHashTableDeletedValue() const {
    return creating_thread_ == reinterpret_cast<ThreadState*>(-1);
  }
  bool operator==(const ThreadMarker& other) const {
    return other.creating_thread_ == creating_thread_ && other.num_ == num_;
  }
  ThreadState* creating_thread_;
  unsigned num_ = 0;
};
}  // namespace

}  // namespace blink

namespace WTF {

// ThreadMarkerHash is the default hash for ThreadMarker
template <>
struct HashTraits<blink::ThreadMarker>
    : SimpleClassHashTraits<blink::ThreadMarker> {
  static unsigned GetHash(const blink::ThreadMarker& key) {
    return static_cast<unsigned>(
        reinterpret_cast<uintptr_t>(key.creating_thread_) + key.num_);
  }
  static constexpr bool kSafeToCompareToEmptyOrDeleted = false;
};

}  // namespace WTF

namespace blink {

namespace {
class ThreadedWeaknessTester : public ThreadedTesterBase {
 public:
  static void Test() { ThreadedTesterBase::Test(new ThreadedWeaknessTester); }

 private:
  void RunThread() override {
    int gc_count = 0;
    while (!Done()) {
      {
        Persistent<HeapHashMap<ThreadMarker, WeakMember<IntWrapper>>> weak_map =
            MakeGarbageCollected<
                HeapHashMap<ThreadMarker, WeakMember<IntWrapper>>>();

        for (int i = 0; i < kNumberOfAllocations; i++) {
          weak_map->insert(ThreadMarker(i),
                           MakeGarbageCollected<IntWrapper>(0));
          test::YieldCurrentThread();
        }

        if (gc_count < kGcPerThread) {
          TestSupportingGC::PreciselyCollectGarbage();
          gc_count++;
          gc_count_.fetch_add(1, std::memory_order_release);
        }

        TestSupportingGC::PreciselyCollectGarbage();
        EXPECT_TRUE(weak_map->empty());
      }
      test::YieldCurrentThread();
    }
  }
};
}  // namespace

TEST_F(HeapTest, ThreadedWeakness) {
  ThreadedWeaknessTester::Test();
}

namespace {
class ThreadPersistentHeapTester : public ThreadedTesterBase {
 public:
  static void Test() {
    ThreadedTesterBase::Test(new ThreadPersistentHeapTester);
  }

 protected:
  class Local final : public GarbageCollected<Local> {
   public:
    Local() = default;

    void Trace(Visitor* visitor) const {}
  };

  class PersistentChain;

  class RefCountedChain : public RefCounted<RefCountedChain> {
   public:
    static RefCountedChain* Create(int count) {
      return new RefCountedChain(count);
    }

   private:
    explicit RefCountedChain(int count) {
      if (count > 0) {
        --count;
        persistent_chain_ = MakeGarbageCollected<PersistentChain>(count);
      }
    }

    Persistent<PersistentChain> persistent_chain_;
  };

  class PersistentChain final : public GarbageCollected<PersistentChain> {
   public:
    explicit PersistentChain(int count) {
      ref_counted_chain_ = base::AdoptRef(RefCountedChain::Create(count));
    }

    void Trace(Visitor* visitor) const {}

   private:
    scoped_refptr<RefCountedChain> ref_counted_chain_;
  };

  void RunThread() override {
    MakeGarbageCollected<PersistentChain>(100);

    // Upon thread detach, GCs will run until all persistents have been
    // released. We verify that the draining of persistents proceeds
    // as expected by dropping one Persistent<> per GC until there
    // are none left.
  }
};
}  // namespace

TEST_F(HeapTest, ThreadPersistent) {
  ThreadPersistentHeapTester::Test();
}

namespace {
size_t GetOverallObjectSize() {
  return ThreadState::Current()
      ->cpp_heap()
      .CollectStatistics(cppgc::HeapStatistics::DetailLevel::kDetailed)
      .used_size_bytes;
}
}  // namespace

TEST_F(HeapTest, HashMapOfMembers) {
  ClearOutOldGarbage();
  IntWrapper::destructor_calls_ = 0;
  size_t initial_object_payload_size = GetOverallObjectSize();
  {
    typedef HeapHashMap<Member<IntWrapper>, Member<IntWrapper>>
        HeapObjectIdentityMap;

    Persistent<HeapObjectIdentityMap> map =
        MakeGarbageCollected<HeapObjectIdentityMap>();

    map->clear();
    size_t after_set_was_created = GetOverallObjectSize();
    EXPECT_GT(after_set_was_created, initial_object_payload_size);

    PreciselyCollectGarbage();
    size_t after_gc = GetOverallObjectSize();
    EXPECT_EQ(after_gc, after_set_was_created);

    // If the additions below cause garbage collections, these
    // pointers should be found by conservative stack scanning.
    auto* one(MakeGarbageCollected<IntWrapper>(1));
    auto* another_one(MakeGarbageCollected<IntWrapper>(1));

    map->insert(one, one);

    size_t after_one_add = GetOverallObjectSize();
    EXPECT_GT(after_one_add, after_gc);

    HeapObjectIdentityMap::iterator it(map->begin());
    HeapObjectIdentityMap::iterator it2(map->begin());
    ++it;
    ++it2;

    map->insert(another_one, one);

    // The addition above can cause an allocation of a new
    // backing store. We therefore garbage collect before
    // taking the heap stats in order to get rid of the old
    // backing store. We make sure to not use conservative
    // stack scanning as that could find a pointer to the
    // old backing.
    PreciselyCollectGarbage();
    size_t after_add_and_gc = GetOverallObjectSize();
    EXPECT_GE(after_add_and_gc, after_one_add);

    EXPECT_EQ(map->size(), 2u);  // Two different wrappings of '1' are distinct.

    PreciselyCollectGarbage();
    EXPECT_TRUE(map->Contains(one));
    EXPECT_TRUE(map->Contains(another_one));

    IntWrapper* gotten(map->at(one));
    EXPECT_EQ(gotten->Value(), one->Value());
    EXPECT_EQ(gotten, one);

    size_t after_gc2 = GetOverallObjectSize();
    EXPECT_EQ(after_gc2, after_add_and_gc);

    IntWrapper* dozen = nullptr;

    for (int i = 1; i < 1000; i++) {  // 999 iterations.
      auto* i_wrapper(MakeGarbageCollected<IntWrapper>(i));
      auto* i_squared(MakeGarbageCollected<IntWrapper>(i * i));
      map->insert(i_wrapper, i_squared);
      if (i == 12)
        dozen = i_wrapper;
    }
    size_t after_adding1000 = GetOverallObjectSize();
    EXPECT_GT(after_adding1000, after_gc2);

    IntWrapper* gross(map->at(dozen));
    EXPECT_EQ(gross->Value(), 144);

    // This should clear out any junk backings created by all the adds.
    PreciselyCollectGarbage();
    size_t after_gc3 = GetOverallObjectSize();
    EXPECT_LE(after_gc3, after_adding1000);
  }

  PreciselyCollectGarbage();
  // The objects 'one', anotherOne, and the 999 other pairs.
  EXPECT_EQ(IntWrapper::destructor_calls_, 2000);
  size_t after_gc4 = GetOverallObjectSize();
  EXPECT_EQ(after_gc4, initial_object_payload_size);
}

namespace {

static constexpr size_t kLargeObjectSize = size_t{1} << 27;

}  // namespace

// This test often fails on Android (https://crbug.com/843032).
// We run out of memory on Android devices because ReserveCapacityForSize
// actually allocates a much larger backing than specified (in this case 400MB).
#if BUILDFLAG(IS_ANDROID)
#define MAYBE_LargeHashMap DISABLED_LargeHashMap
#else
#define MAYBE_LargeHashMap LargeHashMap
#endif
TEST_F(HeapTest, MAYBE_LargeHashMap) {
  // Regression test: https://crbug.com/597953
  //
  // Try to allocate a HashTable larger than kLargeObjectSize.

  ClearOutOldGarbage();
  wtf_size_t size = kLargeObjectSize /
                    sizeof(HeapHashMap<int, Member<IntWrapper>>::ValueType);
  Persistent<HeapHashMap<int, Member<IntWrapper>>> map =
      MakeGarbageCollected<HeapHashMap<int, Member<IntWrapper>>>();
  map->ReserveCapacityForSize(size);
  EXPECT_LE(size, map->Capacity());
}

TEST_F(HeapTest, LargeVector) {
  // Regression test: https://crbug.com/597953
  //
  // Try to allocate a HeapVector larger than kLargeObjectSize.

  ClearOutOldGarbage();

  const wtf_size_t size = kLargeObjectSize / sizeof(Member<IntWrapper>);
  Persistent<HeapVector<Member<IntWrapper>>> vector =
      MakeGarbageCollected<HeapVector<Member<IntWrapper>>>(size);
  EXPECT_LE(size, vector->capacity());
}

TEST_F(HeapTest, HeapVectorFilledWithValue) {
  auto* val = MakeGarbageCollected<IntWrapper>(1);
  HeapVector<Member<IntWrapper>> vector(10, val);
  EXPECT_EQ(10u, vector.size());
  for (wtf_size_t i = 0; i < vector.size(); i++)
    EXPECT_EQ(val, vector[i]);
}

TEST_F(HeapTest, HeapVectorWithInlineCapacity) {
  auto* one = MakeGarbageCollected<IntWrapper>(1);
  auto* two = MakeGarbageCollected<IntWrapper>(2);
  auto* three = MakeGarbageCollected<IntWrapper>(3);
  auto* four = MakeGarbageCollected<IntWrapper>(4);
  auto* five = MakeGarbageCollected<IntWrapper>(5);
  auto* six = MakeGarbageCollected<IntWrapper>(6);
  {
    HeapVector<Member<IntWrapper>, 2> vector;
    vector.push_back(one);
    vector.push_back(two);
    ConservativelyCollectGarbage();
    EXPECT_TRUE(vector.Contains(one));
    EXPECT_TRUE(vector.Contains(two));

    vector.push_back(three);
    vector.push_back(four);
    ConservativelyCollectGarbage();
    EXPECT_TRUE(vector.Contains(one));
    EXPECT_TRUE(vector.Contains(two));
    EXPECT_TRUE(vector.Contains(three));
    EXPECT_TRUE(vector.Contains(four));

    vector.Shrink(1);
    ConservativelyCollectGarbage();
    EXPECT_TRUE(vector.Contains(one));
    EXPECT_FALSE(vector.Contains(two));
    EXPECT_FALSE(vector.Contains(three));
    EXPECT_FALSE(vector.Contains(four));
  }
  {
    HeapVector<Member<IntWrapper>, 2> vector1;
    HeapVector<Member<IntWrapper>, 2> vector2;

    vector1.push_back(one);
    vector2.push_back(two);
    vector1.swap(vector2);
    ConservativelyCollectGarbage();
    EXPECT_TRUE(vector1.Contains(two));
    EXPECT_TRUE(vector2.Contains(one));
  }
  {
    HeapVector<Member<IntWrapper>, 2> vector1;
    HeapVector<Member<IntWrapper>, 2> vector2;

    vector1.push_back(one);
    vector1.push_back(two);
    vector2.push_back(three);
    vector2.push_back(four);
    vector2.push_back(five);
    vector2.push_back(six);
    vector1.swap(vector2);
    ConservativelyCollectGarbage();
    EXPECT_TRUE(vector1.Contains(three));
    EXPECT_TRUE(vector1.Contains(four));
    EXPECT_TRUE(vector1.Contains(five));
    EXPECT_TRUE(vector1.Contains(six));
    EXPECT_TRUE(vector2.Contains(one));
    EXPECT_TRUE(vector2.Contains(two));
  }
}

TEST_F(HeapTest, HeapVectorShrinkCapacity) {
  ClearOutOldGarbage();
  HeapVector<Member<IntWrapper>> vector1;
  HeapVector<Member<IntWrapper>> vector2;
  vector1.reserve(96);
  EXPECT_LE(96u, vector1.capacity());
  vector1.Grow(vector1.capacity());

  // Assumes none was allocated just after a vector backing of vector1.
  vector1.Shrink(56);
  vector1.shrink_to_fit();
  EXPECT_GT(96u, vector1.capacity());

  vector2.reserve(20);
  // Assumes another vector backing was allocated just after the vector
  // backing of vector1.
  vector1.Shrink(10);
  vector1.shrink_to_fit();
  EXPECT_GT(56u, vector1.capacity());

  vector1.Grow(192);
  EXPECT_LE(192u, vector1.capacity());
}

TEST_F(HeapTest, HeapVectorShrinkInlineCapacity) {
  ClearOutOldGarbage();
  const size_t kInlineCapacity = 64;
  HeapVector<Member<IntWrapper>, kInlineCapacity> vector1;
  vector1.reserve(128);
  EXPECT_LE(128u, vector1.capacity());
  vector1.Grow(vector1.capacity());

  // Shrink the external buffer.
  vector1.Shrink(90);
  vector1.shrink_to_fit();
  EXPECT_GT(128u, vector1.capacity());

// TODO(sof): if the ASan support for 'contiguous containers' is enabled,
// Vector inline buffers are disabled; that constraint should be attempted
// removed, but until that time, disable testing handling of capacities
// of inline buffers.
#if !defined(ANNOTATE_CONTIGUOUS_CONTAINER)
  // Shrinking switches the buffer from the external one to the inline one.
  vector1.Shrink(kInlineCapacity - 1);
  vector1.shrink_to_fit();
  EXPECT_EQ(kInlineCapacity, vector1.capacity());

  // Try to shrink the inline buffer.
  vector1.Shrink(1);
  vector1.shrink_to_fit();
  EXPECT_EQ(kInlineCapacity, vector1.capacity());
#endif
}

namespace {
typedef std::pair<Member<IntWrapper>, int> PairWrappedUnwrapped;
typedef std::pair<int, Member<IntWrapper>> PairUnwrappedWrapped;

class Container final : public GarbageCollected<Container> {
 public:
  HeapHashMap<Member<IntWrapper>, Member<IntWrapper>> map;
  HeapHashSet<Member<IntWrapper>> set;
  HeapHashSet<Member<IntWrapper>> set2;
  HeapHashCountedSet<Member<IntWrapper>> set3;
  HeapVector<Member<IntWrapper>, 2> vector;
  HeapVector<PairWrappedUnwrapped, 2> vector_wu;
  HeapVector<PairUnwrappedWrapped, 2> vector_uw;
  HeapDeque<Member<IntWrapper>> deque;
  void Trace(Visitor* visitor) const {
    visitor->Trace(map);
    visitor->Trace(set);
    visitor->Trace(set2);
    visitor->Trace(set3);
    visitor->Trace(vector);
    visitor->Trace(vector_wu);
    visitor->Trace(vector_uw);
    visitor->Trace(deque);
  }
};
}  // namespace

TEST_F(HeapTest, HeapVectorOnStackLargeObjectPageSized) {
  static constexpr size_t kLargeObjectSizeThreshold =
      cppgc::internal::api_constants::kLargeObjectSizeThreshold;
  ClearOutOldGarbage();
  using Container = HeapVector<Member<IntWrapper>>;
  Container vector;
  wtf_size_t size = (kLargeObjectSizeThreshold + sizeof(Container::ValueType)) /
                    sizeof(Container::ValueType);
  vector.reserve(size);
  for (unsigned i = 0; i < size; ++i)
    vector.push_back(MakeGarbageCollected<IntWrapper>(i));
  ConservativelyCollectGarbage();
}

namespace {
template <typename T, typename U>
bool DequeContains(HeapDeque<T>& deque, U u) {
  typedef typename HeapDeque<T>::iterator iterator;
  for (iterator it = deque.begin(); it != deque.end(); ++it) {
    if (*it == u)
      return true;
  }
  return false;
}
}  // namespace

TEST_F(HeapTest, HeapCollectionTypes) {
  IntWrapper::destructor_calls_ = 0;

  typedef HeapHashMap<Member<IntWrapper>, Member<IntWrapper>> MemberMember;
  typedef HeapHashMap<Member<IntWrapper>, int> MemberPrimitive;
  typedef HeapHashMap<int, Member<IntWrapper>> PrimitiveMember;

  typedef HeapHashSet<Member<IntWrapper>> MemberSet;
  typedef HeapHashCountedSet<Member<IntWrapper>> MemberCountedSet;

  typedef HeapVector<Member<IntWrapper>, 2> MemberVector;
  typedef HeapDeque<Member<IntWrapper>> MemberDeque;

  typedef HeapVector<PairWrappedUnwrapped, 2> VectorWU;
  typedef HeapVector<PairUnwrappedWrapped, 2> VectorUW;

  Persistent<MemberMember> member_member = MakeGarbageCollected<MemberMember>();
  Persistent<MemberMember> member_member2 =
      MakeGarbageCollected<MemberMember>();
  Persistent<MemberMember> member_member3 =
      MakeGarbageCollected<MemberMember>();
  Persistent<MemberPrimitive> member_primitive =
      MakeGarbageCollected<MemberPrimitive>();
  Persistent<PrimitiveMember> primitive_member =
      MakeGarbageCollected<PrimitiveMember>();
  Persistent<MemberSet> set = MakeGarbageCollected<MemberSet>();
  Persistent<MemberSet> set2 = MakeGarbageCollected<MemberSet>();
  Persistent<MemberCountedSet> set3 = MakeGarbageCollected<MemberCountedSet>();
  Persistent<MemberVector> vector = MakeGarbageCollected<MemberVector>();
  Persistent<MemberVector> vector2 = MakeGarbageCollected<MemberVector>();
  Persistent<VectorWU> vector_wu = MakeGarbageCollected<VectorWU>();
  Persistent<VectorWU> vector_wu2 = MakeGarbageCollected<VectorWU>();
  Persistent<VectorUW> vector_uw = MakeGarbageCollected<VectorUW>();
  Persistent<VectorUW> vector_uw2 = MakeGarbageCollected<VectorUW>();
  Persistent<MemberDeque> deque = MakeGarbageCollected<MemberDeque>();
  Persistent<MemberDeque> deque2 = MakeGarbageCollected<MemberDeque>();
  Persistent<Container> container = MakeGarbageCollected<Container>();

  ClearOutOldGarbage();
  {
    Persistent<IntWrapper> one(MakeGarbageCollected<IntWrapper>(1));
    Persistent<IntWrapper> two(MakeGarbageCollected<IntWrapper>(2));
    Persistent<IntWrapper> one_b(MakeGarbageCollected<IntWrapper>(1));
    Persistent<IntWrapper> two_b(MakeGarbageCollected<IntWrapper>(2));
    Persistent<IntWrapper> one_c(MakeGarbageCollected<IntWrapper>(1));
    Persistent<IntWrapper> one_d(MakeGarbageCollected<IntWrapper>(1));
    Persistent<IntWrapper> one_e(MakeGarbageCollected<IntWrapper>(1));
    Persistent<IntWrapper> one_f(MakeGarbageCollected<IntWrapper>(1));
    {
      auto* three_b(MakeGarbageCollected<IntWrapper>(3));
      auto* three_c(MakeGarbageCollected<IntWrapper>(3));
      auto* three_d(MakeGarbageCollected<IntWrapper>(3));
      auto* three_e(MakeGarbageCollected<IntWrapper>(3));
      auto* three(MakeGarbageCollected<IntWrapper>(3));
      auto* four_b(MakeGarbageCollected<IntWrapper>(4));
      auto* four_c(MakeGarbageCollected<IntWrapper>(4));
      auto* four_d(MakeGarbageCollected<IntWrapper>(4));
      auto* four_e(MakeGarbageCollected<IntWrapper>(4));
      auto* four(MakeGarbageCollected<In
```