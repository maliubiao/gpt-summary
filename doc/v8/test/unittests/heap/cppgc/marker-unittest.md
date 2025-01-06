Response: Let's break down the thought process to analyze this C++ code and generate the summary and JavaScript examples.

1. **Understand the Goal:** The primary task is to understand the functionality of the `marker-unittest.cc` file within the `v8/test/unittests/heap/cppgc` directory. The key is to identify what aspects of garbage collection this unit test is verifying. The secondary goal is to relate this back to JavaScript's garbage collection behavior.

2. **High-Level Structure Analysis:**  The file name "marker-unittest.cc" immediately suggests it's testing the "marker" component of the `cppgc` (C++ garbage collector) within V8. The `#include` directives point to core `cppgc` headers like `marker.h`, `allocation.h`, `ephemeron-pair.h`, etc. This confirms the focus is on the marking phase of garbage collection. The presence of `testing/gtest/include/gtest/gtest.h` indicates this uses the Google Test framework for unit testing.

3. **Class-Level Analysis:**

   * **`MarkerTest`:**  This appears to be the main fixture for testing the `Marker` class. The `DoMarking` method suggests a way to trigger a marking cycle. `InitializeMarker` sets up the `Marker` object. The `ResetMarker` method is for cleanup.

   * **`GCed`:** This is a simple garbage-collected class with `Member` (strong) and `WeakMember` (weak) pointers to other `GCed` objects. The `Trace` method is crucial – it defines how the garbage collector should traverse the object graph.

   * **`GCedWithCallback`:** This class is designed to test scenarios where objects are being constructed *during* the garbage collection cycle. The callback allows interaction during object creation.

   * **`GCObliviousObjectStorage`:** This is a utility to deliberately hide pointers from the garbage collector for specific testing purposes, likely related to stack scanning.

   * **`SimpleObject` and `ObjectWithEphemeronPair`:** These classes are used to test the handling of `EphemeronPair`s, which are key-value pairs where the value is only kept alive if the key is reachable.

   * **`IncrementalMarkingTest`:**  This fixture specifically focuses on testing the *incremental* marking functionality of the garbage collector.

4. **Test Case Breakdown (Keyword Spotting):**  Read through each `TEST_F` function and identify the key aspect being tested:

   * **`PersistentIsMarked`:** Tests that persistently held objects are marked.
   * **`ReachableMemberIsMarked`:** Tests that objects reachable via strong members are marked.
   * **`UnreachableMemberIsNotMarked`:** Tests that unreachable objects are *not* marked.
   * **`ObjectReachableFromStackIsMarked`:** Tests marking of objects reachable from the stack.
   * **`ObjectReachableOnlyFromStackIsNotMarkedIfStackIsEmpty`:** Tests that stack-only reachable objects are not marked when the stack is considered empty.
   * **`WeakReferenceToUnreachableObjectIsCleared`:** Tests that weak references to unreachable objects are cleared.
   * **`WeakReferenceToReachableObjectIsNotCleared`:** Tests that weak references to reachable objects are kept alive.
   * **`DeepHierarchyIsMarked`:** Tests marking in deep object graphs.
   * **`NestedObjectsOnStackAreMarked`:** Tests marking with nested stack references.
   * **`InConstructionObjectIsEventuallyMarkedEmptyStack` / `NonEmptyStack` / `DifferentNonEmptyStack`:** Tests the handling of objects being constructed during marking.
   * **`SentinelNotClearedOnWeakPersistentHandling`:** Tests a specific behavior related to weak persistent handles and sentinels.
   * **`MarkerProcessesAllEphemeronPairs`:** Tests the correct processing of ephemeron pairs.
   * **`IncrementalMarkingTest` cases:** Focus on testing the steps and behavior of *incremental* marking.

5. **Synthesize the Functionality:** Based on the class structure and the test cases, the core functionality of `marker-unittest.cc` is to rigorously test the **marking phase** of the `cppgc` garbage collector. This includes:

   * **Reachability:** Ensuring that reachable objects (via persistent handles, strong members, and the stack) are correctly identified and marked.
   * **Unreachability:** Ensuring that unreachable objects are *not* marked.
   * **Weak References:** Verifying the correct handling of weak references (being cleared when the referent is unreachable, staying alive when reachable).
   * **Stack Scanning:** Testing the garbage collector's ability to find live objects on the stack.
   * **Incremental Marking:** Testing the ability to perform marking in smaller steps without requiring a full stop-the-world pause.
   * **In-Construction Objects:** Handling objects that are being allocated and initialized during the marking process.
   * **Ephemeron Pairs:**  Specifically testing the behavior of ephemeron pairs.

6. **Relate to JavaScript Garbage Collection:**  JavaScript's garbage collection also relies on marking (typically mark-and-sweep or variations thereof). The core concepts are the same: identifying reachable objects to keep them alive. The differences lie in the implementation details and the dynamic nature of JavaScript.

7. **Craft JavaScript Examples:**  Translate the C++ test scenarios into equivalent JavaScript examples. Focus on demonstrating the same concepts:

   * **Reachability:**  Show how assigning an object to a variable keeps it alive.
   * **Unreachability:** Show how removing all references allows the garbage collector to reclaim the object.
   * **Weak References:** Use `WeakRef` to demonstrate the behavior of weak references.
   * **Callbacks during allocation (less direct equivalent):**  While C++ allows more direct manipulation during construction, in JavaScript, you can illustrate the idea with functions that create and then immediately use objects.
   * **Ephemerons (Closest analogy):** Explain how `WeakMap` behaves similarly to ephemerons.

8. **Refine and Organize:**  Structure the summary and examples clearly. Use headings, bullet points, and code blocks for readability. Explain the connection between the C++ code and the JavaScript examples. Ensure the language is precise and avoids jargon where possible. For instance, explain "persistent handle" as a stable reference.

**(Self-Correction during the process):**

* **Initial thought:**  Focus solely on the marking algorithm.
* **Correction:** Realize the unit tests also cover aspects like weak references and handling objects under construction, which are integral parts of the overall garbage collection process.
* **Initial thought:** Directly translate C++ memory management concepts to JavaScript.
* **Correction:**  Recognize the abstraction layer in JavaScript and use more idiomatic JavaScript constructs (like `WeakRef` and `WeakMap`) to illustrate the *concepts* being tested.
* **Initial thought:** Provide very detailed explanations of the C++ code.
* **Correction:**  Focus the explanation on the *purpose* of the tests and how they relate to GC principles, rather than getting bogged down in the low-level C++ implementation details. The target audience is likely looking for a high-level understanding and the connection to JavaScript.
这个C++源代码文件 `marker-unittest.cc` 是 V8 引擎中 `cppgc`（C++ Garbage Collection）库的单元测试文件，专门用来测试 **标记 (marking)** 阶段的功能。

**核心功能归纳：**

这个文件中的测试用例旨在验证 `cppgc::internal::Marker` 类的各种行为，确保垃圾回收器的标记阶段能够正确识别和标记活动对象，并处理各种边界情况，例如：

1. **基本标记功能:**
   - 验证持久 (Persistent) 对象会被标记。
   - 验证通过强引用 (Member) 可达的对象会被标记。
   - 验证不可达的对象不会被标记。
   - 验证从栈上可达的对象会被标记。
   - 验证仅从栈上可达且栈被视为空的对象不会被标记。

2. **弱引用处理:**
   - 验证指向不可达对象的弱引用 (WeakPersistent, WeakMember) 会被清除。
   - 验证指向可达对象的弱引用不会被清除。

3. **深度和嵌套对象图的标记:**
   - 验证在深层对象继承关系中，所有可达对象都能被正确标记。
   - 验证栈上的嵌套对象也能被正确标记。

4. **对象构造期间的标记:**
   - 验证在对象构造过程中被引用的对象最终会被标记，即使在构造函数执行期间发生垃圾回收。这包括栈为空和非空的情况。

5. **增量标记:**
   - 验证增量标记的步骤能够逐步标记对象图。
   - 验证增量标记能在分配过程中进行。
   - 验证增量标记最终会完成，所有可达对象都会被标记。

6. **特殊情况处理:**
   - 验证在处理弱持久句柄时，哨兵值不会被错误清除。
   - 验证能正确处理 EphemeronPair（瞬态对），确保当 key 被标记为 live 时，value 也能被访问到。

**与 JavaScript 的功能关系及 JavaScript 示例:**

虽然 `cppgc` 是 V8 引擎的 C++ 实现部分，但其核心功能直接影响着 JavaScript 的垃圾回收行为。 JavaScript 的垃圾回收机制依赖于标记清除 (mark-and-sweep) 或其变种算法。 `marker-unittest.cc` 中测试的正是标记阶段的关键逻辑。

**JavaScript 示例说明:**

以下 JavaScript 示例对应了 `marker-unittest.cc` 中测试的一些核心概念：

**1. 可达性 (Reachability):**

```javascript
// 对应 PersistentIsMarked, ReachableMemberIsMarked
let obj1 = {}; // obj1 是一个根对象，相当于 Persistent
let obj2 = { child: obj1 }; // obj2 通过强引用持有 obj1

// 在垃圾回收的标记阶段，obj1 和 obj2 都会被标记为活动对象，因为它们是可达的。
```

**2. 不可达性 (Unreachability):**

```javascript
// 对应 UnreachableMemberIsNotMarked
let obj = { data: {} };
obj = null; // 断开所有外部引用

// 在垃圾回收的标记阶段，原来 obj 指向的对象将不会被标记，因为没有任何根对象可以访问到它，最终会被回收。
```

**3. 弱引用 (Weak References):**

```javascript
// 对应 WeakReferenceToUnreachableObjectIsCleared, WeakReferenceToReachableObjectIsNotCleared
let weakRef = new WeakRef({});
let obj = weakRef.deref(); // 尝试获取弱引用指向的对象

if (obj) {
  // 对象仍然存在，因为还有其他强引用或者还未被垃圾回收。
  console.log("对象仍然存在");
} else {
  // 对象已经被垃圾回收。
  console.log("对象已经被回收");
}

// 示例：如果没有任何其他强引用指向 WeakRef 指向的对象，垃圾回收器可能会在未来的某个时刻回收该对象，
// 此时 weakRef.deref() 将返回 undefined。
```

**4. 增量垃圾回收 (Incremental Garbage Collection):**

尽管 `marker-unittest.cc` 测试的是 C++ 层的增量标记，JavaScript 引擎也常采用增量或并发垃圾回收技术来减少主线程的暂停时间。

```javascript
// JavaScript 引擎的增量垃圾回收通常是自动进行的，开发者无法直接控制。
// 但其核心思想与 C++ 层的增量标记类似：将标记工作分解为多个小步骤，
// 穿插在 JavaScript 代码执行之间，减少长时间的阻塞。
```

**总结:**

`marker-unittest.cc` 通过各种测试用例，确保了 `cppgc` 库的标记功能的正确性和健壮性。这直接保证了 V8 引擎在进行 JavaScript 垃圾回收时，能够准确地识别和保留活动对象，回收不再使用的内存，从而保证 JavaScript 代码的稳定运行和性能。 JavaScript 中类似的概念，如可达性、弱引用和增量回收，都与这个 C++ 单元测试中验证的核心逻辑密切相关。

Prompt: 
```
这是目录为v8/test/unittests/heap/cppgc/marker-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/cppgc/marker.h"

#include <memory>

#include "include/cppgc/allocation.h"
#include "include/cppgc/ephemeron-pair.h"
#include "include/cppgc/internal/pointer-policies.h"
#include "include/cppgc/member.h"
#include "include/cppgc/persistent.h"
#include "include/cppgc/trace-trait.h"
#include "src/heap/cppgc/heap-object-header.h"
#include "src/heap/cppgc/marking-visitor.h"
#include "src/heap/cppgc/object-allocator.h"
#include "src/heap/cppgc/stats-collector.h"
#include "test/unittests/heap/cppgc/tests.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace cppgc {
namespace internal {

namespace {
class MarkerTest : public testing::TestWithHeap {
 public:
  void DoMarking(StackState stack_state) {
    const MarkingConfig config = {CollectionType::kMajor, stack_state};
    auto* heap = Heap::From(GetHeap());
    InitializeMarker(*heap, GetPlatformHandle().get(), config);
    marker_->FinishMarking(stack_state);
    // Pretend do finish sweeping as StatsCollector verifies that Notify*
    // methods are called in the right order.
    heap->stats_collector()->NotifySweepingCompleted(
        GCConfig::SweepingType::kAtomic);
  }

  void InitializeMarker(HeapBase& heap, cppgc::Platform* platform,
                        MarkingConfig config) {
    marker_ = std::make_unique<Marker>(heap, platform, config);
    marker_->StartMarking();
  }

  Marker* marker() const { return marker_.get(); }

  void ResetMarker() { marker_.reset(); }

 private:
  std::unique_ptr<Marker> marker_;
};

class GCed : public GarbageCollected<GCed> {
 public:
  void SetChild(GCed* child) { child_ = child; }
  void SetWeakChild(GCed* child) { weak_child_ = child; }
  GCed* child() const { return child_.Get(); }
  GCed* weak_child() const { return weak_child_.Get(); }
  void Trace(cppgc::Visitor* visitor) const {
    visitor->Trace(child_);
    visitor->Trace(weak_child_);
  }

 private:
  Member<GCed> child_;
  WeakMember<GCed> weak_child_;
};

template <typename T>
V8_NOINLINE T access(volatile const T& t) {
  return t;
}

}  // namespace

TEST_F(MarkerTest, PersistentIsMarked) {
  Persistent<GCed> object = MakeGarbageCollected<GCed>(GetAllocationHandle());
  HeapObjectHeader& header = HeapObjectHeader::FromObject(object);
  EXPECT_FALSE(header.IsMarked());
  DoMarking(StackState::kNoHeapPointers);
  EXPECT_TRUE(header.IsMarked());
}

TEST_F(MarkerTest, ReachableMemberIsMarked) {
  Persistent<GCed> parent = MakeGarbageCollected<GCed>(GetAllocationHandle());
  parent->SetChild(MakeGarbageCollected<GCed>(GetAllocationHandle()));
  HeapObjectHeader& header = HeapObjectHeader::FromObject(parent->child());
  EXPECT_FALSE(header.IsMarked());
  DoMarking(StackState::kNoHeapPointers);
  EXPECT_TRUE(header.IsMarked());
}

TEST_F(MarkerTest, UnreachableMemberIsNotMarked) {
  Member<GCed> object = MakeGarbageCollected<GCed>(GetAllocationHandle());
  HeapObjectHeader& header = HeapObjectHeader::FromObject(object);
  EXPECT_FALSE(header.IsMarked());
  DoMarking(StackState::kNoHeapPointers);
  EXPECT_FALSE(header.IsMarked());
}

TEST_F(MarkerTest, ObjectReachableFromStackIsMarked) {
  GCed* object = MakeGarbageCollected<GCed>(GetAllocationHandle());
  EXPECT_FALSE(HeapObjectHeader::FromObject(object).IsMarked());
  DoMarking(StackState::kMayContainHeapPointers);
  EXPECT_TRUE(HeapObjectHeader::FromObject(object).IsMarked());
  access(object);
}

TEST_F(MarkerTest, ObjectReachableOnlyFromStackIsNotMarkedIfStackIsEmpty) {
  GCed* object = MakeGarbageCollected<GCed>(GetAllocationHandle());
  HeapObjectHeader& header = HeapObjectHeader::FromObject(object);
  EXPECT_FALSE(header.IsMarked());
  DoMarking(StackState::kNoHeapPointers);
  EXPECT_FALSE(header.IsMarked());
  access(object);
}

TEST_F(MarkerTest, WeakReferenceToUnreachableObjectIsCleared) {
  {
    WeakPersistent<GCed> weak_object =
        MakeGarbageCollected<GCed>(GetAllocationHandle());
    EXPECT_TRUE(weak_object);
    DoMarking(StackState::kNoHeapPointers);
    EXPECT_FALSE(weak_object);
  }
  {
    Persistent<GCed> parent = MakeGarbageCollected<GCed>(GetAllocationHandle());
    parent->SetWeakChild(MakeGarbageCollected<GCed>(GetAllocationHandle()));
    EXPECT_TRUE(parent->weak_child());
    DoMarking(StackState::kNoHeapPointers);
    EXPECT_FALSE(parent->weak_child());
  }
}

TEST_F(MarkerTest, WeakReferenceToReachableObjectIsNotCleared) {
  // Reachable from Persistent
  {
    Persistent<GCed> object = MakeGarbageCollected<GCed>(GetAllocationHandle());
    WeakPersistent<GCed> weak_object(object);
    EXPECT_TRUE(weak_object);
    DoMarking(StackState::kNoHeapPointers);
    EXPECT_TRUE(weak_object);
  }
  {
    Persistent<GCed> object = MakeGarbageCollected<GCed>(GetAllocationHandle());
    Persistent<GCed> parent = MakeGarbageCollected<GCed>(GetAllocationHandle());
    parent->SetWeakChild(object);
    EXPECT_TRUE(parent->weak_child());
    DoMarking(StackState::kNoHeapPointers);
    EXPECT_TRUE(parent->weak_child());
  }
  // Reachable from Member
  {
    Persistent<GCed> parent = MakeGarbageCollected<GCed>(GetAllocationHandle());
    WeakPersistent<GCed> weak_object(
        MakeGarbageCollected<GCed>(GetAllocationHandle()));
    parent->SetChild(weak_object);
    EXPECT_TRUE(weak_object);
    DoMarking(StackState::kNoHeapPointers);
    EXPECT_TRUE(weak_object);
  }
  {
    Persistent<GCed> parent = MakeGarbageCollected<GCed>(GetAllocationHandle());
    parent->SetChild(MakeGarbageCollected<GCed>(GetAllocationHandle()));
    parent->SetWeakChild(parent->child());
    EXPECT_TRUE(parent->weak_child());
    DoMarking(StackState::kNoHeapPointers);
    EXPECT_TRUE(parent->weak_child());
  }
  // Reachable from stack
  {
    GCed* object = MakeGarbageCollected<GCed>(GetAllocationHandle());
    WeakPersistent<GCed> weak_object(object);
    EXPECT_TRUE(weak_object);
    DoMarking(StackState::kMayContainHeapPointers);
    EXPECT_TRUE(weak_object);
    access(object);
  }
  {
    GCed* object = MakeGarbageCollected<GCed>(GetAllocationHandle());
    Persistent<GCed> parent = MakeGarbageCollected<GCed>(GetAllocationHandle());
    parent->SetWeakChild(object);
    EXPECT_TRUE(parent->weak_child());
    DoMarking(StackState::kMayContainHeapPointers);
    EXPECT_TRUE(parent->weak_child());
    access(object);
  }
}

TEST_F(MarkerTest, DeepHierarchyIsMarked) {
  static constexpr int kHierarchyDepth = 10;
  Persistent<GCed> root = MakeGarbageCollected<GCed>(GetAllocationHandle());
  GCed* parent = root;
  for (int i = 0; i < kHierarchyDepth; ++i) {
    parent->SetChild(MakeGarbageCollected<GCed>(GetAllocationHandle()));
    parent->SetWeakChild(parent->child());
    parent = parent->child();
  }
  DoMarking(StackState::kNoHeapPointers);
  EXPECT_TRUE(HeapObjectHeader::FromObject(root).IsMarked());
  parent = root;
  for (int i = 0; i < kHierarchyDepth; ++i) {
    EXPECT_TRUE(HeapObjectHeader::FromObject(parent->child()).IsMarked());
    EXPECT_TRUE(parent->weak_child());
    parent = parent->child();
  }
}

TEST_F(MarkerTest, NestedObjectsOnStackAreMarked) {
  GCed* root = MakeGarbageCollected<GCed>(GetAllocationHandle());
  root->SetChild(MakeGarbageCollected<GCed>(GetAllocationHandle()));
  root->child()->SetChild(MakeGarbageCollected<GCed>(GetAllocationHandle()));
  DoMarking(StackState::kMayContainHeapPointers);
  EXPECT_TRUE(HeapObjectHeader::FromObject(root).IsMarked());
  EXPECT_TRUE(HeapObjectHeader::FromObject(root->child()).IsMarked());
  EXPECT_TRUE(HeapObjectHeader::FromObject(root->child()->child()).IsMarked());
}

namespace {

class GCedWithCallback : public GarbageCollected<GCedWithCallback> {
 public:
  template <typename Callback>
  explicit GCedWithCallback(Callback callback) {
    callback(this);
  }

  template <typename Callback>
  GCedWithCallback(Callback callback, GCed* gced) : gced_(gced) {
    callback(this);
  }

  void Trace(Visitor* visitor) const { visitor->Trace(gced_); }

  GCed* gced() const { return gced_; }

 private:
  Member<GCed> gced_;
};

}  // namespace

TEST_F(MarkerTest, InConstructionObjectIsEventuallyMarkedEmptyStack) {
  static const MarkingConfig config = {CollectionType::kMajor,
                                       StackState::kMayContainHeapPointers};
  InitializeMarker(*Heap::From(GetHeap()), GetPlatformHandle().get(), config);
  GCedWithCallback* object = MakeGarbageCollected<GCedWithCallback>(
      GetAllocationHandle(), [marker = marker()](GCedWithCallback* obj) {
        Member<GCedWithCallback> member(obj);
        marker->Visitor().Trace(member);
      });
  EXPECT_FALSE(HeapObjectHeader::FromObject(object).IsMarked());
  marker()->FinishMarking(StackState::kMayContainHeapPointers);
  EXPECT_TRUE(HeapObjectHeader::FromObject(object).IsMarked());
}

TEST_F(MarkerTest, InConstructionObjectIsEventuallyMarkedNonEmptyStack) {
  static const MarkingConfig config = {CollectionType::kMajor,
                                       StackState::kMayContainHeapPointers};
  InitializeMarker(*Heap::From(GetHeap()), GetPlatformHandle().get(), config);
  MakeGarbageCollected<GCedWithCallback>(
      GetAllocationHandle(), [marker = marker()](GCedWithCallback* obj) {
        Member<GCedWithCallback> member(obj);
        marker->Visitor().Trace(member);
        EXPECT_FALSE(HeapObjectHeader::FromObject(obj).IsMarked());
        marker->FinishMarking(StackState::kMayContainHeapPointers);
        EXPECT_TRUE(HeapObjectHeader::FromObject(obj).IsMarked());
      });
}

namespace {

// Storage that can be used to hide a pointer from the GC. Only useful when
// dealing with the stack separately.
class GCObliviousObjectStorage final {
 public:
  GCObliviousObjectStorage()
      : storage_(std::make_unique<const void*>(nullptr)) {}

  template <typename T>
  void set_object(T* t) {
    *storage_.get() = TraceTrait<T>::GetTraceDescriptor(t).base_object_payload;
  }

  const void* object() const { return *storage_; }

 private:
  std::unique_ptr<const void*> storage_;
};

V8_NOINLINE void RegisterInConstructionObject(
    AllocationHandle& allocation_handle, Visitor& v,
    GCObliviousObjectStorage& storage) {
  // Create deeper stack to avoid finding any temporary reference in the caller.
  char space[500];
  USE(space);
  MakeGarbageCollected<GCedWithCallback>(
      allocation_handle,
      [&visitor = v, &storage](GCedWithCallback* obj) {
        Member<GCedWithCallback> member(obj);
        // Adds GCedWithCallback to in-construction objects.
        visitor.Trace(member);
        EXPECT_FALSE(HeapObjectHeader::FromObject(obj).IsMarked());
        // The inner object GCed is only found if GCedWithCallback is processed.
        storage.set_object(obj->gced());
      },
      // Initializing store does not trigger a write barrier.
      MakeGarbageCollected<GCed>(allocation_handle));
}

}  // namespace

TEST_F(MarkerTest,
       InConstructionObjectIsEventuallyMarkedDifferentNonEmptyStack) {
  static const MarkingConfig config = {CollectionType::kMajor,
                                       StackState::kMayContainHeapPointers};
  InitializeMarker(*Heap::From(GetHeap()), GetPlatformHandle().get(), config);

  GCObliviousObjectStorage storage;
  RegisterInConstructionObject(GetAllocationHandle(), marker()->Visitor(),
                               storage);
  EXPECT_FALSE(HeapObjectHeader::FromObject(storage.object()).IsMarked());
  marker()->FinishMarking(StackState::kMayContainHeapPointers);
  EXPECT_TRUE(HeapObjectHeader::FromObject(storage.object()).IsMarked());
}

TEST_F(MarkerTest, SentinelNotClearedOnWeakPersistentHandling) {
  static const MarkingConfig config = {
      CollectionType::kMajor, StackState::kNoHeapPointers,
      MarkingConfig::MarkingType::kIncremental};
  Persistent<GCed> root = MakeGarbageCollected<GCed>(GetAllocationHandle());
  auto* tmp = MakeGarbageCollected<GCed>(GetAllocationHandle());
  root->SetWeakChild(tmp);
  InitializeMarker(*Heap::From(GetHeap()), GetPlatformHandle().get(), config);
  while (!marker()->IncrementalMarkingStepForTesting(
      StackState::kNoHeapPointers)) {
  }
  // {root} object must be marked at this point because we do not allow
  // encountering kSentinelPointer in WeakMember on regular Trace() calls.
  ASSERT_TRUE(HeapObjectHeader::FromObject(root.Get()).IsMarked());
  root->SetWeakChild(kSentinelPointer);
  marker()->FinishMarking(StackState::kNoHeapPointers);
  EXPECT_EQ(kSentinelPointer, root->weak_child());
}

namespace {

class SimpleObject final : public GarbageCollected<SimpleObject> {
 public:
  void Trace(Visitor*) const {}
};

class ObjectWithEphemeronPair final
    : public GarbageCollected<ObjectWithEphemeronPair> {
 public:
  explicit ObjectWithEphemeronPair(AllocationHandle& handle)
      : ephemeron_pair_(MakeGarbageCollected<SimpleObject>(handle),
                        MakeGarbageCollected<SimpleObject>(handle)) {}

  void Trace(Visitor* visitor) const {
    // First trace the ephemeron pair. The key is not yet marked as live, so the
    // pair should be recorded for later processing. Then strongly mark the key.
    // Marking the key will not trigger another worklist processing iteration,
    // as it merely continues the same loop for regular objects and will leave
    // the main marking worklist empty. If recording the ephemeron pair doesn't
    // as well, we will get a crash when destroying the marker.
    visitor->Trace(ephemeron_pair_);
    visitor->TraceStrongly(ephemeron_pair_.key);
  }

 private:
  const EphemeronPair<SimpleObject, SimpleObject> ephemeron_pair_;
};

}  // namespace

TEST_F(MarkerTest, MarkerProcessesAllEphemeronPairs) {
  static const MarkingConfig config = {CollectionType::kMajor,
                                       StackState::kNoHeapPointers,
                                       MarkingConfig::MarkingType::kAtomic};
  Persistent<ObjectWithEphemeronPair> obj =
      MakeGarbageCollected<ObjectWithEphemeronPair>(GetAllocationHandle(),
                                                    GetAllocationHandle());
  InitializeMarker(*Heap::From(GetHeap()), GetPlatformHandle().get(), config);
  marker()->FinishMarking(StackState::kNoHeapPointers);
  ResetMarker();
}

// Incremental Marking

class IncrementalMarkingTest : public testing::TestWithHeap {
 public:
  static constexpr MarkingConfig IncrementalPreciseMarkingConfig = {
      CollectionType::kMajor, StackState::kNoHeapPointers,
      MarkingConfig::MarkingType::kIncremental};

  void FinishSteps(StackState stack_state) {
    while (!SingleStep(stack_state)) {
    }
  }

  void FinishMarking() {
    GetMarkerRef()->FinishMarking(StackState::kMayContainHeapPointers);
    // Pretend do finish sweeping as StatsCollector verifies that Notify*
    // methods are called in the right order.
    GetMarkerRef().reset();
    Heap::From(GetHeap())->stats_collector()->NotifySweepingCompleted(
        GCConfig::SweepingType::kIncremental);
  }

  void InitializeMarker(HeapBase& heap, cppgc::Platform* platform,
                        MarkingConfig config) {
    GetMarkerRef() = std::make_unique<Marker>(heap, platform, config);
    GetMarkerRef()->StartMarking();
  }

  MarkerBase* marker() const { return Heap::From(GetHeap())->marker(); }

 private:
  bool SingleStep(StackState stack_state) {
    return GetMarkerRef()->IncrementalMarkingStepForTesting(stack_state);
  }
};

constexpr MarkingConfig IncrementalMarkingTest::IncrementalPreciseMarkingConfig;

TEST_F(IncrementalMarkingTest, RootIsMarkedAfterMarkingStarted) {
  Persistent<GCed> root = MakeGarbageCollected<GCed>(GetAllocationHandle());
  EXPECT_FALSE(HeapObjectHeader::FromObject(root).IsMarked());
  InitializeMarker(*Heap::From(GetHeap()), GetPlatformHandle().get(),
                   IncrementalPreciseMarkingConfig);
  EXPECT_TRUE(HeapObjectHeader::FromObject(root).IsMarked());
  FinishMarking();
}

TEST_F(IncrementalMarkingTest, MemberIsMarkedAfterMarkingSteps) {
  Persistent<GCed> root = MakeGarbageCollected<GCed>(GetAllocationHandle());
  root->SetChild(MakeGarbageCollected<GCed>(GetAllocationHandle()));
  HeapObjectHeader& header = HeapObjectHeader::FromObject(root->child());
  EXPECT_FALSE(header.IsMarked());
  InitializeMarker(*Heap::From(GetHeap()), GetPlatformHandle().get(),
                   IncrementalPreciseMarkingConfig);
  FinishSteps(StackState::kNoHeapPointers);
  EXPECT_TRUE(header.IsMarked());
  FinishMarking();
}

TEST_F(IncrementalMarkingTest,
       MemberWithWriteBarrierIsMarkedAfterMarkingSteps) {
  Persistent<GCed> root = MakeGarbageCollected<GCed>(GetAllocationHandle());
  InitializeMarker(*Heap::From(GetHeap()), GetPlatformHandle().get(),
                   IncrementalPreciseMarkingConfig);
  root->SetChild(MakeGarbageCollected<GCed>(GetAllocationHandle()));
  FinishSteps(StackState::kNoHeapPointers);
  HeapObjectHeader& header = HeapObjectHeader::FromObject(root->child());
  EXPECT_TRUE(header.IsMarked());
  FinishMarking();
}

namespace {
class Holder : public GarbageCollected<Holder> {
 public:
  void Trace(Visitor* visitor) const { visitor->Trace(member_); }

  Member<GCedWithCallback> member_;
};
}  // namespace

TEST_F(IncrementalMarkingTest, IncrementalStepDuringAllocation) {
  Persistent<Holder> holder =
      MakeGarbageCollected<Holder>(GetAllocationHandle());
  InitializeMarker(*Heap::From(GetHeap()), GetPlatformHandle().get(),
                   IncrementalPreciseMarkingConfig);
  const HeapObjectHeader* header;
  MakeGarbageCollected<GCedWithCallback>(
      GetAllocationHandle(), [this, &holder, &header](GCedWithCallback* obj) {
        header = &HeapObjectHeader::FromObject(obj);
        holder->member_ = obj;
        EXPECT_FALSE(header->IsMarked());
        FinishSteps(StackState::kMayContainHeapPointers);
        EXPECT_FALSE(header->IsMarked());
      });
  FinishSteps(StackState::kNoHeapPointers);
  EXPECT_TRUE(header->IsMarked());
  FinishMarking();
}

TEST_F(IncrementalMarkingTest, MarkingRunsOutOfWorkEventually) {
  InitializeMarker(*Heap::From(GetHeap()), GetPlatformHandle().get(),
                   IncrementalPreciseMarkingConfig);
  FinishSteps(StackState::kNoHeapPointers);
  FinishMarking();
}

}  // namespace internal
}  // namespace cppgc

"""

```