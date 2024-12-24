Response: Let's break down the thought process for analyzing this C++ unit test file for `cppgc` write barriers.

1. **Understand the Goal:** The core purpose of a "write barrier" in garbage collection is to notify the garbage collector when a pointer within a managed object is updated to point to another managed object. This ensures the collector can correctly trace object references and prevent premature collection of reachable objects. Unit tests for write barriers aim to verify that these notifications happen correctly under various conditions.

2. **Identify Key Concepts:**  Scanning the code reveals important terms:
    * `cppgc`: This signals we're dealing with the C++ garbage collector in V8.
    * `write-barrier`: The central concept.
    * `IncrementalMarkingScope`:  Implies the tests involve incremental garbage collection, where marking happens in steps.
    * `MarkerBase`, `Marker`: Components of the garbage collection marking process.
    * `MarkingWorklists`, `WriteBarrierWorklist`: Data structures used by the marker to track objects to process. The write barrier adds objects to these worklists.
    * `HeapObjectHeader`: Metadata associated with each garbage-collected object, including marking status.
    * `IsMarked()`: A function to check if an object has been marked by the garbage collector.
    * `Member<T>`: A smart pointer-like class used in `cppgc` to manage references between garbage-collected objects. These are the primary targets of write barriers.
    * `GarbageCollected<T>`, `GarbageCollectedMixin`: Base classes for objects managed by `cppgc`.
    * `Trace()`: A virtual function used by the garbage collector to traverse object graphs.
    * `kSentinelPointer`: A special value often used to indicate a null or uninitialized pointer.
    * `subtle::HeapConsistency::WriteBarrierParams`, `WriteBarrierType`: Structures and enums related to the low-level implementation of write barriers.
    * `DijkstraWriteBarrier`, `SteeleWriteBarrier`:  Different algorithms or strategies for implementing write barriers.

3. **Examine the Test Structure:** The file uses Google Test (`TEST_F`). We see several test fixtures (`WriteBarrierTest`, `NoWriteBarrierTest`) which set up the testing environment (likely involving a mock or real `cppgc` heap). Individual tests within these fixtures focus on specific scenarios.

4. **Analyze the Helper Classes:**
    * `IncrementalMarkingScope`: Manages the start and finish of an incremental marking cycle. This is crucial for testing write barriers in the context of active marking.
    * `ExpectWriteBarrierFires`:  A test helper that sets up an expectation that certain objects will trigger the write barrier. It checks the worklists after the operation to confirm the objects were added.
    * `ExpectNoWriteBarrierFires`:  A test helper that sets up an expectation that no write barrier will be triggered for certain operations. It verifies the worklists remain empty.

5. **Deconstruct Individual Tests:** For each `TEST_F`, identify:
    * **What is being tested?** (e.g., assigning a member, initializing a member, using mixins, raw write barrier functions).
    * **What is the setup?** (creation of objects, marking status of objects).
    * **What action triggers the potential write barrier?** (setting a `Member`, calling `DijkstraWriteBarrier`, etc.).
    * **What is the expected outcome?** (write barrier fires or not, based on marking status and the type of operation).

6. **Connect to JavaScript (if applicable):**  Think about how the concepts tested in this C++ code relate to JavaScript's garbage collection. JavaScript's garbage collection is also automatic and needs to track object references. While JavaScript doesn't expose "write barriers" directly as a concept to developers, the *mechanism* of tracking changes to object references exists under the hood.

7. **Synthesize the Summary:** Based on the analysis, summarize the file's functionality. Highlight the core concepts and how the tests verify the correct behavior of write barriers under different conditions.

8. **Illustrate with JavaScript:**  Create simple JavaScript examples that conceptually demonstrate the scenarios tested in the C++ code. Focus on object relationships and how changes might affect garbage collection. Since direct write barrier concepts aren't in JavaScript, use analogies like updating object properties that hold references to other objects.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "This is just about pointers."  **Correction:**  It's specifically about *managed* pointers in a garbage-collected environment. The write barrier is tied to the GC.
* **Initial thought:**  "The helper classes are just boilerplate." **Correction:** They are crucial for setting up specific testing conditions (like incremental marking being active) and for verifying the *effects* of the write barrier (by checking the worklists).
* **Struggling with the JavaScript analogy:** Initially, I might try to find a direct equivalent of `Member<>`. **Correction:** The focus should be on the *effect* – how changes in object references are handled by the GC, even if the implementation details differ. Focus on the observable behavior from a JavaScript perspective.

By following this structured approach, breaking down the code into its components, and focusing on the underlying principles of garbage collection, a comprehensive understanding of the unit test file can be achieved, and meaningful connections to JavaScript can be drawn.
这个C++源代码文件 `write-barrier-unittest.cc` 的主要功能是**测试 `cppgc` (C++ garbage collection) 的写屏障机制**。

**核心功能归纳：**

1. **验证写屏障的触发条件：** 测试在垃圾回收的标记阶段，当一个未被标记的对象（旧对象）的成员指针指向另一个未被标记的对象（新对象）时，写屏障是否会被正确触发。触发写屏障会将新对象加入到垃圾回收器的待处理队列中，确保其不会被错误回收。

2. **验证写屏障的跳过条件：** 测试在某些情况下，写屏障应该被跳过，例如：
    * 垃圾回收的标记阶段未激活。
    * 被指向的对象（新对象）已经被标记。
    * 正在进行成员的初始化赋值（而不是后续的赋值）。
    * 将成员指针设置为哨兵值 (kSentinelPointer)。

3. **测试不同类型的写屏障：** 文件中包含了对不同写屏障实现（如 Dijkstra 写屏障和 Steele 写屏障）的测试，验证它们在标记阶段是否能正确触发，以及在特定条件下是否能正确跳过。

4. **测试写屏障在混入 (Mixin) 中的应用：** 测试当一个对象混入包含垃圾回收指针的基类时，写屏障是否能够正确处理这些指针的更新。

5. **使用辅助类进行断言：** 文件中定义了 `ExpectWriteBarrierFires` 和 `ExpectNoWriteBarrierFires` 这两个辅助类，用于更清晰地表达测试意图，并自动验证写屏障是否按预期触发（或未触发），以及相关的对象是否被标记。

**与 JavaScript 的关系以及 JavaScript 举例：**

虽然 JavaScript 本身没有像 C++ `cppgc` 那样显式的写屏障概念，但 JavaScript 的垃圾回收机制背后也存在类似的需求。当 JavaScript 引擎执行类似以下的操作时，内部的垃圾回收器需要追踪对象间的引用关系：

```javascript
let obj1 = {};
let obj2 = {};

// 这里的赋值操作就类似于 C++ 中更新成员指针
obj1.child = obj2;
```

在这个例子中，`obj1.child = obj2;` 这个操作相当于在 `obj1` 中创建了一个指向 `obj2` 的引用。  如果 JavaScript 的垃圾回收器正在进行标记阶段，并且 `obj1` 之前已经被访问过（可能是“旧对象”的概念），而 `obj2` 是新创建的或者之前未被访问的，那么就需要某种机制来通知垃圾回收器 `obj2` 现在是可达的，不能被回收。

**C++ 写屏障在 JavaScript 中的概念性对应：**

C++ 的写屏障机制可以看作是 JavaScript 垃圾回收器内部用于维护对象图连通性的一个低级别实现细节。当 JavaScript 引擎执行赋值操作时，可能会触发内部的机制，类似于 C++ 的写屏障，来确保垃圾回收器能够正确追踪到新的对象引用。

**JavaScript 举例说明 (概念性)：**

假设 JavaScript 引擎内部有一个类似于 C++ `cppgc` 的垃圾回收器。当执行 `obj1.child = obj2;` 时，如果满足某些条件（例如，垃圾回收器正在进行标记，`obj1` 已被标记但 `obj2` 未被标记），引擎内部可能会执行类似写屏障的操作，将 `obj2` 添加到待处理队列中，确保它不会在接下来的垃圾回收周期中被错误地回收。

**总结：**

`write-barrier-unittest.cc` 文件是 `v8` 引擎中 `cppgc` 组件的关键测试，用于验证写屏障机制的正确性。虽然 JavaScript 开发者通常不需要直接处理写屏障，但理解其背后的原理有助于理解 JavaScript 垃圾回收的工作方式，以及为什么某些对象能够被保留在内存中。这个 C++ 文件实际上是在测试 V8 引擎底层用来支撑 JavaScript 内存管理的关键机制。

Prompt: 
```
这是目录为v8/test/unittests/heap/cppgc/write-barrier-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "include/cppgc/internal/write-barrier.h"

#include <algorithm>
#include <initializer_list>
#include <vector>

#include "include/cppgc/heap-consistency.h"
#include "include/cppgc/internal/pointer-policies.h"
#include "src/base/logging.h"
#include "src/heap/cppgc/heap-object-header.h"
#include "src/heap/cppgc/marker.h"
#include "test/unittests/heap/cppgc/tests.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace cppgc {
namespace internal {

namespace {

class V8_NODISCARD IncrementalMarkingScope {
 public:
  explicit IncrementalMarkingScope(MarkerBase* marker) : marker_(marker) {}

  ~IncrementalMarkingScope() V8_NOEXCEPT {
    marker_->FinishMarking(kIncrementalConfig.stack_state);
  }

  static constexpr MarkingConfig kIncrementalConfig{
      CollectionType::kMajor, StackState::kNoHeapPointers,
      MarkingConfig::MarkingType::kIncremental};

 private:
  MarkerBase* marker_;
};

constexpr MarkingConfig IncrementalMarkingScope::kIncrementalConfig;

class V8_NODISCARD ExpectWriteBarrierFires final
    : private IncrementalMarkingScope {
 public:
  ExpectWriteBarrierFires(MarkerBase* marker,
                          std::initializer_list<void*> objects)
      : IncrementalMarkingScope(marker),
        marking_worklist_(
            marker->MutatorMarkingStateForTesting().marking_worklist()),
        write_barrier_worklist_(
            marker->MutatorMarkingStateForTesting().write_barrier_worklist()),
        retrace_marked_objects_worklist_(
            marker->MutatorMarkingStateForTesting()
                .retrace_marked_objects_worklist()),
        objects_(objects) {
    EXPECT_TRUE(marking_worklist_.IsGlobalEmpty());
    EXPECT_TRUE(write_barrier_worklist_.IsGlobalEmpty());
    for (void* object : objects) {
      headers_.push_back(&HeapObjectHeader::FromObject(object));
      EXPECT_FALSE(headers_.back()->IsMarked());
    }
  }

  ~ExpectWriteBarrierFires() V8_NOEXCEPT {
    {
      MarkingWorklists::MarkingItem item;
      while (marking_worklist_.Pop(&item)) {
        auto pos = std::find(objects_.begin(), objects_.end(),
                             item.base_object_payload);
        if (pos != objects_.end()) objects_.erase(pos);
      }
    }
    {
      HeapObjectHeader* item;
      while (write_barrier_worklist_.Pop(&item)) {
        auto pos =
            std::find(objects_.begin(), objects_.end(), item->ObjectStart());
        if (pos != objects_.end()) objects_.erase(pos);
      }
    }
    {
      HeapObjectHeader* item;
      while (retrace_marked_objects_worklist_.Pop(&item)) {
        auto pos =
            std::find(objects_.begin(), objects_.end(), item->ObjectStart());
        if (pos != objects_.end()) objects_.erase(pos);
      }
    }
    EXPECT_TRUE(objects_.empty());
    for (auto* header : headers_) {
      EXPECT_TRUE(header->IsMarked());
      header->Unmark();
    }
    EXPECT_TRUE(marking_worklist_.IsGlobalEmpty());
    EXPECT_TRUE(write_barrier_worklist_.IsGlobalEmpty());
  }

 private:
  MarkingWorklists::MarkingWorklist::Local& marking_worklist_;
  MarkingWorklists::WriteBarrierWorklist::Local& write_barrier_worklist_;
  MarkingWorklists::RetraceMarkedObjectsWorklist::Local&
      retrace_marked_objects_worklist_;
  std::vector<void*> objects_;
  std::vector<HeapObjectHeader*> headers_;
};

class V8_NODISCARD ExpectNoWriteBarrierFires final
    : private IncrementalMarkingScope {
 public:
  ExpectNoWriteBarrierFires(MarkerBase* marker,
                            std::initializer_list<void*> objects)
      : IncrementalMarkingScope(marker),
        marking_worklist_(
            marker->MutatorMarkingStateForTesting().marking_worklist()),
        write_barrier_worklist_(
            marker->MutatorMarkingStateForTesting().write_barrier_worklist()) {
    EXPECT_TRUE(marking_worklist_.IsGlobalEmpty());
    EXPECT_TRUE(write_barrier_worklist_.IsGlobalEmpty());
    for (void* object : objects) {
      auto* header = &HeapObjectHeader::FromObject(object);
      headers_.emplace_back(header, header->IsMarked());
    }
  }

  ~ExpectNoWriteBarrierFires() {
    EXPECT_TRUE(marking_worklist_.IsGlobalEmpty());
    EXPECT_TRUE(write_barrier_worklist_.IsGlobalEmpty());
    for (const auto& pair : headers_) {
      EXPECT_EQ(pair.second, pair.first->IsMarked());
    }
  }

 private:
  MarkingWorklists::MarkingWorklist::Local& marking_worklist_;
  MarkingWorklists::WriteBarrierWorklist::Local& write_barrier_worklist_;
  std::vector<std::pair<HeapObjectHeader*, bool /* was marked */>> headers_;
};

class GCed : public GarbageCollected<GCed> {
 public:
  GCed() = default;
  explicit GCed(GCed* next) : next_(next) {}

  void Trace(cppgc::Visitor* v) const { v->Trace(next_); }

  bool IsMarked() const {
    return HeapObjectHeader::FromObject(this).IsMarked();
  }

  void set_next(GCed* next) { next_ = next; }
  GCed* next() const { return next_; }
  Member<GCed>& next_ref() { return next_; }

 private:
  Member<GCed> next_ = nullptr;
};

}  // namespace

class WriteBarrierTest : public testing::TestWithHeap {
 public:
  WriteBarrierTest() : internal_heap_(Heap::From(GetHeap())) {
    DCHECK_NULL(GetMarkerRef().get());
    GetMarkerRef() =
        std::make_unique<Marker>(*internal_heap_, GetPlatformHandle().get(),
                                 IncrementalMarkingScope::kIncrementalConfig);
    marker_ = GetMarkerRef().get();
    marker_->StartMarking();
  }

  ~WriteBarrierTest() override {
    marker_->ClearAllWorklistsForTesting();
    GetMarkerRef().reset();
  }

  MarkerBase* marker() const { return marker_; }

 private:
  Heap* internal_heap_;
  MarkerBase* marker_;
};

class NoWriteBarrierTest : public testing::TestWithHeap {};

// =============================================================================
// Basic support. ==============================================================
// =============================================================================

TEST_F(WriteBarrierTest, EnableDisableIncrementalMarking) {
  {
    IncrementalMarkingScope scope(marker());
    EXPECT_TRUE(WriteBarrier::IsEnabled());
  }
}

TEST_F(WriteBarrierTest, TriggersWhenMarkingIsOn) {
  auto* object1 = MakeGarbageCollected<GCed>(GetAllocationHandle());
  auto* object2 = MakeGarbageCollected<GCed>(GetAllocationHandle());
  {
    ExpectWriteBarrierFires scope(marker(), {object1});
    EXPECT_FALSE(object1->IsMarked());
    object2->set_next(object1);
    EXPECT_TRUE(object1->IsMarked());
  }
}

TEST_F(NoWriteBarrierTest, BailoutWhenMarkingIsOff) {
  auto* object1 = MakeGarbageCollected<GCed>(GetAllocationHandle());
  auto* object2 = MakeGarbageCollected<GCed>(GetAllocationHandle());
  EXPECT_FALSE(object1->IsMarked());
  object2->set_next(object1);
  EXPECT_FALSE(object1->IsMarked());
}

TEST_F(WriteBarrierTest, BailoutIfMarked) {
  auto* object1 = MakeGarbageCollected<GCed>(GetAllocationHandle());
  auto* object2 = MakeGarbageCollected<GCed>(GetAllocationHandle());
  EXPECT_TRUE(HeapObjectHeader::FromObject(object1).TryMarkAtomic());
  {
    ExpectNoWriteBarrierFires scope(marker(), {object1});
    object2->set_next(object1);
  }
}

TEST_F(WriteBarrierTest, MemberInitializingStoreNoBarrier) {
  auto* object1 = MakeGarbageCollected<GCed>(GetAllocationHandle());
  {
    ExpectNoWriteBarrierFires scope(marker(), {object1});
    auto* object2 = MakeGarbageCollected<GCed>(GetAllocationHandle(), object1);
    HeapObjectHeader& object2_header = HeapObjectHeader::FromObject(object2);
    EXPECT_FALSE(object2_header.IsMarked());
  }
}

TEST_F(WriteBarrierTest, MemberReferenceAssignMember) {
  auto* obj = MakeGarbageCollected<GCed>(GetAllocationHandle());
  auto* ref_obj = MakeGarbageCollected<GCed>(GetAllocationHandle());
  Member<GCed>& m2 = ref_obj->next_ref();
  Member<GCed> m3(obj);
  {
    ExpectWriteBarrierFires scope(marker(), {obj});
    m2 = m3;
  }
}

TEST_F(WriteBarrierTest, MemberSetSentinelValueNoBarrier) {
  auto* obj = MakeGarbageCollected<GCed>(GetAllocationHandle());
  Member<GCed>& m = obj->next_ref();
  {
    ExpectNoWriteBarrierFires scope(marker(), {});
    m = kSentinelPointer;
  }
}

TEST_F(WriteBarrierTest, MemberCopySentinelValueNoBarrier) {
  auto* obj1 = MakeGarbageCollected<GCed>(GetAllocationHandle());
  Member<GCed>& m1 = obj1->next_ref();
  m1 = kSentinelPointer;
  {
    ExpectNoWriteBarrierFires scope(marker(), {});
    auto* obj2 = MakeGarbageCollected<GCed>(GetAllocationHandle());
    obj2->next_ref() = m1;
  }
}

// =============================================================================
// Mixin support. ==============================================================
// =============================================================================

namespace {

class Mixin : public GarbageCollectedMixin {
 public:
  void Trace(cppgc::Visitor* visitor) const override { visitor->Trace(next_); }

  virtual void Bar() {}

 protected:
  Member<GCed> next_;
};

class ClassWithVirtual {
 protected:
  virtual void Foo() {}
};

class Child : public GarbageCollected<Child>,
              public ClassWithVirtual,
              public Mixin {
 public:
  Child() : ClassWithVirtual(), Mixin() {}
  ~Child() = default;

  void Trace(cppgc::Visitor* visitor) const override { Mixin::Trace(visitor); }

  void Foo() override {}
  void Bar() override {}
};

class ParentWithMixinPointer : public GarbageCollected<ParentWithMixinPointer> {
 public:
  ParentWithMixinPointer() = default;

  void set_mixin(Mixin* mixin) { mixin_ = mixin; }

  virtual void Trace(cppgc::Visitor* visitor) const { visitor->Trace(mixin_); }

 protected:
  Member<Mixin> mixin_;
};

}  // namespace

TEST_F(WriteBarrierTest, WriteBarrierOnUnmarkedMixinApplication) {
  ParentWithMixinPointer* parent =
      MakeGarbageCollected<ParentWithMixinPointer>(GetAllocationHandle());
  auto* child = MakeGarbageCollected<Child>(GetAllocationHandle());
  Mixin* mixin = static_cast<Mixin*>(child);
  EXPECT_NE(static_cast<void*>(child), static_cast<void*>(mixin));
  {
    ExpectWriteBarrierFires scope(marker(), {child});
    parent->set_mixin(mixin);
  }
}

TEST_F(WriteBarrierTest, NoWriteBarrierOnMarkedMixinApplication) {
  ParentWithMixinPointer* parent =
      MakeGarbageCollected<ParentWithMixinPointer>(GetAllocationHandle());
  auto* child = MakeGarbageCollected<Child>(GetAllocationHandle());
  EXPECT_TRUE(HeapObjectHeader::FromObject(child).TryMarkAtomic());
  Mixin* mixin = static_cast<Mixin*>(child);
  EXPECT_NE(static_cast<void*>(child), static_cast<void*>(mixin));
  {
    ExpectNoWriteBarrierFires scope(marker(), {child});
    parent->set_mixin(mixin);
  }
}

// =============================================================================
// Raw barriers. ===============================================================
// =============================================================================

using WriteBarrierParams = subtle::HeapConsistency::WriteBarrierParams;
using WriteBarrierType = subtle::HeapConsistency::WriteBarrierType;
using subtle::HeapConsistency;

TEST_F(NoWriteBarrierTest, WriteBarrierBailoutWhenMarkingIsOff) {
  auto* object1 = MakeGarbageCollected<GCed>(GetAllocationHandle());
  auto* object2 = MakeGarbageCollected<GCed>(GetAllocationHandle(), object1);
  {
    EXPECT_FALSE(object1->IsMarked());
    WriteBarrierParams params;
    const WriteBarrierType expected =
        Heap::From(GetHeap())->generational_gc_supported()
            ? WriteBarrierType::kGenerational
            : WriteBarrierType::kNone;
    EXPECT_EQ(expected, HeapConsistency::GetWriteBarrierType(
                            object2->next_ref().GetSlotForTesting(),
                            object2->next_ref().Get(), params));
    EXPECT_FALSE(object1->IsMarked());
  }
}

TEST_F(WriteBarrierTest, DijkstraWriteBarrierTriggersWhenMarkingIsOn) {
  auto* object1 = MakeGarbageCollected<GCed>(GetAllocationHandle());
  auto* object2 = MakeGarbageCollected<GCed>(GetAllocationHandle(), object1);
  {
    ExpectWriteBarrierFires scope(marker(), {object1});
    EXPECT_FALSE(object1->IsMarked());
    WriteBarrierParams params;
    EXPECT_EQ(WriteBarrierType::kMarking,
              HeapConsistency::GetWriteBarrierType(
                  object2->next_ref().GetSlotForTesting(),
                  object2->next_ref().Get(), params));
    HeapConsistency::DijkstraWriteBarrier(params, object2->next_ref().Get());
    EXPECT_TRUE(object1->IsMarked());
  }
}

TEST_F(WriteBarrierTest, DijkstraWriteBarrierBailoutIfMarked) {
  auto* object1 = MakeGarbageCollected<GCed>(GetAllocationHandle());
  auto* object2 = MakeGarbageCollected<GCed>(GetAllocationHandle(), object1);
  EXPECT_TRUE(HeapObjectHeader::FromObject(object1).TryMarkAtomic());
  {
    ExpectNoWriteBarrierFires scope(marker(), {object1});
    WriteBarrierParams params;
    EXPECT_EQ(WriteBarrierType::kMarking,
              HeapConsistency::GetWriteBarrierType(
                  object2->next_ref().GetSlotForTesting(),
                  object2->next_ref().Get(), params));
    HeapConsistency::DijkstraWriteBarrier(params, object2->next_ref().Get());
  }
}

namespace {

struct InlinedObject {
  void Trace(cppgc::Visitor* v) const { v->Trace(ref); }

  Member<GCed> ref;
};

class GCedWithInlinedArray : public GarbageCollected<GCedWithInlinedArray> {
 public:
  static constexpr size_t kNumReferences = 4;

  explicit GCedWithInlinedArray(GCed* value2) {
    new (&objects[2].ref) Member<GCed>(value2);
  }

  void Trace(cppgc::Visitor* v) const {
    for (size_t i = 0; i < kNumReferences; ++i) {
      v->Trace(objects[i]);
    }
  }

  InlinedObject objects[kNumReferences];
};

}  // namespace

TEST_F(WriteBarrierTest, DijkstraWriteBarrierRangeTriggersWhenMarkingIsOn) {
  auto* object1 = MakeGarbageCollected<GCed>(GetAllocationHandle());
  auto* object2 = MakeGarbageCollected<GCedWithInlinedArray>(
      GetAllocationHandle(), object1);
  {
    ExpectWriteBarrierFires scope(marker(), {object1});
    EXPECT_FALSE(object1->IsMarked());
    WriteBarrierParams params;
    EXPECT_EQ(WriteBarrierType::kMarking,
              HeapConsistency::GetWriteBarrierType(
                  object2->objects, params, [this]() -> HeapHandle& {
                    return GetHeap()->GetHeapHandle();
                  }));
    HeapConsistency::DijkstraWriteBarrierRange(
        params, object2->objects, sizeof(InlinedObject), 4,
        TraceTrait<InlinedObject>::Trace);
    EXPECT_TRUE(object1->IsMarked());
  }
}

TEST_F(WriteBarrierTest, DijkstraWriteBarrierRangeBailoutIfMarked) {
  auto* object1 = MakeGarbageCollected<GCed>(GetAllocationHandle());
  auto* object2 = MakeGarbageCollected<GCedWithInlinedArray>(
      GetAllocationHandle(), object1);
  EXPECT_TRUE(HeapObjectHeader::FromObject(object1).TryMarkAtomic());
  {
    ExpectNoWriteBarrierFires scope(marker(), {object1});
    WriteBarrierParams params;
    EXPECT_EQ(WriteBarrierType::kMarking,
              HeapConsistency::GetWriteBarrierType(
                  object2->objects, params, [this]() -> HeapHandle& {
                    return GetHeap()->GetHeapHandle();
                  }));
    HeapConsistency::DijkstraWriteBarrierRange(
        params, object2->objects, sizeof(InlinedObject), 4,
        TraceTrait<InlinedObject>::Trace);
  }
}

TEST_F(WriteBarrierTest, SteeleWriteBarrierTriggersWhenMarkingIsOn) {
  auto* object1 = MakeGarbageCollected<GCed>(GetAllocationHandle());
  auto* object2 = MakeGarbageCollected<GCed>(GetAllocationHandle(), object1);
  {
    ExpectWriteBarrierFires scope(marker(), {object1});
    EXPECT_TRUE(HeapObjectHeader::FromObject(object1).TryMarkAtomic());
    WriteBarrierParams params;
    EXPECT_EQ(WriteBarrierType::kMarking,
              HeapConsistency::GetWriteBarrierType(
                  &object2->next_ref(), object2->next_ref().Get(), params));
    HeapConsistency::SteeleWriteBarrier(params, object2->next_ref().Get());
  }
}

TEST_F(WriteBarrierTest, SteeleWriteBarrierBailoutIfNotMarked) {
  auto* object1 = MakeGarbageCollected<GCed>(GetAllocationHandle());
  auto* object2 = MakeGarbageCollected<GCed>(GetAllocationHandle(), object1);
  {
    ExpectNoWriteBarrierFires scope(marker(), {object1});
    WriteBarrierParams params;
    EXPECT_EQ(WriteBarrierType::kMarking,
              HeapConsistency::GetWriteBarrierType(
                  &object2->next_ref(), object2->next_ref().Get(), params));
    HeapConsistency::SteeleWriteBarrier(params, object2->next_ref().Get());
  }
}

}  // namespace internal
}  // namespace cppgc

"""

```