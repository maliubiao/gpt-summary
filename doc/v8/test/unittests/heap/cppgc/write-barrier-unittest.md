Response:
Let's break down the thought process for analyzing this C++ unit test file.

1. **Identify the Core Purpose:** The file name `write-barrier-unittest.cc` immediately suggests the primary focus is testing the write barrier mechanism within the `cppgc` (C++ garbage collection) system of V8. Unit tests are designed to isolate and verify specific functionalities.

2. **Scan for Key Concepts:** Look for recurring terms and classes. "WriteBarrier," "Marker," "Marking," "GCed" (likely "Garbage Collected"), "Heap," "Member," "Trace," "IncrementalMarking,"  "DijkstraWriteBarrier," "SteeleWriteBarrier" stand out. These provide clues about the functionalities being tested.

3. **Examine Test Fixtures:**  The classes `WriteBarrierTest` and `NoWriteBarrierTest` are test fixtures using Google Test (`testing::TestWithHeap`). This indicates groups of tests related to write barriers under different conditions. `WriteBarrierTest` seems to set up an environment *with* marking enabled, while `NoWriteBarrierTest` likely operates without active marking.

4. **Analyze Individual Tests (Keywords and Actions):** Go through each `TEST_F` function and extract the core action and expected outcome. Look for keywords like `EnableDisable`, `TriggersWhen`, `BailoutWhen`, `BailoutIf`, `MemberInitializingStore`, `MemberReferenceAssign`, `MemberSetSentinelValue`, `MemberCopySentinelValue`,  `Mixin`, `Raw barriers`, `DijkstraWriteBarrier`, `SteeleWriteBarrier`. These keywords often directly correspond to the functionality being tested.

5. **Infer Functionality from Test Names and Code:**

   * **`EnableDisableIncrementalMarking`**: Checks if the write barrier is enabled during incremental marking.
   * **`TriggersWhenMarkingIsOn`**: Verifies that a write barrier is triggered (and an object is marked) when marking is active and a pointer is updated.
   * **`BailoutWhenMarkingIsOff`**: Confirms that no write barrier is triggered when marking is disabled.
   * **`BailoutIfMarked`**: Tests the optimization where a write barrier is skipped if the target object is already marked.
   * **`MemberInitializingStoreNoBarrier`**: Investigates if a write barrier is necessary during the *initialization* of a `Member`. It seems not, likely an optimization.
   * **`MemberReferenceAssignMember`**: Checks the write barrier when assigning one `Member` to another.
   * **`MemberSetSentinelValueNoBarrier` / `MemberCopySentinelValueNoBarrier`**:  Examines the case of assigning/copying sentinel values (likely null pointers). These might be optimized to avoid write barriers.
   * **`WriteBarrierOnUnmarkedMixinApplication` / `NoWriteBarrierOnMarkedMixinApplication`**: Focuses on write barriers when dealing with mixins (multiple inheritance). The marking status of the mixin seems to matter.
   * **`WriteBarrierBailoutWhenMarkingIsOff` (Raw barriers)**: Similar to the earlier "BailoutWhenMarkingIsOff" but using the raw `HeapConsistency` API.
   * **`DijkstraWriteBarrierTriggersWhenMarkingIsOn` / `DijkstraWriteBarrierBailoutIfMarked`**: Tests the specific Dijkstra write barrier algorithm.
   * **`DijkstraWriteBarrierRangeTriggersWhenMarkingIsOn` / `DijkstraWriteBarrierRangeBailoutIfMarked`**:  Tests the range-based version of the Dijkstra write barrier, likely for inline arrays or structures.
   * **`SteeleWriteBarrierTriggersWhenMarkingIsOn` / `SteeleWriteBarrierBailoutIfNotMarked`**: Tests the Steele write barrier algorithm.

6. **Identify Supporting Classes:**  The classes like `IncrementalMarkingScope`, `ExpectWriteBarrierFires`, and `ExpectNoWriteBarrierFires` are helper classes for setting up the testing environment and asserting the expected behavior (whether write barriers fire or not). `GCed` is a simple garbage-collected class used for demonstration.

7. **Connect to JavaScript (if applicable):** Consider how these low-level C++ concepts relate to JavaScript's garbage collection. While the direct implementation isn't in JS, the *effect* of write barriers is crucial for maintaining correctness in JS. When a JavaScript object's property is updated to reference another object, the underlying C++ `cppgc` might use a write barrier. This is where the example of assigning `obj2.next = obj1;` comes in.

8. **Look for Code Logic and Assumptions:**  The `ExpectWriteBarrierFires` and `ExpectNoWriteBarrierFires` classes contain logic to check the marking and write barrier worklists. The assumptions here are that:
    * A triggered write barrier will add the *target* object to a worklist.
    * No triggered write barrier will leave the worklists empty.
    * The marking status of objects is updated correctly.

9. **Consider Common Programming Errors:**  Think about scenarios where a missing or incorrect write barrier would cause problems. This leads to examples like:
    * Failing to mark an object, leading to premature collection.
    * Performance issues due to unnecessary write barriers.

10. **Structure the Output:** Organize the findings into clear categories: Functionality, Torque, JavaScript Relation, Code Logic, and Common Errors. Use bullet points for readability.

By following these steps, we can systematically analyze the C++ unit test file and understand its purpose and implications. The process involves reading the code, identifying key components, inferring functionality from test names, and connecting the low-level details to higher-level concepts (like JavaScript garbage collection).
这个C++源代码文件 `v8/test/unittests/heap/cppgc/write-barrier-unittest.cc` 的主要功能是**测试 V8 中 cppgc (C++ garbage collection) 的写屏障 (write barrier) 机制**。

更具体地说，它测试了在不同的场景下，写屏障是否按预期触发以及是否正确地将对象添加到标记队列中，以确保垃圾回收器能够正确地追踪对象引用，防止过早回收仍然被引用的对象。

以下是该文件更详细的功能点：

**1. 测试写屏障的基本启用和禁用:**
    * `TEST_F(WriteBarrierTest, EnableDisableIncrementalMarking)`:  验证在增量标记期间，写屏障是否被启用。

**2. 测试在标记开启时写屏障的触发:**
    * `TEST_F(WriteBarrierTest, TriggersWhenMarkingIsOn)`: 当垃圾回收的标记阶段正在进行时，如果修改了对象之间的引用关系，写屏障应该被触发，并将被引用的对象加入到标记队列中。

**3. 测试在标记关闭时写屏障的跳过:**
    * `TEST_F(NoWriteBarrierTest, BailoutWhenMarkingIsOff)`: 当垃圾回收的标记阶段没有进行时，修改对象引用关系不应该触发写屏障。

**4. 测试当目标对象已被标记时写屏障的跳过:**
    * `TEST_F(WriteBarrierTest, BailoutIfMarked)`: 如果被引用的目标对象已经被标记，则不需要再次触发写屏障。

**5. 测试特定场景下写屏障的行为:**
    * `TEST_F(WriteBarrierTest, MemberInitializingStoreNoBarrier)`: 测试在初始化 `Member` 指针时是否触发写屏障（通常不应该触发，因为是初始化）。
    * `TEST_F(WriteBarrierTest, MemberReferenceAssignMember)`: 测试将一个 `Member` 指针赋值给另一个 `Member` 指针时写屏障是否触发。
    * `TEST_F(WriteBarrierTest, MemberSetSentinelValueNoBarrier)` 和 `TEST_F(WriteBarrierTest, MemberCopySentinelValueNoBarrier)`: 测试设置或复制哨兵值（例如 `kSentinelPointer`，通常表示空指针或特殊值）时是否触发写屏障。

**6. 测试与 Mixin (多重继承) 相关的写屏障:**
    * `TEST_F(WriteBarrierTest, WriteBarrierOnUnmarkedMixinApplication)` 和 `TEST_F(WriteBarrierTest, NoWriteBarrierOnMarkedMixinApplication)`:  测试在将一个包含 Mixin 的对象赋值给另一个对象时，写屏障是否正确触发，并考虑了目标对象是否已被标记的情况。

**7. 测试原始 (Raw) 写屏障函数:**
    *  这部分测试了底层的 `HeapConsistency::DijkstraWriteBarrier` 和 `HeapConsistency::SteeleWriteBarrier` 函数，这些是不同写屏障算法的实现。
    *  测试了在标记开启和关闭的不同情况下，这些原始写屏障函数的行为，以及它们是否正确地将对象添加到标记队列。
    *  还测试了范围版本的 Dijkstra 写屏障 (`DijkstraWriteBarrierRange`)，用于处理对象内部的数组或连续的引用。

**关于文件扩展名和 Torque:**

该文件以 `.cc` 结尾，因此它是 **C++ 源代码文件**，而不是 Torque (`.tq`) 文件。 Torque 是 V8 中用于生成高效的 JavaScript 内置函数的领域特定语言。

**与 JavaScript 的功能关系 (示例):**

写屏障是垃圾回收器实现增量标记和并发标记的关键技术。当 JavaScript 代码修改对象之间的引用时，底层的 cppgc 的写屏障机制会被触发，以确保垃圾回收器能够正确地跟踪这些变化。

**JavaScript 示例:**

```javascript
let obj1 = { data: 1 };
let obj2 = { next: null };

// 当执行以下赋值操作时，底层的 C++ 写屏障可能会被触发
// 如果垃圾回收器正在进行标记阶段，它会记录 obj1 被 obj2 引用了
obj2.next = obj1;

// 后续，垃圾回收器在标记阶段会遍历 obj2，并根据写屏障记录的信息找到 obj1，
// 从而确保 obj1 不会被过早回收。
```

**代码逻辑推理 (假设输入与输出):**

考虑 `TEST_F(WriteBarrierTest, TriggersWhenMarkingIsOn)`:

**假设输入:**

1. `object1` 和 `object2` 是两个新分配的、未被标记的 `GCed` 对象。
2. 垃圾回收器的标记阶段正在进行中。

**代码执行:**

1. `ExpectWriteBarrierFires scope(marker(), {object1});`  创建一个作用域，期望当在这个作用域内发生写操作时，`object1` 会被添加到写屏障的工作队列中，最终会被标记。
2. `object2->set_next(object1);`  将 `object1` 的地址赋值给 `object2` 的 `next_` 成员。这是一个写操作，因为它修改了 `object2` 的内部状态。

**预期输出:**

1. 由于标记正在进行且 `object1` 最初未被标记，写屏障被触发。
2. `object1` 的 `HeapObjectHeader` 被添加到写屏障的工作队列中（或者标记工作队列，取决于具体的写屏障实现策略）。
3. 在 `ExpectWriteBarrierFires` 作用域结束时，会检查 `object1` 是否已被标记，以及工作队列是否为空。 预期 `object1` 已被标记，且相关的工作队列已处理完毕。

**用户常见的编程错误 (与写屏障相关):**

虽然用户通常不会直接操作写屏障，但理解写屏障有助于理解垃圾回收的工作原理，并避免可能导致内存泄漏或程序崩溃的错误。

一个与写屏障概念相关的常见编程错误是 **在并发或增量垃圾回收器下，未能正确处理对象引用的更新，导致数据竞争或对象过早回收。**  例如，在手动管理内存的场景中，如果忘记更新引用计数或在多线程环境下不正确地同步对对象引用的修改，就可能出现问题。

在 V8 的 cppgc 中，写屏障的存在很大程度上是为了 **简化开发者处理内存管理的复杂性**。开发者只需要按照正常的面向对象编程方式更新对象引用，底层的写屏障机制会确保垃圾回收的正确性。

然而，理解写屏障的概念可以帮助开发者更好地理解性能问题。例如，频繁地修改对象引用可能会导致写屏障被频繁触发，从而带来一定的性能开销。在性能敏感的场景下，可能需要考虑更高效的数据结构或算法来减少不必要的对象引用修改。

### 提示词
```
这是目录为v8/test/unittests/heap/cppgc/write-barrier-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/heap/cppgc/write-barrier-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
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
```