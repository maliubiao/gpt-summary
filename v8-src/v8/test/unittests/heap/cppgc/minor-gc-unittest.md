Response: Let's break down the thought process for analyzing this C++ unittest file and generating the summary and JavaScript example.

1. **Understand the Core Purpose:** The file name itself, `minor-gc-unittest.cc`, is a strong indicator. It's a unit test file specifically for the "minor garbage collection" functionality within the `cppgc` (C++) garbage collector. The `#if defined(CPPGC_YOUNG_GENERATION)` further reinforces that it's dealing with generational garbage collection, where a "young generation" is a key concept.

2. **Identify Key Concepts and Components:**  Start scanning the code for important terms and classes. Immediately, terms like `MinorGC`, `Young`, `Old`, `RememberedSet`, `AgeTable`, `Persistent`, `GarbageCollected`, `Visitor`, `Heap`, `BasePage`, `NormalPage`, `LargePage`, and macros like `MakeGarbageCollected` stand out. These are the building blocks of the garbage collection system being tested.

3. **Infer Relationships and Functionality:**  Consider how these components interact.
    * **Generational GC:** The "young" and "old" keywords, along with functions like `IsHeapObjectYoung` and `IsHeapObjectOld`, directly point to generational GC. The tests are likely verifying how objects are moved between these generations.
    * **Minor GC Focus:** The tests explicitly call `CollectMinor()`, suggesting the focus is on the efficiency and correctness of minor collections.
    * **Remembered Set:** The `RememberedSetExtractor` and mentions of `remembered_source_objects_` and `remembered_in_construction_objects_` indicate a mechanism to track pointers from older generations to younger ones. This is crucial for minor GC to avoid scanning the entire heap.
    * **Object Lifecycle:** The `SimpleGCedBase` class with its `destructed_objects` counter helps track when objects are collected. `Persistent` likely prevents immediate collection.
    * **Age Table:** The `AgeTable` and functions like `ExpectPageYoung`, `ExpectPageMixed`, `ExpectPageOld` are used to verify the age of memory pages.
    * **Write Barriers:**  Sections dealing with `subtle::HeapConsistency::WriteBarrierType` and `GenerationalBarrierForSourceObject` suggest the testing of write barriers, which are essential for maintaining the correctness of the remembered set.
    * **Weak Callbacks:** The `GCedWithCustomWeakCallback` class shows testing of weak references and their callbacks during GC.
    * **In-Construction Objects:** The `GCOnConstruction` and `InConstructionWithYoungRef` structures highlight tests related to garbage collection happening *during* object construction.

4. **Understand the Testing Methodology:** Notice the use of `gtest` (`TEST_F`, `TYPED_TEST`, `EXPECT_TRUE`, `EXPECT_EQ`). This confirms it's a standard C++ unit test suite. The tests seem to be setting up specific scenarios (allocating objects of different ages, creating inter-generational pointers, etc.) and then running garbage collection (minor and major) while asserting expected outcomes (objects promoted, destructed, remembered sets updated).

5. **Synthesize the Functionality:** Combine the identified concepts and their relationships to form a high-level description. The core functionality is clearly about testing the minor garbage collector in a generational setting.

6. **Identify JavaScript Relevance (The Tricky Part):** This requires understanding how V8 (the JavaScript engine this code is part of) performs garbage collection. Key connections include:
    * **Generational GC in V8:** V8 employs a generational garbage collector with a young generation (often called the "nursery" or "young space") and an old generation. This directly maps to the C++ code's concepts.
    * **Minor GC in V8:** V8 performs frequent minor GCs to collect garbage within the young generation quickly. This aligns perfectly with the focus of the C++ tests.
    * **Remembered Sets/Write Barriers in V8:**  While the implementation details differ, V8 also uses similar mechanisms (like "remembered sets" and "write barriers") to track pointers from the old generation to the young generation, optimizing minor GC performance.
    * **Weak References in JavaScript:** JavaScript has `WeakRef` and `FinalizationRegistry` which serve a purpose similar to the weak callbacks being tested in the C++ code.

7. **Craft the JavaScript Example:**  The goal is to illustrate the *effects* of minor GC as demonstrated by the C++ tests, without needing to delve into C++-level details.
    * **Focus on the Outcome:** The C++ tests show that objects in the young generation are collected by minor GC unless they are referenced from the old generation.
    * **Use JavaScript Equivalents:** Use `let` for variables that might be garbage collected and object properties to simulate pointers.
    * **Demonstrate the Key Scenario:** Create an object in the "young generation" (implicitly, when you create an object in JavaScript). Then, create another object (the "old generation" object) and point to the first object. Show that a "minor GC" (which you can't directly trigger in JavaScript, but the effect is observable) will *not* collect the young object because it's referenced from the old. If the old object doesn't reference the young one, the young one *can* be collected (although this isn't guaranteed immediately in JavaScript). The `globalThis.gc()` (if available and allowed) is a crude way to *suggest* garbage collection for demonstration purposes.

8. **Refine and Explain:** Review the summary and JavaScript example for clarity and accuracy. Ensure the explanation correctly links the C++ functionality to the JavaScript example. Emphasize that the C++ code is *implementing* the underlying mechanism that makes JavaScript's garbage collection work.

By following these steps, we can dissect the C++ code, understand its purpose, and connect it to the higher-level concepts relevant to JavaScript's garbage collection. The key is to move from the specific C++ implementation details to the general principles of generational garbage collection and how those principles manifest in JavaScript.
这个C++源代码文件 `minor-gc-unittest.cc` 是 V8 JavaScript 引擎中 `cppgc` 组件的一个单元测试文件。它的主要功能是**测试 `cppgc` 的 Minor Garbage Collection (Minor GC) 机制的正确性和行为**。

`cppgc` 是 V8 中用于管理 C++ 对象的垃圾回收器，它支持分代垃圾回收（Generational GC），其中 Minor GC 专注于回收年轻代（Young Generation）中的垃圾对象。

**归纳一下它的主要测试点：**

1. **基本 Minor GC 功能:**
   - 测试创建年轻对象，然后执行 Minor GC，验证这些对象是否被正确回收。
   - 测试在没有外部引用的情况下，大量年轻对象能否被 Minor GC 清理。

2. **粘性位 (Sticky Bits) 和对象年龄:**
   - 测试 `Persistent` 对象（类似 JavaScript 中的强引用）在 Minor GC 后是否仍然存活，并且其年龄会提升（从年轻代到老年代）。
   - 测试老年代对象在 Minor GC 期间不会被访问。

3. **跨代指针 (Inter-generational Pointers):**
   - 测试老年代对象持有指向年轻代对象的指针时，Minor GC 如何处理。这涉及到 **Remembered Set** 的机制，用于记录老年代到年轻代的指针，确保年轻代对象不会被错误回收。
   - 测试在老年代对象更新指向年轻代对象的指针时，是否正确地将相关信息添加到 Remembered Set。
   - 测试在老年代对象不再指向年轻代对象后，Remembered Set 是否会更新。

4. **省略代间屏障 (Omit Generational Barrier):**
   - 测试对于栈上分配的对象或者哨兵值（如 `nullptr`），是否会省略代间屏障的操作，因为它们不需要被 Remembered Set 追踪。

5. **Remembered Set 的失效和清理:**
   - 测试当老年代对象被回收或缩小时，指向其内部的 Remembered Set 条目是否会被正确清理，避免悬空指针。

6. **内联对象和延迟追踪 (Inlined Objects and Deferred Tracing):**
   - 测试包含内联对象的场景下，Minor GC 如何处理，以及代间屏障如何影响内联对象的追踪。

7. **自定义弱回调 (Custom Weak Callbacks):**
   - 测试在 Minor GC 中自定义弱回调函数的执行情况。

8. **年龄表 (Age Table) 的重置:**
   - 测试在 Minor GC 后，内存页的年龄是否会被更新，以及 Major GC 后所有页面的年龄状态。

9. **构造中对象 (In-Construction Objects):**
   - 测试在对象构造过程中触发 GC 的情况，确保构造中的对象和其引用的年轻对象不会被错误回收。

**与 JavaScript 功能的关系以及 JavaScript 例子:**

这个 C++ 文件测试的是 V8 引擎的底层垃圾回收机制，直接影响着 JavaScript 的内存管理和性能。Minor GC 的效率直接关系到 JavaScript 程序的运行流畅度，因为它能快速回收大部分临时对象。

**JavaScript 例子：**

```javascript
// 模拟年轻代对象
let youngObject = { data: '一些数据' };

// 模拟老年代对象
let oldObject = { ref: null };

// 老年代对象引用年轻代对象
oldObject.ref = youngObject;

// 此时，即使执行 Minor GC (JavaScript 中无法直接触发，但引擎会自动执行)，
// youngObject 也不会被回收，因为它被老年代对象引用着。

// 清除老年代对象的引用
oldObject.ref = null;

// 现在，youngObject 变成了孤立的年轻代对象，
// 在下一次 Minor GC 时，很可能会被回收。

// 可以通过 Performance API 观察内存变化，间接了解 GC 的发生
// performance.measure('beforeGC');
// ... 执行一些可能产生垃圾的操作 ...
// performance.measure('afterGC');
// let measure = performance.getEntriesByName('afterGC')[0];
// console.log(measure.duration);

// 注意：JavaScript 中无法精确控制 Minor GC 的触发和行为，
//       这里只是概念上的对应。
```

**解释 JavaScript 例子与 C++ 测试的关联：**

- **`youngObject` 对应 C++ 测试中分配的年轻对象。**
- **`oldObject` 对应 C++ 测试中分配的老年代对象。**
- **`oldObject.ref = youngObject;` 模拟了 C++ 测试中的跨代指针，即老年代对象指向年轻代对象。** 在 C++ 的测试中，这会导致 Remembered Set 被更新，以保护 `youngObject` 不被 Minor GC 回收。
- **`oldObject.ref = null;` 移除了跨代引用，使得 `youngObject` 成为 Minor GC 的潜在回收目标。** 这对应 C++ 测试中 Remembered Set 的更新和清理。

总而言之，`minor-gc-unittest.cc` 通过一系列细致的测试用例，确保 V8 的 `cppgc` 组件能够正确高效地执行 Minor GC，这是 JavaScript 内存管理的关键组成部分，直接影响着 JavaScript 程序的性能和稳定性。它验证了在各种复杂场景下，年轻对象的回收和跨代引用的处理是否符合预期。

Prompt: 
```
这是目录为v8/test/unittests/heap/cppgc/minor-gc-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if defined(CPPGC_YOUNG_GENERATION)

#include <initializer_list>
#include <vector>

#include "include/cppgc/allocation.h"
#include "include/cppgc/explicit-management.h"
#include "include/cppgc/heap-consistency.h"
#include "include/cppgc/internal/caged-heap-local-data.h"
#include "include/cppgc/persistent.h"
#include "src/heap/cppgc/heap-object-header.h"
#include "src/heap/cppgc/heap-visitor.h"
#include "src/heap/cppgc/heap.h"
#include "test/unittests/heap/cppgc/tests.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace cppgc {
namespace internal {

namespace {

bool IsHeapObjectYoung(void* obj) {
  return HeapObjectHeader::FromObject(obj).IsYoung();
}

bool IsHeapObjectOld(void* obj) { return !IsHeapObjectYoung(obj); }

class SimpleGCedBase : public GarbageCollected<SimpleGCedBase> {
 public:
  static size_t destructed_objects;

  virtual ~SimpleGCedBase() { ++destructed_objects; }

  virtual void Trace(Visitor* v) const { v->Trace(next); }

  Member<SimpleGCedBase> next;
};

size_t SimpleGCedBase::destructed_objects;

template <size_t Size>
class SimpleGCed : public SimpleGCedBase {
  char array[Size];
};

using Small = SimpleGCed<64>;
using Large = SimpleGCed<kLargeObjectSizeThreshold * 2>;

template <typename Type>
struct OtherType;
template <>
struct OtherType<Small> {
  using Type = Large;
};
template <>
struct OtherType<Large> {
  using Type = Small;
};

void ExpectPageYoung(BasePage& page) {
  EXPECT_TRUE(page.contains_young_objects());
  auto& age_table = CagedHeapLocalData::Get().age_table;
  EXPECT_EQ(AgeTable::Age::kYoung,
            age_table.GetAgeForRange(
                CagedHeap::OffsetFromAddress(page.PayloadStart()),
                CagedHeap::OffsetFromAddress(page.PayloadEnd())));
}

void ExpectPageMixed(BasePage& page) {
  EXPECT_TRUE(page.contains_young_objects());
  auto& age_table = CagedHeapLocalData::Get().age_table;
  EXPECT_EQ(AgeTable::Age::kMixed,
            age_table.GetAgeForRange(
                CagedHeap::OffsetFromAddress(page.PayloadStart()),
                CagedHeap::OffsetFromAddress(page.PayloadEnd())));
}

void ExpectPageOld(BasePage& page) {
  EXPECT_FALSE(page.contains_young_objects());
  auto& age_table = CagedHeapLocalData::Get().age_table;
  EXPECT_EQ(AgeTable::Age::kOld,
            age_table.GetAgeForRange(
                CagedHeap::OffsetFromAddress(page.PayloadStart()),
                CagedHeap::OffsetFromAddress(page.PayloadEnd())));
}

class RememberedSetExtractor : HeapVisitor<RememberedSetExtractor> {
  friend class HeapVisitor<RememberedSetExtractor>;

 public:
  static std::set<void*> Extract(cppgc::Heap* heap) {
    RememberedSetExtractor extractor;
    extractor.Traverse(Heap::From(heap)->raw_heap());
    return std::move(extractor.slots_);
  }

 private:
  void VisitPage(BasePage& page) {
    auto* slot_set = page.slot_set();
    if (!slot_set) return;

    const uintptr_t page_start = reinterpret_cast<uintptr_t>(&page);
    const size_t buckets_size = SlotSet::BucketsForSize(page.AllocatedSize());

    slot_set->Iterate(
        page_start, 0, buckets_size,
        [this](SlotSet::Address slot) {
          slots_.insert(reinterpret_cast<void*>(slot));
          return heap::base::KEEP_SLOT;
        },
        SlotSet::EmptyBucketMode::FREE_EMPTY_BUCKETS);
  }

  bool VisitNormalPage(NormalPage& page) {
    VisitPage(page);
    return true;
  }

  bool VisitLargePage(LargePage& page) {
    VisitPage(page);
    return true;
  }

  std::set<void*> slots_;
};

}  // namespace

class MinorGCTest : public testing::TestWithHeap {
 public:
  MinorGCTest() : testing::TestWithHeap() {
    // Enable young generation flag and run GC. After the first run the heap
    // will enable minor GC.
    Heap::From(GetHeap())->EnableGenerationalGC();
    CollectMajor();

    SimpleGCedBase::destructed_objects = 0;
  }

  ~MinorGCTest() override { Heap::From(GetHeap())->Terminate(); }

  static size_t DestructedObjects() {
    return SimpleGCedBase::destructed_objects;
  }

  void CollectMinor() {
    Heap::From(GetHeap())->CollectGarbage(GCConfig::MinorPreciseAtomicConfig());
  }

  void CollectMinorWithStack() {
    Heap::From(GetHeap())->CollectGarbage(
        GCConfig::MinorConservativeAtomicConfig());
  }

  void CollectMajor() {
    Heap::From(GetHeap())->CollectGarbage(GCConfig::PreciseAtomicConfig());
  }

  void CollectMajorWithStack() {
    Heap::From(GetHeap())->CollectGarbage(GCConfig::ConservativeAtomicConfig());
  }

  const auto& RememberedSourceObjects() const {
    return Heap::From(GetHeap())->remembered_set().remembered_source_objects_;
  }

  const auto& RememberedInConstructionObjects() const {
    return Heap::From(GetHeap())
        ->remembered_set()
        .remembered_in_construction_objects_.previous;
  }
};

template <typename SmallOrLarge>
class MinorGCTestForType : public MinorGCTest {
 public:
  using Type = SmallOrLarge;
};

using ObjectTypes = ::testing::Types<Small, Large>;
TYPED_TEST_SUITE(MinorGCTestForType, ObjectTypes);

namespace {

enum class GCType {
  kMinor,
  kMajor,
};

enum class StackType {
  kWithout,
  kWith,
};

template <GCType gc_type, StackType stack_type, typename... Args>
void RunGCAndExpectObjectsPromoted(MinorGCTest& test, Args*... args) {
  EXPECT_TRUE((IsHeapObjectYoung(args) && ...));
  if constexpr (gc_type == GCType::kMajor) {
    if constexpr (stack_type == StackType::kWithout) {
      test.CollectMajor();
    } else {
      test.CollectMajorWithStack();
    }
  } else {
    if constexpr (stack_type == StackType::kWithout) {
      test.CollectMinor();
    } else {
      test.CollectMinorWithStack();
    }
  }
  EXPECT_TRUE((IsHeapObjectOld(args) && ...));
}

struct ExpectRememberedSlotsAdded final {
  ExpectRememberedSlotsAdded(
      const MinorGCTest& test,
      std::initializer_list<void*> slots_expected_to_be_remembered)
      : test_(test),
        slots_expected_to_be_remembered_(slots_expected_to_be_remembered),
        initial_slots_(RememberedSetExtractor::Extract(test.GetHeap())) {
    // Check that the remembered set doesn't contain specified slots.
    EXPECT_FALSE(std::includes(initial_slots_.begin(), initial_slots_.end(),
                               slots_expected_to_be_remembered_.begin(),
                               slots_expected_to_be_remembered_.end()));
  }

  ~ExpectRememberedSlotsAdded() {
    const auto current_slots = RememberedSetExtractor::Extract(test_.GetHeap());
    EXPECT_EQ(initial_slots_.size() + slots_expected_to_be_remembered_.size(),
              current_slots.size());
    EXPECT_TRUE(std::includes(current_slots.begin(), current_slots.end(),
                              slots_expected_to_be_remembered_.begin(),
                              slots_expected_to_be_remembered_.end()));
  }

 private:
  const MinorGCTest& test_;
  std::set<void*> slots_expected_to_be_remembered_;
  std::set<void*> initial_slots_;
};

struct ExpectRememberedSlotsRemoved final {
  ExpectRememberedSlotsRemoved(
      const MinorGCTest& test,
      std::initializer_list<void*> slots_expected_to_be_removed)
      : test_(test),
        slots_expected_to_be_removed_(slots_expected_to_be_removed),
        initial_slots_(RememberedSetExtractor::Extract(test.GetHeap())) {
    DCHECK_GE(initial_slots_.size(), slots_expected_to_be_removed_.size());
    // Check that the remembered set does contain specified slots to be removed.
    EXPECT_TRUE(std::includes(initial_slots_.begin(), initial_slots_.end(),
                              slots_expected_to_be_removed_.begin(),
                              slots_expected_to_be_removed_.end()));
  }

  ~ExpectRememberedSlotsRemoved() {
    const auto current_slots = RememberedSetExtractor::Extract(test_.GetHeap());
    EXPECT_EQ(initial_slots_.size() - slots_expected_to_be_removed_.size(),
              current_slots.size());
    EXPECT_FALSE(std::includes(current_slots.begin(), current_slots.end(),
                               slots_expected_to_be_removed_.begin(),
                               slots_expected_to_be_removed_.end()));
  }

 private:
  const MinorGCTest& test_;
  std::set<void*> slots_expected_to_be_removed_;
  std::set<void*> initial_slots_;
};

struct ExpectNoRememberedSlotsAdded final {
  explicit ExpectNoRememberedSlotsAdded(const MinorGCTest& test)
      : test_(test),
        initial_remembered_slots_(
            RememberedSetExtractor::Extract(test.GetHeap())) {}

  ~ExpectNoRememberedSlotsAdded() {
    EXPECT_EQ(initial_remembered_slots_,
              RememberedSetExtractor::Extract(test_.GetHeap()));
  }

 private:
  const MinorGCTest& test_;
  std::set<void*> initial_remembered_slots_;
};

}  // namespace

TYPED_TEST(MinorGCTestForType, MinorCollection) {
  using Type = typename TestFixture::Type;

  MakeGarbageCollected<Type>(this->GetAllocationHandle());
  EXPECT_EQ(0u, TestFixture::DestructedObjects());
  MinorGCTest::CollectMinor();
  EXPECT_EQ(1u, TestFixture::DestructedObjects());

  {
    subtle::NoGarbageCollectionScope no_gc_scope(*Heap::From(this->GetHeap()));

    Type* prev = nullptr;
    for (size_t i = 0; i < 64; ++i) {
      auto* ptr = MakeGarbageCollected<Type>(this->GetAllocationHandle());
      ptr->next = prev;
      prev = ptr;
    }
  }

  MinorGCTest::CollectMinor();
  EXPECT_EQ(65u, TestFixture::DestructedObjects());
}

TYPED_TEST(MinorGCTestForType, StickyBits) {
  using Type = typename TestFixture::Type;

  Persistent<Type> p1 = MakeGarbageCollected<Type>(this->GetAllocationHandle());
  TestFixture::CollectMinor();
  EXPECT_FALSE(HeapObjectHeader::FromObject(p1.Get()).IsYoung());
  TestFixture::CollectMajor();
  EXPECT_FALSE(HeapObjectHeader::FromObject(p1.Get()).IsYoung());
  EXPECT_EQ(0u, TestFixture::DestructedObjects());
}

TYPED_TEST(MinorGCTestForType, OldObjectIsNotVisited) {
  using Type = typename TestFixture::Type;

  Persistent<Type> p = MakeGarbageCollected<Type>(this->GetAllocationHandle());
  TestFixture::CollectMinor();
  EXPECT_EQ(0u, TestFixture::DestructedObjects());
  EXPECT_FALSE(HeapObjectHeader::FromObject(p.Get()).IsYoung());

  // Check that the old deleted object won't be visited during minor GC.
  Type* raw = p.Release();
  TestFixture::CollectMinor();
  EXPECT_EQ(0u, TestFixture::DestructedObjects());
  EXPECT_FALSE(HeapObjectHeader::FromObject(raw).IsYoung());
  EXPECT_FALSE(HeapObjectHeader::FromObject(raw).IsFree());

  // Check that the old deleted object will be revisited in major GC.
  TestFixture::CollectMajor();
  EXPECT_EQ(1u, TestFixture::DestructedObjects());
}

template <typename Type1, typename Type2>
void InterGenerationalPointerTest(MinorGCTest* test, cppgc::Heap* heap) {
  Persistent<Type1> old =
      MakeGarbageCollected<Type1>(heap->GetAllocationHandle());
  test->CollectMinor();
  EXPECT_FALSE(HeapObjectHeader::FromObject(old.Get()).IsYoung());

  Type2* young = nullptr;

  {
    subtle::NoGarbageCollectionScope no_gc_scope(*Heap::From(heap));

    // Allocate young objects.
    for (size_t i = 0; i < 64; ++i) {
      auto* ptr = MakeGarbageCollected<Type2>(heap->GetAllocationHandle());
      ptr->next = young;
      young = ptr;
      EXPECT_TRUE(HeapObjectHeader::FromObject(young).IsYoung());
      const uintptr_t offset = CagedHeap::OffsetFromAddress(young);
      // Age may be young or unknown.
      EXPECT_NE(AgeTable::Age::kOld,
                CagedHeapLocalData::Get().age_table.GetAge(offset));
    }
  }

  auto remembered_set_size_before_barrier =
      RememberedSetExtractor::Extract(test->GetHeap()).size();

  // Issue generational barrier.
  old->next = young;

  auto remembered_set_size_after_barrier =
      RememberedSetExtractor::Extract(test->GetHeap()).size();

  EXPECT_EQ(remembered_set_size_before_barrier + 1u,
            remembered_set_size_after_barrier);

  // Check that the remembered set is visited.
  test->CollectMinor();

  EXPECT_EQ(0u, MinorGCTest::DestructedObjects());
  EXPECT_TRUE(RememberedSetExtractor::Extract(test->GetHeap()).empty());

  for (size_t i = 0; i < 64; ++i) {
    EXPECT_FALSE(HeapObjectHeader::FromObject(young).IsFree());
    EXPECT_FALSE(HeapObjectHeader::FromObject(young).IsYoung());
    young = static_cast<Type2*>(young->next.Get());
  }

  old.Release();
  test->CollectMajor();
  EXPECT_EQ(65u, MinorGCTest::DestructedObjects());
}

TYPED_TEST(MinorGCTestForType, InterGenerationalPointerForSamePageTypes) {
  using Type = typename TestFixture::Type;
  InterGenerationalPointerTest<Type, Type>(this, this->GetHeap());
}

TYPED_TEST(MinorGCTestForType, InterGenerationalPointerForDifferentPageTypes) {
  using Type = typename TestFixture::Type;
  InterGenerationalPointerTest<Type, typename OtherType<Type>::Type>(
      this, this->GetHeap());
}

TYPED_TEST(MinorGCTestForType, OmitGenerationalBarrierForOnStackObject) {
  using Type = typename TestFixture::Type;

  class StackAllocated : GarbageCollected<StackAllocated> {
    CPPGC_STACK_ALLOCATED();

   public:
    Type* ptr = nullptr;
  } stack_object;

  // Try issuing generational barrier for on-stack object.
  stack_object.ptr = MakeGarbageCollected<Type>(this->GetAllocationHandle());
  subtle::HeapConsistency::WriteBarrierParams params;
  EXPECT_EQ(subtle::HeapConsistency::WriteBarrierType::kNone,
            subtle::HeapConsistency::GetWriteBarrierType(
                reinterpret_cast<void*>(&stack_object.ptr), stack_object.ptr,
                params));
}

TYPED_TEST(MinorGCTestForType, OmitGenerationalBarrierForSentinels) {
  using Type = typename TestFixture::Type;

  Persistent<Type> old =
      MakeGarbageCollected<Type>(this->GetAllocationHandle());

  TestFixture::CollectMinor();
  EXPECT_FALSE(HeapObjectHeader::FromObject(old.Get()).IsYoung());

  {
    ExpectNoRememberedSlotsAdded _(*this);
    // Try issuing generational barrier for nullptr.
    old->next = static_cast<Type*>(nullptr);
  }
  {
    ExpectNoRememberedSlotsAdded _(*this);
    // Try issuing generational barrier for sentinel.
    old->next = kSentinelPointer;
  }
}

template <typename From, typename To>
void TestRememberedSetInvalidation(MinorGCTest& test) {
  Persistent<From> old = MakeGarbageCollected<From>(test.GetAllocationHandle());

  test.CollectMinor();

  auto* young = MakeGarbageCollected<To>(test.GetAllocationHandle());

  {
    ExpectRememberedSlotsAdded _(test, {old->next.GetSlotForTesting()});
    // Issue the generational barrier.
    old->next = young;
  }

  {
    ExpectRememberedSlotsRemoved _(test, {old->next.GetSlotForTesting()});
    // Release the persistent and free the old object.
    auto* old_raw = old.Release();
    subtle::FreeUnreferencedObject(test.GetHeapHandle(), *old_raw);
  }

  // Visiting remembered slots must not fail.
  test.CollectMinor();
}

TYPED_TEST(MinorGCTestForType, RememberedSetInvalidationOnPromptlyFree) {
  using Type1 = typename TestFixture::Type;
  using Type2 = typename OtherType<Type1>::Type;
  TestRememberedSetInvalidation<Type1, Type1>(*this);
  TestRememberedSetInvalidation<Type1, Type2>(*this);
}

TEST_F(MinorGCTest, RememberedSetInvalidationOnShrink) {
  using Member = Member<Small>;

  static constexpr size_t kTrailingMembers = 64;
  static constexpr size_t kBytesToAllocate = kTrailingMembers * sizeof(Member);

  static constexpr size_t kFirstMemberToInvalidate = kTrailingMembers / 2;
  static constexpr size_t kLastMemberToInvalidate = kTrailingMembers;

  // Create an object with additional kBytesToAllocate bytes.
  Persistent<Small> old = MakeGarbageCollected<Small>(
      this->GetAllocationHandle(), AdditionalBytes(kBytesToAllocate));

  auto get_member = [&old](size_t i) -> Member& {
    return *reinterpret_cast<Member*>(reinterpret_cast<uint8_t*>(old.Get()) +
                                      sizeof(Small) + i * sizeof(Member));
  };

  CollectMinor();

  auto* young = MakeGarbageCollected<Small>(GetAllocationHandle());

  const size_t remembered_set_size_before_barrier =
      RememberedSetExtractor::Extract(GetHeap()).size();

  // Issue the generational barriers.
  for (size_t i = kFirstMemberToInvalidate; i < kLastMemberToInvalidate; ++i) {
    // Construct the member.
    new (&get_member(i)) Member;
    // Issue the barrier.
    get_member(i) = young;
  }

  const auto remembered_set_size_after_barrier =
      RememberedSetExtractor::Extract(GetHeap()).size();

  // Check that barriers hit (kLastMemberToInvalidate -
  // kFirstMemberToInvalidate) times.
  EXPECT_EQ(remembered_set_size_before_barrier +
                (kLastMemberToInvalidate - kFirstMemberToInvalidate),
            remembered_set_size_after_barrier);

  // Shrink the buffer for old object.
  subtle::Resize(*old, AdditionalBytes(kBytesToAllocate / 2));

  const auto remembered_set_after_shrink =
      RememberedSetExtractor::Extract(GetHeap()).size();

  // Check that the reference was invalidated.
  EXPECT_EQ(remembered_set_size_before_barrier, remembered_set_after_shrink);

  // Visiting remembered slots must not fail.
  CollectMinor();
}

namespace {

template <typename Value>
struct InlinedObject {
  struct Inner {
    Inner() = default;
    explicit Inner(AllocationHandle& handle)
        : ref(MakeGarbageCollected<Value>(handle)) {}

    void Trace(Visitor* v) const { v->Trace(ref); }

    double d = -1.;
    Member<Value> ref;
  };

  InlinedObject() = default;
  explicit InlinedObject(AllocationHandle& handle)
      : ref(MakeGarbageCollected<Value>(handle)), inner(handle) {}

  void Trace(cppgc::Visitor* v) const {
    v->Trace(ref);
    v->Trace(inner);
  }

  int a_ = -1;
  Member<Value> ref;
  Inner inner;
};

template <typename Value>
class GCedWithInlinedArray
    : public GarbageCollected<GCedWithInlinedArray<Value>> {
 public:
  static constexpr size_t kNumObjects = 16;

  GCedWithInlinedArray(HeapHandle& heap_handle, AllocationHandle& alloc_handle)
      : heap_handle_(heap_handle), alloc_handle_(alloc_handle) {}

  using WriteBarrierParams = subtle::HeapConsistency::WriteBarrierParams;
  using HeapConsistency = subtle::HeapConsistency;

  void SetInPlaceRange(size_t from, size_t to) {
    DCHECK_GT(to, from);
    DCHECK_GT(kNumObjects, from);

    for (; from != to; ++from)
      new (&objects[from]) InlinedObject<Value>(alloc_handle_);

    GenerationalBarrierForSourceObject(&objects[from]);
  }

  void Trace(cppgc::Visitor* v) const {
    for (const auto& object : objects) v->Trace(object);
  }

  InlinedObject<Value> objects[kNumObjects];

 private:
  void GenerationalBarrierForSourceObject(void* object) {
    DCHECK(object);
    WriteBarrierParams params;
    const auto barrier_type = HeapConsistency::GetWriteBarrierType(
        object, params, [this]() -> HeapHandle& { return heap_handle_; });
    EXPECT_EQ(HeapConsistency::WriteBarrierType::kGenerational, barrier_type);
    HeapConsistency::GenerationalBarrierForSourceObject(params, object);
  }

  HeapHandle& heap_handle_;
  AllocationHandle& alloc_handle_;
};

}  // namespace

TYPED_TEST(MinorGCTestForType, GenerationalBarrierDeferredTracing) {
  using Type = typename TestFixture::Type;

  Persistent<GCedWithInlinedArray<Type>> array =
      MakeGarbageCollected<GCedWithInlinedArray<Type>>(
          this->GetAllocationHandle(), this->GetHeapHandle(),
          this->GetAllocationHandle());

  this->CollectMinor();

  EXPECT_TRUE(IsHeapObjectOld(array.Get()));

  const auto& remembered_objects = this->RememberedSourceObjects();
  {
    ExpectNoRememberedSlotsAdded _(*this);
    EXPECT_EQ(0u, remembered_objects.count(
                      &HeapObjectHeader::FromObject(array->objects)));

    array->SetInPlaceRange(2, 4);

    EXPECT_EQ(1u, remembered_objects.count(
                      &HeapObjectHeader::FromObject(array->objects)));
  }

  RunGCAndExpectObjectsPromoted<GCType::kMinor, StackType::kWithout>(
      *this, array->objects[2].ref.Get(), array->objects[2].inner.ref.Get(),
      array->objects[3].ref.Get(), array->objects[3].inner.ref.Get());

  EXPECT_EQ(0u, remembered_objects.size());
}

namespace {
class GCedWithCustomWeakCallback final
    : public GarbageCollected<GCedWithCustomWeakCallback> {
 public:
  static size_t custom_callback_called;

  void CustomWeakCallbackMethod(const LivenessBroker& broker) {
    custom_callback_called++;
  }

  void Trace(cppgc::Visitor* visitor) const {
    visitor->RegisterWeakCallbackMethod<
        GCedWithCustomWeakCallback,
        &GCedWithCustomWeakCallback::CustomWeakCallbackMethod>(this);
  }
};
size_t GCedWithCustomWeakCallback::custom_callback_called = 0;
}  // namespace

TEST_F(MinorGCTest, ReexecuteCustomCallback) {
  // Create an object with additional kBytesToAllocate bytes.
  Persistent<GCedWithCustomWeakCallback> old =
      MakeGarbageCollected<GCedWithCustomWeakCallback>(GetAllocationHandle());

  CollectMinor();
  EXPECT_EQ(1u, GCedWithCustomWeakCallback::custom_callback_called);

  CollectMinor();
  EXPECT_EQ(2u, GCedWithCustomWeakCallback::custom_callback_called);

  CollectMinor();
  EXPECT_EQ(3u, GCedWithCustomWeakCallback::custom_callback_called);

  CollectMajor();
  // The callback must be called only once.
  EXPECT_EQ(4u, GCedWithCustomWeakCallback::custom_callback_called);
}

TEST_F(MinorGCTest, AgeTableIsReset) {
  using Type1 = SimpleGCed<16>;
  using Type2 = SimpleGCed<64>;
  using Type3 = SimpleGCed<kLargeObjectSizeThreshold * 2>;

  Persistent<Type1> p1 = MakeGarbageCollected<Type1>(GetAllocationHandle());
  Persistent<Type2> p2 = MakeGarbageCollected<Type2>(GetAllocationHandle());
  Persistent<Type3> p3 = MakeGarbageCollected<Type3>(GetAllocationHandle());

  auto* page1 = BasePage::FromPayload(p1.Get());
  auto* page2 = BasePage::FromPayload(p2.Get());
  auto* page3 = BasePage::FromPayload(p3.Get());

  ASSERT_FALSE(page1->is_large());
  ASSERT_FALSE(page2->is_large());
  ASSERT_TRUE(page3->is_large());

  ASSERT_NE(page1, page2);
  ASSERT_NE(page1, page3);
  ASSERT_NE(page2, page3);

  // First, expect all the pages to be young.
  ExpectPageYoung(*page1);
  ExpectPageYoung(*page2);
  ExpectPageYoung(*page3);

  CollectMinor();

  // Expect pages to be promoted after the minor GC.
  ExpectPageOld(*page1);
  ExpectPageOld(*page2);
  ExpectPageOld(*page3);

  // Allocate another objects on the normal pages and a new large page.
  p1 = MakeGarbageCollected<Type1>(GetAllocationHandle());
  p2 = MakeGarbageCollected<Type2>(GetAllocationHandle());
  p3 = MakeGarbageCollected<Type3>(GetAllocationHandle());

  // Expect now the normal pages to be mixed.
  ExpectPageMixed(*page1);
  ExpectPageMixed(*page2);
  // The large page must remain old.
  ExpectPageOld(*page3);

  CollectMajor();

  // After major GC all the pages must also become old.
  ExpectPageOld(*page1);
  ExpectPageOld(*page2);
  ExpectPageOld(*BasePage::FromPayload(p3.Get()));
}

namespace {

template <GCType type>
struct GCOnConstruction {
  explicit GCOnConstruction(MinorGCTest& test, size_t depth) {
    if constexpr (type == GCType::kMajor) {
      test.CollectMajorWithStack();
    } else {
      test.CollectMinorWithStack();
    }
    EXPECT_EQ(depth, test.RememberedInConstructionObjects().size());
  }
};

template <GCType type>
struct InConstructionWithYoungRef
    : GarbageCollected<InConstructionWithYoungRef<type>> {
  using ValueType = SimpleGCed<64>;

  explicit InConstructionWithYoungRef(MinorGCTest& test)
      : call_gc(test, 1u),
        m(MakeGarbageCollected<ValueType>(test.GetAllocationHandle())) {}

  void Trace(Visitor* v) const { v->Trace(m); }

  GCOnConstruction<type> call_gc;
  Member<ValueType> m;
};

}  // namespace

TEST_F(MinorGCTest, RevisitInConstructionObjectsMinorMinorWithStack) {
  static constexpr auto kFirstGCType = GCType::kMinor;

  auto* gced = MakeGarbageCollected<InConstructionWithYoungRef<kFirstGCType>>(
      GetAllocationHandle(), *this);

  RunGCAndExpectObjectsPromoted<GCType::kMinor, StackType::kWith>(
      *this, gced->m.Get());

  EXPECT_EQ(0u, RememberedInConstructionObjects().size());
}

TEST_F(MinorGCTest, RevisitInConstructionObjectsMinorMinorWithoutStack) {
  static constexpr auto kFirstGCType = GCType::kMinor;

  Persistent<InConstructionWithYoungRef<kFirstGCType>> gced =
      MakeGarbageCollected<InConstructionWithYoungRef<kFirstGCType>>(
          GetAllocationHandle(), *this);

  RunGCAndExpectObjectsPromoted<GCType::kMinor, StackType::kWithout>(
      *this, gced->m.Get());

  EXPECT_EQ(0u, RememberedInConstructionObjects().size());
}

TEST_F(MinorGCTest, RevisitInConstructionObjectsMajorMinorWithStack) {
  static constexpr auto kFirstGCType = GCType::kMajor;

  auto* gced = MakeGarbageCollected<InConstructionWithYoungRef<kFirstGCType>>(
      GetAllocationHandle(), *this);

  RunGCAndExpectObjectsPromoted<GCType::kMinor, StackType::kWith>(
      *this, gced->m.Get());

  EXPECT_EQ(0u, RememberedInConstructionObjects().size());
}

TEST_F(MinorGCTest, RevisitInConstructionObjectsMajorMinorWithoutStack) {
  static constexpr auto kFirstGCType = GCType::kMajor;

  Persistent<InConstructionWithYoungRef<kFirstGCType>> gced =
      MakeGarbageCollected<InConstructionWithYoungRef<kFirstGCType>>(
          GetAllocationHandle(), *this);

  RunGCAndExpectObjectsPromoted<GCType::kMinor, StackType::kWithout>(
      *this, gced->m.Get());

  EXPECT_EQ(0u, RememberedInConstructionObjects().size());
}

TEST_F(MinorGCTest, PreviousInConstructionObjectsAreDroppedAfterFullGC) {
  MakeGarbageCollected<InConstructionWithYoungRef<GCType::kMinor>>(
      GetAllocationHandle(), *this);

  EXPECT_EQ(1u, RememberedInConstructionObjects().size());

  CollectMajor();

  EXPECT_EQ(0u, RememberedInConstructionObjects().size());
}

namespace {

template <GCType type>
struct NestedInConstructionWithYoungRef
    : GarbageCollected<NestedInConstructionWithYoungRef<type>> {
  using ValueType = SimpleGCed<64>;

  NestedInConstructionWithYoungRef(MinorGCTest& test, size_t depth)
      : NestedInConstructionWithYoungRef(test, 1, depth) {}

  NestedInConstructionWithYoungRef(MinorGCTest& test, size_t current_depth,
                                   size_t max_depth)
      : current_depth(current_depth),
        max_depth(max_depth),
        next(current_depth != max_depth
                 ? MakeGarbageCollected<NestedInConstructionWithYoungRef<type>>(
                       test.GetAllocationHandle(), test, current_depth + 1,
                       max_depth)
                 : nullptr),
        call_gc(test, current_depth),
        m(MakeGarbageCollected<ValueType>(test.GetAllocationHandle())) {}

  void Trace(Visitor* v) const {
    v->Trace(next);
    v->Trace(m);
  }

  size_t current_depth = 0;
  size_t max_depth = 0;

  Member<NestedInConstructionWithYoungRef<type>> next;
  GCOnConstruction<type> call_gc;
  Member<ValueType> m;
};

}  // namespace

TEST_F(MinorGCTest, RevisitNestedInConstructionObjects) {
  static constexpr auto kFirstGCType = GCType::kMinor;

  Persistent<NestedInConstructionWithYoungRef<kFirstGCType>> gced =
      MakeGarbageCollected<NestedInConstructionWithYoungRef<kFirstGCType>>(
          GetAllocationHandle(), *this, 10);

  CollectMinor();

  for (auto* p = gced.Get(); p; p = p->next.Get()) {
    EXPECT_TRUE(IsHeapObjectOld(p));
    EXPECT_TRUE(IsHeapObjectOld(p->m));
  }

  EXPECT_EQ(0u, RememberedInConstructionObjects().size());
}

}  // namespace internal
}  // namespace cppgc

#endif

"""

```