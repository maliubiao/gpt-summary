Response:
Let's break down the thought process for analyzing the C++ code and generating the requested information.

1. **Understanding the Request:** The core request is to analyze a C++ unit test file for a garbage collector (cppgc) focusing on minor garbage collection. The request also includes specific conditions (filename ending in `.tq`, relation to Javascript, code logic inference, common programming errors).

2. **Initial File Examination:**  The first step is to read through the code, paying attention to:
    * **Includes:**  These reveal the dependencies and high-level components being tested (e.g., `cppgc/allocation.h`, `cppgc/heap.h`, `testing/gtest/gtest.h`). The `#if defined(CPPGC_YOUNG_GENERATION)` is a key indicator that this code is specifically related to the "young generation" feature of the garbage collector.
    * **Namespaces:**  `cppgc::internal` tells us this is testing internal implementation details.
    * **Test Fixture (`MinorGCTest`):** This class sets up the testing environment. The constructor initializes the heap with generational GC enabled and the destructor terminates it. Methods like `CollectMinor`, `CollectMajor`, `DestructedObjects` are crucial for the testing logic.
    * **Helper Classes/Functions:**  `SimpleGCedBase`, `SimpleGCed`, `IsHeapObjectYoung`, `IsHeapObjectOld`, `ExpectPageYoung/Mixed/Old`, `RememberedSetExtractor` all provide utility for the tests. Understanding their purpose is vital.
    * **`TYPED_TEST` and `TEST_F`:** These are Google Test macros, confirming this is indeed a unit test file. The tests themselves (like `MinorCollection`, `StickyBits`, etc.) show the specific scenarios being tested.

3. **Identifying Core Functionality:** Based on the initial examination, the primary purpose is to test the **minor garbage collection** functionality of the cppgc. Key aspects being tested include:
    * **Object Lifecycles:**  Whether young objects are collected during minor GC and whether old objects are left alone.
    * **Object Promotion:** How objects move from the young generation to the old generation.
    * **Remembered Sets:** How the garbage collector tracks pointers from old objects to young objects (generational barriers). The tests around `ExpectRememberedSlotsAdded` and `ExpectRememberedSlotsRemoved` are strong indicators of this.
    * **Weak Callbacks:** Testing the execution of weak callbacks during minor GC.
    * **Age Table:** How the heap tracks the age of memory pages.
    * **In-Construction Objects:** How the GC handles objects being constructed when a GC occurs.

4. **Addressing Specific Request Points:**

    * **`.tq` extension:** The code clearly uses `.cc`, so it's C++ source, *not* Torque.
    * **Relationship to Javascript:**  While this is C++ code, cppgc is the C++ garbage collector used by V8 (the Javascript engine). Therefore, this code *directly* supports Javascript's memory management. The example provided shows a simple Javascript object and how V8's GC (using cppgc under the hood) would reclaim its memory.
    * **Code Logic Inference (Hypothetical Input/Output):**  Select a relatively simple test case, like `MinorCollection`. Break down the steps: allocate an object, perform a minor GC, and assert that the destructor was called. The input is the allocation, and the output is the object's destruction.
    * **Common Programming Errors:** Think about what could go wrong when dealing with garbage collection and manual memory management. Dangling pointers and memory leaks are the classic examples. Illustrate these with simple C++ code snippets (not directly from the test file, but related concepts).

5. **Structuring the Output:** Organize the findings logically:

    * **Purpose:** Start with a concise summary of the file's main goal.
    * **Key Functions:** List the important classes and functions and their roles.
    * **Detailed Functionality Breakdown:**  Elaborate on the different aspects of minor GC being tested (object lifecycle, remembered sets, etc.), drawing examples from the test code.
    * **Specific Request Responses:**  Address each of the specific conditions in the prompt clearly and directly.
    * **JavaScript Relationship and Example:** Explain the connection and provide a relevant Javascript example.
    * **Code Logic Inference:** Present the chosen test case with its hypothetical input and output.
    * **Common Programming Errors:**  Give clear examples of potential issues related to garbage collection in a broader programming context.

6. **Refinement and Review:**  After drafting the analysis, reread the code and the generated output. Are there any inaccuracies?  Is the explanation clear and easy to understand?  Are all aspects of the request addressed?  For example, initially, I might not have emphasized the "young generation" aspect enough, so I'd go back and add that detail. I'd also double-check that the Javascript example is accurate and relevant.

This iterative process of examination, identification, analysis, and refinement leads to a comprehensive and accurate understanding of the C++ unit test file and its purpose within the V8 project.
这是 V8 JavaScript 引擎中 cppgc (C++ garbage collection) 组件的一个单元测试文件，专门用于测试 **次要垃圾回收 (minor garbage collection)** 的功能。

**功能列表:**

1. **测试次要垃圾回收的基本功能:**
   - 创建年轻代对象。
   - 执行次要垃圾回收。
   - 验证年轻代中不再被引用的对象是否被回收。
   - 验证对象的析构函数是否被正确调用。

2. **测试粘性位 (Sticky Bits):**
   - 测试在次要垃圾回收后，持久对象（通过 `Persistent` 管理）是否仍然存活，并且不会被错误地标记为年轻代。

3. **测试老年代对象在次要垃圾回收中的行为:**
   - 验证在次要垃圾回收期间，老年代的对象不会被访问或回收。

4. **测试跨代指针 (Inter-Generational Pointers):**
   - 测试老年代对象指向年轻代对象的指针 (需要 generational barrier) 在次要垃圾回收中如何处理，确保年轻代对象不会被错误回收。
   - 测试年轻代对象指向老年代对象的指针在次要垃圾回收中的影响 (不需要 generational barrier)。

5. **测试省略栈上对象的代际屏障 (Omit Generational Barrier for On-Stack Object):**
   - 验证对于栈上分配的对象，不会触发代际屏障。

6. **测试省略哨兵指针的代际屏障 (Omit Generational Barrier for Sentinels):**
   - 验证对于空指针 (`nullptr`) 和哨兵指针 (`kSentinelPointer`)，不会触发代际屏障。

7. **测试记得集 (Remembered Set) 的失效处理:**
   - 当老年代对象被释放时，测试相关记得集条目是否被正确移除，避免悬挂指针。
   - 当老年代对象的大小被调整时，测试相关记得集条目是否被正确失效。

8. **测试内联对象的代际屏障和延迟追踪 (Generational Barrier Deferred Tracing):**
   - 测试包含内联对象的对象，其内部年轻代引用是否会被正确追踪和晋升。

9. **测试自定义弱回调的重新执行 (Reexecute Custom Callback):**
   - 验证在多次次要垃圾回收后，自定义弱回调是否会被多次调用，直到对象被完全回收。

10. **测试年龄表 (Age Table) 的重置:**
    - 验证在次要垃圾回收后，对象的页面的年龄状态会更新。
    - 验证在主要垃圾回收后，所有页面的年龄状态都会变为老年代。

11. **测试构造中对象 (In-Construction Objects) 的处理:**
    - 测试在对象构造过程中触发垃圾回收时，如何处理对年轻代对象的引用，确保这些对象不会被过早回收。

12. **测试嵌套构造中对象的处理:**
    - 类似地，测试在嵌套的对象构造过程中触发垃圾回收时的行为。

**关于 `.tq` 结尾:**

该文件名为 `minor-gc-unittest.cc`，以 `.cc` 结尾，这意味着它是一个 **C++ 源文件**，而不是 Torque 源文件。如果文件名以 `.tq` 结尾，那才是一个 V8 Torque 源代码。

**与 JavaScript 的功能关系:**

`v8/test/unittests/heap/cppgc/minor-gc-unittest.cc` 中测试的次要垃圾回收功能是 **V8 JavaScript 引擎内存管理的关键部分**。JavaScript 运行时依赖于垃圾回收来自动回收不再使用的内存，防止内存泄漏。

**JavaScript 示例:**

在 JavaScript 中创建的对象会被 V8 的垃圾回收器管理。次要垃圾回收主要负责回收**年轻代 (Young Generation)** 中的对象。年轻代通常包含新创建的、生命周期较短的对象。

```javascript
// 创建一些对象
let obj1 = { data: "一些数据" };
let obj2 = { ref: obj1 };
let obj3 = { another: "更多数据" };

// 假设此时触发了一次次要垃圾回收

// 如果 obj1 不再被任何其他对象引用 (比如 obj2 = null)，
// 那么在次要垃圾回收期间，obj1 很有可能被回收。

// 但如果 obj2 仍然引用 obj1，那么 obj1 将会被保留。

// obj3 如果也不再被引用，也会在次要垃圾回收中被回收。

obj2 = null; // 现在 obj1 不再被 obj2 引用

// 再次触发次要垃圾回收，此时 obj1 很可能被回收。
```

**代码逻辑推理 (假设输入与输出):**

考虑 `TYPED_TEST(MinorGCTestForType, MinorCollection)` 这个测试用例：

**假设输入:**

1. 堆中没有任何垃圾对象。
2. 执行 `MakeGarbageCollected<Type>(this->GetAllocationHandle())` 创建一个年轻代对象。
3. 此时，`TestFixture::DestructedObjects()` 返回 0，表示没有对象被析构。
4. 执行 `MinorGCTest::CollectMinor()` 触发一次次要垃圾回收。

**预期输出:**

1. 创建的年轻代对象在次要垃圾回收后，如果不再被引用，则会被回收。
2. 对象的析构函数 `~SimpleGCedBase()` 会被调用。
3. `TestFixture::DestructedObjects()` 返回 1，表示有一个对象被析构。

**涉及用户常见的编程错误:**

虽然这个文件是测试垃圾回收器本身的，但它所测试的功能直接关系到用户在编写 JavaScript 时可能遇到的与内存管理相关的问题。

**常见编程错误示例:**

1. **意外的全局变量导致内存泄漏:**

   ```javascript
   function createObject() {
     // 忘记使用 'let' 或 'const' 声明变量，导致成为全局变量
     globalObject = { data: "重要数据" };
   }

   createObject();
   // globalObject 将一直存在于全局作用域，不会被垃圾回收，即使不再需要。
   ```

2. **闭包引用导致意外的对象存活:**

   ```javascript
   function createCounter() {
     let count = 0;
     return function() {
       count++;
       console.log(count);
     };
   }

   let counter = createCounter();
   // counter 闭包引用了 createCounter 函数的局部变量 count。
   // 即使 createCounter 函数执行完毕，count 变量仍然会被保留，
   // 如果 counter 变量本身一直存活，那么 count 相关的内存也无法被回收。
   ```

3. **忘记解绑事件监听器或清理定时器:**

   ```javascript
   let element = document.getElementById('myButton');
   element.addEventListener('click', function() {
     // ... 一些操作
   });

   // 如果 element 从 DOM 中移除，但事件监听器没有被移除，
   // 那么监听器回调函数及其引用的变量可能无法被垃圾回收。

   setInterval(function() {
     // ... 一些定时操作
   }, 1000);

   // 如果不再需要定时器，但没有调用 clearInterval 清理，
   // 定时器回调函数及其引用的变量也会持续存在。
   ```

4. **循环引用:**

   ```javascript
   let objA = {};
   let objB = {};

   objA.ref = objB;
   objB.ref = objA;

   // objA 和 objB 相互引用，即使它们不再被其他外部变量引用，
   // 垃圾回收器也需要特殊的算法 (比如标记清除) 来回收它们。
   ```

总而言之，`v8/test/unittests/heap/cppgc/minor-gc-unittest.cc` 这个文件通过各种测试用例，确保 V8 引擎的次要垃圾回收机制能够正确高效地工作，从而保障 JavaScript 程序的内存管理。

Prompt: 
```
这是目录为v8/test/unittests/heap/cppgc/minor-gc-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/heap/cppgc/minor-gc-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

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