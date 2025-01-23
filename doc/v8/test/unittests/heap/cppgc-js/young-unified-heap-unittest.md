Response:
Let's break down the request and the provided C++ code.

**1. Understanding the Request:**

The user wants to understand the functionality of the given C++ source code file (`young-unified-heap-unittest.cc`). They specifically asked for:

* **Functionality Summary:** What does this code do?
* **Torque Check:** Is it a Torque file (indicated by `.tq`)?
* **JavaScript Relevance:**  If related to JavaScript, provide a JavaScript example.
* **Logic Reasoning (Input/Output):** If there's logical flow, illustrate with hypothetical inputs and outputs.
* **Common Programming Errors:** If it touches on potential developer mistakes, give examples.

**2. Initial Code Analysis (Scanning for Keywords and Structure):**

* **Headers:**  Includes like `<memory>`, `<vector>`, `"include/cppgc/...`, `"include/v8-..."`, `"src/heap/cppgc-js/..."`, `"test/..."`  strongly suggest this is a unit test file for V8's garbage collection, specifically focusing on the "young generation" and CppGC integration.
* **Namespaces:** `v8::internal` and an anonymous namespace indicate internal V8 implementation details.
* **`#if defined(CPPGC_YOUNG_GENERATION)`:**  This conditional compilation means the code is only active when the `CPPGC_YOUNG_GENERATION` flag is defined during the build. This confirms the focus on the young generation.
* **Test Framework:**  The presence of `TEST_F(YoungUnifiedHeapTest, ...)` immediately signals that this uses a C++ testing framework (likely Google Test, common in V8). The `YoungUnifiedHeapTest` class seems to set up the testing environment.
* **Key Classes:** `Wrappable`, `MinorMSEnabler`, `YoungWrapperCollector`, `ExpectCppGCToV8GenerationalBarrierToFire`, `ExpectCppGCToV8NoGenerationalBarrier`. These class names are highly descriptive and hint at the tested scenarios.
* **Garbage Collection Actions:** Functions like `CollectYoungGarbageWithEmbedderStack()`, `CollectGarbageWithoutEmbedderStack()` point to tests related to triggering and observing garbage collection behavior.
* **V8 API Usage:**  Interactions with `v8::Isolate`, `v8::Local<v8::Object>`, `v8::Utils`, and `v8::TracedReference` indicate that the tests involve interactions between CppGC-managed objects and V8's JavaScript objects.
* **Generational Barriers:**  The terms "GenerationalBarrier" are repeated, suggesting a focus on how the garbage collector handles references between objects in different generations (young vs. old).

**3. Deeper Dive into Key Classes and Tests:**

* **`Wrappable`:**  A simple CppGC-managed class that can hold a `v8::Object` (JavaScript object) using `TracedReference`. The destructor and `destructor_callcount` are used to verify when objects are collected.
* **`MinorMSEnabler`:** This class uses `FlagScope` to temporarily enable minor garbage collection and the CppGC young generation feature during the tests.
* **`YoungWrapperCollector`:** This visitor iterates through the young generation roots and collects the addresses of "wrappers" (likely the `v8::Object` held by `Wrappable`).
* **`ExpectCppGCToV8GenerationalBarrierToFire` and `ExpectCppGCToV8NoGenerationalBarrier`:** These are crucial test helpers. They are used to assert whether or not a generational barrier was triggered when a CppGC object holds a reference to a V8 object. They work by checking the set of young wrappers before and after an operation. A generational barrier adds the V8 object as a root in the young generation.
* **Test Cases:** Each `TEST_F` function focuses on a specific aspect of young generation garbage collection and the interaction between CppGC and the V8 heap:
    * `OnlyGC`:  Basic young generation GC.
    * `CollectUnreachableCppGCObject`: Verifies CppGC objects are collected.
    * `FindingV8ToCppGCReference`: Tests if the GC finds references from V8 to CppGC.
    * `FindingCppGCToV8Reference`: Tests if the GC finds references from CppGC to V8.
    * `GenerationalBarrierV8ToCppGCReference`: Focuses on the barrier when V8 objects reference CppGC objects.
    * `GenerationalBarrierCppGCToV8...`: A series of tests specifically examining the generational barrier in different scenarios where CppGC objects hold references to V8 objects (initialization, reset, copy, move).

**4. Answering the Specific Questions:**

* **Functionality:** The file contains unit tests for the young generation garbage collector in V8, specifically focusing on the interaction between CppGC-managed objects and V8 JavaScript objects. It tests scenarios involving object allocation, garbage collection of unreachable objects, and the correctness of generational barriers.
* **Torque:** The filename ends in `.cc`, not `.tq`. Therefore, it is **not** a Torque source file.
* **JavaScript Relevance:** Yes, it's directly related to how V8 manages JavaScript objects alongside CppGC objects.
* **Logic Reasoning:** The `ExpectCppGCToV8GenerationalBarrierToFire` and `ExpectCppGCToV8NoGenerationalBarrier` classes provide the core logic. They check the state of young wrappers before and after an action to determine if a barrier fired.
* **Common Programming Errors:** The tests implicitly highlight potential errors related to memory management, especially when mixing managed and unmanaged objects, and the importance of generational barriers for correct garbage collection.

**5. Constructing the JavaScript Example and Error Scenarios:**

Based on the understanding of the code, I can formulate a relevant JavaScript example and common errors.

**Self-Correction/Refinement during thought process:**

* Initially, I might have focused too much on individual test cases without grasping the overarching theme of generational barriers. Recognizing the importance of `ExpectCppGCToV8...` classes was key to understanding the core functionality.
* I considered whether to provide very low-level C++ explanations of the GC, but the user's request seemed more focused on the *testing* aspect and the connection to JavaScript.
* I made sure to explicitly address each point in the user's request (Torque, JavaScript example, etc.).
好的，让我们来分析一下 `v8/test/unittests/heap/cppgc-js/young-unified-heap-unittest.cc` 这个文件。

**文件功能概述:**

这个 C++ 文件是 V8 引擎的一个单元测试文件。它专门用于测试 V8 中 **年轻代统一堆 (Young Unified Heap)** 的相关功能。年轻代是垃圾回收器管理内存的一部分，主要存放新创建的对象。统一堆指的是 CppGC（C++ Garbage Collector）与 V8 的 JavaScript 堆进行更紧密的集成。

该文件的主要功能是：

1. **验证年轻代垃圾回收 (Minor GC) 的基本功能**:  例如，能够正确地回收只存在于年轻代且不再被引用的 CppGC 对象和 JavaScript 对象。
2. **测试 V8 和 CppGC 对象之间的引用关系**:  特别是当年轻代的 V8 对象引用老年代的 CppGC 对象，或者反之，以及它们在垃圾回收过程中的处理。
3. **验证代际屏障 (Generational Barrier) 的正确性**:  代际屏障是确保垃圾回收器能够正确追踪跨代引用关系的关键机制。当一个老年代对象引用年轻代对象时，需要设置屏障来通知垃圾回收器。这个文件测试了从 V8 到 CppGC 以及从 CppGC 到 V8 的代际屏障在不同场景下的触发情况。
4. **测试 `TracedReference` 的行为**: `TracedReference` 是 CppGC 中用于持有 V8 对象引用的智能指针，这个文件测试了其在年轻代垃圾回收中的行为，例如赋值、拷贝和移动操作是否会触发正确的代际屏障。

**关于文件后缀名：**

`v8/test/unittests/heap/cppgc-js/young-unified-heap-unittest.cc` 的后缀是 `.cc`，这表明它是一个 **C++ 源代码文件**。如果文件以 `.tq` 结尾，那它才是 V8 Torque 源代码文件。

**与 JavaScript 功能的关系以及 JavaScript 示例:**

这个测试文件直接关系到 V8 如何管理 JavaScript 对象的内存，特别是新创建的 JavaScript 对象。年轻代垃圾回收的目标是高效地回收这些生命周期较短的对象。CppGC 的引入使得 C++ 代码也可以创建和管理对象，并与 JavaScript 对象在同一个堆中进行交互。

以下是一个简化的 JavaScript 示例，展示了与这个测试文件相关的概念：

```javascript
let outerObject = {}; // 假设 outerObject 分配在老年代

function createInnerObject() {
  let innerObject = {}; // innerObject 很可能分配在年轻代
  outerObject.child = innerObject; // 老年代对象引用年轻代对象
  return innerObject;
}

let myInnerObject = createInnerObject();

// ... 一段时间后，如果 myInnerObject 不再被其他地方引用，
// 那么年轻代垃圾回收应该能够回收它。
// 并且，由于 outerObject 引用了它，需要有代际屏障机制来保证回收的正确性。

myInnerObject = null; // 解除对年轻代对象的引用

// 触发垃圾回收 (这只是示意，实际 V8 的 GC 是自动触发的)
// ...
```

在这个例子中，`innerObject` 很可能被分配在年轻代。`outerObject.child = innerObject;` 这行代码创建了一个从老年代对象到年轻代对象的引用，这时就需要代际屏障来记录这种关系，以便在进行年轻代垃圾回收时，能够正确地判断 `innerObject` 是否仍然被引用。

**代码逻辑推理与假设输入输出:**

我们来看一个具体的测试用例：`TEST_F(YoungUnifiedHeapTest, GenerationalBarrierCppGCToV8ReferenceReset)`

**假设输入:**

1. 创建一个 CppGC 管理的 `Wrappable` 对象 `wrappable_object`，它最初会被分配在年轻代。
2. 触发一次 Major GC (Full GC)，将 `wrappable_object` 晋升到老年代。
3. 创建一个新的 JavaScript 对象 `local`，它分配在年轻代。
4. 将 `wrappable_object` 的内部 `wrapper_` (一个 `TracedReference<v8::Object>`) 指向 `local`。

**代码逻辑:**

* 测试首先断言 `wrappable_object` 在创建时处于年轻代 (`IsHeapObjectYoung`).
* 触发 Major GC 后，断言 `wrappable_object` 已经晋升到老年代 (`IsHeapObjectOld`).
* 在将 `wrappable_object` 的 `wrapper_` 指向年轻代的 `local` 对象时，`ExpectCppGCToV8GenerationalBarrierToFire` 会检查是否触发了从 CppGC 到 V8 的代际屏障。这意味着 V8 的垃圾回收器会记录下这个老年代的 CppGC 对象引用了年轻代的 JavaScript 对象。
* 最后，触发一次年轻代垃圾回收，并断言 `local` 对象仍然是可访问的 (`EXPECT_TRUE(local->IsObject())`)，因为它被老年代的 CppGC 对象引用。

**预期输出:**

* 在将 `wrappable_object->SetWrapper(v8_isolate(), local);` 后，代际屏障应该被触发。
* 年轻代垃圾回收后，`local` 对象不会被回收。

**用户常见的编程错误:**

这个测试文件涉及的常见编程错误包括：

1. **忘记设置代际屏障**:  如果在 C++ 代码中，老年代的 CppGC 对象持有了年轻代的 V8 对象的引用，但没有正确地通知 V8 的垃圾回收器（即没有触发代际屏障），那么年轻代垃圾回收可能会错误地回收这些仍然被引用的对象，导致悬挂指针或程序崩溃。

   **C++ 示例 (错误):**

   ```c++
   class OldObject : public cppgc::GarbageCollected<OldObject> {
    public:
     void SetYoungObject(v8::Local<v8::Object> young) {
       young_object_.Reset(v8_isolate(), young); // 缺少必要的屏障处理
     }
    private:
     v8::Global<v8::Object> young_object_;
   };

   // ... 在老年代分配 OldObject ...
   v8::Local<v8::Object> youngObj = v8::Object::New(isolate); // 分配在年轻代
   oldObject->SetYoungObject(youngObj);

   // ... 触发年轻代 GC，可能错误回收 youngObj
   ```

2. **对垃圾回收机制理解不足**: 开发者可能不清楚年轻代和老年代的区别，以及跨代引用的处理方式，导致在设计 C++ 和 JavaScript 交互的程序时出现内存管理问题。

3. **手动管理内存与垃圾回收的冲突**: 尝试在垃圾回收的环境中手动释放由垃圾回收器管理的对象是非常危险的，会导致双重释放等错误。

总而言之，`young-unified-heap-unittest.cc` 文件通过一系列精心设计的测试用例，确保 V8 的年轻代统一堆能够正确地管理内存，并保证 CppGC 和 JavaScript 对象之间的互操作性和垃圾回收的正确性。这些测试对于 V8 引擎的稳定性和性能至关重要。

### 提示词
```
这是目录为v8/test/unittests/heap/cppgc-js/young-unified-heap-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/heap/cppgc-js/young-unified-heap-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if defined(CPPGC_YOUNG_GENERATION)

#include <algorithm>
#include <memory>
#include <vector>

#include "include/cppgc/allocation.h"
#include "include/cppgc/garbage-collected.h"
#include "include/cppgc/persistent.h"
#include "include/cppgc/testing.h"
#include "include/v8-context.h"
#include "include/v8-cppgc.h"
#include "include/v8-local-handle.h"
#include "include/v8-object.h"
#include "include/v8-traced-handle.h"
#include "src/api/api-inl.h"
#include "src/common/globals.h"
#include "src/heap/cppgc-js/cpp-heap.h"
#include "src/heap/cppgc/heap-object-header.h"
#include "src/objects/objects-inl.h"
#include "test/common/flag-utils.h"
#include "test/unittests/heap/cppgc-js/unified-heap-utils.h"
#include "test/unittests/heap/heap-utils.h"

namespace v8 {
namespace internal {

namespace {

bool IsHeapObjectYoung(void* obj) {
  return cppgc::internal::HeapObjectHeader::FromObject(obj).IsYoung();
}

bool IsHeapObjectOld(void* obj) { return !IsHeapObjectYoung(obj); }

class Wrappable final : public cppgc::GarbageCollected<Wrappable> {
 public:
  static size_t destructor_callcount;

  Wrappable() = default;
  Wrappable(v8::Isolate* isolate, v8::Local<v8::Object> local)
      : wrapper_(isolate, local) {}

  Wrappable(const Wrappable&) = default;
  Wrappable(Wrappable&&) = default;

  Wrappable& operator=(const Wrappable&) = default;
  Wrappable& operator=(Wrappable&&) = default;

  ~Wrappable() { destructor_callcount++; }

  void Trace(cppgc::Visitor* visitor) const { visitor->Trace(wrapper_); }

  void SetWrapper(v8::Isolate* isolate, v8::Local<v8::Object> wrapper) {
    wrapper_.Reset(isolate, wrapper);
  }

  TracedReference<v8::Object>& wrapper() { return wrapper_; }

 private:
  TracedReference<v8::Object> wrapper_;
};

size_t Wrappable::destructor_callcount = 0;

class MinorMSEnabler {
 public:
  MinorMSEnabler()
      : minor_ms_(&v8_flags.minor_ms, true),
        cppgc_young_generation_(&v8_flags.cppgc_young_generation, true) {}

 private:
  FlagScope<bool> minor_ms_;
  FlagScope<bool> cppgc_young_generation_;
};

class YoungWrapperCollector : public RootVisitor {
 public:
  using YoungWrappers = std::set<Address>;

  void VisitRootPointers(Root root, const char*, FullObjectSlot start,
                         FullObjectSlot end) override {
    for (FullObjectSlot p = start; p < end; ++p) {
      all_young_wrappers_.insert(*p.location());
    }
  }

  YoungWrappers get_wrappers() { return std::move(all_young_wrappers_); }

 private:
  YoungWrappers all_young_wrappers_;
};

class ExpectCppGCToV8GenerationalBarrierToFire {
 public:
  ExpectCppGCToV8GenerationalBarrierToFire(
      v8::Isolate& isolate, std::initializer_list<Address> expected_wrappers)
      : isolate_(reinterpret_cast<Isolate&>(isolate)),
        expected_wrappers_(expected_wrappers) {
    YoungWrapperCollector visitor;
    isolate_.traced_handles()->IterateYoungRootsWithOldHostsForTesting(
        &visitor);
    young_wrappers_before_ = visitor.get_wrappers();

    std::vector<Address> diff;
    std::set_intersection(young_wrappers_before_.begin(),
                          young_wrappers_before_.end(),
                          expected_wrappers_.begin(), expected_wrappers_.end(),
                          std::back_inserter(diff));
    EXPECT_TRUE(diff.empty());
  }

  ~ExpectCppGCToV8GenerationalBarrierToFire() {
    YoungWrapperCollector visitor;
    isolate_.traced_handles()->IterateYoungRootsWithOldHostsForTesting(
        &visitor);
    const auto young_wrappers_after = visitor.get_wrappers();
    EXPECT_GE(young_wrappers_after.size(), young_wrappers_before_.size());

    EXPECT_TRUE(
        std::includes(young_wrappers_after.begin(), young_wrappers_after.end(),
                      expected_wrappers_.begin(), expected_wrappers_.end()));
    EXPECT_EQ(expected_wrappers_.size(),
              young_wrappers_after.size() - young_wrappers_before_.size());
  }

 private:
  Isolate& isolate_;
  YoungWrapperCollector::YoungWrappers expected_wrappers_;
  YoungWrapperCollector::YoungWrappers young_wrappers_before_;
};

class ExpectCppGCToV8NoGenerationalBarrier {
 public:
  explicit ExpectCppGCToV8NoGenerationalBarrier(v8::Isolate& isolate)
      : isolate_(reinterpret_cast<Isolate&>(isolate)) {
    YoungWrapperCollector visitor;
    isolate_.traced_handles()->IterateYoungRootsWithOldHostsForTesting(
        &visitor);
    young_wrappers_before_ = visitor.get_wrappers();
  }

  ~ExpectCppGCToV8NoGenerationalBarrier() {
    YoungWrapperCollector visitor;
    isolate_.traced_handles()->IterateYoungRootsWithOldHostsForTesting(
        &visitor);
    const auto young_wrappers_after = visitor.get_wrappers();
    EXPECT_EQ(young_wrappers_before_, young_wrappers_after);
  }

 private:
  Isolate& isolate_;
  YoungWrapperCollector::YoungWrappers young_wrappers_before_;
};

}  // namespace

class YoungUnifiedHeapTest : public MinorMSEnabler, public UnifiedHeapTest {
 public:
  YoungUnifiedHeapTest() {
    // Enable young generation flag and run GC. After the first run the heap
    // will enable minor GC.
    CollectGarbageWithoutEmbedderStack();
  }
};

TEST_F(YoungUnifiedHeapTest, OnlyGC) { CollectYoungGarbageWithEmbedderStack(); }

TEST_F(YoungUnifiedHeapTest, CollectUnreachableCppGCObject) {
  cppgc::MakeGarbageCollected<Wrappable>(allocation_handle());
  v8::Local<v8::Object> api_object =
      WrapperHelper::CreateWrapper(context(), nullptr);
  EXPECT_FALSE(api_object.IsEmpty());

  Wrappable::destructor_callcount = 0;
  CollectYoungGarbageWithoutEmbedderStack(cppgc::Heap::SweepingType::kAtomic);
  EXPECT_EQ(1u, Wrappable::destructor_callcount);
}

TEST_F(YoungUnifiedHeapTest, FindingV8ToCppGCReference) {
  auto* wrappable_object =
      cppgc::MakeGarbageCollected<Wrappable>(allocation_handle());
  v8::Local<v8::Object> api_object =
      WrapperHelper::CreateWrapper(context(), wrappable_object);
  EXPECT_FALSE(api_object.IsEmpty());
  // With direct locals, api_object may be invalid after a stackless GC.
  auto handle_api_object = v8::Utils::OpenIndirectHandle(*api_object);

  Wrappable::destructor_callcount = 0;
  CollectYoungGarbageWithoutEmbedderStack(cppgc::Heap::SweepingType::kAtomic);
  EXPECT_EQ(0u, Wrappable::destructor_callcount);

  WrapperHelper::ResetWrappableConnection(
      v8_isolate(), v8::Utils::ToLocal(handle_api_object));
  CollectGarbageWithoutEmbedderStack(cppgc::Heap::SweepingType::kAtomic);
  EXPECT_EQ(1u, Wrappable::destructor_callcount);
}

TEST_F(YoungUnifiedHeapTest, FindingCppGCToV8Reference) {
  auto* wrappable_object =
      cppgc::MakeGarbageCollected<Wrappable>(allocation_handle());

  {
    v8::HandleScope inner_handle_scope(v8_isolate());
    auto local = v8::Object::New(v8_isolate());
    EXPECT_TRUE(local->IsObject());
    wrappable_object->SetWrapper(v8_isolate(), local);
  }

  CollectYoungGarbageWithEmbedderStack(cppgc::Heap::SweepingType::kAtomic);
  auto local = wrappable_object->wrapper().Get(v8_isolate());
  EXPECT_TRUE(local->IsObject());
}

TEST_F(YoungUnifiedHeapTest, GenerationalBarrierV8ToCppGCReference) {
  if (i::v8_flags.single_generation) return;

  FlagScope<bool> no_incremental_marking(&v8_flags.incremental_marking, false);

  v8::Local<v8::Object> api_object =
      WrapperHelper::CreateWrapper(context(), nullptr);
  // With direct locals, api_object may be invalid after a stackless GC.
  auto handle_api_object = v8::Utils::OpenIndirectHandle(*api_object);

  EXPECT_TRUE(HeapLayout::InYoungGeneration(*handle_api_object));
  InvokeMemoryReducingMajorGCs();
  EXPECT_EQ(0u, Wrappable::destructor_callcount);
  EXPECT_FALSE(HeapLayout::InYoungGeneration(*handle_api_object));

  auto* wrappable = cppgc::MakeGarbageCollected<Wrappable>(allocation_handle());
  WrapperHelper::SetWrappableConnection(
      v8_isolate(), v8::Utils::ToLocal(handle_api_object), wrappable);

  Wrappable::destructor_callcount = 0;
  CollectYoungGarbageWithoutEmbedderStack(cppgc::Heap::SweepingType::kAtomic);
  EXPECT_EQ(0u, Wrappable::destructor_callcount);
}

TEST_F(YoungUnifiedHeapTest,
       GenerationalBarrierCppGCToV8NoInitializingStoreBarrier) {
  if (i::v8_flags.single_generation) return;

  FlagScope<bool> no_incremental_marking(&v8_flags.incremental_marking, false);

  auto local = v8::Object::New(v8_isolate());
  {
    ExpectCppGCToV8NoGenerationalBarrier expect_no_barrier(*v8_isolate());
    auto* wrappable = cppgc::MakeGarbageCollected<Wrappable>(
        allocation_handle(), v8_isolate(), local);
    auto* copied_wrappable =
        cppgc::MakeGarbageCollected<Wrappable>(allocation_handle(), *wrappable);
    auto* moved_wrappable = cppgc::MakeGarbageCollected<Wrappable>(
        allocation_handle(), std::move(*wrappable));
    USE(moved_wrappable);
    USE(copied_wrappable);
    USE(wrappable);
  }
}

TEST_F(YoungUnifiedHeapTest, GenerationalBarrierCppGCToV8ReferenceReset) {
  if (i::v8_flags.single_generation) return;

  FlagScope<bool> no_incremental_marking(&v8_flags.incremental_marking, false);

  cppgc::Persistent<Wrappable> wrappable_object =
      cppgc::MakeGarbageCollected<Wrappable>(allocation_handle());

  EXPECT_TRUE(IsHeapObjectYoung(wrappable_object.Get()));
  InvokeMemoryReducingMajorGCs();
  EXPECT_EQ(0u, Wrappable::destructor_callcount);
  EXPECT_TRUE(IsHeapObjectOld(wrappable_object.Get()));

  {
    v8::HandleScope inner_handle_scope(v8_isolate());
    auto local = v8::Object::New(v8_isolate());
    EXPECT_TRUE(local->IsObject());
    {
      ExpectCppGCToV8GenerationalBarrierToFire expect_barrier(
          *v8_isolate(), {i::ValueHelper::ValueAsAddress(*local)});
      wrappable_object->SetWrapper(v8_isolate(), local);
    }
  }

  CollectYoungGarbageWithoutEmbedderStack(cppgc::Heap::SweepingType::kAtomic);
  auto local = wrappable_object->wrapper().Get(v8_isolate());
  EXPECT_TRUE(local->IsObject());
}

TEST_F(YoungUnifiedHeapTest, GenerationalBarrierCppGCToV8ReferenceCopy) {
  if (i::v8_flags.single_generation) return;

  FlagScope<bool> no_incremental_marking(&v8_flags.incremental_marking, false);

  cppgc::Persistent<Wrappable> wrappable_object =
      cppgc::MakeGarbageCollected<Wrappable>(allocation_handle());

  EXPECT_TRUE(IsHeapObjectYoung(wrappable_object.Get()));
  InvokeMemoryReducingMajorGCs();
  EXPECT_EQ(0u, Wrappable::destructor_callcount);
  EXPECT_TRUE(IsHeapObjectOld(wrappable_object.Get()));

  {
    v8::HandleScope inner_handle_scope(v8_isolate());
    auto local = v8::Object::New(v8_isolate());
    EXPECT_TRUE(local->IsObject());

    Wrappable* another_wrappable_object = nullptr;
    {
      // Assign to young host and expect no barrier.
      ExpectCppGCToV8NoGenerationalBarrier expect_no_barrier(*v8_isolate());
      another_wrappable_object =
          cppgc::MakeGarbageCollected<Wrappable>(allocation_handle());
      another_wrappable_object->SetWrapper(v8_isolate(), local);
    }
    {
      // Assign to old object using TracedReference::operator= and expect
      // the barrier to trigger.
      ExpectCppGCToV8GenerationalBarrierToFire expect_barrier(
          *v8_isolate(), {i::ValueHelper::ValueAsAddress(*local)});
      *wrappable_object = *another_wrappable_object;
    }
  }

  CollectYoungGarbageWithoutEmbedderStack(cppgc::Heap::SweepingType::kAtomic);
  auto local = wrappable_object->wrapper().Get(v8_isolate());
  EXPECT_TRUE(local->IsObject());
}

TEST_F(YoungUnifiedHeapTest, GenerationalBarrierCppGCToV8ReferenceMove) {
  if (i::v8_flags.single_generation) return;

  FlagScope<bool> no_incremental_marking(&v8_flags.incremental_marking, false);

  cppgc::Persistent<Wrappable> wrappable_object =
      cppgc::MakeGarbageCollected<Wrappable>(allocation_handle());

  EXPECT_TRUE(IsHeapObjectYoung(wrappable_object.Get()));
  InvokeMemoryReducingMajorGCs();
  EXPECT_EQ(0u, Wrappable::destructor_callcount);
  EXPECT_TRUE(IsHeapObjectOld(wrappable_object.Get()));

  {
    v8::HandleScope inner_handle_scope(v8_isolate());
    auto local = v8::Object::New(v8_isolate());
    EXPECT_TRUE(local->IsObject());

    Wrappable* another_wrappable_object = nullptr;
    {
      // Assign to young host and expect no barrier.
      ExpectCppGCToV8NoGenerationalBarrier expect_no_barrier(*v8_isolate());
      another_wrappable_object =
          cppgc::MakeGarbageCollected<Wrappable>(allocation_handle());
      another_wrappable_object->SetWrapper(v8_isolate(), local);
    }
    {
      // Assign to old object using TracedReference::operator= and expect
      // the barrier to trigger.
      ExpectCppGCToV8GenerationalBarrierToFire expect_barrier(
          *v8_isolate(), {i::ValueHelper::ValueAsAddress(*local)});
      *wrappable_object = std::move(*another_wrappable_object);
    }
  }

  CollectYoungGarbageWithoutEmbedderStack(cppgc::Heap::SweepingType::kAtomic);
  auto local = wrappable_object->wrapper().Get(v8_isolate());
  EXPECT_TRUE(local->IsObject());
}

}  // namespace internal
}  // namespace v8

#endif  // defined(CPPGC_YOUNG_GENERATION)
```