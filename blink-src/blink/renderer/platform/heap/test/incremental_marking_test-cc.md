Response:
The user wants to understand the functionality of the provided C++ code snippet. This file seems to be a unit test for the incremental marking garbage collection in the Blink rendering engine.

Here's a breakdown of the request and a plan to address it:

1. **List the functionalities:**  The core function is to test the behavior of `HeapVector`, `HeapDeque`, `HeapHashSet`, `HeapLinkedHashSet`, and `HeapHashMap` during incremental garbage collection. Specifically, it checks if garbage-collected objects held within these containers are correctly identified and kept alive during the GC process under various operations like `push_back`, `emplace_back`, copy, move, swap, and iterator manipulation.

2. **Relation to JavaScript, HTML, CSS:** These data structures are fundamental for managing the lifecycle of objects in the rendering engine. They hold objects representing DOM elements (HTML), style information (CSS), and JavaScript objects. The tests ensure that the GC correctly handles these relationships, preventing premature collection and ensuring memory safety.

3. **Logical reasoning (input/output):**  The tests are structured around specific scenarios (e.g., pushing an object into a `HeapVector` and then triggering GC). The input is the initial state of the heap and the performed operation. The output is whether the weak persistent pointer to the object is still valid after garbage collection. A successful test means the object was correctly identified as reachable and not garbage collected.

4. **User/programming errors:**  The tests implicitly help prevent common errors. For example, if a container didn't correctly trace its members, the test would fail, highlighting a bug in the container's implementation. A common conceptual error might be assuming a contained object is always alive simply because the container is alive, without understanding how garbage collection works.

5. **Summarize the functionality:** Concisely state the overall purpose of the file.

**Constraint Checklist & Confidence Score:**

* List the functionalities: Yes
* Relation to JS/HTML/CSS: Yes
* Examples for JS/HTML/CSS: Yes
* Logical reasoning (input/output): Yes
* Examples for input/output: Yes
* User/programming errors: Yes
* Examples for user errors: Yes
* Summarize functionality: Yes

Confidence Score: 5/5

**Mental Sandbox:**

I'll go through the code and identify the patterns: each `TEST_F` function sets up a scenario involving a specific container type and an operation, triggers garbage collection, and then asserts whether a weakly held object is still alive. This confirms that the container correctly informs the garbage collector about its contained objects. I'll focus on connecting the container types to their roles in the rendering engine.

Strategizing complete. I will now generate the response.

这个C++源代码文件 `incremental_marking_test.cc` 是 Chromium Blink 引擎中用于测试**增量标记垃圾回收机制 (Incremental Marking)** 的单元测试文件。 它的主要功能是：

1. **测试各种 Blink 引擎中自定义的容器类在增量标记垃圾回收下的行为:**  这些容器类包括 `HeapVector`, `HeapDeque`, `HeapHashSet`, `HeapLinkedHashSet`, `HeapHashCountedSet`, 和 `HeapHashMap`。 增量标记是一种垃圾回收策略，它将标记过程分解为多个步骤，与主线程交错执行，以减少垃圾回收对性能的影响。 这个测试文件确保在增量标记过程中，这些容器类能够正确地管理其内部持有的垃圾回收对象，防止对象被过早回收。

2. **验证 `Member` 和 `WeakMember` 类型在增量标记下的行为:** `Member<T>` 和 `WeakMember<T>` 是 Blink 中用于持有垃圾回收对象的智能指针。 `Member` 提供强引用，确保对象存活； `WeakMember` 提供弱引用，不阻止对象被回收，但在当前回收周期内可以被 "强壮化" 以访问对象。 这个测试文件验证了这些类型在增量标记过程中是否能正确地跟踪和报告其引用的对象。

3. **模拟和测试不同的容器操作:**  测试覆盖了向容器中添加元素 (`push_back`, `push_front`, `emplace_back`, `emplace_front`, `insert`, `Set`)，复制容器 (拷贝构造和拷贝赋值)，移动容器 (移动构造和移动赋值)，交换容器 (`swap`)，以及通过下标或迭代器访问和修改容器元素等操作。  这些测试确保在增量标记进行时，这些操作不会导致内存泄漏或者过早回收对象。

**与 JavaScript, HTML, CSS 的关系举例说明:**

这些容器类和垃圾回收机制是 Blink 引擎管理网页对象生命周期的基础。  以下是一些例子：

* **JavaScript 对象:**  JavaScript 中的对象在 Blink 引擎内部通常被表示为垃圾回收对象。  例如，一个 JavaScript 对象可能被存储在一个 `HeapHashMap` 中，键是字符串（属性名），值是代表 JavaScript 值的垃圾回收对象。  `incremental_marking_test.cc` 中的测试确保当增量标记进行时，这些 JavaScript 对象不会因为容器操作而被错误回收。

   * **假设输入:**  一个 JavaScript 对象 `obj` 被添加到 `document` 对象的某个属性中，而 `document` 对象内部使用 `HeapHashMap` 来存储属性。 增量标记开始执行。
   * **输出:** 测试会验证即使在增量标记过程中对 `document` 的属性进行读写操作，`obj` 也不会被回收，因为它被 `HeapHashMap` 正确引用。

* **HTML 元素:** HTML DOM 树中的元素也是垃圾回收对象。 例如，一个 `<div>` 元素对象可能被存储在一个 `HeapVector` 中，作为其父元素的子节点列表。

   * **假设输入:**  一个新创建的 `<div>` 元素被 `appendChild` 到另一个元素中，这个添加操作导致该 `<div>` 元素被添加到父元素的 `HeapVector` 子节点列表中。 增量标记开始。
   * **输出:**  测试会验证即使在增量标记过程中，由于父元素的 `HeapVector` 正确引用了该 `<div>` 元素，该元素不会被回收。

* **CSS 样式:**  应用于 HTML 元素的 CSS 样式信息也可能存储在垃圾回收对象中。 例如，一个元素的计算样式可能被存储在一个 `HeapHashMap` 中，键是 CSS 属性名，值是代表样式值的垃圾回收对象。

   * **假设输入:**  一个元素的 CSS 样式被修改，导致其样式对象内部的 `HeapHashMap` 发生更新。 增量标记同时进行。
   * **输出:**  测试会验证即使在增量标记过程中修改样式，相关的样式对象不会因为 `HeapHashMap` 的操作而被错误回收。

**逻辑推理的假设输入与输出:**

以 `TEST_F(IncrementalMarkingTest, HeapVectorPushBackMember)` 为例：

* **假设输入:**
    1. 创建一个垃圾回收对象 `LinkedObject` 的实例 `obj`。
    2. 创建一个存储 `Member<LinkedObject>` 类型的 `HeapVector` 实例 `vec`。
    3. 启动增量标记垃圾回收。
    4. 将 `obj` 添加到 `vec` 中。
    5. 完成增量标记垃圾回收。
* **输出:** 在垃圾回收完成后，`obj` 仍然存活（可以通过 `WeakPersistent` 智能指针的 `operator bool()` 验证）。  这是因为 `HeapVector` 正确地通过 `Member` 引用了 `obj`，使得垃圾回收器知道它仍然被使用。

**涉及用户或者编程常见的使用错误举例说明:**

这个测试文件主要关注 Blink 引擎内部的正确性，但它间接帮助防止了一些与垃圾回收相关的常见编程错误：

* **忘记维护对象引用:**  如果一个 Blink 的开发者在实现一个容器类时，忘记在垃圾回收的 `Trace` 方法中遍历并标记容器内的垃圾回收对象，那么这些对象可能会在增量标记过程中被错误回收。 这个测试文件会通过模拟增量标记和容器操作来检测这类错误。
* **在不当的时机释放资源:**  增量标记的复杂性在于它与主线程交错执行。  如果在增量标记进行时，不正确地释放了仍然被垃圾回收器扫描的对象，可能会导致崩溃或数据损坏。 这些测试有助于确保各种容器操作在增量标记的不同阶段都能安全执行。
* **循环引用导致内存泄漏 (虽然增量标记主要解决的是减少停顿):**  虽然增量标记本身不是为了解决循环引用导致的内存泄漏（通常由标记-清除或引用计数解决），但正确实现增量标记有助于更可靠地识别和管理对象间的引用关系，间接地有助于发现潜在的循环引用问题。

**功能归纳 (第 1 部分):**

`incremental_marking_test.cc` 的第 1 部分主要功能是**测试 `HeapVector` 和 `HeapDeque` 这两种基于顺序存储的容器类在增量标记垃圾回收下的正确性**。  它覆盖了这些容器的常见操作，例如添加元素、复制、移动和交换，以及在增量标记过程中，它们是否能正确地维护对内部垃圾回收对象的引用，防止对象被过早回收。  这些测试使用 `Member` 和 `WeakMember` 来验证对象在垃圾回收后的存活状态。

Prompt: 
```
这是目录为blink/renderer/platform/heap/test/incremental_marking_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <initializer_list>

#include "base/functional/bind.h"
#include "base/test/scoped_feature_list.h"
#include "build/buildflag.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_deque.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_hash_counted_set.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_hash_map.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_hash_set.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_linked_hash_set.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/heap_buildflags.h"
#include "third_party/blink/renderer/platform/heap/heap_test_objects.h"
#include "third_party/blink/renderer/platform/heap/heap_test_utilities.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/heap/trace_traits.h"
#include "third_party/blink/renderer/platform/heap/visitor.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

class IncrementalMarkingTest : public TestSupportingGC {};

namespace incremental_marking_test {

// =============================================================================
// HeapVector support. =========================================================
// =============================================================================

namespace {

// HeapVector allows for insertion of container objects that can be traced but
// are themselves non-garbage collected.
class NonGarbageCollectedContainer {
  DISALLOW_NEW();

 public:
  NonGarbageCollectedContainer(LinkedObject* obj, int y) : obj_(obj), y_(y) {}

  virtual ~NonGarbageCollectedContainer() {}
  virtual void Trace(Visitor* visitor) const { visitor->Trace(obj_); }

 private:
  Member<LinkedObject> obj_;
  int y_;
};

class NonGarbageCollectedContainerRoot {
  DISALLOW_NEW();

 public:
  NonGarbageCollectedContainerRoot(LinkedObject* obj1,
                                   LinkedObject* obj2,
                                   int y)
      : next_(obj1, y), obj_(obj2) {}
  virtual ~NonGarbageCollectedContainerRoot() {}

  virtual void Trace(Visitor* visitor) const {
    visitor->Trace(next_);
    visitor->Trace(obj_);
  }

 private:
  NonGarbageCollectedContainer next_;
  Member<LinkedObject> obj_;
};

}  // namespace

TEST_F(IncrementalMarkingTest, HeapVectorPushBackMember) {
  WeakPersistent<LinkedObject> obj = MakeGarbageCollected<LinkedObject>();
  HeapVector<Member<LinkedObject>>* vec =
      MakeGarbageCollected<HeapVector<Member<LinkedObject>>>();
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  vec->push_back(obj);
  driver.FinishGC();
  EXPECT_TRUE(obj);
}

TEST_F(IncrementalMarkingTest, HeapVectorPushBackNonGCedContainer) {
  WeakPersistent<LinkedObject> obj = MakeGarbageCollected<LinkedObject>();
  HeapVector<NonGarbageCollectedContainer>* vec =
      MakeGarbageCollected<HeapVector<NonGarbageCollectedContainer>>();
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  vec->push_back(NonGarbageCollectedContainer(obj, 1));
  driver.FinishGC();
  EXPECT_TRUE(obj);
}

TEST_F(IncrementalMarkingTest, HeapVectorPushBackStdPair) {
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  HeapVector<std::pair<Member<LinkedObject>, Member<LinkedObject>>>* vec =
      MakeGarbageCollected<
          HeapVector<std::pair<Member<LinkedObject>, Member<LinkedObject>>>>();
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  vec->push_back(
      std::make_pair(Member<LinkedObject>(obj1), Member<LinkedObject>(obj2)));
  driver.FinishGC();
  EXPECT_TRUE(obj1);
  EXPECT_TRUE(obj2);
}

TEST_F(IncrementalMarkingTest, HeapVectorEmplaceBackMember) {
  WeakPersistent<LinkedObject> obj = MakeGarbageCollected<LinkedObject>();
  HeapVector<Member<LinkedObject>>* vec =
      MakeGarbageCollected<HeapVector<Member<LinkedObject>>>();
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  vec->emplace_back(obj);
  driver.FinishGC();
  EXPECT_TRUE(obj);
}

TEST_F(IncrementalMarkingTest, HeapVectorEmplaceBackNonGCedContainer) {
  WeakPersistent<LinkedObject> obj = MakeGarbageCollected<LinkedObject>();
  HeapVector<NonGarbageCollectedContainer>* vec =
      MakeGarbageCollected<HeapVector<NonGarbageCollectedContainer>>();
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  vec->emplace_back(obj, 1);
  driver.FinishGC();
  EXPECT_TRUE(obj);
}

TEST_F(IncrementalMarkingTest, HeapVectorEmplaceBackStdPair) {
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  HeapVector<std::pair<Member<LinkedObject>, Member<LinkedObject>>>* vec =
      MakeGarbageCollected<
          HeapVector<std::pair<Member<LinkedObject>, Member<LinkedObject>>>>();
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  vec->emplace_back(obj1, obj2);
  driver.FinishGC();
  EXPECT_TRUE(obj1);
  EXPECT_TRUE(obj2);
}

TEST_F(IncrementalMarkingTest, HeapVectorCopyMember) {
  WeakPersistent<LinkedObject> obj = MakeGarbageCollected<LinkedObject>();
  HeapVector<Member<LinkedObject>>* vec =
      MakeGarbageCollected<HeapVector<Member<LinkedObject>>>();
  vec->push_back(obj);
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  *MakeGarbageCollected<HeapVector<Member<LinkedObject>>>() = *vec;
  driver.FinishGC();
  EXPECT_TRUE(obj);
}

TEST_F(IncrementalMarkingTest, HeapVectorCopyMemberInCtor) {
  WeakPersistent<LinkedObject> obj = MakeGarbageCollected<LinkedObject>();
  HeapVector<Member<LinkedObject>>* vec =
      MakeGarbageCollected<HeapVector<Member<LinkedObject>>>();
  vec->push_back(obj);
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  MakeGarbageCollected<HeapVector<Member<LinkedObject>>>(*vec);
  driver.FinishGC();
  // Copy during object construction does not emit write barriers as
  // in-construction/on-stack objects would be found during conservative GC.
  EXPECT_FALSE(obj);
}

TEST_F(IncrementalMarkingTest, HeapVectorCopyNonGCedContainer) {
  WeakPersistent<LinkedObject> obj = MakeGarbageCollected<LinkedObject>();
  HeapVector<NonGarbageCollectedContainer>* vec =
      MakeGarbageCollected<HeapVector<NonGarbageCollectedContainer>>();
  vec->emplace_back(obj, 1);
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  *MakeGarbageCollected<HeapVector<NonGarbageCollectedContainer>>() = *vec;
  driver.FinishGC();
  EXPECT_TRUE(obj);
}

TEST_F(IncrementalMarkingTest, HeapVectorCopyNonGCedContainerInCtor) {
  WeakPersistent<LinkedObject> obj = MakeGarbageCollected<LinkedObject>();
  HeapVector<NonGarbageCollectedContainer>* vec =
      MakeGarbageCollected<HeapVector<NonGarbageCollectedContainer>>();
  vec->emplace_back(obj, 1);
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  MakeGarbageCollected<HeapVector<NonGarbageCollectedContainer>>(*vec);
  driver.FinishGC();
  // Copy during object construction does not emit write barriers as
  // in-construction/on-stack objects would be found during conservative GC.
  EXPECT_FALSE(obj);
}

TEST_F(IncrementalMarkingTest, HeapVectorCopyStdPair) {
  using ValueType = std::pair<Member<LinkedObject>, Member<LinkedObject>>;
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  HeapVector<ValueType>* vec = MakeGarbageCollected<HeapVector<ValueType>>();
  vec->emplace_back(obj1, obj2);
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  *MakeGarbageCollected<HeapVector<ValueType>>() = *vec;
  driver.FinishGC();
  EXPECT_TRUE(obj1);
  EXPECT_TRUE(obj2);
}

TEST_F(IncrementalMarkingTest, HeapVectorCopyStdPairInCtor) {
  using ValueType = std::pair<Member<LinkedObject>, Member<LinkedObject>>;
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  HeapVector<ValueType>* vec = MakeGarbageCollected<HeapVector<ValueType>>();
  vec->emplace_back(obj1, obj2);
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  MakeGarbageCollected<HeapVector<ValueType>>(*vec);
  driver.FinishGC();
  // Copy during object construction does not emit write barriers as
  // in-construction/on-stack objects would be found during conservative GC.
  EXPECT_FALSE(obj1);
  EXPECT_FALSE(obj2);
}

TEST_F(IncrementalMarkingTest, HeapVectorMoveMember) {
  WeakPersistent<LinkedObject> obj = MakeGarbageCollected<LinkedObject>();
  HeapVector<Member<LinkedObject>>* vec =
      MakeGarbageCollected<HeapVector<Member<LinkedObject>>>();
  vec->push_back(obj);
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  *MakeGarbageCollected<HeapVector<Member<LinkedObject>>>() = std::move(*vec);
  driver.FinishGC();
  EXPECT_TRUE(obj);
}

TEST_F(IncrementalMarkingTest, HeapVectorMoveMemberInCtor) {
  WeakPersistent<LinkedObject> obj = MakeGarbageCollected<LinkedObject>();
  HeapVector<Member<LinkedObject>>* vec =
      MakeGarbageCollected<HeapVector<Member<LinkedObject>>>();
  vec->push_back(obj);
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  MakeGarbageCollected<HeapVector<Member<LinkedObject>>>(std::move(*vec));
  driver.FinishGC();
  // Move during object construction does not emit write barriers as
  // in-construction/on-stack objects would be found during conservative GC.
  EXPECT_FALSE(obj);
}

TEST_F(IncrementalMarkingTest, HeapVectorMoveNonGCedContainer) {
  WeakPersistent<LinkedObject> obj = MakeGarbageCollected<LinkedObject>();
  HeapVector<NonGarbageCollectedContainer>* vec =
      MakeGarbageCollected<HeapVector<NonGarbageCollectedContainer>>();
  vec->emplace_back(obj, 1);
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  *MakeGarbageCollected<HeapVector<NonGarbageCollectedContainer>>() =
      std::move(*vec);
  driver.FinishGC();
  EXPECT_TRUE(obj);
}

TEST_F(IncrementalMarkingTest, HeapVectorMoveNonGCedContainerInCtor) {
  WeakPersistent<LinkedObject> obj = MakeGarbageCollected<LinkedObject>();
  HeapVector<NonGarbageCollectedContainer>* vec =
      MakeGarbageCollected<HeapVector<NonGarbageCollectedContainer>>();
  vec->emplace_back(obj, 1);
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  MakeGarbageCollected<HeapVector<NonGarbageCollectedContainer>>(
      std::move(*vec));
  driver.FinishGC();
  // Move during object construction does not emit write barriers as
  // in-construction/on-stack objects would be found during conservative GC.
  EXPECT_FALSE(obj);
}

TEST_F(IncrementalMarkingTest, HeapVectorMoveStdPair) {
  using ValueType = std::pair<Member<LinkedObject>, Member<LinkedObject>>;
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  HeapVector<ValueType>* vec = MakeGarbageCollected<HeapVector<ValueType>>();
  vec->emplace_back(obj1, obj2);
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  *MakeGarbageCollected<HeapVector<ValueType>>() = std::move(*vec);
  driver.FinishGC();
  EXPECT_TRUE(obj1);
  EXPECT_TRUE(obj2);
}

TEST_F(IncrementalMarkingTest, HeapVectorMoveStdPairInCtor) {
  using ValueType = std::pair<Member<LinkedObject>, Member<LinkedObject>>;
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  HeapVector<ValueType>* vec = MakeGarbageCollected<HeapVector<ValueType>>();
  vec->emplace_back(obj1, obj2);
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  MakeGarbageCollected<HeapVector<ValueType>>(std::move(*vec));
  driver.FinishGC();
  // Move during object construction does not emit write barriers as
  // in-construction/on-stack objects would be found during conservative GC.
  EXPECT_FALSE(obj1);
  EXPECT_FALSE(obj2);
}

TEST_F(IncrementalMarkingTest, HeapVectorSwapMember) {
  using VectorType = HeapVector<Member<LinkedObject>>;
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  VectorType* vec1 = MakeGarbageCollected<VectorType>();
  vec1->push_back(obj1);
  VectorType* vec2 = MakeGarbageCollected<VectorType>();
  vec2->push_back(obj2);
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  std::swap(*vec1, *vec2);
  driver.FinishGC();
  EXPECT_TRUE(obj1);
  EXPECT_TRUE(obj2);
}

TEST_F(IncrementalMarkingTest, HeapVectorSwapNonGCedContainer) {
  using VectorType = HeapVector<NonGarbageCollectedContainer>;
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  VectorType* vec1 = MakeGarbageCollected<VectorType>();
  vec1->emplace_back(obj1, 1);
  VectorType* vec2 = MakeGarbageCollected<VectorType>();
  vec2->emplace_back(obj2, 2);
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  std::swap(*vec1, *vec2);
  driver.FinishGC();
  EXPECT_TRUE(obj1);
  EXPECT_TRUE(obj2);
}

TEST_F(IncrementalMarkingTest, HeapVectorSwapStdPair) {
  using ValueType = std::pair<Member<LinkedObject>, Member<LinkedObject>>;
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  HeapVector<ValueType>* vec1 = MakeGarbageCollected<HeapVector<ValueType>>();
  vec1->emplace_back(obj1, nullptr);
  HeapVector<ValueType>* vec2 = MakeGarbageCollected<HeapVector<ValueType>>();
  vec2->emplace_back(nullptr, obj2);
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  std::swap(*vec1, *vec2);
  driver.FinishGC();
  EXPECT_TRUE(obj1);
  EXPECT_TRUE(obj2);
}

TEST_F(IncrementalMarkingTest, HeapVectorSubscriptOperator) {
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  HeapVector<Member<LinkedObject>>* vec =
      MakeGarbageCollected<HeapVector<Member<LinkedObject>>>();
  vec->push_back(obj1);
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  EXPECT_EQ(1u, vec->size());
  EXPECT_EQ(obj1, (*vec)[0]);
  (*vec)[0] = obj2.Get();
  EXPECT_EQ(obj2, (*vec)[0]);
  driver.FinishGC();
  EXPECT_FALSE(obj1);
  EXPECT_TRUE(obj2);
}

TEST_F(IncrementalMarkingTest, HeapVectorEagerTracingStopsAtMember) {
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj3 = MakeGarbageCollected<LinkedObject>();
  obj1->set_next(obj3);
  HeapVector<NonGarbageCollectedContainerRoot>* vec =
      MakeGarbageCollected<HeapVector<NonGarbageCollectedContainerRoot>>();
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  vec->emplace_back(obj1, obj2, 3);
  driver.FinishGC();
  EXPECT_TRUE(obj1);
  EXPECT_TRUE(obj2);
  EXPECT_TRUE(obj3);
}

// =============================================================================
// HeapDeque support. ==========================================================
// =============================================================================

TEST_F(IncrementalMarkingTest, HeapDequePushBackMember) {
  WeakPersistent<LinkedObject> obj = MakeGarbageCollected<LinkedObject>();
  HeapDeque<Member<LinkedObject>>* deq =
      MakeGarbageCollected<HeapDeque<Member<LinkedObject>>>();
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  deq->push_back(obj);
  driver.FinishGC();
  EXPECT_TRUE(obj);
}

TEST_F(IncrementalMarkingTest, HeapDequePushFrontMember) {
  WeakPersistent<LinkedObject> obj = MakeGarbageCollected<LinkedObject>();
  HeapDeque<Member<LinkedObject>>* deq =
      MakeGarbageCollected<HeapDeque<Member<LinkedObject>>>();
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  deq->push_front(obj);
  driver.FinishGC();
  EXPECT_TRUE(obj);
}

TEST_F(IncrementalMarkingTest, HeapDequeEmplaceBackMember) {
  WeakPersistent<LinkedObject> obj = MakeGarbageCollected<LinkedObject>();
  HeapDeque<Member<LinkedObject>>* deq =
      MakeGarbageCollected<HeapDeque<Member<LinkedObject>>>();
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  deq->emplace_back(obj);
  driver.FinishGC();
  EXPECT_TRUE(obj);
}

TEST_F(IncrementalMarkingTest, HeapDequeEmplaceFrontMember) {
  WeakPersistent<LinkedObject> obj = MakeGarbageCollected<LinkedObject>();
  HeapDeque<Member<LinkedObject>>* deq =
      MakeGarbageCollected<HeapDeque<Member<LinkedObject>>>();
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  deq->emplace_front(obj);
  driver.FinishGC();
  EXPECT_TRUE(obj);
}

TEST_F(IncrementalMarkingTest, HeapDequeCopyMember) {
  WeakPersistent<LinkedObject> obj = MakeGarbageCollected<LinkedObject>();
  HeapDeque<Member<LinkedObject>>* deq =
      MakeGarbageCollected<HeapDeque<Member<LinkedObject>>>();
  deq->push_back(obj);
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  *MakeGarbageCollected<HeapDeque<Member<LinkedObject>>>() = *deq;
  driver.FinishGC();
  EXPECT_TRUE(obj);
}

TEST_F(IncrementalMarkingTest, HeapDequeCopyMemberInCtor) {
  WeakPersistent<LinkedObject> obj = MakeGarbageCollected<LinkedObject>();
  HeapDeque<Member<LinkedObject>>* deq =
      MakeGarbageCollected<HeapDeque<Member<LinkedObject>>>();
  deq->push_back(obj);
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  MakeGarbageCollected<HeapDeque<Member<LinkedObject>>>(*deq);
  driver.FinishGC();
  // Copy during object construction does not emit write barriers as
  // in-construction/on-stack objects would be found during conservative GC.
  EXPECT_FALSE(obj);
}

TEST_F(IncrementalMarkingTest, HeapDequeMoveMember) {
  WeakPersistent<LinkedObject> obj = MakeGarbageCollected<LinkedObject>();
  HeapDeque<Member<LinkedObject>>* deq =
      MakeGarbageCollected<HeapDeque<Member<LinkedObject>>>();
  deq->push_back(obj);
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  *MakeGarbageCollected<HeapDeque<Member<LinkedObject>>>() = std::move(*deq);
  driver.FinishGC();
  EXPECT_TRUE(obj);
}

TEST_F(IncrementalMarkingTest, HeapDequeMoveMemberInCtor) {
  WeakPersistent<LinkedObject> obj = MakeGarbageCollected<LinkedObject>();
  HeapDeque<Member<LinkedObject>>* deq =
      MakeGarbageCollected<HeapDeque<Member<LinkedObject>>>();
  deq->push_back(obj);
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  MakeGarbageCollected<HeapDeque<Member<LinkedObject>>>(std::move(*deq));
  driver.FinishGC();
  // Move construction does not emit a write barrier.
  EXPECT_FALSE(obj);
}

TEST_F(IncrementalMarkingTest, HeapDequeSwapMember) {
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  HeapDeque<Member<LinkedObject>>* deq1 =
      MakeGarbageCollected<HeapDeque<Member<LinkedObject>>>();
  deq1->push_back(obj1);
  HeapDeque<Member<LinkedObject>>* deq2 =
      MakeGarbageCollected<HeapDeque<Member<LinkedObject>>>();
  deq2->push_back(obj2);
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  std::swap(*deq1, *deq2);
  driver.FinishGC();
  EXPECT_TRUE(obj1);
  EXPECT_TRUE(obj2);
}

// =============================================================================
// HeapHashSet support. ========================================================
// =============================================================================

namespace {

template <typename Container>
void Insert() {
  WeakPersistent<LinkedObject> obj = MakeGarbageCollected<LinkedObject>();
  Container* container = MakeGarbageCollected<Container>();
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  container->insert(obj.Get());
  driver.FinishGC();
  EXPECT_TRUE(obj);
}

template <typename Container>
void Copy() {
  WeakPersistent<LinkedObject> obj = MakeGarbageCollected<LinkedObject>();
  Container* container1 = MakeGarbageCollected<Container>();
  container1->insert(obj.Get());
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  Container* container2 = MakeGarbageCollected<Container>(*container1);
  EXPECT_TRUE(container1->Contains(obj));
  EXPECT_TRUE(container2->Contains(obj));
  driver.FinishGC();
  EXPECT_TRUE(obj);
}

template <typename Container>
void Move() {
  WeakPersistent<LinkedObject> obj = MakeGarbageCollected<LinkedObject>();
  Container* container1 = MakeGarbageCollected<Container>();
  Container* container2 = MakeGarbageCollected<Container>();
  container1->insert(obj.Get());
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  *container2 = std::move(*container1);
  driver.FinishGC();
  EXPECT_TRUE(obj);
}

template <typename Container>
void Swap() {
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  Container* container1 = MakeGarbageCollected<Container>();
  container1->insert(obj1.Get());
  Container* container2 = MakeGarbageCollected<Container>();
  container2->insert(obj2.Get());
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  std::swap(*container1, *container2);
  driver.FinishGC();
  EXPECT_TRUE(obj1);
  EXPECT_TRUE(obj2);
}

}  // namespace

TEST_F(IncrementalMarkingTest, HeapHashSetInsert) {
  Insert<HeapHashSet<Member<LinkedObject>>>();
  // Weak references are strongified for the current cycle.
  Insert<HeapHashSet<WeakMember<LinkedObject>>>();
}

TEST_F(IncrementalMarkingTest, HeapHashSetCopy) {
  Copy<HeapHashSet<Member<LinkedObject>>>();
  // Weak references are strongified for the current cycle.
  Copy<HeapHashSet<WeakMember<LinkedObject>>>();
}

TEST_F(IncrementalMarkingTest, HeapHashSetMove) {
  Move<HeapHashSet<Member<LinkedObject>>>();
  // Weak references are strongified for the current cycle.
  Move<HeapHashSet<WeakMember<LinkedObject>>>();
}

TEST_F(IncrementalMarkingTest, HeapHashSetSwap) {
  Swap<HeapHashSet<Member<LinkedObject>>>();
  // Weak references are strongified for the current cycle.
  Swap<HeapHashSet<WeakMember<LinkedObject>>>();
}

// =============================================================================
// HeapLinkedHashSet support. ==================================================
// =============================================================================

TEST_F(IncrementalMarkingTest, HeapLinkedHashSetInsert) {
  Insert<HeapLinkedHashSet<Member<LinkedObject>>>();
  // Weak references are strongified for the current cycle.
  Insert<HeapLinkedHashSet<WeakMember<LinkedObject>>>();
}

TEST_F(IncrementalMarkingTest, HeapLinkedHashSetCopy) {
  Copy<HeapLinkedHashSet<Member<LinkedObject>>>();
  // Weak references are strongified for the current cycle.
  Copy<HeapLinkedHashSet<WeakMember<LinkedObject>>>();
}

TEST_F(IncrementalMarkingTest, HeapLinkedHashSetMove) {
  Move<HeapLinkedHashSet<Member<LinkedObject>>>();
  // Weak references are strongified for the current cycle.
  Move<HeapLinkedHashSet<WeakMember<LinkedObject>>>();
}

TEST_F(IncrementalMarkingTest, HeapLinkedHashSetSwap) {
  Swap<HeapLinkedHashSet<Member<LinkedObject>>>();
  // Weak references are strongified for the current cycle.
  Swap<HeapLinkedHashSet<WeakMember<LinkedObject>>>();
}

// =============================================================================
// HeapHashCountedSet support. =================================================
// =============================================================================

// HeapHashCountedSet does not support copy or move.

TEST_F(IncrementalMarkingTest, HeapHashCountedSetInsert) {
  Insert<HeapHashCountedSet<Member<LinkedObject>>>();
  // Weak references are strongified for the current cycle.
  Insert<HeapHashCountedSet<WeakMember<LinkedObject>>>();
}

TEST_F(IncrementalMarkingTest, HeapHashCountedSetSwap) {
  // HeapHashCountedSet is not move constructible so we cannot use std::swap.
  {
    WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
    WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
    HeapHashCountedSet<Member<LinkedObject>>* container1 =
        MakeGarbageCollected<HeapHashCountedSet<Member<LinkedObject>>>();
    container1->insert(obj1.Get());
    HeapHashCountedSet<Member<LinkedObject>>* container2 =
        MakeGarbageCollected<HeapHashCountedSet<Member<LinkedObject>>>();
    container2->insert(obj2.Get());
    IncrementalMarkingTestDriver driver(ThreadState::Current());
    driver.StartGC();
    container1->swap(*container2);
    driver.FinishGC();
    EXPECT_TRUE(obj1);
    EXPECT_TRUE(obj2);
  }
  {
    WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
    WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
    HeapHashCountedSet<WeakMember<LinkedObject>>* container1 =
        MakeGarbageCollected<HeapHashCountedSet<WeakMember<LinkedObject>>>();
    container1->insert(obj1.Get());
    HeapHashCountedSet<WeakMember<LinkedObject>>* container2 =
        MakeGarbageCollected<HeapHashCountedSet<WeakMember<LinkedObject>>>();
    container2->insert(obj2.Get());
    IncrementalMarkingTestDriver driver(ThreadState::Current());
    driver.StartGC();
    container1->swap(*container2);
    driver.FinishGC();
    EXPECT_TRUE(obj1);
    EXPECT_TRUE(obj2);
  }
}

// =============================================================================
// HeapHashMap support. ========================================================
// =============================================================================

TEST_F(IncrementalMarkingTest, HeapHashMapInsertMember) {
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  HeapHashMap<Member<LinkedObject>, Member<LinkedObject>>* map =
      MakeGarbageCollected<
          HeapHashMap<Member<LinkedObject>, Member<LinkedObject>>>();
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  map->insert(obj1.Get(), obj2.Get());
  driver.FinishGC();
  EXPECT_TRUE(obj1);
  EXPECT_TRUE(obj2);
}

TEST_F(IncrementalMarkingTest, HeapHashMapInsertWeakMember) {
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  HeapHashMap<WeakMember<LinkedObject>, WeakMember<LinkedObject>>* map =
      MakeGarbageCollected<
          HeapHashMap<WeakMember<LinkedObject>, WeakMember<LinkedObject>>>();
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  map->insert(obj1.Get(), obj2.Get());
  driver.FinishGC();
  EXPECT_TRUE(obj1);
  EXPECT_TRUE(obj2);
}

TEST_F(IncrementalMarkingTest, HeapHashMapInsertMemberWeakMember) {
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  HeapHashMap<Member<LinkedObject>, WeakMember<LinkedObject>>* map =
      MakeGarbageCollected<
          HeapHashMap<Member<LinkedObject>, WeakMember<LinkedObject>>>();
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  map->insert(obj1.Get(), obj2.Get());
  driver.FinishGC();
  EXPECT_TRUE(obj1);
  EXPECT_TRUE(obj2);
}

TEST_F(IncrementalMarkingTest, HeapHashMapInsertWeakMemberMember) {
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  HeapHashMap<WeakMember<LinkedObject>, Member<LinkedObject>>* map =
      MakeGarbageCollected<
          HeapHashMap<WeakMember<LinkedObject>, Member<LinkedObject>>>();
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  map->insert(obj1.Get(), obj2.Get());
  driver.FinishGC();
  EXPECT_TRUE(obj1);
  EXPECT_TRUE(obj2);
}

TEST_F(IncrementalMarkingTest, HeapHashMapSetMember) {
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  HeapHashMap<Member<LinkedObject>, Member<LinkedObject>>* map =
      MakeGarbageCollected<
          HeapHashMap<Member<LinkedObject>, Member<LinkedObject>>>();
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  map->Set(obj1.Get(), obj2.Get());
  driver.FinishGC();
  EXPECT_TRUE(obj1);
  EXPECT_TRUE(obj2);
}

TEST_F(IncrementalMarkingTest, HeapHashMapSetMemberUpdateValue) {
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj3 = MakeGarbageCollected<LinkedObject>();
  HeapHashMap<Member<LinkedObject>, Member<LinkedObject>>* map =
      MakeGarbageCollected<
          HeapHashMap<Member<LinkedObject>, Member<LinkedObject>>>();
  map->insert(obj1.Get(), obj2.Get());
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  // Only |obj3| is newly added to |map|, so we only expect the barrier to
  // fire on this one.
  map->Set(obj1.Get(), obj3.Get());
  driver.FinishGC();
  EXPECT_FALSE(obj1);
  EXPECT_FALSE(obj2);
  EXPECT_TRUE(obj3);
}

TEST_F(IncrementalMarkingTest, HeapHashMapIteratorChangeKey) {
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj3 = MakeGarbageCollected<LinkedObject>();
  HeapHashMap<Member<LinkedObject>, Member<LinkedObject>>* map =
      MakeGarbageCollected<
          HeapHashMap<Member<LinkedObject>, Member<LinkedObject>>>();
  map->insert(obj1.Get(), obj2.Get());
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  auto it = map->find(obj1.Get());
  EXPECT_NE(map->end(), it);
  it->key = obj3.Get();
  driver.FinishGC();
  EXPECT_FALSE(obj1);
  EXPECT_FALSE(obj2);
  EXPECT_TRUE(obj3);
}

TEST_F(IncrementalMarkingTest, HeapHashMapIteratorChangeValue) {
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj3 = MakeGarbageCollected<LinkedObject>();
  HeapHashMap<Member<LinkedObject>, Member<LinkedObject>>* map =
      MakeGarbageCollected<
          HeapHashMap<Member<LinkedObject>, Member<LinkedObject>>>();
  map->insert(obj1.Get(), obj2.Get());
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  auto it = map->find(obj1.Get());
  EXPECT_NE(map->end(), it);
  it->value = obj3.Get();
  driver.FinishGC();
  EXPECT_FALSE(obj1);
  EXPECT_FALSE(obj2);
  EXPECT_TRUE(obj3);
}

TEST_F(IncrementalMarkingTest, HeapHashMapCopyMemberMember) {
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  HeapHashMap<Member<LinkedObject>, Member<LinkedObject>>* map1 =
      MakeGarbageCollected<
          HeapHashMap<Member<LinkedObject>, Member<LinkedObject>>>();
  map1->insert(ob
"""


```