Response:
Let's break down the thought process to analyze the provided C++ code and fulfill the request.

1. **Understand the Goal:** The primary goal is to understand the functionality of the `marker-unittest.cc` file, which is a C++ unit test file within the V8 project's `cppgc` (C++ Garbage Collection) component. The request also asks about potential Torque involvement, JavaScript relevance, logical reasoning within the code, and common programming errors it might expose.

2. **Initial Scan and Keywords:** Quickly scan the file for key terms:
    * `TEST_F`:  Indicates Google Test framework usage, meaning this file contains unit tests.
    * `Marker`:  A central class being tested.
    * `Persistent`, `Member`, `WeakMember`: These are smart pointers related to garbage collection.
    * `MakeGarbageCollected`:  A function for allocating garbage-collected objects.
    * `Trace`: A method indicating how objects are traversed during garbage collection.
    * `IsMarked`: A method to check if an object has been marked as reachable.
    * `DoMarking`, `InitializeMarker`, `FinishMarking`: Functions controlling the marking process.
    * `StackState`: An enum likely representing the state of the stack regarding potential pointers to the heap.
    * `IncrementalMarkingStepForTesting`:  Suggests incremental garbage collection testing.
    * `EphemeronPair`:  A data structure with specific GC behavior (key-value pairs where the value's liveness depends on the key).

3. **Identify the Core Functionality:**  The presence of `Marker` and the various tests strongly suggest this file tests the **marking phase of the C++ garbage collector**. Marking is the process of identifying which objects are reachable and therefore should not be garbage collected.

4. **Categorize the Tests:**  Group the tests by their apparent purpose. This helps structure the explanation. Common patterns emerge:
    * Tests related to different types of references (`Persistent`, `Member`, `WeakMember`).
    * Tests about reachability from the stack.
    * Tests about weak references being cleared or not.
    * Tests involving object hierarchies and nested objects.
    * Tests specifically for in-construction objects.
    * Tests for incremental marking.
    * Tests for `EphemeronPair`.

5. **Analyze Individual Tests (Mental Execution):** For each test, mentally simulate the code execution:
    * **Setup:** What objects are created, and what relationships are established?
    * **Action:** What is `DoMarking` or `IncrementalMarkingStepForTesting` called with?
    * **Assertion:** What `EXPECT_TRUE` or `EXPECT_FALSE` checks are performed, and why?

    *Example: `TEST_F(MarkerTest, PersistentIsMarked)`*
        * *Setup:* A `Persistent<GCed>` object is created.
        * *Action:* `DoMarking(StackState::kNoHeapPointers)` is called.
        * *Assertion:* `EXPECT_TRUE(header.IsMarked())` - This verifies that persistently held objects are marked even without stack references.

6. **Address Specific Questions from the Request:**

    * **Functionality:**  Summarize the categories of tests and their overall goal (testing the marking phase of the C++ garbage collector).
    * **Torque:** Look for `.tq` extension. Since it's `.cc`, it's C++, not Torque. State this explicitly.
    * **JavaScript Relevance:**  Consider how C++ garbage collection in V8 relates to JavaScript. JavaScript objects are managed by V8's GC, which includes the C++ GC for internal C++ objects. The concepts of reachability, persistent handles, and weak references have parallels in JavaScript (though the implementation details differ). Provide JavaScript examples of similar concepts (object reachability, `WeakRef`).
    * **Code Logic Reasoning (Hypothetical Inputs/Outputs):**  Choose a couple of tests and provide a simple example of how different inputs (`StackState`) affect the output (whether an object is marked).
    * **Common Programming Errors:** Think about common mistakes related to manual memory management that garbage collection aims to prevent (dangling pointers, memory leaks). Also consider errors specific to garbage collection concepts like improper handling of weak references or misunderstanding reachability.

7. **Refine and Organize:**  Structure the explanation logically:
    * Start with a general overview of the file's purpose.
    * Detail the functionalities based on the test categories.
    * Address the specific questions in the request clearly and concisely.
    * Use clear language and provide examples where necessary.

8. **Review and Verify:**  Read through the entire explanation to ensure accuracy, clarity, and completeness. Double-check that all parts of the request have been addressed. For instance, ensure the assumptions for the input/output example are clear.

This iterative process of scanning, categorizing, analyzing, and refining leads to a comprehensive understanding of the code and the ability to answer the user's request effectively. The mental execution of the tests is crucial for understanding the specific scenarios being covered.
这是一个名为 `marker-unittest.cc` 的 C++ 源代码文件，属于 V8 JavaScript 引擎的 `cppgc`（C++ Garbage Collection）组件的单元测试。它主要用于测试 `cppgc` 中 **标记（Marking）** 功能的正确性。标记是垃圾回收的核心阶段之一，其目标是识别出哪些对象是“存活的”（reachable），哪些是“垃圾”（unreachable），以便后续的清理阶段可以回收垃圾对象占用的内存。

**主要功能概括:**

`marker-unittest.cc` 文件包含多个单元测试，用于验证 `cppgc::Marker` 类的各种行为和场景，包括：

1. **基本标记功能:**
   - 验证持久对象（`Persistent`）总是被标记。
   - 验证通过成员指针（`Member`）可达的对象会被标记。
   - 验证不可达的对象不会被标记。
   - 验证从栈上可达的对象会被标记（在特定栈状态下）。

2. **弱引用处理:**
   - 验证指向不可达对象的弱引用（`WeakPersistent`, `WeakMember`）会被清除（设置为 null）。
   - 验证指向可达对象的弱引用不会被清除。

3. **深度对象图处理:**
   - 验证在深层对象层次结构中，所有可达对象都会被标记。

4. **栈上对象处理:**
   - 验证栈上的嵌套对象会被正确标记。

5. **对象构造期间的标记:**
   - 测试在对象构造函数执行期间，如果对象被其他已标记对象引用，最终会被正确标记。

6. **增量标记:**
   - 测试增量标记的步骤和最终完成状态。
   - 验证在增量标记过程中，根对象和成员对象会被逐步标记。
   - 验证在分配期间进行增量标记的场景。

7. **EphemeronPair 处理:**
   - 测试 `EphemeronPair`（临时键值对，只有当键存活时值才存活）的标记行为。

**关于文件扩展名和 Torque:**

如果 `v8/test/unittests/heap/cppgc/marker-unittest.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。Torque 是一种 V8 使用的类型安全、编译时的元编程语言，用于生成高效的 C++ 代码。然而，根据提供的代码内容和 `.cc` 扩展名，可以确定它是一个 **C++ 源代码文件**，而不是 Torque 文件。

**与 JavaScript 的功能关系:**

虽然这是一个 C++ 的单元测试文件，但它直接关系到 V8 JavaScript 引擎的垃圾回收机制。`cppgc` 是 V8 中用于管理 C++ 对象的垃圾回收器，这些 C++ 对象是 V8 内部实现 JavaScript 各种功能的基础。

以下是一些 JavaScript 功能与 `cppgc` 标记功能相关的例子：

```javascript
// JavaScript 例子 1: 对象的可达性

let obj1 = { data: 1 };
let obj2 = { ref: obj1 }; // obj1 被 obj2 引用

// 在垃圾回收的标记阶段，如果 obj2 是可达的（比如被全局变量引用），
// 那么 obj1 也会被标记为可达的。

// 如果没有其他引用指向 obj2，那么在下一次垃圾回收时，
// obj2 和 obj1 都会被标记为不可达，最终被回收。

// JavaScript 例子 2: WeakRef (弱引用)

let obj = { data: 1 };
let weakRef = new WeakRef(obj);

// 在垃圾回收的标记阶段，即使存在 weakRef，如果 obj 没有被其他强引用指向，
// obj 仍然会被标记为不可达并被回收。
// 回收后，weakRef.deref() 将返回 undefined。

// JavaScript 例子 3: finalizationRegistry (终结器注册表)

let obj = { data: 1 };
let registry = new FinalizationRegistry(heldValue => {
  console.log("对象被回收了!", heldValue);
});
registry.register(obj, "obj的信息");
// ... 当 obj 没有其他强引用指向时，在垃圾回收后，
// 注册的回调函数会被调用。

// 这些 JavaScript 的特性背后，V8 的 C++ 垃圾回收器（包括 cppgc）
// 负责识别和管理这些对象的生命周期。cppgc 的标记阶段就是决定
// 哪些 C++ 对象需要保留，哪些可以回收的关键步骤。
```

**代码逻辑推理 (假设输入与输出):**

以 `TEST_F(MarkerTest, ReachableMemberIsMarked)` 为例：

**假设输入:**

1. 创建一个 `Persistent<GCed>` 对象 `parent`。
2. 在 `parent` 中创建一个 `GCed` 类型的子对象，并通过 `parent->SetChild()` 方法设置。

**代码逻辑:**

1. 在 `DoMarking(StackState::kNoHeapPointers)` 调用之前，子对象的 `IsMarked()` 方法返回 `false`。
2. `DoMarking` 函数模拟执行一次主要垃圾回收的标记阶段，并且假设栈上没有指向堆的指针。
3. 在标记阶段，由于 `parent` 是 `Persistent` 的，它会被标记为可达。
4. 标记器会遍历 `parent` 的成员，发现 `child_` 指向子对象。
5. 子对象因此也会被标记为可达。

**预期输出:**

在 `DoMarking` 调用之后，子对象的 `IsMarked()` 方法返回 `true`。

**涉及用户常见的编程错误 (举例说明):**

这个单元测试主要关注垃圾回收器的内部逻辑，但它也间接反映了用户在编写 C++ 代码时可能遇到的一些与内存管理相关的常见错误：

1. **忘记解除不再需要的对象的引用，导致内存泄漏:**

   ```c++
   // 假设用户代码中没有正确管理对象的生命周期
   void someFunction() {
     GCed* obj = MakeGarbageCollected<GCed>(GetAllocationHandle());
     // ... 使用 obj ...
     // 忘记删除或解除引用 obj，如果 cppgc 没有正确标记和回收，
     // 可能会导致内存泄漏。
   }
   ```

   `cppgc` 通过标记和清理来解决这个问题。单元测试验证了标记阶段能够正确识别哪些对象仍然被引用。

2. **使用悬挂指针 (dangling pointer):**

   虽然 `cppgc` 负责管理内存，但如果用户在 C++ 代码中直接操作裸指针，仍然可能出现悬挂指针的问题。`cppgc` 通过智能指针 (`Persistent`, `Member`, `WeakMember`) 来帮助避免这类问题。

   ```c++
   void anotherFunction() {
     GCed* obj = MakeGarbageCollected<GCed>(GetAllocationHandle());
     GCed* rawPtr = obj; // 保存一个裸指针

     // ... cppgc 可能回收了 obj ...

     // 此时 rawPtr 可能变成悬挂指针，访问它会导致未定义行为。
     // rawPtr->SomeMethod(); // 潜在的错误
   }
   ```

   `cppgc` 的 `WeakPersistent` 和 `WeakMember` 可以用来观察对象的生命周期，避免在对象被回收后仍然访问它。`marker-unittest.cc` 中关于弱引用的测试就验证了 `cppgc` 能正确处理这种情况。

总之，`v8/test/unittests/heap/cppgc/marker-unittest.cc` 是一个关键的测试文件，用于确保 V8 的 C++ 垃圾回收器的标记功能正确无误，这对于 V8 的稳定性和性能至关重要，并间接影响到 JavaScript 代码的执行。

### 提示词
```
这是目录为v8/test/unittests/heap/cppgc/marker-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/heap/cppgc/marker-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```