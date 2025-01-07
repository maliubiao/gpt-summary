Response:
Let's break down the thought process for analyzing this C++ unit test file.

**1. Initial Scan and Keywords:**

The first step is to quickly scan the file for prominent keywords and patterns. I'm looking for things like:

* `#include`:  This tells me about dependencies. Seeing `cppgc/persistent.h`, `cppgc/cross-thread-persistent.h`, and various `cppgc/internal/` headers strongly suggests this file is about testing the `Persistent` and `CrossThreadPersistent` smart pointer types in cppgc.
* `namespace cppgc::internal`: This confirms it's related to the internal implementation of cppgc.
* `struct GCed : GarbageCollected<GCed>`: This indicates the presence of garbage-collected objects, which are the target of the persistent pointers.
* `template <template <typename> class PersistentType>`: This pattern appears repeatedly, indicating that the tests are parameterized over different kinds of persistent pointers (e.g., `Persistent`, `WeakPersistent`, `CrossThreadPersistent`).
* `TEST_F(PersistentTest, ...)`:  This clearly identifies the file as a Google Test unit test suite focused on `Persistent` types.
* `EXPECT_EQ`, `EXPECT_NE`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_STREQ`: These are standard Google Test assertion macros, signaling testing of various properties.
* Operations like constructors (`Ctor`), assignment operators, `Get()`, `Release()`, `Clear()`, `Trace()`, and comparisons (`==`, `!=`).

**2. Understanding the Core Concepts:**

Based on the keywords, I form a basic understanding:

* **Persistent Pointers:** The core subject is the `Persistent` and related smart pointer types provided by cppgc for managing garbage-collected objects. These pointers hold references that prevent the garbage collector from reclaiming the pointed-to object.
* **Strong vs. Weak:** The presence of `WeakPersistent` and `subtle::WeakCrossThreadPersistent` suggests the tests cover both strong references (keeping the object alive) and weak references (allowing the object to be collected).
* **Cross-Thread:**  The `CrossThreadPersistent` types indicate support for sharing persistent pointers between different threads.
* **Lifecycle Management:** The tests likely cover how these pointers are created, copied, moved, assigned, and how they release their hold on objects.
* **Garbage Collection Interaction:** The `Trace()` method in `GCed` and the `TestRootVisitor` hint at how these persistent pointers interact with the garbage collection process. Strong pointers cause the object to be traced as live, while weak pointers have a different behavior.
* **Source Location:** The `LocalizedPersistent` and `LocalizedCrossThreadPersistent` types, along with `SourceLocation::Current()`, point to testing the ability to track the source code location where a persistent pointer was created.

**3. Analyzing the Test Structure:**

I observe the use of template functions like `NullStateCtor`, `RawCtor`, `CopyCtor`, etc. This tells me the tests are systematically covering different operations on the persistent pointer types. The templates are instantiated with different `PersistentType` variants to ensure all flavors are tested.

**4. Inferring Functionality from Test Names and Code:**

I examine individual test functions to understand their purpose:

* **`NullStateCtor`:** Tests the creation of persistent pointers without an initial object (e.g., default constructor, `nullptr`).
* **`RawCtor`:** Tests creating persistent pointers directly from raw pointers.
* **`CopyCtor` and `MoveCtor`:** Test copy and move construction, respectively. The move constructor's behavior (whether it actually moves or falls back to copy) is important.
* **`Assignment` tests:** Similar to constructors, but for assignment operations.
* **`ClearTest` and `ReleaseTest`:** Test methods for explicitly releasing the pointer's hold on the object.
* **`HeterogeneousConversion`:** Tests implicit and explicit conversions between different persistent pointer types (e.g., `Persistent` to `WeakPersistent`).
* **`ImplicitUpcast` and `ExplicitDowncast`:** Test type conversions in inheritance hierarchies.
* **`EqualityTest`:** Tests the equality and inequality operators.
* **`TraceStrong` and `TraceWeak`:** Verify how strong and weak persistent pointers affect garbage collection tracing.
* **`ClearOnHeapDestruction`:** Checks if persistent pointers are correctly cleared when the heap they belong to is destroyed.
* **`LocalizedPersistent`:** Focuses on testing the source location tracking feature.

**5. Connecting to JavaScript (If Applicable):**

While this is low-level C++ code, I consider if there's a conceptual connection to JavaScript. JavaScript has automatic garbage collection, and the *idea* of holding a reference to prevent collection is analogous to how JavaScript variables keep objects alive. However, the specific `Persistent` types are an implementation detail of V8, not directly exposed in JavaScript. Therefore, a direct JavaScript example is difficult. The core concept of managing object lifecycles exists, but the mechanism is different.

**6. Code Logic and Examples (If Applicable):**

For code logic inference, I look at specific test cases. For example, in `CopyAssignment`, I see assertions about `NodesInUse()`. This implies the test is checking if the old node associated with the persistent pointer is correctly released when a new object is assigned.

* **Hypothetical Input/Output (CopyAssignment):**
    * **Input:** A `Persistent<GCed>` `p1` pointing to a `GCed` object, and an uninitialized `Persistent<GCed>` `p2`.
    * **Action:** `p2 = p1;`
    * **Expected Output:** `p2` now points to the same `GCed` object as `p1`. The number of nodes in use increases.

**7. Common Programming Errors:**

I think about common mistakes developers might make when dealing with smart pointers or garbage collection:

* **Dangling Pointers:**  Forgetting to manage the lifetime of the underlying object, leading to accessing freed memory. Persistent pointers help avoid this.
* **Memory Leaks:**  Holding onto objects unintentionally, preventing them from being garbage collected. Understanding the difference between strong and weak pointers is crucial here.
* **Incorrectly Assuming Object Lifetime:** Making assumptions about when an object will be collected, which can lead to errors if using raw pointers in a garbage-collected environment.

**8. Synthesizing the Summary (Part 1):**

Finally, I synthesize the gathered information into a concise summary, addressing the specific questions in the prompt:

* **Functionality:** Test the behavior of `Persistent`, `WeakPersistent`, `CrossThreadPersistent`, and `WeakCrossThreadPersistent` smart pointers in cppgc. This includes construction, assignment, destruction, comparison, interaction with garbage collection, and source location tracking.
* **Torque:** No, the file ends in `.cc`, not `.tq`.
* **JavaScript Relation:**  Indirectly related to JavaScript's garbage collection concept but not directly exposed.
* **Code Logic:** Provide a simple example related to copy assignment and node management.
* **Common Errors:** Mention dangling pointers and memory leaks.
* **Overall Function:**  Summarize the file's role in testing the persistent pointer family within cppgc.
这是一个V8 C++源代码文件，名为 `persistent-family-unittest.cc`，位于 `v8/test/unittests/heap/cppgc/` 目录下。从文件名和包含的头文件来看，它主要用于测试 `cppgc`（C++ Garbage Collection）库中关于 **持久化句柄 (Persistent Handles)** 及其相关功能的单元测试。

**功能归纳:**

该文件的主要功能是为 `cppgc` 库中的以下持久化句柄类型编写单元测试：

* **`cppgc::Persistent<T>` (强持久化句柄):**  用于持有对垃圾回收对象的强引用，防止对象被垃圾回收器回收。
* **`cppgc::WeakPersistent<T>` (弱持久化句柄):** 用于持有对垃圾回收对象的弱引用。即使存在弱引用，对象仍然可以被垃圾回收器回收。当对象被回收后，弱持久化句柄会自动置空。
* **`cppgc::subtle::CrossThreadPersistent<T>` (跨线程强持久化句柄):** 类似于 `cppgc::Persistent<T>`，但设计用于在不同线程之间安全地持有对垃圾回收对象的强引用。
* **`cppgc::subtle::WeakCrossThreadPersistent<T>` (跨线程弱持久化句柄):** 类似于 `cppgc::WeakPersistent<T>`，但设计用于在不同线程之间安全地持有对垃圾回收对象的弱引用。

**具体测试的功能点包括但不限于:**

* **构造函数:** 测试各种构造函数（默认构造、拷贝构造、移动构造、从原始指针构造等）的行为和资源管理。
* **赋值运算符:** 测试各种赋值运算符（拷贝赋值、移动赋值、从原始指针赋值等）的行为和资源管理。
* **`Get()` 方法:**  测试获取持久化句柄所指向的原始指针的功能。
* **`Release()` 方法:** 测试释放持久化句柄对对象的拥有权并返回原始指针的功能。
* **`Clear()` 方法:** 测试将持久化句柄置空的功能。
* **类型转换:** 测试持久化句柄之间的隐式和显式类型转换，包括向上转型和向下转型。
* **比较运算符:** 测试持久化句柄之间的相等和不等比较。
* **与垃圾回收器的交互:** 通过模拟垃圾回收过程（`Trace` 方法和 `TestRootVisitor`），测试强持久化句柄如何阻止对象被回收，以及弱持久化句柄在对象被回收后的行为。
* **跨线程安全:**  尽管代码中没有直接的跨线程测试，但使用了 `CrossThreadPersistent` 类型，表明测试涵盖了这些类型的基本操作。
* **本地化持久化句柄 (`LocalizedPersistent` 和 `LocalizedCrossThreadPersistent`):**  测试带有源码位置信息的持久化句柄。

**关于文件类型和 JavaScript 关系:**

* **`.tq 结尾？`**  `v8/test/unittests/heap/cppgc/persistent-family-unittest.cc` 以 `.cc` 结尾，因此它是一个 **C++** 源代码文件，而不是 Torque (`.tq`) 文件。
* **与 JavaScript 的功能关系:**  `cppgc` 是 V8 引擎的 C++ 垃圾回收器。持久化句柄是 `cppgc` 提供的核心机制，用于在 C++ 代码中安全地持有对 JavaScript 堆上对象的引用，防止这些对象被过早回收。虽然这个文件是 C++ 代码，但它测试的功能直接支撑着 V8 引擎管理 JavaScript 对象的生命周期。

**代码逻辑推理 (假设输入与输出):**

以 `CopyAssignment` 测试中的一个片段为例：

```c++
TEST_F(PersistentTest, CopyAssignment) {
  // ...
  {
    PersistentType<GCed> p1 =
        MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    PersistentType<GCed> p2;
    EXPECT_EQ(1u, GetRegion<PersistentType>(heap).NodesInUse());
    p2 = p1;
    EXPECT_EQ(2u, GetRegion<PersistentType>(heap).NodesInUse());
    EXPECT_EQ(p1.Get(), p2.Get());
    EXPECT_EQ(p1, p2);
  }
  // ...
}
```

**假设输入:**

1. `heap` 是一个有效的 `cppgc::Heap` 对象。
2. `MakeGarbageCollected<GCed>(heap->GetAllocationHandle())` 成功在堆上分配了一个 `GCed` 类型的对象，并返回其指针。

**代码逻辑推理:**

1. 创建一个强持久化句柄 `p1`，它持有新分配的 `GCed` 对象。此时，持久化区域中使用的节点数应该是 1。
2. 创建一个空的强持久化句柄 `p2`。
3. 将 `p1` 赋值给 `p2` (拷贝赋值)。
4. **预期输出:**
   * 持久化区域中使用的节点数应该增加到 2，因为拷贝赋值会创建一个新的节点来管理 `p2` 的引用。
   * `p2.Get()` 应该返回与 `p1.Get()` 相同的原始指针，即指向同一个 `GCed` 对象。
   * `p1 == p2` 的比较结果应该为 true。

**用户常见的编程错误 (举例说明):**

在使用持久化句柄时，用户可能会犯以下错误：

1. **忘记使用持久化句柄而使用原始指针:**  如果直接使用原始指针持有垃圾回收对象，对象可能会在 C++ 代码仍然持有指针的情况下被垃圾回收器回收，导致悬 dangling 指针。

   ```c++
   // 错误示例
   GCed* gced = MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
   // ... 一段时间后，gced 指向的对象可能被回收
   gced->Trace(nullptr); // 访问已回收的内存，导致错误
   ```

   **正确做法:**

   ```c++
   Persistent<GCed> persistent_gced = MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
   // ...
   persistent_gced->Trace(nullptr); // 通过持久化句柄访问，确保对象存活
   ```

2. **在不需要强引用时使用了强持久化句柄:** 如果只需要观察对象而不阻止其回收，应该使用弱持久化句柄。过度使用强持久化句柄可能会导致内存泄漏，因为对象永远不会被回收。

   ```c++
   // 可能导致内存泄漏的示例
   std::vector<Persistent<GCed>> keep_alive;
   for (int i = 0; i < 100000; ++i) {
     keep_alive.push_back(MakeGarbageCollected<GCed>(heap->GetAllocationHandle()));
   }
   // 这些对象可能永远不会被回收，即使程序不再需要它们
   ```

   **更合理的做法 (如果不需要一直持有):**

   ```c++
   std::vector<WeakPersistent<GCed>> observe;
   for (int i = 0; i < 100000; ++i) {
     observe.push_back(MakeGarbageCollected<GCed>(heap->GetAllocationHandle()));
   }
   // ... 稍后检查弱引用是否仍然有效
   for (const auto& weak_gced : observe) {
     if (GCed* g = weak_gced.Get()) {
       // 对象仍然存活，可以安全访问
       g->Trace(nullptr);
     }
   }
   ```

**总结 (第 1 部分):**

`v8/test/unittests/heap/cppgc/persistent-family-unittest.cc` 文件是 V8 引擎中 `cppgc` 垃圾回收器关于持久化句柄功能的单元测试集合。它测试了强持久化、弱持久化以及它们的跨线程变体的各种构造、赋值、操作和与垃圾回收器的交互行为。该文件是确保 V8 引擎能够安全可靠地管理 C++ 代码中 JavaScript 堆上对象生命周期的关键组成部分。

Prompt: 
```
这是目录为v8/test/unittests/heap/cppgc/persistent-family-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/heap/cppgc/persistent-family-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <vector>

#include "include/cppgc/allocation.h"
#include "include/cppgc/cross-thread-persistent.h"
#include "include/cppgc/garbage-collected.h"
#include "include/cppgc/internal/persistent-node.h"
#include "include/cppgc/internal/pointer-policies.h"
#include "include/cppgc/member.h"
#include "include/cppgc/persistent.h"
#include "include/cppgc/source-location.h"
#include "include/cppgc/type-traits.h"
#include "src/base/logging.h"
#include "src/base/platform/platform.h"
#include "src/heap/cppgc/globals.h"
#include "src/heap/cppgc/heap.h"
#include "src/heap/cppgc/liveness-broker.h"
#include "src/heap/cppgc/visitor.h"
#include "test/unittests/heap/cppgc/tests.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace cppgc {
namespace internal {

namespace {

struct GCed : GarbageCollected<GCed> {
  static size_t trace_call_count;
  virtual void Trace(cppgc::Visitor*) const { ++trace_call_count; }
};
size_t GCed::trace_call_count = 0;

struct DerivedGCed : GCed {
  void Trace(cppgc::Visitor* v) const override { GCed::Trace(v); }
};

template <template <typename> class PersistentType>
struct PersistentRegionTrait;

template <>
struct PersistentRegionTrait<Persistent> {
  static PersistentRegion& Get(cppgc::Heap* heap) {
    return internal::Heap::From(heap)->GetStrongPersistentRegion();
  }
};

template <>
struct PersistentRegionTrait<WeakPersistent> {
  static PersistentRegion& Get(cppgc::Heap* heap) {
    return internal::Heap::From(heap)->GetWeakPersistentRegion();
  }
};

template <>
struct PersistentRegionTrait<subtle::CrossThreadPersistent> {
  static CrossThreadPersistentRegion& Get(cppgc::Heap* heap) {
    return internal::Heap::From(heap)->GetStrongCrossThreadPersistentRegion();
  }
};

template <>
struct PersistentRegionTrait<subtle::WeakCrossThreadPersistent> {
  static CrossThreadPersistentRegion& Get(cppgc::Heap* heap) {
    return internal::Heap::From(heap)->GetWeakCrossThreadPersistentRegion();
  }
};

template <template <typename> class PersistentType>
auto& GetRegion(cppgc::Heap* heap) {
  return PersistentRegionTrait<PersistentType>::Get(heap);
}

template <typename T>
using LocalizedPersistent =
    internal::BasicPersistent<T, internal::StrongPersistentPolicy,
                              internal::KeepLocationPolicy,
                              internal::DefaultPersistentCheckingPolicy>;

template <typename T>
using LocalizedCrossThreadPersistent = internal::BasicCrossThreadPersistent<
    T, internal::StrongCrossThreadPersistentPolicy,
    internal::KeepLocationPolicy, internal::DisabledCheckingPolicy>;

class TestRootVisitor final : public RootVisitorBase {
 public:
  TestRootVisitor() = default;

  const auto& WeakCallbacks() const { return weak_callbacks_; }

  void ProcessWeakCallbacks() {
    const auto info = LivenessBrokerFactory::Create();
    for (const auto& cb : weak_callbacks_) {
      cb.first(info, cb.second);
    }
    weak_callbacks_.clear();
  }

 protected:
  void VisitRoot(const void* t, TraceDescriptor desc,
                 const SourceLocation&) final {
    desc.callback(nullptr, desc.base_object_payload);
  }
  void VisitWeakRoot(const void*, TraceDescriptor, WeakCallback callback,
                     const void* object, const SourceLocation&) final {
    weak_callbacks_.emplace_back(callback, object);
  }

 private:
  std::vector<std::pair<WeakCallback, const void*>> weak_callbacks_;
};

class PersistentTest : public testing::TestWithHeap {};
class PersistentDeathTest : public testing::TestWithHeap {};

}  // namespace

template <template <typename> class PersistentType>
void NullStateCtor(cppgc::Heap* heap) {
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  {
    PersistentType<GCed> empty;
    EXPECT_EQ(nullptr, empty.Get());
    EXPECT_EQ(nullptr, empty.Release());
    EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  }
  {
    PersistentType<GCed> empty = nullptr;
    EXPECT_EQ(nullptr, empty.Get());
    EXPECT_EQ(nullptr, empty.Release());
    EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  }
  {
    PersistentType<GCed> empty = kSentinelPointer;
    EXPECT_EQ(kSentinelPointer, empty);
    EXPECT_EQ(kSentinelPointer, empty.Release());
    EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  }
  {
    // Runtime null must not allocated associated node.
    PersistentType<GCed> empty = static_cast<GCed*>(nullptr);
    EXPECT_EQ(nullptr, empty.Get());
    EXPECT_EQ(nullptr, empty.Release());
    EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  }
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
}

TEST_F(PersistentTest, NullStateCtor) {
  auto* heap = GetHeap();
  NullStateCtor<Persistent>(heap);
  NullStateCtor<WeakPersistent>(heap);
  NullStateCtor<subtle::CrossThreadPersistent>(heap);
  NullStateCtor<subtle::WeakCrossThreadPersistent>(heap);
}

template <template <typename> class PersistentType>
void RawCtor(cppgc::Heap* heap) {
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  GCed* gced = MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
  {
    PersistentType<GCed> p = gced;
    EXPECT_EQ(gced, p.Get());
    EXPECT_EQ(1u, GetRegion<PersistentType>(heap).NodesInUse());
  }
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  {
    PersistentType<GCed> p = *gced;
    EXPECT_EQ(gced, p.Get());
    EXPECT_EQ(1u, GetRegion<PersistentType>(heap).NodesInUse());
  }
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  {
    PersistentType<const GCed> p = gced;
    EXPECT_EQ(gced, p.Get());
    EXPECT_EQ(1u, GetRegion<PersistentType>(heap).NodesInUse());
  }
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
}

TEST_F(PersistentTest, RawCtor) {
  auto* heap = GetHeap();
  RawCtor<Persistent>(heap);
  RawCtor<WeakPersistent>(heap);
  RawCtor<subtle::CrossThreadPersistent>(heap);
  RawCtor<subtle::WeakCrossThreadPersistent>(heap);
}

template <template <typename> class PersistentType>
void CopyCtor(cppgc::Heap* heap) {
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  {
    PersistentType<GCed> p1 =
        MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    EXPECT_EQ(1u, GetRegion<PersistentType>(heap).NodesInUse());
    PersistentType<GCed> p2 = p1;
    EXPECT_EQ(2u, GetRegion<PersistentType>(heap).NodesInUse());
    EXPECT_EQ(p1.Get(), p2.Get());
    EXPECT_EQ(p1, p2);
  }
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  {
    PersistentType<GCed> p1;
    EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
    PersistentType<GCed> p2 = p1;
    EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
    EXPECT_EQ(nullptr, p1.Get());
    EXPECT_EQ(p1, p2);
  }
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  {
    PersistentType<DerivedGCed> p1 =
        MakeGarbageCollected<DerivedGCed>(heap->GetAllocationHandle());
    EXPECT_EQ(1u, GetRegion<PersistentType>(heap).NodesInUse());
    PersistentType<GCed> p2 = p1;
    EXPECT_EQ(2u, GetRegion<PersistentType>(heap).NodesInUse());
    EXPECT_EQ(p1.Get(), p2.Get());
    EXPECT_EQ(p1, p2);
  }
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  {
    static constexpr size_t kSlots = 512u;
    const PersistentType<GCed> prototype =
        MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    std::vector<PersistentType<GCed>> vector;
    vector.reserve(kSlots);
    EXPECT_EQ(1u, GetRegion<PersistentType>(heap).NodesInUse());
    for (size_t i = 0; i < kSlots; ++i) {
      vector.emplace_back(prototype);
      EXPECT_EQ(i + 2, GetRegion<PersistentType>(heap).NodesInUse());
    }
    vector.clear();
    EXPECT_EQ(1u, GetRegion<PersistentType>(heap).NodesInUse());
  }
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
}

TEST_F(PersistentTest, CopyCtor) {
  auto* heap = GetHeap();
  CopyCtor<Persistent>(heap);
  CopyCtor<WeakPersistent>(heap);
  CopyCtor<subtle::CrossThreadPersistent>(heap);
  CopyCtor<subtle::WeakCrossThreadPersistent>(heap);
}

template <template <typename> class PersistentType>
void MoveCtor(cppgc::Heap* heap) {
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  {
    GCed* gced = MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    PersistentType<GCed> p1 = gced;
    EXPECT_EQ(1u, GetRegion<PersistentType>(heap).NodesInUse());
    PersistentType<GCed> p2 = std::move(p1);
    EXPECT_EQ(1u, GetRegion<PersistentType>(heap).NodesInUse());
    EXPECT_EQ(gced, p2.Get());
    // Moved-from-object is in the valid specified (nullptr) state.
    EXPECT_EQ(nullptr, p1.Get());
  }
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  {
    PersistentType<DerivedGCed> p1 =
        MakeGarbageCollected<DerivedGCed>(heap->GetAllocationHandle());
    EXPECT_EQ(1u, GetRegion<PersistentType>(heap).NodesInUse());
    // Move ctor is not heterogeneous - fall back to copy ctor.
    PersistentType<GCed> p2 = std::move(p1);
    EXPECT_EQ(2u, GetRegion<PersistentType>(heap).NodesInUse());
    EXPECT_EQ(p1.Get(), p2.Get());
    EXPECT_EQ(p1, p2);
  }
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  {
    PersistentType<GCed> p1;
    EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
    PersistentType<GCed> p2 = std::move(p1);
    EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
    EXPECT_EQ(nullptr, p1.Get());
    EXPECT_EQ(p1, p2);
  }
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
}

TEST_F(PersistentTest, MoveCtor) {
  auto* heap = GetHeap();
  MoveCtor<Persistent>(heap);
  MoveCtor<WeakPersistent>(heap);
  MoveCtor<subtle::CrossThreadPersistent>(heap);
  MoveCtor<subtle::WeakCrossThreadPersistent>(heap);
}

template <template <typename> class PersistentType,
          template <typename> class MemberType>
void MemberCtor(cppgc::Heap* heap) {
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  {
    MemberType<GCed> m =
        MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    PersistentType<GCed> p = m;
    EXPECT_EQ(m.Get(), p.Get());
    EXPECT_EQ(m, p);
    EXPECT_EQ(1u, GetRegion<PersistentType>(heap).NodesInUse());
  }
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
}

TEST_F(PersistentTest, MemberCtor) {
  auto* heap = GetHeap();
  MemberCtor<Persistent, Member>(heap);
  MemberCtor<Persistent, WeakMember>(heap);
  MemberCtor<Persistent, UntracedMember>(heap);
  MemberCtor<WeakPersistent, Member>(heap);
  MemberCtor<WeakPersistent, WeakMember>(heap);
  MemberCtor<WeakPersistent, UntracedMember>(heap);
  MemberCtor<subtle::CrossThreadPersistent, Member>(heap);
  MemberCtor<subtle::CrossThreadPersistent, WeakMember>(heap);
  MemberCtor<subtle::CrossThreadPersistent, UntracedMember>(heap);
  MemberCtor<subtle::WeakCrossThreadPersistent, Member>(heap);
  MemberCtor<subtle::WeakCrossThreadPersistent, WeakMember>(heap);
  MemberCtor<subtle::WeakCrossThreadPersistent, UntracedMember>(heap);
}

template <template <typename> class PersistentType>
void NullStateAssignment(cppgc::Heap* heap) {
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  {
    PersistentType<GCed> p =
        MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    EXPECT_EQ(1u, GetRegion<PersistentType>(heap).NodesInUse());
    p = nullptr;
    EXPECT_EQ(nullptr, p.Get());
    EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  }
  {
    PersistentType<GCed> p =
        MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    EXPECT_EQ(1u, GetRegion<PersistentType>(heap).NodesInUse());
    p = kSentinelPointer;
    EXPECT_EQ(kSentinelPointer, p);
    EXPECT_EQ(kSentinelPointer, p.Get());
    EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  }
  {
    PersistentType<GCed> p =
        MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    EXPECT_EQ(1u, GetRegion<PersistentType>(heap).NodesInUse());
    p = static_cast<GCed*>(nullptr);
    EXPECT_EQ(nullptr, p.Get());
    EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  }
}

TEST_F(PersistentTest, NullStateAssignment) {
  auto* heap = GetHeap();
  NullStateAssignment<Persistent>(heap);
  NullStateAssignment<WeakPersistent>(heap);
  NullStateAssignment<subtle::CrossThreadPersistent>(heap);
  NullStateAssignment<subtle::WeakCrossThreadPersistent>(heap);
}

template <template <typename> class PersistentType>
void RawAssignment(cppgc::Heap* heap) {
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  GCed* gced = MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
  {
    PersistentType<GCed> p;
    EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
    p = gced;
    EXPECT_EQ(gced, p.Get());
    EXPECT_EQ(1u, GetRegion<PersistentType>(heap).NodesInUse());
  }
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  {
    PersistentType<GCed> p;
    EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
    p = *gced;
    EXPECT_EQ(gced, p.Get());
    EXPECT_EQ(1u, GetRegion<PersistentType>(heap).NodesInUse());
  }
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
}

TEST_F(PersistentTest, RawAssignment) {
  auto* heap = GetHeap();
  RawAssignment<Persistent>(heap);
  RawAssignment<WeakPersistent>(heap);
  RawAssignment<subtle::CrossThreadPersistent>(heap);
  RawAssignment<subtle::WeakCrossThreadPersistent>(heap);
}

template <template <typename> class PersistentType>
void CopyAssignment(cppgc::Heap* heap) {
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  {
    PersistentType<GCed> p1 =
        MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    PersistentType<GCed> p2;
    EXPECT_EQ(1u, GetRegion<PersistentType>(heap).NodesInUse());
    p2 = p1;
    EXPECT_EQ(2u, GetRegion<PersistentType>(heap).NodesInUse());
    EXPECT_EQ(p1.Get(), p2.Get());
    EXPECT_EQ(p1, p2);
  }
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  {
    PersistentType<GCed> p1 =
        MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    PersistentType<GCed> p2 =
        MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    EXPECT_EQ(2u, GetRegion<PersistentType>(heap).NodesInUse());
    p2 = p1;
    // The old node from p2 must be dropped.
    EXPECT_EQ(2u, GetRegion<PersistentType>(heap).NodesInUse());
    EXPECT_EQ(p1.Get(), p2.Get());
    EXPECT_EQ(p1, p2);
  }
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  {
    PersistentType<DerivedGCed> p1 =
        MakeGarbageCollected<DerivedGCed>(heap->GetAllocationHandle());
    PersistentType<GCed> p2;
    EXPECT_EQ(1u, GetRegion<PersistentType>(heap).NodesInUse());
    p2 = p1;
    EXPECT_EQ(2u, GetRegion<PersistentType>(heap).NodesInUse());
    EXPECT_EQ(p1.Get(), p2.Get());
    EXPECT_EQ(p1, p2);
  }
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  {
    static constexpr size_t kSlots = 512u;
    const PersistentType<GCed> prototype =
        MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    std::vector<PersistentType<GCed>> vector(kSlots);
    EXPECT_EQ(1u, GetRegion<PersistentType>(heap).NodesInUse());
    size_t i = 0;
    for (auto& p : vector) {
      p = prototype;
      EXPECT_EQ(i + 2, GetRegion<PersistentType>(heap).NodesInUse());
      ++i;
    }
    vector.clear();
    EXPECT_EQ(1u, GetRegion<PersistentType>(heap).NodesInUse());
  }
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
}

TEST_F(PersistentTest, CopyAssignment) {
  auto* heap = GetHeap();
  CopyAssignment<Persistent>(heap);
  CopyAssignment<WeakPersistent>(heap);
  CopyAssignment<subtle::CrossThreadPersistent>(heap);
  CopyAssignment<subtle::WeakCrossThreadPersistent>(heap);
}

template <template <typename> class PersistentType>
void MoveAssignment(cppgc::Heap* heap) {
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  {
    GCed* gced = MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    PersistentType<GCed> p1 = gced;
    PersistentType<GCed> p2;
    EXPECT_EQ(1u, GetRegion<PersistentType>(heap).NodesInUse());
    p2 = std::move(p1);
    EXPECT_EQ(1u, GetRegion<PersistentType>(heap).NodesInUse());
    EXPECT_EQ(gced, p2.Get());
    // Moved-from-object is in the valid specified (nullptr) state.
    EXPECT_EQ(nullptr, p1.Get());
  }
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  {
    PersistentType<GCed> p1;
    PersistentType<GCed> p2 =
        MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    EXPECT_EQ(1u, GetRegion<PersistentType>(heap).NodesInUse());
    p2 = std::move(p1);
    EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
    // Moved-from-object is in the valid specified (nullptr) state.
    EXPECT_EQ(nullptr, p2.Get());
  }
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  {
    GCed* gced = MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    PersistentType<GCed> p1 = gced;
    PersistentType<GCed> p2 =
        MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    EXPECT_EQ(2u, GetRegion<PersistentType>(heap).NodesInUse());
    p2 = std::move(p1);
    // The old node from p2 must be dropped.
    EXPECT_EQ(1u, GetRegion<PersistentType>(heap).NodesInUse());
    EXPECT_EQ(gced, p2.Get());
    // Moved-from-object is in the valid specified (nullptr) state.
    EXPECT_EQ(nullptr, p1.Get());
  }
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  {
    PersistentType<DerivedGCed> p1 =
        MakeGarbageCollected<DerivedGCed>(heap->GetAllocationHandle());
    PersistentType<GCed> p2;
    EXPECT_EQ(1u, GetRegion<PersistentType>(heap).NodesInUse());
    // Move ctor is not heterogeneous - fall back to copy assignment.
    p2 = std::move(p1);
    EXPECT_EQ(2u, GetRegion<PersistentType>(heap).NodesInUse());
    EXPECT_EQ(p1.Get(), p2.Get());
    EXPECT_EQ(p1, p2);
  }
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
}

TEST_F(PersistentTest, MoveAssignment) {
  auto* heap = GetHeap();
  MoveAssignment<Persistent>(heap);
  MoveAssignment<WeakPersistent>(heap);
  MoveAssignment<subtle::CrossThreadPersistent>(heap);
  MoveAssignment<subtle::WeakCrossThreadPersistent>(heap);
}

template <template <typename> class PersistentType,
          template <typename> class MemberType>
void MemberAssignment(cppgc::Heap* heap) {
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  {
    MemberType<GCed> m =
        MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    PersistentType<GCed> p;
    p = m;
    EXPECT_EQ(m.Get(), p.Get());
    EXPECT_EQ(m, p);
    EXPECT_EQ(1u, GetRegion<PersistentType>(heap).NodesInUse());
  }
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
}

TEST_F(PersistentTest, MemberAssignment) {
  auto* heap = GetHeap();
  MemberAssignment<Persistent, Member>(heap);
  MemberAssignment<Persistent, WeakMember>(heap);
  MemberAssignment<Persistent, UntracedMember>(heap);
  MemberAssignment<WeakPersistent, Member>(heap);
  MemberAssignment<WeakPersistent, WeakMember>(heap);
  MemberAssignment<WeakPersistent, UntracedMember>(heap);
  MemberAssignment<subtle::CrossThreadPersistent, Member>(heap);
  MemberAssignment<subtle::CrossThreadPersistent, WeakMember>(heap);
  MemberAssignment<subtle::CrossThreadPersistent, UntracedMember>(heap);
  MemberAssignment<subtle::WeakCrossThreadPersistent, Member>(heap);
  MemberAssignment<subtle::WeakCrossThreadPersistent, WeakMember>(heap);
  MemberAssignment<subtle::WeakCrossThreadPersistent, UntracedMember>(heap);
}

template <template <typename> class PersistentType>
void ClearTest(cppgc::Heap* heap) {
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  PersistentType<GCed> p =
      MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
  EXPECT_EQ(1u, GetRegion<PersistentType>(heap).NodesInUse());
  EXPECT_NE(nullptr, p.Get());
  p.Clear();
  EXPECT_EQ(nullptr, p.Get());
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
}

TEST_F(PersistentTest, Clear) {
  auto* heap = GetHeap();
  ClearTest<Persistent>(heap);
  ClearTest<WeakPersistent>(heap);
  ClearTest<subtle::CrossThreadPersistent>(heap);
  ClearTest<subtle::WeakCrossThreadPersistent>(heap);
}

template <template <typename> class PersistentType>
void ReleaseTest(cppgc::Heap* heap) {
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
  GCed* gced = MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
  PersistentType<GCed> p = gced;
  EXPECT_EQ(1u, GetRegion<PersistentType>(heap).NodesInUse());
  EXPECT_NE(nullptr, p.Get());
  GCed* raw = p.Release();
  EXPECT_EQ(gced, raw);
  EXPECT_EQ(nullptr, p.Get());
  EXPECT_EQ(0u, GetRegion<PersistentType>(heap).NodesInUse());
}

TEST_F(PersistentTest, Release) {
  auto* heap = GetHeap();
  ReleaseTest<Persistent>(heap);
  ReleaseTest<WeakPersistent>(heap);
  ReleaseTest<subtle::CrossThreadPersistent>(heap);
  ReleaseTest<subtle::WeakCrossThreadPersistent>(heap);
}

template <template <typename> class PersistentType1,
          template <typename> class PersistentType2>
void HeterogeneousConversion(cppgc::Heap* heap) {
  EXPECT_EQ(0u, GetRegion<PersistentType1>(heap).NodesInUse());
  EXPECT_EQ(0u, GetRegion<PersistentType2>(heap).NodesInUse());
  {
    PersistentType1<GCed> persistent1 =
        MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    PersistentType2<GCed> persistent2 = persistent1;
    EXPECT_EQ(persistent1.Get(), persistent2.Get());
    EXPECT_EQ(1u, GetRegion<PersistentType1>(heap).NodesInUse());
    EXPECT_EQ(1u, GetRegion<PersistentType2>(heap).NodesInUse());
  }
  EXPECT_EQ(0u, GetRegion<PersistentType1>(heap).NodesInUse());
  EXPECT_EQ(0u, GetRegion<PersistentType2>(heap).NodesInUse());
  {
    PersistentType1<DerivedGCed> persistent1 =
        MakeGarbageCollected<DerivedGCed>(heap->GetAllocationHandle());
    PersistentType2<GCed> persistent2 = persistent1;
    EXPECT_EQ(persistent1.Get(), persistent2.Get());
    EXPECT_EQ(1u, GetRegion<PersistentType1>(heap).NodesInUse());
    EXPECT_EQ(1u, GetRegion<PersistentType2>(heap).NodesInUse());
  }
  EXPECT_EQ(0u, GetRegion<PersistentType1>(heap).NodesInUse());
  EXPECT_EQ(0u, GetRegion<PersistentType2>(heap).NodesInUse());
  {
    PersistentType1<GCed> persistent1 =
        MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    PersistentType2<GCed> persistent2;
    persistent2 = persistent1;
    EXPECT_EQ(persistent1.Get(), persistent2.Get());
    EXPECT_EQ(1u, GetRegion<PersistentType1>(heap).NodesInUse());
    EXPECT_EQ(1u, GetRegion<PersistentType2>(heap).NodesInUse());
  }
  EXPECT_EQ(0u, GetRegion<PersistentType1>(heap).NodesInUse());
  EXPECT_EQ(0u, GetRegion<PersistentType2>(heap).NodesInUse());
  {
    PersistentType1<DerivedGCed> persistent1 =
        MakeGarbageCollected<DerivedGCed>(heap->GetAllocationHandle());
    PersistentType2<GCed> persistent2;
    persistent2 = persistent1;
    EXPECT_EQ(persistent1.Get(), persistent2.Get());
    EXPECT_EQ(1u, GetRegion<PersistentType1>(heap).NodesInUse());
    EXPECT_EQ(1u, GetRegion<PersistentType2>(heap).NodesInUse());
  }
  EXPECT_EQ(0u, GetRegion<PersistentType1>(heap).NodesInUse());
  EXPECT_EQ(0u, GetRegion<PersistentType2>(heap).NodesInUse());
}

TEST_F(PersistentTest, HeterogeneousConversion) {
  auto* heap = GetHeap();
  HeterogeneousConversion<Persistent, WeakPersistent>(heap);
  HeterogeneousConversion<WeakPersistent, Persistent>(heap);
}

namespace {

class Parent : public GarbageCollected<Parent> {
 public:
  virtual void Trace(Visitor*) const {}
  void ParentFoo() { /* Dummy method to trigger vtable check on UBSan. */
  }
};
class Child : public Parent {
 public:
  void ChildFoo() { /* Dummy method to trigger vtable check on UBSan. */
  }
};

template <template <typename> class PersistentType>
void ImplicitUpcast(cppgc::Heap* heap) {
  PersistentType<Child> child;
  PersistentType<Parent> parent = child;
}

template <template <typename> class PersistentType>
void ExplicitDowncast(cppgc::Heap* heap) {
  PersistentType<Parent> parent{
      MakeGarbageCollected<Child>(heap->GetAllocationHandle())};
  PersistentType<Child> child = parent.template To<Child>();
  child->ChildFoo();
}

}  // namespace

TEST_F(PersistentTest, ImplicitUpcast) {
  auto* heap = GetHeap();
  ImplicitUpcast<Persistent>(heap);
  ImplicitUpcast<WeakPersistent>(heap);
  ImplicitUpcast<subtle::CrossThreadPersistent>(heap);
  ImplicitUpcast<subtle::WeakCrossThreadPersistent>(heap);
}

TEST_F(PersistentTest, ExplicitDowncast) {
  auto* heap = GetHeap();
  ExplicitDowncast<Persistent>(heap);
  ExplicitDowncast<WeakPersistent>(heap);
  ExplicitDowncast<subtle::CrossThreadPersistent>(heap);
  ExplicitDowncast<subtle::WeakCrossThreadPersistent>(heap);
}

namespace {
template <template <typename> class PersistentType1,
          template <typename> class PersistentType2>
void EqualityTest(cppgc::Heap* heap) {
  {
    GCed* gced = MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    PersistentType1<GCed> persistent1 = gced;
    PersistentType2<GCed> persistent2 = gced;
    EXPECT_TRUE(persistent1 == persistent2);
    EXPECT_FALSE(persistent1 != persistent2);
    persistent2 = persistent1;
    EXPECT_TRUE(persistent1 == persistent2);
    EXPECT_FALSE(persistent1 != persistent2);
  }
  {
    PersistentType1<GCed> persistent1 =
        MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    PersistentType2<GCed> persistent2 =
        MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    EXPECT_TRUE(persistent1 != persistent2);
    EXPECT_FALSE(persistent1 == persistent2);
  }
}
}  // namespace

TEST_F(PersistentTest, EqualityTest) {
  cppgc::Heap* heap = GetHeap();
  EqualityTest<Persistent, Persistent>(heap);
  EqualityTest<Persistent, WeakPersistent>(heap);
  EqualityTest<Persistent, subtle::CrossThreadPersistent>(heap);
  EqualityTest<Persistent, subtle::WeakCrossThreadPersistent>(heap);
  EqualityTest<WeakPersistent, Persistent>(heap);
  EqualityTest<WeakPersistent, WeakPersistent>(heap);
  EqualityTest<WeakPersistent, subtle::CrossThreadPersistent>(heap);
  EqualityTest<WeakPersistent, subtle::WeakCrossThreadPersistent>(heap);
  EqualityTest<subtle::CrossThreadPersistent, Persistent>(heap);
  EqualityTest<subtle::CrossThreadPersistent, WeakPersistent>(heap);
  EqualityTest<subtle::CrossThreadPersistent, subtle::CrossThreadPersistent>(
      heap);
  EqualityTest<subtle::CrossThreadPersistent,
               subtle::WeakCrossThreadPersistent>(heap);
  EqualityTest<subtle::WeakCrossThreadPersistent, Persistent>(heap);
  EqualityTest<subtle::WeakCrossThreadPersistent, WeakPersistent>(heap);
  EqualityTest<subtle::WeakCrossThreadPersistent,
               subtle::CrossThreadPersistent>(heap);
  EqualityTest<subtle::WeakCrossThreadPersistent,
               subtle::WeakCrossThreadPersistent>(heap);
}

TEST_F(PersistentTest, TraceStrong) {
  auto* heap = GetHeap();
  static constexpr size_t kItems = 512;
  std::vector<Persistent<GCed>> vec(kItems);
  for (auto& p : vec) {
    p = MakeGarbageCollected<GCed>(GetAllocationHandle());
  }
  {
    GCed::trace_call_count = 0;
    TestRootVisitor v;
    GetRegion<Persistent>(heap).Iterate(v);
    EXPECT_EQ(kItems, GCed::trace_call_count);
    EXPECT_EQ(kItems, GetRegion<Persistent>(heap).NodesInUse());
  }
  {
    GCed::trace_call_count = 0;
    vec[0].Clear();
    vec[kItems / 2].Clear();
    vec[kItems / 4].Clear();
    vec[kItems - 1].Clear();
    TestRootVisitor v;
    GetRegion<Persistent>(heap).Iterate(v);
    EXPECT_EQ(kItems - 4, GCed::trace_call_count);
    EXPECT_EQ(kItems - 4, GetRegion<Persistent>(heap).NodesInUse());
  }
  {
    GCed::trace_call_count = 0;
    vec.clear();
    TestRootVisitor v;
    GetRegion<Persistent>(heap).Iterate(v);
    EXPECT_EQ(0u, GCed::trace_call_count);
    EXPECT_EQ(0u, GetRegion<Persistent>(heap).NodesInUse());
  }
}

TEST_F(PersistentTest, TraceWeak) {
  auto* heap = GetHeap();
  static constexpr size_t kItems = 512;
  std::vector<WeakPersistent<GCed>> vec(kItems);
  for (auto& p : vec) {
    p = MakeGarbageCollected<GCed>(GetAllocationHandle());
  }
  GCed::trace_call_count = 0;
  TestRootVisitor v;
  GetRegion<WeakPersistent>(heap).Iterate(v);
  const auto& callbacks = v.WeakCallbacks();
  EXPECT_EQ(kItems, callbacks.size());
  EXPECT_EQ(kItems, GetRegion<WeakPersistent>(heap).NodesInUse());

  v.ProcessWeakCallbacks();
  for (const auto& p : vec) {
    EXPECT_EQ(nullptr, p.Get());
  }
  EXPECT_EQ(0u, GetRegion<WeakPersistent>(heap).NodesInUse());
}

TEST_F(PersistentTest, ClearOnHeapDestruction) {
  Persistent<GCed> persistent;
  WeakPersistent<GCed> weak_persistent;

  // Create another heap that can be destroyed during the test.
  auto heap = Heap::Create(GetPlatformHandle());
  persistent = MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
  weak_persistent = MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
  const Persistent<GCed> persistent_sentinel(kSentinelPointer);
  const WeakPersistent<GCed> weak_persistent_sentinel(kSentinelPointer);
  const subtle::CrossThreadPersistent<GCed> cross_thread_persistent_sentinel(
      kSentinelPointer);
  const subtle::WeakCrossThreadPersistent<GCed>
      cross_thread_weak_persistent_sentinel(kSentinelPointer);
  heap.reset();

  EXPECT_EQ(nullptr, persistent);
  EXPECT_EQ(nullptr, weak_persistent);
  // Sentinel values survive as they do not represent actual heap objects.
  EXPECT_EQ(kSentinelPointer, persistent_sentinel);
  EXPECT_EQ(kSentinelPointer, weak_persistent_sentinel);
}

#if V8_SUPPORTS_SOURCE_LOCATION
TEST_F(PersistentTest, LocalizedPersistent) {
  GCed* gced = MakeGarbageCollected<GCed>(GetAllocationHandle());
  {
    const auto expected_loc = SourceLocation::Current();
    LocalizedPersistent<GCed> p = gced;
    const auto actual_loc = p.Location();
    EXPECT_STREQ(expected_loc.Function(), actual_loc.Function());
    EXPECT_STREQ(expected_loc.FileName(), actual_loc.FileName());
    EXPECT_EQ(expected_loc.Line() + 1, actual_loc.Line());
  }
  {
    const auto expected_loc = SourceLocation::Current();
    LocalizedCrossThreadPersistent<GCed> p = gced;
    const auto actual_loc = p.Location();
    EXPECT_STREQ(expected_loc.Function(), actual_loc.Function());
    EXPECT_STREQ(expected_loc.FileName(), actual_loc.FileName());
    EXPECT_EQ(expected_loc.Line() + 1, actual_loc.Line());
  }
  {
    // Copy ctor doesn't copy source location.
    LocalizedPersistent<GCed> p1 = gced;
    LocalizedPersistent<GCed> p2 = p1;
    EXPECT_STREQ(p1.Location().Function(), p2.Location().Function());
    EXPECT_STREQ(p1.Location().FileName(), p2.Location().FileName());
    EXPECT_EQ(p1.Location().Line() + 1, p2.Location().Line());
  }
  {
    // Copy ctor doesn't copy source location.
    LocalizedCrossThreadPersistent<GCed> p1 = gced;
    LocalizedCrossThreadPersistent<GCed> p2 = p1;
    EXPECT_STREQ(p1.Location().Function(), p2.Location().Function());
    EXPECT_STREQ(p1.Location().FileName(), p2.Location().FileName());
    EXPECT_EQ(p1.Location().Line() + 1, p2.Location().Line());
  }
  {
    // Copy assignment doesn't copy source location.
    LocalizedPersistent<GCed> p1 = gced;
    LocalizedPersistent<GCed> p2;
    p2 = p1;
    EXPECT_STREQ(p1.Location().Function(), p2.Location().Function());
    EXPECT_STREQ(p1.Location().FileName(), p2.Location().FileName());
    EXPECT_EQ(p1.Location().Line() + 1, p2.Location().Line());
  }
  {
    // Copy assignment doesn't copy source location.
    LocalizedCrossThreadPersistent<GCed> p1 = gced;
    LocalizedCrossThreadPersistent<GCed> p2;
    p2 = p1;
    EXPECT_STREQ(p1.Location().Function(), p2.Location().Function());
    EXPECT_STREQ(p1.Location().FileName(), p2.Location().FileName());
    EXPECT_EQ(p1.Location().Line() + 1, p2.Location().Line());
  }
  {
    // Clearing doesn't clear source location.
    LocalizedPersistent<GCed> p1 = gced;
    LocalizedPersistent<GCed> p2 = gced;
    p2.Clear();
    EXPECT_STREQ(p1.Location().Function(), p2.Location().Function());
    EXPECT_STREQ(p1.Location().FileName(), p2.Location().FileName());
    EXPECT_EQ(p1.Location().Line() + 1, p2.Location().Line());
  }
  {
    // Clearing doesn't clear source location.
    LocalizedCrossThreadPersistent<GCed> p1 = gced;
    LocalizedCrossThreadPersistent<GCed> p2 = gced;
    p2.Clear();
    EXPECT_STREQ(p1.Location().Function(), p2.Location().Function());
    EXPECT_STREQ(p1.Location().FileName(), p2.Location().FileName());
    EXPECT_EQ(p1.Location().Line() + 1, p2.Location().Line());
  }
  {
    LocalizedPersistent<GCed> p1 = gced;
    const auto expected_loc = p1.Location();
    LocalizedPersistent<GCed> p2 = std::move(p1);
    EXPECT_STREQ(expected
"""


```