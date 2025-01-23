Response:
Let's break down the thought process for analyzing the provided C++ code and generating the summary.

1. **Understanding the Goal:** The primary request is to analyze the functionality of the provided C++ source code file (`unified-heap-unittest.cc`). Specifically, the prompt asks for:
    * Listing the functionalities.
    * Checking if it's a Torque file (based on the `.tq` extension).
    * Explaining its relation to JavaScript and providing examples.
    * Identifying code logic and providing input/output examples.
    * Pointing out common programming errors.
    * Summarizing the functionality.

2. **Initial Scan and Keyword Recognition:**  The first step is to quickly scan the code for key terms and patterns. I see:
    * `#include`: This indicates inclusion of other header files, suggesting dependencies and functionalities being brought in.
    * `namespace v8::internal`: This clearly places the code within the V8 engine's internal implementation.
    * `TEST_F`: This is a strong indicator of unit tests using the Google Test framework. The tests are named descriptively (e.g., `OnlyGC`, `FindingV8ToCppReference`).
    * `cppgc::`:  This namespace points to the C++ garbage collection system used within V8.
    * `v8::`: This namespace refers to the public V8 API.
    * `Wrappable`, `TracedReference`, `Persistent`, `WeakPersistent`: These are custom types likely related to object management and garbage collection within the test suite.
    * `WrapperHelper`: This suggests interactions between C++ objects and JavaScript objects (wrappers).
    * `CollectGarbage`, `InvokeMajorGC`, `SimulateIncrementalMarking`: These are functions related to triggering garbage collection.
    * `v8::Object`, `v8::Isolate`, `v8::Context`: These are core V8 JavaScript API types.
    * `DEBUG`, `V8_ENABLE_ALLOCATION_TIMEOUT`: These are preprocessor directives, indicating conditional compilation or features.

3. **Categorizing Functionalities based on Tests:** The `TEST_F` macros are the most direct way to understand the specific functionalities being tested. I'll go through each test and summarize its purpose:

    * `OnlyGC`:  Simple test to trigger garbage collection.
    * `FindingV8ToCppReference`: Checks how C++ objects referenced by JavaScript wrappers are handled during GC.
    * `WriteBarrierV8ToCppReference`: Tests the write barrier mechanism for references between JavaScript and C++ during incremental marking.
    * `FreeUnreferencedDuringNoGcScope`: Verifies that freeing unreferenced objects within a `NoGarbageCollectionScope` works correctly (DEBUG build only).
    * `TracedReferenceRetainsFromStack`: Tests that `TracedReference` keeps objects alive even after the `HandleScope` is gone.
    * `AllocationBeforeConfigureHeap`: Tests allocating C++ objects before the C++ heap is fully attached to the V8 heap.
    * `StandAloneCppGC`: Checks if C++ garbage collection can run independently of V8's GC.
    * `StandaloneTestingHeap`: Tests using a dedicated testing API for C++ GC.
    * Tests related to `CustomSpace`: These explore how C++ GC interacts with custom memory spaces.
    * `InConstructionObjectReferringToGlobalHandle`: Tests object creation and garbage collection during construction.
    * `ResetReferenceInDestructor`:  Checks the behavior of resetting `TracedReference` in a destructor.
    * Tests related to `OnStackReferencesAreTemporary` and `TracedReferenceOnStack`:  Focus on the lifecycle of `TracedReference` on the stack and how garbage collection interacts with them.
    * Tests involving `Operation` enum (`kCopy`, `kMove`):  Test moving and copying `TracedReference` and their impact on garbage collection.
    * `TracingInEphemerons`: Verifies that objects in JavaScript weak collections (ephemerons) are traced correctly.
    * `TracedReferenceHandlesDoNotLeak`: Ensures that internal handles associated with `TracedReference` are properly managed.
    * `WrapperWithTracedReferenceData`: Tests wrapping C++ data with `TracedReference` and accessing it from JavaScript.
    * `CppgcSweepingDuringMinorV8Sweeping`: Checks the interaction between C++ GC sweeping and V8's minor GC.
    * `AllocationTimeout`: Tests a mechanism to trigger GC based on the number of allocations.
    * `UsingV8Locker`: Examines the use of `v8::Locker` in a multi-threaded context and its interaction with C++ GC.

4. **Answering Specific Questions:**

    * **`.tq` extension:** The code snippet is C++ (`.cc`), not Torque (`.tq`).
    * **Relation to JavaScript:** The code heavily uses `v8::Object`, `v8::Isolate`, and `WrapperHelper`. This strongly indicates interaction with JavaScript objects. I'll formulate JavaScript examples that demonstrate creating wrappers around C++ objects.
    * **Code Logic and Input/Output:** I need to select a test case with clear logic. The `FindingV8ToCppReference` test is a good candidate. I'll define a scenario (input) and what's expected to happen (output), focusing on the destructor call count.
    * **Common Programming Errors:** The tests involving `TracedReference` and manual garbage collection hint at potential issues with object lifetime management. I'll give an example of a dangling pointer issue when C++ objects aren't properly tracked by the garbage collector.

5. **Summarizing the Functionality:** After analyzing the individual tests, I can synthesize a high-level summary that captures the overall purpose of the file. It's clearly a unit test suite focused on the integration of the C++ garbage collector (`cppgc`) with V8's JavaScript heap, specifically the "unified heap."

6. **Structuring the Output:**  Finally, I'll organize the information clearly, addressing each point in the prompt with appropriate headings and formatting. Using bullet points for lists of functionalities and code blocks for examples will improve readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe some tests are about low-level memory management.
* **Correction:**  The presence of `cppgc::` and the focus on garbage collection cycles indicate the tests are primarily about the integrated GC.
* **Initial thought:** Provide very complex JavaScript examples.
* **Correction:** Keep the JavaScript examples simple and focused on demonstrating the wrapping concept.
* **Initial thought:** Focus heavily on the technical details of each test.
* **Correction:**  Provide a high-level overview of what each test *achieves* rather than getting bogged down in implementation specifics. The prompt asks for functionality, not a code walkthrough.

By following this structured thought process, combining code scanning with an understanding of the request's nuances, I can generate a comprehensive and accurate summary of the provided V8 source code.
```
这是目录为v8/test/unittests/heap/cppgc-js/unified-heap-unittest.cc的一个v8源代码， 请列举一下它的功能,
如果v8/test/unittests/heap/cppgc-js/unified-heap-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

这个 C++ 文件 `unified-heap-unittest.cc` 是 V8 JavaScript 引擎的一部分，专门用于测试 **Unified Heap** 的功能。 Unified Heap 是 V8 中将 JavaScript 垃圾回收器和 C++ 垃圾回收器 (cppgc) 整合在一起的一种机制。

以下是该文件的一些主要功能点：

1. **测试基本的垃圾回收 (GC) 功能:**
   - 测试仅进行 GC 操作 (`OnlyGC`)。
   - 测试在没有嵌入器栈的情况下进行 GC (`CollectGarbageWithoutEmbedderStack`)。

2. **测试 JavaScript 对象到 C++ 对象的引用管理:**
   - 测试如何找到从 V8 (JavaScript) 指向 C++ 对象的引用 (`FindingV8ToCppReference`)。这涉及到 V8 的对象包装机制，允许 C++ 对象被 JavaScript 代码持有和访问。
   - 测试在 V8 到 C++ 的引用上使用写屏障 (`WriteBarrierV8ToCppReference`)。这对于增量标记等高级 GC 机制至关重要。

3. **测试 C++ 垃圾回收器的独立功能 (在特定场景下):**
   - 测试在没有 GC 作用域时释放未引用的 C++ 对象 (`FreeUnreferencedDuringNoGcScope`)。这涉及到 `cppgc::subtle::FreeUnreferencedObject`。
   - 测试独立的 C++ GC (`StandAloneCppGC`)，即使在存在 `TracedReference` 的情况下也能工作。
   - 测试通过 `StandaloneTestingHeap` API 进行垃圾回收。

4. **测试 `TracedReference` 的行为和生命周期:**
   - 测试 `TracedReference` 如何从栈上保留对象 (`TracedReferenceRetainsFromStack`)。
   - 测试 `TracedReference` 在栈上的临时性 (`OnStackReferencesAreTemporary`)。
   - 测试在栈上的 `TracedReference` 的行为 (`TracedReferenceOnStack`)。
   - 测试 `TracedReference` 的移动和复制操作 (`TracedReferenceMove`, `TracedReferenceCopy`)，包括在栈和堆之间的操作以及不同初始化状态下的操作。

5. **测试 Unified Heap 的初始化和配置:**
   - 测试在配置堆之前进行分配 (`AllocationBeforeConfigureHeap`)。

6. **测试自定义内存空间 (Custom Space) 的集成:**
   - 测试如何在 Unified Heap 中使用自定义内存空间，并收集相关的统计信息 (`CollectCustomSpaceStatisticsAtLastGC`)。

7. **测试在特定生命周期阶段的对象交互:**
   - 测试在构造过程中引用全局句柄的对象 (`InConstructionObjectReferringToGlobalHandle`)。
   - 测试在析构函数中重置引用的对象 (`ResetReferenceInDestructor`)。

8. **测试 Ephemerons (弱映射) 中的追踪:**
   - 测试属于 Ephemerons 的包装器是否被正确追踪 (`TracingInEphemerons`)。

9. **测试资源管理:**
   - 测试 `TracedReference` 句柄是否不会泄漏 (`TracedReferenceHandlesDoNotLeak`)。

10. **测试带有 `TracedReference` 数据的包装器:**
    - 测试包装器对象包含对其他 C++ 对象的 `TracedReference` 成员的情况 (`WrapperWithTracedReferenceData`)。

11. **测试 C++ GC 与 V8 GC 的协同工作:**
    - 测试在 V8 的 Minor GC 期间 C++ GC 的 Sweeping 阶段 (`CppgcSweepingDuringMinorV8Sweeping`)。

12. **测试基于分配超时的垃圾回收:**
    - 测试当分配次数超过预设阈值时是否会触发 GC (`AllocationTimeout`)。

13. **测试在多线程环境中使用 `v8::Locker` 的情况:**
    - 测试在持有 `v8::Locker` 的线程中操作 C++ 堆是否安全 (`UsingV8Locker`)。

**关于代码的特性：**

* **不是 Torque 代码:** 该文件以 `.cc` 结尾，表明它是 C++ 源代码，而不是 Torque 源代码（以 `.tq` 结尾）。
* **与 JavaScript 的功能有密切关系:**  该文件测试的是 Unified Heap，而 Unified Heap 的核心目标就是更好地整合 V8 的 JavaScript 堆和 C++ 堆。许多测试用例都涉及到 JavaScript 对象和 C++ 对象之间的交互。

**JavaScript 示例 (说明与 JavaScript 的关系):**

```javascript
// 假设在 C++ 端，`Wrappable` 类代表一个可以被 JavaScript 包装的对象。

// 在 JavaScript 中创建 `Wrappable` 的包装器
let wrappableInstance = new Wrappable(); // 假设 C++ 提供了这样的接口
let jsObject = getOrCreateWrapper(wrappableInstance); // C++ 代码负责创建包装器

// JavaScript 代码持有对包装器的引用
globalThis.myObject = jsObject;

// ... 一段时间后，如果 JavaScript 代码不再引用 `jsObject`，
// 并且 C++ 代码也不再强引用 `wrappableInstance`，
// 那么 Unified Heap 的 GC 机制应该能够回收 `wrappableInstance`。
```

**代码逻辑推理示例：**

以 `FindingV8ToCppReference` 测试为例：

**假设输入:**

1. 创建一个 `Wrappable` C++ 对象。
2. 使用 `WrapperHelper::CreateWrapper` 创建该 C++ 对象的 JavaScript 包装器对象 `api_object`。
3. 记录 `Wrappable::destructor_callcount` 的初始值为 0。
4. 进行一次不包含嵌入器栈信息的原子 GC。
5. 重置 JavaScript 包装器与 C++ 对象的连接 (`WrapperHelper::ResetWrappableConnection`)。
6. 再次进行一次不包含嵌入器栈信息的原子 GC。

**预期输出:**

1. 第一次 GC 后，由于 JavaScript 端仍然持有 `api_object` 的引用（通过 `handle_api_object`），C++ 对象 `wrappable_object` 不应该被回收，因此 `Wrappable::destructor_callcount` 仍然为 0。
2. 在重置连接后，JavaScript 包装器不再持有对 C++ 对象的有效引用。
3. 第二次 GC 后，由于没有其他强引用指向 `wrappable_object`，它应该被回收，因此 `Wrappable::destructor_callcount` 变为 1。

**用户常见的编程错误示例：**

与 Unified Heap 相关的常见编程错误可能包括：

1. **C++ 对象未被正确追踪，导致过早回收:**

   ```c++
   // C++ 代码
   class MyObject : public cppgc::GarbageCollected<MyObject> {
   public:
       int value;
   };

   MyObject* obj = new MyObject(); // 错误：未使用 cppgc::MakeGarbageCollected
   v8::Local<v8::Object> wrapper = WrapperHelper::CreateWrapper(isolate->GetCurrentContext(), obj);

   // ... 稍后，如果 GC 运行，`obj` 可能会被回收，即使 JavaScript 包装器仍然存在，
   // 导致访问已释放内存。
   ```

   **正确做法:** 应该使用 `cppgc::MakeGarbageCollected` 来分配需要被 cppgc 管理的对象。

2. **在 C++ 对象的析构函数中访问 JavaScript 对象时没有适当的保护:**

   如果 C++ 对象的析构函数需要与 JavaScript 环境交互（例如，通知 JavaScript 对象即将被销毁），则需要确保 V8 堆的状态是安全的，并且 JavaScript 环境仍然可用。这通常需要谨慎地使用 `v8::Isolate` 和作用域。

**归纳一下它的功能 (第 1 部分):**

这个 `unified-heap-unittest.cc` 文件的第 1 部分主要集中在测试 Unified Heap 的核心功能，包括：

* **基本的垃圾回收机制**，确保 GC 能够正常运行。
* **JavaScript 到 C++ 对象引用的正确管理**，这是 Unified Heap 的关键特性。
* **C++ 垃圾回收器在特定场景下的独立运作**，验证其在与 V8 整合前的基本能力。
* **`TracedReference` 的各种行为和生命周期管理**，这是连接 JavaScript 和 C++ 对象的重要工具。
* **Unified Heap 的初始化和配置流程**。
* **自定义内存空间与 Unified Heap 的集成**。

这些测试旨在验证 Unified Heap 的基本正确性和稳定性，为更高级的功能测试奠定基础。

### 提示词
```
这是目录为v8/test/unittests/heap/cppgc-js/unified-heap-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/heap/cppgc-js/unified-heap-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include "include/cppgc/allocation.h"
#include "include/cppgc/explicit-management.h"
#include "include/cppgc/garbage-collected.h"
#include "include/cppgc/heap-consistency.h"
#include "include/cppgc/internal/api-constants.h"
#include "include/cppgc/persistent.h"
#include "include/cppgc/testing.h"
#include "include/libplatform/libplatform.h"
#include "include/v8-context.h"
#include "include/v8-cppgc.h"
#include "include/v8-local-handle.h"
#include "include/v8-locker.h"
#include "include/v8-object.h"
#include "include/v8-traced-handle.h"
#include "src/api/api-inl.h"
#include "src/common/globals.h"
#include "src/flags/flags.h"
#include "src/heap/cppgc-js/cpp-heap.h"
#include "src/heap/cppgc/heap-object-header.h"
#include "src/heap/cppgc/sweeper.h"
#include "src/heap/gc-tracer-inl.h"
#include "src/objects/objects-inl.h"
#include "test/unittests/heap/cppgc-js/unified-heap-utils.h"
#include "test/unittests/heap/heap-utils.h"

namespace v8::internal {

namespace {

class Wrappable final : public cppgc::GarbageCollected<Wrappable> {
 public:
  static size_t destructor_callcount;

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

using UnifiedHeapDetachedTest = TestWithHeapInternals;

}  // namespace

TEST_F(UnifiedHeapTest, OnlyGC) { CollectGarbageWithEmbedderStack(); }

TEST_F(UnifiedHeapTest, FindingV8ToCppReference) {
  auto* wrappable_object =
      cppgc::MakeGarbageCollected<Wrappable>(allocation_handle());
  v8::Local<v8::Object> api_object = WrapperHelper::CreateWrapper(
      v8_isolate()->GetCurrentContext(), wrappable_object);
  EXPECT_FALSE(api_object.IsEmpty());
  // With direct locals, api_object may be invalid after a stackless GC.
  auto handle_api_object = v8::Utils::OpenIndirectHandle(*api_object);
  Wrappable::destructor_callcount = 0;
  EXPECT_EQ(0u, Wrappable::destructor_callcount);
  CollectGarbageWithoutEmbedderStack(cppgc::Heap::SweepingType::kAtomic);
  EXPECT_EQ(0u, Wrappable::destructor_callcount);
  WrapperHelper::ResetWrappableConnection(
      v8_isolate(), v8::Utils::ToLocal(handle_api_object));
  CollectGarbageWithoutEmbedderStack(cppgc::Heap::SweepingType::kAtomic);
  EXPECT_EQ(1u, Wrappable::destructor_callcount);
}

TEST_F(UnifiedHeapTest, WriteBarrierV8ToCppReference) {
  if (!v8_flags.incremental_marking) return;

  void* wrappable = cppgc::MakeGarbageCollected<Wrappable>(allocation_handle());
  v8::Local<v8::Object> api_object =
      WrapperHelper::CreateWrapper(v8_isolate()->GetCurrentContext(), nullptr);
  EXPECT_FALSE(api_object.IsEmpty());
  // With direct locals, api_object may be invalid after a stackless GC.
  auto handle_api_object = v8::Utils::OpenIndirectHandle(*api_object);
  // Create an additional Global that gets picked up by the incremetnal marker
  // as root.
  Global<v8::Object> global(v8_isolate(), api_object);
  Wrappable::destructor_callcount = 0;
  WrapperHelper::ResetWrappableConnection(v8_isolate(), api_object);
  SimulateIncrementalMarking();
  WrapperHelper::SetWrappableConnection(
      v8_isolate(), v8::Utils::ToLocal(handle_api_object), wrappable);
  CollectGarbageWithoutEmbedderStack(cppgc::Heap::SweepingType::kAtomic);
  EXPECT_EQ(0u, Wrappable::destructor_callcount);
}

#if DEBUG
namespace {
class Unreferenced : public cppgc::GarbageCollected<Unreferenced> {
 public:
  void Trace(cppgc::Visitor*) const {}
};
}  // namespace

TEST_F(UnifiedHeapTest, FreeUnreferencedDuringNoGcScope) {
  auto* unreferenced = cppgc::MakeGarbageCollected<Unreferenced>(
      allocation_handle(),
      cppgc::AdditionalBytes(cppgc::internal::api_constants::kMB));
  // Force safepoint to force flushing of cached allocated/freed sizes in cppgc.
  cpp_heap().stats_collector()->NotifySafePointForTesting();
  {
    cppgc::subtle::NoGarbageCollectionScope no_gc_scope(cpp_heap());
    cppgc::subtle::FreeUnreferencedObject(cpp_heap(), *unreferenced);
    // Force safepoint to make sure allocated size decrease due to freeing
    // unreferenced object is reported to CppHeap. Due to
    // NoGarbageCollectionScope, CppHeap will cache the reported decrease and
    // won't report it further.
    cpp_heap().stats_collector()->NotifySafePointForTesting();
  }
  // Running a GC resets the allocated size counters to the current marked bytes
  // counter.
  CollectGarbageWithoutEmbedderStack(cppgc::Heap::SweepingType::kAtomic);
  // If CppHeap didn't clear it's cached values when the counters were reset,
  // the next safepoint will try to decrease the cached value from the last
  // marked bytes (which is smaller than the cached value) and crash.
  cppgc::MakeGarbageCollected<Unreferenced>(allocation_handle());
  cpp_heap().stats_collector()->NotifySafePointForTesting();
}
#endif  // DEBUG

TEST_F(UnifiedHeapTest, TracedReferenceRetainsFromStack) {
  TracedReference<v8::Object> holder;
  {
    v8::HandleScope inner_handle_scope(v8_isolate());
    auto local = v8::Object::New(v8_isolate());
    EXPECT_TRUE(local->IsObject());
    holder.Reset(v8_isolate(), local);
  }
  CollectGarbageWithEmbedderStack(cppgc::Heap::SweepingType::kAtomic);
  auto local = holder.Get(v8_isolate());
  EXPECT_TRUE(local->IsObject());
}

TEST_F(UnifiedHeapDetachedTest, AllocationBeforeConfigureHeap) {
  auto heap =
      v8::CppHeap::Create(V8::GetCurrentPlatform(), CppHeapCreateParams{{}});
  auto* object =
      cppgc::MakeGarbageCollected<Wrappable>(heap->GetAllocationHandle());
  cppgc::WeakPersistent<Wrappable> weak_holder{object};

  auto& js_heap = *isolate()->heap();
  js_heap.AttachCppHeap(heap.get());
  auto& cpp_heap = *CppHeap::From(isolate()->heap()->cpp_heap());
  {
    InvokeMajorGC();
    cpp_heap.AsBase().sweeper().FinishIfRunning();
    EXPECT_TRUE(weak_holder);
  }
  USE(object);
  {
    EmbedderStackStateScope stack_scope(
        &js_heap, EmbedderStackStateOrigin::kExplicitInvocation,
        StackState::kNoHeapPointers);
    InvokeMajorGC();
    cpp_heap.AsBase().sweeper().FinishIfRunning();
    EXPECT_FALSE(weak_holder);
  }
}

TEST_F(UnifiedHeapDetachedTest, StandAloneCppGC) {
  // Test ensures that stand-alone C++ GC are possible when using CppHeap. This
  // works even in the presence of wrappables using TracedReference as long
  // as the reference is empty.
  auto heap =
      v8::CppHeap::Create(V8::GetCurrentPlatform(), CppHeapCreateParams{{}});
  auto* object =
      cppgc::MakeGarbageCollected<Wrappable>(heap->GetAllocationHandle());
  cppgc::WeakPersistent<Wrappable> weak_holder{object};

  heap->EnableDetachedGarbageCollectionsForTesting();
  {
    heap->CollectGarbageForTesting(
        cppgc::EmbedderStackState::kMayContainHeapPointers);
    EXPECT_TRUE(weak_holder);
  }
  USE(object);
  {
    heap->CollectGarbageForTesting(cppgc::EmbedderStackState::kNoHeapPointers);
    EXPECT_FALSE(weak_holder);
  }
}

TEST_F(UnifiedHeapDetachedTest, StandaloneTestingHeap) {
  // Perform garbage collection through the StandaloneTestingHeap API.
  auto cpp_heap =
      v8::CppHeap::Create(V8::GetCurrentPlatform(), CppHeapCreateParams{{}});
  cpp_heap->EnableDetachedGarbageCollectionsForTesting();
  cppgc::testing::StandaloneTestingHeap heap(cpp_heap->GetHeapHandle());
  heap.StartGarbageCollection();
  heap.PerformMarkingStep(cppgc::EmbedderStackState::kNoHeapPointers);
  heap.FinalizeGarbageCollection(cppgc::EmbedderStackState::kNoHeapPointers);
}

}  // namespace v8::internal

namespace cppgc {

class CustomSpaceForTest : public CustomSpace<CustomSpaceForTest> {
 public:
  static constexpr size_t kSpaceIndex = 0;
};

constexpr size_t CustomSpaceForTest::kSpaceIndex;

}  // namespace cppgc

namespace v8::internal {

namespace {

class StatisticsReceiver final : public CustomSpaceStatisticsReceiver {
 public:
  static size_t num_calls_;

  StatisticsReceiver(cppgc::CustomSpaceIndex space_index, size_t bytes)
      : expected_space_index_(space_index), expected_bytes_(bytes) {}

  void AllocatedBytes(cppgc::CustomSpaceIndex space_index, size_t bytes) final {
    EXPECT_EQ(expected_space_index_.value, space_index.value);
    EXPECT_EQ(expected_bytes_, bytes);
    ++num_calls_;
  }

 private:
  const cppgc::CustomSpaceIndex expected_space_index_;
  const size_t expected_bytes_;
};

size_t StatisticsReceiver::num_calls_ = 0u;

class GCed final : public cppgc::GarbageCollected<GCed> {
 public:
  ~GCed() {
    // Force a finalizer to guarantee sweeping can't finish without the main
    // thread.
    USE(data_);
  }
  static size_t GetAllocatedSize() {
    return sizeof(GCed) + sizeof(cppgc::internal::HeapObjectHeader);
  }
  void Trace(cppgc::Visitor*) const {}

 private:
  char data_[KB];
};

}  // namespace
}  // namespace v8::internal

namespace cppgc {
template <>
struct SpaceTrait<v8::internal::GCed> {
  using Space = CustomSpaceForTest;
};

}  // namespace cppgc

namespace v8::internal {

namespace {

class UnifiedHeapWithCustomSpaceTest : public UnifiedHeapTest {
 public:
  static std::vector<std::unique_ptr<cppgc::CustomSpaceBase>>
  GetCustomSpaces() {
    std::vector<std::unique_ptr<cppgc::CustomSpaceBase>> custom_spaces;
    custom_spaces.emplace_back(std::make_unique<cppgc::CustomSpaceForTest>());
    return custom_spaces;
  }
  UnifiedHeapWithCustomSpaceTest() : UnifiedHeapTest(GetCustomSpaces()) {}
};

}  // namespace

TEST_F(UnifiedHeapWithCustomSpaceTest, CollectCustomSpaceStatisticsAtLastGC) {
  StatisticsReceiver::num_calls_ = 0;
  // Initial state.
  cpp_heap().CollectCustomSpaceStatisticsAtLastGC(
      {cppgc::CustomSpaceForTest::kSpaceIndex},
      std::make_unique<StatisticsReceiver>(
          cppgc::CustomSpaceForTest::kSpaceIndex, 0u));
  EXPECT_EQ(1u, StatisticsReceiver::num_calls_);
  // State unpdated only after GC.
  cppgc::Persistent<GCed> live_obj =
      cppgc::MakeGarbageCollected<GCed>(allocation_handle());
  cppgc::MakeGarbageCollected<GCed>(allocation_handle());
  cpp_heap().CollectCustomSpaceStatisticsAtLastGC(
      {cppgc::CustomSpaceForTest::kSpaceIndex},
      std::make_unique<StatisticsReceiver>(
          cppgc::CustomSpaceForTest::kSpaceIndex, 0u));
  EXPECT_EQ(2u, StatisticsReceiver::num_calls_);
  // Check state after GC.
  CollectGarbageWithoutEmbedderStack(cppgc::Heap::SweepingType::kAtomic);
  cpp_heap().CollectCustomSpaceStatisticsAtLastGC(
      {cppgc::CustomSpaceForTest::kSpaceIndex},
      std::make_unique<StatisticsReceiver>(
          cppgc::CustomSpaceForTest::kSpaceIndex, GCed::GetAllocatedSize()));
  EXPECT_EQ(3u, StatisticsReceiver::num_calls_);
  // State callback delayed during sweeping.
  cppgc::Persistent<GCed> another_live_obj =
      cppgc::MakeGarbageCollected<GCed>(allocation_handle());
  while (v8::platform::PumpMessageLoop(
      V8::GetCurrentPlatform(), v8_isolate(),
      v8::platform::MessageLoopBehavior::kDoNotWait)) {
    // Empty the message loop to avoid finalizing garbage collections through
    // unrelated tasks.
  }
  CollectGarbageWithoutEmbedderStack(
      cppgc::Heap::SweepingType::kIncrementalAndConcurrent);
  DCHECK(cpp_heap().sweeper().IsSweepingInProgress());
  cpp_heap().CollectCustomSpaceStatisticsAtLastGC(
      {cppgc::CustomSpaceForTest::kSpaceIndex},
      std::make_unique<StatisticsReceiver>(
          cppgc::CustomSpaceForTest::kSpaceIndex,
          2 * GCed::GetAllocatedSize()));
  while (v8::platform::PumpMessageLoop(
      V8::GetCurrentPlatform(), v8_isolate(),
      v8::platform::MessageLoopBehavior::kWaitForWork)) {
    if (3 < StatisticsReceiver::num_calls_) {
      EXPECT_FALSE(cpp_heap().sweeper().IsSweepingInProgress());
      break;
    }
  }
  EXPECT_EQ(4u, StatisticsReceiver::num_calls_);
}

namespace {

class InConstructionObjectReferringToGlobalHandle final
    : public cppgc::GarbageCollected<
          InConstructionObjectReferringToGlobalHandle> {
 public:
  InConstructionObjectReferringToGlobalHandle(Heap* heap,
                                              v8::Local<v8::Object> wrapper)
      : wrapper_(reinterpret_cast<v8::Isolate*>(heap->isolate()), wrapper) {
    heap->CollectGarbage(OLD_SPACE, GarbageCollectionReason::kTesting);
    heap->CollectGarbage(OLD_SPACE, GarbageCollectionReason::kTesting);
  }

  void Trace(cppgc::Visitor* visitor) const { visitor->Trace(wrapper_); }

  TracedReference<v8::Object>& GetWrapper() { return wrapper_; }

 private:
  TracedReference<v8::Object> wrapper_;
};

}  // namespace

TEST_F(UnifiedHeapTest, InConstructionObjectReferringToGlobalHandle) {
  v8::HandleScope handle_scope(v8_isolate());
  {
    v8::HandleScope inner_handle_scope(v8_isolate());
    auto local = v8::Object::New(v8_isolate());
    auto* cpp_obj = cppgc::MakeGarbageCollected<
        InConstructionObjectReferringToGlobalHandle>(
        allocation_handle(),
        reinterpret_cast<i::Isolate*>(v8_isolate())->heap(), local);
    CHECK_NE(kGlobalHandleZapValue,
             ValueHelper::ValueAsAddress(
                 ValueHelper::HandleAsValue(cpp_obj->GetWrapper())));
  }
}

namespace {

class ResetReferenceInDestructorObject final
    : public cppgc::GarbageCollected<ResetReferenceInDestructorObject> {
 public:
  ResetReferenceInDestructorObject(Heap* heap, v8::Local<v8::Object> wrapper)
      : wrapper_(reinterpret_cast<v8::Isolate*>(heap->isolate()), wrapper) {}
  ~ResetReferenceInDestructorObject() { wrapper_.Reset(); }

  void Trace(cppgc::Visitor* visitor) const { visitor->Trace(wrapper_); }

 private:
  TracedReference<v8::Object> wrapper_;
};

}  // namespace

TEST_F(UnifiedHeapTest, ResetReferenceInDestructor) {
  v8::HandleScope handle_scope(v8_isolate());
  {
    v8::HandleScope inner_handle_scope(v8_isolate());
    auto local = v8::Object::New(v8_isolate());
    cppgc::MakeGarbageCollected<ResetReferenceInDestructorObject>(
        allocation_handle(),
        reinterpret_cast<i::Isolate*>(v8_isolate())->heap(), local);
  }
  CollectGarbageWithoutEmbedderStack(cppgc::Heap::SweepingType::kAtomic);
}

TEST_F(UnifiedHeapTest, OnStackReferencesAreTemporary) {
  ManualGCScope manual_gc(i_isolate());
  v8::Global<v8::Object> observer;
  {
    v8::TracedReference<v8::Value> stack_ref;
    v8::HandleScope scope(v8_isolate());
    v8::Local<v8::Object> api_object = WrapperHelper::CreateWrapper(
        v8_isolate()->GetCurrentContext(), nullptr);
    stack_ref.Reset(v8_isolate(), api_object);
    observer.Reset(v8_isolate(), api_object);
    observer.SetWeak();
  }
  EXPECT_FALSE(observer.IsEmpty());
  {
    // Conservative scanning may find stale pointers to on-stack handles.
    // Disable scanning, assuming the slots are overwritten.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        reinterpret_cast<Isolate*>(v8_isolate())->heap());
    CollectGarbageWithoutEmbedderStack(cppgc::Heap::SweepingType::kAtomic);
  }
  EXPECT_TRUE(observer.IsEmpty());
}

TEST_F(UnifiedHeapTest, TracedReferenceOnStack) {
  ManualGCScope manual_gc(i_isolate());
  v8::Global<v8::Object> observer;
  v8::TracedReference<v8::Value> stack_ref;
  {
    v8::HandleScope scope(v8_isolate());
    v8::Local<v8::Object> object = WrapperHelper::CreateWrapper(
        v8_isolate()->GetCurrentContext(), nullptr);
    stack_ref.Reset(v8_isolate(), object);
    observer.Reset(v8_isolate(), object);
    observer.SetWeak();
  }
  EXPECT_FALSE(observer.IsEmpty());
  InvokeMajorGC();
  EXPECT_FALSE(observer.IsEmpty());
}

namespace {

enum class Operation {
  kCopy,
  kMove,
};

template <typename T>
V8_NOINLINE void PerformOperation(Operation op, T* target, T* source) {
  switch (op) {
    case Operation::kMove:
      *target = std::move(*source);
      break;
    case Operation::kCopy:
      *target = *source;
      source->Reset();
      break;
  }
}

enum class TargetHandling {
  kNonInitialized,
  kInitializedYoungGen,
  kInitializedOldGen
};

class GCedWithHeapRef final : public cppgc::GarbageCollected<GCedWithHeapRef> {
 public:
  v8::TracedReference<v8::Value> heap_handle;

  void Trace(cppgc::Visitor* visitor) const { visitor->Trace(heap_handle); }
};

V8_NOINLINE void StackToHeapTest(v8::Isolate* v8_isolate, Operation op,
                                 TargetHandling target_handling) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  i::ManualGCScope manual_gc_scope(i_isolate);
  v8::Global<v8::Object> observer;
  v8::TracedReference<v8::Value> stack_handle;
  v8::CppHeap* cpp_heap = v8_isolate->GetCppHeap();
  cppgc::Persistent<GCedWithHeapRef> cpp_heap_obj =
      cppgc::MakeGarbageCollected<GCedWithHeapRef>(
          cpp_heap->GetAllocationHandle());
  if (target_handling != TargetHandling::kNonInitialized) {
    v8::HandleScope scope(v8_isolate);
    v8::Local<v8::Object> to_object =
        WrapperHelper::CreateWrapper(v8_isolate->GetCurrentContext(), nullptr);
    EXPECT_TRUE(IsNewObjectInCorrectGeneration(
        *v8::Utils::OpenDirectHandle(*to_object)));
    if (!v8_flags.single_generation &&
        target_handling == TargetHandling::kInitializedOldGen) {
      InvokeMajorGC(i_isolate);
      EXPECT_FALSE(i::HeapLayout::InYoungGeneration(
          *v8::Utils::OpenDirectHandle(*to_object)));
    }
    cpp_heap_obj->heap_handle.Reset(v8_isolate, to_object);
  }
  {
    v8::HandleScope scope(v8_isolate);
    v8::Local<v8::Object> object =
        WrapperHelper::CreateWrapper(v8_isolate->GetCurrentContext(), nullptr);
    stack_handle.Reset(v8_isolate, object);
    observer.Reset(v8_isolate, object);
    observer.SetWeak();
  }
  EXPECT_FALSE(observer.IsEmpty());
  InvokeMajorGC(i_isolate);
  EXPECT_FALSE(observer.IsEmpty());
  PerformOperation(op, &cpp_heap_obj->heap_handle, &stack_handle);
  InvokeMajorGC(i_isolate);
  EXPECT_FALSE(observer.IsEmpty());
  cpp_heap_obj.Clear();
  {
    // Conservative scanning may find stale pointers to on-stack handles.
    // Disable scanning, assuming the slots are overwritten.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        i_isolate->heap());
    InvokeMajorGC(i_isolate);
  }
  ASSERT_TRUE(observer.IsEmpty());
}

V8_NOINLINE void HeapToStackTest(v8::Isolate* v8_isolate, Operation op,
                                 TargetHandling target_handling) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  i::ManualGCScope manual_gc_scope(i_isolate);
  v8::Global<v8::Object> observer;
  v8::TracedReference<v8::Value> stack_handle;
  v8::CppHeap* cpp_heap = v8_isolate->GetCppHeap();
  cppgc::Persistent<GCedWithHeapRef> cpp_heap_obj =
      cppgc::MakeGarbageCollected<GCedWithHeapRef>(
          cpp_heap->GetAllocationHandle());
  if (target_handling != TargetHandling::kNonInitialized) {
    v8::HandleScope scope(v8_isolate);
    v8::Local<v8::Object> to_object =
        WrapperHelper::CreateWrapper(v8_isolate->GetCurrentContext(), nullptr);
    EXPECT_TRUE(IsNewObjectInCorrectGeneration(
        *v8::Utils::OpenDirectHandle(*to_object)));
    if (!v8_flags.single_generation &&
        target_handling == TargetHandling::kInitializedOldGen) {
      InvokeMajorGC(i_isolate);
      EXPECT_FALSE(i::HeapLayout::InYoungGeneration(
          *v8::Utils::OpenDirectHandle(*to_object)));
    }
    stack_handle.Reset(v8_isolate, to_object);
  }
  {
    v8::HandleScope scope(v8_isolate);
    v8::Local<v8::Object> object =
        WrapperHelper::CreateWrapper(v8_isolate->GetCurrentContext(), nullptr);
    cpp_heap_obj->heap_handle.Reset(v8_isolate, object);
    observer.Reset(v8_isolate, object);
    observer.SetWeak();
  }
  EXPECT_FALSE(observer.IsEmpty());
  InvokeMajorGC(i_isolate);
  EXPECT_FALSE(observer.IsEmpty());
  PerformOperation(op, &stack_handle, &cpp_heap_obj->heap_handle);
  InvokeMajorGC(i_isolate);
  EXPECT_FALSE(observer.IsEmpty());
  stack_handle.Reset();
  {
    // Conservative scanning may find stale pointers to on-stack handles.
    // Disable scanning, assuming the slots are overwritten.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        i_isolate->heap());
    InvokeMajorGC(i_isolate);
  }
  EXPECT_TRUE(observer.IsEmpty());
}

V8_NOINLINE void StackToStackTest(v8::Isolate* v8_isolate, Operation op,
                                  TargetHandling target_handling) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  i::ManualGCScope manual_gc_scope(i_isolate);
  v8::Global<v8::Object> observer;
  v8::TracedReference<v8::Value> stack_handle1;
  v8::TracedReference<v8::Value> stack_handle2;
  if (target_handling != TargetHandling::kNonInitialized) {
    v8::HandleScope scope(v8_isolate);
    v8::Local<v8::Object> to_object =
        WrapperHelper::CreateWrapper(v8_isolate->GetCurrentContext(), nullptr);
    EXPECT_TRUE(IsNewObjectInCorrectGeneration(
        *v8::Utils::OpenDirectHandle(*to_object)));
    if (!v8_flags.single_generation &&
        target_handling == TargetHandling::kInitializedOldGen) {
      InvokeMajorGC(i_isolate);
      EXPECT_FALSE(i::HeapLayout::InYoungGeneration(
          *v8::Utils::OpenDirectHandle(*to_object)));
    }
    stack_handle2.Reset(v8_isolate, to_object);
  }
  {
    v8::HandleScope scope(v8_isolate);
    v8::Local<v8::Object> object =
        WrapperHelper::CreateWrapper(v8_isolate->GetCurrentContext(), nullptr);
    stack_handle1.Reset(v8_isolate, object);
    observer.Reset(v8_isolate, object);
    observer.SetWeak();
  }
  EXPECT_FALSE(observer.IsEmpty());
  InvokeMajorGC(i_isolate);
  EXPECT_FALSE(observer.IsEmpty());
  PerformOperation(op, &stack_handle2, &stack_handle1);
  InvokeMajorGC(i_isolate);
  EXPECT_FALSE(observer.IsEmpty());
  stack_handle2.Reset();
  {
    // Conservative scanning may find stale pointers to on-stack handles.
    // Disable scanning, assuming the slots are overwritten.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        i_isolate->heap());
    InvokeMajorGC(i_isolate);
  }
  EXPECT_TRUE(observer.IsEmpty());
}

}  // namespace

TEST_F(UnifiedHeapTest, TracedReferenceMove) {
  ManualGCScope manual_gc(i_isolate());
  StackToHeapTest(v8_isolate(), Operation::kMove,
                  TargetHandling::kNonInitialized);
  StackToHeapTest(v8_isolate(), Operation::kMove,
                  TargetHandling::kInitializedYoungGen);
  StackToHeapTest(v8_isolate(), Operation::kMove,
                  TargetHandling::kInitializedOldGen);
  HeapToStackTest(v8_isolate(), Operation::kMove,
                  TargetHandling::kNonInitialized);
  HeapToStackTest(v8_isolate(), Operation::kMove,
                  TargetHandling::kInitializedYoungGen);
  HeapToStackTest(v8_isolate(), Operation::kMove,
                  TargetHandling::kInitializedOldGen);
  StackToStackTest(v8_isolate(), Operation::kMove,
                   TargetHandling::kNonInitialized);
  StackToStackTest(v8_isolate(), Operation::kMove,
                   TargetHandling::kInitializedYoungGen);
  StackToStackTest(v8_isolate(), Operation::kMove,
                   TargetHandling::kInitializedOldGen);
}

TEST_F(UnifiedHeapTest, TracedReferenceCopy) {
  ManualGCScope manual_gc(i_isolate());
  StackToHeapTest(v8_isolate(), Operation::kCopy,
                  TargetHandling::kNonInitialized);
  StackToHeapTest(v8_isolate(), Operation::kCopy,
                  TargetHandling::kInitializedYoungGen);
  StackToHeapTest(v8_isolate(), Operation::kCopy,
                  TargetHandling::kInitializedOldGen);
  HeapToStackTest(v8_isolate(), Operation::kCopy,
                  TargetHandling::kNonInitialized);
  HeapToStackTest(v8_isolate(), Operation::kCopy,
                  TargetHandling::kInitializedYoungGen);
  HeapToStackTest(v8_isolate(), Operation::kCopy,
                  TargetHandling::kInitializedOldGen);
  StackToStackTest(v8_isolate(), Operation::kCopy,
                   TargetHandling::kNonInitialized);
  StackToStackTest(v8_isolate(), Operation::kCopy,
                   TargetHandling::kInitializedYoungGen);
  StackToStackTest(v8_isolate(), Operation::kCopy,
                   TargetHandling::kInitializedOldGen);
}

TEST_F(UnifiedHeapTest, TracingInEphemerons) {
  // Tests that wrappers that are part of ephemerons are traced.
  ManualGCScope manual_gc(i_isolate());

  Wrappable::destructor_callcount = 0;

  v8::Local<v8::Object> key =
      v8::Local<v8::Object>::New(v8_isolate(), v8::Object::New(v8_isolate()));
  DirectHandle<JSWeakMap> weak_map = i_isolate()->factory()->NewJSWeakMap();
  {
    v8::HandleScope inner_scope(v8_isolate());
    // C++ object that should be traced through ephemeron value.
    auto* wrappable_object =
        cppgc::MakeGarbageCollected<Wrappable>(allocation_handle());
    v8::Local<v8::Object> value = WrapperHelper::CreateWrapper(
        v8_isolate()->GetCurrentContext(), wrappable_object);
    EXPECT_FALSE(value.IsEmpty());
    Handle<JSObject> js_key =
        handle(Cast<JSObject>(*v8::Utils::OpenDirectHandle(*key)), i_isolate());
    DirectHandle<JSReceiver> js_value = v8::Utils::OpenDirectHandle(*value);
    int32_t hash = Object::GetOrCreateHash(*js_key, i_isolate()).value();
    JSWeakCollection::Set(weak_map, js_key, js_value, hash);
  }
  CollectGarbageWithoutEmbedderStack(cppgc::Heap::SweepingType::kAtomic);
  EXPECT_EQ(Wrappable::destructor_callcount, 0u);
}

TEST_F(UnifiedHeapTest, TracedReferenceHandlesDoNotLeak) {
  // TracedReference handles are not cleared by the destructor of the embedder
  // object. To avoid leaks we need to mark these handles during GC.
  // This test checks that unmarked handles do not leak.
  ManualGCScope manual_gc(i_isolate());
  v8::TracedReference<v8::Value> ref;
  ref.Reset(v8_isolate(), v8::Undefined(v8_isolate()));
  auto* traced_handles = i_isolate()->traced_handles();
  const size_t initial_count = traced_handles->used_node_count();
  CollectGarbageWithoutEmbedderStack(cppgc::Heap::SweepingType::kAtomic);
  CollectGarbageWithoutEmbedderStack(cppgc::Heap::SweepingType::kAtomic);
  const size_t final_count = traced_handles->used_node_count();
  EXPECT_EQ(initial_count, final_count + 1);
}

namespace {
class Wrappable2 final : public cppgc::GarbageCollected<Wrappable2> {
 public:
  static size_t destructor_call_count;
  void Trace(cppgc::Visitor* visitor) const {}
  ~Wrappable2() { destructor_call_count++; }
};

size_t Wrappable2::destructor_call_count = 0;
}  // namespace

namespace {
class WrappedData final : public cppgc::GarbageCollected<WrappedData> {
 public:
  WrappedData(v8::Isolate* isolate, v8::Local<v8::Private> data) {
    data_.Reset(isolate, data);
  }

  void Trace(cppgc::Visitor* visitor) const { visitor->Trace(data_); }

  v8::Local<v8::Private> data(v8::Isolate* isolate) {
    return data_.Get(isolate);
  }

 private:
  TracedReference<v8::Private> data_;
};
}  // namespace

TEST_F(UnifiedHeapTest, WrapperWithTracedReferenceData) {
  v8::Isolate* isolate = v8_isolate();

  cppgc::Persistent<WrappedData> live_wrap;
  {
    live_wrap = cppgc::MakeGarbageCollected<WrappedData>(
        allocation_handle(), isolate,
        v8::Private::New(isolate,
                         v8::String::NewFromUtf8Literal(isolate, "test")));
  }
  CollectGarbageWithoutEmbedderStack(cppgc::Heap::SweepingType::kAtomic);
  {
    v8::Local<v8::Value> name = live_wrap.Get()->data(isolate)->Name();
    CHECK(name->IsString());
    CHECK(name.As<v8::String>()->StringEquals(
        v8::String::NewFromUtf8Literal(isolate, "test")));
  }
}

TEST_F(UnifiedHeapTest, CppgcSweepingDuringMinorV8Sweeping) {
  if (!v8_flags.minor_ms) return;
  if (v8_flags.single_generation) return;
  // Heap verification finalizes sweeping in the atomic pause.
  if (v8_flags.verify_heap) return;
  bool single_threaded_gc_flag = v8_flags.single_threaded_gc;
  // Single threaded gc force non-concurrent sweeping in cppgc, which makes
  // CppHeap bail out of `FinishSweepingIfOutOfWork`.
  v8_flags.single_threaded_gc = true;
  ManualGCScope manual_gc(isolate());
  Heap* heap = isolate()->heap();
  CppHeap* cppheap = CppHeap::From(heap->cpp_heap());
  cppheap->UpdateGCCapabilitiesFromFlagsForTesting();
  CHECK_NOT_NULL(heap->cpp_heap());
  heap->CollectGarbage(AllocationSpace::OLD_SPACE,
                       GarbageCollectionReason::kTesting,
                       GCCallbackFlags::kNoGCCallbackFlags);
  CHECK(heap->sweeping_in_progress());
  CHECK(cppheap->sweeper().IsSweepingInProgress());
  heap->EnsureSweepingCompleted(Heap::SweepingForcedFinalizationMode::kV8Only);
  CHECK(!heap->sweeping_in_progress());
  CHECK(cppheap->sweeper().IsSweepingInProgress());
  heap->CollectGarbage(AllocationSpace::NEW_SPACE,
                       GarbageCollectionReason::kTesting,
                       GCCallbackFlags::kNoGCCallbackFlags);
  CHECK(!heap->major_sweeping_in_progress());
  CHECK(heap->minor_sweeping_in_progress());
  CHECK(cppheap->sweeper().IsSweepingInProgress());
  cppheap->sweeper().FinishIfRunning();
  CHECK(!heap->major_sweeping_in_progress());
  CHECK(heap->minor_sweeping_in_progress());
  CHECK(!cppheap->sweeper().IsSweepingInProgress());
  heap->EnsureSweepingCompleted(
      Heap::SweepingForcedFinalizationMode::kUnifiedHeap);
  v8_flags.single_threaded_gc = single_threaded_gc_flag;
}

#ifdef V8_ENABLE_ALLOCATION_TIMEOUT
struct RandomGCIntervalTestSetter {
  RandomGCIntervalTestSetter() {
    static constexpr int kInterval = 87;
    v8_flags.cppgc_random_gc_interval = kInterval;
  }
  ~RandomGCIntervalTestSetter() { v8_flags.cppgc_random_gc_interval = 0; }
};

struct UnifiedHeapTestWithRandomGCInterval : RandomGCIntervalTestSetter,
                                             UnifiedHeapTest {};

TEST_F(UnifiedHeapTestWithRandomGCInterval, AllocationTimeout) {
  if (v8_flags.stress_incremental_marking) return;
  if (v8_flags.stress_concurrent_allocation) return;
  auto& cpp_heap = *CppHeap::From(isolate()->heap()->cpp_heap());
  auto& allocator = cpp_heap.object_allocator();
  const int initial_allocation_timeout =
      allocator.get_allocation_timeout_for_testing();
  ASSERT_GT(initial_allocation_timeout, 0);
  const auto current_epoch = isolate()->heap()->tracer()->CurrentEpoch(
      GCTracer::Scope::MARK_COMPACTOR);
  for (int i = 0; i < initial_allocation_timeout - 1; ++i) {
    MakeGarbageCollected<Wrappable>(allocation_handle());
  }
  // Expect no GC happened so far.
  EXPECT_EQ(current_epoch, isolate()->heap()->tracer()->CurrentEpoch(
                               GCTracer::Scope::MARK_COMPACTOR));
  // This allocation must cause a GC.
  MakeGarbageCollected<Wrappable>(allocation_handle());
  EXPECT_EQ(current_epoch + 1, isolate()->heap()->tracer()->CurrentEpoch(
                                   GCTracer::Scope::MARK_COMPACTOR));
}
#endif  // V8_ENABLE_ALLOCATION_TIMEOUT

namespace {
using UnifiedHeapMinimalTest = WithIsolateMixin<  //
    WithDefaultPlatformMixin<                     //
        ::testing::Test>>;

class ThreadUsingV8Locker final : public v8::base::Thread {
 public:
  ThreadUsingV8Locker(v8::Isolate* isolate, CppHeap* heap,
                      cppgc::Persistent<Wrappable>& holder)
      : v8::base::Thread(Options("Thread using V8::Locker.")),
        isolate_(isolate),
        heap_(heap),
        holder_(holder) {}

  void Run() final {
    v8::Locker locker(isolate_);
    v8::Isolate::Scope isolate_scope(isolate_);
    // This should not trigger a DCHECK (when allocating a persistent).
    cppgc::Persistent<Wrappable> obj =
        cppgc::MakeGarbageCollected<Wrappable>(heap_->object_allocator());
    // This should not trigger a DCHECK (when invoking prefinalizers).
    InvokeMajorGC(heap_->isolate());
    // This should not trigger a DCHECK (upon assignment, due to pointer
    // policies).
    holder_ = obj;
  }

 private:
  v8::Isolate* isolate_;
  CppHeap* heap_;
  cppgc::Persistent<Wrappable>& holder_;
};
}  // anonymous namespace

TEST_F(UnifiedHeapMinimalTest, UsingV8Locker) {
  auto heap =
      CppHeap::Create(V8::GetCurrentPlatform(), CppHeapCreateParams{{}});
  Isolate* isolate = reinterpret_cast<Isolate*>(v8_isolate());
  isolate->heap()->AttachCppHeap(heap.get());
  auto* cpp_heap = CppHeap::From(isolate->heap()->cpp_heap());

  // The use of v8::Locker in this test should suppress DCHECKs and CHECKS
  // that enforce that the current thread is the creation thread of the heap
  // or of a persistent.
  cppgc::Persistent<Wrappable> obj;
  {
    v8::Locker locker(v8_isolate());
    v8::Isolate::Scope isolate_scope(v8_isolate());
    obj = cppgc::MakeGarbageCollecte
```