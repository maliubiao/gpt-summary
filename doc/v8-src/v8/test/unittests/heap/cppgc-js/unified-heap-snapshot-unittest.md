Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript example.

1. **Understand the Goal:** The core request is to understand the functionality of the C++ code and illustrate its connection to JavaScript, if any. The specific file path (`v8/test/unittests/heap/cppgc-js/unified-heap-snapshot-unittest.cc`) strongly suggests that the code is related to memory management (heap) and how C++ objects interact with JavaScript within the V8 engine. The "snapshot" part hints at inspecting the state of the heap.

2. **Initial Skim and Keyword Spotting:** Quickly read through the code, looking for familiar terms and patterns. Keywords like `cppgc`, `v8`, `HeapSnapshot`, `Persistent`, `GarbageCollected`, `NameProvider`, `TracedReference`, `Isolate`, `Context`, `Object`, `Wrapper`, and `Detachedness` jump out. These words point towards:
    * **`cppgc`:**  Likely the C++ garbage collector within V8.
    * **`v8`:**  The JavaScript engine itself.
    * **`HeapSnapshot`:**  A mechanism to capture the state of the memory heap.
    * **`Persistent`, `GarbageCollected`:**  Concepts from garbage collection – objects that persist or are subject to collection.
    * **`NameProvider`:**  A way to give names to C++ objects for debugging or profiling.
    * **`TracedReference`:**  A way for C++ objects to hold references to JavaScript objects.
    * **`Isolate`, `Context`, `Object`:**  Core V8 JavaScript concepts.
    * **`Wrapper`:**  Likely a bridge between C++ and JavaScript objects.
    * **`Detachedness`:** A concept related to whether a JavaScript wrapper for a C++ object is still considered "live" or has been detached.

3. **Identify Key Structures and Classes:** Pay attention to the class definitions and how they are used. Notice classes like `UnifiedHeapSnapshotTest`, `CompactableGCed`, `GCed`, `GCedWithJSRef`, and `WrappedContext`. The inheritance relationships and member variables provide clues about their purpose.

4. **Focus on the `TEST_F` blocks:**  These are the unit tests. Each test focuses on a specific aspect of the heap snapshot functionality. Analyzing the names of the tests reveals the different scenarios being tested:
    * `EmptySnapshot`: Basic functionality.
    * `RetainedByCppRoot`, `RetainedByCppCrossThreadRoot`, `RetainedByStackRoots`: How C++ roots keep objects alive and how they appear in snapshots.
    * `ConsistentId`, `ConsistentIdAfterCompaction`:  Stability of object IDs across snapshots and after memory compaction.
    * Tests involving `BaseWithoutName`: How objects without explicit names are handled.
    * Tests involving `GCedWithJSRef`: The interaction between C++ and JavaScript objects in snapshots, including merging and detachedness.
    * `WrappedContext`: More complex scenarios involving cycles and embedder data.
    * `DynamicName`:  Dynamically generating names for objects in snapshots.

5. **Understand the Flow of a Typical Test:**  Most tests follow a pattern:
    * Create C++ objects (potentially linked together).
    * Optionally, create JavaScript wrappers for C++ objects.
    * Take a heap snapshot using `TakeHeapSnapshot()`.
    * Use assertions (e.g., `EXPECT_TRUE`, `EXPECT_EQ`) and helper functions (`IsValidSnapshot`, `ContainsRetainingPath`, `GetIds`) to verify the contents and structure of the snapshot.

6. **Infer the Purpose of Helper Functions:** Functions like `IsValidSnapshot`, `GetIds`, and `ContainsRetainingPath` are crucial for validating the correctness of the heap snapshot. `ContainsRetainingPath` is particularly important for understanding how object retention is represented in the snapshot.

7. **Connect C++ Concepts to JavaScript:**  The tests involving `GCedWithJSRef` and `WrappedContext` clearly demonstrate the interaction between C++ and JavaScript. The concept of "wrappers" is central here. The `TracedReference<v8::Object>` in `GCedWithJSRef` shows how a C++ object can hold a reference to a JavaScript object. The tests involving `Detachedness` highlight how the liveness of these wrappers is tracked.

8. **Formulate the Summary:** Based on the analysis, summarize the key functionalities: taking heap snapshots, representing C++ and JavaScript objects and their relationships, handling different types of roots, merging C++ and JavaScript nodes, and tracking detachedness.

9. **Create the JavaScript Example:**  Think about how the concepts demonstrated in the C++ code would manifest in JavaScript. The key is to illustrate the creation of a C++ object, its wrapping in a JavaScript object, and how a heap snapshot can reveal this relationship and the concept of detachedness. The example should be simple enough to understand but demonstrate the core interaction. The example uses the profiler API to take a snapshot and then inspect the nodes to confirm the C++ object's presence and its relationship to the JavaScript wrapper.

10. **Refine and Organize:**  Review the summary and example for clarity and accuracy. Ensure the JavaScript code is syntactically correct and the explanation is easy to follow. Organize the information logically.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This is just about C++ memory management."  **Correction:**  Realized the "cppgc-js" part is crucial and the tests heavily involve JavaScript interop.
* **Confusion about `NameProvider`:**  Initially unsure of its exact purpose. **Clarification:**  Figured out it's for providing names in the heap snapshot, especially for debugging.
* **Difficulty understanding `Detachedness`:**  Needed to examine the tests carefully to see how it's used to track the liveness of wrappers.
* **Choosing the right JavaScript example:** Initially considered a more complex example. **Simplification:** Decided a simpler example focusing on the core wrapper concept would be more effective.

By following these steps, including the iterative process of analyzing, inferring, connecting, and refining, a comprehensive understanding of the C++ code and its relation to JavaScript can be achieved.
这个C++源代码文件 `unified-heap-snapshot-unittest.cc` 的主要功能是**测试 V8 引擎中统一堆（Unified Heap）的堆快照（Heap Snapshot）功能**。  更具体地说，它验证了在统一堆的上下文中，堆快照能否正确地捕获 C++ 对象以及它们与 JavaScript 对象的关联关系。

以下是其功能的详细归纳：

1. **创建和验证堆快照:** 代码定义了一系列测试用例 (`TEST_F`)，用于创建不同场景下的堆快照，并使用 `IsValidSnapshot` 函数来验证快照的基本有效性。

2. **测试 C++ 对象的保留路径:**  测试了 C++ 对象如何通过不同的方式被保留，例如：
    * **C++ 持久根 (Persistent Roots):**  `RetainedByCppRoot` 测试用例验证了通过 `cppgc::Persistent` 持有的 C++ 对象能在堆快照中被找到，并且其保留路径是从 "C++ Persistent roots" 开始。
    * **C++ 跨线程持久根 (CrossThreadPersistent Roots):** `RetainedByCppCrossThreadRoot` 测试用例验证了通过 `cppgc::subtle::CrossThreadPersistent` 持有的 C++ 对象也能在快照中找到。
    * **C++ 本地栈根 (Stack Roots):** `RetainedByStackRoots` 测试用例验证了当前 C++ 栈上的变量引用的 C++ 对象也能在快照中被检测到。

3. **测试 C++ 对象的 ID 一致性:** `ConsistentId` 和 `ConsistentIdAfterCompaction` 测试用例验证了在多次快照之间，即使在发生垃圾回收和堆压缩后，同一个 C++ 对象的 ID 在快照中仍然保持一致。这对于分析内存泄漏和性能问题非常重要。

4. **处理未命名类型:**  `RetainingUnnamedTypeWithInternalDetails` 和 `RetainingUnnamedTypeWithoutInternalDetails` 测试用例测试了如何处理没有明确名称的 C++ 对象在堆快照中的表示。根据快照模式的不同，这些对象可能显示内部名称或隐藏名称。

5. **测试 C++ 对象之间的引用关系:**  测试了 C++ 对象之间的互相引用以及通过中间未命名对象的引用链如何在堆快照中体现。

6. **测试 C++ 对象与 JavaScript 对象的交互:**  这是这个文件最核心的功能之一，测试了以下场景：
    * **JavaScript 引用强制 C++ 对象可见:** `JSReferenceForcesVisibleObject` 测试用例验证了当一个 C++ 对象被 JavaScript 对象引用时，即使在非内部细节模式下，该 C++ 对象也会在堆快照中显示。
    * **合并 C++ 和 JavaScript 节点:** `TestMergedWrapperNode` 系列测试用例验证了当 C++ 对象有一个对应的 JavaScript 包装器（Wrapper）时，堆快照可以将这两个节点合并，以便更好地理解对象之间的关系。
    * **跟踪分离状态 (Detachedness):**  `DetachedObjectsRetainedByJSReference`、`NoTriggerForStandAloneTracedReference`、`TriggerDetachednessCallbackSettingAttached` 和 `TriggerDetachednessCallbackSettingDetached` 等测试用例验证了如何跟踪 C++ 对象对应的 JavaScript 包装器是否已被分离（Detached），这对于理解对象生命周期至关重要。V8 提供了回调函数 `GetDetachednessCallback` 来获取对象的 detachedness 状态。

7. **测试上下文包装器 (Context Wrapper):** `WrappedContext` 测试用例测试了涉及 `v8::Context` 的复杂引用关系，以及如何通过堆快照来理解这种循环引用和 detachedness。

8. **测试动态名称:** `DynamicName` 测试用例验证了在生成堆快照时，可以为 C++ 对象提供动态生成的名称，这可以提供更具描述性的快照信息。

**与 JavaScript 的关系和示例:**

这个测试文件主要关注的是 V8 引擎内部 C++ 代码的功能，特别是与垃圾回收和堆快照相关的部分。然而，它与 JavaScript 的关系非常紧密，因为统一堆的目标就是为了更好地集成 C++ 和 JavaScript 的对象管理。

当 C++ 代码中创建了一个可以被 JavaScript 访问的对象时，通常会创建一个 JavaScript 包装器（Wrapper）对象来代表这个 C++ 对象。堆快照的目标之一就是清晰地展示这种关系。

**JavaScript 示例:**

假设在 C++ 代码中定义了一个类 `MyCppObject`，并且可以通过某种方式在 JavaScript 中访问它。例如，通过 V8 的 Native Extensions API 或者通过 WebAssembly。

```javascript
// 假设我们有一个通过 Native Extension 暴露的 C++ 对象
const myCppObject = new NativeExtension.MyCppObject();

// 创建一个 JavaScript 对象，并引用这个 C++ 对象
const jsObject = {
  cppReference: myCppObject,
  data: "some data"
};

// 获取堆快照 (使用 Chrome DevTools 或 V8 Profiler API)
// 在 Chrome DevTools 中，你可以打开 "Memory" 面板，然后点击 "Take heap snapshot"。
// 或者，你可以使用 V8 的 Profiler API (在 Node.js 中)：
const v8 = require('v8');
v8.getHeapSnapshot(); // 这会返回一个可以写入文件的流

// 在堆快照中，你可能会看到类似这样的节点关系：
// - "C++ Persistent roots"
//   - "NativeExtension::MyCppObject"  // 代表 C++ 对象
//     - "jsObject"                    // 代表 JavaScript 对象
//       - "cppReference" (property) -> "NativeExtension::MyCppObject"
//       - "data" (property) -> "some data" (string)

// 如果 C++ 对象对应的 JavaScript 包装器被分离：
myCppObject.detach(); // 假设 C++ 代码提供了 detach 方法

// 再次获取堆快照，你可能会看到 "NativeExtension::MyCppObject" 的 detachedness 状态被标记为 true。
```

**解释:**

* 在 JavaScript 中创建的 `jsObject` 持有一个名为 `cppReference` 的属性，它指向 C++ 对象 `myCppObject`。
* 当我们获取堆快照时，快照会记录下这种引用关系。在 "C++ Persistent roots" 下，我们能找到 `MyCppObject` 的实例。
* `jsObject` 也会作为一个节点出现在快照中，并且它的 `cppReference` 属性会指向对应的 `MyCppObject` 节点。
* 如果 C++ 对象被“分离”（意味着 JavaScript 包装器不再有效或被断开连接），堆快照能够记录下这种状态，这有助于调试内存泄漏和理解对象生命周期。

总而言之，`unified-heap-snapshot-unittest.cc` 这个 C++ 文件是 V8 引擎中用于测试堆快照功能的单元测试，它特别关注统一堆场景下 C++ 和 JavaScript 对象的交互和关系在堆快照中的正确表示。 理解这些测试用例可以帮助开发者更好地理解 V8 引擎的内存管理机制，以及如何使用堆快照来分析 JavaScript 和 C++ 代码的内存使用情况。

Prompt: 
```
这是目录为v8/test/unittests/heap/cppgc-js/unified-heap-snapshot-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstring>

#include "include/cppgc/allocation.h"
#include "include/cppgc/common.h"
#include "include/cppgc/cross-thread-persistent.h"
#include "include/cppgc/custom-space.h"
#include "include/cppgc/garbage-collected.h"
#include "include/cppgc/name-provider.h"
#include "include/cppgc/persistent.h"
#include "include/v8-cppgc.h"
#include "include/v8-profiler.h"
#include "src/api/api-inl.h"
#include "src/heap/cppgc-js/cpp-heap.h"
#include "src/heap/cppgc/heap-object-header.h"
#include "src/heap/cppgc/object-allocator.h"
#include "src/objects/heap-object.h"
#include "src/objects/objects-inl.h"
#include "src/profiler/heap-snapshot-generator-inl.h"
#include "src/profiler/heap-snapshot-generator.h"
#include "test/unittests/heap/cppgc-js/unified-heap-utils.h"
#include "test/unittests/heap/heap-utils.h"

namespace cppgc {

class CompactableCustomSpace : public CustomSpace<CompactableCustomSpace> {
 public:
  static constexpr size_t kSpaceIndex = 0;
  static constexpr bool kSupportsCompaction = true;
};

}  // namespace cppgc

namespace v8::internal {

struct CompactableGCed : public cppgc::GarbageCollected<CompactableGCed>,
                         public cppgc::NameProvider {
 public:
  static constexpr const char kExpectedName[] = "CompactableGCed";
  void Trace(cppgc::Visitor* v) const {}
  const char* GetHumanReadableName() const final { return "CompactableGCed"; }
  size_t data = 0;
};

struct CompactableHolder : public cppgc::GarbageCollected<CompactableHolder> {
 public:
  explicit CompactableHolder(cppgc::AllocationHandle& allocation_handle) {
    object = cppgc::MakeGarbageCollected<CompactableGCed>(allocation_handle);
  }

  void Trace(cppgc::Visitor* visitor) const {
    cppgc::internal::VisitorBase::TraceRawForTesting(
        visitor, const_cast<const CompactableGCed*>(object));
    visitor->RegisterMovableReference(
        const_cast<const CompactableGCed**>(&object));
  }
  CompactableGCed* object = nullptr;
};

}  // namespace v8::internal

namespace cppgc {
template <>
struct SpaceTrait<v8::internal::CompactableGCed> {
  using Space = CompactableCustomSpace;
};
}  // namespace cppgc

namespace v8 {
namespace internal {

namespace {

class UnifiedHeapSnapshotTest : public UnifiedHeapTest {
 public:
  UnifiedHeapSnapshotTest() = default;
  explicit UnifiedHeapSnapshotTest(
      std::vector<std::unique_ptr<cppgc::CustomSpaceBase>> custom_spaces)
      : UnifiedHeapTest(std::move(custom_spaces)) {}
  const v8::HeapSnapshot* TakeHeapSnapshot(
      cppgc::EmbedderStackState stack_state =
          cppgc::EmbedderStackState::kMayContainHeapPointers,
      v8::HeapProfiler::HeapSnapshotMode snapshot_mode =
          v8::HeapProfiler::HeapSnapshotMode::kExposeInternals) {
    v8::HeapProfiler* heap_profiler = v8_isolate()->GetHeapProfiler();

    v8::HeapProfiler::HeapSnapshotOptions options;
    options.control = nullptr;
    options.global_object_name_resolver = nullptr;
    options.snapshot_mode = snapshot_mode;
    options.numerics_mode = v8::HeapProfiler::NumericsMode::kHideNumericValues;
    options.stack_state = stack_state;
    return heap_profiler->TakeHeapSnapshot(options);
  }

 protected:
  void TestMergedWrapperNode(v8::HeapProfiler::HeapSnapshotMode snapshot_mode);
};

bool IsValidSnapshot(const v8::HeapSnapshot* snapshot, int depth = 3) {
  const HeapSnapshot* heap_snapshot =
      reinterpret_cast<const HeapSnapshot*>(snapshot);
  std::unordered_set<const HeapEntry*> visited;
  for (const HeapGraphEdge& edge : heap_snapshot->edges()) {
    visited.insert(edge.to());
  }
  size_t unretained_entries_count = 0;
  for (const HeapEntry& entry : heap_snapshot->entries()) {
    if (visited.find(&entry) == visited.end() && entry.id() != 1) {
      entry.Print("entry with no retainer", "", depth, 0);
      ++unretained_entries_count;
    }
  }
  return unretained_entries_count == 0;
}

// Returns the IDs of all entries in the snapshot with the given name.
std::vector<SnapshotObjectId> GetIds(const v8::HeapSnapshot& snapshot,
                                     std::string name) {
  const HeapSnapshot& heap_snapshot =
      reinterpret_cast<const HeapSnapshot&>(snapshot);
  std::vector<SnapshotObjectId> result;
  for (const HeapEntry& entry : heap_snapshot.entries()) {
    if (entry.name() == name) {
      result.push_back(entry.id());
    }
  }
  return result;
}

bool ContainsRetainingPath(const v8::HeapSnapshot& snapshot,
                           const std::vector<std::string> retaining_path,
                           bool debug_retaining_path = false) {
  const HeapSnapshot& heap_snapshot =
      reinterpret_cast<const HeapSnapshot&>(snapshot);
  std::vector<HeapEntry*> haystack = {heap_snapshot.root()};
  for (size_t i = 0; i < retaining_path.size(); ++i) {
    const std::string& needle = retaining_path[i];
    std::vector<HeapEntry*> new_haystack;
    for (HeapEntry* parent : haystack) {
      for (int j = 0; j < parent->children_count(); j++) {
        HeapEntry* child = parent->child(j)->to();
        if (0 == strcmp(child->name(), needle.c_str())) {
          new_haystack.push_back(child);
        }
      }
    }
    if (new_haystack.empty()) {
      if (debug_retaining_path) {
        fprintf(stderr,
                "#\n# Could not find object with name '%s'\n#\n# Path:\n",
                needle.c_str());
        for (size_t j = 0; j < retaining_path.size(); ++j) {
          fprintf(stderr, "# - '%s'%s\n", retaining_path[j].c_str(),
                  i == j ? "\t<--- not found" : "");
        }
        fprintf(stderr, "#\n");
      }
      return false;
    }
    std::swap(haystack, new_haystack);
  }
  return true;
}

class BaseWithoutName : public cppgc::GarbageCollected<BaseWithoutName> {
 public:
  static constexpr const char kExpectedName[] =
      "v8::internal::(anonymous namespace)::BaseWithoutName";

  virtual void Trace(cppgc::Visitor* v) const {
    v->Trace(next);
    v->Trace(next2);
  }
  cppgc::Member<BaseWithoutName> next;
  cppgc::Member<BaseWithoutName> next2;
};
// static
constexpr const char BaseWithoutName::kExpectedName[];

class GCed final : public BaseWithoutName, public cppgc::NameProvider {
 public:
  static constexpr const char kExpectedName[] = "GCed";

  void Trace(cppgc::Visitor* v) const final { BaseWithoutName::Trace(v); }
  const char* GetHumanReadableName() const final { return "GCed"; }
};
// static
constexpr const char GCed::kExpectedName[];

static constexpr const char kExpectedCppRootsName[] = "C++ Persistent roots";
static constexpr const char kExpectedCppCrossThreadRootsName[] =
    "C++ CrossThreadPersistent roots";
static constexpr const char kExpectedCppStackRootsName[] =
    "C++ native stack roots";

template <typename T>
constexpr const char* GetExpectedName() {
  if (std::is_base_of<cppgc::NameProvider, T>::value ||
      cppgc::NameProvider::SupportsCppClassNamesAsObjectNames()) {
    return T::kExpectedName;
  } else {
    return cppgc::NameProvider::kHiddenName;
  }
}

}  // namespace

TEST_F(UnifiedHeapSnapshotTest, EmptySnapshot) {
  const v8::HeapSnapshot* snapshot = TakeHeapSnapshot();
  EXPECT_TRUE(IsValidSnapshot(snapshot));
}

TEST_F(UnifiedHeapSnapshotTest, RetainedByCppRoot) {
  cppgc::Persistent<GCed> gced =
      cppgc::MakeGarbageCollected<GCed>(allocation_handle());
  const v8::HeapSnapshot* snapshot = TakeHeapSnapshot();
  EXPECT_TRUE(IsValidSnapshot(snapshot));
  EXPECT_TRUE(ContainsRetainingPath(
      *snapshot, {kExpectedCppRootsName, GetExpectedName<GCed>()}));
}

TEST_F(UnifiedHeapSnapshotTest, ConsistentId) {
  cppgc::Persistent<GCed> gced =
      cppgc::MakeGarbageCollected<GCed>(allocation_handle());
  const v8::HeapSnapshot* snapshot1 = TakeHeapSnapshot();
  EXPECT_TRUE(IsValidSnapshot(snapshot1));
  const v8::HeapSnapshot* snapshot2 = TakeHeapSnapshot();
  EXPECT_TRUE(IsValidSnapshot(snapshot2));
  std::vector<SnapshotObjectId> ids1 =
      GetIds(*snapshot1, GetExpectedName<GCed>());
  std::vector<SnapshotObjectId> ids2 =
      GetIds(*snapshot2, GetExpectedName<GCed>());
  EXPECT_EQ(ids1.size(), size_t{1});
  EXPECT_EQ(ids2.size(), size_t{1});
  EXPECT_EQ(ids1[0], ids2[0]);
}

class UnifiedHeapWithCustomSpaceSnapshotTest : public UnifiedHeapSnapshotTest {
 public:
  static std::vector<std::unique_ptr<cppgc::CustomSpaceBase>>
  GetCustomSpaces() {
    std::vector<std::unique_ptr<cppgc::CustomSpaceBase>> custom_spaces;
    custom_spaces.emplace_back(
        std::make_unique<cppgc::CompactableCustomSpace>());
    return custom_spaces;
  }
  UnifiedHeapWithCustomSpaceSnapshotTest()
      : UnifiedHeapSnapshotTest(GetCustomSpaces()) {}
};

TEST_F(UnifiedHeapWithCustomSpaceSnapshotTest, ConsistentIdAfterCompaction) {
  // Ensure that only things held by Persistent handles will remain after GC.
  DisableConservativeStackScanningScopeForTesting no_css(isolate()->heap());

  // Allocate an object that will be thrown away by the GC, so that there's
  // somewhere for the compactor to move stuff to.
  cppgc::Persistent<CompactableGCed> trash =
      cppgc::MakeGarbageCollected<CompactableGCed>(allocation_handle());

  // Create the object which we'll actually test.
  cppgc::Persistent<CompactableHolder> gced =
      cppgc::MakeGarbageCollected<CompactableHolder>(allocation_handle(),
                                                     allocation_handle());

  // Release the persistent reference to the other object.
  trash.Release();

  void* original_pointer = gced->object;

  // This first snapshot should not trigger compaction of the cppgc heap because
  // the heap is still very small.
  const v8::HeapSnapshot* snapshot1 =
      TakeHeapSnapshot(cppgc::EmbedderStackState::kNoHeapPointers);
  EXPECT_TRUE(IsValidSnapshot(snapshot1));
  EXPECT_EQ(original_pointer, gced->object);

  // Manually run a GC with compaction. The GCed object should move.
  CppHeap::From(isolate()->heap()->cpp_heap())
      ->compactor()
      .EnableForNextGCForTesting();
  i::InvokeMajorGC(isolate(), i::GCFlag::kReduceMemoryFootprint);
  EXPECT_NE(original_pointer, gced->object);

  // In the second heap snapshot, the moved object should still have the same
  // ID.
  const v8::HeapSnapshot* snapshot2 =
      TakeHeapSnapshot(cppgc::EmbedderStackState::kNoHeapPointers);
  EXPECT_TRUE(IsValidSnapshot(snapshot2));
  std::vector<SnapshotObjectId> ids1 =
      GetIds(*snapshot1, GetExpectedName<CompactableGCed>());
  std::vector<SnapshotObjectId> ids2 =
      GetIds(*snapshot2, GetExpectedName<CompactableGCed>());
  // Depending on build config, GetIds might have returned only the ID for the
  // CompactableGCed instance or it might have also returned the ID for the
  // CompactableHolder.
  EXPECT_TRUE(ids1.size() == 1 || ids1.size() == 2);
  std::sort(ids1.begin(), ids1.end());
  std::sort(ids2.begin(), ids2.end());
  EXPECT_EQ(ids1, ids2);
}

TEST_F(UnifiedHeapSnapshotTest, RetainedByCppCrossThreadRoot) {
  cppgc::subtle::CrossThreadPersistent<GCed> gced =
      cppgc::MakeGarbageCollected<GCed>(allocation_handle());
  const v8::HeapSnapshot* snapshot = TakeHeapSnapshot();
  EXPECT_TRUE(IsValidSnapshot(snapshot));
  EXPECT_TRUE(ContainsRetainingPath(
      *snapshot, {kExpectedCppCrossThreadRootsName, GetExpectedName<GCed>()}));
}

TEST_F(UnifiedHeapSnapshotTest, RetainedByStackRoots) {
  auto* volatile gced = cppgc::MakeGarbageCollected<GCed>(allocation_handle());
  const v8::HeapSnapshot* snapshot =
      TakeHeapSnapshot(cppgc::EmbedderStackState::kMayContainHeapPointers);
  EXPECT_TRUE(IsValidSnapshot(snapshot));
  EXPECT_TRUE(ContainsRetainingPath(
      *snapshot, {kExpectedCppStackRootsName, GetExpectedName<GCed>()}));
  EXPECT_STREQ(gced->GetHumanReadableName(), GetExpectedName<GCed>());
}

TEST_F(UnifiedHeapSnapshotTest, RetainingUnnamedTypeWithInternalDetails) {
  cppgc::Persistent<BaseWithoutName> base_without_name =
      cppgc::MakeGarbageCollected<BaseWithoutName>(allocation_handle());
  const v8::HeapSnapshot* snapshot = TakeHeapSnapshot();
  EXPECT_TRUE(IsValidSnapshot(snapshot));
  EXPECT_TRUE(ContainsRetainingPath(
      *snapshot, {kExpectedCppRootsName, GetExpectedName<BaseWithoutName>()}));
}

TEST_F(UnifiedHeapSnapshotTest, RetainingUnnamedTypeWithoutInternalDetails) {
  cppgc::Persistent<BaseWithoutName> base_without_name =
      cppgc::MakeGarbageCollected<BaseWithoutName>(allocation_handle());
  const v8::HeapSnapshot* snapshot =
      TakeHeapSnapshot(cppgc::EmbedderStackState::kMayContainHeapPointers,
                       v8::HeapProfiler::HeapSnapshotMode::kRegular);
  EXPECT_TRUE(IsValidSnapshot(snapshot));
  EXPECT_FALSE(ContainsRetainingPath(
      *snapshot, {kExpectedCppRootsName, cppgc::NameProvider::kHiddenName}));
  EXPECT_FALSE(ContainsRetainingPath(
      *snapshot, {kExpectedCppRootsName, GetExpectedName<BaseWithoutName>()}));
}

TEST_F(UnifiedHeapSnapshotTest, RetainingNamedThroughUnnamed) {
  cppgc::Persistent<BaseWithoutName> base_without_name =
      cppgc::MakeGarbageCollected<BaseWithoutName>(allocation_handle());
  base_without_name->next =
      cppgc::MakeGarbageCollected<GCed>(allocation_handle());
  const v8::HeapSnapshot* snapshot =
      TakeHeapSnapshot(cppgc::EmbedderStackState::kMayContainHeapPointers,
                       v8::HeapProfiler::HeapSnapshotMode::kRegular);
  EXPECT_TRUE(IsValidSnapshot(snapshot));
  EXPECT_TRUE(ContainsRetainingPath(
      *snapshot, {kExpectedCppRootsName, cppgc::NameProvider::kHiddenName,
                  GetExpectedName<GCed>()}));
}

TEST_F(UnifiedHeapSnapshotTest, PendingCallStack) {
  // Test ensures that the algorithm handles references into the current call
  // stack.
  //
  // Graph:
  //   Persistent -> BaseWithoutName (2) <-> BaseWithoutName (1) -> GCed (3)
  //
  // Visitation order is (1)->(2)->(3) which is a corner case, as when following
  // back from (2)->(1) the object in (1) is already visited and will only later
  // be marked as visible.
  auto* first =
      cppgc::MakeGarbageCollected<BaseWithoutName>(allocation_handle());
  auto* second =
      cppgc::MakeGarbageCollected<BaseWithoutName>(allocation_handle());
  first->next = second;
  first->next->next = first;
  auto* third = cppgc::MakeGarbageCollected<GCed>(allocation_handle());
  first->next2 = third;

  cppgc::Persistent<BaseWithoutName> holder(second);
  const v8::HeapSnapshot* snapshot =
      TakeHeapSnapshot(cppgc::EmbedderStackState::kMayContainHeapPointers,
                       v8::HeapProfiler::HeapSnapshotMode::kRegular);
  EXPECT_TRUE(IsValidSnapshot(snapshot));
  EXPECT_TRUE(ContainsRetainingPath(
      *snapshot, {kExpectedCppRootsName, cppgc::NameProvider::kHiddenName,
                  cppgc::NameProvider::kHiddenName, GetExpectedName<GCed>()}));
}

TEST_F(UnifiedHeapSnapshotTest, ReferenceToFinishedSCC) {
  // Test ensures that the algorithm handles reference into an already finished
  // SCC that is marked as hidden whereas the current SCC would resolve to
  // visible.
  //
  // Graph:
  //   Persistent -> BaseWithoutName (1)
  //   Persistent -> BaseWithoutName (2)
  //                        + <-> BaseWithoutName (3) -> BaseWithoutName (1)
  //                        + -> GCed (4)
  //
  // Visitation order (1)->(2)->(3)->(1) which is a corner case as (3) would set
  // a dependency on (1) which is hidden. Instead (3) should set a dependency on
  // (2) as (1) resolves to hidden whereas (2) resolves to visible. The test
  // ensures that resolved hidden dependencies are ignored.
  cppgc::Persistent<BaseWithoutName> hidden_holder(
      cppgc::MakeGarbageCollected<BaseWithoutName>(allocation_handle()));
  auto* first =
      cppgc::MakeGarbageCollected<BaseWithoutName>(allocation_handle());
  auto* second =
      cppgc::MakeGarbageCollected<BaseWithoutName>(allocation_handle());
  first->next = second;
  second->next = *hidden_holder;
  second->next2 = first;
  first->next2 = cppgc::MakeGarbageCollected<GCed>(allocation_handle());
  cppgc::Persistent<BaseWithoutName> holder(first);
  const v8::HeapSnapshot* snapshot =
      TakeHeapSnapshot(cppgc::EmbedderStackState::kMayContainHeapPointers,
                       v8::HeapProfiler::HeapSnapshotMode::kRegular);
  EXPECT_TRUE(IsValidSnapshot(snapshot));
  EXPECT_TRUE(ContainsRetainingPath(
      *snapshot, {kExpectedCppRootsName, cppgc::NameProvider::kHiddenName,
                  cppgc::NameProvider::kHiddenName,
                  cppgc::NameProvider::kHiddenName, GetExpectedName<GCed>()}));
}

namespace {

class GCedWithJSRef : public cppgc::GarbageCollected<GCedWithJSRef> {
 public:
  static constexpr const char kExpectedName[] =
      "v8::internal::(anonymous namespace)::GCedWithJSRef";

  virtual void Trace(cppgc::Visitor* v) const { v->Trace(v8_object_); }

  void SetV8Object(v8::Isolate* isolate, v8::Local<v8::Object> object) {
    v8_object_.Reset(isolate, object);
  }

  TracedReference<v8::Object>& wrapper() { return v8_object_; }

  void set_detachedness(v8::EmbedderGraph::Node::Detachedness detachedness) {
    detachedness_ = detachedness;
  }
  v8::EmbedderGraph::Node::Detachedness detachedness() const {
    return detachedness_;
  }

 private:
  TracedReference<v8::Object> v8_object_;
  v8::EmbedderGraph::Node::Detachedness detachedness_ =
      v8::EmbedderGraph::Node::Detachedness ::kUnknown;
};

constexpr const char GCedWithJSRef::kExpectedName[];

class V8_NODISCARD JsTestingScope {
 public:
  explicit JsTestingScope(v8::Isolate* isolate)
      : isolate_(isolate),
        handle_scope_(isolate),
        context_(v8::Context::New(isolate)),
        context_scope_(context_) {}

  v8::Isolate* isolate() const { return isolate_; }
  v8::Local<v8::Context> context() const { return context_; }

 private:
  v8::Isolate* isolate_;
  v8::HandleScope handle_scope_;
  v8::Local<v8::Context> context_;
  v8::Context::Scope context_scope_;
};

cppgc::Persistent<GCedWithJSRef> SetupWrapperWrappablePair(
    JsTestingScope& testing_scope, cppgc::AllocationHandle& allocation_handle,
    const char* name,
    v8::EmbedderGraph::Node::Detachedness detachedness =
        v8::EmbedderGraph::Node::Detachedness::kUnknown) {
  cppgc::Persistent<GCedWithJSRef> gc_w_js_ref =
      cppgc::MakeGarbageCollected<GCedWithJSRef>(allocation_handle);
  v8::Local<v8::Object> wrapper_object = WrapperHelper::CreateWrapper(
      testing_scope.context(), gc_w_js_ref.Get(), name);
  gc_w_js_ref->SetV8Object(testing_scope.isolate(), wrapper_object);
  gc_w_js_ref->set_detachedness(detachedness);
  return gc_w_js_ref;
}

template <typename Callback>
void ForEachEntryWithName(const v8::HeapSnapshot* snapshot, const char* needle,
                          Callback callback) {
  const HeapSnapshot* heap_snapshot =
      reinterpret_cast<const HeapSnapshot*>(snapshot);
  for (const HeapEntry& entry : heap_snapshot->entries()) {
    if (strcmp(entry.name(), needle) == 0) {
      callback(entry);
    }
  }
}

}  // namespace

TEST_F(UnifiedHeapSnapshotTest, JSReferenceForcesVisibleObject) {
  // Test ensures that a C++->JS reference forces an object to be visible in the
  // snapshot.
  JsTestingScope testing_scope(v8_isolate());
  cppgc::Persistent<GCedWithJSRef> gc_w_js_ref = SetupWrapperWrappablePair(
      testing_scope, allocation_handle(), "LeafJSObject");
  // Reset the JS->C++ ref or otherwise the nodes would be merged.
  WrapperHelper::ResetWrappableConnection(
      v8_isolate(), gc_w_js_ref->wrapper().Get(v8_isolate()));
  const v8::HeapSnapshot* snapshot =
      TakeHeapSnapshot(cppgc::EmbedderStackState::kMayContainHeapPointers,
                       v8::HeapProfiler::HeapSnapshotMode::kRegular);
  EXPECT_TRUE(IsValidSnapshot(snapshot));
  EXPECT_TRUE(ContainsRetainingPath(
      *snapshot,
      {kExpectedCppRootsName, cppgc::NameProvider::kHiddenName, "LeafJSObject"},
      true));
}

void UnifiedHeapSnapshotTest::TestMergedWrapperNode(
    v8::HeapProfiler::HeapSnapshotMode snapshot_mode) {
  // Test ensures that the snapshot sets a wrapper node for C++->JS references
  // that have a valid back reference and that object nodes are merged. In
  // practice, the C++ node is merged into the existing JS node.
  JsTestingScope testing_scope(v8_isolate());
  cppgc::Persistent<GCedWithJSRef> gc_w_js_ref = SetupWrapperWrappablePair(
      testing_scope, allocation_handle(), "MergedObject");
  v8::Local<v8::Object> next_object = WrapperHelper::CreateWrapper(
      testing_scope.context(), nullptr, "NextObject");
  v8::Local<v8::Object> wrapper_object =
      gc_w_js_ref->wrapper().Get(v8_isolate());
  // Chain another object to `wrapper_object`. Since `wrapper_object` should be
  // merged into `GCedWithJSRef`, the additional object must show up as direct
  // child from `GCedWithJSRef`.
  wrapper_object
      ->Set(testing_scope.context(),
            v8::String::NewFromUtf8(v8::Isolate::GetCurrent(), "link")
                .ToLocalChecked(),
            next_object)
      .ToChecked();
  const v8::HeapSnapshot* snapshot = TakeHeapSnapshot(
      cppgc::EmbedderStackState::kMayContainHeapPointers, snapshot_mode);
  EXPECT_TRUE(IsValidSnapshot(snapshot));
  const char* kExpectedName =
      snapshot_mode == v8::HeapProfiler::HeapSnapshotMode::kExposeInternals
          ? GetExpectedName<GCedWithJSRef>()
          : cppgc::NameProvider::kHiddenName;
  EXPECT_TRUE(ContainsRetainingPath(
      *snapshot,
      {kExpectedCppRootsName, kExpectedName,
       // GCedWithJSRef is merged into MergedObject, replacing its name.
       "NextObject"}));
  const size_t js_size = Utils::OpenDirectHandle(*wrapper_object)->Size();
  if (snapshot_mode == v8::HeapProfiler::HeapSnapshotMode::kExposeInternals) {
    const size_t cpp_size =
        cppgc::internal::HeapObjectHeader::FromObject(gc_w_js_ref.Get())
            .AllocatedSize();
    ForEachEntryWithName(snapshot, kExpectedName,
                         [cpp_size, js_size](const HeapEntry& entry) {
                           EXPECT_EQ(cpp_size + js_size, entry.self_size());
                         });
  } else {
    ForEachEntryWithName(snapshot, kExpectedName,
                         [js_size](const HeapEntry& entry) {
                           EXPECT_EQ(js_size, entry.self_size());
                         });
  }
}

TEST_F(UnifiedHeapSnapshotTest, MergedWrapperNodeWithInternalDetails) {
  TestMergedWrapperNode(v8::HeapProfiler::HeapSnapshotMode::kExposeInternals);
}

TEST_F(UnifiedHeapSnapshotTest, MergedWrapperNodeWithoutInternalDetails) {
  TestMergedWrapperNode(v8::HeapProfiler::HeapSnapshotMode::kRegular);
}

namespace {

class DetachednessHandler {
 public:
  static size_t callback_count;

  static v8::EmbedderGraph::Node::Detachedness GetDetachedness(
      v8::Isolate* isolate, const v8::Local<v8::Value>& v8_value, uint16_t,
      void*) {
    callback_count++;
    return WrapperHelper::UnwrapAs<GCedWithJSRef>(isolate,
                                                  v8_value.As<v8::Object>())
        ->detachedness();
  }

  static void Reset() { callback_count = 0; }
};
// static
size_t DetachednessHandler::callback_count = 0;

constexpr uint8_t kExpectedDetachedValueForUnknown =
    static_cast<uint8_t>(v8::EmbedderGraph::Node::Detachedness::kUnknown);
constexpr uint8_t kExpectedDetachedValueForAttached =
    static_cast<uint8_t>(v8::EmbedderGraph::Node::Detachedness::kAttached);
constexpr uint8_t kExpectedDetachedValueForDetached =
    static_cast<uint8_t>(v8::EmbedderGraph::Node::Detachedness::kDetached);

}  // namespace

TEST_F(UnifiedHeapSnapshotTest, DetachedObjectsRetainedByJSReference) {
  v8::Isolate* isolate = v8_isolate();
  v8::HandleScope scope(isolate);
  v8::HeapProfiler* heap_profiler = isolate->GetHeapProfiler();
  heap_profiler->SetGetDetachednessCallback(
      DetachednessHandler::GetDetachedness, nullptr);
  // Test ensures that objects that are retained by a JS reference are obtained
  // by the GetDetachedJSWrapperObjects() function
  JsTestingScope testing_scope(v8_isolate());
  cppgc::Persistent<GCedWithJSRef> gc_w_js_ref = SetupWrapperWrappablePair(
      testing_scope, allocation_handle(), "Obj",
      v8::EmbedderGraph::Node::Detachedness ::kDetached);
  // Ensure we are obtaining a Detached Wrapper
  CHECK_EQ(1, heap_profiler->GetDetachedJSWrapperObjects().size());

  cppgc::Persistent<GCedWithJSRef> gc_w_js_ref_not_detached =
      SetupWrapperWrappablePair(
          testing_scope, allocation_handle(), "Obj",
          v8::EmbedderGraph::Node::Detachedness ::kAttached);
  cppgc::Persistent<GCedWithJSRef> gc_w_js_ref_unknown =
      SetupWrapperWrappablePair(
          testing_scope, allocation_handle(), "Obj",
          v8::EmbedderGraph::Node::Detachedness ::kUnknown);
  // Ensure we are only obtaining Wrappers that are Detached
  CHECK_EQ(1, heap_profiler->GetDetachedJSWrapperObjects().size());

  cppgc::Persistent<GCedWithJSRef> gc_w_js_ref2 = SetupWrapperWrappablePair(
      testing_scope, allocation_handle(), "Obj",
      v8::EmbedderGraph::Node::Detachedness ::kDetached);
  cppgc::Persistent<GCedWithJSRef> gc_w_js_ref3 = SetupWrapperWrappablePair(
      testing_scope, allocation_handle(), "Obj",
      v8::EmbedderGraph::Node::Detachedness ::kDetached);
  // Ensure we are obtaining all Detached Wrappers
  CHECK_EQ(3, heap_profiler->GetDetachedJSWrapperObjects().size());
}

TEST_F(UnifiedHeapSnapshotTest, NoTriggerForStandAloneTracedReference) {
  // Test ensures that C++ objects with TracedReference have their V8 objects
  // not merged and queried for detachedness if the backreference is invalid.
  JsTestingScope testing_scope(v8_isolate());
  // Marking the object as attached. The check below queries for unknown, making
  // sure that the state is not propagated.
  cppgc::Persistent<GCedWithJSRef> gc_w_js_ref = SetupWrapperWrappablePair(
      testing_scope, allocation_handle(), "MergedObject",
      v8::EmbedderGraph::Node::Detachedness::kAttached);
  DetachednessHandler::Reset();
  v8_isolate()->GetHeapProfiler()->SetGetDetachednessCallback(
      DetachednessHandler::GetDetachedness, nullptr);
  WrapperHelper::ResetWrappableConnection(
      v8_isolate(), gc_w_js_ref->wrapper().Get(v8_isolate()));
  const v8::HeapSnapshot* snapshot = TakeHeapSnapshot();
  EXPECT_EQ(0u, DetachednessHandler::callback_count);
  EXPECT_TRUE(IsValidSnapshot(snapshot));
  EXPECT_TRUE(
      ContainsRetainingPath(*snapshot, {
                                           kExpectedCppRootsName,
                                           GetExpectedName<GCedWithJSRef>(),
                                       }));
  ForEachEntryWithName(
      snapshot, GetExpectedName<GCedWithJSRef>(), [](const HeapEntry& entry) {
        EXPECT_EQ(kExpectedDetachedValueForUnknown, entry.detachedness());
      });
}

TEST_F(UnifiedHeapSnapshotTest, TriggerDetachednessCallbackSettingAttached) {
  // Test ensures that objects with JS references that have a valid back
  // reference set do have their detachedness state queried and set (attached
  // version).
  JsTestingScope testing_scope(v8_isolate());
  cppgc::Persistent<GCedWithJSRef> gc_w_js_ref = SetupWrapperWrappablePair(
      testing_scope, allocation_handle(), "MergedObject",
      v8::EmbedderGraph::Node::Detachedness::kAttached);
  DetachednessHandler::Reset();
  v8_isolate()->GetHeapProfiler()->SetGetDetachednessCallback(
      DetachednessHandler::GetDetachedness, nullptr);
  const v8::HeapSnapshot* snapshot = TakeHeapSnapshot();
  EXPECT_EQ(1u, DetachednessHandler::callback_count);
  EXPECT_TRUE(IsValidSnapshot(snapshot));
  EXPECT_TRUE(
      ContainsRetainingPath(*snapshot, {
                                           kExpectedCppRootsName,
                                           GetExpectedName<GCedWithJSRef>(),
                                       }));
  ForEachEntryWithName(
      snapshot, GetExpectedName<GCedWithJSRef>(), [](const HeapEntry& entry) {
        EXPECT_EQ(kExpectedDetachedValueForAttached, entry.detachedness());
      });
}

TEST_F(UnifiedHeapSnapshotTest, TriggerDetachednessCallbackSettingDetached) {
  // Test ensures that objects with JS references that have a valid back
  // reference set do have their detachedness state queried and set (detached
  // version).
  JsTestingScope testing_scope(v8_isolate());
  cppgc::Persistent<GCedWithJSRef> gc_w_js_ref = SetupWrapperWrappablePair(
      testing_scope, allocation_handle(), "MergedObject",
      v8::EmbedderGraph::Node::Detachedness ::kDetached);
  DetachednessHandler::Reset();
  v8_isolate()->GetHeapProfiler()->SetGetDetachednessCallback(
      DetachednessHandler::GetDetachedness, nullptr);
  const v8::HeapSnapshot* snapshot = TakeHeapSnapshot();
  EXPECT_EQ(1u, DetachednessHandler::callback_count);
  EXPECT_TRUE(IsValidSnapshot(snapshot));
  EXPECT_TRUE(
      ContainsRetainingPath(*snapshot, {
                                           kExpectedCppRootsName,
                                           GetExpectedName<GCedWithJSRef>(),
                                       }));
  ForEachEntryWithName(
      snapshot, GetExpectedName<GCedWithJSRef>(), [](const HeapEntry& entry) {
        EXPECT_EQ(kExpectedDetachedValueForDetached, entry.detachedness());
      });
}

namespace {
class WrappedContext : public cppgc::GarbageCollected<WrappedContext>,
                       public cppgc::NameProvider {
 public:
  static constexpr const char kExpectedName[] = "cppgc WrappedContext";

  // Cycle:
  // Context -> EmbdderData -> WrappedContext JS object -> WrappedContext cppgc
  // object -> Context
  static cppgc::Persistent<WrappedContext> New(v8::Isolate* isolate) {
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    v8::Local<v8::Object> obj =
        WrapperHelper::CreateWrapper(context, nullptr, "js WrappedContext");
    context->SetEmbedderData(kContextDataIndex, obj);
    cppgc::Persistent<WrappedContext> ref =
        cppgc::MakeGarbageCollected<WrappedContext>(
            isolate->GetCppHeap()->GetAllocationHandle(), isolate, obj,
            context);
    WrapperHelper::SetWrappableConnection(isolate, obj, ref.Get());
    return ref;
  }

  static v8::EmbedderGraph::Node::Detachedness GetDetachedness(
      v8::Isolate* isolate, const v8::Local<v8::Value>& v8_value, uint16_t,
      void*) {
    return WrapperHelper::UnwrapAs<WrappedContext>(isolate,
                                                   v8_value.As<v8::Object>())
        ->detachedness();
  }

  const char* GetHumanReadableName() const final { return kExpectedName; }

  virtual void Trace(cppgc::Visitor* v) const {
    v->Trace(object_);
    v->Trace(context_);
  }

  WrappedContext(v8::Isolate* isolate, v8::Local<v8::Object> object,
                 v8::Local<v8::Context> context) {
    object_.Reset(isolate, object);
    context_.Reset(isolate, context);
  }

  v8::Local<v8::Context> context(v8::Isolate* isolate) {
    return context_.Get(isolate);
  }

  void set_detachedness(v8::EmbedderGraph::Node::Detachedness detachedness) {
    detachedness_ = detachedness;
  }
  v8::EmbedderGraph::Node::Detachedness detachedness() const {
    return detachedness_;
  }

 private:
  static constexpr int kContextDataIndex = 0;
  // This is needed to merge the nodes in the heap snapshot.
  TracedReference<v8::Object> object_;
  TracedReference<v8::Context> context_;
  v8::EmbedderGraph::Node::Detachedness detachedness_ =
      v8::EmbedderGraph::Node::Detachedness::kUnknown;
};
}  // anonymous namespace

TEST_F(UnifiedHeapSnapshotTest, WrappedContext) {
  JsTestingScope testing_scope(v8_isolate());
  v8_isolate()->GetHeapProfiler()->SetGetDetachednessCallback(
      WrappedContext::GetDetachedness, nullptr);
  cppgc::Persistent<WrappedContext> wrapped = WrappedContext::New(v8_isolate());
  const v8::HeapSnapshot* snapshot = TakeHeapSnapshot();
  EXPECT_TRUE(IsValidSnapshot(snapshot));
  EXPECT_TRUE(ContainsRetainingPath(
      *snapshot,
      {kExpectedCppRootsName, wrapped->GetHumanReadableName(),
       "system / NativeContext", "system / EmbedderDataArray",
       wrapped->GetHumanReadableName()},
      true));

  wrapped->set_detachedness(v8::EmbedderGraph::Node::Detachedness::kDetached);
  v8_isolate()->GetHeapProfiler()->DeleteAllHeapSnapshots();
  snapshot = TakeHeapSnapshot();
  EXPECT_TRUE(IsValidSnapshot(snapshot));
  EXPECT_TRUE(ContainsRetainingPath(
      *snapshot,
      {kExpectedCppRootsName, wrapped->GetHumanReadableName(),
       "system / NativeContext", "system / EmbedderDataArray",
       wrapped->GetHumanReadableName()},
      true));
  ForEachEntryWithName(
      snapshot, wrapped->GetHumanReadableName(), [](const HeapEntry& entry) {
        EXPECT_EQ(kExpectedDetachedValueForDetached, entry.detachedness());
      });
}

namespace {

class GCedWithDynamicName : public cppgc::GarbageCollected<GCedWithDynamicName>,
                            public cppgc::NameProvider {
 public:
  virtual void Trace(cppgc::Visitor* v) const {}

  void SetValue(int value) { value_ = value; }

  const char* GetHumanReadableName() const final {
    v8::HeapProfiler* heap_profiler =
        v8::Isolate::GetCurrent()->GetHeapProfiler();
    if (heap_profiler->IsTakingSnapshot()) {
      std::string name = "dynamic name " + std::to_string(value_);
      return heap_profiler->CopyNameForHeapSnapshot(name.c_str());
    }
    return "static name";
  }

 private:
  int value_ = 0;
};

}  // namespace

TEST_F(UnifiedHeapSnapshotTest, DynamicName) {
  cppgc::Persistent<GCedWithDynamicName> object_zero =
      cppgc::MakeGarbageCollected<GCedWithDynamicName>(allocation_handle());
  cppgc::Persistent<GCedWithDynamicName> object_one =
      cppgc::MakeGarbageCollected<GCedWithDynamicName>(allocation_handle());
  object_one->SetValue(1);
  std::string static_name =
      cppgc::internal::HeapObjectHeader::FromObject(object_one.Get())
          .GetName()
          .value;
  EXPECT_EQ(static_name, std::string("static name"));
  const v8::HeapSnapshot* snapshot = TakeHeapSnapshot();
  EXPECT_TRUE(IsValidSnapshot(snapshot));
  EXPECT_TRUE(ContainsRetainingPath(*snapshot,
                                    {kExpectedCppRootsName, "dynamic name 0"}));
  EXPECT_TRUE(ContainsRetainingPath(*snapshot,
                                    {kExpectedCppRootsName, "dynamic name 1"}));
  EXPECT_FALSE(
      ContainsRetainingPath(*snapshot, {kExpectedCppRootsName, "static name"}));
}

}  // namespace internal
}  // namespace v8

"""

```