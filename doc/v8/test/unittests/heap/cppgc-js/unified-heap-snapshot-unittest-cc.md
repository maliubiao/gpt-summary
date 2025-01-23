Response:
The user wants a summary of the provided C++ code snippet. The request asks for several things:

1. **Functionality:**  A high-level description of what the code does.
2. **Torque Check:** Whether the filename ending with `.tq` indicates a Torque source file.
3. **JavaScript Relation:** If the code relates to JavaScript, provide a JavaScript example.
4. **Logic Inference:** If there's logic, provide hypothetical inputs and outputs.
5. **Common Errors:** If it relates to common programming mistakes, give examples.
6. **Summary:**  A concise overall summary.

Let's break down the code and address each point.

**Code Analysis:**

* **Includes:** The code includes headers related to `cppgc` (V8's C++ garbage collector) and V8's heap profiling. This strongly suggests the code is testing or demonstrating features related to heap snapshots generated for the unified heap (which manages both JavaScript and C++ objects).
* **Custom Spaces:** The code defines a `CompactableCustomSpace`, indicating it's exploring how heap snapshots interact with custom memory spaces that support compaction.
* **Garbage Collected Types:** It defines `CompactableGCed`, `CompactableHolder`, `BaseWithoutName`, and `GCed`, all deriving from `cppgc::GarbageCollected`. This confirms it's dealing with C++ objects managed by `cppgc`.
* **NameProvider:** Some of these classes also inherit from `cppgc::NameProvider`, suggesting they can provide custom names for heap snapshots.
* **UnifiedHeapSnapshotTest:**  The core of the code is the `UnifiedHeapSnapshotTest` class, which inherits from `UnifiedHeapTest`. This strongly indicates it's a unit test for heap snapshot functionality in the context of the unified heap.
* **TakeHeapSnapshot:** The `TakeHeapSnapshot` method is key. It uses V8's `HeapProfiler` to generate heap snapshots.
* **Helper Functions:** There are functions like `IsValidSnapshot`, `GetIds`, `ContainsRetainingPath`, and `ForEachEntryWithName` that operate on `v8::HeapSnapshot` objects, likely for assertion and verification in the tests.
* **JS Interaction:** The code introduces `GCedWithJSRef` which has a `TracedReference<v8::Object>`, indicating it holds a reference to a JavaScript object. This, along with the `JsTestingScope` and `WrapperHelper` classes, shows interaction with the JavaScript heap.
* **Detachedness:** The code deals with the concept of "detachedness" for objects with JavaScript wrappers, which is a feature in V8's heap profiler to track objects that are no longer reachable from JavaScript but might still be held by C++.

**Addressing the Request Points:**

1. **Functionality:** The code defines unit tests for V8's unified heap snapshot functionality. It tests how C++ objects (with and without JavaScript references, in different memory spaces, and with various reachability scenarios) are represented in heap snapshots. It also explores the concept of object merging and detachedness in the snapshots.

2. **Torque Check:** The filename ends with `.cc`, not `.tq`. Therefore, it is **not** a V8 Torque source file.

3. **JavaScript Relation:** Yes, the code directly relates to JavaScript. The `GCedWithJSRef` class demonstrates C++ objects holding references to JavaScript objects.

4. **Logic Inference:**  Many of the tests have implicit logic. For example, the `RetainedByCppRoot` test:
    * **Assumption:**  Creating a `cppgc::Persistent` should make the object reachable from the C++ roots.
    * **Input:**  Create a `GCed` object and hold it with a `cppgc::Persistent`. Take a heap snapshot.
    * **Output:** The snapshot should contain a retaining path from "C++ Persistent roots" to the `GCed` object.

5. **Common Errors:** This code is primarily for testing, but it touches upon potential errors in managing object lifetimes and references between C++ and JavaScript. For instance, failing to properly manage `TracedReference` could lead to dangling pointers or memory leaks. A common error would be if the C++ side holds a reference to a JavaScript object that is no longer alive, or vice-versa, leading to inconsistencies.

6. **Summary:** This C++ source file contains unit tests for V8's unified heap snapshot generation. It focuses on verifying the correctness of heap snapshots when dealing with C++ objects, including those in custom memory spaces, those with JavaScript references, and scenarios involving object merging and detachedness tracking.
## 功能归纳：v8/test/unittests/heap/cppgc-js/unified-heap-snapshot-unittest.cc (第 1 部分)

这个C++源代码文件 `unified-heap-snapshot-unittest.cc` 是 **V8 JavaScript 引擎** 的一部分， 专门用于 **测试统一堆的快照功能**。  更具体地说，它测试了 **cppgc** (V8 的 C++ 垃圾回收器) 管理的 C++ 对象在统一堆快照中的表现。

**主要功能可以概括为以下几点：**

1. **生成堆快照:** 代码使用 `v8::HeapProfiler` 来创建堆快照，用于后续的分析和验证。
2. **验证快照的有效性:**  `IsValidSnapshot` 函数用于检查生成的堆快照是否符合预期的结构，例如，所有非根节点都有保留路径。
3. **查找特定对象:**  `GetIds` 函数可以根据对象名称在快照中查找对象的 ID。
4. **检查保留路径:**  `ContainsRetainingPath` 函数用于验证快照中是否存在从根节点到特定对象的预期保留路径。这有助于确认对象是否被正确地报告为存活，以及被哪些对象或根节点保留。
5. **测试不同类型的 C++ 对象:** 代码定义了多种继承自 `cppgc::GarbageCollected` 的 C++ 类 (`CompactableGCed`, `CompactableHolder`, `BaseWithoutName`, `GCed`, `GCedWithJSRef`, `WrappedContext`)，并针对它们在堆快照中的表示进行测试。
6. **测试 C++ 根节点的影响:**  测试了通过 `cppgc::Persistent` 和 `cppgc::subtle::CrossThreadPersistent` 持有的 C++ 对象在快照中的保留路径。
7. **测试 C++ 栈根的影响:** 测试了栈上局部变量持有的 C++ 对象在快照中的保留路径。
8. **测试命名和未命名的 C++ 对象:**  测试了实现了 `cppgc::NameProvider` 的命名对象和未实现该接口的未命名对象在快照中的显示方式。
9. **测试 C++ 对象之间的引用关系:**  测试了 C++ 对象之间的相互引用以及链式引用在快照中的表示。
10. **测试与 JavaScript 的交互:** 代码引入了 `GCedWithJSRef` 类，它包含一个 `v8::Object` 的 `TracedReference`，用于测试 C++ 对象持有 JavaScript 对象引用时在快照中的表现，包括对象合并和 detachedness 的概念。
11. **测试自定义内存空间:**  使用了 `CompactableCustomSpace` 来测试在自定义的可压缩内存空间中分配的 C++ 对象在快照中的表现，并验证对象在压缩后 ID 的一致性。

**关于代码逻辑推理的假设输入与输出示例 (以 `RetainedByCppRoot` 测试为例):**

**假设输入:**

* 在测试开始时，堆中没有 `GCed` 类型的对象。
* 通过 `cppgc::MakeGarbageCollected<GCed>(allocation_handle())` 创建一个 `GCed` 对象。
* 使用 `cppgc::Persistent<GCed> gced` 持有该对象，使其成为 C++ 持久根的可达对象。
* 调用 `TakeHeapSnapshot()` 生成堆快照。

**预期输出:**

* `IsValidSnapshot(snapshot)` 返回 `true`，表明生成的快照是有效的。
* `ContainsRetainingPath(*snapshot, {kExpectedCppRootsName, GetExpectedName<GCed>()})` 返回 `true`，表明在快照中存在从 "C++ Persistent roots" 到 `GCed` 对象的保留路径。

**关于用户常见的编程错误 (与 C++/JavaScript 互操作相关):**

* **忘记释放 `Persistent` 句柄:** 如果 C++ 代码创建了 `cppgc::Persistent` 或 `cppgc::subtle::CrossThreadPersistent`  来持有对象，但忘记在不再需要时 `Reset()` 或 `Release()`，会导致对象无法被垃圾回收，造成内存泄漏。
* **错误的生命周期管理导致悬挂指针:**  在 C++ 中手动管理内存时，如果过早地释放了对象，而其他部分的代码仍然持有指向该对象的指针，就会导致悬挂指针，访问时会引发崩溃或其他未定义行为。`cppgc` 通过自动垃圾回收减轻了这个问题，但仍然需要注意 `Persistent` 句柄的管理。
* **在 C++/JavaScript 边界处的生命周期不一致:**  当 C++ 对象持有 JavaScript 对象的引用 (如 `GCedWithJSRef`)，或者 JavaScript 对象持有 C++ 对象的 wrapper 时，必须确保两边的生命周期管理一致。如果 JavaScript 对象被垃圾回收，但 C++ 端仍然持有指向它的 `TracedReference`，则该引用会变为无效。反之亦然。V8 的统一堆和垃圾回收器会尝试处理这些情况，但错误的引用管理仍然可能导致问题。

**总结:**

总的来说，`v8/test/unittests/heap/cppgc-js/unified-heap-snapshot-unittest.cc` 的第一部分主要定义了用于测试 V8 统一堆快照功能的基础设施和一些核心的测试用例。这些测试用例覆盖了 C++ 对象在不同场景下 (例如，被不同类型的根节点持有、与其他 C++ 对象存在引用关系、以及与 JavaScript 对象存在关联) 如何出现在堆快照中，以及如何验证这些快照的正确性。它旨在确保 V8 的堆快照功能能够准确地反映统一堆的状态，这对于内存分析和性能调试至关重要。

### 提示词
```
这是目录为v8/test/unittests/heap/cppgc-js/unified-heap-snapshot-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/heap/cppgc-js/unified-heap-snapshot-unittest.cc以.tq结尾，那它是个v8 torque源代码，
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
        EXPECT_EQ(kExpectedDetachedValueForDetached, e
```