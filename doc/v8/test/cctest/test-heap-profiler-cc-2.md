Response:
The user wants me to analyze a C++ source code file related to V8's heap profiler.

Here's a breakdown of the thought process:

1. **Identify the core functionality:** The filename `test-heap-profiler.cc` and the presence of `v8::HeapProfiler` strongly suggest this code is testing the heap profiler's features.

2. **Scan for key API calls:** Look for calls to `v8::HeapProfiler` methods. I see calls like `TakeHeapSnapshot()`, `AddBuildEmbedderGraphCallback()`, `GetObjectId()`, `ClearObjectIds()`, `StartTrackingHeapObjects()`, `StopTrackingHeapObjects()`, `DeleteAllHeapSnapshots()`, `Delete()`, `GetSnapshotCount()`, `GetHeapSnapshot()`, `FindObjectById()`. These reveal the primary functionalities being tested.

3. **Analyze the tests:** Each `TEST(...)` block represents a specific test case. Analyze what each test does:
    * `HeapSnapshotRetainedObjectInfo`:  Focuses on how embedder-provided graphs are integrated into heap snapshots, specifically verifying the creation of synthetic group nodes and their connections to native objects.
    * `NativeSnapshotObjectId`: Tests the ability to obtain unique IDs for native (non-V8) objects and how these IDs relate to nodes in the heap snapshot. It also checks the `ClearObjectIds()` functionality.
    * `NativeSnapshotObjectIdMoving`:  Similar to the previous test but includes a garbage collection step to ensure that native object IDs persist even after the objects move in memory.
    * `DeleteAllHeapSnapshots`:  Tests the deletion of all taken heap snapshots.
    * `DeleteHeapSnapshot`: Tests the deletion of individual heap snapshots.
    * `GlobalObjectName`: Checks if a custom name resolver can provide names for global objects in the heap snapshot.
    * `GlobalObjectFields`: Verifies the presence of expected fields (like `global_proxy`) on the global object in the heap snapshot.
    * `NoHandleLeaks`:  Ensures that taking a heap snapshot doesn't introduce handle leaks.
    * `NodesIteration`:  Confirms that all nodes in a snapshot can be iterated over.
    * `GetHeapValueForNode`:  Tests the ability to retrieve the actual V8 `Object` corresponding to a node in the heap snapshot.
    * `GetHeapValueForDeletedObject`: Checks that `FindObjectById()` returns an empty handle for deleted objects.
    * `GetConstructor`:  Tests a helper function (`i::V8HeapExplorer::GetConstructor`) that attempts to find the constructor of a given JavaScript object.
    * `GetConstructorName`: Tests a helper function (`i::V8HeapExplorer::GetConstructorName`) to get the name of an object's constructor.
    * `FastCaseAccessors`: Tests how accessors defined with `__defineGetter__` and `__defineSetter__` are represented in the heap snapshot.
    * `FastCaseRedefinedAccessors`: Tests how redefined accessors (using `Object.defineProperty`) appear in the snapshot.
    * `SlowCaseAccessors`: Similar to `FastCaseAccessors`, but for objects with many properties to trigger "slow" property access.
    * `HiddenPropertiesFastCase`: Tests the representation of hidden properties (using `Private` symbols) in the heap snapshot.
    * `SymbolsAndPrivateClassFields`: Verifies the representation of symbols and private class fields in the snapshot.
    * `AccessorInfo`: Checks for the presence and correctness of `AccessorInfo` nodes in the snapshot, specifically related to function parameters.
    * `JSGeneratorObject`:  Examines the structure of `JSGeneratorObject` instances in the heap snapshot.
    * `HasWeakEdge`: This test case is incomplete in the provided snippet.

4. **Identify JavaScript relevance:** Many tests involve creating JavaScript objects and observing their representation in the heap snapshot. This directly relates to how developers interact with JavaScript and how the V8 engine manages memory.

5. **Look for code logic and potential errors:**  The tests often involve setting up specific scenarios (e.g., creating objects with certain properties, defining accessors) and then asserting that the heap snapshot reflects these scenarios accurately. Common programming errors related to memory management in JavaScript (though V8 handles much of this automatically) or incorrect assumptions about object structure could be revealed by these tests.

6. **Determine if it's Torque:** The prompt mentions checking for `.tq` extension. This file has a `.cc` extension, so it's C++ and not Torque.

7. **Synthesize the findings:** Combine the analysis of individual tests and the overall purpose to summarize the functionality of the file.

8. **Address specific constraints:** The prompt asks for examples and code logic reasoning.

    * **JavaScript example:**  Choose a simple test case that demonstrates a clear link between JavaScript code and the heap snapshot. The `GlobalObjectName` test is a good example.
    * **Code logic:** Select a test with some logic, like `NativeSnapshotObjectId`, and explain the assumptions and expected outputs.
    * **Common errors:** Think about typical mistakes when dealing with object properties, prototypes, or memory management concepts.

9. **Final review:** Ensure the summary accurately reflects the content of the code snippet and addresses all parts of the prompt. Pay attention to the "part 3 of 6" instruction, indicating a need for summarizing the functionality *of this specific part*.
这是 `v8/test/cctest/test-heap-profiler.cc` 的第三部分源代码，主要功能是**测试 V8 堆分析器 (Heap Profiler) 的功能，特别是关于快照 (Snapshot) 的创建、操作以及快照中节点信息的准确性。**

以下是更详细的功能分解：

**核心功能：**

* **验证 Embedder Graph 的集成:** `TEST(HeapSnapshotRetainedObjectInfo)` 检查了当通过 `AddBuildEmbedderGraphCallback` 添加自定义的 embedder graph 时，快照中是否正确地包含了这些信息，例如创建了合成的组节点并将 native 对象关联到这些组。
* **测试 Native 对象的快照 ID:** `TEST(NativeSnapshotObjectId)` 和 `TEST(NativeSnapshotObjectIdMoving)` 测试了 `HeapProfiler::GetObjectId()` 方法，该方法用于获取非 V8 管理的 native 对象的唯一 ID。它们验证了 ID 的唯一性，以及在垃圾回收移动对象后 ID 的持久性。
* **快照的删除操作:** `TEST(DeleteAllHeapSnapshots)` 和 `TEST(DeleteHeapSnapshot)` 测试了删除快照的功能，包括删除所有快照和删除单个快照。
* **全局对象名称的自定义:** `TEST(GlobalObjectName)` 演示了如何使用 `ObjectNameResolver` 接口自定义全局对象在快照中的名称。
* **全局对象字段的检查:** `TEST(GlobalObjectFields)` 检查了全局对象快照中是否存在预期的内部字段（例如 `global_proxy`）。
* **避免句柄泄漏:** `TEST(NoHandleLeaks)` 确保在拍摄快照后没有遗留的未释放的 V8 句柄。
* **节点迭代:** `TEST(NodesIteration)` 验证了可以遍历快照中的所有节点。
* **根据节点获取 V8 对象:** `TEST(GetHeapValueForNode)` 测试了 `HeapProfiler::FindObjectById()` 方法，该方法可以根据快照中节点的 ID 找到对应的 V8 对象。
* **处理已删除的对象:** `TEST(GetHeapValueForDeletedObject)` 验证了对于已删除的 JavaScript 对象，`HeapProfiler::FindObjectById()` 能正确返回空值。
* **获取构造函数信息:** `TEST(GetConstructor)` 和 `TEST(GetConstructorName)` 测试了辅助函数，用于获取 JavaScript 对象的构造函数以及构造函数的名称。
* **访问器属性的处理:** `TEST(FastCaseAccessors)`, `TEST(FastCaseRedefinedAccessors)`, 和 `TEST(SlowCaseAccessors)` 验证了堆快照如何表示通过 `__defineGetter__`, `__defineSetter__`, 和 `Object.defineProperty` 定义的访问器属性。
* **隐藏属性的处理:** `TEST(HiddenPropertiesFastCase)` 测试了如何表示使用 `Private` symbols 定义的隐藏属性。
* **符号和私有类字段的处理:** `TEST(SymbolsAndPrivateClassFields)` 验证了如何表示 Symbol 属性和私有类字段。
* **AccessorInfo 的检查:** `TEST(AccessorInfo)` 检查了与函数参数相关的 `AccessorInfo` 节点是否正确出现在快照中。
* **JSGeneratorObject 的检查:** `TEST(JSGeneratorObject)` 检查了生成器对象在快照中的结构，包括其内部属性。

**关于文件类型：**

`v8/test/cctest/test-heap-profiler.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque 文件。

**与 Javascript 的关系及示例：**

这个文件中的测试直接与 Javascript 的堆内存管理相关。堆分析器的目的是提供 Javascript 运行时堆内存的快照，帮助开发者理解内存使用情况和发现内存泄漏。

**JavaScript 示例 (基于 `TEST(GlobalObjectName)`)：**

```javascript
// 在 V8 环境中运行

document = { URL: "abcdefgh" };

// 当拍摄堆快照时，HeapProfiler 可以通过 NameResolver 自定义全局对象的名称。
// 在 C++ 测试代码中，定义了一个 NameResolver，
// 将所有对象的名字都返回 "Global object name"。

// 因此，在快照中，global 对象的名称可能显示为 "Object / Global object name"。
```

**代码逻辑推理 (基于 `TEST(NativeSnapshotObjectId)`)：**

**假设输入：**

1. 创建一个 V8 Isolate 和 HeapProfiler 实例。
2. 定义一个 Javascript 字符串对象 `wrapper`。
3. 定义两个 native 的整型变量 `native1` 和 `native2`。
4. 注册一个 `EmbedderGraphBuilderForNativeSnapshotObjectId::BuildEmbedderGraph` 回调函数。
5. 在回调函数中，创建两个 embedder graph 节点，一个关联到 `native1`，另一个关联到 `native2` 并与 `wrapper` 字符串的 V8 节点关联。
6. 拍摄堆快照。

**预期输出：**

1. `heap_profiler->GetObjectId(&native1)` 应该返回一个非 `kUnknownObjectId` 的 ID。
2. `heap_profiler->GetObjectId(&native2)` 应该返回一个非 `kUnknownObjectId` 的 ID。
3. `native1` 和 `native2` 的 ID 应该不同。
4. 通过这些 ID，可以从快照中找到对应的 `HeapGraphNode`。
5. 调用 `heap_profiler->ClearObjectIds()` 后，再次调用 `heap_profiler->GetObjectId(&native1)` 和 `heap_profiler->GetObjectId(&native2)` 应该返回 `kUnknownObjectId`。

**用户常见的编程错误 (与堆分析相关)：**

* **内存泄漏:**  忘记取消对不再使用的对象的引用，导致垃圾回收器无法回收内存。堆快照可以帮助识别这些持续存在的对象。
    ```javascript
    let leakedData = [];
    function createLeak() {
      let obj = { data: new Array(1000000) };
      leakedData.push(obj); // 错误：持续持有引用
    }

    setInterval(createLeak, 1000); // 每秒创建新的泄漏对象
    ```
    通过堆快照，可以看到 `leakedData` 数组不断增长，其中包含大量无法回收的对象。

* **意外的全局变量:**  在无意中创建了全局变量，导致其生命周期超出预期。
    ```javascript
    function myFunction() {
      mistake = "oops, global!"; // 错误：忘记使用 var/let/const
    }
    myFunction();
    ```
    堆快照会显示一个名为 `mistake` 的属性附加到全局对象上。

* **闭包引起的内存泄漏:**  闭包持有对其外部作用域变量的引用，如果这些闭包长期存在，可能会导致内存泄漏。
    ```javascript
    function createClosureLeak() {
      let largeData = new Array(1000000);
      return function() {
        console.log(largeData.length); // 闭包持有 largeData 的引用
      };
    }

    let leakyClosure = createClosureLeak();
    // 如果 leakyClosure 一直被持有，largeData 就无法被回收。
    ```
    堆快照会显示 `leakyClosure` 仍然持有对 `largeData` 的引用。

**功能归纳（针对第三部分）：**

这部分代码主要关注 **V8 堆分析器如何处理和表示快照中的各种对象和属性，包括 native 对象、全局对象、访问器属性、隐藏属性、符号以及私有类字段。** 它测试了获取 native 对象 ID 的机制，以及快照的删除功能。 核心目标是确保堆分析器能够准确地反映 V8 堆的状态，为开发者提供可靠的内存分析工具。

Prompt: 
```
这是目录为v8/test/cctest/test-heap-profiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-heap-profiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能

"""
e* isolate_;
  v8::EmbedderGraph* graph_;
  v8::EmbedderGraph::Node* classid_to_group_[3];
};

}  // namespace


static const v8::HeapGraphNode* GetNode(const v8::HeapGraphNode* parent,
                                        v8::HeapGraphNode::Type type,
                                        const char* name) {
  for (int i = 0, count = parent->GetChildrenCount(); i < count; ++i) {
    const v8::HeapGraphNode* node = parent->GetChild(i)->GetToNode();
    if (node->GetType() == type && strcmp(name,
               const_cast<i::HeapEntry*>(
                   reinterpret_cast<const i::HeapEntry*>(node))->name()) == 0) {
      return node;
    }
  }
  return nullptr;
}


TEST(HeapSnapshotRetainedObjectInfo) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::HeapProfiler* heap_profiler = isolate->GetHeapProfiler();

  heap_profiler->AddBuildEmbedderGraphCallback(
      EmbedderGraphBuilder::BuildEmbedderGraph, nullptr);
  v8::Persistent<v8::String> p_AAA(isolate, v8_str("AAA"));
  p_AAA.SetWrapperClassId(1);
  v8::Persistent<v8::String> p_BBB(isolate, v8_str("BBB"));
  p_BBB.SetWrapperClassId(1);
  v8::Persistent<v8::String> p_CCC(isolate, v8_str("CCC"));
  p_CCC.SetWrapperClassId(2);
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));

  const v8::HeapGraphNode* native_group_aaa =
      GetNode(snapshot->GetRoot(), v8::HeapGraphNode::kSynthetic, "aaa-group");
  CHECK_NOT_NULL(native_group_aaa);
  const v8::HeapGraphNode* native_group_ccc =
      GetNode(snapshot->GetRoot(), v8::HeapGraphNode::kSynthetic, "ccc-group");
  CHECK_NOT_NULL(native_group_ccc);

  const v8::HeapGraphNode* n_AAA =
      GetNode(native_group_aaa, v8::HeapGraphNode::kString, "AAA");
  CHECK(n_AAA);
  const v8::HeapGraphNode* n_BBB =
      GetNode(native_group_aaa, v8::HeapGraphNode::kString, "BBB");
  CHECK(n_BBB);
  const v8::HeapGraphNode* n_CCC =
      GetNode(native_group_ccc, v8::HeapGraphNode::kString, "CCC");
  CHECK(n_CCC);

  CHECK_EQ(native_group_aaa, GetChildByName(n_AAA, "aaa-group"));
  CHECK_EQ(native_group_aaa, GetChildByName(n_BBB, "aaa-group"));
  CHECK_EQ(native_group_ccc, GetChildByName(n_CCC, "ccc-group"));
}

namespace {

class EmbedderGraphBuilderForNativeSnapshotObjectId final {
 public:
  class RegularNode : public v8::EmbedderGraph::Node {
   public:
    RegularNode(v8::NativeObject native_object, const char* name, size_t size,
                Node* wrapper_node)
        : name_(name),
          size_(size),
          native_object_(native_object),
          wrapper_node_(wrapper_node) {}
    // v8::EmbedderGraph::Node
    const char* Name() override { return name_; }
    size_t SizeInBytes() override { return size_; }
    Node* WrapperNode() override { return wrapper_node_; }
    v8::NativeObject GetNativeObject() override {
      return native_object_ ? native_object_ : this;
    }

   private:
    const char* name_;
    size_t size_;
    v8::NativeObject native_object_;
    Node* wrapper_node_;
  };

  class RootNode : public RegularNode {
   public:
    explicit RootNode(const char* name)
        : RegularNode(nullptr, name, 0, nullptr) {}
    // v8::EmbedderGraph::EmbedderNode
    bool IsRootNode() override { return true; }
  };

  struct BuildParameter {
    v8::Persistent<v8::String>* wrapper;
    void* native1;
    void* native2;
  };

  static void BuildEmbedderGraph(v8::Isolate* isolate, v8::EmbedderGraph* graph,
                                 void* data) {
    BuildParameter* parameter = reinterpret_cast<BuildParameter*>(data);
    v8::Local<v8::String> local_str =
        v8::Local<v8::String>::New(isolate, *(parameter->wrapper));
    auto* v8_node = graph->V8Node(local_str.As<v8::Value>());
    CHECK(!v8_node->IsEmbedderNode());
    auto* root_node =
        graph->AddNode(std::unique_ptr<RootNode>(new RootNode("root")));
    auto* non_merged_node = graph->AddNode(std::unique_ptr<RegularNode>(
        new RegularNode(parameter->native1, "non-merged", 0, nullptr)));
    auto* merged_node = graph->AddNode(std::unique_ptr<RegularNode>(
        new RegularNode(parameter->native2, "merged", 0, v8_node)));
    graph->AddEdge(root_node, non_merged_node);
    graph->AddEdge(root_node, merged_node);
  }
};

}  // namespace

TEST(NativeSnapshotObjectId) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::HeapProfiler* heap_profiler = isolate->GetHeapProfiler();

  v8::Persistent<v8::String> wrapper(isolate, v8_str("wrapper"));
  int native1;
  int native2;

  EmbedderGraphBuilderForNativeSnapshotObjectId::BuildParameter parameter{
      &wrapper, &native1, &native2};
  heap_profiler->AddBuildEmbedderGraphCallback(
      EmbedderGraphBuilderForNativeSnapshotObjectId::BuildEmbedderGraph,
      &parameter);
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));

  v8::SnapshotObjectId non_merged_id = heap_profiler->GetObjectId(&native1);
  CHECK_NE(v8::HeapProfiler::kUnknownObjectId, non_merged_id);
  v8::SnapshotObjectId merged_id = heap_profiler->GetObjectId(&native2);
  CHECK_NE(v8::HeapProfiler::kUnknownObjectId, merged_id);
  CHECK_NE(non_merged_id, merged_id);
  const v8::HeapGraphNode* non_merged_node =
      snapshot->GetNodeById(non_merged_id);
  CHECK_NOT_NULL(non_merged_node);
  const v8::HeapGraphNode* merged_node = snapshot->GetNodeById(merged_id);
  CHECK_NOT_NULL(merged_node);

  heap_profiler->ClearObjectIds();
  CHECK_EQ(v8::HeapProfiler::kUnknownObjectId,
           heap_profiler->GetObjectId(&native1));
  CHECK_EQ(v8::HeapProfiler::kUnknownObjectId,
           heap_profiler->GetObjectId(&native2));
}

TEST(NativeSnapshotObjectIdMoving) {
  // Required to allow moving specific objects.
  i::ManualGCScope manual_gc_scope;
  i::heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);
  // Concurrent allocation writes page flags in a racy way.
  i::v8_flags.stress_concurrent_allocation = false;

  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::HeapProfiler* heap_profiler = isolate->GetHeapProfiler();
  heap_profiler->StartTrackingHeapObjects(true);

  v8::Persistent<v8::String> wrapper(isolate, v8_str("wrapper"));
  int native1;
  int native2;

  EmbedderGraphBuilderForNativeSnapshotObjectId::BuildParameter parameter{
      &wrapper, &native1, &native2};
  heap_profiler->AddBuildEmbedderGraphCallback(
      EmbedderGraphBuilderForNativeSnapshotObjectId::BuildEmbedderGraph,
      &parameter);
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));

  v8::SnapshotObjectId non_merged_id = heap_profiler->GetObjectId(&native1);
  CHECK_NE(v8::HeapProfiler::kUnknownObjectId, non_merged_id);
  v8::SnapshotObjectId merged_id = heap_profiler->GetObjectId(&native2);
  CHECK_NE(v8::HeapProfiler::kUnknownObjectId, merged_id);
  CHECK_NE(non_merged_id, merged_id);
  const v8::HeapGraphNode* non_merged_node =
      snapshot->GetNodeById(non_merged_id);
  CHECK_NOT_NULL(non_merged_node);
  const v8::HeapGraphNode* merged_node = snapshot->GetNodeById(merged_id);
  CHECK_NOT_NULL(merged_node);

  {
    v8::HandleScope inner_scope(isolate);
    auto local = v8::Local<v8::String>::New(isolate, wrapper);
    i::DirectHandle<i::String> internal = i::Cast<i::String>(
        v8::Utils::OpenDirectHandle(*v8::Local<v8::String>::Cast(local)));
    i::heap::ForceEvacuationCandidate(
        i::PageMetadata::FromHeapObject(*internal));
  }
  i::heap::InvokeMajorGC(CcTest::heap());

  non_merged_id = heap_profiler->GetObjectId(&native1);
  CHECK_NE(v8::HeapProfiler::kUnknownObjectId, non_merged_id);
  merged_id = heap_profiler->GetObjectId(&native2);
  CHECK_NE(v8::HeapProfiler::kUnknownObjectId, merged_id);
  CHECK_NE(non_merged_id, merged_id);

  heap_profiler->StopTrackingHeapObjects();
}

TEST(DeleteAllHeapSnapshots) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  CHECK_EQ(0, heap_profiler->GetSnapshotCount());
  heap_profiler->DeleteAllHeapSnapshots();
  CHECK_EQ(0, heap_profiler->GetSnapshotCount());
  CHECK(heap_profiler->TakeHeapSnapshot());
  CHECK_EQ(1, heap_profiler->GetSnapshotCount());
  heap_profiler->DeleteAllHeapSnapshots();
  CHECK_EQ(0, heap_profiler->GetSnapshotCount());
  CHECK(heap_profiler->TakeHeapSnapshot());
  CHECK(heap_profiler->TakeHeapSnapshot());
  CHECK_EQ(2, heap_profiler->GetSnapshotCount());
  heap_profiler->DeleteAllHeapSnapshots();
  CHECK_EQ(0, heap_profiler->GetSnapshotCount());
}


static bool FindHeapSnapshot(v8::HeapProfiler* profiler,
                             const v8::HeapSnapshot* snapshot) {
  int length = profiler->GetSnapshotCount();
  for (int i = 0; i < length; i++) {
    if (snapshot == profiler->GetHeapSnapshot(i)) return true;
  }
  return false;
}


TEST(DeleteHeapSnapshot) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  CHECK_EQ(0, heap_profiler->GetSnapshotCount());
  const v8::HeapSnapshot* s1 = heap_profiler->TakeHeapSnapshot();

  CHECK(s1);
  CHECK_EQ(1, heap_profiler->GetSnapshotCount());
  CHECK(FindHeapSnapshot(heap_profiler, s1));
  const_cast<v8::HeapSnapshot*>(s1)->Delete();
  CHECK_EQ(0, heap_profiler->GetSnapshotCount());
  CHECK(!FindHeapSnapshot(heap_profiler, s1));

  const v8::HeapSnapshot* s2 = heap_profiler->TakeHeapSnapshot();
  CHECK(s2);
  CHECK_EQ(1, heap_profiler->GetSnapshotCount());
  CHECK(FindHeapSnapshot(heap_profiler, s2));
  const v8::HeapSnapshot* s3 = heap_profiler->TakeHeapSnapshot();
  CHECK(s3);
  CHECK_EQ(2, heap_profiler->GetSnapshotCount());
  CHECK_NE(s2, s3);
  CHECK(FindHeapSnapshot(heap_profiler, s3));
  const_cast<v8::HeapSnapshot*>(s2)->Delete();
  CHECK_EQ(1, heap_profiler->GetSnapshotCount());
  CHECK(!FindHeapSnapshot(heap_profiler, s2));
  CHECK(FindHeapSnapshot(heap_profiler, s3));
  const_cast<v8::HeapSnapshot*>(s3)->Delete();
  CHECK_EQ(0, heap_profiler->GetSnapshotCount());
  CHECK(!FindHeapSnapshot(heap_profiler, s3));
}


class NameResolver : public v8::HeapProfiler::ObjectNameResolver {
 public:
  const char* GetName(v8::Local<v8::Object> object) override {
    return "Global object name";
  }
};


TEST(GlobalObjectName) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  CompileRun("document = { URL:\"abcdefgh\" };");

  NameResolver name_resolver;
  const v8::HeapSnapshot* snapshot =
      heap_profiler->TakeHeapSnapshot(nullptr, &name_resolver);
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  CHECK(global);
  CHECK_EQ(0,
           strcmp("Object / Global object name",
                  const_cast<i::HeapEntry*>(
                      reinterpret_cast<const i::HeapEntry*>(global))->name()));
}


TEST(GlobalObjectFields) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  CompileRun("obj = {};");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  const v8::HeapGraphNode* global_proxy = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kInternal, "global_proxy");
  CHECK(global_proxy);
}


TEST(NoHandleLeaks) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  CompileRun("document = { URL:\"abcdefgh\" };");

  i::Isolate* isolate = CcTest::i_isolate();
  int count_before = i::HandleScope::NumberOfHandles(isolate);
  heap_profiler->TakeHeapSnapshot();
  int count_after = i::HandleScope::NumberOfHandles(isolate);
  CHECK_EQ(count_before, count_after);
}


TEST(NodesIteration) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  CHECK(global);
  // Verify that we can find this object by iteration.
  const int nodes_count = snapshot->GetNodesCount();
  int count = 0;
  for (int i = 0; i < nodes_count; ++i) {
    if (snapshot->GetNode(i) == global)
      ++count;
  }
  CHECK_EQ(1, count);
}

// Allow usages of v8::Object::GetPrototype() for now.
// TODO(https://crbug.com/333672197): remove.
START_ALLOW_USE_DEPRECATED()

TEST(GetHeapValueForNode) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  CompileRun("a = { s_prop: \'value\', n_prop: \'value2\' };");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  CHECK(heap_profiler->FindObjectById(global->GetId())->IsObject());
  v8::Local<v8::Object> js_global =
      env->Global()->GetPrototype().As<v8::Object>();
  CHECK_EQ(js_global, heap_profiler->FindObjectById(global->GetId()));
  const v8::HeapGraphNode* obj =
      GetProperty(env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "a");
  CHECK(heap_profiler->FindObjectById(obj->GetId())->IsObject());
  v8::Local<v8::Object> js_obj = js_global->Get(env.local(), v8_str("a"))
                                     .ToLocalChecked()
                                     .As<v8::Object>();
  CHECK_EQ(js_obj, heap_profiler->FindObjectById(obj->GetId()));
  const v8::HeapGraphNode* s_prop = GetProperty(
      env->GetIsolate(), obj, v8::HeapGraphEdge::kProperty, "s_prop");
  v8::Local<v8::String> js_s_prop = js_obj->Get(env.local(), v8_str("s_prop"))
                                        .ToLocalChecked()
                                        .As<v8::String>();
  CHECK_EQ(js_s_prop, heap_profiler->FindObjectById(s_prop->GetId()));
  const v8::HeapGraphNode* n_prop = GetProperty(
      env->GetIsolate(), obj, v8::HeapGraphEdge::kProperty, "n_prop");
  v8::Local<v8::String> js_n_prop = js_obj->Get(env.local(), v8_str("n_prop"))
                                        .ToLocalChecked()
                                        .As<v8::String>();
  CHECK_EQ(js_n_prop, heap_profiler->FindObjectById(n_prop->GetId()));
}


TEST(GetHeapValueForDeletedObject) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  // It is impossible to delete a global property, so we are about to delete a
  // property of the "a" object. Also, the "p" object can't be an empty one
  // because the empty object is static and isn't actually deleted.
  CompileRun("a = { p: { r: {} } };");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  const v8::HeapGraphNode* obj =
      GetProperty(env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "a");
  const v8::HeapGraphNode* prop =
      GetProperty(env->GetIsolate(), obj, v8::HeapGraphEdge::kProperty, "p");
  {
    // Perform the check inside a nested local scope to avoid creating a
    // reference to the object we are deleting.
    v8::HandleScope inner_scope(env->GetIsolate());
    CHECK(heap_profiler->FindObjectById(prop->GetId())->IsObject());
  }
  CompileRun("delete a.p;");
  {
    // Exclude the stack during object finding, so that conservative stack
    // scanning may not accidentally mark the object as reachable.
    i::Heap* heap = reinterpret_cast<i::Isolate*>(env->GetIsolate())->heap();
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    CHECK(heap_profiler->FindObjectById(prop->GetId()).IsEmpty());
  }
}

static int StringCmp(const char* ref, i::Tagged<i::String> act) {
  std::unique_ptr<char[]> s_act = act->ToCString();
  int result = strcmp(ref, s_act.get());
  if (result != 0)
    fprintf(stderr, "Expected: \"%s\", Actual: \"%s\"\n", ref, s_act.get());
  return result;
}

TEST(GetConstructor) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(env->GetIsolate());

  CompileRun(
      "function Constructor1() {};\n"
      "var obj1 = new Constructor1();\n"
      "var Constructor2 = function() {};\n"
      "var obj2 = new Constructor2();\n"
      "var obj3 = {};\n"
      "obj3.__proto__ = { constructor: function Constructor3() {} };\n"
      "var obj4 = {};\n"
      "// Slow properties\n"
      "for (var i=0; i<2000; ++i) obj4[\"p\" + i] = i;\n"
      "obj4.__proto__ = { constructor: function Constructor4() {} };\n"
      "var obj5 = {};\n"
      "var obj6 = {};\n"
      "obj6.constructor = 6;");
  v8::Local<v8::Object> js_global =
      env->Global()->GetPrototype().As<v8::Object>();
  v8::Local<v8::Object> obj1 = js_global->Get(env.local(), v8_str("obj1"))
                                   .ToLocalChecked()
                                   .As<v8::Object>();
  i::DirectHandle<i::JSObject> js_obj1 =
      i::Cast<i::JSObject>(v8::Utils::OpenDirectHandle(*obj1));
  CHECK(!i::V8HeapExplorer::GetConstructor(i_isolate, *js_obj1).is_null());
  v8::Local<v8::Object> obj2 = js_global->Get(env.local(), v8_str("obj2"))
                                   .ToLocalChecked()
                                   .As<v8::Object>();
  i::DirectHandle<i::JSObject> js_obj2 =
      i::Cast<i::JSObject>(v8::Utils::OpenDirectHandle(*obj2));
  CHECK(!i::V8HeapExplorer::GetConstructor(i_isolate, *js_obj2).is_null());
  v8::Local<v8::Object> obj3 = js_global->Get(env.local(), v8_str("obj3"))
                                   .ToLocalChecked()
                                   .As<v8::Object>();
  i::DirectHandle<i::JSObject> js_obj3 =
      i::Cast<i::JSObject>(v8::Utils::OpenDirectHandle(*obj3));
  CHECK(!i::V8HeapExplorer::GetConstructor(i_isolate, *js_obj3).is_null());
  v8::Local<v8::Object> obj4 = js_global->Get(env.local(), v8_str("obj4"))
                                   .ToLocalChecked()
                                   .As<v8::Object>();
  i::DirectHandle<i::JSObject> js_obj4 =
      i::Cast<i::JSObject>(v8::Utils::OpenDirectHandle(*obj4));
  CHECK(!i::V8HeapExplorer::GetConstructor(i_isolate, *js_obj4).is_null());
  v8::Local<v8::Object> obj5 = js_global->Get(env.local(), v8_str("obj5"))
                                   .ToLocalChecked()
                                   .As<v8::Object>();
  i::DirectHandle<i::JSObject> js_obj5 =
      i::Cast<i::JSObject>(v8::Utils::OpenDirectHandle(*obj5));
  CHECK(i::V8HeapExplorer::GetConstructor(i_isolate, *js_obj5).is_null());
  v8::Local<v8::Object> obj6 = js_global->Get(env.local(), v8_str("obj6"))
                                   .ToLocalChecked()
                                   .As<v8::Object>();
  i::DirectHandle<i::JSObject> js_obj6 =
      i::Cast<i::JSObject>(v8::Utils::OpenDirectHandle(*obj6));
  CHECK(i::V8HeapExplorer::GetConstructor(i_isolate, *js_obj6).is_null());
}

TEST(GetConstructorName) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(env->GetIsolate());

  CompileRun(
      "function Constructor1() {};\n"
      "var obj1 = new Constructor1();\n"
      "var Constructor2 = function() {};\n"
      "var obj2 = new Constructor2();\n"
      "var obj3 = {};\n"
      "obj3.__proto__ = { constructor: function Constructor3() {} };\n"
      "var obj4 = {};\n"
      "// Slow properties\n"
      "for (var i=0; i<2000; ++i) obj4[\"p\" + i] = i;\n"
      "obj4.__proto__ = { constructor: function Constructor4() {} };\n"
      "var obj5 = {};\n"
      "var obj6 = {};\n"
      "obj6.constructor = 6;");
  v8::Local<v8::Object> js_global =
      env->Global()->GetPrototype().As<v8::Object>();
  v8::Local<v8::Object> obj1 = js_global->Get(env.local(), v8_str("obj1"))
                                   .ToLocalChecked()
                                   .As<v8::Object>();
  i::DirectHandle<i::JSObject> js_obj1 =
      i::Cast<i::JSObject>(v8::Utils::OpenDirectHandle(*obj1));
  CHECK_EQ(0, StringCmp("Constructor1", i::V8HeapExplorer::GetConstructorName(
                                            i_isolate, *js_obj1)));
  v8::Local<v8::Object> obj2 = js_global->Get(env.local(), v8_str("obj2"))
                                   .ToLocalChecked()
                                   .As<v8::Object>();
  i::DirectHandle<i::JSObject> js_obj2 =
      i::Cast<i::JSObject>(v8::Utils::OpenDirectHandle(*obj2));
  CHECK_EQ(0, StringCmp("Constructor2", i::V8HeapExplorer::GetConstructorName(
                                            i_isolate, *js_obj2)));
  v8::Local<v8::Object> obj3 = js_global->Get(env.local(), v8_str("obj3"))
                                   .ToLocalChecked()
                                   .As<v8::Object>();
  i::DirectHandle<i::JSObject> js_obj3 =
      i::Cast<i::JSObject>(v8::Utils::OpenDirectHandle(*obj3));
  CHECK_EQ(0, StringCmp("Constructor3", i::V8HeapExplorer::GetConstructorName(
                                            i_isolate, *js_obj3)));
  v8::Local<v8::Object> obj4 = js_global->Get(env.local(), v8_str("obj4"))
                                   .ToLocalChecked()
                                   .As<v8::Object>();
  i::DirectHandle<i::JSObject> js_obj4 =
      i::Cast<i::JSObject>(v8::Utils::OpenDirectHandle(*obj4));
  CHECK_EQ(0, StringCmp("Constructor4", i::V8HeapExplorer::GetConstructorName(
                                            i_isolate, *js_obj4)));
  v8::Local<v8::Object> obj5 = js_global->Get(env.local(), v8_str("obj5"))
                                   .ToLocalChecked()
                                   .As<v8::Object>();
  i::DirectHandle<i::JSObject> js_obj5 =
      i::Cast<i::JSObject>(v8::Utils::OpenDirectHandle(*obj5));
  CHECK_EQ(0, StringCmp("Object", i::V8HeapExplorer::GetConstructorName(
                                      i_isolate, *js_obj5)));
  v8::Local<v8::Object> obj6 = js_global->Get(env.local(), v8_str("obj6"))
                                   .ToLocalChecked()
                                   .As<v8::Object>();
  i::DirectHandle<i::JSObject> js_obj6 =
      i::Cast<i::JSObject>(v8::Utils::OpenDirectHandle(*obj6));
  CHECK_EQ(0, StringCmp("Object", i::V8HeapExplorer::GetConstructorName(
                                      i_isolate, *js_obj6)));
}

// Allow usages of v8::Object::GetPrototype() for now.
// TODO(https://crbug.com/333672197): remove.
END_ALLOW_USE_DEPRECATED()

TEST(FastCaseAccessors) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  CompileRun("var obj1 = {};\n"
             "obj1.__defineGetter__('propWithGetter', function Y() {\n"
             "  return 42;\n"
             "});\n"
             "obj1.__defineSetter__('propWithSetter', function Z(value) {\n"
             "  return this.value_ = value;\n"
             "});\n");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));

  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  CHECK(global);
  const v8::HeapGraphNode* obj1 = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "obj1");
  CHECK(obj1);
  const v8::HeapGraphNode* func;
  func = GetProperty(env->GetIsolate(), obj1, v8::HeapGraphEdge::kProperty,
                     "get propWithGetter");
  CHECK(func);
  func = GetProperty(env->GetIsolate(), obj1, v8::HeapGraphEdge::kProperty,
                     "set propWithGetter");
  CHECK(!func);
  func = GetProperty(env->GetIsolate(), obj1, v8::HeapGraphEdge::kProperty,
                     "set propWithSetter");
  CHECK(func);
  func = GetProperty(env->GetIsolate(), obj1, v8::HeapGraphEdge::kProperty,
                     "get propWithSetter");
  CHECK(!func);
}

// Allow usages of v8::Object::GetPrototype() for now.
// TODO(https://crbug.com/333672197): remove.
START_ALLOW_USE_DEPRECATED()

TEST(FastCaseRedefinedAccessors) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  CompileRun(
      "var obj1 = {};\n"
      "Object.defineProperty(obj1, 'prop', { "
      "  get: function() { return 42; },\n"
      "  set: function(value) { return this.prop_ = value; },\n"
      "  configurable: true,\n"
      "  enumerable: true,\n"
      "});\n"
      "Object.defineProperty(obj1, 'prop', { "
      "  get: function() { return 153; },\n"
      "  set: function(value) { return this.prop_ = value; },\n"
      "  configurable: true,\n"
      "  enumerable: true,\n"
      "});\n");
  v8::Local<v8::Object> js_global =
      env->Global()->GetPrototype().As<v8::Object>();
  i::Handle<i::JSReceiver> js_obj1 =
      v8::Utils::OpenHandle(*js_global->Get(env.local(), v8_str("obj1"))
                                 .ToLocalChecked()
                                 .As<v8::Object>());
  USE(js_obj1);

  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  CHECK(global);
  const v8::HeapGraphNode* obj1 = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "obj1");
  CHECK(obj1);
  const v8::HeapGraphNode* func;
  func = GetProperty(env->GetIsolate(), obj1, v8::HeapGraphEdge::kProperty,
                     "get prop");
  CHECK(func);
  func = GetProperty(env->GetIsolate(), obj1, v8::HeapGraphEdge::kProperty,
                     "set prop");
  CHECK(func);
}

// Allow usages of v8::Object::GetPrototype() for now.
// TODO(https://crbug.com/333672197): remove.
END_ALLOW_USE_DEPRECATED()

TEST(SlowCaseAccessors) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  CompileRun("var obj1 = {};\n"
             "for (var i = 0; i < 100; ++i) obj1['z' + i] = {};"
             "obj1.__defineGetter__('propWithGetter', function Y() {\n"
             "  return 42;\n"
             "});\n"
             "obj1.__defineSetter__('propWithSetter', function Z(value) {\n"
             "  return this.value_ = value;\n"
             "});\n");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));

  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  CHECK(global);
  const v8::HeapGraphNode* obj1 = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "obj1");
  CHECK(obj1);
  const v8::HeapGraphNode* func;
  func = GetProperty(env->GetIsolate(), obj1, v8::HeapGraphEdge::kProperty,
                     "get propWithGetter");
  CHECK(func);
  func = GetProperty(env->GetIsolate(), obj1, v8::HeapGraphEdge::kProperty,
                     "set propWithGetter");
  CHECK(!func);
  func = GetProperty(env->GetIsolate(), obj1, v8::HeapGraphEdge::kProperty,
                     "set propWithSetter");
  CHECK(func);
  func = GetProperty(env->GetIsolate(), obj1, v8::HeapGraphEdge::kProperty,
                     "get propWithSetter");
  CHECK(!func);
}


TEST(HiddenPropertiesFastCase) {
  v8::Isolate* isolate = CcTest::isolate();
  LocalContext env;
  v8::HandleScope scope(isolate);
  v8::HeapProfiler* heap_profiler = isolate->GetHeapProfiler();

  CompileRun(
      "function C(x) { this.a = this; this.b = x; }\n"
      "c = new C(2012);\n");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  const v8::HeapGraphNode* c =
      GetProperty(isolate, global, v8::HeapGraphEdge::kProperty, "c");
  CHECK(c);
  const v8::HeapGraphNode* hidden_props =
      GetProperty(isolate, c, v8::HeapGraphEdge::kProperty, "<symbol key>");
  CHECK(!hidden_props);

  v8::Local<v8::Value> cHandle =
      env->Global()->Get(env.local(), v8_str("c")).ToLocalChecked();
  CHECK(!cHandle.IsEmpty() && cHandle->IsObject());
  cHandle->ToObject(env.local())
      .ToLocalChecked()
      ->SetPrivate(env.local(),
                   v8::Private::ForApi(env->GetIsolate(), v8_str("key")),
                   v8_str("val"))
      .FromJust();

  snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  global = GetGlobalObject(snapshot);
  c = GetProperty(isolate, global, v8::HeapGraphEdge::kProperty, "c");
  CHECK(c);
  hidden_props =
      GetProperty(isolate, c, v8::HeapGraphEdge::kProperty, "<symbol key>");
  CHECK(hidden_props);
}

TEST(SymbolsAndPrivateClassFields) {
  v8::Isolate* isolate = CcTest::isolate();
  LocalContext env;
  v8::HandleScope scope(isolate);
  v8::HeapProfiler* heap_profiler = isolate->GetHeapProfiler();

  CompileRun(
      "class C { #private = this; [Symbol('MySymbol')] = this; };\n"
      "c = new C;\n");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  const v8::HeapGraphNode* c =
      GetProperty(isolate, global, v8::HeapGraphEdge::kProperty, "c");
  CHECK(c);
  const v8::HeapGraphNode* prop;
  prop = GetProperty(isolate, c, v8::HeapGraphEdge::kProperty, "#private");
  CHECK(prop);
  prop = GetProperty(isolate, c, v8::HeapGraphEdge::kProperty,
                     "<symbol MySymbol>");
  CHECK(prop);
}

TEST(AccessorInfo) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  CompileRun("function foo(x) { }\n");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  const v8::HeapGraphNode* foo = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "foo");
  CHECK(foo);
  const v8::HeapGraphNode* map =
      GetProperty(env->GetIsolate(), foo, v8::HeapGraphEdge::kInternal, "map");
  CHECK(map);
  const v8::HeapGraphNode* descriptors = GetProperty(
      env->GetIsolate(), map, v8::HeapGraphEdge::kInternal, "descriptors");
  CHECK(descriptors);
  const v8::HeapGraphNode* length_name = GetProperty(
      env->GetIsolate(), descriptors, v8::HeapGraphEdge::kInternal, "0");
  CHECK(length_name);
  CHECK_EQ(0, strcmp("length", *v8::String::Utf8Value(env->GetIsolate(),
                                                      length_name->GetName())));
  const v8::HeapGraphNode* length_accessor = GetProperty(
      env->GetIsolate(), descriptors, v8::HeapGraphEdge::kInternal, "2");
  CHECK(length_accessor);
  CHECK_EQ(0, strcmp("system / AccessorInfo",
                     *v8::String::Utf8Value(env->GetIsolate(),
                                            length_accessor->GetName())));
  const v8::HeapGraphNode* name = GetProperty(
      env->GetIsolate(), length_accessor, v8::HeapGraphEdge::kInternal, "name");
  CHECK(name);
}

TEST(JSGeneratorObject) {
  v8::Isolate* isolate = CcTest::isolate();
  LocalContext env;
  v8::HandleScope scope(isolate);
  v8::HeapProfiler* heap_profiler = isolate->GetHeapProfiler();

  CompileRun(
      "function* foo() { yield 1; }\n"
      "g = foo();\n");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  const v8::HeapGraphNode* g =
      GetProperty(isolate, global, v8::HeapGraphEdge::kProperty, "g");
  CHECK(g);
  const v8::HeapGraphNode* function = GetProperty(
      env->GetIsolate(), g, v8::HeapGraphEdge::kInternal, "function");
  CHECK(function);
  const v8::HeapGraphNode* context = GetProperty(
      env->GetIsolate(), g, v8::HeapGraphEdge::kInternal, "context");
  CHECK(context);
  const v8::HeapGraphNode* receiver = GetProperty(
      env->GetIsolate(), g, v8::HeapGraphEdge::kInternal, "receiver");
  CHECK(receiver);
  const v8::HeapGraphNode* parameters_and_registers =
      GetProperty(env->GetIsolate(), g, v8::HeapGraphEdge::kInternal,
                  "parameters_and_registers");
  CHECK(parameters_and_registers);
}

bool HasWeakEdge(const v8::HeapGraphNode* node) {
  for (int i = 0; i < node->GetChildrenCount(); ++i) {
    const v8::HeapGraphEdge* handle_edge = n
"""


```