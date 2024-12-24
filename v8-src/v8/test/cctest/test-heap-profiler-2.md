Response: The user wants a summary of the provided C++ code, which is the third part of a larger file related to heap profiling in V8. I need to identify the functionalities tested in this code snippet. The code seems to be testing various aspects of the V8 heap profiler, especially features related to:

1. **Embedder Graphs:**  Building and manipulating graphs that represent embedder-specific data within the heap snapshot.
2. **Sampling Heap Profiler:**  Taking allocation samples and generating allocation profiles. This includes testing different sampling rates, API allocations, and handling deoptimizations.
3. **Heap Snapshots:** Taking and validating heap snapshots, including scenarios with weak references and interactions with garbage collection.
4. **Querying Objects:**  Filtering objects in the heap based on specific criteria.
5. **Edge Cases and Bug Fixes:** Testing specific scenarios and bug fixes related to heap profiling, such as deleting snapshots during the snapshot process.
6. **WebAssembly Integration:** (Conditional) Testing heap snapshots in the presence of WebAssembly instances.

If any of these features relate to Javascript, I need to provide Javascript examples to illustrate the connection.
这是 `v8/test/cctest/test-heap-profiler.cc` 文件第三部分的总结，它主要测试了 V8 堆分析器的以下功能：

**1. 嵌入器图 (Embedder Graph) 的构建和测试:**

*   **添加命名边 (Named Edges):**  测试在嵌入器图中添加带有名称的边，以便在堆快照中更清晰地表示嵌入器对象的引用关系。
*   **使用上下文 (Context):**  测试在构建嵌入器图时使用上下文数据，允许根据不同的上下文状态添加不同的节点和边。
*   **多个回调 (Multiple Callbacks):**  测试注册多个嵌入器图构建回调函数，并确保它们都能按预期执行，以及可以移除这些回调。
*   **包装节点 (Wrapper Node):**  测试使用“包装节点”来组织和表示嵌入器图中的节点，这有助于更好地分组和理解嵌入器对象的结构。
*   **节点前缀 (Node Prefix):** 测试为嵌入器图中的节点设置名称前缀，以便在堆快照中更好地区分它们。

**2. `AddressToTraceMap` 功能测试:**

*   测试 `AddressToTraceMap` 数据结构的正确性，该结构用于将内存地址映射到跟踪节点 ID，这在堆分析中用于关联内存分配和调用栈信息。

**3. 采样堆分析器 (Sampling Heap Profiler) 的功能测试:**

*   **基本采样:** 测试启动和停止采样堆分析器，并获取生成的分配概要信息 (Allocation Profile)。
*   **查找分配概要节点:**  测试在分配概要信息中查找特定调用栈路径对应的节点。
*   **非零计数节点:**  验证分配概要信息中的节点至少有一个分配计数。
*   **采样率无关估计:** 测试不同采样率下，采样堆分析器提供的分配数量估计是否一致。
*   **API 分配采样:** 测试采样由 V8 API 引起的内存分配。
*   **API 采样:** 检查采样得到的样本数据是否包含正确的节点 ID 和样本 ID。
*   **左侧修剪 (Left Trimming):**  测试采样堆分析器在处理脚本卸载时的行为，避免崩溃。
*   **预分配内联分配 (Pretenured Inline Allocations):**  测试采样堆分析器是否能正确跟踪预分配的对象（分配在老生代）。
*   **大采样间隔 (Large Interval):** 测试使用较大采样间隔时的行为。
*   **去优化时采样 (Sample During Deopt):** 测试在代码去优化过程中进行采样是否会导致问题。

**4. 堆快照 (Heap Snapshot) 的功能测试:**

*   **原型非 JSReceiver:** 测试当对象的原型不是 JSReceiver 时，拍摄堆快照是否正常工作。
*   **强句柄注解 (Strong Handle Annotation):**  测试使用 `AnnotateStrongRetainer` API 为强句柄添加标签，并在堆快照中验证这些标签。
*   **弱引用 (Weak Reference):** 测试堆快照如何处理弱引用对象。
*   **在拍摄快照期间删除快照 (HeapSnapshotDeleteDuringTakeSnapshot):** 测试在拍摄一个堆快照时删除另一个堆快照是否会导致问题。
*   **对象保留在句柄中 (ObjectRetainedInHandle) 和直接句柄中 (ObjectRetainedInDirectHandle):** 测试当对象被 V8 句柄或直接句柄引用时，堆快照是否能正确地捕获它们。
*   **与 WebAssembly 的集成 (HeapSnapshotWithWasmInstance，条件编译):**  测试在存在 WebAssembly 实例的情况下拍摄堆快照，并验证 WebAssembly 相关对象的表示是否正确。

**5. 查询对象 (Query Objects) 的功能测试:**

*   测试使用 `QueryObjects` API 根据提供的谓词 (Predicate) 查询堆中的对象。

**6. Bug 修复测试:**

*   **Bug8373_1 和 Bug8373_2:** 针对特定 Bug 的回归测试，确保在删除堆快照后进行采样或对象跟踪不会导致崩溃。

**与 Javascript 的关系及示例:**

这些 C++ 测试直接关联到 V8 的 Javascript 运行时环境提供的堆分析功能。开发者可以使用 Javascript API 来触发堆快照和采样，以便分析内存使用情况和查找内存泄漏。

以下是一些与这些 C++ 测试相关的 Javascript 功能示例：

**a. 拍摄堆快照:**

```javascript
// 获取 HeapProfiler 对象
const heapProfiler = require('v8').getHeapSnapshot;

// 拍摄堆快照
const snapshot = heapProfiler();

// 可以将快照保存到文件
const fs = require('fs');
fs.writeFileSync('heap.json', JSON.stringify(snapshot));
```

这个 Javascript 例子对应了 C++ 代码中 `heap_profiler->TakeHeapSnapshot()` 的功能。

**b. 使用嵌入器图 (虽然 Javascript 中不能直接操作嵌入器图，但嵌入器可以通过 C++ API 添加信息到快照中):**

假设有一个 C++ 嵌入器，它创建了一些自定义的 C++ 对象，并希望在堆快照中看到这些对象以及它们与 Javascript 对象的关联。

**C++ 嵌入器代码 (简化示例):**

```c++
// ...
void BuildEmbedderGraph(v8::Isolate* isolate, v8::EmbedderGraph* graph, void* data) {
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  v8::Local<v8::Object> global = context->Global();

  // 假设我们有一个自定义的 C++ 对象 myEmbedderObject
  MyEmbedderObject* myEmbedderObject = static_cast<MyEmbedderObject*>(data);

  // 在嵌入器图中添加一个节点来表示 myEmbedderObject
  v8::EmbedderGraph::Node* embedder_node = graph->AddNode(
      std::unique_ptr<v8::EmbedderGraph::Node>(
          new EmbedderNode("MyEmbedderObject", sizeof(MyEmbedderObject))));

  // 将嵌入器节点连接到 Javascript 全局对象
  graph->AddEdge(graph->V8Node(global), embedder_node);
}

// ... 在初始化 V8 时
v8::Isolate::CreateParams create_params;
create_params.array_buffer_allocator = ...;
v8::Isolate* isolate = v8::Isolate::New(create_params);
{
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::Context> context = v8::Context::New(isolate);
  v8::Context::Scope context_scope(context);

  v8::HeapProfiler* heap_profiler = isolate->GetHeapProfiler();
  MyEmbedderObject myObject;
  heap_profiler->AddBuildEmbedderGraphCallback(BuildEmbedderGraph, &myObject);

  // ... 运行 Javascript 代码 ...
}
v8::Isolate::Dispose();
```

**Javascript 代码:**

```javascript
// Javascript 代码，可能会创建一些对象
const obj = { a: 1 };
```

当拍摄堆快照时，通过 C++ 嵌入器添加的 `MyEmbedderObject` 节点也会出现在快照中，可以分析它与 `obj` 的关系（如果存在）。

**c. 采样堆分析器:**

```javascript
const heapProfiler = require('v8').heapProfiler;

// 开始采样，每 1024 字节采样一次
heapProfiler.startSamplingHeapProfiler(1024);

// 执行一些会分配内存的代码
const arr = [];
for (let i = 0; i < 1000; i++) {
  arr.push(new Array(100));
}

// 获取分配概要信息
const profile = heapProfiler.getAllocationProfile();
console.log(JSON.stringify(profile));

// 停止采样
heapProfiler.stopSamplingHeapProfiler();
```

这个 Javascript 例子对应了 C++ 代码中 `heap_profiler->StartSamplingHeapProfiler()` 和 `heap_profiler->GetAllocationProfile()` 以及 `heap_profiler->StopSamplingHeapProfiler()` 的功能。

**d. 查询对象:**

```javascript
const v8 = require('v8');

globalThis.mySymbol = Symbol('query_object_test');
globalThis.trackedObjects = [];
for (let i = 0; i < 5; i++) {
  globalThis.trackedObjects.push({ [mySymbol]: true, id: i });
}
globalThis.otherObjects = [{}, {}];

const heapProfiler = v8.getHeapProfiler();

const matchingObjects = heapProfiler.getHeapSnapshot().nodes
  .filter(node => node.type === 'object')
  .filter(node => {
    return node.edges.some(edge => {
      return edge.name === 'mySymbol';
    });
  });

console.log(matchingObjects.length); // 输出可能为 5，取决于快照的具体内容和实现细节
```

虽然 Javascript API 没有直接的 `QueryObjects` 对应项，但可以通过分析堆快照的 JSON 数据来达到类似的目的。 C++ 中的 `QueryObjects` API 提供了更直接和高效的方式来过滤特定对象。

总而言之，这个 C++ 测试文件深入测试了 V8 引擎中用于进行堆分析的各种底层机制，这些机制最终为开发者提供了通过 Javascript API 分析内存使用的能力。

Prompt: 
```
这是目录为v8/test/cctest/test-heap-profiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
embedder_node_B, "EmbedderNodeC");
  CHECK(b_to_c);
  CHECK(b_to_c->GetName()->IsNumber());
  CHECK_EQ(v8::HeapGraphEdge::kElement, b_to_c->GetType());
  const v8::HeapGraphNode* embedder_node_C = b_to_c->GetToNode();
  CHECK_EQ(0, strcmp("EmbedderNodeC", GetName(embedder_node_C)));
  CHECK_EQ(30, GetSize(embedder_node_C));
}

TEST(EmbedderGraphWithNamedEdges) {
  i::v8_flags.heap_profiler_use_embedder_graph = true;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(env->GetIsolate());
  v8::Local<v8::Value> global_object =
      v8::Utils::ToLocal(i::Handle<i::JSObject>(
          (isolate->context()->native_context()->global_object()), isolate));
  global_object_pointer = &global_object;
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  heap_profiler->AddBuildEmbedderGraphCallback(BuildEmbedderGraphWithNamedEdges,
                                               nullptr);
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  CheckEmbedderGraphWithNamedEdges(env->GetIsolate(), snapshot);
}

struct GraphBuildingContext {
  int counter = 0;
};

void CheckEmbedderGraphSnapshotWithContext(
    v8::Isolate* isolate, const v8::HeapSnapshot* snapshot,
    const GraphBuildingContext* context) {
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  CHECK_GE(context->counter, 1);
  CHECK_LE(context->counter, 2);

  const v8::HeapGraphNode* embedder_node_A =
      GetChildByName(global, "EmbedderNodeA");
  CHECK_EQ(10, GetSize(embedder_node_A));

  const v8::HeapGraphNode* embedder_node_B =
      GetChildByName(global, "EmbedderNodeB");
  if (context->counter == 2) {
    CHECK_NOT_NULL(embedder_node_B);
    CHECK_EQ(20, GetSize(embedder_node_B));
  } else {
    CHECK_NULL(embedder_node_B);
  }
}

void BuildEmbedderGraphWithContext(v8::Isolate* v8_isolate,
                                   v8::EmbedderGraph* graph, void* data) {
  using Node = v8::EmbedderGraph::Node;
  GraphBuildingContext* context = static_cast<GraphBuildingContext*>(data);
  Node* global_node = graph->V8Node(*global_object_pointer);

  CHECK_GE(context->counter, 0);
  CHECK_LE(context->counter, 1);
  switch (context->counter++) {
    case 0: {
      Node* embedder_node_A = graph->AddNode(
          std::unique_ptr<Node>(new EmbedderNode("EmbedderNodeA", 10)));
      graph->AddEdge(global_node, embedder_node_A);
      break;
    }
    case 1: {
      Node* embedder_node_B = graph->AddNode(
          std::unique_ptr<Node>(new EmbedderNode("EmbedderNodeB", 20)));
      graph->AddEdge(global_node, embedder_node_B);
      break;
    }
  }
}

TEST(EmbedderGraphMultipleCallbacks) {
  i::v8_flags.heap_profiler_use_embedder_graph = true;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(env->GetIsolate());
  v8::Local<v8::Value> global_object =
      v8::Utils::ToLocal(i::Handle<i::JSObject>(
          (isolate->context()->native_context()->global_object()), isolate));
  global_object_pointer = &global_object;
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  GraphBuildingContext context;

  heap_profiler->AddBuildEmbedderGraphCallback(BuildEmbedderGraphWithContext,
                                               &context);
  heap_profiler->AddBuildEmbedderGraphCallback(BuildEmbedderGraphWithContext,
                                               &context);
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK_EQ(context.counter, 2);
  CHECK(ValidateSnapshot(snapshot));
  CheckEmbedderGraphSnapshotWithContext(env->GetIsolate(), snapshot, &context);

  heap_profiler->RemoveBuildEmbedderGraphCallback(BuildEmbedderGraphWithContext,
                                                  &context);
  context.counter = 0;

  snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK_EQ(context.counter, 1);
  CHECK(ValidateSnapshot(snapshot));
  CheckEmbedderGraphSnapshotWithContext(env->GetIsolate(), snapshot, &context);
}

TEST(StrongHandleAnnotation) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Persistent<v8::Object> handle1, handle2;
  handle1.Reset(env->GetIsolate(), v8::Object::New(env->GetIsolate()));
  handle2.Reset(env->GetIsolate(), v8::Object::New(env->GetIsolate()));
  handle1.AnnotateStrongRetainer("my_label");
  handle2.AnnotateStrongRetainer("my_label");
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  const v8::HeapGraphNode* gc_roots = GetRootChild(snapshot, "(GC roots)");
  CHECK(gc_roots);
  const v8::HeapGraphNode* global_handles =
      GetChildByName(gc_roots, "(Global handles)");
  CHECK(global_handles);
  int found = 0;
  for (int i = 0, count = global_handles->GetChildrenCount(); i < count; ++i) {
    const v8::HeapGraphEdge* edge = global_handles->GetChild(i);
    v8::String::Utf8Value edge_name(CcTest::isolate(), edge->GetName());
    if (EndsWith(*edge_name, "my_label")) ++found;
  }
  CHECK_EQ(2, found);
}

void BuildEmbedderGraphWithWrapperNode(v8::Isolate* v8_isolate,
                                       v8::EmbedderGraph* graph, void* data) {
  using Node = v8::EmbedderGraph::Node;
  Node* global_node = graph->V8Node(*global_object_pointer);
  Node* wrapper_node = graph->AddNode(
      std::unique_ptr<Node>(new EmbedderNode("WrapperNode / TAG", 10)));
  Node* embedder_node = graph->AddNode(std::unique_ptr<Node>(
      new EmbedderNode("EmbedderNode", 10, wrapper_node)));
  Node* other_node =
      graph->AddNode(std::unique_ptr<Node>(new EmbedderNode("OtherNode", 20)));
  graph->AddEdge(global_node, embedder_node);
  graph->AddEdge(wrapper_node, other_node);

  Node* wrapper_node2 = graph->AddNode(
      std::unique_ptr<Node>(new EmbedderNode("WrapperNode2", 10)));
  Node* embedder_node2 = graph->AddNode(std::unique_ptr<Node>(
      new EmbedderNode("EmbedderNode2", 10, wrapper_node2)));
  graph->AddEdge(global_node, embedder_node2);
  graph->AddEdge(embedder_node2, wrapper_node2);
  graph->AddEdge(wrapper_node2, other_node);
}

TEST(EmbedderGraphWithWrapperNode) {
  i::v8_flags.heap_profiler_use_embedder_graph = true;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(env->GetIsolate());
  v8::Local<v8::Value> global_object =
      v8::Utils::ToLocal(i::Handle<i::JSObject>(
          (isolate->context()->native_context()->global_object()), isolate));
  global_object_pointer = &global_object;
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  heap_profiler->AddBuildEmbedderGraphCallback(
      BuildEmbedderGraphWithWrapperNode, nullptr);
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  const v8::HeapGraphNode* embedder_node =
      GetChildByName(global, "EmbedderNode / TAG");
  const v8::HeapGraphNode* other_node =
      GetChildByName(embedder_node, "OtherNode");
  CHECK(other_node);
  const v8::HeapGraphNode* wrapper_node =
      GetChildByName(embedder_node, "WrapperNode / TAG");
  CHECK(!wrapper_node);

  const v8::HeapGraphNode* embedder_node2 =
      GetChildByName(global, "EmbedderNode2");
  other_node = GetChildByName(embedder_node2, "OtherNode");
  CHECK(other_node);
  const v8::HeapGraphNode* wrapper_node2 =
      GetChildByName(embedder_node, "WrapperNode2");
  CHECK(!wrapper_node2);
}

class EmbedderNodeWithPrefix : public v8::EmbedderGraph::Node {
 public:
  EmbedderNodeWithPrefix(const char* prefix, const char* name)
      : prefix_(prefix), name_(name) {}

  // Graph::Node overrides.
  const char* Name() override { return name_; }
  size_t SizeInBytes() override { return 0; }
  const char* NamePrefix() override { return prefix_; }

 private:
  const char* prefix_;
  const char* name_;
};

void BuildEmbedderGraphWithPrefix(v8::Isolate* v8_isolate,
                                  v8::EmbedderGraph* graph, void* data) {
  using Node = v8::EmbedderGraph::Node;
  Node* global_node = graph->V8Node(*global_object_pointer);
  Node* node = graph->AddNode(
      std::unique_ptr<Node>(new EmbedderNodeWithPrefix("Detached", "Node")));
  graph->AddEdge(global_node, node);
}

TEST(EmbedderGraphWithPrefix) {
  i::v8_flags.heap_profiler_use_embedder_graph = true;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(env->GetIsolate());
  v8::Local<v8::Value> global_object =
      v8::Utils::ToLocal(i::Handle<i::JSObject>(
          (isolate->context()->native_context()->global_object()), isolate));
  global_object_pointer = &global_object;
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  heap_profiler->AddBuildEmbedderGraphCallback(BuildEmbedderGraphWithPrefix,
                                               nullptr);
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  const v8::HeapGraphNode* node = GetChildByName(global, "Detached Node");
  CHECK(node);
}

static inline i::Address ToAddress(int n) { return static_cast<i::Address>(n); }

TEST(AddressToTraceMap) {
  i::AddressToTraceMap map;

  CHECK_EQ(0u, map.GetTraceNodeId(ToAddress(150)));

  // [0x100, 0x200) -> 1
  map.AddRange(ToAddress(0x100), 0x100, 1U);
  CHECK_EQ(0u, map.GetTraceNodeId(ToAddress(0x50)));
  CHECK_EQ(1u, map.GetTraceNodeId(ToAddress(0x100)));
  CHECK_EQ(1u, map.GetTraceNodeId(ToAddress(0x150)));
  CHECK_EQ(0u, map.GetTraceNodeId(ToAddress(0x100 + 0x100)));
  CHECK_EQ(1u, map.size());

  // [0x100, 0x200) -> 1, [0x200, 0x300) -> 2
  map.AddRange(ToAddress(0x200), 0x100, 2U);
  CHECK_EQ(2u, map.GetTraceNodeId(ToAddress(0x2A0)));
  CHECK_EQ(2u, map.size());

  // [0x100, 0x180) -> 1, [0x180, 0x280) -> 3, [0x280, 0x300) -> 2
  map.AddRange(ToAddress(0x180), 0x100, 3U);
  CHECK_EQ(1u, map.GetTraceNodeId(ToAddress(0x17F)));
  CHECK_EQ(2u, map.GetTraceNodeId(ToAddress(0x280)));
  CHECK_EQ(3u, map.GetTraceNodeId(ToAddress(0x180)));
  CHECK_EQ(3u, map.size());

  // [0x100, 0x180) -> 1, [0x180, 0x280) -> 3, [0x280, 0x300) -> 2,
  // [0x400, 0x500) -> 4
  map.AddRange(ToAddress(0x400), 0x100, 4U);
  CHECK_EQ(1u, map.GetTraceNodeId(ToAddress(0x17F)));
  CHECK_EQ(2u, map.GetTraceNodeId(ToAddress(0x280)));
  CHECK_EQ(3u, map.GetTraceNodeId(ToAddress(0x180)));
  CHECK_EQ(4u, map.GetTraceNodeId(ToAddress(0x450)));
  CHECK_EQ(0u, map.GetTraceNodeId(ToAddress(0x500)));
  CHECK_EQ(0u, map.GetTraceNodeId(ToAddress(0x350)));
  CHECK_EQ(4u, map.size());

  // [0x100, 0x180) -> 1, [0x180, 0x200) -> 3, [0x200, 0x600) -> 5
  map.AddRange(ToAddress(0x200), 0x400, 5U);
  CHECK_EQ(5u, map.GetTraceNodeId(ToAddress(0x200)));
  CHECK_EQ(5u, map.GetTraceNodeId(ToAddress(0x400)));
  CHECK_EQ(3u, map.size());

  // [0x100, 0x180) -> 1, [0x180, 0x200) -> 7, [0x200, 0x600) ->5
  map.AddRange(ToAddress(0x180), 0x80, 6U);
  map.AddRange(ToAddress(0x180), 0x80, 7U);
  CHECK_EQ(7u, map.GetTraceNodeId(ToAddress(0x180)));
  CHECK_EQ(5u, map.GetTraceNodeId(ToAddress(0x200)));
  CHECK_EQ(3u, map.size());

  map.Clear();
  CHECK_EQ(0u, map.size());
  CHECK_EQ(0u, map.GetTraceNodeId(ToAddress(0x400)));
}

static const v8::AllocationProfile::Node* FindAllocationProfileNode(
    v8::Isolate* isolate, v8::AllocationProfile* profile,
    v8::base::Vector<const char*> names) {
  v8::AllocationProfile::Node* node = profile->GetRootNode();
  for (int i = 0; node != nullptr && i < names.length(); ++i) {
    const char* name = names[i];
    auto children = node->children;
    node = nullptr;
    for (v8::AllocationProfile::Node* child : children) {
      v8::String::Utf8Value child_name(isolate, child->name);
      if (strcmp(*child_name, name) == 0) {
        node = child;
        break;
      }
    }
  }
  return node;
}

static void CheckNoZeroCountNodes(v8::AllocationProfile::Node* node) {
  for (auto alloc : node->allocations) {
    CHECK_GT(alloc.count, 0u);
  }
  for (auto child : node->children) {
    CheckNoZeroCountNodes(child);
  }
}

static int NumberOfAllocations(const v8::AllocationProfile::Node* node) {
  int count = 0;
  for (auto allocation : node->allocations) {
    count += allocation.count;
  }
  return count;
}

static const char* simple_sampling_heap_profiler_script =
    "var A = [];\n"
    "function bar(size) { return new Array(size); }\n"
    "%NeverOptimizeFunction(bar);\n"
    "var foo = function() {\n"
    "  for (var i = 0; i < 2048; ++i) {\n"
    "    A[i] = bar(1024);\n"
    "  }\n"
    "}\n"
    "foo();";

TEST(SamplingHeapProfiler) {
  i::v8_flags.allow_natives_syntax = true;
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  // Turn off always_turbofan. Inlining can cause stack traces to be shorter
  // than what we expect in this test.
  i::v8_flags.always_turbofan = false;

  // Suppress randomness to avoid flakiness in tests.
  i::v8_flags.sampling_heap_profiler_suppress_randomness = true;

  // Sample should be empty if requested before sampling has started.
  {
    v8::AllocationProfile* profile = heap_profiler->GetAllocationProfile();
    CHECK_NULL(profile);
  }

  {
    heap_profiler->StartSamplingHeapProfiler(1024);
    CompileRun(simple_sampling_heap_profiler_script);

    std::unique_ptr<v8::AllocationProfile> profile(
        heap_profiler->GetAllocationProfile());
    CHECK(profile);

    const char* names[] = {"", "foo", "bar"};
    auto node_bar = FindAllocationProfileNode(env->GetIsolate(), profile.get(),
                                              v8::base::ArrayVector(names));
    CHECK(node_bar);

    heap_profiler->StopSamplingHeapProfiler();
  }

  // Samples should get cleared once sampling is stopped.
  {
    v8::AllocationProfile* profile = heap_profiler->GetAllocationProfile();
    CHECK_NULL(profile);
  }

  // A more complicated test cases with deeper call graph and dynamically
  // generated function names.
  {
    heap_profiler->StartSamplingHeapProfiler(64);
    CompileRun(record_trace_tree_source);

    std::unique_ptr<v8::AllocationProfile> profile(
        heap_profiler->GetAllocationProfile());
    CHECK(profile);

    const char* names1[] = {"", "start", "f_0_0", "f_0_1", "f_0_2"};
    auto node1 = FindAllocationProfileNode(env->GetIsolate(), profile.get(),
                                           v8::base::ArrayVector(names1));
    CHECK(node1);

    const char* names2[] = {"", "generateFunctions"};
    auto node2 = FindAllocationProfileNode(env->GetIsolate(), profile.get(),
                                           v8::base::ArrayVector(names2));
    CHECK(node2);

    heap_profiler->StopSamplingHeapProfiler();
  }

  // A test case with scripts unloaded before profile gathered
  {
    heap_profiler->StartSamplingHeapProfiler(64);
    CompileRun(
        "for (var i = 0; i < 1024; i++) {\n"
        "  eval(\"new Array(100)\");\n"
        "}\n");

    i::heap::InvokeMajorGC(CcTest::heap());

    std::unique_ptr<v8::AllocationProfile> profile(
        heap_profiler->GetAllocationProfile());
    CHECK(profile);

    CheckNoZeroCountNodes(profile->GetRootNode());

    heap_profiler->StopSamplingHeapProfiler();
  }
}

TEST(SamplingHeapProfilerRateAgnosticEstimates) {
  i::v8_flags.allow_natives_syntax = true;
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  // Turn off always_turbofan. Inlining can cause stack traces to be shorter
  // than what we expect in this test.
  i::v8_flags.always_turbofan = false;

  // Disable compilation cache to force compilation in both cases
  i::v8_flags.compilation_cache = false;

  // Suppress randomness to avoid flakiness in tests.
  i::v8_flags.sampling_heap_profiler_suppress_randomness = true;

  // stress_incremental_marking adds randomness to the test.
  i::v8_flags.stress_incremental_marking = false;

  // warmup compilation
  CompileRun(simple_sampling_heap_profiler_script);

  int count_1024 = 0;
  {
    heap_profiler->StartSamplingHeapProfiler(1024);
    CompileRun(simple_sampling_heap_profiler_script);

    std::unique_ptr<v8::AllocationProfile> profile(
        heap_profiler->GetAllocationProfile());
    CHECK(profile);

    const char* path_to_foo[] = {"", "foo"};
    auto node_foo = FindAllocationProfileNode(
        env->GetIsolate(), profile.get(), v8::base::ArrayVector(path_to_foo));
    CHECK(node_foo);
    const char* path_to_bar[] = {"", "foo", "bar"};
    auto node_bar = FindAllocationProfileNode(
        env->GetIsolate(), profile.get(), v8::base::ArrayVector(path_to_bar));
    CHECK(node_bar);

    // Function bar can be inlined in foo.
    count_1024 = NumberOfAllocations(node_foo) + NumberOfAllocations(node_bar);

    heap_profiler->StopSamplingHeapProfiler();
  }

  // Sampling at a higher rate should give us similar numbers of objects.
  {
    heap_profiler->StartSamplingHeapProfiler(128);
    CompileRun(simple_sampling_heap_profiler_script);

    std::unique_ptr<v8::AllocationProfile> profile(
        heap_profiler->GetAllocationProfile());
    CHECK(profile);

    const char* path_to_foo[] = {"", "foo"};
    auto node_foo = FindAllocationProfileNode(
        env->GetIsolate(), profile.get(), v8::base::ArrayVector(path_to_foo));
    CHECK(node_foo);
    const char* path_to_bar[] = {"", "foo", "bar"};
    auto node_bar = FindAllocationProfileNode(
        env->GetIsolate(), profile.get(), v8::base::ArrayVector(path_to_bar));
    CHECK(node_bar);

    // Function bar can be inlined in foo.
    int count_128 =
        NumberOfAllocations(node_foo) + NumberOfAllocations(node_bar);

    // We should have similar unsampled counts of allocations. Though
    // we will sample different numbers of objects at different rates,
    // the unsampling process should produce similar final estimates
    // at the true number of allocations. However, the process to
    // determine these unsampled counts is probabilisitic so we need to
    // account for error.
    double max_count = std::max(count_128, count_1024);
    double min_count = std::min(count_128, count_1024);
    double percent_difference = (max_count - min_count) / min_count;
    CHECK_LT(percent_difference, 0.1);

    heap_profiler->StopSamplingHeapProfiler();
  }
}

TEST(SamplingHeapProfilerApiAllocation) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  // Suppress randomness to avoid flakiness in tests.
  i::v8_flags.sampling_heap_profiler_suppress_randomness = true;

  heap_profiler->StartSamplingHeapProfiler(256);

  for (int i = 0; i < 8 * 1024; ++i) v8::Object::New(env->GetIsolate());

  std::unique_ptr<v8::AllocationProfile> profile(
      heap_profiler->GetAllocationProfile());
  CHECK(profile);
  const char* names[] = {"(V8 API)"};
  auto node = FindAllocationProfileNode(env->GetIsolate(), profile.get(),
                                        v8::base::ArrayVector(names));
  CHECK(node);

  heap_profiler->StopSamplingHeapProfiler();
}

TEST(SamplingHeapProfilerApiSamples) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  // Suppress randomness to avoid flakiness in tests.
  i::v8_flags.sampling_heap_profiler_suppress_randomness = true;

  heap_profiler->StartSamplingHeapProfiler(1024);

  size_t count = 8 * 1024;
  for (size_t i = 0; i < count; ++i) v8::Object::New(env->GetIsolate());

  std::unique_ptr<v8::AllocationProfile> profile(
      heap_profiler->GetAllocationProfile());
  CHECK(profile);

  std::vector<v8::AllocationProfile::Node*> nodes_to_visit;
  std::unordered_set<uint32_t> node_ids;
  nodes_to_visit.push_back(profile->GetRootNode());
  while (!nodes_to_visit.empty()) {
    v8::AllocationProfile::Node* node = nodes_to_visit.back();
    nodes_to_visit.pop_back();
    CHECK_LT(0, node->node_id);
    CHECK_EQ(0, node_ids.count(node->node_id));
    node_ids.insert(node->node_id);
    nodes_to_visit.insert(nodes_to_visit.end(), node->children.begin(),
                          node->children.end());
  }

  size_t total_size = 0;
  std::unordered_set<uint64_t> samples_set;
  for (auto& sample : profile->GetSamples()) {
    total_size += sample.size * sample.count;
    CHECK_EQ(0, samples_set.count(sample.sample_id));
    CHECK_EQ(1, node_ids.count(sample.node_id));
    CHECK_GT(sample.node_id, 0);
    CHECK_GT(sample.sample_id, 0);
    samples_set.insert(sample.sample_id);
  }
  size_t object_size = total_size / count;
  CHECK_GE(object_size, sizeof(void*) * 2);
  heap_profiler->StopSamplingHeapProfiler();
}

TEST(SamplingHeapProfilerLeftTrimming) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  // Suppress randomness to avoid flakiness in tests.
  i::v8_flags.sampling_heap_profiler_suppress_randomness = true;

  heap_profiler->StartSamplingHeapProfiler(64);

  CompileRun(
      "for (var j = 0; j < 500; ++j) {\n"
      "  var a = [];\n"
      "  for (var i = 0; i < 5; ++i)\n"
      "      a[i] = i;\n"
      "  for (var i = 0; i < 3; ++i)\n"
      "      a.shift();\n"
      "}\n");

  i::heap::InvokeMinorGC(CcTest::heap());
  // Should not crash.

  heap_profiler->StopSamplingHeapProfiler();
}

TEST(SamplingHeapProfilerPretenuredInlineAllocations) {
  i::v8_flags.allow_natives_syntax = true;
  i::v8_flags.expose_gc = true;

  CcTest::InitializeVM();
  if (!CcTest::i_isolate()->use_optimizer() || i::v8_flags.always_turbofan)
    return;
  if (i::v8_flags.gc_global || i::v8_flags.stress_compaction ||
      i::v8_flags.stress_incremental_marking ||
      i::v8_flags.stress_concurrent_allocation ||
      i::v8_flags.single_generation) {
    return;
  }

  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  // Suppress randomness to avoid flakiness in tests.
  i::v8_flags.sampling_heap_profiler_suppress_randomness = true;

  // Disable loop unrolling to have a more predictable number of allocations
  // (loop unrolling could cause allocation folding).
  i::v8_flags.turboshaft_loop_unrolling = false;

  GrowNewSpaceToMaximumCapacity(CcTest::heap());

  v8::base::ScopedVector<char> source(1024);
  v8::base::SNPrintF(source,
                     "var number_elements = %d;"
                     "var elements = new Array(number_elements);"
                     "function f() {"
                     "  for (var i = 0; i < number_elements; i++) {"
                     "    elements[i] = [{}, {}, {}];"
                     "  }"
                     "  return elements[number_elements - 1];"
                     "};"
                     "%%PrepareFunctionForOptimization(f);"
                     "f(); gc();"
                     "f(); f();"
                     "%%OptimizeFunctionOnNextCall(f);"
                     "f();"
                     "f;",
                     i::PretenuringHandler::GetMinMementoCountForTesting() + 1);

  v8::Local<v8::Function> f =
      v8::Local<v8::Function>::Cast(CompileRun(source.begin()));

  // Make sure the function is producing pre-tenured objects.
  auto res = f->Call(env.local(), env->Global(), 0, nullptr).ToLocalChecked();
  i::DirectHandle<i::JSObject> o = i::Cast<i::JSObject>(
      v8::Utils::OpenDirectHandle(*v8::Local<v8::Object>::Cast(res)));
  CHECK(CcTest::heap()->InOldSpace(o->elements()));
  CHECK(CcTest::heap()->InOldSpace(*o));

  // Call the function and profile it.
  heap_profiler->StartSamplingHeapProfiler(64);
  for (int i = 0; i < 80; ++i) {
    f->Call(env.local(), env->Global(), 0, nullptr).ToLocalChecked();
  }

  std::unique_ptr<v8::AllocationProfile> profile(
      heap_profiler->GetAllocationProfile());
  CHECK(profile);
  heap_profiler->StopSamplingHeapProfiler();

  const char* names[] = {"f"};
  auto node_f = FindAllocationProfileNode(env->GetIsolate(), profile.get(),
                                          v8::base::ArrayVector(names));
  CHECK(node_f);

  int count = 0;
  for (auto allocation : node_f->allocations) {
    count += allocation.count;
  }

  CHECK_GE(count, 8000);
}

TEST(SamplingHeapProfilerLargeInterval) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  // Suppress randomness to avoid flakiness in tests.
  i::v8_flags.sampling_heap_profiler_suppress_randomness = true;

  heap_profiler->StartSamplingHeapProfiler(512 * 1024);

  for (int i = 0; i < 8 * 1024; ++i) {
    CcTest::i_isolate()->factory()->NewFixedArray(1024);
  }

  std::unique_ptr<v8::AllocationProfile> profile(
      heap_profiler->GetAllocationProfile());
  CHECK(profile);
  const char* names[] = {"(EXTERNAL)"};
  auto node = FindAllocationProfileNode(env->GetIsolate(), profile.get(),
                                        v8::base::ArrayVector(names));
  CHECK(node);

  heap_profiler->StopSamplingHeapProfiler();
}

TEST(HeapSnapshotPrototypeNotJSReceiver) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  CompileRun(
      "function object() {}"
      "object.prototype = 42;");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
}

TEST(SamplingHeapProfilerSampleDuringDeopt) {
  i::v8_flags.allow_natives_syntax = true;

  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  // Suppress randomness to avoid flakiness in tests.
  i::v8_flags.sampling_heap_profiler_suppress_randomness = true;

  // Small sample interval to force each object to be sampled.
  heap_profiler->StartSamplingHeapProfiler(i::kTaggedSize);

  // Lazy deopt from runtime call from inlined callback function.
  const char* source =
      "var b = "
      "  [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25];"
      "(function f() {"
      "  var result = 0;"
      "  var lazyDeopt = function(deopt) {"
      "    var callback = function(v,i,o) {"
      "      result += i;"
      "      if (i == 13 && deopt) {"
      "          %DeoptimizeNow();"
      "      }"
      "      return v;"
      "    };"
      "    b.map(callback);"
      "  };"
      "  %PrepareFunctionForOptimization(lazyDeopt);"
      "  lazyDeopt();"
      "  lazyDeopt();"
      "  %OptimizeFunctionOnNextCall(lazyDeopt);"
      "  lazyDeopt();"
      "  lazyDeopt(true);"
      "  lazyDeopt();"
      "})();";

  CompileRun(source);
  // Should not crash.

  std::unique_ptr<v8::AllocationProfile> profile(
      heap_profiler->GetAllocationProfile());
  CHECK(profile);
  heap_profiler->StopSamplingHeapProfiler();
}

namespace {
class TestQueryObjectPredicate : public v8::QueryObjectPredicate {
 public:
  TestQueryObjectPredicate(v8::Local<v8::Context> context,
                           v8::Local<v8::Symbol> symbol)
      : context_(context), symbol_(symbol) {}

  bool Filter(v8::Local<v8::Object> object) override {
    return object->HasOwnProperty(context_, symbol_).FromMaybe(false);
  }

 private:
  v8::Local<v8::Context> context_;
  v8::Local<v8::Symbol> symbol_;
};

class IncludeAllQueryObjectPredicate : public v8::QueryObjectPredicate {
 public:
  IncludeAllQueryObjectPredicate() {}
  bool Filter(v8::Local<v8::Object> object) override { return true; }
};
}  // anonymous namespace

TEST(QueryObjects) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> context = env.local();

  v8::Local<v8::Symbol> sym =
      v8::Symbol::New(isolate, v8_str("query_object_test"));
  context->Global()->Set(context, v8_str("test_symbol"), sym).Check();
  v8::Local<v8::Value> arr = CompileRun(R"(
      const arr = [];
      for (let i = 0; i < 10; ++i) {
        arr.push({[test_symbol]: true});
      }
      arr;
    )");
  context->Global()->Set(context, v8_str("arr"), arr).Check();
  v8::HeapProfiler* heap_profiler = isolate->GetHeapProfiler();

  {
    TestQueryObjectPredicate predicate(context, sym);
    std::vector<v8::Global<v8::Object>> out;
    heap_profiler->QueryObjects(context, &predicate, &out);

    CHECK_EQ(out.size(), 10);
    for (size_t i = 0; i < out.size(); ++i) {
      CHECK(out[i].Get(isolate)->HasOwnProperty(context, sym).FromMaybe(false));
    }
  }

  {
    IncludeAllQueryObjectPredicate predicate;
    std::vector<v8::Global<v8::Object>> out;
    heap_profiler->QueryObjects(context, &predicate, &out);
    CHECK_GE(out.size(), 10);
  }
}

TEST(WeakReference) {
  v8::Isolate* isolate = CcTest::isolate();
  i::Isolate* i_isolate = CcTest::i_isolate();
  i::Factory* factory = i_isolate->factory();
  i::HandleScope scope(i_isolate);
  LocalContext env;

  // Create a FeedbackVector.
  v8::Local<v8::Script> script =
      v8::Script::Compile(
          isolate->GetCurrentContext(),
          v8::String::NewFromUtf8Literal(isolate, "function foo() {}"))
          .ToLocalChecked();
  v8::MaybeLocal<v8::Value> value = script->Run(isolate->GetCurrentContext());
  CHECK(!value.IsEmpty());

  i::DirectHandle<i::Object> obj = v8::Utils::OpenDirectHandle(*script);
  i::DirectHandle<i::SharedFunctionInfo> shared_function(
      i::Cast<i::JSFunction>(*obj)->shared(), i_isolate);
  i::DirectHandle<i::ClosureFeedbackCellArray> feedback_cell_array =
      i::ClosureFeedbackCellArray::New(i_isolate, shared_function);
  i::DirectHandle<i::FeedbackVector> fv = factory->NewFeedbackVector(
      shared_function, feedback_cell_array,
      handle(i::Cast<i::JSFunction>(*obj)->raw_feedback_cell(), i_isolate));

  // Create a Code object.
  i::Assembler assm(i_isolate->allocator(), i::AssemblerOptions{});
  assm.nop();  // supported on all architectures
  i::CodeDesc desc;
  assm.GetCode(i_isolate, &desc);
  i::DirectHandle<i::Code> code =
      i::Factory::CodeBuilder(i_isolate, desc, i::CodeKind::FOR_TESTING)
          .Build();
  CHECK(IsCode(*code));

#ifdef V8_ENABLE_LEAPTIERING
  USE(fv);
#else
  // Manually inlined version of FeedbackVector::SetOptimizedCode (needed due
  // to the FOR_TESTING code kind).
  fv->set_maybe_optimized_code(i::MakeWeak(code->wrapper()));
  fv->set_flags(
      i::FeedbackVector::MaybeHasTurbofanCodeBit::encode(true) |
      i::FeedbackVector::TieringStateBits::encode(i::TieringState::kNone));
#endif  // V8_ENABLE_LEAPTIERING

  v8::HeapProfiler* heap_profiler = isolate->GetHeapProfiler();
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
}

TEST(Bug8373_1) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  heap_profiler->StartSamplingHeapProfiler(100);

  heap_profiler->TakeHeapSnapshot();
  // Causes the StringsStorage to be deleted.
  heap_profiler->DeleteAllHeapSnapshots();

  // Triggers an allocation sample that tries to use the StringsStorage.
  for (int i = 0; i < 2 * 1024; ++i) {
    CompileRun(
        "new Array(64);"
        "new Uint8Array(16);");
  }

  heap_profiler->StopSamplingHeapProfiler();
}

TEST(Bug8373_2) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  heap_profiler->StartTrackingHeapObjects(true);

  heap_profiler->TakeHeapSnapshot();
  // Causes the StringsStorage to be deleted.
  heap_profiler->DeleteAllHeapSnapshots();

  // Triggers an allocations that try to use the StringsStorage.
  for (int i = 0; i < 2 * 1024; ++i) {
    CompileRun(
        "new Array(64);"
        "new Uint8Array(16);");
  }

  heap_profiler->StopTrackingHeapObjects();
}

TEST(HeapSnapshotDeleteDuringTakeSnapshot) {
  // Check that a heap snapshot can be deleted during GC while another one
  // is being taken.

  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  int gc_calls = 0;
  v8::Global<v8::Object> handle;
  v8::Isolate* isolate = env->GetIsolate();
  i::Heap* heap = reinterpret_cast<i::Isolate*>(isolate)->heap();

  {
    struct WeakData {
      const v8::HeapSnapshot* snapshot;
      int* gc_calls;
      v8::Global<v8::Object>* handle;
    };
    WeakData* data =
        new WeakData{heap_profiler->TakeHeapSnapshot(), &gc_calls, &handle};

    v8::HandleScope inner_scope(isolate);
    handle.Reset(isolate, v8::Object::New(isolate));
    handle.SetWeak(
        data,
        [](const v8::WeakCallbackInfo<WeakData>& data) {
          std::unique_ptr<WeakData> weakdata{data.GetParameter()};
          const_cast<v8::HeapSnapshot*>(weakdata->snapshot)->Delete();
          ++*weakdata->gc_calls;
          weakdata->handle->Reset();
        },
        v8::WeakCallbackType::kParameter);
  }
  CHECK_EQ(gc_calls, 0);

  // We need to invoke GC without stack, otherwise some objects may survive.
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
  // For the same reason, we need to take the snapshot without scanning the
  // stack.
  v8::HeapProfiler::HeapSnapshotOptions options;
  options.stack_state = cppgc::EmbedderStackState::kNoHeapPointers;

  CHECK(ValidateSnapshot(heap_profiler->TakeHeapSnapshot(options)));
  CHECK_EQ(gc_calls, 1);
}

TEST(ObjectRetainedInHandle) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  v8::HandleScope scope(isolate);
  v8::HeapProfiler* heap_profiler = isolate->GetHeapProfiler();

  // Allocate an array and keep a handle to it.
  i::Handle<i::FixedArray> handle = i_isolate->factory()->NewFixedArray(1024);

  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));

  // Make sure to keep the handle alive.
  CHECK(!handle.is_null());
}

TEST(ObjectRetainedInDirectHandle) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  v8::HandleScope scope(isolate);
  v8::HeapProfiler* heap_profiler = isolate->GetHeapProfiler();

  // Allocate an array and keep a direct handle to it.
  i::DirectHandle<i::FixedArray> direct;
  {
    // Make sure the temporary indirect handle goes away.
    v8::HandleScope inner_scope(isolate);
    direct = i_isolate->factory()->NewFixedArray(1024);
  }

  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));

  // Make sure to keep the handle alive.
  CHECK(!direct.is_null());
}

#if V8_ENABLE_WEBASSEMBLY
TEST(HeapSnapshotWithWasmInstance) {
  LocalContext env2;
  v8::Isolate* isolate = env2->GetIsolate();
  v8::HandleScope scope(isolate);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  v8::HeapProfiler* heap_profiler = isolate->GetHeapProfiler();

  i::Zone zone(i_isolate->allocator(), ZONE_NAME);
  i::wasm::ZoneBuffer buffer(&zone);
  i::wasm::WasmModuleBuilder module_builder{&zone};
  module_builder.WriteTo(&buffer);

  v8::Local<v8::Context> context = isolate->GetCurrentContext();

  // Get the "WebAssembly.Module" and "WebAssembly.Instance" functions.
  auto get_property = [context, isolate](
                          v8::Local<v8::Object> obj,
                          const char* property_name) -> v8::Local<v8::Object> {
    auto name = v8::String::NewFromUtf8(isolate, property_name,
                                        v8::NewStringType::kInternalized)
                    .ToLocalChecked();
    return obj->Get(context, name).ToLocalChecked().As<v8::Object>();
  };
  auto wasm_class = get_property(context->Global(), "WebAssembly");
  auto module_class = get_property(wasm_class, "Module");
  auto instance_class = get_property(wasm_class, "Instance");

  // Create an arraybuffer with the wire bytes.
  v8::Local<v8::ArrayBuffer> buf = v8::ArrayBuffer::New(isolate, buffer.size());
  memcpy(static_cast<uint8_t*>(buf->GetBackingStore()->Data()), buffer.data(),
         buffer.size());

  // Now call the "WebAssembly.Module" function with the array buffer.
  v8::Local<v8::Value> module_args[] = {buf};
  v8::Local<v8::Value> module_object =
      module_class
          ->CallAsConstructor(context, arraysize(module_args), module_args)
          .ToLocalChecked();
  auto set_property = [context, isolate](v8::Local<v8::Object> obj,
                                         const char* property_name,
                                         v8::Local<v8::Value> value) {
    auto name = v8::String::NewFromUtf8(isolate, property_name,
                                        v8::NewStringType::kInternalized)
                    .ToLocalChecked();
    CHECK(obj->Set(context, name, value).FromMaybe(false));
  };
  // Store the module as global "module".
  set_property(context->Global(), "module", module_object);

  // Create a Wasm instance by calling "WebAssembly.Instance" with the module.
  v8::Local<v8::Value> instance_args[] = {module_object};
  v8::Local<v8::Value> instance_object =
      instance_class
          ->CallAsConstructor(context, arraysize(instance_args), instance_args)
          .ToLocalChecked();
  // Store the instance object as global "instance".
  set_property(context->Global(), "instance", instance_object);

  // Now take a snapshot and check the representation of the Wasm objects.
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);

  // Check the properties of the global "instance" (adapt this when fields are
  // added or removed).
  const v8::HeapGraphNode* instance_node =
      GetProperty(isolate, global, v8::HeapGraphEdge::kProperty, "instance");
  CHECK_NOT_NULL(instance_node);
  CheckProperties(
      isolate, instance_node,
      {"__proto__", "exports", "map", "module_object", "trusted_data"});

  // Check the properties of the WasmTrustedInstanceData.
  const v8::HeapGraphNode* trusted_instance_data_node = GetProperty(
      isolate, instance_node, v8::HeapGraphEdge::kInternal, "trusted_data");
  CHECK_NOT_NULL(trusted_instance_data_node);
  CheckProperties(
      isolate, trusted_instance_data_node,
      {"dispatch_table0", "dispatch_table_for_imports", "dispatch_tables",
       "instance_object", "managed_native_module", "map",
       "memory_bases_and_sizes", "native_context", "shared_part"});

  // "module_object" should be the same as the global "module".
  const v8::HeapGraphNode* module_node =
      GetProperty(isolate, global, v8::HeapGraphEdge::kProperty, "module");
  CHECK_NOT_NULL(module_node);
  CHECK_EQ(module_node,
           GetProperty(isolate, instance_node, v8::HeapGraphEdge::kInternal,
                       "module_object"));
  // Check that all properties of the WasmModuleObject are there (adapt this
  // when fields are added or removed).
  CheckProperties(isolate, module_node,
                  {"__proto__", "managed_native_module", "map", "script"});
  // Check the "managed_native_module" specifically. It should say
  // "Managed<wasm::NativeModule>" and should have a reasonable size.
  const v8::HeapGraphNode* managed_node =
      GetProperty(isolate, module_node, v8::HeapGraphEdge::kInternal,
                  "managed_native_module");
  CHECK_NOT_NULL(managed_node);
  v8::String::Utf8Value managed_name{isolate, managed_node->GetName()};
#if V8_ENABLE_SANDBOX
  CHECK_EQ(std::string_view{"system / Managed<wasm::NativeModule>"},
           std::string_view{*managed_name});
  // The size of the Managed is computed from the size of the NativeModule. This
  // is multiple kB, just conservatively assume >= 500b here.
  CHECK_LE(500, managed_node->GetShallowSize());
#else
  CHECK_EQ(std::string_view{"system / Foreign"},
           std::string_view{*managed_name});
#endif  // V8_ENABLE_SANDBOX
}
#endif  // V8_ENABLE_WEBASSEMBLY

"""


```