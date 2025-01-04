Response: The user wants a summary of the C++ source code file `v8/test/cctest/test-heap-profiler.cc`. This is the second part of a three-part file.

The file appears to be testing the heap profiler functionality in V8. It covers various aspects, including:

- **Embedder Graph:**  How native (C++) objects can be included in heap snapshots and how they relate to JavaScript objects.
- **Object IDs:**  Assigning and retrieving unique IDs for native objects in snapshots.
- **Heap Snapshots:** Taking, deleting, and iterating through heap snapshots.
- **Object Information:**  Retrieving names, constructors, and properties of objects in the heap.
- **Garbage Collection:** How garbage collection affects object tracking and snapshots.
- **Allocation Tracking:**  Tracking where objects are allocated and their sizes.
- **Weak References:** How weak references are handled in heap snapshots.
- **Specific Object Types:** Testing how different JavaScript object types (e.g., Promises, ArrayBuffers, Generators) are represented in heap snapshots.

Since this is part 2, I should focus on the functionalities covered in *this specific section*. Looking at the code, this part seems to primarily focus on:

- **Embedder Graph functionality:** Defining custom node types (`EmbedderNode`, `EmbedderRootNode`) and testing the integration of these nodes into heap snapshots. This includes testing named edges in the embedder graph.

I need to provide a summary of these features and an example in JavaScript demonstrating the relationship between JavaScript and native code in the context of heap profiling (specifically, how native objects can be linked to JavaScript objects).
这是 `v8/test/cctest/test-heap-profiler.cc` 文件的第二部分，主要功能是测试 V8 堆分析器（Heap Profiler）的以下特性：

**1. 支持带名称的 Embedder Graph 边 (Named Embedder Graph Edges):**

   - 这部分测试了当构建嵌入器图时，可以为连接 V8 节点和嵌入器节点的边添加名称。
   - 它定义了 `BuildEmbedderGraphWithNamedEdges` 函数，该函数在创建嵌入器图时，为从 JavaScript 全局对象到 `EmbedderNodeA` 以及从 `EmbedderNodeA` 到 `EmbedderNodeB` 的边指定了名称 `"global_to_a"` 和 `"a_to_b"`。
   - `CheckEmbedderGraphWithNamedEdges` 函数验证了生成的堆快照中，这些边的类型是 `kInternal`，并且它们的名称与预期一致。

**与 JavaScript 的关系:**

嵌入器图允许将 V8 引擎外部的 C++ 对象（嵌入器对象）添加到堆快照中，以便在分析内存时可以查看这些对象及其与 JavaScript 对象的关联。带名称的边使得更能理解这些关联的含义。

**JavaScript 示例:**

虽然直接在 JavaScript 中创建带名称的嵌入器图边是不可能的，但可以展示嵌入器如何创建与 JavaScript 对象关联的本地对象，这些关联可以在堆快照中通过带名称的边来表示。

假设有一个 C++ 嵌入器，它创建了一个本地 C++ 对象，并将其与一个 JavaScript 对象关联起来：

```cpp
// C++ 代码 (嵌入器)
#include <v8.h>

void CreateAndLinkNativeObject(const v8::FunctionCallbackInfo<v8::Value>& args) {
  v8::Isolate* isolate = args.GetIsolate();
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::Context> context = isolate->GetCurrentContext();

  // 创建一个 JavaScript 对象
  v8::Local<v8::ObjectTemplate> object_template = v8::ObjectTemplate::New(isolate);
  v8::Local<v8::Object> js_object = object_template->NewInstance(context).ToLocalChecked();

  // 创建一个本地 C++ 对象 (假设 MyNativeObject 是一个 C++ 类)
  MyNativeObject* native_object = new MyNativeObject();

  // 将本地对象与 JavaScript 对象关联起来 (例如，使用 SetInternalField)
  js_object->SetInternalField(0, v8::External::New(isolate, native_object));

  // 当构建嵌入器图时，可以添加一个从 js_object 到 native_object 的边，并命名它

  args.GetReturnValue().Set(js_object);
}

// 在初始化 V8 时，注册 CreateAndLinkNativeObject 函数到 JavaScript
// ...
  global->Set(context,
              v8::String::NewFromUtf8(isolate, "createAndLinkNativeObject").ToLocalChecked(),
              v8::Function::New(context, CreateAndLinkNativeObject).ToLocalChecked()).Check();
// ...
```

```javascript
// JavaScript 代码
const myObject = createAndLinkNativeObject();

// 当拍摄堆快照时，嵌入器可以构建一个图，其中 myObject (JavaScript 对象) 通过一个
// 带名称的边 (例如 "nativeBinding") 连接到一个本地 C++ 对象。
```

在这个例子中，C++ 嵌入器负责创建和管理嵌入器图。JavaScript 代码创建了一个对象，而嵌入器将这个 JavaScript 对象与一个本地 C++ 对象关联起来。当拍摄堆快照时，嵌入器可以使用 `AddBuildEmbedderGraphCallback` 来添加自定义节点和边，包括带名称的边，来表示这种关联。在堆快照分析工具中，可以看到 `myObject` 通过一个名为 "nativeBinding" 的边连接到它的关联本地对象。

总而言之，这部分测试了 V8 堆分析器如何处理和表示嵌入器定义的节点和带名称的边，从而更好地理解 JavaScript 代码与底层 C++ 代码之间的内存关系。

Prompt: 
```
这是目录为v8/test/cctest/test-heap-profiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能

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
    const v8::HeapGraphEdge* handle_edge = node->GetChild(i);
    if (handle_edge->GetType() == v8::HeapGraphEdge::kWeak) return true;
  }
  return false;
}


bool HasWeakGlobalHandle() {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HeapProfiler* heap_profiler = isolate->GetHeapProfiler();
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* gc_roots = GetNode(
      snapshot->GetRoot(), v8::HeapGraphNode::kSynthetic, "(GC roots)");
  CHECK(gc_roots);
  const v8::HeapGraphNode* global_handles = GetNode(
      gc_roots, v8::HeapGraphNode::kSynthetic, "(Global handles)");
  CHECK(global_handles);
  return HasWeakEdge(global_handles);
}


TEST(WeakGlobalHandle) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  CHECK(!HasWeakGlobalHandle());

  v8::Global<v8::Object> handle;

  handle.Reset(env->GetIsolate(), v8::Object::New(env->GetIsolate()));
  handle.SetWeak();

  CHECK(HasWeakGlobalHandle());
}


TEST(SfiAndJsFunctionWeakRefs) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  CompileRun(
      "fun = (function (x) { return function () { return x + 1; } })(1);");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  CHECK(global);
  const v8::HeapGraphNode* fun = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "fun");
  CHECK(!HasWeakEdge(fun));
  const v8::HeapGraphNode* shared = GetProperty(
      env->GetIsolate(), fun, v8::HeapGraphEdge::kInternal, "shared");
  CHECK(!HasWeakEdge(shared));
}


TEST(AllStrongGcRootsHaveNames) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  CompileRun("foo = {};");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* gc_roots = GetNode(
      snapshot->GetRoot(), v8::HeapGraphNode::kSynthetic, "(GC roots)");
  CHECK(gc_roots);
  const v8::HeapGraphNode* strong_roots = GetNode(
      gc_roots, v8::HeapGraphNode::kSynthetic, "(Strong roots)");
  CHECK(strong_roots);
  for (int i = 0; i < strong_roots->GetChildrenCount(); ++i) {
    const v8::HeapGraphEdge* edge = strong_roots->GetChild(i);
    CHECK_EQ(v8::HeapGraphEdge::kInternal, edge->GetType());
    v8::String::Utf8Value name(env->GetIsolate(), edge->GetName());
    CHECK(isalpha(**name));
  }
}


TEST(NoRefsToNonEssentialEntries) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  CompileRun("global_object = {};\n");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  const v8::HeapGraphNode* global_object = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "global_object");
  CHECK(global_object);
  const v8::HeapGraphNode* properties =
      GetProperty(env->GetIsolate(), global_object,
                  v8::HeapGraphEdge::kInternal, "properties");
  CHECK(!properties);
  const v8::HeapGraphNode* elements =
      GetProperty(env->GetIsolate(), global_object,
                  v8::HeapGraphEdge::kInternal, "elements");
  CHECK(!elements);
}


TEST(MapHasDescriptorsAndTransitions) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  CompileRun("obj = { a: 10 };\n");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  const v8::HeapGraphNode* global_object = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "obj");
  CHECK(global_object);

  const v8::HeapGraphNode* map = GetProperty(
      env->GetIsolate(), global_object, v8::HeapGraphEdge::kInternal, "map");
  CHECK(map);
  const v8::HeapGraphNode* own_descriptors = GetProperty(
      env->GetIsolate(), map, v8::HeapGraphEdge::kInternal, "descriptors");
  CHECK(own_descriptors);
  const v8::HeapGraphNode* own_transitions = GetProperty(
      env->GetIsolate(), map, v8::HeapGraphEdge::kInternal, "transitions");
  CHECK(!own_transitions);
}


TEST(ManyLocalsInSharedContext) {
  // This test gets very slow with slow asserts (18 minutes instead of 1:30,
  // as of November 2018).
#ifdef ENABLE_SLOW_DCHECKS
  i::v8_flags.enable_slow_asserts = false;
#endif
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  int num_objects = 6000;
  CompileRun(
      "var n = 6000;"
      "var result = [];"
      "result.push('(function outer() {');"
      "for (var i = 0; i < n; i++) {"
      "    var f = 'function f_' + i + '() { ';"
      "    if (i > 0)"
      "        f += 'f_' + (i - 1) + '();';"
      "    f += ' }';"
      "    result.push(f);"
      "}"
      "result.push('return f_' + (n - 1) + ';');"
      "result.push('})()');"
      "var ok = eval(result.join('\\n'));");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  CHECK(global);
  const v8::HeapGraphNode* ok_object = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "ok");
  CHECK(ok_object);
  const v8::HeapGraphNode* context_object = GetProperty(
      env->GetIsolate(), ok_object, v8::HeapGraphEdge::kInternal, "context");
  CHECK(context_object);
  // Check the objects are not duplicated in the context.
  CHECK_EQ(i::Context::MIN_CONTEXT_EXTENDED_SLOTS + num_objects - 1,
           context_object->GetChildrenCount());
  // Check all the objects have got their names.
  // ... well check just every 15th because otherwise it's too slow in debug.
  for (int i = 0; i < num_objects - 1; i += 15) {
    v8::base::EmbeddedVector<char, 100> var_name;
    v8::base::SNPrintF(var_name, "f_%d", i);
    const v8::HeapGraphNode* f_object =
        GetProperty(env->GetIsolate(), context_object,
                    v8::HeapGraphEdge::kContextVariable, var_name.begin());
    CHECK(f_object);
  }
}

TEST(AllocationSitesAreVisible) {
  i::v8_flags.lazy_feedback_allocation = false;
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::HeapProfiler* heap_profiler = isolate->GetHeapProfiler();
  CompileRun(
      "fun = function () { var a = [3, 2, 1]; return a; }\n"
      "fun();");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));

  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  CHECK(global);
  const v8::HeapGraphNode* fun_code = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "fun");
  CHECK(fun_code);
  const v8::HeapGraphNode* feedback_cell =
      GetProperty(env->GetIsolate(), fun_code, v8::HeapGraphEdge::kInternal,
                  "feedback_cell");
  CHECK(feedback_cell);
  const v8::HeapGraphNode* vector = GetProperty(
      env->GetIsolate(), feedback_cell, v8::HeapGraphEdge::kInternal, "value");
  CHECK_EQ(v8::HeapGraphNode::kCode, vector->GetType());
  CHECK_EQ(5, vector->GetChildrenCount());

  // The last value in the feedback vector should be the boilerplate,
  // found in AllocationSite.transition_info.
  const v8::HeapGraphEdge* prop = vector->GetChild(4);
  const v8::HeapGraphNode* allocation_site = prop->GetToNode();
  v8::String::Utf8Value name(env->GetIsolate(), allocation_site->GetName());
  CHECK_EQ(0, strcmp("system / AllocationSite", *name));
  const v8::HeapGraphNode* transition_info =
      GetProperty(env->GetIsolate(), allocation_site,
                  v8::HeapGraphEdge::kInternal, "transition_info");
  CHECK(transition_info);

  const v8::HeapGraphNode* elements =
      GetProperty(env->GetIsolate(), transition_info,
                  v8::HeapGraphEdge::kInternal, "elements");
  CHECK(elements);
  CHECK_EQ(v8::HeapGraphNode::kCode, elements->GetType());
  CHECK_EQ(i::FixedArray::SizeFor(3),
           static_cast<int>(elements->GetShallowSize()));

  v8::Local<v8::Value> array_val =
      heap_profiler->FindObjectById(transition_info->GetId());
  CHECK(array_val->IsArray());
  v8::Local<v8::Array> array = v8::Local<v8::Array>::Cast(array_val);
  // Verify the array is "a" in the code above.
  CHECK_EQ(3u, array->Length());
  CHECK(v8::Integer::New(isolate, 3)
            ->Equals(env.local(),
                     array->Get(env.local(), v8::Integer::New(isolate, 0))
                         .ToLocalChecked())
            .FromJust());
  CHECK(v8::Integer::New(isolate, 2)
            ->Equals(env.local(),
                     array->Get(env.local(), v8::Integer::New(isolate, 1))
                         .ToLocalChecked())
            .FromJust());
  CHECK(v8::Integer::New(isolate, 1)
            ->Equals(env.local(),
                     array->Get(env.local(), v8::Integer::New(isolate, 2))
                         .ToLocalChecked())
            .FromJust());
}


TEST(JSFunctionHasCodeLink) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  CompileRun("function foo(x, y) { return x + y; }\n");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  const v8::HeapGraphNode* foo_func = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "foo");
  CHECK(foo_func);
  const v8::HeapGraphNode* code = GetProperty(
      env->GetIsolate(), foo_func, v8::HeapGraphEdge::kInternal, "code");
  CHECK(code);
}

static const v8::HeapGraphNode* GetNodeByPath(v8::Isolate* isolate,
                                              const v8::HeapSnapshot* snapshot,
                                              const char* path[], int depth) {
  const v8::HeapGraphNode* node = snapshot->GetRoot();
  for (int current_depth = 0; current_depth < depth; ++current_depth) {
    int i, count = node->GetChildrenCount();
    for (i = 0; i < count; ++i) {
      const v8::HeapGraphEdge* edge = node->GetChild(i);
      const v8::HeapGraphNode* to_node = edge->GetToNode();
      v8::String::Utf8Value edge_name(isolate, edge->GetName());
      v8::String::Utf8Value node_name(isolate, to_node->GetName());
      v8::base::EmbeddedVector<char, 100> name;
      v8::base::SNPrintF(name, "%s::%s", *edge_name, *node_name);
      if (strstr(name.begin(), path[current_depth])) {
        node = to_node;
        break;
      }
    }
    if (i == count) return nullptr;
  }
  return node;
}


TEST(CheckCodeNames) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  CompileRun("var a = 1.1;");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));

  const char* builtin_path1[] = {
      "::(GC roots)",
      "::(Builtins)",
      "::(KeyedLoadIC_PolymorphicName builtin code)",
  };
  const v8::HeapGraphNode* node = GetNodeByPath(
      env->GetIsolate(), snapshot, builtin_path1, arraysize(builtin_path1));
  CHECK(node);

  const char* builtin_path2[] = {
      "::(GC roots)",
      "::(Builtins)",
      "::(CompileLazy builtin code)",
  };
  node = GetNodeByPath(env->GetIsolate(), snapshot, builtin_path2,
                       arraysize(builtin_path2));
  CHECK(node);
  v8::String::Utf8Value node_name(env->GetIsolate(), node->GetName());
  CHECK_EQ(0, strcmp("(CompileLazy builtin code)", *node_name));
}


static const char* record_trace_tree_source =
"var topFunctions = [];\n"
"var global = this;\n"
"function generateFunctions(width, depth) {\n"
"  var script = [];\n"
"  for (var i = 0; i < width; i++) {\n"
"    for (var j = 0; j < depth; j++) {\n"
"      script.push('function f_' + i + '_' + j + '(x) {\\n');\n"
"      script.push('  try {\\n');\n"
"      if (j < depth-2) {\n"
"        script.push('    return f_' + i + '_' + (j+1) + '(x+1);\\n');\n"
"      } else if (j == depth - 2) {\n"
"        script.push('    return new f_' + i + '_' + (depth - 1) + '();\\n');\n"
"      } else if (j == depth - 1) {\n"
"        script.push('    this.ts = Date.now();\\n');\n"
"      }\n"
"      script.push('  } catch (e) {}\\n');\n"
"      script.push('}\\n');\n"
"      \n"
"    }\n"
"  }\n"
"  var script = script.join('');\n"
"  // throw script;\n"
"  global.eval(script);\n"
"  for (var i = 0; i < width; i++) {\n"
"    topFunctions.push(this['f_' + i + '_0']);\n"
"  }\n"
"}\n"
"\n"
"var width = 3;\n"
"var depth = 3;\n"
"generateFunctions(width, depth);\n"
"var instances = [];\n"
"function start() {\n"
"  for (var i = 0; i < width; i++) {\n"
"    instances.push(topFunctions[i](0));\n"
"  }\n"
"}\n"
"\n"
"for (var i = 0; i < 100; i++) start();\n";

static AllocationTraceNode* FindNode(AllocationTracker* tracker,
                                     v8::base::Vector<const char*> names) {
  AllocationTraceNode* node = tracker->trace_tree()->root();
  for (int i = 0; node != nullptr && i < names.length(); i++) {
    const char* name = names[i];
    const std::vector<AllocationTraceNode*>& children = node->children();
    node = nullptr;
    for (AllocationTraceNode* child : children) {
      unsigned index = child->function_info_index();
      AllocationTracker::FunctionInfo* info =
          tracker->function_info_list()[index];
      if (info && strcmp(info->name, name) == 0) {
        node = child;
        break;
      }
    }
  }
  return node;
}

TEST(ArrayGrowLeftTrim) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  heap_profiler->StartTrackingHeapObjects(true);

  CompileRun(
    "var a = [];\n"
    "for (var i = 0; i < 5; ++i)\n"
    "    a[i] = i;\n"
    "for (var i = 0; i < 3; ++i)\n"
    "    a.shift();\n");

  const char* names[] = {""};
  AllocationTracker* tracker =
      reinterpret_cast<i::HeapProfiler*>(heap_profiler)->allocation_tracker();
  CHECK(tracker);
  // Print for better diagnostics in case of failure.
  tracker->trace_tree()->Print(tracker);

  AllocationTraceNode* node = FindNode(tracker, v8::base::ArrayVector(names));
  CHECK(node);
  CHECK_GE(node->allocation_count(), 2u);
  CHECK_GE(node->allocation_size(), 4u * 5u);
  heap_profiler->StopTrackingHeapObjects();
}

TEST(TrackHeapAllocationsWithInlining) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;

  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  heap_profiler->StartTrackingHeapObjects(true);

  CompileRun(record_trace_tree_source);

  AllocationTracker* tracker =
      reinterpret_cast<i::HeapProfiler*>(heap_profiler)->allocation_tracker();
  CHECK(tracker);
  // Print for better diagnostics in case of failure.
  tracker->trace_tree()->Print(tracker);

  const char* names[] = {"", "start", "f_0_0"};
  AllocationTraceNode* node = FindNode(tracker, v8::base::ArrayVector(names));
  CHECK(node);
  // In lite mode, there is feedback and feedback metadata.
  unsigned int num_nodes = (i::v8_flags.lite_mode) ? 6 : 8;
  // Without forced source position collection, there is no source position
  // table.
  if (i::v8_flags.enable_lazy_source_positions) num_nodes -= 1;
  CHECK_GE(node->allocation_count(), num_nodes);
  CHECK_GE(node->allocation_size(), 4 * node->allocation_count());
  heap_profiler->StopTrackingHeapObjects();
}

TEST(TrackHeapAllocationsWithoutInlining) {
  i::v8_flags.turbo_inlining = false;
  // Disable inlining
  i::v8_flags.max_inlined_bytecode_size = 0;
  i::v8_flags.max_inlined_bytecode_size_small = 0;
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;

  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  heap_profiler->StartTrackingHeapObjects(true);

  CompileRun(record_trace_tree_source);

  AllocationTracker* tracker =
      reinterpret_cast<i::HeapProfiler*>(heap_profiler)->allocation_tracker();
  CHECK(tracker);
  // Print for better diagnostics in case of failure.
  tracker->trace_tree()->Print(tracker);

  const char* names[] = {"", "start", "f_0_0", "f_0_1", "f_0_2"};
  AllocationTraceNode* node = FindNode(tracker, v8::base::ArrayVector(names));
  CHECK(node);
  CHECK_GE(node->allocation_count(), 100u);
  CHECK_GE(node->allocation_size(), 4 * node->allocation_count());
  heap_profiler->StopTrackingHeapObjects();
}


static const char* inline_heap_allocation_source =
    "function f_0(x) {\n"
    "  return f_1(x+1);\n"
    "}\n"
    "%NeverOptimizeFunction(f_0);\n"
    "function f_1(x) {\n"
    "  return new f_2(x+1);\n"
    "}\n"
    "%NeverOptimizeFunction(f_1);\n"
    "function f_2(x) {\n"
    "  this.foo = x;\n"
    "}\n"
    "var instances = [];\n"
    "function start() {\n"
    "  instances.push(f_0(0));\n"
    "}\n"
    "\n"
    "for (var i = 0; i < 100; i++) start();\n";


TEST(TrackBumpPointerAllocations) {
  i::v8_flags.allow_natives_syntax = true;
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;

  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  const char* names[] = {"", "start", "f_0", "f_1"};
  // First check that normally all allocations are recorded.
  {
    heap_profiler->StartTrackingHeapObjects(true);

    CompileRun(inline_heap_allocation_source);

    AllocationTracker* tracker =
        reinterpret_cast<i::HeapProfiler*>(heap_profiler)->allocation_tracker();
    CHECK(tracker);
    // Print for better diagnostics in case of failure.
    tracker->trace_tree()->Print(tracker);

    AllocationTraceNode* node = FindNode(tracker, v8::base::ArrayVector(names));
    CHECK(node);
    CHECK_GE(node->allocation_count(), 100u);
    CHECK_GE(node->allocation_size(), 4 * node->allocation_count());
    heap_profiler->StopTrackingHeapObjects();
  }

  {
    heap_profiler->StartTrackingHeapObjects(true);

    // Now check that not all allocations are tracked if we manually reenable
    // inline allocations.
    CHECK(i::v8_flags.single_generation ||
          !CcTest::heap()->IsInlineAllocationEnabled());
    CcTest::heap()->EnableInlineAllocation();

    CompileRun(inline_heap_allocation_source);

    AllocationTracker* tracker =
        reinterpret_cast<i::HeapProfiler*>(heap_profiler)->allocation_tracker();
    CHECK(tracker);
    // Print for better diagnostics in case of failure.
    tracker->trace_tree()->Print(tracker);

    AllocationTraceNode* node = FindNode(tracker, v8::base::ArrayVector(names));
    CHECK(node);
    CHECK_LT(node->allocation_count(), 100u);

    CcTest::heap()->DisableInlineAllocation();
    heap_profiler->StopTrackingHeapObjects();
  }
}


TEST(TrackV8ApiAllocation) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;

  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  const char* names[] = { "(V8 API)" };
  heap_profiler->StartTrackingHeapObjects(true);

  v8::Local<v8::Object> o1 = v8::Object::New(env->GetIsolate());
  o1->Clone();

  AllocationTracker* tracker =
      reinterpret_cast<i::HeapProfiler*>(heap_profiler)->allocation_tracker();
  CHECK(tracker);
  // Print for better diagnostics in case of failure.
  tracker->trace_tree()->Print(tracker);

  AllocationTraceNode* node = FindNode(tracker, v8::base::ArrayVector(names));
  CHECK(node);
  CHECK_GE(node->allocation_count(), 2u);
  CHECK_GE(node->allocation_size(), 4 * node->allocation_count());
  heap_profiler->StopTrackingHeapObjects();
}


TEST(ArrayBufferAndArrayBufferView) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  CompileRun("arr1 = new Uint32Array(100);\n");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  const v8::HeapGraphNode* arr1_obj = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "arr1");
  CHECK(arr1_obj);
  const v8::HeapGraphNode* arr1_buffer = GetProperty(
      env->GetIsolate(), arr1_obj, v8::HeapGraphEdge::kInternal, "buffer");
  CHECK(arr1_buffer);
  const v8::HeapGraphNode* backing_store =
      GetProperty(env->GetIsolate(), arr1_buffer, v8::HeapGraphEdge::kInternal,
                  "backing_store");
  CHECK(backing_store);
  CHECK_EQ(400, static_cast<int>(backing_store->GetShallowSize()));
}


static int GetRetainersCount(const v8::HeapSnapshot* snapshot,
                             const v8::HeapGraphNode* node) {
  int count = 0;
  for (int i = 0, l = snapshot->GetNodesCount(); i < l; ++i) {
    const v8::HeapGraphNode* parent = snapshot->GetNode(i);
    for (int j = 0, l2 = parent->GetChildrenCount(); j < l2; ++j) {
      if (parent->GetChild(j)->GetToNode() == node) {
        ++count;
      }
    }
  }
  return count;
}


TEST(ArrayBufferSharedBackingStore) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);
  v8::HeapProfiler* heap_profiler = isolate->GetHeapProfiler();

  v8::Local<v8::ArrayBuffer> ab = v8::ArrayBuffer::New(isolate, 1024);
  CHECK_EQ(1024, static_cast<int>(ab->ByteLength()));
  std::shared_ptr<v8::BackingStore> backing_store = ab->GetBackingStore();

  CHECK_EQ(1024, static_cast<int>(backing_store->ByteLength()));
  void* data = backing_store->Data();
  CHECK_NOT_NULL(data);
  v8::Local<v8::ArrayBuffer> ab2 = v8::ArrayBuffer::New(isolate, backing_store);
  env->Global()->Set(env.local(), v8_str("ab1"), ab).FromJust();
  env->Global()->Set(env.local(), v8_str("ab2"), ab2).FromJust();

  v8::Local<v8::Value> result = CompileRun("ab2.byteLength");
  CHECK_EQ(1024, result->Int32Value(env.local()).FromJust());

  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  const v8::HeapGraphNode* ab1_node = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "ab1");
  CHECK(ab1_node);
  const v8::HeapGraphNode* ab1_data =
      GetProperty(env->GetIsolate(), ab1_node, v8::HeapGraphEdge::kInternal,
                  "backing_store");
  CHECK(ab1_data);
  const v8::HeapGraphNode* ab2_node = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "ab2");
  CHECK(ab2_node);
  const v8::HeapGraphNode* ab2_data =
      GetProperty(env->GetIsolate(), ab2_node, v8::HeapGraphEdge::kInternal,
                  "backing_store");
  CHECK(ab2_data);
  CHECK_EQ(ab1_data, ab2_data);
  CHECK_EQ(2, GetRetainersCount(snapshot, ab1_data));
}


TEST(WeakContainers) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  if (!CcTest::i_isolate()->use_optimizer()) return;
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  CompileRun(
      "function foo(a) { return a.x; }\n"
      "obj = {x : 123};\n"
      "%PrepareFunctionForOptimization(foo);"
      "foo(obj);\n"
      "foo(obj);\n"
      "%OptimizeFunctionOnNextCall(foo);\n"
      "foo(obj);\n");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  const v8::HeapGraphNode* obj = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "obj");
  CHECK(obj);
  const v8::HeapGraphNode* map =
      GetProperty(env->GetIsolate(), obj, v8::HeapGraphEdge::kInternal, "map");
  CHECK(map);
  const v8::HeapGraphNode* dependent_code = GetProperty(
      env->GetIsolate(), map, v8::HeapGraphEdge::kInternal, "dependent_code");
  if (!dependent_code) return;
  int count = dependent_code->GetChildrenCount();
  CHECK_NE(0, count);
  for (int i = 0; i < count; ++i) {
    const v8::HeapGraphEdge* prop = dependent_code->GetChild(i);
    CHECK(prop->GetType() == v8::HeapGraphEdge::kInternal ||
          prop->GetType() == v8::HeapGraphEdge::kWeak);
  }
}

TEST(JSPromise) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  CompileRun(
      "function A() {}\n"
      "function B() {}\n"
      "resolved = Promise.resolve(new A());\n"
      "rejected = Promise.reject(new B());\n"
      "pending = new Promise(() => 0);\n"
      "chained = pending.then(A, B);\n");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);

  const v8::HeapGraphNode* resolved = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "resolved");
  CHECK(GetProperty(env->GetIsolate(), resolved, v8::HeapGraphEdge::kInternal,
                    "reactions_or_result"));

  const v8::HeapGraphNode* rejected = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "rejected");
  CHECK(GetProperty(env->GetIsolate(), rejected, v8::HeapGraphEdge::kInternal,
                    "reactions_or_result"));

  const v8::HeapGraphNode* pending = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "pending");
  CHECK(GetProperty(env->GetIsolate(), pending, v8::HeapGraphEdge::kInternal,
                    "reactions_or_result"));

  const char* objectNames[] = {"resolved", "rejected", "pending", "chained"};
  for (auto objectName : objectNames) {
    const v8::HeapGraphNode* promise = GetProperty(
        env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, objectName);
    EnsureNoUninstrumentedInternals(env->GetIsolate(), promise);
  }
}

TEST(HeapSnapshotScriptContext) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  CompileRun("class Foo{}; const foo = new Foo();");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  const v8::HeapGraphNode* global_map = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kInternal, "map");
  const v8::HeapGraphNode* map_map = GetProperty(
      env->GetIsolate(), global_map, v8::HeapGraphEdge::kInternal, "map");
  const v8::HeapGraphNode* native_context =
      GetProperty(env->GetIsolate(), map_map, v8::HeapGraphEdge::kInternal,
                  "native_context");
  const v8::HeapGraphNode* script_context_table =
      GetProperty(env->GetIsolate(), native_context,
                  v8::HeapGraphEdge::kInternal, "script_context_table");

  CHECK(script_context_table);
  bool found_foo = false;
  for (int i = 0, count = script_context_table->GetChildrenCount(); i < count;
       ++i) {
    const v8::HeapGraphNode* context =
        script_context_table->GetChild(i)->GetToNode();
    const v8::HeapGraphNode* foo = GetProperty(
        env->GetIsolate(), context, v8::HeapGraphEdge::kContextVariable, "foo");
    if (foo) {
      found_foo = true;
    }
  }
  CHECK(found_foo);
}

class EmbedderNode : public v8::EmbedderGraph::Node {
 public:
  EmbedderNode(const char* name, size_t size,
               v8::EmbedderGraph::Node* wrapper_node = nullptr)
      : name_(name), size_(size), wrapper_node_(wrapper_node) {}

  // Graph::Node overrides.
  const char* Name() override { return name_; }
  size_t SizeInBytes() override { return size_; }
  Node* WrapperNode() override { return wrapper_node_; }

 private:
  const char* name_;
  size_t size_;
  Node* wrapper_node_;
};

class EmbedderRootNode : public EmbedderNode {
 public:
  explicit EmbedderRootNode(const char* name) : EmbedderNode(name, 0) {}
  // Graph::Node override.
  bool IsRootNode() override { return true; }
};

// Used to pass the global object to the BuildEmbedderGraph callback.
// Otherwise, the callback has to iterate the global handles to find the
// global object.
v8::Local<v8::Value>* global_object_pointer;

void BuildEmbedderGraph(v8::Isolate* v8_isolate, v8::EmbedderGraph* graph,
                        void* data) {
  using Node = v8::EmbedderGraph::Node;
  Node* global_node = graph->V8Node(*global_object_pointer);
  Node* embedder_node_A = graph->AddNode(
      std::unique_ptr<Node>(new EmbedderNode("EmbedderNodeA", 10)));
  Node* embedder_node_B = graph->AddNode(
      std::unique_ptr<Node>(new EmbedderNode("EmbedderNodeB", 20)));
  Node* embedder_node_C = graph->AddNode(
      std::unique_ptr<Node>(new EmbedderNode("EmbedderNodeC", 30)));
  Node* embedder_root = graph->AddNode(
      std::unique_ptr<Node>(new EmbedderRootNode("EmbedderRoot")));
  graph->AddEdge(global_node, embedder_node_A);
  graph->AddEdge(embedder_node_A, embedder_node_B);
  graph->AddEdge(embedder_root, embedder_node_C);
  graph->AddEdge(embedder_node_C, global_node);
}

void CheckEmbedderGraphSnapshot(v8::Isolate* isolate,
                                const v8::HeapSnapshot* snapshot) {
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  const v8::HeapGraphNode* embedder_node_A =
      GetChildByName(global, "EmbedderNodeA");
  CHECK_EQ(10, GetSize(embedder_node_A));
  const v8::HeapGraphNode* embedder_node_B =
      GetChildByName(embedder_node_A, "EmbedderNodeB");
  CHECK_EQ(20, GetSize(embedder_node_B));
  const v8::HeapGraphNode* embedder_root =
      GetRootChild(snapshot, "EmbedderRoot");
  CHECK(embedder_root);
  const v8::HeapGraphNode* embedder_node_C =
      GetChildByName(embedder_root, "EmbedderNodeC");
  CHECK_EQ(30, GetSize(embedder_node_C));
  const v8::HeapGraphNode* global_reference =
      GetChildByName(embedder_node_C, "Object");
  CHECK(global_reference);
}

TEST(EmbedderGraph) {
  i::v8_flags.heap_profiler_use_embedder_graph = true;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(env->GetIsolate());
  v8::Local<v8::Value> global_object =
      v8::Utils::ToLocal(i::Handle<i::JSObject>(
          (isolate->context()->native_context()->global_object()), isolate));
  global_object_pointer = &global_object;
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  heap_profiler->AddBuildEmbedderGraphCallback(BuildEmbedderGraph, nullptr);
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  CheckEmbedderGraphSnapshot(env->GetIsolate(), snapshot);
}

void BuildEmbedderGraphWithNamedEdges(v8::Isolate* v8_isolate,
                                      v8::EmbedderGraph* graph, void* data) {
  using Node = v8::EmbedderGraph::Node;
  Node* global_node = graph->V8Node(*global_object_pointer);
  Node* embedder_node_A = graph->AddNode(
      std::unique_ptr<Node>(new EmbedderNode("EmbedderNodeA", 10)));
  Node* embedder_node_B = graph->AddNode(
      std::unique_ptr<Node>(new EmbedderNode("EmbedderNodeB", 20)));
  Node* embedder_node_C = graph->AddNode(
      std::unique_ptr<Node>(new EmbedderNode("EmbedderNodeC", 30)));
  graph->AddEdge(global_node, embedder_node_A, "global_to_a");
  graph->AddEdge(embedder_node_A, embedder_node_B, "a_to_b");
  graph->AddEdge(embedder_node_B, embedder_node_C);
}

void CheckEmbedderGraphWithNamedEdges(v8::Isolate* isolate,
                                      const v8::HeapSnapshot* snapshot) {
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  const v8::HeapGraphEdge* global_to_a =
      GetEdgeByChildName(global, "EmbedderNodeA");
  CHECK(global_to_a);
  CHECK_EQ(v8::HeapGraphEdge::kInternal, global_to_a->GetType());
  CHECK(global_to_a->GetName()->IsString());
  CHECK_EQ(0, strcmp("global_to_a", GetName(global_to_a)));
  const v8::HeapGraphNode* embedder_node_A = global_to_a->GetToNode();
  CHECK_EQ(0, strcmp("EmbedderNodeA", GetName(embedder_node_A)));
  CHECK_EQ(10, GetSize(embedder_node_A));

  const v8::HeapGraphEdge* a_to_b =
      GetEdgeByChildName(embedder_node_A, "EmbedderNodeB");
  CHECK(a_to_b);
  CHECK(a_to_b->GetName()->IsString());
  CHECK_EQ(0, strcmp("a_to_b", GetName(a_to_b)));
  CHECK_EQ(v8::HeapGraphEdge::kInternal, a_to_b->GetType());
  const v8::HeapGraphNode* embedder_node_B = a_to_b->GetToNode();
  CHECK_EQ(0, strcmp("EmbedderNodeB", GetName(embedder_node_B)));
  CHECK_EQ(20, GetSize(embedder_node_B));

  const v8::HeapGraphEdge* b_to_c =
      GetEdgeByChildName(
"""


```