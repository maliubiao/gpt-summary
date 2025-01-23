Response:
The user wants a summary of the provided C++ code snippet, which is part 5 of 6, focusing on its functionalities.

Here's a breakdown of the thought process to achieve the desired output:

1. **Identify the Core Functionality:** The file name `test-heap-profiler.cc` and the content strongly suggest that this code tests the heap profiler functionality in V8.

2. **Scan for Key APIs:** Look for V8 Heap Profiler related APIs being used in the tests. Keywords like `HeapProfiler`, `TakeHeapSnapshot`, `StartSamplingHeapProfiler`, `StopSamplingHeapProfiler`, `GetAllocationProfile`, `AddBuildEmbedderGraphCallback`, `RemoveBuildEmbedderGraphCallback`, `QueryObjects`, and `AnnotateStrongRetainer` are good indicators.

3. **Group Tests by Functionality:**  Notice that the code is organized into `TEST` macros. Group these tests based on the V8 Heap Profiler features they are exercising. This will provide a structured overview.

4. **Analyze Each Test Group:** For each group, determine the specific aspect of the heap profiler being tested.

    * **Embedder Graph:** Tests like `EmbedderGraph`, `EmbedderGraphWithNamedEdges`, `EmbedderGraphMultipleCallbacks`, `EmbedderGraphWithWrapperNode`, `EmbedderGraphWithPrefix` are clearly related to building and manipulating the embedder graph within heap snapshots. Pay attention to the callbacks used (`BuildEmbedderGraph`, `BuildEmbedderGraphWithContext`, etc.).
    * **Strong Handle Annotation:** The `StrongHandleAnnotation` test focuses on how strong handles are labeled in heap snapshots.
    * **Sampling Heap Profiler:**  Tests starting with `SamplingHeapProfiler` are about the sampling profiler, covering basic usage, allocation tracking, API allocations, sample retrieval, and edge cases like deoptimization and large intervals. Look for the use of `StartSamplingHeapProfiler` and `GetAllocationProfile`.
    * **Allocation Profile:**  This is closely tied to the sampling profiler, focusing on how the allocation data is structured and accessed.
    * **AddressToTraceMap:**  This seems to be a utility used internally by the heap profiler to map addresses to trace IDs.
    * **Query Objects:** The `QueryObjects` test demonstrates how to filter objects in the heap based on a predicate.
    * **Weak References:** The `WeakReference` test verifies how weak references (like those used in `FeedbackVector`) are handled in heap snapshots.
    * **Error Handling/Edge Cases:** Tests like `Bug8373_1`, `Bug8373_2`, and `HeapSnapshotDeleteDuringTakeSnapshot` are designed to catch potential issues or race conditions.

5. **Check for .tq Extension:**  A quick scan of the file content reveals no `.tq` extensions, so it's not a Torque file.

6. **JavaScript Relevance and Examples:**  Consider how the tested heap profiler features relate to JavaScript.

    * **Embedder Graph:**  Think about scenarios where native code (the "embedder") interacts with JavaScript objects and how those relationships might be visualized in a heap snapshot.
    * **Sampling Profiler:**  This directly helps developers understand where memory allocations are happening in their JavaScript code. Provide a simple example showing function calls and object creation.
    * **Query Objects:** Imagine a developer wanting to find all objects with a specific property.
    * **Strong Handles:**  Explain how these are important for preventing garbage collection.

7. **Code Logic and Examples:**  For tests involving specific logic (like `AddressToTraceMap`),  provide example inputs and expected outputs to illustrate how the code works.

8. **Common Programming Errors:** Relate the heap profiler to common JavaScript memory management issues (memory leaks, unexpected object retention).

9. **Synthesize the Summary:** Combine the information gathered in the previous steps into a concise summary, addressing all the user's points. Since this is part 5 of 6, focus on the functionality demonstrated in *this specific part*.

10. **Refine and Organize:**  Ensure the summary is clear, well-organized, and easy to understand. Use headings and bullet points for readability. Double-check that all aspects of the prompt are covered.

**(Self-Correction during the process):**

* Initially, I might focus too much on the individual test names. It's more effective to group them by the underlying feature being tested.
*  I need to remember that the user explicitly asked about JavaScript relevance, so I must provide concrete JavaScript examples.
*  For `AddressToTraceMap`, simply stating it's an internal utility isn't enough. Providing input/output examples makes its function clearer.
* I need to pay close attention to the "part 5 of 6" instruction and tailor the summary accordingly, avoiding overgeneralization.
```cpp
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
  i::v8_flags.sampling_heap
### 提示词
```
这是目录为v8/test/cctest/test-heap-profiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-heap-profiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
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
```