Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/cctest/test-heap-profiler.cc`. This is part 2 of a 6-part code analysis. I need to identify the purpose of the code, focusing on what aspects of the heap profiler it's testing. The instructions mention checking for `.tq` files (not applicable here), JavaScript connections (which are strong in these tests), code logic (in the form of test cases), and common programming errors (implicitly covered by the testing).

**Plan:**

1. **Identify the main subject:** The code is testing the V8 heap profiler.
2. **Analyze individual test cases:** Each `TEST()` block focuses on a specific feature or scenario related to heap snapshots. I'll go through them one by one and summarize their purpose.
3. **Look for JavaScript interactions:**  The `CompileRun()` function indicates JavaScript execution, so I'll note how the JavaScript code sets up the scenarios for testing.
4. **Infer functionality:** Based on the tests, I'll deduce the capabilities being verified.
5. **Formulate a concise summary:**  I'll synthesize the findings into a summary of the code's functionality as part 2 of a larger analysis.
这是 `v8/test/cctest/test-heap-profiler.cc` 的第 2 部分代码，它主要关注 V8 堆快照 (Heap Snapshot) 的功能测试。以下是这部分代码中测试的主要功能归纳：

1. **`TEST(HeapSnapshotMap)`:**  测试堆快照是否能正确反映对象的 `map` 属性及其内部结构。这包括 `map` 的 `map` 自身、`prototype`、`back_pointer`、`descriptors` 和 `transition` 等内部属性。它验证了对象元数据的正确捕获。

    *   **JavaScript 示例:**
        ```javascript
        function Z() { this.foo = {}; this.bar = 0; }
        z = new Z();
        ```
        这段 JavaScript 代码创建了一个对象 `z`，测试会检查其内部的 `map` 结构是否在堆快照中正确表示。

2. **`TEST(HeapSnapshotInternalReferences)`:** 测试堆快照是否能正确捕获对象的内部引用，特别是通过 `SetInternalField` 设置的内部字段。这个测试关注非属性的、由 C++ 代码管理的 JavaScript 对象的引用关系。

    *   **假设输入与输出:**  假设一个 C++ 创建的全局对象，使用 `SetInternalField` 设置了两个内部字段，一个存储数字 17，另一个存储一个 JavaScript 对象。测试会验证堆快照中只包含对第二个 JavaScript 对象的内部引用（因为数字是 Smi，通常不会作为单独的堆对象）。

3. **`TEST(HeapSnapshotEphemeron)`:** 测试堆快照如何处理弱引用，特别是 `WeakMap` 中的键值对。它验证了当键是可回收对象时，堆快照中边的标签能够正确指示这是一个弱引用关系。

    *   **JavaScript 示例:**
        ```javascript
        class KeyClass{};
        class ValueClass{};
        var wm = new WeakMap();
        function foo(key) { wm.set(key, new ValueClass()); }
        var key = new KeyClass();
        foo(key);
        ```
        测试会检查 `WeakMap` 的内部表，确认从 `key` 对象到 `ValueClass` 对象的边是否带有指示其为弱引用的标签。

4. **`TEST(HeapSnapshotAddressReuse)`:** 测试堆快照中的对象 ID 在垃圾回收后是否能够正确处理地址的重用。它创建大量对象，进行快照，然后再次创建并进行垃圾回收，确保新的对象的 ID 不会小于旧的对象的 ID。

    *   **假设输入与输出:**  先创建 10000 个 `A` 的实例并进行快照，记录最大的对象 ID。然后再次创建 10000 个 `A` 的实例并进行垃圾回收。再次进行快照，检查新创建的对象的 ID 是否都大于第一次快照的最大 ID。

5. **`TEST(HeapEntryIdsAndArrayShift)`:** 测试在数组执行 `shift()` 操作后，堆快照中数组及其元素（特别是内部的 `elements` 数组）的 ID 是否保持一致。

    *   **JavaScript 示例:**
        ```javascript
        function AnObject() {
            this.first = 'first';
            this.second = 'second';
        }
        var a = new Array();
        for (var i = 0; i < 10; ++i)
          a.push(new AnObject());
        a.shift();
        ```
        测试会比较 `shift()` 操作前后，数组对象 `a` 和其内部 `elements` 数组在两次快照中的 ID。

6. **`TEST(HeapEntryIdsAndGC)`:** 测试垃圾回收后，堆快照中对象的 ID 是否保持一致。它创建一些对象，进行快照，然后进行垃圾回收，再次进行快照，并比较两次快照中相同逻辑对象的 ID。

    *   **JavaScript 示例:**
        ```javascript
        function A() {}
        function B(x) { this.x = x; }
        var a = new A();
        var b = new B(a);
        ```
        测试会比较全局对象、构造函数 `A` 和 `B` 以及实例 `a` 和 `b` 在两次快照中的 ID。

7. **`TEST(HeapSnapshotJSONSerialization)`:** 测试堆快照是否可以正确序列化为 JSON 格式，并且验证了 JSON 数据的结构和内容。它创建了一些包含字符串的对象，并检查序列化后的 JSON 数据是否包含了这些字符串的正确表示。

    *   **代码逻辑推理:**  测试首先生成一个堆快照，然后将其序列化为 JSON。之后，它在 JavaScript 环境中解析这个 JSON，并验证其包含预期的字段（如 `snapshot`、`nodes`、`edges`、`locations`、`strings`）。然后，它使用 JavaScript 代码来导航 JSON 结构，找到特定字符串对象的位置，并验证其内容是否与原始字符串一致。

8. **`TEST(HeapSnapshotJSONSerializationAborting)`:** 测试在序列化堆快照到 JSON 过程中，如果输出流提前终止，序列化过程是否能正确处理。

9. **`TEST(HeapSnapshotObjectsStats)`:** 测试 V8 堆分析器能够跟踪堆对象的分配和释放，并提供统计信息更新。它创建和释放对象，并使用 `GetHeapStatsUpdate` 检查统计信息的更新情况，包括新增和释放的对象数量和大小。

10. **`TEST(HeapObjectIds)`:** 测试 V8 堆分析器能够为堆对象分配和管理 ID，即使在垃圾回收后，通过 `GetObjectId` 获取的 ID 仍然有效。它还测试了 `FindObjectById` 功能以及 `ClearObjectIds` 功能。

    *   **用户常见的编程错误:**  如果用户依赖于对象在垃圾回收后保持相同的内存地址，这将会导致问题。V8 的堆分析器通过稳定的对象 ID 来解决这个问题，允许在对象移动或被回收后仍然能追踪到它们。

11. **`TEST(HeapSnapshotGetNodeById)`:** 测试可以通过对象在堆快照中的 ID (`HeapGraphNode::GetId()`) 来重新获取该节点 (`HeapSnapshot::GetNodeById()`)。

12. **`TEST(HeapSnapshotGetSnapshotObjectId)`:** 测试可以通过 JavaScript 对象的句柄获取其在堆快照中的 ID，并且这个 ID 与堆快照节点对象的 ID 相匹配。

13. **`TEST(HeapSnapshotUnknownSnapshotObjectId)`:** 测试当使用 `kUnknownObjectId` 获取堆快照节点时，应该返回空指针。

14. **`TEST(TakeHeapSnapshotAborting)`:** 测试在生成堆快照的过程中，可以通过 `ActivityControl` 中止快照的生成。

15. **`TEST(TakeHeapSnapshotReportFinishOnce)`:** 测试在堆快照生成完成后，`ActivityControl` 的完成报告只会被调用一次。

16. **`TEST(EmbedderGraph)`:**  测试了嵌入器 (Embedder) 可以向堆快照中添加自定义的节点和边。这允许非 JavaScript 的宿主环境将其自身的对象图与 V8 的堆快照集成在一起。

**总结:**

这部分代码专注于测试 V8 堆快照功能的正确性和健壮性。它涵盖了快照对对象内部结构、弱引用、对象 ID 的管理、垃圾回收的影响、JSON 序列化、对象统计跟踪以及嵌入器扩展等方面的能力。这些测试确保了堆快照能够提供准确、可靠的堆信息，这对于内存泄漏分析、性能优化等至关重要。

### 提示词
```
这是目录为v8/test/cctest/test-heap-profiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-heap-profiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
* prop = map_table->GetChild(i);
    const v8::SnapshotObjectId to_node_id = prop->GetToNode()->GetId();
    if (to_node_id == k->GetId() || to_node_id == v->GetId()) {
      ++entries;
    }
  }
  CHECK_EQ(2, entries);
  const v8::HeapGraphNode* map_s =
      GetProperty(env->GetIsolate(), map, v8::HeapGraphEdge::kProperty, "str");
  CHECK(map_s);
  CHECK_EQ(s->GetId(), map_s->GetId());
}

TEST(HeapSnapshotMap) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  CompileRun(
      "function Z() { this.foo = {}; this.bar = 0; }\n"
      "z = new Z();\n");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  const v8::HeapGraphNode* z =
      GetProperty(env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "z");
  CHECK(z);
  const v8::HeapGraphNode* map =
      GetProperty(env->GetIsolate(), z, v8::HeapGraphEdge::kInternal, "map");
  CHECK(map);
  CHECK(
      GetProperty(env->GetIsolate(), map, v8::HeapGraphEdge::kInternal, "map"));
  CHECK(GetProperty(env->GetIsolate(), map, v8::HeapGraphEdge::kInternal,
                    "prototype"));
  const v8::HeapGraphNode* parent_map = GetProperty(
      env->GetIsolate(), map, v8::HeapGraphEdge::kInternal, "back_pointer");
  CHECK(parent_map);

  CHECK(GetProperty(env->GetIsolate(), map, v8::HeapGraphEdge::kInternal,
                    "back_pointer"));
  CHECK(GetProperty(env->GetIsolate(), map, v8::HeapGraphEdge::kInternal,
                    "descriptors"));
  CHECK(GetProperty(env->GetIsolate(), parent_map, v8::HeapGraphEdge::kWeak,
                    "transition"));
}

// Allow usages of v8::Object::GetPrototype() for now.
// TODO(https://crbug.com/333672197): remove.
START_ALLOW_USE_DEPRECATED()

TEST(HeapSnapshotInternalReferences) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> global_template =
      v8::ObjectTemplate::New(isolate);
  global_template->SetInternalFieldCount(2);
  LocalContext env(nullptr, global_template);
  v8::Local<v8::Object> global_proxy = env->Global();
  v8::Local<v8::Object> global = global_proxy->GetPrototype().As<v8::Object>();
  CHECK_EQ(2, global->InternalFieldCount());
  v8::Local<v8::Object> obj = v8::Object::New(isolate);
  global->SetInternalField(0, v8_num(17));
  global->SetInternalField(1, obj);
  v8::HeapProfiler* heap_profiler = isolate->GetHeapProfiler();
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global_node = GetGlobalObject(snapshot);
  // The first reference will not present, because it's a Smi.
  CHECK(!GetProperty(env->GetIsolate(), global_node,
                     v8::HeapGraphEdge::kInternal, "0"));
  // The second reference is to an object.
  CHECK(GetProperty(env->GetIsolate(), global_node,
                    v8::HeapGraphEdge::kInternal, "1"));
}

// Allow usages of v8::Object::GetPrototype() for now.
// TODO(https://crbug.com/333672197): remove.
END_ALLOW_USE_DEPRECATED()

TEST(HeapSnapshotEphemeron) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  CompileRun(
      "class KeyClass{};\n"
      "class ValueClass{};\n"
      "var wm = new WeakMap();\n"
      "function foo(key) { wm.set(key, new ValueClass()); }\n"
      "var key = new KeyClass();\n"
      "foo(key);");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);

  const v8::HeapGraphNode* key = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "key");
  CHECK(key);
  const v8::HeapGraphNode* weakmap = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "wm");
  CHECK(weakmap);
  const v8::HeapGraphNode* weakmap_table = GetProperty(
      env->GetIsolate(), weakmap, v8::HeapGraphEdge::kInternal, "table");
  CHECK(weakmap_table);
  bool success = false;
  for (int i = 0, count = key->GetChildrenCount(); i < count; ++i) {
    const v8::HeapGraphEdge* edge = key->GetChild(i);
    const v8::HeapGraphNode* child = edge->GetToNode();
    if (!strcmp("ValueClass", GetName(child))) {
      v8::String::Utf8Value edge_name(CcTest::isolate(), edge->GetName());
      std::stringstream end_of_label;
      end_of_label << "/ part of key (KeyClass @" << key->GetId()
                   << ") -> value (ValueClass @" << child->GetId()
                   << ") pair in WeakMap (table @" << weakmap_table->GetId()
                   << ")";
      CHECK(EndsWith(*edge_name, end_of_label.str().c_str()));
      success = true;
      break;
    }
  }
  CHECK(success);
}

TEST(HeapSnapshotAddressReuse) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  CompileRun(
      "function A() {}\n"
      "var a = [];\n"
      "for (var i = 0; i < 10000; ++i)\n"
      "  a[i] = new A();\n");
  const v8::HeapSnapshot* snapshot1 = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot1));
  v8::SnapshotObjectId maxId1 = snapshot1->GetMaxSnapshotJSObjectId();

  CompileRun(
      "for (var i = 0; i < 10000; ++i)\n"
      "  a[i] = new A();\n");
  i::heap::InvokeMajorGC(CcTest::heap());

  const v8::HeapSnapshot* snapshot2 = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot2));
  const v8::HeapGraphNode* global2 = GetGlobalObject(snapshot2);

  const v8::HeapGraphNode* array_node = GetProperty(
      env->GetIsolate(), global2, v8::HeapGraphEdge::kProperty, "a");
  CHECK(array_node);
  int wrong_count = 0;
  for (int i = 0, count = array_node->GetChildrenCount(); i < count; ++i) {
    const v8::HeapGraphEdge* prop = array_node->GetChild(i);
    if (prop->GetType() != v8::HeapGraphEdge::kElement)
      continue;
    v8::SnapshotObjectId id = prop->GetToNode()->GetId();
    if (id < maxId1)
      ++wrong_count;
  }
  CHECK_EQ(0, wrong_count);
}


TEST(HeapEntryIdsAndArrayShift) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  CompileRun(
      "function AnObject() {\n"
      "    this.first = 'first';\n"
      "    this.second = 'second';\n"
      "}\n"
      "var a = new Array();\n"
      "for (var i = 0; i < 10; ++i)\n"
      "  a.push(new AnObject());\n");
  const v8::HeapSnapshot* snapshot1 = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot1));

  CompileRun(
      "for (var i = 0; i < 1; ++i)\n"
      "  a.shift();\n");

  i::heap::InvokeMajorGC(CcTest::heap());

  const v8::HeapSnapshot* snapshot2 = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot2));

  const v8::HeapGraphNode* global1 = GetGlobalObject(snapshot1);
  const v8::HeapGraphNode* global2 = GetGlobalObject(snapshot2);
  CHECK_NE(0u, global1->GetId());
  CHECK_EQ(global1->GetId(), global2->GetId());

  const v8::HeapGraphNode* a1 = GetProperty(env->GetIsolate(), global1,
                                            v8::HeapGraphEdge::kProperty, "a");
  CHECK(a1);
  const v8::HeapGraphNode* k1 = GetProperty(
      env->GetIsolate(), a1, v8::HeapGraphEdge::kInternal, "elements");
  CHECK(k1);
  const v8::HeapGraphNode* a2 = GetProperty(env->GetIsolate(), global2,
                                            v8::HeapGraphEdge::kProperty, "a");
  CHECK(a2);
  const v8::HeapGraphNode* k2 = GetProperty(
      env->GetIsolate(), a2, v8::HeapGraphEdge::kInternal, "elements");
  CHECK(k2);

  CHECK_EQ(a1->GetId(), a2->GetId());
  CHECK_EQ(k1->GetId(), k2->GetId());
}


TEST(HeapEntryIdsAndGC) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  CompileRun(
      "function A() {}\n"
      "function B(x) { this.x = x; }\n"
      "var a = new A();\n"
      "var b = new B(a);");
  const v8::HeapSnapshot* snapshot1 = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot1));

  i::heap::InvokeMajorGC(CcTest::heap());

  const v8::HeapSnapshot* snapshot2 = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot2));

  CHECK_GT(snapshot1->GetMaxSnapshotJSObjectId(), 7000u);
  CHECK(snapshot1->GetMaxSnapshotJSObjectId() <=
        snapshot2->GetMaxSnapshotJSObjectId());

  const v8::HeapGraphNode* global1 = GetGlobalObject(snapshot1);
  const v8::HeapGraphNode* global2 = GetGlobalObject(snapshot2);
  CHECK_NE(0u, global1->GetId());
  CHECK_EQ(global1->GetId(), global2->GetId());
  const v8::HeapGraphNode* A1 = GetProperty(env->GetIsolate(), global1,
                                            v8::HeapGraphEdge::kProperty, "A");
  CHECK(A1);
  const v8::HeapGraphNode* A2 = GetProperty(env->GetIsolate(), global2,
                                            v8::HeapGraphEdge::kProperty, "A");
  CHECK(A2);
  CHECK_NE(0u, A1->GetId());
  CHECK_EQ(A1->GetId(), A2->GetId());
  const v8::HeapGraphNode* B1 = GetProperty(env->GetIsolate(), global1,
                                            v8::HeapGraphEdge::kProperty, "B");
  CHECK(B1);
  const v8::HeapGraphNode* B2 = GetProperty(env->GetIsolate(), global2,
                                            v8::HeapGraphEdge::kProperty, "B");
  CHECK(B2);
  CHECK_NE(0u, B1->GetId());
  CHECK_EQ(B1->GetId(), B2->GetId());
  const v8::HeapGraphNode* a1 = GetProperty(env->GetIsolate(), global1,
                                            v8::HeapGraphEdge::kProperty, "a");
  CHECK(a1);
  const v8::HeapGraphNode* a2 = GetProperty(env->GetIsolate(), global2,
                                            v8::HeapGraphEdge::kProperty, "a");
  CHECK(a2);
  CHECK_NE(0u, a1->GetId());
  CHECK_EQ(a1->GetId(), a2->GetId());
  const v8::HeapGraphNode* b1 = GetProperty(env->GetIsolate(), global1,
                                            v8::HeapGraphEdge::kProperty, "b");
  CHECK(b1);
  const v8::HeapGraphNode* b2 = GetProperty(env->GetIsolate(), global2,
                                            v8::HeapGraphEdge::kProperty, "b");
  CHECK(b2);
  CHECK_NE(0u, b1->GetId());
  CHECK_EQ(b1->GetId(), b2->GetId());
}

TEST(HeapSnapshotJSONSerialization) {
  v8::Isolate* isolate = CcTest::isolate();
  LocalContext env;
  v8::HandleScope scope(isolate);
  v8::HeapProfiler* heap_profiler = isolate->GetHeapProfiler();

#define STRING_LITERAL_FOR_TEST \
  "\"String \\n\\r\\u0008\\u0081\\u0101\\u0801\\u8001\""
  CompileRun(
      "function A(s) { this.s = s; }\n"
      "function B(x) { this.x = x; }\n"
      "var a = new A(" STRING_LITERAL_FOR_TEST ");\n"
      "var b = new B(a);");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));

  v8::internal::TestJSONStream stream;
  snapshot->Serialize(&stream, v8::HeapSnapshot::kJSON);
  CHECK_GT(stream.size(), 0);
  CHECK_EQ(1, stream.eos_signaled());
  v8::base::ScopedVector<char> json(stream.size());
  stream.WriteTo(json);

  // Verify that snapshot string is valid JSON.
  v8::internal::OneByteResource* json_res =
      new v8::internal::OneByteResource(json);
  v8::Local<v8::String> json_string =
      v8::String::NewExternalOneByte(env->GetIsolate(), json_res)
          .ToLocalChecked();
  v8::Local<v8::Context> context = v8::Context::New(env->GetIsolate());
  v8::Local<v8::Value> snapshot_parse_result =
      v8::JSON::Parse(context, json_string).ToLocalChecked();
  CHECK(snapshot_parse_result->IsObject());

  // Verify that snapshot object has required fields.
  v8::Local<v8::Object> parsed_snapshot =
      snapshot_parse_result.As<v8::Object>();
  CHECK(parsed_snapshot->Get(env.local(), v8_str("snapshot"))
            .ToLocalChecked()
            ->IsObject());
  CHECK(parsed_snapshot->Get(env.local(), v8_str("nodes"))
            .ToLocalChecked()
            ->IsArray());
  CHECK(parsed_snapshot->Get(env.local(), v8_str("edges"))
            .ToLocalChecked()
            ->IsArray());
  CHECK(parsed_snapshot->Get(env.local(), v8_str("locations"))
            .ToLocalChecked()
            ->IsArray());
  CHECK(parsed_snapshot->Get(env.local(), v8_str("strings"))
            .ToLocalChecked()
            ->IsArray());

  // Get node and edge "member" offsets.
  env->Global()->Set(env.local(), v8_str("parsed"), parsed_snapshot).FromJust();
  v8::Local<v8::Value> meta_analysis_result = CompileRun(
      "var meta = parsed.snapshot.meta;\n"
      "var edge_count_offset = meta.node_fields.indexOf('edge_count');\n"
      "var node_fields_count = meta.node_fields.length;\n"
      "var edge_fields_count = meta.edge_fields.length;\n"
      "var edge_type_offset = meta.edge_fields.indexOf('type');\n"
      "var edge_name_offset = meta.edge_fields.indexOf('name_or_index');\n"
      "var edge_to_node_offset = meta.edge_fields.indexOf('to_node');\n"
      "var property_type ="
      "    meta.edge_types[edge_type_offset].indexOf('property');\n"
      "var shortcut_type ="
      "    meta.edge_types[edge_type_offset].indexOf('shortcut');\n"
      "var node_count = parsed.nodes.length / node_fields_count;\n"
      "var first_edge_indexes = parsed.first_edge_indexes = [];\n"
      "for (var i = 0, first_edge_index = 0; i < node_count; ++i) {\n"
      "  first_edge_indexes[i] = first_edge_index;\n"
      "  first_edge_index += edge_fields_count *\n"
      "      parsed.nodes[i * node_fields_count + edge_count_offset];\n"
      "}\n"
      "first_edge_indexes[node_count] = first_edge_index;\n");
  CHECK(!meta_analysis_result.IsEmpty());

  // A helper function for processing encoded nodes.
  CompileRun(
      "function GetChildPosByProperty(pos, prop_name, prop_type) {\n"
      "  var nodes = parsed.nodes;\n"
      "  var edges = parsed.edges;\n"
      "  var strings = parsed.strings;\n"
      "  var node_ordinal = pos / node_fields_count;\n"
      "  for (var i = parsed.first_edge_indexes[node_ordinal],\n"
      "      count = parsed.first_edge_indexes[node_ordinal + 1];\n"
      "      i < count; i += edge_fields_count) {\n"
      "    if (edges[i + edge_type_offset] === prop_type\n"
      "        && strings[edges[i + edge_name_offset]] === prop_name)\n"
      "      return edges[i + edge_to_node_offset];\n"
      "  }\n"
      "  return null;\n"
      "}\n");
  // Get the string index using the path: <root> -> <global>.b.x.s
  v8::Local<v8::Value> string_obj_pos_val = CompileRun(
      "GetChildPosByProperty(\n"
      "  GetChildPosByProperty(\n"
      "    GetChildPosByProperty("
      "      parsed.edges[edge_fields_count + edge_to_node_offset],"
      "      \"b\", property_type),\n"
      "    \"x\", property_type),"
      "  \"s\", property_type)");
  CHECK(!string_obj_pos_val.IsEmpty());
  int string_obj_pos = static_cast<int>(
      string_obj_pos_val->ToNumber(env.local()).ToLocalChecked()->Value());
  v8::Local<v8::Object> nodes_array =
      parsed_snapshot->Get(env.local(), v8_str("nodes"))
          .ToLocalChecked()
          ->ToObject(env.local())
          .ToLocalChecked();
  int string_index =
      static_cast<int>(nodes_array->Get(env.local(), string_obj_pos + 1)
                           .ToLocalChecked()
                           ->ToNumber(env.local())
                           .ToLocalChecked()
                           ->Value());
  CHECK_GT(string_index, 0);
  v8::Local<v8::Object> strings_array =
      parsed_snapshot->Get(env.local(), v8_str("strings"))
          .ToLocalChecked()
          ->ToObject(env.local())
          .ToLocalChecked();
  v8::Local<v8::String> string = strings_array->Get(env.local(), string_index)
                                     .ToLocalChecked()
                                     ->ToString(env.local())
                                     .ToLocalChecked();
  v8::Local<v8::String> ref_string = CompileRun(STRING_LITERAL_FOR_TEST)
                                         ->ToString(env.local())
                                         .ToLocalChecked();
#undef STRING_LITERAL_FOR_TEST
  CHECK_EQ(0, strcmp(*v8::String::Utf8Value(env->GetIsolate(), ref_string),
                     *v8::String::Utf8Value(env->GetIsolate(), string)));
}


TEST(HeapSnapshotJSONSerializationAborting) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  v8::internal::TestJSONStream stream(5);
  snapshot->Serialize(&stream, v8::HeapSnapshot::kJSON);
  CHECK_GT(stream.size(), 0);
  CHECK_EQ(0, stream.eos_signaled());
}

namespace {

class TestStatsStream : public v8::OutputStream {
 public:
  TestStatsStream()
    : eos_signaled_(0),
      updates_written_(0),
      entries_count_(0),
      entries_size_(0),
      intervals_count_(0),
      first_interval_index_(-1) { }
  TestStatsStream(const TestStatsStream& stream) V8_NOEXCEPT = default;
  ~TestStatsStream() override = default;
  void EndOfStream() override { ++eos_signaled_; }
  WriteResult WriteAsciiChunk(char* buffer, int chars_written) override {
    UNREACHABLE();
  }
  WriteResult WriteHeapStatsChunk(v8::HeapStatsUpdate* buffer,
                                  int updates_written) override {
    ++intervals_count_;
    CHECK(updates_written);
    updates_written_ += updates_written;
    entries_count_ = 0;
    if (first_interval_index_ == -1 && updates_written != 0)
      first_interval_index_ = buffer[0].index;
    for (int i = 0; i < updates_written; ++i) {
      entries_count_ += buffer[i].count;
      entries_size_ += buffer[i].size;
    }

    return kContinue;
  }
  int eos_signaled() { return eos_signaled_; }
  int updates_written() { return updates_written_; }
  uint32_t entries_count() const { return entries_count_; }
  uint32_t entries_size() const { return entries_size_; }
  int intervals_count() const { return intervals_count_; }
  int first_interval_index() const { return first_interval_index_; }

 private:
  int eos_signaled_;
  int updates_written_;
  uint32_t entries_count_;
  uint32_t entries_size_;
  int intervals_count_;
  int first_interval_index_;
};

}  // namespace

static TestStatsStream GetHeapStatsUpdate(
    v8::HeapProfiler* heap_profiler,
    v8::SnapshotObjectId* object_id = nullptr) {
  TestStatsStream stream;
  int64_t timestamp = -1;
  v8::SnapshotObjectId last_seen_id =
      heap_profiler->GetHeapStats(&stream, &timestamp);
  if (object_id)
    *object_id = last_seen_id;
  CHECK_NE(-1, timestamp);
  CHECK_EQ(1, stream.eos_signaled());
  return stream;
}


TEST(HeapSnapshotObjectsStats) {
  // Concurrent allocation and conservative stack scanning might break results.
  i::v8_flags.stress_concurrent_allocation = false;
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      CcTest::heap());

  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::HeapProfiler* heap_profiler = isolate->GetHeapProfiler();

  heap_profiler->StartTrackingHeapObjects();
  // We have to call GC 6 times. In other case the garbage will be
  // the reason of flakiness.
  for (int i = 0; i < 6; ++i) {
    i::heap::InvokeMajorGC(CcTest::heap());
  }

  v8::SnapshotObjectId initial_id;
  {
    // Single chunk of data expected in update. Initial data.
    TestStatsStream stats_update = GetHeapStatsUpdate(heap_profiler,
                                                      &initial_id);
    CHECK_EQ(1, stats_update.intervals_count());
    CHECK_EQ(1, stats_update.updates_written());
    CHECK_LT(0u, stats_update.entries_size());
    CHECK_EQ(0, stats_update.first_interval_index());
  }

  // No data expected in update because nothing has happened.
  v8::SnapshotObjectId same_id;
  CHECK_EQ(0, GetHeapStatsUpdate(heap_profiler, &same_id).updates_written());
  CHECK_EQ(initial_id, same_id);

  {
    v8::SnapshotObjectId additional_string_id;
    v8::HandleScope inner_scope_1(isolate);
    v8_str("string1");
    {
      // Single chunk of data with one new entry expected in update.
      TestStatsStream stats_update = GetHeapStatsUpdate(heap_profiler,
                                                        &additional_string_id);
      CHECK_LT(same_id, additional_string_id);
      CHECK_EQ(1, stats_update.intervals_count());
      CHECK_EQ(1, stats_update.updates_written());
      CHECK_LT(0u, stats_update.entries_size());
      CHECK_EQ(1u, stats_update.entries_count());
      CHECK_EQ(2, stats_update.first_interval_index());
    }

    // No data expected in update because nothing happened.
    v8::SnapshotObjectId last_id;
    CHECK_EQ(0, GetHeapStatsUpdate(heap_profiler, &last_id).updates_written());
    CHECK_EQ(additional_string_id, last_id);

    {
      v8::HandleScope inner_scope_2(isolate);
      v8_str("string2");

      uint32_t entries_size;
      {
        v8::HandleScope inner_scope_3(isolate);
        v8_str("string3");
        v8_str("string4");

        {
          // Single chunk of data with three new entries expected in update.
          TestStatsStream stats_update = GetHeapStatsUpdate(heap_profiler);
          CHECK_EQ(1, stats_update.intervals_count());
          CHECK_EQ(1, stats_update.updates_written());
          CHECK_LT(0u, entries_size = stats_update.entries_size());
          CHECK_EQ(3u, stats_update.entries_count());
          CHECK_EQ(4, stats_update.first_interval_index());
        }
      }

      {
        // Single chunk of data with two left entries expected in update.
        TestStatsStream stats_update = GetHeapStatsUpdate(heap_profiler);
        CHECK_EQ(1, stats_update.intervals_count());
        CHECK_EQ(1, stats_update.updates_written());
        CHECK_GT(entries_size, stats_update.entries_size());
        CHECK_EQ(1u, stats_update.entries_count());
        // Two strings from forth interval were released.
        CHECK_EQ(4, stats_update.first_interval_index());
      }
    }

    {
      // Single chunk of data with 0 left entries expected in update.
      TestStatsStream stats_update = GetHeapStatsUpdate(heap_profiler);
      CHECK_EQ(1, stats_update.intervals_count());
      CHECK_EQ(1, stats_update.updates_written());
      CHECK_EQ(0u, stats_update.entries_size());
      CHECK_EQ(0u, stats_update.entries_count());
      // The last string from forth interval was released.
      CHECK_EQ(4, stats_update.first_interval_index());
    }
  }
  {
    // Single chunk of data with 0 left entries expected in update.
    TestStatsStream stats_update = GetHeapStatsUpdate(heap_profiler);
    CHECK_EQ(1, stats_update.intervals_count());
    CHECK_EQ(1, stats_update.updates_written());
    CHECK_EQ(0u, stats_update.entries_size());
    CHECK_EQ(0u, stats_update.entries_count());
    // The only string from the second interval was released.
    CHECK_EQ(2, stats_update.first_interval_index());
  }

  // With conservative stack scanning disabled and with direct locals, a
  // v8::Local<v8::Array> here would be reclaimed by GetHeapStatsUpdate.
  v8::Persistent<v8::Array> array(isolate, v8::Array::New(isolate));
  CHECK_EQ(0u, array.Get(isolate)->Length());
  // Force array's buffer allocation.
  array.Get(isolate)->Set(env.local(), 2, v8_num(7)).FromJust();

  uint32_t entries_size;
  {
    // Single chunk of data with 2 entries expected in update.
    TestStatsStream stats_update = GetHeapStatsUpdate(heap_profiler);
    CHECK_EQ(1, stats_update.intervals_count());
    CHECK_EQ(1, stats_update.updates_written());
    CHECK_LT(0u, entries_size = stats_update.entries_size());
    // They are the array and its buffer.
    CHECK_EQ(2u, stats_update.entries_count());
    CHECK_EQ(8, stats_update.first_interval_index());
  }

  for (int i = 0; i < 100; ++i)
    array.Get(isolate)->Set(env.local(), i, v8_num(i)).FromJust();

  {
    // Single chunk of data with 1 entry expected in update.
    TestStatsStream stats_update = GetHeapStatsUpdate(heap_profiler);
    CHECK_EQ(1, stats_update.intervals_count());
    // The first interval was changed because old buffer was collected.
    // The second interval was changed because new buffer was allocated.
    CHECK_EQ(2, stats_update.updates_written());
    CHECK_LT(entries_size, stats_update.entries_size());
    CHECK_EQ(2u, stats_update.entries_count());
    CHECK_EQ(8, stats_update.first_interval_index());
  }

  heap_profiler->StopTrackingHeapObjects();
}


TEST(HeapObjectIds) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  const int kLength = 10;
  v8::Local<v8::Object> objects[kLength];
  v8::SnapshotObjectId ids[kLength];

  heap_profiler->StartTrackingHeapObjects(false);

  for (int i = 0; i < kLength; i++) {
    objects[i] = v8::Object::New(isolate);
  }
  GetHeapStatsUpdate(heap_profiler);

  for (int i = 0; i < kLength; i++) {
    v8::SnapshotObjectId id = heap_profiler->GetObjectId(objects[i]);
    CHECK_NE(v8::HeapProfiler::kUnknownObjectId, id);
    ids[i] = id;
  }

  heap_profiler->StopTrackingHeapObjects();
  i::heap::InvokeMemoryReducingMajorGCs(CcTest::heap());

  for (int i = 0; i < kLength; i++) {
    v8::SnapshotObjectId id = heap_profiler->GetObjectId(objects[i]);
    CHECK_EQ(ids[i], id);
    v8::Local<v8::Value> obj = heap_profiler->FindObjectById(ids[i]);
    CHECK(objects[i]->Equals(env.local(), obj).FromJust());
  }

  heap_profiler->ClearObjectIds();
  for (int i = 0; i < kLength; i++) {
    v8::SnapshotObjectId id = heap_profiler->GetObjectId(objects[i]);
    CHECK_EQ(v8::HeapProfiler::kUnknownObjectId, id);
    v8::Local<v8::Value> obj = heap_profiler->FindObjectById(ids[i]);
    CHECK(obj.IsEmpty());
  }
}


static void CheckChildrenIds(const v8::HeapSnapshot* snapshot,
                             const v8::HeapGraphNode* node,
                             int level, int max_level) {
  if (level > max_level) return;
  CHECK_EQ(node, snapshot->GetNodeById(node->GetId()));
  for (int i = 0, count = node->GetChildrenCount(); i < count; ++i) {
    const v8::HeapGraphEdge* prop = node->GetChild(i);
    const v8::HeapGraphNode* child =
        snapshot->GetNodeById(prop->GetToNode()->GetId());
    CHECK_EQ(prop->GetToNode()->GetId(), child->GetId());
    CHECK_EQ(prop->GetToNode(), child);
    CheckChildrenIds(snapshot, child, level + 1, max_level);
  }
}


TEST(HeapSnapshotGetNodeById) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* root = snapshot->GetRoot();
  CheckChildrenIds(snapshot, root, 0, 3);
  // Check a big id, which should not exist yet.
  CHECK(!snapshot->GetNodeById(0x1000000UL));
}


TEST(HeapSnapshotGetSnapshotObjectId) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  CompileRun("globalObject = {};\n");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  const v8::HeapGraphNode* global_object = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "globalObject");
  CHECK(global_object);

  v8::Local<v8::Value> globalObjectHandle =
      env->Global()->Get(env.local(), v8_str("globalObject")).ToLocalChecked();
  CHECK(!globalObjectHandle.IsEmpty());
  CHECK(globalObjectHandle->IsObject());

  v8::SnapshotObjectId id = heap_profiler->GetObjectId(globalObjectHandle);
  CHECK_NE(v8::HeapProfiler::kUnknownObjectId, id);
  CHECK_EQ(id, global_object->GetId());
}


TEST(HeapSnapshotUnknownSnapshotObjectId) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  CompileRun("globalObject = {};\n");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* node =
      snapshot->GetNodeById(v8::HeapProfiler::kUnknownObjectId);
  CHECK(!node);
}


namespace {

class TestActivityControl : public v8::ActivityControl {
 public:
  explicit TestActivityControl(int abort_count)
      : done_(0),
        total_(0),
        abort_count_(abort_count),
        reported_finish_(false) {}
  ControlOption ReportProgressValue(uint32_t done, uint32_t total) override {
    done_ = done;
    total_ = total;
    CHECK_LE(done_, total_);
    if (done_ == total_) {
      CHECK(!reported_finish_);
      reported_finish_ = true;
    }
    return --abort_count_ != 0 ? kContinue : kAbort;
  }
  int done() { return done_; }
  int total() { return total_; }

 private:
  int done_;
  int total_;
  int abort_count_;
  bool reported_finish_;
};

}  // namespace


TEST(TakeHeapSnapshotAborting) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  const int snapshots_count = heap_profiler->GetSnapshotCount();
  TestActivityControl aborting_control(1);
  const v8::HeapSnapshot* no_snapshot =
      heap_profiler->TakeHeapSnapshot(&aborting_control);
  CHECK(!no_snapshot);
  CHECK_EQ(snapshots_count, heap_profiler->GetSnapshotCount());
  CHECK_GT(aborting_control.total(), aborting_control.done());

  TestActivityControl control(-1);  // Don't abort.
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot(&control);
  CHECK(ValidateSnapshot(snapshot));

  CHECK(snapshot);
  CHECK_EQ(snapshots_count + 1, heap_profiler->GetSnapshotCount());
  CHECK_EQ(control.total(), control.done());
  CHECK_GT(control.total(), 0);
}

TEST(TakeHeapSnapshotReportFinishOnce) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  TestActivityControl control(-1);
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot(&control);
  CHECK(ValidateSnapshot(snapshot));
  CHECK_EQ(control.total(), control.done());
  CHECK_GT(control.total(), 0);
}

namespace {

class EmbedderGraphBuilder : public v8::PersistentHandleVisitor {
 public:
  class Node : public v8::EmbedderGraph::Node {
   public:
    Node(const char* name, size_t size) : name_(name), size_(size) {}
    // v8::EmbedderGraph::Node
    const char* Name() override { return name_; }
    size_t SizeInBytes() override { return size_; }

   private:
    const char* name_;
    size_t size_;
  };

  class Group : public Node {
   public:
    explicit Group(const char* name) : Node(name, 0) {}
    // v8::EmbedderGraph::EmbedderNode
    bool IsRootNode() override { return true; }
  };

  EmbedderGraphBuilder(v8::Isolate* isolate, v8::EmbedderGraph* graph)
      : isolate_(isolate), graph_(graph) {
    classid_to_group_[0] = nullptr;
    classid_to_group_[1] =
        graph->AddNode(std::unique_ptr<Group>(new Group("aaa-group")));
    classid_to_group_[2] =
        graph->AddNode(std::unique_ptr<Group>(new Group("ccc-group")));
  }

  static void BuildEmbedderGraph(v8::Isolate* isolate, v8::EmbedderGraph* graph,
                                 void* data) {
    EmbedderGraphBuilder builder(isolate, graph);
    reinterpret_cast<i::Isolate*>(isolate)
        ->global_handles()
        ->IterateAllRootsForTesting(&builder);
  }

  void VisitPersistentHandle(v8::Persistent<v8::Value>* value,
                             uint16_t class_id) override {
    v8::Local<v8::Value> wrapper = v8::Local<v8::Value>::New(
        isolate_, v8::Persistent<v8::Value>::Cast(*value));
    if (class_id == 1) {
      if (wrapper->IsString()) {
        v8::String::Utf8Value utf8(CcTest::isolate(), wrapper);
        DCHECK(!strcmp(*utf8, "AAA") || !strcmp(*utf8, "BBB"));
        v8::EmbedderGraph::Node* node = graph_->V8Node(wrapper);
        v8::EmbedderGraph::Node* group = classid_to_group_[1];
        graph_->AddEdge(node, group);
        graph_->AddEdge(group, node);
      }
    } else if (class_id == 2) {
      if (wrapper->IsString()) {
        v8::String::Utf8Value utf8(CcTest::isolate(), wrapper);
        DCHECK(!strcmp(*utf8, "CCC"));
        v8::EmbedderGraph::Node* node = graph_->V8Node(wrapper);
        v8::EmbedderGraph::Node* group = classid_to_group_[2];
        graph_->AddEdge(node, group);
        graph_->AddEdge(group, node);
      }
    }
  }

 private:
  v8::Isolat
```