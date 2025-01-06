Response:
The user wants me to analyze a C++ source code file for V8 related to heap profiling.
I need to identify its functionality, check if it could be a Torque file (based on the .tq extension, which it isn't), and if it's related to Javascript, provide a Javascript example.
If there's code logic, I should provide example input and output.
I also need to point out common programming errors the code might help to detect.
Finally, I need to summarize the functionality of this specific part of the code.

**Plan:**

1. **Overall Functionality:**  The file `test-heap-profiler.cc` contains C++ tests for the V8 heap profiler. These tests verify the correctness of the heap snapshots generated by the profiler. They check various aspects of the heap structure and object relationships.
2. **Torque Check:** The filename ends in `.cc`, not `.tq`, so it's not a Torque file.
3. **Javascript Relation:** Heap profiling is directly related to Javascript as it analyzes the memory used by Javascript code. The tests in this file use Javascript code snippets to create specific heap structures and then verify the profiler's output.
4. **Javascript Example:** I will provide a simple Javascript example that would be relevant to the heap profiler, focusing on creating objects and relationships that the tests might be examining.
5. **Code Logic and Input/Output:** The code consists of individual test cases (`TEST` macros). Each test has its own setup and assertions. I will select a test case to explain its logic and what it verifies. The input is the state of the V8 heap after running the Javascript code within the test. The output is the assertion results (pass or fail).
6. **Common Programming Errors:** Heap profilers are used to diagnose memory leaks and unexpected object retention. I will provide examples of Javascript coding errors that can lead to such issues and how a heap profiler (and these tests) can help identify them.
7. **Summary of Functionality (Part 4):** I will review the specific test cases in the provided snippet and summarize the aspects of heap profiling they are testing.
这是对V8源代码文件 `v8/test/cctest/test-heap-profiler.cc` 的第4部分分析。

**功能归纳:**

这部分代码主要包含了一系列针对 V8 堆分析器（Heap Profiler）的 C++ 测试用例。这些测试用例旨在验证堆快照（Heap Snapshot）的正确性和完整性，确保堆分析器能够准确地反映 V8 堆的内部结构和对象之间的关系。

**具体功能点:**

* **弱全局句柄（Weak Global Handles）:**  `TEST(WeakGlobalHandle)` 验证堆快照是否能正确地反映弱全局句柄的存在。
* **SFI 和 JSFunction 的弱引用：** `TEST(SfiAndJsFunctionWeakRefs)` 检查堆快照中脚本帧信息（SFI）和 JS 函数是否被正确地处理，特别是它们是否会产生不必要的弱引用。
* **所有强 GC Roots 都有名称：** `TEST(AllStrongGcRootsHaveNames)` 确保堆快照中所有强垃圾回收根节点都有名称，方便理解和调试。
* **没有到非必要条目的引用：** `TEST(NoRefsToNonEssentialEntries)` 验证堆快照中是否避免引用一些非必要的内部对象属性，例如 `properties` 和 `elements`，以减少快照的噪音。
* **Map 对象包含描述符和转换信息：** `TEST(MapHasDescriptorsAndTransitions)` 检查堆快照中 `Map` 对象是否包含了指向其描述符和转换信息的链接。
* **共享上下文中的大量局部变量：** `TEST(ManyLocalsInSharedContext)` 测试在具有大量局部变量的共享上下文中，堆快照是否能正确捕捉到这些变量。
* **分配站点可见性：** `TEST(AllocationSitesAreVisible)` 验证堆快照是否能够显示对象的分配站点信息，这对于性能分析和调试很有用。
* **JSFunction 包含代码链接：** `TEST(JSFunctionHasCodeLink)` 确保堆快照中 `JSFunction` 对象能够链接到其对应的代码对象。
* **检查代码对象名称：** `TEST(CheckCodeNames)` 验证堆快照中内置代码对象（Builtin Code）的命名是否正确。
* **跟踪堆分配（带和不带内联）：** `TEST(TrackHeapAllocationsWithInlining)` 和 `TEST(TrackHeapAllocationsWithoutInlining)` 测试堆分析器在启用和禁用函数内联的情况下，是否能够正确跟踪堆对象的分配。
* **跟踪 Bump Pointer 分配：** `TEST(TrackBumpPointerAllocations)`  测试堆分析器是否能区分并通过 Bump Pointer 进行的快速对象分配。
* **跟踪 V8 API 分配：** `TEST(TrackV8ApiAllocation)` 验证通过 V8 C++ API 创建的对象是否也能被堆分析器跟踪。
* **ArrayBuffer 和 ArrayBufferView：** `TEST(ArrayBufferAndArrayBufferView)` 检查堆快照是否能正确表示 `ArrayBuffer` 和 `ArrayBufferView` 及其内部结构（例如 `backing_store`）。
* **共享 ArrayBuffer 的 Backing Store：** `TEST(ArrayBufferSharedBackingStore)` 验证当多个 `ArrayBuffer` 共享同一个 `backing_store` 时，堆快照是否能正确反映这种共享关系。
* **弱容器：** `TEST(WeakContainers)`  检查堆快照是否能正确处理弱容器，例如与优化代码相关的依赖代码（dependent code）。
* **JSPromise：** `TEST(JSPromise)` 验证堆快照是否能正确表示 `Promise` 对象及其内部状态（例如 `reactions_or_result`）。
* **堆快照的脚本上下文：** `TEST(HeapSnapshotScriptContext)`  测试堆快照是否包含了脚本上下文的信息，使得可以追踪到在特定上下文中创建的对象。
* **嵌入器图（Embedder Graph）：** `TEST(EmbedderGraph)` 和 `TEST(EmbedderGraphWithNamedEdges)` 测试了 V8 的嵌入器可以向堆分析器提供额外的图信息，以便在堆快照中包含非 V8 管理的对象及其关系。

**关于文件类型和 Javascript 关系:**

* **文件类型:** `v8/test/cctest/test-heap-profiler.cc` 以 `.cc` 结尾，表明它是一个 C++ 源代码文件，而不是 Torque 文件（`.tq`）。
* **Javascript 关系:**  `v8/test/cctest/test-heap-profiler.cc` 的功能与 Javascript 密切相关。堆分析器的目的是分析 Javascript 代码运行时在 V8 堆上创建的对象和它们之间的关系。这些 C++ 测试用例通过 V8 的测试框架执行 Javascript 代码，然后断言生成的堆快照是否符合预期。

**Javascript 示例:**

以下 Javascript 代码展示了一些与这些测试用例相关的概念：

```javascript
// 创建一个普通对象
let obj = { a: 1 };

// 创建一个函数
function myFunction(x) {
  return x * 2;
}

// 创建一个 Promise
let myPromise = new Promise((resolve, reject) => {
  setTimeout(() => {
    resolve("done");
  }, 100);
});

// 创建一个 ArrayBuffer 和 Uint32Array
let buffer = new ArrayBuffer(16);
let uint32Array = new Uint32Array(buffer);

// 创建一个 WeakMap
let weakMap = new WeakMap();
let key = {};
weakMap.set(key, "value");

// 创建一个闭包
function createCounter() {
  let count = 0;
  return function() {
    count++;
    return count;
  };
}
let counter = createCounter();
```

这个示例展示了创建各种 Javascript 对象的过程，包括普通对象、函数、Promise、ArrayBuffer 及其视图、WeakMap 和闭包。这些都是堆分析器需要跟踪和表示的对象类型。

**代码逻辑推理和假设输入/输出:**

以 `TEST(WeakGlobalHandle)` 为例：

**假设输入:**  一个 V8 隔离（Isolate）环境，其中没有创建弱全局句柄。然后，创建一个新的对象并为其创建一个弱全局句柄。

**代码逻辑:**

1. `CHECK(!HasWeakGlobalHandle());`:  调用 `HasWeakGlobalHandle` 函数，该函数会拍摄堆快照并检查是否存在弱全局句柄。在没有创建弱全局句柄的情况下，该函数应该返回 `false`，断言通过。
2. `v8::Global<v8::Object> handle;`: 声明一个全局句柄。
3. `handle.Reset(env->GetIsolate(), v8::Object::New(env->GetIsolate()));`: 创建一个新的 Javascript 对象，并将其赋值给全局句柄。此时是强引用。
4. `handle.SetWeak();`: 将全局句柄设置为弱引用。
5. `CHECK(HasWeakGlobalHandle());`: 再次调用 `HasWeakGlobalHandle`，此时堆快照中应该能够检测到弱全局句柄，函数返回 `true`，断言通过。

**假设输出:**

* 第一次 `CHECK(!HasWeakGlobalHandle())` 断言通过。
* 第二次 `CHECK(HasWeakGlobalHandle())` 断言通过。

**涉及用户常见的编程错误:**

堆分析器可以帮助检测与内存管理相关的常见编程错误，例如：

* **内存泄漏:**  对象在不再需要时仍然被引用，导致无法被垃圾回收。例如，在 Javascript 中意外地将对象存储在全局变量或闭包中，即使这些对象已经不再使用。

   ```javascript
   // 潜在的内存泄漏
   let leakedObject;
   function createLeakedObject() {
     leakedObject = { data: new Array(1000000) }; // 大对象
   }
   createLeakedObject(); // leakedObject 仍然可以访问，即使函数执行完毕
   ```

* **意外的对象保留:**  对象被意外地保留在内存中，可能是由于意想不到的引用关系。堆分析器可以帮助可视化这些引用链。

   ```javascript
   let obj1 = {};
   let obj2 = {};
   obj1.ref = obj2;
   obj2.ref = obj1; // 循环引用，可能导致垃圾回收困难
   ```

* **闭包引起的意外内存占用:**  闭包会捕获其作用域中的变量，如果不小心，可能会导致不必要的对象被保留。

   ```javascript
   function createClickHandler() {
     let largeData = new Array(1000000);
     return function() {
       console.log("Clicked!");
       // largeData 仍然被闭包引用，即使点击处理函数本身可能很简单
     };
   }
   document.getElementById('myButton').onclick = createClickHandler();
   ```

这些测试用例通过验证堆快照的正确性，间接地帮助确保堆分析器能够有效地帮助开发者诊断和解决这些内存管理问题。例如，`TEST(WeakGlobalHandle)` 确保了弱全局句柄不会阻止对象被回收，这与避免内存泄漏相关。 `TEST(NoRefsToNonEssentialEntries)` 帮助减少快照的噪音，使开发者更容易找到关键的内存泄漏或保留问题。

Prompt: 
```
这是目录为v8/test/cctest/test-heap-profiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-heap-profiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能

"""
ode->GetChild(i);
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