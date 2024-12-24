Response: The user wants to understand the functionality of the C++ code snippet provided.
The code is part of V8's test suite, specifically for testing the heap profiler.

Here's a plan to summarize the functionality:
1. Identify the main purpose of the code based on the file name and includes.
2. Analyze the provided code to understand what specific aspects of the heap profiler are being tested.
3. Explain the connection to Javascript functionality, as the heap profiler is used to analyze Javascript heap.
4. Provide a Javascript example demonstrating the concept.
这个C++代码文件 `v8/test/cctest/test-heap-profiler.cc` 的主要功能是**测试 V8 JavaScript 引擎的堆分析器 (heap profiler) 功能**。

更具体地说，这部分代码主要涵盖了以下方面的测试：

1. **生成堆快照 (Heap Snapshot)**: 测试能否正确生成当前 JavaScript 堆的快照，包括堆中对象的类型、大小、引用关系等信息。
2. **验证堆快照的结构和内容**:  测试生成的堆快照是否包含了预期的节点 (nodes) 和边 (edges)，以及这些节点和边是否正确表示了 JavaScript 对象的结构和引用关系。
3. **测试特定类型的 JavaScript 对象在堆快照中的表示**: 例如，测试函数 (functions)、闭包 (closures)、对象 (objects)、数组 (arrays)、字符串 (strings)、数字 (numbers)、BigInt、Symbol、WeakSet、WeakMap、Set、Map 等不同类型的 JavaScript 对象在堆快照中的结构和属性信息是否正确。
4. **测试堆快照中对象的元数据**:  例如，测试能否获取到对象的源代码位置 (location information)。
5. **测试堆快照中对象的 ID**: 测试在多次快照之间，同一对象的 ID 是否保持一致，以及在垃圾回收 (GC) 后，对象的 ID 是否能够正确维护。
6. **测试堆快照的序列化**: 测试能否将生成的堆快照序列化成 JSON 格式，并验证序列化后的 JSON 数据是否符合预期，以及能否正确解析。
7. **测试堆对象统计 (Heap Objects Stats)**: 测试能否追踪堆中对象的分配和回收，并获取对象的统计信息。
8. **测试获取对象 ID (Object IDs)**: 测试能否获取到 JavaScript 对象的唯一 ID，并在 GC 后仍然能够通过 ID 找到该对象。
9. **测试通过 ID 获取节点 (Get Node By ID)**: 测试能否通过堆快照中节点的 ID 重新获取到该节点。
10. **测试快照操作的中断 (Aborting)**: 测试在生成堆快照的过程中，能否通过 `ActivityControl` 接口来中断操作。
11. **测试嵌入器提供的图形 (Embedder Graph)**:  测试能否将 V8 引擎之外的宿主环境的对象信息也包含到堆快照中。

**与 Javascript 的关系以及 Javascript 示例**

堆分析器是用来分析 JavaScript 程序的内存使用情况的工具。它通过生成堆快照来展示 JavaScript 堆中对象的分布和引用关系，帮助开发者识别内存泄漏、性能瓶颈等问题。

例如，这个测试文件中有很多测试用例验证了特定 JavaScript 对象类型在堆快照中的表示。我们可以用一个简单的 JavaScript 示例来说明：

```javascript
function MyObject(name) {
  this.name = name;
}

let obj1 = new MyObject("object1");
let obj2 = { value: obj1 };
```

当 V8 引擎执行这段代码并生成堆快照时，`test-heap-profiler.cc` 中的测试会验证：

* 快照中会存在 `MyObject` 类型的节点，并且其 `name` 属性会正确地指向一个字符串 "object1"。
* 快照中会存在一个普通对象类型的节点 (对应 `obj2`)，并且会存在一条从该节点到 `obj1` 节点的边，表示 `obj2.value` 引用了 `obj1`。
* 快照中会存在字符串类型的节点，表示 "object1"。

这个 C++ 测试文件实际上是在幕后模拟 V8 引擎生成堆快照的过程，并对快照的数据结构和内容进行断言，确保堆分析器的功能正常工作。开发者可以使用 Chrome DevTools 或 V8 提供的 API 来生成和分析 JavaScript 堆快照，从而了解程序的内存使用情况。

总结来说，这部分 `test-heap-profiler.cc` 代码是 V8 引擎的内部测试，用于验证其堆分析器功能的正确性和可靠性，而堆分析器是帮助 JavaScript 开发者理解和优化程序内存使用的重要工具。

Prompt: 
```
这是目录为v8/test/cctest/test-heap-profiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2011 the V8 project authors. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//     * Neither the name of Google Inc. nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Tests for heap profiler

#include <ctype.h>

#include <memory>
#include <optional>
#include <vector>

#include "include/v8-function.h"
#include "include/v8-json.h"
#include "include/v8-profiler.h"
#include "src/api/api-inl.h"
#include "src/base/hashmap.h"
#include "src/base/logging.h"
#include "src/base/strings.h"
#include "src/codegen/assembler-inl.h"
#include "src/debug/debug.h"
#include "src/handles/global-handles.h"
#include "src/heap/heap-inl.h"
#include "src/heap/pretenuring-handler.h"
#include "src/objects/objects-inl.h"
#include "src/profiler/allocation-tracker.h"
#include "src/profiler/heap-profiler.h"
#include "src/profiler/heap-snapshot-generator-inl.h"
#include "test/cctest/cctest.h"
#include "test/cctest/collector.h"
#include "test/cctest/heap/heap-utils.h"
#include "test/cctest/jsonstream-helper.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-module-builder.h"
#endif

using i::AllocationTraceNode;
using i::AllocationTraceTree;
using i::AllocationTracker;
using i::EntrySourceLocation;
using i::heap::GrowNewSpaceToMaximumCapacity;
using std::optional;
using v8::base::ArrayVector;
using v8::base::OS;
using v8::base::Vector;
using v8::base::VectorOf;

namespace {

class NamedEntriesDetector {
 public:
  NamedEntriesDetector()
      : has_A2(false), has_B2(false), has_C2(false) {
  }

  void CheckEntry(i::HeapEntry* entry) {
    if (strcmp(entry->name(), "A2") == 0) has_A2 = true;
    if (strcmp(entry->name(), "B2") == 0) has_B2 = true;
    if (strcmp(entry->name(), "C2") == 0) has_C2 = true;
  }

  void CheckAllReachables(i::HeapEntry* root) {
    v8::base::HashMap visited;
    std::vector<i::HeapEntry*> list;
    list.push_back(root);
    CheckEntry(root);
    while (!list.empty()) {
      i::HeapEntry* heap_entry = list.back();
      list.pop_back();
      for (int i = 0; i < heap_entry->children_count(); ++i) {
        i::HeapGraphEdge* edge = heap_entry->child(i);
        if (edge->type() == i::HeapGraphEdge::kShortcut) continue;
        i::HeapEntry* child = edge->to();
        v8::base::HashMap::Entry* entry = visited.LookupOrInsert(
            reinterpret_cast<void*>(child),
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(child)));
        if (entry->value)
          continue;
        entry->value = reinterpret_cast<void*>(1);
        list.push_back(child);
        CheckEntry(child);
      }
    }
  }

  bool has_A2;
  bool has_B2;
  bool has_C2;
};

}  // namespace


static const v8::HeapGraphNode* GetGlobalObject(
    const v8::HeapSnapshot* snapshot) {
  // The 0th-child is (GC Roots), 1st is the user root.
  const v8::HeapGraphNode* global_obj =
      snapshot->GetRoot()->GetChild(1)->GetToNode();
  CHECK_EQ(0, strncmp("Object", const_cast<i::HeapEntry*>(
      reinterpret_cast<const i::HeapEntry*>(global_obj))->name(), 6));
  return global_obj;
}

static const char* GetName(const v8::HeapGraphNode* node) {
  return const_cast<i::HeapEntry*>(reinterpret_cast<const i::HeapEntry*>(node))
      ->name();
}

static const char* GetName(const v8::HeapGraphEdge* edge) {
  return const_cast<i::HeapGraphEdge*>(
             reinterpret_cast<const i::HeapGraphEdge*>(edge))
      ->name();
}

static size_t GetSize(const v8::HeapGraphNode* node) {
  return const_cast<i::HeapEntry*>(reinterpret_cast<const i::HeapEntry*>(node))
      ->self_size();
}

static const v8::HeapGraphNode* GetChildByName(const v8::HeapGraphNode* node,
                                               const char* name) {
  for (int i = 0, count = node->GetChildrenCount(); i < count; ++i) {
    const v8::HeapGraphNode* child = node->GetChild(i)->GetToNode();
    if (!strcmp(name, GetName(child))) {
      return child;
    }
  }
  return nullptr;
}

static const v8::HeapGraphEdge* GetEdgeByChildName(
    const v8::HeapGraphNode* node, const char* name) {
  for (int i = 0, count = node->GetChildrenCount(); i < count; ++i) {
    const v8::HeapGraphEdge* edge = node->GetChild(i);
    const v8::HeapGraphNode* child = edge->GetToNode();
    if (!strcmp(name, GetName(child))) {
      return edge;
    }
  }
  return nullptr;
}

static const v8::HeapGraphNode* GetRootChild(const v8::HeapSnapshot* snapshot,
                                             const char* name) {
  return GetChildByName(snapshot->GetRoot(), name);
}

static optional<EntrySourceLocation> GetLocation(
    const v8::HeapSnapshot* s, const v8::HeapGraphNode* node) {
  const i::HeapSnapshot* snapshot = reinterpret_cast<const i::HeapSnapshot*>(s);
  const std::vector<EntrySourceLocation>& locations = snapshot->locations();
  const i::HeapEntry* entry = reinterpret_cast<const i::HeapEntry*>(node);
  for (const auto& loc : locations) {
    if (loc.entry_index == entry->index()) {
      return optional<EntrySourceLocation>(loc);
    }
  }

  return optional<EntrySourceLocation>();
}

static const v8::HeapGraphNode* GetProperty(v8::Isolate* isolate,
                                            const v8::HeapGraphNode* node,
                                            v8::HeapGraphEdge::Type type,
                                            const char* name) {
  for (int i = 0, count = node->GetChildrenCount(); i < count; ++i) {
    const v8::HeapGraphEdge* prop = node->GetChild(i);
    v8::String::Utf8Value prop_name(isolate, prop->GetName());
    if (prop->GetType() == type && strcmp(name, *prop_name) == 0)
      return prop->GetToNode();
  }
  return nullptr;
}

// The following functions are not Wasm-specific, but are only used in a
// Wasm-specific test. As long as this is the case we only define them if Wasm
// is enabled to avoid warnings about unused functions.
#if V8_ENABLE_WEBASSEMBLY
static const std::vector<std::string> GetProperties(
    v8::Isolate* isolate, const v8::HeapGraphNode* node) {
  int num_children = node->GetChildrenCount();
  std::vector<std::string> properties(num_children);
  for (int i = 0; i < num_children; ++i) {
    const v8::HeapGraphEdge* prop = node->GetChild(i);
    v8::String::Utf8Value prop_name(isolate, prop->GetName());
    properties[i] = *prop_name;
  }
  std::sort(properties.begin(), properties.end());
  return properties;
}

static void CheckProperties(
    v8::Isolate* isolate, const v8::HeapGraphNode* node,
    std::initializer_list<std::string> expected_properties) {
  std::vector<std::string> properties = GetProperties(isolate, node);
  if (VectorOf(properties) == VectorOf(expected_properties)) return;

  std::ostringstream full_error;
  full_error << "Expected properties: "
             << i::PrintCollection(expected_properties) << "\n";
  full_error << "Found properties:    " << i::PrintCollection(properties)
             << "\n";
  OS::PrintError("%s\n", full_error.str().c_str());
  FATAL("Mismatch in properties");
}
#endif  // V8_ENABLE_WEBASSEMBLY

static bool HasString(v8::Isolate* isolate, const v8::HeapGraphNode* node,
                      const char* contents) {
  for (int i = 0, count = node->GetChildrenCount(); i < count; ++i) {
    const v8::HeapGraphEdge* prop = node->GetChild(i);
    const v8::HeapGraphNode* dest_node = prop->GetToNode();
    if (dest_node->GetType() == v8::HeapGraphNode::kString) {
      v8::String::Utf8Value node_name(isolate, dest_node->GetName());
      if (strcmp(contents, *node_name) == 0) return true;
    }
  }
  return false;
}

static void EnsureNoUninstrumentedInternals(v8::Isolate* isolate,
                                            const v8::HeapGraphNode* node) {
  for (int i = 0; i < 20; ++i) {
    v8::base::ScopedVector<char> buffer(10);
    const v8::HeapGraphNode* internal =
        GetProperty(isolate, node, v8::HeapGraphEdge::kInternal,
                    i::IntToCString(i, buffer));
    CHECK(!internal);
  }
}

// Check that snapshot has no unretained entries except root.
static bool ValidateSnapshot(const v8::HeapSnapshot* snapshot, int depth = 3) {
  i::HeapSnapshot* heap_snapshot = const_cast<i::HeapSnapshot*>(
      reinterpret_cast<const i::HeapSnapshot*>(snapshot));

  v8::base::HashMap visited;
  std::deque<i::HeapGraphEdge>& edges = heap_snapshot->edges();
  for (size_t i = 0; i < edges.size(); ++i) {
    v8::base::HashMap::Entry* entry = visited.LookupOrInsert(
        reinterpret_cast<void*>(edges[i].to()),
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(edges[i].to())));
    uint32_t ref_count = static_cast<uint32_t>(
        reinterpret_cast<uintptr_t>(entry->value));
    entry->value = reinterpret_cast<void*>(ref_count + 1);
  }
  uint32_t unretained_entries_count = 0;
  std::deque<i::HeapEntry>& entries = heap_snapshot->entries();
  for (i::HeapEntry& entry : entries) {
    v8::base::HashMap::Entry* map_entry = visited.Lookup(
        reinterpret_cast<void*>(&entry),
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&entry)));
    if (!map_entry && entry.id() != 1) {
      entry.Print("entry with no retainer", "", depth, 0);
      ++unretained_entries_count;
    }
  }
  return unretained_entries_count == 0;
}

bool EndsWith(const char* a, const char* b) {
  size_t length_a = strlen(a);
  size_t length_b = strlen(b);
  return (length_a >= length_b) && !strcmp(a + length_a - length_b, b);
}

TEST(HeapSnapshot) {
  LocalContext env2;
  v8::HandleScope scope(env2->GetIsolate());
  v8::HeapProfiler* heap_profiler = env2->GetIsolate()->GetHeapProfiler();

  CompileRun(
      "function A2() {}\n"
      "function B2(x) { return function() { return typeof x; }; }\n"
      "function C2(x) { this.x1 = x; this.x2 = x; this[1] = x; }\n"
      "var a2 = new A2();\n"
      "var b2_1 = new B2(a2), b2_2 = new B2(a2);\n"
      "var c2 = new C2(a2);");
  const v8::HeapSnapshot* snapshot_env2 = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot_env2));
  const v8::HeapGraphNode* global_env2 = GetGlobalObject(snapshot_env2);

  // Verify, that JS global object of env2 has '..2' properties.
  const v8::HeapGraphNode* a2_node = GetProperty(
      env2->GetIsolate(), global_env2, v8::HeapGraphEdge::kProperty, "a2");
  CHECK(a2_node);
  CHECK(GetProperty(env2->GetIsolate(), global_env2,
                    v8::HeapGraphEdge::kProperty, "b2_1"));
  CHECK(GetProperty(env2->GetIsolate(), global_env2,
                    v8::HeapGraphEdge::kProperty, "b2_2"));
  CHECK(GetProperty(env2->GetIsolate(), global_env2,
                    v8::HeapGraphEdge::kProperty, "c2"));

  NamedEntriesDetector det;
  det.CheckAllReachables(const_cast<i::HeapEntry*>(
      reinterpret_cast<const i::HeapEntry*>(global_env2)));
  CHECK(det.has_A2);
  CHECK(det.has_B2);
  CHECK(det.has_C2);
}

TEST(HeapSnapshotLocations) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  CompileRun(
      "function X(a) { return function() { return a; } }\n"
      "function* getid() { yield 1; }\n"
      "class A {}\n"
      "var x = X(1);\n"
      "var g = getid();\n"
      "var o = new A();");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));

  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  const v8::HeapGraphNode* x =
      GetProperty(env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "x");
  CHECK(x);

  optional<EntrySourceLocation> x_loc = GetLocation(snapshot, x);
  CHECK(x_loc);
  CHECK_EQ(0, x_loc->line);
  CHECK_EQ(31, x_loc->col);

  const v8::HeapGraphNode* g =
      GetProperty(env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "g");
  CHECK(x);

  optional<EntrySourceLocation> g_loc = GetLocation(snapshot, g);
  CHECK(g_loc);
  CHECK_EQ(1, g_loc->line);
  CHECK_EQ(15, g_loc->col);

  const v8::HeapGraphNode* o =
      GetProperty(env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "o");
  CHECK(x);

  optional<EntrySourceLocation> o_loc = GetLocation(snapshot, o);
  CHECK(o_loc);
  CHECK_EQ(2, o_loc->line);
  CHECK_EQ(0, o_loc->col);
}

TEST(HeapSnapshotObjectSizes) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  //   -a-> X1 --a
  // x -b-> X2 <-|
  CompileRun(
      "function X(a, b) { this.a = a; this.b = b; }\n"
      "x = new X(new X(), new X());\n"
      "dummy = new X();\n"
      "(function() { x.a.a = x.b; })();");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  const v8::HeapGraphNode* x =
      GetProperty(env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "x");
  CHECK(x);
  const v8::HeapGraphNode* x1 =
      GetProperty(env->GetIsolate(), x, v8::HeapGraphEdge::kProperty, "a");
  CHECK(x1);
  const v8::HeapGraphNode* x2 =
      GetProperty(env->GetIsolate(), x, v8::HeapGraphEdge::kProperty, "b");
  CHECK(x2);

  // Test sizes.
  CHECK_NE(0, static_cast<int>(x->GetShallowSize()));
  CHECK_NE(0, static_cast<int>(x1->GetShallowSize()));
  CHECK_NE(0, static_cast<int>(x2->GetShallowSize()));
}


TEST(BoundFunctionInSnapshot) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  CompileRun(
      "function myFunction(a, b) { this.a = a; this.b = b; }\n"
      "function AAAAA() {}\n"
      "boundFunction = myFunction.bind(new AAAAA(), 20, new Number(12)); \n");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  const v8::HeapGraphNode* f = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "boundFunction");
  CHECK(f);
  CHECK(v8_str("native_bind")->Equals(env.local(), f->GetName()).FromJust());
  const v8::HeapGraphNode* bindings = GetProperty(
      env->GetIsolate(), f, v8::HeapGraphEdge::kInternal, "bindings");
  CHECK(bindings);
  CHECK_EQ(v8::HeapGraphNode::kArray, bindings->GetType());
  CHECK_EQ(1, bindings->GetChildrenCount());

  const v8::HeapGraphNode* bound_this = GetProperty(
      env->GetIsolate(), f, v8::HeapGraphEdge::kInternal, "bound_this");
  CHECK(bound_this);
  CHECK_EQ(v8::HeapGraphNode::kObject, bound_this->GetType());

  const v8::HeapGraphNode* bound_function = GetProperty(
      env->GetIsolate(), f, v8::HeapGraphEdge::kInternal, "bound_function");
  CHECK(bound_function);
  CHECK_EQ(v8::HeapGraphNode::kClosure, bound_function->GetType());

  const v8::HeapGraphNode* bound_argument = GetProperty(
      env->GetIsolate(), f, v8::HeapGraphEdge::kShortcut, "bound_argument_1");
  CHECK(bound_argument);
  CHECK_EQ(v8::HeapGraphNode::kObject, bound_argument->GetType());
}


TEST(HeapSnapshotEntryChildren) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  CompileRun(
      "function A() { }\n"
      "a = new A;");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  for (int i = 0, count = global->GetChildrenCount(); i < count; ++i) {
    const v8::HeapGraphEdge* prop = global->GetChild(i);
    CHECK_EQ(global, prop->GetFromNode());
  }
  const v8::HeapGraphNode* a =
      GetProperty(env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "a");
  CHECK(a);
  for (int i = 0, count = a->GetChildrenCount(); i < count; ++i) {
    const v8::HeapGraphEdge* prop = a->GetChild(i);
    CHECK_EQ(a, prop->GetFromNode());
  }
}


TEST(HeapSnapshotCodeObjects) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  CompileRun(
      "function lazy(x) { return x - 1; }\n"
      "function compiled(x) { ()=>x; return x + 1; }\n"
      "var anonymous = (function() { return function() { return 0; } })();\n"
      "compiled(1)");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));

  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  const v8::HeapGraphNode* compiled = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "compiled");
  CHECK(compiled);
  CHECK_EQ(v8::HeapGraphNode::kClosure, compiled->GetType());
  const v8::HeapGraphNode* lazy = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "lazy");
  CHECK(lazy);
  CHECK_EQ(v8::HeapGraphNode::kClosure, lazy->GetType());
  const v8::HeapGraphNode* anonymous = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "anonymous");
  CHECK(anonymous);
  CHECK_EQ(v8::HeapGraphNode::kClosure, anonymous->GetType());
  v8::String::Utf8Value anonymous_name(env->GetIsolate(), anonymous->GetName());
  CHECK_EQ(0, strcmp("", *anonymous_name));

  // Find references to shared function info.
  const v8::HeapGraphNode* compiled_sfi = GetProperty(
      env->GetIsolate(), compiled, v8::HeapGraphEdge::kInternal, "shared");
  CHECK(compiled_sfi);
  const v8::HeapGraphNode* lazy_sfi = GetProperty(
      env->GetIsolate(), lazy, v8::HeapGraphEdge::kInternal, "shared");
  CHECK(lazy_sfi);

  // TODO(leszeks): Check that there's bytecode on the compiled function, but
  // not the lazy function.

  // Verify that non-compiled function doesn't contain references to "x"
  // literal, while compiled function does. The scope info is stored in
  // ScopeInfo objects attached to the SharedFunctionInfo.
  bool compiled_references_x = false, lazy_references_x = false;
  for (int i = 0, count = compiled_sfi->GetChildrenCount(); i < count; ++i) {
    const v8::HeapGraphEdge* prop = compiled_sfi->GetChild(i);
    const v8::HeapGraphNode* node = prop->GetToNode();
    if (node->GetType() == v8::HeapGraphNode::kCode &&
        !strcmp("system / ScopeInfo", GetName(node))) {
      if (HasString(env->GetIsolate(), node, "x")) {
        compiled_references_x = true;
        break;
      }
    }
  }
  for (int i = 0, count = lazy_sfi->GetChildrenCount(); i < count; ++i) {
    const v8::HeapGraphEdge* prop = lazy_sfi->GetChild(i);
    const v8::HeapGraphNode* node = prop->GetToNode();
    if (node->GetType() == v8::HeapGraphNode::kCode &&
        !strcmp("system / ScopeInfo", GetName(node))) {
      if (HasString(env->GetIsolate(), node, "x")) {
        lazy_references_x = true;
        break;
      }
    }
  }
  CHECK(compiled_references_x);
  if (i::v8_flags.lazy) {
    CHECK(!lazy_references_x);
  }
}


TEST(HeapSnapshotHeapNumbers) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  CompileRun(
      "a = 1;    // a is Smi\n"
      "b = 2.5;  // b is HeapNumber");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  CHECK(!GetProperty(env->GetIsolate(), global, v8::HeapGraphEdge::kProperty,
                     "a"));
  const v8::HeapGraphNode* b =
      GetProperty(env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "b");
  CHECK(b);
  CHECK_EQ(v8::HeapGraphNode::kHeapNumber, b->GetType());
}

TEST(HeapSnapshotHeapNumbersCaptureNumericValue) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  CompileRun(
      "a = 1;    // a is Smi\n"
      "b = 2.5;  // b is HeapNumber");
  const v8::HeapSnapshot* snapshot =
      heap_profiler->TakeHeapSnapshot(nullptr, nullptr, true, true);
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  const v8::HeapGraphNode* a =
      GetProperty(env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "a");
  CHECK(a);
  CHECK_EQ(1, a->GetChildrenCount());
  v8::String::Utf8Value value_a(CcTest::isolate(),
                                a->GetChild(0)->GetToNode()->GetName());
  CHECK_EQ(0, strcmp("1", *value_a));

  const v8::HeapGraphNode* b =
      GetProperty(env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "b");
  CHECK(b);
  CHECK_EQ(2, b->GetChildrenCount());
  v8::String::Utf8Value value_b(CcTest::isolate(),
                                b->GetChild(0)->GetToNode()->GetName());
  CHECK_EQ(0, strcmp("2.5", *value_b));
}

TEST(HeapSnapshotHeapBigInts) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  CompileRun(
      "a = 1n;"
      "b = Object(BigInt(2))");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  const v8::HeapGraphNode* a =
      GetProperty(env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "a");
  CHECK(a);
  CHECK_EQ(v8::HeapGraphNode::kBigInt, a->GetType());
  const v8::HeapGraphNode* b =
      GetProperty(env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "b");
  CHECK(b);
  CHECK_EQ(v8::HeapGraphNode::kObject, b->GetType());
}

TEST(HeapSnapshotSlicedString) {
  if (!i::v8_flags.string_slices) return;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();
  CompileRun(
      "parent_string = \"123456789.123456789.123456789.123456789.123456789."
      "123456789.123456789.123456789.123456789.123456789."
      "123456789.123456789.123456789.123456789.123456789."
      "123456789.123456789.123456789.123456789.123456789."
      "123456789.123456789.123456789.123456789.123456789."
      "123456789.123456789.123456789.123456789.123456789."
      "123456789.123456789.123456789.123456789.123456789."
      "123456789.123456789.123456789.123456789.123456789.\";"
      "child_string = parent_string.slice(100);");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  const v8::HeapGraphNode* parent_string = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "parent_string");
  CHECK(parent_string);
  const v8::HeapGraphNode* child_string = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "child_string");
  CHECK(child_string);
  CHECK_EQ(v8::HeapGraphNode::kSlicedString, child_string->GetType());
  const v8::HeapGraphNode* parent = GetProperty(
      env->GetIsolate(), child_string, v8::HeapGraphEdge::kInternal, "parent");
  CHECK_EQ(parent_string, parent);
  heap_profiler->DeleteAllHeapSnapshots();
}

// Allow usages of v8::Object::GetPrototype() for now.
// TODO(https://crbug.com/333672197): remove.
START_ALLOW_USE_DEPRECATED()

TEST(HeapSnapshotConsString) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> global_template =
      v8::ObjectTemplate::New(isolate);
  global_template->SetInternalFieldCount(1);
  LocalContext env(nullptr, global_template);
  v8::Local<v8::Object> global_proxy = env->Global();
  CHECK_EQ(1, global_proxy->InternalFieldCount());
  v8::Local<v8::Object> global = global_proxy->GetPrototype().As<v8::Object>();
  CHECK_EQ(1, global->InternalFieldCount());

  i::Factory* factory = CcTest::i_isolate()->factory();
  i::Handle<i::String> first = factory->NewStringFromStaticChars("0123456789");
  i::Handle<i::String> second = factory->NewStringFromStaticChars("0123456789");
  i::DirectHandle<i::String> cons_string =
      factory->NewConsString(first, second).ToHandleChecked();

  global_proxy->SetInternalField(0, v8::ToApiHandle<v8::String>(cons_string));
  global->SetInternalField(0, v8::ToApiHandle<v8::String>(cons_string));

  v8::HeapProfiler* heap_profiler = isolate->GetHeapProfiler();
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global_node = GetGlobalObject(snapshot);

  const v8::HeapGraphNode* string_node =
      GetProperty(isolate, global_node, v8::HeapGraphEdge::kInternal, "0");
  CHECK(string_node);
  CHECK_EQ(v8::HeapGraphNode::kConsString, string_node->GetType());

  const v8::HeapGraphNode* first_node =
      GetProperty(isolate, string_node, v8::HeapGraphEdge::kInternal, "first");
  CHECK_EQ(v8::HeapGraphNode::kString, first_node->GetType());

  const v8::HeapGraphNode* second_node =
      GetProperty(isolate, string_node, v8::HeapGraphEdge::kInternal, "second");
  CHECK_EQ(v8::HeapGraphNode::kString, second_node->GetType());

  heap_profiler->DeleteAllHeapSnapshots();
}

// Allow usages of v8::Object::GetPrototype() for now.
// TODO(https://crbug.com/333672197): remove.
END_ALLOW_USE_DEPRECATED()

TEST(HeapSnapshotSymbol) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  CompileRun("a = Symbol('mySymbol');\n");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  const v8::HeapGraphNode* a =
      GetProperty(env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "a");
  CHECK(a);
  CHECK_EQ(a->GetType(), v8::HeapGraphNode::kSymbol);
  CHECK(v8_str("symbol")->Equals(env.local(), a->GetName()).FromJust());
  const v8::HeapGraphNode* name =
      GetProperty(env->GetIsolate(), a, v8::HeapGraphEdge::kInternal, "name");
  CHECK(name);
  CHECK(v8_str("mySymbol")->Equals(env.local(), name->GetName()).FromJust());
}

TEST(HeapSnapshotWeakCollection) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  CompileRun(
      "k = {}; v = {}; s = 'str';\n"
      "ws = new WeakSet(); ws.add(k); ws.add(v); ws[s] = s;\n"
      "wm = new WeakMap(); wm.set(k, v); wm[s] = s;\n");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  const v8::HeapGraphNode* k =
      GetProperty(env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "k");
  CHECK(k);
  const v8::HeapGraphNode* v =
      GetProperty(env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "v");
  CHECK(v);
  const v8::HeapGraphNode* s =
      GetProperty(env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "s");
  CHECK(s);

  const v8::HeapGraphNode* ws = GetProperty(env->GetIsolate(), global,
                                            v8::HeapGraphEdge::kProperty, "ws");
  CHECK(ws);
  CHECK_EQ(v8::HeapGraphNode::kObject, ws->GetType());
  CHECK(v8_str("WeakSet")->Equals(env.local(), ws->GetName()).FromJust());

  const v8::HeapGraphNode* ws_table =
      GetProperty(env->GetIsolate(), ws, v8::HeapGraphEdge::kInternal, "table");
  CHECK_EQ(v8::HeapGraphNode::kArray, ws_table->GetType());
  CHECK_GT(ws_table->GetChildrenCount(), 0);
  int weak_entries = 0;
  for (int i = 0, count = ws_table->GetChildrenCount(); i < count; ++i) {
    const v8::HeapGraphEdge* prop = ws_table->GetChild(i);
    if (prop->GetType() != v8::HeapGraphEdge::kWeak) continue;
    if (k->GetId() == prop->GetToNode()->GetId()) {
      ++weak_entries;
    }
  }
  CHECK_EQ(1, weak_entries);
  const v8::HeapGraphNode* ws_s =
      GetProperty(env->GetIsolate(), ws, v8::HeapGraphEdge::kProperty, "str");
  CHECK(ws_s);
  CHECK_EQ(s->GetId(), ws_s->GetId());

  const v8::HeapGraphNode* wm = GetProperty(env->GetIsolate(), global,
                                            v8::HeapGraphEdge::kProperty, "wm");
  CHECK(wm);
  CHECK_EQ(v8::HeapGraphNode::kObject, wm->GetType());
  CHECK(v8_str("WeakMap")->Equals(env.local(), wm->GetName()).FromJust());

  const v8::HeapGraphNode* wm_table =
      GetProperty(env->GetIsolate(), wm, v8::HeapGraphEdge::kInternal, "table");
  CHECK_EQ(v8::HeapGraphNode::kArray, wm_table->GetType());
  CHECK_GT(wm_table->GetChildrenCount(), 0);
  weak_entries = 0;
  for (int i = 0, count = wm_table->GetChildrenCount(); i < count; ++i) {
    const v8::HeapGraphEdge* prop = wm_table->GetChild(i);
    if (prop->GetType() != v8::HeapGraphEdge::kWeak) continue;
    const v8::SnapshotObjectId to_node_id = prop->GetToNode()->GetId();
    if (to_node_id == k->GetId() || to_node_id == v->GetId()) {
      ++weak_entries;
    }
  }
  CHECK_EQ(2, weak_entries);  // Key and value are weak.
  const v8::HeapGraphNode* wm_s =
      GetProperty(env->GetIsolate(), wm, v8::HeapGraphEdge::kProperty, "str");
  CHECK(wm_s);
  CHECK_EQ(s->GetId(), wm_s->GetId());
}


TEST(HeapSnapshotCollection) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::HeapProfiler* heap_profiler = env->GetIsolate()->GetHeapProfiler();

  CompileRun(
      "k = {}; v = {}; s = 'str';\n"
      "set = new Set(); set.add(k); set.add(v); set[s] = s;\n"
      "map = new Map(); map.set(k, v); map[s] = s;\n");
  const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();
  CHECK(ValidateSnapshot(snapshot));
  const v8::HeapGraphNode* global = GetGlobalObject(snapshot);
  const v8::HeapGraphNode* k =
      GetProperty(env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "k");
  CHECK(k);
  const v8::HeapGraphNode* v =
      GetProperty(env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "v");
  CHECK(v);
  const v8::HeapGraphNode* s =
      GetProperty(env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "s");
  CHECK(s);

  const v8::HeapGraphNode* set = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "set");
  CHECK(set);
  CHECK_EQ(v8::HeapGraphNode::kObject, set->GetType());
  CHECK(v8_str("Set")->Equals(env.local(), set->GetName()).FromJust());

  const v8::HeapGraphNode* set_table = GetProperty(
      env->GetIsolate(), set, v8::HeapGraphEdge::kInternal, "table");
  CHECK_EQ(v8::HeapGraphNode::kArray, set_table->GetType());
  CHECK_GT(set_table->GetChildrenCount(), 0);
  int entries = 0;
  for (int i = 0, count = set_table->GetChildrenCount(); i < count; ++i) {
    const v8::HeapGraphEdge* prop = set_table->GetChild(i);
    const v8::SnapshotObjectId to_node_id = prop->GetToNode()->GetId();
    if (to_node_id == k->GetId() || to_node_id == v->GetId()) {
      ++entries;
    }
  }
  CHECK_EQ(2, entries);
  const v8::HeapGraphNode* set_s =
      GetProperty(env->GetIsolate(), set, v8::HeapGraphEdge::kProperty, "str");
  CHECK(set_s);
  CHECK_EQ(s->GetId(), set_s->GetId());

  const v8::HeapGraphNode* map = GetProperty(
      env->GetIsolate(), global, v8::HeapGraphEdge::kProperty, "map");
  CHECK(map);
  CHECK_EQ(v8::HeapGraphNode::kObject, map->GetType());
  CHECK(v8_str("Map")->Equals(env.local(), map->GetName()).FromJust());

  const v8::HeapGraphNode* map_table = GetProperty(
      env->GetIsolate(), map, v8::HeapGraphEdge::kInternal, "table");
  CHECK_EQ(v8::HeapGraphNode::kArray, map_table->GetType());
  CHECK_GT(map_table->GetChildrenCount(), 0);
  entries = 0;
  for (int i = 0, count = map_table->GetChildrenCount(); i < count; ++i) {
    const v8::HeapGraphEdge* prop = map_table->GetChild(i);
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
"""


```