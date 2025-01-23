Response:
Let's break down the thought process for analyzing this V8 heap profiler test code.

**1. Initial Skim and Keyword Recognition:**

* **Keywords:**  "heap profiler", "heap snapshot", "test", "v8". This immediately tells us the code's purpose: testing the heap profiler functionality within the V8 JavaScript engine.
* **File Path:** `v8/test/cctest/test-heap-profiler.cc`. `.cc` signifies C++ source code. The `test` and `cctest` directories confirm it's a testing file.
* **Copyright Notice:**  Standard V8 copyright, no specific insights here except confirmation of origin.
* **Includes:**  `v8-profiler.h`, `v8-heap-snapshot.h` (indirectly through `v8-profiler.h`), various `src` headers like `heap-inl.h`, `profiler/heap-profiler.h`, etc. These reinforce the core function. Seeing `v8-function.h`, `v8-json.h` hints at interaction with JavaScript functions and JSON representation of heap data. `test/cctest/cctest.h` confirms the testing framework being used.

**2. High-Level Understanding of Heap Profiling:**

Before diving into the specifics, recall what a heap profiler does: it allows you to take "snapshots" of the memory used by a running JavaScript program. This snapshot represents the objects in memory, their sizes, and the relationships (edges) between them. This information is crucial for identifying memory leaks and optimizing memory usage.

**3. Analyzing the Structure and Key Components:**

* **Namespaces:** The code is in an unnamed namespace, which is common practice in C++ to limit symbol visibility.
* **`NamedEntriesDetector` Class:** This looks like a helper class for a specific test. It checks for the presence of certain named objects ("A2", "B2", "C2") within a heap snapshot. The depth-first search (`CheckAllReachables`) suggests verifying reachability of objects.
* **Helper Functions:** A series of static functions like `GetGlobalObject`, `GetName`, `GetSize`, `GetChildByName`, `GetEdgeByChildName`, `GetRootChild`, `GetLocation`, `GetProperty`, `HasString`, `EnsureNoUninstrumentedInternals`, and `ValidateSnapshot`. These clearly provide utilities for navigating and inspecting the structure of a `v8::HeapSnapshot`. `ValidateSnapshot` is particularly important, as it seems to check the integrity of the snapshot data.
* **`TEST` Macros:**  These are the core test cases using the `cctest` framework. Each test focuses on a specific aspect of heap snapshotting. The names of the tests (e.g., `HeapSnapshot`, `HeapSnapshotLocations`, `HeapSnapshotObjectSizes`) are very descriptive.

**4. Examining Individual Test Cases (Focusing on the First Few):**

* **`TEST(HeapSnapshot)`:**
    *  Creates a local V8 context (`LocalContext`).
    *  Runs some JavaScript code using `CompileRun`. This code defines functions and creates objects.
    *  Takes a heap snapshot using `heap_profiler->TakeHeapSnapshot()`.
    *  `CHECK(ValidateSnapshot(...))` suggests basic snapshot integrity.
    *  `GetGlobalObject` gets the global object from the snapshot.
    *  `GetProperty` is used to find specific properties on the global object (like "a2", "b2_1", "c2").
    *  The `NamedEntriesDetector` is used to verify the presence of specific named objects reachable from the global object.
    * **Inference:** This test verifies that basic object creation and relationships are correctly captured in the heap snapshot.

* **`TEST(HeapSnapshotLocations)`:**
    * Similar setup with JavaScript code.
    * Focuses on retrieving source code location information using `GetLocation`.
    * **Inference:** This test checks if the heap profiler correctly associates objects with their source code locations (line and column numbers).

* **`TEST(HeapSnapshotObjectSizes)`:**
    * JavaScript code creates objects and establishes relationships between them (a cycle).
    * Verifies that the shallow sizes of the objects in the snapshot are non-zero.
    * **Inference:** This tests if the heap profiler correctly captures the size of objects.

**5. Identifying Patterns and Key Functionality:**

* **Snapshot Creation:** The central action is taking a heap snapshot using `heap_profiler->TakeHeapSnapshot()`.
* **Snapshot Validation:** `ValidateSnapshot` is a recurring theme, highlighting the importance of ensuring the captured data is consistent and correct.
* **Graph Traversal:**  The helper functions indicate the code extensively traverses the heap graph represented by the snapshot.
* **Property and Internal Property Access:**  `GetProperty` is used to access object properties and internal slots.
* **Object Type Verification:**  The tests frequently check the type of nodes in the snapshot (e.g., `kClosure`, `kHeapNumber`, `kString`).
* **Specific Object Types:**  Tests are dedicated to specific JavaScript object types like bound functions, code objects, heap numbers, big integers, strings (sliced, cons), symbols, and collections (weak and strong). This indicates thorough testing of different object representations in the heap.

**6. Answering the Specific Questions (Mental Walkthrough):**

* **Functionality:** List the main actions observed.
* **Torque:** Check if the filename ends in `.tq`. It doesn't.
* **JavaScript Relation:** Yes, the tests run JavaScript code and then examine the resulting heap snapshots. Provide JavaScript examples corresponding to the C++ tests.
* **Code Logic Inference:**  For simple tests like `HeapSnapshotObjectSizes`, the input is the JavaScript code, and the output is the verification that object sizes are non-zero. For more complex tests, the assertions describe the expected structure of the snapshot.
* **Common Programming Errors:** Consider what heap profilers are used for – identifying memory leaks. A common error would be creating circular references that prevent garbage collection. Example: Two objects referencing each other indefinitely.
* **Part 1 Summary:**  Synthesize the observations into a concise summary.

**7. Refinement and Organization:**

Structure the answer logically, grouping related functionalities together. Use clear and concise language. Provide concrete examples where requested. Ensure all parts of the initial prompt are addressed.```cpp
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
      "b = 2.5;
### 提示词
```
这是目录为v8/test/cctest/test-heap-profiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-heap-profiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能
```

### 源代码
```
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
    const v8::HeapGraphEdge
```