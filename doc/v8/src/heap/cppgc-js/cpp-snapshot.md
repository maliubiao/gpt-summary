Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript example.

1. **Understanding the Request:** The request asks for a summary of the C++ code's functionality and a JavaScript example illustrating its relation to JavaScript. The file path suggests it deals with heap snapshots for C++ objects within the V8 JavaScript engine.

2. **Initial Skim for Keywords and Structures:** I would first quickly scan the code looking for prominent keywords and structures that give clues about its purpose. I'd be looking for:
    * `Snapshot`, `Graph`, `Node`, `Edge`: These immediately suggest graph construction for representing memory.
    * `CppHeap`, `JSObject`, `Isolate`: These indicate interaction with both C++ and JavaScript heaps within V8.
    * `Visit`, `Trace`: These are common patterns in garbage collection and memory traversal.
    * `Persistent`, `Weak`: Hints about different types of object references.
    * `Ephemeron`:  A specific type of weak reference often used in language implementations.
    * `Root`:  Starting points for graph traversal.
    * `State`, `Visibility`:  Suggests managing the status of objects during the snapshot process.
    * `SCC` (Strongly Connected Component), `Hidden`: Indicates a filtering mechanism for optimizing the graph.

3. **Identifying the Core Goal:** From the keywords, it becomes clear that the code's main purpose is to create a snapshot of the C++ heap that can be used by tools like the V8 heap profiler. This snapshot includes information about the objects, their sizes, and the relationships (edges) between them.

4. **Focusing on Key Classes and Their Roles:** I would then zoom in on the major classes to understand their specific functions:
    * `CppGraphBuilderImpl`: This is clearly the main driver of the snapshot process. It manages the overall algorithm.
    * `EmbedderNode`, `EmbedderRootNode`: These represent nodes in the graph, either regular C++ objects or special root nodes.
    * `State`, `RootState`, `StateStorage`: These handle the state and visibility of C++ objects during the snapshot process. The `Visibility` enum is important here.
    * `WeakVisitor`, `VisiblityVisitor`, `GraphBuildingVisitor`: These are different visitor patterns used for traversing the heap and building the graph in different phases.

5. **Deconstructing the Algorithm:** The comments in the code are crucial here. The "Main algorithm idea (two passes)" section explains the core logic:
    * **Pass 1 (Visibility):**  Determines which C++ objects are "visible" (reachable and not just hidden internal objects). This involves handling hidden objects and SCCs.
    * **Pass 2 (Graph Building):**  Creates the actual graph nodes and edges for the visible objects.

6. **Understanding the JavaScript Connection:** The code interacts with JavaScript in several ways:
    * `v8::Isolate`: Represents a JavaScript execution environment.
    * `v8::EmbedderGraph`: The API provided by V8 for building the heap snapshot graph.
    * `JSObject`, `v8::Local<v8::Data>`: Represent JavaScript objects and values.
    * `ExtractEmbedderDataBackref`: This function is key to understanding how C++ objects might be associated with JavaScript objects (e.g., through wrappers). The merging of nodes based on this backreference is a significant detail.

7. **Formulating the Summary:**  Based on the above analysis, I would start drafting the summary, focusing on:
    * The core purpose: Creating C++ heap snapshots for the V8 profiler.
    * The main components: Nodes, edges, and the two-pass algorithm.
    * The handling of hidden objects and SCCs.
    * The interaction with JavaScript objects through wrappers.
    * The different types of references (strong, weak, ephemeron).
    * The inclusion of root nodes.

8. **Crafting the JavaScript Example:** The key here is to illustrate *how* the C++ snapshot relates to JavaScript. The most direct link is through C++ objects that *wrap* JavaScript objects. The `ExtractEmbedderDataBackref` function is the clue.

    * **Scenario:** I would think of a common pattern where C++ code interacts with JavaScript. A good example is a C++ object that holds a reference to a JavaScript object (often as a wrapper or backing store).
    * **C++ Side:** Define a simple C++ class that has a `v8::Local<v8::Object>` member and uses the `SetEmbedderData` mechanism to establish the backreference.
    * **JavaScript Side:** Create a JavaScript object and then instantiate the C++ wrapper, passing the JavaScript object.
    * **The Connection:** The C++ snapshot will capture the C++ wrapper object. Crucially, the `ExtractEmbedderDataBackref` function will allow the snapshot process to recognize the link back to the JavaScript object. This is where the "merging" of nodes can occur.
    * **Illustrative Code:** The JavaScript example should clearly show the creation of both the C++ and JavaScript objects and how they are linked.

9. **Refining and Iterating:**  I would review the summary and the JavaScript example to ensure clarity, accuracy, and conciseness. I would check if the JavaScript example directly relates to the concepts described in the C++ code (especially the backreference and node merging). I might iterate on the wording to make it easier to understand for someone who isn't deeply familiar with V8 internals. For example, explicitly mentioning "wrappers" helps connect the C++ and JavaScript concepts.

This detailed breakdown demonstrates how to systematically approach understanding a complex piece of code by focusing on key elements, the overall algorithm, and the relationships between different parts of the system.
这个C++源代码文件 `cpp-snapshot.cc` 的主要功能是**为 V8 引擎中的 C++ 堆创建快照，以便进行堆分析和性能分析。** 它特别关注 cppgc (C++ garbage collection) 管理的 C++ 对象。

以下是其功能的详细归纳：

**核心功能:**

1. **构建 C++ 堆的对象图:**  它遍历 C++ 堆中的所有活动对象，并构建一个表示对象及其相互引用的图结构。这个图被用于 V8 的堆分析器。

2. **处理 C++ 对象和 JavaScript 对象之间的关系:**  它可以识别并表示 C++ 对象和 JavaScript 对象之间的关联。这对于理解整个 V8 堆（包括 C++ 和 JavaScript 部分）的内存结构至关重要。

3. **过滤 "隐藏" 对象:**  为了减少快照的大小和复杂性，它可以过滤掉仅被其他 "隐藏" 对象引用的对象。 "隐藏" 对象通常是内部实现细节，用户通常不感兴趣。

4. **处理不同类型的引用:**  它区分并处理不同类型的引用，包括：
    * **强引用:**  普通的 C++ 指针和引用。
    * **弱引用:**  `cppgc::Weak` 等弱引用机制。
    * **Ephemeron 引用:**  一种特殊的弱引用，只有当 key 存活时，value 才被认为是存活的。

5. **识别根对象:**  它识别 C++ 堆的根对象，例如全局持久句柄。这些根对象是垃圾回收的起始点。

6. **支持增量快照（可能）：** 虽然代码中没有明确提到增量快照，但其设计和状态管理可能为未来实现增量快照提供基础。

7. **与 V8 的堆分析器集成:**  最终生成的快照数据被传递给 V8 的堆分析器，用于生成堆统计信息、对象关系图等。

**与 JavaScript 的关系以及 JavaScript 示例:**

`cpp-snapshot.cc` 与 JavaScript 的功能有密切关系，因为它负责捕捉 C++ 堆中与 JavaScript 对象交互的部分。 V8 引擎内部大量使用了 C++ 来实现 JavaScript 的各种功能，例如：

* **内置对象和函数:** 很多内置的 JavaScript 对象（如 `Array`, `Map`, `Set`）和函数在底层是由 C++ 实现的。
* **宿主对象（Host Objects）:**  浏览器或 Node.js 等宿主环境提供的对象，通常是由 C++ 实现的。
* **V8 内部数据结构:**  V8 内部用于管理 JavaScript 堆的数据结构，很多也是由 C++ 实现的。

**JavaScript 示例:**

假设有一个 C++ 对象，它包装了一个 JavaScript 对象。当创建堆快照时，`cpp-snapshot.cc` 会识别并表示这种关系。

**C++ 代码片段（简化）：**

```c++
// 假设有一个 C++ 类，它持有一个 JavaScript 对象的引用
class MyWrapper {
 public:
  explicit MyWrapper(v8::Local<v8::Object> js_object) : js_object_(js_object) {
    // 设置 embedder data，以便在堆快照中建立关联
    js_object->SetInternalField(0, v8::External::New(v8::Isolate::GetCurrent(), this));
  }

 private:
  v8::Local<v8::Object> js_object_;
};
```

**JavaScript 代码:**

```javascript
// 创建一个 JavaScript 对象
let myJsObject = { data: "some data" };

// 创建一个 C++ 包装器对象，并将 JavaScript 对象传递给它
// (这通常是通过 Native Node.js 插件或 V8 的 C++ API 完成的)
let myCppWrapper = new MyWrapper(myJsObject);

// 当生成堆快照时，cpp-snapshot.cc 会检测到 myCppWrapper 对象，
// 并尝试找到与其关联的 JavaScript 对象。
```

**快照中的表示:**

在生成的堆快照中，你可能会看到：

* 一个表示 `myCppWrapper` C++ 对象的节点。
* 一个表示 `myJsObject` JavaScript 对象的节点。
* 一条从 `myCppWrapper` 节点指向 `myJsObject` 节点的边，表示 `myCppWrapper` 拥有或引用 `myJsObject`。

**更复杂的例子:**

考虑一个 Node.js 的 `Buffer` 对象。 `Buffer` 对象在 JavaScript 中表现为一个对象，但在底层，它是由 C++ 的 `node::Buffer` 类实现的，并管理着一块 C++ 分配的内存。 `cpp-snapshot.cc` 会负责捕捉这种关系，将 JavaScript 的 `Buffer` 对象与其底层的 C++ 实现连接起来。

**总结:**

`cpp-snapshot.cc` 是 V8 引擎中一个关键的组件，它负责生成 C++ 堆的快照，以便开发者能够理解 V8 的内存结构，识别内存泄漏，并进行性能优化。它通过识别 C++ 对象及其与 JavaScript 对象的关联，为分析整个 V8 运行时环境的内存使用情况提供了基础。

### 提示词
```
这是目录为v8/src/heap/cppgc-js/cpp-snapshot.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/cppgc-js/cpp-snapshot.h"

#include <memory>

#include "include/cppgc/heap-consistency.h"
#include "include/cppgc/internal/name-trait.h"
#include "include/cppgc/trace-trait.h"
#include "include/cppgc/visitor.h"
#include "include/v8-cppgc.h"
#include "include/v8-internal.h"
#include "include/v8-profiler.h"
#include "src/api/api-inl.h"
#include "src/base/logging.h"
#include "src/execution/isolate.h"
#include "src/heap/cppgc-js/cpp-heap.h"
#include "src/heap/cppgc/heap-object-header.h"
#include "src/heap/cppgc/heap-visitor.h"
#include "src/heap/cppgc/visitor.h"
#include "src/heap/mark-compact.h"
#include "src/objects/js-objects.h"
#include "src/objects/objects-inl.h"
#include "src/profiler/heap-profiler.h"

namespace v8 {
namespace internal {

class CppGraphBuilderImpl;
class StateStorage;
class State;

using cppgc::internal::HeapObjectHeader;

// Node representing a C++ object on the heap.
class EmbedderNode : public v8::EmbedderGraph::Node {
 public:
  EmbedderNode(const HeapObjectHeader* header_address,
               cppgc::internal::HeapObjectName name, size_t size)
      : header_address_(header_address),
        name_(name.value),
        size_(name.name_was_hidden ? 0 : size) {}
  ~EmbedderNode() override = default;

  const char* Name() final { return name_; }
  size_t SizeInBytes() final { return size_; }

  void SetWrapperNode(v8::EmbedderGraph::Node* wrapper_node) {
    // An embedder node may only be merged with a single wrapper node, as
    // consumers of the graph may merge a node and its wrapper node.
    //
    // TODO(chromium:1218404): Add a DCHECK() to avoid overriding an already
    // set `wrapper_node_`. This can currently happen with global proxies that
    // are rewired (and still kept alive) after reloading a page, see
    // `AddEdge`. We accept overriding the wrapper node in such cases,
    // leading to a random merged node and separated nodes for all other
    // proxies.
    wrapper_node_ = wrapper_node;
  }
  Node* WrapperNode() final { return wrapper_node_; }

  void SetDetachedness(Detachedness detachedness) {
    detachedness_ = detachedness;
  }
  Detachedness GetDetachedness() final { return detachedness_; }

  // Edge names are passed to V8 but are required to be held alive from the
  // embedder until the snapshot is compiled.
  const char* InternalizeEdgeName(std::string edge_name) {
    const size_t edge_name_len = edge_name.length();
    named_edges_.emplace_back(std::make_unique<char[]>(edge_name_len + 1));
    char* named_edge_str = named_edges_.back().get();
    snprintf(named_edge_str, edge_name_len + 1, "%s", edge_name.c_str());
    return named_edge_str;
  }

  const void* GetAddress() override { return header_address_; }

 private:
  const void* header_address_;
  const char* name_;
  size_t size_;
  Node* wrapper_node_ = nullptr;
  Detachedness detachedness_ = Detachedness::kUnknown;
  std::vector<std::unique_ptr<char[]>> named_edges_;
};

constexpr HeapObjectHeader* kNoNativeAddress = nullptr;

// Node representing an artificial root group, e.g., set of Persistent handles.
class EmbedderRootNode final : public EmbedderNode {
 public:
  explicit EmbedderRootNode(const char* name)
      : EmbedderNode(kNoNativeAddress, {name, false}, 0) {}
  ~EmbedderRootNode() final = default;

  bool IsRootNode() final { return true; }
};

// Canonical state representing real and artificial (e.g. root) objects.
class StateBase {
 public:
  // Objects can either be hidden/visible, or depend on some other nodes while
  // traversing the same SCC.
  enum class Visibility {
    kHidden,
    kDependentVisibility,
    kVisible,
  };

  StateBase(const void* key, size_t state_count, Visibility visibility,
            EmbedderNode* node, bool visited)
      : key_(key),
        state_count_(state_count),
        visibility_(visibility),
        node_(node),
        visited_(visited) {
    DCHECK_NE(Visibility::kDependentVisibility, visibility);
  }
  virtual ~StateBase() = default;

  // Visited objects have already been processed or are currently being
  // processed, see also IsPending() below.
  bool IsVisited() const { return visited_; }

  // Pending objects are currently being processed as part of the same SCC.
  bool IsPending() const { return pending_; }

  bool IsVisibleNotDependent() {
    auto v = GetVisibility();
    CHECK_NE(Visibility::kDependentVisibility, v);
    return v == Visibility::kVisible;
  }

  void set_node(EmbedderNode* node) {
    CHECK_EQ(Visibility::kVisible, GetVisibility());
    DCHECK_NULL(node_);
    node_ = node;
  }

  EmbedderNode* get_node() {
    CHECK_EQ(Visibility::kVisible, GetVisibility());
    return node_;
  }

 protected:
  const void* key_;
  // State count keeps track of node processing order. It is used to create only
  // dependencies on ancestors in the sub graph which ensures that there will be
  // no cycles in dependencies.
  const size_t state_count_;

  Visibility visibility_;
  StateBase* visibility_dependency_ = nullptr;
  EmbedderNode* node_;
  bool visited_;
  bool pending_ = false;

  Visibility GetVisibility() {
    FollowDependencies();
    return visibility_;
  }

  StateBase* FollowDependencies() {
    if (visibility_ != Visibility::kDependentVisibility) {
      CHECK_NULL(visibility_dependency_);
      return this;
    }
    StateBase* current = this;
    std::vector<StateBase*> dependencies;
    while (current->visibility_dependency_ &&
           current->visibility_dependency_ != current) {
      DCHECK_EQ(Visibility::kDependentVisibility, current->visibility_);
      dependencies.push_back(current);
      current = current->visibility_dependency_;
    }
    auto new_visibility = Visibility::kDependentVisibility;
    auto* new_visibility_dependency = current;
    if (current->visibility_ == Visibility::kVisible) {
      new_visibility = Visibility::kVisible;
      new_visibility_dependency = nullptr;
    } else if (!IsPending()) {
      DCHECK(IsVisited());
      // The object was not visible (above case). Having a dependency on itself
      // or null means no visible object was found.
      new_visibility = Visibility::kHidden;
      new_visibility_dependency = nullptr;
    }
    current->visibility_ = new_visibility;
    current->visibility_dependency_ = new_visibility_dependency;
    for (auto* state : dependencies) {
      state->visibility_ = new_visibility;
      state->visibility_dependency_ = new_visibility_dependency;
    }
    return current;
  }

  friend class State;
};

class State final : public StateBase {
 public:
  State(const HeapObjectHeader& header, size_t state_count)
      : StateBase(&header, state_count, Visibility::kHidden, nullptr, false) {}
  ~State() final = default;

  const HeapObjectHeader* header() const {
    return static_cast<const HeapObjectHeader*>(key_);
  }

  void MarkVisited() { visited_ = true; }

  void MarkPending() { pending_ = true; }
  void UnmarkPending() { pending_ = false; }

  void MarkVisible() {
    visibility_ = Visibility::kVisible;
    visibility_dependency_ = nullptr;
  }

  void MarkDependentVisibility(StateBase* dependency) {
    // Follow and update dependencies as much as possible.
    dependency = dependency->FollowDependencies();
    DCHECK(dependency->IsVisited());
    if (visibility_ == StateBase::Visibility::kVisible) {
      // Already visible, no dependency needed.
      DCHECK_NULL(visibility_dependency_);
      return;
    }
    if (dependency->visibility_ == Visibility::kVisible) {
      // Simple case: Dependency is visible.
      visibility_ = Visibility::kVisible;
      visibility_dependency_ = nullptr;
      return;
    }
    if ((visibility_dependency_ &&
         (visibility_dependency_->state_count_ > dependency->state_count_)) ||
        (!visibility_dependency_ &&
         (state_count_ > dependency->state_count_))) {
      // Only update when new state_count_ < original state_count_. This
      // ensures that we pick an ancestor as dependency and not a child which
      // is guaranteed to converge to an answer.
      //
      // Dependency is now
      // a) either pending with unknown visibility (same call chain), or
      // b) not pending and has defined visibility.
      //
      // It's not possible to point to a state that is not pending but has
      // dependent visibility because dependencies are updated to the top-most
      // dependency at the beginning of method.
      if (dependency->IsPending()) {
        visibility_ = Visibility::kDependentVisibility;
        visibility_dependency_ = dependency;
      } else {
        CHECK_NE(Visibility::kDependentVisibility, dependency->visibility_);
        if (dependency->visibility_ == Visibility::kVisible) {
          visibility_ = Visibility::kVisible;
          visibility_dependency_ = nullptr;
        }
      }
    }
  }

  void MarkAsWeakContainer() { is_weak_container_ = true; }
  bool IsWeakContainer() const { return is_weak_container_; }

  void MarkVisitedFromStack() { was_visited_from_stack_ = true; }
  bool WasVisitedFromStack() const { return was_visited_from_stack_; }

  void RecordEphemeronKey(const HeapObjectHeader& key) {
    // This ignores duplicate entries (in different containers) for the same
    // Key->Value pairs. Only one edge will be emitted in this case.
    ephemeron_keys_.insert(&key);
  }

  void AddEphemeronEdge(const HeapObjectHeader& value) {
    // This ignores duplicate entries (in different containers) for the same
    // Key->Value pairs. Only one edge will be emitted in this case.
    ephemeron_edges_.insert(&value);
  }

  void AddEagerEphemeronEdge(const void* value, cppgc::TraceCallback callback) {
    eager_ephemeron_edges_.insert({value, callback});
  }

  template <typename Callback>
  void ForAllEphemeronKeys(Callback callback) {
    for (const HeapObjectHeader* value : ephemeron_keys_) {
      callback(*value);
    }
  }

  template <typename Callback>
  void ForAllEphemeronEdges(Callback callback) {
    for (const HeapObjectHeader* value : ephemeron_edges_) {
      callback(*value);
    }
  }

  template <typename Callback>
  void ForAllEagerEphemeronEdges(Callback callback) {
    for (const auto& pair : eager_ephemeron_edges_) {
      callback(pair.first, pair.second);
    }
  }

 private:
  bool is_weak_container_ = false;
  bool was_visited_from_stack_ = false;
  // Ephemeron keys that will be strongified if a weak container is reachable
  // from stack.
  std::unordered_set<const HeapObjectHeader*> ephemeron_keys_;
  // Values that are held alive through ephemerons by this particular key.
  std::unordered_set<const HeapObjectHeader*> ephemeron_edges_;
  // Values that are eagerly traced and held alive through ephemerons by this
  // particular key.
  std::unordered_map<const void*, cppgc::TraceCallback> eager_ephemeron_edges_;
};

// Root states are similar to regular states with the difference that they are
// always visible.
class RootState final : public StateBase {
 public:
  RootState(EmbedderRootNode* node, size_t state_count)
      // Root states are always visited, visible, and have a node attached.
      : StateBase(node, state_count, Visibility::kVisible, node, true) {}
  ~RootState() final = default;
};

// Abstraction for storing states. Storage allows for creation and lookup of
// different state objects.
class StateStorage final {
 public:
  bool StateExists(const void* key) const {
    return states_.find(key) != states_.end();
  }

  StateBase& GetExistingState(const void* key) const {
    CHECK(StateExists(key));
    return *states_.at(key).get();
  }

  State& GetExistingState(const HeapObjectHeader& header) const {
    return static_cast<State&>(GetExistingState(&header));
  }

  State& GetOrCreateState(const HeapObjectHeader& header) {
    if (!StateExists(&header)) {
      auto it = states_.insert(std::make_pair(
          &header, std::make_unique<State>(header, ++state_count_)));
      DCHECK(it.second);
      USE(it);
    }
    return GetExistingState(header);
  }

  RootState& CreateRootState(EmbedderRootNode* root_node) {
    CHECK(!StateExists(root_node));
    auto it = states_.insert(std::make_pair(
        root_node, std::make_unique<RootState>(root_node, ++state_count_)));
    DCHECK(it.second);
    USE(it);
    return static_cast<RootState&>(*it.first->second);
  }

  template <typename Callback>
  void ForAllVisibleStates(Callback callback) {
    for (auto& state : states_) {
      if (state.second->IsVisibleNotDependent()) {
        callback(state.second.get());
      }
    }
  }

 private:
  std::unordered_map<const void*, std::unique_ptr<StateBase>> states_;
  size_t state_count_ = 0;
};

void* ExtractEmbedderDataBackref(Isolate* isolate, CppHeap& cpp_heap,
                                 v8::Local<v8::Data> v8_value) {
  if (!(v8_value->IsValue() && v8_value.As<v8::Value>()->IsObject()))
    return nullptr;

  DirectHandle<Object> v8_object = Utils::OpenDirectHandle(*v8_value);
  if (!IsJSObject(*v8_object) ||
      !Cast<JSObject>(*v8_object)->MayHaveEmbedderFields()) {
    return nullptr;
  }

  Tagged<JSObject> js_object = Cast<JSObject>(*v8_object);
  // Not every object that can have embedder fields is actually a JSApiWrapper.
  if (!IsJSApiWrapperObject(*js_object)) {
    return nullptr;
  }
  // Wrapper using cpp_heap_wrappable field.
  return JSApiWrapper(*js_object)
      .GetCppHeapWrappable(isolate, kAnyCppHeapPointer);
}

// The following implements a snapshotting algorithm for C++ objects that also
// filters strongly-connected components (SCCs) of only "hidden" objects that
// are not (transitively) referencing any non-hidden objects.
//
// C++ objects come in two versions.
// a. Named objects that have been assigned a name through NameProvider.
// b. Unnamed objects, that are potentially hidden if the build configuration
//    requires Oilpan to hide such names. Hidden objects have their name
//    set to NameProvider::kHiddenName.
//
// The main challenge for the algorithm is to avoid blowing up the final object
// graph with hidden nodes that do not carry information. For that reason, the
// algorithm filters SCCs of only hidden objects, e.g.:
//   ... -> (object) -> (object) -> (hidden) -> (hidden)
// In this case the (hidden) objects are filtered from the graph. The trickiest
// part is maintaining visibility state for objects referencing other objects
// that are currently being processed.
//
// Main algorithm idea (two passes):
// 1. First pass marks all non-hidden objects and those that transitively reach
//    non-hidden objects as visible. Details:
//    - Iterate over all objects.
//    - If object is non-hidden mark it as visible and also mark parent as
//      visible if needed.
//    - If object is hidden, traverse children as DFS to find non-hidden
//      objects. Post-order process the objects and mark those objects as
//      visible that have child nodes that are visible themselves.
//    - Maintain an epoch counter (StateStorage::state_count_) to allow
//      deferring the visibility decision to other objects in the same SCC. This
//      is similar to the "lowlink" value in Tarjan's algorithm for SCC.
//    - After the first pass it is guaranteed that all deferred visibility
//      decisions can be resolved.
// 2. Second pass adds nodes and edges for all visible objects.
//    - Upon first checking the visibility state of an object, all deferred
//      visibility states are resolved.
//
// For practical reasons, the recursion is transformed into an iteration. We do
// do not use plain Tarjan's algorithm to avoid another pass over all nodes to
// create SCCs.
class CppGraphBuilderImpl final {
 public:
  CppGraphBuilderImpl(CppHeap& cpp_heap, v8::EmbedderGraph& graph)
      : cpp_heap_(cpp_heap), graph_(graph) {}

  void Run();

  void VisitForVisibility(State* parent, const HeapObjectHeader&);
  void VisitForVisibility(State& parent, const TracedReferenceBase&);
  void VisitEphemeronForVisibility(const HeapObjectHeader& key,
                                   const HeapObjectHeader& value);
  void VisitEphemeronWithNonGarbageCollectedValueForVisibility(
      const HeapObjectHeader& key, const void* value,
      cppgc::TraceDescriptor value_desc);
  void VisitWeakContainerForVisibility(const HeapObjectHeader&);
  void VisitRootForGraphBuilding(RootState&, const HeapObjectHeader&,
                                 const cppgc::SourceLocation&);
  void ProcessPendingObjects();

  void RecordEphemeronKey(const HeapObjectHeader&, const HeapObjectHeader&);
  void AddConservativeEphemeronKeyEdgesIfNeeded(const HeapObjectHeader&);

  EmbedderRootNode* AddRootNode(const char* name) {
    return static_cast<EmbedderRootNode*>(graph_.AddNode(
        std::unique_ptr<v8::EmbedderGraph::Node>{new EmbedderRootNode(name)}));
  }

  EmbedderNode* AddNode(const HeapObjectHeader& header) {
    return static_cast<EmbedderNode*>(graph_.AddNode(
        std::unique_ptr<v8::EmbedderGraph::Node>{new EmbedderNode(
            &header, header.GetName(), header.AllocatedSize())}));
  }

  void AddEdge(State& parent, const HeapObjectHeader& header,
               const std::string& edge_name) {
    DCHECK(parent.IsVisibleNotDependent());
    auto& current = states_.GetExistingState(header);
    if (!current.IsVisibleNotDependent()) return;

    // Both states are visible. Create nodes in case this is the first edge
    // created for any of them.
    if (!parent.get_node()) {
      parent.set_node(AddNode(*parent.header()));
    }
    if (!current.get_node()) {
      current.set_node(AddNode(header));
    }

    if (!edge_name.empty()) {
      graph_.AddEdge(parent.get_node(), current.get_node(),
                     parent.get_node()->InternalizeEdgeName(edge_name));
    } else {
      graph_.AddEdge(parent.get_node(), current.get_node());
    }
  }

  void AddEdge(State& parent, const TracedReferenceBase& ref,
               const std::string& edge_name) {
    DCHECK(parent.IsVisibleNotDependent());
    v8::Local<v8::Data> v8_data =
        ref.Get(reinterpret_cast<v8::Isolate*>(cpp_heap_.isolate()));
    if (v8_data.IsEmpty()) return;

    if (!parent.get_node()) {
      parent.set_node(AddNode(*parent.header()));
    }
    auto* v8_node = graph_.V8Node(v8_data);
    if (!edge_name.empty()) {
      graph_.AddEdge(parent.get_node(), v8_node,
                     parent.get_node()->InternalizeEdgeName(edge_name));
    } else {
      graph_.AddEdge(parent.get_node(), v8_node);
    }

    // Don't merge nodes if edges have a name.
    if (!edge_name.empty()) return;

    // Try to extract the back reference. If the back reference matches
    // `parent`, then the nodes are merged.
    void* back_reference_object = ExtractEmbedderDataBackref(
        reinterpret_cast<v8::internal::Isolate*>(cpp_heap_.isolate()),
        cpp_heap_, v8_data);
    if (!back_reference_object) return;
    // Only JS objects have back references.
    DCHECK(v8_data->IsValue() && v8_data.As<v8::Value>()->IsObject());

    auto& back_header = HeapObjectHeader::FromObject(back_reference_object);
    auto& back_state = states_.GetExistingState(back_header);

    // If the back reference doesn't point to the same header, just return. In
    // such a case we have stand-alone references to a wrapper.
    if (parent.header() != back_state.header()) return;

    // Back reference points to parents header. In this case, the nodes should
    // be merged and query the detachedness state of the embedder.
    if (!back_state.get_node()) {
      back_state.set_node(AddNode(back_header));
    }
    back_state.get_node()->SetWrapperNode(v8_node);

    auto* profiler =
        reinterpret_cast<Isolate*>(cpp_heap_.isolate())->heap_profiler();
    if (profiler->HasGetDetachednessCallback()) {
      back_state.get_node()->SetDetachedness(
          profiler->GetDetachedness(v8_data.As<v8::Value>(), 0));
    }
  }

  void AddRootEdge(RootState& root, State& child, std::string edge_name) {
    DCHECK(root.IsVisibleNotDependent());
    if (!child.IsVisibleNotDependent()) return;

    // Root states always have a node set.
    DCHECK_NOT_NULL(root.get_node());
    if (!child.get_node()) {
      child.set_node(AddNode(*child.header()));
    }

    if (!edge_name.empty()) {
      graph_.AddEdge(root.get_node(), child.get_node(),
                     root.get_node()->InternalizeEdgeName(edge_name));
      return;
    }
    graph_.AddEdge(root.get_node(), child.get_node());
  }

 private:
  class WorkstackItemBase;
  class VisitationItem;
  class VisitationDoneItem;

  struct MergedNodeItem {
    EmbedderGraph::Node* node_;
    v8::Local<v8::Value> value_;
  };

  CppHeap& cpp_heap_;
  v8::EmbedderGraph& graph_;
  StateStorage states_;
  std::vector<std::unique_ptr<WorkstackItemBase>> workstack_;
};

// Iterating live objects to mark them as visible if needed.
class LiveObjectsForVisibilityIterator final
    : public cppgc::internal::HeapVisitor<LiveObjectsForVisibilityIterator> {
  friend class cppgc::internal::HeapVisitor<LiveObjectsForVisibilityIterator>;

 public:
  explicit LiveObjectsForVisibilityIterator(CppGraphBuilderImpl& graph_builder)
      : graph_builder_(graph_builder) {}

 private:
  bool VisitHeapObjectHeader(HeapObjectHeader& header) {
    if (header.IsFree()) return true;
    graph_builder_.VisitForVisibility(nullptr, header);
    graph_builder_.ProcessPendingObjects();
    return true;
  }

  CppGraphBuilderImpl& graph_builder_;
};

class ParentScope final {
 public:
  explicit ParentScope(StateBase& parent) : parent_(parent) {}

  RootState& ParentAsRootState() const {
    return static_cast<RootState&>(parent_);
  }
  State& ParentAsRegularState() const { return static_cast<State&>(parent_); }

 private:
  StateBase& parent_;
};

// This visitor can be used stand-alone to handle fully weak and ephemeron
// containers or as part of the VisibilityVisitor that recursively traverses
// the object graph.
class WeakVisitor : public JSVisitor {
 public:
  explicit WeakVisitor(CppGraphBuilderImpl& graph_builder)
      : JSVisitor(cppgc::internal::VisitorFactory::CreateKey()),
        graph_builder_(graph_builder) {}

  void VisitWeakContainer(const void* object,
                          cppgc::TraceDescriptor strong_desc,
                          cppgc::TraceDescriptor weak_desc, cppgc::WeakCallback,
                          const void*) final {
    const auto& container_header =
        HeapObjectHeader::FromObject(strong_desc.base_object_payload);
    WeakContainerScope weak_container_scope(*this, container_header);

    graph_builder_.VisitWeakContainerForVisibility(container_header);

    if (!weak_desc.callback) {
      // Weak container does not contribute to liveness.
      return;
    }
    // Heap snapshot is always run after a GC so we know there are no dead
    // entries in the container.
    if (object) {
      // The container will itself be traced strongly via the regular Visit()
      // handling that iterates over all live objects. The visibility visitor
      // will thus see (because of strongly treating the container):
      // 1. the container itself;
      // 2. for each {key} in container: container->key;
      // 3. for each {key, value} in container: key->value;
      //
      // In case the visitor is used stand-alone, we trace through the container
      // here to create the same state as we would when the container is traced
      // separately.
      container_header.Trace(this);
    }
  }
  void VisitEphemeron(const void* key, const void* value,
                      cppgc::TraceDescriptor value_desc) final {
    // For ephemerons, the key retains the value.
    // Key always must be a GarbageCollected object.
    auto& key_header = HeapObjectHeader::FromObject(key);
    if (current_weak_container_header_) {
      graph_builder_.RecordEphemeronKey(*current_weak_container_header_,
                                        key_header);
    }
    if (!value_desc.base_object_payload) {
      // Value does not represent an actual GarbageCollected object but rather
      // should be traced eagerly.
      graph_builder_.VisitEphemeronWithNonGarbageCollectedValueForVisibility(
          key_header, value, value_desc);
      return;
    }
    // Regular path where both key and value are GarbageCollected objects.
    graph_builder_.VisitEphemeronForVisibility(
        key_header, HeapObjectHeader::FromObject(value));
  }

 protected:
  class WeakContainerScope {
   public:
    explicit WeakContainerScope(WeakVisitor& weak_visitor,
                                const HeapObjectHeader& weak_container_header)
        : weak_visitor_(weak_visitor),
          prev_weak_container_header_(
              weak_visitor_.current_weak_container_header_) {
      weak_visitor_.current_weak_container_header_ = &weak_container_header;
    }
    ~WeakContainerScope() {
      weak_visitor_.current_weak_container_header_ =
          prev_weak_container_header_;
    }

   private:
    WeakVisitor& weak_visitor_;
    const HeapObjectHeader* prev_weak_container_header_;
  };

  CppGraphBuilderImpl& graph_builder_;
  const HeapObjectHeader* current_weak_container_header_ = nullptr;
};

class VisiblityVisitor final : public WeakVisitor {
 public:
  VisiblityVisitor(CppGraphBuilderImpl& graph_builder,
                   const ParentScope& parent_scope)
      : WeakVisitor(graph_builder), parent_scope_(parent_scope) {}

  // C++ handling.
  void Visit(const void*, cppgc::TraceDescriptor desc) final {
    graph_builder_.VisitForVisibility(
        &parent_scope_.ParentAsRegularState(),
        HeapObjectHeader::FromObject(desc.base_object_payload));
  }

  // JS handling.
  void Visit(const TracedReferenceBase& ref) final {
    graph_builder_.VisitForVisibility(parent_scope_.ParentAsRegularState(),
                                      ref);
  }

 private:
  const ParentScope& parent_scope_;
};

class GraphBuildingRootVisitor final : public cppgc::internal::RootVisitorBase {
 public:
  GraphBuildingRootVisitor(CppGraphBuilderImpl& graph_builder,
                           const ParentScope& parent_scope)
      : graph_builder_(graph_builder), parent_scope_(parent_scope) {}

  void VisitRoot(const void*, cppgc::TraceDescriptor desc,
                 const cppgc::SourceLocation& loc) final {
    graph_builder_.VisitRootForGraphBuilding(
        parent_scope_.ParentAsRootState(),
        HeapObjectHeader::FromObject(desc.base_object_payload), loc);
  }

 private:
  CppGraphBuilderImpl& graph_builder_;
  const ParentScope& parent_scope_;
};

class GraphBuildingVisitor final : public JSVisitor {
 public:
  GraphBuildingVisitor(CppGraphBuilderImpl& graph_builder,
                       const ParentScope& parent_scope)
      : JSVisitor(cppgc::internal::VisitorFactory::CreateKey()),
        graph_builder_(graph_builder),
        parent_scope_(parent_scope) {}

  // C++ handling.
  void Visit(const void*, cppgc::TraceDescriptor desc) final {
    graph_builder_.AddEdge(
        parent_scope_.ParentAsRegularState(),
        HeapObjectHeader::FromObject(desc.base_object_payload), edge_name_);
  }
  void VisitWeakContainer(const void* object,
                          cppgc::TraceDescriptor strong_desc,
                          cppgc::TraceDescriptor weak_desc, cppgc::WeakCallback,
                          const void*) final {
    // Add an edge from the object holding the weak container to the weak
    // container itself.
    graph_builder_.AddEdge(
        parent_scope_.ParentAsRegularState(),
        HeapObjectHeader::FromObject(strong_desc.base_object_payload),
        edge_name_);
  }

  // JS handling.
  void Visit(const TracedReferenceBase& ref) final {
    graph_builder_.AddEdge(parent_scope_.ParentAsRegularState(), ref,
                           edge_name_);
  }

  void set_edge_name(std::string edge_name) {
    edge_name_ = std::move(edge_name);
  }

 private:
  CppGraphBuilderImpl& graph_builder_;
  const ParentScope& parent_scope_;
  std::string edge_name_;
};

// Base class for transforming recursion into iteration. Items are processed
// in stack fashion.
class CppGraphBuilderImpl::WorkstackItemBase {
 public:
  WorkstackItemBase(State* parent, State& current)
      : parent_(parent), current_(current) {}

  virtual ~WorkstackItemBase() = default;
  virtual void Process(CppGraphBuilderImpl&) = 0;

 protected:
  State* parent_;
  State& current_;
};

void CppGraphBuilderImpl::ProcessPendingObjects() {
  while (!workstack_.empty()) {
    std::unique_ptr<WorkstackItemBase> item = std::move(workstack_.back());
    workstack_.pop_back();
    item->Process(*this);
  }
}

// Post-order processing of an object. It's guaranteed that all children have
// been processed first.
class CppGraphBuilderImpl::VisitationDoneItem final : public WorkstackItemBase {
 public:
  VisitationDoneItem(State* parent, State& current)
      : WorkstackItemBase(parent, current) {}

  void Process(CppGraphBuilderImpl& graph_builder) final {
    CHECK(parent_);
    parent_->MarkDependentVisibility(&current_);
    current_.UnmarkPending();
  }
};

class CppGraphBuilderImpl::VisitationItem final : public WorkstackItemBase {
 public:
  VisitationItem(State* parent, State& current)
      : WorkstackItemBase(parent, current) {}

  void Process(CppGraphBuilderImpl& graph_builder) final {
    if (parent_) {
      // Re-add the same object for post-order processing. This must happen
      // lazily, as the parent's visibility depends on its children.
      graph_builder.workstack_.push_back(std::unique_ptr<WorkstackItemBase>{
          new VisitationDoneItem(parent_, current_)});
    }
    ParentScope parent_scope(current_);
    VisiblityVisitor object_visitor(graph_builder, parent_scope);
    if (!current_.header()->IsInConstruction()) {
      // TODO(mlippautz): Handle in construction objects.
      current_.header()->Trace(&object_visitor);
    }
    if (!parent_) {
      current_.UnmarkPending();
    }
  }
};

void CppGraphBuilderImpl::VisitForVisibility(State* parent,
                                             const HeapObjectHeader& header) {
  auto& current = states_.GetOrCreateState(header);

  if (current.IsVisited()) {
    // Avoid traversing into already visited subgraphs and just update the state
    // based on a previous result.
    if (parent) {
      parent->MarkDependentVisibility(&current);
    }
    return;
  }

  current.MarkVisited();
  if (header.GetName().name_was_hidden) {
    current.MarkPending();
    workstack_.push_back(std::unique_ptr<WorkstackItemBase>{
        new VisitationItem(parent, current)});
  } else {
    // No need to mark/unmark pending as the node is immediately processed.
    current.MarkVisible();
    // In case the names are visible, the graph is not traversed in this phase.
    // Explicitly trace one level to handle weak containers.
    WeakVisitor weak_visitor(*this);
    header.Trace(&weak_visitor);
    if (parent) {
      // Eagerly update a parent object as its visibility state is now fixed.
      parent->MarkVisible();
    }
  }
}

void CppGraphBuilderImpl::
    VisitEphemeronWithNonGarbageCollectedValueForVisibility(
        const HeapObjectHeader& key, const void* value,
        cppgc::TraceDescriptor value_desc) {
  auto& key_state = states_.GetOrCreateState(key);
  // Eagerly trace the value here, effectively marking key as visible and
  // queuing processing for all reachable values.
  ParentScope parent_scope(key_state);
  VisiblityVisitor visitor(*this, parent_scope);
  value_desc.callback(&visitor, value);
  key_state.AddEagerEphemeronEdge(value, value_desc.callback);
}

void CppGraphBuilderImpl::VisitEphemeronForVisibility(
    const HeapObjectHeader& key, const HeapObjectHeader& value) {
  auto& key_state = states_.GetOrCreateState(key);
  VisitForVisibility(&key_state, value);
  key_state.AddEphemeronEdge(value);
}

void CppGraphBuilderImpl::VisitWeakContainerForVisibility(
    const HeapObjectHeader& container_header) {
  // Mark the container here as weak container to avoid creating any
  // outgoing edges in the second phase.
  states_.GetOrCreateState(container_header).MarkAsWeakContainer();
}

void CppGraphBuilderImpl::RecordEphemeronKey(const HeapObjectHeader& container,
                                             const HeapObjectHeader& key) {
  auto& container_state = states_.GetOrCreateState(container);
  DCHECK(container_state.IsWeakContainer());
  container_state.RecordEphemeronKey(key);
}

void CppGraphBuilderImpl::AddConservativeEphemeronKeyEdgesIfNeeded(
    const HeapObjectHeader& header) {
  auto& state = states_.GetExistingState(header);
  if (state.WasVisitedFromStack()) {
    return;
  }
  state.MarkVisitedFromStack();
  state.ForAllEphemeronKeys([this, &state](const HeapObjectHeader& key) {
    DCHECK(state.IsWeakContainer());
    AddEdge(state, key, "");
  });
}

void CppGraphBuilderImpl::VisitForVisibility(State& parent,
                                             const TracedReferenceBase& ref) {
  v8::Local<v8::Data> v8_value =
      ref.Get(reinterpret_cast<v8::Isolate*>(cpp_heap_.isolate()));
  if (!v8_value.IsEmpty()) {
    parent.MarkVisible();
  }
}

void CppGraphBuilderImpl::VisitRootForGraphBuilding(
    RootState& root, const HeapObjectHeader& header,
    const cppgc::SourceLocation& loc) {
  State& current = states_.GetExistingState(header);
  if (!current.IsVisibleNotDependent()) return;

  AddRootEdge(root, current, loc.ToString());
}

namespace {

// Visitor adds edges from native stack roots to objects.
class GraphBuildingStackVisitor
    : public cppgc::internal::ConservativeTracingVisitor,
      public ::heap::base::StackVisitor,
      public cppgc::Visitor {
 public:
  GraphBuildingStackVisitor(CppGraphBuilderImpl& graph_builder, CppHeap& heap,
                            GraphBuildingRootVisitor& root_visitor)
      : cppgc::internal::ConservativeTracingVisitor(heap, *heap.page_backend(),
                                                    *this),
        cppgc::Visitor(cppgc::internal::VisitorFactory::CreateKey()),
        graph_builder_(graph_builder),
        root_visitor_(root_visitor) {}

  void VisitPointer(const void* address) final {
    // Entry point for stack walk. The conservative visitor dispatches as
    // follows:
    // - Fully constructed objects: VisitFullyConstructedConservatively()
    // - Objects in construction: VisitInConstructionConservatively()
    TraceConservativelyIfNeeded(address);
  }

  void VisitFullyConstructedConservatively(HeapObjectHeader& header) final {
    VisitConservatively(header);
  }

  void VisitInConstructionConservatively(HeapObjectHeader& header,
                                         TraceConservativelyCallback) final {
    VisitConservatively(header);
  }

 private:
  void VisitConservatively(HeapObjectHeader& header) {
    root_visitor_.VisitRoot(header.ObjectStart(),
                            {header.ObjectStart(), nullptr},
                            cppgc::SourceLocation());
    graph_builder_.AddConservativeEphemeronKeyEdgesIfNeeded(header);
  }

  CppGraphBuilderImpl& graph_builder_;
  GraphBuildingRootVisitor& root_visitor_;
};

}  // namespace

void CppGraphBuilderImpl::Run() {
  // Sweeping from a previous GC might still be running, in which case not all
  // pages have been returned to spaces yet.
  cpp_heap_.sweeper().FinishIfRunning();
  cppgc::subtle::DisallowGarbageCollectionScope no_gc(
      cpp_heap_.GetHeapHandle());
  // First pass: Figure out which objects should be included in the graph -- see
  // class-level comment on CppGraphBuilder.
  LiveObjectsForVisibilityIterator visitor(*this);
  visitor.Traverse(cpp_heap_.raw_heap());
  // Second pass: Add graph nodes for objects that must be shown.
  states_.ForAllVisibleStates([this](StateBase* state_base) {
    // No roots have been created so far, so all StateBase objects are State.
    State& state = *static_cast<State*>(state_base);

    // Emit no edges for the contents of the weak containers. For both, fully
    // weak and ephemeron containers, the contents should be retained from
    // somewhere else.
    if (state.IsWeakContainer()) return;

    ParentScope parent_scope(state);
    GraphBuildingVisitor object_visitor(*this, parent_scope);
    if (!state.header()->IsInConstruction()) {
      // TODO(mlippautz): Handle in-construction objects.
      state.header()->Trace(&object_visitor);
    }
    state.ForAllEphemeronEdges([this, &state](const HeapObjectHeader& value) {
      AddEdge(state, value, "part of key -> value pair in ephemeron table");
    });
    object_visitor.set_edge_name(
        "part of key -> value pair in ephemeron table");
    state.ForAllEagerEphemeronEdges(
        [&object_visitor](const void* value, cppgc::TraceCallback callback) {
          callback(&object_visitor, value);
        });
  });
  // Add roots.
  {
    ParentScope parent_scope(
        states_.CreateRootState(AddRootNode("C++ Persistent roots")));
    GraphBuildingRootVisitor root_object_visitor(*this, parent_scope);
    cpp_heap_.GetStrongPersistentRegion().Iterate(root_object_visitor);
  }
  {
    ParentScope parent_scope(states_.CreateRootState(
        AddRootNode("C++ CrossThreadPersistent roots")));
    GraphBuildingRootVisitor root_object_visitor(*this, parent_scope);
    cppgc::internal::PersistentRegionLock guard;
    cpp_heap_.GetStrongCrossThreadPersistentRegion().Iterate(
        root_object_visitor);
  }
  // Only add stack roots in case the callback is not run from generating a
  // snapshot without stack. This avoids adding false-positive edges when
  // conservatively scanning the stack.
  if (cpp_heap_.isolate()->heap()->IsGCWithMainThreadStack()) {
    ParentScope parent_scope(
        states_.CreateRootState(AddRootNode("C++ native stack roots")));
    GraphBuildingRootVisitor root_object_visitor(*this, parent_scope);
    GraphBuildingStackVisitor stack_visitor(*this, cpp_heap_,
                                            root_object_visitor);
    cpp_heap_.stack()->IteratePointersUntilMarker(&stack_visitor);
  }
}

// static
void CppGraphBuilder::Run(v8::Isolate* isolate, v8::EmbedderGraph* graph,
                          void* data) {
  CppHeap* cpp_heap = static_cast<CppHeap*>(data);
  CHECK_NOT_NULL(cpp_heap);
  CHECK_NOT_NULL(graph);
  CppGraphBuilderImpl graph_builder(*cpp_heap, *graph);
  graph_builder.Run();
}

}  // namespace internal
}  // namespace v8
```