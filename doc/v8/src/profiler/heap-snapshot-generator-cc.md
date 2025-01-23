Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

1. **Initial Scan and Purpose Identification:**

   - The file name `heap-snapshot-generator.cc` strongly suggests its core function: generating heap snapshots.
   - The included headers like `profiler/heap-profiler.h`, `heap/heap.h`, and `objects/objects-inl.h` confirm this is related to V8's profiling and memory management.
   - The copyright notice indicates it's part of the V8 project.

2. **High-Level Functionality - The "What":**

   - Heap snapshots are for debugging and performance analysis. They capture the state of the heap (objects and their relationships) at a specific point in time.
   - The code seems to be responsible for traversing the heap and constructing a representation of this snapshot.

3. **Key Data Structures and Concepts - The "How":**

   - **`HeapSnapshot`:**  Likely the main class representing the snapshot. It will contain the nodes (objects) and edges (references).
   - **`HeapEntry`:** Represents a single object in the heap snapshot. It stores information like type, name, size, and connections to other objects.
   - **`HeapGraphEdge`:** Represents a reference (edge) between two `HeapEntry` objects. It has a type (e.g., property, element, weak) and information about the connection.
   - **`HeapObjectsMap`:**  Seems to be a utility for managing the mapping between actual heap object addresses and their IDs in the snapshot. This is crucial for efficiency and avoiding duplicates.
   - **Verification (`HeapEntryVerifier`):**  There's a conditional compilation block (`#ifdef V8_ENABLE_HEAP_SNAPSHOT_VERIFY`) for a verifier. This strongly suggests the code has built-in mechanisms to ensure the correctness of the generated snapshot. This involves checking if the reported edges actually correspond to real object references in the heap.

4. **Code Logic and Flow (Initial Observations):**

   - **Object Traversal:** The `HeapObjectsMap::UpdateHeapObjectsMap()` function clearly iterates through the heap.
   - **Entry Creation:** Functions like `HeapSnapshot::AddEntry()` are responsible for creating `HeapEntry` objects.
   - **Edge Creation:**  `HeapEntry::SetNamedReference()` and `HeapEntry::SetIndexedReference()` add edges between entries.
   - **Verification Logic:** The `HeapEntryVerifier` class with methods like `CheckStrongReference` and `CheckWeakReference` suggests a process of validating the relationships.
   - **Synthetic Roots:** The `HeapSnapshot::AddSyntheticRootEntries()` function indicates the inclusion of special "root" nodes to represent the starting points of garbage collection.

5. **Relating to JavaScript (if applicable):**

   - The heap being analyzed is the V8 JavaScript heap.
   - The types of `HeapEntry` (e.g., `kString`, `kArray`, `kObject`, `kClosure`) directly correspond to JavaScript data types and structures.
   - The relationships captured by `HeapGraphEdge` represent how JavaScript objects reference each other (e.g., object properties, array elements, closure scopes).
   -  The concept of garbage collection roots is fundamental to JavaScript's memory management.

6. **Hypothetical Input and Output (Simplified):**

   - *Input:*  A running V8 instance with some JavaScript objects allocated (e.g., an object with properties, an array).
   - *Output:* A structured representation (the heap snapshot) containing:
     - `HeapEntry` objects for each allocated JavaScript object (and potentially internal V8 objects).
     - `HeapGraphEdge` objects representing the references between these objects. For example, an edge from the object to its properties, or from the array to its elements.

7. **Common Programming Errors (related to heap snapshots):**

   - **Memory Leaks:**  Heap snapshots are a primary tool for identifying memory leaks in JavaScript applications. The snapshot can show objects that are unexpectedly retained, preventing them from being garbage collected.
   - **Unexpected Object Retention:**  Sometimes objects are kept alive longer than intended due to unforeseen references. Heap snapshots help in tracing these reference chains.

8. **Torque Check:**

   - The prompt specifically asks about `.tq` files. A quick scan reveals no `.tq` extensions in the provided code. Therefore, it's not Torque code.

9. **Summarization (Instruction #5):**

   -  Combine the key observations into a concise summary of the file's purpose and core functionalities.

10. **Iteration and Refinement:**

   - Review the code more carefully, paying attention to details like enums (`HeapGraphEdge::Type`), structs, and helper functions.
   - Ensure the summary accurately reflects the code's behavior. For example, emphasize the verification aspect if the `#ifdef` block is prominent.

This step-by-step approach, starting with broad strokes and gradually diving into details, helps to understand complex code like this V8 component. The focus is on identifying the "what," "how," and "why" of the code, and then relating it back to the user's query (JavaScript relevance, potential errors, etc.).
好的，让我们来分析一下 `v8/src/profiler/heap-snapshot-generator.cc` 这个文件的功能。

**1. 文件类型判断：**

* 文件名以 `.cc` 结尾，这表明它是一个 **C++** 源代码文件，而不是 Torque 源代码（Torque 源代码以 `.tq` 结尾）。

**2. 核心功能归纳：**

从代码的结构、包含的头文件以及类名来看，`heap-snapshot-generator.cc` 的主要功能是 **生成 V8 堆的快照（Heap Snapshot）**。  这个快照记录了 V8 引擎在特定时间点的堆内存状态，包括：

* **堆中存在的对象：**  各种类型的 JavaScript 对象（如对象、数组、字符串、函数等）以及 V8 内部对象。
* **对象之间的引用关系：**  哪些对象引用了哪些其他对象，构成了对象的引用图。
* **对象的大小：**  每个对象占用的内存大小。
* **对象的类型：**  例如，是普通对象、数组、字符串、闭包等等。
* **对象的 ID：**  用于在快照中唯一标识每个对象。
* **对象的名称或描述：**  尽可能提供对象的描述性名称。
* **代码位置信息：**  某些对象的创建位置（脚本 ID、行号、列号）。

**3. 关键类和数据结构：**

* **`HeapSnapshotGenerator`：** (在 `heap-snapshot-generator-inl.h` 中定义，但此处被使用) 负责遍历堆并生成快照的主要类。
* **`HeapSnapshot`：**  代表一个堆快照，包含所有捕获到的对象和引用信息。
* **`HeapEntry`：**  表示快照中的一个节点，对应堆中的一个对象。存储了对象的类型、名称、大小、ID 以及与其他对象的连接信息。
* **`HeapGraphEdge`：** 表示快照中两个 `HeapEntry` 之间的引用关系（边）。记录了引用的类型（属性、元素、上下文变量等）和名称/索引。
* **`HeapObjectsMap`：**  用于管理堆中对象的唯一 ID，并跟踪对象的大小和地址。
* **`V8HeapExplorer`：**  用于探索 V8 堆，提取对象信息并创建 `HeapEntry`。

**4. 与 JavaScript 的关系 (用 JavaScript 举例说明)：**

堆快照直接反映了 JavaScript 代码运行时在 V8 堆上创建的对象及其关系。例如，考虑以下 JavaScript 代码：

```javascript
let obj = {
  name: "example",
  count: 10,
  items: [1, 2, 3]
};

function myFunction() {
  let localVar = "inside function";
  return localVar;
}
```

当对此代码运行堆快照生成器时，快照会包含：

* **`obj` 对象的 `HeapEntry`：** 类型可能是 `/object/`，名称可能是 "Object"。
* **`name` 属性的 `HeapGraphEdge`：** 从 `obj` 的 `HeapEntry` 指向字符串 "example" 的 `HeapEntry`，类型为 `kProperty`，名称为 "name"。
* **`count` 属性的 `HeapGraphEdge`：** 从 `obj` 的 `HeapEntry` 指向数字 `10` 的 `HeapEntry`，类型为 `kProperty`，名称为 "count"。
* **`items` 属性的 `HeapGraphEdge`：** 从 `obj` 的 `HeapEntry` 指向数组 `[1, 2, 3]` 的 `HeapEntry`，类型为 `kProperty`，名称为 "items"。
* **数组 `[1, 2, 3]` 的 `HeapEntry`：** 类型可能是 `/array/`。
* **数组元素的 `HeapGraphEdge`：** 从数组的 `HeapEntry` 指向数字 `1`、`2`、`3` 的 `HeapEntry`，类型为 `kElement`，索引分别为 0、1、2。
* **`myFunction` 函数的 `HeapEntry`：** 类型可能是 `/closure/`。
* **闭包的 `HeapGraphEdge`：** 可能包含指向其作用域（包含 `localVar`）的引用。

**5. 代码逻辑推理 (假设输入与输出)：**

假设输入是 V8 引擎正在执行一段 JavaScript 代码，并且调用了堆快照生成功能。

**假设输入：** V8 堆中存在以下对象：

* 一个 JavaScript 对象 `A`，包含一个属性 `propB`，其值为另一个 JavaScript 对象 `B`。
* 一个 JavaScript 数组 `C`，包含两个元素，分别是字符串 "hello" 和数字 123。

**预期输出（快照的部分内容）：**

* **`HeapEntry` for 对象 A：**  类型 `/object/`，ID 为某个值，大小为 A 对象的大小。
* **`HeapEntry` for 对象 B：**  类型 `/object/`，ID 为另一个值，大小为 B 对象的大小。
* **`HeapGraphEdge` from A to B：** 类型 `kProperty`，名称 "propB"，指向对象 B 的 `HeapEntry`。
* **`HeapEntry` for 数组 C：**  类型 `/array/`，ID 为某个值，大小为数组 C 的大小。
* **`HeapEntry` for 字符串 "hello"：** 类型 `/string/`，ID 为某个值，大小为字符串 "hello" 的大小。
* **`HeapEntry` for 数字 123：** 类型 `/number/`，ID 为某个值。
* **`HeapGraphEdge` from C to "hello"：** 类型 `kElement`，索引 0，指向字符串 "hello" 的 `HeapEntry`。
* **`HeapGraphEdge` from C to 123：** 类型 `kElement`，索引 1，指向数字 123 的 `HeapEntry`。

**6. 涉及用户常见的编程错误 (举例说明)：**

堆快照常用于诊断内存泄漏。用户常见的编程错误可能导致对象被意外地保留在堆中，无法被垃圾回收。例如：

```javascript
// 错误示例：忘记取消事件监听器
let element = document.getElementById('myButton');
let data = { longString: new Array(1000000).join('*') }; // 占用大量内存

function onClick() {
  console.log('Button clicked');
  console.log(data.longString.substring(0, 10));
}

element.addEventListener('click', onClick);

// ... 在某些情况下 element 被移除，但 onClick 仍然持有对 data 的引用，
// 导致 data 无法被垃圾回收，造成内存泄漏。
```

在这种情况下，生成的堆快照会显示，即使 `element` 从 DOM 中移除，`data` 对象仍然被 `onClick` 函数（作为闭包）引用，从而阻止其被回收。通过分析堆快照，开发者可以找到这种意外的引用链。

**7. 第 1 部分功能归纳：**

作为第一部分，`v8/src/profiler/heap-snapshot-generator.cc` 的主要功能是 **定义了生成 V8 堆快照的核心数据结构和初步的逻辑**。它包含了表示快照、快照条目（对象）和引用关系的类，以及用于管理对象 ID 和基本快照操作的方法。  这部分代码为后续更具体的堆遍历和信息提取工作奠定了基础。它定义了快照的“骨架”和基本元素。

总结来说，`v8/src/profiler/heap-snapshot-generator.cc` 是 V8 引擎中负责创建和表示堆快照的关键组件，用于帮助开发者理解和分析 JavaScript 程序的内存使用情况。

### 提示词
```
这是目录为v8/src/profiler/heap-snapshot-generator.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/profiler/heap-snapshot-generator.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/profiler/heap-snapshot-generator.h"

#include <optional>
#include <utility>

#include "src/api/api-inl.h"
#include "src/base/vector.h"
#include "src/codegen/assembler-inl.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/debug/debug.h"
#include "src/handles/global-handles.h"
#include "src/heap/combined-heap.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/heap.h"
#include "src/heap/safepoint.h"
#include "src/heap/visit-object.h"
#include "src/numbers/conversions.h"
#include "src/objects/allocation-site-inl.h"
#include "src/objects/api-callbacks.h"
#include "src/objects/cell-inl.h"
#include "src/objects/feedback-cell-inl.h"
#include "src/objects/hash-table-inl.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-collection-inl.h"
#include "src/objects/js-generator-inl.h"
#include "src/objects/js-objects.h"
#include "src/objects/js-promise-inl.h"
#include "src/objects/js-regexp-inl.h"
#include "src/objects/js-weak-refs-inl.h"
#include "src/objects/literal-objects-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/prototype.h"
#include "src/objects/slots-inl.h"
#include "src/objects/struct-inl.h"
#include "src/objects/transitions-inl.h"
#include "src/objects/visitors.h"
#include "src/profiler/allocation-tracker.h"
#include "src/profiler/heap-profiler.h"
#include "src/profiler/heap-snapshot-generator-inl.h"
#include "src/profiler/output-stream-writer.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/names-provider.h"
#include "src/wasm/string-builder.h"
#include "src/wasm/wasm-objects.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8::internal {

#ifdef V8_ENABLE_HEAP_SNAPSHOT_VERIFY
class HeapEntryVerifier {
 public:
  HeapEntryVerifier(HeapSnapshotGenerator* generator, Tagged<HeapObject> obj)
      : generator_(generator),
        primary_object_(obj),
        reference_summary_(
            ReferenceSummary::SummarizeReferencesFrom(generator->heap(), obj)) {
    generator->set_verifier(this);
  }
  ~HeapEntryVerifier() {
    CheckAllReferencesWereChecked();
    generator_->set_verifier(nullptr);
  }

  // Checks that `host` retains `target`, according to the marking visitor. This
  // allows us to verify, when adding edges to the snapshot, that they
  // correspond to real retaining relationships.
  void CheckStrongReference(Tagged<HeapObject> host,
                            Tagged<HeapObject> target) {
    // All references should be from the current primary object.
    CHECK_EQ(host, primary_object_);

    checked_objects_.insert(target);

    // Check whether there is a direct strong reference from host to target.
    if (reference_summary_.strong_references().find(target) !=
        reference_summary_.strong_references().end()) {
      return;
    }

    // There is no direct reference from host to target, but sometimes heap
    // snapshots include references that skip one, two, or three objects, such
    // as __proto__ on a JSObject referring to its Map's prototype, or a
    // property getter that bypasses the property array and accessor info. At
    // this point, we must check for those indirect references.
    for (size_t level = 0; level < 3; ++level) {
      const UnorderedHeapObjectSet& indirect =
          GetIndirectStrongReferences(level);
      if (indirect.find(target) != indirect.end()) {
        return;
      }
    }

    FATAL("Could not find any matching reference");
  }

  // Checks that `host` has a weak reference to `target`, according to the
  // marking visitor.
  void CheckWeakReference(Tagged<HeapObject> host, Tagged<HeapObject> target) {
    // All references should be from the current primary object.
    CHECK_EQ(host, primary_object_);

    checked_objects_.insert(target);
    CHECK_NE(reference_summary_.weak_references().find(target),
             reference_summary_.weak_references().end());
  }

  // Marks the relationship between `host` and `target` as checked, even if the
  // marking visitor found no such relationship. This is necessary for
  // ephemerons, where a pair of objects is required to retain the target.
  // Use this function with care, since it bypasses verification.
  void MarkReferenceCheckedWithoutChecking(Tagged<HeapObject> host,
                                           Tagged<HeapObject> target) {
    if (host == primary_object_) {
      checked_objects_.insert(target);
    }
  }

  // Verifies that all of the references found by the marking visitor were
  // checked via a call to CheckStrongReference or CheckWeakReference, or
  // deliberately skipped via a call to MarkReferenceCheckedWithoutChecking.
  // This ensures that there aren't retaining relationships found by the marking
  // visitor which were omitted from the heap snapshot.
  void CheckAllReferencesWereChecked() {
    // Both loops below skip pointers to read-only objects, because the heap
    // snapshot deliberately omits many of those (see IsEssentialObject).
    // Read-only objects can't ever retain normal read-write objects, so these
    // are fine to skip.
    for (Tagged<HeapObject> obj : reference_summary_.strong_references()) {
      if (!MemoryChunk::FromHeapObject(obj)->InReadOnlySpace()) {
        CHECK_NE(checked_objects_.find(obj), checked_objects_.end());
      }
    }
    for (Tagged<HeapObject> obj : reference_summary_.weak_references()) {
      if (!MemoryChunk::FromHeapObject(obj)->InReadOnlySpace()) {
        CHECK_NE(checked_objects_.find(obj), checked_objects_.end());
      }
    }
  }

 private:
  using UnorderedHeapObjectSet =
      std::unordered_set<Tagged<HeapObject>, Object::Hasher,
                         Object::KeyEqualSafe>;

  const UnorderedHeapObjectSet& GetIndirectStrongReferences(size_t level) {
    CHECK_GE(indirect_strong_references_.size(), level);

    if (indirect_strong_references_.size() == level) {
      // Expansion is needed.
      indirect_strong_references_.resize(level + 1);
      const UnorderedHeapObjectSet& previous =
          level == 0 ? reference_summary_.strong_references()
                     : indirect_strong_references_[level - 1];
      for (Tagged<HeapObject> obj : previous) {
        if (MemoryChunk::FromHeapObject(obj)->InReadOnlySpace()) {
          // Marking visitors don't expect to visit objects in read-only space,
          // and will fail DCHECKs if they are used on those objects. Read-only
          // objects can never retain anything outside read-only space, so
          // skipping those objects doesn't weaken verification.
          continue;
        }

        // Indirect references should only bypass internal structures, not
        // user-visible objects or contexts.
        if (IsJSReceiver(obj) || IsString(obj) || IsContext(obj)) {
          continue;
        }

        ReferenceSummary summary =
            ReferenceSummary::SummarizeReferencesFrom(generator_->heap(), obj);
        indirect_strong_references_[level].insert(
            summary.strong_references().begin(),
            summary.strong_references().end());
      }
    }

    return indirect_strong_references_[level];
  }

  DISALLOW_GARBAGE_COLLECTION(no_gc)
  HeapSnapshotGenerator* generator_;
  Tagged<HeapObject> primary_object_;

  // All objects referred to by primary_object_, according to a marking visitor.
  ReferenceSummary reference_summary_;

  // Objects that have been checked via a call to CheckStrongReference or
  // CheckWeakReference, or deliberately skipped via a call to
  // MarkReferenceCheckedWithoutChecking.
  std::unordered_set<Tagged<HeapObject>, Object::Hasher, Object::KeyEqualSafe>
      checked_objects_;

  // Objects transitively retained by the primary object. The objects in the set
  // at index i are retained by the primary object via a chain of i+1
  // intermediate objects.
  std::vector<UnorderedHeapObjectSet> indirect_strong_references_;
};
#endif

HeapGraphEdge::HeapGraphEdge(Type type, const char* name, HeapEntry* from,
                             HeapEntry* to)
    : bit_field_(TypeField::encode(type) |
                 FromIndexField::encode(from->index())),
      to_entry_(to),
      name_(name) {
  DCHECK(type == kContextVariable || type == kProperty || type == kInternal ||
         type == kShortcut || type == kWeak);
}

HeapGraphEdge::HeapGraphEdge(Type type, int index, HeapEntry* from,
                             HeapEntry* to)
    : bit_field_(TypeField::encode(type) |
                 FromIndexField::encode(from->index())),
      to_entry_(to),
      index_(index) {
  DCHECK(type == kElement || type == kHidden);
}

HeapEntry::HeapEntry(HeapSnapshot* snapshot, int index, Type type,
                     const char* name, SnapshotObjectId id, size_t self_size,
                     unsigned trace_node_id)
    : type_(static_cast<unsigned>(type)),
      index_(index),
      children_count_(0),
      self_size_(self_size),
      snapshot_(snapshot),
      name_(name),
      id_(id),
      trace_node_id_(trace_node_id) {
  DCHECK_GE(index, 0);
}

void HeapEntry::VerifyReference(HeapGraphEdge::Type type, HeapEntry* entry,
                                HeapSnapshotGenerator* generator,
                                ReferenceVerification verification) {
#ifdef V8_ENABLE_HEAP_SNAPSHOT_VERIFY
  if (verification == kOffHeapPointer || generator->verifier() == nullptr) {
    // Off-heap pointers are outside the scope of this verification; we just
    // trust the embedder to provide accurate data. If the verifier is null,
    // then verification is disabled.
    return;
  }
  if (verification == kCustomWeakPointer) {
    // The caller declared that this is a weak pointer ignored by the marking
    // visitor. All we can verify at this point is that the edge type declares
    // it to be weak.
    CHECK_EQ(type, HeapGraphEdge::kWeak);
    return;
  }
  Address from_address =
      reinterpret_cast<Address>(generator->FindHeapThingForHeapEntry(this));
  Address to_address =
      reinterpret_cast<Address>(generator->FindHeapThingForHeapEntry(entry));
  if (from_address == kNullAddress || to_address == kNullAddress) {
    // One of these entries doesn't correspond to a real heap object.
    // Verification is not possible.
    return;
  }
  Tagged<HeapObject> from_obj = Cast<HeapObject>(Tagged<Object>(from_address));
  Tagged<HeapObject> to_obj = Cast<HeapObject>(Tagged<Object>(to_address));
  if (MemoryChunk::FromHeapObject(to_obj)->InReadOnlySpace()) {
    // We can't verify pointers into read-only space, because marking visitors
    // might not mark those. For example, every Map has a pointer to the
    // MetaMap, but marking visitors don't bother with following that link.
    // Read-only objects are immortal and can never point to things outside of
    // read-only space, so ignoring these objects is safe from the perspective
    // of ensuring accurate retaining paths for normal read-write objects.
    // Therefore, do nothing.
  } else if (verification == kEphemeron) {
    // Ephemerons can't be verified because they aren't marked directly by the
    // marking visitor.
    generator->verifier()->MarkReferenceCheckedWithoutChecking(from_obj,
                                                               to_obj);
  } else if (type == HeapGraphEdge::kWeak) {
    generator->verifier()->CheckWeakReference(from_obj, to_obj);
  } else {
    generator->verifier()->CheckStrongReference(from_obj, to_obj);
  }
#endif
}

void HeapEntry::SetNamedReference(HeapGraphEdge::Type type, const char* name,
                                  HeapEntry* entry,
                                  HeapSnapshotGenerator* generator,
                                  ReferenceVerification verification) {
  ++children_count_;
  snapshot_->edges().emplace_back(type, name, this, entry);
  VerifyReference(type, entry, generator, verification);
}

void HeapEntry::SetIndexedReference(HeapGraphEdge::Type type, int index,
                                    HeapEntry* entry,
                                    HeapSnapshotGenerator* generator,
                                    ReferenceVerification verification) {
  ++children_count_;
  snapshot_->edges().emplace_back(type, index, this, entry);
  VerifyReference(type, entry, generator, verification);
}

void HeapEntry::SetNamedAutoIndexReference(HeapGraphEdge::Type type,
                                           const char* description,
                                           HeapEntry* child,
                                           StringsStorage* names,
                                           HeapSnapshotGenerator* generator,
                                           ReferenceVerification verification) {
  int index = children_count_ + 1;
  const char* name = description
                         ? names->GetFormatted("%d / %s", index, description)
                         : names->GetName(index);
  SetNamedReference(type, name, child, generator, verification);
}

void HeapEntry::Print(const char* prefix, const char* edge_name, int max_depth,
                      int indent) const {
  static_assert(sizeof(unsigned) == sizeof(id()));
  base::OS::Print("%6zu @%6u %*c %s%s: ", self_size(), id(), indent, ' ',
                  prefix, edge_name);
  if (type() != kString) {
    base::OS::Print("%s %.40s\n", TypeAsString(), name_);
  } else {
    base::OS::Print("\"");
    const char* c = name_;
    while (*c && (c - name_) <= 40) {
      if (*c != '\n')
        base::OS::Print("%c", *c);
      else
        base::OS::Print("\\n");
      ++c;
    }
    base::OS::Print("\"\n");
  }
  if (--max_depth == 0) return;
  for (auto i = children_begin(); i != children_end(); ++i) {
    HeapGraphEdge& edge = **i;
    const char* edge_prefix = "";
    base::EmbeddedVector<char, 64> index;
    edge_name = index.begin();
    switch (edge.type()) {
      case HeapGraphEdge::kContextVariable:
        edge_prefix = "#";
        edge_name = edge.name();
        break;
      case HeapGraphEdge::kElement:
        SNPrintF(index, "%d", edge.index());
        break;
      case HeapGraphEdge::kInternal:
        edge_prefix = "$";
        edge_name = edge.name();
        break;
      case HeapGraphEdge::kProperty:
        edge_name = edge.name();
        break;
      case HeapGraphEdge::kHidden:
        edge_prefix = "$";
        SNPrintF(index, "%d", edge.index());
        break;
      case HeapGraphEdge::kShortcut:
        edge_prefix = "^";
        edge_name = edge.name();
        break;
      case HeapGraphEdge::kWeak:
        edge_prefix = "w";
        edge_name = edge.name();
        break;
      default:
        SNPrintF(index, "!!! unknown edge type: %d ", edge.type());
    }
    edge.to()->Print(edge_prefix, edge_name, max_depth, indent + 2);
  }
}

const char* HeapEntry::TypeAsString() const {
  switch (type()) {
    case kHidden:
      return "/hidden/";
    case kObject:
      return "/object/";
    case kClosure:
      return "/closure/";
    case kString:
      return "/string/";
    case kCode:
      return "/code/";
    case kArray:
      return "/array/";
    case kRegExp:
      return "/regexp/";
    case kHeapNumber:
      return "/number/";
    case kNative:
      return "/native/";
    case kSynthetic:
      return "/synthetic/";
    case kConsString:
      return "/concatenated string/";
    case kSlicedString:
      return "/sliced string/";
    case kSymbol:
      return "/symbol/";
    case kBigInt:
      return "/bigint/";
    case kObjectShape:
      return "/object shape/";
    default:
      return "???";
  }
}

HeapSnapshot::HeapSnapshot(HeapProfiler* profiler,
                           v8::HeapProfiler::HeapSnapshotMode snapshot_mode,
                           v8::HeapProfiler::NumericsMode numerics_mode)
    : profiler_(profiler),
      snapshot_mode_(snapshot_mode),
      numerics_mode_(numerics_mode) {
  // It is very important to keep objects that form a heap snapshot
  // as small as possible. Check assumptions about data structure sizes.
  static_assert(kSystemPointerSize != 4 || sizeof(HeapGraphEdge) == 12);
  static_assert(kSystemPointerSize != 8 || sizeof(HeapGraphEdge) == 24);
  static_assert(kSystemPointerSize != 4 || sizeof(HeapEntry) == 32);
#if V8_CC_MSVC
  static_assert(kSystemPointerSize != 8 || sizeof(HeapEntry) == 48);
#else   // !V8_CC_MSVC
  static_assert(kSystemPointerSize != 8 || sizeof(HeapEntry) == 40);
#endif  // !V8_CC_MSVC
  memset(&gc_subroot_entries_, 0, sizeof(gc_subroot_entries_));
}

void HeapSnapshot::Delete() { profiler_->RemoveSnapshot(this); }

void HeapSnapshot::RememberLastJSObjectId() {
  max_snapshot_js_object_id_ = profiler_->heap_object_map()->last_assigned_id();
}

void HeapSnapshot::AddSyntheticRootEntries() {
  AddRootEntry();
  AddGcRootsEntry();
  SnapshotObjectId id = HeapObjectsMap::kGcRootsFirstSubrootId;
  for (int root = 0; root < static_cast<int>(Root::kNumberOfRoots); root++) {
    AddGcSubrootEntry(static_cast<Root>(root), id);
    id += HeapObjectsMap::kObjectIdStep;
  }
  DCHECK_EQ(HeapObjectsMap::kFirstAvailableObjectId, id);
}

void HeapSnapshot::AddRootEntry() {
  DCHECK_NULL(root_entry_);
  DCHECK(entries_.empty());  // Root entry must be the first one.
  root_entry_ = AddEntry(HeapEntry::kSynthetic, "",
                         HeapObjectsMap::kInternalRootObjectId, 0, 0);
  DCHECK_EQ(1u, entries_.size());
  DCHECK_EQ(root_entry_, &entries_.front());
}

void HeapSnapshot::AddGcRootsEntry() {
  DCHECK_NULL(gc_roots_entry_);
  gc_roots_entry_ = AddEntry(HeapEntry::kSynthetic, "(GC roots)",
                             HeapObjectsMap::kGcRootsObjectId, 0, 0);
}

void HeapSnapshot::AddGcSubrootEntry(Root root, SnapshotObjectId id) {
  DCHECK_NULL(gc_subroot_entries_[static_cast<int>(root)]);
  gc_subroot_entries_[static_cast<int>(root)] =
      AddEntry(HeapEntry::kSynthetic, RootVisitor::RootName(root), id, 0, 0);
}

void HeapSnapshot::AddLocation(HeapEntry* entry, int scriptId, int line,
                               int col) {
  locations_.emplace_back(entry->index(), scriptId, line, col);
}

HeapEntry* HeapSnapshot::AddEntry(HeapEntry::Type type, const char* name,
                                  SnapshotObjectId id, size_t size,
                                  unsigned trace_node_id) {
  DCHECK(!is_complete());
  entries_.emplace_back(this, static_cast<int>(entries_.size()), type, name, id,
                        size, trace_node_id);
  return &entries_.back();
}

void HeapSnapshot::AddScriptLineEnds(int script_id,
                                     String::LineEndsVector&& line_ends) {
  scripts_line_ends_map_.emplace(script_id, std::move(line_ends));
}

String::LineEndsVector& HeapSnapshot::GetScriptLineEnds(int script_id) {
  DCHECK(scripts_line_ends_map_.find(script_id) !=
         scripts_line_ends_map_.end());
  return scripts_line_ends_map_[script_id];
}

void HeapSnapshot::FillChildren() {
  DCHECK(children().empty());
  int children_index = 0;
  for (HeapEntry& entry : entries()) {
    children_index = entry.set_children_index(children_index);
  }
  DCHECK_EQ(edges().size(), static_cast<size_t>(children_index));
  children().resize(edges().size());
  for (HeapGraphEdge& edge : edges()) {
    edge.from()->add_child(&edge);
  }
}

HeapEntry* HeapSnapshot::GetEntryById(SnapshotObjectId id) {
  if (entries_by_id_cache_.empty()) {
    CHECK(is_complete());
    entries_by_id_cache_.reserve(entries_.size());
    for (HeapEntry& entry : entries_) {
      entries_by_id_cache_.emplace(entry.id(), &entry);
    }
  }
  auto it = entries_by_id_cache_.find(id);
  return it != entries_by_id_cache_.end() ? it->second : nullptr;
}

void HeapSnapshot::Print(int max_depth) { root()->Print("", "", max_depth, 0); }

// We split IDs on evens for embedder objects (see
// HeapObjectsMap::GenerateId) and odds for native objects.
const SnapshotObjectId HeapObjectsMap::kInternalRootObjectId = 1;
const SnapshotObjectId HeapObjectsMap::kGcRootsObjectId =
    HeapObjectsMap::kInternalRootObjectId + HeapObjectsMap::kObjectIdStep;
const SnapshotObjectId HeapObjectsMap::kGcRootsFirstSubrootId =
    HeapObjectsMap::kGcRootsObjectId + HeapObjectsMap::kObjectIdStep;
const SnapshotObjectId HeapObjectsMap::kFirstAvailableObjectId =
    HeapObjectsMap::kGcRootsFirstSubrootId +
    static_cast<int>(Root::kNumberOfRoots) * HeapObjectsMap::kObjectIdStep;
const SnapshotObjectId HeapObjectsMap::kFirstAvailableNativeId = 2;

HeapObjectsMap::HeapObjectsMap(Heap* heap)
    : next_id_(kFirstAvailableObjectId),
      next_native_id_(kFirstAvailableNativeId),
      heap_(heap) {
  // The dummy element at zero index is needed as entries_map_ cannot hold
  // an entry with zero value. Otherwise it's impossible to tell if
  // LookupOrInsert has added a new item or just returning exisiting one
  // having the value of zero.
  entries_.emplace_back(0, kNullAddress, 0, true);
}

bool HeapObjectsMap::MoveObject(Address from, Address to, int object_size) {
  DCHECK_NE(kNullAddress, to);
  DCHECK_NE(kNullAddress, from);
  if (from == to) return false;
  void* from_value = entries_map_.Remove(reinterpret_cast<void*>(from),
                                         ComputeAddressHash(from));
  if (from_value == nullptr) {
    // It may occur that some untracked object moves to an address X and there
    // is a tracked object at that address. In this case we should remove the
    // entry as we know that the object has died.
    void* to_value = entries_map_.Remove(reinterpret_cast<void*>(to),
                                         ComputeAddressHash(to));
    if (to_value != nullptr) {
      int to_entry_info_index =
          static_cast<int>(reinterpret_cast<intptr_t>(to_value));
      entries_.at(to_entry_info_index).addr = kNullAddress;
    }
  } else {
    base::HashMap::Entry* to_entry = entries_map_.LookupOrInsert(
        reinterpret_cast<void*>(to), ComputeAddressHash(to));
    if (to_entry->value != nullptr) {
      // We found the existing entry with to address for an old object.
      // Without this operation we will have two EntryInfo's with the same
      // value in addr field. It is bad because later at RemoveDeadEntries
      // one of this entry will be removed with the corresponding entries_map_
      // entry.
      int to_entry_info_index =
          static_cast<int>(reinterpret_cast<intptr_t>(to_entry->value));
      entries_.at(to_entry_info_index).addr = kNullAddress;
    }
    int from_entry_info_index =
        static_cast<int>(reinterpret_cast<intptr_t>(from_value));
    entries_.at(from_entry_info_index).addr = to;
    // Size of an object can change during its life, so to keep information
    // about the object in entries_ consistent, we have to adjust size when the
    // object is migrated.
    if (v8_flags.heap_profiler_trace_objects) {
      PrintF("Move object from %p to %p old size %6d new size %6d\n",
             reinterpret_cast<void*>(from), reinterpret_cast<void*>(to),
             entries_.at(from_entry_info_index).size, object_size);
    }
    entries_.at(from_entry_info_index).size = object_size;
    to_entry->value = from_value;
  }
  return from_value != nullptr;
}

void HeapObjectsMap::UpdateObjectSize(Address addr, int size) {
  FindOrAddEntry(addr, size, MarkEntryAccessed::kNo);
}

SnapshotObjectId HeapObjectsMap::FindEntry(Address addr) {
  base::HashMap::Entry* entry = entries_map_.Lookup(
      reinterpret_cast<void*>(addr), ComputeAddressHash(addr));
  if (entry == nullptr) return v8::HeapProfiler::kUnknownObjectId;
  int entry_index = static_cast<int>(reinterpret_cast<intptr_t>(entry->value));
  EntryInfo& entry_info = entries_.at(entry_index);
  DCHECK(static_cast<uint32_t>(entries_.size()) > entries_map_.occupancy());
  return entry_info.id;
}

SnapshotObjectId HeapObjectsMap::FindOrAddEntry(
    Address addr, unsigned int size, MarkEntryAccessed accessed,
    IsNativeObject is_native_object) {
  bool accessed_bool = accessed == MarkEntryAccessed::kYes;
  bool is_native_object_bool = is_native_object == IsNativeObject::kYes;
  DCHECK(static_cast<uint32_t>(entries_.size()) > entries_map_.occupancy());
  base::HashMap::Entry* entry = entries_map_.LookupOrInsert(
      reinterpret_cast<void*>(addr), ComputeAddressHash(addr));
  if (entry->value != nullptr) {
    int entry_index =
        static_cast<int>(reinterpret_cast<intptr_t>(entry->value));
    EntryInfo& entry_info = entries_.at(entry_index);
    entry_info.accessed = accessed_bool;
    if (v8_flags.heap_profiler_trace_objects) {
      PrintF("Update object size : %p with old size %d and new size %d\n",
             reinterpret_cast<void*>(addr), entry_info.size, size);
    }
    entry_info.size = size;
    DCHECK_EQ(is_native_object_bool, entry_info.id % 2 == 0);
    return entry_info.id;
  }
  entry->value = reinterpret_cast<void*>(entries_.size());
  SnapshotObjectId id =
      is_native_object_bool ? get_next_native_id() : get_next_id();
  entries_.push_back(EntryInfo(id, addr, size, accessed_bool));
  DCHECK(static_cast<uint32_t>(entries_.size()) > entries_map_.occupancy());
  return id;
}

SnapshotObjectId HeapObjectsMap::FindMergedNativeEntry(NativeObject addr) {
  auto it = merged_native_entries_map_.find(addr);
  if (it == merged_native_entries_map_.end())
    return v8::HeapProfiler::kUnknownObjectId;
  return entries_[it->second].id;
}

void HeapObjectsMap::AddMergedNativeEntry(NativeObject addr,
                                          Address canonical_addr) {
  base::HashMap::Entry* entry =
      entries_map_.Lookup(reinterpret_cast<void*>(canonical_addr),
                          ComputeAddressHash(canonical_addr));
  auto result = merged_native_entries_map_.insert(
      {addr, reinterpret_cast<size_t>(entry->value)});
  if (!result.second) {
    result.first->second = reinterpret_cast<size_t>(entry->value);
  }
}

void HeapObjectsMap::StopHeapObjectsTracking() { time_intervals_.clear(); }

void HeapObjectsMap::UpdateHeapObjectsMap() {
  if (v8_flags.heap_profiler_trace_objects) {
    PrintF("Begin HeapObjectsMap::UpdateHeapObjectsMap. map has %d entries.\n",
           entries_map_.occupancy());
  }
  heap_->PreciseCollectAllGarbage(GCFlag::kNoFlags,
                                  GarbageCollectionReason::kHeapProfiler);
  PtrComprCageBase cage_base(heap_->isolate());
  CombinedHeapObjectIterator iterator(heap_);
  for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
       obj = iterator.Next()) {
    int object_size = obj->Size(cage_base);
    FindOrAddEntry(obj.address(), object_size);
    if (v8_flags.heap_profiler_trace_objects) {
      PrintF("Update object      : %p %6d. Next address is %p\n",
             reinterpret_cast<void*>(obj.address()), object_size,
             reinterpret_cast<void*>(obj.address() + object_size));
    }
  }
  RemoveDeadEntries();
  if (v8_flags.heap_profiler_trace_objects) {
    PrintF("End HeapObjectsMap::UpdateHeapObjectsMap. map has %d entries.\n",
           entries_map_.occupancy());
  }
}

SnapshotObjectId HeapObjectsMap::PushHeapObjectsStats(OutputStream* stream,
                                                      int64_t* timestamp_us) {
  UpdateHeapObjectsMap();
  time_intervals_.emplace_back(next_id_);
  int prefered_chunk_size = stream->GetChunkSize();
  std::vector<v8::HeapStatsUpdate> stats_buffer;
  DCHECK(!entries_.empty());
  EntryInfo* entry_info = &entries_.front();
  EntryInfo* end_entry_info = &entries_.back() + 1;
  for (size_t time_interval_index = 0;
       time_interval_index < time_intervals_.size(); ++time_interval_index) {
    TimeInterval& time_interval = time_intervals_[time_interval_index];
    SnapshotObjectId time_interval_id = time_interval.id;
    uint32_t entries_size = 0;
    EntryInfo* start_entry_info = entry_info;
    while (entry_info < end_entry_info && entry_info->id < time_interval_id) {
      entries_size += entry_info->size;
      ++entry_info;
    }
    uint32_t entries_count =
        static_cast<uint32_t>(entry_info - start_entry_info);
    if (time_interval.count != entries_count ||
        time_interval.size != entries_size) {
      stats_buffer.emplace_back(static_cast<uint32_t>(time_interval_index),
                                time_interval.count = entries_count,
                                time_interval.size = entries_size);
      if (static_cast<int>(stats_buffer.size()) >= prefered_chunk_size) {
        OutputStream::WriteResult result = stream->WriteHeapStatsChunk(
            &stats_buffer.front(), static_cast<int>(stats_buffer.size()));
        if (result == OutputStream::kAbort) return last_assigned_id();
        stats_buffer.clear();
      }
    }
  }
  DCHECK(entry_info == end_entry_info);
  if (!stats_buffer.empty()) {
    OutputStream::WriteResult result = stream->WriteHeapStatsChunk(
        &stats_buffer.front(), static_cast<int>(stats_buffer.size()));
    if (result == OutputStream::kAbort) return last_assigned_id();
  }
  stream->EndOfStream();
  if (timestamp_us) {
    *timestamp_us =
        (time_intervals_.back().timestamp - time_intervals_.front().timestamp)
            .InMicroseconds();
  }
  return last_assigned_id();
}

void HeapObjectsMap::RemoveDeadEntries() {
  DCHECK(entries_.size() > 0 && entries_.at(0).id == 0 &&
         entries_.at(0).addr == kNullAddress);

  // Build up temporary reverse map.
  std::unordered_map<size_t, NativeObject> reverse_merged_native_entries_map;
  for (const auto& it : merged_native_entries_map_) {
    auto result =
        reverse_merged_native_entries_map.emplace(it.second, it.first);
    DCHECK(result.second);
    USE(result);
  }

  size_t first_free_entry = 1;
  for (size_t i = 1; i < entries_.size(); ++i) {
    EntryInfo& entry_info = entries_.at(i);
    auto merged_reverse_it = reverse_merged_native_entries_map.find(i);
    if (entry_info.accessed) {
      if (first_free_entry != i) {
        entries_.at(first_free_entry) = entry_info;
      }
      entries_.at(first_free_entry).accessed = false;
      base::HashMap::Entry* entry =
          entries_map_.Lookup(reinterpret_cast<void*>(entry_info.addr),
                              ComputeAddressHash(entry_info.addr));
      DCHECK(entry);
      entry->value = reinterpret_cast<void*>(first_free_entry);
      if (merged_reverse_it != reverse_merged_native_entries_map.end()) {
        auto it = merged_native_entries_map_.find(merged_reverse_it->second);
        DCHECK_NE(merged_native_entries_map_.end(), it);
        it->second = first_free_entry;
      }
      ++first_free_entry;
    } else {
      if (entry_info.addr) {
        entries_map_.Remove(reinterpret_cast<void*>(entry_info.addr),
                            ComputeAddressHash(entry_info.addr));
        if (merged_reverse_it != reverse_merged_native_entries_map.end()) {
          merged_native_entries_map_.erase(merged_reverse_it->second);
        }
      }
    }
  }
  entries_.erase(entries_.begin() + first_free_entry, entries_.end());

  DCHECK(static_cast<uint32_t>(entries_.size()) - 1 ==
         entries_map_.occupancy());
}

V8HeapExplorer::V8HeapExplorer(HeapSnapshot* snapshot,
                               SnapshottingProgressReportingInterface* progress,
                               v8::HeapProfiler::ObjectNameResolver* resolver)
    : heap_(snapshot->profiler()->heap_object_map()->heap()),
      snapshot_(snapshot),
      names_(snapshot_->profiler()->names()),
      heap_object_map_(snapshot_->profiler()->heap_object_map()),
      progress_(progress),
      generator_(nullptr),
      global_object_name_resolver_(resolver) {}

HeapEntry* V8HeapExplorer::AllocateEntry(HeapThing ptr) {
  return AddEntry(
      Cast<HeapObject>(Tagged<Object>(reinterpret_cast<Address>(ptr))));
}

HeapEntry* V8HeapExplorer::AllocateEntry(Tagged<Smi> smi) {
  SnapshotObjectId id = heap_object_map_->get_next_id();
  HeapEntry* entry =
      snapshot_->AddEntry(HeapEntry::kHeapNumber, "smi number", id, 0, 0);
  // XXX: Smis do not appear in CombinedHeapObjectIterator, so we need to
  // extract the references here
  ExtractNumberReference(entry, smi);
  return entry;
}

Tagged<JSFunction> V8HeapExplorer::GetLocationFunction(
    Tagged<HeapObject> object) {
  DisallowHeapAllocation no_gc;

  if (IsJSFunction(object)) {
    return Cast<JSFunction>(object);
  } else if (IsJSGeneratorObject(object)) {
    Tagged<JSGeneratorObject> gen = Cast<JSGeneratorObject>(object);
    return gen->function();
  } else if (IsJSObject(object)) {
    Tagged<JSObject> obj = Cast<JSObject>(object);
    Tagged<JSFunction> maybe_constructor =
        GetConstructor(heap_->isolate(), obj);

    return m
```