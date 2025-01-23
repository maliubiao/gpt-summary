Response: The user wants me to summarize the functionality of the C++ code in `v8/src/profiler/heap-snapshot-generator.cc`. Since this is part 1 of 3, I should focus on the functionality present in this specific chunk of code.

Based on the included headers and the code itself, it seems this part focuses on:

1. **Data Structures for Heap Snapshots:**  Defining classes like `HeapSnapshot`, `HeapEntry`, and `HeapGraphEdge` to represent the structure of a heap snapshot.
2. **Heap Object Tracking:**  The `HeapObjectsMap` class is responsible for tracking the identity and size of heap objects.
3. **Heap Exploration:** The `V8HeapExplorer` class appears to be the core component for traversing the heap and extracting information to build the snapshot. It handles different object types and their internal references.
4. **Reference Extraction Logic:**  There's a lot of code dedicated to identifying and recording different types of references between objects (strong, weak, internal, etc.) for various V8 object types.
5. **Verification (Optional):**  The `HeapEntryVerifier` class (enabled by a flag) seems to provide a mechanism for verifying the correctness of the extracted references against the actual heap structure.
6. **Location Information:**  Code for extracting source code location information (script ID, line, column) for objects.

Therefore, the core function of this part is to **define the data structures and logic for exploring the V8 heap and extracting information about objects and their relationships to generate a heap snapshot.**

Regarding the relationship with JavaScript: This code directly deals with the internal representation of JavaScript objects in the V8 engine. The classes and logic here are what enable tools (like the Chrome DevTools memory profiler) to understand the structure of the JavaScript heap.

For a JavaScript example, consider a simple object and its prototype chain:

```javascript
function A() {
  this.name = "instance of A";
}

function B() {
  this.value = 10;
}
B.prototype = new A();

let b = new B();
```

The `heap-snapshot-generator.cc` (specifically the `V8HeapExplorer`) would be responsible for:

*   Identifying the `b` object as a `JSObject`.
*   Identifying the `B` constructor function as a `JSFunction`.
*   Identifying the `A` constructor function as a `JSFunction`.
*   Identifying the `A.prototype` object.
*   Creating `HeapEntry` objects for `b`, `B`, `A`, and `A.prototype`.
*   Creating `HeapGraphEdge` objects representing the relationships:
    *   `b` has a property `value` pointing to a HeapNumber (10).
    *   `b` has an internal `__proto__` property pointing to the instance of `A`.
    *   The instance of `A` has a property `name` pointing to a string "instance of A".
    *   The `B` function has a `prototype` property pointing to the instance of `A`.

Essentially, this C++ code is the engine's way of understanding and serializing the complex graph of JavaScript objects and their connections.
这个C++源代码文件（`v8/src/profiler/heap-snapshot-generator.cc`）的主要功能是**生成 V8 堆快照 (Heap Snapshot)**。

更具体地说，这部分代码包含了：

1. **定义了用于表示堆快照的数据结构：**  例如 `HeapSnapshot`、`HeapEntry`（堆条目）、`HeapGraphEdge`（堆图边）。这些结构体或类用于存储堆中对象的信息以及对象之间的引用关系。
2. **实现了对堆中对象的跟踪和识别：**  `HeapObjectsMap` 类负责维护一个映射，将堆中对象的地址与其唯一的 ID 关联起来，并记录对象的大小。这对于在快照中标识和区分不同的对象至关重要。
3. **提供了遍历和探索堆的机制：**  `V8HeapExplorer` 类是核心，它负责遍历 V8 堆，识别不同类型的对象（例如 `JSObject`、`String`、`Function` 等），并提取它们之间的引用关系。
4. **定义了不同类型引用的处理逻辑：** 代码中可以看到针对不同 V8 对象类型的特定引用提取方法（例如 `ExtractJSObjectReferences`、`ExtractStringReferences` 等）。这些方法会识别对象内部的属性、元素、内部槽位等，并创建相应的 `HeapGraphEdge` 来表示这些引用。
5. **包含了可选的堆快照验证机制：**  `HeapEntryVerifier` 类（通过宏 `V8_ENABLE_HEAP_SNAPSHOT_VERIFY` 启用）用于在生成快照时验证提取的引用是否与实际的堆结构一致，这有助于调试和确保快照的准确性。
6. **支持记录对象的位置信息：**  代码中包含了提取 JavaScript 函数的源代码位置（脚本 ID、行号、列号）的功能，并将这些信息添加到堆快照中，这对于分析内存泄漏非常有用。

**与 JavaScript 的关系：**

这个 C++ 文件直接操作 V8 引擎的内部结构，用于捕获 JavaScript 运行时的堆状态。生成的堆快照可以用于分析 JavaScript 代码的内存使用情况，例如查找内存泄漏、了解对象之间的引用关系等。

**JavaScript 示例：**

假设有以下简单的 JavaScript 代码：

```javascript
let obj1 = { name: "object1" };
let obj2 = { ref: obj1 };
```

当生成堆快照时，`heap-snapshot-generator.cc` 中的代码会执行以下操作（简化描述）：

1. `HeapObjectsMap` 会记录 `obj1` 和 `obj2` 的地址以及它们的大小，并分配唯一的 ID。
2. `V8HeapExplorer` 会识别 `obj1` 和 `obj2` 都是 `JSObject`。
3. 对于 `obj1`，`ExtractJSObjectReferences` 会识别其属性 `name`，并创建一个 `HeapGraphEdge`，类型为 `kProperty`，指向一个字符串对象 `"object1"`。
4. 对于 `obj2`，`ExtractJSObjectReferences` 会识别其属性 `ref`，并创建一个 `HeapGraphEdge`，类型为 `kProperty`，指向 `obj1`。

最终，堆快照会包含表示 `obj1`、`obj2` 以及字符串 `"object1"` 的 `HeapEntry`，以及表示它们之间引用关系的 `HeapGraphEdge`。

总而言之，这个 C++ 文件是 V8 引擎中生成堆快照的核心组成部分，它深入到引擎的内部，理解 JavaScript 对象的结构和关系，并将这些信息转化为结构化的数据，供开发者分析和调试 JavaScript 代码的内存问题。

### 提示词
```
这是目录为v8/src/profiler/heap-snapshot-generator.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```
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

    return maybe_constructor;
  }

  return JSFunction();
}

void V8HeapExplorer::ExtractLocation(HeapEntry* entry,
                                     Tagged<HeapObject> object) {
  DisallowHeapAllocation no_gc;
  Tagged<JSFunction> func = GetLocationFunction(object);
  if (!func.is_null()) {
    ExtractLocationForJSFunction(entry, func);
  }
}

void V8HeapExplorer::ExtractLocationForJSFunction(HeapEntry* entry,
                                                  Tagged<JSFunction> func) {
  if (!IsScript(func->shared()->script())) return;
  Tagged<Script> script = Cast<Script>(func->shared()->script());
  int scriptId = script->id();
  int start = func->shared()->StartPosition();
  Script::PositionInfo info;
  if (script->has_line_ends()) {
    script->GetPositionInfo(start, &info);
  } else {
    script->GetPositionInfoWithLineEnds(
        start, &info, snapshot_->GetScriptLineEnds(script->id()));
  }
  snapshot_->AddLocation(entry, scriptId, info.line, info.column);
}

namespace {
// Templatized struct to statically generate the string "system / Managed<Foo>"
// from "kFooTag".
template <const char kTagNameCStr[]>
struct ManagedName {
  static constexpr std::string_view kTagName = kTagNameCStr;
  static_assert(kTagName.starts_with("k"));
  static_assert(kTagName.ends_with("Tag"));

  static constexpr std::string_view prefix = "system / Managed<";
  static constexpr std::string_view suffix = ">";

  // We strip four characters, but add prefix and suffix and null termination.
  static constexpr size_t kManagedNameLength =
      kTagName.size() - 4 + prefix.size() + suffix.size() + 1;

  static constexpr auto str_arr =
      base::make_array<kManagedNameLength>([](std::size_t i) {
        if (i < prefix.size()) return prefix[i];
        if (i == kManagedNameLength - 2) return suffix[0];
        if (i == kManagedNameLength - 1) return '\0';
        return kTagName[i - prefix.size() + 1];
      });

  // Ignore "kFirstManagedResourceTag".
  static constexpr bool ignore_me = kTagName == "kFirstManagedResourceTag";
};

// A little inline test:
constexpr const char kTagNameForTesting[] = "kFooTag";
static_assert(std::string_view{
                  ManagedName<kTagNameForTesting>::str_arr.data()} ==
              std::string_view{"system / Managed<Foo>"});
}  // namespace

HeapEntry* V8HeapExplorer::AddEntry(Tagged<HeapObject> object) {
  PtrComprCageBase cage_base(isolate());
  InstanceType instance_type = object->map(cage_base)->instance_type();
  if (InstanceTypeChecker::IsJSObject(instance_type)) {
    if (InstanceTypeChecker::IsJSFunction(instance_type)) {
      Tagged<JSFunction> func = Cast<JSFunction>(object);
      Tagged<SharedFunctionInfo> shared = func->shared();
      const char* name = names_->GetName(shared->Name());
      return AddEntry(object, HeapEntry::kClosure, name);

    } else if (InstanceTypeChecker::IsJSBoundFunction(instance_type)) {
      return AddEntry(object, HeapEntry::kClosure, "native_bind");
    }
    if (InstanceTypeChecker::IsJSRegExp(instance_type)) {
      Tagged<JSRegExp> re = Cast<JSRegExp>(object);
      return AddEntry(object, HeapEntry::kRegExp,
                      names_->GetName(re->source()));
    }
    // TODO(v8:12674) Fix and run full gcmole.
    DisableGCMole no_gcmole;
    const char* name = names_->GetName(
        GetConstructorName(heap_->isolate(), Cast<JSObject>(object)));
    if (InstanceTypeChecker::IsJSGlobalObject(instance_type)) {
      auto it = global_object_tag_map_.find(Cast<JSGlobalObject>(object));
      if (it != global_object_tag_map_.end()) {
        name = names_->GetFormatted("%s / %s", name, it->second);
      }
    }
    return AddEntry(object, HeapEntry::kObject, name);

  } else if (InstanceTypeChecker::IsString(instance_type)) {
    Tagged<String> string = Cast<String>(object);
    if (IsConsString(string, cage_base)) {
      return AddEntry(object, HeapEntry::kConsString, "(concatenated string)");
    } else if (IsSlicedString(string, cage_base)) {
      return AddEntry(object, HeapEntry::kSlicedString, "(sliced string)");
    } else {
      return AddEntry(object, HeapEntry::kString,
                      names_->GetName(Cast<String>(object)));
    }
  } else if (InstanceTypeChecker::IsSymbol(instance_type)) {
    if (Cast<Symbol>(object)->is_private())
      return AddEntry(object, HeapEntry::kHidden, "private symbol");
    else
      return AddEntry(object, HeapEntry::kSymbol, "symbol");

  } else if (InstanceTypeChecker::IsBigInt(instance_type)) {
    return AddEntry(object, HeapEntry::kBigInt, "bigint");

  } else if (InstanceTypeChecker::IsInstructionStream(instance_type) ||
             InstanceTypeChecker::IsCode(instance_type)) {
    return AddEntry(object, HeapEntry::kCode, "");

  } else if (InstanceTypeChecker::IsSharedFunctionInfo(instance_type)) {
    Tagged<String> name = Cast<SharedFunctionInfo>(object)->Name();
    return AddEntry(object, HeapEntry::kCode, names_->GetName(name));

  } else if (InstanceTypeChecker::IsScript(instance_type)) {
    Tagged<Object> name = Cast<Script>(object)->name();
    return AddEntry(object, HeapEntry::kCode,
                    IsString(name) ? names_->GetName(Cast<String>(name)) : "");

  } else if (InstanceTypeChecker::IsNativeContext(instance_type)) {
    return AddEntry(object, HeapEntry::kHidden, "system / NativeContext");

  } else if (InstanceTypeChecker::IsContext(instance_type)) {
    return AddEntry(object, HeapEntry::kObject, "system / Context");

  } else if (InstanceTypeChecker::IsHeapNumber(instance_type)) {
    return AddEntry(object, HeapEntry::kHeapNumber, "heap number");
  }
#if V8_ENABLE_WEBASSEMBLY
  if (InstanceTypeChecker::IsWasmObject(instance_type)) {
    Tagged<WasmTypeInfo> info = object->map()->wasm_type_info();
    // Getting the trusted data is safe; structs and arrays always have their
    // trusted data defined.
    wasm::NamesProvider* names =
        info->trusted_data(isolate())->native_module()->GetNamesProvider();
    wasm::StringBuilder sb;
    names->PrintTypeName(sb, info->type_index());
    sb << " (wasm)" << '\0';
    const char* name = names_->GetCopy(sb.start());
    return AddEntry(object, HeapEntry::kObject, name);
  }
  if (InstanceTypeChecker::IsWasmNull(instance_type)) {
    // Inlined copies of {GetSystemEntryType}, {GetSystemEntryName}, and
    // {AddEntry}, allowing us to override the size.
    // The actual object's size is fairly large (at the time of this writing,
    // just over 64 KB) and mostly includes a guard region. We report it as
    // much smaller to avoid confusion.
    static constexpr size_t kSize = WasmNull::kHeaderSize;
    return AddEntry(object.address(), HeapEntry::kHidden, "system / WasmNull",
                    kSize);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  if (InstanceTypeChecker::IsForeign(instance_type)) {
    Tagged<Foreign> foreign = Cast<Foreign>(object);
    ExternalPointerTag tag = foreign->GetTag();
    if (tag >= kFirstManagedResourceTag && tag < kLastManagedResourceTag) {
      // First handle special cases with more information.
#if V8_ENABLE_WEBASSEMBLY
      if (tag == kWasmNativeModuleTag) {
        wasm::NativeModule* native_module =
            Cast<Managed<wasm::NativeModule>>(foreign)->raw();
        size_t size = native_module->EstimateCurrentMemoryConsumption();
        return AddEntry(object.address(), HeapEntry::kHidden,
                        "system / Managed<wasm::NativeModule>", size);
      }
#endif  // V8_ENABLE_WEBASSEMBLY
#define MANAGED_TAG(name, ...)                                \
  if (tag == name) {                                          \
    static constexpr const char kTagName[] = #name;           \
    if constexpr (!ManagedName<kTagName>::ignore_me) {        \
      return AddEntry(object, HeapEntry::kHidden,             \
                      ManagedName<kTagName>::str_arr.data()); \
    }                                                         \
  }
      PER_ISOLATE_EXTERNAL_POINTER_TAGS(MANAGED_TAG)
#undef MANAGED_TAG
    }
  }

  return AddEntry(object, GetSystemEntryType(object),
                  GetSystemEntryName(object));
}

HeapEntry* V8HeapExplorer::AddEntry(Tagged<HeapObject> object,
                                    HeapEntry::Type type, const char* name) {
  PtrComprCageBase cage_base(isolate());
  return AddEntry(object.address(), type, name, object->Size(cage_base));
}

HeapEntry* V8HeapExplorer::AddEntry(Address address, HeapEntry::Type type,
                                    const char* name, size_t size) {
  if (v8_flags.heap_profiler_show_hidden_objects &&
      type == HeapEntry::kHidden) {
    type = HeapEntry::kNative;
  }
  SnapshotObjectId object_id = heap_object_map_->FindOrAddEntry(
      address, static_cast<unsigned int>(size));
  unsigned trace_node_id = 0;
  if (AllocationTracker* allocation_tracker =
          snapshot_->profiler()->allocation_tracker()) {
    trace_node_id =
        allocation_tracker->address_to_trace()->GetTraceNodeId(address);
  }
  return snapshot_->AddEntry(type, name, object_id, size, trace_node_id);
}

const char* V8HeapExplorer::GetSystemEntryName(Tagged<HeapObject> object) {
  if (IsMap(object)) {
    switch (Cast<Map>(object)->instance_type()) {
#define MAKE_STRING_MAP_CASE(instance_type, size, name, Name) \
  case instance_type:                                         \
    return "system / Map (" #Name ")";
      STRING_TYPE_LIST(MAKE_STRING_MAP_CASE)
#undef MAKE_STRING_MAP_CASE
      default:
        return "system / Map";
    }
  }

  InstanceType type = object->map()->instance_type();

  // Empty string names are special: TagObject can overwrite them, and devtools
  // will report them as "(internal array)".
  if (InstanceTypeChecker::IsFixedArray(type) ||
      InstanceTypeChecker::IsFixedDoubleArray(type) ||
      InstanceTypeChecker::IsByteArray(type)) {
    return "";
  }

  switch (type) {
#define MAKE_TORQUE_CASE(Name, TYPE) \
  case TYPE:                         \
    return "system / " #Name;
    // The following lists include every non-String instance type.
    // This includes a few types that already have non-"system" names assigned
    // by AddEntry, but this is a convenient way to avoid manual upkeep here.
    TORQUE_INSTANCE_CHECKERS_SINGLE_FULLY_DEFINED(MAKE_TORQUE_CASE)
    TORQUE_INSTANCE_CHECKERS_MULTIPLE_FULLY_DEFINED(MAKE_TORQUE_CASE)
    TORQUE_INSTANCE_CHECKERS_SINGLE_ONLY_DECLARED(MAKE_TORQUE_CASE)
    TORQUE_INSTANCE_CHECKERS_MULTIPLE_ONLY_DECLARED(MAKE_TORQUE_CASE)
#undef MAKE_TORQUE_CASE

    // Strings were already handled by AddEntry.
#define MAKE_STRING_CASE(instance_type, size, name, Name) \
  case instance_type:                                     \
    UNREACHABLE();
    STRING_TYPE_LIST(MAKE_STRING_CASE)
#undef MAKE_STRING_CASE
  }
}

HeapEntry::Type V8HeapExplorer::GetSystemEntryType(Tagged<HeapObject> object) {
  InstanceType type = object->map()->instance_type();
  if (InstanceTypeChecker::IsAllocationSite(type) ||
      InstanceTypeChecker::IsArrayBoilerplateDescription(type) ||
      InstanceTypeChecker::IsBytecodeArray(type) ||
      InstanceTypeChecker::IsBytecodeWrapper(type) ||
      InstanceTypeChecker::IsClosureFeedbackCellArray(type) ||
      InstanceTypeChecker::IsCode(type) ||
      InstanceTypeChecker::IsCodeWrapper(type) ||
      InstanceTypeChecker::IsFeedbackCell(type) ||
      InstanceTypeChecker::IsFeedbackMetadata(type) ||
      InstanceTypeChecker::IsFeedbackVector(type) ||
      InstanceTypeChecker::IsInstructionStream(type) ||
      InstanceTypeChecker::IsInterpreterData(type) ||
      InstanceTypeChecker::IsLoadHandler(type) ||
      InstanceTypeChecker::IsObjectBoilerplateDescription(type) ||
      InstanceTypeChecker::IsPreparseData(type) ||
      InstanceTypeChecker::IsRegExpBoilerplateDescription(type) ||
      InstanceTypeChecker::IsScopeInfo(type) ||
      InstanceTypeChecker::IsStoreHandler(type) ||
      InstanceTypeChecker::IsTemplateObjectDescription(type) ||
      InstanceTypeChecker::IsTurbofanType(type) ||
      InstanceTypeChecker::IsUncompiledData(type)) {
    return HeapEntry::kCode;
  }

  // This check must come second, because some subtypes of FixedArray are
  // determined above to represent code content.
  if (InstanceTypeChecker::IsFixedArray(type) ||
      InstanceTypeChecker::IsFixedDoubleArray(type) ||
      InstanceTypeChecker::IsByteArray(type)) {
    return HeapEntry::kArray;
  }

  // Maps in read-only space are for internal V8 data, not user-defined object
  // shapes.
  if ((InstanceTypeChecker::IsMap(type) &&
       !MemoryChunk::FromHeapObject(object)->InReadOnlySpace()) ||
      InstanceTypeChecker::IsDescriptorArray(type) ||
      InstanceTypeChecker::IsTransitionArray(type) ||
      InstanceTypeChecker::IsPrototypeInfo(type) ||
      InstanceTypeChecker::IsEnumCache(type)) {
    return HeapEntry::kObjectShape;
  }

  return HeapEntry::kHidden;
}

void V8HeapExplorer::PopulateLineEnds() {
  std::vector<Handle<Script>> scripts;
  HandleScope scope(isolate());

  {
    Script::Iterator iterator(isolate());
    for (Tagged<Script> script = iterator.Next(); !script.is_null();
         script = iterator.Next()) {
      if (!script->has_line_ends()) {
        scripts.push_back(handle(script, isolate()));
      }
    }
  }

  for (auto& script : scripts) {
    snapshot_->AddScriptLineEnds(script->id(),
                                 Script::GetLineEnds(isolate(), script));
  }
}

uint32_t V8HeapExplorer::EstimateObjectsCount() {
  CombinedHeapObjectIterator it(heap_, HeapObjectIterator::kNoFiltering);
  uint32_t objects_count = 0;
  // Avoid overflowing the objects count. In worst case, we will show the same
  // progress for a longer period of time, but we do not expect to have that
  // many objects.
  while (!it.Next().is_null() &&
         objects_count != std::numeric_limits<uint32_t>::max())
    ++objects_count;
  return objects_count;
}

#ifdef V8_TARGET_BIG_ENDIAN
namespace {
int AdjustEmbedderFieldIndex(Tagged<HeapObject> heap_obj, int field_index) {
  Tagged<Map> map = heap_obj->map();
  if (JSObject::MayHaveEmbedderFields(map)) {
    int emb_start_index = (JSObject::GetEmbedderFieldsStartOffset(map) +
                           EmbedderDataSlot::kTaggedPayloadOffset) /
                          kTaggedSize;
    int emb_field_count = JSObject::GetEmbedderFieldCount(map);
    int emb_end_index = emb_start_index + emb_field_count;
    if (base::IsInRange(field_index, emb_start_index, emb_end_index)) {
      return -EmbedderDataSlot::kTaggedPayloadOffset / kTaggedSize;
    }
  }
  return 0;
}
}  // namespace
#endif  // V8_TARGET_BIG_ENDIAN
class IndexedReferencesExtractor : public ObjectVisitorWithCageBases {
 public:
  IndexedReferencesExtractor(V8HeapExplorer* generator,
                             Tagged<HeapObject> parent_obj, HeapEntry* parent)
      : ObjectVisitorWithCageBases(generator->isolate()),
        generator_(generator),
        parent_obj_(parent_obj),
        parent_start_(parent_obj_->RawMaybeWeakField(0)),
        parent_end_(
            parent_obj_->RawMaybeWeakField(parent_obj_->Size(cage_base()))),
        parent_(parent),
        next_index_(0) {}
  void VisitPointers(Tagged<HeapObject> host, ObjectSlot start,
                     ObjectSlot end) override {
    VisitPointers(host, MaybeObjectSlot(start), MaybeObjectSlot(end));
  }
  void VisitMapPointer(Tagged<HeapObject> object) override {
    VisitSlotImpl(cage_base(), object->map_slot());
  }
  void VisitPointers(Tagged<HeapObject> host, MaybeObjectSlot start,
                     MaybeObjectSlot end) override {
    // [start,end) must be a sub-region of [parent_start_, parent_end), i.e.
    // all the slots must point inside the object.
    CHECK_LE(parent_start_, start);
    CHECK_LE(end, parent_end_);
    for (MaybeObjectSlot slot = start; slot < end; ++slot) {
      VisitSlotImpl(cage_base(), slot);
    }
  }

  void VisitInstructionStreamPointer(Tagged<Code> host,
                                     InstructionStreamSlot slot) override {
    VisitSlotImpl(code_cage_base(), slot);
  }

  void VisitCodeTarget(Tagged<InstructionStream> host,
                       RelocInfo* rinfo) override {
    Tagged<InstructionStream> target =
        InstructionStream::FromTargetAddress(rinfo->target_address());
    VisitHeapObjectImpl(target, -1);
  }

  void VisitEmbeddedPointer(Tagged<InstructionStream> host,
                            RelocInfo* rinfo) override {
    Tagged<HeapObject> object = rinfo->target_object(cage_base());
    Tagged<Code> code = UncheckedCast<Code>(host->raw_code(kAcquireLoad));
    if (code->IsWeakObject(object)) {
      generator_->SetWeakReference(parent_, next_index_++, object, {});
    } else {
      VisitHeapObjectImpl(object, -1);
    }
  }

  void VisitIndirectPointer(Tagged<HeapObject> host, IndirectPointerSlot slot,
                            IndirectPointerMode mode) override {
    VisitSlotImpl(generator_->isolate(), slot);
  }

  void VisitProtectedPointer(Tagged<TrustedObject> host,
                             ProtectedPointerSlot slot) override {
    // TODO(saelo): the cage base doesn't currently matter as it isn't used,
    // but technically we should either use the trusted cage base here or
    // remove the cage_base parameter.
    const PtrComprCageBase unused_cage_base(kNullAddress);
    VisitSlotImpl(unused_cage_base, slot);
  }

  void VisitJSDispatchTableEntry(Tagged<HeapObject> host,
                                 JSDispatchHandle handle) override {
#ifdef V8_ENABLE_LEAPTIERING
    // TODO(saelo): implement proper support for these fields here, similar to
    // how we handle indirect pointer or protected pointer fields.
    // Currently we only expect to see FeedbackCells or JSFunctions here.
    if (IsJSFunction(host)) {
      int field_index = JSFunction::kDispatchHandleOffset / kTaggedSize;
      CHECK(generator_->visited_fields_[field_index]);
      generator_->visited_fields_[field_index] = false;
    } else if (IsFeedbackCell(host)) {
      // Nothing to do: the Code object is tracked as part of the JSFunction.
    } else {
      UNREACHABLE();
    }
#endif  // V8_ENABLE_LEAPTIERING
  }

 private:
  template <typename TIsolateOrCageBase, typename TSlot>
  V8_INLINE void VisitSlotImpl(TIsolateOrCageBase isolate_or_cage_base,
                               TSlot slot) {
    int field_index =
        static_cast<int>(slot.address() - parent_start_.address()) /
        TSlot::kSlotDataSize;
#ifdef V8_TARGET_BIG_ENDIAN
    field_index += AdjustEmbedderFieldIndex(parent_obj_, field_index);
#endif
    DCHECK_GE(field_index, 0);
    if (generator_->visited_fields_[field_index]) {
      generator_->visited_fields_[field_index] = false;
    } else {
      Tagged<HeapObject> heap_object;
      auto loaded_value = slot.load(isolate_or_cage_base);
      if (loaded_value.GetHeapObjectIfStrong(&heap_object)) {
        VisitHeapObjectImpl(heap_object, field_index);
      } else if (loaded_value.GetHeapObjectIfWeak(&heap_object)) {
        generator_->SetWeakReference(parent_, next_index_++, heap_object, {});
      }
    }
  }

  V8_INLINE void VisitHeapObjectImpl(Tagged<HeapObject> heap_object,
                                     int field_index) {
    DCHECK_LE(-1, field_index);
    // The last parameter {field_offset} is only used to check some well-known
    // skipped references, so passing -1 * kTaggedSize for objects embedded
    // into code is fine.
    generator_->SetHiddenReference(parent_obj_, parent_, next_index_++,
                                   heap_object, field_index * kTaggedSize);
  }

  V8HeapExplorer* generator_;
  Tagged<HeapObject> parent_obj_;
  MaybeObjectSlot parent_start_;
  MaybeObjectSlot parent_end_;
  HeapEntry* parent_;
  int next_index_;
};

void V8HeapExplorer::ExtractReferences(HeapEntry* entry,
                                       Tagged<HeapObject> obj) {
  if (IsJSGlobalProxy(obj)) {
    ExtractJSGlobalProxyReferences(entry, Cast<JSGlobalProxy>(obj));
  } else if (IsJSArrayBuffer(obj)) {
    ExtractJSArrayBufferReferences(entry, Cast<JSArrayBuffer>(obj));
  } else if (IsJSObject(obj)) {
    if (IsJSWeakSet(obj)) {
      ExtractJSWeakCollectionReferences(entry, Cast<JSWeakSet>(obj));
    } else if (IsJSWeakMap(obj)) {
      ExtractJSWeakCollectionReferences(entry, Cast<JSWeakMap>(obj));
    } else if (IsJSSet(obj)) {
      ExtractJSCollectionReferences(entry, Cast<JSSet>(obj));
    } else if (IsJSMap(obj)) {
      ExtractJSCollectionReferences(entry, Cast<JSMap>(obj));
    } else if (IsJSPromise(obj)) {
      ExtractJSPromiseReferences(entry, Cast<JSPromise>(obj));
    } else if (IsJSGeneratorObject(obj)) {
      ExtractJSGeneratorObjectReferences(entry, Cast<JSGeneratorObject>(obj));
    } else if (IsJSWeakRef(obj)) {
      ExtractJSWeakRefReferences(entry, Cast<JSWeakRef>(obj));
#if V8_ENABLE_WEBASSEMBLY
    } else if (IsWasmInstanceObject(obj)) {
      ExtractWasmInstanceObjectReferences(Cast<WasmInstanceObject>(obj), entry);
    } else if (IsWasmModuleObject(obj)) {
      ExtractWasmModuleObjectReferences(Cast<WasmModuleObject>(obj), entry);
#endif  // V8_ENABLE_WEBASSEMBLY
    }
    ExtractJSObjectReferences(entry, Cast<JSObject>(obj));
  } else if (IsString(obj)) {
    ExtractStringReferences(entry, Cast<String>(obj));
  } else if (IsSymbol(obj)) {
    ExtractSymbolReferences(entry, Cast<Symbol>(obj));
  } else if (IsMap(obj)) {
    ExtractMapReferences(entry, Cast<Map>(obj));
  } else if (IsSharedFunctionInfo(obj)) {
    ExtractSharedFunctionInfoReferences(entry, Cast<SharedFunctionInfo>(obj));
  } else if (IsScript(obj)) {
    ExtractScriptReferences(entry, Cast<Script>(obj));
  } else if (IsAccessorInfo(obj)) {
    ExtractAccessorInfoReferences(entry, Cast<AccessorInfo>(obj));
  } else if (IsAccessorPair(obj)) {
    ExtractAccessorPairReferences(entry, Cast<AccessorPair>(obj));
  } else if (IsCode(obj)) {
    ExtractCodeReferences(entry, Cast<Code>(obj));
  } else if (IsInstructionStream(obj)) {
    ExtractInstructionStreamReferences(entry, Cast<InstructionStream>(obj));
  } else if (IsCell(obj)) {
    ExtractCellReferences(entry, Cast<Cell>(obj));
  } else if (IsFeedbackCell(obj)) {
    ExtractFeedbackCellReferences(entry, Cast<FeedbackCell>(obj));
  } else if (IsPropertyCell(obj)) {
    ExtractPropertyCellReferences(entry, Cast<PropertyCell>(obj));
  } else if (IsPrototypeInfo(obj)) {
    ExtractPrototypeInfoReferences(entry, Cast<PrototypeInfo>(obj));
  } else if (IsAllocationSite(obj)) {
    ExtractAllocationSiteReferences(entry, Cast<AllocationSite>(obj));
  } else if (IsArrayBoilerplateDescription(obj)) {
    ExtractArrayBoilerplateDescriptionReferences(
        entry, Cast<ArrayBoilerplateDescription>(obj));
  } else if (IsRegExpBoilerplateDescription(obj)) {
    ExtractRegExpBoilerplateDescriptionReferences(
        entry, Cast<RegExpBoilerplateDescription>(obj));
  } else if (IsFeedbackVector(obj)) {
    ExtractFeedbackVectorReferences(entry, Cast<FeedbackVector>(obj));
  } else if (IsDescriptorArray(obj)) {
    ExtractDescriptorArrayReferences(entry, Cast<DescriptorArray>(obj));
  } else if (IsEnumCache(obj)) {
    ExtractEnumCacheReferences(entry, Cast<EnumCache>(obj));
  } else if (IsTransitionArray(obj)) {
    ExtractTransitionArrayReferences(entry, Cast<TransitionArray>(obj));
  } else if (IsWeakFixedArray(obj)) {
    ExtractWeakArrayReferences(OFFSET_OF_DATA_START(WeakFixedArray), entry,
                               Cast<WeakFixedArray>(obj));
  } else if (IsWeakArrayList(obj)) {
    ExtractWeakArrayReferences(WeakArrayList::kHeaderSize, entry,
                               Cast<WeakArrayList>(obj));
  } else if (IsContext(obj)) {
    ExtractContextReferences(entry, Cast<Context>(obj));
  } else if (IsEphemeronHashTable(obj)) {
    ExtractEphemeronHashTableReferences(entry, Cast<EphemeronHashTable>(obj));
  } else if (IsFixedArray(obj)) {
    ExtractFixedArrayReferences(entry, Cast<FixedArray>(obj));
  } else if (IsWeakCell(obj)) {
    ExtractWeakCellReferences(entry, Cast<WeakCell>(obj));
  } else if (IsHeapNumber(obj)) {
    if (snapshot_->capture_numeric_value()) {
      ExtractNumberReference(entry, obj);
    }
  } else if (IsBytecodeArray(obj)) {
    ExtractBytecodeArrayReferences(entry, Cast<BytecodeArray>(obj));
  } else if (IsScopeInfo(obj)) {
    ExtractScopeInfoReferences(entry, Cast<ScopeInfo>(obj));
#if V8_ENABLE_WEBASSEMBLY
  } else if (IsWasmStruct(obj)) {
    ExtractWasmStructReferences(Cast<WasmStruct>(obj), entry);
  } else if (IsWasmArray(obj)) {
    ExtractWasmArrayReferences(Cast<WasmArray>(obj), entry);
  } else if (IsWasmTrustedInstanceData(obj)) {
    ExtractWasmTrustedInstanceDataReferences(Cast<WasmTrustedInstanceData>(obj),
                                             entry);
#endif  // V8_ENABLE_WEBASSEMBLY
  }
}

void V8HeapExplorer::ExtractJSGlobalProxyReferences(
    HeapEntry* entry, Tagged<JSGlobalProxy> proxy) {}

void V8HeapExplorer::ExtractJSObjectReferences(HeapEntry* entry,
                                               Tagged<JSObject> js_obj) {
  Tagged<HeapObject> obj = js_obj;
  ExtractPropertyReferences(js_obj, entry);
  ExtractElementReferences(js_obj, entry);
  ExtractInternalReferences(js_obj, entry);
  Isolate* isolate = Isolate::FromHeap(heap_);
  PrototypeIterator iter(isolate, js_obj);
  ReadOnlyRoots roots(isolate);
  SetPropertyReference(entry, roots.proto_string(), iter.GetCurrent());
  if (IsJSBoundFunction(obj)) {
    Tagged<JSBoundFunction> js_fun = Cast<JSBoundFunction>(obj);
    TagObject(js_fun->bound_arguments(), "(bound arguments)");
    SetInternalReference(entry, "bindings", js_fun->bound_arguments(),
                         JSBoundFunction::kBoundArgumentsOffset);
    SetInternalReference(entry, "bound_this", js_fun->bound_this(),
                         JSBoundFunction::kBoundThisOffset);
    SetInternalReference(entry, "bound_function",
                         js_fun->bound_target_function(),
                         JSBoundFunction::kBoundTargetFunctionOffset);
    Tagged<FixedArray> bindings = js_fun->bound_arguments();
    for (int i = 0; i < bindings->length(); i++) {
      const char* reference_name = names_->GetFormatted("bound_argument_%d", i);
      SetNativeBindReference(entry, reference_name, bindings->get(i));
    }
  } else if (IsJSFunction(obj)) {
    Tagged<JSFunction> js_fun = Cast<JSFunction>(js_obj);
    if (js_fun->has_prototype_slot()) {
      Tagged<Object> proto_or_map =
          js_fun->prototype_or_initial_map(kAcquireLoad);
      if (!IsTheHole(proto_or_map, isolate)) {
        if (!IsMap(proto_or_map)) {
          SetPropertyReference(entry, roots.prototype_string(), proto_or_map,
                               nullptr,
                               JSFunction::kPrototypeOrInitialMapOffset);
        } else {
          SetPropertyReference(entry, roots.prototype_string(),
                               js_fun->prototype());
          SetInternalReference(entry, "initial_map", proto_or_map,
                               JSFunction::kPrototypeOrInitialMapOffset);
        }
      }
    }
    Tagged<SharedFunctionInfo> shared_info = js_fun->shared();
    TagObject(js_fun->raw_feedback_cell(), "(function feedback cell)");
    SetInternalReference(entry, "feedback_cell", js_fun->raw_feedback_cell(),
                         JSFunction::kFeedbackCellOffset);
    TagObject(shared_info, "(shared function info)");
    SetInternalReference(entry, "shared", shared_info,
                         JSFunction::kSharedFunctionInfoOffset);
    TagObject(js_fun->context(), "(context)");
    SetInternalReference(entry, "context", js_fun->context(),
                         JSFunction::kContextOffset);
#ifdef V8_ENABLE_LEAPTIERING
    SetInternalReference(entry, "code", js_fun->code(isolate),
                         JSFunction::kDispatchHandleOffset);
#else
    SetInternalReference(entry, "code", js_fun->code(isolate),
                         JSFunction::kCodeOffset);
#endif  // V8_ENABLE_LEAPTIERING
  } else if (IsJSGlobalObject(obj)) {
    Tagged<JSGlobalObject> global_obj = Cast<JSGlobalObject>(obj);
    SetInternalReference(entry, "global_proxy", global_obj->global_proxy(),
                         JSGlobalObject::kGlobalProxyOffset);
  } else if (IsJSArrayBufferView(obj)) {
    Tagged<JSArrayBufferView> view = Cast<JSArrayBufferView>(obj);
    SetInternalReference(entry, "buffer", view->buffer(),
                         JSArrayBufferView::kBufferOffset);
  }

  TagObject(js_obj->raw_properties_or_hash(), "(object properties)");
  SetInternalReference(entry, "properties", js_obj->raw_properties_or_hash(),
                       JSObject::kPropertiesOrHashOffset);

  TagObject(js_obj->elements(), "(object elements)");
  SetInternalReference(entry, "elements", js_obj->elements(),
                       JSObject::kElementsOffset);
}

void V8HeapExplorer::ExtractStringReferences(HeapEntry* entry,
                                             Tagged<String> string) {
  if (IsConsString(string)) {
    Tagged<ConsString> cs = Cast<ConsString>(string);
    SetInternalReference(entry, "first", cs->first(),
                         offsetof(ConsString, first_));
    SetInternalReference(entry, "second", cs->second(),
                         offsetof(ConsString, second_));
  } else if (IsSlicedString(string)) {
    Tagged<SlicedString> ss = Cast<SlicedString>(string);
    SetInternalReference(entry, "parent", ss->parent(),
                         offsetof(SlicedString, parent_));
  } else if (IsThinString(string)) {
    Tagged<ThinString> ts = Cast<ThinString>(string);
    SetInternalReference(entry, "actual", ts->actual(),
                         offsetof(ThinString, actual_));
  }
}

void V8HeapExplorer::ExtractSymbolReferences(HeapEntry* entry,
                                             Tagged<Symbol> symbol) {
  SetInternalReference(entry, "name", symbol->description(),
                       offsetof(Symbol, description_));
}

void V8HeapExplorer::ExtractJSCollectionReferences(
    HeapEntry* entry, Tagged<JSCollection> collection) {
  SetInternalReference(entry, "table", collection->table(),
                       JSCollection::kTableOffset);
}

void V8HeapExplorer::ExtractJSWeakCollectionReferences(
    HeapEntry* entry, Tagged<JSWeakCollection> obj) {
  SetInternalReference(entry, "table", obj->table(),
                       JSWeakCollection::kTableOffset);
}

void V8HeapExplorer::ExtractEphemeronHashTableReferences(
    HeapEntry* entry, Tagged<EphemeronHashTable> table) {
  for (InternalIndex i : table->IterateEntries()) {
    int key_index = EphemeronHashTable::EntryToIndex(i) +
                    EphemeronHashTable::kEntryKeyIndex;
    int value_index = EphemeronHashTable::EntryToValueIndex(i);
    Tagged<Object> key = table->get(key_index);
    Tagged<Object> value = table->get(value_index);
    SetWeakReference(entry, key_index, key,
                     table->OffsetOfElementAt(key_index));
    SetWeakReference(entry, value_index, value,
                     table->OffsetOfElementAt(value_index));
    HeapEntry* key_entry = GetEntry(key);
    HeapEntry* value_entry = GetEntry(value);
    HeapEntry* table_entry = GetEntry(table);
    if (key_entry && value_entry && !IsUndefined(key)) {
      const char* edge_name = names_->GetFormatted(
          "part of key (%s @%u) -> value (%s @%u) pair in WeakMap (table @%u)",
          key_entry->name(), key_entry->id(), value_entry->name(),
          value_entry->id(), table_entry->id());
      key_entry->SetNamedAutoIndexReference(HeapGraphEdge::kInternal, edge_name,
                                            value_entry, names_, generator_,
                                            HeapEntry::kEphemeron);
      table_entry->SetNamedAutoIndexReference(
          HeapGraphEdge::kInternal, edge_name, value_entry, names_, generator_,
          HeapEntry::kEphemeron);
    }
  }
}

// These static arrays are used to prevent excessive code-size in
// ExtractContextReferences below, which would happen if we called
// SetInternalReference for every native context field in a macro.
static const struct {
  int index;
  const char* name;
} native_context_names[] = {
#define CONTEXT_FIELD_INDEX_NAME(index, _, name) {Context::index, #name},
    NATIVE_CONTEXT_FIELDS(CONTEXT_FIELD_INDEX_NAME)
#undef CONTEXT_FIELD_INDEX_NAME
};

void V8HeapExplorer::ExtractContextReferences(HeapEntry* entry,
                                              Tagged<Context> context) {
  DisallowGarbageCollection no_gc;
  if (!IsNativeContext(context) && context->is_declaration_context()) {
    Tagged<ScopeInfo> scope_info = context->scope_info();
    // Add context allocated locals.
    for (auto it : ScopeInfo::IterateLocalNames(scope_info, no_gc))
```