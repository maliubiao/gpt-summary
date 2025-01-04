Response: Let's break down the thought process for analyzing this C++ code and relating it to JavaScript.

1. **Understand the Goal:** The filename `read-only-promotion.cc` and the namespace `v8::internal::heap` immediately suggest this code is about moving objects in V8's heap to a read-only space. The term "promotion" implies moving something to a better, more permanent location.

2. **Identify Key Classes and Functions:**  Scan the code for class and function names. This helps identify the main actors and their actions. Key players seem to be:
    * `Committee`:  Suggests a group making decisions about what to promote.
    * `ReadOnlyPromotionImpl`:  Implies the actual implementation of the promotion process.
    * `DeterminePromotees`:  A function in `Committee`, likely responsible for identifying candidates for promotion.
    * `CopyToReadOnlyHeap`:  In `ReadOnlyPromotionImpl`, clearly responsible for the physical move.
    * `UpdatePointers`:  In `ReadOnlyPromotionImpl`, vital for fixing up references after the move.
    * `DeleteDeadObjects`: In `ReadOnlyPromotionImpl`, cleaning up the original locations.
    * `Verify`: In `ReadOnlyPromotionImpl`, likely for debugging and ensuring correctness.
    * `Promote`: The main entry point for the promotion process.

3. **Analyze `Committee::DeterminePromotees`:** This seems to be the core decision-making logic. Key observations:
    * It iterates through all objects in the heap.
    * `EvaluateSubgraph` is called, suggesting it considers not just individual objects but connected groups.
    * `IsPromoCandidate` checks if an object *can* be promoted. This function has a long list of specific object types.
    * There's logic for handling cycles to avoid infinite recursion.
    * The use of `promo_accepted_` and `promo_rejected_` sets indicates tracking of promotion decisions.
    * The code mentions "full and precise GC" implying this happens after a garbage collection.

4. **Analyze `ReadOnlyPromotionImpl`:** This class seems to handle the mechanics of the promotion.
    * `CopyToReadOnlyHeap`:  Straightforward memory copying.
    * `UpdatePointers`:  This is crucial. It iterates through roots, the heap, and even the newly copied objects, updating any pointers to the old locations. This is where the connection to how JavaScript objects are linked becomes apparent.
    * `DeleteDeadObjects`:  Overwriting the old locations is important for memory management and potential verification.
    * `Verify`:  Confirms the promotion worked as expected, especially for known objects and builtin code.

5. **Connect to JavaScript Concepts:** Now, think about how these C++ actions relate to JavaScript:
    * **Immutability:** The goal of moving objects to read-only space strongly suggests this is about optimizing immutable data. In JavaScript, certain built-in objects (like some strings, numbers, and compiled code) *behave* immutably. This code is likely the underlying mechanism for making that immutability more concrete at the memory level.
    * **Optimization:**  Making frequently accessed, immutable objects read-only can improve performance. The CPU can potentially cache these objects more aggressively, and the garbage collector doesn't need to track them as closely for changes.
    * **Built-in Objects:** The code specifically mentions `Code`, `SharedFunctionInfo`, and other internal V8 types. These are the building blocks of JavaScript execution. Promoting these to read-only makes sense for performance and security.
    * **Memory Management:** The code interacts with the garbage collector implicitly by running *after* a full GC. This implies a coordinated effort to manage memory efficiently.

6. **Craft the JavaScript Examples:**  Based on the above connections, create illustrative JavaScript examples. Focus on:
    * **Built-in Functions and Objects:**  These are the most likely candidates for read-only promotion. `String.prototype.toUpperCase`, `Array.isArray`, etc.
    * **Compiled Code:**  Functions are compiled, and the compiled code is a prime candidate for being made read-only.
    * **Internal State:** Acknowledge that the exact promotion is an internal V8 optimization, but the *effect* is observable in terms of performance and the immutability of certain objects. Emphasize that the JavaScript developer doesn't directly control this.

7. **Structure the Explanation:** Organize the findings into a clear and logical explanation:
    * Start with a concise summary of the file's purpose.
    * Explain the key functionalities in more detail, highlighting the important classes and functions.
    * Explicitly connect the C++ concepts to JavaScript features and benefits.
    * Provide concrete JavaScript examples to illustrate the connection.
    * Conclude with a summary emphasizing the optimization aspect.

8. **Refine and Review:**  Read through the explanation to ensure it's accurate, easy to understand, and flows well. Check for any jargon that needs clarification. Make sure the JavaScript examples are relevant and helpful. For instance, initially, I might have just said "strings," but specifying *built-in* string methods makes the connection clearer. Similarly, mentioning compiled code directly links to the `Code` objects being promoted.

By following these steps, we can effectively analyze the C++ code and explain its relevance to JavaScript developers, even though they don't interact with this code directly. The key is to understand the underlying principles and how they manifest in the behavior of the JavaScript engine.
这个C++源代码文件 `v8/src/heap/read-only-promotion.cc` 的功能是**将V8堆中的某些对象提升（Promotion）到只读内存空间（Read-Only Space）**。

**功能归纳:**

1. **确定可提升的对象 (Determine Promotees):**
   - 遍历整个V8堆，找出符合提升到只读空间条件的对象。
   - 使用 `Committee` 类来做决策，判断哪些对象及其关联的子图可以被提升。
   - `IsPromoCandidate` 函数检查特定类型的对象是否是提升的候选者。目前支持提升的类型包括 `AccessCheckInfo`, `AccessorInfo`, `Code`, `CodeWrapper`, `InterceptorInfo`, `ScopeInfo`, `SharedFunctionInfo`, `Symbol` 等。
   - 考虑对象的连接性，如果一个对象可以被提升，那么它引用的其他符合条件的对象也可能被一起提升。
   - 避免提升包含可变引用的对象，以确保只读空间的真正只读性。

2. **拷贝对象到只读堆 (CopyToReadOnlyHeap):**
   - 将确定好的可提升对象复制到只读内存空间。
   - 记录每个被移动的对象及其在新只读空间中的地址，方便后续更新引用。

3. **更新指针 (UpdatePointers):**
   - 遍历V8堆中的所有对象和根节点。
   - 将所有指向被提升对象的指针更新为指向其在只读空间中的新地址。
   - 这包括堆中的普通对象、全局对象、栈中的引用等等。
   - 特别处理了代码对象 (`Code`) 的指针更新，可能涉及到代码指针表的更新。

4. **删除原始对象 (DeleteDeadObjects):**
   - 在对象被成功复制到只读空间后，将原始内存位置填充为特殊的填充对象。这有助于内存管理和调试。

5. **验证 (Verify):**
   - 在Debug模式下，进行一些验证，确保某些预期的对象已经被成功提升到只读空间，例如内置的Code对象。

**与JavaScript功能的关联:**

这个功能与JavaScript的性能优化和内存管理密切相关。将某些对象放入只读内存空间有以下好处：

* **性能提升:**
    * 只读内存可以被更积极地缓存，提高访问速度。
    * 减少了垃圾回收器需要扫描和处理的对象数量，降低了GC的压力。
* **安全提升:**
    * 确保某些关键的对象（例如内置函数和某些元数据）不会被意外修改，提高了运行时的安全性。

**JavaScript 示例:**

虽然JavaScript开发者无法直接控制V8的只读提升过程，但这个过程影响着JavaScript代码的执行效率。以下是一些与只读提升相关的JavaScript概念和示例：

1. **内置对象和函数:** JavaScript的内置对象和函数（例如 `String.prototype.toUpperCase`, `Array.isArray`, `Math.sin` 等）的元数据和编译后的代码很可能是只读提升的候选者。

   ```javascript
   const str = "hello";
   const upperStr = str.toUpperCase(); // String.prototype.toUpperCase 的实现可能被提升到只读空间

   const arr = [1, 2, 3];
   const isArray = Array.isArray(arr); // Array.isArray 的实现也可能被提升

   const result = Math.sin(0); // Math.sin 的实现也可能被提升
   ```

2. **编译后的代码:** JavaScript函数在执行前会被编译成机器码，这些编译后的代码（对应 `Code` 对象）是非常理想的只读提升对象。

   ```javascript
   function add(a, b) {
     return a + b;
   }

   const sum = add(5, 3); // 函数 add 被编译后的代码可能被提升
   ```

3. **共享的元数据:** 例如，多个函数可能共享相同的 `SharedFunctionInfo` 对象，这个对象也可能是只读提升的候选者。

   ```javascript
   function greet(name) {
     console.log("Hello, " + name);
   }

   function farewell(name) {
     console.log("Goodbye, " + name);
   }

   // greet 和 farewell 可能共享某些元数据 (SharedFunctionInfo)
   ```

**总结:**

`v8/src/heap/read-only-promotion.cc` 文件实现了V8引擎中将符合条件的对象移动到只读内存空间的关键优化功能。这个过程对JavaScript开发者是透明的，但它显著地提升了JavaScript代码的执行效率和安全性，特别是对于内置对象、函数和编译后的代码而言。通过将这些对象标记为只读，V8能够进行更积极的缓存和更高效的内存管理。

Prompt: 
```
这是目录为v8/src/heap/read-only-promotion.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/read-only-promotion.h"

#include <unordered_set>

#include "src/common/assert-scope.h"
#include "src/execution/isolate.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/heap.h"
#include "src/heap/read-only-spaces.h"
#include "src/heap/visit-object.h"
#include "src/objects/heap-object-inl.h"
#include "src/objects/objects-inl.h"
#include "src/sandbox/external-pointer-table.h"
#include "src/utils/ostreams.h"

namespace v8 {
namespace internal {
namespace {

// Convenience aliases:
using HeapObjectSet = std::unordered_set<Tagged<HeapObject>, Object::Hasher,
                                         Object::KeyEqualSafe>;
using HeapObjectMap = std::unordered_map<Tagged<HeapObject>, Tagged<HeapObject>,
                                         Object::Hasher, Object::KeyEqualSafe>;
using HeapObjectList = std::vector<Tagged<HeapObject>>;

bool Contains(const HeapObjectSet& s, Tagged<HeapObject> o) {
  return s.count(o) != 0;
}
bool Contains(const HeapObjectMap& s, Tagged<HeapObject> o) {
  return s.count(o) != 0;
}

class Committee final {
 public:
  static HeapObjectList DeterminePromotees(
      Isolate* isolate, const DisallowGarbageCollection& no_gc,
      const SafepointScope& safepoint_scope) {
    return Committee(isolate).DeterminePromotees(safepoint_scope);
  }

 private:
  explicit Committee(Isolate* isolate) : isolate_(isolate) {}

  HeapObjectList DeterminePromotees(const SafepointScope& safepoint_scope) {
    DCHECK(promo_accepted_.empty());
    DCHECK(promo_rejected_.empty());

    // List of promotees as discovered in insertion order. Using the
    // `HeapObjectIterator` will visit pages in insertion order from a GC
    // perspective which is deterministic independent of the absolute pages
    // provided by the OS allocators in case of 32-bit builds (that don't use
    // cages).
    //
    // We keep a separate HeapObjectList as there's no standard-equivalent for a
    // hash set that can maintain insertion order.
    HeapObjectList promo_accepted_list;

    // We assume that a full and precise GC has reclaimed all dead objects
    // and therefore that no filtering of unreachable objects is required here.
    HeapObjectIterator it(isolate_->heap(), safepoint_scope);
    for (Tagged<HeapObject> o = it.Next(); !o.is_null(); o = it.Next()) {
      DCHECK(!HeapLayout::InReadOnlySpace(o));

      // Note that cycles prevent us from promoting/rejecting each subgraph as
      // we visit it, since locally we cannot determine whether the deferred
      // decision on the 'cycle object' will be 'promote' or 'reject'. This
      // could be solved if necessary (with more complex code), but for now
      // there are no performance issues.
      HeapObjectSet accepted_subgraph;  // Either all are accepted or none.
      HeapObjectList accepted_subgraph_list;
      HeapObjectSet visited;            // Cycle detection.
      if (!EvaluateSubgraph(o, &accepted_subgraph, &visited,
                            &accepted_subgraph_list)) {
        continue;
      }
      if (accepted_subgraph.empty()) {
        continue;
      }

      if (V8_UNLIKELY(v8_flags.trace_read_only_promotion)) {
        LogAcceptedPromotionSet(accepted_subgraph);
      }
      promo_accepted_.insert(accepted_subgraph.begin(),
                             accepted_subgraph.end());
      promo_accepted_list.insert(promo_accepted_list.end(),
                                 accepted_subgraph_list.begin(),
                                 accepted_subgraph_list.end());
    }

    // Remove duplicates from the promo_accepted_list. Note we have to jump
    // through these hoops in order to preserve deterministic ordering
    // (otherwise simply using the promo_accepted_ set would be sufficient).
    HeapObjectSet seen_promotees;
    HeapObjectList promotees;
    promotees.reserve(promo_accepted_list.size());
    for (Tagged<HeapObject> o : promo_accepted_list) {
      if (Contains(seen_promotees, o)) continue;
      seen_promotees.insert(o);
      promotees.push_back(o);
    }
    CHECK_EQ(promotees.size(), promo_accepted_.size());

    return promotees;
  }

  // Returns `false` if the subgraph rooted at `o` is rejected.
  // Returns `true` if it is accepted, or if we've reached a cycle and `o`
  // will be processed further up the callchain.
  bool EvaluateSubgraph(Tagged<HeapObject> o, HeapObjectSet* accepted_subgraph,
                        HeapObjectSet* visited, HeapObjectList* promotees) {
    if (HeapLayout::InReadOnlySpace(o)) return true;
    if (Contains(promo_rejected_, o)) return false;
    if (Contains(promo_accepted_, o)) return true;
    if (Contains(*visited, o)) return true;
    visited->insert(o);
    if (!IsPromoCandidate(isolate_, o)) {
      const auto& [it, inserted] = promo_rejected_.insert(o);
      if (V8_UNLIKELY(v8_flags.trace_read_only_promotion) && inserted) {
        LogRejectedPromotionForFailedPredicate(o);
      }
      return false;
    }
    // Recurse into outgoing pointers.
    CandidateVisitor v(this, accepted_subgraph, visited, promotees);
    VisitObject(isolate_, o, &v);
    if (!v.all_slots_are_promo_candidates()) {
      const auto& [it, inserted] = promo_rejected_.insert(o);
      if (V8_UNLIKELY(v8_flags.trace_read_only_promotion) && inserted) {
        LogRejectedPromotionForInvalidSubgraph(o,
                                               v.first_rejected_slot_offset());
      }
      return false;
    }

    accepted_subgraph->insert(o);
    promotees->push_back(o);
    return true;
  }

#define PROMO_CANDIDATE_TYPE_LIST(V) \
  V(AccessCheckInfo)                 \
  V(AccessorInfo)                    \
  V(Code)                            \
  V(CodeWrapper)                     \
  V(InterceptorInfo)                 \
  V(ScopeInfo)                       \
  V(SharedFunctionInfo)              \
  V(Symbol)
  // TODO(jgruber): Don't forget to extend ReadOnlyPromotionImpl::Verify when
  // adding new object types here.

  static bool IsPromoCandidate(Isolate* isolate, Tagged<HeapObject> o) {
    const InstanceType itype = o->map(isolate)->instance_type();
#define V(TYPE)                                            \
  if (InstanceTypeChecker::Is##TYPE(itype)) {              \
    return IsPromoCandidate##TYPE(isolate, Cast<TYPE>(o)); \
    /* NOLINTNEXTLINE(readability/braces) */               \
  } else
    PROMO_CANDIDATE_TYPE_LIST(V)
    /* if { ... } else */ {
      return false;
    }
#undef V
    UNREACHABLE();
  }
#undef PROMO_CANDIDATE_TYPE_LIST

#define DEF_PROMO_CANDIDATE(Type)                                        \
  static bool IsPromoCandidate##Type(Isolate* isolate, Tagged<Type> o) { \
    return true;                                                         \
  }

  DEF_PROMO_CANDIDATE(AccessCheckInfo)
  DEF_PROMO_CANDIDATE(AccessorInfo)
  static bool IsPromoCandidateCode(Isolate* isolate, Tagged<Code> o) {
    return Builtins::kCodeObjectsAreInROSpace && o->is_builtin();
  }
  static bool IsPromoCandidateCodeWrapper(Isolate* isolate,
                                          Tagged<CodeWrapper> o) {
    return IsPromoCandidateCode(isolate, o->code(isolate));
  }
  DEF_PROMO_CANDIDATE(InterceptorInfo)
  DEF_PROMO_CANDIDATE(ScopeInfo)
  static bool IsPromoCandidateSharedFunctionInfo(Isolate* isolate,
                                                 Tagged<SharedFunctionInfo> o) {
    // Only internal SFIs are guaranteed to remain immutable.
    if (o->has_script(kAcquireLoad)) return false;
    // kIllegal is used for js_global_object_function, which is created during
    // bootstrapping but never rooted. We currently assumed that all objects in
    // the snapshot are live. But RO space is 1) not GC'd and 2) serialized
    // verbatim, preserving dead objects. As a workaround, exclude this builtin
    // id from RO allocation.
    // TODO(jgruber): A better solution. Remove the liveness assumption (see
    // test-heap-profiler.cc)? Overwrite dead RO objects with fillers
    // pre-serialization? Implement a RO GC pass pre-serialization?
    return o->HasBuiltinId() && o->builtin_id() != Builtin::kIllegal;
  }
  DEF_PROMO_CANDIDATE(Symbol)

#undef DEF_PROMO_CANDIDATE

  // Recurses into all tagged slots of an object and tracks whether predicates
  // failed on any part of the subgraph.
  class CandidateVisitor : public ObjectVisitor {
   public:
    CandidateVisitor(Committee* committee, HeapObjectSet* accepted_subgraph,
                     HeapObjectSet* visited, HeapObjectList* promotees)
        : committee_(committee),
          accepted_subgraph_(accepted_subgraph),
          visited_(visited),
          promotees_(promotees) {}

    int first_rejected_slot_offset() const {
      return first_rejected_slot_offset_;
    }
    bool all_slots_are_promo_candidates() const {
      return first_rejected_slot_offset_ == -1;
    }

    void VisitPointers(Tagged<HeapObject> host, MaybeObjectSlot start,
                       MaybeObjectSlot end) final {
      if (!all_slots_are_promo_candidates()) return;
      for (MaybeObjectSlot slot = start; slot < end; slot++) {
        Tagged<MaybeObject> maybe_object = slot.load(committee_->isolate_);
        Tagged<HeapObject> heap_object;
        if (!maybe_object.GetHeapObject(&heap_object)) continue;
        if (!committee_->EvaluateSubgraph(heap_object, accepted_subgraph_,
                                          visited_, promotees_)) {
          first_rejected_slot_offset_ =
              static_cast<int>(slot.address() - host.address());
          DCHECK_GE(first_rejected_slot_offset_, 0);
          return;
        }
      }
    }
    void VisitPointers(Tagged<HeapObject> host, ObjectSlot start,
                       ObjectSlot end) final {
      VisitPointers(host, MaybeObjectSlot(start), MaybeObjectSlot(end));
    }
    void VisitInstructionStreamPointer(Tagged<Code> host,
                                       InstructionStreamSlot slot) final {
      DCHECK(host->is_builtin());
    }
    void VisitMapPointer(Tagged<HeapObject> host) final {
      MaybeObjectSlot slot = host->RawMaybeWeakField(HeapObject::kMapOffset);
      VisitPointers(host, slot, slot + 1);
    }

   private:
    Committee* const committee_;
    HeapObjectSet* const accepted_subgraph_;
    HeapObjectSet* const visited_;
    HeapObjectList* const promotees_;
    int first_rejected_slot_offset_ = -1;
  };

  static void LogAcceptedPromotionSet(const HeapObjectSet& os) {
    std::cout << "ro-promotion: accepted set {";
    for (Tagged<HeapObject> o : os) {
      std::cout << reinterpret_cast<void*>(o.ptr()) << ", ";
    }
    std::cout << "}\n";
  }

  static void LogRejectedPromotionForFailedPredicate(Tagged<HeapObject> o) {
    std::cout << "ro-promotion: rejected due to failed predicate "
              << reinterpret_cast<void*>(o.ptr()) << " ("
              << o->map()->instance_type() << ")"
              << "\n";
  }

  void LogRejectedPromotionForInvalidSubgraph(Tagged<HeapObject> o,
                                              int first_rejected_slot_offset) {
    std::cout << "ro-promotion: rejected due to rejected subgraph "
              << reinterpret_cast<void*>(o.ptr()) << " ("
              << o->map()->instance_type() << ")"
              << " at slot offset " << first_rejected_slot_offset << " ";

    MaybeObjectSlot slot = o->RawMaybeWeakField(first_rejected_slot_offset);
    Tagged<MaybeObject> maybe_object = slot.load(isolate_);
    Tagged<HeapObject> heap_object;
    if (maybe_object.GetHeapObject(&heap_object)) {
      std::cout << reinterpret_cast<void*>(heap_object.ptr()) << " ("
                << heap_object->map()->instance_type() << ")"
                << "\n";
    } else {
      std::cout << "<cleared weak object>\n";
    }
  }

  Isolate* const isolate_;
  HeapObjectSet promo_accepted_;
  HeapObjectSet promo_rejected_;
};

class ReadOnlyPromotionImpl final : public AllStatic {
 public:
  static void CopyToReadOnlyHeap(
      Isolate* isolate, const std::vector<Tagged<HeapObject>>& promotees,
      HeapObjectMap* moves) {
    ReadOnlySpace* rospace = isolate->heap()->read_only_space();
    for (Tagged<HeapObject> src : promotees) {
      const int size = src->Size(isolate);
      Tagged<HeapObject> dst =
          rospace->AllocateRaw(size, kTaggedAligned).ToObjectChecked();
      Heap::CopyBlock(dst.address(), src.address(), size);
      moves->emplace(src, dst);

      if (V8_UNLIKELY(v8_flags.trace_read_only_promotion_verbose)) {
        LogPromotedObject(src, dst);
      }
    }
  }

  static void UpdatePointers(Isolate* isolate,
                             const SafepointScope& safepoint_scope,
                             const HeapObjectMap& moves) {
    Heap* heap = isolate->heap();
#ifdef V8_COMPRESS_POINTERS
    ExternalPointerTable::UnsealReadOnlySegmentScope unseal_scope(
        &isolate->external_pointer_table());
#endif  // V8_COMPRESS_POINTERS
    UpdatePointersVisitor v(isolate, &moves);

    // Iterate all roots.
    EmbedderStackStateScope stack_scope(
        isolate->heap(), EmbedderStackStateOrigin::kExplicitInvocation,
        StackState::kNoHeapPointers);
    heap->IterateRoots(&v, base::EnumSet<SkipRoot>{});

    // Iterate all objects on the mutable heap.
    // We assume that a full and precise GC has reclaimed all dead objects
    // and therefore that no filtering of unreachable objects is required here.
    HeapObjectIterator it(heap, safepoint_scope);
    for (Tagged<HeapObject> o = it.Next(); !o.is_null(); o = it.Next()) {
      VisitObject(isolate, o, &v);
    }

    // Iterate all objects we just copied into RO space.
    for (auto [src, dst] : moves) {
      VisitObject(isolate, dst, &v);
    }

#ifdef V8_ENABLE_LEAPTIERING
    // Iterate all entries in the JSDispatchTable as they could contain
    // pointers to promoted Code objects.
    JSDispatchTable* const jdt = GetProcessWideJSDispatchTable();
    jdt->IterateActiveEntriesIn(heap->js_dispatch_table_space(),
                                [&](JSDispatchHandle handle) {
                                  Tagged<Code> old_code = jdt->GetCode(handle);
                                  auto it = moves.find(old_code);
                                  if (it == moves.end()) return;
                                  Tagged<HeapObject> new_code = it->second;
                                  CHECK(IsCode(new_code));
                                  // TODO(saelo): is it worth logging something
                                  // in this case?
                                  jdt->SetCodeNoWriteBarrier(
                                      handle, Cast<Code>(new_code));
                                });
#endif  // V8_ENABLE_LEAPTIERING
  }

  static void DeleteDeadObjects(Isolate* isolate,
                                const SafepointScope& safepoint_scope,
                                const HeapObjectMap& moves) {
    // After moving a source object to a new destination, overwrite the source
    // memory with a filler. This is needed for moved objects that are verified
    // by the heap verifier to have a 1-1 relation with some other object (e.g.
    // objects related to trusted space). The verifier won't compute liveness
    // and instead just iterates linearly over pages. Without this change the
    // verifier would fail on this now-dead object.
    for (auto [src, dst] : moves) {
      CHECK(!HeapLayout::InReadOnlySpace(src));
      isolate->heap()->CreateFillerObjectAt(src.address(), src->Size(isolate));
    }
  }

  static void Verify(Isolate* isolate, const SafepointScope& safepoint_scope) {
#ifdef DEBUG
    // Verify that certain objects were promoted as expected.
    //
    // Known objects.
    Heap* heap = isolate->heap();
    CHECK(HeapLayout::InReadOnlySpace(
        heap->promise_all_resolve_element_closure_shared_fun()));
    // TODO(jgruber): Extend here with more objects as they are added to
    // the promotion algorithm.

    // Builtin Code objects.
    if (Builtins::kCodeObjectsAreInROSpace) {
      Builtins* builtins = isolate->builtins();
      for (int i = 0; i < Builtins::kBuiltinCount; i++) {
        CHECK(HeapLayout::InReadOnlySpace(
            builtins->code(static_cast<Builtin>(i))));
      }
    }
#endif  // DEBUG
  }

 private:
  class UpdatePointersVisitor final : public ObjectVisitor, public RootVisitor {
   public:
    UpdatePointersVisitor(Isolate* isolate, const HeapObjectMap* moves)
        : isolate_(isolate), moves_(moves) {
#ifdef V8_ENABLE_SANDBOX
      for (auto [_src, dst] : *moves_) {
        promoted_objects_.emplace(dst);
        if (IsCode(dst)) {
          PromoteCodePointerEntryFor(Cast<Code>(dst));
        }
      }
#endif  // V8_ENABLE_SANDBOX
    }

    // The RootVisitor interface.
    void VisitRootPointers(Root root, const char* description,
                           FullObjectSlot start, FullObjectSlot end) final {
      for (FullObjectSlot slot = start; slot < end; slot++) {
        ProcessSlot(root, slot);
      }
    }

    // The ObjectVisitor interface.
    void VisitPointers(Tagged<HeapObject> host, MaybeObjectSlot start,
                       MaybeObjectSlot end) final {
      for (MaybeObjectSlot slot = start; slot < end; slot++) {
        ProcessSlot(host, slot);
      }
    }
    void VisitPointers(Tagged<HeapObject> host, ObjectSlot start,
                       ObjectSlot end) final {
      VisitPointers(host, MaybeObjectSlot(start), MaybeObjectSlot(end));
    }
    void VisitInstructionStreamPointer(Tagged<Code> host,
                                       InstructionStreamSlot slot) final {
      // InstructionStream objects never move to RO space.
    }
    void VisitMapPointer(Tagged<HeapObject> host) final {
      ProcessSlot(host, host->RawMaybeWeakField(HeapObject::kMapOffset));
    }
    void VisitExternalPointer(Tagged<HeapObject> host,
                              ExternalPointerSlot slot) final {
#ifdef V8_ENABLE_SANDBOX
      if (promoted_objects_.find(host) == promoted_objects_.end()) return;

      // If we reach here, `host` is a moved object with external pointer slots
      // located in RO space. To preserve the 1:1 relation between slots and
      // table entries, allocate a new entry (in
      // read_only_external_pointer_space) now.
      RecordProcessedSlotIfDebug(slot.address());
      Address slot_value = slot.load(isolate_);
      slot.init(isolate_, host, slot_value);

      if (V8_UNLIKELY(v8_flags.trace_read_only_promotion_verbose)) {
        LogUpdatedExternalPointerTableEntry(host, slot, slot_value);
      }
#endif  // V8_ENABLE_SANDBOX
    }
    void VisitIndirectPointer(Tagged<HeapObject> host, IndirectPointerSlot slot,
                              IndirectPointerMode mode) final {
#ifdef V8_ENABLE_SANDBOX
      if (slot.tag() == kCodeIndirectPointerTag) {
        VisitCodePointer(host, slot);
      }
#endif  // V8_ENABLE_SANDBOX
    }
    void VisitTrustedPointerTableEntry(Tagged<HeapObject> host,
                                       IndirectPointerSlot slot) final {
#ifdef V8_ENABLE_SANDBOX
      if (slot.tag() == kCodeIndirectPointerTag) {
        VisitCodePointer(host, slot);
      }
#endif  // V8_ENABLE_SANDBOX
    }
    void VisitRootPointers(Root root, const char* description,
                           OffHeapObjectSlot start,
                           OffHeapObjectSlot end) override {
      // We shouldn't have moved any string table contents or SharedStructType
      // registry contents (which is what OffHeapObjectSlot currently refers
      // to).
      for (OffHeapObjectSlot slot = start; slot < end; slot++) {
        Tagged<Object> o = slot.load(isolate_);
        if (!IsHeapObject(o)) continue;
        CHECK(!Contains(*moves_, Cast<HeapObject>(o)));
      }
    }

   private:
    void ProcessSlot(Root root, FullObjectSlot slot) {
      Tagged<Object> old_slot_value_obj = slot.load(isolate_);
#ifdef V8_ENABLE_DIRECT_HANDLE
      if (old_slot_value_obj.ptr() == kTaggedNullAddress) return;
#endif
      if (!IsHeapObject(old_slot_value_obj)) return;
      Tagged<HeapObject> old_slot_value = Cast<HeapObject>(old_slot_value_obj);
      auto it = moves_->find(old_slot_value);
      if (it == moves_->end()) return;
      Tagged<HeapObject> new_slot_value = it->second;
      slot.store(new_slot_value);
      if (V8_UNLIKELY(v8_flags.trace_read_only_promotion_verbose)) {
        LogUpdatedPointer(root, slot, old_slot_value, new_slot_value);
      }
    }
    void ProcessSlot(Tagged<HeapObject> host, MaybeObjectSlot slot) {
      Tagged<HeapObject> old_slot_value;
      if (!slot.load(isolate_).GetHeapObject(&old_slot_value)) return;
      auto it = moves_->find(old_slot_value);
      if (it == moves_->end()) return;
      Tagged<HeapObject> new_slot_value = it->second;
      slot.store(new_slot_value);
      if (V8_UNLIKELY(v8_flags.trace_read_only_promotion_verbose)) {
        LogUpdatedPointer(host, slot, old_slot_value, new_slot_value);
      }
    }

#ifdef V8_ENABLE_SANDBOX
    void VisitCodePointer(Tagged<HeapObject> host, IndirectPointerSlot slot) {
      CHECK_EQ(kCodeIndirectPointerTag, slot.tag());
      IndirectPointerHandle old_handle = slot.Relaxed_LoadHandle();
      auto it = code_pointer_moves_.find(old_handle);
      if (it == code_pointer_moves_.end()) return;

      // If we reach here, `host` is a moved object with a code pointer slot
      // located in RO space. To preserve the 1:1 relation between slots and
      // table entries, we need to use the relocated code pointer table entry.
      RecordProcessedSlotIfDebug(slot.address());
      IndirectPointerHandle new_handle = it->second;
      slot.Relaxed_StoreHandle(new_handle);

      if (V8_UNLIKELY(v8_flags.trace_read_only_promotion_verbose)) {
        LogUpdatedCodePointerTableEntry(host, slot, old_handle, new_handle);
      }
    }

    void PromoteCodePointerEntryFor(Tagged<Code> code) {
      // If we reach here, `code` is a moved Code object located in RO space.
      CHECK(HeapLayout::InReadOnlySpace(code));

      IndirectPointerSlot slot = code->RawIndirectPointerField(
          Code::kSelfIndirectPointerOffset, kCodeIndirectPointerTag);
      CodeEntrypointTag entrypoint_tag = code->entrypoint_tag();

      IndirectPointerHandle old_handle = slot.Relaxed_LoadHandle();
      CodePointerTable* cpt = IsolateGroup::current()->code_pointer_table();

      // To preserve the 1:1 relation between slots and code table entries,
      // allocate a new entry (in the code_pointer_space of the RO heap) now.
      // The slot will be updated later, when the Code object is visited.
      CodePointerTable::Space* space =
          IsolateForSandbox(isolate_).GetCodePointerTableSpaceFor(
              slot.address());
      IndirectPointerHandle new_handle = cpt->AllocateAndInitializeEntry(
          space, code.address(), cpt->GetEntrypoint(old_handle, entrypoint_tag),
          entrypoint_tag);

      code_pointer_moves_.emplace(old_handle, new_handle);

      if (V8_UNLIKELY(v8_flags.trace_read_only_promotion_verbose)) {
        LogPromotedCodePointerTableEntry(code, old_handle, new_handle);
      }
    }
#endif  // V8_ENABLE_SANDBOX

    void LogUpdatedPointer(Root root, FullObjectSlot slot,
                           Tagged<HeapObject> old_slot_value,
                           Tagged<HeapObject> new_slot_value) {
      std::cout << "ro-promotion: updated pointer {root "
                << static_cast<int>(root) << " slot "
                << reinterpret_cast<void*>(slot.address()) << " from "
                << reinterpret_cast<void*>(old_slot_value.ptr()) << " to "
                << reinterpret_cast<void*>(new_slot_value.ptr()) << "}\n";
    }
    void LogUpdatedPointer(Tagged<HeapObject> host, MaybeObjectSlot slot,
                           Tagged<HeapObject> old_slot_value,
                           Tagged<HeapObject> new_slot_value) {
      std::cout << "ro-promotion: updated pointer {host "
                << reinterpret_cast<void*>(host.address()) << " slot "
                << reinterpret_cast<void*>(slot.address()) << " from "
                << reinterpret_cast<void*>(old_slot_value.ptr()) << " to "
                << reinterpret_cast<void*>(new_slot_value.ptr()) << "}\n";
    }
    void LogUpdatedExternalPointerTableEntry(Tagged<HeapObject> host,
                                             ExternalPointerSlot slot,
                                             Address slot_value) {
      std::cout << "ro-promotion: updated external pointer slot {host "
                << reinterpret_cast<void*>(host.address()) << " slot "
                << reinterpret_cast<void*>(slot.address()) << " slot_value "
                << reinterpret_cast<void*>(slot_value) << "}\n";
    }
    void LogUpdatedCodePointerTableEntry(Tagged<HeapObject> host,
                                         IndirectPointerSlot slot,
                                         IndirectPointerHandle old_handle,
                                         IndirectPointerHandle new_handle) {
      std::cout << "ro-promotion: updated code pointer table entry {host "
                << reinterpret_cast<void*>(host.address()) << " slot "
                << reinterpret_cast<void*>(slot.address()) << " from "
                << AsHex(old_handle, 8, true) << " to "
                << AsHex(new_handle, 8, true) << "}\n";
    }

#ifdef DEBUG
    void RecordProcessedSlotIfDebug(Address slot_address) {
      // If this fails, we're visiting some object multiple times by accident.
      CHECK_EQ(processed_slots_.count(slot_address), 0);
      processed_slots_.insert(slot_address);
    }
    std::unordered_set<Address> processed_slots_;  // To avoid dupe processing.
#else
    void RecordProcessedSlotIfDebug(Address slot_address) const {}
#endif  // DEBUG

    Isolate* const isolate_;
    const HeapObjectMap* moves_;

#ifdef V8_ENABLE_SANDBOX
    HeapObjectSet promoted_objects_;

    // When an object owning an pointer table entry is relocated to the RO
    // space, it cannot just update the entry to point to its new location
    // (see b/330450848). A new pointer table entry must be allocated for the
    // relocated object, in a RO segment of the table.

    using IndirectPointerHandleMap =
        std::unordered_map<IndirectPointerHandle, IndirectPointerHandle>;
    IndirectPointerHandleMap code_pointer_moves_;
#endif  // V8_ENABLE_SANDBOX
  };

  static void LogPromotedObject(Tagged<HeapObject> src,
                                Tagged<HeapObject> dst) {
    std::cout << "ro-promotion: promoted object {from "
              << reinterpret_cast<void*>(src.ptr()) << " to "
              << reinterpret_cast<void*>(dst.ptr()) << "}\n";
  }

  static void LogPromotedCodePointerTableEntry(
      Tagged<Code> code, IndirectPointerHandle old_handle,
      IndirectPointerHandle new_handle) {
    std::cout << "ro-promotion: promoted code pointer table entry {code "
              << reinterpret_cast<void*>(code.ptr()) << " slot "
              << AsHex(old_handle, 8, true) << " to "
              << AsHex(new_handle, 8, true) << "}\n";
  }
};

}  // namespace

// static
void ReadOnlyPromotion::Promote(Isolate* isolate,
                                const SafepointScope& safepoint_scope,
                                const DisallowGarbageCollection& no_gc) {
  // Visit the mutable heap and determine the set of objects that can be
  // promoted to RO space.
  std::vector<Tagged<HeapObject>> promotees =
      Committee::DeterminePromotees(isolate, no_gc, safepoint_scope);
  // Physically copy promotee objects to RO space and track all object moves.
  HeapObjectMap moves;
  ReadOnlyPromotionImpl::CopyToReadOnlyHeap(isolate, promotees, &moves);
  // Update all references to moved objects to point at their new location in
  // RO space.
  ReadOnlyPromotionImpl::UpdatePointers(isolate, safepoint_scope, moves);
  ReadOnlyPromotionImpl::DeleteDeadObjects(isolate, safepoint_scope, moves);
  ReadOnlyPromotionImpl::Verify(isolate, safepoint_scope);
}

}  // namespace internal
}  // namespace v8

"""

```