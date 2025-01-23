Response:
Let's break down the thought process for analyzing the C++ code and generating the requested information.

1. **Understand the Goal:** The primary goal is to understand the purpose and functionality of the `read-only-promotion.cc` file within the V8 JavaScript engine. This involves identifying its main tasks, any relationships to JavaScript, potential error scenarios, and providing illustrative examples.

2. **Initial Code Scan - High-Level Overview:**  Quickly read through the code, paying attention to class names, function names, and comments. Keywords like "promote," "read-only," "heap," and "visitor" stand out. The copyright notice confirms it's part of the V8 project. The `#include` directives tell us it interacts with various V8 components related to heap management, execution, and objects.

3. **Identify Key Classes and Their Roles:**

   * **`Committee`:** This class seems responsible for *deciding* which objects should be promoted to read-only space. The `DeterminePromotees` function strongly suggests this. The `EvaluateSubgraph` function hints at a recursive process for checking dependencies. The `IsPromoCandidate` functions define the criteria for promotion.

   * **`ReadOnlyPromotionImpl`:** This class appears to handle the *actual* promotion process. `CopyToReadOnlyHeap` clearly indicates the physical copying of data. `UpdatePointers` suggests updating references to the moved objects. `DeleteDeadObjects` and `Verify` point to post-promotion cleanup and checks.

   * **Visitors (`CandidateVisitor`, `UpdatePointersVisitor`):** These classes are used to traverse the heap and object graphs, performing specific actions on each object or slot. This is a common pattern in V8 for heap manipulation.

4. **Trace the Core Logic Flow (`ReadOnlyPromotion::Promote`):** This function seems to be the entry point. Observe the order of operations:
   * `Committee::DeterminePromotees`: Find candidates.
   * `ReadOnlyPromotionImpl::CopyToReadOnlyHeap`: Copy them.
   * `ReadOnlyPromotionImpl::UpdatePointers`: Update references.
   * `ReadOnlyPromotionImpl::DeleteDeadObjects`: Clean up the original locations.
   * `ReadOnlyPromotionImpl::Verify`: Check for correctness.

5. **Analyze `Committee::DeterminePromotees` in Detail:**

   * It iterates through heap objects using `HeapObjectIterator`.
   * It uses `EvaluateSubgraph` to decide if a connected group of objects can be promoted together.
   * `IsPromoCandidate` is the core logic for individual object eligibility. Examine the `PROMO_CANDIDATE_TYPE_LIST` and the specific `IsPromoCandidate...` functions. This reveals which V8 internal object types are eligible for read-only promotion (e.g., `Code`, `SharedFunctionInfo`, `Symbol`).

6. **Analyze `ReadOnlyPromotionImpl` Functions:**

   * **`CopyToReadOnlyHeap`:**  Simple memory copying.
   * **`UpdatePointers`:**  Crucial for correctness. It iterates through roots, the mutable heap, and the newly promoted objects, updating pointers using the `UpdatePointersVisitor`.
   * **`DeleteDeadObjects`:** Overwrites the original memory to prevent issues with heap verification.
   * **`Verify`:** Contains `CHECK` statements, indicating debugging assertions to ensure the promotion process worked correctly.

7. **Connect to JavaScript (If Applicable):**

   * **`Code` objects:**  These are generated when JavaScript functions are compiled. Promoting built-in `Code` objects to read-only space makes sense for performance and immutability.
   * **`SharedFunctionInfo`:**  Contains metadata about functions. Promoting immutable information about built-in functions is a good optimization.
   * **`Symbol`:**  Often used for internal properties or unique identifiers. Immutable symbols can be safely promoted.

8. **Identify Potential User Errors:**  Think about scenarios where a user might unintentionally create objects that *look* like they should be read-only but aren't, or rely on mutability of objects that V8 might try to make read-only. This is where the "internal" nature of the optimization becomes important – it's not something JavaScript developers directly control.

9. **Construct Examples and Explanations:** Based on the analysis, create:

   * **Functional Summary:**  A concise description of the file's purpose.
   * **JavaScript Relationship:**  Illustrate how the promoted objects relate to JavaScript concepts.
   * **Code Logic Explanation:**  Explain the flow of the core functions, including inputs and outputs (even if abstract).
   * **Potential Errors:**  Focus on *why* certain objects might *not* be promoted, as this is closer to potential observable behavior.
   * **Torque Check:**  Address the `.tq` file extension question.

10. **Refine and Organize:** Review the generated information for clarity, accuracy, and completeness. Use formatting (like headings and bullet points) to improve readability. Ensure the JavaScript examples are clear and relevant.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "Maybe this promotes *user-defined* objects to read-only."  **Correction:**  The code focuses on *internal* V8 objects like `Code` and `SharedFunctionInfo`. User-defined objects are generally not directly promotable in this way. The goal is V8 internal optimization.
* **Considering Errors:**  Instead of thinking about *user* coding errors *causing* promotion, focus on user code that *relies* on mutability of objects that *might* be targeted for promotion (though this is largely internal to V8). The more relevant "error" is the *expectation* of mutability where V8 might enforce immutability.
* **JavaScript Examples:** Initially, might think of complex examples. **Correction:** Keep the JavaScript examples simple and directly related to the V8 internal objects being discussed (functions, symbols).

By following this structured analysis and iterative refinement, we can arrive at a comprehensive understanding of the `read-only-promotion.cc` file and generate the requested information.
This C++ source code file `v8/src/heap/read-only-promotion.cc` implements a mechanism within the V8 JavaScript engine to **promote certain heap objects from regular, mutable memory spaces to the read-only heap space.**

Here's a breakdown of its functionalities:

**Core Functionality:**

1. **Identifying Promotion Candidates:** The code defines criteria and a process for determining which heap objects are suitable for promotion to read-only space. This is primarily handled by the `Committee` class.
2. **Copying to Read-Only Space:** Once candidate objects are identified, the code physically copies these objects to the read-only heap space. This is done by the `ReadOnlyPromotionImpl::CopyToReadOnlyHeap` function.
3. **Updating Pointers:**  After an object is moved to read-only space, all existing pointers to that object in the regular heap need to be updated to point to its new location in the read-only space. The `ReadOnlyPromotionImpl::UpdatePointers` function is responsible for this, traversing the heap and roots to find and update these pointers.
4. **Deleting Dead Objects (Overwriting with Fillers):**  The original locations of the promoted objects in the mutable heap are overwritten with filler objects. This is important for heap verification and to mark the memory as no longer in use. `ReadOnlyPromotionImpl::DeleteDeadObjects` handles this.
5. **Verification:** The code includes verification steps to ensure that the promotion process has been carried out correctly and that expected objects have been moved to read-only space. `ReadOnlyPromotionImpl::Verify` performs these checks.

**Key Classes and Components:**

* **`Committee`:** This class is responsible for deciding which objects to promote.
    * `DeterminePromotees`:  The main function that orchestrates the process of finding eligible objects.
    * `EvaluateSubgraph`: Recursively checks if an object and the objects it points to are all valid promotion candidates. This handles dependencies between objects.
    * `IsPromoCandidate`: A set of functions (e.g., `IsPromoCandidateCode`, `IsPromoCandidateSharedFunctionInfo`) that define the specific criteria for different types of objects to be considered for promotion. These criteria often involve checking if the object is immutable or intended to be read-only.
* **`ReadOnlyPromotionImpl`:** This class implements the actions of copying, updating pointers, and deleting the original objects.
    * `CopyToReadOnlyHeap`:  Performs the physical memory copy to the read-only space.
    * `UpdatePointers`: Iterates through the heap and roots, updating pointers to the relocated objects.
    * `DeleteDeadObjects`: Overwrites the original memory of promoted objects with fillers.
    * `Verify`: Contains assertions to check if the promotion process was successful.
* **`CandidateVisitor`:**  A visitor class used by `EvaluateSubgraph` to traverse the object graph and check if all reachable objects from a potential promotee are also valid candidates.
* **`UpdatePointersVisitor`:** A visitor class used by `UpdatePointers` to iterate through the heap and roots, finding and updating pointers to the moved objects.

**Relationship to JavaScript:**

While this is a low-level V8 implementation detail, it directly impacts the performance and memory usage of JavaScript execution. By moving immutable objects to read-only memory:

* **Performance:**  Accessing objects in read-only memory can be faster in some architectures.
* **Memory Efficiency:** Read-only memory can potentially be shared more aggressively and might have other memory management benefits.
* **Security:**  Ensuring certain core objects are immutable can improve security by preventing accidental or malicious modification.

**Examples of JavaScript objects that might be backed by promoted read-only objects:**

* **Built-in Functions and Objects:**  The code explicitly checks for promoting `Code` objects that are built-ins. Built-in functions like `Array.prototype.map`, `String.fromCharCode`, etc., are compiled into `Code` objects. Their underlying implementations can be promoted to read-only.
* **Shared Function Information:**  Metadata about functions that is immutable, such as the function's name, the number of parameters, etc., can be stored in `SharedFunctionInfo` objects which can be promoted.
* **Symbols:**  JavaScript `Symbol` values, especially those used for well-known symbols (like `Symbol.iterator`), are good candidates for read-only promotion as their values are inherently immutable.

**JavaScript Example:**

```javascript
// Accessing a built-in method
const arr = [1, 2, 3];
arr.map(x => x * 2); // The underlying implementation of 'map' might reside in read-only space.

// Using a well-known symbol
const iterator = arr[Symbol.iterator](); // The Symbol.iterator itself is likely a read-only object.

// Accessing properties of built-in objects
console.log(Math.PI); // The value of Math.PI is constant and could be part of a read-only object.
```

**Code Logic Inference (Hypothetical Example):**

**Assumption:** The `IsPromoCandidateCode` function checks if a `Code` object is a built-in and if a flag `Builtins::kCodeObjectsAreInROSpace` is true.

**Input:** A `Code` object representing the implementation of `Array.prototype.push`.

**Process:**
1. `DeterminePromotees` iterates through heap objects.
2. When it encounters the `Code` object for `Array.prototype.push`, it calls `EvaluateSubgraph`.
3. `EvaluateSubgraph` calls `IsPromoCandidate(code_object)`.
4. `IsPromoCandidateCode(code_object)` checks:
   - `code_object->is_builtin()`:  This would likely return `true`.
   - `Builtins::kCodeObjectsAreInROSpace`: Let's assume this flag is set to `true`.
5. Since both conditions are met, `IsPromoCandidateCode` returns `true`.
6. If all objects reachable from this `Code` object also satisfy promotion criteria, the `Code` object is added to the list of promotees.
7. Later, `CopyToReadOnlyHeap` copies this `Code` object to the read-only space.
8. `UpdatePointers` updates all references to this `Code` object to point to its new read-only location.

**Output:** The `Code` object for `Array.prototype.push` is moved to the read-only heap.

**User-Common Programming Errors (Indirect Relationship):**

Users don't directly control read-only promotion. However, understanding this process helps in understanding why certain behaviors are enforced:

1. **Attempting to Modify Built-in Objects:** JavaScript prevents modification of properties on certain built-in objects or their prototypes that are intended to be immutable. This aligns with the concept of promoting these objects (or their underlying data) to read-only space.

   ```javascript
   // Error: Cannot assign to read only property 'prototype' of function 'String'
   String.prototype = {};

   // Error (in strict mode): Cannot assign to read only property 'PI' of object '[object Math]'
   Math.PI = 3;
   ```

   While the error message doesn't explicitly mention "read-only promotion," the underlying mechanism contributes to this immutability.

2. **Relying on Mutability of Internal V8 Structures (Highly Uncommon and Usually Not Directly Observable):**  In extremely rare and advanced scenarios, if a user were somehow able to access and attempt to modify internal V8 objects that have been promoted to read-only space, it would lead to errors or unexpected behavior at the C++ level. However, this is not a typical JavaScript programming error.

**In summary, `v8/src/heap/read-only-promotion.cc` is a crucial part of V8's optimization strategy, responsible for identifying and moving immutable heap objects to a dedicated read-only memory area, improving performance, memory efficiency, and potentially security. While users don't directly interact with this process, it underlies the immutability of certain core JavaScript features.**

**Regarding the `.tq` extension:**

The provided code snippet is in C++ (`.cc`). If `v8/src/heap/read-only-promotion.cc` *were* to end in `.tq`, then it would indeed be a **Torque** source file. Torque is V8's domain-specific language for implementing built-in functions and runtime components. Torque code is statically typed and compiles to machine code.

If a file with the `.tq` extension existed related to read-only promotion, it would likely contain the Torque implementation of some of the core logic for determining promotion candidates or manipulating objects during the promotion process. However, based on the provided code, the current file is a standard C++ implementation.

### 提示词
```
这是目录为v8/src/heap/read-only-promotion.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/read-only-promotion.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```