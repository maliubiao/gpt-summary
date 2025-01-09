Response:
Let's break down the thought process to analyze this C++ header file.

1. **Understand the Context:** The filename `v8/src/heap/scavenger.h` immediately tells us this is part of the V8 JavaScript engine, specifically dealing with memory management within the "heap" and a component called "scavenger."  The `.h` extension confirms it's a C++ header file.

2. **Initial Scan for Keywords and Structures:**  A quick scan reveals important C++ constructs:
    * `#ifndef`, `#define`, `#endif`:  Standard header guard to prevent multiple inclusions.
    * `#include`:  Dependencies on other V8 or system headers. These give clues about the scavenger's responsibilities (e.g., `worklist`, `ephemeron-remembered-set`, `evacuation-allocator`).
    * `namespace v8`, `namespace internal`:  Indicates the code is part of the V8 internal implementation.
    * `class Scavenger`, `class ScavengerCollector`:  Key classes defining the scavenger's architecture.
    * `enum class`:  Defines an enumeration, likely for internal state or result codes.
    * `struct`: Defines data structures.
    * `using`:  Type aliases for convenience.
    * `static const`:  Constants used within the class.
    * Public and Private sections:  Standard C++ access modifiers.
    * Methods (functions within classes):  These describe the actions the scavenger performs (e.g., `ScavengePage`, `Process`, `Finalize`).
    * Member variables: These hold the state of the scavenger.
    * `friend class`:  Allows specific other classes access to private members.

3. **Focus on the `Scavenger` Class:** This appears to be the core of the scavenging process. Let's analyze its members:

    * **`PromotionList`:**  This nested class, with its `RegularObjectPromotionList` and `LargeObjectPromotionList`, suggests a mechanism for moving objects from the young generation to older generations. The "promotion" term is a strong indicator. The `Local` inner class suggests thread-local handling of promotion tasks.
    * **`CopiedList`:**  Likely a list of objects that have been successfully copied during scavenging.
    * **`EmptyChunksList`:**  A list of memory chunks that became empty after scavenging, potentially to be reused.
    * **Constructor:**  Takes a `ScavengerCollector`, `Heap`, and other parameters, implying dependencies.
    * **`ScavengePage`:** The primary function for scavenging a memory page.
    * **`Process`:**  Handles remaining work after initial scavenging.
    * **`Finalize`, `Publish`:** Lifecycle methods for the scavenger.
    * **`AddEphemeronHashTable`:**  Deals with weak references (ephemerons).
    * **`bytes_copied`, `bytes_promoted`:**  Metrics tracking the scavenging process.
    * **Private methods:** Implement the core logic of object copying, promotion, and handling different object types (`MigrateObject`, `SemiSpaceCopyObject`, `PromoteObject`, `EvacuateObject`, `HandleLargeObject`). The presence of template methods suggests generic handling of slots.
    * **Member variables:**  Hold state related to the scavenging process (`collector_`, `heap_`, worklists, allocators, flags for different scavenging modes).

4. **Focus on the `ScavengerCollector` Class:** This class seems to orchestrate the scavenging process.

    * **`kMaxScavengerTasks`, `kMainThreadId`:** Constants indicating parallelism.
    * **`CollectGarbage`:** The entry point for triggering a scavenge.
    * **`JobTask`:** An inner class inheriting from `v8::JobTask`, strongly suggesting that scavenging can be performed in parallel using V8's job queue.
    * **Methods for handling weak references:** `ProcessWeakReferences`, `ClearYoungEphemerons`, `ClearOldEphemerons`.
    * **`HandleSurvivingNewLargeObjects`:**  Handles large objects that survived the scavenge.
    * **`SweepArrayBufferExtensions`:** Related to managing `ArrayBuffer` memory.
    * **`IterateStackAndScavenge`:**  Scans the stack for references to objects to be scavenged.
    * **Member variables:** Hold state for the collection process (`isolate_`, `heap_`, `surviving_new_large_objects_`, concurrency estimation).

5. **Look for Connections to JavaScript Concepts:**  The terms "young generation," "old generation," and "promotion" strongly relate to generational garbage collection, a common technique in JavaScript engines. The handling of "ephemerons" (weak references) is also a JavaScript concept.

6. **Infer Functionality:** Based on the names and types, we can infer the following:

    * **Young Generation Garbage Collection:** The scavenger is responsible for collecting garbage in the young generation (often called the "nursery" or "from-space").
    * **Object Copying and Promotion:**  Live objects in the young generation are copied to either the young generation's "to-space" or promoted to an older generation.
    * **Handling Different Object Sizes:** Separate lists for regular and large objects suggest different handling strategies.
    * **Parallelism:** The `ScavengerCollector` uses `JobTask` to perform scavenging in parallel.
    * **Weak Reference Handling:** The scavenger handles weak references (ephemerons) to prevent them from keeping objects alive unnecessarily.
    * **Remembered Sets:**  The `EphemeronRememberedSet` indicates a mechanism for tracking pointers from old generations to young generations.
    * **Evacuation:** The `EvacuationAllocator` suggests a copying garbage collection algorithm where live objects are moved out of the current space.

7. **Address Specific Questions:**

    * **Is it Torque?** The filename ends in `.h`, not `.tq`, so it's a standard C++ header file.
    * **Relationship to JavaScript:**  Strong relationship, as it's a core component of V8's garbage collection, which directly impacts JavaScript memory management.
    * **Code Logic and Examples:**  Since it's a header file, the actual logic is in the corresponding `.cc` file. However, we can infer behavior based on the method names. For example, `ScavengeObject` likely takes an object, copies it if necessary, and updates references.
    * **Common Programming Errors:**  While this is engine code, understanding its purpose can help avoid errors like creating unnecessary long-lived objects in JavaScript, which can impact garbage collection performance.

8. **Structure the Output:** Organize the findings logically, covering the key functionalities, answering the specific questions, and providing examples where possible (even if they are high-level JavaScript examples). Use clear and concise language.

This systematic approach, combining code scanning, keyword analysis, and understanding of garbage collection concepts, allows for a comprehensive analysis of the header file's purpose even without examining the implementation details.
This header file `v8/src/heap/scavenger.h` defines the `Scavenger` and `ScavengerCollector` classes in the V8 JavaScript engine. These classes are responsible for the **scavenging garbage collection** process, which is a key part of V8's memory management. Scavenging primarily targets the **young generation** (also known as the nursery) of the heap, where newly allocated objects reside.

Here's a breakdown of its functionalities:

**Core Functionality: Young Generation Garbage Collection (Scavenging)**

The primary goal of the scavenger is to identify and reclaim memory occupied by dead objects in the young generation. This involves:

1. **Identifying Live Objects:** Starting from the roots (global variables, stack, etc.), the scavenger traverses the object graph to identify objects that are still reachable.
2. **Copying Live Objects:**  Live objects in the "from-space" of the young generation are copied to the "to-space" or promoted to the old generation. This process updates all references to these copied objects.
3. **Reclaiming Dead Objects:**  Once all live objects have been copied, the entire "from-space" is considered garbage and its memory can be reclaimed. The "from-space" and "to-space" then swap roles for the next scavenge cycle.

**Key Classes and Their Roles:**

* **`Scavenger`:**
    * **Performs the actual scavenging work on a given memory page or object.** It iterates through objects, determines if they are live, and copies them if necessary.
    * **Manages promotion of objects to the old generation.**  Objects that survive multiple scavenge cycles might be promoted to avoid the overhead of repeatedly copying them.
    * **Maintains worklists (`PromotionList`, `CopiedList`, `EmptyChunksList`)** to manage objects to be processed, copied objects, and empty memory chunks.
    * **Handles ephemerons (weak references).**
    * **Tracks statistics like `bytes_copied` and `bytes_promoted`.**
    * **Uses `EvacuationAllocator` to allocate space for copied objects.**

* **`ScavengerCollector`:**
    * **Orchestrates the overall scavenging process.**
    * **Divides the work into tasks that can be executed in parallel using `JobTask`.**
    * **Manages the `Scavenger` instances.**
    * **Handles weak references (ephemerons) after the main scavenging phase.**
    * **Manages surviving new large objects.**
    * **Sweeps array buffer extensions.**
    * **Iterates through the stack and scavenges objects referenced there.**

**Specific Functionalities and Data Structures:**

* **`PromotionList`:**  A worklist for objects that need to be promoted from the young generation to the old generation. It has separate lists for regular and large objects.
* **`CopiedList`:** A worklist for objects that have been successfully copied during scavenging.
* **`EmptyChunksList`:** A worklist for memory chunks that become empty after scavenging and can be reused.
* **`EphemeronRememberedSet`:** Used for tracking weak references (ephemerons) and ensuring they are processed correctly during garbage collection.
* **`EvacuationAllocator`:** Allocates memory in the "to-space" for objects being copied during scavenging.
* **`RootScavengeVisitor`:** A visitor pattern implementation used to traverse and scavenge objects directly referenced from the roots (global variables, stack, etc.).
* **`ScavengeVisitor`:**  Likely used to visit and scavenge objects within a page or object graph.
* **`CopyAndForwardResult`:** An enum indicating the success and destination (young or old generation) of a copy operation.

**Is `v8/src/heap/scavenger.h` a Torque source file?**

No, the file extension is `.h`, which signifies a standard C++ header file. If it were a Torque source file, it would have the `.tq` extension.

**Relationship to JavaScript and Examples:**

The scavenger directly impacts JavaScript's memory management. When you create objects in JavaScript, V8 initially allocates them in the young generation. The scavenger then reclaims the memory of objects that are no longer in use.

**JavaScript Example:**

```javascript
function createObject() {
  return { data: new Array(100000) }; // Create a relatively large object
}

let myObject = createObject();
// myObject is now in the young generation.

// ... some time later, myObject is no longer needed ...
myObject = null; // Make the object eligible for garbage collection.

// When the scavenger runs, it will identify that the object
// previously referenced by 'myObject' is no longer reachable
// and will reclaim its memory.
```

In this example, the `createObject` function allocates an object that initially resides in the young generation. When `myObject` is set to `null`, the object becomes unreachable (assuming no other references exist). During the next scavenging cycle, the scavenger will identify this dead object and free up the memory it occupied.

**Code Logic Inference (Hypothetical Example):**

Let's imagine a simplified version of the `ScavengeObject` function:

**Hypothetical C++ (inside `Scavenger`):**

```c++
// Simplified example - actual implementation is more complex
template <typename THeapObjectSlot>
inline SlotCallbackResult ScavengeObject(THeapObjectSlot slot, Tagged<HeapObject> object) {
  Heap* heap = heap();
  if (heap->IsInYoungGeneration(object)) {
    // Object is in the young generation, try to copy it

    // 1. Check if the object has already been copied (forwarding pointer)
    if (object->IsForwardingAddress()) {
      slot.Store(object->GetForwardingAddress()); // Update the slot
      return SlotCallbackResult::kKeepSlot;
    }

    // 2. Allocate space in the to-space
    Tagged<HeapObject> copy = allocator_.Allocate(object->Size());
    if (copy.is_null()) {
      // Handle allocation failure (e.g., promote to old gen)
      return SlotCallbackResult::kKeepSlot; // Simplified
    }

    // 3. Copy the object
    memcpy(copy.address(), object.address(), object->Size());

    // 4. Set the forwarding pointer in the original object
    object->SetForwardingAddress(copy);

    // 5. Update the slot to point to the copied object
    slot.Store(copy);

    local_copied_list_.Push({copy, object->Size()}); // Add to copied list
    return SlotCallbackResult::kKeepSlot;
  } else {
    // Object is not in the young generation, no need to scavenge
    return SlotCallbackResult::kKeepSlot;
  }
}
```

**Assumptions:**

* **Input:** `slot` is a memory location (slot) pointing to an object, `object` is the object being pointed to.
* **Output:** The function might update the `slot` to point to a new location if the object was copied. It returns a `SlotCallbackResult` indicating the outcome.

**Logic:**

1. **Check if the object is in the young generation.** Scavenging primarily targets this area.
2. **Check for a forwarding pointer:** If the object has already been copied in a previous scavenging pass, update the slot to the new location.
3. **Allocate space:** If not already copied, allocate space for the copy in the "to-space".
4. **Copy the object:**  Copy the contents of the original object to the new location.
5. **Set forwarding pointer:**  Mark the original object with a forwarding pointer to the new copy. This ensures that if this object is encountered again during the same scavenging cycle, its references can be updated correctly.
6. **Update the slot:**  The original slot is updated to point to the newly copied object.
7. **Add to copied list:** The copied object is added to the `CopiedList` for further processing (e.g., updating references within the copied object).

**Common Programming Errors (Relating to Garbage Collection Awareness):**

While developers don't directly interact with `scavenger.h`, understanding its principles helps avoid performance issues related to garbage collection:

1. **Creating Excessive Short-Lived Objects:**  If a program creates a large number of temporary objects that quickly become unreachable, the scavenger will have to work harder to collect them, potentially impacting performance.

   **Example:**

   ```javascript
   function processData(data) {
     for (let i = 0; i < data.length; i++) {
       const temp = { value: data[i] * 2 }; // Short-lived object
       // ... some operation with temp ...
     }
   }
   ```

   In this case, a new `temp` object is created in each iteration of the loop. If `data.length` is large, this can put pressure on the young generation and trigger more frequent scavenging.

2. **Holding Unnecessary References:**  Keeping references to objects that are no longer needed prevents the garbage collector from reclaiming their memory. This can lead to memory leaks.

   **Example:**

   ```javascript
   let largeData = new Array(1000000);
   let cache = {};

   function processAndCache(id, data) {
     cache[id] = data; // Store a reference
     // ... process data ...
   }

   processAndCache("important", largeData);
   // Even if 'largeData' is no longer explicitly used elsewhere,
   // the 'cache' object holds a reference, preventing it from
   // being garbage collected.
   ```

3. **Circular References:** While modern garbage collectors (including V8's) can handle basic circular references, complex cycles involving finalizers or weak references can sometimes lead to issues.

**In Summary:**

`v8/src/heap/scavenger.h` defines the core components responsible for the young generation garbage collection in V8. It's a critical part of V8's memory management system, ensuring efficient allocation and reclamation of memory for JavaScript applications. Understanding its role can help developers write more performant and memory-efficient JavaScript code.

Prompt: 
```
这是目录为v8/src/heap/scavenger.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/scavenger.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_HEAP_SCAVENGER_H_
#define V8_HEAP_SCAVENGER_H_

#include "src/base/platform/condition-variable.h"
#include "src/heap/base/worklist.h"
#include "src/heap/ephemeron-remembered-set.h"
#include "src/heap/evacuation-allocator.h"
#include "src/heap/heap-visitor.h"
#include "src/heap/index-generator.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/heap/parallel-work-item.h"
#include "src/heap/pretenuring-handler.h"
#include "src/heap/slot-set.h"

namespace v8 {
namespace internal {

class RootScavengeVisitor;
class Scavenger;
class ScavengeVisitor;

enum class CopyAndForwardResult {
  SUCCESS_YOUNG_GENERATION,
  SUCCESS_OLD_GENERATION,
  FAILURE
};

using ObjectAndSize = std::pair<Tagged<HeapObject>, int>;
using SurvivingNewLargeObjectsMap =
    std::unordered_map<Tagged<HeapObject>, Tagged<Map>, Object::Hasher>;
using SurvivingNewLargeObjectMapEntry =
    std::pair<Tagged<HeapObject>, Tagged<Map>>;

class ScavengerCollector;

class Scavenger {
 public:
  struct PromotionListEntry {
    Tagged<HeapObject> heap_object;
    Tagged<Map> map;
    int size;
  };

  class PromotionList {
   public:
    static constexpr size_t kRegularObjectPromotionListSegmentSize = 256;
    static constexpr size_t kLargeObjectPromotionListSegmentSize = 4;

    using RegularObjectPromotionList =
        ::heap::base::Worklist<ObjectAndSize,
                               kRegularObjectPromotionListSegmentSize>;
    using LargeObjectPromotionList =
        ::heap::base::Worklist<PromotionListEntry,
                               kLargeObjectPromotionListSegmentSize>;

    class Local {
     public:
      explicit Local(PromotionList* promotion_list);

      inline void PushRegularObject(Tagged<HeapObject> object, int size);
      inline void PushLargeObject(Tagged<HeapObject> object, Tagged<Map> map,
                                  int size);
      inline size_t LocalPushSegmentSize() const;
      inline bool Pop(struct PromotionListEntry* entry);
      inline bool IsGlobalPoolEmpty() const;
      inline bool ShouldEagerlyProcessPromotionList() const;
      inline void Publish();

     private:
      RegularObjectPromotionList::Local regular_object_promotion_list_local_;
      LargeObjectPromotionList::Local large_object_promotion_list_local_;
    };

    inline bool IsEmpty() const;
    inline size_t Size() const;

   private:
    RegularObjectPromotionList regular_object_promotion_list_;
    LargeObjectPromotionList large_object_promotion_list_;
  };

  static const int kCopiedListSegmentSize = 256;

  using CopiedList =
      ::heap::base::Worklist<ObjectAndSize, kCopiedListSegmentSize>;
  using EmptyChunksList = ::heap::base::Worklist<MutablePageMetadata*, 64>;

  Scavenger(ScavengerCollector* collector, Heap* heap, bool is_logging,
            EmptyChunksList* empty_chunks, CopiedList* copied_list,
            PromotionList* promotion_list,
            EphemeronRememberedSet::TableList* ephemeron_table_list);

  // Entry point for scavenging an old generation page. For scavenging single
  // objects see RootScavengingVisitor and ScavengeVisitor below.
  void ScavengePage(MutablePageMetadata* page);

  // Processes remaining work (=objects) after single objects have been
  // manually scavenged using ScavengeObject or CheckAndScavengeObject.
  void Process(JobDelegate* delegate = nullptr);

  // Finalize the Scavenger. Needs to be called from the main thread.
  void Finalize();
  void Publish();

  void AddEphemeronHashTable(Tagged<EphemeronHashTable> table);

  size_t bytes_copied() const { return copied_size_; }
  size_t bytes_promoted() const { return promoted_size_; }

 private:
  enum PromotionHeapChoice { kPromoteIntoLocalHeap, kPromoteIntoSharedHeap };

  // Number of objects to process before interrupting for potentially waking
  // up other tasks.
  static const int kInterruptThreshold = 128;

  inline Heap* heap() { return heap_; }

  inline void PageMemoryFence(Tagged<MaybeObject> object);

  void AddPageToSweeperIfNecessary(MutablePageMetadata* page);

  // Potentially scavenges an object referenced from |slot| if it is
  // indeed a HeapObject and resides in from space.
  template <typename TSlot>
  inline SlotCallbackResult CheckAndScavengeObject(Heap* heap, TSlot slot);

  template <typename TSlot>
  inline void CheckOldToNewSlotForSharedUntyped(MemoryChunk* chunk,
                                                MutablePageMetadata* page,
                                                TSlot slot);
  inline void CheckOldToNewSlotForSharedTyped(MemoryChunk* chunk,
                                              MutablePageMetadata* page,
                                              SlotType slot_type,
                                              Address slot_address,
                                              Tagged<MaybeObject> new_target);

  // Scavenges an object |object| referenced from slot |p|. |object| is required
  // to be in from space.
  template <typename THeapObjectSlot>
  inline SlotCallbackResult ScavengeObject(THeapObjectSlot p,
                                           Tagged<HeapObject> object);

  // Copies |source| to |target| and sets the forwarding pointer in |source|.
  V8_INLINE bool MigrateObject(Tagged<Map> map, Tagged<HeapObject> source,
                               Tagged<HeapObject> target, int size,
                               PromotionHeapChoice promotion_heap_choice);

  V8_INLINE SlotCallbackResult
  RememberedSetEntryNeeded(CopyAndForwardResult result);

  template <typename THeapObjectSlot>
  V8_INLINE CopyAndForwardResult SemiSpaceCopyObject(
      Tagged<Map> map, THeapObjectSlot slot, Tagged<HeapObject> object,
      int object_size, ObjectFields object_fields);

  template <typename THeapObjectSlot,
            PromotionHeapChoice promotion_heap_choice = kPromoteIntoLocalHeap>
  V8_INLINE CopyAndForwardResult PromoteObject(Tagged<Map> map,
                                               THeapObjectSlot slot,
                                               Tagged<HeapObject> object,
                                               int object_size,
                                               ObjectFields object_fields);

  template <typename THeapObjectSlot>
  V8_INLINE SlotCallbackResult EvacuateObject(THeapObjectSlot slot,
                                              Tagged<Map> map,
                                              Tagged<HeapObject> source);

  V8_INLINE bool HandleLargeObject(Tagged<Map> map, Tagged<HeapObject> object,
                                   int object_size, ObjectFields object_fields);

  // Different cases for object evacuation.
  template <typename THeapObjectSlot,
            PromotionHeapChoice promotion_heap_choice = kPromoteIntoLocalHeap>
  V8_INLINE SlotCallbackResult EvacuateObjectDefault(
      Tagged<Map> map, THeapObjectSlot slot, Tagged<HeapObject> object,
      int object_size, ObjectFields object_fields);

  template <typename THeapObjectSlot>
  inline SlotCallbackResult EvacuateThinString(Tagged<Map> map,
                                               THeapObjectSlot slot,
                                               Tagged<ThinString> object,
                                               int object_size);

  template <typename THeapObjectSlot>
  inline SlotCallbackResult EvacuateShortcutCandidate(Tagged<Map> map,
                                                      THeapObjectSlot slot,
                                                      Tagged<ConsString> object,
                                                      int object_size);

  template <typename THeapObjectSlot>
  inline SlotCallbackResult EvacuateInPlaceInternalizableString(
      Tagged<Map> map, THeapObjectSlot slot, Tagged<String> string,
      int object_size, ObjectFields object_fields);

  void IterateAndScavengePromotedObject(Tagged<HeapObject> target,
                                        Tagged<Map> map, int size);
  void RememberPromotedEphemeron(Tagged<EphemeronHashTable> table, int index);

  ScavengerCollector* const collector_;
  Heap* const heap_;
  EmptyChunksList::Local local_empty_chunks_;
  PromotionList::Local local_promotion_list_;
  CopiedList::Local local_copied_list_;
  EphemeronRememberedSet::TableList::Local local_ephemeron_table_list_;
  PretenuringHandler::PretenuringFeedbackMap local_pretenuring_feedback_;
  EphemeronRememberedSet::TableMap local_ephemeron_remembered_set_;
  SurvivingNewLargeObjectsMap local_surviving_new_large_objects_;
  size_t copied_size_{0};
  size_t promoted_size_{0};
  EvacuationAllocator allocator_;

  const bool is_logging_;
  const bool is_incremental_marking_;
  const bool is_compacting_;
  const bool shared_string_table_;
  const bool mark_shared_heap_;
  const bool shortcut_strings_;

  friend class IterateAndScavengePromotedObjectsVisitor;
  friend class RootScavengeVisitor;
  friend class ScavengeVisitor;
};

// Helper class for turning the scavenger into an object visitor that is also
// filtering out non-HeapObjects and objects which do not reside in new space.
class RootScavengeVisitor final : public RootVisitor {
 public:
  explicit RootScavengeVisitor(Scavenger& scavenger);
  ~RootScavengeVisitor() final;

  void VisitRootPointer(Root root, const char* description,
                        FullObjectSlot p) final;
  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) final;

 private:
  void ScavengePointer(FullObjectSlot p);

  Scavenger& scavenger_;
};

class ScavengerCollector {
 public:
  static const int kMaxScavengerTasks = 8;
  static const int kMainThreadId = 0;

  explicit ScavengerCollector(Heap* heap);

  void CollectGarbage();

 private:
  class JobTask : public v8::JobTask {
   public:
    JobTask(ScavengerCollector* collector,
            std::vector<std::unique_ptr<Scavenger>>* scavengers,
            std::vector<std::pair<ParallelWorkItem, MutablePageMetadata*>>
                old_to_new_chunks,
            const Scavenger::CopiedList& copied_list,
            const Scavenger::PromotionList& promotion_list);

    void Run(JobDelegate* delegate) override;
    size_t GetMaxConcurrency(size_t worker_count) const override;

    uint64_t trace_id() const { return trace_id_; }

   private:
    void ProcessItems(JobDelegate* delegate, Scavenger* scavenger);
    void ConcurrentScavengePages(Scavenger* scavenger);

    ScavengerCollector* collector_;

    std::vector<std::unique_ptr<Scavenger>>* scavengers_;
    std::vector<std::pair<ParallelWorkItem, MutablePageMetadata*>>
        old_to_new_chunks_;
    std::atomic<size_t> remaining_memory_chunks_{0};
    IndexGenerator generator_;

    const Scavenger::CopiedList& copied_list_;
    const Scavenger::PromotionList& promotion_list_;

    const uint64_t trace_id_;
  };

  void MergeSurvivingNewLargeObjects(
      const SurvivingNewLargeObjectsMap& objects);

  int NumberOfScavengeTasks();

  void ProcessWeakReferences(
      EphemeronRememberedSet::TableList* ephemeron_table_list);
  void ClearYoungEphemerons(
      EphemeronRememberedSet::TableList* ephemeron_table_list);
  void ClearOldEphemerons();
  void HandleSurvivingNewLargeObjects();

  void SweepArrayBufferExtensions();

  void IterateStackAndScavenge(
      RootScavengeVisitor* root_scavenge_visitor,
      std::vector<std::unique_ptr<Scavenger>>* scavengers,
      Scavenger& main_thread_scavenger);

  size_t FetchAndResetConcurrencyEstimate() {
    const size_t estimate =
        estimate_concurrency_.exchange(0, std::memory_order_relaxed);
    return estimate == 0 ? 1 : estimate;
  }

  Isolate* const isolate_;
  Heap* const heap_;
  SurvivingNewLargeObjectsMap surviving_new_large_objects_;
  std::atomic<size_t> estimate_concurrency_{0};

  friend class Scavenger;
};

}  // namespace internal
}  // namespace v8

#endif  // V8_HEAP_SCAVENGER_H_

"""

```