Response:
My thinking process to analyze the `v8/src/heap/mark-compact.h` file went through these stages:

1. **Initial Scan and High-Level Understanding:** I first skimmed through the file, paying attention to comments, class names, and included headers. This gave me a general idea that the file is related to garbage collection, specifically the mark-compact algorithm in V8. The inclusion of headers like `marking-state.h`, `marking-visitor.h`, `spaces.h`, and `sweeper.h` reinforced this.

2. **Identifying Key Classes and their Roles:** I then focused on the major classes defined in the file: `RootMarkingVisitor` and `MarkCompactCollector`.

    * **`RootMarkingVisitor`:**  The name strongly suggests its purpose: visiting and marking objects directly reachable from the "roots" of the object graph (global variables, stack, etc.). The methods `VisitRootPointer` and `VisitRootPointers` confirm this. The comment about syncing with `RootsReferencesExtractor::VisitRunningCode()` hints at its role in identifying code objects.

    * **`MarkCompactCollector`:** This is the central class. The name clearly indicates it implements the mark-compact garbage collection algorithm. I looked for methods that correspond to the different phases of GC: marking (`StartMarking`, `MarkRoots`, `MarkTransitiveClosure`), sweeping (`Sweep`, `StartSweepSpace`), and compaction (`StartCompaction`, `Evacuate`). The presence of nested classes and enums further suggested its complexity.

3. **Analyzing `MarkCompactCollector`'s Members and Methods:** I systematically went through the public and private members and methods of `MarkCompactCollector`, grouping them by functionality:

    * **Configuration and Control:** Enums like `StartCompactionMode` and `MarkingWorklistProcessingMode`, and methods like `CollectGarbage`, `Prepare`, and `FinishConcurrentMarking`.
    * **Marking Phase:** Methods starting with "Mark" (e.g., `MarkLiveObjects`, `MarkRoots`, `MarkObject`). The importance of the worklist (`MarkingWorklists`) and ephemerons (`ProcessEphemeron`) became evident.
    * **Sweeping Phase:** Methods starting with "Sweep" (e.g., `SweepArrayBufferExtensions`, `SweepLargeSpace`).
    * **Compaction/Evacuation Phase:** Methods starting with "Evacuate" (e.g., `Evacuate`, `EvacuatePagesInParallel`).
    * **Weak References Handling:** Methods related to clearing weak references and collections (e.g., `ClearNonLiveReferences`, `ClearWeakCollections`).
    * **Optimization and Code Management:** Methods related to bytecode flushing and deoptimization (e.g., `FlushBytecodeFromSFI`, `MarkDependentCodeForDeoptimization`).
    * **Internal State and Debugging:**  Private members like `state_`, `compacting_`, and debug-related methods (`VerifyMarking`, `VerifyMarkbitsAreClean`).

4. **Looking for Connections to JavaScript:** I considered how the concepts in the header file relate to JavaScript. Garbage collection is fundamental to JavaScript's memory management. I thought about:

    * **Object Reachability:** The marking phase directly relates to determining which JavaScript objects are still in use.
    * **Weak References:**  JavaScript's `WeakRef` and `WeakMap`/`WeakSet` are directly handled by the weak reference clearing mechanisms.
    * **Code Optimization:** The bytecode flushing and deoptimization are related to V8's optimization pipeline for JavaScript code.

5. **Considering Edge Cases and Potential Errors:** I tried to think about situations where the garbage collector might encounter problems or where developers might make mistakes that interact with garbage collection. This led to examples like:

    * **Memory Leaks:**  While GC prevents many leaks, holding onto objects unnecessarily can still cause high memory usage.
    * **Performance Issues:**  Frequent or long GC pauses can impact application performance. Understanding the different GC modes (incremental vs. atomic) is relevant here.
    * **Weak Reference Behavior:** Misunderstanding how weak references work can lead to unexpected object reclamation.

6. **Addressing Specific Instructions:** I specifically looked for the prompt's instructions:

    * **File Extension:** Noted that `.h` means it's a C++ header file, not Torque.
    * **Functionality Listing:**  Systematically listed the functions based on the analysis in steps 2 and 3.
    * **JavaScript Examples:** Provided relevant JavaScript examples to illustrate the connection between the C++ code and JavaScript concepts.
    * **Logic Reasoning:** Chose a simple scenario (marking an object) to illustrate the input and output.
    * **Common Programming Errors:**  Provided examples of common errors related to memory management and weak references.

7. **Structuring the Output:** Finally, I organized the information logically with clear headings and bullet points to make it easy to understand. I made sure to address all the points raised in the initial prompt.

Essentially, my approach was a combination of top-down (understanding the overall purpose) and bottom-up (analyzing individual components) analysis, combined with domain knowledge about garbage collection and JavaScript. I tried to connect the technical details in the header file to higher-level concepts and practical implications for JavaScript developers.
This is a header file (`.h`) in the V8 JavaScript engine's source code, specifically for the mark-compact garbage collector. Since the filename ends with `.h`, it's a **C++ header file**, not a Torque source file (which would end in `.tq`).

Here's a breakdown of its functionality:

**Core Functionality: Mark-Compact Garbage Collection**

The primary purpose of `v8/src/heap/mark-compact.h` is to **define the interface and data structures for the mark-compact garbage collector** in V8. This garbage collector is responsible for reclaiming memory occupied by objects that are no longer in use by the JavaScript program. The mark-compact algorithm works in two main phases:

1. **Marking:** Identifying all live (reachable) objects in the heap.
2. **Compaction:** Moving the live objects together to one end of the memory space, leaving a contiguous block of free memory.

**Key Components and Functionality Defined in the Header:**

* **`RootMarkingVisitor`:**  This class is responsible for visiting and marking objects directly reachable from the "roots" of the object graph (e.g., global variables, stack).
    * **`VisitRootPointer`, `VisitRootPointers`:** Methods to mark objects pointed to by root pointers.
    * **`VisitRunningCode`:** Handles marking objects referenced within currently executing code.

* **`MarkCompactCollector`:** This is the central class that orchestrates the mark-compact garbage collection process. It encapsulates the entire algorithm and its state. Key responsibilities include:
    * **Starting and Stopping GC:**  Methods like `CollectGarbage`, `StartMarking`, `FinishConcurrentMarking`, `StartCompaction`.
    * **Marking Phase Implementation:**
        * Managing marking worklists (`MarkingWorklists`) to keep track of objects to be visited.
        * Handling weak objects and ephemerons (objects whose reachability depends on the reachability of another object).
        * Visiting and marking objects reachable from various sources (roots, stack, client heaps).
        * Implementing different marking strategies (incremental, atomic).
    * **Compaction Phase Implementation:**
        * Selecting evacuation candidates (pages to compact).
        * Moving live objects to new locations.
        * Updating pointers to moved objects.
    * **Sweeping Phase Implementation:** Reclaiming unmarked memory.
    * **Handling Weak References:** Clearing weak references to dead objects.
    * **Code Flushing and Deoptimization:**  Managing cached code (bytecode, baseline code) and deoptimizing code based on garbage collection events.
    * **Statistics and Verification:** Tracking GC progress and verifying the correctness of the process.

**Relationship to JavaScript Functionality**

While this header file is C++, it directly underpins JavaScript's automatic memory management. JavaScript developers don't directly interact with these classes, but the mark-compact collector defined here is what allows JavaScript to avoid manual memory allocation and deallocation.

**JavaScript Examples Illustrating the Need for Mark-Compact GC:**

```javascript
// Example 1: Basic object creation and garbage collection
function createObject() {
  let obj = { data: "important data" };
  return obj; // The object is now referenced outside the function
}

let myObject = createObject();
// ... use myObject ...
myObject = null; // Now the object is no longer reachable

// The mark-compact collector will eventually identify that the original
// object created inside createObject is no longer reachable and reclaim its memory.

// Example 2: Circular references
function createCircularObjects() {
  let obj1 = {};
  let obj2 = {};
  obj1.circularRef = obj2;
  obj2.circularRef = obj1;
  return { obj1, obj2 }; // Both objects are reachable
}

let circular = createCircularObjects();
circular = null; // Neither obj1 nor obj2 are directly reachable anymore

// Even though obj1 and obj2 reference each other, the mark-compact collector
// can detect that the entire circular structure is no longer reachable from
// the roots and reclaim the memory.

// Example 3: Weak References (JavaScript's WeakRef, WeakMap, WeakSet)
let weakRef = new WeakRef({ data: "weakly held data" });
// ... later ...
let derefObject = weakRef.deref(); // May return the object or undefined if GC'd

// The mark-compact collector's weak reference handling logic is crucial
// for the correct behavior of JavaScript's WeakRef, WeakMap, and WeakSet.
```

**Code Logic Reasoning (Hypothetical Example)**

Let's consider a simplified scenario within the marking phase:

**Assumption:** The garbage collector has identified a root object `A`. Object `A` has a pointer to object `B`.

**Input:**
* `RootMarkingVisitor` instance.
* `FullObjectSlot p` pointing to the memory location of object `A`.
* Object `A` contains a field that points to object `B`.

**Logic within `RootMarkingVisitor::VisitRootPointer` (simplified):**

1. The method is called with the pointer `p` of root object `A`.
2. The collector checks if object `A` has already been marked.
3. If `A` is not marked, it is marked as live.
4. The collector iterates through the fields of object `A`.
5. It encounters the pointer to object `B`.
6. The collector checks if object `B` has already been marked.
7. If `B` is not marked, it is marked as live and added to the marking worklist (a queue of objects to visit).

**Output:**
* Object `A` is marked as live.
* Object `B` is marked as live.
* Object `B` is added to the marking worklist for further processing (to mark objects reachable from `B`).

**Common Programming Errors Related to Garbage Collection (and thus implicitly related to this code):**

While developers don't directly interact with this C++ code, their JavaScript code can create situations that affect the garbage collector's behavior. Common errors include:

1. **Memory Leaks (Unintentional Object Retention):**
   ```javascript
   let detachedElement;

   function createAndDetach() {
     let element = document.createElement('div');
     detachedElement = element; // Accidentally holding a reference
     document.body.appendChild(element);
     document.body.removeChild(element); // Detached from the DOM
   }

   createAndDetach();
   // detachedElement still holds a reference to the detached DOM element,
   // preventing it from being garbage collected.
   ```
   **Explanation:**  The `detachedElement` variable keeps a reference to the DOM element even after it's removed from the document. The garbage collector won't reclaim this memory as the object is still reachable.

2. **Performance Issues due to Excessive Object Creation:**
   ```javascript
   function processData(data) {
     for (let i = 0; i < data.length; i++) {
       let tempObject = { value: data[i] }; // Creating many short-lived objects
       // ... some processing with tempObject ...
     }
   }
   ```
   **Explanation:**  Creating a large number of temporary objects can put pressure on the garbage collector, leading to more frequent or longer GC pauses, impacting performance.

3. **Misunderstanding Weak References:**
   ```javascript
   let myWeakMap = new WeakMap();
   let key = {};
   myWeakMap.set(key, "some value");
   // ... later ...
   // If 'key' is no longer referenced elsewhere, the entry in myWeakMap
   // will be automatically removed by the garbage collector.
   ```
   **Explanation:**  Developers might misunderstand when objects in `WeakMap` or referenced by `WeakRef` become eligible for garbage collection, leading to unexpected behavior if they assume the object will always be present.

In summary, `v8/src/heap/mark-compact.h` is a crucial C++ header file in V8 that defines the core logic for the mark-compact garbage collector, enabling JavaScript's automatic memory management. While JavaScript developers don't directly interact with this code, understanding the principles of garbage collection helps them write more efficient and less memory-intensive JavaScript applications.

### 提示词
```
这是目录为v8/src/heap/mark-compact.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/mark-compact.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_HEAP_MARK_COMPACT_H_
#define V8_HEAP_MARK_COMPACT_H_

#include <vector>

#include "include/v8-internal.h"
#include "src/common/globals.h"
#include "src/heap/marking-state.h"
#include "src/heap/marking-visitor.h"
#include "src/heap/marking-worklist.h"
#include "src/heap/marking.h"
#include "src/heap/memory-measurement.h"
#include "src/heap/spaces.h"
#include "src/heap/sweeper.h"

namespace v8 {
namespace internal {

// Forward declarations.
class HeapObjectVisitor;
class LargeObjectSpace;
class LargePageMetadata;
class MainMarkingVisitor;
class MarkCompactCollector;
class RecordMigratedSlotVisitor;

class RootMarkingVisitor final : public RootVisitor {
 public:
  explicit RootMarkingVisitor(MarkCompactCollector* collector);
  ~RootMarkingVisitor();

  V8_INLINE void VisitRootPointer(Root root, const char* description,
                                  FullObjectSlot p) final;

  V8_INLINE void VisitRootPointers(Root root, const char* description,
                                   FullObjectSlot start,
                                   FullObjectSlot end) final;

  // Keep this synced with `RootsReferencesExtractor::VisitRunningCode()`.
  void VisitRunningCode(FullObjectSlot code_slot,
                        FullObjectSlot istream_or_smi_zero_slot) final;

  RootMarkingVisitor(const RootMarkingVisitor&) = delete;
  RootMarkingVisitor& operator=(const RootMarkingVisitor&) = delete;

 private:
  V8_INLINE void MarkObjectByPointer(Root root, FullObjectSlot p);

  MarkCompactCollector* const collector_;
};

// Collector for young and old generation.
class MarkCompactCollector final {
 public:
  class CustomRootBodyMarkingVisitor;
  class SharedHeapObjectVisitor;

  enum class StartCompactionMode {
    kIncremental,
    kAtomic,
  };

  enum class MarkingWorklistProcessingMode {
    kDefault,
    kTrackNewlyDiscoveredObjects
  };

  enum class CallOrigin {
    kIncrementalMarkingStep,
    kAtomicGC,
  };

  // Callback function for telling whether the object *p is an unmarked
  // heap object.
  static bool IsUnmarkedHeapObject(Heap* heap, FullObjectSlot p);
  static bool IsUnmarkedSharedHeapObject(Heap* heap, FullObjectSlot p);

  std::pair<size_t, size_t> ProcessMarkingWorklist(
      v8::base::TimeDelta max_duration, size_t max_bytes_to_process,
      MarkingWorklistProcessingMode mode);

  void TearDown();

  // Performs a global garbage collection.
  void CollectGarbage();

  void CollectEvacuationCandidates(PagedSpace* space);

  void AddEvacuationCandidate(PageMetadata* p);

  // Prepares for GC by resetting relocation info in old and map spaces and
  // choosing spaces to compact.
  void Prepare();

  // Stop concurrent marking (either by preempting it right away or waiting for
  // it to complete as requested by |stop_request|).
  void FinishConcurrentMarking();

  // Returns whether compaction is running.
  bool StartCompaction(StartCompactionMode mode);

  void StartMarking();

  static inline bool IsOnEvacuationCandidate(Tagged<MaybeObject> obj) {
    return MemoryChunk::FromAddress(obj.ptr())->IsEvacuationCandidate();
  }

  struct RecordRelocSlotInfo {
    MutablePageMetadata* page_metadata;
    SlotType slot_type;
    uint32_t offset;
  };

  static bool ShouldRecordRelocSlot(Tagged<InstructionStream> host,
                                    RelocInfo* rinfo,
                                    Tagged<HeapObject> target);
  static RecordRelocSlotInfo ProcessRelocInfo(Tagged<InstructionStream> host,
                                              RelocInfo* rinfo,
                                              Tagged<HeapObject> target);

  static void RecordRelocSlot(Tagged<InstructionStream> host, RelocInfo* rinfo,
                              Tagged<HeapObject> target);
  template <typename THeapObjectSlot>
  V8_INLINE static void RecordSlot(Tagged<HeapObject> object,
                                   THeapObjectSlot slot,
                                   Tagged<HeapObject> target);
  template <typename THeapObjectSlot>
  V8_INLINE static void RecordSlot(MemoryChunk* source_chunk,
                                   THeapObjectSlot slot,
                                   Tagged<HeapObject> target);

  bool is_compacting() const { return compacting_; }

  V8_INLINE void AddTransitionArray(Tagged<TransitionArray> array);

  void RecordStrongDescriptorArraysForWeakening(
      GlobalHandleVector<DescriptorArray> strong_descriptor_arrays);

#ifdef DEBUG
  // Checks whether performing mark-compact collection.
  bool in_use() { return state_ > PREPARE_GC; }
  bool are_map_pointers_encoded() { return state_ == UPDATE_POINTERS; }
#endif

  void VerifyMarking();
#ifdef VERIFY_HEAP
  void VerifyMarkbitsAreClean();
  void VerifyMarkbitsAreClean(PagedSpaceBase* space);
  void VerifyMarkbitsAreClean(NewSpace* space);
  void VerifyMarkbitsAreClean(LargeObjectSpace* space);
#endif

  unsigned epoch() const { return epoch_; }

  base::EnumSet<CodeFlushMode> code_flush_mode() const {
    return code_flush_mode_;
  }

  MarkingWorklists* marking_worklists() { return &marking_worklists_; }

  MarkingWorklists::Local* local_marking_worklists() const {
    return local_marking_worklists_.get();
  }

  WeakObjects* weak_objects() { return &weak_objects_; }
  WeakObjects::Local* local_weak_objects() { return local_weak_objects_.get(); }

  void AddNewlyDiscovered(Tagged<HeapObject> object) {
    if (ephemeron_marking_.newly_discovered_overflowed) return;

    if (ephemeron_marking_.newly_discovered.size() <
        ephemeron_marking_.newly_discovered_limit) {
      ephemeron_marking_.newly_discovered.push_back(object);
    } else {
      ephemeron_marking_.newly_discovered_overflowed = true;
    }
  }

  void ResetNewlyDiscovered() {
    ephemeron_marking_.newly_discovered_overflowed = false;
    ephemeron_marking_.newly_discovered.clear();
  }

  bool UseBackgroundThreadsInCycle() const {
    return use_background_threads_in_cycle_;
  }

  void MaybeEnableBackgroundThreadsInCycle(CallOrigin origin);

  Heap* heap() { return heap_; }

  explicit MarkCompactCollector(Heap* heap);
  ~MarkCompactCollector();

 private:
  using ResizeNewSpaceMode = Heap::ResizeNewSpaceMode;

  void ComputeEvacuationHeuristics(size_t area_size,
                                   int* target_fragmentation_percent,
                                   size_t* max_evacuated_bytes);

  void RecordObjectStats();

  // Finishes GC, performs heap verification if enabled.
  void Finish();

  // Free unmarked ArrayBufferExtensions.
  void SweepArrayBufferExtensions();

  void MarkLiveObjects();

  // Marks the object and adds it to the worklist.
  V8_INLINE void MarkObject(Tagged<HeapObject> host, Tagged<HeapObject> obj,
                            MarkingHelper::WorklistTarget target_worklist);

  // Marks the root object and adds it to the worklist.
  V8_INLINE void MarkRootObject(Root root, Tagged<HeapObject> obj,
                                MarkingHelper::WorklistTarget target_worklist);

  // Mark the heap roots and all objects reachable from them.
  void MarkRoots(RootVisitor* root_visitor);

  // Mark the stack roots and all objects reachable from them.
  void MarkRootsFromConservativeStack(RootVisitor* root_visitor);

  // Mark all objects that are directly referenced from one of the clients
  // heaps.
  void MarkObjectsFromClientHeaps();
  void MarkObjectsFromClientHeap(Isolate* client);

  // Updates pointers to shared objects from client heaps.
  void UpdatePointersInClientHeaps();
  void UpdatePointersInClientHeap(Isolate* client);

  // Update pointers in sandbox-related pointer tables.
  void UpdatePointersInPointerTables();

  // Marks object reachable from harmony weak maps and wrapper tracing.
  void MarkTransitiveClosure();
  void VerifyEphemeronMarking();

  // If the call-site of the top optimized code was not prepared for
  // deoptimization, then treat embedded pointers in the code as strong as
  // otherwise they can die and try to deoptimize the underlying code.
  void ProcessTopOptimizedFrame(ObjectVisitor* visitor, Isolate* isolate);

  // Implements ephemeron semantics: Marks value if key is already reachable.
  // Returns true if value was actually marked.
  bool ProcessEphemeron(Tagged<HeapObject> key, Tagged<HeapObject> value);

  // Marks the transitive closure by draining the marking worklist iteratively,
  // applying ephemerons semantics and invoking embedder tracing until a
  // fixpoint is reached. Returns false if too many iterations have been tried
  // and the linear approach should be used.
  bool MarkTransitiveClosureUntilFixpoint();

  // Marks the transitive closure applying ephemeron semantics and invoking
  // embedder tracing with a linear algorithm for ephemerons. Only used if
  // fixpoint iteration doesn't finish within a few iterations.
  void MarkTransitiveClosureLinear();

  // Drains ephemeron and marking worklists. Single iteration of the
  // fixpoint iteration.
  bool ProcessEphemerons();

  // Perform Wrapper Tracing if in use.
  void PerformWrapperTracing();

  // Retain dying maps for `v8_flags.retain_maps_for_n_gc` garbage collections
  // to increase chances of reusing of map transition tree in future.
  void RetainMaps();

  // Clear non-live references in weak cells, transition and descriptor arrays,
  // and deoptimize dependent code of non-live maps.
  void ClearNonLiveReferences();
  void MarkDependentCodeForDeoptimization();

  // Special handling for clearing map slots.
  // Returns true if the slot was cleared.
  bool SpecialClearMapSlot(Tagged<HeapObject> host, Tagged<Map> dead_target,
                           HeapObjectSlot slot);

  // Checks if the given weak cell is a simple transition from the parent map
  // of the given dead target. If so it clears the transition and trims
  // the descriptor array of the parent if needed.
  void ClearPotentialSimpleMapTransition(Tagged<Map> dead_target);
  void ClearPotentialSimpleMapTransition(Tagged<Map> map,
                                         Tagged<Map> dead_target);

  // Flushes a weakly held bytecode array from a shared function info.
  void FlushBytecodeFromSFI(Tagged<SharedFunctionInfo> shared_info);

  // Clears bytecode arrays / baseline code that have not been executed for
  // multiple collections.
  void ProcessOldCodeCandidates();

  bool ProcessOldBytecodeSFI(Tagged<SharedFunctionInfo> flushing_candidate);
  bool ProcessOldBaselineSFI(Tagged<SharedFunctionInfo> flushing_candidate);
  void FlushSFI(Tagged<SharedFunctionInfo> sfi,
                bool bytecode_already_decompiled);

#ifndef V8_ENABLE_LEAPTIERING
  void ProcessFlushedBaselineCandidates();
#endif  // !V8_ENABLE_LEAPTIERING

  // Resets any JSFunctions which have had their bytecode flushed.
  void ClearFlushedJsFunctions();

  // Compact every array in the global list of transition arrays and
  // trim the corresponding descriptor array if a transition target is non-live.
  void ClearFullMapTransitions();
  void TrimDescriptorArray(Tagged<Map> map,
                           Tagged<DescriptorArray> descriptors);
  void TrimEnumCache(Tagged<Map> map, Tagged<DescriptorArray> descriptors);
  bool CompactTransitionArray(Tagged<Map> map,
                              Tagged<TransitionArray> transitions,
                              Tagged<DescriptorArray> descriptors);
  bool TransitionArrayNeedsCompaction(Tagged<TransitionArray> transitions,
                                      int num_transitions);
  void WeakenStrongDescriptorArrays();

  // After all reachable objects have been marked those weak map entries
  // with an unreachable key are removed from all encountered weak maps.
  // The linked list of all encountered weak maps is destroyed.
  void ClearWeakCollections();

  // Goes through the list of encountered trivial weak references and clears
  // those with dead values. This is performed in a parallel job. In short, a
  // weak reference is considered trivial if its value does not require special
  // weakness clearing.
  void ClearTrivialWeakReferences();
  class ClearTrivialWeakRefJobItem;

  // Goes through the list of encountered non-trivial weak references and
  // filters out those whose values are still alive. This is performed in a
  // parallel job.
  void FilterNonTrivialWeakReferences();
  class FilterNonTrivialWeakRefJobItem;

  // Goes through the list of encountered non-trivial weak references with
  // dead values. If the value is a dead map and the parent map transitions to
  // the dead map via weak cell, then this function also clears the map
  // transition.
  void ClearNonTrivialWeakReferences();

  // Goes through the list of encountered JSWeakRefs and WeakCells and clears
  // those with dead values.
  void ClearJSWeakRefs();

  // Starts sweeping of spaces by contributing on the main thread and setting
  // up other pages for sweeping. Does not start sweeper tasks.
  void Sweep();
  void StartSweepSpace(PagedSpace* space);

  void EvacuatePrologue();
  void EvacuateEpilogue();
  void Evacuate();
  void EvacuatePagesInParallel();
  void UpdatePointersAfterEvacuation();

  void ReleaseEvacuationCandidates();
  // Returns number of aborted pages.
  size_t PostProcessAbortedEvacuationCandidates();
  void ReportAbortedEvacuationCandidateDueToOOM(Address failed_start,
                                                PageMetadata* page);
  void ReportAbortedEvacuationCandidateDueToFlags(Address failed_start,
                                                  PageMetadata* page);

  static const int kEphemeronChunkSize = 8 * KB;

  int NumberOfParallelEphemeronVisitingTasks(size_t elements);

  void RightTrimDescriptorArray(Tagged<DescriptorArray> array,
                                int descriptors_to_trim);

  void StartSweepNewSpace();
  void SweepLargeSpace(LargeObjectSpace* space);

  void ResetAndRelinkBlackAllocatedPage(PagedSpace*, PageMetadata*);

  Heap* const heap_;

  base::Mutex mutex_;
  base::Semaphore page_parallel_job_semaphore_{0};

#ifdef DEBUG
  enum CollectorState{IDLE,
                      PREPARE_GC,
                      MARK_LIVE_OBJECTS,
                      SWEEP_SPACES,
                      ENCODE_FORWARDING_ADDRESSES,
                      UPDATE_POINTERS,
                      RELOCATE_OBJECTS};

  // The current stage of the collector.
  CollectorState state_;
#endif

  const bool uses_shared_heap_;
  const bool is_shared_space_isolate_;

  // True if we are collecting slots to perform evacuation from evacuation
  // candidates.
  bool compacting_ = false;
  bool black_allocation_ = false;
  bool have_code_to_deoptimize_ = false;
  bool parallel_marking_ = false;

  MarkingWorklists marking_worklists_;
  std::unique_ptr<MarkingWorklists::Local> local_marking_worklists_;

  WeakObjects weak_objects_;
  EphemeronMarking ephemeron_marking_;

  std::unique_ptr<MainMarkingVisitor> marking_visitor_;
  std::unique_ptr<WeakObjects::Local> local_weak_objects_;
  NativeContextInferrer native_context_inferrer_;
  NativeContextStats native_context_stats_;

  std::vector<GlobalHandleVector<DescriptorArray>> strong_descriptor_arrays_;
  base::Mutex strong_descriptor_arrays_mutex_;

  // Candidates for pages that should be evacuated.
  std::vector<PageMetadata*> evacuation_candidates_;
  // Pages that are actually processed during evacuation.
  std::vector<PageMetadata*> old_space_evacuation_pages_;
  std::vector<PageMetadata*> new_space_evacuation_pages_;
  std::vector<std::pair<Address, PageMetadata*>>
      aborted_evacuation_candidates_due_to_oom_;
  std::vector<std::pair<Address, PageMetadata*>>
      aborted_evacuation_candidates_due_to_flags_;
  std::vector<LargePageMetadata*> promoted_large_pages_;

  MarkingState* const marking_state_;
  NonAtomicMarkingState* const non_atomic_marking_state_;
  Sweeper* const sweeper_;

  // Counts the number of major mark-compact collections. The counter is
  // incremented right after marking. This is used for:
  // - marking descriptor arrays. See NumberOfMarkedDescriptors. Only the lower
  //   two bits are used, so it is okay if this counter overflows and wraps
  //   around.
  unsigned epoch_ = 0;

  ResizeNewSpaceMode resize_new_space_ = ResizeNewSpaceMode::kNone;

  // Bytecode flushing is disabled when the code coverage mode is changed. Since
  // that can happen while a GC is happening and we need the
  // code_flush_mode_ to remain the same through out a GC, we record this at
  // the start of each GC.
  base::EnumSet<CodeFlushMode> code_flush_mode_;

  std::vector<PageMetadata*> empty_new_space_pages_to_be_swept_;

  bool use_background_threads_in_cycle_ = false;

  friend class Evacuator;
  friend class RecordMigratedSlotVisitor;
  friend class RootMarkingVisitor;
};

}  // namespace internal
}  // namespace v8

#endif  // V8_HEAP_MARK_COMPACT_H_
```