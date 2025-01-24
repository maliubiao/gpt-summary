Response:
The user wants to understand the functionality of the provided C++ header file `v8/src/heap/marking-visitor-inl.h`. They are also asking for specific information related to its potential nature as a Torque file, its relation to JavaScript, code logic inference, common programming errors, and a summary of its functions.

Here's a breakdown of the thought process to answer the request:

1. **Identify the core purpose:** The filename and content clearly indicate that this file is related to the *marking phase* of garbage collection in V8. It's an "inline" header file, suggesting it contains the implementations of methods declared in a corresponding `.h` file. The presence of `MarkingVisitorBase` confirms this.

2. **Analyze the includes:** The included headers provide crucial context:
    * `src/common/globals.h`:  Fundamental V8 global definitions.
    * `src/heap/*`:  Various heap management components like remembered sets, layout, visitors, progress tracking, marking state, worklists, and the main `marking.h`.
    * `src/objects/*`: Definitions of V8's object model (HeapObject, JSObject, String, etc.) and related concepts like slots and descriptors.
    * `src/sandbox/*`: Components related to sandboxing and isolation.
    * `src/objects/object-macros.h`: Macros for defining object structures.

3. **Examine the class structure:** The core of the file is the `MarkingVisitorBase` template class. This implies a Visitor pattern, where different concrete visitor classes (represented by the `ConcreteVisitor` template parameter) can use the base class's functionality.

4. **Deconstruct key methods:** Analyze the purpose of the prominent methods:
    * `MarkObject`: Marks an object as live during garbage collection and adds it to a worklist for further processing.
    * `ProcessStrongHeapObject`: Handles strong references to heap objects. It checks if the object needs marking and then marks it. It also includes a debugging check for invalid object states.
    * `ProcessWeakHeapObject`: Handles weak references. It distinguishes between trivial and non-trivial weak references, putting them on different worklists for optimized processing.
    * `VisitPointersImpl`, `VisitStrongPointerImpl`: Iterate through object slots and process the referenced objects.
    * `VisitEmbeddedPointer`, `VisitCodeTarget`: Handle pointers embedded within code objects.
    * `VisitExternalPointer`, `VisitCppHeapPointer`, `VisitIndirectPointer`: Deal with pointers to external memory, C++ heap objects, and indirectly referenced objects (used in sandboxing).
    * `VisitJSDispatchTableEntry`: Manages entries in the JavaScript dispatch table (related to leap-tiering optimization).
    * `VisitJSFunction`, `VisitSharedFunctionInfo`: Implement logic for handling JavaScript functions and their shared information, particularly related to bytecode and baseline code flushing (optimizations to reduce memory usage).
    * `VisitFixedArrayWithProgressTracker`, `VisitFixedArray`:  Handle marking of fixed-size arrays, potentially with incremental processing.
    * `VisitJSArrayBuffer`: Marks the external memory associated with `JSArrayBuffer` objects.
    * `VisitEphemeronHashTable`, `VisitJSWeakRef`, `VisitWeakCell`: Handle weak data structures like WeakMaps, WeakSets, and WeakRefs.
    * `VisitDescriptorArray`, `VisitDescriptorArrayStrongly`: Manage marking of descriptor arrays, which contain information about object properties.

5. **Address specific questions:**
    * **Torque:** The filename ends with `.h`, not `.tq`. Thus, it's a regular C++ header file, not a Torque source file.
    * **JavaScript relationship:**  Many methods directly interact with JavaScript concepts like `JSFunction`, `SharedFunctionInfo`, `JSWeakRef`, etc. The code flushing mechanisms are directly tied to JavaScript performance and memory management.
    * **Code logic inference:** The `MarkObject` function and the `ShouldMarkObject` check form the core marking logic. If an object is reachable and not already marked, it gets marked and added to a worklist. Weak references are handled differently, with checks for liveness.
    * **Common programming errors:**  The debugging assertion in `ProcessStrongHeapObject` suggests a potential error where a marked object points to free space. This can happen due to memory corruption or incorrect object lifecycle management.
    * **Functionality summary:** Condense the detailed analysis into a concise description of the file's role in the marking phase of garbage collection, emphasizing the different types of object references and the optimizations like code flushing.

6. **Structure the answer:**  Organize the findings into clear sections addressing each part of the user's request. Use bullet points and code formatting to improve readability. Provide a clear "Conclusion" to summarize the overall functionality.
```cpp
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_HEAP_MARKING_VISITOR_INL_H_
#define V8_HEAP_MARKING_VISITOR_INL_H_

#include "src/common/globals.h"
#include "src/heap/ephemeron-remembered-set.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/heap-visitor-inl.h"
#include "src/heap/heap-visitor.h"
#include "src/heap/marking-progress-tracker.h"
#include "src/heap/marking-state-inl.h"
#include "src/heap/marking-visitor.h"
#include "src/heap/marking-worklist-inl.h"
#include "src/heap/marking.h"
#include "src/heap/pretenuring-handler-inl.h"
#include "src/heap/spaces.h"
#include "src/objects/compressed-slots.h"
#include "src/objects/descriptor-array.h"
#include "src/objects/heap-object.h"
#include "src/objects/js-objects.h"
#include "src/objects/objects.h"
#include "src/objects/property-details.h"
#include "src/objects/slots.h"
#include "src/objects/smi.h"
#include "src/objects/string.h"
#include "src/sandbox/external-pointer-inl.h"
#include "src/sandbox/indirect-pointer-tag.h"
#include "src/sandbox/js-dispatch-table-inl.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8 {
namespace internal {

// ===========================================================================
// Visiting strong and weak pointers =========================================
// ===========================================================================

template <typename ConcreteVisitor>
bool MarkingVisitorBase<ConcreteVisitor>::MarkObject(
    Tagged<HeapObject> retainer, Tagged<HeapObject> object,
    MarkingHelper::WorklistTarget target_worklist) {
  DCHECK(heap_->Contains(object));
  SynchronizePageAccess(object);
  concrete_visitor()->AddStrongReferenceForReferenceSummarizer(retainer,
                                                               object);
  return MarkingHelper::TryMarkAndPush(heap_, local_marking_worklists_,
                                       concrete_visitor()->marking_state(),
                                       target_worklist, object);
}

// class template arguments
template <typename ConcreteVisitor>
// method template arguments
template <typename THeapObjectSlot>
void MarkingVisitorBase<ConcreteVisitor>::ProcessStrongHeapObject(
    Tagged<HeapObject> host, THeapObjectSlot slot,
    Tagged<HeapObject> heap_object) {
  SynchronizePageAccess(heap_object);
  const auto target_worklist =
      MarkingHelper::ShouldMarkObject(heap_, heap_object);
  if (!target_worklist) {
    return;
  }
  // TODO(chromium:1495151): Remove after diagnosing.
  if (V8_UNLIKELY(!MemoryChunk::FromHeapObject(heap_object)->IsMarking() &&
                  IsFreeSpaceOrFiller(
                      heap_object, ObjectVisitorWithCageBases::cage_base()))) {
    heap_->isolate()->PushStackTraceAndDie(
        reinterpret_cast<void*>(host->map().ptr()),
        reinterpret_cast<void*>(host->address()),
        reinterpret_cast<void*>(slot.address()),
        reinterpret_cast<void*>(MemoryChunkMetadata::FromHeapObject(heap_object)
                                    ->owner()
                                    ->identity()));
  }
  MarkObject(host, heap_object, target_worklist.value());
  concrete_visitor()->RecordSlot(host, slot, heap_object);
}

// static
template <typename ConcreteVisitor>
V8_INLINE constexpr bool
MarkingVisitorBase<ConcreteVisitor>::IsTrivialWeakReferenceValue(
    Tagged<HeapObject> host, Tagged<HeapObject> heap_object) {
  return !IsMap(heap_object) ||
         !(IsMap(host) || IsTransitionArray(host) || IsDescriptorArray(host));
}

// class template arguments
template <typename ConcreteVisitor>
// method template arguments
template <typename THeapObjectSlot>
void MarkingVisitorBase<ConcreteVisitor>::ProcessWeakHeapObject(
    Tagged<HeapObject> host, THeapObjectSlot slot,
    Tagged<HeapObject> heap_object) {
  SynchronizePageAccess(heap_object);
  concrete_visitor()->AddWeakReferenceForReferenceSummarizer(host, heap_object);
  const auto target_worklist =
      MarkingHelper::ShouldMarkObject(heap_, heap_object);
  if (!target_worklist) {
    return;
  }
  if (concrete_visitor()->marking_state()->IsMarked(heap_object)) {
    // Weak references with live values are directly processed here to
    // reduce the processing time of weak cells during the main GC
    // pause.
    concrete_visitor()->RecordSlot(host, slot, heap_object);
  } else {
    // If we do not know about liveness of the value, we have to process
    // the reference when we know the liveness of the whole transitive
    // closure.
    // Distinguish trivial cases (non involving custom weakness) from
    // non-trivial ones. The latter are maps in host objects of type Map,
    // TransitionArray and DescriptorArray.
    if (V8_LIKELY(IsTrivialWeakReferenceValue(host, heap_object))) {
      local_weak_objects_->weak_references_trivial_local.Push(
          HeapObjectAndSlot{host, slot});
    } else {
      local_weak_objects_->weak_references_non_trivial_local.Push(
          HeapObjectAndSlot{host, slot});
    }
  }
}

// class template arguments
template <typename ConcreteVisitor>
// method template arguments
template <typename TSlot>
void MarkingVisitorBase<ConcreteVisitor>::VisitPointersImpl(
    Tagged<HeapObject> host, TSlot start, TSlot end) {
  using THeapObjectSlot = typename TSlot::THeapObjectSlot;
  for (TSlot slot = start; slot < end; ++slot) {
    const std::optional<Tagged<Object>> optional_object =
        this->GetObjectFilterReadOnlyAndSmiFast(slot);
    if (!optional_object) {
      continue;
    }
    typename TSlot::TObject object = *optional_object;
    Tagged<HeapObject> heap_object;
    if (object.GetHeapObjectIfStrong(&heap_object)) {
      // If the reference changes concurrently from strong to weak, the write
      // barrier will treat the weak reference as strong, so we won't miss the
      // weak reference.
      ProcessStrongHeapObject(host, THeapObjectSlot(slot), heap_object);
    } else if (TSlot::kCanBeWeak && object.GetHeapObjectIfWeak(&heap_object)) {
      ProcessWeakHeapObject(host, THeapObjectSlot(slot), heap_object);
    }
  }
}

// class template arguments
template <typename ConcreteVisitor>
// method template arguments
template <typename TSlot>
void MarkingVisitorBase<ConcreteVisitor>::VisitStrongPointerImpl(
    Tagged<HeapObject> host, TSlot slot) {
  static_assert(!TSlot::kCanBeWeak);
  using THeapObjectSlot = typename TSlot::THeapObjectSlot;
  typename TSlot::TObject object = slot.Relaxed_Load();
  Tagged<HeapObject> heap_object;
  if (object.GetHeapObject(&heap_object)) {
    ProcessStrongHeapObject(host, THeapObjectSlot(slot), heap_object);
  }
}

template <typename ConcreteVisitor>
void MarkingVisitorBase<ConcreteVisitor>::VisitEmbeddedPointer(
    Tagged<InstructionStream> host, RelocInfo* rinfo) {
  DCHECK(RelocInfo::IsEmbeddedObjectMode(rinfo->rmode()));
  Tagged<HeapObject> object =
      rinfo->target_object(ObjectVisitorWithCageBases::cage_base());
  const auto target_worklist = MarkingHelper::ShouldMarkObject(heap_, object);
  if (!target_worklist) {
    return;
  }

  if (!concrete_visitor()->marking_state()->IsMarked(object)) {
    Tagged<Code> code = UncheckedCast<Code>(host->raw_code(kAcquireLoad));
    if (code->IsWeakObject(object)) {
      local_weak_objects_->weak_objects_in_code_local.Push(
          HeapObjectAndCode{object, code});
      concrete_visitor()->AddWeakReferenceForReferenceSummarizer(host, object);
    } else {
      MarkObject(host, object, target_worklist.value());
    }
  }
  concrete_visitor()->RecordRelocSlot(host, rinfo, object);
}

template <typename ConcreteVisitor>
void MarkingVisitorBase<ConcreteVisitor>::VisitCodeTarget(
    Tagged<InstructionStream> host, RelocInfo* rinfo) {
  DCHECK(RelocInfo::IsCodeTargetMode(rinfo->rmode()));
  Tagged<InstructionStream> target =
      InstructionStream::FromTargetAddress(rinfo->target_address());

  const auto target_worklist = MarkingHelper::ShouldMarkObject(heap_, target);
  if (!target_worklist) {
    return;
  }
  MarkObject(host, target, target_worklist.value());
  concrete_visitor()->RecordRelocSlot(host, rinfo, target);
}

template <typename ConcreteVisitor>
void MarkingVisitorBase<ConcreteVisitor>::VisitExternalPointer(
    Tagged<HeapObject> host, ExternalPointerSlot slot) {
#ifdef V8_COMPRESS_POINTERS
  DCHECK_NE(slot.tag(), kExternalPointerNullTag);
  if (slot.HasExternalPointerHandle()) {
    ExternalPointerHandle handle = slot.Relaxed_LoadHandle();
    ExternalPointerTable* table;
    ExternalPointerTable::Space* space;
    if (IsSharedExternalPointerType(slot.tag())) {
      table = shared_external_pointer_table_;
      space = shared_external_pointer_space_;
    } else {
      table = external_pointer_table_;
      if (v8_flags.sticky_mark_bits) {
        // Everything is considered old during major GC.
        DCHECK(!HeapLayout::InYoungGeneration(host));
        if (handle == kNullExternalPointerHandle) return;
        // The object may either be in young or old EPT.
        if (table->Contains(heap_->young_external_pointer_space(), handle)) {
          space = heap_->young_external_pointer_space();
        } else {
          DCHECK(table->Contains(heap_->old_external_pointer_space(), handle));
          space = heap_->old_external_pointer_space();
        }
      } else {
        space = HeapLayout::InYoungGeneration(host)
                    ? heap_->young_external_pointer_space()
                    : heap_->old_external_pointer_space();
      }
    }
    table->Mark(space, handle, slot.address());
  }
#endif  // V8_COMPRESS_POINTERS
}

template <typename ConcreteVisitor>
void MarkingVisitorBase<ConcreteVisitor>::VisitCppHeapPointer(
    Tagged<HeapObject> host, CppHeapPointerSlot slot) {
#ifdef V8_COMPRESS_POINTERS
  const ExternalPointerHandle handle = slot.Relaxed_LoadHandle();
  if (handle == kNullExternalPointerHandle) {
    return;
  }
  CppHeapPointerTable* table = cpp_heap_pointer_table_;
  CppHeapPointerTable::Space* space = heap_->cpp_heap_pointer_space();
  table->Mark(space, handle, slot.address());
#endif  // V8_COMPRESS_POINTERS
  if (auto cpp_heap_pointer =
          slot.try_load(heap_->isolate(), kAnyCppHeapPointer)) {
    local_marking_worklists_->cpp_marking_state()->MarkAndPush(
        reinterpret_cast<void*>(cpp_heap_pointer));
  }
}

template <typename ConcreteVisitor>
void MarkingVisitorBase<ConcreteVisitor>::VisitIndirectPointer(
    Tagged<HeapObject> host, IndirectPointerSlot slot,
    IndirectPointerMode mode) {
#ifdef V8_ENABLE_SANDBOX
  if (mode == IndirectPointerMode::kStrong) {
    // Load the referenced object (if the slot is initialized) and mark it as
    // alive if necessary. Indirect pointers never have to be added to a
    // remembered set because the referenced object will update the pointer
    // table entry when it is relocated.
    Tagged<Object> value = slot.Relaxed_Load(heap_->isolate());
    if (IsHeapObject(value)) {
      Tagged<HeapObject> obj = Cast<HeapObject>(value);
      SynchronizePageAccess(obj);
      const auto target_worklist = MarkingHelper::ShouldMarkObject(heap_, obj);
      if (!target_worklist) {
        return;
      }
      MarkObject(host, obj, target_worklist.value());
    }
  }
#else
  UNREACHABLE();
#endif
}

template <typename ConcreteVisitor>
void MarkingVisitorBase<ConcreteVisitor>::VisitTrustedPointerTableEntry(
    Tagged<HeapObject> host, IndirectPointerSlot slot) {
  concrete_visitor()->MarkPointerTableEntry(host, slot);
}

template <typename ConcreteVisitor>
void MarkingVisitorBase<ConcreteVisitor>::VisitJSDispatchTableEntry(
    Tagged<HeapObject> host, JSDispatchHandle handle) {
#ifdef V8_ENABLE_LEAPTIERING
  JSDispatchTable* table = GetProcessWideJSDispatchTable();
#ifdef DEBUG
  JSDispatchTable::Space* space = heap_->js_dispatch_table_space();
  JSDispatchTable::Space* ro_space =
      heap_->isolate()->read_only_heap()->js_dispatch_table_space();
  table->VerifyEntry(handle, space, ro_space);
#endif  // DEBUG

  table->Mark(handle);

  // The code objects referenced from a dispatch table entry are treated as weak
  // references for the purpose of bytecode/baseline flushing, so they are not
  // marked here. See also VisitJSFunction below.
#endif  // V8_ENABLE_LEAPTIERING
}

// ===========================================================================
// Object participating in bytecode flushing =================================
// ===========================================================================

template <typename ConcreteVisitor>
size_t MarkingVisitorBase<ConcreteVisitor>::VisitJSFunction(
    Tagged<Map> map, Tagged<JSFunction> js_function,
    MaybeObjectSize maybe_object_size) {
  if (ShouldFlushBaselineCode(js_function)) {
    DCHECK(IsBaselineCodeFlushingEnabled(code_flush_mode_));
#ifndef V8_ENABLE_LEAPTIERING
    local_weak_objects_->baseline_flushing_candidates_local.Push(js_function);
#endif  // !V8_ENABLE_LEAPTIERING
    return Base::VisitJSFunction(map, js_function, maybe_object_size);
  }

  // We're not flushing the Code, so mark it as alive.
#ifdef V8_ENABLE_LEAPTIERING
  // Here we can see JSFunctions that aren't fully initialized (e.g. during
  // deserialization) so we need to check for the null handle.
  JSDispatchHandle handle = js_function->Relaxed_ReadField<JSDispatchHandle>(
      JSFunction::kDispatchHandleOffset);
  if (handle != kNullJSDispatchHandle) {
    Tagged<HeapObject> obj = GetProcessWideJSDispatchTable()->GetCode(handle);
    // TODO(saelo): maybe factor out common code with VisitIndirectPointer
    // into a helper routine?
    SynchronizePageAccess(obj);
    const auto target_worklist = MarkingHelper::ShouldMarkObject(heap_, obj);
    if (target_worklist) {
      MarkObject(js_function, obj, target_worklist.value());
    }
  }
#else

#ifdef V8_ENABLE_SANDBOX
  VisitIndirectPointer(js_function,
                       js_function->RawIndirectPointerField(
                           JSFunction::kCodeOffset, kCodeIndirectPointerTag),
                       IndirectPointerMode::kStrong);
#else
  VisitPointer(js_function, js_function->RawField(JSFunction::kCodeOffset));
#endif  // V8_ENABLE_SANDBOX

#endif  // V8_ENABLE_LEAPTIERING

  // TODO(mythria): Consider updating the check for ShouldFlushBaselineCode to
  // also include cases where there is old bytecode even when there is no
  // baseline code and remove this check here.
  if (IsByteCodeFlushingEnabled(code_flush_mode_) &&
      js_function->NeedsResetDueToFlushedBytecode(heap_->isolate())) {
    local_weak_objects_->flushed_js_functions_local.Push(js_function);
  }

  return Base::VisitJSFunction(map, js_function, maybe_object_size);
}

template <typename ConcreteVisitor>
size_t MarkingVisitorBase<ConcreteVisitor>::VisitSharedFunctionInfo(
    Tagged<Map> map, Tagged<SharedFunctionInfo> shared_info,
    MaybeObjectSize maybe_object_size) {
  const bool can_flush_bytecode = HasBytecodeArrayForFlushing(shared_info);

  // We found a BytecodeArray that can be flushed. Increment the age of the SFI.
  if (can_flush_bytecode && !should_keep_ages_unchanged_) {
    MakeOlder(shared_info);
  }

  if (!can_flush_bytecode || !ShouldFlushCode(shared_info)) {
    // If the SharedFunctionInfo doesn't have old bytecode visit the function
    // data strongly.
#ifdef V8_ENABLE_SANDBOX
    VisitIndirectPointer(shared_info,
                         shared_info->RawIndirectPointerField(
                             SharedFunctionInfo::kTrustedFunctionDataOffset,
                             kUnknownIndirectPointerTag),
                         IndirectPointerMode::kStrong);
#else
    VisitPointer(
        shared_info,
        shared_info->RawField(SharedFunctionInfo::kTrustedFunctionDataOffset));
#endif
    VisitPointer(shared_info,
                 shared_info->RawField(
                     SharedFunctionInfo::kUntrustedFunctionDataOffset));
  } else if (!IsByteCodeFlushingEnabled(code_flush_mode_)) {
    // If bytecode flushing is disabled but baseline code flushing is enabled
    // then we have to visit the bytecode but not the baseline code.
    DCHECK(IsBaselineCodeFlushingEnabled(code_flush_mode_));
    Tagged<Code> baseline_code = shared_info->baseline_code(kAcquireLoad);
    // Visit the bytecode hanging off baseline code.
    VisitProtectedPointer(
        baseline_code, baseline_code->RawProtectedPointerField(
                           Code::kDeoptimizationDataOrInterpreterDataOffset));
    local_weak_objects_->code_flushing_candidates_local.Push(shared_info);
  } else {
    // In other cases, record as a flushing candidate since we have old
    // bytecode.
    local_weak_objects_->code_flushing_candidates_local.Push(shared_info);
  }
  return Base::VisitSharedFunctionInfo(map, shared_info, maybe_object_size);
}

template <typename ConcreteVisitor>
bool MarkingVisitorBase<ConcreteVisitor>::HasBytecodeArrayForFlushing(
    Tagged<SharedFunctionInfo> sfi) const {
  if (IsFlushingDisabled(code_flush_mode_)) return false;

  // TODO(rmcilroy): Enable bytecode flushing for resumable functions.
  if (IsResumableFunction(sfi->kind()) || !sfi->allows_lazy_compilation()) {
    return false;
  }

  // Get a snapshot of the function data field, and if it is a bytecode array,
  // check if it is old. Note, this is done this way since this function can be
  // called by the concurrent marker.
  Tagged<Object> data = sfi->GetTrustedData(heap_->isolate());
  if (IsCode(data)) {
    Tagged<Code> baseline_code = Cast<Code>(data);
    DCHECK_EQ(baseline_code->kind(), CodeKind::BASELINE);
    // If baseline code flushing isn't enabled and we have baseline data on SFI
    // we cannot flush baseline / bytecode.
    if (!IsBaselineCodeFlushingEnabled(code_flush_mode_)) return false;
    data = baseline_code->bytecode_or_interpreter_data();
  } else if (!IsByteCodeFlushingEnabled(code_flush_mode_)) {
    // If bytecode flushing isn't enabled and there is no baseline code there is
    // nothing to flush.
    return false;
  }

  return IsBytecodeArray(data);
}

template <typename ConcreteVisitor>
bool MarkingVisitorBase<ConcreteVisitor>::ShouldFlushCode(
    Tagged<SharedFunctionInfo> sfi) const {
  return IsStressFlushingEnabled(code_flush_mode_) || IsOld(sfi);
}

template <typename ConcreteVisitor>
bool MarkingVisitorBase<ConcreteVisitor>::IsOld(
    Tagged<SharedFunctionInfo> sfi) const {
  if (v8_flags.flush_code_based_on_time) {
    return sfi->age() >= v8_flags.bytecode_old_time;
  } else if (v8_flags.flush_code_based_on_tab_visibility) {
    return isolate_in_background_ ||
           V8_UNLIKELY(sfi->age() == SharedFunctionInfo::kMaxAge);
  } else {
    return sfi->age() >= v8_flags.bytecode_old_age;
  }
}

template <typename ConcreteVisitor>
void MarkingVisitorBase<ConcreteVisitor>::MakeOlder(
    Tagged<SharedFunctionInfo> sfi) const {
  if (v8_flags.flush_code_based_on_time) {
    if (code_flushing_increase_ == 0) {
      return;
    }

    uint16_t current_age;
    uint16_t updated_age;
    do {
      current_age = sfi->age();
      // When the age is 0, it was reset by the function prologue in
      // Ignition/Sparkplug. But that might have been some time after the last
      // full GC. So in this case we don't increment the value like we normally
      // would but just set the age to 1. All non-0 values can be incremented as
      // expected (we add the number of seconds since the last GC) as they were
      // definitely last executed before the last full GC.
      updated_age = current_age == 0
                        ? 1
                        : SaturateAdd(current_age, code_flushing_increase_);
    } while (sfi->CompareExchangeAge(current_age, updated_age) != current_age);
  } else if (v8_flags.flush_code_based_on_tab_visibility) {
    // No need to increment age.
  } else {
    uint16_t age = sfi->age();
    if (age < v8_flags.bytecode_old_age) {
      sfi->CompareExchangeAge(age, age + 1);
    }
    DCHECK_LE(sfi->age(), v8_flags.bytecode_old_age);
  }
}

template <typename ConcreteVisitor>
bool MarkingVisitorBase<ConcreteVisitor>::ShouldFlushBaselineCode(
    Tagged<JSFunction> js_function) const {
  if (!IsBaselineCodeFlushingEnabled(code_flush_mode_)) return false;
  // Do a raw read for shared and code fields here since this function may be
  // called on a concurrent thread. JSFunction itself should be fully
  // initialized here but the SharedFunctionInfo, InstructionStream objects may
  // not be initialized. We read using acquire loads to defend against that.
  Tagged<Object> maybe_shared =
      ACQUIRE_READ_FIELD(js_function, JSFunction::kSharedFunctionInfoOffset);
  if (!IsSharedFunctionInfo(maybe_shared)) return false;

  // See crbug.com/v8/11972 for more details on acquire / release semantics for
  // code field. We don't use release stores when copying code pointers from
  // SFI / FV to JSFunction but it is safe in practice.
  Tagged<Object> maybe_code =
      js_function->raw_code(heap_->isolate(), kAcquireLoad);

#ifdef THREAD_SANITIZER
  // This is needed because TSAN does not process the memory fence
  // emitted after page initialization.
  MemoryChunk::FromAddress(maybe_code.ptr())->SynchronizedLoad();
#endif
  if (!IsCode(maybe_code)) return false;
  Tagged<Code> code = Cast<Code>(maybe_code);
  if (code->kind() != CodeKind::BASELINE) return false;

  Tagged<SharedFunctionInfo> shared = Cast<SharedFunctionInfo>(maybe_shared);
  return HasBytecodeArrayForFlushing(shared) && ShouldFlushCode(shared);
}

// ===========================================================================
// Fixed arrays that need incremental processing =============================
// ===========================================================================

template <typename ConcreteVisitor>
size_t MarkingVisitorBase<ConcreteVisitor>::VisitFixedArrayWithProgressTracker(
    Tagged<Map> map, Tagged<FixedArray> object,
    MarkingProgressTracker& progress_tracker) {
  static_assert(kMaxRegularHeapObjectSize % kTaggedSize == 0);
  static constexpr size_t kMaxQueuedWorklistItems = 8u;
  DCHECK(concrete_visitor()->marking_state()->IsMarked(object));

  const size_t size = FixedArray::BodyDescriptor::SizeOf(map, object);
  const size_t chunk = progress_tracker.GetNextChunkToMark();
  const size_t total_chunks = progress_tracker.TotalNumberOfChunks();
  size_t start = 0;
  size_t end = 0;
  if (chunk == 0) {
    // We just started marking the fixed array. Push the total number of chunks
    // to the marking worklist and publish it so that other markers can
    // participate.
    if (const auto target_worklist =
            MarkingHelper::ShouldMarkObject(heap_, object)) {
      DCHECK_EQ(target_worklist.value(),
                MarkingHelper::WorklistTarget::kRegular);
      const size_t scheduled_chunks =
          std::min(total_chunks, kMaxQueuedWorklistItems);
      DCHECK_GT(scheduled_chunks, 0);
      for (size_t i = 1; i < scheduled_chunks; ++i) {
        local_marking_worklists_->Push(object);
        // Publish each chunk into a new segment so that other markers would be
        // able to steal work. This is probabilistic (a single marker can be
        // fast and steal multiple segments), but it works well in practice.
        local_marking_worklists_->ShareWork();
      }
    }
    concrete_visitor()
        ->template VisitMapPointerIfNeeded<VisitorId::kVisitFixedArray>(object);
    start = FixedArray::BodyDescriptor::kStartOffset;
    end = std::min(size, MarkingProgressTracker::kChunkSize);
  } else {
    start = chunk * MarkingProgressTracker::kChunkSize;
    end = std::min(size, start + MarkingProgressTracker::kChunkSize);
  }

  // Repost the task if needed.
  if (chunk + kMaxQueuedWorklistItems < total_chunks) {
    if (const auto target_worklist =
            MarkingHelper::ShouldMarkObject(heap_, object)) {
      local_marking_worklists_->Push(object);
      local_marking_worklists_->ShareWork();
    }
  }

  if (start < end) {
    VisitPointers(object,
                  Cast<HeapObject>(object)->RawField(static_cast<int>(start)),
                  Cast<HeapObject>(object)->RawField(static_cast<int>(end)));
  }

  return end - start;
}

template <typename ConcreteVisitor>
size_t MarkingVisitorBase<ConcreteVisitor>::VisitFixedArray(
    Tagged<Map> map, Tagged<FixedArray> object,
    MaybeObjectSize maybe_object_size) {
  MarkingProgressTracker& progress_tracker =
      MutablePageMetadata::FromHeapObject(object)->MarkingProgressTracker();
  return concrete_visitor()->CanUpdateValuesInHeap() &&
                 progress_tracker.IsEnabled()
             ? VisitFixedArrayWithProgressTracker(map, object, progress_tracker)
             : Base::VisitFixedArray(map, object, maybe_object_size);
}

// ===========================================================================
// Custom visitation =========================================================
// ===========================================================================

template <typename ConcreteVisitor>
size_t MarkingVisitorBase<ConcreteVisitor>::VisitJSArrayBuffer(
    Tagged<Map> map, Tagged<JSArrayBuffer> object,
    MaybeObjectSize maybe_object_size) {
  object->MarkExtension();
  return Base::VisitJSArrayBuffer(map, object, maybe_object_size);
}

// ===========================================================================
// Weak JavaScript objects ===================================================
// ===========================================================================

template <typename ConcreteVisitor>
size_t MarkingVisitorBase<ConcreteVisitor>::VisitEphemeronHashTable(
    Tagged<Map> map, Tagged<EphemeronHashTable> table, MaybeObjectSize) {
  local_weak_objects_->ephemeron_hash_tables_local.Push(table);

  for (InternalIndex i : table->IterateEntries()) {
    ObjectSlot key_slot =
        table->RawFieldOfElementAt(EphemeronHashTable::EntryToIndex(i));
    Tagged<HeapObject> key = Cast<HeapObject>(table->KeyAt(i, kRelaxedLoad));

    SynchronizePageAccess(key);
    concrete_visitor()->RecordSlot(table, key_slot, key);
    concrete_visitor()->AddWeakReferenceForReferenceSummarizer
### 提示词
```
这是目录为v8/src/heap/marking-visitor-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/marking-visitor-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_HEAP_MARKING_VISITOR_INL_H_
#define V8_HEAP_MARKING_VISITOR_INL_H_

#include "src/common/globals.h"
#include "src/heap/ephemeron-remembered-set.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/heap-visitor-inl.h"
#include "src/heap/heap-visitor.h"
#include "src/heap/marking-progress-tracker.h"
#include "src/heap/marking-state-inl.h"
#include "src/heap/marking-visitor.h"
#include "src/heap/marking-worklist-inl.h"
#include "src/heap/marking.h"
#include "src/heap/pretenuring-handler-inl.h"
#include "src/heap/spaces.h"
#include "src/objects/compressed-slots.h"
#include "src/objects/descriptor-array.h"
#include "src/objects/heap-object.h"
#include "src/objects/js-objects.h"
#include "src/objects/objects.h"
#include "src/objects/property-details.h"
#include "src/objects/slots.h"
#include "src/objects/smi.h"
#include "src/objects/string.h"
#include "src/sandbox/external-pointer-inl.h"
#include "src/sandbox/indirect-pointer-tag.h"
#include "src/sandbox/js-dispatch-table-inl.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8 {
namespace internal {

// ===========================================================================
// Visiting strong and weak pointers =========================================
// ===========================================================================

template <typename ConcreteVisitor>
bool MarkingVisitorBase<ConcreteVisitor>::MarkObject(
    Tagged<HeapObject> retainer, Tagged<HeapObject> object,
    MarkingHelper::WorklistTarget target_worklist) {
  DCHECK(heap_->Contains(object));
  SynchronizePageAccess(object);
  concrete_visitor()->AddStrongReferenceForReferenceSummarizer(retainer,
                                                               object);
  return MarkingHelper::TryMarkAndPush(heap_, local_marking_worklists_,
                                       concrete_visitor()->marking_state(),
                                       target_worklist, object);
}

// class template arguments
template <typename ConcreteVisitor>
// method template arguments
template <typename THeapObjectSlot>
void MarkingVisitorBase<ConcreteVisitor>::ProcessStrongHeapObject(
    Tagged<HeapObject> host, THeapObjectSlot slot,
    Tagged<HeapObject> heap_object) {
  SynchronizePageAccess(heap_object);
  const auto target_worklist =
      MarkingHelper::ShouldMarkObject(heap_, heap_object);
  if (!target_worklist) {
    return;
  }
  // TODO(chromium:1495151): Remove after diagnosing.
  if (V8_UNLIKELY(!MemoryChunk::FromHeapObject(heap_object)->IsMarking() &&
                  IsFreeSpaceOrFiller(
                      heap_object, ObjectVisitorWithCageBases::cage_base()))) {
    heap_->isolate()->PushStackTraceAndDie(
        reinterpret_cast<void*>(host->map().ptr()),
        reinterpret_cast<void*>(host->address()),
        reinterpret_cast<void*>(slot.address()),
        reinterpret_cast<void*>(MemoryChunkMetadata::FromHeapObject(heap_object)
                                    ->owner()
                                    ->identity()));
  }
  MarkObject(host, heap_object, target_worklist.value());
  concrete_visitor()->RecordSlot(host, slot, heap_object);
}

// static
template <typename ConcreteVisitor>
V8_INLINE constexpr bool
MarkingVisitorBase<ConcreteVisitor>::IsTrivialWeakReferenceValue(
    Tagged<HeapObject> host, Tagged<HeapObject> heap_object) {
  return !IsMap(heap_object) ||
         !(IsMap(host) || IsTransitionArray(host) || IsDescriptorArray(host));
}

// class template arguments
template <typename ConcreteVisitor>
// method template arguments
template <typename THeapObjectSlot>
void MarkingVisitorBase<ConcreteVisitor>::ProcessWeakHeapObject(
    Tagged<HeapObject> host, THeapObjectSlot slot,
    Tagged<HeapObject> heap_object) {
  SynchronizePageAccess(heap_object);
  concrete_visitor()->AddWeakReferenceForReferenceSummarizer(host, heap_object);
  const auto target_worklist =
      MarkingHelper::ShouldMarkObject(heap_, heap_object);
  if (!target_worklist) {
    return;
  }
  if (concrete_visitor()->marking_state()->IsMarked(heap_object)) {
    // Weak references with live values are directly processed here to
    // reduce the processing time of weak cells during the main GC
    // pause.
    concrete_visitor()->RecordSlot(host, slot, heap_object);
  } else {
    // If we do not know about liveness of the value, we have to process
    // the reference when we know the liveness of the whole transitive
    // closure.
    // Distinguish trivial cases (non involving custom weakness) from
    // non-trivial ones. The latter are maps in host objects of type Map,
    // TransitionArray and DescriptorArray.
    if (V8_LIKELY(IsTrivialWeakReferenceValue(host, heap_object))) {
      local_weak_objects_->weak_references_trivial_local.Push(
          HeapObjectAndSlot{host, slot});
    } else {
      local_weak_objects_->weak_references_non_trivial_local.Push(
          HeapObjectAndSlot{host, slot});
    }
  }
}

// class template arguments
template <typename ConcreteVisitor>
// method template arguments
template <typename TSlot>
void MarkingVisitorBase<ConcreteVisitor>::VisitPointersImpl(
    Tagged<HeapObject> host, TSlot start, TSlot end) {
  using THeapObjectSlot = typename TSlot::THeapObjectSlot;
  for (TSlot slot = start; slot < end; ++slot) {
    const std::optional<Tagged<Object>> optional_object =
        this->GetObjectFilterReadOnlyAndSmiFast(slot);
    if (!optional_object) {
      continue;
    }
    typename TSlot::TObject object = *optional_object;
    Tagged<HeapObject> heap_object;
    if (object.GetHeapObjectIfStrong(&heap_object)) {
      // If the reference changes concurrently from strong to weak, the write
      // barrier will treat the weak reference as strong, so we won't miss the
      // weak reference.
      ProcessStrongHeapObject(host, THeapObjectSlot(slot), heap_object);
    } else if (TSlot::kCanBeWeak && object.GetHeapObjectIfWeak(&heap_object)) {
      ProcessWeakHeapObject(host, THeapObjectSlot(slot), heap_object);
    }
  }
}

// class template arguments
template <typename ConcreteVisitor>
// method template arguments
template <typename TSlot>
void MarkingVisitorBase<ConcreteVisitor>::VisitStrongPointerImpl(
    Tagged<HeapObject> host, TSlot slot) {
  static_assert(!TSlot::kCanBeWeak);
  using THeapObjectSlot = typename TSlot::THeapObjectSlot;
  typename TSlot::TObject object = slot.Relaxed_Load();
  Tagged<HeapObject> heap_object;
  if (object.GetHeapObject(&heap_object)) {
    ProcessStrongHeapObject(host, THeapObjectSlot(slot), heap_object);
  }
}

template <typename ConcreteVisitor>
void MarkingVisitorBase<ConcreteVisitor>::VisitEmbeddedPointer(
    Tagged<InstructionStream> host, RelocInfo* rinfo) {
  DCHECK(RelocInfo::IsEmbeddedObjectMode(rinfo->rmode()));
  Tagged<HeapObject> object =
      rinfo->target_object(ObjectVisitorWithCageBases::cage_base());
  const auto target_worklist = MarkingHelper::ShouldMarkObject(heap_, object);
  if (!target_worklist) {
    return;
  }

  if (!concrete_visitor()->marking_state()->IsMarked(object)) {
    Tagged<Code> code = UncheckedCast<Code>(host->raw_code(kAcquireLoad));
    if (code->IsWeakObject(object)) {
      local_weak_objects_->weak_objects_in_code_local.Push(
          HeapObjectAndCode{object, code});
      concrete_visitor()->AddWeakReferenceForReferenceSummarizer(host, object);
    } else {
      MarkObject(host, object, target_worklist.value());
    }
  }
  concrete_visitor()->RecordRelocSlot(host, rinfo, object);
}

template <typename ConcreteVisitor>
void MarkingVisitorBase<ConcreteVisitor>::VisitCodeTarget(
    Tagged<InstructionStream> host, RelocInfo* rinfo) {
  DCHECK(RelocInfo::IsCodeTargetMode(rinfo->rmode()));
  Tagged<InstructionStream> target =
      InstructionStream::FromTargetAddress(rinfo->target_address());

  const auto target_worklist = MarkingHelper::ShouldMarkObject(heap_, target);
  if (!target_worklist) {
    return;
  }
  MarkObject(host, target, target_worklist.value());
  concrete_visitor()->RecordRelocSlot(host, rinfo, target);
}

template <typename ConcreteVisitor>
void MarkingVisitorBase<ConcreteVisitor>::VisitExternalPointer(
    Tagged<HeapObject> host, ExternalPointerSlot slot) {
#ifdef V8_COMPRESS_POINTERS
  DCHECK_NE(slot.tag(), kExternalPointerNullTag);
  if (slot.HasExternalPointerHandle()) {
    ExternalPointerHandle handle = slot.Relaxed_LoadHandle();
    ExternalPointerTable* table;
    ExternalPointerTable::Space* space;
    if (IsSharedExternalPointerType(slot.tag())) {
      table = shared_external_pointer_table_;
      space = shared_external_pointer_space_;
    } else {
      table = external_pointer_table_;
      if (v8_flags.sticky_mark_bits) {
        // Everything is considered old during major GC.
        DCHECK(!HeapLayout::InYoungGeneration(host));
        if (handle == kNullExternalPointerHandle) return;
        // The object may either be in young or old EPT.
        if (table->Contains(heap_->young_external_pointer_space(), handle)) {
          space = heap_->young_external_pointer_space();
        } else {
          DCHECK(table->Contains(heap_->old_external_pointer_space(), handle));
          space = heap_->old_external_pointer_space();
        }
      } else {
        space = HeapLayout::InYoungGeneration(host)
                    ? heap_->young_external_pointer_space()
                    : heap_->old_external_pointer_space();
      }
    }
    table->Mark(space, handle, slot.address());
  }
#endif  // V8_COMPRESS_POINTERS
}

template <typename ConcreteVisitor>
void MarkingVisitorBase<ConcreteVisitor>::VisitCppHeapPointer(
    Tagged<HeapObject> host, CppHeapPointerSlot slot) {
#ifdef V8_COMPRESS_POINTERS
  const ExternalPointerHandle handle = slot.Relaxed_LoadHandle();
  if (handle == kNullExternalPointerHandle) {
    return;
  }
  CppHeapPointerTable* table = cpp_heap_pointer_table_;
  CppHeapPointerTable::Space* space = heap_->cpp_heap_pointer_space();
  table->Mark(space, handle, slot.address());
#endif  // V8_COMPRESS_POINTERS
  if (auto cpp_heap_pointer =
          slot.try_load(heap_->isolate(), kAnyCppHeapPointer)) {
    local_marking_worklists_->cpp_marking_state()->MarkAndPush(
        reinterpret_cast<void*>(cpp_heap_pointer));
  }
}

template <typename ConcreteVisitor>
void MarkingVisitorBase<ConcreteVisitor>::VisitIndirectPointer(
    Tagged<HeapObject> host, IndirectPointerSlot slot,
    IndirectPointerMode mode) {
#ifdef V8_ENABLE_SANDBOX
  if (mode == IndirectPointerMode::kStrong) {
    // Load the referenced object (if the slot is initialized) and mark it as
    // alive if necessary. Indirect pointers never have to be added to a
    // remembered set because the referenced object will update the pointer
    // table entry when it is relocated.
    Tagged<Object> value = slot.Relaxed_Load(heap_->isolate());
    if (IsHeapObject(value)) {
      Tagged<HeapObject> obj = Cast<HeapObject>(value);
      SynchronizePageAccess(obj);
      const auto target_worklist = MarkingHelper::ShouldMarkObject(heap_, obj);
      if (!target_worklist) {
        return;
      }
      MarkObject(host, obj, target_worklist.value());
    }
  }
#else
  UNREACHABLE();
#endif
}

template <typename ConcreteVisitor>
void MarkingVisitorBase<ConcreteVisitor>::VisitTrustedPointerTableEntry(
    Tagged<HeapObject> host, IndirectPointerSlot slot) {
  concrete_visitor()->MarkPointerTableEntry(host, slot);
}

template <typename ConcreteVisitor>
void MarkingVisitorBase<ConcreteVisitor>::VisitJSDispatchTableEntry(
    Tagged<HeapObject> host, JSDispatchHandle handle) {
#ifdef V8_ENABLE_LEAPTIERING
  JSDispatchTable* table = GetProcessWideJSDispatchTable();
#ifdef DEBUG
  JSDispatchTable::Space* space = heap_->js_dispatch_table_space();
  JSDispatchTable::Space* ro_space =
      heap_->isolate()->read_only_heap()->js_dispatch_table_space();
  table->VerifyEntry(handle, space, ro_space);
#endif  // DEBUG

  table->Mark(handle);

  // The code objects referenced from a dispatch table entry are treated as weak
  // references for the purpose of bytecode/baseline flushing, so they are not
  // marked here. See also VisitJSFunction below.
#endif  // V8_ENABLE_LEAPTIERING
}

// ===========================================================================
// Object participating in bytecode flushing =================================
// ===========================================================================

template <typename ConcreteVisitor>
size_t MarkingVisitorBase<ConcreteVisitor>::VisitJSFunction(
    Tagged<Map> map, Tagged<JSFunction> js_function,
    MaybeObjectSize maybe_object_size) {
  if (ShouldFlushBaselineCode(js_function)) {
    DCHECK(IsBaselineCodeFlushingEnabled(code_flush_mode_));
#ifndef V8_ENABLE_LEAPTIERING
    local_weak_objects_->baseline_flushing_candidates_local.Push(js_function);
#endif  // !V8_ENABLE_LEAPTIERING
    return Base::VisitJSFunction(map, js_function, maybe_object_size);
  }

  // We're not flushing the Code, so mark it as alive.
#ifdef V8_ENABLE_LEAPTIERING
  // Here we can see JSFunctions that aren't fully initialized (e.g. during
  // deserialization) so we need to check for the null handle.
  JSDispatchHandle handle = js_function->Relaxed_ReadField<JSDispatchHandle>(
      JSFunction::kDispatchHandleOffset);
  if (handle != kNullJSDispatchHandle) {
    Tagged<HeapObject> obj = GetProcessWideJSDispatchTable()->GetCode(handle);
    // TODO(saelo): maybe factor out common code with VisitIndirectPointer
    // into a helper routine?
    SynchronizePageAccess(obj);
    const auto target_worklist = MarkingHelper::ShouldMarkObject(heap_, obj);
    if (target_worklist) {
      MarkObject(js_function, obj, target_worklist.value());
    }
  }
#else

#ifdef V8_ENABLE_SANDBOX
  VisitIndirectPointer(js_function,
                       js_function->RawIndirectPointerField(
                           JSFunction::kCodeOffset, kCodeIndirectPointerTag),
                       IndirectPointerMode::kStrong);
#else
  VisitPointer(js_function, js_function->RawField(JSFunction::kCodeOffset));
#endif  // V8_ENABLE_SANDBOX

#endif  // V8_ENABLE_LEAPTIERING

  // TODO(mythria): Consider updating the check for ShouldFlushBaselineCode to
  // also include cases where there is old bytecode even when there is no
  // baseline code and remove this check here.
  if (IsByteCodeFlushingEnabled(code_flush_mode_) &&
      js_function->NeedsResetDueToFlushedBytecode(heap_->isolate())) {
    local_weak_objects_->flushed_js_functions_local.Push(js_function);
  }

  return Base::VisitJSFunction(map, js_function, maybe_object_size);
}

template <typename ConcreteVisitor>
size_t MarkingVisitorBase<ConcreteVisitor>::VisitSharedFunctionInfo(
    Tagged<Map> map, Tagged<SharedFunctionInfo> shared_info,
    MaybeObjectSize maybe_object_size) {
  const bool can_flush_bytecode = HasBytecodeArrayForFlushing(shared_info);

  // We found a BytecodeArray that can be flushed. Increment the age of the SFI.
  if (can_flush_bytecode && !should_keep_ages_unchanged_) {
    MakeOlder(shared_info);
  }

  if (!can_flush_bytecode || !ShouldFlushCode(shared_info)) {
    // If the SharedFunctionInfo doesn't have old bytecode visit the function
    // data strongly.
#ifdef V8_ENABLE_SANDBOX
    VisitIndirectPointer(shared_info,
                         shared_info->RawIndirectPointerField(
                             SharedFunctionInfo::kTrustedFunctionDataOffset,
                             kUnknownIndirectPointerTag),
                         IndirectPointerMode::kStrong);
#else
    VisitPointer(
        shared_info,
        shared_info->RawField(SharedFunctionInfo::kTrustedFunctionDataOffset));
#endif
    VisitPointer(shared_info,
                 shared_info->RawField(
                     SharedFunctionInfo::kUntrustedFunctionDataOffset));
  } else if (!IsByteCodeFlushingEnabled(code_flush_mode_)) {
    // If bytecode flushing is disabled but baseline code flushing is enabled
    // then we have to visit the bytecode but not the baseline code.
    DCHECK(IsBaselineCodeFlushingEnabled(code_flush_mode_));
    Tagged<Code> baseline_code = shared_info->baseline_code(kAcquireLoad);
    // Visit the bytecode hanging off baseline code.
    VisitProtectedPointer(
        baseline_code, baseline_code->RawProtectedPointerField(
                           Code::kDeoptimizationDataOrInterpreterDataOffset));
    local_weak_objects_->code_flushing_candidates_local.Push(shared_info);
  } else {
    // In other cases, record as a flushing candidate since we have old
    // bytecode.
    local_weak_objects_->code_flushing_candidates_local.Push(shared_info);
  }
  return Base::VisitSharedFunctionInfo(map, shared_info, maybe_object_size);
}

template <typename ConcreteVisitor>
bool MarkingVisitorBase<ConcreteVisitor>::HasBytecodeArrayForFlushing(
    Tagged<SharedFunctionInfo> sfi) const {
  if (IsFlushingDisabled(code_flush_mode_)) return false;

  // TODO(rmcilroy): Enable bytecode flushing for resumable functions.
  if (IsResumableFunction(sfi->kind()) || !sfi->allows_lazy_compilation()) {
    return false;
  }

  // Get a snapshot of the function data field, and if it is a bytecode array,
  // check if it is old. Note, this is done this way since this function can be
  // called by the concurrent marker.
  Tagged<Object> data = sfi->GetTrustedData(heap_->isolate());
  if (IsCode(data)) {
    Tagged<Code> baseline_code = Cast<Code>(data);
    DCHECK_EQ(baseline_code->kind(), CodeKind::BASELINE);
    // If baseline code flushing isn't enabled and we have baseline data on SFI
    // we cannot flush baseline / bytecode.
    if (!IsBaselineCodeFlushingEnabled(code_flush_mode_)) return false;
    data = baseline_code->bytecode_or_interpreter_data();
  } else if (!IsByteCodeFlushingEnabled(code_flush_mode_)) {
    // If bytecode flushing isn't enabled and there is no baseline code there is
    // nothing to flush.
    return false;
  }

  return IsBytecodeArray(data);
}

template <typename ConcreteVisitor>
bool MarkingVisitorBase<ConcreteVisitor>::ShouldFlushCode(
    Tagged<SharedFunctionInfo> sfi) const {
  return IsStressFlushingEnabled(code_flush_mode_) || IsOld(sfi);
}

template <typename ConcreteVisitor>
bool MarkingVisitorBase<ConcreteVisitor>::IsOld(
    Tagged<SharedFunctionInfo> sfi) const {
  if (v8_flags.flush_code_based_on_time) {
    return sfi->age() >= v8_flags.bytecode_old_time;
  } else if (v8_flags.flush_code_based_on_tab_visibility) {
    return isolate_in_background_ ||
           V8_UNLIKELY(sfi->age() == SharedFunctionInfo::kMaxAge);
  } else {
    return sfi->age() >= v8_flags.bytecode_old_age;
  }
}

template <typename ConcreteVisitor>
void MarkingVisitorBase<ConcreteVisitor>::MakeOlder(
    Tagged<SharedFunctionInfo> sfi) const {
  if (v8_flags.flush_code_based_on_time) {
    if (code_flushing_increase_ == 0) {
      return;
    }

    uint16_t current_age;
    uint16_t updated_age;
    do {
      current_age = sfi->age();
      // When the age is 0, it was reset by the function prologue in
      // Ignition/Sparkplug. But that might have been some time after the last
      // full GC. So in this case we don't increment the value like we normally
      // would but just set the age to 1. All non-0 values can be incremented as
      // expected (we add the number of seconds since the last GC) as they were
      // definitely last executed before the last full GC.
      updated_age = current_age == 0
                        ? 1
                        : SaturateAdd(current_age, code_flushing_increase_);
    } while (sfi->CompareExchangeAge(current_age, updated_age) != current_age);
  } else if (v8_flags.flush_code_based_on_tab_visibility) {
    // No need to increment age.
  } else {
    uint16_t age = sfi->age();
    if (age < v8_flags.bytecode_old_age) {
      sfi->CompareExchangeAge(age, age + 1);
    }
    DCHECK_LE(sfi->age(), v8_flags.bytecode_old_age);
  }
}

template <typename ConcreteVisitor>
bool MarkingVisitorBase<ConcreteVisitor>::ShouldFlushBaselineCode(
    Tagged<JSFunction> js_function) const {
  if (!IsBaselineCodeFlushingEnabled(code_flush_mode_)) return false;
  // Do a raw read for shared and code fields here since this function may be
  // called on a concurrent thread. JSFunction itself should be fully
  // initialized here but the SharedFunctionInfo, InstructionStream objects may
  // not be initialized. We read using acquire loads to defend against that.
  Tagged<Object> maybe_shared =
      ACQUIRE_READ_FIELD(js_function, JSFunction::kSharedFunctionInfoOffset);
  if (!IsSharedFunctionInfo(maybe_shared)) return false;

  // See crbug.com/v8/11972 for more details on acquire / release semantics for
  // code field. We don't use release stores when copying code pointers from
  // SFI / FV to JSFunction but it is safe in practice.
  Tagged<Object> maybe_code =
      js_function->raw_code(heap_->isolate(), kAcquireLoad);

#ifdef THREAD_SANITIZER
  // This is needed because TSAN does not process the memory fence
  // emitted after page initialization.
  MemoryChunk::FromAddress(maybe_code.ptr())->SynchronizedLoad();
#endif
  if (!IsCode(maybe_code)) return false;
  Tagged<Code> code = Cast<Code>(maybe_code);
  if (code->kind() != CodeKind::BASELINE) return false;

  Tagged<SharedFunctionInfo> shared = Cast<SharedFunctionInfo>(maybe_shared);
  return HasBytecodeArrayForFlushing(shared) && ShouldFlushCode(shared);
}

// ===========================================================================
// Fixed arrays that need incremental processing =============================
// ===========================================================================

template <typename ConcreteVisitor>
size_t MarkingVisitorBase<ConcreteVisitor>::VisitFixedArrayWithProgressTracker(
    Tagged<Map> map, Tagged<FixedArray> object,
    MarkingProgressTracker& progress_tracker) {
  static_assert(kMaxRegularHeapObjectSize % kTaggedSize == 0);
  static constexpr size_t kMaxQueuedWorklistItems = 8u;
  DCHECK(concrete_visitor()->marking_state()->IsMarked(object));

  const size_t size = FixedArray::BodyDescriptor::SizeOf(map, object);
  const size_t chunk = progress_tracker.GetNextChunkToMark();
  const size_t total_chunks = progress_tracker.TotalNumberOfChunks();
  size_t start = 0;
  size_t end = 0;
  if (chunk == 0) {
    // We just started marking the fixed array. Push the total number of chunks
    // to the marking worklist and publish it so that other markers can
    // participate.
    if (const auto target_worklist =
            MarkingHelper::ShouldMarkObject(heap_, object)) {
      DCHECK_EQ(target_worklist.value(),
                MarkingHelper::WorklistTarget::kRegular);
      const size_t scheduled_chunks =
          std::min(total_chunks, kMaxQueuedWorklistItems);
      DCHECK_GT(scheduled_chunks, 0);
      for (size_t i = 1; i < scheduled_chunks; ++i) {
        local_marking_worklists_->Push(object);
        // Publish each chunk into a new segment so that other markers would be
        // able to steal work. This is probabilistic (a single marker can be
        // fast and steal multiple segments), but it works well in practice.
        local_marking_worklists_->ShareWork();
      }
    }
    concrete_visitor()
        ->template VisitMapPointerIfNeeded<VisitorId::kVisitFixedArray>(object);
    start = FixedArray::BodyDescriptor::kStartOffset;
    end = std::min(size, MarkingProgressTracker::kChunkSize);
  } else {
    start = chunk * MarkingProgressTracker::kChunkSize;
    end = std::min(size, start + MarkingProgressTracker::kChunkSize);
  }

  // Repost the task if needed.
  if (chunk + kMaxQueuedWorklistItems < total_chunks) {
    if (const auto target_worklist =
            MarkingHelper::ShouldMarkObject(heap_, object)) {
      local_marking_worklists_->Push(object);
      local_marking_worklists_->ShareWork();
    }
  }

  if (start < end) {
    VisitPointers(object,
                  Cast<HeapObject>(object)->RawField(static_cast<int>(start)),
                  Cast<HeapObject>(object)->RawField(static_cast<int>(end)));
  }

  return end - start;
}

template <typename ConcreteVisitor>
size_t MarkingVisitorBase<ConcreteVisitor>::VisitFixedArray(
    Tagged<Map> map, Tagged<FixedArray> object,
    MaybeObjectSize maybe_object_size) {
  MarkingProgressTracker& progress_tracker =
      MutablePageMetadata::FromHeapObject(object)->MarkingProgressTracker();
  return concrete_visitor()->CanUpdateValuesInHeap() &&
                 progress_tracker.IsEnabled()
             ? VisitFixedArrayWithProgressTracker(map, object, progress_tracker)
             : Base::VisitFixedArray(map, object, maybe_object_size);
}

// ===========================================================================
// Custom visitation =========================================================
// ===========================================================================

template <typename ConcreteVisitor>
size_t MarkingVisitorBase<ConcreteVisitor>::VisitJSArrayBuffer(
    Tagged<Map> map, Tagged<JSArrayBuffer> object,
    MaybeObjectSize maybe_object_size) {
  object->MarkExtension();
  return Base::VisitJSArrayBuffer(map, object, maybe_object_size);
}

// ===========================================================================
// Weak JavaScript objects ===================================================
// ===========================================================================

template <typename ConcreteVisitor>
size_t MarkingVisitorBase<ConcreteVisitor>::VisitEphemeronHashTable(
    Tagged<Map> map, Tagged<EphemeronHashTable> table, MaybeObjectSize) {
  local_weak_objects_->ephemeron_hash_tables_local.Push(table);

  for (InternalIndex i : table->IterateEntries()) {
    ObjectSlot key_slot =
        table->RawFieldOfElementAt(EphemeronHashTable::EntryToIndex(i));
    Tagged<HeapObject> key = Cast<HeapObject>(table->KeyAt(i, kRelaxedLoad));

    SynchronizePageAccess(key);
    concrete_visitor()->RecordSlot(table, key_slot, key);
    concrete_visitor()->AddWeakReferenceForReferenceSummarizer(table, key);

    ObjectSlot value_slot =
        table->RawFieldOfElementAt(EphemeronHashTable::EntryToValueIndex(i));

    // Objects in the shared heap are prohibited from being used as keys in
    // WeakMaps and WeakSets and therefore cannot be ephemeron keys. See also
    // MarkCompactCollector::ProcessEphemeron.
    DCHECK(!HeapLayout::InWritableSharedSpace(key));
    if (MarkingHelper::IsMarkedOrAlwaysLive(
            heap_, concrete_visitor()->marking_state(), key)) {
      VisitPointer(table, value_slot);
    } else {
      Tagged<Object> value_obj = table->ValueAt(i);

      if (IsHeapObject(value_obj)) {
        Tagged<HeapObject> value = Cast<HeapObject>(value_obj);
        SynchronizePageAccess(value);
        concrete_visitor()->RecordSlot(table, value_slot, value);
        concrete_visitor()->AddWeakReferenceForReferenceSummarizer(table,
                                                                   value);

        const auto target_worklist =
            MarkingHelper::ShouldMarkObject(heap_, value);
        if (!target_worklist) {
          continue;
        }

        // Revisit ephemerons with both key and value unreachable at end
        // of concurrent marking cycle.
        if (concrete_visitor()->marking_state()->IsUnmarked(value)) {
          local_weak_objects_->discovered_ephemerons_local.Push(
              Ephemeron{key, value});
        }
      }
    }
  }
  return table->SizeFromMap(map);
}

template <typename ConcreteVisitor>
size_t MarkingVisitorBase<ConcreteVisitor>::VisitJSWeakRef(
    Tagged<Map> map, Tagged<JSWeakRef> weak_ref,
    MaybeObjectSize maybe_object_size) {
  if (IsHeapObject(weak_ref->target())) {
    Tagged<HeapObject> target = Cast<HeapObject>(weak_ref->target());
    SynchronizePageAccess(target);
    concrete_visitor()->AddWeakReferenceForReferenceSummarizer(weak_ref,
                                                               target);
    if (MarkingHelper::IsMarkedOrAlwaysLive(
            heap_, concrete_visitor()->marking_state(), target)) {
      // Record the slot inside the JSWeakRef, since the VisitJSWeakRef above
      // didn't visit it.
      ObjectSlot slot = weak_ref->RawField(JSWeakRef::kTargetOffset);
      concrete_visitor()->RecordSlot(weak_ref, slot, target);
    } else {
      // JSWeakRef points to a potentially dead object. We have to process them
      // when we know the liveness of the whole transitive closure.
      local_weak_objects_->js_weak_refs_local.Push(weak_ref);
    }
  }
  return Base::VisitJSWeakRef(map, weak_ref, maybe_object_size);
}

template <typename ConcreteVisitor>
size_t MarkingVisitorBase<ConcreteVisitor>::VisitWeakCell(
    Tagged<Map> map, Tagged<WeakCell> weak_cell,
    MaybeObjectSize maybe_object_size) {
  Tagged<HeapObject> target = weak_cell->relaxed_target();
  Tagged<HeapObject> unregister_token = weak_cell->relaxed_unregister_token();
  SynchronizePageAccess(target);
  SynchronizePageAccess(unregister_token);
  if (MarkingHelper::IsMarkedOrAlwaysLive(
          heap_, concrete_visitor()->marking_state(), target) &&
      MarkingHelper::IsMarkedOrAlwaysLive(
          heap_, concrete_visitor()->marking_state(), unregister_token)) {
    // Record the slots inside the WeakCell, since its IterateBody doesn't visit
    // it.
    ObjectSlot slot = weak_cell->RawField(WeakCell::kTargetOffset);
    concrete_visitor()->RecordSlot(weak_cell, slot, target);
    slot = weak_cell->RawField(WeakCell::kUnregisterTokenOffset);
    concrete_visitor()->RecordSlot(weak_cell, slot, unregister_token);
  } else {
    // WeakCell points to a potentially dead object or a dead unregister
    // token. We have to process them when we know the liveness of the whole
    // transitive closure.
    local_weak_objects_->weak_cells_local.Push(weak_cell);
    concrete_visitor()->AddWeakReferenceForReferenceSummarizer(weak_cell,
                                                               target);
    concrete_visitor()->AddWeakReferenceForReferenceSummarizer(
        weak_cell, unregister_token);
  }
  return Base::VisitWeakCell(map, weak_cell, maybe_object_size);
}

// ===========================================================================
// Custom weakness in descriptor arrays and transition arrays ================
// ===========================================================================

template <typename ConcreteVisitor>
size_t MarkingVisitorBase<ConcreteVisitor>::VisitDescriptorArrayStrongly(
    Tagged<Map> map, Tagged<DescriptorArray> array, MaybeObjectSize) {
  this->template VisitMapPointerIfNeeded<VisitorId::kVisitDescriptorArray>(
      array);
  const int size = DescriptorArray::BodyDescriptor::SizeOf(map, array);
  VisitPointers(array, array->GetFirstPointerSlot(),
                array->GetDescriptorSlot(0));
  VisitPointers(array, MaybeObjectSlot(array->GetDescriptorSlot(0)),
                MaybeObjectSlot(
                    array->GetDescriptorSlot(array->number_of_descriptors())));
  return size;
}

template <typename ConcreteVisitor>
size_t MarkingVisitorBase<ConcreteVisitor>::VisitDescriptorArray(
    Tagged<Map> map, Tagged<DescriptorArray> array,
    MaybeObjectSize maybe_object_size) {
  if (!concrete_visitor()->CanUpdateValuesInHeap()) {
    // If we cannot update the values in the heap, we just treat the array
    // strongly.
    return VisitDescriptorArrayStrongly(map, array, maybe_object_size);
  }

  // The markbit is not used anymore. This is different from a checked
  // transition in that the array is re-added to the worklist and thus there's
  // many invocations of this transition. All cases (roots, marking via map,
  // write barrier) are handled here as they all update the state accordingly.
  const auto [start, end] =
      DescriptorArrayMarkingState::AcquireDescriptorRangeToMark(
          mark_compact_epoch_, array);
  if (start != end) {
    DCHECK_LT(start, end);
    VisitPointers(array, MaybeObjectSlot(array->GetDescriptorSlot(start)),
                  MaybeObjectSlot(array->GetDescriptorSlot(end)));
    if (start == 0) {
      // We are processing the object the first time. Visit the header and
      // return a size for accounting.
      size_t size = DescriptorArray::BodyDescriptor::SizeOf(map, array);
      VisitPointers(array, array->GetFirstPointerSlot(),
                    array->GetDescriptorSlot(0));
      concrete_visitor()
          ->template VisitMapPointerIfNeeded<VisitorId::kVisitDescriptorArray>(
```