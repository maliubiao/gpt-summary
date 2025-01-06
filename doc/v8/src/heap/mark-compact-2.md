Response: The user wants a summary of the functionality of the C++ code in `v8/src/heap/mark-compact.cc`. This is the *third* part of a four-part file. The summary should also explain its relation to JavaScript, providing a JavaScript example if applicable.

Given that this is part 3 of 4, I need to consider the context of the entire file's purpose, while focusing on the specific code provided in this section. Based on the variable names and function calls, this part seems to be heavily involved in the *evacuation* phase of the mark-compact garbage collection algorithm.

Here's a breakdown of the key functionalities I observe in this code snippet:

1. **Flushing Compiled Code:**  Functions like `ProcessOldCodeCandidates`, `ProcessOldBytecodeSFI`, `ProcessOldBaselineSFI`, and `FlushSFI` deal with identifying and discarding (flushing) old, potentially unused compiled JavaScript code (bytecode and baseline code). This optimization helps reduce memory usage.

2. **Clearing Weak References:** Functions like `ClearWeakCollections`, `ClearTrivialWeakReferences`, `FilterNonTrivialWeakReferences`, `ClearNonTrivialWeakReferences`, and `ClearJSWeakRefs` handle the cleanup of weak references. Weak references are a mechanism in garbage collection to hold references to objects without preventing them from being collected if they are otherwise unreachable.

3. **Managing Descriptor Arrays:** Functions like `ClearFullMapTransitions`, `CompactTransitionArray`, `RightTrimDescriptorArray`, `RecordStrongDescriptorArraysForWeakening`, `WeakenStrongDescriptorArrays`, `TrimDescriptorArray`, and `TrimEnumCache` deal with optimizing and managing `DescriptorArray` objects, which store information about object properties. This involves removing dead transitions and compacting the arrays to save space.

4. **Evacuation Process:**  The code defines an `Evacuator` class and related functions like `EvacuatePrologue`, `EvacuateEpilogue`, `EvacuatePage`, and `EvacuatePagesInParallel`. This is the core of the mark-compact algorithm's "compact" phase, where live objects are moved to new locations in memory to defragment the heap.

5. **Parallel Processing:** The presence of `PageEvacuationJob` suggests that the evacuation process is parallelized to improve performance.

6. **Updating Pointers:**  The `PointersUpdatingVisitor` class is used to iterate through memory and update pointers to reflect the new locations of moved objects after evacuation.

7. **Aborted Evacuation Handling:** The code includes mechanisms to handle situations where evacuation of a page needs to be aborted (e.g., due to out-of-memory errors).

**Relationship to JavaScript:**

These functionalities are directly related to how V8 (the JavaScript engine used in Chrome and Node.js) manages memory and optimizes performance for JavaScript execution.

* **Code Flushing:** When JavaScript functions are no longer frequently used, V8 can discard their compiled code to save memory. This is transparent to the JavaScript developer.
* **Weak References:** JavaScript provides `WeakRef` and `FinalizationRegistry` which rely on the underlying weak reference mechanism handled by this code.
* **Object Properties:**  The management of `DescriptorArray`s directly impacts how JavaScript objects and their properties are stored and accessed in memory.
* **Garbage Collection:** The entire evacuation process is a critical part of V8's garbage collection, ensuring that memory used by JavaScript programs is reclaimed efficiently.

**JavaScript Example:**

```javascript
// Demonstrating WeakRef and FinalizationRegistry which are related
// to the weak reference clearing mechanisms in the C++ code.

let heldObject = { data: "important data" };
const weakRef = new WeakRef(heldObject);
const registry = new FinalizationRegistry((heldValue) => {
  console.log("Object with value:", heldValue, "was garbage collected.");
});

registry.register(heldObject, "important data");

// heldObject is still strongly referenced, so it won't be collected yet.
console.log(weakRef.deref()?.data); // Output: important data

heldObject = null; // Remove the strong reference

// At some point in the future, the garbage collector might identify
// that the object is no longer reachable (except through the WeakRef).
// When this happens, the FinalizationRegistry's callback will be invoked.
// The C++ code in this file is responsible for the low-level details
// of identifying and clearing these weak references during garbage collection.
```

**Specific Functionality of Part 3:**

Based on the provided code snippet, this specific part of `mark-compact.cc` focuses heavily on the **evacuation and post-evacuation processing** steps of the mark-compact garbage collection algorithm. It handles:

* **Moving live objects** from "from-space" to "to-space" (evacuation).
* **Updating pointers** in the heap to point to the new locations of the moved objects.
* **Managing the flushing of old compiled code** (both bytecode and baseline code) to reclaim memory.
* **Clearing different types of weak references** to maintain memory integrity.
* **Optimizing data structures like `TransitionArray` and `DescriptorArray`** by removing dead entries and compacting them.

It seems like this part handles the core mechanics of physically reorganizing the heap during the mark-compact cycle.

这是 `v8/src/heap/mark-compact.cc` 源代码文件的第三部分，主要功能集中在 **标记压缩垃圾回收器的对象迁移（Evacuation）和迁移后的指针更新阶段**。

具体来说，这部分代码负责以下关键任务：

1. **刷新旧代码（Flushing Old Code）:**
   - 识别并清理不再活跃的字节码（BytecodeArray）和基线代码（Baseline Code）。
   - `ProcessOldCodeCandidates`、`ProcessOldBytecodeSFI`、`ProcessOldBaselineSFI` 和 `FlushSFI` 等函数负责判断 `SharedFunctionInfo` 中关联的字节码或基线代码是否存活，如果不再需要则将其替换为 `UncompiledData`，从而减少内存占用。
   - **与 JavaScript 的关系:** 当 JavaScript 函数很久没有被调用时，V8 可以选择丢弃其编译后的代码，只保留字节码或者更早期的形式。这可以节省内存。

   ```javascript
   function myFunction() {
     // 一些代码
   }

   // 如果 myFunction 很长时间没有被调用，V8 可能会刷新它的编译代码。
   ```

2. **清理弱引用（Clearing Weak References）:**
   - 管理和清理各种类型的弱引用，包括 `EphemeronHashTable`、简单的弱引用、非简单的弱引用以及 `JSWeakRef` 和 `WeakCell`。
   - `ClearWeakCollections`、`ClearTrivialWeakReferences`、`FilterNonTrivialWeakReferences`、`ClearNonTrivialWeakReferences` 和 `ClearJSWeakRefs` 等函数负责检查弱引用指向的对象是否仍然存活，如果不再存活则清除弱引用或执行相关的清理操作。
   - **与 JavaScript 的关系:** JavaScript 中的 `WeakRef` 和 `FinalizationRegistry` 功能依赖于这些底层的弱引用清理机制。

   ```javascript
   let obj = { data: 1 };
   const weakRef = new WeakRef(obj);
   const registry = new FinalizationRegistry(heldValue => {
     console.log('对象被回收了', heldValue);
   });
   registry.register(obj, 'myObject');

   // 当 obj 不再被强引用时，垃圾回收器会回收它，并执行 FinalizationRegistry 的回调。
   obj = null;
   ```

3. **处理 Map 的转换数组（Handling Map Transitions）:**
   - `ClearFullMapTransitions`、`CompactTransitionArray`、`RightTrimDescriptorArray` 等函数负责清理和压缩 `TransitionArray`，这些数组记录了对象类型转换的信息。通过移除不再需要的转换信息来节省内存。
   - **与 JavaScript 的关系:** JavaScript 中对象的属性添加和删除会导致对象类型的转换，V8 使用 `TransitionArray` 来高效地管理这些转换信息。

   ```javascript
   const obj = {};
   obj.a = 1; // 触发对象类型的转换
   obj.b = 2; // 再次触发
   delete obj.a; // 又一次触发
   ```

4. **对象迁移（Evacuation）:**
   - 定义了 `Evacuator` 类及其相关方法，如 `EvacuatePrologue`、`EvacuateEpilogue`、`EvacuatePage` 和 `EvacuatePagesInParallel`。这些函数负责将存活的对象从旧的内存区域迁移到新的区域，从而整理内存碎片。
   - `PageEvacuationJob` 表明对象迁移过程可以并行执行以提高效率。
   - **与 JavaScript 的关系:** 这是标记压缩垃圾回收算法的核心步骤，对 JavaScript 程序的内存管理至关重要，但对 JavaScript 开发者是透明的。

5. **更新指针（Updating Pointers）:**
   - `PointersUpdatingVisitor` 类用于遍历堆内存，并将所有指向已迁移对象的指针更新为它们的新地址。
   - **与 JavaScript 的关系:** 在对象迁移后，V8 需要确保所有指向这些对象的引用都指向新的内存位置，以保证程序的正确性。

6. **处理迁移失败的情况（Handling Aborted Evacuation）:**
   - 代码中包含处理由于内存不足或其他原因导致的对象迁移失败的逻辑。

总而言之，`v8/src/heap/mark-compact.cc` 的第三部分主要关注标记压缩垃圾回收器的核心流程，包括**整理内存空间**（通过对象迁移）和**回收不再使用的资源**（通过刷新旧代码和清理弱引用），从而提升 JavaScript 程序的内存利用率和执行效率。这部分功能是 V8 引擎实现自动内存管理的关键组成部分，对 JavaScript 开发者来说是幕后工作，但直接影响着程序的性能和稳定性。

Prompt: 
```
这是目录为v8/src/heap/mark-compact.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
outPreparseData::kSize);
    heap_->CreateFillerObjectAt(compiled_data.address() + aligned_filler_offset,
                                compiled_data_size - aligned_filler_offset);
  }

  // Initialize the uncompiled data.
  Tagged<UncompiledData> uncompiled_data = Cast<UncompiledData>(compiled_data);

  uncompiled_data->InitAfterBytecodeFlush(
      heap_->isolate(), inferred_name, start_position, end_position,
      [](Tagged<HeapObject> object, ObjectSlot slot,
         Tagged<HeapObject> target) { RecordSlot(object, slot, target); });

  // Mark the uncompiled data as black, and ensure all fields have already been
  // marked.
  DCHECK(MarkingHelper::IsMarkedOrAlwaysLive(heap_, marking_state_,
                                             inferred_name));
  if (MarkingHelper::GetLivenessMode(heap_, uncompiled_data) ==
      MarkingHelper::LivenessMode::kMarkbit) {
    marking_state_->TryMarkAndAccountLiveBytes(uncompiled_data);
  }

#ifdef V8_ENABLE_SANDBOX
  // Mark the new entry in the trusted pointer table as alive.
  TrustedPointerTable::Space* space = heap_->trusted_pointer_space();
  table.Mark(space, self_indirect_pointer_slot.Relaxed_LoadHandle());
#endif

  shared_info->set_uncompiled_data(uncompiled_data);
  DCHECK(!shared_info->is_compiled());
}

void MarkCompactCollector::ProcessOldCodeCandidates() {
  DCHECK(v8_flags.flush_bytecode || v8_flags.flush_baseline_code ||
         weak_objects_.code_flushing_candidates.IsEmpty());
  Tagged<SharedFunctionInfo> flushing_candidate;
  int number_of_flushed_sfis = 0;
  while (local_weak_objects()->code_flushing_candidates_local.Pop(
      &flushing_candidate)) {
    bool is_bytecode_live;
    if (v8_flags.flush_baseline_code && flushing_candidate->HasBaselineCode()) {
      is_bytecode_live = ProcessOldBaselineSFI(flushing_candidate);
    } else {
      is_bytecode_live = ProcessOldBytecodeSFI(flushing_candidate);
    }

    if (!is_bytecode_live) number_of_flushed_sfis++;

    // Now record the data slots, which have been updated to an uncompiled
    // data, Baseline code or BytecodeArray which is still alive.
#ifndef V8_ENABLE_SANDBOX
    // If the sandbox is enabled, the slot contains an indirect pointer which
    // does not need to be updated during mark-compact (because the pointer in
    // the pointer table will be updated), so no action is needed here.
    ObjectSlot slot = flushing_candidate->RawField(
        SharedFunctionInfo::kTrustedFunctionDataOffset);
    if (IsHeapObject(*slot)) {
      RecordSlot(flushing_candidate, slot, Cast<HeapObject>(*slot));
    }
#endif
  }

  if (v8_flags.trace_flush_code) {
    PrintIsolate(heap_->isolate(), "%d flushed SharedFunctionInfo(s)\n",
                 number_of_flushed_sfis);
  }
}

bool MarkCompactCollector::ProcessOldBytecodeSFI(
    Tagged<SharedFunctionInfo> flushing_candidate) {
  // During flushing a BytecodeArray is transformed into an UncompiledData
  // in place. Seeing an UncompiledData here implies that another
  // SharedFunctionInfo had a reference to the same BytecodeArray and
  // flushed it before processing this candidate. This can happen when using
  // CloneSharedFunctionInfo().
  Isolate* const isolate = heap_->isolate();

  const bool bytecode_already_decompiled =
      flushing_candidate->HasUncompiledData();
  if (!bytecode_already_decompiled) {
    // Check if the bytecode is still live.
    Tagged<BytecodeArray> bytecode =
        flushing_candidate->GetBytecodeArray(isolate);
    if (MarkingHelper::IsMarkedOrAlwaysLive(heap_, non_atomic_marking_state_,
                                            bytecode)) {
      return true;
    }
  }
  FlushSFI(flushing_candidate, bytecode_already_decompiled);
  return false;
}

bool MarkCompactCollector::ProcessOldBaselineSFI(
    Tagged<SharedFunctionInfo> flushing_candidate) {
  Tagged<Code> baseline_code = flushing_candidate->baseline_code(kAcquireLoad);
  // Safe to do a relaxed load here since the Code was acquire-loaded.
  Tagged<InstructionStream> baseline_istream =
      baseline_code->instruction_stream(baseline_code->code_cage_base(),
                                        kRelaxedLoad);
  Tagged<HeapObject> baseline_bytecode_or_interpreter_data =
      baseline_code->bytecode_or_interpreter_data();

  // During flushing a BytecodeArray is transformed into an UncompiledData
  // in place. Seeing an UncompiledData here implies that another
  // SharedFunctionInfo had a reference to the same BytecodeArray and
  // flushed it before processing this candidate. This can happen when using
  // CloneSharedFunctionInfo().
  const bool bytecode_already_decompiled =
      IsUncompiledData(baseline_bytecode_or_interpreter_data, heap_->isolate());
  bool is_bytecode_live = false;
  if (!bytecode_already_decompiled) {
    Tagged<BytecodeArray> bytecode =
        flushing_candidate->GetBytecodeArray(heap_->isolate());
    is_bytecode_live = MarkingHelper::IsMarkedOrAlwaysLive(
        heap_, non_atomic_marking_state_, bytecode);
  }

  if (MarkingHelper::IsMarkedOrAlwaysLive(heap_, non_atomic_marking_state_,
                                          baseline_istream)) {
    // Currently baseline code holds bytecode array strongly and it is
    // always ensured that bytecode is live if baseline code is live. Hence
    // baseline code can safely load bytecode array without any additional
    // checks. In future if this changes we need to update these checks to
    // flush code if the bytecode is not live and also update baseline code
    // to bailout if there is no bytecode.
    DCHECK(is_bytecode_live);

    // Regardless of whether the Code is a Code or
    // the InstructionStream itself, if the InstructionStream is live then
    // the Code has to be live and will have been marked via
    // the owning JSFunction.
    DCHECK(MarkingHelper::IsMarkedOrAlwaysLive(heap_, non_atomic_marking_state_,
                                               baseline_code));
  } else if (is_bytecode_live || bytecode_already_decompiled) {
    // Reset the function_data field to the BytecodeArray, InterpreterData,
    // or UncompiledData found on the baseline code. We can skip this step
    // if the BytecodeArray is not live and not already decompiled, because
    // FlushBytecodeFromSFI below will set the function_data field.
    flushing_candidate->FlushBaselineCode();
  }

  if (!is_bytecode_live) {
    FlushSFI(flushing_candidate, bytecode_already_decompiled);
  }
  return is_bytecode_live;
}

void MarkCompactCollector::FlushSFI(Tagged<SharedFunctionInfo> sfi,
                                    bool bytecode_already_decompiled) {
  // If baseline code flushing is disabled we should only flush bytecode
  // from functions that don't have baseline data.
  DCHECK(v8_flags.flush_baseline_code || !sfi->HasBaselineCode());

  if (bytecode_already_decompiled) {
    sfi->DiscardCompiledMetadata(
        heap_->isolate(),
        [](Tagged<HeapObject> object, ObjectSlot slot,
           Tagged<HeapObject> target) { RecordSlot(object, slot, target); });
  } else {
    // If the BytecodeArray is dead, flush it, which will replace the field
    // with an uncompiled data object.
    FlushBytecodeFromSFI(sfi);
  }
}

void MarkCompactCollector::ClearFlushedJsFunctions() {
  DCHECK(v8_flags.flush_bytecode ||
         weak_objects_.flushed_js_functions.IsEmpty());
  Tagged<JSFunction> flushed_js_function;
  while (local_weak_objects()->flushed_js_functions_local.Pop(
      &flushed_js_function)) {
    auto gc_notify_updated_slot = [](Tagged<HeapObject> object, ObjectSlot slot,
                                     Tagged<Object> target) {
      RecordSlot(object, slot, Cast<HeapObject>(target));
    };
    flushed_js_function->ResetIfCodeFlushed(heap_->isolate(),
                                            gc_notify_updated_slot);
  }
}

#ifndef V8_ENABLE_LEAPTIERING

void MarkCompactCollector::ProcessFlushedBaselineCandidates() {
  DCHECK(v8_flags.flush_baseline_code ||
         weak_objects_.baseline_flushing_candidates.IsEmpty());
  Tagged<JSFunction> flushed_js_function;
  while (local_weak_objects()->baseline_flushing_candidates_local.Pop(
      &flushed_js_function)) {
    auto gc_notify_updated_slot = [](Tagged<HeapObject> object, ObjectSlot slot,
                                     Tagged<Object> target) {
      RecordSlot(object, slot, Cast<HeapObject>(target));
    };
    flushed_js_function->ResetIfCodeFlushed(heap_->isolate(),
                                            gc_notify_updated_slot);

#ifndef V8_ENABLE_SANDBOX
    // Record the code slot that has been updated either to CompileLazy,
    // InterpreterEntryTrampoline or baseline code.
    // This is only necessary when the sandbox is not enabled. If it is, the
    // Code objects are referenced through a pointer table indirection and so
    // remembered slots are not necessary as the Code object will update its
    // entry in the pointer table when it is relocated.
    ObjectSlot slot = flushed_js_function->RawField(JSFunction::kCodeOffset);
    RecordSlot(flushed_js_function, slot, Cast<HeapObject>(*slot));
#endif
  }
}

#endif  // !V8_ENABLE_LEAPTIERING

void MarkCompactCollector::ClearFullMapTransitions() {
  Tagged<TransitionArray> array;
  Isolate* const isolate = heap_->isolate();
  ReadOnlyRoots roots(isolate);
  while (local_weak_objects()->transition_arrays_local.Pop(&array)) {
    int num_transitions = array->number_of_transitions();
    if (num_transitions > 0) {
        Tagged<Map> map;
        // The array might contain "undefined" elements because it's not yet
        // filled. Allow it.
        if (array->GetTargetIfExists(0, isolate, &map)) {
          DCHECK(!map.is_null());  // Weak pointers aren't cleared yet.
          Tagged<Object> constructor_or_back_pointer =
              map->constructor_or_back_pointer();
          if (IsSmi(constructor_or_back_pointer)) {
            DCHECK(isolate->has_active_deserializer());
            DCHECK_EQ(constructor_or_back_pointer,
                      Smi::uninitialized_deserialization_value());
            continue;
          }
          Tagged<Map> parent = Cast<Map>(map->constructor_or_back_pointer());
          const bool parent_is_alive = MarkingHelper::IsMarkedOrAlwaysLive(
              heap_, non_atomic_marking_state_, parent);
          Tagged<DescriptorArray> descriptors =
              parent_is_alive ? parent->instance_descriptors(isolate)
                              : Tagged<DescriptorArray>();
          bool descriptors_owner_died =
              CompactTransitionArray(parent, array, descriptors);
          if (descriptors_owner_died) {
            TrimDescriptorArray(parent, descriptors);
          }
        }
      }
  }
}

// Returns false if no maps have died, or if the transition array is
// still being deserialized.
bool MarkCompactCollector::TransitionArrayNeedsCompaction(
    Tagged<TransitionArray> transitions, int num_transitions) {
  ReadOnlyRoots roots(heap_->isolate());
  for (int i = 0; i < num_transitions; ++i) {
    Tagged<MaybeObject> raw_target = transitions->GetRawTarget(i);
    if (raw_target.IsSmi()) {
      // This target is still being deserialized,
      DCHECK(heap_->isolate()->has_active_deserializer());
      DCHECK_EQ(raw_target.ToSmi(), Smi::uninitialized_deserialization_value());
#ifdef DEBUG
      // Targets can only be dead iff this array is fully deserialized.
      for (int j = 0; j < num_transitions; ++j) {
        DCHECK_IMPLIES(
            !transitions->GetRawTarget(j).IsSmi(),
            !non_atomic_marking_state_->IsUnmarked(transitions->GetTarget(j)));
      }
#endif
      return false;
    } else if (MarkingHelper::IsUnmarkedAndNotAlwaysLive(
                   heap_, non_atomic_marking_state_,
                   TransitionsAccessor::GetTargetFromRaw(raw_target))) {
#ifdef DEBUG
      // Targets can only be dead iff this array is fully deserialized.
      for (int j = 0; j < num_transitions; ++j) {
        DCHECK(!transitions->GetRawTarget(j).IsSmi());
      }
#endif
      return true;
    }
  }
  return false;
}

bool MarkCompactCollector::CompactTransitionArray(
    Tagged<Map> map, Tagged<TransitionArray> transitions,
    Tagged<DescriptorArray> descriptors) {
  DCHECK(!map->is_prototype_map());
  int num_transitions = transitions->number_of_transitions();
  if (!TransitionArrayNeedsCompaction(transitions, num_transitions)) {
    return false;
  }
  ReadOnlyRoots roots(heap_->isolate());
  bool descriptors_owner_died = false;
  int transition_index = 0;
  // Compact all live transitions to the left.
  for (int i = 0; i < num_transitions; ++i) {
    Tagged<Map> target = transitions->GetTarget(i);
    DCHECK_EQ(target->constructor_or_back_pointer(), map);

    if (MarkingHelper::IsUnmarkedAndNotAlwaysLive(
            heap_, non_atomic_marking_state_, target)) {
      if (!descriptors.is_null() &&
          target->instance_descriptors(heap_->isolate()) == descriptors) {
        DCHECK(!target->is_prototype_map());
        descriptors_owner_died = true;
      }
      continue;
    }

    if (i != transition_index) {
      Tagged<Name> key = transitions->GetKey(i);
      transitions->SetKey(transition_index, key);
      HeapObjectSlot key_slot = transitions->GetKeySlot(transition_index);
      RecordSlot(transitions, key_slot, key);
      Tagged<MaybeObject> raw_target = transitions->GetRawTarget(i);
      transitions->SetRawTarget(transition_index, raw_target);
      HeapObjectSlot target_slot = transitions->GetTargetSlot(transition_index);
      RecordSlot(transitions, target_slot, raw_target.GetHeapObject());
    }
    transition_index++;
  }
  // If there are no transitions to be cleared, return.
  if (transition_index == num_transitions) {
    DCHECK(!descriptors_owner_died);
    return false;
  }
  // Note that we never eliminate a transition array, though we might right-trim
  // such that number_of_transitions() == 0. If this assumption changes,
  // TransitionArray::Insert() will need to deal with the case that a transition
  // array disappeared during GC.
  int old_capacity_in_entries = transitions->Capacity();
  if (transition_index < old_capacity_in_entries) {
    int old_capacity = transitions->length();
    static_assert(TransitionArray::kEntryKeyIndex == 0);
    DCHECK_EQ(TransitionArray::ToKeyIndex(old_capacity_in_entries),
              old_capacity);
    int new_capacity = TransitionArray::ToKeyIndex(transition_index);
    heap_->RightTrimArray(transitions, new_capacity, old_capacity);
    transitions->SetNumberOfTransitions(transition_index);
  }
  return descriptors_owner_died;
}

void MarkCompactCollector::RightTrimDescriptorArray(
    Tagged<DescriptorArray> array, int descriptors_to_trim) {
  int old_nof_all_descriptors = array->number_of_all_descriptors();
  int new_nof_all_descriptors = old_nof_all_descriptors - descriptors_to_trim;
  DCHECK_LT(0, descriptors_to_trim);
  DCHECK_LE(0, new_nof_all_descriptors);
  Address start = array->GetDescriptorSlot(new_nof_all_descriptors).address();
  Address end = array->GetDescriptorSlot(old_nof_all_descriptors).address();
  MutablePageMetadata* chunk = MutablePageMetadata::FromHeapObject(array);
  RememberedSet<OLD_TO_NEW>::RemoveRange(chunk, start, end,
                                         SlotSet::FREE_EMPTY_BUCKETS);
  RememberedSet<OLD_TO_NEW_BACKGROUND>::RemoveRange(
      chunk, start, end, SlotSet::FREE_EMPTY_BUCKETS);
  RememberedSet<OLD_TO_SHARED>::RemoveRange(chunk, start, end,
                                            SlotSet::FREE_EMPTY_BUCKETS);
  RememberedSet<OLD_TO_OLD>::RemoveRange(chunk, start, end,
                                         SlotSet::FREE_EMPTY_BUCKETS);
  if (V8_COMPRESS_POINTERS_8GB_BOOL) {
    Address aligned_start = ALIGN_TO_ALLOCATION_ALIGNMENT(start);
    Address aligned_end = ALIGN_TO_ALLOCATION_ALIGNMENT(end);
    if (aligned_start < aligned_end) {
      heap_->CreateFillerObjectAt(
          aligned_start, static_cast<int>(aligned_end - aligned_start));
    }
    if (heap::ShouldZapGarbage()) {
      Address zap_end = std::min(aligned_start, end);
      MemsetTagged(ObjectSlot(start),
                   Tagged<Object>(static_cast<Address>(kZapValue)),
                   (zap_end - start) >> kTaggedSizeLog2);
    }
  } else {
    heap_->CreateFillerObjectAt(start, static_cast<int>(end - start));
  }
  array->set_number_of_all_descriptors(new_nof_all_descriptors);
}

void MarkCompactCollector::RecordStrongDescriptorArraysForWeakening(
    GlobalHandleVector<DescriptorArray> strong_descriptor_arrays) {
  DCHECK(heap_->incremental_marking()->IsMajorMarking());
  base::MutexGuard guard(&strong_descriptor_arrays_mutex_);
  strong_descriptor_arrays_.push_back(std::move(strong_descriptor_arrays));
}

void MarkCompactCollector::WeakenStrongDescriptorArrays() {
  Tagged<Map> descriptor_array_map =
      ReadOnlyRoots(heap_->isolate()).descriptor_array_map();
  for (auto vec : strong_descriptor_arrays_) {
    for (auto it = vec.begin(); it != vec.end(); ++it) {
      Tagged<DescriptorArray> raw = it.raw();
      DCHECK(IsStrongDescriptorArray(raw));
      raw->set_map_safe_transition_no_write_barrier(heap_->isolate(),
                                                    descriptor_array_map);
      DCHECK_EQ(raw->raw_gc_state(kRelaxedLoad), 0);
    }
  }
  strong_descriptor_arrays_.clear();
}

void MarkCompactCollector::TrimDescriptorArray(
    Tagged<Map> map, Tagged<DescriptorArray> descriptors) {
  int number_of_own_descriptors = map->NumberOfOwnDescriptors();
  if (number_of_own_descriptors == 0) {
    DCHECK(descriptors == ReadOnlyRoots(heap_).empty_descriptor_array());
    return;
  }
  int to_trim =
      descriptors->number_of_all_descriptors() - number_of_own_descriptors;
  if (to_trim > 0) {
    descriptors->set_number_of_descriptors(number_of_own_descriptors);
    RightTrimDescriptorArray(descriptors, to_trim);

    TrimEnumCache(map, descriptors);
    descriptors->Sort();
  }
  DCHECK(descriptors->number_of_descriptors() == number_of_own_descriptors);
  map->set_owns_descriptors(true);
}

void MarkCompactCollector::TrimEnumCache(Tagged<Map> map,
                                         Tagged<DescriptorArray> descriptors) {
  int live_enum = map->EnumLength();
  if (live_enum == kInvalidEnumCacheSentinel) {
    live_enum = map->NumberOfEnumerableProperties();
  }
  if (live_enum == 0) return descriptors->ClearEnumCache();
  Tagged<EnumCache> enum_cache = descriptors->enum_cache();

  Tagged<FixedArray> keys = enum_cache->keys();
  int keys_length = keys->length();
  if (live_enum >= keys_length) return;
  heap_->RightTrimArray(keys, live_enum, keys_length);

  Tagged<FixedArray> indices = enum_cache->indices();
  int indices_length = indices->length();
  if (live_enum >= indices_length) return;
  heap_->RightTrimArray(indices, live_enum, indices_length);
}

void MarkCompactCollector::ClearWeakCollections() {
  TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_CLEAR_WEAK_COLLECTIONS);
  Tagged<EphemeronHashTable> table;
  while (local_weak_objects()->ephemeron_hash_tables_local.Pop(&table)) {
    for (InternalIndex i : table->IterateEntries()) {
      Tagged<HeapObject> key = Cast<HeapObject>(table->KeyAt(i));
#ifdef VERIFY_HEAP
      if (v8_flags.verify_heap) {
        Tagged<Object> value = table->ValueAt(i);
        if (IsHeapObject(value)) {
          Tagged<HeapObject> heap_object = Cast<HeapObject>(value);

          CHECK_IMPLIES(MarkingHelper::IsMarkedOrAlwaysLive(
                            heap_, non_atomic_marking_state_, key),
                        MarkingHelper::IsMarkedOrAlwaysLive(
                            heap_, non_atomic_marking_state_, heap_object));
        }
      }
#endif  // VERIFY_HEAP
      if (MarkingHelper::IsUnmarkedAndNotAlwaysLive(
              heap_, non_atomic_marking_state_, key)) {
        table->RemoveEntry(i);
      }
    }
  }
  auto* table_map = heap_->ephemeron_remembered_set()->tables();
  for (auto it = table_map->begin(); it != table_map->end();) {
    if (MarkingHelper::IsUnmarkedAndNotAlwaysLive(
            heap_, non_atomic_marking_state_, it->first)) {
      it = table_map->erase(it);
    } else {
      ++it;
    }
  }
}

void MarkCompactCollector::ClearTrivialWeakReferences() {
  HeapObjectAndSlot slot;
  Tagged<HeapObjectReference> cleared_weak_ref = ClearedValue(heap_->isolate());
  while (local_weak_objects()->weak_references_trivial_local.Pop(&slot)) {
    Tagged<HeapObject> value;
    // The slot could have been overwritten, so we have to treat it
    // as MaybeObjectSlot.
    MaybeObjectSlot location(slot.slot);
    if ((*location).GetHeapObjectIfWeak(&value)) {
      DCHECK(!IsWeakCell(value));
      // Values in RO space have already been filtered, but a non-RO value may
      // have been overwritten by a RO value since marking.
      if (MarkingHelper::IsMarkedOrAlwaysLive(heap_, non_atomic_marking_state_,
                                              value)) {
        // The value of the weak reference is alive.
        RecordSlot(slot.heap_object, HeapObjectSlot(location), value);
      } else {
        DCHECK(MainMarkingVisitor::IsTrivialWeakReferenceValue(slot.heap_object,
                                                               value));
        // The value of the weak reference is non-live.
        // This is a non-atomic store, which is fine as long as we only have a
        // single clearing job.
        location.store(cleared_weak_ref);
      }
    }
  }
}

void MarkCompactCollector::FilterNonTrivialWeakReferences() {
  HeapObjectAndSlot slot;
  while (local_weak_objects()->weak_references_non_trivial_local.Pop(&slot)) {
    Tagged<HeapObject> value;
    // The slot could have been overwritten, so we have to treat it
    // as MaybeObjectSlot.
    MaybeObjectSlot location(slot.slot);
    if ((*location).GetHeapObjectIfWeak(&value)) {
      DCHECK(!IsWeakCell(value));
      // Values in RO space have already been filtered, but a non-RO value may
      // have been overwritten by a RO value since marking.
      if (MarkingHelper::IsMarkedOrAlwaysLive(heap_, non_atomic_marking_state_,
                                              value)) {
        // The value of the weak reference is alive.
        RecordSlot(slot.heap_object, HeapObjectSlot(location), value);
      } else {
        DCHECK(!MainMarkingVisitor::IsTrivialWeakReferenceValue(
            slot.heap_object, value));
        // The value is non-live, defer the actual clearing.
        // This is non-atomic, which is fine as long as we only have a single
        // filtering job.
        local_weak_objects_->weak_references_non_trivial_unmarked_local.Push(
            slot);
      }
    }
  }
}

void MarkCompactCollector::ClearNonTrivialWeakReferences() {
  TRACE_GC(heap_->tracer(),
           GCTracer::Scope::MC_CLEAR_WEAK_REFERENCES_NON_TRIVIAL);
  HeapObjectAndSlot slot;
  Tagged<HeapObjectReference> cleared_weak_ref = ClearedValue(heap_->isolate());
  while (local_weak_objects()->weak_references_non_trivial_unmarked_local.Pop(
      &slot)) {
    // The slot may not have been overwritten since it was filtered, so we can
    // directly read its value.
    Tagged<HeapObject> value = (*slot.slot).GetHeapObjectAssumeWeak();
    DCHECK(!IsWeakCell(value));
    DCHECK(!HeapLayout::InReadOnlySpace(value));
    DCHECK_IMPLIES(v8_flags.black_allocated_pages,
                   !HeapLayout::InBlackAllocatedPage(value));
    DCHECK(!non_atomic_marking_state_->IsMarked(value));
    DCHECK(!MainMarkingVisitor::IsTrivialWeakReferenceValue(slot.heap_object,
                                                            value));
    if (!SpecialClearMapSlot(slot.heap_object, Cast<Map>(value), slot.slot)) {
      slot.slot.store(cleared_weak_ref);
    }
  }
}

void MarkCompactCollector::ClearJSWeakRefs() {
  TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_CLEAR_JS_WEAK_REFERENCES);
  Tagged<JSWeakRef> weak_ref;
  Isolate* const isolate = heap_->isolate();
  while (local_weak_objects()->js_weak_refs_local.Pop(&weak_ref)) {
    Tagged<HeapObject> target = Cast<HeapObject>(weak_ref->target());
    if (MarkingHelper::IsUnmarkedAndNotAlwaysLive(
            heap_, non_atomic_marking_state_, target)) {
      weak_ref->set_target(ReadOnlyRoots(isolate).undefined_value());
    } else {
      // The value of the JSWeakRef is alive.
      ObjectSlot slot = weak_ref->RawField(JSWeakRef::kTargetOffset);
      RecordSlot(weak_ref, slot, target);
    }
  }
  Tagged<WeakCell> weak_cell;
  while (local_weak_objects()->weak_cells_local.Pop(&weak_cell)) {
    auto gc_notify_updated_slot = [](Tagged<HeapObject> object, ObjectSlot slot,
                                     Tagged<Object> target) {
      if (IsHeapObject(target)) {
        RecordSlot(object, slot, Cast<HeapObject>(target));
      }
    };
    Tagged<HeapObject> target = Cast<HeapObject>(weak_cell->target());
    if (MarkingHelper::IsUnmarkedAndNotAlwaysLive(
            heap_, non_atomic_marking_state_, target)) {
      DCHECK(Object::CanBeHeldWeakly(target));
      // The value of the WeakCell is dead.
      Tagged<JSFinalizationRegistry> finalization_registry =
          Cast<JSFinalizationRegistry>(weak_cell->finalization_registry());
      if (!finalization_registry->scheduled_for_cleanup()) {
        heap_->EnqueueDirtyJSFinalizationRegistry(finalization_registry,
                                                  gc_notify_updated_slot);
      }
      // We're modifying the pointers in WeakCell and JSFinalizationRegistry
      // during GC; thus we need to record the slots it writes. The normal write
      // barrier is not enough, since it's disabled before GC.
      weak_cell->Nullify(isolate, gc_notify_updated_slot);
      DCHECK(finalization_registry->NeedsCleanup());
      DCHECK(finalization_registry->scheduled_for_cleanup());
    } else {
      // The value of the WeakCell is alive.
      ObjectSlot slot = weak_cell->RawField(WeakCell::kTargetOffset);
      RecordSlot(weak_cell, slot, Cast<HeapObject>(*slot));
    }

    Tagged<HeapObject> unregister_token = weak_cell->unregister_token();
    if (MarkingHelper::IsUnmarkedAndNotAlwaysLive(
            heap_, non_atomic_marking_state_, unregister_token)) {
      DCHECK(Object::CanBeHeldWeakly(unregister_token));
      // The unregister token is dead. Remove any corresponding entries in the
      // key map. Multiple WeakCell with the same token will have all their
      // unregister_token field set to undefined when processing the first
      // WeakCell. Like above, we're modifying pointers during GC, so record the
      // slots.
      Tagged<JSFinalizationRegistry> finalization_registry =
          Cast<JSFinalizationRegistry>(weak_cell->finalization_registry());
      finalization_registry->RemoveUnregisterToken(
          unregister_token, isolate,
          JSFinalizationRegistry::kKeepMatchedCellsInRegistry,
          gc_notify_updated_slot);
    } else {
      // The unregister_token is alive.
      ObjectSlot slot = weak_cell->RawField(WeakCell::kUnregisterTokenOffset);
      RecordSlot(weak_cell, slot, Cast<HeapObject>(*slot));
    }
  }
  heap_->PostFinalizationRegistryCleanupTaskIfNeeded();
}

// static
bool MarkCompactCollector::ShouldRecordRelocSlot(Tagged<InstructionStream> host,
                                                 RelocInfo* rinfo,
                                                 Tagged<HeapObject> target) {
  MemoryChunk* source_chunk = MemoryChunk::FromHeapObject(host);
  MemoryChunk* target_chunk = MemoryChunk::FromHeapObject(target);
  return target_chunk->IsEvacuationCandidate() &&
         !source_chunk->ShouldSkipEvacuationSlotRecording();
}

// static
MarkCompactCollector::RecordRelocSlotInfo
MarkCompactCollector::ProcessRelocInfo(Tagged<InstructionStream> host,
                                       RelocInfo* rinfo,
                                       Tagged<HeapObject> target) {
  RecordRelocSlotInfo result;
  const RelocInfo::Mode rmode = rinfo->rmode();
  Address addr;
  SlotType slot_type;

  if (rinfo->IsInConstantPool()) {
    addr = rinfo->constant_pool_entry_address();

    if (RelocInfo::IsCodeTargetMode(rmode)) {
      slot_type = SlotType::kConstPoolCodeEntry;
    } else if (RelocInfo::IsCompressedEmbeddedObject(rmode)) {
      slot_type = SlotType::kConstPoolEmbeddedObjectCompressed;
    } else {
      DCHECK(RelocInfo::IsFullEmbeddedObject(rmode));
      slot_type = SlotType::kConstPoolEmbeddedObjectFull;
    }
  } else {
    addr = rinfo->pc();

    if (RelocInfo::IsCodeTargetMode(rmode)) {
      slot_type = SlotType::kCodeEntry;
    } else if (RelocInfo::IsFullEmbeddedObject(rmode)) {
      slot_type = SlotType::kEmbeddedObjectFull;
    } else {
      DCHECK(RelocInfo::IsCompressedEmbeddedObject(rmode));
      slot_type = SlotType::kEmbeddedObjectCompressed;
    }
  }

  MemoryChunk* const source_chunk = MemoryChunk::FromHeapObject(host);
  MutablePageMetadata* const source_page_metadata =
      MutablePageMetadata::cast(source_chunk->Metadata());
  const uintptr_t offset = source_chunk->Offset(addr);
  DCHECK_LT(offset, static_cast<uintptr_t>(TypedSlotSet::kMaxOffset));
  result.page_metadata = source_page_metadata;
  result.slot_type = slot_type;
  result.offset = static_cast<uint32_t>(offset);

  return result;
}

// static
void MarkCompactCollector::RecordRelocSlot(Tagged<InstructionStream> host,
                                           RelocInfo* rinfo,
                                           Tagged<HeapObject> target) {
  if (!ShouldRecordRelocSlot(host, rinfo, target)) return;
  RecordRelocSlotInfo info = ProcessRelocInfo(host, rinfo, target);

  // Access to TypeSlots need to be protected, since LocalHeaps might
  // publish code in the background thread.
  std::optional<base::MutexGuard> opt_guard;
  if (v8_flags.concurrent_sparkplug) {
    opt_guard.emplace(info.page_metadata->mutex());
  }
  RememberedSet<OLD_TO_OLD>::InsertTyped(info.page_metadata, info.slot_type,
                                         info.offset);
}

namespace {

// Missing specialization MakeSlotValue<FullObjectSlot, WEAK>() will turn
// attempt to store a weak reference to strong-only slot to a compilation error.
template <typename TSlot, HeapObjectReferenceType reference_type>
typename TSlot::TObject MakeSlotValue(Tagged<HeapObject> heap_object);

template <>
Tagged<Object> MakeSlotValue<ObjectSlot, HeapObjectReferenceType::STRONG>(
    Tagged<HeapObject> heap_object) {
  return heap_object;
}

template <>
Tagged<MaybeObject>
MakeSlotValue<MaybeObjectSlot, HeapObjectReferenceType::STRONG>(
    Tagged<HeapObject> heap_object) {
  return heap_object;
}

template <>
Tagged<MaybeObject>
MakeSlotValue<MaybeObjectSlot, HeapObjectReferenceType::WEAK>(
    Tagged<HeapObject> heap_object) {
  return MakeWeak(heap_object);
}

template <>
Tagged<Object>
MakeSlotValue<WriteProtectedSlot<ObjectSlot>, HeapObjectReferenceType::STRONG>(
    Tagged<HeapObject> heap_object) {
  return heap_object;
}

#ifdef V8_ENABLE_SANDBOX
template <>
Tagged<Object> MakeSlotValue<WriteProtectedSlot<ProtectedPointerSlot>,
                             HeapObjectReferenceType::STRONG>(
    Tagged<HeapObject> heap_object) {
  return heap_object;
}
#endif

template <>
Tagged<Object>
MakeSlotValue<OffHeapObjectSlot, HeapObjectReferenceType::STRONG>(
    Tagged<HeapObject> heap_object) {
  return heap_object;
}

#ifdef V8_COMPRESS_POINTERS
template <>
Tagged<Object> MakeSlotValue<FullObjectSlot, HeapObjectReferenceType::STRONG>(
    Tagged<HeapObject> heap_object) {
  return heap_object;
}

template <>
Tagged<MaybeObject>
MakeSlotValue<FullMaybeObjectSlot, HeapObjectReferenceType::STRONG>(
    Tagged<HeapObject> heap_object) {
  return heap_object;
}

template <>
Tagged<MaybeObject>
MakeSlotValue<FullMaybeObjectSlot, HeapObjectReferenceType::WEAK>(
    Tagged<HeapObject> heap_object) {
  return MakeWeak(heap_object);
}

#ifdef V8_EXTERNAL_CODE_SPACE
template <>
Tagged<Object>
MakeSlotValue<InstructionStreamSlot, HeapObjectReferenceType::STRONG>(
    Tagged<HeapObject> heap_object) {
  return heap_object;
}
#endif  // V8_EXTERNAL_CODE_SPACE

#ifdef V8_ENABLE_SANDBOX
template <>
Tagged<Object>
MakeSlotValue<ProtectedPointerSlot, HeapObjectReferenceType::STRONG>(
    Tagged<HeapObject> heap_object) {
  return heap_object;
}
#endif  // V8_ENABLE_SANDBOX

// The following specialization
//   MakeSlotValue<FullMaybeObjectSlot, HeapObjectReferenceType::WEAK>()
// is not used.
#endif  // V8_COMPRESS_POINTERS

template <HeapObjectReferenceType reference_type, typename TSlot>
static inline void UpdateSlot(PtrComprCageBase cage_base, TSlot slot,
                              Tagged<HeapObject> heap_obj) {
  static_assert(
      std::is_same<TSlot, FullObjectSlot>::value ||
          std::is_same<TSlot, ObjectSlot>::value ||
          std::is_same<TSlot, FullMaybeObjectSlot>::value ||
          std::is_same<TSlot, MaybeObjectSlot>::value ||
          std::is_same<TSlot, OffHeapObjectSlot>::value ||
          std::is_same<TSlot, InstructionStreamSlot>::value ||
          std::is_same<TSlot, ProtectedPointerSlot>::value ||
          std::is_same<TSlot, WriteProtectedSlot<ObjectSlot>>::value ||
          std::is_same<TSlot, WriteProtectedSlot<ProtectedPointerSlot>>::value,
      "Only [Full|OffHeap]ObjectSlot, [Full]MaybeObjectSlot, "
      "InstructionStreamSlot, ProtectedPointerSlot, or WriteProtectedSlot are "
      "expected here");
  MapWord map_word = heap_obj->map_word(cage_base, kRelaxedLoad);
  if (!map_word.IsForwardingAddress()) return;
  DCHECK_IMPLIES((!v8_flags.minor_ms && !Heap::InFromPage(heap_obj)),
                 MarkCompactCollector::IsOnEvacuationCandidate(heap_obj) ||
                     MemoryChunk::FromHeapObject(heap_obj)->IsFlagSet(
                         MemoryChunk::COMPACTION_WAS_ABORTED));
  typename TSlot::TObject target = MakeSlotValue<TSlot, reference_type>(
      map_word.ToForwardingAddress(heap_obj));
  // Needs to be atomic for map space compaction: This slot could be a map
  // word which we update while loading the map word for updating the slot
  // on another page.
  slot.Relaxed_Store(target);
  DCHECK_IMPLIES(!v8_flags.sticky_mark_bits, !Heap::InFromPage(target));
  DCHECK(!MarkCompactCollector::IsOnEvacuationCandidate(target));
}

template <typename TSlot>
static inline void UpdateSlot(PtrComprCageBase cage_base, TSlot slot) {
  typename TSlot::TObject obj = slot.Relaxed_Load(cage_base);
  Tagged<HeapObject> heap_obj;
  if constexpr (TSlot::kCanBeWeak) {
    if (obj.GetHeapObjectIfWeak(&heap_obj)) {
      return UpdateSlot<HeapObjectReferenceType::WEAK>(cage_base, slot,
                                                       heap_obj);
    }
  }
  if (obj.GetHeapObjectIfStrong(&heap_obj)) {
    UpdateSlot<HeapObjectReferenceType::STRONG>(cage_base, slot, heap_obj);
  }
}

template <typename TSlot>
static inline SlotCallbackResult UpdateOldToSharedSlot(
    PtrComprCageBase cage_base, TSlot slot) {
  typename TSlot::TObject obj = slot.Relaxed_Load(cage_base);
  Tagged<HeapObject> heap_obj;

  if constexpr (TSlot::kCanBeWeak) {
    if (obj.GetHeapObjectIfWeak(&heap_obj)) {
      UpdateSlot<HeapObjectReferenceType::WEAK>(cage_base, slot, heap_obj);
      return HeapLayout::InWritableSharedSpace(heap_obj) ? KEEP_SLOT
                                                         : REMOVE_SLOT;
    }
  }

  if (obj.GetHeapObjectIfStrong(&heap_obj)) {
    UpdateSlot<HeapObjectReferenceType::STRONG>(cage_base, slot, heap_obj);
    return HeapLayout::InWritableSharedSpace(heap_obj) ? KEEP_SLOT
                                                       : REMOVE_SLOT;
  }

  return REMOVE_SLOT;
}

template <typename TSlot>
static inline void UpdateStrongSlot(PtrComprCageBase cage_base, TSlot slot) {
  typename TSlot::TObject obj = slot.Relaxed_Load(cage_base);
#ifdef V8_ENABLE_DIRECT_HANDLE
  if (obj.ptr() == kTaggedNullAddress) return;
#endif
  DCHECK(!HAS_WEAK_HEAP_OBJECT_TAG(obj.ptr()));
  Tagged<HeapObject> heap_obj;
  if (obj.GetHeapObject(&heap_obj)) {
    UpdateSlot<HeapObjectReferenceType::STRONG>(cage_base, slot, heap_obj);
  }
}

static inline SlotCallbackResult UpdateStrongOldToSharedSlot(
    PtrComprCageBase cage_base, FullMaybeObjectSlot slot) {
  Tagged<MaybeObject> obj = slot.Relaxed_Load(cage_base);
#ifdef V8_ENABLE_DIRECT_HANDLE
  if (obj.ptr() == kTaggedNullAddress) return REMOVE_SLOT;
#endif
  DCHECK(!HAS_WEAK_HEAP_OBJECT_TAG(obj.ptr()));
  Tagged<HeapObject> heap_obj;
  if (obj.GetHeapObject(&heap_obj)) {
    UpdateSlot<HeapObjectReferenceType::STRONG>(cage_base, slot, heap_obj);
    return HeapLayout::InWritableSharedSpace(heap_obj) ? KEEP_SLOT
                                                       : REMOVE_SLOT;
  }

  return REMOVE_SLOT;
}

static inline void UpdateStrongCodeSlot(Tagged<HeapObject> host,
                                        PtrComprCageBase cage_base,
                                        PtrComprCageBase code_cage_base,
                                        InstructionStreamSlot slot) {
  Tagged<Object> obj = slot.Relaxed_Load(code_cage_base);
  DCHECK(!HAS_WEAK_HEAP_OBJECT_TAG(obj.ptr()));
  Tagged<HeapObject> heap_obj;
  if (obj.GetHeapObject(&heap_obj)) {
    UpdateSlot<HeapObjectReferenceType::STRONG>(cage_base, slot, heap_obj);

    Tagged<Code> code = Cast<Code>(HeapObject::FromAddress(
        slot.address() - Code::kInstructionStreamOffset));
    Tagged<InstructionStream> instruction_stream =
        code->instruction_stream(code_cage_base);
    code->UpdateInstructionStart(GetIsolateForSandbox(host),
                                 instruction_stream);
  }
}

}  // namespace

// Visitor for updating root pointers and to-space pointers.
// It does not expect to encounter pointers to dead objects.
class PointersUpdatingVisitor final : public ObjectVisitorWithCageBases,
                                      public RootVisitor {
 public:
  explicit PointersUpdatingVisitor(Heap* heap)
      : ObjectVisitorWithCageBases(heap) {}

  void VisitPointer(Tagged<HeapObject> host, ObjectSlot p) override {
    UpdateStrongSlotInternal(cage_base(), p);
  }

  void VisitPointer(Tagged<HeapObject> host, MaybeObjectSlot p) override {
    UpdateSlotInternal(cage_base(), p);
  }

  void VisitPointers(Tagged<HeapObject> host, ObjectSlot start,
                     ObjectSlot end) override {
    for (ObjectSlot p = start; p < end; ++p) {
      UpdateStrongSlotInternal(cage_base(), p);
    }
  }

  void VisitPointers(Tagged<HeapObject> host, MaybeObjectSlot start,
                     MaybeObjectSlot end) final {
    for (MaybeObjectSlot p = start; p < end; ++p) {
      UpdateSlotInternal(cage_base(), p);
    }
  }

  void VisitInstructionStreamPointer(Tagged<Code> host,
                                     InstructionStreamSlot slot) override {
    UpdateStrongCodeSlot(host, cage_base(), code_cage_base(), slot);
  }

  void VisitRootPointer(Root root, const char* description,
                        FullObjectSlot p) override {
    DCHECK(!MapWord::IsPacked(p.Relaxed_Load().ptr()));
    UpdateRootSlotInternal(cage_base(), p);
  }

  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) override {
    for (FullObjectSlot p = start; p < end; ++p) {
      UpdateRootSlotInternal(cage_base(), p);
    }
  }

  void VisitRootPointers(Root root, const char* description,
                         OffHeapObjectSlot start,
                         OffHeapObjectSlot end) override {
    for (OffHeapObjectSlot p = start; p < end; ++p) {
      UpdateRootSlotInternal(cage_base(), p);
    }
  }

  void VisitCodeTarget(Tagged<InstructionStream> host,
                       RelocInfo* rinfo) override {
    // This visitor nevers visits code objects.
    UNREACHABLE();
  }

  void VisitEmbeddedPointer(Tagged<InstructionStream> host,
                            RelocInfo* rinfo) override {
    // This visitor nevers visits code objects.
    UNREACHABLE();
  }

 private:
  static inline void UpdateRootSlotInternal(PtrComprCageBase cage_base,
                                            FullObjectSlot slot) {
    UpdateStrongSlot(cage_base, slot);
  }

  static inline void UpdateRootSlotInternal(PtrComprCageBase cage_base,
                                            OffHeapObjectSlot slot) {
    UpdateStrongSlot(cage_base, slot);
  }

  static inline void UpdateStrongMaybeObjectSlotInternal(
      PtrComprCageBase cage_base, MaybeObjectSlot slot) {
    UpdateStrongSlot(cage_base, slot);
  }

  static inline void UpdateStrongSlotInternal(PtrComprCageBase cage_base,
                                              ObjectSlot slot) {
    UpdateStrongSlot(cage_base, slot);
  }

  static inline void UpdateSlotInternal(PtrComprCageBase cage_base,
                                        MaybeObjectSlot slot) {
    UpdateSlot(cage_base, slot);
  }
};

static Tagged<String> UpdateReferenceInExternalStringTableEntry(
    Heap* heap, FullObjectSlot p) {
  Tagged<HeapObject> old_string = Cast<HeapObject>(*p);
  MapWord map_word = old_string->map_word(kRelaxedLoad);

  if (map_word.IsForwardingAddress()) {
    Tagged<String> new_string =
        Cast<String>(map_word.ToForwardingAddress(old_string));

    if (IsExternalString(new_string)) {
      MutablePageMetadata::MoveExternalBackingStoreBytes(
          ExternalBackingStoreType::kExternalString,
          PageMetadata::FromAddress((*p).ptr()),
          PageMetadata::FromHeapObject(new_string),
          Cast<ExternalString>(new_string)->ExternalPayloadSize());
    }
    return new_string;
  }

  return Cast<String>(*p);
}

void MarkCompactCollector::EvacuatePrologue() {
  // New space.
  if (NewSpace* new_space = heap_->new_space()) {
    DCHECK(new_space_evacuation_pages_.empty());
    std::copy_if(new_space->begin(), new_space->end(),
                 std::back_inserter(new_space_evacuation_pages_),
                 [](PageMetadata* p) { return p->live_bytes() > 0; });
    if (!v8_flags.minor_ms) {
      SemiSpaceNewSpace::From(new_space)->EvacuatePrologue();
    }
  }

  // Large new space.
  if (NewLargeObjectSpace* new_lo_space = heap_->new_lo_space()) {
    new_lo_space->Flip();
    new_lo_space->ResetPendingObject();
  }

  // Old space.
  DCHECK(old_space_evacuation_pages_.empty());
  old_space_evacuation_pages_ = std::move(evacuation_candidates_);
  evacuation_candidates_.clear();
  DCHECK(evacuation_candidates_.empty());
}

void MarkCompactCollector::EvacuateEpilogue() {
  aborted_evacuation_candidates_due_to_oom_.clear();
  aborted_evacuation_candidates_due_to_flags_.clear();

  // New space.
  if (heap_->new_space()) {
    DCHECK_EQ(0, heap_->new_space()->Size());
  }

  // Old generation. Deallocate evacuated candidate pages.
  ReleaseEvacuationCandidates();

#ifdef DEBUG
  VerifyRememberedSetsAfterEvacuation(heap_, GarbageCollector::MARK_COMPACTOR);
#endif  // DEBUG
}

class Evacuator final : public Malloced {
 public:
  enum EvacuationMode {
    kObjectsNewToOld,
    kPageNewToOld,
    kObjectsOldToOld,
  };

  static const char* EvacuationModeName(EvacuationMode mode) {
    switch (mode) {
      case kObjectsNewToOld:
        return "objects-new-to-old";
      case kPageNewToOld:
        return "page-new-to-old";
      case kObjectsOldToOld:
        return "objects-old-to-old";
    }
  }

  static inline EvacuationMode ComputeEvacuationMode(MemoryChunk* chunk) {
    // Note: The order of checks is important in this function.
    if (chunk->IsFlagSet(MemoryChunk::PAGE_NEW_OLD_PROMOTION))
      return kPageNewToOld;
    if (chunk->InYoungGeneration()) return kObjectsNewToOld;
    return kObjectsOldToOld;
  }

  explicit Evacuator(Heap* heap)
      : heap_(heap),
        local_pretenuring_feedback_(
            PretenuringHandler::kInitialFeedbackCapacity),
        local_allocator_(heap_,
                         CompactionSpaceKind::kCompactionSpaceForMarkCompact),
        record_visitor_(heap_),
        new_space_visitor_(heap_, &local_allocator_, &record_visitor_,
                           &local_pretenuring_feedback_),
        new_to_old_page_visitor_(heap_, &record_visitor_,
                                 &local_pretenuring_feedback_),

        old_space_visitor_(heap_, &local_allocator_, &record_visitor_),
        duration_(0.0),
        bytes_compacted_(0) {}

  void EvacuatePage(MutablePageMetadata* chunk);

  void AddObserver(MigrationObserver* observer) {
    new_space_visitor_.AddObserver(observer);
    old_space_visitor_.AddObserver(observer);
  }

  // Merge back locally cached info sequentially. Note that this method needs
  // to be called from the main thread.
  void Finalize();

 private:
  // |saved_live_bytes| returns the live bytes of the page that was processed.
  bool RawEvacuatePage(MutablePageMetadata* chunk);

  inline Heap* heap() { return heap_; }

  void ReportCompactionProgress(double duration, intptr_t bytes_compacted) {
    duration_ += duration;
    bytes_compacted_ += bytes_compacted;
  }

  Heap* heap_;

  PretenuringHandler::PretenuringFeedbackMap local_pretenuring_feedback_;

  // Locally cached collector data.
  EvacuationAllocator local_allocator_;

  RecordMigratedSlotVisitor record_visitor_;

  // Visitors for the corresponding spaces.
  EvacuateNewSpaceVisitor new_space_visitor_;
  EvacuateNewToOldSpacePageVisitor new_to_old_page_visitor_;
  EvacuateOldSpaceVisitor old_space_visitor_;

  // Book keeping info.
  double duration_;
  intptr_t bytes_compacted_;
};

void Evacuator::EvacuatePage(MutablePageMetadata* page) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.gc"), "Evacuator::EvacuatePage");
  DCHECK(page->SweepingDone());
  intptr_t saved_live_bytes = page->live_bytes();
  double evacuation_time = 0.0;
  bool success = false;
  {
    TimedScope timed_scope(&evacuation_time);
    success = RawEvacuatePage(page);
  }
  ReportCompactionProgress(evacuation_time, saved_live_bytes);
  if (v8_flags.trace_evacuation) {
    MemoryChunk* chunk = page->Chunk();
    PrintIsolate(heap_->isolate(),
                 "evacuation[%p]: page=%p new_space=%d "
                 "page_evacuation=%d executable=%d can_promote=%d "
                 "live_bytes=%" V8PRIdPTR " time=%f success=%d\n",
                 static_cast<void*>(this), static_cast<void*>(page),
                 chunk->InNewSpace(),
                 chunk->IsFlagSet(MemoryChunk::PAGE_NEW_OLD_PROMOTION),
                 chunk->IsFlagSet(MemoryChunk::IS_EXECUTABLE),
                 heap_->new_space()->IsPromotionCandidate(page),
                 saved_live_bytes, evacuation_time, success);
  }
}

void Evacuator::Finalize() {
  local_allocator_.Finalize();
  heap_->tracer()->AddCompactionEvent(duration_, bytes_compacted_);
  heap_->IncrementPromotedObjectsSize(new_space_visitor_.promoted_size() +
                                      new_to_old_page_visitor_.moved_bytes());
  heap_->IncrementNewSpaceSurvivingObjectSize(
      new_space_visitor_.semispace_copied_size());
  heap_->IncrementYoungSurvivorsCounter(
      new_space_visitor_.promoted_size() +
      new_space_visitor_.semispace_copied_size() +
      new_to_old_page_visitor_.moved_bytes());
  heap_->pretenuring_handler()->MergeAllocationSitePretenuringFeedback(
      local_pretenuring_feedback_);
}

class LiveObjectVisitor final : AllStatic {
 public:
  // Visits marked objects using `bool Visitor::Visit(HeapObject object, size_t
  // size)` as long as the return value is true.
  //
  // Returns whether all objects were successfully visited. Upon returning
  // false, also sets `failed_object` to the object for which the visitor
  // returned false.
  template <class Visitor>
  static bool VisitMarkedObjects(PageMetadata* page, Visitor* visitor,
                                 Tagged<HeapObject>* failed_object);

  // Visits marked objects using `bool Visitor::Visit(HeapObject object, size_t
  // size)` as long as the return value is true. Assumes that the return value
  // is always true (success).
  template <class Visitor>
  static void VisitMarkedObjectsNoFail(PageMetadata* page, Visitor* visitor);
};

template <class Visitor>
bool LiveObjectVisitor::VisitMarkedObjects(PageMetadata* page, Visitor* visitor,
                                           Tagged<HeapObject>* failed_object) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.gc"),
               "LiveObjectVisitor::VisitMarkedObjects");
  for (auto [object, size] : LiveObjectRange(page)) {
    if (!visitor->Visit(object, size)) {
      *failed_object = object;
      return false;
    }
  }
  return true;
}

template <class Visitor>
void LiveObjectVisitor::VisitMarkedObjectsNoFail(PageMetadata* page,
                                                 Visitor* visitor) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.gc"),
               "LiveObjectVisitor::VisitMarkedObjectsNoFail");
  for (auto [object, size] : LiveObjectRange(page)) {
    const bool success = visitor->Visit(object, size);
    USE(success);
    DCHECK(success);
  }
}

bool Evacuator::RawEvacuatePage(MutablePageMetadata* page) {
  MemoryChunk* chunk = page->Chunk();
  const EvacuationMode evacuation_mode = ComputeEvacuationMode(chunk);
  TRACE_EVENT2(TRACE_DISABLED_BY_DEFAULT("v8.gc"),
               "FullEvacuator::RawEvacuatePage", "evacuation_mode",
               EvacuationModeName(evacuation_mode), "live_bytes",
               page->live_bytes());
  switch (evacuation_mode) {
    case kObjectsNewToOld:
#if DEBUG
      new_space_visitor_.DisableAbortEvacuationAtAddress(page);
#endif  // DEBUG
      LiveObjectVisitor::VisitMarkedObjectsNoFail(PageMetadata::cast(page),
                                                  &new_space_visitor_);
      page->ClearLiveness();
      break;
    case kPageNewToOld:
      if (chunk->IsLargePage()) {
        auto object = LargePageMetadata::cast(page)->GetObject();
        bool success = new_to_old_page_visitor_.Visit(object, object->Size());
        USE(success);
        DCHECK(success);
      } else {
        LiveObjectVisitor::VisitMarkedObjectsNoFail(PageMetadata::cast(page),
                                                    &new_to_old_page_visitor_);
      }
      new_to_old_page_visitor_.account_moved_bytes(page->live_bytes());
      break;
    case kObjectsOldToOld: {
#if DEBUG
      old_space_visitor_.SetUpAbortEvacuationAtAddress(page);
#endif  // DEBUG
      Tagged<HeapObject> failed_object;
      if (LiveObjectVisitor::VisitMarkedObjects(
              PageMetadata::cast(page), &old_space_visitor_, &failed_object)) {
        page->ClearLiveness();
      } else {
        // Aborted compaction page. Actual processing happens on the main
        // thread for simplicity reasons.
        heap_->mark_compact_collector()
            ->ReportAbortedEvacuationCandidateDueToOOM(
                failed_object.address(), static_cast<PageMetadata*>(page));
        return false;
      }
      break;
    }
  }

  return true;
}

class PageEvacuationJob : public v8::JobTask {
 public:
  PageEvacuationJob(
      Isolate* isolate, MarkCompactCollector* collector,
      std::vector<std::unique_ptr<Evacuator>>* evacuators,
      std::vector<std::pair<ParallelWorkItem, MutablePageMetadata*>>
          evacuation_items)
      : collector_(collector),
        evacuators_(evacuators),
        evacuation_items_(std::move(evacuation_items)),
        remaining_evacuation_items_(evacuation_items_.size()),
        generator_(evacuation_items_.size()),
        tracer_(isolate->heap()->tracer()),
        trace_id_(reinterpret_cast<uint64_t>(this) ^
                  tracer_->CurrentEpoch(GCTracer::Scope::MC_EVACUATE)) {}

  void Run(JobDelegate* delegate) override {
    // In case multi-cage pointer compression mode is enabled ensure that
    // current thread's cage base values are properly initialized.
    PtrComprCageAccessScope ptr_compr_cage_access_scope(
        collector_->heap()->isolate());

    Evacuator* evacuator = (*evacuators_)[delegate->GetTaskId()].get();
    if (delegate->IsJoiningThread()) {
      TRACE_GC_WITH_FLOW(tracer_, GCTracer::Scope::MC_EVACUATE_COPY_PARALLEL,
                         trace_id_, TRACE_EVENT_FLAG_FLOW_IN);
      ProcessItems(delegate, evacuator);
    } else {
      TRACE_GC_EPOCH_WITH_FLOW(
          tracer_, GCTracer::Scope::MC_BACKGROUND_EVACUATE_COPY,
          ThreadKind::kBackground, trace_id_, TRACE_EVENT_FLAG_FLOW_IN);
      ProcessItems(delegate, evacuator);
    }
  }

  void ProcessItems(JobDelegate* delegate, Evacuator* evacuator) {
    while (remaining_evacuation_items_.load(std::memory_order_relaxed) > 0) {
      std::optional<size_t> index = generator_.GetNext();
      if (!index) return;
      for (size_t i = *index; i < evacuation_items_.size(); ++i) {
        auto& work_item = evacuation_items_[i];
        if (!work_item.first.TryAcquire()) break;
        evacuator->EvacuatePage(work_item.second);
        if (remaining_evacuation_items_.fetch_sub(
                1, std::memory_order_relaxed) <= 1) {
          return;
        }
      }
    }
  }

  size_t GetMaxConcurrency(size_t worker_count) const override {
    const size_t kItemsPerWorker = std::max(1, MB / PageMetadata::kPageSize);
    // Ceiling division to ensure enough workers for all
    // |remaining_evacuation_items_|
    size_t wanted_num_workers =
        (remaining_evacuation_items_.load(std::memory_order_relaxed) +
         kItemsPerWorker - 1) /
        kItemsPerWorker;
    wanted_num_workers =
        std::min<size_t>(wanted_num_workers, evacuators_->size());
    if (!collector_->UseBackgroundThreadsInCycle()) {
      return std::min<size_t>(wanted_num_workers, 1);
    }
    return wanted_num_workers;
  }

  uint64_t trace_id() const { return trace_id_; }

 private:
  MarkCompactCollector* collector_;
  std::vector<std::unique_ptr<Evacuator>>* evacuators_;
  std::vector<std::pair<ParallelWorkItem, MutablePageMetadata*>>
      evacuation_items_;
  std::atomic<size_t> remaining_evacuation_items_{0};
  IndexGenerator generator_;

  GCTracer* tracer_;
  const uint64_t trace_id_;
};

namespace {
size_t CreateAndExecuteEvacuationTasks(
    Heap* heap, MarkCompactCollector* collector,
    std::vector<std::pair<ParallelWorkItem, MutablePageMetadata*>>
        evacuation_items) {
  std::optional<ProfilingMigrationObserver> profiling_observer;
  if (heap->isolate()->log_object_relocation()) {
    profiling_observer.emplace(heap);
  }
  std::vector<std::unique_ptr<v8::internal::Evacuator>> evacuators;
  const int wanted_num_tasks = NumberOfParallelCompactionTasks(heap);
  for (int i = 0; i < wanted_num_tasks; i++) {
    auto evacuator = std::make_unique<Evacuator>(heap);
    if (profiling_observer) {
      evacuator->AddObserver(&profiling_observer.value());
    }
    evacuators.push_back(std::move(evacuator));
  }
  auto page_evacuation_job = std::make_unique<PageEvacuationJob>(
      heap->isolate(), collector, &evacuators, std::move(evacuation_items));
  TRACE_GC_NOTE_WITH_FLOW("PageEvacuationJob started",
                          page_evacuation_job->trace_id(),
                          TRACE_EVENT_FLAG_FLOW_OUT);
  V8::GetCurrentPlatform()
      ->CreateJob(v8::TaskPriority::kUserBlocking,
                  std::move(page_evacuation_job))
      ->Join();
  for (auto& evacuator : evacuators) {
    evacuator->Finalize();
  }
  return wanted_num_tasks;
}

enum class MemoryReductionMode { kNone, kShouldReduceMemory };

// NewSpacePages with more live bytes than this threshold qualify for fast
// evacuation.
intptr_t NewSpacePageEvacuationThreshold() {
  return v8_flags.page_promotion_threshold *
         MemoryChunkLayout::AllocatableMemoryInDataPage() / 100;
}

bool ShouldMovePage(PageMetadata* p, intptr_t live_bytes,
                    MemoryReductionMode memory_reduction_mode) {
  Heap* heap = p->heap();
  DCHECK(!p->Chunk()->NeverEvacuate());
  const bool should_move_page =
      v8_flags.page_promotion &&
      (memory_reduction_mode == MemoryReductionMode::kNone) &&
      (live_bytes > NewSpacePageEvacuationThreshold()) &&
      heap->CanExpandOldGeneration(live_bytes);
  if (v8_flags.trace_page_promotions) {
    PrintIsolate(heap->isolate(),
                 "[Page Promotion] %p: collector=mc, should move: %d"
                 ", live bytes = %zu, promotion threshold = %zu"
                 ", allocated labs size = %zu\n",
                 p, should_move_page, live_bytes,
                 NewSpacePageEvacuationThreshold(), p->AllocatedLabSize());
  }
  return should_move_page;
}

void TraceEvacuation(Isolate* isolate, size_t pages_count,
                     size_t wanted_num_tasks, size_t live_bytes,
                     size_t aborted_pages) {
  DCHECK(v8_flags.trace_evacuation);
  PrintIsolate(
      isolate,
      "%8.0f ms: evacuation-summary: parallel=%s pages=%zu "
      "wanted_tasks=%zu cores=%d live_bytes=%" V8PRIdPTR
      " compaction_speed=%.f aborted=%zu\n",
      isolate->time_millis_since_init(),
      v8_flags.parallel_compaction ? "yes" : "no", pages_count,
      wanted_num_tasks, V8::GetCurrentPlatform()->NumberOfWorkerThreads() + 1,
      live_bytes,
      isolate->heap()->tracer()->CompactionSpeedInBytesPerMillisecond(),
      aborted_pages);
}

}  // namespace

void MarkCompactCollector::EvacuatePagesInParallel() {
  std::vector<std::pair<ParallelWorkItem, MutablePageMetadata*>>
      evacuation_items;
  intptr_t live_bytes = 0;

  // Evacuation of new space pages cannot be aborted, so it needs to run
  // before old space evacuation.
  bool force_page_promotion =
      heap_->IsGCWithStack() && !v8_flags.compact_with_stack;
  for (PageMetadata* page : new_space_evacuation_pages_) {
    intptr_t live_bytes_on_page = page->live_bytes();
    DCHECK_LT(0, live_bytes_on_page);
    live_bytes += live_bytes_on_page;
    MemoryReductionMode memory_reduction_mode =
        heap_->ShouldReduceMemory() ? MemoryReductionMode::kShouldReduceMemory
                                    : MemoryReductionMode::kNone;
    if (ShouldMovePage(page, live_bytes_on_page, memory_reduction_mode) ||
        force_page_promotion) {
      EvacuateNewToOldSpacePageVisitor::Move(page);
      page->Chunk()->SetFlagNonExecutable(MemoryChunk::PAGE_NEW_OLD_PROMOTION);
      DCHECK_EQ(heap_->old_space(), page->owner());
      // The move added page->allocated_bytes to the old space, but we are
      // going to sweep the page and add page->live_byte_count.
      heap_->old_space()->DecreaseAllocatedBytes(page->allocated_bytes(), page);
    }
    evacuation_items.emplace_back(ParallelWorkItem{}, page);
  }

  if (heap_->IsGCWithStack()) {
    if (!v8_flags.compact_with_stack) {
      for (PageMetadata* page : old_space_evacuation_pages_) {
        ReportAbortedEvacuationCandidateDueToFlags(page->area_start(), page);
      }
    } else if (!v8_flags.compact_code_space_with_stack ||
               heap_->isolate()->InFastCCall()) {
      // For fast C calls we cannot patch the return address in the native stack
      // frame if we would relocate InstructionStream objects.
      for (PageMetadata* page : old_space_evacuation_pages_) {
        if (page->owner_identity() != CODE_SPACE) continue;
        ReportAbortedEvacuationCandidateDueToFlags(page->area_start(), page);
      }
    }
  } else {
    // There should always be a stack when we are in a fast c call.
    DCHECK(!heap_->isolate()->InFastCCall());
  }

  if (v8_flags.stress_compaction || v8_flags.stress_compaction_random) {
    // Stress aborting of evacuation by aborting ~10% of evacuation candidates
    // when stress testing.
    const double kFraction = 0.05;

    for (PageMetadata* page : old_space_evacuation_pages_) {
      MemoryChunk* chunk = page->Chunk();
      if (chunk->IsFlagSet(MemoryChunk::COMPACTION_WAS_ABORTED)) continue;

      if (heap_->isolate()->fuzzer_rng()->NextDouble() < kFraction) {
        ReportAbortedEvacuationCandidateDueToFlags(page->area_start(), page);
      }
    }
  }

  for (PageMetadata* page : old_space_evacuation_pages_) {
    MemoryChunk* chunk = page->Chunk();
    if (chunk->IsFlagSet(MemoryChunk::COMPACTION_WAS_ABORTED)) continue;

    live_bytes += page->live_bytes();
    evacuation_items.emplace_back(ParallelWorkItem{}, page);
  }

  // Promote young generation large objects.
  if (auto* new_lo_space = heap_->new_lo_space()) {
    for (auto it = new_lo_space->begin(); it != new_lo_space->end();) {
      LargePageMetadata* current = *(it++);
      Tagged<HeapObject> object = current->GetObject();
      // The black-allocated flag was already cleared in SweepLargeSpace().
      DCHECK_IMPLIES(v8_flags.black_allocated_pages,
                     !HeapLayout::InBlackAllocatedPage(object));
      if (marking_state_->IsMarked(object)) {
        heap_->lo_space()->PromoteNewLargeObject(current);
        current->Chunk()->SetFlagNonExecutable(
            MemoryChunk::PAGE_NEW_OLD_PROMOTION);
        promoted_large_pages_.push_back(current);
        evacuation_items.emplace_back(ParallelWorkItem{}, current);
      }
    }
    new_lo_space->set_objects_size(0);
  }

  const size_t pages_count = evacuation_items.size();
  size_t wanted_num_tasks = 0;
  if (!evacuation_items.empty()) {
    TRACE_EVENT1(TRACE_DISABLED_BY_DEFAULT("v8.gc"),
                 "MarkCompactCollector::EvacuatePagesInParallel", "pages",
                 evacuation_items.size());

    wanted_num_tasks = CreateAndExecuteEvacuationTasks(
        heap_, this, std::move(evacuation_items));
  }

  const size_t aborted_pages = PostProcessAbortedEvacuationCandidates();

  if (v8_flags.trace_evacuation) {
    TraceEvacuation(heap_->isolate(), pages_count, wanted_num_tasks, live_bytes,
                    aborted_pages);
  }
}

class EvacuationWeakObjectRetainer : public WeakObjectRetainer {
 public:
  Tagged<Object> RetainAs(Tagged<Object> object) override {
    if (object.IsHeapObject()) {
      Tagged<HeapObject> heap_object = Cast<HeapObject>(object);
      MapWord map_word = heap_object->map_word(kRelaxedLoad);
      if (map_word.IsForwardingAddress()) {
        return map_word.ToForwardingAddress(heap_object);
      }
    }
    return object;
  }
};

void MarkCompactCollector::Evacuate() {
  TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_EVACUATE);
  base::MutexGuard guard(heap_->relocation_mutex());

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_EVACUATE_PROLOGUE);
    EvacuatePrologue();
  }

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_EVACUATE_COPY);
    EvacuatePagesInParallel();
  }

  UpdatePointersAfterEvacuation();

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_EVACUATE_CLEAN_UP);

    for (PageMetadata* p : new_space_evacuation_pages_) {
      MemoryChunk* chunk = p->Chunk();
      AllocationSpace owner_identity = p->owner_identity();
      USE(owner_identity);
      if (chunk->IsFlagSet(MemoryChunk::PAGE_NEW_OLD_PROMOTION)) {
        chunk->ClearFlagNonExecutable(MemoryChunk::PAGE_NEW_OLD_PROMOTION);
        // The in-sandbox page flags may be corrupted, so we currently need
        // this check here to make sure that this doesn't lead to further
        // confusion about the state of MemoryChunkMetadata objects.
        // TODO(377724745): if we move (some of) the flags into the trusted
        // MemoryChunkMetadata object, then this wouldn't be necessary.
        SBXCHECK_EQ(OLD_SPACE, owner_identity);
        sweeper_->AddPage(OLD_SPACE, p);
      } else if (v8_flags.minor_ms) {
        // Sweep non-promoted pages to add them back to the free list.
        DCHECK_EQ(NEW_SPACE, owner_identity);
        DCHECK_EQ(0, p->live_bytes());
        DCHECK(p->SweepingDone());
        PagedNewSpace* space = heap_->paged_new_space();
        if (space->ShouldReleaseEmptyPage()) {
          space->ReleasePage(p);
        } else {
          sweeper_->SweepEmptyNewSpacePage(p);
        }
      }
    }
    new_space_evacuation_pages_.clear();

    for (LargePageMetadata* p : promoted_large_pages_) {
      MemoryChunk* chunk = p->Chunk();
      DCHECK(chunk->IsFlagSet(MemoryChunk::PAGE_NEW_OLD_PROMOTION));
      chunk->ClearFlagNonExecutable(MemoryChunk::PAGE_NEW_OLD_PROMOTION);
      Tagged<HeapObject> object = p->GetObject();
      if (!v8_flags.sticky_mark_bits) {
        MarkBit::From(object).Clear();
        p->SetLiveBytes(0);
      }
      p->MarkingProgressTracker().ResetIfEnabled();
    }
    promoted_large_pages_.clear();

    for (PageMetadata* p : old_space_evacuation_pages_) {
      MemoryChunk* chunk = p->Chunk();
      if (chunk->IsFlagSet(MemoryChunk::COMPACTION_WAS_ABORTED)) {
        sweeper_->AddPage(p->owner_identity(), p);
        chunk->ClearFlagSlow(MemoryChunk::COMPACTION_WAS_ABORTED);
      }
    }
  }

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_EVACUATE_EPILOGUE);
    EvacuateEpilogue();
  }

#ifdef VERIFY_HEAP
  if (v8_flags.verify_heap && !sweeper_->sweeping_in_progress()) {
    EvacuationVerifier verifier(heap_);
    verifier.Run();
  }
#endif  // VERIFY_HEAP
}

class UpdatingItem : public ParallelWorkItem {
 public:
  virtual ~UpdatingItem() = default;
  virtual void Process() = 0;
};

class PointersUpdatingJob : public v8::JobTask {
 public:
  explicit PointersUpdatingJob(
      Isolate* isolate, MarkCompactCollector* collector,
      std::vector<std::unique_ptr<UpdatingItem>> updating_items)
      : collector_(collector),
        updating_items_(std::move(updating_items)),
        remaining_updating_items_(updating_items_.size()),
        generator_(updating_items_.size()),
        tracer_(isolate->h
"""


```