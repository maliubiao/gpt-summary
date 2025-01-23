Response:
My thought process to arrive at the summarized functionality of the provided C++ code snippet goes like this:

1. **Identify the File:** The code is from `v8/src/heap/mark-compact.cc`. The "mark-compact" part immediately signals involvement in garbage collection.

2. **Scan for Key Terms and Patterns:** I look for recurring terms and patterns that indicate the code's purpose. Some obvious ones jump out:
    * `Flush`:  Appears with `Bytecode`, `BaselineCode`, `SFI` (SharedFunctionInfo). This suggests code removal or invalidation.
    * `ProcessOldCodeCandidates`, `ProcessOldBytecodeSFI`, `ProcessOldBaselineSFI`:  More confirmation of dealing with "old" code.
    * `MarkingHelper::IsMarkedOrAlwaysLive`: This strongly points to the marking phase of garbage collection, checking if objects are still reachable.
    * `UncompiledData`:  This suggests a state before code is fully compiled.
    * `RecordSlot`:  This hints at updating references between objects, crucial for GC.
    * `Clear`: Used with `FlushedJsFunctions`, `FullMapTransitions`, `WeakCollections`, `WeakReferences`, `JSWeakRefs`. This clearly indicates removing or clearing data related to these concepts.
    * `TransitionArray`, `DescriptorArray`: These are V8 internal data structures related to object structure and property access.
    * `Weak`: Preceding many collection types (`WeakCollections`, `WeakReferences`, `JSWeakRefs`, `WeakCell`). This signifies dealing with objects that don't prevent garbage collection.
    * `FinalizationRegistry`:  Part of the weak object management system in JavaScript.
    * `RelocInfo`, `InstructionStream`: Relates to code patching and relocation during garbage collection.

3. **Group Related Operations:** Based on the identified terms, I start grouping related actions:
    * **Code Flushing:** `ProcessOldCodeCandidates`, `ProcessOldBytecodeSFI`, `ProcessOldBaselineSFI`, `FlushSFI`, `ClearFlushedJsFunctions`, `ProcessFlushedBaselineCandidates`. This group deals with removing compiled code (bytecode or baseline) from `SharedFunctionInfo` and associated `JSFunction` objects.
    * **Weak Object Handling:** `ClearWeakCollections`, `ClearTrivialWeakReferences`, `FilterNonTrivialWeakReferences`, `ClearNonTrivialWeakReferences`, `ClearJSWeakRefs`. This group focuses on managing weak references and weak collections, removing entries where the referenced object is no longer live.
    * **Map/Transition Array Compaction:** `ClearFullMapTransitions`, `CompactTransitionArray`, `RightTrimDescriptorArray`, `TrimDescriptorArray`, `TrimEnumCache`. This is about optimizing the data structures related to object shapes and transitions between them.
    * **Relocation Information:** `RecordRelocSlot`, `ProcessRelocInfo`. This focuses on updating references within compiled code.

4. **Infer High-Level Functionality:**  From the grouped operations, I infer the high-level goals:
    * **Code Optimization/Memory Saving:** Flushing bytecode and baseline code reduces memory usage by removing compiled code that might not be needed anymore.
    * **Correctness of Weak References:**  Clearing weak references ensures that they don't point to garbage-collected objects, maintaining the expected behavior of weak references in JavaScript.
    * **Efficiency of Object Access:** Compacting transition arrays and descriptor arrays optimizes how V8 looks up object properties.
    * **Maintaining Code Integrity:**  Recording relocation slots ensures that pointers within compiled code are updated correctly after objects are moved during garbage collection.

5. **Relate to JavaScript (if applicable):**  I consider how these low-level operations manifest in JavaScript:
    * Code flushing is related to JavaScript's ability to lazily compile functions. Functions might be de-optimized if they haven't been used recently.
    * Weak references and finalization registries are directly exposed as JavaScript features.
    * While transition arrays and descriptor arrays aren't directly exposed, their optimization contributes to the overall performance of JavaScript object manipulation.

6. **Consider Edge Cases and Assumptions:**  I notice checks for `v8_flags` which indicate conditional execution based on V8's internal flags. This highlights that certain optimizations or behaviors might be enabled or disabled. The presence of `#ifdef V8_ENABLE_SANDBOX` suggests considerations for security sandboxing.

7. **Synthesize the Summary:** I combine the inferred functionalities into a concise summary, focusing on the main purposes of the code. I use clear and understandable language, avoiding excessive technical jargon where possible. I also address the specific instructions in the prompt (Torque, JavaScript examples, code logic, common errors).

8. **Review and Refine:** I reread the code and my summary, ensuring accuracy and completeness. I check if the summary captures the core actions and their motivations. I make sure to address all the explicit points raised in the prompt. For instance, I initially might have missed the nuances of how `RecordSlot` is used in different contexts, so I'd refine the explanation to be more precise. I also double-check if the JavaScript examples are relevant and accurate.

This iterative process of scanning, grouping, inferring, relating, and refining helps me construct a comprehensive and accurate summary of the code's functionality.
这是对 `v8/src/heap/mark-compact.cc` 文件中一部分代码的分析，主要关注的是 Mark-Compact 垃圾回收器在处理代码对象、弱引用以及对象形状优化方面的功能。

**功能归纳：**

这部分代码主要负责在 Mark-Compact 垃圾回收周期的特定阶段执行以下关键任务：

1. **代码清除（Code Flushing）：**
   - 识别并清除不再活跃的编译代码（包括字节码和基线代码）。
   - 将 `SharedFunctionInfo` 对象中的已清除代码的相关数据（如字节码数组）替换为 `UncompiledData` 对象，以便在需要时重新编译。
   - 更新引用这些 `SharedFunctionInfo` 的 `JSFunction` 对象，使其指向新的 `UncompiledData` 或仍然存活的代码。

2. **弱引用处理（Weak Reference Handling）：**
   - 清除指向已回收对象的弱引用，包括 `EphemeronHashTable` 中的条目、简单的弱引用（`weak_references_trivial_local`）、非简单的弱引用（`weak_references_non_trivial_local`）以及 `JSWeakRef` 和 `WeakCell` 对象。
   - 对于 `WeakCell`，如果其目标对象被回收，则将其与关联的 `JSFinalizationRegistry` 连接，以便在后续进行清理操作。

3. **对象形状优化（Object Shape Optimization）：**
   - 清理不再需要的 Map 之间的转换信息（`TransitionArray`）。
   - 压缩 `TransitionArray`，移除指向已回收 Map 的转换。
   - 裁剪 `DescriptorArray`，移除不再使用的属性描述符。
   - 裁剪枚举缓存 (`EnumCache`)，使其只包含仍然存在的属性。

4. **记录代码对象的重定位信息（Relocation Information）：**
   - 在代码移动后，记录代码对象中的重定位槽位，以便在需要时更新这些槽位中的指针。

**关于代码特性：**

* **.tq 扩展名：**  根据描述，如果 `v8/src/heap/mark-compact.cc` 以 `.tq` 结尾，则它是 Torque 源代码。但这里明确指出是 `.cc` 文件，所以它是 **C++ 源代码**。

* **与 JavaScript 的关系：** 这段代码直接影响 JavaScript 的执行效率和内存管理。
    - **代码清除**使得 V8 可以回收不再使用的编译代码占用的内存，从而节省资源。这与 JavaScript 引擎的优化策略密切相关，例如，对于不常执行的代码，可以将其降级为未编译状态。
    - **弱引用处理**实现了 JavaScript 中 `WeakRef` 和 `FinalizationRegistry` 等功能的基础。开发者可以使用这些特性来创建不会阻止垃圾回收的对象引用。
    - **对象形状优化**提升了 JavaScript 属性访问的性能。通过压缩和裁剪 `TransitionArray` 和 `DescriptorArray`，V8 可以更快地找到对象的属性。

**JavaScript 示例：**

虽然这段 C++ 代码本身不直接是 JavaScript，但它可以说明 JavaScript 中弱引用和代码优化的概念：

```javascript
// 弱引用
let target = { name: 'John' };
const weakRef = new WeakRef(target);

// 当 target 不再被强引用时，可能会被垃圾回收
target = null;

// 在某个时间点尝试获取弱引用指向的对象
const dereferenced = weakRef.deref();
if (dereferenced) {
  console.log(dereferenced.name); // 可能输出 "John"，也可能因为 target 已被回收而输出 undefined
}

// FinalizationRegistry (与 WeakCell 相关)
const registry = new FinalizationRegistry((heldValue) => {
  console.log('对象被回收了:', heldValue);
});

let objectToWatch = { id: 1 };
registry.register(objectToWatch, 'my-watched-object');

objectToWatch = null; // 当 objectToWatch 不再被强引用时，注册的回调函数最终会被调用

// 代码优化（虽然不可直接观察，但 Mark-Compact 的代码清除会影响性能）
function expensiveFunction() {
  // 一段复杂的计算
  for (let i = 0; i < 1000000; i++) {
    // ...
  }
}

// 如果 expensiveFunction 不常被调用，V8 可能会清除其编译后的代码
```

**代码逻辑推理（假设输入与输出）：**

假设我们有一个 `SharedFunctionInfo` 对象 `sfi`，它关联了一个很大的 `BytecodeArray`，并且该函数不再被任何活跃的执行上下文引用。

**输入：**
- `sfi`: 指向一个不再活跃的 `SharedFunctionInfo` 对象的指针。
- `non_atomic_marking_state_`:  当前的标记状态，指示 `BytecodeArray` 未被标记为活跃。
- `v8_flags.flush_bytecode` 为 true。

**执行 `ProcessOldBytecodeSFI(sfi)` 后的输出：**
- `sfi->HasUncompiledData()` 将为 true。
- `sfi` 内部指向 `BytecodeArray` 的指针将被替换为一个指向 `UncompiledData` 对象的指针。
- 函数 `ProcessOldBytecodeSFI` 返回 `false`，表示字节码已被清除。

**用户常见的编程错误：**

1. **意外地依赖被弱引用的对象仍然存在：**

   ```javascript
   let cache = new WeakMap();

   function getCachedData(key) {
     if (cache.has(key)) {
       return cache.get(key);
     }
     const data = fetchData(key); // 假设 fetchData 返回一些数据
     cache.set(key, data);
     return data;
   }

   let myKey = { id: 1 };
   let cachedData = getCachedData(myKey);
   console.log(cachedData);

   myKey = null; // 此时如果发生 GC，WeakMap 中的 myKey 可能会被清除

   // 之后再次调用 getCachedData(myKey) 可能需要重新获取数据，
   // 因为之前的缓存条目可能已被清除。
   ```

   **错误：**  程序员可能错误地认为只要 `getCachedData` 函数还在使用，`WeakMap` 中的数据就一定存在。实际上，如果 `myKey` 指向的对象不再被强引用，它可能会被垃圾回收，导致 `WeakMap` 中的条目消失。

2. **在 FinalizationRegistry 的回调中访问可能已经被回收的对象：**

   ```javascript
   const registry = new FinalizationRegistry((heldValue) => {
     console.log('对象被回收了:', heldValue.name); // 错误：heldValue 可能已经被部分回收，访问其属性可能出错
   });

   let obj = { name: 'Test' };
   registry.register(obj, obj);
   obj = null;
   ```

   **错误：**  FinalizationRegistry 的回调函数在对象被回收后执行，此时对象可能已经处于部分回收状态，访问其属性是不安全的。回调函数应该处理对象已经被回收的情况。

**总结该部分的功能：**

这段 `v8/src/heap/mark-compact.cc` 代码片段在 Mark-Compact 垃圾回收过程中扮演着至关重要的角色，负责：

- **回收不再使用的代码占用的内存，**通过清除过时的字节码和基线代码，为运行中的程序释放资源。
- **正确管理弱引用，**确保弱引用不会阻止对象的回收，并为 JavaScript 的 `WeakRef` 和 `FinalizationRegistry` 提供底层支持。
- **优化对象结构，**通过压缩和裁剪 `TransitionArray` 和 `DescriptorArray`，提高对象属性访问的效率。
- **维护代码完整性，**记录和更新代码对象中的重定位信息，确保代码在内存移动后仍然可以正确执行。

这些功能共同作用，保证了 V8 引擎能够高效、稳定地运行 JavaScript 代码，并有效地利用内存资源。

### 提示词
```
这是目录为v8/src/heap/mark-compact.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/mark-compact.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
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
      std::is_same<TSlot, FullObjectSl
```