Response:
The user wants a summary of the provided C++ code file `v8/src/builtins/builtins-internal-gen.cc`. The request has several constraints:

1. **List Functionality:** Enumerate the features implemented in the code.
2. **Torque Source:** Check if the filename suggests it's a Torque file (it doesn't, as it ends with `.cc`).
3. **JavaScript Relation:** If the code relates to JavaScript functionality, provide a JavaScript example.
4. **Code Logic Inference:** If there's logical deduction based on input, provide example inputs and outputs.
5. **Common Programming Errors:** Point out potential mistakes developers might make that this code addresses.
6. **Part 1 Summary:**  Since this is part 1 of 3, summarize the functionality of *this specific part*.

Let's break down the code section by section to identify its functions:

* **Includes:** The initial `#include` statements indicate the code interacts with various V8 components like API, baseline compiler, builtins utilities, code generation, heap management, IC (Inline Cache), logging, and object representation.

* **`CopyFastSmiOrObjectElements`:** This function seems to create a copy of an object's elements array.

* **`GrowFastDoubleElements` and `GrowFastSmiOrObjectElements`:** These functions appear to handle growing the internal array used to store object elements. They have a fast path and a slower "runtime" path.

* **`ReturnReceiver`:**  A simple function that returns the received object.

* **`DebugBreakTrampoline`:** This is related to debugging, specifically handling breakpoints at the entry of a function. It checks a flag and can call the debugger.

* **`WriteBarrierCodeStubAssembler`:** This class is crucial. It implements various write barrier mechanisms for garbage collection. It checks for marking phases (major and minor), shared heaps, and inserts objects into remembered sets. It has logic for different scenarios during garbage collection. The functions within this class include:
    * `IsMarking`, `IsMinorMarking`, `IsSharedSpaceIsolate`, `UsesSharedHeap`, `IsUnmarked`:  Functions to check GC state.
    * `InsertIntoRememberedSet`: Adds an object to the remembered set.
    * `LoadSlotSet`, `LoadBucket`, `SetBitInCell`: Helper functions for interacting with the slot set.
    * `WriteBarrier`: The main write barrier logic, delegating to other specific barriers.
    * `IndirectPointerWriteBarrier`: Handles write barriers for indirect pointers.
    * `GenerationalOrSharedBarrierSlow`, `GenerationalBarrierSlow`, `SharedBarrierSlow`: Implement different parts of the write barrier when incremental marking is off.
    * `WriteBarrierDuringMarking`, `GenerationalOrSharedBarrierDuringMarking`: Implement write barrier logic when incremental marking is on.
    * `InYoungGeneration`, `InSharedHeap`: Check object age and location.
    * `IncrementalWriteBarrierMinor`, `IncrementalWriteBarrierMajor`, `IsValueUnmarkedOrRecordSlot`, `IncrementalWriteBarrier`, `IncrementalWriteBarrierShared`, `IncrementalWriteBarrierLocal`: Implement the incremental write barrier logic for different scenarios (minor/major marking, shared/local objects).
    * `GenerateRecordWrite`, `GenerateIndirectPointerBarrier`, `GenerateEphemeronKeyBarrier`: Public entry points for triggering write barriers.

* **`TSANRelaxedStoreCodeStubAssembler`, `TSANSeqCstStoreCodeStubAssembler`, `TSANRelaxedLoadCodeStubAssembler`:** These classes seem to deal with ThreadSanitizer (TSAN) integration, providing relaxed and sequentially consistent store and load operations.

* **`DeletePropertyBaseAssembler`:**  This class is responsible for deleting properties from JavaScript objects, specifically handling dictionaries.

**Plan for the Output:**

1. State the primary function of the file.
2. Confirm it's not a Torque file.
3. Provide JavaScript examples for the relevant builtins (`CopyFastSmiOrObjectElements`, `GrowFastDoubleElements`, `GrowFastSmiOrObjectElements`, potentially `ReturnReceiver`).
4. Explain the write barrier logic and how it relates to garbage collection, without going into extreme detail in this first part. Give a simplified example if possible.
5. Briefly mention the TSAN functionality.
6. Mention the property deletion functionality.
7. Summarize the key functionalities present in this part of the code.
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#include "src/api/api.h"
#include "src/baseline/baseline.h"
#include "src/builtins/builtins-inl.h"
#include "src/builtins/builtins-utils-gen.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/macro-assembler-inl.h"
#include "src/common/globals.h"
#include "src/execution/frame-constants.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/ic/accessor-assembler.h"
#include "src/ic/keyed-store-generic.h"
#include "src/logging/counters.h"
#include "src/objects/debug-objects.h"
#include "src/objects/scope-info.h"
#include "src/objects/shared-function-info.h"
#include "src/runtime/runtime.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

// -----------------------------------------------------------------------------
// TurboFan support builtins.

TF_BUILTIN(CopyFastSmiOrObjectElements, CodeStubAssembler) {
  auto js_object = Parameter<JSObject>(Descriptor::kObject);

  // Load the {object}s elements.
  TNode<FixedArrayBase> source =
      CAST(LoadObjectField(js_object, JSObject::kElementsOffset));
  TNode<FixedArrayBase> target =
      CloneFixedArray(source, ExtractFixedArrayFlag::kFixedArrays);
  StoreObjectField(js_object, JSObject::kElementsOffset, target);
  Return(target);
}

TF_BUILTIN(GrowFastDoubleElements, CodeStubAssembler) {
  auto object = Parameter<JSObject>(Descriptor::kObject);
  auto key = Parameter<Smi>(Descriptor::kKey);

  Label runtime(this, Label::kDeferred);
  TNode<FixedArrayBase> elements = LoadElements(object);
  elements = TryGrowElementsCapacity(object, elements, PACKED_DOUBLE_ELEMENTS,
                                     key, &runtime);
  Return(elements);

  BIND(&runtime);
  TailCallRuntime(Runtime::kGrowArrayElements, NoContextConstant(), object,
                  key);
}

TF_BUILTIN(GrowFastSmiOrObjectElements, CodeStubAssembler) {
  auto object = Parameter<JSObject>(Descriptor::kObject);
  auto key = Parameter<Smi>(Descriptor::kKey);

  Label runtime(this, Label::kDeferred);
  TNode<FixedArrayBase> elements = LoadElements(object);
  elements =
      TryGrowElementsCapacity(object, elements, PACKED_ELEMENTS, key, &runtime);
  Return(elements);

  BIND(&runtime);
  TailCallRuntime(Runtime::kGrowArrayElements, NoContextConstant(), object,
                  key);
}

TF_BUILTIN(ReturnReceiver, CodeStubAssembler) {
  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  Return(receiver);
}

TF_BUILTIN(DebugBreakTrampoline, CodeStubAssembler) {
  Label tailcall_to_shared(this);
  auto context = Parameter<Context>(Descriptor::kContext);
  auto new_target = Parameter<Object>(Descriptor::kJSNewTarget);
  auto arg_count =
      UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount);
#ifdef V8_ENABLE_LEAPTIERING
  auto dispatch_handle =
      UncheckedParameter<JSDispatchHandleT>(Descriptor::kJSDispatchHandle);
#else
  auto dispatch_handle = InvalidDispatchHandleConstant();
#endif
  auto function = Parameter<JSFunction>(Descriptor::kJSTarget);

  // Check break-at-entry flag on the debug info.
  TNode<ExternalReference> f =
      ExternalConstant(ExternalReference::debug_break_at_entry_function());
  TNode<ExternalReference> isolate_ptr =
      ExternalConstant(ExternalReference::isolate_address());
  TNode<SharedFunctionInfo> shared =
      CAST(LoadObjectField(function, JSFunction::kSharedFunctionInfoOffset));
  TNode<IntPtrT> result = UncheckedCast<IntPtrT>(
      CallCFunction(f, MachineType::UintPtr(),
                    std::make_pair(MachineType::Pointer(), isolate_ptr),
                    std::make_pair(MachineType::TaggedPointer(), shared)));
  GotoIf(IntPtrEqual(result, IntPtrConstant(0)), &tailcall_to_shared);

  CallRuntime(Runtime::kDebugBreakAtEntry, context, function);
  Goto(&tailcall_to_shared);

  BIND(&tailcall_to_shared);
  // Tail call into code object on the SharedFunctionInfo.
  // TODO(saelo): this is not safe. We either need to validate the parameter
  // count here or obtain the code from the dispatch table.
  TNode<Code> code = GetSharedFunctionInfoCode(shared);
  TailCallJSCode(code, context, function, new_target, arg_count,
                 dispatch_handle);
}

class WriteBarrierCodeStubAssembler : public CodeStubAssembler {
 public:
  explicit WriteBarrierCodeStubAssembler(compiler::CodeAssemblerState* state)
      : CodeStubAssembler(state) {}

  TNode<BoolT> IsMarking() {
    TNode<ExternalReference> is_marking_addr = ExternalConstant(
        ExternalReference::heap_is_marking_flag_address(this->isolate()));
    return Word32NotEqual(Load<Uint8T>(is_marking_addr), Int32Constant(0));
  }

  TNode<BoolT> IsMinorMarking() {
    TNode<ExternalReference> is_minor_marking_addr = ExternalConstant(
        ExternalReference::heap_is_minor_marking_flag_address(this->isolate()));
    return Word32NotEqual(Load<Uint8T>(is_minor_marking_addr),
                          Int32Constant(0));
  }

  TNode<BoolT> IsSharedSpaceIsolate() {
    TNode<ExternalReference> is_shared_space_isolate_addr = ExternalConstant(
        ExternalReference::is_shared_space_isolate_flag_address(
            this->isolate()));
    return Word32NotEqual(Load<Uint8T>(is_shared_space_isolate_addr),
                          Int32Constant(0));
  }

  TNode<BoolT> UsesSharedHeap() {
    TNode<ExternalReference> uses_shared_heap_addr =
        IsolateField(IsolateFieldId::kUsesSharedHeapFlag);
    return Word32NotEqual(Load<Uint8T>(uses_shared_heap_addr),
                          Int32Constant(0));
  }

  TNode<BoolT> IsUnmarked(TNode<IntPtrT> object) {
    TNode<IntPtrT> cell;
    TNode<IntPtrT> mask;
    GetMarkBit(object, &cell, &mask);
    // Marked only requires checking a single bit here.
    return WordEqual(WordAnd(Load<IntPtrT>(cell), mask), IntPtrConstant(0));
  }

  void InsertIntoRememberedSet(TNode<IntPtrT> object, TNode<IntPtrT> slot,
                               SaveFPRegsMode fp_mode) {
    Label slow_path(this), next(this);
    TNode<IntPtrT> chunk = MemoryChunkFromAddress(object);
    TNode<IntPtrT> page = PageMetadataFromMemoryChunk(chunk);

    // Load address of SlotSet
    TNode<IntPtrT> slot_set = LoadSlotSet(page, &slow_path);
    TNode<IntPtrT> slot_offset = IntPtrSub(slot, chunk);
    TNode<IntPtrT> num_buckets_address =
        IntPtrSub(slot_set, IntPtrConstant(SlotSet::kNumBucketsSize));
    TNode<IntPtrT> num_buckets = UncheckedCast<IntPtrT>(
        Load(MachineType::Pointer(), num_buckets_address, IntPtrConstant(0)));

    // Load bucket
    TNode<IntPtrT> bucket =
        LoadBucket(slot_set, slot_offset, num_buckets, &slow_path);

    // Update cell
    SetBitInCell(bucket, slot_offset);
    Goto(&next);

    BIND(&slow_path);
    {
      TNode<ExternalReference> function =
          ExternalConstant(ExternalReference::insert_remembered_set_function());
      CallCFunctionWithCallerSavedRegisters(
          function, MachineTypeOf<Int32T>::value, fp_mode,
          std::make_pair(MachineTypeOf<IntPtrT>::value, page),
          std::make_pair(MachineTypeOf<IntPtrT>::value, slot_offset));
      Goto(&next);
    }

    BIND(&next);
  }

  TNode<IntPtrT> LoadSlotSet(TNode<IntPtrT> page, Label* slow_path) {
    TNode<IntPtrT> slot_set = UncheckedCast<IntPtrT>(
        Load(MachineType::Pointer(), page,
             IntPtrConstant(MutablePageMetadata::SlotSetOffset(
                 RememberedSetType::OLD_TO_NEW))));
    GotoIf(WordEqual(slot_set, IntPtrConstant(0)), slow_path);
    return slot_set;
  }

  TNode<IntPtrT> LoadBucket(TNode<IntPtrT> slot_set, TNode<WordT> slot_offset,
                            TNode<IntPtrT> num_buckets, Label* slow_path) {
    TNode<WordT> bucket_index =
        WordShr(slot_offset, SlotSet::kBitsPerBucketLog2 + kTaggedSizeLog2);
    CSA_CHECK(this, IntPtrLessThan(bucket_index, num_buckets));
    TNode<IntPtrT> bucket = UncheckedCast<IntPtrT>(
        Load(MachineType::Pointer(), slot_set,
             WordShl(bucket_index, kSystemPointerSizeLog2)));
    GotoIf(WordEqual(bucket, IntPtrConstant(0)), slow_path);
    return bucket;
  }

  void SetBitInCell(TNode<IntPtrT> bucket, TNode<WordT> slot_offset) {
    // Load cell value
    TNode<WordT> cell_offset = WordAnd(
        WordShr(slot_offset, SlotSet::kBitsPerCellLog2 + kTaggedSizeLog2 -
                                 SlotSet::kCellSizeBytesLog2),
        IntPtrConstant((SlotSet::kCellsPerBucket - 1)
                       << SlotSet::kCellSizeBytesLog2));
    TNode<IntPtrT> cell_address =
        UncheckedCast<IntPtrT>(IntPtrAdd(bucket, cell_offset));
    TNode<IntPtrT> old_cell_value =
        ChangeInt32ToIntPtr(Load<Int32T>(cell_address));

    // Calculate new cell value
    TNode<WordT> bit_index = WordAnd(WordShr(slot_offset, kTaggedSizeLog2),
                                     IntPtrConstant(SlotSet::kBitsPerCell - 1));
    TNode<IntPtrT> new_cell_value = UncheckedCast<IntPtrT>(
        WordOr(old_cell_value, WordShl(IntPtrConstant(1), bit_index)));

    // Update cell value
    StoreNoWriteBarrier(MachineRepresentation::kWord32, cell_address,
                        TruncateIntPtrToInt32(new_cell_value));
  }

  void WriteBarrier(SaveFPRegsMode fp_mode) {
    Label marking_is_on(this), marking_is_off(this), next(this);

    auto slot =
        UncheckedParameter<IntPtrT>(WriteBarrierDescriptor::kSlotAddress);
    Branch(IsMarking(), &marking_is_on, &marking_is_off);

    BIND(&marking_is_off);
    GenerationalOrSharedBarrierSlow(slot, &next, fp_mode);

    BIND(&marking_is_on);
    WriteBarrierDuringMarking(slot, &next, fp_mode);

    BIND(&next);
  }

  void IndirectPointerWriteBarrier(SaveFPRegsMode fp_mode) {
    CSA_DCHECK(this, IsMarking());

    // For this barrier, the slot contains an index into a pointer table and not
    // directly a pointer to a HeapObject. Further, the slot address is tagged
    // with the indirect pointer tag of the slot, so it cannot directly be
    // dereferenced but needs to be decoded first.
    TNode<IntPtrT> slot = UncheckedParameter<IntPtrT>(
        IndirectPointerWriteBarrierDescriptor::kSlotAddress);
    TNode<IntPtrT> object = BitcastTaggedToWord(UncheckedParameter<Object>(
        IndirectPointerWriteBarrierDescriptor::kObject));
    TNode<IntPtrT> tag = UncheckedParameter<IntPtrT>(
        IndirectPointerWriteBarrierDescriptor::kIndirectPointerTag);

    TNode<ExternalReference> function = ExternalConstant(
        ExternalReference::
            write_barrier_indirect_pointer_marking_from_code_function());
    CallCFunctionWithCallerSavedRegisters(
        function, MachineTypeOf<Int32T>::value, fp_mode,
        std::make_pair(MachineTypeOf<IntPtrT>::value, object),
        std::make_pair(MachineTypeOf<IntPtrT>::value, slot),
        std::make_pair(MachineTypeOf<IntPtrT>::value, tag));
  }

  void GenerationalOrSharedBarrierSlow(TNode<IntPtrT> slot, Label* next,
                                       SaveFPRegsMode fp_mode) {
    // When incremental marking is not on, the fast and out-of-line fast path of
    // the write barrier already checked whether we need to run the generational
    // or shared barrier slow path.
    Label generational_barrier(this), shared_barrier(this);

    TNode<IntPtrT> value = BitcastTaggedToWord(Load<HeapObject>(slot));

    InYoungGeneration(value, &generational_barrier, &shared_barrier);

    BIND(&generational_barrier);
    if (!v8_flags.sticky_mark_bits) {
      CSA_DCHECK(this,
                 IsPageFlagSet(value, MemoryChunk::kIsInYoungGenerationMask));
    }
    GenerationalBarrierSlow(slot, next, fp_mode);

    // TODO(333906585): With sticky-mark bits and without the shared barrier
    // support, we actually never jump here. Don't put it under the flag though,
    // since the assert below has been useful.
    BIND(&shared_barrier);
    CSA_DCHECK(this, IsPageFlagSet(value, MemoryChunk::kInSharedHeap));
    SharedBarrierSlow(slot, next, fp_mode);
  }

  void GenerationalBarrierSlow(TNode<IntPtrT> slot, Label* next,
                               SaveFPRegsMode fp_mode) {
    TNode<IntPtrT> object = BitcastTaggedToWord(
        UncheckedParameter<Object>(WriteBarrierDescriptor::kObject));
    InsertIntoRememberedSet(object, slot, fp_mode);
    Goto(next);
  }

  void SharedBarrierSlow(TNode<IntPtrT> slot, Label* next,
                         SaveFPRegsMode fp_mode) {
    TNode<ExternalReference> function = ExternalConstant(
        ExternalReference::shared_barrier_from_code_function());
    TNode<IntPtrT> object = BitcastTaggedToWord(
        UncheckedParameter<Object>(WriteBarrierDescriptor::kObject));
    CallCFunctionWithCallerSavedRegisters(
        function, MachineTypeOf<Int32T>::value, fp_mode,
        std::make_pair(MachineTypeOf<IntPtrT>::value, object),
        std::make_pair(MachineTypeOf<IntPtrT>::value, slot));
    Goto(next);
  }

  void WriteBarrierDuringMarking(TNode<IntPtrT> slot, Label* next,
                                 SaveFPRegsMode fp_mode) {
    // When incremental marking is on, we need to perform generational, shared
    // and incremental marking write barrier.
    Label incremental_barrier(this);

    GenerationalOrSharedBarrierDuringMarking(slot, &incremental_barrier,
                                             fp_mode);

    BIND(&incremental_barrier);
    IncrementalWriteBarrier(slot, fp_mode);
    Goto(next);
  }

  void GenerationalOrSharedBarrierDuringMarking(TNode<IntPtrT> slot,
                                                Label* next,
                                                SaveFPRegsMode fp_mode) {
    Label generational_barrier_check(this), shared_barrier_check(this),
        shared_barrier_slow(this), generational_barrier_slow(this);

    // During incremental marking we always reach this slow path, so we need to
    // check whether this is an old-to-new or old-to-shared reference.
    TNode<IntPtrT> object = BitcastTaggedToWord(
        UncheckedParameter<Object>(WriteBarrierDescriptor::kObject));

    if (!v8_flags.sticky_mark_bits) {
      // With sticky markbits we know everything will be old after the GC so no
      // need to check the age.
      InYoungGeneration(object, next, &generational_barrier_check);

      BIND(&generational_barrier_check);
    }

    TNode<IntPtrT> value = BitcastTaggedToWord(Load<HeapObject>(slot));

    if (!v8_flags.sticky_mark_bits) {
      // With sticky markbits we know everything will be old after the GC so no
      // need to track old-to-new references.
      InYoungGeneration(value, &generational_barrier_slow,
                        &shared_barrier_check);

      BIND(&generational_barrier_slow);
      GenerationalBarrierSlow(slot, next, fp_mode);

      BIND(&shared_barrier_check);
    }

    InSharedHeap(value, &shared_barrier_slow, next);

    BIND(&shared_barrier_slow);

    SharedBarrierSlow(slot, next, fp_mode);
  }

  void InYoungGeneration(TNode<IntPtrT> object, Label* true_label,
                         Label* false_label) {
    if (v8_flags.sticky_mark_bits) {
      // This method is currently only used when marking is disabled. Checking
      // markbits while marking is active may result in unexpected results.
      CSA_DCHECK(this, Word32Equal(IsMarking(), BoolConstant(false)));

      Label not_read_only(this);

      TNode<BoolT> is_read_only_page =
          IsPageFlagSet(object, MemoryChunk::kIsOnlyOldOrMajorGCInProgressMask);
      Branch(is_read_only_page, false_label, &not_read_only);

      BIND(&not_read_only);
      Branch(IsUnmarked(object), true_label, false_label);
    } else {
      TNode<BoolT> object_is_young =
          IsPageFlagSet(object, MemoryChunk::kIsInYoungGenerationMask);
      Branch(object_is_young, true_label, false_label);
    }
  }

  void InSharedHeap(TNode<IntPtrT> object, Label* true_label,
                    Label* false_label) {
    TNode<BoolT> object_is_young =
        IsPageFlagSet(object, MemoryChunk::kInSharedHeap);

    Branch(object_is_young, true_label, false_label);
  }

  void IncrementalWriteBarrierMinor(TNode<IntPtrT> slot, TNode<IntPtrT> value,
                                    SaveFPRegsMode fp_mode, Label* next) {
    Label check_is_unmarked(this, Label::kDeferred);

    if (!v8_flags.sticky_mark_bits) {
      // With sticky markbits, InYoungGeneration and IsUnmarked below are
      // equivalent.
      InYoungGeneration(value, &check_is_unmarked, next);

      BIND(&check_is_unmarked);
    }

    GotoIfNot(IsUnmarked(value), next);

    {
      TNode<ExternalReference> function = ExternalConstant(
          ExternalReference::write_barrier_marking_from_code_function());
      TNode<IntPtrT> object = BitcastTaggedToWord(
          UncheckedParameter<Object>(WriteBarrierDescriptor::kObject));
      CallCFunctionWithCallerSavedRegisters(
          function, MachineTypeOf<Int32T>::value, fp_mode,
          std::make_pair(MachineTypeOf<IntPtrT>::value, object),
          std::make_pair(MachineTypeOf<IntPtrT>::value, slot));
      Goto(next);
    }
  }

  void IncrementalWriteBarrierMajor(TNode<IntPtrT> slot, TNode<IntPtrT> value,
                                    SaveFPRegsMode fp_mode, Label* next) {
    Label marking_cpp_slow_path(this);

    IsValueUnmarkedOrRecordSlot(value, &marking_cpp_slow_path, next);

    BIND(&marking_cpp_slow_path);
    {
      TNode<ExternalReference> function = ExternalConstant(
          ExternalReference::write_barrier_marking_from_code_function());
      TNode<IntPtrT> object = BitcastTaggedToWord(
          UncheckedParameter<Object>(WriteBarrierDescriptor::kObject));
      CallCFunctionWithCallerSavedRegisters(
          function, MachineTypeOf<Int32T>::value, fp_mode,
          std::make_pair(MachineTypeOf<IntPtrT>::value, object),
          std::make_pair(MachineTypeOf<IntPtrT>::value, slot));
      Goto(next);
    }
  }

  void IsValueUnmarkedOrRecordSlot(TNode<IntPtrT> value, Label* true_label,
                                   Label* false_label) {
    // This code implements the following condition:
    // IsUnmarked(value) ||
    //   OnEvacuationCandidate(value) &&
    //   !SkipEvacuationCandidateRecording(value)

    // 1) IsUnmarked(value) || ....
    GotoIf(IsUnmarked(value), true_label);

    // 2) OnEvacuationCandidate(value) &&
    //    !SkipEvacuationCandidateRecording(value)
    GotoIfNot(IsPageFlagSet(value, MemoryChunk::kEvacuationCandidateMask),
              false_label);

    {
      TNode<IntPtrT> object = BitcastTaggedToWord(
          UncheckedParameter<Object>(WriteBarrierDescriptor::kObject));
      Branch(
          IsPageFlagSet(object, MemoryChunk::kSkipEvacuationSlotsRecordingMask),
          false_label, true_label);
    }
  }

  void IncrementalWriteBarrier(TNode<IntPtrT> slot, SaveFPRegsMode fp_mode) {
    Label next(this), write_into_shared_object(this),
        write_into_local_object(this),
        local_object_and_value(this, Label::kDeferred);

    TNode<IntPtrT> object = BitcastTaggedToWord(
        UncheckedParameter<Object>(WriteBarrierDescriptor::kObject));
    TNode<IntPtrT> value = BitcastTaggedToWord(Load<HeapObject>(slot));

    // Without a shared heap, all objects are local. This is the fast path
    // always used when no shared heap exists.
    GotoIfNot(UsesSharedHeap(), &local_object_and_value);

    // From the point-of-view of the shared space isolate (= the main isolate)
    // shared heap objects are just local objects.
    GotoIf(IsSharedSpaceIsolate(), &local_object_and_value);

    // These checks here are now only reached by client isolates (= worker
    // isolates). Now first check whether incremental marking is activated for
    // that particular object's space. Incrementally marking might only be
    // enabled for either local or shared objects on client isolates.
    GotoIfNot(IsPageFlagSet(object, MemoryChunk::kIncrementalMarking), &next);

    // We now know that incremental marking is enabled for the given object.
    // Decide whether to run the shared or local incremental marking barrier.
    InSharedHeap(object, &write_into_shared_object, &write_into_local_object);

    BIND(&write_into_shared_object);

    // Run the shared incremental marking barrier.
    IncrementalWriteBarrierShared(object, slot, value, fp_mode, &next);

    BIND(&write_into_local_object);

    // When writing into a local object we can ignore stores of shared object
    // values since for those no slot recording or marking is required.
    InSharedHeap(value, &next, &local_object_and_value);

    // Both object and value are now guaranteed to be local objects, run the
    // local incremental marking barrier.
    BIND(&local_object_and_value);
    IncrementalWriteBarrierLocal(slot, value, fp_mode, &next);

    BIND(&next);
  }

  void IncrementalWriteBarrierShared(TNode<IntPtrT> object, TNode<IntPtrT> slot,
                                     TNode<IntPtrT> value,
                                     SaveFPRegsMode fp_mode, Label* next) {
    Label shared_marking_cpp_slow_path(this);

    IsValueUnmarkedOrRecordSlot(value, &shared_marking_cpp_slow_path, next);

    BIND(&shared_marking_cpp_slow_path);
    {
      TNode<ExternalReference> function = ExternalConstant(
          ExternalReference::write_barrier_shared_marking_from_code_function());
      CallCFunctionWithCallerSavedRegisters(
          function, MachineTypeOf<Int32T>::value, fp_mode,
          std::make_pair(MachineTypeOf<IntPtrT>::value, object),
          std::make_pair(MachineTypeOf<IntPtrT>::value, slot));

      Goto(next);
    }
  }

  void IncrementalWriteBarrierLocal(TNode<IntPtrT> slot, TNode<IntPtrT> value,
                                    SaveFPRegsMode fp_mode, Label* next) {
    Label is_minor(this), is_major(this);
    Branch(IsMinorMarking(), &is_minor, &is_major);

    BIND(&is_minor);
    IncrementalWriteBarrierMinor(slot, value, fp_mode, next);

    BIND(&is_major);
    IncrementalWriteBarrierMajor(slot, value, fp_mode, next);
  }

  void GenerateRecordWrite(SaveFPRegsMode fp_mode) {
    if (V8_DISABLE_WRITE_BARRIERS_BOOL) {
      Return(TrueConstant());
      return;
    }

    WriteBarrier(fp_mode);
    IncrementCounter(isolate()->counters()->write_barriers(), 1);
    Return(TrueConstant());
  }

  void GenerateIndirectPointerBarrier(SaveFPRegsMode fp_mode) {
    if (V8_DISABLE_WRITE_BARRIERS_BOOL) {
      Return(TrueConstant());
      return;
    }

    if (!V8_ENABLE_SANDBOX_BOOL) {
      Unreachable();
      return;
    }

    IndirectPointerWriteBarrier(fp_mode);
    IncrementCounter(isolate()->counters()->write_barriers(), 1);
    Return(TrueConstant());
  }

  void GenerateEphemeronKeyBarrier(SaveFPRegsMode fp_mode) {
    TNode<ExternalReference> function = ExternalConstant(
        ExternalReference::ephemeron_key_write_barrier_function());
    TNode<ExternalReference> isolate_constant =
        ExternalConstant(ExternalReference::isolate_address());
    // In this method we limit the allocatable registers so we have to use
    // UncheckedParameter. Parameter does not work because the checked cast
    // needs more registers.
    auto address =
        UncheckedParameter<IntPtrT>(WriteBarrierDescriptor::kSlotAddress);
    TNode<IntPtrT> object = BitcastTaggedToWord(
        UncheckedParameter<Object>(WriteBarrierDescriptor::kObject));

    CallCFunctionWithCallerSavedRegisters(
        function, MachineTypeOf<Int32T>::value, fp_mode,
        std::make_pair(MachineTypeOf<IntPtrT>::value, object),
        std::make_pair(MachineTypeOf<IntPtrT>::value, address),
        std::make_pair(MachineTypeOf<ExternalReference>::value,
                       isolate_constant));

    IncrementCounter(isolate()->counters()->write_barriers(), 1);
    Return(TrueConstant());
  }
};

TF_BUILTIN(RecordWriteSaveFP, WriteBarrierCodeStubAssembler) {
  GenerateRecordWrite(SaveFPRegsMode::kSave);
}

TF_BUILTIN(RecordWriteIgnoreFP, WriteBarrierCodeStubAssembler) {
  GenerateRecordWrite(SaveFPRegsMode::kIgnore);
}

TF_BUILTIN(IndirectPointerBarrierSaveFP, WriteBarrierCodeStubAssembler) {
  GenerateIndirectPointerBarrier(SaveFPRegsMode::kSave);
}

TF_BUILTIN(IndirectPointerBarrierIgnoreFP, WriteBarrierCodeStubAssembler) {
  GenerateIndirectPointerBarrier(SaveFPRegsMode::kIgnore);
}

TF_BUILTIN(EphemeronKeyBarrierSaveFP, WriteBarrierCodeStubAssembler) {
  GenerateEphemeronKeyBarrier(SaveFPRegsMode::kSave);
}

TF_BUILTIN(EphemeronKeyBarrierIgnoreFP, WriteBarrierCodeStubAssembler) {
  GenerateEphemeronKeyBarrier(SaveFPRegsMode::kIgnore);
}

#ifdef V8_IS_TSAN
class TSANRelaxedStoreCodeStubAssembler : public CodeStubAssembler {
 public:
  explicit TSANRelaxedStoreCodeStubAssembler(
      compiler::CodeAssemblerState* state)
      : CodeStubAssembler(state) {}

  TNode<ExternalReference> GetExternalReference(int size) {
    if (size == kInt8Size) {
      return ExternalConstant(
          ExternalReference::tsan_relaxed_store_function_8_bits());
    } else if (size == kInt16Size) {
      return ExternalConstant(
          ExternalReference::tsan_relaxed_store
### 提示词
```
这是目录为v8/src/builtins/builtins-internal-gen.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-internal-gen.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#include "src/api/api.h"
#include "src/baseline/baseline.h"
#include "src/builtins/builtins-inl.h"
#include "src/builtins/builtins-utils-gen.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/macro-assembler-inl.h"
#include "src/common/globals.h"
#include "src/execution/frame-constants.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/ic/accessor-assembler.h"
#include "src/ic/keyed-store-generic.h"
#include "src/logging/counters.h"
#include "src/objects/debug-objects.h"
#include "src/objects/scope-info.h"
#include "src/objects/shared-function-info.h"
#include "src/runtime/runtime.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

// -----------------------------------------------------------------------------
// TurboFan support builtins.

TF_BUILTIN(CopyFastSmiOrObjectElements, CodeStubAssembler) {
  auto js_object = Parameter<JSObject>(Descriptor::kObject);

  // Load the {object}s elements.
  TNode<FixedArrayBase> source =
      CAST(LoadObjectField(js_object, JSObject::kElementsOffset));
  TNode<FixedArrayBase> target =
      CloneFixedArray(source, ExtractFixedArrayFlag::kFixedArrays);
  StoreObjectField(js_object, JSObject::kElementsOffset, target);
  Return(target);
}

TF_BUILTIN(GrowFastDoubleElements, CodeStubAssembler) {
  auto object = Parameter<JSObject>(Descriptor::kObject);
  auto key = Parameter<Smi>(Descriptor::kKey);

  Label runtime(this, Label::kDeferred);
  TNode<FixedArrayBase> elements = LoadElements(object);
  elements = TryGrowElementsCapacity(object, elements, PACKED_DOUBLE_ELEMENTS,
                                     key, &runtime);
  Return(elements);

  BIND(&runtime);
  TailCallRuntime(Runtime::kGrowArrayElements, NoContextConstant(), object,
                  key);
}

TF_BUILTIN(GrowFastSmiOrObjectElements, CodeStubAssembler) {
  auto object = Parameter<JSObject>(Descriptor::kObject);
  auto key = Parameter<Smi>(Descriptor::kKey);

  Label runtime(this, Label::kDeferred);
  TNode<FixedArrayBase> elements = LoadElements(object);
  elements =
      TryGrowElementsCapacity(object, elements, PACKED_ELEMENTS, key, &runtime);
  Return(elements);

  BIND(&runtime);
  TailCallRuntime(Runtime::kGrowArrayElements, NoContextConstant(), object,
                  key);
}

TF_BUILTIN(ReturnReceiver, CodeStubAssembler) {
  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  Return(receiver);
}

TF_BUILTIN(DebugBreakTrampoline, CodeStubAssembler) {
  Label tailcall_to_shared(this);
  auto context = Parameter<Context>(Descriptor::kContext);
  auto new_target = Parameter<Object>(Descriptor::kJSNewTarget);
  auto arg_count =
      UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount);
#ifdef V8_ENABLE_LEAPTIERING
  auto dispatch_handle =
      UncheckedParameter<JSDispatchHandleT>(Descriptor::kJSDispatchHandle);
#else
  auto dispatch_handle = InvalidDispatchHandleConstant();
#endif
  auto function = Parameter<JSFunction>(Descriptor::kJSTarget);

  // Check break-at-entry flag on the debug info.
  TNode<ExternalReference> f =
      ExternalConstant(ExternalReference::debug_break_at_entry_function());
  TNode<ExternalReference> isolate_ptr =
      ExternalConstant(ExternalReference::isolate_address());
  TNode<SharedFunctionInfo> shared =
      CAST(LoadObjectField(function, JSFunction::kSharedFunctionInfoOffset));
  TNode<IntPtrT> result = UncheckedCast<IntPtrT>(
      CallCFunction(f, MachineType::UintPtr(),
                    std::make_pair(MachineType::Pointer(), isolate_ptr),
                    std::make_pair(MachineType::TaggedPointer(), shared)));
  GotoIf(IntPtrEqual(result, IntPtrConstant(0)), &tailcall_to_shared);

  CallRuntime(Runtime::kDebugBreakAtEntry, context, function);
  Goto(&tailcall_to_shared);

  BIND(&tailcall_to_shared);
  // Tail call into code object on the SharedFunctionInfo.
  // TODO(saelo): this is not safe. We either need to validate the parameter
  // count here or obtain the code from the dispatch table.
  TNode<Code> code = GetSharedFunctionInfoCode(shared);
  TailCallJSCode(code, context, function, new_target, arg_count,
                 dispatch_handle);
}

class WriteBarrierCodeStubAssembler : public CodeStubAssembler {
 public:
  explicit WriteBarrierCodeStubAssembler(compiler::CodeAssemblerState* state)
      : CodeStubAssembler(state) {}

  TNode<BoolT> IsMarking() {
    TNode<ExternalReference> is_marking_addr = ExternalConstant(
        ExternalReference::heap_is_marking_flag_address(this->isolate()));
    return Word32NotEqual(Load<Uint8T>(is_marking_addr), Int32Constant(0));
  }

  TNode<BoolT> IsMinorMarking() {
    TNode<ExternalReference> is_minor_marking_addr = ExternalConstant(
        ExternalReference::heap_is_minor_marking_flag_address(this->isolate()));
    return Word32NotEqual(Load<Uint8T>(is_minor_marking_addr),
                          Int32Constant(0));
  }

  TNode<BoolT> IsSharedSpaceIsolate() {
    TNode<ExternalReference> is_shared_space_isolate_addr = ExternalConstant(
        ExternalReference::is_shared_space_isolate_flag_address(
            this->isolate()));
    return Word32NotEqual(Load<Uint8T>(is_shared_space_isolate_addr),
                          Int32Constant(0));
  }

  TNode<BoolT> UsesSharedHeap() {
    TNode<ExternalReference> uses_shared_heap_addr =
        IsolateField(IsolateFieldId::kUsesSharedHeapFlag);
    return Word32NotEqual(Load<Uint8T>(uses_shared_heap_addr),
                          Int32Constant(0));
  }

  TNode<BoolT> IsUnmarked(TNode<IntPtrT> object) {
    TNode<IntPtrT> cell;
    TNode<IntPtrT> mask;
    GetMarkBit(object, &cell, &mask);
    // Marked only requires checking a single bit here.
    return WordEqual(WordAnd(Load<IntPtrT>(cell), mask), IntPtrConstant(0));
  }

  void InsertIntoRememberedSet(TNode<IntPtrT> object, TNode<IntPtrT> slot,
                               SaveFPRegsMode fp_mode) {
    Label slow_path(this), next(this);
    TNode<IntPtrT> chunk = MemoryChunkFromAddress(object);
    TNode<IntPtrT> page = PageMetadataFromMemoryChunk(chunk);

    // Load address of SlotSet
    TNode<IntPtrT> slot_set = LoadSlotSet(page, &slow_path);
    TNode<IntPtrT> slot_offset = IntPtrSub(slot, chunk);
    TNode<IntPtrT> num_buckets_address =
        IntPtrSub(slot_set, IntPtrConstant(SlotSet::kNumBucketsSize));
    TNode<IntPtrT> num_buckets = UncheckedCast<IntPtrT>(
        Load(MachineType::Pointer(), num_buckets_address, IntPtrConstant(0)));

    // Load bucket
    TNode<IntPtrT> bucket =
        LoadBucket(slot_set, slot_offset, num_buckets, &slow_path);

    // Update cell
    SetBitInCell(bucket, slot_offset);
    Goto(&next);

    BIND(&slow_path);
    {
      TNode<ExternalReference> function =
          ExternalConstant(ExternalReference::insert_remembered_set_function());
      CallCFunctionWithCallerSavedRegisters(
          function, MachineTypeOf<Int32T>::value, fp_mode,
          std::make_pair(MachineTypeOf<IntPtrT>::value, page),
          std::make_pair(MachineTypeOf<IntPtrT>::value, slot_offset));
      Goto(&next);
    }

    BIND(&next);
  }

  TNode<IntPtrT> LoadSlotSet(TNode<IntPtrT> page, Label* slow_path) {
    TNode<IntPtrT> slot_set = UncheckedCast<IntPtrT>(
        Load(MachineType::Pointer(), page,
             IntPtrConstant(MutablePageMetadata::SlotSetOffset(
                 RememberedSetType::OLD_TO_NEW))));
    GotoIf(WordEqual(slot_set, IntPtrConstant(0)), slow_path);
    return slot_set;
  }

  TNode<IntPtrT> LoadBucket(TNode<IntPtrT> slot_set, TNode<WordT> slot_offset,
                            TNode<IntPtrT> num_buckets, Label* slow_path) {
    TNode<WordT> bucket_index =
        WordShr(slot_offset, SlotSet::kBitsPerBucketLog2 + kTaggedSizeLog2);
    CSA_CHECK(this, IntPtrLessThan(bucket_index, num_buckets));
    TNode<IntPtrT> bucket = UncheckedCast<IntPtrT>(
        Load(MachineType::Pointer(), slot_set,
             WordShl(bucket_index, kSystemPointerSizeLog2)));
    GotoIf(WordEqual(bucket, IntPtrConstant(0)), slow_path);
    return bucket;
  }

  void SetBitInCell(TNode<IntPtrT> bucket, TNode<WordT> slot_offset) {
    // Load cell value
    TNode<WordT> cell_offset = WordAnd(
        WordShr(slot_offset, SlotSet::kBitsPerCellLog2 + kTaggedSizeLog2 -
                                 SlotSet::kCellSizeBytesLog2),
        IntPtrConstant((SlotSet::kCellsPerBucket - 1)
                       << SlotSet::kCellSizeBytesLog2));
    TNode<IntPtrT> cell_address =
        UncheckedCast<IntPtrT>(IntPtrAdd(bucket, cell_offset));
    TNode<IntPtrT> old_cell_value =
        ChangeInt32ToIntPtr(Load<Int32T>(cell_address));

    // Calculate new cell value
    TNode<WordT> bit_index = WordAnd(WordShr(slot_offset, kTaggedSizeLog2),
                                     IntPtrConstant(SlotSet::kBitsPerCell - 1));
    TNode<IntPtrT> new_cell_value = UncheckedCast<IntPtrT>(
        WordOr(old_cell_value, WordShl(IntPtrConstant(1), bit_index)));

    // Update cell value
    StoreNoWriteBarrier(MachineRepresentation::kWord32, cell_address,
                        TruncateIntPtrToInt32(new_cell_value));
  }

  void WriteBarrier(SaveFPRegsMode fp_mode) {
    Label marking_is_on(this), marking_is_off(this), next(this);

    auto slot =
        UncheckedParameter<IntPtrT>(WriteBarrierDescriptor::kSlotAddress);
    Branch(IsMarking(), &marking_is_on, &marking_is_off);

    BIND(&marking_is_off);
    GenerationalOrSharedBarrierSlow(slot, &next, fp_mode);

    BIND(&marking_is_on);
    WriteBarrierDuringMarking(slot, &next, fp_mode);

    BIND(&next);
  }

  void IndirectPointerWriteBarrier(SaveFPRegsMode fp_mode) {
    CSA_DCHECK(this, IsMarking());

    // For this barrier, the slot contains an index into a pointer table and not
    // directly a pointer to a HeapObject. Further, the slot address is tagged
    // with the indirect pointer tag of the slot, so it cannot directly be
    // dereferenced but needs to be decoded first.
    TNode<IntPtrT> slot = UncheckedParameter<IntPtrT>(
        IndirectPointerWriteBarrierDescriptor::kSlotAddress);
    TNode<IntPtrT> object = BitcastTaggedToWord(UncheckedParameter<Object>(
        IndirectPointerWriteBarrierDescriptor::kObject));
    TNode<IntPtrT> tag = UncheckedParameter<IntPtrT>(
        IndirectPointerWriteBarrierDescriptor::kIndirectPointerTag);

    TNode<ExternalReference> function = ExternalConstant(
        ExternalReference::
            write_barrier_indirect_pointer_marking_from_code_function());
    CallCFunctionWithCallerSavedRegisters(
        function, MachineTypeOf<Int32T>::value, fp_mode,
        std::make_pair(MachineTypeOf<IntPtrT>::value, object),
        std::make_pair(MachineTypeOf<IntPtrT>::value, slot),
        std::make_pair(MachineTypeOf<IntPtrT>::value, tag));
  }

  void GenerationalOrSharedBarrierSlow(TNode<IntPtrT> slot, Label* next,
                                       SaveFPRegsMode fp_mode) {
    // When incremental marking is not on, the fast and out-of-line fast path of
    // the write barrier already checked whether we need to run the generational
    // or shared barrier slow path.
    Label generational_barrier(this), shared_barrier(this);

    TNode<IntPtrT> value = BitcastTaggedToWord(Load<HeapObject>(slot));

    InYoungGeneration(value, &generational_barrier, &shared_barrier);

    BIND(&generational_barrier);
    if (!v8_flags.sticky_mark_bits) {
      CSA_DCHECK(this,
                 IsPageFlagSet(value, MemoryChunk::kIsInYoungGenerationMask));
    }
    GenerationalBarrierSlow(slot, next, fp_mode);

    // TODO(333906585): With sticky-mark bits and without the shared barrier
    // support, we actually never jump here. Don't put it under the flag though,
    // since the assert below has been useful.
    BIND(&shared_barrier);
    CSA_DCHECK(this, IsPageFlagSet(value, MemoryChunk::kInSharedHeap));
    SharedBarrierSlow(slot, next, fp_mode);
  }

  void GenerationalBarrierSlow(TNode<IntPtrT> slot, Label* next,
                               SaveFPRegsMode fp_mode) {
    TNode<IntPtrT> object = BitcastTaggedToWord(
        UncheckedParameter<Object>(WriteBarrierDescriptor::kObject));
    InsertIntoRememberedSet(object, slot, fp_mode);
    Goto(next);
  }

  void SharedBarrierSlow(TNode<IntPtrT> slot, Label* next,
                         SaveFPRegsMode fp_mode) {
    TNode<ExternalReference> function = ExternalConstant(
        ExternalReference::shared_barrier_from_code_function());
    TNode<IntPtrT> object = BitcastTaggedToWord(
        UncheckedParameter<Object>(WriteBarrierDescriptor::kObject));
    CallCFunctionWithCallerSavedRegisters(
        function, MachineTypeOf<Int32T>::value, fp_mode,
        std::make_pair(MachineTypeOf<IntPtrT>::value, object),
        std::make_pair(MachineTypeOf<IntPtrT>::value, slot));
    Goto(next);
  }

  void WriteBarrierDuringMarking(TNode<IntPtrT> slot, Label* next,
                                 SaveFPRegsMode fp_mode) {
    // When incremental marking is on, we need to perform generational, shared
    // and incremental marking write barrier.
    Label incremental_barrier(this);

    GenerationalOrSharedBarrierDuringMarking(slot, &incremental_barrier,
                                             fp_mode);

    BIND(&incremental_barrier);
    IncrementalWriteBarrier(slot, fp_mode);
    Goto(next);
  }

  void GenerationalOrSharedBarrierDuringMarking(TNode<IntPtrT> slot,
                                                Label* next,
                                                SaveFPRegsMode fp_mode) {
    Label generational_barrier_check(this), shared_barrier_check(this),
        shared_barrier_slow(this), generational_barrier_slow(this);

    // During incremental marking we always reach this slow path, so we need to
    // check whether this is an old-to-new or old-to-shared reference.
    TNode<IntPtrT> object = BitcastTaggedToWord(
        UncheckedParameter<Object>(WriteBarrierDescriptor::kObject));

    if (!v8_flags.sticky_mark_bits) {
      // With sticky markbits we know everything will be old after the GC so no
      // need to check the age.
      InYoungGeneration(object, next, &generational_barrier_check);

      BIND(&generational_barrier_check);
    }

    TNode<IntPtrT> value = BitcastTaggedToWord(Load<HeapObject>(slot));

    if (!v8_flags.sticky_mark_bits) {
      // With sticky markbits we know everything will be old after the GC so no
      // need to track old-to-new references.
      InYoungGeneration(value, &generational_barrier_slow,
                        &shared_barrier_check);

      BIND(&generational_barrier_slow);
      GenerationalBarrierSlow(slot, next, fp_mode);

      BIND(&shared_barrier_check);
    }

    InSharedHeap(value, &shared_barrier_slow, next);

    BIND(&shared_barrier_slow);

    SharedBarrierSlow(slot, next, fp_mode);
  }

  void InYoungGeneration(TNode<IntPtrT> object, Label* true_label,
                         Label* false_label) {
    if (v8_flags.sticky_mark_bits) {
      // This method is currently only used when marking is disabled. Checking
      // markbits while marking is active may result in unexpected results.
      CSA_DCHECK(this, Word32Equal(IsMarking(), BoolConstant(false)));

      Label not_read_only(this);

      TNode<BoolT> is_read_only_page =
          IsPageFlagSet(object, MemoryChunk::kIsOnlyOldOrMajorGCInProgressMask);
      Branch(is_read_only_page, false_label, &not_read_only);

      BIND(&not_read_only);
      Branch(IsUnmarked(object), true_label, false_label);
    } else {
      TNode<BoolT> object_is_young =
          IsPageFlagSet(object, MemoryChunk::kIsInYoungGenerationMask);
      Branch(object_is_young, true_label, false_label);
    }
  }

  void InSharedHeap(TNode<IntPtrT> object, Label* true_label,
                    Label* false_label) {
    TNode<BoolT> object_is_young =
        IsPageFlagSet(object, MemoryChunk::kInSharedHeap);

    Branch(object_is_young, true_label, false_label);
  }

  void IncrementalWriteBarrierMinor(TNode<IntPtrT> slot, TNode<IntPtrT> value,
                                    SaveFPRegsMode fp_mode, Label* next) {
    Label check_is_unmarked(this, Label::kDeferred);

    if (!v8_flags.sticky_mark_bits) {
      // With sticky markbits, InYoungGeneration and IsUnmarked below are
      // equivalent.
      InYoungGeneration(value, &check_is_unmarked, next);

      BIND(&check_is_unmarked);
    }

    GotoIfNot(IsUnmarked(value), next);

    {
      TNode<ExternalReference> function = ExternalConstant(
          ExternalReference::write_barrier_marking_from_code_function());
      TNode<IntPtrT> object = BitcastTaggedToWord(
          UncheckedParameter<Object>(WriteBarrierDescriptor::kObject));
      CallCFunctionWithCallerSavedRegisters(
          function, MachineTypeOf<Int32T>::value, fp_mode,
          std::make_pair(MachineTypeOf<IntPtrT>::value, object),
          std::make_pair(MachineTypeOf<IntPtrT>::value, slot));
      Goto(next);
    }
  }

  void IncrementalWriteBarrierMajor(TNode<IntPtrT> slot, TNode<IntPtrT> value,
                                    SaveFPRegsMode fp_mode, Label* next) {
    Label marking_cpp_slow_path(this);

    IsValueUnmarkedOrRecordSlot(value, &marking_cpp_slow_path, next);

    BIND(&marking_cpp_slow_path);
    {
      TNode<ExternalReference> function = ExternalConstant(
          ExternalReference::write_barrier_marking_from_code_function());
      TNode<IntPtrT> object = BitcastTaggedToWord(
          UncheckedParameter<Object>(WriteBarrierDescriptor::kObject));
      CallCFunctionWithCallerSavedRegisters(
          function, MachineTypeOf<Int32T>::value, fp_mode,
          std::make_pair(MachineTypeOf<IntPtrT>::value, object),
          std::make_pair(MachineTypeOf<IntPtrT>::value, slot));
      Goto(next);
    }
  }

  void IsValueUnmarkedOrRecordSlot(TNode<IntPtrT> value, Label* true_label,
                                   Label* false_label) {
    // This code implements the following condition:
    // IsUnmarked(value) ||
    //   OnEvacuationCandidate(value) &&
    //   !SkipEvacuationCandidateRecording(value)

    // 1) IsUnmarked(value) || ....
    GotoIf(IsUnmarked(value), true_label);

    // 2) OnEvacuationCandidate(value) &&
    //    !SkipEvacuationCandidateRecording(value)
    GotoIfNot(IsPageFlagSet(value, MemoryChunk::kEvacuationCandidateMask),
              false_label);

    {
      TNode<IntPtrT> object = BitcastTaggedToWord(
          UncheckedParameter<Object>(WriteBarrierDescriptor::kObject));
      Branch(
          IsPageFlagSet(object, MemoryChunk::kSkipEvacuationSlotsRecordingMask),
          false_label, true_label);
    }
  }

  void IncrementalWriteBarrier(TNode<IntPtrT> slot, SaveFPRegsMode fp_mode) {
    Label next(this), write_into_shared_object(this),
        write_into_local_object(this),
        local_object_and_value(this, Label::kDeferred);

    TNode<IntPtrT> object = BitcastTaggedToWord(
        UncheckedParameter<Object>(WriteBarrierDescriptor::kObject));
    TNode<IntPtrT> value = BitcastTaggedToWord(Load<HeapObject>(slot));

    // Without a shared heap, all objects are local. This is the fast path
    // always used when no shared heap exists.
    GotoIfNot(UsesSharedHeap(), &local_object_and_value);

    // From the point-of-view of the shared space isolate (= the main isolate)
    // shared heap objects are just local objects.
    GotoIf(IsSharedSpaceIsolate(), &local_object_and_value);

    // These checks here are now only reached by client isolates (= worker
    // isolates). Now first check whether incremental marking is activated for
    // that particular object's space. Incrementally marking might only be
    // enabled for either local or shared objects on client isolates.
    GotoIfNot(IsPageFlagSet(object, MemoryChunk::kIncrementalMarking), &next);

    // We now know that incremental marking is enabled for the given object.
    // Decide whether to run the shared or local incremental marking barrier.
    InSharedHeap(object, &write_into_shared_object, &write_into_local_object);

    BIND(&write_into_shared_object);

    // Run the shared incremental marking barrier.
    IncrementalWriteBarrierShared(object, slot, value, fp_mode, &next);

    BIND(&write_into_local_object);

    // When writing into a local object we can ignore stores of shared object
    // values since for those no slot recording or marking is required.
    InSharedHeap(value, &next, &local_object_and_value);

    // Both object and value are now guaranteed to be local objects, run the
    // local incremental marking barrier.
    BIND(&local_object_and_value);
    IncrementalWriteBarrierLocal(slot, value, fp_mode, &next);

    BIND(&next);
  }

  void IncrementalWriteBarrierShared(TNode<IntPtrT> object, TNode<IntPtrT> slot,
                                     TNode<IntPtrT> value,
                                     SaveFPRegsMode fp_mode, Label* next) {
    Label shared_marking_cpp_slow_path(this);

    IsValueUnmarkedOrRecordSlot(value, &shared_marking_cpp_slow_path, next);

    BIND(&shared_marking_cpp_slow_path);
    {
      TNode<ExternalReference> function = ExternalConstant(
          ExternalReference::write_barrier_shared_marking_from_code_function());
      CallCFunctionWithCallerSavedRegisters(
          function, MachineTypeOf<Int32T>::value, fp_mode,
          std::make_pair(MachineTypeOf<IntPtrT>::value, object),
          std::make_pair(MachineTypeOf<IntPtrT>::value, slot));

      Goto(next);
    }
  }

  void IncrementalWriteBarrierLocal(TNode<IntPtrT> slot, TNode<IntPtrT> value,
                                    SaveFPRegsMode fp_mode, Label* next) {
    Label is_minor(this), is_major(this);
    Branch(IsMinorMarking(), &is_minor, &is_major);

    BIND(&is_minor);
    IncrementalWriteBarrierMinor(slot, value, fp_mode, next);

    BIND(&is_major);
    IncrementalWriteBarrierMajor(slot, value, fp_mode, next);
  }

  void GenerateRecordWrite(SaveFPRegsMode fp_mode) {
    if (V8_DISABLE_WRITE_BARRIERS_BOOL) {
      Return(TrueConstant());
      return;
    }

    WriteBarrier(fp_mode);
    IncrementCounter(isolate()->counters()->write_barriers(), 1);
    Return(TrueConstant());
  }

  void GenerateIndirectPointerBarrier(SaveFPRegsMode fp_mode) {
    if (V8_DISABLE_WRITE_BARRIERS_BOOL) {
      Return(TrueConstant());
      return;
    }

    if (!V8_ENABLE_SANDBOX_BOOL) {
      Unreachable();
      return;
    }

    IndirectPointerWriteBarrier(fp_mode);
    IncrementCounter(isolate()->counters()->write_barriers(), 1);
    Return(TrueConstant());
  }

  void GenerateEphemeronKeyBarrier(SaveFPRegsMode fp_mode) {
    TNode<ExternalReference> function = ExternalConstant(
        ExternalReference::ephemeron_key_write_barrier_function());
    TNode<ExternalReference> isolate_constant =
        ExternalConstant(ExternalReference::isolate_address());
    // In this method we limit the allocatable registers so we have to use
    // UncheckedParameter. Parameter does not work because the checked cast
    // needs more registers.
    auto address =
        UncheckedParameter<IntPtrT>(WriteBarrierDescriptor::kSlotAddress);
    TNode<IntPtrT> object = BitcastTaggedToWord(
        UncheckedParameter<Object>(WriteBarrierDescriptor::kObject));

    CallCFunctionWithCallerSavedRegisters(
        function, MachineTypeOf<Int32T>::value, fp_mode,
        std::make_pair(MachineTypeOf<IntPtrT>::value, object),
        std::make_pair(MachineTypeOf<IntPtrT>::value, address),
        std::make_pair(MachineTypeOf<ExternalReference>::value,
                       isolate_constant));

    IncrementCounter(isolate()->counters()->write_barriers(), 1);
    Return(TrueConstant());
  }
};

TF_BUILTIN(RecordWriteSaveFP, WriteBarrierCodeStubAssembler) {
  GenerateRecordWrite(SaveFPRegsMode::kSave);
}

TF_BUILTIN(RecordWriteIgnoreFP, WriteBarrierCodeStubAssembler) {
  GenerateRecordWrite(SaveFPRegsMode::kIgnore);
}

TF_BUILTIN(IndirectPointerBarrierSaveFP, WriteBarrierCodeStubAssembler) {
  GenerateIndirectPointerBarrier(SaveFPRegsMode::kSave);
}

TF_BUILTIN(IndirectPointerBarrierIgnoreFP, WriteBarrierCodeStubAssembler) {
  GenerateIndirectPointerBarrier(SaveFPRegsMode::kIgnore);
}

TF_BUILTIN(EphemeronKeyBarrierSaveFP, WriteBarrierCodeStubAssembler) {
  GenerateEphemeronKeyBarrier(SaveFPRegsMode::kSave);
}

TF_BUILTIN(EphemeronKeyBarrierIgnoreFP, WriteBarrierCodeStubAssembler) {
  GenerateEphemeronKeyBarrier(SaveFPRegsMode::kIgnore);
}

#ifdef V8_IS_TSAN
class TSANRelaxedStoreCodeStubAssembler : public CodeStubAssembler {
 public:
  explicit TSANRelaxedStoreCodeStubAssembler(
      compiler::CodeAssemblerState* state)
      : CodeStubAssembler(state) {}

  TNode<ExternalReference> GetExternalReference(int size) {
    if (size == kInt8Size) {
      return ExternalConstant(
          ExternalReference::tsan_relaxed_store_function_8_bits());
    } else if (size == kInt16Size) {
      return ExternalConstant(
          ExternalReference::tsan_relaxed_store_function_16_bits());
    } else if (size == kInt32Size) {
      return ExternalConstant(
          ExternalReference::tsan_relaxed_store_function_32_bits());
    } else {
      CHECK_EQ(size, kInt64Size);
      return ExternalConstant(
          ExternalReference::tsan_relaxed_store_function_64_bits());
    }
  }

  void GenerateTSANRelaxedStore(SaveFPRegsMode fp_mode, int size) {
    TNode<ExternalReference> function = GetExternalReference(size);
    auto address = UncheckedParameter<IntPtrT>(TSANStoreDescriptor::kAddress);
    TNode<IntPtrT> value = BitcastTaggedToWord(
        UncheckedParameter<Object>(TSANStoreDescriptor::kValue));
    CallCFunctionWithCallerSavedRegisters(
        function, MachineType::Int32(), fp_mode,
        std::make_pair(MachineType::IntPtr(), address),
        std::make_pair(MachineType::IntPtr(), value));
    Return(UndefinedConstant());
  }
};

TF_BUILTIN(TSANRelaxedStore8IgnoreFP, TSANRelaxedStoreCodeStubAssembler) {
  GenerateTSANRelaxedStore(SaveFPRegsMode::kIgnore, kInt8Size);
}

TF_BUILTIN(TSANRelaxedStore8SaveFP, TSANRelaxedStoreCodeStubAssembler) {
  GenerateTSANRelaxedStore(SaveFPRegsMode::kSave, kInt8Size);
}

TF_BUILTIN(TSANRelaxedStore16IgnoreFP, TSANRelaxedStoreCodeStubAssembler) {
  GenerateTSANRelaxedStore(SaveFPRegsMode::kIgnore, kInt16Size);
}

TF_BUILTIN(TSANRelaxedStore16SaveFP, TSANRelaxedStoreCodeStubAssembler) {
  GenerateTSANRelaxedStore(SaveFPRegsMode::kSave, kInt16Size);
}

TF_BUILTIN(TSANRelaxedStore32IgnoreFP, TSANRelaxedStoreCodeStubAssembler) {
  GenerateTSANRelaxedStore(SaveFPRegsMode::kIgnore, kInt32Size);
}

TF_BUILTIN(TSANRelaxedStore32SaveFP, TSANRelaxedStoreCodeStubAssembler) {
  GenerateTSANRelaxedStore(SaveFPRegsMode::kSave, kInt32Size);
}

TF_BUILTIN(TSANRelaxedStore64IgnoreFP, TSANRelaxedStoreCodeStubAssembler) {
  GenerateTSANRelaxedStore(SaveFPRegsMode::kIgnore, kInt64Size);
}

TF_BUILTIN(TSANRelaxedStore64SaveFP, TSANRelaxedStoreCodeStubAssembler) {
  GenerateTSANRelaxedStore(SaveFPRegsMode::kSave, kInt64Size);
}

class TSANSeqCstStoreCodeStubAssembler : public CodeStubAssembler {
 public:
  explicit TSANSeqCstStoreCodeStubAssembler(compiler::CodeAssemblerState* state)
      : CodeStubAssembler(state) {}

  TNode<ExternalReference> GetExternalReference(int size) {
    if (size == kInt8Size) {
      return ExternalConstant(
          ExternalReference::tsan_seq_cst_store_function_8_bits());
    } else if (size == kInt16Size) {
      return ExternalConstant(
          ExternalReference::tsan_seq_cst_store_function_16_bits());
    } else if (size == kInt32Size) {
      return ExternalConstant(
          ExternalReference::tsan_seq_cst_store_function_32_bits());
    } else {
      CHECK_EQ(size, kInt64Size);
      return ExternalConstant(
          ExternalReference::tsan_seq_cst_store_function_64_bits());
    }
  }

  void GenerateTSANSeqCstStore(SaveFPRegsMode fp_mode, int size) {
    TNode<ExternalReference> function = GetExternalReference(size);
    auto address = UncheckedParameter<IntPtrT>(TSANStoreDescriptor::kAddress);
    TNode<IntPtrT> value = BitcastTaggedToWord(
        UncheckedParameter<Object>(TSANStoreDescriptor::kValue));
    CallCFunctionWithCallerSavedRegisters(
        function, MachineType::Int32(), fp_mode,
        std::make_pair(MachineType::IntPtr(), address),
        std::make_pair(MachineType::IntPtr(), value));
    Return(UndefinedConstant());
  }
};

TF_BUILTIN(TSANSeqCstStore8IgnoreFP, TSANSeqCstStoreCodeStubAssembler) {
  GenerateTSANSeqCstStore(SaveFPRegsMode::kIgnore, kInt8Size);
}

TF_BUILTIN(TSANSeqCstStore8SaveFP, TSANSeqCstStoreCodeStubAssembler) {
  GenerateTSANSeqCstStore(SaveFPRegsMode::kSave, kInt8Size);
}

TF_BUILTIN(TSANSeqCstStore16IgnoreFP, TSANSeqCstStoreCodeStubAssembler) {
  GenerateTSANSeqCstStore(SaveFPRegsMode::kIgnore, kInt16Size);
}

TF_BUILTIN(TSANSeqCstStore16SaveFP, TSANSeqCstStoreCodeStubAssembler) {
  GenerateTSANSeqCstStore(SaveFPRegsMode::kSave, kInt16Size);
}

TF_BUILTIN(TSANSeqCstStore32IgnoreFP, TSANSeqCstStoreCodeStubAssembler) {
  GenerateTSANSeqCstStore(SaveFPRegsMode::kIgnore, kInt32Size);
}

TF_BUILTIN(TSANSeqCstStore32SaveFP, TSANSeqCstStoreCodeStubAssembler) {
  GenerateTSANSeqCstStore(SaveFPRegsMode::kSave, kInt32Size);
}

TF_BUILTIN(TSANSeqCstStore64IgnoreFP, TSANSeqCstStoreCodeStubAssembler) {
  GenerateTSANSeqCstStore(SaveFPRegsMode::kIgnore, kInt64Size);
}

TF_BUILTIN(TSANSeqCstStore64SaveFP, TSANSeqCstStoreCodeStubAssembler) {
  GenerateTSANSeqCstStore(SaveFPRegsMode::kSave, kInt64Size);
}

class TSANRelaxedLoadCodeStubAssembler : public CodeStubAssembler {
 public:
  explicit TSANRelaxedLoadCodeStubAssembler(compiler::CodeAssemblerState* state)
      : CodeStubAssembler(state) {}

  TNode<ExternalReference> GetExternalReference(int size) {
    if (size == kInt32Size) {
      return ExternalConstant(
          ExternalReference::tsan_relaxed_load_function_32_bits());
    } else {
      CHECK_EQ(size, kInt64Size);
      return ExternalConstant(
          ExternalReference::tsan_relaxed_load_function_64_bits());
    }
  }

  void GenerateTSANRelaxedLoad(SaveFPRegsMode fp_mode, int size) {
    TNode<ExternalReference> function = GetExternalReference(size);
    auto address = UncheckedParameter<IntPtrT>(TSANLoadDescriptor::kAddress);
    CallCFunctionWithCallerSavedRegisters(
        function, MachineType::Int32(), fp_mode,
        std::make_pair(MachineType::IntPtr(), address));
    Return(UndefinedConstant());
  }
};

TF_BUILTIN(TSANRelaxedLoad32IgnoreFP, TSANRelaxedLoadCodeStubAssembler) {
  GenerateTSANRelaxedLoad(SaveFPRegsMode::kIgnore, kInt32Size);
}

TF_BUILTIN(TSANRelaxedLoad32SaveFP, TSANRelaxedLoadCodeStubAssembler) {
  GenerateTSANRelaxedLoad(SaveFPRegsMode::kSave, kInt32Size);
}

TF_BUILTIN(TSANRelaxedLoad64IgnoreFP, TSANRelaxedLoadCodeStubAssembler) {
  GenerateTSANRelaxedLoad(SaveFPRegsMode::kIgnore, kInt64Size);
}

TF_BUILTIN(TSANRelaxedLoad64SaveFP, TSANRelaxedLoadCodeStubAssembler) {
  GenerateTSANRelaxedLoad(SaveFPRegsMode::kSave, kInt64Size);
}
#endif  // V8_IS_TSAN

class DeletePropertyBaseAssembler : public AccessorAssembler {
 public:
  explicit DeletePropertyBaseAssembler(compiler::CodeAssemblerState* state)
      : AccessorAssembler(state) {}

  void DictionarySpecificDelete(TNode<JSReceiver> receiver,
                                TNode<NameDictionary> properties,
                                TNode<IntPtrT> key_index,
                                TNode<Context> context) {
    // Overwrite the entry itself (see NameDictionary::SetEntry).
    TNode<Hole> filler = TheHoleConstant();
    DCHECK(RootsTable::IsImmortalImmovable(RootIndex::kTheHoleValue));
    StoreFixedArrayElement(properties, key_index, filler, SKIP_WRITE_BARRIER);
    StoreValueByKeyIndex<NameDictionary>(properties, key_index, filler,
                                         SKIP_WRITE_BARRIER);
    StoreDetailsByKeyIndex<NameDictionary>(properties, key_index,
                                           SmiConstant(0));

    // Update bookkeeping information (see NameDictionary::ElementRemoved).
    TNode<Smi> nof = GetNumberOfElements<NameDictionary>(properties);
    TNode<Smi> new_nof = SmiSub(nof, SmiConstant(1));
    SetNumberOfElements<NameDictionary>(properties, new_nof);
    TNode<Smi> num_deleted =
        GetNumberOfDeletedElements<NameDictionary>(properties);
    TNode<Smi> new_deleted = SmiAdd(num_deleted, SmiConstant(1));
    SetNumberOfDeletedElements<NameDictionary>(properties, new_deleted);

    // Shrink the dictionary if necessary (see NameDictionary::Shrink).
```