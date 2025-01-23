Response:
The user wants a summary of the provided C++ code snippet from V8's `code-stub-assembler.cc`. The summary should cover the functionality, potential relationship to JavaScript, examples of usage in JavaScript if applicable, logical code inferences with hypothetical inputs and outputs, common programming errors related to the code, and a general overview of its purpose within the larger file.

Here's a breakdown of how to approach this:

1. **Identify Core Functionality:**  Scan the code for function definitions and their actions. Keywords like `Copy`, `BuildFastLoop`, `Fill`, `Allocate`, `Grow`, `Truncate`, `TryTaggedTo`, and `Load/Store` provide strong hints. The code appears to be dealing with copying data between arrays, managing array growth, converting between different data types (especially numbers and tagged values), and memory management.

2. **Analyze Individual Functions:** For each function, try to understand its input parameters, the operations it performs, and its return value (if any). Pay attention to template parameters and their implications (e.g., `TIndex` being `Smi` or `IntPtrT`).

3. **Connect to JavaScript:** Think about how these low-level operations might be used in JavaScript. Array manipulation (slicing, copying), type conversions (number to integer, string to number), and object creation/modification are likely candidates.

4. **Create JavaScript Examples:**  For functions related to JavaScript functionality, construct simple JavaScript code snippets that would likely trigger the execution of these C++ functions.

5. **Infer Logic and Provide Examples:**  For functions with clear logic (like `CalculateNewElementsCapacity`), provide hypothetical input values and the expected output based on the code.

6. **Identify Potential Errors:** Based on the operations performed, consider common programming errors that could lead to issues with these functions. For example, incorrect array indices, type mismatches, or exceeding array bounds.

7. **Synthesize the Overall Purpose:** Combine the understanding of individual functions to formulate a high-level summary of the code's role within `code-stub-assembler.cc`. Recognize that it's part of the code generation process and likely involves optimizing common operations.

8. **Address Specific Instructions:** Ensure all parts of the prompt are covered: `.tq` extension, JavaScript examples, input/output examples, common errors, and the overall summary as part 8 of 23.```cpp
de<IntPtrT> dst_elements_intptr = BitcastTaggedToWord(dst_elements);
  TNode<IntPtrT> dst_data_ptr =
      IntPtrAdd(dst_elements_intptr, dst_offset_start);
  TNode<ExternalReference> memcpy =
      ExternalConstant(ExternalReference::libc_memcpy_function());
  CallCFunction(memcpy, MachineType::Pointer(),
                std::make_pair(MachineType::Pointer(), dst_data_ptr),
                std::make_pair(MachineType::Pointer(), source_data_ptr),
                std::make_pair(MachineType::UintPtr(), source_byte_length));

  if (needs_barrier_check) {
    Goto(&finished);

    BIND(&needs_barrier);
    {
      const TNode<IntPtrT> begin = src_index;
      const TNode<IntPtrT> end = IntPtrAdd(begin, length);
      const TNode<IntPtrT> delta =
          IntPtrMul(IntPtrSub(dst_index, src_index),
                    IntPtrConstant(ElementsKindToByteSize(kind)));
      BuildFastArrayForEach(
          src_elements, kind, begin, end,
          [&](TNode<HeapObject> array, TNode<IntPtrT> offset) {
            const TNode<AnyTaggedT> element = Load<AnyTaggedT>(array, offset);
            const TNode<WordT> delta_offset = IntPtrAdd(offset, delta);
            if (write_barrier == SKIP_WRITE_BARRIER) {
              StoreNoWriteBarrier(MachineRepresentation::kTagged, dst_elements,
                                  delta_offset, element);
            } else {
              Store(dst_elements, delta_offset, element);
            }
          },
          LoopUnrollingMode::kYes, ForEachDirection::kForward);
      Goto(&finished);
    }
    BIND(&finished);
  }
}

void CodeStubAssembler::CopyRange(TNode<HeapObject> dst_object, int dst_offset,
                                  TNode<HeapObject> src_object, int src_offset,
                                  TNode<IntPtrT> length_in_tagged,
                                  WriteBarrierMode mode) {
  // TODO(jgruber): This could be a lot more involved (e.g. better code when
  // write barriers can be skipped). Extend as needed.
  BuildFastLoop<IntPtrT>(
      IntPtrConstant(0), length_in_tagged,
      [=, this](TNode<IntPtrT> index) {
        TNode<IntPtrT> current_src_offset =
            IntPtrAdd(TimesTaggedSize(index), IntPtrConstant(src_offset));
        TNode<Object> value = LoadObjectField(src_object, current_src_offset);
        TNode<IntPtrT> current_dst_offset =
            IntPtrAdd(TimesTaggedSize(index), IntPtrConstant(dst_offset));
        if (mode == SKIP_WRITE_BARRIER) {
          StoreObjectFieldNoWriteBarrier(dst_object, current_dst_offset, value);
        } else {
          StoreObjectField(dst_object, current_dst_offset, value);
        }
      },
      1, LoopUnrollingMode::kYes, IndexAdvanceMode::kPost);
}

template <typename TIndex>
void CodeStubAssembler::CopyFixedArrayElements(
    ElementsKind from_kind, TNode<FixedArrayBase> from_array,
    ElementsKind to_kind, TNode<FixedArrayBase> to_array,
    TNode<TIndex> first_element, TNode<TIndex> element_count,
    TNode<TIndex> capacity, WriteBarrierMode barrier_mode,
    HoleConversionMode convert_holes, TVariable<BoolT>* var_holes_converted) {
  DCHECK_IMPLIES(var_holes_converted != nullptr,
                 convert_holes == HoleConversionMode::kConvertToUndefined);
  CSA_SLOW_DCHECK(this, IsFixedArrayWithKindOrEmpty(from_array, from_kind));
  CSA_SLOW_DCHECK(this, IsFixedArrayWithKindOrEmpty(to_array, to_kind));
  static_assert(OFFSET_OF_DATA_START(FixedArray) ==
                OFFSET_OF_DATA_START(FixedDoubleArray));
  static_assert(
      std::is_same<TIndex, Smi>::value || std::is_same<TIndex, IntPtrT>::value,
      "Only Smi or IntPtrT indices are allowed");

  const int first_element_offset =
      OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag;
  Comment("[ CopyFixedArrayElements");

  // Typed array elements are not supported.
  DCHECK(!IsTypedArrayElementsKind(from_kind));
  DCHECK(!IsTypedArrayElementsKind(to_kind));

  Label done(this);
  bool from_double_elements = IsDoubleElementsKind(from_kind);
  bool to_double_elements = IsDoubleElementsKind(to_kind);
  bool doubles_to_objects_conversion =
      IsDoubleElementsKind(from_kind) && IsObjectElementsKind(to_kind);
  bool needs_write_barrier =
      doubles_to_objects_conversion ||
      (barrier_mode == UPDATE_WRITE_BARRIER && IsObjectElementsKind(to_kind));
  bool element_offset_matches =
      !needs_write_barrier &&
      (kTaggedSize == kDoubleSize ||
       IsDoubleElementsKind(from_kind) == IsDoubleElementsKind(to_kind));
  TNode<UintPtrT> double_hole =
      Is64() ? ReinterpretCast<UintPtrT>(Int64Constant(kHoleNanInt64))
             : ReinterpretCast<UintPtrT>(Int32Constant(kHoleNanLower32));

  // If copying might trigger a GC, we pre-initialize the FixedArray such that
  // it's always in a consistent state.
  if (convert_holes == HoleConversionMode::kConvertToUndefined) {
    DCHECK(IsObjectElementsKind(to_kind));
    // Use undefined for the part that we copy and holes for the rest.
    // Later if we run into a hole in the source we can just skip the writing
    // to the target and are still guaranteed that we get an undefined.
    FillFixedArrayWithValue(to_kind, to_array, IntPtrOrSmiConstant<TIndex>(0),
                            element_count, RootIndex::kUndefinedValue);
    FillFixedArrayWithValue(to_kind, to_array, element_count, capacity,
                            RootIndex::kTheHoleValue);
  } else if (doubles_to_objects_conversion) {
    // Pre-initialized the target with holes so later if we run into a hole in
    // the source we can just skip the writing to the target.
    FillFixedArrayWithValue(to_kind, to_array, IntPtrOrSmiConstant<TIndex>(0),
                            capacity, RootIndex::kTheHoleValue);
  } else if (element_count != capacity) {
    FillFixedArrayWithValue(to_kind, to_array, element_count, capacity,
                            RootIndex::kTheHoleValue);
  }

  TNode<IntPtrT> first_from_element_offset =
      ElementOffsetFromIndex(first_element, from_kind, 0);
  TNode<IntPtrT> limit_offset = Signed(IntPtrAdd(
      first_from_element_offset, IntPtrConstant(first_element_offset)));
  TVARIABLE(IntPtrT, var_from_offset,
            ElementOffsetFromIndex(IntPtrOrSmiAdd(first_element, element_count),
                                   from_kind, first_element_offset));
  // This second variable is used only when the element sizes of source and
  // destination arrays do not match.
  TVARIABLE(IntPtrT, var_to_offset);
  if (element_offset_matches) {
    var_to_offset = var_from_offset.value();
  } else {
    var_to_offset =
        ElementOffsetFromIndex(element_count, to_kind, first_element_offset);
  }

  VariableList vars({&var_from_offset, &var_to_offset}, zone());
  if (var_holes_converted != nullptr) vars.push_back(var_holes_converted);
  Label decrement(this, vars);

  TNode<IntPtrT> to_array_adjusted =
      element_offset_matches
          ? IntPtrSub(BitcastTaggedToWord(to_array), first_from_element_offset)
          : ReinterpretCast<IntPtrT>(to_array);

  Branch(WordEqual(var_from_offset.value(), limit_offset), &done, &decrement);

  BIND(&decrement);
  {
    TNode<IntPtrT> from_offset = Signed(IntPtrSub(
        var_from_offset.value(),
        IntPtrConstant(from_double_elements ? kDoubleSize : kTaggedSize)));
    var_from_offset = from_offset;

    TNode<IntPtrT> to_offset;
    if (element_offset_matches) {
      to_offset = from_offset;
    } else {
      to_offset = IntPtrSub(
          var_to_offset.value(),
          IntPtrConstant(to_double_elements ? kDoubleSize : kTaggedSize));
      var_to_offset = to_offset;
    }

    Label next_iter(this), store_double_hole(this), signal_hole(this);
    Label* if_hole;
    if (convert_holes == HoleConversionMode::kConvertToUndefined) {
      // The target elements array is already preinitialized with undefined
      // so we only need to signal that a hole was found and continue the loop.
      if_hole = &signal_hole;
    } else if (doubles_to_objects_conversion) {
      // The target elements array is already preinitialized with holes, so we
      // can just proceed with the next iteration.
      if_hole = &next_iter;
    } else if (IsDoubleElementsKind(to_kind)) {
      if_hole = &store_double_hole;
    } else {
      // In all the other cases don't check for holes and copy the data as is.
      if_hole = nullptr;
    }

    if (to_double_elements) {
      DCHECK(!needs_write_barrier);
      TNode<Float64T> value = LoadElementAndPrepareForStore<Float64T>(
          from_array, var_from_offset.value(), from_kind, to_kind, if_hole);
      StoreNoWriteBarrier(MachineRepresentation::kFloat64, to_array_adjusted,
                          to_offset, value);
    } else {
      TNode<Object> value = LoadElementAndPrepareForStore<Object>(
          from_array, var_from_offset.value(), from_kind, to_kind, if_hole);
      if (needs_write_barrier) {
        CHECK_EQ(to_array, to_array_adjusted);
        Store(to_array_adjusted, to_offset, value);
      } else {
        UnsafeStoreNoWriteBarrier(MachineRepresentation::kTagged,
                                  to_array_adjusted, to_offset, value);
      }
    }

    Goto(&next_iter);

    if (if_hole == &store_double_hole) {
      BIND(&store_double_hole);
      // Don't use doubles to store the hole double, since manipulating the
      // signaling NaN used for the hole in C++, e.g. with base::bit_cast,
      // will change its value on ia32 (the x87 stack is used to return values
      // and stores to the stack silently clear the signalling bit).
      //
      // TODO(danno): When we have a Float32/Float64 wrapper class that
      // preserves double bits during manipulation, remove this code/change
      // this to an indexed Float64 store.
      if (Is64()) {
        StoreNoWriteBarrier(MachineRepresentation::kWord64, to_array_adjusted,
                            to_offset, double_hole);
      } else {
        StoreNoWriteBarrier(MachineRepresentation::kWord32, to_array_adjusted,
                            to_offset, double_hole);
        StoreNoWriteBarrier(MachineRepresentation::kWord32, to_array_adjusted,
                            IntPtrAdd(to_offset, IntPtrConstant(kInt32Size)),
                            double_hole);
      }
      Goto(&next_iter);
    } else if (if_hole == &signal_hole) {
      // This case happens only when IsObjectElementsKind(to_kind).
      BIND(&signal_hole);
      if (var_holes_converted != nullptr) {
        *var_holes_converted = Int32TrueConstant();
      }
      Goto(&next_iter);
    }

    BIND(&next_iter);
    TNode<BoolT> compare = WordNotEqual(from_offset, limit_offset);
    Branch(compare, &decrement, &done);
  }

  BIND(&done);
  Comment("] CopyFixedArrayElements");
}

TNode<FixedArray> CodeStubAssembler::HeapObjectToFixedArray(
    TNode<HeapObject> base, Label* cast_fail) {
  Label fixed_array(this);
  TNode<Map> map = LoadMap(base);
  GotoIf(TaggedEqual(map, FixedArrayMapConstant()), &fixed_array);
  GotoIf(TaggedNotEqual(map, FixedCOWArrayMapConstant()), cast_fail);
  Goto(&fixed_array);
  BIND(&fixed_array);
  return UncheckedCast<FixedArray>(base);
}

void CodeStubAssembler::CopyPropertyArrayValues(TNode<HeapObject> from_array,
                                                TNode<PropertyArray> to_array,
                                                TNode<IntPtrT> property_count,
                                                WriteBarrierMode barrier_mode,
                                                DestroySource destroy_source) {
  CSA_SLOW_DCHECK(this, Word32Or(IsPropertyArray(from_array),
                                 IsEmptyFixedArray(from_array)));
  Comment("[ CopyPropertyArrayValues");

  bool needs_write_barrier = barrier_mode == UPDATE_WRITE_BARRIER;

  if (destroy_source == DestroySource::kNo) {
    // PropertyArray may contain mutable HeapNumbers, which will be cloned on
    // the heap, requiring a write barrier.
    needs_write_barrier = true;
  }

  TNode<IntPtrT> start = IntPtrConstant(0);
  ElementsKind kind = PACKED_ELEMENTS;
  BuildFastArrayForEach(
      from_array, kind, start, property_count,
      [this, to_array, needs_write_barrier, destroy_source](
          TNode<HeapObject> array, TNode<IntPtrT> offset) {
        TNode<AnyTaggedT> value = Load<AnyTaggedT>(array, offset);

        if (destroy_source == DestroySource::kNo) {
          value = CloneIfMutablePrimitive(CAST(value));
        }

        if (needs_write_barrier) {
          Store(to_array, offset, value);
        } else {
          StoreNoWriteBarrier(MachineRepresentation::kTagged, to_array, offset,
                              value);
        }
      },
      LoopUnrollingMode::kYes);

#ifdef DEBUG
  // Zap {from_array} if the copying above has made it invalid.
  if (destroy_source == DestroySource::kYes) {
    Label did_zap(this);
    GotoIf(IsEmptyFixedArray(from_array), &did_zap);
    FillPropertyArrayWithUndefined(CAST(from_array), start, property_count);

    Goto(&did_zap);
    BIND(&did_zap);
  }
#endif
  Comment("] CopyPropertyArrayValues");
}

TNode<FixedArrayBase> CodeStubAssembler::CloneFixedArray(
    TNode<FixedArrayBase> source, ExtractFixedArrayFlags flags) {
  return ExtractFixedArray(
      source, std::optional<TNode<BInt>>(IntPtrOrSmiConstant<BInt>(0)),
      std::optional<TNode<BInt>>(std::nullopt),
      std::optional<TNode<BInt>>(std::nullopt), flags);
}

template <>
TNode<Object> CodeStubAssembler::LoadElementAndPrepareForStore(
    TNode<FixedArrayBase> array, TNode<IntPtrT> offset, ElementsKind from_kind,
    ElementsKind to_kind, Label* if_hole) {
  CSA_DCHECK(this, IsFixedArrayWithKind(array, from_kind));
  DCHECK(!IsDoubleElementsKind(to_kind));
  if (IsDoubleElementsKind(from_kind)) {
    TNode<Float64T> value =
        LoadDoubleWithHoleCheck(array, offset, if_hole, MachineType::Float64());
    return AllocateHeapNumberWithValue(value);
  } else {
    TNode<Object> value = Load<Object>(array, offset);
    if (if_hole) {
      GotoIf(TaggedEqual(value, TheHoleConstant()), if_hole);
    }
    return value;
  }
}

template <>
TNode<Float64T> CodeStubAssembler::LoadElementAndPrepareForStore(
    TNode<FixedArrayBase> array, TNode<IntPtrT> offset, ElementsKind from_kind,
    ElementsKind to_kind, Label* if_hole) {
  CSA_DCHECK(this, IsFixedArrayWithKind(array, from_kind));
  DCHECK(IsDoubleElementsKind(to_kind));
  if (IsDoubleElementsKind(from_kind)) {
    return LoadDoubleWithHoleCheck(array, offset, if_hole,
                                   MachineType::Float64());
  } else {
    TNode<Object> value = Load<Object>(array, offset);
    if (if_hole) {
      GotoIf(TaggedEqual(value, TheHoleConstant()), if_hole);
    }
    if (IsSmiElementsKind(from_kind)) {
      return SmiToFloat64(CAST(value));
    }
    return LoadHeapNumberValue(CAST(value));
  }
}

template <typename TIndex>
TNode<TIndex> CodeStubAssembler::CalculateNewElementsCapacity(
    TNode<TIndex> old_capacity) {
  static_assert(
      std::is_same<TIndex, Smi>::value || std::is_same<TIndex, IntPtrT>::value,
      "Only Smi or IntPtrT old_capacity is allowed");
  Comment("TryGrowElementsCapacity");
  TNode<TIndex> half_old_capacity = WordOrSmiShr(old_capacity, 1);
  TNode<TIndex> new_capacity = IntPtrOrSmiAdd(half_old_capacity, old_capacity);
  TNode<TIndex> padding =
      IntPtrOrSmiConstant<TIndex>(JSObject::kMinAddedElementsCapacity);
  return IntPtrOrSmiAdd(new_capacity, padding);
}

template V8_EXPORT_PRIVATE TNode<IntPtrT>
    CodeStubAssembler::CalculateNewElementsCapacity<IntPtrT>(TNode<IntPtrT>);
template V8_EXPORT_PRIVATE TNode<Smi>
    CodeStubAssembler::CalculateNewElementsCapacity<Smi>(TNode<Smi>);

TNode<FixedArrayBase> CodeStubAssembler::TryGrowElementsCapacity(
    TNode<HeapObject> object, TNode<FixedArrayBase> elements, ElementsKind kind,
    TNode<Smi> key, Label* bailout) {
  CSA_SLOW_DCHECK(this, IsFixedArrayWithKindOrEmpty(elements, kind));
  TNode<Smi> capacity = LoadFixedArrayBaseLength(elements);

  return TryGrowElementsCapacity(object, elements, kind,
                                 TaggedToParameter<BInt>(key),
                                 TaggedToParameter<BInt>(capacity), bailout);
}

template <typename TIndex>
TNode<FixedArrayBase> CodeStubAssembler::TryGrowElementsCapacity(
    TNode<HeapObject> object, TNode<FixedArrayBase> elements, ElementsKind kind,
    TNode<TIndex> key, TNode<TIndex> capacity, Label* bailout) {
  static_assert(
      std::is_same<TIndex, Smi>::value || std::is_same<TIndex, IntPtrT>::value,
      "Only Smi or IntPtrT key and capacity nodes are allowed");
  Comment("TryGrowElementsCapacity");
  CSA_SLOW_DCHECK(this, IsFixedArrayWithKindOrEmpty(elements, kind));

  // If the gap growth is too big, fall back to the runtime.
  TNode<TIndex> max_gap = IntPtrOrSmiConstant<TIndex>(JSObject::kMaxGap);
  TNode<TIndex> max_capacity = IntPtrOrSmiAdd(capacity, max_gap);
  GotoIf(UintPtrOrSmiGreaterThanOrEqual(key, max_capacity), bailout);

  // Calculate the capacity of the new backing store.
  TNode<TIndex> new_capacity = CalculateNewElementsCapacity(
      IntPtrOrSmiAdd(key, IntPtrOrSmiConstant<TIndex>(1)));

  return GrowElementsCapacity(object, elements, kind, kind, capacity,
                              new_capacity, bailout);
}

template <typename TIndex>
TNode<FixedArrayBase> CodeStubAssembler::GrowElementsCapacity(
    TNode<HeapObject> object, TNode<FixedArrayBase> elements,
    ElementsKind from_kind, ElementsKind to_kind, TNode<TIndex> capacity,
    TNode<TIndex> new_capacity, Label* bailout) {
  static_assert(
      std::is_same<TIndex, Smi>::value || std::is_same<TIndex, IntPtrT>::value,
      "Only Smi or IntPtrT capacities are allowed");
  Comment("[ GrowElementsCapacity");
  CSA_SLOW_DCHECK(this, IsFixedArrayWithKindOrEmpty(elements, from_kind));

  // If size of the allocation for the new capacity doesn't fit in a page
  // that we can bump-pointer allocate from, fall back to the runtime.
  int max_size = FixedArrayBase::GetMaxLengthForNewSpaceAllocation(to_kind);
  GotoIf(UintPtrOrSmiGreaterThanOrEqual(new_capacity,
                                        IntPtrOrSmiConstant<TIndex>(max_size)),
         bailout);

  // Allocate the new backing store.
  TNode<FixedArrayBase> new_elements =
      AllocateFixedArray(to_kind, new_capacity);

  // Copy the elements from the old elements store to the new.
  // The size-check above guarantees that the |new_elements| is allocated
  // in new space so we can skip the write barrier.
  CopyFixedArrayElements(from_kind, elements, to_kind, new_elements, capacity,
                         new_capacity, SKIP_WRITE_BARRIER);

  StoreObjectField(object, JSObject::kElementsOffset, new_elements);
  Comment("] GrowElementsCapacity");
  return new_elements;
}

template TNode<FixedArrayBase> CodeStubAssembler::GrowElementsCapacity<IntPtrT>(
    TNode<HeapObject>, TNode<FixedArrayBase>, ElementsKind, ElementsKind,
    TNode<IntPtrT>, TNode<IntPtrT>, compiler::CodeAssemblerLabel*);

namespace {

// Helper function for folded memento allocation.
// Memento objects are designed to be put right after the objects they are
// tracking on. So memento allocations have to be folded together with previous
// object allocations.
TNode<HeapObject> InnerAllocateMemento(CodeStubAssembler* csa,
                                       TNode<HeapObject> previous,
                                       TNode<IntPtrT> offset) {
  return csa->UncheckedCast<HeapObject>(csa->BitcastWordToTagged(
      csa->IntPtrAdd(csa->BitcastTaggedToWord(previous), offset)));
}

}  // namespace

void CodeStubAssembler::InitializeAllocationMemento(
    TNode<HeapObject> base, TNode<IntPtrT> base_allocation_size,
    TNode<AllocationSite> allocation_site) {
  DCHECK(V8_ALLOCATION_SITE_TRACKING_BOOL);
  Comment("[Initialize AllocationMemento");
  TNode<HeapObject> memento =
      InnerAllocateMemento(this, base, base_allocation_size);
  StoreMapNoWriteBarrier(memento, RootIndex::kAllocationMementoMap);
  StoreObjectFieldNoWriteBarrier(
      memento, AllocationMemento::kAllocationSiteOffset, allocation_site);
  if (v8_flags.allocation_site_pretenuring) {
    TNode<Int32T> count = LoadObjectField<Int32T>(
        allocation_site, AllocationSite::kPretenureCreateCountOffset);

    TNode<Int32T> incremented_count = Int32Add(count, Int32Constant(1));
    StoreObjectFieldNoWriteBarrier(allocation_site,
                                   AllocationSite::kPretenureCreateCountOffset,
                                   incremented_count);
  }
  Comment("]");
}

TNode<IntPtrT> CodeStubAssembler::TryTaggedToInt32AsIntPtr(
    TNode<Object> acc, Label* if_not_possible) {
  TVARIABLE(IntPtrT, acc_intptr);
  Label is_not_smi(this), have_int32(this);

  GotoIfNot(TaggedIsSmi(acc), &is_not_smi);
  acc_intptr = SmiUntag(CAST(acc));
  Goto(&have_int32);

  BIND(&is_not_smi);
  GotoIfNot(IsHeapNumber(CAST(acc)), if_not_possible);
  TNode<Float64T> value = LoadHeapNumberValue(CAST(acc));
  TNode<Int32T> value32 = RoundFloat64ToInt32(value);
  TNode<Float64T> value64 = ChangeInt32ToFloat64(value32);
  GotoIfNot(Float64Equal(value, value64), if_not_possible);
  acc_intptr = ChangeInt32ToIntPtr(value32);
  Goto(&have_int32);

  BIND(&have_int32);
  return acc_intptr.value();
}

TNode<Float64T> CodeStubAssembler::TryTaggedToFloat64(
    TNode<Object> value, Label* if_valueisnotnumber) {
  return Select<Float64T>(
      TaggedIsSmi(value), [&]() { return SmiToFloat64(CAST(value)); },
      [&]() {
        GotoIfNot(IsHeapNumber(CAST(value)), if_valueisnotnumber);
        return LoadHeapNumberValue(CAST(value));
      });
}

TNode<Float64T> CodeStubAssembler::TruncateTaggedToFloat64(
    TNode<Context> context, TNode<Object> value) {
  // We might need to loop once due to ToNumber conversion.
  TVARIABLE(Object, var_value, value);
  TVARIABLE(Float64T, var_result);
  Label loop(this, &var_value), done_loop(this, &var_result);
  Goto(&loop);
  BIND(&loop);
  {
    Label if_valueisnotnumber(this, Label::kDeferred);

    // Load the current {value}.
    value = var_value.value();

    // Convert {value} to Float64 if it is a number and convert it to a number
    // otherwise.
    var_result = TryTaggedToFloat64(value, &if_valueisnotnumber);
    Goto(&done_loop);

    BIND(&if_valueisnotnumber);
    {
      // Convert the {value} to a Number first.
      var_value = CallBuiltin(Builtin::kNonNumberToNumber, context, value);
      Goto(&loop);
    }
  }
  BIND(&done_loop);
  return var_result.value();
}

TNode<Word32T> CodeStubAssembler::TruncateTaggedToWord32(TNode<Context> context,
                                                         TNode<Object> value) {
  TVARIABLE(Word32T, var_result);
  Label done(this);
  TaggedToWord32OrBigIntImpl<Object::Conversion::kToNumber>(
      context, value, &done, &var_result, IsKnownTaggedPointer::kNo, {});
  BIND(&done);
  return var_result.value();
}

// Truncate {value} to word32 and jump to {if_number} if it is a Number,
// or find that it is a BigInt and jump to {if_bigint}.
void CodeStubAssembler::TaggedToWord32OrBigInt(
    TNode<Context> context, TNode<Object> value, Label* if_number,
    TVariable<Word32T>* var_word32, Label* if_bigint, Label* if_bigint64,
    TVariable<BigInt>* var_maybe_bigint) {
  TaggedToWord32OrBigIntImpl<Object::Conversion::kToNumeric>(
      context, value, if_number, var_word32, IsKnownTaggedPointer::kNo, {},
      if_bigint, if_bigint64, var_maybe_bigint);
}

// Truncate {value} to word32 and jump to {if_number} if it is a Number,
// or find that it is a BigInt and jump to {if_bigint}. In either case,
// store the type feedback in {var_feedback}.
void CodeStubAssembler::TaggedToWord32OrBigIntWithFeedback(
    TNode<Context> context, TNode<Object> value, Label* if_number,
    TVariable<Word32T>* var_word32, Label* if_bigint, Label* if_bigint64,
    TVariable<BigInt>* var_maybe_bigint, const FeedbackValues& feedback) {
  TaggedToWord32OrBigIntImpl<Object::Conversion::kToNumeric>(
      context, value, if_number, var_word32, IsKnownTaggedPointer::kNo,
      feedback, if_bigint, if_bigint64, var_maybe_bigint);
}

// Truncate {pointer} to word32 and jump to {if_number} if it is a Number,
// or find that it is a BigInt and jump to {if_bigint}. In either case,
// store the type feedback in {var_feedback}.
void CodeStubAssembler::TaggedPointerToWord32OrBigIntWithFeedback(
    TNode<Context> context, TNode<HeapObject> pointer, Label* if_number,
    TVariable<Word32T>* var_word32, Label* if_bigint, Label* if_bigint64,
    TVariable<BigInt>* var_maybe_bigint, const FeedbackValues& feedback) {
  TaggedToWord32OrBigIntImpl<Object::Conversion::kToNumeric>(
      context, pointer, if_number, var_word32, IsKnownTaggedPointer::kYes,
      feedback, if_bigint, if_bigint64, var_maybe_bigint);
}

template <Object::Conversion conversion>
void CodeStubAssembler::TaggedToWord32OrBigIntImpl(
    TNode<Context> context, TNode<Object> value, Label* if_number,
    TVariable<Word32T>* var_word32,
    IsKnownTaggedPointer is_known_tagged_pointer,
    const FeedbackValues& feedback, Label* if_bigint, Label* if_bigint64,
    TVariable<BigInt>* var_maybe_bigint) {
  // We might need to loop after conversion.
  TVARIABLE(Object, var_value, value);
  TVARIABLE(Object, var_exception);
  OverwriteFeedback(feedback.var_feedback, BinaryOperationFeedback::kNone);
  VariableList loop_vars({&var_value}, zone());
  if (feedback.var_feedback != nullptr) {
    loop_vars.push_back(feedback.var_feedback);
  }
  Label loop(this, loop_vars);
  Label if_exception(
### 提示词
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/code-stub-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共23部分，请归纳一下它的功能
```

### 源代码
```cpp
de<IntPtrT> dst_elements_intptr = BitcastTaggedToWord(dst_elements);
  TNode<IntPtrT> dst_data_ptr =
      IntPtrAdd(dst_elements_intptr, dst_offset_start);
  TNode<ExternalReference> memcpy =
      ExternalConstant(ExternalReference::libc_memcpy_function());
  CallCFunction(memcpy, MachineType::Pointer(),
                std::make_pair(MachineType::Pointer(), dst_data_ptr),
                std::make_pair(MachineType::Pointer(), source_data_ptr),
                std::make_pair(MachineType::UintPtr(), source_byte_length));

  if (needs_barrier_check) {
    Goto(&finished);

    BIND(&needs_barrier);
    {
      const TNode<IntPtrT> begin = src_index;
      const TNode<IntPtrT> end = IntPtrAdd(begin, length);
      const TNode<IntPtrT> delta =
          IntPtrMul(IntPtrSub(dst_index, src_index),
                    IntPtrConstant(ElementsKindToByteSize(kind)));
      BuildFastArrayForEach(
          src_elements, kind, begin, end,
          [&](TNode<HeapObject> array, TNode<IntPtrT> offset) {
            const TNode<AnyTaggedT> element = Load<AnyTaggedT>(array, offset);
            const TNode<WordT> delta_offset = IntPtrAdd(offset, delta);
            if (write_barrier == SKIP_WRITE_BARRIER) {
              StoreNoWriteBarrier(MachineRepresentation::kTagged, dst_elements,
                                  delta_offset, element);
            } else {
              Store(dst_elements, delta_offset, element);
            }
          },
          LoopUnrollingMode::kYes, ForEachDirection::kForward);
      Goto(&finished);
    }
    BIND(&finished);
  }
}

void CodeStubAssembler::CopyRange(TNode<HeapObject> dst_object, int dst_offset,
                                  TNode<HeapObject> src_object, int src_offset,
                                  TNode<IntPtrT> length_in_tagged,
                                  WriteBarrierMode mode) {
  // TODO(jgruber): This could be a lot more involved (e.g. better code when
  // write barriers can be skipped). Extend as needed.
  BuildFastLoop<IntPtrT>(
      IntPtrConstant(0), length_in_tagged,
      [=, this](TNode<IntPtrT> index) {
        TNode<IntPtrT> current_src_offset =
            IntPtrAdd(TimesTaggedSize(index), IntPtrConstant(src_offset));
        TNode<Object> value = LoadObjectField(src_object, current_src_offset);
        TNode<IntPtrT> current_dst_offset =
            IntPtrAdd(TimesTaggedSize(index), IntPtrConstant(dst_offset));
        if (mode == SKIP_WRITE_BARRIER) {
          StoreObjectFieldNoWriteBarrier(dst_object, current_dst_offset, value);
        } else {
          StoreObjectField(dst_object, current_dst_offset, value);
        }
      },
      1, LoopUnrollingMode::kYes, IndexAdvanceMode::kPost);
}

template <typename TIndex>
void CodeStubAssembler::CopyFixedArrayElements(
    ElementsKind from_kind, TNode<FixedArrayBase> from_array,
    ElementsKind to_kind, TNode<FixedArrayBase> to_array,
    TNode<TIndex> first_element, TNode<TIndex> element_count,
    TNode<TIndex> capacity, WriteBarrierMode barrier_mode,
    HoleConversionMode convert_holes, TVariable<BoolT>* var_holes_converted) {
  DCHECK_IMPLIES(var_holes_converted != nullptr,
                 convert_holes == HoleConversionMode::kConvertToUndefined);
  CSA_SLOW_DCHECK(this, IsFixedArrayWithKindOrEmpty(from_array, from_kind));
  CSA_SLOW_DCHECK(this, IsFixedArrayWithKindOrEmpty(to_array, to_kind));
  static_assert(OFFSET_OF_DATA_START(FixedArray) ==
                OFFSET_OF_DATA_START(FixedDoubleArray));
  static_assert(
      std::is_same<TIndex, Smi>::value || std::is_same<TIndex, IntPtrT>::value,
      "Only Smi or IntPtrT indices are allowed");

  const int first_element_offset =
      OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag;
  Comment("[ CopyFixedArrayElements");

  // Typed array elements are not supported.
  DCHECK(!IsTypedArrayElementsKind(from_kind));
  DCHECK(!IsTypedArrayElementsKind(to_kind));

  Label done(this);
  bool from_double_elements = IsDoubleElementsKind(from_kind);
  bool to_double_elements = IsDoubleElementsKind(to_kind);
  bool doubles_to_objects_conversion =
      IsDoubleElementsKind(from_kind) && IsObjectElementsKind(to_kind);
  bool needs_write_barrier =
      doubles_to_objects_conversion ||
      (barrier_mode == UPDATE_WRITE_BARRIER && IsObjectElementsKind(to_kind));
  bool element_offset_matches =
      !needs_write_barrier &&
      (kTaggedSize == kDoubleSize ||
       IsDoubleElementsKind(from_kind) == IsDoubleElementsKind(to_kind));
  TNode<UintPtrT> double_hole =
      Is64() ? ReinterpretCast<UintPtrT>(Int64Constant(kHoleNanInt64))
             : ReinterpretCast<UintPtrT>(Int32Constant(kHoleNanLower32));

  // If copying might trigger a GC, we pre-initialize the FixedArray such that
  // it's always in a consistent state.
  if (convert_holes == HoleConversionMode::kConvertToUndefined) {
    DCHECK(IsObjectElementsKind(to_kind));
    // Use undefined for the part that we copy and holes for the rest.
    // Later if we run into a hole in the source we can just skip the writing
    // to the target and are still guaranteed that we get an undefined.
    FillFixedArrayWithValue(to_kind, to_array, IntPtrOrSmiConstant<TIndex>(0),
                            element_count, RootIndex::kUndefinedValue);
    FillFixedArrayWithValue(to_kind, to_array, element_count, capacity,
                            RootIndex::kTheHoleValue);
  } else if (doubles_to_objects_conversion) {
    // Pre-initialized the target with holes so later if we run into a hole in
    // the source we can just skip the writing to the target.
    FillFixedArrayWithValue(to_kind, to_array, IntPtrOrSmiConstant<TIndex>(0),
                            capacity, RootIndex::kTheHoleValue);
  } else if (element_count != capacity) {
    FillFixedArrayWithValue(to_kind, to_array, element_count, capacity,
                            RootIndex::kTheHoleValue);
  }

  TNode<IntPtrT> first_from_element_offset =
      ElementOffsetFromIndex(first_element, from_kind, 0);
  TNode<IntPtrT> limit_offset = Signed(IntPtrAdd(
      first_from_element_offset, IntPtrConstant(first_element_offset)));
  TVARIABLE(IntPtrT, var_from_offset,
            ElementOffsetFromIndex(IntPtrOrSmiAdd(first_element, element_count),
                                   from_kind, first_element_offset));
  // This second variable is used only when the element sizes of source and
  // destination arrays do not match.
  TVARIABLE(IntPtrT, var_to_offset);
  if (element_offset_matches) {
    var_to_offset = var_from_offset.value();
  } else {
    var_to_offset =
        ElementOffsetFromIndex(element_count, to_kind, first_element_offset);
  }

  VariableList vars({&var_from_offset, &var_to_offset}, zone());
  if (var_holes_converted != nullptr) vars.push_back(var_holes_converted);
  Label decrement(this, vars);

  TNode<IntPtrT> to_array_adjusted =
      element_offset_matches
          ? IntPtrSub(BitcastTaggedToWord(to_array), first_from_element_offset)
          : ReinterpretCast<IntPtrT>(to_array);

  Branch(WordEqual(var_from_offset.value(), limit_offset), &done, &decrement);

  BIND(&decrement);
  {
    TNode<IntPtrT> from_offset = Signed(IntPtrSub(
        var_from_offset.value(),
        IntPtrConstant(from_double_elements ? kDoubleSize : kTaggedSize)));
    var_from_offset = from_offset;

    TNode<IntPtrT> to_offset;
    if (element_offset_matches) {
      to_offset = from_offset;
    } else {
      to_offset = IntPtrSub(
          var_to_offset.value(),
          IntPtrConstant(to_double_elements ? kDoubleSize : kTaggedSize));
      var_to_offset = to_offset;
    }

    Label next_iter(this), store_double_hole(this), signal_hole(this);
    Label* if_hole;
    if (convert_holes == HoleConversionMode::kConvertToUndefined) {
      // The target elements array is already preinitialized with undefined
      // so we only need to signal that a hole was found and continue the loop.
      if_hole = &signal_hole;
    } else if (doubles_to_objects_conversion) {
      // The target elements array is already preinitialized with holes, so we
      // can just proceed with the next iteration.
      if_hole = &next_iter;
    } else if (IsDoubleElementsKind(to_kind)) {
      if_hole = &store_double_hole;
    } else {
      // In all the other cases don't check for holes and copy the data as is.
      if_hole = nullptr;
    }

    if (to_double_elements) {
      DCHECK(!needs_write_barrier);
      TNode<Float64T> value = LoadElementAndPrepareForStore<Float64T>(
          from_array, var_from_offset.value(), from_kind, to_kind, if_hole);
      StoreNoWriteBarrier(MachineRepresentation::kFloat64, to_array_adjusted,
                          to_offset, value);
    } else {
      TNode<Object> value = LoadElementAndPrepareForStore<Object>(
          from_array, var_from_offset.value(), from_kind, to_kind, if_hole);
      if (needs_write_barrier) {
        CHECK_EQ(to_array, to_array_adjusted);
        Store(to_array_adjusted, to_offset, value);
      } else {
        UnsafeStoreNoWriteBarrier(MachineRepresentation::kTagged,
                                  to_array_adjusted, to_offset, value);
      }
    }

    Goto(&next_iter);

    if (if_hole == &store_double_hole) {
      BIND(&store_double_hole);
      // Don't use doubles to store the hole double, since manipulating the
      // signaling NaN used for the hole in C++, e.g. with base::bit_cast,
      // will change its value on ia32 (the x87 stack is used to return values
      // and stores to the stack silently clear the signalling bit).
      //
      // TODO(danno): When we have a Float32/Float64 wrapper class that
      // preserves double bits during manipulation, remove this code/change
      // this to an indexed Float64 store.
      if (Is64()) {
        StoreNoWriteBarrier(MachineRepresentation::kWord64, to_array_adjusted,
                            to_offset, double_hole);
      } else {
        StoreNoWriteBarrier(MachineRepresentation::kWord32, to_array_adjusted,
                            to_offset, double_hole);
        StoreNoWriteBarrier(MachineRepresentation::kWord32, to_array_adjusted,
                            IntPtrAdd(to_offset, IntPtrConstant(kInt32Size)),
                            double_hole);
      }
      Goto(&next_iter);
    } else if (if_hole == &signal_hole) {
      // This case happens only when IsObjectElementsKind(to_kind).
      BIND(&signal_hole);
      if (var_holes_converted != nullptr) {
        *var_holes_converted = Int32TrueConstant();
      }
      Goto(&next_iter);
    }

    BIND(&next_iter);
    TNode<BoolT> compare = WordNotEqual(from_offset, limit_offset);
    Branch(compare, &decrement, &done);
  }

  BIND(&done);
  Comment("] CopyFixedArrayElements");
}

TNode<FixedArray> CodeStubAssembler::HeapObjectToFixedArray(
    TNode<HeapObject> base, Label* cast_fail) {
  Label fixed_array(this);
  TNode<Map> map = LoadMap(base);
  GotoIf(TaggedEqual(map, FixedArrayMapConstant()), &fixed_array);
  GotoIf(TaggedNotEqual(map, FixedCOWArrayMapConstant()), cast_fail);
  Goto(&fixed_array);
  BIND(&fixed_array);
  return UncheckedCast<FixedArray>(base);
}

void CodeStubAssembler::CopyPropertyArrayValues(TNode<HeapObject> from_array,
                                                TNode<PropertyArray> to_array,
                                                TNode<IntPtrT> property_count,
                                                WriteBarrierMode barrier_mode,
                                                DestroySource destroy_source) {
  CSA_SLOW_DCHECK(this, Word32Or(IsPropertyArray(from_array),
                                 IsEmptyFixedArray(from_array)));
  Comment("[ CopyPropertyArrayValues");

  bool needs_write_barrier = barrier_mode == UPDATE_WRITE_BARRIER;

  if (destroy_source == DestroySource::kNo) {
    // PropertyArray may contain mutable HeapNumbers, which will be cloned on
    // the heap, requiring a write barrier.
    needs_write_barrier = true;
  }

  TNode<IntPtrT> start = IntPtrConstant(0);
  ElementsKind kind = PACKED_ELEMENTS;
  BuildFastArrayForEach(
      from_array, kind, start, property_count,
      [this, to_array, needs_write_barrier, destroy_source](
          TNode<HeapObject> array, TNode<IntPtrT> offset) {
        TNode<AnyTaggedT> value = Load<AnyTaggedT>(array, offset);

        if (destroy_source == DestroySource::kNo) {
          value = CloneIfMutablePrimitive(CAST(value));
        }

        if (needs_write_barrier) {
          Store(to_array, offset, value);
        } else {
          StoreNoWriteBarrier(MachineRepresentation::kTagged, to_array, offset,
                              value);
        }
      },
      LoopUnrollingMode::kYes);

#ifdef DEBUG
  // Zap {from_array} if the copying above has made it invalid.
  if (destroy_source == DestroySource::kYes) {
    Label did_zap(this);
    GotoIf(IsEmptyFixedArray(from_array), &did_zap);
    FillPropertyArrayWithUndefined(CAST(from_array), start, property_count);

    Goto(&did_zap);
    BIND(&did_zap);
  }
#endif
  Comment("] CopyPropertyArrayValues");
}

TNode<FixedArrayBase> CodeStubAssembler::CloneFixedArray(
    TNode<FixedArrayBase> source, ExtractFixedArrayFlags flags) {
  return ExtractFixedArray(
      source, std::optional<TNode<BInt>>(IntPtrOrSmiConstant<BInt>(0)),
      std::optional<TNode<BInt>>(std::nullopt),
      std::optional<TNode<BInt>>(std::nullopt), flags);
}

template <>
TNode<Object> CodeStubAssembler::LoadElementAndPrepareForStore(
    TNode<FixedArrayBase> array, TNode<IntPtrT> offset, ElementsKind from_kind,
    ElementsKind to_kind, Label* if_hole) {
  CSA_DCHECK(this, IsFixedArrayWithKind(array, from_kind));
  DCHECK(!IsDoubleElementsKind(to_kind));
  if (IsDoubleElementsKind(from_kind)) {
    TNode<Float64T> value =
        LoadDoubleWithHoleCheck(array, offset, if_hole, MachineType::Float64());
    return AllocateHeapNumberWithValue(value);
  } else {
    TNode<Object> value = Load<Object>(array, offset);
    if (if_hole) {
      GotoIf(TaggedEqual(value, TheHoleConstant()), if_hole);
    }
    return value;
  }
}

template <>
TNode<Float64T> CodeStubAssembler::LoadElementAndPrepareForStore(
    TNode<FixedArrayBase> array, TNode<IntPtrT> offset, ElementsKind from_kind,
    ElementsKind to_kind, Label* if_hole) {
  CSA_DCHECK(this, IsFixedArrayWithKind(array, from_kind));
  DCHECK(IsDoubleElementsKind(to_kind));
  if (IsDoubleElementsKind(from_kind)) {
    return LoadDoubleWithHoleCheck(array, offset, if_hole,
                                   MachineType::Float64());
  } else {
    TNode<Object> value = Load<Object>(array, offset);
    if (if_hole) {
      GotoIf(TaggedEqual(value, TheHoleConstant()), if_hole);
    }
    if (IsSmiElementsKind(from_kind)) {
      return SmiToFloat64(CAST(value));
    }
    return LoadHeapNumberValue(CAST(value));
  }
}

template <typename TIndex>
TNode<TIndex> CodeStubAssembler::CalculateNewElementsCapacity(
    TNode<TIndex> old_capacity) {
  static_assert(
      std::is_same<TIndex, Smi>::value || std::is_same<TIndex, IntPtrT>::value,
      "Only Smi or IntPtrT old_capacity is allowed");
  Comment("TryGrowElementsCapacity");
  TNode<TIndex> half_old_capacity = WordOrSmiShr(old_capacity, 1);
  TNode<TIndex> new_capacity = IntPtrOrSmiAdd(half_old_capacity, old_capacity);
  TNode<TIndex> padding =
      IntPtrOrSmiConstant<TIndex>(JSObject::kMinAddedElementsCapacity);
  return IntPtrOrSmiAdd(new_capacity, padding);
}

template V8_EXPORT_PRIVATE TNode<IntPtrT>
    CodeStubAssembler::CalculateNewElementsCapacity<IntPtrT>(TNode<IntPtrT>);
template V8_EXPORT_PRIVATE TNode<Smi>
    CodeStubAssembler::CalculateNewElementsCapacity<Smi>(TNode<Smi>);

TNode<FixedArrayBase> CodeStubAssembler::TryGrowElementsCapacity(
    TNode<HeapObject> object, TNode<FixedArrayBase> elements, ElementsKind kind,
    TNode<Smi> key, Label* bailout) {
  CSA_SLOW_DCHECK(this, IsFixedArrayWithKindOrEmpty(elements, kind));
  TNode<Smi> capacity = LoadFixedArrayBaseLength(elements);

  return TryGrowElementsCapacity(object, elements, kind,
                                 TaggedToParameter<BInt>(key),
                                 TaggedToParameter<BInt>(capacity), bailout);
}

template <typename TIndex>
TNode<FixedArrayBase> CodeStubAssembler::TryGrowElementsCapacity(
    TNode<HeapObject> object, TNode<FixedArrayBase> elements, ElementsKind kind,
    TNode<TIndex> key, TNode<TIndex> capacity, Label* bailout) {
  static_assert(
      std::is_same<TIndex, Smi>::value || std::is_same<TIndex, IntPtrT>::value,
      "Only Smi or IntPtrT key and capacity nodes are allowed");
  Comment("TryGrowElementsCapacity");
  CSA_SLOW_DCHECK(this, IsFixedArrayWithKindOrEmpty(elements, kind));

  // If the gap growth is too big, fall back to the runtime.
  TNode<TIndex> max_gap = IntPtrOrSmiConstant<TIndex>(JSObject::kMaxGap);
  TNode<TIndex> max_capacity = IntPtrOrSmiAdd(capacity, max_gap);
  GotoIf(UintPtrOrSmiGreaterThanOrEqual(key, max_capacity), bailout);

  // Calculate the capacity of the new backing store.
  TNode<TIndex> new_capacity = CalculateNewElementsCapacity(
      IntPtrOrSmiAdd(key, IntPtrOrSmiConstant<TIndex>(1)));

  return GrowElementsCapacity(object, elements, kind, kind, capacity,
                              new_capacity, bailout);
}

template <typename TIndex>
TNode<FixedArrayBase> CodeStubAssembler::GrowElementsCapacity(
    TNode<HeapObject> object, TNode<FixedArrayBase> elements,
    ElementsKind from_kind, ElementsKind to_kind, TNode<TIndex> capacity,
    TNode<TIndex> new_capacity, Label* bailout) {
  static_assert(
      std::is_same<TIndex, Smi>::value || std::is_same<TIndex, IntPtrT>::value,
      "Only Smi or IntPtrT capacities are allowed");
  Comment("[ GrowElementsCapacity");
  CSA_SLOW_DCHECK(this, IsFixedArrayWithKindOrEmpty(elements, from_kind));

  // If size of the allocation for the new capacity doesn't fit in a page
  // that we can bump-pointer allocate from, fall back to the runtime.
  int max_size = FixedArrayBase::GetMaxLengthForNewSpaceAllocation(to_kind);
  GotoIf(UintPtrOrSmiGreaterThanOrEqual(new_capacity,
                                        IntPtrOrSmiConstant<TIndex>(max_size)),
         bailout);

  // Allocate the new backing store.
  TNode<FixedArrayBase> new_elements =
      AllocateFixedArray(to_kind, new_capacity);

  // Copy the elements from the old elements store to the new.
  // The size-check above guarantees that the |new_elements| is allocated
  // in new space so we can skip the write barrier.
  CopyFixedArrayElements(from_kind, elements, to_kind, new_elements, capacity,
                         new_capacity, SKIP_WRITE_BARRIER);

  StoreObjectField(object, JSObject::kElementsOffset, new_elements);
  Comment("] GrowElementsCapacity");
  return new_elements;
}

template TNode<FixedArrayBase> CodeStubAssembler::GrowElementsCapacity<IntPtrT>(
    TNode<HeapObject>, TNode<FixedArrayBase>, ElementsKind, ElementsKind,
    TNode<IntPtrT>, TNode<IntPtrT>, compiler::CodeAssemblerLabel*);

namespace {

// Helper function for folded memento allocation.
// Memento objects are designed to be put right after the objects they are
// tracking on. So memento allocations have to be folded together with previous
// object allocations.
TNode<HeapObject> InnerAllocateMemento(CodeStubAssembler* csa,
                                       TNode<HeapObject> previous,
                                       TNode<IntPtrT> offset) {
  return csa->UncheckedCast<HeapObject>(csa->BitcastWordToTagged(
      csa->IntPtrAdd(csa->BitcastTaggedToWord(previous), offset)));
}

}  // namespace

void CodeStubAssembler::InitializeAllocationMemento(
    TNode<HeapObject> base, TNode<IntPtrT> base_allocation_size,
    TNode<AllocationSite> allocation_site) {
  DCHECK(V8_ALLOCATION_SITE_TRACKING_BOOL);
  Comment("[Initialize AllocationMemento");
  TNode<HeapObject> memento =
      InnerAllocateMemento(this, base, base_allocation_size);
  StoreMapNoWriteBarrier(memento, RootIndex::kAllocationMementoMap);
  StoreObjectFieldNoWriteBarrier(
      memento, AllocationMemento::kAllocationSiteOffset, allocation_site);
  if (v8_flags.allocation_site_pretenuring) {
    TNode<Int32T> count = LoadObjectField<Int32T>(
        allocation_site, AllocationSite::kPretenureCreateCountOffset);

    TNode<Int32T> incremented_count = Int32Add(count, Int32Constant(1));
    StoreObjectFieldNoWriteBarrier(allocation_site,
                                   AllocationSite::kPretenureCreateCountOffset,
                                   incremented_count);
  }
  Comment("]");
}

TNode<IntPtrT> CodeStubAssembler::TryTaggedToInt32AsIntPtr(
    TNode<Object> acc, Label* if_not_possible) {
  TVARIABLE(IntPtrT, acc_intptr);
  Label is_not_smi(this), have_int32(this);

  GotoIfNot(TaggedIsSmi(acc), &is_not_smi);
  acc_intptr = SmiUntag(CAST(acc));
  Goto(&have_int32);

  BIND(&is_not_smi);
  GotoIfNot(IsHeapNumber(CAST(acc)), if_not_possible);
  TNode<Float64T> value = LoadHeapNumberValue(CAST(acc));
  TNode<Int32T> value32 = RoundFloat64ToInt32(value);
  TNode<Float64T> value64 = ChangeInt32ToFloat64(value32);
  GotoIfNot(Float64Equal(value, value64), if_not_possible);
  acc_intptr = ChangeInt32ToIntPtr(value32);
  Goto(&have_int32);

  BIND(&have_int32);
  return acc_intptr.value();
}

TNode<Float64T> CodeStubAssembler::TryTaggedToFloat64(
    TNode<Object> value, Label* if_valueisnotnumber) {
  return Select<Float64T>(
      TaggedIsSmi(value), [&]() { return SmiToFloat64(CAST(value)); },
      [&]() {
        GotoIfNot(IsHeapNumber(CAST(value)), if_valueisnotnumber);
        return LoadHeapNumberValue(CAST(value));
      });
}

TNode<Float64T> CodeStubAssembler::TruncateTaggedToFloat64(
    TNode<Context> context, TNode<Object> value) {
  // We might need to loop once due to ToNumber conversion.
  TVARIABLE(Object, var_value, value);
  TVARIABLE(Float64T, var_result);
  Label loop(this, &var_value), done_loop(this, &var_result);
  Goto(&loop);
  BIND(&loop);
  {
    Label if_valueisnotnumber(this, Label::kDeferred);

    // Load the current {value}.
    value = var_value.value();

    // Convert {value} to Float64 if it is a number and convert it to a number
    // otherwise.
    var_result = TryTaggedToFloat64(value, &if_valueisnotnumber);
    Goto(&done_loop);

    BIND(&if_valueisnotnumber);
    {
      // Convert the {value} to a Number first.
      var_value = CallBuiltin(Builtin::kNonNumberToNumber, context, value);
      Goto(&loop);
    }
  }
  BIND(&done_loop);
  return var_result.value();
}

TNode<Word32T> CodeStubAssembler::TruncateTaggedToWord32(TNode<Context> context,
                                                         TNode<Object> value) {
  TVARIABLE(Word32T, var_result);
  Label done(this);
  TaggedToWord32OrBigIntImpl<Object::Conversion::kToNumber>(
      context, value, &done, &var_result, IsKnownTaggedPointer::kNo, {});
  BIND(&done);
  return var_result.value();
}

// Truncate {value} to word32 and jump to {if_number} if it is a Number,
// or find that it is a BigInt and jump to {if_bigint}.
void CodeStubAssembler::TaggedToWord32OrBigInt(
    TNode<Context> context, TNode<Object> value, Label* if_number,
    TVariable<Word32T>* var_word32, Label* if_bigint, Label* if_bigint64,
    TVariable<BigInt>* var_maybe_bigint) {
  TaggedToWord32OrBigIntImpl<Object::Conversion::kToNumeric>(
      context, value, if_number, var_word32, IsKnownTaggedPointer::kNo, {},
      if_bigint, if_bigint64, var_maybe_bigint);
}

// Truncate {value} to word32 and jump to {if_number} if it is a Number,
// or find that it is a BigInt and jump to {if_bigint}. In either case,
// store the type feedback in {var_feedback}.
void CodeStubAssembler::TaggedToWord32OrBigIntWithFeedback(
    TNode<Context> context, TNode<Object> value, Label* if_number,
    TVariable<Word32T>* var_word32, Label* if_bigint, Label* if_bigint64,
    TVariable<BigInt>* var_maybe_bigint, const FeedbackValues& feedback) {
  TaggedToWord32OrBigIntImpl<Object::Conversion::kToNumeric>(
      context, value, if_number, var_word32, IsKnownTaggedPointer::kNo,
      feedback, if_bigint, if_bigint64, var_maybe_bigint);
}

// Truncate {pointer} to word32 and jump to {if_number} if it is a Number,
// or find that it is a BigInt and jump to {if_bigint}. In either case,
// store the type feedback in {var_feedback}.
void CodeStubAssembler::TaggedPointerToWord32OrBigIntWithFeedback(
    TNode<Context> context, TNode<HeapObject> pointer, Label* if_number,
    TVariable<Word32T>* var_word32, Label* if_bigint, Label* if_bigint64,
    TVariable<BigInt>* var_maybe_bigint, const FeedbackValues& feedback) {
  TaggedToWord32OrBigIntImpl<Object::Conversion::kToNumeric>(
      context, pointer, if_number, var_word32, IsKnownTaggedPointer::kYes,
      feedback, if_bigint, if_bigint64, var_maybe_bigint);
}

template <Object::Conversion conversion>
void CodeStubAssembler::TaggedToWord32OrBigIntImpl(
    TNode<Context> context, TNode<Object> value, Label* if_number,
    TVariable<Word32T>* var_word32,
    IsKnownTaggedPointer is_known_tagged_pointer,
    const FeedbackValues& feedback, Label* if_bigint, Label* if_bigint64,
    TVariable<BigInt>* var_maybe_bigint) {
  // We might need to loop after conversion.
  TVARIABLE(Object, var_value, value);
  TVARIABLE(Object, var_exception);
  OverwriteFeedback(feedback.var_feedback, BinaryOperationFeedback::kNone);
  VariableList loop_vars({&var_value}, zone());
  if (feedback.var_feedback != nullptr) {
    loop_vars.push_back(feedback.var_feedback);
  }
  Label loop(this, loop_vars);
  Label if_exception(this, Label::kDeferred);
  if (is_known_tagged_pointer == IsKnownTaggedPointer::kNo) {
    GotoIf(TaggedIsNotSmi(value), &loop);

    // {value} is a Smi.
    *var_word32 = SmiToInt32(CAST(value));
    CombineFeedback(feedback.var_feedback,
                    BinaryOperationFeedback::kSignedSmall);
    Goto(if_number);
  } else {
    Goto(&loop);
  }
  BIND(&loop);
  {
    value = var_value.value();
    Label not_smi(this), is_heap_number(this), is_oddball(this),
        maybe_bigint64(this), is_bigint(this), check_if_smi(this);

    TNode<HeapObject> value_heap_object = CAST(value);
    TNode<Map> map = LoadMap(value_heap_object);
    GotoIf(IsHeapNumberMap(map), &is_heap_number);
    TNode<Uint16T> instance_type = LoadMapInstanceType(map);
    if (conversion == Object::Conversion::kToNumeric) {
      if (Is64() && if_bigint64) {
        GotoIf(IsBigIntInstanceType(instance_type), &maybe_bigint64);
      } else {
        GotoIf(IsBigIntInstanceType(instance_type), &is_bigint);
      }
    }

    // Not HeapNumber (or BigInt if conversion == kToNumeric).
    {
      if (feedback.var_feedback != nullptr) {
        // We do not require an Or with earlier feedback here because once we
        // convert the value to a Numeric, we cannot reach this path. We can
        // only reach this path on the first pass when the feedback is kNone.
        CSA_DCHECK(this, SmiEqual(feedback.var_feedback->value(),
                                  SmiConstant(BinaryOperationFeedback::kNone)));
      }
      GotoIf(InstanceTypeEqual(instance_type, ODDBALL_TYPE), &is_oddball);
      // Not an oddball either -> convert.
      auto builtin = conversion == Object::Conversion::kToNumeric
                         ? Builtin::kNonNumberToNumeric
                         : Builtin::kNonNumberToNumber;
      if (feedback.var_feedback != nullptr) {
        ScopedExceptionHandler handler(this, &if_exception, &var_exception);
        var_value = CallBuiltin(builtin, context, value);
      } else {
        var_value = CallBuiltin(builtin, context, value);
      }
      OverwriteFeedback(feedback.var_feedback, BinaryOperationFeedback::kAny);
      Goto(&check_if_smi);

      if (feedback.var_feedback != nullptr) {
        BIND(&if_exception);
        DCHECK(feedback.slot != nullptr);
        DCHECK(feedback.maybe_feedback_vector != nullptr);
        UpdateFeedback(SmiConstant(BinaryOperationFeedback::kAny),
                       (*feedback.maybe_feedback_vector)(), *feedback.slot,
                       feedback.update_mode);
        CallRuntime(Runtime::kReThrow, context, var_exception.value());
        Unreachable();
      }

      BIND(&is_oddball);
      var_value =
          LoadObjectField(value_heap_object, offsetof(Oddball, to_number_));
      OverwriteFeedback(feedback.var_feedback,
                        BinaryOperationFeedback::kNumberOrOddball);
      Goto(&check_if_smi);
    }

    BIND(&is_heap_number);
    *var_word32 = TruncateHeapNumberValueToWord32(CAST(value));
    CombineFeedback(feedback.var_feedback, BinaryOperationFeedback::kNumber);
    Goto(if_number);

    if (conversion == Object::Conversion::kToNumeric) {
      if (Is64() && if_bigint64) {
        BIND(&maybe_bigint64);
        GotoIfLargeBigInt(CAST(value), &is_bigint);
        if (var_maybe_bigint) {
          *var_maybe_bigint = CAST(value);
        }
        CombineFeedback(feedback.var_feedback,
                        BinaryOperationFeedback::kBigInt64);
        Goto(if_bigint64);
      }

      BIND(&is_bigint);
      if (var_maybe_bigint) {
        *var_maybe_bigint = CAST(value);
      }
      CombineFeedback(feedback.var_feedback, BinaryOperationFeedback::kBigInt);
      Goto(if_bigint);
    }

    BIND(&check_if_smi);
    value = var_value.value();
    GotoIf(TaggedIsNotSmi(value), &loop);

    // {value} is a Smi.
    *var_word32 = SmiToInt32(CAST(value));
    CombineFeedback(feedback.var_feedback,
                    BinaryOperationFeedback::kSignedSmall);
    Goto(if_number);
  }
}

TNode<Int32T> CodeStubAssembler::TruncateNumberToWord32(TNode<Number> number) {
  TVARIABLE(Int32T, var_result);
  Label done(this), if_heapnumber(this);
  GotoIfNot(TaggedIsSmi(number), &if_heapnumber);
  var_result = SmiToInt32(CAST(number));
  Goto(&done);

  BIND(&if_heapnumber);
  TNode<Float64T> value = LoadHeapNumberValue(CAST(number));
  var_result = Signed(TruncateFloat64ToWord32(value));
  Goto(&done);

  BIND(&done);
  return var_result.value();
}

TNode<Int32T> CodeStubAssembler::TruncateHeapNumberValueToWord32(
    TNode<HeapNumber> object) {
  TNode<Float64T> value = LoadHeapNumberValue(object);
  return Signed(TruncateFloat64ToWord32(value));
}

TNode<Smi> CodeStubAssembler::TryHeapNumberToSmi(TNode<HeapNumber> number,
                                                 Label* not_smi) {
  TNode<Float64T> value = LoadHeapNumberValue(number);
  return TryFloat64ToSmi(value, not_smi);
}

TNode<Smi> CodeStubAssembler::TryFloat32ToSmi(TNode<Float32T> value,
                                              Label* not_smi) {
  TNode<Int32T> ivalue = TruncateFloat32ToInt32(value);
  TNode<Float32T> fvalue = RoundInt32ToFloat32(ivalue);

  Label if_int32(this);

  GotoIfNot(Float32Equal(value, fvalue), not_smi);
  GotoIfNot(Word32Equal(ivalue, Int32Constant(0)), &if_int32);
  // if (value == -0.0)
  Branch(Int32LessThan(UncheckedCast<Int32T>(BitcastFloat32ToInt32(value)),
                       Int32Constant(0)),
         not_smi, &if_int32);

  BIND(&if_int32);
  if (SmiValuesAre32Bits()) {
    return SmiTag(ChangeInt32ToIntPtr(ivalue));
  } else {
    DCHECK(SmiValuesAre31Bits());
    TNode<PairT<Int32T, BoolT>> pair = Int32AddWithOverflow(ivalue, ivalue);
    TNode<BoolT> overflow = Projection<1>(pair);
    GotoIf(overflow, not_smi);
    return BitcastWordToTaggedSigned(ChangeInt32ToIntPtr(Projection<0>(pair)));
  }
}

TNode<Smi> CodeStubAssembler::TryFloat64ToSmi(TNode<Float64T> value,
                                              Label* not_smi) {
  TNode<Int32T> value32 = RoundFloat64ToInt32(value);
  TNode<Float64T> value64 = ChangeInt32ToFloat64(value32);

  Label if_int32(this);
  GotoIfNot(Float64Equal(value, value64), not_smi);
  GotoIfNot(Word32Equal(value32, Int32Constant(0)), &if_int32);
  Branch(Int32LessThan(UncheckedCast<Int32T>(Float64ExtractHighWord32(value)),
                       Int32Constant(0)),
         not_smi, &if_int32);

  TVARIABLE(Number, var_result);
  BIND(&if_int32);
  if (SmiValuesAre32Bits()) {
    return SmiTag(ChangeInt32ToIntPtr(value32));
  } else {
    DCHECK(SmiValuesAre31Bits());
    TNode<PairT<Int32T, BoolT>> pair = Int32AddWithOverflow(value32, value32);
    TNode<BoolT> overflow = Projection<1>(pair);
    GotoIf(overflow, not_smi);
    return BitcastWordToTaggedSigned(ChangeInt32ToIntPtr(Projection<0>(pair)));
  }
}

TNode<Float16RawBitsT> CodeStubAssembler::TruncateFloat64ToFloat16(
    TNode<Float64T> value) {
  TVARIABLE(Float16RawBitsT, float16_out);
  Label truncate_op_supported(this), truncate_op_fallback(this),
      return_out(this);
  // See Float64Ceil for the reason there is a branch for the static constant
  // (PGO profiles).
  Branch(UniqueInt32Constant(IsT
```