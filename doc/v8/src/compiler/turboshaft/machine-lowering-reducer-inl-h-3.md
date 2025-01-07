Response:
The user wants a summary of the C++ code provided, specifically the `machine-lowering-reducer-inl.h` file from the V8 JavaScript engine.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The name "machine-lowering-reducer" suggests this code is responsible for transforming high-level operations into lower-level machine instructions. The "reducer" part likely indicates it simplifies or canonicalizes these operations.

2. **Analyze individual functions (the `REDUCE` methods):** Each `REDUCE` function seems to correspond to a specific high-level operation. I need to understand what each of these operations does.

3. **Look for common themes:** Are there patterns in how these reductions are implemented?  Do they involve calls to built-in functions, memory access, or conditional logic based on object types?

4. **Address specific requests:**
    * **Functionality:** List the actions performed by the code.
    * **`.tq` extension:** Determine if this file could be a Torque file based on the naming convention.
    * **JavaScript relationship:** Find connections to JavaScript concepts and provide examples.
    * **Code logic reasoning:** If there are conditional branches, provide example inputs and expected outputs.
    * **Common programming errors:** Identify potential pitfalls that developers might encounter related to the functionality.
    * **Overall summary:** Condense the functionality into a concise description.

**Detailed analysis of each `REDUCE` function:**

* **`CreateArgumentsElements`:** Handles the creation of `arguments` objects in JavaScript. Different types (mapped, unmapped, rest) are handled by calling specific built-in functions.
* **`LoadTypedElement`:**  Loads elements from Typed Arrays. It calculates the memory address and performs the load. The `__ Retain(buffer)` part is important for garbage collection safety.
* **`LoadStackArgument`:** Loads arguments from the stack frame. Deals with platform-specific memory layouts and potential pointer compression.
* **`StoreTypedElement`:** Stores elements into Typed Arrays, similar to `LoadTypedElement` but for writing.
* **`TransitionAndStoreArrayElement`:**  A complex function for storing elements in JavaScript Arrays. It handles transitions between different array element kinds (SMI, double, object) to optimize storage. This involves checks for the type of the value being stored and potentially modifying the array's map.
* **`CompareMaps`:**  Compares the map of a `HeapObject` against a set of allowed maps. This is used for type checking.
* **`CheckMaps`:**  Similar to `CompareMaps`, but also includes logic for deoptimization if the map doesn't match and potential instance migration.
* **`FloatUnary`:** Implements unary operations on floating-point numbers (like `ceil`, `floor`, `round`). It handles different rounding modes and potential platform-specific optimizations.
* **`CheckedClosure`:** Checks if a given object is a valid JavaScript function and if its feedback cell matches the expected one. This is part of optimizing function calls.
* **`CheckEqualsInternalizedString`:**  Verifies if a value is equal to an expected internalized string. It handles cases where the value might be a non-internalized string with the same content.
* **`LoadMessage` and `StoreMessage`:**  Deal with loading and storing messages, likely for communication or error handling within the VM.
* **`SameValue` and `Float64SameValue`:** Implement the `SameValue` and `SameValueNumbersOnly` JavaScript comparisons, which have special handling for NaN and -0.
* **`RuntimeAbort`:**  Triggers a runtime abort with a specified reason.
* **`EnsureWritableFastElements`:** Ensures that the element backing store of an object is writable (not a copy-on-write array).
* **`MaybeGrowFastElements`:**  Checks if the element backing store needs to be grown and performs the growth if necessary.
* **`TransitionElementsKind`:**  Handles transitions between different kinds of array elements, potentially migrating the object or updating its map.
* **`FindOrderedHashEntry`:**  Searches for entries in ordered hash maps (like JavaScript `Map` objects).

**Synthesizing the summary:**

Based on the individual function analyses, I can now summarize the overall functionality. The code handles operations related to:

* Creating function arguments objects.
* Loading and storing elements in Typed Arrays and regular JavaScript Arrays (handling type transitions).
* Comparing object maps for type checking and deoptimization.
* Implementing floating-point unary operations with different rounding modes.
* Verifying function call targets and feedback cells.
* Comparing strings, including handling internalized strings.
* Managing object element backing stores (ensuring writability and growing if needed).
* Searching in hash maps.
* Performing `SameValue` comparisons.
* Triggering runtime errors.

Now, I can structure the answer according to the user's specific requests.
```cpp
  OpIndex REDUCE(CreateArgumentsElements)(V<Smi> arguments_count,
                                         CreateArgumentsType type,
                                         int formal_parameter_count) {
    V<WordPtr> frame = __ FramePointer();
    V<WordPtr> p_count = __ IntPtrConstant(formal_parameter_count);
    switch (type) {
      case CreateArgumentsType::kMappedArguments:
        return __ CallBuiltin_NewSloppyArgumentsElements(
            isolate_, frame, p_count, arguments_count);
      case CreateArgumentsType::kUnmappedArguments:
        return __ CallBuiltin_NewStrictArgumentsElements(
            isolate_, frame, p_count, arguments_count);
      case CreateArgumentsType::kRestParameter:
        return __ CallBuiltin_NewRestArgumentsElements(isolate_, frame, p_count,
                                                       arguments_count);
    }
  }

  OpIndex REDUCE(LoadTypedElement)(OpIndex buffer, V<Object> base,
                                   V<WordPtr> external, V<WordPtr> index,
                                   ExternalArrayType array_type) {
    V<WordPtr> data_ptr = BuildTypedArrayDataPointer(base, external);

    // Perform the actual typed element access.
    OpIndex result = __ LoadArrayBufferElement(
        data_ptr, AccessBuilder::ForTypedArrayElement(array_type, true), index);

    // We need to keep the {buffer} alive so that the GC will not release the
    // ArrayBuffer (if there's any) as long as we are still operating on it.
    __ Retain(buffer);
    return result;
  }

  V<Object> REDUCE(LoadStackArgument)(V<WordPtr> base, V<WordPtr> index) {
    // Note that this is a load of a Tagged value
    // (MemoryRepresentation::TaggedPointer()), but since it's on the stack
    // where stack slots are all kSystemPointerSize, we use kSystemPointerSize
    // for element_size_log2. On 64-bit plateforms with pointer compression,
    // this means that we're kinda loading a 32-bit value from an array of
    // 64-bit values.
#if V8_COMPRESS_POINTERS && V8_TARGET_BIG_ENDIAN
    constexpr int offset =
        CommonFrameConstants::kFixedFrameSizeAboveFp - kSystemPointerSize + 4;
#else
    constexpr int offset =
        CommonFrameConstants::kFixedFrameSizeAboveFp - kSystemPointerSize;
#endif
    return __ Load(base, index, LoadOp::Kind::RawAligned(),
                   MemoryRepresentation::TaggedPointer(), offset,
                   kSystemPointerSizeLog2);
  }

  OpIndex REDUCE(StoreTypedElement)(OpIndex buffer, V<Object> base,
                                    V<WordPtr> external, V<WordPtr> index,
                                    OpIndex value,
                                    ExternalArrayType array_type) {
    V<WordPtr> data_ptr = BuildTypedArrayDataPointer(base, external);

    // Perform the actual typed element access.
    __ StoreArrayBufferElement(
        data_ptr, AccessBuilder::ForTypedArrayElement(array_type, true), index,
        value);

    // We need to keep the {buffer} alive so that the GC will not release the
    // ArrayBuffer (if there's any) as long as we are still operating on it.
    __ Retain(buffer);
    return {};
  }

  OpIndex REDUCE(TransitionAndStoreArrayElement)(
      V<JSArray> array, V<WordPtr> index, OpIndex value,
      TransitionAndStoreArrayElementOp::Kind kind, MaybeHandle<Map> fast_map,
      MaybeHandle<Map> double_map) {
    V<Map> map = __ LoadMapField(array);
    V<Word32> bitfield2 =
        __ template LoadField<Word32>(map, AccessBuilder::ForMapBitField2());
    V<Word32> elements_kind = __ Word32ShiftRightLogical(
        __ Word32BitwiseAnd(bitfield2, Map::Bits2::ElementsKindBits::kMask),
        Map::Bits2::ElementsKindBits::kShift);

    switch (kind) {
      case TransitionAndStoreArrayElementOp::Kind::kElement: {
        // Possibly transition array based on input and store.
        //
        //   -- TRANSITION PHASE -----------------
        //   kind = ElementsKind(array)
        //   if value is not smi {
        //     if kind == HOLEY_SMI_ELEMENTS {
        //       if value is heap number {
        //         Transition array to HOLEY_DOUBLE_ELEMENTS
        //         kind = HOLEY_DOUBLE_ELEMENTS
        //       } else {
        //         Transition array to HOLEY_ELEMENTS
        //         kind = HOLEY_ELEMENTS
        //       }
        //     } else if kind == HOLEY_DOUBLE_ELEMENTS {
        //       if value is not heap number {
        //         Transition array to HOLEY_ELEMENTS
        //         kind = HOLEY_ELEMENTS
        //       }
        //     }
        //   }
        //
        //   -- STORE PHASE ----------------------
        //   [make sure {kind} is up-to-date]
        //   if kind == HOLEY_DOUBLE_ELEMENTS {
        //     if value is smi {
        //       float_value = convert smi to float
        //       Store array[index] = float_value
        //     } else {
        //       float_value = value
        //       Store array[index] = float_value
        //     }
        //   } else {
        //     // kind is HOLEY_SMI_ELEMENTS or HOLEY_ELEMENTS
        //     Store array[index] = value
        //   }
        //
        Label<Word32> do_store(this);
        // We can store a smi anywhere.
        GOTO_IF(__ ObjectIsSmi(value), do_store, elements_kind);

        // {value} is a HeapObject.
        IF_NOT (LIKELY(__ Int32LessThan(HOLEY_SMI_ELEMENTS, elements_kind))) {
          // Transition {array} from HOLEY_SMI_ELEMENTS to HOLEY_DOUBLE_ELEMENTS
          // or to HOLEY_ELEMENTS.
          V<Map> value_map = __ LoadMapField(value);
          IF (__ TaggedEqual(value_map,
                             __ HeapConstant(factory_->heap_number_map()))) {
            // {value} is a HeapNumber.
            TransitionElementsTo(array, HOLEY_SMI_ELEMENTS,
                                 HOLEY_DOUBLE_ELEMENTS,
                                 double_map.ToHandleChecked());
            GOTO(do_store, HOLEY_DOUBLE_ELEMENTS);
          } ELSE {
            TransitionElementsTo(array, HOLEY_SMI_ELEMENTS, HOLEY_ELEMENTS,
                                 fast_map.ToHandleChecked());
            GOTO(do_store, HOLEY_ELEMENTS);
          }
        }

        GOTO_IF_NOT(LIKELY(__ Int32LessThan(HOLEY_ELEMENTS, elements_kind)),
                    do_store, elements_kind);

        // We have double elements kind. Only a HeapNumber can be stored
        // without effecting a transition.
        V<Map> value_map = __ LoadMapField(value);
        IF_NOT (UNLIKELY(__ TaggedEqual(
                    value_map, __ HeapConstant(factory_->heap_number_map())))) {
          TransitionElementsTo(array, HOLEY_DOUBLE_ELEMENTS, HOLEY_ELEMENTS,
                               fast_map.ToHandleChecked());
          GOTO(do_store, HOLEY_ELEMENTS);
        }

        GOTO(do_store, elements_kind);

        BIND(do_store, store_kind);
        V<Object> elements = __ template LoadField<Object>(
            array, AccessBuilder::ForJSObjectElements());
        IF (__ Int32LessThan(HOLEY_ELEMENTS, store_kind)) {
          // Our ElementsKind is HOLEY_DOUBLE_ELEMENTS.
          IF (__ ObjectIsSmi(value)) {
            V<Float64> float_value =
                __ ChangeInt32ToFloat64(__ UntagSmi(value));
            __ StoreNonArrayBufferElement(
                elements, AccessBuilder::ForFixedDoubleArrayElement(), index,
                float_value);
          } ELSE {
            V<Float64> float_value =
                __ LoadHeapNumberValue(V<HeapNumber>::Cast(value));
            __ StoreNonArrayBufferElement(
                elements, AccessBuilder::ForFixedDoubleArrayElement(), index,
                __ Float64SilenceNaN(float_value));
          }
        } ELSE {
          // Our ElementsKind is HOLEY_SMI_ELEMENTS or HOLEY_ELEMENTS.
          __ StoreNonArrayBufferElement(
              elements, AccessBuilder::ForFixedArrayElement(HOLEY_ELEMENTS),
              index, value);
        }

        break;
      }
      case TransitionAndStoreArrayElementOp::Kind::kNumberElement: {
        Label<> done(this);
        // Possibly transition array based on input and store.
        //
        //   -- TRANSITION PHASE -----------------
        //   kind = ElementsKind(array)
        //   if kind == HOLEY_SMI_ELEMENTS {
        //     Transition array to HOLEY_DOUBLE_ELEMENTS
        //   } else if kind != HOLEY_DOUBLE_ELEMENTS {
        //     if kind == HOLEY_ELEMENTS {
        //       Store value as a HeapNumber in array[index].
        //     } else {
        //       This is UNREACHABLE, execute a debug break.
        //     }
        //   }
        //
        //   -- STORE PHASE ----------------------
        //   Store array[index] = value (it's a float)
        //
        // {value} is a float64.
        IF_NOT (LIKELY(__ Int32LessThan(HOLEY_SMI_ELEMENTS, elements_kind))) {
          // Transition {array} from HOLEY_SMI_ELEMENTS to
          // HOLEY_DOUBLE_ELEMENTS.
          TransitionElementsTo(array, HOLEY_SMI_ELEMENTS, HOLEY_DOUBLE_ELEMENTS,
                               double_map.ToHandleChecked());
        } ELSE {
          // We expect that our input array started at HOLEY_SMI_ELEMENTS, and
          // climbs the lattice up to HOLEY_DOUBLE_ELEMENTS. However, loop
          // peeling can break this assumption, because in the peeled iteration,
          // the array might have transitioned to HOLEY_ELEMENTS kind, so we
          // handle this as well.
          IF_NOT (LIKELY(
                      __ Word32Equal(elements_kind, HOLEY_DOUBLE_ELEMENTS))) {
            IF (__ Word32Equal(elements_kind, HOLEY_ELEMENTS)) {
              V<Object> elements = __ template LoadField<Object>(
                  array, AccessBuilder::ForJSObjectElements());
              // Our ElementsKind is HOLEY_ELEMENTS.
              __ StoreNonArrayBufferElement(
                  elements, AccessBuilder::ForFixedArrayElement(HOLEY_ELEMENTS),
                  index, AllocateHeapNumber(value));
              GOTO(done);
            }

            __ Unreachable();
          }
        }

        V<Object> elements = __ template LoadField<Object>(
            array, AccessBuilder::ForJSObjectElements());
        __ StoreNonArrayBufferElement(
            elements, AccessBuilder::ForFixedDoubleArrayElement(), index,
            __ Float64SilenceNaN(value));
        GOTO(done);

        BIND(done);
        break;
      }
      case TransitionAndStoreArrayElementOp::Kind::kOddballElement:
      case TransitionAndStoreArrayElementOp::Kind::kNonNumberElement: {
        // Possibly transition array based on input and store.
        //
        //   -- TRANSITION PHASE -----------------
        //   kind = ElementsKind(array)
        //   if kind == HOLEY_SMI_ELEMENTS {
        //     Transition array to HOLEY_ELEMENTS
        //   } else if kind == HOLEY_DOUBLE_ELEMENTS {
        //     Transition array to HOLEY_ELEMENTS
        //   }
        //
        //   -- STORE PHASE ----------------------
        //   // kind is HOLEY_ELEMENTS
        //   Store array[index] = value
        //
        IF_NOT (LIKELY(__ Int32LessThan(HOLEY_SMI_ELEMENTS, elements_kind))) {
          // Transition {array} from HOLEY_SMI_ELEMENTS to HOLEY_ELEMENTS.
          TransitionElementsTo(array, HOLEY_SMI_ELEMENTS, HOLEY_ELEMENTS,
                               fast_map.ToHandleChecked());
        } ELSE IF (UNLIKELY(__ Int32LessThan(HOLEY_ELEMENTS, elements_kind))) {
          TransitionElementsTo(array, HOLEY_DOUBLE_ELEMENTS, HOLEY_ELEMENTS,
                               fast_map.ToHandleChecked());
        }

        V<Object> elements = __ template LoadField<Object>(
            array, AccessBuilder::ForJSObjectElements());
        ElementAccess access =
            AccessBuilder::ForFixedArrayElement(HOLEY_ELEMENTS);
        if (kind == TransitionAndStoreArrayElementOp::Kind::kOddballElement) {
          access.type = compiler::Type::BooleanOrNullOrUndefined();
          access.write_barrier_kind = kNoWriteBarrier;
        }
        __ StoreNonArrayBufferElement(elements, access, index, value);
        break;
      }
      case TransitionAndStoreArrayElementOp::Kind::kSignedSmallElement: {
        // Store a signed small in an output array.
        //
        //   kind = ElementsKind(array)
        //
        //   -- STORE PHASE ----------------------
        //   if kind == HOLEY_DOUBLE_ELEMENTS {
        //     float_value = convert int32 to float
        //     Store array[index] = float_value
        //   } else {
        //     // kind is HOLEY_SMI_ELEMENTS or HOLEY_ELEMENTS
        //     smi_value = convert int32 to smi
        //     Store array[index] = smi_value
        //   }
        //
        V<Object> elements = __ template LoadField<Object>(
            array, AccessBuilder::ForJSObjectElements());
        IF (__ Int32LessThan(HOLEY_ELEMENTS, elements_kind)) {
          // Our ElementsKind is HOLEY_DOUBLE_ELEMENTS.
          V<Float64> f64 = __ ChangeInt32ToFloat64(value);
          __ StoreNonArrayBufferElement(
              elements, AccessBuilder::ForFixedDoubleArrayElement(), index,
              f64);
        } ELSE {
          // Our ElementsKind is HOLEY_SMI_ELEMENTS or HOLEY_ELEMENTS.
          // In this case, we know our value is a signed small, and we can
          // optimize the ElementAccess information.
          ElementAccess access = AccessBuilder::ForFixedArrayElement();
          access.type = compiler::Type::SignedSmall();
          access.machine_type = MachineType::TaggedSigned();
          access.write_barrier_kind = kNoWriteBarrier;
          __ StoreNonArrayBufferElement(elements, access, index,
                                        __ TagSmi(value));
        }

        break;
      }
    }

    return OpIndex::Invalid();
  }

  V<Word32> REDUCE(CompareMaps)(V<HeapObject> heap_object, OptionalV<Map> map,
                                const ZoneRefSet<Map>& maps) {
    if (!map.has_value()) {
      map = __ LoadMapField(heap_object);
    }
    return CompareMapAgainstMultipleMaps(map.value(), maps);
  }

  V<None> REDUCE(CheckMaps)(V<HeapObject> heap_object,
                            V<FrameState> frame_state, OptionalV<Map> map,
                            const ZoneRefSet<Map>& maps, CheckMapsFlags flags,
                            const FeedbackSource& feedback) {
    if (maps.is_empty()) {
      __ Deoptimize(frame_state, DeoptimizeReason::kWrongMap, feedback);
      return {};
    }

    V<Map> heap_object_map;
    if (map.has_value()) {
      heap_object_map = map.value();
    } else {
      heap_object_map = __ LoadMapField(heap_object);
    }

    if (flags & CheckMapsFlag::kTryMigrateInstance) {
      IF_NOT (LIKELY(CompareMapAgainstMultipleMaps(heap_object_map, maps))) {
        // Reloading the map slightly reduces register pressure, and we are on a
        // slow path here anyway.
        MigrateInstanceOrDeopt(heap_object, heap_object_map, frame_state,
                               feedback);
        heap_object_map = __ LoadMapField(heap_object);
        __ DeoptimizeIfNot(__ CompareMaps(heap_object, heap_object_map, maps),
                           frame_state, DeoptimizeReason::kWrongMap, feedback);
      }
    } else {
      __ DeoptimizeIfNot(__ CompareMaps(heap_object, heap_object_map, maps),
                         frame_state, DeoptimizeReason::kWrongMap, feedback);
    }
    // Inserting a AssumeMap so that subsequent optimizations know the map of
    // this object.
    __ AssumeMap(heap_object, maps);
    return {};
  }

  V<Float> REDUCE(FloatUnary)(V<Float> input, FloatUnaryOp::Kind kind,
                              FloatRepresentation rep) {
    LABEL_BLOCK(no_change) { return Next::ReduceFloatUnary(input, kind, rep); }
    switch (kind) {
      case FloatUnaryOp::Kind::kRoundUp:
      case FloatUnaryOp::Kind::kRoundDown:
      case FloatUnaryOp::Kind::kRoundTiesEven:
      case FloatUnaryOp::Kind::kRoundToZero: {
        // TODO(14108): Implement for Float32.
        if (rep == FloatRepresentation::Float32()) {
          goto no_change;
        }
        DCHECK_EQ(rep, FloatRepresentation::Float64());
        V<Float64> input_f64 = V<Float64>::Cast(input);
        if (FloatUnaryOp::IsSupported(kind, rep)) {
          // If we have a fast machine operation for this, we can just keep it.
          goto no_change;
        }
        // Otherwise we have to lower it.
        V<Float64> two_52 = __ Float64Constant(4503599627370496.0E0);
        V<Float64> minus_two_52 = __ Float64Constant(-4503599627370496.0E0);

        if (kind == FloatUnaryOp::Kind::kRoundUp) {
          // General case for ceil.
          //
          //   if 0.0 < input then
          //     if 2^52 <= input then
          //       input
          //     else
          //       let temp1 = (2^52 + input) - 2^52 in
          //       if temp1 < input then
          //         temp1 + 1
          //       else
          //         temp1
          //   else
          //     if input == 0 then
          //       input
          //     else
          //       if input <= -2^52 then
          //         input
          //       else
          //         let temp1 = -0 - input in
          //         let temp2 = (2^52 + temp1) - 2^52 in
          //         if temp1 < temp2 then -0 - (temp2 - 1) else -0 - temp2

          Label<Float64> done(this);

          IF (LIKELY(__ Float64LessThan(0.0, input_f64))) {
            GOTO_IF(UNLIKELY(__ Float64LessThanOrEqual(two_52, input_f64)),
                    done, input_f64);
            V<Float64> temp1 =
                __ Float64Sub(__ Float64Add(two_52, input_f64), two_52);
            GOTO_IF_NOT(__ Float64LessThan(temp1, input_f64), done, temp1);
            GOTO(done, __ Float64Add(temp1, 1.0));
          } ELSE IF (UNLIKELY(__ Float64Equal(input_f64, 0.0))) {
            GOTO(done, input_f64);
          } ELSE IF (UNLIKELY(
                        __ Float64LessThanOrEqual(input_f64, minus_two_52))) {
            GOTO(done, input_f64);
          } ELSE {
            V<Float64> temp1 = __ Float64Sub(-0.0, input_f64);
            V<Float64> temp2 =
                __ Float64Sub(__ Float64Add(two_52, temp1), two_52);
            GOTO_IF_NOT(__ Float64LessThan(temp1, temp2), done,
                        __ Float64Sub(-0.0, temp2));
            GOTO(done, __ Float64Sub(-0.0, __ Float64Sub(temp2, 1.0)));
          }

          BIND(done, result);
          return result;
        } else if (kind == FloatUnaryOp::Kind::kRoundDown) {
          // General case for floor.
          //
          //   if 0.0 < input then
          //     if 2^52 <= input then
          //       input
          //     else
          //       let temp1 = (2^52 + input) - 2^52 in
          //       if input < temp1 then
          //         temp1 - 1
          //       else
          //         temp1
          //   else
          //     if input == 0 then
          //       input
          //     else
          //       if input <= -2^52 then
          //         input
          //       else
          //         let temp1 = -0 - input in
          //         let temp2 = (2^52 + temp1) - 2^52 in
          //         if temp2 < temp1 then
          //           -1 - temp2
          //         else
          //           -0 - temp2

          Label<Float64> done(this);

          IF (LIKELY(__ Float64LessThan(0.0, input_f64))) {
            GOTO_IF(UNLIKELY(__ Float64LessThanOrEqual(two_52, input_f64)),
                    done, input_f64);
            V<Float64> temp1 =
                __ Float64Sub(__ Float64Add(two_52, input_f64), two_52);
            GOTO_IF_NOT(__ Float64LessThan(input_f64, temp1), done, temp1);
            GOTO(done, __ Float64Sub(temp1, 1.0));
          } ELSE IF (UNLIKELY(__ Float64Equal(input_f64, 0.0))) {
            GOTO(done, input_f64);
          } ELSE IF (UNLIKELY(
                        __ Float64LessThanOrEqual(input_f64, minus_two_52))) {
            GOTO(done, input_f64);
          } ELSE {
            V<Float64> temp1 = __ Float64Sub(-0.0, input_f64);
            V<Float64> temp2 =
                __ Float64Sub(__ Float64Add(two_52, temp1), two_52);
            GOTO_IF_NOT(__ Float64LessThan(temp2, temp1), done,
                        __ Float64Sub(-0.0, temp2));
            GOTO(done, __ Float64Sub(-1.0, temp2));
          }

          BIND(done, result);
          return result;
        } else if (kind == FloatUnaryOp::Kind::kRoundTiesEven) {
          // Generate case for round ties to even:
          //
          //   let value = floor(input) in
          //   let temp1 = input - value in
          //   if temp1 < 0.5 then
          //     value
          //   else if 0.5 < temp1 then
          //     value + 1.0
          //   else
          //     let temp2 = value % 2.0 in
          //     if temp2 == 0.0 then
          //       value
          //     else
          //       value + 1.0

          Label<Float64> done(this);

          V<Float64> value = __ Float64RoundDown(input_f64);
          V<Float64> temp1 = __ Float64Sub(input_f64, value);
          GOTO_IF(__ Float64LessThan(temp1, 0.5), done, value);
          GOTO_IF(__ Float64LessThan(0.5, temp1), done,
                  __ Float64Add(value, 1.0));

          V<Float64> temp2 = __ Float64Mod(value, 2.0);
          GOTO_IF(__ Float64Equal(temp2, 0.0), done, value);
          GOTO(done, __ Float64Add(value, 1.0));

          BIND(done, result);
          return result;
        } else if (kind == FloatUnaryOp::Kind::kRoundToZero) {
          // General case for trunc.
          //
          //   if 0.0 < input then
          //     if 2^52 <= input then
          //       input
          //     else
          //       let temp1 = (2^52 + input) - 2^52 in
          //       if input < temp1 then
          //         temp1 - 1
          //       else
          //         temp1
          //   else
          //     if input == 0 then
          //        input
          //     if input <= -2^52 then
          //       input
          //     else
          //       let temp1 = -0 - input in
          //       let temp2 = (2^52 + temp1) - 2^52 in
          //       if temp1 < temp2 then
          //          -0 - (temp2 - 1)
          //       else
          //          -0 - temp2

          Label<Float64> done(this);

          IF (__ Float64LessThan(0.0, input_f64)) {
            GOTO_IF(UNLIKELY(__ Float64LessThanOrEqual(two_52, input_f64)),
                    done, input_f64);

            V<Float64> temp1 =
                __ Float64Sub(__ Float64Add(two_52, input_f64), two_52);
            GOTO_IF(__ Float64LessThan(input_f64, temp1), done,
                    __ Float64Sub(temp1, 1.0));
            GOTO(done, temp1);
          } ELSE {
            GOTO_IF(UNLIKELY(__ Float64Equal(input_f64, 0.0)), done, input_f64);
            GOTO_IF(
                UNLIKELY(__ Float64LessThanOrEqual(input_f64, minus_two_52)),
                done, input_f64);

            V<Float64> temp1 = __ Float64Sub(-0.0, input_f64);
            V<Float64> temp2 =
                __ Float64Sub(__ Float64Add(two_52, temp1), two_52);

            IF (__ Float64LessThan(temp1, temp2)) {
              GOTO(done, __ Float64Sub(-0.0, __ Float64Sub(temp2, 1.0)));
            } ELSE {
              GOTO(done, __ Float64Sub(-0.0, temp2));
            }
          }

          BIND(done, result);
          return result;
        }
        UNREACHABLE();
      }
      default:
        DCHECK(FloatUnaryOp::IsSupported(kind, rep));
        goto no_change;
    }
    UNREACHABLE();
  }

  V<Object> REDUCE(CheckedClosure)(V<Object> input, V<FrameState> frame_state,
                                   Handle<FeedbackCell> feedback_cell) {
    // Check that {input} is actually a JSFunction.
    V<Map> map = __ LoadMapField(input);
    V<Word32> instance_type = __ LoadInstanceTypeField(map);
    V<Word32> is_function_type = __ Uint32LessThanOrEqual(
        __ Word32Sub(instance_type, FIRST_JS_FUNCTION_TYPE),
        (LAST_JS_FUNCTION_TYPE - FIRST_JS_FUNCTION_TYPE));
    __ DeoptimizeIfNot(is_function_type, frame_state,
                       DeoptimizeReason::kWrongCallTarget, FeedbackSource{});

    // Check that the {input}s feedback vector cell matches the one
    // we recorded before.
    V<HeapObject> cell = __ template LoadField<HeapObject>(
        input, AccessBuilder::ForJSFunctionFeedbackCell());
    __ DeoptimizeIfNot(__ TaggedEqual(cell, __ HeapConstant(feedback_cell)),
                       frame_state, DeoptimizeReason::kWrongFeedbackCell,
                       FeedbackSource{});
    return input;
  }

  V<None> REDUCE(CheckEqualsInternalizedString)(V<Object> expected,
                                                V<Object> value,
                                                V<FrameState> frame_state) {
    Label<> done(this);
    // Check if {expected} and {value} are the same, which is the
Prompt: 
```
这是目录为v8/src/compiler/turboshaft/machine-lowering-reducer-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/machine-lowering-reducer-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能

"""
entsElements)(V<Smi> arguments_count,
                                         CreateArgumentsType type,
                                         int formal_parameter_count) {
    V<WordPtr> frame = __ FramePointer();
    V<WordPtr> p_count = __ IntPtrConstant(formal_parameter_count);
    switch (type) {
      case CreateArgumentsType::kMappedArguments:
        return __ CallBuiltin_NewSloppyArgumentsElements(
            isolate_, frame, p_count, arguments_count);
      case CreateArgumentsType::kUnmappedArguments:
        return __ CallBuiltin_NewStrictArgumentsElements(
            isolate_, frame, p_count, arguments_count);
      case CreateArgumentsType::kRestParameter:
        return __ CallBuiltin_NewRestArgumentsElements(isolate_, frame, p_count,
                                                       arguments_count);
    }
  }

  OpIndex REDUCE(LoadTypedElement)(OpIndex buffer, V<Object> base,
                                   V<WordPtr> external, V<WordPtr> index,
                                   ExternalArrayType array_type) {
    V<WordPtr> data_ptr = BuildTypedArrayDataPointer(base, external);

    // Perform the actual typed element access.
    OpIndex result = __ LoadArrayBufferElement(
        data_ptr, AccessBuilder::ForTypedArrayElement(array_type, true), index);

    // We need to keep the {buffer} alive so that the GC will not release the
    // ArrayBuffer (if there's any) as long as we are still operating on it.
    __ Retain(buffer);
    return result;
  }

  V<Object> REDUCE(LoadStackArgument)(V<WordPtr> base, V<WordPtr> index) {
    // Note that this is a load of a Tagged value
    // (MemoryRepresentation::TaggedPointer()), but since it's on the stack
    // where stack slots are all kSystemPointerSize, we use kSystemPointerSize
    // for element_size_log2. On 64-bit plateforms with pointer compression,
    // this means that we're kinda loading a 32-bit value from an array of
    // 64-bit values.
#if V8_COMPRESS_POINTERS && V8_TARGET_BIG_ENDIAN
    constexpr int offset =
        CommonFrameConstants::kFixedFrameSizeAboveFp - kSystemPointerSize + 4;
#else
    constexpr int offset =
        CommonFrameConstants::kFixedFrameSizeAboveFp - kSystemPointerSize;
#endif
    return __ Load(base, index, LoadOp::Kind::RawAligned(),
                   MemoryRepresentation::TaggedPointer(), offset,
                   kSystemPointerSizeLog2);
  }

  OpIndex REDUCE(StoreTypedElement)(OpIndex buffer, V<Object> base,
                                    V<WordPtr> external, V<WordPtr> index,
                                    OpIndex value,
                                    ExternalArrayType array_type) {
    V<WordPtr> data_ptr = BuildTypedArrayDataPointer(base, external);

    // Perform the actual typed element access.
    __ StoreArrayBufferElement(
        data_ptr, AccessBuilder::ForTypedArrayElement(array_type, true), index,
        value);

    // We need to keep the {buffer} alive so that the GC will not release the
    // ArrayBuffer (if there's any) as long as we are still operating on it.
    __ Retain(buffer);
    return {};
  }

  OpIndex REDUCE(TransitionAndStoreArrayElement)(
      V<JSArray> array, V<WordPtr> index, OpIndex value,
      TransitionAndStoreArrayElementOp::Kind kind, MaybeHandle<Map> fast_map,
      MaybeHandle<Map> double_map) {
    V<Map> map = __ LoadMapField(array);
    V<Word32> bitfield2 =
        __ template LoadField<Word32>(map, AccessBuilder::ForMapBitField2());
    V<Word32> elements_kind = __ Word32ShiftRightLogical(
        __ Word32BitwiseAnd(bitfield2, Map::Bits2::ElementsKindBits::kMask),
        Map::Bits2::ElementsKindBits::kShift);

    switch (kind) {
      case TransitionAndStoreArrayElementOp::Kind::kElement: {
        // Possibly transition array based on input and store.
        //
        //   -- TRANSITION PHASE -----------------
        //   kind = ElementsKind(array)
        //   if value is not smi {
        //     if kind == HOLEY_SMI_ELEMENTS {
        //       if value is heap number {
        //         Transition array to HOLEY_DOUBLE_ELEMENTS
        //         kind = HOLEY_DOUBLE_ELEMENTS
        //       } else {
        //         Transition array to HOLEY_ELEMENTS
        //         kind = HOLEY_ELEMENTS
        //       }
        //     } else if kind == HOLEY_DOUBLE_ELEMENTS {
        //       if value is not heap number {
        //         Transition array to HOLEY_ELEMENTS
        //         kind = HOLEY_ELEMENTS
        //       }
        //     }
        //   }
        //
        //   -- STORE PHASE ----------------------
        //   [make sure {kind} is up-to-date]
        //   if kind == HOLEY_DOUBLE_ELEMENTS {
        //     if value is smi {
        //       float_value = convert smi to float
        //       Store array[index] = float_value
        //     } else {
        //       float_value = value
        //       Store array[index] = float_value
        //     }
        //   } else {
        //     // kind is HOLEY_SMI_ELEMENTS or HOLEY_ELEMENTS
        //     Store array[index] = value
        //   }
        //
        Label<Word32> do_store(this);
        // We can store a smi anywhere.
        GOTO_IF(__ ObjectIsSmi(value), do_store, elements_kind);

        // {value} is a HeapObject.
        IF_NOT (LIKELY(__ Int32LessThan(HOLEY_SMI_ELEMENTS, elements_kind))) {
          // Transition {array} from HOLEY_SMI_ELEMENTS to HOLEY_DOUBLE_ELEMENTS
          // or to HOLEY_ELEMENTS.
          V<Map> value_map = __ LoadMapField(value);
          IF (__ TaggedEqual(value_map,
                             __ HeapConstant(factory_->heap_number_map()))) {
            // {value} is a HeapNumber.
            TransitionElementsTo(array, HOLEY_SMI_ELEMENTS,
                                 HOLEY_DOUBLE_ELEMENTS,
                                 double_map.ToHandleChecked());
            GOTO(do_store, HOLEY_DOUBLE_ELEMENTS);
          } ELSE {
            TransitionElementsTo(array, HOLEY_SMI_ELEMENTS, HOLEY_ELEMENTS,
                                 fast_map.ToHandleChecked());
            GOTO(do_store, HOLEY_ELEMENTS);
          }
        }

        GOTO_IF_NOT(LIKELY(__ Int32LessThan(HOLEY_ELEMENTS, elements_kind)),
                    do_store, elements_kind);

        // We have double elements kind. Only a HeapNumber can be stored
        // without effecting a transition.
        V<Map> value_map = __ LoadMapField(value);
        IF_NOT (UNLIKELY(__ TaggedEqual(
                    value_map, __ HeapConstant(factory_->heap_number_map())))) {
          TransitionElementsTo(array, HOLEY_DOUBLE_ELEMENTS, HOLEY_ELEMENTS,
                               fast_map.ToHandleChecked());
          GOTO(do_store, HOLEY_ELEMENTS);
        }

        GOTO(do_store, elements_kind);

        BIND(do_store, store_kind);
        V<Object> elements = __ template LoadField<Object>(
            array, AccessBuilder::ForJSObjectElements());
        IF (__ Int32LessThan(HOLEY_ELEMENTS, store_kind)) {
          // Our ElementsKind is HOLEY_DOUBLE_ELEMENTS.
          IF (__ ObjectIsSmi(value)) {
            V<Float64> float_value =
                __ ChangeInt32ToFloat64(__ UntagSmi(value));
            __ StoreNonArrayBufferElement(
                elements, AccessBuilder::ForFixedDoubleArrayElement(), index,
                float_value);
          } ELSE {
            V<Float64> float_value =
                __ LoadHeapNumberValue(V<HeapNumber>::Cast(value));
            __ StoreNonArrayBufferElement(
                elements, AccessBuilder::ForFixedDoubleArrayElement(), index,
                __ Float64SilenceNaN(float_value));
          }
        } ELSE {
          // Our ElementsKind is HOLEY_SMI_ELEMENTS or HOLEY_ELEMENTS.
          __ StoreNonArrayBufferElement(
              elements, AccessBuilder::ForFixedArrayElement(HOLEY_ELEMENTS),
              index, value);
        }

        break;
      }
      case TransitionAndStoreArrayElementOp::Kind::kNumberElement: {
        Label<> done(this);
        // Possibly transition array based on input and store.
        //
        //   -- TRANSITION PHASE -----------------
        //   kind = ElementsKind(array)
        //   if kind == HOLEY_SMI_ELEMENTS {
        //     Transition array to HOLEY_DOUBLE_ELEMENTS
        //   } else if kind != HOLEY_DOUBLE_ELEMENTS {
        //     if kind == HOLEY_ELEMENTS {
        //       Store value as a HeapNumber in array[index].
        //     } else {
        //       This is UNREACHABLE, execute a debug break.
        //     }
        //   }
        //
        //   -- STORE PHASE ----------------------
        //   Store array[index] = value (it's a float)
        //
        // {value} is a float64.
        IF_NOT (LIKELY(__ Int32LessThan(HOLEY_SMI_ELEMENTS, elements_kind))) {
          // Transition {array} from HOLEY_SMI_ELEMENTS to
          // HOLEY_DOUBLE_ELEMENTS.
          TransitionElementsTo(array, HOLEY_SMI_ELEMENTS, HOLEY_DOUBLE_ELEMENTS,
                               double_map.ToHandleChecked());
        } ELSE {
          // We expect that our input array started at HOLEY_SMI_ELEMENTS, and
          // climbs the lattice up to HOLEY_DOUBLE_ELEMENTS. However, loop
          // peeling can break this assumption, because in the peeled iteration,
          // the array might have transitioned to HOLEY_ELEMENTS kind, so we
          // handle this as well.
          IF_NOT (LIKELY(
                      __ Word32Equal(elements_kind, HOLEY_DOUBLE_ELEMENTS))) {
            IF (__ Word32Equal(elements_kind, HOLEY_ELEMENTS)) {
              V<Object> elements = __ template LoadField<Object>(
                  array, AccessBuilder::ForJSObjectElements());
              // Our ElementsKind is HOLEY_ELEMENTS.
              __ StoreNonArrayBufferElement(
                  elements, AccessBuilder::ForFixedArrayElement(HOLEY_ELEMENTS),
                  index, AllocateHeapNumber(value));
              GOTO(done);
            }

            __ Unreachable();
          }
        }

        V<Object> elements = __ template LoadField<Object>(
            array, AccessBuilder::ForJSObjectElements());
        __ StoreNonArrayBufferElement(
            elements, AccessBuilder::ForFixedDoubleArrayElement(), index,
            __ Float64SilenceNaN(value));
        GOTO(done);

        BIND(done);
        break;
      }
      case TransitionAndStoreArrayElementOp::Kind::kOddballElement:
      case TransitionAndStoreArrayElementOp::Kind::kNonNumberElement: {
        // Possibly transition array based on input and store.
        //
        //   -- TRANSITION PHASE -----------------
        //   kind = ElementsKind(array)
        //   if kind == HOLEY_SMI_ELEMENTS {
        //     Transition array to HOLEY_ELEMENTS
        //   } else if kind == HOLEY_DOUBLE_ELEMENTS {
        //     Transition array to HOLEY_ELEMENTS
        //   }
        //
        //   -- STORE PHASE ----------------------
        //   // kind is HOLEY_ELEMENTS
        //   Store array[index] = value
        //
        IF_NOT (LIKELY(__ Int32LessThan(HOLEY_SMI_ELEMENTS, elements_kind))) {
          // Transition {array} from HOLEY_SMI_ELEMENTS to HOLEY_ELEMENTS.
          TransitionElementsTo(array, HOLEY_SMI_ELEMENTS, HOLEY_ELEMENTS,
                               fast_map.ToHandleChecked());
        } ELSE IF (UNLIKELY(__ Int32LessThan(HOLEY_ELEMENTS, elements_kind))) {
          TransitionElementsTo(array, HOLEY_DOUBLE_ELEMENTS, HOLEY_ELEMENTS,
                               fast_map.ToHandleChecked());
        }

        V<Object> elements = __ template LoadField<Object>(
            array, AccessBuilder::ForJSObjectElements());
        ElementAccess access =
            AccessBuilder::ForFixedArrayElement(HOLEY_ELEMENTS);
        if (kind == TransitionAndStoreArrayElementOp::Kind::kOddballElement) {
          access.type = compiler::Type::BooleanOrNullOrUndefined();
          access.write_barrier_kind = kNoWriteBarrier;
        }
        __ StoreNonArrayBufferElement(elements, access, index, value);
        break;
      }
      case TransitionAndStoreArrayElementOp::Kind::kSignedSmallElement: {
        // Store a signed small in an output array.
        //
        //   kind = ElementsKind(array)
        //
        //   -- STORE PHASE ----------------------
        //   if kind == HOLEY_DOUBLE_ELEMENTS {
        //     float_value = convert int32 to float
        //     Store array[index] = float_value
        //   } else {
        //     // kind is HOLEY_SMI_ELEMENTS or HOLEY_ELEMENTS
        //     smi_value = convert int32 to smi
        //     Store array[index] = smi_value
        //   }
        //
        V<Object> elements = __ template LoadField<Object>(
            array, AccessBuilder::ForJSObjectElements());
        IF (__ Int32LessThan(HOLEY_ELEMENTS, elements_kind)) {
          // Our ElementsKind is HOLEY_DOUBLE_ELEMENTS.
          V<Float64> f64 = __ ChangeInt32ToFloat64(value);
          __ StoreNonArrayBufferElement(
              elements, AccessBuilder::ForFixedDoubleArrayElement(), index,
              f64);
        } ELSE {
          // Our ElementsKind is HOLEY_SMI_ELEMENTS or HOLEY_ELEMENTS.
          // In this case, we know our value is a signed small, and we can
          // optimize the ElementAccess information.
          ElementAccess access = AccessBuilder::ForFixedArrayElement();
          access.type = compiler::Type::SignedSmall();
          access.machine_type = MachineType::TaggedSigned();
          access.write_barrier_kind = kNoWriteBarrier;
          __ StoreNonArrayBufferElement(elements, access, index,
                                        __ TagSmi(value));
        }

        break;
      }
    }

    return OpIndex::Invalid();
  }

  V<Word32> REDUCE(CompareMaps)(V<HeapObject> heap_object, OptionalV<Map> map,
                                const ZoneRefSet<Map>& maps) {
    if (!map.has_value()) {
      map = __ LoadMapField(heap_object);
    }
    return CompareMapAgainstMultipleMaps(map.value(), maps);
  }

  V<None> REDUCE(CheckMaps)(V<HeapObject> heap_object,
                            V<FrameState> frame_state, OptionalV<Map> map,
                            const ZoneRefSet<Map>& maps, CheckMapsFlags flags,
                            const FeedbackSource& feedback) {
    if (maps.is_empty()) {
      __ Deoptimize(frame_state, DeoptimizeReason::kWrongMap, feedback);
      return {};
    }

    V<Map> heap_object_map;
    if (map.has_value()) {
      heap_object_map = map.value();
    } else {
      heap_object_map = __ LoadMapField(heap_object);
    }

    if (flags & CheckMapsFlag::kTryMigrateInstance) {
      IF_NOT (LIKELY(CompareMapAgainstMultipleMaps(heap_object_map, maps))) {
        // Reloading the map slightly reduces register pressure, and we are on a
        // slow path here anyway.
        MigrateInstanceOrDeopt(heap_object, heap_object_map, frame_state,
                               feedback);
        heap_object_map = __ LoadMapField(heap_object);
        __ DeoptimizeIfNot(__ CompareMaps(heap_object, heap_object_map, maps),
                           frame_state, DeoptimizeReason::kWrongMap, feedback);
      }
    } else {
      __ DeoptimizeIfNot(__ CompareMaps(heap_object, heap_object_map, maps),
                         frame_state, DeoptimizeReason::kWrongMap, feedback);
    }
    // Inserting a AssumeMap so that subsequent optimizations know the map of
    // this object.
    __ AssumeMap(heap_object, maps);
    return {};
  }

  V<Float> REDUCE(FloatUnary)(V<Float> input, FloatUnaryOp::Kind kind,
                              FloatRepresentation rep) {
    LABEL_BLOCK(no_change) { return Next::ReduceFloatUnary(input, kind, rep); }
    switch (kind) {
      case FloatUnaryOp::Kind::kRoundUp:
      case FloatUnaryOp::Kind::kRoundDown:
      case FloatUnaryOp::Kind::kRoundTiesEven:
      case FloatUnaryOp::Kind::kRoundToZero: {
        // TODO(14108): Implement for Float32.
        if (rep == FloatRepresentation::Float32()) {
          goto no_change;
        }
        DCHECK_EQ(rep, FloatRepresentation::Float64());
        V<Float64> input_f64 = V<Float64>::Cast(input);
        if (FloatUnaryOp::IsSupported(kind, rep)) {
          // If we have a fast machine operation for this, we can just keep it.
          goto no_change;
        }
        // Otherwise we have to lower it.
        V<Float64> two_52 = __ Float64Constant(4503599627370496.0E0);
        V<Float64> minus_two_52 = __ Float64Constant(-4503599627370496.0E0);

        if (kind == FloatUnaryOp::Kind::kRoundUp) {
          // General case for ceil.
          //
          //   if 0.0 < input then
          //     if 2^52 <= input then
          //       input
          //     else
          //       let temp1 = (2^52 + input) - 2^52 in
          //       if temp1 < input then
          //         temp1 + 1
          //       else
          //         temp1
          //   else
          //     if input == 0 then
          //       input
          //     else
          //       if input <= -2^52 then
          //         input
          //       else
          //         let temp1 = -0 - input in
          //         let temp2 = (2^52 + temp1) - 2^52 in
          //         if temp1 < temp2 then -0 - (temp2 - 1) else -0 - temp2

          Label<Float64> done(this);

          IF (LIKELY(__ Float64LessThan(0.0, input_f64))) {
            GOTO_IF(UNLIKELY(__ Float64LessThanOrEqual(two_52, input_f64)),
                    done, input_f64);
            V<Float64> temp1 =
                __ Float64Sub(__ Float64Add(two_52, input_f64), two_52);
            GOTO_IF_NOT(__ Float64LessThan(temp1, input_f64), done, temp1);
            GOTO(done, __ Float64Add(temp1, 1.0));
          } ELSE IF (UNLIKELY(__ Float64Equal(input_f64, 0.0))) {
            GOTO(done, input_f64);
          } ELSE IF (UNLIKELY(
                        __ Float64LessThanOrEqual(input_f64, minus_two_52))) {
            GOTO(done, input_f64);
          } ELSE {
            V<Float64> temp1 = __ Float64Sub(-0.0, input_f64);
            V<Float64> temp2 =
                __ Float64Sub(__ Float64Add(two_52, temp1), two_52);
            GOTO_IF_NOT(__ Float64LessThan(temp1, temp2), done,
                        __ Float64Sub(-0.0, temp2));
            GOTO(done, __ Float64Sub(-0.0, __ Float64Sub(temp2, 1.0)));
          }

          BIND(done, result);
          return result;
        } else if (kind == FloatUnaryOp::Kind::kRoundDown) {
          // General case for floor.
          //
          //   if 0.0 < input then
          //     if 2^52 <= input then
          //       input
          //     else
          //       let temp1 = (2^52 + input) - 2^52 in
          //       if input < temp1 then
          //         temp1 - 1
          //       else
          //         temp1
          //   else
          //     if input == 0 then
          //       input
          //     else
          //       if input <= -2^52 then
          //         input
          //       else
          //         let temp1 = -0 - input in
          //         let temp2 = (2^52 + temp1) - 2^52 in
          //         if temp2 < temp1 then
          //           -1 - temp2
          //         else
          //           -0 - temp2

          Label<Float64> done(this);

          IF (LIKELY(__ Float64LessThan(0.0, input_f64))) {
            GOTO_IF(UNLIKELY(__ Float64LessThanOrEqual(two_52, input_f64)),
                    done, input_f64);
            V<Float64> temp1 =
                __ Float64Sub(__ Float64Add(two_52, input_f64), two_52);
            GOTO_IF_NOT(__ Float64LessThan(input_f64, temp1), done, temp1);
            GOTO(done, __ Float64Sub(temp1, 1.0));
          } ELSE IF (UNLIKELY(__ Float64Equal(input_f64, 0.0))) {
            GOTO(done, input_f64);
          } ELSE IF (UNLIKELY(
                        __ Float64LessThanOrEqual(input_f64, minus_two_52))) {
            GOTO(done, input_f64);
          } ELSE {
            V<Float64> temp1 = __ Float64Sub(-0.0, input_f64);
            V<Float64> temp2 =
                __ Float64Sub(__ Float64Add(two_52, temp1), two_52);
            GOTO_IF_NOT(__ Float64LessThan(temp2, temp1), done,
                        __ Float64Sub(-0.0, temp2));
            GOTO(done, __ Float64Sub(-1.0, temp2));
          }

          BIND(done, result);
          return result;
        } else if (kind == FloatUnaryOp::Kind::kRoundTiesEven) {
          // Generate case for round ties to even:
          //
          //   let value = floor(input) in
          //   let temp1 = input - value in
          //   if temp1 < 0.5 then
          //     value
          //   else if 0.5 < temp1 then
          //     value + 1.0
          //   else
          //     let temp2 = value % 2.0 in
          //     if temp2 == 0.0 then
          //       value
          //     else
          //       value + 1.0

          Label<Float64> done(this);

          V<Float64> value = __ Float64RoundDown(input_f64);
          V<Float64> temp1 = __ Float64Sub(input_f64, value);
          GOTO_IF(__ Float64LessThan(temp1, 0.5), done, value);
          GOTO_IF(__ Float64LessThan(0.5, temp1), done,
                  __ Float64Add(value, 1.0));

          V<Float64> temp2 = __ Float64Mod(value, 2.0);
          GOTO_IF(__ Float64Equal(temp2, 0.0), done, value);
          GOTO(done, __ Float64Add(value, 1.0));

          BIND(done, result);
          return result;
        } else if (kind == FloatUnaryOp::Kind::kRoundToZero) {
          // General case for trunc.
          //
          //   if 0.0 < input then
          //     if 2^52 <= input then
          //       input
          //     else
          //       let temp1 = (2^52 + input) - 2^52 in
          //       if input < temp1 then
          //         temp1 - 1
          //       else
          //         temp1
          //   else
          //     if input == 0 then
          //        input
          //     if input <= -2^52 then
          //       input
          //     else
          //       let temp1 = -0 - input in
          //       let temp2 = (2^52 + temp1) - 2^52 in
          //       if temp1 < temp2 then
          //          -0 - (temp2 - 1)
          //       else
          //          -0 - temp2

          Label<Float64> done(this);

          IF (__ Float64LessThan(0.0, input_f64)) {
            GOTO_IF(UNLIKELY(__ Float64LessThanOrEqual(two_52, input_f64)),
                    done, input_f64);

            V<Float64> temp1 =
                __ Float64Sub(__ Float64Add(two_52, input_f64), two_52);
            GOTO_IF(__ Float64LessThan(input_f64, temp1), done,
                    __ Float64Sub(temp1, 1.0));
            GOTO(done, temp1);
          } ELSE {
            GOTO_IF(UNLIKELY(__ Float64Equal(input_f64, 0.0)), done, input_f64);
            GOTO_IF(
                UNLIKELY(__ Float64LessThanOrEqual(input_f64, minus_two_52)),
                done, input_f64);

            V<Float64> temp1 = __ Float64Sub(-0.0, input_f64);
            V<Float64> temp2 =
                __ Float64Sub(__ Float64Add(two_52, temp1), two_52);

            IF (__ Float64LessThan(temp1, temp2)) {
              GOTO(done, __ Float64Sub(-0.0, __ Float64Sub(temp2, 1.0)));
            } ELSE {
              GOTO(done, __ Float64Sub(-0.0, temp2));
            }
          }

          BIND(done, result);
          return result;
        }
        UNREACHABLE();
      }
      default:
        DCHECK(FloatUnaryOp::IsSupported(kind, rep));
        goto no_change;
    }
    UNREACHABLE();
  }

  V<Object> REDUCE(CheckedClosure)(V<Object> input, V<FrameState> frame_state,
                                   Handle<FeedbackCell> feedback_cell) {
    // Check that {input} is actually a JSFunction.
    V<Map> map = __ LoadMapField(input);
    V<Word32> instance_type = __ LoadInstanceTypeField(map);
    V<Word32> is_function_type = __ Uint32LessThanOrEqual(
        __ Word32Sub(instance_type, FIRST_JS_FUNCTION_TYPE),
        (LAST_JS_FUNCTION_TYPE - FIRST_JS_FUNCTION_TYPE));
    __ DeoptimizeIfNot(is_function_type, frame_state,
                       DeoptimizeReason::kWrongCallTarget, FeedbackSource{});

    // Check that the {input}s feedback vector cell matches the one
    // we recorded before.
    V<HeapObject> cell = __ template LoadField<HeapObject>(
        input, AccessBuilder::ForJSFunctionFeedbackCell());
    __ DeoptimizeIfNot(__ TaggedEqual(cell, __ HeapConstant(feedback_cell)),
                       frame_state, DeoptimizeReason::kWrongFeedbackCell,
                       FeedbackSource{});
    return input;
  }

  V<None> REDUCE(CheckEqualsInternalizedString)(V<Object> expected,
                                                V<Object> value,
                                                V<FrameState> frame_state) {
    Label<> done(this);
    // Check if {expected} and {value} are the same, which is the likely case.
    GOTO_IF(LIKELY(__ TaggedEqual(expected, value)), done);

    // Now {value} could still be a non-internalized String that matches
    // {expected}.
    __ DeoptimizeIf(__ ObjectIsSmi(value), frame_state,
                    DeoptimizeReason::kWrongName, FeedbackSource{});
    V<Map> value_map = __ LoadMapField(value);
    V<Word32> value_instance_type = __ LoadInstanceTypeField(value_map);
    V<Word32> value_representation =
        __ Word32BitwiseAnd(value_instance_type, kStringRepresentationMask);
    // ThinString
    IF (__ Word32Equal(value_representation, kThinStringTag)) {
      // The {value} is a ThinString, let's check the actual value.
      V<String> value_actual = __ template LoadField<String>(
          value, AccessBuilder::ForThinStringActual());
      __ DeoptimizeIfNot(__ TaggedEqual(expected, value_actual), frame_state,
                         DeoptimizeReason::kWrongName, FeedbackSource{});
    } ELSE {
      // Check that the {value} is a non-internalized String, if it's anything
      // else it cannot match the recorded feedback {expected} anyways.
      __ DeoptimizeIfNot(
          __ Word32Equal(
              __ Word32BitwiseAnd(value_instance_type,
                                  kIsNotStringMask | kIsNotInternalizedMask),
              kStringTag | kNotInternalizedTag),
          frame_state, DeoptimizeReason::kWrongName, FeedbackSource{});

      // Try to find the {value} in the string table.
      MachineSignature::Builder builder(__ graph_zone(), 1, 2);
      builder.AddReturn(MachineType::AnyTagged());
      builder.AddParam(MachineType::Pointer());
      builder.AddParam(MachineType::AnyTagged());
      OpIndex try_string_to_index_or_lookup_existing = __ ExternalConstant(
          ExternalReference::try_string_to_index_or_lookup_existing());
      OpIndex isolate_ptr =
          __ ExternalConstant(ExternalReference::isolate_address());
      V<String> value_internalized = V<String>::Cast(__ Call(
          try_string_to_index_or_lookup_existing, {isolate_ptr, value},
          TSCallDescriptor::Create(
              Linkage::GetSimplifiedCDescriptor(__ graph_zone(), builder.Get()),
              CanThrow::kNo, LazyDeoptOnThrow::kNo, __ graph_zone())));

      // Now see if the results match.
      __ DeoptimizeIfNot(__ TaggedEqual(expected, value_internalized),
                         frame_state, DeoptimizeReason::kWrongName,
                         FeedbackSource{});
    }

    GOTO(done);

    BIND(done);
    return V<None>::Invalid();
  }

  V<Object> REDUCE(LoadMessage)(V<WordPtr> offset) {
    return __ BitcastWordPtrToTagged(__ template LoadField<WordPtr>(
        offset, AccessBuilder::ForExternalIntPtr()));
  }

  V<None> REDUCE(StoreMessage)(V<WordPtr> offset, V<Object> object) {
    __ StoreField(offset, AccessBuilder::ForExternalIntPtr(),
                  __ BitcastTaggedToWordPtr(object));
    return V<None>::Invalid();
  }

  V<Boolean> REDUCE(SameValue)(OpIndex left, OpIndex right,
                               SameValueOp::Mode mode) {
    switch (mode) {
      case SameValueOp::Mode::kSameValue:
        return __ CallBuiltin_SameValue(isolate_, left, right);
      case SameValueOp::Mode::kSameValueNumbersOnly:
        return __ CallBuiltin_SameValueNumbersOnly(isolate_, left, right);
    }
  }

  V<Word32> REDUCE(Float64SameValue)(V<Float64> left, V<Float64> right) {
    Label<Word32> done(this);

    IF (__ Float64Equal(left, right)) {
      // Even if the values are float64-equal, we still need to distinguish
      // zero and minus zero.
      V<Word32> left_hi = __ Float64ExtractHighWord32(left);
      V<Word32> right_hi = __ Float64ExtractHighWord32(right);
      GOTO(done, __ Word32Equal(left_hi, right_hi));
    } ELSE {
      // Return true iff both {lhs} and {rhs} are NaN.
      GOTO_IF(__ Float64Equal(left, left), done, 0);
      GOTO_IF(__ Float64Equal(right, right), done, 0);
      GOTO(done, 1);
    }

    BIND(done, result);
    return result;
  }

  OpIndex REDUCE(RuntimeAbort)(AbortReason reason) {
    __ CallRuntime_Abort(isolate_, __ NoContextConstant(),
                         __ TagSmi(static_cast<int>(reason)));
    return OpIndex::Invalid();
  }

  V<Object> REDUCE(EnsureWritableFastElements)(V<Object> object,
                                               V<Object> elements) {
    Label<Object> done(this);
    // Load the current map of {elements}.
    V<Map> map = __ LoadMapField(elements);

    // Check if {elements} is not a copy-on-write FixedArray.
    // Nothing to do if the {elements} are not copy-on-write.
    GOTO_IF(LIKELY(__ TaggedEqual(
                map, __ HeapConstant(factory_->fixed_array_map()))),
            done, elements);

    // We need to take a copy of the {elements} and set them up for {object}.
    V<Object> copy =
        __ CallBuiltin_CopyFastSmiOrObjectElements(isolate_, object);
    GOTO(done, copy);

    BIND(done, result);
    return result;
  }

  V<Object> REDUCE(MaybeGrowFastElements)(V<Object> object, V<Object> elements,
                                          V<Word32> index,
                                          V<Word32> elements_length,
                                          V<FrameState> frame_state,
                                          GrowFastElementsMode mode,
                                          const FeedbackSource& feedback) {
    Label<Object> done(this);
    // Check if we need to grow the {elements} backing store.
    GOTO_IF(LIKELY(__ Uint32LessThan(index, elements_length)), done, elements);
    // We need to grow the {elements} for {object}.
    V<Object> new_elements;
    switch (mode) {
      case GrowFastElementsMode::kDoubleElements:
        new_elements = __ CallBuiltin_GrowFastDoubleElements(isolate_, object,
                                                             __ TagSmi(index));
        break;
      case GrowFastElementsMode::kSmiOrObjectElements:
        new_elements = __ CallBuiltin_GrowFastSmiOrObjectElements(
            isolate_, object, __ TagSmi(index));
        break;
    }

    // Ensure that we were able to grow the {elements}.
    __ DeoptimizeIf(__ ObjectIsSmi(new_elements), frame_state,
                    DeoptimizeReason::kCouldNotGrowElements, feedback);
    GOTO(done, new_elements);

    BIND(done, result);
    return result;
  }

  OpIndex REDUCE(TransitionElementsKind)(V<HeapObject> object,
                                         const ElementsTransition& transition) {
    V<Map> source_map = __ HeapConstant(transition.source().object());
    V<Map> target_map = __ HeapConstant(transition.target().object());

    // Load the current map of {object}.
    V<Map> map = __ LoadMapField(object);

    // Check if {map} is the same as {source_map}.
    IF (UNLIKELY(__ TaggedEqual(map, source_map))) {
      switch (transition.mode()) {
        case ElementsTransition::kFastTransition:
          // In-place migration of {object}, just store the {target_map}.
          __ StoreField(object, AccessBuilder::ForMap(), target_map);
          break;
        case ElementsTransition::kSlowTransition:
          // Instance migration, call out to the runtime for {object}.
          __ CallRuntime_TransitionElementsKind(
              isolate_, __ NoContextConstant(), object, target_map);
          break;
      }
    }

    return OpIndex::Invalid();
  }

  OpIndex REDUCE(FindOrderedHashEntry)(V<Object> data_structure, OpIndex key,
                                       FindOrderedHashEntryOp::Kind kind) {
    switch (kind) {
      case FindOrderedHashEntryOp::Kind::kFindOrderedHashMapEntry:
        return __ CallBuiltin_FindOrderedHashMapEntry(
            isolate_, __ NoContextConstant(), data_structure, key);
      case FindOrderedHashEntryOp::Kind::kFindOrderedHashMapEntryForInt32K
"""


```