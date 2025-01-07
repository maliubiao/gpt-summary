Response:
My thinking process to analyze the provided code snippet and fulfill the request goes like this:

1. **Understand the Request:** I first break down the prompt into its core components:
    * Identify the functionality of the code snippet (`v8/src/codegen/code-stub-assembler.cc`).
    * Explain what a `.tq` file indicates in the V8 context.
    * Provide a JavaScript example if the code relates to JavaScript functionality.
    * Illustrate code logic with input and output examples.
    * Give examples of common programming errors related to the code.
    * Summarize the functionality of *this specific part* (part 15 of 23).

2. **High-Level Code Examination:** I skim the code to get a general idea of what it's doing. Keywords and patterns like `Lookup`, `TryLookup`, `PrototypeChain`, `Feedback`, and array element access stand out. This immediately suggests that the code deals with property lookup, prototype chain traversal, and potentially optimized access to object properties and array elements within V8's internal representation.

3. **Function-by-Function Analysis (Focused on Key Areas):** I examine each function to understand its specific purpose:

    * **`TryLookupProperty`:**  Clearly related to property lookup. The logic iterates through the prototype chain, checking dictionaries and handling special cases like interceptors.
    * **`TryLookupElement`:**  Deals with looking up elements in various data structures used for storing object properties (fast and slow arrays, dictionaries, strings, typed arrays). The extensive `switch` statement on `elements_kind` is a strong indicator of this.
    * **`BranchIfMaybeSpecialIndex`:**  Focuses on identifying if a string might represent a numeric index (e.g., "0", "10", "-1", "Infinity", "NaN").
    * **`TryPrototypeChainLookup`:**  A more general function that orchestrates property or element lookup by iterating through the prototype chain, using the `lookup_property_in_holder` and `lookup_element_in_holder` function pointers (or lambdas).
    * **`HasInPrototypeChain`:**  Checks if a given prototype exists in an object's prototype chain.
    * **`OrdinaryHasInstance`:** Implements the `instanceof` operator's logic.
    * **`ElementOffsetFromIndex`:** Calculates the memory offset for accessing an element in an array-like structure based on its index and element kind.
    * **`LoadFeedbackCellValue`, `LoadFeedbackVector`, `LoadClosureFeedbackArray`:**  Deal with accessing feedback mechanisms used for optimizing JavaScript execution.
    * **`UpdateFeedback`, `MaybeUpdateFeedback`, `OverwriteFeedback`, `CombineFeedback`:** Functions related to updating the feedback information.
    * **`CheckForAssociatedProtector`:** Checks for specific names that have associated "protectors" (used for invalidating optimizations).
    * **`DCheckReceiver`:**  Performs assertions (in debug builds) about the type of the receiver object.
    * **`LoadReceiverMap`:**  Loads the map of an object, handling the special case of Smis.
    * **`TryToIntptr`:**  Attempts to convert a JavaScript value to an integer pointer, handling Smis and HeapNumbers.
    * **`LoadScriptContext`:** Loads a script context from the native context.
    * **`StoreElementTypedArrayBigInt`:**  Specifically handles storing BigInt values in typed arrays.

4. **Answering Specific Questions:**

    * **Functionality:** I synthesize the individual function analyses into a coherent description of the file's purpose.
    * **`.tq` Files:** I explain that `.tq` signifies Torque, V8's internal language for defining built-in functions.
    * **JavaScript Examples:** For functions with clear JavaScript equivalents (like property access, `instanceof`, and array access), I provide corresponding examples.
    * **Logic Reasoning (Input/Output):** I choose functions with relatively straightforward logic (e.g., `ElementOffsetFromIndex`, `BranchIfMaybeSpecialIndex`) and create simple input/output scenarios to illustrate their behavior.
    * **Common Programming Errors:** I consider typical JavaScript errors that would lead to the execution of this kind of internal code (e.g., accessing non-existent properties, incorrect `instanceof` usage, out-of-bounds array access, using non-numeric indices).
    * **Part 15 Summary:** I focus on the themes present in the provided code: property/element lookup, prototype chain manipulation, and optimization through feedback.

5. **Refinement and Structuring:** I organize the information clearly with headings and bullet points to make it easy to read and understand. I ensure that the JavaScript examples are concise and relevant. I double-check that all parts of the prompt have been addressed. I use precise language to describe V8 internals (e.g., "Maps," "ElementsKind," "Feedback Vectors").

**Self-Correction/Refinement Example During the Process:**

Initially, I might have just listed the functions and a one-liner for each. However, upon reviewing the request for a *deeper* understanding, I realized I needed to:

* **Group related functions:** For instance, putting all the feedback-related functions together makes more sense.
* **Explain the *why* behind the code:**  Instead of just saying "loads the map," I explain that Maps are V8's internal structure for object layout.
* **Connect the internal code to JavaScript behavior:**  This is crucial for someone trying to understand how V8 works. The JavaScript examples bridge this gap.
* **Provide concrete illustrations:** The input/output examples and common error scenarios make the abstract code more tangible.

By following this detailed analysis and refinement process, I can generate a comprehensive and informative response that addresses all aspects of the user's request.
```cpp
E_SWISS_NAME_DICTIONARY_BOOL) {
        TNode<Smi> flags =
            GetNameDictionaryFlags<NameDictionary>(CAST(properties));
        GotoIf(IsSetSmi(flags,
                        NameDictionary::MayHaveInterestingPropertiesBit::kMask),
               &lookup);
        *var_holder = LoadMapPrototype(holder_map);
        *var_holder_map = LoadMap((*var_holder).value());
      }
      Goto(&loop);
    }
  }

  BIND(&lookup);
  return CallBuiltin(Builtin::kGetPropertyWithReceiver, context,
                     (*var_holder).value(), name, receiver,
                     SmiConstant(OnNonExistent::kReturnUndefined));
}

void CodeStubAssembler::TryLookupElement(
    TNode<HeapObject> object, TNode<Map> map, TNode<Int32T> instance_type,
    TNode<IntPtrT> intptr_index, Label* if_found, Label* if_absent,
    Label* if_not_found, Label* if_bailout) {
  // Handle special objects in runtime.
  GotoIf(IsSpecialReceiverInstanceType(instance_type), if_bailout);

  TNode<Int32T> elements_kind = LoadMapElementsKind(map);

  // TODO(verwaest): Support other elements kinds as well.
  Label if_isobjectorsmi(this), if_isdouble(this), if_isdictionary(this),
      if_isfaststringwrapper(this), if_isslowstringwrapper(this), if_oob(this),
      if_typedarray(this), if_rab_gsab_typedarray(this);
  // clang-format off
  int32_t values[] = {
      // Handled by {if_isobjectorsmi}.
      PACKED_SMI_ELEMENTS, HOLEY_SMI_ELEMENTS, PACKED_ELEMENTS, HOLEY_ELEMENTS,
      PACKED_NONEXTENSIBLE_ELEMENTS, PACKED_SEALED_ELEMENTS,
      HOLEY_NONEXTENSIBLE_ELEMENTS, HOLEY_SEALED_ELEMENTS,
      PACKED_FROZEN_ELEMENTS, HOLEY_FROZEN_ELEMENTS,
      // Handled by {if_isdouble}.
      PACKED_DOUBLE_ELEMENTS, HOLEY_DOUBLE_ELEMENTS,
      // Handled by {if_isdictionary}.
      DICTIONARY_ELEMENTS,
      // Handled by {if_isfaststringwrapper}.
      FAST_STRING_WRAPPER_ELEMENTS,
      // Handled by {if_isslowstringwrapper}.
      SLOW_STRING_WRAPPER_ELEMENTS,
      // Handled by {if_not_found}.
      NO_ELEMENTS,
      // Handled by {if_typed_array}.
      UINT8_ELEMENTS,
      INT8_ELEMENTS,
      UINT16_ELEMENTS,
      INT16_ELEMENTS,
      UINT32_ELEMENTS,
      INT32_ELEMENTS,
      FLOAT32_ELEMENTS,
      FLOAT64_ELEMENTS,
      UINT8_CLAMPED_ELEMENTS,
      BIGUINT64_ELEMENTS,
      BIGINT64_ELEMENTS,
      RAB_GSAB_UINT8_ELEMENTS,
      RAB_GSAB_INT8_ELEMENTS,
      RAB_GSAB_UINT16_ELEMENTS,
      RAB_GSAB_INT16_ELEMENTS,
      RAB_GSAB_UINT32_ELEMENTS,
      RAB_GSAB_INT32_ELEMENTS,
      RAB_GSAB_FLOAT32_ELEMENTS,
      RAB_GSAB_FLOAT64_ELEMENTS,
      RAB_GSAB_UINT8_CLAMPED_ELEMENTS,
      RAB_GSAB_BIGUINT64_ELEMENTS,
      RAB_GSAB_BIGINT64_ELEMENTS,
  };
  Label* labels[] = {
      &if_isobjectorsmi, &if_isobjectorsmi, &if_isobjectorsmi,
      &if_isobjectorsmi, &if_isobjectorsmi, &if_isobjectorsmi,
      &if_isobjectorsmi, &if_isobjectorsmi, &if_isobjectorsmi,
      &if_isobjectorsmi,
      &if_isdouble, &if_isdouble,
      &if_isdictionary,
      &if_isfaststringwrapper,
      &if_isslowstringwrapper,
      if_not_found,
      &if_typedarray,
      &if_typedarray,
      &if_typedarray,
      &if_typedarray,
      &if_typedarray,
      &if_typedarray,
      &if_typedarray,
      &if_typedarray,
      &if_typedarray,
      &if_typedarray,
      &if_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
  };
  // clang-format on
  static_assert(arraysize(values) == arraysize(labels));
  Switch(elements_kind, if_bailout, values, labels, arraysize(values));

  BIND(&if_isobjectorsmi);
  {
    TNode<FixedArray> elements = CAST(LoadElements(CAST(object)));
    TNode<IntPtrT> length = LoadAndUntagFixedArrayBaseLength(elements);

    GotoIfNot(UintPtrLessThan(intptr_index, length), &if_oob);

    TNode<Object> element = UnsafeLoadFixedArrayElement(elements, intptr_index);
    TNode<Hole> the_hole = TheHoleConstant();
    Branch(TaggedEqual(element, the_hole), if_not_found, if_found);
  }
  BIND(&if_isdouble);
  {
    TNode<FixedArrayBase> elements = LoadElements(CAST(object));
    TNode<IntPtrT> length = LoadAndUntagFixedArrayBaseLength(elements);

    GotoIfNot(UintPtrLessThan(intptr_index, length), &if_oob);

    // Check if the element is a double hole, but don't load it.
    LoadFixedDoubleArrayElement(CAST(elements), intptr_index, if_not_found,
                                MachineType::None());
    Goto(if_found);
  }
  BIND(&if_isdictionary);
  {
    // Negative and too-large keys must be converted to property names.
    if (Is64()) {
      GotoIf(UintPtrLessThan(IntPtrConstant(JSObject::kMaxElementIndex),
                             intptr_index),
             if_bailout);
    } else {
      GotoIf(IntPtrLessThan(intptr_index, IntPtrConstant(0)), if_bailout);
    }

    TVARIABLE(IntPtrT, var_entry);
    TNode<NumberDictionary> elements = CAST(LoadElements(CAST(object)));
    NumberDictionaryLookup(elements, intptr_index, if_found, &var_entry,
                           if_not_found);
  }
  BIND(&if_isfaststringwrapper);
  {
    TNode<String> string = CAST(LoadJSPrimitiveWrapperValue(CAST(object)));
    TNode<IntPtrT> length = LoadStringLengthAsWord(string);
    GotoIf(UintPtrLessThan(intptr_index, length), if_found);
    Goto(&if_isobjectorsmi);
  }
  BIND(&if_isslowstringwrapper);
  {
    TNode<String> string = CAST(LoadJSPrimitiveWrapperValue(CAST(object)));
    TNode<IntPtrT> length = LoadStringLengthAsWord(string);
    GotoIf(UintPtrLessThan(intptr_index, length), if_found);
    Goto(&if_isdictionary);
  }
  BIND(&if_typedarray);
  {
    TNode<JSArrayBuffer> buffer = LoadJSArrayBufferViewBuffer(CAST(object));
    GotoIf(IsDetachedBuffer(buffer), if_absent);

    TNode<UintPtrT> length = LoadJSTypedArrayLength(CAST(object));
    Branch(UintPtrLessThan(intptr_index, length), if_found, if_absent);
  }
  BIND(&if_rab_gsab_typedarray);
  {
    TNode<JSArrayBuffer> buffer = LoadJSArrayBufferViewBuffer(CAST(object));
    TNode<UintPtrT> length =
        LoadVariableLengthJSTypedArrayLength(CAST(object), buffer, if_absent);
    Branch(UintPtrLessThan(intptr_index, length), if_found, if_absent);
  }
  BIND(&if_oob);
  {
    // Positive OOB indices mean "not found", negative indices and indices
    // out of array index range must be converted to property names.
    if (Is64()) {
      GotoIf(UintPtrLessThan(IntPtrConstant(JSObject::kMaxElementIndex),
                             intptr_index),
             if_bailout);
    } else {
      GotoIf(IntPtrLessThan(intptr_index, IntPtrConstant(0)), if_bailout);
    }
    Goto(if_not_found);
  }
}

void CodeStubAssembler::BranchIfMaybeSpecialIndex(TNode<String> name_string,
                                                  Label* if_maybe_special_index,
                                                  Label* if_not_special_index) {
  // TODO(cwhan.tunz): Implement fast cases more.

  // If a name is empty or too long, it's not a special index
  // Max length of canonical double: -X.XXXXXXXXXXXXXXXXX-eXXX
  const int kBufferSize = 24;
  TNode<Smi> string_length = LoadStringLengthAsSmi(name_string);
  GotoIf(SmiEqual(string_length, SmiConstant(0)), if_not_special_index);
  GotoIf(SmiGreaterThan(string_length, SmiConstant(kBufferSize)),
         if_not_special_index);

  // If the first character of name is not a digit or '-', or we can't match it
  // to Infinity or NaN, then this is not a special index.
  TNode<Int32T> first_char = StringCharCodeAt(name_string, UintPtrConstant(0));
  // If the name starts with '-', it can be a negative index.
  GotoIf(Word32Equal(first_char, Int32Constant('-')), if_maybe_special_index);
  // If the name starts with 'I', it can be "Infinity".
  GotoIf(Word32Equal(first_char, Int32Constant('I')), if_maybe_special_index);
  // If the name starts with 'N', it can be "NaN".
  GotoIf(Word32Equal(first_char, Int32Constant('N')), if_maybe_special_index);
  // Finally, if the first character is not a digit either, then we are sure
  // that the name is not a special index.
  GotoIf(Uint32LessThan(first_char, Int32Constant('0')), if_not_special_index);
  GotoIf(Uint32LessThan(Int32Constant('9'), first_char), if_not_special_index);
  Goto(if_maybe_special_index);
}

void CodeStubAssembler::TryPrototypeChainLookup(
    TNode<Object> receiver, TNode<Object> object_arg, TNode<Object> key,
    const LookupPropertyInHolder& lookup_property_in_holder,
    const LookupElementInHolder& lookup_element_in_holder, Label* if_end,
    Label* if_bailout, Label* if_proxy, bool handle_private_names) {
  // Ensure receiver is JSReceiver, otherwise bailout.
  GotoIf(TaggedIsSmi(receiver), if_bailout);
  TNode<HeapObject> object = CAST(object_arg);

  TNode<Map> map = LoadMap(object);
  TNode<Uint16T> instance_type = LoadMapInstanceType(map);
  {
    Label if_objectisreceiver(this);
    Branch(IsJSReceiverInstanceType(instance_type), &if_objectisreceiver,
           if_bailout);
    BIND(&if_objectisreceiver);

    GotoIf(InstanceTypeEqual(instance_type, JS_PROXY_TYPE), if_proxy);
  }

  TVARIABLE(IntPtrT, var_index);
  TVARIABLE(Name, var_unique);

  Label if_keyisindex(this), if_iskeyunique(this);
  TryToName(key, &if_keyisindex, &var_index, &if_iskeyunique, &var_unique,
            if_bailout);

  BIND(&if_iskeyunique);
  {
    TVARIABLE(HeapObject, var_holder, object);
    TVARIABLE(Map, var_holder_map, map);
    TVARIABLE(Int32T, var_holder_instance_type, instance_type);

    Label loop(this, {&var_holder, &var_holder_map, &var_holder_instance_type});
    Goto(&loop);
    BIND(&loop);
    {
      TNode<Map> holder_map = var_holder_map.value();
      TNode<Int32T> holder_instance_type = var_holder_instance_type.value();

      Label next_proto(this), check_integer_indexed_exotic(this);
      lookup_property_in_holder(CAST(receiver), var_holder.value(), holder_map,
                                holder_instance_type, var_unique.value(),
                                &check_integer_indexed_exotic, if_bailout);

      BIND(&check_integer_indexed_exotic);
      {
        // Bailout if it can be an integer indexed exotic case.
        GotoIfNot(InstanceTypeEqual(holder_instance_type, JS_TYPED_ARRAY_TYPE),
                  &next_proto);
        GotoIfNot(IsString(var_unique.value()), &next_proto);
        BranchIfMaybeSpecialIndex(CAST(var_unique.value()), if_bailout,
                                  &next_proto);
      }

      BIND(&next_proto);

      if (handle_private_names) {
        // Private name lookup doesn't walk the prototype chain.
        GotoIf(IsPrivateSymbol(CAST(key)), if_end);
      }

      TNode<HeapObject> proto = LoadMapPrototype(holder_map);

      GotoIf(IsNull(proto), if_end);

      TNode<Map> proto_map = LoadMap(proto);
      TNode<Uint16T> proto_instance_type = LoadMapInstanceType(proto_map);

      var_holder = proto;
      var_holder_map = proto_map;
      var_holder_instance_type = proto_instance_type;
      Goto(&loop);
    }
  }
  BIND(&if_keyisindex);
  {
    TVARIABLE(HeapObject, var_holder, object);
    TVARIABLE(Map, var_holder_map, map);
    TVARIABLE(Int32T, var_holder_instance_type, instance_type);

    Label loop(this, {&var_holder, &var_holder_map, &var_holder_instance_type});
    Goto(&loop);
    BIND(&loop);
    {
      Label next_proto(this);
      lookup_element_in_holder(CAST(receiver), var_holder.value(),
                               var_holder_map.value(),
                               var_holder_instance_type.value(),
                               var_index.value(), &next_proto, if_bailout);
      BIND(&next_proto);

      TNode<HeapObject> proto = LoadMapPrototype(var_holder_map.value());

      GotoIf(IsNull(proto), if_end);

      TNode<Map> proto_map = LoadMap(proto);
      TNode<Uint16T> proto_instance_type = LoadMapInstanceType(proto_map);

      var_holder = proto;
      var_holder_map = proto_map;
      var_holder_instance_type = proto_instance_type;
      Goto(&loop);
    }
  }
}

TNode<Boolean> CodeStubAssembler::HasInPrototypeChain(TNode<Context> context,
                                                      TNode<HeapObject> object,
                                                      TNode<Object> prototype) {
  TVARIABLE(Boolean, var_result);
  Label return_false(this), return_true(this),
      return_runtime(this, Label::kDeferred), return_result(this);

  // Loop through the prototype chain looking for the {prototype}.
  TVARIABLE(Map, var_object_map, LoadMap(object));
  Label loop(this, &var_object_map);
  Goto(&loop);
  BIND(&loop);
  {
    // Check if we can determine the prototype directly from the {object_map}.
    Label if_objectisdirect(this), if_objectisspecial(this, Label::kDeferred);
    TNode<Map> object_map = var_object_map.value();
    TNode<Uint16T> object_instance_type = LoadMapInstanceType(object_map);
    Branch(IsSpecialReceiverInstanceType(object_instance_type),
           &if_objectisspecial, &if_objectisdirect);
    BIND(&if_objectisspecial);
    {
      // The {object_map} is a special receiver map or a primitive map, check
      // if we need to use the if_objectisspecial path in the runtime.
      GotoIf(InstanceTypeEqual(object_instance_type, JS_PROXY_TYPE),
             &return_runtime);
      TNode<Int32T> object_bitfield = LoadMapBitField(object_map);
      int mask = Map::Bits1::HasNamedInterceptorBit::kMask |
                 Map::Bits1::IsAccessCheckNeededBit::kMask;
      Branch(IsSetWord32(object_bitfield, mask), &return_runtime,
             &if_objectisdirect);
    }
    BIND(&if_objectisdirect);

    // Check the current {object} prototype.
    TNode<HeapObject> object_prototype = LoadMapPrototype(object_map);
    GotoIf(IsNull(object_prototype), &return_false);
    GotoIf(TaggedEqual(object_prototype, prototype), &return_true);

    // Continue with the prototype.
    CSA_DCHECK(this, TaggedIsNotSmi(object_prototype));
    var_object_map = LoadMap(object_prototype);
    Goto(&loop);
  }

  BIND(&return_true);
  var_result = TrueConstant();
  Goto(&return_result);

  BIND(&return_false);
  var_result = FalseConstant();
  Goto(&return_result);

  BIND(&return_runtime);
  {
    // Fallback to the runtime implementation.
    var_result = CAST(
        CallRuntime(Runtime::kHasInPrototypeChain, context, object, prototype));
  }
  Goto(&return_result);

  BIND(&return_result);
  return var_result.value();
}

TNode<Boolean> CodeStubAssembler::OrdinaryHasInstance(
    TNode<Context> context, TNode<Object> callable_maybe_smi,
    TNode<Object> object_maybe_smi) {
  TVARIABLE(Boolean, var_result);
  Label return_runtime(this, Label::kDeferred), return_result(this);

  GotoIfForceSlowPath(&return_runtime);

  // Goto runtime if {object} is a Smi.
  GotoIf(TaggedIsSmi(object_maybe_smi), &return_runtime);

  // Goto runtime if {callable} is a Smi.
  GotoIf(TaggedIsSmi(callable_maybe_smi), &return_runtime);

  {
    // Load map of {callable}.
    TNode<HeapObject> object = CAST(object_maybe_smi);
    TNode<HeapObject> callable = CAST(callable_maybe_smi);
    TNode<Map> callable_map = LoadMap(callable);

    // Goto runtime if {callable} is not a JSFunction.
    TNode<Uint16T> callable_instance_type = LoadMapInstanceType(callable_map);
    GotoIfNot(IsJSFunctionInstanceType(callable_instance_type),
              &return_runtime);

    GotoIfPrototypeRequiresRuntimeLookup(CAST(callable), callable_map,
                                         &return_runtime);

    // Get the "prototype" (or initial map) of the {callable}.
    TNode<HeapObject> callable_prototype = LoadObjectField<HeapObject>(
        callable, JSFunction::kPrototypeOrInitialMapOffset);
    {
      Label no_initial_map(this), walk_prototype_chain(this);
      TVARIABLE(HeapObject, var_callable_prototype, callable_prototype);

      // Resolve the "prototype" if the {callable} has an initial map.
      GotoIfNot(IsMap(callable_prototype), &no_initial_map);
      var_callable_prototype = LoadObjectField<HeapObject>(
          callable_prototype, Map::kPrototypeOffset);
      Goto(&walk_prototype_chain);

      BIND(&no_initial_map);
      // {callable_prototype} is the hole if the "prototype" property hasn't
      // been requested so far.
      Branch(TaggedEqual(callable_prototype, TheHoleConstant()),
             &return_runtime, &walk_prototype_chain);

      BIND(&walk_prototype_chain);
      callable_prototype = var_callable_prototype.value();
    }

    // Loop through the prototype chain looking for the {callable} prototype.
    var_result = HasInPrototypeChain(context, object, callable_prototype);
    Goto(&return_result);
  }

  BIND(&return_runtime);
  {
    // Fallback to the runtime implementation.
    var_result = CAST(CallRuntime(Runtime::kOrdinaryHasInstance, context,
                                  callable_maybe_smi, object_maybe_smi));
  }
  Goto(&return_result);

  BIND(&return_result);
  return var_result.value();
}

template <typename TIndex>
TNode<IntPtrT> CodeStubAssembler::ElementOffsetFromIndex(
    TNode<TIndex> index_node, ElementsKind kind, int base_size) {
  // TODO(v8:9708): Remove IntPtrT variant in favor of UintPtrT.
  static_assert(std::is_same<TIndex, Smi>::value ||
                    std::is_same<TIndex, TaggedIndex>::value ||
                    std::is_same<TIndex, IntPtrT>::value ||
                    std::is_same<TIndex, UintPtrT>::value,
                "Only Smi, UintPtrT or IntPtrT index nodes are allowed");
  int element_size_shift = ElementsKindToShiftSize(kind);
  int element_size = 1 << element_size_shift;
  intptr_t index = 0;
  TNode<IntPtrT> intptr_index_node;
  bool constant_index = false;
  if (std::is_same<TIndex, Smi>::value) {
    TNode<Smi> smi_index_node = ReinterpretCast<Smi>(index_node);
    int const kSmiShiftBits = kSmiShiftSize + kSmiTagSize;
    element_size_shift -= kSmiShiftBits;
    Tagged<Smi> smi_index;
    constant_index = TryToSmiConstant(smi_index_node, &smi_index);
    if (constant_index) {
      index = smi_index.value();
    } else {
      if (COMPRESS_POINTERS_BOOL) {
        smi_index_node = NormalizeSmiIndex(smi_index_node);
      }
    }
    intptr_index_node = BitcastTaggedToWordForTagAndSmiBits(smi_index_node);
  } else if (std::is_same<TIndex, TaggedIndex>::value) {
    TNode<TaggedIndex> tagged_index_node =
        ReinterpretCast<TaggedIndex>(index_node);
    element_size_shift -= kSmiTagSize;
    intptr_index_node = BitcastTaggedToWordForTagAndSmiBits(tagged_index_node);
    constant_index = TryToIntPtrConstant(intptr_index_node, &index);
  } else {
    intptr_index_node = ReinterpretCast<IntPtrT>(index_node);
    constant_index = TryToIntPtrConstant(intptr_index_node, &index);
  }
  if (constant_index) {
    return IntPtrConstant(base_size + element_size * index);
  }

  TNode<IntPtrT> shifted_index =
      (element_size_shift == 0)
          ? intptr_index_node
          : ((element_size_shift > 0)
                 ? WordShl(intptr_index_node,
                           IntPtrConstant(element_size_shift))
                 : WordSar(intptr_index_node,
                           IntPtrConstant(-element_size_shift)));
  return IntPtrAdd(IntPtrConstant(base_size), Signed(shifted_index));
}

// Instantiate ElementOffsetFromIndex for Smi and IntPtrT.
template V8_EXPORT_PRIVATE TNode<IntPtrT>
CodeStubAssembler::ElementOffsetFromIndex<Smi>(TNode<Smi> index_node,
                                               ElementsKind kind,
                                               int base_size);
template V8_EXPORT_PRIVATE TNode<IntPtrT>
CodeStubAssembler::ElementOffsetFromIndex<TaggedIndex>(
    TNode<TaggedIndex> index_node, ElementsKind kind, int base_size);
template V8_EXPORT_PRIVATE TNode<IntPtrT>
CodeStubAssembler::ElementOffsetFromIndex<IntPtrT>(TNode<IntPtrT> index_node,
                                                   ElementsKind kind,
                                                   int base_size);

TNode<BoolT> CodeStubAssembler::IsOffsetInBounds(TNode<IntPtrT> offset,
                                                 TNode<IntPtrT> length,
                                                 int header_size,
                                                 ElementsKind kind) {
  // Make sure we point to the last field.
  int element_size = 1 << ElementsKindToShiftSize(kind);
  int correction = header_size - kHeapObjectTag - element_size;
  TNode<IntPtrT> last_offset = ElementOffsetFromIndex(length, kind, correction);
  return IntPtrLessThanOrEqual(offset, last_offset);
}

TNode<HeapObject> CodeStubAssembler::LoadFeedbackCellValue(
    TNode<JSFunction> closure) {
  TNode<FeedbackCell> feedback_cell =
      LoadObjectField<FeedbackCell>(closure, JSFunction::kFeedbackCellOffset);
  return LoadObjectField<HeapObject>(feedback_cell, FeedbackCell::kValueOffset);
}

TNode<HeapObject> CodeStubAssembler::LoadFeedbackVector(
    TNode<JSFunction> closure) {
  TVARIABLE(HeapObject, maybe_vector);
  Label if_no_feedback_vector(this), out(this);

  maybe_vector = LoadFeedbackVector(closure, &if_no_feedback_vector);
  Goto(&out);

  BIND(&if_no_feedback_vector);
  // If the closure doesn't have a feedback vector allocated yet, return
  // undefined. The FeedbackCell can contain Undefined / FixedArray (for lazy
  // allocations) / FeedbackVector.
  maybe_vector = UndefinedConstant();
  Goto(&out);

  BIND(&out);
  return maybe_vector.value();
}

TNode<FeedbackVector> CodeStubAssembler::LoadFeedbackVector(
    TNode<JSFunction> closure, Label* if_no_feedback_vector) {
  TNode<HeapObject> maybe_vector = LoadFeedbackCellValue(closure);
  GotoIfNot(IsFeedbackVector(maybe_vector), if_no_feedback_vector);
  return CAST(maybe_vector);
}

TNode<ClosureFeedbackCellArray> CodeStubAssembler::LoadClosureFeedbackArray(
    TNode<JSFunction> closure) {
  TVARIABLE(HeapObject, feedback_cell_array, LoadFeedbackCellValue(closure));
  Label end(this);

  // When feedback vectors are not yet allocated feedback cell contains
  // an array of feedback cells used by create closures.
  GotoIf(HasInstanceType(feedback_cell_array.value(),
                         CLOSURE_FEEDBACK_CELL_ARRAY_TYPE),
         &
Prompt: 
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/code-stub-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第15部分，共23部分，请归纳一下它的功能

"""
E_SWISS_NAME_DICTIONARY_BOOL) {
        TNode<Smi> flags =
            GetNameDictionaryFlags<NameDictionary>(CAST(properties));
        GotoIf(IsSetSmi(flags,
                        NameDictionary::MayHaveInterestingPropertiesBit::kMask),
               &lookup);
        *var_holder = LoadMapPrototype(holder_map);
        *var_holder_map = LoadMap((*var_holder).value());
      }
      Goto(&loop);
    }
  }

  BIND(&lookup);
  return CallBuiltin(Builtin::kGetPropertyWithReceiver, context,
                     (*var_holder).value(), name, receiver,
                     SmiConstant(OnNonExistent::kReturnUndefined));
}

void CodeStubAssembler::TryLookupElement(
    TNode<HeapObject> object, TNode<Map> map, TNode<Int32T> instance_type,
    TNode<IntPtrT> intptr_index, Label* if_found, Label* if_absent,
    Label* if_not_found, Label* if_bailout) {
  // Handle special objects in runtime.
  GotoIf(IsSpecialReceiverInstanceType(instance_type), if_bailout);

  TNode<Int32T> elements_kind = LoadMapElementsKind(map);

  // TODO(verwaest): Support other elements kinds as well.
  Label if_isobjectorsmi(this), if_isdouble(this), if_isdictionary(this),
      if_isfaststringwrapper(this), if_isslowstringwrapper(this), if_oob(this),
      if_typedarray(this), if_rab_gsab_typedarray(this);
  // clang-format off
  int32_t values[] = {
      // Handled by {if_isobjectorsmi}.
      PACKED_SMI_ELEMENTS, HOLEY_SMI_ELEMENTS, PACKED_ELEMENTS, HOLEY_ELEMENTS,
      PACKED_NONEXTENSIBLE_ELEMENTS, PACKED_SEALED_ELEMENTS,
      HOLEY_NONEXTENSIBLE_ELEMENTS, HOLEY_SEALED_ELEMENTS,
      PACKED_FROZEN_ELEMENTS, HOLEY_FROZEN_ELEMENTS,
      // Handled by {if_isdouble}.
      PACKED_DOUBLE_ELEMENTS, HOLEY_DOUBLE_ELEMENTS,
      // Handled by {if_isdictionary}.
      DICTIONARY_ELEMENTS,
      // Handled by {if_isfaststringwrapper}.
      FAST_STRING_WRAPPER_ELEMENTS,
      // Handled by {if_isslowstringwrapper}.
      SLOW_STRING_WRAPPER_ELEMENTS,
      // Handled by {if_not_found}.
      NO_ELEMENTS,
      // Handled by {if_typed_array}.
      UINT8_ELEMENTS,
      INT8_ELEMENTS,
      UINT16_ELEMENTS,
      INT16_ELEMENTS,
      UINT32_ELEMENTS,
      INT32_ELEMENTS,
      FLOAT32_ELEMENTS,
      FLOAT64_ELEMENTS,
      UINT8_CLAMPED_ELEMENTS,
      BIGUINT64_ELEMENTS,
      BIGINT64_ELEMENTS,
      RAB_GSAB_UINT8_ELEMENTS,
      RAB_GSAB_INT8_ELEMENTS,
      RAB_GSAB_UINT16_ELEMENTS,
      RAB_GSAB_INT16_ELEMENTS,
      RAB_GSAB_UINT32_ELEMENTS,
      RAB_GSAB_INT32_ELEMENTS,
      RAB_GSAB_FLOAT32_ELEMENTS,
      RAB_GSAB_FLOAT64_ELEMENTS,
      RAB_GSAB_UINT8_CLAMPED_ELEMENTS,
      RAB_GSAB_BIGUINT64_ELEMENTS,
      RAB_GSAB_BIGINT64_ELEMENTS,
  };
  Label* labels[] = {
      &if_isobjectorsmi, &if_isobjectorsmi, &if_isobjectorsmi,
      &if_isobjectorsmi, &if_isobjectorsmi, &if_isobjectorsmi,
      &if_isobjectorsmi, &if_isobjectorsmi, &if_isobjectorsmi,
      &if_isobjectorsmi,
      &if_isdouble, &if_isdouble,
      &if_isdictionary,
      &if_isfaststringwrapper,
      &if_isslowstringwrapper,
      if_not_found,
      &if_typedarray,
      &if_typedarray,
      &if_typedarray,
      &if_typedarray,
      &if_typedarray,
      &if_typedarray,
      &if_typedarray,
      &if_typedarray,
      &if_typedarray,
      &if_typedarray,
      &if_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
  };
  // clang-format on
  static_assert(arraysize(values) == arraysize(labels));
  Switch(elements_kind, if_bailout, values, labels, arraysize(values));

  BIND(&if_isobjectorsmi);
  {
    TNode<FixedArray> elements = CAST(LoadElements(CAST(object)));
    TNode<IntPtrT> length = LoadAndUntagFixedArrayBaseLength(elements);

    GotoIfNot(UintPtrLessThan(intptr_index, length), &if_oob);

    TNode<Object> element = UnsafeLoadFixedArrayElement(elements, intptr_index);
    TNode<Hole> the_hole = TheHoleConstant();
    Branch(TaggedEqual(element, the_hole), if_not_found, if_found);
  }
  BIND(&if_isdouble);
  {
    TNode<FixedArrayBase> elements = LoadElements(CAST(object));
    TNode<IntPtrT> length = LoadAndUntagFixedArrayBaseLength(elements);

    GotoIfNot(UintPtrLessThan(intptr_index, length), &if_oob);

    // Check if the element is a double hole, but don't load it.
    LoadFixedDoubleArrayElement(CAST(elements), intptr_index, if_not_found,
                                MachineType::None());
    Goto(if_found);
  }
  BIND(&if_isdictionary);
  {
    // Negative and too-large keys must be converted to property names.
    if (Is64()) {
      GotoIf(UintPtrLessThan(IntPtrConstant(JSObject::kMaxElementIndex),
                             intptr_index),
             if_bailout);
    } else {
      GotoIf(IntPtrLessThan(intptr_index, IntPtrConstant(0)), if_bailout);
    }

    TVARIABLE(IntPtrT, var_entry);
    TNode<NumberDictionary> elements = CAST(LoadElements(CAST(object)));
    NumberDictionaryLookup(elements, intptr_index, if_found, &var_entry,
                           if_not_found);
  }
  BIND(&if_isfaststringwrapper);
  {
    TNode<String> string = CAST(LoadJSPrimitiveWrapperValue(CAST(object)));
    TNode<IntPtrT> length = LoadStringLengthAsWord(string);
    GotoIf(UintPtrLessThan(intptr_index, length), if_found);
    Goto(&if_isobjectorsmi);
  }
  BIND(&if_isslowstringwrapper);
  {
    TNode<String> string = CAST(LoadJSPrimitiveWrapperValue(CAST(object)));
    TNode<IntPtrT> length = LoadStringLengthAsWord(string);
    GotoIf(UintPtrLessThan(intptr_index, length), if_found);
    Goto(&if_isdictionary);
  }
  BIND(&if_typedarray);
  {
    TNode<JSArrayBuffer> buffer = LoadJSArrayBufferViewBuffer(CAST(object));
    GotoIf(IsDetachedBuffer(buffer), if_absent);

    TNode<UintPtrT> length = LoadJSTypedArrayLength(CAST(object));
    Branch(UintPtrLessThan(intptr_index, length), if_found, if_absent);
  }
  BIND(&if_rab_gsab_typedarray);
  {
    TNode<JSArrayBuffer> buffer = LoadJSArrayBufferViewBuffer(CAST(object));
    TNode<UintPtrT> length =
        LoadVariableLengthJSTypedArrayLength(CAST(object), buffer, if_absent);
    Branch(UintPtrLessThan(intptr_index, length), if_found, if_absent);
  }
  BIND(&if_oob);
  {
    // Positive OOB indices mean "not found", negative indices and indices
    // out of array index range must be converted to property names.
    if (Is64()) {
      GotoIf(UintPtrLessThan(IntPtrConstant(JSObject::kMaxElementIndex),
                             intptr_index),
             if_bailout);
    } else {
      GotoIf(IntPtrLessThan(intptr_index, IntPtrConstant(0)), if_bailout);
    }
    Goto(if_not_found);
  }
}

void CodeStubAssembler::BranchIfMaybeSpecialIndex(TNode<String> name_string,
                                                  Label* if_maybe_special_index,
                                                  Label* if_not_special_index) {
  // TODO(cwhan.tunz): Implement fast cases more.

  // If a name is empty or too long, it's not a special index
  // Max length of canonical double: -X.XXXXXXXXXXXXXXXXX-eXXX
  const int kBufferSize = 24;
  TNode<Smi> string_length = LoadStringLengthAsSmi(name_string);
  GotoIf(SmiEqual(string_length, SmiConstant(0)), if_not_special_index);
  GotoIf(SmiGreaterThan(string_length, SmiConstant(kBufferSize)),
         if_not_special_index);

  // If the first character of name is not a digit or '-', or we can't match it
  // to Infinity or NaN, then this is not a special index.
  TNode<Int32T> first_char = StringCharCodeAt(name_string, UintPtrConstant(0));
  // If the name starts with '-', it can be a negative index.
  GotoIf(Word32Equal(first_char, Int32Constant('-')), if_maybe_special_index);
  // If the name starts with 'I', it can be "Infinity".
  GotoIf(Word32Equal(first_char, Int32Constant('I')), if_maybe_special_index);
  // If the name starts with 'N', it can be "NaN".
  GotoIf(Word32Equal(first_char, Int32Constant('N')), if_maybe_special_index);
  // Finally, if the first character is not a digit either, then we are sure
  // that the name is not a special index.
  GotoIf(Uint32LessThan(first_char, Int32Constant('0')), if_not_special_index);
  GotoIf(Uint32LessThan(Int32Constant('9'), first_char), if_not_special_index);
  Goto(if_maybe_special_index);
}

void CodeStubAssembler::TryPrototypeChainLookup(
    TNode<Object> receiver, TNode<Object> object_arg, TNode<Object> key,
    const LookupPropertyInHolder& lookup_property_in_holder,
    const LookupElementInHolder& lookup_element_in_holder, Label* if_end,
    Label* if_bailout, Label* if_proxy, bool handle_private_names) {
  // Ensure receiver is JSReceiver, otherwise bailout.
  GotoIf(TaggedIsSmi(receiver), if_bailout);
  TNode<HeapObject> object = CAST(object_arg);

  TNode<Map> map = LoadMap(object);
  TNode<Uint16T> instance_type = LoadMapInstanceType(map);
  {
    Label if_objectisreceiver(this);
    Branch(IsJSReceiverInstanceType(instance_type), &if_objectisreceiver,
           if_bailout);
    BIND(&if_objectisreceiver);

    GotoIf(InstanceTypeEqual(instance_type, JS_PROXY_TYPE), if_proxy);
  }

  TVARIABLE(IntPtrT, var_index);
  TVARIABLE(Name, var_unique);

  Label if_keyisindex(this), if_iskeyunique(this);
  TryToName(key, &if_keyisindex, &var_index, &if_iskeyunique, &var_unique,
            if_bailout);

  BIND(&if_iskeyunique);
  {
    TVARIABLE(HeapObject, var_holder, object);
    TVARIABLE(Map, var_holder_map, map);
    TVARIABLE(Int32T, var_holder_instance_type, instance_type);

    Label loop(this, {&var_holder, &var_holder_map, &var_holder_instance_type});
    Goto(&loop);
    BIND(&loop);
    {
      TNode<Map> holder_map = var_holder_map.value();
      TNode<Int32T> holder_instance_type = var_holder_instance_type.value();

      Label next_proto(this), check_integer_indexed_exotic(this);
      lookup_property_in_holder(CAST(receiver), var_holder.value(), holder_map,
                                holder_instance_type, var_unique.value(),
                                &check_integer_indexed_exotic, if_bailout);

      BIND(&check_integer_indexed_exotic);
      {
        // Bailout if it can be an integer indexed exotic case.
        GotoIfNot(InstanceTypeEqual(holder_instance_type, JS_TYPED_ARRAY_TYPE),
                  &next_proto);
        GotoIfNot(IsString(var_unique.value()), &next_proto);
        BranchIfMaybeSpecialIndex(CAST(var_unique.value()), if_bailout,
                                  &next_proto);
      }

      BIND(&next_proto);

      if (handle_private_names) {
        // Private name lookup doesn't walk the prototype chain.
        GotoIf(IsPrivateSymbol(CAST(key)), if_end);
      }

      TNode<HeapObject> proto = LoadMapPrototype(holder_map);

      GotoIf(IsNull(proto), if_end);

      TNode<Map> proto_map = LoadMap(proto);
      TNode<Uint16T> proto_instance_type = LoadMapInstanceType(proto_map);

      var_holder = proto;
      var_holder_map = proto_map;
      var_holder_instance_type = proto_instance_type;
      Goto(&loop);
    }
  }
  BIND(&if_keyisindex);
  {
    TVARIABLE(HeapObject, var_holder, object);
    TVARIABLE(Map, var_holder_map, map);
    TVARIABLE(Int32T, var_holder_instance_type, instance_type);

    Label loop(this, {&var_holder, &var_holder_map, &var_holder_instance_type});
    Goto(&loop);
    BIND(&loop);
    {
      Label next_proto(this);
      lookup_element_in_holder(CAST(receiver), var_holder.value(),
                               var_holder_map.value(),
                               var_holder_instance_type.value(),
                               var_index.value(), &next_proto, if_bailout);
      BIND(&next_proto);

      TNode<HeapObject> proto = LoadMapPrototype(var_holder_map.value());

      GotoIf(IsNull(proto), if_end);

      TNode<Map> proto_map = LoadMap(proto);
      TNode<Uint16T> proto_instance_type = LoadMapInstanceType(proto_map);

      var_holder = proto;
      var_holder_map = proto_map;
      var_holder_instance_type = proto_instance_type;
      Goto(&loop);
    }
  }
}

TNode<Boolean> CodeStubAssembler::HasInPrototypeChain(TNode<Context> context,
                                                      TNode<HeapObject> object,
                                                      TNode<Object> prototype) {
  TVARIABLE(Boolean, var_result);
  Label return_false(this), return_true(this),
      return_runtime(this, Label::kDeferred), return_result(this);

  // Loop through the prototype chain looking for the {prototype}.
  TVARIABLE(Map, var_object_map, LoadMap(object));
  Label loop(this, &var_object_map);
  Goto(&loop);
  BIND(&loop);
  {
    // Check if we can determine the prototype directly from the {object_map}.
    Label if_objectisdirect(this), if_objectisspecial(this, Label::kDeferred);
    TNode<Map> object_map = var_object_map.value();
    TNode<Uint16T> object_instance_type = LoadMapInstanceType(object_map);
    Branch(IsSpecialReceiverInstanceType(object_instance_type),
           &if_objectisspecial, &if_objectisdirect);
    BIND(&if_objectisspecial);
    {
      // The {object_map} is a special receiver map or a primitive map, check
      // if we need to use the if_objectisspecial path in the runtime.
      GotoIf(InstanceTypeEqual(object_instance_type, JS_PROXY_TYPE),
             &return_runtime);
      TNode<Int32T> object_bitfield = LoadMapBitField(object_map);
      int mask = Map::Bits1::HasNamedInterceptorBit::kMask |
                 Map::Bits1::IsAccessCheckNeededBit::kMask;
      Branch(IsSetWord32(object_bitfield, mask), &return_runtime,
             &if_objectisdirect);
    }
    BIND(&if_objectisdirect);

    // Check the current {object} prototype.
    TNode<HeapObject> object_prototype = LoadMapPrototype(object_map);
    GotoIf(IsNull(object_prototype), &return_false);
    GotoIf(TaggedEqual(object_prototype, prototype), &return_true);

    // Continue with the prototype.
    CSA_DCHECK(this, TaggedIsNotSmi(object_prototype));
    var_object_map = LoadMap(object_prototype);
    Goto(&loop);
  }

  BIND(&return_true);
  var_result = TrueConstant();
  Goto(&return_result);

  BIND(&return_false);
  var_result = FalseConstant();
  Goto(&return_result);

  BIND(&return_runtime);
  {
    // Fallback to the runtime implementation.
    var_result = CAST(
        CallRuntime(Runtime::kHasInPrototypeChain, context, object, prototype));
  }
  Goto(&return_result);

  BIND(&return_result);
  return var_result.value();
}

TNode<Boolean> CodeStubAssembler::OrdinaryHasInstance(
    TNode<Context> context, TNode<Object> callable_maybe_smi,
    TNode<Object> object_maybe_smi) {
  TVARIABLE(Boolean, var_result);
  Label return_runtime(this, Label::kDeferred), return_result(this);

  GotoIfForceSlowPath(&return_runtime);

  // Goto runtime if {object} is a Smi.
  GotoIf(TaggedIsSmi(object_maybe_smi), &return_runtime);

  // Goto runtime if {callable} is a Smi.
  GotoIf(TaggedIsSmi(callable_maybe_smi), &return_runtime);

  {
    // Load map of {callable}.
    TNode<HeapObject> object = CAST(object_maybe_smi);
    TNode<HeapObject> callable = CAST(callable_maybe_smi);
    TNode<Map> callable_map = LoadMap(callable);

    // Goto runtime if {callable} is not a JSFunction.
    TNode<Uint16T> callable_instance_type = LoadMapInstanceType(callable_map);
    GotoIfNot(IsJSFunctionInstanceType(callable_instance_type),
              &return_runtime);

    GotoIfPrototypeRequiresRuntimeLookup(CAST(callable), callable_map,
                                         &return_runtime);

    // Get the "prototype" (or initial map) of the {callable}.
    TNode<HeapObject> callable_prototype = LoadObjectField<HeapObject>(
        callable, JSFunction::kPrototypeOrInitialMapOffset);
    {
      Label no_initial_map(this), walk_prototype_chain(this);
      TVARIABLE(HeapObject, var_callable_prototype, callable_prototype);

      // Resolve the "prototype" if the {callable} has an initial map.
      GotoIfNot(IsMap(callable_prototype), &no_initial_map);
      var_callable_prototype = LoadObjectField<HeapObject>(
          callable_prototype, Map::kPrototypeOffset);
      Goto(&walk_prototype_chain);

      BIND(&no_initial_map);
      // {callable_prototype} is the hole if the "prototype" property hasn't
      // been requested so far.
      Branch(TaggedEqual(callable_prototype, TheHoleConstant()),
             &return_runtime, &walk_prototype_chain);

      BIND(&walk_prototype_chain);
      callable_prototype = var_callable_prototype.value();
    }

    // Loop through the prototype chain looking for the {callable} prototype.
    var_result = HasInPrototypeChain(context, object, callable_prototype);
    Goto(&return_result);
  }

  BIND(&return_runtime);
  {
    // Fallback to the runtime implementation.
    var_result = CAST(CallRuntime(Runtime::kOrdinaryHasInstance, context,
                                  callable_maybe_smi, object_maybe_smi));
  }
  Goto(&return_result);

  BIND(&return_result);
  return var_result.value();
}

template <typename TIndex>
TNode<IntPtrT> CodeStubAssembler::ElementOffsetFromIndex(
    TNode<TIndex> index_node, ElementsKind kind, int base_size) {
  // TODO(v8:9708): Remove IntPtrT variant in favor of UintPtrT.
  static_assert(std::is_same<TIndex, Smi>::value ||
                    std::is_same<TIndex, TaggedIndex>::value ||
                    std::is_same<TIndex, IntPtrT>::value ||
                    std::is_same<TIndex, UintPtrT>::value,
                "Only Smi, UintPtrT or IntPtrT index nodes are allowed");
  int element_size_shift = ElementsKindToShiftSize(kind);
  int element_size = 1 << element_size_shift;
  intptr_t index = 0;
  TNode<IntPtrT> intptr_index_node;
  bool constant_index = false;
  if (std::is_same<TIndex, Smi>::value) {
    TNode<Smi> smi_index_node = ReinterpretCast<Smi>(index_node);
    int const kSmiShiftBits = kSmiShiftSize + kSmiTagSize;
    element_size_shift -= kSmiShiftBits;
    Tagged<Smi> smi_index;
    constant_index = TryToSmiConstant(smi_index_node, &smi_index);
    if (constant_index) {
      index = smi_index.value();
    } else {
      if (COMPRESS_POINTERS_BOOL) {
        smi_index_node = NormalizeSmiIndex(smi_index_node);
      }
    }
    intptr_index_node = BitcastTaggedToWordForTagAndSmiBits(smi_index_node);
  } else if (std::is_same<TIndex, TaggedIndex>::value) {
    TNode<TaggedIndex> tagged_index_node =
        ReinterpretCast<TaggedIndex>(index_node);
    element_size_shift -= kSmiTagSize;
    intptr_index_node = BitcastTaggedToWordForTagAndSmiBits(tagged_index_node);
    constant_index = TryToIntPtrConstant(intptr_index_node, &index);
  } else {
    intptr_index_node = ReinterpretCast<IntPtrT>(index_node);
    constant_index = TryToIntPtrConstant(intptr_index_node, &index);
  }
  if (constant_index) {
    return IntPtrConstant(base_size + element_size * index);
  }

  TNode<IntPtrT> shifted_index =
      (element_size_shift == 0)
          ? intptr_index_node
          : ((element_size_shift > 0)
                 ? WordShl(intptr_index_node,
                           IntPtrConstant(element_size_shift))
                 : WordSar(intptr_index_node,
                           IntPtrConstant(-element_size_shift)));
  return IntPtrAdd(IntPtrConstant(base_size), Signed(shifted_index));
}

// Instantiate ElementOffsetFromIndex for Smi and IntPtrT.
template V8_EXPORT_PRIVATE TNode<IntPtrT>
CodeStubAssembler::ElementOffsetFromIndex<Smi>(TNode<Smi> index_node,
                                               ElementsKind kind,
                                               int base_size);
template V8_EXPORT_PRIVATE TNode<IntPtrT>
CodeStubAssembler::ElementOffsetFromIndex<TaggedIndex>(
    TNode<TaggedIndex> index_node, ElementsKind kind, int base_size);
template V8_EXPORT_PRIVATE TNode<IntPtrT>
CodeStubAssembler::ElementOffsetFromIndex<IntPtrT>(TNode<IntPtrT> index_node,
                                                   ElementsKind kind,
                                                   int base_size);

TNode<BoolT> CodeStubAssembler::IsOffsetInBounds(TNode<IntPtrT> offset,
                                                 TNode<IntPtrT> length,
                                                 int header_size,
                                                 ElementsKind kind) {
  // Make sure we point to the last field.
  int element_size = 1 << ElementsKindToShiftSize(kind);
  int correction = header_size - kHeapObjectTag - element_size;
  TNode<IntPtrT> last_offset = ElementOffsetFromIndex(length, kind, correction);
  return IntPtrLessThanOrEqual(offset, last_offset);
}

TNode<HeapObject> CodeStubAssembler::LoadFeedbackCellValue(
    TNode<JSFunction> closure) {
  TNode<FeedbackCell> feedback_cell =
      LoadObjectField<FeedbackCell>(closure, JSFunction::kFeedbackCellOffset);
  return LoadObjectField<HeapObject>(feedback_cell, FeedbackCell::kValueOffset);
}

TNode<HeapObject> CodeStubAssembler::LoadFeedbackVector(
    TNode<JSFunction> closure) {
  TVARIABLE(HeapObject, maybe_vector);
  Label if_no_feedback_vector(this), out(this);

  maybe_vector = LoadFeedbackVector(closure, &if_no_feedback_vector);
  Goto(&out);

  BIND(&if_no_feedback_vector);
  // If the closure doesn't have a feedback vector allocated yet, return
  // undefined. The FeedbackCell can contain Undefined / FixedArray (for lazy
  // allocations) / FeedbackVector.
  maybe_vector = UndefinedConstant();
  Goto(&out);

  BIND(&out);
  return maybe_vector.value();
}

TNode<FeedbackVector> CodeStubAssembler::LoadFeedbackVector(
    TNode<JSFunction> closure, Label* if_no_feedback_vector) {
  TNode<HeapObject> maybe_vector = LoadFeedbackCellValue(closure);
  GotoIfNot(IsFeedbackVector(maybe_vector), if_no_feedback_vector);
  return CAST(maybe_vector);
}

TNode<ClosureFeedbackCellArray> CodeStubAssembler::LoadClosureFeedbackArray(
    TNode<JSFunction> closure) {
  TVARIABLE(HeapObject, feedback_cell_array, LoadFeedbackCellValue(closure));
  Label end(this);

  // When feedback vectors are not yet allocated feedback cell contains
  // an array of feedback cells used by create closures.
  GotoIf(HasInstanceType(feedback_cell_array.value(),
                         CLOSURE_FEEDBACK_CELL_ARRAY_TYPE),
         &end);

  // Load FeedbackCellArray from feedback vector.
  TNode<FeedbackVector> vector = CAST(feedback_cell_array.value());
  feedback_cell_array = CAST(
      LoadObjectField(vector, FeedbackVector::kClosureFeedbackCellArrayOffset));
  Goto(&end);

  BIND(&end);
  return CAST(feedback_cell_array.value());
}

TNode<FeedbackVector> CodeStubAssembler::LoadFeedbackVectorForStub() {
  TNode<JSFunction> function =
      CAST(LoadFromParentFrame(StandardFrameConstants::kFunctionOffset));
  return CAST(LoadFeedbackVector(function));
}

TNode<BytecodeArray> CodeStubAssembler::LoadBytecodeArrayFromBaseline() {
  return CAST(
      LoadFromParentFrame(BaselineFrameConstants::kBytecodeArrayFromFp));
}

TNode<FeedbackVector> CodeStubAssembler::LoadFeedbackVectorFromBaseline() {
  return CAST(
      LoadFromParentFrame(BaselineFrameConstants::kFeedbackVectorFromFp));
}

TNode<Context> CodeStubAssembler::LoadContextFromBaseline() {
  return CAST(LoadFromParentFrame(InterpreterFrameConstants::kContextOffset));
}

TNode<FeedbackVector>
CodeStubAssembler::LoadFeedbackVectorForStubWithTrampoline() {
  TNode<RawPtrT> frame_pointer = LoadParentFramePointer();
  TNode<RawPtrT> parent_frame_pointer = Load<RawPtrT>(frame_pointer);
  TNode<JSFunction> function = CAST(
      LoadFullTagged(parent_frame_pointer,
                     IntPtrConstant(StandardFrameConstants::kFunctionOffset)));
  return CAST(LoadFeedbackVector(function));
}

void CodeStubAssembler::UpdateFeedback(TNode<Smi> feedback,
                                       TNode<HeapObject> maybe_feedback_vector,
                                       TNode<UintPtrT> slot_id,
                                       UpdateFeedbackMode mode) {
  switch (mode) {
    case UpdateFeedbackMode::kOptionalFeedback:
      MaybeUpdateFeedback(feedback, maybe_feedback_vector, slot_id);
      break;
    case UpdateFeedbackMode::kGuaranteedFeedback:
      CSA_DCHECK(this, IsFeedbackVector(maybe_feedback_vector));
      UpdateFeedback(feedback, CAST(maybe_feedback_vector), slot_id);
      break;
    case UpdateFeedbackMode::kNoFeedback:
#ifdef V8_JITLESS
      CSA_DCHECK(this, IsUndefined(maybe_feedback_vector));
      break;
#else
      UNREACHABLE();
#endif  // !V8_JITLESS
  }
}

void CodeStubAssembler::MaybeUpdateFeedback(TNode<Smi> feedback,
                                            TNode<HeapObject> maybe_vector,
                                            TNode<UintPtrT> slot_id) {
  Label end(this);
  GotoIf(IsUndefined(maybe_vector), &end);
  {
    UpdateFeedback(feedback, CAST(maybe_vector), slot_id);
    Goto(&end);
  }
  BIND(&end);
}

void CodeStubAssembler::UpdateFeedback(TNode<Smi> feedback,
                                       TNode<FeedbackVector> feedback_vector,
                                       TNode<UintPtrT> slot_id) {
  Label end(this);

  // This method is used for binary op and compare feedback. These
  // vector nodes are initialized with a smi 0, so we can simply OR
  // our new feedback in place.
  TNode<MaybeObject> feedback_element =
      LoadFeedbackVectorSlot(feedback_vector, slot_id);
  TNode<Smi> previous_feedback = CAST(feedback_element);
  TNode<Smi> combined_feedback = SmiOr(previous_feedback, feedback);

  GotoIf(SmiEqual(previous_feedback, combined_feedback), &end);
  {
    StoreFeedbackVectorSlot(feedback_vector, slot_id, combined_feedback,
                            SKIP_WRITE_BARRIER);
    ReportFeedbackUpdate(feedback_vector, slot_id, "UpdateFeedback");
    Goto(&end);
  }

  BIND(&end);
}

void CodeStubAssembler::ReportFeedbackUpdate(
    TNode<FeedbackVector> feedback_vector, TNode<UintPtrT> slot_id,
    const char* reason) {
#ifdef V8_TRACE_FEEDBACK_UPDATES
  // Trace the update.
  CallRuntime(Runtime::kTraceUpdateFeedback, NoContextConstant(),
              feedback_vector, SmiTag(Signed(slot_id)), StringConstant(reason));
#endif  // V8_TRACE_FEEDBACK_UPDATES
}

void CodeStubAssembler::OverwriteFeedback(TVariable<Smi>* existing_feedback,
                                          int new_feedback) {
  if (existing_feedback == nullptr) return;
  *existing_feedback = SmiConstant(new_feedback);
}

void CodeStubAssembler::CombineFeedback(TVariable<Smi>* existing_feedback,
                                        int feedback) {
  if (existing_feedback == nullptr) return;
  *existing_feedback = SmiOr(existing_feedback->value(), SmiConstant(feedback));
}

void CodeStubAssembler::CombineFeedback(TVariable<Smi>* existing_feedback,
                                        TNode<Smi> feedback) {
  if (existing_feedback == nullptr) return;
  *existing_feedback = SmiOr(existing_feedback->value(), feedback);
}

void CodeStubAssembler::CheckForAssociatedProtector(TNode<Name> name,
                                                    Label* if_protector) {
  // This list must be kept in sync with LookupIterator::UpdateProtector!
  auto first_ptr = Unsigned(
      BitcastTaggedToWord(LoadRoot(RootIndex::kFirstNameForProtector)));
  auto last_ptr =
      Unsigned(BitcastTaggedToWord(LoadRoot(RootIndex::kLastNameForProtector)));
  auto name_ptr = Unsigned(BitcastTaggedToWord(name));
  GotoIf(IsInRange(name_ptr, first_ptr, last_ptr), if_protector);
}

void CodeStubAssembler::DCheckReceiver(ConvertReceiverMode mode,
                                       TNode<Object> receiver) {
  switch (mode) {
    case ConvertReceiverMode::kNullOrUndefined:
      CSA_DCHECK(this, IsNullOrUndefined(receiver));
      break;
    case ConvertReceiverMode::kNotNullOrUndefined:
      CSA_DCHECK(this, Word32BinaryNot(IsNullOrUndefined(receiver)));
      break;
    case ConvertReceiverMode::kAny:
      break;
  }
}

TNode<Map> CodeStubAssembler::LoadReceiverMap(TNode<Object> receiver) {
  TVARIABLE(Map, value);
  Label vtrue(this, Label::kDeferred), vfalse(this), end(this);
  Branch(TaggedIsSmi(receiver), &vtrue, &vfalse);

  BIND(&vtrue);
  {
    value = HeapNumberMapConstant();
    Goto(&end);
  }
  BIND(&vfalse);
  {
    value = LoadMap(UncheckedCast<HeapObject>(receiver));
    Goto(&end);
  }

  BIND(&end);
  return value.value();
}

TNode<IntPtrT> CodeStubAssembler::TryToIntptr(
    TNode<Object> key, Label* if_not_intptr,
    TVariable<Int32T>* var_instance_type) {
  TVARIABLE(IntPtrT, var_intptr_key);
  Label done(this, &var_intptr_key), key_is_smi(this), key_is_heapnumber(this);
  GotoIf(TaggedIsSmi(key), &key_is_smi);

  TNode<Int32T> instance_type = LoadInstanceType(CAST(key));
  if (var_instance_type != nullptr) {
    *var_instance_type = instance_type;
  }

  Branch(IsHeapNumberInstanceType(instance_type), &key_is_heapnumber,
         if_not_intptr);

  BIND(&key_is_smi);
  {
    var_intptr_key = SmiUntag(CAST(key));
    Goto(&done);
  }

  BIND(&key_is_heapnumber);
  {
    TNode<Float64T> value = LoadHeapNumberValue(CAST(key));
#if V8_TARGET_ARCH_64_BIT
    TNode<IntPtrT> int_value =
        TNode<IntPtrT>::UncheckedCast(TruncateFloat64ToInt64(value));
#else
    TNode<IntPtrT> int_value =
        TNode<IntPtrT>::UncheckedCast(RoundFloat64ToInt32(value));
#endif
    GotoIfNot(Float64Equal(value, RoundIntPtrToFloat64(int_value)),
              if_not_intptr);
#if V8_TARGET_ARCH_64_BIT
    // We can't rely on Is64() alone because 32-bit compilers rightly complain
    // about kMaxSafeIntegerUint64 not fitting into an intptr_t.
    DCHECK(Is64());
    // TODO(jkummerow): Investigate whether we can drop support for
    // negative indices.
    GotoIfNot(IsInRange(int_value, static_cast<intptr_t>(-kMaxSafeInteger),
                        static_cast<intptr_t>(kMaxSafeIntegerUint64)),
              if_not_intptr);
#else
    DCHECK(!Is64());
#endif
    var_intptr_key = int_value;
    Goto(&done);
  }

  BIND(&done);
  return var_intptr_key.value();
}

TNode<Context> CodeStubAssembler::LoadScriptContext(
    TNode<Context> context, TNode<IntPtrT> context_index) {
  TNode<NativeContext> native_context = LoadNativeContext(context);
  TNode<ScriptContextTable> script_context_table = CAST(
      LoadContextElement(native_context, Context::SCRIPT_CONTEXT_TABLE_INDEX));
  return LoadArrayElement(script_context_table, context_index);
}

namespace {

// Converts typed array elements kind to a machine representations.
MachineRepresentation ElementsKindToMachineRepresentation(ElementsKind kind) {
  switch (kind) {
    case UINT8_CLAMPED_ELEMENTS:
    case UINT8_ELEMENTS:
    case INT8_ELEMENTS:
      return MachineRepresentation::kWord8;
    case UINT16_ELEMENTS:
    case INT16_ELEMENTS:
    case FLOAT16_ELEMENTS:
      return MachineRepresentation::kWord16;
    case UINT32_ELEMENTS:
    case INT32_ELEMENTS:
      return MachineRepresentation::kWord32;
    case FLOAT32_ELEMENTS:
      return MachineRepresentation::kFloat32;
    case FLOAT64_ELEMENTS:
      return MachineRepresentation::kFloat64;
    default:
      UNREACHABLE();
  }
}

}  // namespace

// TODO(solanes): Since we can't use `if constexpr` until we enable C++17 we
// have to specialize the BigInt and Word32T cases. Since we can't partly
// specialize, we have to specialize all used combinations.
template <typename TIndex>
void CodeStubAssembler::StoreElementTypedArrayBigInt(TNode<RawPtrT> elements,
                                                     ElementsKind kind,
                                                     TNode<TIndex> index,
                                                     TNode<BigInt> value) {
  static_assert(std::is_same<TIndex, UintPtrT>::value ||
                    std::is_same<TIndex, IntPtrT>::value,
                "Only UintPtrT or IntPtrT indices is allowed");
  DCHECK(kind == BIGINT64_ELEMENTS || kind == BIGUINT64_ELEMENTS);
  TNode<IntPtrT> offset = ElementOffsetFromIndex(index, kind, 0);
  TVARIABLE(UintPtrT, var_low);
  // Only used on 32-bit platforms.
  TVARIABLE(UintPtrT, var_high);
  BigIntToRawBytes(value, &var_low, &var_high);

  MachineRepresentation rep = WordT::kMachineRepresentation;
#if defined(V8_TARGET_BIG_ENDIAN)
    if (!Is64()) {
      StoreNoWriteBarrier(rep, elements, offset, var_high.value());
      StoreNoWriteBarrier(rep, elements,
                          IntPtrAdd(offset, IntPtrConstant(kSystemPointerSize)),
                          var_low.value());
    } else {
      StoreNoWriteBarrier(rep, elements, offset, var_low.value());
    }
#else
    StoreNoWriteBarrier(rep, elements, offset, var_low.value());
    if (!Is64()) {
      StoreNoWriteBarrier(rep, element
"""


```