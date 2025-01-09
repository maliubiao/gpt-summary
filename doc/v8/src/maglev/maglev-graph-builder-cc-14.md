Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/maglev/maglev-graph-builder.cc`.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose of the file:** The filename `maglev-graph-builder.cc` strongly suggests this code is responsible for building the Maglev graph, which is an intermediate representation used in V8's Maglev compiler.

2. **Analyze the class name:** The class `MaglevGraphBuilder` confirms the core purpose. It's a builder class specifically for the Maglev graph.

3. **Examine the methods:**  The provided snippet shows various methods with names like `VisitToString`, `VisitToBoolean`, `VisitCreateRegExpLiteral`, `VisitCreateArrayLiteral`, `TryReadBoilerplateForFastLiteral`, `CreateVirtualObject`, `BuildInlinedAllocation`, etc. These names give strong hints about the operations being performed.

4. **Group related functionalities:**  Observe patterns in the method names:
    * `Visit...`: These seem to correspond to bytecode instructions or higher-level operations that need to be translated into the Maglev graph.
    * `Create...`: These are involved in creating representations of objects in the Maglev graph (often as `VirtualObject`s).
    * `BuildInlinedAllocation`: This clearly relates to allocating objects directly within the generated code, potentially for performance.
    * `TryReadBoilerplateForFastLiteral`: This suggests optimization techniques for creating object literals.

5. **Infer the purpose of `VirtualObject`:**  The frequent use of `VirtualObject` indicates it's a central concept. It likely represents objects within the Maglev graph before they are fully allocated or materialized in memory. This allows for optimizations and analysis before final code generation.

6. **Connect to JavaScript functionality:** Some `Visit...` methods clearly correspond to JavaScript operations (`ToString`, `ToBoolean`, creating regular expressions, arrays). This confirms the graph builder's role in translating JavaScript code.

7. **Address specific instructions from the prompt:**
    * **`.tq` extension:** The prompt asks about the `.tq` extension. Based on the file content being C++, the answer is that it's not a Torque file.
    * **JavaScript examples:**  For methods like `VisitToString` and `VisitCreateArrayLiteral`, provide simple JavaScript examples that would trigger these operations.
    * **Code logic and assumptions:** For methods like `TryReadBoilerplateForFastLiteral`, try to infer the input and output. The input would be a `boilerplate` object, and the output would be a `VirtualObject` representing a fast literal, or nothing if it can't be optimized.
    * **Common programming errors:** Consider what kind of errors might lead to the deoptimizations mentioned in the code (e.g., insufficient type feedback for array literals).
    * **Part 15 of 18:** Acknowledge the context and relate the functionality to the broader goal of a compiler.

8. **Synthesize the summary:** Combine the observations into a concise description of the file's purpose. Highlight the key functionalities like translating bytecode, creating `VirtualObject`s, and implementing optimizations.

9. **Review and refine:** Ensure the answer is clear, accurate, and addresses all parts of the prompt. For example, make sure the JavaScript examples are simple and relevant. Clarify the role of `VirtualObject`.

**Self-Correction/Refinement during the process:**

* Initially, I might focus too much on individual methods. Realizing the importance of grouping related functionalities leads to a better high-level understanding.
* I need to be careful not to overstate the certainty about the purpose of certain methods without deeper knowledge of the V8 codebase. Using phrases like "likely represents" is important.
*  The prompt specifically asks about common programming errors. I need to make sure to include relevant examples based on the deoptimization reasons mentioned in the code.
* Remembering the context of this being part 15 of a larger compilation process is crucial for the final summarization.
Based on the code snippet provided, here's a breakdown of the functionality of `v8/src/maglev/maglev-graph-builder.cc`, focusing on the provided excerpts:

**Core Functionality:**

This file, `maglev-graph-builder.cc`, is responsible for **building the Maglev graph**, an intermediate representation used by V8's Maglev compiler. It takes the output of the bytecode interpreter and translates it into a graph of nodes representing operations and data flow.

**Specific Functionalities in the Snippet:**

1. **Handling Type Conversions:**
   - **`VisitToName()`:**  Converts a value to a name (string or symbol). It checks if the value is already a `JSReceiver` (an object or function). If so, it moves the accumulator value to the destination register. Otherwise, it converts the value to an object using `ToObject` before storing it in the destination register.
   - **`VisitToString()`:** Converts the value in the accumulator to a string, potentially throwing an error if it's a symbol.
   - **`VisitToBoolean()`:** Converts the value in the accumulator to a boolean.

2. **Creating Literals:**
   - **`VisitCreateRegExpLiteral()`:**  Handles the creation of regular expression literals. It tries to use feedback from previous executions to optimize this process. If sufficient feedback is available, it creates an "inlined allocation" of the RegExp object. Otherwise, it creates a `CreateRegExpLiteral` node in the graph.
   - **`VisitCreateArrayLiteral()`:**  Handles the creation of array literals. Similar to RegExp literals, it leverages feedback for optimization. It attempts to build a fast object or array literal based on feedback. It also handles different array creation flags (e.g., for shallow clones).
   - **`VisitCreateArrayFromIterable()`:** Creates an array from an iterable object by calling the `IterableToListWithSymbolLookup` builtin.
   - **`VisitCreateEmptyArrayLiteral()`:** Creates an empty array literal, again using feedback for potential optimizations and determining the appropriate `ElementsKind` for the array.

3. **Optimizing Object Creation (`TryReadBoilerplateForFastLiteral`):**
   - This function attempts to create object literals quickly by copying data from a "boilerplate" object. It performs checks to ensure the boilerplate is in a suitable state for this optimization (e.g., not migrated, not deprecated, using specific element kinds). It recursively copies properties, handling nested objects.

4. **Managing Virtual Objects:**
   - The code extensively uses `VirtualObject`. These are likely **abstractions representing objects within the Maglev graph before they are fully allocated in memory**. They allow for manipulation and optimization of object structures during graph construction.
   - Methods like `CreateVirtualObject`, `CreateHeapNumber`, `CreateDoubleFixedArray`, `CreateJSObject`, `CreateJSArray`, etc., are responsible for creating these `VirtualObject` representations of different JavaScript object types.

5. **Inlined Allocation:**
   - **`BuildInlinedAllocation()` and related methods:** These functions deal with allocating objects directly within the generated code ("inlining" the allocation). This can improve performance by reducing function call overhead. The code manages `AllocationBlock`s to group inlined allocations.

6. **Handling Arguments Objects:**
   - Methods like `BuildVirtualArgumentsObject` are involved in creating the special `arguments` object available inside functions.

**If `v8/src/maglev/maglev-graph-builder.cc` ended with `.tq`:**

If the file ended with `.tq`, it would indeed be a **V8 Torque source code file**. Torque is V8's domain-specific language for writing low-level builtins and compiler intrinsics. The syntax and structure would be significantly different from the C++ code shown.

**Relationship to JavaScript Functionality with Examples:**

Here are JavaScript examples that would likely trigger some of the functionalities in the code:

- **`VisitToName()`:**
  ```javascript
  let obj = { toString: () => "my object" };
  String(obj); // Calls the toString method
  ```

- **`VisitToString()`:**
  ```javascript
  let num = 123;
  num.toString(); // Converts the number to a string
  ```

- **`VisitToBoolean()`:**
  ```javascript
  if (0) { // 0 is converted to false
    console.log("This won't print");
  }
  ```

- **`VisitCreateRegExpLiteral()`:**
  ```javascript
  let regex = /abc/g;
  ```

- **`VisitCreateArrayLiteral()`:**
  ```javascript
  let arr = [1, 2, 3];
  ```

- **`VisitCreateArrayFromIterable()`:**
  ```javascript
  let set = new Set([4, 5, 6]);
  let arrFromSet = Array.from(set);
  ```

- **`VisitCreateEmptyArrayLiteral()`:**
  ```javascript
  let emptyArr = [];
  ```

**Code Logic and Assumptions (Example: `TryReadBoilerplateForFastLiteral`):**

**Assumptions (Input):**

- `boilerplate`: A `compiler::JSObjectRef` representing a JavaScript object that can serve as a template for fast literal creation.
- `allocation`: An `AllocationType` indicating whether the allocation is in young or old generation.
- `max_depth`: An integer limiting the depth of recursion when copying nested objects.
- `max_properties`: A pointer to an integer limiting the number of properties to copy.

**Output:**

- `std::optional<VirtualObject*>`:
    - If successful, it returns a `VirtualObject*` representing the fast literal object created by copying the boilerplate.
    - If the optimization is not possible (due to boilerplate state, recursion depth, property limits, etc.), it returns an empty `std::optional`.

**Logic:**

The function performs a series of checks on the `boilerplate` object:

1. **Depth Limit:**  Checks if the recursion depth limit is reached.
2. **Migration Lock:** Prevents concurrent modifications to the boilerplate.
3. **Map Consistency:** Verifies that the boilerplate's map hasn't changed since the start of the process.
4. **Deprecation:** Checks if the boilerplate's map has been deprecated.
5. **Elements Kind:** Ensures the boilerplate uses supported element kinds (not dictionary mode).
6. **Properties:** Checks if the boilerplate has only fast properties (no slow properties in the dictionary).
7. **Elements:**  Handles empty or copy-on-write elements directly. For other cases, it recursively copies elements.
8. **Recursive Copying:** If properties or elements are themselves objects, it recursively calls `TryReadBoilerplateForFastLiteral` to potentially optimize their creation as well.

**Common Programming Errors (Related to Deoptimizations):**

The code includes checks and potential deoptimizations. Here are some common JavaScript programming errors that could lead to these deoptimizations:

- **Insufficient Type Feedback for Array Literals:**
  ```javascript
  function createArray(condition) {
    let arr = [];
    if (condition) {
      arr.push(1);
    } else {
      arr.push("a"); // Inconsistent types pushed into the array
    }
    return arr;
  }
  ```
  If the `createArray` function is called multiple times with different `condition` values, the V8 engine might not be able to confidently predict the element types, leading to deoptimization.

- **Modifying Boilerplate Objects:**  If the code relies on a boilerplate object for optimization and that object is modified after the optimization has been applied, it could lead to incorrect assumptions and potential deoptimization.

**Part 15 of 18 -归纳功能:**

As part 15 of 18, this file is a **crucial step in the Maglev compilation pipeline**. It takes the output from earlier stages (likely bytecode) and transforms it into the Maglev graph. This graph represents the program's operations in a way that allows for further optimizations and ultimately code generation. The functionalities within this file are focused on:

- **Translating bytecode instructions related to basic operations, type conversions, and literal creation into graph nodes.**
- **Implementing optimizations for object and array literal creation by leveraging feedback and boilerplate objects.**
- **Providing a mechanism to represent objects within the graph (`VirtualObject`) before their final allocation.**
- **Setting the stage for subsequent optimization passes and code generation within the Maglev compiler.**

In essence, this file is a **translator and optimizer** within the Maglev compilation process, bridging the gap between the interpreter and the final generated machine code.

Prompt: 
```
这是目录为v8/src/maglev/maglev-graph-builder.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/maglev-graph-builder.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第15部分，共18部分，请归纳一下它的功能

"""
ister destination = iterator_.GetRegisterOperand(0);
  NodeType old_type;
  if (CheckType(value, NodeType::kJSReceiver, &old_type)) {
    MoveNodeBetweenRegisters(interpreter::Register::virtual_accumulator(),
                             destination);
  } else {
    StoreRegister(destination, AddNewNode<ToObject>({GetContext(), value},
                                                    GetCheckType(old_type)));
  }
}

void MaglevGraphBuilder::VisitToString() {
  // ToString
  SetAccumulator(BuildToString(GetAccumulator(), ToString::kThrowOnSymbol));
}

void MaglevGraphBuilder::VisitToBoolean() {
  SetAccumulator(BuildToBoolean(GetAccumulator()));
}

void MaglevGraphBuilder::VisitCreateRegExpLiteral() {
  // CreateRegExpLiteral <pattern_idx> <literal_idx> <flags>
  compiler::StringRef pattern = GetRefOperand<String>(0);
  FeedbackSlot slot = GetSlotOperand(1);
  uint32_t flags = GetFlag16Operand(2);
  compiler::FeedbackSource feedback_source{feedback(), slot};
  compiler::ProcessedFeedback const& processed_feedback =
      broker()->GetFeedbackForRegExpLiteral(feedback_source);
  if (!processed_feedback.IsInsufficient()) {
    compiler::RegExpBoilerplateDescriptionRef literal =
        processed_feedback.AsRegExpLiteral().value();
    compiler::NativeContextRef native_context =
        broker()->target_native_context();
    compiler::MapRef map =
        native_context.regexp_function(broker()).initial_map(broker());
    SetAccumulator(BuildInlinedAllocation(
        CreateRegExpLiteralObject(map, literal), AllocationType::kYoung));
    // TODO(leszeks): Don't eagerly clear the raw allocation, have the next side
    // effect clear it.
    ClearCurrentAllocationBlock();
    return;
  }
  // Fallback.
  SetAccumulator(
      AddNewNode<CreateRegExpLiteral>({}, pattern, feedback_source, flags));
}

void MaglevGraphBuilder::VisitCreateArrayLiteral() {
  compiler::HeapObjectRef constant_elements = GetRefOperand<HeapObject>(0);
  FeedbackSlot slot_index = GetSlotOperand(1);
  int bytecode_flags = GetFlag8Operand(2);
  int literal_flags =
      interpreter::CreateArrayLiteralFlags::FlagsBits::decode(bytecode_flags);
  compiler::FeedbackSource feedback_source(feedback(), slot_index);

  compiler::ProcessedFeedback const& processed_feedback =
      broker()->GetFeedbackForArrayOrObjectLiteral(feedback_source);

  if (processed_feedback.IsInsufficient()) {
    RETURN_VOID_ON_ABORT(EmitUnconditionalDeopt(
        DeoptimizeReason::kInsufficientTypeFeedbackForArrayLiteral));
  }

  ReduceResult result =
      TryBuildFastCreateObjectOrArrayLiteral(processed_feedback.AsLiteral());
  PROCESS_AND_RETURN_IF_DONE(result, SetAccumulator);

  if (interpreter::CreateArrayLiteralFlags::FastCloneSupportedBit::decode(
          bytecode_flags)) {
    // TODO(victorgomes): CreateShallowArrayLiteral should not need the
    // boilerplate descriptor. However the current builtin checks that the
    // feedback exists and fallsback to CreateArrayLiteral if it doesn't.
    SetAccumulator(AddNewNode<CreateShallowArrayLiteral>(
        {}, constant_elements, feedback_source, literal_flags));
  } else {
    SetAccumulator(AddNewNode<CreateArrayLiteral>(
        {}, constant_elements, feedback_source, literal_flags));
  }
}

void MaglevGraphBuilder::VisitCreateArrayFromIterable() {
  ValueNode* iterable = GetAccumulator();
  SetAccumulator(BuildCallBuiltin<Builtin::kIterableToListWithSymbolLookup>(
      {GetTaggedValue(iterable)}));
}

void MaglevGraphBuilder::VisitCreateEmptyArrayLiteral() {
  FeedbackSlot slot_index = GetSlotOperand(0);
  compiler::FeedbackSource feedback_source(feedback(), slot_index);
  compiler::ProcessedFeedback const& processed_feedback =
      broker()->GetFeedbackForArrayOrObjectLiteral(feedback_source);
  if (processed_feedback.IsInsufficient()) {
    RETURN_VOID_ON_ABORT(EmitUnconditionalDeopt(
        DeoptimizeReason::kInsufficientTypeFeedbackForArrayLiteral));
  }
  compiler::AllocationSiteRef site = processed_feedback.AsLiteral().value();

  broker()->dependencies()->DependOnElementsKind(site);
  ElementsKind kind = site.GetElementsKind();

  compiler::NativeContextRef native_context = broker()->target_native_context();
  compiler::MapRef map = native_context.GetInitialJSArrayMap(broker(), kind);
  // Initial JSArray map shouldn't have any in-object properties.
  SBXCHECK_EQ(map.GetInObjectProperties(), 0);
  SetAccumulator(BuildInlinedAllocation(
      CreateJSArray(map, map.instance_size(), GetSmiConstant(0)),
      AllocationType::kYoung));
  // TODO(leszeks): Don't eagerly clear the raw allocation, have the next side
  // effect clear it.
  ClearCurrentAllocationBlock();
}

std::optional<VirtualObject*>
MaglevGraphBuilder::TryReadBoilerplateForFastLiteral(
    compiler::JSObjectRef boilerplate, AllocationType allocation, int max_depth,
    int* max_properties) {
  DCHECK_GE(max_depth, 0);
  DCHECK_GE(*max_properties, 0);

  if (max_depth == 0) return {};

  // Prevent concurrent migrations of boilerplate objects.
  compiler::JSHeapBroker::BoilerplateMigrationGuardIfNeeded
      boilerplate_access_guard(broker());

  // Now that we hold the migration lock, get the current map.
  compiler::MapRef boilerplate_map = boilerplate.map(broker());
  // Protect against concurrent changes to the boilerplate object by checking
  // for an identical value at the end of the compilation.
  broker()->dependencies()->DependOnObjectSlotValue(
      boilerplate, HeapObject::kMapOffset, boilerplate_map);
  {
    compiler::OptionalMapRef current_boilerplate_map =
        boilerplate.map_direct_read(broker());
    if (!current_boilerplate_map.has_value() ||
        !current_boilerplate_map->equals(boilerplate_map)) {
      // TODO(leszeks): Emit an eager deopt for this case, so that we can
      // re-learn the boilerplate. This will be easier once we get rid of the
      // two-pass approach, since we'll be able to create the eager deopt here
      // and return a ReduceResult::DoneWithAbort().
      return {};
    }
  }

  // Bail out if the boilerplate map has been deprecated.  The map could of
  // course be deprecated at some point after the line below, but it's not a
  // correctness issue -- it only means the literal won't be created with the
  // most up to date map(s).
  if (boilerplate_map.is_deprecated()) return {};

  // We currently only support in-object properties.
  if (boilerplate.map(broker()).elements_kind() == DICTIONARY_ELEMENTS ||
      boilerplate.map(broker()).is_dictionary_map() ||
      !boilerplate.raw_properties_or_hash(broker()).has_value()) {
    return {};
  }
  {
    compiler::ObjectRef properties =
        *boilerplate.raw_properties_or_hash(broker());
    bool const empty =
        properties.IsSmi() ||
        properties.equals(MakeRef(
            broker(), local_isolate()->factory()->empty_fixed_array())) ||
        properties.equals(MakeRef(
            broker(),
            Cast<Object>(local_isolate()->factory()->empty_property_array())));
    if (!empty) return {};
  }

  compiler::OptionalFixedArrayBaseRef maybe_elements =
      boilerplate.elements(broker(), kRelaxedLoad);
  if (!maybe_elements.has_value()) return {};
  compiler::FixedArrayBaseRef boilerplate_elements = maybe_elements.value();
  broker()->dependencies()->DependOnObjectSlotValue(
      boilerplate, JSObject::kElementsOffset, boilerplate_elements);
  const uint32_t elements_length = boilerplate_elements.length();

  VirtualObject* fast_literal =
      boilerplate_map.IsJSArrayMap()
          ? CreateJSArray(
                boilerplate_map, boilerplate_map.instance_size(),
                GetConstant(
                    boilerplate.AsJSArray().GetBoilerplateLength(broker())))
          : CreateJSObject(boilerplate_map);

  int inobject_properties = boilerplate_map.GetInObjectProperties();

  // Compute the in-object properties to store first.
  int index = 0;
  for (InternalIndex i :
       InternalIndex::Range(boilerplate_map.NumberOfOwnDescriptors())) {
    PropertyDetails const property_details =
        boilerplate_map.GetPropertyDetails(broker(), i);
    if (property_details.location() != PropertyLocation::kField) continue;
    DCHECK_EQ(PropertyKind::kData, property_details.kind());
    if ((*max_properties)-- == 0) return {};

    int offset = boilerplate_map.GetInObjectPropertyOffset(index);
#ifdef DEBUG
    FieldIndex field_index =
        FieldIndex::ForDetails(*boilerplate_map.object(), property_details);
    DCHECK(field_index.is_inobject());
    DCHECK_EQ(index, field_index.property_index());
    DCHECK_EQ(field_index.offset(), offset);
#endif

    // The index is derived from the in-sandbox `NumberOfOwnDescriptors` value,
    // but the access is out-of-sandbox fast_literal fields.
    SBXCHECK_LT(index, inobject_properties);

    // Note: the use of RawInobjectPropertyAt (vs. the higher-level
    // GetOwnFastConstantDataProperty) here is necessary, since the underlying
    // value may be `uninitialized`, which the latter explicitly does not
    // support.
    compiler::OptionalObjectRef maybe_boilerplate_value =
        boilerplate.RawInobjectPropertyAt(
            broker(),
            FieldIndex::ForInObjectOffset(offset, FieldIndex::kTagged));
    if (!maybe_boilerplate_value.has_value()) return {};

    // Note: We don't need to take a compilation dependency verifying the value
    // of `boilerplate_value`, since boilerplate properties are constant after
    // initialization modulo map migration. We protect against concurrent map
    // migrations (other than elements kind transition, which don't affect us)
    // via the boilerplate_migration_access lock.
    compiler::ObjectRef boilerplate_value = maybe_boilerplate_value.value();

    if (boilerplate_value.IsJSObject()) {
      compiler::JSObjectRef boilerplate_object = boilerplate_value.AsJSObject();
      std::optional<VirtualObject*> maybe_object_value =
          TryReadBoilerplateForFastLiteral(boilerplate_object, allocation,
                                           max_depth - 1, max_properties);
      if (!maybe_object_value.has_value()) return {};
      fast_literal->set(offset, maybe_object_value.value());
    } else if (property_details.representation().IsDouble()) {
      fast_literal->set(offset,
                        CreateHeapNumber(Float64::FromBits(
                            boilerplate_value.AsHeapNumber().value_as_bits())));
    } else {
      // It's fine to store the 'uninitialized' Oddball into a Smi field since
      // it will get overwritten anyway.
      DCHECK_IMPLIES(property_details.representation().IsSmi() &&
                         !boilerplate_value.IsSmi(),
                     IsUninitialized(*boilerplate_value.object()));
      fast_literal->set(offset, GetConstant(boilerplate_value));
    }
    index++;
  }

  // Fill slack at the end of the boilerplate object with filler maps.
  for (; index < inobject_properties; ++index) {
    DCHECK(!V8_MAP_PACKING_BOOL);
    // TODO(wenyuzhao): Fix incorrect MachineType when V8_MAP_PACKING is
    // enabled.
    int offset = boilerplate_map.GetInObjectPropertyOffset(index);
    fast_literal->set(offset, GetRootConstant(RootIndex::kOnePointerFillerMap));
  }

  DCHECK_EQ(JSObject::kElementsOffset, JSArray::kElementsOffset);
  // Empty or copy-on-write elements just store a constant.
  compiler::MapRef elements_map = boilerplate_elements.map(broker());
  // Protect against concurrent changes to the boilerplate object by checking
  // for an identical value at the end of the compilation.
  broker()->dependencies()->DependOnObjectSlotValue(
      boilerplate_elements, HeapObject::kMapOffset, elements_map);
  if (boilerplate_elements.length() == 0 ||
      elements_map.IsFixedCowArrayMap(broker())) {
    if (allocation == AllocationType::kOld &&
        !boilerplate.IsElementsTenured(boilerplate_elements)) {
      return {};
    }
    fast_literal->set(JSObject::kElementsOffset,
                      GetConstant(boilerplate_elements));
  } else {
    // Compute the elements to store first (might have effects).
    if (boilerplate_elements.IsFixedDoubleArray()) {
      int const size = FixedDoubleArray::SizeFor(elements_length);
      if (size > kMaxRegularHeapObjectSize) return {};
      fast_literal->set(
          JSObject::kElementsOffset,
          CreateDoubleFixedArray(elements_length,
                                 boilerplate_elements.AsFixedDoubleArray()));
    } else {
      int const size = FixedArray::SizeFor(elements_length);
      if (size > kMaxRegularHeapObjectSize) return {};
      VirtualObject* elements =
          CreateFixedArray(broker()->fixed_array_map(), elements_length);
      compiler::FixedArrayRef boilerplate_elements_as_fixed_array =
          boilerplate_elements.AsFixedArray();
      for (uint32_t i = 0; i < elements_length; ++i) {
        if ((*max_properties)-- == 0) return {};
        compiler::OptionalObjectRef element_value =
            boilerplate_elements_as_fixed_array.TryGet(broker(), i);
        if (!element_value.has_value()) return {};
        if (element_value->IsJSObject()) {
          std::optional<VirtualObject*> object =
              TryReadBoilerplateForFastLiteral(element_value->AsJSObject(),
                                               allocation, max_depth - 1,
                                               max_properties);
          if (!object.has_value()) return {};
          elements->set(FixedArray::OffsetOfElementAt(i), *object);
        } else {
          elements->set(FixedArray::OffsetOfElementAt(i),
                        GetConstant(*element_value));
        }
      }

      fast_literal->set(JSObject::kElementsOffset, elements);
    }
  }

  return fast_literal;
}

VirtualObject* MaglevGraphBuilder::DeepCopyVirtualObject(VirtualObject* old) {
  CHECK_EQ(old->type(), VirtualObject::kDefault);
  ValueNode** slots = zone()->AllocateArray<ValueNode*>(old->slot_count());
  VirtualObject* vobject = NodeBase::New<VirtualObject>(
      zone(), 0, old->map(), NewObjectId(), old->slot_count(), slots);
  current_interpreter_frame_.add_object(vobject);
  for (int i = 0; i < static_cast<int>(old->slot_count()); i++) {
    vobject->set_by_index(i, old->get_by_index(i));
  }
  vobject->set_allocation(old->allocation());
  old->allocation()->UpdateObject(vobject);
  return vobject;
}

VirtualObject* MaglevGraphBuilder::CreateVirtualObjectForMerge(
    compiler::MapRef map, uint32_t slot_count) {
  ValueNode** slots = zone()->AllocateArray<ValueNode*>(slot_count);
  VirtualObject* vobject = NodeBase::New<VirtualObject>(
      zone(), 0, map, NewObjectId(), slot_count, slots);
  return vobject;
}

VirtualObject* MaglevGraphBuilder::CreateVirtualObject(
    compiler::MapRef map, uint32_t slot_count_including_map) {
  // VirtualObjects are not added to the Maglev graph.
  DCHECK_GT(slot_count_including_map, 0);
  uint32_t slot_count = slot_count_including_map - 1;
  ValueNode** slots = zone()->AllocateArray<ValueNode*>(slot_count);
  VirtualObject* vobject = NodeBase::New<VirtualObject>(
      zone(), 0, map, NewObjectId(), slot_count, slots);
  return vobject;
}

VirtualObject* MaglevGraphBuilder::CreateHeapNumber(Float64 value) {
  // VirtualObjects are not added to the Maglev graph.
  VirtualObject* vobject = NodeBase::New<VirtualObject>(
      zone(), 0, broker()->heap_number_map(), NewObjectId(), value);
  return vobject;
}

VirtualObject* MaglevGraphBuilder::CreateDoubleFixedArray(
    uint32_t elements_length, compiler::FixedDoubleArrayRef elements) {
  // VirtualObjects are not added to the Maglev graph.
  VirtualObject* vobject = NodeBase::New<VirtualObject>(
      zone(), 0, broker()->fixed_double_array_map(), NewObjectId(),
      elements_length, elements);
  return vobject;
}

VirtualObject* MaglevGraphBuilder::CreateJSObject(compiler::MapRef map) {
  DCHECK(!map.is_dictionary_map());
  DCHECK(!map.IsInobjectSlackTrackingInProgress());
  int slot_count = map.instance_size() / kTaggedSize;
  SBXCHECK_GE(slot_count, 3);
  VirtualObject* object = CreateVirtualObject(map, slot_count);
  object->set(JSObject::kPropertiesOrHashOffset,
              GetRootConstant(RootIndex::kEmptyFixedArray));
  object->set(JSObject::kElementsOffset,
              GetRootConstant(RootIndex::kEmptyFixedArray));
  object->ClearSlots(JSObject::kElementsOffset,
                     GetRootConstant(RootIndex::kOnePointerFillerMap));
  return object;
}

VirtualObject* MaglevGraphBuilder::CreateJSArray(compiler::MapRef map,
                                                 int instance_size,
                                                 ValueNode* length) {
  int slot_count = instance_size / kTaggedSize;
  SBXCHECK_GE(slot_count, 4);
  VirtualObject* object = CreateVirtualObject(map, slot_count);
  object->set(JSArray::kPropertiesOrHashOffset,
              GetRootConstant(RootIndex::kEmptyFixedArray));
  object->set(JSArray::kElementsOffset,
              GetRootConstant(RootIndex::kEmptyFixedArray));
  object->set(JSArray::kLengthOffset, length);
  object->ClearSlots(JSArray::kLengthOffset,
                     GetRootConstant(RootIndex::kOnePointerFillerMap));
  return object;
}

VirtualObject* MaglevGraphBuilder::CreateJSArrayIterator(
    compiler::MapRef map, ValueNode* iterated_object, IterationKind kind) {
  int slot_count = map.instance_size() / kTaggedSize;
  SBXCHECK_EQ(slot_count, 6);
  VirtualObject* object = CreateVirtualObject(map, slot_count);
  object->set(JSArrayIterator::kPropertiesOrHashOffset,
              GetRootConstant(RootIndex::kEmptyFixedArray));
  object->set(JSArrayIterator::kElementsOffset,
              GetRootConstant(RootIndex::kEmptyFixedArray));
  object->set(JSArrayIterator::kIteratedObjectOffset, iterated_object);
  object->set(JSArrayIterator::kNextIndexOffset, GetInt32Constant(0));
  object->set(JSArrayIterator::kKindOffset,
              GetInt32Constant(static_cast<int>(kind)));
  return object;
}

VirtualObject* MaglevGraphBuilder::CreateJSConstructor(
    compiler::JSFunctionRef constructor) {
  compiler::SlackTrackingPrediction prediction =
      broker()->dependencies()->DependOnInitialMapInstanceSizePrediction(
          constructor);
  int slot_count = prediction.instance_size() / kTaggedSize;
  VirtualObject* object =
      CreateVirtualObject(constructor.initial_map(broker()), slot_count);
  SBXCHECK_GE(slot_count, 3);
  object->set(JSObject::kPropertiesOrHashOffset,
              GetRootConstant(RootIndex::kEmptyFixedArray));
  object->set(JSObject::kElementsOffset,
              GetRootConstant(RootIndex::kEmptyFixedArray));
  object->ClearSlots(JSObject::kElementsOffset,
                     GetRootConstant(RootIndex::kOnePointerFillerMap));
  return object;
}

VirtualObject* MaglevGraphBuilder::CreateFixedArray(compiler::MapRef map,
                                                    int length) {
  int slot_count = FixedArray::SizeFor(length) / kTaggedSize;
  VirtualObject* array = CreateVirtualObject(map, slot_count);
  array->set(offsetof(FixedArray, length_), GetInt32Constant(length));
  array->ClearSlots(offsetof(FixedArray, length_),
                    GetRootConstant(RootIndex::kOnePointerFillerMap));
  return array;
}

VirtualObject* MaglevGraphBuilder::CreateContext(
    compiler::MapRef map, int length, compiler::ScopeInfoRef scope_info,
    ValueNode* previous_context, std::optional<ValueNode*> extension) {
  int slot_count = FixedArray::SizeFor(length) / kTaggedSize;
  VirtualObject* context = CreateVirtualObject(map, slot_count);
  context->set(Context::kLengthOffset, GetInt32Constant(length));
  context->set(Context::OffsetOfElementAt(Context::SCOPE_INFO_INDEX),
               GetConstant(scope_info));
  context->set(Context::OffsetOfElementAt(Context::PREVIOUS_INDEX),
               previous_context);
  int index = Context::PREVIOUS_INDEX + 1;
  if (extension.has_value()) {
    context->set(Context::OffsetOfElementAt(Context::EXTENSION_INDEX),
                 extension.value());
    index++;
  }
  for (; index < length; index++) {
    context->set(Context::OffsetOfElementAt(index),
                 GetRootConstant(RootIndex::kUndefinedValue));
  }
  return context;
}

VirtualObject* MaglevGraphBuilder::CreateArgumentsObject(
    compiler::MapRef map, ValueNode* length, ValueNode* elements,
    std::optional<ValueNode*> callee) {
  DCHECK_EQ(JSSloppyArgumentsObject::kLengthOffset, JSArray::kLengthOffset);
  DCHECK_EQ(JSStrictArgumentsObject::kLengthOffset, JSArray::kLengthOffset);
  int slot_count = map.instance_size() / kTaggedSize;
  SBXCHECK_EQ(slot_count, callee.has_value() ? 5 : 4);
  VirtualObject* arguments = CreateVirtualObject(map, slot_count);
  arguments->set(JSArray::kPropertiesOrHashOffset,
                 GetRootConstant(RootIndex::kEmptyFixedArray));
  arguments->set(JSArray::kElementsOffset, elements);
  arguments->set(JSArray::kLengthOffset, length);
  if (callee.has_value()) {
    arguments->set(JSSloppyArgumentsObject::kCalleeOffset, callee.value());
  }
  DCHECK(arguments->map().IsJSArgumentsObjectMap() ||
         arguments->map().IsJSArrayMap());
  return arguments;
}

VirtualObject* MaglevGraphBuilder::CreateMappedArgumentsElements(
    compiler::MapRef map, int mapped_count, ValueNode* context,
    ValueNode* unmapped_elements) {
  int slot_count = SloppyArgumentsElements::SizeFor(mapped_count) / kTaggedSize;
  VirtualObject* elements = CreateVirtualObject(map, slot_count);
  elements->set(offsetof(SloppyArgumentsElements, length_),
                GetInt32Constant(mapped_count));
  elements->set(offsetof(SloppyArgumentsElements, context_), context);
  elements->set(offsetof(SloppyArgumentsElements, arguments_),
                unmapped_elements);
  return elements;
}

VirtualObject* MaglevGraphBuilder::CreateRegExpLiteralObject(
    compiler::MapRef map, compiler::RegExpBoilerplateDescriptionRef literal) {
  DCHECK_EQ(JSRegExp::Size(), JSRegExp::kLastIndexOffset + kTaggedSize);
  int slot_count = JSRegExp::Size() / kTaggedSize;
  VirtualObject* regexp = CreateVirtualObject(map, slot_count);
  regexp->set(JSRegExp::kPropertiesOrHashOffset,
              GetRootConstant(RootIndex::kEmptyFixedArray));
  regexp->set(JSRegExp::kElementsOffset,
              GetRootConstant(RootIndex::kEmptyFixedArray));
  regexp->set(JSRegExp::kDataOffset,
              GetTrustedConstant(literal.data(broker()),
                                 kRegExpDataIndirectPointerTag));
  regexp->set(JSRegExp::kSourceOffset, GetConstant(literal.source(broker())));
  regexp->set(JSRegExp::kFlagsOffset, GetInt32Constant(literal.flags()));
  regexp->set(JSRegExp::kLastIndexOffset,
              GetInt32Constant(JSRegExp::kInitialLastIndexValue));
  return regexp;
}

VirtualObject* MaglevGraphBuilder::CreateJSGeneratorObject(
    compiler::MapRef map, int instance_size, ValueNode* context,
    ValueNode* closure, ValueNode* receiver, ValueNode* register_file) {
  int slot_count = instance_size / kTaggedSize;
  InstanceType instance_type = map.instance_type();
  DCHECK(instance_type == JS_GENERATOR_OBJECT_TYPE ||
         instance_type == JS_ASYNC_GENERATOR_OBJECT_TYPE);
  SBXCHECK_GE(slot_count, instance_type == JS_GENERATOR_OBJECT_TYPE ? 10 : 12);
  VirtualObject* object = CreateVirtualObject(map, slot_count);
  object->set(JSGeneratorObject::kPropertiesOrHashOffset,
              GetRootConstant(RootIndex::kEmptyFixedArray));
  object->set(JSGeneratorObject::kElementsOffset,
              GetRootConstant(RootIndex::kEmptyFixedArray));
  object->set(JSGeneratorObject::kContextOffset, context);
  object->set(JSGeneratorObject::kFunctionOffset, closure);
  object->set(JSGeneratorObject::kReceiverOffset, receiver);
  object->set(JSGeneratorObject::kInputOrDebugPosOffset,
              GetRootConstant(RootIndex::kUndefinedValue));
  object->set(JSGeneratorObject::kResumeModeOffset,
              GetInt32Constant(JSGeneratorObject::kNext));
  object->set(JSGeneratorObject::kContinuationOffset,
              GetInt32Constant(JSGeneratorObject::kGeneratorExecuting));
  object->set(JSGeneratorObject::kParametersAndRegistersOffset, register_file);
  if (instance_type == JS_ASYNC_GENERATOR_OBJECT_TYPE) {
    object->set(JSAsyncGeneratorObject::kQueueOffset,
                GetRootConstant(RootIndex::kUndefinedValue));
    object->set(JSAsyncGeneratorObject::kIsAwaitingOffset, GetInt32Constant(0));
  }
  return object;
}

VirtualObject* MaglevGraphBuilder::CreateJSIteratorResult(compiler::MapRef map,
                                                          ValueNode* value,
                                                          ValueNode* done) {
  static_assert(JSIteratorResult::kSize == 5 * kTaggedSize);
  int slot_count = JSIteratorResult::kSize / kTaggedSize;
  VirtualObject* iter_result = CreateVirtualObject(map, slot_count);
  iter_result->set(JSIteratorResult::kPropertiesOrHashOffset,
                   GetRootConstant(RootIndex::kEmptyFixedArray));
  iter_result->set(JSIteratorResult::kElementsOffset,
                   GetRootConstant(RootIndex::kEmptyFixedArray));
  iter_result->set(JSIteratorResult::kValueOffset, value);
  iter_result->set(JSIteratorResult::kDoneOffset, done);
  return iter_result;
}

VirtualObject* MaglevGraphBuilder::CreateJSStringIterator(compiler::MapRef map,
                                                          ValueNode* string) {
  static_assert(JSStringIterator::kHeaderSize == 5 * kTaggedSize);
  int slot_count = JSStringIterator::kHeaderSize / kTaggedSize;
  VirtualObject* string_iter = CreateVirtualObject(map, slot_count);
  string_iter->set(JSStringIterator::kPropertiesOrHashOffset,
                   GetRootConstant(RootIndex::kEmptyFixedArray));
  string_iter->set(JSStringIterator::kElementsOffset,
                   GetRootConstant(RootIndex::kEmptyFixedArray));
  string_iter->set(JSStringIterator::kStringOffset, string);
  string_iter->set(JSStringIterator::kIndexOffset, GetInt32Constant(0));
  return string_iter;
}

InlinedAllocation* MaglevGraphBuilder::ExtendOrReallocateCurrentAllocationBlock(
    AllocationType allocation_type, VirtualObject* vobject) {
  DCHECK_LT(vobject->size(), kMaxRegularHeapObjectSize);
  if (!current_allocation_block_ ||
      current_allocation_block_->allocation_type() != allocation_type ||
      !v8_flags.inline_new ||
      compilation_unit()->info()->for_turboshaft_frontend()) {
    current_allocation_block_ =
        AddNewNode<AllocationBlock>({}, allocation_type);
  }

  int current_size = current_allocation_block_->size();
  if (current_size + vobject->size() > kMaxRegularHeapObjectSize) {
    current_allocation_block_ =
        AddNewNode<AllocationBlock>({}, allocation_type);
  }

  DCHECK_GE(current_size, 0);
  InlinedAllocation* allocation =
      AddNewNode<InlinedAllocation>({current_allocation_block_}, vobject);
  graph()->allocations_escape_map().emplace(allocation, zone());
  current_allocation_block_->Add(allocation);
  vobject->set_allocation(allocation);
  return allocation;
}

void MaglevGraphBuilder::ClearCurrentAllocationBlock() {
  current_allocation_block_ = nullptr;
}

void MaglevGraphBuilder::AddNonEscapingUses(InlinedAllocation* allocation,
                                            int use_count) {
  if (!v8_flags.maglev_escape_analysis) return;
  allocation->AddNonEscapingUses(use_count);
}

void MaglevGraphBuilder::AddDeoptUse(VirtualObject* vobject) {
  if (vobject->type() != VirtualObject::kDefault) return;
  for (uint32_t i = 0; i < vobject->slot_count(); i++) {
    ValueNode* value = vobject->get_by_index(i);
    if (InlinedAllocation* nested_allocation =
            value->TryCast<InlinedAllocation>()) {
      VirtualObject* nested_object =
          current_interpreter_frame_.virtual_objects().FindAllocatedWith(
              nested_allocation);
      CHECK_NOT_NULL(nested_object);
      AddDeoptUse(nested_object);
    } else if (!IsConstantNode(value->opcode()) &&
               value->opcode() != Opcode::kArgumentsElements &&
               value->opcode() != Opcode::kArgumentsLength &&
               value->opcode() != Opcode::kRestLength) {
      AddDeoptUse(value);
    }
  }
}

ValueNode* MaglevGraphBuilder::BuildInlinedAllocationForHeapNumber(
    VirtualObject* vobject, AllocationType allocation_type) {
  DCHECK(vobject->map().IsHeapNumberMap());
  InlinedAllocation* allocation =
      ExtendOrReallocateCurrentAllocationBlock(allocation_type, vobject);
  AddNonEscapingUses(allocation, 2);
  BuildStoreMap(allocation, broker()->heap_number_map(),
                StoreMap::initializing_kind(allocation_type));
  AddNewNode<StoreFloat64>({allocation, GetFloat64Constant(vobject->number())},
                           static_cast<int>(offsetof(HeapNumber, value_)));
  return allocation;
}

ValueNode* MaglevGraphBuilder::BuildInlinedAllocationForDoubleFixedArray(
    VirtualObject* vobject, AllocationType allocation_type) {
  DCHECK(vobject->map().IsFixedDoubleArrayMap());
  InlinedAllocation* allocation =
      ExtendOrReallocateCurrentAllocationBlock(allocation_type, vobject);
  int length = vobject->double_elements_length();
  AddNonEscapingUses(allocation, length + 2);
  BuildStoreMap(allocation, broker()->fixed_double_array_map(),
                StoreMap::initializing_kind(allocation_type));
  AddNewNode<StoreTaggedFieldNoWriteBarrier>(
      {allocation, GetSmiConstant(length)},
      static_cast<int>(offsetof(FixedDoubleArray, length_)),
      StoreTaggedMode::kDefault);
  for (int i = 0; i < length; ++i) {
    AddNewNode<StoreFloat64>(
        {allocation,
         GetFloat64Constant(
             vobject->double_elements().GetFromImmutableFixedDoubleArray(i))},
        FixedDoubleArray::OffsetOfElementAt(i));
  }
  return allocation;
}

ValueNode* MaglevGraphBuilder::BuildInlinedAllocation(
    VirtualObject* vobject, AllocationType allocation_type) {
  current_interpreter_frame_.add_object(vobject);
  if (vobject->type() == VirtualObject::kHeapNumber) {
    return BuildInlinedAllocationForHeapNumber(vobject, allocation_type);
  }
  if (vobject->type() == VirtualObject::kFixedDoubleArray) {
    return BuildInlinedAllocationForDoubleFixedArray(vobject, allocation_type);
  }
  SmallZoneVector<ValueNode*, 8> values(vobject->slot_count(), zone());
  for (uint32_t i = 0; i < vobject->slot_count(); i++) {
    ValueNode* node = vobject->get_by_index(i);
    if (node->Is<VirtualObject>()) {
      VirtualObject* nested = node->Cast<VirtualObject>();
      node = BuildInlinedAllocation(nested, allocation_type);
      vobject->set_by_index(i, node);
    } else if (node->Is<Float64Constant>()) {
      node = BuildInlinedAllocationForHeapNumber(
          CreateHeapNumber(node->Cast<Float64Constant>()->value()),
          allocation_type);
    } else {
      node = GetTaggedValue(node);
    }
    values[i] = node;
  }
  InlinedAllocation* allocation =
      ExtendOrReallocateCurrentAllocationBlock(allocation_type, vobject);
  AddNonEscapingUses(allocation, vobject->slot_count() + 1);
  BuildStoreMap(allocation, vobject->map(),
                StoreMap::initializing_kind(allocation_type));
  for (uint32_t i = 0; i < vobject->slot_count(); i++) {
    BuildInitializeStore(allocation, values[i], (i + 1) * kTaggedSize);
  }
  if (is_loop_effect_tracking()) {
    loop_effects_->allocations.insert(allocation);
  }
  return allocation;
}

ValueNode* MaglevGraphBuilder::BuildInlinedArgumentsElements(int start_index,
                                                             int length) {
  DCHECK(is_inline());
  if (length == 0) {
    return GetRootConstant(RootIndex::kEmptyFixedArray);
  }
  VirtualObject* elements =
      CreateFixedArray(broker()->fixed_array_map(), length);
  for (int i = 0; i < length; i++) {
    elements->set(FixedArray::OffsetOfElementAt(i),
                  inlined_arguments_[i + start_index + 1]);
  }
  return elements;
}

ValueNode* MaglevGraphBuilder::BuildInlinedUnmappedArgumentsElements(
    int mapped_count) {
  int length = argument_count_without_receiver();
  if (length == 0) {
    return GetRootConstant(RootIndex::kEmptyFixedArray);
  }
  VirtualObject* unmapped_elements =
      CreateFixedArray(broker()->fixed_array_map(), length);
  int i = 0;
  for (; i < mapped_count; i++) {
    unmapped_elements->set(FixedArray::OffsetOfElementAt(i),
                           GetRootConstant(RootIndex::kTheHoleValue));
  }
  for (; i < length; i++) {
    unmapped_elements->set(FixedArray::OffsetOfElementAt(i),
                           inlined_arguments_[i + 1]);
  }
  return unmapped_elements;
}

template <CreateArgumentsType type>
VirtualObject* MaglevGraphBuilder::BuildVirtualArgumentsObject() {
  switch (type) {
    case CreateArgumentsType::kMappedArguments:
      if (
"""


```