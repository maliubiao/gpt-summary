Response: My thinking process to summarize the C++ code snippet goes like this:

1. **Understand the Goal:** The request asks for a functional summary of the C++ code, specifically relating it to JavaScript if applicable, and acknowledging its position as part 4 of a 9-part series.

2. **Initial Scan for Keywords and Concepts:** I quickly scanned the code for recurring keywords and patterns. Terms like `FixedArray`, `FixedDoubleArray`, `Load`, `Store`, `Element`, `Property`, `Map`, `Object`, and function names like `BuildLoad...`, `BuildStore...`, `TryBuild...` stand out. These strongly suggest this part of the code is responsible for building graph nodes related to accessing and modifying elements in JavaScript arrays and potentially other object properties.

3. **Identify Key Data Structures:** The presence of `FixedArray` and `FixedDoubleArray` indicates this code is dealing with optimized array representations in V8. The `Map` concept hints at dealing with object structures and optimizations based on object layouts.

4. **Focus on Functionality by Analyzing Function Names:** I examined the function names more closely. The `BuildLoad...` and `BuildStore...` prefixes clearly denote functions responsible for generating graph nodes for loading and storing data. The suffixes like `FixedArrayElement`, `FixedDoubleArrayElement` specify the type of data being accessed.

5. **Deduce the Role of `MaglevGraphBuilder`:**  The class name `MaglevGraphBuilder` combined with the `Build...` function names strongly suggests this class is central to constructing the Maglev intermediate representation (IR) for JavaScript code.

6. **Look for Optimization Strategies:** I noticed conditional logic based on `CanTrackObjectChanges` and checks for constant values. This signals the code is implementing optimizations by taking advantage of known information about objects and their immutability. The handling of "holes" in arrays also points to optimization considerations specific to JavaScript's dynamic nature.

7. **Connect to JavaScript Concepts:** I started to map the C++ concepts to their JavaScript equivalents. `FixedArray` and `FixedDoubleArray` directly correspond to JavaScript arrays, especially when optimized by the engine. Loading and storing elements are fundamental JavaScript array operations. The mention of prototypes and maps relates to JavaScript's prototype-based inheritance and how V8 optimizes object property access.

8. **Formulate a High-Level Summary:** Based on the above analysis, I formulated an initial summary stating the file's role in building graph nodes for loading and storing array elements, including optimizations.

9. **Refine the Summary with More Detail:** I reread the code, focusing on the specifics of the operations. I noted the handling of different array types (packed, holey, double), the presence of write barriers (important for memory management in garbage-collected environments), and the optimization strategies based on constant values and object tracking.

10. **Create JavaScript Examples:**  To illustrate the connection to JavaScript, I created simple examples demonstrating array access and modification that would likely trigger the code in this file within the V8 engine. I focused on the operations directly handled by the functions, like accessing elements by index.

11. **Address the "Part 4 of 9" aspect:** I acknowledged the context of the file being part of a larger series, implying a focus on array/element access within the broader graph-building process.

12. **Review and Edit:** I reviewed the summary and examples for clarity, accuracy, and conciseness. I ensured the language was accessible and effectively communicated the functionality of the C++ code. I double-checked that the JavaScript examples aligned with the C++ operations.

Essentially, my process involved a top-down and bottom-up approach: starting with the overall purpose hinted at by the file name and class, then drilling down into the individual functions to understand the specific operations, and finally connecting these back to high-level JavaScript concepts and providing illustrative examples. The iterative refinement was crucial to ensure accuracy and completeness.
This C++ source code file, `maglev-graph-builder.cc`, which is part 4 of 9, focuses on building **Maglev graph nodes related to accessing and manipulating elements within JavaScript arrays and typed arrays.**  It provides the functionality to create instructions for loading and storing elements in various array representations used by the V8 JavaScript engine.

Here's a breakdown of its key functionalities:

**Core Functionality:**

* **Loading and Storing Array Elements:**
    * **Fixed Arrays (Tagged):**  Provides functions (`BuildLoadFixedArrayElement`, `BuildStoreFixedArrayElement`) to load and store elements in standard JavaScript arrays (which V8 often represents internally as `FixedArray`). It handles write barriers for proper garbage collection.
    * **Fixed Double Arrays:** Offers similar functions (`BuildLoadFixedDoubleArrayElement`, `BuildStoreFixedDoubleArrayElement`) for arrays specifically containing double-precision floating-point numbers.
    * **Holey Fixed Double Arrays:** Includes functions (`BuildLoadHoleyFixedDoubleArrayElement`) to load elements from arrays that might contain "holes" (uninitialized values). It also has a variation to check if the loaded value is not a hole.
    * **Typed Arrays:** Provides functions (`BuildLoadTypedArrayElement`, `BuildStoreTypedArrayElement`) for accessing elements in various typed array formats (e.g., `Int8Array`, `Uint32Array`, `Float64Array`). It handles clamping for `Uint8ClampedArray`.
* **Handling Array Length:** Includes functions (`BuildLoadFixedArrayLength`, `BuildLoadJSArrayLength`, `BuildLoadTypedArrayLength`) to retrieve the length of different array types.
* **Optimizations:**
    * **Constant Folding:** Attempts to optimize element loads if the array and index are known constants at compile time, directly returning the constant value.
    * **Object Change Tracking:**  Uses `CanTrackObjectChanges` to determine if the structure of the array is stable enough to perform optimizations.
    * **Hole Handling:**  Provides logic to treat "holes" as `undefined` in certain scenarios, improving performance.
* **Type Checking and Assertions:**  Includes checks (`BuildCheckNotHole`, `BuildCheckMaps`, `BuildCheckString`, `BuildCheckNumber`, `BuildCheckInt32Condition`, `BuildCheckTypedArrayNotDetached`, `BuildCheckTypedArrayBounds`) to ensure the integrity of operations and trigger deoptimization if assumptions are violated.
* **Property Access (Indirectly related to array-like objects):** Contains functions (`TryBuildPropertyLoad`, `TryBuildPropertyStore`, `TryBuildPropertyAccess`) that are more generally for accessing properties of objects, but these can be invoked for array-like objects as well (e.g., accessing the `length` property).
* **Polymorphic Access Handling:**  Includes logic (`TryBuildPolymorphicElementAccess`, `TryBuildPolymorphicPropertyAccess`) to handle cases where the type of the array or object is not statically known, generating code that can handle multiple possible types.
* **Inline Caching (IC) Integration:** Functions like `TryBuildNamedAccess` and `TryBuildElementAccess` interact with inline caches to optimize property and element access based on runtime feedback.

**Relationship to JavaScript and Examples:**

This C++ code is a crucial part of how V8 compiles JavaScript code into efficient machine code. The functions in this file directly translate JavaScript array and object manipulation operations into low-level instructions in the Maglev intermediate representation.

Here are some JavaScript examples that would likely involve the code in this file:

**1. Accessing elements in a regular JavaScript array:**

```javascript
const arr = [1, 2.5, "hello"];
const firstElement = arr[0];  // Would involve BuildLoadFixedArrayElement (potentially)
const secondElement = arr[1]; // Would involve BuildLoadFixedArrayElement (potentially)
```

**2. Modifying elements in a regular JavaScript array:**

```javascript
const arr = [1, 2, 3];
arr[1] = 4; // Would involve BuildStoreFixedArrayElement
```

**3. Accessing elements in a typed array:**

```javascript
const typedArray = new Uint32Array([10, 20, 30]);
const firstValue = typedArray[0]; // Would involve BuildLoadTypedArrayElement
```

**4. Modifying elements in a typed array:**

```javascript
const typedArray = new Float64Array(3);
typedArray[1] = 3.14; // Would involve BuildStoreTypedArrayElement
```

**5. Accessing the `length` property of an array:**

```javascript
const arr = [1, 2, 3];
const len = arr.length; // Would involve BuildLoadJSArrayLength
```

**6. Accessing an element that might be a "hole":**

```javascript
const arr = new Array(5); // Creates a sparse array with holes
const element = arr[2];    // Would involve BuildLoadFixedArrayElement and potentially hole handling logic
```

**In summary, this file is a core component of V8's Maglev compiler, responsible for generating the low-level instructions needed to efficiently interact with JavaScript arrays and array-like objects.** It handles various array types, optimizations, and safety checks to ensure correct and performant execution of JavaScript code. The "part 4 of 9" suggests it's a specific module within the larger graph-building process, focusing on array/element manipulation.

Prompt: 
```
这是目录为v8/src/maglev/maglev-graph-builder.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共9部分，请归纳一下它的功能

"""
de<StoreFixedArrayElementNoWriteBarrier>({elements, index, value});
  } else {
    AddNewNode<StoreFixedArrayElementWithWriteBarrier>(
        {elements, index, value});
  }
}

ValueNode* MaglevGraphBuilder::BuildLoadFixedDoubleArrayElement(
    ValueNode* elements, int index) {
  if (CanTrackObjectChanges(elements, TrackObjectMode::kLoad)) {
    VirtualObject* vobject =
        GetObjectFromAllocation(elements->Cast<InlinedAllocation>());
    compiler::FixedDoubleArrayRef elements_array = vobject->double_elements();
    if (index >= 0 && static_cast<uint32_t>(index) < elements_array.length()) {
      Float64 value = elements_array.GetFromImmutableFixedDoubleArray(index);
      return GetFloat64Constant(value.get_scalar());
    } else {
      return GetRootConstant(RootIndex::kTheHoleValue);
    }
  }
  if (index < 0 || index >= FixedArray::kMaxLength) {
    return GetRootConstant(RootIndex::kTheHoleValue);
  }
  return AddNewNode<LoadFixedDoubleArrayElement>(
      {elements, GetInt32Constant(index)});
}

ValueNode* MaglevGraphBuilder::BuildLoadFixedDoubleArrayElement(
    ValueNode* elements, ValueNode* index) {
  if (auto constant = TryGetInt32Constant(index)) {
    return BuildLoadFixedDoubleArrayElement(elements, constant.value());
  }
  return AddNewNode<LoadFixedDoubleArrayElement>({elements, index});
}

void MaglevGraphBuilder::BuildStoreFixedDoubleArrayElement(ValueNode* elements,
                                                           ValueNode* index,
                                                           ValueNode* value) {
  // TODO(victorgomes): Support storing double element to a virtual object.
  AddNewNode<StoreFixedDoubleArrayElement>({elements, index, value});
}

ValueNode* MaglevGraphBuilder::BuildLoadHoleyFixedDoubleArrayElement(
    ValueNode* elements, ValueNode* index, bool convert_hole) {
  if (convert_hole) {
    return AddNewNode<LoadHoleyFixedDoubleArrayElement>({elements, index});
  } else {
    return AddNewNode<LoadHoleyFixedDoubleArrayElementCheckedNotHole>(
        {elements, index});
  }
}

bool MaglevGraphBuilder::CanTreatHoleAsUndefined(
    base::Vector<const compiler::MapRef> const& receiver_maps) {
  // Check if all {receiver_maps} have one of the initial Array.prototype
  // or Object.prototype objects as their prototype (in any of the current
  // native contexts, as the global Array protector works isolate-wide).
  for (compiler::MapRef receiver_map : receiver_maps) {
    compiler::ObjectRef receiver_prototype = receiver_map.prototype(broker());
    if (!receiver_prototype.IsJSObject() ||
        !broker()->IsArrayOrObjectPrototype(receiver_prototype.AsJSObject())) {
      return false;
    }
  }

  // Check if the array prototype chain is intact.
  return broker()->dependencies()->DependOnNoElementsProtector();
}

compiler::OptionalObjectRef
MaglevGraphBuilder::TryFoldLoadDictPrototypeConstant(
    compiler::PropertyAccessInfo const& access_info) {
  DCHECK(V8_DICT_PROPERTY_CONST_TRACKING_BOOL);
  DCHECK(access_info.IsDictionaryProtoDataConstant());
  DCHECK(access_info.holder().has_value());

  compiler::OptionalObjectRef constant =
      access_info.holder()->GetOwnDictionaryProperty(
          broker(), access_info.dictionary_index(), broker()->dependencies());
  if (!constant.has_value()) return {};

  for (compiler::MapRef map : access_info.lookup_start_object_maps()) {
    DirectHandle<Map> map_handle = map.object();
    // Non-JSReceivers that passed AccessInfoFactory::ComputePropertyAccessInfo
    // must have different lookup start map.
    if (!IsJSReceiverMap(*map_handle)) {
      // Perform the implicit ToObject for primitives here.
      // Implemented according to ES6 section 7.3.2 GetV (V, P).
      Tagged<JSFunction> constructor =
          Map::GetConstructorFunction(
              *map_handle, *broker()->target_native_context().object())
              .value();
      // {constructor.initial_map()} is loaded/stored with acquire-release
      // semantics for constructors.
      map = MakeRefAssumeMemoryFence(broker(), constructor->initial_map());
      DCHECK(IsJSObjectMap(*map.object()));
    }
    broker()->dependencies()->DependOnConstantInDictionaryPrototypeChain(
        map, access_info.name(), constant.value(), PropertyKind::kData);
  }

  return constant;
}

compiler::OptionalJSObjectRef MaglevGraphBuilder::TryGetConstantDataFieldHolder(
    compiler::PropertyAccessInfo const& access_info,
    ValueNode* lookup_start_object) {
  if (!access_info.IsFastDataConstant()) return {};
  if (access_info.holder().has_value()) {
    return access_info.holder();
  }
  if (compiler::OptionalHeapObjectRef c = TryGetConstant(lookup_start_object)) {
    if (c.value().IsJSObject()) {
      return c.value().AsJSObject();
    }
  }
  return {};
}

compiler::OptionalObjectRef MaglevGraphBuilder::TryFoldLoadConstantDataField(
    compiler::JSObjectRef holder,
    compiler::PropertyAccessInfo const& access_info) {
  DCHECK(!access_info.field_representation().IsDouble());
  return holder.GetOwnFastConstantDataProperty(
      broker(), access_info.field_representation(), access_info.field_index(),
      broker()->dependencies());
}

std::optional<Float64> MaglevGraphBuilder::TryFoldLoadConstantDoubleField(
    compiler::JSObjectRef holder,
    compiler::PropertyAccessInfo const& access_info) {
  DCHECK(access_info.field_representation().IsDouble());
  return holder.GetOwnFastConstantDoubleProperty(
      broker(), access_info.field_index(), broker()->dependencies());
}

ReduceResult MaglevGraphBuilder::TryBuildPropertyGetterCall(
    compiler::PropertyAccessInfo const& access_info, ValueNode* receiver,
    ValueNode* lookup_start_object) {
  compiler::ObjectRef constant = access_info.constant().value();

  if (access_info.IsDictionaryProtoAccessorConstant()) {
    // For fast mode holders we recorded dependencies in BuildPropertyLoad.
    for (const compiler::MapRef map : access_info.lookup_start_object_maps()) {
      broker()->dependencies()->DependOnConstantInDictionaryPrototypeChain(
          map, access_info.name(), constant, PropertyKind::kAccessor);
    }
  }

  // Introduce the call to the getter function.
  if (constant.IsJSFunction()) {
    ConvertReceiverMode receiver_mode =
        receiver == lookup_start_object
            ? ConvertReceiverMode::kNotNullOrUndefined
            : ConvertReceiverMode::kAny;
    CallArguments args(receiver_mode, {receiver});
    return ReduceCallForConstant(constant.AsJSFunction(), args);
  } else {
    // Disable optimizations for super ICs using API getters, so that we get
    // the correct receiver checks.
    if (receiver != lookup_start_object) {
      return ReduceResult::Fail();
    }
    compiler::FunctionTemplateInfoRef templ = constant.AsFunctionTemplateInfo();
    CallArguments args(ConvertReceiverMode::kNotNullOrUndefined, {receiver});

    return ReduceCallForApiFunction(templ, {}, access_info.api_holder(), args);
  }
}

ReduceResult MaglevGraphBuilder::TryBuildPropertySetterCall(
    compiler::PropertyAccessInfo const& access_info, ValueNode* receiver,
    ValueNode* lookup_start_object, ValueNode* value) {
  // Setting super properties shouldn't end up here.
  DCHECK_EQ(receiver, lookup_start_object);
  compiler::ObjectRef constant = access_info.constant().value();
  if (constant.IsJSFunction()) {
    CallArguments args(ConvertReceiverMode::kNotNullOrUndefined,
                       {receiver, value});
    RETURN_IF_ABORT(ReduceCallForConstant(constant.AsJSFunction(), args));
  } else {
    compiler::FunctionTemplateInfoRef templ = constant.AsFunctionTemplateInfo();
    CallArguments args(ConvertReceiverMode::kNotNullOrUndefined,
                       {receiver, value});
    RETURN_IF_ABORT(
        ReduceCallForApiFunction(templ, {}, access_info.api_holder(), args));
  }
  // Ignore the return value of the setter call.
  return ReduceResult::Done();
}

ValueNode* MaglevGraphBuilder::BuildLoadField(
    compiler::PropertyAccessInfo const& access_info,
    ValueNode* lookup_start_object, compiler::NameRef name) {
  compiler::OptionalJSObjectRef constant_holder =
      TryGetConstantDataFieldHolder(access_info, lookup_start_object);
  if (constant_holder) {
    if (access_info.field_representation().IsDouble()) {
      std::optional<Float64> constant =
          TryFoldLoadConstantDoubleField(constant_holder.value(), access_info);
      if (constant.has_value()) {
        return GetFloat64Constant(constant.value());
      }
    } else {
      compiler::OptionalObjectRef constant =
          TryFoldLoadConstantDataField(constant_holder.value(), access_info);
      if (constant.has_value()) {
        return GetConstant(constant.value());
      }
    }
  }
  // Resolve property holder.
  ValueNode* load_source;
  if (access_info.holder().has_value()) {
    load_source = GetConstant(access_info.holder().value());
  } else {
    load_source = lookup_start_object;
  }

  FieldIndex field_index = access_info.field_index();
  if (!field_index.is_inobject()) {
    // The field is in the property array, first load it from there.
    load_source =
        BuildLoadTaggedField(load_source, JSReceiver::kPropertiesOrHashOffset);
  }

  // Do the load.
  if (field_index.is_double()) {
    return AddNewNode<LoadDoubleField>({load_source}, field_index.offset());
  }
  ValueNode* value = BuildLoadTaggedField<LoadTaggedFieldForProperty>(
      load_source, field_index.offset(), name);
  // Insert stable field information if present.
  if (access_info.field_representation().IsSmi()) {
    NodeInfo* known_info = GetOrCreateInfoFor(value);
    known_info->CombineType(NodeType::kSmi);
  } else if (access_info.field_representation().IsHeapObject()) {
    NodeInfo* known_info = GetOrCreateInfoFor(value);
    if (access_info.field_map().has_value() &&
        access_info.field_map().value().is_stable()) {
      DCHECK(access_info.field_map().value().IsJSReceiverMap());
      auto map = access_info.field_map().value();
      known_info->SetPossibleMaps(PossibleMaps{map}, false,
                                  StaticTypeForMap(map, broker()), broker());
      broker()->dependencies()->DependOnStableMap(map);
    } else {
      known_info->CombineType(NodeType::kAnyHeapObject);
    }
  }
  return value;
}

ValueNode* MaglevGraphBuilder::BuildLoadFixedArrayLength(
    ValueNode* fixed_array) {
  ValueNode* length =
      BuildLoadTaggedField(fixed_array, offsetof(FixedArray, length_));
  EnsureType(length, NodeType::kSmi);
  return length;
}

ValueNode* MaglevGraphBuilder::BuildLoadJSArrayLength(ValueNode* js_array,
                                                      NodeType length_type) {
  // TODO(leszeks): JSArray.length is known to be non-constant, don't bother
  // searching the constant values.
  ReduceResult known_length =
      TryReuseKnownPropertyLoad(js_array, broker()->length_string());
  if (known_length.IsDone()) {
    DCHECK(known_length.IsDoneWithValue());
    return known_length.value();
  }

  ValueNode* length = BuildLoadTaggedField<LoadTaggedFieldForProperty>(
      js_array, JSArray::kLengthOffset, broker()->length_string());
  GetOrCreateInfoFor(length)->CombineType(length_type);
  RecordKnownProperty(js_array, broker()->length_string(), length, false,
                      compiler::AccessMode::kLoad);
  return length;
}

void MaglevGraphBuilder::BuildStoreMap(ValueNode* object, compiler::MapRef map,
                                       StoreMap::Kind kind) {
  AddNewNode<StoreMap>({object}, map, kind);
  NodeType object_type = StaticTypeForMap(map, broker());
  NodeInfo* node_info = GetOrCreateInfoFor(object);
  if (map.is_stable()) {
    node_info->SetPossibleMaps(PossibleMaps{map}, false, object_type, broker());
    broker()->dependencies()->DependOnStableMap(map);
  } else {
    node_info->SetPossibleMaps(PossibleMaps{map}, true, object_type, broker());
    known_node_aspects().any_map_for_any_node_is_unstable = true;
  }
}

ValueNode* MaglevGraphBuilder::BuildExtendPropertiesBackingStore(
    compiler::MapRef map, ValueNode* receiver, ValueNode* property_array) {
  int length = map.NextFreePropertyIndex() - map.GetInObjectProperties();
  // Under normal circumstances, NextFreePropertyIndex() will always be larger
  // than GetInObjectProperties(). However, an attacker able to corrupt heap
  // memory can break this invariant, in which case we'll get confused here,
  // potentially causing a sandbox violation. This CHECK defends against that.
  SBXCHECK_GE(length, 0);
  return AddNewNode<ExtendPropertiesBackingStore>({property_array, receiver},
                                                  length);
}

ReduceResult MaglevGraphBuilder::TryBuildStoreField(
    compiler::PropertyAccessInfo const& access_info, ValueNode* receiver,
    compiler::AccessMode access_mode) {
  FieldIndex field_index = access_info.field_index();
  Representation field_representation = access_info.field_representation();

  compiler::OptionalMapRef original_map;
  if (access_info.HasTransitionMap()) {
    compiler::MapRef transition = access_info.transition_map().value();
    original_map = transition.GetBackPointer(broker()).AsMap();

    if (original_map->UnusedPropertyFields() == 0) {
      DCHECK(!field_index.is_inobject());
    }
    if (!field_index.is_inobject()) {
      // If slack tracking ends after this compilation started but before it's
      // finished, then {original_map} could be out-of-sync with {transition}.
      // In particular, its UnusedPropertyFields could be non-zero, which would
      // lead us to not extend the property backing store, while the underlying
      // Map has actually zero UnusedPropertyFields. Thus, we install a
      // dependency on {orininal_map} now, so that if such a situation happens,
      // we'll throw away the code.
      broker()->dependencies()->DependOnNoSlackTrackingChange(*original_map);
    }
  } else if (access_info.IsFastDataConstant() &&
             access_mode == compiler::AccessMode::kStore) {
    return EmitUnconditionalDeopt(DeoptimizeReason::kStoreToConstant);
  }

  ValueNode* store_target;
  if (field_index.is_inobject()) {
    store_target = receiver;
  } else {
    // The field is in the property array, first load it from there.
    store_target =
        BuildLoadTaggedField(receiver, JSReceiver::kPropertiesOrHashOffset);
    if (original_map && original_map->UnusedPropertyFields() == 0) {
      store_target = BuildExtendPropertiesBackingStore(*original_map, receiver,
                                                       store_target);
    }
  }

  if (field_representation.IsDouble()) {
    ValueNode* float64_value = GetAccumulator();
    if (access_info.HasTransitionMap()) {
      // Allocate the mutable double box owned by the field.
      ValueNode* value =
          AddNewNode<Float64ToHeapNumberForField>({float64_value});
      BuildStoreTaggedField(store_target, value, field_index.offset(),
                            StoreTaggedMode::kTransitioning);
      BuildStoreMap(receiver, access_info.transition_map().value(),
                    StoreMap::Kind::kTransitioning);
    } else {
      AddNewNode<StoreDoubleField>({store_target, float64_value},
                                   field_index.offset());
    }
    return ReduceResult::Done();
  }

  ValueNode* value = GetAccumulator();
  if (field_representation.IsSmi()) {
    RETURN_IF_ABORT(GetAccumulatorSmi());
  } else {
    if (field_representation.IsHeapObject()) {
      // Emit a map check for the field type, if needed, otherwise just a
      // HeapObject check.
      if (access_info.field_map().has_value()) {
        RETURN_IF_ABORT(BuildCheckMaps(
            value, base::VectorOf({access_info.field_map().value()})));
      } else {
        BuildCheckHeapObject(value);
      }
    }
  }

  StoreTaggedMode store_mode = access_info.HasTransitionMap()
                                   ? StoreTaggedMode::kTransitioning
                                   : StoreTaggedMode::kDefault;
  if (field_representation.IsSmi()) {
    BuildStoreTaggedFieldNoWriteBarrier(store_target, value,
                                        field_index.offset(), store_mode);
  } else {
    DCHECK(field_representation.IsHeapObject() ||
           field_representation.IsTagged());
    BuildStoreTaggedField(store_target, value, field_index.offset(),
                          store_mode);
  }
  if (access_info.HasTransitionMap()) {
    BuildStoreMap(receiver, access_info.transition_map().value(),
                  StoreMap::Kind::kTransitioning);
  }

  return ReduceResult::Done();
}

namespace {
bool AccessInfoGuaranteedConst(
    compiler::PropertyAccessInfo const& access_info) {
  if (!access_info.IsFastDataConstant() && !access_info.IsStringLength()) {
    return false;
  }

  // Even if we have a constant load, if the map is not stable, we cannot
  // guarantee that the load is preserved across side-effecting calls.
  // TODO(v8:7700): It might be possible to track it as const if we know
  // that we're still on the main transition tree; and if we add a
  // dependency on the stable end-maps of the entire tree.
  for (auto& map : access_info.lookup_start_object_maps()) {
    if (!map.is_stable()) {
      return false;
    }
  }
  return true;
}
}  // namespace

ReduceResult MaglevGraphBuilder::TryBuildPropertyLoad(
    ValueNode* receiver, ValueNode* lookup_start_object, compiler::NameRef name,
    compiler::PropertyAccessInfo const& access_info) {
  if (access_info.holder().has_value() && !access_info.HasDictionaryHolder()) {
    broker()->dependencies()->DependOnStablePrototypeChains(
        access_info.lookup_start_object_maps(), kStartAtPrototype,
        access_info.holder().value());
  }

  switch (access_info.kind()) {
    case compiler::PropertyAccessInfo::kInvalid:
      UNREACHABLE();
    case compiler::PropertyAccessInfo::kNotFound:
      return GetRootConstant(RootIndex::kUndefinedValue);
    case compiler::PropertyAccessInfo::kDataField:
    case compiler::PropertyAccessInfo::kFastDataConstant: {
      ValueNode* result =
          BuildLoadField(access_info, lookup_start_object, name);
      RecordKnownProperty(lookup_start_object, name, result,
                          AccessInfoGuaranteedConst(access_info),
                          compiler::AccessMode::kLoad);
      return result;
    }
    case compiler::PropertyAccessInfo::kDictionaryProtoDataConstant: {
      compiler::OptionalObjectRef constant =
          TryFoldLoadDictPrototypeConstant(access_info);
      if (!constant.has_value()) return ReduceResult::Fail();
      return GetConstant(constant.value());
    }
    case compiler::PropertyAccessInfo::kFastAccessorConstant:
    case compiler::PropertyAccessInfo::kDictionaryProtoAccessorConstant:
      return TryBuildPropertyGetterCall(access_info, receiver,
                                        lookup_start_object);
    case compiler::PropertyAccessInfo::kModuleExport: {
      ValueNode* cell = GetConstant(access_info.constant().value().AsCell());
      return BuildLoadTaggedField<LoadTaggedFieldForProperty>(
          cell, Cell::kValueOffset, name);
    }
    case compiler::PropertyAccessInfo::kStringLength: {
      DCHECK_EQ(receiver, lookup_start_object);
      ValueNode* result = BuildLoadStringLength(receiver);
      RecordKnownProperty(lookup_start_object, name, result,
                          AccessInfoGuaranteedConst(access_info),
                          compiler::AccessMode::kLoad);
      return result;
    }
    case compiler::PropertyAccessInfo::kStringWrapperLength: {
      // TODO(dmercadier): update KnownNodeInfo.
      ValueNode* string = BuildLoadTaggedField(
          lookup_start_object, JSPrimitiveWrapper::kValueOffset);
      return AddNewNode<StringLength>({string});
    }
  }
}

ReduceResult MaglevGraphBuilder::TryBuildPropertyStore(
    ValueNode* receiver, ValueNode* lookup_start_object, compiler::NameRef name,
    compiler::PropertyAccessInfo const& access_info,
    compiler::AccessMode access_mode) {
  if (access_info.holder().has_value()) {
    broker()->dependencies()->DependOnStablePrototypeChains(
        access_info.lookup_start_object_maps(), kStartAtPrototype,
        access_info.holder().value());
  }

  switch (access_info.kind()) {
    case compiler::PropertyAccessInfo::kFastAccessorConstant: {
      return TryBuildPropertySetterCall(access_info, receiver,
                                        lookup_start_object, GetAccumulator());
    }
    case compiler::PropertyAccessInfo::kDataField:
    case compiler::PropertyAccessInfo::kFastDataConstant: {
      ReduceResult res = TryBuildStoreField(access_info, receiver, access_mode);
      if (res.IsDone()) {
        RecordKnownProperty(
            receiver, name, current_interpreter_frame_.accumulator(),
            AccessInfoGuaranteedConst(access_info), access_mode);
        return res;
      }
      return ReduceResult::Fail();
    }
    case compiler::PropertyAccessInfo::kInvalid:
    case compiler::PropertyAccessInfo::kNotFound:
    case compiler::PropertyAccessInfo::kDictionaryProtoDataConstant:
    case compiler::PropertyAccessInfo::kDictionaryProtoAccessorConstant:
    case compiler::PropertyAccessInfo::kModuleExport:
    case compiler::PropertyAccessInfo::kStringLength:
    case compiler::PropertyAccessInfo::kStringWrapperLength:
      UNREACHABLE();
  }
}

ReduceResult MaglevGraphBuilder::TryBuildPropertyAccess(
    ValueNode* receiver, ValueNode* lookup_start_object, compiler::NameRef name,
    compiler::PropertyAccessInfo const& access_info,
    compiler::AccessMode access_mode) {
  switch (access_mode) {
    case compiler::AccessMode::kLoad:
      return TryBuildPropertyLoad(receiver, lookup_start_object, name,
                                  access_info);
    case compiler::AccessMode::kStore:
    case compiler::AccessMode::kStoreInLiteral:
    case compiler::AccessMode::kDefine:
      DCHECK_EQ(receiver, lookup_start_object);
      return TryBuildPropertyStore(receiver, lookup_start_object, name,
                                   access_info, access_mode);
    case compiler::AccessMode::kHas:
      // TODO(victorgomes): BuildPropertyTest.
      return ReduceResult::Fail();
  }
}

template <typename GenericAccessFunc>
ReduceResult MaglevGraphBuilder::TryBuildNamedAccess(
    ValueNode* receiver, ValueNode* lookup_start_object,
    compiler::NamedAccessFeedback const& feedback,
    compiler::FeedbackSource const& feedback_source,
    compiler::AccessMode access_mode,
    GenericAccessFunc&& build_generic_access) {
  compiler::ZoneRefSet<Map> inferred_maps;

  if (compiler::OptionalHeapObjectRef c = TryGetConstant(lookup_start_object)) {
    compiler::MapRef constant_map = c.value().map(broker());
    if (c.value().IsJSFunction() &&
        feedback.name().equals(broker()->prototype_string())) {
      compiler::JSFunctionRef function = c.value().AsJSFunction();
      if (!constant_map.has_prototype_slot() ||
          !function.has_instance_prototype(broker()) ||
          function.PrototypeRequiresRuntimeLookup(broker()) ||
          access_mode != compiler::AccessMode::kLoad) {
        return ReduceResult::Fail();
      }
      compiler::HeapObjectRef prototype =
          broker()->dependencies()->DependOnPrototypeProperty(function);
      return GetConstant(prototype);
    }
    inferred_maps = compiler::ZoneRefSet<Map>(constant_map);
  } else if (feedback.maps().empty()) {
    // The IC is megamorphic.

    // We can't do megamorphic loads for lookups where the lookup start isn't
    // the receiver (e.g. load from super).
    if (receiver != lookup_start_object) return ReduceResult::Fail();

    // Use known possible maps if we have any.
    NodeInfo* object_info =
        known_node_aspects().TryGetInfoFor(lookup_start_object);
    if (object_info && object_info->possible_maps_are_known()) {
      inferred_maps = object_info->possible_maps();
    } else {
      // If we have no known maps, make the access megamorphic.
      switch (access_mode) {
        case compiler::AccessMode::kLoad:
          return BuildCallBuiltin<Builtin::kLoadIC_Megamorphic>(
              {GetTaggedValue(receiver), GetConstant(feedback.name())},
              feedback_source);
        case compiler::AccessMode::kStore:
          return BuildCallBuiltin<Builtin::kStoreIC_Megamorphic>(
              {GetTaggedValue(receiver), GetConstant(feedback.name()),
               GetTaggedValue(GetAccumulator())},
              feedback_source);
        case compiler::AccessMode::kDefine:
          return ReduceResult::Fail();
        case compiler::AccessMode::kHas:
        case compiler::AccessMode::kStoreInLiteral:
          UNREACHABLE();
      }
    }
  } else {
    // TODO(leszeks): This is doing duplicate work with BuildCheckMaps,
    // consider passing the merger into there.
    KnownMapsMerger merger(broker(), zone(), base::VectorOf(feedback.maps()));
    merger.IntersectWithKnownNodeAspects(lookup_start_object,
                                         known_node_aspects());
    inferred_maps = merger.intersect_set();
  }

  if (inferred_maps.is_empty()) {
    return EmitUnconditionalDeopt(DeoptimizeReason::kWrongMap);
  }

  ZoneVector<compiler::PropertyAccessInfo> access_infos(zone());
  ZoneVector<compiler::PropertyAccessInfo> access_infos_for_feedback(zone());

  for (compiler::MapRef map : inferred_maps) {
    if (map.is_deprecated()) continue;

    // TODO(v8:12547): Support writing to objects in shared space, which
    // need a write barrier that calls Object::Share to ensure the RHS is
    // shared.
    if (InstanceTypeChecker::IsAlwaysSharedSpaceJSObject(map.instance_type()) &&
        access_mode == compiler::AccessMode::kStore) {
      return ReduceResult::Fail();
    }

    compiler::PropertyAccessInfo access_info =
        broker()->GetPropertyAccessInfo(map, feedback.name(), access_mode);
    access_infos_for_feedback.push_back(access_info);
  }

  compiler::AccessInfoFactory access_info_factory(broker(), zone());
  if (!access_info_factory.FinalizePropertyAccessInfos(
          access_infos_for_feedback, access_mode, &access_infos)) {
    return ReduceResult::Fail();
  }

  // Check for monomorphic case.
  if (access_infos.size() == 1) {
    compiler::PropertyAccessInfo const& access_info = access_infos.front();
    base::Vector<const compiler::MapRef> maps =
        base::VectorOf(access_info.lookup_start_object_maps());
    if (HasOnlyStringMaps(maps)) {
      // Check for string maps before checking if we need to do an access
      // check. Primitive strings always get the prototype from the native
      // context they're operated on, so they don't need the access check.
      BuildCheckString(lookup_start_object);
    } else if (HasOnlyNumberMaps(maps)) {
      BuildCheckNumber(lookup_start_object);
    } else {
      RETURN_IF_ABORT(BuildCheckMaps(lookup_start_object, maps));
    }

    // Generate the actual property
    return TryBuildPropertyAccess(receiver, lookup_start_object,
                                  feedback.name(), access_info, access_mode);
  } else {
    // TODO(victorgomes): Unify control flow logic with
    // TryBuildPolymorphicElementAccess.
    return TryBuildPolymorphicPropertyAccess(
        receiver, lookup_start_object, feedback, access_mode, access_infos,
        build_generic_access);
  }
}

ValueNode* MaglevGraphBuilder::GetInt32ElementIndex(ValueNode* object) {
  RecordUseReprHintIfPhi(object, UseRepresentation::kInt32);

  switch (object->properties().value_representation()) {
    case ValueRepresentation::kIntPtr:
      UNREACHABLE();
    case ValueRepresentation::kTagged:
      NodeType old_type;
      if (SmiConstant* constant = object->TryCast<SmiConstant>()) {
        return GetInt32Constant(constant->value().value());
      } else if (CheckType(object, NodeType::kSmi, &old_type)) {
        auto& alternative = GetOrCreateInfoFor(object)->alternative();
        return alternative.get_or_set_int32(
            [&]() { return BuildSmiUntag(object); });
      } else {
        // TODO(leszeks): Cache this knowledge/converted value somehow on
        // the node info.
        return AddNewNode<CheckedObjectToIndex>({object},
                                                GetCheckType(old_type));
      }
    case ValueRepresentation::kInt32:
      // Already good.
      return object;
    case ValueRepresentation::kUint32:
    case ValueRepresentation::kFloat64:
    case ValueRepresentation::kHoleyFloat64:
      return GetInt32(object);
  }
}

// TODO(victorgomes): Consider caching the values and adding an
// uint32_alternative in node_info.
ReduceResult MaglevGraphBuilder::GetUint32ElementIndex(ValueNode* object) {
  // Don't record a Uint32 Phi use here, since the tagged path goes via
  // GetInt32ElementIndex, making this an Int32 Phi use.

  switch (object->properties().value_representation()) {
    case ValueRepresentation::kIntPtr:
      UNREACHABLE();
    case ValueRepresentation::kTagged:
      // TODO(victorgomes): Consider creating a CheckedObjectToUnsignedIndex.
      if (SmiConstant* constant = object->TryCast<SmiConstant>()) {
        int32_t value = constant->value().value();
        if (value < 0) {
          return EmitUnconditionalDeopt(DeoptimizeReason::kNotUint32);
        }
        return GetUint32Constant(value);
      }
      return AddNewNode<CheckedInt32ToUint32>({GetInt32ElementIndex(object)});
    case ValueRepresentation::kInt32:
      if (Int32Constant* constant = object->TryCast<Int32Constant>()) {
        int32_t value = constant->value();
        if (value < 0) {
          return EmitUnconditionalDeopt(DeoptimizeReason::kNotUint32);
        }
        return GetUint32Constant(value);
      }
      return AddNewNode<CheckedInt32ToUint32>({object});
    case ValueRepresentation::kUint32:
      return object;
    case ValueRepresentation::kFloat64:
      if (Float64Constant* constant = object->TryCast<Float64Constant>()) {
        double value = constant->value().get_scalar();
        uint32_t uint32_value;
        if (!DoubleToUint32IfEqualToSelf(value, &uint32_value)) {
          return EmitUnconditionalDeopt(DeoptimizeReason::kNotUint32);
        }
        if (Smi::IsValid(uint32_value)) {
          return GetUint32Constant(uint32_value);
        }
      }
      [[fallthrough]];
    case ValueRepresentation::kHoleyFloat64: {
      // CheckedTruncateFloat64ToUint32 will gracefully deopt on holes.
      return AddNewNode<CheckedTruncateFloat64ToUint32>({object});
    }
  }
}

ReduceResult MaglevGraphBuilder::TryBuildElementAccessOnString(
    ValueNode* object, ValueNode* index_object,
    compiler::KeyedAccessMode const& keyed_mode) {
  // Strings are immutable and `in` cannot be used on strings
  if (keyed_mode.access_mode() != compiler::AccessMode::kLoad) {
    return ReduceResult::Fail();
  }

  // Ensure that {object} is actually a String.
  BuildCheckString(object);

  ValueNode* length = BuildLoadStringLength(object);
  ValueNode* index = GetInt32ElementIndex(index_object);
  auto emit_load = [&] { return AddNewNode<StringAt>({object, index}); };

  if (LoadModeHandlesOOB(keyed_mode.load_mode()) &&
      broker()->dependencies()->DependOnNoElementsProtector()) {
    ValueNode* positive_index;
    GET_VALUE_OR_ABORT(positive_index, GetUint32ElementIndex(index));
    ValueNode* uint32_length = AddNewNode<UnsafeInt32ToUint32>({length});
    return Select(
        [&](auto& builder) {
          return BuildBranchIfUint32Compare(builder, Operation::kLessThan,
                                            positive_index, uint32_length);
        },
        emit_load, [&] { return GetRootConstant(RootIndex::kUndefinedValue); });
  } else {
    RETURN_IF_ABORT(TryBuildCheckInt32Condition(
        index, length, AssertCondition::kUnsignedLessThan,
        DeoptimizeReason::kOutOfBounds));
    return emit_load();
  }
}

namespace {
ReduceResult TryFindLoadedProperty(
    const KnownNodeAspects::LoadedPropertyMap& loaded_properties,
    ValueNode* lookup_start_object,
    KnownNodeAspects::LoadedPropertyMapKey name) {
  auto props_for_name = loaded_properties.find(name);
  if (props_for_name == loaded_properties.end()) return ReduceResult::Fail();

  auto it = props_for_name->second.find(lookup_start_object);
  if (it == props_for_name->second.end()) return ReduceResult::Fail();

  return it->second;
}

bool CheckConditionIn32(int32_t lhs, int32_t rhs, AssertCondition condition) {
  switch (condition) {
    case AssertCondition::kEqual:
      return lhs == rhs;
    case AssertCondition::kNotEqual:
      return lhs != rhs;
    case AssertCondition::kLessThan:
      return lhs < rhs;
    case AssertCondition::kLessThanEqual:
      return lhs <= rhs;
    case AssertCondition::kGreaterThan:
      return lhs > rhs;
    case AssertCondition::kGreaterThanEqual:
      return lhs >= rhs;
    case AssertCondition::kUnsignedLessThan:
      return static_cast<uint32_t>(lhs) < static_cast<uint32_t>(rhs);
    case AssertCondition::kUnsignedLessThanEqual:
      return static_cast<uint32_t>(lhs) <= static_cast<uint32_t>(rhs);
    case AssertCondition::kUnsignedGreaterThan:
      return static_cast<uint32_t>(lhs) > static_cast<uint32_t>(rhs);
    case AssertCondition::kUnsignedGreaterThanEqual:
      return static_cast<uint32_t>(lhs) >= static_cast<uint32_t>(rhs);
  }
}

bool CompareInt32(int32_t lhs, int32_t rhs, Operation operation) {
  switch (operation) {
    case Operation::kEqual:
    case Operation::kStrictEqual:
      return lhs == rhs;
    case Operation::kLessThan:
      return lhs < rhs;
    case Operation::kLessThanOrEqual:
      return lhs <= rhs;
    case Operation::kGreaterThan:
      return lhs > rhs;
    case Operation::kGreaterThanOrEqual:
      return lhs >= rhs;
    default:
      UNREACHABLE();
  }
}

bool CompareUint32(uint32_t lhs, uint32_t rhs, Operation operation) {
  switch (operation) {
    case Operation::kEqual:
    case Operation::kStrictEqual:
      return lhs == rhs;
    case Operation::kLessThan:
      return lhs < rhs;
    case Operation::kLessThanOrEqual:
      return lhs <= rhs;
    case Operation::kGreaterThan:
      return lhs > rhs;
    case Operation::kGreaterThanOrEqual:
      return lhs >= rhs;
    default:
      UNREACHABLE();
  }
}

}  // namespace

ReduceResult MaglevGraphBuilder::TryBuildCheckInt32Condition(
    ValueNode* lhs, ValueNode* rhs, AssertCondition condition,
    DeoptimizeReason reason) {
  auto lhs_const = TryGetInt32Constant(lhs);
  if (lhs_const) {
    auto rhs_const = TryGetInt32Constant(rhs);
    if (rhs_const) {
      if (CheckConditionIn32(lhs_const.value(), rhs_const.value(), condition)) {
        return ReduceResult::Done();
      }
      return EmitUnconditionalDeopt(reason);
    }
  }
  AddNewNode<CheckInt32Condition>({lhs, rhs}, condition, reason);
  return ReduceResult::Done();
}

ValueNode* MaglevGraphBuilder::BuildLoadElements(ValueNode* object) {
  ReduceResult known_elements =
      TryFindLoadedProperty(known_node_aspects().loaded_properties, object,
                            KnownNodeAspects::LoadedPropertyMapKey::Elements());
  if (known_elements.IsDone()) {
    DCHECK(known_elements.IsDoneWithValue());
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  * Reusing non-constant [Elements] "
                << PrintNodeLabel(graph_labeller(), known_elements.value())
                << ": " << PrintNode(graph_labeller(), known_elements.value())
                << std::endl;
    }
    return known_elements.value();
  }

  DCHECK_EQ(JSObject::kElementsOffset, JSArray::kElementsOffset);
  ValueNode* elements = BuildLoadTaggedField(object, JSObject::kElementsOffset);
  RecordKnownProperty(object,
                      KnownNodeAspects::LoadedPropertyMapKey::Elements(),
                      elements, false, compiler::AccessMode::kLoad);
  return elements;
}

ReduceResult MaglevGraphBuilder::BuildLoadTypedArrayLength(
    ValueNode* object, ElementsKind elements_kind) {
  DCHECK(IsTypedArrayOrRabGsabTypedArrayElementsKind(elements_kind));
  bool is_variable_length = IsRabGsabTypedArrayElementsKind(elements_kind);

  if (!is_variable_length) {
    // Note: We can't use broker()->length_string() here, because it could
    // conflict with redefinitions of the TypedArray length property.
    RETURN_IF_DONE(TryFindLoadedProperty(
        known_node_aspects().loaded_constant_properties, object,
        KnownNodeAspects::LoadedPropertyMapKey::TypedArrayLength()));
  }

  ValueNode* result = AddNewNode<LoadTypedArrayLength>({object}, elements_kind);
  if (!is_variable_length) {
    RecordKnownProperty(
        object, KnownNodeAspects::LoadedPropertyMapKey::TypedArrayLength(),
        result, true, compiler::AccessMode::kLoad);
  }
  return result;
}

ValueNode* MaglevGraphBuilder::BuildLoadTypedArrayElement(
    ValueNode* object, ValueNode* index, ElementsKind elements_kind) {
#define BUILD_AND_RETURN_LOAD_TYPED_ARRAY(Type)                     \
  return AddNewNode<Load##Type##TypedArrayElement>({object, index}, \
                                                   elements_kind);

  switch (elements_kind) {
    case INT8_ELEMENTS:
    case INT16_ELEMENTS:
    case INT32_ELEMENTS:
      BUILD_AND_RETURN_LOAD_TYPED_ARRAY(SignedInt);
    case UINT8_CLAMPED_ELEMENTS:
    case UINT8_ELEMENTS:
    case UINT16_ELEMENTS:
    case UINT32_ELEMENTS:
      BUILD_AND_RETURN_LOAD_TYPED_ARRAY(UnsignedInt);
    case FLOAT32_ELEMENTS:
    case FLOAT64_ELEMENTS:
      BUILD_AND_RETURN_LOAD_TYPED_ARRAY(Double);
    default:
      UNREACHABLE();
  }
#undef BUILD_AND_RETURN_LOAD_TYPED_ARRAY
}

void MaglevGraphBuilder::BuildStoreTypedArrayElement(
    ValueNode* object, ValueNode* index, ElementsKind elements_kind) {
#define BUILD_STORE_TYPED_ARRAY(Type, value)                           \
  AddNewNode<Store##Type##TypedArrayElement>({object, index, (value)}, \
                                             elements_kind);

  // TODO(leszeks): These operations have a deopt loop when the ToNumber
  // conversion sees a type other than number or oddball. Turbofan has the same
  // deopt loop, but ideally we'd avoid it.
  switch (elements_kind) {
    case UINT8_CLAMPED_ELEMENTS: {
      BUILD_STORE_TYPED_ARRAY(Int, GetAccumulatorUint8ClampedForToNumber(
                                       ToNumberHint::kAssumeNumberOrOddball))
      break;
    }
    case INT8_ELEMENTS:
    case INT16_ELEMENTS:
    case INT32_ELEMENTS:
    case UINT8_ELEMENTS:
    case UINT16_ELEMENTS:
    case UINT32_ELEMENTS:
      BUILD_STORE_TYPED_ARRAY(Int, GetAccumulatorTruncatedInt32ForToNumber(
                                       ToNumberHint::kAssumeNumberOrOddball))
      break;
    case FLOAT32_ELEMENTS:
    case FLOAT64_ELEMENTS:
      BUILD_STORE_TYPED_ARRAY(Double, GetAccumulatorHoleyFloat64ForToNumber(
                                          ToNumberHint::kAssumeNumberOrOddball))
      break;
    default:
      UNREACHABLE();
  }
#undef BUILD_STORE_TYPED_ARRAY
}

ReduceResult MaglevGraphBuilder::TryBuildElementAccessOnTypedArray(
    ValueNode* object, ValueNode* index_object,
    const compiler::ElementAccessInfo& access_info,
    compiler::KeyedAccessMode const& keyed_mode) {
  DCHECK(HasOnlyJSTypedArrayMaps(
      base::VectorOf(access_info.lookup_start_object_maps())));
  ElementsKind elements_kind = access_info.elements_kind();
  if (elements_kind == FLOAT16_ELEMENTS ||
      elements_kind == BIGUINT64_ELEMENTS ||
      elements_kind == BIGINT64_ELEMENTS) {
    return ReduceResult::Fail();
  }
  if (keyed_mode.access_mode() == compiler::AccessMode::kLoad &&
      LoadModeHandlesOOB(keyed_mode.load_mode())) {
    // TODO(victorgomes): Handle OOB mode.
    return ReduceResult::Fail();
  }
  if (keyed_mode.access_mode() == compiler::AccessMode::kStore &&
      StoreModeIgnoresTypeArrayOOB(keyed_mode.store_mode())) {
    // TODO(victorgomes): Handle OOB mode.
    return ReduceResult::Fail();
  }
  if (keyed_mode.access_mode() == compiler::AccessMode::kStore &&
      elements_kind == UINT8_CLAMPED_ELEMENTS &&
      !IsSupported(CpuOperation::kFloat64Round)) {
    // TODO(victorgomes): Technically we still support if value (in the
    // accumulator) is of type int32. It would be nice to have a roll back
    // mechanism instead, so that we do not need to check this early.
    return ReduceResult::Fail();
  }
  if (!broker()->dependencies()->DependOnArrayBufferDetachingProtector()) {
    // TODO(leszeks): Eliminate this check.
    AddNewNode<CheckTypedArrayNotDetached>({object});
  }
  ValueNode* index;
  ValueNode* length;
  GET_VALUE_OR_ABORT(index, GetUint32ElementIndex(index_object));
  GET_VALUE_OR_ABORT(length, BuildLoadTypedArrayLength(object, elements_kind));
  AddNewNode<CheckTypedArrayBounds>({index, length});
  switch (keyed_mode.access_mode()) {
    case compiler::AccessMode::kLoad:
      DCHECK(!LoadModeHandlesOOB(keyed_mode.load_mode()));
      return BuildLoadTypedArrayElement(object, index, elements_kind);
    case compiler::AccessMode::kStore:
      DCHECK(StoreModeIsInBounds(keyed_mode.store_mode()));
      BuildStoreTypedArrayElement(object, index, elements_kind);
      return ReduceResult::Done();
    case compiler::AccessMode::kHas:
      // TODO(victorgomes): Implement has element access.
      return ReduceResult::Fail();
    case compiler::AccessMode::kStoreInLiteral:
    case compiler::AccessMode::kDefine:
      UNREACHABLE();
  }
}

ReduceResult MaglevGraphBuilder::TryBuildElementLoadOnJSArrayOrJSObject(
    ValueNode* object, ValueNode* index_object,
    base::Vector<const compiler::MapRef> maps, ElementsKind elements_kind,
    KeyedAccessLoadMode load_mode) {
  DCHECK(IsFastElementsKind(elements_kind));
  bool is_jsarray = HasOnlyJSArrayMaps(maps);
  DCHECK(is_jsarray || HasOnlyJSObjectMaps(maps));

  ValueNode* elements_array = BuildLoadElements(object);
  ValueNode* index = GetInt32ElementIndex(index_object);
  ValueNode* length = is_jsarray ? GetInt32(BuildLoadJSArrayLength(object))
                                 : BuildLoadFixedArrayLength(elements_array);

  auto emit_load = [&]() -> ReduceResult {
    ValueNode* result;
    if (elements_kind == HOLEY_DOUBLE_ELEMENTS) {
      result = BuildLoadHoleyFixedDoubleArrayElement(
          elements_array, index,
          CanTreatHoleAsUndefined(maps) && LoadModeHandlesHoles(load_mode));
    } else if (elements_kind == PACKED_DOUBLE_ELEMENTS) {
      result = BuildLoadFixedDoubleArrayElement(elements_array, index);
    } else {
      DCHECK(!IsDoubleElementsKind(elements_kind));
      result = BuildLoadFixedArrayElement(elements_array, index);
      if (IsHoleyElementsKind(elements_kind)) {
        if (CanTreatHoleAsUndefined(maps) && LoadModeHandlesHoles(load_mode)) {
          result = BuildConvertHoleToUndefined(result);
        } else {
          RETURN_IF_ABORT(BuildCheckNotHole(result));
          if (IsSmiElementsKind(elements_kind)) {
            EnsureType(result, NodeType::kSmi);
          }
        }
      } else if (IsSmiElementsKind(elements_kind)) {
        EnsureType(result, NodeType::kSmi);
      }
    }
    return result;
  };

  if (CanTreatHoleAsUndefined(maps) && LoadModeHandlesOOB(load_mode)) {
    ValueNode* positive_index;
    GET_VALUE_OR_ABORT(positive_index, GetUint32ElementIndex(index));
    ValueNode* uint32_length = AddNewNode<UnsafeInt32ToUint32>({length});
    return SelectReduction(
        [&](auto& builder) {
          return BuildBranchIfUint32Compare(builder, Operation::kLessThan,
                                            positive_index, uint32_length);
        },
        emit_load, [&] { return GetRootConstant(RootIndex::kUndefinedValue); });
  } else {
    RETURN_IF_ABORT(TryBuildCheckInt32Condition(
        index, length, AssertCondition::kUnsignedLessThan,
        DeoptimizeReason::kOutOfBounds));
    return emit_load();
  }
}

ReduceResult MaglevGraphBuilder::ConvertForStoring(ValueNode* value,
                                                   ElementsKind kind) {
  if (IsDoubleElementsKind(kind)) {
    // Make sure we do not store signalling NaNs into double arrays.
    // TODO(leszeks): Consider making this a bit on StoreFixedDoubleArrayElement
    // rather than a separate node.
    return GetSilencedNaN(GetFloat64(value));
  }
  if (IsSmiElementsKind(kind)) return GetSmiValue(value);
  return value;
}

ReduceResult MaglevGraphBuilder::TryBuildElementStoreOnJSArrayOrJSObject(
    ValueNode* object, ValueNode* index_object, ValueNode* value,
    base::Vector<const compiler::MapRef> maps, ElementsKind elements_kind,
    const compiler::KeyedAccessMode& keyed_mode) {
  DCHECK(IsFastElementsKind(elements_kind));

  const bool is_jsarray = HasOnlyJSArrayMaps(maps);
  DCHECK(is_jsarray || HasOnlyJSObjectMaps(maps));

  // Get the elements array.
  ValueNode* elements_array = BuildLoadElements(object);
  GET_VALUE_OR_ABORT(value, ConvertForStoring(value, elements_kind));
  ValueNode* index;

  // TODO(verwaest): Loop peeling will turn the first iteration index of spread
  // literals into smi constants as well, breaking the assumption that we'll
  // have preallocated the space if we see known indices. Turn off this
  // optimization if loop peeling is on.
  if (keyed_mode.access_mode() == compiler::AccessMode::kStoreInLiteral &&
      index_object->Is<SmiConstant>() && is_jsarray && !any_peeled_loop_) {
    index = GetInt32ElementIndex(index_object);
  } else {
    // Check boundaries.
    ValueNode* elements_array_length = nullptr;
    ValueNode* length;
    if (is_jsarray) {
      length = GetInt32(BuildLoadJSArrayLength(object));
    } else {
      length = elements_array_length =
          BuildLoadFixedArrayLength(elements_array);
    }
    index = GetInt32ElementIndex(index_object);
    if (keyed_mode.store_mode() == KeyedAccessStoreMode::kGrowAndHandleCOW) {
      if (elements_array_length == nullptr) {
        elements_array_length = BuildLoadFixedArrayLength(elements_array);
      }

      // Validate the {index} depending on holeyness:
      //
      // For HOLEY_*_ELEMENTS the {index} must not exceed the {elements}
      // backing store capacity plus the maximum allowed gap, as otherwise
      // the (potential) backing store growth would normalize and thus
      // the elements kind of the {receiver} would change to slow mode.
      //
      // For JSArray PACKED_*_ELEMENTS the {index} must be within the range
      // [0,length+1[ to be valid. In case {index} equals {length},
      // the {receiver} will be extended, but kept packed.
      //
      // Non-JSArray PACKED_*_ELEMENTS always grow by adding holes because they
      // lack the magical length property, which requires a map transition.
      // So we can assume that this did not happen if we did not see this map.
      ValueNode* limit =
          IsHoleyElementsKind(elements_kind)
              ? AddNewNode<Int32AddWithOverflow>(
                    {elements_array_length,
                     GetInt32Constant(JSObject::kMaxGap)})
          : is_jsarray
              ? AddNewNode<Int32AddWithOverflow>({length, GetInt32Constant(1)})
              : elements_array_length;
      RETURN_IF_ABORT(TryBuildCheckInt32Condition(
          index, limit, AssertCondition::kUnsignedLessThan,
          DeoptimizeReason::kOutOfBounds));

      // Grow backing store if necessary and handle COW.
      elements_array = AddNewNode<MaybeGrowFastElements>(
          {elements_array, object, index, elements_array_length},
          elements_kind);

      // If we didn't grow {elements}, it might still be COW, in which case we
      // copy it now.
      if (IsSmiOrObjectElementsKind(elements_kind)) {
        DCHECK_EQ(keyed_mode.store_mode(),
                  KeyedAccessStoreMode::kGrowAndHandleCOW);
        elements_array =
            AddNewNode<EnsureWritableFastElements>({elements_array, object});
      }

      // Update length if necessary.
      if (is_jsarray) {
        ValueNode* new_length =
            AddNewNode<UpdateJSArrayLength>({length, object, index});
        RecordKnownProperty(object, broker()->length_string(), new_length,
                            false, compiler::AccessMode::kStore);
      }
    } else {
      RETURN_IF_ABORT(TryBuildCheckInt32Condition(
          index, length, AssertCondition::kUnsignedLessThan,
          DeoptimizeReason::kOutOfBounds));

      // Handle COW if needed.
      if (IsSmiOrObjectElementsKind(elements_kind)) {
        if (keyed_mode.store_mode() == KeyedAccessStoreMode::kHandleCOW) {
          elements_array =
              AddNewNode<EnsureWritableFastElements>({elements_array, object});
        } else {
          // Ensure that this is not a COW FixedArray.
          RETURN_IF_ABORT(BuildCheckMaps(
              elements_array, base::VectorOf({broker()->fixed_array_map()})));
        }
      }
    }
  }

  // Do the store.
  if (IsDoubleElementsKind(elements_kind)) {
    BuildStoreFixedDoubleArrayElement(elements_array, index, value);
  } else {
    BuildStoreFixedArrayElement(elements_array, index, value);
  }

  return ReduceResult::Done();
}

ReduceResult MaglevGraphBuilder::TryBuildElementAccessOnJSArrayOrJSObject(
    ValueNode* object, ValueNode* index_object,
    const compiler::ElementAccessInfo& access_info,
    compiler::KeyedAccessMode const& keyed_mode) {
  if (!IsFastElementsKind(access_info.elements_kind())) {
    return ReduceResult::Fail();
  }
  switch (keyed_mode.access_mode()) {
    case compiler::AccessMode::kLoad:
      return TryBuildElementLoadOnJSArrayOrJSObject(
          object, index_object,
          base::VectorOf(access_info.lookup_start_object_maps()),
          access_info.elements_kind(), keyed_mode.load_mode());
    case compiler::AccessMode::kStoreInLiteral:
    case compiler::AccessMode::kStore: {
      base::Vector<const compiler::MapRef> maps =
          base::VectorOf(access_info.lookup_start_object_maps());
      ElementsKind elements_kind = access_info.elements_kind();
      return TryBuildElementStoreOnJSArrayOrJSObject(object, index_object,
                                                     GetAccumulator(), maps,
                                                     elements_kind, keyed_mode);
    }
    default:
      // TODO(victorgomes): Implement more access types.
      return ReduceResult::Fail();
  }
}

template <typename GenericAccessFunc>
ReduceResult MaglevGraphBuilder::TryBuildElementAccess(
    ValueNode* object, ValueNode* index_object,
    compiler::ElementAccessFeedback const& feedback,
    compiler::FeedbackSource const& feedback_source,
    GenericAccessFunc&& build_generic_access) {
  const compiler::KeyedAccessMode& keyed_mode = feedback.keyed_mode();
  // Check for the megamorphic case.
  if (feedback.transition_groups().empty()) {
    if (keyed_mode.access_mode() == compiler::AccessMode::kLoad) {
      return BuildCallBuiltin<Builtin::kKeyedLoadIC_Megamorphic>(
          {GetTaggedValue(object), GetTaggedValue(index_object)},
          feedback_source);
    } else if (keyed_mode.access_mode() == compiler::AccessMode::kStore) {
      return BuildCallBuiltin<Builtin::kKeyedStoreIC_Megamorphic>(
          {GetTaggedValue(object), GetTaggedValue(index_object),
           GetTaggedValue(GetAccumulator())},
          feedback_source);
    }
    return ReduceResult::Fail();
  }

  NodeInfo* object_info = known_node_aspects().TryGetInfoFor(object);
  compiler::ElementAccessFeedback refined_feedback =
      object_info && object_info->possible_maps_are_known()
          ? feedback.Refine(broker(), object_info->possible_maps())
          : feedback;

  if (refined_feedback.HasOnlyStringMaps(broker())) {
    return TryBuildElementAccessOnString(object, index_object, keyed_mode);
  }

  compiler::AccessInfoFactory access_info_factory(broker(), zone());
  ZoneVector<compiler::ElementAccessInfo> access_infos(zone());
  if (!access_info_factory.ComputeElementAccessInfos(refined_feedback,
                                                     &access_infos) ||
      access_infos.empty()) {
    return ReduceResult::Fail();
  }

  // TODO(leszeks): This is copied without changes from TurboFan's native
  // context specialization. We should figure out a way to share this code.
  //
  // For holey stores or growing stores, we need to check that the prototype
  // chain contains no setters for elements, and we need to guard those checks
  // via code dependencies on the relevant prototype maps.
  if (keyed_mode.access_mode() == compiler::AccessMode::kStore) {
    // TODO(v8:7700): We could have a fast path here, that checks for the
    // common case of Array or Object prototype only and therefore avoids
    // the zone allocation of this vector.
    ZoneVector<compiler::MapRef> prototype_maps(zone());
    for (compiler::ElementAccessInfo const& access_info : access_infos) {
      for (compiler::MapRef receiver_map :
           access_info.lookup_start_object_maps()) {
        // If the {receiver_map} has a prototype and its elements backing
        // store is either holey, or we have a potentially growing store,
        // then we need to check that all prototypes have stable maps with
        // with no element accessors and no throwing behavior for elements (and
        // we need to guard against changes to that below).
        if ((IsHoleyOrDictionaryElementsKind(receiver_map.elements_kind()) ||
             StoreModeCanGrow(refined_feedback.keyed_mode().store_mode())) &&
            !receiver_map.PrototypesElementsDoNotHaveAccessorsOrThrow(
                broker(), &prototype_maps)) {
          return ReduceResult::Fail();
        }

        // TODO(v8:12547): Support writing to objects in shared space, which
        // need a write barrier that calls Object::Share to ensure the RHS is
        // shared.
        if (InstanceTypeChecker::IsAlwaysSharedSpaceJSObject(
                receiver_map.instance_type())) {
          return ReduceResult::Fail();
        }
      }
    }
    for (compiler::MapRef prototype_map : prototype_maps) {
      broker()->dependencies()->DependOnStableMap(prototype_map);
    }
  }

  // Check for monomorphic case.
  if (access_infos.size() == 1) {
    compiler::ElementAccessInfo const& access_info = access_infos.front();
    // TODO(victorgomes): Support RAB/GSAB backed typed arrays.
    if (IsRabGsabTypedArrayElementsKind(access_info.elements_kind())) {
      return ReduceResult::Fail();
    }

    if (!access_info.transition_sources().empty()) {
      compiler::MapRef transition_target =
          access_info.lookup_start_object_maps().front();
      const ZoneVector<compiler::MapRef>& transition_sources =
          access_info.transition_sources();

      // There are no transitions in heap number maps. If `object` is a SMI, we
      // would anyway fail the transition and deopt later.
      DCHECK_NE(transition_target.instance_type(),
                InstanceType::HEAP_NUMBER_TYPE);
#ifdef DEBUG
      for (auto& transition_source : transition_sources) {
        DCHECK_NE(transition_source.instance_type(),
                  InstanceType::HEAP_NUMBER_TYPE);
      }
#endif  // DEBUG

      BuildCheckHeapObject(object);
      ValueNode* object_map =
          BuildLoadTaggedField(object, HeapObject::kMapOffset);

      RETURN_IF_ABORT(BuildTransitionElementsKindOrCheckMap(
          object, object_map, transition_sources, transition_target));
    } else {
      RETURN_IF_ABORT(BuildCheckMaps(
          object, base::VectorOf(access_info.lookup_start_object_maps())));
    }
    if (IsTypedArrayElementsKind(access_info.elements_kind())) {
      return TryBuildElementAccessOnTypedArray(object, index_object,
                                               access_info, keyed_mode);
    }
    return TryBuildElementAccessOnJSArrayOrJSObject(object, index_object,
                                                    access_info, keyed_mode);
  } else {
    return TryBuildPolymorphicElementAccess(object, index_object, keyed_mode,
                                            access_infos, build_generic_access);
  }
}

template <typename GenericAccessFunc>
ReduceResult MaglevGraphBuilder::TryBuildPolymorphicElementAccess(
    ValueNode* object, ValueNode* index_object,
    const compiler::KeyedAccessMode& keyed_mode,
    const ZoneVector<compiler::ElementAccessInfo>& access_infos,
    GenericAccessFunc&& build_generic_access) {
  if (keyed_mode.access_mode() == compiler::AccessMode::kLoad &&
      LoadModeHandlesOOB(keyed_mode.load_mode())) {
    // TODO(victorgomes): Handle OOB mode.
    return ReduceResult::Fail();
  }

  const bool is_any_store = compiler::IsAnyStore(keyed_mode.access_mode());
  const int access_info_count = static_cast<int>(access_infos.size());
  // Stores don't return a value, so we don't need a variable for the result.
  MaglevSubGraphBuilder sub_graph(this, is_any_store ? 0 : 1);
  std::optional<MaglevSubGraphBuilder::Variable> ret_val;
  std::optional<MaglevSubGraphBuilder::Label> done;
  std::optional<MaglevSubGraphBuilder::Label> generic_access;

  BuildCheckHeapObject(object);
  ValueNode* object_map = BuildLoadTaggedField(object, HeapObject::kMapOffset);

  // TODO(pthier): We could do better here than just emitting code for each map,
  // as many different maps can produce the exact samce code (e.g. TypedArray
  // access for Uint16/Uint32/Int16/Int32/...).
  for (int i = 0; i < access_info_count; i++) {
    compiler::ElementAccessInfo const& access_info = access_infos[i];
    std::optional<MaglevSubGraphBuilder::Label> check_next_map;
    const bool handle_transitions = !access_info.transition_sources().empty();
    ReduceResult map_check_result;
    if (i == access_info_count - 1) {
      if (handle_transitions) {
        compiler::MapRef transition_target =
            access_info.lookup_start_object_maps().front();
        map_check_result = BuildTransitionElementsKindOrCheckMap(
            object, object_map, access_info.transition_sources(),
            transition_target);
      } else {
        map_check_result = BuildCheckMaps(
            object, base::VectorOf(access_info.lookup_start_object_maps()),
            object_map);
      }
    } else {
      if (handle_transitions) {
        compiler::MapRef transition_target =
            access_info.lookup_start_object_maps().front();
        map_check_result = BuildTransitionElementsKindAndCompareMaps(
            object, object_map, access_info.transition_sources(),
            transition_target, &sub_graph, check_next_map);
      } else {
        map_check_result = BuildCompareMaps(
            object, object_map,
            base::VectorOf(access_info.lookup_start_object_maps()), &sub_graph,
            check_next_map);
      }
    }
    if (map_check_result.IsDoneWithAbort()) {
      // We know from known possible maps that this branch is not reachable,
      // so don't emit any code for it.
      continue;
    }
    ReduceResult result;
    // TODO(victorgomes): Support RAB/GSAB backed typed arrays.
    if (IsRabGsabTypedArrayElementsKind(access_info.elements_kind())) {
      result = ReduceResult::Fail();
    } else if (IsTypedArrayElementsKind(access_info.elements_kind())) {
      result = TryBuildElementAccessOnTypedArray(object, index_object,
                                                 access_info, keyed_mode);
    } else {
      result = TryBuildElementAccessOnJSArrayOrJSObject(
          object, index_object, access_info, keyed_mode);
    }

    switch (result.kind()) {
      case ReduceResult::kDoneWithValue:
      case ReduceResult::kDoneWithoutValue:
        DCHECK_EQ(result.HasValue(), !is_any_store);
        if (!done.has_value()) {
          // We initialize the label {done} lazily on the first possible path.
          // If no possible path exists, it is guaranteed that BuildCheckMaps
          // emitted an unconditional deopt and we return DoneWithAbort at the
          // end. We need one extra predecessor to jump from the generic case.
          const int possible_predecessors = access_info_count - i + 1;
          if (is_any_store) {
            done.emplace(&sub_graph, possible_predecessors);
          } else {
            ret_val.emplace(0);
            done.emplace(
                &sub_graph, possible_predecessors,
                std::initializer_list<MaglevSubGraphBuilder::Variable*>{
                    &*ret_val});
          }
        }
        if (!is_any_store) {
          sub_graph.set(*ret_val, result.value());
        }
        sub_graph.Goto(&*done);
        break;
      case ReduceResult::kFail:
        if (!generic_access.has_value()) {
          // Conservatively assume that all remaining branches can go into the
          // generic path, as we have to initialize the predecessors upfront.
          // TODO(pthier): Find a better way to do that.
          generic_access.emplace(&sub_graph, access_info_count - i);
        }
        sub_graph.Goto(&*generic_access);
        break;
      case ReduceResult::kDoneWithAbort:
        break;
      case ReduceResult::kNone:
        UNREACHABLE();
    }
    if (check_next_map.has_value()) {
      sub_graph.Bind(&*check_next_map);
    }
  }
  if (generic_access.has_value() &&
      !sub_graph.TrimPredecessorsAndBind(&*generic_access).IsDoneWithAbort()) {
    ReduceResult generic_result = build_generic_access();
    DCHECK(generic_result.IsDone());
    DCHECK_EQ(generic_result.IsDoneWithValue(), !is_any_store);
    if (!done.has_value()) {
      return is_any_store ? ReduceResult::Done() : generic_result.value();
    }
    if (!is_any_store) {
      sub_graph.set(*ret_val, generic_result.value());
    }
    sub_graph.Goto(&*done);
  }
  if (done.has_value()) {
    RETURN_IF_ABORT(sub_graph.TrimPredecessorsAndBind(&*done));
    return is_any_store ? ReduceResult::Done() : sub_graph.get(*ret_val);
  } else {
    return ReduceResult::DoneWithAbort();
  }
}

template <typename GenericAccessFunc>
ReduceResult MaglevGraphBuilder::TryBuildPolymorphicPropertyAccess(
    ValueNode* receiver, ValueNode* lookup_start_object,
    compiler::NamedAccessFeedback const& feedback,
    compiler::AccessMode access_mode,
    const ZoneVector<compiler::PropertyAccessInfo>& access_infos,
    GenericAccessFunc&& build_generic_access) {
  const bool is_any_store = compiler::IsAnyStore(access_mode);
  const int access_info_count = static_cast<int>(access_infos.size());
  int number_map_index = -1;

  bool needs_migration = false;
  for (int i = 0; i < access_info_count; i++) {
    compiler::PropertyAccessInfo const& access_info = access_infos[i];
    DCHECK(!access_info.IsInvalid());
    for (compiler::MapRef map : access_info.lookup_start_object_maps()) {
      if (map.is_migration_target()) {
        needs_migration = true;
      }
      if (map.IsHeapNumberMap()) {
        GetOrCreateInfoFor(lookup_start_object);
        base::SmallVector<compiler::MapRef, 1> known_maps = {map};
        KnownMapsMerger merger(broker(), zone(), base::VectorOf(known_maps));
        merger.IntersectWithKnownNodeAspects(lookup_start_object,
                                             known_node_aspects());
        if (!merger.intersect_set().is_empty()) {
          DCHECK_EQ(number_map_index, -1);
          number_map_index = i;
        }
      }
    }
  }

  // Stores don't return a value, so we don't need a variable for the result.
  MaglevSubGraphBuilder sub_graph(this, is_any_store ? 0 : 1);
  std::optional<MaglevSubGraphBuilder::Variable> ret_val;
  std::optional<MaglevSubGraphBuilder::Label> done;
  std::optional<MaglevSubGraphBuilder::Label> is_number;
  std::optional<MaglevSubGraphBuilder::Label> generic_access;

  if (number_map_index >= 0) {
    is_number.emplace(&sub_graph, 2);
    sub_graph.GotoIfTrue<BranchIfSmi>(&*is_number, {lookup_start_object});
  } else {
    BuildCheckHeapObject(lookup_start_object);
  }
  ValueNode* lookup_start_object_map =
      BuildLoadTaggedField(lookup_start_object, HeapObject::kMapOffset);

  if (needs_migration &&
      !v8_flags.maglev_skip_migration_check_for_polymorphic_access) {
    // TODO(marja, v8:7700): Try migrating only if all comparisons failed.
    // TODO(marja, v8:7700): Investigate making polymoprhic map comparison (with
    // migration) a control node (like switch).
    lookup_start_object_map = AddNewNode<MigrateMapIfNeeded>(
        {lookup_start_object_map, lookup_start_object});
  }

  for (int i = 0; i < access_info_count; i++) {
    compiler::PropertyAccessInfo const& access_info = access_infos[i];
    std::optional<MaglevSubGraphBuilder::Label> check_next_map;
    ReduceResult map_check_result;
    const auto& maps = access_info.lookup_start_object_maps();
    if (i == access_info_count - 1) {
      map_check_result =
          BuildCheckMaps(lookup_start_object, base::VectorOf(maps));
    } else {
      map_check_result =
          BuildCompareMaps(lookup_start_object, lookup_start_object_map,
                           base::VectorOf(maps), &sub_graph, check_next_map);
    }
    if (map_check_result.IsDoneWithAbort()) {
      // We know from known possible maps that this branch is not reachable,
      // so don't emit any code for it.
      continue;
    }
    if (i == number_map_index) {
      DCHECK(is_number.has_value());
      sub_graph.Goto(&*is_number);
      sub_graph.Bind(&*is_number);
    }

    ReduceResult result;
    if (is_any_store) {
      result = TryBuildPropertyStore(receiver, lookup_start_object,
                                    
"""


```