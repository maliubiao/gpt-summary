Response: The user wants a summary of the C++ code in `v8/src/maglev/maglev-graph-builder.cc`, specifically part 6 of 9. They also want a JavaScript example if the code relates to JavaScript functionality.

**Thinking Process:**

1. **Scan the code for keywords and patterns:** Look for function names starting with `TryReduce`, common JavaScript built-in names (e.g., `Array.prototype.push`, `String.fromCharCode`), and V8-specific terms (e.g., `MaglevGraphBuilder`, `ValueNode`, `Builtin`).

2. **Identify the primary purpose:** The `TryReduce...` functions suggest this part of the code is responsible for optimizing or "reducing" calls to JavaScript built-in functions or common JavaScript operations during the Maglev compilation process. This involves creating nodes in the Maglev graph to represent these optimized operations.

3. **Group related functions:**  Notice blocks of `TryReduce` functions for specific JavaScript objects like `Array`, `String`, `DataView`, `Function`, `Object`, and `Math`. This suggests the code handles optimizations for various built-in functionalities.

4. **Analyze individual function groups:**
    * **Array:** Functions like `TryReduceArrayPrototypeEntries`, `TryReduceArrayPrototypeKeys`, `TryReduceArrayPrototypeValues`, `TryReduceArrayPrototypePush`, and `TryReduceArrayPrototypePop` deal with array iteration and modification methods. They seem to involve checking the array's type (elements kind) and performing optimized operations based on it.
    * **String:**  Functions like `TryReduceStringFromCharCode`, `TryReduceStringPrototypeCharCodeAt`, `TryReduceStringPrototypeCodePointAt`, and `TryReduceStringPrototypeIterator` handle string-related methods like character code retrieval and iteration.
    * **DataView:** `TryReduceDataViewPrototypeGet...` and `TryReduceDataViewPrototypeSet...` functions relate to reading and writing data in `DataView` objects, ensuring bounds checks and handling endianness.
    * **Function:** `TryReduceFunctionPrototypeCall` and `TryReduceFunctionPrototypeApply` deal with the fundamental function invocation methods.
    * **Object:** `TryReduceObjectPrototypeHasOwnProperty`, `TryReduceObjectPrototypeGetProto`, and `TryReduceObjectGetPrototypeOf` handle object property checks and prototype retrieval. The `hasOwnProperty` optimization seems related to `for...in` loops.
    * **Math:** Functions like `TryReduceMathRound`, `TryReduceNumberParseInt`, `TryReduceMathAbs`, `TryReduceMathFloor`, `TryReduceMathCeil`, and `TryReduceMathPow` aim to optimize calls to common `Math` and `Number` methods.

5. **Look for connections to JavaScript:** The function names directly correspond to JavaScript built-in methods. The code builds graph nodes that perform the equivalent operations in a more efficient way than a generic function call.

6. **Formulate the summary:** Based on the analysis, the core functionality is to identify calls to specific JavaScript built-in methods and replace them with optimized Maglev graph nodes. This optimization often involves type checking and specialization based on the receiver object's properties (like the `ElementsKind` for arrays).

7. **Construct the JavaScript examples:** For methods like `Array.prototype.push`, `Array.prototype.pop`, `String.fromCharCode`, and `String.prototype.charCodeAt`, provide simple JavaScript code snippets that demonstrate the usage of these methods. This will help illustrate the connection between the C++ code and JavaScript functionality.

8. **Refine the summary:** Ensure the summary mentions the focus on performance through graph node construction and the conditional nature of these optimizations (using `TryReduce`). Highlight the role of type checks and speculation.
This part of the `maglev-graph-builder.cc` file focuses on **reducing (optimizing) calls to various JavaScript built-in functions and methods**. It attempts to replace these calls with more efficient sequences of Maglev graph nodes.

Here's a breakdown of the functionalities covered in this section:

**1. Array Prototype Methods:**

* **`TryReduceArrayPrototypeEntries`, `TryReduceArrayPrototypeKeys`, `TryReduceArrayPrototypeValues`**: These functions handle calls to `Array.prototype.entries()`, `Array.prototype.keys()`, and `Array.prototype.values()` respectively. They build and allocate a `JSArrayIterator` object, which is used for iterating over the array. The specific kind of iteration (entries, keys, or values) is determined and stored in the iterator.
* **`TryReduceArrayPrototypePush`**: Optimizes calls to `Array.prototype.push()`. It checks the array's elements kind and potentially grows the backing store if needed, then stores the new element and updates the array's length.
* **`TryReduceArrayPrototypePop`**: Optimizes calls to `Array.prototype.pop()`. It checks the array's elements kind, retrieves the last element, potentially sets a hole in its place, and updates the array's length. It handles different elements kinds (SMI, Object, Double) and holey/packed arrays.

**2. String Prototype Methods:**

* **`TryReduceStringFromCharCode`**: Optimizes calls to `String.fromCharCode()`. It takes an integer and creates a single-character string from its Unicode code point.
* **`TryReduceStringPrototypeCharCodeAt`**: Optimizes calls to `String.prototype.charCodeAt()`. It retrieves the character code at a specific index in a string. It includes constant folding for cases where the string and index are known at compile time.
* **`TryReduceStringPrototypeCodePointAt`**: Similar to `TryReduceStringPrototypeCharCodeAt`, but handles Unicode code points which can span multiple characters.
* **`TryReduceStringPrototypeIterator`**: Optimizes calls to `String.prototype[Symbol.iterator]()`. It creates and allocates a `JSStringIterator` object for iterating over the string's characters.
* **`TryReduceStringPrototypeLocaleCompareIntl`**:  Handles `String.prototype.localeCompare()` when using Intl for comparison, potentially optimizing for fast-path comparisons.

**3. DataView Prototype Methods:**

* **`TryReduceDataViewPrototypeGetInt8`, `TryReduceDataViewPrototypeSetInt8`, etc.**:  A series of functions to optimize `DataView`'s `getInt*` and `setInt*` methods. They perform bounds checks and load/store integer and floating-point values with specified endianness.

**4. Function Prototype Methods:**

* **`TryReduceFunctionPrototypeCall`**: Optimizes calls to `Function.prototype.call()`. It extracts the receiver and arguments and attempts to reduce the underlying call.
* **`TryReduceFunctionPrototypeApply`**: Optimizes calls to `Function.prototype.apply()`. Similar to `call`, but takes arguments as an array.
* **`TryReduceFunctionPrototypeHasInstance`**: Optimizes calls to `Function.prototype.hasInstance()`. It checks if an object is an instance of a function's prototype chain.

**5. Object Prototype Methods:**

* **`TryReduceObjectPrototypeHasOwnProperty`**: Optimizes calls to `Object.prototype.hasOwnProperty()`. It has special handling for calls within `for...in` loops, allowing for more efficient property existence checks.
* **`TryReduceObjectPrototypeGetProto`**: Optimizes calls to `Object.prototype.__proto__` (getter). It attempts to retrieve the prototype of an object.
* **`TryReduceObjectGetPrototypeOf`**: Optimizes calls to `Object.getPrototypeOf()`. It also attempts to retrieve the prototype of an object.

**6. Math and Number Methods:**

* **`TryReduceMathRound`, `TryReduceMathAbs`, `TryReduceMathFloor`, `TryReduceMathCeil`, `TryReduceNumberParseInt`**: Optimize calls to common `Math` and `Number` methods like rounding, absolute value, and parsing integers.
* **`TryReduceMathPow`**: Optimizes calls to `Math.pow()`.
* **`TryReduceMathSin`, `TryReduceMathCos`, `TryReduceMathTan`, etc.**: Optimize calls to various trigonometric and other `Math` functions using their IEEE 754 equivalents.

**7. Constructor Calls:**

* **`TryReduceArrayConstructor`**: Optimizes calls to the `Array` constructor.
* **`TryReduceStringConstructor`**: Optimizes calls to the `String` constructor.

**8. General Built-in Reduction (`TryReduceBuiltin`)**:

* This function acts as a central dispatcher for reducing calls to various built-in functions based on their `BuiltinId`.

**Relationship to JavaScript Functionality (with Examples):**

This code directly relates to the implementation and optimization of core JavaScript features. When JavaScript code calls a built-in function, Maglev attempts to "reduce" that call into a sequence of lower-level operations for better performance.

**JavaScript Examples:**

* **`TryReduceArrayPrototypePush`:**
   ```javascript
   const arr = [1, 2, 3];
   arr.push(4); // This call might be optimized by TryReduceArrayPrototypePush
   ```

* **`TryReduceStringFromCharCode`:**
   ```javascript
   const char = String.fromCharCode(65); // This call might be optimized by TryReduceStringFromCharCode
   console.log(char); // Output: "A"
   ```

* **`TryReduceStringPrototypeCharCodeAt`:**
   ```javascript
   const str = "Hello";
   const code = str.charCodeAt(1); // This call might be optimized by TryReduceStringPrototypeCharCodeAt
   console.log(code); // Output: 101 (ASCII code for 'e')
   ```

* **`TryReduceObjectPrototypeHasOwnProperty` (within a `for...in` loop):**
   ```javascript
   const obj = { a: 1, b: 2 };
   for (let key in obj) {
     if (obj.hasOwnProperty(key)) { // This call might be optimized by TryReduceObjectPrototypeHasOwnProperty
       console.log(key);
     }
   }
   ```

* **`TryReduceMathRound`:**
   ```javascript
   const rounded = Math.round(3.7); // This call might be optimized by TryReduceMathRound
   console.log(rounded); // Output: 4
   ```

**In summary, this part of the Maglev graph builder is crucial for achieving performance in V8 by recognizing common JavaScript operations and implementing them in a highly optimized manner within the Maglev intermediate representation.** It acts as a bridge between the high-level semantics of JavaScript and the lower-level operations required for efficient execution.

### 提示词
```
这是目录为v8/src/maglev/maglev-graph-builder.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第6部分，共9部分，请归纳一下它的功能
```

### 源代码
```
;
  RETURN_IF_ABORT(subgraph.Branch(
      {&is_done, &ret_value},
      [&](auto& builder) {
        return BuildBranchIfUint32Compare(builder, Operation::kLessThan,
                                          uint32_index, uint32_length);
      },
      [&] {
        ValueNode* int32_index = GetInt32(uint32_index);
        subgraph.set(is_done, GetBooleanConstant(false));
        DCHECK(
            iterator->get(JSArrayIterator::kKindOffset)->Is<Int32Constant>());
        IterationKind iteration_kind = static_cast<IterationKind>(
            iterator->get(JSArrayIterator::kKindOffset)
                ->Cast<Int32Constant>()
                ->value());
        if (iteration_kind == IterationKind::kKeys) {
          subgraph.set(ret_value, index);
        } else {
          ValueNode* value;
          GET_VALUE_OR_ABORT(
              value,
              TryBuildElementLoadOnJSArrayOrJSObject(
                  iterated_object, int32_index, base::VectorOf(maps),
                  elements_kind, KeyedAccessLoadMode::kHandleOOBAndHoles));
          if (iteration_kind == IterationKind::kEntries) {
            subgraph.set(ret_value,
                         BuildAndAllocateKeyValueArray(index, value));
          } else {
            subgraph.set(ret_value, value);
          }
        }
        // Add 1 to index
        ValueNode* next_index = AddNewNode<Int32AddWithOverflow>(
            {int32_index, GetInt32Constant(1)});
        EnsureType(next_index, NodeType::kSmi);
        // Update [[NextIndex]]
        BuildStoreTaggedFieldNoWriteBarrier(receiver, next_index,
                                            JSArrayIterator::kNextIndexOffset,
                                            StoreTaggedMode::kDefault);
        return ReduceResult::Done();
      },
      [&] {
        // Index is greater or equal than length.
        subgraph.set(is_done, GetBooleanConstant(true));
        subgraph.set(ret_value, GetRootConstant(RootIndex::kUndefinedValue));
        if (!IsTypedArrayElementsKind(elements_kind)) {
          // Mark the {iterator} as exhausted by setting the [[NextIndex]] to a
          // value that will never pass the length check again (aka the maximum
          // value possible for the specific iterated object). Note that this is
          // different from what the specification says, which is changing the
          // [[IteratedObject]] field to undefined, but that makes it difficult
          // to eliminate the map checks and "length" accesses in for..of loops.
          //
          // This is not necessary for JSTypedArray's, since the length of those
          // cannot change later and so if we were ever out of bounds for them
          // we will stay out-of-bounds forever.
          BuildStoreTaggedField(receiver, GetFloat64Constant(kMaxUInt32),
                                JSArrayIterator::kNextIndexOffset,
                                StoreTaggedMode::kDefault);
        }
        return ReduceResult::Done();
      }));

  // Allocate result object and return.
  compiler::MapRef map =
      broker()->target_native_context().iterator_result_map(broker());
  VirtualObject* iter_result = CreateJSIteratorResult(
      map, subgraph.get(ret_value), subgraph.get(is_done));
  ValueNode* allocation =
      BuildInlinedAllocation(iter_result, AllocationType::kYoung);
  // TODO(leszeks): Don't eagerly clear the raw allocation, have the
  // next side effect clear it.
  ClearCurrentAllocationBlock();
  return allocation;
}

ReduceResult MaglevGraphBuilder::TryReduceArrayPrototypeEntries(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  ValueNode* receiver = GetValueOrUndefined(args.receiver());
  if (!CheckType(receiver, NodeType::kJSReceiver)) {
    return ReduceResult::Fail();
  }
  return BuildAndAllocateJSArrayIterator(receiver, IterationKind::kEntries);
}

ReduceResult MaglevGraphBuilder::TryReduceArrayPrototypeKeys(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  ValueNode* receiver = GetValueOrUndefined(args.receiver());
  if (!CheckType(receiver, NodeType::kJSReceiver)) {
    return ReduceResult::Fail();
  }
  return BuildAndAllocateJSArrayIterator(receiver, IterationKind::kKeys);
}

ReduceResult MaglevGraphBuilder::TryReduceArrayPrototypeValues(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  ValueNode* receiver = GetValueOrUndefined(args.receiver());
  if (!CheckType(receiver, NodeType::kJSReceiver)) {
    return ReduceResult::Fail();
  }
  return BuildAndAllocateJSArrayIterator(receiver, IterationKind::kValues);
}

ReduceResult MaglevGraphBuilder::TryReduceStringFromCharCode(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  if (args.count() != 1) return ReduceResult::Fail();
  return AddNewNode<BuiltinStringFromCharCode>({GetTruncatedInt32ForToNumber(
      args[0], ToNumberHint::kAssumeNumberOrOddball)});
}

ReduceResult MaglevGraphBuilder::TryReduceStringPrototypeCharCodeAt(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  ValueNode* receiver = GetValueOrUndefined(args.receiver());
  ValueNode* index;
  if (args.count() == 0) {
    // Index is the undefined object. ToIntegerOrInfinity(undefined) = 0.
    index = GetInt32Constant(0);
  } else {
    index = GetInt32ElementIndex(args[0]);
  }
  // Any other argument is ignored.

  // Try to constant-fold if receiver and index are constant
  if (auto cst = TryGetConstant(receiver)) {
    if (cst->IsString() && index->Is<Int32Constant>()) {
      compiler::StringRef str = cst->AsString();
      int idx = index->Cast<Int32Constant>()->value();
      if (idx >= 0 && static_cast<uint32_t>(idx) < str.length()) {
        if (std::optional<uint16_t> value = str.GetChar(broker(), idx)) {
          return GetSmiConstant(*value);
        }
      }
    }
  }

  // Ensure that {receiver} is actually a String.
  BuildCheckString(receiver);
  // And index is below length.
  ValueNode* length = BuildLoadStringLength(receiver);
  RETURN_IF_ABORT(TryBuildCheckInt32Condition(
      index, length, AssertCondition::kUnsignedLessThan,
      DeoptimizeReason::kOutOfBounds));
  return AddNewNode<BuiltinStringPrototypeCharCodeOrCodePointAt>(
      {receiver, index},
      BuiltinStringPrototypeCharCodeOrCodePointAt::kCharCodeAt);
}

ReduceResult MaglevGraphBuilder::TryReduceStringPrototypeCodePointAt(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  ValueNode* receiver = GetValueOrUndefined(args.receiver());
  ValueNode* index;
  if (args.count() == 0) {
    // Index is the undefined object. ToIntegerOrInfinity(undefined) = 0.
    index = GetInt32Constant(0);
  } else {
    index = GetInt32ElementIndex(args[0]);
  }
  // Any other argument is ignored.
  // Ensure that {receiver} is actually a String.
  BuildCheckString(receiver);
  // And index is below length.
  ValueNode* length = BuildLoadStringLength(receiver);
  RETURN_IF_ABORT(TryBuildCheckInt32Condition(
      index, length, AssertCondition::kUnsignedLessThan,
      DeoptimizeReason::kOutOfBounds));
  return AddNewNode<BuiltinStringPrototypeCharCodeOrCodePointAt>(
      {receiver, index},
      BuiltinStringPrototypeCharCodeOrCodePointAt::kCodePointAt);
}

ReduceResult MaglevGraphBuilder::TryReduceStringPrototypeIterator(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  ValueNode* receiver = GetValueOrUndefined(args.receiver());
  // Ensure that {receiver} is actually a String.
  BuildCheckString(receiver);
  compiler::MapRef map =
      broker()->target_native_context().initial_string_iterator_map(broker());
  VirtualObject* string_iterator = CreateJSStringIterator(map, receiver);
  ValueNode* allocation =
      BuildInlinedAllocation(string_iterator, AllocationType::kYoung);
  // TODO(leszeks): Don't eagerly clear the raw allocation, have the
  // next side effect clear it.
  ClearCurrentAllocationBlock();
  return allocation;
}

#ifdef V8_INTL_SUPPORT

ReduceResult MaglevGraphBuilder::TryReduceStringPrototypeLocaleCompareIntl(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (args.count() < 1 || args.count() > 3) return ReduceResult::Fail();

  LocalFactory* factory = local_isolate()->factory();
  compiler::ObjectRef undefined_ref = broker()->undefined_value();

  Handle<Object> locales_handle;
  ValueNode* locales_node = nullptr;
  if (args.count() > 1) {
    compiler::OptionalHeapObjectRef maybe_locales = TryGetConstant(args[1]);
    if (!maybe_locales) return ReduceResult::Fail();
    compiler::HeapObjectRef locales = maybe_locales.value();
    if (locales.equals(undefined_ref)) {
      locales_handle = factory->undefined_value();
      locales_node = GetRootConstant(RootIndex::kUndefinedValue);
    } else {
      if (!locales.IsString()) return ReduceResult::Fail();
      compiler::StringRef sref = locales.AsString();
      std::optional<Handle<String>> maybe_locales_handle =
          sref.ObjectIfContentAccessible(broker());
      if (!maybe_locales_handle) return ReduceResult::Fail();
      locales_handle = *maybe_locales_handle;
      locales_node = args[1];
    }
  } else {
    locales_handle = factory->undefined_value();
    locales_node = GetRootConstant(RootIndex::kUndefinedValue);
  }

  if (args.count() > 2) {
    compiler::OptionalHeapObjectRef maybe_options = TryGetConstant(args[2]);
    if (!maybe_options) return ReduceResult::Fail();
    if (!maybe_options.value().equals(undefined_ref))
      return ReduceResult::Fail();
  }

  DCHECK(!locales_handle.is_null());
  DCHECK_NOT_NULL(locales_node);

  if (Intl::CompareStringsOptionsFor(local_isolate(), locales_handle,
                                     factory->undefined_value()) !=
      Intl::CompareStringsOptions::kTryFastPath) {
    return ReduceResult::Fail();
  }
  return BuildCallBuiltin<Builtin::kStringFastLocaleCompare>(
      {GetConstant(target),
       GetTaggedValue(GetValueOrUndefined(args.receiver())),
       GetTaggedValue(args[0]), GetTaggedValue(locales_node)});
}

#endif  // V8_INTL_SUPPORT

#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
ReduceResult MaglevGraphBuilder::TryReduceGetContinuationPreservedEmbedderData(
    compiler::JSFunctionRef target, CallArguments& args) {
  return AddNewNode<GetContinuationPreservedEmbedderData>({});
}

ReduceResult MaglevGraphBuilder::TryReduceSetContinuationPreservedEmbedderData(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (args.count() == 0) return ReduceResult::Fail();

  AddNewNode<SetContinuationPreservedEmbedderData>({args[0]});
  return GetRootConstant(RootIndex::kUndefinedValue);
}
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA

template <typename LoadNode>
ReduceResult MaglevGraphBuilder::TryBuildLoadDataView(const CallArguments& args,
                                                      ExternalArrayType type) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  if (!broker()->dependencies()->DependOnArrayBufferDetachingProtector()) {
    // TODO(victorgomes): Add checks whether the array has been detached.
    return ReduceResult::Fail();
  }
  // TODO(victorgomes): Add data view to known types.
  ValueNode* receiver = GetValueOrUndefined(args.receiver());
  AddNewNode<CheckInstanceType>({receiver}, CheckType::kCheckHeapObject,
                                JS_DATA_VIEW_TYPE, JS_DATA_VIEW_TYPE);
  // TODO(v8:11111): Optimize for JS_RAB_GSAB_DATA_VIEW_TYPE too.
  ValueNode* offset =
      args[0] ? GetInt32ElementIndex(args[0]) : GetInt32Constant(0);
  AddNewNode<CheckJSDataViewBounds>({receiver, offset}, type);
  ValueNode* is_little_endian = args[1] ? args[1] : GetBooleanConstant(false);
  return AddNewNode<LoadNode>({receiver, offset, is_little_endian}, type);
}

template <typename StoreNode, typename Function>
ReduceResult MaglevGraphBuilder::TryBuildStoreDataView(
    const CallArguments& args, ExternalArrayType type, Function&& getValue) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  if (!broker()->dependencies()->DependOnArrayBufferDetachingProtector()) {
    // TODO(victorgomes): Add checks whether the array has been detached.
    return ReduceResult::Fail();
  }
  // TODO(victorgomes): Add data view to known types.
  ValueNode* receiver = GetValueOrUndefined(args.receiver());
  AddNewNode<CheckInstanceType>({receiver}, CheckType::kCheckHeapObject,
                                JS_DATA_VIEW_TYPE, JS_DATA_VIEW_TYPE);
  // TODO(v8:11111): Optimize for JS_RAB_GSAB_DATA_VIEW_TYPE too.
  ValueNode* offset =
      args[0] ? GetInt32ElementIndex(args[0]) : GetInt32Constant(0);
  AddNewNode<CheckJSDataViewBounds>({receiver, offset},
                                    ExternalArrayType::kExternalFloat64Array);
  ValueNode* value = getValue(args[1]);
  ValueNode* is_little_endian = args[2] ? args[2] : GetBooleanConstant(false);
  AddNewNode<StoreNode>({receiver, offset, value, is_little_endian}, type);
  return GetRootConstant(RootIndex::kUndefinedValue);
}

ReduceResult MaglevGraphBuilder::TryReduceDataViewPrototypeGetInt8(
    compiler::JSFunctionRef target, CallArguments& args) {
  return TryBuildLoadDataView<LoadSignedIntDataViewElement>(
      args, ExternalArrayType::kExternalInt8Array);
}
ReduceResult MaglevGraphBuilder::TryReduceDataViewPrototypeSetInt8(
    compiler::JSFunctionRef target, CallArguments& args) {
  return TryBuildStoreDataView<StoreSignedIntDataViewElement>(
      args, ExternalArrayType::kExternalInt8Array,
      [&](ValueNode* value) { return value ? value : GetInt32Constant(0); });
}
ReduceResult MaglevGraphBuilder::TryReduceDataViewPrototypeGetInt16(
    compiler::JSFunctionRef target, CallArguments& args) {
  return TryBuildLoadDataView<LoadSignedIntDataViewElement>(
      args, ExternalArrayType::kExternalInt16Array);
}
ReduceResult MaglevGraphBuilder::TryReduceDataViewPrototypeSetInt16(
    compiler::JSFunctionRef target, CallArguments& args) {
  return TryBuildStoreDataView<StoreSignedIntDataViewElement>(
      args, ExternalArrayType::kExternalInt16Array,
      [&](ValueNode* value) { return value ? value : GetInt32Constant(0); });
}
ReduceResult MaglevGraphBuilder::TryReduceDataViewPrototypeGetInt32(
    compiler::JSFunctionRef target, CallArguments& args) {
  return TryBuildLoadDataView<LoadSignedIntDataViewElement>(
      args, ExternalArrayType::kExternalInt32Array);
}
ReduceResult MaglevGraphBuilder::TryReduceDataViewPrototypeSetInt32(
    compiler::JSFunctionRef target, CallArguments& args) {
  return TryBuildStoreDataView<StoreSignedIntDataViewElement>(
      args, ExternalArrayType::kExternalInt32Array,
      [&](ValueNode* value) { return value ? value : GetInt32Constant(0); });
}
ReduceResult MaglevGraphBuilder::TryReduceDataViewPrototypeGetFloat64(
    compiler::JSFunctionRef target, CallArguments& args) {
  return TryBuildLoadDataView<LoadDoubleDataViewElement>(
      args, ExternalArrayType::kExternalFloat64Array);
}
ReduceResult MaglevGraphBuilder::TryReduceDataViewPrototypeSetFloat64(
    compiler::JSFunctionRef target, CallArguments& args) {
  return TryBuildStoreDataView<StoreDoubleDataViewElement>(
      args, ExternalArrayType::kExternalFloat64Array, [&](ValueNode* value) {
        return value ? GetHoleyFloat64ForToNumber(
                           value, ToNumberHint::kAssumeNumberOrOddball)
                     : GetFloat64Constant(
                           std::numeric_limits<double>::quiet_NaN());
      });
}

ReduceResult MaglevGraphBuilder::TryReduceFunctionPrototypeCall(
    compiler::JSFunctionRef target, CallArguments& args) {
  // We can't reduce Function#call when there is no receiver function.
  if (args.receiver_mode() == ConvertReceiverMode::kNullOrUndefined) {
    return ReduceResult::Fail();
  }
  ValueNode* receiver = GetValueOrUndefined(args.receiver());
  args.PopReceiver(ConvertReceiverMode::kAny);

  SaveCallSpeculationScope saved(this);
  return ReduceCall(receiver, args, saved.value());
}

ReduceResult MaglevGraphBuilder::TryReduceFunctionPrototypeApply(
    compiler::JSFunctionRef target, CallArguments& args) {
  compiler::OptionalHeapObjectRef maybe_receiver;
  if (current_speculation_feedback_.IsValid()) {
    const compiler::ProcessedFeedback& processed_feedback =
        broker()->GetFeedbackForCall(current_speculation_feedback_);
    DCHECK_EQ(processed_feedback.kind(), compiler::ProcessedFeedback::kCall);
    const compiler::CallFeedback& call_feedback = processed_feedback.AsCall();
    compiler::OptionalHeapObjectRef maybe_receiver;
    if (call_feedback.call_feedback_content() ==
        CallFeedbackContent::kReceiver) {
      maybe_receiver = call_feedback.target();
    }
  }
  return ReduceFunctionPrototypeApplyCallWithReceiver(
      maybe_receiver, args, current_speculation_feedback_);
}

namespace {

template <size_t MaxKindCount, typename KindsToIndexFunc>
bool CanInlineArrayResizingBuiltin(
    compiler::JSHeapBroker* broker, const PossibleMaps& possible_maps,
    std::array<SmallZoneVector<compiler::MapRef, 2>, MaxKindCount>& map_kinds,
    KindsToIndexFunc&& elements_kind_to_index, int* unique_kind_count,
    bool is_loading) {
  uint8_t kind_bitmap = 0;
  for (compiler::MapRef map : possible_maps) {
    if (!map.supports_fast_array_resize(broker)) {
      return false;
    }
    ElementsKind kind = map.elements_kind();
    if (is_loading && kind == HOLEY_DOUBLE_ELEMENTS) {
      return false;
    }
    // Group maps by elements kind, using the provided function to translate
    // elements kinds to indices.
    // kind_bitmap is used to get the unique kinds (predecessor count for the
    // next block).
    uint8_t kind_index = elements_kind_to_index(kind);
    kind_bitmap |= 1 << kind_index;
    map_kinds[kind_index].push_back(map);
  }

  *unique_kind_count = base::bits::CountPopulation(kind_bitmap);
  DCHECK_GE(*unique_kind_count, 1);
  return true;
}

}  // namespace

template <typename MapKindsT, typename IndexToElementsKindFunc,
          typename BuildKindSpecificFunc>
ReduceResult MaglevGraphBuilder::BuildJSArrayBuiltinMapSwitchOnElementsKind(
    ValueNode* receiver, const MapKindsT& map_kinds,
    MaglevSubGraphBuilder& sub_graph,
    std::optional<MaglevSubGraphBuilder::Label>& do_return,
    int unique_kind_count, IndexToElementsKindFunc&& index_to_elements_kind,
    BuildKindSpecificFunc&& build_kind_specific) {
  // TODO(pthier): Support map packing.
  DCHECK(!V8_MAP_PACKING_BOOL);
  ValueNode* receiver_map =
      BuildLoadTaggedField(receiver, HeapObject::kMapOffset);
  int emitted_kind_checks = 0;
  bool any_successful = false;
  for (size_t kind_index = 0; kind_index < map_kinds.size(); kind_index++) {
    const auto& maps = map_kinds[kind_index];
    // Skip kinds we haven't observed.
    if (maps.empty()) continue;
    ElementsKind kind = index_to_elements_kind(kind_index);
    // Create branches for all but the last elements kind. We don't need
    // to check the maps of the last kind, as all possible maps have already
    // been checked when the property (builtin name) was loaded.
    if (++emitted_kind_checks < unique_kind_count) {
      MaglevSubGraphBuilder::Label check_next_map(&sub_graph, 1);
      std::optional<MaglevSubGraphBuilder::Label> do_push;
      if (maps.size() > 1) {
        do_push.emplace(&sub_graph, static_cast<int>(maps.size()));
        for (size_t map_index = 1; map_index < maps.size(); map_index++) {
          sub_graph.GotoIfTrue<BranchIfReferenceEqual>(
              &*do_push, {receiver_map, GetConstant(maps[map_index])});
        }
      }
      sub_graph.GotoIfFalse<BranchIfReferenceEqual>(
          &check_next_map, {receiver_map, GetConstant(maps[0])});
      if (do_push.has_value()) {
        sub_graph.Goto(&*do_push);
        sub_graph.Bind(&*do_push);
      }
      if (!build_kind_specific(kind).IsDoneWithAbort()) {
        any_successful = true;
      }
      DCHECK(do_return.has_value());
      sub_graph.GotoOrTrim(&*do_return);
      sub_graph.Bind(&check_next_map);
    } else {
      if (!build_kind_specific(kind).IsDoneWithAbort()) {
        any_successful = true;
      }
      if (do_return.has_value()) {
        sub_graph.GotoOrTrim(&*do_return);
      }
    }
  }
  DCHECK_IMPLIES(!any_successful, !current_block_);
  return any_successful ? ReduceResult::Done() : ReduceResult::DoneWithAbort();
}

ReduceResult MaglevGraphBuilder::TryReduceArrayPrototypePush(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  // We can't reduce Function#call when there is no receiver function.
  if (args.receiver_mode() == ConvertReceiverMode::kNullOrUndefined) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  ! Failed to reduce Array.prototype.push - no receiver"
                << std::endl;
    }
    return ReduceResult::Fail();
  }
  // TODO(pthier): Support multiple arguments.
  if (args.count() != 1) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  ! Failed to reduce Array.prototype.push - invalid "
                   "argument count"
                << std::endl;
    }
    return ReduceResult::Fail();
  }
  ValueNode* receiver = GetValueOrUndefined(args.receiver());

  auto node_info = known_node_aspects().TryGetInfoFor(receiver);
  // If the map set is not found, then we don't know anything about the map of
  // the receiver, so bail.
  if (!node_info || !node_info->possible_maps_are_known()) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout
          << "  ! Failed to reduce Array.prototype.push - unknown receiver map"
          << std::endl;
    }
    return ReduceResult::Fail();
  }

  const PossibleMaps& possible_maps = node_info->possible_maps();
  // If the set of possible maps is empty, then there's no possible map for this
  // receiver, therefore this path is unreachable at runtime. We're unlikely to
  // ever hit this case, BuildCheckMaps should already unconditionally deopt,
  // but check it in case another checking operation fails to statically
  // unconditionally deopt.
  if (possible_maps.is_empty()) {
    // TODO(leszeks): Add an unreachable assert here.
    return ReduceResult::DoneWithAbort();
  }

  if (!broker()->dependencies()->DependOnNoElementsProtector()) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  ! Failed to reduce Array.prototype.push - "
                   "NoElementsProtector invalidated"
                << std::endl;
    }
    return ReduceResult::Fail();
  }

  // Check that inlining resizing array builtins is supported and group maps
  // by elements kind.
  std::array<SmallZoneVector<compiler::MapRef, 2>, 3> map_kinds = {
      SmallZoneVector<compiler::MapRef, 2>(zone()),
      SmallZoneVector<compiler::MapRef, 2>(zone()),
      SmallZoneVector<compiler::MapRef, 2>(zone())};
  // Function to group maps by elements kind, ignoring packedness. Packedness
  // doesn't matter for push().
  // Kinds we care about are all paired in the first 6 values of ElementsKind,
  // so we can use integer division to truncate holeyness.
  auto elements_kind_to_index = [&](ElementsKind kind) {
    static_assert(kFastElementsKindCount <= 6);
    static_assert(kFastElementsKindPackedToHoley == 1);
    return static_cast<uint8_t>(kind) / 2;
  };
  auto index_to_elements_kind = [&](uint8_t kind_index) {
    return static_cast<ElementsKind>(kind_index * 2);
  };
  int unique_kind_count;
  if (!CanInlineArrayResizingBuiltin(broker(), possible_maps, map_kinds,
                                     elements_kind_to_index, &unique_kind_count,
                                     false)) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  ! Failed to reduce Array.prototype.push - Map doesn't "
                   "support fast resizing"
                << std::endl;
    }
    return ReduceResult::Fail();
  }

  MaglevSubGraphBuilder sub_graph(this, 0);

  std::optional<MaglevSubGraphBuilder::Label> do_return;
  if (unique_kind_count > 1) {
    do_return.emplace(&sub_graph, unique_kind_count);
  }

  ValueNode* old_array_length_smi;
  GET_VALUE_OR_ABORT(old_array_length_smi,
                     GetSmiValue(BuildLoadJSArrayLength(receiver)));
  ValueNode* old_array_length =
      AddNewNode<UnsafeSmiUntag>({old_array_length_smi});
  ValueNode* new_array_length_smi =
      AddNewNode<CheckedSmiIncrement>({old_array_length_smi});

  ValueNode* elements_array = BuildLoadElements(receiver);
  ValueNode* elements_array_length = BuildLoadFixedArrayLength(elements_array);

  auto build_array_push = [&](ElementsKind kind) {
    ValueNode* value;
    GET_VALUE_OR_ABORT(value, ConvertForStoring(args[0], kind));

    ValueNode* writable_elements_array = AddNewNode<MaybeGrowFastElements>(
        {elements_array, receiver, old_array_length, elements_array_length},
        kind);

    AddNewNode<StoreTaggedFieldNoWriteBarrier>({receiver, new_array_length_smi},
                                               JSArray::kLengthOffset,
                                               StoreTaggedMode::kDefault);

    // Do the store
    if (IsDoubleElementsKind(kind)) {
      BuildStoreFixedDoubleArrayElement(writable_elements_array,
                                        old_array_length, value);
    } else {
      DCHECK(IsSmiElementsKind(kind) || IsObjectElementsKind(kind));
      BuildStoreFixedArrayElement(writable_elements_array, old_array_length,
                                  value);
    }
    return ReduceResult::Done();
  };

  RETURN_IF_ABORT(BuildJSArrayBuiltinMapSwitchOnElementsKind(
      receiver, map_kinds, sub_graph, do_return, unique_kind_count,
      index_to_elements_kind, build_array_push));

  if (do_return.has_value()) {
    sub_graph.Bind(&*do_return);
  }
  RecordKnownProperty(receiver, broker()->length_string(), new_array_length_smi,
                      false, compiler::AccessMode::kStore);
  return new_array_length_smi;
}

ReduceResult MaglevGraphBuilder::TryReduceArrayPrototypePop(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  // We can't reduce Function#call when there is no receiver function.
  if (args.receiver_mode() == ConvertReceiverMode::kNullOrUndefined) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  ! Failed to reduce Array.prototype.pop - no receiver"
                << std::endl;
    }
    return ReduceResult::Fail();
  }

  ValueNode* receiver = GetValueOrUndefined(args.receiver());

  auto node_info = known_node_aspects().TryGetInfoFor(receiver);
  // If the map set is not found, then we don't know anything about the map of
  // the receiver, so bail.
  if (!node_info || !node_info->possible_maps_are_known()) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout
          << "  ! Failed to reduce Array.prototype.pop - unknown receiver map"
          << std::endl;
    }
    return ReduceResult::Fail();
  }

  const PossibleMaps& possible_maps = node_info->possible_maps();

  // If the set of possible maps is empty, then there's no possible map for this
  // receiver, therefore this path is unreachable at runtime. We're unlikely to
  // ever hit this case, BuildCheckMaps should already unconditionally deopt,
  // but check it in case another checking operation fails to statically
  // unconditionally deopt.
  if (possible_maps.is_empty()) {
    // TODO(leszeks): Add an unreachable assert here.
    return ReduceResult::DoneWithAbort();
  }

  if (!broker()->dependencies()->DependOnNoElementsProtector()) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  ! Failed to reduce Array.prototype.pop - "
                   "NoElementsProtector invalidated"
                << std::endl;
    }
    return ReduceResult::Fail();
  }

  constexpr int max_kind_count = 4;
  std::array<SmallZoneVector<compiler::MapRef, 2>, max_kind_count> map_kinds = {
      SmallZoneVector<compiler::MapRef, 2>(zone()),
      SmallZoneVector<compiler::MapRef, 2>(zone()),
      SmallZoneVector<compiler::MapRef, 2>(zone()),
      SmallZoneVector<compiler::MapRef, 2>(zone())};
  // Smi and Object elements kinds are treated as identical for pop, so we can
  // group them together without differentiation.
  // ElementsKind is mapped to an index in the 4 element array using:
  //   - Bit 2 (Only set for double in the fast element range) is mapped to bit
  //   1)
  //   - Bit 0 (packedness)
  // The complete mapping:
  // +-------+----------------------------------------------+
  // | Index |    ElementsKinds                             |
  // +-------+----------------------------------------------+
  // |   0   |    PACKED_SMI_ELEMENTS and PACKED_ELEMENTS   |
  // |   1   |    HOLEY_SMI_ELEMENETS and HOLEY_ELEMENTS    |
  // |   2   |    PACKED_DOUBLE_ELEMENTS                    |
  // |   3   |    HOLEY_DOUBLE_ELEMENTS                     |
  // +-------+----------------------------------------------+
  auto elements_kind_to_index = [&](ElementsKind kind) {
    uint8_t kind_int = static_cast<uint8_t>(kind);
    uint8_t kind_index = ((kind_int & 0x4) >> 1) | (kind_int & 0x1);
    DCHECK_LT(kind_index, max_kind_count);
    return kind_index;
  };
  auto index_to_elements_kind = [&](uint8_t kind_index) {
    uint8_t kind_int;
    kind_int = ((kind_index & 0x2) << 1) | (kind_index & 0x1);
    return static_cast<ElementsKind>(kind_int);
  };

  int unique_kind_count;
  if (!CanInlineArrayResizingBuiltin(broker(), possible_maps, map_kinds,
                                     elements_kind_to_index, &unique_kind_count,
                                     true)) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  ! Failed to reduce Array.prototype.pop - Map doesn't "
                   "support fast resizing"
                << std::endl;
    }
    return ReduceResult::Fail();
  }

  MaglevSubGraphBuilder sub_graph(this, 2);
  MaglevSubGraphBuilder::Variable var_value(0);
  MaglevSubGraphBuilder::Variable var_new_array_length(1);

  std::optional<MaglevSubGraphBuilder::Label> do_return =
      std::make_optional<MaglevSubGraphBuilder::Label>(
          &sub_graph, unique_kind_count + 1,
          std::initializer_list<MaglevSubGraphBuilder::Variable*>{
              &var_value, &var_new_array_length});
  MaglevSubGraphBuilder::Label empty_array(&sub_graph, 1);

  ValueNode* old_array_length_smi;
  GET_VALUE_OR_ABORT(old_array_length_smi,
                     GetSmiValue(BuildLoadJSArrayLength(receiver)));

  // If the array is empty, skip the pop and return undefined.
  sub_graph.GotoIfTrue<BranchIfReferenceEqual>(
      &empty_array, {old_array_length_smi, GetSmiConstant(0)});

  ValueNode* elements_array = BuildLoadElements(receiver);
  ValueNode* new_array_length_smi =
      AddNewNode<CheckedSmiDecrement>({old_array_length_smi});
  ValueNode* new_array_length =
      AddNewNode<UnsafeSmiUntag>({new_array_length_smi});
  sub_graph.set(var_new_array_length, new_array_length_smi);

  auto build_array_pop = [&](ElementsKind kind) {
    // Handle COW if needed.
    ValueNode* writable_elements_array =
        IsSmiOrObjectElementsKind(kind)
            ? AddNewNode<EnsureWritableFastElements>({elements_array, receiver})
            : elements_array;

    // Store new length.
    AddNewNode<StoreTaggedFieldNoWriteBarrier>({receiver, new_array_length_smi},
                                               JSArray::kLengthOffset,
                                               StoreTaggedMode::kDefault);

    // Load the value and store the hole in it's place.
    ValueNode* value;
    if (IsDoubleElementsKind(kind)) {
      value = BuildLoadFixedDoubleArrayElement(writable_elements_array,
                                               new_array_length);
      BuildStoreFixedDoubleArrayElement(
          writable_elements_array, new_array_length,
          GetFloat64Constant(Float64::FromBits(kHoleNanInt64)));
    } else {
      DCHECK(IsSmiElementsKind(kind) || IsObjectElementsKind(kind));
      value =
          BuildLoadFixedArrayElement(writable_elements_array, new_array_length);
      BuildStoreFixedArrayElement(writable_elements_array, new_array_length,
                                  GetRootConstant(RootIndex::kTheHoleValue));
    }

    if (IsHoleyElementsKind(kind)) {
      value = AddNewNode<ConvertHoleToUndefined>({value});
    }
    sub_graph.set(var_value, value);
    return ReduceResult::Done();
  };

  RETURN_IF_ABORT(BuildJSArrayBuiltinMapSwitchOnElementsKind(
      receiver, map_kinds, sub_graph, do_return, unique_kind_count,
      index_to_elements_kind, build_array_pop));

  sub_graph.Bind(&empty_array);
  sub_graph.set(var_new_array_length, GetSmiConstant(0));
  sub_graph.set(var_value, GetRootConstant(RootIndex::kUndefinedValue));
  sub_graph.Goto(&*do_return);

  sub_graph.Bind(&*do_return);
  RecordKnownProperty(receiver, broker()->length_string(),
                      sub_graph.get(var_new_array_length), false,
                      compiler::AccessMode::kStore);
  return sub_graph.get(var_value);
}

ReduceResult MaglevGraphBuilder::TryReduceFunctionPrototypeHasInstance(
    compiler::JSFunctionRef target, CallArguments& args) {
  // We can't reduce Function#hasInstance when there is no receiver function.
  if (args.receiver_mode() == ConvertReceiverMode::kNullOrUndefined) {
    return ReduceResult::Fail();
  }
  if (args.count() != 1) {
    return ReduceResult::Fail();
  }
  compiler::OptionalHeapObjectRef maybe_receiver_constant =
      TryGetConstant(args.receiver());
  if (!maybe_receiver_constant) {
    return ReduceResult::Fail();
  }
  compiler::HeapObjectRef receiver_object = maybe_receiver_constant.value();
  if (!receiver_object.IsJSObject() ||
      !receiver_object.map(broker()).is_callable()) {
    return ReduceResult::Fail();
  }
  return BuildOrdinaryHasInstance(args[0], receiver_object.AsJSObject(),
                                  nullptr);
}

ReduceResult MaglevGraphBuilder::TryReduceObjectPrototypeHasOwnProperty(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  if (args.receiver_mode() == ConvertReceiverMode::kNullOrUndefined) {
    return ReduceResult::Fail();
  }

  // We can constant-fold the {receiver.hasOwnProperty(name)} builtin call to
  // the {True} node in this case:

  //   for (name in receiver) {
  //     if (receiver.hasOwnProperty(name)) {
  //        ...
  //     }
  //   }

  if (args.count() != 1 || args[0] != current_for_in_state.key) {
    return ReduceResult::Fail();
  }
  ValueNode* receiver = args.receiver();
  if (receiver == current_for_in_state.receiver) {
    if (current_for_in_state.receiver_needs_map_check) {
      auto* receiver_map =
          BuildLoadTaggedField(receiver, HeapObject::kMapOffset);
      AddNewNode<CheckDynamicValue>(
          {receiver_map, current_for_in_state.cache_type});
      current_for_in_state.receiver_needs_map_check = false;
    }
    return GetRootConstant(RootIndex::kTrueValue);
  }

  // We can also optimize for this case below:

  // receiver(is a heap constant with fast map)
  //  ^
  //  |    object(all keys are enumerable)
  //  |      ^
  //  |      |
  //  |   JSForInNext
  //  |      ^
  //  +----+ |
  //       | |
  //  JSCall[hasOwnProperty]

  // We can replace the {JSCall} with several internalized string
  // comparisons.

  compiler::OptionalMapRef maybe_receiver_map;
  compiler::OptionalHeapObjectRef receiver_ref = TryGetConstant(receiver);
  if (receiver_ref.has_value()) {
    compiler::HeapObjectRef receiver_object = receiver_ref.value();
    compiler::MapRef receiver_map = receiver_object.map(broker());
    maybe_receiver_map = receiver_map;
  } else {
    NodeInfo* known_info = GetOrCreateInfoFor(receiver);
    if (known_info->possible_maps_are_known()) {
      compiler::ZoneRefSet<Map> possible_maps = known_info->possible_maps();
      if (possible_maps.size() == 1) {
        compiler::MapRef receiver_map = *(possible_maps.begin());
        maybe_receiver_map = receiver_map;
      }
    }
  }
  if (!maybe_receiver_map.has_value()) {
    return ReduceResult::Fail();
  }

  compiler::MapRef receiver_map = maybe_receiver_map.value();
  InstanceType instance_type = receiver_map.instance_type();
  int const nof = receiver_map.NumberOfOwnDescriptors();
  // We set a heuristic value to limit the compare instructions number.
  if (nof > 4 || IsSpecialReceiverInstanceType(instance_type) ||
      receiver_map.is_dictionary_map()) {
    return ReduceResult::Fail();
  }
  RETURN_IF_ABORT(BuildCheckMaps(receiver, base::VectorOf({receiver_map})));
  //  Replace builtin call with several internalized string comparisons.
  MaglevSubGraphBuilder sub_graph(this, 1);
  MaglevSubGraphBuilder::Variable var_result(0);
  MaglevSubGraphBuilder::Label done(
      &sub_graph, nof + 1,
      std::initializer_list<MaglevSubGraphBuilder::Variable*>{&var_result});
  const compiler::DescriptorArrayRef descriptor_array =
      receiver_map.instance_descriptors(broker());
  for (InternalIndex key_index : InternalIndex::Range(nof)) {
    compiler::NameRef receiver_key =
        descriptor_array.GetPropertyKey(broker(), key_index);
    ValueNode* lhs = GetConstant(receiver_key);
    sub_graph.set(var_result, GetRootConstant(RootIndex::kTrueValue));
    sub_graph.GotoIfTrue<BranchIfReferenceEqual>(&done, {lhs, args[0]});
  }
  sub_graph.set(var_result, GetRootConstant(RootIndex::kFalseValue));
  sub_graph.Goto(&done);
  sub_graph.Bind(&done);
  return sub_graph.get(var_result);
}

ReduceResult MaglevGraphBuilder::TryReduceGetProto(ValueNode* object) {
  NodeInfo* info = known_node_aspects().TryGetInfoFor(object);
  if (!info || !info->possible_maps_are_known()) {
    return ReduceResult::Fail();
  }
  auto& possible_maps = info->possible_maps();
  if (possible_maps.is_empty()) {
    return ReduceResult::DoneWithAbort();
  }
  auto it = possible_maps.begin();
  compiler::MapRef map = *it;
  if (IsSpecialReceiverInstanceType(map.instance_type())) {
    return ReduceResult::Fail();
  }
  DCHECK(!map.IsPrimitiveMap() && map.IsJSReceiverMap());
  compiler::HeapObjectRef proto = map.prototype(broker());
  ++it;
  for (; it != possible_maps.end(); ++it) {
    map = *it;
    if (IsSpecialReceiverInstanceType(map.instance_type()) ||
        !proto.equals(map.prototype(broker()))) {
      return ReduceResult::Fail();
    }
    DCHECK(!map.IsPrimitiveMap() && map.IsJSReceiverMap());
  }
  return GetConstant(proto);
}

ReduceResult MaglevGraphBuilder::TryReduceObjectPrototypeGetProto(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (args.count() != 0) {
    return ReduceResult::Fail();
  }
  return TryReduceGetProto(args.receiver());
}

ReduceResult MaglevGraphBuilder::TryReduceObjectGetPrototypeOf(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (args.count() != 1) {
    return ReduceResult::Fail();
  }
  return TryReduceGetProto(args[0]);
}

ReduceResult MaglevGraphBuilder::TryReduceReflectGetPrototypeOf(
    compiler::JSFunctionRef target, CallArguments& args) {
  return TryReduceObjectGetPrototypeOf(target, args);
}

ReduceResult MaglevGraphBuilder::TryReduceMathRound(
    compiler::JSFunctionRef target, CallArguments& args) {
  return DoTryReduceMathRound(args, Float64Round::Kind::kNearest);
}

ReduceResult MaglevGraphBuilder::TryReduceNumberParseInt(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (args.count() == 0) {
    return GetRootConstant(RootIndex::kNanValue);
  }
  if (args.count() != 1) {
    if (RootConstant* c = args[1]->TryCast<RootConstant>()) {
      if (c->index() != RootIndex::kUndefinedValue) {
        return ReduceResult::Fail();
      }
    } else if (SmiConstant* c = args[1]->TryCast<SmiConstant>()) {
      if (c->value().value() != 10 && c->value().value() != 0) {
        return ReduceResult::Fail();
      }
    } else {
      return ReduceResult::Fail();
    }
  }

  ValueNode* arg = args[0];

  switch (arg->value_representation()) {
    case ValueRepresentation::kUint32:
    case ValueRepresentation::kInt32:
      return arg;
    case ValueRepresentation::kTagged:
      switch (CheckTypes(arg, {NodeType::kSmi})) {
        case NodeType::kSmi:
          return arg;
        default:
          // TODO(verwaest): Support actually parsing strings, converting
          // doubles to ints, ...
          return ReduceResult::Fail();
      }
    case ValueRepresentation::kIntPtr:
      UNREACHABLE();
    case ValueRepresentation::kFloat64:
    case ValueRepresentation::kHoleyFloat64:
      return ReduceResult::Fail();
  }
}

ReduceResult MaglevGraphBuilder::TryReduceMathAbs(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (args.count() == 0) {
    return GetRootConstant(RootIndex::kNanValue);
  }
  ValueNode* arg = args[0];

  switch (arg->value_representation()) {
    case ValueRepresentation::kUint32:
      return arg;
    case ValueRepresentation::kInt32:
      if (!CanSpeculateCall()) {
        return ReduceResult::Fail();
      }
      return AddNewNode<Int32AbsWithOverflow>({arg});
    case ValueRepresentation::kTagged:
      switch (CheckTypes(arg, {NodeType::kSmi, NodeType::kNumberOrOddball})) {
        case NodeType::kSmi:
          if (!CanSpeculateCall()) return ReduceResult::Fail();
          return AddNewNode<Int32AbsWithOverflow>({arg});
        case NodeType::kNumberOrOddball:
          return AddNewNode<Float64Abs>({GetHoleyFloat64ForToNumber(
              arg, ToNumberHint::kAssumeNumberOrOddball)});
        // TODO(verwaest): Add support for ToNumberOrNumeric and deopt.
        default:
          break;
      }
      break;
    case ValueRepresentation::kIntPtr:
      UNREACHABLE();
    case ValueRepresentation::kFloat64:
    case ValueRepresentation::kHoleyFloat64:
      return AddNewNode<Float64Abs>({arg});
  }
  return ReduceResult::Fail();
}

ReduceResult MaglevGraphBuilder::TryReduceMathFloor(
    compiler::JSFunctionRef target, CallArguments& args) {
  return DoTryReduceMathRound(args, Float64Round::Kind::kFloor);
}

ReduceResult MaglevGraphBuilder::TryReduceMathCeil(
    compiler::JSFunctionRef target, CallArguments& args) {
  return DoTryReduceMathRound(args, Float64Round::Kind::kCeil);
}

ReduceResult MaglevGraphBuilder::DoTryReduceMathRound(CallArguments& args,
                                                      Float64Round::Kind kind) {
  if (args.count() == 0) {
    return GetRootConstant(RootIndex::kNanValue);
  }
  ValueNode* arg = args[0];
  auto arg_repr = arg->value_representation();
  if (arg_repr == ValueRepresentation::kInt32 ||
      arg_repr == ValueRepresentation::kUint32) {
    return arg;
  }
  if (CheckType(arg, NodeType::kSmi)) return arg;
  if (!IsSupported(CpuOperation::kFloat64Round)) {
    return ReduceResult::Fail();
  }
  if (arg_repr == ValueRepresentation::kFloat64 ||
      arg_repr == ValueRepresentation::kHoleyFloat64) {
    return AddNewNode<Float64Round>({arg}, kind);
  }
  DCHECK_EQ(arg_repr, ValueRepresentation::kTagged);
  if (CheckType(arg, NodeType::kNumberOrOddball)) {
    return AddNewNode<Float64Round>(
        {GetHoleyFloat64ForToNumber(arg, ToNumberHint::kAssumeNumberOrOddball)},
        kind);
  }
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  DeoptFrameScope continuation_scope(this, Float64Round::continuation(kind));
  ToNumberOrNumeric* conversion =
      AddNewNode<ToNumberOrNumeric>({arg}, Object::Conversion::kToNumber);
  ValueNode* float64_value = AddNewNode<UncheckedNumberOrOddballToFloat64>(
      {conversion}, TaggedToFloat64ConversionType::kOnlyNumber);
  return AddNewNode<Float64Round>({float64_value}, kind);
}

ReduceResult MaglevGraphBuilder::TryReduceArrayConstructor(
    compiler::JSFunctionRef target, CallArguments& args) {
  return TryReduceConstructArrayConstructor(target, args);
}

ReduceResult MaglevGraphBuilder::TryReduceStringConstructor(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (args.count() == 0) {
    return GetRootConstant(RootIndex::kempty_string);
  }

  return BuildToString(args[0], ToString::kConvertSymbol);
}

ReduceResult MaglevGraphBuilder::TryReduceMathPow(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (args.count() < 2) {
    // For < 2 args, we'll be calculating Math.Pow(arg[0], undefined), which is
    // ToNumber(arg[0]) ** NaN == NaN. So we can just return NaN.
    // However, if there is a single argument and it's tagged, we have to call
    // ToNumber on it before returning NaN, for side effects. This call could
    // lazy deopt, which would mean we'd need a continuation to actually set
    // the NaN return value... it's easier to just bail out, this should be
    // an uncommon case anyway.
    if (args.count() == 1 && args[0]->properties().is_tagged()) {
      return ReduceResult::Fail();
    }
    return GetRootConstant(RootIndex::kNanValue);
  }
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  // If both arguments are tagged, it is cheaper to call Math.Pow builtin,
  // instead of Float64Exponentiate, since we are still making a call and we
  // don't need to unbox both inputs. See https://crbug.com/1393643.
  if (args[0]->properties().is_tagged() && args[1]->properties().is_tagged()) {
    // The Math.pow call will be created in CallKnownJSFunction reduction.
    return ReduceResult::Fail();
  }
  ValueNode* left =
      GetHoleyFloat64ForToNumber(args[0], ToNumberHint::kAssumeNumber);
  ValueNode* right =
      GetHoleyFloat64ForToNumber(args[1], ToNumberHint::kAssumeNumber);
  return AddNewNode<Float64Exponentiate>({left, right});
}

#define MATH_UNARY_IEEE_BUILTIN_REDUCER(MathName, ExtName, EnumName)          \
  ReduceResult MaglevGraphBuilder::TryReduce##MathName(                       \
      compiler::JSFunctionRef target, CallArguments& args) {                  \
    if (args.count() < 1) {                                                   \
      return GetRootConstant(RootIndex::kNanValue);                           \
    }                                                                         \
    if (!CanSpeculateCall()) {                                                \
      ValueRepresentation rep = args[0]->properties().value_representation(); \
      if (rep == ValueRepresentation::kTagged ||                              \
          rep == ValueRepresentation::kHoleyFloat64) {                        \
        return ReduceResult::Fail();                                          \
      }                                                                       \
    }                                                                         \
    ValueNode* value =                                                        \
        GetFloat64ForToNumber(args[0], ToNumberHint::kAssumeNumber);          \
    return AddNewNode<Float64Ieee754Unary>(                                   \
        {value}, Float64Ieee754Unary::Ieee754Function::k##EnumName);          \
  }

IEEE_754_UNARY_LIST(MATH_UNARY_IEEE_BUILTIN_REDUCER)
#undef MATH_UNARY_IEEE_BUILTIN_REDUCER

ReduceResult MaglevGraphBuilder::TryReduceBuiltin(
    compiler::JSFunctionRef target, compiler::SharedFunctionInfoRef shared,
    CallArguments& args, const compiler::FeedbackSource& feedback_source) {
  if (args.mode() != CallArguments::kDefault) {
    // TODO(victorgomes): Maybe inline the spread stub? Or call known function
    // directly if arguments list is an array.
    return ReduceResult::Fail();
  }
  SaveCallSpeculationScope speculate(this, feedback_source);
  if (!shared.HasBuiltinId()) {
    return ReduceResult::Fail();
  }
  if (v8_flags.trace_maglev_graph_building) {
    std::cout << "  ! Trying to reduce builtin "
              << Builtins::name(shared.builtin_id()) << std::endl;
  }
  switch (shared.builtin_id()) {
#define CASE(Name, ...)  \
  case Builtin::k##Name: \
    return TryReduce##Name(target, args);
    MAGLEV_REDUCED_BUILTIN(CASE)
#undef CASE
    default:
      // TODO(v8:7700): Inline more builtins.
      return ReduceResult::Fail();
  }
}

ValueNode* MaglevGraphBuilder::GetConvertReceiver(
    compiler::SharedFunctionInfoRef shared, const CallArguments& args) {
  if (shared.native() || shared.language_mode() == LanguageMode::kStrict) {
    if (args.receiver_mode() == ConvertReceiverMode::kNullOrUndefined) {
      return GetRootConstant(RootIndex::kUndefinedValue);
    } else {
      return args.receiver();
    }
  }
  if (args.receiver_mode() == ConvertReceiverMode::kNullOrUndefined) {
    return GetConstant(
        broker()->target_native_context().global_proxy_object(broker()));
  }
  ValueNode* receiver = args.receiver();
  if (CheckType(receiver, NodeType::kJSReceiver)) return receiver;
  if (compiler::OptionalHeapObjectRef maybe_constant =
          TryGetConstant(receiver)) {
    compiler::HeapObjectRef constant = maybe_constant.value();
    if (constant.IsNullOrUndefined()) {
      return GetConstant(
          broker()->target_native_context().global_proxy_object(broker()));
    }
  }
  return AddNewNode<ConvertReceiver>(
      {receiver}, broker()->target_native_context(), args.receiver_mode());
}

template <typename CallNode, typename... Args>
CallNode* MaglevGraphBuilder::AddNewCallNode(const CallArguments& args,
                                             Args&&... extra_args) {
  size_t input_count = args.count_with_receiver() + CallNode::kFixedInputCount;
  return AddNewNode<CallNode>(
      input_count,
      [&](CallNode* call) {
        int arg_index = 0;
        call->set_arg(arg_index++,
                      GetTaggedValue(GetValueOrUndefined(args.receiver())));
        for (size_t i = 0; i < args.count(); ++i) {
          call->set_arg(arg_index++, GetTaggedValue(args[i]));
        }
      },
      std::forward<Args>(extra_args)...);
}

ValueNode* MaglevGraphBuilder::BuildGenericCall(ValueNode* target,
                                                Call::TargetType target_type,
                                                const CallArguments& args) {
  // TODO(victorgomes): We do not collect call feedback from optimized/inlined
  // calls. In order to be consistent, we don't pass the feedback_source to the
  // IR, so that we avoid collecting for generic calls as well. We might want to
  // revisit this in the future.
  switch (args.mode()) {
    case CallArguments::kDefault:
      return AddNewCallNode<Call>(args, args.receiver_mode(), target_type,
                                  GetTaggedValue(target),
                                  GetTaggedValue(GetContext()));
    case CallArguments::kWithSpread:
      DCHECK_EQ(args.receiver_mode(), ConvertReceiverMode::kAny);
      return AddNewCallNode<CallWithSpread>(args, GetTaggedValue(target),
                                            GetTaggedValue(GetContext()));
    case CallArguments::kWithArrayLike:
      DCHECK_EQ(args.receiver_mode(), ConvertReceiverMode::kAny);
      // We don't use AddNewCallNode here, because the number of required
      // arguments is known statically.
      return AddNewNode<CallWithArrayLike>(
          {target, GetValueOrUndefined(args.receiver()), args[0],
           GetContext()});
  }
}

ValueNode* MaglevGraphBuilder::BuildCallSelf(
    ValueNode* context, ValueNode* function, ValueNode* new_target,
    compiler::SharedFunctionInfoRef shared, CallArguments& args) {
  ValueNode* receiver = GetConvertReceiver(shared, args);
  size_t input_count = args.count() + CallSelf::kFixedInputCount;
  graph()->set_has_recursive_calls(true);
  return AddNewNode<CallSelf>(
      input_count,
      [&](CallSelf* call) {
        for (int i = 0; i < static_cast<int>(args.count()); i++) {
          call->set_arg(i, GetTaggedValue(args[i]));
        }
      },
      shared, GetTaggedValue(function), GetTaggedValue(context),
      GetTaggedValue(receiver), GetTaggedValue(new_target));
}

bool MaglevGraphBuilder::TargetIsCurrentCompilingUnit(
    compiler::JSFunctionRef target) {
  if (compilation_unit_->info()->specialize_to_function_context()) {
    return target.object().equals(
        compilation_unit_->info()->toplevel_function());
  }
  return target.object()->shared() ==
         compilation_unit_->info()->toplevel_function()->shared();
}

ReduceResult MaglevGraphBuilder::ReduceCallForApiFunction(
    compiler::FunctionTemplateInfoRef api_callback,
    compiler::OptionalSharedFunctionInfoRef maybe_shared,
    compiler::OptionalJSObjectRef api_holder, CallArguments& args) {
  if (args.mode() != CallArguments::kDefault) {
    // TODO(victorgomes): Maybe inline the spread stub? Or call known function
    // directly if arguments list is an array.
    return ReduceResult::Fail();
  }
  // Check if the function has an associated C++ code to execute.
  compiler::OptionalObjectRef maybe_callback_data =
      api_callback.callback_data(broker());
  if (!maybe_callback_data.has_value()) {
    // TODO(ishell): consider generating "return undefined" for empty function
    // instead of failing.
    return ReduceResult::Fail();
  }

  size_t input_count = args.count() + CallKnownApiFunction::kFixedInputCount;
  ValueNode* receiver;
  if (maybe_shared.has_value()) {
    receiver = GetConvertReceiver(maybe_shared.value(), args);
  } else {
    receiver = args.receiver();
    CHECK_NOT_NULL(receiver);
  }

  CallKnownApiFunction::Mode mode =
      broker()->dependencies()->DependOnNoProfilingProtector()
          ? (v8_flags.maglev_inline_api_calls
                 ? CallKnownApiFunction::kNoProfilingInlined
                 : CallKnownApiFunction::kNoProfiling)
          : CallKnownApiFunction::kGeneric;

  return AddNewNode<CallKnownApiFunction>(
      input_count,
      [&](CallKnownApiFunction* call) {
        for (int i = 0; i < static_cast<int>(args.count()); i++) {
          call->set_arg(i, GetTaggedValue(args[i]));
        }
      },
      mode, api_callback, api_holder, GetTaggedValue(GetContext()),
      GetTaggedValue(receiver));
}

ReduceResult MaglevGraphBuilder::TryBuildCallKnownApiFunction(
    compiler::JSFunctionRef function, compiler::SharedFunctionInfoRef shared,
    CallArguments& args) {
  compiler::OptionalFunctionTemplateInfoRef maybe_function_template_info =
      shared.function_template_info(broker());
  if (!maybe_function_template_info.has_value()) {
    // Not an Api function.
    return ReduceResult::Fail();
  }

  // See if we can optimize this API call.
  compiler::FunctionTemplateInfoRef function_template_info =
      maybe_function_template_info.value();

  compiler::HolderLookupResult api_holder;
  if (function_template_info.accept_any_receiver() &&
      function_template_info.is_signature_undefined(broker())) {
    // We might be able to optimize the API call depending on the
    // {function_template_info}.
    // If the API function accepts any kind of {receiver}, we only need to
    // ensure that the {receiver} is actually a JSReceiver at this point,
    // and also pass that as the {holder}. There are two independent bits
    // here:
    //
    //  a. When the "accept any receiver" bit is set, it means we don't
    //     need to perform access checks, even if the {receiver}'s map
    //     has the "needs access check" bit set.
    //  b. When the {function_template_info} has no signature, we don't
    //     need to do the compatible receiver check, since all receivers
    //     are considered compatible at that point, and the {receiver}
    //     will be pass as the {holder}.

    api_holder =
        compiler::HolderLookupResult{CallOptimization::kHolderIsReceiver};
  } else {
    // Try to infer API holder from the known aspects of the {receiver}.
    api_holder =
        TryInferApiHolderValue(function_template_info, args.receiver());
  }

  switch (api_holder.lookup) {
    case CallOptimization::kHolderIsReceiver:
    case CallOptimization::kHolderFound:
      return ReduceCallForApiFunction(function_template_info, shared,
                                      api_holder.holder, args);

    case CallOptimization::kHolderNotFound:
      break;
  }

  // We don't have enough information to eliminate the access check
  // and/or the compatible receiver check, so use the generic builtin
  // that does those checks dynamically. This is still significantly
  // faster than the generic call sequence.
  Builtin builtin_name;
  // TODO(ishell): create no-profiling versions of kCallFunctionTemplate
  // builtins and use them here based on DependOnNoProfilingProtector()
  // dependency state.
  if (function_template_info.accept_any_receiver()) {
    DCHECK(!function_template_info.is_signature_undefined(broker()));
    builtin_name = Builtin::kCallFunctionTemplate_CheckCompatibleReceiver;
  } else if (function_template_info.is_signature_undefined(broker())) {
    builtin_name = Builtin::kCallFunctionTemplate_CheckAccess;
  } else {
    builtin_name =
        Builtin::kCallFunctionTemplate_CheckAccessAndCompatibleReceiver;
  }

  // The CallFunctionTemplate builtin requires the {receiver} to be
  // an actual JSReceiver, so make sure we do the proper conversion
  // first if necessary.
  ValueNode* receiver = GetConvertReceiver(shared, args);
  int kContext = 1;
  int kFunctionTemplateInfo = 1;
  int kArgc = 1;
  return AddNewNode<CallBuiltin>(
      kFunctionTemplateInfo + kArgc + kContext + args.count_with_receiver(),
      [&](CallBuiltin* call_builtin) {
        int arg_index = 0;
        call_builtin->set_arg(arg_index++, GetConstant(function_template_info));
        call_builtin->set_arg(
            arg_index++,
            GetInt32Constant(JSParameterCount(static_cast<int>(args.count()))));

        call_builtin->set_arg(arg_index++, GetTaggedValue(receiver));
        for (int i = 0; i < static_cast<int>(args.count()); i++) {
          call_builtin->set_arg(arg_index++, GetTaggedValue(args[i]));
        }
      },
      builtin_name, GetTaggedValue(GetContext()));
}

ReduceResult MaglevGraphBuilder::TryBuildCallKnownJSFunction(
    compiler::JSFunctionRef function, ValueNode* new_target,
    CallArguments& args, const compiler::FeedbackSource& feedback_source) {
  // Don't inline CallFunction stub across native contexts.
  if (function.native_context(broker()) != broker()->target_native_context()) {
    return ReduceResult::Fail();
  }
  compiler::SharedFunctionInfoRef shared = function.shared(broker());
  RETURN_IF_DONE(TryBuildCallKnownApiFunction(function, shared, args));

  ValueNode* closure = GetConstant(function);
  compiler::ContextRef context = function.context(broker());
  ValueNode* context_node = GetConstant(context);
  ReduceResult res;
  if (MaglevIsTopTier() && TargetIsCurrentCompilingUnit(function) &&
      !graph_->is_osr()) {
    res = BuildCallSelf(context_node, closure, new_target, shared, args);
  } else {
    res = TryBuildCallKnownJSFunction(context_node, closure, new_target, shared,
                                      function.feedback_vector(broker()), args,
                                      feedback_source);
  }
  return res;
}

ReduceResult MaglevGraphBuilder::TryBuildCallKnownJSFunction(
    ValueNode* context, ValueNode* function, ValueNode* new_target,
    compiler::SharedFunctionInfoRef shared,
    compiler::OptionalFeedbackVectorRef feedback_vector, CallArguments& args,
    const compiler::FeedbackSource& feedback_source) {
  if (v8_flags.maglev_inlining) {
    RETURN_IF_DONE(TryBuildInlinedCall(context, function, new_target, shared,
                                       feedback_vector, args, feedback_source));
  }
  ValueNode* receiver = GetConvertReceiver(shared, args);
  size_t input_count = args.count() + CallKnownJSFunction::kFixedInputCount;
  return AddNewNode<CallKnownJSFunction>(
      input_count,
      [&](CallKnownJSFunction* call) {
        for (int i = 0; i < static_cast<int>(args.count()); i++) {
          call->set_arg(i, GetTaggedValue(args[i]));
        }
      },
      shared, GetTaggedValue(function), GetTaggedValue(context),
      GetTaggedValue(receiver), GetTaggedValue(new_target));
}

ReduceResult MaglevGraphBuilder::BuildCheckValue(ValueNode* node,
                                                 compiler::HeapObjectRef ref) {
  DCHECK(!ref.IsSmi());
  DCHECK(!ref.IsHeapNumber());

  if (compiler::OptionalHeapObjectRef maybe_constant = TryGetConstant(node)) {
    if (maybe_constant.value().equals(ref)) {
      return ReduceResult::Done();
    }
    return EmitUnconditionalDeopt(DeoptimizeReason::kUnknown);
  }
  if (ref.IsString()) {
    DCHECK(ref.IsInternalizedString());
    AddNewNode<CheckValueEqualsString>({node}, ref.AsInternalizedString());
    SetKnownValue(node, ref, NodeType::kString);
  } else {
    AddNewNode<CheckValue>({node}, ref);
    SetKnownValue(node, ref, StaticTypeForConstant(broker(), ref));
  }

  return ReduceResult::Done();
}

ReduceResult MaglevGraphBuilder::BuildCheckValue(ValueNode* node,
                                                 compiler::ObjectRef ref) {
  if (ref.IsHeapObject() && !ref.IsHeapNumber()) {
    return BuildCheckValue(node, ref.AsHeapObject());
  }
  if (ref.IsSmi()) {
    int ref_value = ref.AsSmi();
    if (IsConstantNode(node->opcode())) {
      if (node->Is<SmiConstant>() &&
          node->Cast<SmiConstant>()->value().value() == ref_value) {
        return ReduceResult::Done();
      }
      if (node->Is<Int32Constant>() &&
          node->Cast<Int32Constant>()->value() == ref_value) {
        return ReduceResult::Done();
      }
      return EmitUnconditionalDeopt(DeoptimizeReason::kUnknown);
    }
    AddNewNode<CheckValueEqualsInt32>({node}, ref_value);
  } else {
    DCHECK(ref.IsHeapNumber());
    Float64 ref_value = Float64::FromBits(ref.AsHeapNumber().value_as_bits());
    DCHECK(!ref_value.is_hole_nan());
    if (node->Is<Float64Constant>()) {
      Float64 f64 = node->Cast<Float64Constant>()->value();
      DCHECK(!f64.is_hole_nan());
      if (f64 == ref_value) {
        return ReduceResult::Done();
      }
      return EmitUnconditionalDeopt(DeoptimizeReason::kUnknown);
    } else if (compiler::OptionalHeapObjectRef constant =
                   TryGetConstant(node)) {
      if (constant.value().IsHeapNumber()) {
        Float64 f64 =
            Float64::FromBits(constant.value().AsHeapNumber().value_as_bits());
        DCHECK(!f64.is_hole_nan());
        if (f64 == ref_value) {
          return ReduceResult::Done();
        }
      }
      return EmitUnconditionalDeopt(DeoptimizeReason::kUnknown);
    }
    if (ref_value.is_nan()) {
      AddNewNode<CheckFloat64IsNan>({node});
    } else {
      AddNewNode<CheckValueEqualsFloat64>({node}, ref_value);
    }
  }
  SetKnownValue(node, ref, NodeType::kNumber);
  return ReduceResult::Done();
}

ValueNode* MaglevGraphBuilder::BuildConvertHoleToUndefined(ValueNode* node) {
  if (!node->is_tagged()) return node;
  compiler::OptionalHeapObjectRef maybe_constant = TryGetConstant(node);
  if (maybe_constant) {
    return maybe_constant.value().IsTheHole()
               ? GetRootConstant(RootIndex::kUndefinedValue)
               : node;
  }
  return AddNewNode<ConvertHoleToUndefined>({node});
}

ReduceResult MaglevGraphBuilder::BuildCheckNotHole(ValueNode* node) {
  if (!node->is_tagged()) return ReduceResult::Done();
  compiler::OptionalHeapObjectRef maybe_constant = TryGetConstant(node);
  if (maybe_constant) {
    if (maybe_constant.value().IsTheHole()) {
      return EmitUnconditionalDeopt(DeoptimizeReason::kHole);
    }
    return ReduceResult::Done();
  }
  AddNewNode<CheckNotHole>({node});
  return ReduceResult::Done();
}

ReduceResult MaglevGraphBuilder::ReduceCallForConstant(
    compiler::JSFunctionRef target, CallArguments& args,
    const compiler::FeedbackSource& feedback_source) {
  if (args.mode() != CallArguments::kDefault) {
    // TODO(victorgomes): Maybe inline the spread stub? Or call known function
    // directly if arguments list is an array.
    return ReduceResult::Fail();
  }
  compiler::SharedFunctionInfoRef shared = target.shared(broker());
  ValueNode* target_node = GetConstant(target);
  // Do not reduce calls to functions with break points.
  if (!shared.HasBreakInfo(broker())) {
    if (IsClassConstructor(shared.kind())) {
      // If we have a class constructor, we should raise an exception.
      return BuildCallRuntime(Runtime::kThrowConstructorNonCallableError,
                              {target_node});
    }
    DCHECK(IsCallable(*target.object()));
    RETURN_IF_DONE(TryReduceBuiltin(target, shared, args, feedback_source));
    RETURN_IF_DONE(TryBuildCallKnownJSFunction(
        target, GetRootConstant(RootIndex::kUndefinedValue), args,
        feedback_source));
  }
  return BuildGenericCall(target_node, Call::TargetType::kJSFunction, args);
}

compiler::HolderLookupResult MaglevGraphBuilder::TryInferApiHolderValue(
    compiler::FunctionTemplateInfoRef function_template_info,
    ValueNode* receiver) {
  const compiler::HolderLookupResult not_found;

  auto receiver_info = known_node_aspects().TryGetInfoFor(receiver);
  if (!receiver_info || !receiv
```