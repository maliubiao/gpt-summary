Response:
The user wants to understand the functionality of the V8 source code file `v8/src/compiler/js-call-reducer.cc`. They have also provided some specific instructions on how the explanation should be structured.

Here's a breakdown of the thinking process to generate the response:

1. **Identify the core purpose of `js-call-reducer.cc`:** The name itself, "js-call-reducer," strongly suggests that this code is responsible for optimizing JavaScript calls within the V8 compiler. Specifically, it likely involves transforming or "reducing" JavaScript call nodes in the compiler's intermediate representation (IR).

2. **Scan the code for key functionalities:**  Quickly read through the provided code snippets to identify the different JavaScript methods or operations being handled. Keywords like "ReduceArrayPrototypeSlice," "ReduceArrayIsArray," "ReduceStringPrototypeCharAt," etc., clearly indicate the different reduction scenarios.

3. **Categorize the functionalities:** Group the identified functionalities into logical categories. Based on the code, the primary categories appear to be:
    * Array methods (`slice`, `isArray`, iterators)
    * String methods (`charCodeAt`, `codePointAt`, `startsWith`, `endsWith`, `charAt`, `toLowerCase`, `toUpperCase`, `fromCodePoint`, `iterator`, `localeCompare`, `concat`)
    * Generic optimizations (like merging arguments).

4. **Explain each category and individual function:** For each identified function, explain:
    * **Its purpose:**  What does the original JavaScript method do?
    * **The reduction strategy:** How does the `JSCallReducer` optimize this call?  This often involves:
        * Inlining built-in functionality.
        * Replacing with simpler or more specialized IR nodes.
        * Adding checks or dependencies for deoptimization.
        * Constant folding where possible.
    * **JavaScript examples:**  Provide simple JavaScript code demonstrating the method being reduced.

5. **Address the specific instructions:**
    * **`.tq` extension:** Explicitly state that the file is a C++ file and not a Torque file (since it ends with `.cc`).
    * **JavaScript relation:** Ensure each functionality is linked to its corresponding JavaScript counterpart with examples.
    * **Logic inference (input/output):** For some reductions (like `Array.isArray`), it's possible to infer the output based on the input. Provide such examples.
    * **Common programming errors:**  Where relevant, point out typical mistakes programmers might make that these reductions handle or might cause deoptimization.
    * **Summarize overall functionality:**  Provide a concise summary of the role of `js-call-reducer.cc`.

6. **Structure the response:** Organize the information clearly using headings and bullet points for readability.

7. **Refine and review:** Read through the generated explanation to ensure accuracy, clarity, and completeness. Make sure all aspects of the user's request are addressed. For example, double-check that the JavaScript examples are correct and illustrative. Ensure the language is precise and avoids jargon where possible, or explains it when necessary.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus heavily on the low-level compiler details.
* **Correction:** Shift the focus to explaining the high-level impact on JavaScript execution and the intent behind the optimizations. The user is likely more interested in *what* is being optimized and *why*, rather than the intricate details of the IR transformations.
* **Initial thought:** Provide very detailed explanations of each optimization.
* **Correction:** Keep the explanations concise and focused on the key aspects of each reduction. Avoid getting bogged down in implementation specifics that might not be relevant to the user's understanding.
* **Initial thought:**  Treat all reductions equally.
* **Correction:**  Give more emphasis to the more common and important optimizations, like those for array and string methods.

By following this structured thinking process and incorporating self-correction, the aim is to produce a comprehensive and easy-to-understand explanation of the `js-call-reducer.cc` file.
Based on the provided C++ source code for `v8/src/compiler/js-call-reducer.cc`, here's a breakdown of its functionality:

**Core Functionality: Optimizing JavaScript Calls**

The primary goal of `js-call-reducer.cc` is to optimize JavaScript function calls during the Turbofan compilation process in V8. It acts as a **reducer**, meaning it looks for specific patterns of JavaScript calls and attempts to replace them with more efficient sequences of lower-level operations. This process is crucial for improving the performance of JavaScript code.

**Key Functionalities and Reductions:**

The code snippet illustrates reductions for several built-in JavaScript functions and operations, primarily focusing on `Array` and `String` methods. Here's a summary of the observed functionalities:

* **Array Methods:**
    * **`Array.prototype.slice()`:**  Optimizes the `slice` method, especially in the common case where it's used to clone an array (when `start` is 0 and `end` is undefined). It may replace this with a call to the `CloneFastJSArray` built-in for potentially copy-on-write arrays.
    * **`Array.isArray()`:**  Simplifies calls to `Array.isArray()`. If the argument is known to be `undefined`, it directly returns `false`. Otherwise, it transforms the call into a lower-level `ObjectIsArray` operation.
    * **Array Iterators (`Array.prototype.values()`, `Array.prototype.keys()`, `Array.prototype.entries()`):**  Reduces calls to create array iterators by directly creating a `JSCreateArrayIterator` node with the appropriate iteration kind. It also handles optimizations for typed arrays, including checks for detached buffers.
    * **`%ArrayIteratorPrototype%.next()`:**  Optimizes the `next()` method of array iterators. It inlines the logic for retrieving the next element, handling bounds checks, and creating the iterator result object. It also handles TypedArray iteration and potential buffer detachment.

* **String Methods:**
    * **`String.prototype.charCodeAt()` and `String.prototype.codePointAt()`:** Optimizes these methods by performing checks to ensure the receiver is a string and the index is within bounds. It then replaces the call with the lower-level `StringCharCodeAt` or `StringCodePointAt` operations.
    * **`String.prototype.startsWith()` and `String.prototype.endsWith()`:**  Attempts to inline the logic for `startsWith` and `endsWith`, especially when the `searchString` is a constant string with a length within a certain limit.
    * **`String.prototype.charAt()`:** Optimizes `charAt` by attempting constant folding if the receiver is a known string and the index is a known number within range. Otherwise, it inlines the necessary checks and operations.
    * **`String.prototype.toLowerCase()` and `String.prototype.toUpperCase()` (with Intl support):**  Reduces these calls to simpler `StringToLowerCaseIntl` and `StringToUpperCaseIntl` operations after verifying the receiver is a string.
    * **`String.fromCharCode()`:** Optimizes `String.fromCharCode()` when called with a single argument by converting the argument to a number and using the `StringFromSingleCharCode` operation.
    * **`String.fromCodePoint()`:**  Optimizes `String.fromCodePoint()` with a single argument by ensuring the argument is within the valid code point range and using the `StringFromSingleCodePoint` operation.
    * **`String.prototype.iterator()`:**  Replaces calls to get a string iterator with a direct creation of a `CreateStringIterator` node.
    * **`String.prototype.localeCompare()` (with Intl support):**  Attempts to optimize `localeCompare` by potentially replacing it with a faster `StringFastLocaleCompare` built-in if certain conditions regarding locales and options are met.
    * **`%StringIteratorPrototype%.next()`:** Optimizes the `next()` method of string iterators, similar to array iterators, by inlining the logic to retrieve the next character (code point) and creating the iterator result object.

**Is it a Torque file?**

The prompt states: "如果v8/src/compiler/js-call-reducer.cc以.tq结尾，那它是个v8 torque源代码". Since the file ends with `.cc`, it is **not** a V8 Torque source code file. It is a **C++** source code file. Torque files typically have the `.tq` extension.

**Relation to JavaScript Functionality with Examples:**

Yes, all the functionalities listed above directly correspond to built-in JavaScript methods. Here are examples:

* **`Array.prototype.slice()`:**
   ```javascript
   const arr = [1, 2, 3, 4, 5];
   const clonedArr = arr.slice(); // This is optimized by ReduceArrayPrototypeSlice
   const subArr = arr.slice(1, 3);
   ```

* **`Array.isArray()`:**
   ```javascript
   Array.isArray([1, 2, 3]); // true - Optimized by ReduceArrayIsArray
   Array.isArray("hello");   // false
   Array.isArray(undefined); // false - Directly returned by ReduceArrayIsArray
   ```

* **`String.prototype.charAt()`:**
   ```javascript
   const str = "hello";
   const char = str.charAt(1); // 'e' - Optimized by ReduceStringPrototypeCharAt
   ```

* **`String.fromCharCode()`:**
   ```javascript
   const charCode = 65;
   const char = String.fromCharCode(charCode); // 'A' - Optimized by ReduceStringFromCharCode
   
### 提示词
```
这是目录为v8/src/compiler/js-call-reducer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-call-reducer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第9部分，共12部分，请归纳一下它的功能
```

### 源代码
```cpp
count),
                         count + 1, &values_to_merge.front());
  }

  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

// ES6 section 22.1.3.23 Array.prototype.slice ( )
Reduction JSCallReducer::ReduceArrayPrototypeSlice(Node* node) {
  if (!v8_flags.turbo_inline_array_builtins) return NoChange();
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Node* receiver = n.receiver();
  Node* start = n.ArgumentOr(0, jsgraph()->ZeroConstant());
  Node* end = n.ArgumentOrUndefined(1, jsgraph());
  Node* context = n.context();
  Effect effect = n.effect();
  Control control = n.control();

  // Optimize for the case where we simply clone the {receiver}, i.e. when the
  // {start} is zero and the {end} is undefined (meaning it will be set to
  // {receiver}s "length" property). This logic should be in sync with
  // ReduceArrayPrototypeSlice (to a reasonable degree). This is because
  // CloneFastJSArray produces arrays which are potentially COW. If there's a
  // discrepancy, TF generates code which produces a COW array and then expects
  // it to be non-COW (or the other way around) -> immediate deopt.
  if (!NumberMatcher(start).Is(0) ||
      !HeapObjectMatcher(end).Is(factory()->undefined_value())) {
    return NoChange();
  }

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps()) return NoChange();
  ZoneRefSet<Map> const& receiver_maps = inference.GetMaps();

  // Check that the maps are of JSArray (and more).
  // TODO(turbofan): Consider adding special case for the common pattern
  // `slice.call(arguments)`, for example jQuery makes heavy use of that.
  bool can_be_holey = false;
  for (MapRef receiver_map : receiver_maps) {
    if (!receiver_map.supports_fast_array_iteration(broker())) {
      return inference.NoChange();
    }
    if (IsHoleyElementsKind(receiver_map.elements_kind())) {
      can_be_holey = true;
    }
  }

  if (!dependencies()->DependOnArraySpeciesProtector()) {
    return inference.NoChange();
  }
  if (can_be_holey && !dependencies()->DependOnNoElementsProtector()) {
    return inference.NoChange();
  }
  inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                      control, p.feedback());

  // TODO(turbofan): We can do even better here, either adding a CloneArray
  // simplified operator, whose output type indicates that it's an Array,
  // saving subsequent checks, or yet better, by introducing new operators
  // CopySmiOrObjectElements / CopyDoubleElements and inlining the JSArray
  // allocation in here. That way we'd even get escape analysis and scalar
  // replacement to help in some cases.
  Callable callable =
      Builtins::CallableFor(isolate(), Builtin::kCloneFastJSArray);
  auto call_descriptor = Linkage::GetStubCallDescriptor(
      graph()->zone(), callable.descriptor(),
      callable.descriptor().GetStackParameterCount(), CallDescriptor::kNoFlags,
      Operator::kNoThrow | Operator::kNoDeopt);

  // Calls to Builtin::kCloneFastJSArray produce COW arrays
  // if the original array is COW
  Node* clone = effect =
      graph()->NewNode(common()->Call(call_descriptor),
                       jsgraph()->HeapConstantNoHole(callable.code()), receiver,
                       context, effect, control);

  ReplaceWithValue(node, clone, effect, control);
  return Replace(clone);
}

// ES6 section 22.1.2.2 Array.isArray ( arg )
Reduction JSCallReducer::ReduceArrayIsArray(Node* node) {
  // We certainly know that undefined is not an array.
  JSCallNode n(node);
  if (n.ArgumentCount() < 1) {
    Node* value = jsgraph()->FalseConstant();
    ReplaceWithValue(node, value);
    return Replace(value);
  }

  Effect effect = n.effect();
  Control control = n.control();
  Node* context = n.context();
  FrameState frame_state = n.frame_state();
  Node* object = n.Argument(0);
  node->ReplaceInput(0, object);
  node->ReplaceInput(1, context);
  node->ReplaceInput(2, frame_state);
  node->ReplaceInput(3, effect);
  node->ReplaceInput(4, control);
  node->TrimInputCount(5);
  NodeProperties::ChangeOp(node, javascript()->ObjectIsArray());
  return Changed(node);
}

Reduction JSCallReducer::ReduceArrayIterator(Node* node,
                                             ArrayIteratorKind array_kind,
                                             IterationKind iteration_kind) {
  JSCallNode n(node);
  Node* receiver = n.receiver();
  Node* context = n.context();
  Effect effect = n.effect();
  Control control = n.control();

  // Check if we know that {receiver} is a valid JSReceiver.
  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() || !inference.AllOfInstanceTypesAreJSReceiver()) {
    return NoChange();
  }

  // TypedArray iteration is stricter: it throws if the receiver is not a typed
  // array. So don't bother optimizing in that case.
  if (array_kind == ArrayIteratorKind::kTypedArray &&
      !inference.AllOfInstanceTypesAre(InstanceType::JS_TYPED_ARRAY_TYPE)) {
    return NoChange();
  }

  if (array_kind == ArrayIteratorKind::kTypedArray) {
    // Make sure we deopt when the JSArrayBuffer is detached.
    if (!dependencies()->DependOnArrayBufferDetachingProtector()) {
      CallParameters const& p = CallParametersOf(node->op());
      if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
        return NoChange();
      }

      std::set<ElementsKind> elements_kinds;
      for (MapRef map : inference.GetMaps()) {
        elements_kinds.insert(map.elements_kind());
      }

      // The following detach check is built with the given {elements_kinds} in
      // mind, so we have to install dependency on those.
      inference.RelyOnMapsPreferStability(
          dependencies(), jsgraph(), &effect, control,
          CallParametersOf(node->op()).feedback());

      JSCallReducerAssembler a(this, node);
      a.CheckIfTypedArrayWasDetached(
          TNode<JSTypedArray>::UncheckedCast(receiver),
          std::move(elements_kinds), p.feedback());
      std::tie(effect, control) = ReleaseEffectAndControlFromAssembler(&a);
    }
  }

  // JSCreateArrayIterator doesn't have control output, so we bypass the old
  // JSCall node on the control chain.
  ReplaceWithValue(node, node, node, control);

  // Morph the {node} into a JSCreateArrayIterator with the given {kind}.
  node->ReplaceInput(0, receiver);
  node->ReplaceInput(1, context);
  node->ReplaceInput(2, effect);
  node->ReplaceInput(3, control);
  node->TrimInputCount(4);
  NodeProperties::ChangeOp(node,
                           javascript()->CreateArrayIterator(iteration_kind));
  return Changed(node);
}

// ES #sec-%arrayiteratorprototype%.next
Reduction JSCallReducer::ReduceArrayIteratorPrototypeNext(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  Node* iterator = n.receiver();
  Node* context = n.context();
  Effect effect = n.effect();
  Control control = n.control();

  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  if (iterator->opcode() != IrOpcode::kJSCreateArrayIterator) return NoChange();

  IterationKind const iteration_kind =
      CreateArrayIteratorParametersOf(iterator->op()).kind();
  Node* iterated_object = NodeProperties::GetValueInput(iterator, 0);
  Effect iterator_effect{NodeProperties::GetEffectInput(iterator)};

  MapInference inference(broker(), iterated_object, iterator_effect);
  if (!inference.HaveMaps()) return NoChange();
  ZoneRefSet<Map> const& iterated_object_maps = inference.GetMaps();

  // Check that various {iterated_object_maps} have compatible elements kinds.
  ElementsKind elements_kind = iterated_object_maps[0].elements_kind();
  if (IsTypedArrayElementsKind(elements_kind)) {
    // TurboFan doesn't support loading from BigInt typed arrays yet.
    if (elements_kind == BIGUINT64_ELEMENTS ||
        elements_kind == BIGINT64_ELEMENTS) {
      return inference.NoChange();
    }
    for (MapRef iterated_object_map : iterated_object_maps) {
      if (iterated_object_map.elements_kind() != elements_kind) {
        return inference.NoChange();
      }
    }
  } else {
    if (!CanInlineArrayIteratingBuiltin(broker(), iterated_object_maps,
                                        &elements_kind)) {
      return inference.NoChange();
    }
  }

  if (IsHoleyElementsKind(elements_kind) &&
      !dependencies()->DependOnNoElementsProtector()) {
    return inference.NoChange();
  }

  if (IsFloat16TypedArrayElementsKind(elements_kind)) {
    // TODO(v8:14212): Allow optimizing Float16 typed arrays here, once they are
    // supported in the rest of the compiler.
    return inference.NoChange();
  }

  // Since the map inference was done relative to {iterator_effect} rather than
  // {effect}, we need to guard the use of the map(s) even when the inference
  // was reliable.
  inference.InsertMapChecks(jsgraph(), &effect, control, p.feedback());

  if (IsTypedArrayElementsKind(elements_kind)) {
    // See if we can skip the detaching check.
    if (!dependencies()->DependOnArrayBufferDetachingProtector()) {
      // Bail out if the {iterated_object}s JSArrayBuffer was detached.
      Node* buffer = effect = graph()->NewNode(
          simplified()->LoadField(AccessBuilder::ForJSArrayBufferViewBuffer()),
          iterated_object, effect, control);
      Node* buffer_bit_field = effect = graph()->NewNode(
          simplified()->LoadField(AccessBuilder::ForJSArrayBufferBitField()),
          buffer, effect, control);
      Node* check = graph()->NewNode(
          simplified()->NumberEqual(),
          graph()->NewNode(
              simplified()->NumberBitwiseAnd(), buffer_bit_field,
              jsgraph()->ConstantNoHole(JSArrayBuffer::WasDetachedBit::kMask)),
          jsgraph()->ZeroConstant());
      effect = graph()->NewNode(
          simplified()->CheckIf(DeoptimizeReason::kArrayBufferWasDetached,
                                p.feedback()),
          check, effect, control);
    }
  }

  // Load the [[NextIndex]] from the {iterator} and leverage the fact
  // that we definitely know that it's in Unsigned32 range since the
  // {iterated_object} is either a JSArray or a JSTypedArray. For the
  // latter case we even know that it's a Smi in UnsignedSmall range.
  FieldAccess index_access = AccessBuilder::ForJSArrayIteratorNextIndex();
  if (IsTypedArrayElementsKind(elements_kind)) {
    index_access.type = TypeCache::Get()->kJSTypedArrayLengthType;
  } else {
    index_access.type = TypeCache::Get()->kJSArrayLengthType;
  }
  Node* index = effect = graph()->NewNode(simplified()->LoadField(index_access),
                                          iterator, effect, control);

  // Load the elements of the {iterated_object}. While it feels
  // counter-intuitive to place the elements pointer load before
  // the condition below, as it might not be needed (if the {index}
  // is out of bounds for the {iterated_object}), it's better this
  // way as it allows the LoadElimination to eliminate redundant
  // reloads of the elements pointer.
  Node* elements = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForJSObjectElements()),
      iterated_object, effect, control);

  // Load the length of the {iterated_object}. Due to the map checks we
  // already know something about the length here, which we can leverage
  // to generate Word32 operations below without additional checking.
  FieldAccess length_access =
      IsTypedArrayElementsKind(elements_kind)
          ? AccessBuilder::ForJSTypedArrayLength()
          : AccessBuilder::ForJSArrayLength(elements_kind);
  Node* length = effect = graph()->NewNode(
      simplified()->LoadField(length_access), iterated_object, effect, control);

  // Check whether {index} is within the valid range for the {iterated_object}.
  Node* check = graph()->NewNode(simplified()->NumberLessThan(), index, length);
  Node* branch =
      graph()->NewNode(common()->Branch(BranchHint::kNone), check, control);

  Node* done_true;
  Node* value_true;
  Node* etrue = effect;
  Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
  {
    // This extra check exists to refine the type of {index} but also to break
    // an exploitation technique that abuses typer mismatches.
    if (v8_flags.turbo_typer_hardening) {
      index = etrue = graph()->NewNode(
          simplified()->CheckBounds(p.feedback(),
                                    CheckBoundsFlag::kAbortOnOutOfBounds),
          index, length, etrue, if_true);
    }

    done_true = jsgraph()->FalseConstant();
    if (iteration_kind == IterationKind::kKeys) {
      // Just return the {index}.
      value_true = index;
    } else {
      DCHECK(iteration_kind == IterationKind::kEntries ||
             iteration_kind == IterationKind::kValues);

      if (IsTypedArrayElementsKind(elements_kind)) {
        Node* base_ptr = etrue =
            graph()->NewNode(simplified()->LoadField(
                                 AccessBuilder::ForJSTypedArrayBasePointer()),
                             iterated_object, etrue, if_true);
        Node* external_ptr = etrue = graph()->NewNode(
            simplified()->LoadField(
                AccessBuilder::ForJSTypedArrayExternalPointer()),
            iterated_object, etrue, if_true);

        ExternalArrayType array_type = kExternalInt8Array;
        switch (elements_kind) {
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) \
  case TYPE##_ELEMENTS:                           \
    array_type = kExternal##Type##Array;          \
    break;
          TYPED_ARRAYS(TYPED_ARRAY_CASE)
          default:
            UNREACHABLE();
#undef TYPED_ARRAY_CASE
        }

        Node* buffer = etrue =
            graph()->NewNode(simplified()->LoadField(
                                 AccessBuilder::ForJSArrayBufferViewBuffer()),
                             iterated_object, etrue, if_true);

        value_true = etrue =
            graph()->NewNode(simplified()->LoadTypedElement(array_type), buffer,
                             base_ptr, external_ptr, index, etrue, if_true);
      } else {
        value_true = etrue = graph()->NewNode(
            simplified()->LoadElement(
                AccessBuilder::ForFixedArrayElement(elements_kind)),
            elements, index, etrue, if_true);

        // Convert hole to undefined if needed.
        if (IsHoleyElementsKind(elements_kind)) {
          value_true = ConvertHoleToUndefined(value_true, elements_kind);
        }
      }

      if (iteration_kind == IterationKind::kEntries) {
        // Allocate elements for key/value pair
        value_true = etrue =
            graph()->NewNode(javascript()->CreateKeyValueArray(), index,
                             value_true, context, etrue);
      } else {
        DCHECK_EQ(IterationKind::kValues, iteration_kind);
      }
    }

    // Increment the [[NextIndex]] field in the {iterator}. The TypeGuards
    // above guarantee that the {next_index} is in the UnsignedSmall range.
    Node* next_index = graph()->NewNode(simplified()->NumberAdd(), index,
                                        jsgraph()->OneConstant());
    etrue = graph()->NewNode(simplified()->StoreField(index_access), iterator,
                             next_index, etrue, if_true);
  }

  Node* done_false;
  Node* value_false;
  Node* efalse = effect;
  Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
  {
    // iterator.[[NextIndex]] >= array.length, stop iterating.
    done_false = jsgraph()->TrueConstant();
    value_false = jsgraph()->UndefinedConstant();

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
      Node* end_index = jsgraph()->ConstantNoHole(index_access.type.Max());
      efalse = graph()->NewNode(simplified()->StoreField(index_access),
                                iterator, end_index, efalse, if_false);
    }
  }

  control = graph()->NewNode(common()->Merge(2), if_true, if_false);
  effect = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);
  Node* value =
      graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                       value_true, value_false, control);
  Node* done =
      graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                       done_true, done_false, control);

  // Create IteratorResult object.
  value = effect = graph()->NewNode(javascript()->CreateIterResultObject(),
                                    value, done, context, effect);
  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

// ES6 section 21.1.3.2 String.prototype.charCodeAt ( pos )
// ES6 section 21.1.3.3 String.prototype.codePointAt ( pos )
Reduction JSCallReducer::ReduceStringPrototypeStringAt(
    const Operator* string_access_operator, Node* node) {
  DCHECK(string_access_operator->opcode() == IrOpcode::kStringCharCodeAt ||
         string_access_operator->opcode() == IrOpcode::kStringCodePointAt);
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Node* receiver = n.receiver();
  Node* index = n.ArgumentOr(0, jsgraph()->ZeroConstant());
  Effect effect = n.effect();
  Control control = n.control();

  // Ensure that the {receiver} is actually a String.
  receiver = effect = graph()->NewNode(simplified()->CheckString(p.feedback()),
                                       receiver, effect, control);

  // Determine the {receiver} length.
  Node* receiver_length =
      graph()->NewNode(simplified()->StringLength(), receiver);

  // Check that the {index} is within range.
  index = effect = graph()->NewNode(simplified()->CheckBounds(p.feedback()),
                                    index, receiver_length, effect, control);

  // Return the character from the {receiver} as single character string.
  Node* value = effect = graph()->NewNode(string_access_operator, receiver,
                                          index, effect, control);

  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

// ES section 21.1.3.20
// String.prototype.startsWith ( searchString [ , position ] )
Reduction JSCallReducer::ReduceStringPrototypeStartsWith(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  TNode<Object> search_element = n.ArgumentOrUndefined(0, jsgraph());

  // Here are three conditions:
  // First, If search_element is definitely not a string, we make no change.
  // Second, If search_element is definitely a string and its length is less
  // or equal than max inline matching sequence threshold, we could inline
  // the entire matching sequence.
  // Third, we try to inline, and have a runtime deopt if search_element is
  // not a string.
  HeapObjectMatcher search_element_matcher(search_element);
  if (search_element_matcher.HasResolvedValue()) {
    ObjectRef target_ref = search_element_matcher.Ref(broker());
    if (!target_ref.IsString()) return NoChange();
    StringRef search_element_string = target_ref.AsString();
    if (!search_element_string.IsContentAccessible()) return NoChange();
    int length = search_element_string.length();
    // If search_element's length is less or equal than
    // kMaxInlineMatchSequence, we inline the entire
    // matching sequence.
    if (length <= kMaxInlineMatchSequence) {
      JSCallReducerAssembler a(this, node);
      Node* subgraph = a.ReduceStringPrototypeStartsWith(search_element_string);
      return ReplaceWithSubgraph(&a, subgraph);
    }
  }

  JSCallReducerAssembler a(this, node);
  Node* subgraph = a.ReduceStringPrototypeStartsWith();
  return ReplaceWithSubgraph(&a, subgraph);
}

// ES section 21.1.3.7
// String.prototype.endsWith(searchString [, endPosition])
Reduction JSCallReducer::ReduceStringPrototypeEndsWith(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  TNode<Object> search_element = n.ArgumentOrUndefined(0, jsgraph());

  // Here are three conditions:
  // First, If search_element is definitely not a string, we make no change.
  // Second, If search_element is definitely a string and its length is less
  // or equal than max inline matching sequence threshold, we could inline
  // the entire matching sequence.
  // Third, we try to inline, and have a runtime deopt if search_element is
  // not a string.
  HeapObjectMatcher search_element_matcher(search_element);
  if (search_element_matcher.HasResolvedValue()) {
    ObjectRef target_ref = search_element_matcher.Ref(broker());
    if (!target_ref.IsString()) return NoChange();
    StringRef search_element_string = target_ref.AsString();
    if (!search_element_string.IsContentAccessible()) return NoChange();
    int length = search_element_string.length();
    // If search_element's length is less or equal than
    // kMaxInlineMatchSequence, we inline the entire
    // matching sequence.
    if (length <= kMaxInlineMatchSequence) {
      JSCallReducerAssembler a(this, node);
      Node* subgraph = a.ReduceStringPrototypeEndsWith(search_element_string);
      return ReplaceWithSubgraph(&a, subgraph);
    }
  }

  JSCallReducerAssembler a(this, node);
  Node* subgraph = a.ReduceStringPrototypeEndsWith();
  return ReplaceWithSubgraph(&a, subgraph);
}

// ES section 21.1.3.1 String.prototype.charAt ( pos )
Reduction JSCallReducer::ReduceStringPrototypeCharAt(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Node* receiver = n.receiver();
  Node* index = n.ArgumentOr(0, jsgraph()->ZeroConstant());

  // Attempt to constant fold the operation when we know
  // that receiver is a string and index is a number.
  HeapObjectMatcher receiver_matcher(receiver);
  NumberMatcher index_matcher(index);
  if (receiver_matcher.HasResolvedValue()) {
    HeapObjectRef receiver_ref = receiver_matcher.Ref(broker());
    if (!receiver_ref.IsString()) return NoChange();
    StringRef receiver_string = receiver_ref.AsString();
    bool is_content_accessible = receiver_string.IsContentAccessible();
    bool is_integer_in_max_range =
        index_matcher.IsInteger() &&
        index_matcher.IsInRange(
            0.0, static_cast<double>(JSObject::kMaxElementIndex));
    if (is_content_accessible && is_integer_in_max_range) {
      const uint32_t index =
          static_cast<uint32_t>(index_matcher.ResolvedValue());
      JSCallReducerAssembler a(this, node);
      Node* subgraph = a.ReduceStringPrototypeCharAt(receiver_string, index);
      return ReplaceWithSubgraph(&a, subgraph);
    }
  }

  JSCallReducerAssembler a(this, node);
  Node* subgraph = a.ReduceStringPrototypeCharAt();
  return ReplaceWithSubgraph(&a, subgraph);
}

#ifdef V8_INTL_SUPPORT

Reduction JSCallReducer::ReduceStringPrototypeToLowerCaseIntl(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }
  Effect effect = n.effect();
  Control control = n.control();

  Node* receiver = effect = graph()->NewNode(
      simplified()->CheckString(p.feedback()), n.receiver(), effect, control);

  NodeProperties::ReplaceEffectInput(node, effect);
  RelaxEffectsAndControls(node);
  node->ReplaceInput(0, receiver);
  node->TrimInputCount(1);
  NodeProperties::ChangeOp(node, simplified()->StringToLowerCaseIntl());
  NodeProperties::SetType(node, Type::String());
  return Changed(node);
}

Reduction JSCallReducer::ReduceStringPrototypeToUpperCaseIntl(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }
  Effect effect = n.effect();
  Control control = n.control();

  Node* receiver = effect = graph()->NewNode(
      simplified()->CheckString(p.feedback()), n.receiver(), effect, control);

  NodeProperties::ReplaceEffectInput(node, effect);
  RelaxEffectsAndControls(node);
  node->ReplaceInput(0, receiver);
  node->TrimInputCount(1);
  NodeProperties::ChangeOp(node, simplified()->StringToUpperCaseIntl());
  NodeProperties::SetType(node, Type::String());
  return Changed(node);
}

#endif  // V8_INTL_SUPPORT

// ES #sec-string.fromcharcode
Reduction JSCallReducer::ReduceStringFromCharCode(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }
  if (n.ArgumentCount() == 1) {
    Effect effect = n.effect();
    Control control = n.control();
    Node* input = n.Argument(0);

    input = effect = graph()->NewNode(
        simplified()->SpeculativeToNumber(NumberOperationHint::kNumberOrOddball,
                                          p.feedback()),
        input, effect, control);

    Node* value =
        graph()->NewNode(simplified()->StringFromSingleCharCode(), input);
    ReplaceWithValue(node, value, effect);
    return Replace(value);
  }
  return NoChange();
}

// ES #sec-string.fromcodepoint
Reduction JSCallReducer::ReduceStringFromCodePoint(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }
  if (n.ArgumentCount() != 1) return NoChange();

  Effect effect = n.effect();
  Control control = n.control();
  Node* input = n.Argument(0);

  input = effect = graph()->NewNode(
      simplified()->CheckBounds(p.feedback(),
                                CheckBoundsFlag::kConvertStringAndMinusZero),
      input, jsgraph()->ConstantNoHole(0x10FFFF + 1), effect, control);

  Node* value =
      graph()->NewNode(simplified()->StringFromSingleCodePoint(), input);
  ReplaceWithValue(node, value, effect);
  return Replace(value);
}

Reduction JSCallReducer::ReduceStringPrototypeIterator(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  Node* receiver = effect = graph()->NewNode(
      simplified()->CheckString(p.feedback()), n.receiver(), effect, control);
  Node* iterator = effect =
      graph()->NewNode(javascript()->CreateStringIterator(), receiver,
                       jsgraph()->NoContextConstant(), effect);
  ReplaceWithValue(node, iterator, effect, control);
  return Replace(iterator);
}

#ifdef V8_INTL_SUPPORT

Reduction JSCallReducer::ReduceStringPrototypeLocaleCompareIntl(Node* node) {
  JSCallNode n(node);
  // Signature: receiver.localeCompare(compareString, locales, options)
  if (n.ArgumentCount() < 1 || n.ArgumentCount() > 3) {
    return NoChange();
  }

  {
    DirectHandle<Object> locales;
    {
      HeapObjectMatcher m(n.ArgumentOrUndefined(1, jsgraph()));
      if (!m.HasResolvedValue()) return NoChange();
      if (m.Is(factory()->undefined_value())) {
        locales = factory()->undefined_value();
      } else {
        ObjectRef ref = m.Ref(broker());
        if (!ref.IsString()) return NoChange();
        StringRef sref = ref.AsString();
        if (std::optional<Handle<String>> maybe_locales =
                sref.ObjectIfContentAccessible(broker())) {
          locales = *maybe_locales;
        } else {
          return NoChange();
        }
      }
    }

    TNode<Object> options = n.ArgumentOrUndefined(2, jsgraph());
    {
      HeapObjectMatcher m(options);
      if (!m.Is(factory()->undefined_value())) {
        return NoChange();
      }
    }

    if (Intl::CompareStringsOptionsFor(broker()->local_isolate_or_isolate(),
                                       locales, factory()->undefined_value()) !=
        Intl::CompareStringsOptions::kTryFastPath) {
      return NoChange();
    }
  }

  Callable callable =
      Builtins::CallableFor(isolate(), Builtin::kStringFastLocaleCompare);
  auto call_descriptor = Linkage::GetStubCallDescriptor(
      graph()->zone(), callable.descriptor(),
      callable.descriptor().GetStackParameterCount(),
      CallDescriptor::kNeedsFrameState);
  node->RemoveInput(n.FeedbackVectorIndex());
  if (n.ArgumentCount() == 3) {
    node->RemoveInput(n.ArgumentIndex(2));
  } else if (n.ArgumentCount() == 1) {
    node->InsertInput(graph()->zone(), n.LastArgumentIndex() + 1,
                      jsgraph()->UndefinedConstant());
  } else {
    DCHECK_EQ(2, n.ArgumentCount());
  }
  node->InsertInput(graph()->zone(), 0,
                    jsgraph()->HeapConstantNoHole(callable.code()));
  NodeProperties::ChangeOp(node, common()->Call(call_descriptor));
  return Changed(node);
}
#endif  // V8_INTL_SUPPORT

Reduction JSCallReducer::ReduceStringIteratorPrototypeNext(Node* node) {
  JSCallNode n(node);
  Node* receiver = n.receiver();
  Effect effect = n.effect();
  Control control = n.control();
  Node* context = n.context();

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() ||
      !inference.AllOfInstanceTypesAre(JS_STRING_ITERATOR_TYPE)) {
    return NoChange();
  }

  Node* string = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForJSStringIteratorString()),
      receiver, effect, control);
  Node* index = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForJSStringIteratorIndex()),
      receiver, effect, control);
  Node* length = graph()->NewNode(simplified()->StringLength(), string);

  // branch0: if (index < length)
  Node* check0 =
      graph()->NewNode(simplified()->NumberLessThan(), index, length);
  Node* branch0 =
      graph()->NewNode(common()->Branch(BranchHint::kNone), check0, control);

  Node* etrue0 = effect;
  Node* if_true0 = graph()->NewNode(common()->IfTrue(), branch0);
  Node* done_true;
  Node* vtrue0;
  {
    done_true = jsgraph()->FalseConstant();
    vtrue0 = etrue0 = graph()->NewNode(simplified()->StringFromCodePointAt(),
                                       string, index, etrue0, if_true0);

    // Update iterator.[[NextIndex]]
    Node* char_length = graph()->NewNode(simplified()->StringLength(), vtrue0);
    index = graph()->NewNode(simplified()->NumberAdd(), index, char_length);
    etrue0 = graph()->NewNode(
        simplified()->StoreField(AccessBuilder::ForJSStringIteratorIndex()),
        receiver, index, etrue0, if_true0);
  }

  Node* if_false0 = graph()->NewNode(common()->IfFalse(), branch0);
  Node* done_false;
  Node* vfalse0;
  {
    vfalse0 = jsgraph()->UndefinedConstant();
    done_false = jsgraph()->TrueConstant();
  }

  control = graph()->NewNode(common()->Merge(2), if_true0, if_false0);
  effect = graph()->NewNode(common()->EffectPhi(2), etrue0, effect, control);
  Node* value =
      graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2), vtrue0,
                       vfalse0, control);
  Node* done =
      graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                       done_true, done_false, control);

  value = effect = graph()->NewNode(javascript()->CreateIterResultObject(),
                                    value, done, context, effect);

  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

// ES #sec-string.prototype.concat
Reduction JSCallReducer::ReduceStringPrototypeConcat(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  const int parameter_count = n.ArgumentCount();
  if (parameter_count > 1) return NoChange();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Effect effect = n.effect();
```