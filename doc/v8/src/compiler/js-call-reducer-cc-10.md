Response:
The user wants a summary of the functionality of the V8 source code file `v8/src/compiler/js-call-reducer.cc`. They also have some specific questions related to the content:

1. **General Functionality:** What does this file do?
2. **Torque Source:** Is this file a Torque source file (indicated by a `.tq` extension)?
3. **JavaScript Relation:** If related to JavaScript functionality, provide JavaScript examples.
4. **Code Logic Inference:** Provide examples of code logic with assumed inputs and outputs.
5. **Common Programming Errors:**  Illustrate common programming errors related to the code.
6. **Overall Function Summary:**  Provide a concise summary of the file's purpose, considering this is part 11 of 12.

Let's break down the thought process for answering these points:

**1. General Functionality:**

* **Keywords:** Look for recurring keywords and patterns. "Reduce," "JSCall," "Node," "simplified," "javascript()," "Builtins::CallableFor," "MapInference," "ReplaceWithValue," "NoChange,"  "Check...". These suggest this code is involved in optimizing JavaScript calls within the Turbofan compiler.
* **Class Name:** The class name `JSCallReducer` strongly indicates its purpose: to reduce or simplify JavaScript call operations. This often involves replacing complex calls with simpler, more efficient sequences of operations.
* **Code Structure:** The presence of numerous functions named `Reduce...` suggests a pattern of handling specific JavaScript call scenarios.

**Initial Hypothesis:** This file contains logic within the Turbofan compiler that identifies specific JavaScript call patterns and replaces them with optimized sequences of lower-level operations.

**2. Torque Source:**

* **File Extension Check:** The prompt explicitly states to check the file extension. The provided text is from a `.cc` file, not `.tq`.

**Answer:** No, this is not a Torque source file.

**3. JavaScript Relation:**

* **Function Names:** Many of the `Reduce...` function names correspond directly to standard JavaScript methods (e.g., `ReduceCollectionPrototypeHas`, `ReduceArrayBufferIsView`, `ReduceGlobalIsFinite`, `ReduceDatePrototypeGetTime`, `ReduceRegExpPrototypeTest`, `ReduceNumberConstructor`).
* **`javascript()` Namespace:** The frequent use of `javascript()->...` indicates interaction with JavaScript built-in functions or operations.

**Action:** Select a few prominent examples and demonstrate the JavaScript equivalents. For instance, `ReduceCollectionPrototypeHas` relates to `collection.has(key)`, `ReduceArrayBufferIsView` relates to `ArrayBuffer.isView(object)`, and so on.

**4. Code Logic Inference:**

* **Focus on a Specific `Reduce...` Function:** Choose a function that is not too complex to illustrate. `ReduceCollectionPrototypeHas` is a good candidate.
* **Identify Inputs:** Determine the inputs to the function (e.g., the `node` representing the JSCall, the `collection_kind`).
* **Trace the Logic:** Follow the code's steps. It checks the receiver's map, performs an optimized lookup if possible, and replaces the original call with a simpler operation.
* **Define Hypothetical Inputs:** Create specific JavaScript code that would lead to this reduction.
* **Predict Output:** Describe the optimized sequence of operations (or the "NoChange" scenario).

**5. Common Programming Errors:**

* **Think about the Optimizations:** The optimizations often rely on certain assumptions about the types and structure of objects. Violating these assumptions could lead to errors or unexpected behavior if the code weren't robust.
* **Consider the "NoChange" Cases:** The code explicitly returns `NoChange()` in certain scenarios. These scenarios often correspond to situations where the optimization isn't safe or applicable.

**Examples:**
    * Using a non-standard object where a specific collection type is expected.
    * Modifying an object's prototype in a way that invalidates the assumptions made by the reducer.
    * Passing the wrong type of argument to a built-in function.

**6. Overall Function Summary:**

* **Combine Previous Observations:** Synthesize the information gathered from the previous steps.
* **Consider the "Part 11 of 12" Context:**  This suggests that this file is likely dealing with a specific stage or aspect of the compilation process. Given the focus on optimizing calls, it likely falls within a later optimization phase.
* **Focus on the "Reduction" Concept:**  Emphasize the idea of transforming complex operations into simpler ones.

**Refined Hypothesis:** This file is a crucial part of Turbofan's optimization pipeline, specifically responsible for identifying and simplifying various JavaScript call patterns. It leverages type information and object structure to replace these calls with more efficient lower-level operations, improving performance.

**Self-Correction/Refinement during the process:**

* Initially, I might focus too much on the low-level details of nodes and graphs. It's important to keep the explanation at a higher level, focusing on the *intent* of the code.
*  I need to ensure the JavaScript examples are clear and directly relate to the code snippets.
*  For code logic inference, choosing a simple example is key. Trying to trace a complex function in detail would be too time-consuming and difficult to explain concisely.
* When considering common programming errors, think from the *user's* perspective – what mistakes might a JavaScript developer make that would interact with these optimizations?

By following this thought process, I can generate a comprehensive and accurate answer to the user's request.
```cpp
Reduction JSCallReducer::ForCollectionKind(collection_kind);
  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() || !inference.AllOfInstanceTypesAre(type)) {
    return NoChange();
  }

  Node* js_create_iterator = effect = graph()->NewNode(
      javascript()->CreateCollectionIterator(collection_kind, iteration_kind),
      receiver, context, effect, control);
  ReplaceWithValue(node, js_create_iterator, effect);
  return Replace(js_create_iterator);
}

Reduction JSCallReducer::ReduceCollectionPrototypeSize(
    Node* node, CollectionKind collection_kind) {
  DCHECK_EQ(IrOpcode::kJSCall, node->opcode());
  Node* receiver = NodeProperties::GetValueInput(node, 1);
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};

  InstanceType type = InstanceTypeForCollectionKind(collection_kind);
  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() || !inference.AllOfInstanceTypesAre(type)) {
    return NoChange();
  }

  Node* table = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForJSCollectionTable()), receiver,
      effect, control);
  Node* value = effect = graph()->NewNode(
      simplified()->LoadField(
          AccessBuilder::ForOrderedHashMapOrSetNumberOfElements()),
      table, effect, control);
  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

Reduction JSCallReducer::ReduceCollectionIteratorPrototypeNext(
    Node* node, int entry_size, Handle<HeapObject> empty_collection,
    InstanceType collection_iterator_instance_type_first,
    InstanceType collection_iterator_instance_type_last) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Node* receiver = n.receiver();
  Node* context = n.context();
  Effect effect = n.effect();
  Control control = n.control();

  // A word of warning to begin with: This whole method might look a bit
  // strange at times, but that's mostly because it was carefully handcrafted
  // to allow for full escape analysis and scalar replacement of both the
  // collection iterator object and the iterator results, including the
  // key-value arrays in case of Set/Map entry iteration.
  //
  // TODO(turbofan): Currently the escape analysis (and the store-load
  // forwarding) is unable to eliminate the allocations for the key-value
  // arrays in case of Set/Map entry iteration, and we should investigate
  // how to update the escape analysis / arrange the graph in a way that
  // this becomes possible.

  InstanceType receiver_instance_type;
  {
    MapInference inference(broker(), receiver, effect);
    if (!inference.HaveMaps()) return NoChange();
    ZoneRefSet<Map> const& receiver_maps = inference.GetMaps();
    receiver_instance_type = receiver_maps[0].instance_type();
    for (size_t i = 1; i < receiver_maps.size(); ++i) {
      if (receiver_maps[i].instance_type() != receiver_instance_type) {
        return inference.NoChange();
      }
    }
    if (receiver_instance_type < collection_iterator_instance_type_first ||
        receiver_instance_type > collection_iterator_instance_type_last) {
      return inference.NoChange();
    }
    inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                        control, p.feedback());
  }

  // Transition the JSCollectionIterator {receiver} if necessary
  // (i.e. there were certain mutations while we're iterating).
  {
    Node* done_loop;
    Node* done_eloop;
    Node* loop = control =
        graph()->NewNode(common()->Loop(2), control, control);
    Node* eloop = effect =
        graph()->NewNode(common()->EffectPhi(2), effect, effect, loop);
    Node* terminate = graph()->NewNode(common()->Terminate(), eloop, loop);
    MergeControlToEnd(graph(), common(), terminate);

    // Check if reached the final table of the {receiver}.
    Node* table = effect = graph()->NewNode(
        simplified()->LoadField(AccessBuilder::ForJSCollectionIteratorTable()),
        receiver, effect, control);
    Node* next_table = effect =
        graph()->NewNode(simplified()->LoadField(
                             AccessBuilder::ForOrderedHashMapOrSetNextTable()),
                         table, effect, control);
    Node* check = graph()->NewNode(simplified()->ObjectIsSmi(), next_table);
    control =
        graph()->NewNode(common()->Branch(BranchHint::kTrue), check, control);

    // Abort the {loop} when we reach the final table.
    done_loop = graph()->NewNode(common()->IfTrue(), control);
    done_eloop = effect;

    // Migrate to the {next_table} otherwise.
    control = graph()->NewNode(common()->IfFalse(), control);

    // Self-heal the {receiver}s index.
    Node* index = effect = graph()->NewNode(
        simplified()->LoadField(AccessBuilder::ForJSCollectionIteratorIndex()),
        receiver, effect, control);
    Callable const callable =
        Builtins::CallableFor(isolate(), Builtin::kOrderedHashTableHealIndex);
    auto call_descriptor = Linkage::GetStubCallDescriptor(
        graph()->zone(), callable.descriptor(),
        callable.descriptor().GetStackParameterCount(),
        CallDescriptor::kNoFlags, Operator::kEliminatable);
    index = effect =
        graph()->NewNode(common()->Call(call_descriptor),
                         jsgraph()->HeapConstantNoHole(callable.code()), table,
                         index, jsgraph()->NoContextConstant(), effect);

    index = effect = graph()->NewNode(
        common()->TypeGuard(TypeCache::Get()->kFixedArrayLengthType), index,
        effect, control);

    // Update the {index} and {table} on the {receiver}.
    effect = graph()->NewNode(
        simplified()->StoreField(AccessBuilder::ForJSCollectionIteratorIndex()),
        receiver, index, effect, control);
    effect = graph()->NewNode(
        simplified()->StoreField(AccessBuilder::ForJSCollectionIteratorTable()),
        receiver, next_table, effect, control);

    // Tie the knot.
    loop->ReplaceInput(1, control);
    eloop->ReplaceInput(1, effect);

    control = done_loop;
    effect = done_eloop;
  }

  // Get current index and table from the JSCollectionIterator {receiver}.
  Node* index = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForJSCollectionIteratorIndex()),
      receiver, effect, control);
  Node* table = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForJSCollectionIteratorTable()),
      receiver, effect, control);

  // Create the {JSIteratorResult} first to ensure that we always have
  // a dominating Allocate node for the allocation folding phase.
  Node* iterator_result = effect = graph()->NewNode(
      javascript()->CreateIterResultObject(), jsgraph()->UndefinedConstant(),
      jsgraph()->TrueConstant(), context, effect);

  // Look for the next non-holey key, starting from {index} in the {table}.
  Node* controls[2];
  Node* effects[3];
  {
    // Compute the currently used capacity.
    Node* number_of_buckets = effect = graph()->NewNode(
        simplified()->LoadField(
            AccessBuilder::ForOrderedHashMapOrSetNumberOfBuckets()),
        table, effect, control);
    Node* number_of_elements = effect = graph()->NewNode(
        simplified()->LoadField(
            AccessBuilder::ForOrderedHashMapOrSetNumberOfElements()),
        table, effect, control);
    Node* number_of_deleted_elements = effect = graph()->NewNode(
        simplified()->LoadField(
            AccessBuilder::ForOrderedHashMapOrSetNumberOfDeletedElements()),
        table, effect, control);
    Node* used_capacity =
        graph()->NewNode(simplified()->NumberAdd(), number_of_elements,
                         number_of_deleted_elements);

    // Skip holes and update the {index}.
    Node* loop = graph()->NewNode(common()->Loop(2), control, control);
    Node* eloop =
        graph()->NewNode(common()->EffectPhi(2), effect, effect, loop);
    Node* terminate = graph()->NewNode(common()->Terminate(), eloop, loop);
    MergeControlToEnd(graph(), common(), terminate);
    Node* iloop = graph()->NewNode(
        common()->Phi(MachineRepresentation::kTagged, 2), index, index, loop);

    index = effect = graph()->NewNode(
        common()->TypeGuard(TypeCache::Get()->kFixedArrayLengthType), iloop,
        eloop, control);
    {
      Node* check0 = graph()->NewNode(simplified()->NumberLessThan(), index,
                                      used_capacity);
      Node* branch0 =
          graph()->NewNode(common()->Branch(BranchHint::kTrue), check0, loop);

      Node* if_false0 = graph()->NewNode(common()->IfFalse(), branch0);
      Node* efalse0 = effect;
      {
        // Mark the {receiver} as exhausted.
        efalse0 = graph()->NewNode(
            simplified()->StoreField(
                AccessBuilder::ForJSCollectionIteratorTable()),
            receiver, jsgraph()->HeapConstantNoHole(empty_collection), efalse0,
            if_false0);

        controls[0] = if_false0;
        effects[0] = efalse0;
      }

      Node* if_true0 = graph()->NewNode(common()->IfTrue(), branch0);
      Node* etrue0 = effect;
      {
        // Load the key of the entry.
        static_assert(OrderedHashMap::HashTableStartIndex() ==
                      OrderedHashSet::HashTableStartIndex());
        Node* entry_start_position = graph()->NewNode(
            simplified()->NumberAdd(),
            graph()->NewNode(
                simplified()->NumberAdd(),
                graph()->NewNode(simplified()->NumberMultiply(), index,
                                 jsgraph()->ConstantNoHole(entry_size)),
                number_of_buckets),
            jsgraph()->ConstantNoHole(OrderedHashMap::HashTableStartIndex()));
        Node* entry_key = etrue0 = graph()->NewNode(
            simplified()->LoadElement(AccessBuilder::ForFixedArrayElement()),
            table, entry_start_position, etrue0, if_true0);

        // Advance the index.
        index = graph()->NewNode(simplified()->NumberAdd(), index,
                                 jsgraph()->OneConstant());

        Node* check1 =
            graph()->NewNode(simplified()->ReferenceEqual(), entry_key,
                             jsgraph()->HashTableHoleConstant());
        Node* branch1 = graph()->NewNode(common()->Branch(BranchHint::kFalse),
                                         check1, if_true0);

        {
          // Abort loop with resulting value.
          control = graph()->NewNode(common()->IfFalse(), branch1);
          effect = etrue0;
          Node* value = effect =
              graph()->NewNode(common()->TypeGuard(Type::NonInternal()),
                               entry_key, effect, control);
          Node* done = jsgraph()->FalseConstant();

          // Advance the index on the {receiver}.
          effect = graph()->NewNode(
              simplified()->StoreField(
                  AccessBuilder::ForJSCollectionIteratorIndex()),
              receiver, index, effect, control);

          // The actual {value} depends on the {receiver} iteration type.
          switch (receiver_instance_type) {
            case JS_MAP_KEY_ITERATOR_TYPE:
            case JS_SET_VALUE_ITERATOR_TYPE:
              break;

            case JS_SET_KEY_VALUE_ITERATOR_TYPE:
              value = effect =
                  graph()->NewNode(javascript()->CreateKeyValueArray(), value,
                                   value, context, effect);
              break;

            case JS_MAP_VALUE_ITERATOR_TYPE:
              value = effect = graph()->NewNode(
                  simplified()->LoadElement(
                      AccessBuilder::ForFixedArrayElement()),
                  table,
                  graph()->NewNode(
                      simplified()->NumberAdd(), entry_start_position,
                      jsgraph()->ConstantNoHole(OrderedHashMap::kValueOffset)),
                  effect, control);
              break;

            case JS_MAP_KEY_VALUE_ITERATOR_TYPE:
              value = effect = graph()->NewNode(
                  simplified()->LoadElement(
                      AccessBuilder::ForFixedArrayElement()),
                  table,
                  graph()->NewNode(
                      simplified()->NumberAdd(), entry_start_position,
                      jsgraph()->ConstantNoHole(OrderedHashMap::kValueOffset)),
                  effect, control);
              value = effect =
                  graph()->NewNode(javascript()->CreateKeyValueArray(),
                                   entry_key, value, context, effect);
              break;

            default:
              UNREACHABLE();
          }

          // Store final {value} and {done} into the {iterator_result}.
          effect =
              graph()->NewNode(simplified()->StoreField(
                                   AccessBuilder::ForJSIteratorResultValue()),
                               iterator_result, value, effect, control);
          effect =
              graph()->NewNode(simplified()->StoreField(
                                   AccessBuilder::ForJSIteratorResultDone()),
                               iterator_result, done, effect, control);

          controls[1] = control;
          effects[1] = effect;
        }

        // Continue with next loop index.
        loop->ReplaceInput(1, graph()->NewNode(common()->IfTrue(), branch1));
        eloop->ReplaceInput(1, etrue0);
        iloop->ReplaceInput(1, index);
      }
    }

    control = effects[2] = graph()->NewNode(common()->Merge(2), 2, controls);
    effect = graph()->NewNode(common()->EffectPhi(2), 3, effects);
  }

  // Yield the final {iterator_result}.
  ReplaceWithValue(node, iterator_result, effect, control);
  return Replace(iterator_result);
}

Reduction JSCallReducer::ReduceArrayBufferIsView(Node* node) {
  JSCallNode n(node);
  Node* value = n.ArgumentOrUndefined(0, jsgraph());
  RelaxEffectsAndControls(node);
  node->ReplaceInput(0, value);
  node->TrimInputCount(1);
  NodeProperties::ChangeOp(node, simplified()->ObjectIsArrayBufferView());
  return Changed(node);
}

Reduction JSCallReducer::ReduceArrayBufferViewAccessor(
    Node* node, InstanceType instance_type, FieldAccess const& access,
    Builtin builtin) {
  // TODO(v8:11111): Optimize for JS_RAB_GSAB_DATA_VIEW_TYPE too.
  Node* receiver = NodeProperties::GetValueInput(node, 1);
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() ||
      !inference.AllOfInstanceTypesAre(instance_type)) {
    return inference.NoChange();
  }

  DCHECK_IMPLIES((builtin == Builtin::kTypedArrayPrototypeLength ||
                  builtin == Builtin::kTypedArrayPrototypeByteLength),
                 base::none_of(inference.GetMaps(), [](MapRef map) {
                   return IsRabGsabTypedArrayElementsKind(map.elements_kind());
                 }));

  if (!inference.RelyOnMapsViaStability(dependencies())) {
    return inference.NoChange();
  }

  const bool depended_on_detaching_protector =
      dependencies()->DependOnArrayBufferDetachingProtector();
  if (!depended_on_detaching_protector && instance_type == JS_DATA_VIEW_TYPE) {
    // DataView prototype accessors throw on detached ArrayBuffers instead of
    // return 0, so skip the optimization.
    //
    // TODO(turbofan): Ideally we would bail out if the buffer is actually
    // detached.
    return inference.NoChange();
  }

  // Load the {receiver}s field.
  Node* value = effect = graph()->NewNode(simplified()->LoadField(access),
                                          receiver, effect, control);

  // See if we can skip the detaching check.
  if (!depended_on_detaching_protector) {
    // Check whether {receiver}s JSArrayBuffer was detached.
    Node* buffer = effect = graph()->NewNode(
        simplified()->LoadField(AccessBuilder::ForJSArrayBufferViewBuffer()),
        receiver, effect, control);
    Node* buffer_bit_field = effect = graph()->NewNode(
        simplified()->LoadField(AccessBuilder::ForJSArrayBufferBitField()),
        buffer, effect, control);
    Node* check = graph()->NewNode(
        simplified()->NumberEqual(),
        graph()->NewNode(
            simplified()->NumberBitwiseAnd(), buffer_bit_field,
            jsgraph()->ConstantNoHole(JSArrayBuffer::WasDetachedBit::kMask)),
        jsgraph()->ZeroConstant());

    // TODO(turbofan): Ideally we would bail out here if the {receiver}s
    // JSArrayBuffer was detached, but there's no way to guard against
    // deoptimization loops right now, since the JSCall {node} is usually
    // created from a LOAD_IC inlining, and so there's no CALL_IC slot
    // from which we could use the speculation bit.
    value = graph()->NewNode(
        common()->Select(MachineRepresentation::kTagged, BranchHint::kTrue),
        check, value, jsgraph()->ZeroConstant());
  }

  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

Reduction JSCallReducer::ReduceDataViewAccess(Node* node, DataViewAccess access,
                                              ExternalArrayType element_type) {
  // TODO(v8:11111): Optimize for JS_RAB_GSAB_DATA_VIEW_TYPE too.
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  size_t const element_size = ExternalArrayElementSize(element_type);
  Effect effect = n.effect();
  Control control = n.control();
  Node* receiver = n.receiver();
  Node* offset = n.ArgumentOr(0, jsgraph()->ZeroConstant());
  Node* value = nullptr;

  if (!Is64() && (element_type == kExternalBigInt64Array ||
                  element_type == kExternalBigUint64Array)) {
    return NoChange();
  }

  if (access == DataViewAccess::kSet) {
    value = n.ArgumentOrUndefined(1, jsgraph());
  }
  const int endian_index = (access == DataViewAccess::kGet ? 1 : 2);
  Node* is_little_endian =
      n.ArgumentOr(endian_index, jsgraph()->FalseConstant());

  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  // Only do stuff if the {receiver} is really a DataView.
  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() ||
      !inference.AllOfInstanceTypesAre(JS_DATA_VIEW_TYPE)) {
    return NoChange();
  }

  // Check that the {offset} is within range for the {receiver}.
  HeapObjectMatcher m(receiver);
  if (m.HasResolvedValue() && m.Ref(broker()).IsJSDataView()) {
    // We only deal with DataViews here whose [[ByteLength]] is at least
    // {element_size}, as for all other DataViews it'll be out-of-bounds.
    JSDataViewRef dataview = m.Ref(broker()).AsJSDataView();

    size_t length = dataview.byte_length();
    if (length < element_size) return NoChange();

    // Check that the {offset} is within range of the {length}.
    Node* byte_length = jsgraph()->ConstantNoHole(length - (element_size - 1));
    offset = effect = graph()->NewNode(simplified()->CheckBounds(p.feedback()),
                                       offset, byte_length, effect, control);
  } else {
    // We only deal with DataViews here that have Smi [[ByteLength]]s.
    Node* byte_length = effect =
        graph()->NewNode(simplified()->LoadField(
                             AccessBuilder::ForJSArrayBufferViewByteLength()),
                         receiver, effect, control);
    if (element_size > 1) {
      // For non-byte accesses we also need to check that the {offset}
      // plus the {element_size}-1 fits within the given {byte_length}.
      // So to keep this as a single check on the {offset}, we subtract
      // the {element_size}-1 from the {byte_length} here (clamped to
      // positive safe integer range), and perform a check against that
      // with the {offset} below.
      byte_length = graph()->NewNode(
          simplified()->NumberMax(), jsgraph()->ZeroConstant(),
          graph()->NewNode(simplified()->NumberSubtract(), byte_length,
                           jsgraph()->ConstantNoHole(element_size - 1)));
    }

    // Check that the {offset} is within range of the {byte_length}.
    offset = effect = graph()->NewNode(simplified()->CheckBounds(p.feedback()),
                                       offset, byte_length, effect, control);
  }

  // Coerce {is_little_endian} to boolean.
  is_little_endian =
      graph()->NewNode(simplified()->ToBoolean(), is_little_endian);

  // Coerce {value} to Number.
  if (access == DataViewAccess::kSet) {
    if (element_type == kExternalBigInt64Array ||
        element_type == kExternalBigUint64Array) {
      value = effect =
          graph()->NewNode(simplified()->SpeculativeToBigInt(
                               BigIntOperationHint::kBigInt, p.feedback()),
                           value, effect, control);
    } else {
      value = effect = graph()->NewNode(
          simplified()->SpeculativeToNumber(
              NumberOperationHint::kNumberOrOddball, p.feedback()),
          value, effect, control);
    }
  }

  // We need to retain either the {receiver} itself or its backing
  // JSArrayBuffer to make sure that the GC doesn't collect the raw
  // memory. We default to {receiver} here, and only use the buffer
  // if we anyways have to load it (to reduce register pressure).
  Node* buffer_or_receiver = receiver;

  if (!dependencies()->DependOnArrayBufferDetachingProtector()) {
    // Get the underlying buffer and check that it has not been detached.
    Node* buffer = effect = graph()->NewNode(
        simplified()->LoadField(AccessBuilder::ForJSArrayBufferViewBuffer()),
        receiver, effect, control);

    // Bail out if the {buffer} was detached.
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

    // We can reduce register pressure by holding on to the {buffer}
    // now to retain the backing store memory.
    buffer_or_receiver = buffer;
  }

  // Load the {receiver}s data pointer.
  Node* data_pointer = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForJSDataViewDataPointer()),
      receiver, effect, control);

  switch (access) {
    case DataViewAccess::kGet:
      // Perform the load.
      value = effect = graph()->NewNode(
          simplified()->LoadDataViewElement(element_type), buffer_or_receiver,
          data_pointer, offset, is_little_endian, effect, control);
      break;
    case DataViewAccess::kSet:
      // Perform the store.
      effect = graph()->NewNode(
          simplified()->StoreDataViewElement(element_type), buffer_or_receiver,
          data_pointer, offset, value, is_little_endian, effect, control);
      value = jsgraph()->UndefinedConstant();
      break;
  }

  ReplaceWithValue(node, value, effect, control);
  return Changed(value);
}

// ES6 section 18.2.2 isFinite ( number )
Reduction JSCallReducer::ReduceGlobalIsFinite(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }
  if (n.ArgumentCount() < 1) {
    Node* value = jsgraph()->FalseConstant();
    ReplaceWithValue(node, value);
    return Replace(value);
  }

  Effect effect = n.effect();
  Control control = n.control();
  Node* input = n.Argument(0);

  input = effect =
      graph()->NewNode(simplified()->SpeculativeToNumber(
                           NumberOperationHint::kNumberOrOddball, p.feedback()),
                       input, effect, control);
  Node* value = graph()->NewNode(simplified()->NumberIsFinite(), input);
  ReplaceWithValue(node, value, effect);
  return Replace(value);
}

// ES6 section 18.2.3 isNaN ( number )
Reduction JSCallReducer::ReduceGlobalIsNaN(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }
  if (n.ArgumentCount() < 1) {
    Node* value = jsgraph()->TrueConstant();
    ReplaceWithValue(node, value);
    return Replace(value);
  }

  Effect effect = n.effect();
  Control control = n.control();
  Node* input = n.Argument(0);

  input = effect =
      graph()->NewNode(simplified()->SpeculativeToNumber(
                           NumberOperationHint::kNumberOrOddball, p.feedback()),
                       input, effect, control);
  Node* value = graph()->NewNode(simplified()->NumberIsNaN(), input);
  ReplaceWithValue(node, value, effect);
  return Replace(value);
}

// ES6 section 20.3.4.10 Date.prototype.getTime ( )
Reduction JSCallReducer::ReduceDatePrototypeGetTime(Node* node) {
  Node* receiver = NodeProperties::GetValueInput(node, 1);
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() || !inference.AllOfInstanceTypesAre(JS_DATE_TYPE)) {
    return NoChange();
  }

  Node* value = effect =
      graph()->NewNode(simplified()->LoadField(AccessBuilder::ForJSDateValue()),
                       receiver, effect, control);
  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

// ES6 section 20.3.3.1 Date.now ( )
Reduction JSCallReducer::ReduceDateNow(Node* node) {
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  Node* value = effect =
      graph()->NewNode(simplified()->DateNow(), effect, control);
  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

// ES6 section 20.1.2.13 Number.parseInt ( string, radix )
Reduction JSCallReducer::ReduceNumberParseInt(Node* node) {
  JSCallNode n(node);
  if (n.ArgumentCount() < 1) {
    Node* value = jsgraph()->NaNConstant();
    ReplaceWithValue(node, value);
    return Replace(value);
  }

  Effect effect = n.effect();
  Control control = n.control();
  Node* context = n.context();
  FrameState frame_state = n.frame_state();
  Node* object = n.Argument(0);
  Node* radix = n.ArgumentOrUndefined(1, jsgraph());

  // Try constant-folding when input is a string constant.
  HeapObjectMatcher object_matcher(object);
  HeapObjectMatcher radix_object_matcher(radix);
  NumberMatcher radix_number_matcher(radix);
  if (object_matcher.HasResolvedValue() &&
      object_
### 提示词
```
这是目录为v8/src/compiler/js-call-reducer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-call-reducer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第11部分，共12部分，请归纳一下它的功能
```

### 源代码
```cpp
ForCollectionKind(collection_kind);
  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() || !inference.AllOfInstanceTypesAre(type)) {
    return NoChange();
  }

  Node* js_create_iterator = effect = graph()->NewNode(
      javascript()->CreateCollectionIterator(collection_kind, iteration_kind),
      receiver, context, effect, control);
  ReplaceWithValue(node, js_create_iterator, effect);
  return Replace(js_create_iterator);
}

Reduction JSCallReducer::ReduceCollectionPrototypeSize(
    Node* node, CollectionKind collection_kind) {
  DCHECK_EQ(IrOpcode::kJSCall, node->opcode());
  Node* receiver = NodeProperties::GetValueInput(node, 1);
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};

  InstanceType type = InstanceTypeForCollectionKind(collection_kind);
  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() || !inference.AllOfInstanceTypesAre(type)) {
    return NoChange();
  }

  Node* table = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForJSCollectionTable()), receiver,
      effect, control);
  Node* value = effect = graph()->NewNode(
      simplified()->LoadField(
          AccessBuilder::ForOrderedHashMapOrSetNumberOfElements()),
      table, effect, control);
  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

Reduction JSCallReducer::ReduceCollectionIteratorPrototypeNext(
    Node* node, int entry_size, Handle<HeapObject> empty_collection,
    InstanceType collection_iterator_instance_type_first,
    InstanceType collection_iterator_instance_type_last) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Node* receiver = n.receiver();
  Node* context = n.context();
  Effect effect = n.effect();
  Control control = n.control();

  // A word of warning to begin with: This whole method might look a bit
  // strange at times, but that's mostly because it was carefully handcrafted
  // to allow for full escape analysis and scalar replacement of both the
  // collection iterator object and the iterator results, including the
  // key-value arrays in case of Set/Map entry iteration.
  //
  // TODO(turbofan): Currently the escape analysis (and the store-load
  // forwarding) is unable to eliminate the allocations for the key-value
  // arrays in case of Set/Map entry iteration, and we should investigate
  // how to update the escape analysis / arrange the graph in a way that
  // this becomes possible.

  InstanceType receiver_instance_type;
  {
    MapInference inference(broker(), receiver, effect);
    if (!inference.HaveMaps()) return NoChange();
    ZoneRefSet<Map> const& receiver_maps = inference.GetMaps();
    receiver_instance_type = receiver_maps[0].instance_type();
    for (size_t i = 1; i < receiver_maps.size(); ++i) {
      if (receiver_maps[i].instance_type() != receiver_instance_type) {
        return inference.NoChange();
      }
    }
    if (receiver_instance_type < collection_iterator_instance_type_first ||
        receiver_instance_type > collection_iterator_instance_type_last) {
      return inference.NoChange();
    }
    inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                        control, p.feedback());
  }

  // Transition the JSCollectionIterator {receiver} if necessary
  // (i.e. there were certain mutations while we're iterating).
  {
    Node* done_loop;
    Node* done_eloop;
    Node* loop = control =
        graph()->NewNode(common()->Loop(2), control, control);
    Node* eloop = effect =
        graph()->NewNode(common()->EffectPhi(2), effect, effect, loop);
    Node* terminate = graph()->NewNode(common()->Terminate(), eloop, loop);
    MergeControlToEnd(graph(), common(), terminate);

    // Check if reached the final table of the {receiver}.
    Node* table = effect = graph()->NewNode(
        simplified()->LoadField(AccessBuilder::ForJSCollectionIteratorTable()),
        receiver, effect, control);
    Node* next_table = effect =
        graph()->NewNode(simplified()->LoadField(
                             AccessBuilder::ForOrderedHashMapOrSetNextTable()),
                         table, effect, control);
    Node* check = graph()->NewNode(simplified()->ObjectIsSmi(), next_table);
    control =
        graph()->NewNode(common()->Branch(BranchHint::kTrue), check, control);

    // Abort the {loop} when we reach the final table.
    done_loop = graph()->NewNode(common()->IfTrue(), control);
    done_eloop = effect;

    // Migrate to the {next_table} otherwise.
    control = graph()->NewNode(common()->IfFalse(), control);

    // Self-heal the {receiver}s index.
    Node* index = effect = graph()->NewNode(
        simplified()->LoadField(AccessBuilder::ForJSCollectionIteratorIndex()),
        receiver, effect, control);
    Callable const callable =
        Builtins::CallableFor(isolate(), Builtin::kOrderedHashTableHealIndex);
    auto call_descriptor = Linkage::GetStubCallDescriptor(
        graph()->zone(), callable.descriptor(),
        callable.descriptor().GetStackParameterCount(),
        CallDescriptor::kNoFlags, Operator::kEliminatable);
    index = effect =
        graph()->NewNode(common()->Call(call_descriptor),
                         jsgraph()->HeapConstantNoHole(callable.code()), table,
                         index, jsgraph()->NoContextConstant(), effect);

    index = effect = graph()->NewNode(
        common()->TypeGuard(TypeCache::Get()->kFixedArrayLengthType), index,
        effect, control);

    // Update the {index} and {table} on the {receiver}.
    effect = graph()->NewNode(
        simplified()->StoreField(AccessBuilder::ForJSCollectionIteratorIndex()),
        receiver, index, effect, control);
    effect = graph()->NewNode(
        simplified()->StoreField(AccessBuilder::ForJSCollectionIteratorTable()),
        receiver, next_table, effect, control);

    // Tie the knot.
    loop->ReplaceInput(1, control);
    eloop->ReplaceInput(1, effect);

    control = done_loop;
    effect = done_eloop;
  }

  // Get current index and table from the JSCollectionIterator {receiver}.
  Node* index = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForJSCollectionIteratorIndex()),
      receiver, effect, control);
  Node* table = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForJSCollectionIteratorTable()),
      receiver, effect, control);

  // Create the {JSIteratorResult} first to ensure that we always have
  // a dominating Allocate node for the allocation folding phase.
  Node* iterator_result = effect = graph()->NewNode(
      javascript()->CreateIterResultObject(), jsgraph()->UndefinedConstant(),
      jsgraph()->TrueConstant(), context, effect);

  // Look for the next non-holey key, starting from {index} in the {table}.
  Node* controls[2];
  Node* effects[3];
  {
    // Compute the currently used capacity.
    Node* number_of_buckets = effect = graph()->NewNode(
        simplified()->LoadField(
            AccessBuilder::ForOrderedHashMapOrSetNumberOfBuckets()),
        table, effect, control);
    Node* number_of_elements = effect = graph()->NewNode(
        simplified()->LoadField(
            AccessBuilder::ForOrderedHashMapOrSetNumberOfElements()),
        table, effect, control);
    Node* number_of_deleted_elements = effect = graph()->NewNode(
        simplified()->LoadField(
            AccessBuilder::ForOrderedHashMapOrSetNumberOfDeletedElements()),
        table, effect, control);
    Node* used_capacity =
        graph()->NewNode(simplified()->NumberAdd(), number_of_elements,
                         number_of_deleted_elements);

    // Skip holes and update the {index}.
    Node* loop = graph()->NewNode(common()->Loop(2), control, control);
    Node* eloop =
        graph()->NewNode(common()->EffectPhi(2), effect, effect, loop);
    Node* terminate = graph()->NewNode(common()->Terminate(), eloop, loop);
    MergeControlToEnd(graph(), common(), terminate);
    Node* iloop = graph()->NewNode(
        common()->Phi(MachineRepresentation::kTagged, 2), index, index, loop);

    index = effect = graph()->NewNode(
        common()->TypeGuard(TypeCache::Get()->kFixedArrayLengthType), iloop,
        eloop, control);
    {
      Node* check0 = graph()->NewNode(simplified()->NumberLessThan(), index,
                                      used_capacity);
      Node* branch0 =
          graph()->NewNode(common()->Branch(BranchHint::kTrue), check0, loop);

      Node* if_false0 = graph()->NewNode(common()->IfFalse(), branch0);
      Node* efalse0 = effect;
      {
        // Mark the {receiver} as exhausted.
        efalse0 = graph()->NewNode(
            simplified()->StoreField(
                AccessBuilder::ForJSCollectionIteratorTable()),
            receiver, jsgraph()->HeapConstantNoHole(empty_collection), efalse0,
            if_false0);

        controls[0] = if_false0;
        effects[0] = efalse0;
      }

      Node* if_true0 = graph()->NewNode(common()->IfTrue(), branch0);
      Node* etrue0 = effect;
      {
        // Load the key of the entry.
        static_assert(OrderedHashMap::HashTableStartIndex() ==
                      OrderedHashSet::HashTableStartIndex());
        Node* entry_start_position = graph()->NewNode(
            simplified()->NumberAdd(),
            graph()->NewNode(
                simplified()->NumberAdd(),
                graph()->NewNode(simplified()->NumberMultiply(), index,
                                 jsgraph()->ConstantNoHole(entry_size)),
                number_of_buckets),
            jsgraph()->ConstantNoHole(OrderedHashMap::HashTableStartIndex()));
        Node* entry_key = etrue0 = graph()->NewNode(
            simplified()->LoadElement(AccessBuilder::ForFixedArrayElement()),
            table, entry_start_position, etrue0, if_true0);

        // Advance the index.
        index = graph()->NewNode(simplified()->NumberAdd(), index,
                                 jsgraph()->OneConstant());

        Node* check1 =
            graph()->NewNode(simplified()->ReferenceEqual(), entry_key,
                             jsgraph()->HashTableHoleConstant());
        Node* branch1 = graph()->NewNode(common()->Branch(BranchHint::kFalse),
                                         check1, if_true0);

        {
          // Abort loop with resulting value.
          control = graph()->NewNode(common()->IfFalse(), branch1);
          effect = etrue0;
          Node* value = effect =
              graph()->NewNode(common()->TypeGuard(Type::NonInternal()),
                               entry_key, effect, control);
          Node* done = jsgraph()->FalseConstant();

          // Advance the index on the {receiver}.
          effect = graph()->NewNode(
              simplified()->StoreField(
                  AccessBuilder::ForJSCollectionIteratorIndex()),
              receiver, index, effect, control);

          // The actual {value} depends on the {receiver} iteration type.
          switch (receiver_instance_type) {
            case JS_MAP_KEY_ITERATOR_TYPE:
            case JS_SET_VALUE_ITERATOR_TYPE:
              break;

            case JS_SET_KEY_VALUE_ITERATOR_TYPE:
              value = effect =
                  graph()->NewNode(javascript()->CreateKeyValueArray(), value,
                                   value, context, effect);
              break;

            case JS_MAP_VALUE_ITERATOR_TYPE:
              value = effect = graph()->NewNode(
                  simplified()->LoadElement(
                      AccessBuilder::ForFixedArrayElement()),
                  table,
                  graph()->NewNode(
                      simplified()->NumberAdd(), entry_start_position,
                      jsgraph()->ConstantNoHole(OrderedHashMap::kValueOffset)),
                  effect, control);
              break;

            case JS_MAP_KEY_VALUE_ITERATOR_TYPE:
              value = effect = graph()->NewNode(
                  simplified()->LoadElement(
                      AccessBuilder::ForFixedArrayElement()),
                  table,
                  graph()->NewNode(
                      simplified()->NumberAdd(), entry_start_position,
                      jsgraph()->ConstantNoHole(OrderedHashMap::kValueOffset)),
                  effect, control);
              value = effect =
                  graph()->NewNode(javascript()->CreateKeyValueArray(),
                                   entry_key, value, context, effect);
              break;

            default:
              UNREACHABLE();
          }

          // Store final {value} and {done} into the {iterator_result}.
          effect =
              graph()->NewNode(simplified()->StoreField(
                                   AccessBuilder::ForJSIteratorResultValue()),
                               iterator_result, value, effect, control);
          effect =
              graph()->NewNode(simplified()->StoreField(
                                   AccessBuilder::ForJSIteratorResultDone()),
                               iterator_result, done, effect, control);

          controls[1] = control;
          effects[1] = effect;
        }

        // Continue with next loop index.
        loop->ReplaceInput(1, graph()->NewNode(common()->IfTrue(), branch1));
        eloop->ReplaceInput(1, etrue0);
        iloop->ReplaceInput(1, index);
      }
    }

    control = effects[2] = graph()->NewNode(common()->Merge(2), 2, controls);
    effect = graph()->NewNode(common()->EffectPhi(2), 3, effects);
  }

  // Yield the final {iterator_result}.
  ReplaceWithValue(node, iterator_result, effect, control);
  return Replace(iterator_result);
}

Reduction JSCallReducer::ReduceArrayBufferIsView(Node* node) {
  JSCallNode n(node);
  Node* value = n.ArgumentOrUndefined(0, jsgraph());
  RelaxEffectsAndControls(node);
  node->ReplaceInput(0, value);
  node->TrimInputCount(1);
  NodeProperties::ChangeOp(node, simplified()->ObjectIsArrayBufferView());
  return Changed(node);
}

Reduction JSCallReducer::ReduceArrayBufferViewAccessor(
    Node* node, InstanceType instance_type, FieldAccess const& access,
    Builtin builtin) {
  // TODO(v8:11111): Optimize for JS_RAB_GSAB_DATA_VIEW_TYPE too.
  Node* receiver = NodeProperties::GetValueInput(node, 1);
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() ||
      !inference.AllOfInstanceTypesAre(instance_type)) {
    return inference.NoChange();
  }

  DCHECK_IMPLIES((builtin == Builtin::kTypedArrayPrototypeLength ||
                  builtin == Builtin::kTypedArrayPrototypeByteLength),
                 base::none_of(inference.GetMaps(), [](MapRef map) {
                   return IsRabGsabTypedArrayElementsKind(map.elements_kind());
                 }));

  if (!inference.RelyOnMapsViaStability(dependencies())) {
    return inference.NoChange();
  }

  const bool depended_on_detaching_protector =
      dependencies()->DependOnArrayBufferDetachingProtector();
  if (!depended_on_detaching_protector && instance_type == JS_DATA_VIEW_TYPE) {
    // DataView prototype accessors throw on detached ArrayBuffers instead of
    // return 0, so skip the optimization.
    //
    // TODO(turbofan): Ideally we would bail out if the buffer is actually
    // detached.
    return inference.NoChange();
  }

  // Load the {receiver}s field.
  Node* value = effect = graph()->NewNode(simplified()->LoadField(access),
                                          receiver, effect, control);

  // See if we can skip the detaching check.
  if (!depended_on_detaching_protector) {
    // Check whether {receiver}s JSArrayBuffer was detached.
    Node* buffer = effect = graph()->NewNode(
        simplified()->LoadField(AccessBuilder::ForJSArrayBufferViewBuffer()),
        receiver, effect, control);
    Node* buffer_bit_field = effect = graph()->NewNode(
        simplified()->LoadField(AccessBuilder::ForJSArrayBufferBitField()),
        buffer, effect, control);
    Node* check = graph()->NewNode(
        simplified()->NumberEqual(),
        graph()->NewNode(
            simplified()->NumberBitwiseAnd(), buffer_bit_field,
            jsgraph()->ConstantNoHole(JSArrayBuffer::WasDetachedBit::kMask)),
        jsgraph()->ZeroConstant());

    // TODO(turbofan): Ideally we would bail out here if the {receiver}s
    // JSArrayBuffer was detached, but there's no way to guard against
    // deoptimization loops right now, since the JSCall {node} is usually
    // created from a LOAD_IC inlining, and so there's no CALL_IC slot
    // from which we could use the speculation bit.
    value = graph()->NewNode(
        common()->Select(MachineRepresentation::kTagged, BranchHint::kTrue),
        check, value, jsgraph()->ZeroConstant());
  }

  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

Reduction JSCallReducer::ReduceDataViewAccess(Node* node, DataViewAccess access,
                                              ExternalArrayType element_type) {
  // TODO(v8:11111): Optimize for JS_RAB_GSAB_DATA_VIEW_TYPE too.
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  size_t const element_size = ExternalArrayElementSize(element_type);
  Effect effect = n.effect();
  Control control = n.control();
  Node* receiver = n.receiver();
  Node* offset = n.ArgumentOr(0, jsgraph()->ZeroConstant());
  Node* value = nullptr;

  if (!Is64() && (element_type == kExternalBigInt64Array ||
                  element_type == kExternalBigUint64Array)) {
    return NoChange();
  }

  if (access == DataViewAccess::kSet) {
    value = n.ArgumentOrUndefined(1, jsgraph());
  }
  const int endian_index = (access == DataViewAccess::kGet ? 1 : 2);
  Node* is_little_endian =
      n.ArgumentOr(endian_index, jsgraph()->FalseConstant());

  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  // Only do stuff if the {receiver} is really a DataView.
  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() ||
      !inference.AllOfInstanceTypesAre(JS_DATA_VIEW_TYPE)) {
    return NoChange();
  }

  // Check that the {offset} is within range for the {receiver}.
  HeapObjectMatcher m(receiver);
  if (m.HasResolvedValue() && m.Ref(broker()).IsJSDataView()) {
    // We only deal with DataViews here whose [[ByteLength]] is at least
    // {element_size}, as for all other DataViews it'll be out-of-bounds.
    JSDataViewRef dataview = m.Ref(broker()).AsJSDataView();

    size_t length = dataview.byte_length();
    if (length < element_size) return NoChange();

    // Check that the {offset} is within range of the {length}.
    Node* byte_length = jsgraph()->ConstantNoHole(length - (element_size - 1));
    offset = effect = graph()->NewNode(simplified()->CheckBounds(p.feedback()),
                                       offset, byte_length, effect, control);
  } else {
    // We only deal with DataViews here that have Smi [[ByteLength]]s.
    Node* byte_length = effect =
        graph()->NewNode(simplified()->LoadField(
                             AccessBuilder::ForJSArrayBufferViewByteLength()),
                         receiver, effect, control);
    if (element_size > 1) {
      // For non-byte accesses we also need to check that the {offset}
      // plus the {element_size}-1 fits within the given {byte_length}.
      // So to keep this as a single check on the {offset}, we subtract
      // the {element_size}-1 from the {byte_length} here (clamped to
      // positive safe integer range), and perform a check against that
      // with the {offset} below.
      byte_length = graph()->NewNode(
          simplified()->NumberMax(), jsgraph()->ZeroConstant(),
          graph()->NewNode(simplified()->NumberSubtract(), byte_length,
                           jsgraph()->ConstantNoHole(element_size - 1)));
    }

    // Check that the {offset} is within range of the {byte_length}.
    offset = effect = graph()->NewNode(simplified()->CheckBounds(p.feedback()),
                                       offset, byte_length, effect, control);
  }

  // Coerce {is_little_endian} to boolean.
  is_little_endian =
      graph()->NewNode(simplified()->ToBoolean(), is_little_endian);

  // Coerce {value} to Number.
  if (access == DataViewAccess::kSet) {
    if (element_type == kExternalBigInt64Array ||
        element_type == kExternalBigUint64Array) {
      value = effect =
          graph()->NewNode(simplified()->SpeculativeToBigInt(
                               BigIntOperationHint::kBigInt, p.feedback()),
                           value, effect, control);
    } else {
      value = effect = graph()->NewNode(
          simplified()->SpeculativeToNumber(
              NumberOperationHint::kNumberOrOddball, p.feedback()),
          value, effect, control);
    }
  }

  // We need to retain either the {receiver} itself or its backing
  // JSArrayBuffer to make sure that the GC doesn't collect the raw
  // memory. We default to {receiver} here, and only use the buffer
  // if we anyways have to load it (to reduce register pressure).
  Node* buffer_or_receiver = receiver;

  if (!dependencies()->DependOnArrayBufferDetachingProtector()) {
    // Get the underlying buffer and check that it has not been detached.
    Node* buffer = effect = graph()->NewNode(
        simplified()->LoadField(AccessBuilder::ForJSArrayBufferViewBuffer()),
        receiver, effect, control);

    // Bail out if the {buffer} was detached.
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

    // We can reduce register pressure by holding on to the {buffer}
    // now to retain the backing store memory.
    buffer_or_receiver = buffer;
  }

  // Load the {receiver}s data pointer.
  Node* data_pointer = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForJSDataViewDataPointer()),
      receiver, effect, control);

  switch (access) {
    case DataViewAccess::kGet:
      // Perform the load.
      value = effect = graph()->NewNode(
          simplified()->LoadDataViewElement(element_type), buffer_or_receiver,
          data_pointer, offset, is_little_endian, effect, control);
      break;
    case DataViewAccess::kSet:
      // Perform the store.
      effect = graph()->NewNode(
          simplified()->StoreDataViewElement(element_type), buffer_or_receiver,
          data_pointer, offset, value, is_little_endian, effect, control);
      value = jsgraph()->UndefinedConstant();
      break;
  }

  ReplaceWithValue(node, value, effect, control);
  return Changed(value);
}

// ES6 section 18.2.2 isFinite ( number )
Reduction JSCallReducer::ReduceGlobalIsFinite(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }
  if (n.ArgumentCount() < 1) {
    Node* value = jsgraph()->FalseConstant();
    ReplaceWithValue(node, value);
    return Replace(value);
  }

  Effect effect = n.effect();
  Control control = n.control();
  Node* input = n.Argument(0);

  input = effect =
      graph()->NewNode(simplified()->SpeculativeToNumber(
                           NumberOperationHint::kNumberOrOddball, p.feedback()),
                       input, effect, control);
  Node* value = graph()->NewNode(simplified()->NumberIsFinite(), input);
  ReplaceWithValue(node, value, effect);
  return Replace(value);
}

// ES6 section 18.2.3 isNaN ( number )
Reduction JSCallReducer::ReduceGlobalIsNaN(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }
  if (n.ArgumentCount() < 1) {
    Node* value = jsgraph()->TrueConstant();
    ReplaceWithValue(node, value);
    return Replace(value);
  }

  Effect effect = n.effect();
  Control control = n.control();
  Node* input = n.Argument(0);

  input = effect =
      graph()->NewNode(simplified()->SpeculativeToNumber(
                           NumberOperationHint::kNumberOrOddball, p.feedback()),
                       input, effect, control);
  Node* value = graph()->NewNode(simplified()->NumberIsNaN(), input);
  ReplaceWithValue(node, value, effect);
  return Replace(value);
}

// ES6 section 20.3.4.10 Date.prototype.getTime ( )
Reduction JSCallReducer::ReduceDatePrototypeGetTime(Node* node) {
  Node* receiver = NodeProperties::GetValueInput(node, 1);
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() || !inference.AllOfInstanceTypesAre(JS_DATE_TYPE)) {
    return NoChange();
  }

  Node* value = effect =
      graph()->NewNode(simplified()->LoadField(AccessBuilder::ForJSDateValue()),
                       receiver, effect, control);
  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

// ES6 section 20.3.3.1 Date.now ( )
Reduction JSCallReducer::ReduceDateNow(Node* node) {
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  Node* value = effect =
      graph()->NewNode(simplified()->DateNow(), effect, control);
  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

// ES6 section 20.1.2.13 Number.parseInt ( string, radix )
Reduction JSCallReducer::ReduceNumberParseInt(Node* node) {
  JSCallNode n(node);
  if (n.ArgumentCount() < 1) {
    Node* value = jsgraph()->NaNConstant();
    ReplaceWithValue(node, value);
    return Replace(value);
  }

  Effect effect = n.effect();
  Control control = n.control();
  Node* context = n.context();
  FrameState frame_state = n.frame_state();
  Node* object = n.Argument(0);
  Node* radix = n.ArgumentOrUndefined(1, jsgraph());

  // Try constant-folding when input is a string constant.
  HeapObjectMatcher object_matcher(object);
  HeapObjectMatcher radix_object_matcher(radix);
  NumberMatcher radix_number_matcher(radix);
  if (object_matcher.HasResolvedValue() &&
      object_matcher.Ref(broker()).IsString() &&
      (radix_object_matcher.Is(factory()->undefined_value()) ||
       radix_number_matcher.HasResolvedValue())) {
    StringRef input_value = object_matcher.Ref(broker()).AsString();
    // {undefined} is treated same as 0.
    int radix_value = radix_object_matcher.Is(factory()->undefined_value())
                          ? 0
                          : DoubleToInt32(radix_number_matcher.ResolvedValue());
    if (radix_value != 0 && (radix_value < 2 || radix_value > 36)) {
      Node* value = jsgraph()->NaNConstant();
      ReplaceWithValue(node, value);
      return Replace(value);
    }

    std::optional<double> number = input_value.ToInt(broker(), radix_value);
    if (number.has_value()) {
      Node* result = graph()->NewNode(common()->NumberConstant(number.value()));
      ReplaceWithValue(node, result);
      return Replace(result);
    }
  }

  node->ReplaceInput(0, object);
  node->ReplaceInput(1, radix);
  node->ReplaceInput(2, context);
  node->ReplaceInput(3, frame_state);
  node->ReplaceInput(4, effect);
  node->ReplaceInput(5, control);
  node->TrimInputCount(6);
  NodeProperties::ChangeOp(node, javascript()->ParseInt());
  return Changed(node);
}

Reduction JSCallReducer::ReduceRegExpPrototypeTest(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (v8_flags.force_slow_path) return NoChange();
  if (n.ArgumentCount() < 1) return NoChange();

  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Effect effect = n.effect();
  Control control = n.control();
  Node* regexp = n.receiver();

  // Only the initial JSRegExp map is valid here, since the following lastIndex
  // check as well as the lowered builtin call rely on a known location of the
  // lastIndex field.
  MapRef regexp_initial_map =
      native_context().regexp_function(broker()).initial_map(broker());

  MapInference inference(broker(), regexp, effect);
  if (!inference.Is(regexp_initial_map)) return inference.NoChange();
  ZoneRefSet<Map> const& regexp_maps = inference.GetMaps();

  ZoneVector<PropertyAccessInfo> access_infos(graph()->zone());
  AccessInfoFactory access_info_factory(broker(), graph()->zone());

  for (MapRef map : regexp_maps) {
    access_infos.push_back(broker()->GetPropertyAccessInfo(
        map, broker()->exec_string(), AccessMode::kLoad));
  }

  PropertyAccessInfo ai_exec =
      access_info_factory.FinalizePropertyAccessInfosAsOne(access_infos,
                                                           AccessMode::kLoad);
  if (ai_exec.IsInvalid()) return inference.NoChange();
  if (!ai_exec.IsFastDataConstant()) return inference.NoChange();

  // Do not reduce if the exec method is not on the prototype chain.
  OptionalJSObjectRef holder = ai_exec.holder();
  if (!holder.has_value()) return inference.NoChange();

  // Bail out if the exec method is not the original one.
  if (ai_exec.field_representation().IsDouble()) return inference.NoChange();
  OptionalObjectRef constant = holder->GetOwnFastConstantDataProperty(
      broker(), ai_exec.field_representation(), ai_exec.field_index(),
      dependencies());
  if (!constant.has_value() ||
      !constant->equals(native_context().regexp_exec_function(broker()))) {
    return inference.NoChange();
  }

  // Add proper dependencies on the {regexp}s [[Prototype]]s.
  dependencies()->DependOnStablePrototypeChains(
      ai_exec.lookup_start_object_maps(), kStartAtPrototype, holder.value());

  inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                      control, p.feedback());

  Node* context = n.context();
  FrameState frame_state = n.frame_state();
  Node* search = n.Argument(0);
  Node* search_string = effect = graph()->NewNode(
      simplified()->CheckString(p.feedback()), search, effect, control);

  Node* lastIndex = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForJSRegExpLastIndex()), regexp,
      effect, control);

  Node* lastIndexSmi = effect = graph()->NewNode(
      simplified()->CheckSmi(p.feedback()), lastIndex, effect, control);

  Node* is_positive = graph()->NewNode(simplified()->NumberLessThanOrEqual(),
                                       jsgraph()->ZeroConstant(), lastIndexSmi);

  effect = graph()->NewNode(
      simplified()->CheckIf(DeoptimizeReason::kNotASmi, p.feedback()),
      is_positive, effect, control);

  node->ReplaceInput(0, regexp);
  node->ReplaceInput(1, search_string);
  node->ReplaceInput(2, context);
  node->ReplaceInput(3, frame_state);
  node->ReplaceInput(4, effect);
  node->ReplaceInput(5, control);
  node->TrimInputCount(6);
  NodeProperties::ChangeOp(node, javascript()->RegExpTest());
  return Changed(node);
}

// ES section #sec-number-constructor
Reduction JSCallReducer::ReduceNumberConstructor(Node* node) {
  JSCallNode n(node);
  Node* target = n.target();
  Node* receiver = n.receiver();
  Node* value = n.ArgumentOr(0, jsgraph()->ZeroConstant());
  Node* context = n.context();
  FrameState frame_state = n.frame_state();

  // Create the artificial frame state in the middle of the Number constructor.
  SharedFunctionInfoRef shared_info =
      native_context().number_function(broker()).shared(broker());
  Node* continuation_frame_state = CreateGenericLazyDeoptContinuationFrameState(
      jsgraph(), shared_info, target, context, receiver, frame_state);

  // Convert the {value} to a Number.
  NodeProperties::ReplaceValueInputs(node, value);
  NodeProperties::ChangeOp(node, javascript()->ToNumberConvertBigInt());
  NodeProperties::ReplaceFrameStateInput(node, continuation_frame_state);
  return Changed(node);
}

// ES section #sec-bigint-constructor
Reduction JSCallReducer::ReduceBigIntConstructor(Node* node) {
  if (!jsgraph()->machine()->Is64())
```