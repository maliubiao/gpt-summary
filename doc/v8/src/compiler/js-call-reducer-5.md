Response: The user wants a summary of the C++ source code file `v8/src/compiler/js-call-reducer.cc`.
This file seems to be part of the V8 JavaScript engine's compiler.
The name "JSCallReducer" suggests it's responsible for optimizing JavaScript function calls.

**Plan:**

1. Read through the code and identify the main functionalities.
2. Group these functionalities based on the JavaScript features they relate to.
3. For each functionality, provide a brief description in plain English.
4. If a functionality is related to a specific JavaScript feature, provide a simple JavaScript example.
5. Since this is part 6 of 6, ensure the summary covers the entire file.

**Observations from the code:**

*   The file contains many methods with names like `Reduce...`, suggesting different optimization strategies for different types of JavaScript calls.
*   Several methods deal with collections (Map, Set), iterators, and their prototypes.
*   There are optimizations for `ArrayBuffer` and `DataView` related functions.
*   Global functions like `isFinite`, `isNaN`, `parseInt` are being optimized.
*   Date object methods (`getTime`, `now`) are targeted for optimization.
*   Regular Expression methods (`test`) are optimized.
*   Constructor calls for `Number` and `BigInt` are handled.
*   `Math.min` and `Math.max` calls with array-like arguments are optimized.
*   There are mentions of "escape analysis" and "scalar replacement," which are compiler optimization techniques.
*   There are also sections related to speculation and deoptimization, indicating that the optimizations are not always guaranteed.

**High-level summary:**

The `js-call-reducer.cc` file in V8's compiler implements various optimization techniques for JavaScript function calls. It analyzes the types of objects involved and applies specific transformations to simplify the code and improve performance.

**Detailed breakdown:**

*   **Collection Iteration (`ReduceCreateCollectionIterator`, `ReduceCollectionPrototypeSize`, `ReduceCollectionIteratorPrototypeNext`):** Optimizes the creation of iterators and the `next()` method for JavaScript collections like Map and Set. This involves directly accessing the internal data structures of these collections when the types are known.

*   **ArrayBuffer and DataView (`ReduceArrayBufferIsView`, `ReduceArrayBufferViewAccessor`, `ReduceDataViewAccess`):** Optimizes calls related to `ArrayBuffer` and `DataView`, allowing direct memory access when the types and bounds are known. This avoids the overhead of generic JavaScript calls.

*   **Global Functions (`ReduceGlobalIsFinite`, `ReduceGlobalIsNaN`):** Optimizes calls to global functions `isFinite` and `isNaN` by directly using the underlying numerical operations.

*   **Date Object (`ReduceDatePrototypeGetTime`, `ReduceDateNow`):** Optimizes calls to `Date.prototype.getTime()` and `Date.now()` by directly accessing the internal time representation or using efficient native calls.

*   **Number Parsing (`ReduceNumberParseInt`):** Optimizes calls to `Number.parseInt()` by attempting to constant-fold the result if the input is a constant string and the radix is known.

*   **Regular Expressions (`ReduceRegExpPrototypeTest`):** Optimizes calls to `RegExp.prototype.test()` by directly using the internal regular expression matching engine when the receiver is a non-modified RegExp object.

*   **Constructor Calls (`ReduceNumberConstructor`, `ReduceBigIntConstructor`):** Optimizes constructor calls for `Number` and `BigInt` by directly performing the necessary type conversions.

*   **BigInt Operations (`ReduceBigIntAsN`):** Optimizes calls to `BigInt.asIntN` and `BigInt.asUintN` by directly performing the bitwise operations when the bit length is a constant.

*   **Math.min/max with Array-like (`TryReduceJSCallMathMinMaxWithArrayLike`, `ReduceJSCallMathMinMaxWithArrayLike`):** Optimizes calls to `Math.min()` and `Math.max()` when called with an array-like object as an argument by directly iterating through the array-like structure.

*   **Continuation Preserved Embedder Data (`ReduceGetContinuationPreservedEmbedderData`, `ReduceSetContinuationPreservedEmbedderData`):**  Provides optimizations for accessing and setting data associated with continuations, a feature related to asynchronous operations and embedding V8.
`v8/src/compiler/js-call-reducer.cc` is a crucial component of the V8 JavaScript engine's optimizing compiler (TurboFan). As the name suggests, its primary function is to **reduce complex JavaScript call operations into simpler, more efficient low-level operations**. This process is a form of **compiler optimization**.

This specific part of the `JSCallReducer` focuses on reducing calls to various built-in JavaScript functions and methods, including:

*   **Collection Iteration:** Optimizes calls related to iterating over JavaScript collections like `Map` and `Set`.
*   **ArrayBuffer and DataView:** Optimizes calls for working with binary data through `ArrayBuffer` and `DataView`.
*   **Global Functions:** Optimizes calls to global functions like `isFinite` and `isNaN`.
*   **Date Object:** Optimizes calls to `Date` object methods like `getTime` and `now`.
*   **Number Parsing:** Optimizes calls to `Number.parseInt`.
*   **Regular Expressions:** Optimizes calls to `RegExp.prototype.test`.
*   **Number and BigInt Constructors:** Optimizes calls to the `Number` and `BigInt` constructors.
*   **BigInt Operations:** Optimizes calls to `BigInt.asIntN` and `BigInt.asUintN`.
*   **Math.min/max with Array-like:** Optimizes calls to `Math.min` and `Math.max` when called with an array-like object.
*   **Continuation Preserved Embedder Data:** Optimizes accessing and setting embedder-specific data related to continuations.

The code achieves these reductions by:

1. **Type Inference:** Analyzing the types of the objects involved in the call.
2. **Map Checks:** Verifying the shape and properties of objects (using their `Map`s) to ensure they haven't been unexpectedly modified.
3. **Direct Access:** When types are known and stable, replacing the generic JavaScript call with direct access to the underlying data or a more efficient internal operation.
4. **Inlining:**  In some cases, effectively inlining the logic of the called function.
5. **Lowering to Simpler Operations:** Converting high-level JavaScript operations into simpler machine-level operations.
6. **Speculation and Deoptimization:**  Making optimistic assumptions about types and properties and including mechanisms to "deoptimize" if those assumptions prove incorrect during runtime.

**Relationship to JavaScript and Examples:**

The optimizations performed by `JSCallReducer` directly impact the performance of JavaScript code. Here are some examples illustrating how the reductions in this file relate to JavaScript functionality:

**1. Collection Iteration:**

```javascript
const myMap = new Map([['a', 1], ['b', 2]]);
for (const [key, value] of myMap) {
  console.log(key, value);
}
```

The `ReduceCreateCollectionIterator` and related functions aim to optimize the creation of the iterator used in the `for...of` loop and the subsequent calls to the iterator's `next()` method. Instead of going through the full JavaScript call machinery, the compiler can directly access the internal storage of the `Map`.

**2. ArrayBuffer and DataView:**

```javascript
const buffer = new ArrayBuffer(8);
const view = new DataView(buffer);
view.setInt32(0, 42, true); // Set an integer at byte offset 0 (little-endian)
const value = view.getInt32(0, true); // Get the integer back
console.log(value); // Output: 42
```

`ReduceArrayBufferViewAccessor` and `ReduceDataViewAccess` optimize operations like `setInt32` and `getInt32` on `DataView` objects. The compiler can bypass much of the standard JavaScript method call overhead and directly interact with the underlying buffer.

**3. Global Functions (isFinite, isNaN):**

```javascript
console.log(isFinite(10));   // Output: true
console.log(isNaN('hello')); // Output: true
```

`ReduceGlobalIsFinite` and `ReduceGlobalIsNaN` can replace these function calls with efficient internal checks, avoiding the overhead of a full function call.

**4. Date Object:**

```javascript
const now = Date.now();
const date = new Date();
const timestamp = date.getTime();
console.log(now, timestamp);
```

`ReduceDateNow` and `ReduceDatePrototypeGetTime` optimize these methods to retrieve the current timestamp efficiently, potentially using native system calls.

**5. Number Parsing:**

```javascript
const num = Number.parseInt("123");
console.log(num); // Output: 123
```

`ReduceNumberParseInt` attempts to optimize this by constant-folding if the input string is a constant, avoiding the need for runtime parsing.

**6. Regular Expressions:**

```javascript
const regex = /hello/;
const result = regex.test("hello world");
console.log(result); // Output: true
```

`ReduceRegExpPrototypeTest` optimizes the `test()` method by potentially using a more direct and efficient regular expression matching mechanism within V8.

**7. Number and BigInt Constructors:**

```javascript
const num = Number("42");
const bigInt = BigInt("9007199254740991");
console.log(num, bigInt);
```

`ReduceNumberConstructor` and `ReduceBigIntConstructor` optimize these calls by directly performing the necessary type conversions.

**8. Math.min/max with Array-like:**

```javascript
const numbers = [5, 2, 8, 1];
const min = Math.min(...numbers);
const max = Math.max.apply(null, numbers); // Another way to call with an array
console.log(min, max); // Output: 1, 8
```

`ReduceJSCallMathMinMaxWithArrayLike` optimizes these calls when provided with an array-like object, potentially by iterating over the array directly instead of going through the general argument processing.

In summary, `v8/src/compiler/js-call-reducer.cc` (specifically this part) plays a vital role in making JavaScript execution faster by intelligently transforming and simplifying common JavaScript function calls at compile time. It leverages type information and object structure to bypass the overhead of generic call mechanisms and directly perform the intended operations more efficiently.

### 提示词
```
这是目录为v8/src/compiler/js-call-reducer.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第6部分，共6部分，请归纳一下它的功能
```

### 源代码
```
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
  if (!jsgraph()->machine()->Is64()) return NoChange();

  JSCallNode n(node);
  if (n.ArgumentCount() < 1) {
    return NoChange();
  }

  Node* target = n.target();
  Node* receiver = n.receiver();
  Node* value = n.Argument(0);
  Node* context = n.context();
  FrameState frame_state = n.frame_state();

  // Create the artificial frame state in the middle of the BigInt constructor.
  SharedFunctionInfoRef shared_info =
      native_context().bigint_function(broker()).shared(broker());
  Node* continuation_frame_state = CreateGenericLazyDeoptContinuationFrameState(
      jsgraph(), shared_info, target, context, receiver, frame_state);

  // Convert the {value} to a BigInt.
  NodeProperties::ReplaceValueInputs(node, value);
  NodeProperties::ChangeOp(node, javascript()->ToBigIntConvertNumber());
  NodeProperties::ReplaceFrameStateInput(node, continuation_frame_state);
  return Changed(node);
}

Reduction JSCallReducer::ReduceBigIntAsN(Node* node, Builtin builtin) {
  DCHECK(builtin == Builtin::kBigIntAsIntN ||
         builtin == Builtin::kBigIntAsUintN);

  if (!jsgraph()->machine()->Is64()) return NoChange();

  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }
  if (n.ArgumentCount() < 2) {
    return NoChange();
  }

  Effect effect = n.effect();
  Control control = n.control();
  Node* bits = n.Argument(0);
  Node* value = n.Argument(1);

  NumberMatcher matcher(bits);
  if (matcher.IsInteger() && matcher.IsInRange(0, 64)) {
    const int bits_value = static_cast<int>(matcher.ResolvedValue());
    value = effect = graph()->NewNode(
        (builtin == Builtin::kBigIntAsIntN
             ? simplified()->SpeculativeBigIntAsIntN(bits_value, p.feedback())
             : simplified()->SpeculativeBigIntAsUintN(bits_value,
                                                      p.feedback())),
        value, effect, control);
    ReplaceWithValue(node, value, effect);
    return Replace(value);
  }

  return NoChange();
}

std::optional<Reduction> JSCallReducer::TryReduceJSCallMathMinMaxWithArrayLike(
    Node* node) {
  if (!v8_flags.turbo_optimize_math_minmax) return std::nullopt;

  JSCallWithArrayLikeNode n(node);
  CallParameters const& p = n.Parameters();
  Node* target = n.target();
  Effect effect = n.effect();
  Control control = n.control();

  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return std::nullopt;
  }

  if (n.ArgumentCount() != 1) {
    return std::nullopt;
  }

  if (!dependencies()->DependOnNoElementsProtector()) {
    return std::nullopt;
  }

  // These ops are handled by ReduceCallOrConstructWithArrayLikeOrSpread.
  // IrOpcode::kJSCreateEmptyLiteralArray is not included, since arguments_list
  // for Math.min/min is not likely to keep empty.
  Node* arguments_list = n.Argument(0);
  if (arguments_list->opcode() == IrOpcode::kJSCreateLiteralArray ||
      arguments_list->opcode() == IrOpcode::kJSCreateArguments) {
    return std::nullopt;
  }

  HeapObjectMatcher m(target);
  if (m.HasResolvedValue()) {
    ObjectRef target_ref = m.Ref(broker());
    if (target_ref.IsJSFunction()) {
      JSFunctionRef function = target_ref.AsJSFunction();

      // Don't inline cross native context.
      if (!function.native_context(broker()).equals(native_context())) {
        return std::nullopt;
      }

      SharedFunctionInfoRef shared = function.shared(broker());
      Builtin builtin =
          shared.HasBuiltinId() ? shared.builtin_id() : Builtin::kNoBuiltinId;
      if (builtin == Builtin::kMathMax || builtin == Builtin::kMathMin) {
        return ReduceJSCallMathMinMaxWithArrayLike(node, builtin);
      } else {
        return std::nullopt;
      }
    }
  }

  // Try specialize the JSCallWithArrayLike node with feedback target.
  if (ShouldUseCallICFeedback(target) &&
      p.feedback_relation() == CallFeedbackRelation::kTarget &&
      p.feedback().IsValid()) {
    ProcessedFeedback const& feedback =
        broker()->GetFeedbackForCall(p.feedback());
    if (feedback.IsInsufficient()) {
      return std::nullopt;
    }
    OptionalHeapObjectRef feedback_target = feedback.AsCall().target();
    if (feedback_target.has_value() &&
        feedback_target->map(broker()).is_callable()) {
      Node* target_function =
          jsgraph()->ConstantNoHole(*feedback_target, broker());
      ObjectRef target_ref = feedback_target.value();
      if (!target_ref.IsJSFunction()) {
        return std::nullopt;
      }
      JSFunctionRef function = target_ref.AsJSFunction();
      SharedFunctionInfoRef shared = function.shared(broker());
      Builtin builtin =
          shared.HasBuiltinId() ? shared.builtin_id() : Builtin::kNoBuiltinId;
      if (builtin == Builtin::kMathMax || builtin == Builtin::kMathMin) {
        // Check that the {target} is still the {target_function}.
        Node* check = graph()->NewNode(simplified()->ReferenceEqual(), target,
                                       target_function);
        effect = graph()->NewNode(
            simplified()->CheckIf(DeoptimizeReason::kWrongCallTarget), check,
            effect, control);

        // Specialize the JSCallWithArrayLike node to the {target_function}.
        NodeProperties::ReplaceValueInput(node, target_function,
                                          n.TargetIndex());
        NodeProperties::ReplaceEffectInput(node, effect);
        // Try to further reduce the Call MathMin/Max with double array.
        return Changed(node).FollowedBy(
            ReduceJSCallMathMinMaxWithArrayLike(node, builtin));
      }
    }
  }

  return std::nullopt;
}

Reduction JSCallReducer::ReduceJSCallMathMinMaxWithArrayLike(Node* node,
                                                             Builtin builtin) {
  JSCallWithArrayLikeNode n(node);
  DCHECK_NE(n.Parameters().speculation_mode(),
            SpeculationMode::kDisallowSpeculation);
  DCHECK_EQ(n.ArgumentCount(), 1);

  JSCallReducerAssembler a(this, node);
  Node* subgraph = a.ReduceJSCallMathMinMaxWithArrayLike(builtin);
  return ReplaceWithSubgraph(&a, subgraph);
}

#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
Reduction JSCallReducer::ReduceGetContinuationPreservedEmbedderData(
    Node* node) {
  JSCallNode n(node);
  Effect effect = n.effect();
  Control control = n.control();

  Node* value = effect = graph()->NewNode(
      simplified()->GetContinuationPreservedEmbedderData(), effect);

  ReplaceWithValue(node, value, effect, control);
  return Replace(node);
}

Reduction JSCallReducer::ReduceSetContinuationPreservedEmbedderData(
    Node* node) {
  JSCallNode n(node);
  Effect effect = n.effect();
  Control control = n.control();

  if (n.ArgumentCount() == 0) return NoChange();

  effect =
      graph()->NewNode(simplified()->SetContinuationPreservedEmbedderData(),
                       n.Argument(0), effect);

  Node* value = jsgraph()->UndefinedConstant();

  ReplaceWithValue(node, value, effect, control);
  return Replace(node);
}
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA

CompilationDependencies* JSCallReducer::dependencies() const {
  return broker()->dependencies();
}

Graph* JSCallReducer::graph() const { return jsgraph()->graph(); }

Isolate* JSCallReducer::isolate() const { return jsgraph()->isolate(); }

Factory* JSCallReducer::factory() const { return isolate()->factory(); }

NativeContextRef JSCallReducer::native_context() const {
  return broker()->target_native_context();
}

CommonOperatorBuilder* JSCallReducer::common() const {
  return jsgraph()->common();
}

JSOperatorBuilder* JSCallReducer::javascript() const {
  return jsgraph()->javascript();
}

SimplifiedOperatorBuilder* JSCallReducer::simplified() const {
  return jsgraph()->simplified();
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```