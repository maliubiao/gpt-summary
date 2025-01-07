Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/js-create-lowering.cc`.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the core purpose:** The file name `js-create-lowering.cc` strongly suggests that this code is responsible for *lowering* JavaScript `create` operations to a more fundamental representation within the V8 compiler. "Lowering" typically involves transforming high-level operations into a series of lower-level steps that are closer to the machine.

2. **Scan for keywords and patterns:** Look for recurring patterns and function names. The code is full of functions named `ReduceJSCreate...`. The word "Reduce" in compiler terminology often means simplifying or transforming an operation. The `JSCreate...` prefix indicates these functions handle specific JavaScript "create" operations.

3. **Analyze individual `ReduceJSCreate...` functions:**  Examine what each function does.
    * **`ReduceJSCreateArray`**: Deals with creating arrays. It considers the types of the initial values to optimize the kind of array created (e.g., packed smis, packed doubles, etc.).
    * **`ReduceJSCreateArrayIterator`**: Creates iterators for arrays. It allocates memory for the iterator object and sets up its initial state.
    * **`ReduceJSCreateAsyncFunctionObject`**: Handles the creation of asynchronous function objects. This involves allocating memory for the object and its register file.
    * **`ReduceJSCreateCollectionIterator`**: Similar to array iterators, but for collections like Maps and Sets.
    * **`ReduceJSCreateBoundFunction`**: Creates bound functions (using `Function.bind`). This involves storing the target function and bound arguments.
    * **`ReduceJSCreateClosure`**:  Focuses on creating function closures. It tries to optimize this process by inlining allocation for certain cases.
    * **`ReduceJSCreateIterResultObject`**: Creates the result objects for iterators (objects with `value` and `done` properties).
    * **`ReduceJSCreateStringIterator`**: Creates iterators for strings.
    * **`ReduceJSCreateKeyValueArray`**:  Creates small arrays, often used for key-value pairs.
    * **`ReduceJSCreatePromise`**:  Handles the creation of `Promise` objects.
    * **`ReduceJSCreateLiteralArrayOrObject`**, **`ReduceJSCreateEmptyLiteralArray`**, **`ReduceJSCreateEmptyLiteralObject`**: These deal with creating literal arrays and objects (`[]`, `{}`). They leverage feedback from previous executions to optimize allocation.
    * **`ReduceJSCreateLiteralRegExp`**: Creates regular expression literals (`/.../`).
    * **`ReduceJSGetTemplateObject`**: Handles template literals (e.g., `\`hello\``).
    * **`ReduceJSCreateFunctionContext`**, **`ReduceJSCreateWithContext`**, **`ReduceJSCreateCatchContext`**, **`ReduceJSCreateBlockContext`**: These functions are responsible for creating different types of execution contexts in JavaScript (function scope, `with` statements, `catch` blocks, block scopes).
    * **`ReduceJSCreateObject`**:  Handles the general case of creating objects (e.g., using `new Object()` or `Object.create(proto)`).

4. **Identify common themes:**  Notice the repeated use of `AllocationBuilder`, `AccessBuilder`, and concepts like `MapRef`, `AllocationType`, and different element kinds for arrays. These point to the underlying mechanisms of memory management and object representation in V8.

5. **Consider the "lowering" aspect:**  The code isn't directly executing JavaScript. Instead, it's transforming JavaScript "create" operations into a sequence of lower-level V8 internal operations like allocating memory, setting up object headers (maps), and storing initial values.

6. **Address the specific prompts:**
    * **`.tq` extension:** The prompt asks about `.tq`. The code is C++, so it's not a Torque file.
    * **JavaScript relationship:**  Each `ReduceJSCreate...` function directly corresponds to a way of creating objects in JavaScript. Provide examples for some key cases.
    * **Logic and assumptions:**  For `ReduceJSCreateArray`, the logic for determining the array element kind is evident. Provide an example to illustrate the input (array values) and output (resulting array with a specific element kind).
    * **Common errors:**  Think about common mistakes developers make that relate to object creation. Incorrectly assuming the type of an array element or misunderstanding prototype inheritance are relevant examples.

7. **Synthesize the summary:** Combine the observations into a concise description of the file's purpose. Emphasize the "lowering" aspect, the handling of various object creation scenarios, and the optimization strategies employed.

8. **Refine the summary:** Ensure the language is clear and avoids overly technical jargon where possible. Organize the information logically.

By following these steps, you can effectively analyze the code snippet and generate the requested summary. The iterative process of looking for patterns, analyzing individual functions, and then synthesizing the overall picture is key to understanding complex code.
```cpp
ue,
         values_any_nonnumber = false;
    std::vector<Node*> values;
    values.reserve(p.arity());
    for (int i = 0; i < arity; ++i) {
      Node* value = NodeProperties::GetValueInput(node, 2 + i);
      Type value_type = NodeProperties::GetType(value);
      if (!value_type.Is(Type::SignedSmall())) {
        values_all_smis = false;
      }
      if (!value_type.Is(Type::Number())) {
        values_all_numbers = false;
      }
      if (!value_type.Maybe(Type::Number())) {
        values_any_nonnumber = true;
      }
      values.push_back(value);
    }

    // Try to figure out the ideal elements kind statically.
    if (values_all_smis) {
      // Smis can be stored with any elements kind.
    } else if (values_all_numbers) {
      elements_kind = GetMoreGeneralElementsKind(
          elements_kind, IsHoleyElementsKind(elements_kind)
                             ? HOLEY_DOUBLE_ELEMENTS
                             : PACKED_DOUBLE_ELEMENTS);
    } else if (values_any_nonnumber) {
      elements_kind = GetMoreGeneralElementsKind(
          elements_kind, IsHoleyElementsKind(elements_kind) ? HOLEY_ELEMENTS
                                                            : PACKED_ELEMENTS);
    } else if (!can_inline_call) {
      // We have some crazy combination of types for the {values} where
      // there's no clear decision on the elements kind statically. And
      // we don't have a protection against deoptimization loops for the
      // checks that are introduced in the call to ReduceNewArray, so
      // we cannot inline this invocation of the Array constructor here.
      return NoChange();
    }
    return ReduceNewArray(node, values, *initial_map, elements_kind, allocation,
                          slack_tracking_prediction);
  }
  return NoChange();
}

Reduction JSCreateLowering::ReduceJSCreateArrayIterator(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreateArrayIterator, node->opcode());
  CreateArrayIteratorParameters const& p =
      CreateArrayIteratorParametersOf(node->op());
  Node* iterated_object = NodeProperties::GetValueInput(node, 0);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  // Create the JSArrayIterator result.
  AllocationBuilder a(jsgraph(), broker(), effect, control);
  a.Allocate(JSArrayIterator::kHeaderSize, AllocationType::kYoung,
             Type::OtherObject());
  a.Store(AccessBuilder::ForMap(),
          native_context().initial_array_iterator_map(broker()));
  a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSObjectElements(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSArrayIteratorIteratedObject(), iterated_object);
  a.Store(AccessBuilder::ForJSArrayIteratorNextIndex(),
          jsgraph()->ZeroConstant());
  a.Store(AccessBuilder::ForJSArrayIteratorKind(),
          jsgraph()->ConstantNoHole(static_cast<int>(p.kind())));
  RelaxControls(node);
  a.FinishAndChange(node);
  return Changed(node);
}

Reduction JSCreateLowering::ReduceJSCreateAsyncFunctionObject(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreateAsyncFunctionObject, node->opcode());
  int const register_count = RegisterCountOf(node->op());
  Node* closure = NodeProperties::GetValueInput(node, 0);
  Node* receiver = NodeProperties::GetValueInput(node, 1);
  Node* promise = NodeProperties::GetValueInput(node, 2);
  Node* context = NodeProperties::GetContextInput(node);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  // Create the register file.
  MapRef fixed_array_map = broker()->fixed_array_map();
  AllocationBuilder ab(jsgraph(), broker(), effect, control);
  CHECK(ab.CanAllocateArray(register_count, fixed_array_map));
  ab.AllocateArray(register_count, fixed_array_map);
  for (int i = 0; i < register_count; ++i) {
    ab.Store(AccessBuilder::ForFixedArraySlot(i),
             jsgraph()->UndefinedConstant());
  }
  Node* parameters_and_registers = effect = ab.Finish();

  // Create the JSAsyncFunctionObject result.
  AllocationBuilder a(jsgraph(), broker(), effect, control);
  a.Allocate(JSAsyncFunctionObject::kHeaderSize);
  a.Store(AccessBuilder::ForMap(),
          native_context().async_function_object_map(broker()));
  a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSObjectElements(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSGeneratorObjectContext(), context);
  a.Store(AccessBuilder::ForJSGeneratorObjectFunction(), closure);
  a.Store(AccessBuilder::ForJSGeneratorObjectReceiver(), receiver);
  a.Store(AccessBuilder::ForJSGeneratorObjectInputOrDebugPos(),
          jsgraph()->UndefinedConstant());
  a.Store(AccessBuilder::ForJSGeneratorObjectResumeMode(),
          jsgraph()->ConstantNoHole(JSGeneratorObject::kNext));
  a.Store(AccessBuilder::ForJSGeneratorObjectContinuation(),
          jsgraph()->ConstantNoHole(JSGeneratorObject::kGeneratorExecuting));
  a.Store(AccessBuilder::ForJSGeneratorObjectParametersAndRegisters(),
          parameters_and_registers);
  a.Store(AccessBuilder::ForJSAsyncFunctionObjectPromise(), promise);
  a.FinishAndChange(node);
  return Changed(node);
}

namespace {

MapRef MapForCollectionIterationKind(JSHeapBroker* broker,
                                     NativeContextRef native_context,
                                     CollectionKind collection_kind,
                                     IterationKind iteration_kind) {
  switch (collection_kind) {
    case CollectionKind::kSet:
      switch (iteration_kind) {
        case IterationKind::kKeys:
          UNREACHABLE();
        case IterationKind::kValues:
          return native_context.set_value_iterator_map(broker);
        case IterationKind::kEntries:
          return native_context.set_key_value_iterator_map(broker);
      }
      break;
    case CollectionKind::kMap:
      switch (iteration_kind) {
        case IterationKind::kKeys:
          return native_context.map_key_iterator_map(broker);
        case IterationKind::kValues:
          return native_context.map_value_iterator_map(broker);
        case IterationKind::kEntries:
          return native_context.map_key_value_iterator_map(broker);
      }
      break;
  }
  UNREACHABLE();
}

}  // namespace

Reduction JSCreateLowering::ReduceJSCreateCollectionIterator(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreateCollectionIterator, node->opcode());
  CreateCollectionIteratorParameters const& p =
      CreateCollectionIteratorParametersOf(node->op());
  Node* iterated_object = NodeProperties::GetValueInput(node, 0);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  // Load the OrderedHashTable from the {receiver}.
  Node* table = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForJSCollectionTable()),
      iterated_object, effect, control);

  // Create the JSCollectionIterator result.
  AllocationBuilder a(jsgraph(), broker(), effect, control);
  a.Allocate(JSCollectionIterator::kHeaderSize, AllocationType::kYoung,
             Type::OtherObject());
  a.Store(
      AccessBuilder::ForMap(),
      MapForCollectionIterationKind(broker(), native_context(),
                                    p.collection_kind(), p.iteration_kind()));
  a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSObjectElements(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSCollectionIteratorTable(), table);
  a.Store(AccessBuilder::ForJSCollectionIteratorIndex(),
          jsgraph()->ZeroConstant());
  RelaxControls(node);
  a.FinishAndChange(node);
  return Changed(node);
}

Reduction JSCreateLowering::ReduceJSCreateBoundFunction(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreateBoundFunction, node->opcode());
  CreateBoundFunctionParameters const& p =
      CreateBoundFunctionParametersOf(node->op());
  int const arity = static_cast<int>(p.arity());
  MapRef const map = p.map();
  Node* bound_target_function = NodeProperties::GetValueInput(node, 0);
  Node* bound_this = NodeProperties::GetValueInput(node, 1);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  // Create the [[BoundArguments]] for the result.
  Node* bound_arguments = jsgraph()->EmptyFixedArrayConstant();
  if (arity > 0) {
    MapRef fixed_array_map = broker()->fixed_array_map();
    AllocationBuilder ab(jsgraph(), broker(), effect, control);
    CHECK(ab.CanAllocateArray(arity, fixed_array_map));
    ab.AllocateArray(arity, fixed_array_map);
    for (int i = 0; i < arity; ++i) {
      ab.Store(AccessBuilder::ForFixedArraySlot(i),
               NodeProperties::GetValueInput(node, 2 + i));
    }
    bound_arguments = effect = ab.Finish();
  }

  // Create the JSBoundFunction result.
  AllocationBuilder a(jsgraph(), broker(), effect, control);
  a.Allocate(JSBoundFunction::kHeaderSize, AllocationType::kYoung,
             Type::BoundFunction());
  a.Store(AccessBuilder::ForMap(), map);
  a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSObjectElements(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSBoundFunctionBoundTargetFunction(),
          bound_target_function);
  a.Store(AccessBuilder::ForJSBoundFunctionBoundThis(), bound_this);
  a.Store(AccessBuilder::ForJSBoundFunctionBoundArguments(), bound_arguments);
  RelaxControls(node);
  a.FinishAndChange(node);
  return Changed(node);
}

Reduction JSCreateLowering::ReduceJSCreateClosure(Node* node) {
  JSCreateClosureNode n(node);
  CreateClosureParameters const& p = n.Parameters();
  SharedFunctionInfoRef shared = p.shared_info();
  FeedbackCellRef feedback_cell = n.GetFeedbackCellRefChecked(broker());
#ifndef V8_ENABLE_LEAPTIERING
  HeapObjectRef code = p.code();
#endif
  Effect effect = n.effect();
  Control control = n.control();
  Node* context = n.context();

  // Use inline allocation of closures only for instantiation sites that have
  // seen more than one instantiation, this simplifies the generated code and
  // also serves as a heuristic of which allocation sites benefit from it.
  if (!feedback_cell.map(broker()).equals(broker()->many_closures_cell_map())) {
    return NoChange();
  }

  // Don't inline anything for class constructors.
  if (IsClassConstructor(shared.kind())) return NoChange();

  MapRef function_map = native_context().GetFunctionMapFromIndex(
      broker(), shared.function_map_index());
  DCHECK(!function_map.IsInobjectSlackTrackingInProgress());
  DCHECK(!function_map.is_dictionary_map());

#ifdef V8_ENABLE_LEAPTIERING
  // TODO(saelo): we should embed the dispatch handle directly into the
  // generated code instead of loading it at runtime from the FeedbackCell.
  // This will likely first require GC support though.
  Node* feedback_cell_node = jsgraph()->ConstantNoHole(feedback_cell, broker());
  Node* dispatch_handle;
  if (shared.HasBuiltinId()) {
    // This uses a smi constant to store the static dispatch handle, since
    // currently we expect dispatch handles to be encoded as numbers in the
    // deopt metadata.
    // TODO(olivf): Dispatch handles should be supported in deopt metadata.
    dispatch_handle = jsgraph()->SmiConstant(
        jsgraph()->isolate()->builtin_dispatch_handle(shared.builtin_id()));
  } else {
    DCHECK(feedback_cell.object()->dispatch_handle() != kNullJSDispatchHandle);
    dispatch_handle = effect = graph()->NewNode(
        simplified()->LoadField(
            AccessBuilder::ForFeedbackCellDispatchHandleNoWriteBarrier()),
        feedback_cell_node, effect, control);
  }
#endif  // V8_ENABLE_LEAPTIERING

  // TODO(turbofan): We should use the pretenure flag from {p} here,
  // but currently the heuristic in the parser works against us, as
  // it marks closures like
  //
  //   args[l] = function(...) { ... }
  //
  // for old-space allocation, which doesn't always make sense. For
  // example in case of the bluebird-parallel benchmark, where this
  // is a core part of the *promisify* logic (see crbug.com/810132).
  AllocationType allocation = AllocationType::kYoung;

  // Emit code to allocate the JSFunction instance.
  static_assert(JSFunction::kSizeWithoutPrototype == 7 * kTaggedSize);
  AllocationBuilder a(jsgraph(), broker(), effect, control);
  a.Allocate(function_map.instance_size(), allocation,
             Type::CallableFunction());
  a.Store(AccessBuilder::ForMap(), function_map);
  a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSObjectElements(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSFunctionSharedFunctionInfo(), shared);
  a.Store(AccessBuilder::ForJSFunctionContext(), context);
  a.Store(AccessBuilder::ForJSFunctionFeedbackCell(), feedback_cell);
#ifdef V8_ENABLE_LEAPTIERING
  a.Store(AccessBuilder::ForJSFunctionDispatchHandleNoWriteBarrier(),
          dispatch_handle);
#else
  a.Store(AccessBuilder::ForJSFunctionCode(), code);
#endif  // V8_ENABLE_LEAPTIERING
  static_assert(JSFunction::kSizeWithoutPrototype == 7 * kTaggedSize);
  if (function_map.has_prototype_slot()) {
    a.Store(AccessBuilder::ForJSFunctionPrototypeOrInitialMap(),
            jsgraph()->TheHoleConstant());
    static_assert(JSFunction::kSizeWithPrototype == 8 * kTaggedSize);
  }
  for (int i = 0; i < function_map.GetInObjectProperties(); i++) {
    a.Store(AccessBuilder::ForJSObjectInObjectProperty(function_map, i),
            jsgraph()->UndefinedConstant());
  }
  RelaxControls(node);
  a.FinishAndChange(node);
  return Changed(node);
}

Reduction JSCreateLowering::ReduceJSCreateIterResultObject(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreateIterResultObject, node->opcode());
  Node* value = NodeProperties::GetValueInput(node, 0);
  Node* done = NodeProperties::GetValueInput(node, 1);
  Node* effect = NodeProperties::GetEffectInput(node);

  Node* iterator_result_map = jsgraph()->ConstantNoHole(
      native_context().iterator_result_map(broker()), broker());

  // Emit code to allocate the JSIteratorResult instance.
  AllocationBuilder a(jsgraph(), broker(), effect, graph()->start());
  a.Allocate(JSIteratorResult::kSize);
  a.Store(AccessBuilder::ForMap(), iterator_result_map);
  a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSObjectElements(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSIteratorResultValue(), value);
  a.Store(AccessBuilder::ForJSIteratorResultDone(), done);
  static_assert(JSIteratorResult::kSize == 5 * kTaggedSize);
  a.FinishAndChange(node);
  return Changed(node);
}

Reduction JSCreateLowering::ReduceJSCreateStringIterator(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreateStringIterator, node->opcode());
  Node* string = NodeProperties::GetValueInput(node, 0);
  Node* effect = NodeProperties::GetEffectInput(node);

  Node* map = jsgraph()->ConstantNoHole(
      native_context().initial_string_iterator_map(broker()), broker());
  // Allocate new iterator and attach the iterator to this string.
  AllocationBuilder a(jsgraph(), broker(), effect, graph()->start());
  a.Allocate(JSStringIterator::kHeaderSize, AllocationType::kYoung,
             Type::OtherObject());
  a.Store(AccessBuilder::ForMap(), map);
  a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSObjectElements(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSStringIteratorString(), string);
  a.Store(AccessBuilder::ForJSStringIteratorIndex(), jsgraph()->SmiConstant(0));
  static_assert(JSIteratorResult::kSize == 5 * kTaggedSize);
  a.FinishAndChange(node);
  return Changed(node);
}

Reduction JSCreateLowering::ReduceJSCreateKeyValueArray(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreateKeyValueArray, node->opcode());
  Node* key = NodeProperties::GetValueInput(node, 0);
  Node* value = NodeProperties::GetValueInput(node, 1);
  Node* effect = NodeProperties::GetEffectInput(node);

  Node* array_map = jsgraph()->ConstantNoHole(
      native_context().js_array_packed_elements_map(broker()), broker());
  Node* length = jsgraph()->ConstantNoHole(2);

  AllocationBuilder aa(jsgraph(), broker(), effect, graph()->start());
  aa.AllocateArray(2, broker()->fixed_array_map());
  aa.Store(AccessBuilder::ForFixedArrayElement(PACKED_ELEMENTS),
           jsgraph()->ZeroConstant(), key);
  aa.Store(AccessBuilder::ForFixedArrayElement(PACKED_ELEMENTS),
           jsgraph()->OneConstant(), value);
  Node* elements = aa.Finish();

  AllocationBuilder a(jsgraph(), broker(), elements, graph()->start());
  a.Allocate(ALIGN_TO_ALLOCATION_ALIGNMENT(JSArray::kHeaderSize));
  a.Store(AccessBuilder::ForMap(), array_map);
  a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSObjectElements(), elements);
  a.Store(AccessBuilder::ForJSArrayLength(PACKED_ELEMENTS), length);
  static_assert(JSArray::kHeaderSize == 4 * kTaggedSize);
  a.FinishAndChange(node);
  return Changed(node);
}

Reduction JSCreateLowering::ReduceJSCreatePromise(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreatePromise, node->opcode());
  Node* effect = NodeProperties::GetEffectInput(node);

  MapRef promise_map =
      native_context().promise_function(broker()).initial_map(broker());

  AllocationBuilder a(jsgraph(), broker(), effect, graph()->start());
  a.Allocate(promise_map.instance_size());
  a.Store(AccessBuilder::ForMap(), promise_map);
  a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSObjectElements(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSObjectOffset(JSPromise::kReactionsOrResultOffset),
          jsgraph()->ZeroConstant());
  static_assert(v8::Promise::kPending == 0);
  a.Store(AccessBuilder::ForJSObjectOffset(JSPromise::kFlagsOffset),
          jsgraph()->ZeroConstant());
  static_assert(JSPromise::kHeaderSize == 5 * kTaggedSize);
  for (int offset = JSPromise::kHeaderSize;
       offset < JSPromise::kSizeWithEmbedderFields; offset += kTaggedSize) {
    a.Store(AccessBuilder::ForJSObjectOffset(offset),
            jsgraph()->ZeroConstant());
  }
  a.FinishAndChange(node);
  return Changed(node);
}

Reduction JSCreateLowering::ReduceJSCreateLiteralArrayOrObject(Node* node) {
  DCHECK(node->opcode() == IrOpcode::kJSCreateLiteralArray ||
         node->opcode() == IrOpcode::kJSCreateLiteralObject);
  JSCreateLiteralOpNode n(node);
  CreateLiteralParameters const& p = n.Parameters();
  Effect effect = n.effect();
  Control control = n.control();
  ProcessedFeedback const& feedback =
      broker()->GetFeedbackForArrayOrObjectLiteral(p.feedback());
  if (!feedback.IsInsufficient()) {
    AllocationSiteRef site = feedback.AsLiteral().value();
    if (!site.boilerplate(broker()).has_value()) return NoChange();
    AllocationType allocation = dependencies()->DependOnPretenureMode(site);
    int max_properties = kMaxFastLiteralProperties;
    std::optional<Node*> maybe_value = TryAllocateFastLiteral(
        effect, control, *site.boilerplate(broker()), allocation,
        kMaxFastLiteralDepth, &max_properties);
    if (!maybe_value.has_value()) return NoChange();
    dependencies()->DependOnElementsKinds(site);
    Node* value = effect = maybe_value.value();
    ReplaceWithValue(node, value, effect, control);
    return Replace(value);
  }
  return NoChange();
}

Reduction JSCreateLowering::ReduceJSCreateEmptyLiteralArray(Node* node) {
  JSCreateEmptyLiteralArrayNode n(node);
  FeedbackParameter const& p = n.Parameters();
  ProcessedFeedback const& feedback =
      broker()->GetFeedbackForArrayOrObjectLiteral(p.feedback());
  if (!feedback.IsInsufficient()) {
    AllocationSiteRef site = feedback.AsLiteral().value();
    DCHECK(!site.PointsToLiteral());
    MapRef initial_map =
        native_context().GetInitialJSArrayMap(broker(), site.GetElementsKind());
    AllocationType const allocation =
        dependencies()->DependOnPretenureMode(site);
    dependencies()->DependOnElementsKind(site);
    Node* length = jsgraph()->ZeroConstant();
    DCHECK(!initial_map.IsInobjectSlackTrackingInProgress());
    SlackTrackingPrediction slack_tracking_prediction(
        initial_map, initial_map.instance_size());
    return ReduceNewArray(node, length, 0, initial_map,
                          initial_map.elements_kind(), allocation,
                          slack_tracking_prediction);
  }
  return NoChange();
}

Reduction JSCreateLowering::ReduceJSCreateEmptyLiteralObject(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreateEmptyLiteralObject, node->opcode());
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  // Retrieve the initial map for the object.
  MapRef map = native_context().object_function(broker()).initial_map(broker());
  DCHECK(!map.is_dictionary_map());
  DCHECK(!map.IsInobjectSlackTrackingInProgress());
  Node* js_object_map = jsgraph()->ConstantNoHole(map, broker());

  // Setup elements and properties.
  Node* elements = jsgraph()->EmptyFixedArrayConstant();

  // Perform the allocation of the actual JSArray object.
  AllocationBuilder a(jsgraph(), broker(), effect, control);
  a.Allocate(map.instance_size());
  a.Store(AccessBuilder::ForMap(), js_object_map);
  a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSObjectElements(), elements);
  for (int i = 0; i < map.GetInObjectProperties(); i++) {
    a.Store(AccessBuilder::ForJSObjectInObjectProperty(map, i),
            jsgraph()->UndefinedConstant());
  }

  RelaxControls(node);
  a.FinishAndChange(node);
  return Changed(node);
}

Reduction JSCreateLowering::ReduceJSCreateLiteralRegExp(Node* node) {
  JSCreateLiteralRegExpNode n(node);
  CreateLiteralParameters const& p = n.Parameters();
  Effect effect = n.effect();
  Control control = n.control();
  ProcessedFeedback const& feedback =
      broker()->GetFeedbackForRegExpLiteral(p.feedback());
  if (!feedback.IsInsufficient()) {
    RegExpBoilerplateDescriptionRef literal =
        feedback.AsRegExpLiteral().value();
    Node* value = effect = AllocateLiteralRegExp(effect, control, literal);
    ReplaceWithValue(node, value, effect, control);
    return Replace(value);
  }
  return NoChange();
}

Reduction JSCreateLowering::ReduceJSGetTemplateObject(Node* node) {
  JSGetTemplateObjectNode n(node);
  GetTemplateObjectParameters const& parameters = n.Parameters();

  const ProcessedFeedback& feedback =
      broker()->GetFeedbackForTemplateObject(parameters.feedback());
  // TODO(v8:7790): Consider not generating JSGetTemplateObject operator
  // in the BytecodeGraphBuilder in the first place, if template_object is not
  // available.
  if (feedback.IsInsufficient()) return NoChange();

  JSArrayRef template_object = feedback.AsTemplateObject().value();
  Node* value = jsgraph()->ConstantNoHole(template_object, broker());
  ReplaceWithValue(node, value);
  return Replace(value);
}

Reduction JSCreateLowering::ReduceJSCreateFunctionContext(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreateFunctionContext, node->opcode());
  const CreateFunctionContextParameters& parameters =
      CreateFunctionContextParametersOf(node->op());
  ScopeInfoRef scope_info = parameters.scope_info();
  int slot_count = parameters.slot_count();
  ScopeType scope_type = parameters.scope_type();

  // Use inline allocation for function contexts up to a size limit.
  if (slot_count < kFunctionContextAllocationLimit) {
    // JSCreateFunctionContext[slot_count < limit]](fun)
    Node* effect = NodeProperties::GetEffectInput(node);
    Node* control = NodeProperties::GetControlInput(node);
    Node* context = NodeProperties::GetContextInput(node);
    AllocationBuilder a(jsgraph(), broker(), effect, control);
    static_assert(Context::MIN_CONTEXT_SLOTS == 2);  // Ensure fully covered.
    int context_length = slot_count + Context::MIN_CONTEXT_SLOTS;
    switch (scope_type) {
      case EVAL_SCOPE:
        a.AllocateContext(context_length,
                          native_context().eval_context_map(broker()));
        break;
      case FUNCTION_SCOPE:
        a.AllocateContext(context_length,
                          native_context().function_context_map(broker()));
        break;
      default:
        UNREACHABLE();
    }
    a.Store(AccessBuilder::ForContextSlot(Context::SCOPE_INFO_INDEX),
            scope_info);
    a.Store(AccessBuilder::ForContextSlot(Context::PREVIOUS_INDEX), context);
    for (int i = Context::MIN_CONTEXT_SLOTS; i < context_length; ++i) {
      a.Store(AccessBuilder::ForContextSlot(i), jsgraph()->UndefinedConstant());
    }
    RelaxControls(node);
    a.FinishAndChange(node);
    return Changed(node);
  }

  return NoChange();
}

Reduction JSCreateLowering::ReduceJSCreateWithContext(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreateWithContext, node->opcode());
  ScopeInfoRef scope_info = ScopeInfoOf(node->op());
  Node* extension = NodeProperties::GetValueInput(node, 0);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput
Prompt: 
```
这是目录为v8/src/compiler/js-create-lowering.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-create-lowering.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
ue,
         values_any_nonnumber = false;
    std::vector<Node*> values;
    values.reserve(p.arity());
    for (int i = 0; i < arity; ++i) {
      Node* value = NodeProperties::GetValueInput(node, 2 + i);
      Type value_type = NodeProperties::GetType(value);
      if (!value_type.Is(Type::SignedSmall())) {
        values_all_smis = false;
      }
      if (!value_type.Is(Type::Number())) {
        values_all_numbers = false;
      }
      if (!value_type.Maybe(Type::Number())) {
        values_any_nonnumber = true;
      }
      values.push_back(value);
    }

    // Try to figure out the ideal elements kind statically.
    if (values_all_smis) {
      // Smis can be stored with any elements kind.
    } else if (values_all_numbers) {
      elements_kind = GetMoreGeneralElementsKind(
          elements_kind, IsHoleyElementsKind(elements_kind)
                             ? HOLEY_DOUBLE_ELEMENTS
                             : PACKED_DOUBLE_ELEMENTS);
    } else if (values_any_nonnumber) {
      elements_kind = GetMoreGeneralElementsKind(
          elements_kind, IsHoleyElementsKind(elements_kind) ? HOLEY_ELEMENTS
                                                            : PACKED_ELEMENTS);
    } else if (!can_inline_call) {
      // We have some crazy combination of types for the {values} where
      // there's no clear decision on the elements kind statically. And
      // we don't have a protection against deoptimization loops for the
      // checks that are introduced in the call to ReduceNewArray, so
      // we cannot inline this invocation of the Array constructor here.
      return NoChange();
    }
    return ReduceNewArray(node, values, *initial_map, elements_kind, allocation,
                          slack_tracking_prediction);
  }
  return NoChange();
}

Reduction JSCreateLowering::ReduceJSCreateArrayIterator(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreateArrayIterator, node->opcode());
  CreateArrayIteratorParameters const& p =
      CreateArrayIteratorParametersOf(node->op());
  Node* iterated_object = NodeProperties::GetValueInput(node, 0);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  // Create the JSArrayIterator result.
  AllocationBuilder a(jsgraph(), broker(), effect, control);
  a.Allocate(JSArrayIterator::kHeaderSize, AllocationType::kYoung,
             Type::OtherObject());
  a.Store(AccessBuilder::ForMap(),
          native_context().initial_array_iterator_map(broker()));
  a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSObjectElements(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSArrayIteratorIteratedObject(), iterated_object);
  a.Store(AccessBuilder::ForJSArrayIteratorNextIndex(),
          jsgraph()->ZeroConstant());
  a.Store(AccessBuilder::ForJSArrayIteratorKind(),
          jsgraph()->ConstantNoHole(static_cast<int>(p.kind())));
  RelaxControls(node);
  a.FinishAndChange(node);
  return Changed(node);
}

Reduction JSCreateLowering::ReduceJSCreateAsyncFunctionObject(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreateAsyncFunctionObject, node->opcode());
  int const register_count = RegisterCountOf(node->op());
  Node* closure = NodeProperties::GetValueInput(node, 0);
  Node* receiver = NodeProperties::GetValueInput(node, 1);
  Node* promise = NodeProperties::GetValueInput(node, 2);
  Node* context = NodeProperties::GetContextInput(node);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  // Create the register file.
  MapRef fixed_array_map = broker()->fixed_array_map();
  AllocationBuilder ab(jsgraph(), broker(), effect, control);
  CHECK(ab.CanAllocateArray(register_count, fixed_array_map));
  ab.AllocateArray(register_count, fixed_array_map);
  for (int i = 0; i < register_count; ++i) {
    ab.Store(AccessBuilder::ForFixedArraySlot(i),
             jsgraph()->UndefinedConstant());
  }
  Node* parameters_and_registers = effect = ab.Finish();

  // Create the JSAsyncFunctionObject result.
  AllocationBuilder a(jsgraph(), broker(), effect, control);
  a.Allocate(JSAsyncFunctionObject::kHeaderSize);
  a.Store(AccessBuilder::ForMap(),
          native_context().async_function_object_map(broker()));
  a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSObjectElements(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSGeneratorObjectContext(), context);
  a.Store(AccessBuilder::ForJSGeneratorObjectFunction(), closure);
  a.Store(AccessBuilder::ForJSGeneratorObjectReceiver(), receiver);
  a.Store(AccessBuilder::ForJSGeneratorObjectInputOrDebugPos(),
          jsgraph()->UndefinedConstant());
  a.Store(AccessBuilder::ForJSGeneratorObjectResumeMode(),
          jsgraph()->ConstantNoHole(JSGeneratorObject::kNext));
  a.Store(AccessBuilder::ForJSGeneratorObjectContinuation(),
          jsgraph()->ConstantNoHole(JSGeneratorObject::kGeneratorExecuting));
  a.Store(AccessBuilder::ForJSGeneratorObjectParametersAndRegisters(),
          parameters_and_registers);
  a.Store(AccessBuilder::ForJSAsyncFunctionObjectPromise(), promise);
  a.FinishAndChange(node);
  return Changed(node);
}

namespace {

MapRef MapForCollectionIterationKind(JSHeapBroker* broker,
                                     NativeContextRef native_context,
                                     CollectionKind collection_kind,
                                     IterationKind iteration_kind) {
  switch (collection_kind) {
    case CollectionKind::kSet:
      switch (iteration_kind) {
        case IterationKind::kKeys:
          UNREACHABLE();
        case IterationKind::kValues:
          return native_context.set_value_iterator_map(broker);
        case IterationKind::kEntries:
          return native_context.set_key_value_iterator_map(broker);
      }
      break;
    case CollectionKind::kMap:
      switch (iteration_kind) {
        case IterationKind::kKeys:
          return native_context.map_key_iterator_map(broker);
        case IterationKind::kValues:
          return native_context.map_value_iterator_map(broker);
        case IterationKind::kEntries:
          return native_context.map_key_value_iterator_map(broker);
      }
      break;
  }
  UNREACHABLE();
}

}  // namespace

Reduction JSCreateLowering::ReduceJSCreateCollectionIterator(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreateCollectionIterator, node->opcode());
  CreateCollectionIteratorParameters const& p =
      CreateCollectionIteratorParametersOf(node->op());
  Node* iterated_object = NodeProperties::GetValueInput(node, 0);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  // Load the OrderedHashTable from the {receiver}.
  Node* table = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForJSCollectionTable()),
      iterated_object, effect, control);

  // Create the JSCollectionIterator result.
  AllocationBuilder a(jsgraph(), broker(), effect, control);
  a.Allocate(JSCollectionIterator::kHeaderSize, AllocationType::kYoung,
             Type::OtherObject());
  a.Store(
      AccessBuilder::ForMap(),
      MapForCollectionIterationKind(broker(), native_context(),
                                    p.collection_kind(), p.iteration_kind()));
  a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSObjectElements(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSCollectionIteratorTable(), table);
  a.Store(AccessBuilder::ForJSCollectionIteratorIndex(),
          jsgraph()->ZeroConstant());
  RelaxControls(node);
  a.FinishAndChange(node);
  return Changed(node);
}

Reduction JSCreateLowering::ReduceJSCreateBoundFunction(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreateBoundFunction, node->opcode());
  CreateBoundFunctionParameters const& p =
      CreateBoundFunctionParametersOf(node->op());
  int const arity = static_cast<int>(p.arity());
  MapRef const map = p.map();
  Node* bound_target_function = NodeProperties::GetValueInput(node, 0);
  Node* bound_this = NodeProperties::GetValueInput(node, 1);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  // Create the [[BoundArguments]] for the result.
  Node* bound_arguments = jsgraph()->EmptyFixedArrayConstant();
  if (arity > 0) {
    MapRef fixed_array_map = broker()->fixed_array_map();
    AllocationBuilder ab(jsgraph(), broker(), effect, control);
    CHECK(ab.CanAllocateArray(arity, fixed_array_map));
    ab.AllocateArray(arity, fixed_array_map);
    for (int i = 0; i < arity; ++i) {
      ab.Store(AccessBuilder::ForFixedArraySlot(i),
               NodeProperties::GetValueInput(node, 2 + i));
    }
    bound_arguments = effect = ab.Finish();
  }

  // Create the JSBoundFunction result.
  AllocationBuilder a(jsgraph(), broker(), effect, control);
  a.Allocate(JSBoundFunction::kHeaderSize, AllocationType::kYoung,
             Type::BoundFunction());
  a.Store(AccessBuilder::ForMap(), map);
  a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSObjectElements(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSBoundFunctionBoundTargetFunction(),
          bound_target_function);
  a.Store(AccessBuilder::ForJSBoundFunctionBoundThis(), bound_this);
  a.Store(AccessBuilder::ForJSBoundFunctionBoundArguments(), bound_arguments);
  RelaxControls(node);
  a.FinishAndChange(node);
  return Changed(node);
}

Reduction JSCreateLowering::ReduceJSCreateClosure(Node* node) {
  JSCreateClosureNode n(node);
  CreateClosureParameters const& p = n.Parameters();
  SharedFunctionInfoRef shared = p.shared_info();
  FeedbackCellRef feedback_cell = n.GetFeedbackCellRefChecked(broker());
#ifndef V8_ENABLE_LEAPTIERING
  HeapObjectRef code = p.code();
#endif
  Effect effect = n.effect();
  Control control = n.control();
  Node* context = n.context();

  // Use inline allocation of closures only for instantiation sites that have
  // seen more than one instantiation, this simplifies the generated code and
  // also serves as a heuristic of which allocation sites benefit from it.
  if (!feedback_cell.map(broker()).equals(broker()->many_closures_cell_map())) {
    return NoChange();
  }

  // Don't inline anything for class constructors.
  if (IsClassConstructor(shared.kind())) return NoChange();

  MapRef function_map = native_context().GetFunctionMapFromIndex(
      broker(), shared.function_map_index());
  DCHECK(!function_map.IsInobjectSlackTrackingInProgress());
  DCHECK(!function_map.is_dictionary_map());

#ifdef V8_ENABLE_LEAPTIERING
  // TODO(saelo): we should embed the dispatch handle directly into the
  // generated code instead of loading it at runtime from the FeedbackCell.
  // This will likely first require GC support though.
  Node* feedback_cell_node = jsgraph()->ConstantNoHole(feedback_cell, broker());
  Node* dispatch_handle;
  if (shared.HasBuiltinId()) {
    // This uses a smi constant to store the static dispatch handle, since
    // currently we expect dispatch handles to be encoded as numbers in the
    // deopt metadata.
    // TODO(olivf): Dispatch handles should be supported in deopt metadata.
    dispatch_handle = jsgraph()->SmiConstant(
        jsgraph()->isolate()->builtin_dispatch_handle(shared.builtin_id()));
  } else {
    DCHECK(feedback_cell.object()->dispatch_handle() != kNullJSDispatchHandle);
    dispatch_handle = effect = graph()->NewNode(
        simplified()->LoadField(
            AccessBuilder::ForFeedbackCellDispatchHandleNoWriteBarrier()),
        feedback_cell_node, effect, control);
  }
#endif  // V8_ENABLE_LEAPTIERING

  // TODO(turbofan): We should use the pretenure flag from {p} here,
  // but currently the heuristic in the parser works against us, as
  // it marks closures like
  //
  //   args[l] = function(...) { ... }
  //
  // for old-space allocation, which doesn't always make sense. For
  // example in case of the bluebird-parallel benchmark, where this
  // is a core part of the *promisify* logic (see crbug.com/810132).
  AllocationType allocation = AllocationType::kYoung;

  // Emit code to allocate the JSFunction instance.
  static_assert(JSFunction::kSizeWithoutPrototype == 7 * kTaggedSize);
  AllocationBuilder a(jsgraph(), broker(), effect, control);
  a.Allocate(function_map.instance_size(), allocation,
             Type::CallableFunction());
  a.Store(AccessBuilder::ForMap(), function_map);
  a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSObjectElements(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSFunctionSharedFunctionInfo(), shared);
  a.Store(AccessBuilder::ForJSFunctionContext(), context);
  a.Store(AccessBuilder::ForJSFunctionFeedbackCell(), feedback_cell);
#ifdef V8_ENABLE_LEAPTIERING
  a.Store(AccessBuilder::ForJSFunctionDispatchHandleNoWriteBarrier(),
          dispatch_handle);
#else
  a.Store(AccessBuilder::ForJSFunctionCode(), code);
#endif  // V8_ENABLE_LEAPTIERING
  static_assert(JSFunction::kSizeWithoutPrototype == 7 * kTaggedSize);
  if (function_map.has_prototype_slot()) {
    a.Store(AccessBuilder::ForJSFunctionPrototypeOrInitialMap(),
            jsgraph()->TheHoleConstant());
    static_assert(JSFunction::kSizeWithPrototype == 8 * kTaggedSize);
  }
  for (int i = 0; i < function_map.GetInObjectProperties(); i++) {
    a.Store(AccessBuilder::ForJSObjectInObjectProperty(function_map, i),
            jsgraph()->UndefinedConstant());
  }
  RelaxControls(node);
  a.FinishAndChange(node);
  return Changed(node);
}

Reduction JSCreateLowering::ReduceJSCreateIterResultObject(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreateIterResultObject, node->opcode());
  Node* value = NodeProperties::GetValueInput(node, 0);
  Node* done = NodeProperties::GetValueInput(node, 1);
  Node* effect = NodeProperties::GetEffectInput(node);

  Node* iterator_result_map = jsgraph()->ConstantNoHole(
      native_context().iterator_result_map(broker()), broker());

  // Emit code to allocate the JSIteratorResult instance.
  AllocationBuilder a(jsgraph(), broker(), effect, graph()->start());
  a.Allocate(JSIteratorResult::kSize);
  a.Store(AccessBuilder::ForMap(), iterator_result_map);
  a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSObjectElements(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSIteratorResultValue(), value);
  a.Store(AccessBuilder::ForJSIteratorResultDone(), done);
  static_assert(JSIteratorResult::kSize == 5 * kTaggedSize);
  a.FinishAndChange(node);
  return Changed(node);
}

Reduction JSCreateLowering::ReduceJSCreateStringIterator(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreateStringIterator, node->opcode());
  Node* string = NodeProperties::GetValueInput(node, 0);
  Node* effect = NodeProperties::GetEffectInput(node);

  Node* map = jsgraph()->ConstantNoHole(
      native_context().initial_string_iterator_map(broker()), broker());
  // Allocate new iterator and attach the iterator to this string.
  AllocationBuilder a(jsgraph(), broker(), effect, graph()->start());
  a.Allocate(JSStringIterator::kHeaderSize, AllocationType::kYoung,
             Type::OtherObject());
  a.Store(AccessBuilder::ForMap(), map);
  a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSObjectElements(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSStringIteratorString(), string);
  a.Store(AccessBuilder::ForJSStringIteratorIndex(), jsgraph()->SmiConstant(0));
  static_assert(JSIteratorResult::kSize == 5 * kTaggedSize);
  a.FinishAndChange(node);
  return Changed(node);
}

Reduction JSCreateLowering::ReduceJSCreateKeyValueArray(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreateKeyValueArray, node->opcode());
  Node* key = NodeProperties::GetValueInput(node, 0);
  Node* value = NodeProperties::GetValueInput(node, 1);
  Node* effect = NodeProperties::GetEffectInput(node);

  Node* array_map = jsgraph()->ConstantNoHole(
      native_context().js_array_packed_elements_map(broker()), broker());
  Node* length = jsgraph()->ConstantNoHole(2);

  AllocationBuilder aa(jsgraph(), broker(), effect, graph()->start());
  aa.AllocateArray(2, broker()->fixed_array_map());
  aa.Store(AccessBuilder::ForFixedArrayElement(PACKED_ELEMENTS),
           jsgraph()->ZeroConstant(), key);
  aa.Store(AccessBuilder::ForFixedArrayElement(PACKED_ELEMENTS),
           jsgraph()->OneConstant(), value);
  Node* elements = aa.Finish();

  AllocationBuilder a(jsgraph(), broker(), elements, graph()->start());
  a.Allocate(ALIGN_TO_ALLOCATION_ALIGNMENT(JSArray::kHeaderSize));
  a.Store(AccessBuilder::ForMap(), array_map);
  a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSObjectElements(), elements);
  a.Store(AccessBuilder::ForJSArrayLength(PACKED_ELEMENTS), length);
  static_assert(JSArray::kHeaderSize == 4 * kTaggedSize);
  a.FinishAndChange(node);
  return Changed(node);
}

Reduction JSCreateLowering::ReduceJSCreatePromise(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreatePromise, node->opcode());
  Node* effect = NodeProperties::GetEffectInput(node);

  MapRef promise_map =
      native_context().promise_function(broker()).initial_map(broker());

  AllocationBuilder a(jsgraph(), broker(), effect, graph()->start());
  a.Allocate(promise_map.instance_size());
  a.Store(AccessBuilder::ForMap(), promise_map);
  a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSObjectElements(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSObjectOffset(JSPromise::kReactionsOrResultOffset),
          jsgraph()->ZeroConstant());
  static_assert(v8::Promise::kPending == 0);
  a.Store(AccessBuilder::ForJSObjectOffset(JSPromise::kFlagsOffset),
          jsgraph()->ZeroConstant());
  static_assert(JSPromise::kHeaderSize == 5 * kTaggedSize);
  for (int offset = JSPromise::kHeaderSize;
       offset < JSPromise::kSizeWithEmbedderFields; offset += kTaggedSize) {
    a.Store(AccessBuilder::ForJSObjectOffset(offset),
            jsgraph()->ZeroConstant());
  }
  a.FinishAndChange(node);
  return Changed(node);
}

Reduction JSCreateLowering::ReduceJSCreateLiteralArrayOrObject(Node* node) {
  DCHECK(node->opcode() == IrOpcode::kJSCreateLiteralArray ||
         node->opcode() == IrOpcode::kJSCreateLiteralObject);
  JSCreateLiteralOpNode n(node);
  CreateLiteralParameters const& p = n.Parameters();
  Effect effect = n.effect();
  Control control = n.control();
  ProcessedFeedback const& feedback =
      broker()->GetFeedbackForArrayOrObjectLiteral(p.feedback());
  if (!feedback.IsInsufficient()) {
    AllocationSiteRef site = feedback.AsLiteral().value();
    if (!site.boilerplate(broker()).has_value()) return NoChange();
    AllocationType allocation = dependencies()->DependOnPretenureMode(site);
    int max_properties = kMaxFastLiteralProperties;
    std::optional<Node*> maybe_value = TryAllocateFastLiteral(
        effect, control, *site.boilerplate(broker()), allocation,
        kMaxFastLiteralDepth, &max_properties);
    if (!maybe_value.has_value()) return NoChange();
    dependencies()->DependOnElementsKinds(site);
    Node* value = effect = maybe_value.value();
    ReplaceWithValue(node, value, effect, control);
    return Replace(value);
  }
  return NoChange();
}

Reduction JSCreateLowering::ReduceJSCreateEmptyLiteralArray(Node* node) {
  JSCreateEmptyLiteralArrayNode n(node);
  FeedbackParameter const& p = n.Parameters();
  ProcessedFeedback const& feedback =
      broker()->GetFeedbackForArrayOrObjectLiteral(p.feedback());
  if (!feedback.IsInsufficient()) {
    AllocationSiteRef site = feedback.AsLiteral().value();
    DCHECK(!site.PointsToLiteral());
    MapRef initial_map =
        native_context().GetInitialJSArrayMap(broker(), site.GetElementsKind());
    AllocationType const allocation =
        dependencies()->DependOnPretenureMode(site);
    dependencies()->DependOnElementsKind(site);
    Node* length = jsgraph()->ZeroConstant();
    DCHECK(!initial_map.IsInobjectSlackTrackingInProgress());
    SlackTrackingPrediction slack_tracking_prediction(
        initial_map, initial_map.instance_size());
    return ReduceNewArray(node, length, 0, initial_map,
                          initial_map.elements_kind(), allocation,
                          slack_tracking_prediction);
  }
  return NoChange();
}

Reduction JSCreateLowering::ReduceJSCreateEmptyLiteralObject(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreateEmptyLiteralObject, node->opcode());
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  // Retrieve the initial map for the object.
  MapRef map = native_context().object_function(broker()).initial_map(broker());
  DCHECK(!map.is_dictionary_map());
  DCHECK(!map.IsInobjectSlackTrackingInProgress());
  Node* js_object_map = jsgraph()->ConstantNoHole(map, broker());

  // Setup elements and properties.
  Node* elements = jsgraph()->EmptyFixedArrayConstant();

  // Perform the allocation of the actual JSArray object.
  AllocationBuilder a(jsgraph(), broker(), effect, control);
  a.Allocate(map.instance_size());
  a.Store(AccessBuilder::ForMap(), js_object_map);
  a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSObjectElements(), elements);
  for (int i = 0; i < map.GetInObjectProperties(); i++) {
    a.Store(AccessBuilder::ForJSObjectInObjectProperty(map, i),
            jsgraph()->UndefinedConstant());
  }

  RelaxControls(node);
  a.FinishAndChange(node);
  return Changed(node);
}

Reduction JSCreateLowering::ReduceJSCreateLiteralRegExp(Node* node) {
  JSCreateLiteralRegExpNode n(node);
  CreateLiteralParameters const& p = n.Parameters();
  Effect effect = n.effect();
  Control control = n.control();
  ProcessedFeedback const& feedback =
      broker()->GetFeedbackForRegExpLiteral(p.feedback());
  if (!feedback.IsInsufficient()) {
    RegExpBoilerplateDescriptionRef literal =
        feedback.AsRegExpLiteral().value();
    Node* value = effect = AllocateLiteralRegExp(effect, control, literal);
    ReplaceWithValue(node, value, effect, control);
    return Replace(value);
  }
  return NoChange();
}

Reduction JSCreateLowering::ReduceJSGetTemplateObject(Node* node) {
  JSGetTemplateObjectNode n(node);
  GetTemplateObjectParameters const& parameters = n.Parameters();

  const ProcessedFeedback& feedback =
      broker()->GetFeedbackForTemplateObject(parameters.feedback());
  // TODO(v8:7790): Consider not generating JSGetTemplateObject operator
  // in the BytecodeGraphBuilder in the first place, if template_object is not
  // available.
  if (feedback.IsInsufficient()) return NoChange();

  JSArrayRef template_object = feedback.AsTemplateObject().value();
  Node* value = jsgraph()->ConstantNoHole(template_object, broker());
  ReplaceWithValue(node, value);
  return Replace(value);
}

Reduction JSCreateLowering::ReduceJSCreateFunctionContext(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreateFunctionContext, node->opcode());
  const CreateFunctionContextParameters& parameters =
      CreateFunctionContextParametersOf(node->op());
  ScopeInfoRef scope_info = parameters.scope_info();
  int slot_count = parameters.slot_count();
  ScopeType scope_type = parameters.scope_type();

  // Use inline allocation for function contexts up to a size limit.
  if (slot_count < kFunctionContextAllocationLimit) {
    // JSCreateFunctionContext[slot_count < limit]](fun)
    Node* effect = NodeProperties::GetEffectInput(node);
    Node* control = NodeProperties::GetControlInput(node);
    Node* context = NodeProperties::GetContextInput(node);
    AllocationBuilder a(jsgraph(), broker(), effect, control);
    static_assert(Context::MIN_CONTEXT_SLOTS == 2);  // Ensure fully covered.
    int context_length = slot_count + Context::MIN_CONTEXT_SLOTS;
    switch (scope_type) {
      case EVAL_SCOPE:
        a.AllocateContext(context_length,
                          native_context().eval_context_map(broker()));
        break;
      case FUNCTION_SCOPE:
        a.AllocateContext(context_length,
                          native_context().function_context_map(broker()));
        break;
      default:
        UNREACHABLE();
    }
    a.Store(AccessBuilder::ForContextSlot(Context::SCOPE_INFO_INDEX),
            scope_info);
    a.Store(AccessBuilder::ForContextSlot(Context::PREVIOUS_INDEX), context);
    for (int i = Context::MIN_CONTEXT_SLOTS; i < context_length; ++i) {
      a.Store(AccessBuilder::ForContextSlot(i), jsgraph()->UndefinedConstant());
    }
    RelaxControls(node);
    a.FinishAndChange(node);
    return Changed(node);
  }

  return NoChange();
}

Reduction JSCreateLowering::ReduceJSCreateWithContext(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreateWithContext, node->opcode());
  ScopeInfoRef scope_info = ScopeInfoOf(node->op());
  Node* extension = NodeProperties::GetValueInput(node, 0);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  Node* context = NodeProperties::GetContextInput(node);

  AllocationBuilder a(jsgraph(), broker(), effect, control);
  static_assert(Context::MIN_CONTEXT_EXTENDED_SLOTS ==
                3);  // Ensure fully covered.
  a.AllocateContext(Context::MIN_CONTEXT_EXTENDED_SLOTS,
                    native_context().with_context_map(broker()));
  a.Store(AccessBuilder::ForContextSlot(Context::SCOPE_INFO_INDEX), scope_info);
  a.Store(AccessBuilder::ForContextSlot(Context::PREVIOUS_INDEX), context);
  a.Store(AccessBuilder::ForContextSlot(Context::EXTENSION_INDEX), extension);
  RelaxControls(node);
  a.FinishAndChange(node);
  return Changed(node);
}

Reduction JSCreateLowering::ReduceJSCreateCatchContext(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreateCatchContext, node->opcode());
  ScopeInfoRef scope_info = ScopeInfoOf(node->op());
  Node* exception = NodeProperties::GetValueInput(node, 0);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  Node* context = NodeProperties::GetContextInput(node);

  AllocationBuilder a(jsgraph(), broker(), effect, control);
  static_assert(Context::MIN_CONTEXT_SLOTS == 2);  // Ensure fully covered.
  a.AllocateContext(Context::MIN_CONTEXT_SLOTS + 1,
                    native_context().catch_context_map(broker()));
  a.Store(AccessBuilder::ForContextSlot(Context::SCOPE_INFO_INDEX), scope_info);
  a.Store(AccessBuilder::ForContextSlot(Context::PREVIOUS_INDEX), context);
  a.Store(AccessBuilder::ForContextSlot(Context::THROWN_OBJECT_INDEX),
          exception);
  RelaxControls(node);
  a.FinishAndChange(node);
  return Changed(node);
}

Reduction JSCreateLowering::ReduceJSCreateBlockContext(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreateBlockContext, node->opcode());
  ScopeInfoRef scope_info = ScopeInfoOf(node->op());
  int const context_length = scope_info.ContextLength();

  // Use inline allocation for block contexts up to a size limit.
  if (context_length < kBlockContextAllocationLimit) {
    // JSCreateBlockContext[scope[length < limit]](fun)
    Node* effect = NodeProperties::GetEffectInput(node);
    Node* control = NodeProperties::GetControlInput(node);
    Node* context = NodeProperties::GetContextInput(node);

    AllocationBuilder a(jsgraph(), broker(), effect, control);
    static_assert(Context::MIN_CONTEXT_SLOTS == 2);  // Ensure fully covered.
    a.AllocateContext(context_length,
                      native_context().block_context_map(broker()));
    a.Store(AccessBuilder::ForContextSlot(Context::SCOPE_INFO_INDEX),
            scope_info);
    a.Store(AccessBuilder::ForContextSlot(Context::PREVIOUS_INDEX), context);
    for (int i = Context::MIN_CONTEXT_SLOTS; i < context_length; ++i) {
      a.Store(AccessBuilder::ForContextSlot(i), jsgraph()->UndefinedConstant());
    }
    RelaxControls(node);
    a.FinishAndChange(node);
    return Changed(node);
  }

  return NoChange();
}

namespace {

OptionalMapRef GetObjectCreateMap(JSHeapBroker* broker,
                                  HeapObjectRef prototype) {
  MapRef standard_map =
      broker->target_native_context().object_function(broker).initial_map(
          broker);
  if (prototype.equals(standard_map.prototype(broker))) {
    return standard_map;
  }
  if (prototype.map(broker).oddball_type(broker) == OddballType::kNull) {
    return broker->target_native_context().slow_object_with_null_prototype_map(
        broker);
  }
  if (prototype.IsJSObject()) {
    return prototype.AsJSObject().GetObjectCreateMap(broker);
  }
  return OptionalMapRef();
}

}  // namespace

Reduction JSCreateLowering::ReduceJSCreateObject(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreateObject, node->opcode());
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  Node* prototype = NodeProperties::GetValueInput(node, 0);
  Type prototype_type = NodeProperties::GetType(prototype);
  if (!prototype_type.IsHeapConstant()) return NoChange();

  HeapObjectRef prototype_const = prototype_type.AsHeapConstant()->Ref();
  auto maybe_instance_map = GetObjectCreateMap(broker(), prototype_const);
  if (!maybe_instance_map) return NoChange();
  MapRef instance_map = maybe_instance_map.value();

  Node* properties = jsgraph()->EmptyFixedArrayConstant();
  if (instance_map.is_dictionary_map()) {
    DCHECK_EQ(prototype_const.map(broker()).oddball_type(broker()),
              OddballType::kNull);
    // Allocate an empty NameDictionary as backing store for the properties.
    MapRef map = broker()->name_dictionary_map();
    int capacity =
        NameDictionary::ComputeCapacity(NameDictionary::kInitialCapacity);
    DCHECK(base::bits::IsPowerOfTwo(capacity));
    int length = NameDictionary::EntryToIndex(InternalIndex(capacity));
    int size = NameDictionary::SizeFor(length);

    AllocationBuilder a(jsgraph(), broker(), effect, control);
    a.Allocate(size, AllocationType::kYoung, Type::Any());
    a.Store(AccessBuilder::ForMap(), map);
    // Initialize FixedArray fields.
    a.Store(AccessBuilder::ForFixedArrayLength(),
            jsgraph()->SmiConstant(length));
    // Initialize HashTable fields.
    a.Store(AccessBuilder::ForHashTableBaseNumberOfElements(),
            jsgraph()->SmiConstant(0));
    a.Store(AccessBuilder::ForHashTableBaseNumberOfDeletedElement(),
            jsgraph()->SmiConstant(0));
    a.Store(AccessBuilder::ForHashTableBaseCapacity(),
            jsgraph()->SmiConstant(capacity));
    // Initialize Dictionary fields.
    a.Store(AccessBuilder::ForDictionaryNextEnumerationIndex(),
            jsgraph()->SmiConstant(PropertyDetails::kInitialIndex));
    a.Store(AccessBuilder::ForDictionaryObjectHashIndex(),
            jsgraph()->SmiConstant(PropertyArray::kNoHashSentinel));
    // Initialize NameDictionary fields.
    a.Store(AccessBuilder::ForNameDictionaryFlagsIndex(),
            jsgraph()->SmiConstant(NameDictionary::kFlagsDefault));
    // Initialize the Properties fields.
    Node* undefined = jsgraph()->UndefinedConstant();
    static_assert(NameDictionary::kElementsStartIndex ==
                  NameDictionary::kFlagsIndex + 1);
    for (int index = NameDictionary::kElementsStartIndex; index < length;
         index++) {
      a.Store(AccessBuilder::ForFixedArraySlot(index, kNoWriteBarrier),
              undefined);
    }
    properties = effect = a.Finish();
  }

  int const instance_size = instance_map.instance_size();
  if (instance_size > kMaxRegularHeapObjectSize) return NoChange();
  CHECK(!instance_map.IsInobjectSlackTrackingInProgress());

  // Emit code to allocate the JSObject instance for the given
  // {instance_map}.
  AllocationBuilder a(jsgraph(), broker(), effect, control);
  a.Allocate(instance_size, AllocationType::kYoung, Type::Any());
  a.Store(AccessBuilder::ForMap(), instance_map);
  a.Store(AccessBuilder::ForJSObjectPropertiesOrHash(), properties);

"""


```