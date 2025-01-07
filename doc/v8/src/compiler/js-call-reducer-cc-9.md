Response:
The user wants a summary of the functionality of the provided C++ code snippet from V8's `js-call-reducer.cc`. I need to analyze the code and identify the patterns of code transformation and optimization it performs.

Here's a breakdown of the thinking process to generate the response:

1. **Identify the core purpose:** The filename `js-call-reducer.cc` strongly suggests that this code is responsible for *reducing* or simplifying JavaScript call nodes in V8's intermediate representation (IR). This reduction is a key optimization step in the compilation pipeline.

2. **Analyze individual reduction functions:**  Go through each function starting with `Reduce...`. These functions are the primary units of work.

3. **`ReduceStringPrototypeConcat`:** This function handles `String.prototype.concat()`. It checks if the receiver and the argument are strings and then replaces the call with a more efficient `StringConcat` operation.

4. **`ReduceStringConstructor`:** This function handles the `String()` constructor. It optimizes cases where the constructor is called without `new`, creating primitive strings or string wrappers. It also deals with potential deoptimization.

5. **`ReducePromiseConstructor`:** This handles the `Promise` constructor. It appears to be inlining the promise construction process when the executor is available and it's a built-in Promise.

6. **`ReducePromisePrototypeCatch`:** This handles `Promise.prototype.catch()`. It rewrites the call to `Promise.prototype.then()` with the `onRejected` handler and `undefined` for `onFulfilled`.

7. **`ReducePromisePrototypeFinally`:** This handles `Promise.prototype.finally()`. It's more complex, involving checking if the `onFinally` handler is callable and creating closures to handle both fulfillment and rejection cases. It also rewrites the call to `Promise.prototype.then()`.

8. **`ReducePromisePrototypeThen`:** This handles `Promise.prototype.then()`. It creates a new `Promise` and chains the fulfillment and rejection handlers using `PerformPromiseThen`.

9. **`ReducePromiseResolveTrampoline`:** This handles `Promise.resolve()`. It simplifies the call when the receiver is known to be a `JSReceiver`.

10. **`ReduceTypedArrayConstructor`:** This handles `TypedArray` constructors. It seems to create a `CreateTypedArray` node, likely for efficient typed array allocation.

11. **`ReduceTypedArrayPrototypeToStringTag`:** This handles the `@@toStringTag` symbol for `TypedArray.prototype`. It determines the correct string tag based on the underlying element type of the TypedArray.

12. **`ReduceArrayBufferViewByteLengthAccessor`:** This handles the `byteLength` accessor for `ArrayBufferView` (including `TypedArray` and `DataView`). It has special handling for resizable array buffers (RAB) and growable shared array buffers (GSAB).

13. **`ReduceArrayBufferViewByteOffsetAccessor`:** This handles the `byteOffset` accessor for `ArrayBufferView`. It also has special handling for RAB/GSAB.

14. **`ReduceTypedArrayPrototypeLength`:** This handles the `length` accessor for `TypedArray`. It also has special handling for RAB/GSAB.

15. **`ReduceNumberIsFinite`, `ReduceNumberIsInteger`, `ReduceNumberIsSafeInteger`, `ReduceNumberIsNaN`:** These handle the static methods of the `Number` object. They replace the calls with simpler, more efficient IR nodes.

16. **`ReduceMapPrototypeGet`:** This optimizes `Map.prototype.get()`. It directly accesses the underlying hash table to retrieve the value.

17. **`ReduceMapPrototypeHas`, `ReduceSetPrototypeHas`:** These optimize `Map.prototype.has()` and `Set.prototype.has()`. They directly check for the presence of a key in the underlying hash table.

18. **Identify common themes:**  Notice that many of these functions:
    * Check preconditions (e.g., argument counts, receiver types).
    * Speculate on object types using `MapInference`.
    * Replace JavaScript call nodes with simpler, more specialized IR nodes (e.g., `StringConcat`, `CreateTypedArray`, `LoadField`).
    * Handle deoptimization scenarios.
    * Depend on protector cells for optimization safety.

19. **Address specific requirements:**
    * **Functionality:** List the actions performed by the code (optimization, inlining, etc.).
    * **Torque:** Confirm that `.cc` extension means it's C++, not Torque.
    * **JavaScript examples:** Provide illustrative JavaScript code that would trigger the optimizations.
    * **Logic inference:** Create simple scenarios with inputs and expected outputs to demonstrate the transformations.
    * **Common errors:**  Think about typical mistakes developers make that these optimizations might address or work around.
    * **Part 10 of 12:** Acknowledge this context and emphasize the ongoing nature of optimization within the compiler.

20. **Structure the response:** Organize the information clearly with headings and bullet points for readability.

By following these steps, I can generate a comprehensive and accurate summary of the `js-call-reducer.cc` code, addressing all the user's requirements.
```cpp
 Control control = n.control();
  Node* receiver = effect = graph()->NewNode(
      simplified()->CheckString(p.feedback()), n.receiver(), effect, control);

  if (parameter_count == 0) {
    ReplaceWithValue(node, receiver, effect, control);
    return Replace(receiver);
  }

  Node* argument = effect = graph()->NewNode(
      simplified()->CheckString(p.feedback()), n.Argument(0), effect, control);
  Node* receiver_length =
      graph()->NewNode(simplified()->StringLength(), receiver);
  Node* argument_length =
      graph()->NewNode(simplified()->StringLength(), argument);
  Node* length = graph()->NewNode(simplified()->NumberAdd(), receiver_length,
                                  argument_length);
  length = effect = graph()->NewNode(
      simplified()->CheckBounds(p.feedback()), length,
      jsgraph()->ConstantNoHole(String::kMaxLength + 1), effect, control);

  Node* value = graph()->NewNode(simplified()->StringConcat(), length, receiver,
                                 argument);

  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

namespace {

FrameState CreateStringCreateLazyDeoptContinuationFrameState(
    JSGraph* graph, SharedFunctionInfoRef shared, Node* target, Node* context,
    Node* outer_frame_state) {
  Node* const receiver = graph->TheHoleConstant();
  Node* stack_parameters[]{receiver};
  const int stack_parameter_count = arraysize(stack_parameters);
  return CreateJavaScriptBuiltinContinuationFrameState(
      graph, shared, Builtin::kStringCreateLazyDeoptContinuation, target,
      context, stack_parameters, stack_parameter_count, outer_frame_state,
      ContinuationFrameStateMode::LAZY);
}

}  // namespace

Reduction JSCallReducer::ReduceStringConstructor(Node* node,
                                                 JSFunctionRef constructor) {
  JSConstructNode n(node);
  if (n.target() != n.new_target()) return NoChange();

  DCHECK_EQ(constructor, native_context().string_function(broker_));
  DCHECK(constructor.initial_map(broker_).IsJSPrimitiveWrapperMap());

  Node* context = n.context();
  FrameState frame_state = n.frame_state();
  Effect effect = n.effect();
  Control control = n.control();

  Node* primitive_value;
  if (n.ArgumentCount() == 0) {
    primitive_value = jsgraph()->EmptyStringConstant();
  } else {
    // Insert a construct stub frame into the chain of frame states. This will
    // reconstruct the proper frame when deoptimizing within the constructor.
    frame_state = CreateConstructInvokeStubFrameState(
        node, frame_state, constructor.shared(broker_), context, common(),
        graph());

    // This continuation takes the newly created primitive string, and wraps it
    // in a string wrapper, matching CreateStringWrapper.
    Node* continuation_frame_state =
        CreateStringCreateLazyDeoptContinuationFrameState(
            jsgraph(), constructor.shared(broker_), n.target(), context,
            frame_state);

    primitive_value = effect = control =
        graph()->NewNode(javascript()->ToString(), n.Argument(0), context,
                         continuation_frame_state, effect, control);

    // Rewire potential exception edges.
    Node* on_exception = nullptr;
    if (NodeProperties::IsExceptionalCall(node, &on_exception)) {
      // Create appropriate {IfException} and {IfSuccess} nodes.
      Node* if_exception =
          graph()->NewNode(common()->IfException(), effect, control);
      control = graph()->NewNode(common()->IfSuccess(), control);

      // Join the exception edges.
      Node* merge =
          graph()->NewNode(common()->Merge(2), if_exception, on_exception);
      Node* ephi = graph()->NewNode(common()->EffectPhi(2), if_exception,
                                    on_exception, merge);
      Node* phi =
          graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                           if_exception, on_exception, merge);
      ReplaceWithValue(on_exception, phi, ephi, merge);
      merge->ReplaceInput(1, on_exception);
      ephi->ReplaceInput(1, on_exception);
      phi->ReplaceInput(1, on_exception);
    }
  }

  RelaxControls(node, control);
  node->ReplaceInput(0, primitive_value);
  node->ReplaceInput(1, context);
  node->ReplaceInput(2, effect);
  node->TrimInputCount(3);
  NodeProperties::ChangeOp(node, javascript()->CreateStringWrapper());
  return Changed(node);
}

Reduction JSCallReducer::ReducePromiseConstructor(Node* node) {
  PromiseBuiltinReducerAssembler a(this, node);

  // We only inline when we have the executor.
  if (a.ConstructArity() < 1) return NoChange();
  // Only handle builtins Promises, not subclasses.
  if (a.TargetInput() != a.NewTargetInput()) return NoChange();
  if (!dependencies()->DependOnPromiseHookProtector()) return NoChange();

  TNode<Object> subgraph = a.ReducePromiseConstructor(native_context());
  return ReplaceWithSubgraph(&a, subgraph);
}

bool JSCallReducer::DoPromiseChecks(MapInference* inference) {
  if (!inference->HaveMaps()) return false;
  ZoneRefSet<Map> const& receiver_maps = inference->GetMaps();

  // Check whether all {receiver_maps} are JSPromise maps and
  // have the initial Promise.prototype as their [[Prototype]].
  for (MapRef receiver_map : receiver_maps) {
    if (!receiver_map.IsJSPromiseMap()) return false;
    HeapObjectRef prototype = receiver_map.prototype(broker());
    if (!prototype.equals(native_context().promise_prototype(broker()))) {
      return false;
    }
  }

  return true;
}

// ES section #sec-promise.prototype.catch
Reduction JSCallReducer::ReducePromisePrototypeCatch(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }
  int arity = p.arity_without_implicit_args();
  Node* receiver = n.receiver();
  Effect effect = n.effect();
  Control control = n.control();

  MapInference inference(broker(), receiver, effect);
  if (!DoPromiseChecks(&inference)) return inference.NoChange();

  if (!dependencies()->DependOnPromiseThenProtector()) {
    return inference.NoChange();
  }
  inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                      control, p.feedback());

  // Massage the {node} to call "then" instead by first removing all inputs
  // following the onRejected parameter, and then filling up the parameters
  // to two inputs from the left with undefined.
  Node* target = jsgraph()->ConstantNoHole(
      native_context().promise_then(broker()), broker());
  NodeProperties::ReplaceValueInput(node, target, 0);
  NodeProperties::ReplaceEffectInput(node, effect);
  for (; arity > 1; --arity) node->RemoveInput(3);
  for (; arity < 2; ++arity) {
    node->InsertInput(graph()->zone(), 2, jsgraph()->UndefinedConstant());
  }
  NodeProperties::ChangeOp(
      node, javascript()->Call(
                JSCallNode::ArityForArgc(arity), p.frequency(), p.feedback(),
                ConvertReceiverMode::kNotNullOrUndefined, p.speculation_mode(),
                CallFeedbackRelation::kUnrelated));
  return Changed(node).FollowedBy(ReducePromisePrototypeThen(node));
}

Node* JSCallReducer::CreateClosureFromBuiltinSharedFunctionInfo(
    SharedFunctionInfoRef shared, Node* context, Node* effect, Node* control) {
  DCHECK(shared.HasBuiltinId());
  Handle<FeedbackCell> feedback_cell =
      isolate()->factory()->many_closures_cell();
  Callable const callable =
      Builtins::CallableFor(isolate(), shared.builtin_id());
  CodeRef code = MakeRef(broker(), *callable.code());
  return graph()->NewNode(javascript()->CreateClosure(shared, code),
                          jsgraph()->HeapConstantNoHole(feedback_cell), context,
                          effect, control);
}

// ES section #sec-promise.prototype.finally
Reduction JSCallReducer::ReducePromisePrototypeFinally(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  int arity = p.arity_without_implicit_args();
  Node* receiver = n.receiver();
  Node* on_finally = n.ArgumentOrUndefined(0, jsgraph());
  Effect effect = n.effect();
  Control control = n.control();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  MapInference inference(broker(), receiver, effect);
  if (!DoPromiseChecks(&inference)) return inference.NoChange();
  ZoneRefSet<Map> const& receiver_maps = inference.GetMaps();

  if (!dependencies()->DependOnPromiseHookProtector()) {
    return inference.NoChange();
  }
  if (!dependencies()->DependOnPromiseThenProtector()) {
    return inference.NoChange();
  }
  if (!dependencies()->DependOnPromiseSpeciesProtector()) {
    return inference.NoChange();
  }
  inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                      control, p.feedback());

  // Check if {on_finally} is callable, and if so wrap it into appropriate
  // closures that perform the finalization.
  Node* check = graph()->NewNode(simplified()->ObjectIsCallable(), on_finally);
  Node* branch =
      graph()->NewNode(common()->Branch(BranchHint::kTrue), check, control);

  Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
  Node* etrue = effect;
  Node* catch_true;
  Node* then_true;
  {
    Node* context = jsgraph()->ConstantNoHole(native_context(), broker());
    Node* constructor = jsgraph()->ConstantNoHole(
        native_context().promise_function(broker()), broker());

    // Allocate shared context for the closures below.
    context = etrue = graph()->NewNode(
        javascript()->CreateFunctionContext(
            native_context().scope_info(broker()),
            int{PromiseBuiltins::kPromiseFinallyContextLength} -
                Context::MIN_CONTEXT_SLOTS,
            FUNCTION_SCOPE),
        context, etrue, if_true);
    etrue = graph()->NewNode(
        simplified()->StoreField(
            AccessBuilder::ForContextSlot(PromiseBuiltins::kOnFinallySlot)),
        context, on_finally, etrue, if_true);
    etrue = graph()->NewNode(
        simplified()->StoreField(
            AccessBuilder::ForContextSlot(PromiseBuiltins::kConstructorSlot)),
        context, constructor, etrue, if_true);

    // Allocate the closure for the reject case.
    SharedFunctionInfoRef promise_catch_finally =
        MakeRef(broker(), factory()->promise_catch_finally_shared_fun());
    catch_true = etrue = CreateClosureFromBuiltinSharedFunctionInfo(
        promise_catch_finally, context, etrue, if_true);

    // Allocate the closure for the fulfill case.
    SharedFunctionInfoRef promise_then_finally =
        MakeRef(broker(), factory()->promise_then_finally_shared_fun());
    then_true = etrue = CreateClosureFromBuiltinSharedFunctionInfo(
        promise_then_finally, context, etrue, if_true);
  }

  Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
  Node* efalse = effect;
  Node* catch_false = on_finally;
  Node* then_false = on_finally;

  control = graph()->NewNode(common()->Merge(2), if_true, if_false);
  effect = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);
  Node* catch_finally =
      graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                       catch_true, catch_false, control);
  Node* then_finally =
      graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                       then_true, then_false, control);

  // At this point we definitely know that {receiver} has one of the
  // {receiver_maps}, so insert a MapGuard as a hint for the lowering
  // of the call to "then" below.
  {
    effect = graph()->NewNode(simplified()->MapGuard(receiver_maps), receiver,
                              effect, control);
  }

  // Massage the {node} to call "then" instead by first removing all inputs
  // following the onFinally parameter, and then replacing the only parameter
  // input with the {on_finally} value.
  Node* target = jsgraph()->ConstantNoHole(
      native_context().promise_then(broker()), broker());
  NodeProperties::ReplaceValueInput(node, target, n.TargetIndex());
  NodeProperties::ReplaceEffectInput(node, effect);
  NodeProperties::ReplaceControlInput(node, control);
  for (; arity > 2; --arity) node->RemoveInput(2);
  for (; arity < 2; ++arity) {
    node->InsertInput(graph()->zone(), 2, then_finally);
  }
  node->ReplaceInput(2, then_finally);
  node->ReplaceInput(3, catch_finally);
  NodeProperties::ChangeOp(
      node, javascript()->Call(
                JSCallNode::ArityForArgc(arity), p.frequency(), p.feedback(),
                ConvertReceiverMode::kNotNullOrUndefined, p.speculation_mode(),
                CallFeedbackRelation::kUnrelated));
  return Changed(node).FollowedBy(ReducePromisePrototypeThen(node));
}

Reduction JSCallReducer::ReducePromisePrototypeThen(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Node* receiver = n.receiver();
  Node* on_fulfilled = n.ArgumentOrUndefined(0, jsgraph());
  Node* on_rejected = n.ArgumentOrUndefined(1, jsgraph());
  Node* context = n.context();
  Effect effect = n.effect();
  Control control = n.control();
  FrameState frame_state = n.frame_state();

  MapInference inference(broker(), receiver, effect);
  if (!DoPromiseChecks(&inference)) return inference.NoChange();

  if (!dependencies()->DependOnPromiseHookProtector()) {
    return inference.NoChange();
  }
  if (!dependencies()->DependOnPromiseSpeciesProtector()) {
    return inference.NoChange();
  }
  inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                      control, p.feedback());

  // Check that {on_fulfilled} is callable.
  on_fulfilled = graph()->NewNode(
      common()->Select(MachineRepresentation::kTagged, BranchHint::kTrue),
      graph()->NewNode(simplified()->ObjectIsCallable(), on_fulfilled),
      on_fulfilled, jsgraph()->UndefinedConstant());

  // Check that {on_rejected} is callable.
  on_rejected = graph()->NewNode(
      common()->Select(MachineRepresentation::kTagged, BranchHint::kTrue),
      graph()->NewNode(simplified()->ObjectIsCallable(), on_rejected),
      on_rejected, jsgraph()->UndefinedConstant());

  // Create the resulting JSPromise.
  Node* promise = effect =
      graph()->NewNode(javascript()->CreatePromise(), context, effect);

  // Chain {result} onto {receiver}.
  promise = effect = graph()->NewNode(
      javascript()->PerformPromiseThen(), receiver, on_fulfilled, on_rejected,
      promise, context, frame_state, effect, control);

  // At this point we know that {promise} is going to have the
  // initial Promise map, since even if {PerformPromiseThen}
  // above called into the host rejection tracker, the {promise}
  // doesn't escape to user JavaScript. So bake this information
  // into the graph such that subsequent passes can use the
  // information for further optimizations.
  MapRef promise_map =
      native_context().promise_function(broker()).initial_map(broker());
  effect =
      graph()->NewNode(simplified()->MapGuard(ZoneRefSet<Map>(promise_map)),
                       promise, effect, control);

  ReplaceWithValue(node, promise, effect, control);
  return Replace(promise);
}

// ES section #sec-promise.resolve
Reduction JSCallReducer::ReducePromiseResolveTrampoline(Node* node) {
  JSCallNode n(node);
  Node* receiver = n.receiver();
  Node* value = n.ArgumentOrUndefined(0, jsgraph());
  Node* context = n.context();
  Effect effect = n.effect();
  Control control = n.control();
  FrameState frame_state = n.frame_state();

  // Only reduce when the receiver is guaranteed to be a JSReceiver.
  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() || !inference.AllOfInstanceTypesAreJSReceiver()) {
    return NoChange();
  }

  // Morph the {node} into a JSPromiseResolve operation.
  node->ReplaceInput(0, receiver);
  node->ReplaceInput(1, value);
  node->ReplaceInput(2, context);
  node->ReplaceInput(3, frame_state);
  node->ReplaceInput(4, effect);
  node->ReplaceInput(5, control);
  node->TrimInputCount(6);
  NodeProperties::ChangeOp(node, javascript()->PromiseResolve());
  return Changed(node);
}

// ES #sec-typedarray-constructors
Reduction JSCallReducer::ReduceTypedArrayConstructor(
    Node* node, SharedFunctionInfoRef shared) {
  JSConstructNode n(node);
  Node* target = n.target();
  Node* arg0 = n.ArgumentOrUndefined(0, jsgraph());
  Node* arg1 = n.ArgumentOrUndefined(1, jsgraph());
  Node* arg2 = n.ArgumentOrUndefined(2, jsgraph());
  Node* new_target = n.new_target();
  Node* context = n.context();
  FrameState frame_state = n.frame_state();
  Effect effect = n.effect();
  Control control = n.control();

  // Insert a construct stub frame into the chain of frame states. This will
  // reconstruct the proper frame when deoptimizing within the constructor.
  frame_state = CreateConstructInvokeStubFrameState(node, frame_state, shared,
                                                    context, common(), graph());

  // This continuation just returns the newly created JSTypedArray. We
  // pass the_hole as the receiver, just like the builtin construct stub
  // does in this case.
  Node* const receiver = jsgraph()->TheHoleConstant();
  Node* continuation_frame_state = CreateGenericLazyDeoptContinuationFrameState(
      jsgraph(), shared, target, context, receiver, frame_state);

  Node* result = graph()->NewNode(javascript()->CreateTypedArray(), target,
                                  new_target, arg0, arg1, arg2, context,
                                  continuation_frame_state, effect, control);
  return Replace(result);
}

// ES #sec-get-%typedarray%.prototype-@@tostringtag
Reduction JSCallReducer::ReduceTypedArrayPrototypeToStringTag(Node* node) {
  Node* receiver = NodeProperties::GetValueInput(node, 1);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  NodeVector values(graph()->zone());
  NodeVector effects(graph()->zone());
  NodeVector controls(graph()->zone());

  Node* smi_check = graph()->NewNode(simplified()->ObjectIsSmi(), receiver);
  control = graph()->NewNode(common()->Branch(BranchHint::kFalse), smi_check,
                             control);

  values.push_back(jsgraph()->UndefinedConstant());
  effects.push_back(effect);
  controls.push_back(graph()->NewNode(common()->IfTrue(), control));

  control = graph()->NewNode(common()->IfFalse(), control);
  Node* receiver_map = effect =
      graph()->NewNode(simplified()->LoadField(AccessBuilder::ForMap()),
                       receiver, effect, control);
  Node* receiver_bit_field2 = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForMapBitField2()), receiver_map,
      effect, control);
  Node* receiver_elements_kind = graph()->NewNode(
      simplified()->NumberShiftRightLogical(),
      graph()->NewNode(
          simplified()->NumberBitwiseAnd(), receiver_bit_field2,
          jsgraph()->ConstantNoHole(Map::Bits2::ElementsKindBits::kMask)),
      jsgraph()->ConstantNoHole(Map::Bits2::ElementsKindBits::kShift));

  // Offset the elements kind by FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND,
  // so that the branch cascade below is turned into a simple table
  // switch by the ControlFlowOptimizer later.
  receiver_elements_kind = graph()->NewNode(
      simplified()->NumberSubtract(), receiver_elements_kind,
      jsgraph()->ConstantNoHole(FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND));

  // To be converted into a switch by the ControlFlowOptimizer, the below
  // code requires that TYPED_ARRAYS and RAB_GSAB_TYPED_ARRAYS are consecutive.
  static_assert(LAST_FIXED_TYPED_ARRAY_ELEMENTS_KIND + 1 ==
                FIRST_RAB_GSAB_FIXED_TYPED_ARRAY_ELEMENTS_KIND);
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype)                          \
  do {                                                                     \
    Node* check = graph()->NewNode(                                        \
        simplified()->NumberEqual(), receiver_elements_kind,               \
        jsgraph()->ConstantNoHole(TYPE##_ELEMENTS -                        \
                                  FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND)); \
    control = graph()->NewNode(common()->Branch(), check, control);        \
    values.push_back(jsgraph()->ConstantNoHole(                            \
        broker()->GetTypedArrayStringTag(TYPE##_ELEMENTS), broker()));     \
    effects.push_back(effect);                                             \
    controls.push_back(graph()->NewNode(common()->IfTrue(), control));     \
    control = graph()->NewNode(common()->IfFalse(), control);              \
  } while (false);
  TYPED_ARRAYS(TYPED_ARRAY_CASE)
  RAB_GSAB_TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE

  values.push_back(jsgraph()->UndefinedConstant());
  effects.push_back(effect);
  controls.push_back(control);

  int const count = static_cast<int>(controls.size());
  control = graph()->NewNode(common()->Merge(count), count, &controls.front());
  effects.push_back(control);
  effect =
      graph()->NewNode(common()->EffectPhi(count), count + 1, &effects.front());
  values.push_back(control);
  Node* value =
      graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, count),
                       count + 1, &values.front());
  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

Reduction JSCallReducer::ReduceArrayBufferViewByteLengthAccessor(
    Node* node, InstanceType instance_type, Builtin builtin) {
  // TODO(v8:11111): Optimize for JS_RAB_GSAB_DATA_VIEW_TYPE too.
  DCHECK(instance_type == JS_TYPED_ARRAY_TYPE ||
         instance_type == JS_DATA_VIEW_TYPE);
  Node* receiver = NodeProperties::GetValueInput(node, 1);
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() ||
      !inference.AllOfInstanceTypesAre(instance_type)) {
    return inference.NoChange();
  }

  std::set<ElementsKind> elements_kinds;
  bool maybe_rab_gsab = false;
  if (instance_type == JS_TYPED_ARRAY_TYPE) {
    for (MapRef map : inference.GetMaps()) {
      ElementsKind kind = map.elements_kind();
      elements_kinds.insert(kind);
      if (IsRabGsabTypedArrayElementsKind(kind)) maybe_rab_gsab = true;
    }
  }

  if (!maybe_rab_gsab) {
    // We do not perform any change depending on this inference.
    Reduction unused_reduction = inference.NoChange();
    USE(unused_reduction);
    // Call default implementation for non-rab/gsab TAs.
    return ReduceArrayBufferViewAccessor(
        node, instance_type, AccessBuilder::ForJSArrayBufferViewByteLength(),
        builtin);
  }

  const CallParameters& p = CallParametersOf(node->op());
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return inference.NoChange();
  }
  DCHECK(p.feedback().IsValid());

  inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                      control, p.feedback());

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

  JSCallReducerAssembler a(this, node);
  TNode<JSTypedArray> typed_array =
      TNode<JSTypedArray>::UncheckedCast(receiver);
  TNode<Number> length = a.ArrayBufferViewByteLength(
      typed_array, instance_type, std::move(elements_kinds), a.ContextInput());

  return ReplaceWithSubgraph(&a, length);
}

Reduction JSCallReducer::ReduceArrayBufferViewByteOffsetAccessor(
    Node* node, InstanceType instance_type, Builtin builtin) {
  // TODO(v8:11111): Optimize for JS_RAB_GSAB_DATA_VIEW_TYPE too.
  DCHECK(instance_type == JS_TYPED_ARRAY_TYPE ||
         instance_type == JS_DATA_VIEW_TYPE);
  Node* receiver = NodeProperties::GetValueInput(node, 1);
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() ||
      !inference.AllOfInstanceTypesAre(instance_type)) {
    return inference.NoChange();
  }

  std::set<ElementsKind> elements_kinds;
  bool maybe_rab_gsab = false;
  if (instance_type == JS_TYPED_ARRAY_TYPE) {
    for (MapRef map : inference.GetMaps()) {
      ElementsKind kind = map.elements_kind();
      elements_kinds.insert(kind);
      if (IsRabGsabTypedArrayElementsKind(kind)) maybe_rab_gsab = true;
    }
  }

  if (!maybe_rab_gsab) {
    // We do not perform any change depending on this inference.
    Reduction unused_reduction = inference.NoChange();
    USE(unused_reduction);
    // Call default implementation for non-rab/gsab TAs.
    return ReduceArrayBufferViewAccessor(
        node, instance_type, AccessBuilder::ForJSArrayBufferViewByteOffset(),
        builtin);
  }

  // TODO(v8:11111): Optimize for RAG/GSAB TypedArray/DataView.
  return inference.NoChange();
}

Reduction JSCallReducer::ReduceTypedArrayPrototypeLength(Node* node) {
  Node* receiver = NodeProperties::GetValueInput(node, 1);
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() ||
      !inference.AllOfInstanceTypesAre(JS_TYPED_ARRAY_TYPE)) {
    return inference.NoChange();
  }

  std::set<ElementsKind> elements_kinds;
  bool maybe_rab_gsab = false;
  for (MapRef map : inference.GetMaps
Prompt: 
```
这是目录为v8/src/compiler/js-call-reducer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-call-reducer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第10部分，共12部分，请归纳一下它的功能

"""
 Control control = n.control();
  Node* receiver = effect = graph()->NewNode(
      simplified()->CheckString(p.feedback()), n.receiver(), effect, control);

  if (parameter_count == 0) {
    ReplaceWithValue(node, receiver, effect, control);
    return Replace(receiver);
  }

  Node* argument = effect = graph()->NewNode(
      simplified()->CheckString(p.feedback()), n.Argument(0), effect, control);
  Node* receiver_length =
      graph()->NewNode(simplified()->StringLength(), receiver);
  Node* argument_length =
      graph()->NewNode(simplified()->StringLength(), argument);
  Node* length = graph()->NewNode(simplified()->NumberAdd(), receiver_length,
                                  argument_length);
  length = effect = graph()->NewNode(
      simplified()->CheckBounds(p.feedback()), length,
      jsgraph()->ConstantNoHole(String::kMaxLength + 1), effect, control);

  Node* value = graph()->NewNode(simplified()->StringConcat(), length, receiver,
                                 argument);

  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

namespace {

FrameState CreateStringCreateLazyDeoptContinuationFrameState(
    JSGraph* graph, SharedFunctionInfoRef shared, Node* target, Node* context,
    Node* outer_frame_state) {
  Node* const receiver = graph->TheHoleConstant();
  Node* stack_parameters[]{receiver};
  const int stack_parameter_count = arraysize(stack_parameters);
  return CreateJavaScriptBuiltinContinuationFrameState(
      graph, shared, Builtin::kStringCreateLazyDeoptContinuation, target,
      context, stack_parameters, stack_parameter_count, outer_frame_state,
      ContinuationFrameStateMode::LAZY);
}

}  // namespace

Reduction JSCallReducer::ReduceStringConstructor(Node* node,
                                                 JSFunctionRef constructor) {
  JSConstructNode n(node);
  if (n.target() != n.new_target()) return NoChange();

  DCHECK_EQ(constructor, native_context().string_function(broker_));
  DCHECK(constructor.initial_map(broker_).IsJSPrimitiveWrapperMap());

  Node* context = n.context();
  FrameState frame_state = n.frame_state();
  Effect effect = n.effect();
  Control control = n.control();

  Node* primitive_value;
  if (n.ArgumentCount() == 0) {
    primitive_value = jsgraph()->EmptyStringConstant();
  } else {
    // Insert a construct stub frame into the chain of frame states. This will
    // reconstruct the proper frame when deoptimizing within the constructor.
    frame_state = CreateConstructInvokeStubFrameState(
        node, frame_state, constructor.shared(broker_), context, common(),
        graph());

    // This continuation takes the newly created primitive string, and wraps it
    // in a string wrapper, matching CreateStringWrapper.
    Node* continuation_frame_state =
        CreateStringCreateLazyDeoptContinuationFrameState(
            jsgraph(), constructor.shared(broker_), n.target(), context,
            frame_state);

    primitive_value = effect = control =
        graph()->NewNode(javascript()->ToString(), n.Argument(0), context,
                         continuation_frame_state, effect, control);

    // Rewire potential exception edges.
    Node* on_exception = nullptr;
    if (NodeProperties::IsExceptionalCall(node, &on_exception)) {
      // Create appropriate {IfException} and {IfSuccess} nodes.
      Node* if_exception =
          graph()->NewNode(common()->IfException(), effect, control);
      control = graph()->NewNode(common()->IfSuccess(), control);

      // Join the exception edges.
      Node* merge =
          graph()->NewNode(common()->Merge(2), if_exception, on_exception);
      Node* ephi = graph()->NewNode(common()->EffectPhi(2), if_exception,
                                    on_exception, merge);
      Node* phi =
          graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                           if_exception, on_exception, merge);
      ReplaceWithValue(on_exception, phi, ephi, merge);
      merge->ReplaceInput(1, on_exception);
      ephi->ReplaceInput(1, on_exception);
      phi->ReplaceInput(1, on_exception);
    }
  }

  RelaxControls(node, control);
  node->ReplaceInput(0, primitive_value);
  node->ReplaceInput(1, context);
  node->ReplaceInput(2, effect);
  node->TrimInputCount(3);
  NodeProperties::ChangeOp(node, javascript()->CreateStringWrapper());
  return Changed(node);
}

Reduction JSCallReducer::ReducePromiseConstructor(Node* node) {
  PromiseBuiltinReducerAssembler a(this, node);

  // We only inline when we have the executor.
  if (a.ConstructArity() < 1) return NoChange();
  // Only handle builtins Promises, not subclasses.
  if (a.TargetInput() != a.NewTargetInput()) return NoChange();
  if (!dependencies()->DependOnPromiseHookProtector()) return NoChange();

  TNode<Object> subgraph = a.ReducePromiseConstructor(native_context());
  return ReplaceWithSubgraph(&a, subgraph);
}

bool JSCallReducer::DoPromiseChecks(MapInference* inference) {
  if (!inference->HaveMaps()) return false;
  ZoneRefSet<Map> const& receiver_maps = inference->GetMaps();

  // Check whether all {receiver_maps} are JSPromise maps and
  // have the initial Promise.prototype as their [[Prototype]].
  for (MapRef receiver_map : receiver_maps) {
    if (!receiver_map.IsJSPromiseMap()) return false;
    HeapObjectRef prototype = receiver_map.prototype(broker());
    if (!prototype.equals(native_context().promise_prototype(broker()))) {
      return false;
    }
  }

  return true;
}

// ES section #sec-promise.prototype.catch
Reduction JSCallReducer::ReducePromisePrototypeCatch(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }
  int arity = p.arity_without_implicit_args();
  Node* receiver = n.receiver();
  Effect effect = n.effect();
  Control control = n.control();

  MapInference inference(broker(), receiver, effect);
  if (!DoPromiseChecks(&inference)) return inference.NoChange();

  if (!dependencies()->DependOnPromiseThenProtector()) {
    return inference.NoChange();
  }
  inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                      control, p.feedback());

  // Massage the {node} to call "then" instead by first removing all inputs
  // following the onRejected parameter, and then filling up the parameters
  // to two inputs from the left with undefined.
  Node* target = jsgraph()->ConstantNoHole(
      native_context().promise_then(broker()), broker());
  NodeProperties::ReplaceValueInput(node, target, 0);
  NodeProperties::ReplaceEffectInput(node, effect);
  for (; arity > 1; --arity) node->RemoveInput(3);
  for (; arity < 2; ++arity) {
    node->InsertInput(graph()->zone(), 2, jsgraph()->UndefinedConstant());
  }
  NodeProperties::ChangeOp(
      node, javascript()->Call(
                JSCallNode::ArityForArgc(arity), p.frequency(), p.feedback(),
                ConvertReceiverMode::kNotNullOrUndefined, p.speculation_mode(),
                CallFeedbackRelation::kUnrelated));
  return Changed(node).FollowedBy(ReducePromisePrototypeThen(node));
}

Node* JSCallReducer::CreateClosureFromBuiltinSharedFunctionInfo(
    SharedFunctionInfoRef shared, Node* context, Node* effect, Node* control) {
  DCHECK(shared.HasBuiltinId());
  Handle<FeedbackCell> feedback_cell =
      isolate()->factory()->many_closures_cell();
  Callable const callable =
      Builtins::CallableFor(isolate(), shared.builtin_id());
  CodeRef code = MakeRef(broker(), *callable.code());
  return graph()->NewNode(javascript()->CreateClosure(shared, code),
                          jsgraph()->HeapConstantNoHole(feedback_cell), context,
                          effect, control);
}

// ES section #sec-promise.prototype.finally
Reduction JSCallReducer::ReducePromisePrototypeFinally(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  int arity = p.arity_without_implicit_args();
  Node* receiver = n.receiver();
  Node* on_finally = n.ArgumentOrUndefined(0, jsgraph());
  Effect effect = n.effect();
  Control control = n.control();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  MapInference inference(broker(), receiver, effect);
  if (!DoPromiseChecks(&inference)) return inference.NoChange();
  ZoneRefSet<Map> const& receiver_maps = inference.GetMaps();

  if (!dependencies()->DependOnPromiseHookProtector()) {
    return inference.NoChange();
  }
  if (!dependencies()->DependOnPromiseThenProtector()) {
    return inference.NoChange();
  }
  if (!dependencies()->DependOnPromiseSpeciesProtector()) {
    return inference.NoChange();
  }
  inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                      control, p.feedback());

  // Check if {on_finally} is callable, and if so wrap it into appropriate
  // closures that perform the finalization.
  Node* check = graph()->NewNode(simplified()->ObjectIsCallable(), on_finally);
  Node* branch =
      graph()->NewNode(common()->Branch(BranchHint::kTrue), check, control);

  Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
  Node* etrue = effect;
  Node* catch_true;
  Node* then_true;
  {
    Node* context = jsgraph()->ConstantNoHole(native_context(), broker());
    Node* constructor = jsgraph()->ConstantNoHole(
        native_context().promise_function(broker()), broker());

    // Allocate shared context for the closures below.
    context = etrue = graph()->NewNode(
        javascript()->CreateFunctionContext(
            native_context().scope_info(broker()),
            int{PromiseBuiltins::kPromiseFinallyContextLength} -
                Context::MIN_CONTEXT_SLOTS,
            FUNCTION_SCOPE),
        context, etrue, if_true);
    etrue = graph()->NewNode(
        simplified()->StoreField(
            AccessBuilder::ForContextSlot(PromiseBuiltins::kOnFinallySlot)),
        context, on_finally, etrue, if_true);
    etrue = graph()->NewNode(
        simplified()->StoreField(
            AccessBuilder::ForContextSlot(PromiseBuiltins::kConstructorSlot)),
        context, constructor, etrue, if_true);

    // Allocate the closure for the reject case.
    SharedFunctionInfoRef promise_catch_finally =
        MakeRef(broker(), factory()->promise_catch_finally_shared_fun());
    catch_true = etrue = CreateClosureFromBuiltinSharedFunctionInfo(
        promise_catch_finally, context, etrue, if_true);

    // Allocate the closure for the fulfill case.
    SharedFunctionInfoRef promise_then_finally =
        MakeRef(broker(), factory()->promise_then_finally_shared_fun());
    then_true = etrue = CreateClosureFromBuiltinSharedFunctionInfo(
        promise_then_finally, context, etrue, if_true);
  }

  Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
  Node* efalse = effect;
  Node* catch_false = on_finally;
  Node* then_false = on_finally;

  control = graph()->NewNode(common()->Merge(2), if_true, if_false);
  effect = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);
  Node* catch_finally =
      graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                       catch_true, catch_false, control);
  Node* then_finally =
      graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                       then_true, then_false, control);

  // At this point we definitely know that {receiver} has one of the
  // {receiver_maps}, so insert a MapGuard as a hint for the lowering
  // of the call to "then" below.
  {
    effect = graph()->NewNode(simplified()->MapGuard(receiver_maps), receiver,
                              effect, control);
  }

  // Massage the {node} to call "then" instead by first removing all inputs
  // following the onFinally parameter, and then replacing the only parameter
  // input with the {on_finally} value.
  Node* target = jsgraph()->ConstantNoHole(
      native_context().promise_then(broker()), broker());
  NodeProperties::ReplaceValueInput(node, target, n.TargetIndex());
  NodeProperties::ReplaceEffectInput(node, effect);
  NodeProperties::ReplaceControlInput(node, control);
  for (; arity > 2; --arity) node->RemoveInput(2);
  for (; arity < 2; ++arity) {
    node->InsertInput(graph()->zone(), 2, then_finally);
  }
  node->ReplaceInput(2, then_finally);
  node->ReplaceInput(3, catch_finally);
  NodeProperties::ChangeOp(
      node, javascript()->Call(
                JSCallNode::ArityForArgc(arity), p.frequency(), p.feedback(),
                ConvertReceiverMode::kNotNullOrUndefined, p.speculation_mode(),
                CallFeedbackRelation::kUnrelated));
  return Changed(node).FollowedBy(ReducePromisePrototypeThen(node));
}

Reduction JSCallReducer::ReducePromisePrototypeThen(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Node* receiver = n.receiver();
  Node* on_fulfilled = n.ArgumentOrUndefined(0, jsgraph());
  Node* on_rejected = n.ArgumentOrUndefined(1, jsgraph());
  Node* context = n.context();
  Effect effect = n.effect();
  Control control = n.control();
  FrameState frame_state = n.frame_state();

  MapInference inference(broker(), receiver, effect);
  if (!DoPromiseChecks(&inference)) return inference.NoChange();

  if (!dependencies()->DependOnPromiseHookProtector()) {
    return inference.NoChange();
  }
  if (!dependencies()->DependOnPromiseSpeciesProtector()) {
    return inference.NoChange();
  }
  inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                      control, p.feedback());

  // Check that {on_fulfilled} is callable.
  on_fulfilled = graph()->NewNode(
      common()->Select(MachineRepresentation::kTagged, BranchHint::kTrue),
      graph()->NewNode(simplified()->ObjectIsCallable(), on_fulfilled),
      on_fulfilled, jsgraph()->UndefinedConstant());

  // Check that {on_rejected} is callable.
  on_rejected = graph()->NewNode(
      common()->Select(MachineRepresentation::kTagged, BranchHint::kTrue),
      graph()->NewNode(simplified()->ObjectIsCallable(), on_rejected),
      on_rejected, jsgraph()->UndefinedConstant());

  // Create the resulting JSPromise.
  Node* promise = effect =
      graph()->NewNode(javascript()->CreatePromise(), context, effect);

  // Chain {result} onto {receiver}.
  promise = effect = graph()->NewNode(
      javascript()->PerformPromiseThen(), receiver, on_fulfilled, on_rejected,
      promise, context, frame_state, effect, control);

  // At this point we know that {promise} is going to have the
  // initial Promise map, since even if {PerformPromiseThen}
  // above called into the host rejection tracker, the {promise}
  // doesn't escape to user JavaScript. So bake this information
  // into the graph such that subsequent passes can use the
  // information for further optimizations.
  MapRef promise_map =
      native_context().promise_function(broker()).initial_map(broker());
  effect =
      graph()->NewNode(simplified()->MapGuard(ZoneRefSet<Map>(promise_map)),
                       promise, effect, control);

  ReplaceWithValue(node, promise, effect, control);
  return Replace(promise);
}

// ES section #sec-promise.resolve
Reduction JSCallReducer::ReducePromiseResolveTrampoline(Node* node) {
  JSCallNode n(node);
  Node* receiver = n.receiver();
  Node* value = n.ArgumentOrUndefined(0, jsgraph());
  Node* context = n.context();
  Effect effect = n.effect();
  Control control = n.control();
  FrameState frame_state = n.frame_state();

  // Only reduce when the receiver is guaranteed to be a JSReceiver.
  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() || !inference.AllOfInstanceTypesAreJSReceiver()) {
    return NoChange();
  }

  // Morph the {node} into a JSPromiseResolve operation.
  node->ReplaceInput(0, receiver);
  node->ReplaceInput(1, value);
  node->ReplaceInput(2, context);
  node->ReplaceInput(3, frame_state);
  node->ReplaceInput(4, effect);
  node->ReplaceInput(5, control);
  node->TrimInputCount(6);
  NodeProperties::ChangeOp(node, javascript()->PromiseResolve());
  return Changed(node);
}

// ES #sec-typedarray-constructors
Reduction JSCallReducer::ReduceTypedArrayConstructor(
    Node* node, SharedFunctionInfoRef shared) {
  JSConstructNode n(node);
  Node* target = n.target();
  Node* arg0 = n.ArgumentOrUndefined(0, jsgraph());
  Node* arg1 = n.ArgumentOrUndefined(1, jsgraph());
  Node* arg2 = n.ArgumentOrUndefined(2, jsgraph());
  Node* new_target = n.new_target();
  Node* context = n.context();
  FrameState frame_state = n.frame_state();
  Effect effect = n.effect();
  Control control = n.control();

  // Insert a construct stub frame into the chain of frame states. This will
  // reconstruct the proper frame when deoptimizing within the constructor.
  frame_state = CreateConstructInvokeStubFrameState(node, frame_state, shared,
                                                    context, common(), graph());

  // This continuation just returns the newly created JSTypedArray. We
  // pass the_hole as the receiver, just like the builtin construct stub
  // does in this case.
  Node* const receiver = jsgraph()->TheHoleConstant();
  Node* continuation_frame_state = CreateGenericLazyDeoptContinuationFrameState(
      jsgraph(), shared, target, context, receiver, frame_state);

  Node* result = graph()->NewNode(javascript()->CreateTypedArray(), target,
                                  new_target, arg0, arg1, arg2, context,
                                  continuation_frame_state, effect, control);
  return Replace(result);
}

// ES #sec-get-%typedarray%.prototype-@@tostringtag
Reduction JSCallReducer::ReduceTypedArrayPrototypeToStringTag(Node* node) {
  Node* receiver = NodeProperties::GetValueInput(node, 1);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  NodeVector values(graph()->zone());
  NodeVector effects(graph()->zone());
  NodeVector controls(graph()->zone());

  Node* smi_check = graph()->NewNode(simplified()->ObjectIsSmi(), receiver);
  control = graph()->NewNode(common()->Branch(BranchHint::kFalse), smi_check,
                             control);

  values.push_back(jsgraph()->UndefinedConstant());
  effects.push_back(effect);
  controls.push_back(graph()->NewNode(common()->IfTrue(), control));

  control = graph()->NewNode(common()->IfFalse(), control);
  Node* receiver_map = effect =
      graph()->NewNode(simplified()->LoadField(AccessBuilder::ForMap()),
                       receiver, effect, control);
  Node* receiver_bit_field2 = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForMapBitField2()), receiver_map,
      effect, control);
  Node* receiver_elements_kind = graph()->NewNode(
      simplified()->NumberShiftRightLogical(),
      graph()->NewNode(
          simplified()->NumberBitwiseAnd(), receiver_bit_field2,
          jsgraph()->ConstantNoHole(Map::Bits2::ElementsKindBits::kMask)),
      jsgraph()->ConstantNoHole(Map::Bits2::ElementsKindBits::kShift));

  // Offset the elements kind by FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND,
  // so that the branch cascade below is turned into a simple table
  // switch by the ControlFlowOptimizer later.
  receiver_elements_kind = graph()->NewNode(
      simplified()->NumberSubtract(), receiver_elements_kind,
      jsgraph()->ConstantNoHole(FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND));

  // To be converted into a switch by the ControlFlowOptimizer, the below
  // code requires that TYPED_ARRAYS and RAB_GSAB_TYPED_ARRAYS are consecutive.
  static_assert(LAST_FIXED_TYPED_ARRAY_ELEMENTS_KIND + 1 ==
                FIRST_RAB_GSAB_FIXED_TYPED_ARRAY_ELEMENTS_KIND);
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype)                          \
  do {                                                                     \
    Node* check = graph()->NewNode(                                        \
        simplified()->NumberEqual(), receiver_elements_kind,               \
        jsgraph()->ConstantNoHole(TYPE##_ELEMENTS -                        \
                                  FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND)); \
    control = graph()->NewNode(common()->Branch(), check, control);        \
    values.push_back(jsgraph()->ConstantNoHole(                            \
        broker()->GetTypedArrayStringTag(TYPE##_ELEMENTS), broker()));     \
    effects.push_back(effect);                                             \
    controls.push_back(graph()->NewNode(common()->IfTrue(), control));     \
    control = graph()->NewNode(common()->IfFalse(), control);              \
  } while (false);
  TYPED_ARRAYS(TYPED_ARRAY_CASE)
  RAB_GSAB_TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE

  values.push_back(jsgraph()->UndefinedConstant());
  effects.push_back(effect);
  controls.push_back(control);

  int const count = static_cast<int>(controls.size());
  control = graph()->NewNode(common()->Merge(count), count, &controls.front());
  effects.push_back(control);
  effect =
      graph()->NewNode(common()->EffectPhi(count), count + 1, &effects.front());
  values.push_back(control);
  Node* value =
      graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, count),
                       count + 1, &values.front());
  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

Reduction JSCallReducer::ReduceArrayBufferViewByteLengthAccessor(
    Node* node, InstanceType instance_type, Builtin builtin) {
  // TODO(v8:11111): Optimize for JS_RAB_GSAB_DATA_VIEW_TYPE too.
  DCHECK(instance_type == JS_TYPED_ARRAY_TYPE ||
         instance_type == JS_DATA_VIEW_TYPE);
  Node* receiver = NodeProperties::GetValueInput(node, 1);
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() ||
      !inference.AllOfInstanceTypesAre(instance_type)) {
    return inference.NoChange();
  }

  std::set<ElementsKind> elements_kinds;
  bool maybe_rab_gsab = false;
  if (instance_type == JS_TYPED_ARRAY_TYPE) {
    for (MapRef map : inference.GetMaps()) {
      ElementsKind kind = map.elements_kind();
      elements_kinds.insert(kind);
      if (IsRabGsabTypedArrayElementsKind(kind)) maybe_rab_gsab = true;
    }
  }

  if (!maybe_rab_gsab) {
    // We do not perform any change depending on this inference.
    Reduction unused_reduction = inference.NoChange();
    USE(unused_reduction);
    // Call default implementation for non-rab/gsab TAs.
    return ReduceArrayBufferViewAccessor(
        node, instance_type, AccessBuilder::ForJSArrayBufferViewByteLength(),
        builtin);
  }

  const CallParameters& p = CallParametersOf(node->op());
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return inference.NoChange();
  }
  DCHECK(p.feedback().IsValid());

  inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                      control, p.feedback());

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

  JSCallReducerAssembler a(this, node);
  TNode<JSTypedArray> typed_array =
      TNode<JSTypedArray>::UncheckedCast(receiver);
  TNode<Number> length = a.ArrayBufferViewByteLength(
      typed_array, instance_type, std::move(elements_kinds), a.ContextInput());

  return ReplaceWithSubgraph(&a, length);
}

Reduction JSCallReducer::ReduceArrayBufferViewByteOffsetAccessor(
    Node* node, InstanceType instance_type, Builtin builtin) {
  // TODO(v8:11111): Optimize for JS_RAB_GSAB_DATA_VIEW_TYPE too.
  DCHECK(instance_type == JS_TYPED_ARRAY_TYPE ||
         instance_type == JS_DATA_VIEW_TYPE);
  Node* receiver = NodeProperties::GetValueInput(node, 1);
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() ||
      !inference.AllOfInstanceTypesAre(instance_type)) {
    return inference.NoChange();
  }

  std::set<ElementsKind> elements_kinds;
  bool maybe_rab_gsab = false;
  if (instance_type == JS_TYPED_ARRAY_TYPE) {
    for (MapRef map : inference.GetMaps()) {
      ElementsKind kind = map.elements_kind();
      elements_kinds.insert(kind);
      if (IsRabGsabTypedArrayElementsKind(kind)) maybe_rab_gsab = true;
    }
  }

  if (!maybe_rab_gsab) {
    // We do not perform any change depending on this inference.
    Reduction unused_reduction = inference.NoChange();
    USE(unused_reduction);
    // Call default implementation for non-rab/gsab TAs.
    return ReduceArrayBufferViewAccessor(
        node, instance_type, AccessBuilder::ForJSArrayBufferViewByteOffset(),
        builtin);
  }

  // TODO(v8:11111): Optimize for RAG/GSAB TypedArray/DataView.
  return inference.NoChange();
}

Reduction JSCallReducer::ReduceTypedArrayPrototypeLength(Node* node) {
  Node* receiver = NodeProperties::GetValueInput(node, 1);
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() ||
      !inference.AllOfInstanceTypesAre(JS_TYPED_ARRAY_TYPE)) {
    return inference.NoChange();
  }

  std::set<ElementsKind> elements_kinds;
  bool maybe_rab_gsab = false;
  for (MapRef map : inference.GetMaps()) {
    ElementsKind kind = map.elements_kind();
    elements_kinds.insert(kind);
    if (IsRabGsabTypedArrayElementsKind(kind)) maybe_rab_gsab = true;
  }

  if (!maybe_rab_gsab) {
    // We do not perform any change depending on this inference.
    Reduction unused_reduction = inference.NoChange();
    USE(unused_reduction);
    // Call default implementation for non-rab/gsab TAs.
    return ReduceArrayBufferViewAccessor(node, JS_TYPED_ARRAY_TYPE,
                                         AccessBuilder::ForJSTypedArrayLength(),
                                         Builtin::kTypedArrayPrototypeLength);
  }

  if (!inference.RelyOnMapsViaStability(dependencies())) {
    return inference.NoChange();
  }

  JSCallReducerAssembler a(this, node);
  TNode<JSTypedArray> typed_array =
      TNode<JSTypedArray>::UncheckedCast(receiver);
  TNode<Number> length = a.TypedArrayLength(
      typed_array, std::move(elements_kinds), a.ContextInput());

  return ReplaceWithSubgraph(&a, length);
}

// ES #sec-number.isfinite
Reduction JSCallReducer::ReduceNumberIsFinite(Node* node) {
  JSCallNode n(node);
  if (n.ArgumentCount() < 1) {
    Node* value = jsgraph()->FalseConstant();
    ReplaceWithValue(node, value);
    return Replace(value);
  }
  Node* input = n.Argument(0);
  Node* value = graph()->NewNode(simplified()->ObjectIsFiniteNumber(), input);
  ReplaceWithValue(node, value);
  return Replace(value);
}

// ES #sec-number.isfinite
Reduction JSCallReducer::ReduceNumberIsInteger(Node* node) {
  JSCallNode n(node);
  if (n.ArgumentCount() < 1) {
    Node* value = jsgraph()->FalseConstant();
    ReplaceWithValue(node, value);
    return Replace(value);
  }
  Node* input = n.Argument(0);
  Node* value = graph()->NewNode(simplified()->ObjectIsInteger(), input);
  ReplaceWithValue(node, value);
  return Replace(value);
}

// ES #sec-number.issafeinteger
Reduction JSCallReducer::ReduceNumberIsSafeInteger(Node* node) {
  JSCallNode n(node);
  if (n.ArgumentCount() < 1) {
    Node* value = jsgraph()->FalseConstant();
    ReplaceWithValue(node, value);
    return Replace(value);
  }
  Node* input = n.Argument(0);
  Node* value = graph()->NewNode(simplified()->ObjectIsSafeInteger(), input);
  ReplaceWithValue(node, value);
  return Replace(value);
}

// ES #sec-number.isnan
Reduction JSCallReducer::ReduceNumberIsNaN(Node* node) {
  JSCallNode n(node);
  if (n.ArgumentCount() < 1) {
    Node* value = jsgraph()->FalseConstant();
    ReplaceWithValue(node, value);
    return Replace(value);
  }
  Node* input = n.Argument(0);
  Node* value = graph()->NewNode(simplified()->ObjectIsNaN(), input);
  ReplaceWithValue(node, value);
  return Replace(value);
}

Reduction JSCallReducer::ReduceMapPrototypeGet(Node* node) {
  // We only optimize if we have target, receiver and key parameters.
  JSCallNode n(node);
  if (n.ArgumentCount() != 1) return NoChange();
  Node* receiver = NodeProperties::GetValueInput(node, 1);
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};
  Node* key = NodeProperties::GetValueInput(node, 2);

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() || !inference.AllOfInstanceTypesAre(JS_MAP_TYPE)) {
    return NoChange();
  }

  Node* table = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForJSCollectionTable()), receiver,
      effect, control);

  Node* entry = effect = graph()->NewNode(
      simplified()->FindOrderedCollectionEntry(CollectionKind::kMap), table,
      key, effect, control);

  Node* check = graph()->NewNode(simplified()->NumberEqual(), entry,
                                 jsgraph()->MinusOneConstant());

  Node* branch = graph()->NewNode(common()->Branch(), check, control);

  // Key not found.
  Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
  Node* etrue = effect;
  Node* vtrue = jsgraph()->UndefinedConstant();

  // Key found.
  Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
  Node* efalse = effect;
  Node* vfalse = efalse = graph()->NewNode(
      simplified()->LoadElement(AccessBuilder::ForOrderedHashMapEntryValue()),
      table, entry, efalse, if_false);

  control = graph()->NewNode(common()->Merge(2), if_true, if_false);
  Node* value = graph()->NewNode(
      common()->Phi(MachineRepresentation::kTagged, 2), vtrue, vfalse, control);
  effect = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);

  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

namespace {

InstanceType InstanceTypeForCollectionKind(CollectionKind kind) {
  switch (kind) {
    case CollectionKind::kMap:
      return JS_MAP_TYPE;
    case CollectionKind::kSet:
      return JS_SET_TYPE;
  }
  UNREACHABLE();
}

}  // namespace

Reduction JSCallReducer::ReduceCollectionPrototypeHas(
    Node* node, CollectionKind collection_kind) {
  // We only optimize if we have target, receiver and key parameters.
  JSCallNode n(node);
  if (n.ArgumentCount() != 1) return NoChange();
  Node* receiver = NodeProperties::GetValueInput(node, 1);
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};
  Node* key = NodeProperties::GetValueInput(node, 2);
  InstanceType instance_type = InstanceTypeForCollectionKind(collection_kind);

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() ||
      !inference.AllOfInstanceTypesAre(instance_type)) {
    return NoChange();
  }

  Node* table = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForJSCollectionTable()), receiver,
      effect, control);

  Node* index = effect = graph()->NewNode(
      simplified()->FindOrderedCollectionEntry(collection_kind), table, key,
      effect, control);

  Node* value = graph()->NewNode(simplified()->NumberEqual(), index,
                                 jsgraph()->MinusOneConstant());
  value = graph()->NewNode(simplified()->BooleanNot(), value);

  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

Reduction JSCallReducer::ReduceMapPrototypeHas(Node* node) {
  return ReduceCollectionPrototypeHas(node, CollectionKind::kMap);
}

Reduction JSCallReducer::ReduceSetPrototypeHas(Node* node) {
  return ReduceCollectionPrototypeHas(node, CollectionKind::kSet);
}

Reduction JSCallReducer::ReduceCollectionIteration(
    Node* node, CollectionKind collection_kind, IterationKind iteration_kind) {
  DCHECK_EQ(IrOpcode::kJSCall, node->opcode());
  Node* receiver = NodeProperties::GetValueInput(node, 1);
  Node* context = NodeProperties::GetContextInput(node);
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};

  InstanceType type = InstanceType
"""


```