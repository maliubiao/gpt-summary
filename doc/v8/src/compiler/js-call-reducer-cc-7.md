Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/js-call-reducer.cc`. The summary should include:

1. **General Functionality:** What does this code do?
2. **Torque Source:** Check if the filename ends with `.tq`.
3. **JavaScript Relation:** If the code relates to JavaScript functionality, provide JavaScript examples.
4. **Code Logic Inference:** Provide examples of input and output based on the code's logic.
5. **Common Programming Errors:**  Illustrate potential user errors related to this code.
6. **Overall Functionality (Part 8 of 12):**  A high-level summary considering this is part of a larger piece of code.

Let's break down the code:

* **`ReduceJSConstruct` for bound functions:** This handles calls to `new` on bound functions, inserting bound arguments.
* **`ReduceStringPrototypeIndexOfIncludes`:** This optimizes calls to `String.prototype.indexOf` and `String.prototype.includes` by converting them to a simpler `StringIndexOf` operation. It also handles type checking and position arguments.
* **`ReduceStringPrototypeSubstring`, `ReduceStringPrototypeSlice`, `ReduceStringPrototypeSubstr`:** These seem to handle the optimization of string manipulation methods, likely delegating to an assembler class.
* **`ReduceJSConstructWithArrayLike`, `ReduceJSConstructWithSpread`:** These functions handle the `new` operator with array-like objects or spread syntax, likely converting them into more efficient operations.
* **`ReduceJSConstructForwardAllArgs`:** This handles forwarding arguments in constructor calls within inlined functions.
* **`ReduceReturnReceiver`:**  This seems to optimize cases where a function simply returns its receiver.
* **`ReduceForInsufficientFeedback`:** This introduces deoptimization if there isn't enough feedback for optimization.
* **Helper functions (`LoadReceiverElementsKind`, `CheckIfElementsKind`):** These are utilities for checking the internal representation of arrays.
* **`ReduceArrayPrototypeAt`:** Optimizes `Array.prototype.at` using knowledge of array maps and elements kinds.
* **`ReduceArrayPrototypePush`:** Optimizes `Array.prototype.push`, handling different array element kinds.
* **`ReduceArrayPrototypePop`:** Optimizes `Array.prototype.pop`, including fast-path for small arrays and handling different element kinds.
* **`ReduceArrayPrototypeShift`:** Optimizes `Array.prototype.shift`, also with a fast-path and handling different element kinds.

**Plan:**

1. State the primary function of `js-call-reducer.cc`: optimizing JavaScript calls and constructor invocations.
2. Confirm that the file is not a Torque file.
3. Provide JavaScript examples for `bind`, `indexOf`, `includes`, `substring`, `slice`, `substr`, constructor calls with array-like/spread, `Array.prototype.at`, `push`, `pop`, and `shift`.
4. Give examples of input and output for `String.prototype.indexOf` and `Array.prototype.push`.
5. Illustrate common errors like incorrect argument types for string methods and using `shift` on very large arrays.
6. Summarize the role of this part in the overall call reduction process, focusing on string and array built-in optimizations and handling constructor variations.
```cpp
   } else {
      node->ReplaceInput(
          n.NewTargetIndex(),
          graph()->NewNode(common()->Select(MachineRepresentation::kTagged),
                           graph()->NewNode(simplified()->ReferenceEqual(),
                                            target, new_target),
                           bound_target_function, new_target));
    }

    // Insert the [[BoundArguments]] for {node}.
    for (uint32_t i = 0; i < bound_arguments_length; ++i) {
      Node* value = NodeProperties::GetValueInput(target, 2 + i);
      node->InsertInput(graph()->zone(), n.ArgumentIndex(i), value);
      arity++;
    }

    // Update the JSConstruct operator on {node}.
    NodeProperties::ChangeOp(
        node, javascript()->Construct(JSConstructNode::ArityForArgc(arity),
                                      p.frequency(), FeedbackSource()));

    // Try to further reduce the JSConstruct {node}.
    return Changed(node).FollowedBy(ReduceJSConstruct(node));
  }

  return NoChange();
}

// ES #sec-string.prototype.indexof
// ES #sec-string.prototype.includes
Reduction JSCallReducer::ReduceStringPrototypeIndexOfIncludes(
    Node* node, StringIndexOfIncludesVariant variant) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Effect effect = n.effect();
  Control control = n.control();
  if (n.ArgumentCount() > 0) {
    Node* receiver = n.receiver();
    Node* new_receiver = effect = graph()->NewNode(
        simplified()->CheckString(p.feedback()), receiver, effect, control);

    Node* search_string = n.Argument(0);
    Node* new_search_string = effect =
        graph()->NewNode(simplified()->CheckString(p.feedback()), search_string,
                         effect, control);

    Node* new_position = jsgraph()->ZeroConstant();
    if (n.ArgumentCount() > 1) {
      Node* position = n.Argument(1);
      new_position = effect = graph()->NewNode(
          simplified()->CheckSmi(p.feedback()), position, effect, control);

      Node* receiver_length =
          graph()->NewNode(simplified()->StringLength(), new_receiver);
      new_position = graph()->NewNode(
          simplified()->NumberMin(),
          graph()->NewNode(simplified()->NumberMax(), new_position,
                           jsgraph()->ZeroConstant()),
          receiver_length);
    }

    NodeProperties::ReplaceEffectInput(node, effect);
    RelaxEffectsAndControls(node);
    node->ReplaceInput(0, new_receiver);
    node->ReplaceInput(1, new_search_string);
    node->ReplaceInput(2, new_position);
    node->TrimInputCount(3);
    NodeProperties::ChangeOp(node, simplified()->StringIndexOf());

    if (variant == StringIndexOfIncludesVariant::kIndexOf) {
      return Changed(node);
    } else {
      DCHECK(variant == StringIndexOfIncludesVariant::kIncludes);
      Node* result =
          graph()->NewNode(simplified()->BooleanNot(),
                           graph()->NewNode(simplified()->NumberEqual(), node,
                                            jsgraph()->SmiConstant(-1)));
      return Replace(result);
    }
  }
  return NoChange();
}

// ES #sec-string.prototype.substring
Reduction JSCallReducer::ReduceStringPrototypeSubstring(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (n.ArgumentCount() < 1) return NoChange();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  JSCallReducerAssembler a(this, node);
  Node* subgraph = a.ReduceStringPrototypeSubstring();
  return ReplaceWithSubgraph(&a, subgraph);
}

// ES #sec-string.prototype.slice
Reduction JSCallReducer::ReduceStringPrototypeSlice(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (n.ArgumentCount() < 1) return NoChange();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  JSCallReducerAssembler a(this, node);
  Node* subgraph = a.ReduceStringPrototypeSlice();
  return ReplaceWithSubgraph(&a, subgraph);
}

// ES #sec-string.prototype.substr
Reduction JSCallReducer::ReduceStringPrototypeSubstr(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (n.ArgumentCount() < 1) return NoChange();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Effect effect = n.effect();
  Control control = n.control();
  Node* receiver = n.receiver();
  Node* start = n.Argument(0);
  Node* end = n.ArgumentOrUndefined(1, jsgraph());

  receiver = effect = graph()->NewNode(simplified()->CheckString(p.feedback()),
                                       receiver, effect, control);

  start = effect = graph()->NewNode(simplified()->CheckSmi(p.feedback()), start,
                                    effect, control);

  Node* length = graph()->NewNode(simplified()->StringLength(), receiver);

  // Replace {end} argument with {length} if it is undefined.
  {
    Node* check = graph()->NewNode(simplified()->ReferenceEqual(), end,
                                   jsgraph()->UndefinedConstant());
    Node* branch =
        graph()->NewNode(common()->Branch(BranchHint::kFalse), check, control);

    Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
    Node* etrue = effect;
    Node* vtrue = length;

    Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
    Node* efalse = effect;
    Node* vfalse = efalse = graph()->NewNode(
        simplified()->CheckSmi(p.feedback()), end, efalse, if_false);

    control = graph()->NewNode(common()->Merge(2), if_true, if_false);
    effect = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);
    end = graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                           vtrue, vfalse, control);
  }

  Node* initStart = graph()->NewNode(
      common()->Select(MachineRepresentation::kTagged, BranchHint::kFalse),
      graph()->NewNode(simplified()->NumberLessThan(), start,
                       jsgraph()->ZeroConstant()),
      graph()->NewNode(
          simplified()->NumberMax(),
          graph()->NewNode(simplified()->NumberAdd(), length, start),
          jsgraph()->ZeroConstant()),
      start);
  // The select above guarantees that initStart is non-negative, but
  // our typer can't figure that out yet.
  initStart = effect = graph()->NewNode(
      common()->TypeGuard(Type::UnsignedSmall()), initStart, effect, control);

  Node* resultLength = graph()->NewNode(
      simplified()->NumberMin(),
      graph()->NewNode(simplified()->NumberMax(), end,
                       jsgraph()->ZeroConstant()),
      graph()->NewNode(simplified()->NumberSubtract(), length, initStart));

  // The the select below uses {resultLength} only if {resultLength > 0},
  // but our typer can't figure that out yet.
  Node* to = effect = graph()->NewNode(
      common()->TypeGuard(Type::UnsignedSmall()),
      graph()->NewNode(simplified()->NumberAdd(), initStart, resultLength),
      effect, control);

  Node* result_string = nullptr;
  // Return empty string if {from} is smaller than {to}.
  {
    Node* check = graph()->NewNode(simplified()->NumberLessThan(),
                                   jsgraph()->ZeroConstant(), resultLength);

    Node* branch =
        graph()->NewNode(common()->Branch(BranchHint::kTrue), check, control);

    Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
    Node* etrue = effect;
    Node* vtrue = etrue =
        graph()->NewNode(simplified()->StringSubstring(), receiver, initStart,
                         to, etrue, if_true);

    Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
    Node* efalse = effect;
    Node* vfalse = jsgraph()->EmptyStringConstant();

    control = graph()->NewNode(common()->Merge(2), if_true, if_false);
    effect = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);
    result_string =
        graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                         vtrue, vfalse, control);
  }

  ReplaceWithValue(node, result_string, effect, control);
  return Replace(result_string);
}

Reduction JSCallReducer::ReduceJSConstructWithArrayLike(Node* node) {
  JSConstructWithArrayLikeNode n(node);
  ConstructParameters const& p = n.Parameters();
  const int arraylike_index = n.LastArgumentIndex();
  DCHECK_EQ(n.ArgumentCount(), 1);  // The arraylike object.
  return ReduceCallOrConstructWithArrayLikeOrSpread(
      node, n.ArgumentCount(), arraylike_index, p.frequency(), p.feedback(),
      SpeculationMode::kDisallowSpeculation, CallFeedbackRelation::kTarget,
      n.target(), n.effect(), n.control());
}

Reduction JSCallReducer::ReduceJSConstructWithSpread(Node* node) {
  JSConstructWithSpreadNode n(node);
  ConstructParameters const& p = n.Parameters();
  const int spread_index = n.LastArgumentIndex();
  DCHECK_GE(n.ArgumentCount(), 1);  // At least the spread.
  return ReduceCallOrConstructWithArrayLikeOrSpread(
      node, n.ArgumentCount(), spread_index, p.frequency(), p.feedback(),
      SpeculationMode::kDisallowSpeculation, CallFeedbackRelation::kTarget,
      n.target(), n.effect(), n.control());
}

Reduction JSCallReducer::ReduceJSConstructForwardAllArgs(Node* node) {
  JSConstructForwardAllArgsNode n(node);
  DCHECK_EQ(n.ArgumentCount(), 0);

  // If this frame is not being inlined, JSConstructForwardAllArgs will be
  // lowered later in JSGenericLowering to a builtin call.
  FrameState frame_state = n.frame_state();
  if (frame_state.outer_frame_state()->opcode() != IrOpcode::kFrameState) {
    return NoChange();
  }

  // Hook up the arguments directly when forwarding arguments of inlined frames.
  FrameState outer_state{frame_state.outer_frame_state()};
  FrameStateInfo outer_info = outer_state.frame_state_info();
  if (outer_info.type() == FrameStateType::kInlinedExtraArguments) {
    frame_state = outer_state;
  }

  int argc = 0;
  StateValuesAccess parameters_access(frame_state.parameters());
  for (auto it = parameters_access.begin_without_receiver(); !it.done(); ++it) {
    DCHECK_NOT_NULL(it.node());
    node->InsertInput(graph()->zone(),
                      JSCallOrConstructNode::ArgumentIndex(argc++), it.node());
  }

  ConstructParameters const& p = n.Parameters();
  NodeProperties::ChangeOp(
      node, javascript()->Construct(JSConstructNode::ArityForArgc(argc),
                                    p.frequency(), p.feedback()));
  CheckIfConstructor(node);
  return Changed(node).FollowedBy(ReduceJSConstruct(node));
}

Reduction JSCallReducer::ReduceReturnReceiver(Node* node) {
  JSCallNode n(node);
  Node* receiver = n.receiver();
  ReplaceWithValue(node, receiver);
  return Replace(receiver);
}

Reduction JSCallReducer::ReduceForInsufficientFeedback(
    Node* node, DeoptimizeReason reason) {
  DCHECK(node->opcode() == IrOpcode::kJSCall ||
         node->opcode() == IrOpcode::kJSConstruct);
  if (!(flags() & kBailoutOnUninitialized)) return NoChange();

  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  Node* frame_state =
      NodeProperties::FindFrameStateBefore(node, jsgraph()->Dead());
  Node* deoptimize =
      graph()->NewNode(common()->Deoptimize(reason, FeedbackSource()),
                       frame_state, effect, control);
  MergeControlToEnd(graph(), common(), deoptimize);
  node->TrimInputCount(0);
  NodeProperties::ChangeOp(node, common()->Dead());
  return Changed(node);
}

Node* JSCallReducer::LoadReceiverElementsKind(Node* receiver, Effect* effect,
                                              Control control) {
  Node* effect_node = *effect;
  Node* receiver_map = effect_node =
      graph()->NewNode(simplified()->LoadField(AccessBuilder::ForMap()),
                       receiver, effect_node, control);
  Node* receiver_bit_field2 = effect_node = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForMapBitField2()), receiver_map,
      effect_node, control);
  Node* receiver_elements_kind = graph()->NewNode(
      simplified()->NumberShiftRightLogical(),
      graph()->NewNode(
          simplified()->NumberBitwiseAnd(), receiver_bit_field2,
          jsgraph()->ConstantNoHole(Map::Bits2::ElementsKindBits::kMask)),
      jsgraph()->ConstantNoHole(Map::Bits2::ElementsKindBits::kShift));
  *effect = effect_node;
  return receiver_elements_kind;
}

void JSCallReducer::CheckIfElementsKind(Node* receiver_elements_kind,
                                        ElementsKind kind, Node* control,
                                        Node** if_true, Node** if_false) {
  Node* is_packed_kind =
      graph()->NewNode(simplified()->NumberEqual(), receiver_elements_kind,
                       jsgraph()->ConstantNoHole(GetPackedElementsKind(kind)));
  Node* packed_branch =
      graph()->NewNode(common()->Branch(), is_packed_kind, control);
  Node* if_packed = graph()->NewNode(common()->IfTrue(), packed_branch);

  if (IsHoleyElementsKind(kind)) {
    Node* if_not_packed = graph()->NewNode(common()->IfFalse(), packed_branch);
    Node* is_holey_kind =
        graph()->NewNode(simplified()->NumberEqual(), receiver_elements_kind,
                         jsgraph()->ConstantNoHole(GetHoleyElementsKind(kind)));
    Node* holey_branch =
        graph()->NewNode(common()->Branch(), is_holey_kind, if_not_packed);
    Node* if_holey = graph()->NewNode(common()->IfTrue(), holey_branch);

    Node* if_not_packed_not_holey =
        graph()->NewNode(common()->IfFalse(), holey_branch);

    *if_true = graph()->NewNode(common()->Merge(2), if_packed, if_holey);
    *if_false = if_not_packed_not_holey;
  } else {
    *if_true = if_packed;
    *if_false = graph()->NewNode(common()->IfFalse(), packed_branch);
  }
}

// ES6 section 23.1.3.1 Array.prototype.at ( )
Reduction JSCallReducer::ReduceArrayPrototypeAt(Node* node) {
  if (!v8_flags.turbo_inline_array_builtins) return NoChange();

  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Node* receiver = n.receiver();
  Effect effect = n.effect();
  Control control = n.control();

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps()) return NoChange();

  // Collecting maps, and checking if a fallback builtin call will be required
  // (it is required if at least one map doesn't support fast array iteration).
  ZoneVector<MapRef> maps(broker()->zone());
  bool needs_fallback_builtin_call = false;
  for (MapRef map : inference.GetMaps()) {
    if (map.supports_fast_array_iteration(broker())) {
      maps.push_back(map);
    } else {
      needs_fallback_builtin_call = true;
    }
  }

  inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                      control, p.feedback());

  if (maps.empty()) {
    // No map in the feedback supports fast iteration. Keeping the builtin call.
    return NoChange();
  }

  if (!dependencies()->DependOnNoElementsProtector()) {
    return NoChange();
  }

  IteratingArrayBuiltinReducerAssembler a(this, node);
  a.InitializeEffectControl(effect, control);

  TNode<Object> subgraph =
      a.ReduceArrayPrototypeAt(maps, needs_fallback_builtin_call);
  return ReplaceWithSubgraph(&a, subgraph);
}

// ES6 section 22.1.3.18 Array.prototype.push ( )
Reduction JSCallReducer::ReduceArrayPrototypePush(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Node* receiver = n.receiver();
  Effect effect = n.effect();
  Control control = n.control();

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps()) return NoChange();
  ZoneRefSet<Map> const& receiver_maps = inference.GetMaps();

  std::vector<ElementsKind> kinds;
  if (!CanInlineArrayResizingBuiltin(broker(), receiver_maps, &kinds, true)) {
    return inference.NoChange();
  }
  if (!dependencies()->DependOnNoElementsProtector()) {
    return inference.NoChange();
  }

  inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                      control, p.feedback());

  IteratingArrayBuiltinReducerAssembler a(this, node);
  a.InitializeEffectControl(effect, control);

  TNode<Object> subgraph = a.ReduceArrayPrototypePush(&inference);
  return ReplaceWithSubgraph(&a, subgraph);
}

// ES6 section 22.1.3.17 Array.prototype.pop ( )
Reduction JSCallReducer::ReduceArrayPrototypePop(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Effect effect = n.effect();
  Control control = n.control();
  Node* receiver = n.receiver();

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps()) return NoChange();
  ZoneRefSet<Map> const& receiver_maps = inference.GetMaps();

  std::vector<ElementsKind> kinds;
  if (!CanInlineArrayResizingBuiltin(broker(), receiver_maps, &kinds)) {
    return inference.NoChange();
  }
  if (!dependencies()->DependOnNoElementsProtector()) {
    return inference.NoChange();
  }
  inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                      control, p.feedback());

  std::vector<Node*> controls_to_merge;
  std::vector<Node*> effects_to_merge;
  std::vector<Node*> values_to_merge;
  Node* value = jsgraph()->UndefinedConstant();

  Node* receiver_elements_kind =
      LoadReceiverElementsKind(receiver, &effect, control);
  Node* next_control = control;
  Node* next_effect = effect;
  for (size_t i = 0; i < kinds.size(); i++) {
    ElementsKind kind = kinds[i];
    control = next_control;
    effect = next_effect;
    // We do not need branch for the last elements kind.
    if (i != kinds.size() - 1) {
      Node* control_node = control;
      CheckIfElementsKind(receiver_elements_kind, kind, control_node,
                          &control_node, &next_control);
      control = control_node;
    }

    // Load the "length" property of the {receiver}.
    Node* length = effect = graph()->NewNode(
        simplified()->LoadField(AccessBuilder::ForJSArrayLength(kind)),
        receiver, effect, control);

    // Check if the {receiver} has any elements.
    Node* check = graph()->NewNode(simplified()->NumberEqual(), length,
                                   jsgraph()->ZeroConstant());
    Node* branch =
        graph()->NewNode(common()->Branch(BranchHint::kFalse), check, control);

    Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
    Node* etrue = effect;
    Node* vtrue = jsgraph()->UndefinedConstant();

    Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
    Node* efalse = effect;
    Node* vfalse;
    {
      // TODO(turbofan): We should trim the backing store if the capacity is too
      // big, as implemented in elements.cc:ElementsAccessorBase::SetLengthImpl.

      // Load the elements backing store from the {receiver}.
      Node* elements = efalse = graph()->NewNode(
          simplified()->LoadField(AccessBuilder::ForJSObjectElements()),
          receiver, efalse, if_false);

      // Ensure that we aren't popping from a copy-on-write backing store.
      if (IsSmiOrObjectElementsKind(kind)) {
        elements = efalse =
            graph()->NewNode(simplified()->EnsureWritableFastElements(),
                             receiver, elements, efalse, if_false);
      }

      // Compute the new {length}.
      Node* new_length = graph()->NewNode(simplified()->NumberSubtract(),
                                          length, jsgraph()->OneConstant());

      if (v8_flags.turbo_typer_hardening) {
        new_length = efalse = graph()->NewNode(
            simplified()->CheckBounds(p.feedback(),
                                      CheckBoundsFlag::kAbortOnOutOfBounds),
            new_length, length, efalse, if_false);
      }

      // Store the new {length} to the {receiver}.
      efalse = graph()->NewNode(
          simplified()->StoreField(AccessBuilder::ForJSArrayLength(kind)),
          receiver, new_length, efalse, if_false);

      // Load the last entry from the {elements}.
      vfalse = efalse = graph()->NewNode(
          simplified()->LoadElement(AccessBuilder::ForFixedArrayElement(kind)),
          elements, new_length, efalse, if_false);

      // Store a hole to the element we just removed from the {receiver}.
      efalse = graph()->NewNode(
          simplified()->StoreElement(
              AccessBuilder::ForFixedArrayElement(GetHoleyElementsKind(kind))),
          elements, new_length, jsgraph()->TheHoleConstant(), efalse, if_false);
    }

    control = graph()->NewNode(common()->Merge(2), if_true, if_false);
    effect = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);
    value = graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                             vtrue, vfalse, control);

    // Convert the hole to undefined. Do this last, so that we can optimize
    // conversion operator via some smart strength reduction in many cases.
    if (IsHoleyElementsKind(kind)) {
      value =
          graph()->NewNode(simplified()->ConvertTaggedHoleToUndefined(), value);
    }

    controls_to_merge.push_back(control);
    effects_to_merge.push_back(effect);
    values_to_merge.push_back(value);
  }

  if (controls_to_merge.size() > 1) {
    int const count = static_cast<int>(controls_to_merge.size());

    control = graph()->NewNode(common()->Merge(count), count,
                               &controls_to_merge.front());
    effects_to_merge.push_back(control);
    effect = graph()->NewNode(common()->EffectPhi(count), count + 1,
                              &effects_to_merge.front());
    values_to_merge.push_back(control);
    value =
        graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, count),
                         count + 1, &values_to_merge.front());
  }

  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

// ES6 section 22.1.3.22 Array.prototype.shift ( )
// Currently disabled. See https://crbug.com/v8/14409
Reduction JSCallReducer::ReduceArrayPrototypeShift(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Node* target = n.target();
  Node* receiver = n.receiver();
  Node* context = n.context();
  FrameState frame_state = n.frame_state();
  Effect effect = n.effect();
  Control control = n.control();

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps()) return NoChange();
  ZoneRefSet<Map> const& receiver_maps = inference.GetMaps();

  std::vector<ElementsKind> kinds;
  if (!CanInlineArrayResizingBuiltin(broker(), receiver_maps, &kinds)) {
    return inference.NoChange();
  }
  if (!dependencies()->DependOnNoElementsProtector()) {
    return inference.NoChange();
  }
  inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                      control, p.feedback());

  std::vector<Node*> controls_to_merge;
  std::vector<Node*> effects_to_merge;
  std::vector<Node*> values_to_merge;
  Node* value = jsgraph()->UndefinedConstant();

  Node* receiver_elements_kind =
      LoadReceiverElementsKind(receiver, &effect, control);
  Node* next_control = control;
  Node* next_effect = effect;
  for (size_t i = 0; i < kinds.size(); i++) {
    ElementsKind kind = kinds[i];
    control = next_control;
    effect = next_effect;
    // We do not need branch for the last elements kind.
    if (i != kinds.size() - 1) {
      Node* control_node = control;
      CheckIfElementsKind(receiver_elements_kind, kind, control_node,
                          &control_node, &next_control);
      control = control_node;
    }

    // Load length of the {receiver}.
    Node* length = effect = graph()->NewNode(
        simplified()->LoadField(AccessBuilder::ForJSArrayLength(kind)),
        receiver, effect, control);

    // Return undefined if {receiver} has no elements.
    Node* check0 = graph()->NewNode(simplified()->NumberEqual(), length,
                                    jsgraph()->ZeroConstant());
    Node* branch0 =
        graph()->NewNode(common()->Branch(BranchHint::kFalse), check0, control);

    Node* if_true0 = graph()->NewNode(common()->IfTrue(), branch0);
    Node* etrue0 = effect;
    Node* vtrue0 = jsgraph()->UndefinedConstant();

    Node* if_false0 = graph()->NewNode(common()->IfFalse(), branch0);
    Node* efalse0 = effect;
    Node* vfalse0;
    {
      // Check if we should take the fast-path.
      Node* check1 = graph()->NewNode(
          simplified()->NumberLessThanOrEqual(), length,
          jsgraph()->ConstantNoHole(JSArray::kMaxCopyElements));
      Node* branch1 = graph()->NewNode(common()->Branch(BranchHint::kTrue),
                                       check1, if_false0);

      Node* if_true1 = graph()->NewNode(common()->IfTrue(), branch1);
      Node* etrue1 = efalse0;
      Node* vtrue1;
      {
        Node* elements = etrue1 = graph()->NewNode(
            simplified()->LoadField(AccessBuilder::ForJSObjectElements()),
            receiver, etrue1, if_true1);

        // Load the first element here, which we return below.
        vtrue1 = etrue1 = graph()->NewNode(
            simplified()->LoadElement(
                AccessBuilder::ForFixedArrayElement(kind)),
            elements, jsgraph()->ZeroConstant(), etrue1, if_true1);

        // Ensure that we aren't shifting a copy-on-write backing store.
        if (IsSmiOrObjectElementsKind(kind)) {
          elements = etrue1 =
              graph()->NewNode(simplified()->EnsureWritableFastElements(),
                               receiver, elements, etrue1, if_true1);
        }

        // Shift the remaining {elements} by one towards the start.
        Node* loop = graph()->NewNode(common()->Loop(2), if_true1, if_true1);
        Node* eloop =
            graph()->NewNode(common()->EffectPhi(2), etrue1, etrue1, loop);
        Node* terminate = graph()->NewNode(common()->Terminate(), eloop, loop);
        MergeControlToEnd(graph(), common(), terminate);

        Node* index = graph()->NewNode(
            common()->Phi(MachineRepresentation::kTagged, 2),
            jsgraph()->OneConstant(),
            jsgraph()->ConstantNoHole(JSArray::kMaxCopyElements - 1), loop);

        {
          Node* check2 =
              graph()->NewNode(simplified()->NumberLessThan(), index, length);
          Node* branch2 = graph()->NewNode(common()->Branch(), check2, loop);

          if_true1 = graph()->NewNode(common()->IfFalse(), branch2);
          etrue1 = eloop;

          Node* control2 = graph()->NewNode(common()->IfTrue(), branch2);
          Node* effect2 = etrue1;

          ElementAccess const access =
              AccessBuilder::ForFixedArrayElement(kind);

          // When disable v8_flags.turbo_loop_variable, typer cannot infer index
          // is in [1,
### 提示词
```
这是目录为v8/src/compiler/js-call-reducer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-call-reducer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共12部分，请归纳一下它的功能
```

### 源代码
```cpp
} else {
      node->ReplaceInput(
          n.NewTargetIndex(),
          graph()->NewNode(common()->Select(MachineRepresentation::kTagged),
                           graph()->NewNode(simplified()->ReferenceEqual(),
                                            target, new_target),
                           bound_target_function, new_target));
    }

    // Insert the [[BoundArguments]] for {node}.
    for (uint32_t i = 0; i < bound_arguments_length; ++i) {
      Node* value = NodeProperties::GetValueInput(target, 2 + i);
      node->InsertInput(graph()->zone(), n.ArgumentIndex(i), value);
      arity++;
    }

    // Update the JSConstruct operator on {node}.
    NodeProperties::ChangeOp(
        node, javascript()->Construct(JSConstructNode::ArityForArgc(arity),
                                      p.frequency(), FeedbackSource()));

    // Try to further reduce the JSConstruct {node}.
    return Changed(node).FollowedBy(ReduceJSConstruct(node));
  }

  return NoChange();
}

// ES #sec-string.prototype.indexof
// ES #sec-string.prototype.includes
Reduction JSCallReducer::ReduceStringPrototypeIndexOfIncludes(
    Node* node, StringIndexOfIncludesVariant variant) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Effect effect = n.effect();
  Control control = n.control();
  if (n.ArgumentCount() > 0) {
    Node* receiver = n.receiver();
    Node* new_receiver = effect = graph()->NewNode(
        simplified()->CheckString(p.feedback()), receiver, effect, control);

    Node* search_string = n.Argument(0);
    Node* new_search_string = effect =
        graph()->NewNode(simplified()->CheckString(p.feedback()), search_string,
                         effect, control);

    Node* new_position = jsgraph()->ZeroConstant();
    if (n.ArgumentCount() > 1) {
      Node* position = n.Argument(1);
      new_position = effect = graph()->NewNode(
          simplified()->CheckSmi(p.feedback()), position, effect, control);

      Node* receiver_length =
          graph()->NewNode(simplified()->StringLength(), new_receiver);
      new_position = graph()->NewNode(
          simplified()->NumberMin(),
          graph()->NewNode(simplified()->NumberMax(), new_position,
                           jsgraph()->ZeroConstant()),
          receiver_length);
    }

    NodeProperties::ReplaceEffectInput(node, effect);
    RelaxEffectsAndControls(node);
    node->ReplaceInput(0, new_receiver);
    node->ReplaceInput(1, new_search_string);
    node->ReplaceInput(2, new_position);
    node->TrimInputCount(3);
    NodeProperties::ChangeOp(node, simplified()->StringIndexOf());

    if (variant == StringIndexOfIncludesVariant::kIndexOf) {
      return Changed(node);
    } else {
      DCHECK(variant == StringIndexOfIncludesVariant::kIncludes);
      Node* result =
          graph()->NewNode(simplified()->BooleanNot(),
                           graph()->NewNode(simplified()->NumberEqual(), node,
                                            jsgraph()->SmiConstant(-1)));
      return Replace(result);
    }
  }
  return NoChange();
}

// ES #sec-string.prototype.substring
Reduction JSCallReducer::ReduceStringPrototypeSubstring(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (n.ArgumentCount() < 1) return NoChange();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  JSCallReducerAssembler a(this, node);
  Node* subgraph = a.ReduceStringPrototypeSubstring();
  return ReplaceWithSubgraph(&a, subgraph);
}

// ES #sec-string.prototype.slice
Reduction JSCallReducer::ReduceStringPrototypeSlice(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (n.ArgumentCount() < 1) return NoChange();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  JSCallReducerAssembler a(this, node);
  Node* subgraph = a.ReduceStringPrototypeSlice();
  return ReplaceWithSubgraph(&a, subgraph);
}

// ES #sec-string.prototype.substr
Reduction JSCallReducer::ReduceStringPrototypeSubstr(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (n.ArgumentCount() < 1) return NoChange();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Effect effect = n.effect();
  Control control = n.control();
  Node* receiver = n.receiver();
  Node* start = n.Argument(0);
  Node* end = n.ArgumentOrUndefined(1, jsgraph());

  receiver = effect = graph()->NewNode(simplified()->CheckString(p.feedback()),
                                       receiver, effect, control);

  start = effect = graph()->NewNode(simplified()->CheckSmi(p.feedback()), start,
                                    effect, control);

  Node* length = graph()->NewNode(simplified()->StringLength(), receiver);

  // Replace {end} argument with {length} if it is undefined.
  {
    Node* check = graph()->NewNode(simplified()->ReferenceEqual(), end,
                                   jsgraph()->UndefinedConstant());
    Node* branch =
        graph()->NewNode(common()->Branch(BranchHint::kFalse), check, control);

    Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
    Node* etrue = effect;
    Node* vtrue = length;

    Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
    Node* efalse = effect;
    Node* vfalse = efalse = graph()->NewNode(
        simplified()->CheckSmi(p.feedback()), end, efalse, if_false);

    control = graph()->NewNode(common()->Merge(2), if_true, if_false);
    effect = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);
    end = graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                           vtrue, vfalse, control);
  }

  Node* initStart = graph()->NewNode(
      common()->Select(MachineRepresentation::kTagged, BranchHint::kFalse),
      graph()->NewNode(simplified()->NumberLessThan(), start,
                       jsgraph()->ZeroConstant()),
      graph()->NewNode(
          simplified()->NumberMax(),
          graph()->NewNode(simplified()->NumberAdd(), length, start),
          jsgraph()->ZeroConstant()),
      start);
  // The select above guarantees that initStart is non-negative, but
  // our typer can't figure that out yet.
  initStart = effect = graph()->NewNode(
      common()->TypeGuard(Type::UnsignedSmall()), initStart, effect, control);

  Node* resultLength = graph()->NewNode(
      simplified()->NumberMin(),
      graph()->NewNode(simplified()->NumberMax(), end,
                       jsgraph()->ZeroConstant()),
      graph()->NewNode(simplified()->NumberSubtract(), length, initStart));

  // The the select below uses {resultLength} only if {resultLength > 0},
  // but our typer can't figure that out yet.
  Node* to = effect = graph()->NewNode(
      common()->TypeGuard(Type::UnsignedSmall()),
      graph()->NewNode(simplified()->NumberAdd(), initStart, resultLength),
      effect, control);

  Node* result_string = nullptr;
  // Return empty string if {from} is smaller than {to}.
  {
    Node* check = graph()->NewNode(simplified()->NumberLessThan(),
                                   jsgraph()->ZeroConstant(), resultLength);

    Node* branch =
        graph()->NewNode(common()->Branch(BranchHint::kTrue), check, control);

    Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
    Node* etrue = effect;
    Node* vtrue = etrue =
        graph()->NewNode(simplified()->StringSubstring(), receiver, initStart,
                         to, etrue, if_true);

    Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
    Node* efalse = effect;
    Node* vfalse = jsgraph()->EmptyStringConstant();

    control = graph()->NewNode(common()->Merge(2), if_true, if_false);
    effect = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);
    result_string =
        graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                         vtrue, vfalse, control);
  }

  ReplaceWithValue(node, result_string, effect, control);
  return Replace(result_string);
}

Reduction JSCallReducer::ReduceJSConstructWithArrayLike(Node* node) {
  JSConstructWithArrayLikeNode n(node);
  ConstructParameters const& p = n.Parameters();
  const int arraylike_index = n.LastArgumentIndex();
  DCHECK_EQ(n.ArgumentCount(), 1);  // The arraylike object.
  return ReduceCallOrConstructWithArrayLikeOrSpread(
      node, n.ArgumentCount(), arraylike_index, p.frequency(), p.feedback(),
      SpeculationMode::kDisallowSpeculation, CallFeedbackRelation::kTarget,
      n.target(), n.effect(), n.control());
}

Reduction JSCallReducer::ReduceJSConstructWithSpread(Node* node) {
  JSConstructWithSpreadNode n(node);
  ConstructParameters const& p = n.Parameters();
  const int spread_index = n.LastArgumentIndex();
  DCHECK_GE(n.ArgumentCount(), 1);  // At least the spread.
  return ReduceCallOrConstructWithArrayLikeOrSpread(
      node, n.ArgumentCount(), spread_index, p.frequency(), p.feedback(),
      SpeculationMode::kDisallowSpeculation, CallFeedbackRelation::kTarget,
      n.target(), n.effect(), n.control());
}

Reduction JSCallReducer::ReduceJSConstructForwardAllArgs(Node* node) {
  JSConstructForwardAllArgsNode n(node);
  DCHECK_EQ(n.ArgumentCount(), 0);

  // If this frame is not being inlined, JSConstructForwardAllArgs will be
  // lowered later in JSGenericLowering to a builtin call.
  FrameState frame_state = n.frame_state();
  if (frame_state.outer_frame_state()->opcode() != IrOpcode::kFrameState) {
    return NoChange();
  }

  // Hook up the arguments directly when forwarding arguments of inlined frames.
  FrameState outer_state{frame_state.outer_frame_state()};
  FrameStateInfo outer_info = outer_state.frame_state_info();
  if (outer_info.type() == FrameStateType::kInlinedExtraArguments) {
    frame_state = outer_state;
  }

  int argc = 0;
  StateValuesAccess parameters_access(frame_state.parameters());
  for (auto it = parameters_access.begin_without_receiver(); !it.done(); ++it) {
    DCHECK_NOT_NULL(it.node());
    node->InsertInput(graph()->zone(),
                      JSCallOrConstructNode::ArgumentIndex(argc++), it.node());
  }

  ConstructParameters const& p = n.Parameters();
  NodeProperties::ChangeOp(
      node, javascript()->Construct(JSConstructNode::ArityForArgc(argc),
                                    p.frequency(), p.feedback()));
  CheckIfConstructor(node);
  return Changed(node).FollowedBy(ReduceJSConstruct(node));
}

Reduction JSCallReducer::ReduceReturnReceiver(Node* node) {
  JSCallNode n(node);
  Node* receiver = n.receiver();
  ReplaceWithValue(node, receiver);
  return Replace(receiver);
}

Reduction JSCallReducer::ReduceForInsufficientFeedback(
    Node* node, DeoptimizeReason reason) {
  DCHECK(node->opcode() == IrOpcode::kJSCall ||
         node->opcode() == IrOpcode::kJSConstruct);
  if (!(flags() & kBailoutOnUninitialized)) return NoChange();

  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  Node* frame_state =
      NodeProperties::FindFrameStateBefore(node, jsgraph()->Dead());
  Node* deoptimize =
      graph()->NewNode(common()->Deoptimize(reason, FeedbackSource()),
                       frame_state, effect, control);
  MergeControlToEnd(graph(), common(), deoptimize);
  node->TrimInputCount(0);
  NodeProperties::ChangeOp(node, common()->Dead());
  return Changed(node);
}

Node* JSCallReducer::LoadReceiverElementsKind(Node* receiver, Effect* effect,
                                              Control control) {
  Node* effect_node = *effect;
  Node* receiver_map = effect_node =
      graph()->NewNode(simplified()->LoadField(AccessBuilder::ForMap()),
                       receiver, effect_node, control);
  Node* receiver_bit_field2 = effect_node = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForMapBitField2()), receiver_map,
      effect_node, control);
  Node* receiver_elements_kind = graph()->NewNode(
      simplified()->NumberShiftRightLogical(),
      graph()->NewNode(
          simplified()->NumberBitwiseAnd(), receiver_bit_field2,
          jsgraph()->ConstantNoHole(Map::Bits2::ElementsKindBits::kMask)),
      jsgraph()->ConstantNoHole(Map::Bits2::ElementsKindBits::kShift));
  *effect = effect_node;
  return receiver_elements_kind;
}

void JSCallReducer::CheckIfElementsKind(Node* receiver_elements_kind,
                                        ElementsKind kind, Node* control,
                                        Node** if_true, Node** if_false) {
  Node* is_packed_kind =
      graph()->NewNode(simplified()->NumberEqual(), receiver_elements_kind,
                       jsgraph()->ConstantNoHole(GetPackedElementsKind(kind)));
  Node* packed_branch =
      graph()->NewNode(common()->Branch(), is_packed_kind, control);
  Node* if_packed = graph()->NewNode(common()->IfTrue(), packed_branch);

  if (IsHoleyElementsKind(kind)) {
    Node* if_not_packed = graph()->NewNode(common()->IfFalse(), packed_branch);
    Node* is_holey_kind =
        graph()->NewNode(simplified()->NumberEqual(), receiver_elements_kind,
                         jsgraph()->ConstantNoHole(GetHoleyElementsKind(kind)));
    Node* holey_branch =
        graph()->NewNode(common()->Branch(), is_holey_kind, if_not_packed);
    Node* if_holey = graph()->NewNode(common()->IfTrue(), holey_branch);

    Node* if_not_packed_not_holey =
        graph()->NewNode(common()->IfFalse(), holey_branch);

    *if_true = graph()->NewNode(common()->Merge(2), if_packed, if_holey);
    *if_false = if_not_packed_not_holey;
  } else {
    *if_true = if_packed;
    *if_false = graph()->NewNode(common()->IfFalse(), packed_branch);
  }
}

// ES6 section 23.1.3.1 Array.prototype.at ( )
Reduction JSCallReducer::ReduceArrayPrototypeAt(Node* node) {
  if (!v8_flags.turbo_inline_array_builtins) return NoChange();

  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Node* receiver = n.receiver();
  Effect effect = n.effect();
  Control control = n.control();

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps()) return NoChange();

  // Collecting maps, and checking if a fallback builtin call will be required
  // (it is required if at least one map doesn't support fast array iteration).
  ZoneVector<MapRef> maps(broker()->zone());
  bool needs_fallback_builtin_call = false;
  for (MapRef map : inference.GetMaps()) {
    if (map.supports_fast_array_iteration(broker())) {
      maps.push_back(map);
    } else {
      needs_fallback_builtin_call = true;
    }
  }

  inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                      control, p.feedback());

  if (maps.empty()) {
    // No map in the feedback supports fast iteration. Keeping the builtin call.
    return NoChange();
  }

  if (!dependencies()->DependOnNoElementsProtector()) {
    return NoChange();
  }

  IteratingArrayBuiltinReducerAssembler a(this, node);
  a.InitializeEffectControl(effect, control);

  TNode<Object> subgraph =
      a.ReduceArrayPrototypeAt(maps, needs_fallback_builtin_call);
  return ReplaceWithSubgraph(&a, subgraph);
}

// ES6 section 22.1.3.18 Array.prototype.push ( )
Reduction JSCallReducer::ReduceArrayPrototypePush(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Node* receiver = n.receiver();
  Effect effect = n.effect();
  Control control = n.control();

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps()) return NoChange();
  ZoneRefSet<Map> const& receiver_maps = inference.GetMaps();

  std::vector<ElementsKind> kinds;
  if (!CanInlineArrayResizingBuiltin(broker(), receiver_maps, &kinds, true)) {
    return inference.NoChange();
  }
  if (!dependencies()->DependOnNoElementsProtector()) {
    return inference.NoChange();
  }

  inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                      control, p.feedback());

  IteratingArrayBuiltinReducerAssembler a(this, node);
  a.InitializeEffectControl(effect, control);

  TNode<Object> subgraph = a.ReduceArrayPrototypePush(&inference);
  return ReplaceWithSubgraph(&a, subgraph);
}

// ES6 section 22.1.3.17 Array.prototype.pop ( )
Reduction JSCallReducer::ReduceArrayPrototypePop(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Effect effect = n.effect();
  Control control = n.control();
  Node* receiver = n.receiver();

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps()) return NoChange();
  ZoneRefSet<Map> const& receiver_maps = inference.GetMaps();

  std::vector<ElementsKind> kinds;
  if (!CanInlineArrayResizingBuiltin(broker(), receiver_maps, &kinds)) {
    return inference.NoChange();
  }
  if (!dependencies()->DependOnNoElementsProtector()) {
    return inference.NoChange();
  }
  inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                      control, p.feedback());

  std::vector<Node*> controls_to_merge;
  std::vector<Node*> effects_to_merge;
  std::vector<Node*> values_to_merge;
  Node* value = jsgraph()->UndefinedConstant();

  Node* receiver_elements_kind =
      LoadReceiverElementsKind(receiver, &effect, control);
  Node* next_control = control;
  Node* next_effect = effect;
  for (size_t i = 0; i < kinds.size(); i++) {
    ElementsKind kind = kinds[i];
    control = next_control;
    effect = next_effect;
    // We do not need branch for the last elements kind.
    if (i != kinds.size() - 1) {
      Node* control_node = control;
      CheckIfElementsKind(receiver_elements_kind, kind, control_node,
                          &control_node, &next_control);
      control = control_node;
    }

    // Load the "length" property of the {receiver}.
    Node* length = effect = graph()->NewNode(
        simplified()->LoadField(AccessBuilder::ForJSArrayLength(kind)),
        receiver, effect, control);

    // Check if the {receiver} has any elements.
    Node* check = graph()->NewNode(simplified()->NumberEqual(), length,
                                   jsgraph()->ZeroConstant());
    Node* branch =
        graph()->NewNode(common()->Branch(BranchHint::kFalse), check, control);

    Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
    Node* etrue = effect;
    Node* vtrue = jsgraph()->UndefinedConstant();

    Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
    Node* efalse = effect;
    Node* vfalse;
    {
      // TODO(turbofan): We should trim the backing store if the capacity is too
      // big, as implemented in elements.cc:ElementsAccessorBase::SetLengthImpl.

      // Load the elements backing store from the {receiver}.
      Node* elements = efalse = graph()->NewNode(
          simplified()->LoadField(AccessBuilder::ForJSObjectElements()),
          receiver, efalse, if_false);

      // Ensure that we aren't popping from a copy-on-write backing store.
      if (IsSmiOrObjectElementsKind(kind)) {
        elements = efalse =
            graph()->NewNode(simplified()->EnsureWritableFastElements(),
                             receiver, elements, efalse, if_false);
      }

      // Compute the new {length}.
      Node* new_length = graph()->NewNode(simplified()->NumberSubtract(),
                                          length, jsgraph()->OneConstant());

      if (v8_flags.turbo_typer_hardening) {
        new_length = efalse = graph()->NewNode(
            simplified()->CheckBounds(p.feedback(),
                                      CheckBoundsFlag::kAbortOnOutOfBounds),
            new_length, length, efalse, if_false);
      }

      // Store the new {length} to the {receiver}.
      efalse = graph()->NewNode(
          simplified()->StoreField(AccessBuilder::ForJSArrayLength(kind)),
          receiver, new_length, efalse, if_false);

      // Load the last entry from the {elements}.
      vfalse = efalse = graph()->NewNode(
          simplified()->LoadElement(AccessBuilder::ForFixedArrayElement(kind)),
          elements, new_length, efalse, if_false);

      // Store a hole to the element we just removed from the {receiver}.
      efalse = graph()->NewNode(
          simplified()->StoreElement(
              AccessBuilder::ForFixedArrayElement(GetHoleyElementsKind(kind))),
          elements, new_length, jsgraph()->TheHoleConstant(), efalse, if_false);
    }

    control = graph()->NewNode(common()->Merge(2), if_true, if_false);
    effect = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);
    value = graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                             vtrue, vfalse, control);

    // Convert the hole to undefined. Do this last, so that we can optimize
    // conversion operator via some smart strength reduction in many cases.
    if (IsHoleyElementsKind(kind)) {
      value =
          graph()->NewNode(simplified()->ConvertTaggedHoleToUndefined(), value);
    }

    controls_to_merge.push_back(control);
    effects_to_merge.push_back(effect);
    values_to_merge.push_back(value);
  }

  if (controls_to_merge.size() > 1) {
    int const count = static_cast<int>(controls_to_merge.size());

    control = graph()->NewNode(common()->Merge(count), count,
                               &controls_to_merge.front());
    effects_to_merge.push_back(control);
    effect = graph()->NewNode(common()->EffectPhi(count), count + 1,
                              &effects_to_merge.front());
    values_to_merge.push_back(control);
    value =
        graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, count),
                         count + 1, &values_to_merge.front());
  }

  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

// ES6 section 22.1.3.22 Array.prototype.shift ( )
// Currently disabled. See https://crbug.com/v8/14409
Reduction JSCallReducer::ReduceArrayPrototypeShift(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Node* target = n.target();
  Node* receiver = n.receiver();
  Node* context = n.context();
  FrameState frame_state = n.frame_state();
  Effect effect = n.effect();
  Control control = n.control();

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps()) return NoChange();
  ZoneRefSet<Map> const& receiver_maps = inference.GetMaps();

  std::vector<ElementsKind> kinds;
  if (!CanInlineArrayResizingBuiltin(broker(), receiver_maps, &kinds)) {
    return inference.NoChange();
  }
  if (!dependencies()->DependOnNoElementsProtector()) {
    return inference.NoChange();
  }
  inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                      control, p.feedback());

  std::vector<Node*> controls_to_merge;
  std::vector<Node*> effects_to_merge;
  std::vector<Node*> values_to_merge;
  Node* value = jsgraph()->UndefinedConstant();

  Node* receiver_elements_kind =
      LoadReceiverElementsKind(receiver, &effect, control);
  Node* next_control = control;
  Node* next_effect = effect;
  for (size_t i = 0; i < kinds.size(); i++) {
    ElementsKind kind = kinds[i];
    control = next_control;
    effect = next_effect;
    // We do not need branch for the last elements kind.
    if (i != kinds.size() - 1) {
      Node* control_node = control;
      CheckIfElementsKind(receiver_elements_kind, kind, control_node,
                          &control_node, &next_control);
      control = control_node;
    }

    // Load length of the {receiver}.
    Node* length = effect = graph()->NewNode(
        simplified()->LoadField(AccessBuilder::ForJSArrayLength(kind)),
        receiver, effect, control);

    // Return undefined if {receiver} has no elements.
    Node* check0 = graph()->NewNode(simplified()->NumberEqual(), length,
                                    jsgraph()->ZeroConstant());
    Node* branch0 =
        graph()->NewNode(common()->Branch(BranchHint::kFalse), check0, control);

    Node* if_true0 = graph()->NewNode(common()->IfTrue(), branch0);
    Node* etrue0 = effect;
    Node* vtrue0 = jsgraph()->UndefinedConstant();

    Node* if_false0 = graph()->NewNode(common()->IfFalse(), branch0);
    Node* efalse0 = effect;
    Node* vfalse0;
    {
      // Check if we should take the fast-path.
      Node* check1 = graph()->NewNode(
          simplified()->NumberLessThanOrEqual(), length,
          jsgraph()->ConstantNoHole(JSArray::kMaxCopyElements));
      Node* branch1 = graph()->NewNode(common()->Branch(BranchHint::kTrue),
                                       check1, if_false0);

      Node* if_true1 = graph()->NewNode(common()->IfTrue(), branch1);
      Node* etrue1 = efalse0;
      Node* vtrue1;
      {
        Node* elements = etrue1 = graph()->NewNode(
            simplified()->LoadField(AccessBuilder::ForJSObjectElements()),
            receiver, etrue1, if_true1);

        // Load the first element here, which we return below.
        vtrue1 = etrue1 = graph()->NewNode(
            simplified()->LoadElement(
                AccessBuilder::ForFixedArrayElement(kind)),
            elements, jsgraph()->ZeroConstant(), etrue1, if_true1);

        // Ensure that we aren't shifting a copy-on-write backing store.
        if (IsSmiOrObjectElementsKind(kind)) {
          elements = etrue1 =
              graph()->NewNode(simplified()->EnsureWritableFastElements(),
                               receiver, elements, etrue1, if_true1);
        }

        // Shift the remaining {elements} by one towards the start.
        Node* loop = graph()->NewNode(common()->Loop(2), if_true1, if_true1);
        Node* eloop =
            graph()->NewNode(common()->EffectPhi(2), etrue1, etrue1, loop);
        Node* terminate = graph()->NewNode(common()->Terminate(), eloop, loop);
        MergeControlToEnd(graph(), common(), terminate);

        Node* index = graph()->NewNode(
            common()->Phi(MachineRepresentation::kTagged, 2),
            jsgraph()->OneConstant(),
            jsgraph()->ConstantNoHole(JSArray::kMaxCopyElements - 1), loop);

        {
          Node* check2 =
              graph()->NewNode(simplified()->NumberLessThan(), index, length);
          Node* branch2 = graph()->NewNode(common()->Branch(), check2, loop);

          if_true1 = graph()->NewNode(common()->IfFalse(), branch2);
          etrue1 = eloop;

          Node* control2 = graph()->NewNode(common()->IfTrue(), branch2);
          Node* effect2 = etrue1;

          ElementAccess const access =
              AccessBuilder::ForFixedArrayElement(kind);

          // When disable v8_flags.turbo_loop_variable, typer cannot infer index
          // is in [1, kMaxCopyElements-1], and will break in representing
          // kRepFloat64 (Range(1, inf)) to kRepWord64 when converting
          // input for kLoadElement. So we need to add type guard here.
          // And we need to use index when using NumberLessThan to check
          // terminate and updating index, otherwise which will break inducing
          // variables in LoopVariableOptimizer.
          static_assert(JSArray::kMaxCopyElements < kSmiMaxValue);
          Node* index_retyped = effect2 =
              graph()->NewNode(common()->TypeGuard(Type::UnsignedSmall()),
                               index, effect2, control2);

          Node* value2 = effect2 =
              graph()->NewNode(simplified()->LoadElement(access), elements,
                               index_retyped, effect2, control2);
          effect2 = graph()->NewNode(
              simplified()->StoreElement(access), elements,
              graph()->NewNode(simplified()->NumberSubtract(), index_retyped,
                               jsgraph()->OneConstant()),
              value2, effect2, control2);

          loop->ReplaceInput(1, control2);
          eloop->ReplaceInput(1, effect2);
          index->ReplaceInput(1,
                              graph()->NewNode(simplified()->NumberAdd(), index,
                                               jsgraph()->OneConstant()));
        }

        // Compute the new {length}.
        Node* new_length = graph()->NewNode(simplified()->NumberSubtract(),
                                            length, jsgraph()->OneConstant());

        if (v8_flags.turbo_typer_hardening) {
          new_length = etrue1 = graph()->NewNode(
              simplified()->CheckBounds(p.feedback(),
                                        CheckBoundsFlag::kAbortOnOutOfBounds),
              new_length, length, etrue1, if_true1);
        }

        // Store the new {length} to the {receiver}.
        etrue1 = graph()->NewNode(
            simplified()->StoreField(AccessBuilder::ForJSArrayLength(kind)),
            receiver, new_length, etrue1, if_true1);

        // Store a hole to the element we just removed from the {receiver}.
        etrue1 = graph()->NewNode(
            simplified()->StoreElement(AccessBuilder::ForFixedArrayElement(
                GetHoleyElementsKind(kind))),
            elements, new_length, jsgraph()->TheHoleConstant(), etrue1,
            if_true1);
      }

      Node* if_false1 = graph()->NewNode(common()->IfFalse(), branch1);
      Node* efalse1 = efalse0;
      Node* vfalse1;
      {
        // Call the generic C++ implementation.
        const Builtin builtin = Builtin::kArrayShift;
        auto call_descriptor = Linkage::GetCEntryStubCallDescriptor(
            graph()->zone(), 1, BuiltinArguments::kNumExtraArgsWithReceiver,
            Builtins::name(builtin), node->op()->properties(),
            CallDescriptor::kNeedsFrameState);
        const bool has_builtin_exit_frame = true;
        Node* stub_code = jsgraph()->CEntryStubConstant(1, ArgvMode::kStack,
                                                        has_builtin_exit_frame);
        Address builtin_entry = Builtins::CppEntryOf(builtin);
        Node* entry = jsgraph()->ExternalConstant(
            ExternalReference::Create(builtin_entry));
        Node* argc = jsgraph()->ConstantNoHole(
            BuiltinArguments::kNumExtraArgsWithReceiver);
        static_assert(BuiltinArguments::kNewTargetIndex == 0);
        static_assert(BuiltinArguments::kTargetIndex == 1);
        static_assert(BuiltinArguments::kArgcIndex == 2);
        static_assert(BuiltinArguments::kPaddingIndex == 3);
        if_false1 = efalse1 = vfalse1 =
            graph()->NewNode(common()->Call(call_descriptor), stub_code,
                             receiver, jsgraph()->PaddingConstant(), argc,
                             target, jsgraph()->UndefinedConstant(), entry,
                             argc, context, frame_state, efalse1, if_false1);
      }

      if_false0 = graph()->NewNode(common()->Merge(2), if_true1, if_false1);
      efalse0 =
          graph()->NewNode(common()->EffectPhi(2), etrue1, efalse1, if_false0);
      vfalse0 =
          graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                           vtrue1, vfalse1, if_false0);
    }

    control = graph()->NewNode(common()->Merge(2), if_true0, if_false0);
    effect = graph()->NewNode(common()->EffectPhi(2), etrue0, efalse0, control);
    value = graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                             vtrue0, vfalse0, control);

    // Convert the hole to undefined. Do this last, so that we can optimize
    // conversion operator via some smart strength reduction in many cases.
    if (IsHoleyElementsKind(kind)) {
      value =
          graph()->NewNode(simplified()->ConvertTaggedHoleToUndefined(), value);
    }

    controls_to_merge.push_back(control);
    effects_to_merge.push_back(effect);
    values_to_merge.push_back(value);
  }

  if (controls_to_merge.size() > 1) {
    int const count = static_cast<int>(controls_to_merge.size());

    control = graph()->NewNode(common()->Merge(count), count,
                               &controls_to_merge.front());
    effects_to_merge.push_back(control);
    effect = graph()->NewNode(common()->EffectPhi(count), count + 1,
                              &effects_to_merge.front());
    values_to_merge.push_back(control);
    value =
        graph()->NewNode(common()->Phi(MachineRepresentation::kTagged,
```