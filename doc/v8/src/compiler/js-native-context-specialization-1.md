Response: The user wants me to summarize the functionality of the C++ code provided in the second part of a three-part snippet from the file `v8/src/compiler/js-native-context-specialization.cc`.

I need to analyze the code and identify its main purpose. The code seems to be dealing with optimizing property access in JavaScript by specializing based on the type feedback gathered during runtime.

Specifically, this part handles:
- **Polymorphic property access:** It deals with scenarios where the property access might involve different object shapes (maps).
- **Generating checks:** It generates code to check the maps of objects involved in the property access.
- **Optimized property access:**  If the object's map matches expectations, it generates optimized code to access the property.
- **Handling exceptions:** It handles potential exceptions during property access.
- **Specific optimizations:** It includes optimizations for accessing the `length` property of strings and the `prototype` property of functions.
- **Iterator handling:** It includes logic for handling the `getIterator` operation.
- **Element access on strings:** It optimizes accessing elements of string objects.
- **Element access on other objects:** It optimizes accessing elements of objects based on their elements kind.

I will now formulate the summary and provide a JavaScript example illustrating the concepts.
这是 C++ 源代码文件 `v8/src/compiler/js-native-context-specialization.cc` 的第 2 部分，它延续了第 1 部分的功能，主要负责在编译 JavaScript 代码时，根据运行时收集到的类型反馈信息，对属性访问（包括命名属性和索引属性）进行更精细化的优化。

**第 2 部分的主要功能可以归纳为：**

1. **处理多态属性访问:** 当属性访问的目标对象可能具有多种不同的结构（由 `Map` 对象表示）时，这段代码会生成检查代码，判断当前对象的 `Map` 是否符合预期。它会为每种可能的 `Map` 生成不同的代码路径，并在运行时选择合适的路径。这提高了多态场景下的性能。

2. **生成类型检查代码:** 为了确保安全性并执行优化，这段代码会生成检查目标对象 `Map` 的代码。如果对象的 `Map` 与期望的 `Map` 不符，可能会触发去优化（deoptimization）或执行更通用的代码路径。

3. **构建优化的属性访问操作:**  一旦确定了对象的 `Map` 符合预期，这段代码会生成更高效的属性访问指令，例如直接访问对象的字段，而不是通过更慢的通用属性查找机制。

4. **处理 `getIterator` 操作:**  这段代码包含了对 JavaScript 中 `getIterator` 方法调用的优化逻辑。它会尝试根据反馈信息优化获取迭代器属性和调用迭代器方法的过程。

5. **优化字符串的元素访问:**  针对字符串类型的对象，这段代码会进行特殊的优化，例如直接计算字符串的长度，或者根据索引获取字符。

6. **优化数组等其他对象的元素访问:** 这部分代码会根据数组或其他对象的元素类型（例如，是否是快速数组，是否包含空洞等）生成优化的元素访问代码。

7. **处理属性访问的异常情况:** 代码中包含了对可能在属性访问过程中抛出异常的情况的处理，例如当尝试访问不存在的属性或调用访问器时。

**与 JavaScript 功能的关系和示例：**

这段 C++ 代码直接对应了 JavaScript 中访问对象属性的多种方式，包括点号访问 (`object.property`)、方括号访问 (`object['property']` 或 `array[index]`) 以及 `for...in` 循环中的属性访问。

**JavaScript 示例：**

```javascript
function Point(x, y) {
  this.x = x;
  this.y = y;
}

function ColorPoint(x, y, color) {
  Point.call(this, x, y);
  this.color = color;
}

let p1 = new Point(1, 2);
let p2 = new ColorPoint(3, 4, 'red');

// 第一次访问 p1.x，可能触发单态优化，假设 p1 的 Map 被记录
console.log(p1.x);

// 第一次访问 p2.x，可能触发从单态到多态的转换，因为 p2 的 Map 不同于 p1
console.log(p2.x);

function getLength(obj) {
  return obj.length;
}

let str = "hello";
let arr = [1, 2, 3];

// getLength(str) 会触发对字符串 length 属性的优化
console.log(getLength(str));

// getLength(arr) 也会触发，但可能使用不同的优化路径
console.log(getLength(arr));

const iterable = [10, 20, 30];
// 触发 getIterator 优化
for (const value of iterable) {
  console.log(value);
}

// 访问字符串的元素
console.log(str[1]); // 触发字符串元素访问的优化

// 访问数组的元素
console.log(arr[0]); // 触发数组元素访问的优化
```

**解释：**

- 当 JavaScript 引擎执行 `p1.x` 时，如果这是第一次执行，引擎可能会记录 `p1` 对象的 `Map` 信息。在后续执行中，如果再次遇到对 `Point` 对象的 `x` 属性访问，且对象的 `Map` 没有改变，TurboFan 可能会生成优化的代码，直接访问 `x` 字段，而无需进行完整的属性查找。
- 当执行 `p2.x` 时，由于 `p2` 是 `ColorPoint` 的实例，其对象结构（`Map`）与 `Point` 的实例不同。这时，引擎可能会从单态优化转换为多态优化，为 `Point` 和 `ColorPoint` 的 `x` 属性访问分别生成代码路径。
- `getLength(str)` 和 `getLength(arr)` 展示了对不同类型对象的 `length` 属性访问的优化。字符串的 `length` 是一个可以直接访问的属性，而数组的 `length` 可能涉及到更复杂的内部结构。
- `for...of` 循环会调用对象的 `Symbol.iterator` 方法来获取迭代器，这段 C++ 代码负责优化这个过程。
- `str[1]` 和 `arr[0]` 展示了对字符串和数组元素访问的优化。对于字符串，可以直接根据索引获取字符；对于数组，则需要考虑数组的元素类型和存储方式。

总而言之，`js-native-context-specialization.cc` 的第 2 部分在 V8 引擎中扮演着关键的角色，它通过分析和利用类型反馈信息，使得 JavaScript 代码在运行时能够以更高效的方式访问对象属性，从而显著提升整体性能。

### 提示词
```
这是目录为v8/src/compiler/js-native-context-specialization.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```
,
                                  effect);
      }
    }
  }

  ZoneVector<PropertyAccessInfo> access_infos(zone());
  {
    ZoneVector<PropertyAccessInfo> access_infos_for_feedback(zone());
    for (MapRef map : inferred_maps) {
      if (map.is_deprecated()) continue;

      // TODO(v8:12547): Support writing to objects in shared space, which need
      // a write barrier that calls Object::Share to ensure the RHS is shared.
      if (InstanceTypeChecker::IsAlwaysSharedSpaceJSObject(
              map.instance_type()) &&
          access_mode == AccessMode::kStore) {
        return NoChange();
      }

      PropertyAccessInfo access_info =
          broker()->GetPropertyAccessInfo(map, feedback.name(), access_mode);
      access_infos_for_feedback.push_back(access_info);
    }

    AccessInfoFactory access_info_factory(broker(), graph()->zone());
    if (!access_info_factory.FinalizePropertyAccessInfos(
            access_infos_for_feedback, access_mode, &access_infos)) {
      return NoChange();
    }
  }

  // Ensure that {key} matches the specified name (if {key} is given).
  if (key != nullptr) {
    effect = BuildCheckEqualsName(feedback.name(), key, effect, control);
  }

  // Collect call nodes to rewire exception edges.
  ZoneVector<Node*> if_exception_nodes(zone());
  ZoneVector<Node*>* if_exceptions = nullptr;
  Node* if_exception = nullptr;
  if (NodeProperties::IsExceptionalCall(node, &if_exception)) {
    if_exceptions = &if_exception_nodes;
  }

  PropertyAccessBuilder access_builder(jsgraph(), broker());

  // Check for the monomorphic cases.
  if (access_infos.size() == 1) {
    PropertyAccessInfo access_info = access_infos.front();
    if (receiver != lookup_start_object) {
      // Super property access. lookup_start_object is a JSReceiver or
      // null. It can't be a number, a string etc. So trying to build the
      // checks in the "else if" branch doesn't make sense.

      access_builder.BuildCheckMaps(lookup_start_object, &effect, control,
                                    access_info.lookup_start_object_maps());

      if (HasOnlyStringWrapperMaps(broker(),
                                   access_info.lookup_start_object_maps())) {
        // In order to be able to use StringWrapperLength, we need a TypeGuard
        // when all input maps are StringWrapper maps.
        lookup_start_object = effect =
            graph()->NewNode(common()->TypeGuard(Type::StringWrapper()),
                             lookup_start_object, effect, control);
      }

    } else if (!access_builder.TryBuildStringCheck(
                   broker(), access_info.lookup_start_object_maps(), &receiver,
                   &effect, control) &&
               !access_builder.TryBuildNumberCheck(
                   broker(), access_info.lookup_start_object_maps(), &receiver,
                   &effect, control)) {
      // Try to build string check or number check if possible. Otherwise build
      // a map check.

      // TryBuildStringCheck and TryBuildNumberCheck don't update the receiver
      // if they fail.
      DCHECK_EQ(receiver, lookup_start_object);
      if (HasNumberMaps(broker(), access_info.lookup_start_object_maps())) {
        // We need to also let Smi {receiver}s through in this case, so
        // we construct a diamond, guarded by the Sminess of the {receiver}
        // and if {receiver} is not a Smi just emit a sequence of map checks.
        Node* check = graph()->NewNode(simplified()->ObjectIsSmi(), receiver);
        Node* branch = graph()->NewNode(common()->Branch(), check, control);

        Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
        Node* etrue = effect;

        Control if_false{graph()->NewNode(common()->IfFalse(), branch)};
        Effect efalse = effect;
        access_builder.BuildCheckMaps(receiver, &efalse, if_false,
                                      access_info.lookup_start_object_maps());

        control = graph()->NewNode(common()->Merge(2), if_true, if_false);
        effect =
            graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);
      } else {
        access_builder.BuildCheckMaps(receiver, &effect, control,
                                      access_info.lookup_start_object_maps());
      }

      if (HasOnlyStringWrapperMaps(broker(),
                                   access_info.lookup_start_object_maps())) {
        // In order to be able to use StringWrapperLength, we need a TypeGuard
        // when all input maps are StringWrapper maps. Note that, alternatively,
        // we could have a CheckStringWrapper, but it makes things simpler to
        // just rely on CheckMaps. This is slightly suboptimal in case the code
        // contains multiple string wrappers with different properties, but this
        // should be a rare case.
        lookup_start_object = receiver = effect =
            graph()->NewNode(common()->TypeGuard(Type::StringWrapper()),
                             lookup_start_object, effect, control);
      }
    } else {
      // At least one of TryBuildStringCheck & TryBuildNumberCheck succeeded
      // and updated the receiver. Update lookup_start_object to match (they
      // should be the same).
      lookup_start_object = receiver;
    }

    // Generate the actual property access.
    std::optional<ValueEffectControl> continuation = BuildPropertyAccess(
        lookup_start_object, receiver, value, context, frame_state, effect,
        control, feedback.name(), if_exceptions, access_info, access_mode);
    if (!continuation) {
      // At this point we maybe have added nodes into the graph (e.g. via
      // NewNode or BuildCheckMaps) in some cases but we haven't connected them
      // to End since we haven't called ReplaceWithValue. Since they are nodes
      // which are not connected with End, they will be removed by graph
      // trimming.
      return NoChange();
    }
    value = continuation->value();
    effect = continuation->effect();
    control = continuation->control();
  } else {
    // The final states for every polymorphic branch. We join them with
    // Merge+Phi+EffectPhi at the bottom.
    ZoneVector<Node*> values(zone());
    ZoneVector<Node*> effects(zone());
    ZoneVector<Node*> controls(zone());

    Node* receiverissmi_control = nullptr;
    Node* receiverissmi_effect = effect;

    if (receiver == lookup_start_object) {
      // Check if {receiver} may be a number.
      bool receiverissmi_possible = false;
      for (PropertyAccessInfo const& access_info : access_infos) {
        if (HasNumberMaps(broker(), access_info.lookup_start_object_maps())) {
          receiverissmi_possible = true;
          break;
        }
      }

      // Handle the case that {receiver} may be a number.
      if (receiverissmi_possible) {
        Node* check = graph()->NewNode(simplified()->ObjectIsSmi(), receiver);
        Node* branch = graph()->NewNode(common()->Branch(), check, control);
        control = graph()->NewNode(common()->IfFalse(), branch);
        receiverissmi_control = graph()->NewNode(common()->IfTrue(), branch);
        receiverissmi_effect = effect;
      }
    }

    // Generate code for the various different property access patterns.
    Node* fallthrough_control = control;
    for (size_t j = 0; j < access_infos.size(); ++j) {
      PropertyAccessInfo const& access_info = access_infos[j];
      Node* this_value = value;
      Node* this_lookup_start_object = lookup_start_object;
      Node* this_receiver = receiver;
      Effect this_effect = effect;
      Control this_control{fallthrough_control};

      // Perform map check on {lookup_start_object}.
      ZoneVector<MapRef> const& lookup_start_object_maps =
          access_info.lookup_start_object_maps();
      {
        // Whether to insert a dedicated MapGuard node into the
        // effect to be able to learn from the control flow.
        bool insert_map_guard = true;

        // Check maps for the {lookup_start_object}s.
        if (j == access_infos.size() - 1) {
          // Last map check on the fallthrough control path, do a
          // conditional eager deoptimization exit here.
          access_builder.BuildCheckMaps(lookup_start_object, &this_effect,
                                        this_control, lookup_start_object_maps);
          fallthrough_control = nullptr;

          // Don't insert a MapGuard in this case, as the CheckMaps
          // node already gives you all the information you need
          // along the effect chain.
          insert_map_guard = false;
        } else {
          // Explicitly branch on the {lookup_start_object_maps}.
          ZoneRefSet<Map> maps(lookup_start_object_maps.begin(),
                               lookup_start_object_maps.end(), graph()->zone());
          Node* check = this_effect =
              graph()->NewNode(simplified()->CompareMaps(maps),
                               lookup_start_object, this_effect, this_control);
          Node* branch =
              graph()->NewNode(common()->Branch(), check, this_control);
          fallthrough_control = graph()->NewNode(common()->IfFalse(), branch);
          this_control = graph()->NewNode(common()->IfTrue(), branch);
        }

        // The Number case requires special treatment to also deal with Smis.
        if (HasNumberMaps(broker(), lookup_start_object_maps)) {
          // Join this check with the "receiver is smi" check above.
          DCHECK_EQ(receiver, lookup_start_object);
          DCHECK_NOT_NULL(receiverissmi_effect);
          DCHECK_NOT_NULL(receiverissmi_control);
          this_control = graph()->NewNode(common()->Merge(2), this_control,
                                          receiverissmi_control);
          this_effect = graph()->NewNode(common()->EffectPhi(2), this_effect,
                                         receiverissmi_effect, this_control);
          receiverissmi_effect = receiverissmi_control = nullptr;

          // The {lookup_start_object} can also be a Smi in this case, so
          // a MapGuard doesn't make sense for this at all.
          insert_map_guard = false;
        }

        // Introduce a MapGuard to learn from this on the effect chain.
        if (insert_map_guard) {
          ZoneRefSet<Map> maps(lookup_start_object_maps.begin(),
                               lookup_start_object_maps.end(), graph()->zone());
          this_effect =
              graph()->NewNode(simplified()->MapGuard(maps),
                               lookup_start_object, this_effect, this_control);
        }

        // If all {lookup_start_object_maps} are Strings we also need to rename
        // the {lookup_start_object} here to make sure that TurboFan knows that
        // along this path the {this_lookup_start_object} is a String. This is
        // because we want strict checking of types, for example for
        // StringLength operators.
        if (HasOnlyStringMaps(broker(), lookup_start_object_maps)) {
          DCHECK_EQ(receiver, lookup_start_object);
          this_lookup_start_object = this_receiver = this_effect =
              graph()->NewNode(common()->TypeGuard(Type::String()),
                               lookup_start_object, this_effect, this_control);
        } else if (HasOnlyStringWrapperMaps(broker(),
                                            lookup_start_object_maps)) {
          bool receiver_is_lookup_start =
              this_lookup_start_object == this_receiver;
          DCHECK_IMPLIES(access_mode != AccessMode::kLoad,
                         receiver_is_lookup_start);
          this_lookup_start_object = this_effect =
              graph()->NewNode(common()->TypeGuard(Type::StringWrapper()),
                               lookup_start_object, this_effect, this_control);
          if (receiver_is_lookup_start) {
            this_receiver = this_lookup_start_object;
          }
        }
      }

      // Generate the actual property access.
      std::optional<ValueEffectControl> continuation = BuildPropertyAccess(
          this_lookup_start_object, this_receiver, this_value, context,
          frame_state, this_effect, this_control, feedback.name(),
          if_exceptions, access_info, access_mode);
      if (!continuation) {
        // At this point we maybe have added nodes into the graph (e.g. via
        // NewNode or BuildCheckMaps) in some cases but we haven't connected
        // them to End since we haven't called ReplaceWithValue. Since they are
        // nodes which are not connected with End, they will be removed by graph
        // trimming.
        return NoChange();
      }

      values.push_back(continuation->value());
      effects.push_back(continuation->effect());
      controls.push_back(continuation->control());
    }

    DCHECK_NULL(fallthrough_control);

    // Generate the final merge point for all (polymorphic) branches.
    int const control_count = static_cast<int>(controls.size());
    if (control_count == 0) {
      value = effect = control = jsgraph()->Dead();
    } else if (control_count == 1) {
      value = values.front();
      effect = effects.front();
      control = controls.front();
    } else {
      control = graph()->NewNode(common()->Merge(control_count), control_count,
                                 &controls.front());
      values.push_back(control);
      value = graph()->NewNode(
          common()->Phi(MachineRepresentation::kTagged, control_count),
          control_count + 1, &values.front());
      effects.push_back(control);
      effect = graph()->NewNode(common()->EffectPhi(control_count),
                                control_count + 1, &effects.front());
    }
  }

  // Properly rewire IfException edges if {node} is inside a try-block.
  if (!if_exception_nodes.empty()) {
    DCHECK_NOT_NULL(if_exception);
    DCHECK_EQ(if_exceptions, &if_exception_nodes);
    int const if_exception_count = static_cast<int>(if_exceptions->size());
    Node* merge = graph()->NewNode(common()->Merge(if_exception_count),
                                   if_exception_count, &if_exceptions->front());
    if_exceptions->push_back(merge);
    Node* ephi =
        graph()->NewNode(common()->EffectPhi(if_exception_count),
                         if_exception_count + 1, &if_exceptions->front());
    Node* phi = graph()->NewNode(
        common()->Phi(MachineRepresentation::kTagged, if_exception_count),
        if_exception_count + 1, &if_exceptions->front());
    ReplaceWithValue(if_exception, phi, ephi, merge);
  }

  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

Reduction JSNativeContextSpecialization::ReduceJSLoadNamed(Node* node) {
  JSLoadNamedNode n(node);
  NamedAccess const& p = n.Parameters();
  Node* const receiver = n.object();
  NameRef name = p.name();

  // Check if we have a constant receiver.
  HeapObjectMatcher m(receiver);
  if (m.HasResolvedValue()) {
    ObjectRef object = m.Ref(broker());
    if (object.IsJSFunction() && name.equals(broker()->prototype_string())) {
      // Optimize "prototype" property of functions.
      JSFunctionRef function = object.AsJSFunction();
      // TODO(neis): Remove the has_prototype_slot condition once the broker is
      // always enabled.
      if (!function.map(broker()).has_prototype_slot() ||
          !function.has_instance_prototype(broker()) ||
          function.PrototypeRequiresRuntimeLookup(broker())) {
        return NoChange();
      }
      HeapObjectRef prototype =
          dependencies()->DependOnPrototypeProperty(function);
      Node* value = jsgraph()->ConstantNoHole(prototype, broker());
      ReplaceWithValue(node, value);
      return Replace(value);
    } else if (object.IsString() && name.equals(broker()->length_string())) {
      // Constant-fold "length" property on constant strings.
      Node* value = jsgraph()->ConstantNoHole(object.AsString().length());
      ReplaceWithValue(node, value);
      return Replace(value);
    }
  }

  if (!p.feedback().IsValid()) return NoChange();
  return ReducePropertyAccess(node, nullptr, name, jsgraph()->Dead(),
                              FeedbackSource(p.feedback()), AccessMode::kLoad);
}

Reduction JSNativeContextSpecialization::ReduceJSLoadNamedFromSuper(
    Node* node) {
  JSLoadNamedFromSuperNode n(node);
  NamedAccess const& p = n.Parameters();
  NameRef name = p.name();

  if (!p.feedback().IsValid()) return NoChange();
  return ReducePropertyAccess(node, nullptr, name, jsgraph()->Dead(),
                              FeedbackSource(p.feedback()), AccessMode::kLoad);
}

Reduction JSNativeContextSpecialization::ReduceJSGetIterator(Node* node) {
  JSGetIteratorNode n(node);
  GetIteratorParameters const& p = n.Parameters();

  TNode<Object> receiver = n.receiver();
  TNode<Object> context = n.context();
  FrameState frame_state = n.frame_state();
  Effect effect = n.effect();
  Control control = n.control();

  Node* iterator_exception_node = nullptr;
  Node* if_exception_merge = nullptr;
  Node* if_exception_effect_phi = nullptr;
  Node* if_exception_phi = nullptr;
  bool has_exception_node =
      NodeProperties::IsExceptionalCall(node, &iterator_exception_node);
  int exception_node_index = 0;
  if (has_exception_node) {
    DCHECK_NOT_NULL(iterator_exception_node);
    // If there exists an IfException node for the iterator node, we need
    // to merge all the desugared nodes exception. The iterator node will be
    // desugared to LoadNamed, Call, CallRuntime, we can pre-allocate the
    // nodes with 4 inputs here and we use dead_node as a placeholder for the
    // input, which will be replaced.
    // We use dead_node as a placeholder for the original exception node before
    // it's uses are rewired.

    Node* dead_node = jsgraph()->Dead();
    if_exception_merge =
        graph()->NewNode(common()->Merge(5), dead_node, dead_node, dead_node,
                         dead_node, dead_node);
    if_exception_effect_phi =
        graph()->NewNode(common()->EffectPhi(5), dead_node, dead_node,
                         dead_node, dead_node, dead_node, if_exception_merge);
    if_exception_phi = graph()->NewNode(
        common()->Phi(MachineRepresentation::kTagged, 5), dead_node, dead_node,
        dead_node, dead_node, dead_node, if_exception_merge);
    // Rewire the original exception node uses.
    ReplaceWithValue(iterator_exception_node, if_exception_phi,
                     if_exception_effect_phi, if_exception_merge);
    if_exception_merge->ReplaceInput(exception_node_index,
                                     iterator_exception_node);
    if_exception_effect_phi->ReplaceInput(exception_node_index,
                                          iterator_exception_node);
    if_exception_phi->ReplaceInput(exception_node_index,
                                   iterator_exception_node);
    exception_node_index++;
  }

  // Load iterator property operator
  NameRef iterator_symbol = broker()->iterator_symbol();
  const Operator* load_op =
      javascript()->LoadNamed(iterator_symbol, p.loadFeedback());

  // Lazy deopt of the load iterator property
  // TODO(v8:10047): Use TaggedIndexConstant here once deoptimizer supports it.
  Node* call_slot = jsgraph()->SmiConstant(p.callFeedback().slot.ToInt());
  Node* call_feedback = jsgraph()->HeapConstantNoHole(p.callFeedback().vector);
  Node* lazy_deopt_parameters[] = {receiver, call_slot, call_feedback};
  Node* lazy_deopt_frame_state = CreateStubBuiltinContinuationFrameState(
      jsgraph(), Builtin::kGetIteratorWithFeedbackLazyDeoptContinuation,
      context, lazy_deopt_parameters, arraysize(lazy_deopt_parameters),
      frame_state, ContinuationFrameStateMode::LAZY);
  Node* load_property =
      graph()->NewNode(load_op, receiver, n.feedback_vector(), context,
                       lazy_deopt_frame_state, effect, control);
  effect = load_property;
  control = load_property;

  // Merge the exception path for LoadNamed.
  if (has_exception_node) {
    Node* if_exception =
        graph()->NewNode(common()->IfException(), effect, control);
    if_exception_merge->ReplaceInput(exception_node_index, if_exception);
    if_exception_phi->ReplaceInput(exception_node_index, if_exception);
    if_exception_effect_phi->ReplaceInput(exception_node_index, if_exception);
    exception_node_index++;
    control = graph()->NewNode(common()->IfSuccess(), control);
  }

  Node* check = graph()->NewNode(simplified()->ReferenceEqual(), load_property,
                                 jsgraph()->UndefinedConstant());
  Node* branch =
      graph()->NewNode(common()->Branch(BranchHint::kFalse), check, control);

  {
    Node* if_not_iterator = graph()->NewNode(common()->IfTrue(), branch);
    Node* effect_not_iterator = effect;
    Node* control_not_iterator = if_not_iterator;
    Node* call_runtime = effect_not_iterator = control_not_iterator =
        graph()->NewNode(
            javascript()->CallRuntime(Runtime::kThrowIteratorError, 1),
            receiver, context, frame_state, effect_not_iterator,
            control_not_iterator);
    // Merge the exception path for CallRuntime.
    if (has_exception_node) {
      Node* if_exception = graph()->NewNode(
          common()->IfException(), effect_not_iterator, control_not_iterator);
      if_exception_merge->ReplaceInput(exception_node_index, if_exception);
      if_exception_phi->ReplaceInput(exception_node_index, if_exception);
      if_exception_effect_phi->ReplaceInput(exception_node_index, if_exception);
      exception_node_index++;
      control_not_iterator =
          graph()->NewNode(common()->IfSuccess(), control_not_iterator);
    }
    Node* throw_node =
        graph()->NewNode(common()->Throw(), call_runtime, control_not_iterator);
    MergeControlToEnd(graph(), common(), throw_node);
  }

  control = graph()->NewNode(common()->IfFalse(), branch);

  // Eager deopt of call iterator property
  Node* parameters[] = {receiver, load_property, call_slot, call_feedback};
  Node* eager_deopt_frame_state = CreateStubBuiltinContinuationFrameState(
      jsgraph(), Builtin::kCallIteratorWithFeedback, context, parameters,
      arraysize(parameters), frame_state, ContinuationFrameStateMode::EAGER);
  Node* deopt_checkpoint = graph()->NewNode(
      common()->Checkpoint(), eager_deopt_frame_state, effect, control);
  effect = deopt_checkpoint;

  // Call iterator property operator
  ProcessedFeedback const& feedback =
      broker()->GetFeedbackForCall(p.callFeedback());
  SpeculationMode mode = feedback.IsInsufficient()
                             ? SpeculationMode::kDisallowSpeculation
                             : feedback.AsCall().speculation_mode();
  const Operator* call_op = javascript()->Call(
      JSCallNode::ArityForArgc(0), CallFrequency(), p.callFeedback(),
      ConvertReceiverMode::kNotNullOrUndefined, mode,
      CallFeedbackRelation::kTarget);
  // Lazy deopt to check the call result is JSReceiver.
  Node* call_lazy_deopt_frame_state = CreateStubBuiltinContinuationFrameState(
      jsgraph(), Builtin::kCallIteratorWithFeedbackLazyDeoptContinuation,
      context, nullptr, 0, frame_state, ContinuationFrameStateMode::LAZY);
  Node* call_property = effect = control =
      graph()->NewNode(call_op, load_property, receiver, n.feedback_vector(),
                       context, call_lazy_deopt_frame_state, effect, control);

  // Merge the exception path for Call.
  if (has_exception_node) {
    Node* if_exception =
        graph()->NewNode(common()->IfException(), effect, control);
    if_exception_merge->ReplaceInput(exception_node_index, if_exception);
    if_exception_phi->ReplaceInput(exception_node_index, if_exception);
    if_exception_effect_phi->ReplaceInput(exception_node_index, if_exception);
    exception_node_index++;
    control = graph()->NewNode(common()->IfSuccess(), control);
  }

  // If the result is not JSReceiver, throw invalid iterator exception.
  Node* is_receiver =
      graph()->NewNode(simplified()->ObjectIsReceiver(), call_property);
  Node* branch_node = graph()->NewNode(common()->Branch(BranchHint::kTrue),
                                       is_receiver, control);
  {
    Node* if_not_receiver = graph()->NewNode(common()->IfFalse(), branch_node);
    Node* effect_not_receiver = effect;
    Node* control_not_receiver = if_not_receiver;
    Node* call_runtime = effect_not_receiver = control_not_receiver =
        graph()->NewNode(
            javascript()->CallRuntime(Runtime::kThrowSymbolIteratorInvalid, 0),
            context, frame_state, effect_not_receiver, control_not_receiver);
    // Merge the exception path for CallRuntime.
    if (has_exception_node) {
      Node* if_exception = graph()->NewNode(
          common()->IfException(), effect_not_receiver, control_not_receiver);
      if_exception_merge->ReplaceInput(exception_node_index, if_exception);
      if_exception_phi->ReplaceInput(exception_node_index, if_exception);
      if_exception_effect_phi->ReplaceInput(exception_node_index, if_exception);
      exception_node_index++;
      control_not_receiver =
          graph()->NewNode(common()->IfSuccess(), control_not_receiver);
    }
    Node* throw_node =
        graph()->NewNode(common()->Throw(), call_runtime, control_not_receiver);
    MergeControlToEnd(graph(), common(), throw_node);
  }
  Node* if_receiver = graph()->NewNode(common()->IfTrue(), branch_node);
  ReplaceWithValue(node, call_property, effect, if_receiver);

  if (has_exception_node) {
    DCHECK_EQ(exception_node_index, if_exception_merge->InputCount());
    DCHECK_EQ(exception_node_index, if_exception_effect_phi->InputCount() - 1);
    DCHECK_EQ(exception_node_index, if_exception_phi->InputCount() - 1);
#ifdef DEBUG
    for (Node* input : if_exception_merge->inputs()) {
      DCHECK(!input->IsDead());
    }
    for (Node* input : if_exception_effect_phi->inputs()) {
      DCHECK(!input->IsDead());
    }
    for (Node* input : if_exception_phi->inputs()) {
      DCHECK(!input->IsDead());
    }
#endif
  }
  return Replace(if_receiver);
}

Reduction JSNativeContextSpecialization::ReduceJSSetNamedProperty(Node* node) {
  JSSetNamedPropertyNode n(node);
  NamedAccess const& p = n.Parameters();
  if (!p.feedback().IsValid()) return NoChange();
  return ReducePropertyAccess(node, nullptr, p.name(), n.value(),
                              FeedbackSource(p.feedback()), AccessMode::kStore);
}

Reduction JSNativeContextSpecialization::ReduceJSDefineNamedOwnProperty(
    Node* node) {
  JSDefineNamedOwnPropertyNode n(node);
  DefineNamedOwnPropertyParameters const& p = n.Parameters();
  if (!p.feedback().IsValid()) return NoChange();
  return ReducePropertyAccess(node, nullptr, p.name(), n.value(),
                              FeedbackSource(p.feedback()),
                              AccessMode::kStoreInLiteral);
}

Reduction JSNativeContextSpecialization::ReduceElementAccessOnString(
    Node* node, Node* index, Node* value, KeyedAccessMode const& keyed_mode) {
  Node* receiver = NodeProperties::GetValueInput(node, 0);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  // Strings are immutable in JavaScript.
  if (keyed_mode.access_mode() == AccessMode::kStore) return NoChange();

  // `in` cannot be used on strings.
  if (keyed_mode.access_mode() == AccessMode::kHas) return NoChange();

  // Ensure that the {receiver} is actually a String.
  receiver = effect = graph()->NewNode(
      simplified()->CheckString(FeedbackSource()), receiver, effect, control);

  // Determine the {receiver} length.
  Node* length = graph()->NewNode(simplified()->StringLength(), receiver);

  // Load the single character string from {receiver} or yield undefined
  // if the {index} is out of bounds (depending on the {load_mode}).
  value = BuildIndexedStringLoad(receiver, index, length, &effect, &control,
                                 keyed_mode.load_mode());

  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

namespace {

OptionalJSTypedArrayRef GetTypedArrayConstant(JSHeapBroker* broker,
                                              Node* receiver) {
  HeapObjectMatcher m(receiver);
  if (!m.HasResolvedValue()) return std::nullopt;
  ObjectRef object = m.Ref(broker);
  if (!object.IsJSTypedArray()) return std::nullopt;
  JSTypedArrayRef typed_array = object.AsJSTypedArray();
  if (typed_array.is_on_heap()) return std::nullopt;
  return typed_array;
}

}  // namespace

void JSNativeContextSpecialization::RemoveImpossibleMaps(
    Node* object, ZoneVector<MapRef>* maps) const {
  OptionalMapRef root_map = InferRootMap(object);
  if (root_map.has_value() && !root_map->is_abandoned_prototype_map()) {
    maps->erase(
        std::remove_if(maps->begin(), maps->end(),
                       [root_map, this](MapRef map) {
                         return map.is_abandoned_prototype_map() ||
                                !map.FindRootMap(broker()).equals(*root_map);
                       }),
        maps->end());
  }
}

// Possibly refine the feedback using inferred map information from the graph.
ElementAccessFeedback const&
JSNativeContextSpecialization::TryRefineElementAccessFeedback(
    ElementAccessFeedback const& feedback, Node* receiver,
    Effect effect) const {
  AccessMode access_mode = feedback.keyed_mode().access_mode();
  bool use_inference =
      access_mode == AccessMode::kLoad || access_mode == AccessMode::kHas;
  if (!use_inference) return feedback;

  ZoneVector<MapRef> inferred_maps(zone());
  if (!InferMaps(receiver, effect, &inferred_maps)) return feedback;

  RemoveImpossibleMaps(receiver, &inferred_maps);
  // TODO(neis): After Refine, the resulting feedback can still contain
  // impossible maps when a target is kept only because more than one of its
  // sources was inferred. Think of a way to completely rule out impossible
  // maps.
  return feedback.Refine(broker(), inferred_maps);
}

Reduction JSNativeContextSpecialization::ReduceElementAccess(
    Node* node, Node* index, Node* value,
    ElementAccessFeedback const& feedback) {
  DCHECK(node->opcode() == IrOpcode::kJSLoadProperty ||
         node->opcode() == IrOpcode::kJSSetKeyedProperty ||
         node->opcode() == IrOpcode::kJSStoreInArrayLiteral ||
         node->opcode() == IrOpcode::kJSDefineKeyedOwnPropertyInLiteral ||
         node->opcode() == IrOpcode::kJSHasProperty ||
         node->opcode() == IrOpcode::kJSDefineKeyedOwnProperty);
  static_assert(JSLoadPropertyNode::ObjectIndex() == 0 &&
                JSSetKeyedPropertyNode::ObjectIndex() == 0 &&
                JSStoreInArrayLiteralNode::ArrayIndex() == 0 &&
                JSDefineKeyedOwnPropertyInLiteralNode::ObjectIndex() == 0 &&
                JSHasPropertyNode::ObjectIndex() == 0);

  Node* receiver = NodeProperties::GetValueInput(node, 0);
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};
  Node* context = NodeProperties::GetContextInput(node);

  // TODO(neis): It's odd that we do optimizations below that don't really care
  // about the feedback, but we don't do them when the feedback is megamorphic.
  if (feedback.transition_groups().empty()) return NoChange();

  ElementAccessFeedback const& refined_feedback =
      TryRefineElementAccessFeedback(feedback, receiver, effect);

  AccessMode access_mode = refined_feedback.keyed_mode().access_mode();
  if ((access_mode == AccessMode::kLoad || access_mode == AccessMode::kHas) &&
      receiver->opcode() == IrOpcode::kHeapConstant) {
    Reduction reduction = ReduceElementLoadFromHeapConstant(
        node, index, access_mode, refined_feedback.keyed_mode().load_mode());
    if (reduction.Changed()) return reduction;
  }

  if (!refined_feedback.transition_groups().empty() &&
      refined_feedback.HasOnlyStringMaps(broker())) {
    return ReduceElementAccessOnString(node, index, value,
                                       refined_feedback.keyed_mode());
  }

  AccessInfoFactory access_info_factory(broker(), graph()->zone());
  ZoneVector<ElementAccessInfo> access_infos(zone());
  if (!access_info_factory.ComputeElementAccessInfos(refined_feedback,
                                                     &access_infos) ||
      access_infos.empty()) {
    return NoChange();
  }

  // Do not optimize AccessMode::kDefine for typed arrays.
  if (access_mode == AccessMode::kDefine) {
    for (const ElementAccessInfo& access_info : access_infos) {
      if (IsTypedArrayOrRabGsabTypedArrayElementsKind(
              access_info.elements_kind())) {
        return NoChange();
      }
    }
  }

  // Do not optimize Float16 typed arrays, since they are not yet supported by
  // the rest of the compiler.
  // TODO(v8:14012): We could lower further here and emit LoadTypedElement (like
  // we do for other typed arrays). However, given the lack of hardware support
  // for Float16 operations, it's not clear whether optimizing further would be
  // really useful.
  for (const ElementAccessInfo& access_info : access_infos) {
    if (IsFloat16TypedArrayElementsKind(access_info.elements_kind())) {
      return NoChange();
    }
  }

  // For holey stores or growing stores, we need to check that the prototype
  // chain contains no setters for elements, and we need to guard those checks
  // via code dependencies on the relevant prototype maps.
  if (access_mode == AccessMode::kStore) {
    // TODO(turbofan): We could have a fast path here, that checks for the
    // common case of Array or Object prototype only and therefore avoids
    // the zone allocation of this vector.
    ZoneVector<MapRef> prototype_maps(zone());
    for (ElementAccessInfo const& access_info : access_infos) {
      for (MapRef receiver_map : access_info.lookup_start_object_maps()) {
        // If the {receiver_map} has a prototype and its elements backing
        // store is either holey, or we have a potentially growing store,
        // then we need to check that all prototypes have stable maps with
        // no element accessors and no throwing behavior for elements (and we
        // need to guard against changes to that below).
        if ((IsHoleyOrDictionaryElementsKind(receiver_map.elements_kind()) ||
             StoreModeCanGrow(feedback.keyed_mode().store_mode())) &&
            !receiver_map.PrototypesElementsDoNotHaveAccessorsOrThrow(
                broker(), &prototype_maps)) {
          return NoChange();
        }

        // TODO(v8:12547): Support writing to objects in shared space, which
        // need a write barrier that calls Object::Share to ensure the RHS is
        // shared.
        if (InstanceTypeChecker::IsAlwaysSharedSpaceJSObject(
                receiver_map.instance_type())) {
          return NoChange();
        }
      }
    }
    for (MapRef prototype_map : prototype_maps) {
      dependencies()->DependOnStableMap(prototype_map);
    }
  } else if (access_mode == AccessMode::kHas) {
    // If we have any fast arrays, we need to check and depend on
    // NoElementsProtector.
    for (ElementAccessInfo const& access_info : access_infos) {
      if (IsFastElementsKind(access_info.elements_kind())) {
        if (!dependencies()->DependOnNoElementsProtector()) return NoChange();
        break;
      }
    }
  }

  // Check for the monomorphic case.
  PropertyAccessBuilder access_builder(jsgraph(), broker());
  if (access_infos.size() == 1) {
    ElementAccessInfo access_info = access_infos.front();

    // Perform possible elements kind transitions.
    MapRef transition_target = access_info.lookup_start_object_maps().front();
    for (MapRef transition_source : access_info.transition_sources()) {
      DCHECK_EQ(access_info.lookup_start_object_maps().size(), 1);
      effect = graph()->NewNode(
          simplified()->TransitionElementsKind(ElementsTransition(
              IsSimpleMapChangeTransition(transition_source.elements_kind(),
                                          transition_target.elements_kind())
                  ? ElementsTransition::kFastTransition
                  : ElementsTransition::kSlowTransition,
              transition_source, transition_target)),
          receiver, effect, control);
    }

    // TODO(turbofan): The effect/control linearization will not find a
    // FrameState after the StoreField or Call that is generated for the
    // elements kind transition above. This is because those operators
    // don't have the kNoWrite flag on it, even though they are not
    // observable by JavaScript.
    Node* frame_state =
        NodeProperties::FindFrameStateBefore(node, jsgraph()->Dead());
    effect =
        graph()->NewNode(common()->Checkpoint(), frame_state, effect, control);

    // Perform map check on the {receiver}.
    access_builder.BuildCheckMaps(receiver, &effect, control,
                                  access_info.lookup_start_object_maps());

    // Access the actual element.
    ValueEffectControl continuation =
        BuildElementAccess(receiver, index, value, effect, control, context,
                           access_info, feedback.keyed_mode());
    value = continuation.value();
    effect = continuation.effect();
    control = continuation.control();
  } else {
    // The final states for every polymorphic branch. We join them with
    // Merge+Phi+EffectPhi at the bottom.
    ZoneVector<Node*> values(zone());
    ZoneVector<Node*> effects(zone());
    ZoneVector<Node*> controls(zone());

    // Generate code for the various different element access patterns.
    Node* fallthrough_control = control;
    for (size_t j = 0; j < access_infos.size(); ++j) {
      ElementAccessInfo const& access_info = access_infos[j];
      Node* this_receiver = receiver;
      Node* this_value = value;
      Node* this_index = index;
      Effect this_effect = effect;
      Control this_control{fallthrough_control};

      // Perform possible elements kind transitions.
      MapRef transition_target = access_info.lookup_start_object_maps().front();
      for (MapRef transition_source : access_info.transition_sources()) {
        DCHECK_EQ(access_info.lookup_start_object_maps().size(), 1);
        this_effect = graph()->NewNode(
            simplified()->TransitionElementsKind(ElementsTransition(
                IsSimpleMapChangeTransition(transition_source.elements_kind(),
                                            transition_target.elements_kind())
                    ? ElementsTransition::kFastTransition
                    : ElementsTransition::kSlowTransition,
                transition_source, transition_target)),
            receiver, this_effect, this_control);
      }

      // Perform map check(s) on {receiver}.
      ZoneVector<MapRef> const& receiver_maps =
          access_info.lookup_start_object_maps();
      if (j == access_infos.size() - 1) {
        // Last map check on the fallthrough control path, do a
        // conditional eager deoptimization exit here.
        access_builder.BuildCheckMaps(receiver, &this_effect, this_control,
                                      receiver_maps);
        fallthrough_control = nullptr;
      } else {
        // Explicitly branch on the {receiver_maps}.
        ZoneRefSet<Map> maps(receiver_maps.begin(), receiver_maps.end(),
                             graph()->zone());
        Node* check = this_effect =
            graph()->NewNode(simplified()->CompareMaps(maps), receiver,
                             this_effect, fallthrough_control);
        Node* branch =
            graph()->NewNode(common()->Branch(), check, fallthrough_control);
        fallthrough_control = graph()->NewNode(common()->IfFalse(), branch);
        this_control = graph()->NewNode(common()->IfTrue(), branch);

        // Introduce a MapGuard to learn from this on the effect chain.
        this_effect = graph()->NewNode(simplified()->MapGuard(maps), receiver,
                                       this_effect, this_control);
      }

      // Access the actual element.
      ValueEffectControl continuation = BuildElementAccess(
          this_receiver, this_index, this_value, this_effect, this_control,
          context, access_info, feedback.keyed_mode());
      values.push_back(continuation.value());
      effects.push_back(continuation.effect());
      controls.push_back(continuation.control());
    }

    DCHECK_NULL(fallthrough_control);

    // Generate the final merge point for all (polymorphic) branches.
    int const control_count = static_cast<int>(controls.size());
    if (control_count == 0) {
      value = effect = control = jsgraph()->Dead();
    } else if (control_count == 1) {
      value = values.front();
      effect = effects.front();
      control = controls.front();
    } else {
      control = graph()->NewNode(common()->Merge(control_count), control_count,
                                 &controls.front());
      values.push_back(control);
      value = graph()->NewNode(
          common()->Phi(MachineRepresentation::kTagged, control_count),
          control_count + 1, &values.front());
      effects.push_back(control);
      effect = graph()->NewNode(common()->EffectPhi(control_count),
                                control_count + 1, &effects.front());
    }
  }

  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

Reduction JSNativeContextSpecialization::ReduceElementLoadFromHeapConstant(
    Node* node, Node* key, AccessMode access_mode,
    KeyedAccessLoadMode load_mode) {
  DCHECK(node->opcode() == IrOpcode::kJSLoadProperty ||
         node->opcode() == IrOpcode::kJSHasProperty);
  Node* receiver = NodeProperties::GetValueInput(node, 0);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  HeapObjectMatcher mreceiver(receiver);
  HeapObjectRef receiver_ref = mreceiver.Ref(broker());
  if (receiver_ref.IsNull() || receiver_ref.IsUndefined() ||
      // The 'in' operator throws a TypeError on primitive values.
      (receiver_ref.IsString() && access_mode == AccessMode::kHas)) {
    return NoChange();
  }

  // Check whether we're accessing a known element on the {receiver} and can
  // constant-fold the load.
  NumberMatcher mkey(key);
  if (mkey.IsInteger() &&
      mkey.IsInRange(0.0, static_cast<double>(JSObject::kMaxElementIndex))) {
    static_assert(JSObject::kMaxElementIndex <= kMaxUInt32);
    const uint32_t index = static_cast<uint32_t>(mkey.ResolvedValue());
    OptionalObjectRef element;

    if (receiver_ref.IsJSObject()) {
      JSObjectRef jsobject_ref = receiver_ref.AsJSObject();
      OptionalFixedArrayBaseRef elements =
          jsobject_ref.elements(broker(), kRelaxedLoad);
      if (elements.has_value()) {
        element = jsobject_ref.GetOwnConstantElement(broker(), *elements, index,
                                                     dependencies());
        if (!element.has_value() && receiver_ref.IsJSArray()) {
          // We didn't find a constant element, but if the receiver is a
          // cow-array we can exploit the fact that any future write to the
          // element will replace the whole elements storage.
          element = receiver_ref.AsJSArray().GetOwnCowElement(broker(),
                                                              *elements, index);
          if (element.has_value()) {
            Node* actual_elements = effect = graph()->NewNode(
                simplified()->LoadField(AccessBuilder::ForJSObjectElements()),
                receiver, effect, control);
            Node* check = graph()->NewNode(
                simplified()->ReferenceEqual(), actual_elements,
                jsgraph()->ConstantNoHole(*elements, broker()));
            effect = graph()->NewNode(
                simplified()->CheckIf(
                    DeoptimizeReason::kCowArrayElementsChanged),
                check, effect, control);
          }
        }
      }
    } else if (receiver_ref.IsString()) {
      element =
          receiver_ref.AsString().GetCharAsStringOrUndefined(broker(), index);
    }

    if (element.has_value()) {
      Node* value = access_mode == AccessMode::kHas
                        ? jsgraph()->TrueConstant()
                        : jsgraph()->ConstantNoHole(*element, broker());
      ReplaceWithValue(node, value, effect, control);
      return Replace(value);
    }
  }

  // For constant Strings we can eagerly strength-reduce the keyed
  // accesses using the known length, which doesn't change.
  if (receiver_ref.IsString()) {
    DCHECK_NE(access_mode, AccessMode::kHas);
    // Ensure that {key} is less than {receiver} length.
    Node* length = jsgraph()->ConstantNoHole(receiver_ref.AsString().length());

    // Load the single character string from {receiver} or yield
    // undefined if the {key} is out of bounds (depending on the
    // {load_mode}).
    Node* value = BuildIndexedStringLoad(receiver, key, length, &effect,
                                         &control, load_mode);
    ReplaceWithValue(node, value, effect, control);
    return Replace(value);
  }

  return NoChange();
}

Reduction JSNativeContextSpecialization::ReducePropertyAccess(
    Node* node, Node* key, OptionalNameRef static_name, Node* value,
    FeedbackSource const& source, AccessMode access_mode) {
  DCHECK_EQ(key == nullptr, static_name.has_value());
  DCHECK(node->opcode() == IrOpcode::kJSLoadProperty ||
         node->opcode() == IrOpcode::kJSSetKeyedProperty ||
         node->opcode() == IrOpcode::kJSStoreInArrayLiteral ||
         node->opcode() == IrOpcode::kJSDefineKeyedOwnPropertyInLiteral ||
         node->opcode() == IrOpcode::kJSHasProperty ||
         node->opcode() == IrOpcode::kJSLoadNamed ||
         node->opcode() == IrOpcode::kJSSetNamedProperty ||
         node->opcode() == IrOpcode::kJSDefineNamedOwnProperty ||
         node->opcode() == IrOpcode::kJSLoadNamedFromSuper ||
         node->opcode() == IrOpcode::kJSDefineKeyedOwnProperty);
  DCHECK_GE(node->op()->ControlOutputCount(), 1);

  ProcessedFeedback const* feedback =
      &broker()->GetFeedbackForPropertyAccess(source, access_mode, static_name);

  if (feedback->kind() == ProcessedFeedback::kElementAccess &&
      feedback->AsElementAccess().transition_groups().empty()) {
    HeapObjectMatcher m_key(key);
    if (m_key.HasResolvedValue() && m_key.Ref(broker()).IsName()) {
      NameRef name_key = m_key.Ref(broker()).AsName();
      if (name_key.IsUniqueName() && !name_key.object()->IsArrayIndex()) {
        feedback = &feedback->AsElementAccess().Refine(
            broker(), m_key.Ref(broker()).AsName());
      }
    }
  }

  switch (feedback->kind()) {
    case ProcessedFeedback::kInsufficient:
      return ReduceEagerDeoptimize(
          node,
          DeoptimizeReason::kInsufficientTypeFeedbackForGenericNamedAccess);
    case ProcessedFeedback::kNamedAccess:
      return ReduceNamedAccess(node, value, feedback->AsNamedAccess(),
                               access_mode, key);
    case ProcessedFeedback::kMegaDOMPropertyAccess:
      DCHECK_EQ(access_mode, AccessMode::kLoad);
      DCHECK_NULL(key);
      return ReduceMegaDOMPropertyAccess(
          node, value, feedback->AsMegaDOMPropertyAccess(), source);
    case ProcessedFeedback::kElementAccess:
      DCHECK_EQ(feedback->AsElementAccess().keyed_mode().access_mode(),
                access_mode);
      DCHECK_NE(node->opcode(), IrOpcode::kJSLoadNamedFromSuper);
      return ReduceElementAccess(node, key, value, feedback->AsElementAccess());
    default:
      UNREACHABLE();
  }
}

Reduction JSNativeContextSpecialization::ReduceEagerDeoptimize(
    Node* node, DeoptimizeReason reason) {
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

Reduction JSNativeContextSpecialization::ReduceJSHasProperty(Node* node) {
  JSHasPropertyNode n(node);
  PropertyAccess const& p = n.Parameters();
  Node* value = jsgraph()->Dead();
  if (!p.feedback().IsValid()) return NoChange();
  return ReducePropertyAccess(node, n.key(), std::nullopt, value,
                              FeedbackSource(p.feedback()), AccessMode::kHas);
}

Reduction JSNativeContextSpecialization::ReduceJSLoadPropertyWithEnumeratedKey(
    Node* node) {
  // We can optimize a property load if it's being used inside a for..in:
  //   for (name in receiver) {
  //     value = receiver[name];
  //     ...
  //   }
  //
  // If the for..in is in fast-mode, we know that the {receiver} has {name}
  // as own property, otherwise the enumeration wouldn't include it. The graph
  // constructed by the BytecodeGraphBuilder in this case looks like this:

  // receiver
  //  ^    ^
  //  |    |
  //  |    +-+
  //  |      |
  //  |   JSToObject
  //  |      ^
  //  |      |
  //  |      |
  //  |  JSForInNext
  //  |      ^
  //  |      |
  //  +----+ |
  //       | |
  //       | |
  //   JSLoadProperty

  // If the for..in has only seen maps with enum cache consisting of keys
  // and indices so far, we can turn the {JSLoadProperty} into a map check
  // on the {receiver} and then just load the field value dynamically via
  // the {LoadFieldByIndex} operator. The map check is only necessary when
  // TurboFan cannot prove that there is no observable side effect between
  // the {JSForInNext} and the {JSLoadProperty} node.
  //
  // We can do a similar optimization when the receiver of {JSLoadProperty} is
  // not identical to the receiver of {JSForInNext}:
  //   for (name in receiver) {
  //     value = object[name];
  //     ...
  //   }
  //
  // This is because when the key is {JSForInNext}, we will generate a
  // {GetEnumeratedKeyedProperty} bytecode for {JSLoadProperty}. If the bytecode
  // always manages to use the enum cache, we will keep the inline cache in
  // uninitialized state. So If the graph is as below, we can firstly do a map
  // check on {object} and then turn the {JSLoadProperty} into the
  // {LoadFieldByIndex}. This is also safe when the bytecode has never been
  // profiled. When it happens to pass the the map check, we can use the fast
  // path. Otherwise it will trigger a deoptimization.

  // object     receiver
  //  ^             ^
  //  |             |
  //  |             |
  //  |             |
  //  |        JSToObject
  //  |             ^
  //  |             |
  //  |             |
  //  |        JSForInNext
  //  |             ^
  //  |             |
  //  +----+  +-----+
  //       |  |
  //       |  |
  //   JSLoadProperty (insufficient feedback)

  // Also note that it's safe to look through the {JSToObject}, since the
  // [[Get]] operation does an implicit ToObject anyway, and these operations
  // are not observable.

  DCHECK_EQ(IrOpcode::kJSLoadProperty, node->opcode());
  Node* receiver = NodeProperties::GetValueInput(node, 0);
  JSForInNextNode name(NodeProperties::GetValueInput(node, 1));
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  if (name.Parameters().mode() != ForInMode::kUseEnumCacheKeysAndIndices) {
    return NoChange();
  }

  Node* object = name.receiver();
  Node* cache_type = name.cache_type();
  Node* index = name.index();
  if (object->opcode() == IrOpcode::kJSToObject) {
    object = NodeProperties::GetValueInput(object, 0);
  }
  bool speculating_object_is_receiver = false;
  if (object != receiver) {
    JSLoadPropertyNode n(node);
    PropertyAccess const& p = n.Parameters();

    ProcessedFeedback const& feedback = broker()->GetFeedbackForPropertyAccess(
        FeedbackSource(p.feedback()), AccessMode::kLoad, std::nullopt);
    // When the feedback is uninitialized, it is either a load from a
    // {GetEnumeratedKeyedProperty} which always hits the enum cache, or a keyed
    // load that had never been reached. In either case, we can check the map
    // of the receiver and use the enum cache if the map match the {cache_type}.
    if (feedback.kind() != ProcessedFeedback::kInsufficient) {
      return NoChange();
    }

    // Ensure that {receiver} is a HeapObject.
    receiver = effect = graph()->NewNode(simplified()->CheckHeapObject(),
                                         receiver, effect, control);
    speculating_object_is_receiver = true;
  }

  // No need to repeat the map check if we can prove that there's no
  // observable side effect between {effect} and {name]. But we always need a
  // map check when {object} is not identical to {receiver}.
  if (!NodeProperties::NoObservableSideEffectBetween(effect, name) ||
      speculating_object_is_receiver) {
    // Check that the {receiver} map is still valid.
    Node* receiver_map = effect =
        graph()->NewNode(simplified()->LoadField(AccessBuilder::ForMap()),
                         receiver, effect, control);
    Node* check = graph()->NewNode(simplified()->ReferenceEqual(), receiver_map,
                                   cache_type);
    effect =
        graph()->NewNode(simplified()->CheckIf(DeoptimizeReason::kWrongMap),
                         check, effect, control);
  }

  // Load the enum cache indices from the {cache_type}.
  Node* descriptor_array = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForMapDescriptors()), cache_type,
      effect, control);
  Node* enum_cache = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForDescriptorArrayEnumCache()),
      descriptor_array, effect, control);
  Node* enum_indices = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForEnumCacheIndices()), enum_cache,
      effect, control);

  // Ensure that the {enum_indices} are valid.
  Node* check = graph()->NewNode(
      simplified()->BooleanNot(),
      graph()->NewNode(simplified()->ReferenceEqual(), enum_indices,
                       jsgraph()->EmptyFixedArrayConstant()));
  effect = graph()->NewNode(
      simplified()->CheckIf(DeoptimizeReason::kWrongEnumIndices), check, effect,
      control);

  // Determine the key from the {enum_indices}.
  Node* key = effect = graph()->NewNode(
      simplified()->LoadElement(
          AccessBuilder::ForFixedArrayElement(PACKED_SMI_ELEMENTS)),
      enum_indices, index, effect, control);

  // Load the actual field value.
  Node* value = effect = graph()->NewNode(simplified()->LoadFieldByIndex(),
                                          receiver, key, effect, control);
  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

Reduction JSNativeContextSpecialization::ReduceJSLoadProperty(Node* node) {
  JSLoadPropertyNode n(node);
  PropertyAccess const& p = n.Parameters();
  Node* name = n.key();

  if (name->opcode() == IrOpcode::kJSForInNext) {
    Reduction reduction = ReduceJSLoadPropertyWithEnumeratedKey(node);
    if (reduction.Changed()) return reduction;
  }

  if (!p.feedback().IsValid()) return NoChange();
  Node* value = jsgraph()->Dead();
  return ReducePropertyAccess(node, name, std::nullopt, value,
                              FeedbackSource(p.feedback()), AccessMode::kLoad);
}

Reduction JSNativeContextSpecialization::ReduceJSSetKeyedProperty(Node* node) {
  JSSetKeyedPropertyNode n(node);
  PropertyAccess const& p = n.Parameters();
  if (!p.feedback().IsValid()) return NoChange();
  return ReducePropertyAccess(node, n.key(), std::nullopt, n.value(),
                              FeedbackSource(p.feedback()), AccessMode::kStore);
}

Reduction JSNativeContextSpecialization::ReduceJSDefineKeyedOwnProperty(
    Node* node) {
  JSDefineKeyedOwnPropertyNode n(node);
  PropertyAccess const& p = n.Parameters();
  if (!p.feedback().IsValid()) return NoChange();
  return ReducePropertyAccess(node, n.key(), std::nullopt, n.value(),
                              FeedbackSource(p.feedback()),
                              AccessMode::kDefine);
}

Node* JSNativeContextSpecialization::InlinePropertyGetterCall(
    Node* receiver, ConvertReceiverMode receiver_mode,
    Node* lookup_start_object, Node* context, Node* frame_state, Node** effect,
    Node** control, ZoneVector<Node*>* if_exceptions,
    PropertyAccessInfo const& access_info) {
  ObjectRef constant = access_info.constant().value();

  if (access_info.IsDictionaryProtoAccessorConstant()) {
    // For fast mode holders we recorded dependencies in BuildPropertyLoad.
    for (const MapRef map : access_info.lookup_start_object_maps()) {
      dependencies()->DependOnConstantInDictionaryPrototypeChain(
          map, access_info.name(), constant, PropertyKind::kAccessor);
    }
  }

  Node* target = jsgraph()->ConstantNoHole(constant, broker());
  // Introduce the call to the getter function.
  Node* value;
  if (constant.IsJSFunction()) {
    Node* feedback = jsgraph()->UndefinedConstant();
    value = *effect = *control = graph()->NewNode(
        jsgraph()->javascript()->Call(JSCallNode::ArityForArgc(0),
                                      CallFrequency(), FeedbackSource(),
                                      receiver_mode),
        target, receiver, feedback, context, frame_state, *effect, *control);
  } else {
    // Disable optimizations for super ICs using API getters, so that we get
    // the correct receiver checks.
    if (receiver != lookup_start_object) {
      return nullptr;
    }
    Node* api_holder = access_info.api_holder().has_value()
                           ? jsgraph()->ConstantNoHole(
                                 access_info.api_holder().value(), broker())
                           : receiver;
    value = InlineApiCall(receiver, api_holder, frame_state, nullptr, effect,
                          control, constant.AsFunctionTemplateInfo());
  }
  // Remember to rewire the IfException edge if this is inside a try-block.
  if (if_exceptions != nullptr) {
    // Create the appropriate IfException/IfSuccess projections.
    Node* const if_exception =
        graph()->NewNode(common()->IfException(), *control, *effect);
    Node* const if_success = graph()->NewNode(common()->IfSuccess(), *control);
    if_exceptions->push_back(if_exception);
    *control = if_success;
  }
  return value;
}

void JSNativeContextSpecialization::InlinePropertySetterCall(
    Node* receiver, Node* value, Node* context, Node* frame_state,
    Node** effect, Node** control, ZoneVector<Node*>* if_exceptions,
    PropertyAccessInfo const& access_info) {
  ObjectRef constant = access_info.constant().value();
  Node* target = jsgraph()->ConstantNoHole(constant, broker());
  // Introduce the call to the setter function.
  if (constant.IsJSFunction()) {
    Node* feedback = jsgraph()->UndefinedConstant();
    *effect = *control = graph()->NewNode(
        jsgraph()->javascript()->Call(JSCallNode::ArityForArgc(1),
                                      CallFrequency(), FeedbackSource(),
                                      ConvertReceiverMode::kNotNullOrUndefined),
        target, receiver, value, feedback, context, frame_state, *effect,
        *control);
  } else {
    Node* api_holder = access_info.api_holder().has_value()
                           ? jsgraph()->ConstantNoHole(
                                 access_info.api_holder().value(), broker())
                           : receiver;
    InlineApiCall(receiver, api_holder, frame_state, value, effect, control,
                  constant.AsFunctionTemplateInfo());
  }
  // Remember to rewire the IfException edge if this is inside a try-block.
  if (if_exceptions != nullptr) {
    // Create the appropriate IfException/IfSuccess projections.
    Node* const if_exception =
        graph()->NewNode(common()->IfException(), *control, *effect);
    Node* const if_success = graph()->NewNode(common()->IfSuccess(), *control);
    if_exceptions->push_back(if_exception);
    *control = if_success;
  }
}

Node* JSNativeContextSpecialization::InlineApiCall(
    Node* receiver, Node* api_holder, Node* frame_state, Node* value,
    Node** effect, Node** control,
    FunctionTemplateInfoRef function_template_info) {
  compiler::OptionalObjectRef maybe_callback_data =
      function_template_info.callback_data(broker());
  // Check if the function has an associated C++ code to execute.
  if (!maybe_callback_data.has_value()) {
    // TODO(ishell): consider generating "return undefined" for empty function
    // instead of failing.
    TRACE_BROKER_MISSING(broker(), "call code for function template info "
                                       << function_template_info);
    return nullptr;
  }

  // Only setters have a value.
  int const argc = value == nullptr ? 0 : 1;
  // The builtin always expects the receiver as the first param on the stack.
  bool no_profiling = broker()->dependencies()->DependOnNoProfilingProtector();
  Callable call_api_callback = Builtins::CallableFor(
      isolate(), no_profiling ? Builtin::kCallApiCallbackOptimizedNoProfiling
                              : Builtin::kCallApiCallbackOptimized);
  CallInterfaceDescriptor call_interface_descriptor =
      call_api_callback.descriptor();
  auto call_descriptor = Linkage::GetStubCallDescriptor(
      graph()->zone(), call_interface_descriptor,
      call_interface_descriptor.GetStackParameterCount() + argc +
          1 /* implicit receiver */,
      CallDescriptor::kNeedsFrameState);

  Node* func_templ =
      jsgraph()->HeapConstantNoHole(function_template_info.object());
  ApiFunction function(function_template_info.callback(broker()));
  Node* function_reference =
      graph()->NewNode(common()->ExternalConstant(ExternalReference::Create(
          &function, ExternalReference::DIRECT_API_CALL)));
  Node* code = jsgraph()->HeapConstantNoHole(call_api_callback.code());

  // Add CallApiCallbackStub's register argument as well.
  Node* context = jsgraph()->ConstantNoHole(native_context(), broker());
  Node* inputs[11] = {
      code,       function_reference, jsgraph()->ConstantNoHole(argc),
      func_templ, api_holder,         receiver};
  int index = 6 + argc;
  inputs[index++] = context;
  inputs[index++] = frame_state;
  inputs[index++] = *effect;
  inputs[index++] = *control;
  // This needs to stay here because of the edge case described in
  // http://crbug.com/675648.
  if (value != nullptr) {
    inputs[6] = value;
  }

  return *effect = *control =
             graph()->NewNode(common()->Call(call_descriptor), index, inputs);
}

std::optional<JSNativeContextSpecialization::ValueEffectControl>
JSNativeContextSpecialization::BuildPropertyLoad(
    Node* lookup_start_object, Node* receiver, Node* context, Node* frame_state,
    Node* effect, Node* control, NameRef name, ZoneVector<Node*>* if_exceptions,
    PropertyAccessInfo const& access_info) {
  // Determine actual holder and perform prototype chain checks.
  OptionalJSObjectRef holder = access_info.holder();
  if (holder.has_value() && !access_info.HasDictionaryHolder()) {
    dependencies()->DependOnStablePrototypeChains(
        access_info.lookup_start_object_maps(), kStartAtPrototype,
        holder.value());
  }

  // Generate the actual property access.
  Node* value;
  if (access_info.IsNotFound()) {
    value = jsgraph()->UndefinedConstant();
  } else if (access_info.IsFastAccessorConstant() ||
             access_info.IsDictionaryProtoAccessorConstant()) {
    ConvertReceiverMode receiver_mode =
        receiver == lookup_start_object
            ? ConvertReceiverMode::kNotNullOrUndefined
            : ConvertReceiverMode::kAny;
    value = InlinePropertyGetterCall(
        receiver, receiver_mode, lookup_start_object, context, frame_state,
        &effect, &control, if_exceptions, access_info);
  } else if (access_info.IsModuleExport()) {
    Node* cell = jsgraph()->ConstantNoHole(
        access_info.constant().value().AsCell(), broker());
    value = effect =
        graph()->NewNode(simplified()->LoadField(AccessBuilder::ForCellValue()),
                         cell, effect, control);
  } else if (access_info.IsStringLength()) {
    DCHECK_EQ(receiver, lookup_start_object);
    value = graph()->NewNode(simplified()->StringLength(), receiver);
  } else if (access_info.IsStringWrapperLength()) {
    value = graph()->NewNode(simplified()->StringWrapperLength(),
                             lookup_start_object);
  } else {
    DCHECK(access_info.IsDataField() || access_info.IsFastDataConstant() ||
           access_info.IsDictionaryProtoDataConstant());
    PropertyAccessBuilder access_builder(jsgraph(), broker());
    if (access_info.IsDictionaryProtoDataConstant()) {
      auto maybe_value =
          access_builder.FoldLoadDictPrototypeConstant(access_info);
      if (!maybe_value) return {};
      value = maybe_value.value();
    } else {
      value = access_builder.BuildLoadDataField(
          name, access_info, lookup_start_object, &effect, &control);
    }
  }
  if (value != nullptr) {
    return ValueEffectControl(value, effect, control);
  }
  return std::optional<ValueEffectControl>();
}

JSNativeContextSpecialization::ValueEffectControl
JSNativeContextSpecialization::BuildPropertyTest(
    Node* effect,
```