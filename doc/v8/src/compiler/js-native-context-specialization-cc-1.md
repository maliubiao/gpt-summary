Response:
The user wants a summary of the functionality of the provided C++ code snippet. The snippet is part of the V8 JavaScript engine's compiler and deals with optimizing JavaScript code based on the context in which it's executed.

Here's a breakdown of the code's key actions:

1. **`ReduceJSInstanceOf`**: Optimizes the `instanceof` operator. It checks if the right-hand side (`constructor`) has a `@@hasInstance` method and calls it. If not, it performs the standard prototype chain check.
2. **`InferHasInPrototypeChain`**:  Attempts to statically determine if an object has a specific prototype in its chain. This allows for compile-time optimizations.
3. **`ReduceJSHasInPrototypeChain`**: Optimizes the `in` operator when used with prototypes (`o in Class`). It tries to determine if the prototype is present in the object's prototype chain.
4. **`ReduceJSOrdinaryHasInstance`**: Optimizes the internal `OrdinaryHasInstance` operation, which is part of the `instanceof` logic. It handles cases where the constructor is a bound function or a regular function with a known prototype.
5. **`ReduceJSPromiseResolve`**: Optimizes calls to `Promise.resolve()`. If the argument is not already a Promise and the constructor is the built-in `Promise` constructor, it creates a new Promise and resolves it.
6. **`ReduceJSResolvePromise`**: Optimizes the internal `ResolvePromise` operation. If the resolution value doesn't have a `then` method, it directly fulfills the promise.
7. **`ReduceGlobalAccess`**: Optimizes access (load, store, has) to global variables. It checks the properties of the global object and can potentially constant-fold or inline the access.
8. **`ReduceJSLoadGlobal`**: Optimizes loading global variables. It checks feedback from previous executions to potentially perform faster loads (e.g., loading from script context slots or property cells).
9. **`ReduceJSStoreGlobal`**: Optimizes storing values into global variables, similar to `ReduceJSLoadGlobal`.
10. **`ReduceMegaDOMPropertyAccess`**: Optimizes access to properties on DOM objects. It checks the receiver's type against allowed types defined in the function template.
11. **`ReduceNamedAccess`**: A central function for optimizing named property access (load, store, has, define). It handles various scenarios based on the feedback collected and the object's structure. It also handles cases where the access is on the global proxy.

Based on this analysis, I can formulate a concise summary.
这是 V8 源代码文件 `v8/src/compiler/js-native-context-specialization.cc` 的第二部分，它专注于对与 **JavaScript 原生上下文相关的操作** 进行 **编译优化**。

**主要功能归纳:**

这部分代码主要负责在编译时对特定的 JavaScript 操作进行优化，这些操作通常涉及到原生对象、全局对象、原型链以及 Promise 等。优化手段包括：

* **常量折叠 (Constant Folding):** 如果能在编译时确定操作的结果，就直接用常量替换，避免运行时的计算。
* **内联 (Inlining):** 将一些简单的操作直接嵌入到生成的代码中，减少函数调用的开销。
* **类型推断与优化:** 利用类型信息来生成更高效的代码，例如，如果知道某个对象肯定有某个属性，就可以避免运行时的查找。
* **基于反馈的优化:** 利用之前代码执行的信息（例如，属性访问的类型、调用的目标等）来优化当前的代码。
* **特殊情况处理:** 针对一些特定的原生对象和操作（例如，`instanceof`，Promise 操作，全局变量访问等）进行专门的优化。

**如果 `v8/src/compiler/js-native-context-specialization.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码:**

当前的 `.cc` 结尾表明它是一个 C++ 源代码文件，而不是 Torque 源代码。Torque 是一种 V8 内部使用的领域特定语言，用于编写一些性能关键的内置函数。

**与 JavaScript 功能的关系及 JavaScript 示例:**

这部分代码优化的 JavaScript 功能包括：

1. **`instanceof` 运算符:**

   ```javascript
   class MyClass {}
   const obj = new MyClass();
   console.log(obj instanceof MyClass); // 代码会尝试优化这个 instanceof 操作
   ```

2. **`in` 运算符 (用于检查原型链):**

   ```javascript
   function Parent() {}
   Parent.prototype.property = 1;
   function Child() {}
   Child.prototype = Object.create(Parent.prototype);
   const child = new Child();
   console.log("property" in child); // 代码会尝试优化这个原型链上的 in 操作
   ```

3. **`Promise.resolve()`:**

   ```javascript
   const resolvedPromise = Promise.resolve(10); // 代码会尝试优化这个 Promise.resolve
   ```

4. **全局变量的访问:**

   ```javascript
   console.log(window.myGlobalVariable); // 代码会尝试优化对全局变量的读取
   window.myGlobalVariable = 20;       // 代码会尝试优化对全局变量的写入
   ```

5. **属性访问:**

   ```javascript
   const obj = { a: 1 };
   console.log(obj.a); // 代码会尝试优化对对象属性的读取
   obj.a = 2;           // 代码会尝试优化对对象属性的写入
   ```

**代码逻辑推理与假设输入输出:**

以 `ReduceJSInstanceOf` 函数为例，假设有以下输入：

**假设输入:**

* `node`: 代表 `instanceof` 操作的 AST 节点，例如 `obj instanceof MyClass`。
* `constructor`: 代表 `MyClass` 的节点。
* `object`: 代表 `obj` 的节点。

**逻辑推理:**

代码会尝试获取 `MyClass` 的 `@@hasInstance` 方法。如果存在，则生成调用该方法的代码。如果不存在，则生成执行标准原型链检查的代码。

**假设输出 (如果 `MyClass` 没有 `@@hasInstance` 方法):**

优化的代码会执行类似以下逻辑（简化）：遍历 `obj` 的原型链，检查是否存在 `MyClass.prototype`。最终结果是一个布尔值。

**涉及用户常见的编程错误及示例:**

虽然这部分代码主要关注编译器优化，但它可以间接地帮助发现一些潜在的运行时错误，并通过生成的优化代码进行处理或触发 deoptimization。例如：

1. **对只读全局变量进行赋值:**  编译器在 `ReduceGlobalAccess` 中可能会识别出只读的全局变量，并避免生成不必要的存储操作，或者在运行时触发错误。

   ```javascript
   // 假设 window.undefined 是只读的
   window.undefined = 10; // 严格模式下会报错，非严格模式下赋值无效，编译器可能会进行优化
   ```

2. **类型假设错误:**  如果编译器基于之前的反馈假设某个变量总是某个类型，并进行了优化，但在运行时遇到不同类型的值，则可能会触发 deoptimization。

   ```javascript
   function foo(obj) {
       return obj.property; // 假设之前 obj 总是拥有 'property'
   }

   foo({ property: 1 });
   foo(null); // 如果编译器优化了属性访问，这里可能会触发 deoptimization
   ```

**功能归纳:**

这部分 `js-native-context-specialization.cc` 的核心功能是**针对与 JavaScript 原生上下文相关的操作，在编译阶段进行深入的分析和优化，以提升代码的执行效率。** 它利用类型信息、反馈数据以及对特定原生对象行为的理解，来生成更高效的目标代码。

### 提示词
```
这是目录为v8/src/compiler/js-native-context-specialization.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-native-context-specialization.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
// ToBoolean stub that finishes the remaining work of instanceof and returns
    // to the caller without duplicating side-effects upon a lazy deopt.
    Node* continuation_frame_state = CreateStubBuiltinContinuationFrameState(
        jsgraph(), Builtin::kToBooleanLazyDeoptContinuation, context, nullptr,
        0, frame_state, ContinuationFrameStateMode::LAZY);

    // Call the @@hasInstance handler.
    Node* target = jsgraph()->ConstantNoHole(*constant, broker());
    Node* feedback = jsgraph()->UndefinedConstant();
    // Value inputs plus context, frame state, effect, control.
    static_assert(JSCallNode::ArityForArgc(1) + 4 == 8);
    node->EnsureInputCount(graph()->zone(), 8);
    node->ReplaceInput(JSCallNode::TargetIndex(), target);
    node->ReplaceInput(JSCallNode::ReceiverIndex(), constructor);
    node->ReplaceInput(JSCallNode::ArgumentIndex(0), object);
    node->ReplaceInput(3, feedback);
    node->ReplaceInput(4, context);
    node->ReplaceInput(5, continuation_frame_state);
    node->ReplaceInput(6, effect);
    node->ReplaceInput(7, control);
    NodeProperties::ChangeOp(
        node, javascript()->Call(JSCallNode::ArityForArgc(1), CallFrequency(),
                                 FeedbackSource(),
                                 ConvertReceiverMode::kNotNullOrUndefined));

    // Rewire the value uses of {node} to ToBoolean conversion of the result.
    Node* value = graph()->NewNode(simplified()->ToBoolean(), node);
    for (Edge edge : node->use_edges()) {
      if (NodeProperties::IsValueEdge(edge) && edge.from() != value) {
        edge.UpdateTo(value);
        Revisit(edge.from());
      }
    }
    return Changed(node);
  }

  return NoChange();
}

JSNativeContextSpecialization::InferHasInPrototypeChainResult
JSNativeContextSpecialization::InferHasInPrototypeChain(
    Node* receiver, Effect effect, HeapObjectRef prototype) {
  ZoneRefSet<Map> receiver_maps;
  NodeProperties::InferMapsResult result = NodeProperties::InferMapsUnsafe(
      broker(), receiver, effect, &receiver_maps);
  if (result == NodeProperties::kNoMaps) return kMayBeInPrototypeChain;

  ZoneVector<MapRef> receiver_map_refs(zone());

  // Try to determine either that all of the {receiver_maps} have the given
  // {prototype} in their chain, or that none do. If we can't tell, return
  // kMayBeInPrototypeChain.
  bool all = true;
  bool none = true;
  for (MapRef map : receiver_maps) {
    receiver_map_refs.push_back(map);
    if (result == NodeProperties::kUnreliableMaps && !map.is_stable()) {
      return kMayBeInPrototypeChain;
    }
    while (true) {
      if (IsSpecialReceiverInstanceType(map.instance_type())) {
        return kMayBeInPrototypeChain;
      }
      if (!map.IsJSObjectMap()) {
        all = false;
        break;
      }
      HeapObjectRef map_prototype = map.prototype(broker());
      if (map_prototype.equals(prototype)) {
        none = false;
        break;
      }
      map = map_prototype.map(broker());
      // TODO(v8:11457) Support dictionary mode protoypes here.
      if (!map.is_stable() || map.is_dictionary_map()) {
        return kMayBeInPrototypeChain;
      }
      if (map.oddball_type(broker()) == OddballType::kNull) {
        all = false;
        break;
      }
    }
  }
  DCHECK_IMPLIES(all, !none);
  if (!all && !none) return kMayBeInPrototypeChain;

  {
    OptionalJSObjectRef last_prototype;
    if (all) {
      // We don't need to protect the full chain if we found the prototype, we
      // can stop at {prototype}.  In fact we could stop at the one before
      // {prototype} but since we're dealing with multiple receiver maps this
      // might be a different object each time, so it's much simpler to include
      // {prototype}. That does, however, mean that we must check {prototype}'s
      // map stability.
      if (!prototype.IsJSObject() || !prototype.map(broker()).is_stable()) {
        return kMayBeInPrototypeChain;
      }
      last_prototype = prototype.AsJSObject();
    }
    WhereToStart start = result == NodeProperties::kUnreliableMaps
                             ? kStartAtReceiver
                             : kStartAtPrototype;
    dependencies()->DependOnStablePrototypeChains(receiver_map_refs, start,
                                                  last_prototype);
  }

  DCHECK_EQ(all, !none);
  return all ? kIsInPrototypeChain : kIsNotInPrototypeChain;
}

Reduction JSNativeContextSpecialization::ReduceJSHasInPrototypeChain(
    Node* node) {
  DCHECK_EQ(IrOpcode::kJSHasInPrototypeChain, node->opcode());
  Node* value = NodeProperties::GetValueInput(node, 0);
  Node* prototype = NodeProperties::GetValueInput(node, 1);
  Effect effect{NodeProperties::GetEffectInput(node)};

  // Check if we can constant-fold the prototype chain walk
  // for the given {value} and the {prototype}.
  HeapObjectMatcher m(prototype);
  if (m.HasResolvedValue()) {
    InferHasInPrototypeChainResult result =
        InferHasInPrototypeChain(value, effect, m.Ref(broker()));
    if (result != kMayBeInPrototypeChain) {
      Node* result_in_chain =
          jsgraph()->BooleanConstant(result == kIsInPrototypeChain);
      ReplaceWithValue(node, result_in_chain);
      return Replace(result_in_chain);
    }
  }

  return NoChange();
}

Reduction JSNativeContextSpecialization::ReduceJSOrdinaryHasInstance(
    Node* node) {
  DCHECK_EQ(IrOpcode::kJSOrdinaryHasInstance, node->opcode());
  Node* constructor = NodeProperties::GetValueInput(node, 0);
  Node* object = NodeProperties::GetValueInput(node, 1);

  // Check if the {constructor} is known at compile time.
  HeapObjectMatcher m(constructor);
  if (!m.HasResolvedValue()) return NoChange();

  if (m.Ref(broker()).IsJSBoundFunction()) {
    // OrdinaryHasInstance on bound functions turns into a recursive invocation
    // of the instanceof operator again.
    JSBoundFunctionRef function = m.Ref(broker()).AsJSBoundFunction();
    Node* feedback = jsgraph()->UndefinedConstant();
    NodeProperties::ReplaceValueInput(node, object,
                                      JSInstanceOfNode::LeftIndex());
    NodeProperties::ReplaceValueInput(
        node,
        jsgraph()->ConstantNoHole(function.bound_target_function(broker()),
                                  broker()),
        JSInstanceOfNode::RightIndex());
    node->InsertInput(zone(), JSInstanceOfNode::FeedbackVectorIndex(),
                      feedback);
    NodeProperties::ChangeOp(node, javascript()->InstanceOf(FeedbackSource()));
    return Changed(node).FollowedBy(ReduceJSInstanceOf(node));
  }

  if (m.Ref(broker()).IsJSFunction()) {
    // Optimize if we currently know the "prototype" property.

    JSFunctionRef function = m.Ref(broker()).AsJSFunction();

    // TODO(neis): Remove the has_prototype_slot condition once the broker is
    // always enabled.
    if (!function.map(broker()).has_prototype_slot() ||
        !function.has_instance_prototype(broker()) ||
        function.PrototypeRequiresRuntimeLookup(broker())) {
      return NoChange();
    }

    HeapObjectRef prototype =
        dependencies()->DependOnPrototypeProperty(function);
    Node* prototype_constant = jsgraph()->ConstantNoHole(prototype, broker());

    // Lower the {node} to JSHasInPrototypeChain.
    NodeProperties::ReplaceValueInput(node, object, 0);
    NodeProperties::ReplaceValueInput(node, prototype_constant, 1);
    NodeProperties::ChangeOp(node, javascript()->HasInPrototypeChain());
    return Changed(node).FollowedBy(ReduceJSHasInPrototypeChain(node));
  }

  return NoChange();
}

// ES section #sec-promise-resolve
Reduction JSNativeContextSpecialization::ReduceJSPromiseResolve(Node* node) {
  DCHECK_EQ(IrOpcode::kJSPromiseResolve, node->opcode());
  Node* constructor = NodeProperties::GetValueInput(node, 0);
  Node* value = NodeProperties::GetValueInput(node, 1);
  Node* context = NodeProperties::GetContextInput(node);
  FrameState frame_state{NodeProperties::GetFrameStateInput(node)};
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};

  // Check if the {constructor} is the %Promise% function.
  HeapObjectMatcher m(constructor);
  if (!m.HasResolvedValue() ||
      !m.Ref(broker()).equals(native_context().promise_function(broker()))) {
    return NoChange();
  }

  // Only optimize if {value} cannot be a JSPromise.
  MapInference inference(broker(), value, effect);
  if (!inference.HaveMaps() ||
      inference.AnyOfInstanceTypesAre(JS_PROMISE_TYPE)) {
    return NoChange();
  }

  if (!dependencies()->DependOnPromiseHookProtector()) return NoChange();

  // Create a %Promise% instance and resolve it with {value}.
  Node* promise = effect =
      graph()->NewNode(javascript()->CreatePromise(), context, effect);

  // Create a nested frame state inside the current method's most-recent
  // {frame_state} that will ensure that lazy deoptimizations at this
  // point will still return the {promise} instead of the result of the
  // ResolvePromise operation (which yields undefined).
  Node* parameters[] = {promise};
  frame_state = CreateStubBuiltinContinuationFrameState(
      jsgraph(), Builtin::kAsyncFunctionLazyDeoptContinuation, context,
      parameters, arraysize(parameters), frame_state,
      ContinuationFrameStateMode::LAZY);

  effect = graph()->NewNode(javascript()->ResolvePromise(), promise, value,
                            context, frame_state, effect, control);
  ReplaceWithValue(node, promise, effect, control);
  return Replace(promise);
}

// ES section #sec-promise-resolve-functions
Reduction JSNativeContextSpecialization::ReduceJSResolvePromise(Node* node) {
  DCHECK_EQ(IrOpcode::kJSResolvePromise, node->opcode());
  Node* promise = NodeProperties::GetValueInput(node, 0);
  Node* resolution = NodeProperties::GetValueInput(node, 1);
  Node* context = NodeProperties::GetContextInput(node);
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};

  // Check if we know something about the {resolution}.
  MapInference inference(broker(), resolution, effect);
  if (!inference.HaveMaps()) return NoChange();
  ZoneRefSet<Map> const& resolution_maps = inference.GetMaps();

  // Compute property access info for "then" on {resolution}.
  ZoneVector<PropertyAccessInfo> access_infos(graph()->zone());
  AccessInfoFactory access_info_factory(broker(), graph()->zone());

  for (MapRef map : resolution_maps) {
    access_infos.push_back(broker()->GetPropertyAccessInfo(
        map, broker()->then_string(), AccessMode::kLoad));
  }
  PropertyAccessInfo access_info =
      access_info_factory.FinalizePropertyAccessInfosAsOne(access_infos,
                                                           AccessMode::kLoad);

  // TODO(v8:11457) Support dictionary mode prototypes here.
  if (access_info.IsInvalid() || access_info.HasDictionaryHolder()) {
    return inference.NoChange();
  }

  // Only optimize when {resolution} definitely doesn't have a "then" property.
  if (!access_info.IsNotFound()) return inference.NoChange();

  if (!inference.RelyOnMapsViaStability(dependencies())) {
    return inference.NoChange();
  }

  dependencies()->DependOnStablePrototypeChains(
      access_info.lookup_start_object_maps(), kStartAtPrototype);

  // Simply fulfill the {promise} with the {resolution}.
  Node* value = effect =
      graph()->NewNode(javascript()->FulfillPromise(), promise, resolution,
                       context, effect, control);
  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

namespace {

FieldAccess ForPropertyCellValue(MachineRepresentation representation,
                                 Type type, OptionalMapRef map, NameRef name) {
  WriteBarrierKind kind = kFullWriteBarrier;
  if (representation == MachineRepresentation::kTaggedSigned) {
    kind = kNoWriteBarrier;
  } else if (representation == MachineRepresentation::kTaggedPointer) {
    kind = kPointerWriteBarrier;
  }
  MachineType r = MachineType::TypeForRepresentation(representation);
  FieldAccess access = {
      kTaggedBase, PropertyCell::kValueOffset, name.object(), map, type, r,
      kind, "PropertyCellValue"};
  return access;
}

}  // namespace

// TODO(neis): Try to merge this with ReduceNamedAccess by introducing a new
// PropertyAccessInfo kind for global accesses and using the existing mechanism
// for building loads/stores.
// Note: The "receiver" parameter is only used for DCHECKS, but that's on
// purpose. This way we can assert the super property access cases won't hit the
// code which hasn't been modified to support super property access.
Reduction JSNativeContextSpecialization::ReduceGlobalAccess(
    Node* node, Node* lookup_start_object, Node* receiver, Node* value,
    NameRef name, AccessMode access_mode, Node* key,
    PropertyCellRef property_cell, Node* effect) {
  if (!property_cell.Cache(broker())) {
    TRACE_BROKER_MISSING(broker(), "usable data for " << property_cell);
    return NoChange();
  }

  ObjectRef property_cell_value = property_cell.value(broker());
  if (property_cell_value.IsPropertyCellHole()) {
    // The property cell is no longer valid.
    return NoChange();
  }

  PropertyDetails property_details = property_cell.property_details();
  PropertyCellType property_cell_type = property_details.cell_type();
  DCHECK_EQ(PropertyKind::kData, property_details.kind());

  Node* control = NodeProperties::GetControlInput(node);
  if (effect == nullptr) {
    effect = NodeProperties::GetEffectInput(node);
  }

  // We have additional constraints for stores.
  if (access_mode == AccessMode::kStore) {
    DCHECK_EQ(receiver, lookup_start_object);
    if (property_details.IsReadOnly()) {
      // Don't even bother trying to lower stores to read-only data properties.
      // TODO(neis): We could generate code that checks if the new value equals
      // the old one and then does nothing or deopts, respectively.
      return NoChange();
    } else if (property_cell_type == PropertyCellType::kUndefined) {
      return NoChange();
    } else if (property_cell_type == PropertyCellType::kConstantType) {
      // We rely on stability further below.
      if (property_cell_value.IsHeapObject() &&
          !property_cell_value.AsHeapObject().map(broker()).is_stable()) {
        return NoChange();
      }
    }
  } else if (access_mode == AccessMode::kHas) {
    DCHECK_EQ(receiver, lookup_start_object);
    // has checks cannot follow the fast-path used by loads when these
    // conditions hold.
    if ((property_details.IsConfigurable() || !property_details.IsReadOnly()) &&
        property_details.cell_type() != PropertyCellType::kConstant &&
        property_details.cell_type() != PropertyCellType::kUndefined)
      return NoChange();
  }

  // Ensure that {key} matches the specified {name} (if {key} is given).
  if (key != nullptr) {
    effect = BuildCheckEqualsName(name, key, effect, control);
  }

  // If we have a {lookup_start_object} to validate, we do so by checking that
  // its map is the (target) global proxy's map. This guarantees that in fact
  // the lookup start object is the global proxy.
  // Note: we rely on the map constant below being the same as what is used in
  // NativeContextRef::GlobalIsDetached().
  if (lookup_start_object != nullptr) {
    effect = graph()->NewNode(
        simplified()->CheckMaps(
            CheckMapsFlag::kNone,
            ZoneRefSet<Map>(
                native_context().global_proxy_object(broker()).map(broker()))),
        lookup_start_object, effect, control);
  }

  if (access_mode == AccessMode::kLoad || access_mode == AccessMode::kHas) {
    // Load from non-configurable, read-only data property on the global
    // object can be constant-folded, even without deoptimization support.
    if (!property_details.IsConfigurable() && property_details.IsReadOnly()) {
      value = access_mode == AccessMode::kHas
                  ? jsgraph()->TrueConstant()
                  : jsgraph()->ConstantNoHole(property_cell_value, broker());
    } else {
      // Record a code dependency on the cell if we can benefit from the
      // additional feedback, or the global property is configurable (i.e.
      // can be deleted or reconfigured to an accessor property).
      if (property_details.cell_type() != PropertyCellType::kMutable ||
          property_details.IsConfigurable()) {
        dependencies()->DependOnGlobalProperty(property_cell);
      }

      // Load from constant/undefined global property can be constant-folded.
      if (property_details.cell_type() == PropertyCellType::kConstant ||
          property_details.cell_type() == PropertyCellType::kUndefined) {
        value = access_mode == AccessMode::kHas
                    ? jsgraph()->TrueConstant()
                    : jsgraph()->ConstantNoHole(property_cell_value, broker());
        DCHECK(!property_cell_value.IsHeapObject() ||
               !property_cell_value.IsPropertyCellHole());
      } else {
        DCHECK_NE(AccessMode::kHas, access_mode);

        // Load from constant type cell can benefit from type feedback.
        OptionalMapRef map;
        Type property_cell_value_type = Type::NonInternal();
        MachineRepresentation representation = MachineRepresentation::kTagged;
        if (property_details.cell_type() == PropertyCellType::kConstantType) {
          // Compute proper type based on the current value in the cell.
          if (property_cell_value.IsSmi()) {
            property_cell_value_type = Type::SignedSmall();
            representation = MachineRepresentation::kTaggedSigned;
          } else if (property_cell_value.IsHeapNumber()) {
            property_cell_value_type = Type::Number();
            representation = MachineRepresentation::kTaggedPointer;
          } else {
            MapRef property_cell_value_map =
                property_cell_value.AsHeapObject().map(broker());
            property_cell_value_type =
                Type::For(property_cell_value_map, broker());
            representation = MachineRepresentation::kTaggedPointer;

            // We can only use the property cell value map for map check
            // elimination if it's stable, i.e. the HeapObject wasn't
            // mutated without the cell state being updated.
            if (property_cell_value_map.is_stable()) {
              dependencies()->DependOnStableMap(property_cell_value_map);
              map = property_cell_value_map;
            }
          }
        }
        value = effect = graph()->NewNode(
            simplified()->LoadField(ForPropertyCellValue(
                representation, property_cell_value_type, map, name)),
            jsgraph()->ConstantNoHole(property_cell, broker()), effect,
            control);
      }
    }
  } else if (access_mode == AccessMode::kStore) {
    DCHECK_EQ(receiver, lookup_start_object);
    DCHECK(!property_details.IsReadOnly());
    switch (property_details.cell_type()) {
      case PropertyCellType::kConstant: {
        // Record a code dependency on the cell, and just deoptimize if the new
        // value doesn't match the previous value stored inside the cell.
        dependencies()->DependOnGlobalProperty(property_cell);
        Node* check = graph()->NewNode(
            simplified()->ReferenceEqual(), value,
            jsgraph()->ConstantNoHole(property_cell_value, broker()));
        effect = graph()->NewNode(
            simplified()->CheckIf(DeoptimizeReason::kValueMismatch), check,
            effect, control);
        break;
      }
      case PropertyCellType::kConstantType: {
        // Record a code dependency on the cell, and just deoptimize if the new
        // value's type doesn't match the type of the previous value in the
        // cell.
        dependencies()->DependOnGlobalProperty(property_cell);
        Type property_cell_value_type;
        MachineRepresentation representation = MachineRepresentation::kTagged;
        if (property_cell_value.IsHeapObject()) {
          MapRef property_cell_value_map =
              property_cell_value.AsHeapObject().map(broker());
          dependencies()->DependOnStableMap(property_cell_value_map);

          // Check that the {value} is a HeapObject.
          value = effect = graph()->NewNode(simplified()->CheckHeapObject(),
                                            value, effect, control);
          // Check {value} map against the {property_cell_value} map.
          effect = graph()->NewNode(
              simplified()->CheckMaps(CheckMapsFlag::kNone,
                                      ZoneRefSet<Map>(property_cell_value_map)),
              value, effect, control);
          property_cell_value_type = Type::OtherInternal();
          representation = MachineRepresentation::kTaggedPointer;
        } else {
          // Check that the {value} is a Smi.
          value = effect = graph()->NewNode(
              simplified()->CheckSmi(FeedbackSource()), value, effect, control);
          property_cell_value_type = Type::SignedSmall();
          representation = MachineRepresentation::kTaggedSigned;
        }
        effect =
            graph()->NewNode(simplified()->StoreField(ForPropertyCellValue(
                                 representation, property_cell_value_type,
                                 OptionalMapRef(), name)),
                             jsgraph()->ConstantNoHole(property_cell, broker()),
                             value, effect, control);
        break;
      }
      case PropertyCellType::kMutable: {
        // Record a code dependency on the cell, and just deoptimize if the
        // property ever becomes read-only.
        dependencies()->DependOnGlobalProperty(property_cell);
        effect =
            graph()->NewNode(simplified()->StoreField(ForPropertyCellValue(
                                 MachineRepresentation::kTagged,
                                 Type::NonInternal(), OptionalMapRef(), name)),
                             jsgraph()->ConstantNoHole(property_cell, broker()),
                             value, effect, control);
        break;
      }
      case PropertyCellType::kUndefined:
      case PropertyCellType::kInTransition:
        UNREACHABLE();
    }
  } else {
    return NoChange();
  }

  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

Reduction JSNativeContextSpecialization::ReduceJSLoadGlobal(Node* node) {
  JSLoadGlobalNode n(node);
  LoadGlobalParameters const& p = n.Parameters();
  if (!p.feedback().IsValid()) return NoChange();

  ProcessedFeedback const& processed =
      broker()->GetFeedbackForGlobalAccess(FeedbackSource(p.feedback()));
  if (processed.IsInsufficient()) return NoChange();

  GlobalAccessFeedback const& feedback = processed.AsGlobalAccess();
  if (feedback.IsScriptContextSlot()) {
    Effect effect = n.effect();
    Control control = n.control();
    Node* script_context =
        jsgraph()->ConstantNoHole(feedback.script_context(), broker());
    Node* value;
    if (feedback.immutable()) {
      value = effect = graph()->NewNode(
          javascript()->LoadContext(0, feedback.slot_index(), true),
          script_context, effect);
    } else {
      value = effect = graph()->NewNode(
          javascript()->LoadScriptContext(0, feedback.slot_index()),
          script_context, effect, control);
    }
    ReplaceWithValue(node, value, effect, control);
    return Replace(value);
  } else if (feedback.IsPropertyCell()) {
    return ReduceGlobalAccess(node, nullptr, nullptr, nullptr, p.name(),
                              AccessMode::kLoad, nullptr,
                              feedback.property_cell());
  } else {
    DCHECK(feedback.IsMegamorphic());
    return NoChange();
  }
}

Reduction JSNativeContextSpecialization::ReduceJSStoreGlobal(Node* node) {
  JSStoreGlobalNode n(node);
  StoreGlobalParameters const& p = n.Parameters();
  Node* value = n.value();
  if (!p.feedback().IsValid()) return NoChange();

  ProcessedFeedback const& processed =
      broker()->GetFeedbackForGlobalAccess(FeedbackSource(p.feedback()));
  if (processed.IsInsufficient()) return NoChange();

  GlobalAccessFeedback const& feedback = processed.AsGlobalAccess();
  if (feedback.IsScriptContextSlot()) {
    if (feedback.immutable()) return NoChange();
    Node* effect = n.effect();
    Node* control = n.control();
    Node* script_context =
        jsgraph()->ConstantNoHole(feedback.script_context(), broker());
    effect = control = graph()->NewNode(
        javascript()->StoreScriptContext(0, feedback.slot_index()), value,
        script_context, effect, control);
    ReplaceWithValue(node, value, effect, control);
    return Replace(value);
  } else if (feedback.IsPropertyCell()) {
    return ReduceGlobalAccess(node, nullptr, nullptr, value, p.name(),
                              AccessMode::kStore, nullptr,
                              feedback.property_cell());
  } else {
    DCHECK(feedback.IsMegamorphic());
    return NoChange();
  }
}

Reduction JSNativeContextSpecialization::ReduceMegaDOMPropertyAccess(
    Node* node, Node* value, MegaDOMPropertyAccessFeedback const& feedback,
    FeedbackSource const& source) {
  DCHECK(node->opcode() == IrOpcode::kJSLoadNamed ||
         node->opcode() == IrOpcode::kJSLoadProperty);
  // TODO(mslekova): Add support and tests for kJSLoadNamedFromSuper.
  static_assert(JSLoadNamedNode::ObjectIndex() == 0 &&
                    JSLoadPropertyNode::ObjectIndex() == 0,
                "Assumptions about ObjectIndex have changed, please update "
                "this function.");

  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  Node* frame_state = NodeProperties::GetFrameStateInput(node);

  Node* lookup_start_object = NodeProperties::GetValueInput(node, 0);

  if (!dependencies()->DependOnMegaDOMProtector()) {
    return NoChange();
  }

  FunctionTemplateInfoRef function_template_info = feedback.info();
  int16_t range_start =
      function_template_info.allowed_receiver_instance_type_range_start();
  int16_t range_end =
      function_template_info.allowed_receiver_instance_type_range_end();
  DCHECK_IMPLIES(range_start == 0, range_end == 0);
  DCHECK_LE(range_start, range_end);

  // TODO(mslekova): This could be a new InstanceTypeCheck operator
  // that gets lowered later on (e.g. during generic lowering).
  Node* receiver_map = effect =
      graph()->NewNode(simplified()->LoadField(AccessBuilder::ForMap()),
                       lookup_start_object, effect, control);
  Node* receiver_instance_type = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForMapInstanceType()),
      receiver_map, effect, control);

  if (v8_flags.experimental_embedder_instance_types && range_start != 0) {
    // Embedder instance ID is set, doing a simple range check.
    Node* diff_to_start =
        graph()->NewNode(simplified()->NumberSubtract(), receiver_instance_type,
                         jsgraph()->ConstantNoHole(range_start));
    Node* range_length = jsgraph()->ConstantNoHole(range_end - range_start);

    // TODO(mslekova): Once we have the InstanceTypeCheck operator, we could
    // lower it to Uint32LessThan later on to perform what is done in bounds.h.
    Node* check = graph()->NewNode(simplified()->NumberLessThanOrEqual(),
                                   diff_to_start, range_length);
    effect = graph()->NewNode(
        simplified()->CheckIf(DeoptimizeReason::kWrongInstanceType), check,
        effect, control);
  } else if (function_template_info.is_signature_undefined(broker())) {
    // Signature is undefined, enough to check if the receiver is a JSApiObject.
    Node* check =
        graph()->NewNode(simplified()->NumberEqual(), receiver_instance_type,
                         jsgraph()->ConstantNoHole(JS_API_OBJECT_TYPE));
    effect = graph()->NewNode(
        simplified()->CheckIf(DeoptimizeReason::kWrongInstanceType), check,
        effect, control);
  } else {
    // Calling out to builtin to do signature check.
    Callable callable = Builtins::CallableFor(
        isolate(), Builtin::kCallFunctionTemplate_CheckCompatibleReceiver);
    int stack_arg_count = callable.descriptor().GetStackParameterCount() +
                          1 /* implicit receiver */;

    CallDescriptor* call_descriptor = Linkage::GetStubCallDescriptor(
        graph()->zone(), callable.descriptor(), stack_arg_count,
        CallDescriptor::kNeedsFrameState, Operator::kNoProperties);

    Node* inputs[8] = {
        jsgraph()->HeapConstantNoHole(callable.code()),
        jsgraph()->ConstantNoHole(function_template_info, broker()),
        jsgraph()->Int32Constant(stack_arg_count),
        lookup_start_object,
        jsgraph()->ConstantNoHole(native_context(), broker()),
        frame_state,
        effect,
        control};

    value = effect = control =
        graph()->NewNode(common()->Call(call_descriptor), 8, inputs);
    return Replace(value);
  }

  value = InlineApiCall(lookup_start_object, lookup_start_object, frame_state,
                        nullptr /*value*/, &effect, &control,
                        function_template_info);
  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

Reduction JSNativeContextSpecialization::ReduceNamedAccess(
    Node* node, Node* value, NamedAccessFeedback const& feedback,
    AccessMode access_mode, Node* key) {
  DCHECK(node->opcode() == IrOpcode::kJSLoadNamed ||
         node->opcode() == IrOpcode::kJSSetNamedProperty ||
         node->opcode() == IrOpcode::kJSLoadProperty ||
         node->opcode() == IrOpcode::kJSSetKeyedProperty ||
         node->opcode() == IrOpcode::kJSDefineNamedOwnProperty ||
         node->opcode() == IrOpcode::kJSDefineKeyedOwnPropertyInLiteral ||
         node->opcode() == IrOpcode::kJSHasProperty ||
         node->opcode() == IrOpcode::kJSLoadNamedFromSuper ||
         node->opcode() == IrOpcode::kJSDefineKeyedOwnProperty);
  static_assert(JSLoadNamedNode::ObjectIndex() == 0 &&
                JSSetNamedPropertyNode::ObjectIndex() == 0 &&
                JSLoadPropertyNode::ObjectIndex() == 0 &&
                JSSetKeyedPropertyNode::ObjectIndex() == 0 &&
                JSDefineNamedOwnPropertyNode::ObjectIndex() == 0 &&
                JSSetNamedPropertyNode::ObjectIndex() == 0 &&
                JSDefineKeyedOwnPropertyInLiteralNode::ObjectIndex() == 0 &&
                JSHasPropertyNode::ObjectIndex() == 0 &&
                JSDefineKeyedOwnPropertyNode::ObjectIndex() == 0);
  static_assert(JSLoadNamedFromSuperNode::ReceiverIndex() == 0);

  Node* context = NodeProperties::GetContextInput(node);
  FrameState frame_state{NodeProperties::GetFrameStateInput(node)};
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};

  // receiver = the object we pass to the accessor (if any) as the "this" value.
  Node* receiver = NodeProperties::GetValueInput(node, 0);
  // lookup_start_object = the object where we start looking for the property.
  Node* lookup_start_object;
  if (node->opcode() == IrOpcode::kJSLoadNamedFromSuper) {
    DCHECK(v8_flags.super_ic);
    JSLoadNamedFromSuperNode n(node);
    // Lookup start object is the __proto__ of the home object.
    lookup_start_object = effect =
        BuildLoadPrototypeFromObject(n.home_object(), effect, control);
  } else {
    lookup_start_object = receiver;
  }

  // Either infer maps from the graph or use the feedback.
  ZoneVector<MapRef> inferred_maps(zone());
  if (!InferMaps(lookup_start_object, effect, &inferred_maps)) {
    for (MapRef map : feedback.maps()) {
      inferred_maps.push_back(map);
    }
  }
  RemoveImpossibleMaps(lookup_start_object, &inferred_maps);

  // Check if we have an access o.x or o.x=v where o is the target native
  // contexts' global proxy, and turn that into a direct access to the
  // corresponding global object instead.
  if (inferred_maps.size() == 1) {
    MapRef lookup_start_object_map = inferred_maps[0];
    if (lookup_start_object_map.equals(
            native_context().global_proxy_object(broker()).map(broker()))) {
      if (!native_context().GlobalIsDetached(broker())) {
        OptionalPropertyCellRef cell =
            native_context().global_object(broker()).GetPropertyCell(
                broker(), feedback.name());
        if (!cell.has_value()) return NoChange();
        // Note: The map check generated by ReduceGlobalAccesses ensures that we
        // will deopt when/if GlobalIsDetached becomes true.
        return ReduceGlobalAccess(node, lookup_start_object, receiver, value,
                                  feedback.name(), access_mode, key, *cell
```