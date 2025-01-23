Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/js-typed-lowering.cc`.

Here's a breakdown of the thought process to arrive at the answer:

1. **Identify the core purpose:** The file name `js-typed-lowering.cc` strongly suggests that this code is responsible for *lowering* JavaScript operations to a more basic, typed representation within the V8 compiler. This is a crucial step in optimization.

2. **Scan for class name and methods:** The code defines a class `JSTypedLowering`. The provided snippet shows various methods within this class, many starting with `ReduceJS...`. This naming convention strongly indicates that these methods are responsible for *reducing* or *transforming* specific JavaScript operations.

3. **Analyze individual `ReduceJS...` methods:** Examine the logic within each `ReduceJS...` method. Look for patterns and keywords:
    * `DCHECK_EQ(IrOpcode::kJS..., node->opcode())`: This confirms the method is handling a specific JavaScript operation (identified by the `IrOpcode`).
    * `simplified()->...`:  This suggests the code is transforming JavaScript operations into simpler, *simplified* operations within the V8 intermediate representation.
    * `graph()->NewNode(...)`: This indicates the creation of new nodes in the compiler's graph representation, likely representing the lowered operation.
    * `ReplaceWithValue(...)`, `Replace(...)`: These methods suggest replacing the original JavaScript operation node with the newly created, lowered representation.
    *  Specific operations like `JSAdd`, `JSEqual`, `JSLoadNamed`, `JSCall`, `JSForInPrepare`, etc., clearly link the code to corresponding JavaScript language features.

4. **Look for patterns and common themes:**  Notice that many methods involve:
    * Checking types of operands.
    * Loading/storing values from objects and arrays using `AccessBuilder`.
    * Conditional branching and merging of control flow.
    * Handling specific JavaScript object types like `Map`, `FixedArray`, `JSGeneratorObject`, etc.
    * Interacting with the `simplified` operator builder.

5. **Identify the role of `Torque` (based on the prompt's condition):** The prompt mentions `.tq` files. While this snippet is `.cc`, the prompt's condition is a good reminder that Torque is used in V8 for generating compiler code. If this *were* a `.tq` file, it would mean the lowering logic was defined in a higher-level, more declarative way using Torque.

6. **Connect to JavaScript functionality:** For methods handling common JavaScript operations, think about how those operations work in JavaScript and try to find a corresponding example.

7. **Identify potential user errors:**  Consider common mistakes developers make related to the JavaScript operations being lowered. For example, type coercion issues with addition, or incorrect usage of `for...in`.

8. **Synthesize a summary:** Combine the observations into a concise description of the file's purpose. Emphasize the "lowering" aspect, the focus on specific JavaScript operations, and the goal of optimization.

9. **Address the specific points in the prompt:**
    * List the functionalities (the `ReduceJS...` methods).
    * Address the `.tq` condition (even though it doesn't apply here, explain what it would mean).
    * Provide JavaScript examples where relevant.
    * Explain code logic with input/output examples (even simplified ones).
    * Give examples of common user errors.
    * Provide a final, concise summary.

**Self-Correction/Refinement:**

* **Initial thought:** Simply listing all the `ReduceJS...` methods might be too granular.
* **Refinement:** Group related functionalities (e.g., arithmetic operations, object access, function calls). Provide a higher-level explanation of the overall process.
* **Initial thought:**  Focus too much on the low-level implementation details.
* **Refinement:**  Explain the *purpose* of the lowering process – making the code more suitable for further optimization and code generation.
* **Consider the audience:** The explanation should be understandable to someone with some knowledge of compilers and JavaScript, but not necessarily an expert in V8 internals. Avoid overly technical jargon where possible.
This is part 4 of 4 of the analysis of the `v8/src/compiler/js-typed-lowering.cc` file. Combining the insights from all parts, here's a comprehensive summary of its functionality:

**归纳一下它的功能 (Summary of its Functionality):**

The `v8/src/compiler/js-typed-lowering.cc` file plays a crucial role in V8's optimizing compiler. Its primary function is to **lower** high-level JavaScript operations (represented as `IrOpcode`s in V8's intermediate representation) into simpler, more primitive operations that are closer to the machine level. This lowering process takes into account the **types** of the operands involved, enabling type-specific optimizations.

Here's a breakdown of the key aspects:

* **Type-Aware Lowering:** The "typed" in the name highlights the importance of type information. This component analyzes the types of variables and operands to perform more efficient lowering. For example, knowing that both operands of an addition are integers allows for a direct integer addition instead of a more general (and slower) JavaScript addition that handles various types.

* **Specific JavaScript Operation Handling:** The code contains numerous `ReduceJS...` methods, each responsible for lowering a specific JavaScript operation like `JSAdd`, `JSEqual`, `JSLoadNamed`, `JSCall`, `JSForInPrepare`, and many others.

* **Transformation to Simplified Operations:**  The lowering process typically involves transforming JavaScript operations into equivalent sequences of simpler operations provided by the `SimplifiedOperatorBuilder`. This often involves:
    * **Load/Store Operations:** Accessing object properties, array elements, and context variables using `simplified()->LoadField` and `simplified()->StoreField`.
    * **Comparison and Type Checks:**  Performing type checks (e.g., `simplified()->ObjectIsSmi()`) and comparisons (`simplified()->NumberEqual()`).
    * **Bitwise and Arithmetic Operations:**  Using more basic bitwise (`simplified()->NumberBitwiseAnd()`) and arithmetic operations.
    * **Control Flow Manipulation:** Creating branches (`common()->Branch`) and merges (`common()->Merge`) to handle different execution paths.
    * **Runtime Calls:**  Sometimes, lowering involves calling specific runtime functions (`javascript()->CallRuntime`) for more complex operations or when type information is insufficient.

* **Optimization Opportunities:** By lowering to simpler, typed operations, the compiler can apply further optimizations in subsequent phases, such as:
    * **Register Allocation:**  Simpler operations are easier to map to machine registers.
    * **Instruction Selection:**  More efficient machine instructions can be chosen.
    * **Inlining:**  Lowered operations are often better candidates for inlining.

* **Handling Special Cases:** The code also addresses specific scenarios and optimizations for particular JavaScript features, such as:
    * **For-in loops:** Lowering the `JSForInPrepare` and `JSForInNext` operations involves handling different enumeration scenarios (using enum caches or iterating over FixedArrays).
    * **Generator functions:**  Specific lowering rules exist for `JSGeneratorStore`, `JSGeneratorRestoreContinuation`, etc., to manage the state of generator functions.
    * **Promises:**  Optimizations like reducing `JSResolvePromise` to `JSFulfillPromise` for primitive resolutions are implemented.

**In essence, `v8/src/compiler/js-typed-lowering.cc` acts as a translator, converting high-level JavaScript semantics into a lower-level representation that the compiler can more effectively optimize and generate machine code from.**

**Regarding the specific checks in the prompt:**

* **`.tq` extension:** The code snippet is in `.cc`, indicating it's a C++ source file. If it were `.tq`, it would be a Torque source file, a domain-specific language used within V8 for defining compilerBuiltins and some lowering rules in a more declarative way.

* **Relationship with JavaScript:** The entire purpose of this file is directly related to JavaScript functionality. Each `ReduceJS...` method handles a specific JavaScript operation.

* **Code Logic and Assumptions (Illustrative Example from Part 4 - `ReduceJSForInPrepare`):**

    **Assumed Input:** A `JSForInPrepare` node in the compiler graph representing the start of a `for...in` loop. This node has an input representing the object being iterated over.

    **Logic:** The code checks the type of the object to determine the most efficient way to perform the enumeration:
    * **Fast Case (JSReceiver with enum cache):** If the object is a plain JavaScript object with an enum cache, it loads the cached keys and length.
    * **Slow Case (Generic):** If the object doesn't have a simple enum cache or is a FixedArray, it handles the enumeration accordingly. It checks if the enumerator is a Map or a FixedArray and loads the keys and length from the appropriate source.

    **Output:** The `JSForInPrepare` node is replaced with multiple new nodes representing the initial state of the enumeration: the type of enumeration, the array of keys (or the FixedArray itself), and the length.

* **Common User Programming Errors (Illustrative Example from Part 4 - `ReduceJSForInPrepare`):**

    * **Assuming Order in `for...in`:**  JavaScript's `for...in` loop doesn't guarantee the order of iteration over object properties (except for specific cases like array indices). Users sometimes make the mistake of relying on a specific order, which can lead to unexpected behavior. V8's lowering, while optimizing the iteration, still adheres to the language specification regarding order.

    ```javascript
    const obj = { b: 2, a: 1, c: 3 };
    for (let key in obj) {
      console.log(key); // Output might be a, b, c or b, a, c or other permutations.
    }
    ```

    * **Modifying the Object During `for...in`:**  Modifying the object's properties (adding or deleting) during a `for...in` loop can lead to unpredictable results. The iteration might skip or process properties multiple times.

    ```javascript
    const obj = { a: 1, b: 2 };
    for (let key in obj) {
      console.log(key);
      if (key === 'a') {
        delete obj.b; // Modifying the object during iteration
      }
    }
    ```

This detailed breakdown should provide a good understanding of the functionality of the `v8/src/compiler/js-typed-lowering.cc` file within the context of the V8 JavaScript engine.

### 提示词
```
这是目录为v8/src/compiler/js-typed-lowering.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-typed-lowering.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
adField(AccessBuilder::ForMapBitField3()), enumerator,
          effect, control);
      static_assert(Map::Bits3::EnumLengthBits::kShift == 0);
      cache_length = graph()->NewNode(
          simplified()->NumberBitwiseAnd(), bit_field3,
          jsgraph()->ConstantNoHole(Map::Bits3::EnumLengthBits::kMask));
      break;
    }
    case ForInMode::kGeneric: {
      // Check if the {enumerator} is a Map or a FixedArray.
      // The direct IsMap check requires reading of an instance type, so we
      // compare against fixed array map instead (by definition,
      // the {enumerator} is either the receiver's Map or a FixedArray).
      Node* check = effect =
          graph()->NewNode(simplified()->CompareMaps(
                               ZoneRefSet<Map>(broker()->fixed_array_map())),
                           enumerator, effect, control);
      Node* branch = graph()->NewNode(common()->Branch(BranchHint::kFalse),
                                      check, control);

      Node* if_map = graph()->NewNode(common()->IfFalse(), branch);
      Node* etrue = effect;
      Node* cache_array_true;
      Node* cache_length_true;
      {
        // Load the enum cache from the {enumerator} map.
        Node* descriptor_array = etrue = graph()->NewNode(
            simplified()->LoadField(AccessBuilder::ForMapDescriptors()),
            enumerator, etrue, if_map);
        Node* enum_cache = etrue =
            graph()->NewNode(simplified()->LoadField(
                                 AccessBuilder::ForDescriptorArrayEnumCache()),
                             descriptor_array, etrue, if_map);
        cache_array_true = etrue = graph()->NewNode(
            simplified()->LoadField(AccessBuilder::ForEnumCacheKeys()),
            enum_cache, etrue, if_map);

        // Load the enum length of the {enumerator} map.
        Node* bit_field3 = etrue = graph()->NewNode(
            simplified()->LoadField(AccessBuilder::ForMapBitField3()),
            enumerator, etrue, if_map);
        static_assert(Map::Bits3::EnumLengthBits::kShift == 0);
        cache_length_true = graph()->NewNode(
            simplified()->NumberBitwiseAnd(), bit_field3,
            jsgraph()->ConstantNoHole(Map::Bits3::EnumLengthBits::kMask));
      }

      Node* if_fixed_array = graph()->NewNode(common()->IfTrue(), branch);
      Node* efalse = effect;
      Node* cache_array_false;
      Node* cache_length_false;
      {
        // The {enumerator} is the FixedArray with the keys to iterate.
        cache_array_false = enumerator;
        cache_length_false = efalse = graph()->NewNode(
            simplified()->LoadField(AccessBuilder::ForFixedArrayLength()),
            cache_array_false, efalse, if_fixed_array);
      }

      // Rewrite the uses of the {node}.
      control = graph()->NewNode(common()->Merge(2), if_map, if_fixed_array);
      effect = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);
      cache_array =
          graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                           cache_array_true, cache_array_false, control);
      cache_length =
          graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                           cache_length_true, cache_length_false, control);
      break;
    }
  }

  // Update the uses of {node}.
  for (Edge edge : node->use_edges()) {
    Node* const user = edge.from();
    if (NodeProperties::IsEffectEdge(edge)) {
      edge.UpdateTo(effect);
      Revisit(user);
    } else if (NodeProperties::IsControlEdge(edge)) {
      edge.UpdateTo(control);
      Revisit(user);
    } else {
      DCHECK(NodeProperties::IsValueEdge(edge));
      switch (ProjectionIndexOf(user->op())) {
        case 0:
          Replace(user, cache_type);
          break;
        case 1:
          Replace(user, cache_array);
          break;
        case 2:
          Replace(user, cache_length);
          break;
        default:
          UNREACHABLE();
      }
    }
  }
  node->Kill();
  return Replace(effect);
}

Reduction JSTypedLowering::ReduceJSLoadMessage(Node* node) {
  DCHECK_EQ(IrOpcode::kJSLoadMessage, node->opcode());
  ExternalReference const ref =
      ExternalReference::address_of_pending_message(isolate());
  node->ReplaceInput(0, jsgraph()->ExternalConstant(ref));
  NodeProperties::ChangeOp(node, simplified()->LoadMessage());
  return Changed(node);
}

Reduction JSTypedLowering::ReduceJSStoreMessage(Node* node) {
  DCHECK_EQ(IrOpcode::kJSStoreMessage, node->opcode());
  ExternalReference const ref =
      ExternalReference::address_of_pending_message(isolate());
  Node* value = NodeProperties::GetValueInput(node, 0);
  node->ReplaceInput(0, jsgraph()->ExternalConstant(ref));
  node->ReplaceInput(1, value);
  NodeProperties::ChangeOp(node, simplified()->StoreMessage());
  return Changed(node);
}

Reduction JSTypedLowering::ReduceJSGeneratorStore(Node* node) {
  DCHECK_EQ(IrOpcode::kJSGeneratorStore, node->opcode());
  Node* generator = NodeProperties::GetValueInput(node, 0);
  Node* continuation = NodeProperties::GetValueInput(node, 1);
  Node* offset = NodeProperties::GetValueInput(node, 2);
  Node* context = NodeProperties::GetContextInput(node);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  int value_count = GeneratorStoreValueCountOf(node->op());

  FieldAccess array_field =
      AccessBuilder::ForJSGeneratorObjectParametersAndRegisters();
  FieldAccess context_field = AccessBuilder::ForJSGeneratorObjectContext();
  FieldAccess continuation_field =
      AccessBuilder::ForJSGeneratorObjectContinuation();
  FieldAccess input_or_debug_pos_field =
      AccessBuilder::ForJSGeneratorObjectInputOrDebugPos();

  Node* array = effect = graph()->NewNode(simplified()->LoadField(array_field),
                                          generator, effect, control);

  for (int i = 0; i < value_count; ++i) {
    Node* value = NodeProperties::GetValueInput(node, 3 + i);
    if (value != jsgraph()->OptimizedOutConstant()) {
      effect = graph()->NewNode(
          simplified()->StoreField(AccessBuilder::ForFixedArraySlot(i)), array,
          value, effect, control);
    }
  }

  effect = graph()->NewNode(simplified()->StoreField(context_field), generator,
                            context, effect, control);
  effect = graph()->NewNode(simplified()->StoreField(continuation_field),
                            generator, continuation, effect, control);
  effect = graph()->NewNode(simplified()->StoreField(input_or_debug_pos_field),
                            generator, offset, effect, control);

  ReplaceWithValue(node, effect, effect, control);
  return Changed(effect);
}

Reduction JSTypedLowering::ReduceJSGeneratorRestoreContinuation(Node* node) {
  DCHECK_EQ(IrOpcode::kJSGeneratorRestoreContinuation, node->opcode());
  Node* generator = NodeProperties::GetValueInput(node, 0);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  FieldAccess continuation_field =
      AccessBuilder::ForJSGeneratorObjectContinuation();

  Node* continuation = effect = graph()->NewNode(
      simplified()->LoadField(continuation_field), generator, effect, control);
  Node* executing =
      jsgraph()->ConstantNoHole(JSGeneratorObject::kGeneratorExecuting);
  effect = graph()->NewNode(simplified()->StoreField(continuation_field),
                            generator, executing, effect, control);

  ReplaceWithValue(node, continuation, effect, control);
  return Changed(continuation);
}

Reduction JSTypedLowering::ReduceJSGeneratorRestoreContext(Node* node) {
  DCHECK_EQ(IrOpcode::kJSGeneratorRestoreContext, node->opcode());

  const Operator* new_op =
      simplified()->LoadField(AccessBuilder::ForJSGeneratorObjectContext());

  // Mutate the node in-place.
  DCHECK(OperatorProperties::HasContextInput(node->op()));
  DCHECK(!OperatorProperties::HasContextInput(new_op));
  node->RemoveInput(NodeProperties::FirstContextIndex(node));

  NodeProperties::ChangeOp(node, new_op);
  return Changed(node);
}

Reduction JSTypedLowering::ReduceJSGeneratorRestoreRegister(Node* node) {
  DCHECK_EQ(IrOpcode::kJSGeneratorRestoreRegister, node->opcode());
  Node* generator = NodeProperties::GetValueInput(node, 0);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  int index = RestoreRegisterIndexOf(node->op());

  FieldAccess array_field =
      AccessBuilder::ForJSGeneratorObjectParametersAndRegisters();
  FieldAccess element_field = AccessBuilder::ForFixedArraySlot(index);

  Node* array = effect = graph()->NewNode(simplified()->LoadField(array_field),
                                          generator, effect, control);
  Node* element = effect = graph()->NewNode(
      simplified()->LoadField(element_field), array, effect, control);
  Node* stale = jsgraph()->StaleRegisterConstant();
  effect = graph()->NewNode(simplified()->StoreField(element_field), array,
                            stale, effect, control);

  ReplaceWithValue(node, element, effect, control);
  return Changed(element);
}

Reduction JSTypedLowering::ReduceJSGeneratorRestoreInputOrDebugPos(Node* node) {
  DCHECK_EQ(IrOpcode::kJSGeneratorRestoreInputOrDebugPos, node->opcode());

  FieldAccess input_or_debug_pos_field =
      AccessBuilder::ForJSGeneratorObjectInputOrDebugPos();
  const Operator* new_op = simplified()->LoadField(input_or_debug_pos_field);

  // Mutate the node in-place.
  DCHECK(OperatorProperties::HasContextInput(node->op()));
  DCHECK(!OperatorProperties::HasContextInput(new_op));
  node->RemoveInput(NodeProperties::FirstContextIndex(node));

  NodeProperties::ChangeOp(node, new_op);
  return Changed(node);
}

Reduction JSTypedLowering::ReduceObjectIsArray(Node* node) {
  Node* value = NodeProperties::GetValueInput(node, 0);
  Type value_type = NodeProperties::GetType(value);
  Node* context = NodeProperties::GetContextInput(node);
  Node* frame_state = NodeProperties::GetFrameStateInput(node);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  // Constant-fold based on {value} type.
  if (value_type.Is(Type::Array())) {
    value = jsgraph()->TrueConstant();
    ReplaceWithValue(node, value);
    return Replace(value);
  } else if (!value_type.Maybe(Type::ArrayOrProxy())) {
    value = jsgraph()->FalseConstant();
    ReplaceWithValue(node, value);
    return Replace(value);
  }

  int count = 0;
  Node* values[5];
  Node* effects[5];
  Node* controls[4];

  // Check if the {value} is a Smi.
  Node* check = graph()->NewNode(simplified()->ObjectIsSmi(), value);
  control =
      graph()->NewNode(common()->Branch(BranchHint::kFalse), check, control);

  // The {value} is a Smi.
  controls[count] = graph()->NewNode(common()->IfTrue(), control);
  effects[count] = effect;
  values[count] = jsgraph()->FalseConstant();
  count++;

  control = graph()->NewNode(common()->IfFalse(), control);

  // Load the {value}s instance type.
  Node* value_map = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForMap()), value, effect, control);
  Node* value_instance_type = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForMapInstanceType()), value_map,
      effect, control);

  // Check if the {value} is a JSArray.
  check = graph()->NewNode(simplified()->NumberEqual(), value_instance_type,
                           jsgraph()->ConstantNoHole(JS_ARRAY_TYPE));
  control = graph()->NewNode(common()->Branch(), check, control);

  // The {value} is a JSArray.
  controls[count] = graph()->NewNode(common()->IfTrue(), control);
  effects[count] = effect;
  values[count] = jsgraph()->TrueConstant();
  count++;

  control = graph()->NewNode(common()->IfFalse(), control);

  // Check if the {value} is a JSProxy.
  check = graph()->NewNode(simplified()->NumberEqual(), value_instance_type,
                           jsgraph()->ConstantNoHole(JS_PROXY_TYPE));
  control =
      graph()->NewNode(common()->Branch(BranchHint::kFalse), check, control);

  // The {value} is neither a JSArray nor a JSProxy.
  controls[count] = graph()->NewNode(common()->IfFalse(), control);
  effects[count] = effect;
  values[count] = jsgraph()->FalseConstant();
  count++;

  control = graph()->NewNode(common()->IfTrue(), control);

  // Let the %ArrayIsArray runtime function deal with the JSProxy {value}.
  value = effect = control =
      graph()->NewNode(javascript()->CallRuntime(Runtime::kArrayIsArray), value,
                       context, frame_state, effect, control);
  NodeProperties::SetType(value, Type::Boolean());

  // Update potential {IfException} uses of {node} to point to the above
  // %ArrayIsArray runtime call node instead.
  Node* on_exception = nullptr;
  if (NodeProperties::IsExceptionalCall(node, &on_exception)) {
    NodeProperties::ReplaceControlInput(on_exception, control);
    NodeProperties::ReplaceEffectInput(on_exception, effect);
    control = graph()->NewNode(common()->IfSuccess(), control);
    Revisit(on_exception);
  }

  // The {value} is neither a JSArray nor a JSProxy.
  controls[count] = control;
  effects[count] = effect;
  values[count] = value;
  count++;

  control = graph()->NewNode(common()->Merge(count), count, controls);
  effects[count] = control;
  values[count] = control;
  effect = graph()->NewNode(common()->EffectPhi(count), count + 1, effects);
  value = graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, count),
                           count + 1, values);
  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

Reduction JSTypedLowering::ReduceJSParseInt(Node* node) {
  Node* value = NodeProperties::GetValueInput(node, 0);
  Type value_type = NodeProperties::GetType(value);
  Node* radix = NodeProperties::GetValueInput(node, 1);
  Type radix_type = NodeProperties::GetType(radix);
  // We need kTenOrUndefined and kZeroOrUndefined because
  // the type representing {0,10} would become the range 1-10.
  if (value_type.Is(type_cache_->kSafeInteger) &&
      (radix_type.Is(type_cache_->kTenOrUndefined) ||
       radix_type.Is(type_cache_->kZeroOrUndefined))) {
    // Number.parseInt(a:safe-integer) -> a
    // Number.parseInt(a:safe-integer,b:#0\/undefined) -> a
    // Number.parseInt(a:safe-integer,b:#10\/undefined) -> a
    ReplaceWithValue(node, value);
    return Replace(value);
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSResolvePromise(Node* node) {
  DCHECK_EQ(IrOpcode::kJSResolvePromise, node->opcode());
  Node* resolution = NodeProperties::GetValueInput(node, 1);
  Type resolution_type = NodeProperties::GetType(resolution);
  // We can strength-reduce JSResolvePromise to JSFulfillPromise
  // if the {resolution} is known to be a primitive, as in that
  // case we don't perform the implicit chaining (via "then").
  if (resolution_type.Is(Type::Primitive())) {
    // JSResolvePromise(p,v:primitive) -> JSFulfillPromise(p,v)
    node->RemoveInput(3);  // frame state
    NodeProperties::ChangeOp(node, javascript()->FulfillPromise());
    return Changed(node);
  }
  return NoChange();
}

Reduction JSTypedLowering::Reduce(Node* node) {
  switch (node->opcode()) {
    case IrOpcode::kJSEqual:
      return ReduceJSEqual(node);
    case IrOpcode::kJSStrictEqual:
      return ReduceJSStrictEqual(node);
    case IrOpcode::kJSLessThan:         // fall through
    case IrOpcode::kJSGreaterThan:      // fall through
    case IrOpcode::kJSLessThanOrEqual:  // fall through
    case IrOpcode::kJSGreaterThanOrEqual:
      return ReduceJSComparison(node);
    case IrOpcode::kJSBitwiseOr:
    case IrOpcode::kJSBitwiseXor:
    case IrOpcode::kJSBitwiseAnd:
      return ReduceInt32Binop(node);
    case IrOpcode::kJSShiftLeft:
    case IrOpcode::kJSShiftRight:
      return ReduceUI32Shift(node, kSigned);
    case IrOpcode::kJSShiftRightLogical:
      return ReduceUI32Shift(node, kUnsigned);
    case IrOpcode::kJSAdd:
      return ReduceJSAdd(node);
    case IrOpcode::kJSSubtract:
    case IrOpcode::kJSMultiply:
    case IrOpcode::kJSDivide:
    case IrOpcode::kJSModulus:
    case IrOpcode::kJSExponentiate:
      return ReduceNumberBinop(node);
    case IrOpcode::kJSBitwiseNot:
      return ReduceJSBitwiseNot(node);
    case IrOpcode::kJSDecrement:
      return ReduceJSDecrement(node);
    case IrOpcode::kJSIncrement:
      return ReduceJSIncrement(node);
    case IrOpcode::kJSNegate:
      return ReduceJSNegate(node);
    case IrOpcode::kJSHasInPrototypeChain:
      return ReduceJSHasInPrototypeChain(node);
    case IrOpcode::kJSOrdinaryHasInstance:
      return ReduceJSOrdinaryHasInstance(node);
    case IrOpcode::kJSToLength:
      return ReduceJSToLength(node);
    case IrOpcode::kJSToName:
      return ReduceJSToName(node);
    case IrOpcode::kJSToNumber:
    case IrOpcode::kJSToNumberConvertBigInt:
      return ReduceJSToNumber(node);
    case IrOpcode::kJSToBigInt:
      return ReduceJSToBigInt(node);
    case IrOpcode::kJSToBigIntConvertNumber:
      return ReduceJSToBigIntConvertNumber(node);
    case IrOpcode::kJSToNumeric:
      return ReduceJSToNumeric(node);
    case IrOpcode::kJSToString:
      return ReduceJSToString(node);
    case IrOpcode::kJSToObject:
      return ReduceJSToObject(node);
    case IrOpcode::kJSLoadNamed:
      return ReduceJSLoadNamed(node);
    case IrOpcode::kJSLoadContext:
      return ReduceJSLoadContext(node);
    case IrOpcode::kJSLoadScriptContext:
      return ReduceJSLoadScriptContext(node);
    case IrOpcode::kJSStoreContext:
      return ReduceJSStoreContext(node);
    case IrOpcode::kJSStoreScriptContext:
      return ReduceJSStoreScriptContext(node);
    case IrOpcode::kJSLoadModule:
      return ReduceJSLoadModule(node);
    case IrOpcode::kJSStoreModule:
      return ReduceJSStoreModule(node);
    case IrOpcode::kJSConstructForwardVarargs:
      return ReduceJSConstructForwardVarargs(node);
    case IrOpcode::kJSConstruct:
      return ReduceJSConstruct(node);
    case IrOpcode::kJSCallForwardVarargs:
      return ReduceJSCallForwardVarargs(node);
    case IrOpcode::kJSCall:
      return ReduceJSCall(node);
    case IrOpcode::kJSForInPrepare:
      return ReduceJSForInPrepare(node);
    case IrOpcode::kJSForInNext:
      return ReduceJSForInNext(node);
    case IrOpcode::kJSHasContextExtension:
      return ReduceJSHasContextExtension(node);
    case IrOpcode::kJSLoadMessage:
      return ReduceJSLoadMessage(node);
    case IrOpcode::kJSStoreMessage:
      return ReduceJSStoreMessage(node);
    case IrOpcode::kJSGeneratorStore:
      return ReduceJSGeneratorStore(node);
    case IrOpcode::kJSGeneratorRestoreContinuation:
      return ReduceJSGeneratorRestoreContinuation(node);
    case IrOpcode::kJSGeneratorRestoreContext:
      return ReduceJSGeneratorRestoreContext(node);
    case IrOpcode::kJSGeneratorRestoreRegister:
      return ReduceJSGeneratorRestoreRegister(node);
    case IrOpcode::kJSGeneratorRestoreInputOrDebugPos:
      return ReduceJSGeneratorRestoreInputOrDebugPos(node);
    case IrOpcode::kJSObjectIsArray:
      return ReduceObjectIsArray(node);
    case IrOpcode::kJSParseInt:
      return ReduceJSParseInt(node);
    case IrOpcode::kJSResolvePromise:
      return ReduceJSResolvePromise(node);
    default:
      break;
  }
  return NoChange();
}

Factory* JSTypedLowering::factory() const { return jsgraph()->factory(); }

Graph* JSTypedLowering::graph() const { return jsgraph()->graph(); }

CompilationDependencies* JSTypedLowering::dependencies() const {
  return broker()->dependencies();
}

Isolate* JSTypedLowering::isolate() const { return jsgraph()->isolate(); }

JSOperatorBuilder* JSTypedLowering::javascript() const {
  return jsgraph()->javascript();
}

CommonOperatorBuilder* JSTypedLowering::common() const {
  return jsgraph()->common();
}

SimplifiedOperatorBuilder* JSTypedLowering::simplified() const {
  return jsgraph()->simplified();
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```