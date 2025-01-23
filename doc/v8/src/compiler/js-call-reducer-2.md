Response: The user wants a summary of the C++ code in `v8/src/compiler/js-call-reducer.cc`. This is part 3 of 6. I need to identify the functionalities implemented in this specific chunk of code.

Looking at the code, I see several `Reduce...` methods. These methods seem to be related to optimizing JavaScript calls by transforming the intermediate representation (IR) of the code.

Specifically, this part seems to handle reductions for:
- Accessing properties with a symbol key (using `broker()` and `key_index`).
- `Object.prototype.isPrototypeOf`.
- `Reflect.apply`.
- `Reflect.construct`.
- `Reflect.getPrototypeOf`.
- `Object.create`.
- `Reflect.get`.
- `Reflect.has`.
- Various `Array.prototype` methods like `forEach`, `reduce`, `map`, `filter`, `find`, `findIndex`, `every`, `includes`, `indexOf`, `some`.
- Calls to WebAssembly functions (`ReduceCallWasmFunction`).
- Calls to API functions defined in C++ (`ReduceCallApiFunction`).
- Optimizations for `arguments` objects in `JSCallWithArrayLike` and `JSConstructWithArrayLike`.
- General `JSCall` optimizations based on target function type and feedback.

To illustrate the interaction with JavaScript, I can pick a simple example like `Object.prototype.isPrototypeOf`.
这是 `v8/src/compiler/js-call-reducer.cc` 文件的一部分，主要负责对 JavaScript 函数调用进行优化。具体来说，这个部分实现了以下功能：

**1. 特殊属性访问优化 (Symbol 键)**

当尝试访问对象的 Symbol 类型的属性时，如果编译器能够确定接收者对象和 Symbol 键，它可以直接获取属性值，避免运行时的查找。

**JavaScript 示例:**

```javascript
const mySymbol = Symbol('myKey');
const obj = { [mySymbol]: 'myValue' };

function getSymbolValue(o, key) {
  return o[key];
}

getSymbolValue(obj, mySymbol); //  编译器可能将此调用优化为直接访问 obj[mySymbol]
```

**2. `Object.prototype.isPrototypeOf` 优化**

如果可以确定 `isPrototypeOf` 的接收者是一个 `JSReceiver` 对象，编译器可以将 `Object.prototype.isPrototypeOf(value)` 调用转换为更高效的 `HasInPrototypeChain(value)` 操作。

**JavaScript 示例:**

```javascript
const proto = {};
const obj = Object.create(proto);

obj.isPrototypeOf(obj); // 编译器可能将其优化为直接检查 obj 的原型链
```

**3. `Reflect` API 优化 (`apply`, `construct`, `getPrototypeOf`, `get`, `has`)**

这部分代码针对 `Reflect` 对象的几个静态方法进行了优化，例如：

*   **`Reflect.apply(target, thisArgument, argumentsList)`:**  被优化为更底层的 `CallWithArrayLike` 操作。
*   **`Reflect.construct(target, argumentsList [, newTarget])`:** 被优化为更底层的 `ConstructWithArrayLike` 操作。
*   **`Reflect.getPrototypeOf(target)`:** 被优化为 `ObjectGetPrototype` 操作。
*   **`Reflect.get(target, key)`:**  编译器会检查 `target` 是否为 `JSReceiver`，如果不是，则抛出 `TypeError`，否则使用更高效的属性获取机制。
*   **`Reflect.has(target, key)`:** 编译器会检查 `target` 是否为 `JSReceiver`，如果不是，则抛出 `TypeError`，否则使用更高效的属性检查机制。

**JavaScript 示例 (`Reflect.apply`):**

```javascript
function myFunction(a, b) {
  return this.value + a + b;
}

const context = { value: 10 };
const args = [5, 3];

Reflect.apply(myFunction, context, args); // 编译器可能将其优化为直接调用 myFunction.call(context, ...args)
```

**4. `Object.create` 优化**

当 `Object.create` 只传入原型参数，没有传入属性描述符时，编译器可以将其转换为更简单的 `CreateObject` 操作。

**JavaScript 示例:**

```javascript
const proto = {};
const obj = Object.create(proto); // 编译器可能将其优化为直接创建以 proto 为原型的对象
```

**5. `Array.prototype` 方法优化 (`forEach`, `reduce`, `map`, `filter`, `find`, `findIndex`, `every`, `includes`, `indexOf`, `some`)**

针对常用的数组迭代方法，编译器会尝试进行内联优化。如果能确定接收者是可优化的数组（例如，元素类型稳定），它可以生成更高效的代码，避免每次迭代都进行类型检查和方法调用。

**JavaScript 示例 (`Array.prototype.forEach`):**

```javascript
const arr = [1, 2, 3];
arr.forEach(item => console.log(item)); // 编译器可能将其优化为类似 for 循环的结构，直接访问数组元素
```

**6. WebAssembly 函数调用优化 (`ReduceCallWasmFunction`)**

如果启用了相应的标志，并且满足特定条件（例如，参数和返回值类型简单），编译器可以将 JavaScript 调用 WebAssembly 函数的操作优化为更直接的调用。

**7. C++ API 函数调用优化 (`ReduceCallApiFunction`)**

对于通过 C++ API 注册的 JavaScript 函数，编译器可以尝试进行优化，例如，直接调用 C++ 函数，避免中间的调用层级。

**8. 基于 `arguments` 对象的调用优化**

对于使用 `arguments` 对象进行调用的场景（例如，`Function.prototype.apply`），如果编译器能确定 `arguments` 对象的来源（例如，通过 `JSCreateArguments` 创建），它可以直接将参数传递给目标函数，避免中间的数组展开操作。

**JavaScript 示例 (基于 `arguments` 对象的优化):**

```javascript
function myFunction() {
  console.log(arguments[0], arguments[1]);
}

function caller() {
  myFunction.apply(null, arguments); // 如果 arguments 来自 caller 函数，编译器可以优化
}

caller(1, 2);
```

**9. 通用 `JSCall` 优化**

编译器会尝试根据目标函数的类型（例如，是否是闭包、是否是绑定函数）以及收集到的类型反馈信息，对 `JSCall` 节点进行更具体的优化。如果能确定调用的目标函数，就可以进行更激进的内联和优化。

总而言之，这个代码片段是 V8 引擎中负责函数调用优化的重要组成部分，它通过分析和转换中间表示，将一些常见的 JavaScript 函数调用模式替换为更高效的底层操作，从而提升代码的执行效率。

### 提示词
```
这是目录为v8/src/compiler/js-call-reducer.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共6部分，请归纳一下它的功能
```

### 源代码
```
y(broker(), key_index);
            Node* lhs = jsgraph()->HeapConstantNoHole(receiver_key.object());
            __ GotoIf(__ ReferenceEqual(TNode<Object>::UncheckedCast(lhs),
                                        TNode<Object>::UncheckedCast(name)),
                      &done, __ TrueConstant());
          }
          __ Goto(&done, __ FalseConstant());
          __ Bind(&done);

          Node* value = done.PhiAt(0);
          ReplaceWithValue(node, value, gasm.effect(), gasm.control());
          return Replace(value);
#undef __
        }
        return inference.NoChange();
      }
    }
  }

  return NoChange();
}

// ES #sec-object.prototype.isprototypeof
Reduction JSCallReducer::ReduceObjectPrototypeIsPrototypeOf(Node* node) {
  JSCallNode n(node);
  Node* receiver = n.receiver();
  Node* value = n.ArgumentOrUndefined(0, jsgraph());
  Effect effect = n.effect();

  // Ensure that the {receiver} is known to be a JSReceiver (so that
  // the ToObject step of Object.prototype.isPrototypeOf is a no-op).
  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() || !inference.AllOfInstanceTypesAreJSReceiver()) {
    return NoChange();
  }

  // We don't check whether {value} is a proper JSReceiver here explicitly,
  // and don't explicitly rule out Primitive {value}s, since all of them
  // have null as their prototype, so the prototype chain walk inside the
  // JSHasInPrototypeChain operator immediately aborts and yields false.
  NodeProperties::ReplaceValueInput(node, value, n.TargetIndex());
  for (int i = node->op()->ValueInputCount(); i > 2; i--) {
    node->RemoveInput(2);
  }
  NodeProperties::ChangeOp(node, javascript()->HasInPrototypeChain());
  return Changed(node);
}

// ES6 section 26.1.1 Reflect.apply ( target, thisArgument, argumentsList )
Reduction JSCallReducer::ReduceReflectApply(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  int arity = p.arity_without_implicit_args();
  // Massage value inputs appropriately.
  static_assert(n.ReceiverIndex() > n.TargetIndex());
  node->RemoveInput(n.ReceiverIndex());
  node->RemoveInput(n.TargetIndex());
  while (arity < 3) {
    node->InsertInput(graph()->zone(), arity++, jsgraph()->UndefinedConstant());
  }
  while (arity-- > 3) {
    node->RemoveInput(arity);
  }
  NodeProperties::ChangeOp(
      node, javascript()->CallWithArrayLike(p.frequency(), p.feedback(),
                                            p.speculation_mode(),
                                            CallFeedbackRelation::kUnrelated));
  return Changed(node).FollowedBy(ReduceJSCallWithArrayLike(node));
}

// ES6 section 26.1.2 Reflect.construct ( target, argumentsList [, newTarget] )
Reduction JSCallReducer::ReduceReflectConstruct(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  int arity = p.arity_without_implicit_args();
  // Massage value inputs appropriately.
  TNode<Object> arg_target = n.ArgumentOrUndefined(0, jsgraph());
  TNode<Object> arg_argument_list = n.ArgumentOrUndefined(1, jsgraph());
  TNode<Object> arg_new_target = n.ArgumentOr(2, arg_target);

  static_assert(n.ReceiverIndex() > n.TargetIndex());
  node->RemoveInput(n.ReceiverIndex());
  node->RemoveInput(n.TargetIndex());

  // TODO(jgruber): This pattern essentially ensures that we have the correct
  // number of inputs for a given argument count. Wrap it in a helper function.
  static_assert(JSConstructNode::FirstArgumentIndex() == 2);
  while (arity < 3) {
    node->InsertInput(graph()->zone(), arity++, jsgraph()->UndefinedConstant());
  }
  while (arity-- > 3) {
    node->RemoveInput(arity);
  }

  static_assert(JSConstructNode::TargetIndex() == 0);
  static_assert(JSConstructNode::NewTargetIndex() == 1);
  static_assert(JSConstructNode::kFeedbackVectorIsLastInput);
  node->ReplaceInput(JSConstructNode::TargetIndex(), arg_target);
  node->ReplaceInput(JSConstructNode::NewTargetIndex(), arg_new_target);
  node->ReplaceInput(JSConstructNode::ArgumentIndex(0), arg_argument_list);

  NodeProperties::ChangeOp(
      node, javascript()->ConstructWithArrayLike(p.frequency(), p.feedback()));
  return Changed(node).FollowedBy(ReduceJSConstructWithArrayLike(node));
}

// ES6 section 26.1.7 Reflect.getPrototypeOf ( target )
Reduction JSCallReducer::ReduceReflectGetPrototypeOf(Node* node) {
  JSCallNode n(node);
  Node* target = n.ArgumentOrUndefined(0, jsgraph());
  return ReduceObjectGetPrototype(node, target);
}

// ES6 section #sec-object.create Object.create(proto, properties)
Reduction JSCallReducer::ReduceObjectCreate(Node* node) {
  JSCallNode n(node);
  Node* properties = n.ArgumentOrUndefined(1, jsgraph());
  if (properties != jsgraph()->UndefinedConstant()) return NoChange();

  Node* context = n.context();
  FrameState frame_state = n.frame_state();
  Effect effect = n.effect();
  Control control = n.control();
  Node* prototype = n.ArgumentOrUndefined(0, jsgraph());
  node->ReplaceInput(0, prototype);
  node->ReplaceInput(1, context);
  node->ReplaceInput(2, frame_state);
  node->ReplaceInput(3, effect);
  node->ReplaceInput(4, control);
  node->TrimInputCount(5);
  NodeProperties::ChangeOp(node, javascript()->CreateObject());
  return Changed(node);
}

// ES section #sec-reflect.get
Reduction JSCallReducer::ReduceReflectGet(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  int arity = p.arity_without_implicit_args();
  if (arity != 2) return NoChange();
  Node* target = n.Argument(0);
  Node* key = n.Argument(1);
  Node* context = n.context();
  FrameState frame_state = n.frame_state();
  Effect effect = n.effect();
  Control control = n.control();

  // Check whether {target} is a JSReceiver.
  Node* check = graph()->NewNode(simplified()->ObjectIsReceiver(), target);
  Node* branch =
      graph()->NewNode(common()->Branch(BranchHint::kTrue), check, control);

  // Throw an appropriate TypeError if the {target} is not a JSReceiver.
  Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
  Node* efalse = effect;
  {
    if_false = efalse = graph()->NewNode(
        javascript()->CallRuntime(Runtime::kThrowTypeError, 2),
        jsgraph()->ConstantNoHole(
            static_cast<int>(MessageTemplate::kCalledOnNonObject)),
        jsgraph()->HeapConstantNoHole(factory()->ReflectGet_string()), context,
        frame_state, efalse, if_false);
  }

  // Otherwise just use the existing GetPropertyStub.
  Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
  Node* etrue = effect;
  Node* vtrue;
  {
    Callable callable = Builtins::CallableFor(isolate(), Builtin::kGetProperty);
    auto call_descriptor = Linkage::GetStubCallDescriptor(
        graph()->zone(), callable.descriptor(),
        callable.descriptor().GetStackParameterCount(),
        CallDescriptor::kNeedsFrameState, Operator::kNoProperties);
    Node* stub_code = jsgraph()->HeapConstantNoHole(callable.code());
    vtrue = etrue = if_true =
        graph()->NewNode(common()->Call(call_descriptor), stub_code, target,
                         key, context, frame_state, etrue, if_true);
  }

  // Rewire potential exception edges.
  Node* on_exception = nullptr;
  if (NodeProperties::IsExceptionalCall(node, &on_exception)) {
    // Create appropriate {IfException} and {IfSuccess} nodes.
    Node* extrue = graph()->NewNode(common()->IfException(), etrue, if_true);
    if_true = graph()->NewNode(common()->IfSuccess(), if_true);
    Node* exfalse = graph()->NewNode(common()->IfException(), efalse, if_false);
    if_false = graph()->NewNode(common()->IfSuccess(), if_false);

    // Join the exception edges.
    Node* merge = graph()->NewNode(common()->Merge(2), extrue, exfalse);
    Node* ephi =
        graph()->NewNode(common()->EffectPhi(2), extrue, exfalse, merge);
    Node* phi =
        graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                         extrue, exfalse, merge);
    ReplaceWithValue(on_exception, phi, ephi, merge);
  }

  // Connect the throwing path to end.
  if_false = graph()->NewNode(common()->Throw(), efalse, if_false);
  MergeControlToEnd(graph(), common(), if_false);

  // Continue on the regular path.
  ReplaceWithValue(node, vtrue, etrue, if_true);
  return Changed(vtrue);
}

// ES section #sec-reflect.has
Reduction JSCallReducer::ReduceReflectHas(Node* node) {
  JSCallNode n(node);
  Node* target = n.ArgumentOrUndefined(0, jsgraph());
  Node* key = n.ArgumentOrUndefined(1, jsgraph());
  Node* context = n.context();
  Effect effect = n.effect();
  Control control = n.control();
  FrameState frame_state = n.frame_state();

  // Check whether {target} is a JSReceiver.
  Node* check = graph()->NewNode(simplified()->ObjectIsReceiver(), target);
  Node* branch =
      graph()->NewNode(common()->Branch(BranchHint::kTrue), check, control);

  // Throw an appropriate TypeError if the {target} is not a JSReceiver.
  Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
  Node* efalse = effect;
  {
    if_false = efalse = graph()->NewNode(
        javascript()->CallRuntime(Runtime::kThrowTypeError, 2),
        jsgraph()->ConstantNoHole(
            static_cast<int>(MessageTemplate::kCalledOnNonObject)),
        jsgraph()->HeapConstantNoHole(factory()->ReflectHas_string()), context,
        frame_state, efalse, if_false);
  }

  // Otherwise just use the existing {JSHasProperty} logic.
  Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
  Node* etrue = effect;
  Node* vtrue;
  {
    // TODO(magardn): collect feedback so this can be optimized
    vtrue = etrue = if_true = graph()->NewNode(
        javascript()->HasProperty(FeedbackSource()), target, key,
        jsgraph()->UndefinedConstant(), context, frame_state, etrue, if_true);
  }

  // Rewire potential exception edges.
  Node* on_exception = nullptr;
  if (NodeProperties::IsExceptionalCall(node, &on_exception)) {
    // Create appropriate {IfException} and {IfSuccess} nodes.
    Node* extrue = graph()->NewNode(common()->IfException(), etrue, if_true);
    if_true = graph()->NewNode(common()->IfSuccess(), if_true);
    Node* exfalse = graph()->NewNode(common()->IfException(), efalse, if_false);
    if_false = graph()->NewNode(common()->IfSuccess(), if_false);

    // Join the exception edges.
    Node* merge = graph()->NewNode(common()->Merge(2), extrue, exfalse);
    Node* ephi =
        graph()->NewNode(common()->EffectPhi(2), extrue, exfalse, merge);
    Node* phi =
        graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                         extrue, exfalse, merge);
    ReplaceWithValue(on_exception, phi, ephi, merge);
  }

  // Connect the throwing path to end.
  if_false = graph()->NewNode(common()->Throw(), efalse, if_false);
  MergeControlToEnd(graph(), common(), if_false);

  // Continue on the regular path.
  ReplaceWithValue(node, vtrue, etrue, if_true);
  return Changed(vtrue);
}

namespace {

bool CanInlineArrayIteratingBuiltin(JSHeapBroker* broker,
                                    ZoneRefSet<Map> const& receiver_maps,
                                    ElementsKind* kind_return) {
  DCHECK_NE(0, receiver_maps.size());
  *kind_return = receiver_maps[0].elements_kind();
  for (MapRef map : receiver_maps) {
    if (!map.supports_fast_array_iteration(broker) ||
        !UnionElementsKindUptoSize(kind_return, map.elements_kind())) {
      return false;
    }
  }
  return true;
}

bool CanInlineArrayResizingBuiltin(JSHeapBroker* broker,
                                   ZoneRefSet<Map> const& receiver_maps,
                                   std::vector<ElementsKind>* kinds,
                                   bool builtin_is_push = false) {
  DCHECK_NE(0, receiver_maps.size());
  for (MapRef map : receiver_maps) {
    if (!map.supports_fast_array_resize(broker)) return false;
    // TODO(turbofan): We should also handle fast holey double elements once
    // we got the hole NaN mess sorted out in TurboFan/V8.
    if (map.elements_kind() == HOLEY_DOUBLE_ELEMENTS && !builtin_is_push) {
      return false;
    }
    ElementsKind current_kind = map.elements_kind();
    auto kind_ptr = kinds->data();
    size_t i;
    for (i = 0; i < kinds->size(); i++, kind_ptr++) {
      if (UnionElementsKindUptoPackedness(kind_ptr, current_kind)) {
        break;
      }
    }
    if (i == kinds->size()) kinds->push_back(current_kind);
  }
  return true;
}

// Wraps common setup code for iterating array builtins.
class IteratingArrayBuiltinHelper {
 public:
  IteratingArrayBuiltinHelper(Node* node, JSHeapBroker* broker,
                              JSGraph* jsgraph,
                              CompilationDependencies* dependencies)
      : receiver_(NodeProperties::GetValueInput(node, 1)),
        effect_(NodeProperties::GetEffectInput(node)),
        control_(NodeProperties::GetControlInput(node)),
        inference_(broker, receiver_, effect_) {
    if (!v8_flags.turbo_inline_array_builtins) return;

    DCHECK_EQ(IrOpcode::kJSCall, node->opcode());
    const CallParameters& p = CallParametersOf(node->op());
    if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
      return;
    }

    // Try to determine the {receiver} map.
    if (!inference_.HaveMaps()) return;
    ZoneRefSet<Map> const& receiver_maps = inference_.GetMaps();

    if (!CanInlineArrayIteratingBuiltin(broker, receiver_maps,
                                        &elements_kind_)) {
      return;
    }

    // TODO(jgruber): May only be needed for holey elements kinds.
    if (!dependencies->DependOnNoElementsProtector()) return;

    has_stability_dependency_ = inference_.RelyOnMapsPreferStability(
        dependencies, jsgraph, &effect_, control_, p.feedback());

    can_reduce_ = true;
  }

  bool can_reduce() const { return can_reduce_; }
  bool has_stability_dependency() const { return has_stability_dependency_; }
  Effect effect() const { return effect_; }
  Control control() const { return control_; }
  MapInference* inference() { return &inference_; }
  ElementsKind elements_kind() const { return elements_kind_; }

 private:
  bool can_reduce_ = false;
  bool has_stability_dependency_ = false;
  Node* receiver_;
  Effect effect_;
  Control control_;
  MapInference inference_;
  ElementsKind elements_kind_;
};

}  // namespace

Reduction JSCallReducer::ReduceArrayForEach(Node* node,
                                            SharedFunctionInfoRef shared) {
  IteratingArrayBuiltinHelper h(node, broker(), jsgraph(), dependencies());
  if (!h.can_reduce()) return h.inference()->NoChange();

  IteratingArrayBuiltinReducerAssembler a(this, node);
  a.InitializeEffectControl(h.effect(), h.control());
  TNode<Object> subgraph = a.ReduceArrayPrototypeForEach(
      h.inference(), h.has_stability_dependency(), h.elements_kind(), shared);
  return ReplaceWithSubgraph(&a, subgraph);
}

Reduction JSCallReducer::ReduceArrayReduce(Node* node,
                                           SharedFunctionInfoRef shared) {
  IteratingArrayBuiltinHelper h(node, broker(), jsgraph(), dependencies());
  if (!h.can_reduce()) return h.inference()->NoChange();

  IteratingArrayBuiltinReducerAssembler a(this, node);
  a.InitializeEffectControl(h.effect(), h.control());
  TNode<Object> subgraph = a.ReduceArrayPrototypeReduce(
      h.inference(), h.has_stability_dependency(), h.elements_kind(),
      ArrayReduceDirection::kLeft, shared);
  return ReplaceWithSubgraph(&a, subgraph);
}

Reduction JSCallReducer::ReduceArrayReduceRight(Node* node,
                                                SharedFunctionInfoRef shared) {
  IteratingArrayBuiltinHelper h(node, broker(), jsgraph(), dependencies());
  if (!h.can_reduce()) return h.inference()->NoChange();

  IteratingArrayBuiltinReducerAssembler a(this, node);
  a.InitializeEffectControl(h.effect(), h.control());
  TNode<Object> subgraph = a.ReduceArrayPrototypeReduce(
      h.inference(), h.has_stability_dependency(), h.elements_kind(),
      ArrayReduceDirection::kRight, shared);
  return ReplaceWithSubgraph(&a, subgraph);
}

Reduction JSCallReducer::ReduceArrayMap(Node* node,
                                        SharedFunctionInfoRef shared) {
  IteratingArrayBuiltinHelper h(node, broker(), jsgraph(), dependencies());
  if (!h.can_reduce()) return h.inference()->NoChange();

  // Calls CreateArray and thus requires this additional protector dependency.
  if (!dependencies()->DependOnArraySpeciesProtector()) {
    return h.inference()->NoChange();
  }

  IteratingArrayBuiltinReducerAssembler a(this, node);
  a.InitializeEffectControl(h.effect(), h.control());

  TNode<Object> subgraph =
      a.ReduceArrayPrototypeMap(h.inference(), h.has_stability_dependency(),
                                h.elements_kind(), shared, native_context());
  return ReplaceWithSubgraph(&a, subgraph);
}

Reduction JSCallReducer::ReduceArrayFilter(Node* node,
                                           SharedFunctionInfoRef shared) {
  IteratingArrayBuiltinHelper h(node, broker(), jsgraph(), dependencies());
  if (!h.can_reduce()) return h.inference()->NoChange();

  // Calls CreateArray and thus requires this additional protector dependency.
  if (!dependencies()->DependOnArraySpeciesProtector()) {
    return h.inference()->NoChange();
  }

  IteratingArrayBuiltinReducerAssembler a(this, node);
  a.InitializeEffectControl(h.effect(), h.control());

  TNode<Object> subgraph =
      a.ReduceArrayPrototypeFilter(h.inference(), h.has_stability_dependency(),
                                   h.elements_kind(), shared, native_context());
  return ReplaceWithSubgraph(&a, subgraph);
}

Reduction JSCallReducer::ReduceArrayFind(Node* node,
                                         SharedFunctionInfoRef shared) {
  IteratingArrayBuiltinHelper h(node, broker(), jsgraph(), dependencies());
  if (!h.can_reduce()) return h.inference()->NoChange();

  IteratingArrayBuiltinReducerAssembler a(this, node);
  a.InitializeEffectControl(h.effect(), h.control());

  TNode<Object> subgraph = a.ReduceArrayPrototypeFind(
      h.inference(), h.has_stability_dependency(), h.elements_kind(), shared,
      native_context(), ArrayFindVariant::kFind);
  return ReplaceWithSubgraph(&a, subgraph);
}

Reduction JSCallReducer::ReduceArrayFindIndex(Node* node,
                                              SharedFunctionInfoRef shared) {
  IteratingArrayBuiltinHelper h(node, broker(), jsgraph(), dependencies());
  if (!h.can_reduce()) return h.inference()->NoChange();

  IteratingArrayBuiltinReducerAssembler a(this, node);
  a.InitializeEffectControl(h.effect(), h.control());

  TNode<Object> subgraph = a.ReduceArrayPrototypeFind(
      h.inference(), h.has_stability_dependency(), h.elements_kind(), shared,
      native_context(), ArrayFindVariant::kFindIndex);
  return ReplaceWithSubgraph(&a, subgraph);
}

Reduction JSCallReducer::ReduceArrayEvery(Node* node,
                                          SharedFunctionInfoRef shared) {
  IteratingArrayBuiltinHelper h(node, broker(), jsgraph(), dependencies());
  if (!h.can_reduce()) return h.inference()->NoChange();

  IteratingArrayBuiltinReducerAssembler a(this, node);
  a.InitializeEffectControl(h.effect(), h.control());

  TNode<Object> subgraph = a.ReduceArrayPrototypeEverySome(
      h.inference(), h.has_stability_dependency(), h.elements_kind(), shared,
      native_context(), ArrayEverySomeVariant::kEvery);
  return ReplaceWithSubgraph(&a, subgraph);
}

// ES7 Array.prototype.inludes(searchElement[, fromIndex])
// #sec-array.prototype.includes
Reduction JSCallReducer::ReduceArrayIncludes(Node* node) {
  IteratingArrayBuiltinHelper h(node, broker(), jsgraph(), dependencies());
  if (!h.can_reduce()) return h.inference()->NoChange();

  IteratingArrayBuiltinReducerAssembler a(this, node);
  a.InitializeEffectControl(h.effect(), h.control());

  TNode<Object> subgraph = a.ReduceArrayPrototypeIndexOfIncludes(
      h.elements_kind(), ArrayIndexOfIncludesVariant::kIncludes);
  return ReplaceWithSubgraph(&a, subgraph);
}

// ES6 Array.prototype.indexOf(searchElement[, fromIndex])
// #sec-array.prototype.indexof
Reduction JSCallReducer::ReduceArrayIndexOf(Node* node) {
  IteratingArrayBuiltinHelper h(node, broker(), jsgraph(), dependencies());
  if (!h.can_reduce()) return h.inference()->NoChange();

  IteratingArrayBuiltinReducerAssembler a(this, node);
  a.InitializeEffectControl(h.effect(), h.control());

  TNode<Object> subgraph = a.ReduceArrayPrototypeIndexOfIncludes(
      h.elements_kind(), ArrayIndexOfIncludesVariant::kIndexOf);
  return ReplaceWithSubgraph(&a, subgraph);
}

Reduction JSCallReducer::ReduceArraySome(Node* node,
                                         SharedFunctionInfoRef shared) {
  IteratingArrayBuiltinHelper h(node, broker(), jsgraph(), dependencies());
  if (!h.can_reduce()) return h.inference()->NoChange();

  IteratingArrayBuiltinReducerAssembler a(this, node);
  a.InitializeEffectControl(h.effect(), h.control());

  TNode<Object> subgraph = a.ReduceArrayPrototypeEverySome(
      h.inference(), h.has_stability_dependency(), h.elements_kind(), shared,
      native_context(), ArrayEverySomeVariant::kSome);
  return ReplaceWithSubgraph(&a, subgraph);
}

#if V8_ENABLE_WEBASSEMBLY

namespace {

bool CanInlineJSToWasmCall(const wasm::CanonicalSig* wasm_signature) {
  if (wasm_signature->return_count() > 1) {
    return false;
  }

  for (auto type : wasm_signature->all()) {
#if defined(V8_TARGET_ARCH_32_BIT)
    if (type == wasm::kCanonicalI64) return false;
#endif
    if (type != wasm::kCanonicalI32 && type != wasm::kCanonicalI64 &&
        type != wasm::kCanonicalF32 && type != wasm::kCanonicalF64 &&
        type != wasm::kCanonicalExternRef) {
      return false;
    }
  }

  return true;
}

}  // namespace

Reduction JSCallReducer::ReduceCallWasmFunction(Node* node,
                                                SharedFunctionInfoRef shared) {
  DCHECK(flags() & kInlineJSToWasmCalls);

  JSCallNode n(node);
  const CallParameters& p = n.Parameters();

  // Avoid deoptimization loops
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  // Read the trusted object only once to ensure a consistent view on it.
  Tagged<Object> trusted_data = shared.object()->GetTrustedData();
  if (!IsWasmExportedFunctionData(trusted_data)) return NoChange();
  Tagged<WasmExportedFunctionData> function_data =
      Cast<WasmExportedFunctionData>(trusted_data);

  if (function_data->is_promising()) return NoChange();

  Tagged<WasmTrustedInstanceData> instance_data =
      function_data->instance_data();
  const wasm::CanonicalSig* wasm_signature = function_data->sig();
  if (!CanInlineJSToWasmCall(wasm_signature)) {
    return NoChange();
  }

  wasm::NativeModule* native_module = instance_data->native_module();
  const wasm::WasmModule* wasm_module = native_module->module();
  int wasm_function_index = function_data->function_index();

  if (wasm_module_for_inlining_ == nullptr) {
    wasm_module_for_inlining_ = wasm_module;
  }

  // TODO(mliedtke): We should be able to remove module, signature, native
  // module and function index from the SharedFunctionInfoRef. However, for some
  // reason I may dereference the SharedFunctionInfoRef here but not in
  // JSInliningHeuristic later on.
  const Operator* op =
      javascript()->CallWasm(wasm_module, wasm_signature, wasm_function_index,
                             shared, native_module, p.feedback());

  // Remove additional inputs
  size_t actual_arity = n.ArgumentCount();
  DCHECK(JSCallNode::kFeedbackVectorIsLastInput);
  DCHECK_EQ(actual_arity + JSWasmCallNode::kExtraInputCount - 1,
            n.FeedbackVectorIndex());
  size_t expected_arity = wasm_signature->parameter_count();

  while (actual_arity > expected_arity) {
    int removal_index =
        static_cast<int>(n.FirstArgumentIndex() + expected_arity);
    DCHECK_LT(removal_index, static_cast<int>(node->InputCount()));
    node->RemoveInput(removal_index);
    actual_arity--;
  }

  // Add missing inputs
  while (actual_arity < expected_arity) {
    int insertion_index = n.ArgumentIndex(n.ArgumentCount());
    node->InsertInput(graph()->zone(), insertion_index,
                      jsgraph()->UndefinedConstant());
    actual_arity++;
  }

  NodeProperties::ChangeOp(node, op);
  return Changed(node);
}
#endif  // V8_ENABLE_WEBASSEMBLY

// Given a FunctionTemplateInfo, checks whether the fast API call can be
// optimized, applying the initial step of the overload resolution algorithm:
// Given an overload set function_template_info.c_signatures, and a list of
// arguments of size arg_count:
// 1. Remove from the set all entries whose type list is not of length
//    arg_count.
// Returns an array with the indexes of the remaining entries in S, which
// represents the set of "optimizable" function overloads.

FastApiCallFunction GetFastApiCallTarget(
    JSHeapBroker* broker, FunctionTemplateInfoRef function_template_info,
    size_t arg_count) {
  if (!v8_flags.turbo_fast_api_calls) return {0, nullptr};

  static constexpr int kReceiver = 1;

  ZoneVector<Address> functions = function_template_info.c_functions(broker);
  ZoneVector<const CFunctionInfo*> signatures =
      function_template_info.c_signatures(broker);
  const size_t overloads_count = signatures.size();

  // Only considers entries whose type list length matches arg_count.
  for (size_t i = 0; i < overloads_count; i++) {
    const CFunctionInfo* c_signature = signatures[i];
    const size_t len = c_signature->ArgumentCount() - kReceiver;
    bool optimize_to_fast_call = (len == arg_count);

    optimize_to_fast_call =
        optimize_to_fast_call &&
        fast_api_call::CanOptimizeFastSignature(c_signature);

    if (optimize_to_fast_call) {
      // TODO(nicohartmann@): {Flags::kEnforceRangeBit} is currently only
      // supported on 64 bit architectures. We should support this on 32 bit
      // architectures.
#if defined(V8_TARGET_ARCH_32_BIT)
      for (unsigned int i = 0; i < c_signature->ArgumentCount(); ++i) {
        const uint8_t flags =
            static_cast<uint8_t>(c_signature->ArgumentInfo(i).GetFlags());
        if (flags & static_cast<uint8_t>(CTypeInfo::Flags::kEnforceRangeBit)) {
          // Bailout
          return {0, nullptr};
        }
      }
#endif
      return {functions[i], c_signature};
    }
  }

  return {0, nullptr};
}

Reduction JSCallReducer::ReduceCallApiFunction(Node* node,
                                               SharedFunctionInfoRef shared) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  int const argc = p.arity_without_implicit_args();
  Node* target = n.target();
  Node* global_proxy = jsgraph()->ConstantNoHole(
      native_context().global_proxy_object(broker()), broker());
  Node* receiver = (p.convert_mode() == ConvertReceiverMode::kNullOrUndefined)
                       ? global_proxy
                       : n.receiver();
  Node* holder;
  Node* context = n.context();
  Effect effect = n.effect();
  Control control = n.control();
  FrameState frame_state = n.frame_state();

  if (!shared.function_template_info(broker()).has_value()) {
    TRACE_BROKER_MISSING(
        broker(), "FunctionTemplateInfo for function with SFI " << shared);
    return NoChange();
  }

  // See if we can optimize this API call to {shared}.
  FunctionTemplateInfoRef function_template_info(
      shared.function_template_info(broker()).value());

  if (function_template_info.accept_any_receiver() &&
      function_template_info.is_signature_undefined(broker())) {
    // We might be able to
    // optimize the API call depending on the {function_template_info}.
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
    //
    receiver = holder = effect = graph()->NewNode(
        simplified()->ConvertReceiver(p.convert_mode()), receiver,
        jsgraph()->ConstantNoHole(native_context(), broker()), global_proxy,
        effect, control);
  } else {
    // Try to infer the {receiver} maps from the graph.
    MapInference inference(broker(), receiver, effect);
    if (inference.HaveMaps()) {
      ZoneRefSet<Map> const& receiver_maps = inference.GetMaps();
      MapRef first_receiver_map = receiver_maps[0];

      // See if we can constant-fold the compatible receiver checks.
      HolderLookupResult api_holder =
          function_template_info.LookupHolderOfExpectedType(broker(),
                                                            first_receiver_map);
      if (api_holder.lookup == CallOptimization::kHolderNotFound) {
        return inference.NoChange();
      }

      // Check that all {receiver_maps} are actually JSReceiver maps and
      // that the {function_template_info} accepts them without access
      // checks (even if "access check needed" is set for {receiver}).
      //
      // Note that we don't need to know the concrete {receiver} maps here,
      // meaning it's fine if the {receiver_maps} are unreliable, and we also
      // don't need to install any stability dependencies, since the only
      // relevant information regarding the {receiver} is the Map::constructor
      // field on the root map (which is different from the JavaScript exposed
      // "constructor" property) and that field cannot change.
      //
      // So if we know that {receiver} had a certain constructor at some point
      // in the past (i.e. it had a certain map), then this constructor is going
      // to be the same later, since this information cannot change with map
      // transitions.
      //
      // The same is true for the instance type, e.g. we still know that the
      // instance type is JSObject even if that information is unreliable, and
      // the "access check needed" bit, which also cannot change later.
      CHECK(first_receiver_map.IsJSReceiverMap());
      CHECK(!first_receiver_map.is_access_check_needed() ||
            function_template_info.accept_any_receiver());

      for (size_t i = 1; i < receiver_maps.size(); ++i) {
        MapRef receiver_map = receiver_maps[i];
        HolderLookupResult holder_i =
            function_template_info.LookupHolderOfExpectedType(broker(),
                                                              receiver_map);

        if (api_holder.lookup != holder_i.lookup) return inference.NoChange();
        DCHECK(holder_i.lookup == CallOptimization::kHolderFound ||
               holder_i.lookup == CallOptimization::kHolderIsReceiver);
        if (holder_i.lookup == CallOptimization::kHolderFound) {
          DCHECK(api_holder.holder.has_value() && holder_i.holder.has_value());
          if (!api_holder.holder->equals(*holder_i.holder)) {
            return inference.NoChange();
          }
        }

        CHECK(receiver_map.IsJSReceiverMap());
        CHECK(!receiver_map.is_access_check_needed() ||
              function_template_info.accept_any_receiver());
      }

      if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation &&
          !inference.RelyOnMapsViaStability(dependencies())) {
        // We were not able to make the receiver maps reliable without map
        // checks but doing map checks would lead to deopt loops, so give up.
        return inference.NoChange();
      }

      // TODO(neis): The maps were used in a way that does not actually require
      // map checks or stability dependencies.
      inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                          control, p.feedback());

      // Determine the appropriate holder for the {lookup}.
      holder = api_holder.lookup == CallOptimization::kHolderFound
                   ? jsgraph()->ConstantNoHole(*api_holder.holder, broker())
                   : receiver;
    } else {
      // We don't have enough information to eliminate the access check
      // and/or the compatible receiver check, so use the generic builtin
      // that does those checks dynamically. This is still significantly
      // faster than the generic call sequence.
      Builtin builtin_name;
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
      receiver = holder = effect = graph()->NewNode(
          simplified()->ConvertReceiver(p.convert_mode()), receiver,
          jsgraph()->ConstantNoHole(native_context(), broker()), global_proxy,
          effect, control);

      Callable callable = Builtins::CallableFor(isolate(), builtin_name);
      auto call_descriptor = Linkage::GetStubCallDescriptor(
          graph()->zone(), callable.descriptor(),
          argc + 1 /* implicit receiver */, CallDescriptor::kNeedsFrameState);
      node->RemoveInput(n.FeedbackVectorIndex());
      node->InsertInput(graph()->zone(), 0,
                        jsgraph()->HeapConstantNoHole(callable.code()));
      node->ReplaceInput(
          1, jsgraph()->ConstantNoHole(function_template_info, broker()));
      node->InsertInput(graph()->zone(), 2,
                        jsgraph()->Int32Constant(JSParameterCount(argc)));
      node->ReplaceInput(3, receiver);       // Update receiver input.
      node->ReplaceInput(6 + argc, effect);  // Update effect input.
      NodeProperties::ChangeOp(node, common()->Call(call_descriptor));
      return Changed(node);
    }
  }

  // TODO(turbofan): Consider introducing a JSCallApiCallback operator for
  // this and lower it during JSGenericLowering, and unify this with the
  // JSNativeContextSpecialization::InlineApiCall method a bit.
  compiler::OptionalObjectRef maybe_callback_data =
      function_template_info.callback_data(broker());
  // Check if the function has an associated C++ code to execute.
  if (!maybe_callback_data.has_value()) {
    // TODO(ishell): consider generating "return undefined" for empty function
    // instead of failing.
    TRACE_BROKER_MISSING(broker(), "call code for function template info "
                                       << function_template_info);
    return NoChange();
  }

  // Handles overloaded functions.
  FastApiCallFunction c_function =
      GetFastApiCallTarget(broker(), function_template_info, argc);

  if (c_function.address) {
    FastApiCallReducerAssembler a(this, node, function_template_info,
                                  c_function, receiver, holder, shared, target,
                                  argc, effect);
    Node* fast_call_subgraph = a.ReduceFastApiCall();

    return Replace(fast_call_subgraph);
  }

  // Slow call

  bool no_profiling = broker()->dependencies()->DependOnNoProfilingProtector();
  Callable call_api_callback = Builtins::CallableFor(
      isolate(), no_profiling ? Builtin::kCallApiCallbackOptimizedNoProfiling
                              : Builtin::kCallApiCallbackOptimized);
  CallInterfaceDescriptor cid = call_api_callback.descriptor();
  auto call_descriptor =
      Linkage::GetStubCallDescriptor(graph()->zone(), cid, argc + 1 /*
     implicit receiver */, CallDescriptor::kNeedsFrameState);
  ApiFunction api_function(function_template_info.callback(broker()));
  ExternalReference function_reference = ExternalReference::Create(
      &api_function, ExternalReference::DIRECT_API_CALL);

  Node* continuation_frame_state = CreateInlinedApiFunctionFrameState(
      jsgraph(), shared, target, context, receiver, frame_state);

  node->RemoveInput(n.FeedbackVectorIndex());
  node->InsertInput(graph()->zone(), 0,
                    jsgraph()->HeapConstantNoHole(call_api_callback.code()));
  node->ReplaceInput(1, jsgraph()->ExternalConstant(function_reference));
  node->InsertInput(graph()->zone(), 2, jsgraph()->ConstantNoHole(argc));
  node->InsertInput(
      graph()->zone(), 3,
      jsgraph()->HeapConstantNoHole(function_template_info.object()));
  node->InsertInput(graph()->zone(), 4, holder);
  node->ReplaceInput(5, receiver);  // Update receiver input.
  // 6 + argc is context input.
  node->ReplaceInput(6 + argc + 1, continuation_frame_state);
  node->ReplaceInput(6 + argc + 2, effect);
  NodeProperties::ChangeOp(node, common()->Call(call_descriptor));
  return Changed(node);
}

namespace {

// Check whether elements aren't mutated; we play it extremely safe here by
// explicitly checking that {node} is only used by {LoadField} or
// {LoadElement}.
bool IsSafeArgumentsElements(Node* node) {
  for (Edge const edge : node->use_edges()) {
    if (!NodeProperties::IsValueEdge(edge)) continue;
    if (edge.from()->opcode() != IrOpcode::kLoadField &&
        edge.from()->opcode() != IrOpcode::kLoadElement) {
      return false;
    }
  }
  return true;
}

#ifdef DEBUG
bool IsCallOrConstructWithArrayLike(Node* node) {
  return node->opcode() == IrOpcode::kJSCallWithArrayLike ||
         node->opcode() == IrOpcode::kJSConstructWithArrayLike;
}
#endif

bool IsCallOrConstructWithSpread(Node* node) {
  return node->opcode() == IrOpcode::kJSCallWithSpread ||
         node->opcode() == IrOpcode::kJSConstructWithSpread;
}

bool IsCallWithArrayLikeOrSpread(Node* node) {
  return node->opcode() == IrOpcode::kJSCallWithArrayLike ||
         node->opcode() == IrOpcode::kJSCallWithSpread;
}

}  // namespace

Node* JSCallReducer::ConvertHoleToUndefined(Node* value, ElementsKind kind) {
  DCHECK(IsHoleyElementsKind(kind));
  if (kind == HOLEY_DOUBLE_ELEMENTS) {
    return graph()->NewNode(simplified()->ChangeFloat64HoleToTagged(), value);
  }
  return graph()->NewNode(simplified()->ConvertTaggedHoleToUndefined(), value);
}

void JSCallReducer::CheckIfConstructor(Node* construct) {
  JSConstructNode n(construct);
  Node* new_target = n.new_target();
  Control control = n.control();

  Node* check =
      graph()->NewNode(simplified()->ObjectIsConstructor(), new_target);
  Node* check_branch =
      graph()->NewNode(common()->Branch(BranchHint::kTrue), check, control);
  Node* check_fail = graph()->NewNode(common()->IfFalse(), check_branch);
  Node* check_throw = check_fail = graph()->NewNode(
      javascript()->CallRuntime(Runtime::kThrowTypeError, 2),
      jsgraph()->ConstantNoHole(
          static_cast<int>(MessageTemplate::kNotConstructor)),
      new_target, n.context(), n.frame_state(), n.effect(), check_fail);
  control = graph()->NewNode(common()->IfTrue(), check_branch);
  NodeProperties::ReplaceControlInput(construct, control);

  // Rewire potential exception edges.
  Node* on_exception = nullptr;
  if (NodeProperties::IsExceptionalCall(construct, &on_exception)) {
    // Create appropriate {IfException}  and {IfSuccess} nodes.
    Node* if_exception =
        graph()->NewNode(common()->IfException(), check_throw, check_fail);
    check_fail = graph()->NewNode(common()->IfSuccess(), check_fail);

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

  // The above %ThrowTypeError runtime call is an unconditional throw,
  // making it impossible to return a successful completion in this case. We
  // simply connect the successful completion to the graph end.
  Node* throw_node =
      graph()->NewNode(common()->Throw(), check_throw, check_fail);
  MergeControlToEnd(graph(), common(), throw_node);
}

namespace {

bool ShouldUseCallICFeedback(Node* node) {
  HeapObjectMatcher m(node);
  if (m.HasResolvedValue() || m.IsCheckClosure() || m.IsJSCreateClosure()) {
    // Don't use CallIC feedback when we know the function
    // being called, i.e. either know the closure itself or
    // at least the SharedFunctionInfo.
    return false;
  } else if (m.IsPhi()) {
    // Protect against endless loops here.
    Node* control = NodeProperties::GetControlInput(node);
    if (control->opcode() == IrOpcode::kLoop ||
        control->opcode() == IrOpcode::kDead)
      return false;
    // Check if {node} is a Phi of nodes which shouldn't
    // use CallIC feedback (not looking through loops).
    int const value_input_count = m.node()->op()->ValueInputCount();
    for (int n = 0; n < value_input_count; ++n) {
      if (ShouldUseCallICFeedback(node->InputAt(n))) return true;
    }
    return false;
  }
  return true;
}

}  // namespace

Node* JSCallReducer::CheckArrayLength(Node* array, ElementsKind elements_kind,
                                      uint32_t array_length,
                                      const FeedbackSource& feedback_source,
                                      Effect effect, Control control) {
  Node* length = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForJSArrayLength(elements_kind)),
      array, effect, control);
  Node* check = graph()->NewNode(simplified()->NumberEqual(), length,
                                 jsgraph()->ConstantNoHole(array_length));
  return graph()->NewNode(
      simplified()->CheckIf(DeoptimizeReason::kArrayLengthChanged,
                            feedback_source),
      check, effect, control);
}

Reduction
JSCallReducer::ReduceCallOrConstructWithArrayLikeOrSpreadOfCreateArguments(
    Node* node, Node* arguments_list, int arraylike_or_spread_index,
    CallFrequency const& frequency, FeedbackSource const& feedback,
    SpeculationMode speculation_mode, CallFeedbackRelation feedback_relation) {
  DCHECK_EQ(arguments_list->opcode(), IrOpcode::kJSCreateArguments);

  // Check if {node} is the only value user of {arguments_list} (except for
  // value uses in frame states). If not, we give up for now.
  for (Edge edge : arguments_list->use_edges()) {
    if (!NodeProperties::IsValueEdge(edge)) continue;
    Node* const user = edge.from();
    switch (user->opcode()) {
      case IrOpcode::kCheckMaps:
      case IrOpcode::kFrameState:
      case IrOpcode::kStateValues:
      case IrOpcode::kReferenceEqual:
      case IrOpcode::kReturn:
        // Ignore safe uses that definitely don't mess with the arguments.
        continue;
      case IrOpcode::kLoadField: {
        DCHECK_EQ(arguments_list, user->InputAt(0));
        FieldAccess const& access = FieldAccessOf(user->op());
        if (access.offset == JSArray::kLengthOffset) {
          // Ignore uses for arguments#length.
          static_assert(
              static_cast<int>(JSArray::kLengthOffset) ==
              static_cast<int>(JSStrictArgumentsObject::kLengthOffset));
          static_assert(
              static_cast<int>(JSArray::kLengthOffset) ==
              static_cast<int>(JSSloppyArgumentsObject::kLengthOffset));
          continue;
        } else if (access.offset == JSObject::kElementsOffset) {
          // Ignore safe uses for arguments#elements.
          if (IsSafeArgumentsElements(user)) continue;
        }
        break;
      }
      case IrOpcode::kJSCallWithArrayLike: {
        // Ignore uses as argumentsList input to calls with array like.
        JSCallWithArrayLikeNode n(user);
        if (edge.index() == n.ArgumentIndex(0)) continue;
        break;
      }
      case IrOpcode::kJSConstructWithArrayLike: {
        // Ignore uses as argumentsList input to calls with array like.
        JSConstructWithArrayLikeNode n(user);
        if (edge.index() == n.ArgumentIndex(0)) continue;
        break;
      }
      case IrOpcode::kJSCallWithSpread: {
        // Ignore uses as spread input to calls with spread.
        JSCallWithSpreadNode n(user);
        if (edge.index() == n.LastArgumentIndex()) continue;
        break;
      }
      case IrOpcode::kJSConstructWithSpread: {
        // Ignore uses as spread input to construct with spread.
        JSConstructWithSpreadNode n(user);
        if (edge.index() == n.LastArgumentIndex()) continue;
        break;
      }
      default:
        break;
    }
    // We cannot currently reduce the {node} to something better than what
    // it already is, but we might be able to do something about the {node}
    // later, so put it on the waitlist and try again during finalization.
    waitlist_.insert(node);
    return NoChange();
  }

  // Get to the actual frame state from which to extract the arguments;
  // we can only optimize this in case the {node} was already inlined into
  // some other function (and same for the {arguments_list}).
  CreateArgumentsType const type = CreateArgumentsTypeOf(arguments_list->op());
  FrameState frame_state =
      FrameState{NodeProperties::GetFrameStateInput(arguments_list)};

  int formal_parameter_count;
  {
    Handle<SharedFunctionInfo> shared;
    if (!frame_state.frame_state_info().shared_info().ToHandle(&shared)) {
      return NoChange();
    }
    formal_parameter_count =
        MakeRef(broker(), shared)
            .internal_formal_parameter_count_without_receiver();
  }

  if (type == CreateArgumentsType::kMappedArguments) {
    // Mapped arguments (sloppy mode) that are aliased can only be handled
    // here if there's no side-effect between the {node} and the {arg_array}.
    // TODO(turbofan): Further relax this constraint.
    if (formal_parameter_count != 0) {
      Node* effect = NodeProperties::GetEffectInput(node);
      if (!NodeProperties::NoObservableSideEffectBetween(effect,
                                                         arguments_list)) {
        return NoChange();
      }
    }
  }

  // For call/construct with spread, we need to also install a code
  // dependency on the array iterator lookup protector cell to ensure
  // that no one messed with the %ArrayIteratorPrototype%.next method.
  if (IsCallOrConstructWithSpread(node)) {
    if (!dependencies()->DependOnArrayIteratorProtector()) return NoChange();
  }

  // Remove the {arguments_list} input from the {node}.
  node->RemoveInput(arraylike_or_spread_index);

  // The index of the first relevant parameter. Only non-zero when looking at
  // rest parameters, in which case it is set to the index of the first rest
  // parameter.
  const int start_index = (type == CreateArgumentsType::kRestParameter)
                              ? formal_parameter_count
                              : 0;

  // After removing the arraylike or spread object, the argument count is:
  int argc =
      arraylike_or_spread_index - JSCallOrConstructNode::FirstArgumentIndex();
  // Check if are spreading to inlined arguments or to the arguments of
  // the outermost function.
  if (frame_state.outer_frame_state()->opcode() != IrOpcode::kFrameState) {
    Operator const* op;
    if (IsCallWithArrayLikeOrSpread(node)) {
      static constexpr int kTargetAndReceiver = 2;
      op = javascript()->CallForwardVarargs(argc + kTargetAndReceiver,
                                            start_index);
    } else {
      static constexpr int kTargetAndNewTarget = 2;
      op = javascript()->ConstructForwardVarargs(argc + kTargetAndNewTarget,
                                                 start_index);
    }
    node->RemoveInput(JSCallOrConstructNode::FeedbackVectorIndexForArgc(argc));
    NodeProperties::ChangeOp(node, op);
    return Changed(node);
  }
  // Get to the actual frame state from which to extract the arguments;
  // we can only optimize this in case the {node} was already inlined into
  // some other function (and same for the {arg_array}).
  FrameState outer_state{frame_state.outer_frame_state()};
  FrameStateInfo outer_info = outer_state.frame_state_info();
  if (outer_info.type() == FrameStateType::kInlinedExtraArguments) {
    // Need to take the parameters from the inlined extra arguments frame state.
    frame_state = outer_state;
  }
  // Add the actual parameters to the {node}, skipping the receiver.
  StateValuesAccess parameters_access(frame_state.parameters());
  for (auto it = parameters_access.begin_without_receiver_and_skip(start_index);
       !it.done(); ++it) {
    DCHECK_NOT_NULL(it.node());
    node->InsertInput(graph()->zone(),
                      JSCallOrConstructNode::ArgumentIndex(argc++), it.node());
  }

  if (IsCallWithArrayLikeOrSpread(node)) {
    NodeProperties::ChangeOp(
        node, javascript()->Call(JSCallNode::ArityForArgc(argc), frequency,
                                 feedback, ConvertReceiverMode::kAny,
                                 speculation_mode, feedback_relation));
    return Changed(node).FollowedBy(ReduceJSCall(node));
  } else {
    NodeProperties::ChangeOp(
        node, javascript()->Construct(JSConstructNode::ArityForArgc(argc),
                                      frequency, feedback));

    // Check whether the given new target value is a constructor function. The
    // replacement {JSConstruct} operator only checks the passed target value
    // but relies on the new target value to be implicitly valid.
    CheckIfConstructor(node);
    return Changed(node).FollowedBy(ReduceJSConstruct(node));
  }
}

Reduction JSCallReducer::ReduceCallOrConstructWithArrayLikeOrSpread(
    Node* node, int argument_count, int arraylike_or_spread_index,
    CallFrequency const& frequency, FeedbackSource const& feedback_source,
    SpeculationMode speculation_mode, CallFeedbackRelation feedback_relation,
    Node* target, Effect effect, Control control) {
  DCHECK(IsCallOrConstructWithArrayLike(node) ||
         IsCallOrConstructWithSpread(node));
  DCHECK_IMPLIES(speculation_mode == SpeculationMode::kAllowSpeculation,
                 feedback_source.IsValid());

  Node* arguments_list =
      NodeProperties::GetValueInput(node, arraylike_or_spread_index);

  if (arguments_list->opcode() == IrOpcode::kJSCreateArguments) {
    return ReduceCallOrConstructWithArrayLikeOrSpreadOfCreateArguments(
        node, arguments_list, arraylike_or_spread_index, frequency,
        feedback_source, speculation_mode, feedback_relation);
  }

  if (!v8_flags.turbo_optimize_apply) return NoChange();

  // Optimization of construct nodes not supported yet.
  if (!IsCallWithArrayLikeOrSpread(node)) return NoChange();

  // Avoid deoptimization loops.
  if (speculation_mode != SpeculationMode::kAllowSpeculation) return NoChange();

  // Only optimize with array literals.
  if (arguments_list->opcode() != IrOpcode::kJSCreateLiteralArray &&
      arguments_list->opcode() != IrOpcode::kJSCreateEmptyLiteralArray) {
    return NoChange();
  }

  // For call/construct with spread, we need to also install a code
  // dependency on the array iterator lookup protector cell to ensure
  // that no one messed with the %ArrayIteratorPrototype%.next method.
  if (IsCallOrConstructWithSpread(node)) {
    if (!dependencies()->DependOnArrayIteratorProtector()) return NoChange();
  }

  if (arguments_list->opcode() == IrOpcode::kJSCreateEmptyLiteralArray) {
    if (generated_calls_with_array_like_or_spread_.count(node)) {
      return NoChange();  // Avoid infinite recursion.
    }
    JSCallReducerAssembler a(this, node);
    Node* subgraph = a.ReduceJSCallWithArrayLikeOrSpreadOfEmpty(
        &generated_calls_with_array_like_or_spread_);
    return ReplaceWithSubgraph(&a, subgraph);
  }

  DCHECK_EQ(arguments_list->opcode(), IrOpcode::kJSCreateLiteralArray);
  int new_argument_count;

  // Find array length and elements' kind from the feedback's allocation
  // site's boilerplate JSArray.
  JSCreateLiteralOpNode args_node(arguments_list);
  CreateLiteralParameters const& args_params = args_node.Parameters();
  const FeedbackSource& array_feedback = args_params.feedback();
  const ProcessedFeedback& feedback =
      broker()->GetFeedbackForArrayOrObjectLiteral(array_feedback);
  if (feedback.IsInsufficient()) return NoChange();

  AllocationSiteRef site = feedback.AsLiteral().value();
  if (!site.boilerplate(broker()).has_value()) return NoChange();

  JSArrayRef boilerplate_array = site.boilerplate(broker())->AsJSArray();
  int const array_length =
      boilerplate_array.GetBoilerplateLength(broker()).AsSmi();

  // We'll replace the arguments_list input with {array_length} element loads.
  new_argument_count = argument_count - 1 + array_length;

  // Do not optimize calls with a large number of arguments.
  // Arbitrarily sets the limit to 32 arguments.
  const int kMaxArityForOptimizedFunctionApply = 32;
  if (new_argument_count > kMaxArityForOptimizedFunctionApply) {
    return NoChange();
  }

  // Determine the array's map.
  MapRef array_map = boilerplate_array.map(broker());
  if (!array_map.supports_fast_array_iteration(broker())) {
    return NoChange();
  }

  // Check and depend on NoElementsProtector.
  if (!dependencies()->DependOnNoElementsProtector()) {
    return NoChange();
  }

  // Remove the {arguments_list} node which will be replaced by a sequence of
  // LoadElement nodes.
  node->RemoveInput(arraylike_or_spread_index);

  // Speculate on that array's map is still equal to the dynamic map of
  // arguments_list; generate a map check.
  effect = graph()->NewNode(
      simplified()->CheckMaps(CheckMapsFlag::kNone, ZoneRefSet<Map>(array_map),
                              feedback_source),
      arguments_list, effect, control);

  // Speculate on that array's length being equal to the dynamic length of
  // arguments_list; generate a deopt check.
  ElementsKind elements_kind = array_map.elements_kind();
  effect = CheckArrayLength(arguments_list, elements_kind, array_length,
                            feedback_source, effect, control);

  // Generate N element loads to replace the {arguments_list} node with a set
  // of arguments loaded from it.
  Node* elements = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForJSObjectElements()),
      arguments_list, effect, control);
  for (int i = 0; i < array_length; i++) {
    // Load the i-th element from the array.
    Node* index = jsgraph()->ConstantNoHole(i);
    Node* load = effect = graph()->NewNode(
        simplified()->LoadElement(
            AccessBuilder::ForFixedArrayElement(elements_kind)),
        elements, index, effect, control);

    // In "holey" arrays some arguments might be missing and we pass
    // 'undefined' instead.
    if (IsHoleyElementsKind(elements_kind)) {
      load = ConvertHoleToUndefined(load, elements_kind);
    }

    node->InsertInput(graph()->zone(), arraylike_or_spread_index + i, load);
  }

  NodeProperties::ChangeOp(
      node,
      javascript()->Call(JSCallNode::ArityForArgc(new_argument_count),
                         frequency, feedback_source, ConvertReceiverMode::kAny,
                         speculation_mode, CallFeedbackRelation::kUnrelated));
  NodeProperties::ReplaceEffectInput(node, effect);
  return Changed(node).FollowedBy(ReduceJSCall(node));
}

bool JSCallReducer::IsBuiltinOrApiFunction(JSFunctionRef function) const {
  // TODO(neis): Add a way to check if function template info isn't serialized
  // and add a warning in such cases. Currently we can't tell if function
  // template info doesn't exist or wasn't serialized.
  return function.shared(broker()).HasBuiltinId() ||
         function.shared(broker()).function_template_info(broker()).has_value();
}

Reduction JSCallReducer::ReduceJSCall(Node* node) {
  if (broker()->StackHasOverflowed()) return NoChange();

  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  Node* target = n.target();
  Effect effect = n.effect();
  Control control = n.control();
  int arity = p.arity_without_implicit_args();

  // Try to specialize JSCall {node}s with constant {target}s.
  HeapObjectMatcher m(target);
  if (m.HasResolvedValue()) {
    ObjectRef target_ref = m.Ref(broker());
    if (target_ref.IsJSFunction()) {
      JSFunctionRef function = target_ref.AsJSFunction();

      // Don't inline cross native context.
      if (!function.native_context(broker()).equals(native_context())) {
        return NoChange();
      }

      return ReduceJSCall(node, function.shared(broker()));
    } else if (target_ref.IsJSBoundFunction()) {
      JSBoundFunctionRef function = target_ref.AsJSBoundFunction();
      ObjectRef bound_this = function.bound_this(broker());
      ConvertReceiverMode const convert_mode =
          bound_this.IsNullOrUndefined()
              ? ConvertReceiverMode::kNullOrUndefined
              : ConvertReceiverMode::kNotNullOrUndefined;

      // TODO(jgruber): Inline this block below once TryGet is guaranteed to
      // succeed.
      FixedArrayRef bound_arguments = function.bound_arguments(broker());
      const uint32_t bound_arguments_length = bound_arguments.length();
      static constexpr int kInlineSize = 16;  // Arbitrary.
      base::SmallVector<Node*, kInlineSize> args;
      for (uint32_t i = 0; i < bound_arguments_length; ++i) {
        OptionalObjectRef maybe_arg = bound_arguments.TryGet(broker(), i);
        if (!maybe_arg.has_value()) {
          TRACE_BROKER_MISSING(broker(), "bound argument");
          return NoChange();
        }
        args.emplace_back(
            jsgraph()->ConstantNoHole(maybe_arg.value(), broker()));
      }

      // Patch {node} to use [[BoundTargetFunction]] and [[BoundThis]].
      NodeProperties::ReplaceValueInput(
          node,
          jsgraph()->ConstantNoHole(function.bound_target_function(broker()),
                                    broker()),
          JSCallNode::TargetIndex());
      NodeProperties::ReplaceValueInput(
          node, jsgraph()->ConstantNoHole(bound_this, broker()),
          JSCallNode::ReceiverIndex());

      // Insert the [[BoundArguments]] for {node}.
      for (uint32_t i = 0; i < bound_arguments_length; ++i) {
        node->InsertInput(graph()->zone(), i + 2, args[i]);
        arity++;
      }

      NodeProperties::ChangeOp(
          node,
          javascript()->Call(JSCallNode::ArityForArgc(arity), p.frequency(),
                             p.feedback(), convert_mode, p.speculation_mode(),
                             CallFeedbackRelation::kUnrelated));

      // Try to further reduce the JSCall {node}.
      return Changed(node).FollowedBy(ReduceJSCall(node));
    }

    // Don't mess with other {node}s that have a constant {target}.
    // TODO(bmeurer): Also support proxies here.
    return NoChange();
  }

  // If {target} is the result of a JSCreateClosure operation, we can
  // just immediately try to inline based on the SharedFunctionInfo,
  // since TurboFan generally doesn't inline cross-context, and hence
  // the {target} must have the same native context as the call site.
  // Same if the {target} is the result of a CheckClosure operation.
  if (target->opcode() == IrOpcode::kJSCreateClosure) {
    CreateClosureParameters const& params =
        JSCreateClosureNode{target}.Parameters();
    return ReduceJSCall(node, params.shared_info());
  } else if (target->opcode() == IrOpcode::kCheckClosure) {
    FeedbackCellRef cell = MakeRef(broker(), FeedbackCellOf(target->op()));
    OptionalSharedFunctionInfoRef shared = cell.shared_function_info(broker());
    if (!shared.has_value()) {
      TRACE_BROKER_MISSING(broker(), "Unable to reduce JSCall. FeedbackCell "
                                         << cell << " has no FeedbackVector");
      return NoChange();
    }
    return ReduceJSCall(node, *shared);
  }

  // If {target} is the result of a JSCreateBoundFunction operation,
  // we can just fold the construction and call the bound target
  // function directly instead.
  if (target->opcode() == IrOpcode::kJSCreateBoundFunction) {
    Node* bound_target_function = NodeProperties::GetValueInput(target, 0);
    Node* bound_this = NodeProperties::GetValueInput(target, 1);
    uint32_t const bound_arguments_length =
        static_cast<int>(CreateBoundFunctionParametersOf(target->op()).arity());

    // Patch the {node} to use [[BoundTargetFunction]] and [[BoundThis]].
    NodeProperties::ReplaceValueInput(node, bound_target_function,
                                      n.TargetIndex());
    NodeProperties::ReplaceValueInput(node, bound_this, n.ReceiverIndex());

    // Insert the [[BoundArguments]] for {node}.
    for (uint32_t i = 0; i < bound_arguments_length; ++i) {
      Node* value = NodeProperties::GetValueInput(target, 2 + i);
      node->InsertInput(graph()->zone(), n.ArgumentIndex(i), value);
      arity++;
    }

    // Update the JSCall operator on {node}.
    ConvertReceiverMode const convert_mode =
        NodeProperties::CanBeNullOrUndefined(broker(), bound_this, effect)
            ? ConvertReceiverMode::kAny
            : ConvertReceiverMode::kNotNullOrUndefined;
    NodeProperties::ChangeOp(
        node,
        javascript()->Call(JSCallNode::ArityForArgc(arity), p.frequency(),
                           p.feedback(), convert_mode, p.speculation_mode(),
                           CallFeedbackRelation::kUnrelated));

    // Try to further reduce the JSCall {node}.
    return Changed(node).FollowedBy(ReduceJSCall(node));
  }

  if (!ShouldUseCallICFeedback(target) ||
      p.feedback_relation() == CallFeedbackRelation::kUnrelated ||
      !p.feedback().IsValid()) {
    return NoChange();
  }

  ProcessedFeedback const& feedback =
      broker()->GetFeedbackForCall(p.feedback());
  if (feedback.IsInsufficient()) {
    return ReduceForInsufficientFeedback(
        node, DeoptimizeReason::kInsufficientTypeFeedbackForCall);
  }

  OptionalHeapObjectRef feedback_target;
  if (p.feedback_relation() == CallFeedbackRelation::kTarget) {
    feedback_target = feedback.AsCall().target();
  } else {
    DCHECK_EQ(p.feedback_relation(), CallFeedbackRelation::kReceiver);
    feedback_target = native_context().function_prototype_apply(broker());
  }

  if (feedback_target.has_value() &&
      feedback_target->map(broker()).is_callable()) {
    Node* target_function =
        jsgraph()->ConstantNoHole(*feedback_target, broker());

    // Check that the {target} is still the {target_function}.
    Node* check = graph()->NewNode(simplified()->ReferenceEqual(), target,
                                   target_function);
    effect = graph()->NewNode(
        simplified()->CheckIf(DeoptimizeReason::kWrongCallTarget), check,
        effect, control);

    // Specialize the JSCall node to the {target_function}.
    NodeProperties::ReplaceValueInput(node, target_function, n.TargetIndex());
    NodeProperties::ReplaceEffectInput(node, effect);

    // Try to further reduce the JSCall {node}.
    return Changed(node).FollowedBy(ReduceJSCall(node));
  } else if (feedback_target.has_value() && feedback_target->IsFeedbackCell()) {
    FeedbackCellRef feedback_cell = feedback_target.value().AsFeedbackCell();
    // TODO(neis): This check seems unnecessary.
    if (feedback_cell.feedback_vector(broker()).has_value()) {
      // Check that {target} is a closure with given {feedback_cell},
      // which uniquely identifies a given function inside a native context.
      Node* target_closure = effect =
          graph()->NewNode(simplified()->CheckClosure(feedback_cell.object()),
                           target, effect, control);

      // Specialize the JSCall node to the {target_closure}.
      NodeProperties::ReplaceValueInput(node, target_closure, n.TargetIndex());
      NodeProperties::ReplaceEffectInput(node, effect);

      // Try to further reduce the JSCall {node}.
      return Changed(node).FollowedBy(ReduceJSCall(node));
    }
  }
  return NoChange();
}

Reduction JSCallReducer::ReduceJSCall(Node* node,
                                      SharedFunctionInfoRef shared) {
  JSCallNode n(node);
  Node* target = n.target();

  // Do not reduce calls to functions with break points.
  // If this state changes during background compilation, the compilation
  // job will be aborted from the main thread (see
  // Debug::PrepareFunctionForDebugExecution()).
  if (shared.HasBreakInfo(broker())) return NoChange();

  // Class constructors are callable, but [[Call]] will raise an exception.
  // See ES6 section 9.2.1 [[Call]] ( thisArgument, argumentsList ).
  if (IsClassConstructor(shared.kind())) {
    NodeProperties::ReplaceValueInputs(node, target);
    NodeProperties::ChangeOp(
        node, javascript()->CallRuntime(
                  Runtime::kThrowConstructorNonCallableError, 1));
    return Changed(node);
  }
```