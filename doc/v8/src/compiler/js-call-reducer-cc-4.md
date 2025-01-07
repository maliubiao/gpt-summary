Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/js-call-reducer.cc`. I need to analyze the code and identify its main responsibilities. The prompt also includes specific instructions related to Torque files, JavaScript examples, logic reasoning, common programming errors, and position in a larger set of files.

Here's a breakdown of how to approach this:

1. **High-Level Purpose:** The filename `js-call-reducer.cc` suggests this code is part of the V8 compiler and is responsible for *reducing* JavaScript call nodes. This means it's looking for opportunities to replace high-level JavaScript calls with more efficient lower-level operations.

2. **Individual Function Analysis:** I need to examine each function within the snippet and understand what specific JavaScript call it's trying to optimize. Keywords like `ReduceObjectPrototypeIsPrototypeOf`, `ReduceReflectApply`, `ReduceArrayForEach`, etc., are strong hints.

3. **Reduction Logic:**  For each function, I need to identify the pattern of transformation. What is being replaced with what?  Are there checks being performed before the replacement? This will involve understanding the V8 node types and operators being used (e.g., `javascript()->HasInPrototypeChain()`, `simplified()->ObjectIsReceiver()`, `common()->Call()`).

4. **Torque Check:** The prompt asks about `.tq` files. This snippet is `.cc`, so that part of the condition is false. I should explicitly mention this.

5. **JavaScript Relevance & Examples:** For functions that clearly relate to JavaScript features, I need to provide corresponding JavaScript examples. This will illustrate the high-level behavior being optimized.

6. **Logic Reasoning, Input/Output:**  Where the code makes decisions based on input (like checking the type of an argument), I can provide hypothetical input and explain the resulting output after the reduction.

7. **Common Programming Errors:** If a reduction targets a specific kind of error (like calling a method on a non-object), I should provide a JavaScript example of that error.

8. **Summarization:** Finally, I need to synthesize the information from the individual function analyses into a concise summary of the overall functionality.

**Pre-computation/Pre-analysis:**

* **V8 Concepts:**  I need a basic understanding of V8's compilation pipeline, especially the role of the Turbofan compiler and its intermediate representation (nodes).
* **JavaScript Semantics:**  Familiarity with the semantics of the JavaScript methods being reduced (e.g., `Object.prototype.isPrototypeOf`, `Reflect.apply`, array methods) is crucial.
* **V8 Internal Functions/Operators:** I need to recognize some common V8 internal functions and operators (like `javascript()->CallRuntime`, `simplified()->ConvertReceiver`).

**Mental Walkthrough of Key Functions:**

* **`ReduceKeyedLoadGeneric`:**  Seems to handle property access using a potentially non-string key. The code checks if the key is the same as the receiver's key.
* **`ReduceObjectPrototypeIsPrototypeOf`:**  Simplifies calls to `Object.prototype.isPrototypeOf` by directly using the `HasInPrototypeChain` operator when the receiver is known to be a `JSReceiver`.
* **`ReduceReflectApply` and `ReduceReflectConstruct`:** These functions handle `Reflect.apply` and `Reflect.construct` by rearranging arguments and using specific `CallWithArrayLike` and `ConstructWithArrayLike` operators.
* **`ReduceReflectGet` and `ReduceReflectHas`:**  These optimize `Reflect.get` and `Reflect.has` by performing a check for `JSReceiver` and then using existing V8 mechanisms for property access and checking. They also handle potential `TypeError` exceptions.
* **Array Builtin Reductions (`ReduceArrayForEach`, `ReduceArrayReduce`, etc.):** These functions attempt to inline the execution of common array methods when the receiver is a known fast array type. They use the `IteratingArrayBuiltinHelper` to check if inlining is possible.
* **`ReduceCallWasmFunction`:**  Deals with optimizing calls to WebAssembly functions.
* **`ReduceCallApiFunction`:**  Handles calls to native JavaScript API functions, potentially optimizing them by resolving the target function and handling receiver checks.

By going through each function in this way, I can build up a detailed understanding of the code's purpose and then synthesize the final answer. I need to be careful to address all parts of the user's prompt.
`v8/src/compiler/js-call-reducer.cc` 是 V8 编译器的源代码文件，它的主要功能是**优化 (reduce)** JavaScript 函数调用。这个过程发生在编译的早期阶段，旨在将高层次的 JavaScript 调用转换为更低层次、更高效的内部操作，从而提高代码的执行效率。

以下是该文件更详细的功能分解：

**主要功能：JavaScript 函数调用优化**

该文件中的代码实现了各种针对特定 JavaScript 函数调用的优化策略。它会检查当前正在编译的函数调用节点（`Node* node`），并尝试识别可以被更高效操作替代的模式。如果找到可优化的模式，`JSCallReducer` 会修改抽象语法树 (AST) 或中间表示 (IR) 图，用优化的节点替换原始的函数调用节点。

**具体优化示例 (根据代码片段)：**

* **`ReduceKeyedLoadGeneric(Node* node)`:**
    * **功能:** 优化使用非字符串键访问对象属性的情况。
    * **逻辑推理:**  它检查正在访问的键是否与接收者对象自身的键相同（通过 `broker()->GetKeyName`）。如果是，则可以跳过一些查找步骤。
    * **假设输入与输出:**
        * **假设输入:**  一个 JavaScript 对象 `obj` 和一个索引 `key_index`，其中 `obj` 的某个属性的键与 `key_index` 指向的键相同。
        * **输出:**  原始的属性访问节点被替换为直接访问对象内部属性的节点，可能避免了原型链查找。
    * **JavaScript 举例:**
        ```javascript
        const obj = { a: 1 };
        const keyIndex = 'a';
        console.log(obj[keyIndex]); // 这里的访问可能会被优化
        ```

* **`ReduceObjectPrototypeIsPrototypeOf(Node* node)`:**
    * **功能:** 优化 `Object.prototype.isPrototypeOf` 方法的调用。
    * **逻辑推理:**  如果接收者已知是一个 `JSReceiver` (非原始值)，则可以将 `Object.prototype.isPrototypeOf` 调用替换为更底层的 `javascript()->HasInPrototypeChain()` 操作，直接检查原型链。
    * **JavaScript 举例:**
        ```javascript
        const proto = {};
        const obj = Object.create(proto);
        console.log(proto.isPrototypeOf(obj)); // 这里的调用会被优化
        ```

* **`ReduceReflectApply(Node* node)`:**
    * **功能:** 优化 `Reflect.apply` 的调用。
    * **逻辑推理:**  它会将 `Reflect.apply` 调用转换为 `javascript()->CallWithArrayLike` 操作，并调整参数的顺序和数量以匹配该操作的要求。
    * **JavaScript 举例:**
        ```javascript
        function sum(a, b) { return a + b; }
        console.log(Reflect.apply(sum, null, [1, 2])); // 这里的调用会被优化
        ```

* **`ReduceReflectConstruct(Node* node)`:**
    * **功能:** 优化 `Reflect.construct` 的调用。
    * **逻辑推理:** 类似 `ReduceReflectApply`，它将 `Reflect.construct` 转换为 `javascript()->ConstructWithArrayLike`，并调整参数。
    * **JavaScript 举例:**
        ```javascript
        class MyClass {
          constructor(value) { this.value = value; }
        }
        const instance = Reflect.construct(MyClass, [5]); // 这里的调用会被优化
        console.log(instance.value);
        ```

* **`ReduceReflectGetPrototypeOf(Node* node)`:**
    * **功能:** 优化 `Reflect.getPrototypeOf` 的调用。
    * **逻辑推理:**  直接调用 `ReduceObjectGetPrototype` 来处理。

* **`ReduceObjectCreate(Node* node)`:**
    * **功能:** 优化 `Object.create` 的调用。
    * **逻辑推理:** 当 `Object.create` 只传入原型参数时 (第二个参数为 `undefined`)，可以替换为更直接的 `javascript()->CreateObject()` 操作。
    * **JavaScript 举例:**
        ```javascript
        const proto = {};
        const obj = Object.create(proto); // 这里的调用会被优化
        ```

* **`ReduceReflectGet(Node* node)`:**
    * **功能:** 优化 `Reflect.get` 的调用。
    * **逻辑推理:** 它会检查目标对象是否为 `JSReceiver`，如果不是，则抛出 `TypeError`。如果是，则使用底层的属性获取机制 (`Builtins::kGetProperty`)。
    * **用户常见的编程错误:** 在非对象上调用 `Reflect.get`。
    * **JavaScript 举例 (错误):**
        ```javascript
        Reflect.get(null, 'prop'); //  会导致 TypeError
        ```

* **`ReduceReflectHas(Node* node)`:**
    * **功能:** 优化 `Reflect.has` 的调用。
    * **逻辑推理:** 类似 `ReduceReflectGet`，它检查目标是否为 `JSReceiver`，然后使用底层的 `javascript()->HasProperty` 操作。
    * **用户常见的编程错误:** 在非对象上调用 `Reflect.has`。
    * **JavaScript 举例 (错误):**
        ```javascript
        Reflect.has(undefined, 'prop'); // 会导致 TypeError
        ```

* **数组迭代方法的优化 (`ReduceArrayForEach`, `ReduceArrayReduce`, `ReduceArrayMap`, 等等):**
    * **功能:** 优化 `Array.prototype.forEach`, `Array.prototype.reduce`, `Array.prototype.map` 等数组迭代方法。
    * **逻辑推理:**  如果数组的类型是已知的且支持快速迭代（例如，非稀疏数组），则可以将这些高层次的方法调用替换为更底层的循环和元素访问操作，通常由汇编器代码实现（如 `IteratingArrayBuiltinReducerAssembler`）。
    * **假设输入与输出:**
        * **假设输入:**  一个已知元素类型的数组和一个回调函数。
        * **输出:**  原始的 `forEach` 等调用被替换为直接操作数组元素的循环结构。
    * **JavaScript 举例:**
        ```javascript
        const arr = [1, 2, 3];
        arr.forEach(item => console.log(item)); // 可能会被优化为更快的循环
        ```

* **`ReduceCallWasmFunction(Node* node, SharedFunctionInfoRef shared)`:**
    * **功能:** 优化 JavaScript 调用 WebAssembly 函数的情况。
    * **逻辑推理:**  当启用内联 JSToWasm 调用时，它可以将 JavaScript 调用直接转换为 WebAssembly 调用操作 (`javascript()->CallWasm`)。
    * **假设输入与输出:**
        * **假设输入:**  一个对 WebAssembly 导出函数的 JavaScript 调用。
        * **输出:**  原始的 JavaScript 调用被替换为直接调用 WebAssembly 代码的节点。
    * **JavaScript 举例:**
        ```javascript
        // 假设 'wasmModule' 是一个已加载的 WebAssembly 模块
        const add = wasmModule.exports.add;
        console.log(add(5, 3)); // 这里的调用可能会被优化为直接的 Wasm 调用
        ```

* **`ReduceCallApiFunction(Node* node, SharedFunctionInfoRef shared)`:**
    * **功能:** 优化对 C++ 实现的 JavaScript API 函数的调用。
    * **逻辑推理:**  它会尝试根据 `FunctionTemplateInfo` 中的信息，直接调用 C++ 函数，避免一些中间步骤，例如通用的调用处理逻辑。 它还处理接收者类型检查和持有者查找等问题。

**关于 .tq 结尾的文件:**

你提到如果 `v8/src/compiler/js-call-reducer.cc` 以 `.tq` 结尾，那它就是 V8 Torque 源代码。这是正确的。`.tq` 文件是 V8 中用于编写类型化的、更易于推理的低级代码的 DSL (领域特定语言)。  然而，**当前提供的文件 `v8/src/compiler/js-call-reducer.cc` 是一个 C++ 文件，而不是 Torque 文件**。Torque 文件通常用于实现一些底层的内置函数和运行时代码。

**第 5 部分，共 12 部分的功能归纳:**

由于这是第 5 部分，可以推断 `js-call-reducer.cc` 是 V8 编译器中负责函数调用优化的一系列文件之一。 这部分可能专注于特定的优化类型，例如通用的 JavaScript 方法调用优化、`Reflect` API 的优化以及一些数组方法的优化。其他部分可能处理不同类型的调用优化，例如构造函数调用、绑定函数调用、以及与内联相关的优化等。

**总结 `v8/src/compiler/js-call-reducer.cc` 的功能:**

总而言之，`v8/src/compiler/js-call-reducer.cc` 在 V8 编译过程中扮演着关键角色，它通过识别并替换低效的 JavaScript 函数调用模式来提升代码的性能。 它针对各种内置函数和 API 提供了特定的优化策略，利用 V8 内部的低级操作来加速执行。 它的工作是编译器优化流程的一部分，旨在生成更高效的机器代码。

Prompt: 
```
这是目录为v8/src/compiler/js-call-reducer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-call-reducer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共12部分，请归纳一下它的功能

"""
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
      if (function_tem
"""


```