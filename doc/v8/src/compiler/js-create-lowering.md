Response: The user wants a summary of the C++ source code file `v8/src/compiler/js-create-lowering.cc`.
The file seems to be part of the V8 JavaScript engine's compiler.
It likely deals with the lowering of JavaScript "create" operations into simpler, lower-level operations.
The numerous `ReduceJSCreate...` functions suggest this file handles the translation of various JavaScript object creation expressions.

The request also asks for JavaScript examples if a connection exists between the C++ code and JavaScript functionality.

**Plan:**

1. Identify the main purpose of the file based on its name and included headers.
2. Iterate through the `ReduceJS...` functions and determine which JavaScript creation operations they handle.
3. For each handled JavaScript operation, provide a corresponding JavaScript example.
这个C++源代码文件 `v8/src/compiler/js-create-lowering.cc` 的主要功能是 **将 JavaScript 中各种对象创建操作（例如 `new` 关键字、字面量创建等）降低（lowering）为更底层的、更接近机器指令的操作**。这是 V8 编译器优化管道中的一个重要步骤。

简单来说，编译器前端（Parser 等）会将 JavaScript 代码解析成一个抽象语法树 (AST)，然后转换成中间表示 (IR)。在这个 IR 中，会有像 `JSCreate`、`JSCreateArray` 这样的节点表示 JavaScript 的创建操作。`js-create-lowering.cc` 的作用就是将这些高级的创建操作转换成一系列更基础的内存分配、对象初始化等操作。

**与 JavaScript 的关系以及 JavaScript 例子：**

这个文件直接对应于 JavaScript 中创建各种对象的方式。下面是一些 `ReduceJS...` 函数与相应 JavaScript 功能的对应关系和例子：

*   **`ReduceJSCreate(Node* node)`:** 对应于使用 `new` 关键字调用构造函数创建对象。

    ```javascript
    function MyClass() {
      this.property = 1;
    }
    const instance = new MyClass(); // 对应 JSCreate 操作
    ```

*   **`ReduceJSCreateArguments(Node* node)`:** 对应于函数内部的 `arguments` 对象或剩余参数（rest parameters）。

    ```javascript
    function myFunction() {
      console.log(arguments); // 对应 JSCreateArguments (mapped 或 unmapped)
    }

    function anotherFunction(...rest) {
      console.log(rest);      // 对应 JSCreateArguments (rest parameter)
    }
    ```

*   **`ReduceJSCreateArray(Node* node)`:** 对应于创建数组，包括使用 `new Array()` 和数组字面量 `[]`。

    ```javascript
    const arr1 = new Array(5);   // 对应 JSCreateArray (指定长度)
    const arr2 = new Array(1, 2); // 对应 JSCreateArray (指定元素)
    const arr3 = [1, 2, 3];      // 对应 JSCreateArray 或 JSCreateLiteralArray
    ```

*   **`ReduceJSCreateArrayIterator(Node* node)`:** 对应于通过 `array[Symbol.iterator]()` 或 `for...of` 循环创建数组迭代器。

    ```javascript
    const arr = [1, 2, 3];
    const iterator = arr[Symbol.iterator](); // 对应 JSCreateArrayIterator
    for (const item of arr) { // 内部会创建迭代器
      console.log(item);
    }
    ```

*   **`ReduceJSCreateAsyncFunctionObject(Node* node)`:** 对应于创建 `async function` 返回的 Promise 包装的对象。

    ```javascript
    async function myAsyncFunction() {
      return 1;
    }
    const promise = myAsyncFunction(); // 对应 JSCreateAsyncFunctionObject
    ```

*   **`ReduceJSCreateBoundFunction(Node* node)`:** 对应于使用 `Function.prototype.bind()` 创建绑定函数。

    ```javascript
    function myFunction(a, b) {
      console.log(this, a, b);
    }
    const boundFunction = myFunction.bind({ value: 'bound' }, 1); // 对应 JSCreateBoundFunction
    boundFunction(2);
    ```

*   **`ReduceJSCreateClosure(Node* node)`:** 对应于创建函数（包括普通函数和箭头函数），形成闭包。

    ```javascript
    function outerFunction() {
      const localVar = 10;
      return function innerFunction() { // 对应 JSCreateClosure
        console.log(localVar); // innerFunction 闭包了 localVar
      };
    }
    const closure = outerFunction();
    ```

*   **`ReduceJSCreateCollectionIterator(Node* node)`:** 对应于创建 Set 或 Map 的迭代器（例如 `keys()`、`values()`、`entries()`）。

    ```javascript
    const mySet = new Set([1, 2]);
    const setIterator = mySet.values(); // 对应 JSCreateCollectionIterator

    const myMap = new Map([['a', 1], ['b', 2]]);
    const mapIterator = myMap.entries(); // 对应 JSCreateCollectionIterator
    ```

*   **`ReduceJSCreateIterResultObject(Node* node)`:** 对应于手动创建迭代器结果对象（例如在自定义迭代器中）。

    ```javascript
    function* myGenerator() {
      yield 1;
      return 2;
    }
    const gen = myGenerator();
    console.log(gen.next()); // 返回 { value: 1, done: false }，内部可能涉及 JSCreateIterResultObject
    console.log(gen.next()); // 返回 { value: 2, done: true }，内部可能涉及 JSCreateIterResultObject
    ```

*   **`ReduceJSCreateStringIterator(Node* node)`:** 对应于字符串的迭代器。

    ```javascript
    const str = "hello";
    const strIterator = str[Symbol.iterator](); // 对应 JSCreateStringIterator
    for (const char of str) {
      console.log(char);
    }
    ```

*   **`ReduceJSCreateKeyValueArray(Node* node)`:** 常见于 Map 的迭代器中，表示一个键值对组成的数组。

    ```javascript
    const myMap = new Map([['a', 1]]);
    const entry = myMap.entries().next().value; // entry 可能对应 JSCreateKeyValueArray，例如 ['a', 1]
    ```

*   **`ReduceJSCreatePromise(Node* node)`:** 对应于创建 Promise 对象。

    ```javascript
    const promise = new Promise((resolve, reject) => { // 对应 JSCreatePromise
      // ...
    });
    ```

*   **`ReduceJSCreateLiteralArrayOrObject(Node* node)`:** 对应于创建数组或对象字面量。

    ```javascript
    const arr = [1, 2]; // 对应 JSCreateLiteralArray
    const obj = { a: 1, b: 2 }; // 对应 JSCreateLiteralObject
    ```

*   **`ReduceJSCreateLiteralRegExp(Node* node)`:** 对应于创建正则表达式字面量。

    ```javascript
    const regex = /pattern/g; // 对应 JSCreateLiteralRegExp
    ```

*   **`ReduceJSGetTemplateObject(Node* node)`:** 对应于模板字面量中用于缓存模板的对象。

    ```javascript
    const name = "World";
    const greeting = `Hello, ${name}!`; // 内部会用到 JSGetTemplateObject
    ```

*   **`ReduceJSCreateEmptyLiteralArray(Node* node)`:** 对应于创建空的数组字面量 `[]`。

    ```javascript
    const emptyArray = []; // 对应 JSCreateEmptyLiteralArray
    ```

*   **`ReduceJSCreateEmptyLiteralObject(Node* node)`:** 对应于创建空的对象字面量 `{}`。

    ```javascript
    const emptyObject = {}; // 对应 JSCreateEmptyLiteralObject
    ```

*   **`ReduceJSCreateFunctionContext(Node* node)`:** 对应于创建函数执行上下文。

    ```javascript
    function myFunction() {
      // 此处会创建函数上下文，可能对应 JSCreateFunctionContext
      console.log("hello");
    }
    myFunction();
    ```

*   **`ReduceJSCreateWithContext(Node* node)`:** 对应于 `with` 语句创建的作用域上下文（不推荐使用）。

    ```javascript
    const obj = { a: 1 };
    with (obj) { // 对应 JSCreateWithContext
      console.log(a);
    }
    ```

*   **`ReduceJSCreateCatchContext(Node* node)`:** 对应于 `try...catch` 语句的 `catch` 块创建的上下文。

    ```javascript
    try {
      throw new Error("Something went wrong");
    } catch (e) { // 对应 JSCreateCatchContext
      console.error(e);
    }
    ```

*   **`ReduceJSCreateBlockContext(Node* node)`:** 对应于块级作用域（例如 `let`、`const` 声明的变量所在的块）创建的上下文。

    ```javascript
    {
      let localVar = 5; // 此处会创建块级上下文，可能对应 JSCreateBlockContext
      console.log(localVar);
    }
    ```

*   **`ReduceJSCreateGeneratorObject(Node* node)`:** 对应于创建生成器函数返回的生成器对象。

    ```javascript
    function* myGenerator() {
      yield 1;
      yield 2;
    }
    const generator = myGenerator(); // 对应 JSCreateGeneratorObject
    ```

*   **`ReduceJSCreateObject(Node* node)`:** 对应于使用 `Object.create(prototype)` 创建对象。

    ```javascript
    const proto = { x: 1 };
    const obj = Object.create(proto); // 对应 JSCreateObject
    ```

*   **`ReduceJSCreateStringWrapper(Node* node)`:**  对应于使用 `new String()` 创建字符串包装对象（虽然通常不推荐显式使用）。

    ```javascript
    const strObj = new String("hello"); // 对应 JSCreateStringWrapper
    ```

总而言之，`js-create-lowering.cc` 是 V8 编译器中负责将 JavaScript 对象创建操作转化为底层实现的模块，它在 JavaScript 代码的编译和优化过程中扮演着关键的角色。

Prompt: 
```
这是目录为v8/src/compiler/js-create-lowering.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/js-create-lowering.h"

#include <optional>

#include "src/compiler/access-builder.h"
#include "src/compiler/allocation-builder-inl.h"
#include "src/compiler/common-operator.h"
#include "src/compiler/compilation-dependencies.h"
#include "src/compiler/js-graph.h"
#include "src/compiler/js-heap-broker-inl.h"
#include "src/compiler/js-operator.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/node.h"
#include "src/compiler/simplified-operator.h"
#include "src/compiler/state-values-utils.h"
#include "src/execution/protectors.h"
#include "src/objects/arguments.h"
#include "src/objects/contexts.h"
#include "src/objects/hash-table-inl.h"
#include "src/objects/heap-number.h"
#include "src/objects/js-collection-iterator.h"
#include "src/objects/js-generator.h"
#include "src/objects/js-promise.h"
#include "src/objects/js-regexp-inl.h"
#include "src/objects/objects-inl.h"

namespace v8 {
namespace internal {
namespace compiler {

namespace {

// Retrieves the frame state holding actual argument values.
FrameState GetArgumentsFrameState(FrameState frame_state) {
  FrameState outer_state{NodeProperties::GetFrameStateInput(frame_state)};
  return outer_state.frame_state_info().type() ==
                 FrameStateType::kInlinedExtraArguments
             ? outer_state
             : frame_state;
}

// When initializing arrays, we'll unfold the loop if the number of
// elements is known to be of this type.
const int kElementLoopUnrollLimit = 16;

// Limits up to which context allocations are inlined.
const int kFunctionContextAllocationLimit = 16;
const int kBlockContextAllocationLimit = 16;

}  // namespace

Reduction JSCreateLowering::Reduce(Node* node) {
  switch (node->opcode()) {
    case IrOpcode::kJSCreate:
      return ReduceJSCreate(node);
    case IrOpcode::kJSCreateArguments:
      return ReduceJSCreateArguments(node);
    case IrOpcode::kJSCreateArray:
      return ReduceJSCreateArray(node);
    case IrOpcode::kJSCreateArrayIterator:
      return ReduceJSCreateArrayIterator(node);
    case IrOpcode::kJSCreateAsyncFunctionObject:
      return ReduceJSCreateAsyncFunctionObject(node);
    case IrOpcode::kJSCreateBoundFunction:
      return ReduceJSCreateBoundFunction(node);
    case IrOpcode::kJSCreateClosure:
      return ReduceJSCreateClosure(node);
    case IrOpcode::kJSCreateCollectionIterator:
      return ReduceJSCreateCollectionIterator(node);
    case IrOpcode::kJSCreateIterResultObject:
      return ReduceJSCreateIterResultObject(node);
    case IrOpcode::kJSCreateStringIterator:
      return ReduceJSCreateStringIterator(node);
    case IrOpcode::kJSCreateKeyValueArray:
      return ReduceJSCreateKeyValueArray(node);
    case IrOpcode::kJSCreatePromise:
      return ReduceJSCreatePromise(node);
    case IrOpcode::kJSCreateLiteralArray:
    case IrOpcode::kJSCreateLiteralObject:
      return ReduceJSCreateLiteralArrayOrObject(node);
    case IrOpcode::kJSCreateLiteralRegExp:
      return ReduceJSCreateLiteralRegExp(node);
    case IrOpcode::kJSGetTemplateObject:
      return ReduceJSGetTemplateObject(node);
    case IrOpcode::kJSCreateEmptyLiteralArray:
      return ReduceJSCreateEmptyLiteralArray(node);
    case IrOpcode::kJSCreateEmptyLiteralObject:
      return ReduceJSCreateEmptyLiteralObject(node);
    case IrOpcode::kJSCreateFunctionContext:
      return ReduceJSCreateFunctionContext(node);
    case IrOpcode::kJSCreateWithContext:
      return ReduceJSCreateWithContext(node);
    case IrOpcode::kJSCreateCatchContext:
      return ReduceJSCreateCatchContext(node);
    case IrOpcode::kJSCreateBlockContext:
      return ReduceJSCreateBlockContext(node);
    case IrOpcode::kJSCreateGeneratorObject:
      return ReduceJSCreateGeneratorObject(node);
    case IrOpcode::kJSCreateObject:
      return ReduceJSCreateObject(node);
    case IrOpcode::kJSCreateStringWrapper:
      return ReduceJSCreateStringWrapper(node);
    default:
      break;
  }
  return NoChange();
}

Reduction JSCreateLowering::ReduceJSCreate(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreate, node->opcode());
  Node* const new_target = NodeProperties::GetValueInput(node, 1);
  Node* const effect = NodeProperties::GetEffectInput(node);
  Node* const control = NodeProperties::GetControlInput(node);

  OptionalMapRef initial_map = NodeProperties::GetJSCreateMap(broker(), node);
  if (!initial_map.has_value()) return NoChange();

  JSFunctionRef original_constructor =
      HeapObjectMatcher(new_target).Ref(broker()).AsJSFunction();
  SlackTrackingPrediction slack_tracking_prediction =
      dependencies()->DependOnInitialMapInstanceSizePrediction(
          original_constructor);

  // Emit code to allocate the JSObject instance for the
  // {original_constructor}.
  AllocationBuilder a(jsgraph(), broker(), effect, control);
  a.Allocate(slack_tracking_prediction.instance_size());
  a.Store(AccessBuilder::ForMap(), *initial_map);
  a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSObjectElements(),
          jsgraph()->EmptyFixedArrayConstant());
  for (int i = 0; i < slack_tracking_prediction.inobject_property_count();
       ++i) {
    a.Store(AccessBuilder::ForJSObjectInObjectProperty(*initial_map, i),
            jsgraph()->UndefinedConstant());
  }

  RelaxControls(node);
  a.FinishAndChange(node);
  return Changed(node);
}

Reduction JSCreateLowering::ReduceJSCreateArguments(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreateArguments, node->opcode());
  CreateArgumentsType type = CreateArgumentsTypeOf(node->op());
  FrameState frame_state{NodeProperties::GetFrameStateInput(node)};
  Node* const control = graph()->start();
  FrameStateInfo state_info = frame_state.frame_state_info();
  SharedFunctionInfoRef shared =
      MakeRef(broker(), state_info.shared_info().ToHandleChecked());

  // Use the ArgumentsAccessStub for materializing both mapped and unmapped
  // arguments object, but only for non-inlined (i.e. outermost) frames.
  if (frame_state.outer_frame_state()->opcode() != IrOpcode::kFrameState) {
    switch (type) {
      case CreateArgumentsType::kMappedArguments: {
        // TODO(turbofan): Duplicate parameters are not handled yet.
        if (shared.has_duplicate_parameters()) return NoChange();
        Node* const callee = NodeProperties::GetValueInput(node, 0);
        Node* const context = NodeProperties::GetContextInput(node);
        Node* effect = NodeProperties::GetEffectInput(node);
        Node* const arguments_length =
            graph()->NewNode(simplified()->ArgumentsLength());
        // Allocate the elements backing store.
        bool has_aliased_arguments = false;
        Node* const elements = effect = TryAllocateAliasedArguments(
            effect, control, context, arguments_length, shared,
            &has_aliased_arguments);
        if (elements == nullptr) return NoChange();

        // Load the arguments object map.
        Node* const arguments_map = jsgraph()->ConstantNoHole(
            has_aliased_arguments
                ? native_context().fast_aliased_arguments_map(broker())
                : native_context().sloppy_arguments_map(broker()),
            broker());
        // Actually allocate and initialize the arguments object.
        AllocationBuilder a(jsgraph(), broker(), effect, control);
        static_assert(JSSloppyArgumentsObject::kSize == 5 * kTaggedSize);
        a.Allocate(JSSloppyArgumentsObject::kSize);
        a.Store(AccessBuilder::ForMap(), arguments_map);
        a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
                jsgraph()->EmptyFixedArrayConstant());
        a.Store(AccessBuilder::ForJSObjectElements(), elements);
        a.Store(AccessBuilder::ForArgumentsLength(), arguments_length);
        a.Store(AccessBuilder::ForArgumentsCallee(), callee);
        RelaxControls(node);
        a.FinishAndChange(node);
        return Changed(node);
      }
      case CreateArgumentsType::kUnmappedArguments: {
        Node* effect = NodeProperties::GetEffectInput(node);
        Node* const arguments_length =
            graph()->NewNode(simplified()->ArgumentsLength());
        // Allocate the elements backing store.
        Node* const elements = effect = graph()->NewNode(
            simplified()->NewArgumentsElements(
                CreateArgumentsType::kUnmappedArguments,
                shared.internal_formal_parameter_count_without_receiver()),
            arguments_length, effect);
        // Load the arguments object map.
        Node* const arguments_map = jsgraph()->ConstantNoHole(
            native_context().strict_arguments_map(broker()), broker());
        // Actually allocate and initialize the arguments object.
        AllocationBuilder a(jsgraph(), broker(), effect, control);
        static_assert(JSStrictArgumentsObject::kSize == 4 * kTaggedSize);
        a.Allocate(JSStrictArgumentsObject::kSize);
        a.Store(AccessBuilder::ForMap(), arguments_map);
        a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
                jsgraph()->EmptyFixedArrayConstant());
        a.Store(AccessBuilder::ForJSObjectElements(), elements);
        a.Store(AccessBuilder::ForArgumentsLength(), arguments_length);
        RelaxControls(node);
        a.FinishAndChange(node);
        return Changed(node);
      }
      case CreateArgumentsType::kRestParameter: {
        Node* effect = NodeProperties::GetEffectInput(node);
        Node* const arguments_length =
            graph()->NewNode(simplified()->ArgumentsLength());
        Node* const rest_length = graph()->NewNode(simplified()->RestLength(
            shared.internal_formal_parameter_count_without_receiver()));
        // Allocate the elements backing store.
        Node* const elements = effect = graph()->NewNode(
            simplified()->NewArgumentsElements(
                CreateArgumentsType::kRestParameter,
                shared.internal_formal_parameter_count_without_receiver()),
            arguments_length, effect);
        // Load the JSArray object map.
        Node* const jsarray_map = jsgraph()->ConstantNoHole(
            native_context().js_array_packed_elements_map(broker()), broker());
        // Actually allocate and initialize the jsarray.
        AllocationBuilder a(jsgraph(), broker(), effect, control);
        static_assert(JSArray::kHeaderSize == 4 * kTaggedSize);
        a.Allocate(JSArray::kHeaderSize);
        a.Store(AccessBuilder::ForMap(), jsarray_map);
        a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
                jsgraph()->EmptyFixedArrayConstant());
        a.Store(AccessBuilder::ForJSObjectElements(), elements);
        a.Store(AccessBuilder::ForJSArrayLength(PACKED_ELEMENTS), rest_length);
        RelaxControls(node);
        a.FinishAndChange(node);
        return Changed(node);
      }
    }
    UNREACHABLE();
  }
  // Use inline allocation for all mapped arguments objects within inlined
  // (i.e. non-outermost) frames, independent of the object size.
  DCHECK_EQ(frame_state.outer_frame_state()->opcode(), IrOpcode::kFrameState);
  switch (type) {
    case CreateArgumentsType::kMappedArguments: {
      Node* const callee = NodeProperties::GetValueInput(node, 0);
      Node* const context = NodeProperties::GetContextInput(node);
      Node* effect = NodeProperties::GetEffectInput(node);
      // TODO(turbofan): Duplicate parameters are not handled yet.
      if (shared.has_duplicate_parameters()) return NoChange();
      // Choose the correct frame state and frame state info depending on
      // whether there conceptually is an inlined arguments frame in the call
      // chain.
      FrameState args_state = GetArgumentsFrameState(frame_state);
      if (args_state.parameters()->opcode() == IrOpcode::kDeadValue) {
        // This protects against an incompletely propagated DeadValue node.
        // If the FrameState has a DeadValue input, then this node will be
        // pruned anyway.
        return NoChange();
      }
      FrameStateInfo args_state_info = args_state.frame_state_info();
      int length = args_state_info.parameter_count() - 1;  // Minus receiver.
      // Prepare element backing store to be used by arguments object.
      bool has_aliased_arguments = false;
      Node* const elements = TryAllocateAliasedArguments(
          effect, control, args_state, context, shared, &has_aliased_arguments);
      if (elements == nullptr) return NoChange();
      effect = elements->op()->EffectOutputCount() > 0 ? elements : effect;
      // Load the arguments object map.
      Node* const arguments_map = jsgraph()->ConstantNoHole(
          has_aliased_arguments
              ? native_context().fast_aliased_arguments_map(broker())
              : native_context().sloppy_arguments_map(broker()),
          broker());
      // Actually allocate and initialize the arguments object.
      AllocationBuilder a(jsgraph(), broker(), effect, control);
      static_assert(JSSloppyArgumentsObject::kSize == 5 * kTaggedSize);
      a.Allocate(JSSloppyArgumentsObject::kSize);
      a.Store(AccessBuilder::ForMap(), arguments_map);
      a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
              jsgraph()->EmptyFixedArrayConstant());
      a.Store(AccessBuilder::ForJSObjectElements(), elements);
      a.Store(AccessBuilder::ForArgumentsLength(),
              jsgraph()->ConstantNoHole(length));
      a.Store(AccessBuilder::ForArgumentsCallee(), callee);
      RelaxControls(node);
      a.FinishAndChange(node);
      return Changed(node);
    }
    case CreateArgumentsType::kUnmappedArguments: {
      // Use inline allocation for all unmapped arguments objects within inlined
      // (i.e. non-outermost) frames, independent of the object size.
      Node* effect = NodeProperties::GetEffectInput(node);
      // Choose the correct frame state and frame state info depending on
      // whether there conceptually is an inlined arguments frame in the call
      // chain.
      FrameState args_state = GetArgumentsFrameState(frame_state);
      if (args_state.parameters()->opcode() == IrOpcode::kDeadValue) {
        // This protects against an incompletely propagated DeadValue node.
        // If the FrameState has a DeadValue input, then this node will be
        // pruned anyway.
        return NoChange();
      }
      FrameStateInfo args_state_info = args_state.frame_state_info();
      int length = args_state_info.parameter_count() - 1;  // Minus receiver.
      // Prepare element backing store to be used by arguments object.
      Node* const elements = TryAllocateArguments(effect, control, args_state);
      if (elements == nullptr) return NoChange();
      effect = elements->op()->EffectOutputCount() > 0 ? elements : effect;
      // Load the arguments object map.
      Node* const arguments_map = jsgraph()->ConstantNoHole(
          native_context().strict_arguments_map(broker()), broker());
      // Actually allocate and initialize the arguments object.
      AllocationBuilder a(jsgraph(), broker(), effect, control);
      static_assert(JSStrictArgumentsObject::kSize == 4 * kTaggedSize);
      a.Allocate(JSStrictArgumentsObject::kSize);
      a.Store(AccessBuilder::ForMap(), arguments_map);
      a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
              jsgraph()->EmptyFixedArrayConstant());
      a.Store(AccessBuilder::ForJSObjectElements(), elements);
      a.Store(AccessBuilder::ForArgumentsLength(),
              jsgraph()->ConstantNoHole(length));
      RelaxControls(node);
      a.FinishAndChange(node);
      return Changed(node);
    }
    case CreateArgumentsType::kRestParameter: {
      int start_index =
          shared.internal_formal_parameter_count_without_receiver();
      // Use inline allocation for all unmapped arguments objects within inlined
      // (i.e. non-outermost) frames, independent of the object size.
      Node* effect = NodeProperties::GetEffectInput(node);
      // Choose the correct frame state and frame state info depending on
      // whether there conceptually is an inlined arguments frame in the call
      // chain.
      FrameState args_state = GetArgumentsFrameState(frame_state);
      if (args_state.parameters()->opcode() == IrOpcode::kDeadValue) {
        // This protects against an incompletely propagated DeadValue node.
        // If the FrameState has a DeadValue input, then this node will be
        // pruned anyway.
        return NoChange();
      }
      FrameStateInfo args_state_info = args_state.frame_state_info();
      // Prepare element backing store to be used by the rest array.
      Node* const elements =
          TryAllocateRestArguments(effect, control, args_state, start_index);
      if (elements == nullptr) return NoChange();
      effect = elements->op()->EffectOutputCount() > 0 ? elements : effect;
      // Load the JSArray object map.
      Node* const jsarray_map = jsgraph()->ConstantNoHole(
          native_context().js_array_packed_elements_map(broker()), broker());
      // Actually allocate and initialize the jsarray.
      AllocationBuilder a(jsgraph(), broker(), effect, control);

      // -1 to minus receiver
      int argument_count = args_state_info.parameter_count() - 1;
      int length = std::max(0, argument_count - start_index);
      static_assert(JSArray::kHeaderSize == 4 * kTaggedSize);
      a.Allocate(ALIGN_TO_ALLOCATION_ALIGNMENT(JSArray::kHeaderSize));
      a.Store(AccessBuilder::ForMap(), jsarray_map);
      a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
              jsgraph()->EmptyFixedArrayConstant());
      a.Store(AccessBuilder::ForJSObjectElements(), elements);
      a.Store(AccessBuilder::ForJSArrayLength(PACKED_ELEMENTS),
              jsgraph()->ConstantNoHole(length));
      RelaxControls(node);
      a.FinishAndChange(node);
      return Changed(node);
    }
  }
  UNREACHABLE();
}

Reduction JSCreateLowering::ReduceJSCreateGeneratorObject(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreateGeneratorObject, node->opcode());
  Node* const closure = NodeProperties::GetValueInput(node, 0);
  Node* const receiver = NodeProperties::GetValueInput(node, 1);
  Node* const context = NodeProperties::GetContextInput(node);
  Type const closure_type = NodeProperties::GetType(closure);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* const control = NodeProperties::GetControlInput(node);
  if (closure_type.IsHeapConstant()) {
    DCHECK(closure_type.AsHeapConstant()->Ref().IsJSFunction());
    JSFunctionRef js_function =
        closure_type.AsHeapConstant()->Ref().AsJSFunction();
    if (!js_function.has_initial_map(broker())) return NoChange();

    SlackTrackingPrediction slack_tracking_prediction =
        dependencies()->DependOnInitialMapInstanceSizePrediction(js_function);

    MapRef initial_map = js_function.initial_map(broker());
    DCHECK(initial_map.instance_type() == JS_GENERATOR_OBJECT_TYPE ||
           initial_map.instance_type() == JS_ASYNC_GENERATOR_OBJECT_TYPE);

    // Allocate a register file.
    SharedFunctionInfoRef shared = js_function.shared(broker());
    DCHECK(shared.HasBytecodeArray());
    int parameter_count_no_receiver =
        shared.internal_formal_parameter_count_without_receiver();
    int length = parameter_count_no_receiver +
                 shared.GetBytecodeArray(broker()).register_count();
    MapRef fixed_array_map = broker()->fixed_array_map();
    AllocationBuilder ab(jsgraph(), broker(), effect, control);
    if (!ab.CanAllocateArray(length, fixed_array_map)) {
      return NoChange();
    }
    ab.AllocateArray(length, fixed_array_map);
    for (int i = 0; i < length; ++i) {
      ab.Store(AccessBuilder::ForFixedArraySlot(i),
               jsgraph()->UndefinedConstant());
    }
    Node* parameters_and_registers = effect = ab.Finish();

    // Emit code to allocate the JS[Async]GeneratorObject instance.
    AllocationBuilder a(jsgraph(), broker(), effect, control);
    a.Allocate(slack_tracking_prediction.instance_size());
    Node* undefined = jsgraph()->UndefinedConstant();
    a.Store(AccessBuilder::ForMap(), initial_map);
    a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
            jsgraph()->EmptyFixedArrayConstant());
    a.Store(AccessBuilder::ForJSObjectElements(),
            jsgraph()->EmptyFixedArrayConstant());
    a.Store(AccessBuilder::ForJSGeneratorObjectContext(), context);
    a.Store(AccessBuilder::ForJSGeneratorObjectFunction(), closure);
    a.Store(AccessBuilder::ForJSGeneratorObjectReceiver(), receiver);
    a.Store(AccessBuilder::ForJSGeneratorObjectInputOrDebugPos(), undefined);
    a.Store(AccessBuilder::ForJSGeneratorObjectResumeMode(),
            jsgraph()->ConstantNoHole(JSGeneratorObject::kNext));
    a.Store(AccessBuilder::ForJSGeneratorObjectContinuation(),
            jsgraph()->ConstantNoHole(JSGeneratorObject::kGeneratorExecuting));
    a.Store(AccessBuilder::ForJSGeneratorObjectParametersAndRegisters(),
            parameters_and_registers);

    if (initial_map.instance_type() == JS_ASYNC_GENERATOR_OBJECT_TYPE) {
      a.Store(AccessBuilder::ForJSAsyncGeneratorObjectQueue(), undefined);
      a.Store(AccessBuilder::ForJSAsyncGeneratorObjectIsAwaiting(),
              jsgraph()->ZeroConstant());
    }

    // Handle in-object properties, too.
    for (int i = 0; i < slack_tracking_prediction.inobject_property_count();
         ++i) {
      a.Store(AccessBuilder::ForJSObjectInObjectProperty(initial_map, i),
              undefined);
    }
    a.FinishAndChange(node);
    return Changed(node);
  }
  return NoChange();
}

// Constructs an array with a variable {length} when no upper bound
// is known for the capacity.
Reduction JSCreateLowering::ReduceNewArray(
    Node* node, Node* length, MapRef initial_map, ElementsKind elements_kind,
    AllocationType allocation,
    const SlackTrackingPrediction& slack_tracking_prediction) {
  DCHECK_EQ(IrOpcode::kJSCreateArray, node->opcode());
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  // Constructing an Array via new Array(N) where N is an unsigned
  // integer, always creates a holey backing store.
  OptionalMapRef maybe_initial_map =
      initial_map.AsElementsKind(broker(), GetHoleyElementsKind(elements_kind));
  if (!maybe_initial_map.has_value()) return NoChange();
  initial_map = maybe_initial_map.value();

  // Because CheckBounds performs implicit conversion from string to number, an
  // additional CheckNumber is required to behave correctly for calls with a
  // single string argument.
  length = effect = graph()->NewNode(
      simplified()->CheckNumber(FeedbackSource{}), length, effect, control);

  // Check that the {limit} is an unsigned integer in the valid range.
  // This has to be kept in sync with src/runtime/runtime-array.cc,
  // where this limit is protected.
  length = effect = graph()->NewNode(
      simplified()->CheckBounds(FeedbackSource()), length,
      jsgraph()->ConstantNoHole(JSArray::kInitialMaxFastElementArray), effect,
      control);

  // Construct elements and properties for the resulting JSArray.
  Node* elements = effect =
      graph()->NewNode(IsDoubleElementsKind(initial_map.elements_kind())
                           ? simplified()->NewDoubleElements(allocation)
                           : simplified()->NewSmiOrObjectElements(allocation),
                       length, effect, control);

  // Perform the allocation of the actual JSArray object.
  AllocationBuilder a(jsgraph(), broker(), effect, control);
  a.Allocate(slack_tracking_prediction.instance_size(), allocation);
  a.Store(AccessBuilder::ForMap(), initial_map);
  a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSObjectElements(), elements);
  a.Store(AccessBuilder::ForJSArrayLength(initial_map.elements_kind()), length);
  for (int i = 0; i < slack_tracking_prediction.inobject_property_count();
       ++i) {
    a.Store(AccessBuilder::ForJSObjectInObjectProperty(initial_map, i),
            jsgraph()->UndefinedConstant());
  }
  RelaxControls(node);
  a.FinishAndChange(node);
  return Changed(node);
}

// Constructs an array with a variable {length} when an actual
// upper bound is known for the {capacity}.
Reduction JSCreateLowering::ReduceNewArray(
    Node* node, Node* length, int capacity, MapRef initial_map,
    ElementsKind elements_kind, AllocationType allocation,
    const SlackTrackingPrediction& slack_tracking_prediction) {
  DCHECK(node->opcode() == IrOpcode::kJSCreateArray ||
         node->opcode() == IrOpcode::kJSCreateEmptyLiteralArray);
  DCHECK(NodeProperties::GetType(length).Is(Type::Number()));
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  // Determine the appropriate elements kind.
  if (NodeProperties::GetType(length).Max() > 0.0) {
    elements_kind = GetHoleyElementsKind(elements_kind);
  }

  OptionalMapRef maybe_initial_map =
      initial_map.AsElementsKind(broker(), elements_kind);
  if (!maybe_initial_map.has_value()) return NoChange();
  initial_map = maybe_initial_map.value();

  DCHECK(IsFastElementsKind(elements_kind));

  // Setup elements and properties.
  Node* elements;
  if (capacity == 0) {
    elements = jsgraph()->EmptyFixedArrayConstant();
  } else {
    elements = effect =
        AllocateElements(effect, control, elements_kind, capacity, allocation);
  }

  // Perform the allocation of the actual JSArray object.
  AllocationBuilder a(jsgraph(), broker(), effect, control);
  a.Allocate(slack_tracking_prediction.instance_size(), allocation);
  a.Store(AccessBuilder::ForMap(), initial_map);
  a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSObjectElements(), elements);
  a.Store(AccessBuilder::ForJSArrayLength(elements_kind), length);
  for (int i = 0; i < slack_tracking_prediction.inobject_property_count();
       ++i) {
    a.Store(AccessBuilder::ForJSObjectInObjectProperty(initial_map, i),
            jsgraph()->UndefinedConstant());
  }
  RelaxControls(node);
  a.FinishAndChange(node);
  return Changed(node);
}

Reduction JSCreateLowering::ReduceNewArray(
    Node* node, std::vector<Node*> values, MapRef initial_map,
    ElementsKind elements_kind, AllocationType allocation,
    const SlackTrackingPrediction& slack_tracking_prediction) {
  DCHECK_EQ(IrOpcode::kJSCreateArray, node->opcode());
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  // Determine the appropriate elements kind.
  DCHECK(IsFastElementsKind(elements_kind));

  OptionalMapRef maybe_initial_map =
      initial_map.AsElementsKind(broker(), elements_kind);
  if (!maybe_initial_map.has_value()) return NoChange();
  initial_map = maybe_initial_map.value();

  // Check {values} based on the {elements_kind}. These checks are guarded
  // by the {elements_kind} feedback on the {site}, so it's safe to just
  // deoptimize in this case.
  if (IsSmiElementsKind(elements_kind)) {
    for (auto& value : values) {
      if (!NodeProperties::GetType(value).Is(Type::SignedSmall())) {
        value = effect = graph()->NewNode(
            simplified()->CheckSmi(FeedbackSource()), value, effect, control);
      }
    }
  } else if (IsDoubleElementsKind(elements_kind)) {
    for (auto& value : values) {
      if (!NodeProperties::GetType(value).Is(Type::Number())) {
        value = effect =
            graph()->NewNode(simplified()->CheckNumber(FeedbackSource()), value,
                             effect, control);
      }
      // Make sure we do not store signaling NaNs into double arrays.
      value = graph()->NewNode(simplified()->NumberSilenceNaN(), value);
    }
  }

  // Setup elements, properties and length.
  Node* elements = effect =
      AllocateElements(effect, control, elements_kind, values, allocation);
  Node* length = jsgraph()->ConstantNoHole(static_cast<int>(values.size()));

  // Perform the allocation of the actual JSArray object.
  AllocationBuilder a(jsgraph(), broker(), effect, control);
  a.Allocate(slack_tracking_prediction.instance_size(), allocation);
  a.Store(AccessBuilder::ForMap(), initial_map);
  a.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSObjectElements(), elements);
  a.Store(AccessBuilder::ForJSArrayLength(elements_kind), length);
  for (int i = 0; i < slack_tracking_prediction.inobject_property_count();
       ++i) {
    a.Store(AccessBuilder::ForJSObjectInObjectProperty(initial_map, i),
            jsgraph()->UndefinedConstant());
  }
  RelaxControls(node);
  a.FinishAndChange(node);
  return Changed(node);
}

Reduction JSCreateLowering::ReduceJSCreateArray(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreateArray, node->opcode());
  CreateArrayParameters const& p = CreateArrayParametersOf(node->op());
  int const arity = static_cast<int>(p.arity());
  OptionalAllocationSiteRef site_ref = p.site();
  AllocationType allocation = AllocationType::kYoung;

  OptionalMapRef initial_map = NodeProperties::GetJSCreateMap(broker(), node);
  if (!initial_map.has_value()) return NoChange();

  Node* new_target = NodeProperties::GetValueInput(node, 1);
  JSFunctionRef original_constructor =
      HeapObjectMatcher(new_target).Ref(broker()).AsJSFunction();
  SlackTrackingPrediction slack_tracking_prediction =
      dependencies()->DependOnInitialMapInstanceSizePrediction(
          original_constructor);

  // Tells whether we are protected by either the {site} or a
  // protector cell to do certain speculative optimizations.
  bool can_inline_call = false;

  // Check if we have a feedback {site} on the {node}.
  ElementsKind elements_kind = initial_map->elements_kind();
  if (site_ref) {
    elements_kind = site_ref->GetElementsKind();
    can_inline_call = site_ref->CanInlineCall();
    allocation = dependencies()->DependOnPretenureMode(*site_ref);
    dependencies()->DependOnElementsKind(*site_ref);
  } else {
    PropertyCellRef array_constructor_protector =
        MakeRef(broker(), factory()->array_constructor_protector());
    array_constructor_protector.CacheAsProtector(broker());
    can_inline_call = array_constructor_protector.value(broker()).AsSmi() ==
                      Protectors::kProtectorValid;
  }

  if (arity == 0) {
    Node* length = jsgraph()->ZeroConstant();
    int capacity = JSArray::kPreallocatedArrayElements;
    return ReduceNewArray(node, length, capacity, *initial_map, elements_kind,
                          allocation, slack_tracking_prediction);
  } else if (arity == 1) {
    Node* length = NodeProperties::GetValueInput(node, 2);
    Type length_type = NodeProperties::GetType(length);
    if (!length_type.Maybe(Type::Number())) {
      // Handle the single argument case, where we know that the value
      // cannot be a valid Array length.
      elements_kind = GetMoreGeneralElementsKind(
          elements_kind, IsHoleyElementsKind(elements_kind) ? HOLEY_ELEMENTS
                                                            : PACKED_ELEMENTS);
      return ReduceNewArray(node, std::vector<Node*>{length}, *initial_map,
                            elements_kind, allocation,
                            slack_tracking_prediction);
    }
    if (length_type.Is(Type::SignedSmall()) && length_type.Min() >= 0 &&
        length_type.Max() <= kElementLoopUnrollLimit &&
        length_type.Min() == length_type.Max()) {
      int capacity = static_cast<int>(length_type.Max());
      // Replace length with a constant in order to protect against a potential
      // typer bug leading to length > capacity.
      length = jsgraph()->ConstantNoHole(capacity);
      return ReduceNewArray(node, length, capacity, *initial_map, elements_kind,
                            allocation, slack_tracking_prediction);
    }
    if (length_type.Maybe(Type::UnsignedSmall()) && can_inline_call) {
      return ReduceNewArray(node, length, *initial_map, elements_kind,
                            allocation, slack_tracking_prediction);
    }
  } else if (arity <= JSArray::kInitialMaxFastElementArray) {
    // Gather the values to store into the newly created array.
    bool values_all_smis = true, values_all_numbers = true,
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