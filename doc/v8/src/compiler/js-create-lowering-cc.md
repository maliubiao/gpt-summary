Response:
The user wants me to analyze a C++ source code file from the V8 JavaScript engine.

Here's a breakdown of the request and how I'll address each part:

1. **List the functionality of `v8/src/compiler/js-create-lowering.cc`:** I will examine the code and identify the key operations it performs. The file name "js-create-lowering" strongly suggests it's involved in the process of converting high-level JavaScript creation operations into lower-level, more concrete operations within the compiler.

2. **Check if it's a Torque file:** I will examine the file extension. The prompt explicitly states how to identify Torque files.

3. **Relationship to JavaScript and provide an example:** If the file handles JavaScript creation operations, I will illustrate the corresponding JavaScript code.

4. **Code logic reasoning (hypothetical input/output):**  This will be tricky without the full context of the compiler. I will focus on the specific functions within the provided snippet and describe what kind of compiler nodes they might process and what lower-level operations they might generate. I'll need to make some assumptions about the inputs (likely intermediate representation nodes of the compiler).

5. **Common programming errors:** I will think about common JavaScript mistakes related to the creation operations handled in this file (e.g., array creation, object creation).

6. **Summarize the functionality:** I will provide a concise summary based on the analysis.

**Mental Sandbox:**

* **Functionality Identification:**  The `Reduce` method and the various `ReduceJSCreate...` functions are the core. They seem to handle different ways JavaScript objects are created (arrays, arguments objects, closures, promises, etc.). This confirms the "lowering" aspect - taking general "create" operations and making them more specific.

* **Torque Check:** The file extension is `.cc`, not `.tq`. This is straightforward.

* **JavaScript Example:**  I can use examples like `new Array()`, `[]`, `arguments`, `function*() {}`, `Promise.resolve()`, etc., depending on the specific `ReduceJSCreate...` function.

* **Input/Output:**  I'll imagine the input being an abstract "create array" node and the output being a sequence of lower-level operations for allocating memory, setting up the map, properties, and elements.

* **Common Errors:**  Creating arrays with non-numeric lengths, forgetting `new` for constructors, misunderstanding the behavior of `arguments`, etc.

**Constraint Checklist & Confidence:**

* List functionality: Yes
* Torque check: Yes
* JavaScript example: Yes (for related functionality)
* Input/output example: Yes (with assumptions)
* Common errors: Yes
* Summarize: Yes

Confidence: 4/5 (Slight uncertainty in precisely defining input/output without the full compiler context, but I can make reasonable assumptions.)

Strategizing complete. I will now proceed with generating the response based on these steps.```
v8/src/compiler/js-create-lowering.cc 的功能:

1. **将高级的 JavaScript 对象创建操作转换为更底层的、更具体的编译器操作。**  这个过程被称为 "降低" (lowering)。这使得后续的编译器优化和代码生成阶段更容易处理。

2. **处理 `JSCreate` 操作:**  这是用于普通对象创建的通用操作。它会根据对象的初始 Map 信息来分配内存并初始化对象。

3. **处理 `JSCreateArguments` 操作:**  用于创建 `arguments` 对象，这在函数调用时捕获传递给函数的参数。它会根据不同的参数类型（mapped, unmapped, rest parameters）生成不同的代码。

4. **处理 `JSCreateArray` 操作:**  用于创建数组。它会根据数组的大小、初始元素类型以及是否使用了字面量等情况生成不同的代码，包括分配元素存储空间。

5. **处理各种迭代器创建操作 (例如, `JSCreateArrayIterator`, `JSCreateCollectionIterator`, `JSCreateStringIterator`):**  用于创建不同类型的迭代器对象，这些对象允许按顺序访问集合中的元素。

6. **处理异步函数对象创建 (`JSCreateAsyncFunctionObject`):**  用于创建表示异步函数的对象。

7. **处理绑定函数创建 (`JSCreateBoundFunction`):**  用于创建通过 `Function.prototype.bind()` 创建的函数。

8. **处理闭包创建 (`JSCreateClosure`):**  用于创建函数闭包，闭包会捕获其词法作用域中的变量。

9. **处理 `JSCreateIterResultObject` 操作:** 用于创建迭代器返回的结果对象，通常包含 `value` 和 `done` 属性。

10. **处理键值对数组创建 (`JSCreateKeyValueArray`):**  可能用于创建包含键值对的数组，例如在某些对象解构场景中。

11. **处理 Promise 创建 (`JSCreatePromise`):**  用于创建 Promise 对象，用于处理异步操作。

12. **处理字面量创建操作 (`JSCreateLiteralArray`, `JSCreateLiteralObject`, `JSCreateLiteralRegExp`):**  用于创建通过字面量语法（例如 `[]`, `{}`, `/abc/`) 创建的对象。它会尝试优化这些创建过程。

13. **处理模板对象创建 (`JSGetTemplateObject`):**  用于创建模板字面量中使用的模板对象。

14. **处理创建空字面量对象和数组 (`JSCreateEmptyLiteralArray`, `JSCreateEmptyLiteralObject`):**  针对创建空的 `[]` 和 `{}` 进行优化。

15. **处理上下文创建操作 (`JSCreateFunctionContext`, `JSCreateWithContext`, `JSCreateCatchContext`, `JSCreateBlockContext`):**  用于创建不同类型的执行上下文，这些上下文用于管理变量的作用域。

16. **处理生成器对象创建 (`JSCreateGeneratorObject`):**  用于创建生成器函数返回的生成器对象。

17. **处理普通对象创建 (`JSCreateObject`):**  与 `JSCreate` 类似，但可能更具体用于通过 `new Object()` 或 `Object.create(null)` 创建的对象。

18. **处理字符串包装对象创建 (`JSCreateStringWrapper`):** 用于创建字符串的包装对象，例如 `new String("abc")`。

**关于文件类型:**

`v8/src/compiler/js-create-lowering.cc` 的文件扩展名是 `.cc`，这意味着它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件。Torque 文件的扩展名是 `.tq`。

**与 JavaScript 功能的关系及示例:**

`v8/src/compiler/js-create-lowering.cc` 中的每一个 `ReduceJSCreate...` 函数都直接对应于 JavaScript 中创建特定类型对象的方式。

**示例:**

* **`ReduceJSCreate(node)` 对应于:**

   ```javascript
   const obj = new MyClass(); // 或 new Object();
   ```

* **`ReduceJSCreateArguments(node)` 对应于:**

   ```javascript
   function foo(a, b) {
     console.log(arguments); // arguments 对象
   }
   foo(1, 2);

   function bar(...rest) {
     console.log(rest); // rest 参数创建的数组
   }
   bar(3, 4, 5);
   ```

* **`ReduceJSCreateArray(node)` 对应于:**

   ```javascript
   const arr1 = new Array(5); // 创建一个长度为 5 的空数组
   const arr2 = new Array(1, 2, 3); // 创建包含元素的数组
   const arr3 = [4, 5, 6]; // 字面量创建数组
   ```

* **`ReduceJSCreatePromise(node)` 对应于:**

   ```javascript
   const promise = new Promise((resolve, reject) => {
     // ... 异步操作 ...
   });
   ```

* **`ReduceJSCreateGeneratorObject(node)` 对应于:**

   ```javascript
   function* myGenerator() {
     yield 1;
     yield 2;
   }
   const generator = myGenerator();
   ```

**代码逻辑推理 (假设输入与输出):**

假设输入一个代表 `const arr = [1, 2, 3];` 的 `JSCreateLiteralArray` 节点。

**假设输入:**

* `node` 是一个 `JSCreateLiteralArray` 节点。
* `node` 包含字面量数组的元素信息：常量 `1`, `2`, `3`。
* `node` 关联了用于数组创建的初始 Map 信息 (例如，数组的元素类型)。

**可能的输出 (经过 `ReduceJSCreateLiteralArray` 处理后):**

编译器可能会生成以下操作序列：

1. **分配内存:**  根据数组的长度和元素类型分配足够的内存来存储数组的元素。
2. **初始化 Map:**  将分配的内存与预先确定的数组 Map 关联起来，该 Map 描述了数组的结构和类型。
3. **存储元素:**  将常量值 `1`, `2`, `3` 存储到数组的元素存储空间中。
4. **设置长度:**  将数组的 `length` 属性设置为 `3`。

**涉及用户常见的编程错误 (举例说明):**

1. **创建具有非数字长度的数组:**

   ```javascript
   const arr = new Array("abc"); // 可能会导致意外行为或错误，因为 "abc" 不是有效的数组长度。
   console.log(arr.length); // 输出 1
   console.log(arr[0]);    // 输出 "abc"，而不是创建一个具有 "abc" 长度的空数组。
   ```
   `ReduceJSCreateArray` 中会处理这种情况，将其视为创建一个包含单个元素的数组。

2. **忘记 `new` 关键字调用构造函数:**

   ```javascript
   function MyClass() {
     this.value = 10;
   }
   const obj = MyClass(); // 忘记了 new 关键字
   console.log(obj);      // 输出 undefined (或根据上下文可能报错)
   console.log(value);    // 如果在全局作用域中，可能意外创建了全局变量 value
   ```
   虽然这个错误不是 `JSCreateLowering` 直接处理的创建过程，但它与理解对象创建相关。

3. **误解 `arguments` 对象的行为:**

   ```javascript
   function foo(a) {
     arguments[0] = 5;
     console.log(a); // 在非严格模式下，a 的值也会被修改为 5
   }
   foo(1);
   ```
   `ReduceJSCreateArguments` 需要正确处理 `arguments` 对象的这种特殊行为。

**功能归纳 (第 1 部分):**

`v8/src/compiler/js-create-lowering.cc` 的主要功能是 **作为 V8 编译器的一部分，将高级的 JavaScript 对象创建操作转换为更底层的、更容易优化的表示形式。** 它针对各种不同的对象创建场景（普通对象、数组、函数、Promise 等）提供了专门的处理逻辑，以便后续的编译器阶段能够生成高效的目标代码。 这个文件是连接 JavaScript 语义和底层机器表示的关键桥梁。
```
Prompt: 
```
这是目录为v8/src/compiler/js-create-lowering.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-create-lowering.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

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
    bool values_all_smis = true, values_all_numbers = tr
"""


```