Response:
Let's break down the thought process for analyzing this V8 code snippet.

**1. Initial Understanding of the Goal:**

The request asks for an explanation of the functionality of `v8/src/compiler/js-intrinsic-lowering.cc`. Key points to extract are:

* **Core Function:** What does this file *do* in the V8 compilation pipeline?
* **Torque:** Is it related to Torque? (The file extension is crucial here.)
* **JavaScript Relationship:** How does it relate to JavaScript functionality?
* **Code Logic:** Are there specific transformations or reasoning steps within the code?
* **Common Errors:** Does it address or prevent common JavaScript mistakes?

**2. Examining the File Extension:**

The prompt itself provides a crucial clue: "If `v8/src/compiler/js-intrinsic-lowering.cc` ended with `.tq`, it would be a V8 Torque source code."  Since it ends in `.cc`, it's standard C++ code. This immediately tells us it's *not* Torque and will involve direct manipulation of the V8 intermediate representation (IR).

**3. Analyzing the Includes:**

The `#include` directives offer significant insights:

* `"src/compiler/js-intrinsic-lowering.h"`: This is the header for the current file, indicating it defines the `JSIntrinsicLowering` class.
* `<stack>`:  While present, it's not immediately obvious how it's used. A closer look at the code reveals it's not actually used, so we can note this as a potential artifact.
* `"src/codegen/callable.h"`:  Suggests interactions with the code generation phase, particularly with callable entities (built-ins, functions).
* `"src/compiler/access-builder.h"`: Points to the mechanism for accessing properties of JavaScript objects within the compiler.
* `"src/compiler/js-graph.h"`:  A core component of the TurboFan compiler, indicating this code manipulates the graph-based intermediate representation.
* `"src/compiler/js-heap-broker.h"`: Implies interaction with the heap and access to object properties and types.
* `"src/compiler/linkage.h"`: Deals with calling conventions and linking between different parts of the compiled code.
* `"src/compiler/node-matchers.h"` and `"src/compiler/node-properties.h"`:  Essential for working with the TurboFan graph nodes, inspecting their properties, and matching specific patterns.
* `"src/objects/js-generator.h"` and `"src/objects/objects-inl.h"`: Shows specific handling of generator objects, a crucial asynchronous JavaScript feature.

**4. Understanding the `JSIntrinsicLowering` Class:**

* **Inheritance:** It inherits from `AdvancedReducer`. Knowing what a "reducer" does in a compiler (simplifies or transforms the IR) is key. "AdvancedReducer" likely implies more complex transformations.
* **Constructor:** Takes `Editor`, `JSGraph`, and `JSHeapBroker` as arguments, solidifying its role within the TurboFan pipeline.
* **`Reduce(Node* node)`:**  This is the central method. It takes a `Node` (part of the IR graph) and returns a `Reduction`. This confirms its role as a transformer. The initial check for `IrOpcode::kJSCallRuntime` suggests it primarily targets calls to runtime functions.

**5. Examining the `Reduce` Method's Logic:**

* **Runtime Function Handling:** The first `switch` statement handles specific `Runtime` functions (e.g., `kIsBeingInterpreted`, `kTurbofanStaticAssert`). This indicates direct replacements or simplifications for these runtime calls.
* **Intrinsic Function Handling:** The second `switch` handles runtime functions marked as `INLINE`. This is where the core "lowering" happens – replacing high-level intrinsic calls with lower-level built-in calls or sequences of simpler operations.
* **Specific Reduction Methods:**  Each `case` in the `switch` statements corresponds to a dedicated `Reduce...` method (e.g., `ReduceCopyDataProperties`). This promotes modularity and makes the code easier to understand.

**6. Analyzing Individual `Reduce` Methods (Examples):**

* **`ReduceCopyDataProperties`:**  Directly changes the `JSCallRuntime` node to a `Call` node targeting the `kCopyDataProperties` built-in. This exemplifies the core "lowering" action.
* **`ReduceCreateIterResultObject`:** Replaces the runtime call with a direct call to the `javascript()->CreateIterResultObject()` operator, which is a lower-level representation.
* **`ReduceDeoptimizeNow`:** Shows how a runtime call can trigger more complex actions like inserting a `Deoptimize` node into the graph.
* **`ReduceGeneratorClose`:** Demonstrates how a runtime call can be translated into a series of lower-level operations like storing a value in an object field.
* **`ReduceIsBeingInterpreted`:** A straightforward replacement with `jsgraph_->FalseConstant()`, illustrating a simplification based on the compiler's context.

**7. Identifying Patterns and Key Concepts:**

* **Lowering:** The central theme is "lowering" – converting high-level operations (runtime calls) into lower-level, more primitive operations (built-in calls, graph operators).
* **Optimization:** This process is an optimization. By replacing runtime calls with more direct operations, the generated code can be more efficient.
* **Built-ins:**  Many runtime calls are lowered to calls to specific built-in functions.
* **Graph Manipulation:** The code directly interacts with and modifies the TurboFan IR graph.
* **Context Sensitivity:** Some decisions (like ignoring `TurbofanStaticAssert` in `always_turbofan` mode) depend on compiler flags and the overall compilation context.

**8. Connecting to JavaScript Functionality:**

For each `Reduce...` method, think about the corresponding JavaScript concept:

* `CopyDataProperties`:  `Object.assign()`, spread syntax for objects.
* `CreateIterResultObject`: The result object returned by iterators.
* `DeoptimizeNow`:  The mechanism for forcing the compiler to abandon optimized code.
* Generator functions (`async function`, `async*`): The `await`, `yield`, `return` behavior and lifecycle of these functions.

**9. Addressing Specific Request Points:**

* **Functionality:** Summarize the overall purpose (lowering intrinsics for optimization).
* **Torque:** Explicitly state it's not Torque.
* **JavaScript Examples:** Provide concrete JavaScript code snippets that would trigger the execution of the runtime functions being lowered.
* **Code Logic:** Explain the transformation steps within the key `Reduce...` methods. Use simple examples with assumptions.
* **Common Errors:** Think about what JavaScript code could lead to these intrinsics being called and where errors might occur (e.g., using `deoptimizeNow()` directly, improper generator usage).

**10. Structuring the Output:**

Organize the information logically with clear headings and bullet points. Start with a high-level overview and then delve into specifics. Use examples and clear explanations.

By following this systematic approach, we can effectively analyze the C++ code, understand its purpose within the V8 compiler, and explain its relationship to JavaScript functionality. The key is to understand the compiler's role, the concept of "lowering," and how specific V8 components like the IR graph and built-ins are involved.
`v8/src/compiler/js-intrinsic-lowering.cc` 是 V8 引擎中 TurboFan 编译器的一个关键组成部分，其主要功能是将 JavaScript 的**内建函数（intrinsics）**和一些特定的 **Runtime 函数**调用转换为更底层的、更优化的操作。这个过程被称为 **intrinsic lowering** 或 **inlining**。

**主要功能：**

1. **识别特定的 Runtime 函数调用：** `JSIntrinsicLowering::Reduce` 方法是入口点，它会检查当前处理的节点是否是一个 `JSCallRuntime` 操作。
2. **内联优化的 Runtime 函数：**  对于某些标记为 `INLINE` 的 Runtime 函数（通过 `f->intrinsic_type != Runtime::IntrinsicType::INLINE` 判断），它会使用更高效的内置函数（built-ins）或更底层的操作来替换这些调用。
3. **处理特殊的 Runtime 函数：** 对于一些非内联的特定 Runtime 函数，例如 `kIsBeingInterpreted`, `kTurbofanStaticAssert`, `kVerifyType`, `kCheckTurboshaftTypeOf`，它会进行特定的转换或处理。
4. **将 Runtime 调用转换为 Built-in 调用：**  很多 `Reduce...` 方法的目标是将 `JSCallRuntime` 节点替换为一个调用相应 Built-in 函数的 `Call` 节点。Built-in 函数是用 C++ 或汇编编写的，通常比通用的 Runtime 函数更高效。
5. **将 Runtime 调用转换为底层的 JavaScript 操作：**  对于某些 Runtime 函数，例如 `kInlineCreateIterResultObject`，它会被替换为直接创建对应 JavaScript 对象的节点（例如 `javascript()->CreateIterResultObject()`）。
6. **处理异步操作和生成器：** 特别处理了与 `async function` 和 `generator function` 相关的 Runtime 函数，例如 `kInlineAsyncFunctionAwait`, `kInlineGeneratorClose` 等。
7. **提供类型检查和断言机制：** 处理了 `kVerifyType` 和 `kTurbofanStaticAssert` 等用于类型验证和静态断言的 Runtime 函数。

**关于 `.tq` 结尾：**

正如代码注释中提到的，如果 `v8/src/compiler/js-intrinsic-lowering.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque** 源代码文件。 Torque 是一种 V8 特有的领域特定语言，用于定义 Built-in 函数和 Runtime 函数的实现。当前的 `.cc` 结尾表明这是一个标准的 C++ 源文件。

**与 JavaScript 功能的关系 (附带 JavaScript 例子)：**

`JSIntrinsicLowering` 的目标是优化 JavaScript 代码的执行效率，它处理的 Runtime 函数和 Built-in 函数通常对应着 JavaScript 的一些核心功能。以下是一些例子：

* **`Runtime::kInlineCopyDataProperties`:**  对应 `Object.assign()` 或对象展开语法 (`{...obj}`)，用于将一个或多个源对象的属性复制到目标对象。
   ```javascript
   const target = { a: 1 };
   const source = { b: 2, c: 3 };
   Object.assign(target, source); // 此处可能会调用到 CopyDataProperties
   console.log(target); // 输出: { a: 1, b: 2, c: 3 }

   const target2 = { d: 4 };
   const source2 = { e: 5 };
   const merged = { ...target2, ...source2 }; // 对象展开也可能使用 CopyDataProperties
   console.log(merged); // 输出: { d: 4, e: 5 }
   ```

* **`Runtime::kInlineCreateIterResultObject`:** 对应迭代器（Iterator）的 `next()` 方法返回的结果对象，包含 `value` 和 `done` 属性。
   ```javascript
   function* myGenerator() {
       yield 1;
       yield 2;
   }
   const iterator = myGenerator();
   console.log(iterator.next()); // 输出: { value: 1, done: false }  此处会创建 IterResultObject
   console.log(iterator.next()); // 输出: { value: 2, done: false }
   console.log(iterator.next()); // 输出: { value: undefined, done: true }
   ```

* **`Runtime::kInlineDeoptimizeNow`:** 对应开发者在调试或性能分析时手动触发代码反优化的场景（尽管不推荐在生产环境中使用）。
   ```javascript
   function potentiallyOptimizedFunction(x) {
       // 一些复杂的逻辑
       if (x < 0) {
           %DeoptimizeNow(); // 手动触发反优化 (注意: %DeoptimizeNow 是 V8 特有的，非标准 JavaScript)
       }
       return x * 2;
   }
   ```

* **`Runtime::kInlineGeneratorClose`:** 对应生成器对象的 `return()` 方法，用于显式关闭生成器。
   ```javascript
   function* myGenerator() {
       yield 1;
       yield 2;
   }
   const generator = myGenerator();
   console.log(generator.next()); // 输出: { value: 1, done: false }
   console.log(generator.return(10)); // 输出: { value: 10, done: true }，生成器被关闭
   console.log(generator.next()); // 输出: { value: undefined, done: true }
   ```

* **`Runtime::kInlineAsyncFunctionAwait`:** 对应 `async function` 中的 `await` 关键字。
   ```javascript
   async function myFunction() {
       console.log("开始");
       await new Promise(resolve => setTimeout(resolve, 100)); // 此处会涉及到 AsyncFunctionAwait
       console.log("结束");
   }
   myFunction();
   ```

**代码逻辑推理 (假设输入与输出)：**

假设 `JSIntrinsicLowering::Reduce` 方法接收到一个代表 `Object.assign(target, source)` 调用的 `JSCallRuntime` 节点，其中调用的 Runtime 函数是 `Runtime::kInlineCopyDataProperties`。

**假设输入 (简化表示)：**

```
Node {
  opcode: IrOpcode::kJSCallRuntime,
  runtime_function_id: Runtime::kInlineCopyDataProperties,
  inputs: [target_object_node, source_object_node, context_node, effect_node, control_node]
}
```

**代码逻辑推理过程：**

1. `Reduce` 方法判断 `node->opcode()` 是 `IrOpcode::kJSCallRuntime`。
2. 它获取 Runtime 函数的 ID，发现是 `Runtime::kInlineCopyDataProperties`。
3. 根据 `f->intrinsic_type != Runtime::IntrinsicType::INLINE` 的判断，确认这是一个需要内联的函数。
4. 进入 `switch (f->function_id)` 的 `case Runtime::kInlineCopyDataProperties:` 分支。
5. 调用 `ReduceCopyDataProperties(node)` 方法。
6. `ReduceCopyDataProperties` 方法会创建一个新的 `Call` 操作符，指向 `Builtin::kCopyDataProperties`。
7. 它会更新 `node` 的操作符为 `common()->Call(call_descriptor)`，并将输入的参数调整为 Built-in 函数需要的参数。

**假设输出 (简化表示)：**

```
Node {
  opcode: IrOpcode::kCall,
  call_descriptor: 指向 Builtin::kCopyDataProperties 的调用描述符,
  inputs: [Builtin::kCopyDataProperties的代码, target_object_node, source_object_node]
}
```

原始的 `JSCallRuntime` 节点被替换为了一个直接调用 `CopyDataProperties` Built-in 函数的 `Call` 节点。

**涉及用户常见的编程错误 (举例说明)：**

虽然 `JSIntrinsicLowering` 主要关注性能优化，但它处理的某些 Runtime 函数也与用户可能犯的错误有关：

* **不恰当的类型假设：** `Runtime::kVerifyType` 和 `Runtime::kCheckTurboshaftTypeOf` 涉及到类型检查。用户如果错误地假设变量的类型，可能会导致类型错误，这些函数在编译过程中可以帮助捕获或优化与类型相关的操作。例如：
   ```javascript
   function add(a, b) {
       return a + b; // 如果 a 或 b 不是数字，可能会得到意想不到的结果
   }
   add(5, "10"); // JavaScript 不会报错，但结果可能是 "510"
   ```
   V8 内部可能会使用类型信息进行优化，而 `VerifyType` 可以确保在某些关键点变量的类型符合预期。

* **过度使用 `deoptimizeNow()`：**  虽然 `Runtime::kInlineDeoptimizeNow` 对应手动反优化，但开发者不应该在生产代码中过度使用它。这会严重影响性能，因为它强制 V8 放弃已经进行的优化。

* **不理解生成器和异步函数的生命周期：** 与 `Runtime::kInlineGeneratorClose`, `Runtime::kInlineAsyncFunctionAwait` 等相关的错误通常涉及到对生成器和异步函数状态管理的误解，例如在生成器已经关闭后继续调用 `next()`，或者在异步操作未完成时就尝试获取结果。

总而言之，`v8/src/compiler/js-intrinsic-lowering.cc` 通过将高层的 JavaScript 内建函数和 Runtime 函数调用转换为更底层的操作，在 V8 的编译优化过程中扮演着至关重要的角色，直接影响着 JavaScript 代码的执行效率。

### 提示词
```
这是目录为v8/src/compiler/js-intrinsic-lowering.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-intrinsic-lowering.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/js-intrinsic-lowering.h"

#include <stack>

#include "src/codegen/callable.h"
#include "src/compiler/access-builder.h"
#include "src/compiler/js-graph.h"
#include "src/compiler/js-heap-broker.h"
#include "src/compiler/linkage.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/node-properties.h"
#include "src/objects/js-generator.h"
#include "src/objects/objects-inl.h"

namespace v8 {
namespace internal {
namespace compiler {

JSIntrinsicLowering::JSIntrinsicLowering(Editor* editor, JSGraph* jsgraph,
                                         JSHeapBroker* broker)
    : AdvancedReducer(editor), jsgraph_(jsgraph), broker_(broker) {}

Reduction JSIntrinsicLowering::Reduce(Node* node) {
  if (node->opcode() != IrOpcode::kJSCallRuntime) return NoChange();
  const Runtime::Function* const f =
      Runtime::FunctionForId(CallRuntimeParametersOf(node->op()).id());
  switch (f->function_id) {
    case Runtime::kIsBeingInterpreted:
      return ReduceIsBeingInterpreted(node);
    case Runtime::kTurbofanStaticAssert:
      return ReduceTurbofanStaticAssert(node);
    case Runtime::kVerifyType:
      return ReduceVerifyType(node);
    case Runtime::kCheckTurboshaftTypeOf:
      return ReduceCheckTurboshaftTypeOf(node);
    default:
      break;
  }
  if (f->intrinsic_type != Runtime::IntrinsicType::INLINE) return NoChange();
  switch (f->function_id) {
    case Runtime::kInlineCopyDataProperties:
      return ReduceCopyDataProperties(node);
    case Runtime::kInlineCopyDataPropertiesWithExcludedPropertiesOnStack:
      return ReduceCopyDataPropertiesWithExcludedPropertiesOnStack(node);
    case Runtime::kInlineCreateIterResultObject:
      return ReduceCreateIterResultObject(node);
    case Runtime::kInlineDeoptimizeNow:
      return ReduceDeoptimizeNow(node);
    case Runtime::kInlineGeneratorClose:
      return ReduceGeneratorClose(node);
    case Runtime::kInlineCreateJSGeneratorObject:
      return ReduceCreateJSGeneratorObject(node);
    case Runtime::kInlineAsyncFunctionAwait:
      return ReduceAsyncFunctionAwait(node);
    case Runtime::kInlineAsyncFunctionEnter:
      return ReduceAsyncFunctionEnter(node);
    case Runtime::kInlineAsyncFunctionReject:
      return ReduceAsyncFunctionReject(node);
    case Runtime::kInlineAsyncFunctionResolve:
      return ReduceAsyncFunctionResolve(node);
    case Runtime::kInlineAsyncGeneratorAwait:
      return ReduceAsyncGeneratorAwait(node);
    case Runtime::kInlineAsyncGeneratorReject:
      return ReduceAsyncGeneratorReject(node);
    case Runtime::kInlineAsyncGeneratorResolve:
      return ReduceAsyncGeneratorResolve(node);
    case Runtime::kInlineAsyncGeneratorYieldWithAwait:
      return ReduceAsyncGeneratorYieldWithAwait(node);
    case Runtime::kInlineGeneratorGetResumeMode:
      return ReduceGeneratorGetResumeMode(node);
    case Runtime::kInlineIncBlockCounter:
      return ReduceIncBlockCounter(node);
    case Runtime::kInlineGetImportMetaObject:
      return ReduceGetImportMetaObject(node);
    default:
      break;
  }
  return NoChange();
}

Reduction JSIntrinsicLowering::ReduceCopyDataProperties(Node* node) {
  return Change(
      node, Builtins::CallableFor(isolate(), Builtin::kCopyDataProperties), 0);
}

Reduction
JSIntrinsicLowering::ReduceCopyDataPropertiesWithExcludedPropertiesOnStack(
    Node* node) {
  int input_count =
      static_cast<int>(CallRuntimeParametersOf(node->op()).arity());
  CallDescriptor::Flags flags = CallDescriptor::kNeedsFrameState;
  auto callable = Builtins::CallableFor(
      isolate(), Builtin::kCopyDataPropertiesWithExcludedProperties);
  auto call_descriptor = Linkage::GetStubCallDescriptor(
      graph()->zone(), callable.descriptor(), input_count - 1, flags,
      node->op()->properties());
  node->InsertInput(graph()->zone(), 0,
                    jsgraph()->HeapConstantNoHole(callable.code()));
  node->InsertInput(graph()->zone(), 2,
                    jsgraph()->SmiConstant(input_count - 1));
  NodeProperties::ChangeOp(node, common()->Call(call_descriptor));
  return Changed(node);
}

Reduction JSIntrinsicLowering::ReduceCreateIterResultObject(Node* node) {
  Node* const value = NodeProperties::GetValueInput(node, 0);
  Node* const done = NodeProperties::GetValueInput(node, 1);
  Node* const context = NodeProperties::GetContextInput(node);
  Node* const effect = NodeProperties::GetEffectInput(node);
  return Change(node, javascript()->CreateIterResultObject(), value, done,
                context, effect);
}

Reduction JSIntrinsicLowering::ReduceDeoptimizeNow(Node* node) {
  Node* const frame_state = NodeProperties::GetFrameStateInput(node);
  Node* const effect = NodeProperties::GetEffectInput(node);
  Node* const control = NodeProperties::GetControlInput(node);

  Node* deoptimize = graph()->NewNode(
      common()->Deoptimize(DeoptimizeReason::kDeoptimizeNow, FeedbackSource()),
      frame_state, effect, control);
  MergeControlToEnd(graph(), common(), deoptimize);

  node->TrimInputCount(0);
  NodeProperties::ChangeOp(node, common()->Dead());
  return Changed(node);
}

Reduction JSIntrinsicLowering::ReduceCreateJSGeneratorObject(Node* node) {
  Node* const closure = NodeProperties::GetValueInput(node, 0);
  Node* const receiver = NodeProperties::GetValueInput(node, 1);
  Node* const context = NodeProperties::GetContextInput(node);
  Node* const effect = NodeProperties::GetEffectInput(node);
  Node* const control = NodeProperties::GetControlInput(node);
  Operator const* const op = javascript()->CreateGeneratorObject();
  Node* create_generator =
      graph()->NewNode(op, closure, receiver, context, effect, control);
  ReplaceWithValue(node, create_generator, create_generator);
  return Changed(create_generator);
}

Reduction JSIntrinsicLowering::ReduceGeneratorClose(Node* node) {
  Node* const generator = NodeProperties::GetValueInput(node, 0);
  Node* const effect = NodeProperties::GetEffectInput(node);
  Node* const control = NodeProperties::GetControlInput(node);
  Node* const closed =
      jsgraph()->ConstantNoHole(JSGeneratorObject::kGeneratorClosed);
  Node* const undefined = jsgraph()->UndefinedConstant();
  Operator const* const op = simplified()->StoreField(
      AccessBuilder::ForJSGeneratorObjectContinuation());

  ReplaceWithValue(node, undefined, node);
  NodeProperties::RemoveType(node);
  return Change(node, op, generator, closed, effect, control);
}

Reduction JSIntrinsicLowering::ReduceAsyncFunctionAwait(Node* node) {
  return Change(
      node, Builtins::CallableFor(isolate(), Builtin::kAsyncFunctionAwait), 0);
}

Reduction JSIntrinsicLowering::ReduceAsyncFunctionEnter(Node* node) {
  NodeProperties::ChangeOp(node, javascript()->AsyncFunctionEnter());
  return Changed(node);
}

Reduction JSIntrinsicLowering::ReduceAsyncFunctionReject(Node* node) {
  RelaxControls(node);
  NodeProperties::ChangeOp(node, javascript()->AsyncFunctionReject());
  return Changed(node);
}

Reduction JSIntrinsicLowering::ReduceAsyncFunctionResolve(Node* node) {
  RelaxControls(node);
  NodeProperties::ChangeOp(node, javascript()->AsyncFunctionResolve());
  return Changed(node);
}

Reduction JSIntrinsicLowering::ReduceAsyncGeneratorAwait(Node* node) {
  return Change(
      node, Builtins::CallableFor(isolate(), Builtin::kAsyncGeneratorAwait), 0);
}

Reduction JSIntrinsicLowering::ReduceAsyncGeneratorReject(Node* node) {
  return Change(
      node, Builtins::CallableFor(isolate(), Builtin::kAsyncGeneratorReject),
      0);
}

Reduction JSIntrinsicLowering::ReduceAsyncGeneratorResolve(Node* node) {
  return Change(
      node, Builtins::CallableFor(isolate(), Builtin::kAsyncGeneratorResolve),
      0);
}

Reduction JSIntrinsicLowering::ReduceAsyncGeneratorYieldWithAwait(Node* node) {
  return Change(
      node,
      Builtins::CallableFor(isolate(), Builtin::kAsyncGeneratorYieldWithAwait),
      0);
}

Reduction JSIntrinsicLowering::ReduceGeneratorGetResumeMode(Node* node) {
  Node* const generator = NodeProperties::GetValueInput(node, 0);
  Node* const effect = NodeProperties::GetEffectInput(node);
  Node* const control = NodeProperties::GetControlInput(node);
  Operator const* const op =
      simplified()->LoadField(AccessBuilder::ForJSGeneratorObjectResumeMode());

  return Change(node, op, generator, effect, control);
}

Reduction JSIntrinsicLowering::ReduceIsInstanceType(
    Node* node, InstanceType instance_type) {
  // if (%_IsSmi(value)) {
  //   return false;
  // } else {
  //   return %_GetInstanceType(%_GetMap(value)) == instance_type;
  // }
  Node* value = NodeProperties::GetValueInput(node, 0);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  Node* check = graph()->NewNode(simplified()->ObjectIsSmi(), value);
  Node* branch = graph()->NewNode(common()->Branch(), check, control);

  Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
  Node* etrue = effect;
  Node* vtrue = jsgraph()->FalseConstant();

  Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
  Node* efalse = effect;
  Node* map = efalse =
      graph()->NewNode(simplified()->LoadField(AccessBuilder::ForMap()), value,
                       efalse, if_false);
  Node* map_instance_type = efalse = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForMapInstanceType()), map, efalse,
      if_false);
  Node* vfalse =
      graph()->NewNode(simplified()->NumberEqual(), map_instance_type,
                       jsgraph()->ConstantNoHole(instance_type));

  Node* merge = graph()->NewNode(common()->Merge(2), if_true, if_false);

  // Replace all effect uses of {node} with the {ephi}.
  Node* ephi = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, merge);
  ReplaceWithValue(node, node, ephi, merge);

  // Turn the {node} into a Phi.
  return Change(node, common()->Phi(MachineRepresentation::kTagged, 2), vtrue,
                vfalse, merge);
}

Reduction JSIntrinsicLowering::ReduceIsJSReceiver(Node* node) {
  return Change(node, simplified()->ObjectIsReceiver());
}

Reduction JSIntrinsicLowering::ReduceTurbofanStaticAssert(Node* node) {
  if (v8_flags.always_turbofan) {
    // Ignore static asserts, as we most likely won't have enough information
    RelaxEffectsAndControls(node);
  } else {
    Node* value = NodeProperties::GetValueInput(node, 0);
    Node* effect = NodeProperties::GetEffectInput(node);
    Node* assert = graph()->NewNode(
        common()->StaticAssert("%TurbofanStaticAssert"), value, effect);
    ReplaceWithValue(node, node, assert, nullptr);
  }
  return Changed(jsgraph_->UndefinedConstant());
}

Reduction JSIntrinsicLowering::ReduceVerifyType(Node* node) {
  Node* value = NodeProperties::GetValueInput(node, 0);
  Node* effect = NodeProperties::GetEffectInput(node);
  effect = graph()->NewNode(simplified()->VerifyType(), value, effect);
  ReplaceWithValue(node, value, effect);
  return Changed(effect);
}

Reduction JSIntrinsicLowering::ReduceCheckTurboshaftTypeOf(Node* node) {
  Node* value = node->InputAt(0);
  if (!v8_flags.turboshaft) {
    RelaxEffectsAndControls(node);
    ReplaceWithValue(node, value);
    return Changed(value);
  }

  Node* pattern = node->InputAt(1);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  Node* check = graph()->NewNode(simplified()->CheckTurboshaftTypeOf(), value,
                                 pattern, effect, control);
  ReplaceWithValue(node, value, check);
  return Changed(value);
}

Reduction JSIntrinsicLowering::ReduceIsBeingInterpreted(Node* node) {
  RelaxEffectsAndControls(node);
  return Changed(jsgraph_->FalseConstant());
}

Reduction JSIntrinsicLowering::Change(Node* node, const Operator* op) {
  // Replace all effect uses of {node} with the effect dependency.
  RelaxEffectsAndControls(node);
  // Remove the inputs corresponding to context, effect and control.
  NodeProperties::RemoveNonValueInputs(node);
  // Finally update the operator to the new one.
  NodeProperties::ChangeOp(node, op);
  return Changed(node);
}

Reduction JSIntrinsicLowering::ReduceToLength(Node* node) {
  NodeProperties::ChangeOp(node, javascript()->ToLength());
  return Changed(node);
}

Reduction JSIntrinsicLowering::ReduceToObject(Node* node) {
  NodeProperties::ChangeOp(node, javascript()->ToObject());
  return Changed(node);
}

Reduction JSIntrinsicLowering::ReduceToString(Node* node) {
  // ToString is unnecessary if the input is a string.
  HeapObjectMatcher m(NodeProperties::GetValueInput(node, 0));
  if (m.HasResolvedValue() && m.Ref(broker()).IsString()) {
    ReplaceWithValue(node, m.node());
    return Replace(m.node());
  }
  NodeProperties::ChangeOp(node, javascript()->ToString());
  return Changed(node);
}

Reduction JSIntrinsicLowering::ReduceCall(Node* node) {
  int const arity =
      static_cast<int>(CallRuntimeParametersOf(node->op()).arity());
  static constexpr int kTargetAndReceiver = 2;
  static_assert(JSCallNode::kFeedbackVectorIsLastInput);
  Node* feedback = jsgraph()->UndefinedConstant();
  node->InsertInput(graph()->zone(), arity, feedback);
  NodeProperties::ChangeOp(
      node,
      javascript()->Call(JSCallNode::ArityForArgc(arity - kTargetAndReceiver)));
  return Changed(node);
}

Reduction JSIntrinsicLowering::ReduceIncBlockCounter(Node* node) {
  DCHECK(!Linkage::NeedsFrameStateInput(Runtime::kIncBlockCounter));
  DCHECK(!Linkage::NeedsFrameStateInput(Runtime::kInlineIncBlockCounter));
  return Change(node,
                Builtins::CallableFor(isolate(), Builtin::kIncBlockCounter), 0,
                kDoesNotNeedFrameState);
}

Reduction JSIntrinsicLowering::ReduceGetImportMetaObject(Node* node) {
  NodeProperties::ChangeOp(node, javascript()->GetImportMeta());
  return Changed(node);
}

Reduction JSIntrinsicLowering::Change(Node* node, const Operator* op, Node* a,
                                      Node* b) {
  RelaxControls(node);
  node->ReplaceInput(0, a);
  node->ReplaceInput(1, b);
  node->TrimInputCount(2);
  NodeProperties::ChangeOp(node, op);
  return Changed(node);
}

Reduction JSIntrinsicLowering::Change(Node* node, const Operator* op, Node* a,
                                      Node* b, Node* c) {
  RelaxControls(node);
  node->ReplaceInput(0, a);
  node->ReplaceInput(1, b);
  node->ReplaceInput(2, c);
  node->TrimInputCount(3);
  NodeProperties::ChangeOp(node, op);
  return Changed(node);
}

Reduction JSIntrinsicLowering::Change(Node* node, const Operator* op, Node* a,
                                      Node* b, Node* c, Node* d) {
  RelaxControls(node);
  node->ReplaceInput(0, a);
  node->ReplaceInput(1, b);
  node->ReplaceInput(2, c);
  node->ReplaceInput(3, d);
  node->TrimInputCount(4);
  NodeProperties::ChangeOp(node, op);
  return Changed(node);
}

Reduction JSIntrinsicLowering::Change(Node* node, Callable const& callable,
                                      int stack_parameter_count,
                                      enum FrameStateFlag frame_state_flag) {
  CallDescriptor::Flags flags = frame_state_flag == kNeedsFrameState
                                    ? CallDescriptor::kNeedsFrameState
                                    : CallDescriptor::kNoFlags;
  auto call_descriptor = Linkage::GetStubCallDescriptor(
      graph()->zone(), callable.descriptor(), stack_parameter_count, flags,
      node->op()->properties());
  node->InsertInput(graph()->zone(), 0,
                    jsgraph()->HeapConstantNoHole(callable.code()));
  NodeProperties::ChangeOp(node, common()->Call(call_descriptor));
  return Changed(node);
}

Graph* JSIntrinsicLowering::graph() const { return jsgraph()->graph(); }

Isolate* JSIntrinsicLowering::isolate() const { return jsgraph()->isolate(); }

CommonOperatorBuilder* JSIntrinsicLowering::common() const {
  return jsgraph()->common();
}

JSOperatorBuilder* JSIntrinsicLowering::javascript() const {
  return jsgraph_->javascript();
}

SimplifiedOperatorBuilder* JSIntrinsicLowering::simplified() const {
  return jsgraph()->simplified();
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```