Response: Let's break down the thought process to analyze the C++ code and generate the summary and JavaScript example.

1. **Understanding the Request:** The core request is to understand the functionality of the given C++ file (`js-context-specialization.cc`) and illustrate its relation to JavaScript using an example.

2. **Initial Code Scan - Identifying Key Elements:**  I'll first quickly scan the code, looking for keywords and patterns that give clues about its purpose. I see:
    * `#include`: Standard C++ includes, suggesting this is part of a larger system.
    * `namespace v8::internal::compiler`:  This clearly indicates this code is part of the V8 JavaScript engine's compiler.
    * `class JSContextSpecialization`: This is the central class we need to understand.
    * `Reduction Reduce(Node* node)`: This is the main entry point for the specialization logic, operating on a graph node.
    * `IrOpcode::k...`:  These are opcodes related to different JavaScript operations. Specifically, I see things like `kJSLoadContext`, `kJSStoreContext`, `kJSLoadScriptContext`, `kJSStoreScriptContext`, `kJSGetImportMeta`, and `kParameter`. This strongly suggests the file deals with how the compiler handles accessing and manipulating JavaScript's *context*.
    * `ContextAccess`: This struct or class likely holds information about how a context is being accessed (depth, index, immutability).
    * `JSGraph`, `JSHeapBroker`: These are core compiler components for representing the program's structure and accessing the JavaScript heap.
    * `ConstantNoHole`:  This function likely creates a node representing a constant value.
    * `DependOnScriptContextSlotProperty`: This suggests the code is trying to optimize by understanding the properties of context variables.
    * `OuterContext`:  This likely represents the enclosing context of a function.

3. **Focusing on the `Reduce` Method:** The `Reduce` method is the central point where the specialization logic is applied. The `switch` statement based on `node->opcode()` tells me that this class handles different kinds of context-related operations.

4. **Analyzing Individual `Reduce...` Methods:** I will now go through each of the `Reduce...` methods to understand their specific purpose:
    * **`ReduceParameter`:**  Handles function parameters, especially the `closure` (the function itself). It tries to constant-fold the function if it's known.
    * **`ReduceJSLoadContext`:**  This looks like the core of context loading optimization. It tries to find the concrete context object and, if possible, the constant value stored in the context slot. It also handles immutable context variables.
    * **`ReduceJSLoadScriptContext`:**  Similar to `ReduceJSLoadContext`, but specifically for script-level contexts, with additional handling for constant, Smi (small integer), and mutable heap number properties.
    * **`ReduceJSStoreContext`:**  Handles storing values into context variables. It tries to find the concrete context.
    * **`ReduceJSStoreScriptContext`:** Similar to `ReduceJSStoreContext`, but for script-level contexts, with checks for immutability and specialized handling of Smis and mutable heap numbers.
    * **`ReduceJSGetImportMeta`:**  Handles access to `import.meta`, trying to resolve the module context and the `import.meta` object at compile time.

5. **Identifying the Core Functionality:** From the analysis of the `Reduce` methods, the central theme is **context specialization**. The compiler is trying to:
    * **Resolve context lookups at compile time:** If the context and the variable's value are known, replace the lookup with a constant.
    * **Optimize context access:** For mutable variables, potentially use more efficient load/store operations based on the variable's type (Smi, HeapNumber).
    * **Track dependencies:**  Use `DependOnScriptContextSlotProperty` to ensure optimizations remain valid.

6. **Considering the "Why":** Why is this important?  Accessing context variables can be relatively expensive. By specializing these operations, the compiler can generate more efficient machine code. Constant folding is a major optimization, and knowing variable types allows for faster access.

7. **Formulating the Summary:** Now I can formulate a concise summary based on my understanding:  The file implements a compiler optimization phase that specializes operations related to accessing and modifying JavaScript's context (scope). It attempts to resolve context variable lookups at compile time, replacing them with constants if possible. It also optimizes access to script-level context variables based on their mutability and type.

8. **Creating the JavaScript Example:** To illustrate the functionality, I need a JavaScript example that showcases how context and scope work, and where the compiler optimizations would be relevant. A simple function accessing a variable from an outer scope is a good starting point.

9. **Connecting the C++ to the JavaScript:**  I need to explain *how* the C++ code relates to the JavaScript. This involves connecting the `JSLoadContext`, `JSStoreContext`, etc., opcodes to the underlying mechanisms of JavaScript's scope resolution. For example, accessing a variable declared in an outer function's scope translates to a `JSLoadContext` operation in the compiler's internal representation.

10. **Refining the Explanation and Example:** I will review the summary and example to ensure clarity and accuracy. I'll double-check if the JavaScript example effectively demonstrates the concept of context and scope. I'll make sure the explanation clearly links the C++ code to the JavaScript behavior. For instance, highlighting how the compiler might constant-fold a variable if its value is known at compile time. The `import.meta` example also fits nicely as it's explicitly handled in the C++ code.

This iterative process of code scanning, detailed analysis, and connecting the implementation to the language semantics allows for a comprehensive understanding and the creation of a relevant example.
这个C++源代码文件 `js-context-specialization.cc` 是 V8 JavaScript 引擎编译器中的一个组件，它的主要功能是**对 JavaScript 代码中的上下文（Context）相关的操作进行特化和优化**。

更具体地说，这个文件中的 `JSContextSpecialization` 类负责在编译过程中分析和转换与上下文相关的节点（Nodes），例如：

* **加载上下文变量 (`JSLoadContext`, `JSLoadScriptContext`)**:  尝试在编译时确定上下文变量的值，并将其替换为常量，从而避免运行时的查找操作。
* **存储上下文变量 (`JSStoreContext`, `JSStoreScriptContext`)**:  对存储操作进行优化，例如，如果知道变量是常量，则可以添加断言来确保不会被修改。
* **访问函数参数 (`Parameter`)**:  对于表示函数自身的参数，尝试将其替换为常量。
* **获取 `import.meta` 对象 (`JSGetImportMeta`)**:  尝试在编译时解析 `import.meta` 对象。

**核心思想是：**  通过在编译时尽可能多地了解上下文变量的信息（例如，它的值是否是常量，它存储在哪个上下文中），编译器可以生成更高效的机器代码。

**与 JavaScript 功能的关系及举例说明：**

JavaScript 中的作用域和闭包机制依赖于上下文。当 JavaScript 代码访问一个变量时，引擎需要在当前执行上下文以及其父级上下文中查找该变量的定义。  `js-context-specialization.cc` 做的就是优化这些查找和操作。

以下用 JavaScript 例子来说明其相关性：

**例子 1：常量折叠优化 (与 `ReduceJSLoadContext` 相关)**

```javascript
function outer() {
  const message = "Hello";
  function inner() {
    console.log(message); // 访问外部作用域的变量 message
  }
  return inner;
}

const myInnerFunction = outer();
myInnerFunction();
```

在这个例子中，`inner` 函数访问了 `outer` 函数作用域中的常量 `message`。  `JSContextSpecialization` 中的 `ReduceJSLoadContext` 可能会尝试在编译 `inner` 函数时，发现 `message` 是一个常量且其值已知为 `"Hello"`。  然后，编译器可以将 `console.log(message)` 优化为直接使用常量 `"Hello"`，避免了运行时的上下文查找。

在编译后的代码中，原本可能需要从上下文中加载 `message` 变量的操作会被替换为直接使用常量：

```assembly
// 优化前的可能指令 (示意)
load_context [scope_slot_of_message] ; 从上下文中加载 message
call console.log, message

// 优化后的可能指令 (示意)
load_constant "Hello"
call console.log, "Hello"
```

**例子 2：`import.meta` 优化 (与 `ReduceJSGetImportMeta` 相关)**

```javascript
// my_module.js
console.log(import.meta.url);
```

当 V8 编译 `my_module.js` 时，`JSContextSpecialization` 中的 `ReduceJSGetImportMeta` 会尝试解析 `import.meta`。如果编译器能够确定当前的模块 URL，它可以将 `import.meta.url` 替换为该 URL 的字符串常量。

**总结来说，`js-context-specialization.cc` 通过在编译时分析和优化 JavaScript 的上下文操作，提高了代码的执行效率。它关注的是 JavaScript 引擎内部的优化，对开发者来说是透明的，但对提升 JavaScript 性能至关重要。**

### 提示词
```
这是目录为v8/src/compiler/js-context-specialization.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/js-context-specialization.h"

#include "src/base/logging.h"
#include "src/compiler/access-builder.h"
#include "src/compiler/common-operator.h"
#include "src/compiler/compilation-dependencies.h"
#include "src/compiler/feedback-source.h"
#include "src/compiler/js-graph.h"
#include "src/compiler/js-heap-broker.h"
#include "src/compiler/js-operator.h"
#include "src/compiler/linkage.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/property-access-builder.h"
#include "src/compiler/simplified-operator.h"
#include "src/deoptimizer/deoptimize-reason.h"
#include "src/objects/contexts-inl.h"
#include "src/objects/property-cell.h"

namespace v8 {
namespace internal {
namespace compiler {

Reduction JSContextSpecialization::Reduce(Node* node) {
  switch (node->opcode()) {
    case IrOpcode::kParameter:
      return ReduceParameter(node);
    case IrOpcode::kJSLoadContext:
      return ReduceJSLoadContext(node);
    case IrOpcode::kJSLoadScriptContext:
      return ReduceJSLoadScriptContext(node);
    case IrOpcode::kJSStoreContext:
      return ReduceJSStoreContext(node);
    case IrOpcode::kJSStoreScriptContext:
      return ReduceJSStoreScriptContext(node);
    case IrOpcode::kJSGetImportMeta:
      return ReduceJSGetImportMeta(node);
    default:
      break;
  }
  return NoChange();
}

Reduction JSContextSpecialization::ReduceParameter(Node* node) {
  DCHECK_EQ(IrOpcode::kParameter, node->opcode());
  int const index = ParameterIndexOf(node->op());
  if (index == Linkage::kJSCallClosureParamIndex) {
    // Constant-fold the function parameter {node}.
    Handle<JSFunction> function;
    if (closure().ToHandle(&function)) {
      Node* value =
          jsgraph()->ConstantNoHole(MakeRef(broker_, function), broker());
      return Replace(value);
    }
  }
  return NoChange();
}

Reduction JSContextSpecialization::SimplifyJSLoadContext(Node* node,
                                                         Node* new_context,
                                                         size_t new_depth) {
  DCHECK_EQ(IrOpcode::kJSLoadContext, node->opcode());
  const ContextAccess& access = ContextAccessOf(node->op());
  DCHECK_LE(new_depth, access.depth());

  if (new_depth == access.depth() &&
      new_context == NodeProperties::GetContextInput(node)) {
    return NoChange();
  }

  const Operator* op = jsgraph_->javascript()->LoadContext(
      new_depth, access.index(), access.immutable());
  NodeProperties::ReplaceContextInput(node, new_context);
  NodeProperties::ChangeOp(node, op);
  return Changed(node);
}

Reduction JSContextSpecialization::SimplifyJSLoadScriptContext(
    Node* node, Node* new_context, size_t new_depth) {
  DCHECK_EQ(IrOpcode::kJSLoadScriptContext, node->opcode());
  const ContextAccess& access = ContextAccessOf(node->op());
  DCHECK_LE(new_depth, access.depth());

  if (new_depth == access.depth() &&
      new_context == NodeProperties::GetContextInput(node)) {
    return NoChange();
  }

  const Operator* op =
      jsgraph_->javascript()->LoadScriptContext(new_depth, access.index());
  NodeProperties::ReplaceContextInput(node, new_context);
  NodeProperties::ChangeOp(node, op);
  return Changed(node);
}

Reduction JSContextSpecialization::SimplifyJSStoreContext(Node* node,
                                                          Node* new_context,
                                                          size_t new_depth) {
  DCHECK_EQ(IrOpcode::kJSStoreContext, node->opcode());
  const ContextAccess& access = ContextAccessOf(node->op());
  DCHECK_LE(new_depth, access.depth());

  if (new_depth == access.depth() &&
      new_context == NodeProperties::GetContextInput(node)) {
    return NoChange();
  }

  const Operator* op =
      jsgraph_->javascript()->StoreContext(new_depth, access.index());
  NodeProperties::ReplaceContextInput(node, new_context);
  NodeProperties::ChangeOp(node, op);
  return Changed(node);
}

Reduction JSContextSpecialization::SimplifyJSStoreScriptContext(
    Node* node, Node* new_context, size_t new_depth) {
  DCHECK_EQ(IrOpcode::kJSStoreScriptContext, node->opcode());
  const ContextAccess& access = ContextAccessOf(node->op());
  DCHECK_LE(new_depth, access.depth());

  if (new_depth == access.depth() &&
      new_context == NodeProperties::GetContextInput(node)) {
    return NoChange();
  }

  const Operator* op =
      jsgraph_->javascript()->StoreScriptContext(new_depth, access.index());
  NodeProperties::ReplaceContextInput(node, new_context);
  NodeProperties::ChangeOp(node, op);
  return Changed(node);
}

namespace {

bool IsContextParameter(Node* node) {
  DCHECK_EQ(IrOpcode::kParameter, node->opcode());
  return ParameterIndexOf(node->op()) ==
         StartNode{NodeProperties::GetValueInput(node, 0)}
             .ContextParameterIndex_MaybeNonStandardLayout();
}

// Given a context {node} and the {distance} from that context to the target
// context (which we want to read from or store to), try to return a
// specialization context.  If successful, update {distance} to whatever
// distance remains from the specialization context.
OptionalContextRef GetSpecializationContext(JSHeapBroker* broker, Node* node,
                                            size_t* distance,
                                            Maybe<OuterContext> maybe_outer) {
  switch (node->opcode()) {
    case IrOpcode::kHeapConstant: {
      // TODO(jgruber,chromium:1209798): Using kAssumeMemoryFence works around
      // the fact that the graph stores handles (and not refs). The assumption
      // is that any handle inserted into the graph is safe to read; but we
      // don't preserve the reason why it is safe to read. Thus we must
      // over-approximate here and assume the existence of a memory fence. In
      // the future, we should consider having the graph store ObjectRefs or
      // ObjectData pointer instead, which would make new ref construction here
      // unnecessary.
      HeapObjectRef object =
          MakeRefAssumeMemoryFence(broker, HeapConstantOf(node->op()));
      if (object.IsContext()) return object.AsContext();
      break;
    }
    case IrOpcode::kParameter: {
      OuterContext outer;
      if (maybe_outer.To(&outer) && IsContextParameter(node) &&
          *distance >= outer.distance) {
        *distance -= outer.distance;
        return MakeRef(broker, outer.context);
      }
      break;
    }
    default:
      break;
  }
  return OptionalContextRef();
}

}  // anonymous namespace

Reduction JSContextSpecialization::ReduceJSLoadContext(Node* node) {
  DCHECK_EQ(IrOpcode::kJSLoadContext, node->opcode());

  const ContextAccess& access = ContextAccessOf(node->op());
  size_t depth = access.depth();

  // First walk up the context chain in the graph as far as possible.
  Node* context = NodeProperties::GetOuterContext(node, &depth);

  OptionalContextRef maybe_concrete =
      GetSpecializationContext(broker(), context, &depth, outer());
  if (!maybe_concrete.has_value()) {
    // We do not have a concrete context object, so we can only partially reduce
    // the load by folding-in the outer context node.
    return SimplifyJSLoadContext(node, context, depth);
  }

  // Now walk up the concrete context chain for the remaining depth.
  ContextRef concrete = maybe_concrete.value();
  concrete = concrete.previous(broker(), &depth);
  if (depth > 0) {
    TRACE_BROKER_MISSING(broker(), "previous value for context " << concrete);
    return SimplifyJSLoadContext(
        node, jsgraph()->ConstantNoHole(concrete, broker()), depth);
  }

  if (!access.immutable() &&
      !broker()->dependencies()->DependOnScriptContextSlotProperty(
          concrete, access.index(), ContextSidePropertyCell::kConst,
          broker())) {
    // We found the requested context object but since the context slot is
    // mutable we can only partially reduce the load.
    return SimplifyJSLoadContext(
        node, jsgraph()->ConstantNoHole(concrete, broker()), depth);
  }

  // This will hold the final value, if we can figure it out.
  OptionalObjectRef maybe_value;
  maybe_value = concrete.get(broker(), static_cast<int>(access.index()));

  if (!maybe_value.has_value()) {
    TRACE_BROKER_MISSING(broker(), "slot value " << access.index()
                                                 << " for context "
                                                 << concrete);
    return SimplifyJSLoadContext(
        node, jsgraph()->ConstantNoHole(concrete, broker()), depth);
  }

  // Even though the context slot is immutable, the context might have escaped
  // before the function to which it belongs has initialized the slot.
  // We must be conservative and check if the value in the slot is currently
  // the hole or undefined. Only if it is neither of these, can we be sure
  // that it won't change anymore.
  if (maybe_value->IsUndefined() || maybe_value->IsTheHole()) {
    return SimplifyJSLoadContext(
        node, jsgraph()->ConstantNoHole(concrete, broker()), depth);
  }

  // Success. The context load can be replaced with the constant.
  Node* constant = jsgraph_->ConstantNoHole(*maybe_value, broker());
  ReplaceWithValue(node, constant);
  return Replace(constant);
}

Reduction JSContextSpecialization::ReduceJSLoadScriptContext(Node* node) {
  DCHECK_EQ(IrOpcode::kJSLoadScriptContext, node->opcode());

  const ContextAccess& access = ContextAccessOf(node->op());
  DCHECK(!access.immutable());
  size_t depth = access.depth();

  // First walk up the context chain in the graph as far as possible.
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  Node* context = NodeProperties::GetOuterContext(node, &depth);

  OptionalContextRef maybe_concrete =
      GetSpecializationContext(broker(), context, &depth, outer());
  if (!maybe_concrete.has_value()) {
    // We do not have a concrete context object, so we can only partially reduce
    // the load by folding-in the outer context node.
    return SimplifyJSLoadScriptContext(node, context, depth);
  }

  // Now walk up the concrete context chain for the remaining depth.
  ContextRef concrete = maybe_concrete.value();
  concrete = concrete.previous(broker(), &depth);
  if (depth > 0) {
    TRACE_BROKER_MISSING(broker(), "previous value for context " << concrete);
    return SimplifyJSLoadScriptContext(
        node, jsgraph()->ConstantNoHole(concrete, broker()), depth);
  }

  DCHECK(concrete.object()->IsScriptContext());
  auto maybe_property =
      concrete.object()->GetScriptContextSideProperty(access.index());
  auto property =
      maybe_property ? maybe_property.value() : ContextSidePropertyCell::kOther;
  switch (property) {
    case ContextSidePropertyCell::kConst: {
      OptionalObjectRef maybe_value =
          concrete.get(broker(), static_cast<int>(access.index()));
      if (!maybe_value.has_value()) {
        TRACE_BROKER_MISSING(broker(), "slot value " << access.index()
                                                     << " for context "
                                                     << concrete);
        return SimplifyJSLoadScriptContext(
            node, jsgraph()->ConstantNoHole(concrete, broker()), depth);
      }
      broker()->dependencies()->DependOnScriptContextSlotProperty(
          concrete, access.index(), property, broker());
      Node* constant = jsgraph_->ConstantNoHole(*maybe_value, broker());
      ReplaceWithValue(node, constant, effect, control);
      return Changed(node);
    }
    case ContextSidePropertyCell::kSmi: {
      broker()->dependencies()->DependOnScriptContextSlotProperty(
          concrete, access.index(), property, broker());
      Node* load = effect = jsgraph_->graph()->NewNode(
          jsgraph_->simplified()->LoadField(
              AccessBuilder::ForContextSlotSmi(access.index())),
          jsgraph_->ConstantNoHole(concrete, broker()), effect, control);
      ReplaceWithValue(node, load, effect, control);
      return Changed(node);
    }
    case ContextSidePropertyCell::kMutableHeapNumber: {
      broker()->dependencies()->DependOnScriptContextSlotProperty(
          concrete, access.index(), property, broker());
      Node* heap_number = effect = jsgraph_->graph()->NewNode(
          jsgraph_->simplified()->LoadField(
              AccessBuilder::ForContextSlot(access.index())),
          jsgraph_->ConstantNoHole(concrete, broker()), effect, control);
      Node* double_load = effect =
          jsgraph_->graph()->NewNode(jsgraph_->simplified()->LoadField(
                                         AccessBuilder::ForHeapNumberValue()),
                                     heap_number, effect, control);
      ReplaceWithValue(node, double_load, effect, control);
      return Changed(node);
    }
    case ContextSidePropertyCell::kOther: {
      // Do a normal context load.
      Node* load = effect = jsgraph_->graph()->NewNode(
          jsgraph_->simplified()->LoadField(
              AccessBuilder::ForContextSlot(access.index())),
          jsgraph_->ConstantNoHole(concrete, broker()), effect, control);
      ReplaceWithValue(node, load, effect, control);
      return Changed(node);
    }
  }
}

Reduction JSContextSpecialization::ReduceJSStoreContext(Node* node) {
  DCHECK_EQ(IrOpcode::kJSStoreContext, node->opcode());

  const ContextAccess& access = ContextAccessOf(node->op());
  size_t depth = access.depth();

  // First walk up the context chain in the graph until we reduce the depth to 0
  // or hit a node that does not have a CreateXYZContext operator.
  Node* context = NodeProperties::GetOuterContext(node, &depth);

  OptionalContextRef maybe_concrete =
      GetSpecializationContext(broker(), context, &depth, outer());
  if (!maybe_concrete.has_value()) {
    // We do not have a concrete context object, so we can only partially reduce
    // the load by folding-in the outer context node.
    return SimplifyJSStoreContext(node, context, depth);
  }

  // Now walk up the concrete context chain for the remaining depth.
  ContextRef concrete = maybe_concrete.value();
  concrete = concrete.previous(broker(), &depth);
  if (depth > 0) {
    TRACE_BROKER_MISSING(broker(), "previous value for context " << concrete);
    return SimplifyJSStoreContext(
        node, jsgraph()->ConstantNoHole(concrete, broker()), depth);
  }

  return SimplifyJSStoreContext(
      node, jsgraph()->ConstantNoHole(concrete, broker()), depth);
}

Reduction JSContextSpecialization::ReduceJSStoreScriptContext(Node* node) {
  DCHECK(v8_flags.const_tracking_let);
  DCHECK_EQ(IrOpcode::kJSStoreScriptContext, node->opcode());

  const ContextAccess& access = ContextAccessOf(node->op());
  size_t depth = access.depth();

  // First walk up the context chain in the graph until we reduce the depth to 0
  // or hit a node that does not have a CreateXYZContext operator.
  Node* context = NodeProperties::GetOuterContext(node, &depth);
  Node* value = NodeProperties::GetValueInput(node, 0);
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};

  OptionalContextRef maybe_concrete =
      GetSpecializationContext(broker(), context, &depth, outer());
  if (!maybe_concrete.has_value()) {
    // We do not have a concrete context object, so we can only partially reduce
    // the load by folding-in the outer context node.
    return SimplifyJSStoreScriptContext(node, context, depth);
  }

  // Now walk up the concrete context chain for the remaining depth.
  ContextRef concrete = maybe_concrete.value();
  concrete = concrete.previous(broker(), &depth);
  if (depth > 0) {
    TRACE_BROKER_MISSING(broker(), "previous value for context " << concrete);
    return SimplifyJSStoreScriptContext(
        node, jsgraph()->ConstantNoHole(concrete, broker()), depth);
  }
  DCHECK(concrete.object()->IsScriptContext());
  auto maybe_property =
      concrete.object()->GetScriptContextSideProperty(access.index());
  if (!maybe_property) {
    return SimplifyJSStoreScriptContext(
        node, jsgraph()->ConstantNoHole(concrete, broker()), depth);
  }
  auto property = maybe_property.value();
  PropertyAccessBuilder access_builder(jsgraph(), broker());
  if (property == ContextSidePropertyCell::kConst) {
    compiler::OptionalObjectRef constant =
        concrete.get(broker(), static_cast<int>(access.index()));
    if (!constant.has_value() ||
        (constant->IsString() && !constant->IsInternalizedString())) {
      return SimplifyJSStoreScriptContext(
          node, jsgraph()->ConstantNoHole(concrete, broker()), depth);
    }
    broker()->dependencies()->DependOnScriptContextSlotProperty(
        concrete, access.index(), property, broker());
    access_builder.BuildCheckValue(value, &effect, control, *constant);
    ReplaceWithValue(node, effect, effect, control);
    return Changed(node);
  }

  if (!v8_flags.script_context_mutable_heap_number) {
    // Do a normal context store.
    Node* store = jsgraph()->graph()->NewNode(
        jsgraph()->simplified()->StoreField(
            AccessBuilder::ForContextSlot(access.index())),
        jsgraph()->ConstantNoHole(concrete, broker()), value, effect, control);
    ReplaceWithValue(node, store, store, control);
    return Changed(node);
  }

  switch (property) {
    case ContextSidePropertyCell::kConst:
      UNREACHABLE();
    case ContextSidePropertyCell::kSmi: {
      broker()->dependencies()->DependOnScriptContextSlotProperty(
          concrete, access.index(), property, broker());
      Node* smi_value = access_builder.BuildCheckSmi(value, &effect, control);
      Node* smi_store = jsgraph()->graph()->NewNode(
          jsgraph()->simplified()->StoreField(
              AccessBuilder::ForContextSlotSmi(access.index())),
          jsgraph()->ConstantNoHole(concrete, broker()), smi_value, effect,
          control);
      ReplaceWithValue(node, smi_store, smi_store, control);
      return Changed(node);
    }
    case ContextSidePropertyCell::kMutableHeapNumber: {
      broker()->dependencies()->DependOnScriptContextSlotProperty(
          concrete, access.index(), property, broker());
      Node* mutable_heap_number = effect = jsgraph()->graph()->NewNode(
          jsgraph()->simplified()->LoadField(
              AccessBuilder::ForContextSlot(access.index())),
          jsgraph()->ConstantNoHole(concrete, broker()), effect, control);
      Node* input_number =
          access_builder.BuildCheckNumber(value, &effect, control);
      Node* double_store = jsgraph()->graph()->NewNode(
          jsgraph()->simplified()->StoreField(
              AccessBuilder::ForHeapNumberValue()),
          mutable_heap_number, input_number, effect, control);
      ReplaceWithValue(node, double_store, double_store, control);
      return Changed(node);
    }
    case ContextSidePropertyCell::kOther: {
      // Do a normal context store.
      Node* store = jsgraph()->graph()->NewNode(
          jsgraph()->simplified()->StoreField(
              AccessBuilder::ForContextSlot(access.index())),
          jsgraph()->ConstantNoHole(concrete, broker()), value, effect,
          control);
      ReplaceWithValue(node, store, store, control);
      return Changed(node);
    }
  }
}

OptionalContextRef GetModuleContext(JSHeapBroker* broker, Node* node,
                                    Maybe<OuterContext> maybe_context) {
  size_t depth = std::numeric_limits<size_t>::max();
  Node* context = NodeProperties::GetOuterContext(node, &depth);

  auto find_context = [broker](ContextRef c) {
    while (c.map(broker).instance_type() != MODULE_CONTEXT_TYPE) {
      size_t depth = 1;
      c = c.previous(broker, &depth);
      CHECK_EQ(depth, 0);
    }
    return c;
  };

  switch (context->opcode()) {
    case IrOpcode::kHeapConstant: {
      // TODO(jgruber,chromium:1209798): Using kAssumeMemoryFence works around
      // the fact that the graph stores handles (and not refs). The assumption
      // is that any handle inserted into the graph is safe to read; but we
      // don't preserve the reason why it is safe to read. Thus we must
      // over-approximate here and assume the existence of a memory fence. In
      // the future, we should consider having the graph store ObjectRefs or
      // ObjectData pointer instead, which would make new ref construction here
      // unnecessary.
      HeapObjectRef object =
          MakeRefAssumeMemoryFence(broker, HeapConstantOf(context->op()));
      if (object.IsContext()) {
        return find_context(object.AsContext());
      }
      break;
    }
    case IrOpcode::kParameter: {
      OuterContext outer;
      if (maybe_context.To(&outer) && IsContextParameter(context)) {
        return find_context(MakeRef(broker, outer.context));
      }
      break;
    }
    default:
      break;
  }

  return OptionalContextRef();
}

Reduction JSContextSpecialization::ReduceJSGetImportMeta(Node* node) {
  OptionalContextRef maybe_context = GetModuleContext(broker(), node, outer());
  if (!maybe_context.has_value()) return NoChange();

  ContextRef context = maybe_context.value();
  OptionalObjectRef module = context.get(broker(), Context::EXTENSION_INDEX);
  if (!module.has_value()) return NoChange();
  OptionalObjectRef import_meta =
      module->AsSourceTextModule().import_meta(broker());
  if (!import_meta.has_value()) return NoChange();
  if (!import_meta->IsJSObject()) {
    DCHECK(import_meta->IsTheHole());
    // The import.meta object has not yet been created. Let JSGenericLowering
    // replace the operator with a runtime call.
    return NoChange();
  }

  Node* import_meta_const = jsgraph()->ConstantNoHole(*import_meta, broker());
  ReplaceWithValue(node, import_meta_const);
  return Changed(import_meta_const);
}

Isolate* JSContextSpecialization::isolate() const {
  return jsgraph()->isolate();
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```