Response:
Let's break down the thought process for analyzing this V8 source code.

1. **Initial Scan for Obvious Information:**  The first step is to read the initial comments and the file path. We see:
    * File path: `v8/src/compiler/js-context-specialization.cc`
    * Copyright and license information.
    * Inclusion of various header files from the `src/compiler` and `src/objects` directories.

2. **Identify the Core Class:**  The core of the file seems to be the `JSContextSpecialization` class. This suggests the file is about optimizing or specializing operations related to JavaScript contexts.

3. **Analyze the `Reduce` Method:** The `Reduce` method is the entry point for the specialization process. The `switch` statement inside it tells us the specific node types this pass handles:
    * `kParameter`
    * `kJSLoadContext`
    * `kJSLoadScriptContext`
    * `kJSStoreContext`
    * `kJSStoreScriptContext`
    * `kJSGetImportMeta`

    This immediately gives us a high-level understanding of the file's purpose: to optimize these specific JavaScript context-related operations within the compiler.

4. **Examine Individual `Reduce*` Methods:**  Next, we need to understand what each `Reduce*` method does.

    * **`ReduceParameter`:** This seems to handle function parameters, specifically checking for the `kJSCallClosureParamIndex`. If the closure (the function being called) is known, it replaces the parameter node with a constant. This is a classic constant folding optimization.

    * **`ReduceJSLoadContext` and `ReduceJSLoadScriptContext`:** These are about loading values from a JavaScript context. The code tries to walk up the context chain, both within the graph and through concrete context objects, to find the value being loaded. It handles immutable and mutable context slots, and also considers the possibility of the value being uninitialized (hole or undefined).

    * **`ReduceJSStoreContext` and `ReduceJSStoreScriptContext`:** These deal with storing values into a JavaScript context. Similar to the load operations, they try to resolve the target context. The `ReduceJSStoreScriptContext` method has additional logic related to constant tracking and different types of script context properties (Smi, MutableHeapNumber).

    * **`ReduceJSGetImportMeta`:** This focuses on the `import.meta` object. It tries to find the module context and then retrieve the `import.meta` object from the module.

5. **Look for Helper Functions and Data Structures:** The file also contains helper functions and data structures:

    * **`SimplifyJSLoadContext`, `SimplifyJSLoadScriptContext`, `SimplifyJSStoreContext`, `SimplifyJSStoreScriptContext`:** These seem to be helper functions to modify the operation of a node, primarily by changing its context input and the operator itself. They are called when a full reduction isn't possible.

    * **`IsContextParameter`:** A utility to check if a `Parameter` node represents the context.

    * **`GetSpecializationContext`:**  A key function to attempt to resolve a context chain and find a concrete context object.

    * **`GetModuleContext`:** Specifically targets finding the module context in the context chain.

    * **`ContextAccess`:** This structure (from `js-operator.h`) holds information about the context access (depth, index, immutability).

6. **Connect to JavaScript Concepts:**  As we analyze the code, we need to relate it back to JavaScript concepts:

    * **Contexts:**  JavaScript uses lexical scoping, and contexts store variables accessible in a particular scope.
    * **Closures:** Functions "close over" the variables in their surrounding scope.
    * **`import.meta`:**  Provides metadata about a JavaScript module.
    * **`const` and `let`:**  Block-scoped variables, with `const` being immutable after initialization.
    * **Scope Chain:** The chain of contexts searched to resolve variable names.

7. **Consider Potential Torque Implementation:** The prompt specifically asks about `.tq` files. While this file is `.cc`, it's important to remember that V8 uses Torque, and some similar logic *might* be implemented in Torque for other parts of the system. However, this specific file isn't Torque.

8. **Identify Optimization Strategies:**  From the analysis, we can identify several optimization strategies being used:

    * **Constant Folding:** Replacing operations with their constant results when possible (e.g., `ReduceParameter`, `ReduceJSLoadContext`).
    * **Context Chain Optimization:**  Trying to resolve context accesses statically, avoiding dynamic lookups.
    * **Specialization:**  Tailoring the generated code based on the properties of the context (e.g., immutability, type of script context variable).
    * **Dependency Tracking:** Using `CompilationDependencies` to ensure optimizations remain valid (e.g., when a context slot is immutable).

9. **Think About Potential Errors and Examples:** Finally, consider common programming errors and how this code interacts with them:

    * **Accessing Undeclared Variables:**  While this code doesn't directly *cause* this error, its optimizations rely on the structure of the scope chain, which is defined by how variables are declared.
    * **Modifying `const` Variables:** The checks for immutability in `ReduceJSStoreScriptContext` are directly related to this error.
    * **Early Access to `let` and `const` (Temporal Dead Zone):**  The handling of uninitialized values (hole/undefined) in context slots is relevant here.

10. **Structure the Answer:** Organize the findings into a clear and structured answer, covering the requested points: functionality, Torque relevance, JavaScript examples, code logic examples, and common errors. Use clear headings and bullet points for readability.

By following these steps, we can systematically analyze the V8 source code and understand its purpose and implications. The key is to move from the general to the specific, identify the core components, and connect the code back to the underlying JavaScript concepts.
This C++ source code file, `v8/src/compiler/js-context-specialization.cc`, is part of the V8 JavaScript engine's optimizing compiler. Its primary function is **to perform optimizations related to JavaScript contexts during the compilation process.**  It analyzes and potentially simplifies operations that access or manipulate the current JavaScript execution context.

Here's a breakdown of its functionalities:

**Core Functionality: Optimizing Context Operations**

The main goal of this code is to make context accesses more efficient. JavaScript uses a concept of "contexts" to manage variables and their scope. Accessing variables often involves traversing a chain of these contexts. This file implements optimizations to:

* **Constant Folding of Context Variables:** If the value of a variable in a specific context can be determined at compile time (e.g., it's a constant), the compiler can directly substitute that value, avoiding the need for a runtime lookup.
* **Simplifying Context Lookups:** By analyzing the context chain and the properties of context variables (like immutability), the compiler can potentially simplify the instructions needed to access a variable.
* **Specializing Context Accesses:**  Depending on the type and properties of the context and the variable being accessed, the compiler can generate more specialized and efficient code.

**Specific Operations Handled by `JSContextSpecialization::Reduce`:**

The `Reduce` method acts as a dispatcher, handling different types of context-related operations:

* **`IrOpcode::kParameter`:**  Handles function parameters. It tries to constant-fold the function itself if it's known.
* **`IrOpcode::kJSLoadContext`:**  Optimizes loading a value from a context variable. It attempts to resolve the context and potentially the value at compile time.
* **`IrOpcode::kJSLoadScriptContext`:** Similar to `kJSLoadContext` but specifically for script-level context variables. It considers properties like whether the variable is a constant, a Smi (small integer), or a mutable heap number.
* **`IrOpcode::kJSStoreContext`:** Optimizes storing a value into a context variable. It attempts to resolve the target context.
* **`IrOpcode::kJSStoreScriptContext`:** Similar to `kJSStoreContext` but specifically for script-level context variables. It includes checks related to constant tracking and different storage types.
* **`IrOpcode::kJSGetImportMeta`:** Optimizes access to the `import.meta` object within modules.

**Is it a Torque file?**

The code snippet you provided ends with `.cc`, which signifies a standard C++ source file in the V8 project. Therefore, **it is not a Torque file**. Torque files have the `.tq` extension.

**Relationship to JavaScript and Examples:**

This code directly impacts the performance of JavaScript code by optimizing how variables are accessed and manipulated. Here are some JavaScript examples illustrating the scenarios this code aims to optimize:

**Example 1: Constant Folding**

```javascript
function foo() {
  const x = 10;
  return x + 5;
}
```

In this case, `JSContextSpecialization` might be able to determine that `x` is a constant with the value `10`. It could then replace the `x` in `x + 5` with `10` at compile time, resulting in the optimized code directly calculating `15`. The `ReduceParameter` and `ReduceJSLoadContext` methods play a role here.

**Example 2: Optimizing Context Lookups (Scope Chain)**

```javascript
let globalVar = 20;

function outer() {
  let outerVar = 30;
  function inner() {
    return globalVar + outerVar;
  }
  return inner();
}

console.log(outer()); // Output: 50
```

When the `inner` function tries to access `globalVar` and `outerVar`, the JavaScript engine needs to traverse the scope chain. `JSContextSpecialization` can analyze this chain during compilation. If the compiler can determine the locations of these variables, it can generate more direct access instructions, avoiding a full runtime scope lookup. Methods like `ReduceJSLoadContext` are crucial for this optimization.

**Example 3: Optimizing `const` Variables**

```javascript
function calculateArea(radius) {
  const PI = 3.14159;
  return PI * radius * radius;
}
```

Because `PI` is declared as `const`, its value is immutable. `JSContextSpecialization` (especially `ReduceJSLoadScriptContext` when dealing with script-level constants) can leverage this immutability to perform more aggressive optimizations, knowing the value won't change.

**Code Logic Reasoning (Assumption and Output):**

Let's consider the `ReduceJSLoadContext` function with a hypothetical scenario:

**Hypothetical Input:**

* `node`: A `JSLoadContext` node representing the operation of accessing a variable `y` in a context two levels up in the scope chain.
* The context two levels up holds a constant variable `y` with the value `42`.

**Assumptions:**

* The compiler has successfully analyzed the context chain leading to the context where `y` is defined.
* The variable `y` is marked as immutable in that context.

**Expected Output:**

The `ReduceJSLoadContext` function would:

1. **Walk up the context chain:**  Determine that the target context is indeed two levels up.
2. **Access the concrete context:** Obtain a reference to the context object where `y` is stored.
3. **Check immutability:** Verify that `y` is immutable.
4. **Retrieve the constant value:** Fetch the value `42` associated with `y`.
5. **Replace the node:** Replace the original `JSLoadContext` node with a new node representing the constant value `42`.

Essentially, the compiler transforms a potentially expensive context lookup into a direct use of the constant value.

**Common Programming Errors and How This Code Relates:**

While `JSContextSpecialization` optimizes existing code, it doesn't directly prevent common programming errors. However, its optimizations are based on understanding the semantics of JavaScript, including how scope and variable declarations work.

Here are some connections:

* **Accessing undeclared variables:**  If a program tries to access an undeclared variable, the JavaScript runtime will throw an error. `JSContextSpecialization` won't optimize this away; the error will still occur. However, the *absence* of a variable in the context chain is something the compiler considers.

* **Modifying `const` variables:**  JavaScript throws a `TypeError` if you try to reassign a `const` variable. The `ReduceJSStoreScriptContext` method has logic specifically to handle `const` variables in script contexts. It uses `DependOnScriptContextSlotProperty` to ensure that if it assumes a variable is constant, it can invalidate that assumption if the underlying property somehow changes (though this shouldn't happen with correctly written `const`). This ensures the optimization remains valid.

* **Closures and variable capture:**  `JSContextSpecialization`'s ability to analyze context chains is crucial for optimizing code involving closures. It needs to understand how variables from outer scopes are accessed by inner functions. Misunderstanding closures can lead to unexpected behavior, but the compiler aims to optimize the *correct* execution of closures.

**In summary, `v8/src/compiler/js-context-specialization.cc` is a vital component of V8's optimizing compiler, focusing on improving the performance of JavaScript code by specializing and simplifying operations related to JavaScript contexts. It leverages knowledge of JavaScript's scoping rules and variable properties to make code execution more efficient.**

### 提示词
```
这是目录为v8/src/compiler/js-context-specialization.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-context-specialization.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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