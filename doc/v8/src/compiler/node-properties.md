Response: Let's break down the thought process for summarizing the C++ code and providing a JavaScript example.

1. **Understand the Goal:** The request asks for a summary of the C++ file's functionality and a JavaScript example illustrating its connection to JavaScript (if any).

2. **Initial Scan and Keyword Identification:**  Quickly read through the code, looking for recurring terms and patterns. Keywords like `Node`, `Edge`, `Input`, `Output`, `Control`, `Effect`, `Value`, `FrameState`, `Operator`, `IrOpcode`, `Map`, and helper functions like `IsValueEdge`, `ReplaceValueInput`, etc., stand out. The namespace `v8::internal::compiler` is also a significant clue about the context.

3. **Identify the Core Abstraction:** The frequent mention of `Node` and different types of edges (`Value`, `Control`, `Effect`, etc.) suggests a graph-like representation. The file seems to provide tools for working with nodes and their connections.

4. **Group Functionality by Purpose:**  Start grouping the static methods based on their actions.

    * **Edge Classification:**  Functions like `IsValueEdge`, `IsContextEdge`, `IsControlEdge`, etc., are clearly about categorizing connections between nodes.

    * **Input Manipulation:**  Functions like `ReplaceValueInput`, `ReplaceContextInput`, `RemoveValueInputs`, etc., focus on modifying the input connections of nodes.

    * **Control Flow Analysis:** Functions like `IsExceptionalCall`, `FindSuccessfulControlProjection`, `MergeControlToEnd`, and `RemoveControlFromEnd` deal with the control flow aspects of the graph. The `IfSuccess` and `IfException` opcodes are indicators of conditional execution.

    * **Node Modification:** `ChangeOp` and `ChangeOpUnchecked` are straightforward ways to alter the type of an existing node.

    * **Finding Related Nodes:** `FindFrameStateBefore`, `FindProjection`, `CollectValueProjections`, and `CollectControlProjections` help locate specific related nodes based on criteria.

    * **Type and Property Inference:**  Functions like `GetProjectionType`, `InferMapsUnsafe`, `CanBePrimitive`, and `CanBeNullOrUndefined` are about understanding the type information associated with nodes.

    * **Node Comparison:** `IsSame`, `HashCode`, and `Equals` are utility functions for comparing nodes.

5. **Formulate a High-Level Summary:** Based on the grouped functionalities, draft a concise summary. Emphasize the core purpose: providing utilities for working with the intermediate representation (IR) graph in the V8 compiler.

6. **Identify the Connection to JavaScript:** The presence of terms like "Map," "JSCreate," "Promise," and function names prefixed with "JS" (like `JSCreate`, `JSCreateArray`) strongly suggests a connection to JavaScript semantics and the compilation process of JavaScript code. The `InferMapsUnsafe` function explicitly deals with JavaScript object maps.

7. **Develop a JavaScript Example:**  Think about a simple JavaScript scenario that involves concepts the C++ code manipulates. Creating an object and accessing its properties is a fundamental operation. Consider how the V8 compiler might represent this internally. The example should ideally touch upon:

    * Object creation:  Connects to `JSCreate`.
    * Property access: Implies graph nodes for loading properties.
    * Potential type checks/optimizations: Relates to the `InferMapsUnsafe` functionality.

    A basic object literal creation and property access (`const obj = { a: 1 }; const x = obj.a;`) serves as a good starting point.

8. **Explain the Connection in the Example:**  Clearly articulate how the JavaScript example relates to the C++ code. Focus on:

    * How the JavaScript code is translated into an IR graph.
    * How `NodeProperties` helps manage the nodes in that graph.
    * Specifically mention the connection between `JSCreate` and object creation, and how `InferMapsUnsafe` might be used to optimize property access based on object structure (maps).

9. **Refine and Organize:** Review the summary and the example for clarity, accuracy, and conciseness. Ensure logical flow and use appropriate terminology. Add a concluding statement to reinforce the core message.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  "This file just manipulates some kind of internal data structure."  **Correction:** Recognize the "compiler" namespace and the specific terminology (`Node`, `Edge`, `Opcode`) point to an Intermediate Representation (IR) graph used in compilation.

* **Initial example idea:**  Something very complex involving prototypes. **Correction:**  Start with a simpler example like basic object creation and property access to make the connection clearer. The core concepts of node manipulation and type inference apply even to simple cases.

* **Vague connection:** Just saying "it's related to JavaScript compilation." **Correction:** Be specific about *how* it's related – by manipulating the IR graph that represents JavaScript code during compilation and optimization. Mention specific function names that hint at JavaScript operations.

By following these steps, combining analysis of the code structure with knowledge of compiler concepts, and iteratively refining the explanation and example, a comprehensive and accurate answer can be constructed.
这个C++源代码文件 `node-properties.cc` 是 V8 JavaScript 引擎中 **Turbofan 优化编译器** 的一部分。它的主要功能是提供了一组**静态工具函数**，用于**查询和操作**编译器内部表示（IR - Intermediate Representation）中的**节点 (Node)** 的各种属性和关系。

简单来说，这个文件就像是 V8 编译器内部 IR 图的 "瑞士军刀"，提供了一系列便捷的方法来处理图中的节点及其连接方式。

以下是其主要功能的归纳：

**1. 识别节点之间的连接类型 (Edge Types):**

* `IsValueEdge`: 判断一个边是否是**值边 (Value Edge)**，表示传递数据的连接。
* `IsContextEdge`: 判断一个边是否是**上下文边 (Context Edge)**，表示传递执行上下文的连接。
* `IsFrameStateEdge`: 判断一个边是否是**帧状态边 (Frame State Edge)**，表示传递当前函数调用栈状态的连接。
* `IsEffectEdge`: 判断一个边是否是**效果边 (Effect Edge)**，表示操作执行顺序和副作用的连接。
* `IsControlEdge`: 判断一个边是否是**控制边 (Control Edge)**，表示程序控制流的连接。

**2. 检查和查找控制流相关的节点:**

* `IsExceptionalCall`: 判断一个调用是否可能抛出异常，并返回异常处理节点。
* `FindSuccessfulControlProjection`: 查找一个操作成功执行后的控制流节点。

**3. 修改节点的输入连接:**

* `ReplaceValueInput`: 替换节点的某个值输入。
* `ReplaceValueInputs`: 替换节点的所有值输入。
* `ReplaceContextInput`: 替换节点的上下文输入。
* `ReplaceControlInput`: 替换节点的某个控制输入。
* `ReplaceEffectInput`: 替换节点的某个效果输入。
* `ReplaceFrameStateInput`: 替换节点的帧状态输入。
* `RemoveNonValueInputs`: 移除节点的所有非值输入。
* `RemoveValueInputs`: 移除节点的所有值输入。

**4. 操作控制流图:**

* `MergeControlToEnd`: 将一个控制流节点添加到图的末尾。
* `RemoveControlFromEnd`: 从图的末尾移除一个控制流节点。
* `ReplaceUses`: 替换一个节点的所有使用者 (uses)，可以分别指定用于值、效果和控制边的替换节点。

**5. 修改节点的操作符:**

* `ChangeOp`: 更改节点的操作符 (Operator)。
* `ChangeOpUnchecked`: 更改节点的操作符，但不进行校验。

**6. 查找与节点相关的其他节点:**

* `FindFrameStateBefore`: 查找某个节点之前的帧状态节点。
* `FindProjection`: 查找一个节点的某个投影 (Projection) 节点。
* `CollectValueProjections`: 收集一个节点的所有值投影节点。
* `CollectControlProjections`: 收集一个节点的所有控制投影节点。

**7. 获取节点的属性信息:**

* `GetProjectionType`: 获取投影节点的类型。

**8. 比较节点:**

* `IsSame`: 判断两个节点是否代表相同的计算结果 (考虑了 `CheckHeapObject` 节点)。
* `HashCode`: 计算节点的哈希值。
* `Equals`: 判断两个节点是否完全相同。

**9. 进行类型推断和分析:**

* `GetJSCreateMap`: 尝试获取 `JSCreate` 或 `JSCreateArray` 节点创建的对象的初始 Map (对象布局)。
* `InferMapsUnsafe`: 推断一个接收者 (receiver) 可能具有的 Map 集合。
* `NoObservableSideEffectBetween`: 判断两个效果节点之间是否存在可观察的副作用。
* `CanBePrimitive`: 判断一个节点的值是否可能是原始类型。
* `CanBeNullOrUndefined`: 判断一个节点的值是否可能是 null 或 undefined。
* `GetOuterContext`: 获取外层上下文节点。
* `GetTypeOrAny`: 获取节点的类型，如果节点没有类型信息则返回 Any 类型。
* `AllValueInputsAreTyped`: 判断节点的所有值输入是否都有类型信息。

**10. 其他辅助函数:**

* `IsInputRange`: 判断一个边的索引是否在给定的输入范围内。

**与 JavaScript 的关系和示例:**

`node-properties.cc` 文件中的功能直接服务于 V8 引擎编译和优化 JavaScript 代码的过程。Turbofan 编译器会将 JavaScript 代码转换为一个由节点组成的图结构，然后利用 `NodeProperties` 中提供的工具函数来分析和转换这个图，最终生成优化的机器码。

例如，当 JavaScript 代码中创建一个对象时，Turbofan 可能会创建一个 `JSCreate` 节点来表示这个操作。 `NodeProperties::GetJSCreateMap` 函数可以帮助编译器确定这个新创建的对象的初始布局 (Map)，从而进行更深层次的优化。

**JavaScript 示例:**

```javascript
function createAndAccessObject(flag) {
  const obj = { x: 10 };
  if (flag) {
    return obj.x;
  } else {
    return 0;
  }
}

createAndAccessObject(true);
createAndAccessObject(false);
```

在这个简单的 JavaScript 函数中：

1. **对象创建 `const obj = { x: 10 };`**:  Turbofan 编译器会创建一个 `JSCreate` 节点来表示对象 `obj` 的创建。 `NodeProperties::GetJSCreateMap` 可以被用来获取 `{x: 10}` 这种字面量对象的初始 Map。

2. **属性访问 `obj.x`**:  编译器会创建类似 `LoadField` 的节点来表示属性的访问。 `NodeProperties::InferMapsUnsafe` 可以被用来推断 `obj` 的类型 (Map)，以便优化属性访问。如果编译器能够确定 `obj` 始终具有某个特定的 Map，那么它可以直接访问内存中的偏移量，而无需进行昂贵的运行时查找。

3. **控制流 `if (flag)`**:  编译器会创建 `Branch` 节点和 `IfTrue/IfFalse` 节点来表示条件分支。 `NodeProperties` 中用于操作控制流的函数 (如 `FindSuccessfulControlProjection`) 可以帮助编译器分析和优化这些分支。

**总结:**

`node-properties.cc` 文件是 V8 编译器内部基础设施的关键部分，它提供了一组用于理解和操作 JavaScript 代码编译后产生的中间表示的工具。这些工具使得编译器能够进行各种分析和优化，从而提升 JavaScript 代码的执行效率。虽然开发者通常不会直接接触到这些 C++ 代码，但理解其背后的原理有助于理解 V8 引擎是如何高效执行 JavaScript 代码的。

### 提示词
```
这是目录为v8/src/compiler/node-properties.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/node-properties.h"

#include <optional>

#include "src/compiler/common-operator.h"
#include "src/compiler/js-heap-broker.h"
#include "src/compiler/map-inference.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/operator-properties.h"
#include "src/compiler/simplified-operator.h"
#include "src/compiler/turbofan-graph.h"
#include "src/compiler/verifier.h"

namespace v8 {
namespace internal {
namespace compiler {

// static

// static
bool NodeProperties::IsValueEdge(Edge edge) {
  Node* const node = edge.from();
  return IsInputRange(edge, FirstValueIndex(node),
                      node->op()->ValueInputCount());
}


// static
bool NodeProperties::IsContextEdge(Edge edge) {
  Node* const node = edge.from();
  return IsInputRange(edge, FirstContextIndex(node),
                      OperatorProperties::GetContextInputCount(node->op()));
}


// static
bool NodeProperties::IsFrameStateEdge(Edge edge) {
  Node* const node = edge.from();
  return IsInputRange(edge, FirstFrameStateIndex(node),
                      OperatorProperties::GetFrameStateInputCount(node->op()));
}


// static
bool NodeProperties::IsEffectEdge(Edge edge) {
  Node* const node = edge.from();
  return IsInputRange(edge, FirstEffectIndex(node),
                      node->op()->EffectInputCount());
}


// static
bool NodeProperties::IsControlEdge(Edge edge) {
  Node* const node = edge.from();
  return IsInputRange(edge, FirstControlIndex(node),
                      node->op()->ControlInputCount());
}


// static
bool NodeProperties::IsExceptionalCall(Node* node, Node** out_exception) {
  if (node->op()->HasProperty(Operator::kNoThrow)) return false;
  for (Edge const edge : node->use_edges()) {
    if (!NodeProperties::IsControlEdge(edge)) continue;
    if (edge.from()->opcode() == IrOpcode::kIfException) {
      if (out_exception != nullptr) *out_exception = edge.from();
      return true;
    }
  }
  return false;
}

// static
Node* NodeProperties::FindSuccessfulControlProjection(Node* node) {
  CHECK_GT(node->op()->ControlOutputCount(), 0);
  if (node->op()->HasProperty(Operator::kNoThrow)) return node;
  for (Edge const edge : node->use_edges()) {
    if (!NodeProperties::IsControlEdge(edge)) continue;
    if (edge.from()->opcode() == IrOpcode::kIfSuccess) {
      return edge.from();
    }
  }
  return node;
}

// static
void NodeProperties::ReplaceValueInput(Node* node, Node* value, int index) {
  CHECK_LE(0, index);
  CHECK_LT(index, node->op()->ValueInputCount());
  node->ReplaceInput(FirstValueIndex(node) + index, value);
}


// static
void NodeProperties::ReplaceValueInputs(Node* node, Node* value) {
  int value_input_count = node->op()->ValueInputCount();
  CHECK_GT(value_input_count, 0);
  node->ReplaceInput(0, value);
  while (--value_input_count > 0) {
    node->RemoveInput(value_input_count);
  }
}


// static
void NodeProperties::ReplaceContextInput(Node* node, Node* context) {
  CHECK(OperatorProperties::HasContextInput(node->op()));
  node->ReplaceInput(FirstContextIndex(node), context);
}


// static
void NodeProperties::ReplaceControlInput(Node* node, Node* control, int index) {
  CHECK_LE(0, index);
  CHECK_LT(index, node->op()->ControlInputCount());
  node->ReplaceInput(FirstControlIndex(node) + index, control);
}


// static
void NodeProperties::ReplaceEffectInput(Node* node, Node* effect, int index) {
  CHECK_LE(0, index);
  CHECK_LT(index, node->op()->EffectInputCount());
  return node->ReplaceInput(FirstEffectIndex(node) + index, effect);
}


// static
void NodeProperties::ReplaceFrameStateInput(Node* node, Node* frame_state) {
  CHECK(OperatorProperties::HasFrameStateInput(node->op()));
  node->ReplaceInput(FirstFrameStateIndex(node), frame_state);
}

// static
void NodeProperties::RemoveNonValueInputs(Node* node) {
  node->TrimInputCount(node->op()->ValueInputCount());
}


// static
void NodeProperties::RemoveValueInputs(Node* node) {
  int value_input_count = node->op()->ValueInputCount();
  while (--value_input_count >= 0) {
    node->RemoveInput(value_input_count);
  }
}


void NodeProperties::MergeControlToEnd(Graph* graph,
                                       CommonOperatorBuilder* common,
                                       Node* node) {
  graph->end()->AppendInput(graph->zone(), node);
  graph->end()->set_op(common->End(graph->end()->InputCount()));
}

void NodeProperties::RemoveControlFromEnd(Graph* graph,
                                          CommonOperatorBuilder* common,
                                          Node* node) {
  int index_to_remove = -1;
  for (int i = 0; i < graph->end()->op()->ControlInputCount(); i++) {
    int index = NodeProperties::FirstControlIndex(graph->end()) + i;
    if (graph->end()->InputAt(index) == node) {
      index_to_remove = index;
      break;
    }
  }
  CHECK_NE(-1, index_to_remove);
  graph->end()->RemoveInput(index_to_remove);
  graph->end()->set_op(common->End(graph->end()->InputCount()));
}

// static
void NodeProperties::ReplaceUses(Node* node, Node* value, Node* effect,
                                 Node* success, Node* exception) {
  // Requires distinguishing between value, effect and control edges.
  for (Edge edge : node->use_edges()) {
    if (IsControlEdge(edge)) {
      if (edge.from()->opcode() == IrOpcode::kIfSuccess) {
        DCHECK_NOT_NULL(success);
        edge.UpdateTo(success);
      } else if (edge.from()->opcode() == IrOpcode::kIfException) {
        DCHECK_NOT_NULL(exception);
        edge.UpdateTo(exception);
      } else {
        DCHECK_NOT_NULL(success);
        edge.UpdateTo(success);
      }
    } else if (IsEffectEdge(edge)) {
      DCHECK_NOT_NULL(effect);
      edge.UpdateTo(effect);
    } else {
      DCHECK_NOT_NULL(value);
      edge.UpdateTo(value);
    }
  }
}


// static
void NodeProperties::ChangeOp(Node* node, const Operator* new_op) {
  node->set_op(new_op);
  Verifier::VerifyNode(node);
}

// static
void NodeProperties::ChangeOpUnchecked(Node* node, const Operator* new_op) {
  node->set_op(new_op);
}

// static
Node* NodeProperties::FindFrameStateBefore(Node* node,
                                           Node* unreachable_sentinel) {
  Node* effect = NodeProperties::GetEffectInput(node);
  while (effect->opcode() != IrOpcode::kCheckpoint) {
    if (effect->opcode() == IrOpcode::kDead ||
        effect->opcode() == IrOpcode::kUnreachable) {
      return unreachable_sentinel;
    }
    DCHECK(effect->op()->HasProperty(Operator::kNoWrite));
    DCHECK_EQ(1, effect->op()->EffectInputCount());
    effect = NodeProperties::GetEffectInput(effect);
  }
  Node* frame_state = GetFrameStateInput(effect);
  return frame_state;
}

// static
Node* NodeProperties::FindProjection(Node* node, size_t projection_index) {
  for (auto use : node->uses()) {
    if (use->opcode() == IrOpcode::kProjection &&
        ProjectionIndexOf(use->op()) == projection_index) {
      return use;
    }
  }
  return nullptr;
}


// static
void NodeProperties::CollectValueProjections(Node* node, Node** projections,
                                             size_t projection_count) {
#ifdef DEBUG
  for (size_t index = 0; index < projection_count; ++index) {
    DCHECK_NULL(projections[index]);
  }
#endif
  for (Edge const edge : node->use_edges()) {
    if (!IsValueEdge(edge)) continue;
    Node* use = edge.from();
    DCHECK_EQ(IrOpcode::kProjection, use->opcode());
    projections[ProjectionIndexOf(use->op())] = use;
  }
}


// static
void NodeProperties::CollectControlProjections(Node* node, Node** projections,
                                               size_t projection_count) {
#ifdef DEBUG
  DCHECK_LE(static_cast<int>(projection_count), node->UseCount());
  std::memset(projections, 0, sizeof(*projections) * projection_count);
#endif
  size_t if_value_index = 0;
  for (Edge const edge : node->use_edges()) {
    if (!IsControlEdge(edge)) continue;
    Node* use = edge.from();
    size_t index;
    switch (use->opcode()) {
      case IrOpcode::kIfTrue:
        DCHECK_EQ(IrOpcode::kBranch, node->opcode());
        index = 0;
        break;
      case IrOpcode::kIfFalse:
        DCHECK_EQ(IrOpcode::kBranch, node->opcode());
        index = 1;
        break;
      case IrOpcode::kIfSuccess:
        DCHECK(!node->op()->HasProperty(Operator::kNoThrow));
        index = 0;
        break;
      case IrOpcode::kIfException:
        DCHECK(!node->op()->HasProperty(Operator::kNoThrow));
        index = 1;
        break;
      case IrOpcode::kIfValue:
        DCHECK_EQ(IrOpcode::kSwitch, node->opcode());
        index = if_value_index++;
        break;
      case IrOpcode::kIfDefault:
        DCHECK_EQ(IrOpcode::kSwitch, node->opcode());
        index = projection_count - 1;
        break;
      default:
        continue;
    }
    DCHECK_LT(if_value_index, projection_count);
    DCHECK_LT(index, projection_count);
    DCHECK_NULL(projections[index]);
    projections[index] = use;
  }
#ifdef DEBUG
  for (size_t index = 0; index < projection_count; ++index) {
    DCHECK_NOT_NULL(projections[index]);
  }
#endif
}

// static
MachineRepresentation NodeProperties::GetProjectionType(
    Node const* projection) {
  size_t index = ProjectionIndexOf(projection->op());
  Node* input = projection->InputAt(0);
  switch (input->opcode()) {
    case IrOpcode::kInt32AddWithOverflow:
    case IrOpcode::kInt32SubWithOverflow:
    case IrOpcode::kInt32MulWithOverflow:
    case IrOpcode::kInt32AbsWithOverflow:
      CHECK_LE(index, static_cast<size_t>(1));
      return index == 0 ? MachineRepresentation::kWord32
                        : MachineRepresentation::kBit;
    case IrOpcode::kInt64AddWithOverflow:
    case IrOpcode::kInt64SubWithOverflow:
    case IrOpcode::kInt64MulWithOverflow:
    case IrOpcode::kInt64AbsWithOverflow:
      CHECK_LE(index, static_cast<size_t>(1));
      return index == 0 ? MachineRepresentation::kWord64
                        : MachineRepresentation::kBit;
    case IrOpcode::kTryTruncateFloat64ToInt32:
    case IrOpcode::kTryTruncateFloat64ToUint32:
      CHECK_LE(index, static_cast<size_t>(1));
      return index == 0 ? MachineRepresentation::kWord32
                        : MachineRepresentation::kBit;
    case IrOpcode::kTryTruncateFloat32ToInt64:
    case IrOpcode::kTryTruncateFloat64ToInt64:
    case IrOpcode::kTryTruncateFloat64ToUint64:
    case IrOpcode::kTryTruncateFloat32ToUint64:
      CHECK_LE(index, static_cast<size_t>(1));
      return index == 0 ? MachineRepresentation::kWord64
                        : MachineRepresentation::kBit;
    case IrOpcode::kCall: {
      auto call_descriptor = CallDescriptorOf(input->op());
      return call_descriptor->GetReturnType(index).representation();
    }
    case IrOpcode::kInt32PairAdd:
    case IrOpcode::kInt32PairSub:
    case IrOpcode::kWord32AtomicPairLoad:
    case IrOpcode::kWord32AtomicPairAdd:
    case IrOpcode::kWord32AtomicPairSub:
    case IrOpcode::kWord32AtomicPairAnd:
    case IrOpcode::kWord32AtomicPairOr:
    case IrOpcode::kWord32AtomicPairXor:
    case IrOpcode::kWord32AtomicPairExchange:
    case IrOpcode::kWord32AtomicPairCompareExchange:
      CHECK_LE(index, static_cast<size_t>(1));
      return MachineRepresentation::kWord32;
    default:
      return MachineRepresentation::kNone;
  }
}

// static
bool NodeProperties::IsSame(Node* a, Node* b) {
  for (;;) {
    if (a->opcode() == IrOpcode::kCheckHeapObject) {
      a = GetValueInput(a, 0);
      continue;
    }
    if (b->opcode() == IrOpcode::kCheckHeapObject) {
      b = GetValueInput(b, 0);
      continue;
    }
    return a == b;
  }
}

// static
OptionalMapRef NodeProperties::GetJSCreateMap(JSHeapBroker* broker,
                                              Node* receiver) {
  DCHECK(receiver->opcode() == IrOpcode::kJSCreate ||
         receiver->opcode() == IrOpcode::kJSCreateArray);
  HeapObjectMatcher mtarget(GetValueInput(receiver, 0));
  HeapObjectMatcher mnewtarget(GetValueInput(receiver, 1));
  if (mtarget.HasResolvedValue() && mnewtarget.HasResolvedValue() &&
      mnewtarget.Ref(broker).IsJSFunction()) {
    ObjectRef target = mtarget.Ref(broker);
    JSFunctionRef newtarget = mnewtarget.Ref(broker).AsJSFunction();
    if (newtarget.map(broker).has_prototype_slot() &&
        newtarget.has_initial_map(broker)) {
      MapRef initial_map = newtarget.initial_map(broker);
      if (initial_map.GetConstructor(broker).equals(target)) {
        DCHECK(target.AsJSFunction().map(broker).is_constructor());
        DCHECK(newtarget.map(broker).is_constructor());
        return initial_map;
      }
    }
  }
  return std::nullopt;
}

// static
NodeProperties::InferMapsResult NodeProperties::InferMapsUnsafe(
    JSHeapBroker* broker, Node* receiver, Effect effect,
    ZoneRefSet<Map>* maps_out) {
  HeapObjectMatcher m(receiver);
  if (m.HasResolvedValue()) {
    HeapObjectRef ref = m.Ref(broker);
    // We don't use ICs for the Array.prototype and the Object.prototype
    // because the runtime has to be able to intercept them properly, so
    // we better make sure that TurboFan doesn't outsmart the system here
    // by storing to elements of either prototype directly.
    //
    // TODO(bmeurer): This can be removed once the Array.prototype and
    // Object.prototype have NO_ELEMENTS elements kind.
    if (!ref.IsJSObject() ||
        !broker->IsArrayOrObjectPrototype(ref.AsJSObject())) {
      if (ref.map(broker).is_stable()) {
        // The {receiver_map} is only reliable when we install a stability
        // code dependency.
        *maps_out = ZoneRefSet<Map>{ref.map(broker)};
        return kUnreliableMaps;
      }
    }
  }
  InferMapsResult result = kReliableMaps;
  while (true) {
    switch (effect->opcode()) {
      case IrOpcode::kMapGuard: {
        Node* const object = GetValueInput(effect, 0);
        if (IsSame(receiver, object)) {
          *maps_out = MapGuardMapsOf(effect->op());
          return result;
        }
        break;
      }
      case IrOpcode::kCheckMaps: {
        Node* const object = GetValueInput(effect, 0);
        if (IsSame(receiver, object)) {
          *maps_out = CheckMapsParametersOf(effect->op()).maps();
          return result;
        }
        break;
      }
      case IrOpcode::kJSCreate: {
        if (IsSame(receiver, effect)) {
          OptionalMapRef initial_map = GetJSCreateMap(broker, receiver);
          if (initial_map.has_value()) {
            *maps_out = ZoneRefSet<Map>{initial_map.value()};
            return result;
          }
          // We reached the allocation of the {receiver}.
          return kNoMaps;
        }
        result = kUnreliableMaps;  // JSCreate can have side-effect.
        break;
      }
      case IrOpcode::kJSCreatePromise: {
        if (IsSame(receiver, effect)) {
          *maps_out = ZoneRefSet<Map>{broker->target_native_context()
                                          .promise_function(broker)
                                          .initial_map(broker)};
          return result;
        }
        break;
      }
      case IrOpcode::kStoreField: {
        // We only care about StoreField of maps.
        Node* const object = GetValueInput(effect, 0);
        FieldAccess const& access = FieldAccessOf(effect->op());
        if (access.base_is_tagged == kTaggedBase &&
            access.offset == HeapObject::kMapOffset) {
          if (IsSame(receiver, object)) {
            Node* const value = GetValueInput(effect, 1);
            HeapObjectMatcher m2(value);
            if (m2.HasResolvedValue()) {
              *maps_out = ZoneRefSet<Map>{m2.Ref(broker).AsMap()};
              return result;
            }
          }
          // Without alias analysis we cannot tell whether this
          // StoreField[map] affects {receiver} or not.
          result = kUnreliableMaps;
        }
        break;
      }
      case IrOpcode::kJSStoreMessage:
      case IrOpcode::kJSStoreModule:
      case IrOpcode::kStoreElement:
      case IrOpcode::kStoreTypedElement: {
        // These never change the map of objects.
        break;
      }
      case IrOpcode::kFinishRegion: {
        // FinishRegion renames the output of allocations, so we need
        // to update the {receiver} that we are looking for, if the
        // {receiver} matches the current {effect}.
        if (IsSame(receiver, effect)) receiver = GetValueInput(effect, 0);
        break;
      }
      case IrOpcode::kEffectPhi: {
        Node* control = GetControlInput(effect);
        if (control->opcode() != IrOpcode::kLoop) {
          DCHECK(control->opcode() == IrOpcode::kDead ||
                 control->opcode() == IrOpcode::kMerge);
          return kNoMaps;
        }

        // Continue search for receiver map outside the loop. Since operations
        // inside the loop may change the map, the result is unreliable.
        effect = GetEffectInput(effect, 0);
        result = kUnreliableMaps;
        continue;
      }
      default: {
        DCHECK_EQ(1, effect->op()->EffectOutputCount());
        if (effect->op()->EffectInputCount() != 1) {
          // Didn't find any appropriate CheckMaps node.
          return kNoMaps;
        }
        if (!effect->op()->HasProperty(Operator::kNoWrite)) {
          // Without alias/escape analysis we cannot tell whether this
          // {effect} affects {receiver} or not.
          result = kUnreliableMaps;
        }
        break;
      }
    }

    // Stop walking the effect chain once we hit the definition of
    // the {receiver} along the {effect}s.
    if (IsSame(receiver, effect)) return kNoMaps;

    // Continue with the next {effect}.
    DCHECK_EQ(1, effect->op()->EffectInputCount());
    effect = NodeProperties::GetEffectInput(effect);
  }
}

// static
bool NodeProperties::NoObservableSideEffectBetween(Node* effect,
                                                   Node* dominator) {
  while (effect != dominator) {
    if (effect->op()->EffectInputCount() == 1 &&
        effect->op()->properties() & Operator::kNoWrite) {
      effect = NodeProperties::GetEffectInput(effect);
    } else {
      return false;
    }
  }
  return true;
}

// static
bool NodeProperties::CanBePrimitive(JSHeapBroker* broker, Node* receiver,
                                    Effect effect) {
  switch (receiver->opcode()) {
#define CASE(Opcode) case IrOpcode::k##Opcode:
    JS_CONSTRUCT_OP_LIST(CASE)
    JS_CREATE_OP_LIST(CASE)
#undef CASE
    case IrOpcode::kCheckReceiver:
    case IrOpcode::kConvertReceiver:
    case IrOpcode::kJSGetSuperConstructor:
    case IrOpcode::kJSToObject:
      return false;
    case IrOpcode::kHeapConstant: {
      HeapObjectRef value = HeapObjectMatcher(receiver).Ref(broker);
      return value.map(broker).IsPrimitiveMap();
    }
    default: {
      MapInference inference(broker, receiver, effect);
      return !inference.HaveMaps() ||
             !inference.AllOfInstanceTypesAreJSReceiver();
    }
  }
}

// static
bool NodeProperties::CanBeNullOrUndefined(JSHeapBroker* broker, Node* receiver,
                                          Effect effect) {
  if (CanBePrimitive(broker, receiver, effect)) {
    switch (receiver->opcode()) {
      case IrOpcode::kCheckInternalizedString:
      case IrOpcode::kCheckNumber:
      case IrOpcode::kCheckSmi:
      case IrOpcode::kCheckString:
      case IrOpcode::kCheckSymbol:
      case IrOpcode::kJSToLength:
      case IrOpcode::kJSToName:
      case IrOpcode::kJSToNumber:
      case IrOpcode::kJSToNumberConvertBigInt:
      case IrOpcode::kJSToNumeric:
      case IrOpcode::kJSToString:
      case IrOpcode::kToBoolean:
        return false;
      case IrOpcode::kHeapConstant: {
        HeapObjectRef value = HeapObjectMatcher(receiver).Ref(broker);
        OddballType type = value.map(broker).oddball_type(broker);
        return type == OddballType::kNull || type == OddballType::kUndefined;
      }
      default:
        return true;
    }
  }
  return false;
}

// static
Node* NodeProperties::GetOuterContext(Node* node, size_t* depth) {
  Node* context = NodeProperties::GetContextInput(node);
  while (*depth > 0 &&
         IrOpcode::IsContextChainExtendingOpcode(context->opcode())) {
    context = NodeProperties::GetContextInput(context);
    (*depth)--;
  }
  return context;
}

// static
Type NodeProperties::GetTypeOrAny(const Node* node) {
  return IsTyped(node) ? node->type() : Type::Any();
}

// static
bool NodeProperties::AllValueInputsAreTyped(Node* node) {
  int input_count = node->op()->ValueInputCount();
  for (int index = 0; index < input_count; ++index) {
    if (!IsTyped(GetValueInput(node, index))) return false;
  }
  return true;
}

// static
bool NodeProperties::IsInputRange(Edge edge, int first, int num) {
  if (num == 0) return false;
  int const index = edge.index();
  return first <= index && index < first + num;
}

// static
size_t NodeProperties::HashCode(Node* node) {
  size_t h = base::hash_combine(node->op()->HashCode(), node->InputCount());
  for (Node* input : node->inputs()) {
    h = base::hash_combine(h, input->id());
  }
  return h;
}

// static
bool NodeProperties::Equals(Node* a, Node* b) {
  DCHECK_NOT_NULL(a);
  DCHECK_NOT_NULL(b);
  DCHECK_NOT_NULL(a->op());
  DCHECK_NOT_NULL(b->op());
  if (!a->op()->Equals(b->op())) return false;
  if (a->InputCount() != b->InputCount()) return false;
  Node::Inputs aInputs = a->inputs();
  Node::Inputs bInputs = b->inputs();

  auto aIt = aInputs.begin();
  auto bIt = bInputs.begin();
  auto aEnd = aInputs.end();

  for (; aIt != aEnd; ++aIt, ++bIt) {
    DCHECK_NOT_NULL(*aIt);
    DCHECK_NOT_NULL(*bIt);
    if ((*aIt)->id() != (*bIt)->id()) return false;
  }
  return true;
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```