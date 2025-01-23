Response: The user wants to understand the functionality of the provided C++ code snippet, which is the fourth part of a file named `simplified-lowering.cc` within the V8 JavaScript engine's compiler.

The goal is to summarize the functionality and, if related to JavaScript, illustrate with a JavaScript example.

This part of the code seems to contain implementations of various low-level operations, likely transforming higher-level simplified operations into more machine-specific instructions.

**Plan:**
1. Read through the code and identify the key functions and data structures.
2. Analyze the purpose of each function, focusing on how they manipulate the graph of operations.
3. Identify connections to JavaScript concepts or operations.
4. Construct a JavaScript example to demonstrate the functionality where applicable.
This代码片段是 `v8/src/compiler/simplified-lowering.cc` 文件的最后一部分，它主要负责将 **简化图（Simplified Graph）** 中的节点 **降低（Lowering）** 到更接近机器表示的形式。这是编译器优化的一个关键步骤，它将高级的、平台无关的操作转换为可以直接映射到特定硬件指令的操作。

**主要功能归纳:**

1. **节点操作的具体实现:**  这部分代码包含了大量针对特定操作符（例如 `JSToNumber`, `Max`, `Min`, 数学运算等）的 `Do...` 函数。这些函数定义了如何将这些高级操作转换为更底层的操作序列。例如，`DoJSToNumberOrNumericTruncatesToFloat64` 展示了将 JavaScript 的 `ToNumber` 或 `ToNumeric` 操作转换为浮点数的过程，其中考虑了 Smi 和 HeapNumber 的情况。

2. **数值类型转换的细化:** 代码中存在很多关于数值类型转换的逻辑，例如将 JavaScript 的 Number 转换为 Int32、Float64 或 Uint8Clamped 等。这些转换在 JavaScript 中很常见，但在底层需要进行详细的处理以确保精度和效率。

3. **数学运算的底层实现:** 像 `Float64Round`, `Float64Sign`, `Int32Abs`, `Int32Div`, `Int32Mod` 等函数展示了如何用更底层的机器指令来实现 JavaScript 中的数学运算。例如，`Int32Div` 考虑了除数为 0 或 -1 的特殊情况，并对一般的有符号整数除法进行了详细的实现。

4. **比较操作的转换:**  `DoIntegral32ToBit`, `DoOrderedNumberToBit`, `DoNumberToBit` 等函数演示了如何将比较操作转换为基于位运算或浮点数比较的机器指令。

5. **辅助函数的定义:**  `ToNumberCode`, `ToNumberOperator`, `ToNumericCode`, `ToNumericOperator` 等函数用于获取内置函数的代码或操作符，在降低过程中用于生成调用内置函数的节点。

6. **节点替换和修改:** `ChangeOp` 函数用于修改图中节点的操作符。在 lowering 过程中，节点的表示形式可能会发生变化，需要更新其操作符。

7. **利用 `RepresentationSelector`:**  代码中使用了 `RepresentationSelector` 类（在前面的部分定义），它负责选择合适的机器表示并插入必要的类型转换节点。`SimplifiedLowering` 类是 `RepresentationSelector` 的使用者，它驱动着整个降低过程。

**与 JavaScript 功能的关系及示例:**

这部分代码的功能直接关系到 JavaScript 的数值运算和类型转换。在 JavaScript 代码执行之前，V8 引擎会将 JavaScript 代码编译成中间表示，然后通过 Simplified Lowering 阶段将其转换为更接近机器码的形式。

**JavaScript 示例:**

```javascript
function example(x) {
  return Math.max(Math.abs(parseInt(x)), 10);
}
```

在这个简单的 JavaScript 函数中，涉及了多个操作，这些操作都需要在 Simplified Lowering 阶段被处理：

* **`parseInt(x)`:**  JavaScript 的 `parseInt` 函数会将输入转换为整数。在 lowering 阶段，这可能会涉及到调用内置的 `ToNumber` 函数（对应 `DoJSToNumberOrNumericTruncatesToWord32` 或 `DoJSToNumberOrNumericTruncatesToFloat64` 等）以及可能的类型检查和转换。

* **`Math.abs(...)`:** JavaScript 的 `Math.abs` 函数计算绝对值。对于整数输入，可能会对应 `SimplifiedLowering::Int32Abs` 函数的实现，使用位运算来计算绝对值。

* **`Math.max(..., 10)`:** JavaScript 的 `Math.max` 函数返回两个数中的较大值。这会对应 `SimplifiedLowering::DoMax` 函数的实现，根据数值类型生成相应的比较和选择指令。

* **常量 `10`:** 常量 `10` 需要被表示为机器可以理解的形式，例如 `Int32Constant`。

**Simplified Lowering 的作用:**

Simplified Lowering 的目标是将这些高级的 JavaScript 操作分解成更细粒度的、平台相关的操作。例如，`Math.max` 操作可能被转换为一个比较指令和一个条件选择指令。对于不同的数据类型（例如，整数 vs. 浮点数），Lowering 过程会生成不同的机器指令序列。

**总结来说，这部分代码是 V8 引擎中将高级 JavaScript 数值运算和类型转换操作转换为底层机器操作的关键组成部分，它直接影响着 JavaScript 代码的执行效率。**

### 提示词
```
这是目录为v8/src/compiler/simplified-lowering.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```
broker_;
  Zone* zone_;                      // Temporary zone.
  // Map from node to its uses that might need to be revisited.
  ZoneMap<Node*, ZoneVector<Node*>> might_need_revisit_;
  size_t count_;                    // number of nodes in the graph
  ZoneVector<NodeInfo> info_;       // node id -> usage information
#ifdef DEBUG
  ZoneVector<InputUseInfos> node_input_use_infos_;  // Debug information about
                                                    // requirements on inputs.
#endif                                              // DEBUG
  NodeVector replacements_;         // replacements to be done after lowering
  RepresentationChanger* changer_;  // for inserting representation changes
  ZoneQueue<Node*> revisit_queue_;  // Queue for revisiting nodes.

  struct NodeState {
    Node* node;
    int input_index;
  };
  NodeVector traversal_nodes_;  // Order in which to traverse the nodes.
  // TODO(danno): RepresentationSelector shouldn't know anything about the
  // source positions table, but must for now since there currently is no other
  // way to pass down source position information to nodes created during
  // lowering. Once this phase becomes a vanilla reducer, it should get source
  // position information via the SourcePositionWrapper like all other reducers.
  SourcePositionTable* source_positions_;
  NodeOriginTable* node_origins_;
  TypeCache const* type_cache_;
  OperationTyper op_typer_;  // helper for the feedback typer
  Type singleton_true_;
  Type singleton_false_;
  TickCounter* const tick_counter_;
  Linkage* const linkage_;
  ObserveNodeManager* const observe_node_manager_;
  SimplifiedLoweringVerifier* verifier_;  // Used to verify output graph.

  NodeInfo* GetInfo(Node* node) {
    DCHECK(node->id() < count_);
    return &info_[node->id()];
  }
  Zone* zone() { return zone_; }
  Zone* graph_zone() { return jsgraph_->zone(); }
  Linkage* linkage() { return linkage_; }
};

// Template specializations

// Enqueue {use_node}'s {index} input if the {use_info} contains new information
// for that input node.
template <>
void RepresentationSelector::EnqueueInput<PROPAGATE>(Node* use_node, int index,
                                                     UseInfo use_info) {
  Node* node = use_node->InputAt(index);
  NodeInfo* info = GetInfo(node);
#ifdef DEBUG
  // Check monotonicity of input requirements.
  node_input_use_infos_[use_node->id()].SetAndCheckInput(use_node, index,
                                                         use_info);
#endif  // DEBUG
  if (info->unvisited()) {
    info->AddUse(use_info);
    TRACE("  initial #%i: %s\n", node->id(), info->truncation().description());
    return;
  }
  TRACE("   queue #%i?: %s\n", node->id(), info->truncation().description());
  if (info->AddUse(use_info)) {
    // New usage information for the node is available.
    if (!info->queued()) {
      DCHECK(info->visited());
      revisit_queue_.push(node);
      info->set_queued();
      TRACE("   added: %s\n", info->truncation().description());
    } else {
      TRACE(" inqueue: %s\n", info->truncation().description());
    }
  }
}

template <>
void RepresentationSelector::SetOutput<PROPAGATE>(
    Node* node, MachineRepresentation representation, Type restriction_type) {
  NodeInfo* const info = GetInfo(node);
  info->set_restriction_type(restriction_type);
}

template <>
void RepresentationSelector::SetOutput<RETYPE>(
    Node* node, MachineRepresentation representation, Type restriction_type) {
  NodeInfo* const info = GetInfo(node);
  DCHECK(restriction_type.Is(info->restriction_type()));
  info->set_output(representation);
}

template <>
void RepresentationSelector::SetOutput<LOWER>(
    Node* node, MachineRepresentation representation, Type restriction_type) {
  NodeInfo* const info = GetInfo(node);
  DCHECK_EQ(info->representation(), representation);
  DCHECK(restriction_type.Is(info->restriction_type()));
  USE(info);
}

template <>
void RepresentationSelector::ProcessInput<PROPAGATE>(Node* node, int index,
                                                     UseInfo use) {
  DCHECK_IMPLIES(use.type_check() != TypeCheckKind::kNone,
                 !node->op()->HasProperty(Operator::kNoDeopt) &&
                     node->op()->EffectInputCount() > 0);
  EnqueueInput<PROPAGATE>(node, index, use);
}

template <>
void RepresentationSelector::ProcessInput<RETYPE>(Node* node, int index,
                                                  UseInfo use) {
  DCHECK_IMPLIES(use.type_check() != TypeCheckKind::kNone,
                 !node->op()->HasProperty(Operator::kNoDeopt) &&
                     node->op()->EffectInputCount() > 0);
}

template <>
void RepresentationSelector::ProcessInput<LOWER>(Node* node, int index,
                                                 UseInfo use) {
  DCHECK_IMPLIES(use.type_check() != TypeCheckKind::kNone,
                 !node->op()->HasProperty(Operator::kNoDeopt) &&
                     node->op()->EffectInputCount() > 0);
  ConvertInput(node, index, use);
}

template <>
void RepresentationSelector::ProcessRemainingInputs<PROPAGATE>(Node* node,
                                                               int index) {
  DCHECK_GE(index, NodeProperties::PastContextIndex(node));

  // Enqueue other inputs (effects, control).
  for (int i = std::max(index, NodeProperties::FirstEffectIndex(node));
       i < node->InputCount(); ++i) {
    EnqueueInput<PROPAGATE>(node, i);
  }
}

// The default, most general visitation case. For {node}, process all value,
// context, frame state, effect, and control inputs, assuming that value
// inputs should have {kRepTagged} representation and can observe all output
// values {kTypeAny}.
template <>
void RepresentationSelector::VisitInputs<PROPAGATE>(Node* node) {
  int first_effect_index = NodeProperties::FirstEffectIndex(node);
  // Visit value, context and frame state inputs as tagged.
  for (int i = 0; i < first_effect_index; i++) {
    ProcessInput<PROPAGATE>(node, i, UseInfo::AnyTagged());
  }
  // Only enqueue other inputs (effects, control).
  for (int i = first_effect_index; i < node->InputCount(); i++) {
    EnqueueInput<PROPAGATE>(node, i);
  }
}

template <>
void RepresentationSelector::VisitInputs<LOWER>(Node* node) {
  int first_effect_index = NodeProperties::FirstEffectIndex(node);
  // Visit value, context and frame state inputs as tagged.
  for (int i = 0; i < first_effect_index; i++) {
    ProcessInput<LOWER>(node, i, UseInfo::AnyTagged());
  }
}

template <>
void RepresentationSelector::InsertUnreachableIfNecessary<LOWER>(Node* node) {
  // If the node is effectful and it produces an impossible value, then we
  // insert Unreachable node after it.
  if (node->op()->ValueOutputCount() > 0 &&
      node->op()->EffectOutputCount() > 0 &&
      node->opcode() != IrOpcode::kUnreachable && TypeOf(node).IsNone()) {
    Node* control = (node->op()->ControlOutputCount() == 0)
                        ? NodeProperties::GetControlInput(node, 0)
                        : NodeProperties::FindSuccessfulControlProjection(node);

    Node* unreachable =
        graph()->NewNode(common()->Unreachable(), node, control);

    // Insert unreachable node and replace all the effect uses of the {node}
    // with the new unreachable node.
    for (Edge edge : node->use_edges()) {
      if (!NodeProperties::IsEffectEdge(edge)) continue;
      // Make sure to not overwrite the unreachable node's input. That would
      // create a cycle.
      if (edge.from() == unreachable) continue;
      // Avoid messing up the exceptional path.
      if (edge.from()->opcode() == IrOpcode::kIfException) {
        DCHECK(!node->op()->HasProperty(Operator::kNoThrow));
        DCHECK_EQ(NodeProperties::GetControlInput(edge.from()), node);
        continue;
      }

      edge.UpdateTo(unreachable);
    }
  }
}

SimplifiedLowering::SimplifiedLowering(
    JSGraph* jsgraph, JSHeapBroker* broker, Zone* zone,
    SourcePositionTable* source_positions, NodeOriginTable* node_origins,
    TickCounter* tick_counter, Linkage* linkage, OptimizedCompilationInfo* info,
    ObserveNodeManager* observe_node_manager)
    : jsgraph_(jsgraph),
      broker_(broker),
      zone_(zone),
      type_cache_(TypeCache::Get()),
      source_positions_(source_positions),
      node_origins_(node_origins),
      tick_counter_(tick_counter),
      linkage_(linkage),
      info_(info),
      observe_node_manager_(observe_node_manager) {}

void SimplifiedLowering::LowerAllNodes() {
  SimplifiedLoweringVerifier* verifier = nullptr;
  if (v8_flags.verify_simplified_lowering) {
    verifier = zone_->New<SimplifiedLoweringVerifier>(zone_, graph());
  }
  RepresentationChanger changer(jsgraph(), broker_, verifier);
  RepresentationSelector selector(
      jsgraph(), broker_, zone_, &changer, source_positions_, node_origins_,
      tick_counter_, linkage_, observe_node_manager_, verifier);
  selector.Run(this);
}

void SimplifiedLowering::DoJSToNumberOrNumericTruncatesToFloat64(
    Node* node, RepresentationSelector* selector) {
  DCHECK(node->opcode() == IrOpcode::kJSToNumber ||
         node->opcode() == IrOpcode::kJSToNumberConvertBigInt ||
         node->opcode() == IrOpcode::kJSToNumeric);
  Node* value = node->InputAt(0);
  Node* context = node->InputAt(1);
  Node* frame_state = node->InputAt(2);
  Node* effect = node->InputAt(3);
  Node* control = node->InputAt(4);

  Node* check0 = graph()->NewNode(simplified()->ObjectIsSmi(), value);
  Node* branch0 = graph()->NewNode(
      common()->Branch(BranchHint::kTrue, BranchSemantics::kMachine), check0,
      control);

  Node* if_true0 = graph()->NewNode(common()->IfTrue(), branch0);
  Node* etrue0 = effect;
  Node* vtrue0;
  {
    vtrue0 = graph()->NewNode(simplified()->ChangeTaggedSignedToInt32(), value);
    vtrue0 = graph()->NewNode(machine()->ChangeInt32ToFloat64(), vtrue0);
  }

  Node* if_false0 = graph()->NewNode(common()->IfFalse(), branch0);
  Node* efalse0 = effect;
  Node* vfalse0;
  {
    Operator const* op =
        node->opcode() == IrOpcode::kJSToNumber
            ? (node->opcode() == IrOpcode::kJSToNumberConvertBigInt
                   ? ToNumberConvertBigIntOperator()
                   : ToNumberOperator())
            : ToNumericOperator();
    Node* code = node->opcode() == IrOpcode::kJSToNumber
                     ? ToNumberCode()
                     : (node->opcode() == IrOpcode::kJSToNumberConvertBigInt
                            ? ToNumberConvertBigIntCode()
                            : ToNumericCode());
    vfalse0 = efalse0 = if_false0 = graph()->NewNode(
        op, code, value, context, frame_state, efalse0, if_false0);

    // Update potential {IfException} uses of {node} to point to the above
    // stub call node instead.
    Node* on_exception = nullptr;
    if (NodeProperties::IsExceptionalCall(node, &on_exception)) {
      NodeProperties::ReplaceControlInput(on_exception, vfalse0);
      NodeProperties::ReplaceEffectInput(on_exception, efalse0);
      if_false0 = graph()->NewNode(common()->IfSuccess(), vfalse0);
    }

    Node* check1 = graph()->NewNode(simplified()->ObjectIsSmi(), vfalse0);
    Node* branch1 = graph()->NewNode(
        common()->Branch(BranchHint::kNone, BranchSemantics::kMachine), check1,
        if_false0);

    Node* if_true1 = graph()->NewNode(common()->IfTrue(), branch1);
    Node* etrue1 = efalse0;
    Node* vtrue1;
    {
      vtrue1 =
          graph()->NewNode(simplified()->ChangeTaggedSignedToInt32(), vfalse0);
      vtrue1 = graph()->NewNode(machine()->ChangeInt32ToFloat64(), vtrue1);
    }

    Node* if_false1 = graph()->NewNode(common()->IfFalse(), branch1);
    Node* efalse1 = efalse0;
    Node* vfalse1;
    {
      vfalse1 = efalse1 = graph()->NewNode(
          simplified()->LoadField(AccessBuilder::ForHeapNumberValue()), efalse0,
          efalse1, if_false1);
    }

    if_false0 = graph()->NewNode(common()->Merge(2), if_true1, if_false1);
    efalse0 =
        graph()->NewNode(common()->EffectPhi(2), etrue1, efalse1, if_false0);
    vfalse0 =
        graph()->NewNode(common()->Phi(MachineRepresentation::kFloat64, 2),
                         vtrue1, vfalse1, if_false0);
  }

  control = graph()->NewNode(common()->Merge(2), if_true0, if_false0);
  effect = graph()->NewNode(common()->EffectPhi(2), etrue0, efalse0, control);
  value = graph()->NewNode(common()->Phi(MachineRepresentation::kFloat64, 2),
                           vtrue0, vfalse0, control);

  // Replace effect and control uses appropriately.
  for (Edge edge : node->use_edges()) {
    if (NodeProperties::IsControlEdge(edge)) {
      if (edge.from()->opcode() == IrOpcode::kIfSuccess) {
        edge.from()->ReplaceUses(control);
        edge.from()->Kill();
      } else {
        DCHECK_NE(IrOpcode::kIfException, edge.from()->opcode());
        edge.UpdateTo(control);
      }
    } else if (NodeProperties::IsEffectEdge(edge)) {
      edge.UpdateTo(effect);
    }
  }

  selector->DeferReplacement(node, value);
}

void SimplifiedLowering::DoJSToNumberOrNumericTruncatesToWord32(
    Node* node, RepresentationSelector* selector) {
  DCHECK(node->opcode() == IrOpcode::kJSToNumber ||
         node->opcode() == IrOpcode::kJSToNumberConvertBigInt ||
         node->opcode() == IrOpcode::kJSToNumeric);
  Node* value = node->InputAt(0);
  Node* context = node->InputAt(1);
  Node* frame_state = node->InputAt(2);
  Node* effect = node->InputAt(3);
  Node* control = node->InputAt(4);

  Node* check0 = graph()->NewNode(simplified()->ObjectIsSmi(), value);
  Node* branch0 = graph()->NewNode(
      common()->Branch(BranchHint::kTrue, BranchSemantics::kMachine), check0,
      control);

  Node* if_true0 = graph()->NewNode(common()->IfTrue(), branch0);
  Node* etrue0 = effect;
  Node* vtrue0 =
      graph()->NewNode(simplified()->ChangeTaggedSignedToInt32(), value);

  Node* if_false0 = graph()->NewNode(common()->IfFalse(), branch0);
  Node* efalse0 = effect;
  Node* vfalse0;
  {
    Operator const* op =
        node->opcode() == IrOpcode::kJSToNumber
            ? (node->opcode() == IrOpcode::kJSToNumberConvertBigInt
                   ? ToNumberConvertBigIntOperator()
                   : ToNumberOperator())
            : ToNumericOperator();
    Node* code = node->opcode() == IrOpcode::kJSToNumber
                     ? ToNumberCode()
                     : (node->opcode() == IrOpcode::kJSToNumberConvertBigInt
                            ? ToNumberConvertBigIntCode()
                            : ToNumericCode());
    vfalse0 = efalse0 = if_false0 = graph()->NewNode(
        op, code, value, context, frame_state, efalse0, if_false0);

    // Update potential {IfException} uses of {node} to point to the above
    // stub call node instead.
    Node* on_exception = nullptr;
    if (NodeProperties::IsExceptionalCall(node, &on_exception)) {
      NodeProperties::ReplaceControlInput(on_exception, vfalse0);
      NodeProperties::ReplaceEffectInput(on_exception, efalse0);
      if_false0 = graph()->NewNode(common()->IfSuccess(), vfalse0);
    }

    Node* check1 = graph()->NewNode(simplified()->ObjectIsSmi(), vfalse0);
    Node* branch1 = graph()->NewNode(
        common()->Branch(BranchHint::kNone, BranchSemantics::kMachine), check1,
        if_false0);

    Node* if_true1 = graph()->NewNode(common()->IfTrue(), branch1);
    Node* etrue1 = efalse0;
    Node* vtrue1 =
        graph()->NewNode(simplified()->ChangeTaggedSignedToInt32(), vfalse0);

    Node* if_false1 = graph()->NewNode(common()->IfFalse(), branch1);
    Node* efalse1 = efalse0;
    Node* vfalse1;
    {
      vfalse1 = efalse1 = graph()->NewNode(
          simplified()->LoadField(AccessBuilder::ForHeapNumberValue()), efalse0,
          efalse1, if_false1);
      vfalse1 = graph()->NewNode(machine()->TruncateFloat64ToWord32(), vfalse1);
    }

    if_false0 = graph()->NewNode(common()->Merge(2), if_true1, if_false1);
    efalse0 =
        graph()->NewNode(common()->EffectPhi(2), etrue1, efalse1, if_false0);
    vfalse0 = graph()->NewNode(common()->Phi(MachineRepresentation::kWord32, 2),
                               vtrue1, vfalse1, if_false0);
  }

  control = graph()->NewNode(common()->Merge(2), if_true0, if_false0);
  effect = graph()->NewNode(common()->EffectPhi(2), etrue0, efalse0, control);
  value = graph()->NewNode(common()->Phi(MachineRepresentation::kWord32, 2),
                           vtrue0, vfalse0, control);

  // Replace effect and control uses appropriately.
  for (Edge edge : node->use_edges()) {
    if (NodeProperties::IsControlEdge(edge)) {
      if (edge.from()->opcode() == IrOpcode::kIfSuccess) {
        edge.from()->ReplaceUses(control);
        edge.from()->Kill();
      } else {
        DCHECK_NE(IrOpcode::kIfException, edge.from()->opcode());
        edge.UpdateTo(control);
      }
    } else if (NodeProperties::IsEffectEdge(edge)) {
      edge.UpdateTo(effect);
    }
  }

  selector->DeferReplacement(node, value);
}

Node* SimplifiedLowering::Float64Round(Node* const node) {
  Node* const one = jsgraph()->Float64Constant(1.0);
  Node* const one_half = jsgraph()->Float64Constant(0.5);
  Node* const input = node->InputAt(0);

  // Round up towards Infinity, and adjust if the difference exceeds 0.5.
  Node* result = graph()->NewNode(machine()->Float64RoundUp().placeholder(),
                                  node->InputAt(0));
  return graph()->NewNode(
      common()->Select(MachineRepresentation::kFloat64),
      graph()->NewNode(
          machine()->Float64LessThanOrEqual(),
          graph()->NewNode(machine()->Float64Sub(), result, one_half), input),
      result, graph()->NewNode(machine()->Float64Sub(), result, one));
}

Node* SimplifiedLowering::Float64Sign(Node* const node) {
  Node* const minus_one = jsgraph()->Float64Constant(-1.0);
  Node* const zero = jsgraph()->Float64Constant(0.0);
  Node* const one = jsgraph()->Float64Constant(1.0);

  Node* const input = node->InputAt(0);

  return graph()->NewNode(
      common()->Select(MachineRepresentation::kFloat64),
      graph()->NewNode(machine()->Float64LessThan(), input, zero), minus_one,
      graph()->NewNode(
          common()->Select(MachineRepresentation::kFloat64),
          graph()->NewNode(machine()->Float64LessThan(), zero, input), one,
          input));
}

Node* SimplifiedLowering::Int32Abs(Node* const node) {
  Node* const input = node->InputAt(0);

  // Generate case for absolute integer value.
  //
  //    let sign = input >> 31 in
  //    (input ^ sign) - sign

  Node* sign = graph()->NewNode(machine()->Word32Sar(), input,
                                jsgraph()->Int32Constant(31));
  return graph()->NewNode(machine()->Int32Sub(),
                          graph()->NewNode(machine()->Word32Xor(), input, sign),
                          sign);
}

Node* SimplifiedLowering::Int32Div(Node* const node) {
  Int32BinopMatcher m(node);
  Node* const zero = jsgraph()->Int32Constant(0);
  Node* const minus_one = jsgraph()->Int32Constant(-1);
  Node* const lhs = m.left().node();
  Node* const rhs = m.right().node();

  if (m.right().Is(-1)) {
    return graph()->NewNode(machine()->Int32Sub(), zero, lhs);
  } else if (m.right().Is(0)) {
    return rhs;
  } else if (machine()->Int32DivIsSafe() || m.right().HasResolvedValue()) {
    return graph()->NewNode(machine()->Int32Div(), lhs, rhs, graph()->start());
  }

  // General case for signed integer division.
  //
  //    if 0 < rhs then
  //      lhs / rhs
  //    else
  //      if rhs < -1 then
  //        lhs / rhs
  //      else if rhs == 0 then
  //        0
  //      else
  //        0 - lhs
  //
  // Note: We do not use the Diamond helper class here, because it really hurts
  // readability with nested diamonds.
  const Operator* const merge_op = common()->Merge(2);
  const Operator* const phi_op =
      common()->Phi(MachineRepresentation::kWord32, 2);

  Node* check0 = graph()->NewNode(machine()->Int32LessThan(), zero, rhs);
  Node* branch0 = graph()->NewNode(
      common()->Branch(BranchHint::kTrue, BranchSemantics::kMachine), check0,
      graph()->start());

  Node* if_true0 = graph()->NewNode(common()->IfTrue(), branch0);
  Node* true0 = graph()->NewNode(machine()->Int32Div(), lhs, rhs, if_true0);

  Node* if_false0 = graph()->NewNode(common()->IfFalse(), branch0);
  Node* false0;
  {
    Node* check1 = graph()->NewNode(machine()->Int32LessThan(), rhs, minus_one);
    Node* branch1 = graph()->NewNode(
        common()->Branch(BranchHint::kNone, BranchSemantics::kMachine), check1,
        if_false0);

    Node* if_true1 = graph()->NewNode(common()->IfTrue(), branch1);
    Node* true1 = graph()->NewNode(machine()->Int32Div(), lhs, rhs, if_true1);

    Node* if_false1 = graph()->NewNode(common()->IfFalse(), branch1);
    Node* false1;
    {
      Node* check2 = graph()->NewNode(machine()->Word32Equal(), rhs, zero);
      Node* branch2 = graph()->NewNode(
          common()->Branch(BranchHint::kNone, BranchSemantics::kMachine),
          check2, if_false1);

      Node* if_true2 = graph()->NewNode(common()->IfTrue(), branch2);
      Node* true2 = zero;

      Node* if_false2 = graph()->NewNode(common()->IfFalse(), branch2);
      Node* false2 = graph()->NewNode(machine()->Int32Sub(), zero, lhs);

      if_false1 = graph()->NewNode(merge_op, if_true2, if_false2);
      false1 = graph()->NewNode(phi_op, true2, false2, if_false1);
    }

    if_false0 = graph()->NewNode(merge_op, if_true1, if_false1);
    false0 = graph()->NewNode(phi_op, true1, false1, if_false0);
  }

  Node* merge0 = graph()->NewNode(merge_op, if_true0, if_false0);
  return graph()->NewNode(phi_op, true0, false0, merge0);
}

Node* SimplifiedLowering::Int32Mod(Node* const node) {
  Int32BinopMatcher m(node);
  Node* const zero = jsgraph()->Int32Constant(0);
  Node* const minus_one = jsgraph()->Int32Constant(-1);
  Node* const lhs = m.left().node();
  Node* const rhs = m.right().node();

  if (m.right().Is(-1) || m.right().Is(0)) {
    return zero;
  } else if (m.right().HasResolvedValue()) {
    return graph()->NewNode(machine()->Int32Mod(), lhs, rhs, graph()->start());
  }

  // General case for signed integer modulus, with optimization for (unknown)
  // power of 2 right hand side.
  //
  //   if 0 < rhs then
  //     msk = rhs - 1
  //     if rhs & msk != 0 then
  //       lhs % rhs
  //     else
  //       if lhs < 0 then
  //         -(-lhs & msk)
  //       else
  //         lhs & msk
  //   else
  //     if rhs < -1 then
  //       lhs % rhs
  //     else
  //       zero
  //
  // Note: We do not use the Diamond helper class here, because it really hurts
  // readability with nested diamonds.
  const Operator* const merge_op = common()->Merge(2);
  const Operator* const phi_op =
      common()->Phi(MachineRepresentation::kWord32, 2);

  Node* check0 = graph()->NewNode(machine()->Int32LessThan(), zero, rhs);
  Node* branch0 = graph()->NewNode(
      common()->Branch(BranchHint::kTrue, BranchSemantics::kMachine), check0,
      graph()->start());

  Node* if_true0 = graph()->NewNode(common()->IfTrue(), branch0);
  Node* true0;
  {
    Node* msk = graph()->NewNode(machine()->Int32Add(), rhs, minus_one);

    Node* check1 = graph()->NewNode(machine()->Word32And(), rhs, msk);
    Node* branch1 = graph()->NewNode(
        common()->Branch(BranchHint::kNone, BranchSemantics::kMachine), check1,
        if_true0);

    Node* if_true1 = graph()->NewNode(common()->IfTrue(), branch1);
    Node* true1 = graph()->NewNode(machine()->Int32Mod(), lhs, rhs, if_true1);

    Node* if_false1 = graph()->NewNode(common()->IfFalse(), branch1);
    Node* false1;
    {
      Node* check2 = graph()->NewNode(machine()->Int32LessThan(), lhs, zero);
      Node* branch2 = graph()->NewNode(
          common()->Branch(BranchHint::kFalse, BranchSemantics::kMachine),
          check2, if_false1);

      Node* if_true2 = graph()->NewNode(common()->IfTrue(), branch2);
      Node* true2 = graph()->NewNode(
          machine()->Int32Sub(), zero,
          graph()->NewNode(machine()->Word32And(),
                           graph()->NewNode(machine()->Int32Sub(), zero, lhs),
                           msk));

      Node* if_false2 = graph()->NewNode(common()->IfFalse(), branch2);
      Node* false2 = graph()->NewNode(machine()->Word32And(), lhs, msk);

      if_false1 = graph()->NewNode(merge_op, if_true2, if_false2);
      false1 = graph()->NewNode(phi_op, true2, false2, if_false1);
    }

    if_true0 = graph()->NewNode(merge_op, if_true1, if_false1);
    true0 = graph()->NewNode(phi_op, true1, false1, if_true0);
  }

  Node* if_false0 = graph()->NewNode(common()->IfFalse(), branch0);
  Node* false0;
  {
    Node* check1 = graph()->NewNode(machine()->Int32LessThan(), rhs, minus_one);
    Node* branch1 = graph()->NewNode(
        common()->Branch(BranchHint::kTrue, BranchSemantics::kMachine), check1,
        if_false0);

    Node* if_true1 = graph()->NewNode(common()->IfTrue(), branch1);
    Node* true1 = graph()->NewNode(machine()->Int32Mod(), lhs, rhs, if_true1);

    Node* if_false1 = graph()->NewNode(common()->IfFalse(), branch1);
    Node* false1 = zero;

    if_false0 = graph()->NewNode(merge_op, if_true1, if_false1);
    false0 = graph()->NewNode(phi_op, true1, false1, if_false0);
  }

  Node* merge0 = graph()->NewNode(merge_op, if_true0, if_false0);
  return graph()->NewNode(phi_op, true0, false0, merge0);
}

Node* SimplifiedLowering::Int32Sign(Node* const node) {
  Node* const minus_one = jsgraph()->Int32Constant(-1);
  Node* const zero = jsgraph()->Int32Constant(0);
  Node* const one = jsgraph()->Int32Constant(1);

  Node* const input = node->InputAt(0);

  return graph()->NewNode(
      common()->Select(MachineRepresentation::kWord32),
      graph()->NewNode(machine()->Int32LessThan(), input, zero), minus_one,
      graph()->NewNode(
          common()->Select(MachineRepresentation::kWord32),
          graph()->NewNode(machine()->Int32LessThan(), zero, input), one,
          zero));
}

Node* SimplifiedLowering::Uint32Div(Node* const node) {
  Uint32BinopMatcher m(node);
  Node* const zero = jsgraph()->Uint32Constant(0);
  Node* const lhs = m.left().node();
  Node* const rhs = m.right().node();

  if (m.right().Is(0)) {
    return zero;
  } else if (machine()->Uint32DivIsSafe() || m.right().HasResolvedValue()) {
    return graph()->NewNode(machine()->Uint32Div(), lhs, rhs, graph()->start());
  }

  Node* check = graph()->NewNode(machine()->Word32Equal(), rhs, zero);
  Diamond d(graph(), common(), check, BranchHint::kFalse,
            BranchSemantics::kMachine);
  Node* div = graph()->NewNode(machine()->Uint32Div(), lhs, rhs, d.if_false);
  return d.Phi(MachineRepresentation::kWord32, zero, div);
}

Node* SimplifiedLowering::Uint32Mod(Node* const node) {
  Uint32BinopMatcher m(node);
  Node* const minus_one = jsgraph()->Int32Constant(-1);
  Node* const zero = jsgraph()->Uint32Constant(0);
  Node* const lhs = m.left().node();
  Node* const rhs = m.right().node();

  if (m.right().Is(0)) {
    return zero;
  } else if (m.right().HasResolvedValue()) {
    return graph()->NewNode(machine()->Uint32Mod(), lhs, rhs, graph()->start());
  }

  // General case for unsigned integer modulus, with optimization for (unknown)
  // power of 2 right hand side.
  //
  //   if rhs == 0 then
  //     zero
  //   else
  //     msk = rhs - 1
  //     if rhs & msk != 0 then
  //       lhs % rhs
  //     else
  //       lhs & msk
  //
  // Note: We do not use the Diamond helper class here, because it really hurts
  // readability with nested diamonds.
  const Operator* const merge_op = common()->Merge(2);
  const Operator* const phi_op =
      common()->Phi(MachineRepresentation::kWord32, 2);

  Node* check0 = graph()->NewNode(machine()->Word32Equal(), rhs, zero);
  Node* branch0 = graph()->NewNode(
      common()->Branch(BranchHint::kFalse, BranchSemantics::kMachine), check0,
      graph()->start());

  Node* if_true0 = graph()->NewNode(common()->IfTrue(), branch0);
  Node* true0 = zero;

  Node* if_false0 = graph()->NewNode(common()->IfFalse(), branch0);
  Node* false0;
  {
    Node* msk = graph()->NewNode(machine()->Int32Add(), rhs, minus_one);

    Node* check1 = graph()->NewNode(machine()->Word32And(), rhs, msk);
    Node* branch1 = graph()->NewNode(
        common()->Branch(BranchHint::kNone, BranchSemantics::kMachine), check1,
        if_false0);

    Node* if_true1 = graph()->NewNode(common()->IfTrue(), branch1);
    Node* true1 = graph()->NewNode(machine()->Uint32Mod(), lhs, rhs, if_true1);

    Node* if_false1 = graph()->NewNode(common()->IfFalse(), branch1);
    Node* false1 = graph()->NewNode(machine()->Word32And(), lhs, msk);

    if_false0 = graph()->NewNode(merge_op, if_true1, if_false1);
    false0 = graph()->NewNode(phi_op, true1, false1, if_false0);
  }

  Node* merge0 = graph()->NewNode(merge_op, if_true0, if_false0);
  return graph()->NewNode(phi_op, true0, false0, merge0);
}

void SimplifiedLowering::DoMax(Node* node, Operator const* op,
                               MachineRepresentation rep) {
  Node* const lhs = node->InputAt(0);
  Node* const rhs = node->InputAt(1);

  node->ReplaceInput(0, graph()->NewNode(op, lhs, rhs));
  DCHECK_EQ(rhs, node->InputAt(1));
  node->AppendInput(graph()->zone(), lhs);
  ChangeOp(node, common()->Select(rep));
}

void SimplifiedLowering::DoMin(Node* node, Operator const* op,
                               MachineRepresentation rep) {
  Node* const lhs = node->InputAt(0);
  Node* const rhs = node->InputAt(1);

  node->InsertInput(graph()->zone(), 0, graph()->NewNode(op, lhs, rhs));
  DCHECK_EQ(lhs, node->InputAt(1));
  DCHECK_EQ(rhs, node->InputAt(2));
  ChangeOp(node, common()->Select(rep));
}

void SimplifiedLowering::DoIntegral32ToBit(Node* node) {
  Node* const input = node->InputAt(0);
  Node* const zero = jsgraph()->Int32Constant(0);
  Operator const* const op = machine()->Word32Equal();

  node->ReplaceInput(0, graph()->NewNode(op, input, zero));
  node->AppendInput(graph()->zone(), zero);
  ChangeOp(node, op);
}

void SimplifiedLowering::DoOrderedNumberToBit(Node* node) {
  Node* const input = node->InputAt(0);

  node->ReplaceInput(0, graph()->NewNode(machine()->Float64Equal(), input,
                                         jsgraph()->Float64Constant(0.0)));
  node->AppendInput(graph()->zone(), jsgraph()->Int32Constant(0));
  ChangeOp(node, machine()->Word32Equal());
}

void SimplifiedLowering::DoNumberToBit(Node* node) {
  Node* const input = node->InputAt(0);

  node->ReplaceInput(0, jsgraph()->Float64Constant(0.0));
  node->AppendInput(graph()->zone(),
                    graph()->NewNode(machine()->Float64Abs(), input));
  ChangeOp(node, machine()->Float64LessThan());
}

void SimplifiedLowering::DoIntegerToUint8Clamped(Node* node) {
  Node* const input = node->InputAt(0);
  Node* const min = jsgraph()->Float64Constant(0.0);
  Node* const max = jsgraph()->Float64Constant(255.0);

  node->ReplaceInput(
      0, graph()->NewNode(machine()->Float64LessThan(), min, input));
  node->AppendInput(
      graph()->zone(),
      graph()->NewNode(
          common()->Select(MachineRepresentation::kFloat64),
          graph()->NewNode(machine()->Float64LessThan(), input, max), input,
          max));
  node->AppendInput(graph()->zone(), min);
  ChangeOp(node, common()->Select(MachineRepresentation::kFloat64));
}

void SimplifiedLowering::DoNumberToUint8Clamped(Node* node) {
  Node* const input = node->InputAt(0);
  Node* const min = jsgraph()->Float64Constant(0.0);
  Node* const max = jsgraph()->Float64Constant(255.0);

  node->ReplaceInput(
      0, graph()->NewNode(
             common()->Select(MachineRepresentation::kFloat64),
             graph()->NewNode(machine()->Float64LessThan(), min, input),
             graph()->NewNode(
                 common()->Select(MachineRepresentation::kFloat64),
                 graph()->NewNode(machine()->Float64LessThan(), input, max),
                 input, max),
             min));
  ChangeOp(node, machine()->Float64RoundTiesEven().placeholder());
}

void SimplifiedLowering::DoSigned32ToUint8Clamped(Node* node) {
  Node* const input = node->InputAt(0);
  Node* const min = jsgraph()->Int32Constant(0);
  Node* const max = jsgraph()->Int32Constant(255);

  node->ReplaceInput(
      0, graph()->NewNode(machine()->Int32LessThanOrEqual(), input, max));
  node->AppendInput(
      graph()->zone(),
      graph()->NewNode(common()->Select(MachineRepresentation::kWord32),
                       graph()->NewNode(machine()->Int32LessThan(), input, min),
                       min, input));
  node->AppendInput(graph()->zone(), max);
  ChangeOp(node, common()->Select(MachineRepresentation::kWord32));
}

void SimplifiedLowering::DoUnsigned32ToUint8Clamped(Node* node) {
  Node* const input = node->InputAt(0);
  Node* const max = jsgraph()->Uint32Constant(255u);

  node->ReplaceInput(
      0, graph()->NewNode(machine()->Uint32LessThanOrEqual(), input, max));
  node->AppendInput(graph()->zone(), input);
  node->AppendInput(graph()->zone(), max);
  ChangeOp(node, common()->Select(MachineRepresentation::kWord32));
}

Node* SimplifiedLowering::ToNumberCode() {
  if (!to_number_code_.is_set()) {
    Callable callable = Builtins::CallableFor(isolate(), Builtin::kToNumber);
    to_number_code_.set(jsgraph()->HeapConstantNoHole(callable.code()));
  }
  return to_number_code_.get();
}

Node* SimplifiedLowering::ToNumberConvertBigIntCode() {
  if (!to_number_convert_big_int_code_.is_set()) {
    Callable callable =
        Builtins::CallableFor(isolate(), Builtin::kToNumberConvertBigInt);
    to_number_convert_big_int_code_.set(
        jsgraph()->HeapConstantNoHole(callable.code()));
  }
  return to_number_convert_big_int_code_.get();
}

Node* SimplifiedLowering::ToNumericCode() {
  if (!to_numeric_code_.is_set()) {
    Callable callable = Builtins::CallableFor(isolate(), Builtin::kToNumeric);
    to_numeric_code_.set(jsgraph()->HeapConstantNoHole(callable.code()));
  }
  return to_numeric_code_.get();
}

Operator const* SimplifiedLowering::ToNumberOperator() {
  if (!to_number_operator_.is_set()) {
    Callable callable = Builtins::CallableFor(isolate(), Builtin::kToNumber);
    CallDescriptor::Flags flags = CallDescriptor::kNeedsFrameState;
    auto call_descriptor = Linkage::GetStubCallDescriptor(
        graph()->zone(), callable.descriptor(),
        callable.descriptor().GetStackParameterCount(), flags,
        Operator::kNoProperties);
    to_number_operator_.set(common()->Call(call_descriptor));
  }
  return to_number_operator_.get();
}

Operator const* SimplifiedLowering::ToNumberConvertBigIntOperator() {
  if (!to_number_convert_big_int_operator_.is_set()) {
    Callable callable =
        Builtins::CallableFor(isolate(), Builtin::kToNumberConvertBigInt);
    CallDescriptor::Flags flags = CallDescriptor::kNeedsFrameState;
    auto call_descriptor = Linkage::GetStubCallDescriptor(
        graph()->zone(), callable.descriptor(),
        callable.descriptor().GetStackParameterCount(), flags,
        Operator::kNoProperties);
    to_number_convert_big_int_operator_.set(common()->Call(call_descriptor));
  }
  return to_number_convert_big_int_operator_.get();
}

Operator const* SimplifiedLowering::ToNumericOperator() {
  if (!to_numeric_operator_.is_set()) {
    Callable callable = Builtins::CallableFor(isolate(), Builtin::kToNumeric);
    CallDescriptor::Flags flags = CallDescriptor::kNeedsFrameState;
    auto call_descriptor = Linkage::GetStubCallDescriptor(
        graph()->zone(), callable.descriptor(),
        callable.descriptor().GetStackParameterCount(), flags,
        Operator::kNoProperties);
    to_numeric_operator_.set(common()->Call(call_descriptor));
  }
  return to_numeric_operator_.get();
}

void SimplifiedLowering::ChangeOp(Node* node, const Operator* new_op) {
  compiler::NodeProperties::ChangeOp(node, new_op);

  if (V8_UNLIKELY(observe_node_manager_ != nullptr))
    observe_node_manager_->OnNodeChanged(kSimplifiedLoweringReducerName, node,
                                         node);
}

#undef TRACE

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```