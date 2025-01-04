Response: The user wants a summary of the functionality of the C++ code in `v8/src/compiler/verifier.cc`. They also want to know if and how this code relates to JavaScript functionality, with an example if possible.

The code snippet provided defines a `Verifier` class, specifically its `Visitor` inner class and its `Check` and `CheckSwitch` methods. It appears to be performing validation checks on a graph-based intermediate representation used in the V8 compiler. These checks ensure the graph adheres to certain rules and constraints.

Here's a plan to address the user's request:

1. **Identify the core purpose:** Determine that the code is about validating the structure and properties of the compiler's intermediate representation.
2. **Explain the validation process:**  Highlight that the code iterates through nodes in the graph and performs checks based on their opcodes and connections.
3. **Connect to compiler phases:** Explain that this verification likely happens during or after the compilation process, ensuring the integrity of the generated code.
4. **Relate to JavaScript:** Explain that while this C++ code doesn't directly *execute* JavaScript, it plays a crucial role in ensuring that the *compiled* JavaScript code will behave correctly and efficiently.
5. **Provide a JavaScript example:**  Illustrate how a seemingly simple JavaScript construct gets translated into a more complex graph that the verifier would then check.
这个C++代码文件 `v8/src/compiler/verifier.cc` 的主要功能是**验证V8编译器生成的中间代码（通常被称为“图”或“IR”）的正确性**。

更具体地说，它实现了一个 `Verifier` 类，这个类能够遍历编译器生成的图结构，并对图中的每个节点进行一系列的检查，以确保：

* **图的结构是合法的:** 例如，确保节点之间的连接是有效的，没有悬空的引用，控制流和数据流符合预期。
* **节点的操作数类型是正确的:** 验证每个节点的输入和输出类型是否符合该操作的定义。例如，一个加法操作的输入应该是数值类型。
* **节点的属性是合法的:**  检查节点的一些特定属性是否设置正确。
* **是否存在潜在的错误或不一致性:**  例如，检查在可能抛出异常的节点之后，控制流是否正确地处理了成功和异常的情况。

**它与JavaScript的功能的关系在于，这个验证过程是V8编译器将JavaScript代码转换成高效的机器码的关键步骤之一。**  编译器在进行各种优化和代码生成之后，会使用 `verifier.cc` 中的代码来确保这些转换没有引入错误，最终生成的机器码能够按照JavaScript的语义正确执行。

**JavaScript 示例说明:**

考虑一个简单的 JavaScript 加法运算：

```javascript
function add(a, b) {
  return a + b;
}
```

当 V8 编译这个 `add` 函数时，它会生成一个表示这个函数操作的图结构。  这个图中可能包含以下类型的节点（这只是一个简化的例子）：

* **Parameter 节点:**  代表函数的参数 `a` 和 `b`。
* **JSAdd 节点:** 代表 JavaScript 的加法操作。它会连接到表示 `a` 和 `b` 的 Parameter 节点。
* **Return 节点:** 代表函数的返回操作，它会连接到 JSAdd 节点的输出。
* **Start 节点和 End 节点:**  表示图的开始和结束。

`verifier.cc` 中的代码就会对这个图进行检查，例如：

1. **对于 JSAdd 节点:**  它会检查连接到 JSAdd 节点的输入节点是否是合法的数值类型（或者可以被转换为数值类型）。
2. **对于 Return 节点:** 它会检查连接到 Return 节点的输入节点是否产生了一个值。
3. **对于整个图:** 它会检查控制流是否从 Start 节点开始，最终到达 End 节点，并且没有不可达的代码。

如果验证器发现任何错误，它会触发一个 `FATAL` 错误，表明编译过程中出现了严重的问题。这有助于在早期发现编译器中的 bug，并确保生成的代码的可靠性。

**总结一下，`verifier.cc` 的功能就像一个质量控制员，在 JavaScript 代码被编译成机器码的过程中，负责检查中间产物的正确性，以保证最终执行的代码能够按照预期运行。**

Prompt: 
```
这是目录为v8/src/compiler/verifier.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/verifier.h"

#include <algorithm>
#include <deque>
#include <queue>
#include <sstream>
#include <string>

#include "src/compiler/all-nodes.h"
#include "src/compiler/common-operator.h"
#include "src/compiler/js-operator.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/node.h"
#include "src/compiler/opcodes.h"
#include "src/compiler/operator-properties.h"
#include "src/compiler/operator.h"
#include "src/compiler/schedule.h"
#include "src/compiler/state-values-utils.h"
#include "src/compiler/turbofan-graph.h"
#include "src/compiler/type-cache.h"
#include "src/utils/bit-vector.h"

namespace v8 {
namespace internal {
namespace compiler {


class Verifier::Visitor {
 public:
  Visitor(Zone* z, Typing typed, CheckInputs check_inputs, CodeType code_type)
      : zone(z),
        typing(typed),
        check_inputs(check_inputs),
        code_type(code_type) {}

  void CheckSwitch(Node* node, const AllNodes& all);
  void Check(Node* node, const AllNodes& all);

  Zone* zone;
  Typing typing;
  CheckInputs check_inputs;
  CodeType code_type;

 private:
  void CheckNotTyped(Node* node) {
    // Verification of simplified lowering sets types of many additional nodes.
    if (v8_flags.verify_simplified_lowering) return;

    if (NodeProperties::IsTyped(node)) {
      std::ostringstream str;
      str << "TypeError: node #" << node->id() << ":" << *node->op()
          << " should never have a type";
      FATAL("%s", str.str().c_str());
    }
  }
  void CheckTypeIs(Node* node, Type type) {
    if (typing == TYPED && !NodeProperties::GetType(node).Is(type)) {
      std::ostringstream str;
      str << "TypeError: node #" << node->id() << ":" << *node->op() << " type "
          << NodeProperties::GetType(node) << " is not " << type;
      FATAL("%s", str.str().c_str());
    }
  }
  void CheckTypeMaybe(Node* node, Type type) {
    if (typing == TYPED && !NodeProperties::GetType(node).Maybe(type)) {
      std::ostringstream str;
      str << "TypeError: node #" << node->id() << ":" << *node->op() << " type "
          << NodeProperties::GetType(node) << " must intersect " << type;
      FATAL("%s", str.str().c_str());
    }
  }
  void CheckValueInputIs(Node* node, int i, Type type) {
    Node* input = NodeProperties::GetValueInput(node, i);
    if (typing == TYPED && !NodeProperties::GetType(input).Is(type)) {
      std::ostringstream str;
      str << "TypeError: node #" << node->id() << ":" << *node->op()
          << "(input @" << i << " = " << input->opcode() << ":"
          << input->op()->mnemonic() << ") type "
          << NodeProperties::GetType(input) << " is not " << type;
      FATAL("%s", str.str().c_str());
    }
  }
  void CheckOutput(Node* node, Node* use, int count, const char* kind) {
    if (count <= 0) {
      std::ostringstream str;
      str << "GraphError: node #" << node->id() << ":" << *node->op()
          << " does not produce " << kind << " output used by node #"
          << use->id() << ":" << *use->op();
      FATAL("%s", str.str().c_str());
    }
  }
};

void Verifier::Visitor::CheckSwitch(Node* node, const AllNodes& all) {
  // Count the number of {kIfValue} uses.
  int case_count = 0;
  bool expect_default = true;

  // Data structure to check that each {kIfValue} has a unique value.
  std::unordered_set<int32_t> if_value_parameters;

  Node::Uses uses = node->uses();
  for (const Node* use : uses) {
    CHECK(all.IsLive(use));
    switch (use->opcode()) {
      case IrOpcode::kIfValue: {
        // Check if each value is unique.
        CHECK(
            if_value_parameters.emplace(IfValueParametersOf(use->op()).value())
                .second);
        ++case_count;
        break;
      }
      case IrOpcode::kIfDefault: {
        // We expect exactly one {kIfDefault}.
        CHECK(expect_default);
        expect_default = false;
        break;
      }
      default: {
        FATAL("Switch #%d illegally used by #%d:%s", node->id(), use->id(),
              use->op()->mnemonic());
      }
    }
  }

  CHECK(!expect_default);
  // + 1 because of the one {kIfDefault}.
  CHECK_EQ(node->op()->ControlOutputCount(), case_count + 1);
  CheckNotTyped(node);
}

#ifdef DEBUG
namespace {
// Print more debug information just before a DCHECK failure.
bool FailSoon(Node* node) {
  v8::base::OS::PrintError("#\n# Verification failure for node:\n#\n");
  node->Print(std::cerr);
  return false;
}
}  // namespace
#endif  // DEBUG

void Verifier::Visitor::Check(Node* node, const AllNodes& all) {
  int value_count = node->op()->ValueInputCount();
  int context_count = OperatorProperties::GetContextInputCount(node->op());
  int frame_state_count =
      OperatorProperties::GetFrameStateInputCount(node->op());
  int effect_count = node->op()->EffectInputCount();
  int control_count = node->op()->ControlInputCount();

  // Verify number of inputs matches up.
  int input_count = value_count + context_count + frame_state_count;
  if (check_inputs == kAll) {
    input_count += effect_count + control_count;
  }
  CHECK_EQ(input_count, node->InputCount());

  // If this node has any effect outputs, make sure that it is
  // consumed as an effect input somewhere else.
  if (node->op()->EffectOutputCount() > 0) {
#ifdef DEBUG
    int effect_edges = 0;
    for (Edge edge : node->use_edges()) {
      if (all.IsLive(edge.from()) && NodeProperties::IsEffectEdge(edge)) {
        effect_edges++;
      }
    }
    if (effect_edges == 0) {
      FailSoon(node);
    }
    DCHECK_GT(effect_edges, 0);
#endif
  }

  // Verify that frame state has been inserted for the nodes that need it.
  for (int i = 0; i < frame_state_count; i++) {
    Node* frame_state = NodeProperties::GetFrameStateInput(node);
    CHECK(frame_state->opcode() == IrOpcode::kFrameState ||
          // kFrameState uses Start as a sentinel.
          (node->opcode() == IrOpcode::kFrameState &&
           frame_state->opcode() == IrOpcode::kStart));
  }

  // Verify all value inputs actually produce a value.
  for (int i = 0; i < value_count; ++i) {
    Node* value = NodeProperties::GetValueInput(node, i);
    CheckOutput(value, node, value->op()->ValueOutputCount(), "value");
    // Verify that only parameters and projections can have input nodes with
    // multiple outputs.
    CHECK(node->opcode() == IrOpcode::kParameter ||
          node->opcode() == IrOpcode::kProjection ||
          value->op()->ValueOutputCount() <= 1);
  }

  // Verify all context inputs are value nodes.
  for (int i = 0; i < context_count; ++i) {
    Node* context = NodeProperties::GetContextInput(node);
    CheckOutput(context, node, context->op()->ValueOutputCount(), "context");
  }

  if (check_inputs == kAll) {
    // Verify all effect inputs actually have an effect.
    for (int i = 0; i < effect_count; ++i) {
      Node* effect = NodeProperties::GetEffectInput(node);
      CheckOutput(effect, node, effect->op()->EffectOutputCount(), "effect");
    }

    // Verify all control inputs are control nodes.
    for (int i = 0; i < control_count; ++i) {
      Node* control = NodeProperties::GetControlInput(node, i);
      CheckOutput(control, node, control->op()->ControlOutputCount(),
                  "control");
    }

    // Verify that nodes that can throw either have both IfSuccess/IfException
    // projections as the only control uses or no projections at all.
    if (!node->op()->HasProperty(Operator::kNoThrow)) {
      Node* discovered_if_exception = nullptr;
      Node* discovered_if_success = nullptr;
      Node* discovered_direct_use = nullptr;
      int total_number_of_control_uses = 0;
      for (Edge edge : node->use_edges()) {
        if (!NodeProperties::IsControlEdge(edge)) {
          continue;
        }
        total_number_of_control_uses++;
        Node* control_use = edge.from();
        if (control_use->opcode() == IrOpcode::kIfSuccess) {
          CHECK_NULL(discovered_if_success);  // Only one allowed.
          discovered_if_success = control_use;
        } else if (control_use->opcode() == IrOpcode::kIfException) {
          CHECK_NULL(discovered_if_exception);  // Only one allowed.
          discovered_if_exception = control_use;
        } else {
          discovered_direct_use = control_use;
        }
      }
      if (discovered_if_success && !discovered_if_exception) {
        FATAL(
            "#%d:%s should be followed by IfSuccess/IfException, but is "
            "only followed by single #%d:%s",
            node->id(), node->op()->mnemonic(), discovered_if_success->id(),
            discovered_if_success->op()->mnemonic());
      }
      if (discovered_if_exception && !discovered_if_success) {
        FATAL(
            "#%d:%s should be followed by IfSuccess/IfException, but is "
            "only followed by single #%d:%s",
            node->id(), node->op()->mnemonic(), discovered_if_exception->id(),
            discovered_if_exception->op()->mnemonic());
      }
      if ((discovered_if_success || discovered_if_exception) &&
          total_number_of_control_uses != 2) {
        FATAL(
            "#%d:%s if followed by IfSuccess/IfException, there should be "
            "no direct control uses, but direct use #%d:%s was found",
            node->id(), node->op()->mnemonic(), discovered_direct_use->id(),
            discovered_direct_use->op()->mnemonic());
      }
    }
  }

  switch (node->opcode()) {
    case IrOpcode::kStart: {
      // Start has no inputs.
      CHECK_EQ(0, input_count);
      // Type is a tuple.
      // TODO(rossberg): Multiple outputs are currently typed as Internal.
      CheckTypeIs(node, Type::Internal());
      // Check that parameters are unique. We need this because the register
      // allocator gets confused when there are two identical parameters which
      // are both hard-assigned to the same register (such as the instance
      // parameter in wasm).
      std::unordered_set<int> param_indices;
      for (Node* use : node->uses()) {
        if (all.IsLive(use) && use->opcode() == IrOpcode::kParameter) {
          int index = ParameterIndexOf(use->op());
          CHECK_EQ(param_indices.count(index), 0);
          param_indices.insert(index);
        }
      }
      break;
    }
    case IrOpcode::kEnd:
      // End has no outputs.
      CHECK_EQ(0, node->op()->ValueOutputCount());
      CHECK_EQ(0, node->op()->EffectOutputCount());
      CHECK_EQ(0, node->op()->ControlOutputCount());
      // All inputs are graph terminators.
      for (const Node* input : node->inputs()) {
        CHECK(IrOpcode::IsGraphTerminator(input->opcode()));
      }
      CheckNotTyped(node);
      break;
    case IrOpcode::kDead:
      // Dead is never connected to the graph.
      UNREACHABLE();
    case IrOpcode::kDeadValue:
      CheckValueInputIs(node, 0, Type::None());
      CheckTypeIs(node, Type::None());
      break;
    case IrOpcode::kUnreachable:
      CheckTypeIs(node, Type::None());
      for (Edge edge : node->use_edges()) {
        Node* use = edge.from();
        if (NodeProperties::IsValueEdge(edge) && all.IsLive(use)) {
          // {Unreachable} nodes can only be used by {DeadValue}, because they
          // don't actually produce a value.
          CHECK_EQ(IrOpcode::kDeadValue, use->opcode());
        }
      }
      break;
    case IrOpcode::kBranch: {
      // Branch uses are IfTrue and IfFalse.
      int count_true = 0, count_false = 0;
      for (const Node* use : node->uses()) {
        CHECK(all.IsLive(use) && (use->opcode() == IrOpcode::kIfTrue ||
                                  use->opcode() == IrOpcode::kIfFalse));
        if (use->opcode() == IrOpcode::kIfTrue) ++count_true;
        if (use->opcode() == IrOpcode::kIfFalse) ++count_false;
      }
      CHECK_EQ(1, count_true);
      CHECK_EQ(1, count_false);
      switch (BranchParametersOf(node->op()).semantics()) {
        case BranchSemantics::kJS:
        case BranchSemantics::kUnspecified:
          // The condition must be a Boolean.
          CheckValueInputIs(node, 0, Type::Boolean());
          break;
        case BranchSemantics::kMachine:
          CheckValueInputIs(node, 0, Type::Machine());
          break;
      }
      CheckNotTyped(node);
      break;
    }
    case IrOpcode::kIfTrue:
    case IrOpcode::kIfFalse: {
      Node* control = NodeProperties::GetControlInput(node, 0);
      CHECK_EQ(IrOpcode::kBranch, control->opcode());
      CheckNotTyped(node);
      break;
    }
    case IrOpcode::kIfSuccess: {
      // IfSuccess and IfException continuation only on throwing nodes.
      Node* input = NodeProperties::GetControlInput(node, 0);
      CHECK(!input->op()->HasProperty(Operator::kNoThrow));
      CheckNotTyped(node);
      break;
    }
    case IrOpcode::kIfException: {
      // IfSuccess and IfException continuation only on throwing nodes.
      Node* input = NodeProperties::GetControlInput(node, 0);
      CHECK(!input->op()->HasProperty(Operator::kNoThrow));
      CheckTypeIs(node, Type::Any());
      break;
    }
    case IrOpcode::kSwitch: {
      CheckSwitch(node, all);
      break;
    }
    case IrOpcode::kIfValue:
    case IrOpcode::kIfDefault:
      CHECK_EQ(IrOpcode::kSwitch,
               NodeProperties::GetControlInput(node)->opcode());
      CheckNotTyped(node);
      break;
    case IrOpcode::kLoop: {
      CHECK_EQ(control_count, input_count);
      CheckNotTyped(node);
      // All loops need to be connected to a {Terminate} node to ensure they
      // stay connected to the graph end.
      bool has_terminate = false;
      for (const Node* use : node->uses()) {
        if (all.IsLive(use) && use->opcode() == IrOpcode::kTerminate) {
          has_terminate = true;
          break;
        }
      }
      CHECK(has_terminate);
      break;
    }
    case IrOpcode::kMerge:
      CHECK_EQ(control_count, input_count);
      CheckNotTyped(node);
      break;
    case IrOpcode::kDeoptimizeIf:
    case IrOpcode::kDeoptimizeUnless:
    case IrOpcode::kPlug:
    case IrOpcode::kTrapIf:
    case IrOpcode::kTrapUnless:
    case IrOpcode::kAssert:
      CheckNotTyped(node);
      break;
    case IrOpcode::kDeoptimize:
    case IrOpcode::kReturn:
    case IrOpcode::kThrow:
      // Deoptimize, Return and Throw uses are End.
      for (const Node* use : node->uses()) {
        if (all.IsLive(use)) {
          CHECK_EQ(IrOpcode::kEnd, use->opcode());
        }
      }
      CheckNotTyped(node);
      break;
    case IrOpcode::kTerminate:
      // Terminates take one loop and effect.
      CHECK_EQ(1, control_count);
      CHECK_EQ(1, effect_count);
      CHECK_EQ(2, input_count);
      CHECK_EQ(IrOpcode::kLoop,
               NodeProperties::GetControlInput(node)->opcode());
      // Terminate uses are End.
      for (const Node* use : node->uses()) {
        if (all.IsLive(use)) {
          CHECK_EQ(IrOpcode::kEnd, use->opcode());
        }
      }
      CheckNotTyped(node);
      break;

    // Common operators
    // ----------------
    case IrOpcode::kParameter: {
      // Parameters have the start node as inputs.
      CHECK_EQ(1, input_count);
      // Parameter has an input that produces enough values.
      int const index = ParameterIndexOf(node->op());
      StartNode start{NodeProperties::GetValueInput(node, 0)};
      // Currently, parameter indices start at -1 instead of 0.
      CHECK_LE(-1, index);
      CHECK_LE(index, start.LastParameterIndex_MaybeNonStandardLayout());
      CheckTypeIs(node, Type::Any());
      break;
    }
    case IrOpcode::kInt32Constant:    // TODO(turbofan): rename Word32Constant?
    case IrOpcode::kInt64Constant: {  // TODO(turbofan): rename Word64Constant?
      // Constants have no inputs.
      CHECK_EQ(0, input_count);
      // Wasm numeric constants have types. However, since wasm only gets
      // verified in untyped mode, we do not need to check that the types match.
      // TODO(manoskouk): Verify the type if wasm runs in typed mode.
      if (code_type != kWasm) CheckTypeIs(node, Type::Machine());
      break;
    }
    case IrOpcode::kFloat32Constant:
    case IrOpcode::kFloat64Constant: {
      // Constants have no inputs.
      CHECK_EQ(0, input_count);
      // Wasm numeric constants have types. However, since wasm only gets
      // verified in untyped mode, we do not need to check that the types match.
      // TODO(manoskouk): Verify the type if wasm runs in typed mode.
      if (code_type != kWasm) CheckNotTyped(node);
      break;
    }
    case IrOpcode::kTaggedIndexConstant:
    case IrOpcode::kRelocatableInt32Constant:
    case IrOpcode::kRelocatableInt64Constant:
      // Constants have no inputs.
      CHECK_EQ(0, input_count);
      CheckNotTyped(node);
      break;
    case IrOpcode::kNumberConstant:
      // Constants have no inputs.
      CHECK_EQ(0, input_count);
      CheckTypeIs(node, Type::Number());
      break;
    case IrOpcode::kHeapConstant:
    case IrOpcode::kCompressedHeapConstant:
    case IrOpcode::kTrustedHeapConstant:
      // Constants have no inputs.
      CHECK_EQ(0, input_count);
      CheckTypeIs(node, Type::Any());
      break;
    case IrOpcode::kExternalConstant:
    case IrOpcode::kPointerConstant:
      // Constants have no inputs.
      CHECK_EQ(0, input_count);
      CheckTypeIs(node, Type::ExternalPointer());
      break;
    case IrOpcode::kOsrValue:
      // OSR values have a value and a control input.
      CHECK_EQ(1, control_count);
      CHECK_EQ(1, input_count);
      // Type is merged from other values in the graph and could be any.
      CheckTypeIs(node, Type::Any());
      break;
    case IrOpcode::kProjection: {
      // Projection has an input that produces enough values.
      int index = static_cast<int>(ProjectionIndexOf(node->op()));
      Node* input = NodeProperties::GetValueInput(node, 0);
      CHECK_GT(input->op()->ValueOutputCount(), index);
      CheckTypeIs(node, Type::Any());
      break;
    }
    case IrOpcode::kSelect: {
      CHECK_EQ(0, effect_count);
      CHECK_EQ(0, control_count);
      CHECK_EQ(3, value_count);
      // The condition must be a Boolean.
      CheckValueInputIs(node, 0, Type::Boolean());
      CheckTypeIs(node, Type::Any());
      break;
    }
    case IrOpcode::kPhi: {
      // Phi input count matches parent control node.
      CHECK_EQ(0, effect_count);
      CHECK_EQ(1, control_count);
      Node* control = NodeProperties::GetControlInput(node, 0);
      CHECK_EQ(value_count, control->op()->ControlInputCount());
      CHECK_EQ(input_count, 1 + value_count);
      // Type must be subsumed by all input types.
      // TODO(rossberg): for now at least, narrowing does not really hold.
      /*
      for (int i = 0; i < value_count; ++i) {
        CHECK(type_of(ValueInput(node, i))->Is(type_of(node)));
      }
      */
      break;
    }
    case IrOpcode::kInductionVariablePhi: {
      // This is only a temporary node for the typer.
      UNREACHABLE();
    }
    case IrOpcode::kEffectPhi: {
      // EffectPhi input count matches parent control node.
      CHECK_EQ(0, value_count);
      CHECK_EQ(1, control_count);
      Node* control = NodeProperties::GetControlInput(node, 0);
      CHECK_EQ(effect_count, control->op()->ControlInputCount());
      CHECK_EQ(input_count, 1 + effect_count);
      // If the control input is a Merge, then make sure that at least one of
      // its usages is non-phi.
      if (control->opcode() == IrOpcode::kMerge) {
        bool non_phi_use_found = false;
        for (Node* use : control->uses()) {
          if (all.IsLive(use) && use->opcode() != IrOpcode::kEffectPhi &&
              use->opcode() != IrOpcode::kPhi) {
            non_phi_use_found = true;
          }
        }
        CHECK(non_phi_use_found);
      }
      break;
    }
    case IrOpcode::kLoopExit: {
      CHECK_EQ(2, control_count);
      Node* loop = NodeProperties::GetControlInput(node, 1);
      CHECK_EQ(IrOpcode::kLoop, loop->opcode());
      break;
    }
    case IrOpcode::kLoopExitValue: {
      CHECK_EQ(1, control_count);
      Node* loop_exit = NodeProperties::GetControlInput(node, 0);
      CHECK_EQ(IrOpcode::kLoopExit, loop_exit->opcode());
      break;
    }
    case IrOpcode::kLoopExitEffect: {
      CHECK_EQ(1, control_count);
      Node* loop_exit = NodeProperties::GetControlInput(node, 0);
      CHECK_EQ(IrOpcode::kLoopExit, loop_exit->opcode());
      break;
    }
    case IrOpcode::kCheckpoint:
      CheckNotTyped(node);
      break;
    case IrOpcode::kBeginRegion:
      // TODO(rossberg): what are the constraints on these?
      break;
    case IrOpcode::kFinishRegion: {
      // TODO(rossberg): what are the constraints on these?
      // Type must be subsumed by input type.
      if (typing == TYPED) {
        Node* val = NodeProperties::GetValueInput(node, 0);
        CHECK(NodeProperties::GetType(val).Is(NodeProperties::GetType(node)));
      }
      break;
    }
    case IrOpcode::kFrameState: {
      // TODO(jarin): what are the constraints on these?
      CHECK_EQ(5, value_count);
      CHECK_EQ(0, control_count);
      CHECK_EQ(0, effect_count);
      CHECK_EQ(6, input_count);

      FrameState state{node};
      CHECK(state.parameters()->opcode() == IrOpcode::kStateValues ||
            state.parameters()->opcode() == IrOpcode::kTypedStateValues);
      CHECK(state.locals()->opcode() == IrOpcode::kStateValues ||
            state.locals()->opcode() == IrOpcode::kTypedStateValues);

      // Checks that the state input is empty for all but kInterpretedFunction
      // frames, where it should have size one.
      {
        const FrameStateFunctionInfo* func_info =
            state.frame_state_info().function_info();
        CHECK_EQ(func_info->parameter_count(),
                 StateValuesAccess(state.parameters()).size());
        CHECK_EQ(func_info->local_count(),
                 StateValuesAccess(state.locals()).size());

        Node* accumulator = state.stack();
        if (func_info->type() == FrameStateType::kUnoptimizedFunction) {
          // The accumulator (InputAt(2)) cannot be kStateValues.
          // It can be kTypedStateValues (to signal the type) and it can have
          // other Node types including that of the optimized_out HeapConstant.
          CHECK_NE(accumulator->opcode(), IrOpcode::kStateValues);
          if (accumulator->opcode() == IrOpcode::kTypedStateValues) {
            CHECK_EQ(1, StateValuesAccess(accumulator).size());
          }
        } else {
          CHECK(accumulator->opcode() == IrOpcode::kTypedStateValues ||
                accumulator->opcode() == IrOpcode::kStateValues);
          CHECK_EQ(0, StateValuesAccess(accumulator).size());
        }
      }
      break;
    }
    case IrOpcode::kObjectId:
      CheckTypeIs(node, Type::Object());
      break;
    case IrOpcode::kStateValues:
    case IrOpcode::kTypedStateValues:
    case IrOpcode::kArgumentsElementsState:
    case IrOpcode::kArgumentsLengthState:
    case IrOpcode::kObjectState:
    case IrOpcode::kTypedObjectState:
      // TODO(jarin): what are the constraints on these?
      break;
    case IrOpcode::kCall:
      // TODO(rossberg): what are the constraints on these?
      break;
    case IrOpcode::kTailCall:
      // TODO(bmeurer): what are the constraints on these?
      break;
    case IrOpcode::kEnterMachineGraph:
      CheckTypeIs(node, Type::Machine());
      break;
    case IrOpcode::kExitMachineGraph:
      CheckValueInputIs(node, 0, Type::Machine());
      break;

    // JavaScript operators
    // --------------------
    case IrOpcode::kJSEqual:
    case IrOpcode::kJSStrictEqual:
    case IrOpcode::kJSLessThan:
    case IrOpcode::kJSGreaterThan:
    case IrOpcode::kJSLessThanOrEqual:
    case IrOpcode::kJSGreaterThanOrEqual:
      CheckTypeIs(node, Type::Boolean());
      break;

    case IrOpcode::kJSAdd:
      CheckTypeIs(node, Type::NumericOrString());
      break;
    case IrOpcode::kJSBitwiseOr:
    case IrOpcode::kJSBitwiseXor:
    case IrOpcode::kJSBitwiseAnd:
    case IrOpcode::kJSShiftLeft:
    case IrOpcode::kJSShiftRight:
    case IrOpcode::kJSShiftRightLogical:
    case IrOpcode::kJSSubtract:
    case IrOpcode::kJSMultiply:
    case IrOpcode::kJSDivide:
    case IrOpcode::kJSModulus:
    case IrOpcode::kJSExponentiate:
    case IrOpcode::kJSBitwiseNot:
    case IrOpcode::kJSDecrement:
    case IrOpcode::kJSIncrement:
    case IrOpcode::kJSNegate:
      CheckTypeIs(node, Type::Numeric());
      break;

    case IrOpcode::kToBoolean:
      CheckTypeIs(node, Type::Boolean());
      break;
    case IrOpcode::kJSToLength:
      CheckTypeIs(node, Type::Range(0, kMaxSafeInteger, zone));
      break;
    case IrOpcode::kJSToName:
      CheckTypeIs(node, Type::Name());
      break;
    case IrOpcode::kJSToNumber:
    case IrOpcode::kJSToNumberConvertBigInt:
      CheckTypeIs(node, Type::Number());
      break;
    case IrOpcode::kJSToBigInt:
    case IrOpcode::kJSToBigIntConvertNumber:
      CheckTypeIs(node, Type::BigInt());
      break;
    case IrOpcode::kJSToNumeric:
      CheckTypeIs(node, Type::Numeric());
      break;
    case IrOpcode::kJSToString:
      CheckTypeIs(node, Type::String());
      break;
    case IrOpcode::kJSToObject:
      CheckTypeIs(node, Type::Receiver());
      break;
    case IrOpcode::kJSParseInt:
      CheckValueInputIs(node, 0, Type::Any());
      CheckValueInputIs(node, 1, Type::Any());
      CheckTypeIs(node, Type::Number());
      break;
    case IrOpcode::kJSRegExpTest:
      CheckValueInputIs(node, 0, Type::Any());
      CheckValueInputIs(node, 1, Type::String());
      CheckTypeIs(node, Type::Boolean());
      break;
    case IrOpcode::kJSCreate:
      CheckTypeIs(node, Type::Object());
      break;
    case IrOpcode::kJSCreateArguments:
      CheckTypeIs(node, Type::ArrayOrOtherObject());
      break;
    case IrOpcode::kJSCreateArray:
      CheckTypeIs(node, Type::Array());
      break;
    case IrOpcode::kJSCreateArrayIterator:
      CheckTypeIs(node, Type::OtherObject());
      break;
    case IrOpcode::kJSCreateAsyncFunctionObject:
      CheckTypeIs(node, Type::OtherObject());
      break;
    case IrOpcode::kJSCreateCollectionIterator:
      CheckTypeIs(node, Type::OtherObject());
      break;
    case IrOpcode::kJSCreateBoundFunction:
      CheckTypeIs(node, Type::BoundFunction());
      break;
    case IrOpcode::kJSCreateClosure:
      CheckTypeIs(node, Type::Function());
      break;
    case IrOpcode::kJSCreateIterResultObject:
      CheckTypeIs(node, Type::OtherObject());
      break;
    case IrOpcode::kJSCreateStringIterator:
      CheckTypeIs(node, Type::OtherObject());
      break;
    case IrOpcode::kJSCreateKeyValueArray:
      CheckTypeIs(node, Type::Array());
      break;
    case IrOpcode::kJSCreateObject:
      CheckTypeIs(node, Type::OtherObject());
      break;
    case IrOpcode::kJSCreateStringWrapper:
      CheckTypeIs(node, Type::StringWrapper());
      break;
    case IrOpcode::kJSCreatePromise:
      CheckTypeIs(node, Type::OtherObject());
      break;
    case IrOpcode::kJSCreateTypedArray:
      CheckTypeIs(node, Type::OtherObject());
      break;
    case IrOpcode::kJSCreateLiteralArray:
      CheckTypeIs(node, Type::Array());
      break;
    case IrOpcode::kJSCreateEmptyLiteralArray:
      CheckTypeIs(node, Type::Array());
      break;
    case IrOpcode::kJSCreateArrayFromIterable:
      CheckTypeIs(node, Type::Array());
      break;
    case IrOpcode::kJSCreateLiteralObject:
    case IrOpcode::kJSCreateEmptyLiteralObject:
    case IrOpcode::kJSCloneObject:
    case IrOpcode::kJSCreateLiteralRegExp:
      CheckTypeIs(node, Type::OtherObject());
      break;
    case IrOpcode::kJSGetTemplateObject:
      CheckTypeIs(node, Type::Array());
      break;
    case IrOpcode::kJSLoadProperty:
      CheckTypeIs(node, Type::Any());
      CHECK(PropertyAccessOf(node->op()).feedback().IsValid());
      break;
    case IrOpcode::kJSLoadNamed:
      CheckTypeIs(node, Type::Any());
      break;
    case IrOpcode::kJSLoadNamedFromSuper:
      CheckTypeIs(node, Type::Any());
      break;
    case IrOpcode::kJSLoadGlobal:
      CheckTypeIs(node, Type::Any());
      CHECK(LoadGlobalParametersOf(node->op()).feedback().IsValid());
      break;
    case IrOpcode::kJSSetKeyedProperty:
      CheckNotTyped(node);
      CHECK(PropertyAccessOf(node->op()).feedback().IsValid());
      break;
    case IrOpcode::kJSDefineKeyedOwnProperty:
      CheckNotTyped(node);
      CHECK(PropertyAccessOf(node->op()).feedback().IsValid());
      break;
    case IrOpcode::kJSSetNamedProperty:
      CheckNotTyped(node);
      break;
    case IrOpcode::kJSStoreGlobal:
      CheckNotTyped(node);
      CHECK(StoreGlobalParametersOf(node->op()).feedback().IsValid());
      break;
    case IrOpcode::kJSDefineNamedOwnProperty:
      CheckNotTyped(node);
      CHECK(
          DefineNamedOwnPropertyParametersOf(node->op()).feedback().IsValid());
      break;
    case IrOpcode::kJSGetIterator:
      CheckValueInputIs(node, 0, Type::Any());
      CheckTypeIs(node, Type::Any());
      break;
    case IrOpcode::kJSDefineKeyedOwnPropertyInLiteral:
    case IrOpcode::kJSStoreInArrayLiteral:
      CheckNotTyped(node);
      CHECK(FeedbackParameterOf(node->op()).feedback().IsValid());
      break;
    case IrOpcode::kJSDeleteProperty:
    case IrOpcode::kJSHasProperty:
    case IrOpcode::kJSHasInPrototypeChain:
    case IrOpcode::kJSInstanceOf:
    case IrOpcode::kJSOrdinaryHasInstance:
      CheckTypeIs(node, Type::Boolean());
      break;
    case IrOpcode::kTypeOf:
      CheckTypeIs(node, Type::InternalizedString());
      break;
    case IrOpcode::kJSGetSuperConstructor:
      // We don't check the input for Type::Function because this_function can
      // be context-allocated.
      CheckValueInputIs(node, 0, Type::Any());
      CheckTypeIs(node, Type::NonInternal());
      break;
    case IrOpcode::kJSFindNonDefaultConstructorOrConstruct:
      CheckValueInputIs(node, 0, Type::Any());
      CheckValueInputIs(node, 1, Type::Any());
      break;
    case IrOpcode::kJSHasContextExtension:
      CheckTypeIs(node, Type::Boolean());
      break;
    case IrOpcode::kJSLoadContext:
    case IrOpcode::kJSLoadScriptContext:
      CheckTypeIs(node, Type::Any());
      break;
    case IrOpcode::kJSStoreContext:
    case IrOpcode::kJSStoreScriptContext:
      CheckNotTyped(node);
      break;
    case IrOpcode::kJSCreateFunctionContext:
    case IrOpcode::kJSCreateCatchContext:
    case IrOpcode::kJSCreateWithContext:
    case IrOpcode::kJSCreateBlockContext: {
      CheckTypeIs(node, Type::OtherInternal());
      break;
    }

    case IrOpcode::kJSConstructForwardVarargs:
    case IrOpcode::kJSConstructForwardAllArgs:
    case IrOpcode::kJSConstruct:
    case IrOpcode::kJSConstructWithArrayLike:
    case IrOpcode::kJSConstructWithSpread:
      CheckTypeIs(node, Type::Receiver());
      break;
    case IrOpcode::kJSCallForwardVarargs:
    case IrOpcode::kJSCall:
    case IrOpcode::kJSCallWithArrayLike:
    case IrOpcode::kJSCallWithSpread:
    case IrOpcode::kJSCallRuntime:
      CheckTypeIs(node, Type::Any());
      break;

    case IrOpcode::kJSForInEnumerate:
      CheckValueInputIs(node, 0, Type::Any());
      CheckTypeIs(node, Type::OtherInternal());
      break;
    case IrOpcode::kJSForInPrepare:
      CheckTypeIs(node, Type::Any());
      break;
    case IrOpcode::kJSForInNext:
      CheckTypeIs(node, Type::Union(Type::Name(), Type::Undefined(), zone));
      break;

    case IrOpcode::kJSLoadMessage:
    case IrOpcode::kJSStoreMessage:
      break;

    case IrOpcode::kJSLoadModule:
      CheckTypeIs(node, Type::Any());
      break;
    case IrOpcode::kJSStoreModule:
      CheckNotTyped(node);
      break;

    case IrOpcode::kJSGetImportMeta:
      CheckTypeIs(node, Type::Any());
      break;

    case IrOpcode::kJSGeneratorStore:
      CheckNotTyped(node);
      break;

    case IrOpcode::kJSCreateGeneratorObject:
      CheckTypeIs(node, Type::OtherObject());
      break;

    case IrOpcode::kJSGeneratorRestoreContinuation:
      CheckTypeIs(node, Type::SignedSmall());
      break;

    case IrOpcode::kJSGeneratorRestoreContext:
      CheckTypeIs(node, Type::Any());
      break;

    case IrOpcode::kJSGeneratorRestoreRegister:
      CheckTypeIs(node, Type::Any());
      break;

    case IrOpcode::kJSGeneratorRestoreInputOrDebugPos:
      CheckTypeIs(node, Type::Any());
      break;

    case IrOpcode::kJSStackCheck:
    case IrOpcode::kJSDebugger:
      CheckNotTyped(node);
      break;

    case IrOpcode::kJSAsyncFunctionEnter:
      CheckValueInputIs(node, 0, Type::Any());
      CheckValueInputIs(node, 1, Type::Any());
      CheckTypeIs(node, Type::OtherObject());
      break;
    case IrOpcode::kJSAsyncFunctionReject:
      CheckValueInputIs(node, 0, Type::Any());
      CheckValueInputIs(node, 1, Type::Any());
      CheckTypeIs(node, Type::OtherObject());
      break;
    case IrOpcode::kJSAsyncFunctionResolve:
      CheckValueInputIs(node, 0, Type::Any());
      CheckValueInputIs(node, 1, Type::Any());
      CheckTypeIs(node, Type::OtherObject());
      break;
    case IrOpcode::kJSFulfillPromise:
      CheckValueInputIs(node, 0, Type::Any());
      CheckValueInputIs(node, 1, Type::Any());
      CheckTypeIs(node, Type::Undefined());
      break;
    case IrOpcode::kJSPerformPromiseThen:
      CheckValueInputIs(node, 0, Type::Any());
      CheckValueInputIs(node, 1, Type::Any());
      CheckValueInputIs(node, 2, Type::Any());
      CheckValueInputIs(node, 3, Type::Any());
      CheckTypeIs(node, Type::Receiver());
      break;
    case IrOpcode::kJSPromiseResolve:
      CheckValueInputIs(node, 0, Type::Any());
      CheckValueInputIs(node, 1, Type::Any());
      CheckTypeIs(node, Type::Receiver());
      break;
    case IrOpcode::kJSRejectPromise:
      CheckValueInputIs(node, 0, Type::Any());
      CheckValueInputIs(node, 1, Type::Any());
      CheckValueInputIs(node, 2, Type::Any());
      CheckTypeIs(node, Type::Undefined());
      break;
    case IrOpcode::kJSResolvePromise:
      CheckValueInputIs(node, 0, Type::Any());
      CheckValueInputIs(node, 1, Type::Any());
      CheckTypeIs(node, Type::Undefined());
      break;
    case IrOpcode::kJSObjectIsArray:
      CheckValueInputIs(node, 0, Type::Any());
      CheckTypeIs(node, Type::Boolean());
      break;

    case IrOpcode::kComment:
    case IrOpcode::kAbortCSADcheck:
    case IrOpcode::kDebugBreak:
    case IrOpcode::kRetain:
    case IrOpcode::kRuntimeAbort:
      CheckNotTyped(node);
      break;

    // Simplified operators
    // -------------------------------
    case IrOpcode::kBooleanNot:
      CheckValueInputIs(node, 0, Type::Boolean());
      CheckTypeIs(node, Type::Boolean());
      break;
    case IrOpcode::kNumberEqual:
      CheckValueInputIs(node, 0, Type::Number());
      CheckValueInputIs(node, 1, Type::Number());
      CheckTypeIs(node, Type::Boolean());
      break;
    case IrOpcode::kNumberLessThan:
    case IrOpcode::kNumberLessThanOrEqual:
      CheckValueInputIs(node, 0, Type::Number());
      CheckValueInputIs(node, 1, Type::Number());
      CheckTypeIs(node, Type::Boolean());
      break;
    case IrOpcode::kSpeculativeSafeIntegerAdd:
    case IrOpcode::kSpeculativeSafeIntegerSubtract:
    case IrOpcode::kSpeculativeNumberAdd:
    case IrOpcode::kSpeculativeNumberSubtract:
    case IrOpcode::kSpeculativeNumberMultiply:
    case IrOpcode::kSpeculativeNumberPow:
    case IrOpcode::kSpeculativeNumberDivide:
    case IrOpcode::kSpeculativeNumberModulus:
      CheckTypeIs(node, Type::Number());
      break;
    case IrOpcode::kSpeculativeNumberEqual:
    case IrOpcode::kSpeculativeNumberLessThan:
    case IrOpcode::kSpeculativeNumberLessThanOrEqual:
      CheckTypeIs(node, Type::Boolean());
      break;
#define SPECULATIVE_BIGINT_BINOP(Name) case IrOpcode::k##Name:
      SIMPLIFIED_SPECULATIVE_BIGINT_BINOP_LIST(SPECULATIVE_BIGINT_BINOP)
#undef SPECULATIVE_BIGINT_BINOP
      CheckTypeIs(node, Type::BigInt());
      break;
    case IrOpcode::kSpeculativeBigIntEqual:
    case IrOpcode::kSpeculativeBigIntLessThan:
    case IrOpcode::kSpeculativeBigIntLessThanOrEqual:
      CheckTypeIs(node, Type::Boolean());
      break;
    case IrOpcode::kSpeculativeBigIntNegate:
      CheckTypeIs(node, Type::BigInt());
      break;
    case IrOpcode::kSpeculativeBigIntAsIntN:
    case IrOpcode::kSpeculativeBigIntAsUintN:
      CheckValueInputIs(node, 0, Type::Any());
      CheckTypeIs(node, Type::BigInt());
      break;
#define BIGINT_BINOP(Name) case IrOpcode::k##Name:
      SIMPLIFIED_BIGINT_BINOP_LIST(BIGINT_BINOP)
#undef BIGINT_BINOP
      CheckValueInputIs(node, 0, Type::BigInt());
      CheckValueInputIs(node, 1, Type::BigInt());
      CheckTypeIs(node, Type::BigInt());
      break;
    case IrOpcode::kBigIntEqual:
    case IrOpcode::kBigIntLessThan:
    case IrOpcode::kBigIntLessThanOrEqual:
      CheckValueInputIs(node, 0, Type::BigInt());
      CheckValueInputIs(node, 1, Type::BigInt());
      CheckTypeIs(node, Type::Boolean());
      break;
    case IrOpcode::kBigIntNegate:
      CheckValueInputIs(node, 0, Type::BigInt());
      CheckTypeIs(node, Type::BigInt());
      break;
    case IrOpcode::kSpeculativeToBigInt:
      CheckValueInputIs(node, 0, Type::Any());
      CheckTypeIs(node, Type::BigInt());
      break;
    case IrOpcode::kNumberAdd:
    case IrOpcode::kNumberSubtract:
    case IrOpcode::kNumberMultiply:
    case IrOpcode::kNumberDivide:
      CheckValueInputIs(node, 0, Type::Number());
      CheckValueInputIs(node, 1, Type::Number());
      CheckTypeIs(node, Type::Number());
      break;
    case IrOpcode::kNumberModulus:
      CheckValueInputIs(node, 0, Type::Number());
      CheckValueInputIs(node, 1, Type::Number());
      CheckTypeIs(node, Type::Number());
      break;
    case IrOpcode::kNumberBitwiseOr:
    case IrOpcode::kNumberBitwiseXor:
    case IrOpcode::kNumberBitwiseAnd:
      CheckValueInputIs(node, 0, Type::Signed32());
      CheckValueInputIs(node, 1, Type::Signed32());
      CheckTypeIs(node, Type::Signed32());
      break;
    case IrOpcode::kSpeculativeNumberBitwiseOr:
    case IrOpcode::kSpeculativeNumberBitwiseXor:
    case IrOpcode::kSpeculativeNumberBitwiseAnd:
      CheckTypeIs(node, Type::Signed32());
      break;
    case IrOpcode::kNumberShiftLeft:
    case IrOpcode::kNumberShiftRight:
      CheckValueInputIs(node, 0, Type::Signed32());
      CheckValueInputIs(node, 1, Type::Unsigned32());
      CheckTypeIs(node, Type::Signed32());
      break;
    case IrOpcode::kSpeculativeNumberShiftLeft:
    case IrOpcode::kSpeculativeNumberShiftRight:
      CheckTypeIs(node, Type::Signed32());
      break;
    case IrOpcode::kNumberShiftRightLogical:
      CheckValueInputIs(node, 0, Type::Unsigned32());
      CheckValueInputIs(node, 1, Type::Unsigned32());
      CheckTypeIs(node, Type::Unsigned32());
      break;
    case IrOpcode::kSpeculativeNumberShiftRightLogical:
      CheckTypeIs(node, Type::Unsigned32());
      break;
    case IrOpcode::kNumberImul:
      CheckValueInputIs(node, 0, Type::Unsigned32());
      CheckValueInputIs(node, 1, Type::Unsigned32());
      CheckTypeIs(node, Type::Signed32());
      break;
    case IrOpcode::kNumberClz32:
      CheckValueInputIs(node, 0, Type::Unsigned32());
      CheckTypeIs(node, Type::Unsigned32());
      break;
    case IrOpcode::kNumberAtan2:
    case IrOpcode::kNumberMax:
    case IrOpcode::kNumberMin:
    case IrOpcode::kNumberPow:
      CheckValueInputIs(node, 0, Type::Number());
      CheckValueInputIs(node, 1, Type::Number());
      CheckTypeIs(node, Type::Number());
      break;
    case IrOpcode::kNumberAbs:
    case IrOpcode::kNumberCeil:
    case IrOpcode::kNumberFloor:
    case IrOpcode::kNumberFround:
    case IrOpcode::kNumberAcos:
    case IrOpcode::kNumberAcosh:
    case IrOpcode::kNumberAsin:
    case IrOpcode::kNumberAsinh:
    case IrOpcode::kNumberAtan:
    case IrOpcode::kNumberAtanh:
    case IrOpcode::kNumberCos:
    case IrOpcode::kNumberCosh:
    case IrOpcode::kNumberExp:
    case IrOpcode::kNumberExpm1:
    case IrOpcode::kNumberLog:
    case IrOpcode::kNumberLog1p:
    case IrOpcode::kNumberLog2:
    case IrOpcode::kNumberLog10:
    case IrOpcode::kNumberCbrt:
    case IrOpcode::kNumberRound:
    case IrOpcode::kNumberSign:
    case IrOpcode::kNumberSin:
    case IrOpcode::kNumberSinh:
    case IrOpcode::kNumberSqrt:
    case IrOpcode::kNumberTan:
    case IrOpcode::kNumberTanh:
    case IrOpcode::kNumberTrunc:
      CheckValueInputIs(node, 0, Type::Number());
      CheckTypeIs(node, Type::Number());
      break;
    case IrOpcode::kNumberToBoolean:
      CheckValueInputIs(node, 0, Type::Number());
      CheckTypeIs(node, Type::Boolean());
      break;
    case IrOpcode::kNumberToInt32:
      CheckValueInputIs(node, 0, Type::Number());
      CheckTypeIs(node, Type::Signed32());
      break;
    case IrOpcode::kNumberToString:
      CheckValueInputIs(node, 0, Type::Number());
      CheckTypeIs(node, Type::String());
      break;
    case IrOpcode::kNumberToUint32:
    case IrOpcode::kNumberToUint8Clamped:
      CheckValueInputIs(node, 0, Type::Number());
      CheckTypeIs(node, Type::Unsigned32());
      break;
    case IrOpcode::kIntegral32OrMinusZeroToBigInt:
      CheckValueInputIs(node, 0, Type::Integral32OrMinusZero());
      CheckTypeIs(node, Type::BigInt());
      break;
    case IrOpcode::kUnsigned32Divide:
      CheckValueInputIs(node, 0, Type::Unsigned32());
      CheckValueInputIs(node, 1, Type::Unsigned32());
      CheckTypeIs(node, Type::Unsigned32());
      break;
    case IrOpcode::kSpeculativeToNumber:
      CheckValueInputIs(node, 0, Type::Any());
      CheckTypeIs(node, Type::Number());
      break;
    case IrOpcode::kPlainPrimitiveToNumber:
      CheckValueInputIs(node, 0, Type::PlainPrimitive());
      CheckTypeIs(node, Type::Number());
      break;
    case IrOpcode::kPlainPrimitiveToWord32:
      CheckValueInputIs(node, 0, Type::PlainPrimitive());
      CheckTypeIs(node, Type::Integral32());
      break;
    case IrOpcode::kPlainPrimitiveToFloat64:
      CheckValueInputIs(node, 0, Type::PlainPrimitive());
      CheckTypeIs(node, Type::Number());
      break;
    case IrOpcode::kStringConcat:
      CheckValueInputIs(node, 0, TypeCache::Get()->kStringLengthType);
      CheckValueInputIs(node, 1, Type::String());
      CheckValueInputIs(node, 2, Type::String());
      CheckTypeIs(node, Type::String());
      break;
    case IrOpcode::kStringEqual:
    case IrOpcode::kStringLessThan:
    case IrOpcode::kStringLessThanOrEqual:
      CheckValueInputIs(node, 0, Type::String());
      CheckValueInputIs(node, 1, Type::String());
      CheckTypeIs(node, Type::Boolean());
      break;
    case IrOpcode::kStringToNumber:
      CheckValueInputIs(node, 0, Type::String());
      CheckTypeIs(node, Type::Number());
      break;
    case IrOpcode::kStringCharCodeAt:
      CheckValueInputIs(node, 0, Type::String());
      CheckValueInputIs(node, 1, Type::Unsigned32());
      CheckTypeIs(node, Type::UnsignedSmall());
      break;
    case IrOpcode::kStringCodePointAt:
      CheckValueInputIs(node, 0, Type::String());
      CheckValueInputIs(node, 1, Type::Unsigned32());
      CheckTypeIs(node, Type::UnsignedSmall());
      break;
    case IrOpcode::kStringFromSingleCharCode:
      CheckValueInputIs(node, 0, Type::Number());
      CheckTypeIs(node, Type::String());
      break;
    case IrOpcode::kStringFromSingleCodePoint:
      CheckValueInputIs(node, 0, Type::Number());
      CheckTypeIs(node, Type::String());
      break;
    case IrOpcode::kStringFromCodePointAt:
      CheckValueInputIs(node, 0, Type::String());
      CheckValueInputIs(node, 1, Type::Unsigned32());
      CheckTypeIs(node, Type::String());
      break;
    case IrOpcode::kStringIndexOf:
      CheckValueInputIs(node, 0, Type::String());
      CheckValueInputIs(node, 1, Type::String());
      CheckValueInputIs(node, 2, Type::SignedSmall());
      CheckTypeIs(node, Type::SignedSmall());
      break;
    case IrOpcode::kStringLength:
      CheckValueInputIs(node, 0, Type::String());
      CheckTypeIs(node, TypeCache::Get()->kStringLengthType);
      break;
    case IrOpcode::kStringWrapperLength:
      CheckValueInputIs(node, 0, Type::StringWrapper());
      CheckTypeIs(node, TypeCache::Get()->kStringLengthType);
      break;
    case IrOpcode::kStringToLowerCaseIntl:
    case IrOpcode::kStringToUpperCaseIntl:
      CheckValueInputIs(node, 0, Type::String());
      CheckTypeIs(node, Type::String());
      break;
    case IrOpcode::kStringSubstring:
      CheckValueInputIs(node, 0, Type::String());
      CheckValueInputIs(node, 1, Type::SignedSmall());
      CheckValueInputIs(node, 2, Type::SignedSmall());
      CheckTypeIs(node, Type::String());
      break;
    case IrOpcode::kReferenceEqual:
      CheckTypeIs(node, Type::Boolean());
      break;
    case IrOpcode::kSameValue:
    case IrOpcode::kSameValueNumbersOnly:
      CheckValueInputIs(node, 0, Type::Any());
      CheckValueInputIs(node, 1, Type::Any());
      CheckTypeIs(node, Type::Boolean());
      break;
    case IrOpcode::kNumberSameValue:
      CheckValueInputIs(node, 0, Type::Number());
      CheckValueInputIs(node, 1, Type::Number());
      CheckTypeIs(node, Type::Boolean());
      break;
    case IrOpcode::kObjectIsArrayBufferView:
    case IrOpcode::kObjectIsBigInt:
    case IrOpcode::kObjectIsCallable:
    case IrOpcode::kObjectIsConstructor:
    case IrOpcode::kObjectIsDetectableCallable:
    case IrOpcode::kObjectIsMinusZero:
    case IrOpcode::kObjectIsNaN:
    case IrOpcode::kObjectIsNonCallable:
    case IrOpcode::kObjectIsNumber:
    case IrOpcode::kObjectIsReceiver:
    case IrOpcode::kObjectIsSmi:
    case IrOpcode::kObjectIsString:
    case IrOpcode::kObjectIsSymbol:
    case IrOpcode::kObjectIsUndetectable:
      CheckValueInputIs(node, 0, Type::Any());
      CheckTypeIs(node, Type::Boolean());
      break;
    case IrOpcode::kNumberIsFloat64Hole:
      CheckValueInputIs(node, 0, Type::NumberOrHole());
      CheckTypeIs(node, Type::Boolean());
      break;
    case IrOpcode::kNumberIsFinite:
    case IrOpcode::kNumberIsMinusZero:
    case IrOpcode::kNumberIsNaN:
      CheckValueInputIs(node, 0, Type::Number());
      CheckTypeIs(node, Type::Boolean());
      break;
    case IrOpcode::kObjectIsFiniteNumber:
      CheckValueInputIs(node, 0, Type::Any());
      CheckTypeIs(node, Type::Boolean());
      break;
    case IrOpcode::kNumberIsInteger:
      CheckValueInputIs(node, 0, Type::Number());
      CheckTypeIs(node, Type::Boolean());
      break;
    case IrOpcode::kObjectIsSafeInteger:
      CheckValueInputIs(node, 0, Type::Any());
      CheckTypeIs(node, Type::Boolean());
      break;
    case IrOpcode::kNumberIsSafeInteger:
      CheckValueInputIs(node, 0, Type::Number());
      CheckTypeIs(node, Type::Boolean());
      break;
    case IrOpcode::kObjectIsInteger:
      CheckValueInputIs(node, 0, Type::Any());
      CheckTypeIs(node, Type::Boolean());
      break;
    case IrOpcode::kFindOrderedHashMapEntry:
      CheckValueInputIs(node, 0, Type::Any());
      CheckTypeIs(node, Type::SignedSmall());
      break;
    case IrOpcode::kFindOrderedHashMapEntryForInt32Key:
      CheckValueInputIs(node, 0, Type::Any());
      CheckValueInputIs(node, 1, Type::Signed32());
      CheckTypeIs(node, Type::SignedSmall());
      break;
    case IrOpcode::kFindOrderedHashSetEntry:
      CheckValueInputIs(node, 0, Type::Any());
      CheckTypeIs(node, Type::SignedSmall());
      break;
    case IrOpcode::kArgumentsLength:
    case IrOpcode::kRestLength:
      CheckTypeIs(node, TypeCache::Get()->kArgumentsLengthType);
      break;
    case IrOpcode::kNewDoubleElements:
    case IrOpcode::kNewSmiOrObjectElements:
      CheckValueInputIs(node, 0,
                        Type::Range(0.0, FixedArray::kMaxLength, zone));
      CheckTypeIs(node, Type::OtherInternal());
      break;
    case IrOpcode::kNewArgumentsElements:
      CheckValueInputIs(node, 0,
                        Type::Range(0.0, FixedArray::kMaxLength, zone));
      CheckTypeIs(node, Type::OtherInternal());
      break;
    case IrOpcode::kNewConsString:
      CheckValueInputIs(node, 0, TypeCache::Get()->kStringLengthType);
      CheckValueInputIs(node, 1, Type::String());
      CheckValueInputIs(node, 2, Type::String());
      CheckTypeIs(node, Type::String());
      break;
    case IrOpcode::kAllocate:
      CheckValueInputIs(node, 0, Type::PlainNumber());
      break;
    case IrOpcode::kAllocateRaw:
      // CheckValueInputIs(node, 0, Type::PlainNumber());
      break;
    case IrOpcode::kEnsureWritableFastElements:
      CheckValueInputIs(node, 0, Type::Any());
      CheckValueInputIs(node, 1, Type::Internal());
      CheckTypeIs(node, Type::Internal());
      break;
    case IrOpcode::kMaybeGrowFastElements:
      CheckValueInputIs(node, 0, Type::Any());
      CheckValueInputIs(node, 1, Type::Internal());
      CheckValueInputIs(node, 2, Type::Unsigned31());
      CheckValueInputIs(node, 3, Type::Unsigned31());
      CheckTypeIs(node, Type::Internal());
      break;
    case IrOpcode::kTransitionElementsKind:
      CheckValueInputIs(node, 0, Type::Any());
      CheckNotTyped(node);
      break;

    case IrOpcode::kChangeTaggedSignedToInt32: {
      // Signed32 /\ Tagged -> Signed32 /\ UntaggedInt32
      // TODO(neis): Activate once ChangeRepresentation works in typer.
      // Type from = Type::Intersect(Type::Signed32(), Type::Tagged());
      // Type to = Type::Intersect(Type::Signed32(), Type::UntaggedInt32());
      // CheckValueInputIs(node, 0, from));
      // CheckTypeIs(node, to));
      break;
    }
    case IrOpcode::kChangeTaggedSignedToInt64:
      break;
    case IrOpcode::kChangeTaggedToInt32: {
      // Signed32 /\ Tagged -> Signed32 /\ UntaggedInt32
      // TODO(neis): Activate once ChangeRepresentation works in typer.
      // Type from = Type::Intersect(Type::Signed32(), Type::Tagged());
      // Type to = Type::Intersect(Type::Signed32(), Type::UntaggedInt32());
      // CheckValueInputIs(node, 0, from));
      // CheckTypeIs(node, to));
      break;
    }
    case IrOpcode::kChangeTaggedToInt64:
      break;
    case IrOpcode::kChangeTaggedToUint32: {
      // Unsigned32 /\ Tagged -> Unsigned32 /\ UntaggedInt32
      // TODO(neis): Activate once ChangeRepresentation works in typer.
      // Type from = Type::Intersect(Type::Unsigned32(), Type::Tagged());
      // Type to =Type::Intersect(Type::Unsigned32(), Type::UntaggedInt32());
      // CheckValueInputIs(node, 0, from));
      // CheckTypeIs(node, to));
      break;
    }
    case IrOpcode::kChangeTaggedToFloat64: {
      // NumberOrUndefined /\ Tagged -> Number /\ UntaggedFloat64
      // TODO(neis): Activate once ChangeRepresentation works in typer.
      // Type from = Type::Intersect(Type::Number(), Type::Tagged());
      // Type to = Type::Intersect(Type::Number(), Type::UntaggedFloat64());
      // CheckValueInputIs(node, 0, from));
      // CheckTypeIs(node, to));
      break;
    }
    case IrOpcode::kChangeTaggedToTaggedSigned:      // Fall through.
      break;
    case IrOpcode::kTruncateTaggedToFloat64: {
      // NumberOrUndefined /\ Tagged -> Number /\ UntaggedFloat64
      // TODO(neis): Activate once ChangeRepresentation works in typer.
      // Type from = Type::Intersect(Type::NumberOrUndefined(),
      // Type::Tagged());
      // Type to = Type::Intersect(Type::Number(), Type::UntaggedFloat64());
      // CheckValueInputIs(node, 0, from));
      // CheckTypeIs(node, to));
      break;
    }
    case IrOpcode::kChangeInt31ToTaggedSigned: {
      // Signed31 /\ UntaggedInt32 -> Signed31 /\ Tagged
      // TODO(neis): Activate once ChangeRepresentation works in typer.
      // Type from =Type::Intersect(Type::Signed31(), Type::UntaggedInt32());
      // Type to = Type::Intersect(Type::Signed31(), Type::Tagged());
      // CheckValueInputIs(node, 0, from));
      // CheckTypeIs(node, to));
      break;
    }
    case IrOpcode::kChangeInt32ToTagged: {
      // Signed32 /\ UntaggedInt32 -> Signed32 /\ Tagged
      // TODO(neis): Activate once ChangeRepresentation works in typer.
      // Type from =Type::Intersect(Type::Signed32(), Type::UntaggedInt32());
      // Type to = Type::Intersect(Type::Signed32(), Type::Tagged());
      // CheckValueInputIs(node, 0, from));
      // CheckTypeIs(node, to));
      break;
    }
    case IrOpcode::kChangeInt64ToTagged:
      break;
    case IrOpcode::kChangeUint32ToTagged: {
      // Unsigned32 /\ UntaggedInt32 -> Unsigned32 /\ Tagged
      // TODO(neis): Activate once ChangeRepresentation works in typer.
      // Type from=Type::Intersect(Type::Unsigned32(),Type::UntaggedInt32());
      // Type to = Type::Intersect(Type::Unsigned32(), Type::Tagged());
      // CheckValueInputIs(node, 0, from));
      // CheckTypeIs(node, to));
      break;
    }
    case IrOpcode::kChangeUint64ToTagged:
      break;
    case IrOpcode::kChangeFloat64ToTagged: {
      // Number /\ UntaggedFloat64 -> Number /\ Tagged
      // TODO(neis): Activate once ChangeRepresentation works in typer.
      // Type from =Type::Intersect(Type::Number(), Type::UntaggedFloat64());
      // Type to = Type::Intersect(Type::Number(), Type::Tagged());
      // CheckValueInputIs(node, 0, from));
      // CheckTypeIs(node, to));
      break;
    }
    case IrOpcode::kChangeFloat64ToTaggedPointer:
      break;
    case IrOpcode::kChangeTaggedToBit: {
      // Boolean /\ TaggedPtr -> Boolean /\ UntaggedInt1
      // TODO(neis): Activate once ChangeRepresentation works in typer.
      // Type from = Type::Intersect(Type::Boolean(), Type::TaggedPtr());
      // Type to = Type::Intersect(Type::Boolean(), Type::UntaggedInt1());
      // CheckValueInputIs(node, 0, from));
      // CheckTypeIs(node, to));
      break;
    }
    case IrOpcode::kChangeBitToTagged: {
      // Boolean /\ UntaggedInt1 -> Boolean /\ TaggedPtr
      // TODO(neis): Activate once ChangeRepresentation works in typer.
      // Type from = Type::Intersect(Type::Boolean(), Type::UntaggedInt1());
      // Type to = Type::Intersect(Type::Boolean(), Type::TaggedPtr());
      // CheckValueInputIs(node, 0, from));
      // CheckTypeIs(node, to));
      break;
    }
    case IrOpcode::kTruncateTaggedToWord32: {
      // Number /\ Tagged -> Signed32 /\ UntaggedInt32
      // TODO(neis): Activate once ChangeRepresentation works in typer.
      // Type from = Type::Intersect(Type::Number(), Type::Tagged());
      // Type to = Type::Intersect(Type::Number(), Type::UntaggedInt32());
      // CheckValueInputIs(node, 0, from));
      // CheckTypeIs(node, to));
      break;
    }
    case IrOpcode::kTruncateBigIntToWord64:
      CheckValueInputIs(node, 0, Type::BigInt());
      CheckTypeIs(node, Type::BigInt());
      break;
    case IrOpcode::kChangeInt64ToBigInt:
      CheckValueInputIs(node, 0, Type::SignedBigInt64());
      CheckTypeIs(node, Type::SignedBigInt64());
      break;
    case IrOpcode::kChangeUint64ToBigInt:
      CheckValueInputIs(node, 0, Type::UnsignedBigInt64());
      CheckTypeIs(node, Type::UnsignedBigInt64());
      break;
    case IrOpcode::kTruncateTaggedToBit:
    case IrOpcode::kTruncateTaggedPointerToBit:
      break;

    case IrOpcode::kCheckBounds:
      CheckValueInputIs(node, 0, Type::Any());
      CheckValueInputIs(node, 1, TypeCache::Get()->kPositiveSafeInteger);
      CheckTypeIs(node, TypeCache::Get()->kPositiveSafeInteger);
      break;
    case IrOpcode::kCheckClosure:
      // Any -> Function
      CheckValueInputIs(node, 0, Type::Any());
      CheckTypeIs(node, Type::Function());
      break;
    case IrOpcode::kCheckHeapObject:
      CheckValueInputIs(node, 0, Type::Any());
      break;
    case IrOpcode::kCheckIf:
      CheckValueInputIs(node, 0, Type::Boolean());
      CheckNotTyped(node);
      break;
    case IrOpcode::kCheckInternalizedString:
      CheckValueInputIs(node, 0, Type::Any());
      CheckTypeIs(node, Type::InternalizedString());
      break;
    case IrOpcode::kCheckMaps:
      CheckValueInputIs(node, 0, Type::Any());
      CheckNotTyped(node);
      break;
    case IrOpcode::kCompareMaps:
      CheckValueInputIs(node, 0, Type::Any());
      CheckTypeIs(node, Type::Boolean());
      break;
    case IrOpcode::kCheckNumber:
      CheckValueInputIs(node, 0, Type::Any());
      CheckTypeIs(node, Type::Number());
      break;
    case IrOpcode::kCheckReceiver:
      CheckValueInputIs(node, 0, Type::Any());
      CheckTypeIs(node, Type::Receiver());
      break;
    case IrOpcode::kCheckReceiverOrNullOrUndefined:
      CheckValueInputIs(node, 0, Type::Any());
      CheckTypeIs(node, Type::ReceiverOrNullOrUndefined());
      break;
    case IrOpcode::kCheckSmi:
      CheckValueInputIs(node, 0, Type::Any());
      break;
    case IrOpcode::kCheckString:
      CheckValueInputIs(node, 0, Type::Any());
      CheckTypeIs(node, Type::String());
      break;
    case IrOpcode::kCheckStringOrStringWrapper:
      CheckValueInputIs(node, 0, Type::Any());
      CheckTypeIs(node, Type::StringOrStringWrapper());
      break;
    case IrOpcode::kCheckSymbol:
      CheckValueInputIs(node, 0, Type::Any());
      CheckTypeIs(node, Type::Symbol());
      break;
    case IrOpcode::kConvertReceiver:
      CheckValueInputIs(node, 0, Type::Any());
      CheckValueInputIs(node, 1, Type::Any());
      CheckValueInputIs(node, 2, Type::Any());
      CheckTypeIs(node, Type::Receiver());
      break;

    case IrOpcode::kCheckedInt32Add:
    case IrOpcode::kCheckedInt32Sub:
    case IrOpcode::kCheckedInt32Div:
    case IrOpcode::kCheckedInt32Mod:
    case IrOpcode::kCheckedUint32Div:
    case IrOpcode::kCheckedUint32Mod:
    case IrOpcode::kCheckedInt32Mul:
    case IrOpcode::kCheckedInt32ToTaggedSigned:
    case IrOpcode::kCheckedInt64ToInt32:
    case IrOpcode::kCheckedInt64ToTaggedSigned:
    case IrOpcode::kCheckedUint32Bounds:
    case IrOpcode::kCheckedUint32ToInt32:
    case IrOpcode::kCheckedUint32ToTaggedSigned:
    case IrOpcode::kCheckedUint64Bounds:
    case IrOpcode::kCheckedUint64ToInt32:
    case IrOpcode::kCheckedUint64ToInt64:
    case IrOpcode::kCheckedUint64ToTaggedSigned:
    case IrOpcode::kCheckedFloat64ToInt32:
    case IrOpcode::kCheckedFloat64ToInt64:
    case IrOpcode::kCheckedTaggedSignedToInt32:
    case IrOpcode::kCheckedTaggedToInt32:
    case IrOpcode::kCheckedTaggedToArrayIndex:
    case IrOpcode::kCheckedTaggedToInt64:
    case IrOpcode::kCheckedTaggedToFloat64:
    case IrOpcode::kCheckedTaggedToTaggedSigned:
    case IrOpcode::kCheckedTaggedToTaggedPointer:
    case IrOpcode::kCheckedTruncateTaggedToWord32:
    case IrOpcode::kCheckedInt64Add:
    case IrOpcode::kCheckedInt64Sub:
    case IrOpcode::kCheckedInt64Mul:
    case IrOpcode::kCheckedInt64Div:
    case IrOpcode::kCheckedInt64Mod:
    case IrOpcode::kAssertType:
    case IrOpcode::kVerifyType:
    case IrOpcode::kCheckTurboshaftTypeOf:
      break;
    case IrOpcode::kDoubleArrayMin:
    case IrOpcode::kDoubleArrayMax:
      CheckValueInputIs(node, 0, Type::Any());
      CheckTypeIs(node, Type::Number());
      break;
    case IrOpcode::kCheckFloat64Hole:
      CheckValueInputIs(node, 0, Type::NumberOrHole());
      CheckTypeIs(node, Type::NumberOrUndefined());
      break;
    case IrOpcode::kChangeFloat64HoleToTagged:
      CheckValueInputIs(node, 0, Type::NumberOrHole());
      CheckTypeIs(node, Type::NumberOrUndefined());
      break;
    case IrOpcode::kCheckNotTaggedHole:
      CheckValueInputIs(node, 0, Type::Any());
      CheckTypeIs(node, Type::NonInternal());
      break;
    case IrOpcode::kConvertTaggedHoleToUndefined:
      CheckValueInputIs(node, 0, Type::Any());
      CheckTypeIs(node, Type::NonInternal());
      break;

    case IrOpcode::kCheckEqualsInternalizedString:
      CheckValueInputIs(node, 0, Type::InternalizedString());
      CheckValueInputIs(node, 1, Type::Any());
      CheckNotTyped(node);
      break;
    case IrOpcode::kCheckEqualsSymbol:
      CheckValueInputIs(node, 0, Type::Symbol());
      CheckValueInputIs(node, 1, Type::Any());
      CheckNotTyped(node);
      break;

    case IrOpcode::kLoadFieldByIndex:
      CheckValueInputIs(node, 0, Type::Any());
      CheckValueInputIs(node, 1, Type::SignedSmall());
      CheckTypeIs(node, Type::NonInternal());
      break;
    case IrOpcode::kLoadField:
    case IrOpcode::kLoadMessage:
      // Object -> fieldtype
      // TODO(rossberg): activate once machine ops are typed.
      // CheckValueInputIs(node, 0, Type::Object());
      // CheckTypeIs(node, FieldAccessOf(node->op()).type);
      break;
    case IrOpcode::kLoadElement:
    case IrOpcode::kLoadStackArgument:
      // Object -> elementtype
      // TODO(rossberg): activate once machine ops are typed.
      // CheckValueInputIs(node, 0, Type::Object());
      // CheckTypeIs(node, ElementAccessOf(node->op()).type));
      break;
    case IrOpcode::kLoadFromObject:
    case IrOpcode::kLoadImmutableFromObject:
      CheckValueInputIs(node, 0, Type::Receiver());
      break;
    case IrOpcode::kLoadTypedElement:
      break;
    case IrOpcode::kLoadDataViewElement:
      break;
    case IrOpcode::kStoreField:
    case IrOpcode::kStoreMessage:
      // (Object, fieldtype) -> _|_
      // TODO(rossberg): activate once machine ops are typed.
      // CheckValueInputIs(node, 0, Type::Object());
      // CheckValueInputIs(node, 1, FieldAccessOf(node->op()).type));
      CheckNotTyped(node);
      break;
    case IrOpcode::kStoreElement:
      // (Object, elementtype) -> _|_
      // TODO(rossberg): activate once machine ops are typed.
      // CheckValueInputIs(node, 0, Type::Object());
      // CheckValueInputIs(node, 1, ElementAccessOf(node->op()).type));
      CheckNotTyped(node);
      break;
    case IrOpcode::kStoreToObject:
    case IrOpcode::kInitializeImmutableInObject:
      // TODO(gsps): Can we check some types here?
      break;
    case IrOpcode::kTransitionAndStoreElement:
      CheckNotTyped(node);
      break;
    case IrOpcode::kTransitionAndStoreNumberElement:
      CheckNotTyped(node);
      break;
    case IrOpcode::kTransitionAndStoreNonNumberElement:
      CheckNotTyped(node);
      break;
    case IrOpcode::kStoreSignedSmallElement:
      CheckNotTyped(node);
      break;
    case IrOpcode::kStoreTypedElement:
      CheckNotTyped(node);
      break;
    case IrOpcode::kStoreDataViewElement:
      CheckNotTyped(node);
      break;
    case IrOpcode::kNumberSilenceNaN:
      CheckValueInputIs(node, 0, Type::Number());
      CheckTypeIs(node, Type::Number());
      break;
    case IrOpcode::kMapGuard:
      CheckNotTyped(node);
      break;
    case IrOpcode::kTypeGuard:
      CheckTypeIs(node, TypeGuardTypeOf(node->op()));
      break;
    case IrOpcode::kDateNow:
      CHECK_EQ(0, value_count);
      CheckTypeIs(node, Type::Number());
      break;
    case IrOpcode::kCheckBigInt:
      CheckValueInputIs(node, 0, Type::Any());
      CheckTypeIs(node, Type::BigInt());
      break;
    case IrOpcode::kCheckedBigIntToBigInt64:
      CheckValueInputIs(node, 0, Type::BigInt());
      CheckTypeIs(node, Type::SignedBigInt64());
      break;
    case IrOpcode::kFastApiCall:
      CHECK_GE(value_count, 1);
      CheckValueInputIs(node, 0, Type::Any());  // receiver
      break;
#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
    case IrOpcode::kGetContinuationPreservedEmbedderData:
      CHECK_EQ(value_count, 0);
      CHECK_EQ(effect_count, 1);
      CheckTypeIs(node, Type::Any());
      break;
    case IrOpcode::kSetContinuationPreservedEmbedderData:
      CHECK_EQ(value_count, 1);
      CHECK_EQ(effect_count, 1);
      CheckValueInputIs(node, 0, Type::Any());
      CheckNotTyped(node);
      break;
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
    case IrOpcode::kSLVerifierHint:
      // SLVerifierHint is internal to SimplifiedLowering and should never be
      // seen by the verifier.
      UNREACHABLE();
#if V8_ENABLE_WEBASSEMBLY
    case IrOpcode::kJSWasmCall:
      CHECK_GE(value_count, 3);
      CheckTypeIs(node, Type::Any());
      CheckValueInputIs(node, 0, Type::Any());  // callee
      break;
    case IrOpcode::kWasmTypeCheck:
    case IrOpcode::kWasmTypeCheckAbstract:
    case IrOpcode::kWasmTypeCast:
    case IrOpcode::kWasmTypeCastAbstract:
    case IrOpcode::kRttCanon:
    case IrOpcode::kNull:
    case IrOpcode::kIsNull:
    case IrOpcode::kIsNotNull:
    case IrOpcode::kAssertNotNull:
    case IrOpcode::kWasmAnyConvertExtern:
    case IrOpcode::kWasmExternConvertAny:
    case IrOpcode::kWasmStructGet:
    case IrOpcode::kWasmStructSet:
    case IrOpcode::kWasmArrayGet:
    case IrOpcode::kWasmArraySet:
    case IrOpcode::kWasmArrayLength:
    case IrOpcode::kWasmArrayInitializeLength:
    case IrOpcode::kStringAsWtf16:
    case IrOpcode::kStringPrepareForGetCodeunit:
    case IrOpcode::kLoadStackPointer:
    case IrOpcode::kSetStackPointer:
      // TODO(7748): What are the constraints here?
      break;
#endif  // V8_ENABLE_WEBASSEMBLY

    // Machine operators
    // -----------------------
    case IrOpcode::kLoad:
    case IrOpcode::kLoadImmutable:
    case IrOpcode::kProtectedLoad:
    case IrOpcode::kProtectedStore:
    case IrOpcode::kLoadTrapOnNull:
    case IrOpcode::kStoreTrapOnNull:
    case IrOpcode::kStore:
    case IrOpcode::kStorePair:
    case IrOpcode::kStoreIndirectPointer:
    case IrOpcode::kStackSlot:
    case IrOpcode::k
"""


```