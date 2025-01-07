Response:
The user wants to understand the functionality of the `v8/src/compiler/verifier.cc` file. Here's a breakdown of the thinking process to generate the answer:

1. **Identify the Core Purpose:** The file name `verifier.cc` strongly suggests its main function: to verify something. Looking at the code, it iterates through nodes in a graph and performs checks on them. The `#include "src/compiler/verifier.h"` reinforces this.

2. **Pinpoint Key Activities:**  The code contains a `Verifier::Visitor` class and a `Check` method within it. This method does various checks based on the `node->opcode()`. The presence of `FATAL` calls indicates that the verification process stops if an error is found.

3. **Extract Specific Checks:** Scan the `Check` method and the `CheckSwitch` method for the types of verifications performed. Look for `CHECK_EQ`, `CHECK_NE`, `CHECK`, `FATAL`, and conditional checks (`if` statements with error handling). Group these checks into logical categories.

4. **Determine the Verification Scope:** The code interacts with compiler concepts like nodes, operators, types, inputs, outputs, and control flow. This points to verification happening within the Turbofan compiler pipeline.

5. **Address the ".tq" Question:** The prompt asks about ".tq" files. Recognize that ".tq" stands for Torque, a language used for implementing built-in functions. The provided file is ".cc", so it's a C++ source file.

6. **Relate to JavaScript Functionality (if applicable):**  The code verifies `JS` prefixed opcodes (like `kJSEqual`, `JSCreateArray`, etc.). These directly correspond to JavaScript operations. For an example, pick a simple `JS` operation like addition (`JSAdd`) and demonstrate how it works in JavaScript. Highlight the connection between the C++ verification and the JavaScript behavior.

7. **Identify Potential Programming Errors:** Think about what kind of errors this verifier is trying to catch. Type mismatches, incorrect numbers of inputs/outputs, improper control flow, and usage of undefined values are common programming errors in a compiler. Formulate examples of these errors in the context of how a compiler might represent them.

8. **Consider Code Logic Reasoning:**  Look for sections in the code where assumptions are made and validated (e.g., the `CheckSwitch` function ensuring unique case values). Provide a simple scenario with inputs and expected outputs to illustrate this.

9. **Summarize the Functionality:**  Based on the extracted information, create a concise summary of the `verifier.cc` file's role. Emphasize its purpose in ensuring the correctness of the intermediate representation in the compiler.

10. **Structure the Output:** Organize the findings into clear sections as requested by the prompt (Functionality, Torque Check, JavaScript Relationship, Code Logic Reasoning, Common Programming Errors, Summary). Use bullet points for readability.

11. **Refine and Clarify:** Review the generated answer for clarity, accuracy, and completeness. Ensure all parts of the prompt are addressed. For example, initially, I might have just said "checks types". Refining it to "verifies type consistency" is more accurate and informative. Similarly, for code logic reasoning, a concrete example is better than just stating it checks logic.

12. **Address the "Part 1" instruction:** Explicitly state that this is the summary for Part 1, as requested.

By following these steps, we can generate a comprehensive and informative answer that addresses all aspects of the user's query about the `v8/src/compiler/verifier.cc` file.
好的，让我们来分析一下 `v8/src/compiler/verifier.cc` 这个文件的功能。

**功能归纳：**

`v8/src/compiler/verifier.cc` 的主要功能是**对 Turbofan 编译器生成的中间表示（IR，通常是图结构）进行一致性检查和验证**。它旨在在编译的早期阶段发现潜在的错误和不一致性，确保生成的代码的正确性。

更具体地说，它执行以下操作：

* **图结构验证:** 检查图的连接性、节点的输入输出数量是否符合其操作符的定义。
* **类型一致性检查 (可选):**  如果启用了类型检查 (`Typing::TYPED`)，则验证节点上的类型信息是否一致，例如，某个节点的输出类型是否与其使用者的输入类型兼容。
* **操作符特定检查:**  针对不同的操作符（例如 `kBranch`, `kSwitch`, `kJSAdd` 等）执行特定的验证逻辑，确保这些操作符被正确使用。
* **控制流验证:** 检查控制流结构是否正确，例如 `Branch` 节点是否恰好连接到一个 `IfTrue` 和一个 `IfFalse` 节点。
* **帧状态验证:** 检查 `FrameState` 节点是否正确构建，包括参数、局部变量和栈信息。
* **调试和错误报告:** 当发现错误时，会触发 `FATAL` 错误，并打印相关信息，帮助开发者定位问题。

**关于 .tq 结尾：**

文件中明确指出，`v8/src/compiler/verifier.cc` 是一个 **C++** 源代码文件。如果文件名以 `.tq` 结尾，那么它才是 V8 Torque 源代码。Torque 用于定义 V8 的内置函数。

**与 JavaScript 的关系：**

`v8/src/compiler/verifier.cc` 中包含了大量以 `kJS` 开头的操作符（例如 `kJSEqual`, `kJSAdd`, `kJSLoadProperty`）。这些操作符直接对应于 JavaScript 语言的各种操作。 验证器会检查这些 JavaScript 操作在编译器中间表示中的使用是否符合规范。

**JavaScript 示例：**

例如，对于 JavaScript 的加法操作 `a + b`，Turbofan 编译器可能会生成一个 `kJSAdd` 节点。`verifier.cc` 会检查这个 `kJSAdd` 节点的输入是否是值类型的节点，并且在启用类型检查的情况下，还会检查其输出类型是否为 `NumericOrString()`。

```javascript
function add(a, b) {
  return a + b;
}
```

在这个 JavaScript 例子中，`a + b` 会被编译成一个 `kJSAdd` 操作。Verifier 会确保传递给 `kJSAdd` 的 `a` 和 `b` 在 IR 中是某种值的表示。

**代码逻辑推理示例：**

**假设输入：** 一个 `kSwitch` 节点，它有两个 `kIfValue` 使用者，分别对应值 1 和 2，但缺少 `kIfDefault` 使用者。

**verifier.cc 的逻辑：** `CheckSwitch` 函数会遍历 `kSwitch` 节点的使用者，统计 `kIfValue` 的数量，并检查是否存在 `kIfDefault`。

**输出：** `FATAL` 错误，提示缺少 `kIfDefault` 分支，因为 `CHECK(!expect_default);` 将会失败。

**用户常见的编程错误示例：**

`verifier.cc` 可以捕获一些在编译过程中可能由 Turbofan 或开发者引入的错误。 例如：

1. **类型不匹配：**  如果某个操作需要一个数字类型的输入，但实际连接的是一个字符串类型的节点（在启用了类型检查的情况下）。

   ```javascript
   function foo(x) {
     return x * "5"; // 这是一个类型错误，乘法运算不应该直接用于字符串
   }
   ```
   虽然 JavaScript 允许这样的操作并会进行类型转换，但在编译器的中间表示中，如果类型信息不一致，Verifier 可能会发现问题。

2. **错误的控制流连接：**  如果一个需要两个控制流输入的 `Merge` 节点只连接了一个输入。

   ```javascript
   function bar(x) {
     if (x > 0) {
       // ...
     }
     // 缺少 else 分支，可能导致不完整的控制流
   }
   ```
   在编译后的 IR 中，如果 `if` 语句的控制流处理不当，可能会导致 `Merge` 节点的输入不完整，Verifier 会检测到这种错误。

3. **使用了未定义的变量（在某些编译阶段）：** 虽然 JavaScript 允许在运行时访问未声明的变量，但在某些优化编译阶段，编译器会进行更严格的检查。 如果 IR 中使用了表示未定义变量的节点，Verifier 可能会发出警告或错误。

**总结一下 `v8/src/compiler/verifier.cc` 的功能 (Part 1):**

`v8/src/compiler/verifier.cc` 是 Turbofan 编译器的重要组成部分，它通过对中间表示进行全面的结构和一致性检查，来确保编译器生成的代码的正确性。它涵盖了图的连接性、类型一致性（可选）、特定操作符的使用规范以及控制流的完整性。 它可以帮助在编译早期发现潜在的编程错误和编译器自身的逻辑错误。

Prompt: 
```
这是目录为v8/src/compiler/verifier.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/verifier.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

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
      CheckValueInputIs(node, 1, Type::Any())
"""


```