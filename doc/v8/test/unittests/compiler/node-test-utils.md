Response: The user wants a summary of the C++ code provided in the file `v8/test/unittests/compiler/node-test-utils.cc`. The code defines a set of Google Test matchers for `Node` objects in the V8 compiler's intermediate representation (IR). These matchers are used in unit tests to assert the properties of specific nodes within the IR graph.

The key functionalities are:

1. **Defining custom matchers for `Node` objects:** The code implements various matcher classes derived from `testing::MatcherInterface<Node*>`. Each matcher class checks for specific characteristics of a `Node`.
2. **Matchers based on opcode:**  `TestNodeMatcher` checks if a `Node` has a specific `IrOpcode`.
3. **Matchers with input validation:** Many matchers, like `IsBranchMatcher`, `IsPhiMatcher`, `IsCallMatcher`, etc., not only check the opcode but also validate the inputs (value, control, effect) of the `Node` using nested matchers.
4. **Matchers for different node types:** There are matchers for control flow nodes (e.g., `IsBranch`, `IsMerge`, `IsIfValue`, `IsSwitch`), data flow nodes (e.g., `IsPhi`, `IsSelect`, `IsLoadField`, `IsStoreField`), call nodes (`IsCall`, `IsTailCall`), constant nodes (`IsConstant`), and others.
5. **Matchers with parameter validation:** Some matchers also validate parameters specific to an opcode (e.g., `IsPhiMatcher` checks the `MachineRepresentation`, `IsParameterMatcher` checks the parameter index).
6. **Helper functions for creating matchers:**  The code provides convenient functions like `IsDead()`, `IsStart()`, `IsBranch()`, etc., which return instances of the corresponding matcher classes.

The file is essentially a utility library for writing concise and readable unit tests for the V8 compiler's node graph.

Regarding the relationship with JavaScript: This C++ code is part of the V8 JavaScript engine's internals. It's used in the testing framework for the compiler, which takes JavaScript code and transforms it into machine code. While this specific file doesn't directly execute JavaScript, the node graph it helps test *represents* the compiled form of JavaScript code.

To illustrate with a JavaScript example:  Imagine a simple JavaScript `if` statement. The V8 compiler would translate this into a node graph containing, among other things, a `Branch` node. The matchers defined in this C++ file would be used in a unit test to verify the properties of that `Branch` node (e.g., the condition being tested, the control flow).
这个C++源代码文件 `node-test-utils.cc` 的主要功能是**为 V8 JavaScript 引擎的编译器（compiler）的节点（Node）对象提供了一系列的 Google Test 匹配器（Matchers）**。

具体来说，它定义了一组自定义的匹配器类，可以方便地在单元测试中断言（assert）编译器生成的中间表示（IR）图中的节点的各种属性，例如：

* **节点的类型（Opcode）**:  例如 `IsDead()`, `IsStart()`, `IsBranch()`, `IsPhi()` 等函数创建的匹配器可以检查节点是否具有特定的操作码。
* **节点的输入（Inputs）**: 许多匹配器不仅检查节点的类型，还检查其输入节点是否符合预期的匹配器。例如，`IsBranch()` 匹配器会检查 `Branch` 节点的值输入和控制输入。
* **节点的操作数（Operands/Parameters）**: 一些匹配器会检查与节点操作相关的特定参数，例如 `IsPhi()` 匹配器会检查 Phi 节点的表示（representation）。
* **节点的控制流和效果（Control and Effect）**: 匹配器可以检查节点的控制输入和效果输入，这对于理解编译器的控制流和副作用分析至关重要。

**简而言之，这个文件提供了一套便捷的工具，用于在 C++ 单元测试中验证 V8 编译器生成的节点图的正确性。**

**它与 JavaScript 的功能有密切关系。**  V8 编译器将 JavaScript 代码编译成中间表示（IR），而这些匹配器就是用来测试这个 IR 的结构的。 编译器的正确性直接影响到 JavaScript 代码的执行效率和行为。

**JavaScript 举例说明：**

假设有以下简单的 JavaScript 代码：

```javascript
function foo(a) {
  if (a > 0) {
    return a + 1;
  } else {
    return a - 1;
  }
}
```

当 V8 编译这段代码时，会生成一个包含各种节点的 IR 图。 其中，`if` 语句可能会被编译成一个 `Branch` 节点，用于根据条件 `a > 0` 跳转到不同的代码路径。

在 `node-test-utils.cc` 中定义的匹配器就可以用来测试这个 `Branch` 节点：

```c++
// 假设 graph 是代表编译后 IR 图的对象
Node* branch_node = ...; // 从 graph 中找到表示 if 语句的 Branch 节点
Node* condition_node = ...; // 从 graph 中找到表示条件 a > 0 的节点
Node* control_node = ...; // 找到 Branch 节点的控制输入节点

EXPECT_THAT(branch_node, compiler::IsBranch(condition_node, control_node));
```

在这个例子中，`compiler::IsBranch(condition_node, control_node)` 就是一个使用了 `node-test-utils.cc` 中定义的匹配器的断言。它会检查 `branch_node` 是否是一个 `Branch` 类型的节点，并且其值输入是 `condition_node`，控制输入是 `control_node`。

**总结一下，虽然这个 C++ 文件本身不执行 JavaScript 代码，但它提供了一个用于测试将 JavaScript 代码编译成内部表示的编译器的工具集，确保了编译过程的正确性，从而间接地保证了 JavaScript 代码的正确执行。**

Prompt: 
```
这是目录为v8/test/unittests/compiler/node-test-utils.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "test/unittests/compiler/node-test-utils.h"

#include <vector>

#include "src/compiler/common-operator.h"
#include "src/compiler/js-operator.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/simplified-operator.h"
#include "src/handles/handles-inl.h"

using testing::_;
using testing::MakeMatcher;
using testing::MatcherInterface;
using testing::MatchResultListener;
using testing::StringMatchResultListener;

namespace v8 {
namespace internal {

bool operator==(Handle<HeapObject> const& lhs, Handle<HeapObject> const& rhs) {
  return lhs.is_identical_to(rhs);
}

namespace compiler {

namespace {

template <typename T>
bool PrintMatchAndExplain(const T& value, const std::string& value_name,
                          const Matcher<T>& value_matcher,
                          MatchResultListener* listener) {
  StringMatchResultListener value_listener;
  if (!value_matcher.MatchAndExplain(value, &value_listener)) {
    *listener << "whose " << value_name << " " << value << " doesn't match";
    if (value_listener.str() != "") {
      *listener << ", " << value_listener.str();
    }
    return false;
  }
  return true;
}

class TestNodeMatcher : public MatcherInterface<Node*> {
 public:
  explicit TestNodeMatcher(IrOpcode::Value opcode) : opcode_(opcode) {}

  void DescribeTo(std::ostream* os) const override {
    *os << "is a " << IrOpcode::Mnemonic(opcode_) << " node";
  }

  bool MatchAndExplain(Node* node,
                       MatchResultListener* listener) const override {
    if (node == nullptr) {
      *listener << "which is NULL";
      return false;
    }
    if (node->opcode() != opcode_) {
      *listener << "whose opcode is " << IrOpcode::Mnemonic(node->opcode())
                << " but should have been " << IrOpcode::Mnemonic(opcode_);
      return false;
    }
    return true;
  }

 private:
  const IrOpcode::Value opcode_;
};

class IsBranchMatcher final : public TestNodeMatcher {
 public:
  IsBranchMatcher(const Matcher<Node*>& value_matcher,
                  const Matcher<Node*>& control_matcher)
      : TestNodeMatcher(IrOpcode::kBranch),
        value_matcher_(value_matcher),
        control_matcher_(control_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose value (";
    value_matcher_.DescribeTo(os);
    *os << ") and control (";
    control_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0),
                                 "value", value_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetControlInput(node),
                                 "control", control_matcher_, listener));
  }

 private:
  const Matcher<Node*> value_matcher_;
  const Matcher<Node*> control_matcher_;
};

class IsLoopExitValueMatcher final : public TestNodeMatcher {
 public:
  IsLoopExitValueMatcher(const Matcher<MachineRepresentation>& rep_matcher,
                         const Matcher<Node*>& value_matcher)
      : TestNodeMatcher(IrOpcode::kLoopExitValue),
        rep_matcher_(rep_matcher),
        value_matcher_(value_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << ") whose rep (";
    rep_matcher_.DescribeTo(os);
    *os << " and value (";
    value_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(LoopExitValueRepresentationOf(node->op()),
                                 "representation", rep_matcher_, listener)) &&
           PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0), "value",
                                value_matcher_, listener);
  }

 private:
  const Matcher<MachineRepresentation> rep_matcher_;
  const Matcher<Node*> value_matcher_;
};

class IsSwitchMatcher final : public TestNodeMatcher {
 public:
  IsSwitchMatcher(const Matcher<Node*>& value_matcher,
                  const Matcher<Node*>& control_matcher)
      : TestNodeMatcher(IrOpcode::kSwitch),
        value_matcher_(value_matcher),
        control_matcher_(control_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose value (";
    value_matcher_.DescribeTo(os);
    *os << ") and control (";
    control_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0),
                                 "value", value_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetControlInput(node),
                                 "control", control_matcher_, listener));
  }

 private:
  const Matcher<Node*> value_matcher_;
  const Matcher<Node*> control_matcher_;
};

class IsIfValueMatcher final : public TestNodeMatcher {
 public:
  IsIfValueMatcher(const Matcher<IfValueParameters>& value_matcher,
                   const Matcher<Node*>& control_matcher)
      : TestNodeMatcher(IrOpcode::kIfValue),
        value_matcher_(value_matcher),
        control_matcher_(control_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose value (";
    value_matcher_.DescribeTo(os);
    *os << ") and control (";
    control_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(IfValueParametersOf(node->op()), "value",
                                 value_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetControlInput(node),
                                 "control", control_matcher_, listener));
  }

 private:
  const Matcher<IfValueParameters> value_matcher_;
  const Matcher<Node*> control_matcher_;
};

class IsControl1Matcher final : public TestNodeMatcher {
 public:
  IsControl1Matcher(IrOpcode::Value opcode,
                    const Matcher<Node*>& control_matcher)
      : TestNodeMatcher(opcode), control_matcher_(control_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose control (";
    control_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(NodeProperties::GetControlInput(node),
                                 "control", control_matcher_, listener));
  }

 private:
  const Matcher<Node*> control_matcher_;
};

class IsControl2Matcher final : public TestNodeMatcher {
 public:
  IsControl2Matcher(IrOpcode::Value opcode,
                    const Matcher<Node*>& control0_matcher,
                    const Matcher<Node*>& control1_matcher)
      : TestNodeMatcher(opcode),
        control0_matcher_(control0_matcher),
        control1_matcher_(control1_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose control0 (";
    control0_matcher_.DescribeTo(os);
    *os << ") and control1 (";
    control1_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(NodeProperties::GetControlInput(node, 0),
                                 "control0", control0_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetControlInput(node, 1),
                                 "control1", control1_matcher_, listener));
  }

 private:
  const Matcher<Node*> control0_matcher_;
  const Matcher<Node*> control1_matcher_;
};

class IsControl3Matcher final : public TestNodeMatcher {
 public:
  IsControl3Matcher(IrOpcode::Value opcode,
                    const Matcher<Node*>& control0_matcher,
                    const Matcher<Node*>& control1_matcher,
                    const Matcher<Node*>& control2_matcher)
      : TestNodeMatcher(opcode),
        control0_matcher_(control0_matcher),
        control1_matcher_(control1_matcher),
        control2_matcher_(control2_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose control0 (";
    control0_matcher_.DescribeTo(os);
    *os << ") and control1 (";
    control1_matcher_.DescribeTo(os);
    *os << ") and control2 (";
    control2_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(NodeProperties::GetControlInput(node, 0),
                                 "control0", control0_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetControlInput(node, 1),
                                 "control1", control1_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetControlInput(node, 2),
                                 "control2", control2_matcher_, listener));
  }

 private:
  const Matcher<Node*> control0_matcher_;
  const Matcher<Node*> control1_matcher_;
  const Matcher<Node*> control2_matcher_;
};

class IsBeginRegionMatcher final : public TestNodeMatcher {
 public:
  explicit IsBeginRegionMatcher(const Matcher<Node*>& effect_matcher)
      : TestNodeMatcher(IrOpcode::kBeginRegion),
        effect_matcher_(effect_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose effect (";
    effect_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(NodeProperties::GetEffectInput(node), "effect",
                                 effect_matcher_, listener));
  }

 private:
  const Matcher<Node*> effect_matcher_;
};

class IsFinishRegionMatcher final : public TestNodeMatcher {
 public:
  IsFinishRegionMatcher(const Matcher<Node*>& value_matcher,
                        const Matcher<Node*>& effect_matcher)
      : TestNodeMatcher(IrOpcode::kFinishRegion),
        value_matcher_(value_matcher),
        effect_matcher_(effect_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose value (";
    value_matcher_.DescribeTo(os);
    *os << ") and effect (";
    effect_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0),
                                 "value", value_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetEffectInput(node), "effect",
                                 effect_matcher_, listener));
  }

 private:
  const Matcher<Node*> value_matcher_;
  const Matcher<Node*> effect_matcher_;
};

class IsReturnMatcher final : public TestNodeMatcher {
 public:
  IsReturnMatcher(const Matcher<Node*>& value_matcher,
                  const Matcher<Node*>& effect_matcher,
                  const Matcher<Node*>& control_matcher)
      : TestNodeMatcher(IrOpcode::kReturn),
        value_matcher_(value_matcher),
        value2_matcher_(_),
        effect_matcher_(effect_matcher),
        control_matcher_(control_matcher),
        has_second_return_value_(false) {}

  IsReturnMatcher(const Matcher<Node*>& value_matcher,
                  const Matcher<Node*>& value2_matcher,
                  const Matcher<Node*>& effect_matcher,
                  const Matcher<Node*>& control_matcher)
      : TestNodeMatcher(IrOpcode::kReturn),
        value_matcher_(value_matcher),
        value2_matcher_(value2_matcher),
        effect_matcher_(effect_matcher),
        control_matcher_(control_matcher),
        has_second_return_value_(true) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose value (";
    value_matcher_.DescribeTo(os);
    if (has_second_return_value_) {
      *os << ") and second value (";
      value2_matcher_.DescribeTo(os);
    }
    *os << ") and effect (";
    effect_matcher_.DescribeTo(os);
    *os << ") and control (";
    control_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 1),
                                 "value", value_matcher_, listener) &&
            (!has_second_return_value_ ||
             PrintMatchAndExplain(NodeProperties::GetValueInput(node, 2),
                                  "value2", value2_matcher_, listener)) &&
            PrintMatchAndExplain(NodeProperties::GetEffectInput(node), "effect",
                                 effect_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetControlInput(node),
                                 "control", control_matcher_, listener));
  }

 private:
  const Matcher<Node*> value_matcher_;
  const Matcher<Node*> value2_matcher_;
  const Matcher<Node*> effect_matcher_;
  const Matcher<Node*> control_matcher_;
  bool has_second_return_value_;
};

class IsTerminateMatcher final : public TestNodeMatcher {
 public:
  IsTerminateMatcher(const Matcher<Node*>& effect_matcher,
                     const Matcher<Node*>& control_matcher)
      : TestNodeMatcher(IrOpcode::kTerminate),
        effect_matcher_(effect_matcher),
        control_matcher_(control_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose effect (";
    effect_matcher_.DescribeTo(os);
    *os << ") and control (";
    control_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(NodeProperties::GetEffectInput(node), "effect",
                                 effect_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetControlInput(node),
                                 "control", control_matcher_, listener));
  }

 private:
  const Matcher<Node*> effect_matcher_;
  const Matcher<Node*> control_matcher_;
};

class IsTypeGuardMatcher final : public TestNodeMatcher {
 public:
  IsTypeGuardMatcher(const Matcher<Node*>& value_matcher,
                     const Matcher<Node*>& control_matcher)
      : TestNodeMatcher(IrOpcode::kTypeGuard),
        value_matcher_(value_matcher),
        control_matcher_(control_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose value (";
    value_matcher_.DescribeTo(os);
    *os << ") and control (";
    control_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0),
                                 "value", value_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetControlInput(node),
                                 "control", control_matcher_, listener));
  }

 private:
  const Matcher<Node*> value_matcher_;
  const Matcher<Node*> control_matcher_;
};

template <typename T>
class IsConstantMatcher final : public TestNodeMatcher {
 public:
  IsConstantMatcher(IrOpcode::Value opcode, const Matcher<T>& value_matcher)
      : TestNodeMatcher(opcode), value_matcher_(value_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose value (";
    value_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(OpParameter<T>(node->op()), "value",
                                 value_matcher_, listener));
  }

 private:
  const Matcher<T> value_matcher_;
};

class IsSelectMatcher final : public TestNodeMatcher {
 public:
  IsSelectMatcher(const Matcher<MachineRepresentation>& type_matcher,
                  const Matcher<Node*>& value0_matcher,
                  const Matcher<Node*>& value1_matcher,
                  const Matcher<Node*>& value2_matcher)
      : TestNodeMatcher(IrOpcode::kSelect),
        type_matcher_(type_matcher),
        value0_matcher_(value0_matcher),
        value1_matcher_(value1_matcher),
        value2_matcher_(value2_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose representation (";
    type_matcher_.DescribeTo(os);
    *os << "), value0 (";
    value0_matcher_.DescribeTo(os);
    *os << "), value1 (";
    value1_matcher_.DescribeTo(os);
    *os << ") and value2 (";
    value2_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (
        TestNodeMatcher::MatchAndExplain(node, listener) &&
        PrintMatchAndExplain(SelectParametersOf(node->op()).representation(),
                             "representation", type_matcher_, listener) &&
        PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0), "value0",
                             value0_matcher_, listener) &&
        PrintMatchAndExplain(NodeProperties::GetValueInput(node, 1), "value1",
                             value1_matcher_, listener) &&
        PrintMatchAndExplain(NodeProperties::GetValueInput(node, 2), "value2",
                             value2_matcher_, listener));
  }

 private:
  const Matcher<MachineRepresentation> type_matcher_;
  const Matcher<Node*> value0_matcher_;
  const Matcher<Node*> value1_matcher_;
  const Matcher<Node*> value2_matcher_;
};

class IsPhiMatcher final : public TestNodeMatcher {
 public:
  IsPhiMatcher(const Matcher<MachineRepresentation>& type_matcher,
               const Matcher<Node*>& value0_matcher,
               const Matcher<Node*>& value1_matcher,
               const Matcher<Node*>& control_matcher)
      : TestNodeMatcher(IrOpcode::kPhi),
        type_matcher_(type_matcher),
        value0_matcher_(value0_matcher),
        value1_matcher_(value1_matcher),
        control_matcher_(control_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose representation (";
    type_matcher_.DescribeTo(os);
    *os << "), value0 (";
    value0_matcher_.DescribeTo(os);
    *os << "), value1 (";
    value1_matcher_.DescribeTo(os);
    *os << ") and control (";
    control_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(PhiRepresentationOf(node->op()),
                                 "representation", type_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0),
                                 "value0", value0_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 1),
                                 "value1", value1_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetControlInput(node),
                                 "control", control_matcher_, listener));
  }

 private:
  const Matcher<MachineRepresentation> type_matcher_;
  const Matcher<Node*> value0_matcher_;
  const Matcher<Node*> value1_matcher_;
  const Matcher<Node*> control_matcher_;
};

class IsPhi2Matcher final : public TestNodeMatcher {
 public:
  IsPhi2Matcher(const Matcher<MachineRepresentation>& type_matcher,
                const Matcher<Node*>& value0_matcher,
                const Matcher<Node*>& value1_matcher,
                const Matcher<Node*>& value2_matcher,
                const Matcher<Node*>& control_matcher)
      : TestNodeMatcher(IrOpcode::kPhi),
        type_matcher_(type_matcher),
        value0_matcher_(value0_matcher),
        value1_matcher_(value1_matcher),
        value2_matcher_(value2_matcher),
        control_matcher_(control_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose representation (";
    type_matcher_.DescribeTo(os);
    *os << "), value0 (";
    value0_matcher_.DescribeTo(os);
    *os << "), value1 (";
    value1_matcher_.DescribeTo(os);
    *os << "), value2 (";
    value2_matcher_.DescribeTo(os);
    *os << ") and control (";
    control_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(PhiRepresentationOf(node->op()),
                                 "representation", type_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0),
                                 "value0", value0_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 1),
                                 "value1", value1_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 2),
                                 "value2", value2_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetControlInput(node),
                                 "control", control_matcher_, listener));
  }

 private:
  const Matcher<MachineRepresentation> type_matcher_;
  const Matcher<Node*> value0_matcher_;
  const Matcher<Node*> value1_matcher_;
  const Matcher<Node*> value2_matcher_;
  const Matcher<Node*> control_matcher_;
};

class IsEffectPhiMatcher final : public TestNodeMatcher {
 public:
  IsEffectPhiMatcher(const Matcher<Node*>& effect0_matcher,
                     const Matcher<Node*>& effect1_matcher,
                     const Matcher<Node*>& control_matcher)
      : TestNodeMatcher(IrOpcode::kEffectPhi),
        effect0_matcher_(effect0_matcher),
        effect1_matcher_(effect1_matcher),
        control_matcher_(control_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << "), effect0 (";
    effect0_matcher_.DescribeTo(os);
    *os << "), effect1 (";
    effect1_matcher_.DescribeTo(os);
    *os << ") and control (";
    control_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(NodeProperties::GetEffectInput(node, 0),
                                 "effect0", effect0_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetEffectInput(node, 1),
                                 "effect1", effect1_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetControlInput(node),
                                 "control", control_matcher_, listener));
  }

 private:
  const Matcher<Node*> effect0_matcher_;
  const Matcher<Node*> effect1_matcher_;
  const Matcher<Node*> control_matcher_;
};

class IsProjectionMatcher final : public TestNodeMatcher {
 public:
  IsProjectionMatcher(const Matcher<size_t>& index_matcher,
                      const Matcher<Node*>& base_matcher)
      : TestNodeMatcher(IrOpcode::kProjection),
        index_matcher_(index_matcher),
        base_matcher_(base_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose index (";
    index_matcher_.DescribeTo(os);
    *os << ") and base (";
    base_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(OpParameter<size_t>(node->op()), "index",
                                 index_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0), "base",
                                 base_matcher_, listener));
  }

 private:
  const Matcher<size_t> index_matcher_;
  const Matcher<Node*> base_matcher_;
};

class IsCallMatcher final : public TestNodeMatcher {
 public:
  IsCallMatcher(const Matcher<const CallDescriptor*>& descriptor_matcher,
                const std::vector<Matcher<Node*>>& value_matchers,
                const Matcher<Node*>& effect_matcher,
                const Matcher<Node*>& control_matcher)
      : TestNodeMatcher(IrOpcode::kCall),
        descriptor_matcher_(descriptor_matcher),
        value_matchers_(value_matchers),
        effect_matcher_(effect_matcher),
        control_matcher_(control_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    for (size_t i = 0; i < value_matchers_.size(); ++i) {
      if (i == 0) {
        *os << " whose value0 (";
      } else {
        *os << "), value" << i << " (";
      }
      value_matchers_[i].DescribeTo(os);
    }
    *os << "), effect (";
    effect_matcher_.DescribeTo(os);
    *os << ") and control (";
    control_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    if (!TestNodeMatcher::MatchAndExplain(node, listener) ||
        !PrintMatchAndExplain(CallDescriptorOf(node->op()), "descriptor",
                              descriptor_matcher_, listener)) {
      return false;
    }
    for (size_t i = 0; i < value_matchers_.size(); ++i) {
      std::ostringstream ost;
      ost << "value" << i;
      if (!PrintMatchAndExplain(
              NodeProperties::GetValueInput(node, static_cast<int>(i)),
              ost.str(), value_matchers_[i], listener)) {
        return false;
      }
    }
    Node* effect_node = nullptr;
    Node* control_node = nullptr;
    if (NodeProperties::FirstEffectIndex(node) < node->InputCount()) {
      effect_node = NodeProperties::GetEffectInput(node);
    }
    if (NodeProperties::FirstControlIndex(node) < node->InputCount()) {
      control_node = NodeProperties::GetControlInput(node);
    }
    return (PrintMatchAndExplain(effect_node, "effect", effect_matcher_,
                                 listener) &&
            PrintMatchAndExplain(control_node, "control", control_matcher_,
                                 listener));
  }

 private:
  const Matcher<const CallDescriptor*> descriptor_matcher_;
  const std::vector<Matcher<Node*>> value_matchers_;
  const Matcher<Node*> effect_matcher_;
  const Matcher<Node*> control_matcher_;
};

class IsTailCallMatcher final : public TestNodeMatcher {
 public:
  IsTailCallMatcher(const Matcher<CallDescriptor const*>& descriptor_matcher,
                    const std::vector<Matcher<Node*>>& value_matchers,
                    const Matcher<Node*>& effect_matcher,
                    const Matcher<Node*>& control_matcher)
      : TestNodeMatcher(IrOpcode::kTailCall),
        descriptor_matcher_(descriptor_matcher),
        value_matchers_(value_matchers),
        effect_matcher_(effect_matcher),
        control_matcher_(control_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    for (size_t i = 0; i < value_matchers_.size(); ++i) {
      if (i == 0) {
        *os << " whose value0 (";
      } else {
        *os << "), value" << i << " (";
      }
      value_matchers_[i].DescribeTo(os);
    }
    *os << "), effect (";
    effect_matcher_.DescribeTo(os);
    *os << ") and control (";
    control_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    if (!TestNodeMatcher::MatchAndExplain(node, listener) ||
        !PrintMatchAndExplain(CallDescriptorOf(node->op()), "descriptor",
                              descriptor_matcher_, listener)) {
      return false;
    }
    for (size_t i = 0; i < value_matchers_.size(); ++i) {
      std::ostringstream ost;
      ost << "value" << i;
      if (!PrintMatchAndExplain(
              NodeProperties::GetValueInput(node, static_cast<int>(i)),
              ost.str(), value_matchers_[i], listener)) {
        return false;
      }
    }
    Node* effect_node = nullptr;
    Node* control_node = nullptr;
    if (NodeProperties::FirstEffectIndex(node) < node->InputCount()) {
      effect_node = NodeProperties::GetEffectInput(node);
    }
    if (NodeProperties::FirstControlIndex(node) < node->InputCount()) {
      control_node = NodeProperties::GetControlInput(node);
    }
    return (PrintMatchAndExplain(effect_node, "effect", effect_matcher_,
                                 listener) &&
            PrintMatchAndExplain(control_node, "control", control_matcher_,
                                 listener));
  }

 private:
  const Matcher<CallDescriptor const*> descriptor_matcher_;
  const std::vector<Matcher<Node*>> value_matchers_;
  const Matcher<Node*> effect_matcher_;
  const Matcher<Node*> control_matcher_;
};

class IsSpeculativeBinopMatcher final : public TestNodeMatcher {
 public:
  IsSpeculativeBinopMatcher(IrOpcode::Value opcode,
                            const Matcher<NumberOperationHint>& hint_matcher,
                            const Matcher<Node*>& lhs_matcher,
                            const Matcher<Node*>& rhs_matcher,
                            const Matcher<Node*>& effect_matcher,
                            const Matcher<Node*>& control_matcher)
      : TestNodeMatcher(opcode),
        hint_matcher_(hint_matcher),
        lhs_matcher_(lhs_matcher),
        rhs_matcher_(rhs_matcher),
        effect_matcher_(effect_matcher),
        control_matcher_(control_matcher) {}

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            // TODO(bmeurer): The type parameter is currently ignored.
            PrintMatchAndExplain(NumberOperationHintOf(node->op()), "hints",
                                 hint_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0), "lhs",
                                 lhs_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 1), "rhs",
                                 rhs_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetEffectInput(node), "effect",
                                 effect_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetControlInput(node),
                                 "control", control_matcher_, listener));
  }

 private:
  const Matcher<NumberOperationHint> hint_matcher_;
  const Matcher<Type> type_matcher_;
  const Matcher<Node*> lhs_matcher_;
  const Matcher<Node*> rhs_matcher_;
  const Matcher<Node*> effect_matcher_;
  const Matcher<Node*> control_matcher_;
};

class IsAllocateMatcher final : public TestNodeMatcher {
 public:
  IsAllocateMatcher(const Matcher<Node*>& size_matcher,
                    const Matcher<Node*>& effect_matcher,
                    const Matcher<Node*>& control_matcher)
      : TestNodeMatcher(IrOpcode::kAllocate),
        size_matcher_(size_matcher),
        effect_matcher_(effect_matcher),
        control_matcher_(control_matcher) {}

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0), "size",
                                 size_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetEffectInput(node), "effect",
                                 effect_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetControlInput(node),
                                 "control", control_matcher_, listener));
  }

 private:
  const Matcher<Node*> size_matcher_;
  const Matcher<Node*> effect_matcher_;
  const Matcher<Node*> control_matcher_;
};

class IsLoadFieldMatcher final : public TestNodeMatcher {
 public:
  IsLoadFieldMatcher(const Matcher<FieldAccess>& access_matcher,
                     const Matcher<Node*>& base_matcher,
                     const Matcher<Node*>& effect_matcher,
                     const Matcher<Node*>& control_matcher)
      : TestNodeMatcher(IrOpcode::kLoadField),
        access_matcher_(access_matcher),
        base_matcher_(base_matcher),
        effect_matcher_(effect_matcher),
        control_matcher_(control_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose access (";
    access_matcher_.DescribeTo(os);
    *os << "), base (";
    base_matcher_.DescribeTo(os);
    *os << "), effect (";
    effect_matcher_.DescribeTo(os);
    *os << ") and control (";
    control_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(FieldAccessOf(node->op()), "access",
                                 access_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0), "base",
                                 base_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetEffectInput(node), "effect",
                                 effect_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetControlInput(node),
                                 "control", control_matcher_, listener));
  }

 private:
  const Matcher<FieldAccess> access_matcher_;
  const Matcher<Node*> base_matcher_;
  const Matcher<Node*> effect_matcher_;
  const Matcher<Node*> control_matcher_;
};

class IsStoreFieldMatcher final : public TestNodeMatcher {
 public:
  IsStoreFieldMatcher(const Matcher<FieldAccess>& access_matcher,
                      const Matcher<Node*>& base_matcher,
                      const Matcher<Node*>& value_matcher,
                      const Matcher<Node*>& effect_matcher,
                      const Matcher<Node*>& control_matcher)
      : TestNodeMatcher(IrOpcode::kStoreField),
        access_matcher_(access_matcher),
        base_matcher_(base_matcher),
        value_matcher_(value_matcher),
        effect_matcher_(effect_matcher),
        control_matcher_(control_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose access (";
    access_matcher_.DescribeTo(os);
    *os << "), base (";
    base_matcher_.DescribeTo(os);
    *os << "), value (";
    value_matcher_.DescribeTo(os);
    *os << "), effect (";
    effect_matcher_.DescribeTo(os);
    *os << ") and control (";
    control_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(FieldAccessOf(node->op()), "access",
                                 access_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0), "base",
                                 base_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 1),
                                 "value", value_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetEffectInput(node), "effect",
                                 effect_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetControlInput(node),
                                 "control", control_matcher_, listener));
  }

 private:
  const Matcher<FieldAccess> access_matcher_;
  const Matcher<Node*> base_matcher_;
  const Matcher<Node*> value_matcher_;
  const Matcher<Node*> effect_matcher_;
  const Matcher<Node*> control_matcher_;
};

class IsLoadElementMatcher final : public TestNodeMatcher {
 public:
  IsLoadElementMatcher(const Matcher<ElementAccess>& access_matcher,
                       const Matcher<Node*>& base_matcher,
                       const Matcher<Node*>& index_matcher,
                       const Matcher<Node*>& effect_matcher,
                       const Matcher<Node*>& control_matcher)
      : TestNodeMatcher(IrOpcode::kLoadElement),
        access_matcher_(access_matcher),
        base_matcher_(base_matcher),
        index_matcher_(index_matcher),
        effect_matcher_(effect_matcher),
        control_matcher_(control_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose access (";
    access_matcher_.DescribeTo(os);
    *os << "), base (";
    base_matcher_.DescribeTo(os);
    *os << "), index (";
    index_matcher_.DescribeTo(os);
    *os << "), effect (";
    effect_matcher_.DescribeTo(os);
    *os << ") and control (";
    control_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(ElementAccessOf(node->op()), "access",
                                 access_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0), "base",
                                 base_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 1),
                                 "index", index_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetEffectInput(node), "effect",
                                 effect_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetControlInput(node),
                                 "control", control_matcher_, listener));
  }

 private:
  const Matcher<ElementAccess> access_matcher_;
  const Matcher<Node*> base_matcher_;
  const Matcher<Node*> index_matcher_;
  const Matcher<Node*> effect_matcher_;
  const Matcher<Node*> control_matcher_;
};

class IsStoreElementMatcher final : public TestNodeMatcher {
 public:
  IsStoreElementMatcher(const Matcher<ElementAccess>& access_matcher,
                        const Matcher<Node*>& base_matcher,
                        const Matcher<Node*>& index_matcher,
                        const Matcher<Node*>& value_matcher,
                        const Matcher<Node*>& effect_matcher,
                        const Matcher<Node*>& control_matcher)
      : TestNodeMatcher(IrOpcode::kStoreElement),
        access_matcher_(access_matcher),
        base_matcher_(base_matcher),
        index_matcher_(index_matcher),
        value_matcher_(value_matcher),
        effect_matcher_(effect_matcher),
        control_matcher_(control_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose access (";
    access_matcher_.DescribeTo(os);
    *os << "), base (";
    base_matcher_.DescribeTo(os);
    *os << "), index (";
    index_matcher_.DescribeTo(os);
    *os << "), value (";
    value_matcher_.DescribeTo(os);
    *os << "), effect (";
    effect_matcher_.DescribeTo(os);
    *os << ") and control (";
    control_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(ElementAccessOf(node->op()), "access",
                                 access_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0), "base",
                                 base_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 1),
                                 "index", index_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 2),
                                 "value", value_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetEffectInput(node), "effect",
                                 effect_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetControlInput(node),
                                 "control", control_matcher_, listener));
  }

 private:
  const Matcher<ElementAccess> access_matcher_;
  const Matcher<Node*> base_matcher_;
  const Matcher<Node*> index_matcher_;
  const Matcher<Node*> value_matcher_;
  const Matcher<Node*> effect_matcher_;
  const Matcher<Node*> control_matcher_;
};

#define LOAD_MATCHER(kLoad)                                                   \
  class Is##kLoad##Matcher final : public TestNodeMatcher {                   \
   public:                                                                    \
    Is##kLoad##Matcher(const Matcher<LoadRepresentation>& rep_matcher,        \
                       const Matcher<Node*>& base_matcher,                    \
                       const Matcher<Node*>& index_matcher,                   \
                       const Matcher<Node*>& effect_matcher,                  \
                       const Matcher<Node*>& control_matcher)                 \
        : TestNodeMatcher(IrOpcode::k##kLoad),                                \
          rep_matcher_(rep_matcher),                                          \
          base_matcher_(base_matcher),                                        \
          index_matcher_(index_matcher),                                      \
          effect_matcher_(effect_matcher),                                    \
          control_matcher_(control_matcher) {}                                \
                                                                              \
    void DescribeTo(std::ostream* os) const final {                           \
      TestNodeMatcher::DescribeTo(os);                                        \
      *os << " whose rep (";                                                  \
      rep_matcher_.DescribeTo(os);                                            \
      *os << "), base (";                                                     \
      base_matcher_.DescribeTo(os);                                           \
      *os << "), index (";                                                    \
      index_matcher_.DescribeTo(os);                                          \
      *os << "), effect (";                                                   \
      effect_matcher_.DescribeTo(os);                                         \
      *os << ") and control (";                                               \
      control_matcher_.DescribeTo(os);                                        \
      *os << ")";                                                             \
    }                                                                         \
                                                                              \
    bool MatchAndExplain(Node* node,                                          \
                         MatchResultListener* listener) const final {         \
      Node* effect_node = nullptr;                                            \
      Node* control_node = nullptr;                                           \
      if (NodeProperties::FirstEffectIndex(node) < node->InputCount()) {      \
        effect_node = NodeProperties::GetEffectInput(node);                   \
      }                                                                       \
      if (NodeProperties::FirstControlIndex(node) < node->InputCount()) {     \
        control_node = NodeProperties::GetControlInput(node);                 \
      }                                                                       \
      LoadRepresentation rep = IrOpcode::kLoadFromObject == node->opcode()    \
                                   ? ObjectAccessOf(node->op()).machine_type  \
                                   : LoadRepresentationOf(node->op());        \
      return (TestNodeMatcher::MatchAndExplain(node, listener) &&             \
              PrintMatchAndExplain(rep, "rep", rep_matcher_, listener) &&     \
              PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0),    \
                                   "base", base_matcher_, listener) &&        \
              PrintMatchAndExplain(NodeProperties::GetValueInput(node, 1),    \
                                   "index", index_matcher_, listener) &&      \
              PrintMatchAndExplain(effect_node, "effect", effect_matcher_,    \
                                   listener) &&                               \
              PrintMatchAndExplain(control_node, "control", control_matcher_, \
                                   listener));                                \
    }                                                                         \
                                                                              \
   private:                                                                   \
    const Matcher<LoadRepresentation> rep_matcher_;                           \
    const Matcher<Node*> base_matcher_;                                       \
    const Matcher<Node*> index_matcher_;                                      \
    const Matcher<Node*> effect_matcher_;                                     \
    const Matcher<Node*> control_matcher_;                                    \
  };

LOAD_MATCHER(Load)
LOAD_MATCHER(UnalignedLoad)
LOAD_MATCHER(LoadFromObject)

class IsLoadImmutableMatcher final : public TestNodeMatcher {
 public:
  IsLoadImmutableMatcher(const Matcher<LoadRepresentation>& rep_matcher,
                         const Matcher<Node*>& base_matcher,
                         const Matcher<Node*>& index_matcher)
      : TestNodeMatcher(IrOpcode::kLoadImmutable),
        rep_matcher_(rep_matcher),
        base_matcher_(base_matcher),
        index_matcher_(index_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose rep (";
    rep_matcher_.DescribeTo(os);
    *os << "), base (";
    base_matcher_.DescribeTo(os);
    *os << ") and index (";
    index_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    LoadRepresentation rep = LoadRepresentationOf(node->op());
    return TestNodeMatcher::MatchAndExplain(node, listener) &&
           PrintMatchAndExplain(rep, "rep", rep_matcher_, listener) &&
           PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0), "base",
                                base_matcher_, listener) &&
           PrintMatchAndExplain(NodeProperties::GetValueInput(node, 1), "index",
                                index_matcher_, listener);
  }

 private:
  const Matcher<LoadRepresentation> rep_matcher_;
  const Matcher<Node*> base_matcher_;
  const Matcher<Node*> index_matcher_;
};

#define STORE_MATCHER(kStore, representation)                                 \
  class Is##kStore##Matcher final : public TestNodeMatcher {                  \
   public:                                                                    \
    Is##kStore##Matcher(const Matcher<representation>& rep_matcher,           \
                        const Matcher<Node*>& base_matcher,                   \
                        const Matcher<Node*>& index_matcher,                  \
                        const Matcher<Node*>& value_matcher,                  \
                        const Matcher<Node*>& effect_matcher,                 \
                        const Matcher<Node*>& control_matcher)                \
        : TestNodeMatcher(IrOpcode::k##kStore),                               \
          rep_matcher_(rep_matcher),                                          \
          base_matcher_(base_matcher),                                        \
          index_matcher_(index_matcher),                                      \
          value_matcher_(value_matcher),                                      \
          effect_matcher_(effect_matcher),                                    \
          control_matcher_(control_matcher) {}                                \
                                                                              \
    void DescribeTo(std::ostream* os) const final {                           \
      TestNodeMatcher::DescribeTo(os);                                        \
      *os << " whose rep (";                                                  \
      rep_matcher_.DescribeTo(os);                                            \
      *os << "), base (";                                                     \
      base_matcher_.DescribeTo(os);                                           \
      *os << "), index (";                                                    \
      index_matcher_.DescribeTo(os);                                          \
      *os << "), value (";                                                    \
      value_matcher_.DescribeTo(os);                                          \
      *os << "), effect (";                                                   \
      effect_matcher_.DescribeTo(os);                                         \
      *os << ") and control (";                                               \
      control_matcher_.DescribeTo(os);                                        \
      *os << ")";                                                             \
    }                                                                         \
                                                                              \
    bool MatchAndExplain(Node* node,                                          \
                         MatchResultListener* listener) const final {         \
      Node* effect_node = nullptr;                                            \
      Node* control_node = nullptr;                                           \
      if (NodeProperties::FirstEffectIndex(node) < node->InputCount()) {      \
        effect_node = NodeProperties::GetEffectInput(node);                   \
      }                                                                       \
      if (NodeProperties::FirstControlIndex(node) < node->InputCount()) {     \
        control_node = NodeProperties::GetControlInput(node);                 \
      }                                                                       \
      return (TestNodeMatcher::MatchAndExplain(node, listener) &&             \
              PrintMatchAndExplain(OpParameter<representation>(node->op()),   \
                                   "rep", rep_matcher_, listener) &&          \
              PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0),    \
                                   "base", base_matcher_, listener) &&        \
              PrintMatchAndExplain(NodeProperties::GetValueInput(node, 1),    \
                                   "index", index_matcher_, listener) &&      \
              PrintMatchAndExplain(NodeProperties::GetValueInput(node, 2),    \
                                   "value", value_matcher_, listener) &&      \
              PrintMatchAndExplain(effect_node, "effect", effect_matcher_,    \
                                   listener) &&                               \
              PrintMatchAndExplain(control_node, "control", control_matcher_, \
                                   listener));                                \
    }                                                                         \
                                                                              \
   private:                                                                   \
    const Matcher<representation> rep_matcher_;                               \
    const Matcher<Node*> base_matcher_;                                       \
    const Matcher<Node*> index_matcher_;                                      \
    const Matcher<Node*> value_matcher_;                                      \
    const Matcher<Node*> effect_matcher_;                                     \
    const Matcher<Node*> control_matcher_;                                    \
  };

STORE_MATCHER(Store, StoreRepresentation)
STORE_MATCHER(UnalignedStore, UnalignedStoreRepresentation)
STORE_MATCHER(StoreToObject, ObjectAccess)

class IsStackSlotMatcher final : public TestNodeMatcher {
 public:
  explicit IsStackSlotMatcher(
      const Matcher<StackSlotRepresentation>& rep_matcher)
      : TestNodeMatcher(IrOpcode::kStackSlot), rep_matcher_(rep_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose rep (";
    rep_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(StackSlotRepresentationOf(node->op()), "rep",
                                 rep_matcher_, listener));
  }

 private:
  const Matcher<StackSlotRepresentation> rep_matcher_;
};

class IsToNumberMatcher final : public TestNodeMatcher {
 public:
  IsToNumberMatcher(const Matcher<Node*>& base_matcher,
                    const Matcher<Node*>& context_matcher,
                    const Matcher<Node*>& effect_matcher,
                    const Matcher<Node*>& control_matcher)
      : TestNodeMatcher(IrOpcode::kJSToNumber),
        base_matcher_(base_matcher),
        context_matcher_(context_matcher),
        effect_matcher_(effect_matcher),
        control_matcher_(control_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose base (";
    base_matcher_.DescribeTo(os);
    *os << "), context (";
    context_matcher_.DescribeTo(os);
    *os << "), effect (";
    effect_matcher_.DescribeTo(os);
    *os << ") and control (";
    control_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0), "base",
                                 base_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetContextInput(node),
                                 "context", context_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetEffectInput(node), "effect",
                                 effect_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetControlInput(node),
                                 "control", control_matcher_, listener));
  }

 private:
  const Matcher<Node*> base_matcher_;
  const Matcher<Node*> context_matcher_;
  const Matcher<Node*> effect_matcher_;
  const Matcher<Node*> control_matcher_;
};

class IsLoadContextMatcher final : public TestNodeMatcher {
 public:
  IsLoadContextMatcher(const Matcher<ContextAccess>& access_matcher,
                       const Matcher<Node*>& context_matcher)
      : TestNodeMatcher(IrOpcode::kJSLoadContext),
        access_matcher_(access_matcher),
        context_matcher_(context_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose access (";
    access_matcher_.DescribeTo(os);
    *os << ") and context (";
    context_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(ContextAccessOf(node->op()), "access",
                                 access_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetContextInput(node),
                                 "context", context_matcher_, listener));
  }

 private:
  const Matcher<ContextAccess> access_matcher_;
  const Matcher<Node*> context_matcher_;
};

class IsQuadopMatcher final : public TestNodeMatcher {
 public:
  IsQuadopMatcher(IrOpcode::Value opcode, const Matcher<Node*>& a_matcher,
                  const Matcher<Node*>& b_matcher,
                  const Matcher<Node*>& c_matcher,
                  const Matcher<Node*>& d_matcher)
      : TestNodeMatcher(opcode),
        a_matcher_(a_matcher),
        b_matcher_(b_matcher),
        c_matcher_(c_matcher),
        d_matcher_(d_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose a (";
    a_matcher_.DescribeTo(os);
    *os << ") and b (";
    b_matcher_.DescribeTo(os);
    *os << ") and c (";
    c_matcher_.DescribeTo(os);
    *os << ") and d (";
    d_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0), "a",
                                 a_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 1), "b",
                                 b_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 2), "c",
                                 c_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 3), "d",
                                 d_matcher_, listener));
  }

 private:
  const Matcher<Node*> a_matcher_;
  const Matcher<Node*> b_matcher_;
  const Matcher<Node*> c_matcher_;
  const Matcher<Node*> d_matcher_;
};

class IsTernopMatcher final : public TestNodeMatcher {
 public:
  IsTernopMatcher(IrOpcode::Value opcode, const Matcher<Node*>& lhs_matcher,
                  const Matcher<Node*>& mid_matcher,
                  const Matcher<Node*>& rhs_matcher)
      : TestNodeMatcher(opcode),
        lhs_matcher_(lhs_matcher),
        mid_matcher_(mid_matcher),
        rhs_matcher_(rhs_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose lhs (";
    lhs_matcher_.DescribeTo(os);
    *os << ") and mid (";
    mid_matcher_.DescribeTo(os);
    *os << ") and rhs (";
    rhs_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0), "lhs",
                                 lhs_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 1), "mid",
                                 mid_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 2), "rhs",
                                 rhs_matcher_, listener));
  }

 private:
  const Matcher<Node*> lhs_matcher_;
  const Matcher<Node*> mid_matcher_;
  const Matcher<Node*> rhs_matcher_;
};

class IsBinopMatcher final : public TestNodeMatcher {
 public:
  IsBinopMatcher(IrOpcode::Value opcode, const Matcher<Node*>& lhs_matcher,
                 const Matcher<Node*>& rhs_matcher)
      : TestNodeMatcher(opcode),
        lhs_matcher_(lhs_matcher),
        rhs_matcher_(rhs_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose lhs (";
    lhs_matcher_.DescribeTo(os);
    *os << ") and rhs (";
    rhs_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0), "lhs",
                                 lhs_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 1), "rhs",
                                 rhs_matcher_, listener));
  }

 private:
  const Matcher<Node*> lhs_matcher_;
  const Matcher<Node*> rhs_matcher_;
};

class IsStringConcatMatcher final : public TestNodeMatcher {
 public:
  IsStringConcatMatcher(const Matcher<Node*>& length_matcher,
                        const Matcher<Node*>& lhs_matcher,
                        const Matcher<Node*>& rhs_matcher)
      : TestNodeMatcher(IrOpcode::kStringConcat),
        length_matcher_(length_matcher),
        lhs_matcher_(lhs_matcher),
        rhs_matcher_(rhs_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose length (";
    length_matcher_.DescribeTo(os);
    *os << ") and lhs (";
    lhs_matcher_.DescribeTo(os);
    *os << ") and rhs (";
    rhs_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0),
                                 "length", length_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 1), "lhs",
                                 lhs_matcher_, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 2), "rhs",
                                 rhs_matcher_, listener));
  }

 private:
  const Matcher<Node*> length_matcher_;
  const Matcher<Node*> lhs_matcher_;
  const Matcher<Node*> rhs_matcher_;
};

class IsUnopMatcher final : public TestNodeMatcher {
 public:
  IsUnopMatcher(IrOpcode::Value opcode, const Matcher<Node*>& input_matcher)
      : TestNodeMatcher(opcode), input_matcher_(input_matcher) {}

  void DescribeTo(std::ostream* os) const final {
    TestNodeMatcher::DescribeTo(os);
    *os << " whose input (";
    input_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(NodeProperties::GetValueInput(node, 0),
                                 "input", input_matcher_, listener));
  }

 private:
  const Matcher<Node*> input_matcher_;
};

class IsParameterMatcher final : public TestNodeMatcher {
 public:
  explicit IsParameterMatcher(const Matcher<int>& index_matcher)
      : TestNodeMatcher(IrOpcode::kParameter), index_matcher_(index_matcher) {}

  void DescribeTo(std::ostream* os) const override {
    *os << "is a Parameter node with index(";
    index_matcher_.DescribeTo(os);
    *os << ")";
  }

  bool MatchAndExplain(Node* node, MatchResultListener* listener) const final {
    return (TestNodeMatcher::MatchAndExplain(node, listener) &&
            PrintMatchAndExplain(ParameterIndexOf(node->op()), "index",
                                 index_matcher_, listener));
  }

 private:
  const Matcher<int> index_matcher_;
};

}  // namespace

Matcher<Node*> IsDead() {
  return MakeMatcher(new TestNodeMatcher(IrOpcode::kDead));
}

Matcher<Node*> IsUnreachable() {
  return MakeMatcher(new TestNodeMatcher(IrOpcode::kUnreachable));
}

Matcher<Node*> IsThrow() {
  return MakeMatcher(new TestNodeMatcher(IrOpcode::kThrow));
}

Matcher<Node*> IsStart() {
  return MakeMatcher(new TestNodeMatcher(IrOpcode::kStart));
}

Matcher<Node*> IsEnd(const Matcher<Node*>& control0_matcher) {
  return MakeMatcher(new IsControl1Matcher(IrOpcode::kEnd, control0_matcher));
}


Matcher<Node*> IsEnd(const Matcher<Node*>& control0_matcher,
                     const Matcher<Node*>& control1_matcher) {
  return MakeMatcher(new IsControl2Matcher(IrOpcode::kEnd, control0_matcher,
                                           control1_matcher));
}


Matcher<Node*> IsEnd(const Matcher<Node*>& control0_matcher,
                     const Matcher<Node*>& control1_matcher,
                     const Matcher<Node*>& control2_matcher) {
  return MakeMatcher(new IsControl3Matcher(IrOpcode::kEnd, control0_matcher,
                                           control1_matcher, control2_matcher));
}


Matcher<Node*> IsBranch(const Matcher<Node*>& value_matcher,
                        const Matcher<Node*>& control_matcher) {
  return MakeMatcher(new IsBranchMatcher(value_matcher, control_matcher));
}


Matcher<Node*> IsMerge(const Matcher<Node*>& control0_matcher,
                       const Matcher<Node*>& control1_matcher) {
  return MakeMatcher(new IsControl2Matcher(IrOpcode::kMerge, control0_matcher,
                                           control1_matcher));
}


Matcher<Node*> 
"""


```