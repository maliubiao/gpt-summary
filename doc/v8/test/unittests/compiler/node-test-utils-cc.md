Response:
Let's break down the thought process for analyzing this C++ code and generating the summary.

1. **Understand the Goal:** The request asks for a functional summary of the provided C++ code snippet, which is part of V8's compiler testing utilities. It also prompts for checking if the file could be Torque and for JavaScript relevance, along with examples and common programming error connections.

2. **Initial Scan and Keyword Spotting:**  Quickly read through the code, looking for recognizable patterns and keywords. I see:
    * `#include`:  Indicates standard C++ includes and V8-specific headers related to compiler components (`compiler/common-operator.h`, `compiler/js-operator.h`, etc.).
    * `namespace v8 { namespace internal { namespace compiler {`:  Confirms this is within the V8 compiler namespace.
    * `using testing::...`:  Suggests the use of a testing framework (likely Google Test).
    * `class ...Matcher`:  A recurring pattern indicating the definition of custom matchers.
    * `MatchAndExplain`, `DescribeTo`: These are standard methods in Google Test's custom matcher interface.
    * `Node*`: Pointers to `Node` objects are prevalent, indicating this code deals with the compiler's intermediate representation (IR).
    * `IrOpcode`:  Enums related to IR operations.
    * `NodeProperties`:  Utilities for accessing properties of IR nodes.
    * Specific `IrOpcode` values (e.g., `kBranch`, `kLoopExitValue`, `kSwitch`, etc.): These directly point to specific compiler node types.

3. **Identify the Core Functionality:** The repetition of `class ...Matcher` and their internal logic strongly suggests that this code defines a set of **custom matchers** for V8 compiler IR nodes. These matchers are designed to make testing easier and more expressive. They allow testers to assert specific properties of nodes without writing verbose manual checks.

4. **Analyze Individual Matchers (Pattern Recognition):** Look at the structure of the matcher classes:
    * They inherit from `MatcherInterface<Node*>`.
    * They have a constructor that usually takes specific arguments to define what they are matching against (e.g., an `IrOpcode`, other matchers).
    * `DescribeTo` provides a human-readable description of what the matcher is checking.
    * `MatchAndExplain` performs the actual matching logic and provides detailed explanations for mismatches.
    * They often use `PrintMatchAndExplain` to delegate the matching and explanation of nested properties to other matchers.

5. **Categorize Matchers by Node Type:** Observe that many matchers are named after specific IR node types (e.g., `IsBranchMatcher`, `IsLoopExitValueMatcher`, `IsSwitchMatcher`). This strongly suggests that each matcher is designed to verify the properties of a particular kind of compiler node.

6. **Determine the Purpose of Matching:**  The matchers check various aspects of a `Node`:
    * Its opcode (`IrOpcode`).
    * Its input values (using `NodeProperties::GetValueInput`).
    * Its control inputs (using `NodeProperties::GetControlInput`).
    * Its effect inputs (using `NodeProperties::GetEffectInput`).
    * Specific properties extracted from the node's operator (e.g., `LoopExitValueRepresentationOf`, `IfValueParametersOf`).

7. **Address the Specific Questions in the Prompt:**

    * **Functionality:**  The core function is providing custom matchers for testing compiler IR nodes.
    * **Torque:** The filename ends in `.cc`, not `.tq`. Therefore, it's not a Torque file.
    * **JavaScript Relation:**  While this code *directly* manipulates compiler IR, which is *generated* from JavaScript code, it doesn't directly interact with JavaScript syntax or runtime. The connection is indirect: these tests verify the correctness of the compiler's transformations of JavaScript. This needs careful wording to avoid overstating the direct connection. An example of JavaScript code that *could* lead to the creation of these nodes is appropriate.
    * **Code Logic and Input/Output:** The matchers themselves embody logic. The "input" is a `Node*`, and the "output" is a boolean (match or no match) along with a descriptive message. Provide a simple example of a matcher and a matching/non-matching node.
    * **Common Programming Errors:**  The matchers help *detect* errors in the compiler. Focus on how incorrect compiler transformations *would* be caught by these matchers. A concrete example related to incorrect control flow or data flow would be good.

8. **Structure the Summary:**  Organize the findings logically:

    * Start with the main function: providing custom matchers for compiler node testing.
    * Explain what these matchers do (verify opcode, inputs, etc.).
    * Address the Torque question.
    * Explain the JavaScript connection, emphasizing the indirect nature and providing an example.
    * Provide a code logic example with input and output.
    * Illustrate how these matchers help catch compiler errors with a concrete scenario.
    * Conclude with a summary of the overall function of this part of the code.

9. **Refine and Elaborate:** Review the summary for clarity, accuracy, and completeness. Ensure the language is precise and avoids jargon where possible, or explains it when necessary. For instance, clearly define what "IR nodes" are in the context of a compiler.

This step-by-step process, moving from a broad overview to specific details and then addressing each part of the prompt, allows for a comprehensive and accurate understanding and summary of the provided code.
这是对 V8 源代码文件 `v8/test/unittests/compiler/node-test-utils.cc` 的第一部分分析。

**功能归纳：**

该文件定义了一系列的 **GTest Matchers (匹配器)**，用于方便地断言 V8 编译器中间表示 (IR) 中的 `Node` 对象的属性。这些匹配器允许测试用例以更简洁和易懂的方式验证生成的编译器节点是否符合预期。

**具体功能拆解：**

1. **自定义相等运算符：**
   - 为 `Handle<HeapObject>` 定义了 `operator==`，使得可以使用 `is_identical_to` 方法比较两个句柄是否指向同一个堆对象。这为后续的匹配器提供了基础。

2. **辅助函数 `PrintMatchAndExplain`：**
   - 这是一个模板函数，用于在匹配过程中打印详细的匹配信息和解释。它接收一个值、值的名称、一个 `Matcher` 对象和一个 `MatchResultListener`，执行匹配并向 listener 输出结果，如果匹配失败，还会提供更详细的解释信息。

3. **基础节点匹配器 `TestNodeMatcher`：**
   - 这是一个抽象基类，用于检查 `Node` 对象的 `opcode` (操作码)。
   - `DescribeTo` 方法用于生成描述匹配器的字符串，例如 "is a LoadField node"。
   - `MatchAndExplain` 方法执行实际匹配，检查节点的 `opcode` 是否与预期一致。

4. **特定节点类型的匹配器：**
   - 文件中定义了许多继承自 `TestNodeMatcher` 的具体匹配器，用于检查特定类型的 IR 节点及其属性：
     - **`IsBranchMatcher`:** 匹配 `Branch` 节点，并检查其 `value` 输入和 `control` 输入是否匹配给定的匹配器。
     - **`IsLoopExitValueMatcher`:** 匹配 `LoopExitValue` 节点，并检查其表示形式 (`rep`) 和 `value` 输入。
     - **`IsSwitchMatcher`:** 匹配 `Switch` 节点，并检查其 `value` 输入和 `control` 输入。
     - **`IsIfValueMatcher`:** 匹配 `IfValue` 节点，并检查其 `value` 参数和 `control` 输入。
     - **`IsControl1Matcher`**, **`IsControl2Matcher`**, **`IsControl3Matcher`:** 匹配具有 1 个、2 个或 3 个控制输入的控制流节点。
     - **`IsBeginRegionMatcher`:** 匹配 `BeginRegion` 节点，并检查其 `effect` 输入。
     - **`IsFinishRegionMatcher`:** 匹配 `FinishRegion` 节点，并检查其 `value` 输入和 `effect` 输入。
     - **`IsReturnMatcher`:** 匹配 `Return` 节点，并检查其返回值（可能有两个）、`effect` 输入和 `control` 输入。
     - **`IsTerminateMatcher`:** 匹配 `Terminate` 节点，并检查其 `effect` 输入和 `control` 输入。
     - **`IsTypeGuardMatcher`:** 匹配 `TypeGuard` 节点，并检查其 `value` 输入和 `control` 输入。
     - **`IsConstantMatcher`:** 匹配常量节点，并检查其常量值。
     - **`IsSelectMatcher`:** 匹配 `Select` 节点，并检查其表示形式、三个输入值。
     - **`IsPhiMatcher`**, **`IsPhi2Matcher`:** 匹配 `Phi` 节点，并检查其表示形式、输入值和控制输入。
     - **`IsEffectPhiMatcher`:** 匹配 `EffectPhi` 节点，并检查其 effect 输入和控制输入。
     - **`IsProjectionMatcher`:** 匹配 `Projection` 节点，并检查其索引和基础节点。
     - **`IsCallMatcher`:** 匹配 `Call` 节点，并检查其调用描述符、输入值、effect 输入和 control 输入。
     - **`IsTailCallMatcher`:** 匹配 `TailCall` 节点，与 `IsCallMatcher` 类似，用于尾调用。
     - **`IsSpeculativeBinopMatcher`:** 匹配投机二元运算节点，并检查其 hint、左右操作数、effect 输入和 control 输入。
     - **`IsAllocateMatcher`:** 匹配内存分配节点，并检查其大小、effect 输入和 control 输入。

**关于文件类型和 JavaScript 关联：**

- **文件类型：** `v8/test/unittests/compiler/node-test-utils.cc` 的后缀是 `.cc`，这表明它是一个 **C++ 源代码文件**。因此，它不是 Torque 源代码。

- **JavaScript 关联：** 该文件与 JavaScript 的功能 **有关系**。编译器的工作是将 JavaScript 代码转换成机器码。这些匹配器用于测试编译器在将 JavaScript 代码转换为内部表示形式（IR 图）时是否正确地生成了各种类型的节点。

**JavaScript 举例说明：**

虽然 `node-test-utils.cc` 是 C++ 代码，但它可以用来测试由编译以下 JavaScript 代码生成的 IR 图：

```javascript
function example(a, b) {
  if (a > 0) {
    return a + b;
  } else {
    return b - a;
  }
}
```

当 V8 编译 `example` 函数时，会生成一个 IR 图，其中可能包含以下类型的节点，而 `node-test-utils.cc` 中的匹配器可以用来断言这些节点的存在和属性：

- **`Branch` 节点:** 用于表示 `if (a > 0)` 的条件分支。
- **`Return` 节点:** 用于表示 `return a + b;` 和 `return b - a;`。
- **`Phi` 节点:** 如果 `example` 函数在一个循环中，可能存在 `Phi` 节点用于合并来自不同执行路径的值。
- **特定的算术运算节点 (例如，加法或减法)：** 用于表示 `a + b` 和 `b - a`。

**代码逻辑推理 (假设输入与输出):**

假设我们有一个 `Node* node` 指向一个表示 `if (x)` 语句的 `Branch` 节点，并且我们想使用 `IsBranchMatcher` 来断言它：

```c++
// 假设 node 指向一个 Branch 节点，其 value 输入是表示 'x' 的节点，
// 并且 control 输入是前一个控制流节点。
Node* value_node = /* ... 获取表示 'x' 的节点 ... */;
Node* control_node = /* ... 获取前一个控制流节点 ... */;

EXPECT_THAT(node, IsBranch(value_node, control_node));
```

- **假设输入:**
  - `node`: 指向一个 `IrOpcode::kBranch` 的 `Node` 对象。
  - `value_node`: 指向 `node` 的 value 输入的 `Node` 对象。
  - `control_node`: 指向 `node` 的 control 输入的 `Node` 对象。

- **预期输出:**
  - 如果 `node` 的 `opcode` 是 `IrOpcode::kBranch`，并且其 value 输入与 `value_node` 相同，control 输入与 `control_node` 相同，则断言成功。
  - 否则，断言失败，并会输出包含详细信息的错误消息，说明哪个部分不匹配（例如，opcode 不匹配，或者输入节点不一致）。

**涉及用户常见的编程错误 (编译器测试角度):**

从编译器测试的角度来看，这些匹配器帮助检测编译器在 IR 生成阶段的错误，这些错误可能源于以下 JavaScript 编程模式或编译器的缺陷：

1. **错误的控制流生成：**  例如，`if` 语句的条件判断被错误地编译，导致 `Branch` 节点的 value 输入不正确，或者目标控制流不正确。
   ```javascript
   // 用户代码
   if (someCondition) {
     // ...
   }
   ```
   **可能出现的编译器错误 (会被匹配器检测到):** 生成的 `Branch` 节点的 `value` 输入没有正确地表示 `someCondition` 的计算结果。

2. **数据流错误：** 例如，变量的值在传递或使用过程中出现错误，导致 `Phi` 节点或运算节点的输入不正确。
   ```javascript
   // 用户代码
   let x = 10;
   if (condition) {
     x = 20;
   }
   return x;
   ```
   **可能出现的编译器错误 (会被匹配器检测到):**  `Return` 节点的 value 输入没有正确地合并来自不同路径的 `x` 的值（可能 `Phi` 节点配置错误）。

3. **类型推断错误：**  编译器对变量类型的错误推断可能导致生成错误的运算节点。虽然这个文件中的匹配器主要关注节点结构，但某些匹配器（如 `IsSpeculativeBinopMatcher`）会检查与类型相关的 hint 信息。
   ```javascript
   // 用户代码
   function add(a, b) {
     return a + b;
   }
   ```
   **可能出现的编译器错误 (会被匹配器检测到):** 如果编译器错误地认为 `a` 和 `b` 总是整数，可能会生成优化的整数加法节点，而实际上它们可能是其他类型，`IsSpeculativeBinopMatcher` 可以检查其 `NumberOperationHint` 是否符合预期。

**总结 (第一部分功能):**

`v8/test/unittests/compiler/node-test-utils.cc` 的第一部分定义了一套用于测试 V8 编译器生成的 IR 图的强大的工具。它通过提供易于使用的 GTest 匹配器，使得测试用例能够清晰地表达对编译器输出的期望，并有效地检测编译器在节点生成过程中的错误。这些匹配器覆盖了多种关键的 IR 节点类型及其属性，为确保编译器的正确性提供了重要的保障。

Prompt: 
```
这是目录为v8/test/unittests/compiler/node-test-utils.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/node-test-utils.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

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
        
"""


```