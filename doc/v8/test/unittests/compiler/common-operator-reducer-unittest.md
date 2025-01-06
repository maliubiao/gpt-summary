Response: Let's break down the thought process to analyze this C++ unit test file and provide a good summary with JavaScript examples.

1. **Understand the Core Purpose:** The filename `common-operator-reducer-unittest.cc` immediately suggests it's testing a component called `CommonOperatorReducer`. The "unittest" part confirms this. "Reducer" in a compiler context usually means a process of simplifying or transforming the intermediate representation (IR) of the code.

2. **Identify Key Components and Concepts:**  Skimming the `#include` directives reveals the primary focus:
    * `src/compiler/common-operator-reducer.h`: The class being tested.
    * `src/compiler/common-operator.h`, `src/compiler/machine-operator.h`, `src/compiler/simplified-operator.h`, `src/compiler/operator.h`: These are related to the intermediate representation (IR) in V8, defining different kinds of operations.
    * `test/unittests/compiler/graph-reducer-unittest.h`, `test/unittests/compiler/graph-unittest.h`, `test/unittests/compiler/node-test-utils.h`:  These are testing infrastructure for the V8 compiler, involving graphs of nodes representing the IR.

3. **Examine the Test Structure:** The code defines a test fixture `CommonOperatorReducerTest` inheriting from `GraphTest`. This tells us that the tests operate on a graph representation of code. The `Reduce` methods are central, suggesting they invoke the `CommonOperatorReducer` to process nodes in the graph.

4. **Focus on Individual Test Cases:**  The `TEST_F` macros define individual test cases. Analyzing their names is crucial:
    * `BranchWith...`: Tests related to the `Branch` operator. The conditions (e.g., `Int32ZeroConstant`, `FalseConstant`, `BooleanNot`, `Select`) indicate what kind of inputs are being tested for the `Branch` operation.
    * `MergeOfUnusedDiamond...`: Tests involving the `Merge` operator in a specific control flow structure (a diamond).
    * `EffectPhiWith...`, `PhiWith...`: Tests related to `EffectPhi` and `Phi` nodes, often in the context of `Merge` and `Loop` structures. These are related to merging control flow and data flow.
    * `ReturnWith...`: Tests the `Return` operator, often in complex control flow scenarios.
    * `SelectWith...`: Tests the `Select` operator (like a ternary operator).
    * `SwitchInputMatches...`: Tests the `Switch` operator.

5. **Understand the `Reduce` Logic (High-Level):** The `Reduce` methods take a `Node` (representing an operation in the IR) and apply the `CommonOperatorReducer`. The tests then use `EXPECT_CALL` and assertions (`ASSERT_TRUE`, `EXPECT_EQ`, `EXPECT_THAT`) to verify the *expected transformations* performed by the reducer. The `IsDead()` matcher is common, indicating nodes that should be eliminated.

6. **Identify Relationships to JavaScript:** Look for operators that have direct equivalents or close parallels in JavaScript.
    * **`Branch`:**  Corresponds to `if` statements or conditional expressions.
    * **`Merge`:** Represents the joining of control flow paths, implicitly happening after `if` blocks or loops.
    * **`Phi`:**  Represents merging values from different control flow paths, necessary for variables assigned in conditional blocks.
    * **`Select`:**  A direct counterpart to the ternary operator (`condition ? value1 : value2`).
    * **`Switch`:** The `switch` statement in JavaScript.
    * **`BooleanNot`:** The `!` operator in JavaScript.

7. **Construct JavaScript Examples:**  For each relevant operator, create simple JavaScript snippets that would conceptually lead to the corresponding IR nodes and the simplifications being tested. Focus on illustrating *why* the reducer's transformations are beneficial. For instance:
    * A `Branch` with a constant condition can be simplified to directly execute one branch.
    * A `Select` with a constant condition can be replaced by the chosen value.

8. **Summarize the Functionality:** Combine the understanding of the test structure and the individual test cases to describe the overall purpose of the `CommonOperatorReducer`. Highlight the types of optimizations it performs (constant folding, control flow simplification, etc.).

9. **Refine and Organize:**  Structure the summary logically. Start with the core purpose, then detail the specific areas covered by the tests, and finally, provide the JavaScript examples. Use clear and concise language. Emphasize the link to performance optimization in V8.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This is just testing some compiler stuff."  **Correction:**  Focus on *what* aspects of the compiler are being tested (common operators) and *why* (optimization).
* **Stuck on a specific test:** If a test case is unclear, look at the `EXPECT_CALL`s. They reveal the expected outcome of the reduction. For example, `EXPECT_CALL(editor, Replace(if_true, IsDead()));` clearly means the `if_true` branch should be eliminated.
* **JavaScript example too complex:** Keep the JavaScript examples simple and focused on the core concept being illustrated by the corresponding C++ test. Avoid unnecessary details.
* **Summary too technical:**  Explain the concepts in a way that is accessible to someone with a basic understanding of compilers or programming language execution. Use terms like "optimization" and "simplification" rather than purely compiler-specific jargon.

By following these steps, combining code analysis with an understanding of compiler principles, and focusing on the connection to JavaScript, you can arrive at a comprehensive and informative summary like the example provided in the initial prompt.
这个C++源代码文件 `common-operator-reducer-unittest.cc` 是 V8 JavaScript 引擎的一部分，它专门用于测试 `CommonOperatorReducer` 类的功能。 `CommonOperatorReducer` 的主要职责是在 V8 编译器的优化阶段，**简化和优化中间代码表示（IR，Intermediate Representation）中的通用操作符（Common Operators）**。

**功能归纳:**

该测试文件包含了针对 `CommonOperatorReducer` 的各种单元测试用例，旨在验证以下方面的功能：

1. **常量折叠 (Constant Folding):** 当操作符的输入是常量时，`CommonOperatorReducer` 应该能够直接计算出结果，并用常量结果替换该操作符。 例如，测试了 `Branch` 和 `Select` 操作符在输入是布尔或整数常量时的简化。

2. **控制流简化 (Control Flow Simplification):**  `CommonOperatorReducer` 可以简化控制流结构，例如：
   - 当 `Branch` 操作符的条件是常量时，可以直接消除不需要执行的分支 (`IfTrue` 或 `IfFalse` 节点)。
   - 当 `Merge` 节点的输入来自一个已经确定不会执行到的分支时，可以简化为直接连接到另一个可达的控制流。
   - 简化包含 `Phi` 和 `EffectPhi` 节点的循环和合并操作。

3. **基于上下文的优化:**  例如，测试了 `Phi` 节点在特定条件下可以被简化为 `Float32Abs` 或 `Float64Abs` 操作符。

4. **操作符替换:** 在某些情况下，`CommonOperatorReducer` 可以用更简单的或更高效的操作符替换现有的操作符。例如，当 `Select` 操作符的 then 和 else 分支返回相同的值时，可以直接用该值替换 `Select` 操作符。

5. **`Switch` 语句优化:** 测试了 `Switch` 语句在输入常量已知的情况下，可以直接跳转到对应的 case 或 default 分支。

**与 JavaScript 功能的关系及 JavaScript 示例:**

`CommonOperatorReducer` 的优化直接影响着 V8 执行 JavaScript 代码的性能。它通过在编译时进行各种简化，减少了运行时需要执行的工作。

以下是一些与测试用例相关的 JavaScript 示例，展示了 `CommonOperatorReducer` 可能进行的优化：

**1. `Branch` 操作符的常量折叠 (对应 `BranchWithInt32ZeroConstant`, `BranchWithTrueConstant` 等测试):**

```javascript
// JavaScript 代码
if (0) { // 条件是常量 false
  console.log("This won't be executed");
} else {
  console.log("This will be executed");
}

if (1) { // 条件是常量 true
  console.log("This will be executed");
} else {
  console.log("This won't be executed");
}

if (true) { // 条件是常量 true
  console.log("This will be executed");
} else {
  console.log("This won't be executed");
}

if (false) { // 条件是常量 false
  console.log("This won't be executed");
} else {
  console.log("This will be executed");
}
```

在编译过程中，`CommonOperatorReducer` 会识别出 `if` 语句的条件是常量，并直接确定执行哪个分支，从而避免在运行时进行条件判断。

**2. `Select` 操作符的常量折叠 (对应 `SelectWithInt32ZeroConstant`, `SelectWithTrueConstant` 等测试):**

```javascript
// JavaScript 代码
let x = 0 ? "then" : "else"; // 条件是常量 false
console.log(x); // 输出 "else"

let y = 1 ? "then" : "else"; // 条件是常量 true
console.log(y); // 输出 "then"

let z = true ? "then" : "else"; // 条件是常量 true
console.log(z); // 输出 "then"

let w = false ? "then" : "else"; // 条件是常量 false
console.log(w); // 输出 "else"
```

`CommonOperatorReducer` 会识别出三元运算符的条件是常量，并直接用对应的结果替换 `Select` 操作符。

**3. `Branch` 操作符与 `BooleanNot` 的结合 (对应 `BranchWithBooleanNot` 测试):**

```javascript
// JavaScript 代码
let condition = someValue;
if (!condition) {
  // ...
} else {
  // ...
}
```

`CommonOperatorReducer` 可能会将 `!condition` 的分支调整为 `condition` 的相反分支，从而简化后续的控制流。

**4. `Phi` 节点简化为 `Abs` (对应 `PhiToFloat32Abs`, `PhiToFloat64Abs` 测试):**

```javascript
// JavaScript 代码
function abs(x) {
  if (x < 0) {
    return -x;
  } else {
    return x;
  }
}
```

在编译 `abs` 函数时，V8 会生成一个 `Phi` 节点来合并 `return x` 和 `return -x` 的结果。 `CommonOperatorReducer` 可以识别出这种模式，并将其优化为直接调用绝对值操作。

**5. `Switch` 语句优化 (对应 `SwitchInputMatchesCaseWithDefault` 等测试):**

```javascript
// JavaScript 代码
function handleInput(input) {
  switch (input) {
    case 1:
      console.log("Case 1");
      break;
    case 2:
      console.log("Case 2");
      break;
    default:
      console.log("Default");
  }
}

handleInput(1); // 输入是常量 1
```

当 `switch` 语句的输入是常量时，`CommonOperatorReducer` 可以直接确定要执行的 `case` 分支，并消除其他不相关的分支。

总而言之，`common-operator-reducer-unittest.cc` 文件验证了 V8 编译器中 `CommonOperatorReducer` 类的正确性和有效性，确保它能够正确地对中间代码中的通用操作符进行各种优化，从而提升 JavaScript 代码的执行效率。 这些优化是 V8 引擎高性能的关键组成部分。

Prompt: 
```
这是目录为v8/test/unittests/compiler/common-operator-reducer-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/common-operator-reducer.h"
#include "src/codegen/machine-type.h"
#include "src/compiler/common-operator.h"
#include "src/compiler/machine-operator.h"
#include "src/compiler/operator.h"
#include "src/compiler/simplified-operator.h"
#include "test/unittests/compiler/graph-reducer-unittest.h"
#include "test/unittests/compiler/graph-unittest.h"
#include "test/unittests/compiler/node-test-utils.h"

using testing::StrictMock;

namespace v8 {
namespace internal {
namespace compiler {
namespace common_operator_reducer_unittest {

class CommonOperatorReducerTest : public GraphTest {
 public:
  explicit CommonOperatorReducerTest(int num_parameters = 1)
      : GraphTest(num_parameters), machine_(zone()), simplified_(zone()) {}
  ~CommonOperatorReducerTest() override = default;

 protected:
  Reduction Reduce(
      AdvancedReducer::Editor* editor, Node* node,
      BranchSemantics branch_semantics,
      MachineOperatorBuilder::Flags flags = MachineOperatorBuilder::kNoFlags) {
    MachineOperatorBuilder machine(zone(), MachineType::PointerRepresentation(),
                                   flags);
    CommonOperatorReducer reducer(editor, graph(), broker(), common(), &machine,
                                  zone(), branch_semantics);
    return reducer.Reduce(node);
  }

  Reduction Reduce(
      Node* node, BranchSemantics branch_semantics,
      MachineOperatorBuilder::Flags flags = MachineOperatorBuilder::kNoFlags) {
    StrictMock<MockAdvancedReducerEditor> editor;
    return Reduce(&editor, node, branch_semantics, flags);
  }

  MachineOperatorBuilder* machine() { return &machine_; }
  SimplifiedOperatorBuilder* simplified() { return &simplified_; }

 private:
  MachineOperatorBuilder machine_;
  SimplifiedOperatorBuilder simplified_;
};


namespace {

const BranchHint kBranchHints[] = {BranchHint::kNone, BranchHint::kFalse,
                                   BranchHint::kTrue};


const MachineRepresentation kMachineRepresentations[] = {
    MachineRepresentation::kBit,     MachineRepresentation::kWord8,
    MachineRepresentation::kWord16,  MachineRepresentation::kWord32,
    MachineRepresentation::kWord64,  MachineRepresentation::kFloat32,
    MachineRepresentation::kFloat64, MachineRepresentation::kTagged};


const Operator kOp0(0, Operator::kNoProperties, "Op0", 0, 0, 0, 1, 1, 0);

}  // namespace


// -----------------------------------------------------------------------------
// Branch


TEST_F(CommonOperatorReducerTest, BranchWithInt32ZeroConstant) {
  TRACED_FOREACH(BranchHint, hint, kBranchHints) {
    Node* const control = graph()->start();
    Node* const branch =
        graph()->NewNode(common()->Branch(hint), Int32Constant(0), control);
    Node* const if_true = graph()->NewNode(common()->IfTrue(), branch);
    Node* const if_false = graph()->NewNode(common()->IfFalse(), branch);
    StrictMock<MockAdvancedReducerEditor> editor;
    EXPECT_CALL(editor, Replace(if_true, IsDead()));
    EXPECT_CALL(editor, Replace(if_false, control));
    Reduction const r = Reduce(&editor, branch, BranchSemantics::kMachine);
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsDead());
  }
}


TEST_F(CommonOperatorReducerTest, BranchWithInt32OneConstant) {
  TRACED_FOREACH(BranchHint, hint, kBranchHints) {
    Node* const control = graph()->start();
    Node* const branch =
        graph()->NewNode(common()->Branch(hint), Int32Constant(1), control);
    Node* const if_true = graph()->NewNode(common()->IfTrue(), branch);
    Node* const if_false = graph()->NewNode(common()->IfFalse(), branch);
    StrictMock<MockAdvancedReducerEditor> editor;
    EXPECT_CALL(editor, Replace(if_true, control));
    EXPECT_CALL(editor, Replace(if_false, IsDead()));
    Reduction const r = Reduce(&editor, branch, BranchSemantics::kMachine);
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsDead());
  }
}


TEST_F(CommonOperatorReducerTest, BranchWithFalseConstant) {
  TRACED_FOREACH(BranchHint, hint, kBranchHints) {
    Node* const control = graph()->start();
    Node* const branch =
        graph()->NewNode(common()->Branch(hint), FalseConstant(), control);
    Node* const if_true = graph()->NewNode(common()->IfTrue(), branch);
    Node* const if_false = graph()->NewNode(common()->IfFalse(), branch);
    StrictMock<MockAdvancedReducerEditor> editor;
    EXPECT_CALL(editor, Replace(if_true, IsDead()));
    EXPECT_CALL(editor, Replace(if_false, control));
    Reduction const r = Reduce(&editor, branch, BranchSemantics::kJS);
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsDead());
  }
}


TEST_F(CommonOperatorReducerTest, BranchWithTrueConstant) {
  TRACED_FOREACH(BranchHint, hint, kBranchHints) {
    Node* const control = graph()->start();
    Node* const branch =
        graph()->NewNode(common()->Branch(hint), TrueConstant(), control);
    Node* const if_true = graph()->NewNode(common()->IfTrue(), branch);
    Node* const if_false = graph()->NewNode(common()->IfFalse(), branch);
    StrictMock<MockAdvancedReducerEditor> editor;
    EXPECT_CALL(editor, Replace(if_true, control));
    EXPECT_CALL(editor, Replace(if_false, IsDead()));
    Reduction const r = Reduce(&editor, branch, BranchSemantics::kJS);
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsDead());
  }
}


TEST_F(CommonOperatorReducerTest, BranchWithBooleanNot) {
  Node* const value = Parameter(0);
  TRACED_FOREACH(BranchHint, hint, kBranchHints) {
    Node* const control = graph()->start();
    Node* const branch = graph()->NewNode(
        common()->Branch(hint),
        graph()->NewNode(simplified()->BooleanNot(), value), control);
    Node* const if_true = graph()->NewNode(common()->IfTrue(), branch);
    Node* const if_false = graph()->NewNode(common()->IfFalse(), branch);
    Reduction const r = Reduce(branch, BranchSemantics::kJS);
    ASSERT_TRUE(r.Changed());
    EXPECT_EQ(branch, r.replacement());
    EXPECT_THAT(branch, IsBranch(value, control));
    EXPECT_THAT(if_false, IsIfTrue(branch));
    EXPECT_THAT(if_true, IsIfFalse(branch));
    EXPECT_EQ(NegateBranchHint(hint), BranchHintOf(branch->op()));
  }
}

TEST_F(CommonOperatorReducerTest, BranchWithSelect) {
  Node* const value = Parameter(0);
  TRACED_FOREACH(BranchHint, hint, kBranchHints) {
    Node* const control = graph()->start();
    Node* const branch = graph()->NewNode(
        common()->Branch(hint),
        graph()->NewNode(common()->Select(MachineRepresentation::kTagged),
                         value, FalseConstant(), TrueConstant()),
        control);
    Node* const if_true = graph()->NewNode(common()->IfTrue(), branch);
    Node* const if_false = graph()->NewNode(common()->IfFalse(), branch);
    Reduction const r = Reduce(branch, BranchSemantics::kJS);
    ASSERT_TRUE(r.Changed());
    EXPECT_EQ(branch, r.replacement());
    EXPECT_THAT(branch, IsBranch(value, control));
    EXPECT_THAT(if_false, IsIfTrue(branch));
    EXPECT_THAT(if_true, IsIfFalse(branch));
    EXPECT_EQ(NegateBranchHint(hint), BranchHintOf(branch->op()));
  }
}

// -----------------------------------------------------------------------------
// Merge


TEST_F(CommonOperatorReducerTest, MergeOfUnusedDiamond0) {
  Node* const value = Parameter(0);
  Node* const control = graph()->start();
  Node* const branch = graph()->NewNode(common()->Branch(), value, control);
  Node* const if_true = graph()->NewNode(common()->IfTrue(), branch);
  Node* const if_false = graph()->NewNode(common()->IfFalse(), branch);
  Reduction const r =
      Reduce(graph()->NewNode(common()->Merge(2), if_true, if_false),
             BranchSemantics::kJS);
  ASSERT_TRUE(r.Changed());
  EXPECT_EQ(control, r.replacement());
  EXPECT_THAT(branch, IsDead());
}


TEST_F(CommonOperatorReducerTest, MergeOfUnusedDiamond1) {
  Node* const value = Parameter(0);
  Node* const control = graph()->start();
  Node* const branch = graph()->NewNode(common()->Branch(), value, control);
  Node* const if_true = graph()->NewNode(common()->IfTrue(), branch);
  Node* const if_false = graph()->NewNode(common()->IfFalse(), branch);
  Reduction const r =
      Reduce(graph()->NewNode(common()->Merge(2), if_false, if_true),
             BranchSemantics::kJS);
  ASSERT_TRUE(r.Changed());
  EXPECT_EQ(control, r.replacement());
  EXPECT_THAT(branch, IsDead());
}


// -----------------------------------------------------------------------------
// EffectPhi


TEST_F(CommonOperatorReducerTest, EffectPhiWithMerge) {
  const int kMaxInputs = 64;
  Node* inputs[kMaxInputs];
  Node* const input = graph()->NewNode(&kOp0);
  TRACED_FORRANGE(int, input_count, 2, kMaxInputs - 1) {
    int const value_input_count = input_count - 1;
    for (int i = 0; i < value_input_count; ++i) {
      inputs[i] = graph()->start();
    }
    Node* const merge = graph()->NewNode(common()->Merge(value_input_count),
                                         value_input_count, inputs);
    for (int i = 0; i < value_input_count; ++i) {
      inputs[i] = input;
    }
    inputs[value_input_count] = merge;
    StrictMock<MockAdvancedReducerEditor> editor;
    EXPECT_CALL(editor, Revisit(merge));
    Reduction r =
        Reduce(&editor,
               graph()->NewNode(common()->EffectPhi(value_input_count),
                                input_count, inputs),
               BranchSemantics::kJS);
    ASSERT_TRUE(r.Changed());
    EXPECT_EQ(input, r.replacement());
  }
}


TEST_F(CommonOperatorReducerTest, EffectPhiWithLoop) {
  Node* const e0 = graph()->NewNode(&kOp0);
  Node* const loop =
      graph()->NewNode(common()->Loop(2), graph()->start(), graph()->start());
  loop->ReplaceInput(1, loop);
  Node* const ephi = graph()->NewNode(common()->EffectPhi(2), e0, e0, loop);
  ephi->ReplaceInput(1, ephi);
  StrictMock<MockAdvancedReducerEditor> editor;
  EXPECT_CALL(editor, Revisit(loop));
  Reduction const r = Reduce(&editor, ephi, BranchSemantics::kJS);
  ASSERT_TRUE(r.Changed());
  EXPECT_EQ(e0, r.replacement());
}


// -----------------------------------------------------------------------------
// Phi


TEST_F(CommonOperatorReducerTest, PhiWithMerge) {
  const int kMaxInputs = 64;
  Node* inputs[kMaxInputs];
  Node* const input = graph()->NewNode(&kOp0);
  TRACED_FORRANGE(int, input_count, 2, kMaxInputs - 1) {
    int const value_input_count = input_count - 1;
    TRACED_FOREACH(MachineRepresentation, rep, kMachineRepresentations) {
      for (int i = 0; i < value_input_count; ++i) {
        inputs[i] = graph()->start();
      }
      Node* const merge = graph()->NewNode(common()->Merge(value_input_count),
                                           value_input_count, inputs);
      for (int i = 0; i < value_input_count; ++i) {
        inputs[i] = input;
      }
      inputs[value_input_count] = merge;
      StrictMock<MockAdvancedReducerEditor> editor;
      EXPECT_CALL(editor, Revisit(merge));
      Reduction r =
          Reduce(&editor,
                 graph()->NewNode(common()->Phi(rep, value_input_count),
                                  input_count, inputs),
                 BranchSemantics::kJS);
      ASSERT_TRUE(r.Changed());
      EXPECT_EQ(input, r.replacement());
    }
  }
}


TEST_F(CommonOperatorReducerTest, PhiWithLoop) {
  Node* const p0 = Parameter(0);
  Node* const loop =
      graph()->NewNode(common()->Loop(2), graph()->start(), graph()->start());
  loop->ReplaceInput(1, loop);
  Node* const phi = graph()->NewNode(
      common()->Phi(MachineRepresentation::kTagged, 2), p0, p0, loop);
  phi->ReplaceInput(1, phi);
  StrictMock<MockAdvancedReducerEditor> editor;
  EXPECT_CALL(editor, Revisit(loop));
  Reduction const r = Reduce(&editor, phi, BranchSemantics::kMachine);
  ASSERT_TRUE(r.Changed());
  EXPECT_EQ(p0, r.replacement());
}


TEST_F(CommonOperatorReducerTest, PhiToFloat32Abs) {
  Node* p0 = Parameter(0);
  Node* c0 = Float32Constant(0.0);
  Node* check = graph()->NewNode(machine()->Float32LessThan(), c0, p0);
  Node* branch = graph()->NewNode(common()->Branch(), check, graph()->start());
  Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
  Node* vtrue = p0;
  Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
  Node* vfalse = graph()->NewNode(machine()->Float32Sub(), c0, p0);
  Node* merge = graph()->NewNode(common()->Merge(2), if_true, if_false);
  Node* phi = graph()->NewNode(
      common()->Phi(MachineRepresentation::kFloat32, 2), vtrue, vfalse, merge);
  StrictMock<MockAdvancedReducerEditor> editor;
  EXPECT_CALL(editor, Revisit(merge));
  Reduction r = Reduce(&editor, phi, BranchSemantics::kMachine);
  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsFloat32Abs(p0));
}


TEST_F(CommonOperatorReducerTest, PhiToFloat64Abs) {
  Node* p0 = Parameter(0);
  Node* c0 = Float64Constant(0.0);
  Node* check = graph()->NewNode(machine()->Float64LessThan(), c0, p0);
  Node* branch = graph()->NewNode(common()->Branch(), check, graph()->start());
  Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
  Node* vtrue = p0;
  Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
  Node* vfalse = graph()->NewNode(machine()->Float64Sub(), c0, p0);
  Node* merge = graph()->NewNode(common()->Merge(2), if_true, if_false);
  Node* phi = graph()->NewNode(
      common()->Phi(MachineRepresentation::kFloat64, 2), vtrue, vfalse, merge);
  StrictMock<MockAdvancedReducerEditor> editor;
  EXPECT_CALL(editor, Revisit(merge));
  Reduction r = Reduce(&editor, phi, BranchSemantics::kMachine);
  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsFloat64Abs(p0));
}


// -----------------------------------------------------------------------------
// Return


TEST_F(CommonOperatorReducerTest, ReturnWithPhiAndEffectPhiAndMerge) {
  Node* cond = Parameter(2);
  Node* branch = graph()->NewNode(common()->Branch(), cond, graph()->start());
  Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
  Node* etrue = graph()->start();
  Node* vtrue = Parameter(0);
  Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
  Node* efalse = graph()->start();
  Node* vfalse = Parameter(1);
  Node* merge = graph()->NewNode(common()->Merge(2), if_true, if_false);
  Node* ephi = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, merge);
  Node* phi = graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                               vtrue, vfalse, merge);

  Node* zero = graph()->NewNode(common()->Int32Constant(0));
  Node* ret = graph()->NewNode(common()->Return(), zero, phi, ephi, merge);
  graph()->SetEnd(graph()->NewNode(common()->End(1), ret));
  StrictMock<MockAdvancedReducerEditor> editor;
  EXPECT_CALL(editor, Replace(merge, IsDead()));
  EXPECT_CALL(editor, Revisit(graph()->end())).Times(2);
  Reduction const r = Reduce(&editor, ret, BranchSemantics::kJS);
  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsDead());
  EXPECT_THAT(graph()->end(), IsEnd(ret, IsReturn(vtrue, etrue, if_true),
                                    IsReturn(vfalse, efalse, if_false)));
}

TEST_F(CommonOperatorReducerTest, MultiReturnWithPhiAndEffectPhiAndMerge) {
  Node* cond = Parameter(2);
  Node* branch = graph()->NewNode(common()->Branch(), cond, graph()->start());
  Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
  Node* etrue = graph()->start();
  Node* vtrue1 = Parameter(0);
  Node* vtrue2 = Parameter(1);
  Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
  Node* efalse = graph()->start();
  Node* vfalse1 = Parameter(1);
  Node* vfalse2 = Parameter(0);
  Node* merge = graph()->NewNode(common()->Merge(2), if_true, if_false);
  Node* ephi = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, merge);
  Node* phi1 = graph()->NewNode(
      common()->Phi(MachineRepresentation::kTagged, 2), vtrue1, vfalse1, merge);
  Node* phi2 = graph()->NewNode(
      common()->Phi(MachineRepresentation::kTagged, 2), vtrue2, vfalse2, merge);

  Node* zero = graph()->NewNode(common()->Int32Constant(0));
  Node* ret =
      graph()->NewNode(common()->Return(2), zero, phi1, phi2, ephi, merge);
  graph()->SetEnd(graph()->NewNode(common()->End(1), ret));
  StrictMock<MockAdvancedReducerEditor> editor;
  Reduction const r = Reduce(&editor, ret, BranchSemantics::kJS);
  // For now a return with multiple return values should not be reduced.
  ASSERT_TRUE(!r.Changed());
}

// -----------------------------------------------------------------------------
// Select


TEST_F(CommonOperatorReducerTest, SelectWithSameThenAndElse) {
  Node* const input = graph()->NewNode(&kOp0);
  TRACED_FOREACH(BranchHint, hint, kBranchHints) {
    TRACED_FOREACH(MachineRepresentation, rep, kMachineRepresentations) {
      Reduction r = Reduce(
          graph()->NewNode(common()->Select(rep, hint), input, input, input),
          BranchSemantics::kJS);
      ASSERT_TRUE(r.Changed());
      EXPECT_EQ(input, r.replacement());
    }
  }
}


TEST_F(CommonOperatorReducerTest, SelectWithInt32ZeroConstant) {
  Node* p0 = Parameter(0);
  Node* p1 = Parameter(1);
  Node* select =
      graph()->NewNode(common()->Select(MachineRepresentation::kTagged),
                       Int32Constant(0), p0, p1);
  Reduction r = Reduce(select, BranchSemantics::kMachine);
  ASSERT_TRUE(r.Changed());
  EXPECT_EQ(p1, r.replacement());
}


TEST_F(CommonOperatorReducerTest, SelectWithInt32OneConstant) {
  Node* p0 = Parameter(0);
  Node* p1 = Parameter(1);
  Node* select =
      graph()->NewNode(common()->Select(MachineRepresentation::kTagged),
                       Int32Constant(1), p0, p1);
  Reduction r = Reduce(select, BranchSemantics::kMachine);
  ASSERT_TRUE(r.Changed());
  EXPECT_EQ(p0, r.replacement());
}


TEST_F(CommonOperatorReducerTest, SelectWithFalseConstant) {
  Node* p0 = Parameter(0);
  Node* p1 = Parameter(1);
  Node* select =
      graph()->NewNode(common()->Select(MachineRepresentation::kTagged),
                       FalseConstant(), p0, p1);
  Reduction r = Reduce(select, BranchSemantics::kJS);
  ASSERT_TRUE(r.Changed());
  EXPECT_EQ(p1, r.replacement());
}


TEST_F(CommonOperatorReducerTest, SelectWithTrueConstant) {
  Node* p0 = Parameter(0);
  Node* p1 = Parameter(1);
  Node* select = graph()->NewNode(
      common()->Select(MachineRepresentation::kTagged), TrueConstant(), p0, p1);
  Reduction r = Reduce(select, BranchSemantics::kJS);
  ASSERT_TRUE(r.Changed());
  EXPECT_EQ(p0, r.replacement());
}


TEST_F(CommonOperatorReducerTest, SelectToFloat32Abs) {
  Node* p0 = Parameter(0);
  Node* c0 = Float32Constant(0.0);
  Node* check = graph()->NewNode(machine()->Float32LessThan(), c0, p0);
  Node* select =
      graph()->NewNode(common()->Select(MachineRepresentation::kFloat32), check,
                       p0, graph()->NewNode(machine()->Float32Sub(), c0, p0));
  Reduction r = Reduce(select, BranchSemantics::kMachine);
  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsFloat32Abs(p0));
}


TEST_F(CommonOperatorReducerTest, SelectToFloat64Abs) {
  Node* p0 = Parameter(0);
  Node* c0 = Float64Constant(0.0);
  Node* check = graph()->NewNode(machine()->Float64LessThan(), c0, p0);
  Node* select =
      graph()->NewNode(common()->Select(MachineRepresentation::kFloat64), check,
                       p0, graph()->NewNode(machine()->Float64Sub(), c0, p0));
  Reduction r = Reduce(select, BranchSemantics::kMachine);
  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsFloat64Abs(p0));
}

// -----------------------------------------------------------------------------
// Switch

TEST_F(CommonOperatorReducerTest, SwitchInputMatchesCaseWithDefault) {
  Node* const control = graph()->start();

  Node* sw = graph()->NewNode(common()->Switch(2), Int32Constant(1), control);
  Node* const if_1 = graph()->NewNode(common()->IfValue(1), sw);
  graph()->NewNode(common()->IfDefault(), sw);

  StrictMock<MockAdvancedReducerEditor> editor;
  EXPECT_CALL(editor, Replace(if_1, control));
  Reduction r = Reduce(&editor, sw, BranchSemantics::kMachine);
  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsDead());
}

TEST_F(CommonOperatorReducerTest, SwitchInputMatchesDefaultWithCase) {
  Node* const control = graph()->start();

  Node* sw = graph()->NewNode(common()->Switch(2), Int32Constant(0), control);
  graph()->NewNode(common()->IfValue(1), sw);
  Node* const if_default = graph()->NewNode(common()->IfDefault(), sw);

  StrictMock<MockAdvancedReducerEditor> editor;
  EXPECT_CALL(editor, Replace(if_default, control));
  Reduction r = Reduce(&editor, sw, BranchSemantics::kMachine);
  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsDead());
}

TEST_F(CommonOperatorReducerTest, SwitchInputMatchesCaseExtraCaseWithDefault) {
  Node* const control = graph()->start();

  Node* sw = graph()->NewNode(common()->Switch(3), Int32Constant(0), control);
  Node* const if_0 = graph()->NewNode(common()->IfValue(0), sw);
  graph()->NewNode(common()->IfValue(1), sw);
  graph()->NewNode(common()->IfDefault(), sw);

  StrictMock<MockAdvancedReducerEditor> editor;
  EXPECT_CALL(editor, Replace(if_0, control));
  Reduction r = Reduce(&editor, sw, BranchSemantics::kMachine);
  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsDead());
}

}  // namespace common_operator_reducer_unittest
}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""

```