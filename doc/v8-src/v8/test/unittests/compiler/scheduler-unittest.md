Response: Let's break down the thought process for analyzing this C++ code and generating the explanation, including the JavaScript example.

1. **Understand the Goal:** The primary goal is to summarize the functionality of the C++ file `scheduler-unittest.cc` and explain its relation to JavaScript, providing a concrete example.

2. **Initial Code Scan (Keywords and Structure):**  A quick skim reveals keywords like `TEST_F`, `SchedulerTest`, `ComputeSchedule`, `Graph`, `Node`, `CommonOperatorBuilder`, `SimplifiedOperatorBuilder`, `JSOperatorBuilder`, `Branch`, `Phi`, `Loop`, `Return`, `Call`, `TailCall`, `Switch`, and `Terminate`. The `TEST_F` macro strongly suggests this is a unit testing file. The class `SchedulerTest` is central, and it has methods for manipulating a `Graph` and computing a `Schedule`.

3. **Identify Core Functionality:** The core function being tested appears to be `Scheduler::ComputeSchedule`. The `ComputeAndVerifySchedule` method wraps this and performs verification. The tests construct different graph structures using nodes and operators, then use the scheduler.

4. **Focus on the "Why":**  Unit tests verify specific functionalities. What aspect of the scheduler is being tested?  The different test cases (e.g., `BuildScheduleEmpty`, `FloatingDiamond1`, `LoopedFloatingDiamond1`, `CallException`, `Switch`) suggest the scheduler's ability to handle various control flow structures in a program's intermediate representation (the `Graph`). The names often hint at the type of structure being tested. "Floating Diamond" refers to a conditional branch that merges later.

5. **Infer the Purpose of the Scheduler:** Based on the test cases, the scheduler takes a graph (representing program logic) and produces a `Schedule`. The `Schedule` seems to dictate the order of execution of the nodes. The verification (`ScheduleVerifier::Run`) and the `GetScheduledNodeCount` method confirm this.

6. **Connect to JavaScript (the Bridge):** The code imports headers like `src/compiler/js-operator.h`. This signals a connection to JavaScript compilation. V8 compiles JavaScript to machine code. The intermediate representation (the `Graph`) likely represents JavaScript code after some initial processing. The scheduler's job is to optimize the execution order of this intermediate code.

7. **Formulate a High-Level Summary:**  The file tests the V8 compiler's scheduler component. This component takes an intermediate representation of code (a graph) and determines the execution order of operations. It handles various control flow scenarios.

8. **Find Specific Examples in the Tests:**  Look for test cases that illustrate different control flow structures clearly:
    * **Basic Flow:** `BuildScheduleEmpty`, `BuildScheduleOneParameter`
    * **Conditional Logic:** `FloatingDiamond1`, `BranchHintTrue`, `BranchHintFalse`
    * **Loops:** `LoopedFloatingDiamond1`, `NestedFloatingDiamondWithLoop`
    * **Function Calls:** `CallException`, `TailCall`
    * **Switch Statements:** `Switch`

9. **Relate C++ Concepts to JavaScript:**  Map the C++ graph concepts to their JavaScript equivalents:
    * `Graph` -> The overall structure of the JavaScript code.
    * `Node` -> Individual operations (addition, comparison, function calls, etc.).
    * `Branch` -> `if/else` statements.
    * `Phi` -> Variables that can hold different values depending on the execution path (related to how variables are managed in control flow).
    * `Loop` -> `for`, `while` loops.
    * `Call` -> Function calls.
    * `Switch` -> `switch` statements.

10. **Craft a JavaScript Example:**  Create a simple JavaScript function that uses some of the control flow structures seen in the C++ tests. The goal is to demonstrate how the C++ scheduler would be relevant during the compilation of this JavaScript code. A function with an `if/else` and a loop is a good starting point.

11. **Explain the Connection:** Clearly articulate *how* the C++ scheduler relates to the JavaScript example. Emphasize that the scheduler operates on the *internal representation* of the JavaScript code, not the source code directly. Explain that it optimizes the execution order for performance.

12. **Refine and Organize:** Structure the explanation logically with clear headings and bullet points. Ensure that the JavaScript example is easy to understand and directly relates to the C++ concepts. Use clear and concise language. Specifically, make sure to explain *what* the scheduler does and *why* it's important (optimization).

13. **Self-Correction/Review:**  Read through the explanation and the JavaScript example. Are they accurate? Are they clear?  Is the connection between the C++ and JavaScript evident?  For instance, initially, I might not have emphasized the "intermediate representation" aspect strongly enough. Reviewing helps identify these areas for improvement. Perhaps the initial JavaScript example was too simple; adding a loop makes it more representative of the test cases.

By following this thought process, systematically analyzing the C++ code, and focusing on the connection to JavaScript, we can arrive at a comprehensive and informative explanation.
这个C++源代码文件 `scheduler-unittest.cc` 是 **V8 JavaScript 引擎** 中 **Turbofan 编译器** 的一个 **单元测试文件**。它的主要功能是 **测试 Turbofan 编译器的调度器 (Scheduler) 组件**。

**具体来说，这个文件中的测试用例验证了调度器在不同代码结构下的行为，包括：**

1. **基本代码结构:**
   - 空代码块 (`BuildScheduleEmpty`)
   - 只有一个参数的简单函数 (`BuildScheduleOneParameter`)

2. **控制流结构:**
   - **条件分支 (Diamond Structures):**  测试调度器如何处理 `if-else` 语句产生的控制流分支和合并点 (`FloatingDiamond1`, `FloatingDeadDiamond1`, `FloatingDiamond2`, `FloatingDiamond3`). "Floating" 通常意味着这些结构不直接影响最终的返回值，而是作为中间计算。
   - **嵌套的条件分支 (`NestedFloatingDiamonds`, `NestedFloatingDiamondWithChain`):** 测试更复杂的嵌套 `if-else` 结构。
   - **循环 (`NestedFloatingDiamondWithLoop`, `LoopedFloatingDiamond1`, `LoopedFloatingDiamond2`, `LoopedFloatingDiamond3`):** 测试调度器如何处理 `for` 或 `while` 循环。
   - **带有分支提示的分支 (`BranchHintTrue`, `BranchHintFalse`):**  测试调度器如何利用分支预测信息进行调度优化。
   - **异常处理 (`CallException`):** 测试调度器如何处理可能抛出异常的函数调用。
   - **尾调用 (`TailCall`):** 测试调度器对尾调用的优化。
   - **Switch 语句 (`Switch`, `FloatingSwitch`):** 测试调度器如何处理 `switch` 语句。
   - **终止执行 (`Terminate`):** 测试调度器如何处理程序终止的情况。

3. **数据流和依赖关系:**
   - **Phi 节点 (`PhisPushedDownToDifferentBranches`):** 测试调度器如何处理 Phi 节点，这些节点用于在控制流合并点选择不同的输入值。

**与 JavaScript 的关系以及 JavaScript 示例：**

这个文件测试的 `Scheduler` 组件是 Turbofan 编译器的一部分，而 Turbofan 是 V8 引擎中用于优化 JavaScript 代码的关键组件。当 V8 执行 JavaScript 代码时，Turbofan 会将热点代码（经常执行的代码）编译成更高效的机器代码。

**调度器的作用是在编译过程中，决定代码执行的顺序，以便更好地利用 CPU 资源，例如通过指令并行和减少流水线停顿来提高性能。**

**JavaScript 示例：**

让我们用一个简单的 JavaScript 函数来说明其中一个测试用例 `FloatingDiamond1` 背后的概念：

```javascript
function example(x) {
  let a;
  if (x > 0) {
    a = 6;
  } else {
    a = 7;
  }
  return a + 0; // 这里的 + 0 只是为了确保 'a' 被使用
}

console.log(example(5));  // 输出 6
console.log(example(-2)); // 输出 7
```

**在这个 JavaScript 例子中，`if (x > 0)` 语句创建了一个条件分支，类似于 `FloatingDiamond1` 测试用例中创建的 "Diamond" 结构。**

当 Turbofan 编译这个 `example` 函数时，它会创建一个内部的图表示 (Graph)，其中 `if (x > 0)` 会被表示为一个分支节点。调度器会分析这个图，并决定如何安排执行顺序。

**`FloatingDiamond1` 测试用例的目标是验证调度器能否正确地处理这种分支结构，并有效地安排 `a = 6` 和 `a = 7` 的赋值，以及后续的合并操作（虽然在这个简单的 JavaScript 例子中合并操作比较隐式）。**

**更深入地理解：**

在 Turbofan 的内部表示中，`a = 6` 和 `a = 7` 的赋值可能会被表示为不同的节点。`if (x > 0)` 的结果会决定执行哪个分支。最终，`a` 的值需要被传递到 `return a + 0` 这个操作。调度器需要确保这些操作按照正确的依赖关系执行，并且可能进行优化，例如，如果 `x` 的值在程序运行中倾向于大于 0，调度器可能会优先安排执行 `a = 6` 的分支。

**总结:**

`scheduler-unittest.cc` 通过各种精心设计的测试用例，全面地测试了 V8 引擎中 Turbofan 编译器的调度器组件的功能和正确性。这些测试确保了编译器能够有效地处理各种 JavaScript 代码结构，并生成优化的机器代码，从而提高 JavaScript 代码的执行效率。这些 C++ 单元测试是保证 V8 引擎稳定性和性能的关键部分。

Prompt: 
```
这是目录为v8/test/unittests/compiler/scheduler-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/scheduler.h"

#include "src/codegen/tick-counter.h"
#include "src/compiler/access-builder.h"
#include "src/compiler/common-operator.h"
#include "src/compiler/compiler-source-position-table.h"
#include "src/compiler/js-operator.h"
#include "src/compiler/node-origin-table.h"
#include "src/compiler/node.h"
#include "src/compiler/opcodes.h"
#include "src/compiler/operator.h"
#include "src/compiler/schedule.h"
#include "src/compiler/simplified-operator.h"
#include "src/compiler/turbofan-graph-visualizer.h"
#include "src/compiler/turbofan-graph.h"
#include "src/compiler/verifier.h"
#include "test/unittests/compiler/compiler-test-utils.h"
#include "test/unittests/test-utils.h"
#include "testing/gmock/include/gmock/gmock.h"

using testing::AnyOf;

namespace v8 {
namespace internal {
namespace compiler {

class SchedulerTest : public TestWithIsolateAndZone {
 public:
  SchedulerTest()
      : TestWithIsolateAndZone(kCompressGraphZone),
        graph_(zone()),
        common_(zone()),
        simplified_(zone()),
        js_(zone()) {}

  Schedule* ComputeAndVerifySchedule(size_t expected) {
    if (v8_flags.trace_turbo) {
      SourcePositionTable table(graph());
      NodeOriginTable table2(graph());
      StdoutStream{} << AsJSON(*graph(), &table, &table2);
    }

    Schedule* schedule = Scheduler::ComputeSchedule(
        zone(), graph(), Scheduler::kSplitNodes, tick_counter(), nullptr);

    if (v8_flags.trace_turbo_scheduler) {
      StdoutStream{} << *schedule << std::endl;
    }
    ScheduleVerifier::Run(schedule);
    EXPECT_EQ(expected, GetScheduledNodeCount(schedule));
    return schedule;
  }

  size_t GetScheduledNodeCount(const Schedule* schedule) {
    size_t node_count = 0;
    for (auto block : *schedule->rpo_order()) {
      node_count += block->NodeCount();
      if (block->control() != BasicBlock::kNone) ++node_count;
    }
    return node_count;
  }

  Graph* graph() { return &graph_; }
  CommonOperatorBuilder* common() { return &common_; }
  SimplifiedOperatorBuilder* simplified() { return &simplified_; }
  JSOperatorBuilder* js() { return &js_; }
  TickCounter* tick_counter() { return &tick_counter_; }

 private:
  TickCounter tick_counter_;
  Graph graph_;
  CommonOperatorBuilder common_;
  SimplifiedOperatorBuilder simplified_;
  JSOperatorBuilder js_;
};


namespace {

const Operator kHeapConstant(IrOpcode::kHeapConstant, Operator::kPure,
                             "HeapConstant", 0, 0, 0, 1, 0, 0);
const Operator kIntAdd(IrOpcode::kInt32Add, Operator::kPure, "Int32Add", 2, 0,
                       0, 1, 0, 0);
const Operator kMockCall(IrOpcode::kCall, Operator::kNoProperties, "MockCall",
                         0, 0, 1, 1, 1, 2);
const Operator kMockTailCall(IrOpcode::kTailCall, Operator::kNoProperties,
                             "MockTailCall", 1, 1, 1, 0, 0, 1);

}  // namespace


TEST_F(SchedulerTest, BuildScheduleEmpty) {
  graph()->SetStart(graph()->NewNode(common()->Start(0)));
  graph()->SetEnd(graph()->NewNode(common()->End(1), graph()->start()));
  USE(Scheduler::ComputeSchedule(zone(), graph(), Scheduler::kNoFlags,
                                 tick_counter(), nullptr));
}


TEST_F(SchedulerTest, BuildScheduleOneParameter) {
  graph()->SetStart(graph()->NewNode(common()->Start(0)));

  Node* p1 = graph()->NewNode(common()->Parameter(0), graph()->start());
  Node* zero = graph()->NewNode(common()->Int32Constant(0));
  Node* ret = graph()->NewNode(common()->Return(), zero, p1, graph()->start(),
                               graph()->start());

  graph()->SetEnd(graph()->NewNode(common()->End(1), ret));

  USE(Scheduler::ComputeSchedule(zone(), graph(), Scheduler::kNoFlags,
                                 tick_counter(), nullptr));
}


namespace {

Node* CreateDiamond(Graph* graph, CommonOperatorBuilder* common, Node* cond) {
  Node* tv = graph->NewNode(common->Int32Constant(6));
  Node* fv = graph->NewNode(common->Int32Constant(7));
  Node* br = graph->NewNode(common->Branch(), cond, graph->start());
  Node* t = graph->NewNode(common->IfTrue(), br);
  Node* f = graph->NewNode(common->IfFalse(), br);
  Node* m = graph->NewNode(common->Merge(2), t, f);
  Node* phi =
      graph->NewNode(common->Phi(MachineRepresentation::kTagged, 2), tv, fv, m);
  return phi;
}

}  // namespace


TARGET_TEST_F(SchedulerTest, FloatingDiamond1) {
  Node* start = graph()->NewNode(common()->Start(1));
  graph()->SetStart(start);

  Node* p0 = graph()->NewNode(common()->Parameter(0), start);
  Node* d1 = CreateDiamond(graph(), common(), p0);
  Node* zero = graph()->NewNode(common()->Int32Constant(0));
  Node* ret = graph()->NewNode(common()->Return(), zero, d1, start, start);
  Node* end = graph()->NewNode(common()->End(1), ret);

  graph()->SetEnd(end);

  ComputeAndVerifySchedule(14);
}

TARGET_TEST_F(SchedulerTest, FloatingDeadDiamond1) {
  Node* start = graph()->NewNode(common()->Start(1));
  graph()->SetStart(start);

  Node* p0 = graph()->NewNode(common()->Parameter(0), start);
  Node* d1 = CreateDiamond(graph(), common(), p0);
  USE(d1);
  Node* zero = graph()->NewNode(common()->Int32Constant(0));
  Node* ret = graph()->NewNode(common()->Return(), zero, p0, start, start);
  Node* end = graph()->NewNode(common()->End(1), ret);

  graph()->SetEnd(end);

  ComputeAndVerifySchedule(5);
}

TARGET_TEST_F(SchedulerTest, FloatingDeadDiamond2) {
  Graph* g = graph();
  Node* start = g->NewNode(common()->Start(1));
  g->SetStart(start);

  Node* n1 = g->NewNode(common()->Parameter(1), start);

  Node* n2 = g->NewNode(common()->Branch(), n1, start);
  Node* n3 = g->NewNode(common()->IfTrue(), n2);
  Node* n4 = g->NewNode(common()->IfFalse(), n2);
  Node* n5 = g->NewNode(common()->Int32Constant(-100));
  Node* zero = graph()->NewNode(common()->Int32Constant(0));
  Node* n6 = g->NewNode(common()->Return(), zero, n5, start, n4);
  Node* n7 = g->NewNode(common()->Int32Constant(0));
  Node* n8 = g->NewNode(common()->Return(), zero, n7, start, n3);
  Node* n9 = g->NewNode(common()->End(2), n6, n8);

  // Dead nodes
  Node* n10 = g->NewNode(common()->Branch(), n1, n3);
  Node* n11 = g->NewNode(common()->IfTrue(), n10);
  Node* n12 = g->NewNode(common()->IfFalse(), n10);
  Node* n13 = g->NewNode(common()->Merge(2), n11, n12);
  Node* n14 =
      g->NewNode(common()->Phi(MachineRepresentation::kWord32, 2), n1, n7, n13);

  USE(n14);

  g->SetEnd(n9);

  ComputeAndVerifySchedule(11);
}

TARGET_TEST_F(SchedulerTest, FloatingDiamond2) {
  Node* start = graph()->NewNode(common()->Start(2));
  graph()->SetStart(start);

  Node* p0 = graph()->NewNode(common()->Parameter(0), start);
  Node* p1 = graph()->NewNode(common()->Parameter(1), start);
  Node* d1 = CreateDiamond(graph(), common(), p0);
  Node* d2 = CreateDiamond(graph(), common(), p1);
  Node* add = graph()->NewNode(&kIntAdd, d1, d2);
  Node* zero = graph()->NewNode(common()->Int32Constant(0));
  Node* ret = graph()->NewNode(common()->Return(), zero, add, start, start);
  Node* end = graph()->NewNode(common()->End(1), ret);

  graph()->SetEnd(end);

  ComputeAndVerifySchedule(25);
}


TARGET_TEST_F(SchedulerTest, FloatingDiamond3) {
  Node* start = graph()->NewNode(common()->Start(2));
  graph()->SetStart(start);

  Node* p0 = graph()->NewNode(common()->Parameter(0), start);
  Node* p1 = graph()->NewNode(common()->Parameter(1), start);
  Node* d1 = CreateDiamond(graph(), common(), p0);
  Node* d2 = CreateDiamond(graph(), common(), p1);
  Node* add = graph()->NewNode(&kIntAdd, d1, d2);
  Node* d3 = CreateDiamond(graph(), common(), add);
  Node* zero = graph()->NewNode(common()->Int32Constant(0));
  Node* ret = graph()->NewNode(common()->Return(), zero, d3, start, start);
  Node* end = graph()->NewNode(common()->End(1), ret);

  graph()->SetEnd(end);

  ComputeAndVerifySchedule(34);
}


TARGET_TEST_F(SchedulerTest, NestedFloatingDiamonds) {
  Node* start = graph()->NewNode(common()->Start(2));
  graph()->SetStart(start);

  Node* p0 = graph()->NewNode(common()->Parameter(0), start);

  Node* fv = graph()->NewNode(common()->Int32Constant(7));
  Node* br = graph()->NewNode(common()->Branch(), p0, graph()->start());
  Node* t = graph()->NewNode(common()->IfTrue(), br);
  Node* f = graph()->NewNode(common()->IfFalse(), br);

  Node* map = graph()->NewNode(
      simplified()->LoadElement(AccessBuilder::ForFixedArrayElement()), p0, p0,
      start, f);
  Node* br1 = graph()->NewNode(common()->Branch(), map, graph()->start());
  Node* t1 = graph()->NewNode(common()->IfTrue(), br1);
  Node* f1 = graph()->NewNode(common()->IfFalse(), br1);
  Node* m1 = graph()->NewNode(common()->Merge(2), t1, f1);
  Node* ttrue = graph()->NewNode(common()->Int32Constant(1));
  Node* ffalse = graph()->NewNode(common()->Int32Constant(0));
  Node* phi1 = graph()->NewNode(
      common()->Phi(MachineRepresentation::kTagged, 2), ttrue, ffalse, m1);


  Node* m = graph()->NewNode(common()->Merge(2), t, f);
  Node* phi = graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                               fv, phi1, m);
  Node* ephi1 = graph()->NewNode(common()->EffectPhi(2), start, map, m);

  Node* zero = graph()->NewNode(common()->Int32Constant(0));
  Node* ret = graph()->NewNode(common()->Return(), zero, phi, ephi1, start);
  Node* end = graph()->NewNode(common()->End(1), ret);

  graph()->SetEnd(end);

  ComputeAndVerifySchedule(24);
}


TARGET_TEST_F(SchedulerTest, NestedFloatingDiamondWithChain) {
  Node* start = graph()->NewNode(common()->Start(2));
  graph()->SetStart(start);

  Node* p0 = graph()->NewNode(common()->Parameter(0), start);
  Node* p1 = graph()->NewNode(common()->Parameter(1), start);
  Node* c = graph()->NewNode(common()->Int32Constant(7));

  Node* brA1 = graph()->NewNode(common()->Branch(), p0, graph()->start());
  Node* tA1 = graph()->NewNode(common()->IfTrue(), brA1);
  Node* fA1 = graph()->NewNode(common()->IfFalse(), brA1);
  Node* mA1 = graph()->NewNode(common()->Merge(2), tA1, fA1);
  Node* phiA1 = graph()->NewNode(
      common()->Phi(MachineRepresentation::kTagged, 2), p0, p1, mA1);

  Node* brB1 = graph()->NewNode(common()->Branch(), p1, graph()->start());
  Node* tB1 = graph()->NewNode(common()->IfTrue(), brB1);
  Node* fB1 = graph()->NewNode(common()->IfFalse(), brB1);
  Node* mB1 = graph()->NewNode(common()->Merge(2), tB1, fB1);
  Node* phiB1 = graph()->NewNode(
      common()->Phi(MachineRepresentation::kTagged, 2), p0, p1, mB1);

  Node* brA2 = graph()->NewNode(common()->Branch(), phiB1, mA1);
  Node* tA2 = graph()->NewNode(common()->IfTrue(), brA2);
  Node* fA2 = graph()->NewNode(common()->IfFalse(), brA2);
  Node* mA2 = graph()->NewNode(common()->Merge(2), tA2, fA2);
  Node* phiA2 = graph()->NewNode(
      common()->Phi(MachineRepresentation::kTagged, 2), phiB1, c, mA2);

  Node* brB2 = graph()->NewNode(common()->Branch(), phiA1, mB1);
  Node* tB2 = graph()->NewNode(common()->IfTrue(), brB2);
  Node* fB2 = graph()->NewNode(common()->IfFalse(), brB2);
  Node* mB2 = graph()->NewNode(common()->Merge(2), tB2, fB2);
  Node* phiB2 = graph()->NewNode(
      common()->Phi(MachineRepresentation::kTagged, 2), phiA1, c, mB2);

  Node* add = graph()->NewNode(&kIntAdd, phiA2, phiB2);
  Node* zero = graph()->NewNode(common()->Int32Constant(0));
  Node* ret = graph()->NewNode(common()->Return(), zero, add, start, start);
  Node* end = graph()->NewNode(common()->End(1), ret);

  graph()->SetEnd(end);

  ComputeAndVerifySchedule(37);
}


TARGET_TEST_F(SchedulerTest, NestedFloatingDiamondWithLoop) {
  Node* start = graph()->NewNode(common()->Start(2));
  graph()->SetStart(start);

  Node* p0 = graph()->NewNode(common()->Parameter(0), start);

  Node* fv = graph()->NewNode(common()->Int32Constant(7));
  Node* br = graph()->NewNode(common()->Branch(), p0, graph()->start());
  Node* t = graph()->NewNode(common()->IfTrue(), br);
  Node* f = graph()->NewNode(common()->IfFalse(), br);

  Node* loop = graph()->NewNode(common()->Loop(2), f, start);
  Node* ind = graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                               p0, p0, loop);

  Node* add = graph()->NewNode(&kIntAdd, ind, fv);
  Node* br1 = graph()->NewNode(common()->Branch(), add, loop);
  Node* t1 = graph()->NewNode(common()->IfTrue(), br1);
  Node* f1 = graph()->NewNode(common()->IfFalse(), br1);

  loop->ReplaceInput(1, t1);  // close loop.
  ind->ReplaceInput(1, ind);  // close induction variable.

  Node* m = graph()->NewNode(common()->Merge(2), t, f1);
  Node* phi = graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                               fv, ind, m);

  Node* zero = graph()->NewNode(common()->Int32Constant(0));
  Node* ret = graph()->NewNode(common()->Return(), zero, phi, start, start);
  Node* end = graph()->NewNode(common()->End(1), ret);

  graph()->SetEnd(end);

  ComputeAndVerifySchedule(21);
}


TARGET_TEST_F(SchedulerTest, LoopedFloatingDiamond1) {
  Node* start = graph()->NewNode(common()->Start(2));
  graph()->SetStart(start);

  Node* p0 = graph()->NewNode(common()->Parameter(0), start);

  Node* c = graph()->NewNode(common()->Int32Constant(7));
  Node* loop = graph()->NewNode(common()->Loop(2), start, start);
  Node* ind = graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                               p0, p0, loop);
  Node* add = graph()->NewNode(&kIntAdd, ind, c);

  Node* br = graph()->NewNode(common()->Branch(), add, loop);
  Node* t = graph()->NewNode(common()->IfTrue(), br);
  Node* f = graph()->NewNode(common()->IfFalse(), br);

  Node* br1 = graph()->NewNode(common()->Branch(), p0, graph()->start());
  Node* t1 = graph()->NewNode(common()->IfTrue(), br1);
  Node* f1 = graph()->NewNode(common()->IfFalse(), br1);
  Node* m1 = graph()->NewNode(common()->Merge(2), t1, f1);
  Node* phi1 = graph()->NewNode(
      common()->Phi(MachineRepresentation::kTagged, 2), add, p0, m1);

  loop->ReplaceInput(1, t);    // close loop.
  ind->ReplaceInput(1, phi1);  // close induction variable.

  Node* zero = graph()->NewNode(common()->Int32Constant(0));
  Node* ret = graph()->NewNode(common()->Return(), zero, ind, start, f);
  Node* end = graph()->NewNode(common()->End(2), ret, f);

  graph()->SetEnd(end);

  ComputeAndVerifySchedule(21);
}


TARGET_TEST_F(SchedulerTest, LoopedFloatingDiamond2) {
  Node* start = graph()->NewNode(common()->Start(2));
  graph()->SetStart(start);

  Node* p0 = graph()->NewNode(common()->Parameter(0), start);

  Node* c = graph()->NewNode(common()->Int32Constant(7));
  Node* loop = graph()->NewNode(common()->Loop(2), start, start);
  Node* ind = graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                               p0, p0, loop);

  Node* br1 = graph()->NewNode(common()->Branch(), p0, graph()->start());
  Node* t1 = graph()->NewNode(common()->IfTrue(), br1);
  Node* f1 = graph()->NewNode(common()->IfFalse(), br1);
  Node* m1 = graph()->NewNode(common()->Merge(2), t1, f1);
  Node* phi1 = graph()->NewNode(
      common()->Phi(MachineRepresentation::kTagged, 2), c, ind, m1);

  Node* add = graph()->NewNode(&kIntAdd, ind, phi1);

  Node* br = graph()->NewNode(common()->Branch(), add, loop);
  Node* t = graph()->NewNode(common()->IfTrue(), br);
  Node* f = graph()->NewNode(common()->IfFalse(), br);

  loop->ReplaceInput(1, t);   // close loop.
  ind->ReplaceInput(1, add);  // close induction variable.

  Node* zero = graph()->NewNode(common()->Int32Constant(0));
  Node* ret = graph()->NewNode(common()->Return(), zero, ind, start, f);
  Node* end = graph()->NewNode(common()->End(2), ret, f);

  graph()->SetEnd(end);

  ComputeAndVerifySchedule(21);
}


TARGET_TEST_F(SchedulerTest, LoopedFloatingDiamond3) {
  Node* start = graph()->NewNode(common()->Start(2));
  graph()->SetStart(start);

  Node* p0 = graph()->NewNode(common()->Parameter(0), start);

  Node* c = graph()->NewNode(common()->Int32Constant(7));
  Node* loop = graph()->NewNode(common()->Loop(2), start, start);
  Node* ind = graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                               p0, p0, loop);

  Node* br1 = graph()->NewNode(common()->Branch(), p0, graph()->start());
  Node* t1 = graph()->NewNode(common()->IfTrue(), br1);
  Node* f1 = graph()->NewNode(common()->IfFalse(), br1);

  Node* loop1 = graph()->NewNode(common()->Loop(2), t1, start);
  Node* ind1 = graph()->NewNode(
      common()->Phi(MachineRepresentation::kTagged, 2), p0, p0, loop);

  Node* add1 = graph()->NewNode(&kIntAdd, ind1, c);
  Node* br2 = graph()->NewNode(common()->Branch(), add1, loop1);
  Node* t2 = graph()->NewNode(common()->IfTrue(), br2);
  Node* f2 = graph()->NewNode(common()->IfFalse(), br2);

  loop1->ReplaceInput(1, t2);   // close inner loop.
  ind1->ReplaceInput(1, ind1);  // close inner induction variable.

  Node* m1 = graph()->NewNode(common()->Merge(2), f1, f2);
  Node* phi1 = graph()->NewNode(
      common()->Phi(MachineRepresentation::kTagged, 2), c, ind1, m1);

  Node* add = graph()->NewNode(&kIntAdd, ind, phi1);

  Node* br = graph()->NewNode(common()->Branch(), add, loop);
  Node* t = graph()->NewNode(common()->IfTrue(), br);
  Node* f = graph()->NewNode(common()->IfFalse(), br);

  loop->ReplaceInput(1, t);   // close loop.
  ind->ReplaceInput(1, add);  // close induction variable.

  Node* zero = graph()->NewNode(common()->Int32Constant(0));
  Node* ret = graph()->NewNode(common()->Return(), zero, ind, start, f);
  Node* end = graph()->NewNode(common()->End(2), ret, f);

  graph()->SetEnd(end);

  ComputeAndVerifySchedule(29);
}


TARGET_TEST_F(SchedulerTest, PhisPushedDownToDifferentBranches) {
  Node* start = graph()->NewNode(common()->Start(2));
  graph()->SetStart(start);

  Node* p0 = graph()->NewNode(common()->Parameter(0), start);
  Node* p1 = graph()->NewNode(common()->Parameter(1), start);

  Node* v1 = graph()->NewNode(common()->Int32Constant(1));
  Node* v2 = graph()->NewNode(common()->Int32Constant(2));
  Node* v3 = graph()->NewNode(common()->Int32Constant(3));
  Node* v4 = graph()->NewNode(common()->Int32Constant(4));
  Node* br = graph()->NewNode(common()->Branch(), p0, graph()->start());
  Node* t = graph()->NewNode(common()->IfTrue(), br);
  Node* f = graph()->NewNode(common()->IfFalse(), br);
  Node* m = graph()->NewNode(common()->Merge(2), t, f);
  Node* phi = graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                               v1, v2, m);
  Node* phi2 = graph()->NewNode(
      common()->Phi(MachineRepresentation::kTagged, 2), v3, v4, m);

  Node* br2 = graph()->NewNode(common()->Branch(), p1, graph()->start());
  Node* t2 = graph()->NewNode(common()->IfTrue(), br2);
  Node* f2 = graph()->NewNode(common()->IfFalse(), br2);
  Node* m2 = graph()->NewNode(common()->Merge(2), t2, f2);
  Node* phi3 = graph()->NewNode(
      common()->Phi(MachineRepresentation::kTagged, 2), phi, phi2, m2);

  Node* zero = graph()->NewNode(common()->Int32Constant(0));
  Node* ret = graph()->NewNode(common()->Return(), zero, phi3, start, start);
  Node* end = graph()->NewNode(common()->End(1), ret);

  graph()->SetEnd(end);

  ComputeAndVerifySchedule(25);
}


TARGET_TEST_F(SchedulerTest, BranchHintTrue) {
  Node* start = graph()->NewNode(common()->Start(1));
  graph()->SetStart(start);

  Node* p0 = graph()->NewNode(common()->Parameter(0), start);
  Node* tv = graph()->NewNode(common()->Int32Constant(6));
  Node* fv = graph()->NewNode(common()->Int32Constant(7));
  Node* br = graph()->NewNode(common()->Branch(BranchHint::kTrue), p0, start);
  Node* t = graph()->NewNode(common()->IfTrue(), br);
  Node* f = graph()->NewNode(common()->IfFalse(), br);
  Node* m = graph()->NewNode(common()->Merge(2), t, f);
  Node* phi = graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                               tv, fv, m);
  Node* zero = graph()->NewNode(common()->Int32Constant(0));
  Node* ret = graph()->NewNode(common()->Return(), zero, phi, start, start);
  Node* end = graph()->NewNode(common()->End(1), ret);

  graph()->SetEnd(end);

  Schedule* schedule = ComputeAndVerifySchedule(14);
  // Make sure the false block is marked as deferred.
  EXPECT_FALSE(schedule->block(t)->deferred());
  EXPECT_TRUE(schedule->block(f)->deferred());
}


TARGET_TEST_F(SchedulerTest, BranchHintFalse) {
  Node* start = graph()->NewNode(common()->Start(1));
  graph()->SetStart(start);

  Node* p0 = graph()->NewNode(common()->Parameter(0), start);
  Node* tv = graph()->NewNode(common()->Int32Constant(6));
  Node* fv = graph()->NewNode(common()->Int32Constant(7));
  Node* br = graph()->NewNode(common()->Branch(BranchHint::kFalse), p0, start);
  Node* t = graph()->NewNode(common()->IfTrue(), br);
  Node* f = graph()->NewNode(common()->IfFalse(), br);
  Node* m = graph()->NewNode(common()->Merge(2), t, f);
  Node* phi = graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                               tv, fv, m);
  Node* zero = graph()->NewNode(common()->Int32Constant(0));
  Node* ret = graph()->NewNode(common()->Return(), zero, phi, start, start);
  Node* end = graph()->NewNode(common()->End(1), ret);

  graph()->SetEnd(end);

  Schedule* schedule = ComputeAndVerifySchedule(14);
  // Make sure the true block is marked as deferred.
  EXPECT_TRUE(schedule->block(t)->deferred());
  EXPECT_FALSE(schedule->block(f)->deferred());
}


TARGET_TEST_F(SchedulerTest, CallException) {
  Node* start = graph()->NewNode(common()->Start(1));
  graph()->SetStart(start);

  Node* p0 = graph()->NewNode(common()->Parameter(0), start);
  Node* c1 = graph()->NewNode(&kMockCall, start);
  Node* ok1 = graph()->NewNode(common()->IfSuccess(), c1);
  Node* ex1 = graph()->NewNode(common()->IfException(), c1, c1);
  Node* c2 = graph()->NewNode(&kMockCall, ok1);
  Node* ok2 = graph()->NewNode(common()->IfSuccess(), c2);
  Node* ex2 = graph()->NewNode(common()->IfException(), c2, c2);
  Node* hdl = graph()->NewNode(common()->Merge(2), ex1, ex2);
  Node* m = graph()->NewNode(common()->Merge(2), ok2, hdl);
  Node* phi = graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                               c2, p0, m);
  Node* zero = graph()->NewNode(common()->Int32Constant(0));
  Node* ret = graph()->NewNode(common()->Return(), zero, phi, start, m);
  Node* end = graph()->NewNode(common()->End(1), ret);

  graph()->SetEnd(end);

  Schedule* schedule = ComputeAndVerifySchedule(18);
  // Make sure the exception blocks as well as the handler are deferred.
  EXPECT_TRUE(schedule->block(ex1)->deferred());
  EXPECT_TRUE(schedule->block(ex2)->deferred());
  EXPECT_TRUE(schedule->block(hdl)->deferred());
  EXPECT_FALSE(schedule->block(m)->deferred());
}


TARGET_TEST_F(SchedulerTest, TailCall) {
  Node* start = graph()->NewNode(common()->Start(1));
  graph()->SetStart(start);

  Node* p0 = graph()->NewNode(common()->Parameter(0), start);
  Node* call = graph()->NewNode(&kMockTailCall, p0, start, start);
  Node* end = graph()->NewNode(common()->End(1), call);

  graph()->SetEnd(end);

  ComputeAndVerifySchedule(4);
}


TARGET_TEST_F(SchedulerTest, Switch) {
  Node* start = graph()->NewNode(common()->Start(1));
  graph()->SetStart(start);

  Node* p0 = graph()->NewNode(common()->Parameter(0), start);
  Node* sw = graph()->NewNode(common()->Switch(3), p0, start);
  Node* c0 = graph()->NewNode(common()->IfValue(0), sw);
  Node* v0 = graph()->NewNode(common()->Int32Constant(11));
  Node* c1 = graph()->NewNode(common()->IfValue(1), sw);
  Node* v1 = graph()->NewNode(common()->Int32Constant(22));
  Node* d = graph()->NewNode(common()->IfDefault(), sw);
  Node* vd = graph()->NewNode(common()->Int32Constant(33));
  Node* m = graph()->NewNode(common()->Merge(3), c0, c1, d);
  Node* phi = graph()->NewNode(common()->Phi(MachineRepresentation::kWord32, 3),
                               v0, v1, vd, m);
  Node* zero = graph()->NewNode(common()->Int32Constant(0));
  Node* ret = graph()->NewNode(common()->Return(), zero, phi, start, m);
  Node* end = graph()->NewNode(common()->End(1), ret);

  graph()->SetEnd(end);

  ComputeAndVerifySchedule(17);
}


TARGET_TEST_F(SchedulerTest, FloatingSwitch) {
  Node* start = graph()->NewNode(common()->Start(1));
  graph()->SetStart(start);

  Node* p0 = graph()->NewNode(common()->Parameter(0), start);
  Node* sw = graph()->NewNode(common()->Switch(3), p0, start);
  Node* c0 = graph()->NewNode(common()->IfValue(0), sw);
  Node* v0 = graph()->NewNode(common()->Int32Constant(11));
  Node* c1 = graph()->NewNode(common()->IfValue(1), sw);
  Node* v1 = graph()->NewNode(common()->Int32Constant(22));
  Node* d = graph()->NewNode(common()->IfDefault(), sw);
  Node* vd = graph()->NewNode(common()->Int32Constant(33));
  Node* m = graph()->NewNode(common()->Merge(3), c0, c1, d);
  Node* phi = graph()->NewNode(common()->Phi(MachineRepresentation::kWord32, 3),
                               v0, v1, vd, m);
  Node* zero = graph()->NewNode(common()->Int32Constant(0));
  Node* ret = graph()->NewNode(common()->Return(), zero, phi, start, start);
  Node* end = graph()->NewNode(common()->End(1), ret);

  graph()->SetEnd(end);

  ComputeAndVerifySchedule(17);
}


TARGET_TEST_F(SchedulerTest, Terminate) {
  Node* start = graph()->NewNode(common()->Start(1));
  graph()->SetStart(start);

  Node* loop = graph()->NewNode(common()->Loop(2), start, start);
  loop->ReplaceInput(1, loop);  // self loop, NTL.

  Node* effect = graph()->NewNode(common()->EffectPhi(2), start, start, loop);
  effect->ReplaceInput(1, effect);  // self loop.

  Node* terminate = graph()->NewNode(common()->Terminate(), effect, loop);
  Node* end = graph()->NewNode(common()->End(1), terminate);
  graph()->SetEnd(end);

  Schedule* schedule = ComputeAndVerifySchedule(6);
  BasicBlock* block = schedule->block(loop);
  EXPECT_EQ(block, schedule->block(effect));
  EXPECT_GE(block->rpo_number(), 0);
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""

```