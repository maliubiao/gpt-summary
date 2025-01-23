Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a breakdown of the functionality of the provided C++ code (`loop-peeling-unittest.cc`). It also asks to differentiate between Torque and C++ source files, relate the code to JavaScript, provide example inputs and outputs, and illustrate common programming errors.

2. **Initial Code Scan (Keywords and Structure):** I quickly scan the code looking for keywords and structural elements. I see:
    * `#include`: Indicates C++ code. The file extension `.cc` confirms this. So, the initial check for `.tq` is negative.
    * `namespace v8::internal::compiler`:  Confirms this is part of the V8 JavaScript engine's compiler.
    * `TEST_F`:  This is a strong indicator of unit tests, likely using the Google Test framework.
    * `LoopPeelingTest`: The name of the test fixture suggests the code is testing the "loop peeling" optimization.
    * `LoopPeeler`, `LoopTree`:  These classes likely play key roles in the loop peeling process.
    * `NewWhile`, `NewCounter`, `NewPhi`, `NewBranch`:  Helper functions suggesting the tests involve building control flow graphs with loops, branches, and counters.
    * `ExpectPeeled`, `ExpectNotPeeled`:  Functions that check the outcome of the loop peeling process.
    * Various `TEST_F` blocks with descriptive names like `SimpleLoop`, `SimpleLoopWithCounter`, `SimpleNestedLoopWithCounter_peel_outer`, etc.: These are individual test cases.

3. **Deduce Core Functionality (Loop Peeling):**  Based on the file name and the presence of `LoopPeeler`, I deduce that the primary function of this code is to **test the loop peeling optimization** within the V8 compiler.

4. **Explain Loop Peeling:** I need to explain what loop peeling is in a way that's understandable, even without deep compiler knowledge. The core idea is to duplicate the first few iterations of a loop to potentially enable further optimizations.

5. **Connect to JavaScript (If Applicable):** Since this is a compiler optimization, the connection to JavaScript is indirect. The optimization affects *how* JavaScript code is executed, not the JavaScript syntax itself. I need to illustrate this with a simple JavaScript loop that *could* benefit from loop peeling. This helps visualize the optimization in action, even if the C++ code doesn't directly translate to that JavaScript.

6. **Analyze Test Cases for Input/Output and Logic:**  I look at the individual `TEST_F` functions. Each test case:
    * **Sets up a graph:** Uses `NewWhile`, `NewCounter`, etc., to create a specific loop structure. This is the "input" to the loop peeling algorithm.
    * **Performs peeling:** Calls `PeelOne()` or `Peel()`.
    * **Makes assertions:** Uses `EXPECT_THAT`, `ExpectPeeled`, `ExpectNotPeeled` to verify the structure of the graph after peeling. This is the "output" verification.

    For example, in `SimpleLoop`:
    * Input: A simple `while` loop structure.
    * Action: `PeelOne()` is called.
    * Output: Assertions verify that the first iteration's nodes (branch, if_true, if_false) are cloned, and the original loop now starts after these peeled iterations.

    I select a few representative test cases to illustrate the input/output concept. I don't need to go through *every* test case in detail.

7. **Identify Common Programming Errors (Related to Loop Optimizations):**  I think about common mistakes programmers make that could *prevent* loop optimizations or lead to unexpected behavior. Infinite loops, off-by-one errors, and unnecessary computations inside loops are good examples. I provide simple JavaScript examples to illustrate these. The connection to the C++ code is that these are the kinds of scenarios the compiler (and therefore these tests) deals with.

8. **Address Specific Constraints:**
    * **`.tq` extension:** I explicitly state that the file is `.cc` and thus not a Torque file.
    * **JavaScript example:** I provide clear JavaScript examples related to loop functionality.
    * **Input/Output:** I use specific test cases to illustrate input (graph structure before peeling) and output (graph structure after peeling).
    * **Common errors:** I provide relevant JavaScript examples of common loop-related errors.

9. **Structure the Answer:** I organize the information logically with clear headings for each part of the request (functionality, Torque check, JavaScript example, input/output, common errors).

10. **Review and Refine:**  I reread my answer to ensure it's clear, accurate, and addresses all aspects of the request. I check for any jargon that needs further explanation.

By following these steps, I can generate a comprehensive and informative answer that addresses all the requirements of the prompt. The key is to break down the problem, understand the code's purpose, and connect it to the broader context of JavaScript execution and compiler optimizations.
好的，让我们来分析一下 `v8/test/unittests/compiler/loop-peeling-unittest.cc` 这个文件的功能。

**文件功能概述**

`v8/test/unittests/compiler/loop-peeling-unittest.cc` 是 V8 JavaScript 引擎中 **Turbofan 优化编译器** 的一个单元测试文件。  它的主要功能是 **测试循环剥离（Loop Peeling）优化** 的正确性。

**循环剥离（Loop Peeling）优化** 是一种编译器优化技术，旨在通过复制循环的开头几次迭代来改善性能。这样做可以：

* **消除循环前的条件判断：** 如果循环的第一次迭代可以独立处理，那么就可以在循环外执行，从而避免在循环入口处进行条件判断。
* **暴露更多的优化机会：** 剥离后的循环体可能更容易进行其他的优化，例如指令调度、向量化等。

**文件内容详解**

1. **文件类型：**
   - 该文件以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 V8 的 Torque 源代码文件（Torque 文件以 `.tq` 结尾）。

2. **头文件包含：**
   - `src/compiler/loop-peeling.h`: 包含了 `LoopPeeler` 类的定义，这是进行循环剥离优化的核心类。
   - 其他头文件提供了构建和操作 Turbofan 图（Graph）所需的工具，例如节点（Node）、操作符（Operator）等，以及用于单元测试的框架（gmock）。

3. **命名空间：**
   - 代码位于 `v8::internal::compiler` 命名空间下，表明它是 V8 引擎内部编译器的一部分。

4. **辅助结构体：**
   - `While`:  用于辅助构建 `while` 循环结构的抽象。它包含循环的起始节点 (`loop`)、条件分支 (`branch`)、条件为真时的节点 (`if_true`)、条件为假时的节点 (`if_false`) 以及循环出口 (`exit`)。
   - `Branch`: 用于辅助构建条件分支结构的抽象。
   - `Counter`: 用于辅助构建带有计数器的循环结构的抽象。

5. **测试类 `LoopPeelingTest`：**
   - 继承自 `GraphTest`，提供了创建和操作 Turbofan 图的基础设施。
   - 包含 `machine_` 成员，用于创建机器相关的操作符。
   - 提供了辅助方法，例如：
     - `GetLoopTree()`: 构建循环树，用于分析图中的循环结构。
     - `PeelOne()` 和 `Peel()`:  执行循环剥离操作。
     - `InsertReturn()`:  向图中插入返回节点。
     - `ExpectPeeled()` 和 `ExpectNotPeeled()`: 断言节点是否被循环剥离所影响。
     - `NewWhile()`、`NewBranch()`、`NewCounter()`、`NewPhi()`:  方便构建特定结构的图。

6. **测试用例 (TEST_F)：**
   - 文件中包含多个以 `TEST_F(LoopPeelingTest, ...)` 开头的测试用例，每个用例测试了循环剥离在不同循环结构下的行为。
   - **例如：**
     - `SimpleLoop`: 测试一个简单的 `while` 循环的剥离。
     - `SimpleLoopWithCounter`: 测试带有计数器的循环的剥离。
     - `SimpleNestedLoopWithCounter_peel_outer` 和 `SimpleNestedLoopWithCounter_peel_inner`: 测试嵌套循环在剥离不同层级循环时的行为。
     - `TwoBackedgeLoop`: 测试具有多个反向边的循环的剥离。
     - `TwoExitLoop`: 测试具有多个出口的循环的剥离。
     - `SimpleLoopWithUnmarkedExit`: 测试没有明确标记出口的循环是否可以被剥离（预期不能）。

**与 JavaScript 的关系 (通过 Turbofan 编译器)**

尽管此文件是 C++ 代码，但它直接关系到 V8 引擎如何优化执行 JavaScript 代码。当 V8 的 Turbofan 编译器编译 JavaScript 代码时，它会构建一个图表示（Turbofan Graph）。`LoopPeeling` 优化 pass 会在这个图上运行，尝试识别可以进行剥离的循环，并应用相应的优化。

**JavaScript 示例**

以下是一个简单的 JavaScript 循环，它可以受益于循环剥离优化：

```javascript
function foo(arr) {
  let sum = 0;
  for (let i = 0; i < arr.length; i++) {
    sum += arr[i];
  }
  return sum;
}
```

在这个例子中，循环剥离可以复制循环的第一次或前几次迭代，从而避免在每次循环开始时都检查 `i < arr.length` 的条件。例如，剥离一次后，代码在概念上可能变成类似这样（这只是一个概念性的展示，实际编译过程更复杂）：

```javascript
function foo(arr) {
  let sum = 0;
  if (0 < arr.length) { // 循环前的条件判断
    sum += arr[0];
    for (let i = 1; i < arr.length; i++) {
      sum += arr[i];
    }
  }
  return sum;
}
```

**代码逻辑推理 (假设输入与输出)**

让我们以 `TEST_F(LoopPeelingTest, SimpleLoop)` 为例进行代码逻辑推理：

**假设输入 (构建的图)：**

1. 一个参数节点 `p0`。
2. 一个 `while` 循环结构 `w`，其条件是 `p0`。
3. 一个返回节点 `r`，返回 `p0`。

**图结构 (简化表示)：**

```
Start --> Loop(condition=p0) --> Branch(condition=p0)
                           /            \
                          /              \
                  IfTrue --> ... (循环体，这里为空) --> Loop  (back edge)
                          \              /
                           \            /
                         IfFalse --> LoopExit --> Return(p0)
```

**执行 `PeelOne()` 后的预期输出 (剥离后的图)：**

循环的第一次迭代会被“剥离”出来。这意味着条件分支和相应的 `IfTrue`/`IfFalse` 节点会被复制，而原始的 `Loop` 节点会连接到剥离后的 `IfTrue` 分支。

**图结构 (剥离后，简化表示)：**

```
Start --> Branch(condition=p0) (剥离的)
        /            \
       /              \
IfTrue (剥离的) --> Loop(condition=p0) --> Branch(condition=p0)
                            /            \
                           /              \
                   IfTrue --> ... --> Loop
                           \              /
                            \            /
                          IfFalse --> LoopExit
       \              /
        \            /
     IfFalse (剥离的) --> Merge --> Return(p0)
```

**断言会验证以下内容：**

- 剥离后的分支节点 `br1` 的输入是 `p0` 和 `start()`。
- 剥离后的 `if_true1` 连接到 `br1`。
- 剥离后的 `if_false1` 连接到 `br1`。
- 原始的 `loop` 节点的输入现在是剥离后的 `if_true1` 和原始的 `if_true`。
- 返回节点 `r` 的控制流输入是一个 `Merge` 节点，它合并了原始的 `if_false` 和剥离后的 `if_false1`。

**用户常见的编程错误 (可能影响循环优化)**

1. **无限循环：**
   ```javascript
   while (true) {
     // ...
   }
   ```
   编译器通常会尝试检测和处理无限循环，但复杂的无限循环可能难以优化。

2. **不必要的循环条件判断：**
   ```javascript
   for (let i = 0; i <= arr.length - 1; i++) { // 容易写错成 <=
     // ...
   }
   ```
   像这样的 off-by-one 错误可能导致额外的条件判断。

3. **在循环体内进行不必要的计算：**
   ```javascript
   for (let i = 0; i < arr.length; i++) {
     const multiplier = expensiveCalculation(); // 每次循环都计算
     result += arr[i] * multiplier;
   }
   ```
   将不依赖于循环变量的计算移到循环外部可以提高性能。

4. **在循环体内修改循环条件相关的变量：**
   ```javascript
   for (let i = 0; i < arr.length; i++) {
     // ...
     if (someCondition) {
       arr.length = i; // 修改了循环终止条件
     }
   }
   ```
   这种做法会让编译器难以进行有效的循环优化。

5. **使用 `break` 或 `continue` 过度：**
   虽然 `break` 和 `continue` 是合法的控制流语句，但过度使用可能会使循环结构复杂化，降低编译器优化的效果。

总而言之，`v8/test/unittests/compiler/loop-peeling-unittest.cc` 通过一系列精心设计的测试用例，确保 V8 的 Turbofan 编译器能够正确地执行循环剥离优化，从而提升 JavaScript 代码的执行效率。这些测试覆盖了各种常见的循环结构和边界情况，是保证 V8 引擎质量的重要组成部分。

### 提示词
```
这是目录为v8/test/unittests/compiler/loop-peeling-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/loop-peeling-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/loop-peeling.h"

#include "src/compiler/machine-operator.h"
#include "src/compiler/node.h"
#include "src/compiler/turbofan-graph-visualizer.h"
#include "src/compiler/turbofan-graph.h"
#include "test/unittests/compiler/graph-unittest.h"
#include "test/unittests/compiler/node-test-utils.h"
#include "testing/gmock-support.h"

using testing::AllOf;
using testing::BitEq;
using testing::Capture;
using testing::CaptureEq;

namespace v8 {
namespace internal {
namespace compiler {

struct While {
  Node* loop;
  Node* branch;
  Node* if_true;
  Node* if_false;
  Node* exit;
};


// A helper for building branches.
struct Branch {
  Node* branch;
  Node* if_true;
  Node* if_false;
};


// A helper for building counters attached to loops.
struct Counter {
  Node* base;
  Node* inc;
  Node* phi;
  Node* add;
  Node* exit_marker;
};


class LoopPeelingTest : public GraphTest {
 public:
  LoopPeelingTest() : GraphTest(1), machine_(zone()) {}
  ~LoopPeelingTest() override = default;

 protected:
  MachineOperatorBuilder machine_;

  MachineOperatorBuilder* machine() { return &machine_; }

  LoopTree* GetLoopTree() {
    if (v8_flags.trace_turbo_graph) {
      StdoutStream{} << AsRPO(*graph());
    }
    Zone zone(isolate()->allocator(), ZONE_NAME);
    return LoopFinder::BuildLoopTree(graph(), tick_counter(), &zone);
  }


  PeeledIteration* PeelOne() {
    LoopTree* loop_tree = GetLoopTree();
    LoopTree::Loop* loop = loop_tree->outer_loops()[0];
    LoopPeeler peeler(graph(), common(), loop_tree, zone(), source_positions(),
                      node_origins());
    EXPECT_TRUE(peeler.CanPeel(loop));
    return Peel(peeler, loop);
  }

  PeeledIteration* Peel(LoopPeeler peeler, LoopTree::Loop* loop) {
    EXPECT_TRUE(peeler.CanPeel(loop));
    PeeledIteration* peeled = peeler.Peel(loop);
    if (v8_flags.trace_turbo_graph) {
      StdoutStream{} << AsRPO(*graph());
    }
    return peeled;
  }

  Node* InsertReturn(Node* val, Node* effect, Node* control) {
    Node* zero = graph()->NewNode(common()->Int32Constant(0));
    Node* r = graph()->NewNode(common()->Return(), zero, val, effect, control);
    graph()->SetEnd(r);
    return r;
  }

  Node* ExpectPeeled(Node* node, PeeledIteration* iter) {
    Node* p = iter->map(node);
    EXPECT_NE(node, p);
    return p;
  }

  void ExpectNotPeeled(Node* node, PeeledIteration* iter) {
    EXPECT_EQ(node, iter->map(node));
  }

  While NewWhile(Node* cond, Node* control = nullptr) {
    if (control == nullptr) control = start();
    While w;
    w.loop = graph()->NewNode(common()->Loop(2), control, control);
    w.branch = graph()->NewNode(common()->Branch(), cond, w.loop);
    w.if_true = graph()->NewNode(common()->IfTrue(), w.branch);
    w.if_false = graph()->NewNode(common()->IfFalse(), w.branch);
    w.exit = graph()->NewNode(common()->LoopExit(), w.if_false, w.loop);
    w.loop->ReplaceInput(1, w.if_true);
    return w;
  }

  void Chain(While* a, Node* control) { a->loop->ReplaceInput(0, control); }
  void Nest(While* a, While* b) {
    b->loop->ReplaceInput(1, a->exit);
    a->loop->ReplaceInput(0, b->if_true);
  }
  Node* NewPhi(While* w, Node* a, Node* b) {
    return graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2), a,
                            b, w->loop);
  }

  Branch NewBranch(Node* cond, Node* control = nullptr) {
    Branch b;
    if (control == nullptr) control = start();
    b.branch = graph()->NewNode(common()->Branch(), cond, control);
    b.if_true = graph()->NewNode(common()->IfTrue(), b.branch);
    b.if_false = graph()->NewNode(common()->IfFalse(), b.branch);
    return b;
  }

  Counter NewCounter(While* w, int32_t b, int32_t k) {
    Counter c;
    c.base = Int32Constant(b);
    c.inc = Int32Constant(k);
    c.phi = graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                             c.base, c.base, w->loop);
    c.add = graph()->NewNode(machine()->Int32Add(), c.phi, c.inc);
    c.phi->ReplaceInput(1, c.add);
    c.exit_marker = graph()->NewNode(
        common()->LoopExitValue(MachineRepresentation::kTagged), c.phi,
        w->exit);
    return c;
  }
};


TEST_F(LoopPeelingTest, SimpleLoop) {
  Node* p0 = Parameter(0);
  While w = NewWhile(p0);
  Node* r = InsertReturn(p0, start(), w.exit);

  PeeledIteration* peeled = PeelOne();

  Node* br1 = ExpectPeeled(w.branch, peeled);
  Node* if_true1 = ExpectPeeled(w.if_true, peeled);
  Node* if_false1 = ExpectPeeled(w.if_false, peeled);

  EXPECT_THAT(br1, IsBranch(p0, start()));
  EXPECT_THAT(if_true1, IsIfTrue(br1));
  EXPECT_THAT(if_false1, IsIfFalse(br1));

  EXPECT_THAT(w.loop, IsLoop(if_true1, w.if_true));
  EXPECT_THAT(r, IsReturn(p0, start(), IsMerge(w.if_false, if_false1)));
}


TEST_F(LoopPeelingTest, SimpleLoopWithCounter) {
  Node* p0 = Parameter(0);
  While w = NewWhile(p0);
  Counter c = NewCounter(&w, 0, 1);
  Node* r = InsertReturn(c.exit_marker, start(), w.exit);

  PeeledIteration* peeled = PeelOne();

  Node* br1 = ExpectPeeled(w.branch, peeled);
  Node* if_true1 = ExpectPeeled(w.if_true, peeled);
  Node* if_false1 = ExpectPeeled(w.if_false, peeled);

  EXPECT_THAT(br1, IsBranch(p0, start()));
  EXPECT_THAT(if_true1, IsIfTrue(br1));
  EXPECT_THAT(if_false1, IsIfFalse(br1));
  EXPECT_THAT(w.loop, IsLoop(if_true1, w.if_true));

  EXPECT_THAT(peeled->map(c.add), IsInt32Add(c.base, c.inc));

  EXPECT_THAT(w.exit, IsMerge(w.if_false, if_false1));
  EXPECT_THAT(
      r, IsReturn(IsPhi(MachineRepresentation::kTagged, c.phi, c.base, w.exit),
                  start(), w.exit));
}


TEST_F(LoopPeelingTest, SimpleNestedLoopWithCounter_peel_outer) {
  Node* p0 = Parameter(0);
  While outer = NewWhile(p0);
  While inner = NewWhile(p0);
  Nest(&inner, &outer);

  Counter c = NewCounter(&outer, 0, 1);
  Node* r = InsertReturn(c.exit_marker, start(), outer.exit);

  PeeledIteration* peeled = PeelOne();

  Node* bro = ExpectPeeled(outer.branch, peeled);
  Node* if_trueo = ExpectPeeled(outer.if_true, peeled);
  Node* if_falseo = ExpectPeeled(outer.if_false, peeled);

  EXPECT_THAT(bro, IsBranch(p0, start()));
  EXPECT_THAT(if_trueo, IsIfTrue(bro));
  EXPECT_THAT(if_falseo, IsIfFalse(bro));

  Node* bri = ExpectPeeled(inner.branch, peeled);
  Node* if_truei = ExpectPeeled(inner.if_true, peeled);
  Node* if_falsei = ExpectPeeled(inner.if_false, peeled);
  Node* exiti = ExpectPeeled(inner.exit, peeled);

  EXPECT_THAT(bri, IsBranch(p0, ExpectPeeled(inner.loop, peeled)));
  EXPECT_THAT(if_truei, IsIfTrue(bri));
  EXPECT_THAT(if_falsei, IsIfFalse(bri));

  EXPECT_THAT(outer.loop, IsLoop(exiti, inner.exit));
  EXPECT_THAT(peeled->map(c.add), IsInt32Add(c.base, c.inc));

  Capture<Node*> merge;
  EXPECT_THAT(outer.exit, IsMerge(outer.if_false, if_falseo));
  EXPECT_THAT(r, IsReturn(IsPhi(MachineRepresentation::kTagged, c.phi, c.base,
                                outer.exit),
                          start(), outer.exit));
}


TEST_F(LoopPeelingTest, SimpleNestedLoopWithCounter_peel_inner) {
  Node* p0 = Parameter(0);
  While outer = NewWhile(p0);
  While inner = NewWhile(p0);
  Nest(&inner, &outer);

  Counter c = NewCounter(&outer, 0, 1);
  Node* r = InsertReturn(c.exit_marker, start(), outer.exit);

  LoopTree* loop_tree = GetLoopTree();
  LoopTree::Loop* loop = loop_tree->ContainingLoop(inner.loop);
  EXPECT_NE(nullptr, loop);
  EXPECT_EQ(1u, loop->depth());

  LoopPeeler peeler(graph(), common(), loop_tree, zone(), source_positions(),
                    node_origins());
  PeeledIteration* peeled = Peel(peeler, loop);

  ExpectNotPeeled(outer.loop, peeled);
  ExpectNotPeeled(outer.branch, peeled);
  ExpectNotPeeled(outer.if_true, peeled);
  ExpectNotPeeled(outer.if_false, peeled);
  ExpectNotPeeled(outer.exit, peeled);

  Node* bri = ExpectPeeled(inner.branch, peeled);
  Node* if_truei = ExpectPeeled(inner.if_true, peeled);
  Node* if_falsei = ExpectPeeled(inner.if_false, peeled);

  EXPECT_THAT(bri, IsBranch(p0, ExpectPeeled(inner.loop, peeled)));
  EXPECT_THAT(if_truei, IsIfTrue(bri));
  EXPECT_THAT(if_falsei, IsIfFalse(bri));

  EXPECT_THAT(inner.exit, IsMerge(inner.if_false, if_falsei));
  EXPECT_THAT(outer.loop, IsLoop(start(), inner.exit));
  ExpectNotPeeled(c.add, peeled);

  EXPECT_THAT(r, IsReturn(c.exit_marker, start(), outer.exit));
}


TEST_F(LoopPeelingTest, SimpleInnerCounter_peel_inner) {
  Node* p0 = Parameter(0);
  While outer = NewWhile(p0);
  While inner = NewWhile(p0);
  Nest(&inner, &outer);
  Counter c = NewCounter(&inner, 0, 1);
  Node* phi = NewPhi(&outer, Int32Constant(11), c.exit_marker);

  Node* r = InsertReturn(phi, start(), outer.exit);

  LoopTree* loop_tree = GetLoopTree();
  LoopTree::Loop* loop = loop_tree->ContainingLoop(inner.loop);
  EXPECT_NE(nullptr, loop);
  EXPECT_EQ(1u, loop->depth());

  LoopPeeler peeler(graph(), common(), loop_tree, zone(), source_positions(),
                    node_origins());
  PeeledIteration* peeled = Peel(peeler, loop);

  ExpectNotPeeled(outer.loop, peeled);
  ExpectNotPeeled(outer.branch, peeled);
  ExpectNotPeeled(outer.if_true, peeled);
  ExpectNotPeeled(outer.if_false, peeled);
  ExpectNotPeeled(outer.exit, peeled);

  Node* bri = ExpectPeeled(inner.branch, peeled);
  Node* if_truei = ExpectPeeled(inner.if_true, peeled);
  Node* if_falsei = ExpectPeeled(inner.if_false, peeled);

  EXPECT_THAT(bri, IsBranch(p0, ExpectPeeled(inner.loop, peeled)));
  EXPECT_THAT(if_truei, IsIfTrue(bri));
  EXPECT_THAT(if_falsei, IsIfFalse(bri));

  EXPECT_THAT(inner.exit, IsMerge(inner.if_false, if_falsei));
  EXPECT_THAT(outer.loop, IsLoop(start(), inner.exit));
  EXPECT_THAT(peeled->map(c.add), IsInt32Add(c.base, c.inc));

  EXPECT_THAT(c.exit_marker,
              IsPhi(MachineRepresentation::kTagged, c.phi, c.base, inner.exit));

  EXPECT_THAT(phi, IsPhi(MachineRepresentation::kTagged, IsInt32Constant(11),
                         c.exit_marker, outer.loop));

  EXPECT_THAT(r, IsReturn(phi, start(), outer.exit));
}


TEST_F(LoopPeelingTest, TwoBackedgeLoop) {
  Node* p0 = Parameter(0);
  Node* loop = graph()->NewNode(common()->Loop(3), start(), start(), start());
  Branch b1 = NewBranch(p0, loop);
  Branch b2 = NewBranch(p0, b1.if_true);

  loop->ReplaceInput(1, b2.if_true);
  loop->ReplaceInput(2, b2.if_false);

  Node* exit = graph()->NewNode(common()->LoopExit(), b1.if_false, loop);

  Node* r = InsertReturn(p0, start(), exit);

  PeeledIteration* peeled = PeelOne();

  Node* b1b = ExpectPeeled(b1.branch, peeled);
  Node* b1t = ExpectPeeled(b1.if_true, peeled);
  Node* b1f = ExpectPeeled(b1.if_false, peeled);

  EXPECT_THAT(b1b, IsBranch(p0, start()));
  EXPECT_THAT(ExpectPeeled(b1.if_true, peeled), IsIfTrue(b1b));
  EXPECT_THAT(b1f, IsIfFalse(b1b));

  Node* b2b = ExpectPeeled(b2.branch, peeled);
  Node* b2t = ExpectPeeled(b2.if_true, peeled);
  Node* b2f = ExpectPeeled(b2.if_false, peeled);

  EXPECT_THAT(b2b, IsBranch(p0, b1t));
  EXPECT_THAT(b2t, IsIfTrue(b2b));
  EXPECT_THAT(b2f, IsIfFalse(b2b));

  EXPECT_THAT(loop, IsLoop(IsMerge(b2t, b2f), b2.if_true, b2.if_false));
  EXPECT_THAT(exit, IsMerge(b1.if_false, b1f));
  EXPECT_THAT(r, IsReturn(p0, start(), exit));
}


TEST_F(LoopPeelingTest, TwoBackedgeLoopWithPhi) {
  Node* p0 = Parameter(0);
  Node* loop = graph()->NewNode(common()->Loop(3), start(), start(), start());
  Branch b1 = NewBranch(p0, loop);
  Branch b2 = NewBranch(p0, b1.if_true);
  Node* phi = graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 3),
                               Int32Constant(0), Int32Constant(1),
                               Int32Constant(2), loop);

  loop->ReplaceInput(1, b2.if_true);
  loop->ReplaceInput(2, b2.if_false);

  Node* exit = graph()->NewNode(common()->LoopExit(), b1.if_false, loop);
  Node* exit_marker = graph()->NewNode(
      common()->LoopExitValue(MachineRepresentation::kTagged), phi, exit);
  Node* r = InsertReturn(exit_marker, start(), exit);

  PeeledIteration* peeled = PeelOne();

  Node* b1b = ExpectPeeled(b1.branch, peeled);
  Node* b1t = ExpectPeeled(b1.if_true, peeled);
  Node* b1f = ExpectPeeled(b1.if_false, peeled);

  EXPECT_THAT(b1b, IsBranch(p0, start()));
  EXPECT_THAT(ExpectPeeled(b1.if_true, peeled), IsIfTrue(b1b));
  EXPECT_THAT(b1f, IsIfFalse(b1b));

  Node* b2b = ExpectPeeled(b2.branch, peeled);
  Node* b2t = ExpectPeeled(b2.if_true, peeled);
  Node* b2f = ExpectPeeled(b2.if_false, peeled);

  EXPECT_THAT(b2b, IsBranch(p0, b1t));
  EXPECT_THAT(b2t, IsIfTrue(b2b));
  EXPECT_THAT(b2f, IsIfFalse(b2b));

  EXPECT_THAT(loop, IsLoop(IsMerge(b2t, b2f), b2.if_true, b2.if_false));

  EXPECT_THAT(phi,
              IsPhi(MachineRepresentation::kTagged,
                    IsPhi(MachineRepresentation::kTagged, IsInt32Constant(1),
                          IsInt32Constant(2), IsMerge(b2t, b2f)),
                    IsInt32Constant(1), IsInt32Constant(2), loop));

  EXPECT_THAT(exit, IsMerge(b1.if_false, b1f));
  EXPECT_THAT(exit_marker, IsPhi(MachineRepresentation::kTagged, phi,
                                 IsInt32Constant(0), exit));
  EXPECT_THAT(r, IsReturn(exit_marker, start(), exit));
}


TEST_F(LoopPeelingTest, TwoBackedgeLoopWithCounter) {
  Node* p0 = Parameter(0);
  Node* loop = graph()->NewNode(common()->Loop(3), start(), start(), start());
  Branch b1 = NewBranch(p0, loop);
  Branch b2 = NewBranch(p0, b1.if_true);
  Node* phi = graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 3),
                               Int32Constant(0), Int32Constant(1),
                               Int32Constant(2), loop);

  phi->ReplaceInput(
      1, graph()->NewNode(machine()->Int32Add(), phi, Int32Constant(1)));
  phi->ReplaceInput(
      2, graph()->NewNode(machine()->Int32Add(), phi, Int32Constant(2)));

  loop->ReplaceInput(1, b2.if_true);
  loop->ReplaceInput(2, b2.if_false);

  Node* exit = graph()->NewNode(common()->LoopExit(), b1.if_false, loop);
  Node* exit_marker = graph()->NewNode(
      common()->LoopExitValue(MachineRepresentation::kTagged), phi, exit);
  Node* r = InsertReturn(exit_marker, start(), exit);

  PeeledIteration* peeled = PeelOne();

  Node* b1b = ExpectPeeled(b1.branch, peeled);
  Node* b1t = ExpectPeeled(b1.if_true, peeled);
  Node* b1f = ExpectPeeled(b1.if_false, peeled);

  EXPECT_THAT(b1b, IsBranch(p0, start()));
  EXPECT_THAT(ExpectPeeled(b1.if_true, peeled), IsIfTrue(b1b));
  EXPECT_THAT(b1f, IsIfFalse(b1b));

  Node* b2b = ExpectPeeled(b2.branch, peeled);
  Node* b2t = ExpectPeeled(b2.if_true, peeled);
  Node* b2f = ExpectPeeled(b2.if_false, peeled);

  EXPECT_THAT(b2b, IsBranch(p0, b1t));
  EXPECT_THAT(b2t, IsIfTrue(b2b));
  EXPECT_THAT(b2f, IsIfFalse(b2b));

  Capture<Node*> entry;
  EXPECT_THAT(loop, IsLoop(AllOf(CaptureEq(&entry), IsMerge(b2t, b2f)),
                           b2.if_true, b2.if_false));

  Node* eval = phi->InputAt(0);

  EXPECT_THAT(eval, IsPhi(MachineRepresentation::kTagged,
                          IsInt32Add(IsInt32Constant(0), IsInt32Constant(1)),
                          IsInt32Add(IsInt32Constant(0), IsInt32Constant(2)),
                          CaptureEq(&entry)));

  EXPECT_THAT(phi, IsPhi(MachineRepresentation::kTagged, eval,
                         IsInt32Add(phi, IsInt32Constant(1)),
                         IsInt32Add(phi, IsInt32Constant(2)), loop));

  EXPECT_THAT(exit, IsMerge(b1.if_false, b1f));
  EXPECT_THAT(exit_marker, IsPhi(MachineRepresentation::kTagged, phi,
                                 IsInt32Constant(0), exit));
  EXPECT_THAT(r, IsReturn(exit_marker, start(), exit));
}

TEST_F(LoopPeelingTest, TwoExitLoop) {
  Node* p0 = Parameter(0);
  Node* loop = graph()->NewNode(common()->Loop(2), start(), start());
  Branch b1 = NewBranch(p0, loop);
  Branch b2 = NewBranch(p0, b1.if_true);

  loop->ReplaceInput(1, b2.if_true);

  Node* exit1 = graph()->NewNode(common()->LoopExit(), b1.if_false, loop);
  Node* exit2 = graph()->NewNode(common()->LoopExit(), b2.if_false, loop);

  Node* merge = graph()->NewNode(common()->Merge(2), exit1, exit2);
  Node* r = InsertReturn(p0, start(), merge);

  PeeledIteration* peeled = PeelOne();

  Node* b1p = ExpectPeeled(b1.branch, peeled);
  Node* if_true1p = ExpectPeeled(b1.if_true, peeled);
  Node* if_false1p = ExpectPeeled(b1.if_false, peeled);

  Node* b2p = ExpectPeeled(b2.branch, peeled);
  Node* if_true2p = ExpectPeeled(b2.if_true, peeled);
  Node* if_false2p = ExpectPeeled(b2.if_false, peeled);

  EXPECT_THAT(b1p, IsBranch(p0, start()));
  EXPECT_THAT(if_true1p, IsIfTrue(b1p));
  EXPECT_THAT(if_false1p, IsIfFalse(b1p));

  EXPECT_THAT(b2p, IsBranch(p0, if_true1p));
  EXPECT_THAT(if_true2p, IsIfTrue(b2p));
  EXPECT_THAT(if_false2p, IsIfFalse(b2p));

  EXPECT_THAT(exit1, IsMerge(b1.if_false, if_false1p));
  EXPECT_THAT(exit2, IsMerge(b2.if_false, if_false2p));

  EXPECT_THAT(loop, IsLoop(if_true2p, b2.if_true));

  EXPECT_THAT(merge, IsMerge(exit1, exit2));
  EXPECT_THAT(r, IsReturn(p0, start(), merge));
}

TEST_F(LoopPeelingTest, SimpleLoopWithUnmarkedExit) {
  Node* p0 = Parameter(0);
  Node* loop = graph()->NewNode(common()->Loop(2), start(), start());
  Branch b = NewBranch(p0, loop);
  loop->ReplaceInput(1, b.if_true);

  InsertReturn(p0, start(), b.if_false);

  {
    LoopTree* loop_tree = GetLoopTree();
    LoopTree::Loop* outer_loop = loop_tree->outer_loops()[0];
    LoopPeeler peeler(graph(), common(), loop_tree, zone(), source_positions(),
                      node_origins());
    EXPECT_FALSE(peeler.CanPeel(outer_loop));
  }
}


}  // namespace compiler
}  // namespace internal
}  // namespace v8
```