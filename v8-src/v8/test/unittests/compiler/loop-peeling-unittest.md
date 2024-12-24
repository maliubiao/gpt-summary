Response: Let's break down the thought process for analyzing this C++ code and connecting it to JavaScript.

**1. Understanding the Goal:**

The request asks to summarize the C++ code's functionality and relate it to JavaScript with an example if applicable. The file path `v8/test/unittests/compiler/loop-peeling-unittest.cc` immediately suggests it's a *test file* for a *compiler* feature called *loop peeling*.

**2. Initial Scan and Keyword Recognition:**

Quickly scanning the code reveals key terms and structures:

* `#include ...`: Standard C++ includes, hinting at dependencies and functionality.
* `namespace v8::internal::compiler`:  Confirms it's part of the V8 JavaScript engine's compiler.
* `struct While`, `struct Branch`, `struct Counter`:  These define data structures likely representing parts of a control flow graph.
* `class LoopPeelingTest : public GraphTest`:  This is a C++ testing class, inheriting from `GraphTest`, suggesting it tests graph-related operations.
* `PeeledIteration* PeelOne()`, `PeeledIteration* Peel(...)`: Functions with "Peel" in their names strongly indicate the core functionality being tested.
* `EXPECT_TRUE(...)`, `EXPECT_THAT(...)`, `EXPECT_EQ(...)`, `EXPECT_NE(...)`: These are Google Test assertions, confirming this is a unit test file.
*  `IsLoop(...)`, `IsBranch(...)`, `IsIfTrue(...)`, `IsIfFalse(...)`, `IsPhi(...)`, `IsInt32Add(...)`, `IsReturn(...)`: These functions appear to be custom matchers for verifying the structure and properties of nodes in the graph.
*  Mentions of `LoopTree`, `LoopFinder`, `LoopPeeler`: More confirmation of the loop-related nature of the code.

**3. Deciphering the Core Functionality: Loop Peeling**

Based on the file name and the function names, the primary function of this code is to **test the "loop peeling" optimization in the V8 JavaScript compiler.**

* **What is Loop Peeling?**  (This is where prior knowledge or a quick search comes in handy.) Loop peeling is a compiler optimization that duplicates the first few iterations of a loop outside the loop. This can sometimes improve performance by allowing optimizations within the first few iterations or by simplifying the loop condition.

**4. Analyzing the Test Cases:**

Now, let's look at the individual test functions (`TEST_F(LoopPeelingTest, ...)`):

* **`SimpleLoop`:** Tests peeling a basic `while` loop. It checks if the first iteration's nodes (branch, if-true, if-false) are correctly duplicated (peeled).
* **`SimpleLoopWithCounter`:** Adds a counter variable to the loop and verifies that the counter's operations are also peeled.
* **`SimpleNestedLoopWithCounter_peel_outer/inner`:**  Tests peeling in nested loops, specifically targeting either the outer or inner loop for peeling.
* **`SimpleInnerCounter_peel_inner`:** Focuses on peeling the inner loop when the counter is inside the inner loop.
* **`TwoBackedgeLoop` and variations:** Deals with loops that have multiple entry points (backedges), making peeling more complex. It verifies the correct duplication of branches and the handling of `Phi` nodes (which merge values from different control flow paths).
* **`TwoExitLoop`:** Tests peeling a loop with multiple exit points.
* **`SimpleLoopWithUnmarkedExit`:** Checks a scenario where loop peeling *cannot* be applied due to an unmarked exit.

**5. Connecting to JavaScript:**

The core connection lies in the fact that this C++ code is *testing an optimization that will be applied to JavaScript code*. When the V8 engine compiles JavaScript code, it might identify loops suitable for peeling and apply this optimization.

**6. Constructing the JavaScript Example:**

To illustrate the concept in JavaScript, we need a simple loop that could potentially benefit from peeling:

```javascript
function foo(arr) {
  let sum = 0;
  for (let i = 0; i < arr.length; i++) {
    sum += arr[i];
  }
  return sum;
}
```

* **Explanation of the Example:** This is a standard loop iterating over an array. A compiler applying loop peeling might unroll the first one or two iterations:

   ```javascript  (Conceptual Peeling)
   function foo(arr) {
     let sum = 0;
     if (arr.length > 0) { // Peeled first iteration
       sum += arr[0];
     }
     if (arr.length > 1) { // Peeled second iteration
       sum += arr[1];
     }
     for (let i = (arr.length > 1 ? 2 : (arr.length > 0 ? 1 : 0)); i < arr.length; i++) {
       sum += arr[i];
     }
     return sum;
   }
   ```

   * **Key Idea:** The C++ tests verify that the *compiler's internal representation* of the peeled loop is correct. We don't directly write peeled JavaScript.

**7. Refining the Explanation and Adding Nuance:**

* Emphasize that the C++ code is testing the *compiler's internal mechanics*.
* Clarify that the JavaScript example is for *illustration* and the actual peeling is done by the compiler.
* Explain the potential benefits of loop peeling (reducing overhead, enabling further optimizations).
* Point out the connection between the C++ structures (`While`, `Branch`, etc.) and the abstract concept of control flow in the JavaScript loop.

**Self-Correction/Refinement during the Process:**

* Initially, I might have focused too much on the specific C++ syntax. The key is to abstract the purpose.
*  Realizing the importance of explaining *what* loop peeling is would be a crucial correction.
*  Ensuring the JavaScript example is simple and clearly demonstrates the *concept* of unrolling is important. Avoid overly complex examples.

By following these steps, combining code analysis with an understanding of compiler optimizations, and then bridging the gap to JavaScript, we can arrive at a comprehensive and accurate explanation.
这个C++源代码文件 `loop-peeling-unittest.cc` 是 V8 JavaScript 引擎中 Turbofan 编译器的 **循环剥离 (loop peeling)** 优化功能的单元测试。

**功能归纳:**

这个文件的主要目的是测试 `LoopPeeler` 类的各种功能和边界情况，以确保循环剥离优化在不同的循环结构下都能正确执行。循环剥离是一种编译器优化技术，它通过复制循环的首次迭代（或少量迭代）到循环外部来减少循环的开销，并可能暴露更多的优化机会。

具体来说，这个单元测试文件做了以下事情：

1. **定义了辅助结构体:**
   - `While`: 用于构建 while 循环的抽象表示。
   - `Branch`: 用于构建条件分支的抽象表示。
   - `Counter`: 用于构建循环计数器的抽象表示。

2. **定义了测试类 `LoopPeelingTest`:**
   - 继承自 `GraphTest`，提供创建和操作 Turbofan 图的基础设施。
   - 提供了方便的方法来创建各种类型的节点 (Node)，例如循环、分支、Phi 节点、算术运算等。
   - 核心方法是 `PeelOne()` 和 `Peel(LoopPeeler peeler, LoopTree::Loop* loop)`，用于执行循环剥离操作并返回 `PeeledIteration` 对象，该对象包含了剥离后的节点映射。
   - 提供了 `ExpectPeeled()` 和 `ExpectNotPeeled()` 方法来断言在剥离操作后，特定的节点是否被复制（剥离）。

3. **包含多个测试用例 (`TEST_F`)**:
   - **`SimpleLoop`**: 测试对一个简单的 `while` 循环进行剥离。
   - **`SimpleLoopWithCounter`**: 测试对带有计数器的简单循环进行剥离。
   - **`SimpleNestedLoopWithCounter_peel_outer/inner`**: 测试对嵌套循环进行剥离，分别剥离外层和内层循环。
   - **`SimpleInnerCounter_peel_inner`**: 测试当计数器在内层循环时，对内层循环进行剥离。
   - **`TwoBackedgeLoop` 和相关测试**: 测试对具有多个回边的循环进行剥离，这涉及到更复杂的控制流。
   - **`TwoExitLoop`**: 测试对具有多个出口的循环进行剥离。
   - **`SimpleLoopWithUnmarkedExit`**: 测试当循环出口未被明确标记时，循环剥离是否会失败。

每个测试用例都会构建一个包含特定循环结构的 Turbofan 图，然后调用 `PeelOne()` 或 `Peel()` 来执行循环剥离，最后使用 `EXPECT_THAT` 等断言来验证剥离后的图结构是否符合预期。例如，它会检查被剥离的节点是否被复制，以及复制后的节点的连接关系是否正确。

**与 JavaScript 的关系以及 JavaScript 示例:**

这个 C++ 代码直接作用于 V8 引擎的内部，负责将 JavaScript 代码编译成高效的机器码。循环剥离是一种应用于 JavaScript 代码的优化技术。当 V8 编译 JavaScript 代码中的循环时，它会分析循环的特性，并有可能应用循环剥离优化。

**JavaScript 示例:**

考虑以下简单的 JavaScript 循环：

```javascript
function sumArray(arr) {
  let sum = 0;
  for (let i = 0; i < arr.length; i++) {
    sum += arr[i];
  }
  return sum;
}
```

当 V8 编译这段代码时，Turbofan 编译器可能会识别出这个循环可以进行剥离。  循环剥离后的概念上的执行流程可能如下（这只是概念，实际执行是由编译器生成的机器码完成的）：

```javascript
function sumArrayOptimized(arr) {
  let sum = 0;

  // 剥离后的首次迭代 (假设剥离一次)
  if (arr.length > 0) {
    sum += arr[0];
    // 剩余的循环从 i = 1 开始
    for (let i = 1; i < arr.length; i++) {
      sum += arr[i];
    }
  }

  return sum;
}
```

**解释:**

在这个例子中，循环的第一次迭代被“剥离”出来，放到了循环前面。这样做的好处可能包括：

* **减少循环开销:** 循环的条件判断、索引递增等操作在剥离的迭代中只需要执行一次。
* **更好的代码局部性:** 某些情况下，提前执行一些操作可以改善数据访问的局部性。
* **更多的优化机会:** 剥离后的代码可能更容易被进一步优化，例如常量折叠或死代码消除。

**总结:**

`loop-peeling-unittest.cc` 这个 C++ 文件是 V8 引擎的关键组成部分，它通过单元测试确保了循环剥离这一重要的 JavaScript 代码优化技术能够正确可靠地工作，从而提升 JavaScript 代码的执行效率。虽然我们不能直接看到 JavaScript 代码被剥离，但这个测试文件验证了 V8 内部进行这种优化的逻辑。

Prompt: 
```
这是目录为v8/test/unittests/compiler/loop-peeling-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
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

"""

```