Response:
Let's break down the thought process for analyzing the `v8/src/compiler/loop-analysis.cc` file.

1. **Initial Scan for Keywords:**  The first step is to quickly scan the code for relevant keywords that hint at the file's purpose. Keywords like "loop," "analysis," "header," "backedge," "tree," "propagate," "mark," etc., immediately jump out and suggest the file is related to understanding and structuring loops within a compiler's intermediate representation.

2. **Identify the Core Class:** The `LoopFinderImpl` class is central. Its constructor and `Run()` method are strong indicators of the primary algorithm's execution. The comments preceding the class declaration are crucial:  "Conceptually, the contents of a loop are those nodes that are 'between' the loop header and the backedges of the loop." This gives a high-level understanding of the problem being solved.

3. **Deconstruct the `LoopFinderImpl` Algorithm:**
    * **`PropagateBackward()` and `PropagateForward()`:** These methods, along with the associated "mark" variables (`backward_`, `forward_`), strongly suggest a graph traversal algorithm. The names indicate traversal in opposite directions, which is a common technique in graph analysis. The comments mentioning "1 bit per loop per node per direction" are key to understanding the marking scheme.
    * **`CreateLoopInfo()`:**  This function clearly deals with identifying loop headers (specifically `IrOpcode::kLoop` nodes and related phis). The connection to `LoopTree` is also evident.
    * **`FinishLoopTree()`:** This method focuses on structuring the found loops into a hierarchical tree (`LoopTree`). The handling of nested loops is a significant part of this.
    * **Data Structures:**  Paying attention to the data structures used (e.g., `NodeDeque`, `NodeMarker`, `ZoneVector<NodeInfo>`, `ZoneVector<TempLoopInfo>`, `LoopTree`) provides insights into how the algorithm manages nodes and loop information.

4. **Connect to Compiler Concepts:** The code uses terms like "node," "opcode," "phi," "control flow," "backedge," which are fundamental concepts in compiler intermediate representations (like the one used by Turbofan). Understanding these terms is essential for grasping the code's purpose.

5. **Look for Public Interface:** The `LoopFinder::BuildLoopTree()` function provides the public interface for using the loop analysis. It takes a `Graph` as input and returns a `LoopTree`. This clarifies how other parts of the compiler would interact with this module.

6. **Examine the `LoopTree` Class (Implicitly):**  Although the full `LoopTree` definition isn't in this file, the code interacts with it extensively. We can infer its structure and purpose based on the methods called (e.g., `NewLoop()`, `SetParent()`, `LoopNodes()`, `HeaderNodes()`, `Contains()`).

7. **Consider `.tq` Extension:** The prompt asks about the `.tq` extension. Knowing that Torque is V8's internal language for defining built-in functions, the answer is that this file *doesn't* have that extension and thus isn't a Torque file.

8. **Relate to JavaScript Functionality (If Applicable):** The prompt asks for JavaScript examples. Since loop analysis is about understanding loop structures in the *compiled* code, the JavaScript examples should demonstrate different loop constructs (e.g., `for`, `while`, `do...while`, `for...in`, `for...of`). The compiler uses this analysis to optimize these constructs.

9. **Infer Code Logic and Provide Examples:**
    * **Input/Output:**  Think about what the input to the `BuildLoopTree` function is (a `Graph`) and what the output is (a `LoopTree`). A simplified mental model of a graph with a loop helps illustrate the process.
    * **Common Errors:** Consider typical programming mistakes related to loops, such as infinite loops, off-by-one errors, and incorrect loop conditions. These highlight why accurate loop analysis is crucial for optimization and correctness.

10. **Refine and Structure the Answer:** Organize the findings into clear sections (Functionality, `.tq` extension, JavaScript relation, Code logic, Common errors). Use clear and concise language. Provide code examples for the JavaScript and potential input/output scenarios.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  "Maybe this is just about finding simple loops."  **Correction:**  The code explicitly handles nested loops, indicated by the loop tree structure and the recursive nature of `FinishLoopTree()` and `ConnectLoopTree()`.
* **Initial thought:** "The marking seems complex." **Refinement:** Realizing that the forward and backward propagation with bitmasks is a way to efficiently track reachability within different loop contexts. The `width_` variable and the bitwise operations become clearer.
* **Considering JavaScript examples:** Initially thinking of very basic loops. **Refinement:**  Including more diverse loop types (`for...in`, `for...of`) to better illustrate the scope of the analysis.
* **Thinking about errors:** Focusing only on syntax errors. **Refinement:**  Including more semantic errors like infinite loops and off-by-one errors, which are more directly related to the *behavior* of loops that the compiler tries to understand.

By following these steps of scanning, identifying core components, deconstructing the algorithm, connecting to compiler concepts, and providing relevant examples, we can arrive at a comprehensive understanding of the `v8/src/compiler/loop-analysis.cc` file.这个文件 `v8/src/compiler/loop-analysis.cc` 的主要功能是**分析控制流图 (CFG) 中的循环结构**，并构建一个 **循环树 (LoopTree)** 来表示这些循环及其嵌套关系。这对于后续的编译器优化非常重要，因为很多优化手段（比如循环展开、向量化等）都需要对程序的循环结构有清晰的了解。

具体来说，它的功能可以分解为以下几点：

1. **识别循环头 (Loop Headers):** 识别图中的 `Loop` 节点和与 `Loop` 节点关联的 `Phi` 节点，这些节点共同构成循环的头部。
2. **查找循环体 (Loop Body):**  确定构成循环的节点集合。这通过双向遍历图来实现：
   - **反向传播 (Backward Propagation):** 从图的 `End` 节点开始，沿着边的反方向传播标记，直到到达循环的入口。
   - **正向传播 (Forward Propagation):** 从识别出的循环头开始，沿着边的方向传播标记，并结合反向传播的标记来确定循环内的节点。
3. **处理嵌套循环:**  算法能够正确处理循环的嵌套关系，并构建一个树状结构来表示这种嵌套。
4. **构建循环树 (LoopTree):** 将识别出的循环组织成一个树形结构，其中父节点代表外层循环，子节点代表内层循环。`LoopTree` 存储了每个循环的头节点、体节点、出口节点等信息。
5. **提供接口查询循环信息:**  `LoopTree` 类提供了方法来查询特定节点属于哪个循环，以及循环的结构信息。

**关于 .tq 结尾:**

`v8/src/compiler/loop-analysis.cc` 以 `.cc` 结尾，表示这是一个 **C++ 源代码文件**。如果它以 `.tq` 结尾，那它才是一个 **v8 Torque 源代码文件**。Torque 是 V8 用于定义内置函数的一种领域特定语言。

**与 JavaScript 功能的关系 (并用 JavaScript 举例说明):**

`v8/src/compiler/loop-analysis.cc` 的功能直接关系到 JavaScript 代码中循环的执行效率。V8 的 Turbofan 编译器会分析 JavaScript 代码生成的中间表示 (通常是图结构)，并利用 `loop-analysis.cc` 提供的循环信息进行优化。

例如，考虑以下 JavaScript 代码：

```javascript
function sum(arr) {
  let total = 0;
  for (let i = 0; i < arr.length; i++) {
    total += arr[i];
  }
  return total;
}
```

当 V8 编译这段代码时，`loop-analysis.cc` 会识别出 `for` 循环的结构，包括循环头 (涉及 `i` 的初始化和条件判断)、循环体 (`total += arr[i]`) 和循环出口。有了这些信息，编译器可以应用诸如：

* **循环展开 (Loop Unrolling):**  将循环体复制多次，减少循环控制的开销。
* **循环不变代码外提 (Loop-Invariant Code Motion):**  将循环体内不随循环变化的表达式计算移到循环外部。
* **向量化 (Vectorization):** 如果循环可以并行执行，则利用 SIMD 指令加速计算。

**代码逻辑推理 (假设输入与输出):**

假设我们有一个简单的控制流图，表示以下 JavaScript 代码片段：

```javascript
let i = 0;
while (i < 10) {
  i++;
}
```

**假设输入 (简化的 CFG 节点):**

* `Start`
* `Let i = 0`
* `Loop Header` (包含 `i < 10` 的判断)
* `i++`
* `Back Edge` (从 `i++` 返回到 `Loop Header`)
* `Loop Exit` (当 `i >= 10`)
* `End`

**输出 (简化的 LoopTree):**

```
LoopTree:
  Loop 0:  // 代表整个函数
    Loop 1:  // 代表 while 循环
      Header Nodes: [Loop Header 的节点]
      Body Nodes: [i++ 的节点]
      Exit Nodes: [Loop Exit 的节点]
```

`LoopTree` 会包含一个表示 `while` 循环的 `Loop` 对象，并记录了构成该循环的各个节点。

**涉及用户常见的编程错误 (举例说明):**

`loop-analysis.cc` 本身不直接处理用户的编程错误，但它的分析结果会影响编译器如何处理这些错误。一些常见的与循环相关的编程错误，编译器可能会尝试优化，但如果错误过于严重，可能会导致性能下降或程序行为异常：

1. **无限循环 (Infinite Loops):**

   ```javascript
   while (true) {
     // ...
   }
   ```

   `loop-analysis.cc` 可以识别出这种结构，但编译器通常不会对其进行过度优化，因为程序永远无法退出循环。在某些情况下，V8 可能会采取措施来防止脚本挂起。

2. **空循环 (Empty Loops) 但有副作用:**

   ```javascript
   for (let i = 0; i < 10; i++, console.log(i));
   ```

   虽然循环体是空的，但循环条件和副作用仍然需要执行。`loop-analysis.cc` 会识别出循环结构，编译器会根据具体情况进行优化，例如，可能会将 `console.log(i)` 的调用放在循环内部或外部，具体取决于优化策略。

3. **循环条件错误导致非预期行为:**

   ```javascript
   for (let i = 10; i > 0; i++); // 注意分号
   console.log("Loop finished!"); // 这部分代码会被执行
   ```

   由于分号，循环体为空。`loop-analysis.cc` 会正确分析循环结构，但用户的逻辑错误导致循环没有执行任何有意义的操作。编译器可能会对空循环进行优化，但无法修复用户代码的逻辑错误。

总而言之，`v8/src/compiler/loop-analysis.cc` 是 V8 编译器中一个至关重要的组件，它负责理解代码中的循环结构，为后续的各种优化奠定基础，从而提升 JavaScript 代码的执行效率。它不直接处理用户的编程错误，但其分析结果会影响编译器如何处理和优化包含这些错误的代码。

Prompt: 
```
这是目录为v8/src/compiler/loop-analysis.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/loop-analysis.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/loop-analysis.h"

#include "src/codegen/tick-counter.h"
#include "src/compiler/all-nodes.h"
#include "src/compiler/common-operator.h"
#include "src/compiler/node-marker.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/node.h"
#include "src/compiler/turbofan-graph.h"
#include "src/zone/zone.h"

namespace v8 {
namespace internal {

class TickCounter;

namespace compiler {

#define OFFSET(x) ((x)&0x1F)
#define BIT(x) (1u << OFFSET(x))
#define INDEX(x) ((x) >> 5)

// Temporary information for each node during marking.
struct NodeInfo {
  Node* node;
  NodeInfo* next;  // link in chaining loop members
  bool backwards_visited;
};


// Temporary loop info needed during traversal and building the loop tree.
struct TempLoopInfo {
  Node* header;
  NodeInfo* header_list;
  NodeInfo* exit_list;
  NodeInfo* body_list;
  LoopTree::Loop* loop;
};

// Encapsulation of the loop finding algorithm.
// -----------------------------------------------------------------------------
// Conceptually, the contents of a loop are those nodes that are "between" the
// loop header and the backedges of the loop. Graphs in the soup of nodes can
// form improper cycles, so standard loop finding algorithms that work on CFGs
// aren't sufficient. However, in valid TurboFan graphs, all cycles involve
// either a {Loop} node or a phi. The {Loop} node itself and its accompanying
// phis are treated together as a set referred to here as the loop header.
// This loop finding algorithm works by traversing the graph in two directions,
// first from nodes to their inputs, starting at {end}, then in the reverse
// direction, from nodes to their uses, starting at loop headers.
// 1 bit per loop per node per direction are required during the marking phase.
// To handle nested loops correctly, the algorithm must filter some reachability
// marks on edges into/out-of the loop header nodes.
// Note: this algorithm assumes there are no unreachable loop header nodes
// (including loop phis).
class LoopFinderImpl {
 public:
  LoopFinderImpl(Graph* graph, LoopTree* loop_tree, TickCounter* tick_counter,
                 Zone* zone)
      : zone_(zone),
        end_(graph->end()),
        queue_(zone),
        queued_(graph, 2),
        info_(graph->NodeCount(), {nullptr, nullptr, false}, zone),
        loops_(zone),
        loop_num_(graph->NodeCount(), -1, zone),
        loop_tree_(loop_tree),
        loops_found_(0),
        width_(0),
        backward_(nullptr),
        forward_(nullptr),
        tick_counter_(tick_counter) {}

  void Run() {
    PropagateBackward();
    PropagateForward();
    FinishLoopTree();
  }

  void Print() {
    // Print out the results.
    for (NodeInfo& ni : info_) {
      if (ni.node == nullptr) continue;
      for (int i = 1; i <= loops_found_; i++) {
        int index = ni.node->id() * width_ + INDEX(i);
        bool marked_forward = forward_[index] & BIT(i);
        bool marked_backward = backward_[index] & BIT(i);
        if (marked_forward && marked_backward) {
          PrintF("X");
        } else if (marked_forward) {
          PrintF(">");
        } else if (marked_backward) {
          PrintF("<");
        } else {
          PrintF(" ");
        }
      }
      PrintF(" #%d:%s\n", ni.node->id(), ni.node->op()->mnemonic());
    }

    int i = 0;
    for (TempLoopInfo& li : loops_) {
      PrintF("Loop %d headed at #%d\n", i, li.header->id());
      i++;
    }

    for (LoopTree::Loop* loop : loop_tree_->outer_loops_) {
      PrintLoop(loop);
    }
  }

 private:
  Zone* zone_;
  Node* end_;
  NodeDeque queue_;
  NodeMarker<bool> queued_;
  ZoneVector<NodeInfo> info_;
  ZoneVector<TempLoopInfo> loops_;
  ZoneVector<int> loop_num_;
  LoopTree* loop_tree_;
  int loops_found_;
  int width_;
  uint32_t* backward_;
  uint32_t* forward_;
  TickCounter* const tick_counter_;

  int num_nodes() {
    return static_cast<int>(loop_tree_->node_to_loop_num_.size());
  }

  // Tb = Tb | (Fb - loop_filter)
  bool PropagateBackwardMarks(Node* from, Node* to, int loop_filter) {
    if (from == to) return false;
    uint32_t* fp = &backward_[from->id() * width_];
    uint32_t* tp = &backward_[to->id() * width_];
    bool change = false;
    for (int i = 0; i < width_; i++) {
      uint32_t mask = i == INDEX(loop_filter) ? ~BIT(loop_filter) : 0xFFFFFFFF;
      uint32_t prev = tp[i];
      uint32_t next = prev | (fp[i] & mask);
      tp[i] = next;
      if (!change && (prev != next)) change = true;
    }
    return change;
  }

  // Tb = Tb | B
  bool SetBackwardMark(Node* to, int loop_num) {
    uint32_t* tp = &backward_[to->id() * width_ + INDEX(loop_num)];
    uint32_t prev = tp[0];
    uint32_t next = prev | BIT(loop_num);
    tp[0] = next;
    return next != prev;
  }

  // Tf = Tf | B
  bool SetForwardMark(Node* to, int loop_num) {
    uint32_t* tp = &forward_[to->id() * width_ + INDEX(loop_num)];
    uint32_t prev = tp[0];
    uint32_t next = prev | BIT(loop_num);
    tp[0] = next;
    return next != prev;
  }

  // Tf = Tf | (Ff & Tb)
  bool PropagateForwardMarks(Node* from, Node* to) {
    if (from == to) return false;
    bool change = false;
    int findex = from->id() * width_;
    int tindex = to->id() * width_;
    for (int i = 0; i < width_; i++) {
      uint32_t marks = backward_[tindex + i] & forward_[findex + i];
      uint32_t prev = forward_[tindex + i];
      uint32_t next = prev | marks;
      forward_[tindex + i] = next;
      if (!change && (prev != next)) change = true;
    }
    return change;
  }

  bool IsInLoop(Node* node, int loop_num) {
    int offset = node->id() * width_ + INDEX(loop_num);
    return backward_[offset] & forward_[offset] & BIT(loop_num);
  }

  // Propagate marks backward from loop headers.
  void PropagateBackward() {
    ResizeBackwardMarks();
    SetBackwardMark(end_, 0);
    Queue(end_);

    while (!queue_.empty()) {
      tick_counter_->TickAndMaybeEnterSafepoint();
      Node* node = queue_.front();
      info(node).backwards_visited = true;
      queue_.pop_front();
      queued_.Set(node, false);

      int loop_num = -1;
      // Setup loop headers first.
      if (node->opcode() == IrOpcode::kLoop) {
        // found the loop node first.
        loop_num = CreateLoopInfo(node);
      } else if (NodeProperties::IsPhi(node)) {
        // found a phi first.
        Node* merge = node->InputAt(node->InputCount() - 1);
        if (merge->opcode() == IrOpcode::kLoop) {
          loop_num = CreateLoopInfo(merge);
        }
      } else if (node->opcode() == IrOpcode::kLoopExit) {
        // Intentionally ignore return value. Loop exit node marks
        // are propagated normally.
        CreateLoopInfo(node->InputAt(1));
      } else if (node->opcode() == IrOpcode::kLoopExitValue ||
                 node->opcode() == IrOpcode::kLoopExitEffect) {
        Node* loop_exit = NodeProperties::GetControlInput(node);
        // Intentionally ignore return value. Loop exit node marks
        // are propagated normally.
        CreateLoopInfo(loop_exit->InputAt(1));
      }

      // Propagate marks backwards from this node.
      for (int i = 0; i < node->InputCount(); i++) {
        Node* input = node->InputAt(i);
        if (IsBackedge(node, i)) {
          // Only propagate the loop mark on backedges.
          if (SetBackwardMark(input, loop_num) ||
              !info(input).backwards_visited) {
            Queue(input);
          }
        } else {
          // Entry or normal edge. Propagate all marks except loop_num.
          // TODO(manoskouk): Add test that needs backwards_visited to function
          // correctly, probably using wasm loop unrolling when it is available.
          if (PropagateBackwardMarks(node, input, loop_num) ||
              !info(input).backwards_visited) {
            Queue(input);
          }
        }
      }
    }
  }

  // Make a new loop if necessary for the given node.
  int CreateLoopInfo(Node* node) {
    DCHECK_EQ(IrOpcode::kLoop, node->opcode());
    int loop_num = LoopNum(node);
    if (loop_num > 0) return loop_num;

    loop_num = ++loops_found_;
    if (INDEX(loop_num) >= width_) ResizeBackwardMarks();

    // Create a new loop.
    loops_.push_back({node, nullptr, nullptr, nullptr, nullptr});
    loop_tree_->NewLoop();
    SetLoopMarkForLoopHeader(node, loop_num);
    return loop_num;
  }

  void SetLoopMark(Node* node, int loop_num) {
    info(node);  // create the NodeInfo
    SetBackwardMark(node, loop_num);
    loop_tree_->node_to_loop_num_[node->id()] = loop_num;
  }

  void SetLoopMarkForLoopHeader(Node* node, int loop_num) {
    DCHECK_EQ(IrOpcode::kLoop, node->opcode());
    SetLoopMark(node, loop_num);
    for (Node* use : node->uses()) {
      if (NodeProperties::IsPhi(use)) {
        SetLoopMark(use, loop_num);
      }

      // Do not keep the loop alive if it does not have any backedges.
      if (node->InputCount() <= 1) continue;

      if (use->opcode() == IrOpcode::kLoopExit) {
        SetLoopMark(use, loop_num);
        for (Node* exit_use : use->uses()) {
          if (exit_use->opcode() == IrOpcode::kLoopExitValue ||
              exit_use->opcode() == IrOpcode::kLoopExitEffect) {
            SetLoopMark(exit_use, loop_num);
          }
        }
      }
    }
  }

  void ResizeBackwardMarks() {
    int new_width = width_ + 1;
    int max = num_nodes();
    uint32_t* new_backward = zone_->AllocateArray<uint32_t>(new_width * max);
    memset(new_backward, 0, new_width * max * sizeof(uint32_t));
    if (width_ > 0) {  // copy old matrix data.
      for (int i = 0; i < max; i++) {
        uint32_t* np = &new_backward[i * new_width];
        uint32_t* op = &backward_[i * width_];
        for (int j = 0; j < width_; j++) np[j] = op[j];
      }
    }
    width_ = new_width;
    backward_ = new_backward;
  }

  void ResizeForwardMarks() {
    int max = num_nodes();
    forward_ = zone_->AllocateArray<uint32_t>(width_ * max);
    memset(forward_, 0, width_ * max * sizeof(uint32_t));
  }

  // Propagate marks forward from loops.
  void PropagateForward() {
    ResizeForwardMarks();
    for (TempLoopInfo& li : loops_) {
      SetForwardMark(li.header, LoopNum(li.header));
      Queue(li.header);
    }
    // Propagate forward on paths that were backward reachable from backedges.
    while (!queue_.empty()) {
      tick_counter_->TickAndMaybeEnterSafepoint();
      Node* node = queue_.front();
      queue_.pop_front();
      queued_.Set(node, false);
      for (Edge edge : node->use_edges()) {
        Node* use = edge.from();
        if (!IsBackedge(use, edge.index())) {
          if (PropagateForwardMarks(node, use)) Queue(use);
        }
      }
    }
  }

  bool IsLoopHeaderNode(Node* node) {
    return node->opcode() == IrOpcode::kLoop || NodeProperties::IsPhi(node);
  }

  bool IsLoopExitNode(Node* node) {
    return node->opcode() == IrOpcode::kLoopExit ||
           node->opcode() == IrOpcode::kLoopExitValue ||
           node->opcode() == IrOpcode::kLoopExitEffect;
  }

  bool IsBackedge(Node* use, int index) {
    if (LoopNum(use) <= 0) return false;
    if (NodeProperties::IsPhi(use)) {
      return index != NodeProperties::FirstControlIndex(use) &&
             index != kAssumedLoopEntryIndex;
    } else if (use->opcode() == IrOpcode::kLoop) {
      return index != kAssumedLoopEntryIndex;
    }
    DCHECK(IsLoopExitNode(use));
    return false;
  }

  int LoopNum(Node* node) { return loop_tree_->node_to_loop_num_[node->id()]; }

  NodeInfo& info(Node* node) {
    NodeInfo& i = info_[node->id()];
    if (i.node == nullptr) i.node = node;
    return i;
  }

  void Queue(Node* node) {
    if (!queued_.Get(node)) {
      queue_.push_back(node);
      queued_.Set(node, true);
    }
  }

  void AddNodeToLoop(NodeInfo* node_info, TempLoopInfo* loop, int loop_num) {
    if (LoopNum(node_info->node) == loop_num) {
      if (IsLoopHeaderNode(node_info->node)) {
        node_info->next = loop->header_list;
        loop->header_list = node_info;
      } else {
        DCHECK(IsLoopExitNode(node_info->node));
        node_info->next = loop->exit_list;
        loop->exit_list = node_info;
      }
    } else {
      node_info->next = loop->body_list;
      loop->body_list = node_info;
    }
  }

  void FinishLoopTree() {
    DCHECK(loops_found_ == static_cast<int>(loops_.size()));
    DCHECK(loops_found_ == static_cast<int>(loop_tree_->all_loops_.size()));

    // Degenerate cases.
    if (loops_found_ == 0) return;
    if (loops_found_ == 1) return FinishSingleLoop();

    for (int i = 1; i <= loops_found_; i++) ConnectLoopTree(i);

    size_t count = 0;
    // Place the node into the innermost nested loop of which it is a member.
    for (NodeInfo& ni : info_) {
      if (ni.node == nullptr) continue;

      TempLoopInfo* innermost = nullptr;
      int innermost_index = 0;
      int pos = ni.node->id() * width_;
      // Search the marks word by word.
      for (int i = 0; i < width_; i++) {
        uint32_t marks = backward_[pos + i] & forward_[pos + i];

        for (int j = 0; j < 32; j++) {
          if (marks & (1u << j)) {
            int loop_num = i * 32 + j;
            if (loop_num == 0) continue;
            TempLoopInfo* loop = &loops_[loop_num - 1];
            if (innermost == nullptr ||
                loop->loop->depth_ > innermost->loop->depth_) {
              innermost = loop;
              innermost_index = loop_num;
            }
          }
        }
      }
      if (innermost == nullptr) continue;

      // Return statements should never be found by forward or backward walk.
      CHECK(ni.node->opcode() != IrOpcode::kReturn);

      AddNodeToLoop(&ni, innermost, innermost_index);
      count++;
    }

    // Serialize the node lists for loops into the loop tree.
    loop_tree_->loop_nodes_.reserve(count);
    for (LoopTree::Loop* loop : loop_tree_->outer_loops_) {
      SerializeLoop(loop);
    }
  }

  // Handle the simpler case of a single loop (no checks for nesting necessary).
  void FinishSingleLoop() {
    // Place nodes into the loop header and body.
    TempLoopInfo* li = &loops_[0];
    li->loop = &loop_tree_->all_loops_[0];
    loop_tree_->SetParent(nullptr, li->loop);
    size_t count = 0;
    for (NodeInfo& ni : info_) {
      if (ni.node == nullptr || !IsInLoop(ni.node, 1)) continue;

      // Return statements should never be found by forward or backward walk.
      CHECK(ni.node->opcode() != IrOpcode::kReturn);

      AddNodeToLoop(&ni, li, 1);
      count++;
    }

    // Serialize the node lists for the loop into the loop tree.
    loop_tree_->loop_nodes_.reserve(count);
    SerializeLoop(li->loop);
  }

  // Recursively serialize the list of header nodes and body nodes
  // so that nested loops occupy nested intervals.
  void SerializeLoop(LoopTree::Loop* loop) {
    int loop_num = loop_tree_->LoopNum(loop);
    TempLoopInfo& li = loops_[loop_num - 1];

    // Serialize the header.
    loop->header_start_ = static_cast<int>(loop_tree_->loop_nodes_.size());
    for (NodeInfo* ni = li.header_list; ni != nullptr; ni = ni->next) {
      loop_tree_->loop_nodes_.push_back(ni->node);
      loop_tree_->node_to_loop_num_[ni->node->id()] = loop_num;
    }

    // Serialize the body.
    loop->body_start_ = static_cast<int>(loop_tree_->loop_nodes_.size());
    for (NodeInfo* ni = li.body_list; ni != nullptr; ni = ni->next) {
      loop_tree_->loop_nodes_.push_back(ni->node);
      loop_tree_->node_to_loop_num_[ni->node->id()] = loop_num;
    }

    // Serialize nested loops.
    for (LoopTree::Loop* child : loop->children_) SerializeLoop(child);

    // Serialize the exits.
    loop->exits_start_ = static_cast<int>(loop_tree_->loop_nodes_.size());
    for (NodeInfo* ni = li.exit_list; ni != nullptr; ni = ni->next) {
      loop_tree_->loop_nodes_.push_back(ni->node);
      loop_tree_->node_to_loop_num_[ni->node->id()] = loop_num;
    }

    loop->exits_end_ = static_cast<int>(loop_tree_->loop_nodes_.size());
  }

  // Connect the LoopTree loops to their parents recursively.
  LoopTree::Loop* ConnectLoopTree(int loop_num) {
    TempLoopInfo& li = loops_[loop_num - 1];
    if (li.loop != nullptr) return li.loop;

    NodeInfo& ni = info(li.header);
    LoopTree::Loop* parent = nullptr;
    for (int i = 1; i <= loops_found_; i++) {
      if (i == loop_num) continue;
      if (IsInLoop(ni.node, i)) {
        // recursively create potential parent loops first.
        LoopTree::Loop* upper = ConnectLoopTree(i);
        if (parent == nullptr || upper->depth_ > parent->depth_) {
          parent = upper;
        }
      }
    }
    li.loop = &loop_tree_->all_loops_[loop_num - 1];
    loop_tree_->SetParent(parent, li.loop);
    return li.loop;
  }

  void PrintLoop(LoopTree::Loop* loop) {
    for (int i = 0; i < loop->depth_; i++) PrintF("  ");
    PrintF("Loop depth = %d ", loop->depth_);
    int i = loop->header_start_;
    while (i < loop->body_start_) {
      PrintF(" H#%d", loop_tree_->loop_nodes_[i++]->id());
    }
    while (i < loop->exits_start_) {
      PrintF(" B#%d", loop_tree_->loop_nodes_[i++]->id());
    }
    while (i < loop->exits_end_) {
      PrintF(" E#%d", loop_tree_->loop_nodes_[i++]->id());
    }
    PrintF("\n");
    for (LoopTree::Loop* child : loop->children_) PrintLoop(child);
  }
};

LoopTree* LoopFinder::BuildLoopTree(Graph* graph, TickCounter* tick_counter,
                                    Zone* zone) {
  LoopTree* loop_tree =
      graph->zone()->New<LoopTree>(graph->NodeCount(), graph->zone());
  LoopFinderImpl finder(graph, loop_tree, tick_counter, zone);
  finder.Run();
  if (v8_flags.trace_turbo_loop) {
    finder.Print();
  }
  return loop_tree;
}

#if V8_ENABLE_WEBASSEMBLY
// static
ZoneUnorderedSet<Node*>* LoopFinder::FindSmallInnermostLoopFromHeader(
    Node* loop_header, AllNodes& all_nodes, Zone* zone, size_t max_size,
    Purpose purpose) {
  auto* visited = zone->New<ZoneUnorderedSet<Node*>>(zone);
  std::vector<Node*> queue;

  DCHECK_EQ(loop_header->opcode(), IrOpcode::kLoop);

  queue.push_back(loop_header);
  visited->insert(loop_header);

#define ENQUEUE_USES(use_name, condition)             \
  for (Node * use_name : node->uses()) {              \
    if (condition && visited->count(use_name) == 0) { \
      visited->insert(use_name);                      \
      queue.push_back(use_name);                      \
    }                                                 \
  }
  bool has_instruction_worth_peeling = false;
  while (!queue.empty()) {
    Node* node = queue.back();
    queue.pop_back();
    if (node->opcode() == IrOpcode::kEnd) {
      // We reached the end of the graph. The end node is not part of the loop.
      visited->erase(node);
      continue;
    }
    if (visited->size() > max_size) return nullptr;
    switch (node->opcode()) {
      case IrOpcode::kLoop:
        // Found nested loop.
        if (node != loop_header) return nullptr;
        ENQUEUE_USES(use, true);
        break;
      case IrOpcode::kLoopExit:
        // Found nested loop.
        if (node->InputAt(1) != loop_header) return nullptr;
        // LoopExitValue/Effect uses are inside the loop. The rest are not.
        ENQUEUE_USES(use, (use->opcode() == IrOpcode::kLoopExitEffect ||
                           use->opcode() == IrOpcode::kLoopExitValue))
        break;
      case IrOpcode::kLoopExitEffect:
      case IrOpcode::kLoopExitValue:
        if (NodeProperties::GetControlInput(node)->InputAt(1) != loop_header) {
          // Found nested loop.
          return nullptr;
        }
        // All uses are outside the loop, do nothing.
        break;
      // If unrolling, call nodes are considered to have unbounded size,
      // i.e. >max_size, with the exception of certain wasm builtins.
      case IrOpcode::kTailCall:
      case IrOpcode::kJSWasmCall:
      case IrOpcode::kJSCall:
        if (purpose == Purpose::kLoopUnrolling) return nullptr;
        ENQUEUE_USES(use, true)
        break;
      case IrOpcode::kCall: {
        if (purpose == Purpose::kLoopPeeling) {
          ENQUEUE_USES(use, true);
          break;
        }
        Node* callee = node->InputAt(0);
        if (callee->opcode() != IrOpcode::kRelocatableInt32Constant &&
            callee->opcode() != IrOpcode::kRelocatableInt64Constant) {
          return nullptr;
        }
        Builtin builtin = static_cast<Builtin>(
            OpParameter<RelocatablePtrConstantInfo>(callee->op()).value());
        constexpr Builtin unrollable_builtins[] = {
            // Exists in every stack check.
            Builtin::kWasmStackGuard,
            // Fast table operations.
            Builtin::kWasmTableGet, Builtin::kWasmTableSet,
            Builtin::kWasmTableGetFuncRef, Builtin::kWasmTableSetFuncRef,
            Builtin::kWasmTableGrow,
            // Atomics.
            Builtin::kWasmI32AtomicWait, Builtin::kWasmI64AtomicWait,
            // Exceptions.
            Builtin::kWasmAllocateFixedArray, Builtin::kWasmThrow,
            Builtin::kWasmRethrow, Builtin::kWasmRethrowExplicitContext,
            // Fast wasm-gc operations.
            Builtin::kWasmRefFunc,
            // While a built-in call, this is the slow path, so it should not
            // prevent loop unrolling for stringview_wtf16.get_codeunit.
            Builtin::kWasmStringViewWtf16GetCodeUnit};
        if (std::count(std::begin(unrollable_builtins),
                       std::end(unrollable_builtins), builtin) == 0) {
          return nullptr;
        }
        ENQUEUE_USES(use, true)
        break;
      }
      case IrOpcode::kWasmStructGet: {
        // When a chained load occurs in the loop, assume that peeling might
        // help.
        Node* object = node->InputAt(0);
        if (object->opcode() == IrOpcode::kWasmStructGet &&
            visited->find(object) != visited->end()) {
          has_instruction_worth_peeling = true;
        }
        ENQUEUE_USES(use, true);
        break;
      }
      case IrOpcode::kWasmArrayGet:
        // Rationale for array.get: loops that contain an array.get also
        // contain a bounds check, which needs to load the array's length,
        // which benefits from load elimination after peeling.
      case IrOpcode::kStringPrepareForGetCodeunit:
        // Rationale for PrepareForGetCodeunit: this internal operation is
        // specifically designed for being hoisted out of loops.
        has_instruction_worth_peeling = true;
        [[fallthrough]];
      default:
        ENQUEUE_USES(use, true)
        break;
    }
  }

  // Check that there is no floating control other than direct nodes to start().
  // We do this by checking that all non-start control inputs of loop nodes are
  // also in the loop.
  // TODO(manoskouk): This is a safety check. Consider making it DEBUG-only when
  // we are confident there is no incompatible floating control generated in
  // wasm.
  for (Node* node : *visited) {
    // The loop header is allowed to point outside the loop.
    if (node == loop_header) continue;

    if (!all_nodes.IsLive(node)) continue;

    for (Edge edge : node->input_edges()) {
      Node* input = edge.to();
      if (NodeProperties::IsControlEdge(edge) && visited->count(input) == 0 &&
          input->opcode() != IrOpcode::kStart) {
        FATAL(
            "Floating control detected in wasm turbofan graph: Node #%d:%s is "
            "inside loop headed by #%d, but its control dependency #%d:%s is "
            "outside",
            node->id(), node->op()->mnemonic(), loop_header->id(), input->id(),
            input->op()->mnemonic());
      }
    }
  }

  // Only peel functions containing instructions for which loop peeling is known
  // to be useful. TODO(14034): Add more instructions to get more benefits out
  // of loop peeling.
  if (purpose == Purpose::kLoopPeeling && !has_instruction_worth_peeling) {
    return nullptr;
  }
  return visited;
}
#endif  // V8_ENABLE_WEBASSEMBLY

bool LoopFinder::HasMarkedExits(LoopTree* loop_tree,
                                const LoopTree::Loop* loop) {
  // Look for returns and if projections that are outside the loop but whose
  // control input is inside the loop.
  Node* loop_node = loop_tree->GetLoopControl(loop);
  for (Node* node : loop_tree->LoopNodes(loop)) {
    for (Node* use : node->uses()) {
      if (!loop_tree->Contains(loop, use)) {
        bool unmarked_exit;
        switch (node->opcode()) {
          case IrOpcode::kLoopExit:
            unmarked_exit = (node->InputAt(1) != loop_node);
            break;
          case IrOpcode::kLoopExitValue:
          case IrOpcode::kLoopExitEffect:
            unmarked_exit = (node->InputAt(1)->InputAt(1) != loop_node);
            break;
          default:
            unmarked_exit = (use->opcode() != IrOpcode::kTerminate);
        }
        if (unmarked_exit) {
          if (v8_flags.trace_turbo_loop) {
            PrintF(
                "Cannot peel loop %i. Loop exit without explicit mark: Node %i "
                "(%s) is inside loop, but its use %i (%s) is outside.\n",
                loop_node->id(), node->id(), node->op()->mnemonic(), use->id(),
                use->op()->mnemonic());
          }
          return false;
        }
      }
    }
  }
  return true;
}

Node* LoopTree::HeaderNode(const Loop* loop) {
  Node* first = *HeaderNodes(loop).begin();
  if (first->opcode() == IrOpcode::kLoop) return first;
  DCHECK(IrOpcode::IsPhiOpcode(first->opcode()));
  Node* header = NodeProperties::GetControlInput(first);
  DCHECK_EQ(IrOpcode::kLoop, header->opcode());
  return header;
}

Node* NodeCopier::map(Node* node, uint32_t copy_index) {
  DCHECK_LT(copy_index, copy_count_);
  if (node_map_.Get(node) == 0) return node;
  return copies_->at(node_map_.Get(node) + copy_index);
}

void NodeCopier::Insert(Node* original, const NodeVector& new_copies) {
  DCHECK_EQ(new_copies.size(), copy_count_);
  node_map_.Set(original, copies_->size() + 1);
  copies_->push_back(original);
  copies_->insert(copies_->end(), new_copies.begin(), new_copies.end());
}

void NodeCopier::Insert(Node* original, Node* copy) {
  DCHECK_EQ(copy_count_, 1);
  node_map_.Set(original, copies_->size() + 1);
  copies_->push_back(original);
  copies_->push_back(copy);
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""

```