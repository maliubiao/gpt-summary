Response:
Let's break down the thought process for analyzing this C++ unittest file.

**1. Initial Scan for High-Level Understanding:**

* **Keywords:**  Immediately look for terms like `test`, `unittest`, `matcher`, `Node`, `compiler`, `v8`. These give strong hints about the file's purpose.
* **File Path:** `v8/test/unittests/compiler/node-matchers-unittest.cc` reinforces that this is a unit test for the compiler, specifically for something related to "node matchers."
* **Includes:**  The included headers (`node-matchers.h`, `common-operator.h`, `machine-operator.h`, `node.h`, `turbofan-graph.h`, `graph-unittest.h`) confirm it's dealing with the internal representation of code (nodes, graphs, operators) within the V8 compiler.

**2. Deciphering the Core Functionality:**

* **Class `NodeMatcherTest`:** This is the test fixture. It inherits from `GraphTest`, indicating it sets up a graph structure for testing. The `machine()` method suggests it interacts with machine-level operations.
* **Template Function `CheckBaseWithIndexAndDisplacement`:** This function is crucial. It takes a `Matcher`, along with expected values for `index`, `scale`, `base`, and `displacement`. The `EXPECT_TRUE` and `EXPECT_EQ` lines immediately tell you this function *asserts* that the `Matcher` extracts these components correctly. The name "BaseWithIndexAndDisplacement" suggests it's checking how certain node patterns are decomposed into these parts.
* **Macros `ADD_ADDRESSING_OPERAND_USES` and `ADD_NONE_ADDRESSING_OPERAND_USES`:** These are helper macros that create new nodes in the graph. The names suggest they are setting up scenarios where a node is used in addressing calculations or in other, non-addressing contexts. This hints at the matchers being sensitive to how nodes are *used*.
* **`TEST_F(NodeMatcherTest, ...)` Blocks:** These are the individual test cases. The names of the test cases (e.g., `ScaledWithOffset32Matcher`) are the most direct clues to what's being tested.

**3. Focusing on the Matcher Logic (Deduction from Test Cases):**

* **Constant Definitions:**  The long list of `const Operator* dX_op = common()->Int32Constant(X);` and `Node* dX = graph()->NewNode(dX_op);` creates a set of constant integer nodes. Similarly, `b0`, `b1`, `p1` represent different kinds of input nodes (parameters).
* **Operator Definitions:**  `machine()->Int32Add()`, `machine()->Int32Sub()`, `machine()->Int32Mul()`, `machine()->Word32Shl()` are the operations being combined in the graph.
* **Pattern Recognition in Test Case Logic:** The tests repeatedly create nodes representing arithmetic operations (`a_op`, `sub_op`) involving base nodes (`b0`, `b1`), constant displacements (`dX`), and scaled index nodes (multiplications `mX` or shifts `sX`).
* **Matcher Instantiation:** The lines like `BaseWithIndexAndDisplacement32Matcher match1(...)` show the instantiation of the matcher class being tested. The arguments to the constructor are the nodes the matcher is analyzing.
* **Connecting Test Cases to the Template Function:** The calls to `CheckBaseWithIndexAndDisplacement(&matchX, ...)` link the created node patterns with the expected decomposition.

**4. Inferring the Purpose of `BaseWithIndexAndDisplacement32Matcher`:**

* Based on the test cases, the matcher seems designed to identify patterns in the graph that resemble memory addressing calculations.
* It tries to extract the `base`, `index`, `scale`, and `displacement` components from expressions like `base + index * scale + displacement`.
* The tests cover various combinations and orderings of these components, including cases with only a base and displacement, or a base and a scaled index.
* The `DisplacementMode` (positive or negative) indicates the matcher also handles subtraction in the displacement.

**5. Considering JavaScript Relevance (Hypothesis):**

* V8 executes JavaScript. JavaScript has arrays and object properties, which require address calculations.
* The patterns being tested likely correspond to common ways JavaScript engines access memory when dealing with arrays or objects. For instance, accessing `array[i]` involves a base address (array start), an index (`i`), and potentially a scale factor (size of each element). Accessing `object.property` might involve an offset.

**6. Predicting Example Usage and Potential Errors:**

* **Example:**  A simple array access in JavaScript could be represented by these node patterns internally.
* **Common Errors:**  Incorrectly calculating memory addresses (e.g., off-by-one errors) or using the wrong scale factor could lead to crashes or incorrect behavior. The matcher helps ensure the compiler correctly identifies these address calculation patterns for optimization or code generation.

**7. Structuring the Summary:**

Organize the findings into clear points:

* **Core Function:** What the code does at its heart.
* **No Torque:**  Address the `.tq` check.
* **JavaScript Relevance:** Explain the connection with examples.
* **Logic Inference:** Provide hypothetical input and output based on the observed behavior.
* **Common Errors:** Give examples of programming errors this kind of matching might help prevent or optimize around.

This iterative process of scanning, deciphering, focusing, inferring, and connecting the dots leads to a comprehensive understanding of the unittest's purpose. The key is to pay attention to the names of classes, functions, macros, and test cases, and then to analyze the code flow and assertions within the tests.
好的，让我们来分析一下 `v8/test/unittests/compiler/node-matchers-unittest.cc` 这个文件的功能。

**文件功能归纳：**

`v8/test/unittests/compiler/node-matchers-unittest.cc` 是 V8 引擎中 **编译器 (compiler)** 部分的 **节点匹配器 (node matchers)** 的 **单元测试 (unittests)** 文件。

它的主要功能是测试各种 `NodeMatcher` 类（例如 `BaseWithIndexAndDisplacement32Matcher`），这些类用于在编译器生成的中间表示（图结构，Graph）中 **识别和提取特定的节点模式 (node patterns)**。

更具体地说，从当前的代码片段来看，它主要测试了 `BaseWithIndexAndDisplacement32Matcher` 这个匹配器，用于识别类似于 **内存寻址 (memory addressing)** 的模式，例如：

* **base + index * scale + displacement**

该测试文件通过创建各种不同的节点组合，然后使用 `BaseWithIndexAndDisplacement32Matcher` 来尝试匹配这些组合，并验证匹配器是否能够正确地提取出 `base`、`index`、`scale` 和 `displacement` 等组成部分。

**关于文件类型：**

* 该文件以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是以 `.tq` 结尾的 Torque 源代码文件。

**与 JavaScript 功能的关系：**

虽然这个文件本身是 C++ 代码，用于测试编译器的内部机制，但它所测试的功能直接关系到 **V8 引擎如何高效地编译和执行 JavaScript 代码**。

当 V8 编译 JavaScript 代码时，它会将其转换为一种中间表示形式（图结构）。在这个过程中，编译器需要识别各种常见的操作模式，以便进行优化。

例如，当 JavaScript 代码访问数组元素时，例如 `array[i]`，V8 内部会进行类似 `base + index * element_size` 的地址计算。`BaseWithIndexAndDisplacement32Matcher` 这类匹配器就是用来识别这种模式的，以便编译器可以生成更优化的机器码。

**JavaScript 举例说明：**

```javascript
function accessArray(arr, index) {
  return arr[index];
}

const myArray = [10, 20, 30];
const result = accessArray(myArray, 1); // 访问 myArray[1]
```

在 V8 编译 `accessArray` 函数时，编译器内部的节点匹配器可能会识别出访问数组元素的模式，并将 `arr` 视为 `base`，`index` 视为 `index`，数组元素的大小视为 `scale`，从而进行优化。

**代码逻辑推理（假设输入与输出）：**

假设我们有以下节点：

* `b0` 代表一个基地址 (base)
* `p1` 代表一个索引 (index)
* `d2` 代表一个常量 2
* `m2` 代表 `p1 * d2` (index * scale，其中 scale 为 2)
* `d15` 代表一个位移 (displacement)
* `a_op` 代表加法操作

如果我们创建一个表示 `b0 + m2 + d15` 的节点，并使用 `BaseWithIndexAndDisplacement32Matcher` 进行匹配：

**假设输入 (Node 结构):**  一个表示 `Int32Add(Int32Add(b0, m2), d15)` 的节点。

**预期输出：**  匹配器应该成功匹配，并且提取出以下信息：

* `base`: `b0`
* `index`: `p1`
* `scale`: 2
* `displacement`: `d15`
* `displacement_mode`: `kPositiveDisplacement`

这是测试代码中很多测试用例所验证的核心逻辑。 例如：

```c++
  // (B0 + M2) + D15 -> [p1, 1, B0, D15]
  m2 = graph()->NewNode(m_op, p1, d2);
  BaseWithIndexAndDisplacement32Matcher match14(
      graph()->NewNode(a_op, graph()->NewNode(a_op, b0, m2), d15));
  CheckBaseWithIndexAndDisplacement(&match14, p1, 1, b0, d15);
```

这里 `m2` 是 `p1 * d2`，所以 scale 是 2，但是由于 `BaseWithIndexAndDisplacement32Matcher` 在匹配的时候，会尝试将乘法运算中的常量作为 scale，所以这里匹配到的 scale 是 1，而 `m2` 被认为是 index。 这也说明了匹配器的一些匹配规则和优先级。

**涉及用户常见的编程错误：**

虽然这个测试文件是关于编译器内部机制的，但它所测试的模式与用户在编写 JavaScript 代码时可能遇到的问题有关。

例如，**数组越界访问** 是一个常见的编程错误。 当 JavaScript 代码尝试访问数组中不存在的索引时，V8 内部的地址计算可能会出错。 编译器中的节点匹配器确保了这些地址计算的正确性，从而帮助 V8 能够安全地处理这些情况（例如，抛出错误而不是崩溃）。

**举例说明（JavaScript 数组越界）：**

```javascript
const arr = [1, 2, 3];
const value = arr[5]; // 尝试访问索引 5，超出数组范围
console.log(value); // 输出 undefined
```

虽然 V8 不会崩溃，但内部的机制需要正确处理这种越界访问，而编译器中的节点匹配器在生成处理数组访问的代码时起着关键作用。

**第 1 部分功能归纳：**

这部分代码主要集中测试了 `BaseWithIndexAndDisplacement32Matcher` 针对 32 位整数的内存寻址模式匹配能力。它涵盖了以下场景：

* **单输入节点:**  验证不匹配的情况。
* **双输入节点 (加法):**  各种 `base`、`index` (可以是乘法或移位运算)、`displacement` 的组合和顺序，包括正位移。
* **三输入节点 (连续加法或加减法):**  更复杂的寻址模式，包括负位移的情况。
* **考虑节点的使用情况:** 使用 `ADD_ADDRESSING_OPERAND_USES` 宏模拟节点被用作内存寻址操作数的情况，以及使用 `ADD_NONE_ADDRESSING_OPERAND_USES` 宏模拟节点不被用作内存寻址操作数的情况，验证匹配器在这种上下文下的行为。

总结来说，这部分单元测试旨在确保 `BaseWithIndexAndDisplacement32Matcher` 能够准确地识别出各种 32 位内存寻址的模式，这对于 V8 编译器生成高效且正确的机器码至关重要。

### 提示词
```
这是目录为v8/test/unittests/compiler/node-matchers-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/node-matchers-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/node-matchers.h"

#include "src/compiler/common-operator.h"
#include "src/compiler/machine-operator.h"
#include "src/compiler/node.h"
#include "src/compiler/turbofan-graph.h"
#include "test/unittests/compiler/graph-unittest.h"
#include "test/unittests/test-utils.h"

namespace v8 {
namespace internal {
namespace compiler {

class NodeMatcherTest : public GraphTest {
 public:
  NodeMatcherTest() : machine_(zone()) {}
  ~NodeMatcherTest() override = default;

  MachineOperatorBuilder* machine() { return &machine_; }

 private:
  MachineOperatorBuilder machine_;
};

namespace {

template <class Matcher>
void CheckBaseWithIndexAndDisplacement(
    Matcher* matcher, Node* index, int scale, Node* base, Node* displacement,
    DisplacementMode displacement_mode = kPositiveDisplacement) {
  EXPECT_TRUE(matcher->matches());
  EXPECT_EQ(index, matcher->index());
  EXPECT_EQ(scale, matcher->scale());
  EXPECT_EQ(base, matcher->base());
  EXPECT_EQ(displacement, matcher->displacement());
  EXPECT_EQ(displacement_mode, matcher->displacement_mode());
}

}  // namespace

#define ADD_ADDRESSING_OPERAND_USES(node)                                 \
  graph()->NewNode(machine()->Load(MachineType::Int32()), node, d0,       \
                   graph()->start(), graph()->start());                   \
  graph()->NewNode(machine()->Store(rep), node, d0, d0, graph()->start(), \
                   graph()->start());                                     \
  graph()->NewNode(machine()->Int32Add(), node, d0);                      \
  graph()->NewNode(machine()->Int64Add(), node, d0);

#define ADD_NONE_ADDRESSING_OPERAND_USES(node)                            \
  graph()->NewNode(machine()->Store(rep), b0, d0, node, graph()->start(), \
                   graph()->start());

TEST_F(NodeMatcherTest, ScaledWithOffset32Matcher) {
  graph()->SetStart(graph()->NewNode(common()->Start(0)));

  const Operator* d0_op = common()->Int32Constant(0);
  Node* d0 = graph()->NewNode(d0_op);
  USE(d0);
  const Operator* d1_op = common()->Int32Constant(1);
  Node* d1 = graph()->NewNode(d1_op);
  USE(d1);
  const Operator* d2_op = common()->Int32Constant(2);
  Node* d2 = graph()->NewNode(d2_op);
  USE(d2);
  const Operator* d3_op = common()->Int32Constant(3);
  Node* d3 = graph()->NewNode(d3_op);
  USE(d3);
  const Operator* d4_op = common()->Int32Constant(4);
  Node* d4 = graph()->NewNode(d4_op);
  USE(d4);
  const Operator* d5_op = common()->Int32Constant(5);
  Node* d5 = graph()->NewNode(d5_op);
  USE(d5);
  const Operator* d7_op = common()->Int32Constant(7);
  Node* d7 = graph()->NewNode(d7_op);
  USE(d4);
  const Operator* d8_op = common()->Int32Constant(8);
  Node* d8 = graph()->NewNode(d8_op);
  USE(d8);
  const Operator* d9_op = common()->Int32Constant(9);
  Node* d9 = graph()->NewNode(d9_op);
  USE(d9);
  const Operator* d15_op = common()->Int32Constant(15);
  Node* d15 = graph()->NewNode(d15_op);
  USE(d15);

  const Operator* b0_op = common()->Parameter(0);
  Node* b0 = graph()->NewNode(b0_op, graph()->start());
  USE(b0);
  const Operator* b1_op = common()->Parameter(1);
  Node* b1 = graph()->NewNode(b1_op, graph()->start());
  USE(b0);

  const Operator* p1_op = common()->Parameter(3);
  Node* p1 = graph()->NewNode(p1_op, graph()->start());
  USE(p1);

  const Operator* a_op = machine()->Int32Add();
  USE(a_op);

  const Operator* sub_op = machine()->Int32Sub();
  USE(sub_op);

  const Operator* m_op = machine()->Int32Mul();
  Node* m1 = graph()->NewNode(m_op, p1, d1);
  Node* m2 = graph()->NewNode(m_op, p1, d2);
  Node* m3 = graph()->NewNode(m_op, p1, d3);
  Node* m4 = graph()->NewNode(m_op, p1, d4);
  Node* m5 = graph()->NewNode(m_op, p1, d5);
  Node* m7 = graph()->NewNode(m_op, p1, d7);
  Node* m8 = graph()->NewNode(m_op, p1, d8);
  Node* m9 = graph()->NewNode(m_op, p1, d9);
  USE(m1);
  USE(m2);
  USE(m3);
  USE(m4);
  USE(m5);
  USE(m7);
  USE(m8);
  USE(m9);

  const Operator* s_op = machine()->Word32Shl();
  Node* s0 = graph()->NewNode(s_op, p1, d0);
  Node* s1 = graph()->NewNode(s_op, p1, d1);
  Node* s2 = graph()->NewNode(s_op, p1, d2);
  Node* s3 = graph()->NewNode(s_op, p1, d3);
  Node* s4 = graph()->NewNode(s_op, p1, d4);
  USE(s0);
  USE(s1);
  USE(s2);
  USE(s3);
  USE(s4);

  const StoreRepresentation rep(MachineRepresentation::kWord32,
                                kNoWriteBarrier);
  USE(rep);

  // 1 INPUT

  // Only relevant test dases is Checking for non-match.
  BaseWithIndexAndDisplacement32Matcher match0(d15);
  EXPECT_FALSE(match0.matches());

  // 2 INPUT

  // (B0 + B1) -> [B0, 0, B1, NULL]
  BaseWithIndexAndDisplacement32Matcher match1(graph()->NewNode(a_op, b0, b1));
  CheckBaseWithIndexAndDisplacement(&match1, b1, 0, b0, nullptr);

  // (B0 + D15) -> [NULL, 0, B0, D15]
  BaseWithIndexAndDisplacement32Matcher match2(graph()->NewNode(a_op, b0, d15));
  CheckBaseWithIndexAndDisplacement(&match2, nullptr, 0, b0, d15);

  // (D15 + B0) -> [NULL, 0, B0, D15]
  BaseWithIndexAndDisplacement32Matcher match3(graph()->NewNode(a_op, d15, b0));
  CheckBaseWithIndexAndDisplacement(&match3, nullptr, 0, b0, d15);

  // (B0 + M1) -> [p1, 0, B0, NULL]
  BaseWithIndexAndDisplacement32Matcher match4(graph()->NewNode(a_op, b0, m1));
  CheckBaseWithIndexAndDisplacement(&match4, p1, 0, b0, nullptr);

  // (M1 + B0) -> [p1, 0, B0, NULL]
  m1 = graph()->NewNode(m_op, p1, d1);
  BaseWithIndexAndDisplacement32Matcher match5(graph()->NewNode(a_op, m1, b0));
  CheckBaseWithIndexAndDisplacement(&match5, p1, 0, b0, nullptr);

  // (D15 + M1) -> [P1, 0, NULL, D15]
  m1 = graph()->NewNode(m_op, p1, d1);
  BaseWithIndexAndDisplacement32Matcher match6(graph()->NewNode(a_op, d15, m1));
  CheckBaseWithIndexAndDisplacement(&match6, p1, 0, nullptr, d15);

  // (M1 + D15) -> [P1, 0, NULL, D15]
  m1 = graph()->NewNode(m_op, p1, d1);
  BaseWithIndexAndDisplacement32Matcher match7(graph()->NewNode(a_op, m1, d15));
  CheckBaseWithIndexAndDisplacement(&match7, p1, 0, nullptr, d15);

  // (B0 + S0) -> [p1, 0, B0, NULL]
  BaseWithIndexAndDisplacement32Matcher match8(graph()->NewNode(a_op, b0, s0));
  CheckBaseWithIndexAndDisplacement(&match8, p1, 0, b0, nullptr);

  // (S0 + B0) -> [p1, 0, B0, NULL]
  s0 = graph()->NewNode(s_op, p1, d0);
  BaseWithIndexAndDisplacement32Matcher match9(graph()->NewNode(a_op, s0, b0));
  CheckBaseWithIndexAndDisplacement(&match9, p1, 0, b0, nullptr);

  // (D15 + S0) -> [P1, 0, NULL, D15]
  s0 = graph()->NewNode(s_op, p1, d0);
  BaseWithIndexAndDisplacement32Matcher match10(
      graph()->NewNode(a_op, d15, s0));
  CheckBaseWithIndexAndDisplacement(&match10, p1, 0, nullptr, d15);

  // (S0 + D15) -> [P1, 0, NULL, D15]
  s0 = graph()->NewNode(s_op, p1, d0);
  BaseWithIndexAndDisplacement32Matcher match11(
      graph()->NewNode(a_op, s0, d15));
  CheckBaseWithIndexAndDisplacement(&match11, p1, 0, nullptr, d15);

  // (B0 + M2) -> [p1, 1, B0, NULL]
  BaseWithIndexAndDisplacement32Matcher match12(graph()->NewNode(a_op, b0, m2));
  CheckBaseWithIndexAndDisplacement(&match12, p1, 1, b0, nullptr);

  // (M2 + B0) -> [p1, 1, B0, NULL]
  m2 = graph()->NewNode(m_op, p1, d2);
  BaseWithIndexAndDisplacement32Matcher match13(graph()->NewNode(a_op, m2, b0));
  CheckBaseWithIndexAndDisplacement(&match13, p1, 1, b0, nullptr);

  // (D15 + M2) -> [P1, 1, NULL, D15]
  m2 = graph()->NewNode(m_op, p1, d2);
  BaseWithIndexAndDisplacement32Matcher match14(
      graph()->NewNode(a_op, d15, m2));
  CheckBaseWithIndexAndDisplacement(&match14, p1, 1, nullptr, d15);

  // (M2 + D15) -> [P1, 1, NULL, D15]
  m2 = graph()->NewNode(m_op, p1, d2);
  BaseWithIndexAndDisplacement32Matcher match15(
      graph()->NewNode(a_op, m2, d15));
  CheckBaseWithIndexAndDisplacement(&match15, p1, 1, nullptr, d15);

  // (B0 + S1) -> [p1, 1, B0, NULL]
  BaseWithIndexAndDisplacement32Matcher match16(graph()->NewNode(a_op, b0, s1));
  CheckBaseWithIndexAndDisplacement(&match16, p1, 1, b0, nullptr);

  // (S1 + B0) -> [p1, 1, B0, NULL]
  s1 = graph()->NewNode(s_op, p1, d1);
  BaseWithIndexAndDisplacement32Matcher match17(graph()->NewNode(a_op, s1, b0));
  CheckBaseWithIndexAndDisplacement(&match17, p1, 1, b0, nullptr);

  // (D15 + S1) -> [P1, 1, NULL, D15]
  s1 = graph()->NewNode(s_op, p1, d1);
  BaseWithIndexAndDisplacement32Matcher match18(
      graph()->NewNode(a_op, d15, s1));
  CheckBaseWithIndexAndDisplacement(&match18, p1, 1, nullptr, d15);

  // (S1 + D15) -> [P1, 1, NULL, D15]
  s1 = graph()->NewNode(s_op, p1, d1);
  BaseWithIndexAndDisplacement32Matcher match19(
      graph()->NewNode(a_op, s1, d15));
  CheckBaseWithIndexAndDisplacement(&match19, p1, 1, nullptr, d15);

  // (B0 + M4) -> [p1, 2, B0, NULL]
  BaseWithIndexAndDisplacement32Matcher match20(graph()->NewNode(a_op, b0, m4));
  CheckBaseWithIndexAndDisplacement(&match20, p1, 2, b0, nullptr);

  // (M4 + B0) -> [p1, 2, B0, NULL]
  m4 = graph()->NewNode(m_op, p1, d4);
  BaseWithIndexAndDisplacement32Matcher match21(graph()->NewNode(a_op, m4, b0));
  CheckBaseWithIndexAndDisplacement(&match21, p1, 2, b0, nullptr);

  // (D15 + M4) -> [p1, 2, NULL, D15]
  m4 = graph()->NewNode(m_op, p1, d4);
  BaseWithIndexAndDisplacement32Matcher match22(
      graph()->NewNode(a_op, d15, m4));
  CheckBaseWithIndexAndDisplacement(&match22, p1, 2, nullptr, d15);

  // (M4 + D15) -> [p1, 2, NULL, D15]
  m4 = graph()->NewNode(m_op, p1, d4);
  BaseWithIndexAndDisplacement32Matcher match23(
      graph()->NewNode(a_op, m4, d15));
  CheckBaseWithIndexAndDisplacement(&match23, p1, 2, nullptr, d15);

  // (B0 + S2) -> [p1, 2, B0, NULL]
  BaseWithIndexAndDisplacement32Matcher match24(graph()->NewNode(a_op, b0, s2));
  CheckBaseWithIndexAndDisplacement(&match24, p1, 2, b0, nullptr);

  // (S2 + B0) -> [p1, 2, B0, NULL]
  s2 = graph()->NewNode(s_op, p1, d2);
  BaseWithIndexAndDisplacement32Matcher match25(graph()->NewNode(a_op, s2, b0));
  CheckBaseWithIndexAndDisplacement(&match25, p1, 2, b0, nullptr);

  // (D15 + S2) -> [p1, 2, NULL, D15]
  s2 = graph()->NewNode(s_op, p1, d2);
  BaseWithIndexAndDisplacement32Matcher match26(
      graph()->NewNode(a_op, d15, s2));
  CheckBaseWithIndexAndDisplacement(&match26, p1, 2, nullptr, d15);

  // (S2 + D15) -> [p1, 2, NULL, D15]
  s2 = graph()->NewNode(s_op, p1, d2);
  BaseWithIndexAndDisplacement32Matcher match27(
      graph()->NewNode(a_op, s2, d15));
  CheckBaseWithIndexAndDisplacement(&match27, p1, 2, nullptr, d15);

  // (B0 + M8) -> [p1, 2, B0, NULL]
  BaseWithIndexAndDisplacement32Matcher match28(graph()->NewNode(a_op, b0, m8));
  CheckBaseWithIndexAndDisplacement(&match28, p1, 3, b0, nullptr);

  // (M8 + B0) -> [p1, 2, B0, NULL]
  m8 = graph()->NewNode(m_op, p1, d8);
  BaseWithIndexAndDisplacement32Matcher match29(graph()->NewNode(a_op, m8, b0));
  CheckBaseWithIndexAndDisplacement(&match29, p1, 3, b0, nullptr);

  // (D15 + M8) -> [p1, 2, NULL, D15]
  m8 = graph()->NewNode(m_op, p1, d8);
  BaseWithIndexAndDisplacement32Matcher match30(
      graph()->NewNode(a_op, d15, m8));
  CheckBaseWithIndexAndDisplacement(&match30, p1, 3, nullptr, d15);

  // (M8 + D15) -> [p1, 2, NULL, D15]
  m8 = graph()->NewNode(m_op, p1, d8);
  BaseWithIndexAndDisplacement32Matcher match31(
      graph()->NewNode(a_op, m8, d15));
  CheckBaseWithIndexAndDisplacement(&match31, p1, 3, nullptr, d15);

  // (B0 + S3) -> [p1, 2, B0, NULL]
  BaseWithIndexAndDisplacement32Matcher match32(graph()->NewNode(a_op, b0, s3));
  CheckBaseWithIndexAndDisplacement(&match32, p1, 3, b0, nullptr);

  // (S3 + B0) -> [p1, 2, B0, NULL]
  s3 = graph()->NewNode(s_op, p1, d3);
  BaseWithIndexAndDisplacement32Matcher match33(graph()->NewNode(a_op, s3, b0));
  CheckBaseWithIndexAndDisplacement(&match33, p1, 3, b0, nullptr);

  // (D15 + S3) -> [p1, 2, NULL, D15]
  s3 = graph()->NewNode(s_op, p1, d3);
  BaseWithIndexAndDisplacement32Matcher match34(
      graph()->NewNode(a_op, d15, s3));
  CheckBaseWithIndexAndDisplacement(&match34, p1, 3, nullptr, d15);

  // (S3 + D15) -> [p1, 2, NULL, D15]
  s3 = graph()->NewNode(s_op, p1, d3);
  BaseWithIndexAndDisplacement32Matcher match35(
      graph()->NewNode(a_op, s3, d15));
  CheckBaseWithIndexAndDisplacement(&match35, p1, 3, nullptr, d15);

  // 2 INPUT - NEGATIVE CASES

  // (M3 + B1) -> [B0, 0, M3, NULL]
  BaseWithIndexAndDisplacement32Matcher match36(graph()->NewNode(a_op, b1, m3));
  CheckBaseWithIndexAndDisplacement(&match36, m3, 0, b1, nullptr);

  // (S4 + B1) -> [B0, 0, S4, NULL]
  BaseWithIndexAndDisplacement32Matcher match37(graph()->NewNode(a_op, b1, s4));
  CheckBaseWithIndexAndDisplacement(&match37, s4, 0, b1, nullptr);

  // 3 INPUT

  // (D15 + S3) + B0 -> [p1, 2, b0, d15]
  s3 = graph()->NewNode(s_op, p1, d3);
  BaseWithIndexAndDisplacement32Matcher match38(
      graph()->NewNode(a_op, graph()->NewNode(a_op, d15, s3), b0));
  CheckBaseWithIndexAndDisplacement(&match38, p1, 3, b0, d15);

  // (B0 + D15) + S3 -> [p1, 2, b0, d15]
  s3 = graph()->NewNode(s_op, p1, d3);
  BaseWithIndexAndDisplacement32Matcher match39(
      graph()->NewNode(a_op, graph()->NewNode(a_op, b0, d15), s3));
  CheckBaseWithIndexAndDisplacement(&match39, p1, 3, b0, d15);

  // (S3 + B0) + D15 -> [p1, 2, b0, d15]
  s3 = graph()->NewNode(s_op, p1, d3);
  BaseWithIndexAndDisplacement32Matcher match40(
      graph()->NewNode(a_op, graph()->NewNode(a_op, s3, b0), d15));
  CheckBaseWithIndexAndDisplacement(&match40, p1, 3, b0, d15);

  // D15 + (S3 + B0) -> [p1, 2, b0, d15]
  s3 = graph()->NewNode(s_op, p1, d3);
  BaseWithIndexAndDisplacement32Matcher match41(
      graph()->NewNode(a_op, d15, graph()->NewNode(a_op, s3, b0)));
  CheckBaseWithIndexAndDisplacement(&match41, p1, 3, b0, d15);

  // B0 + (D15 + S3) -> [p1, 2, b0, d15]
  s3 = graph()->NewNode(s_op, p1, d3);
  BaseWithIndexAndDisplacement32Matcher match42(
      graph()->NewNode(a_op, b0, graph()->NewNode(a_op, d15, s3)));
  CheckBaseWithIndexAndDisplacement(&match42, p1, 3, b0, d15);

  // S3 + (B0 + D15) -> [p1, 2, b0, d15]
  s3 = graph()->NewNode(s_op, p1, d3);
  BaseWithIndexAndDisplacement32Matcher match43(
      graph()->NewNode(a_op, s3, graph()->NewNode(a_op, b0, d15)));
  CheckBaseWithIndexAndDisplacement(&match43, p1, 3, b0, d15);

  // S3 + (B0 - D15) -> [p1, 2, b0, d15, true]
  s3 = graph()->NewNode(s_op, p1, d3);
  BaseWithIndexAndDisplacement32Matcher match44(
      graph()->NewNode(a_op, s3, graph()->NewNode(sub_op, b0, d15)));
  CheckBaseWithIndexAndDisplacement(&match44, p1, 3, b0, d15,
                                    kNegativeDisplacement);

  // B0 + (B1 - D15) -> [p1, 2, b0, d15, true]
  BaseWithIndexAndDisplacement32Matcher match45(
      graph()->NewNode(a_op, b0, graph()->NewNode(sub_op, b1, d15)));
  CheckBaseWithIndexAndDisplacement(&match45, b1, 0, b0, d15,
                                    kNegativeDisplacement);

  // (B0 - D15) + S3 -> [p1, 2, b0, d15, true]
  s3 = graph()->NewNode(s_op, p1, d3);
  BaseWithIndexAndDisplacement32Matcher match46(
      graph()->NewNode(a_op, graph()->NewNode(sub_op, b0, d15), s3));
  CheckBaseWithIndexAndDisplacement(&match46, p1, 3, b0, d15,
                                    kNegativeDisplacement);

  // 4 INPUT - with addressing operand uses

  // (B0 + M1) -> [p1, 0, B0, NULL]
  m1 = graph()->NewNode(m_op, p1, d1);
  ADD_ADDRESSING_OPERAND_USES(m1);
  BaseWithIndexAndDisplacement32Matcher match47(graph()->NewNode(a_op, b0, m1));
  CheckBaseWithIndexAndDisplacement(&match47, p1, 0, b0, nullptr);

  // (M1 + B0) -> [p1, 0, B0, NULL]
  m1 = graph()->NewNode(m_op, p1, d1);
  ADD_ADDRESSING_OPERAND_USES(m1);
  BaseWithIndexAndDisplacement32Matcher match48(graph()->NewNode(a_op, m1, b0));
  CheckBaseWithIndexAndDisplacement(&match48, p1, 0, b0, nullptr);

  // (D15 + M1) -> [P1, 0, NULL, D15]
  m1 = graph()->NewNode(m_op, p1, d1);
  ADD_ADDRESSING_OPERAND_USES(m1);
  BaseWithIndexAndDisplacement32Matcher match49(
      graph()->NewNode(a_op, d15, m1));
  CheckBaseWithIndexAndDisplacement(&match49, p1, 0, nullptr, d15);

  // (M1 + D15) -> [P1, 0, NULL, D15]
  m1 = graph()->NewNode(m_op, p1, d1);
  ADD_ADDRESSING_OPERAND_USES(m1);
  BaseWithIndexAndDisplacement32Matcher match50(
      graph()->NewNode(a_op, m1, d15));
  CheckBaseWithIndexAndDisplacement(&match50, p1, 0, nullptr, d15);

  // (B0 + S0) -> [p1, 0, B0, NULL]
  s0 = graph()->NewNode(s_op, p1, d0);
  ADD_ADDRESSING_OPERAND_USES(s0);
  BaseWithIndexAndDisplacement32Matcher match51(graph()->NewNode(a_op, b0, s0));
  CheckBaseWithIndexAndDisplacement(&match51, p1, 0, b0, nullptr);

  // (S0 + B0) -> [p1, 0, B0, NULL]
  s0 = graph()->NewNode(s_op, p1, d0);
  ADD_ADDRESSING_OPERAND_USES(s0);
  BaseWithIndexAndDisplacement32Matcher match52(graph()->NewNode(a_op, s0, b0));
  CheckBaseWithIndexAndDisplacement(&match52, p1, 0, b0, nullptr);

  // (D15 + S0) -> [P1, 0, NULL, D15]
  s0 = graph()->NewNode(s_op, p1, d0);
  ADD_ADDRESSING_OPERAND_USES(s0);
  BaseWithIndexAndDisplacement32Matcher match53(
      graph()->NewNode(a_op, d15, s0));
  CheckBaseWithIndexAndDisplacement(&match53, p1, 0, nullptr, d15);

  // (S0 + D15) -> [P1, 0, NULL, D15]
  s0 = graph()->NewNode(s_op, p1, d0);
  ADD_ADDRESSING_OPERAND_USES(s0);
  BaseWithIndexAndDisplacement32Matcher match54(
      graph()->NewNode(a_op, s0, d15));
  CheckBaseWithIndexAndDisplacement(&match54, p1, 0, nullptr, d15);

  // (B0 + M2) -> [p1, 1, B0, NULL]
  m2 = graph()->NewNode(m_op, p1, d2);
  ADD_ADDRESSING_OPERAND_USES(m2);
  BaseWithIndexAndDisplacement32Matcher match55(graph()->NewNode(a_op, b0, m2));
  CheckBaseWithIndexAndDisplacement(&match55, p1, 1, b0, nullptr);

  // (M2 + B0) -> [p1, 1, B0, NULL]
  m2 = graph()->NewNode(m_op, p1, d2);
  ADD_ADDRESSING_OPERAND_USES(m2);
  BaseWithIndexAndDisplacement32Matcher match56(graph()->NewNode(a_op, m2, b0));
  CheckBaseWithIndexAndDisplacement(&match56, p1, 1, b0, nullptr);

  // (D15 + M2) -> [P1, 1, NULL, D15]
  m2 = graph()->NewNode(m_op, p1, d2);
  ADD_ADDRESSING_OPERAND_USES(m2);
  BaseWithIndexAndDisplacement32Matcher match57(
      graph()->NewNode(a_op, d15, m2));
  CheckBaseWithIndexAndDisplacement(&match57, p1, 1, nullptr, d15);

  // (M2 + D15) -> [P1, 1, NULL, D15]
  m2 = graph()->NewNode(m_op, p1, d2);
  ADD_ADDRESSING_OPERAND_USES(m2);
  BaseWithIndexAndDisplacement32Matcher match58(
      graph()->NewNode(a_op, m2, d15));
  CheckBaseWithIndexAndDisplacement(&match58, p1, 1, nullptr, d15);

  // (B0 + S1) -> [p1, 1, B0, NULL]
  s1 = graph()->NewNode(s_op, p1, d1);
  ADD_ADDRESSING_OPERAND_USES(s1);
  BaseWithIndexAndDisplacement32Matcher match59(graph()->NewNode(a_op, b0, s1));
  CheckBaseWithIndexAndDisplacement(&match59, p1, 1, b0, nullptr);

  // (S1 + B0) -> [p1, 1, B0, NULL]
  s1 = graph()->NewNode(s_op, p1, d1);
  ADD_ADDRESSING_OPERAND_USES(s1);
  BaseWithIndexAndDisplacement32Matcher match60(graph()->NewNode(a_op, s1, b0));
  CheckBaseWithIndexAndDisplacement(&match60, p1, 1, b0, nullptr);

  // (D15 + S1) -> [P1, 1, NULL, D15]
  s1 = graph()->NewNode(s_op, p1, d1);
  ADD_ADDRESSING_OPERAND_USES(s1);
  BaseWithIndexAndDisplacement32Matcher match61(
      graph()->NewNode(a_op, d15, s1));
  CheckBaseWithIndexAndDisplacement(&match61, p1, 1, nullptr, d15);

  // (S1 + D15) -> [P1, 1, NULL, D15]
  s1 = graph()->NewNode(s_op, p1, d1);
  ADD_ADDRESSING_OPERAND_USES(s1);
  BaseWithIndexAndDisplacement32Matcher match62(
      graph()->NewNode(a_op, s1, d15));
  CheckBaseWithIndexAndDisplacement(&match62, p1, 1, nullptr, d15);

  // (B0 + M4) -> [p1, 2, B0, NULL]
  m4 = graph()->NewNode(m_op, p1, d4);
  ADD_ADDRESSING_OPERAND_USES(m4);
  BaseWithIndexAndDisplacement32Matcher match63(graph()->NewNode(a_op, b0, m4));
  CheckBaseWithIndexAndDisplacement(&match63, p1, 2, b0, nullptr);

  // (M4 + B0) -> [p1, 2, B0, NULL]
  m4 = graph()->NewNode(m_op, p1, d4);
  ADD_ADDRESSING_OPERAND_USES(m4);
  BaseWithIndexAndDisplacement32Matcher match64(graph()->NewNode(a_op, m4, b0));
  CheckBaseWithIndexAndDisplacement(&match64, p1, 2, b0, nullptr);

  // (D15 + M4) -> [p1, 2, NULL, D15]
  m4 = graph()->NewNode(m_op, p1, d4);
  ADD_ADDRESSING_OPERAND_USES(m4);
  BaseWithIndexAndDisplacement32Matcher match65(
      graph()->NewNode(a_op, d15, m4));
  CheckBaseWithIndexAndDisplacement(&match65, p1, 2, nullptr, d15);

  // (M4 + D15) -> [p1, 2, NULL, D15]
  m4 = graph()->NewNode(m_op, p1, d4);
  ADD_ADDRESSING_OPERAND_USES(m4);
  BaseWithIndexAndDisplacement32Matcher match66(
      graph()->NewNode(a_op, m4, d15));
  CheckBaseWithIndexAndDisplacement(&match66, p1, 2, nullptr, d15);

  // (B0 + S2) -> [p1, 2, B0, NULL]
  s2 = graph()->NewNode(s_op, p1, d2);
  ADD_ADDRESSING_OPERAND_USES(s2);
  BaseWithIndexAndDisplacement32Matcher match67(graph()->NewNode(a_op, b0, s2));
  CheckBaseWithIndexAndDisplacement(&match67, p1, 2, b0, nullptr);

  // (S2 + B0) -> [p1, 2, B0, NULL]
  s2 = graph()->NewNode(s_op, p1, d2);
  ADD_ADDRESSING_OPERAND_USES(s2);
  BaseWithIndexAndDisplacement32Matcher match68(graph()->NewNode(a_op, s2, b0));
  CheckBaseWithIndexAndDisplacement(&match68, p1, 2, b0, nullptr);

  // (D15 + S2) -> [p1, 2, NULL, D15]
  s2 = graph()->NewNode(s_op, p1, d2);
  ADD_ADDRESSING_OPERAND_USES(s2);
  BaseWithIndexAndDisplacement32Matcher match69(
      graph()->NewNode(a_op, d15, s2));
  CheckBaseWithIndexAndDisplacement(&match69, p1, 2, nullptr, d15);

  // (S2 + D15) -> [p1, 2, NULL, D15]
  s2 = graph()->NewNode(s_op, p1, d2);
  ADD_ADDRESSING_OPERAND_USES(s2);
  BaseWithIndexAndDisplacement32Matcher match70(
      graph()->NewNode(a_op, s2, d15));
  CheckBaseWithIndexAndDisplacement(&match70, p1, 2, nullptr, d15);

  // (B0 + M8) -> [p1, 2, B0, NULL]
  m8 = graph()->NewNode(m_op, p1, d8);
  ADD_ADDRESSING_OPERAND_USES(m8);
  BaseWithIndexAndDisplacement32Matcher match71(graph()->NewNode(a_op, b0, m8));
  CheckBaseWithIndexAndDisplacement(&match71, p1, 3, b0, nullptr);

  // (M8 + B0) -> [p1, 2, B0, NULL]
  m8 = graph()->NewNode(m_op, p1, d8);
  ADD_ADDRESSING_OPERAND_USES(m8);
  BaseWithIndexAndDisplacement32Matcher match72(graph()->NewNode(a_op, m8, b0));
  CheckBaseWithIndexAndDisplacement(&match72, p1, 3, b0, nullptr);

  // (D15 + M8) -> [p1, 2, NULL, D15]
  m8 = graph()->NewNode(m_op, p1, d8);
  ADD_ADDRESSING_OPERAND_USES(m8);
  BaseWithIndexAndDisplacement32Matcher match73(
      graph()->NewNode(a_op, d15, m8));
  CheckBaseWithIndexAndDisplacement(&match73, p1, 3, nullptr, d15);

  // (M8 + D15) -> [p1, 2, NULL, D15]
  m8 = graph()->NewNode(m_op, p1, d8);
  ADD_ADDRESSING_OPERAND_USES(m8);
  BaseWithIndexAndDisplacement32Matcher match74(
      graph()->NewNode(a_op, m8, d15));
  CheckBaseWithIndexAndDisplacement(&match74, p1, 3, nullptr, d15);

  // (B0 + S3) -> [p1, 2, B0, NULL]
  s3 = graph()->NewNode(s_op, p1, d3);
  ADD_ADDRESSING_OPERAND_USES(s3);
  BaseWithIndexAndDisplacement32Matcher match75(graph()->NewNode(a_op, b0, s3));
  CheckBaseWithIndexAndDisplacement(&match75, p1, 3, b0, nullptr);

  // (S3 + B0) -> [p1, 2, B0, NULL]
  s3 = graph()->NewNode(s_op, p1, d3);
  ADD_ADDRESSING_OPERAND_USES(s3);
  BaseWithIndexAndDisplacement32Matcher match76(graph()->NewNode(a_op, s3, b0));
  CheckBaseWithIndexAndDisplacement(&match76, p1, 3, b0, nullptr);

  // (D15 + S3) -> [p1, 2, NULL, D15]
  s3 = graph()->NewNode(s_op, p1, d3);
  ADD_ADDRESSING_OPERAND_USES(s3);
  BaseWithIndexAndDisplacement32Matcher match77(
      graph()->NewNode(a_op, d15, s3));
  CheckBaseWithIndexAndDisplacement(&match77, p1, 3, nullptr, d15);

  // (S3 + D15) -> [p1, 2, NULL, D15]
  s3 = graph()->NewNode(s_op, p1, d3);
  ADD_ADDRESSING_OPERAND_USES(s3);
  BaseWithIndexAndDisplacement32Matcher match78(
      graph()->NewNode(a_op, s3, d15));
  CheckBaseWithIndexAndDisplacement(&match78, p1, 3, nullptr, d15);

  // (D15 + S3) + B0 -> [p1, 2, b0, d15]
  s3 = graph()->NewNode(s_op, p1, d3);
  Node* temp = graph()->NewNode(a_op, d15, s3);
  ADD_ADDRESSING_OPERAND_USES(temp);
  BaseWithIndexAndDisplacement32Matcher match79(
      graph()->NewNode(a_op, temp, b0));
  CheckBaseWithIndexAndDisplacement(&match79, p1, 3, b0, d15);

  // (B0 + D15) + S3 -> [p1, 2, b0, d15]
  s3 = graph()->NewNode(s_op, p1, d3);
  temp = graph()->NewNode(a_op, b0, d15);
  ADD_ADDRESSING_OPERAND_USES(temp);
  BaseWithIndexAndDisplacement32Matcher match80(
      graph()->NewNode(a_op, temp, s3));
  CheckBaseWithIndexAndDisplacement(&match80, p1, 3, b0, d15);

  // (S3 + B0) + D15 -> [NULL, 0, (s3 + b0), d15]
  // Avoid changing simple addressing to complex addressing
  s3 = graph()->NewNode(s_op, p1, d3);
  temp = graph()->NewNode(a_op, s3, b0);
  ADD_ADDRESSING_OPERAND_USES(temp);
  BaseWithIndexAndDisplacement32Matcher match81(
      graph()->NewNode(a_op, temp, d15));
  CheckBaseWithIndexAndDisplacement(&match81, nullptr, 0, temp, d15);

  // D15 + (S3 + B0) -> [NULL, 0, (s3 + b0), d15]
  // Avoid changing simple addressing to complex addressing
  s3 = graph()->NewNode(s_op, p1, d3);
  temp = graph()->NewNode(a_op, s3, b0);
  ADD_ADDRESSING_OPERAND_USES(temp);
  BaseWithIndexAndDisplacement32Matcher match82(
      graph()->NewNode(a_op, d15, temp));
  CheckBaseWithIndexAndDisplacement(&match82, nullptr, 0, temp, d15);

  // B0 + (D15 + S3) -> [p1, 2, b0, d15]
  s3 = graph()->NewNode(s_op, p1, d3);
  temp = graph()->NewNode(a_op, d15, s3);
  ADD_ADDRESSING_OPERAND_USES(temp);
  BaseWithIndexAndDisplacement32Matcher match83(
      graph()->NewNode(a_op, b0, temp));
  CheckBaseWithIndexAndDisplacement(&match83, p1, 3, b0, d15);

  // S3 + (B0 + D15) -> [p1, 2, b0, d15]
  s3 = graph()->NewNode(s_op, p1, d3);
  temp = graph()->NewNode(a_op, b0, d15);
  ADD_ADDRESSING_OPERAND_USES(temp);
  BaseWithIndexAndDisplacement32Matcher match84(
      graph()->NewNode(a_op, s3, temp));
  CheckBaseWithIndexAndDisplacement(&match84, p1, 3, b0, d15);

  // S3 + (B0 - D15) -> [p1, 2, b0, d15, true]
  s3 = graph()->NewNode(s_op, p1, d3);
  temp = graph()->NewNode(sub_op, b0, d15);
  ADD_ADDRESSING_OPERAND_USES(temp);
  BaseWithIndexAndDisplacement32Matcher match85(
      graph()->NewNode(a_op, s3, temp));
  CheckBaseWithIndexAndDisplacement(&match85, p1, 3, b0, d15,
                                    kNegativeDisplacement);

  // B0 + (B1 - D15) -> [p1, 2, b0, d15, true]
  temp = graph()->NewNode(sub_op, b1, d15);
  ADD_ADDRESSING_OPERAND_USES(temp);
  BaseWithIndexAndDisplacement32Matcher match86(
      graph()->NewNode(a_op, b0, temp));
  CheckBaseWithIndexAndDisplacement(&match86, b1, 0, b0, d15,
                                    kNegativeDisplacement);

  // (B0 - D15) + S3 -> [p1, 2, b0, d15, true]
  s3 = graph()->NewNode(s_op, p1, d3);
  temp = graph()->NewNode(sub_op, b0, d15);
  ADD_ADDRESSING_OPERAND_USES(temp);
  BaseWithIndexAndDisplacement32Matcher match87(
      graph()->NewNode(a_op, temp, s3));
  CheckBaseWithIndexAndDisplacement(&match87, p1, 3, b0, d15,
                                    kNegativeDisplacement);

  // (B0 + B1) + D15 -> [NULL, 0, (b0 + b1), d15]
  // Avoid changing simple addressing to complex addressing
  temp = graph()->NewNode(a_op, b0, b1);
  ADD_ADDRESSING_OPERAND_USES(temp);
  BaseWithIndexAndDisplacement32Matcher match88(
      graph()->NewNode(a_op, temp, d15));
  CheckBaseWithIndexAndDisplacement(&match88, nullptr, 0, temp, d15);

  // D15 + (B0 + B1) -> [NULL, 0, (b0 + b1), d15]
  // Avoid changing simple addressing to complex addressing
  temp = graph()->NewNode(a_op, b0, b1);
  ADD_ADDRESSING_OPERAND_USES(temp);
  BaseWithIndexAndDisplacement32Matcher match89(
      graph()->NewNode(a_op, d15, temp));
  CheckBaseWithIndexAndDisplacement(&match89, nullptr, 0, temp, d15);

  // 5 INPUT - with none-addressing operand uses

  // (B0 + M1) -> [b0, 0, m1, NULL]
  m1 = graph()->NewNode(m_op, p1, d1);
  ADD_NONE_ADDRESSING_OPERAND_USES(m1);
  BaseWithIndexAndDisplacement32Matcher match90(graph()->NewNode(a_op, b0, m1));
  CheckBaseWithIndexAndDisplacement(&match90, b0, 0, m1, nullptr);

  // (M1 + B0) -> [b0, 0, m1, NULL]
  m1 = graph()->NewNode(m_op, p1, d1);
  ADD_NONE_ADDRESSING_OPERAND_USES(m1);
  BaseWithIndexAndDisplacement32Matcher match91(graph()->NewNode(a_op, m1, b0));
  CheckBaseWithIndexAndDisplacement(&match91, b0, 0, m1, nullptr);

  // (D15 + M1) -> [NULL, 0, m1, d15]
  m1 = graph()->NewNode(m_op, p1, d1);
  ADD_NONE_ADDRESSING_OPERAND_USES(m1);
  BaseWithIndexAndDisplacement32Matcher match92(
      graph()->NewNode(a_op, d15, m1));
  CheckBaseWithIndexAndDisplacement(&match92, nullptr, 0, m1, d15);

  // (M1 + D15) -> [NULL, 0, m1, d15]
  m1 = graph()->NewNode(m_op, p1, d1);
  ADD_NONE_ADDRESSING_OPERAND_USES(m1);
  BaseWithIndexAndDisplacement32Matcher match93(
      graph()->NewNode(a_op, m1, d15));
  CheckBaseWithIndexAndDisplacement(&match93, nullptr, 0, m1, d15);

  // (B0 + S0) -> [b0, 0, s0, NULL]
  s0 = graph()->NewNode(s_op, p1, d0);
  ADD_NONE_ADDRESSING_OPERAND_USES(s0);
  BaseWithIndexAndDisplacement32Matcher match94(graph()->NewNode(a_op, b0, s0));
  CheckBaseWithIndexAndDisplacement(&match94, b0, 0, s0, nullptr);

  // (S0 + B0) -> [b0, 0, s0, NULL]
  s0 = graph()->NewNode(s_op, p1, d0);
  ADD_NONE_ADDRESSING_OPERAND_USES(s0);
  BaseWithIndexAndDisplacement32Matcher match95(graph()->NewNode(a_op, s0, b0));
  CheckBaseWithIndexAndDisplacement(&match95, b0, 0, s0, nullptr);

  // (D15 + S0) -> [NULL, 0, s0, d15]
  s0 = graph()->NewNode(s_op, p1, d0);
  ADD_NONE_ADDRESSING_OPERAND_USES(s0);
  BaseWithIndexAndDisplacement32Matcher match96(
      graph()->NewNode(a_op, d15, s0));
  CheckBaseWithIndexAndDisplacement(&match96, nullptr, 0, s0, d15);

  // (S0 + D15) -> [NULL, 0, s0, d15]
  s0 = graph()->NewNode(s_op, p1, d0);
  ADD_NONE_ADDRESSING_OPERAND_USES(s0);
  BaseWithIndexAndDisplacement32Matcher match97(
      graph()->NewNode(a_op, s0, d15));
  CheckBaseWithIndexAndDisplacement(&match97, nullptr, 0, s0, d15);

  // (B0 + M2) -> [b0, 0, m2, NULL]
  m2 = graph()->NewNode(m_op, p1, d2);
  ADD_NONE_ADDRESSING_OPERAND_USES(m2);
  BaseWithIndexAndDisplacement32Matcher match98(graph()->NewNode(a_op, b0, m2));
  CheckBaseWithIndexAndDisplacement(&match98, b0, 0, m2, nullptr);

  // (M2 + B0) -> [b0, 0, m2, NULL]
  m2 = graph()->NewNode(m_op, p1, d2);
  ADD_NONE_ADDRESSING_OPERAND_USES(m2);
  BaseWithIndexAndDisplacement32Matcher match99(graph()->NewNode(a_op, m2, b0));
  CheckBaseWithIndexAndDisplacement(&match99, b0, 0, m2, nullptr);

  // (D15 + M2) -> [NULL, 0, m2, d15]
  m2 = graph()->NewNode(m_op, p1, d2);
  ADD_NONE_ADDRESSING_OPERAND_USES(m2);
  BaseWithIndexAndDisplacement32Matcher match100(
      graph()->NewNode(a_op, d15, m2));
  CheckBaseWithIndexAndDisplacement(&match100, nullptr, 0, m2, d15);

  // (M2 + D15) -> [NULL, 0, m2, d15]
  m2 = graph()->NewNode(m_op, p1, d2);
  ADD_NONE_ADDRESSING_OPERAND_USES(m2);
  BaseWithIndexAndDisplacement32Matcher match101(
      graph()->NewNode(a_op, m2, d15));
  CheckBaseWithIndexAndDisplacement(&match101, nullptr, 0, m2, d15);

  // (B0 + S1) -> [b0, 0, s1, NULL]
  s1 = graph()->NewNode(s_op, p1, d1);
  ADD_NONE_ADDRESSING_OPERAND_USES(s1);
  BaseWithIndexAndDisplacement32Matcher match102(
      graph()->NewNode(a_op, b0, s1));
  CheckBaseWithIndexAndDisplacement(&match102, b0, 0, s1, nullptr);

  // (S1 + B0) -> [b0, 0, s1, NULL]
  s1 = graph()->NewNode(s_op, p1, d1);
  ADD_NONE_ADDRESSING_OPERAND_USES(s1);
  BaseWithIndexAndDisplacement32Matcher match103(
      graph()->NewNode(a_op, s1, b0));
  CheckBaseWithIndexAndDisplacement(&match103, b0, 0, s1, nullptr);

  // (D15 + S1) -> [NULL, 0, s1, d15]
  s1 = graph()->NewNode(s_op, p1, d1);
  ADD_NONE_ADDRESSING_OPERAND_USES(s1);
  BaseWithIndexAndDisplacement32Matcher match104(
      graph()->NewNode(a_op, d15, s1));
  CheckBaseWithIndexAndDisplacement(&match104, nullptr, 0, s1, d15);

  // (S1 + D15) -> [NULL, 0, s1, d15]
  s1 = graph()->NewNode(s_op, p1, d1);
  ADD_NONE_ADDRESSING_OPERAND_USES(s1);
  BaseWithIndexAndDisplacement32Matcher match105(
      graph()->NewNode(a_op, s1, d15));
  CheckBaseWithIndexAndDisplacement(&match105, nullptr, 0, s1, d15);

  // (B0 + M4) -> [b0, 0, m4, NULL]
  m4 = graph()->NewNode(m_op, p1, d4);
  ADD_NONE_ADDRESSING_OPERAND_USES(m4);
  BaseWithIndexAndDisplacement32Matcher match106(
      graph()->NewNode(a_op, b0, m4));
  CheckBaseWithIndexAndDisplacement(&match106, b0, 0, m4, nullptr);

  // (M4 + B0) -> [b0, 0, m4, NULL]
  m4 = graph()->NewNode(m_op, p1, d4);
  ADD_NONE_ADDRESSING_OPERAND_USES(m4);
  BaseWithIndexAndDisplacement32Matcher match107(
      graph()->NewNode(a_op, m4, b0));
  CheckBaseWithIndexAndDisplacement(&match107, b0, 0, m4, nullptr);

  // (D15 + M4) -> [NULL, 0, m4, d15]
  m4 = graph()->NewNode(m_op, p1, d4);
  ADD_NONE_ADDRESSING_OPERAND_USES(m4);
  BaseWithIndexAndDisplacement32Matcher match108(
      graph()->NewNode(a_op, d15, m4));
  CheckBaseWithIndexAndDisplacement(&match108, nullptr, 0, m4, d15);
```