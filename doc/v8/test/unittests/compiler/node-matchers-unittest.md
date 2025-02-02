Response: Let's break down the thought process for summarizing the C++ code and providing a JavaScript example.

**1. Understanding the Goal:**

The request asks for a summary of the C++ code's functionality and a JavaScript example if it relates to JavaScript features. It's crucial to identify the core purpose of the C++ code, not just describe its syntax.

**2. Initial Code Scan and Keyword Identification:**

I'd start by quickly scanning the code for keywords and patterns that indicate its purpose. Some immediately stand out:

* `#include "src/compiler/node-matchers.h"`: This header file strongly suggests the code is about pattern matching within a compiler.
* `class NodeMatcherTest : public GraphTest`: This indicates it's a unit test for something called "NodeMatcher."  The `GraphTest` part suggests it's working with a graph data structure.
* `BaseWithIndexAndDisplacement32Matcher`, `BaseWithIndexAndDisplacement64Matcher`: These class names are very descriptive. They suggest matching patterns related to memory addressing with an index, base, and displacement (offset). The "32" and "64" likely refer to bit widths.
* `EXPECT_TRUE(matcher->matches())`, `EXPECT_EQ(...)`: These are standard unit testing assertions, confirming the code's testing nature.
* `machine()->Load(...)`, `machine()->Store(...)`, `machine()->Int32Add()`, `machine()->Word32Shl()`: These look like operations on some kind of "machine," likely representing low-level instructions or operations within the compiler's intermediate representation.
* `common()->Int32Constant(...)`, `common()->Parameter(...)`: These are likely ways to create constant values and represent function parameters in the graph.

**3. Formulating a Hypothesis:**

Based on the keywords, a likely hypothesis emerges: This C++ code defines and tests "matchers" that can identify specific patterns of operations within a compiler's internal graph representation. These patterns seem related to how memory addresses are calculated (base + index * scale + displacement).

**4. Deeper Dive into the Matcher Classes:**

I'd then focus on how the matchers work. The `CheckBaseWithIndexAndDisplacement` template function is a key clue. It confirms the hypothesis by checking if a matcher successfully extracts the index, scale, base, and displacement components from a given node in the graph.

**5. Understanding the Test Cases:**

The `TEST_F` macros define individual test cases. These tests systematically create various combinations of nodes (addition, multiplication, shifts, constants, parameters) and then use the matchers to see if they correctly identify the base, index, scale, and displacement. The comments in the tests (e.g., `// (B0 + B1) -> [B0, 0, B1, NULL]`) are invaluable for understanding what each test is verifying.

**6. Connecting to JavaScript (If Applicable):**

The question specifically asks about the relationship to JavaScript. Here's where the thought process involves bridging the gap between low-level compiler concepts and high-level language features:

* **Memory Addressing in JavaScript:** While JavaScript abstracts away direct memory management, the *concept* of accessing data at a certain "offset" from a starting point is fundamental. This happens when accessing array elements or object properties.
* **Compiler Optimizations:**  Compilers like V8 (which this code is part of) analyze JavaScript code and perform optimizations. Recognizing memory access patterns is crucial for generating efficient machine code.
* **Illustrative Example:** To demonstrate the connection, I'd look for a simple JavaScript example that conceptually involves something similar to the matched patterns. Array access (`arr[i]`) is a good candidate because it inherently involves calculating an address based on the array's base address and the index.

**7. Crafting the Summary:**

With a good understanding of the code, I'd synthesize a summary that includes:

* **Overall Purpose:**  Testing node matchers in the V8 compiler.
* **Specific Functionality:**  Matching patterns related to memory addressing (base + index * scale + displacement).
* **Key Classes:** Mentioning `BaseWithIndexAndDisplacement32Matcher` and `BaseWithIndexAndDisplacement64Matcher`.
* **Testing Methodology:** Briefly explaining how the tests work by creating nodes and checking the matcher's output.

**8. Creating the JavaScript Example:**

The JavaScript example needs to be clear, concise, and directly relate to the concept being tested in the C++ code. Showing how array access implicitly involves address calculation achieves this.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe the code is about general graph pattern matching.
* **Correction:** The specific class names and the focus on index, base, and displacement narrow it down to memory addressing patterns.
* **Initial thought about JavaScript:**  Maybe it's too low-level to connect directly to JavaScript.
* **Refinement:** While direct memory access isn't present, the *concept* of indexed access in arrays provides a good analogy for the compiler's optimization target.

By following these steps, combining code analysis with understanding the broader context of a compiler and relating it to JavaScript concepts, a comprehensive and accurate summary can be generated.
这个C++源代码文件 `v8/test/unittests/compiler/node-matchers-unittest.cc` 是 V8 JavaScript 引擎的一部分，其主要功能是**测试编译器中用于匹配特定节点模式的 "matcher" 类**。

更具体地说，这个文件的第1部分（你提供的代码）专注于测试 `BaseWithIndexAndDisplacement32Matcher` 和 `BaseWithIndexAndDisplacement64Matcher` 这两个 matcher 类。这两个类的作用是**识别代码中表示内存寻址模式的特定节点结构**，这种模式通常包括一个基址 (base)、一个索引 (index)、一个比例因子 (scale) 和一个位移 (displacement)。

**与 JavaScript 的关系和示例:**

虽然这个 C++ 文件本身是 V8 引擎的内部测试代码，与直接编写的 JavaScript 代码没有直接的语法对应关系，但它所测试的功能与 JavaScript 引擎的性能优化密切相关。

JavaScript 引擎在执行 JavaScript 代码时，需要将高级的 JavaScript 代码转换为底层的机器码。在这个转换过程中，编译器会识别各种模式，并进行优化。 内存寻址是常见的操作，例如访问数组元素或对象属性。

`BaseWithIndexAndDisplacement32Matcher` 和 `BaseWithIndexAndDisplacement64Matcher` 帮助编译器识别类似以下内存访问模式的结构：

* **数组访问:**  `array[i]`  可以被看作是基址是数组的起始地址，索引是 `i`，比例因子是元素的大小，位移可能是 0。
* **对象属性访问:** 尽管对象属性访问更复杂，但在某些底层实现中，也可能涉及到类似的基于基址和偏移的访问。

**JavaScript 示例:**

考虑以下简单的 JavaScript 代码：

```javascript
function accessArray(arr, index) {
  return arr[index];
}

const myArray = [10, 20, 30, 40];
const result = accessArray(myArray, 2); // 访问索引为 2 的元素
console.log(result); // 输出 30
```

当 V8 编译 `accessArray` 函数时，它会在内部的中间表示 (IR) 中创建节点来表示数组访问操作 `arr[index]`。  `BaseWithIndexAndDisplacement32Matcher` 或 `BaseWithIndexAndDisplacement64Matcher` 的作用就是尝试在这些节点中识别出基址（`arr` 的内存地址）、索引 (`index` 的值）、以及隐含的比例因子（数组元素的大小，例如 32 位或 64 位整数）。

**测试代码的工作方式:**

你提供的 C++ 测试代码创建了各种不同的节点组合，模拟了不同的算术运算，例如加法 (`Int32Add`, `Int64Add`)、乘法 (`Int32Mul`, `Int64Mul`) 和位移 (`Word32Shl`, `Word64Shl`)。然后，它使用 `BaseWithIndexAndDisplacement32Matcher` 和 `BaseWithIndexAndDisplacement64Matcher` 来检查这些节点组合是否匹配预期的内存寻址模式。

例如，测试用例 `TEST_F(NodeMatcherTest, ScaledWithOffset32Matcher)` 中创建了像 `graph()->NewNode(a_op, b0, m1)` 这样的节点，其中 `a_op` 是加法操作，`b0` 可能代表基址，`m1` 可能代表索引乘以比例因子。matcher 会尝试从这个节点结构中提取基址、索引、比例因子和位移，并使用 `CheckBaseWithIndexAndDisplacement` 函数进行断言，确保提取的值是正确的。

**总结:**

总而言之，`v8/test/unittests/compiler/node-matchers-unittest.cc` 的第 1 部分主要功能是**测试 V8 编译器中用于识别 32 位和 64 位内存寻址模式的 matcher 类是否能正确地从不同的节点结构中提取出基址、索引、比例因子和位移信息**。这对于编译器进行高效的内存访问优化至关重要，从而提升 JavaScript 代码的执行性能。

### 提示词
```
这是目录为v8/test/unittests/compiler/node-matchers-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
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

  // (M4 + D15) -> [NULL, 0, m4, d15]
  m4 = graph()->NewNode(m_op, p1, d4);
  ADD_NONE_ADDRESSING_OPERAND_USES(m4);
  BaseWithIndexAndDisplacement32Matcher match109(
      graph()->NewNode(a_op, m4, d15));
  CheckBaseWithIndexAndDisplacement(&match109, nullptr, 0, m4, d15);

  // (B0 + S2) -> [b0, 0, s2, NULL]
  s2 = graph()->NewNode(s_op, p1, d2);
  ADD_NONE_ADDRESSING_OPERAND_USES(s2);
  BaseWithIndexAndDisplacement32Matcher match110(
      graph()->NewNode(a_op, b0, s2));
  CheckBaseWithIndexAndDisplacement(&match110, b0, 0, s2, nullptr);

  // (S2 + B0) -> [b0, 0, s2, NULL]
  s2 = graph()->NewNode(s_op, p1, d2);
  ADD_NONE_ADDRESSING_OPERAND_USES(s2);
  BaseWithIndexAndDisplacement32Matcher match111(
      graph()->NewNode(a_op, s2, b0));
  CheckBaseWithIndexAndDisplacement(&match111, b0, 0, s2, nullptr);

  // (D15 + S2) -> [NULL, 0, s2, d15]
  s2 = graph()->NewNode(s_op, p1, d2);
  ADD_NONE_ADDRESSING_OPERAND_USES(s2);
  BaseWithIndexAndDisplacement32Matcher match112(
      graph()->NewNode(a_op, d15, s2));
  CheckBaseWithIndexAndDisplacement(&match112, nullptr, 0, s2, d15);

  // (S2 + D15) -> [NULL, 0, s2, d15]
  s2 = graph()->NewNode(s_op, p1, d2);
  ADD_NONE_ADDRESSING_OPERAND_USES(s2);
  BaseWithIndexAndDisplacement32Matcher match113(
      graph()->NewNode(a_op, s2, d15));
  CheckBaseWithIndexAndDisplacement(&match113, nullptr, 0, s2, d15);

  // (B0 + M8) -> [b0, 0, m8, NULL]
  m8 = graph()->NewNode(m_op, p1, d8);
  ADD_NONE_ADDRESSING_OPERAND_USES(m8);
  BaseWithIndexAndDisplacement32Matcher match114(
      graph()->NewNode(a_op, b0, m8));
  CheckBaseWithIndexAndDisplacement(&match114, b0, 0, m8, nullptr);

  // (M8 + B0) -> [b0, 0, m8, NULL]
  m8 = graph()->NewNode(m_op, p1, d8);
  ADD_NONE_ADDRESSING_OPERAND_USES(m8);
  BaseWithIndexAndDisplacement32Matcher match115(
      graph()->NewNode(a_op, m8, b0));
  CheckBaseWithIndexAndDisplacement(&match115, b0, 0, m8, nullptr);

  // (D15 + M8) -> [NULL, 0, m8, d15]
  m8 = graph()->NewNode(m_op, p1, d8);
  ADD_NONE_ADDRESSING_OPERAND_USES(m8);
  BaseWithIndexAndDisplacement32Matcher match116(
      graph()->NewNode(a_op, d15, m8));
  CheckBaseWithIndexAndDisplacement(&match116, nullptr, 0, m8, d15);

  // (M8 + D15) -> [NULL, 0, m8, d15]
  m8 = graph()->NewNode(m_op, p1, d8);
  ADD_NONE_ADDRESSING_OPERAND_USES(m8);
  BaseWithIndexAndDisplacement32Matcher match117(
      graph()->NewNode(a_op, m8, d15));
  CheckBaseWithIndexAndDisplacement(&match117, nullptr, 0, m8, d15);

  // (B0 + S3) -> [b0, 0, s3, NULL]
  s3 = graph()->NewNode(s_op, p1, d3);
  ADD_NONE_ADDRESSING_OPERAND_USES(s3);
  BaseWithIndexAndDisplacement32Matcher match118(
      graph()->NewNode(a_op, b0, s3));
  CheckBaseWithIndexAndDisplacement(&match118, b0, 0, s3, nullptr);

  // (S3 + B0) -> [b0, 0, s3, NULL]
  s3 = graph()->NewNode(s_op, p1, d3);
  ADD_NONE_ADDRESSING_OPERAND_USES(s3);
  BaseWithIndexAndDisplacement32Matcher match119(
      graph()->NewNode(a_op, s3, b0));
  CheckBaseWithIndexAndDisplacement(&match119, b0, 0, s3, nullptr);

  // (D15 + S3) -> [NULL, 0, s3, d15]
  s3 = graph()->NewNode(s_op, p1, d3);
  ADD_NONE_ADDRESSING_OPERAND_USES(s3);
  BaseWithIndexAndDisplacement32Matcher match120(
      graph()->NewNode(a_op, d15, s3));
  CheckBaseWithIndexAndDisplacement(&match120, nullptr, 0, s3, d15);

  // (S3 + D15) -> [NULL, 0, s3, d15]
  s3 = graph()->NewNode(s_op, p1, d3);
  ADD_NONE_ADDRESSING_OPERAND_USES(s3);
  BaseWithIndexAndDisplacement32Matcher match121(
      graph()->NewNode(a_op, s3, d15));
  CheckBaseWithIndexAndDisplacement(&match121, nullptr, 0, s3, d15);

  // (D15 + S3) + B0 -> [b0, 0, (D15 + S3), NULL]
  s3 = graph()->NewNode(s_op, p1, d3);
  temp = graph()->NewNode(a_op, d15, s3);
  ADD_NONE_ADDRESSING_OPERAND_USES(temp);
  BaseWithIndexAndDisplacement32Matcher match122(
      graph()->NewNode(a_op, temp, b0));
  CheckBaseWithIndexAndDisplacement(&match122, b0, 0, temp, nullptr);

  // (B0 + D15) + S3 -> [p1, 3, (B0 + D15), NULL]
  s3 = graph()->NewNode(s_op, p1, d3);
  temp = graph()->NewNode(a_op, b0, d15);
  ADD_NONE_ADDRESSING_OPERAND_USES(temp);
  BaseWithIndexAndDisplacement32Matcher match123(
      graph()->NewNode(a_op, temp, s3));
  CheckBaseWithIndexAndDisplacement(&match123, p1, 3, temp, nullptr);

  // (S3 + B0) + D15 -> [NULL, 0, (S3 + B0), d15]
  s3 = graph()->NewNode(s_op, p1, d3);
  temp = graph()->NewNode(a_op, s3, b0);
  ADD_NONE_ADDRESSING_OPERAND_USES(temp);
  BaseWithIndexAndDisplacement32Matcher match124(
      graph()->NewNode(a_op, temp, d15));
  CheckBaseWithIndexAndDisplacement(&match124, nullptr, 0, temp, d15);

  // D15 + (S3 + B0) -> [NULL, 0, (S3 + B0), d15]
  s3 = graph()->NewNode(s_op, p1, d3);
  temp = graph()->NewNode(a_op, s3, b0);
  ADD_NONE_ADDRESSING_OPERAND_USES(temp);
  BaseWithIndexAndDisplacement32Matcher match125(
      graph()->NewNode(a_op, d15, temp));
  CheckBaseWithIndexAndDisplacement(&match125, nullptr, 0, temp, d15);

  // B0 + (D15 + S3) -> [b0, 0, (D15 + S3), NULL]
  s3 = graph()->NewNode(s_op, p1, d3);
  temp = graph()->NewNode(a_op, d15, s3);
  ADD_NONE_ADDRESSING_OPERAND_USES(temp);
  BaseWithIndexAndDisplacement32Matcher match126(
      graph()->NewNode(a_op, b0, temp));
  CheckBaseWithIndexAndDisplacement(&match126, b0, 0, temp, nullptr);

  // S3 + (B0 + D15) -> [p1, 3, (B0 + D15), NULL]
  s3 = graph()->NewNode(s_op, p1, d3);
  temp = graph()->NewNode(a_op, b0, d15);
  ADD_NONE_ADDRESSING_OPERAND_USES(temp);
  BaseWithIndexAndDisplacement32Matcher match127(
      graph()->NewNode(a_op, s3, temp));
  CheckBaseWithIndexAndDisplacement(&match127, p1, 3, temp, nullptr);

  // S3 + (B0 - D15) -> [p1, 3, (B0 - D15), NULL]
  s3 = graph()->NewNode(s_op, p1, d3);
  temp = graph()->NewNode(sub_op, b0, d15);
  ADD_NONE_ADDRESSING_OPERAND_USES(temp);
  BaseWithIndexAndDisplacement32Matcher match128(
      graph()->NewNode(a_op, s3, temp));
  CheckBaseWithIndexAndDisplacement(&match128, p1, 3, temp, nullptr);

  // B0 + (B1 - D15) -> [b0, 0, (B1 - D15), NULL]
  temp = graph()->NewNode(sub_op, b1, d15);
  ADD_NONE_ADDRESSING_OPERAND_USES(temp);
  BaseWithIndexAndDisplacement32Matcher match129(
      graph()->NewNode(a_op, b0, temp));
  CheckBaseWithIndexAndDisplacement(&match129, b0, 0, temp, nullptr);

  // (B0 - D15) + S3 -> [p1, 3, temp, NULL]
  s3 = graph()->NewNode(s_op, p1, d3);
  temp = graph()->NewNode(sub_op, b0, d15);
  ADD_NONE_ADDRESSING_OPERAND_USES(temp);
  BaseWithIndexAndDisplacement32Matcher match130(
      graph()->NewNode(a_op, temp, s3));
  CheckBaseWithIndexAndDisplacement(&match130, p1, 3, temp, nullptr);

  // (B0 + B1) + D15 -> [NULL, 0, (B0 + B1), d15]
  temp = graph()->NewNode(a_op, b0, b1);
  ADD_NONE_ADDRESSING_OPERAND_USES(temp);
  BaseWithIndexAndDisplacement32Matcher match131(
      graph()->NewNode(a_op, temp, d15));
  CheckBaseWithIndexAndDisplacement(&match131, nullptr, 0, temp, d15);

  // D15 + (B0 + B1) -> [NULL, 0, (B0 + B1), d15]
  temp = graph()->NewNode(a_op, b0, b1);
  ADD_NONE_ADDRESSING_OPERAND_USES(temp);
  BaseWithIndexAndDisplacement32Matcher match132(
      graph()->NewNode(a_op, d15, temp));
  CheckBaseWithIndexAndDisplacement(&match132, nullptr, 0, temp, d15);
}


TEST_F(NodeMatcherTest, ScaledWithOffset64Matcher) {
  graph()->SetStart(graph()->NewNode(common()->Start(0)));

  const Operator* d0_op = common()->Int64Constant(0);
  Node* d0 = graph()->NewNode(d0_op);
  USE(d0);
  const Operator* d1_op = common()->Int64Constant(1);
  Node* d1 = graph()->NewNode(d1_op);
  USE(d1);
  const Operator* d2_op = common()->Int64Constant(2);
  Node* d2 = graph()->NewNode(d2_op);
  USE(d2);
  const Operator* d3_op = common()->Int64Constant(3);
  Node* d3 = graph()->NewNode(d3_op);
  USE(d3);
  const Operator* d4_op = common()->Int64Constant(4);
  Node* d4 = graph()->NewNode(d4_op);
  USE(d4);
  const Operator* d5_op = common()->Int64Constant(5);
  Node* d5 = graph()->NewNode(d5_op);
  USE(d5);
  const Operator* d7_op = common()->Int64Constant(7);
  Node* d7 = graph()->NewNode(d7_op);
  USE(d7);
  const Operator* d8_op = common()->Int64Constant(8);
  Node* d8 = graph()->NewNode(d8_op);
  USE(d8);
  const Operator* d9_op = common()->Int64Constant(9);
  Node* d9 = graph()->NewNode(d9_op);
  USE(d8);
  const Operator* d15_op = common()->Int64Constant(15);
  Node* d15 = graph()->NewNode(d15_op);
  USE(d15);
  const Operator* d15_32_op = common()->Int32Constant(15);
  Node* d15_32 = graph()->NewNode(d15_32_op);
  USE(d15_32);

  const Operator* b0_op = common()->Parameter(0);
  Node* b0 = graph()->NewNode(b0_op, graph()->start());
  USE(b0);
  const Operator* b1_op = common()->Parameter(1);
  Node* b1 = graph()->NewNode(b1_op, graph()->start());
  USE(b0);

  const Operator* p1_op = common()->Parameter(3);
  Node* p1 = graph()->NewNode(p1_op, graph()->start());
  USE(p1);

  const Operator* a_op = machine()->Int64Add();
  USE(a_op);

  const Operator* sub_op = machine()->Int64Sub();
  USE(sub_op);

  const Operator* m_op = machine()->Int64Mul();
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

  const Operator* s_op = machine()->Word64Shl();
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
  BaseWithIndexAndDisplacement64Matcher match0(d15);
  EXPECT_FALSE(match0.matches());

  // 2 INPUT

  // (B0 + B1) -> [B0, 0, B1, NULL]
  BaseWithIndexAndDisplacement64Matcher match1(graph()->NewNode(a_op, b0, b1));
  CheckBaseWithIndexAndDisplacement(&match1, b1, 0, b0, nullptr);

  // (B0 + D15) -> [NULL, 0, B0, D15]
  BaseWithIndexAndDisplacement64Matcher match2(graph()->NewNode(a_op, b0, d15));
  CheckBaseWithIndexAndDisplacement(&match2, nullptr, 0, b0, d15);

  BaseWithIndexAndDisplacement64Matcher match2_32(
      graph()->NewNode(a_op, b0, d15_32));
  CheckBaseWithIndexAndDisplacement(&match2_32, nullptr, 0, b0, d15_32);

  // (D15 + B0) -> [NULL, 0, B0, D15]
  BaseWithIndexAndDisplacement64Matcher match3(graph()->NewNode(a_op, d15, b0));
  CheckBaseWithIndexAndDisplacement(&match3, nullptr, 0, b0, d15);

  // (B0 + M1) -> [p1, 0, B0, NULL]
  BaseWithIndexAndDisplacement64Matcher match4(graph()->NewNode(a_op, b0, m1));
  CheckBaseWithIndexAndDisplacement(&match4, p1, 0, b0, nullptr);

  // (M1 + B0) -> [p1, 0, B0, NULL]
  m1 = graph()->NewNode(m_op, p1, d1);
  BaseWithIndexAndDisplacement64Matcher match5(graph()->NewNode(a_op, m1, b0));
  CheckBaseWithIndexAndDisplacement(&match5, p1, 0, b0, nullptr);

  // (D15 + M1) -> [P1, 0, NULL, D15]
  m1 = graph()->NewNode(m_op, p1, d1);
  BaseWithIndexAndDisplacement64Matcher match6(graph()->NewNode(a_op, d15, m1));
  CheckBaseWithIndexAndDisplacement(&match6, p1, 0, nullptr, d15);

  // (M1 + D15) -> [P1, 0, NULL, D15]
  m1 = graph()->NewNode(m_op, p1, d1);
  BaseWithIndexAndDisplacement64Matcher match7(graph()->NewNode(a_op, m1, d15));
  CheckBaseWithIndexAndDisplacement(&match7, p1, 0, nullptr, d15);

  // (B0 + S0) -> [p1, 0, B0, NULL]
  BaseWithIndexAndDisplacement64Matcher match8(graph()->NewNode(a_op, b0, s0));
  CheckBaseWithIndexAndDisplacement(&match8, p1, 0, b0, nullptr);

  // (S0 + B0) -> [p1, 0, B0, NULL]
  s0 = graph()->NewNode(s_op, p1, d0);
  BaseWithIndexAndDisplacement64Matcher match9(graph()->NewNode(a_op, s0, b0));
  CheckBaseWithIndexAndDisplacement(&match9, p1, 0, b0, nullptr);

  // (D15 + S0) -> [P1, 0, NULL, D15]
  s0 = graph()->NewNode(s_op, p1, d0);
  BaseWithIndexAndDisplacement64Matcher match10(
      graph()->NewNode(a_op, d15, s0));
  CheckBaseWithIndexAndDisplacement(&match10, p1, 0, nullptr, d15);

  // (S0 + D15) -> [P1, 0, NULL, D15]
  s0 = graph()->NewNode(s_op, p1, d0);
  BaseWithIndexAndDisplacement64Matcher match11(
      graph()->NewNode(a_op, s0, d15));
  CheckBaseWithIndexAndDisplacement(&match11, p1, 0, nullptr, d15);

  // (B0 + M2) -> [p1, 1, B0, NULL]
  BaseWithIndexAndDisplacement64Matcher match12(graph()->NewNode(a_op, b0, m2));
  CheckBaseWithIndexAndDisplacement(&match12, p1, 1, b0, nullptr);

  // (M2 + B0) -> [p1, 1, B0, NULL]
  m2 = graph()->NewNode(m_op, p1, d2);
  BaseWithIndexAndDisplacement64Matcher match13(graph()->NewNode(a_op, m2, b0));
  CheckBaseWithIndexAndDisplacement(&match13, p1, 1, b0, nullptr);

  // (D15 + M2) -> [P1, 1, NULL, D15]
  m2 = graph()->NewNode(m_op, p1, d2);
  BaseWithIndexAndDisplacement64Matcher match14(
      graph()->NewNode(a_op, d15, m2));
  CheckBaseWithIndexAndDisplacement(&match14, p1, 1, nullptr, d15);

  // (M2 + D15) -> [P1, 1, NULL, D15]
  m2 = graph()->NewNode(m_op, p1, d2);
  BaseWithIndexAndDisplacement64Matcher match15(
      graph()->NewNode(a_op, m2, d15));
  CheckBaseWithIndexAndDisplacement(&match15, p1, 1, nullptr, d15);

  // (B0 + S1) -> [p1, 1, B0, NULL]
  BaseWithIndexAndDisplacement64Matcher match16(graph()->NewNode(a_op, b0, s1));
  CheckBaseWithIndexAndDisplacement(&match16, p1, 1, b0, nullptr);

  // (S1 + B0) -> [p1, 1, B0, NULL]
  s1 = graph()->NewNode(s_op, p1, d1);
  BaseWithIndexAndDisplacement64Matcher match17(graph()->NewNode(a_op, s1, b0));
  CheckBaseWithIndexAndDisplacement(&match17, p1, 1, b0, nullptr);

  // (D15 + S1) -> [P1, 1, NULL, D15]
  s1 = graph()->NewNode(s_op, p1, d1);
  BaseWithIndexAndDisplacement64Matcher match18(
      graph()->NewNode(a_op, d15, s1));
  CheckBaseWithIndexAndDisplacement(&match18, p1, 1, nullptr, d15);

  // (S1 + D15) -> [P1, 1, NULL, D15]
  s1 = graph()->NewNode(s_op, p1, d1);
  BaseWithIndexAndDisplacement64Matcher match19(
      graph()->NewNode(a_op, s1, d15));
  CheckBaseWithIndexAndDisplacement(&match19, p1, 1, nullptr, d15);

  // (B0 + M4) -> [p1, 2, B0, NULL]
  BaseWithIndexAndDisplacement64Matcher match20(graph()->NewNode(a_op, b0, m4));
  CheckBaseWithIndexAndDisplacement(&match20, p1, 2, b0, nullptr);

  // (M4 + B0) -> [p1, 2, B0, NULL]
  m4 = graph()->NewNode(m_op, p1, d4);
  BaseWithIndexAndDisplacement64Matcher match21(graph()->NewNode(a_op, m4, b0));
  CheckBaseWithIndexAndDisplacement(&match21, p1, 2, b0, nullptr);

  // (D15 + M4) -> [p1, 2, NULL, D15]
  m4 = graph()->NewNode(m_op, p1, d4);
  BaseWithIndexAndDisplacement64Matcher match22(
      graph()->NewNode(a_op, d15, m4));
  CheckBaseWithIndexAndDisplacement(&match22, p1, 2, nullptr, d15);

  // (M4 + D15) -> [p1, 2, NULL, D15]
  m4 = graph()->NewNode(m_op, p1, d4);
  BaseWithIndexAndDisplacement64Matcher match23(
      graph()->NewNode(a_op, m4, d15));
  CheckBaseWithIndexAndDisplacement(&match23, p1, 2, nullptr, d15);

  // (B0 + S2) -> [p1, 2, B0, NULL]
  BaseWithIndexAndDisplacement64Matcher match24(graph()->NewNode(a_op, b0, s2));
  CheckBaseWithIndexAndDisplacement(&match24, p1, 2, b0, nullptr);

  // (S2 + B0) -> [p1, 2, B0, NULL]
  s2 = graph()->NewNode(s_op, p1, d2);
  BaseWithIndexAndDisplacement64Matcher match25(graph()->NewNode(a_op, s2, b0));
  CheckBaseWithIndexAndDisplacement(&match25, p1, 2, b0, nullptr);

  // (D15 + S2) -> [p1, 2, NULL, D15]
  s2 = graph()->NewNode(s_op, p1, d2);
  BaseWithIndexAndDisplacement64Matcher match26(
      graph()->NewNode(a_op, d15, s2));
  CheckBaseWithIndexAndDisplacement(&match26, p1, 2, nullptr, d15);

  // (S2 + D15) -> [p1, 2, NULL, D15]
  s2 = graph()->NewNode(s_op, p1, d2);
  BaseWithIndexAndDisplacement64Matcher match27(
      graph()->NewNode(a_op, s2, d15));
  CheckBaseWithIndexAndDisplacement(&match27, p1, 2, nullptr, d15);

  // (B0 + M8) -> [p1, 2, B0, NULL]
  BaseWithIndexAndDisplacement64Matcher match28(graph()->NewNode(a_op, b0, m8));
  CheckBaseWithIndexAndDisplacement(&match28, p1, 3, b0, nullptr);

  // (M8 + B0) -> [p1, 2, B0, NULL]
  m8 = graph()->NewNode(m_op, p1, d8);
  BaseWithIndexAndDisplacement64Matcher match29(graph()->NewNode(a_op, m8, b0));
  CheckBaseWithIndexAndDisplacement(&match29, p1, 3, b0, nullptr);

  // (D15 + M8) -> [p1, 2, NULL, D15]
  m8 = graph()->NewNode(m_op, p1, d8);
  BaseWithIndexAndDisplacement64Matcher match30(
      graph()->NewNode(a_op, d15, m8));
  CheckBaseWithIndexAndDisplacement(&match30, p1, 3, nullptr, d15);

  // (M8 + D15) -> [p1, 2, NULL, D15]
  m8 = graph()->NewNode(m_op, p1, d8);
  BaseWithIndexAndDisplacement64Matcher match31(
      graph()->NewNode(a_op, m8, d15));
  CheckBaseWithIndexAndDisplacement(&match31, p1, 3, nullptr, d15);

  // (B0 + S3) -> [p1, 2, B0, NULL]
  BaseWithIndexAndDisplacement64Matcher match32(graph()->NewNode(a_op, b0, s3));
  CheckBaseWithIndexAndDisplacement(&match32, p1, 3, b0, nullptr);

  // (S3 + B0) -> [p1, 2, B0, NULL]
  s3 = graph()->NewNode(s_op, p1, d3);
  BaseWithIndexAndDisplacement64Matcher match33(graph()->NewNode(a_op, s3, b0));
  CheckBaseWithIndexAndDisplacement(&match33, p1, 3, b0, nullptr);

  // (D15 + S3) -> [p1, 2, NULL, D15]
  s3 = graph()->NewNode(s_op, p1, d3);
  BaseWithIndexAndDisplacement64Matcher match34(
      graph()->NewNode(a_op, d15, s3));
  CheckBaseWithIndexAndDisplacement(&match34, p1, 3, nullptr, d15);

  // (S3 + D15) -> [p1, 2, NULL, D15]
  s3 = graph()->NewNode(s_op, p1, d3);
  BaseWithIndexAndDisplacement64Matcher match35(
      graph()->NewNode(a_op, s3, d15));
  CheckBaseWithIndexAndDisplacement(&match35, p1, 3, nullptr, d15);

  // 2 INPUT - NEGATIVE CASES

  // (M3 + B1) -> [B0, 0, M3, NULL]
  BaseWithIndexAndDisplacement64Matcher match36(graph()->NewNode(a_op, b1, m3));
  CheckBaseWithIndexAndDisplacement(&match36, m3, 0, b1, nullptr);

  // (S4 + B1) -> [B0, 0, S4, NULL]
  BaseWithIndexAndDisplacement64Matcher match37(graph()->NewNode(a_op, b1, s4));
  CheckBaseWithIndexAndDisplacement(&match37, s4, 0, b1, nullptr);

  // 3 INPUT

  // (D15 + S3) + B0 -> [p1, 2, b0, d15]
  s3 = graph()->NewNode(s_op, p1, d3);
  BaseWithIndexAndDisplacement64Matcher match38(
      graph()->NewNode(a_op, graph()->NewNode(a_op, d15, s3), b0));
  CheckBaseWithIndexAndDisplacement(&match38, p1, 3, b0, d15);

  // (B0 + D15) + S3 -> [p1, 2, b0, d15]
  s3 = graph()->NewNode(s_op, p1, d3);
  BaseWithIndexAndDisplacement64Matcher match39(
      graph()->NewNode(a_op, graph()->NewNode(a_op, b0, d15), s3));
  CheckBaseWithIndexAndDisplacement(&match39, p1, 3, b0, d15);

  // (S3 + B0) + D15 -> [p1, 2, b0, d15]
  s3 = graph()->NewNode(s_op, p1, d3);
  BaseWithIndexAndDisplacement64Matcher match40(
      graph()->NewNode(a_op, graph()->NewNode(a_op, s3, b0), d15));
  CheckBaseWithIndexAndDisplacement(&match40, p1, 3, b0, d15);

  // D15 + (S3 + B0) -> [p1, 2, b0, d15]
  s3 = graph()->NewNode(s_op, p1, d3);
  BaseWithIndexAndDisplacement64Matcher match41(
      graph()->NewNode(a_op, d15, graph()->NewNode(a_op, s3, b0)));
  CheckBaseWithIndexAndDisplacement(&match41, p1, 3, b0, d15);

  // B0 + (D15 + S3) -> [p1, 2, b0, d15]
  s3 = graph()->NewNode(s_op, p1, d3);
  BaseWithIndexAndDisplacement64Matcher match42(
      graph()->NewNode(a_op, b0, graph()->NewNode(a_op, d15, s3)));
  CheckBaseWithIndexAndDisplacement(&match42, p1, 3, b0, d15);

  // S3 + (B0 + D15) -> [p1, 2, b0, d15]
  s3 = graph()->NewNode(s_op, p1, d3);
  BaseWithIndexAndDisplacement64Matcher match43(
      graph()->NewNode(a_op, s3, graph()->NewNode(a_op, b0, d15)));
  CheckBaseWithIndexAndDisplacement(&match43, p1, 3, b0, d15);

  // 2 INPUT with non-power of 2 scale

  // (M3 + D15) -> [p1, 1, p1, D15]
  m3 = graph()->NewNode(m_op, p1, d3);
  BaseWithIndexAndDisplacement64Matcher match44(
      graph()->NewNode(a_op, m3, d15));
  CheckBaseWithIndexAndDisplacement(&match44, p1, 1, p1, d15);

  // (M5 + D15) -> [p1, 2, p1, D15]
  m5 = graph()->NewNode(m_op, p1, d5);
  BaseWithIndexAndDisplacement64Matcher match45(
      graph()->NewNode(a_op, m5, d15));
  CheckBaseWithIndexAndDisplacement(&match45, p1, 2, p1, d15);

  // (M9 + D15) -> [p1, 3, p1, D15]
  m9 = graph()->NewNode(m_op, p1, d9);
  BaseWithIndexAndDisplacement64Matcher match46(
      graph()->NewNode(a_op, m9, d15));
  CheckBaseWithIndexAndDisplacement(&match46, p1, 3, p1, d15);

  // 3 INPUT negative cases: non-power of 2 scale but with a base

  // ((M3 + B0) + D15) -> [m3, 0, b0, D15]
  m3 = graph()->NewNode(m_op, p1, d3);
  Node* temp = graph()->NewNode(a_op, m3, b0);
  BaseWithIndexAndDisplacement64Matcher match47(
      graph()->NewNode(a_op, temp, d15));
  CheckBaseWithIndexAndDisplacement(&match47, m3, 0, b0, d15);

  // (M3 + (B0 + D15)) -> [m3, 0, b0, D15]
  m3 = graph()->NewNode(m_op, p1, d3);
  temp = graph()->NewNode(a_op, d15, b0);
  BaseWithIndexAndDisplacement64Matcher match48(
      graph()->NewNode(a_op, m3, temp));
  CheckBaseWithIndexAndDisplacement(&match48, m3, 0, b0, d15);

  // ((B0 + M3) + D15) -> [m3, 0, b0, D15]
  m3 = graph()->NewNode(m_op, p1, d3);
  temp = graph()->NewNode(a_op, b0, m3);
  BaseWithIndexAndDisplacement64Matcher match49(
      graph()->NewNode(a_op, temp, d15));
  CheckBaseWithIndexAndDisplacement(&match49, m3, 0, b0, d15);

  // (M3 + (D15 + B0)) -> [m3, 0, b0, D15]
  m3 = graph()->NewNode(m_op, p1, d3);
  temp = graph()->NewNode(a_op, b0, d15);
  BaseWithIndexAndDisplacement64Matcher match50(
      graph()->NewNode(a_op, m3, temp));
  CheckBaseWithIndexAndDisplacement(&match50, m3, 0, b0, d15);

  // S3 + (B0 - D15) -> [p1, 2, b0, d15, true]
  s3 = graph()->NewNode(s_op, p1, d3);
  BaseWithIndexAndDisplacement64Matcher match51(
      graph()->NewNode(a_op, s3, graph()->NewNode(sub_op, b0, d15)));
  CheckBaseWithIndexAndDisplacement(&match51, p1, 3, b0, d15,
                                    kNegativeDisplacement);

  // B0 + (B1 - D15) -> [p1, 2, b0, d15, true]
  BaseWithIndexAndDisplacement64Matcher match52(
      graph()->NewNode(a_op, b0, graph()->NewNode(sub_op, b1, d15)));
  CheckBaseWithIndexAndDisplacement(&match52, b1, 0, b0, d15,
                                    kNegativeDisplacement);

  // (B0 - D15) + S3 -> [p1, 2, b0, d15, true]
  s3 = graph()->NewNode(s_op, p1, d3);
  BaseWithIndexAndDisplacement64Matcher match53(
      graph()->NewNode(a_op, graph()->NewNode(sub_op, b0, d15), s3));
  CheckBaseWithIndexAndDisplacement(&match53, p1, 3, b0, d15,
                                    kNegativeDisplacement);

  // 4 INPUT - with addressing operand uses

  // (B0 + M1) -> [p1, 0, B0, NULL]
  m1 = graph()->NewNode(m_op, p1, d1);
  ADD_ADDRESSING_OPERAND_USES(m1);
  BaseWithIndexAndDisplacement64Matcher match54(graph()->NewNode(a_op, b0, m1));
  CheckBaseWithIndexAndDisplacement(&match54, p1, 0, b0, nullptr);

  // (M1 + B0) -> [p1, 0, B0, NULL]
  m1 = graph()->NewNode(m_op, p1, d1);
  ADD_ADDRESSING_OPERAND_USES(m1);
  BaseWithIndexAndDisplacement64Matcher match55(graph()->NewNode(a_op, m1, b0));
  CheckBaseWithIndexAndDisplacement(&match55, p1, 0, b0, nullptr);

  // (D15 + M1) -> [P1, 0, NULL, D15]
  m1 = graph()->NewNode(m_op, p1, d1);
  ADD_ADDRESSING_OPERAND_USES(m1);
  BaseWithIndexAndDisplacement64Matcher match56(
      graph()->NewNode(a_op, d15, m1));
  CheckBaseWithIndexAndDisplacement(&match56, p1, 0, nullptr, d15);

  // (M1 + D15) -> [P1, 0, NULL, D15]
  m1 = graph()->NewNode(m_op, p1, d1);
  ADD_ADDRESSING_OPERAND_USES(m1);
  BaseWithIndexAndDisplacement64Matcher match57(
      graph()->NewNode(a_op, m1, d15));
  CheckBaseWithIndexAndDisplacement(&match57, p1, 0, nullptr, d15);

  // (B0 + S0) -> [p1, 0, B0, NULL]
  s0 = graph()->NewNode(s_op, p1, d0);
  ADD_ADDRESSING_OPERAND_USES(s0);
  BaseWithIndexAndDisplacement64Matcher match58(graph()->NewNode(a_op, b0, s0));
  CheckBaseWithIndexAndDisplacement(&match58, p1, 0, b0, nullptr);

  // (S0 + B0) -> [p1, 0, B0, NULL]
  s0 = graph()->NewNode(s_op, p1, d0);
  ADD_ADDRESSING_OPERAND_USES(s0);
  BaseWithIndexAndDisplacement64Matcher match59(graph()->NewNode(a_op, s0, b0));
  CheckBaseWithIndexAndDisplacement(&match59, p1, 0, b0, nullptr);

  // (D15 + S0) -> [P1, 0, NULL, D15]
  s0 = graph()->NewNode(s_op, p1, d0);
  ADD_ADDRESSING_OPERAND_USES(s0);
  BaseWithIndexAndDisplacement64Matcher match60(
      graph()->NewNode(a_op, d15, s0));
  CheckBaseWithIndexAndDisplacement(&match60, p1, 0, nullptr, d15);

  // (S0 + D15) -> [P1, 0, NULL, D15]
  s0 = graph()->NewNode(s_op, p1, d0);
  ADD_ADDRESSING_OPERAND_USES(s0);
  BaseWithIndexAndDisplacement64Matcher match61(
      graph()->NewNode(a_op, s0, d15));
  CheckBaseWithIndexAndDisplacement(&match61, p1, 0, nullptr, d15);

  // (B0 + M2) -> [p1, 1, B0, NULL]
  m2 = graph()->NewNode(m_op, p1, d2);
  ADD_ADDRESSING_OPERAND_USES(m2);
  BaseWithIndexAndDisplacement64Matcher match62(graph()->NewNode(a_op, b0, m2));
  CheckBaseWithIndexAndDisplacement(&match62, p1, 1, b0, nullptr);

  // (M2 + B0) -> [p1, 1, B0, NULL]
  m2 = graph()->NewNode(m_op, p1, d2);
  ADD_ADDRESSING_OPERAND_USES(m2);
  BaseWithIndexAndDisplacement64Matcher match63(graph()->NewNode(a_op, m2, b0));
  CheckBaseWithIndexAndDisplacement(&match63, p1, 1, b0, nullptr);

  // (D15 + M2) -> [P1, 1, NULL, D15]
  m2 = graph()->NewNode(m_op, p1, d2);
  ADD_ADDRESSING_OPERAND_USES(m2);
  BaseWithIndexAndDisplacement64Matcher match64(
      graph()->NewNode(a_op, d15, m2));
  CheckBaseWithIndexAndDisplacement(&match64, p1, 1, nullptr, d15);

  // (M2 + D15) -> [P1, 1, NULL, D15]
  m2 = graph()->NewNode(m_op, p1, d2);
  ADD_ADDRESSING_OPERAND_USES(m2);
  BaseWithIndexAndDisplacement64Matcher match65(
      graph()->NewNode(a_op, m2, d15));
  CheckBaseWithIndexAndDisplacement(&match65, p1, 1, nullptr, d15);

  // (B0 + S1) -> [p1, 1, B0, NULL]
  s1 = graph()->NewNode(s_op, p1, d1);
  ADD_ADDRESSING_OPERAND_USES(s1);
  BaseWithIndexAndDisplacement64Matcher match66(graph()->NewNode(a_op, b0, s1));
  CheckBaseWithIndexAndDisplacement(&match66, p1, 1, b0, nullptr);

  // (S1 + B0) -> [p1, 1, B0, NULL]
  s1 = graph()->NewNode(s_op, p1, d1);
  ADD_ADDRESSING_OPERAND_USES(s1);
  BaseWithIndexAndDisplacement64Matcher match67(graph()->NewNode(a_op, s1, b0));
  CheckBaseWithIndexAndDisplacement(&match67, p1, 1, b0, nullptr);

  // (D15 + S1) -> [P1, 1, NULL, D15]
  s1 = graph()->NewNode(s_op, p1, d1);
  ADD_ADDRESSING_OPERAND_USES(s1);
  BaseWithIndexAndDisplacement64Matcher match68(
      graph()->NewNode(a_op, d15, s1));
  CheckBaseWithIndexAndDisplacement(&match68, p1, 1, nullptr, d15);

  // (S1 + D15) -> [P1, 1, NULL, D15]
  s1 = graph()->NewNode(s_op, p1, d1);
  ADD_ADDRESSING_OPERAND_USES(s1);
  BaseWithIndexAndDisplacement64Matcher match69(
      graph()->NewNode(a_op, s1, d15));
  CheckBaseWithIndexAndDisplacement(&match69, p1, 1, nullptr, d15);

  // (B0 + M4) -> [p1, 2, B0, NULL]
  m4 = graph()->NewNode(m_op, p1, d4);
  ADD_ADDRESSING_OPERAND_USES(m4);
  BaseWithIndexAndDisplacement64Matcher match70(graph()->NewNode(a_op, b0, m4));
  CheckBaseWithIndexAndDisplacement(&match70, p1, 2, b0, nullptr);

  // (M4 + B0) -> [p1, 2, B0, NULL]
  m4 = graph()->NewNode(m_op, p1, d4);
  ADD_ADDRESSING_OPERAND_USES(m4);
  BaseWithIndexAndDisplacement64Matcher match71(graph()->NewNode(a_op, m4, b0));
  CheckBaseWithIndexAndDisplacement(&match71, p1, 2, b0, nullptr);

  // (D15 + M4) -> [p1, 2, NULL, D15]
  m4 = graph()->NewNode(m_op, p1, d4);
  ADD_ADDRESSING_OPERAND_USES(m4);
  BaseWithIndexAndDisplacement64Matcher match72(
      graph()->NewNode(a_op, d15, m4));
  CheckBaseWithIndexAndDisplacement(&match72, p1, 2, nullptr, d15);

  // (M4 + D15) -> [p1, 2, NULL, D15]
  m4 = graph()->NewNode(m_op, p1, d4);
  ADD_ADDRESSING_OPERAND_USES(m4);
  BaseWithIndexAndDisplacement64Matcher match73(
      graph()->NewNode(a_op, m4, d15));
  CheckBaseWithIndexAndDisplacement(&match73, p1, 2, nullptr, d15);

  // (B0 + S2) -> [p1, 2, B0, NULL]
  s2 = graph()->NewNode(s_op, p1, d2);
  ADD_ADDRESSING_OPERAND_USES(s2);
  BaseWithIndexAndDisplacement64Matcher match74(graph()->NewNode(a_op, b0, s2));
  CheckBaseWithIndexAndDisplacement(&match74, p1, 2, b0, nullptr);

  // (S2 + B0) -> [p1, 2, B0, NULL]
  s2 = graph()->NewNode(s_op, p1, d2);
  ADD_ADDRESSING_OPERAND_USES(s2);
  BaseWithIndexAndDisplacement64Matcher match75(graph()->NewNode(a_op, s2, b0));
  CheckBaseWithIndexAndDisplacement(&match75, p1, 2, b0, nullptr);

  // (D15 + S2) -> [p1, 2, NULL, D15]
  s2 = graph()->NewNode(s_op, p1, d2);
  ADD_ADDRESSING_OPERAND_USES(s2);
  BaseWithIndexAndDisplacement64Matcher match76(
      graph()->NewNode(a_op, d15, s2));
  CheckBaseWithIndexAndDisplacement(&match76, p1, 2, nullptr, d15);

  // (S2 + D15) -> [p1, 2, NULL, D15]
  s2 = graph()->NewNode(s_op, p1, d2);
  ADD_ADDRESSING_OPERAND_USES(s2);
  BaseWithIndexAndDisplacement64Matcher match77(
      graph()->NewNode(a_op, s2, d15));
  CheckBaseWithIndexAndDisplacement(&match77, p1, 2, nullptr, d15);

  // (B0 + M8) -> [p1, 2, B0, NULL]
  m8 = graph()->NewNode(m_op, p1, d8);
  ADD_ADDRESSING_OPERAND_USES(m8);
  BaseWithIndexAndDisplacement64Matcher match78(graph()->NewNode(a_op, b0, m8));
  CheckBaseWithIndexAndDisplacement(&match78, p1, 3, b0, nullptr);

  // (M8 + B0) -> [p1, 2, B0, NULL]
  m8 = graph()->NewNode(m_op, p1, d8);
  ADD_ADDRESSING_OPERAND_USES(m8);
  BaseWithIndexAndDisplacement64Matcher match79(graph()->NewNode(a_op, m8, b0));
  CheckBaseWithIndexAndDisplacement(&match79, p1, 3, b0, nullptr);

  // (D15 + M8) -> [p1, 2, NULL, D15]
  m8 = graph()->NewNode(m_op, p1, d8);
  ADD_ADDRESSING_OPERAND_USES(m8);
  BaseWithIndexAndDisplacement64Matcher match80(
      graph()->NewNode(a_op, d15, m8));
  CheckBaseWithIndexAndDisplacement(&match80, p1, 3, nullptr, d15);

  // (M8 + D15) -> [p1, 2, NULL, D15]
  m8 = graph()->NewNode(m_op, p1, d8);
  ADD_ADDRESSING_OPERAND_USES(m8);
  BaseWithIndexAndDisplacement64Matcher match81(
      graph()->NewNode(a_op, m8, d15));
  CheckBaseWithIndexAndDisplacement(&match81, p1, 3, nullptr, d15);

  // (B0 + S3) -> [p1, 2, B0, NULL]
  s3 = graph()->NewNode(s_op, p1, d3);
  ADD_ADDRESSING_OPERAND_USES(s3);
  BaseWithIndexAndDisplacement64Matcher match82(graph()->NewNode(a_op, b0, s3));
  CheckBaseWithIndexAndDisplacement(&match82, p1, 3, b0, nullptr);

  // (S3 + B0) -> [p1, 2, B0, NULL]
  s3 = graph()->NewNode(s_op, p1, d3);
  ADD_ADDRESSING_OPERAND_USES(s3);
  BaseWithIndexAndDisplacement64Matcher match83(graph()->NewNode(a_op, s3, b0));
  CheckBaseWithIndexAndDisplacement(&match83, p1, 3, b0, nullptr);

  // (D15 + S3) -> [p1, 2, NULL, D15]
  s3 = graph()->NewNode(s_op, p1, d3);
  ADD_ADDRESSING_OPERAND_USES(s3);
  BaseWithIndexAndDisplacement64Matcher match84(
      graph()->NewNode(a_op, d15, s3));
  CheckBaseWithIndexAndDisplacement(&match84, p1, 3, nullptr, d15);

  // (S3 + D15) -> [p1, 2, NULL, D15]
  s3 = graph()->NewNode(s_op, p1, d3);
  ADD_ADDRESSING_OPERAND_USES(s3);
  BaseWithIndexAndDisplacement64Matcher match85(
      graph()->NewNode(a_op, s3, d15));
  CheckBaseWithIndexAndDisplacement(&match85, p1, 3, nullptr, d15);

  // (D15 + S3) + B0 -> [p1, 2, b0, d15]
  s3 = graph()->NewNode(s_op, p1, d3);
  temp = graph()->NewNode(a_op, d15, s3);
  ADD_ADDRESSING_OPERAND_USES(temp);
  BaseWithIndexAndDisplacement64Matcher match86(
      graph()->NewNode(a_op, temp, b0));
  CheckBaseWithIndexAndDisplacement(&match86, p1, 3, b0, d15);

  // (B0 + D15) + S3 -> [p1, 2, b0, d15]
  s3 = graph()->NewNode(s_op, p1, d3);
  temp = graph()->NewNode(a_op, b0, d15);
  ADD_ADDRESSING_OPERAND_USES(temp);
  BaseWithIndexAndDisplacement64Matcher match87(
      graph()->NewNode(a_op, temp, s3));
  CheckBaseWithIndexAndDisplacement(&match87, p1, 3, b0, d15);

  // (S3 + B0) + D15 -> [NULL, 0, (s3 + b0), d15]
  // Avoid changing simple addressing to complex addressing
  s3 = graph()->NewNode(s_op, p1, d3);
  temp = graph()->NewNode(a_op, s3, b0);
  ADD_ADDRESSING_OPERAND_USES(temp);
  BaseWithIndexAndDisplacement64Matcher match88(
      graph()->NewNode(a_op, temp, d15));
  CheckBaseWithIndexAndDisplacement(&match88, nullptr, 0, temp, d15);

  // D15 + (S3 + B0) -> [NULL, 0, (s3 + b0), d15]
  // Avoid changing simple addressing to complex addressing
  s3 = graph()->NewNode(s_op, p1, d3);
  temp = graph()->NewNode(a_op, s3, b0);
  ADD_ADDRESSING_OPERAND_USES(temp);
  BaseWithIndexAndDisplacement64Matcher match89(
      graph()->NewNode(a_op, d15, temp));
  CheckBaseWithIndexAndDisplacement(&match89, nullptr, 0, temp, d15);

  // B0 + (D15 + S3) -> [p1, 2, b0, d15]
  s3 = graph()->NewNode(s_op, p1, d3);
  temp = graph()->NewNode(a_op, d15, s3);
  ADD_ADDRESSING_OPERAND_USES(temp);
  BaseWithIndexAndDisplacement64Matcher match90(
      graph()->NewNode(a_op, b0, temp));
  CheckBaseW
```