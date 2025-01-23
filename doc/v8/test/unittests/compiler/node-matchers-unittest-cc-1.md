Response:
Let's break down the thought process for analyzing this C++ code snippet.

1. **Understanding the Goal:** The overarching goal is to understand the functionality of the provided C++ code. The prompt also includes specific requests regarding its relationship to JavaScript, potential programming errors, and its role within a larger context (being part 2 of 3).

2. **Initial Assessment:**  The code uses the Google Test framework (`TEST_F`, `EXPECT_FALSE`) and seems to be testing a class or set of functions related to "node matchers". The class `NodeMatcherTest` suggests this is a unit test. The numerous `BaseWithIndexAndDisplacement32Matcher` and `BaseWithIndexAndDisplacement64Matcher` instances and calls to `CheckBaseWithIndexAndDisplacement` strongly indicate the code is verifying the correct identification and decomposition of memory addressing patterns within an intermediate representation (likely a compiler IR).

3. **Identifying Key Entities:**  Recognize the significant variables and functions:
    * `graph()`:  Likely provides access to the compiler's graph representation.
    * `NewNode()`:  Used to create new nodes in the graph.
    * `common()->...` and `machine()->...`: These seem to create different types of operations/nodes, hinting at different abstraction levels (common optimizations vs. machine-specific instructions).
    * `Int32Constant`, `Int64Constant`: Create constant value nodes.
    * `Parameter`: Represents input parameters.
    * `Int32Add`, `Int64Add`, `Int64Sub`, `Word64Shl`, `Int64Mul`:  Represent arithmetic and bitwise operations.
    * `BaseWithIndexAndDisplacement32Matcher`, `BaseWithIndexAndDisplacement64Matcher`: The core classes being tested, responsible for recognizing addressing patterns.
    * `CheckBaseWithIndexAndDisplacement()`: A helper function to verify the matcher's output.
    * `ADD_NONE_ADDRESSING_OPERAND_USES`, `ADD_ADDRESSING_OPERAND_USES`:  Seem to manage how nodes are used (important for optimization and correctness).

4. **Dissecting the Test Cases:**  Focus on the structure of individual test cases. They generally follow a pattern:
    * Create input nodes (constants, parameters, and intermediate operation nodes).
    * Create a `Matcher` object, passing in a complex expression (usually an addition).
    * Call `CheckBaseWithIndexAndDisplacement()` to assert the matcher correctly extracts the base, index, scale, and displacement.

5. **Inferring Addressing Modes:** By observing the patterns in `NewNode(a_op, ...)` and the parameters to `CheckBaseWithIndexAndDisplacement`, deduce the addressing modes being tested:
    * `base + index`:  E.g., `b0 + b1`
    * `base + displacement`: E.g., `b0 + d15`
    * `displacement + base`: E.g., `d15 + b0`
    * `base + scaled_index`: E.g., `b0 + m1` (where `m1` is a multiplication, representing scaling)
    * `scaled_index + base`: E.g., `m1 + b0`
    * combinations and nested expressions.

6. **Understanding the Matcher's Behavior:** The `CheckBaseWithIndexAndDisplacement` function provides crucial information about the matcher's logic. The order of parameters (`base`, `scale`, `index`, `displacement`) reveals how the matcher decomposes the input expression. The presence of `nullptr` indicates the absence of a particular component.

7. **Considering the "Why":**  Think about *why* this kind of testing is necessary in a compiler. Recognizing addressing modes is essential for:
    * **Instruction Selection:** Mapping high-level operations to efficient machine instructions.
    * **Optimization:**  Applying optimizations specific to certain addressing patterns.
    * **Code Generation:**  Generating correct memory access code.

8. **Addressing Specific Prompts:**
    * **Functionality:** Summarize the core task: testing the ability to match and decompose memory addressing patterns.
    * **.tq Extension:** Recognize this isn't a Torque file based on the C++ syntax.
    * **JavaScript Relationship:** Connect the concept of memory access to JavaScript's array and object property access, but acknowledge the abstraction difference. Provide a simple JavaScript example illustrating the underlying concept.
    * **Code Logic Inference:**  Create a simplified input scenario and predict the output based on the observed patterns.
    * **Common Programming Errors:**  Relate the matcher's purpose to common errors like incorrect pointer arithmetic or out-of-bounds access in languages like C/C++, and how JavaScript prevents some of these through its memory management.
    * **Part 2 Summary:**  Emphasize the focus on more complex addressing modes and the introduction of 64-bit matchers compared to the previous part (even without seeing part 1, this can be inferred).

9. **Structuring the Answer:** Organize the findings into clear sections addressing each part of the prompt. Use bullet points, code examples, and clear explanations to make the information easy to understand.

10. **Refinement and Review:** Read through the answer to ensure accuracy, clarity, and completeness. Double-check the code examples and explanations. For instance, initially, one might focus too much on the specific operators (`Int64Add`, etc.) but realizing they are just *examples* of nodes being combined is important. The core function is the *matching* of the address structure.
好的，这是对提供的代码片段的功能归纳：

**功能归纳：**

这段代码是 `v8/test/unittests/compiler/node-matchers-unittest.cc` 文件的一部分，专门测试 `BaseWithIndexAndDisplacement32Matcher` 和 `BaseWithIndexAndDisplacement64Matcher` 这两个类的功能。这两个 matcher 的作用是尝试在 V8 的编译器中间表示（通常是一个图结构）中，识别出符合特定模式的节点，这些模式代表了带有基址、索引（可选）和位移（可选）的内存寻址方式。

具体来说，这段代码测试了以下场景：

1. **`BaseWithIndexAndDisplacement32Matcher` 测试：**
   - 针对不同的节点组合，测试 `BaseWithIndexAndDisplacement32Matcher` 是否能正确地将它们分解为基址（base）、比例因子（scale，对于索引）、索引（index）和位移（displacement）。
   - 测试了各种基址、索引和位移的组合，包括：
     - 基址寄存器 (B0, B1)
     - 比例化的索引寄存器 (M4, M8，分别代表乘以 4 和 8)
     - 移位索引寄存器 (S2, S3，分别代表左移 2 位和 3 位)
     - 立即数位移 (D15)
   - 测试了操作数的顺序对匹配结果的影响。
   - 测试了嵌套的加法运算。
   - 测试了减法运算作为位移的情况。
   - 重点关注了匹配成功后，各个组成部分（基址、比例因子、索引、位移）是否被正确提取出来。
   - 使用 `ADD_NONE_ADDRESSING_OPERAND_USES` 标记了某些中间节点不会被用作直接的内存寻址操作数。

2. **`BaseWithIndexAndDisplacement64Matcher` 测试：**
   - 与 32 位 matcher 类似，测试了 `BaseWithIndexAndDisplacement64Matcher` 在 64 位场景下的匹配能力。
   - 使用了 64 位的常量 (`Int64Constant`) 和操作 (`Int64Add`, `Int64Sub`, `Word64Shl`, `Int64Mul`)。
   - 测试了与 32 位 matcher 相似的各种基址、索引和位移的组合。
   - 特别测试了比例因子为 1, 2, 4, 8 的情况。
   - 包含了负面测试用例，即故意构造不匹配的表达式，验证 matcher 能正确返回不匹配。
   - 测试了非 2 的幂次的比例因子的情况。
   - 使用了 `ADD_ADDRESSING_OPERAND_USES` 标记了某些中间节点会被用作内存寻址操作数。这可能会影响某些优化或代码生成的决策。

**总结这段代码的功能：**

这段代码主要负责**详尽地测试了 `BaseWithIndexAndDisplacement32Matcher` 和 `BaseWithIndexAndDisplacement64Matcher` 这两个 V8 编译器内部用于识别和分解内存寻址模式的工具类。** 它通过构建各种可能的寻址表达式，并断言 matcher 能正确地解析出基址、索引、比例因子和位移，确保了编译器在处理内存访问相关的操作时能够准确地识别这些模式，为后续的优化和代码生成奠定基础。

**关于其他问题的回答：**

* **`.tq` 结尾：**  `v8/test/unittests/compiler/node-matchers-unittest.cc` 是一个 `.cc` 文件，表示它是一个 C++ 源代码文件，而不是 Torque (`.tq`) 文件。Torque 是 V8 用于定义内置函数的一种领域特定语言。

* **与 JavaScript 的关系：**  虽然这段 C++ 代码本身不直接是 JavaScript 代码，但它与 JavaScript 的功能有密切关系。JavaScript 在运行时需要访问内存来存储变量、对象属性等。V8 编译器负责将 JavaScript 代码转换为机器码，其中就包括生成内存访问指令。`BaseWithIndexAndDisplacementMatcher` 的作用就是帮助编译器理解和优化这些内存访问操作。

   **JavaScript 示例：**

   ```javascript
   const arr = [1, 2, 3, 4, 5];
   const index = 2;
   const value = arr[index + 1]; // 访问数组元素

   const obj = { a: 10, b: 20 };
   const propName = 'a';
   const propValue = obj[propName]; // 访问对象属性
   ```

   在编译 `arr[index + 1]` 这样的 JavaScript 代码时，V8 编译器内部就会涉及到识别基址（数组 `arr` 的起始地址）、索引（`index` 的值加 1）以及可能的比例因子（取决于数组元素的大小）。`BaseWithIndexAndDisplacementMatcher` 就是在编译器的这个阶段发挥作用。

* **代码逻辑推理（假设输入与输出）：**

   **假设输入（对于 `BaseWithIndexAndDisplacement32Matcher`）：**

   一个代表表达式 `(B0 + M4) + D15` 的 V8 编译器节点图，其中：
   - `B0` 是一个基址寄存器节点。
   - `M4` 是一个比例化索引寄存器节点，代表 `p1 * 4`。
   - `D15` 是一个立即数位移节点，值为 15。

   **预期输出：**

   `CheckBaseWithIndexAndDisplacement` 函数会断言 matcher 提取出的信息如下：
   - `base`: `B0`
   - `scale`: 2 (因为 M4 代表乘以 4，是 2 的 2 次方)
   - `index`: `p1` (M4 的操作数)
   - `displacement`: `D15` (值为 15)

* **涉及用户常见的编程错误：**

   虽然这段代码是编译器内部的测试，但它反映了与内存访问相关的常见编程错误，尤其是在像 C/C++ 这样的语言中：

   **示例 (C++)：**

   ```c++
   int arr[10];
   int i = 2;
   int* ptr = arr + i * 4 + 5; // 尝试计算指针地址

   // 常见错误：
   // 1. 错误的比例因子：忘记乘以元素大小。
   // 2. 越界访问：i 的值过大或过小导致访问超出数组边界。
   // 3. 指针类型不匹配：假设 arr 是其他类型的数组。
   ```

   `BaseWithIndexAndDisplacementMatcher` 的正确性有助于确保 V8 编译器在处理类似 JavaScript 数组访问时，能生成正确的机器码，从而避免这些潜在的运行时错误。虽然 JavaScript 有内存管理机制，不容易出现 C/C++ 那样的直接内存错误，但理解底层的寻址方式对于优化性能仍然重要。

### 提示词
```
这是目录为v8/test/unittests/compiler/node-matchers-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/node-matchers-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
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