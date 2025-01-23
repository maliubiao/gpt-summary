Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of V8's redundancy elimination unit tests.

Here's a breakdown of the code's actions and structure:

1. **Test Fixture:** The code uses `TEST_F(RedundancyEliminationTest, ...)` which indicates it's a series of tests within a test fixture named `RedundancyEliminationTest`. This suggests the tests are designed to verify the behavior of a redundancy elimination optimization pass in the V8 compiler.

2. **Test Cases:** Each `TEST_F` block represents an individual test case. The names of the test cases provide clues about what they are testing. For example, `SpeculativeNumberLessThanWithCheckBoundsBetterType` suggests a scenario involving speculative number comparisons and bounds checks.

3. **Graph Construction:** Within each test case, the code constructs a simplified representation of an abstract syntax tree (AST) or intermediate representation (IR) using nodes (`Node*`). This graph represents a small piece of code.

4. **Nodes and Operations:** The code creates various nodes representing operations like:
    - `Parameter`: Represents function parameters.
    - `CheckBounds`: Represents a check to ensure an index is within the bounds of an array.
    - `SpeculativeNumberLessThan`, `SpeculativeNumberLessThanOrEqual`, `SpeculativeNumberAdd`, `SpeculativeNumberSubtract`, `SpeculativeSafeIntegerAdd`, `SpeculativeSafeIntegerSubtract`, `SpeculativeToNumber`:  These represent speculative versions of arithmetic and conversion operations. The "Speculative" prefix indicates that these operations might have different implementations depending on the actual types of the operands at runtime.
    - `simplified()->...`:  This indicates that these nodes belong to the "Simplified" IR of the V8 compiler.

5. **Redundancy Elimination:** The core of the tests revolves around the `Reduce()` method. This method simulates the redundancy elimination pass attempting to simplify the graph.

6. **Assertions and Expectations:** The `ASSERT_TRUE(r.Changed())` line checks if the `Reduce()` operation actually made a change to the graph. The `EXPECT_THAT(r.replacement(), ...)` lines verify the nature of the change, often using a matcher like `IsSpeculativeNumberLessThan` to check if a specific node was replaced with another node of the expected type and with the correct inputs.

7. **Feedback and Hints:** The tests use `FeedbackSource` and `NumberOperationHint`. These represent information gathered during runtime that helps the compiler make optimization decisions.

8. **Type System:** The code uses `Typer` and `Type::...` to define the types of the nodes, influencing how the redundancy elimination pass behaves.

**Overall Function:** The primary goal of these tests is to verify that the redundancy elimination pass in V8 correctly optimizes code involving:

- **Bounds Checks:** Ensuring that redundant bounds checks are removed or combined.
- **Speculative Operations:**  Confirming that when a bounds check precedes a speculative numerical operation, the bounds check's result can be used to refine the inputs of the speculative operation, potentially leading to a more efficient representation. The tests explore scenarios where the types are compatible ("SameType") and where one type is more general than the other ("BetterType").

**Relating to Javascript:** The speculative operations and bounds checks directly correspond to common JavaScript operations on numbers and arrays.

**Hypothesizing Inputs and Outputs:**  Consider the `SpeculativeNumberLessThanWithCheckBoundsBetterType` test.

* **Hypothesized Input (Conceptual JavaScript):**  Imagine the following JavaScript code within a loop or function:

   ```javascript
   function foo(arr, index1, index2) {
     if (index1 < arr.length && index2 < arr.length) {
       return arr[index1] < arr[index2];
     }
     return false;
   }
   ```

* **Hypothesized Graph Construction:** The `TEST_F` sets up a simplified representation where `lhs` and `rhs` conceptually represent `index1` and `index2`, and `length` represents `arr.length`. The `CheckBounds` nodes represent the `index < arr.length` checks. The `SpeculativeNumberLessThan` represents the `<` comparison.

* **Hypothesized Redundancy Elimination:** The redundancy elimination pass recognizes that if the `CheckBounds` for both `lhs` and `rhs` succeed, then the values of `lhs` and `rhs` are guaranteed to be valid array indices. This information can be used to potentially optimize the `SpeculativeNumberLessThan` operation.

* **Hypothesized Output (Graph Transformation):** The `EXPECT_THAT` assertion checks that the original `SpeculativeNumberLessThan` node is replaced by a new `SpeculativeNumberLessThan` node whose inputs are the results of the `CheckBounds` operations (`check1` and `check2`). This means the redundancy elimination pass is using the information from the bounds checks to refine the inputs of the comparison.

**Common Programming Errors:** The tests relate to the common practice of checking array bounds before accessing elements to prevent errors. A common error would be accessing an array element without checking the bounds, which can lead to runtime exceptions or unexpected behavior.

**归纳功能 (Summary of Functionality):**

这部分代码是 V8 编译器中冗余消除优化的单元测试， 专门针对以下场景：在进行推测性的数值运算（例如，小于、小于等于、加法、减法、安全整数加法、安全整数减法、转换为数字）之前存在边界检查。

其主要功能是验证：当对可能超出数组边界的索引进行数值运算时，冗余消除优化能够识别并利用已经执行过的边界检查的结果。 具体来说，如果一个数值运算（例如 `SpeculativeNumberLessThan`）的操作数之前已经进行了边界检查 (`CheckBounds`)，并且类型信息允许，那么优化器会将该数值运算的输入替换为边界检查的结果。 这样可以确保数值运算只在索引有效的情况下执行，并且有可能消除后续的冗余检查或简化运算。

测试用例覆盖了操作数类型相同和不同的情况，以及各种推测性的数值运算。  这些测试旨在确保 V8 编译器在处理包含数组访问和数值计算的 JavaScript 代码时，能够有效地进行优化，提高性能并确保代码的安全性。

好的，这是对所提供的 C++ 代码片段（V8 源代码 `v8/test/unittests/compiler/redundancy-elimination-unittest.cc` 的一部分）的功能归纳：

**功能归纳**

这段代码是 V8 JavaScript 引擎编译器中 **冗余消除（Redundancy Elimination）优化** 的单元测试。 具体来说，它测试了当代码中存在 **数组边界检查（CheckBounds）** 时，冗余消除优化如何处理后续的 **推测性数值运算（Speculative Number Operations）**。

其核心功能是验证：如果一个数值运算（例如比较、加减法、类型转换）的操作数之前已经进行了有效的边界检查，那么冗余消除优化是否能够识别并利用这个信息，从而可能简化或优化后续的数值运算。

**具体测试场景包括：**

* **推测性小于比较 (SpeculativeNumberLessThan):**  测试在边界检查之后进行小于比较时，优化器是否能利用边界检查的结果。
* **推测性小于等于比较 (SpeculativeNumberLessThanOrEqual):** 测试在边界检查之后进行小于等于比较时，优化器是否能利用边界检查的结果。
* **推测性加法 (SpeculativeNumberAdd):** 测试在边界检查之后进行加法运算时，优化器是否能利用边界检查的结果。
* **推测性减法 (SpeculativeNumberSubtract):** 测试在边界检查之后进行减法运算时，优化器是否能利用边界检查的结果。
* **推测性安全整数加法 (SpeculativeSafeIntegerAdd):** 测试在边界检查之后进行安全整数加法运算时，优化器是否能利用边界检查的结果。
* **推测性安全整数减法 (SpeculativeSafeIntegerSubtract):** 测试在边界检查之后进行安全整数减法运算时，优化器是否能利用边界检查的结果。
* **推测性转换为数字 (SpeculativeToNumber):** 测试在边界检查之后进行类型转换为数字时，优化器是否能利用边界检查的结果。

**测试覆盖了以下两种情况：**

* **BetterType (更优的类型):**  边界检查的输入类型比后续数值运算的输入类型更具体或更安全。例如，边界检查的输入是 `Type::Any()`，而数值运算的操作数仍然是 `Type::Any()`，但优化器可以通过边界检查推断出更具体的范围。
* **SameType (相同的类型):** 边界检查的输入类型与后续数值运算的输入类型相同。

**与 JavaScript 的功能关系**

这些测试直接关系到 JavaScript 中常见的数组访问和数值运算场景。例如，以下 JavaScript 代码可能会触发类似的优化：

```javascript
function foo(arr, index1, index2) {
  if (index1 >= 0 && index1 < arr.length && index2 >= 0 && index2 < arr.length) {
    return arr[index1] < arr[index2];
  }
  return false;
}
```

在这个例子中， `index1 >= 0 && index1 < arr.length` 和 `index2 >= 0 && index2 < arr.length` 对应于代码中的 `CheckBounds` 操作。 而 `arr[index1] < arr[index2]` 中的小于比较则对应于 `SpeculativeNumberLessThan` 操作。  V8 的冗余消除优化会尝试识别出边界检查已经确保了 `index1` 和 `index2` 是有效的数组索引，从而可能优化后续的数组元素访问和比较操作。

**代码逻辑推理**

以 `SpeculativeNumberLessThanWithCheckBoundsBetterType` 为例：

**假设输入:**

* `lhs`:  一个类型为 `Type::Any()` 的节点，代表数组索引。
* `rhs`:  一个类型为 `Type::Any()` 的节点，代表另一个数组索引。
* `length`: 一个类型为 `Type::Unsigned31()` 的节点，代表数组的长度。

**步骤:**

1. 创建两个 `CheckBounds` 节点 (`check1` 和 `check2`)，分别检查 `lhs` 和 `rhs` 是否在 `length` 的范围内。
2. 创建一个 `SpeculativeNumberLessThan` 节点 (`cmp3`)，比较 `lhs` 和 `rhs`。
3. 运行冗余消除优化 (`Reduce`)。

**预期输出:**

* 优化器会识别出 `cmp3` 的输入 `lhs` 和 `rhs` 之前已经进行了边界检查。
* 由于类型是 "BetterType"，优化器会将 `cmp3` 的输入替换为 `check1` 和 `check2` 的结果。这意味着比较操作现在基于已经验证过边界的索引值。
* `r3.replacement()` 会是一个新的 `SpeculativeNumberLessThan` 节点，其输入是 `check1` 和 `check2`。

**涉及用户常见的编程错误**

这段测试与用户常见的编程错误密切相关，特别是 **数组越界访问**。  用户可能在没有进行充分的边界检查的情况下访问数组元素，例如：

```javascript
function accessArray(arr, index) {
  return arr[index + 1]; // 如果 index 是 arr.length - 1，则会越界
}
```

V8 的优化器会尝试优化这种代码，但如果没有显式的边界检查，就可能导致运行时错误。  这里的测试确保了当有显式的边界检查时，优化器能够安全地进行优化。

总结来说，这段代码是 V8 编译器中至关重要的测试，用于确保冗余消除优化在处理与数组访问和数值运算相关的代码时能够正确、安全地工作，从而提升 JavaScript 代码的执行效率。

### 提示词
```
这是目录为v8/test/unittests/compiler/redundancy-elimination-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/redundancy-elimination-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
---------------------------------------
// SpeculativeNumberLessThan

TEST_F(RedundancyEliminationTest,
       SpeculativeNumberLessThanWithCheckBoundsBetterType) {
  Typer typer(broker(), Typer::kNoFlags, graph(), tick_counter());
  TRACED_FOREACH(FeedbackSource, feedback1, vector_slot_pairs()) {
    TRACED_FOREACH(FeedbackSource, feedback2, vector_slot_pairs()) {
      Node* lhs = Parameter(Type::Any(), 0);
      Node* rhs = Parameter(Type::Any(), 1);
      Node* length = Parameter(Type::Unsigned31(), 2);
      Node* effect = graph()->start();
      Node* control = graph()->start();

      Node* check1 = effect = graph()->NewNode(
          simplified()->CheckBounds(feedback1), lhs, length, effect, control);
      Reduction r1 = Reduce(check1);
      ASSERT_TRUE(r1.Changed());
      EXPECT_EQ(r1.replacement(), check1);

      Node* check2 = effect = graph()->NewNode(
          simplified()->CheckBounds(feedback2), rhs, length, effect, control);
      Reduction r2 = Reduce(check2);
      ASSERT_TRUE(r2.Changed());
      EXPECT_EQ(r2.replacement(), check2);

      Node* cmp3 = effect =
          graph()->NewNode(simplified()->SpeculativeNumberLessThan(
                               NumberOperationHint::kSignedSmall),
                           lhs, rhs, effect, control);
      Reduction r3 = Reduce(cmp3);
      ASSERT_TRUE(r3.Changed());
      EXPECT_THAT(r3.replacement(),
                  IsSpeculativeNumberLessThan(NumberOperationHint::kSignedSmall,
                                              check1, check2, _, _));
    }
  }
}

TEST_F(RedundancyEliminationTest,
       SpeculativeNumberLessThanWithCheckBoundsSameType) {
  Typer typer(broker(), Typer::kNoFlags, graph(), tick_counter());
  TRACED_FOREACH(FeedbackSource, feedback1, vector_slot_pairs()) {
    TRACED_FOREACH(FeedbackSource, feedback2, vector_slot_pairs()) {
      Node* lhs = Parameter(Type::UnsignedSmall(), 0);
      Node* rhs = Parameter(Type::UnsignedSmall(), 1);
      Node* length = Parameter(Type::Unsigned31(), 2);
      Node* effect = graph()->start();
      Node* control = graph()->start();

      Node* check1 = effect = graph()->NewNode(
          simplified()->CheckBounds(feedback1), lhs, length, effect, control);
      Reduction r1 = Reduce(check1);
      ASSERT_TRUE(r1.Changed());
      EXPECT_EQ(r1.replacement(), check1);

      Node* check2 = effect = graph()->NewNode(
          simplified()->CheckBounds(feedback2), rhs, length, effect, control);
      Reduction r2 = Reduce(check2);
      ASSERT_TRUE(r2.Changed());
      EXPECT_EQ(r2.replacement(), check2);

      Node* cmp3 = effect =
          graph()->NewNode(simplified()->SpeculativeNumberLessThan(
                               NumberOperationHint::kSignedSmall),
                           lhs, rhs, effect, control);
      Reduction r3 = Reduce(cmp3);
      ASSERT_TRUE(r3.Changed());
      EXPECT_THAT(r3.replacement(),
                  IsSpeculativeNumberLessThan(NumberOperationHint::kSignedSmall,
                                              lhs, rhs, _, _));
    }
  }
}

// -----------------------------------------------------------------------------
// SpeculativeNumberLessThanOrEqual

TEST_F(RedundancyEliminationTest,
       SpeculativeNumberLessThanOrEqualWithCheckBoundsBetterType) {
  Typer typer(broker(), Typer::kNoFlags, graph(), tick_counter());
  TRACED_FOREACH(FeedbackSource, feedback1, vector_slot_pairs()) {
    TRACED_FOREACH(FeedbackSource, feedback2, vector_slot_pairs()) {
      Node* lhs = Parameter(Type::Any(), 0);
      Node* rhs = Parameter(Type::Any(), 1);
      Node* length = Parameter(Type::Unsigned31(), 2);
      Node* effect = graph()->start();
      Node* control = graph()->start();

      Node* check1 = effect = graph()->NewNode(
          simplified()->CheckBounds(feedback1), lhs, length, effect, control);
      Reduction r1 = Reduce(check1);
      ASSERT_TRUE(r1.Changed());
      EXPECT_EQ(r1.replacement(), check1);

      Node* check2 = effect = graph()->NewNode(
          simplified()->CheckBounds(feedback2), rhs, length, effect, control);
      Reduction r2 = Reduce(check2);
      ASSERT_TRUE(r2.Changed());
      EXPECT_EQ(r2.replacement(), check2);

      Node* cmp3 = effect =
          graph()->NewNode(simplified()->SpeculativeNumberLessThanOrEqual(
                               NumberOperationHint::kSignedSmall),
                           lhs, rhs, effect, control);
      Reduction r3 = Reduce(cmp3);
      ASSERT_TRUE(r3.Changed());
      EXPECT_THAT(r3.replacement(),
                  IsSpeculativeNumberLessThanOrEqual(
                      NumberOperationHint::kSignedSmall, check1, check2, _, _));
    }
  }
}

TEST_F(RedundancyEliminationTest,
       SpeculativeNumberLessThanOrEqualWithCheckBoundsSameType) {
  Typer typer(broker(), Typer::kNoFlags, graph(), tick_counter());
  TRACED_FOREACH(FeedbackSource, feedback1, vector_slot_pairs()) {
    TRACED_FOREACH(FeedbackSource, feedback2, vector_slot_pairs()) {
      Node* lhs = Parameter(Type::UnsignedSmall(), 0);
      Node* rhs = Parameter(Type::UnsignedSmall(), 1);
      Node* length = Parameter(Type::Unsigned31(), 2);
      Node* effect = graph()->start();
      Node* control = graph()->start();

      Node* check1 = effect = graph()->NewNode(
          simplified()->CheckBounds(feedback1), lhs, length, effect, control);
      Reduction r1 = Reduce(check1);
      ASSERT_TRUE(r1.Changed());
      EXPECT_EQ(r1.replacement(), check1);

      Node* check2 = effect = graph()->NewNode(
          simplified()->CheckBounds(feedback2), rhs, length, effect, control);
      Reduction r2 = Reduce(check2);
      ASSERT_TRUE(r2.Changed());
      EXPECT_EQ(r2.replacement(), check2);

      Node* cmp3 = effect =
          graph()->NewNode(simplified()->SpeculativeNumberLessThanOrEqual(
                               NumberOperationHint::kSignedSmall),
                           lhs, rhs, effect, control);
      Reduction r3 = Reduce(cmp3);
      ASSERT_TRUE(r3.Changed());
      EXPECT_THAT(r3.replacement(),
                  IsSpeculativeNumberLessThanOrEqual(
                      NumberOperationHint::kSignedSmall, lhs, rhs, _, _));
    }
  }
}

// -----------------------------------------------------------------------------
// SpeculativeNumberAdd

TEST_F(RedundancyEliminationTest,
       SpeculativeNumberAddWithCheckBoundsBetterType) {
  Typer typer(broker(), Typer::kNoFlags, graph(), tick_counter());
  TRACED_FOREACH(FeedbackSource, feedback, vector_slot_pairs()) {
    TRACED_FOREACH(NumberOperationHint, hint, kNumberOperationHints) {
      Node* lhs = Parameter(Type::Any(), 0);
      Node* rhs = Parameter(Type::Any(), 1);
      Node* length = Parameter(Type::Unsigned31(), 2);
      Node* effect = graph()->start();
      Node* control = graph()->start();

      Node* check1 = effect = graph()->NewNode(
          simplified()->CheckBounds(feedback), lhs, length, effect, control);
      Reduction r1 = Reduce(check1);
      ASSERT_TRUE(r1.Changed());
      EXPECT_EQ(r1.replacement(), check1);

      Node* add2 = effect = graph()->NewNode(
          simplified()->SpeculativeNumberAdd(hint), lhs, rhs, effect, control);
      Reduction r2 = Reduce(add2);
      ASSERT_TRUE(r2.Changed());
      EXPECT_THAT(r2.replacement(),
                  IsSpeculativeNumberAdd(hint, check1, rhs, _, _));
    }
  }
}

TEST_F(RedundancyEliminationTest, SpeculativeNumberAddWithCheckBoundsSameType) {
  Typer typer(broker(), Typer::kNoFlags, graph(), tick_counter());
  TRACED_FOREACH(FeedbackSource, feedback, vector_slot_pairs()) {
    TRACED_FOREACH(NumberOperationHint, hint, kNumberOperationHints) {
      Node* lhs = Parameter(Type::Range(42.0, 42.0, zone()), 0);
      Node* rhs = Parameter(Type::Any(), 0);
      Node* length = Parameter(Type::Unsigned31(), 1);
      Node* effect = graph()->start();
      Node* control = graph()->start();

      Node* check1 = effect = graph()->NewNode(
          simplified()->CheckBounds(feedback), lhs, length, effect, control);
      Reduction r1 = Reduce(check1);
      ASSERT_TRUE(r1.Changed());
      EXPECT_EQ(r1.replacement(), check1);

      Node* add2 = effect = graph()->NewNode(
          simplified()->SpeculativeNumberAdd(hint), lhs, rhs, effect, control);
      Reduction r2 = Reduce(add2);
      ASSERT_TRUE(r2.Changed());
      EXPECT_THAT(r2.replacement(),
                  IsSpeculativeNumberAdd(hint, lhs, rhs, _, _));
    }
  }
}

// -----------------------------------------------------------------------------
// SpeculativeNumberSubtract

TEST_F(RedundancyEliminationTest,
       SpeculativeNumberSubtractWithCheckBoundsBetterType) {
  Typer typer(broker(), Typer::kNoFlags, graph(), tick_counter());
  TRACED_FOREACH(FeedbackSource, feedback, vector_slot_pairs()) {
    TRACED_FOREACH(NumberOperationHint, hint, kNumberOperationHints) {
      Node* lhs = Parameter(Type::Any(), 0);
      Node* rhs = Parameter(Type::Any(), 1);
      Node* length = Parameter(Type::Unsigned31(), 2);
      Node* effect = graph()->start();
      Node* control = graph()->start();

      Node* check1 = effect = graph()->NewNode(
          simplified()->CheckBounds(feedback), lhs, length, effect, control);
      Reduction r1 = Reduce(check1);
      ASSERT_TRUE(r1.Changed());
      EXPECT_EQ(r1.replacement(), check1);

      Node* subtract2 = effect =
          graph()->NewNode(simplified()->SpeculativeNumberSubtract(hint), lhs,
                           rhs, effect, control);
      Reduction r2 = Reduce(subtract2);
      ASSERT_TRUE(r2.Changed());
      EXPECT_THAT(r2.replacement(),
                  IsSpeculativeNumberSubtract(hint, check1, rhs, _, _));
    }
  }
}

TEST_F(RedundancyEliminationTest,
       SpeculativeNumberSubtractWithCheckBoundsSameType) {
  Typer typer(broker(), Typer::kNoFlags, graph(), tick_counter());
  TRACED_FOREACH(FeedbackSource, feedback, vector_slot_pairs()) {
    TRACED_FOREACH(NumberOperationHint, hint, kNumberOperationHints) {
      Node* lhs = Parameter(Type::Range(42.0, 42.0, zone()), 0);
      Node* rhs = Parameter(Type::Any(), 0);
      Node* length = Parameter(Type::Unsigned31(), 1);
      Node* effect = graph()->start();
      Node* control = graph()->start();

      Node* check1 = effect = graph()->NewNode(
          simplified()->CheckBounds(feedback), lhs, length, effect, control);
      Reduction r1 = Reduce(check1);
      ASSERT_TRUE(r1.Changed());
      EXPECT_EQ(r1.replacement(), check1);

      Node* subtract2 = effect =
          graph()->NewNode(simplified()->SpeculativeNumberSubtract(hint), lhs,
                           rhs, effect, control);
      Reduction r2 = Reduce(subtract2);
      ASSERT_TRUE(r2.Changed());
      EXPECT_THAT(r2.replacement(),
                  IsSpeculativeNumberSubtract(hint, lhs, rhs, _, _));
    }
  }
}

// -----------------------------------------------------------------------------
// SpeculativeSafeIntegerAdd

TEST_F(RedundancyEliminationTest,
       SpeculativeSafeIntegerAddWithCheckBoundsBetterType) {
  Typer typer(broker(), Typer::kNoFlags, graph(), tick_counter());
  TRACED_FOREACH(FeedbackSource, feedback, vector_slot_pairs()) {
    TRACED_FOREACH(NumberOperationHint, hint, kNumberOperationHints) {
      Node* lhs = Parameter(Type::Any(), 0);
      Node* rhs = Parameter(Type::Any(), 1);
      Node* length = Parameter(Type::Unsigned31(), 2);
      Node* effect = graph()->start();
      Node* control = graph()->start();

      Node* check1 = effect = graph()->NewNode(
          simplified()->CheckBounds(feedback), lhs, length, effect, control);
      Reduction r1 = Reduce(check1);
      ASSERT_TRUE(r1.Changed());
      EXPECT_EQ(r1.replacement(), check1);

      Node* add2 = effect =
          graph()->NewNode(simplified()->SpeculativeSafeIntegerAdd(hint), lhs,
                           rhs, effect, control);
      Reduction r2 = Reduce(add2);
      ASSERT_TRUE(r2.Changed());
      EXPECT_THAT(r2.replacement(),
                  IsSpeculativeSafeIntegerAdd(hint, check1, rhs, _, _));
    }
  }
}

TEST_F(RedundancyEliminationTest,
       SpeculativeSafeIntegerAddWithCheckBoundsSameType) {
  Typer typer(broker(), Typer::kNoFlags, graph(), tick_counter());
  TRACED_FOREACH(FeedbackSource, feedback, vector_slot_pairs()) {
    TRACED_FOREACH(NumberOperationHint, hint, kNumberOperationHints) {
      Node* lhs = Parameter(Type::Range(42.0, 42.0, zone()), 0);
      Node* rhs = Parameter(Type::Any(), 0);
      Node* length = Parameter(Type::Unsigned31(), 1);
      Node* effect = graph()->start();
      Node* control = graph()->start();

      Node* check1 = effect = graph()->NewNode(
          simplified()->CheckBounds(feedback), lhs, length, effect, control);
      Reduction r1 = Reduce(check1);
      ASSERT_TRUE(r1.Changed());
      EXPECT_EQ(r1.replacement(), check1);

      Node* add2 = effect =
          graph()->NewNode(simplified()->SpeculativeSafeIntegerAdd(hint), lhs,
                           rhs, effect, control);
      Reduction r2 = Reduce(add2);
      ASSERT_TRUE(r2.Changed());
      EXPECT_THAT(r2.replacement(),
                  IsSpeculativeSafeIntegerAdd(hint, lhs, rhs, _, _));
    }
  }
}

// -----------------------------------------------------------------------------
// SpeculativeSafeIntegerSubtract

TEST_F(RedundancyEliminationTest,
       SpeculativeSafeIntegerSubtractWithCheckBoundsBetterType) {
  Typer typer(broker(), Typer::kNoFlags, graph(), tick_counter());
  TRACED_FOREACH(FeedbackSource, feedback, vector_slot_pairs()) {
    TRACED_FOREACH(NumberOperationHint, hint, kNumberOperationHints) {
      Node* lhs = Parameter(Type::Any(), 0);
      Node* rhs = Parameter(Type::Any(), 1);
      Node* length = Parameter(Type::Unsigned31(), 2);
      Node* effect = graph()->start();
      Node* control = graph()->start();

      Node* check1 = effect = graph()->NewNode(
          simplified()->CheckBounds(feedback), lhs, length, effect, control);
      Reduction r1 = Reduce(check1);
      ASSERT_TRUE(r1.Changed());
      EXPECT_EQ(r1.replacement(), check1);

      Node* subtract2 = effect =
          graph()->NewNode(simplified()->SpeculativeSafeIntegerSubtract(hint),
                           lhs, rhs, effect, control);
      Reduction r2 = Reduce(subtract2);
      ASSERT_TRUE(r2.Changed());
      EXPECT_THAT(r2.replacement(),
                  IsSpeculativeSafeIntegerSubtract(hint, check1, rhs, _, _));
    }
  }
}

TEST_F(RedundancyEliminationTest,
       SpeculativeSafeIntegerSubtractWithCheckBoundsSameType) {
  Typer typer(broker(), Typer::kNoFlags, graph(), tick_counter());
  TRACED_FOREACH(FeedbackSource, feedback, vector_slot_pairs()) {
    TRACED_FOREACH(NumberOperationHint, hint, kNumberOperationHints) {
      Node* lhs = Parameter(Type::Range(42.0, 42.0, zone()), 0);
      Node* rhs = Parameter(Type::Any(), 0);
      Node* length = Parameter(Type::Unsigned31(), 1);
      Node* effect = graph()->start();
      Node* control = graph()->start();

      Node* check1 = effect = graph()->NewNode(
          simplified()->CheckBounds(feedback), lhs, length, effect, control);
      Reduction r1 = Reduce(check1);
      ASSERT_TRUE(r1.Changed());
      EXPECT_EQ(r1.replacement(), check1);

      Node* subtract2 = effect =
          graph()->NewNode(simplified()->SpeculativeSafeIntegerSubtract(hint),
                           lhs, rhs, effect, control);
      Reduction r2 = Reduce(subtract2);
      ASSERT_TRUE(r2.Changed());
      EXPECT_THAT(r2.replacement(),
                  IsSpeculativeSafeIntegerSubtract(hint, lhs, rhs, _, _));
    }
  }
}

// -----------------------------------------------------------------------------
// SpeculativeToNumber

TEST_F(RedundancyEliminationTest,
       SpeculativeToNumberWithCheckBoundsBetterType) {
  Typer typer(broker(), Typer::kNoFlags, graph(), tick_counter());
  TRACED_FOREACH(FeedbackSource, feedback1, vector_slot_pairs()) {
    TRACED_FOREACH(FeedbackSource, feedback2, vector_slot_pairs()) {
      TRACED_FOREACH(NumberOperationHint, hint, kNumberOperationHints) {
        Node* index = Parameter(Type::Any(), 0);
        Node* length = Parameter(Type::Unsigned31(), 1);
        Node* effect = graph()->start();
        Node* control = graph()->start();

        Node* check1 = effect =
            graph()->NewNode(simplified()->CheckBounds(feedback1), index,
                             length, effect, control);
        Reduction r1 = Reduce(check1);
        ASSERT_TRUE(r1.Changed());
        EXPECT_EQ(r1.replacement(), check1);

        Node* to_number2 = effect =
            graph()->NewNode(simplified()->SpeculativeToNumber(hint, feedback2),
                             index, effect, control);
        Reduction r2 = Reduce(to_number2);
        ASSERT_TRUE(r2.Changed());
        EXPECT_THAT(r2.replacement(), IsSpeculativeToNumber(check1));
      }
    }
  }
}

TEST_F(RedundancyEliminationTest, SpeculativeToNumberWithCheckBoundsSameType) {
  Typer typer(broker(), Typer::kNoFlags, graph(), tick_counter());
  TRACED_FOREACH(FeedbackSource, feedback1, vector_slot_pairs()) {
    TRACED_FOREACH(FeedbackSource, feedback2, vector_slot_pairs()) {
      TRACED_FOREACH(NumberOperationHint, hint, kNumberOperationHints) {
        Node* index = Parameter(Type::Range(42.0, 42.0, zone()), 0);
        Node* length = Parameter(Type::Unsigned31(), 1);
        Node* effect = graph()->start();
        Node* control = graph()->start();

        Node* check1 = effect =
            graph()->NewNode(simplified()->CheckBounds(feedback1), index,
                             length, effect, control);
        Reduction r1 = Reduce(check1);
        ASSERT_TRUE(r1.Changed());
        EXPECT_EQ(r1.replacement(), check1);

        Node* to_number2 = effect =
            graph()->NewNode(simplified()->SpeculativeToNumber(hint, feedback2),
                             index, effect, control);
        Reduction r2 = Reduce(to_number2);
        ASSERT_TRUE(r2.Changed());
        EXPECT_THAT(r2.replacement(), IsSpeculativeToNumber(index));
      }
    }
  }
}

}  // namespace redundancy_elimination_unittest
}  // namespace compiler
}  // namespace internal
}  // namespace v8
```