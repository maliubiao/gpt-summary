Response: The user wants to understand the functionality of the C++ source code file `redundancy-elimination-unittest.cc`. I need to analyze the code and summarize its purpose. The user also asks if there's a relationship with JavaScript and wants an example if there is.

Looking at the code, I can see that it's a unit test file within the V8 project (the JavaScript engine used in Chrome and Node.js). It specifically tests the `RedundancyElimination` compiler pass. This pass aims to remove redundant operations in the intermediate representation (IR) of the code being compiled.

The tests focus on various "check" nodes in the IR, like `CheckBounds`, `CheckNumber`, `CheckSmi`, etc., and "checked" operations like `CheckedFloat64ToInt32`, `CheckedTaggedToInt32`, etc. The tests verify that if a check or a checked operation is performed, subsequent identical checks or checked operations on the same input can be eliminated and replaced with the result of the first one. This optimization avoids unnecessary computations.

The connection to JavaScript is that the V8 compiler uses this redundancy elimination pass to optimize JavaScript code. The "check" and "checked" operations often correspond to implicit type checks and conversions that the engine performs while executing JavaScript.

For example, when accessing an array element in JavaScript, the engine needs to check if the index is within the bounds of the array. The `CheckBounds` node in the IR represents this check. If the same array and index are accessed multiple times in a row, the redundancy elimination pass can optimize it by performing the bounds check only once.

I can provide a simple JavaScript example to illustrate this concept.
这个C++源代码文件 `redundancy-elimination-unittest.cc` 是 V8 JavaScript 引擎的一部分，它专门用于测试编译器中的**冗余消除 (Redundancy Elimination)** 功能。

**功能归纳:**

该文件的主要功能是为编译器中的 `RedundancyElimination` 优化过程编写单元测试。 `RedundancyElimination` 是一个编译器优化阶段，其目标是识别并移除代码中的冗余计算，从而提高代码执行效率。

该文件中的测试用例主要关注以下几点：

1. **识别并消除重复的类型检查操作:**  例如，如果代码中连续两次检查某个变量是否为数字 (`CheckNumber`)，冗余消除应该能够识别出第二次检查是多余的，并将其替换为第一次检查的结果。
2. **识别并消除被其他检查 subsumed 的检查操作:** 例如，如果代码已经检查了某个值是否为小整数 (`CheckSmi`)，那么后续检查该值是否为数字 (`CheckNumber`) 就是多余的，因为所有小整数都是数字。
3. **识别并消除重复的边界检查操作:** 例如，如果代码中连续两次使用相同的索引和长度对同一个数组进行边界检查 (`CheckBounds`)，冗余消除应该能够识别出第二次检查是多余的。
4. **识别并优化带有副作用的检查操作:** 例如 `CheckedFloat64ToInt32` 等，如果对同一个输入进行多次相同的 checked 操作，后续的操作可以复用第一次的结果。
5. **测试与类型反馈的交互:**  测试用例中使用了 `FeedbackSource`，这表明冗余消除的决策可能受到运行时类型反馈的影响。
6. **测试投机性操作的优化:**  例如 `SpeculativeNumberEqual` 等，这些操作在编译时基于类型预测进行优化，测试用例验证了在存在冗余检查的情况下，投机性操作是否能正确地利用这些信息。

**与 JavaScript 的关系及示例:**

`RedundancyElimination` 作为 V8 编译器的优化阶段，直接影响 JavaScript 代码的执行效率。 JavaScript 是一种动态类型语言，类型检查通常在运行时进行。 编译器通过冗余消除可以减少不必要的运行时类型检查和计算，从而提升性能。

**JavaScript 示例:**

假设有以下 JavaScript 代码：

```javascript
function foo(arr, index) {
  if (index >= 0 && index < arr.length) { // 第一次边界检查 (隐式)
    const value1 = arr[index];
    if (index >= 0 && index < arr.length) { // 第二次边界检查 (隐式)
      const value2 = arr[index];
      return value1 + value2;
    }
  }
  return 0;
}
```

在 V8 编译执行这段代码时，`RedundancyElimination` 优化可能会识别出第二个 `if` 条件中的边界检查是多余的。 因为如果代码执行到第二个 `if` 语句，那么第一个 `if` 已经确保了 `index` 在 `arr` 的有效范围内。

在编译器的中间表示中，这两个隐式的边界检查可能会被表示为 `CheckBounds` 节点。 `redundancy-elimination-unittest.cc` 中的 `TEST_F(RedundancyEliminationTest, CheckBounds)`  等测试用例，就是为了验证编译器能否正确地消除这类冗余的 `CheckBounds` 操作。

**更具体一点的 JavaScript 示例对应 C++ 测试:**

`TEST_F(RedundancyEliminationTest, CheckBounds)` 这个测试用例模拟了 JavaScript 中连续进行两次相同边界检查的情况。虽然在实际的 JavaScript 代码中，我们可能不会写出完全重复的 `if` 条件，但是编译器在进行内联、循环展开等优化后，可能会产生类似的冗余检查。

例如，考虑一个简单的循环：

```javascript
function bar(arr) {
  let sum = 0;
  for (let i = 0; i < arr.length; i++) { // 循环条件会进行边界检查
    sum += arr[i]; // 访问数组元素会进行边界检查
  }
  return sum;
}
```

在这个循环中，每次迭代都会进行边界检查。编译器可能会尝试优化这个循环，如果它能够确定在循环的整个过程中，索引 `i` 始终在有效范围内（例如，通过一些静态分析或类型反馈），那么它可以消除一部分冗余的边界检查。 `redundancy-elimination-unittest.cc` 中的测试用例就是为了确保这种优化能够正确地进行。

总而言之， `redundancy-elimination-unittest.cc` 通过各种测试用例，确保 V8 编译器能够有效地识别并消除 JavaScript 代码中潜在的冗余操作，从而提高 JavaScript 代码的执行效率。

Prompt: 
```
这是目录为v8/test/unittests/compiler/redundancy-elimination-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/redundancy-elimination.h"

#include "src/codegen/tick-counter.h"
#include "src/compiler/feedback-source.h"
#include "src/compiler/js-graph.h"
#include "test/unittests/compiler/graph-reducer-unittest.h"
#include "test/unittests/compiler/graph-unittest.h"
#include "test/unittests/compiler/node-test-utils.h"

using testing::_;
using testing::NiceMock;

namespace v8 {
namespace internal {
namespace compiler {
namespace redundancy_elimination_unittest {

class RedundancyEliminationTest : public GraphTest {
 public:
  explicit RedundancyEliminationTest(int num_parameters = 4)
      : GraphTest(num_parameters),
        javascript_(zone()),
        simplified_(zone()),
        machine_(zone()),
        jsgraph_(isolate(), graph(), common(), &javascript_, &simplified_,
                 &machine_),
        reducer_(&editor_, &jsgraph_, zone()) {
    // Initialize the {reducer_} state for the Start node.
    reducer_.Reduce(graph()->start());

    // Create a feedback vector with two CALL_IC slots.
    FeedbackVectorSpec spec(zone());
    FeedbackSlot slot1 = spec.AddCallICSlot();
    FeedbackSlot slot2 = spec.AddCallICSlot();
    Handle<FeedbackVector> feedback_vector =
        FeedbackVector::NewForTesting(isolate(), &spec);
    vector_slot_pairs_.push_back(FeedbackSource());
    vector_slot_pairs_.push_back(FeedbackSource(feedback_vector, slot1));
    vector_slot_pairs_.push_back(FeedbackSource(feedback_vector, slot2));
  }
  ~RedundancyEliminationTest() override = default;

 protected:
  Reduction Reduce(Node* node) { return reducer_.Reduce(node); }

  std::vector<FeedbackSource> const& vector_slot_pairs() const {
    return vector_slot_pairs_;
  }
  SimplifiedOperatorBuilder* simplified() { return &simplified_; }

 private:
  NiceMock<MockAdvancedReducerEditor> editor_;
  std::vector<FeedbackSource> vector_slot_pairs_;
  FeedbackSource feedback2_;
  JSOperatorBuilder javascript_;
  SimplifiedOperatorBuilder simplified_;
  MachineOperatorBuilder machine_;
  JSGraph jsgraph_;
  RedundancyElimination reducer_;
};

namespace {

const CheckForMinusZeroMode kCheckForMinusZeroModes[] = {
    CheckForMinusZeroMode::kCheckForMinusZero,
    CheckForMinusZeroMode::kDontCheckForMinusZero,
};

const CheckTaggedInputMode kCheckTaggedInputModes[] = {
    CheckTaggedInputMode::kNumber, CheckTaggedInputMode::kNumberOrOddball};

const NumberOperationHint kNumberOperationHints[] = {
    NumberOperationHint::kSignedSmall,
    NumberOperationHint::kSignedSmallInputs,
    NumberOperationHint::kNumber,
    NumberOperationHint::kNumberOrOddball,
};

}  // namespace

// -----------------------------------------------------------------------------
// CheckBounds

TEST_F(RedundancyEliminationTest, CheckBounds) {
  TRACED_FOREACH(FeedbackSource, feedback1, vector_slot_pairs()) {
    TRACED_FOREACH(FeedbackSource, feedback2, vector_slot_pairs()) {
      Node* index = Parameter(0);
      Node* length = Parameter(1);
      Node* effect = graph()->start();
      Node* control = graph()->start();

      Node* check1 = effect = graph()->NewNode(
          simplified()->CheckBounds(feedback1), index, length, effect, control);
      Reduction r1 = Reduce(check1);
      ASSERT_TRUE(r1.Changed());
      EXPECT_EQ(r1.replacement(), check1);

      Node* check2 = effect = graph()->NewNode(
          simplified()->CheckBounds(feedback2), index, length, effect, control);
      Reduction r2 = Reduce(check2);
      ASSERT_TRUE(r2.Changed());
      EXPECT_EQ(r2.replacement(), check1);
    }
  }
}

// -----------------------------------------------------------------------------
// CheckNumber

TEST_F(RedundancyEliminationTest, CheckNumberSubsumedByCheckSmi) {
  TRACED_FOREACH(FeedbackSource, feedback1, vector_slot_pairs()) {
    TRACED_FOREACH(FeedbackSource, feedback2, vector_slot_pairs()) {
      Node* value = Parameter(0);
      Node* effect = graph()->start();
      Node* control = graph()->start();

      Node* check1 = effect = graph()->NewNode(
          simplified()->CheckSmi(feedback1), value, effect, control);
      Reduction r1 = Reduce(check1);
      ASSERT_TRUE(r1.Changed());
      EXPECT_EQ(r1.replacement(), check1);

      Node* check2 = effect = graph()->NewNode(
          simplified()->CheckNumber(feedback2), value, effect, control);
      Reduction r2 = Reduce(check2);
      ASSERT_TRUE(r2.Changed());
      EXPECT_EQ(r2.replacement(), check1);
    }
  }
}

// -----------------------------------------------------------------------------
// CheckReceiver

TEST_F(RedundancyEliminationTest, CheckReceiver) {
  Node* value = Parameter(0);
  Node* effect = graph()->start();
  Node* control = graph()->start();

  Node* check1 = effect =
      graph()->NewNode(simplified()->CheckReceiver(), value, effect, control);
  Reduction r1 = Reduce(check1);
  ASSERT_TRUE(r1.Changed());
  EXPECT_EQ(r1.replacement(), check1);

  Node* check2 = effect =
      graph()->NewNode(simplified()->CheckReceiver(), value, effect, control);
  Reduction r2 = Reduce(check2);
  ASSERT_TRUE(r2.Changed());
  EXPECT_EQ(r2.replacement(), check1);
}

// -----------------------------------------------------------------------------
// CheckReceiverOrNullOrUndefined

TEST_F(RedundancyEliminationTest, CheckReceiverOrNullOrUndefined) {
  Node* value = Parameter(0);
  Node* effect = graph()->start();
  Node* control = graph()->start();

  Node* check1 = effect = graph()->NewNode(
      simplified()->CheckReceiverOrNullOrUndefined(), value, effect, control);
  Reduction r1 = Reduce(check1);
  ASSERT_TRUE(r1.Changed());
  EXPECT_EQ(r1.replacement(), check1);

  Node* check2 = effect = graph()->NewNode(
      simplified()->CheckReceiverOrNullOrUndefined(), value, effect, control);
  Reduction r2 = Reduce(check2);
  ASSERT_TRUE(r2.Changed());
  EXPECT_EQ(r2.replacement(), check1);
}

TEST_F(RedundancyEliminationTest,
       CheckReceiverOrNullOrUndefinedSubsumedByCheckReceiver) {
  Node* value = Parameter(0);
  Node* effect = graph()->start();
  Node* control = graph()->start();

  Node* check1 = effect =
      graph()->NewNode(simplified()->CheckReceiver(), value, effect, control);
  Reduction r1 = Reduce(check1);
  ASSERT_TRUE(r1.Changed());
  EXPECT_EQ(r1.replacement(), check1);

  Node* check2 = effect = graph()->NewNode(
      simplified()->CheckReceiverOrNullOrUndefined(), value, effect, control);
  Reduction r2 = Reduce(check2);
  ASSERT_TRUE(r2.Changed());
  EXPECT_EQ(r2.replacement(), check1);
}

// -----------------------------------------------------------------------------
// CheckString

TEST_F(RedundancyEliminationTest,
       CheckStringSubsumedByCheckInternalizedString) {
  TRACED_FOREACH(FeedbackSource, feedback, vector_slot_pairs()) {
    Node* value = Parameter(0);
    Node* effect = graph()->start();
    Node* control = graph()->start();

    Node* check1 = effect = graph()->NewNode(
        simplified()->CheckInternalizedString(), value, effect, control);
    Reduction r1 = Reduce(check1);
    ASSERT_TRUE(r1.Changed());
    EXPECT_EQ(r1.replacement(), check1);

    Node* check2 = effect = graph()->NewNode(
        simplified()->CheckString(feedback), value, effect, control);
    Reduction r2 = Reduce(check2);
    ASSERT_TRUE(r2.Changed());
    EXPECT_EQ(r2.replacement(), check1);
  }
}

// -----------------------------------------------------------------------------
// CheckSymbol

TEST_F(RedundancyEliminationTest, CheckSymbol) {
  Node* value = Parameter(0);
  Node* effect = graph()->start();
  Node* control = graph()->start();

  Node* check1 = effect =
      graph()->NewNode(simplified()->CheckSymbol(), value, effect, control);
  Reduction r1 = Reduce(check1);
  ASSERT_TRUE(r1.Changed());
  EXPECT_EQ(r1.replacement(), check1);

  Node* check2 = effect =
      graph()->NewNode(simplified()->CheckSymbol(), value, effect, control);
  Reduction r2 = Reduce(check2);
  ASSERT_TRUE(r2.Changed());
  EXPECT_EQ(r2.replacement(), check1);
}

// -----------------------------------------------------------------------------
// CheckedFloat64ToInt32

TEST_F(RedundancyEliminationTest, CheckedFloat64ToInt32) {
  TRACED_FOREACH(FeedbackSource, feedback1, vector_slot_pairs()) {
    TRACED_FOREACH(FeedbackSource, feedback2, vector_slot_pairs()) {
      TRACED_FOREACH(CheckForMinusZeroMode, mode, kCheckForMinusZeroModes) {
        Node* value = Parameter(0);
        Node* effect = graph()->start();
        Node* control = graph()->start();

        Node* check1 = effect = graph()->NewNode(
            simplified()->CheckedFloat64ToInt32(mode, feedback1), value, effect,
            control);
        Reduction r1 = Reduce(check1);
        ASSERT_TRUE(r1.Changed());
        EXPECT_EQ(r1.replacement(), check1);

        Node* check2 = effect = graph()->NewNode(
            simplified()->CheckedFloat64ToInt32(mode, feedback2), value, effect,
            control);
        Reduction r2 = Reduce(check2);
        ASSERT_TRUE(r2.Changed());
        EXPECT_EQ(r2.replacement(), check1);
      }
    }
  }
}

// -----------------------------------------------------------------------------
// CheckedFloat64ToInt64

TEST_F(RedundancyEliminationTest, CheckedFloat64ToInt64) {
  TRACED_FOREACH(FeedbackSource, feedback1, vector_slot_pairs()) {
    TRACED_FOREACH(FeedbackSource, feedback2, vector_slot_pairs()) {
      TRACED_FOREACH(CheckForMinusZeroMode, mode, kCheckForMinusZeroModes) {
        Node* value = Parameter(0);
        Node* effect = graph()->start();
        Node* control = graph()->start();

        Node* check1 = effect = graph()->NewNode(
            simplified()->CheckedFloat64ToInt64(mode, feedback1), value, effect,
            control);
        Reduction r1 = Reduce(check1);
        ASSERT_TRUE(r1.Changed());
        EXPECT_EQ(r1.replacement(), check1);

        Node* check2 = effect = graph()->NewNode(
            simplified()->CheckedFloat64ToInt64(mode, feedback2), value, effect,
            control);
        Reduction r2 = Reduce(check2);
        ASSERT_TRUE(r2.Changed());
        EXPECT_EQ(r2.replacement(), check1);
      }
    }
  }
}

// -----------------------------------------------------------------------------
// CheckedInt32ToTaggedSigned

TEST_F(RedundancyEliminationTest, CheckedInt32ToTaggedSigned) {
  TRACED_FOREACH(FeedbackSource, feedback1, vector_slot_pairs()) {
    TRACED_FOREACH(FeedbackSource, feedback2, vector_slot_pairs()) {
      Node* value = Parameter(0);
      Node* effect = graph()->start();
      Node* control = graph()->start();

      Node* check1 = effect =
          graph()->NewNode(simplified()->CheckedInt32ToTaggedSigned(feedback1),
                           value, effect, control);
      Reduction r1 = Reduce(check1);
      ASSERT_TRUE(r1.Changed());
      EXPECT_EQ(r1.replacement(), check1);

      Node* check2 = effect =
          graph()->NewNode(simplified()->CheckedInt32ToTaggedSigned(feedback2),
                           value, effect, control);
      Reduction r2 = Reduce(check2);
      ASSERT_TRUE(r2.Changed());
      EXPECT_EQ(r2.replacement(), check1);
    }
  }
}

// -----------------------------------------------------------------------------
// CheckedInt64ToInt32

TEST_F(RedundancyEliminationTest, CheckedInt64ToInt32) {
  TRACED_FOREACH(FeedbackSource, feedback1, vector_slot_pairs()) {
    TRACED_FOREACH(FeedbackSource, feedback2, vector_slot_pairs()) {
      Node* value = Parameter(0);
      Node* effect = graph()->start();
      Node* control = graph()->start();

      Node* check1 = effect = graph()->NewNode(
          simplified()->CheckedInt64ToInt32(feedback1), value, effect, control);
      Reduction r1 = Reduce(check1);
      ASSERT_TRUE(r1.Changed());
      EXPECT_EQ(r1.replacement(), check1);

      Node* check2 = effect = graph()->NewNode(
          simplified()->CheckedInt64ToInt32(feedback2), value, effect, control);
      Reduction r2 = Reduce(check2);
      ASSERT_TRUE(r2.Changed());
      EXPECT_EQ(r2.replacement(), check1);
    }
  }
}

// -----------------------------------------------------------------------------
// CheckedInt64ToTaggedSigned

TEST_F(RedundancyEliminationTest, CheckedInt64ToTaggedSigned) {
  TRACED_FOREACH(FeedbackSource, feedback1, vector_slot_pairs()) {
    TRACED_FOREACH(FeedbackSource, feedback2, vector_slot_pairs()) {
      Node* value = Parameter(0);
      Node* effect = graph()->start();
      Node* control = graph()->start();

      Node* check1 = effect =
          graph()->NewNode(simplified()->CheckedInt64ToTaggedSigned(feedback1),
                           value, effect, control);
      Reduction r1 = Reduce(check1);
      ASSERT_TRUE(r1.Changed());
      EXPECT_EQ(r1.replacement(), check1);

      Node* check2 = effect =
          graph()->NewNode(simplified()->CheckedInt64ToTaggedSigned(feedback2),
                           value, effect, control);
      Reduction r2 = Reduce(check2);
      ASSERT_TRUE(r2.Changed());
      EXPECT_EQ(r2.replacement(), check1);
    }
  }
}

// -----------------------------------------------------------------------------
// CheckedTaggedSignedToInt32

TEST_F(RedundancyEliminationTest, CheckedTaggedSignedToInt32) {
  TRACED_FOREACH(FeedbackSource, feedback1, vector_slot_pairs()) {
    TRACED_FOREACH(FeedbackSource, feedback2, vector_slot_pairs()) {
      Node* value = Parameter(0);
      Node* effect = graph()->start();
      Node* control = graph()->start();

      Node* check1 = effect =
          graph()->NewNode(simplified()->CheckedTaggedSignedToInt32(feedback1),
                           value, effect, control);
      Reduction r1 = Reduce(check1);
      ASSERT_TRUE(r1.Changed());
      EXPECT_EQ(r1.replacement(), check1);

      Node* check2 = effect =
          graph()->NewNode(simplified()->CheckedTaggedSignedToInt32(feedback2),
                           value, effect, control);
      Reduction r2 = Reduce(check2);
      ASSERT_TRUE(r2.Changed());
      EXPECT_EQ(r2.replacement(), check1);
    }
  }
}

// -----------------------------------------------------------------------------
// CheckedTaggedToFloat64

TEST_F(RedundancyEliminationTest, CheckedTaggedToFloat64) {
  TRACED_FOREACH(FeedbackSource, feedback1, vector_slot_pairs()) {
    TRACED_FOREACH(FeedbackSource, feedback2, vector_slot_pairs()) {
      TRACED_FOREACH(CheckTaggedInputMode, mode, kCheckTaggedInputModes) {
        Node* value = Parameter(0);
        Node* effect = graph()->start();
        Node* control = graph()->start();

        Node* check1 = effect = graph()->NewNode(
            simplified()->CheckedTaggedToFloat64(mode, feedback1), value,
            effect, control);
        Reduction r1 = Reduce(check1);
        ASSERT_TRUE(r1.Changed());
        EXPECT_EQ(r1.replacement(), check1);

        Node* check2 = effect = graph()->NewNode(
            simplified()->CheckedTaggedToFloat64(mode, feedback2), value,
            effect, control);
        Reduction r2 = Reduce(check2);
        ASSERT_TRUE(r2.Changed());
        EXPECT_EQ(r2.replacement(), check1);
      }
    }
  }
}

TEST_F(RedundancyEliminationTest,
       CheckedTaggedToFloat64SubsubmedByCheckedTaggedToFloat64) {
  TRACED_FOREACH(FeedbackSource, feedback1, vector_slot_pairs()) {
    TRACED_FOREACH(FeedbackSource, feedback2, vector_slot_pairs()) {
      Node* value = Parameter(0);
      Node* effect = graph()->start();
      Node* control = graph()->start();

      // If the check passed for CheckTaggedInputMode::kNumber, it'll
      // also pass later for CheckTaggedInputMode::kNumberOrOddball.
      Node* check1 = effect =
          graph()->NewNode(simplified()->CheckedTaggedToFloat64(
                               CheckTaggedInputMode::kNumber, feedback1),
                           value, effect, control);
      Reduction r1 = Reduce(check1);
      ASSERT_TRUE(r1.Changed());
      EXPECT_EQ(r1.replacement(), check1);

      Node* check2 = effect = graph()->NewNode(
          simplified()->CheckedTaggedToFloat64(
              CheckTaggedInputMode::kNumberOrOddball, feedback2),
          value, effect, control);
      Reduction r2 = Reduce(check2);
      ASSERT_TRUE(r2.Changed());
      EXPECT_EQ(r2.replacement(), check1);
    }
  }
}

// -----------------------------------------------------------------------------
// CheckedTaggedToInt32

TEST_F(RedundancyEliminationTest, CheckedTaggedToInt32) {
  TRACED_FOREACH(FeedbackSource, feedback1, vector_slot_pairs()) {
    TRACED_FOREACH(FeedbackSource, feedback2, vector_slot_pairs()) {
      TRACED_FOREACH(CheckForMinusZeroMode, mode, kCheckForMinusZeroModes) {
        Node* value = Parameter(0);
        Node* effect = graph()->start();
        Node* control = graph()->start();

        Node* check1 = effect = graph()->NewNode(
            simplified()->CheckedTaggedToInt32(mode, feedback1), value, effect,
            control);
        Reduction r1 = Reduce(check1);
        ASSERT_TRUE(r1.Changed());
        EXPECT_EQ(r1.replacement(), check1);

        Node* check2 = effect = graph()->NewNode(
            simplified()->CheckedTaggedToInt32(mode, feedback2), value, effect,
            control);
        Reduction r2 = Reduce(check2);
        ASSERT_TRUE(r2.Changed());
        EXPECT_EQ(r2.replacement(), check1);
      }
    }
  }
}

TEST_F(RedundancyEliminationTest,
       CheckedTaggedToInt32SubsumedByCheckedTaggedSignedToInt32) {
  TRACED_FOREACH(FeedbackSource, feedback1, vector_slot_pairs()) {
    TRACED_FOREACH(FeedbackSource, feedback2, vector_slot_pairs()) {
      TRACED_FOREACH(CheckForMinusZeroMode, mode, kCheckForMinusZeroModes) {
        Node* value = Parameter(0);
        Node* effect = graph()->start();
        Node* control = graph()->start();

        Node* check1 = effect = graph()->NewNode(
            simplified()->CheckedTaggedSignedToInt32(feedback1), value, effect,
            control);
        Reduction r1 = Reduce(check1);
        ASSERT_TRUE(r1.Changed());
        EXPECT_EQ(r1.replacement(), check1);

        Node* check2 = effect = graph()->NewNode(
            simplified()->CheckedTaggedToInt32(mode, feedback2), value, effect,
            control);
        Reduction r2 = Reduce(check2);
        ASSERT_TRUE(r2.Changed());
        EXPECT_EQ(r2.replacement(), check1);
      }
    }
  }
}

// -----------------------------------------------------------------------------
// CheckedTaggedToInt64

TEST_F(RedundancyEliminationTest, CheckedTaggedToInt64) {
  TRACED_FOREACH(FeedbackSource, feedback1, vector_slot_pairs()) {
    TRACED_FOREACH(FeedbackSource, feedback2, vector_slot_pairs()) {
      TRACED_FOREACH(CheckForMinusZeroMode, mode, kCheckForMinusZeroModes) {
        Node* value = Parameter(0);
        Node* effect = graph()->start();
        Node* control = graph()->start();

        Node* check1 = effect = graph()->NewNode(
            simplified()->CheckedTaggedToInt64(mode, feedback1), value, effect,
            control);
        Reduction r1 = Reduce(check1);
        ASSERT_TRUE(r1.Changed());
        EXPECT_EQ(r1.replacement(), check1);

        Node* check2 = effect = graph()->NewNode(
            simplified()->CheckedTaggedToInt64(mode, feedback2), value, effect,
            control);
        Reduction r2 = Reduce(check2);
        ASSERT_TRUE(r2.Changed());
        EXPECT_EQ(r2.replacement(), check1);
      }
    }
  }
}

// -----------------------------------------------------------------------------
// CheckedTaggedToTaggedPointer

TEST_F(RedundancyEliminationTest, CheckedTaggedToTaggedPointer) {
  TRACED_FOREACH(FeedbackSource, feedback1, vector_slot_pairs()) {
    TRACED_FOREACH(FeedbackSource, feedback2, vector_slot_pairs()) {
      Node* value = Parameter(0);
      Node* effect = graph()->start();
      Node* control = graph()->start();

      Node* check1 = effect = graph()->NewNode(
          simplified()->CheckedTaggedToTaggedPointer(feedback1), value, effect,
          control);
      Reduction r1 = Reduce(check1);
      ASSERT_TRUE(r1.Changed());
      EXPECT_EQ(r1.replacement(), check1);

      Node* check2 = effect = graph()->NewNode(
          simplified()->CheckedTaggedToTaggedPointer(feedback2), value, effect,
          control);
      Reduction r2 = Reduce(check2);
      ASSERT_TRUE(r2.Changed());
      EXPECT_EQ(r2.replacement(), check1);
    }
  }
}

// -----------------------------------------------------------------------------
// CheckedTaggedToTaggedSigned

TEST_F(RedundancyEliminationTest, CheckedTaggedToTaggedSigned) {
  TRACED_FOREACH(FeedbackSource, feedback1, vector_slot_pairs()) {
    TRACED_FOREACH(FeedbackSource, feedback2, vector_slot_pairs()) {
      Node* value = Parameter(0);
      Node* effect = graph()->start();
      Node* control = graph()->start();

      Node* check1 = effect =
          graph()->NewNode(simplified()->CheckedTaggedToTaggedSigned(feedback1),
                           value, effect, control);
      Reduction r1 = Reduce(check1);
      ASSERT_TRUE(r1.Changed());
      EXPECT_EQ(r1.replacement(), check1);

      Node* check2 = effect =
          graph()->NewNode(simplified()->CheckedTaggedToTaggedSigned(feedback2),
                           value, effect, control);
      Reduction r2 = Reduce(check2);
      ASSERT_TRUE(r2.Changed());
      EXPECT_EQ(r2.replacement(), check1);
    }
  }
}

// -----------------------------------------------------------------------------
// CheckedTruncateTaggedToWord32

TEST_F(RedundancyEliminationTest, CheckedTruncateTaggedToWord32) {
  TRACED_FOREACH(FeedbackSource, feedback1, vector_slot_pairs()) {
    TRACED_FOREACH(FeedbackSource, feedback2, vector_slot_pairs()) {
      TRACED_FOREACH(CheckTaggedInputMode, mode, kCheckTaggedInputModes) {
        Node* value = Parameter(0);
        Node* effect = graph()->start();
        Node* control = graph()->start();

        Node* check1 = effect = graph()->NewNode(
            simplified()->CheckedTruncateTaggedToWord32(mode, feedback1), value,
            effect, control);
        Reduction r1 = Reduce(check1);
        ASSERT_TRUE(r1.Changed());
        EXPECT_EQ(r1.replacement(), check1);

        Node* check2 = effect = graph()->NewNode(
            simplified()->CheckedTruncateTaggedToWord32(mode, feedback2), value,
            effect, control);
        Reduction r2 = Reduce(check2);
        ASSERT_TRUE(r2.Changed());
        EXPECT_EQ(r2.replacement(), check1);
      }
    }
  }
}

TEST_F(RedundancyEliminationTest,
       CheckedTruncateTaggedToWord32SubsumedByCheckedTruncateTaggedToWord32) {
  TRACED_FOREACH(FeedbackSource, feedback1, vector_slot_pairs()) {
    TRACED_FOREACH(FeedbackSource, feedback2, vector_slot_pairs()) {
      Node* value = Parameter(0);
      Node* effect = graph()->start();
      Node* control = graph()->start();

      // If the check passed for CheckTaggedInputMode::kNumber, it'll
      // also pass later for CheckTaggedInputMode::kNumberOrOddball.
      Node* check1 = effect =
          graph()->NewNode(simplified()->CheckedTruncateTaggedToWord32(
                               CheckTaggedInputMode::kNumber, feedback1),
                           value, effect, control);
      Reduction r1 = Reduce(check1);
      ASSERT_TRUE(r1.Changed());
      EXPECT_EQ(r1.replacement(), check1);

      Node* check2 = effect = graph()->NewNode(
          simplified()->CheckedTruncateTaggedToWord32(
              CheckTaggedInputMode::kNumberOrOddball, feedback2),
          value, effect, control);
      Reduction r2 = Reduce(check2);
      ASSERT_TRUE(r2.Changed());
      EXPECT_EQ(r2.replacement(), check1);
    }
  }
}

// -----------------------------------------------------------------------------
// CheckedUint32Bounds

TEST_F(RedundancyEliminationTest, CheckedUint32Bounds) {
  TRACED_FOREACH(FeedbackSource, feedback1, vector_slot_pairs()) {
    TRACED_FOREACH(FeedbackSource, feedback2, vector_slot_pairs()) {
      Node* index = Parameter(0);
      Node* length = Parameter(1);
      Node* effect = graph()->start();
      Node* control = graph()->start();

      Node* check1 = effect =
          graph()->NewNode(simplified()->CheckedUint32Bounds(feedback1, {}),
                           index, length, effect, control);
      Reduction r1 = Reduce(check1);
      ASSERT_TRUE(r1.Changed());
      EXPECT_EQ(r1.replacement(), check1);

      Node* check2 = effect =
          graph()->NewNode(simplified()->CheckedUint32Bounds(feedback2, {}),
                           index, length, effect, control);
      Reduction r2 = Reduce(check2);
      ASSERT_TRUE(r2.Changed());
      EXPECT_EQ(r2.replacement(), check1);
    }
  }
}

// -----------------------------------------------------------------------------
// CheckedUint32ToInt32

TEST_F(RedundancyEliminationTest, CheckedUint32ToInt32) {
  TRACED_FOREACH(FeedbackSource, feedback1, vector_slot_pairs()) {
    TRACED_FOREACH(FeedbackSource, feedback2, vector_slot_pairs()) {
      Node* value = Parameter(0);
      Node* effect = graph()->start();
      Node* control = graph()->start();

      Node* check1 = effect =
          graph()->NewNode(simplified()->CheckedUint32ToInt32(feedback1), value,
                           effect, control);
      Reduction r1 = Reduce(check1);
      ASSERT_TRUE(r1.Changed());
      EXPECT_EQ(r1.replacement(), check1);

      Node* check2 = effect =
          graph()->NewNode(simplified()->CheckedUint32ToInt32(feedback2), value,
                           effect, control);
      Reduction r2 = Reduce(check2);
      ASSERT_TRUE(r2.Changed());
      EXPECT_EQ(r2.replacement(), check1);
    }
  }
}

// -----------------------------------------------------------------------------
// CheckedUint32ToTaggedSigned

TEST_F(RedundancyEliminationTest, CheckedUint32ToTaggedSigned) {
  TRACED_FOREACH(FeedbackSource, feedback1, vector_slot_pairs()) {
    TRACED_FOREACH(FeedbackSource, feedback2, vector_slot_pairs()) {
      Node* value = Parameter(0);
      Node* effect = graph()->start();
      Node* control = graph()->start();

      Node* check1 = effect =
          graph()->NewNode(simplified()->CheckedUint32ToTaggedSigned(feedback1),
                           value, effect, control);
      Reduction r1 = Reduce(check1);
      ASSERT_TRUE(r1.Changed());
      EXPECT_EQ(r1.replacement(), check1);

      Node* check2 = effect =
          graph()->NewNode(simplified()->CheckedUint32ToTaggedSigned(feedback2),
                           value, effect, control);
      Reduction r2 = Reduce(check2);
      ASSERT_TRUE(r2.Changed());
      EXPECT_EQ(r2.replacement(), check1);
    }
  }
}

// -----------------------------------------------------------------------------
// CheckedUint64Bounds

TEST_F(RedundancyEliminationTest, CheckedUint64Bounds) {
  TRACED_FOREACH(FeedbackSource, feedback1, vector_slot_pairs()) {
    TRACED_FOREACH(FeedbackSource, feedback2, vector_slot_pairs()) {
      Node* index = Parameter(0);
      Node* length = Parameter(1);
      Node* effect = graph()->start();
      Node* control = graph()->start();

      Node* check1 = effect =
          graph()->NewNode(simplified()->CheckedUint64Bounds(feedback1, {}),
                           index, length, effect, control);
      Reduction r1 = Reduce(check1);
      ASSERT_TRUE(r1.Changed());
      EXPECT_EQ(r1.replacement(), check1);

      Node* check2 = effect =
          graph()->NewNode(simplified()->CheckedUint64Bounds(feedback2, {}),
                           index, length, effect, control);
      Reduction r2 = Reduce(check2);
      ASSERT_TRUE(r2.Changed());
      EXPECT_EQ(r2.replacement(), check1);
    }
  }
}

// -----------------------------------------------------------------------------
// CheckedUint64ToInt32

TEST_F(RedundancyEliminationTest, CheckedUint64ToInt32) {
  TRACED_FOREACH(FeedbackSource, feedback1, vector_slot_pairs()) {
    TRACED_FOREACH(FeedbackSource, feedback2, vector_slot_pairs()) {
      Node* value = Parameter(0);
      Node* effect = graph()->start();
      Node* control = graph()->start();

      Node* check1 = effect =
          graph()->NewNode(simplified()->CheckedUint64ToInt32(feedback1), value,
                           effect, control);
      Reduction r1 = Reduce(check1);
      ASSERT_TRUE(r1.Changed());
      EXPECT_EQ(r1.replacement(), check1);

      Node* check2 = effect =
          graph()->NewNode(simplified()->CheckedUint64ToInt32(feedback2), value,
                           effect, control);
      Reduction r2 = Reduce(check2);
      ASSERT_TRUE(r2.Changed());
      EXPECT_EQ(r2.replacement(), check1);
    }
  }
}

// -----------------------------------------------------------------------------
// CheckedUint64ToTaggedSigned

TEST_F(RedundancyEliminationTest, CheckedUint64ToTaggedSigned) {
  TRACED_FOREACH(FeedbackSource, feedback1, vector_slot_pairs()) {
    TRACED_FOREACH(FeedbackSource, feedback2, vector_slot_pairs()) {
      Node* value = Parameter(0);
      Node* effect = graph()->start();
      Node* control = graph()->start();

      Node* check1 = effect =
          graph()->NewNode(simplified()->CheckedUint64ToTaggedSigned(feedback1),
                           value, effect, control);
      Reduction r1 = Reduce(check1);
      ASSERT_TRUE(r1.Changed());
      EXPECT_EQ(r1.replacement(), check1);

      Node* check2 = effect =
          graph()->NewNode(simplified()->CheckedUint64ToTaggedSigned(feedback2),
                           value, effect, control);
      Reduction r2 = Reduce(check2);
      ASSERT_TRUE(r2.Changed());
      EXPECT_EQ(r2.replacement(), check1);
    }
  }
}

// -----------------------------------------------------------------------------
// SpeculativeNumberEqual

TEST_F(RedundancyEliminationTest,
       SpeculativeNumberEqualWithCheckBoundsBetterType) {
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
          graph()->NewNode(simplified()->SpeculativeNumberEqual(
                               NumberOperationHint::kSignedSmall),
                           lhs, rhs, effect, control);
      Reduction r3 = Reduce(cmp3);
      ASSERT_TRUE(r3.Changed());
      EXPECT_THAT(r3.replacement(),
                  IsSpeculativeNumberEqual(NumberOperationHint::kSignedSmall,
                                           check1, check2, _, _));
    }
  }
}

TEST_F(RedundancyEliminationTest,
       SpeculativeNumberEqualWithCheckBoundsSameType) {
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
          graph()->NewNode(simplified()->SpeculativeNumberEqual(
                               NumberOperationHint::kSignedSmall),
                           lhs, rhs, effect, control);
      Reduction r3 = Reduce(cmp3);
      ASSERT_TRUE(r3.Changed());
      EXPECT_THAT(r3.replacement(),
                  IsSpeculativeNumberEqual(NumberOperationHint::kSignedSmall,
                                           lhs, rhs, _, _));
    }
  }
}

// -----------------------------------------------------------------------------
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

"""

```