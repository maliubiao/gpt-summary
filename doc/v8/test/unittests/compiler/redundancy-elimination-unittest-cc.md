Response:
The user wants a summary of the functionality of the provided C++ code. The code is a unit test for the redundancy elimination optimization pass in the V8 JavaScript engine's compiler.

Here's a breakdown of how to approach the request:

1. **Identify the core purpose:** The file name `redundancy-elimination-unittest.cc` and the included header `src/compiler/redundancy-elimination.h` strongly suggest that this code tests the redundancy elimination compiler pass.

2. **Examine the test structure:** The code uses the Google Test framework (`TEST_F`). Each `TEST_F` block represents a specific test case.

3. **Analyze individual test cases:**  Each test case focuses on verifying that the redundancy elimination pass correctly identifies and removes redundant operations. The tests involve creating nodes representing different operations (like `CheckBounds`, `CheckNumber`, `CheckedFloat64ToInt32`, etc.) and then using the `Reduce` method to apply the redundancy elimination pass. The assertions (`ASSERT_TRUE`, `EXPECT_EQ`) check if the pass correctly identifies redundancies by ensuring the replacement node is the expected one (often the first occurrence of the operation).

4. **Look for patterns and groupings:** Notice that the tests are grouped by the type of operation being tested (e.g., all `CheckBounds` tests together, then `CheckNumber`, etc.). This helps in understanding the scope of the tests.

5. **Address specific instructions:**
    * **`.tq` extension:** The code is C++, not Torque, so this condition is false.
    * **Relationship to JavaScript:**  The tested operations correspond to runtime checks and type conversions performed during JavaScript execution. Examples can illustrate this.
    * **Code logic and inference:** The tests implicitly perform logical inference by checking if one operation subsumes another (e.g., `CheckSmi` subsuming `CheckNumber`). Hypothetical inputs and outputs can demonstrate this.
    * **Common programming errors:** The tests relate to optimizations that can prevent certain runtime errors. Examples of these errors can be provided.

6. **Synthesize the information:** Combine the observations to create a concise summary of the file's functionality. Focus on the core purpose of testing redundancy elimination and the types of redundancies being tested.

7. **Address the "part 1 of 2" instruction:**  Acknowledge that this is the first part and prepare for a potential second part.

**Pre-computation and Pre-analysis:**

* I've identified the core concept: redundancy elimination in the V8 compiler.
* I've scanned the test names and the operations they test (e.g., `CheckBounds`, `CheckedFloat64ToInt32`).
* I've noted the use of `FeedbackSource`, which relates to runtime feedback used for optimization.
* I've seen the patterns in the test structure (creating two similar nodes and checking if the second is replaced by the first).

By following these steps, I can generate a comprehensive and accurate summary that addresses all aspects of the user's request.
这是 V8 JavaScript 引擎的一部分，具体来说，它是编译器中用于消除冗余操作的优化过程的单元测试。

**功能归纳:**

这个 C++ 代码文件的主要功能是测试 `RedundancyElimination` 编译器优化Pass 的正确性。它通过创建包含各种操作节点的图，并验证 `RedundancyElimination` Pass 能否正确地识别并消除冗余的节点。

**详细功能拆解:**

1. **测试 `RedundancyElimination` 类:**  这个文件中的测试用例 (`TEST_F`) 针对 `RedundancyElimination` 类中的 `Reduce` 方法。`Reduce` 方法是该 Pass 的核心，它负责检查给定的节点是否可以被优化掉。

2. **测试各种冗余场景:**  代码针对多种不同的操作符 (operators) 进行了测试，这些操作符主要来自 `Simplified` 阶段的图构建。  每个 `TEST_F` 都对应一个或一组特定的冗余消除场景，例如：
    * **`CheckBounds`:** 检查数组或字符串索引是否越界。
    * **`CheckNumber` 和 `CheckSmi`:**  检查一个值是否是数字或小整数 (Smi)。
    * **`CheckReceiver` 和 `CheckReceiverOrNullOrUndefined`:** 检查一个值是否可以作为 `this` 接收者。
    * **`CheckString` 和 `CheckInternalizedString`:** 检查一个值是否是字符串或内部化字符串。
    * **`CheckSymbol`:** 检查一个值是否是 Symbol。
    * **各种 `Checked...` 操作:**  这些操作通常包含类型检查和转换，例如 `CheckedFloat64ToInt32` (检查并转换 Float64 到 Int32)。
    * **`SpeculativeNumberEqual`:**  推测性的数字相等比较。

3. **模拟图的构建:** 每个测试用例都会创建一个小的图片段，通常包含一些参数节点、effect 节点和 control 节点，以及要测试的特定操作节点。

4. **验证冗余消除:**  测试的核心逻辑通常是创建两个相同的操作节点（或者一个操作会被另一个操作隐含的情况），然后调用 `Reduce` 方法。测试会断言 (`ASSERT_TRUE(r.Changed())`)  `Reduce` 方法返回了已更改的信息，并且替换的节点 (`EXPECT_EQ(r.replacement(), check1)`) 是期望的节点（通常是第一个创建的节点），这表明第二个节点被成功识别为冗余并被替换为第一个节点。

5. **使用 `FeedbackSource`:**  一些测试用例使用了 `FeedbackSource`，这模拟了运行时反馈信息对优化决策的影响。例如，同一个 `CheckBounds` 操作，如果关联了不同的反馈信息，可能不会被认为是完全冗余的。

**关于 `.tq` 结尾:**

正如代码注释所示，这个文件以 `.cc` 结尾，所以它是一个 C++ 源代码文件，而不是 Torque 源代码。如果文件以 `.tq` 结尾，那它才是 V8 Torque 源代码。

**与 JavaScript 的关系及示例:**

这些测试用例针对的优化直接关系到 JavaScript 代码的执行效率。  编译器会尝试消除不必要的类型检查和转换，从而提高性能。

**JavaScript 示例:**

```javascript
function foo(arr, index) {
  // 第一次访问 arr[index]，可能需要进行边界检查
  const value1 = arr[index];
  // 如果编译器能推断出 index 没有改变，并且数组没有被修改，
  // 那么第二次访问 arr[index] 的边界检查可能就是冗余的，
  // 可以被优化掉。
  const value2 = arr[index];
  return value1 + value2;
}

// 类型检查的例子
function bar(x) {
  // 第一次使用 x 进行加法，可能需要检查 x 是否为数字
  const sum1 = x + 1;
  // 如果编译器能确定 x 在这里仍然是数字类型，
  // 那么第二次加法前的类型检查可能是冗余的。
  const sum2 = x + 2;
  return sum1 + sum2;
}
```

在这些 JavaScript 例子中，`RedundancyElimination` Pass 试图识别并消除重复的边界检查或类型检查操作，就像在 C++ 单元测试中模拟的那样。

**代码逻辑推理和假设输入输出:**

以 `TEST_F(RedundancyEliminationTest, CheckBounds)` 为例：

**假设输入:**

* `index` 节点代表一个索引值（例如，来自参数 0）。
* `length` 节点代表数组或字符串的长度（例如，来自参数 1）。
* 两个 `CheckBounds` 节点，`check1` 和 `check2`，都使用相同的 `index` 和 `length` 输入，但可能关联不同的 `FeedbackSource`。

**代码逻辑:**

1. 创建两个 `CheckBounds` 节点 `check1` 和 `check2`，它们的作用是检查 `index` 是否在 `0` 到 `length - 1` 的范围内。
2. 对 `check1` 调用 `Reduce` 方法。  由于这是第一次遇到这个 `CheckBounds`，预计它不会被立即消除，但其状态会被记录下来。
3. 对 `check2` 调用 `Reduce` 方法。  `RedundancyElimination` Pass 会检查是否已经存在一个相同的 `CheckBounds` 操作，并且它们的输入（`index` 和 `length`）以及 effect 和 control 依赖都相同。

**预期输出:**

如果 `check1` 和 `check2` 的所有输入（包括 effect 和 control）以及操作符本身都相同，那么 `r2.replacement()` 应该等于 `check1`，这意味着 `check2` 被识别为冗余，并被替换为指向 `check1` 的指针。

**涉及用户常见的编程错误:**

虽然这个优化本身不是为了直接修复用户的编程错误，但它可以减轻某些因冗余代码导致的性能问题。例如，用户可能会在循环中多次进行相同的类型检查或边界检查，而编译器可以通过冗余消除来优化这些情况。

**示例：**

```javascript
function processArray(arr) {
  for (let i = 0; i < arr.length; i++) {
    // 每次循环都会访问 arr[i]，可能触发边界检查
    const element1 = arr[i];
    // 这里再次访问相同的 arr[i]，如果编译器没有做冗余消除，
    // 可能会再次进行相同的边界检查，这是不必要的。
    const element2 = arr[i];
    console.log(element1, element2);
  }
}
```

在这个例子中，如果 `RedundancyElimination` Pass 工作正常，第二次访问 `arr[i]` 的边界检查就可以被优化掉。

**总结 (针对第 1 部分):**

这个 C++ 源代码文件是 V8 编译器中 `RedundancyElimination` 优化 Pass 的单元测试。它通过创建包含各种操作节点的图，并验证该 Pass 能否正确地识别和消除重复或隐含的操作，例如边界检查、类型检查和类型转换。这些测试覆盖了多种不同的操作符和场景，并使用了运行时反馈信息来模拟真实的优化过程。 这个文件的目的是确保 V8 的冗余消除优化能够正确有效地工作，从而提高 JavaScript 代码的执行效率。

### 提示词
```
这是目录为v8/test/unittests/compiler/redundancy-elimination-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/redundancy-elimination-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
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

// --------------------------------------
```