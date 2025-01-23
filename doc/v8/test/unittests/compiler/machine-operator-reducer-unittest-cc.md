Response:
The user wants a summary of the functionality of the provided C++ code. The code is a unit test for a compiler optimization pass in V8 called `MachineOperatorReducer`.

Here's a breakdown of the thought process to generate the response:

1. **Identify the core purpose:** The filename `machine-operator-reducer-unittest.cc` and the inclusion of `src/compiler/machine-operator-reducer.h` strongly indicate that this code tests the `MachineOperatorReducer` class. Unit tests verify the behavior of specific units of code, in this case, the operator reducer.

2. **Analyze the test setup:** The code defines a `MachineOperatorReducerTest` class that inherits from `GraphTest`. This suggests it's testing graph-based optimizations. The `Reduce` method is crucial; it creates a `MachineOperatorReducer` and calls its `Reduce` method on a given `Node`. This confirms that the tests are about how the reducer transforms or simplifies graph nodes.

3. **Examine the test cases:** The numerous `TEST_F` macros indicate individual test cases. The names of these test cases (e.g., `ChangeFloat64ToFloat32WithConstant`, `Word32AndWithWord32ShlWithConstant`) reveal the specific optimizations being tested. They follow a pattern: `OperationBeingReduced` `With` `InputNodeType`.

4. **Infer the reducer's goals:**  The reducer likely aims to simplify expressions involving machine-level operators. This includes:
    * **Constant folding:** Reducing operations with constant inputs to constant outputs.
    * **Identity elimination:** Removing redundant operations (e.g., converting an int to a float and back to an int).
    * **Algebraic simplification:** Applying mathematical identities to simplify expressions.
    * **Lowering:** Transforming higher-level operations into simpler or more efficient lower-level operations.

5. **Check for Torque involvement:** The prompt asks about `.tq` files. A quick scan of the provided code shows no `.tq` extension, so this part of the question can be answered negatively.

6. **Relate to JavaScript (if applicable):** The prompt asks about the relationship to JavaScript. The `MachineOperatorReducer` works at a lower level of the compiler pipeline, after JavaScript has been parsed and an intermediate representation (the graph) has been created. While the optimizations directly affect how JavaScript is executed, the tests themselves don't directly involve JavaScript *syntax*. However, the *semantics* of the operations being optimized (e.g., integer and floating-point arithmetic, bitwise operations) are directly tied to JavaScript behavior. The generated JavaScript examples would demonstrate the *effect* of these optimizations.

7. **Identify code logic and potential errors:**  The test cases often involve specific patterns of operations. The `IsTruncatingDiv` and `IsTruncatingDiv64` helper functions suggest testing optimizations related to integer division by constants. Potential programming errors that the reducer might help mitigate include inefficient or redundant code patterns.

8. **Address the "part 1 of 4" instruction:** The user explicitly mentions this is part 1. Therefore, the summary should focus on the general functionality demonstrated in this specific code snippet and avoid anticipating the content of the subsequent parts.

9. **Structure the response:** Organize the information clearly into sections addressing each part of the prompt. Use bullet points for lists of features and test categories. Provide concise explanations.

10. **Refine the language:** Use precise terminology (e.g., "intermediate representation," "constant folding").

By following these steps, the detailed and accurate summary provided earlier can be generated. The key is to understand the context of the code (a compiler unit test) and analyze the structure and content of the test cases.
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/machine-operator-reducer.h"

#include <cstdint>
#include <limits>

#include "src/base/bits.h"
#include "src/base/division-by-constant.h"
#include "src/base/ieee754.h"
#include "src/base/overflowing-math.h"
#include "src/builtins/builtins.h"
#include "src/common/globals.h"
#include "src/compiler/js-graph.h"
#include "src/compiler/machine-operator.h"
#include "src/numbers/conversions-inl.h"
#include "src/numbers/ieee754.h"
#include "test/unittests/compiler/graph-unittest.h"
#include "test/unittests/compiler/node-test-utils.h"
#include "testing/gmock-support.h"

using testing::AllOf;
using testing::BitEq;
using testing::Capture;
using testing::CaptureEq;
using testing::NanSensitiveDoubleEq;

namespace v8 {
namespace internal {
namespace compiler {

class MachineOperatorReducerTest : public GraphTest {
 public:
  explicit MachineOperatorReducerTest(int num_parameters = 2)
      : GraphTest(num_parameters),
        data_(std::make_unique<Data>(isolate(), zone(), graph(), tick_counter(),
                                     broker())) {}

 protected:
  void Reset() {
    data_ = nullptr;
    GraphTest::Reset();
    data_ = std::make_unique<Data>(isolate(), zone(), graph(), tick_counter(),
                                   broker());
  }

  Reduction Reduce(Node* node) {
    JSOperatorBuilder javascript(zone());
    JSGraph jsgraph(isolate(), graph(), common(), &javascript, nullptr,
                    &data_->machine_);
    MachineOperatorReducer reducer(
        &data_->graph_reducer_, &jsgraph,
        MachineOperatorReducer::kPropagateSignallingNan);
    return reducer.Reduce(node);
  }

  Matcher<Node*> IsTruncatingDiv(const Matcher<Node*>& dividend_matcher,
                                 const int32_t divisor) {
    base::MagicNumbersForDivision<uint32_t> const mag =
        base::SignedDivisionByConstant(base::bit_cast<uint32_t>(divisor));
    int32_t const multiplier = base::bit_cast<int32_t>(mag.multiplier);
    int32_t const shift = base::bit_cast<int32_t>(mag.shift);
    Matcher<Node*> quotient_matcher =
        IsInt32MulHigh(dividend_matcher, IsInt32Constant(multiplier));
    if (divisor > 0 && multiplier < 0) {
      quotient_matcher = IsInt32Add(quotient_matcher, dividend_matcher);
    } else if (divisor < 0 && multiplier > 0) {
      quotient_matcher = IsInt32Sub(quotient_matcher, dividend_matcher);
    }
    if (shift) {
      quotient_matcher = IsWord32Sar(quotient_matcher, IsInt32Constant(shift));
    }
    return IsInt32Add(quotient_matcher,
                      IsWord32Shr(dividend_matcher, IsInt32Constant(31)));
  }

  Matcher<Node*> IsTruncatingDiv64(const Matcher<Node*>& dividend_matcher,
                                   const int64_t divisor) {
    base::MagicNumbersForDivision<uint64_t> const mag =
        base::SignedDivisionByConstant(base::bit_cast<uint64_t>(divisor));
    int64_t const multiplier = base::bit_cast<int64_t>(mag.multiplier);
    int64_t const shift = base::bit_cast<int32_t>(mag.shift);
    Matcher<Node*> quotient_matcher =
        IsInt64MulHigh(dividend_matcher, IsInt64Constant(multiplier));
    if (divisor > 0 && multiplier < 0) {
      quotient_matcher = IsInt64Add(quotient_matcher, dividend_matcher);
    } else if (divisor < 0 && multiplier > 0) {
      quotient_matcher = IsInt64Sub(quotient_matcher, dividend_matcher);
    }
    if (shift) {
      quotient_matcher = IsWord64Sar(quotient_matcher, IsInt64Constant(shift));
    }
    return IsInt64Add(quotient_matcher,
                      IsWord64Shr(dividend_matcher, IsInt64Constant(63)));
  }

  MachineOperatorBuilder* machine() { return &data_->machine_; }

 private:
  struct Data {
    Data(Isolate* isolate, Zone* zone, Graph* graph, TickCounter* tick_counter,
         JSHeapBroker* broker)
        : machine_(zone, MachineType::PointerRepresentation(),
                   MachineOperatorBuilder::kAllOptionalOps),
          common_(zone),
          javascript_(zone),
          jsgraph_(isolate, graph, &common_, &javascript_, nullptr, &machine_),
          graph_reducer_(zone, graph, tick_counter, broker, jsgraph_.Dead()) {}
    MachineOperatorBuilder machine_;
    CommonOperatorBuilder common_;
    JSOperatorBuilder javascript_;
    JSGraph jsgraph_;
    GraphReducer graph_reducer_;
  };
  std::unique_ptr<Data> data_;
};

template <typename T>
class MachineOperatorReducerTestWithParam
    : public MachineOperatorReducerTest,
      public ::testing::WithParamInterface<T> {
 public:
  explicit MachineOperatorReducerTestWithParam(int num_parameters = 2)
      : MachineOperatorReducerTest(num_parameters) {}
  ~MachineOperatorReducerTestWithParam() override = default;
};

namespace {

// ... (Constant value definitions)

}  // namespace

// -----------------------------------------------------------------------------
// ChangeFloat64ToFloat32

TEST_F(MachineOperatorReducerTest, ChangeFloat64ToFloat32WithConstant) {
  TRACED_FOREACH(float, x, kFloat32Values) {
    Reduction reduction = Reduce(graph()->NewNode(
        machine()->ChangeFloat32ToFloat64(), Float32Constant(x)));
    ASSERT_TRUE(reduction.Changed());
    EXPECT_THAT(reduction.replacement(), IsFloat64Constant(BitEq<double>(x)));
  }
}

// -----------------------------------------------------------------------------
// ChangeFloat64ToInt32

TEST_F(MachineOperatorReducerTest,
       ChangeFloat64ToInt32WithChangeInt32ToFloat64) {
  Node* value = Parameter(0);
  Reduction reduction = Reduce(graph()->NewNode(
      machine()->ChangeFloat64ToInt32(),
      graph()->NewNode(machine()->ChangeInt32ToFloat64(), value)));
  ASSERT_TRUE(reduction.Changed());
  EXPECT_EQ(value, reduction.replacement());
}

TEST_F(MachineOperatorReducerTest, ChangeFloat64ToInt32WithConstant) {
  TRACED_FOREACH(int32_t, x, kInt32Values) {
    Reduction reduction = Reduce(graph()->NewNode(
        machine()->ChangeFloat64ToInt32(), Float64Constant(FastI2D(x))));
    ASSERT_TRUE(reduction.Changed());
    EXPECT_THAT(reduction.replacement(), IsInt32Constant(x));
  }
}

// ... (More test cases for different operators)

TEST_F(MachineOperatorReducerTest, Word32AndWithInt32AddAndConstant) {
  Node* const p0 = Parameter(0);
  Node* const p1 = Parameter(1);

  TRACED_FORRANGE(int32_t, l, 1, 31) {
    TRACED_FOREACH(int32_t, k, kInt32Values) {
      if (Shl(k, l) == 0) continue;
      // (x + (K << L)) & (-1 << L) => (x & (-1 << L)) + (K << L)
      Reduction const r = Reduce(graph()->NewNode(
          machine()->Word32And(),
          graph()->NewNode(machine()->Int32Add(), p0, Int32Constant(Shl(k, l))),
          Int32Constant(Shl(-1, l))));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(),
                  IsInt32Add(IsWord32And(p0, IsInt32Constant(Shl(-1, l))),
                             IsInt32Constant(Shl(k, l))));
    }

    Node* s1 = graph()->NewNode(machine()->Word32Shl(), p1, Int32Constant(l));

    // (y << L + x) & (-1 << L) => (x & (-1 << L)) + y << L
    Reduction const r1 = Reduce(graph()->NewNode(
        machine()->Word32And(), graph()->NewNode(machine()->Int32Add(), s1, p0),
        Int32Constant(Shl(-1, l))));
```

### 功能列举

`v8/test/unittests/compiler/machine-operator-reducer-unittest.cc` 是 V8 JavaScript 引擎中**编译器**模块的一个**单元测试文件**。它的主要功能是测试 `MachineOperatorReducer` 类的各种优化功能。

具体来说，这个文件测试了 `MachineOperatorReducer` 如何对**机器操作 (machine operators)** 进行简化和优化。这些优化包括但不限于：

* **常量折叠 (Constant Folding):**  如果操作符的输入是常量，则在编译时计算结果，替换为常量值。例如，将 `1 + 2` 替换为 `3`。
* **代数简化 (Algebraic Simplification):**  应用代数规则来简化表达式。例如，将 `x + 0` 替换为 `x`。
* **操作符替换 (Operator Replacement):** 将一个操作符替换为另一个更高效或更简单的操作符。 例如，将某些除法操作替换为乘法和移位操作的组合。
* **类型转换优化 (Type Conversion Optimization):**  优化不同数值类型之间的转换操作，例如浮点数和整数之间的转换。如果连续的转换可以被消除，则进行消除。
* **位运算优化 (Bitwise Operation Optimization):**  优化位与、位或、位移等操作，例如利用掩码进行简化。

### 关于文件扩展名和 Torque

`v8/test/unittests/compiler/machine-operator-reducer-unittest.cc` 的扩展名是 `.cc`，这表明它是一个 **C++ 源代码文件**。

如果文件以 `.tq` 结尾，那么它才是一个 **V8 Torque 源代码文件**。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。

**结论：这个文件不是 Torque 源代码。**

### 与 Javascript 的功能关系

`MachineOperatorReducer` 的优化直接影响最终生成的机器码的效率，因此它与 JavaScript 的性能息息相关。虽然这个测试文件本身是用 C++ 写的，用于测试编译器的内部逻辑，但它所验证的优化是为了让执行 JavaScript 代码更快。

**JavaScript 示例：**

假设 `MachineOperatorReducer` 成功地优化了浮点数到整数的转换。

```javascript
function example(x) {
  // 在 JavaScript 中，x 可能是浮点数
  const integerValue = Math.floor(x);
  return integerValue;
}

// 编译器在编译 `Math.floor(x)` 时，会生成一个浮点数到整数的转换操作。
// MachineOperatorReducer 的测试确保了这个转换操作能被正确优化。
```

另一个例子是关于位运算的优化：

```javascript
function bitwiseExample(value) {
  // & 运算符是按位与
  return value & 0xFF; // 提取低 8 位
}

// MachineOperatorReducer 的相关测试会验证类似 `Word32And` 这样的操作是否被正确优化。
```

### 代码逻辑推理示例

考虑以下测试用例：

```cpp
TEST_F(MachineOperatorReducerTest, ChangeFloat64ToInt32WithConstant) {
  TRACED_FOREACH(int32_t, x, kInt32Values) {
    Reduction reduction = Reduce(graph()->NewNode(
        machine()->ChangeFloat64ToInt32(), Float64Constant(FastI2D(x))));
    ASSERT_TRUE(reduction.Changed());
    EXPECT_THAT(reduction.replacement(), IsInt32Constant(x));
  }
}
```

**假设输入：**  一个表示将浮点数转换为 32 位整数的节点 (`ChangeFloat64ToInt32`)，其输入是一个表示常量浮点数的节点 (`Float64Constant`)。 假设 `FastI2D(x)` 将整数 `x` 转换为对应的双精度浮点数。

**例如：**  `x = 10`。那么 `Float64Constant(FastI2D(10))` 会创建一个表示浮点数 `10.0` 的节点。

**代码逻辑推理：**  `MachineOperatorReducer` 会识别出 `ChangeFloat64ToInt32` 的输入是一个常量浮点数。它可以直接在编译时计算出结果，并将该操作替换为表示该常量整数的节点。

**输出：**  `MachineOperatorReducer` 会将原始的 `ChangeFloat64ToInt32` 节点替换为一个 `Int32Constant` 节点，其值为 `10`。

### 用户常见的编程错误示例

虽然 `MachineOperatorReducer` 主要关注编译器的优化，但它所针对的某些操作可能与用户常见的编程错误相关。例如：

1. **不必要的类型转换：** 用户可能在 JavaScript 中进行不必要的类型转换，例如先将数字转换为字符串再转换回数字。编译器的一些优化可以减轻这种低效代码的影响。

   ```javascript
   function unnecessaryConversion(num) {
     const str = String(num);
     return Number(str); // 实际上可以直接返回 num
   }
   ```
   虽然 `MachineOperatorReducer` 不直接处理 JavaScript 语法层面的错误，但它会处理编译器生成的类型转换操作。

2. **低效的位运算：** 用户可能使用效率较低的方式进行位运算。例如，使用乘法或除法代替移位操作。

   ```javascript
   function inefficientShift(value) {
     return value * 2; // 可以用 value << 1 代替
   }
   ```
   `MachineOperatorReducer` 中对 `Word32Shl` 等操作的测试，正是为了确保编译器能够将这些操作优化到最佳状态。

3. **浮点数精度问题：**  在浮点数和整数之间进行转换时，可能会出现精度丢失或意外的行为。`MachineOperatorReducer` 中对 `ChangeFloat64ToInt32` 等操作的测试，确保了这些转换在编译器层面是正确的，但无法完全避免由于浮点数本身的特性导致的问题。

   ```javascript
   function floatToInt(x) {
     return parseInt(x); // 对于很大的浮点数，结果可能不精确
   }
   ```

### 功能归纳 (第 1 部分)

作为第 1 部分，这个 C++ 源代码文件 `v8/test/unittests/compiler/machine-operator-reducer-unittest.cc` 的主要功能是：

* **测试 V8 编译器中 `MachineOperatorReducer` 类的基本优化功能。**
* **针对各种机器操作 (如类型转换、算术运算、位运算) 及其组合进行单元测试。**
* **验证 `MachineOperatorReducer` 能否正确地将某些操作简化为常量。**
* **验证 `MachineOperatorReducer` 能否正确地消除冗余操作。**
* **验证 `MachineOperatorReducer` 能否正确地将某些操作替换为更优的操作。**

这个文件通过创建特定的操作符节点，然后调用 `MachineOperatorReducer` 的 `Reduce` 方法，并断言优化后的结果是否符合预期来进行测试。它不涉及 Torque 源代码，但其测试的优化功能直接影响 JavaScript 代码的执行效率。

### 提示词
```
这是目录为v8/test/unittests/compiler/machine-operator-reducer-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/machine-operator-reducer-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/machine-operator-reducer.h"

#include <cstdint>
#include <limits>

#include "src/base/bits.h"
#include "src/base/division-by-constant.h"
#include "src/base/ieee754.h"
#include "src/base/overflowing-math.h"
#include "src/builtins/builtins.h"
#include "src/common/globals.h"
#include "src/compiler/js-graph.h"
#include "src/compiler/machine-operator.h"
#include "src/numbers/conversions-inl.h"
#include "src/numbers/ieee754.h"
#include "test/unittests/compiler/graph-unittest.h"
#include "test/unittests/compiler/node-test-utils.h"
#include "testing/gmock-support.h"

using testing::AllOf;
using testing::BitEq;
using testing::Capture;
using testing::CaptureEq;
using testing::NanSensitiveDoubleEq;

namespace v8 {
namespace internal {
namespace compiler {

class MachineOperatorReducerTest : public GraphTest {
 public:
  explicit MachineOperatorReducerTest(int num_parameters = 2)
      : GraphTest(num_parameters),
        data_(std::make_unique<Data>(isolate(), zone(), graph(), tick_counter(),
                                     broker())) {}

 protected:
  void Reset() {
    data_ = nullptr;
    GraphTest::Reset();
    data_ = std::make_unique<Data>(isolate(), zone(), graph(), tick_counter(),
                                   broker());
  }

  Reduction Reduce(Node* node) {
    JSOperatorBuilder javascript(zone());
    JSGraph jsgraph(isolate(), graph(), common(), &javascript, nullptr,
                    &data_->machine_);
    MachineOperatorReducer reducer(
        &data_->graph_reducer_, &jsgraph,
        MachineOperatorReducer::kPropagateSignallingNan);
    return reducer.Reduce(node);
  }

  Matcher<Node*> IsTruncatingDiv(const Matcher<Node*>& dividend_matcher,
                                 const int32_t divisor) {
    base::MagicNumbersForDivision<uint32_t> const mag =
        base::SignedDivisionByConstant(base::bit_cast<uint32_t>(divisor));
    int32_t const multiplier = base::bit_cast<int32_t>(mag.multiplier);
    int32_t const shift = base::bit_cast<int32_t>(mag.shift);
    Matcher<Node*> quotient_matcher =
        IsInt32MulHigh(dividend_matcher, IsInt32Constant(multiplier));
    if (divisor > 0 && multiplier < 0) {
      quotient_matcher = IsInt32Add(quotient_matcher, dividend_matcher);
    } else if (divisor < 0 && multiplier > 0) {
      quotient_matcher = IsInt32Sub(quotient_matcher, dividend_matcher);
    }
    if (shift) {
      quotient_matcher = IsWord32Sar(quotient_matcher, IsInt32Constant(shift));
    }
    return IsInt32Add(quotient_matcher,
                      IsWord32Shr(dividend_matcher, IsInt32Constant(31)));
  }

  Matcher<Node*> IsTruncatingDiv64(const Matcher<Node*>& dividend_matcher,
                                   const int64_t divisor) {
    base::MagicNumbersForDivision<uint64_t> const mag =
        base::SignedDivisionByConstant(base::bit_cast<uint64_t>(divisor));
    int64_t const multiplier = base::bit_cast<int64_t>(mag.multiplier);
    int64_t const shift = base::bit_cast<int32_t>(mag.shift);
    Matcher<Node*> quotient_matcher =
        IsInt64MulHigh(dividend_matcher, IsInt64Constant(multiplier));
    if (divisor > 0 && multiplier < 0) {
      quotient_matcher = IsInt64Add(quotient_matcher, dividend_matcher);
    } else if (divisor < 0 && multiplier > 0) {
      quotient_matcher = IsInt64Sub(quotient_matcher, dividend_matcher);
    }
    if (shift) {
      quotient_matcher = IsWord64Sar(quotient_matcher, IsInt64Constant(shift));
    }
    return IsInt64Add(quotient_matcher,
                      IsWord64Shr(dividend_matcher, IsInt64Constant(63)));
  }

  MachineOperatorBuilder* machine() { return &data_->machine_; }

 private:
  struct Data {
    Data(Isolate* isolate, Zone* zone, Graph* graph, TickCounter* tick_counter,
         JSHeapBroker* broker)
        : machine_(zone, MachineType::PointerRepresentation(),
                   MachineOperatorBuilder::kAllOptionalOps),
          common_(zone),
          javascript_(zone),
          jsgraph_(isolate, graph, &common_, &javascript_, nullptr, &machine_),
          graph_reducer_(zone, graph, tick_counter, broker, jsgraph_.Dead()) {}
    MachineOperatorBuilder machine_;
    CommonOperatorBuilder common_;
    JSOperatorBuilder javascript_;
    JSGraph jsgraph_;
    GraphReducer graph_reducer_;
  };
  std::unique_ptr<Data> data_;
};


template <typename T>
class MachineOperatorReducerTestWithParam
    : public MachineOperatorReducerTest,
      public ::testing::WithParamInterface<T> {
 public:
  explicit MachineOperatorReducerTestWithParam(int num_parameters = 2)
      : MachineOperatorReducerTest(num_parameters) {}
  ~MachineOperatorReducerTestWithParam() override = default;
};


namespace {

const float kFloat32Values[] = {
    -std::numeric_limits<float>::infinity(), -2.70497e+38f, -1.4698e+37f,
    -1.22813e+35f,                           -1.20555e+35f, -1.34584e+34f,
    -1.0079e+32f,                            -6.49364e+26f, -3.06077e+25f,
    -1.46821e+25f,                           -1.17658e+23f, -1.9617e+22f,
    -2.7357e+20f,                            -1.48708e+13f, -1.89633e+12f,
    -4.66622e+11f,                           -2.22581e+11f, -1.45381e+10f,
    -1.3956e+09f,                            -1.32951e+09f, -1.30721e+09f,
    -1.19756e+09f,                           -9.26822e+08f, -6.35647e+08f,
    -4.00037e+08f,                           -1.81227e+08f, -5.09256e+07f,
    -964300.0f,                              -192446.0f,    -28455.0f,
    -27194.0f,                               -26401.0f,     -20575.0f,
    -17069.0f,                               -9167.0f,      -960.178f,
    -113.0f,                                 -62.0f,        -15.0f,
    -7.0f,                                   -0.0256635f,   -4.60374e-07f,
    -3.63759e-10f,                           -4.30175e-14f, -5.27385e-15f,
    -1.48084e-15f,                           -1.05755e-19f, -3.2995e-21f,
    -1.67354e-23f,                           -1.11885e-23f, -1.78506e-30f,
    -5.07594e-31f,                           -3.65799e-31f, -1.43718e-34f,
    -1.27126e-38f,                           -0.0f,         0.0f,
    1.17549e-38f,                            1.56657e-37f,  4.08512e-29f,
    3.31357e-28f,                            6.25073e-22f,  4.1723e-13f,
    1.44343e-09f,                            5.27004e-08f,  9.48298e-08f,
    5.57888e-07f,                            4.89988e-05f,  0.244326f,
    12.4895f,                                19.0f,         47.0f,
    106.0f,                                  538.324f,      564.536f,
    819.124f,                                7048.0f,       12611.0f,
    19878.0f,                                20309.0f,      797056.0f,
    1.77219e+09f,                            1.51116e+11f,  4.18193e+13f,
    3.59167e+16f,                            3.38211e+19f,  2.67488e+20f,
    1.78831e+21f,                            9.20914e+21f,  8.35654e+23f,
    1.4495e+24f,                             5.94015e+25f,  4.43608e+30f,
    2.44502e+33f,                            2.61152e+33f,  1.38178e+37f,
    1.71306e+37f,                            3.31899e+38f,  3.40282e+38f,
    std::numeric_limits<float>::infinity()};


const double kFloat64Values[] = {
    -V8_INFINITY,  -4.23878e+275, -5.82632e+265, -6.60355e+220, -6.26172e+212,
    -2.56222e+211, -4.82408e+201, -1.84106e+157, -1.63662e+127, -1.55772e+100,
    -1.67813e+72,  -2.3382e+55,   -3.179e+30,    -1.441e+09,    -1.0647e+09,
    -7.99361e+08,  -5.77375e+08,  -2.20984e+08,  -32757,        -13171,
    -9970,         -3984,         -107,          -105,          -92,
    -77,           -61,           -0.000208163,  -1.86685e-06,  -1.17296e-10,
    -9.26358e-11,  -5.08004e-60,  -1.74753e-65,  -1.06561e-71,  -5.67879e-79,
    -5.78459e-130, -2.90989e-171, -7.15489e-243, -3.76242e-252, -1.05639e-263,
    -4.40497e-267, -2.19666e-273, -4.9998e-276,  -5.59821e-278, -2.03855e-282,
    -5.99335e-283, -7.17554e-284, -3.11744e-309, -0.0,          0.0,
    2.22507e-308,  1.30127e-270,  7.62898e-260,  4.00313e-249,  3.16829e-233,
    1.85244e-228,  2.03544e-129,  1.35126e-110,  1.01182e-106,  5.26333e-94,
    1.35292e-90,   2.85394e-83,   1.78323e-77,   5.4967e-57,    1.03207e-25,
    4.57401e-25,   1.58738e-05,   2,             125,           2310,
    9636,          14802,         17168,         28945,         29305,
    4.81336e+07,   1.41207e+08,   4.65962e+08,   1.40499e+09,   2.12648e+09,
    8.80006e+30,   1.4446e+45,    1.12164e+54,   2.48188e+89,   6.71121e+102,
    3.074e+112,    4.9699e+152,   5.58383e+166,  4.30654e+172,  7.08824e+185,
    9.6586e+214,   2.028e+223,    6.63277e+243,  1.56192e+261,  1.23202e+269,
    5.72883e+289,  8.5798e+290,   1.40256e+294,  1.79769e+308,  V8_INFINITY};


const int32_t kInt32Values[] = {
    std::numeric_limits<int32_t>::min(), -1914954528, -1698749618,
    -1578693386,                         -1577976073, -1573998034,
    -1529085059,                         -1499540537, -1299205097,
    -1090814845,                         -938186388,  -806828902,
    -750927650,                          -520676892,  -513661538,
    -453036354,                          -433622833,  -282638793,
    -28375,                              -27788,      -22770,
    -18806,                              -14173,      -11956,
    -11200,                              -10212,      -8160,
    -3751,                               -2758,       -1522,
    -121,                                -120,        -118,
    -117,                                -106,        -84,
    -80,                                 -74,         -59,
    -52,                                 -48,         -39,
    -35,                                 -17,         -11,
    -10,                                 -9,          -7,
    -5,                                  0,           9,
    12,                                  17,          23,
    29,                                  31,          33,
    35,                                  40,          47,
    55,                                  56,          62,
    64,                                  67,          68,
    69,                                  74,          79,
    84,                                  89,          90,
    97,                                  104,         118,
    124,                                 126,         127,
    7278,                                17787,       24136,
    24202,                               25570,       26680,
    30242,                               32399,       420886487,
    642166225,                           821912648,   822577803,
    851385718,                           1212241078,  1411419304,
    1589626102,                          1596437184,  1876245816,
    1954730266,                          2008792749,  2045320228,
    std::numeric_limits<int32_t>::max()};

const int64_t kInt64Values[] = {std::numeric_limits<int64_t>::min(),
                                int64_t{-8974392461363618006},
                                int64_t{-8874367046689588135},
                                int64_t{-8269197512118230839},
                                int64_t{-8146091527100606733},
                                int64_t{-7550917981466150848},
                                int64_t{-7216590251577894337},
                                int64_t{-6464086891160048440},
                                int64_t{-6365616494908257190},
                                int64_t{-6305630541365849726},
                                int64_t{-5982222642272245453},
                                int64_t{-5510103099058504169},
                                int64_t{-5496838675802432701},
                                int64_t{-4047626578868642657},
                                int64_t{-4033755046900164544},
                                int64_t{-3554299241457877041},
                                int64_t{-2482258764588614470},
                                int64_t{-1688515425526875335},
                                int64_t{-924784137176548532},
                                int64_t{-725316567157391307},
                                int64_t{-439022654781092241},
                                int64_t{-105545757668917080},
                                int64_t{-2088319373},
                                int64_t{-2073699916},
                                int64_t{-1844949911},
                                int64_t{-1831090548},
                                int64_t{-1756711933},
                                int64_t{-1559409497},
                                int64_t{-1281179700},
                                int64_t{-1211513985},
                                int64_t{-1182371520},
                                int64_t{-785934753},
                                int64_t{-767480697},
                                int64_t{-705745662},
                                int64_t{-514362436},
                                int64_t{-459916580},
                                int64_t{-312328082},
                                int64_t{-302949707},
                                int64_t{-285499304},
                                int64_t{-125701262},
                                int64_t{-95139843},
                                int64_t{-32768},
                                int64_t{-27542},
                                int64_t{-23600},
                                int64_t{-18582},
                                int64_t{-17770},
                                int64_t{-9086},
                                int64_t{-9010},
                                int64_t{-8244},
                                int64_t{-2890},
                                int64_t{-103},
                                int64_t{-34},
                                int64_t{-27},
                                int64_t{-25},
                                int64_t{-9},
                                int64_t{-7},
                                int64_t{0},
                                int64_t{2},
                                int64_t{38},
                                int64_t{58},
                                int64_t{65},
                                int64_t{93},
                                int64_t{111},
                                int64_t{1003},
                                int64_t{1267},
                                int64_t{12797},
                                int64_t{23122},
                                int64_t{28200},
                                int64_t{30888},
                                int64_t{42648848},
                                int64_t{116836693},
                                int64_t{263003643},
                                int64_t{571039860},
                                int64_t{1079398689},
                                int64_t{1145196402},
                                int64_t{1184846321},
                                int64_t{1758281648},
                                int64_t{1859991374},
                                int64_t{1960251588},
                                int64_t{2042443199},
                                int64_t{296220586027987448},
                                int64_t{1015494173071134726},
                                int64_t{1151237951914455318},
                                int64_t{1331941174616854174},
                                int64_t{2022020418667972654},
                                int64_t{2450251424374977035},
                                int64_t{3668393562685561486},
                                int64_t{4858229301215502171},
                                int64_t{4919426235170669383},
                                int64_t{5034286595330341762},
                                int64_t{5055797915536941182},
                                int64_t{6072389716149252074},
                                int64_t{6185309910199801210},
                                int64_t{6297328311011094138},
                                int64_t{6932372858072165827},
                                int64_t{8483640924987737210},
                                int64_t{8663764179455849203},
                                int64_t{8877197042645298254},
                                int64_t{8901543506779157333},
                                std::numeric_limits<int64_t>::max()};

const uint32_t kUint32Values[] = {
    0x00000000, 0x00000001, 0xFFFFFFFF, 0x1B09788B, 0x04C5FCE8, 0xCC0DE5BF,
    0x273A798E, 0x187937A3, 0xECE3AF83, 0x5495A16B, 0x0B668ECC, 0x11223344,
    0x0000009E, 0x00000043, 0x0000AF73, 0x0000116B, 0x00658ECC, 0x002B3B4C,
    0x88776655, 0x70000000, 0x07200000, 0x7FFFFFFF, 0x56123761, 0x7FFFFF00,
    0x761C4761, 0x80000000, 0x88888888, 0xA0000000, 0xDDDDDDDD, 0xE0000000,
    0xEEEEEEEE, 0xFFFFFFFD, 0xF0000000, 0x007FFFFF, 0x003FFFFF, 0x001FFFFF,
    0x000FFFFF, 0x0007FFFF, 0x0003FFFF, 0x0001FFFF, 0x0000FFFF, 0x00007FFF,
    0x00003FFF, 0x00001FFF, 0x00000FFF, 0x000007FF, 0x000003FF, 0x000001FF};

const uint64_t kUint64Values[] = {
    0x0000000000000000, 0x0000000000000001, 0xFFFFFFFFFFFFFFFF,
    0x1B09788B1B09788B, 0x0000000004C5FCE8, 0xCC0DE5BFCC0DE5BF,
    0x273A798E273A798E, 0x187937A3187937A3, 0xECE3AF83ECE3AF83,
    0x5495A16B5495A16B, 0x000000000B668ECC, 0x1122334455667788,
    0x000000000000009E, 0x000000000000AF73, 0x000000000000116B,
    0x0000000000658ECC, 0x00000000002B3B4C, 0x8877665588776655,
    0x0720000000000000, 0x7FFFFFFFFFFFFFFF, 0x5612376156123761,
    0x7FFFFFFFFFFF0000, 0x761C4761761C4761, 0x8000000000000000,
    0xA000000000000000, 0xDDDDDDDDDDDDDDDD, 0xEEEEEEEEEEEEEEEE,
    0xFFFFFFFFFFFFFFFD, 0xF000000000000000, 0x007FFFFFFFFFFFFF,
    0x001FFFFFFFFFFFFF, 0x000FFFFFFFFFFFFF, 0x00007FFFFFFFFFFF,
    0x00001FFFFFFFFFFF, 0x00000FFFFFFFFFFF, 0x000007FFFFFFFFFF,
    0x000001FFFFFFFFFF, 0x00000000007FFFFF, 0x00000000001FFFFF,
    0x00000000000FFFFF, 0x00000000000007FF, 0x00000000000001FF};

struct ComparisonBinaryOperator {
  const Operator* (MachineOperatorBuilder::*constructor)();
  const char* constructor_name;
};


std::ostream& operator<<(std::ostream& os,
                         ComparisonBinaryOperator const& cbop) {
  return os << cbop.constructor_name;
}


const ComparisonBinaryOperator kComparisonBinaryOperators[] = {
#define OPCODE(Opcode)                         \
  { &MachineOperatorBuilder::Opcode, #Opcode } \
  ,
    MACHINE_COMPARE_BINOP_LIST(OPCODE)
#undef OPCODE
};

// Avoid undefined behavior on signed integer overflow.
int32_t Shl(int32_t x, int32_t y) { return static_cast<uint32_t>(x) << y; }
int64_t Shl(int64_t x, int64_t y) { return static_cast<uint64_t>(x) << y; }

}  // namespace


// -----------------------------------------------------------------------------
// ChangeFloat64ToFloat32


TEST_F(MachineOperatorReducerTest, ChangeFloat64ToFloat32WithConstant) {
  TRACED_FOREACH(float, x, kFloat32Values) {
    Reduction reduction = Reduce(graph()->NewNode(
        machine()->ChangeFloat32ToFloat64(), Float32Constant(x)));
    ASSERT_TRUE(reduction.Changed());
    EXPECT_THAT(reduction.replacement(), IsFloat64Constant(BitEq<double>(x)));
  }
}


// -----------------------------------------------------------------------------
// ChangeFloat64ToInt32


TEST_F(MachineOperatorReducerTest,
       ChangeFloat64ToInt32WithChangeInt32ToFloat64) {
  Node* value = Parameter(0);
  Reduction reduction = Reduce(graph()->NewNode(
      machine()->ChangeFloat64ToInt32(),
      graph()->NewNode(machine()->ChangeInt32ToFloat64(), value)));
  ASSERT_TRUE(reduction.Changed());
  EXPECT_EQ(value, reduction.replacement());
}

TEST_F(MachineOperatorReducerTest, ChangeFloat64ToInt32WithConstant) {
  TRACED_FOREACH(int32_t, x, kInt32Values) {
    Reduction reduction = Reduce(graph()->NewNode(
        machine()->ChangeFloat64ToInt32(), Float64Constant(FastI2D(x))));
    ASSERT_TRUE(reduction.Changed());
    EXPECT_THAT(reduction.replacement(), IsInt32Constant(x));
  }
}

// -----------------------------------------------------------------------------
// ChangeFloat64ToInt64

TEST_F(MachineOperatorReducerTest,
       ChangeFloat64ToInt64WithChangeInt64ToFloat64) {
  Node* value = Parameter(0);
  Reduction reduction = Reduce(graph()->NewNode(
      machine()->ChangeFloat64ToInt64(),
      graph()->NewNode(machine()->ChangeInt64ToFloat64(), value)));
  ASSERT_TRUE(reduction.Changed());
  EXPECT_EQ(value, reduction.replacement());
}

TEST_F(MachineOperatorReducerTest, ChangeFloat64ToInt64WithConstant) {
  TRACED_FOREACH(int32_t, x, kInt32Values) {
    Reduction reduction = Reduce(graph()->NewNode(
        machine()->ChangeFloat64ToInt64(), Float64Constant(FastI2D(x))));
    ASSERT_TRUE(reduction.Changed());
    EXPECT_THAT(reduction.replacement(), IsInt64Constant(x));
  }
}

// -----------------------------------------------------------------------------
// ChangeFloat64ToUint32


TEST_F(MachineOperatorReducerTest,
       ChangeFloat64ToUint32WithChangeUint32ToFloat64) {
  Node* value = Parameter(0);
  Reduction reduction = Reduce(graph()->NewNode(
      machine()->ChangeFloat64ToUint32(),
      graph()->NewNode(machine()->ChangeUint32ToFloat64(), value)));
  ASSERT_TRUE(reduction.Changed());
  EXPECT_EQ(value, reduction.replacement());
}


TEST_F(MachineOperatorReducerTest, ChangeFloat64ToUint32WithConstant) {
  TRACED_FOREACH(uint32_t, x, kUint32Values) {
    Reduction reduction = Reduce(graph()->NewNode(
        machine()->ChangeFloat64ToUint32(), Float64Constant(FastUI2D(x))));
    ASSERT_TRUE(reduction.Changed());
    EXPECT_THAT(reduction.replacement(),
                IsInt32Constant(base::bit_cast<int32_t>(x)));
  }
}


// -----------------------------------------------------------------------------
// ChangeInt32ToFloat64


TEST_F(MachineOperatorReducerTest, ChangeInt32ToFloat64WithConstant) {
  TRACED_FOREACH(int32_t, x, kInt32Values) {
    Reduction reduction = Reduce(
        graph()->NewNode(machine()->ChangeInt32ToFloat64(), Int32Constant(x)));
    ASSERT_TRUE(reduction.Changed());
    EXPECT_THAT(reduction.replacement(), IsFloat64Constant(BitEq(FastI2D(x))));
  }
}


// -----------------------------------------------------------------------------
// ChangeInt32ToInt64


TEST_F(MachineOperatorReducerTest, ChangeInt32ToInt64WithConstant) {
  TRACED_FOREACH(int32_t, x, kInt32Values) {
    Reduction reduction = Reduce(
        graph()->NewNode(machine()->ChangeInt32ToInt64(), Int32Constant(x)));
    ASSERT_TRUE(reduction.Changed());
    EXPECT_THAT(reduction.replacement(), IsInt64Constant(x));
  }
}

// -----------------------------------------------------------------------------
// ChangeInt64ToFloat64

TEST_F(MachineOperatorReducerTest,
       ChangeInt64ToFloat64WithChangeFloat64ToInt64) {
  Node* value = Parameter(0);
  Reduction reduction = Reduce(graph()->NewNode(
      machine()->ChangeInt64ToFloat64(),
      graph()->NewNode(machine()->ChangeFloat64ToInt64(), value)));
  ASSERT_TRUE(reduction.Changed());
  EXPECT_EQ(value, reduction.replacement());
}

TEST_F(MachineOperatorReducerTest, ChangeInt64ToFloat64WithConstant) {
  TRACED_FOREACH(int32_t, x, kInt32Values) {
    Reduction reduction = Reduce(
        graph()->NewNode(machine()->ChangeInt64ToFloat64(), Int64Constant(x)));
    ASSERT_TRUE(reduction.Changed());
    EXPECT_THAT(reduction.replacement(), IsFloat64Constant(BitEq(FastI2D(x))));
  }
}

// -----------------------------------------------------------------------------
// ChangeUint32ToFloat64


TEST_F(MachineOperatorReducerTest, ChangeUint32ToFloat64WithConstant) {
  TRACED_FOREACH(uint32_t, x, kUint32Values) {
    Reduction reduction =
        Reduce(graph()->NewNode(machine()->ChangeUint32ToFloat64(),
                                Int32Constant(base::bit_cast<int32_t>(x))));
    ASSERT_TRUE(reduction.Changed());
    EXPECT_THAT(reduction.replacement(), IsFloat64Constant(BitEq(FastUI2D(x))));
  }
}


// -----------------------------------------------------------------------------
// ChangeUint32ToUint64


TEST_F(MachineOperatorReducerTest, ChangeUint32ToUint64WithConstant) {
  TRACED_FOREACH(uint32_t, x, kUint32Values) {
    Reduction reduction =
        Reduce(graph()->NewNode(machine()->ChangeUint32ToUint64(),
                                Int32Constant(base::bit_cast<int32_t>(x))));
    ASSERT_TRUE(reduction.Changed());
    EXPECT_THAT(
        reduction.replacement(),
        IsInt64Constant(base::bit_cast<int64_t>(static_cast<uint64_t>(x))));
  }
}


// -----------------------------------------------------------------------------
// TruncateFloat64ToFloat32


TEST_F(MachineOperatorReducerTest,
       TruncateFloat64ToFloat32WithChangeFloat32ToFloat64) {
  Node* value = Parameter(0);
  Reduction reduction = Reduce(graph()->NewNode(
      machine()->TruncateFloat64ToFloat32(),
      graph()->NewNode(machine()->ChangeFloat32ToFloat64(), value)));
  ASSERT_TRUE(reduction.Changed());
  EXPECT_EQ(value, reduction.replacement());
}


TEST_F(MachineOperatorReducerTest, TruncateFloat64ToFloat32WithConstant) {
  TRACED_FOREACH(double, x, kFloat64Values) {
    Reduction reduction = Reduce(graph()->NewNode(
        machine()->TruncateFloat64ToFloat32(), Float64Constant(x)));
    ASSERT_TRUE(reduction.Changed());
    EXPECT_THAT(reduction.replacement(),
                IsFloat32Constant(BitEq(DoubleToFloat32(x))));
  }
}


// -----------------------------------------------------------------------------
// TruncateFloat64ToWord32

TEST_F(MachineOperatorReducerTest,
       TruncateFloat64ToWord32WithChangeInt32ToFloat64) {
  Node* value = Parameter(0);
  Reduction reduction = Reduce(graph()->NewNode(
      machine()->TruncateFloat64ToWord32(),
      graph()->NewNode(machine()->ChangeInt32ToFloat64(), value)));
  ASSERT_TRUE(reduction.Changed());
  EXPECT_EQ(value, reduction.replacement());
}

TEST_F(MachineOperatorReducerTest, TruncateFloat64ToWord32WithConstant) {
  TRACED_FOREACH(double, x, kFloat64Values) {
    Reduction reduction = Reduce(graph()->NewNode(
        machine()->TruncateFloat64ToWord32(), Float64Constant(x)));
    ASSERT_TRUE(reduction.Changed());
    EXPECT_THAT(reduction.replacement(), IsInt32Constant(DoubleToInt32(x)));
  }
}


// -----------------------------------------------------------------------------
// TruncateInt64ToInt32


TEST_F(MachineOperatorReducerTest, TruncateInt64ToInt32WithChangeInt32ToInt64) {
  Node* value = Parameter(0);
  Reduction reduction = Reduce(graph()->NewNode(
      machine()->TruncateInt64ToInt32(),
      graph()->NewNode(machine()->ChangeInt32ToInt64(), value)));
  ASSERT_TRUE(reduction.Changed());
  EXPECT_EQ(value, reduction.replacement());
}


TEST_F(MachineOperatorReducerTest, TruncateInt64ToInt32WithConstant) {
  TRACED_FOREACH(int64_t, x, kInt64Values) {
    Reduction reduction = Reduce(
        graph()->NewNode(machine()->TruncateInt64ToInt32(), Int64Constant(x)));
    ASSERT_TRUE(reduction.Changed());
    EXPECT_THAT(reduction.replacement(),
                IsInt32Constant(base::bit_cast<int32_t>(
                    static_cast<uint32_t>(base::bit_cast<uint64_t>(x)))));
  }
}

TEST_F(MachineOperatorReducerTest, TruncateInt64ToInt32AfterLoadAndBitcast) {
  Node* value = Parameter(0);
  Node* inputs[4] = {value, value, graph()->start(), graph()->start()};
  LoadRepresentation load_reps[3] = {LoadRepresentation::AnyTagged(),
                                     LoadRepresentation::TaggedPointer(),
                                     LoadRepresentation::TaggedSigned()};
  for (LoadRepresentation load_rep : load_reps) {
    if (ElementSizeLog2Of(load_rep.representation()) != 2) continue;
    {
      Node* load = graph()->NewNode(machine()->Load(load_rep), 4, inputs);
      Reduction reduction = Reduce(graph()->NewNode(
          machine()->TruncateInt64ToInt32(),
          graph()->NewNode(machine()->BitcastTaggedToWordForTagAndSmiBits(),
                           load)));
      ASSERT_TRUE(reduction.Changed());
      EXPECT_EQ(load, reduction.replacement());
      EXPECT_EQ(LoadRepresentationOf(load->op()), LoadRepresentation::Int32());
    }
    {
      Node* load =
          graph()->NewNode(machine()->LoadImmutable(load_rep), 2, inputs);
      Reduction reduction = Reduce(graph()->NewNode(
          machine()->TruncateInt64ToInt32(),
          graph()->NewNode(machine()->BitcastTaggedToWordForTagAndSmiBits(),
                           load)));
      ASSERT_TRUE(reduction.Changed());
      EXPECT_EQ(load, reduction.replacement());
      EXPECT_EQ(LoadRepresentationOf(load->op()), LoadRepresentation::Int32());
    }
  }
}

// -----------------------------------------------------------------------------
// RoundFloat64ToInt32

TEST_F(MachineOperatorReducerTest,
       RoundFloat64ToInt32WithChangeInt32ToFloat64) {
  Node* value = Parameter(0);
  Reduction reduction = Reduce(graph()->NewNode(
      machine()->RoundFloat64ToInt32(),
      graph()->NewNode(machine()->ChangeInt32ToFloat64(), value)));
  ASSERT_TRUE(reduction.Changed());
  EXPECT_EQ(value, reduction.replacement());
}

TEST_F(MachineOperatorReducerTest, RoundFloat64ToInt32WithConstant) {
  TRACED_FOREACH(double, x, kFloat64Values) {
    Reduction reduction = Reduce(
        graph()->NewNode(machine()->RoundFloat64ToInt32(), Float64Constant(x)));
    ASSERT_TRUE(reduction.Changed());
    EXPECT_THAT(reduction.replacement(), IsInt32Constant(DoubleToInt32(x)));
  }
}

// -----------------------------------------------------------------------------
// Word32And

TEST_F(MachineOperatorReducerTest, Word32AndWithWord32ShlWithConstant) {
  Node* const p0 = Parameter(0);

  TRACED_FORRANGE(int32_t, l, 1, 31) {
    TRACED_FORRANGE(int32_t, k, 1, l) {
      // (x << L) & (-1 << K) => x << L
      Reduction const r1 = Reduce(graph()->NewNode(
          machine()->Word32And(),
          graph()->NewNode(machine()->Word32Shl(), p0, Int32Constant(l)),
          Int32Constant(Shl(-1, k))));
      ASSERT_TRUE(r1.Changed());
      EXPECT_THAT(r1.replacement(), IsWord32Shl(p0, IsInt32Constant(l)));

      // (-1 << K) & (x << L) => x << L
      Reduction const r2 = Reduce(graph()->NewNode(
          machine()->Word32And(), Int32Constant(Shl(-1, k)),
          graph()->NewNode(machine()->Word32Shl(), p0, Int32Constant(l))));
      ASSERT_TRUE(r2.Changed());
      EXPECT_THAT(r2.replacement(), IsWord32Shl(p0, IsInt32Constant(l)));
    }
  }
}


TEST_F(MachineOperatorReducerTest, Word32AndWithWord32AndWithConstant) {
  TRACED_FOREACH(int32_t, k, kInt32Values) {
    Node* const p0 = Parameter(0);
    TRACED_FOREACH(int32_t, l, kInt32Values) {
      if (k == 0 || k == -1 || l == 0 || l == -1) continue;

      // (x & K) & L => x & (K & L)
      Reduction const r1 = Reduce(graph()->NewNode(
          machine()->Word32And(),
          graph()->NewNode(machine()->Word32And(), p0, Int32Constant(k)),
          Int32Constant(l)));
      ASSERT_TRUE(r1.Changed());
      EXPECT_THAT(r1.replacement(),
                  (k & l) ? IsWord32And(p0, IsInt32Constant(k & l))
                          : IsInt32Constant(0));

      // (K & x) & L => x & (K & L)
      Reduction const r2 = Reduce(graph()->NewNode(
          machine()->Word32And(),
          graph()->NewNode(machine()->Word32And(), Int32Constant(k), p0),
          Int32Constant(l)));
      ASSERT_TRUE(r2.Changed());
      EXPECT_THAT(r2.replacement(),
                  (k & l) ? IsWord32And(p0, IsInt32Constant(k & l))
                          : IsInt32Constant(0));
    }
    // This test uses too much memory if we don't periodically reset.
    Reset();
  }
}


TEST_F(MachineOperatorReducerTest, Word32AndWithInt32AddAndConstant) {
  Node* const p0 = Parameter(0);
  Node* const p1 = Parameter(1);

  TRACED_FORRANGE(int32_t, l, 1, 31) {
    TRACED_FOREACH(int32_t, k, kInt32Values) {
      if (Shl(k, l) == 0) continue;
      // (x + (K << L)) & (-1 << L) => (x & (-1 << L)) + (K << L)
      Reduction const r = Reduce(graph()->NewNode(
          machine()->Word32And(),
          graph()->NewNode(machine()->Int32Add(), p0, Int32Constant(Shl(k, l))),
          Int32Constant(Shl(-1, l))));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(),
                  IsInt32Add(IsWord32And(p0, IsInt32Constant(Shl(-1, l))),
                             IsInt32Constant(Shl(k, l))));
    }

    Node* s1 = graph()->NewNode(machine()->Word32Shl(), p1, Int32Constant(l));

    // (y << L + x) & (-1 << L) => (x & (-1 << L)) + y << L
    Reduction const r1 = Reduce(graph()->NewNode(
        machine()->Word32And(), graph()->NewNode(machine()->Int32Add(), s1, p0),
        Int32Constant(Shl(-1, l)))
```