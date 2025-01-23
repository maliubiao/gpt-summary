Response:
Let's break down the thought process for analyzing the provided C++ code.

**1. Understanding the Request:**

The request asks for several things about the C++ code:

* **Functionality:** What does this code *do*?
* **Torque Check:** Is it Torque?
* **JavaScript Relation:**  Does it interact with JavaScript, and how?
* **Logic Inference:**  Can we infer behavior based on inputs and outputs?
* **Common Errors:** Does it relate to typical programming mistakes?

**2. Initial Code Scan and Keyword Spotting:**

My first step is to quickly scan the code for recognizable keywords and patterns. I see:

* `#include`: Standard C++ includes. `src/compiler/...` is a strong indicator of compiler-related code within V8.
* `namespace v8`, `namespace internal`, `namespace compiler`: Clearly part of the V8 compiler.
* `class TyperTest : public TypedGraphTest`: This is a unit test class inheriting from a testing framework. The name "TyperTest" is highly suggestive.
* `OperationTyper`, `Types`, `JSOperatorBuilder`, `SimplifiedOperatorBuilder`: These names point towards the code being about type analysis and manipulation during compilation. "JS" suggests interaction with JavaScript.
* `TypeUnaryOp`, `TypeBinaryOp`: Functions that seem to be testing the types resulting from unary and binary operations.
* `TestBinaryArithOp`, `TestBinaryCompareOp`, `TestBinaryBitOp`:  Functions that test specific types of binary operations.
* `TEST_F`:  A common macro in Google Test (gtest) for defining test functions.
* `Monotonicity`: This keyword appears repeatedly in test names, suggesting a focus on testing whether type analysis behaves consistently with subtyping relationships.
*  Arithmetic operators (`+`, `-`, `*`, `/`, `%`), bitwise operators (`|`, `&`, `^`, `<<`, `>>`), comparison operators (`<`, `<=`, `>`, `>=`). This reinforces the idea of testing the typing of these operations.

**3. Formulating Initial Hypotheses:**

Based on the initial scan, I can form some preliminary hypotheses:

* **Core Functionality:** This code is a set of unit tests for the V8 JavaScript engine's *typer*. The typer is responsible for inferring and assigning types to expressions during the compilation process.
* **No Torque:** The file ends in `.cc`, not `.tq`.
* **JavaScript Connection:**  The tests directly relate to how JavaScript operators are typed during compilation.
* **Logic Inference:** The `TestBinaryArithOp`, `TestBinaryCompareOp`, etc., functions likely take operator definitions and functions representing the actual operation to verify that the typer produces sound type information.
* **Common Errors:**  While not directly demonstrating user errors, this code *tests* the V8 compiler's ability to correctly handle different types and operations, which *prevents* errors in the compiled JavaScript code. Incorrect typing in the compiler could lead to runtime errors or unexpected behavior.

**4. Deeper Dive and Code Analysis:**

Now I start looking at the individual parts of the code more closely:

* **`TyperTest` class:**  I see members like `current_broker_`, `operation_typer_`, `types_`, `javascript_`, `simplified_`. These likely represent the environment and components needed for type analysis within the compiler. The `integers` and `int32s` vectors suggest the tests involve numeric types.
* **`TypeUnaryOp` and `TypeBinaryOp`:** These functions construct nodes in the compiler's intermediate representation (IR) and use the typer to determine the resulting type. The input parameters and how they are set up (`NodeProperties::SetType`) are key to understanding how the tests work.
* **`RandomRange`, `NewRange`, `RandomInt`, `RandomSubtype`:** These helper functions indicate that the tests use randomized inputs to achieve broader coverage.
* **The `TestBinary...Op` templates:**  These templates are crucial. They show the pattern:
    1. Generate input types (often ranges).
    2. Use `TypeBinaryOp` to get the type inferred by the typer.
    3. Generate concrete values within the input type ranges.
    4. Perform the actual operation using a C++ function (`std::plus`, `std::minus`, etc.).
    5. Check if the *actual* result's type is a subtype of the *inferred* type. This confirms the soundness of the typer.
* **`Monotonicity` tests:** These tests check a fundamental property of type systems. If type `A` is a subtype of type `B`, then applying an operation to `A` should result in a type that's a subtype of the result of applying the operation to `B`. This ensures consistency in type inference.

**5. Refining Hypotheses and Adding Detail:**

Based on the deeper analysis, I can refine my initial hypotheses and add more specific details:

* **More Specific Functionality:**  The code tests the soundness and monotonicity of the V8 compiler's type inference for JavaScript operators. It focuses on how the `OperationTyper` component deduces the output types of unary and binary operations based on the input types.
* **JavaScript Examples:**  I can now construct concrete JavaScript examples that correspond to the tested operations (e.g., `+`, `-`, `<`, `&`).
* **Logic Inference Examples:** I can create specific examples of input types (like ranges) and trace how the tests would evaluate them, predicting the output types.
* **Common Errors (Compiler Perspective):** I realize that this code isn't about user-level JavaScript errors, but rather potential errors *within the V8 compiler's type system itself*. If the typer were incorrect, it could lead to the compiler making wrong optimizations or generating incorrect code.

**6. Structuring the Output:**

Finally, I organize the information into the requested format:

* **Functionality:**  A clear and concise description of the code's purpose.
* **Torque:** A simple "No".
* **JavaScript Relation:** Provide illustrative JavaScript code examples.
* **Logic Inference:** Create a table or bullet points with example inputs and expected outputs based on the code's logic.
* **Common Errors:** Explain that the code relates to *compiler* errors, not typical user errors, and provide examples of what could go wrong in the compiler if the typer wasn't working correctly.

This iterative process of scanning, hypothesizing, analyzing, and refining allows for a comprehensive understanding of the code's purpose and its implications within the V8 JavaScript engine.
这个文件 `v8/test/unittests/compiler/typer-unittest.cc` 是 V8 JavaScript 引擎的一部分，它是一个 **单元测试文件**，专门用于测试 V8 编译器中 **类型推断器 (Typer)** 的功能。

**功能概要:**

该文件的主要目的是验证 V8 编译器中的 `Typer` 组件是否能够正确地推断出各种 JavaScript 表达式的类型。它通过以下方式进行测试：

1. **模拟编译器中的节点:** 它创建表示 JavaScript 操作的编译器内部节点（例如，加法、减法、比较等）。
2. **设置输入类型:**  为这些节点设置不同的输入类型，包括基本类型（数字、字符串、布尔值等）、范围类型、联合类型等。
3. **调用类型推断器:** 使用 `Typer` 组件对这些节点进行类型推断。
4. **断言输出类型:**  验证 `Typer` 推断出的输出类型是否与预期相符。

**关于文件扩展名 .tq:**

根据您的描述，`v8/test/unittests/compiler/typer-unittest.cc`  **不是**以 `.tq` 结尾。`.tq` 文件是 V8 中用于 Torque 语言编写的代码，Torque 是一种用于定义 V8 内部运行时函数的 DSL (Domain Specific Language)。  由于该文件以 `.cc` 结尾，它是一个标准的 C++ 源文件。

**与 JavaScript 的关系:**

`typer-unittest.cc` 文件直接测试 V8 编译器处理 JavaScript 代码时的类型推断逻辑。  类型推断器是编译器优化的关键部分。 通过准确地推断出变量和表达式的类型，编译器可以进行更有效的代码优化，从而提高 JavaScript 代码的执行速度。

**JavaScript 示例:**

以下是一些与 `typer-unittest.cc` 中测试的逻辑相关的 JavaScript 示例：

```javascript
function add(a, b) {
  return a + b;
}

function compare(x, y) {
  return x < y;
}

function bitwiseAnd(p, q) {
  return p & q;
}
```

V8 的类型推断器会分析像 `add`, `compare`, `bitwiseAnd` 这样的 JavaScript 函数，并尝试确定 `a + b`，`x < y`，`p & q`  的结果类型。 `typer-unittest.cc` 中的测试会模拟这些操作，并验证类型推断器在给定不同输入类型的情况下是否能得到正确的输出类型。

**代码逻辑推理 (假设输入与输出):**

让我们看一个 `TypeBinaryOp` 函数的例子，以及一个可能的测试场景：

**假设:**

* **操作符:** JavaScript 的加法运算符 `+` (在代码中对应 `javascript_.Add(...)`)
* **输入类型 1 (lhs):**  一个表示数字范围 5 到 10 的类型 (假设内部表示为 `Type::Range(5, 10, zone())`)
* **输入类型 2 (rhs):**  一个表示数字范围 2 到 3 的类型 (假设内部表示为 `Type::Range(2, 3, zone())`)

**代码执行过程 (`TypeBinaryOp`):**

1. 创建两个参数节点 `p0` 和 `p1`。
2. 使用 `NodeProperties::SetType` 将输入类型 1 设置给 `p0`，将输入类型 2 设置给 `p1`。
3. 创建一个表示加法操作的节点 `n`，并将 `p0` 和 `p1` 作为输入。
4. `NodeProperties::GetType(n)` 调用类型推断器来计算节点 `n` 的输出类型。

**预期输出类型:**

类型推断器应该能够推断出加法运算的结果类型也是一个数字范围。由于最小输入是 `5 + 2 = 7`，最大输入是 `10 + 3 = 13`，所以预期的输出类型应该是一个表示数字范围 7 到 13 的类型 (假设内部表示为 `Type::Range(7, 13, zone())`)。

**实际测试 (`TestBinaryArithOp`):**

`TestBinaryArithOp` 函数会执行类似的操作，并且会进一步验证：对于该类型范围内的具体数值，实际的加法结果的类型是否也包含在推断出的类型范围内。

**用户常见的编程错误 (与类型推断相关):**

虽然这个文件是测试编译器内部机制的，但类型推断的目的是为了更好地处理 JavaScript 代码。以下是一些与类型相关的常见 JavaScript 编程错误，这些错误可能会被 V8 的类型推断器捕获或优化：

1. **类型不匹配的运算:**

    ```javascript
    let x = 10;
    let y = "hello";
    let result = x + y; // 字符串拼接，可能不是预期行为
    ```

    V8 的类型推断器会识别到 `+` 运算符应用于数字和字符串，并推断出结果是字符串类型。虽然这是合法的 JavaScript，但可能不是用户的预期。

2. **对可能为 `null` 或 `undefined` 的值进行操作:**

    ```javascript
    function process(obj) {
      return obj.value.toUpperCase(); // 如果 obj 为 null 或 undefined，会报错
    }
    ```

    类型推断器会尝试分析 `obj` 的类型，如果它可能是 `null` 或 `undefined`，编译器可能会生成额外的检查代码或者进行特定的优化。

3. **假设变量总是某种类型:**

    ```javascript
    function calculate(input) {
      return input * 2; // 假设 input 总是数字
    }

    calculate("abc"); // 传入非数字，结果为 NaN
    ```

    类型推断器可能会尝试根据上下文推断 `input` 的类型，但如果类型不确定，可能会影响编译器的优化。

**`typer-unittest.cc` 如何帮助避免这些错误:**

虽然这个文件不直接阻止用户编写上述错误，但它确保了 V8 编译器能够正确地理解和处理不同类型的 JavaScript 代码。 强大的类型推断能力允许编译器：

*   进行更积极的优化，生成更高效的机器码。
*   在某些情况下，在编译时发现潜在的类型错误，从而提前避免运行时错误。
*   为开发者提供更好的性能。

总而言之，`v8/test/unittests/compiler/typer-unittest.cc` 是一个关键的测试文件，用于确保 V8 编译器中的类型推断器能够准确地理解 JavaScript 代码中值的类型，这对于代码优化和性能至关重要。

### 提示词
```
这是目录为v8/test/unittests/compiler/typer-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/typer-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <functional>

#include "src/base/overflowing-math.h"
#include "src/compiler/js-heap-broker.h"
#include "src/compiler/js-operator.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/operator-properties.h"
#include "src/compiler/simplified-operator.h"
#include "src/objects/objects-inl.h"
#include "test/common/types-fuzz.h"
#include "test/unittests/compiler/graph-unittest.h"

namespace v8 {
namespace internal {
namespace compiler {

// TODO(titzer): generate a large set of deterministic inputs for these tests.
class TyperTest : public TypedGraphTest {
 public:
  TyperTest()
      : TypedGraphTest(3),
        current_broker_(broker()),
        operation_typer_(broker(), zone()),
        types_(zone(), isolate(), random_number_generator()),
        javascript_(zone()),
        simplified_(zone()) {
    context_node_ = graph()->NewNode(common()->Parameter(2), graph()->start());
    rng_ = random_number_generator();

    integers.push_back(0);
    integers.push_back(0);
    integers.push_back(-1);
    integers.push_back(+1);
    integers.push_back(-V8_INFINITY);
    integers.push_back(+V8_INFINITY);
    for (int i = 0; i < 5; ++i) {
      double x = rng_->NextInt();
      integers.push_back(x);
      x *= rng_->NextInt();
      if (!IsMinusZero(x)) integers.push_back(x);
    }

    int32s.push_back(0);
    int32s.push_back(0);
    int32s.push_back(-1);
    int32s.push_back(+1);
    int32s.push_back(kMinInt);
    int32s.push_back(kMaxInt);
    for (int i = 0; i < 10; ++i) {
      int32s.push_back(rng_->NextInt());
    }
  }

  const int kRepetitions = 50;

  CurrentHeapBrokerScope current_broker_;
  OperationTyper operation_typer_;
  Types types_;
  JSOperatorBuilder javascript_;
  SimplifiedOperatorBuilder simplified_;
  Node* context_node_;
  v8::base::RandomNumberGenerator* rng_;
  std::vector<double> integers;
  std::vector<double> int32s;

  Type TypeUnaryOp(const Operator* op, Type type0) {
    Node* p0 = Parameter(0);
    NodeProperties::SetType(p0, type0);
    std::vector<Node*> inputs;
    inputs.push_back(p0);
    if (OperatorProperties::HasContextInput(op)) {
      inputs.push_back(context_node_);
    }
    for (int i = 0; i < OperatorProperties::GetFrameStateInputCount(op); i++) {
      inputs.push_back(EmptyFrameState());
    }
    for (int i = 0; i < op->EffectInputCount(); i++) {
      inputs.push_back(graph()->start());
    }
    for (int i = 0; i < op->ControlInputCount(); i++) {
      inputs.push_back(graph()->start());
    }
    Node* n = graph()->NewNode(op, static_cast<int>(inputs.size()),
                               &(inputs.front()));
    return NodeProperties::GetType(n);
  }

  Node* UndefinedConstant() {
    Handle<HeapObject> value = isolate()->factory()->undefined_value();
    return graph()->NewNode(common()->HeapConstant(value));
  }

  Type TypeBinaryOp(const Operator* op, Type lhs, Type rhs) {
    Node* p0 = Parameter(0);
    Node* p1 = Parameter(1);
    NodeProperties::SetType(p0, lhs);
    NodeProperties::SetType(p1, rhs);
    std::vector<Node*> inputs;
    inputs.push_back(p0);
    inputs.push_back(p1);
    if (JSOperator::IsBinaryWithFeedback(op->opcode())) {
      inputs.push_back(UndefinedConstant());  // Feedback vector.
    }
    if (OperatorProperties::HasContextInput(op)) {
      inputs.push_back(context_node_);
    }
    for (int i = 0; i < OperatorProperties::GetFrameStateInputCount(op); i++) {
      inputs.push_back(EmptyFrameState());
    }
    for (int i = 0; i < op->EffectInputCount(); i++) {
      inputs.push_back(graph()->start());
    }
    for (int i = 0; i < op->ControlInputCount(); i++) {
      inputs.push_back(graph()->start());
    }
    Node* n = graph()->NewNode(op, static_cast<int>(inputs.size()),
                               &(inputs.front()));
    return NodeProperties::GetType(n);
  }

  Type RandomRange(bool int32 = false) {
    std::vector<double>& numbers = int32 ? int32s : integers;
    double i = numbers[rng_->NextInt(static_cast<int>(numbers.size()))];
    double j = numbers[rng_->NextInt(static_cast<int>(numbers.size()))];
    return NewRange(i, j);
  }

  Type NewRange(double i, double j) {
    if (i > j) std::swap(i, j);
    return Type::Range(i, j, zone());
  }

  double RandomInt(double min, double max) {
    switch (rng_->NextInt(4)) {
      case 0:
        return min;
      case 1:
        return max;
      default:
        break;
    }
    if (min == +V8_INFINITY) return +V8_INFINITY;
    if (max == -V8_INFINITY) return -V8_INFINITY;
    if (min == -V8_INFINITY && max == +V8_INFINITY) {
      return rng_->NextInt() * static_cast<double>(rng_->NextInt());
    }
    double result = nearbyint(min + (max - min) * rng_->NextDouble());
    if (IsMinusZero(result)) return 0;
    if (std::isnan(result)) return rng_->NextInt(2) ? min : max;
    DCHECK(min <= result && result <= max);
    return result;
  }

  double RandomInt(const RangeType* range) {
    return RandomInt(range->Min(), range->Max());
  }

  Type RandomSubtype(Type type) {
    Type subtype;
    do {
      subtype = types_.Fuzz();
    } while (!subtype.Is(type));
    return subtype;
  }

  // Careful, this function runs O(max_width^5) trials.
  template <class BinaryFunction>
  void TestBinaryArithOpCloseToZero(const Operator* op, BinaryFunction opfun,
                                    int max_width) {
    const int min_min = -2 - max_width / 2;
    const int max_min = 2 + max_width / 2;
    for (int width = 0; width < max_width; width++) {
      for (int lmin = min_min; lmin <= max_min; lmin++) {
        for (int rmin = min_min; rmin <= max_min; rmin++) {
          Type r1 = NewRange(lmin, lmin + width);
          Type r2 = NewRange(rmin, rmin + width);
          Type expected_type = TypeBinaryOp(op, r1, r2);

          for (int x1 = lmin; x1 < lmin + width; x1++) {
            for (int x2 = rmin; x2 < rmin + width; x2++) {
              double result_value = opfun(x1, x2);
              Type result_type = Type::Constant(
                  broker(),
                  CanonicalHandle(
                      isolate()->factory()->NewNumber(result_value)),
                  zone());
              EXPECT_TRUE(result_type.Is(expected_type));
            }
          }
        }
      }
    }
  }

  template <class BinaryFunction>
  void TestBinaryArithOp(const Operator* op, BinaryFunction opfun) {
    TestBinaryArithOpCloseToZero(op, opfun, 8);
    for (int i = 0; i < 100; ++i) {
      Type r1 = RandomRange();
      Type r2 = RandomRange();
      Type expected_type = TypeBinaryOp(op, r1, r2);
      for (int j = 0; j < 10; j++) {
        double x1 = RandomInt(r1.AsRange());
        double x2 = RandomInt(r2.AsRange());
        double result_value = opfun(x1, x2);
        Type result_type = Type::Constant(
            broker(),
            CanonicalHandle(isolate()->factory()->NewNumber(result_value)),
            zone());
        EXPECT_TRUE(result_type.Is(expected_type));
      }
    }
    // Test extreme cases.
    double x1 = +1e-308;
    double x2 = -1e-308;
    Type r1 = Type::Constant(
        broker(), CanonicalHandle(isolate()->factory()->NewNumber(x1)), zone());
    Type r2 = Type::Constant(
        broker(), CanonicalHandle(isolate()->factory()->NewNumber(x2)), zone());
    Type expected_type = TypeBinaryOp(op, r1, r2);
    double result_value = opfun(x1, x2);
    Type result_type = Type::Constant(
        broker(),
        CanonicalHandle(isolate()->factory()->NewNumber(result_value)), zone());
    EXPECT_TRUE(result_type.Is(expected_type));
  }

  template <class BinaryFunction>
  void TestBinaryCompareOp(const Operator* op, BinaryFunction opfun) {
    for (int i = 0; i < 100; ++i) {
      Type r1 = RandomRange();
      Type r2 = RandomRange();
      Type expected_type = TypeBinaryOp(op, r1, r2);
      for (int j = 0; j < 10; j++) {
        double x1 = RandomInt(r1.AsRange());
        double x2 = RandomInt(r2.AsRange());
        bool result_value = opfun(x1, x2);
        Type result_type = Type::Constant(
            broker(),
            result_value ? broker()->true_value() : broker()->false_value(),
            zone());
        EXPECT_TRUE(result_type.Is(expected_type));
      }
    }
  }

  template <class BinaryFunction>
  void TestBinaryBitOp(const Operator* op, BinaryFunction opfun) {
    for (int i = 0; i < 100; ++i) {
      Type r1 = RandomRange(true);
      Type r2 = RandomRange(true);
      Type expected_type = TypeBinaryOp(op, r1, r2);
      for (int j = 0; j < 10; j++) {
        int32_t x1 = static_cast<int32_t>(RandomInt(r1.AsRange()));
        int32_t x2 = static_cast<int32_t>(RandomInt(r2.AsRange()));
        double result_value = opfun(x1, x2);
        Type result_type = Type::Constant(
            broker(),
            CanonicalHandle(isolate()->factory()->NewNumber(result_value)),
            zone());
        EXPECT_TRUE(result_type.Is(expected_type));
      }
    }
  }

  using UnaryTyper = std::function<Type(Type)>;
  using BinaryTyper = std::function<Type(Type, Type)>;

  void TestUnaryMonotonicity(UnaryTyper typer, Type upper1 = Type::Any()) {
    Type type1 = Type::Intersect(types_.Fuzz(), upper1, zone());
    DCHECK(type1.Is(upper1));
    Type type = typer(type1);

    Type subtype1 = RandomSubtype(type1);
    Type subtype = typer(subtype1);

    EXPECT_TRUE(subtype.Is(type));
  }

  void TestBinaryMonotonicity(BinaryTyper typer, Type upper1 = Type::Any(),
                              Type upper2 = Type::Any()) {
    Type type1 = Type::Intersect(types_.Fuzz(), upper1, zone());
    DCHECK(type1.Is(upper1));
    Type type2 = Type::Intersect(types_.Fuzz(), upper2, zone());
    DCHECK(type2.Is(upper2));
    Type type = typer(type1, type2);

    Type subtype1 = RandomSubtype(type1);
    Type subtype2 = RandomSubtype(type2);
    Type subtype = typer(subtype1, subtype2);

    EXPECT_TRUE(subtype.Is(type));
  }

  void TestUnaryMonotonicity(const Operator* op, Type upper1 = Type::Any()) {
    UnaryTyper typer = [&](Type type1) { return TypeUnaryOp(op, type1); };
    for (int i = 0; i < kRepetitions; ++i) {
      TestUnaryMonotonicity(typer, upper1);
    }
  }

  void TestBinaryMonotonicity(const Operator* op, Type upper1 = Type::Any(),
                              Type upper2 = Type::Any()) {
    BinaryTyper typer = [&](Type type1, Type type2) {
      return TypeBinaryOp(op, type1, type2);
    };
    for (int i = 0; i < kRepetitions; ++i) {
      TestBinaryMonotonicity(typer, upper1, upper2);
    }
  }
};


namespace {

int32_t shift_left(int32_t x, int32_t y) {
  return static_cast<uint32_t>(x) << (y & 0x1F);
}
int32_t shift_right(int32_t x, int32_t y) { return x >> (y & 0x1F); }
int32_t bit_or(int32_t x, int32_t y) { return x | y; }
int32_t bit_and(int32_t x, int32_t y) { return x & y; }
int32_t bit_xor(int32_t x, int32_t y) { return x ^ y; }
double divide_double_double(double x, double y) { return base::Divide(x, y); }
double modulo_double_double(double x, double y) { return Modulo(x, y); }

FeedbackSource FeedbackSourceWithOneBinarySlot(TyperTest* R) {
  return FeedbackSource{
      FeedbackVector::NewWithOneBinarySlotForTesting(R->zone(), R->isolate()),
      FeedbackSlot{0}};
}

FeedbackSource FeedbackSourceWithOneCompareSlot(TyperTest* R) {
  return FeedbackSource{
      FeedbackVector::NewWithOneCompareSlotForTesting(R->zone(), R->isolate()),
      FeedbackSlot{0}};
}

}  // namespace


//------------------------------------------------------------------------------
// Soundness
//   For simplicity, we currently only test soundness on expression operators
//   that have a direct equivalent in C++.  Also, testing is currently limited
//   to ranges as input types.

TEST_F(TyperTest, TypeJSAdd) {
  TestBinaryArithOp(javascript_.Add(FeedbackSourceWithOneBinarySlot(this)),
                    std::plus<double>());
}

TEST_F(TyperTest, TypeJSSubtract) {
  TestBinaryArithOp(javascript_.Subtract(FeedbackSourceWithOneBinarySlot(this)),
                    std::minus<double>());
}

TEST_F(TyperTest, TypeJSMultiply) {
  TestBinaryArithOp(javascript_.Multiply(FeedbackSourceWithOneBinarySlot(this)),
                    std::multiplies<double>());
}

TEST_F(TyperTest, TypeJSDivide) {
  TestBinaryArithOp(javascript_.Divide(FeedbackSourceWithOneBinarySlot(this)),
                    divide_double_double);
}

TEST_F(TyperTest, TypeJSModulus) {
  TestBinaryArithOp(javascript_.Modulus(FeedbackSourceWithOneBinarySlot(this)),
                    modulo_double_double);
}

TEST_F(TyperTest, TypeJSBitwiseOr) {
  TestBinaryBitOp(javascript_.BitwiseOr(FeedbackSourceWithOneBinarySlot(this)),
                  bit_or);
}

TEST_F(TyperTest, TypeJSBitwiseAnd) {
  TestBinaryBitOp(javascript_.BitwiseAnd(FeedbackSourceWithOneBinarySlot(this)),
                  bit_and);
}

TEST_F(TyperTest, TypeJSBitwiseXor) {
  TestBinaryBitOp(javascript_.BitwiseXor(FeedbackSourceWithOneBinarySlot(this)),
                  bit_xor);
}

TEST_F(TyperTest, TypeJSShiftLeft) {
  TestBinaryBitOp(javascript_.ShiftLeft(FeedbackSourceWithOneBinarySlot(this)),
                  shift_left);
}

TEST_F(TyperTest, TypeJSShiftRight) {
  TestBinaryBitOp(javascript_.ShiftRight(FeedbackSourceWithOneBinarySlot(this)),
                  shift_right);
}

TEST_F(TyperTest, TypeJSLessThan) {
  TestBinaryCompareOp(
      javascript_.LessThan(FeedbackSourceWithOneCompareSlot(this)),
      std::less<double>());
}

TEST_F(TyperTest, TypeNumberLessThan) {
  TestBinaryCompareOp(simplified_.NumberLessThan(), std::less<double>());
}

TEST_F(TyperTest, TypeSpeculativeNumberLessThan) {
  TestBinaryCompareOp(simplified_.SpeculativeNumberLessThan(
                          NumberOperationHint::kNumberOrOddball),
                      std::less<double>());
}

TEST_F(TyperTest, TypeJSLessThanOrEqual) {
  TestBinaryCompareOp(
      javascript_.LessThanOrEqual(FeedbackSourceWithOneCompareSlot(this)),
      std::less_equal<double>());
}

TEST_F(TyperTest, TypeNumberLessThanOrEqual) {
  TestBinaryCompareOp(simplified_.NumberLessThanOrEqual(),
                      std::less_equal<double>());
}

TEST_F(TyperTest, TypeSpeculativeNumberLessThanOrEqual) {
  TestBinaryCompareOp(simplified_.SpeculativeNumberLessThanOrEqual(
                          NumberOperationHint::kNumberOrOddball),
                      std::less_equal<double>());
}

TEST_F(TyperTest, TypeJSGreaterThan) {
  TestBinaryCompareOp(
      javascript_.GreaterThan(FeedbackSourceWithOneCompareSlot(this)),
      std::greater<double>());
}


TEST_F(TyperTest, TypeJSGreaterThanOrEqual) {
  TestBinaryCompareOp(
      javascript_.GreaterThanOrEqual(FeedbackSourceWithOneCompareSlot(this)),
      std::greater_equal<double>());
}

TEST_F(TyperTest, TypeJSEqual) {
  TestBinaryCompareOp(javascript_.Equal(FeedbackSourceWithOneCompareSlot(this)),
                      std::equal_to<double>());
}

TEST_F(TyperTest, TypeNumberEqual) {
  TestBinaryCompareOp(simplified_.NumberEqual(), std::equal_to<double>());
}

TEST_F(TyperTest, TypeSpeculativeNumberEqual) {
  TestBinaryCompareOp(
      simplified_.SpeculativeNumberEqual(NumberOperationHint::kNumberOrOddball),
      std::equal_to<double>());
}

// For numbers there's no difference between strict and non-strict equality.
TEST_F(TyperTest, TypeJSStrictEqual) {
  TestBinaryCompareOp(
      javascript_.StrictEqual(FeedbackSourceWithOneCompareSlot(this)),
      std::equal_to<double>());
}

//------------------------------------------------------------------------------
// Typer Monotonicity

// JS UNOPs without hint
#define TEST_MONOTONICITY(name)                \
  TEST_F(TyperTest, Monotonicity_##name) {     \
    TestUnaryMonotonicity(javascript_.name()); \
  }
TEST_MONOTONICITY(ToLength)
TEST_MONOTONICITY(ToName)
TEST_MONOTONICITY(ToNumber)
TEST_MONOTONICITY(ToObject)
TEST_MONOTONICITY(ToString)
#undef TEST_MONOTONICITY

// JS compare ops.
#define TEST_MONOTONICITY(name)                                    \
  TEST_F(TyperTest, Monotonicity_##name) {                         \
    TestBinaryMonotonicity(                                        \
        javascript_.name(FeedbackSourceWithOneCompareSlot(this))); \
  }
TEST_MONOTONICITY(Equal)
TEST_MONOTONICITY(StrictEqual)
TEST_MONOTONICITY(LessThan)
TEST_MONOTONICITY(GreaterThan)
TEST_MONOTONICITY(LessThanOrEqual)
TEST_MONOTONICITY(GreaterThanOrEqual)
#undef TEST_MONOTONICITY

// JS binary ops.
#define TEST_MONOTONICITY(name)                                   \
  TEST_F(TyperTest, Monotonicity_##name) {                        \
    TestBinaryMonotonicity(                                       \
        javascript_.name(FeedbackSourceWithOneBinarySlot(this))); \
  }
TEST_MONOTONICITY(Add)
TEST_MONOTONICITY(BitwiseAnd)
TEST_MONOTONICITY(BitwiseOr)
TEST_MONOTONICITY(BitwiseXor)
TEST_MONOTONICITY(Divide)
TEST_MONOTONICITY(Modulus)
TEST_MONOTONICITY(Multiply)
TEST_MONOTONICITY(ShiftLeft)
TEST_MONOTONICITY(ShiftRight)
TEST_MONOTONICITY(ShiftRightLogical)
TEST_MONOTONICITY(Subtract)
#undef TEST_MONOTONICITY

TEST_F(TyperTest, Monotonicity_InstanceOf) {
  TestBinaryMonotonicity(javascript_.InstanceOf(FeedbackSource()));
}

TEST_F(TyperTest, Monotonicity_OrdinaryHasInstance) {
  TestBinaryMonotonicity(javascript_.OrdinaryHasInstance());
}

// SIMPLIFIED UNOPs without hint
#define TEST_MONOTONICITY(name)                \
  TEST_F(TyperTest, Monotonicity_##name) {     \
    TestUnaryMonotonicity(simplified_.name()); \
  }
TEST_MONOTONICITY(ObjectIsDetectableCallable)
TEST_MONOTONICITY(ObjectIsNaN)
TEST_MONOTONICITY(ObjectIsNonCallable)
TEST_MONOTONICITY(ObjectIsNumber)
TEST_MONOTONICITY(ObjectIsReceiver)
TEST_MONOTONICITY(ObjectIsSmi)
TEST_MONOTONICITY(ObjectIsString)
TEST_MONOTONICITY(ObjectIsSymbol)
TEST_MONOTONICITY(ObjectIsUndetectable)
TEST_MONOTONICITY(TypeOf)
TEST_MONOTONICITY(ToBoolean)
#undef TEST_MONOTONICITY

// SIMPLIFIED BINOPs without hint, with Number input restriction
#define TEST_MONOTONICITY(name)                                \
  TEST_F(TyperTest, Monotonicity_##name) {                     \
    TestBinaryMonotonicity(simplified_.name(), Type::Number(), \
                           Type::Number());                    \
  }
SIMPLIFIED_NUMBER_BINOP_LIST(TEST_MONOTONICITY)
#undef TEST_MONOTONICITY

// SIMPLIFIED BINOPs without hint, without input restriction
#define TEST_MONOTONICITY(name)                 \
  TEST_F(TyperTest, Monotonicity_##name) {      \
    TestBinaryMonotonicity(simplified_.name()); \
  }
TEST_MONOTONICITY(NumberLessThan)
TEST_MONOTONICITY(NumberLessThanOrEqual)
TEST_MONOTONICITY(NumberEqual)
TEST_MONOTONICITY(ReferenceEqual)
TEST_MONOTONICITY(StringEqual)
TEST_MONOTONICITY(StringLessThan)
TEST_MONOTONICITY(StringLessThanOrEqual)
#undef TEST_MONOTONICITY

// SIMPLIFIED BINOPs with NumberOperationHint, without input restriction
#define TEST_MONOTONICITY(name)                                             \
  TEST_F(TyperTest, Monotonicity_##name) {                                  \
    TestBinaryMonotonicity(simplified_.name(NumberOperationHint::kNumber)); \
  }
TEST_MONOTONICITY(SpeculativeNumberEqual)
TEST_MONOTONICITY(SpeculativeNumberLessThan)
TEST_MONOTONICITY(SpeculativeNumberLessThanOrEqual)
#undef TEST_MONOTONICITY

// SIMPLIFIED BINOPs with NumberOperationHint, without input restriction
#define TEST_MONOTONICITY(name)                                             \
  TEST_F(TyperTest, Monotonicity_##name) {                                  \
    TestBinaryMonotonicity(simplified_.name(NumberOperationHint::kNumber)); \
  }
SIMPLIFIED_SPECULATIVE_NUMBER_BINOP_LIST(TEST_MONOTONICITY)
#undef TEST_MONOTONICITY

//------------------------------------------------------------------------------
// OperationTyper Monotonicity

// SIMPLIFIED UNOPs with Number input restriction
#define TEST_MONOTONICITY(name)                      \
  TEST_F(TyperTest, Monotonicity_Operation_##name) { \
    UnaryTyper typer = [&](Type type1) {             \
      return operation_typer_.name(type1);           \
    };                                               \
    for (int i = 0; i < kRepetitions; ++i) {         \
      TestUnaryMonotonicity(typer, Type::Number());  \
    }                                                \
  }
SIMPLIFIED_NUMBER_UNOP_LIST(TEST_MONOTONICITY)
#undef TEST_MONOTONICITY

// SIMPLIFIED BINOPs with Number input restriction
#define TEST_MONOTONICITY(name)                                      \
  TEST_F(TyperTest, Monotonicity_Operation_##name) {                 \
    BinaryTyper typer = [&](Type type1, Type type2) {                \
      return operation_typer_.name(type1, type2);                    \
    };                                                               \
    for (int i = 0; i < kRepetitions; ++i) {                         \
      TestBinaryMonotonicity(typer, Type::Number(), Type::Number()); \
    }                                                                \
  }
SIMPLIFIED_NUMBER_BINOP_LIST(TEST_MONOTONICITY)
#undef TEST_MONOTONICITY

// SIMPLIFIED BINOPs without input restriction
#define TEST_MONOTONICITY(name)                       \
  TEST_F(TyperTest, Monotonicity_Operation_##name) {  \
    BinaryTyper typer = [&](Type type1, Type type2) { \
      return operation_typer_.name(type1, type2);     \
    };                                                \
    for (int i = 0; i < kRepetitions; ++i) {          \
      TestBinaryMonotonicity(typer);                  \
    }                                                 \
  }
SIMPLIFIED_SPECULATIVE_NUMBER_BINOP_LIST(TEST_MONOTONICITY)
#undef TEST_MONOTONICITY

TEST_F(TyperTest, Manual_Operation_NumberMax) {
  BinaryTyper t = [&](Type type1, Type type2) {
    return operation_typer_.NumberMax(type1, type2);
  };

  Type zero = Type::Constant(0, zone());
  Type zero_or_minuszero = Type::Union(zero, Type::MinusZero(), zone());
  Type dot_five = Type::Constant(0.5, zone());

  Type a = t(Type::MinusZero(), Type::MinusZero());
  CHECK(Type::MinusZero().Is(a));

  Type b = t(Type::MinusZero(), zero_or_minuszero);
  CHECK(Type::MinusZero().Is(b));
  CHECK(zero.Is(b));
  CHECK(a.Is(b));  // Monotonicity.

  Type c = t(zero_or_minuszero, Type::MinusZero());
  CHECK(Type::MinusZero().Is(c));
  CHECK(zero.Is(c));
  CHECK(a.Is(c));  // Monotonicity.

  Type d = t(zero_or_minuszero, zero_or_minuszero);
  CHECK(Type::MinusZero().Is(d));
  CHECK(zero.Is(d));
  CHECK(b.Is(d));  // Monotonicity.
  CHECK(c.Is(d));  // Monotonicity.

  Type e =
      t(Type::MinusZero(), Type::Union(Type::MinusZero(), dot_five, zone()));
  CHECK(Type::MinusZero().Is(e));
  CHECK(dot_five.Is(e));
  CHECK(a.Is(e));  // Monotonicity.

  Type f = t(Type::MinusZero(), zero);
  CHECK(zero.Is(f));
  CHECK(f.Is(b));  // Monotonicity.

  Type g = t(zero, Type::MinusZero());
  CHECK(zero.Is(g));
  CHECK(g.Is(c));  // Monotonicity.

  Type h = t(Type::Signed32(), Type::MinusZero());
  CHECK(Type::MinusZero().Is(h));

  Type i = t(Type::Signed32(), zero_or_minuszero);
  CHECK(h.Is(i));  // Monotonicity.
}

TEST_F(TyperTest, Manual_Operation_NumberMin) {
  BinaryTyper t = [&](Type type1, Type type2) {
    return operation_typer_.NumberMin(type1, type2);
  };

  Type zero = Type::Constant(0, zone());
  Type zero_or_minuszero = Type::Union(zero, Type::MinusZero(), zone());
  Type one = Type::Constant(1, zone());
  Type minus_dot_five = Type::Constant(-0.5, zone());

  Type a = t(Type::MinusZero(), Type::MinusZero());
  CHECK(Type::MinusZero().Is(a));

  Type b = t(Type::MinusZero(), zero_or_minuszero);
  CHECK(Type::MinusZero().Is(b));
  CHECK(zero.Is(b));
  CHECK(a.Is(b));  // Monotonicity.

  Type c = t(zero_or_minuszero, Type::MinusZero());
  CHECK(Type::MinusZero().Is(c));
  CHECK(zero.Is(c));
  CHECK(a.Is(c));  // Monotonicity.

  Type d = t(zero_or_minuszero, zero_or_minuszero);
  CHECK(Type::MinusZero().Is(d));
  CHECK(zero.Is(d));
  CHECK(b.Is(d));  // Monotonicity.
  CHECK(c.Is(d));  // Monotonicity.

  Type e = t(Type::MinusZero(),
             Type::Union(Type::MinusZero(), minus_dot_five, zone()));
  CHECK(Type::MinusZero().Is(e));
  CHECK(minus_dot_five.Is(e));
  CHECK(a.Is(e));  // Monotonicity.

  Type f = t(Type::MinusZero(), zero);
  CHECK(Type::MinusZero().Is(f));
  CHECK(f.Is(b));  // Monotonicity.

  Type g = t(zero, Type::MinusZero());
  CHECK(Type::MinusZero().Is(g));
  CHECK(g.Is(c));  // Monotonicity.

  Type h = t(one, Type::MinusZero());
  CHECK(Type::MinusZero().Is(h));

  Type i = t(Type::Signed32(), Type::MinusZero());
  CHECK(Type::MinusZero().Is(i));

  Type j = t(Type::Signed32(), zero_or_minuszero);
  CHECK(i.Is(j));  // Monotonicity.
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```