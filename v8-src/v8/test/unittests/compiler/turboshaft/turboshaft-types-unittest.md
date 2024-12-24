Response: Let's break down the thought process for analyzing this C++ code and relating it to JavaScript.

1. **Understand the Goal:** The request asks for a summary of the C++ file's functionality and to connect it to JavaScript with an example if a relationship exists.

2. **Initial Scan and Keywords:** Quickly read through the code, looking for recognizable patterns and keywords. I see things like:
    * `#include`: Indicates dependencies and external code being used.
    * `namespace v8`:  Immediately suggests this is related to the V8 JavaScript engine.
    * `compiler/turboshaft`: This points to a specific part of the V8 compiler called "Turboshaft."
    * `turboshaft-types-unittest.cc`: The "unittest" part is crucial. It tells us this is for testing the `types.h` file.
    * `TEST_F`, `EXPECT_TRUE`, `EXPECT_FALSE`: These are Google Test macros used for writing unit tests.
    * `Word32Type`, `Word64Type`, `Float32Type`, `Float64Type`: These are likely custom classes representing different numeric types.
    * `Constant`, `Range`, `Set`, `Any`: These are probably methods or static factory functions for creating instances of the type classes, representing different ways to define a type.
    * `IsSubtypeOf`:  This strongly suggests a type system and the concept of subtyping.
    * `LeastUpperBound`:  This hints at operations on types, specifically finding the least common supertype.

3. **Infer the Core Functionality:** Based on the keywords and structure, the file's main purpose is clearly to **test the `turboshaft/types.h` file**. The tests focus on how different numerical types (32-bit integers, 64-bit integers, 32-bit floats, 64-bit floats) are represented and how their subtype relationships are determined. The `LeastUpperBound` tests indicate testing of type inference or type merging.

4. **Focus on the `Type` Classes:** The core of the testing revolves around the `Word32Type`, `Word64Type`, `Float32Type`, and `Float64Type` classes. The tests demonstrate how to create instances of these types (using `Constant`, `Range`, `Set`, `Any`) and how to check if one type is a subtype of another using `IsSubtypeOf`.

5. **Identify Key Concepts:**  The tests cover important concepts in type systems:
    * **Constants:**  Representing a single specific value.
    * **Ranges:** Representing a contiguous set of values.
    * **Sets:** Representing a discrete collection of values.
    * **Subtyping:**  The "is-a" relationship between types.
    * **Least Upper Bound (LUB):** Finding the most specific common supertype of two types.
    * **Special Values (NaN, -0):** Handling edge cases in floating-point numbers.

6. **Relate to JavaScript:** Now, the crucial step: connecting this to JavaScript.
    * **V8 Engine Connection:**  The `namespace v8` makes the connection direct. Turboshaft is a component of the V8 engine that executes JavaScript.
    * **Type System in JavaScript (Implicit):** JavaScript is dynamically typed, meaning you don't explicitly declare types. However, the *engine* internally tracks types for optimization. Turboshaft, as a compiler component, needs to reason about these internal types.
    * **Optimization:**  The tests are about the *compiler*. This implies the type information being tested is used for optimizing JavaScript code. For example, if the compiler knows a variable is always a 32-bit integer within a certain range, it can generate more efficient machine code.
    * **Examples:**  Think about common JavaScript operations where type information matters:
        * **Arithmetic Operations:**  The engine needs to know if it's dealing with integers or floats to perform the correct operations.
        * **Comparisons:**  The type can affect the comparison result.
        * **Bitwise Operations:** Only meaningful for integers.
        * **Type Coercion:** JavaScript often automatically converts between types. The compiler needs to understand these rules.

7. **Construct the JavaScript Example:** Create simple JavaScript code snippets that illustrate the concepts being tested in the C++ code. Focus on the *effects* of the underlying type system:
    * Show cases where the type is implicitly narrowed (e.g., assigning a small integer).
    * Show cases with different numeric types interacting.
    * Demonstrate potential optimizations (even if not explicitly visible in the JS code).

8. **Structure the Answer:** Organize the findings into a clear and logical explanation:
    * State the main purpose of the C++ file.
    * Explain the role of Turboshaft.
    * Describe the types being tested.
    * Explain the significance of the tests (optimization).
    * Provide concrete JavaScript examples.
    * Summarize the connection.

9. **Refine and Review:** Read through the answer to ensure clarity, accuracy, and completeness. Make sure the JavaScript examples are relevant and easy to understand. Double-check the technical terms.

Self-Correction/Refinement During the Process:

* **Initial thought:** "This is just low-level compiler stuff, hard to relate to JS."  **Correction:** Remember that V8 *executes* JavaScript. The compiler directly impacts performance, and understanding internal type representations helps understand how JS code is optimized.
* **Focusing too much on C++ details:**  **Correction:**  Shift the focus to the *concepts* being tested (ranges, sets, subtyping) and how those concepts manifest in JavaScript behavior (even if implicitly).
* **Making the JS examples too complex:** **Correction:** Keep the JS examples simple and focused on the core ideas. Avoid getting bogged down in advanced JS features.

By following this thought process, combining code analysis with knowledge of JavaScript and the V8 engine, we arrive at a comprehensive and accurate answer.
这个C++源代码文件 `turboshaft-types-unittest.cc` 的主要功能是**为 V8 JavaScript 引擎中 Turboshaft 编译器的类型系统 (`src/compiler/turboshaft/types.h`) 编写单元测试**。

更具体地说，这个文件测试了 `Word32Type`、`Word64Type`、`Float32Type` 和 `Float64Type` 这几个类，这些类用于表示 Turboshaft 编译器内部的不同数值类型。

**它主要测试了以下方面：**

1. **类型的表示：**  如何创建和表示不同类型的实例，例如：
   - `Constant`: 表示一个特定的常量值。
   - `Range`: 表示一个数值范围。
   - `Set`: 表示一组离散的数值。
   - `Any`: 表示该类型的全部可能值。

2. **子类型关系 (`IsSubtypeOf`)：**  测试不同类型实例之间的子类型关系。例如，一个表示数值范围 `[100, 300]` 的 `Word32Type` 实例是否是表示范围 `[50, 400]` 的实例的子类型。

3. **最小上界 (`LeastUpperBound`)：**  测试计算两个类型的最小公共超类型的功能。例如，类型 `[100, 400]` 和类型 `[300, 600]` 的最小上界是什么。

4. **特殊浮点数值的处理：**  测试如何处理浮点数中的特殊值，如 `NaN` (非数字) 和 `-0` (负零)。

**与 JavaScript 的功能关系：**

这个文件直接关系到 V8 JavaScript 引擎的性能优化。Turboshaft 是 V8 的新一代编译器，它使用更先进的技术来将 JavaScript 代码编译成高效的机器码。类型系统是编译器进行优化分析的关键。

虽然 JavaScript 是一种动态类型语言，但在 V8 引擎内部，为了进行优化，会尝试推断变量的类型。`turboshaft-types-unittest.cc` 中测试的类型系统就是 Turboshaft 编译器用来表示和推理这些内部类型信息的。

通过精确地表示和推理变量的类型，Turboshaft 可以进行更激进的优化，从而提高 JavaScript 代码的执行速度。例如，如果 Turboshaft 可以确定一个变量始终是一个 32 位整数，它可以生成针对 32 位整数运算的机器码，而无需处理更通用的数字类型。

**JavaScript 示例说明：**

虽然我们不能直接在 JavaScript 中操作 `Word32Type` 等 C++ 类型，但可以通过 JavaScript 的行为来观察到这些内部类型优化带来的影响。

```javascript
function add(a, b) {
  return a + b;
}

// 场景 1：传入的参数始终是小整数
for (let i = 0; i < 1000; i++) {
  add(i % 10, i % 5);
}

// 场景 2：传入的参数可能是浮点数或大整数
for (let i = 0; i < 1000; i++) {
  add(Math.random() * 10, Math.pow(2, 30) + i);
}
```

在上面的 JavaScript 例子中：

- **场景 1：** 如果 V8 的 Turboshaft 编译器能够通过分析循环或类型反馈信息推断出 `add` 函数在第一次循环中接收的参数始终是小的整数（可以放入 32 位有符号整数），那么它可以内部将 `a` 和 `b` 的类型表示为类似于 `Word32Type` 的类型，并生成针对整数加法的优化代码。

- **场景 2：** 在第二个循环中，由于参数可能是浮点数或超出 32 位整数范围的大整数，编译器可能需要使用更通用的数字类型表示，并且生成的机器码可能不会像场景 1 那样优化。

**总结:**

`turboshaft-types-unittest.cc` 这个 C++ 文件是 V8 JavaScript 引擎中 Turboshaft 编译器类型系统的重要测试文件。它确保了编译器内部表示和推理数值类型的功能正确性。虽然 JavaScript 是动态类型的，但 V8 内部的类型系统对于优化 JavaScript 代码的执行至关重要，直接影响了 JavaScript 代码的性能。 开发者虽然不能直接接触这些内部类型，但可以通过观察 JavaScript 代码在不同场景下的执行效率，间接地感受到这些类型优化带来的影响。

Prompt: 
```
这是目录为v8/test/unittests/compiler/turboshaft/turboshaft-types-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/turboshaft/types.h"
#include "src/handles/handles.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8::internal::compiler::turboshaft {

class TurboshaftTypesTest : public TestWithNativeContextAndZone {
 public:
  using Kind = Type::Kind;

  TurboshaftTypesTest() : TestWithNativeContextAndZone() {}
};

TEST_F(TurboshaftTypesTest, Word32) {
  const auto max_value = std::numeric_limits<Word32Type::word_t>::max();

  // Complete range
  {
    Word32Type t = Word32Type::Any();
    EXPECT_TRUE(Word32Type::Constant(0).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Constant(800).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Constant(max_value).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Set({0, 1}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Set({0, max_value}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Set({3, 9, max_value - 1}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Range(0, 10, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Range(800, 1200, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Range(1, max_value - 1, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Range(0, max_value, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Range(max_value - 20, 20, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Range(1000, 999, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Any().IsSubtypeOf(t));
    EXPECT_TRUE(t.IsSubtypeOf(t));
  }

  // Range (non-wrapping)
  {
    Word32Type t = Word32Type::Range(100, 300, zone());
    EXPECT_TRUE(!Word32Type::Constant(0).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Constant(99).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Constant(100).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Constant(250).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Constant(300).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Constant(301).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Set({0, 150}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Set({99, 100}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Set({100, 105}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Set({150, 200, 250}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Set({150, 300}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Set({300, 301}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Range(50, 150, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Range(99, 150, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Range(100, 150, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Range(150, 250, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Range(250, 300, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Range(250, 301, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Range(99, 301, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Range(800, 9000, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(
        !Word32Type::Range(max_value - 100, 100, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Range(250, 200, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Any().IsSubtypeOf(t));
    EXPECT_TRUE(t.IsSubtypeOf(t));
  }

  // Range (wrapping)
  {
    const auto large_value = max_value - 1000;
    Word32Type t = Word32Type::Range(large_value, 800, zone());
    EXPECT_TRUE(Word32Type::Constant(0).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Constant(800).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Constant(801).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Constant(5000).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Constant(large_value - 1).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Constant(large_value).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Constant(large_value + 5).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Constant(max_value).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Set({0, 800}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Set({0, 801}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Set({0, 600, 900}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Set({0, max_value}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Set({100, max_value - 100}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Set({large_value - 1, large_value + 5}, zone())
                     .IsSubtypeOf(t));
    EXPECT_TRUE(
        Word32Type::Set({large_value, large_value + 5, max_value - 5}, zone())
            .IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Range(0, 800, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Range(100, 300, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Range(0, 801, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(
        !Word32Type::Range(200, max_value - 200, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(
        !Word32Type::Range(large_value - 1, max_value, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(
        Word32Type::Range(large_value, max_value, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Range(large_value + 100, max_value - 100, zone())
                    .IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Range(large_value, 800, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(
        Word32Type::Range(large_value + 100, 700, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(
        !Word32Type::Range(large_value - 1, 799, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(
        !Word32Type::Range(large_value + 1, 801, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Range(5000, 100, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Any().IsSubtypeOf(t));
    EXPECT_TRUE(t.IsSubtypeOf(t));
  }

  // Set
  {
    CHECK_GT(Word32Type::kMaxSetSize, 2);
    Word32Type t = Word32Type::Set({4, 890}, zone());
    EXPECT_TRUE(!Word32Type::Constant(0).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Constant(3).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Constant(4).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Constant(5).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Constant(889).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Constant(890).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Set({0, 4}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Set({4, 90}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word32Type::Set({4, 890}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Set({0, 4, 890}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Set({4, 890, 1000}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Set({890, max_value}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Range(0, 100, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Range(4, 890, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Range(800, 900, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Range(800, 100, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Range(890, 4, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Range(max_value - 5, 4, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word32Type::Any().IsSubtypeOf(t));
    EXPECT_TRUE(t.IsSubtypeOf(t));
  }
}

TEST_F(TurboshaftTypesTest, Word64) {
  const auto max_value = std::numeric_limits<Word64Type::word_t>::max();

  // Complete range
  {
    Word64Type t = Word64Type::Any();
    EXPECT_TRUE(Word64Type::Constant(0).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Constant(800).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Constant(max_value).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Set({0, 1}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Set({0, max_value}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Set({3, 9, max_value - 1}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Range(0, 10, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Range(800, 1200, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Range(1, max_value - 1, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Range(0, max_value, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Range(max_value - 20, 20, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Range(1000, 999, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Any().IsSubtypeOf(t));
    EXPECT_TRUE(t.IsSubtypeOf(t));
  }

  // Range (non-wrapping)
  {
    Word64Type t = Word64Type::Range(100, 300, zone());
    EXPECT_TRUE(!Word64Type::Constant(0).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Constant(99).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Constant(100).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Constant(250).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Constant(300).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Constant(301).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Set({0, 150}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Set({99, 100}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Set({100, 105}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Set({150, 200, 250}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Set({150, 300}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Set({300, 301}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Range(50, 150, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Range(99, 150, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Range(100, 150, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Range(150, 250, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Range(250, 300, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Range(250, 301, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Range(99, 301, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Range(800, 9000, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(
        !Word64Type::Range(max_value - 100, 100, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Range(250, 200, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Any().IsSubtypeOf(t));
    EXPECT_TRUE(t.IsSubtypeOf(t));
  }

  // Range (wrapping)
  {
    const auto large_value = max_value - 1000;
    Word64Type t = Word64Type::Range(large_value, 800, zone());
    EXPECT_TRUE(Word64Type::Constant(0).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Constant(800).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Constant(801).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Constant(5000).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Constant(large_value - 1).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Constant(large_value).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Constant(large_value + 5).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Constant(max_value).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Set({0, 800}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Set({0, 801}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Set({0, 600, 900}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Set({0, max_value}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Set({100, max_value - 100}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Set({large_value - 1, large_value + 5}, zone())
                     .IsSubtypeOf(t));
    EXPECT_TRUE(
        Word64Type::Set({large_value, large_value + 5, max_value - 5}, zone())
            .IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Range(0, 800, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Range(100, 300, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Range(0, 801, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(
        !Word64Type::Range(200, max_value - 200, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(
        !Word64Type::Range(large_value - 1, max_value, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(
        Word64Type::Range(large_value, max_value, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Range(large_value + 100, max_value - 100, zone())
                    .IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Range(large_value, 800, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(
        Word64Type::Range(large_value + 100, 700, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(
        !Word64Type::Range(large_value - 1, 799, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(
        !Word64Type::Range(large_value + 1, 801, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Range(5000, 100, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Any().IsSubtypeOf(t));
    EXPECT_TRUE(t.IsSubtypeOf(t));
  }

  // Set
  {
    CHECK_GT(Word64Type::kMaxSetSize, 2);
    Word64Type t = Word64Type::Set({4, 890}, zone());
    EXPECT_TRUE(!Word64Type::Constant(0).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Constant(3).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Constant(4).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Constant(5).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Constant(889).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Constant(890).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Set({0, 4}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Set({4, 90}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Word64Type::Set({4, 890}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Set({0, 4, 890}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Set({4, 890, 1000}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Set({890, max_value}, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Range(0, 100, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Range(4, 890, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Range(800, 900, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Range(800, 100, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Range(890, 4, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Range(max_value - 5, 4, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Word64Type::Any().IsSubtypeOf(t));
    EXPECT_TRUE(t.IsSubtypeOf(t));
  }
}

TEST_F(TurboshaftTypesTest, Float32) {
  const auto large_value =
      std::numeric_limits<Float32Type::float_t>::max() * 0.99f;
  const auto inf = std::numeric_limits<Float32Type::float_t>::infinity();
  const auto kNaN = Float32Type::kNaN;
  const auto kMinusZero = Float32Type::kMinusZero;
  const auto kNoSpecialValues = Float32Type::kNoSpecialValues;

  // Complete range (with NaN)
  for (bool with_nan : {false, true}) {
    uint32_t sv = kMinusZero | (with_nan ? kNaN : kNoSpecialValues);
    Float32Type t = Float32Type::Any(kNaN | kMinusZero);
    EXPECT_TRUE(Float32Type::NaN().IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::Constant(0.0f).IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::MinusZero().IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::Constant(391.113f).IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::Set({0.13f, 91.0f}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(
        Float32Type::Set({-100.4f, large_value}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::Set({-inf, inf}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::Range(0.0f, inf, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::Range(-inf, 12.3f, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::Range(-inf, inf, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::Any(sv).IsSubtypeOf(t));
    EXPECT_TRUE(t.IsSubtypeOf(t));
  }

  // Complete range (without NaN)
  for (bool with_nan : {false, true}) {
    uint32_t sv = kMinusZero | (with_nan ? kNaN : kNoSpecialValues);
    Float32Type t = Float32Type::Any(kMinusZero);
    EXPECT_TRUE(!Float32Type::NaN().IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::Constant(0.0f).IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::MinusZero().IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::Constant(391.113f).IsSubtypeOf(t));
    EXPECT_EQ(!with_nan,
              Float32Type::Set({0.13f, 91.0f}, sv, zone()).IsSubtypeOf(t));
    EXPECT_EQ(
        !with_nan,
        Float32Type::Set({-100.4f, large_value}, sv, zone()).IsSubtypeOf(t));
    EXPECT_EQ(!with_nan,
              Float32Type::Set({-inf, inf}, sv, zone()).IsSubtypeOf(t));
    EXPECT_EQ(!with_nan,
              Float32Type::Range(0.0f, inf, sv, zone()).IsSubtypeOf(t));
    EXPECT_EQ(!with_nan,
              Float32Type::Range(-inf, 12.3f, sv, zone()).IsSubtypeOf(t));
    EXPECT_EQ(!with_nan,
              Float32Type::Range(-inf, inf, sv, zone()).IsSubtypeOf(t));
    EXPECT_EQ(!with_nan, Float32Type::Any(sv).IsSubtypeOf(t));
    EXPECT_TRUE(t.IsSubtypeOf(t));
  }

  // Range (with NaN)
  for (bool with_nan : {false, true}) {
    uint32_t sv = kMinusZero | (with_nan ? kNaN : kNoSpecialValues);
    Float32Type t =
        Float32Type::Range(-1.0f, 3.14159f, kNaN | kMinusZero, zone());
    EXPECT_TRUE(Float32Type::NaN().IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Constant(-100.0f).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Constant(-1.01f).IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::Constant(-1.0f).IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::Constant(-0.99f).IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::MinusZero().IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::Constant(0.0f).IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::Constant(3.14159f).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Constant(3.15f).IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::Set({-0.5f}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Set({-1.1f, 1.5f}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::Set({-0.9f, 1.88f}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Set({0.0f, 3.142f}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Set({-inf, 0.3f}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Range(-inf, 0, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Range(-1.01f, 0.0f, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::Range(-1.0f, 1.0f, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::Range(0.0f, 3.14159f, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Range(0.0f, 3.142f, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Range(3.0f, inf, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Any(sv).IsSubtypeOf(t));
    EXPECT_TRUE(t.IsSubtypeOf(t));
  }

  // Range (without NaN)
  for (bool with_nan : {false, true}) {
    uint32_t sv = kMinusZero | (with_nan ? kNaN : kNoSpecialValues);
    Float32Type t = Float32Type::Range(-1.0f, 3.14159f, kMinusZero, zone());
    EXPECT_TRUE(!Float32Type::NaN().IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Constant(-100.0f).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Constant(-1.01f).IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::Constant(-1.0f).IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::Constant(-0.99f).IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::MinusZero().IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::Constant(0.0f).IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::Constant(3.14159f).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Constant(3.15f).IsSubtypeOf(t));
    EXPECT_EQ(!with_nan, Float32Type::Set({-0.5f}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Set({-1.1f, 1.5f}, sv, zone()).IsSubtypeOf(t));
    EXPECT_EQ(!with_nan,
              Float32Type::Set({-0.9f, 1.88f}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Set({0.0f, 3.142f}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Set({-inf, 0.3f}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Range(-inf, 0, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Range(-1.01f, 0.0f, sv, zone()).IsSubtypeOf(t));
    EXPECT_EQ(!with_nan,
              Float32Type::Range(-1.0f, 1.0f, sv, zone()).IsSubtypeOf(t));
    EXPECT_EQ(!with_nan,
              Float32Type::Range(0.0f, 3.14159f, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Range(0.0f, 3.142f, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Range(3.0f, inf, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Any(sv).IsSubtypeOf(t));
    EXPECT_TRUE(t.IsSubtypeOf(t));
  }

  // Set (with NaN)
  for (bool with_nan : {false, true}) {
    uint32_t sv = with_nan ? kNaN : kNoSpecialValues;
    Float32Type t = Float32Type::Set({-1.0f, 3.14159f}, kNaN, zone());
    EXPECT_TRUE(Float32Type::NaN().IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Constant(-100.0f).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Constant(-1.01f).IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::Constant(-1.0f).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Constant(1.0f).IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::Constant(3.14159f).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Constant(3.1415f).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Constant(inf).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Set({-inf, 0.0f}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Set({-1.0f, 0.0f}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::Set({-1.0f, 3.14159f}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(
        !Float32Type::Set({3.14159f, 3.1416f}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Range(-inf, -1.0f, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Range(-1.01f, -1.0f, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(
        !Float32Type::Range(-1.0f, 3.14159f, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Range(3.14159f, 4.0f, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Any(sv).IsSubtypeOf(t));
    EXPECT_TRUE(t.IsSubtypeOf(t));
  }

  // Set (without NaN)
  for (bool with_nan : {false, true}) {
    uint32_t sv = with_nan ? kNaN : kNoSpecialValues;
    Float32Type t =
        Float32Type::Set({-1.0f, 3.14159f}, kNoSpecialValues, zone());
    EXPECT_TRUE(!Float32Type::NaN().IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Constant(-100.0f).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Constant(-1.01f).IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::Constant(-1.0f).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Constant(1.0f).IsSubtypeOf(t));
    EXPECT_TRUE(Float32Type::Constant(3.14159f).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Constant(3.1415f).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Constant(inf).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Set({-inf, 0.0f}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Set({-1.0f, 0.0f}, sv, zone()).IsSubtypeOf(t));
    EXPECT_EQ(!with_nan,
              Float32Type::Set({-1.0f, 3.14159f}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(
        !Float32Type::Set({3.14159f, 3.1416f}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Range(-inf, -1.0f, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Range(-1.01f, -1.0f, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(
        !Float32Type::Range(-1.0f, 3.14159f, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Range(3.14159f, 4.0f, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float32Type::Any(sv).IsSubtypeOf(t));
    EXPECT_TRUE(t.IsSubtypeOf(t));
  }

  // -0.0f corner cases
  {
    EXPECT_TRUE(!Float32Type::MinusZero().IsSubtypeOf(
        Float32Type::Set({0.0f, 1.0f}, zone())));
    EXPECT_TRUE(
        !Float32Type::Constant(0.0f).IsSubtypeOf(Float32Type::MinusZero()));
    EXPECT_TRUE(
        Float32Type::Set({3.2f}, kMinusZero, zone())
            .IsSubtypeOf(Float32Type::Range(0.0f, 4.0f, kMinusZero, zone())));
    EXPECT_TRUE(!Float32Type::Set({-1.0f, 0.0f}, kMinusZero, zone())
                     .IsSubtypeOf(Float32Type::Range(-inf, 0.0f, zone())));
  }
}

TEST_F(TurboshaftTypesTest, Float64) {
  const auto large_value =
      std::numeric_limits<Float64Type::float_t>::max() * 0.99;
  const auto inf = std::numeric_limits<Float64Type::float_t>::infinity();
  const auto kNaN = Float64Type::kNaN;
  const auto kMinusZero = Float64Type::kMinusZero;
  const auto kNoSpecialValues = Float64Type::kNoSpecialValues;

  // Complete range (with NaN)
  for (bool with_nan : {false, true}) {
    uint32_t sv = kMinusZero | (with_nan ? kNaN : kNoSpecialValues);
    Float64Type t = Float64Type::Any(kNaN | kMinusZero);
    EXPECT_TRUE(Float64Type::NaN().IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::Constant(0.0).IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::MinusZero().IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::Constant(391.113).IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::Set({0.13, 91.0}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(
        Float64Type::Set({-100.4, large_value}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::Set({-inf, inf}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::Range(0.0, inf, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::Range(-inf, 12.3, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::Range(-inf, inf, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::Any(sv).IsSubtypeOf(t));
    EXPECT_TRUE(t.IsSubtypeOf(t));
  }

  // Complete range (without NaN)
  for (bool with_nan : {false, true}) {
    uint32_t sv = kMinusZero | (with_nan ? kNaN : kNoSpecialValues);
    Float64Type t = Float64Type::Any(kMinusZero);
    EXPECT_TRUE(!Float64Type::NaN().IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::Constant(0.0).IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::MinusZero().IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::Constant(391.113).IsSubtypeOf(t));
    EXPECT_EQ(!with_nan,
              Float64Type::Set({0.13, 91.0}, sv, zone()).IsSubtypeOf(t));
    EXPECT_EQ(
        !with_nan,
        Float64Type::Set({-100.4, large_value}, sv, zone()).IsSubtypeOf(t));
    EXPECT_EQ(!with_nan,
              Float64Type::Set({-inf, inf}, sv, zone()).IsSubtypeOf(t));
    EXPECT_EQ(!with_nan,
              Float64Type::Range(0.0, inf, sv, zone()).IsSubtypeOf(t));
    EXPECT_EQ(!with_nan,
              Float64Type::Range(-inf, 12.3, sv, zone()).IsSubtypeOf(t));
    EXPECT_EQ(!with_nan,
              Float64Type::Range(-inf, inf, sv, zone()).IsSubtypeOf(t));
    EXPECT_EQ(!with_nan, Float64Type::Any(sv).IsSubtypeOf(t));
    EXPECT_TRUE(t.IsSubtypeOf(t));
  }

  // Range (with NaN)
  for (bool with_nan : {false, true}) {
    uint32_t sv = kMinusZero | (with_nan ? kNaN : kNoSpecialValues);
    Float64Type t =
        Float64Type::Range(-1.0, 3.14159, kNaN | kMinusZero, zone());
    EXPECT_TRUE(Float64Type::NaN().IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Constant(-100.0).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Constant(-1.01).IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::Constant(-1.0).IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::Constant(-0.99).IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::MinusZero().IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::Constant(0.0).IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::Constant(3.14159).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Constant(3.15).IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::Set({-0.5}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Set({-1.1, 1.5}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::Set({-0.9, 1.88}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Set({0.0, 3.142}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Set({-inf, 0.3}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Range(-inf, 0, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Range(-1.01, 0.0, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::Range(-1.0, 1.0, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::Range(0.0, 3.14159, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Range(0.0, 3.142, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Range(3.0, inf, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Any(sv).IsSubtypeOf(t));
    EXPECT_TRUE(t.IsSubtypeOf(t));
  }

  // Range (without NaN)
  for (bool with_nan : {false, true}) {
    uint32_t sv = kMinusZero | (with_nan ? kNaN : kNoSpecialValues);
    Float64Type t = Float64Type::Range(-1.0, 3.14159, kMinusZero, zone());
    EXPECT_TRUE(!Float64Type::NaN().IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Constant(-100.0).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Constant(-1.01).IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::Constant(-1.0).IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::Constant(-0.99).IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::MinusZero().IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::Constant(0.0).IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::Constant(3.14159).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Constant(3.15).IsSubtypeOf(t));
    EXPECT_EQ(!with_nan, Float64Type::Set({-0.5}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Set({-1.1, 1.5}, sv, zone()).IsSubtypeOf(t));
    EXPECT_EQ(!with_nan,
              Float64Type::Set({-0.9, 1.88}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Set({0.0, 3.142}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Set({-inf, 0.3}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Range(-inf, 0, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Range(-1.01, 0.0, sv, zone()).IsSubtypeOf(t));
    EXPECT_EQ(!with_nan,
              Float64Type::Range(-1.0, 1.0, sv, zone()).IsSubtypeOf(t));
    EXPECT_EQ(!with_nan,
              Float64Type::Range(0.0, 3.14159, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Range(0.0, 3.142, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Range(3.0, inf, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Any(sv).IsSubtypeOf(t));
    EXPECT_TRUE(t.IsSubtypeOf(t));
  }

  // Set (with NaN)
  for (bool with_nan : {false, true}) {
    uint32_t sv = with_nan ? kNaN : kNoSpecialValues;
    Float64Type t = Float64Type::Set({-1.0, 3.14159}, kNaN, zone());
    EXPECT_TRUE(Float64Type::NaN().IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Constant(-100.0).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Constant(-1.01).IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::Constant(-1.0).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Constant(1.0).IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::Constant(3.14159).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Constant(3.1415).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Constant(inf).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Set({-inf, 0.0}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Set({-1.0, 0.0}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::Set({-1.0, 3.14159}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(
        !Float64Type::Set({3.14159, 3.1416}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Range(-inf, -1.0, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Range(-1.01, -1.0, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Range(-1.0, 3.14159, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Range(3.14159, 4.0, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Any(sv).IsSubtypeOf(t));
    EXPECT_TRUE(t.IsSubtypeOf(t));
  }

  // Set (without NaN)
  for (bool with_nan : {false, true}) {
    uint32_t sv = with_nan ? kNaN : kNoSpecialValues;
    Float64Type t = Float64Type::Set({-1.0, 3.14159}, kNoSpecialValues, zone());
    EXPECT_TRUE(!Float64Type::NaN().IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Constant(-100.0).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Constant(-1.01).IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::Constant(-1.0).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Constant(1.0).IsSubtypeOf(t));
    EXPECT_TRUE(Float64Type::Constant(3.14159).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Constant(3.1415).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Constant(inf).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Set({-inf, 0.0}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Set({-1.0, 0.0}, sv, zone()).IsSubtypeOf(t));
    EXPECT_EQ(!with_nan,
              Float64Type::Set({-1.0, 3.14159}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(
        !Float64Type::Set({3.14159, 3.1416}, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Range(-inf, -1.0, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Range(-1.01, -1.0, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Range(-1.0, 3.14159, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Range(3.14159, 4.0, sv, zone()).IsSubtypeOf(t));
    EXPECT_TRUE(!Float64Type::Any(sv).IsSubtypeOf(t));
    EXPECT_TRUE(t.IsSubtypeOf(t));
  }

  // -0.0 corner cases
  {
    EXPECT_TRUE(!Float64Type::MinusZero().IsSubtypeOf(
        Float64Type::Set({0.0, 1.0}, zone())));
    EXPECT_TRUE(
        !Float64Type::Constant(0.0).IsSubtypeOf(Float64Type::MinusZero()));
    EXPECT_TRUE(
        Float64Type::Set({3.2}, kMinusZero, zone())
            .IsSubtypeOf(Float64Type::Range(0.0, 4.0, kMinusZero, zone())));
    EXPECT_TRUE(
        Float64Type::Set({0.0}, kMinusZero, zone())
            .IsSubtypeOf(Float64Type::Range(-inf, 0.0, kMinusZero, zone())));
  }
}

TEST_F(TurboshaftTypesTest, Word32LeastUpperBound) {
  auto CheckLubIs = [&](const Word32Type& lhs, const Word32Type& rhs,
                        const Word32Type& expected) {
    EXPECT_TRUE(
        expected.IsSubtypeOf(Word32Type::LeastUpperBound(lhs, rhs, zone())));
  };

  {
    const auto lhs = Word32Type::Range(100, 400, zone());
    CheckLubIs(lhs, lhs, lhs);
    CheckLubIs(lhs, Word32Type::Range(50, 350, zone()),
               Word32Type::Range(50, 400, zone()));
    CheckLubIs(lhs, Word32Type::Range(150, 600, zone()),
               Word32Type::Range(100, 600, zone()));
    CheckLubIs(lhs, Word32Type::Range(150, 350, zone()), lhs);
    CheckLubIs(lhs, Word32Type::Range(350, 0, zone()),
               Word32Type::Range(100, 0, zone()));
    CheckLubIs(lhs, Word32Type::Range(400, 100, zone()), Word32Type::Any());
    CheckLubIs(lhs, Word32Type::Range(600, 0, zone()),
               Word32Type::Range(600, 400, zone()));
    CheckLubIs(lhs, Word32Type::Range(300, 150, zone()), Word32Type::Any());
  }

  {
    const auto lhs = Word32Type::Constant(18);
    CheckLubIs(lhs, lhs, lhs);
    CheckLubIs(lhs, Word32Type::Constant(1119),
               Word32Type::Set({18, 1119}, zone()));
    CheckLubIs(lhs, Word32Type::Constant(0), Word32Type::Set({0, 18}, zone()));
    CheckLubIs(lhs, Word32Type::Range(40, 100, zone()),
               Word32Type::Range(18, 100, zone()));
    CheckLubIs(lhs, Word32Type::Range(4, 90, zone()),
               Word32Type::Range(4, 90, zone()));
    CheckLubIs(lhs, Word32Type::Set({0, 1, 2, 3}, zone()),
               Word32Type::Set({0, 1, 2, 3, 18}, zone()));
    CheckLubIs(
        lhs, Word32Type::Constant(std::numeric_limits<uint32_t>::max()),
        Word32Type::Set({18, std::numeric_limits<uint32_t>::max()}, zone()));
  }
}

TEST_F(TurboshaftTypesTest, Word64LeastUpperBound) {
  auto CheckLubIs = [&](const Word64Type& lhs, const Word64Type& rhs,
                        const Word64Type& expected) {
    EXPECT_TRUE(
        expected.IsSubtypeOf(Word64Type::LeastUpperBound(lhs, rhs, zone())));
  };

  {
    const auto lhs = Word64Type::Range(100, 400, zone());
    CheckLubIs(lhs, lhs, lhs);
    CheckLubIs(lhs, Word64Type::Range(50, 350, zone()),
               Word64Type::Range(50, 400, zone()));
    CheckLubIs(lhs, Word64Type::Range(150, 600, zone()),
               Word64Type::Range(100, 600, zone()));
    CheckLubIs(lhs, Word64Type::Range(150, 350, zone()), lhs);
    CheckLubIs(lhs, Word64Type::Range(350, 0, zone()),
               Word64Type::Range(100, 0, zone()));
    CheckLubIs(lhs, Word64Type::Range(400, 100, zone()), Word64Type::Any());
    CheckLubIs(lhs, Word64Type::Range(600, 0, zone()),
               Word64Type::Range(600, 400, zone()));
    CheckLubIs(lhs, Word64Type::Range(300, 150, zone()), Word64Type::Any());
  }

  {
    const auto lhs = Word64Type::Constant(18);
    CheckLubIs(lhs, lhs, lhs);
    CheckLubIs(lhs, Word64Type::Constant(1119),
               Word64Type::Set({18, 1119}, zone()));
    CheckLubIs(lhs, Word64Type::Constant(0), Word64Type::Set({0, 18}, zone()));
    CheckLubIs(lhs, Word64Type::Range(40, 100, zone()),
               Word64Type::Range(18, 100, zone()));
    CheckLubIs(lhs, Word64Type::Range(4, 90, zone()),
               Word64Type::Range(4, 90, zone()));
    CheckLubIs(lhs, Word64Type::Range(0, 3, zone()),
               Word64Type::Set({0, 1, 2, 3, 18}, zone()));
    CheckLubIs(
        lhs, Word64Type::Constant(std::numeric_limits<uint64_t>::max()),
        Word64Type::Set({18, std::numeric_limits<uint64_t>::max()}, zone()));
  }
}

TEST_F(TurboshaftTypesTest, Float32LeastUpperBound) {
  auto CheckLubIs = [&](const Float32Type& lhs, const Float32Type& rhs,
                        const Float32Type& expected) {
    EXPECT_TRUE(
        expected.IsSubtypeOf(Float32Type::LeastUpperBound(lhs, rhs, zone())));
  };
  const auto kNaN = Float32Type::kNaN;

  {
    const auto lhs = Float32Type::Range(-32.19f, 94.07f, zone());
    CheckLubIs(lhs, lhs, lhs);
    CheckLubIs(lhs, Float32Type::Range(-32.19f, 94.07f, kNaN, zone()),
               Float32Type::Range(-32.19f, 94.07f, kNaN, zone()));
    CheckLubIs(lhs, Float32Type::NaN(),
               Float32Type::Range(-32.19f, 94.07f, kNaN, zone()));
    CheckLubIs(lhs, Float32Type::Constant(0.0f), lhs);
    CheckLubIs(lhs, Float32Type::Range(-19.9f, 31.29f, zone()), lhs);
    CheckLubIs(lhs, Float32Type::Range(-91.22f, -40.0f, zone()),
               Float32Type::Range(-91.22f, 94.07f, zone()));
    CheckLubIs(lhs, Float32Type::Range(0.0f, 1993.0f, zone()),
               Float32Type::Range(-32.19f, 1993.0f, zone()));
    CheckLubIs(lhs, Float32Type::Range(-100.0f, 100.0f, kNaN, zone()),
               Float32Type::Range(-100.0f, 100.0f, kNaN, zone()));
  }

  {
    const auto lhs = Float32Type::Constant(-0.04f);
    CheckLubIs(lhs, lhs, lhs);
    CheckLubIs(lhs, Float32Type::NaN(),
               Float32Type::Set({-0.04f}, kNaN, zone()));
    CheckLubIs(lhs, Float32Type::Constant(17.14f),
               Float32Type::Set({-0.04f, 17.14f}, zone()));
    CheckLubIs(lhs, Float32Type::Range(-75.4f, -12.7f, zone()),
               Float32Type::Range(-75.4f, -0.04f, zone()));
    CheckLubIs(lhs, Float32Type::Set({0.04f}, kNaN, zone()),
               Float32Type::Set({-0.04f, 0.04f}, kNaN, zone()));
  }
}

TEST_F(TurboshaftTypesTest, Float64LeastUpperBound) {
  auto CheckLubIs = [&](const Float64Type& lhs, const Float64Type& rhs,
                        const Float64Type& expected) {
    EXPECT_TRUE(
        expected.IsSubtypeOf(Float64Type::LeastUpperBound(lhs, rhs, zone())));
  };
  const auto kNaN = Float64Type::kNaN;

  {
    const auto lhs = Float64Type::Range(-32.19, 94.07, zone());
    CheckLubIs(lhs, lhs, lhs);
    CheckLubIs(lhs, Float64Type::Range(-32.19, 94.07, kNaN, zone()),
               Float64Type::Range(-32.19, 94.07, kNaN, zone()));
    CheckLubIs(lhs, Float64Type::NaN(),
               Float64Type::Range(-32.19, 94.07, kNaN, zone()));
    CheckLubIs(lhs, Float64Type::Constant(0.0), lhs);
    CheckLubIs(lhs, Float64Type::Range(-19.9, 31.29, zone()), lhs);
    CheckLubIs(lhs, Float64Type::Range(-91.22, -40.0, zone()),
               Float64Type::Range(-91.22, 94.07, zone()));
    CheckLubIs(lhs, Float64Type::Range(0.0, 1993.0, zone()),
               Float64Type::Range(-32.19, 1993.0, zone()));
    CheckLubIs(lhs, Float64Type::Range(-100.0, 100.0, kNaN, zone()),
               Float64Type::Range(-100.0, 100.0, kNaN, zone()));
  }

  {
    const auto lhs = Float64Type::Constant(-0.04);
    CheckLubIs(lhs, lhs, lhs);
    CheckLubIs(lhs, Float64Type::NaN(),
               Float64Type::Set({-0.04}, kNaN, zone()));
    CheckLubIs(lhs, Float64Type::Constant(17.14),
               Float64Type::Set({-0.04, 17.14}, zone()));
    CheckLubIs(lhs, Float64Type::Range(-75.4, -12.7, zone()),
               Float64Type::Range(-75.4, -0.04, zone()));
    CheckLubIs(lhs, Float64Type::Set({0.04}, kNaN, zone()),
               Float64Type::Set({-0.04, 0.04}, kNaN, zone()));
  }
}

}  // namespace v8::internal::compiler::turboshaft

"""

```