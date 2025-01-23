Response:
Let's break down the thought process for analyzing the given C++ code.

**1. Understanding the Request:**

The core request is to understand the functionality of the provided C++ unit test file (`turboshaft-types-unittest.cc`). The prompt also includes specific instructions about how to interpret the file (Torque vs. C++) and how to relate it to JavaScript if applicable.

**2. Initial Analysis - File Extension and Content:**

* **File Extension:** The file ends in `.cc`. The prompt explicitly states that if it ended in `.tq`, it would be a Torque file. Therefore, this is a standard C++ file.
* **Includes:**  The `#include` directives give crucial hints:
    * `"src/compiler/turboshaft/types.h"`: This strongly suggests the file is testing the `Type` system within the Turboshaft compiler component of V8.
    * `"src/handles/handles.h"`:  Indicates interaction with V8's object management system (handles).
    * `"test/unittests/test-utils.h"`:  Confirms this is a unit test file, likely using V8's testing framework.
    * `"testing/gtest/include/gtest/gtest.h"`:  Explicitly shows the use of the Google Test framework.
* **Namespace:** `namespace v8::internal::compiler::turboshaft`: Reinforces that this code is part of V8's Turboshaft compiler.
* **Test Fixture:** The `TurboshaftTypesTest` class inherits from `TestWithNativeContextAndZone`. This is a common pattern in V8 unit tests, providing a controlled environment with a native context and memory zone.

**3. Analyzing Individual Test Cases (TEST_F macros):**

The `TEST_F` macro indicates individual test cases within the `TurboshaftTypesTest` fixture. The test case names are very descriptive:

* `Word32`:  Likely testing the `Word32Type` class.
* `Word64`:  Likely testing the `Word64Type` class.
* `Float32`: Likely testing the `Float32Type` class.
* `Float64`: Likely testing the `Float64Type` class.
* `Word32LeastUpperBound`: Likely testing the `LeastUpperBound` function for `Word32Type`.

**4. Deeper Dive into a Test Case (e.g., `Word32`):**

* **Constants:**  `const auto max_value = ...`:  Shows the test is dealing with the maximum value of a 32-bit word.
* **Sections (Comments):** The comments like "// Complete range", "// Range (non-wrapping)", "// Range (wrapping)", "// Set" clearly divide the tests into different scenarios for `Word32Type`.
* **Assertions (EXPECT_TRUE, EXPECT_FALSE):** These are the core of the unit tests. They check if certain conditions are met. The pattern `Word32Type::X(...).IsSubtypeOf(t)` is prominent, indicating the tests are verifying the subtype relationship between different `Word32Type` instances.
* **Different `Word32Type` Constructors:** The tests use constructors like `Word32Type::Any()`, `Word32Type::Constant(...)`, `Word32Type::Range(...)`, and `Word32Type::Set(...)`, revealing the different ways `Word32Type` can represent a set of 32-bit words.
* **Wrapping Ranges:** The "Range (wrapping)" section highlights a specific behavior where the range wraps around the maximum value.

**5. Identifying Common Patterns and Functionality:**

* **Testing Subtype Relationships:** The primary focus of the code is to verify the `IsSubtypeOf` method for different numeric types (`Word32`, `Word64`, `Float32`, `Float64`).
* **Testing Different Representations of Types:** The tests cover various ways to represent numeric types:
    * `Any`: Represents the entire range.
    * `Constant`: Represents a single specific value.
    * `Range`: Represents a continuous range of values (with and without wrapping).
    * `Set`: Represents a discrete set of values.
* **Testing Edge Cases:** The tests include checks for maximum values, wrapping ranges, NaN (Not a Number), and negative zero.

**6. Addressing the Specific Instructions in the Prompt:**

* **Functionality:** The code tests the subtype relationships of different numeric types in the Turboshaft compiler.
* **Torque:**  The code is C++, not Torque.
* **JavaScript Relation:**  While this C++ code isn't directly JavaScript, it's testing the *underlying type system* that V8 uses when optimizing JavaScript code. For instance, V8 might infer a variable is always a 32-bit integer based on its usage. The tests here ensure that the type system correctly handles different integer ranges and operations. A JavaScript example demonstrating implicit typing would be helpful.
* **Code Logic Inference (Subtyping):**  The tests implicitly demonstrate logical inference. For example, if a type `A` represents the range [100, 300] and type `B` represents the value 150, then `B` is a subtype of `A`. The tests verify these kinds of relationships.
* **Common Programming Errors:** The tests relate to potential errors where the compiler might make incorrect assumptions about the range of values a variable can hold. A JavaScript example of assigning a value outside the expected range or mixing integer and floating-point types could be used.
* **Summary:** The overall function is to rigorously test the correctness of the numeric type system in Turboshaft.

**7. Structuring the Output:**

Organize the findings logically, addressing each point in the prompt. Use clear headings and examples to illustrate the concepts. Start with a high-level overview and then delve into specifics. Use formatting (like bolding and bullet points) to improve readability.

By following this systematic approach, we can thoroughly analyze the C++ code and provide a comprehensive and informative answer to the prompt. The key is to pay attention to the structure of the code, the naming conventions, and the assertions being made.
这是第1部分的分析。

**功能概括:**

`v8/test/unittests/compiler/turboshaft/turboshaft-types-unittest.cc` 这个 C++ 文件是 V8 JavaScript 引擎中 Turboshaft 编译器的类型系统（`turboshaft::Type`）的单元测试。它主要用于验证 `turboshaft::Type` 及其子类（例如 `Word32Type`, `Word64Type`, `Float32Type`, `Float64Type`）的各种功能，特别是关于类型之间的子类型关系判断 (`IsSubtypeOf`)。

**详细功能拆解:**

1. **类型表示测试:**  测试了不同数值类型的表示方式，包括：
   - **完整范围 (Any):**  测试了表示该类型所有可能值的类型。
   - **常量 (Constant):** 测试了表示单个特定值的类型。
   - **范围 (Range):** 测试了表示一个连续数值范围的类型，包括普通范围和回绕范围（例如，`max_value - 20` 到 `20`）。
   - **集合 (Set):** 测试了表示一组离散数值的类型。

2. **子类型关系测试 (IsSubtypeOf):**  这是该文件的核心功能。它通过大量的断言 (`EXPECT_TRUE`, `EXPECT_FALSE`) 来验证不同类型实例之间的子类型关系是否正确。 例如：
   - 一个常量类型是否是完整范围类型的子类型。
   - 一个较小范围的类型是否是较大范围类型的子类型。
   - 一个集合类型是否是包含它的更大集合类型的子类型。

3. **具体数值类型测试:**  针对以下数值类型进行了详细的测试：
   - `Word32Type`: 32位无符号整数类型。
   - `Word64Type`: 64位无符号整数类型。
   - `Float32Type`: 32位浮点数类型，特别关注了 NaN (Not a Number) 和负零 (-0.0f) 的处理。
   - `Float64Type`: 64位浮点数类型，同样关注了 NaN 和负零的处理。

4. **边界情况测试:**  测试了各种边界情况，例如：
   - 最大值 (`std::numeric_limits<...>::max()`)
   - 回绕范围
   - 空集合（虽然代码中没有直接创建空集合，但逻辑上考虑了集合为空的情况）
   - 浮点数的特殊值 (NaN, -0.0f)

5. **LeastUpperBound 测试 (在后续部分):**  从测试名称 `Word32LeastUpperBound` 可以推断，后续部分会测试计算两个类型最小上界的功能。

**关于文件类型:**

`v8/test/unittests/compiler/turboshaft/turboshaft-types-unittest.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件。

**与 Javascript 的关系 (举例说明):**

虽然这个文件是 C++ 代码，但它测试的类型系统直接关系到 V8 如何在底层表示和优化 JavaScript 的类型。 JavaScript 是一种动态类型语言，但 V8 在编译优化时会尝试推断变量的类型，以便进行更高效的操作。

例如，在 JavaScript 中：

```javascript
function add(a, b) {
  return a + b;
}

add(10, 20); // V8 可能会推断 a 和 b 是小整数
add(2**31 - 1, 1); // V8 需要处理更大的整数
add(1.5, 2.5); // V8 需要处理浮点数
```

Turboshaft 编译器的类型系统需要能够表示和区分这些不同的 JavaScript 值类型（例如，小整数、大整数、浮点数）。 `turboshaft-types-unittest.cc` 中的测试确保了类型系统能够正确地判断例如 "表示数值 10 的类型" 是 "表示所有 32 位整数的类型" 的子类型。

**代码逻辑推理 (假设输入与输出):**

假设我们有以下测试用例：

```c++
TEST_F(TurboshaftTypesTest, Word32Subtype) {
  Word32Type t1 = Word32Type::Range(10, 20, zone());
  Word32Type t2 = Word32Type::Constant(15);
  Word32Type t3 = Word32Type::Range(5, 25, zone());

  EXPECT_TRUE(t2.IsSubtypeOf(t1)); // 输入：t2 (Constant(15)), t1 (Range(10, 20))，输出：true
  EXPECT_FALSE(t1.IsSubtypeOf(t2)); // 输入：t1 (Range(10, 20)), t2 (Constant(15))，输出：false
  EXPECT_TRUE(t1.IsSubtypeOf(t3)); // 输入：t1 (Range(10, 20)), t3 (Range(5, 25))，输出：true
  EXPECT_FALSE(t3.IsSubtypeOf(t1)); // 输入：t3 (Range(5, 25)), t1 (Range(10, 20))，输出：false
}
```

在这个例子中，`IsSubtypeOf` 方法根据类型的表示范围进行逻辑推理。一个更具体的类型（例如，一个常量）是更一般类型（例如，包含该常量的范围）的子类型。

**用户常见的编程错误 (举例说明):**

虽然这个文件是测试代码，但它反映了在编写编译器或进行类型分析时可能出现的错误。 与用户常见的编程错误的联系可能比较间接，但可以从类型系统的角度来理解：

例如，如果类型系统不正确地判断子类型关系，可能会导致：

```javascript
function processNumber(num) {
  // 假设类型系统错误地认为 num 始终是小于 10 的整数
  if (num < 10) {
    // 执行优化后的代码
    console.log("Small number:", num);
  } else {
    // 执行更通用的代码
    console.log("Large number:", num);
  }
}

processNumber(15); // 如果类型系统判断错误，可能会执行错误的 if 分支
```

这里的错误是类型系统（在编译器内部）对变量 `num` 的类型推断不准确，导致基于该推断的优化或代码生成出现问题。 `turboshaft-types-unittest.cc` 这样的测试可以帮助避免这类编译器内部的错误，从而保证 JavaScript 代码的正确执行。

**总结 (第 1 部分功能):**

`v8/test/unittests/compiler/turboshaft/turboshaft-types-unittest.cc` 的第 1 部分主要功能是 **测试 Turboshaft 编译器中数值类型的表示和子类型关系判断的正确性**。它覆盖了整数和浮点数的各种表示形式（常量、范围、集合）以及特殊值（NaN，负零），并使用大量的单元测试用例来确保 `IsSubtypeOf` 方法的逻辑正确。 这对于保证 V8 能够正确地理解和优化 JavaScript 代码中的数值类型至关重要。

### 提示词
```
这是目录为v8/test/unittests/compiler/turboshaft/turboshaft-types-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/turboshaft/turboshaft-types-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
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
    CheckLubIs(lhs, Word32Type::Ran
```