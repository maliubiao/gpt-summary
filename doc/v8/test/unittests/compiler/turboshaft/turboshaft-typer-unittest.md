Response:
Let's break down the thought process for analyzing this C++ unittest file.

**1. Initial Scan and High-Level Understanding:**

The first thing I do is quickly scan the code for keywords and structural elements. I see:

* `#include`:  Indicates C++ code.
* `namespace v8::internal::compiler::turboshaft`:  Clearly part of the V8 JavaScript engine, specifically within the Turboshaft compiler.
* `template`: Suggests generic programming and working with different data types.
* `class ... : public TestWithNativeContextAndZone`:  This is a strong indicator of a unit test using a testing framework (likely Google Test, based on the `EXPECT_LE`). The "NativeContextAndZone" part hints at testing within the V8 environment.
* `WordTyperTest`, `FloatTyperTest`:  Names suggest testing related to type handling for word (integer-like) and floating-point values.
* `Add`, `WidenExponential`, `Divide`:  These are the names of specific test cases.
* `EXPECT_LE`:  Likely an assertion macro meaning "expect the left-hand side to be less than or equal to the right-hand side." In this context, it probably signifies "is a subtype of" in the type system.
* `Type`, `Word32Type`, `Word64Type`, `Float32Type`, `Float64Type`:  These are likely classes representing different types within the Turboshaft compiler.
* `Constant`, `Set`, `Range`: These look like helper functions for creating specific types.
* `WordOperationTyper`, `FloatOperationTyper`: Classes likely responsible for performing type operations (like addition and division) and inferring the resulting type.
* `std::numeric_limits`: Used to get maximum values for data types.
* Comments like "// Adding any." and "// Adding constants.":  These comments provide valuable context for the test cases.

From this initial scan, I can form a hypothesis: This code tests the type inference logic within the Turboshaft compiler for arithmetic operations on word and floating-point types. It checks how the typer handles different combinations of constants, sets of values, and ranges of values.

**2. Deeper Dive into Specific Sections:**

Next, I'd examine the structure of the test cases themselves. I see a consistent pattern:

* **Helper Macros:**  `DEFINE_TEST_HELPERS()` simplifies the code by defining type aliases and helper functions.
* **Test Case Structure:**  Each test case (e.g., `TYPED_TEST(WordTyperTest, Add)`) focuses on a specific operation (e.g., addition).
* **Assertion Macros:**  `EXPECT_ADD` and `EXPECT_DIV` are custom macros that wrap the `WordOperationTyper::Add` and `FloatOperationTyper::Divide` calls and the `EXPECT_LE` assertion. This makes the tests more readable.
* **Test Scenarios:** Within each test case, there are logical groupings of tests based on the types of operands being combined (e.g., "Adding any," "Adding constants," "Adding sets," "Adding ranges").

**3. Understanding the `EXPECT_LE` Semantics:**

The key to understanding the test's purpose is realizing that `EXPECT_LE(a, b)` in this context likely means "the type `a` is a subtype of the type `b`."  This is reinforced by the comment `// We define operator<= here for Type so that we can use gtest's EXPECT_LE to // check for subtyping...`. So, the tests are verifying that the type inferred by `WordOperationTyper::Add` or `FloatOperationTyper::Divide` is a valid supertype of the expected result.

**4. Code Logic Inference (Example: `WordTyperTest, Add`):**

Let's look at a specific example within `WordTyperTest, Add`:

```c++
EXPECT_ADD(Constant(8), Constant(10003), Constant(8 + 10003));
```

This test checks if adding two constants (8 and 10003) results in a type that is a supertype of the constant 10011. Since the typer should be able to precisely determine the result of adding two constants, the inferred type should ideally *be* the constant 10011 itself.

Another example:

```c++
EXPECT_ADD(Range(30, 990), Range(0, 2), Range(30, 992));
```

This tests adding two ranges. The expected result is a range from 30 to 992. The typer should infer a type that encompasses all possible sums of values within the input ranges.

**5. Considering JavaScript Relevance:**

The tests relate to JavaScript because V8 is the JavaScript engine. The Turboshaft compiler is a part of V8 that optimizes JavaScript code. The type system being tested here is used to reason about the values of JavaScript variables during compilation, enabling optimizations.

For example, in JavaScript:

```javascript
let x = 5;
let y = 10;
let z = x + y;
```

The Turboshaft compiler might use a type system similar to the one being tested to infer that `x` and `y` are likely numbers within a certain range, and therefore `z` will also be a number within a calculated range. This allows the compiler to generate more efficient machine code.

**6. Identifying Potential Programming Errors:**

While this code itself is a test, it highlights potential errors in compiler design:

* **Incorrect Type Inference:** If the `EXPECT_LE` assertions fail, it means the typer is inferring an incorrect type. It might be too narrow (missing possible values) or too broad (including impossible values), leading to missed optimization opportunities or even incorrect code generation in more complex scenarios.
* **Handling of Edge Cases:** The tests cover edge cases like adding maximum values (overflow), adding zero, and dividing by zero. Failing to handle these correctly in the typer can lead to unexpected behavior.
* **Loss of Precision:** In the floating-point tests, incorrect type inference during division could lead to a loss of precision or incorrect handling of special values like NaN and infinity.

**7. Addressing the ".tq" Question:**

The prompt asks what it would mean if the file ended in `.tq`. My knowledge base tells me that `.tq` files are related to Torque, V8's domain-specific language for implementing built-in functions. Therefore, if the file was named with `.tq`, it would contain Torque code, not C++ unit tests.

**8. Structuring the Answer:**

Finally, I organize my findings into a clear and structured answer, addressing each point in the prompt:

* Functionality: Describe the main purpose of the tests (type inference for Turboshaft).
* .tq Extension: Explain that it would be Torque code.
* JavaScript Relevance: Provide a JavaScript example showing how type inference is relevant.
* Code Logic Inference:  Give concrete examples of the assumptions and expected outputs.
* Common Programming Errors:  Illustrate potential errors in compiler design related to type inference.

This systematic approach allows for a comprehensive and accurate understanding of the given C++ code.
This C++ source code file, `turboshaft-typer-unittest.cc`, is a **unit test file** for the **Turboshaft typer** component of the V8 JavaScript engine's compiler. Here's a breakdown of its functionalities:

**Core Functionality:**

* **Testing Type Inference:** The primary goal is to test the correctness and accuracy of the `Typer` component in Turboshaft. The typer is responsible for inferring and representing the possible types of values during the compilation process. This is crucial for optimization, as knowing the possible types of variables and expressions allows the compiler to generate more efficient machine code.
* **Testing Arithmetic Operations on Word Types:**  It includes tests specifically for arithmetic operations (like addition) on word types (integers). It tests scenarios involving:
    * **Constants:** Adding specific constant values.
    * **Sets:** Adding sets of discrete values.
    * **Ranges:** Adding ranges of values (potentially wrapping around the maximum value).
    * **Combinations:** Testing the interaction between constants, sets, and ranges.
* **Testing Widen Exponential Operation:**  It tests a `WidenExponential` function, which likely aims to generalize or widen a type based on two input types. This is likely used when the exact type is not known, and the typer needs to find a common supertype.
* **Testing Arithmetic Operations on Float Types:** It includes tests for arithmetic operations (like division) on floating-point types. This involves handling special floating-point values like NaN (Not a Number), positive zero, and negative zero.
* **Using Google Test Framework:** The code utilizes the Google Test framework (`TEST_SUITE`, `TYPED_TEST`, `EXPECT_LE`) for structuring and executing the unit tests. `EXPECT_LE(a, b)` in this context likely checks if type `a` is a subtype of type `b`.
* **Parametrized Testing:** The use of `TYPED_TEST_SUITE` and `::testing::Types` indicates that these tests are parametrized. This means the same test logic is executed for different word types (like `Word32Type`, `Word64Type`) and float types (`Float32Type`, `Float64Type`).

**If `v8/test/unittests/compiler/turboshaft/turboshaft-typer-unittest.cc` ended with `.tq`:**

If the file ended with `.tq`, it would be a **V8 Torque source code file**. Torque is V8's domain-specific language for implementing built-in functions and compiler intrinsics. Torque code is different from C++ and has a more high-level, type-oriented syntax. This file being `.cc` confirms it's a C++ unit test.

**Relationship to JavaScript and Examples:**

The functionality of this test file is directly related to how V8 optimizes JavaScript code. The Turboshaft compiler needs to understand the types of JavaScript values to make informed decisions during optimization.

**JavaScript Example:**

```javascript
function add(a, b) {
  return a + b;
}

let result1 = add(5, 10); // V8's Turboshaft typer tries to infer that a and b are likely numbers.
let result2 = add("hello", " world"); // The typer would infer that a and b are likely strings.
let result3 = add(5, " world"); // The typer needs to handle mixed types and potential type coercion.
```

The `turboshaft-typer-unittest.cc` tests the underlying mechanisms that allow V8 to reason about these types. For instance, the `WordTyperTest` might be testing how Turboshaft handles the addition of integers when it knows the inputs are likely numeric.

**Code Logic Inference (Example: `TYPED_TEST(WordTyperTest, Add)`):**

Let's consider a specific part of the `Add` test:

```c++
EXPECT_ADD(Constant(8), Constant(10003), Constant(8 + 10003));
```

* **Assumption (Input):** The typer is given two constant word values: 8 and 10003.
* **Expected Output (Resulting Type):** The typer should infer a type that represents the constant value 10011. The `EXPECT_LE` macro likely checks if the inferred type is a subtype of the `Constant(10011)` type.

Another example:

```c++
EXPECT_ADD(Range(30, 990), Range(0, 2), Range(30, 992));
```

* **Assumption (Input):** The typer is given two ranges of word values: [30, 990] and [0, 2].
* **Expected Output (Resulting Type):** The typer should infer a type representing the range [30, 992], as the minimum possible sum is 30 + 0 = 30, and the maximum is 990 + 2 = 992.

**User-Common Programming Errors (Relating to Type Inference):**

While this is a *compiler* test, it relates to how V8 handles dynamic typing in JavaScript and how users might introduce errors that the compiler needs to reason about:

* **Incorrect Assumptions about Types:**
   ```javascript
   function multiply(a, b) {
     return a * b;
   }

   let result = multiply("5", 10); // JavaScript will coerce "5" to a number, but the intent might be different.
   ```
   The Turboshaft typer needs to handle these dynamic coercions. If the user *intended* `a` to be a number, but it's a string, the typer's ability to track these potential type variations is crucial for optimization and correctness.

* **Mixing Types Unintentionally:**
   ```javascript
   function process(input) {
     if (typeof input === 'number') {
       return input + 5;
     } else {
       return input.toUpperCase(); // Potential error if input is not a string.
     }
   }

   let value = 10;
   let result1 = process(value); // Works fine

   value = null;
   // let result2 = process(value); // This would cause an error at runtime.
   ```
   The typer needs to be able to reason about the different possible types of `input` based on the code flow (the `if` statement). The tests in `turboshaft-typer-unittest.cc` help ensure the typer can handle these conditional type changes accurately.

* **Relying on Implicit Conversions:** JavaScript's implicit type conversions can sometimes lead to unexpected results. The typer needs to model these conversions correctly. For example:
   ```javascript
   let sum = 1 + "1"; // sum will be the string "11" due to implicit conversion.
   ```
   The tests for operations like addition in the `WordTyperTest` and potentially string-related tests (though not present in this specific file) ensure that the typer correctly understands how these implicit conversions affect types.

In summary, `turboshaft-typer-unittest.cc` plays a vital role in ensuring the robustness and accuracy of V8's Turboshaft compiler by rigorously testing its type inference capabilities for various arithmetic operations and type combinations. This directly impacts the performance and correctness of JavaScript code execution in V8.

### 提示词
```
这是目录为v8/test/unittests/compiler/turboshaft/turboshaft-typer-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/turboshaft/turboshaft-typer-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits>

#include "src/common/globals.h"
#include "src/compiler/turboshaft/typer.h"
#include "src/handles/handles.h"
#include "test/unittests/test-utils.h"

namespace v8::internal::compiler::turboshaft {

template <typename T>
class WordTyperTest : public TestWithNativeContextAndZone {
 public:
  using word_t = typename T::word_t;
  static constexpr size_t Bits = sizeof(word_t) * kBitsPerByte;

  WordTyperTest() : TestWithNativeContextAndZone() {}
};

template <typename T>
class FloatTyperTest : public TestWithNativeContextAndZone {
 public:
  using float_t = typename T::float_t;
  static constexpr size_t Bits = sizeof(float_t) * kBitsPerByte;

  FloatTyperTest() : TestWithNativeContextAndZone() {}
};

template <typename T>
struct Slices {
  Slices(std::initializer_list<T> slices) : slices(slices) {}

  std::vector<T> slices;
};
template <typename T>
inline std::ostream& operator<<(std::ostream& os, const Slices<T>& slices) {
  os << "Slices{";
  for (const auto& s : slices.slices) os << s << ", ";
  return os << "}";
}

// We define operator<= here for Type so that we can use gtest's EXPECT_LE to
// check for subtyping and have the default printing.
inline bool operator<=(const Type& lhs, const Type& rhs) {
  return lhs.IsSubtypeOf(rhs);
}
template <typename T>
inline bool operator<=(const Slices<T>& lhs, const T& rhs) {
  for (const auto& s : lhs.slices) {
    if (!s.IsSubtypeOf(rhs)) return false;
  }
  return true;
}

using WordTypes = ::testing::Types<Word32Type, Word64Type>;
TYPED_TEST_SUITE(WordTyperTest, WordTypes);

#define DEFINE_TEST_HELPERS()                                                 \
  using T = TypeParam;                                                        \
  using word_t = typename TestFixture::word_t;                                \
  using Slices = Slices<T>;                                                   \
  constexpr word_t max = std::numeric_limits<word_t>::max();                  \
  auto Constant = [&](word_t value) { return T::Constant(value); };           \
  auto Set = [&](std::initializer_list<word_t> elements) {                    \
    return WordOperationTyper<TestFixture::Bits>::FromElements(elements,      \
                                                               this->zone()); \
  };                                                                          \
  auto Range = [&](word_t from, word_t to) {                                  \
    return T::Range(from, to, this->zone());                                  \
  };                                                                          \
  USE(Slices{}, Constant, Set, Range);

TYPED_TEST(WordTyperTest, Add) {
  DEFINE_TEST_HELPERS()
#define EXPECT_ADD(lhs, rhs, result)                                           \
  EXPECT_LE(result, WordOperationTyper<TestFixture::Bits>::Add(lhs, rhs,       \
                                                               this->zone())); \
  EXPECT_LE(result, WordOperationTyper<TestFixture::Bits>::Add(rhs, lhs,       \
                                                               this->zone()))

  // Adding any.
  {
    // Any + Any
    EXPECT_ADD(T::Any(), T::Any(), T::Any());
    // c + Any
    EXPECT_ADD(Constant(42), T::Any(), T::Any());
    // {x1, ..., xn} + Any
    EXPECT_ADD(Set({8, 11, 922}), T::Any(), T::Any());
    // [a, b] + Any
    EXPECT_ADD(Range(800, 1020), T::Any(), T::Any());
  }

  // Adding constants.
  {
    // c' + c
    EXPECT_ADD(Constant(8), Constant(10003), Constant(8 + 10003));
    EXPECT_ADD(Constant(max), Constant(0), Constant(max));
    EXPECT_ADD(Constant(max - 8), Constant(12), Constant(3));
    EXPECT_ADD(Constant(max), Constant(max), Constant(max - 1));
    // {x1, ..., xn} + c
    auto set1 = Set({0, 87});
    EXPECT_ADD(set1, Constant(0), set1);
    EXPECT_ADD(set1, Constant(2005), Set({2005, 2092}));
    EXPECT_ADD(set1, Constant(max - 4), Set({82, max - 4}));
    EXPECT_ADD(set1, Constant(max), Set({86, max}));
    auto set2 = Set({15, 25025, max - 99});
    EXPECT_ADD(set2, Constant(0), set2);
    EXPECT_ADD(set2, Constant(4), Set({19, 25029, max - 95}));
    EXPECT_ADD(set2, Constant(max - 50), Set({24974, max - 150, max - 35}));
    EXPECT_ADD(set2, Constant(max), Set({14, 25024, max - 100}));
    // [a, b](non-wrapping) + c
    auto range1 = Range(13, 288);
    EXPECT_ADD(range1, Constant(0), range1);
    EXPECT_ADD(range1, Constant(812), Range(825, 1100));
    EXPECT_ADD(range1, Constant(max - 103), Range(max - 90, 184));
    EXPECT_ADD(range1, Constant(max - 5), Range(7, 282));
    EXPECT_ADD(range1, Constant(max), Range(12, 287));
    // [a, b](wrapping) + c
    auto range2 = Range(max - 100, 70);
    EXPECT_ADD(range2, Constant(0), range2);
    EXPECT_ADD(range2, Constant(14), Range(max - 86, 84));
    EXPECT_ADD(range2, Constant(101), Range(0, 171));
    EXPECT_ADD(range2, Constant(200), Range(99, 270));
    EXPECT_ADD(range2, Constant(max), Range(max - 101, 69));
  }

  // Adding sets.
  {
    // {y1, ..., ym} + {x1, ..., xn}
    auto set1 = Set({0, 87});
    EXPECT_ADD(set1, set1, Set({0, 87, (87 + 87)}));
    EXPECT_ADD(set1, Set({3, 4, 5}), Set({3, 4, 5, 90, 91}));
    EXPECT_ADD(set1, Set({3, 7, 11, 114}),
               Set({3, 7, 11, 90, 94, 98, 114, 201}));
    EXPECT_ADD(set1, Set({0, 1, 87, 200, max}),
               Set({0, 1, 86, 87, 88, 174, 200, 287, max}));
    EXPECT_ADD(set1, Set({max - 86, max - 9, max}),
               Set({0, 77, 86, max - 86, max - 9, max}));
    // [a, b](non-wrapping) + {x1, ..., xn}
    auto range1 = Range(400, 991);
    EXPECT_ADD(range1, Set({0, 55}), Range(400, 1046));
    EXPECT_ADD(range1, Set({49, 110, 100009}), Range(449, 101000));
    EXPECT_ADD(
        range1, Set({112, max - 10094, max - 950}),
        Slices({Range(0, 40), Range(512, 1103), Range(max - 9694, max)}));
    EXPECT_ADD(range1, Set({112, max - 850}),
               Slices({Range(512, 1103), Range(max - 450, 140)}));
    EXPECT_ADD(range1, Set({max - 3, max - 1, max}), Range(396, 990));
    // [a,b](wrapping) + {x1, ..., xn}
    auto range2 = Range(max - 30, 82);
    EXPECT_ADD(range2, Set({0, 20}),
               Slices({Range(max - 30, 82), Range(max - 10, 102)}));
    EXPECT_ADD(range2, Set({20, 30, 32, max}),
               Slices({Range(max - 10, 101), Range(0, 112), Range(1, 114),
                       Range(max - 31, 81)}));
    EXPECT_ADD(range2, Set({1000, 2000}),
               Slices({Range(969, 1082), Range(1969, 2082)}));
    EXPECT_ADD(range2, Set({max - 8, max - 2}),
               Slices({Range(max - 39, 73), Range(max - 33, 79)}));
  }

  // Adding ranges.
  {
    // [a, b](non-wrapping) + [c, d](non-wrapping)
    auto range1 = Range(30, 990);
    EXPECT_ADD(range1, Range(0, 2), Range(30, 992));
    EXPECT_ADD(range1, Range(1000, 22000), Range(1030, 22990));
    EXPECT_ADD(range1, Range(0, max - 1000), Range(30, max - 10));
    EXPECT_ADD(range1, Range(max - 800, max - 700), Range(max - 770, 289));
    EXPECT_ADD(range1, Range(max - 5, max), Range(24, 989));
    // [a, b](wrapping) + [c, d](non-wrapping)
    auto range2 = Range(max - 40, 40);
    EXPECT_ADD(range2, Range(0, 8), Range(max - 40, 48));
    EXPECT_ADD(range2, Range(2000, 90000), Range(1959, 90040));
    EXPECT_ADD(range2, Range(max - 400, max - 200),
               Range(max - 441, max - 160));
    EXPECT_ADD(range2, Range(0, max - 82), Range(max - 40, max - 42));
    EXPECT_ADD(range2, Range(0, max - 81), T::Any());
    EXPECT_ADD(range2, Range(20, max - 20), T::Any());
    // [a, b](wrapping) + [c, d](wrapping)
    EXPECT_ADD(range2, range2, Range(max - 81, 80));
    EXPECT_ADD(range2, Range(max - 2, 2), Range(max - 43, 42));
    EXPECT_ADD(range2, Range(1000, 100), Range(959, 140));
  }

#undef EXPECT_ADD
}

TYPED_TEST(WordTyperTest, WidenExponential) {
  DEFINE_TEST_HELPERS()

  auto SizeOf = [&](const T& type) -> word_t {
    DCHECK(!type.is_any());
    if (type.is_set()) return type.set_size();
    if (type.is_wrapping()) {
      return type.range_to() + (max - type.range_from()) + word_t{2};
    }
    return type.range_to() - type.range_from() + word_t{1};
  };
  auto DoubledInSize = [&](const T& old_type, const T& new_type) {
    // If the `new_type` is any, we accept it.
    if (new_type.is_any()) return true;
    return SizeOf(old_type) <= 2 * SizeOf(new_type);
  };

#define EXPECT_WEXP(old_type, new_type)                                    \
  {                                                                        \
    const T ot = old_type;                                                 \
    const T nt = new_type;                                                 \
    auto result = WordOperationTyper<TestFixture::Bits>::WidenExponential( \
        ot, nt, this->zone());                                             \
    EXPECT_LE(ot, result);                                                 \
    EXPECT_LE(nt, result);                                                 \
    EXPECT_TRUE(DoubledInSize(ot, result));                                \
  }

  // c W set
  EXPECT_WEXP(Constant(0), Set({0, 1}));
  EXPECT_WEXP(Constant(0), Set({0, 3}));
  EXPECT_WEXP(Constant(0), Set({0, 1, max}));
  EXPECT_WEXP(Constant(0), Set({0, 1, 2, max - 2, max - 1, max}));
  EXPECT_WEXP(Constant(max), Set({0, 1, 2, max - 2, max}));
  // c W range
  EXPECT_WEXP(Constant(0), Range(0, 100));
  EXPECT_WEXP(Constant(100), Range(50, 100));
  EXPECT_WEXP(Constant(100), Range(50, 150));
  EXPECT_WEXP(Constant(0), Range(max - 10, 0));
  EXPECT_WEXP(Constant(0), Range(max - 10, 10));
  EXPECT_WEXP(Constant(50), Range(max - 10000, 100));
  EXPECT_WEXP(Constant(max), T::Any());
  // set W set
  EXPECT_WEXP(Set({0, 1}), Set({0, 1, 2}));
  EXPECT_WEXP(Set({0, 1}), Set({0, 1, 2, 3, 4}));
  EXPECT_WEXP(Set({0, max}), Set({0, 1, max}));
  EXPECT_WEXP(Set({8, max - 8}), Set({7, 8, max - 8, max - 7}));
  EXPECT_WEXP(Set({3, 5, 7, 11}), Set({2, 3, 5, 7, 11}));
  // set W range
  EXPECT_WEXP(Set({3, 5, 7, 11}), Range(3, 11));
  EXPECT_WEXP(Set({3, 5, 7, 11}), Range(0, 11));
  EXPECT_WEXP(Set({3, 5, 7, 11}), Range(3, 100));
  EXPECT_WEXP(Set({3, 5, 7, 11}), Range(max, 11));
  EXPECT_WEXP(Set({3, 5, 7, 11}), Range(max - 100, 100));
  EXPECT_WEXP(Set({3, 5, 7, 11}), T::Any());
  // range W range
  EXPECT_WEXP(Range(0, 20), Range(0, 21));
  EXPECT_WEXP(Range(0, 20), Range(0, 220));
  EXPECT_WEXP(Range(0, 20), Range(max, 20));
  EXPECT_WEXP(Range(0, 20), Range(max - 200, 20));
  EXPECT_WEXP(Range(0, 20), T::Any());
  EXPECT_WEXP(Range(max - 100, max - 80), Range(max - 101, max - 80));
  EXPECT_WEXP(Range(max - 100, max - 80), Range(max - 100, max - 79));
  EXPECT_WEXP(Range(max - 100, max - 80), Range(max - 101, max - 79));
  EXPECT_WEXP(Range(max - 100, max - 80), Range(max - 200, 20));
  EXPECT_WEXP(Range(max - 100, max - 80), T::Any());
  EXPECT_WEXP(Range(max - 20, 0), Range(max - 20, 1));
  EXPECT_WEXP(Range(max - 20, 20), Range(max - 20, 21));
  EXPECT_WEXP(Range(max - 20, 20), Range(max - 21, 20));
  EXPECT_WEXP(Range(max - 20, 20), Range(max - 21, 21));
  EXPECT_WEXP(Range(max - 20, 20), Range(max - 2000, 2000));
  EXPECT_WEXP(Range(max - 20, 20), T::Any());

#undef EXPECT_WEXP
}

#undef DEFINE_TEST_HELPERS

using FloatTypes = ::testing::Types<Float32Type, Float64Type>;
TYPED_TEST_SUITE(FloatTyperTest, FloatTypes);

#define DEFINE_TEST_HELPERS()                                               \
  using T = TypeParam;                                                      \
  using float_t = typename TestFixture::float_t;                            \
  using Slices = Slices<T>;                                                 \
  auto Constant = [&](float_t value) { return T::Constant(value); };        \
  auto Set = [&](std::initializer_list<float_t> elements,                   \
                 uint32_t special_values = 0) {                             \
    return T::Set(elements, special_values, this->zone());                  \
  };                                                                        \
  auto Range = [&](float_t from, float_t to, uint32_t special_values = 0) { \
    return T::Range(from, to, special_values, this->zone());                \
  };                                                                        \
  constexpr uint32_t kNaN = T::kNaN;                                        \
  constexpr uint32_t kMZ = T::kMinusZero;                                   \
  constexpr float_t nan = nan_v<TestFixture::Bits>;                         \
  constexpr float_t inf = std::numeric_limits<float_t>::infinity();         \
  USE(Slices{}, Constant, Set, Range);                                      \
  USE(kNaN, kMZ, nan, inf);

TYPED_TEST(FloatTyperTest, Divide) {
  DEFINE_TEST_HELPERS()
#define EXPECT_DIV(lhs, rhs, result)                                \
  EXPECT_LE(result, FloatOperationTyper<TestFixture::Bits>::Divide( \
                        lhs, rhs, this->zone()))

  // 0 / x
  EXPECT_DIV(Constant(0.0), T::Any(), Set({0}, kNaN | kMZ));
  EXPECT_DIV(T::MinusZero(), T::Any(), Set({0}, kNaN | kMZ));
  EXPECT_DIV(Constant(0.0), Range(0.001, inf), Constant(0));
  EXPECT_DIV(T::MinusZero(), Range(0.001, inf), T::MinusZero());
  EXPECT_DIV(Constant(0.0), Range(-inf, -0.001), T::MinusZero());
  EXPECT_DIV(T::MinusZero(), Range(-inf, -0.001), Constant(0));
  EXPECT_DIV(Set({0.0}, kMZ), Constant(3), Set({0}, kMZ));
  EXPECT_DIV(Set({0.0}), Set({-2.5, 0.0, 1.5}), Set({0.0}, kNaN | kMZ));
  EXPECT_DIV(Set({0.0}, kMZ), Set({-2.5, 0.0, 1.5}), Set({0.0}, kNaN | kMZ));
  EXPECT_DIV(Set({0.0}), Set({1.5}, kMZ), Set({0.0}, kNaN));
  EXPECT_DIV(Set({0.0}, kMZ), Set({1.5}, kMZ), Set({0.0}, kNaN | kMZ));

  // x / 0
  EXPECT_DIV(Constant(1.0), Constant(0), Constant(inf));
  EXPECT_DIV(Constant(1.0), T::MinusZero(), Constant(-inf));
  EXPECT_DIV(Constant(inf), Constant(0), Constant(inf));
  EXPECT_DIV(Constant(inf), T::MinusZero(), Constant(-inf));
  EXPECT_DIV(Constant(-1.0), Constant(0), Constant(-inf));
  EXPECT_DIV(Constant(-1.0), T::MinusZero(), Constant(inf));
  EXPECT_DIV(Constant(-inf), Constant(0), Constant(-inf));
  EXPECT_DIV(Constant(-inf), T::MinusZero(), Constant(inf));
  EXPECT_DIV(Constant(1.5), Set({0.0}, kMZ), Set({-inf, inf}));
  EXPECT_DIV(Constant(-1.5), Set({0.0}, kMZ), Set({-inf, inf}));
  EXPECT_DIV(Set({1.5}, kMZ), Set({0.0}, kMZ), Set({-inf, inf}, kNaN));
  EXPECT_DIV(Set({-1.5}, kMZ), Set({0.0}, kMZ), Set({-inf, inf}, kNaN));

  // 0 / 0
  EXPECT_DIV(Constant(0), Constant(0), T::NaN());
  EXPECT_DIV(Constant(0), T::MinusZero(), T::NaN());
  EXPECT_DIV(T::MinusZero(), Constant(0), T::NaN());
  EXPECT_DIV(T::MinusZero(), T::MinusZero(), T::NaN());
  EXPECT_DIV(Set({0}, kMZ), Set({1}, kMZ), Set({0}, kNaN | kMZ));

  // inf / inf
  EXPECT_DIV(Constant(inf), Constant(inf), T::NaN());
  EXPECT_DIV(Constant(inf), Constant(-inf), T::NaN());
  EXPECT_DIV(Constant(-inf), Constant(inf), T::NaN());
  EXPECT_DIV(Constant(-inf), Constant(-inf), T::NaN());
  EXPECT_DIV(Set({-inf, inf}), Constant(inf), T::NaN());
  EXPECT_DIV(Set({-inf, inf}), Constant(-inf), T::NaN());
  EXPECT_DIV(Set({-inf, inf}), Set({-inf, inf}), T::NaN());
}

#undef DEFINE_TEST_HELPERS

}  // namespace v8::internal::compiler::turboshaft
```