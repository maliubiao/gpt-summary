Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Understanding the Goal:**

The request is to analyze a C++ test file for the Chromium Blink engine related to animation interpolation of lists. The key is to understand what aspects of the code are being tested and how it relates to web technologies (JavaScript, HTML, CSS) and potential user/programmer errors.

**2. Initial Code Scan and Keyword Identification:**

I'd start by quickly skimming the code for important keywords and structures:

* `#include`:  This tells us about dependencies. Notice `gtest/gtest.h` (unit testing framework), and files within `blink/renderer/core/animation/`. This confirms it's a test file related to animation logic.
* `namespace blink`: This tells us the code is part of the Blink rendering engine.
* `TEST(...)`:  These are the core unit tests. I'd look at the names of these tests. Names like `EqualMergeSingles`, `EqualComposite`, `BuilderModify` are very informative. They suggest testing merging and compositing of lists with different compatibility rules and modifications using a builder pattern.
* `InterpolationValue`, `InterpolableList`, `NonInterpolableValue`, `NonInterpolableList`: These are key data structures related to animation interpolation. The "Interpolable" vs. "NonInterpolable" distinction is crucial.
* `ListInterpolationFunctions`: This is likely the class being tested.
* `CreateInterpolableList`, `CreateNonInterpolableList`: Helper functions for creating test data.
* `MaybeMergeSingles`, `Composite`:  Functions being tested, related to combining animation values.
* `UnderlyingValue`, `UnderlyingValueOwner`:  Concepts related to the current state of an animated property.
* `GetCSSPropertyZIndex()`: Indicates interaction with CSS properties.
* `AutoBuilder`:  Suggests a builder pattern for modifying lists.
* `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, `ASSERT_EQ`: These are gtest assertions, indicating what conditions the tests are verifying.

**3. Deciphering the Core Functionality (Based on Test Names and Code Structure):**

* **List Interpolation:** The file tests functions for interpolating lists of values. This means smoothly transitioning between two lists of potentially different types of values.
* **Interpolable vs. Non-Interpolable:**  The code distinguishes between values that can be smoothly interpolated (like numbers) and those that cannot (like discrete states). The tests explore how these different types interact within lists.
* **Merging:** Tests with "MergeSingles" in the name likely check how two lists are combined to produce a single interpolation. The "Equal" prefix suggests testing the case where lists have the same length.
* **Compositing:** Tests with "Composite" likely check how an animation value is applied to an existing "underlying" value. This is core to how animations progress over time.
* **Length Matching:** The `LengthMatchingStrategy` enum (even if not fully defined in the snippet) suggests different ways of handling lists of different lengths during interpolation.
* **Compatibility:** The `InterpolableValuesCompatibilityHelper` and the `NonInterpolableValuesAreCompatible` functions indicate testing scenarios where individual elements within lists might or might not be compatible for interpolation.
* **Builder Pattern:** The "BuilderModify" tests clearly demonstrate a builder pattern for modifying non-interpolable lists efficiently.

**4. Connecting to Web Technologies:**

Now, the crucial step is to link the C++ code to how it affects web developers:

* **CSS Animations and Transitions:**  The core functionality of interpolating lists directly relates to CSS animations and transitions involving properties that accept lists of values. Examples include `transform` (multiple transformations), `box-shadow` (multiple shadows), `background-image` (multiple images), and even custom properties that hold lists.
* **JavaScript Animation API (Web Animations API):**  The Web Animations API in JavaScript allows for programmatic control of animations. The underlying interpolation logic tested here is what the browser engine uses when you animate list-based CSS properties using this API.
* **HTML (Indirectly):** HTML elements are the target of these animations. The structure of the HTML determines which elements are being animated and what properties are being manipulated.

**5. Generating Examples and Scenarios:**

Based on the understanding of the code, I would construct concrete examples:

* **CSS Transform:** A good example of an interpolable list (multiple transform functions).
* **CSS Box-Shadow:**  Another example of an interpolable list (multiple shadow definitions).
* **Non-Interpolable Example:**  Think of a property where values can't be smoothly interpolated, like switching between different background images abruptly. This helps illustrate the "NonInterpolableValue" concept.
* **Builder Pattern Use Case:**  Imagine a scenario where a JavaScript animation dynamically updates a complex list-based CSS property. The builder pattern would be efficient for making incremental changes.

**6. Identifying Potential Errors:**

Thinking about how developers might misuse these features leads to error examples:

* **Length Mismatch:** Forgetting that animating between lists of different lengths might not work as expected (depending on the interpolation strategy).
* **Type Mismatch:**  Trying to animate between lists with incompatible types of values.
* **Forgetting to Update Underlying Values:**  If manually manipulating animation data, failing to properly update the underlying values can lead to inconsistencies.

**7. Structuring the Output:**

Finally, organize the information logically, covering the requested aspects: functionality, relationship to web technologies (with examples), logical reasoning (input/output), and common errors. Use clear and concise language, and provide specific code snippets where appropriate.

**Self-Correction/Refinement during the Process:**

* **Initial Over-Simplification:**  I might initially focus only on simple numerical lists. Then, realizing the "NonInterpolableValue" concept is important, I'd refine my understanding and examples to include cases where some elements can't be interpolated.
* **Connecting to Specific CSS Properties:**  Instead of just saying "list-based properties," I would try to name concrete CSS properties like `transform` and `box-shadow` to make the explanation more tangible.
* **Clarifying the Builder Pattern:**  Ensuring the explanation of the builder pattern highlights its efficiency in modifying lists without creating entirely new copies each time.

By following this structured approach, I can effectively analyze the C++ test file and provide a comprehensive answer that addresses all aspects of the request.
这个C++源代码文件 `list_interpolation_functions_test.cc` 是 Chromium Blink 引擎中的一个单元测试文件。它的主要功能是测试 `blink::ListInterpolationFunctions` 这个类中的各种用于处理列表类型插值的函数。

**核心功能：**

1. **测试列表的合并 (Merging):**  测试如何将两个列表型的 `InterpolationValue` 对象合并成一个 `PairwiseInterpolationValue` 对象，以便进行插值。这涉及到判断两个列表的长度是否匹配以及列表中各个元素的兼容性。

2. **测试列表的合成 (Compositing):** 测试在动画过程中，如何将一个新的 `InterpolationValue` 应用到一个已有的 `UnderlyingValue` 上。这涉及到根据一定的比例混合两个列表的值，并且也需要考虑列表长度和元素兼容性。

3. **测试 `NonInterpolableList::AutoBuilder`:** 测试一个用于高效修改 `NonInterpolableList` 的构建器类。这个构建器允许修改列表中的特定元素，而无需完全复制整个列表。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这个文件测试的 `ListInterpolationFunctions` 类是 Blink 引擎动画实现的核心部分，它直接影响到 CSS 动画和 JavaScript Web Animations API 的行为，特别是当动画属性的值是列表类型时。

* **CSS `transform` 属性:**
    * **功能关系:** CSS 的 `transform` 属性可以接受一个包含多个变换函数的列表，例如 `transform: translateX(10px) rotate(45deg) scale(2);`。`ListInterpolationFunctions` 用于处理这种变换列表在动画过程中的插值。
    * **举例:** 假设我们有一个 CSS 动画，从 `transform: translateX(0px) rotate(0deg);` 过渡到 `transform: translateX(100px) rotate(90deg);`。 `ListInterpolationFunctions::MaybeMergeSingles` 会被用来判断这两个变换列表是否可以合并进行插值（长度相同且元素类型兼容）。 `ListInterpolationFunctions::Composite` 会在动画的每一帧计算出中间状态的 `transform` 值，例如在动画进行到一半时，可能会得到类似 `transform: translateX(50px) rotate(45deg);` 的结果。

* **CSS `box-shadow` 属性:**
    * **功能关系:** CSS 的 `box-shadow` 属性可以定义多个阴影效果，例如 `box-shadow: 10px 10px 5px red, -5px -5px 3px blue;`。 `ListInterpolationFunctions` 负责处理这种多阴影列表的动画。
    * **举例:** 如果要动画地改变一个元素的阴影，从一个阴影变为两个阴影，或者改变现有阴影的属性，`ListInterpolationFunctions` 会参与计算中间帧的阴影效果。如果两个 `box-shadow` 值的阴影数量不同，`ListInterpolationFunctions` 会根据配置的策略来处理（例如，如果策略是严格相等，则可能无法进行平滑过渡）。

* **CSS Custom Properties (Variables) 存储列表:**
    * **功能关系:** CSS 自定义属性可以存储任何 CSS 值，包括看起来像列表的值（虽然 CSS 本身没有显式的列表类型）。如果 JavaScript 或 CSS 动画修改了存储列表的自定义属性，`ListInterpolationFunctions` 可能会被用来处理这些值的插值（如果这些值可以被解析为可以插值的类型）。
    * **举例:** 假设有一个自定义属性 `--my-list: 10px, 20px, 30px;`。如果一个 JavaScript 动画修改这个属性，从 `--my-list: 10px, 20px, 30px;` 变为 `--my-list: 40px, 50px, 60px;`，并且引擎能够识别这是一个可以插值的数值列表，那么 `ListInterpolationFunctions` 将负责计算中间值。

**逻辑推理与假设输入输出：**

**测试 `EqualMergeSinglesSameLengths`:**

* **假设输入:**
    * `list1`: 一个包含插值数值和非插值数值的列表，例如 `[{1.0, 1}, {2.0, 2}, {3.0, 3}]` (插值数值为 double，非插值数值为 int)。
    * `list2`: 另一个长度相同且对应位置非插值数值相同的列表，例如 `[{1.0, 1}, {2.0, 2}, {3.0, 3}]`。
* **预期输出:** `MaybeMergeSingles` 返回一个非空的 `PairwiseInterpolationValue`，表示这两个列表可以合并进行插值。

**测试 `EqualCompositeDifferentLengths`:**

* **假设输入:**
    * `owner` 的 `UnderlyingValue` 包含一个列表，例如 `[1.0, 2.0, 3.0]`。
    * 要合成的 `interpolable_value` 是另一个长度不同的列表，例如 `[4.0, 5.0]`。
* **预期输出:** 由于列表长度不同，根据 `LengthMatchingStrategy::kEqual` 策略，无法进行插值合成。`owner` 的 `UnderlyingValue` 将会被替换为新的 `interpolable_value` 的内容，即 `[4.0, 5.0]`。

**测试 `BuilderModifyFirst`:**

* **假设输入:**
    * `list`: 一个包含非插值数值的列表，例如 `[1, 2, 3]`。
    * 使用 `AutoBuilder` 修改索引 0 的元素为 4。
* **预期输出:**  构建器修改后的列表变为 `[4, 2, 3]`。

**用户或编程常见的使用错误：**

1. **尝试在长度不匹配的列表之间进行插值:**
   * **错误示例 (CSS):**
     ```css
     .element {
       transition: transform 1s;
       transform: translateX(10px) rotate(45deg); /* 两个变换函数 */
     }
     .element:hover {
       transform: translateX(100px); /* 一个变换函数 */
     }
     ```
   * **问题:** 当鼠标悬停时，浏览器可能无法平滑地从两个变换函数过渡到一个变换函数。具体行为取决于浏览器的实现，可能直接跳变或者只对匹配的变换函数进行插值。
   * **测试文件中的体现:** `EqualMergeSinglesDifferentLengths` 和 `EqualCompositeDifferentLengths` 这两个测试用例就模拟了这种情况，预期结果是不进行插值或者替换为新的值。

2. **尝试在非兼容类型的列表元素之间进行插值:**
   * **错误示例 (CSS):**
     ```css
     .element {
       transition: box-shadow 1s;
       box-shadow: 10px 10px 5px red;
     }
     .element:hover {
       box-shadow: inset 5px 5px 3px blue;
     }
     ```
   * **问题:**  `red` 是一个颜色值，而 `inset` 是一个关键字，它们的类型不同，无法直接插值。浏览器可能会直接切换，而不是平滑过渡。
   * **测试文件中的体现:**  虽然测试文件中没有直接模拟 CSS 颜色和关键字的插值，但 `EqualCompositeIncompatibleInterpolableValues` 和 `EqualCompositeIncompatibleNonInterpolableValues` 测试了列表中元素不兼容时的情况，预期结果是不进行平滑插值。

3. **在使用 `NonInterpolableList::AutoBuilder` 时索引越界:**
   * **错误示例 (C++ 模拟):**
     ```c++
     auto list = CreateNonInterpolableList({1, 2, 3});
     TestUnderlyingValue underlying_value(list);
     NonInterpolableList::AutoBuilder builder(underlying_value);
     builder.Set(3, TestNonInterpolableValue::Create(4)); // 索引越界
     ```
   * **问题:**  这将导致程序崩溃或未定义的行为。
   * **测试文件中的体现:**  虽然测试文件中没有显式地测试索引越界的情况（因为 DCHECK 会捕获），但测试用例覆盖了修改列表的不同位置，隐含地确保了构建器在有效索引范围内工作。

总而言之，`list_interpolation_functions_test.cc` 这个文件通过各种单元测试，确保了 Blink 引擎在处理列表类型动画时的正确性和鲁棒性，这对于实现平滑流畅的 Web 动画效果至关重要。理解这个文件的功能有助于开发者理解浏览器动画机制的底层实现，并避免在使用 CSS 动画或 Web Animations API 时犯一些常见的错误。

### 提示词
```
这是目录为blink/renderer/core/animation/list_interpolation_functions_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/animation/list_interpolation_functions.h"

#include <utility>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/animation/css_number_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/interpolation_value.h"
#include "third_party/blink/renderer/core/animation/underlying_value.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {

class TestNonInterpolableValue final : public NonInterpolableValue {
 public:
  ~TestNonInterpolableValue() override = default;

  static scoped_refptr<TestNonInterpolableValue> Create(int value) {
    DCHECK_GE(value, 1);
    return base::AdoptRef(new TestNonInterpolableValue(value));
  }

  int GetValue() const { return value_; }

  DECLARE_NON_INTERPOLABLE_VALUE_TYPE();

 private:
  explicit TestNonInterpolableValue(int value) : value_(value) {}

  int value_;
};

DEFINE_NON_INTERPOLABLE_VALUE_TYPE(TestNonInterpolableValue);

// DEFINE_NON_INTERPOLABLE_VALUE_TYPE_CASTS won't work in anonymous namespaces.
inline const TestNonInterpolableValue& ToTestNonInterpolableValue(
    const NonInterpolableValue& value) {
  DCHECK_EQ(value.GetType(), TestNonInterpolableValue::static_type_);
  return static_cast<const TestNonInterpolableValue&>(value);
}

class TestUnderlyingValue : public UnderlyingValue {
  STACK_ALLOCATED();

 public:
  TestUnderlyingValue(InterpolationValue& interpolation_value)
      : interpolation_value_(interpolation_value) {}

  InterpolableValue& MutableInterpolableValue() final {
    return *interpolation_value_.interpolable_value;
  }

  void SetInterpolableValue(InterpolableValue* interpolable_value) final {
    interpolation_value_.interpolable_value = std::move(interpolable_value);
  }

  const NonInterpolableValue* GetNonInterpolableValue() const final {
    return interpolation_value_.non_interpolable_value.get();
  }

  void SetNonInterpolableValue(
      scoped_refptr<const NonInterpolableValue> non_interpolable_value) final {
    interpolation_value_.non_interpolable_value = non_interpolable_value;
  }

 private:
  InterpolationValue& interpolation_value_;
};

// Creates an InterpolationValue containing a list of interpolable and
// non-interpolable values from the pairs of input.
InterpolationValue CreateInterpolableList(
    const Vector<std::pair<double, int>>& values) {
  return ListInterpolationFunctions::CreateList(
      values.size(), [&values](wtf_size_t i) {
        return InterpolationValue(
            MakeGarbageCollected<InterpolableNumber>(values[i].first),
            TestNonInterpolableValue::Create(values[i].second));
      });
}

// Creates an InterpolationValue which contains a list of interpolable values,
// but a non-interpolable list of nullptrs.
InterpolationValue CreateInterpolableList(const Vector<double>& values) {
  return ListInterpolationFunctions::CreateList(
      values.size(), [&values](wtf_size_t i) {
        return InterpolationValue(
            MakeGarbageCollected<InterpolableNumber>(values[i]), nullptr);
      });
}

// Creates an InterpolationValue which contains a list of non-interpolable
// values, but an interpolable list of zeroes.
InterpolationValue CreateNonInterpolableList(const Vector<int>& values) {
  return ListInterpolationFunctions::CreateList(
      values.size(), [&values](wtf_size_t i) {
        return InterpolationValue(MakeGarbageCollected<InterpolableNumber>(0),
                                  TestNonInterpolableValue::Create(values[i]));
      });
}

// A simple helper to specify which InterpolableValues in an InterpolableList
// should be considered compatible.
class InterpolableValuesCompatibilityHelper {
 public:
  // The input |answers| vector must be at least as large as the
  // InterpolableList being tested, or |AreCompatible| will DCHECK.
  InterpolableValuesCompatibilityHelper(Vector<bool> answers)
      : answers_(answers), current_index_(0) {}

  // Callers should pass a reference to this function to
  // ListInterpolationFunctions::Composite.
  bool AreCompatible(const InterpolableValue*, const InterpolableValue*) {
    DCHECK(current_index_ < answers_.size());
    return answers_.at(current_index_++);
  }

 private:
  Vector<bool> answers_;
  wtf_size_t current_index_;
};

bool NonInterpolableValuesAreCompatible(const NonInterpolableValue* a,
                                        const NonInterpolableValue* b) {
  return (a ? ToTestNonInterpolableValue(*a).GetValue() : 0) ==
         (b ? ToTestNonInterpolableValue(*b).GetValue() : 0);
}

PairwiseInterpolationValue MaybeMergeSingles(InterpolationValue&& start,
                                             InterpolationValue&& end) {
  if (!NonInterpolableValuesAreCompatible(start.non_interpolable_value.get(),
                                          end.non_interpolable_value.get())) {
    return nullptr;
  }
  return PairwiseInterpolationValue(std::move(start.interpolable_value),
                                    std::move(end.interpolable_value), nullptr);
}

void Composite(UnderlyingValue& underlying_value,
               double underlying_fraction,
               const InterpolableValue& interpolable_value,
               const NonInterpolableValue* non_interpolable_value) {
  DCHECK(NonInterpolableValuesAreCompatible(
      underlying_value.GetNonInterpolableValue(), non_interpolable_value));
  underlying_value.MutableInterpolableValue().ScaleAndAdd(underlying_fraction,
                                                          interpolable_value);
}

}  // namespace

TEST(ListInterpolationFunctionsTest, EqualMergeSinglesSameLengths) {
  test::TaskEnvironment task_environment;
  auto list1 = CreateInterpolableList({{1.0, 1}, {2.0, 2}, {3.0, 3}});
  auto list2 = CreateInterpolableList({{1.0, 1}, {2.0, 2}, {3.0, 3}});

  auto pairwise = ListInterpolationFunctions::MaybeMergeSingles(
      std::move(list1), std::move(list2),
      ListInterpolationFunctions::LengthMatchingStrategy::kEqual,
      MaybeMergeSingles);

  EXPECT_TRUE(pairwise);
}

TEST(ListInterpolationFunctionsTest, EqualMergeSinglesDifferentLengths) {
  test::TaskEnvironment task_environment;
  auto list1 = CreateInterpolableList({1.0, 2.0, 3.0});
  auto list2 = CreateInterpolableList({1.0, 3.0});

  auto pairwise = ListInterpolationFunctions::MaybeMergeSingles(
      std::move(list1), std::move(list2),
      ListInterpolationFunctions::LengthMatchingStrategy::kEqual,
      MaybeMergeSingles);

  EXPECT_FALSE(pairwise);
}

TEST(ListInterpolationFunctionsTest, EqualMergeSinglesIncompatibleValues) {
  test::TaskEnvironment task_environment;
  auto list1 = CreateInterpolableList({{1.0, 1}, {2.0, 2}, {3.0, 3}});
  auto list2 = CreateInterpolableList({{1.0, 1}, {2.0, 4}, {3.0, 3}});

  auto pairwise = ListInterpolationFunctions::MaybeMergeSingles(
      std::move(list1), std::move(list2),
      ListInterpolationFunctions::LengthMatchingStrategy::kEqual,
      MaybeMergeSingles);

  EXPECT_FALSE(pairwise);
}

TEST(ListInterpolationFunctionsTest, EqualMergeSinglesIncompatibleNullptrs) {
  test::TaskEnvironment task_environment;
  auto list1 = CreateInterpolableList({{1.0, 1}, {2.0, 2}, {3.0, 3}});
  auto list2 = CreateInterpolableList({1, 2, 3});

  auto pairwise = ListInterpolationFunctions::MaybeMergeSingles(
      std::move(list1), std::move(list2),
      ListInterpolationFunctions::LengthMatchingStrategy::kEqual,
      MaybeMergeSingles);

  EXPECT_FALSE(pairwise);
}

TEST(ListInterpolationFunctionsTest, EqualCompositeSameLengths) {
  test::TaskEnvironment task_environment;
  auto list1 = CreateInterpolableList({{1.0, 1}, {2.0, 2}, {3.0, 3}});
  auto list2 = CreateInterpolableList({{1.0, 1}, {2.0, 2}, {3.0, 3}});

  PropertyHandle property_handle(GetCSSPropertyZIndex());
  CSSNumberInterpolationType interpolation_type(property_handle);
  UnderlyingValueOwner owner;
  owner.Set(interpolation_type, std::move(list1));

  ListInterpolationFunctions::Composite(
      owner, 1.0, interpolation_type, list2,
      ListInterpolationFunctions::LengthMatchingStrategy::kEqual,
      ListInterpolationFunctions::InterpolableValuesKnownCompatible,
      NonInterpolableValuesAreCompatible, Composite);

  const auto& result = To<InterpolableList>(*owner.Value().interpolable_value);

  CSSToLengthConversionData length_resolver(/*element=*/nullptr);
  ASSERT_EQ(result.length(), 3u);
  EXPECT_EQ(To<InterpolableNumber>(result.Get(0))->Value(length_resolver), 2.0);
  EXPECT_EQ(To<InterpolableNumber>(result.Get(1))->Value(length_resolver), 4.0);
  EXPECT_EQ(To<InterpolableNumber>(result.Get(2))->Value(length_resolver), 6.0);
}

// Two lists of different lengths are not interpolable, so we expect the
// underlying value to be replaced.
TEST(ListInterpolationFunctionsTest, EqualCompositeDifferentLengths) {
  test::TaskEnvironment task_environment;
  auto list1 = CreateInterpolableList({1.0, 2.0, 3.0});
  auto list2 = CreateInterpolableList({4.0, 5.0});

  PropertyHandle property_handle(GetCSSPropertyZIndex());
  CSSNumberInterpolationType interpolation_type(property_handle);
  UnderlyingValueOwner owner;
  owner.Set(interpolation_type, std::move(list1));

  ListInterpolationFunctions::Composite(
      owner, 1.0, interpolation_type, list2,
      ListInterpolationFunctions::LengthMatchingStrategy::kEqual,
      ListInterpolationFunctions::InterpolableValuesKnownCompatible,
      NonInterpolableValuesAreCompatible, Composite);

  const auto& result = To<InterpolableList>(*owner.Value().interpolable_value);

  CSSToLengthConversionData length_resolver(/*element=*/nullptr);
  ASSERT_EQ(result.length(), 2u);
  EXPECT_EQ(To<InterpolableNumber>(result.Get(0))->Value(length_resolver), 4.0);
  EXPECT_EQ(To<InterpolableNumber>(result.Get(1))->Value(length_resolver), 5.0);
}

// If one (or more) of the element pairs are incompatible, the list as a whole
// is non-interpolable. We expect the underlying value to be replaced.
TEST(ListInterpolationFunctionsTest,
     EqualCompositeIncompatibleInterpolableValues) {
  auto list1 = CreateInterpolableList({1.0, 2.0, 3.0});
  auto list2 = CreateInterpolableList({4.0, 5.0, 6.0});

  InterpolableValuesCompatibilityHelper compatibility_helper(
      {true, false, true});

  PropertyHandle property_handle(GetCSSPropertyZIndex());
  CSSNumberInterpolationType interpolation_type(property_handle);
  UnderlyingValueOwner owner;
  owner.Set(interpolation_type, std::move(list1));

  ListInterpolationFunctions::Composite(
      owner, 1.0, interpolation_type, list2,
      ListInterpolationFunctions::LengthMatchingStrategy::kEqual,
      [&compatibility_helper](const InterpolableValue* a,
                              const InterpolableValue* b) {
        return compatibility_helper.AreCompatible(a, b);
      },
      NonInterpolableValuesAreCompatible, Composite);

  const auto& result = To<InterpolableList>(*owner.Value().interpolable_value);

  CSSToLengthConversionData length_resolver(/*element=*/nullptr);
  ASSERT_EQ(result.length(), 3u);
  EXPECT_EQ(To<InterpolableNumber>(result.Get(0))->Value(length_resolver), 4.0);
  EXPECT_EQ(To<InterpolableNumber>(result.Get(1))->Value(length_resolver), 5.0);
  EXPECT_EQ(To<InterpolableNumber>(result.Get(2))->Value(length_resolver), 6.0);
}

// If one (or more) of the element pairs are incompatible, the list as a whole
// is non-interpolable. We expect the underlying value to be replaced.
TEST(ListInterpolationFunctionsTest,
     EqualCompositeIncompatibleNonInterpolableValues) {
  auto list1 = CreateInterpolableList({{1.0, 1}, {2.0, 2}, {3.0, 3}});
  auto list2 = CreateInterpolableList({{4.0, 1}, {5.0, 4}, {6.0, 3}});

  PropertyHandle property_handle(GetCSSPropertyZIndex());
  CSSNumberInterpolationType interpolation_type(property_handle);
  UnderlyingValueOwner owner;
  owner.Set(interpolation_type, std::move(list1));

  ListInterpolationFunctions::Composite(
      owner, 1.0, interpolation_type, list2,
      ListInterpolationFunctions::LengthMatchingStrategy::kEqual,
      ListInterpolationFunctions::InterpolableValuesKnownCompatible,
      NonInterpolableValuesAreCompatible, Composite);

  const auto& result = To<InterpolableList>(*owner.Value().interpolable_value);

  CSSToLengthConversionData length_resolver(/*element=*/nullptr);
  ASSERT_EQ(result.length(), 3u);
  EXPECT_EQ(To<InterpolableNumber>(result.Get(0))->Value(length_resolver), 4.0);
  EXPECT_EQ(To<InterpolableNumber>(result.Get(1))->Value(length_resolver), 5.0);
  EXPECT_EQ(To<InterpolableNumber>(result.Get(2))->Value(length_resolver), 6.0);
}

TEST(ListInterpolationFunctionsTest, BuilderNoModify) {
  test::TaskEnvironment task_environment;
  auto list = CreateNonInterpolableList({1, 2, 3});
  auto& before = To<NonInterpolableList>(*list.non_interpolable_value);

  {
    TestUnderlyingValue underlying_value(list);
    NonInterpolableList::AutoBuilder builder(underlying_value);
  }

  auto& after = To<NonInterpolableList>(*list.non_interpolable_value);

  EXPECT_EQ(&before, &after);
  ASSERT_EQ(3u, before.length());
  EXPECT_EQ(1, ToTestNonInterpolableValue(*before.Get(0)).GetValue());
  EXPECT_EQ(2, ToTestNonInterpolableValue(*before.Get(1)).GetValue());
  EXPECT_EQ(3, ToTestNonInterpolableValue(*before.Get(2)).GetValue());
}

TEST(ListInterpolationFunctionsTest, BuilderModifyFirst) {
  test::TaskEnvironment task_environment;
  auto list = CreateNonInterpolableList({1, 2, 3});
  auto& before = To<NonInterpolableList>(*list.non_interpolable_value);

  {
    TestUnderlyingValue underlying_value(list);
    NonInterpolableList::AutoBuilder builder(underlying_value);
    builder.Set(0, TestNonInterpolableValue::Create(4));
  }

  auto& after = To<NonInterpolableList>(*list.non_interpolable_value);

  EXPECT_NE(&before, &after);
  ASSERT_EQ(3u, after.length());
  EXPECT_EQ(4, ToTestNonInterpolableValue(*after.Get(0)).GetValue());
  EXPECT_EQ(2, ToTestNonInterpolableValue(*after.Get(1)).GetValue());
  EXPECT_EQ(3, ToTestNonInterpolableValue(*after.Get(2)).GetValue());
}

TEST(ListInterpolationFunctionsTest, BuilderModifyMiddle) {
  test::TaskEnvironment task_environment;
  auto list = CreateNonInterpolableList({1, 2, 3});
  auto& before = To<NonInterpolableList>(*list.non_interpolable_value);

  {
    TestUnderlyingValue underlying_value(list);
    NonInterpolableList::AutoBuilder builder(underlying_value);
    builder.Set(1, TestNonInterpolableValue::Create(4));
  }

  auto& after = To<NonInterpolableList>(*list.non_interpolable_value);

  EXPECT_NE(&before, &after);
  ASSERT_EQ(3u, after.length());
  EXPECT_EQ(1, ToTestNonInterpolableValue(*after.Get(0)).GetValue());
  EXPECT_EQ(4, ToTestNonInterpolableValue(*after.Get(1)).GetValue());
  EXPECT_EQ(3, ToTestNonInterpolableValue(*after.Get(2)).GetValue());
}

TEST(ListInterpolationFunctionsTest, BuilderModifyLast) {
  test::TaskEnvironment task_environment;
  auto list = CreateNonInterpolableList({1, 2, 3});
  auto& before = To<NonInterpolableList>(*list.non_interpolable_value);

  {
    TestUnderlyingValue underlying_value(list);
    NonInterpolableList::AutoBuilder builder(underlying_value);
    builder.Set(2, TestNonInterpolableValue::Create(4));
  }

  auto& after = To<NonInterpolableList>(*list.non_interpolable_value);

  EXPECT_NE(&before, &after);
  ASSERT_EQ(3u, after.length());
  EXPECT_EQ(1, ToTestNonInterpolableValue(*after.Get(0)).GetValue());
  EXPECT_EQ(2, ToTestNonInterpolableValue(*after.Get(1)).GetValue());
  EXPECT_EQ(4, ToTestNonInterpolableValue(*after.Get(2)).GetValue());
}

TEST(ListInterpolationFunctionsTest, BuilderModifyAll) {
  test::TaskEnvironment task_environment;
  auto list = CreateNonInterpolableList({1, 2, 3});
  auto& before = To<NonInterpolableList>(*list.non_interpolable_value);

  {
    TestUnderlyingValue underlying_value(list);
    NonInterpolableList::AutoBuilder builder(underlying_value);
    builder.Set(0, TestNonInterpolableValue::Create(4));
    builder.Set(1, TestNonInterpolableValue::Create(5));
    builder.Set(2, TestNonInterpolableValue::Create(6));
  }

  auto& after = To<NonInterpolableList>(*list.non_interpolable_value);

  EXPECT_NE(&before, &after);
  ASSERT_EQ(3u, after.length());
  EXPECT_EQ(4, ToTestNonInterpolableValue(*after.Get(0)).GetValue());
  EXPECT_EQ(5, ToTestNonInterpolableValue(*after.Get(1)).GetValue());
  EXPECT_EQ(6, ToTestNonInterpolableValue(*after.Get(2)).GetValue());
}

TEST(ListInterpolationFunctionsTest, BuilderModifyReverse) {
  test::TaskEnvironment task_environment;
  auto list = CreateNonInterpolableList({1, 2, 3, 4, 5});
  auto& before = To<NonInterpolableList>(*list.non_interpolable_value);

  {
    TestUnderlyingValue underlying_value(list);
    NonInterpolableList::AutoBuilder builder(underlying_value);
    builder.Set(3, TestNonInterpolableValue::Create(6));
    builder.Set(1, TestNonInterpolableValue::Create(7));
  }

  auto& after = To<NonInterpolableList>(*list.non_interpolable_value);

  EXPECT_NE(&before, &after);
  ASSERT_EQ(5u, after.length());
  EXPECT_EQ(1, ToTestNonInterpolableValue(*after.Get(0)).GetValue());
  EXPECT_EQ(7, ToTestNonInterpolableValue(*after.Get(1)).GetValue());
  EXPECT_EQ(3, ToTestNonInterpolableValue(*after.Get(2)).GetValue());
  EXPECT_EQ(6, ToTestNonInterpolableValue(*after.Get(3)).GetValue());
  EXPECT_EQ(5, ToTestNonInterpolableValue(*after.Get(4)).GetValue());
}

TEST(ListInterpolationFunctionsTest, BuilderModifyListWithOneItem) {
  test::TaskEnvironment task_environment;
  auto list = CreateNonInterpolableList({1});
  auto& before = To<NonInterpolableList>(*list.non_interpolable_value);

  {
    TestUnderlyingValue underlying_value(list);
    NonInterpolableList::AutoBuilder builder(underlying_value);
    builder.Set(0, TestNonInterpolableValue::Create(4));
  }

  auto& after = To<NonInterpolableList>(*list.non_interpolable_value);

  EXPECT_NE(&before, &after);
  EXPECT_EQ(4, ToTestNonInterpolableValue(*after.Get(0)).GetValue());
}

}  // namespace blink
```