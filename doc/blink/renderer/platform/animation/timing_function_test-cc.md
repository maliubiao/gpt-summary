Response:
Let's break down the thought process for analyzing the `timing_function_test.cc` file.

1. **Understand the Purpose of Test Files:** The name `timing_function_test.cc` immediately suggests that this file contains unit tests for code related to timing functions. In software development, especially in large projects like Chromium, unit tests are crucial for verifying the correctness of individual components.

2. **Identify Core Functionality Under Test:**  Scanning the `#include` directives reveals the primary focus: `timing_function.h`. This tells us the tests are specifically designed to check the behavior of the `TimingFunction` class and its derived classes.

3. **Analyze Test Structure:** The file uses the Google Test framework (`testing/gmock/include/gmock/gmock.h`, `testing/gtest/include/gtest/gtest.h`). This framework provides macros like `TEST_F` and `EXPECT_EQ`, `EXPECT_NE`, which are standard for writing tests. The `TimingFunctionTest` class derives from `testing::Test`, setting up a test fixture.

4. **Examine Individual Test Cases:** Now, go through each `TEST_F` function:

   * **`LinearToString`:** This test checks if the `ToString()` method of `LinearTimingFunction` produces the correct string representation ("linear" or "linear(…)"). This relates to how these functions are serialized or displayed.

   * **`CubicToString`:** Similar to `LinearToString`, but for `CubicBezierTimingFunction`. It verifies the string output for both preset easing functions (ease, ease-in, etc.) and custom cubic bezier curves.

   * **`StepToString`:**  Again, focused on the `ToString()` method, this time for `StepsTimingFunction`. It checks the output for "steps(1)" and "steps(N, start)".

   * **`BaseOperatorEq`:** This test explores the equality operator (`operator==`) at the base `TimingFunction` level. It creates different types of timing functions and asserts that they are *not* equal to each other. The `NotEqualHelperLoop` is a helper function to avoid repetitive code for these comparisons.

   * **`LinearOperatorEq`:**  Specifically tests the equality operator for `LinearTimingFunction`. It checks cases where two linear functions are the same (shared instances or identical points) and cases where they are different (different points).

   * **`CubicOperatorEq`:** Tests the equality operator for `CubicBezierTimingFunction`, covering both preset and custom curves.

   * **`CubicOperatorEqReflectivity`:**  A specific test to ensure the equality operator for cubic bezier functions is *reflective* (if A != B, then B != A). This is an important property of equality.

   * **`StepsOperatorEq`:**  Tests the equality operator for `StepsTimingFunction`, including different step counts and `start`/`end` positions.

   * **`StepsOperatorEqPreset`:** A specific check to see if a preset `StepsTimingFunction` is equal to a manually created one with the same parameters.

   * **`LinearEvaluate`:** This is where the *core functionality* of evaluating the timing function at a given time fraction is tested. It checks the `Evaluate()` method for `LinearTimingFunction` with simple and complex point configurations.

   * **`LinearRange`:** Tests the `Range()` method, which likely determines the output range of the timing function for a given input range. It checks how the output range is affected by the defined points.

   * **`StepRange`:** Similar to `LinearRange`, but for `StepsTimingFunction`.

   * **`CubicRange`:** Similar to `LinearRange`, but for `CubicBezierTimingFunction`, testing the range for various preset and custom curves.

   * **`CubicEvaluate`:**  Tests the `Evaluate()` method for `CubicBezierTimingFunction`, comparing the results against expected values (using a small tolerance due to floating-point precision).

   * **`StepsEvaluate`:** Tests the `Evaluate()` method for `StepsTimingFunction`, considering the `start` and `end` step positions and the `LimitDirection` parameter (which affects behavior at step boundaries).

5. **Identify Relationships to Web Technologies:**  Connect the tested concepts to their use in web development:

   * **CSS `transition-timing-function` and `animation-timing-function`:** This is the most direct connection. The timing functions tested here directly correspond to the values you can specify for these CSS properties (e.g., `linear`, `ease`, `ease-in`, `cubic-bezier(...)`, `steps(...)`).

   * **JavaScript's `Animation.easing`:**  While not a direct mapping, the underlying concepts are the same. JavaScript animation APIs also use easing functions to control the rate of change of animated properties.

   * **HTML:**  Indirectly related, as HTML provides the structure that CSS and JavaScript animate.

6. **Consider Assumptions and Edge Cases:** The tests often cover:

   * **Basic cases:** Simple linear, ease, and step functions.
   * **Custom cases:**  User-defined cubic bezier curves and step counts.
   * **Edge cases:**  Negative input values, values greater than 1, behavior at the boundaries of steps (using `LimitDirection`).
   * **Equality checks:** Ensuring different timing functions are correctly identified as different, and identical ones as equal.
   * **String representation:**  Verifying the `ToString()` method is correct for serialization and debugging.

7. **Identify Potential Usage Errors:** Based on the tested functionality, infer common mistakes developers might make:

   * **Incorrect cubic-bezier parameters:**  Providing values outside the [0, 1] range for the control points (though the tests *do* include such cases, indicating the engine handles them).
   * **Misunderstanding `steps()`:**  Not knowing the difference between `steps(n, start)` and `steps(n, end)`.
   * **Assuming linear interpolation everywhere:**  Forgetting to specify a timing function, resulting in the default (often `ease`).

8. **Formulate Input/Output Examples:** For each test case (or a representative subset), create examples that illustrate the tested logic. Focus on the `Evaluate()` method as it's the core of how timing functions work.

By following these steps, you can systematically analyze a source code file like `timing_function_test.cc` and understand its purpose, functionality, relationships to other technologies, and potential implications for users and developers.
这个文件 `blink/renderer/platform/animation/timing_function_test.cc` 是 Chromium Blink 渲染引擎的一部分，它专门用于**测试动画的 timing function（定时函数）** 的功能。

**核心功能：**

1. **验证不同类型 timing function 的正确性：** 该文件包含了针对各种 timing function 的单元测试，例如：
    * **LinearTimingFunction (线性):**  动画以恒定速度进行。
    * **CubicBezierTimingFunction (三次贝塞尔曲线):**  允许自定义动画的速度曲线，例如 ease, ease-in, ease-out, ease-in-out 以及自定义的贝塞尔曲线。
    * **StepsTimingFunction (步进):**  动画在离散的步骤之间跳跃，而不是平滑过渡。

2. **测试 timing function 的各种方法：**
    * **`ToString()` 方法：**  测试 timing function 对象能否正确地转换为字符串表示形式，这对于 CSS 属性的序列化和调试非常重要。
    * **`operator==` (相等运算符):**  测试能否正确地比较两个 timing function 对象是否相等。
    * **`Evaluate(double time)` 方法：**  这是 timing function 的核心方法，用于给定一个介于 0 和 1 之间的时间值，计算出动画的进度值（同样介于 0 和 1 之间）。测试验证了不同 timing function 在不同时间点的计算结果是否符合预期。
    * **`Range(double* start, double* end)` 方法：**  测试在给定输入时间范围的情况下，timing function 输出值的范围。这对于理解 timing function 的输出边界很有用。

**与 javascript, html, css 的关系：**

这个测试文件直接关系到 CSS 动画和过渡的 `transition-timing-function` 和 `animation-timing-function` 属性。这些 CSS 属性允许开发者指定动画的速度曲线。

* **CSS `transition-timing-function` 和 `animation-timing-function`:**  此测试文件中测试的各种 timing function (linear, ease, ease-in, ease-out, ease-in-out, cubic-bezier(), steps()) 正是这些 CSS 属性可以接受的值。

**举例说明：**

假设你在 CSS 中定义了一个元素的过渡效果：

```css
.element {
  width: 100px;
  transition: width 1s ease-in-out; /* 使用 ease-in-out timing function */
}

.element:hover {
  width: 200px;
}
```

当鼠标悬停在 `.element` 上时，它的宽度会从 100px 平滑过渡到 200px，过渡时间为 1 秒。`ease-in-out` timing function 意味着动画开始和结束时速度较慢，中间速度较快。

`timing_function_test.cc` 文件中的 `CubicToString` 和 `CubicEvaluate` 测试用例就专门验证了 `ease-in-out` 这种 timing function 的字符串表示和计算逻辑是否正确。例如，`CubicBezierTimingFunction::Preset(CubicBezierTimingFunction::EaseType::EASE_IN_OUT)` 会创建一个代表 `ease-in-out` 的对象，并且测试会验证其 `ToString()` 方法返回 "ease-in-out"，并且在不同的时间点调用 `Evaluate()` 方法能得到预期的进度值。

类似地，对于 `steps()` timing function：

```css
.element {
  background-position: 0px 0px;
  transition: background-position 1s steps(4, start); /* 使用 steps timing function */
}

.element:hover {
  background-position: -400px 0px;
}
```

当鼠标悬停时，背景位置会在 1 秒内分 4 个离散的步骤进行改变。`steps(4, start)` 表示在每个步骤的开始时发生变化。`StepsToString` 和 `StepsEvaluate` 测试用例会验证这种 timing function 的字符串表示和计算逻辑。

**逻辑推理 (假设输入与输出):**

**假设输入 (LinearEvaluate 测试):**

* Timing Function 类型: `LinearTimingFunction`
* 输入时间 `time`: 0.6

**预期输出:**

* `Evaluate(0.6)` 的结果应该接近 0.6。因为线性 timing function 的输出值与输入时间成正比。

**假设输入 (CubicEvaluate 测试):**

* Timing Function 类型: `CubicBezierTimingFunction` (Ease In Out)
* 输入时间 `time`: 0.25

**预期输出:**

* `Evaluate(0.25)` 的结果应该接近 0.129 (根据测试中的期望值)，因为 Ease In Out 函数在开始阶段变化较慢。

**假设输入 (StepsEvaluate 测试):**

* Timing Function 类型: `StepsTimingFunction` (steps(4, start))
* 输入时间 `time`: 0.25

**预期输出:**

* `Evaluate(0.25)` 的结果应该接近 0.25。因为在 `steps(4, start)` 中，当时间达到一个步进的开始时，进度会立即跳跃到该步进的终点值。

**用户或编程常见的使用错误举例说明：**

1. **`cubic-bezier` 参数错误:**  用户可能会错误地提供 `cubic-bezier` 函数的参数，导致动画效果不符合预期。例如：

   ```css
   transition: transform 1s cubic-bezier(1.5, 0, 0, 1.5); /* 控制点超出 [0, 1] 范围 */
   ```

   `timing_function_test.cc` 中的测试会验证引擎如何处理这些超出范围的参数，并确保其行为是合理的。

2. **对 `steps()` 函数的理解偏差:** 用户可能不清楚 `steps(n, start)` 和 `steps(n, end)` 的区别。

   * `steps(n, end)` (默认) 会在每个步骤的结束时发生变化。
   * `steps(n, start)` 会在每个步骤的开始时发生变化。

   错误地使用 `start` 或 `end` 可能会导致动画在时间点上出现意外的延迟或提前。`StepsEvaluate` 测试用例就重点测试了这两种情况，帮助开发者理解其差异。

3. **混合使用 timing function:**  开发者可能会在同一个动画或过渡中混合使用不同的 timing function，导致动画效果难以预测和维护。虽然这不是一个直接的错误，但理解各种 timing function 的行为对于创建复杂动画至关重要。这个测试文件通过提供各种 timing function 的精确行为定义，帮助开发者避免这类问题。

总而言之，`blink/renderer/platform/animation/timing_function_test.cc` 是一个至关重要的测试文件，它确保了 Blink 引擎中关于动画 timing function 的实现是正确和可靠的，这直接影响到网页动画和过渡效果的呈现。

Prompt: 
```
这是目录为blink/renderer/platform/animation/timing_function_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (c) 2013, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/platform/animation/timing_function.h"

#include <sstream>
#include <string>
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "ui/gfx/animation/keyframe/timing_function.h"

namespace blink {

namespace {

class TimingFunctionTest : public testing::Test {
 public:
  TimingFunctionTest() {}

  void NotEqualHelperLoop(
      Vector<std::pair<std::string, scoped_refptr<TimingFunction>>>& v) {
    for (size_t i = 0; i < v.size(); ++i) {
      for (size_t j = 0; j < v.size(); ++j) {
        if (i == j)
          continue;
        EXPECT_NE(v[i], v[j])
            << v[i].first << " (" << v[i].second->ToString() << ")"
            << " ==  " << v[j].first << " (" << v[j].second->ToString() << ")"
            << "\n";
      }
    }
  }
};

TEST_F(TimingFunctionTest, LinearToString) {
  scoped_refptr<TimingFunction> linear_timing = LinearTimingFunction::Shared();
  EXPECT_EQ(linear_timing->ToString(), "linear");
  std::vector<gfx::LinearEasingPoint> points{{0, 1}, {50, 2}, {100, 3}};
  scoped_refptr<TimingFunction> linear_timing_complex =
      LinearTimingFunction::Create(points);
  EXPECT_EQ(linear_timing_complex->ToString(), "linear(1 0%, 2 50%, 3 100%)");
}

TEST_F(TimingFunctionTest, CubicToString) {
  scoped_refptr<TimingFunction> cubic_ease_timing =
      CubicBezierTimingFunction::Preset(
          CubicBezierTimingFunction::EaseType::EASE);
  EXPECT_EQ("ease", cubic_ease_timing->ToString());
  scoped_refptr<TimingFunction> cubic_ease_in_timing =
      CubicBezierTimingFunction::Preset(
          CubicBezierTimingFunction::EaseType::EASE_IN);
  EXPECT_EQ("ease-in", cubic_ease_in_timing->ToString());
  scoped_refptr<TimingFunction> cubic_ease_out_timing =
      CubicBezierTimingFunction::Preset(
          CubicBezierTimingFunction::EaseType::EASE_OUT);
  EXPECT_EQ("ease-out", cubic_ease_out_timing->ToString());
  scoped_refptr<TimingFunction> cubic_ease_in_out_timing =
      CubicBezierTimingFunction::Preset(
          CubicBezierTimingFunction::EaseType::EASE_IN_OUT);
  EXPECT_EQ("ease-in-out", cubic_ease_in_out_timing->ToString());

  scoped_refptr<TimingFunction> cubic_custom_timing =
      CubicBezierTimingFunction::Create(0.17, 0.67, 1, -1.73);
  EXPECT_EQ("cubic-bezier(0.17, 0.67, 1, -1.73)",
            cubic_custom_timing->ToString());
}

TEST_F(TimingFunctionTest, StepToString) {
  scoped_refptr<TimingFunction> step_timing_start =
      StepsTimingFunction::Preset(StepsTimingFunction::StepPosition::START);
  EXPECT_EQ("steps(1, start)", step_timing_start->ToString());

  scoped_refptr<TimingFunction> step_timing_end =
      StepsTimingFunction::Preset(StepsTimingFunction::StepPosition::END);
  EXPECT_EQ("steps(1)", step_timing_end->ToString());

  scoped_refptr<TimingFunction> step_timing_custom_start =
      StepsTimingFunction::Create(3, StepsTimingFunction::StepPosition::START);
  EXPECT_EQ("steps(3, start)", step_timing_custom_start->ToString());

  scoped_refptr<TimingFunction> step_timing_custom_end =
      StepsTimingFunction::Create(5, StepsTimingFunction::StepPosition::END);
  EXPECT_EQ("steps(5)", step_timing_custom_end->ToString());
}

TEST_F(TimingFunctionTest, BaseOperatorEq) {
  scoped_refptr<TimingFunction> linear_timing = LinearTimingFunction::Shared();
  scoped_refptr<TimingFunction> cubic_timing1 =
      CubicBezierTimingFunction::Preset(
          CubicBezierTimingFunction::EaseType::EASE_IN);
  scoped_refptr<TimingFunction> cubic_timing2 =
      CubicBezierTimingFunction::Create(0.17, 0.67, 1, -1.73);
  scoped_refptr<TimingFunction> steps_timing1 =
      StepsTimingFunction::Preset(StepsTimingFunction::StepPosition::END);
  scoped_refptr<TimingFunction> steps_timing2 =
      StepsTimingFunction::Create(5, StepsTimingFunction::StepPosition::START);

  Vector<std::pair<std::string, scoped_refptr<TimingFunction>>> v;
  v.push_back(std::make_pair("linearTiming", linear_timing));
  v.push_back(std::make_pair("cubicTiming1", cubic_timing1));
  v.push_back(std::make_pair("cubicTiming2", cubic_timing2));
  v.push_back(std::make_pair("stepsTiming1", steps_timing1));
  v.push_back(std::make_pair("stepsTiming2", steps_timing2));
  NotEqualHelperLoop(v);
}

TEST_F(TimingFunctionTest, LinearOperatorEq) {
  scoped_refptr<TimingFunction> linear_timing1 = LinearTimingFunction::Shared();
  scoped_refptr<TimingFunction> linear_timing2 = LinearTimingFunction::Shared();
  EXPECT_EQ(*linear_timing1, *linear_timing1);
  EXPECT_EQ(*linear_timing1, *linear_timing2);
  std::vector<gfx::LinearEasingPoint> points3{{0, 1}, {100, 1}};
  const auto& linear_timing3 = LinearTimingFunction::Create(points3);
  const auto& linear_timing4 = LinearTimingFunction::Create(std::move(points3));
  std::vector<gfx::LinearEasingPoint> points5{{0, 1.1}, {100, 1}};
  const auto& linear_timing5 = LinearTimingFunction::Create(std::move(points5));
  std::vector<gfx::LinearEasingPoint> points6{{0, 1}, {50, .5}, {100, 1}};
  const auto& linear_timing6 = LinearTimingFunction::Create(std::move(points6));
  EXPECT_NE(*linear_timing1, *linear_timing3);
  EXPECT_EQ(*linear_timing3, *linear_timing4);
  EXPECT_NE(*linear_timing4, *linear_timing5);
  EXPECT_NE(*linear_timing5, *linear_timing6);
}

TEST_F(TimingFunctionTest, CubicOperatorEq) {
  scoped_refptr<TimingFunction> cubic_ease_in_timing1 =
      CubicBezierTimingFunction::Preset(
          CubicBezierTimingFunction::EaseType::EASE_IN);
  scoped_refptr<TimingFunction> cubic_ease_in_timing2 =
      CubicBezierTimingFunction::Preset(
          CubicBezierTimingFunction::EaseType::EASE_IN);
  EXPECT_EQ(*cubic_ease_in_timing1, *cubic_ease_in_timing1);
  EXPECT_EQ(*cubic_ease_in_timing1, *cubic_ease_in_timing2);

  scoped_refptr<TimingFunction> cubic_ease_out_timing1 =
      CubicBezierTimingFunction::Preset(
          CubicBezierTimingFunction::EaseType::EASE_OUT);
  scoped_refptr<TimingFunction> cubic_ease_out_timing2 =
      CubicBezierTimingFunction::Preset(
          CubicBezierTimingFunction::EaseType::EASE_OUT);
  EXPECT_EQ(*cubic_ease_out_timing1, *cubic_ease_out_timing1);
  EXPECT_EQ(*cubic_ease_out_timing1, *cubic_ease_out_timing2);

  scoped_refptr<TimingFunction> cubic_ease_in_out_timing1 =
      CubicBezierTimingFunction::Preset(
          CubicBezierTimingFunction::EaseType::EASE_IN_OUT);
  scoped_refptr<TimingFunction> cubic_ease_in_out_timing2 =
      CubicBezierTimingFunction::Preset(
          CubicBezierTimingFunction::EaseType::EASE_IN_OUT);
  EXPECT_EQ(*cubic_ease_in_out_timing1, *cubic_ease_in_out_timing1);
  EXPECT_EQ(*cubic_ease_in_out_timing1, *cubic_ease_in_out_timing2);

  scoped_refptr<TimingFunction> cubic_custom_timing1 =
      CubicBezierTimingFunction::Create(0.17, 0.67, 1, -1.73);
  scoped_refptr<TimingFunction> cubic_custom_timing2 =
      CubicBezierTimingFunction::Create(0.17, 0.67, 1, -1.73);
  EXPECT_EQ(*cubic_custom_timing1, *cubic_custom_timing1);
  EXPECT_EQ(*cubic_custom_timing1, *cubic_custom_timing2);

  Vector<std::pair<std::string, scoped_refptr<TimingFunction>>> v;
  v.push_back(std::make_pair("cubicEaseInTiming1", cubic_ease_in_timing1));
  v.push_back(std::make_pair("cubicEaseOutTiming1", cubic_ease_out_timing1));
  v.push_back(
      std::make_pair("cubicEaseInOutTiming1", cubic_ease_in_out_timing1));
  v.push_back(std::make_pair("cubicCustomTiming1", cubic_custom_timing1));
  NotEqualHelperLoop(v);
}

TEST_F(TimingFunctionTest, CubicOperatorEqReflectivity) {
  scoped_refptr<TimingFunction> cubic_a = CubicBezierTimingFunction::Preset(
      CubicBezierTimingFunction::EaseType::EASE_IN);
  scoped_refptr<TimingFunction> cubic_b =
      CubicBezierTimingFunction::Create(0.42, 0.0, 1.0, 1.0);
  EXPECT_NE(*cubic_a, *cubic_b);
  EXPECT_NE(*cubic_b, *cubic_a);
}

TEST_F(TimingFunctionTest, StepsOperatorEq) {
  scoped_refptr<TimingFunction> steps_timing_start1 =
      StepsTimingFunction::Preset(StepsTimingFunction::StepPosition::START);
  scoped_refptr<TimingFunction> steps_timing_start2 =
      StepsTimingFunction::Preset(StepsTimingFunction::StepPosition::START);
  EXPECT_EQ(*steps_timing_start1, *steps_timing_start1);
  EXPECT_EQ(*steps_timing_start1, *steps_timing_start2);

  scoped_refptr<TimingFunction> steps_timing_end1 =
      StepsTimingFunction::Preset(StepsTimingFunction::StepPosition::END);
  scoped_refptr<TimingFunction> steps_timing_end2 =
      StepsTimingFunction::Preset(StepsTimingFunction::StepPosition::END);
  EXPECT_EQ(*steps_timing_end1, *steps_timing_end1);
  EXPECT_EQ(*steps_timing_end1, *steps_timing_end2);

  scoped_refptr<TimingFunction> steps_timing_custom1 =
      StepsTimingFunction::Create(5, StepsTimingFunction::StepPosition::START);
  scoped_refptr<TimingFunction> steps_timing_custom2 =
      StepsTimingFunction::Create(5, StepsTimingFunction::StepPosition::END);
  scoped_refptr<TimingFunction> steps_timing_custom3 =
      StepsTimingFunction::Create(7, StepsTimingFunction::StepPosition::START);
  scoped_refptr<TimingFunction> steps_timing_custom4 =
      StepsTimingFunction::Create(7, StepsTimingFunction::StepPosition::END);

  EXPECT_EQ(
      *StepsTimingFunction::Create(5, StepsTimingFunction::StepPosition::START),
      *steps_timing_custom1);
  EXPECT_EQ(
      *StepsTimingFunction::Create(5, StepsTimingFunction::StepPosition::END),
      *steps_timing_custom2);
  EXPECT_EQ(
      *StepsTimingFunction::Create(7, StepsTimingFunction::StepPosition::START),
      *steps_timing_custom3);
  EXPECT_EQ(
      *StepsTimingFunction::Create(7, StepsTimingFunction::StepPosition::END),
      *steps_timing_custom4);

  Vector<std::pair<std::string, scoped_refptr<TimingFunction>>> v;
  v.push_back(std::make_pair("stepsTimingStart1", steps_timing_start1));
  v.push_back(std::make_pair("stepsTimingEnd1", steps_timing_end1));
  v.push_back(std::make_pair("stepsTimingCustom1", steps_timing_custom1));
  v.push_back(std::make_pair("stepsTimingCustom2", steps_timing_custom2));
  v.push_back(std::make_pair("stepsTimingCustom3", steps_timing_custom3));
  v.push_back(std::make_pair("stepsTimingCustom4", steps_timing_custom4));
  NotEqualHelperLoop(v);
}

TEST_F(TimingFunctionTest, StepsOperatorEqPreset) {
  scoped_refptr<TimingFunction> steps_a =
      StepsTimingFunction::Preset(StepsTimingFunction::StepPosition::START);
  scoped_refptr<TimingFunction> steps_b =
      StepsTimingFunction::Create(1, StepsTimingFunction::StepPosition::START);
  EXPECT_EQ(*steps_a, *steps_b);
  EXPECT_EQ(*steps_b, *steps_a);
}

TEST_F(TimingFunctionTest, LinearEvaluate) {
  scoped_refptr<LinearTimingFunction> linear_timing =
      LinearTimingFunction::Shared();
  EXPECT_EQ(0.2, linear_timing->Evaluate(0.2));
  EXPECT_EQ(0.6, linear_timing->Evaluate(0.6));
  EXPECT_EQ(-0.2, linear_timing->Evaluate(-0.2));
  EXPECT_EQ(1.6, linear_timing->Evaluate(1.6));
  std::vector<gfx::LinearEasingPoint> points{{0, 0}, {100, 1}};
  scoped_refptr<LinearTimingFunction> linear_timing_trivial =
      LinearTimingFunction::Create(std::move(points));
  EXPECT_EQ(0.2, linear_timing_trivial->Evaluate(0.2));
  EXPECT_EQ(0.6, linear_timing_trivial->Evaluate(0.6));
  EXPECT_EQ(-0.2, linear_timing_trivial->Evaluate(-0.2));
  EXPECT_EQ(1.6, linear_timing_trivial->Evaluate(1.6));
  points = {{0, 0}, {50, 1}, {60, .5}, {100, 1}};
  scoped_refptr<LinearTimingFunction> linear_timing_complex =
      LinearTimingFunction::Create(std::move(points));
  EXPECT_EQ(.5, linear_timing_complex->Evaluate(.25));
  EXPECT_EQ(.5, linear_timing_complex->Evaluate(.6));
  EXPECT_EQ(.75, linear_timing_complex->Evaluate(.80));
  EXPECT_EQ(-.5, linear_timing_complex->Evaluate(-.25));
}

TEST_F(TimingFunctionTest, LinearRange) {
  double start = 0;
  double end = 1;
  scoped_refptr<TimingFunction> linear_timing = LinearTimingFunction::Shared();
  linear_timing->Range(&start, &end);
  EXPECT_NEAR(0, start, 0.01);
  EXPECT_NEAR(1, end, 0.01);
  std::vector<gfx::LinearEasingPoint> points{{0, 0}, {50, 1}, {100, 0}};
  scoped_refptr<TimingFunction> linear_timing_complex =
      LinearTimingFunction::Create(std::move(points));
  start = .25;
  end = .75;
  linear_timing_complex->Range(&start, &end);
  EXPECT_NEAR(.5, start, 0.01);
  EXPECT_NEAR(1, end, 0.01);
  points = {{0, 0}, {50, .75}, {60, 0.1}, {100, 1}};
  linear_timing_complex = LinearTimingFunction::Create(std::move(points));
  start = .5;
  end = .75;
  linear_timing_complex->Range(&start, &end);
  EXPECT_NEAR(.1, start, 0.01);
  EXPECT_NEAR(.75, end, 0.01);
}

TEST_F(TimingFunctionTest, StepRange) {
  double start = 0;
  double end = 1;
  scoped_refptr<TimingFunction> steps =
      StepsTimingFunction::Preset(StepsTimingFunction::StepPosition::START);
  steps->Range(&start, &end);
  EXPECT_NEAR(0, start, 0.01);
  EXPECT_NEAR(1, end, 0.01);

  start = -1;
  end = 10;
  steps->Range(&start, &end);
  EXPECT_NEAR(0, start, 0.01);
  EXPECT_NEAR(1, end, 0.01);
}

TEST_F(TimingFunctionTest, CubicRange) {
  double start = 0;
  double end = 1;

  scoped_refptr<TimingFunction> cubic_ease_timing =
      CubicBezierTimingFunction::Preset(
          CubicBezierTimingFunction::EaseType::EASE);
  start = 0;
  end = 1;
  cubic_ease_timing->Range(&start, &end);
  EXPECT_NEAR(0, start, 0.01);
  EXPECT_NEAR(1, end, 0.01);
  start = -1;
  end = 10;
  cubic_ease_timing->Range(&start, &end);
  EXPECT_NEAR(-0.4, start, 0.01);
  EXPECT_NEAR(1, end, 0.01);

  scoped_refptr<TimingFunction> cubic_ease_in_timing =
      CubicBezierTimingFunction::Preset(
          CubicBezierTimingFunction::EaseType::EASE_IN);
  start = 0;
  end = 1;
  cubic_ease_in_timing->Range(&start, &end);
  EXPECT_NEAR(0, start, 0.01);
  EXPECT_NEAR(1, end, 0.01);
  start = -1;
  end = 10;
  cubic_ease_in_timing->Range(&start, &end);
  EXPECT_NEAR(0.0, start, 0.01);
  EXPECT_NEAR(16.51, end, 0.01);

  scoped_refptr<TimingFunction> cubic_ease_out_timing =
      CubicBezierTimingFunction::Preset(
          CubicBezierTimingFunction::EaseType::EASE_OUT);
  start = 0;
  end = 1;
  cubic_ease_out_timing->Range(&start, &end);
  EXPECT_NEAR(0, start, 0.01);
  EXPECT_NEAR(1, end, 0.01);
  start = -1;
  end = 10;
  cubic_ease_out_timing->Range(&start, &end);
  EXPECT_NEAR(-1.72, start, 0.01);
  EXPECT_NEAR(1.0, end, 0.01);

  scoped_refptr<TimingFunction> cubic_ease_in_out_timing =
      CubicBezierTimingFunction::Preset(
          CubicBezierTimingFunction::EaseType::EASE_IN_OUT);
  start = 0;
  end = 1;
  cubic_ease_in_out_timing->Range(&start, &end);
  EXPECT_NEAR(0, start, 0.01);
  EXPECT_NEAR(1, end, 0.01);
  start = -1;
  end = 10;
  cubic_ease_in_out_timing->Range(&start, &end);
  EXPECT_NEAR(0.0, start, 0.01);
  EXPECT_NEAR(1.0, end, 0.01);

  scoped_refptr<TimingFunction> cubic_custom_timing =
      CubicBezierTimingFunction::Create(0.17, 0.67, 1.0, -1.73);
  start = 0;
  end = 1;
  cubic_custom_timing->Range(&start, &end);
  EXPECT_NEAR(-0.33, start, 0.01);
  EXPECT_NEAR(1.0, end, 0.01);

  start = -1;
  end = 10;
  cubic_custom_timing->Range(&start, &end);
  EXPECT_NEAR(-3.94, start, 0.01);
  EXPECT_NEAR(1.0, end, 0.01);
}

TEST_F(TimingFunctionTest, CubicEvaluate) {
  double tolerance = 0.01;
  scoped_refptr<CubicBezierTimingFunction> cubic_ease_timing =
      CubicBezierTimingFunction::Preset(
          CubicBezierTimingFunction::EaseType::EASE);
  EXPECT_NEAR(0.409, cubic_ease_timing->Evaluate(0.25), tolerance);
  EXPECT_NEAR(0.802, cubic_ease_timing->Evaluate(0.50), tolerance);
  EXPECT_NEAR(0.960, cubic_ease_timing->Evaluate(0.75), tolerance);

  scoped_refptr<CubicBezierTimingFunction> cubic_ease_in_timing =
      CubicBezierTimingFunction::Preset(
          CubicBezierTimingFunction::EaseType::EASE_IN);
  EXPECT_NEAR(0.093, cubic_ease_in_timing->Evaluate(0.25), tolerance);
  EXPECT_NEAR(0.315, cubic_ease_in_timing->Evaluate(0.50), tolerance);
  EXPECT_NEAR(0.622, cubic_ease_in_timing->Evaluate(0.75), tolerance);

  scoped_refptr<CubicBezierTimingFunction> cubic_ease_out_timing =
      CubicBezierTimingFunction::Preset(
          CubicBezierTimingFunction::EaseType::EASE_OUT);
  EXPECT_NEAR(0.378, cubic_ease_out_timing->Evaluate(0.25), tolerance);
  EXPECT_NEAR(0.685, cubic_ease_out_timing->Evaluate(0.50), tolerance);
  EXPECT_NEAR(0.907, cubic_ease_out_timing->Evaluate(0.75), tolerance);

  scoped_refptr<CubicBezierTimingFunction> cubic_ease_in_out_timing =
      CubicBezierTimingFunction::Preset(
          CubicBezierTimingFunction::EaseType::EASE_IN_OUT);
  EXPECT_NEAR(0.129, cubic_ease_in_out_timing->Evaluate(0.25), tolerance);
  EXPECT_NEAR(0.500, cubic_ease_in_out_timing->Evaluate(0.50), tolerance);
  EXPECT_NEAR(0.871, cubic_ease_in_out_timing->Evaluate(0.75), tolerance);

  scoped_refptr<CubicBezierTimingFunction> cubic_custom_timing =
      CubicBezierTimingFunction::Create(0.17, 0.67, 1, -1.73);
  EXPECT_NEAR(0.034, cubic_custom_timing->Evaluate(0.25), tolerance);
  EXPECT_NEAR(-0.217, cubic_custom_timing->Evaluate(0.50), tolerance);
  EXPECT_NEAR(-0.335, cubic_custom_timing->Evaluate(0.75), tolerance);
}

TEST_F(TimingFunctionTest, StepsEvaluate) {
  TimingFunction::LimitDirection left = TimingFunction::LimitDirection::LEFT;
  TimingFunction::LimitDirection right = TimingFunction::LimitDirection::RIGHT;

  scoped_refptr<TimingFunction> steps_timing_start =
      StepsTimingFunction::Preset(StepsTimingFunction::StepPosition::START);
  EXPECT_EQ(-1.00, steps_timing_start->Evaluate(-1.10, right));
  EXPECT_EQ(0.00, steps_timing_start->Evaluate(-0.10, right));
  EXPECT_EQ(0.00, steps_timing_start->Evaluate(0.00, left));
  EXPECT_EQ(1.00, steps_timing_start->Evaluate(0.00, right));
  EXPECT_EQ(1.00, steps_timing_start->Evaluate(0.20, right));
  EXPECT_EQ(1.00, steps_timing_start->Evaluate(0.60, right));
  EXPECT_EQ(1.00, steps_timing_start->Evaluate(1.00, left));
  EXPECT_EQ(1.00, steps_timing_start->Evaluate(1.00, right));
  EXPECT_EQ(2.00, steps_timing_start->Evaluate(2.00, left));
  EXPECT_EQ(3.00, steps_timing_start->Evaluate(2.00, right));

  scoped_refptr<TimingFunction> steps_timing_end =
      StepsTimingFunction::Preset(StepsTimingFunction::StepPosition::END);
  EXPECT_EQ(-2.00, steps_timing_end->Evaluate(-2.00, right));
  EXPECT_EQ(0.00, steps_timing_end->Evaluate(0.00, left));
  EXPECT_EQ(0.00, steps_timing_end->Evaluate(0.00, right));
  EXPECT_EQ(0.00, steps_timing_end->Evaluate(0.20, right));
  EXPECT_EQ(0.00, steps_timing_end->Evaluate(0.60, right));
  EXPECT_EQ(0.00, steps_timing_end->Evaluate(1.00, left));
  EXPECT_EQ(1.00, steps_timing_end->Evaluate(1.00, right));
  EXPECT_EQ(2.00, steps_timing_end->Evaluate(2.00, right));

  scoped_refptr<TimingFunction> steps_timing_custom_start =
      StepsTimingFunction::Create(4, StepsTimingFunction::StepPosition::START);
  EXPECT_EQ(-0.50, steps_timing_custom_start->Evaluate(-0.50, left));
  EXPECT_EQ(-0.25, steps_timing_custom_start->Evaluate(-0.50, right));
  EXPECT_EQ(0.00, steps_timing_custom_start->Evaluate(0.00, left));
  EXPECT_EQ(0.25, steps_timing_custom_start->Evaluate(0.00, right));
  EXPECT_EQ(0.25, steps_timing_custom_start->Evaluate(0.24, right));
  EXPECT_EQ(0.25, steps_timing_custom_start->Evaluate(0.25, left));
  EXPECT_EQ(0.50, steps_timing_custom_start->Evaluate(0.25, right));
  EXPECT_EQ(0.50, steps_timing_custom_start->Evaluate(0.49, right));
  EXPECT_EQ(0.50, steps_timing_custom_start->Evaluate(0.50, left));
  EXPECT_EQ(0.75, steps_timing_custom_start->Evaluate(0.50, right));
  EXPECT_EQ(0.75, steps_timing_custom_start->Evaluate(0.74, right));
  EXPECT_EQ(0.75, steps_timing_custom_start->Evaluate(0.75, left));
  EXPECT_EQ(1.00, steps_timing_custom_start->Evaluate(0.75, right));
  EXPECT_EQ(1.00, steps_timing_custom_start->Evaluate(1.00, left));
  EXPECT_EQ(1.00, steps_timing_custom_start->Evaluate(1.00, right));
  EXPECT_EQ(1.75, steps_timing_custom_start->Evaluate(1.50, right));

  scoped_refptr<TimingFunction> steps_timing_custom_end =
      StepsTimingFunction::Create(4, StepsTimingFunction::StepPosition::END);
  EXPECT_EQ(-2.25, steps_timing_custom_end->Evaluate(-2.00, left));
  EXPECT_EQ(-2.00, steps_timing_custom_end->Evaluate(-2.00, right));
  EXPECT_EQ(0.00, steps_timing_custom_end->Evaluate(0.00, left));
  EXPECT_EQ(0.00, steps_timing_custom_end->Evaluate(0.00, right));
  EXPECT_EQ(0.00, steps_timing_custom_end->Evaluate(0.24, right));
  EXPECT_EQ(0.00, steps_timing_custom_end->Evaluate(0.25, left));
  EXPECT_EQ(0.25, steps_timing_custom_end->Evaluate(0.25, right));
  EXPECT_EQ(0.25, steps_timing_custom_end->Evaluate(0.49, right));
  EXPECT_EQ(0.25, steps_timing_custom_end->Evaluate(0.50, left));
  EXPECT_EQ(0.50, steps_timing_custom_end->Evaluate(0.50, right));
  EXPECT_EQ(0.50, steps_timing_custom_end->Evaluate(0.74, right));
  EXPECT_EQ(0.50, steps_timing_custom_end->Evaluate(0.75, left));
  EXPECT_EQ(0.75, steps_timing_custom_end->Evaluate(0.75, right));
  EXPECT_EQ(0.75, steps_timing_custom_end->Evaluate(0.99, right));
  EXPECT_EQ(0.75, steps_timing_custom_end->Evaluate(1.00, left));
  EXPECT_EQ(1.00, steps_timing_custom_end->Evaluate(1.00, right));
  EXPECT_EQ(1.75, steps_timing_custom_end->Evaluate(2.00, left));
  EXPECT_EQ(2.00, steps_timing_custom_end->Evaluate(2.00, right));
}

}  // namespace

}  // namespace blink

"""

```