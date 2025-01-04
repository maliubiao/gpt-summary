Response:
The user wants to understand the functionality of the `timing_calculations_test.cc` file in the Chromium Blink rendering engine. I need to analyze the test cases within the file to determine what aspects of animation timing calculations are being tested. I should then explain these functionalities in a way that is understandable, highlighting any connections to JavaScript, HTML, and CSS. For the logical reasoning parts, I need to identify the inputs and expected outputs of the test cases. Finally, I should consider common errors developers might make when dealing with animation timing.

Here's a breakdown of the test cases and their functionalities:

*   **ActiveTime:** Tests the calculation of the active time of an animation based on various factors like `fillMode`, `localTime`, and the animation phase.
*   **OffsetActiveTime:** Tests the calculation of the active time adjusted by an offset.
*   **IterationTime:** Tests how the time within an iteration is calculated, considering factors like `iterationDuration`, `activeDuration`, and `startOffset`.
*   **OverallProgress:** Tests the calculation of the overall animation progress based on the current phase, active time, iteration duration, count, and start.
*   **CalculateSimpleIterationProgress:** Tests the calculation of progress within a single iteration.
*   **CurrentIteration:** Tests the calculation of the current animation iteration.
*   **IsCurrentDirectionForwards:** Tests the determination of whether the animation is currently playing forward or backward.
*   **CalculateDirectedProgress:** Tests the calculation of progress taking into account the playback direction.
*   **TransformedProgress:** Tests how timing functions (like `steps()`) affect the animation progress.
*   **AlignmentHistogram:** Seems to be related to tracking misalignment at animation boundaries for performance metrics.

Now I can structure the response based on these identified functionalities and the user's requirements.
这个文件 `blink/renderer/core/animation/timing_calculations_test.cc` 是 Chromium Blink 引擎中的一个 **单元测试文件**。它的主要功能是 **测试 `blink/renderer/core/animation/timing_calculations.h` 中定义的动画 timing 计算相关的逻辑是否正确**。

具体来说，它包含了一系列的测试用例（使用 Google Test 框架），每个测试用例针对 `TimingCalculations` 类中的不同静态方法进行测试，验证这些方法在各种输入条件下是否能返回预期的结果。这些方法负责计算动画的各个阶段和属性，例如：

*   **动画的激活时间 (Active Time)**
*   **偏移后的激活时间 (Offset Active Time)**
*   **迭代时间 (Iteration Time)**
*   **整体进度 (Overall Progress)**
*   **单次迭代进度 (Simple Iteration Progress)**
*   **当前迭代次数 (Current Iteration)**
*   **当前播放方向是否为向前 (Is Current Direction Forwards)**
*   **带方向的进度 (Directed Progress)**
*   **经过时间函数的进度 (Transformed Progress)**
*   **动画阶段 (Phase)**

**与 JavaScript, HTML, CSS 的关系：**

这个文件测试的逻辑是浏览器引擎内部实现动画效果的核心部分。这些计算直接影响到 Web 开发者在 JavaScript、HTML 和 CSS 中定义的动画的行为。

*   **CSS Animations 和 Transitions:** 当你在 CSS 中使用 `animation` 或 `transition` 属性来创建动画时，浏览器引擎会使用这里的 `TimingCalculations` 类中的方法来计算动画在特定时间点的状态。例如，当你设置 `animation-duration`、`animation-delay`、`animation-iteration-count`、`animation-direction`、`animation-timing-function` 等属性时，这些值会被传递到 Blink 引擎中，相关的计算逻辑会使用到这里测试的方法。

    **举例说明：**

    *   **`animation-duration: 2s;`**:  `CalculateActiveTime` 和 `CalculateIterationTime` 等方法会使用这个持续时间来确定动画在不同时间点的状态。
    *   **`animation-delay: 1s;`**: `CalculateActiveTime` 会使用这个延迟来判断动画是否处于 `Before` 阶段。
    *   **`animation-iteration-count: 3;`**: `CalculateOverallProgress` 和 `CalculateCurrentIteration` 会使用这个迭代次数来计算整体进度和当前是第几次迭代。
    *   **`animation-direction: alternate;`**: `IsCurrentDirectionForwards` 和 `CalculateDirectedProgress` 会根据迭代次数和方向来确定当前是正向播放还是反向播放，并计算相应的进度。
    *   **`animation-timing-function: ease-in-out;`**: `CalculateTransformedProgress` 会使用这个 timing function 来调整动画的进度变化曲线。

*   **JavaScript Web Animations API:**  JavaScript 提供了 Web Animations API 来更精细地控制动画。例如，可以使用 `Animation.currentTime` 属性来获取或设置动画的当前时间，或者使用 `Animation.playState` 来控制动画的播放状态。  `TimingCalculations` 中的逻辑确保了 JavaScript 中对动画状态的读取和设置与 CSS 定义的动画行为一致。

    **举例说明：**

    *   当你使用 JavaScript 获取一个动画的 `currentTime` 时，浏览器引擎内部会使用类似 `CalculateActiveTime` 的方法来确定当前的激活时间。
    *   当你使用 JavaScript 设置一个动画的 `iterationStart` 时，`CalculateOverallProgress` 和 `CalculateSimpleIterationProgress` 会受到这个值的影响。

*   **HTML:** HTML 元素是应用动画的目标。无论是通过 CSS 还是 JavaScript 创建的动画，最终都会作用于 HTML 元素上，`TimingCalculations` 保证了动画效果在渲染过程中的正确性。

**逻辑推理的假设输入与输出：**

以下列举一些测试用例中体现的逻辑推理和假设输入与输出：

**1. `ActiveTime` 测试用例：**

*   **假设输入：**
    *   `normalized_timing.start_delay = 10s`
    *   `normalized_timing.active_duration = 20s`
    *   `fillMode = FillMode::FORWARDS`
    *   `localTime = 15s`
    *   `phase = Timing::kPhaseActive`
*   **预期输出：** `ANIMATION_TIME_DELTA_FROM_SECONDS(5)`  （因为 localTime 减去 start_delay 等于 5 秒的激活时间）

*   **假设输入：**
    *   `normalized_timing.start_delay = 10s`
    *   `normalized_timing.active_duration = 21s`
    *   `fillMode = FillMode::FORWARDS`
    *   `localTime = 45s`
    *   `phase = Timing::kPhaseAfter`
*   **预期输出：** `ANIMATION_TIME_DELTA_FROM_SECONDS(21)` （在 `FORWARDS` 模式下，动画结束后会保持最后一帧的状态，激活时间等于持续时间）

**2. `OffsetActiveTime` 测试用例：**

*   **假设输入：**
    *   `active_duration = 40s`
    *   `active_time = 10s`
    *   `offset = 5s`
*   **预期输出：** `ANIMATION_TIME_DELTA_FROM_SECONDS(15)` （偏移后的激活时间等于激活时间加上偏移量）

**3. `IterationTime` 测试用例：**

*   **假设输入：**
    *   `iteration_duration = 10s`
    *   `active_duration = 100s`
    *   `scaled_active_time = 25s`
    *   `start_offset = 4s`
    *   `timing.iteration_count = 10`
    *   `phase = Timing::kPhaseActive`
*   **预期输出：** `ANIMATION_TIME_DELTA_FROM_SECONDS(5)`  （计算公式涉及到 `(scaled_active_time + start_offset) / iteration_duration` 的小数部分乘以 `iteration_duration`）

**4. `OverallProgress` 测试用例：**

*   **假设输入：**
    *   `phase = Timing::kPhaseAfter`
    *   `active_time = 2.5s`
    *   `iteration_duration = 1s`
    *   `iteration_count = 0`
    *   `iteration_start = 0.5`
*   **预期输出：** `3.0` （整体进度计算考虑了激活时间、迭代持续时间、起始迭代和迭代次数）

**5. `CalculateDirectedProgress` 测试用例：**

*   **假设输入：**
    *   `simple_iteration_progress = 0`
    *   `current_iteration = 8`
    *   `direction = Timing::PlaybackDirection::NORMAL`
*   **预期输出：** `0` （正向播放时，单次迭代进度即为带方向的进度）

*   **假设输入：**
    *   `simple_iteration_progress = 0`
    *   `current_iteration = 8`
    *   `direction = Timing::PlaybackDirection::REVERSE`
*   **预期输出：** `1` （反向播放时，单次迭代进度为 0，带方向的进度为 1）

**涉及用户或者编程常见的使用错误：**

虽然这个文件是测试 Blink 引擎内部逻辑的，但它间接地反映了开发者在使用动画时可能遇到的错误，以及浏览器如何处理这些情况。

*   **动画属性值设置不合理：** 例如，将 `animation-duration` 设置为负数或零，或者将 `animation-iteration-count` 设置为负数。虽然 CSS 规范可能对这些值有约束，但测试用例可以帮助验证 Blink 如何处理这些异常情况，并确保不会导致崩溃或其他不可预测的行为。

*   **对动画状态的理解偏差：**  开发者可能不清楚动画在 `forwards` 或 `backwards` fill 模式下的行为，或者对 `alternate` 方向的迭代顺序理解有误。这些测试用例确保了 Blink 按照规范正确地计算动画状态，从而帮助开发者更好地理解和使用动画。

    **举例说明：**

    *   **错误使用 `fill-mode`：**  开发者可能错误地认为 `fill-mode: forwards;` 会让动画在开始前就应用第一帧的样式，而实际上它只会在动画结束后保持最后一帧的样式。`ActiveTime` 的测试用例验证了在 `Before` 阶段，`fillMode` 的不同取值对激活时间的影响。

    *   **错误理解 `animation-direction: alternate;`：**  开发者可能认为 `alternate` 方向总是从头到尾播放，然后再从尾到头播放。但如果 `animation-iteration-count` 是奇数，最后一次迭代将是正向播放。 `IsCurrentDirectionForwards` 和 `CalculateDirectedProgress` 的测试用例覆盖了这些场景。

*   **JavaScript 中操作动画状态时的错误：**  例如，在动画的延迟阶段就尝试获取动画的当前时间，或者在动画结束时错误地假设动画的 `currentTime` 为持续时间。测试用例可以帮助确保 Blink 引擎返回的动画状态与 JavaScript API 的预期行为一致。

    **举例说明：**

    *   **在延迟阶段获取 `currentTime`：**  在动画的 `start-delay` 期间，动画处于 `Before` 阶段。`ActiveTime` 的测试用例验证了在这个阶段激活时间的计算方式，这有助于理解 JavaScript 中获取到的 `currentTime` 的值。

*   **边界条件处理不当：**  例如，动画持续时间非常短或非常长，或者迭代次数非常大。测试用例中包含了一些边界情况的测试，例如激活时间或迭代持续时间接近于零或无穷大的情况，这有助于发现和修复 Blink 引擎在处理这些极端情况时的潜在问题。  例如，`IterationTime` 和 `OverallProgress` 中针对接近零的持续时间的测试用例。

总而言之，`timing_calculations_test.cc` 这个文件通过一系列细致的测试用例，确保了 Blink 引擎在处理各种动画 timing 计算时的正确性，这对于保证 Web 开发者创建的动画在不同浏览器和设备上行为一致至关重要。它也间接反映了开发者在使用 Web 动画技术时需要注意的一些细节和潜在的错误。

Prompt: 
```
这是目录为blink/renderer/core/animation/timing_calculations_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/core/animation/timing_calculations.h"

#include "base/test/metrics/histogram_tester.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/animation/animation_effect.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {

TEST(AnimationTimingCalculationsTest, ActiveTime) {
  test::TaskEnvironment task_environment;
  Timing::NormalizedTiming normalized_timing;

  // calculateActiveTime(
  //     activeDuration, fillMode, localTime, parentPhase, phase, timing)

  // Before Phase
  normalized_timing.start_delay = ANIMATION_TIME_DELTA_FROM_SECONDS(10);
  normalized_timing.active_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(20);
  EXPECT_FALSE(TimingCalculations::CalculateActiveTime(
      normalized_timing, Timing::FillMode::FORWARDS, AnimationTimeDelta(),
      Timing::kPhaseBefore));
  EXPECT_FALSE(TimingCalculations::CalculateActiveTime(
      normalized_timing, Timing::FillMode::NONE, AnimationTimeDelta(),
      Timing::kPhaseBefore));
  EXPECT_EQ(AnimationTimeDelta(),
            TimingCalculations::CalculateActiveTime(
                normalized_timing, Timing::FillMode::BACKWARDS,
                AnimationTimeDelta(), Timing::kPhaseBefore));
  EXPECT_EQ(AnimationTimeDelta(),
            TimingCalculations::CalculateActiveTime(
                normalized_timing, Timing::FillMode::BOTH, AnimationTimeDelta(),
                Timing::kPhaseBefore));
  normalized_timing.start_delay = ANIMATION_TIME_DELTA_FROM_SECONDS(-10);
  EXPECT_EQ(ANIMATION_TIME_DELTA_FROM_SECONDS(5),
            TimingCalculations::CalculateActiveTime(
                normalized_timing, Timing::FillMode::BACKWARDS,
                ANIMATION_TIME_DELTA_FROM_SECONDS(-5), Timing::kPhaseBefore));

  // Active Phase
  normalized_timing.start_delay = ANIMATION_TIME_DELTA_FROM_SECONDS(10);
  EXPECT_EQ(ANIMATION_TIME_DELTA_FROM_SECONDS(5),
            TimingCalculations::CalculateActiveTime(
                normalized_timing, Timing::FillMode::FORWARDS,
                ANIMATION_TIME_DELTA_FROM_SECONDS(15), Timing::kPhaseActive));

  // After Phase
  normalized_timing.start_delay = ANIMATION_TIME_DELTA_FROM_SECONDS(10);
  normalized_timing.active_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(21);
  EXPECT_EQ(ANIMATION_TIME_DELTA_FROM_SECONDS(21),
            TimingCalculations::CalculateActiveTime(
                normalized_timing, Timing::FillMode::FORWARDS,
                ANIMATION_TIME_DELTA_FROM_SECONDS(45), Timing::kPhaseAfter));
  EXPECT_EQ(ANIMATION_TIME_DELTA_FROM_SECONDS(21),
            TimingCalculations::CalculateActiveTime(
                normalized_timing, Timing::FillMode::BOTH,
                ANIMATION_TIME_DELTA_FROM_SECONDS(45), Timing::kPhaseAfter));
  EXPECT_FALSE(TimingCalculations::CalculateActiveTime(
      normalized_timing, Timing::FillMode::BACKWARDS,
      ANIMATION_TIME_DELTA_FROM_SECONDS(45), Timing::kPhaseAfter));
  EXPECT_FALSE(TimingCalculations::CalculateActiveTime(
      normalized_timing, Timing::FillMode::NONE,
      ANIMATION_TIME_DELTA_FROM_SECONDS(45), Timing::kPhaseAfter));

  // None
  normalized_timing.active_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(32);
  EXPECT_FALSE(TimingCalculations::CalculateActiveTime(
      normalized_timing, Timing::FillMode::NONE, std::nullopt,
      Timing::kPhaseNone));
}

TEST(AnimationTimingCalculationsTest, OffsetActiveTime) {
  test::TaskEnvironment task_environment;
  // if the active time is null
  EXPECT_FALSE(TimingCalculations::CalculateOffsetActiveTime(
      ANIMATION_TIME_DELTA_FROM_SECONDS(4), std::nullopt,
      ANIMATION_TIME_DELTA_FROM_SECONDS(5)));

  // normal case
  EXPECT_EQ(ANIMATION_TIME_DELTA_FROM_SECONDS(15),
            TimingCalculations::CalculateOffsetActiveTime(
                ANIMATION_TIME_DELTA_FROM_SECONDS(40),
                ANIMATION_TIME_DELTA_FROM_SECONDS(10),
                ANIMATION_TIME_DELTA_FROM_SECONDS(5)));

  // infinite activeTime
  EXPECT_TRUE(TimingCalculations::CalculateOffsetActiveTime(
                  AnimationTimeDelta::Max(), AnimationTimeDelta::Max(),
                  AnimationTimeDelta())
                  ->is_max());

  // Edge case for active_time being within epsilon of active_duration.
  // https://crbug.com/962138
  auto active_time = ANIMATION_TIME_DELTA_FROM_SECONDS(1.3435713716800004);
  const auto active_duration =
      ANIMATION_TIME_DELTA_FROM_SECONDS(1.3435713716800002);
  EXPECT_EQ(active_time,
            TimingCalculations::CalculateOffsetActiveTime(
                active_duration, active_time, AnimationTimeDelta()));
}

TEST(AnimationTimingCalculationsTest, IterationTime) {
  test::TaskEnvironment task_environment;
  Timing timing;

  // calculateIterationTime(
  //     iterationDuration, activeDuration, scaledActiveTime, startOffset,
  //     phase, timing)

  // if the scaled active time is null
  EXPECT_FALSE(TimingCalculations::CalculateIterationTime(
      ANIMATION_TIME_DELTA_FROM_SECONDS(1),
      ANIMATION_TIME_DELTA_FROM_SECONDS(1), std::nullopt,
      ANIMATION_TIME_DELTA_FROM_SECONDS(1), Timing::kPhaseActive, timing));

  // if (complex-conditions)...
  EXPECT_EQ(ANIMATION_TIME_DELTA_FROM_SECONDS(12),
            TimingCalculations::CalculateIterationTime(
                ANIMATION_TIME_DELTA_FROM_SECONDS(12),
                ANIMATION_TIME_DELTA_FROM_SECONDS(12),
                ANIMATION_TIME_DELTA_FROM_SECONDS(12), AnimationTimeDelta(),
                Timing::kPhaseActive, timing));

  // otherwise
  timing.iteration_count = 10;
  EXPECT_EQ(
      ANIMATION_TIME_DELTA_FROM_SECONDS(5),
      TimingCalculations::CalculateIterationTime(
          ANIMATION_TIME_DELTA_FROM_SECONDS(10),
          ANIMATION_TIME_DELTA_FROM_SECONDS(100),
          ANIMATION_TIME_DELTA_FROM_SECONDS(25),
          ANIMATION_TIME_DELTA_FROM_SECONDS(4), Timing::kPhaseActive, timing));
  EXPECT_EQ(
      ANIMATION_TIME_DELTA_FROM_SECONDS(7),
      TimingCalculations::CalculateIterationTime(
          ANIMATION_TIME_DELTA_FROM_SECONDS(11),
          ANIMATION_TIME_DELTA_FROM_SECONDS(110),
          ANIMATION_TIME_DELTA_FROM_SECONDS(29),
          ANIMATION_TIME_DELTA_FROM_SECONDS(1), Timing::kPhaseActive, timing));
  timing.iteration_start = 1.1;
  EXPECT_EQ(
      ANIMATION_TIME_DELTA_FROM_SECONDS(8),
      TimingCalculations::CalculateIterationTime(
          ANIMATION_TIME_DELTA_FROM_SECONDS(12),
          ANIMATION_TIME_DELTA_FROM_SECONDS(120),
          ANIMATION_TIME_DELTA_FROM_SECONDS(20),
          ANIMATION_TIME_DELTA_FROM_SECONDS(7), Timing::kPhaseActive, timing));

  // Edge case for offset_active_time being within epsilon of (active_duration
  // + start_offset). https://crbug.com/962138
  timing.iteration_count = 1;
  const AnimationTimeDelta offset_active_time =
      ANIMATION_TIME_DELTA_FROM_SECONDS(1.3435713716800004);
  const AnimationTimeDelta iteration_duration =
      ANIMATION_TIME_DELTA_FROM_SECONDS(1.3435713716800002);
  const AnimationTimeDelta active_duration =
      ANIMATION_TIME_DELTA_FROM_SECONDS(1.3435713716800002);
  EXPECT_NEAR(2.22045e-16,
              TimingCalculations::CalculateIterationTime(
                  iteration_duration, active_duration, offset_active_time,
                  AnimationTimeDelta(), Timing::kPhaseActive, timing)
                  ->InSecondsF(),
              std::numeric_limits<float>::epsilon());
}

TEST(AnimationTimingCalculationsTest, OverallProgress) {
  test::TaskEnvironment task_environment;
  // If the active time is null.
  EXPECT_FALSE(TimingCalculations::CalculateOverallProgress(
      Timing::kPhaseAfter,
      /*active_time=*/std::nullopt,
      /*iteration_duration=*/ANIMATION_TIME_DELTA_FROM_SECONDS(1.0),
      /*iteration_count=*/1.0,
      /*iteration_start=*/1.0));

  // If iteration duration is zero, calculate progress based on iteration count.
  EXPECT_EQ(3, TimingCalculations::CalculateOverallProgress(
                   Timing::kPhaseActive,
                   /*active_time=*/ANIMATION_TIME_DELTA_FROM_SECONDS(3.0),
                   /*iteration_duration=*/AnimationTimeDelta(),
                   /*iteration_count=*/3.0,
                   /*iteration_start=*/0.0));
  // ...unless in before phase, in which case progress is zero.
  EXPECT_EQ(0, TimingCalculations::CalculateOverallProgress(
                   Timing::kPhaseBefore,
                   /*active_time=*/ANIMATION_TIME_DELTA_FROM_SECONDS(3.0),
                   /*iteration_duration=*/AnimationTimeDelta(),
                   /*iteration_count=*/3.0,
                   /*iteration_start=*/0.0));
  // Edge case for duration being within Epsilon of zero.
  // crbug.com/954558
  EXPECT_EQ(1,
            TimingCalculations::CalculateOverallProgress(
                Timing::kPhaseActive,
                /*active_time=*/ANIMATION_TIME_DELTA_FROM_SECONDS(3.0),
                /*iteration_duration=*/ANIMATION_TIME_DELTA_FROM_SECONDS(1e-18),
                /*iteration_count=*/1.0,
                /*iteration_start=*/0.0));

  // Otherwise.
  EXPECT_EQ(3.0,
            TimingCalculations::CalculateOverallProgress(
                Timing::kPhaseAfter,
                /*active_time=*/ANIMATION_TIME_DELTA_FROM_SECONDS(2.5),
                /*iteration_duration=*/ANIMATION_TIME_DELTA_FROM_SECONDS(1.0),
                /*iteration_count=*/0.0,
                /*iteration_start=*/0.5));
}

TEST(AnimationTimingCalculationsTest, CalculateSimpleIterationProgress) {
  test::TaskEnvironment task_environment;
  // If the overall progress is null.
  EXPECT_FALSE(TimingCalculations::CalculateSimpleIterationProgress(
      Timing::kPhaseAfter,
      /*overall_progress=*/std::nullopt,
      /*iteration_start=*/1.0,
      /*active_time=*/std::nullopt,
      /*active_duration=*/ANIMATION_TIME_DELTA_FROM_SECONDS(1.0),
      /*iteration_count=*/1.0));

  // If the overall progress is infinite.
  const double inf = std::numeric_limits<double>::infinity();
  EXPECT_EQ(0.5, TimingCalculations::CalculateSimpleIterationProgress(
                     Timing::kPhaseAfter,
                     /*overall_progress=*/inf,
                     /*iteration_start=*/1.5,
                     /*active_time=*/AnimationTimeDelta(),
                     /*active_duration=*/AnimationTimeDelta(),
                     /*iteration_count=*/inf));

  // Precisely on an iteration boundary.
  EXPECT_EQ(1.0, TimingCalculations::CalculateSimpleIterationProgress(
                     Timing::kPhaseAfter,
                     /*overall_progress=*/3.0,
                     /*iteration_start=*/0.0,
                     /*active_time=*/ANIMATION_TIME_DELTA_FROM_SECONDS(3.0),
                     /*active_duration=*/ANIMATION_TIME_DELTA_FROM_SECONDS(3.0),
                     /*iteration_count=*/3.0));

  // Otherwise.
  EXPECT_EQ(0.5, TimingCalculations::CalculateSimpleIterationProgress(
                     Timing::kPhaseAfter,
                     /*overall_progress=*/2.5,
                     /*iteration_start=*/0.0,
                     /*active_time=*/ANIMATION_TIME_DELTA_FROM_SECONDS(2.5),
                     /*active_duration=*/AnimationTimeDelta(),
                     /*iteration_count=*/0.0));
}

TEST(AnimationTimingCalculationsTest, CurrentIteration) {
  test::TaskEnvironment task_environment;
  // If the active time is null.
  EXPECT_FALSE(TimingCalculations::CalculateCurrentIteration(
      Timing::kPhaseAfter,
      /*active_time=*/std::nullopt,
      /*iteration_count=*/1.0,
      /*overall_progress=*/std::nullopt,
      /*simple_iteration_progress=*/0));

  // If the iteration count is infinite.
  const double inf = std::numeric_limits<double>::infinity();
  EXPECT_EQ(inf, TimingCalculations::CalculateCurrentIteration(
                     Timing::kPhaseAfter,
                     /*active_time=*/ANIMATION_TIME_DELTA_FROM_SECONDS(1.0),
                     /*iteration_count=*/inf,
                     /*overall_progress=*/inf,
                     /*simple_iteration_progress=*/0.0));

  // Hold the endpoint of the final iteration of ending precisely on an
  // iteration boundary.
  EXPECT_EQ(2, TimingCalculations::CalculateCurrentIteration(
                   Timing::kPhaseAfter,
                   /*active_time=*/ANIMATION_TIME_DELTA_FROM_SECONDS(3.0),
                   /*iteration_count=*/3.0,
                   /*overall_progress=*/3.0,
                   /*simple_iteration_progress=*/1.0));

  // Edge case for zero-duration animation.
  // crbug.com/954558
  EXPECT_EQ(0, TimingCalculations::CalculateCurrentIteration(
                   Timing::kPhaseAfter,
                   /*active_time=*/AnimationTimeDelta(),
                   /*iteration_count=*/1.0,
                   /*overall_progress=*/0.0,
                   /*simple_iteration_progress=*/1.0));

  // Otherwise.
  EXPECT_EQ(2, TimingCalculations::CalculateCurrentIteration(
                   Timing::kPhaseAfter,
                   /*active_time=*/ANIMATION_TIME_DELTA_FROM_SECONDS(2.5),
                   /*iteration_count=*/0.0,
                   /*overall_progress=*/2.5,
                   /*simple_iteration_progress=*/0.5));
}

TEST(AnimationTimingCalculationsTest, IsCurrentDirectionForwards) {
  test::TaskEnvironment task_environment;
  // IsCurrentDirectionForwards(current_iteration,
  //                            direction);

  EXPECT_TRUE(TimingCalculations::IsCurrentDirectionForwards(
      0, Timing::PlaybackDirection::NORMAL));
  EXPECT_TRUE(TimingCalculations::IsCurrentDirectionForwards(
      1, Timing::PlaybackDirection::NORMAL));
  EXPECT_TRUE(TimingCalculations::IsCurrentDirectionForwards(
      0, Timing::PlaybackDirection::ALTERNATE_NORMAL));
  EXPECT_TRUE(TimingCalculations::IsCurrentDirectionForwards(
      1, Timing::PlaybackDirection::ALTERNATE_REVERSE));

  EXPECT_FALSE(TimingCalculations::IsCurrentDirectionForwards(
      0, Timing::PlaybackDirection::REVERSE));
  EXPECT_FALSE(TimingCalculations::IsCurrentDirectionForwards(
      1, Timing::PlaybackDirection::REVERSE));
  EXPECT_FALSE(TimingCalculations::IsCurrentDirectionForwards(
      0, Timing::PlaybackDirection::ALTERNATE_REVERSE));
  EXPECT_FALSE(TimingCalculations::IsCurrentDirectionForwards(
      1, Timing::PlaybackDirection::ALTERNATE_NORMAL));
}

TEST(AnimationTimingCalculationsTest, CalculateDirectedProgress) {
  test::TaskEnvironment task_environment;
  // CalculateDirectedProgress(simple_iteration_progress,
  //                           current_iteration,
  //                           direction);

  // if the simple iteration progress is null
  EXPECT_FALSE(TimingCalculations::CalculateDirectedProgress(
      std::nullopt, std::nullopt, Timing::PlaybackDirection::NORMAL));

  // forwards
  EXPECT_EQ(0, TimingCalculations::CalculateDirectedProgress(
                   0, 8, Timing::PlaybackDirection::NORMAL));
  EXPECT_EQ(1, TimingCalculations::CalculateDirectedProgress(
                   1, 8, Timing::PlaybackDirection::NORMAL));
  EXPECT_EQ(0, TimingCalculations::CalculateDirectedProgress(
                   0, 9, Timing::PlaybackDirection::NORMAL));
  EXPECT_EQ(1, TimingCalculations::CalculateDirectedProgress(
                   1, 9, Timing::PlaybackDirection::NORMAL));
  EXPECT_EQ(0, TimingCalculations::CalculateDirectedProgress(
                   0, 8, Timing::PlaybackDirection::ALTERNATE_NORMAL));
  EXPECT_EQ(1, TimingCalculations::CalculateDirectedProgress(
                   1, 8, Timing::PlaybackDirection::ALTERNATE_NORMAL));
  EXPECT_EQ(0, TimingCalculations::CalculateDirectedProgress(
                   0, 9, Timing::PlaybackDirection::ALTERNATE_REVERSE));
  EXPECT_EQ(1, TimingCalculations::CalculateDirectedProgress(
                   1, 9, Timing::PlaybackDirection::ALTERNATE_REVERSE));

  // reverse
  EXPECT_EQ(1, TimingCalculations::CalculateDirectedProgress(
                   0, 8, Timing::PlaybackDirection::REVERSE));
  EXPECT_EQ(0, TimingCalculations::CalculateDirectedProgress(
                   1, 8, Timing::PlaybackDirection::REVERSE));
  EXPECT_EQ(1, TimingCalculations::CalculateDirectedProgress(
                   0, 9, Timing::PlaybackDirection::REVERSE));
  EXPECT_EQ(0, TimingCalculations::CalculateDirectedProgress(
                   1, 9, Timing::PlaybackDirection::REVERSE));
  EXPECT_EQ(1, TimingCalculations::CalculateDirectedProgress(
                   0, 9, Timing::PlaybackDirection::ALTERNATE_NORMAL));
  EXPECT_EQ(0, TimingCalculations::CalculateDirectedProgress(
                   1, 9, Timing::PlaybackDirection::ALTERNATE_NORMAL));
  EXPECT_EQ(1, TimingCalculations::CalculateDirectedProgress(
                   0, 8, Timing::PlaybackDirection::ALTERNATE_REVERSE));
  EXPECT_EQ(0, TimingCalculations::CalculateDirectedProgress(
                   1, 8, Timing::PlaybackDirection::ALTERNATE_REVERSE));
}

TEST(AnimationTimingCalculationsTest, TransformedProgress) {
  test::TaskEnvironment task_environment;
  // CalculateTransformedProgress(
  //     phase, directed_progress,
  //     is_current_direction_forward, timing_function)

  scoped_refptr<TimingFunction> timing_function =
      StepsTimingFunction::Create(4, StepsTimingFunction::StepPosition::END);

  // directed_progress is null.
  EXPECT_FALSE(TimingCalculations::CalculateTransformedProgress(
      Timing::kPhaseActive, std::nullopt, true, timing_function));

  // At step boundaries.
  // Forward direction.
  EXPECT_EQ(0, TimingCalculations::CalculateTransformedProgress(
                   Timing::kPhaseBefore, 0, true, timing_function));
  EXPECT_EQ(0, TimingCalculations::CalculateTransformedProgress(
                   Timing::kPhaseBefore, 0.25, true, timing_function));
  EXPECT_EQ(0.25, TimingCalculations::CalculateTransformedProgress(
                      Timing::kPhaseAfter, 0.25, true, timing_function));
  EXPECT_EQ(0.25, TimingCalculations::CalculateTransformedProgress(
                      Timing::kPhaseBefore, 0.5, true, timing_function));
  EXPECT_EQ(0.5, TimingCalculations::CalculateTransformedProgress(
                     Timing::kPhaseAfter, 0.5, true, timing_function));
  EXPECT_EQ(0.5, TimingCalculations::CalculateTransformedProgress(
                     Timing::kPhaseBefore, 0.75, true, timing_function));
  EXPECT_EQ(0.75, TimingCalculations::CalculateTransformedProgress(
                      Timing::kPhaseAfter, 0.75, true, timing_function));
  EXPECT_EQ(0.75, TimingCalculations::CalculateTransformedProgress(
                      Timing::kPhaseBefore, 1, true, timing_function));
  EXPECT_EQ(1, TimingCalculations::CalculateTransformedProgress(
                   Timing::kPhaseAfter, 1, true, timing_function));
  // Reverse direction.
  EXPECT_EQ(1, TimingCalculations::CalculateTransformedProgress(
                   Timing::kPhaseBefore, 1, false, timing_function));
  EXPECT_EQ(0.75, TimingCalculations::CalculateTransformedProgress(
                      Timing::kPhaseAfter, 1, false, timing_function));
  EXPECT_EQ(0.75, TimingCalculations::CalculateTransformedProgress(
                      Timing::kPhaseBefore, 0.75, false, timing_function));
  EXPECT_EQ(0.5, TimingCalculations::CalculateTransformedProgress(
                     Timing::kPhaseAfter, 0.75, false, timing_function));
  EXPECT_EQ(0.5, TimingCalculations::CalculateTransformedProgress(
                     Timing::kPhaseBefore, 0.5, false, timing_function));
  EXPECT_EQ(0.25, TimingCalculations::CalculateTransformedProgress(
                      Timing::kPhaseAfter, 0.5, false, timing_function));
  EXPECT_EQ(0.25, TimingCalculations::CalculateTransformedProgress(
                      Timing::kPhaseBefore, 0.25, false, timing_function));
  EXPECT_EQ(0, TimingCalculations::CalculateTransformedProgress(
                   Timing::kPhaseAfter, 0.25, false, timing_function));

  // Edges cases
  EXPECT_EQ(1, TimingCalculations::CalculateTransformedProgress(
                   Timing::kPhaseAfter, 1 - 1e-16, true, timing_function));
  scoped_refptr<TimingFunction> step_start_timing_function =
      StepsTimingFunction::Create(4, StepsTimingFunction::StepPosition::START);
  EXPECT_EQ(0,
            TimingCalculations::CalculateTransformedProgress(
                Timing::kPhaseAfter, 1e-16, false, step_start_timing_function));
}

TEST(AnimationTimingCalculationsTest, AlignmentHistogram) {
  test::TaskEnvironment task_environment;
  Timing::NormalizedTiming normalized_timing;
  normalized_timing.active_duration = ANIMATION_TIME_DELTA_FROM_MILLISECONDS(1);
  normalized_timing.end_time = ANIMATION_TIME_DELTA_FROM_SECONDS(1);
  std::optional<AnimationTimeDelta> local_time =
      ANIMATION_TIME_DELTA_FROM_MILLISECONDS(1);

  const std::string histogram_name = "Blink.Animation.SDA.BoundaryMisalignment";
  base::HistogramTester histogram_tester;

  EXPECT_EQ(Timing::kPhaseAfter, TimingCalculations::CalculatePhase(
                                     normalized_timing, local_time,
                                     Timing::AnimationDirection::kForwards));
  histogram_tester.ExpectBucketCount(histogram_name, 0, 0);

  normalized_timing.is_start_boundary_aligned = true;
  EXPECT_EQ(Timing::kPhaseAfter, TimingCalculations::CalculatePhase(
                                     normalized_timing, local_time,
                                     Timing::AnimationDirection::kForwards));
  histogram_tester.ExpectBucketCount(histogram_name, 0, 0);

  normalized_timing.is_end_boundary_aligned = true;
  EXPECT_EQ(Timing::kPhaseActive, TimingCalculations::CalculatePhase(
                                      normalized_timing, local_time,
                                      Timing::AnimationDirection::kForwards));
  histogram_tester.ExpectBucketCount(histogram_name, 0, 0);

  local_time = ANIMATION_TIME_DELTA_FROM_MILLISECONDS(1.003);
  EXPECT_EQ(Timing::kPhaseAfter, TimingCalculations::CalculatePhase(
                                     normalized_timing, local_time,
                                     Timing::AnimationDirection::kForwards));
  histogram_tester.ExpectBucketCount(histogram_name, 3, 1);

  // Repeat and ensure the counter increments.
  EXPECT_EQ(Timing::kPhaseAfter, TimingCalculations::CalculatePhase(
                                     normalized_timing, local_time,
                                     Timing::AnimationDirection::kForwards));
  histogram_tester.ExpectBucketCount(histogram_name, 3, 2);

  normalized_timing.is_end_boundary_aligned = false;
  EXPECT_EQ(Timing::kPhaseAfter, TimingCalculations::CalculatePhase(
                                     normalized_timing, local_time,
                                     Timing::AnimationDirection::kForwards));
  // Value remains unchanged.
  histogram_tester.ExpectBucketCount(histogram_name, 3, 2);

  local_time = ANIMATION_TIME_DELTA_FROM_MILLISECONDS(0);
  EXPECT_EQ(Timing::kPhaseActive, TimingCalculations::CalculatePhase(
                                      normalized_timing, local_time,
                                      Timing::AnimationDirection::kBackwards));
  histogram_tester.ExpectBucketCount(histogram_name, 0, 0);

  normalized_timing.is_start_boundary_aligned = false;
  EXPECT_EQ(Timing::kPhaseBefore, TimingCalculations::CalculatePhase(
                                      normalized_timing, local_time,
                                      Timing::AnimationDirection::kBackwards));
  histogram_tester.ExpectBucketCount(histogram_name, 0, 0);

  normalized_timing.is_start_boundary_aligned = true;
  local_time = ANIMATION_TIME_DELTA_FROM_MILLISECONDS(-0.005);
  EXPECT_EQ(Timing::kPhaseBefore, TimingCalculations::CalculatePhase(
                                      normalized_timing, local_time,
                                      Timing::AnimationDirection::kBackwards));
  histogram_tester.ExpectBucketCount(histogram_name, 5, 1);

  normalized_timing.is_start_boundary_aligned = false;
  EXPECT_EQ(Timing::kPhaseBefore, TimingCalculations::CalculatePhase(
                                      normalized_timing, local_time,
                                      Timing::AnimationDirection::kBackwards));
  // Value remains unchanged.
  histogram_tester.ExpectBucketCount(histogram_name, 5, 1);
}

}  // namespace blink

"""

```