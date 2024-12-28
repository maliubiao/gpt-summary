Response:
The user wants a summary of the provided C++ source code file: `animation_effect_test.cc`.
This file appears to contain unit tests for the `AnimationEffect` class in the Blink rendering engine.

Here's a plan to generate the summary:

1. **Identify the core purpose:** The file tests the functionality of the `AnimationEffect` class.
2. **List key functionalities tested:** Look for `TEST` macros and their descriptions to identify the features being tested. These seem to revolve around timing properties and the effect's lifecycle.
3. **Check for relationships with web technologies:**  Note any mentions of timing, duration, iterations, fill modes, directions, etc., as these are concepts shared with CSS Animations and the Web Animations API.
4. **Look for logical reasoning:**  The tests themselves represent logical reasoning by setting up specific conditions (inputs) and verifying expected outcomes (outputs).
5. **Identify potential user/programming errors:**  Look for tests that specifically check for invalid inputs or edge cases that might lead to errors.
6. **Synthesize the findings into a concise summary.**
这是名为 `animation_effect_test.cc` 的 C++ 文件，属于 Chromium Blink 引擎，其主要功能是**对 `AnimationEffect` 类进行单元测试**。

以下是根据代码内容进行的详细功能列举和分析：

**1. 核心功能：测试 `AnimationEffect` 类的行为和状态**

这个文件包含多个 `TEST` 宏，每个 `TEST` 对应一个或一组针对 `AnimationEffect` 特定功能的测试用例。  这些测试用例旨在验证 `AnimationEffect` 在不同时间输入和配置下的状态和行为是否符合预期。

**2. 与 JavaScript, HTML, CSS 功能的关系 (及其举例说明):**

`AnimationEffect` 类是 Blink 引擎中处理动画效果的核心组件，它直接关联到 Web 标准中的 CSS 动画和 Web Animations API。 这些测试用例模拟了通过 CSS 或 JavaScript 设置动画属性后，`AnimationEffect` 应该如何响应。

*   **CSS `animation-duration` (持续时间):**
    *   测试用例 `Sanity`、`FillAuto` 等都涉及到设置 `timing.iteration_duration`，这模拟了 CSS `animation-duration` 属性。测试会验证在指定持续时间后，动画的状态 (如 `GetPhase()`, `IsInPlay()`, `Progress()`) 是否正确。
    *   **假设输入/输出:** 如果 CSS 设置了 `animation-duration: 2s;`，则测试会模拟在时间 0s、1s、2s 等时刻，`AnimationEffect` 的 `Progress()` 方法返回值是否分别为 0, 0.5, 1。

*   **CSS `animation-fill-mode` (填充模式):**
    *   测试用例 `FillAuto`、`FillForwards`、`FillBackwards`、`FillBoth` 测试了 `timing.fill_mode`，对应 CSS 的 `animation-fill-mode` 属性 (如 `forwards`, `backwards`, `both`, `auto`)。这些测试验证了动画在开始延迟之前和结束后如何应用样式。
    *   **假设输入/输出:** 如果 CSS 设置了 `animation-fill-mode: forwards;`，并且动画持续 1 秒，测试会验证在时间 -1 秒时，动画的 `Progress()` 是否为空 (或特定初始状态)，在 2 秒时 `Progress()` 是否为 1。

*   **CSS `animation-delay` (延迟):**
    *   测试用例 `StartDelay` 测试了 `timing.start_delay`，对应 CSS 的 `animation-delay` 属性。它验证了动画是否会在指定延迟后才开始生效。
    *   **假设输入/输出:** 如果 CSS 设置了 `animation-delay: 0.5s;`，测试会验证在时间 0 秒时，动画的 `Progress()` 是否为空，而在 0.5 秒时 `Progress()` 是否为 0。

*   **CSS `animation-iteration-count` (迭代次数):**
    *   测试用例 `ZeroIteration`、`InfiniteIteration`、`Iteration` 测试了 `timing.iteration_count`，对应 CSS 的 `animation-iteration-count` 属性 (如数字或 `infinite`)。测试验证了动画循环的次数和行为。
    *   **假设输入/输出:** 如果 CSS 设置了 `animation-iteration-count: 2;`，动画持续 2 秒，测试会验证在时间 0 秒时 `CurrentIteration()` 为 0，在 2 秒时 `CurrentIteration()` 为 1，在 5 秒时 `CurrentIteration()` 仍然为 1。

*   **CSS `animation-direction` (播放方向):**
    *   测试用例 `IterationAlternate`、`IterationAlternateReverse` 测试了 `timing.direction`，对应 CSS 的 `animation-direction` 属性 (如 `normal`, `reverse`, `alternate`, `alternate-reverse`)。测试验证了动画在不同迭代中播放方向的变化。
    *   **假设输入/输出:** 如果 CSS 设置了 `animation-direction: alternate;`，动画持续 1 秒，测试会验证在时间 0.75 秒时 `Progress()` 为 0.75，在时间 1.75 秒时 `Progress()` 为 0.25 (反向播放)。

*   **CSS `animation-timing-function` (缓动函数):**
    *   测试用例 `UpdateTiming` 中设置 `effect_timing->setEasing("ease-in-out")` 模拟了 CSS 的 `animation-timing-function` 属性。虽然当前的测试并没有直接验证缓动函数的计算结果，但它展示了如何设置相关的属性。

*   **Web Animations API:**  `AnimationEffect` 类也是 Web Animations API 的底层实现之一。JavaScript 可以通过 `Element.animate()` 方法创建动画，该方法最终会创建和操作 `AnimationEffect` 对象。

**3. 逻辑推理 (及其假设输入与输出):**

每个测试用例都包含逻辑推理，通过设置特定的 `Timing` 属性 (假设输入)，然后断言 `AnimationEffect` 的状态 (输出) 是否符合预期。  上面的 "与 JavaScript, HTML, CSS 功能的关系" 部分的举例已经包含了假设输入和输出。

**4. 涉及用户或者编程常见的使用错误 (及其举例说明):**

虽然这个测试文件主要关注 `AnimationEffect` 内部逻辑，但也间接反映了一些用户或编程中可能出现的错误配置：

*   **错误的迭代开始值 (`iterationStart`):**  测试用例 `IterationStart` 演示了 `iterationStart` 的使用。如果用户在 CSS 或 JavaScript 中设置了不合理的 `iteration-start` 值 (例如负数，尽管通常会被规范化为非负)，可能会导致动画行为不符合预期。
    *   **举例说明:** 如果用户设置 `animation-iteration-start: -1;`，虽然 CSS 可能会将其处理为 0，但在理解动画逻辑时，可能会产生混淆。

*   **持续时间为零的动画 (`ZeroDuration...` 测试用例):** 这些测试用例覆盖了 `iteration_duration` 为 0 的情况。虽然这是允许的，但用户可能不理解其行为，例如动画会立即跳到结束状态。
    *   **举例说明:** 用户可能错误地认为 `animation-duration: 0s;` 的动画会保持初始状态，但实际上它会立刻完成。

*   **无限迭代与零持续时间的组合 (`ZeroDurationInfiniteIteration`):**  虽然技术上可行，但这种组合可能不是用户期望的行为，需要特殊处理。

*   **不正确的 `fill-mode` 设置:** 用户可能不理解 `forwards`、`backwards`、`both` 和 `auto` 的区别，导致动画在开始或结束后出现意外的样式。

**5. 功能归纳 (第 1 部分):**

这部分代码主要功能是 **为 `AnimationEffect` 类提供全面的单元测试**，覆盖了其核心的 timing 属性 (duration, delay, fill-mode, iteration-count, iteration-start, direction) 在不同场景下的行为。它通过模拟不同的时间输入和配置，验证 `AnimationEffect` 的状态变化 (例如 phase, inPlay, isCurrent, progress, currentIteration) 是否与预期一致。 这些测试用例间接验证了 Blink 引擎对 CSS 动画和 Web Animations API 相关规范的实现是否正确。  其中还包含了一个用于测试事件触发的委托类 `TestAnimationEffectEventDelegate`。

总体而言，这个文件是 Blink 引擎中动画功能健壮性的重要保障，确保了动画效果在各种配置下都能正确运行。

Prompt: 
```
这是目录为blink/renderer/core/animation/animation_effect_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

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

#include "third_party/blink/renderer/core/animation/animation_effect.h"

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_computed_effect_timing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_optional_effect_timing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_timeline_range_offset.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_cssnumericvalue_string_unrestricteddouble.h"
#include "third_party/blink/renderer/core/animation/animation_effect_owner.h"
#include "third_party/blink/renderer/core/animation/timing.h"
#include "third_party/blink/renderer/core/css/cssom/css_unit_values.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {

Timing::V8Delay* CreateTimeDelay(double delay_in_ms) {
  return MakeGarbageCollected<Timing::V8Delay>(delay_in_ms);
}

class MockAnimationEffectOwner
    : public GarbageCollected<MockAnimationEffectOwner>,
      public AnimationEffectOwner {
 public:
  MOCK_CONST_METHOD0(SequenceNumber, unsigned());
  MOCK_CONST_METHOD0(Playing, bool());
  MOCK_CONST_METHOD0(IsEventDispatchAllowed, bool());
  MOCK_CONST_METHOD0(EffectSuppressed, bool());
  MOCK_CONST_METHOD0(ReplaceStateRemoved, bool());
  MOCK_METHOD0(EffectInvalidated, void());
  MOCK_METHOD0(UpdateIfNecessary, void());
  MOCK_METHOD0(GetAnimation, Animation*());
};

class TestAnimationEffectEventDelegate : public AnimationEffect::EventDelegate {
 public:
  void OnEventCondition(const AnimationEffect& animation_node,
                        Timing::Phase current_phase) override {
    event_triggered_ = true;
  }
  bool RequiresIterationEvents(const AnimationEffect& animation_node) override {
    return true;
  }
  void Reset() { event_triggered_ = false; }
  bool EventTriggered() { return event_triggered_; }

 private:
  bool event_triggered_;
};

class TestAnimationEffect : public AnimationEffect {
 public:
  TestAnimationEffect(
      const Timing& specified,
      TestAnimationEffectEventDelegate* event_delegate =
          MakeGarbageCollected<TestAnimationEffectEventDelegate>())
      : AnimationEffect(specified, event_delegate),
        event_delegate_(event_delegate) {}

  void UpdateInheritedTime(double time) {
    UpdateInheritedTime(time, kTimingUpdateForAnimationFrame);
  }

  void UpdateInheritedTime(double time, TimingUpdateReason reason) {
    event_delegate_->Reset();
    AnimationEffect::UpdateInheritedTime(
        ANIMATION_TIME_DELTA_FROM_SECONDS(time),
        /* is_idle */ false,
        /* inherited_playback_rate */ 1.0, reason);
  }

  bool Affects(const PropertyHandle&) const override { return false; }
  void UpdateChildrenAndEffects() const override {}
  void WillDetach() {}
  TestAnimationEffectEventDelegate* EventDelegate() {
    return event_delegate_.Get();
  }
  AnimationTimeDelta CalculateTimeToEffectChange(
      bool forwards,
      std::optional<AnimationTimeDelta> local_time,
      AnimationTimeDelta time_to_next_iteration) const override {
    local_time_ = local_time;
    time_to_next_iteration_ = time_to_next_iteration;
    return AnimationTimeDelta::Max();
  }
  std::optional<AnimationTimeDelta> TimelineDuration() const override {
    return std::nullopt;
  }
  double TakeLocalTime() {
    DCHECK(local_time_);
    const double result = local_time_->InSecondsF();
    local_time_.reset();
    return result;
  }

  std::optional<AnimationTimeDelta> TakeTimeToNextIteration() {
    const std::optional<AnimationTimeDelta> result = time_to_next_iteration_;
    time_to_next_iteration_.reset();
    return result;
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(event_delegate_);
    AnimationEffect::Trace(visitor);
  }

 private:
  Member<TestAnimationEffectEventDelegate> event_delegate_;
  mutable std::optional<AnimationTimeDelta> local_time_;
  mutable std::optional<AnimationTimeDelta> time_to_next_iteration_;
};

TEST(AnimationAnimationEffectTest, Sanity) {
  test::TaskEnvironment task_environment;
  Timing timing;
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(2);
  auto* animation_node = MakeGarbageCollected<TestAnimationEffect>(timing);

  animation_node->UpdateInheritedTime(0);

  EXPECT_EQ(Timing::kPhaseActive, animation_node->GetPhase());
  EXPECT_TRUE(animation_node->IsInPlay());
  EXPECT_TRUE(animation_node->IsCurrent());
  EXPECT_TRUE(animation_node->IsInEffect());
  EXPECT_EQ(0, animation_node->CurrentIteration());
  EXPECT_EQ(ANIMATION_TIME_DELTA_FROM_SECONDS(2),
            animation_node->NormalizedTiming().active_duration);
  EXPECT_EQ(0, animation_node->Progress());

  animation_node->UpdateInheritedTime(1);

  EXPECT_EQ(Timing::kPhaseActive, animation_node->GetPhase());
  EXPECT_TRUE(animation_node->IsInPlay());
  EXPECT_TRUE(animation_node->IsCurrent());
  EXPECT_TRUE(animation_node->IsInEffect());
  EXPECT_EQ(0, animation_node->CurrentIteration());
  EXPECT_EQ(ANIMATION_TIME_DELTA_FROM_SECONDS(2),
            animation_node->NormalizedTiming().active_duration);
  EXPECT_EQ(0.5, animation_node->Progress());

  animation_node->UpdateInheritedTime(2);

  EXPECT_EQ(Timing::kPhaseAfter, animation_node->GetPhase());
  EXPECT_FALSE(animation_node->IsInPlay());
  EXPECT_FALSE(animation_node->IsCurrent());
  EXPECT_TRUE(animation_node->IsInEffect());
  EXPECT_EQ(0, animation_node->CurrentIteration());
  EXPECT_EQ(ANIMATION_TIME_DELTA_FROM_SECONDS(2),
            animation_node->NormalizedTiming().active_duration);
  EXPECT_EQ(1, animation_node->Progress());

  animation_node->UpdateInheritedTime(3);

  EXPECT_EQ(Timing::kPhaseAfter, animation_node->GetPhase());
  EXPECT_FALSE(animation_node->IsInPlay());
  EXPECT_FALSE(animation_node->IsCurrent());
  EXPECT_TRUE(animation_node->IsInEffect());
  EXPECT_EQ(0, animation_node->CurrentIteration());
  EXPECT_EQ(ANIMATION_TIME_DELTA_FROM_SECONDS(2),
            animation_node->NormalizedTiming().active_duration);
  EXPECT_EQ(1, animation_node->Progress());
}

TEST(AnimationAnimationEffectTest, FillAuto) {
  test::TaskEnvironment task_environment;
  Timing timing;
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(1);
  auto* animation_node = MakeGarbageCollected<TestAnimationEffect>(timing);

  animation_node->UpdateInheritedTime(-1);
  EXPECT_EQ(0, animation_node->Progress());

  animation_node->UpdateInheritedTime(2);
  EXPECT_EQ(1, animation_node->Progress());
}

TEST(AnimationAnimationEffectTest, FillForwards) {
  test::TaskEnvironment task_environment;
  Timing timing;
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(1);
  timing.fill_mode = Timing::FillMode::FORWARDS;
  auto* animation_node = MakeGarbageCollected<TestAnimationEffect>(timing);

  animation_node->UpdateInheritedTime(-1);
  EXPECT_FALSE(animation_node->Progress());

  animation_node->UpdateInheritedTime(2);
  EXPECT_EQ(1, animation_node->Progress());
}

TEST(AnimationAnimationEffectTest, FillBackwards) {
  test::TaskEnvironment task_environment;
  Timing timing;
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(1);
  timing.fill_mode = Timing::FillMode::BACKWARDS;
  auto* animation_node = MakeGarbageCollected<TestAnimationEffect>(timing);

  animation_node->UpdateInheritedTime(-1);
  EXPECT_EQ(0, animation_node->Progress());

  animation_node->UpdateInheritedTime(2);
  EXPECT_FALSE(animation_node->Progress());
}

TEST(AnimationAnimationEffectTest, FillBoth) {
  test::TaskEnvironment task_environment;
  Timing timing;
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(1);
  timing.fill_mode = Timing::FillMode::BOTH;
  auto* animation_node = MakeGarbageCollected<TestAnimationEffect>(timing);

  animation_node->UpdateInheritedTime(-1);
  EXPECT_EQ(0, animation_node->Progress());

  animation_node->UpdateInheritedTime(2);
  EXPECT_EQ(1, animation_node->Progress());
}

TEST(AnimationAnimationEffectTest, StartDelay) {
  test::TaskEnvironment task_environment;
  Timing timing;
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(1);
  timing.fill_mode = Timing::FillMode::FORWARDS;
  timing.start_delay = Timing::Delay(ANIMATION_TIME_DELTA_FROM_SECONDS(0.5));
  auto* animation_node = MakeGarbageCollected<TestAnimationEffect>(timing);

  animation_node->UpdateInheritedTime(0);
  EXPECT_FALSE(animation_node->Progress());

  animation_node->UpdateInheritedTime(0.5);
  EXPECT_EQ(0, animation_node->Progress());

  animation_node->UpdateInheritedTime(1.5);
  EXPECT_EQ(1, animation_node->Progress());
}

TEST(AnimationAnimationEffectTest, ZeroIteration) {
  test::TaskEnvironment task_environment;
  Timing timing;
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(1);
  timing.fill_mode = Timing::FillMode::FORWARDS;
  timing.iteration_count = 0;
  auto* animation_node = MakeGarbageCollected<TestAnimationEffect>(timing);

  animation_node->UpdateInheritedTime(-1);
  EXPECT_EQ(AnimationTimeDelta(),
            animation_node->NormalizedTiming().active_duration);
  EXPECT_FALSE(animation_node->CurrentIteration());
  EXPECT_FALSE(animation_node->Progress());

  animation_node->UpdateInheritedTime(0);
  EXPECT_EQ(AnimationTimeDelta(),
            animation_node->NormalizedTiming().active_duration);
  EXPECT_EQ(0, animation_node->CurrentIteration());
  EXPECT_EQ(0, animation_node->Progress());
}

TEST(AnimationAnimationEffectTest, InfiniteIteration) {
  test::TaskEnvironment task_environment;
  Timing timing;
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(1);
  timing.fill_mode = Timing::FillMode::FORWARDS;
  timing.iteration_count = std::numeric_limits<double>::infinity();
  auto* animation_node = MakeGarbageCollected<TestAnimationEffect>(timing);

  animation_node->UpdateInheritedTime(-1);
  EXPECT_FALSE(animation_node->CurrentIteration());
  EXPECT_FALSE(animation_node->Progress());

  EXPECT_EQ(AnimationTimeDelta::Max(),
            animation_node->NormalizedTiming().active_duration);

  animation_node->UpdateInheritedTime(0);
  EXPECT_EQ(0, animation_node->CurrentIteration());
  EXPECT_EQ(0, animation_node->Progress());
}

TEST(AnimationAnimationEffectTest, Iteration) {
  test::TaskEnvironment task_environment;
  Timing timing;
  timing.iteration_count = 2;
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(2);
  auto* animation_node = MakeGarbageCollected<TestAnimationEffect>(timing);

  animation_node->UpdateInheritedTime(0);
  EXPECT_EQ(0, animation_node->CurrentIteration());
  EXPECT_EQ(0, animation_node->Progress());

  animation_node->UpdateInheritedTime(1);
  EXPECT_EQ(0, animation_node->CurrentIteration());
  EXPECT_EQ(0.5, animation_node->Progress());

  animation_node->UpdateInheritedTime(2);
  EXPECT_EQ(1, animation_node->CurrentIteration());
  EXPECT_EQ(0, animation_node->Progress());

  animation_node->UpdateInheritedTime(2);
  EXPECT_EQ(1, animation_node->CurrentIteration());
  EXPECT_EQ(0, animation_node->Progress());

  animation_node->UpdateInheritedTime(5);
  EXPECT_EQ(1, animation_node->CurrentIteration());
  EXPECT_EQ(1, animation_node->Progress());
}

TEST(AnimationAnimationEffectTest, IterationStart) {
  test::TaskEnvironment task_environment;
  Timing timing;
  timing.iteration_start = 1.2;
  timing.iteration_count = 2.2;
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(1);
  timing.fill_mode = Timing::FillMode::BOTH;
  auto* animation_node = MakeGarbageCollected<TestAnimationEffect>(timing);

  animation_node->UpdateInheritedTime(-1);
  EXPECT_EQ(1, animation_node->CurrentIteration());
  EXPECT_NEAR(0.2, animation_node->Progress().value(), 0.000000000000001);

  animation_node->UpdateInheritedTime(0);
  EXPECT_EQ(1, animation_node->CurrentIteration());
  EXPECT_NEAR(0.2, animation_node->Progress().value(), 0.000000000000001);

  animation_node->UpdateInheritedTime(10);
  EXPECT_EQ(3, animation_node->CurrentIteration());
  EXPECT_NEAR(0.4, animation_node->Progress().value(), 0.000000000000001);
}

TEST(AnimationAnimationEffectTest, IterationAlternate) {
  test::TaskEnvironment task_environment;
  Timing timing;
  timing.iteration_count = 10;
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(1);
  timing.direction = Timing::PlaybackDirection::ALTERNATE_NORMAL;
  auto* animation_node = MakeGarbageCollected<TestAnimationEffect>(timing);

  animation_node->UpdateInheritedTime(0.75);
  EXPECT_EQ(0, animation_node->CurrentIteration());
  EXPECT_EQ(0.75, animation_node->Progress());

  animation_node->UpdateInheritedTime(1.75);
  EXPECT_EQ(1, animation_node->CurrentIteration());
  EXPECT_EQ(0.25, animation_node->Progress());

  animation_node->UpdateInheritedTime(2.75);
  EXPECT_EQ(2, animation_node->CurrentIteration());
  EXPECT_EQ(0.75, animation_node->Progress());
}

TEST(AnimationAnimationEffectTest, IterationAlternateReverse) {
  test::TaskEnvironment task_environment;
  Timing timing;
  timing.iteration_count = 10;
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(1);
  timing.direction = Timing::PlaybackDirection::ALTERNATE_REVERSE;
  auto* animation_node = MakeGarbageCollected<TestAnimationEffect>(timing);

  animation_node->UpdateInheritedTime(0.75);
  EXPECT_EQ(0, animation_node->CurrentIteration());
  EXPECT_EQ(0.25, animation_node->Progress());

  animation_node->UpdateInheritedTime(1.75);
  EXPECT_EQ(1, animation_node->CurrentIteration());
  EXPECT_EQ(0.75, animation_node->Progress());

  animation_node->UpdateInheritedTime(2.75);
  EXPECT_EQ(2, animation_node->CurrentIteration());
  EXPECT_EQ(0.25, animation_node->Progress());
}

TEST(AnimationAnimationEffectTest, ZeroDurationSanity) {
  test::TaskEnvironment task_environment;
  Timing timing;
  auto* animation_node = MakeGarbageCollected<TestAnimationEffect>(timing);

  animation_node->UpdateInheritedTime(0);

  EXPECT_EQ(Timing::kPhaseAfter, animation_node->GetPhase());
  EXPECT_FALSE(animation_node->IsInPlay());
  EXPECT_FALSE(animation_node->IsCurrent());
  EXPECT_TRUE(animation_node->IsInEffect());
  EXPECT_EQ(0, animation_node->CurrentIteration());
  EXPECT_EQ(AnimationTimeDelta(),
            animation_node->NormalizedTiming().active_duration);
  EXPECT_EQ(1, animation_node->Progress());

  animation_node->UpdateInheritedTime(1);

  EXPECT_EQ(Timing::kPhaseAfter, animation_node->GetPhase());
  EXPECT_FALSE(animation_node->IsInPlay());
  EXPECT_FALSE(animation_node->IsCurrent());
  EXPECT_TRUE(animation_node->IsInEffect());
  EXPECT_EQ(0, animation_node->CurrentIteration());
  EXPECT_EQ(AnimationTimeDelta(),
            animation_node->NormalizedTiming().active_duration);
  EXPECT_EQ(1, animation_node->Progress());
}

TEST(AnimationAnimationEffectTest, ZeroDurationFillForwards) {
  test::TaskEnvironment task_environment;
  Timing timing;
  timing.fill_mode = Timing::FillMode::FORWARDS;
  auto* animation_node = MakeGarbageCollected<TestAnimationEffect>(timing);

  animation_node->UpdateInheritedTime(-1);
  EXPECT_FALSE(animation_node->Progress());

  animation_node->UpdateInheritedTime(0);
  EXPECT_EQ(1, animation_node->Progress());

  animation_node->UpdateInheritedTime(1);
  EXPECT_EQ(1, animation_node->Progress());
}

TEST(AnimationAnimationEffectTest, ZeroDurationFillBackwards) {
  test::TaskEnvironment task_environment;
  Timing timing;
  timing.fill_mode = Timing::FillMode::BACKWARDS;
  auto* animation_node = MakeGarbageCollected<TestAnimationEffect>(timing);

  animation_node->UpdateInheritedTime(-1);
  EXPECT_EQ(0, animation_node->Progress());

  animation_node->UpdateInheritedTime(0);
  EXPECT_FALSE(animation_node->Progress());

  animation_node->UpdateInheritedTime(1);
  EXPECT_FALSE(animation_node->Progress());
}

TEST(AnimationAnimationEffectTest, ZeroDurationFillBoth) {
  test::TaskEnvironment task_environment;
  Timing timing;
  timing.fill_mode = Timing::FillMode::BOTH;
  auto* animation_node = MakeGarbageCollected<TestAnimationEffect>(timing);

  animation_node->UpdateInheritedTime(-1);
  EXPECT_EQ(0, animation_node->Progress());

  animation_node->UpdateInheritedTime(0);
  EXPECT_EQ(1, animation_node->Progress());

  animation_node->UpdateInheritedTime(1);
  EXPECT_EQ(1, animation_node->Progress());
}

TEST(AnimationAnimationEffectTest, ZeroDurationStartDelay) {
  test::TaskEnvironment task_environment;
  Timing timing;
  timing.fill_mode = Timing::FillMode::FORWARDS;
  timing.start_delay = Timing::Delay(ANIMATION_TIME_DELTA_FROM_SECONDS(0.5));
  auto* animation_node = MakeGarbageCollected<TestAnimationEffect>(timing);

  animation_node->UpdateInheritedTime(0);
  EXPECT_FALSE(animation_node->Progress());

  animation_node->UpdateInheritedTime(0.5);
  EXPECT_EQ(1, animation_node->Progress());

  animation_node->UpdateInheritedTime(1.5);
  EXPECT_EQ(1, animation_node->Progress());
}

TEST(AnimationAnimationEffectTest, ZeroDurationIterationStartAndCount) {
  test::TaskEnvironment task_environment;
  Timing timing;
  timing.iteration_start = 0.1;
  timing.iteration_count = 0.2;
  timing.fill_mode = Timing::FillMode::BOTH;
  timing.start_delay = Timing::Delay(ANIMATION_TIME_DELTA_FROM_SECONDS(0.3));
  auto* animation_node = MakeGarbageCollected<TestAnimationEffect>(timing);

  animation_node->UpdateInheritedTime(0);
  EXPECT_EQ(0.1, animation_node->Progress());

  animation_node->UpdateInheritedTime(0.3);
  EXPECT_DOUBLE_EQ(0.3, animation_node->Progress().value());

  animation_node->UpdateInheritedTime(1);
  EXPECT_DOUBLE_EQ(0.3, animation_node->Progress().value());
}

// FIXME: Needs specification work.
TEST(AnimationAnimationEffectTest, ZeroDurationInfiniteIteration) {
  test::TaskEnvironment task_environment;
  Timing timing;
  timing.fill_mode = Timing::FillMode::FORWARDS;
  timing.iteration_count = std::numeric_limits<double>::infinity();
  auto* animation_node = MakeGarbageCollected<TestAnimationEffect>(timing);

  animation_node->UpdateInheritedTime(-1);
  EXPECT_EQ(AnimationTimeDelta(),
            animation_node->NormalizedTiming().active_duration);
  EXPECT_FALSE(animation_node->CurrentIteration());
  EXPECT_FALSE(animation_node->Progress());

  animation_node->UpdateInheritedTime(0);
  EXPECT_EQ(AnimationTimeDelta(),
            animation_node->NormalizedTiming().active_duration);
  EXPECT_EQ(std::numeric_limits<double>::infinity(),
            animation_node->CurrentIteration());
  EXPECT_EQ(1, animation_node->Progress());
}

TEST(AnimationAnimationEffectTest, ZeroDurationIteration) {
  test::TaskEnvironment task_environment;
  Timing timing;
  timing.fill_mode = Timing::FillMode::FORWARDS;
  timing.iteration_count = 2;
  auto* animation_node = MakeGarbageCollected<TestAnimationEffect>(timing);

  animation_node->UpdateInheritedTime(-1);
  EXPECT_FALSE(animation_node->CurrentIteration());
  EXPECT_FALSE(animation_node->Progress());

  animation_node->UpdateInheritedTime(0);
  EXPECT_EQ(1, animation_node->CurrentIteration());
  EXPECT_EQ(1, animation_node->Progress());

  animation_node->UpdateInheritedTime(1);
  EXPECT_EQ(1, animation_node->CurrentIteration());
  EXPECT_EQ(1, animation_node->Progress());
}

TEST(AnimationAnimationEffectTest, ZeroDurationIterationStart) {
  test::TaskEnvironment task_environment;
  Timing timing;
  timing.iteration_start = 1.2;
  timing.iteration_count = 2.2;
  timing.fill_mode = Timing::FillMode::BOTH;
  auto* animation_node = MakeGarbageCollected<TestAnimationEffect>(timing);

  animation_node->UpdateInheritedTime(-1);
  EXPECT_EQ(1, animation_node->CurrentIteration());
  EXPECT_NEAR(0.2, animation_node->Progress().value(), 0.000000000000001);

  animation_node->UpdateInheritedTime(0);
  EXPECT_EQ(3, animation_node->CurrentIteration());
  EXPECT_NEAR(0.4, animation_node->Progress().value(), 0.000000000000001);

  animation_node->UpdateInheritedTime(10);
  EXPECT_EQ(3, animation_node->CurrentIteration());
  EXPECT_NEAR(0.4, animation_node->Progress().value(), 0.000000000000001);
}

TEST(AnimationAnimationEffectTest, ZeroDurationIterationAlternate) {
  test::TaskEnvironment task_environment;
  Timing timing;
  timing.fill_mode = Timing::FillMode::FORWARDS;
  timing.iteration_count = 2;
  timing.direction = Timing::PlaybackDirection::ALTERNATE_NORMAL;
  auto* animation_node = MakeGarbageCollected<TestAnimationEffect>(timing);

  animation_node->UpdateInheritedTime(-1);
  EXPECT_FALSE(animation_node->CurrentIteration());
  EXPECT_FALSE(animation_node->Progress());

  animation_node->UpdateInheritedTime(0);
  EXPECT_EQ(1, animation_node->CurrentIteration());
  EXPECT_EQ(0, animation_node->Progress());

  animation_node->UpdateInheritedTime(1);
  EXPECT_EQ(1, animation_node->CurrentIteration());
  EXPECT_EQ(0, animation_node->Progress());
}

TEST(AnimationAnimationEffectTest, ZeroDurationIterationAlternateReverse) {
  test::TaskEnvironment task_environment;
  Timing timing;
  timing.fill_mode = Timing::FillMode::FORWARDS;
  timing.iteration_count = 2;
  timing.direction = Timing::PlaybackDirection::ALTERNATE_REVERSE;
  auto* animation_node = MakeGarbageCollected<TestAnimationEffect>(timing);

  animation_node->UpdateInheritedTime(-1);
  EXPECT_FALSE(animation_node->CurrentIteration());
  EXPECT_FALSE(animation_node->Progress());

  animation_node->UpdateInheritedTime(0);
  EXPECT_EQ(1, animation_node->CurrentIteration());
  EXPECT_EQ(1, animation_node->Progress());

  animation_node->UpdateInheritedTime(1);
  EXPECT_EQ(1, animation_node->CurrentIteration());
  EXPECT_EQ(1, animation_node->Progress());
}

TEST(AnimationAnimationEffectTest, InfiniteDurationSanity) {
  test::TaskEnvironment task_environment;
  Timing timing;
  timing.iteration_duration = AnimationTimeDelta::Max();
  timing.iteration_count = 1;
  auto* animation_node = MakeGarbageCollected<TestAnimationEffect>(timing);

  animation_node->UpdateInheritedTime(0);

  EXPECT_EQ(AnimationTimeDelta::Max(),
            animation_node->NormalizedTiming().active_duration);
  EXPECT_EQ(Timing::kPhaseActive, animation_node->GetPhase());
  EXPECT_TRUE(animation_node->IsInPlay());
  EXPECT_TRUE(animation_node->IsCurrent());
  EXPECT_TRUE(animation_node->IsInEffect());
  EXPECT_EQ(0, animation_node->CurrentIteration());
  EXPECT_EQ(0, animation_node->Progress());

  animation_node->UpdateInheritedTime(1);

  EXPECT_EQ(AnimationTimeDelta::Max(),
            animation_node->NormalizedTiming().active_duration);
  EXPECT_EQ(Timing::kPhaseActive, animation_node->GetPhase());
  EXPECT_TRUE(animation_node->IsInPlay());
  EXPECT_TRUE(animation_node->IsCurrent());
  EXPECT_TRUE(animation_node->IsInEffect());
  EXPECT_EQ(0, animation_node->CurrentIteration());
  EXPECT_EQ(0, animation_node->Progress());
}

// FIXME: Needs specification work.
TEST(AnimationAnimationEffectTest, InfiniteDurationZeroIterations) {
  test::TaskEnvironment task_environment;
  Timing timing;
  timing.iteration_duration = AnimationTimeDelta::Max();
  timing.iteration_count = 0;
  auto* animation_node = MakeGarbageCollected<TestAnimationEffect>(timing);

  animation_node->UpdateInheritedTime(0);

  EXPECT_EQ(AnimationTimeDelta(),
            animation_node->NormalizedTiming().active_duration);
  EXPECT_EQ(Timing::kPhaseAfter, animation_node->GetPhase());
  EXPECT_FALSE(animation_node->IsInPlay());
  EXPECT_FALSE(animation_node->IsCurrent());
  EXPECT_TRUE(animation_node->IsInEffect());
  EXPECT_EQ(0, animation_node->CurrentIteration());
  EXPECT_EQ(0, animation_node->Progress());

  animation_node->UpdateInheritedTime(1);

  EXPECT_EQ(Timing::kPhaseAfter, animation_node->GetPhase());
  EXPECT_EQ(Timing::kPhaseAfter, animation_node->GetPhase());
  EXPECT_FALSE(animation_node->IsInPlay());
  EXPECT_FALSE(animation_node->IsCurrent());
  EXPECT_TRUE(animation_node->IsInEffect());
  EXPECT_EQ(0, animation_node->CurrentIteration());
  EXPECT_EQ(0, animation_node->Progress());
}

TEST(AnimationAnimationEffectTest, InfiniteDurationInfiniteIterations) {
  test::TaskEnvironment task_environment;
  Timing timing;
  timing.iteration_duration = AnimationTimeDelta::Max();
  timing.iteration_count = std::numeric_limits<double>::infinity();
  auto* animation_node = MakeGarbageCollected<TestAnimationEffect>(timing);

  animation_node->UpdateInheritedTime(0);

  EXPECT_EQ(AnimationTimeDelta::Max(),
            animation_node->NormalizedTiming().active_duration);
  EXPECT_EQ(Timing::kPhaseActive, animation_node->GetPhase());
  EXPECT_TRUE(animation_node->IsInPlay());
  EXPECT_TRUE(animation_node->IsCurrent());
  EXPECT_TRUE(animation_node->IsInEffect());
  EXPECT_EQ(0, animation_node->CurrentIteration());
  EXPECT_EQ(0, animation_node->Progress());

  animation_node->UpdateInheritedTime(1);

  EXPECT_EQ(AnimationTimeDelta::Max(),
            animation_node->NormalizedTiming().active_duration);
  EXPECT_EQ(Timing::kPhaseActive, animation_node->GetPhase());
  EXPECT_TRUE(animation_node->IsInPlay());
  EXPECT_TRUE(animation_node->IsCurrent());
  EXPECT_TRUE(animation_node->IsInEffect());
  EXPECT_EQ(0, animation_node->CurrentIteration());
  EXPECT_EQ(0, animation_node->Progress());
}

TEST(AnimationAnimationEffectTest, EndTime) {
  test::TaskEnvironment task_environment;
  Timing timing;
  timing.start_delay = Timing::Delay(ANIMATION_TIME_DELTA_FROM_SECONDS(1));
  timing.end_delay = Timing::Delay(ANIMATION_TIME_DELTA_FROM_SECONDS(2));
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(4);
  timing.iteration_count = 2;
  auto* animation_node = MakeGarbageCollected<TestAnimationEffect>(timing);
  EXPECT_EQ(ANIMATION_TIME_DELTA_FROM_SECONDS(11),
            animation_node->NormalizedTiming().end_time);
}

TEST(AnimationAnimationEffectTest, Events) {
  test::TaskEnvironment task_environment;
  Timing timing;
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(1);
  timing.fill_mode = Timing::FillMode::FORWARDS;
  timing.iteration_count = 2;
  timing.start_delay = Timing::Delay(ANIMATION_TIME_DELTA_FROM_SECONDS(1));
  auto* animation_node = MakeGarbageCollected<TestAnimationEffect>(timing);

  animation_node->UpdateInheritedTime(0.0, kTimingUpdateOnDemand);
  EXPECT_FALSE(animation_node->EventDelegate()->EventTriggered());

  animation_node->UpdateInheritedTime(0.0, kTimingUpdateForAnimationFrame);
  EXPECT_TRUE(animation_node->EventDelegate()->EventTriggered());

  animation_node->UpdateInheritedTime(1.5, kTimingUpdateOnDemand);
  EXPECT_FALSE(animation_node->EventDelegate()->EventTriggered());

  animation_node->UpdateInheritedTime(1.5, kTimingUpdateForAnimationFrame);
  EXPECT_TRUE(animation_node->EventDelegate()->EventTriggered());
}

TEST(AnimationAnimationEffectTest, TimeToEffectChange) {
  test::TaskEnvironment task_environment;
  Timing timing;
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(1);
  timing.fill_mode = Timing::FillMode::FORWARDS;
  timing.iteration_start = 0.2;
  timing.iteration_count = 2.5;
  timing.start_delay = Timing::Delay(ANIMATION_TIME_DELTA_FROM_SECONDS(1));
  timing.direction = Timing::PlaybackDirection::ALTERNATE_NORMAL;
  auto* animation_node = MakeGarbageCollected<TestAnimationEffect>(timing);

  animation_node->UpdateInheritedTime(0);
  EXPECT_EQ(0, animation_node->TakeLocalTime());
  std::optional<AnimationTimeDelta> time_to_next_iteration =
      animation_node->TakeTimeToNextIteration();
  EXPECT_TRUE(time_to_next_iteration);
  EXPECT_TRUE(time_to_next_iteration->is_max());

  // Normal iteration.
  animation_node->UpdateInheritedTime(1.75);
  EXPECT_EQ(1.75, animation_node->TakeLocalTime());
  time_to_next_iteration = animation_node->TakeTimeToNextIteration();
  EXPECT_TRUE(time_to_next_iteration);
  EXPECT_NEAR(0.05, time_to_next_iteration->InSecondsF(), 0.000000000000001);

  // Reverse iteration.
  animation_node->UpdateInheritedTime(2.75);
  EXPECT_EQ(2.75, animation_node->TakeLocalTime());
  time_to_next_iteration = animation_node->TakeTimeToNextIteration();
  EXPECT_TRUE(time_to_next_iteration);
  EXPECT_NEAR(0.05, time_to_next_iteration->InSecondsF(), 0.000000000000001);

  // Item ends before iteration finishes.
  animation_node->UpdateInheritedTime(3.4);
  EXPECT_EQ(Timing::kPhaseActive, animation_node->GetPhase());
  EXPECT_EQ(3.4, animation_node->TakeLocalTime());
  time_to_next_iteration = animation_node->TakeTimeToNextIteration();
  EXPECT_TRUE(time_to_next_iteration);
  EXPECT_TRUE(time_to_next_iteration->is_max());

  // Item has finished.
  animation_node->UpdateInheritedTime(3.5);
  EXPECT_EQ(Timing::kPhaseAfter, animation_node->GetPhase());
  EXPECT_EQ(3.5, animation_node->TakeLocalTime());
  time_to_next_iteration = animation_node->TakeTimeToNextIteration();
  EXPECT_TRUE(time_to_next_iteration);
  EXPECT_TRUE(time_to_next_iteration->is_max());
}

TEST(AnimationAnimationEffectTest, UpdateTiming) {
  test::TaskEnvironment task_environment;
  Timing timing;
  auto* effect = MakeGarbageCollected<TestAnimationEffect>(timing);

  EXPECT_EQ(0, effect->getTiming()->delay()->GetAsDouble());
  OptionalEffectTiming* effect_timing = OptionalEffectTiming::Create();
  effect_timing->setDelay(CreateTimeDelay(2));
  effect->updateTiming(effect_timing);
  EXPECT_EQ(2, effect->getTiming()->delay()->GetAsDouble());
  effect_timing = OptionalEffectTiming::Create();
  effect_timing->setEndDelay(CreateTimeDelay(0.5));
  effect->updateTiming(effect_timing);
  EXPECT_EQ(0.5, effect->getTiming()->endDelay()->GetAsDouble());
  effect_timing = OptionalEffectTiming::Create();
  effect_timing->setFill("backwards");
  effect->updateTiming(effect_timing);
  EXPECT_EQ("backwards", effect->getTiming()->fill());

  EXPECT_EQ(0, effect->getTiming()->iterationStart());
  effect_timing = OptionalEffectTiming::Create();
  effect_timing->setIterationStart(2);
  effect->updateTiming(effect_timing);
  EXPECT_EQ(2, effect->getTiming()->iterationStart());

  EXPECT_EQ(1, effect->getTiming()->iterations());
  effect_timing = OptionalEffectTiming::Create();
  effect_timing->setIterations(10);
  effect->updateTiming(effect_timing);
  EXPECT_EQ(10, effect->getTiming()->iterations());

  EXPECT_EQ("normal", effect->getTiming()->direction());
  effect_timing = OptionalEffectTiming::Create();
  effect_timing->setDirection("reverse");
  effect->updateTiming(effect_timing);
  EXPECT_EQ("reverse", effect->getTiming()->direction());

  EXPECT_EQ("linear", effect->getTiming()->easing());
  effect_timing = OptionalEffectTiming::Create();
  effect_timing->setEasing("ease-in-out");
  effect->updateTiming(effect_timing);
  EXPECT_EQ("ease-in-out", effect->getTiming()->easing());

  EXPECT_EQ("auto", effect->getTiming()->duration()->GetAsString());
  effect_timing = OptionalEffectTiming::Create();
  effect_timing->setDuration(
      MakeGarbageCollected<V8UnionCSSNumericValueOrStringOrUnrestrictedDouble>(
          2.5));
  effect->updateTiming(effect_timing);
  EXPECT_EQ(2.5, effect->getTiming()->duration()->GetAsUnrestrictedDouble());
}

TEST(AnimationAnimationEffectTest, UpdateTimingThrowsWhenExpected) {
  test::TaskEnvironment task_environment;
  Timing timing;
  auto* effect = MakeGarbageCollected<TestAnimationEffect>(timing);

  // iterationStart must be non-negative
  {
    DummyExceptionStateForTesting exception_state;
    OptionalEffectTiming* effect_timing = Optio
"""


```