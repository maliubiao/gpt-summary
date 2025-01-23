Response:
Let's break down the thought process for analyzing this `animation_effect.cc` file.

**1. Initial Understanding of the File's Purpose (Based on Name and Path):**

* **`blink`:**  This clearly indicates it's part of the Chromium Blink rendering engine.
* **`renderer`:**  Suggests it's involved in the rendering pipeline.
* **`core`:**  Indicates core functionality, not specific platform implementations.
* **`animation`:**  Confirms it's related to animations.
* **`animation_effect.cc`:**  The name strongly suggests this file implements the `AnimationEffect` class, which is a fundamental component in the Web Animations API.

**2. Examining the Header Includes:**

The included headers give immediate clues about the file's dependencies and interactions:

* **`animation_effect.h`:**  Confirms the implementation of the `AnimationEffect` class.
* **`v8_computed_effect_timing.h`, `v8_optional_effect_timing.h`, `v8_union_cssnumericvalue_string_unrestricteddouble.h`:**  These indicate interaction with JavaScript and the V8 engine. They handle conversions between internal Blink types and JavaScript representations of timing properties.
* **`animation.h`, `animation_input_helpers.h`, `animation_timeline.h`, `keyframe_effect.h`, `timing_calculations.h`, `timing_input.h`:** These highlight the file's role within the broader animation system in Blink. It interacts with `Animation` objects, `AnimationTimeline` objects, and likely deals with keyframes and timing calculations.
* **`document.h`:**  Shows interaction with the DOM `Document`, suggesting it's tied to elements and their properties.
* **`web_feature.h`:** Points to the use of feature tracking, likely for usage statistics.

**3. Analyzing the Class Definition (`AnimationEffect`):**

* **Constructor:**  Takes `Timing` and `EventDelegate*`. This suggests an `AnimationEffect` has timing properties and can dispatch events.
* **Member Variables:** `owner_`, `timing_`, `event_delegate_`, `needs_update_`, `cancel_time_`, `calculated_`, `normalized_`, `last_update_time_`, `last_is_idle_`. These variables hold the state of the animation effect, including its timing, ownership, event handling, and calculated values. The `normalized_` member is particularly interesting, hinting at a normalization process.
* **Key Methods (High-Level Overview):**
    * `IntrinsicIterationDuration()`:  Calculates the duration of a single iteration.
    * `EnsureNormalizedTiming()`:  Performs a crucial timing normalization process, potentially related to different types of timelines (time-based vs. progress-based). This looks complex and important.
    * `UpdateSpecifiedTiming()`:  Allows updating the timing properties.
    * `SetIgnoreCssTimingProperties()`:  Indicates a way to override CSS-defined timing.
    * `getTiming()`, `getComputedTiming()`:  Methods to retrieve timing information, likely exposed to JavaScript.
    * `updateTiming()`:  A method to update timing from JavaScript.
    * `UpdateInheritedTime()`:  This method seems to be the core of the animation update logic, taking into account inherited time and playback rate.
    * `InvalidateAndNotifyOwner()`:  Used to signal changes to the owning object.
    * `EnsureCalculated()`:  Forces a calculation of the timing.
    * `GetAnimation()`:  Retrieves the associated `Animation` object.

**4. Deep Dive into Key Methods (Applying Logical Reasoning):**

* **`EnsureNormalizedTiming()`:** This method is clearly crucial. The comments point to different types of timelines ("time-based" and "progress-based"). The logic involving `TimelineDuration()` and the calculations with `start_delay`, `end_delay`, and `iteration_duration` strongly suggest it's converting timing values to a common scale, especially for scroll timelines. The handling of `end_time` being zero or infinite highlights edge cases and robustness. The mention of "animation-range" connects it to specific CSS features.

* **`UpdateInheritedTime()`:** The logic here involves checking `needs_update_`, comparing `last_update_time_` and `last_is_idle_`, and then calling `SpecifiedTiming().CalculateTimings()`. This strongly suggests a state-driven update mechanism based on changes in time and idle status. The handling of `was_canceled` and event delegation is also important. The recursive call to `UpdateChildrenAndEffects()` indicates a hierarchical structure of animation effects.

* **`getTiming()` and `getComputedTiming()`:**  These methods clearly bridge the gap between the internal C++ representation and the JavaScript API. `getTiming()` returns the specified timing, while `getComputedTiming()` returns the calculated timing, likely after performing updates.

* **`updateTiming()`:** The checks for `ScrollTimeline` and restrictions on `duration` and `iterations` reveal specific constraints when using scroll-linked animations. The call to `TimingInput::Update()` suggests a separate helper class for handling timing updates from JavaScript.

**5. Identifying Connections to JavaScript, HTML, and CSS:**

The analysis of the methods and header files reveals strong connections:

* **JavaScript:**  Methods like `getTiming()`, `getComputedTiming()`, and `updateTiming()` are clearly part of the Web Animations API exposed to JavaScript. The `V8` prefixes in the header files confirm this. The `OptionalEffectTiming` parameter in `updateTiming()` directly corresponds to the JavaScript object used to update animation timing.
* **HTML:** The connection to the `Document` signifies that `AnimationEffect` operates on elements within the HTML structure.
* **CSS:** The `Timing` object likely stores timing values parsed from CSS. The `SetIgnoreCssTimingProperties()` method explicitly deals with overriding CSS timing. The mention of "scroll timelines" links it to CSS Scroll Snap and related features.

**6. Identifying Potential User Errors and Providing Examples:**

Based on the code and comments, potential errors include:

* **Setting `duration` to `Infinity` on scroll timelines.** The `updateTiming()` method explicitly throws an error for this.
* **Setting `iterations` to `Infinity` on scroll timelines.**  Similarly, `updateTiming()` checks for this.
* **Using `duration: auto` with non-zero time delays on scroll timelines (for now).** This is a current limitation noted in the comments and code.

**7. Structuring the Output:**

Finally, the information needs to be organized into a clear and comprehensive response, covering the requested aspects: functionality, relationships with web technologies, logical reasoning (with input/output examples), and common user errors. Using bullet points and clear explanations enhances readability.

This structured approach, starting with the big picture and gradually diving into the details, helps in understanding complex C++ code and its role in a larger system like a browser engine. The key is to make connections between the code and the web technologies it supports.
这个文件 `animation_effect.cc` 是 Chromium Blink 引擎中负责动画效果核心逻辑的实现。它定义了 `AnimationEffect` 类，该类是 Web Animations API 中 `AnimationEffect` 接口在 Blink 内部的表示。

**主要功能：**

1. **表示动画效果的通用属性:**  `AnimationEffect` 存储和管理所有动画效果实例共有的定时属性，例如：
    * **`startDelay` (启动延迟):** 动画开始前的延迟时间。
    * **`iterationDuration` (迭代持续时间):** 动画单次循环的持续时间。
    * **`iterations` (迭代次数):** 动画循环的次数。
    * **`endDelay` (结束延迟):** 动画结束后保持最终状态的延迟时间。
    * **`fill` (填充模式):**  动画在开始前和结束后如何应用样式 (`none`, `forwards`, `backwards`, `both`).
    * **`direction` (播放方向):** 动画播放的方向 (`normal`, `reverse`, `alternate`, `alternate-reverse`).
    * **`easing` (缓动函数):** 控制动画在时间上的速度变化。
    * **`timeline` (时间线):**  关联动画的时间源（例如，文档时间线、滚动时间线）。

2. **定时计算和标准化:** `AnimationEffect` 负责根据上述定时属性进行复杂的计算，以确定动画在给定时间点的状态。 这包括：
    * **规范化定时 (Normalization):**  对于基于进度的动画时间线（如滚动时间线），将时间单位的定时值转换为与时间线进度相关的比例值。
    * **计算活动时间和结束时间:**  根据迭代次数、持续时间、延迟等计算动画的有效活动时间和总结束时间。
    * **确定动画阶段:**  判断动画当前处于哪个阶段 (例如，启动延迟、活动中、结束延迟、填充阶段)。

3. **与 `Animation` 对象关联:**  每个 `AnimationEffect` 对象都与一个 `Animation` 对象关联，`Animation` 对象负责管理动画的播放控制（例如，播放、暂停、反转）。 `AnimationEffect` 提供了获取关联 `Animation` 对象的方法。

4. **事件处理委托:**  `AnimationEffect` 使用 `EventDelegate` 来处理动画相关的事件，例如动画开始、结束、循环等。

5. **与 JavaScript 接口交互:**  该文件包含了与 JavaScript Web Animations API 交互的逻辑，例如：
    * **`getTiming()`:**  返回一个 `EffectTiming` 对象，该对象包含了当前动画效果的定时属性，可以传递给 JavaScript。
    * **`getComputedTiming()`:**  返回一个 `ComputedEffectTiming` 对象，该对象包含了计算后的动画效果定时属性，例如当前的局部时间。
    * **`updateTiming()`:**  允许从 JavaScript 更新动画效果的定时属性。

6. **处理定时更新:**  `UpdateInheritedTime` 方法是核心，它根据父动画或时间线的进度更新动画效果的状态。这包括计算当前时间和触发相关事件。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **JavaScript:**
    * **获取和设置定时属性:** JavaScript 可以通过 `getTiming()` 获取动画效果的定时信息，并通过 `updateTiming()` 方法来修改这些属性。
        ```javascript
        const element = document.getElementById('myElement');
        const animation = element.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 1000 });
        const effect = animation.effect;

        // 获取动画效果的定时信息
        const timing = effect.getTiming();
        console.log(timing.duration); // 输出 1000

        // 修改动画效果的延迟
        effect.updateTiming({ delay: 500 });
        ```
    * **处理动画事件:** JavaScript 可以监听动画的 `finish`、`cancel` 等事件，这些事件的触发与 `AnimationEffect` 内部的逻辑有关。

* **HTML:**
    * **动画目标:** `AnimationEffect` 通常与 HTML 元素关联，动画会影响这些元素的样式。`Animation` 对象会持有动画应用的目标元素的信息。

* **CSS:**
    * **声明式动画:**  CSS `@keyframes` 规则定义的动画最终会转换为 `KeyframeEffect` 对象，而 `KeyframeEffect` 继承自 `AnimationEffect`。CSS 中的 `animation-*` 属性（如 `animation-duration`, `animation-delay` 等）的值会影响 `AnimationEffect` 对象的定时属性。
        ```css
        .my-element {
          animation-name: fadeIn;
          animation-duration: 2s;
          animation-delay: 1s;
        }

        @keyframes fadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }
        ```
    * **滚动时间线:** CSS 可以定义基于滚动位置的动画时间线，`AnimationEffect` 中的逻辑会处理这种基于进度的定时。

**逻辑推理的假设输入与输出：**

假设我们有一个 `AnimationEffect` 对象，其定时属性如下：

* `startDelay`: 1 秒
* `iterationDuration`: 2 秒
* `iterations`: 2
* 当前时间线上的时间（`inherited_time`）： 3.5 秒

**假设输入:**

* `inherited_time`: 3.5 秒
* `is_idle`: false (动画正在进行)
* `inherited_playback_rate`: 1 (正常播放速度)

**逻辑推理 (在 `UpdateInheritedTime` 方法中):**

1. **检查是否需要更新:** 代码会比较 `inherited_time` 和 `last_update_time_` 等，判断是否需要重新计算动画状态。
2. **计算定时:** `SpecifiedTiming().CalculateTimings()` 会根据 `inherited_time`、定时属性以及播放方向等计算出动画在当前时间点的状态。
3. **确定动画阶段:**  由于 `startDelay` 是 1 秒，第一个迭代的活动时间是 2 秒，所以第一个迭代结束时间是 1 + 2 = 3 秒。因为 `iterations` 是 2，第二个迭代的开始时间是 3 秒。当 `inherited_time` 为 3.5 秒时，动画正处于第二个迭代的活动阶段。
4. **输出 (可能的计算结果):**
    * `calculated_.phase`:  `Timing::kPhaseActive` (动画处于活动阶段)
    * `calculated_.current_time`: 0.5 秒 (相对于当前迭代的开始时间)
    * `calculated_.iteration`: 1 (当前是第二个迭代，索引从 0 开始)
    * 其他与动画效果相关的属性值 (例如，如果这是 `KeyframeEffect`，则会计算出当前时间点对应的属性值)。

**用户或编程常见的使用错误举例说明：**

1. **在滚动时间线上设置无限迭代次数:**  滚动时间线通常与页面的滚动位置关联，无限迭代没有实际意义，会导致错误或不可预测的行为。`updateTiming` 方法内部会检查这种情况并抛出异常。
    ```javascript
    // 错误示例：在滚动时间线上设置无限迭代
    const animation = element.animate([{ transform: 'translateX(0px)' }, { transform: 'translateX(100px)' }], {
      timeline: new ScrollTimeline(),
      iterations: Infinity
    }); // 这可能会导致错误或被浏览器限制
    ```
    **`animation_effect.cc` 中的相关逻辑:**
    ```c++
    void AnimationEffect::updateTiming(OptionalEffectTiming* optional_timing,
                                       ExceptionState& exception_state) {
      // ...
      if (GetAnimation() && GetAnimation()->TimelineInternal() &&
          GetAnimation()->TimelineInternal()->IsProgressBased()) {
        // ...
        if (optional_timing->hasIterations() &&
            optional_timing->iterations() ==
                std::numeric_limits<double>::infinity()) {
          // iteration count of infinity makes no sense for scroll timelines
          exception_state.ThrowTypeError(
              "Effect iterations cannot be Infinity when used with Scroll "
              "Timelines");
          return;
        }
      }
      // ...
    }
    ```

2. **在滚动时间线上使用 `duration: auto` 且存在时间延迟:**  当使用滚动时间线时，`duration: auto` 的含义可能不明确，并且与时间延迟 (如 `delay`) 的组合可能会导致混淆。目前 Blink 中可能存在对这种情况的限制。
    ```javascript
    // 潜在的错误或限制：在滚动时间线上使用 auto duration 和延迟
    const animation = element.animate([{ opacity: 0 }, { opacity: 1 }], {
      timeline: new ScrollTimeline(),
      duration: 'auto',
      delay: 1000 // 可能会导致问题
    });
    ```
    **`animation_effect.cc` 中的相关逻辑:**
    ```c++
    void AnimationEffect::updateTiming(OptionalEffectTiming* optional_timing,
                                       ExceptionState& exception_state) {
      // ...
      if (GetAnimation() && GetAnimation()->TimelineInternal() &&
          GetAnimation()->TimelineInternal()->IsProgressBased()) {
        if (optional_timing->hasDuration()) {
          if (optional_timing->duration()->GetAsString() == "auto") {
            // TODO(crbug.com/1216527)
            // ...
            if (SpecifiedTiming().start_delay.IsNonzeroTimeBasedDelay() ||
                SpecifiedTiming().end_delay.IsNonzeroTimeBasedDelay()) {
              exception_state.ThrowDOMException(
                  DOMExceptionCode::kNotSupportedError,
                  "Effect duration \"auto\" with time delays is not yet "
                  "implemented when used with Scroll Timelines");
              return;
            }
          }
        }
        // ...
      }
      // ...
    }
    ```

3. **错误地理解 `fill` 属性:** 用户可能不清楚 `fill` 属性在动画开始前和结束后如何应用样式，导致动画效果与预期不符。 例如，希望动画结束后停留在最终状态，但没有设置 `fill: forwards;`。

理解 `animation_effect.cc` 的功能对于深入了解 Blink 引擎如何实现 Web Animations API 至关重要。它涉及到复杂的定时计算、状态管理以及与 JavaScript 和 CSS 的交互。

### 提示词
```
这是目录为blink/renderer/core/animation/animation_effect.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/bindings/core/v8/v8_computed_effect_timing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_optional_effect_timing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_cssnumericvalue_string_unrestricteddouble.h"
#include "third_party/blink/renderer/core/animation/animation.h"
#include "third_party/blink/renderer/core/animation/animation_input_helpers.h"
#include "third_party/blink/renderer/core/animation/animation_timeline.h"
#include "third_party/blink/renderer/core/animation/keyframe_effect.h"
#include "third_party/blink/renderer/core/animation/timing_calculations.h"
#include "third_party/blink/renderer/core/animation/timing_input.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"

namespace blink {

namespace {

void UseCountEffectTimingDelayZero(Document& document, const Timing& timing) {
  if (timing.iteration_duration == AnimationTimeDelta()) {
    UseCounter::Count(document, WebFeature::kGetEffectTimingDelayZero);
  }
}

}  // namespace

AnimationEffect::AnimationEffect(const Timing& timing,
                                 EventDelegate* event_delegate)
    : owner_(nullptr),
      timing_(timing),
      event_delegate_(event_delegate),
      needs_update_(true),
      cancel_time_(AnimationTimeDelta()) {
  timing_.AssertValid();
  InvalidateNormalizedTiming();
}

AnimationTimeDelta AnimationEffect::IntrinsicIterationDuration() const {
  if (auto* animation = GetAnimation()) {
    auto* timeline = animation->TimelineInternal();
    if (timeline) {
      return timeline->CalculateIntrinsicIterationDuration(animation, timing_);
    }
  }
  return AnimationTimeDelta();
}

// Scales all timing values so that end_time == timeline_duration
// https://drafts.csswg.org/web-animations-2/#time-based-animation-to-a-proportional-animation
void AnimationEffect::EnsureNormalizedTiming() const {
  // Only run the normalization process if needed
  if (normalized_)
    return;

  normalized_ = Timing::NormalizedTiming();
  // A valid timeline duration signifies use of a progress based timeline.
  if (TimelineDuration()) {
    // Normalize timings for progress based timelines
    normalized_->timeline_duration = TimelineDuration();

    // TODO(crbug.com/1216527): Refactor for animation-range + delays. Still
    // some details to sort out in the spec when mixing delays and range
    // offsets. What happens if you have an animation range and time based
    // delays?
    if (timing_.iteration_duration) {
      // TODO(kevers): We can probably get rid of this branch and just
      // ignore all timing that is not % based.  A fair number of tests still
      // rely on this branch though, so will need to update the tests
      // accordingly to see if they are still relevant.

      // Scaling up iteration_duration allows animation effect to be able to
      // handle values produced by progress based timelines. At this point it
      // can be assumed that EndTimeInternal() will give us a good value.

      const AnimationTimeDelta active_duration =
          TimingCalculations::MultiplyZeroAlwaysGivesZero(
              timing_.iteration_duration.value(), timing_.iteration_count);
      DCHECK_GE(active_duration, AnimationTimeDelta());

      // Per the spec, the end time has a lower bound of 0.0:
      // https://w3.org/TR/web-animations-1/#end-time
      const AnimationTimeDelta end_time =
          std::max(timing_.start_delay.AsTimeValue() + active_duration +
                       timing_.end_delay.AsTimeValue(),
                   AnimationTimeDelta());

      // Negative start_delay that is >= iteration_duration or iteration_count
      // of 0 will cause end_time to be 0 or negative.
      if (end_time.is_zero()) {
        // end_time of zero causes division by zero so we handle it here
        normalized_->start_delay = AnimationTimeDelta();
        normalized_->end_delay = AnimationTimeDelta();
        normalized_->iteration_duration = AnimationTimeDelta();
      } else if (end_time.is_inf()) {
        // The iteration count or duration may be infinite; however, start and
        // end delays are strictly finite. Thus, in the limit when end time
        // approaches infinity:
        //    start delay / end time = finite / infinite = 0
        //    end delay / end time = finite / infinite = 0
        //    iteration duration / end time = 1 / iteration count
        // This condition can be reached by switching to a scroll timeline on
        // an existing infinite duration animation.
        // Note that base::TimeDelta::operator/() DCHECKS that the numerator and
        // denominator cannot both be zero or both be infinite since both cases
        // are undefined. Fortunately, we can evaluate the limit in the infinite
        // end time case based on the definition of end time
        normalized_->start_delay = AnimationTimeDelta();
        normalized_->end_delay = AnimationTimeDelta();
        normalized_->iteration_duration =
            (1.0 / timing_.iteration_count) *
            normalized_->timeline_duration.value();
      } else {
        // End time is not 0 or infinite.
        // Convert to percentages then multiply by the timeline_duration

        // TODO(kevers): Revisit once % delays are supported. At present,
        // % delays are zero and the following product aligns with the animation
        // range. Note the range duration will need to be plumbed through to
        // InertEffect via CSSAnimationProxy. One more reason to try and get rid
        // of InertEffect.
        AnimationTimeDelta range_duration =
            IntrinsicIterationDuration() * timing_.iteration_count;

        normalized_->start_delay =
            (timing_.start_delay.AsTimeValue() / end_time) * range_duration;

        normalized_->end_delay =
            (timing_.end_delay.AsTimeValue() / end_time) * range_duration;

        normalized_->iteration_duration =
            (timing_.iteration_duration.value() / end_time) * range_duration;
      }
    } else {
      // Default (auto) duration with a non-monotonic timeline case.
      // TODO(crbug.com/1216527): Update timing once ratified in the spec.
      // Normalized timing is purely used internally in order to keep the bulk
      // of the animation code time-based.
      normalized_->iteration_duration = IntrinsicIterationDuration();
      AnimationTimeDelta active_duration =
          normalized_->iteration_duration * timing_.iteration_count;
      double start_delay = timing_.start_delay.relative_delay.value_or(0);
      double end_delay = timing_.end_delay.relative_delay.value_or(0);

      if (active_duration > AnimationTimeDelta()) {
        double active_percent = (1 - start_delay - end_delay);
        AnimationTimeDelta end_time = active_duration / active_percent;
        normalized_->start_delay = end_time * start_delay;
        normalized_->end_delay = end_time * end_delay;
      } else {
        // TODO(kevers): This is not quite correct as the delays should probably
        // be divided proportionately.
        normalized_->start_delay = AnimationTimeDelta();
        normalized_->end_delay = TimelineDuration().value();
      }
    }
  } else {
    // Monotonic timeline case.
    // Populates normalized values for use with time based timelines.
    normalized_->start_delay = timing_.start_delay.AsTimeValue();
    normalized_->end_delay = timing_.end_delay.AsTimeValue();
    normalized_->iteration_duration =
        timing_.iteration_duration.value_or(AnimationTimeDelta());
  }

  normalized_->active_duration =
      TimingCalculations::MultiplyZeroAlwaysGivesZero(
          normalized_->iteration_duration, timing_.iteration_count);

  // Per the spec, the end time has a lower bound of 0.0:
  // https://w3.org/TR/web-animations-1/#end-time#end-time
  normalized_->end_time =
      std::max(normalized_->start_delay + normalized_->active_duration +
                   normalized_->end_delay,
               AnimationTimeDelta());

  // Determine if boundary aligned to indicate if the active-(before|after)
  // phase boundary is inclusive or exclusive.
  if (GetAnimation()) {
    GetAnimation()->UpdateBoundaryAlignment(normalized_.value());
  }
}

void AnimationEffect::UpdateSpecifiedTiming(const Timing& timing) {
  if (!timing_.HasTimingOverrides()) {
    timing_ = timing;
  } else {
    // Style changes that are overridden due to an explicit call to
    // AnimationEffect.updateTiming are not applied.
    if (!timing_.HasTimingOverride(Timing::kOverrideStartDelay))
      timing_.start_delay = timing.start_delay;

    if (!timing_.HasTimingOverride(Timing::kOverrideDirection))
      timing_.direction = timing.direction;

    if (!timing_.HasTimingOverride(Timing::kOverrideDuration))
      timing_.iteration_duration = timing.iteration_duration;

    if (!timing_.HasTimingOverride(Timing::kOverrideEndDelay))
      timing_.end_delay = timing.end_delay;

    if (!timing_.HasTimingOverride(Timing::kOverideFillMode))
      timing_.fill_mode = timing.fill_mode;

    if (!timing_.HasTimingOverride(Timing::kOverrideIterationCount))
      timing_.iteration_count = timing.iteration_count;

    if (!timing_.HasTimingOverride(Timing::kOverrideIterationStart))
      timing_.iteration_start = timing.iteration_start;

    if (!timing_.HasTimingOverride(Timing::kOverrideTimingFunction))
      timing_.timing_function = timing.timing_function;
  }

  InvalidateNormalizedTiming();
  InvalidateAndNotifyOwner();
}

void AnimationEffect::SetIgnoreCssTimingProperties() {
  timing_.SetTimingOverride(Timing::kOverrideAll);
}

EffectTiming* AnimationEffect::getTiming() const {
  if (const Animation* animation = GetAnimation()) {
    animation->FlushPendingUpdates();
    UseCountEffectTimingDelayZero(*animation->GetDocument(), SpecifiedTiming());
  }
  return SpecifiedTiming().ConvertToEffectTiming();
}

ComputedEffectTiming* AnimationEffect::getComputedTiming() {
  // A composited animation does not need to tick main frame updates, and
  // the cached state for localTime can become stale.
  if (Animation* animation = GetAnimation()) {
    std::optional<AnimationTimeDelta> current_time =
        animation->CurrentTimeInternal();
    if (current_time != last_update_time_ || animation->Outdated()) {
      animation->Update(kTimingUpdateOnDemand);
    }
  }

  return SpecifiedTiming().getComputedTiming(
      EnsureCalculated(), NormalizedTiming(), IsA<KeyframeEffect>(this));
}

void AnimationEffect::updateTiming(OptionalEffectTiming* optional_timing,
                                   ExceptionState& exception_state) {
  if (GetAnimation() && GetAnimation()->TimelineInternal() &&
      GetAnimation()->TimelineInternal()->IsProgressBased()) {
    if (optional_timing->hasDuration()) {
      if (optional_timing->duration()->IsUnrestrictedDouble()) {
        double duration =
            optional_timing->duration()->GetAsUnrestrictedDouble();
        if (duration == std::numeric_limits<double>::infinity()) {
          exception_state.ThrowTypeError(
              "Effect duration cannot be Infinity when used with Scroll "
              "Timelines");
          return;
        }
      } else if (optional_timing->duration()->GetAsString() == "auto") {
        // TODO(crbug.com/1216527)
        // Eventually we hope to be able to be more flexible with
        // iteration_duration "auto" and its interaction with start_delay and
        // end_delay. For now we will throw an exception if either delay is set.
        // Once delays are changed to CSSNumberish, we will need to adjust logic
        // here to allow for percentage values but not time values.

        // If either delay or end_delay are non-zero, we can't handle "auto"
        if (SpecifiedTiming().start_delay.IsNonzeroTimeBasedDelay() ||
            SpecifiedTiming().end_delay.IsNonzeroTimeBasedDelay()) {
          exception_state.ThrowDOMException(
              DOMExceptionCode::kNotSupportedError,
              "Effect duration \"auto\" with time delays is not yet "
              "implemented when used with Scroll Timelines");
          return;
        }
      }
    }

    if (optional_timing->hasIterations() &&
        optional_timing->iterations() ==
            std::numeric_limits<double>::infinity()) {
      // iteration count of infinity makes no sense for scroll timelines
      exception_state.ThrowTypeError(
          "Effect iterations cannot be Infinity when used with Scroll "
          "Timelines");
      return;
    }
  }

  // TODO(crbug.com/827178): Determine whether we should pass a Document in here
  // (and which) to resolve the CSS secure/insecure context against.
  if (!TimingInput::Update(timing_, optional_timing, nullptr, exception_state))
    return;

  InvalidateNormalizedTiming();
  InvalidateAndNotifyOwner();
}

void AnimationEffect::UpdateInheritedTime(
    std::optional<AnimationTimeDelta> inherited_time,
    bool is_idle,
    double inherited_playback_rate,
    TimingUpdateReason reason) const {
  const Timing::AnimationDirection direction =
      (inherited_playback_rate < 0) ? Timing::AnimationDirection::kBackwards
                                    : Timing::AnimationDirection::kForwards;

  bool needs_update = needs_update_ || last_update_time_ != inherited_time ||
                      last_is_idle_ != is_idle ||
                      (owner_ && owner_->EffectSuppressed());
  needs_update_ = false;
  last_update_time_ = inherited_time;
  last_is_idle_ = is_idle;

  if (needs_update) {
    Timing::CalculatedTiming calculated = SpecifiedTiming().CalculateTimings(
        inherited_time, is_idle, NormalizedTiming(), direction,
        IsA<KeyframeEffect>(this), inherited_playback_rate);

    const bool was_canceled = calculated.phase != calculated_.phase &&
                              calculated.phase == Timing::kPhaseNone;

    // If the animation was canceled, we need to fire the event condition before
    // updating the calculated timing so that the cancellation time can be
    // determined.
    if (was_canceled && event_delegate_) {
      event_delegate_->OnEventCondition(*this, calculated.phase);
    }

    calculated_ = calculated;
  }

  // Test for events even if timing didn't need an update as the animation may
  // have gained a start time.
  // FIXME: Refactor so that we can DCHECK(owner_) here, this is currently
  // required to be nullable for testing.
  if (reason == kTimingUpdateForAnimationFrame &&
      (!owner_ || owner_->IsEventDispatchAllowed())) {
    if (event_delegate_)
      event_delegate_->OnEventCondition(*this, calculated_.phase);
  }

  if (needs_update) {
    // FIXME: This probably shouldn't be recursive.
    UpdateChildrenAndEffects();
    calculated_.time_to_forwards_effect_change = CalculateTimeToEffectChange(
        true, inherited_time, calculated_.time_to_next_iteration);
    calculated_.time_to_reverse_effect_change = CalculateTimeToEffectChange(
        false, inherited_time, calculated_.time_to_next_iteration);
  }
}

void AnimationEffect::InvalidateAndNotifyOwner() const {
  Invalidate();
  if (owner_)
    owner_->EffectInvalidated();
}

const Timing::CalculatedTiming& AnimationEffect::EnsureCalculated() const {
  if (owner_)
    owner_->UpdateIfNecessary();
  return calculated_;
}

Animation* AnimationEffect::GetAnimation() {
  return owner_ ? owner_->GetAnimation() : nullptr;
}
const Animation* AnimationEffect::GetAnimation() const {
  return owner_ ? owner_->GetAnimation() : nullptr;
}

void AnimationEffect::Trace(Visitor* visitor) const {
  visitor->Trace(owner_);
  visitor->Trace(event_delegate_);
  ScriptWrappable::Trace(visitor);
}

}  // namespace blink
```