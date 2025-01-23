Response:
Let's break down the thought process for analyzing the `timing.cc` file.

1. **Initial Understanding of the Purpose:** The filename `timing.cc` and the namespace `blink::` strongly suggest this file deals with animation timing within the Blink rendering engine. The inclusion of headers like `V8ComputedEffectTiming.h`, `V8EffectTiming.h`, etc., further points towards an interface between C++ and JavaScript (V8).

2. **Scanning for Key Structures and Functions:**  I'd start by skimming the file to identify the main classes, structs, and functions. The `Timing` class is prominent. I'd note functions like `ToV8Delay`, `FillModeEnum`, `EnumToFillMode`, `PlaybackDirectionString`, `ResolvedFillMode`, `ConvertToEffectTiming`, `ToComputedValue`, `getComputedTiming`, and `CalculateTimings`. These names hint at their responsibilities.

3. **Analyzing Core Functions:**  Now, I'd dive deeper into the most important functions:

    * **`ToV8Delay`:**  The name suggests converting a delay value to a V8 representation. The comment `// TODO(crbug.com/1216527) support delay as percentage.` is a valuable clue, indicating a current limitation.

    * **`FillModeEnum` and `EnumToFillMode`:**  These clearly handle the conversion between the C++ `FillMode` enum and its V8 counterpart. The `switch` statements are straightforward.

    * **`PlaybackDirectionString`:** This converts the `PlaybackDirection` enum to a string, likely for use in JavaScript APIs.

    * **`ResolvedFillMode`:**  This function implements the logic for resolving the `fill` mode, especially when it's `AUTO`. The distinction between keyframe effects and other animations is important.

    * **`ConvertToEffectTiming`:**  This is a crucial function. It creates a `EffectTiming` object (likely a JavaScript representation) and populates it with the `Timing` object's properties. The conversion of `iteration_duration` to a `V8UnionCSSNumericValueOrStringOrUnrestrictedDouble` (handling both numeric and "auto" values) is noteworthy.

    * **`ToComputedValue`:** This handles the conversion of time values to CSS-compatible units (milliseconds or percentages), depending on the timeline type. The logic for handling progress-based timelines (with `max_time`) is important.

    * **`getComputedTiming`:**  This function calculates and constructs a `ComputedEffectTiming` object, which provides more detailed information about the current state of an animation. It uses the `CalculatedTiming` and `NormalizedTiming` structs as inputs. The comments referencing the Web Animations specification are key.

    * **`CalculateTimings`:** This is the most complex function. It takes a local time, whether the animation is idle, normalized timing information, animation direction, and playback rate as inputs. It calculates various timing parameters like phase, active time, progress, current iteration, and whether the animation is currently in effect or playing. The reliance on the `TimingCalculations` namespace is also worth noting (though the contents of *that* file aren't directly in front of us).

4. **Identifying Relationships with JavaScript, HTML, and CSS:**  Throughout the analysis, the frequent use of "V8" in type names and the conversion to string values for properties strongly indicate a connection to JavaScript. The mention of CSS units (`CSSUnitValues::percent`) links it to CSS. The concepts of `fill-mode`, `direction`, `easing`, and duration are directly related to CSS animations and transitions. The creation of `EffectTiming` objects points to the Web Animations API, accessible via JavaScript.

5. **Inferring Logic and Providing Examples:** Based on the function names and the Web Animations API concepts, I can start making educated guesses about the logic. For instance, `ResolvedFillMode` handles the `auto` keyword. `CalculateTimings` seems to be the core logic for determining the animation's state at a given time. To provide examples, I'd choose common use cases of these features in CSS and JavaScript.

6. **Recognizing Potential User Errors:**  Considering the input types and the logic, I would identify common mistakes like providing invalid duration values or incorrect `fill` modes in CSS or JavaScript. The comment about percentage delays being unsupported is a direct example of a potential error.

7. **Structuring the Output:** Finally, I'd organize the information into clear categories like "Functionality," "Relationship with JavaScript/HTML/CSS," "Logic and Examples," and "Common User Errors."  This makes the analysis easier to understand.

**Self-Correction/Refinement During the Process:**

* **Initial Over-reliance on Names:**  While function names are helpful, I'd avoid jumping to conclusions without examining the code. For example, `ToComputedValue` might seem simple at first, but the logic for percentage-based timelines adds complexity.

* **Clarifying Web Animations API Concepts:** I'd ensure I'm accurately representing the concepts from the Web Animations API (like `fill`, `direction`, `easing`). If I'm unsure, I'd quickly look up the specification.

* **Providing Concrete Examples:**  Instead of just saying "relates to CSS," I'd give specific CSS properties or JavaScript API methods.

* **Focusing on the *Provided* Code:** I'd avoid speculating too much about what's happening in other files (like `timing_calculations.h`). The analysis should primarily focus on the given `timing.cc` content.

By following this systematic approach, I can effectively analyze the code and extract the required information, connecting it to relevant web technologies and common usage scenarios.
这个文件 `blink/renderer/core/animation/timing.cc` 是 Chromium Blink 引擎中负责处理动画定时（timing）相关逻辑的核心组件。 它定义了 `Timing` 类，该类封装了动画的各种时间属性，并提供了计算动画状态的方法。

以下是其主要功能以及与 JavaScript, HTML, CSS 的关系：

**主要功能：**

1. **存储和管理动画的定时属性：** `Timing` 类存储了动画的关键定时属性，例如：
    * `start_delay` (动画开始前的延迟)
    * `end_delay` (动画结束后的延迟)
    * `fill_mode` (动画在开始前和结束后如何应用样式，例如 `forwards`, `backwards`, `both`, `none`, `auto`)
    * `iteration_start` (动画从哪个点开始迭代)
    * `iteration_count` (动画重复的次数)
    * `iteration_duration` (单次迭代的持续时间)
    * `direction` (动画播放的方向，例如 `normal`, `reverse`, `alternate`, `alternate-reverse`)
    * `timing_function` (缓动函数，定义动画速度的变化曲线，例如 `ease`, `linear`, `cubic-bezier(...)`)

2. **与 JavaScript 接口：**  该文件包含了与 JavaScript 交互的代码，使用了 Blink 的绑定机制（`third_party/blink/renderer/bindings/core/v8/...`）。它提供了将 `Timing` 对象转换为 JavaScript 可理解的 `EffectTiming` 和 `ComputedEffectTiming` 对象的方法。
    * `ConvertToEffectTiming()`:  将 `Timing` 对象的属性转换为 `EffectTiming` 对象，这个对象对应 JavaScript 中的 `AnimationEffect.timing` 属性，允许 JavaScript 代码获取和修改动画的定时信息。
    * `getComputedTiming()`:  计算动画在特定时间点的状态，并将其封装到 `ComputedEffectTiming` 对象中。这个对象对应 JavaScript 中的 `Animation.getComputedTiming()` 方法的返回值。

3. **计算动画的当前状态：** `CalculateTimings()` 函数是核心，它根据当前时间、动画的定时属性以及播放速率等因素，计算动画的各种状态，例如：
    * `phase`: 动画所处的阶段 (before, active, after, idle)。
    * `current_iteration`: 当前迭代次数。
    * `progress`: 动画当前的进度值 (0 到 1)。
    * `is_in_effect`: 动画是否在生效。
    * `is_in_play`: 动画是否正在播放。
    * `local_time`: 动画的本地时间。
    * `time_to_next_iteration`: 到下一次迭代剩余的时间。

4. **处理 `fill` 模式的解析：** `ResolvedFillMode()` 函数根据动画是否为关键帧动画来解析 `fill` 模式。`fill: auto` 对关键帧动画和普通动画有不同的行为。

5. **类型转换和枚举处理：**  提供了一些辅助函数，用于在 C++ 内部的枚举类型和 JavaScript 可以理解的字符串或枚举值之间进行转换，例如 `FillModeEnum()`, `EnumToFillMode()`, `PlaybackDirectionString()`。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **CSS 动画和过渡:**  当浏览器解析 CSS 动画 (`@keyframes`) 或过渡 (`transition`) 时，会创建 `Timing` 对象来存储这些动画的定时属性。例如，以下 CSS 代码：

  ```css
  .element {
    animation-name: fadeIn;
    animation-duration: 1s;
    animation-delay: 0.5s;
    animation-fill-mode: forwards;
    animation-iteration-count: infinite;
    animation-direction: alternate;
    animation-timing-function: ease-in-out;
  }
  ```

  Blink 引擎会创建一个 `Timing` 对象，其属性值对应于 CSS 中设置的值：`start_delay` 为 0.5 秒，`iteration_duration` 为 1 秒，`fill_mode` 为 `FORWARDS` 等。

* **Web Animations API (JavaScript):** JavaScript 可以通过 Web Animations API 直接控制动画的定时。例如，可以使用 `Element.animate()` 方法创建一个动画，并传入一个包含 `duration`, `delay`, `easing` 等属性的 `timing` 对象：

  ```javascript
  const element = document.querySelector('.element');
  const animation = element.animate([
    { opacity: 0 },
    { opacity: 1 }
  ], {
    duration: 1000, // 对应 iteration_duration
    delay: 500,     // 对应 start_delay
    fill: 'forwards', // 对应 fill_mode
    iterations: Infinity, // 对应 iteration_count
    direction: 'alternate', // 对应 direction
    easing: 'ease-in-out'  // 对应 timing_function
  });
  ```

  `timing.cc` 中的 `ConvertToEffectTiming()` 函数用于将 C++ 的 `Timing` 对象转换为 JavaScript 可以操作的 `EffectTiming` 对象，使得 JavaScript 可以读取和修改这些属性。  `getComputedTiming()` 则对应 JavaScript 的 `animation.getComputedTiming()` 方法，允许获取动画在当前时刻的详细状态。

* **HTML 和 DOM:**  虽然 `timing.cc` 本身不直接操作 HTML 元素或 DOM 结构，但它为应用于 HTML 元素的动画提供底层的时间管理。动画的目标是在特定的时间范围内改变 HTML 元素的样式属性，而 `timing.cc` 负责计算这个时间范围内的进度和状态。

**逻辑推理与假设输入输出：**

以 `CalculateTimings()` 函数为例，我们可以进行一些假设输入和输出的推理：

**假设输入：**

* `local_time`: 假设为 1500 毫秒 (表示动画开始后的 1.5 秒)
* `is_idle`: `false` (动画不是空闲状态)
* `normalized_timing.active_duration`: 假设为 1000 毫秒 (动画的有效持续时间)
* `normalized_timing.iteration_duration`: 假设为 500 毫秒 (单次迭代时长)
* `animation_direction`: `AnimationDirection::NORMAL`
* `is_keyframe_effect`: `false`
* `playback_rate`: 可选，假设为 1

**基于假设输入的逻辑推理和可能的输出：**

1. **计算 `current_phase`:**  如果 `local_time` 为 1500ms，且动画有 500ms 的 `start_delay`（假设 `normalized_timing` 中包含此信息），那么有效作用时间是 1500 - 500 = 1000ms。由于 `active_duration` 是 1000ms，此时动画可能处于 `kPhaseActive` 阶段。

2. **计算 `current_iteration`:**  有效作用时间为 1000ms，`iteration_duration` 为 500ms，那么可能正在进行第二次迭代 (`current_iteration` 可能为 1，因为迭代从 0 开始）。

3. **计算 `progress`:**  在第二次迭代中，经过的时间是 1000ms - 500ms = 500ms。由于 `iteration_duration` 是 500ms，那么 `progress` 可能接近 1。

4. **计算 `is_in_effect`:** 由于 `local_time` 大于 `start_delay` 且小于动画结束时间，`is_in_effect` 应该为 `true`。

5. **计算 `is_in_play`:** 如果 `current_phase` 是 `kPhaseActive`，那么 `is_in_play` 应该为 `true`。

**可能的输出（`CalculatedTiming` 对象）：**

* `phase`: `Timing::kPhaseActive`
* `current_iteration`: `1`
* `progress`: 接近 `1.0`
* `is_in_effect`: `true`
* `is_in_play`: `true`
* `local_time`: `1500ms`
* `time_to_next_iteration`: 可能为 `0ms` (如果正好在迭代结束时) 或一个较小的值。

**用户或编程常见的使用错误：**

1. **`delay` 使用百分比 (目前不支持):**  代码中有 `// TODO(crbug.com/1216527) support delay as percentage.` 的注释，表明目前 `delay` 属性可能不支持百分比值。如果用户尝试在 CSS 或 JavaScript 中将动画的 `delay` 设置为百分比，可能会导致解析错误或行为不符合预期。

   **示例 (错误用法):**

   ```css
   .element {
     animation-delay: 50%; /* 可能不会按预期工作 */
   }
   ```

   ```javascript
   element.animate([], { delay: '50%' }); // 也可能导致问题
   ```

2. **`fill-mode` 使用不当导致动画状态闪烁:**  如果 `fill-mode` 设置不当，例如设置为 `none`，动画在开始前和结束后可能会恢复到初始状态，导致闪烁。

   **示例 (可能导致闪烁):**

   ```css
   .element {
     animation-fill-mode: none;
     /* ...其他动画属性 */
   }
   ```

   如果动画旨在保持结束时的状态，应该使用 `forwards`。

3. **`iteration-count` 设置为非数字或负数:**  如果用户错误地将 `iteration-count` 设置为非数字字符串或负数，可能会导致动画不播放或行为异常。

   **示例 (错误用法):**

   ```css
   .element {
     animation-iteration-count: 'infinite-typo'; /* 应该使用 infinite */
   }
   ```

   ```javascript
   element.animate([], { iterations: -1 }); // 无效的迭代次数
   ```

4. **`duration` 设置为零或负数:**  将动画的 `duration` 设置为零或负数通常会导致动画立即完成，可能不会产生预期的视觉效果。

   **示例 (可能看不到动画效果):**

   ```css
   .element {
     animation-duration: 0s;
   }
   ```

5. **缓动函数 `cubic-bezier` 参数错误:** 如果使用 `cubic-bezier` 定义缓动函数，但提供的参数超出范围 (0 到 1)，可能会导致缓动效果不正确或被忽略。

   **示例 (参数错误):**

   ```css
   .element {
     animation-timing-function: cubic-bezier(1.5, 0, 0, 1); /* 第一个参数超出范围 */
   }
   ```

理解 `timing.cc` 的功能对于深入了解 Chromium Blink 引擎的动画实现至关重要，它连接了 CSS 声明、JavaScript API 和底层的动画计算逻辑。

### 提示词
```
这是目录为blink/renderer/core/animation/timing.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/animation/timing.h"

#include "third_party/blink/renderer/bindings/core/v8/v8_computed_effect_timing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_effect_timing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_timeline_range_offset.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_cssnumericvalue_double.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_cssnumericvalue_string_unrestricteddouble.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_double_string.h"
#include "third_party/blink/renderer/core/animation/timing_calculations.h"
#include "third_party/blink/renderer/core/css/cssom/css_unit_values.h"

namespace blink {

Timing::V8Delay* Timing::Delay::ToV8Delay() const {
  // TODO(crbug.com/1216527) support delay as percentage.
  return MakeGarbageCollected<V8Delay>(AsTimeValue().InMillisecondsF());
}

V8FillMode::Enum Timing::FillModeEnum(FillMode fill_mode) {
  switch (fill_mode) {
    case FillMode::NONE:
      return V8FillMode::Enum::kNone;
    case FillMode::FORWARDS:
      return V8FillMode::Enum::kForwards;
    case FillMode::BACKWARDS:
      return V8FillMode::Enum::kBackwards;
    case FillMode::BOTH:
      return V8FillMode::Enum::kBoth;
    case FillMode::AUTO:
      return V8FillMode::Enum::kAuto;
  }
}

Timing::FillMode Timing::EnumToFillMode(V8FillMode::Enum fill_mode) {
  switch (fill_mode) {
    case V8FillMode::Enum::kNone:
      return Timing::FillMode::NONE;
    case V8FillMode::Enum::kBackwards:
      return Timing::FillMode::BACKWARDS;
    case V8FillMode::Enum::kBoth:
      return Timing::FillMode::BOTH;
    case V8FillMode::Enum::kForwards:
      return Timing::FillMode::FORWARDS;
    case V8FillMode::Enum::kAuto:
      return Timing::FillMode::AUTO;
  }
}

String Timing::PlaybackDirectionString(PlaybackDirection playback_direction) {
  switch (playback_direction) {
    case PlaybackDirection::NORMAL:
      return "normal";
    case PlaybackDirection::REVERSE:
      return "reverse";
    case PlaybackDirection::ALTERNATE_NORMAL:
      return "alternate";
    case PlaybackDirection::ALTERNATE_REVERSE:
      return "alternate-reverse";
  }
  NOTREACHED();
}

Timing::FillMode Timing::ResolvedFillMode(bool is_keyframe_effect) const {
  if (fill_mode != Timing::FillMode::AUTO)
    return fill_mode;

  // https://w3.org/TR/web-animations-1/#the-effecttiming-dictionaries
  if (is_keyframe_effect)
    return Timing::FillMode::NONE;
  return Timing::FillMode::BOTH;
}

EffectTiming* Timing::ConvertToEffectTiming() const {
  EffectTiming* effect_timing = EffectTiming::Create();

  // Specified values used here so that inputs match outputs for JS API calls
  effect_timing->setDelay(start_delay.ToV8Delay());
  effect_timing->setEndDelay(end_delay.ToV8Delay());
  effect_timing->setFill(FillModeEnum(fill_mode));
  effect_timing->setIterationStart(iteration_start);
  effect_timing->setIterations(iteration_count);
  V8UnionCSSNumericValueOrStringOrUnrestrictedDouble* duration;
  if (iteration_duration) {
    duration = MakeGarbageCollected<
        V8UnionCSSNumericValueOrStringOrUnrestrictedDouble>(
        iteration_duration->InMillisecondsF());
  } else {
    duration = MakeGarbageCollected<
        V8UnionCSSNumericValueOrStringOrUnrestrictedDouble>("auto");
  }
  effect_timing->setDuration(duration);
  effect_timing->setDirection(PlaybackDirectionString(direction));
  effect_timing->setEasing(timing_function->ToString());

  return effect_timing;
}

// Converts values to CSSNumberish based on corresponding timeline type
V8CSSNumberish* Timing::ToComputedValue(
    std::optional<AnimationTimeDelta> time,
    std::optional<AnimationTimeDelta> max_time) const {
  if (time) {
    // A valid timeline_duration indicates use of progress based timeline. We
    // need to convert values to percentages using timeline_duration as 100%
    if (max_time) {
      return MakeGarbageCollected<V8CSSNumberish>(
          CSSUnitValues::percent((time.value() / max_time.value()) * 100));
    } else {
      // For time based timeline, simply return the value in milliseconds.
      return MakeGarbageCollected<V8CSSNumberish>(
          time.value().InMillisecondsF());
    }
  }
  return nullptr;
}

ComputedEffectTiming* Timing::getComputedTiming(
    const CalculatedTiming& calculated_timing,
    const NormalizedTiming& normalized_timing,
    bool is_keyframe_effect) const {
  ComputedEffectTiming* computed_timing = ComputedEffectTiming::Create();

  // ComputedEffectTiming members.
  computed_timing->setEndTime(ToComputedValue(
      normalized_timing.end_time, normalized_timing.timeline_duration));
  computed_timing->setActiveDuration(ToComputedValue(
      normalized_timing.active_duration, normalized_timing.timeline_duration));
  computed_timing->setLocalTime(ToComputedValue(
      calculated_timing.local_time, normalized_timing.timeline_duration));

  if (calculated_timing.is_in_effect) {
    DCHECK(calculated_timing.current_iteration);
    DCHECK(calculated_timing.progress);
    computed_timing->setProgress(calculated_timing.progress.value());
    computed_timing->setCurrentIteration(
        calculated_timing.current_iteration.value());
  } else {
    computed_timing->setProgress(std::nullopt);
    computed_timing->setCurrentIteration(std::nullopt);
  }

  // For the EffectTiming members, getComputedTiming is equivalent to getTiming
  // except that the fill and duration must be resolved.
  //
  // https://w3.org/TR/web-animations-1/#dom-animationeffect-getcomputedtiming

  // TODO(crbug.com/1216527): Animation effect timing members start_delay and
  // end_delay should be CSSNumberish
  computed_timing->setDelay(start_delay.ToV8Delay());
  computed_timing->setEndDelay(end_delay.ToV8Delay());
  computed_timing->setFill(
      Timing::FillModeEnum(ResolvedFillMode(is_keyframe_effect)));
  computed_timing->setIterationStart(iteration_start);
  computed_timing->setIterations(iteration_count);

  V8CSSNumberish* computed_duration =
      ToComputedValue(normalized_timing.iteration_duration,
                      normalized_timing.timeline_duration);
  if (computed_duration->IsCSSNumericValue()) {
    if (normalized_timing.timeline_duration) {
      computed_timing->setDuration(
          MakeGarbageCollected<
              V8UnionCSSNumericValueOrStringOrUnrestrictedDouble>(
              computed_duration->GetAsCSSNumericValue()));
    }
  } else {
    computed_timing->setDuration(
        MakeGarbageCollected<
            V8UnionCSSNumericValueOrStringOrUnrestrictedDouble>(
            computed_duration->GetAsDouble()));
  }

  computed_timing->setDirection(Timing::PlaybackDirectionString(direction));
  computed_timing->setEasing(timing_function->ToString());

  return computed_timing;
}

Timing::CalculatedTiming Timing::CalculateTimings(
    std::optional<AnimationTimeDelta> local_time,
    bool is_idle,
    const NormalizedTiming& normalized_timing,
    AnimationDirection animation_direction,
    bool is_keyframe_effect,
    std::optional<double> playback_rate) const {
  const AnimationTimeDelta active_duration = normalized_timing.active_duration;
  const AnimationTimeDelta duration = normalized_timing.iteration_duration;

  Timing::Phase current_phase = TimingCalculations::CalculatePhase(
      normalized_timing, local_time, animation_direction);

  const std::optional<AnimationTimeDelta> active_time =
      TimingCalculations::CalculateActiveTime(
          normalized_timing, ResolvedFillMode(is_keyframe_effect), local_time,
          current_phase);

  std::optional<double> progress;

  const std::optional<double> overall_progress =
      TimingCalculations::CalculateOverallProgress(current_phase, active_time,
                                                   duration, iteration_count,
                                                   iteration_start);
  const std::optional<double> simple_iteration_progress =
      TimingCalculations::CalculateSimpleIterationProgress(
          current_phase, overall_progress, iteration_start, active_time,
          active_duration, iteration_count);
  const std::optional<double> current_iteration =
      TimingCalculations::CalculateCurrentIteration(
          current_phase, active_time, iteration_count, overall_progress,
          simple_iteration_progress);
  const bool current_direction_is_forwards =
      TimingCalculations::IsCurrentDirectionForwards(current_iteration,
                                                     direction);
  const std::optional<double> directed_progress =
      TimingCalculations::CalculateDirectedProgress(
          simple_iteration_progress, current_iteration, direction);

  progress = TimingCalculations::CalculateTransformedProgress(
      current_phase, directed_progress, current_direction_is_forwards,
      timing_function);

  AnimationTimeDelta time_to_next_iteration = AnimationTimeDelta::Max();
  // Conditionally compute the time to next iteration, which is only
  // applicable if the iteration duration is non-zero.
  if (!duration.is_zero()) {
    const AnimationTimeDelta start_offset =
        TimingCalculations::MultiplyZeroAlwaysGivesZero(duration,
                                                        iteration_start);
    DCHECK_GE(start_offset, AnimationTimeDelta());
    const std::optional<AnimationTimeDelta> offset_active_time =
        TimingCalculations::CalculateOffsetActiveTime(
            active_duration, active_time, start_offset);
    const std::optional<AnimationTimeDelta> iteration_time =
        TimingCalculations::CalculateIterationTime(
            duration, active_duration, offset_active_time, start_offset,
            current_phase, *this);
    if (iteration_time) {
      // active_time cannot be null if iteration_time is not null.
      DCHECK(active_time);
      time_to_next_iteration = duration - iteration_time.value();
      if (active_duration - active_time.value() < time_to_next_iteration)
        time_to_next_iteration = AnimationTimeDelta::Max();
    }
  }

  CalculatedTiming calculated = CalculatedTiming();
  calculated.phase = current_phase;
  calculated.current_iteration = current_iteration;
  calculated.progress = progress;
  calculated.is_in_effect = active_time.has_value();
  // If active_time is not null then current_iteration and (transformed)
  // progress are also non-null).
  DCHECK(!calculated.is_in_effect ||
         (current_iteration.has_value() && progress.has_value()));
  calculated.is_in_play = calculated.phase == Timing::kPhaseActive;

  // https://w3.org/TR/web-animations-1/#current
  calculated.is_current = calculated.is_in_play ||
                          (playback_rate.has_value() && playback_rate > 0 &&
                           calculated.phase == Timing::kPhaseBefore) ||
                          (playback_rate.has_value() && playback_rate < 0 &&
                           calculated.phase == Timing::kPhaseAfter) ||
                          (!is_idle && normalized_timing.timeline_duration);

  calculated.local_time = local_time;
  calculated.time_to_next_iteration = time_to_next_iteration;

  return calculated;
}

}  // namespace blink
```