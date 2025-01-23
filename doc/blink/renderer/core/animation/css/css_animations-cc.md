Response:
My thought process to answer the request "这是目录为blink/renderer/core/animation/css/css_animations.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 如果它与javascript, html, css的功能有关系，请做出对应的举例说明，如果做了逻辑推理，请给出假设输入与输出, 如果涉及用户或者编程常见的使用错误，请举例说明 这是第1部分，共5部分，请归纳一下它的功能" follows these steps:

1. **Understand the Core Request:** The primary goal is to analyze the provided C++ code snippet from `css_animations.cc` and explain its purpose and relationships with web technologies (HTML, CSS, JavaScript), including potential issues and a summary. The "第1部分，共5部分" indicates this is an initial overview and I should focus on the overarching functionality revealed in this segment.

2. **Identify Key Data Structures and Classes:** I scan the `#include` directives and the code itself to identify the central classes and data structures being used. Key ones that jump out are:

    * `CSSAnimations`: The file name itself suggests this is a crucial class.
    * `CSSAnimation`, `CSSTransition`: These are specific types of CSS animations.
    * `Keyframe`, `StringKeyframe`:  Related to animation keyframes.
    * `KeyframeEffectModel`, `CssKeyframeEffectModel`: Represent the model of keyframe animations.
    * `AnimationTimeline`, `DocumentTimeline`:  Deal with the timing of animations.
    * `Timing`: Structure to hold animation timing properties.
    * `ComputedStyle`: Represents the final computed style of an element.
    * `StyleRuleKeyframes`, `StyleRuleKeyframe`: Represent the CSS `@keyframes` rule.

3. **Infer High-Level Functionality:** Based on the included headers and the names of classes and functions, I can deduce the main purpose of this code: **It's responsible for handling CSS Animations within the Blink rendering engine.** This includes:

    * **Parsing and Processing `@keyframes` rules:** The `ProcessKeyframesRule` function is a clear indicator of this. It extracts information from the CSS rules.
    * **Creating and managing `CSSAnimation` objects:**  The `CSSAnimationProxy` class and related logic hint at the creation and lifecycle management of these animation objects.
    * **Calculating animation timing and progress:** Functions like `CalculateInheritedTime`, `StartTimeFromDelay`, `IntervalStart`, `IntervalEnd`, and `IterationElapsedTime` point to this aspect.
    * **Merging and optimizing keyframes:** The logic within `ProcessKeyframesRule` about finding and merging keyframes demonstrates optimization efforts.
    * **Interacting with the rendering pipeline:** The inclusion of headers related to `LayoutObject`, `PaintLayer`, and `ComputedStyle` suggests integration with the rendering process.

4. **Connect to HTML, CSS, and JavaScript:**  I think about how this C++ code relates to the front-end technologies:

    * **CSS:** This is the most direct connection. The code parses `@keyframes` rules, understands properties like `animation-name`, `animation-duration`, `animation-timing-function`, etc. It manipulates styles based on these animations.
    * **HTML:** The animations are applied to HTML elements. The code interacts with `Element` objects and their associated styles.
    * **JavaScript:** JavaScript can interact with CSS Animations through the Web Animations API. While this specific file might not directly handle the JavaScript API, it provides the underlying mechanics that the API uses. JavaScript can control animation playback, timing, and even create animations programmatically.

5. **Identify Logical Inferences and Potential Inputs/Outputs:** I look for functions that perform calculations or transformations based on inputs.

    * **`ProcessKeyframesRule`:** *Input:* A `StyleRuleKeyframes` object (parsed from CSS). *Output:* A `StringKeyframeVector` representing the processed keyframes.
    * **`CalculateInheritedTime`:** *Input:* Animation timeline, animation object, range start/end, timing. *Output:* The inherited animation time.
    * **`StartTimeFromDelay`:** *Input:* Animation start delay. *Output:* The animation start time.

6. **Consider Common Errors:**  I think about potential mistakes developers might make when using CSS Animations and how this code might handle them:

    * **Syntax errors in `@keyframes`:**  The parsing logic in `ProcessKeyframesRule` likely has error handling (although not explicitly shown in this snippet).
    * **Conflicting animation properties:** The merging logic in `ProcessKeyframesRule` addresses how to resolve conflicts between keyframes.
    * **Incorrect timing values:**  The timing calculation functions could potentially detect or handle invalid timing values.
    * **JavaScript manipulation causing inconsistencies:**  The interaction with the Web Animations API could lead to scenarios where JavaScript attempts to manipulate animations in ways that conflict with CSS-defined animations. This code needs to be robust enough to handle these interactions.

7. **Summarize the Functionality (Part 1):** Based on the analysis of this first part of the file, I focus on the core responsibilities evident so far. I avoid speculating too much about parts of the animation process not yet visible. My summary points include:

    * Parsing and processing CSS `@keyframes` rules.
    * Creating and managing internal representations of CSS animations.
    * Calculating animation timing and progress based on CSS properties.
    * Merging keyframes for optimization.
    * Laying the groundwork for applying animations to HTML elements.

By following these steps, I arrive at the comprehensive explanation provided in the initial good answer, ensuring that the analysis is grounded in the provided code and addresses all aspects of the prompt.
这是 Chromium Blink 引擎源代码文件 `blink/renderer/core/animation/css/css_animations.cc` 的第一部分，主要负责处理和管理 CSS 动画的创建、解析、更新和生命周期。它将 CSS 中定义的动画效果转化为浏览器可以理解和执行的内部表示。

以下是它的主要功能归纳和与前端技术的关系：

**核心功能：**

1. **解析 CSS `@keyframes` 规则：**
   -  `ProcessKeyframesRule` 函数负责解析 CSS 中定义的 `@keyframes` 规则。
   -  它从 `StyleRuleKeyframes` 对象中提取关键帧的偏移量、缓动函数、以及要动画的 CSS 属性和值。
   -  它会将简写属性展开为长写属性，并处理逻辑属性到物理属性的转换。
   -  **与 CSS 的关系：** 直接解析和理解 CSS 动画的定义。例如，解析以下 CSS 代码：
     ```css
     @keyframes my-animation {
       0% { opacity: 0; transform: translateX(0); }
       50% { opacity: 1; }
       100% { opacity: 0; transform: translateX(100px); }
     }
     ```
     `ProcessKeyframesRule` 会提取出 `opacity` 和 `transform` 属性在不同百分比下的值和缓动函数。

2. **创建和管理 `CSSAnimation` 对象：**
   -  代码中定义了 `CSSAnimationProxy` 类，它作为 `CSSAnimation` 对象的代理，负责提供动画的各种属性（如播放速率、暂停状态、继承时间等）给动画系统。
   -  `CreateKeyframeEffectModel` 函数根据解析后的 `@keyframes` 规则创建 `CssKeyframeEffectModel` 对象，这是动画效果的内部表示。
   -  **与 CSS 的关系：**  将 CSS 中 `animation-*` 属性（如 `animation-name`, `animation-duration`, `animation-timing-function` 等）与 `@keyframes` 规则关联起来，创建实际的动画对象。

3. **计算动画时间和进度：**
   -  `CalculateInheritedTime` 函数用于计算动画的继承时间，这在处理时间轴和动画同步时非常重要。
   -  `StartTimeFromDelay` 函数根据 `animation-delay` 计算动画的起始时间。
   -  `IntervalStart`, `IntervalEnd`, `IterationElapsedTime` 等函数用于计算动画在不同阶段的时间。
   -  **与 CSS 和 JavaScript 的关系：**  这些计算是实现 CSS 动画的关键，同时也影响 JavaScript 通过 Web Animations API 操作动画时的行为。例如，JavaScript 可以通过 `animation.currentTime` 获取或设置动画的当前时间，而背后的计算逻辑就可能涉及到这些函数。

4. **处理动画的 Timing：**
   -  代码涉及到 `Timing` 结构，用于存储动画的各种时间属性，如 `duration`（持续时间）、`delay`（延迟）、`iteration-count`（重复次数）等。
   -  **与 CSS 的关系：**  直接对应于 CSS 中的 `animation-duration`, `animation-delay`, `animation-iteration-count` 等属性。

5. **合并和优化关键帧：**
   -  `ProcessKeyframesRule` 中包含了合并重复关键帧的逻辑，避免创建不必要的关键帧对象。
   -  **优化性能：**  减少内存占用和计算量。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **CSS:**
    ```css
    .animated-element {
      animation-name: slide-in;
      animation-duration: 1s;
      animation-timing-function: ease-in-out;
    }

    @keyframes slide-in {
      from { transform: translateX(-100%); opacity: 0; }
      to { transform: translateX(0); opacity: 1; }
    }
    ```
    当浏览器渲染带有 `.animated-element` 类的 HTML 元素时，`css_animations.cc` 中的代码会解析 `slide-in` 动画的 `@keyframes` 规则，并根据 `animation-*` 属性创建 `CSSAnimation` 对象。

* **HTML:**
    ```html
    <div class="animated-element">This will be animated!</div>
    ```
    `css_animations.cc` 中的代码会与 HTML 元素关联，确定哪些元素应用了哪些 CSS 动画。

* **JavaScript:**
    ```javascript
    const element = document.querySelector('.animated-element');
    element.getAnimations().forEach(animation => {
      console.log(animation.playState);
      animation.pause();
      setTimeout(() => animation.play(), 2000);
    });
    ```
    JavaScript 通过 Web Animations API 可以访问和控制 CSS 动画。 `css_animations.cc` 中计算的动画时间和状态会被暴露给 JavaScript API。 例如，`animation.playState` 的值就反映了 `CSSAnimation` 对象的内部状态。 `animation.pause()` 和 `animation.play()` 等方法会触发 `css_animations.cc` 中相应的逻辑。

**假设输入与输出（逻辑推理）：**

**假设输入：**  一个包含以下 CSS 规则的样式表被应用到一个 HTML 元素上：
```css
@keyframes fade-out {
  0% { opacity: 1; }
  100% { opacity: 0; }
}

.fadeable {
  animation: fade-out 0.5s linear;
}
```

**输出（`ProcessKeyframesRule` 的可能输出）：**
一个 `StringKeyframeVector`，包含两个 `StringKeyframe` 对象：

1. 第一个 `StringKeyframe`：
   - `offset`: 0
   - 包含属性：`opacity: 1`

2. 第二个 `StringKeyframe`：
   - `offset`: 1
   - 包含属性：`opacity: 0`

**用户或编程常见的使用错误举例：**

1. **`@keyframes` 规则语法错误：**  例如，关键帧偏移量不是百分比或 `from`/`to` 关键字，或者属性值不合法。`css_animations.cc` 中的解析逻辑需要能够处理这些错误，可能忽略错误的规则或回退到默认值。

2. **动画属性命名错误：**  如果在 CSS 中使用了不存在的 `animation-*` 属性，`css_animations.cc` 中对应的处理逻辑可能不会被触发，导致动画无法生效。

3. **关键帧偏移量重复且属性冲突：**  如果 `@keyframes` 中定义了多个具有相同偏移量的关键帧，并且它们设置了同一个属性的不同值，`ProcessKeyframesRule` 中会使用最后定义的那个。开发者可能没有意识到这一点导致动画效果与预期不符。

4. **JavaScript 操作与 CSS 动画冲突：**  例如，JavaScript 直接修改了动画正在改变的属性，可能会导致动画效果中断或出现跳跃。 `css_animations.cc` 的设计需要能够协调 CSS 动画和 JavaScript 的操作。

**总结（第 1 部分的功能）：**

这部分 `css_animations.cc` 文件的主要功能是**解析 CSS 动画的定义并将其转换为浏览器内部可以处理的数据结构**。它负责从 `@keyframes` 规则中提取关键帧信息，并根据 `animation-*` 属性创建和管理 `CSSAnimation` 对象。此外，它还包含了计算动画时间和进度的关键逻辑，为后续的动画执行奠定了基础。这部分代码是 Blink 引擎中实现 CSS 动画的核心组件之一，直接关系到网页中 CSS 动画的正确渲染和 JavaScript 对动画的控制。

### 提示词
```
这是目录为blink/renderer/core/animation/css/css_animations.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能
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

#include "third_party/blink/renderer/core/animation/css/css_animations.h"

#include <algorithm>
#include <bitset>
#include <tuple>

#include "base/containers/contains.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_computed_effect_timing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_cssnumericvalue_double.h"
#include "third_party/blink/renderer/core/animation/animation.h"
#include "third_party/blink/renderer/core/animation/animation_utils.h"
#include "third_party/blink/renderer/core/animation/compositor_animations.h"
#include "third_party/blink/renderer/core/animation/css/compositor_keyframe_value_factory.h"
#include "third_party/blink/renderer/core/animation/css/css_animation.h"
#include "third_party/blink/renderer/core/animation/css/css_keyframe_effect_model.h"
#include "third_party/blink/renderer/core/animation/css/css_transition.h"
#include "third_party/blink/renderer/core/animation/css_default_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/css_interpolation_types_map.h"
#include "third_party/blink/renderer/core/animation/document_animations.h"
#include "third_party/blink/renderer/core/animation/document_timeline.h"
#include "third_party/blink/renderer/core/animation/element_animations.h"
#include "third_party/blink/renderer/core/animation/inert_effect.h"
#include "third_party/blink/renderer/core/animation/interpolable_length.h"
#include "third_party/blink/renderer/core/animation/interpolation.h"
#include "third_party/blink/renderer/core/animation/interpolation_environment.h"
#include "third_party/blink/renderer/core/animation/interpolation_type.h"
#include "third_party/blink/renderer/core/animation/keyframe_effect.h"
#include "third_party/blink/renderer/core/animation/keyframe_effect_model.h"
#include "third_party/blink/renderer/core/animation/timing.h"
#include "third_party/blink/renderer/core/animation/timing_calculations.h"
#include "third_party/blink/renderer/core/animation/transition_interpolation.h"
#include "third_party/blink/renderer/core/animation/worklet_animation_base.h"
#include "third_party/blink/renderer/core/css/css_keyframe_rule.h"
#include "third_party/blink/renderer/core/css/css_property_equality.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/css/native_paint_image_generator.h"
#include "third_party/blink/renderer/core/css/parser/css_variable_parser.h"
#include "third_party/blink/renderer/core/css/post_style_update_scope.h"
#include "third_party/blink/renderer/core/css/properties/computed_style_utils.h"
#include "third_party/blink/renderer/core/css/properties/css_property.h"
#include "third_party/blink/renderer/core/css/properties/css_property_ref.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/property_registry.h"
#include "third_party/blink/renderer/core/css/resolver/css_to_style_map.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/events/event_path.h"
#include "third_party/blink/renderer/core/dom/layout_tree_builder_traversal.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/events/animation_event.h"
#include "third_party/blink/renderer/core/events/transition_event.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/style_property_shorthand.h"
#include "third_party/blink/renderer/platform/animation/timing_function.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/hash_set.h"

namespace blink {

using PropertySet = HashSet<CSSPropertyName>;

namespace {

class CSSAnimationProxy : public AnimationProxy {
 public:
  CSSAnimationProxy(AnimationTimeline* timeline,
                    CSSAnimation* animation,
                    bool is_paused,
                    const std::optional<TimelineOffset>& range_start,
                    const std::optional<TimelineOffset>& range_end,
                    const Timing& timing);

  // AnimationProxy interface.
  bool AtScrollTimelineBoundary() const override {
    return at_scroll_timeline_boundary_;
  }
  std::optional<AnimationTimeDelta> TimelineDuration() const override {
    return timeline_duration_;
  }
  AnimationTimeDelta IntrinsicIterationDuration() const override {
    return intrinsic_iteration_duration_;
  }
  double PlaybackRate() const override { return playback_rate_; }
  bool Paused() const override { return is_paused_; }
  std::optional<AnimationTimeDelta> InheritedTime() const override {
    return inherited_time_;
  }

 private:
  std::optional<AnimationTimeDelta> CalculateInheritedTime(
      AnimationTimeline* timeline,
      CSSAnimation* animation,
      const std::optional<TimelineOffset>& range_start,
      const std::optional<TimelineOffset>& range_end,
      const Timing& timing);

  double playback_rate_ = 1;
  std::optional<AnimationTimeDelta> inherited_time_;
  AnimationTimeDelta intrinsic_iteration_duration_;
  std::optional<AnimationTimeDelta> timeline_duration_;
  bool is_paused_;
  bool at_scroll_timeline_boundary_ = false;
};

CSSAnimationProxy::CSSAnimationProxy(
    AnimationTimeline* timeline,
    CSSAnimation* animation,
    bool is_paused,
    const std::optional<TimelineOffset>& range_start,
    const std::optional<TimelineOffset>& range_end,
    const Timing& timing)
    : is_paused_(is_paused) {
  std::optional<TimelineOffset> adjusted_range_start;
  std::optional<TimelineOffset> adjusted_range_end;
  if (animation) {
    playback_rate_ = animation->playbackRate();
    adjusted_range_start = animation->GetIgnoreCSSRangeStart()
                               ? animation->GetRangeStartInternal()
                               : range_start;
    adjusted_range_end = animation->GetIgnoreCSSRangeEnd()
                             ? animation->GetRangeEndInternal()
                             : range_end;
  } else {
    adjusted_range_start = range_start;
    adjusted_range_end = range_end;
  }

  intrinsic_iteration_duration_ =
      timeline ? timeline->CalculateIntrinsicIterationDuration(
                     adjusted_range_start, adjusted_range_end, timing)
               : AnimationTimeDelta();
  inherited_time_ = CalculateInheritedTime(
      timeline, animation, adjusted_range_start, adjusted_range_end, timing);

  timeline_duration_ = timeline ? timeline->GetDuration() : std::nullopt;
  if (timeline && timeline->IsProgressBased() && timeline->CurrentTime()) {
    AnimationTimeDelta timeline_time = timeline->CurrentTime().value();
    at_scroll_timeline_boundary_ =
        timeline_time.is_zero() ||
        TimingCalculations::IsWithinAnimationTimeTolerance(
            timeline_time, timeline_duration_.value());
  }
}

std::optional<AnimationTimeDelta> CSSAnimationProxy::CalculateInheritedTime(
    AnimationTimeline* timeline,
    CSSAnimation* animation,
    const std::optional<TimelineOffset>& range_start,
    const std::optional<TimelineOffset>& range_end,
    const Timing& timing) {
  std::optional<AnimationTimeDelta> inherited_time;
  // Even in cases where current time is "preserved" the internal value may
  // change if using a scroll-driven animation since preserving the progress and
  // not the actual underlying time.
  std::optional<double> previous_progress;
  AnimationTimeline* previous_timeline = nullptr;

  if (animation) {
    // A cancelled CSS animation does not become active again due to an
    // animation update.
    if (animation->CalculateAnimationPlayState() ==
        V8AnimationPlayState::Enum::kIdle) {
      return std::nullopt;
    }

    // In most cases, current time is preserved on an animation update.
    inherited_time = animation->UnlimitedCurrentTime();
    if (inherited_time) {
      previous_progress =
          animation->TimeAsAnimationProgress(inherited_time.value());
    }
    previous_timeline = animation->TimelineInternal();
  }

  bool range_changed =
      !animation || ((range_start != animation->GetRangeStartInternal() ||
                      range_end != animation->GetRangeEndInternal()) &&
                     !animation->StartTimeInternal());
  if (timeline && timeline->IsProgressBased()) {
    if (is_paused_ && timeline != previous_timeline) {
      if (!previous_progress) {
        return std::nullopt;
      }
      // Preserve current animation progress.
      AnimationTimeDelta iteration_duration =
          timeline->CalculateIntrinsicIterationDuration(animation, timing);
      AnimationTimeDelta active_duration =
          iteration_duration * timing.iteration_count;
      // TODO(kevers): Revisit once % delays are supported.
      return previous_progress.value() * active_duration;
    }

    if ((timeline == previous_timeline) && !range_changed) {
      return inherited_time;
    }

    // Running animation with an update that potentially affects the
    // animation's start time. Need to compute a new value for
    // inherited_time_.
    double relative_offset;
    TimelineRange timeline_range = timeline->GetTimelineRange();
    if (playback_rate_ >= 0) {
      relative_offset =
          range_start ? timeline_range.ToFractionalOffset(range_start.value())
                      : 0;
    } else {
      relative_offset =
          range_end ? timeline_range.ToFractionalOffset(range_end.value()) : 1;
    }
    if (timeline->CurrentTime()) {
      // This might not be correct for an animation with a sticky start time.
      AnimationTimeDelta pending_start_time =
          timeline->GetDuration().value() * relative_offset;
      return (timeline->CurrentTime().value() - pending_start_time) *
             playback_rate_;
    }
    return std::nullopt;
  }

  if (previous_timeline && previous_timeline->IsProgressBased() &&
      previous_progress) {
    // Going from a progress-based timeline to a document or null timeline.
    // In this case, we preserve the animation progress to avoid a
    // discontinuity.
    AnimationTimeDelta end_time = std::max(
        timing.start_delay.AsTimeValue() +
            TimingCalculations::MultiplyZeroAlwaysGivesZero(
                timing.iteration_duration.value_or(AnimationTimeDelta()),
                timing.iteration_count) +
            timing.end_delay.AsTimeValue(),
        AnimationTimeDelta());

    return previous_progress.value() * end_time;
  }

  if (!timeline) {
    // If changing from a monotonic-timeline to a null-timeline, current time
    // may become null.
    // TODO(https://github.com/w3c/csswg-drafts/issues/6412): Update once the
    // issue is resolved.
    if (previous_timeline && previous_timeline->IsMonotonicallyIncreasing() &&
        !is_paused_ && animation->StartTimeInternal() &&
        animation->CalculateAnimationPlayState() ==
            V8AnimationPlayState::Enum::kRunning) {
      return std::nullopt;
    }
    // A new animation with a null timeline will be stuck in the play or pause
    // pending state.
    if (!inherited_time && !animation) {
      return AnimationTimeDelta();
    }
  }

  // A timeline attached to a monotonic timeline that does not currently have a
  // time will start in either the play or paused state.
  if (timeline && timeline->IsMonotonicallyIncreasing() && !inherited_time) {
    return AnimationTimeDelta();
  }

  return inherited_time;
}

class CSSTransitionProxy : public AnimationProxy {
 public:
  explicit CSSTransitionProxy(std::optional<AnimationTimeDelta> current_time)
      : current_time_(current_time) {}

  // AnimationProxy interface.
  bool AtScrollTimelineBoundary() const override { return false; }
  std::optional<AnimationTimeDelta> TimelineDuration() const override {
    return std::nullopt;
  }
  AnimationTimeDelta IntrinsicIterationDuration() const override {
    return AnimationTimeDelta();
  }
  double PlaybackRate() const override { return 1; }
  bool Paused() const override { return false; }
  std::optional<AnimationTimeDelta> InheritedTime() const override {
    return current_time_;
  }

 private:
  std::optional<AnimationTimeDelta> current_time_;
};

// A keyframe can have an offset as a fixed percent or as a
// <timeline-range percent>. In the later case, we store the specified
// offset on the Keyframe, and delay the resolution that offset until later.
// (See ResolveTimelineOffset).
bool SetOffsets(Keyframe& keyframe, const KeyframeOffset& offset) {
  if (offset.name == TimelineOffset::NamedRange::kNone) {
    keyframe.SetOffset(offset.percent);
    return false;
  }

  TimelineOffset timeline_offset(offset.name,
                                 Length::Percent(100 * offset.percent));
  keyframe.SetOffset(std::nullopt);
  keyframe.SetTimelineOffset(timeline_offset);
  return true;
}

// Processes keyframe rules, extracting the timing function and properties being
// animated for each keyframe. The extraction process is doing more work that
// strictly required for the setup to step 6 in the spec
// (https://drafts.csswg.org/css-animations-2/#keyframes) as an optimization
// to avoid needing to process each rule multiple times to extract different
// properties.
StringKeyframeVector ProcessKeyframesRule(
    const StyleRuleKeyframes* keyframes_rule,
    const TreeScope* tree_scope,
    const Document& document,
    const ComputedStyle* parent_style,
    TimingFunction* default_timing_function,
    WritingDirectionMode writing_direction,
    bool& has_named_range_keyframes) {
  StringKeyframeVector keyframes;
  const HeapVector<Member<StyleRuleKeyframe>>& style_keyframes =
      keyframes_rule->Keyframes();
  for (wtf_size_t i = 0; i < style_keyframes.size(); ++i) {
    const StyleRuleKeyframe* style_keyframe = style_keyframes[i].Get();
    auto* keyframe = MakeGarbageCollected<StringKeyframe>(tree_scope);
    const Vector<KeyframeOffset>& offsets = style_keyframe->Keys();
    DCHECK(!offsets.empty());

    has_named_range_keyframes |= SetOffsets(*keyframe, offsets[0]);
    keyframe->SetEasing(default_timing_function);
    const CSSPropertyValueSet& properties = style_keyframe->Properties();
    for (unsigned j = 0; j < properties.PropertyCount(); j++) {
      CSSPropertyValueSet::PropertyReference property_reference =
          properties.PropertyAt(j);
      CSSPropertyRef ref(property_reference.Name(), document);
      const CSSProperty& property = ref.GetProperty();
      if (property.PropertyID() == CSSPropertyID::kAnimationComposition) {
        if (const auto* value_list =
                DynamicTo<CSSValueList>(property_reference.Value())) {
          if (const auto* identifier_value =
                  DynamicTo<CSSIdentifierValue>(value_list->Item(0))) {
            keyframe->SetComposite(
                identifier_value->ConvertTo<EffectModel::CompositeOperation>());
          }
        }
      } else if (property.PropertyID() ==
                 CSSPropertyID::kAnimationTimingFunction) {
        const CSSValue& value = property_reference.Value();
        scoped_refptr<TimingFunction> timing_function;
        if (value.IsInheritedValue() && parent_style->Animations()) {
          timing_function = parent_style->Animations()->TimingFunctionList()[0];
        } else if (auto* value_list = DynamicTo<CSSValueList>(value)) {
          timing_function =
              CSSToStyleMap::MapAnimationTimingFunction(value_list->Item(0));
        } else {
          DCHECK(value.IsCSSWideKeyword());
          timing_function = CSSTimingData::InitialTimingFunction();
        }
        keyframe->SetEasing(std::move(timing_function));
      } else if (!CSSAnimations::IsAnimationAffectingProperty(property)) {
        // Map Logical to physical property name.
        const CSSProperty& physical_property =
            property.ResolveDirectionAwareProperty(writing_direction);
        const CSSPropertyName& name = physical_property.GetCSSPropertyName();
        keyframe->SetCSSPropertyValue(name, property_reference.Value());
      }
    }
    keyframes.push_back(keyframe);

    // The last keyframe specified at a given offset is used.
    for (wtf_size_t j = 1; j < offsets.size(); ++j) {
      StringKeyframe* clone = To<StringKeyframe>(keyframe->Clone());
      has_named_range_keyframes |= SetOffsets(*clone, offsets[j]);
      keyframes.push_back(clone);
    }
  }
  for (wtf_size_t i = 0; i < keyframes.size(); i++) {
    keyframes[i]->SetIndex(i);
  }
  std::stable_sort(keyframes.begin(), keyframes.end(), &Keyframe::LessThan);
  return keyframes;
}

// Finds the index of a keyframe with matching offset and easing.
std::optional<int> FindIndexOfMatchingKeyframe(
    const StringKeyframeVector& keyframes,
    wtf_size_t start_index,
    std::optional<double> offset,
    std::optional<TimelineOffset> timeline_offset,
    const TimingFunction& easing,
    const std::optional<EffectModel::CompositeOperation>& composite) {
  for (wtf_size_t i = start_index; i < keyframes.size(); i++) {
    StringKeyframe* keyframe = keyframes[i];
    // Keyframes are sorted by offset. Search can stop once we hit and offset
    // that exceeds the target value.
    if (offset && keyframe->Offset() && offset < keyframe->Offset()) {
      break;
    }

    // Timeline offsets do not need to be consecutive.
    if (timeline_offset != keyframe->GetTimelineOffset()) {
      continue;
    }

    if (easing.ToString() != keyframe->Easing().ToString()) {
      continue;
    }

    if (composite == keyframe->Composite()) {
      return i;
    }
  }
  return std::nullopt;
}

StringKeyframeEffectModel* CreateKeyframeEffectModel(
    StyleResolver* resolver,
    Element& element,
    const Element& animating_element,
    WritingDirectionMode writing_direction,
    const ComputedStyle* parent_style,
    const AtomicString& name,
    TimingFunction* default_timing_function,
    EffectModel::CompositeOperation composite,
    size_t animation_index) {
  // The algorithm for constructing string keyframes for a CSS animation is
  // covered in the following spec:
  // https://drafts.csswg.org/css-animations-2/#keyframes

  // For a given target (pseudo-)element, element, animation name, and
  // position of the animation in element’s animation-name list, keyframe
  // objects are generated as follows:

  // 1. Let default timing function be the timing function at the position
  //    of the resolved value of the animation-timing-function for element,
  //    repeating the list as necessary as described in CSS Animations 1 §4.2
  //    The animation-name property.

  // 2. Let default composite be replace.

  // 3. Find the last @keyframes at-rule in document order with <keyframes-name>
  //    matching name.
  //    If there is no @keyframes at-rule with <keyframes-name> matching name,
  //    abort this procedure. In this case no animation is generated, and any
  //    existing animation matching name is canceled.

  StyleResolver::FindKeyframesRuleResult find_result =
      resolver->FindKeyframesRule(&element, &animating_element, name);
  const StyleRuleKeyframes* keyframes_rule = find_result.rule;
  DCHECK(keyframes_rule);

  // 4. Let keyframes be an empty sequence of keyframe objects.
  StringKeyframeVector keyframes;

  // 5. Let animated properties be an empty set of longhand CSS property names.
  PropertySet animated_properties;

  // Start and end properties are also tracked to simplify the process of
  // determining if the first and last keyframes are missing properties.
  PropertySet start_properties;
  PropertySet end_properties;

  PropertySet fixed_offset_properties;

  HashMap<String, PropertySet> timeline_offset_properties_map;

  // Properties that have already been processed at the current keyframe.
  PropertySet* current_offset_properties;

  // 6. Perform a stable sort of the keyframe blocks in the @keyframes rule by
  //    the offset specified in the keyframe selector, and iterate over the
  //    result in reverse applying the following steps:
  bool has_named_range_keyframes = false;
  keyframes = ProcessKeyframesRule(keyframes_rule, find_result.tree_scope,
                                   element.GetDocument(), parent_style,
                                   default_timing_function, writing_direction,
                                   has_named_range_keyframes);

  std::optional<double> last_offset;
  wtf_size_t merged_frame_count = 0;
  for (wtf_size_t i = keyframes.size(); i > 0; --i) {
    // 6.1 Let keyframe offset be the value of the keyframe selector converted
    //     to a value in the range 0 ≤ keyframe offset ≤ 1.
    int source_index = i - 1;
    StringKeyframe* rule_keyframe = keyframes[source_index];
    std::optional<double> keyframe_offset = rule_keyframe->Offset();
    std::optional<TimelineOffset> timeline_offset =
        rule_keyframe->GetTimelineOffset();

    if (!timeline_offset) {
      current_offset_properties = &fixed_offset_properties;
    } else {
      String key = timeline_offset->ToString();
      auto it = timeline_offset_properties_map.find(key);
      if (it == timeline_offset_properties_map.end()) {
        auto add_result =
            timeline_offset_properties_map.insert(key, PropertySet());
        current_offset_properties = &add_result.stored_value->value;
      } else {
        current_offset_properties = &it.Get()->value;
      }
    }

    // 6.2 Let keyframe timing function be the value of the last valid
    //     declaration of animation-timing-function specified on the keyframe
    //     block, or, if there is no such valid declaration, default timing
    //     function.
    const TimingFunction& easing = rule_keyframe->Easing();

    // 6.3 Let keyframe composite be the value of the last valid declaration of
    // animation-composition specified on the keyframe block,
    // or, if there is no such valid declaration, default composite.
    std::optional<EffectModel::CompositeOperation> keyframe_composite =
        rule_keyframe->Composite();

    // 6.4 After converting keyframe timing function to its canonical form (e.g.
    //     such that step-end becomes steps(1, end)) let keyframe refer to the
    //     existing keyframe in keyframes with matching keyframe offset and
    //     timing function, if any.
    //     If there is no such existing keyframe, let keyframe be a new empty
    //     keyframe with offset, keyframe offset, and timing function, keyframe
    //     timing function, and prepend it to keyframes.

    // Prevent stomping a rule override by tracking properties applied at
    // the current offset.
    if (last_offset != keyframe_offset && !timeline_offset) {
      fixed_offset_properties.clear();
      last_offset = keyframe_offset;
    }

    // TODO(crbug.com/1408702): we should merge keyframes to the most left one,
    // not the most right one.
    // Avoid unnecessary creation of extra keyframes by merging into
    // existing keyframes.
    std::optional<int> existing_keyframe_index = FindIndexOfMatchingKeyframe(
        keyframes, source_index + merged_frame_count + 1, keyframe_offset,
        timeline_offset, easing, keyframe_composite);
    int target_index;
    if (existing_keyframe_index) {
      // Merge keyframe propoerties.
      target_index = existing_keyframe_index.value();
      merged_frame_count++;
    } else {
      target_index = source_index + merged_frame_count;
      if (target_index != source_index) {
        // Move keyframe to fill the gap.
        keyframes[target_index] = keyframes[source_index];
        source_index = target_index;
      }
    }

    // 6.5 Iterate over all declarations in the keyframe block and add them to
    //     keyframe such that:
    //     * All variable references are resolved to their current values.
    //     * Each shorthand property is expanded to its longhand subproperties.
    //     * All logical properties are converted to their equivalent physical
    //       properties.
    //     * For any expanded physical longhand properties that appear more than
    //       once, only the last declaration in source order is added.
    //       Note, since multiple keyframe blocks may specify the same keyframe
    //       offset, and since this algorithm iterates over these blocks in
    //       reverse, this implies that if any properties are encountered that
    //       have already added at this same keyframe offset, they should be
    //       skipped.
    //     * All property values are replaced with their computed values.
    // 6.6 Add each property name that was added to keyframe
    //     to animated properties.
    StringKeyframe* keyframe = keyframes[target_index];
    for (const auto& property : rule_keyframe->Properties()) {
      CSSPropertyName property_name = property.GetCSSPropertyName();

      // Since processing keyframes in reverse order, skipping properties that
      // have already been inserted prevents overwriting a later merged
      // keyframe.
      if (current_offset_properties->Contains(property_name)) {
        continue;
      }

      if (source_index != target_index) {
        keyframe->SetCSSPropertyValue(
            property.GetCSSPropertyName(),
            rule_keyframe->CssPropertyValue(property));
      }

      current_offset_properties->insert(property_name);
      animated_properties.insert(property_name);
      if (keyframe_offset == 0)
        start_properties.insert(property_name);
      else if (keyframe_offset == 1)
        end_properties.insert(property_name);
    }
  }

  // Compact the vector of keyframes if any keyframes have been merged.
  keyframes.EraseAt(0, merged_frame_count);

  // Steps 7 and 8 are for adding boundary (neutral) keyframes if needed.
  // These steps are deferred and handled in
  // KeyframeEffectModelBase::PropertySpecificKeyframeGroup::
  // AddSyntheticKeyframeIfRequired
  // The rationale for not adding here is as follows:
  //   1. Neutral keyframes are also needed for CSS transitions and
  //      programmatic animations. Avoid duplicating work.
  //   2. Keyframe ordering can change due to timeline offsets within keyframes.
  //      This reordering makes it cumbersome to have to remove and re-inject
  //      neutral keyframes if explicitly added.
  // NOTE: By not adding here, we need to explicitly inject into the set
  // generated in effect.getKeyframes().

  auto* model = MakeGarbageCollected<CssKeyframeEffectModel>(
      keyframes, composite, default_timing_function, has_named_range_keyframes);
  if (animation_index > 0 && model->HasSyntheticKeyframes()) {
    UseCounter::Count(element.GetDocument(),
                      WebFeature::kCSSAnimationsStackedNeutralKeyframe);
  }

  return model;
}

// Returns the start time of an animation given the start delay. A negative
// start delay results in the animation starting with non-zero progress.
AnimationTimeDelta StartTimeFromDelay(AnimationTimeDelta start_delay) {
  return start_delay < AnimationTimeDelta() ? -start_delay
                                            : AnimationTimeDelta();
}

// Timing functions for computing elapsed time of an event.

AnimationTimeDelta IntervalStart(const AnimationEffect& effect) {
  AnimationTimeDelta start_delay = effect.NormalizedTiming().start_delay;
  const AnimationTimeDelta active_duration =
      effect.NormalizedTiming().active_duration;
  // This fixes a problem where start_delay could be -0
  if (!start_delay.is_zero()) {
    start_delay = -start_delay;
  }
  return std::max(std::min(start_delay, active_duration), AnimationTimeDelta());
}

AnimationTimeDelta IntervalEnd(const AnimationEffect& effect) {
  const AnimationTimeDelta start_delay = effect.NormalizedTiming().start_delay;
  const AnimationTimeDelta end_delay = effect.NormalizedTiming().end_delay;
  const AnimationTimeDelta active_duration =
      effect.NormalizedTiming().active_duration;
  const AnimationTimeDelta target_effect_end =
      std::max(start_delay + active_duration + end_delay, AnimationTimeDelta());
  return std::max(std::min(target_effect_end - start_delay, active_duration),
                  AnimationTimeDelta());
}

AnimationTimeDelta IterationElapsedTime(const AnimationEffect& effect,
                                        double previous_iteration) {
  const double current_iteration = effect.CurrentIteration().value();
  const double iteration_boundary = (previous_iteration > current_iteration)
                                        ? current_iteration + 1
                                        : current_iteration;
  const double iteration_start = effect.SpecifiedTiming().iteration_start;
  const AnimationTimeDelta iteration_duration =
      effect.NormalizedTiming().iteration_duration;
  return iteration_duration * (iteration_boundary - iteration_start);
}

const CSSAnimationUpdate* GetPendingAnimationUpdate(Node& node) {
  Element* element = DynamicTo<Element>(node);
  if (!element)
    return nullptr;
  ElementAnimations* element_animations = element->GetElementAnimations();
  if (!element_animations)
    return nullptr;
  return &element_animations->CssAnimations().PendingUpdate();
}

// SpecifiedTimelines "zips" together name/axis/inset vectors such that
// individual name/axis/inset values can be accessed as a tuple.
//
// SpecifiedTimelines skips over entries with nullptr-names (which
// represents "none"), because such entries should not yield timelines.
class SpecifiedTimelines {
  STACK_ALLOCATED();

 public:
  explicit SpecifiedTimelines(const ScopedCSSNameList* names,
                              const Vector<TimelineAxis>& axes,
                              const Vector<TimelineInset>* insets)
      : names_(names ? &names->GetNames() : nullptr),
        axes_(axes),
        insets_(insets) {}

  class Iterator {
    STACK_ALLOCATED();

   public:
    Iterator(wtf_size_t index, const SpecifiedTimelines& timelines)
        : index_(index), timelines_(timelines) {}

    std::tuple<Member<const ScopedCSSName>, TimelineAxis, TimelineInset>
    operator*() const {
      const HeapVector<Member<const ScopedCSSName>>& names = *timelines_.names_;
      const Vector<TimelineAxis>& axes = timelines_.axes_;
      const Vector<TimelineInset>* insets = timelines_.insets_;

      Member<const ScopedCSSName> name = names[index_];
      TimelineAxis axis = axes.empty()
                              ? TimelineAxis::kBlock
                              : axes[std::min(index_, axes.size() - 1)];
      const TimelineInset& inset =
          (!insets || insets->empty())
              ? TimelineInset()
```