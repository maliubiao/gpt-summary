Response:
The user wants a summary of the functionality of the `animation.cc` file in the Chromium Blink engine. They are also interested in:

1. **Relationship to web technologies:**  How does this code interact with JavaScript, HTML, and CSS?
2. **Logical reasoning:** Examples of how the code might work with specific inputs and outputs.
3. **Common usage errors:**  Mistakes developers might make when working with animations.

Since this is part 1 of 5, the request focuses on summarizing the functionality covered in this initial code snippet.

**Plan:**

1. **Identify Core Functionality:** Analyze the included headers and the defined `Animation` class to understand the main purpose of the file. It appears to be the core implementation of the Web Animations API within Blink.
2. **Relate to Web Technologies:** Connect the identified functionality to how JavaScript, HTML, and CSS are used to create and control animations on web pages.
3. **Logical Reasoning (Hypothetical):**  Consider a simple animation scenario and how the code might handle it. Focus on the initialization and state management.
4. **Common Usage Errors (Hypothetical):** Think about typical mistakes developers make with animations, particularly those related to timing and timelines.
5. **Summarize:**  Condense the findings into a concise summary of the file's purpose based on the provided code.
这是 `blink/renderer/core/animation/animation.cc` 文件的第一部分，其主要功能是**实现 Web Animations API 的核心逻辑，负责管理和控制动画对象 (Animation)**。

**功能归纳：**

1. **动画对象的创建和初始化:**  定义了 `Animation` 类的创建方法 (`Create`)，负责根据提供的 `AnimationEffect` 和 `AnimationTimeline` 创建动画实例。它会进行一些参数校验，例如时间线类型和 effect 的持续时间等。
2. **管理动画的时间状态:**  维护动画的 `currentTime`（当前时间）、`startTime`（开始时间）、`holdTime`（保持时间）和 `playbackRate`（播放速率）。提供了设置和获取这些属性的方法，并处理了不同时间线类型（例如 `DocumentTimeline` 和 `ScrollTimeline`）下的时间转换。
3. **动画的播放控制:**  实现了动画的播放、暂停和结束等状态管理，并通过 `pending_pause_` 和 `pending_play_` 等标志位来处理异步操作。
4. **与时间线的关联:**  `Animation` 对象需要关联一个 `AnimationTimeline`，用于驱动动画的进行。代码中处理了 `DocumentTimeline` 和 `ScrollTimeline` 两种类型的时间线。
5. **与 AnimationEffect 的关联:**  `Animation` 对象关联一个 `AnimationEffect`，定义了动画的目标属性和关键帧。
6. **与 Compositor 的交互:**  涉及到将动画信息传递给 Compositor 线程进行硬件加速渲染的部分，包括 `PreCommit` 和 `PostCommit` 方法，以及对 Compositor 动画状态的管理（`compositor_state_`）。
7. **优先级管理:**  定义了动画的优先级 (`AnimationClassPriority`)，用于在多个动画同时作用于同一元素时确定其合成顺序。

**与 JavaScript, HTML, CSS 的关系举例说明：**

*   **JavaScript:**  JavaScript 通过 Web Animations API 来创建和控制动画。例如，可以使用 `document.createElement('div').animate(...)` 创建一个动画，这个操作在 Blink 内部就会调用到 `Animation::Create` 方法。
    *   **假设输入:** JavaScript 代码 `element.animate([{opacity: 0}, {opacity: 1}], {duration: 1000})` 创建了一个动画。
    *   **可能涉及的 `animation.cc` 逻辑:**  `Animation::Create` 会被调用，根据传入的关键帧和持续时间创建一个 `KeyframeEffect` 对象，并将其关联到新的 `Animation` 对象上。
*   **HTML:** HTML 元素是动画的目标。动画会修改 HTML 元素的样式。
    *   **例子:**  上述 JavaScript 动画作用于一个 `<div>` 元素。`animation.cc` 中的逻辑会处理如何将这个动画应用到该 `<div>` 元素上，并在合适的时机更新其样式。
*   **CSS:** CSS 可以通过 CSS 动画和 CSS 过渡来定义动画。Blink 会解析 CSS 并创建相应的动画对象。
    *   **例子:**  CSS 代码 `div { animation: fade-in 1s; } @keyframes fade-in { from { opacity: 0; } to { opacity: 1; } }` 定义了一个 CSS 动画。Blink 会解析这段 CSS，创建一个 `CSSAnimation` 对象，并将其关联到对应的 `<div>` 元素。`animation.cc` 中会处理 `CSSAnimation` 相关的逻辑，例如优先级排序。

**逻辑推理举例：**

假设用户使用 JavaScript 设置了动画的 `currentTime`：

*   **假设输入:** JavaScript 代码 `animation.currentTime = 500;` (假设动画时间单位是毫秒)。
*   **`animation.cc` 的处理逻辑:**  `Animation::setCurrentTime` 方法会被调用。
    *   它会调用 `ConvertCSSNumberishToTime` 将 JavaScript 传入的数值转换为 `AnimationTimeDelta`。
    *   然后调用 `SetCurrentTimeInternal` 更新动画的内部时间状态。
    *   如果动画正在播放，可能会更新 `startTime_` 以保持动画的连续性。如果动画已暂停，则会更新 `hold_time_`。
    *   会设置 `outdated_` 标志，表明动画状态已改变，需要重新计算和渲染。
    *   可能会触发 Compositor 的更新 (`SetCompositorPending`)。
*   **假设输出:** 动画的当前时间被设置为 500 毫秒，如果动画正在播放，视觉效果会立即跳转到 500 毫秒对应的状态。

**用户或编程常见的使用错误举例：**

*   **错误地在 ScrollTimeline 上使用无限循环的动画:**  代码中 `Animation::Create` 方法会检查当时间线是 `ScrollTimeline` 时，`AnimationEffect` 的迭代次数是否为无限 (`std::numeric_limits<double>::infinity()`)。如果用户尝试创建一个在滚动时间线上无限循环的动画，将会抛出一个 `TypeError`。
    *   **错误示例 (JavaScript):**  `element.animate([{transform: 'translateX(0)'}, {transform: 'translateX(100px)'}], {timeline: scrollTimeline, iterations: Infinity});`
    *   **`animation.cc` 的错误处理:**  `Animation::Create` 方法中的 `if (effect->timing_.iteration_count == std::numeric_limits<double>::infinity())` 条件会捕获这个错误并抛出异常。
*   **在 ScrollTimeline 上使用 "auto" 持续时间并设置了非零的 time-based 延迟:**  代码中 `Animation::Create` 方法也对 `ScrollTimeline` 和 `AnimationEffect` 的 `iteration_duration` 为 "auto" 的情况进行了限制，如果同时设置了非零的时间延迟，也会抛出异常。这是因为这种组合目前的实现还存在一些复杂性。
    *   **错误示例 (JavaScript):** `element.animate([{opacity: 0}, {opacity: 1}], {timeline: scrollTimeline, duration: 'auto', delay: 100});`
    *   **`animation.cc` 的错误处理:** `Animation::Create` 方法中的相关 `if` 语句会检测到这种情况并抛出 `DOMExceptionCode::kNotSupportedError` 异常。

总结来说，`blink/renderer/core/animation/animation.cc` 的第一部分主要负责 `Animation` 对象的生命周期管理、时间状态控制以及与底层 Compositor 的初步交互。它是实现 Web Animations API 的核心组件。

Prompt: 
```
这是目录为blink/renderer/core/animation/animation.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能

"""
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

#include "third_party/blink/renderer/core/animation/animation.h"

#include <limits>
#include <memory>

#include "base/debug/stack_trace.h"
#include "base/metrics/histogram_macros.h"
#include "cc/animation/animation_timeline.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_timeline_range_offset.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_cssnumericvalue_double.h"
#include "third_party/blink/renderer/core/animation/animation_timeline.h"
#include "third_party/blink/renderer/core/animation/animation_utils.h"
#include "third_party/blink/renderer/core/animation/compositor_animations.h"
#include "third_party/blink/renderer/core/animation/css/css_animation.h"
#include "third_party/blink/renderer/core/animation/css/css_animations.h"
#include "third_party/blink/renderer/core/animation/css/css_transition.h"
#include "third_party/blink/renderer/core/animation/document_timeline.h"
#include "third_party/blink/renderer/core/animation/element_animations.h"
#include "third_party/blink/renderer/core/animation/keyframe_effect.h"
#include "third_party/blink/renderer/core/animation/pending_animations.h"
#include "third_party/blink/renderer/core/animation/scroll_timeline.h"
#include "third_party/blink/renderer/core/animation/scroll_timeline_util.h"
#include "third_party/blink/renderer/core/animation/timeline_range.h"
#include "third_party/blink/renderer/core/animation/timing_calculations.h"
#include "third_party/blink/renderer/core/css/cssom/css_unit_values.h"
#include "third_party/blink/renderer/core/css/native_paint_image_generator.h"
#include "third_party/blink/renderer/core/css/properties/css_property_ref.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/style_attribute_mutation_scope.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_document_state.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/event_target_names.h"
#include "third_party/blink/renderer/core/events/animation_playback_event.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/platform/animation/compositor_animation.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/scheduler/public/event_loop.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"

namespace blink {

namespace {

// Accessing the compositor animation state should not be done during style,
// layout or paint to avoid blocking on a previous pending commit.
#if DCHECK_IS_ON()
#define VERIFY_PAINT_CLEAN_LOG_ONCE()                                         \
  if (VLOG_IS_ON(1)) {                                                        \
    if (document_->Lifecycle().GetState() < DocumentLifecycle::kPaintClean) { \
      static bool first_call = true;                                          \
      bool was_first_call = first_call;                                       \
      first_call = false;                                                     \
      if (was_first_call) {                                                   \
        VLOG(1) << __PRETTY_FUNCTION__                                        \
                << " called during style, layout or paint";                   \
        if (VLOG_IS_ON(2)) {                                                  \
          base::debug::StackTrace().Print();                                  \
        }                                                                     \
      }                                                                       \
    }                                                                         \
  }
#else
#define VERIFY_PAINT_CLEAN_LOG_ONCE()
#endif

// Ensure the time is bounded such that it can be resolved to microsecond
// accuracy. Beyond this limit, we can effectively stall an animation when
// ticking (i.e. b + delta == b for high enough floating point value of b).
// Furthermore, we can encounter numeric overflows when converting to a
// time format that is backed by a 64-bit integer.
bool SupportedTimeValue(double time_in_ms) {
  return std::abs(time_in_ms) < std::pow(std::numeric_limits<double>::radix,
                                         std::numeric_limits<double>::digits) /
                                    1000;
}

enum class PseudoPriority {
  kNone,
  kScrollPrevButton,
  kScrollMarkerGroupBefore,
  kMarker,
  kScrollMarker,
  kBefore,
  kOther,
  kAfter,
  kScrollMarkerGroupAfter,
  kScrollNextButton,
};

unsigned NextSequenceNumber() {
  static unsigned next = 0;
  return ++next;
}

PseudoPriority ConvertPseudoIdtoPriority(const PseudoId& pseudo) {
  if (pseudo == kPseudoIdNone)
    return PseudoPriority::kNone;
  if (pseudo == kPseudoIdScrollPrevButton) {
    return PseudoPriority::kScrollPrevButton;
  }
  if (pseudo == kPseudoIdScrollMarkerGroupBefore) {
    return PseudoPriority::kScrollMarkerGroupBefore;
  }
  if (pseudo == kPseudoIdMarker)
    return PseudoPriority::kMarker;
  if (pseudo == kPseudoIdScrollMarker) {
    return PseudoPriority::kScrollMarker;
  }
  if (pseudo == kPseudoIdBefore)
    return PseudoPriority::kBefore;
  if (pseudo == kPseudoIdAfter)
    return PseudoPriority::kAfter;
  if (pseudo == kPseudoIdScrollMarkerGroupAfter) {
    return PseudoPriority::kScrollMarkerGroupAfter;
  }
  if (pseudo == kPseudoIdScrollNextButton) {
    return PseudoPriority::kScrollNextButton;
  }
  return PseudoPriority::kOther;
}

Animation::AnimationClassPriority AnimationPriority(
    const Animation& animation) {
  // https://www.w3.org/TR/web-animations-1/#animation-class

  // CSS transitions have a lower composite order than CSS animations, and CSS
  // animations have a lower composite order than other animations. Thus,CSS
  // transitions are to appear before CSS animations and CSS animations are to
  // appear before other animations.
  // When animations are disassociated from their element they are sorted
  // by their sequence number, i.e. kDefaultPriority. See
  // https://drafts.csswg.org/css-animations-2/#animation-composite-order and
  // https://drafts.csswg.org/css-transitions-2/#animation-composite-order
  Animation::AnimationClassPriority priority;
  if (animation.IsCSSTransition() && animation.IsOwned())
    priority = Animation::AnimationClassPriority::kCssTransitionPriority;
  else if (animation.IsCSSAnimation() && animation.IsOwned())
    priority = Animation::AnimationClassPriority::kCssAnimationPriority;
  else
    priority = Animation::AnimationClassPriority::kDefaultPriority;
  return priority;
}

void RecordCompositorAnimationFailureReasons(
    CompositorAnimations::FailureReasons failure_reasons) {
  // UMA_HISTOGRAM_ENUMERATION requires that the enum_max must be strictly
  // greater than the sample value. kFailureReasonCount doesn't include the
  // kNoFailure value but the histograms do so adding the +1 is necessary.
  // TODO(dcheng): Fix https://crbug.com/705169 so this isn't needed.
  constexpr uint32_t kFailureReasonEnumMax =
      CompositorAnimations::kFailureReasonCount + 1;

  if (failure_reasons == CompositorAnimations::kNoFailure) {
    UMA_HISTOGRAM_ENUMERATION(
        "Blink.Animation.CompositedAnimationFailureReason",
        CompositorAnimations::kNoFailure, kFailureReasonEnumMax);
    return;
  }

  for (uint32_t i = 0; i < CompositorAnimations::kFailureReasonCount; i++) {
    unsigned val = 1 << i;
    if (failure_reasons & val) {
      UMA_HISTOGRAM_ENUMERATION(
          "Blink.Animation.CompositedAnimationFailureReason", i + 1,
          kFailureReasonEnumMax);
    }
  }
}

Element* OriginatingElement(Element* owning_element) {
  if (owning_element->IsPseudoElement()) {
    return owning_element->parentElement();
  }
  return owning_element;
}

AtomicString GetCSSTransitionCSSPropertyName(const Animation* animation) {
  CSSPropertyID property_id =
      To<CSSTransition>(animation)->TransitionCSSPropertyName().Id();
  if (property_id == CSSPropertyID::kVariable ||
      property_id == CSSPropertyID::kInvalid)
    return AtomicString();
  return To<CSSTransition>(animation)
      ->TransitionCSSPropertyName()
      .ToAtomicString();
}

bool GreaterThanOrEqualWithinTimeTolerance(const AnimationTimeDelta& a,
                                           const AnimationTimeDelta& b) {
  double a_ms = a.InMillisecondsF();
  double b_ms = b.InMillisecondsF();
  if (std::abs(a_ms - b_ms) < Animation::kTimeToleranceMs)
    return true;

  return a_ms > b_ms;
}

// Consider boundaries aligned if they round to the same integer pixel value.
const double kScrollBoundaryTolerance = 0.5;

}  // namespace

Animation* Animation::Create(AnimationEffect* effect,
                             AnimationTimeline* timeline,
                             ExceptionState& exception_state) {
  DCHECK(timeline);
  if (!IsA<DocumentTimeline>(timeline) && !timeline->IsScrollTimeline()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "Invalid timeline. Animation requires a "
                                      "DocumentTimeline or ScrollTimeline");
    return nullptr;
  }
  DCHECK(IsA<DocumentTimeline>(timeline) || timeline->IsScrollTimeline());

  if (effect && timeline->IsScrollTimeline()) {
    if (effect->timing_.iteration_duration) {
      if (effect->timing_.iteration_duration->is_inf()) {
        exception_state.ThrowTypeError(
            "Effect duration cannot be Infinity when used with Scroll "
            "Timelines");
        return nullptr;
      }
    } else {
      // TODO(crbug.com/1216527)
      // Eventually we hope to be able to be more flexible with
      // iteration_duration "auto" and its interaction with start_delay and
      // end_delay. For now we will throw an exception if either delay is set
      // to a non-zero time-based value.
      // Once the spec (https://github.com/w3c/csswg-drafts/pull/6337) has been
      // ratified, we will be able to better handle mixed scenarios like "auto"
      // and time based delays.

      // If either delay or end_delay are non-zero, we can't yet handle "auto"
      if (effect->timing_.start_delay.IsNonzeroTimeBasedDelay() ||
          effect->timing_.end_delay.IsNonzeroTimeBasedDelay()) {
        exception_state.ThrowDOMException(
            DOMExceptionCode::kNotSupportedError,
            "Effect duration \"auto\" with time-based delays is not yet "
            "implemented when used with Scroll Timelines");
        return nullptr;
      }
    }

    if (effect->timing_.iteration_count ==
        std::numeric_limits<double>::infinity()) {
      // iteration count of infinity makes no sense for scroll timelines
      exception_state.ThrowTypeError(
          "Effect iterations cannot be Infinity when used with Scroll "
          "Timelines");
      return nullptr;
    }
  }

  auto* context = timeline->GetDocument()->GetExecutionContext();
  return MakeGarbageCollected<Animation>(context, timeline, effect);
}

Animation* Animation::Create(ExecutionContext* execution_context,
                             AnimationEffect* effect,
                             ExceptionState& exception_state) {
  Document* document = To<LocalDOMWindow>(execution_context)->document();
  return Create(effect, &document->Timeline(), exception_state);
}

Animation* Animation::Create(ExecutionContext* execution_context,
                             AnimationEffect* effect,
                             AnimationTimeline* timeline,
                             ExceptionState& exception_state) {
  if (!timeline) {
    Animation* animation =
        MakeGarbageCollected<Animation>(execution_context, nullptr, effect);
    return animation;
  }

  return Create(effect, timeline, exception_state);
}

Animation::Animation(ExecutionContext* execution_context,
                     AnimationTimeline* timeline,
                     AnimationEffect* content)
    : ActiveScriptWrappable<Animation>({}),
      ExecutionContextLifecycleObserver(nullptr),
      playback_rate_(1),
      start_time_(),
      hold_time_(),
      sequence_number_(NextSequenceNumber()),
      content_(content),
      timeline_(timeline),
      is_paused_for_testing_(false),
      is_composited_animation_disabled_for_testing_(false),
      pending_pause_(false),
      pending_play_(false),
      pending_finish_notification_(false),
      has_queued_microtask_(false),
      outdated_(false),
      finished_(true),
      committed_finish_notification_(false),
      compositor_state_(nullptr),
      compositor_pending_(false),
      compositor_group_(0),
      effect_suppressed_(false),
      compositor_property_animations_have_no_effect_(false),
      animation_has_no_effect_(false) {
  if (execution_context && !execution_context->IsContextDestroyed())
    SetExecutionContext(execution_context);

  if (content_) {
    if (content_->GetAnimation()) {
      content_->GetAnimation()->setEffect(nullptr);
    }
    content_->Attach(this);
  }

  AnimationTimeline* attached_timeline = timeline_;
  if (!attached_timeline) {
    attached_timeline =
        &To<LocalDOMWindow>(execution_context)->document()->Timeline();
  }
  document_ = attached_timeline->GetDocument();
  DCHECK(document_);
  attached_timeline->AnimationAttached(this);
  timeline_duration_ = attached_timeline->GetDuration();
  probe::DidCreateAnimation(document_, sequence_number_);
}

Animation::~Animation() {
  // Verify that compositor_animation_ has been disposed of.
  DCHECK(!compositor_animation_);
}

void Animation::Dispose() {
  if (timeline_)
    timeline_->AnimationDetached(this);
  DestroyCompositorAnimation();
  // If the DocumentTimeline and its Animation objects are
  // finalized by the same GC, we have to eagerly clear out
  // this Animation object's compositor animation registration.
  DCHECK(!compositor_animation_);
}

AnimationTimeDelta Animation::EffectEnd() const {
  return content_ ? content_->NormalizedTiming().end_time
                  : AnimationTimeDelta();
}

bool Animation::Limited(std::optional<AnimationTimeDelta> current_time) const {
  if (!current_time)
    return false;

  return (EffectivePlaybackRate() < 0 &&
          current_time <= AnimationTimeDelta()) ||
         (EffectivePlaybackRate() > 0 &&
          GreaterThanOrEqualWithinTimeTolerance(current_time.value(),
                                                EffectEnd()));
}

Document* Animation::GetDocument() const {
  return document_.Get();
}

std::optional<AnimationTimeDelta> Animation::TimelineTime() const {
  return timeline_ ? timeline_->CurrentTime() : std::nullopt;
}

bool Animation::ConvertCSSNumberishToTime(
    const V8CSSNumberish* numberish,
    std::optional<AnimationTimeDelta>& time,
    String variable_name,
    ExceptionState& exception_state) {
  // This function is used to handle the CSSNumberish input for setting
  // currentTime and startTime. Spec issue can be found here for this process:
  // https://github.com/w3c/csswg-drafts/issues/6458

  // Handle converting null
  if (!numberish) {
    time = std::nullopt;
    return true;
  }

  if (timeline_ && timeline_->IsProgressBased()) {
    // Progress based timeline
    if (numberish->IsCSSNumericValue()) {
      CSSUnitValue* numberish_as_percentage =
          numberish->GetAsCSSNumericValue()->to(
              CSSPrimitiveValue::UnitType::kPercentage);
      if (!numberish_as_percentage) {
        exception_state.ThrowDOMException(
            DOMExceptionCode::kNotSupportedError,
            "Invalid " + variable_name +
                ". CSSNumericValue must be a percentage for "
                "progress based animations.");
        return false;
      }
      timeline_duration_ = timeline_->GetDuration();
      time =
          (numberish_as_percentage->value() / 100) * timeline_duration_.value();
      return true;
    } else {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kNotSupportedError,
          "Invalid " + variable_name + ". Setting " + variable_name +
              " using absolute time "
              "values is not supported for progress based animations.");
      return false;
    }
  }

  // Document timeline
  if (numberish->IsCSSNumericValue()) {
    CSSUnitValue* numberish_as_number = numberish->GetAsCSSNumericValue()->to(
        CSSPrimitiveValue::UnitType::kNumber);
    if (numberish_as_number) {
      time =
          ANIMATION_TIME_DELTA_FROM_MILLISECONDS(numberish_as_number->value());
      return true;
    }

    CSSUnitValue* numberish_as_milliseconds =
        numberish->GetAsCSSNumericValue()->to(
            CSSPrimitiveValue::UnitType::kMilliseconds);
    if (numberish_as_milliseconds) {
      time = ANIMATION_TIME_DELTA_FROM_MILLISECONDS(
          numberish_as_milliseconds->value());
      return true;
    }

    CSSUnitValue* numberish_as_seconds = numberish->GetAsCSSNumericValue()->to(
        CSSPrimitiveValue::UnitType::kSeconds);
    if (numberish_as_seconds) {
      time = ANIMATION_TIME_DELTA_FROM_SECONDS(numberish_as_seconds->value());
      return true;
    }

    // TODO (crbug.com/1232181): Look into allowing document timelines to set
    // currentTime and startTime using CSSNumericValues that are percentages.
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "Invalid " + variable_name +
            ". CSSNumericValue must be either a number or a time value for "
            "time based animations.");
    return false;
  }

  time = ANIMATION_TIME_DELTA_FROM_MILLISECONDS(numberish->GetAsDouble());
  return true;
}

// https://www.w3.org/TR/web-animations-1/#setting-the-current-time-of-an-animation
void Animation::setCurrentTime(const V8CSSNumberish* current_time,
                               ExceptionState& exception_state) {
  if (!current_time) {
    // If the current time is resolved, then throw a TypeError.
    if (CurrentTimeInternal()) {
      exception_state.ThrowTypeError(
          "currentTime may not be changed from resolved to unresolved");
    }
    return;
  }

  auto_align_start_time_ = false;

  std::optional<AnimationTimeDelta> new_current_time;
  // Failure to convert results in a thrown exception and returning false.
  if (!ConvertCSSNumberishToTime(current_time, new_current_time, "currentTime",
                                 exception_state))
    return;

  DCHECK(new_current_time);
  SetCurrentTimeInternal(new_current_time.value());

  // Synchronously resolve pending pause task.
  if (pending_pause_) {
    hold_time_ = new_current_time;
    ApplyPendingPlaybackRate();
    start_time_ = std::nullopt;
    pending_pause_ = false;
    if (ready_promise_)
      ResolvePromiseMaybeAsync(ready_promise_.Get());
  }

  // Update the finished state.
  UpdateFinishedState(UpdateType::kDiscontinuous, NotificationType::kAsync);

  SetCompositorPending(CompositorPendingReason::kPendingUpdate);

  // Notify of potential state change.
  NotifyProbe();
}

// https://www.w3.org/TR/web-animations-1/#setting-the-current-time-of-an-animation
// See steps for silently setting the current time. The preliminary step of
// handling an unresolved time are to be handled by the caller.
void Animation::SetCurrentTimeInternal(AnimationTimeDelta new_current_time) {
  std::optional<AnimationTimeDelta> previous_start_time = start_time_;
  std::optional<AnimationTimeDelta> previous_hold_time = hold_time_;

  // Update either the hold time or the start time.
  if (hold_time_ || !start_time_ || !timeline_ || !timeline_->IsActive() ||
      playback_rate_ == 0) {
    hold_time_ = new_current_time;
  } else {
    start_time_ = CalculateStartTime(new_current_time);
  }

  // Preserve invariant that we can only set a start time or a hold time in the
  // absence of an active timeline.
  if (!timeline_ || !timeline_->IsActive())
    start_time_ = std::nullopt;

  // Reset the previous current time.
  previous_current_time_ = std::nullopt;

  if (previous_start_time != start_time_ || previous_hold_time != hold_time_)
    SetOutdated();
}

V8CSSNumberish* Animation::startTime() const {
  if (start_time_) {
    return ConvertTimeToCSSNumberish(start_time_.value());
  }
  return nullptr;
}

V8CSSNumberish* Animation::ConvertTimeToCSSNumberish(
    std::optional<AnimationTimeDelta> time) const {
  if (time) {
    if (timeline_ && timeline_->IsScrollSnapshotTimeline()) {
      return To<ScrollSnapshotTimeline>(*timeline_)
          .ConvertTimeToProgress(time.value());
    }
    return MakeGarbageCollected<V8CSSNumberish>(time.value().InMillisecondsF());
  }
  return nullptr;
}

std::optional<double> Animation::TimeAsAnimationProgress(
    AnimationTimeDelta time) const {
  return !EffectEnd().is_zero() ? std::make_optional(time / EffectEnd())
                                : std::nullopt;
}

// https://www.w3.org/TR/web-animations-1/#the-current-time-of-an-animation
V8CSSNumberish* Animation::currentTime() const {
  // 1. If the animation’s hold time is resolved,
  //    The current time is the animation’s hold time.
  if (hold_time_.has_value()) {
    return ConvertTimeToCSSNumberish(hold_time_.value());
  }

  // 2.  If any of the following are true:
  //    * the animation has no associated timeline, or
  //    * the associated timeline is inactive, or
  //    * the animation’s start time is unresolved.
  // The current time is an unresolved time value.
  if (!timeline_ || !timeline_->IsActive() || !start_time_)
    return nullptr;

  // 3. Otherwise,
  // current time = (timeline time - start time) × playback rate
  std::optional<AnimationTimeDelta> timeline_time = timeline_->CurrentTime();

  // An active timeline should always have a value, and since inactive timeline
  // is handled in step 2 above, make sure that timeline_time has a value.
  DCHECK(timeline_time.has_value());

  AnimationTimeDelta calculated_current_time =
      (timeline_time.value() - start_time_.value()) * playback_rate_;

  return ConvertTimeToCSSNumberish(calculated_current_time);
}

std::optional<AnimationTimeDelta> Animation::CurrentTimeInternal() const {
  return hold_time_ ? hold_time_ : CalculateCurrentTime();
}

std::optional<AnimationTimeDelta> Animation::UnlimitedCurrentTime() const {
  return CalculateAnimationPlayState() == V8AnimationPlayState::Enum::kPaused ||
                 !start_time_
             ? CurrentTimeInternal()
             : CalculateCurrentTime();
}

std::optional<double> Animation::progress() const {
  std::optional<AnimationTimeDelta> current_time = CurrentTimeInternal();
  if (!effect() || !current_time) {
    return std::nullopt;
  }

  const AnimationTimeDelta effect_end = EffectEnd();
  if (effect_end.is_zero()) {
    if (current_time < AnimationTimeDelta()) {
      return 0;
    }
    return 1;
  }

  if (effect_end.is_inf()) {
    return 0;
  }

  return std::clamp<double>(*current_time / effect_end, 0, 1);
}

V8AnimationPlayState Animation::playState() const {
  return V8AnimationPlayState(CalculateAnimationPlayState());
}

bool Animation::PreCommit(
    int compositor_group,
    const PaintArtifactCompositor* paint_artifact_compositor,
    bool start_on_compositor) {
  if (CompositorPendingCancel()) {
    CancelAnimationOnCompositor();
  }

  if (!start_time_ && !hold_time_) {
    // Waiting on a deferred start time.
    return false;
  }

  bool soft_change =
      compositor_state_ &&
      (Paused() || compositor_state_->playback_rate != EffectivePlaybackRate());
  bool hard_change =
      compositor_state_ && (compositor_state_->effect_changed ||
                            !compositor_state_->start_time || !start_time_ ||
                            !TimingCalculations::IsWithinAnimationTimeEpsilon(
                                compositor_state_->start_time.value(),
                                start_time_.value().InSecondsF()));

  bool compositor_property_animations_had_no_effect =
      compositor_property_animations_have_no_effect_;
  compositor_property_animations_have_no_effect_ = false;
  animation_has_no_effect_ = false;

  // FIXME: softChange && !hardChange should generate a Pause/ThenStart,
  // not a Cancel, but we can't communicate these to the compositor yet.

  bool changed = soft_change || hard_change;
  bool should_cancel = (!Playing() && compositor_state_) || changed;
  bool should_start = Playing() && (!compositor_state_ || changed);

  // If the property nodes were removed for this animation we must
  // cancel it. It may be running even though blink has not been
  // notified yet.
  if (!compositor_property_animations_had_no_effect && start_on_compositor &&
      should_cancel && should_start && compositor_state_ &&
      compositor_state_->pending_action == CompositorAction::kStart &&
      !compositor_state_->effect_changed) {
    // Restarting but still waiting for a start time.
    return false;
  }

  std::optional<int> replaced_cc_animation_id;
  if (should_cancel) {
    // TODO(https://crbug.com/41496930): This code currently avoids preserving
    // the id and compositor group of the cc animation on playback rate and
    // state changes (i.e. "soft changes") due to the linked bug. That's
    // because these soft changes use a time offset that assumes the start_time
    // is reset. A more complete fix should account for the fact that the start
    // time may be preserved when computing the offset.
    if (should_start && GetCompositorAnimation() && !soft_change) {
      // If the animation is being canceled and restarted, pass the replaced
      // cc::Animation's id along so the compositor can recreate the
      // cc::Animation with the same id, ensuring continuity in the animation.
      replaced_cc_animation_id = GetCompositorAnimation()->CcAnimationId();
      // Preserve the compositor group for a restarted Animation so that
      // animation events are routed correctly.
      compositor_group = compositor_group_;
    }
    CancelAnimationOnCompositor();
  }

  DCHECK(!compositor_state_ || compositor_state_->start_time);

  if (should_start) {
    compositor_group_ = compositor_group;
    if (start_on_compositor) {
      PropertyHandleSet unsupported_properties;
      CompositorAnimations::FailureReasons failure_reasons =
          CheckCanStartAnimationOnCompositor(paint_artifact_compositor,
                                             &unsupported_properties);
      RecordCompositorAnimationFailureReasons(failure_reasons);

      if (failure_reasons == CompositorAnimations::kNoFailure) {
        // We could still have a stale compositor keyframe model ID if
        // a previous cancel failed due to not having a layout object at the
        // time of the cancel operation. The start and stop of an animation
        // for a marquee element does not depend on having a layout object.
        if (HasActiveAnimationsOnCompositor())
          CancelAnimationOnCompositor();
        CreateCompositorAnimation(replaced_cc_animation_id);
        StartAnimationOnCompositor(paint_artifact_compositor);
        compositor_state_ = std::make_unique<CompositorState>(*this);
      } else {
        CancelIncompatibleAnimationsOnCompositor();
      }

      compositor_property_animations_have_no_effect_ =
          failure_reasons & CompositorAnimations::kAnimationHasNoVisibleChange;
      animation_has_no_effect_ =
          failure_reasons == CompositorAnimations::kAnimationHasNoVisibleChange;

      DCHECK_EQ(V8AnimationPlayState::Enum::kRunning,
                CalculateAnimationPlayState());
      TRACE_EVENT_NESTABLE_ASYNC_INSTANT1(
          "blink.animations,devtools.timeline,benchmark,rail", "Animation",
          this, "data", [&](perfetto::TracedValue context) {
            inspector_animation_compositor_event::Data(
                std::move(context), failure_reasons, unsupported_properties);
          });
    }
  }

  return true;
}

void Animation::PostCommit() {
  compositor_pending_ = false;

  if (!compositor_state_ ||
      compositor_state_->pending_action == CompositorAction::kNone) {
    return;
  }

  DCHECK_EQ(CompositorAction::kStart, compositor_state_->pending_action);
  if (compositor_state_->start_time) {
    DCHECK(TimingCalculations::IsWithinAnimationTimeEpsilon(
        start_time_.value().InSecondsF(),
        compositor_state_->start_time.value()));
    compositor_state_->pending_action = CompositorAction::kNone;
  }
}

bool Animation::HasLowerCompositeOrdering(
    const Animation* animation1,
    const Animation* animation2,
    CompareAnimationsOrdering compare_animation_type) {
  AnimationClassPriority anim_priority1 = AnimationPriority(*animation1);
  AnimationClassPriority anim_priority2 = AnimationPriority(*animation2);
  if (anim_priority1 != anim_priority2)
    return anim_priority1 < anim_priority2;

  // If the the animation class is CssAnimation or CssTransition, then first
  // compare the owning element of animation1 and animation2, sort two of them
  // by tree order of their conrresponding owning element
  // The specs:
  // https://drafts.csswg.org/css-animations-2/#animation-composite-order
  // https://drafts.csswg.org/css-transitions-2/#animation-composite-order
  if (anim_priority1 != kDefaultPriority) {
    Element* owning_element1 = animation1->OwningElement();
    Element* owning_element2 = animation2->OwningElement();

    // Both animations are either CSS transitions or CSS animations with owning
    // elements.
    DCHECK(owning_element1 && owning_element2);
    Element* originating_element1 = OriginatingElement(owning_element1);
    Element* originating_element2 = OriginatingElement(owning_element2);

    // The tree position comparison would take a longer time, thus affect the
    // performance. We only do it when it comes to getAnimation.
    if (originating_element1 != originating_element2) {
      if (compare_animation_type == CompareAnimationsOrdering::kTreeOrder) {
      
"""


```