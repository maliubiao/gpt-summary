Response:
The user is asking for a summary of the functionality of the `animation.cc` file in the Chromium Blink engine. The request specifically asks to:

1. **List the file's functions.**
2. **Explain its relation to Javascript, HTML, and CSS with examples.**
3. **Provide examples of logical reasoning with input and output.**
4. **Give examples of common user/programming errors.**
5. **Summarize the file's overall function.**

Since this is part 4 of a 5-part request, I need to synthesize the information from the provided code snippet and consider what might have been covered in the previous parts. The code heavily revolves around the `Animation` class, its lifecycle, and its interaction with other components like `KeyframeEffect`, `Timeline`, and the compositor.

**Plan:**

1. **Identify Core Functionality:** Focus on the methods within the `Animation` class that manage its state, timing, and interaction with effects and the compositor.
2. **Relate to Web Technologies:** Connect these functionalities to how animations are defined and controlled using Javascript, how they affect elements in the HTML structure, and how their styling is determined by CSS.
3. **Infer Logical Reasoning:** Look for methods that involve conditional logic or calculations based on input, and create hypothetical scenarios to illustrate their behavior.
4. **Consider Error Scenarios:** Think about how developers might misuse the animation API or how the browser might handle invalid animation configurations.
5. **Synthesize a Summary:** Combine all the above points into a concise overview of the `animation.cc` file's purpose within the Blink rendering engine.
```
功能：

这个代码片段是 `blink/renderer/core/animation/animation.cc` 文件的一部分，主要负责实现 Web Animations API 中的 `Animation` 接口。  它定义了动画对象的行为和状态管理。以下是其主要功能归纳：

1. **动画范围控制 (Range Control):**
   - `rangeStart()`, `rangeEnd()`: 获取动画的起始和结束范围边界。
   - `setRangeStart()`, `setRangeEnd()`: 设置动画的起始和结束范围边界，允许基于时间轴的特定范围播放动画。
   - `GetEffectiveTimelineOffset()`:  计算相对于时间轴的有效偏移量，用于定义动画的起始和结束。
   - `ToRangeBoundary()`: 将时间轴偏移量转换为 `RangeBoundary` 对象。
   - `UpdateAutoAlignedStartTime()`:  根据动画范围和播放速率自动调整动画的起始时间。
   - `OnRangeUpdate()`: 当动画范围更新时执行相应的操作，例如重新计算持续时间。
   - `UpdateBoundaryAlignment()`:  根据动画的范围和滚动时间轴的状态，更新边界对齐信息。
   - `ResolveTimelineOffsets()`:  解析时间轴偏移量，用于动画效果模型的计算。

2. **动画状态管理:**
   - `OnValidateSnapshot()`:  验证动画快照，并在必要时更新动画的各种属性，例如持续时间、起始时间、范围偏移等。
   - `SetRangeStartInternal()`, `SetRangeEndInternal()`: 内部方法，用于设置动画的范围边界，并处理样式相关的偏移量。
   - `SetRange()`:  一次性设置动画的起始和结束范围。

3. **与渲染引擎的交互:**
   - `CancelAnimationOnCompositor()`:  取消在合成器线程上的动画。
   - `RestartAnimationOnCompositor()`:  重启在合成器线程上的动画。
   - `CancelIncompatibleAnimationsOnCompositor()`: 取消与当前动画不兼容的合成器动画。
   - `HasActiveAnimationsOnCompositor()`: 检查是否有正在合成器线程上运行的动画。
   - `CreateCompositorAnimation()`:  在合成器线程上创建动画。
   - `DestroyCompositorAnimation()`:  销毁在合成器线程上的动画。
   - `AttachCompositorTimeline()`, `DetachCompositorTimeline()`:  将动画附加/分离到合成器时间轴。
   - `AttachCompositedLayers()`, `DetachCompositedLayers()`: 将动画影响的图层附加/分离到合成器。
   - `NotifyAnimationStarted()`: 通知动画已在合成器线程上启动。

4. **动画更新和事件:**
   - `Update()`: 更新动画的当前时间，并触发相应的事件。
   - `QueueFinishedEvent()`:  将 `finish` 事件添加到事件队列。
   - `UpdateIfNecessary()`:  在必要时更新动画。
   - `EffectInvalidated()`:  当动画效果失效时进行处理。
   - `IsEventDispatchAllowed()`:  检查是否允许派发事件。
   - `TimeToEffectChange()`:  计算动画效果发生改变的时间。
   - `cancel()`:  取消动画，并触发 `cancel` 事件。

5. **测试和调试:**
   - `PauseForTesting()`:  用于测试目的暂停动画。
   - `SetEffectSuppressed()`:  抑制动画效果。
   - `DisableCompositedAnimationForTesting()`:  禁用合成器动画以进行测试。

6. **样式失效:**
   - `InvalidateKeyframeEffect()`:  使关键帧效果失效，触发样式重算。
   - `InvalidateEffectTargetStyle()`:  使动画目标元素的样式失效。
   - `InvalidateNormalizedTiming()`: 使规范化的时间信息失效。

7. **Promise 管理:**
   - `ResolvePromiseMaybeAsync()`, `RejectAndResetPromise()`, `RejectAndResetPromiseMaybeAsync()`:  用于管理与动画相关的 Promise 对象 (例如 `finished` Promise)。

8. **性能监控和调试:**
   - `NotifyProbe()`:  用于发送动画更新的探测信息，用于性能监控和开发者工具。

9. **动画替换 (Animation Replacement):**
   - `IsReplaceable()`:  检查动画是否可以被替换。
   - `RemoveReplacedAnimation()`:  移除可替换的动画，并触发 `remove` 事件。
   - `persist()`:  使动画持久化，防止被替换。
   - `replaceState()`:  获取动画的替换状态。

10. **提交样式 (Commit Styles):**
    - `commitStyles()`: 将动画效果应用的样式直接写入目标元素的 style 属性中。

**与 Javascript, HTML, CSS 的关系：**

* **Javascript:**  `Animation` 对象是 Web Animations API 的核心，Javascript 代码可以通过 `document.getAnimations()` 或元素上的 `getAnimations()` 方法获取动画对象，并调用其方法 (例如 `play()`, `pause()`, `cancel()`, `setRangeStart()`, `setRangeEnd()`) 来控制动画的播放状态和范围。
    * **举例:**  `animation.setRangeStart({ anchor: 'scroll-timeline', offset: '10px' });`  这段 Javascript 代码调用了 `setRangeStart()` 方法来设置动画的起始范围，使其与名为 'scroll-timeline' 的滚动时间轴的偏移量为 10px 的位置对齐。

* **HTML:**  虽然 `animation.cc` 本身不直接解析 HTML，但动画的目标元素通常是 HTML 元素。动画效果会作用于这些 HTML 元素，改变它们的样式。HTML 结构决定了哪些元素可以被动画化。
    * **举例:**  一个 `<div>` 元素可以通过 CSS 或 Javascript 应用动画效果，`animation.cc` 中相关的逻辑会处理如何将动画效果应用到这个 `<div>` 元素上。

* **CSS:**  CSS 可以定义动画的关键帧 (`@keyframes`) 和过渡 (`transition`)，这些定义会被 Blink 引擎解析并最终由 `animation.cc` 中的 `Animation` 对象来管理。CSS 时间轴 (Scroll Timeline, View Timeline) 的概念也与这里的动画范围控制密切相关。
    * **举例:** CSS 中定义的 `@keyframes slidein { from { transform: translateX(-100%); } to { transform: translateX(0%); } }`  与 `animation.cc` 中关键帧效果 (`KeyframeEffect`) 的处理逻辑相关，`animation.cc` 负责驱动这些关键帧之间的过渡。  CSS 的 `animation-range` 属性也会影响 `animation.cc` 中动画范围的设置。

**逻辑推理的假设输入与输出：**

假设输入：

1. **动画当前未播放:** `CalculateAnimationPlayState()` 返回 `V8AnimationPlayState::Enum::kIdle`。
2. **调用 `play()` 方法 (通过 Javascript):** 这将设置 `pending_play_ = true;`。
3. **`OnValidateSnapshot()` 被调用:**

逻辑推理：

* **假设:** `auto_align_start_time_` 为 `true`，且 `start_time_` 为空。
* **输出:**  `OnValidateSnapshot()` 中的相关逻辑会判断动画需要一个新的起始时间 (`needs_new_start_time = true`)。然后，`UpdateAutoAlignedStartTime()` 会被调用，根据动画的范围和时间轴来计算并设置 `start_time_`。动画的状态会变为 `kRunning` (或 `kPending`)，并且可能触发 `SetCompositorPending(CompositorPendingReason::kPendingEffectChange)`。

假设输入：

1. **动画正在播放:** `CalculateAnimationPlayState()` 返回 `V8AnimationPlayState::Enum::kRunning`。
2. **`EffectivePlaybackRate()` 大于 0。**
3. **`GetRangeEndInternal()` 返回一个有效的时间轴偏移量。**

逻辑推理：

* **假设:** `UpdateAutoAlignedStartTime()` 被调用。
* **输出:**  `UpdateAutoAlignedStartTime()` 会进入 `else` 分支（因为 `EffectivePlaybackRate() >= 0` 不成立），获取结束范围的边界。然后，它会计算相对于时间轴的偏移量 (`relative_offset`)，并根据动画的持续时间更新 `start_time_`。

**用户或编程常见的使用错误：**

1. **在动画完成前设置 `rangeStart` 或 `rangeEnd` 导致意外行为:**
   * **错误:** 开发者可能在动画播放过程中动态地改变动画的范围，而没有充分理解这可能如何影响动画的当前时间和播放进度。
   * **举例:**  一个正在播放的动画，如果突然将其 `rangeEnd` 设置到一个比当前时间更早的位置，可能会导致动画立即结束或跳跃到新的结束点。

2. **不理解 `auto_align_start_time` 的影响:**
   * **错误:**  开发者可能期望设置了 `start-time` 后动画就从那个时间开始播放，但如果动画的范围被设置并且 `auto_align_start_time` 为 `true`，那么 `start-time` 可能会被覆盖，导致意想不到的起始时间。
   * **举例:**  开发者设置 `animation.startTime = 5;`，但动画的 `rangeStart` 被设置为时间轴的某个特定位置，并且 `auto_align_start_time` 为真，那么动画的实际起始时间可能不是 5 秒。

3. **在不合适的时机调用 `commitStyles()`:**
   * **错误:**  开发者可能尝试在动画未完成或者目标元素不可渲染时调用 `commitStyles()`。
   * **举例:**  如果动画的目标元素被设置为 `display: none;`，然后调用 `commitStyles()`，将会抛出 `InvalidStateError` 异常。

4. **忘记处理动画的 `finish` 和 `cancel` 事件:**
   * **错误:**  开发者可能没有监听动画的完成或取消事件，导致在动画结束或被取消后，程序的状态没有正确更新。
   * **举例:**  一个动画用于显示一个通知，但开发者没有监听 `finish` 事件来移除这个通知，导致通知一直停留在屏幕上。

**总结 `animation.cc` 的功能 (第 4 部分):**

这个代码片段主要关注 `Animation` 对象在**范围控制、状态管理以及与渲染引擎合成器线程的交互**。它实现了设置和更新动画播放范围的功能，能够根据时间轴的特定区域播放动画。同时，它处理动画状态的验证和更新，并负责将动画同步到合成器线程，以便进行高性能的渲染。此外，还涉及到动画的生命周期管理，包括取消、重启以及与事件派发机制的交互。这部分代码体现了 Blink 引擎如何精细地控制 Web Animations API 中动画的行为，并确保动画能正确高效地在浏览器中呈现。
```
Prompt: 
```
这是目录为blink/renderer/core/animation/animation.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能

"""
his);
  }
}

const Animation::RangeBoundary* Animation::rangeStart() {
  return ToRangeBoundary(range_start_);
}

const Animation::RangeBoundary* Animation::rangeEnd() {
  return ToRangeBoundary(range_end_);
}

void Animation::setRangeStart(const Animation::RangeBoundary* range_start,
                              ExceptionState& exception_state) {
  SetRangeStartInternal(
      GetEffectiveTimelineOffset(range_start, 0, exception_state));
}

void Animation::setRangeEnd(const Animation::RangeBoundary* range_end,
                            ExceptionState& exception_state) {
  SetRangeEndInternal(
      GetEffectiveTimelineOffset(range_end, 1, exception_state));
}

std::optional<TimelineOffset> Animation::GetEffectiveTimelineOffset(
    const Animation::RangeBoundary* boundary,
    double default_percent,
    ExceptionState& exception_state) {
  KeyframeEffect* keyframe_effect = DynamicTo<KeyframeEffect>(effect());
  Element* element = keyframe_effect ? keyframe_effect->target() : nullptr;

  return TimelineOffset::Create(element, boundary, default_percent,
                                exception_state);
}

/* static */
Animation::RangeBoundary* Animation::ToRangeBoundary(
    std::optional<TimelineOffset> timeline_offset) {
  if (!timeline_offset) {
    return MakeGarbageCollected<RangeBoundary>("normal");
  }

  TimelineRangeOffset* timeline_range_offset =
      MakeGarbageCollected<TimelineRangeOffset>();
  timeline_range_offset->setRangeName(timeline_offset->name);
  CSSPrimitiveValue* value =
      CSSPrimitiveValue::CreateFromLength(timeline_offset->offset, 1);
  CSSNumericValue* offset = CSSNumericValue::FromCSSValue(*value);
  timeline_range_offset->setOffset(offset);
  return MakeGarbageCollected<RangeBoundary>(timeline_range_offset);
}

void Animation::UpdateAutoAlignedStartTime() {
  DCHECK(auto_align_start_time_ || !start_time_);

  double relative_offset = 0;
  std::optional<TimelineOffset> boundary;
  if (EffectivePlaybackRate() >= 0) {
    boundary = GetRangeStartInternal();
  } else {
    boundary = GetRangeEndInternal();
    relative_offset = 1;
  }

  if (boundary) {
    relative_offset =
        timeline_->GetTimelineRange().ToFractionalOffset(boundary.value());
  }

  AnimationTimeDelta duration = timeline_->GetDuration().value();
  start_time_ = duration * relative_offset;
  SetCompositorPending(CompositorPendingReason::kPendingEffectChange);
}

bool Animation::OnValidateSnapshot(bool snapshot_changed) {
  bool needs_update = snapshot_changed;

  // Track a change in duration and update hold time if required.
  std::optional<AnimationTimeDelta> duration = timeline_->GetDuration();
  if (duration != timeline_duration_) {
    if (hold_time_) {
      DCHECK(timeline_duration_);
      double progress =
          hold_time_->InMillisecondsF() / timeline_duration_->InMillisecondsF();
      hold_time_ = progress * duration.value();
    }
    if (start_time_ && !auto_align_start_time_) {
      DCHECK(timeline_duration_);
      std::optional<AnimationTimeDelta> current_time = UnlimitedCurrentTime();
      if (current_time) {
        double progress = current_time->InMillisecondsF() /
                          timeline_duration_->InMillisecondsF();
        start_time_ = CalculateStartTime(progress * duration.value());
      }
    }
    timeline_duration_ = duration;
  }

  // Update style-dependent range offsets.
  bool range_changed = false;
  if (auto* keyframe_effect = DynamicTo<KeyframeEffect>(effect())) {
    if (keyframe_effect->target()) {
      if (style_dependent_range_start_) {
        DCHECK(range_start_);
        range_changed |= range_start_->UpdateOffset(
            keyframe_effect->target(), style_dependent_range_start_);
      }
      if (style_dependent_range_end_) {
        DCHECK(range_end_);
        range_changed |= range_end_->UpdateOffset(keyframe_effect->target(),
                                                  style_dependent_range_end_);
      }
    }
  }

  bool needs_new_start_time = false;
  switch (CalculateAnimationPlayState()) {
    case V8AnimationPlayState::Enum::kIdle:
      break;

    case V8AnimationPlayState::Enum::kPaused:
      needs_new_start_time = !start_time_ && !hold_time_;
      DCHECK(!needs_new_start_time || pending_pause_);
      break;

    case V8AnimationPlayState::Enum::kRunning:
    case V8AnimationPlayState::Enum::kFinished:
      if (!auto_align_start_time_ && hold_time_ && pending_play_ &&
          timeline_->CurrentTime()) {
        // The auto-alignment flag was reset via an API call. Set the start time
        // to preserve current time.
        ApplyPendingPlaybackRate();
        start_time_ = (playback_rate_ != 0)
                          ? CalculateStartTime(hold_time_.value()).value()
                          : timeline()->CurrentTime().value();
        hold_time_ = std::nullopt;
        needs_update = true;
      }
      needs_new_start_time =
          auto_align_start_time_ &&
          (!start_time_ || snapshot_changed || range_changed);
      break;

    default:
      NOTREACHED();
  }

  if (snapshot_changed || needs_new_start_time || range_changed) {
    InvalidateNormalizedTiming();
  }

  if (needs_new_start_time) {
    // Previous current time is used in update finished state to maintain
    // the current time if seeking out of bounds. A range update can place
    // current time temporarily out of bounds, but this should not be
    // confused with an explicit seek operation like setting the current or
    // start time.
    previous_current_time_ = std::nullopt;

    std::optional<AnimationTimeDelta> previous_start_time = start_time_;
    UpdateAutoAlignedStartTime();
    ApplyPendingPlaybackRate();
    if (start_time_ != previous_start_time) {
      needs_update = true;
      if (start_time_ && hold_time_) {
        hold_time_ = std::nullopt;
      }
    }
  }

  if (needs_update) {
    InvalidateEffectTargetStyle();
    SetOutdated();
    if (content_) {
      content_->Invalidate();
    }
    SetCompositorPending(CompositorPendingReason::kPendingEffectChange);
  }

  return !needs_update;
}

void Animation::SetRangeStartInternal(
    const std::optional<TimelineOffset>& range_start) {
  auto_align_start_time_ = true;
  if (range_start_ != range_start) {
    range_start_ = range_start;
    if (range_start_ && range_start_->style_dependent_offset) {
      style_dependent_range_start_ = TimelineOffset::ParseOffset(
          GetDocument(), range_start_->style_dependent_offset.value());
    } else {
      style_dependent_range_start_ = nullptr;
    }
    OnRangeUpdate();
  }
}

void Animation::SetRangeEndInternal(
    const std::optional<TimelineOffset>& range_end) {
  auto_align_start_time_ = true;
  if (range_end_ != range_end) {
    range_end_ = range_end;
    if (range_end_ && range_end_->style_dependent_offset) {
      style_dependent_range_end_ = TimelineOffset::ParseOffset(
          GetDocument(), range_end_->style_dependent_offset.value());
    } else {
      style_dependent_range_end_ = nullptr;
    }
    OnRangeUpdate();
  }
}

void Animation::SetRange(const std::optional<TimelineOffset>& range_start,
                         const std::optional<TimelineOffset>& range_end) {
  SetRangeStartInternal(range_start);
  SetRangeEndInternal(range_end);
}

void Animation::OnRangeUpdate() {
  // Change in animation range has no effect unless using a scroll-timeline.
  if (!IsA<ScrollSnapshotTimeline>(timeline_.Get())) {
    return;
  }

  // Force recalculation of the intrinsic iteration duration.
  InvalidateNormalizedTiming();
  if (PendingInternal()) {
    return;
  }

  V8AnimationPlayState::Enum play_state = CalculateAnimationPlayState();
  if (play_state == V8AnimationPlayState::Enum::kRunning ||
      play_state == V8AnimationPlayState::Enum::kFinished) {
    PlayInternal(AutoRewind::kEnabled, ASSERT_NO_EXCEPTION);
  }
}

void Animation::UpdateBoundaryAlignment(
    Timing::NormalizedTiming& timing) const {
  timing.is_start_boundary_aligned = false;
  timing.is_end_boundary_aligned = false;
  if (!auto_align_start_time_) {
    // If the start time is not auto adjusted to align with the bounds of the
    // animation range, then it is not possible in all cases to test whether
    // setting the scroll position with either end of the scroll range will
    // align with the before-active or active-after boundaries. Safest to
    // assume that we are not-aligned and the boundary is exclusive.
    // TODO(kevers): Investigate if/when a use-case pops up that is important to
    // address.
    return;
  }

  if (auto* scroll_timeline = DynamicTo<ScrollTimeline>(TimelineInternal())) {
    std::optional<double> max_scroll =
        scroll_timeline->GetMaximumScrollPosition();
    if (!max_scroll) {
      return;
    }
    std::optional<ScrollOffsets> scroll_offsets =
        scroll_timeline->GetResolvedScrollOffsets();
    if (!scroll_offsets) {
      return;
    }
    TimelineRange timeline_range = scroll_timeline->GetTimelineRange();
    double start = range_start_
                       ? timeline_range.ToFractionalOffset(range_start_.value())
                       : 0;
    double end =
        range_end_ ? timeline_range.ToFractionalOffset(range_end_.value()) : 1;

    AnimationTimeDelta timeline_duration =
        scroll_timeline->GetDuration().value();
    if (timeline_duration > AnimationTimeDelta()) {
      start += timing.start_delay / timeline_duration;
      end -= timing.end_delay / timeline_duration;
    }

    double start_offset =
        start * scroll_offsets->end + (1 - start) * scroll_offsets->start;

    double end_offset =
        end * scroll_offsets->end + (1 - end) * scroll_offsets->start;

    double rate = EffectivePlaybackRate();
    timing.is_start_boundary_aligned =
        rate < 0 && start_offset <= kScrollBoundaryTolerance;
    timing.is_end_boundary_aligned =
        rate > 0 &&
        rate * end_offset >= max_scroll.value() - kScrollBoundaryTolerance;
  }
}

namespace {

double ResolveAnimationRange(const std::optional<TimelineOffset>& offset,
                             const TimelineRange& timeline_range,
                             double default_value) {
  if (offset.has_value()) {
    return timeline_range.ToFractionalOffset(offset.value());
  }
  if (timeline_range.IsEmpty()) {
    return 0;
  }
  return default_value;
}

}  // namespace

bool Animation::ResolveTimelineOffsets(const TimelineRange& timeline_range) {
  if (auto* keyframe_effect = DynamicTo<KeyframeEffect>(effect())) {
    double range_start = ResolveAnimationRange(
        GetRangeStartInternal(), timeline_range, /* default_value */ 0);
    double range_end = ResolveAnimationRange(
        GetRangeEndInternal(), timeline_range, /* default_value */ 1);
    return keyframe_effect->Model()->ResolveTimelineOffsets(
        timeline_range, range_start, range_end);
  }
  return false;
}

void Animation::CancelAnimationOnCompositor() {
  VERIFY_PAINT_CLEAN_LOG_ONCE()
  if (HasActiveAnimationsOnCompositor()) {
    To<KeyframeEffect>(content_.Get())
        ->CancelAnimationOnCompositor(GetCompositorAnimation());
  }

  // Note: We do not update the composited paint status here since already
  // updated via setCompositorPending. If the animation is to be restarted on
  // compositor, paint has already been given the opportunity to make the
  // compositing decision.
  DestroyCompositorAnimation();
  compositor_state_.reset();
}

void Animation::RestartAnimationOnCompositor() {
  if (!HasActiveAnimationsOnCompositor()) {
    return;
  }
  SetCompositorPending(CompositorPendingReason::kPendingRestart);
}

void Animation::CancelIncompatibleAnimationsOnCompositor() {
  VERIFY_PAINT_CLEAN_LOG_ONCE()
  if (auto* keyframe_effect = DynamicTo<KeyframeEffect>(content_.Get()))
    keyframe_effect->CancelIncompatibleAnimationsOnCompositor();
}

bool Animation::HasActiveAnimationsOnCompositor() {
  auto* keyframe_effect = DynamicTo<KeyframeEffect>(content_.Get());
  if (!keyframe_effect)
    return false;

  return keyframe_effect->HasActiveAnimationsOnCompositor();
}

// Update current time of the animation. Refer to step 1 in:
// https://www.w3.org/TR/web-animations-1/#update-animations-and-send-events
bool Animation::Update(TimingUpdateReason reason) {
  // Due to the hierarchical nature of the timing model, updating the current
  // time of an animation also involves:
  //   * Running the update an animation’s finished state procedure.
  //   * Queueing animation events.

  if (!Outdated() && reason == kTimingUpdateForAnimationFrame &&
      IsInDisplayLockedSubtree())
    return true;

  ClearOutdated();
  bool idle =
      CalculateAnimationPlayState() == V8AnimationPlayState::Enum::kIdle;
  if (!idle && reason == kTimingUpdateForAnimationFrame)
    UpdateFinishedState(UpdateType::kContinuous, NotificationType::kAsync);

  if (content_) {
    std::optional<AnimationTimeDelta> inherited_time;

    if (!idle) {
      inherited_time = CurrentTimeInternal();
    }

    content_->UpdateInheritedTime(inherited_time, idle, playback_rate_, reason);

    // After updating the animation time if the animation is no longer current
    // blink will no longer composite the element (see
    // CompositingReasonFinder::RequiresCompositingFor*Animation).
    if (!content_->IsCurrent()) {
      SetCompositorPending(CompositorPendingReason::kPendingCancel);
    }
  }

  if (reason == kTimingUpdateForAnimationFrame) {
    if (idle || CalculateAnimationPlayState() ==
                    V8AnimationPlayState::Enum::kFinished) {
      finished_ = true;
    }
    NotifyProbe();
  }

  DCHECK(!outdated_);

  return !finished_ || TimeToEffectChange() ||
         // Always return true for not idle animations attached to not
         // monotonically increasing timelines even if the animation is
         // finished. This is required to accommodate cases where timeline ticks
         // back in time.
         (!idle && timeline_ && !timeline_->IsMonotonicallyIncreasing());
}

void Animation::QueueFinishedEvent() {
  const AtomicString& event_type = event_type_names::kFinish;
  if (GetExecutionContext() && HasEventListeners(event_type)) {
    pending_finished_event_ = MakeGarbageCollected<AnimationPlaybackEvent>(
        event_type, currentTime(), ConvertTimeToCSSNumberish(TimelineTime()));
    pending_finished_event_->SetTarget(this);
    pending_finished_event_->SetCurrentTarget(this);
    document_->EnqueueAnimationFrameEvent(pending_finished_event_);
  }
}

void Animation::UpdateIfNecessary() {
  if (Outdated())
    Update(kTimingUpdateOnDemand);
  DCHECK(!Outdated());
}

void Animation::EffectInvalidated() {
  SetOutdated();
  UpdateFinishedState(UpdateType::kContinuous, NotificationType::kAsync);
  // FIXME: Needs to consider groups when added.
  SetCompositorPending(CompositorPendingReason::kPendingEffectChange);
}

bool Animation::IsEventDispatchAllowed() const {
  return Paused() || start_time_;
}

std::optional<AnimationTimeDelta> Animation::TimeToEffectChange() {
  DCHECK(!outdated_);
  if (!start_time_ || hold_time_ || !playback_rate_) {
    return std::nullopt;
  }

  if (!content_) {
    std::optional<AnimationTimeDelta> current_time = CurrentTimeInternal();
    if (!current_time) {
      return std::nullopt;
    }
    return -current_time.value() / playback_rate_;
  }

  // If this animation has no effect, we can skip ticking it on main.
  if (!HasActiveAnimationsOnCompositor() && !animation_has_no_effect_ &&
      (content_->GetPhase() == Timing::kPhaseActive)) {
    return AnimationTimeDelta();
  }

  return (playback_rate_ > 0)
             ? (content_->TimeToForwardsEffectChange() / playback_rate_)
             : (content_->TimeToReverseEffectChange() / -playback_rate_);
}

// https://www.w3.org/TR/web-animations-1/#canceling-an-animation-section
void Animation::cancel() {
  AnimationTimeDelta current_time_before_cancel =
      CurrentTimeInternal().value_or(AnimationTimeDelta());
  V8AnimationPlayState::Enum initial_play_state = CalculateAnimationPlayState();
  if (initial_play_state != V8AnimationPlayState::Enum::kIdle) {
    ResetPendingTasks();

    if (finished_promise_) {
      if (finished_promise_->GetState() == AnimationPromise::kPending)
        RejectAndResetPromiseMaybeAsync(finished_promise_.Get());
      else
        finished_promise_->Reset();
    }

    const AtomicString& event_type = event_type_names::kCancel;
    if (GetExecutionContext() && HasEventListeners(event_type)) {
      pending_cancelled_event_ = MakeGarbageCollected<AnimationPlaybackEvent>(
          event_type, nullptr, ConvertTimeToCSSNumberish(TimelineTime()));
      pending_cancelled_event_->SetTarget(this);
      pending_cancelled_event_->SetCurrentTarget(this);
      document_->EnqueueAnimationFrameEvent(pending_cancelled_event_);
    }
  } else {
    // Quietly reset without rejecting promises.
    pending_playback_rate_ = std::nullopt;
    pending_pause_ = pending_play_ = false;
  }

  hold_time_ = std::nullopt;
  start_time_ = std::nullopt;

  SetCompositorPending(CompositorPendingReason::kPendingCancel);
  SetOutdated();

  // Force dispatch of canceled event.
  if (content_)
    content_->SetCancelTime(current_time_before_cancel);
  Update(kTimingUpdateOnDemand);

  // Notify of change to canceled state.
  NotifyProbe();
}

void Animation::CreateCompositorAnimation(
    std::optional<int> replaced_cc_animation_id) {
  VERIFY_PAINT_CLEAN_LOG_ONCE()
  if (Platform::Current()->IsThreadedAnimationEnabled() &&
      !compositor_animation_) {
    compositor_animation_ =
        CompositorAnimationHolder::Create(this, replaced_cc_animation_id);
    AttachCompositorTimeline();
  }

  AttachCompositedLayers();
}

void Animation::DestroyCompositorAnimation() {
  VERIFY_PAINT_CLEAN_LOG_ONCE()
  DetachCompositedLayers();

  if (compositor_animation_) {
    DetachCompositorTimeline();
    compositor_animation_->Detach();
    compositor_animation_ = nullptr;
  }
}

void Animation::AttachCompositorTimeline() {
  VERIFY_PAINT_CLEAN_LOG_ONCE()
  DCHECK(compositor_animation_);

  // Register ourselves on the compositor timeline. This will cause our cc-side
  // animation animation to be registered.
  cc::AnimationTimeline* compositor_timeline =
      timeline_ ? timeline_->EnsureCompositorTimeline() : nullptr;
  if (!compositor_timeline)
    return;

  if (CompositorAnimation* compositor_animation = GetCompositorAnimation()) {
    compositor_timeline->AttachAnimation(compositor_animation->CcAnimation());
  }

  // Note that while we attach here but we don't detach because the
  // |compositor_timeline| is detached in its destructor.
  document_->AttachCompositorTimeline(compositor_timeline);
}

void Animation::DetachCompositorTimeline() {
  VERIFY_PAINT_CLEAN_LOG_ONCE()
  DCHECK(compositor_animation_);
  cc::AnimationTimeline* compositor_timeline =
      timeline_ ? timeline_->CompositorTimeline() : nullptr;
  if (!compositor_timeline)
    return;

  if (CompositorAnimation* compositor_animation = GetCompositorAnimation()) {
    compositor_timeline->DetachAnimation(compositor_animation->CcAnimation());
  }
}

void Animation::AttachCompositedLayers() {
  VERIFY_PAINT_CLEAN_LOG_ONCE()
  if (!compositor_animation_) {
    return;
  }

  DCHECK(content_);
  DCHECK(IsA<KeyframeEffect>(*content_));

  To<KeyframeEffect>(content_.Get())->AttachCompositedLayers();
}

void Animation::DetachCompositedLayers() {
  VERIFY_PAINT_CLEAN_LOG_ONCE()
  if (compositor_animation_ &&
      compositor_animation_->GetAnimation()->IsElementAttached())
    compositor_animation_->GetAnimation()->DetachElement();
}

void Animation::NotifyAnimationStarted(base::TimeDelta monotonic_time,
                                       int group) {
  document_->GetPendingAnimations().NotifyCompositorAnimationStarted(
      monotonic_time.InSecondsF(), group);
}

void Animation::AddedEventListener(
    const AtomicString& event_type,
    RegisteredEventListener& registered_listener) {
  EventTarget::AddedEventListener(event_type, registered_listener);
  if (event_type == event_type_names::kFinish)
    UseCounter::Count(GetExecutionContext(), WebFeature::kAnimationFinishEvent);
}

void Animation::PauseForTesting(AnimationTimeDelta pause_time) {
  // Normally, cancel is deferred until Precommit, but cannot here since
  // updated below and must not be stale.
  if (CompositorPendingCancel()) {
    CancelAnimationOnCompositor();
  }

  // Do not restart a canceled animation.
  if (CalculateAnimationPlayState() == V8AnimationPlayState::Enum::kIdle) {
    return;
  }

  // Pause a running animation, or update the hold time of a previously paused
  // animation.
  SetCurrentTimeInternal(pause_time);
  if (HasActiveAnimationsOnCompositor()) {
    std::optional<AnimationTimeDelta> current_time = CurrentTimeInternal();
    DCHECK(current_time);
    To<KeyframeEffect>(content_.Get())
        ->PauseAnimationForTestingOnCompositor(
            base::Seconds(current_time.value().InSecondsF()));
  }

  // Do not wait for animation ready to lock in the hold time. Otherwise,
  // the pause won't take effect until the next frame and the hold time will
  // potentially drift.
  is_paused_for_testing_ = true;
  pending_pause_ = false;
  pending_play_ = false;
  hold_time_ = pause_time;
  start_time_ = std::nullopt;
  UpdateCompositedPaintStatus();
}

void Animation::SetEffectSuppressed(bool suppressed) {
  effect_suppressed_ = suppressed;
  if (suppressed) {
    SetCompositorPending(CompositorPendingReason::kPendingCancel);
  }
}

void Animation::DisableCompositedAnimationForTesting() {
  is_composited_animation_disabled_for_testing_ = true;
  CancelAnimationOnCompositor();
}

void Animation::InvalidateKeyframeEffect(
    const TreeScope& tree_scope,
    const StyleChangeReasonForTracing& reason) {
  auto* keyframe_effect = DynamicTo<KeyframeEffect>(content_.Get());
  if (!keyframe_effect)
    return;

  Element* target = keyframe_effect->EffectTarget();

  // TODO(alancutter): Remove dependency of this function on CSSAnimations.
  // This function makes the incorrect assumption that the animation uses
  // @keyframes for its effect model when it may instead be using JS provided
  // keyframes.
  if (target &&
      CSSAnimations::IsAffectedByKeyframesFromScope(*target, tree_scope)) {
    target->SetNeedsStyleRecalc(kLocalStyleChange, reason);
  }
}

void Animation::InvalidateEffectTargetStyle() {
  auto* keyframe_effect = DynamicTo<KeyframeEffect>(content_.Get());
  if (!keyframe_effect)
    return;
  Element* target = keyframe_effect->EffectTarget();
  if (target) {
    // TODO(andruud): Should we add a new style_change_reason?
    target->SetNeedsStyleRecalc(kLocalStyleChange,
                                StyleChangeReasonForTracing::Create(
                                    style_change_reason::kScrollTimeline));
  }
}

void Animation::InvalidateNormalizedTiming() {
  if (effect())
    effect()->InvalidateNormalizedTiming();
}

void Animation::ResolvePromiseMaybeAsync(AnimationPromise* promise) {
  if (ScriptForbiddenScope::IsScriptForbidden()) {
    GetExecutionContext()
        ->GetTaskRunner(TaskType::kDOMManipulation)
        ->PostTask(
            FROM_HERE,
            WTF::BindOnce(&AnimationPromise::Resolve<Animation*>,
                          WrapPersistent(promise), WrapPersistent(this)));
  } else {
    promise->Resolve(this);
  }
}

void Animation::RejectAndResetPromise(AnimationPromise* promise) {
  promise->Reject(
      MakeGarbageCollected<DOMException>(DOMExceptionCode::kAbortError));
  promise->Reset();
}

void Animation::RejectAndResetPromiseMaybeAsync(AnimationPromise* promise) {
  if (ScriptForbiddenScope::IsScriptForbidden()) {
    GetExecutionContext()
        ->GetTaskRunner(TaskType::kDOMManipulation)
        ->PostTask(FROM_HERE, WTF::BindOnce(&Animation::RejectAndResetPromise,
                                            WrapPersistent(this),
                                            WrapPersistent(promise)));
  } else {
    RejectAndResetPromise(promise);
  }
}

void Animation::NotifyProbe() {
  V8AnimationPlayState::Enum old_play_state = reported_play_state_;
  V8AnimationPlayState::Enum new_play_state =
      PendingInternal() ? V8AnimationPlayState::Enum::kPending
                        : CalculateAnimationPlayState();
  probe::AnimationUpdated(document_, this);

  if (old_play_state != new_play_state) {
    reported_play_state_ = new_play_state;

    bool was_active = old_play_state == V8AnimationPlayState::Enum::kPending ||
                      old_play_state == V8AnimationPlayState::Enum::kRunning;
    bool is_active = new_play_state == V8AnimationPlayState::Enum::kPending ||
                     new_play_state == V8AnimationPlayState::Enum::kRunning;

    if (!was_active && is_active) {
      TRACE_EVENT_NESTABLE_ASYNC_BEGIN1(
          "blink.animations,devtools.timeline,benchmark,rail", "Animation",
          this, "data", [&](perfetto::TracedValue context) {
            inspector_animation_event::Data(std::move(context), *this);
          });
    } else if (was_active && !is_active) {
      TRACE_EVENT_NESTABLE_ASYNC_END1(
          "blink.animations,devtools.timeline,benchmark,rail", "Animation",
          this, "endData", [&](perfetto::TracedValue context) {
            inspector_animation_state_event::Data(std::move(context), *this);
          });
    } else {
      TRACE_EVENT_NESTABLE_ASYNC_INSTANT1(
          "blink.animations,devtools.timeline,benchmark,rail", "Animation",
          this, "data", [&](perfetto::TracedValue context) {
            inspector_animation_state_event::Data(std::move(context), *this);
          });
    }
  }
}

// -------------------------------------
// Replacement of animations
// -------------------------------------

// https://www.w3.org/TR/web-animations-1/#removing-replaced-animations
bool Animation::IsReplaceable() {
  // An animation is replaceable if all of the following conditions are true:

  // 1. The existence of the animation is not prescribed by markup. That is, it
  //    is not a CSS animation with an owning element, nor a CSS transition with
  //    an owning element.
  if ((IsCSSAnimation() || IsCSSTransition()) && OwningElement()) {
    // A CSS animation or transition that is bound to markup is not replaceable.
    return false;
  }

  // 2. The animation's play state is finished.
  if (CalculateAnimationPlayState() != V8AnimationPlayState::Enum::kFinished) {
    return false;
  }

  // 3. The animation's replace state is not removed.
  if (replace_state_ == V8ReplaceState::Enum::kRemoved) {
    return false;
  }

  // 4. The animation is associated with a monotonically increasing timeline.
  if (!timeline_ || !timeline_->IsMonotonicallyIncreasing())
    return false;

  // 5. The animation has an associated effect.
  if (!content_ || !content_->IsKeyframeEffect())
    return false;

  // 6. The animation's associated effect is in effect.
  if (!content_->IsInEffect())
    return false;

  // 7. The animation's associated effect has an effect target.
  Element* target = To<KeyframeEffect>(content_.Get())->EffectTarget();
  if (!target)
    return false;

  return true;
}

// https://www.w3.org/TR/web-animations-1/#removing-replaced-animations
void Animation::RemoveReplacedAnimation() {
  DCHECK(IsReplaceable());

  // To remove a replaced animation, perform the following steps:
  // 1. Set animation’s replace state to removed.
  // 2. Create an AnimationPlaybackEvent, removeEvent.
  // 3. Set removeEvent’s type attribute to remove.
  // 4. Set removeEvent’s currentTime attribute to the current time of
  //    animation.
  // 5. Set removeEvent’s timelineTime attribute to the current time of the
  //    timeline with which animation is associated.
  //
  // If animation has a document for timing, then append removeEvent to its
  // document for timing's pending animation event queue along with its target,
  // animation. For the scheduled event time, use the result of applying the
  // procedure to convert timeline time to origin-relative time to the current
  // time of the timeline with which animation is associated.
  replace_state_ = V8ReplaceState::Enum::kRemoved;
  const AtomicString& event_type = event_type_names::kRemove;
  if (GetExecutionContext() && HasEventListeners(event_type)) {
    pending_remove_event_ = MakeGarbageCollected<AnimationPlaybackEvent>(
        event_type, currentTime(), ConvertTimeToCSSNumberish(TimelineTime()));
    pending_remove_event_->SetTarget(this);
    pending_remove_event_->SetCurrentTarget(this);
    document_->EnqueueAnimationFrameEvent(pending_remove_event_);
  }

  // Force timing update to clear the effect.
  if (content_)
    content_->Invalidate();
  Update(kTimingUpdateOnDemand);
}

void Animation::persist() {
  if (replace_state_ == V8ReplaceState::Enum::kPersisted) {
    return;
  }

  replace_state_ = V8ReplaceState::Enum::kPersisted;

  // Force timing update to reapply the effect.
  if (content_)
    content_->Invalidate();
  Update(kTimingUpdateOnDemand);
}

V8ReplaceState Animation::replaceState() {
  return V8ReplaceState(replace_state_);
}

// https://www.w3.org/TR/web-animations-1/#dom-animation-commitstyles
void Animation::commitStyles(ExceptionState& exception_state) {
  Element* target = content_ && content_->IsKeyframeEffect()
                        ? To<KeyframeEffect>(effect())->target()
                        : nullptr;

  // 1. If target is not an element capable of having a style attribute
  //    (for example, it is a pseudo-element or is an element in a document
  //    format for which style attributes are not defined) throw a
  //    "NoModificationAllowedError" DOMException and abort these steps.
  if (!target || !target->IsStyledElement() ||
      !To<KeyframeEffect>(effect())->pseudoElement().empty()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNoModificationAllowedError,
        "Animation not associated with a styled element");
    return;
  }
  // 2. If, after applying any pending style changes, target is not being
  //    rendered, throw an "InvalidStateError" DOMException and abort these
  //    steps.
  target->GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kJavaScript);
  if (!target->GetLayoutObject()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Target element is not rendered.");
    return;
  }

  // 3. Let inline style be the result of getting the CSS declaration block
  //    corresponding to target’s style attribute. If target does not have a
  //    style attribute, let inline style be a new empty CSS declaration block
  //    with the readonly flag unset and owner node set to target.
  CSSStyleDeclaration* inline_style = target->style();

  // 4. Let targeted properties be the set of physical longhand properties
  //    that are a target property for at least one animation effect
  //    associated with animation whose effect target is target.
  PropertyHandleSet animation_properties =
      To<KeyframeEffect>(effect())->Model()->Properties();

  // 5. For each property, property, in targeted properties:
  //   5.1 Let partialEffectStack be a copy of the effect stack for property
  //       on target.
  //   5.2 If animation’s replace state is removed, add all animation effects
  //       associated with animation whose effect target is target and which
  //       include property as a target property to partialEffectStack.
  //   5.3 Remove from partialEffectStack any animation effects whose
  //       associated animation has a higher composite order than animation.
  //   5.4 Let effect value be the result of calculating the result of
  //       partialEffectStack for property using target’s computed style
  //       (see § 5.4.3 Calculating the result of an effect stack).
  //   5.5 Set a CSS declaration property for effect value in inline style.
  // 6. Update style attribute for inline style.
  ActiveInterpolationsMap interpolations_map =
      To<KeyframeEffect>(effect())->InterpolationsForCommitStyles();

  // `inline_style` must be an inline style declaration, which is a subclass of
  // `AbstractPropertySetCSSStyleDeclaration`.
  CHECK(inline_style->IsAbstractPropertySet());
  StyleAttributeMutationScope style_attr_mutation_scope(
      To<AbstractPropertySetCSSStyleDeclaration>(inline_style));

  AnimationUtils::ForEachInterpolatedPropertyValue(
      target, animation_properties, interpolations_map,
      [inline_style, target](PropertyHandle property, const CSSValue* value) {
        inline_style->setProperty(
            target->GetExecutionContext(),
            property.GetCSSPropertyName().ToAtomicString(), value->CssText
"""


```