Response:
The user wants me to analyze a part of the `animation.cc` file in the Chromium Blink engine.
Specifically, they want me to:
1. **List the functionalities** present in the provided code snippet.
2. **Relate functionalities to web technologies (JavaScript, HTML, CSS)** with examples.
3. **Infer logic** with hypothetical inputs and outputs.
4. **Identify common user/programming errors** with examples.
5. **Summarize the overall functionality** of the provided code.

Let's break down the code snippet:

- **`OrderAnimations` function:** This function seems to be responsible for sorting animations based on various criteria, including element order, pseudo-element priority, and animation-specific properties (like `animation-index` for CSS animations and `transition-generation`/`css-property-name` for CSS transitions). It also handles non-CSS Web Animations.
- **`NotifyReady` function:** This function appears to be triggered when an animation is ready. It handles committing pending play or pause actions and updating the compositor state.
- **`CommitPendingPlay` function:** This function implements the logic for starting an animation, considering hold time and playback rate. It also resolves the ready promise and updates the finished state.
- **`CommitPendingPause` function:** This function implements the logic for pausing an animation, updating the hold time, and resolving the ready promise.
- **`Affects` function:** This function checks if an animation affects a specific element and CSS property.
- **`timeline` and `setTimeline` functions:** These functions manage the animation's associated timeline, handling attachment, detachment, and updates based on the timeline's properties (e.g., whether it's monotonically increasing).
- **`CalculateStartTime` and `CalculateCurrentTime` functions:** These functions calculate the animation's start and current times based on the associated timeline.
- **`setStartTime` function:** This function allows setting the animation's start time, considering timeline activity and handling pending tasks.
- **`setEffect` function:** This function allows setting the animation's effect, handling attachment, detachment, and updating the finished state. It also manages event delegates for CSS animations and transitions.
- **`CalculateAnimationPlayState` function:** This function determines the current play state of the animation (idle, paused, running, finished).
- **`PendingInternal` and `pending` functions:** These functions check if there are any pending play or pause tasks.
- **`ResetPendingTasks` function:** This function cancels any pending play or pause tasks and resets the ready promise.
- **`pause` function:** This function implements the logic for pausing an animation, including handling seek times and managing the ready promise.
- **`Unpause` function:** This function resumes a paused animation.
- **`play` and `PlayInternal` functions:** These functions implement the logic for starting or resuming an animation, handling auto-rewind, and resolving the ready promise.

Now, let's connect these functionalities to web technologies and consider potential errors.
```python
功能归纳：

Animation 类的这部分代码主要负责管理动画的播放状态、时间控制、以及与动画效果 (AnimationEffect) 和时间线 (AnimationTimeline) 的关联。它包含了以下核心功能：

1. **动画排序 (OrderAnimations):**  定义了动画在合成过程中的排序规则。这对于确保多个动画同时作用于同一元素时，按照正确的顺序进行渲染至关重要。排序考虑了元素的文档位置、伪元素类型及其优先级、以及 CSS 动画和过渡的特定属性（例如，在 `animation-name` 属性中的索引或过渡的生成次序和属性名）。对于非 CSS 的 Web Animation，则主要根据创建时间或序列号进行排序。

2. **动画就绪通知 (NotifyReady):** 当动画准备好应用状态变更时被调用，用于提交待处理的播放或暂停操作，并更新合成器状态的开始时间。

3. **提交待处理的播放 (CommitPendingPlay):**  实现了动画播放的具体逻辑。它根据动画是否有已解析的 `hold_time` 或 `start_time`，以及是否有待处理的播放速率变化，来计算并设置动画的 `start_time`。同时，它会解析与播放相关的 Promise 对象，并更新动画的完成状态。

4. **提交待处理的暂停 (CommitPendingPause):** 实现了动画暂停的具体逻辑。它计算并设置动画的 `hold_time`，清除 `start_time`，解析与暂停相关的 Promise 对象，并更新动画的完成状态。

5. **判断动画是否影响特定元素和属性 (Affects):**  允许查询动画是否会影响指定的 HTML 元素及其 CSS 属性。

6. **管理动画时间线 (timeline, setTimeline):**  负责关联和管理动画所使用的时间线对象。当时间线发生变化时，会更新动画的状态和时序信息，并处理与时间线相关的事件。对于非单调递增的时间线（例如 `ScrollTimeline`），会特别处理播放状态的维护。

7. **计算动画的开始和当前时间 (CalculateStartTime, CalculateCurrentTime):**  基于关联的时间线计算动画的开始时间和当前时间。

8. **设置动画开始时间 (setStartTime):**  允许通过 JavaScript 设置动画的开始时间，并相应地更新动画的 `hold_time`。它还会处理待处理的播放或暂停任务，并更新动画的完成状态。

9. **设置动画效果 (setEffect):**  允许将动画与特定的动画效果对象关联或解除关联。当关联的动画效果发生变化时，会处理事件委托的重新绑定，并触发必要的更新以确保事件的正确分发。对于 CSS 动画和过渡，这部分代码还负责处理 `transitionrun`、`transitionstart`、`transitionend`、`transitioncancel` 和 `animationstart`、`animationend`、`animationcancel` 等事件的触发。

10. **计算动画的播放状态 (CalculateAnimationPlayState):**  根据动画的内部状态（例如，`current_time`、`start_time`、是否有待处理的任务、以及有效的播放速率）来确定动画当前的播放状态（`idle`, `paused`, `running`, `finished`）。

11. **检查是否有待处理的任务 (PendingInternal, pending):**  用于判断动画是否有待处理的播放或暂停任务。

12. **重置待处理的任务 (ResetPendingTasks):**  取消任何待处理的播放或暂停任务，并拒绝相关的 Promise 对象。

13. **暂停动画 (pause):**  实现了暂停动画的逻辑，包括处理 `seek_time` 和管理 Promise 对象。对于具有非单调递增时间线的动画，会特别处理。

14. **取消暂停动画 (Unpause):**  恢复已暂停的动画的播放。

15. **播放动画 (play, PlayInternal):**  实现了开始或恢复动画播放的逻辑，包括处理自动回放 (`auto_rewind`) 和管理 Promise 对象。对于反向播放且目标效果持续时间为无限长的动画，会抛出异常。
"""
```
### 提示词
```
这是目录为blink/renderer/core/animation/animation.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
// Since pseudo elements are compared by their originating element,
        // they sort before their children.
        return originating_element1->compareDocumentPosition(
                   originating_element2) &
               Node::kDocumentPositionFollowing;
      } else {
        return originating_element1 < originating_element2;
      }
    }

    // A pseudo-element has a higher composite ordering than its originating
    // element, hence kPseudoIdNone is sorted earliest.
    // Two pseudo-elements sharing the same originating element are sorted
    // as follows:
    // ::marker
    // ::before
    // other pseudo-elements (ordered by selector)
    // ::after
    // TODO(bokan): ::view-transition ordering should probably also be explicit:
    // https://github.com/w3c/csswg-drafts/issues/9588.
    const PseudoId pseudo1 = owning_element1->GetPseudoId();
    const PseudoId pseudo2 = owning_element2->GetPseudoId();
    PseudoPriority priority1 = ConvertPseudoIdtoPriority(pseudo1);
    PseudoPriority priority2 = ConvertPseudoIdtoPriority(pseudo2);

    if (priority1 != priority2)
      return priority1 < priority2;

    if (priority1 == PseudoPriority::kOther && pseudo1 != pseudo2) {
      // TODO(bokan): This can happen with child pseudos in the
      // ::view-transition subtree but we may want to sort them based on their
      // actual composite order.
      // https://github.com/w3c/csswg-drafts/issues/9588.
      return CodeUnitCompareLessThan(
          PseudoElement::PseudoElementNameForEvents(owning_element1),
          PseudoElement::PseudoElementNameForEvents(owning_element2));
    }
    if (anim_priority1 == kCssAnimationPriority) {
      // When comparing two CSSAnimations with the same owning element, we sort
      // A and B based on their position in the computed value of the
      // animation-name property of the (common) owning element.
      return To<CSSAnimation>(animation1)->AnimationIndex() <
             To<CSSAnimation>(animation2)->AnimationIndex();
    } else {
      // First compare the transition generation of two transitions, then
      // compare them by the property name.
      if (To<CSSTransition>(animation1)->TransitionGeneration() !=
          To<CSSTransition>(animation2)->TransitionGeneration()) {
        return To<CSSTransition>(animation1)->TransitionGeneration() <
               To<CSSTransition>(animation2)->TransitionGeneration();
      }
      AtomicString css_property_name1 =
          GetCSSTransitionCSSPropertyName(animation1);
      AtomicString css_property_name2 =
          GetCSSTransitionCSSPropertyName(animation2);
      if (css_property_name1 && css_property_name2)
        return css_property_name1.Utf8() < css_property_name2.Utf8();
    }
    return animation1->SequenceNumber() < animation2->SequenceNumber();
  }
  // If the anmiations are not-CSS WebAnimation just compare them via generation
  // time/ sequence number.
  return animation1->SequenceNumber() < animation2->SequenceNumber();
}

void Animation::NotifyReady(AnimationTimeDelta ready_time) {
  // Complete the pending updates prior to updating the compositor state in
  // order to ensure a correct start time for the compositor state without the
  // need to duplicate the calculations.
  if (pending_play_)
    CommitPendingPlay(ready_time);
  else if (pending_pause_)
    CommitPendingPause(ready_time);

  if (compositor_state_ &&
      compositor_state_->pending_action == CompositorAction::kStart) {
    DCHECK(!compositor_state_->start_time);
    compositor_state_->pending_action = CompositorAction::kNone;
    compositor_state_->start_time =
        start_time_ ? std::make_optional(start_time_.value().InSecondsF())
                    : std::nullopt;
  }

  // Notify of change to play state.
  NotifyProbe();
}

// Microtask for playing an animation.
// Refer to Step 8.3 'pending play task' in the following spec:
// https://www.w3.org/TR/web-animations-1/#playing-an-animation-section
void Animation::CommitPendingPlay(AnimationTimeDelta ready_time) {
  DCHECK(start_time_ || hold_time_);
  DCHECK(pending_play_);
  pending_play_ = false;

  // Update hold and start time.
  if (hold_time_) {
    // A: If animation’s hold time is resolved,
    // A.1. Apply any pending playback rate on animation.
    // A.2. Let new start time be the result of evaluating:
    //        ready time - hold time / playback rate for animation.
    //      If the playback rate is zero, let new start time be simply ready
    //      time.
    // A.3. Set the start time of animation to new start time.
    // A.4. If animation’s playback rate is not 0, make animation’s hold time
    //      unresolved.
    ApplyPendingPlaybackRate();
    if (playback_rate_ == 0) {
      start_time_ = ready_time;
    } else {
      start_time_ = ready_time - hold_time_.value() / playback_rate_;
      hold_time_ = std::nullopt;
    }
  } else if (start_time_ && pending_playback_rate_) {
    // B: If animation’s start time is resolved and animation has a pending
    //    playback rate,
    // B.1. Let current time to match be the result of evaluating:
    //        (ready time - start time) × playback rate for animation.
    // B.2 Apply any pending playback rate on animation.
    // B.3 If animation’s playback rate is zero, let animation’s hold time be
    //     current time to match.
    // B.4 Let new start time be the result of evaluating:
    //       ready time - current time to match / playback rate for animation.
    //     If the playback rate is zero, let new start time be simply ready
    //     time.
    // B.5 Set the start time of animation to new start time.
    AnimationTimeDelta current_time_to_match =
        (ready_time - start_time_.value()) * playback_rate_;
    ApplyPendingPlaybackRate();
    if (playback_rate_ == 0) {
      hold_time_ = current_time_to_match;
      start_time_ = ready_time;
    } else {
      start_time_ = ready_time - current_time_to_match / playback_rate_;
    }
  }

  // 8.4 Resolve animation’s current ready promise with animation.
  if (ready_promise_ &&
      ready_promise_->GetState() == AnimationPromise::kPending)
    ResolvePromiseMaybeAsync(ready_promise_.Get());

  // 8.5 Run the procedure to update an animation’s finished state for
  //     animation with the did seek flag set to false, and the synchronously
  //     notify flag set to false.
  UpdateFinishedState(UpdateType::kContinuous, NotificationType::kAsync);
}

// Microtask for pausing an animation.
// Refer to step 7 'pending pause task' in the following spec:
// https://www.w3.org/TR/web-animations-1/#pausing-an-animation-section
void Animation::CommitPendingPause(AnimationTimeDelta ready_time) {
  DCHECK(pending_pause_);
  pending_pause_ = false;

  // 1. Let ready time be the time value of the timeline associated with
  //    animation at the moment when the user agent completed processing
  //    necessary to suspend playback of animation’s associated effect.
  // 2. If animation’s start time is resolved and its hold time is not resolved,
  //    let animation’s hold time be the result of evaluating
  //    (ready time - start time) × playback rate.
  if (start_time_ && !hold_time_) {
    hold_time_ = (ready_time - start_time_.value()) * playback_rate_;
  }

  // 3. Apply any pending playback rate on animation.
  // 4. Make animation’s start time unresolved.
  ApplyPendingPlaybackRate();
  start_time_ = std::nullopt;

  // 5. Resolve animation’s current ready promise with animation.
  if (ready_promise_ &&
      ready_promise_->GetState() == AnimationPromise::kPending)
    ResolvePromiseMaybeAsync(ready_promise_.Get());

  // 6. Run the procedure to update an animation’s finished state for animation
  //    with the did seek flag set to false (continuous), and the synchronously
  //    notify flag set to false.
  UpdateFinishedState(UpdateType::kContinuous, NotificationType::kAsync);
}

bool Animation::Affects(const Element& element,
                        const CSSProperty& property) const {
  const auto* effect = DynamicTo<KeyframeEffect>(content_.Get());
  if (!effect)
    return false;

  return (effect->EffectTarget() == &element) &&
         effect->Affects(PropertyHandle(property));
}

AnimationTimeline* Animation::timeline() {
  if (AnimationTimeline* timeline = TimelineInternal()) {
    return timeline->ExposedTimeline();
  }
  return nullptr;
}

void Animation::setTimeline(AnimationTimeline* timeline) {
  // https://www.w3.org/TR/web-animations-1/#setting-the-timeline

  // Unfortunately cannot mark the setter only as being conditionally enabled
  // via a feature flag. Conditionally making the feature a no-op is nearly
  // equivalent.
  if (!RuntimeEnabledFeatures::ScrollTimelineEnabled())
    return;

  // 1. Let the old timeline be the current timeline of the animation, if any.
  AnimationTimeline* old_timeline = timeline_;

  // 2. If the new timeline is the same object as the old timeline, abort this
  //    procedure.
  if (old_timeline == timeline)
    return;

  UpdateIfNecessary();
  V8AnimationPlayState::Enum old_play_state = CalculateAnimationPlayState();
  std::optional<AnimationTimeDelta> old_current_time = CurrentTimeInternal();

  // In some cases, we need to preserve the progress of the animation between
  // the old timeline and the new one. We do this by storing the progress using
  // the old current time and the effect end based on the old timeline. Pending
  // spec issue: https://github.com/w3c/csswg-drafts/issues/6452
  double progress = 0;
  if (old_current_time && !EffectEnd().is_zero()) {
    progress = old_current_time.value() / EffectEnd();
  }

  // 3. Let the timeline of the animation be the new timeline.

  // The Blink implementation requires additional steps to link the animation
  // to the new timeline. Animations with a null timeline hang off of the
  // document timeline in order to be properly included in the results for
  // getAnimations calls.
  if (old_timeline)
    old_timeline->AnimationDetached(this);
  else
    document_->Timeline().AnimationDetached(this);
  timeline_ = timeline;
  timeline_duration_ = timeline ? timeline->GetDuration() : std::nullopt;
  if (timeline)
    timeline->AnimationAttached(this);
  else
    document_->Timeline().AnimationAttached(this);
  SetOutdated();

  // Update content timing to be based on new timeline type. This ensures that
  // EffectEnd() is returning a value appropriate to the new timeline.
  if (content_) {
    content_->InvalidateNormalizedTiming();
  }

  if (timeline && !timeline->IsMonotonicallyIncreasing()) {
    switch (old_play_state) {
      case V8AnimationPlayState::Enum::kIdle:
        break;

      case V8AnimationPlayState::Enum::kRunning:
      case V8AnimationPlayState::Enum::kFinished:
        if (old_current_time) {
          start_time_ = std::nullopt;
          hold_time_ = progress * EffectEnd();
        }
        PlayInternal(AutoRewind::kEnabled, ASSERT_NO_EXCEPTION);
        return;

      case V8AnimationPlayState::Enum::kPaused:
        if (old_current_time) {
          start_time_ = std::nullopt;
          hold_time_ = progress * EffectEnd();
        }
        break;

      default:
        NOTREACHED();
    }
  } else if (old_current_time && old_timeline &&
             !old_timeline->IsMonotonicallyIncreasing()) {
    SetCurrentTimeInternal(progress * EffectEnd());
  }

  // 4. If the start time of animation is resolved, make the animation’s hold
  //    time unresolved. This step ensures that the finished play state of the
  //    animation is not “sticky” but is re-evaluated based on its updated
  //    current time.
  if (start_time_)
    hold_time_ = std::nullopt;

  // 5. Run the procedure to update an animation’s finished state for animation
  //    with the did seek flag set to false, and the synchronously notify flag
  //    set to false.
  UpdateFinishedState(UpdateType::kContinuous, NotificationType::kAsync);

  if (content_ && !timeline_) {
    // Update the timing model to capture the phase change and cancel an active
    // CSS animation or transition.
    content_->Invalidate();
    Update(kTimingUpdateOnDemand);
  }

  SetCompositorPending(CompositorPendingReason::kPendingRestart);

  // Inform devtools of a potential change to the play state.
  NotifyProbe();
}

std::optional<AnimationTimeDelta> Animation::CalculateStartTime(
    AnimationTimeDelta current_time) const {
  std::optional<AnimationTimeDelta> start_time;
  if (timeline_) {
    std::optional<AnimationTimeDelta> timeline_time = timeline_->CurrentTime();
    if (timeline_time)
      start_time = timeline_time.value() - current_time / playback_rate_;
    // TODO(crbug.com/916117): Handle NaN time for scroll-linked animations.
    DCHECK(start_time || timeline_->IsProgressBased());
  }
  return start_time;
}

std::optional<AnimationTimeDelta> Animation::CalculateCurrentTime() const {
  if (!start_time_ || !timeline_ || !timeline_->IsActive())
    return std::nullopt;

  std::optional<AnimationTimeDelta> timeline_time = timeline_->CurrentTime();
  // timeline_ must be active here, make sure it is returning a current_time.
  DCHECK(timeline_time);

  return (timeline_time.value() - start_time_.value()) * playback_rate_;
}

// https://www.w3.org/TR/web-animations-1/#setting-the-start-time-of-an-animation
void Animation::setStartTime(const V8CSSNumberish* start_time,
                             ExceptionState& exception_state) {
  std::optional<AnimationTimeDelta> new_start_time;
  // Failure to convert results in a thrown exception and returning false.
  if (!ConvertCSSNumberishToTime(start_time, new_start_time, "startTime",
                                 exception_state))
    return;

  auto_align_start_time_ = false;

  const bool had_start_time = start_time_.has_value();

  // 1. Let timeline time be the current time value of the timeline that
  //    animation is associated with. If there is no timeline associated with
  //    animation or the associated timeline is inactive, let the timeline time
  //    be unresolved.
  std::optional<AnimationTimeDelta> timeline_time =
      timeline_ && timeline_->IsActive() ? timeline_->CurrentTime()
                                         : std::nullopt;

  // 2. If timeline time is unresolved and new start time is resolved, make
  //    animation’s hold time unresolved.
  // This preserves the invariant that when we don’t have an active timeline it
  // is only possible to set either the start time or the animation’s current
  // time.
  if (!timeline_time && new_start_time) {
    hold_time_ = std::nullopt;
  }

  // 3. Let previous current time be animation’s current time.
  std::optional<AnimationTimeDelta> previous_current_time =
      CurrentTimeInternal();

  // 4. Apply any pending playback rate on animation.
  ApplyPendingPlaybackRate();

  // 5. Set animation’s start time to new start time.
  if (new_start_time) {
    // Snap to timeline time if within floating point tolerance to ensure
    // deterministic behavior in phase transitions.
    if (timeline_time && TimingCalculations::IsWithinAnimationTimeEpsilon(
                             timeline_time.value().InSecondsF(),
                             new_start_time.value().InSecondsF())) {
      new_start_time = timeline_time.value();
    }
  }
  start_time_ = new_start_time;

  // 6. Update animation’s hold time based on the first matching condition from
  //    the following,
  // 6a If new start time is resolved,
  //      If animation’s playback rate is not zero, make animation’s hold time
  //      unresolved.
  // 6b Otherwise (new start time is unresolved),
  //      Set animation’s hold time to previous current time even if previous
  //      current time is unresolved.
  if (start_time_) {
    if (playback_rate_ != 0) {
      hold_time_ = std::nullopt;
    }
  } else {
    hold_time_ = previous_current_time;
  }

  // 7. If animation has a pending play task or a pending pause task, cancel
  //    that task and resolve animation’s current ready promise with animation.
  if (PendingInternal()) {
    pending_pause_ = false;
    pending_play_ = false;
    if (ready_promise_ &&
        ready_promise_->GetState() == AnimationPromise::kPending)
      ResolvePromiseMaybeAsync(ready_promise_.Get());
  }

  // 8. Run the procedure to update an animation’s finished state for animation
  //    with the did seek flag set to true (discontinuous), and the
  //    synchronously notify flag set to false (async).
  UpdateFinishedState(UpdateType::kDiscontinuous, NotificationType::kAsync);

  // Update user agent.
  std::optional<AnimationTimeDelta> new_current_time = CurrentTimeInternal();
  // Even when the animation is not outdated,call SetOutdated to ensure
  // the animation is tracked by its timeline for future timing
  // updates.
  if (previous_current_time != new_current_time ||
      (!had_start_time && start_time_)) {
    SetOutdated();
  }
  SetCompositorPending(CompositorPendingReason::kPendingUpdate);

  NotifyProbe();
}

// https://www.w3.org/TR/web-animations-1/#setting-the-associated-effect
void Animation::setEffect(AnimationEffect* new_effect) {
  // 1. Let old effect be the current associated effect of animation, if any.
  AnimationEffect* old_effect = content_;

  // 2. If new effect is the same object as old effect, abort this procedure.
  if (new_effect == old_effect)
    return;

  // 3. If animation has a pending pause task, reschedule that task to run as
  //    soon as animation is ready.
  // 4. If animation has a pending play task, reschedule that task to run as
  //    soon as animation is ready to play new effect.
  // No special action required for a reschedule. The pending_pause_ and
  // pending_play_ flags remain unchanged.

  // 5. If new effect is not null and if new effect is the associated effect of
  //    another previous animation, run the procedure to set the associated
  //    effect of an animation (this procedure) on previous animation passing
  //    null as new effect.
  if (new_effect && new_effect->GetAnimation())
    new_effect->GetAnimation()->setEffect(nullptr);

  // Clear timeline offsets for old effect.
  ResolveTimelineOffsets(TimelineRange());

  // 6. Let the associated effect of the animation be the new effect.
  if (old_effect)
    old_effect->Detach();
  content_ = new_effect;
  if (new_effect)
    new_effect->Attach(this);

  // Resolve timeline offsets for new effect.
  ResolveTimelineOffsets(timeline_ ? timeline_->GetTimelineRange()
                                   : TimelineRange());

  SetOutdated();

  // 7. Run the procedure to update an animation’s finished state for animation
  //    with the did seek flag set to false (continuous), and the synchronously
  //    notify flag set to false (async).
  UpdateFinishedState(UpdateType::kContinuous, NotificationType::kAsync);

  SetCompositorPending(CompositorPendingReason::kPendingEffectChange);

  // Notify of a potential state change.
  NotifyProbe();

  // The effect is no longer associated with CSS properties.
  if (new_effect) {
    new_effect->SetIgnoreCssTimingProperties();
    if (KeyframeEffect* keyframe_effect =
            DynamicTo<KeyframeEffect>(new_effect)) {
      keyframe_effect->SetIgnoreCSSKeyframes();
    }
  }

  // The remaining steps are for handling CSS animation and transition events.
  // Both use an event delegate to dispatch events, which must be reattached to
  // the new effect.

  // When the animation no longer has an associated effect, calls to
  // Animation::Update will no longer update the animation timing and,
  // consequently, do not trigger animation or transition events.
  // Each transitionrun or transitionstart requires a corresponding
  // transitionend or transitioncancel.
  // https://drafts.csswg.org/css-transitions-2/#event-dispatch
  // Similarly, each animationstart requires a corresponding animationend or
  // animationcancel.
  // https://drafts.csswg.org/css-animations-2/#event-dispatch
  AnimationEffect::EventDelegate* old_event_delegate =
      old_effect ? old_effect->GetEventDelegate() : nullptr;
  if (!new_effect && old_effect && old_event_delegate) {
    // If the animation|transition has no target effect, the timing phase is set
    // according to the first matching condition from below:
    //   If the current time is unresolved,
    //     The timing phase is ‘idle’.
    //   If current time < 0,
    //     The timing phase is ‘before’.
    //   Otherwise,
    //     The timing phase is ‘after’.
    std::optional<AnimationTimeDelta> current_time = CurrentTimeInternal();
    Timing::Phase phase;
    if (!current_time)
      phase = Timing::kPhaseNone;
    else if (current_time < AnimationTimeDelta())
      phase = Timing::kPhaseBefore;
    else
      phase = Timing::kPhaseAfter;
    old_event_delegate->OnEventCondition(*old_effect, phase);
    return;
  }

  if (!new_effect || !old_effect)
    return;

  // Use the original target for event targeting.
  Element* target = To<KeyframeEffect>(old_effect)->target();
  if (!target)
    return;

  // Attach an event delegate to the new effect.
  AnimationEffect::EventDelegate* new_event_delegate =
      CreateEventDelegate(target, old_event_delegate);
  new_effect->SetEventDelegate(new_event_delegate);

  // Force an update to the timing model to ensure correct ordering of
  // animation or transition events.
  Update(kTimingUpdateOnDemand);
}

// https://www.w3.org/TR/web-animations-1/#play-states
V8AnimationPlayState::Enum Animation::CalculateAnimationPlayState() const {
  // 1. All of the following conditions are true:
  //    * The current time of animation is unresolved, and
  //    * the start time of animation is unresolved, and
  //    * animation does not have either a pending play task or a pending pause
  //      task,
  //    then idle.
  if (!CurrentTimeInternal() && !start_time_ && !PendingInternal())
    return V8AnimationPlayState::Enum::kIdle;

  // 2. Either of the following conditions are true:
  //    * animation has a pending pause task, or
  //    * both the start time of animation is unresolved and it does not have a
  //      pending play task,
  //    then paused.
  if (pending_pause_ || (!start_time_ && !pending_play_))
    return V8AnimationPlayState::Enum::kPaused;

  // 3.  For animation, current time is resolved and either of the following
  //     conditions are true:
  //     * animation’s effective playback rate > 0 and current time ≥ target
  //       effect end; or
  //     * animation’s effective playback rate < 0 and current time ≤ 0,
  //    then finished.
  if (Limited())
    return V8AnimationPlayState::Enum::kFinished;

  // 4.  Otherwise
  return V8AnimationPlayState::Enum::kRunning;
}

bool Animation::PendingInternal() const {
  return pending_pause_ || pending_play_;
}

bool Animation::pending() const {
  return PendingInternal();
}

// https://www.w3.org/TR/web-animations-1/#reset-an-animations-pending-tasks.
void Animation::ResetPendingTasks() {
  // 1. If animation does not have a pending play task or a pending pause task,
  //    abort this procedure.
  if (!PendingInternal())
    return;

  // 2. If animation has a pending play task, cancel that task.
  // 3. If animation has a pending pause task, cancel that task.
  pending_play_ = false;
  pending_pause_ = false;

  // 4. Apply any pending playback rate on animation.
  ApplyPendingPlaybackRate();

  // 5. Reject animation’s current ready promise with a DOMException named
  //    "AbortError".
  // 6. Let animation’s current ready promise be the result of creating a new
  //    resolved Promise object with value animation in the relevant Realm of
  //    animation.
  if (ready_promise_)
    RejectAndResetPromiseMaybeAsync(ready_promise_.Get());
}

// ----------------------------------------------
// Pause methods.
// ----------------------------------------------

// https://www.w3.org/TR/web-animations-1/#pausing-an-animation-section
void Animation::pause(ExceptionState& exception_state) {
  // 1. If animation has a pending pause task, abort these steps.
  // 2. If the play state of animation is paused, abort these steps.
  if (pending_pause_ ||
      CalculateAnimationPlayState() == V8AnimationPlayState::Enum::kPaused) {
    return;
  }

  // 3. Let seek time be a time value that is initially unresolved.
  std::optional<AnimationTimeDelta> seek_time;

  // 4. Let has finite timeline be true if animation has an associated timeline
  //    that is not monotonically increasing.
  bool has_finite_timeline =
      timeline_ && !timeline_->IsMonotonicallyIncreasing();

  // 5.  If the animation’s current time is unresolved, perform the steps
  //     according to the first matching condition from below:
  // 5a. If animation’s playback rate is ≥ 0,
  //       Set seek time to zero.
  // 5b. Otherwise,
  //         If associated effect end for animation is positive infinity,
  //             throw an "InvalidStateError" DOMException and abort these
  //             steps.
  //         Otherwise,
  //             Set seek time to animation's associated effect end.
  if (!CurrentTimeInternal() && !has_finite_timeline) {
    if (playback_rate_ >= 0) {
      seek_time = AnimationTimeDelta();
    } else {
      if (EffectEnd().is_inf()) {
        exception_state.ThrowDOMException(
            DOMExceptionCode::kInvalidStateError,
            "Cannot play reversed Animation with infinite target effect end.");
        return;
      }
      seek_time = EffectEnd();
    }
  }

  // 6. If seek time is resolved,
  //        If has finite timeline is true,
  //            Set animation's start time to seek time.
  //        Otherwise,
  //            Set animation's hold time to seek time.
  if (seek_time) {
    hold_time_ = seek_time;
  }

  // TODO(kevers): Add step to the spec for handling scroll-driven animations.
  if (!hold_time_ && !start_time_) {
    DCHECK(has_finite_timeline);
    auto_align_start_time_ = true;
  }

  // 7. Let has pending ready promise be a boolean flag that is initially false.
  // 8. If animation has a pending play task, cancel that task and let has
  //    pending ready promise be true.
  // 9. If has pending ready promise is false, set animation’s current ready
  //    promise to a new promise in the relevant Realm of animation.
  if (pending_play_) {
    pending_play_ = false;
  } else if (ready_promise_) {
    ready_promise_->Reset();
  }

  // 10. Schedule a task to be executed at the first possible moment where both
  //    of the following conditions are true:
  //    10a. the user agent has performed any processing necessary to suspend
  //        the playback of animation’s associated effect, if any.
  //    10b. the animation is associated with a timeline that is not inactive.
  pending_pause_ = true;

  SetOutdated();
  SetCompositorPending(CompositorPendingReason::kPendingUpdate);

  // 11. Run the procedure to update an animation’s finished state for animation
  //    with the did seek flag set to false (continuous), and synchronously
  //    notify flag set to false.
  UpdateFinishedState(UpdateType::kContinuous, NotificationType::kAsync);

  NotifyProbe();
}

// ----------------------------------------------
// Play methods.
// ----------------------------------------------

// Refer to the unpause operation in the following spec:
// https://www.w3.org/TR/css-animations-1/#animation-play-state
void Animation::Unpause() {
  if (CalculateAnimationPlayState() != V8AnimationPlayState::Enum::kPaused) {
    return;
  }

  // TODO(kevers): Add step in the spec for making auto-rewind dependent on the
  // type of timeline.
  bool has_finite_timeline =
      timeline_ && !timeline_->IsMonotonicallyIncreasing();
  AutoRewind rewind_mode =
      has_finite_timeline ? AutoRewind::kEnabled : AutoRewind::kDisabled;
  PlayInternal(rewind_mode, ASSERT_NO_EXCEPTION);
}

// https://www.w3.org/TR/web-animations-1/#playing-an-animation-section
void Animation::play(ExceptionState& exception_state) {
  // Begin or resume playback of the animation by running the procedure to
  // play an animation passing true as the value of the auto-rewind flag.
  PlayInternal(AutoRewind::kEnabled, exception_state);
}

// https://www.w3.org/TR/web-animations-2/#playing-an-animation-section
void Animation::PlayInternal(AutoRewind auto_rewind,
                             ExceptionState& exception_state) {
  // 1. Let aborted pause be a boolean flag that is true if animation has a
  //    pending pause task, and false otherwise.
  // 2. Let has pending ready promise be a boolean flag that is initially false.
  // 3. Let seek time be a time value that is initially unresolved.
  //
  //    TODO(kevers): We should not use a seek time for scroll-driven
  //    animations.
  //
  //    NOTE: Seeking is enabled for time based animations when a discontinuity
  //    in the animation's progress is permitted, such as when starting from
  //    the idle state, or rewinding an animation that outside of the range
  //    [0, effect end]. Operations like unpausing an animation or updating its
  //    playback rate must preserve current time for time-based animations.
  //    Conversely, seeking is never permitted for scroll-driven animations
  //    because the start time is layout dependent and may not be resolvable at
  //    this stage.
  //
  // 4. Let has finite timeline be true if animation has an associated timeline
  //    that is not monotonically increasing.
  //
  //    TODO(kevers): Move this before step 3 in the spec since we shouldn't
  //    calculate a seek time for a scroll-driven animation.
  //
  // 5. Let previous current time be the animation’s current time
  // 6. If reset current time on resume is set:
  //      * Set previous current time to unresolved.
  //      * Set the reset current time on resume flag to false.
  //
  //    TODO(kevers): Remove the reset current time on resume flag. Unpausing
  //    a scroll-linked animation should update its start time based on the
  //    animation range regardless of whether the timeline was changed.

  bool aborted_pause = pending_pause_;
  bool has_pending_ready_promise = false;
  std::optional<AnimationTimeDelta> seek_time;
  bool has_finite_timeline =
      timeline_ && !timeline_->IsMonotonicallyIncreasing();
  bool enable_seek =
      auto_rewind == AutoRewind::kEnabled && !has_finite_timeline;

  // 7. Perform the steps corresponding to the first matching condition from the
  //    following, if any:
  //     * If animation’s effective playback rate > 0, the auto-rewind flag is
  //       true and either animation’s:
  //         * previous current time is unresolved, or
  //         * previous current time < zero, or
  //         * previous current time ≥ associated effect end,
  //       Set seek time to zero.
  //     * If animation’s effective playback rate < 0, the auto-rewind flag is
  //       true and either animation’s:
  //         * previous current time is unresolved, or
  //         * previous current time ≤ zero, or
  //         * previous current time > associated effect end,
  //       If associated effect end is positive infinity,
  //         throw an "InvalidStateError" DOMException and abort these steps.
  //       Otherwise,
  //         Set seek time to animation’s associated effect end.
  //     * If animation’s effective playback rate = 0 and animation’s current
  //       time is unresolved,
  //         Set seek time to zero.
  //
  // (TLDR version) If seek is enabled:
  //   Jump to the beginning or end of the animation depending on the playback
  //   rate if the current time is not resolved or out of bounds. Attempting
  //   to jump to the end of an infinite duration animation is not permitted.
  double effective_playback_rate = EffectivePlaybackRate();
  std::optional<AnimationTimeDelta> current_time = CurrentTimeInternal();
  std::optional<AnimationTimeDelta> effect_end = EffectEnd();
  if (effective_playback_rate > 0 && enable_seek &&
      (!current_time || current_time < AnimationTimeDelta() ||
       current_time >= effect_end)) {
    hold_time_ = AnimationTimeDelta();
  } else if (effective_playback_rate < 0 && enable_seek &&
             (!current_time || current_time <= AnimationTimeDelta() ||
              current_time > EffectEnd())) {
    if (EffectEnd().is_inf()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidStateError,
          "Cannot play reversed Animation with infinite target effect end.");
      return;
    }
    hold_time_ = EffectEnd();
  } else if (effective_playback_rate == 0 && !current_time) {
    hold_time_ = AnimationTimeDelta();
  }

  // 8. If seek time is resolved,
  //      * If has finite t
```