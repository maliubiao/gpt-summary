Response:
The user wants a summary of the provided C++ code snippet from the Chromium Blink engine. The code is located in `blink/renderer/core/animation/css/css_animations.cc`.

Here's a breakdown of how to approach this:

1. **Identify the Core Functionality:**  The code clearly deals with CSS Animations. The methods and variable names (e.g., `CSSAnimations`, `RunningAnimation`, `CSSAnimationProxy`, `update.StartAnimation`, `update.CancelAnimation`, `Timing`) strongly suggest this.

2. **Analyze Key Methods:**
    * The initial `if (animation_data && ...)` block seems to iterate through defined CSS animations and manage their states (start, pause, update).
    * The logic within this block checks for existing animations and either updates them or starts new ones.
    * The loops related to `cancel_running_animation_flags` handle the cancellation of animations.
    * `CreateEventDelegate` is likely responsible for creating event handlers related to animation events.
    * `SnapshotCompositorKeyframes` appears to handle optimization for animations running on the compositor.
    * `UpdateAnimationFlags` sets flags in the `ComputedStyleBuilder` based on which animation properties are active.
    * `MaybeApplyPendingUpdate` seems to process and apply changes accumulated in a `pending_update_` object. This involves starting, updating, cancelling animations and transitions, and managing timeline attachments.
    * `CreateCancelledTransitionsSet` helps identify which transitions need to be cancelled.
    * `CanCalculateTransitionUpdateForProperty` and `CalculateTransitionUpdateForPropertyHandle` are concerned with determining when and how CSS transitions should be applied. They check for conflicts with running animations.

3. **Identify Relationships with Web Technologies:** The code interacts with CSS (obviously), and by extension, HTML (as CSS styles elements in HTML). JavaScript's role is in triggering style changes that lead to these animations.

4. **Look for Logical Reasoning and Assumptions:** The code makes decisions based on the current state of animations, the provided `animation_data`, and potentially existing animations. Assumptions are made about the structure of the data and the order of operations.

5. **Identify Potential User/Programming Errors:** Incorrectly defining CSS animation properties, conflicts between JavaScript and CSS animation control, and misuse of transition properties are potential issues.

6. **Synthesize the Information into a Summary:** Combine the above points into a concise description of the file's purpose.

**Constraint Checklist & Confidence Score:**

* Does the response list the functions of the code? Yes.
* Does the response explain the relationship with Javascript, HTML, and CSS? Yes.
* Does the response provide examples for the relationships? Yes.
* Does the response provide examples of logical reasoning with input and output? Yes.
* Does the response provide examples of user/programming errors? Yes.
* Is this part 3 of 5? Yes.
* Does the response summarize the function of the code? Yes.

Confidence Score: 5/5

**Mental Sandbox Simulation:**

Imagine the code receives new style information that includes a CSS animation.

* **Input:**  `animation_data` containing details about the animation (name, duration, etc.), current element style, potentially existing animations.
* **Processing:**
    * The code iterates through the animations in `animation_data`.
    * It checks if an animation with the same name and index already exists.
    * If it exists, it compares the properties and updates the existing animation if needed (e.g., changing play state, timing, keyframes).
    * If it doesn't exist, it creates a new `CSSAnimation` object and starts it.
    * If an existing animation is no longer in `animation_data`, it's marked for cancellation.
* **Output:** The `update` object will contain instructions to start, update, or cancel animations. The internal state of `css_animations` will be modified.

Consider a potential error: The user defines two animations with the same name on the same element. The code correctly handles this by using the `name_index` to differentiate them. However, the user might not intend this, leading to unexpected animation behavior.
这是 `blink/renderer/core/animation/css/css_animations.cc` 文件的第三部分，主要负责 **处理和更新 CSS 动画**。 它包含了在元素样式更新时，如何识别、创建、更新和取消 CSS 动画的逻辑。

**功能归纳:**

1. **管理 CSS 动画的生命周期:**  该部分代码的核心功能是管理 CSS 动画的启动、更新、暂停/恢复以及取消。它将 CSS 样式中的动画属性（如 `animation-name`, `animation-duration`, `animation-play-state` 等）转化为实际运行的动画效果。

2. **与 Web Animations API 集成:**  Blink 引擎的 CSS 动画实现是基于 Web Animations API 的。这段代码通过 `Animation` 和 `AnimationEffect` 等接口来操作动画。

3. **处理动画属性的变更:** 当元素的 CSS 动画属性发生变化时，这段代码会检测这些变化，并相应地更新正在运行的动画或创建新的动画。

4. **优化动画性能:**  代码中包含了一些针对性能的考虑，例如判断动画是否可以在合成器线程上运行 (`SnapshotCompositorKeyframes`)，以及设置动画相关的标志位来优化样式计算 (`UpdateAnimationFlags`).

5. **处理 CSS 过渡 (Transitions) 的中断和启动:** 代码中也包含一些与 CSS 过渡相关的逻辑，例如在动画运行时阻止过渡 (`CanCalculateTransitionUpdateForProperty`)，以及在某些情况下启动新的过渡。

**与 Javascript, HTML, CSS 的关系及举例说明:**

* **CSS:**  这是该文件的核心关注点。它解析 CSS 动画相关的属性，并根据这些属性创建和控制动画。
    * **例子:**  当 CSS 中定义了如下动画时：
      ```css
      .my-element {
        animation-name: fadeIn;
        animation-duration: 1s;
      }

      @keyframes fadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
      }
      ```
      这段 C++ 代码会解析这些 CSS 规则，找到 `fadeIn` 关键帧规则，并创建一个 `CSSAnimation` 对象来执行从 `opacity: 0` 到 `opacity: 1` 的动画。

* **HTML:**  CSS 动画应用于 HTML 元素。这段代码处理的是特定 HTML 元素上的动画。
    * **例子:** 如果一个 `<div>` 元素应用了上述的 `.my-element` 类，那么这段 C++ 代码将会为这个 `<div>` 元素创建并管理 `fadeIn` 动画。

* **Javascript:** Javascript 可以通过修改元素的 CSS 样式来触发或控制 CSS 动画。 Web Animations API 也允许 Javascript 直接创建和控制动画，这段代码也需要与这些 Javascript 操作协同工作。
    * **例子:**  Javascript 可以通过修改元素的 `className` 或 `style` 属性来触发 CSS 动画：
      ```javascript
      const element = document.querySelector('.my-element');
      element.classList.add('animate'); // 假设 .animate 触发了 CSS 动画
      ```
      或者使用 Web Animations API 直接控制：
      ```javascript
      const element = document.querySelector('.my-element');
      const animation = element.animate([
        { opacity: 0 },
        { opacity: 1 }
      ], { duration: 1000 });
      ```
      这段 C++ 代码会响应这些 Javascript 操作引起的样式变化，并更新或创建相应的 CSS 动画。代码中 `animation->CalculateAnimationPlayState()` 涉及到 Web Animations API 的 `play()` 和 `pause()` 方法对动画状态的影响。

**逻辑推理的假设输入与输出:**

**假设输入:**

* `animation_data`: 包含了从样式计算中获取的元素的 CSS 动画属性信息，例如 `animation-name` 为 "slideIn"，`animation-duration` 为 "0.5s"，`animation-play-state` 为 "running"。
* `old_style`:  元素之前的样式信息，可能不包含任何动画，或者包含不同的动画属性。
* `css_animations`:  指向元素当前正在运行的 CSS 动画的集合。

**逻辑推理:**

1. **检查是否存在同名动画:** 代码会遍历 `css_animations`，查找是否已经存在名为 "slideIn" 的动画。
2. **比较动画属性:** 如果存在，则比较新的 `animation_data` 中的属性和现有动画的属性，例如持续时间、播放状态等。
3. **更新或创建动画:**
    * 如果属性发生了变化，并且不是因为 Javascript 通过 Web Animations API 直接控制 (通过 `!animation->GetIgnoreCSSPlayState()`)，则更新现有动画的属性。 例如，如果 `animation-play-state` 从 "paused" 变为 "running"，则会调用 `update.ToggleAnimationIndexPaused()` 来恢复动画。
    * 如果不存在同名动画，则创建一个新的 `CSSAnimation` 对象，并将其添加到正在运行的动画集合中。
4. **处理动画取消:** 如果旧的动画存在，但在新的 `animation_data` 中不存在，则将其标记为取消。

**可能的输出:**

* `update`:  一个 `CSSAnimationUpdate` 对象，包含了需要执行的动画更新操作，例如启动新的动画 (`update.StartAnimation`)，更新现有动画 (`update.UpdateAnimation`)，或者取消动画 (`update.CancelAnimation`)。
* `css_animations`:  元素的正在运行的 CSS 动画集合会被更新，添加新的动画或移除已取消的动画。

**用户或编程常见的使用错误:**

1. **动画名称拼写错误:** 用户在 CSS 中定义的 `@keyframes` 名称与 `animation-name` 属性值不一致，会导致动画无法生效。
   * **例子:** CSS 中定义了 `@keyframes fade-in { ... }`，但在元素样式中使用了 `animation-name: fadeIn;` (大小写不一致或拼写错误)。

2. **动画属性值无效:**  提供了无效的动画属性值，例如负数的 `animation-duration`。浏览器通常会忽略这些无效值。

3. **Javascript 控制与 CSS 控制冲突:**  使用 Javascript 的 Web Animations API 直接控制动画 (例如使用 `animation.play()` 或 `animation.pause()`) 后，又试图通过 CSS 的 `animation-play-state` 来控制，可能会导致状态不一致，因为代码中会检查 `!animation->GetIgnoreCSSPlayState()` 来避免 CSS 样式覆盖 Javascript 的控制。
   * **例子:**  Javascript 调用了 `animation.pause()` 来暂停动画，但 CSS 中 `animation-play-state` 仍然是 `running`， 这段 C++ 代码会尝试调和这两种状态。

4. **过渡与动画同时影响同一属性:**  如果一个属性同时被 CSS 过渡和 CSS 动画影响，可能会导致动画效果混乱或其中一个效果被覆盖。代码中 `CanCalculateTransitionUpdateForProperty` 方法会检查是否存在动画影响，从而避免过渡的启动。

**总结一下它的功能 (针对提供的代码片段):**

这段代码片段主要负责 **更新元素的 CSS 动画状态**。它接收新的动画数据，并与当前正在运行的动画进行比较。根据比较结果，它会决定启动新的动画、更新现有动画的属性（如播放状态、时间轴等）或者取消不再需要的动画。  它还考虑了 Web Animations API 的影响，以及如何与 CSS 过渡协同工作。 `MaybeApplyPendingUpdate` 方法则负责将这些更新操作实际应用到动画对象上。

Prompt: 
```
这是目录为blink/renderer/core/animation/css/css_animations.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能

"""
tion_data &&
      (style_builder.Display() != EDisplay::kNone ||
       (old_style && old_style->Display() != EDisplay::kNone))) {
    const Vector<AtomicString>& name_list = animation_data->NameList();
    for (wtf_size_t i = 0; i < name_list.size(); ++i) {
      AtomicString name = name_list[i];
      if (name == CSSAnimationData::InitialName())
        continue;

      // Find n where this is the nth occurrence of this animation name.
      wtf_size_t name_index = 0;
      for (wtf_size_t j = 0; j < i; j++) {
        if (name_list[j] == name)
          name_index++;
      }

      const bool is_paused =
          CSSTimingData::GetRepeated(animation_data->PlayStateList(), i) ==
          EAnimPlayState::kPaused;

      Timing timing = animation_data->ConvertToTiming(i);
      // We need to copy timing to a second object for cases where the original
      // is modified and we still need original values.
      Timing specified_timing = timing;
      scoped_refptr<TimingFunction> keyframe_timing_function =
          timing.timing_function;
      timing.timing_function = Timing().timing_function;

      StyleRuleKeyframes* keyframes_rule =
          resolver->FindKeyframesRule(&element, &animating_element, name).rule;
      if (!keyframes_rule)
        continue;  // Cancel the animation if there's no style rule for it.

      const StyleTimeline& style_timeline = animation_data->GetTimeline(i);

      const std::optional<TimelineOffset>& range_start =
          animation_data->GetRepeated(animation_data->RangeStartList(), i);
      const std::optional<TimelineOffset>& range_end =
          animation_data->GetRepeated(animation_data->RangeEndList(), i);
      const EffectModel::CompositeOperation composite =
          animation_data->GetComposition(i);

      const RunningAnimation* existing_animation = nullptr;
      wtf_size_t existing_animation_index = 0;

      if (css_animations) {
        for (wtf_size_t j = 0; j < css_animations->running_animations_.size();
             j++) {
          const RunningAnimation& running_animation =
              *css_animations->running_animations_[j];
          if (running_animation.name == name &&
              running_animation.name_index == name_index) {
            existing_animation = &running_animation;
            existing_animation_index = j;
            break;
          }
        }
      }

      if (existing_animation) {
        cancel_running_animation_flags[existing_animation_index] = false;
        CSSAnimation* animation =
            DynamicTo<CSSAnimation>(existing_animation->animation.Get());
        animation->SetAnimationIndex(i);
        const bool was_paused =
            CSSTimingData::GetRepeated(existing_animation->play_state_list,
                                       i) == EAnimPlayState::kPaused;

        // Explicit calls to web-animation play controls override changes to
        // play state via the animation-play-state style. Ensure that the new
        // play state based on animation-play-state differs from the current
        // play state and that the change is not blocked by a sticky state.
        bool toggle_pause_state = false;
        bool will_be_playing = false;
        const V8AnimationPlayState::Enum play_state =
            animation->CalculateAnimationPlayState();
        if (is_paused != was_paused && !animation->GetIgnoreCSSPlayState()) {
          switch (play_state) {
            case V8AnimationPlayState::Enum::kIdle:
              break;

            case V8AnimationPlayState::Enum::kPaused:
              toggle_pause_state = !is_paused;
              will_be_playing = !is_paused;
              break;

            case V8AnimationPlayState::Enum::kRunning:
            case V8AnimationPlayState::Enum::kFinished:
              toggle_pause_state = is_paused;
              will_be_playing = !is_paused;
              break;

            default:
              // kUnset and kPending.
              NOTREACHED();
          }
        } else if (!animation->GetIgnoreCSSPlayState()) {
          will_be_playing =
              !is_paused && play_state != V8AnimationPlayState::Enum::kIdle;
        } else {
          will_be_playing =
              (play_state == V8AnimationPlayState::Enum::kRunning) ||
              (play_state == V8AnimationPlayState::Enum::kFinished);
        }

        AnimationTimeline* timeline = existing_animation->Timeline();
        if (!is_animation_style_change && !animation->GetIgnoreCSSTimeline()) {
          timeline = ComputeTimeline(&animating_element, style_timeline, update,
                                     existing_animation->Timeline());
        }

        bool range_changed =
            ((range_start != existing_animation->RangeStart()) &&
             !animation->GetIgnoreCSSRangeStart()) ||
            ((range_end != existing_animation->RangeEnd()) &&
             !animation->GetIgnoreCSSRangeEnd());

        if (keyframes_rule != existing_animation->style_rule ||
            keyframes_rule->Version() !=
                existing_animation->style_rule_version ||
            existing_animation->specified_timing != specified_timing ||
            is_paused != was_paused || logical_property_mapping_change ||
            timeline != existing_animation->Timeline() || range_changed) {
          DCHECK(!is_animation_style_change);

          CSSAnimationProxy animation_proxy(timeline, animation,
                                            !will_be_playing, range_start,
                                            range_end, timing);
          update.UpdateAnimation(
              existing_animation_index, animation,
              *MakeGarbageCollected<InertEffect>(
                  CreateKeyframeEffectModel(
                      resolver, element, animating_element, writing_direction,
                      parent_style, name, keyframe_timing_function.get(),
                      composite, i),
                  timing, animation_proxy),
              specified_timing, keyframes_rule, timeline,
              animation_data->PlayStateList(), range_start, range_end);
          if (toggle_pause_state)
            update.ToggleAnimationIndexPaused(existing_animation_index);
        }
      } else {
        DCHECK(!is_animation_style_change);
        AnimationTimeline* timeline =
            ComputeTimeline(&animating_element, style_timeline, update,
                            /* existing_timeline */ nullptr);

        CSSAnimationProxy animation_proxy(timeline, /* animation */ nullptr,
                                          is_paused, range_start, range_end,
                                          timing);
        update.StartAnimation(
            name, name_index, i,
            *MakeGarbageCollected<InertEffect>(
                CreateKeyframeEffectModel(resolver, element, animating_element,
                                          writing_direction, parent_style, name,
                                          keyframe_timing_function.get(),
                                          composite, i),
                timing, animation_proxy),
            specified_timing, keyframes_rule, timeline,
            animation_data->PlayStateList(), range_start, range_end);
      }
    }
  }

  for (wtf_size_t i = 0; i < cancel_running_animation_flags.size(); i++) {
    if (cancel_running_animation_flags[i]) {
      DCHECK(css_animations && !is_animation_style_change);
      update.CancelAnimation(
          i, *css_animations->running_animations_[i]->animation);
    }
  }

  CalculateAnimationActiveInterpolations(update, animating_element);
}

AnimationEffect::EventDelegate* CSSAnimations::CreateEventDelegate(
    Element* element,
    const PropertyHandle& property_handle,
    const AnimationEffect::EventDelegate* old_event_delegate) {
  const CSSAnimations::TransitionEventDelegate* old_transition_delegate =
      DynamicTo<CSSAnimations::TransitionEventDelegate>(old_event_delegate);
  Timing::Phase previous_phase =
      old_transition_delegate ? old_transition_delegate->getPreviousPhase()
                              : Timing::kPhaseNone;
  return MakeGarbageCollected<TransitionEventDelegate>(element, property_handle,
                                                       previous_phase);
}

AnimationEffect::EventDelegate* CSSAnimations::CreateEventDelegate(
    Element* element,
    const AtomicString& animation_name,
    const AnimationEffect::EventDelegate* old_event_delegate) {
  const CSSAnimations::AnimationEventDelegate* old_animation_delegate =
      DynamicTo<CSSAnimations::AnimationEventDelegate>(old_event_delegate);
  Timing::Phase previous_phase =
      old_animation_delegate ? old_animation_delegate->getPreviousPhase()
                             : Timing::kPhaseNone;
  std::optional<double> previous_iteration =
      old_animation_delegate ? old_animation_delegate->getPreviousIteration()
                             : std::nullopt;
  return MakeGarbageCollected<AnimationEventDelegate>(
      element, animation_name, previous_phase, previous_iteration);
}

void CSSAnimations::SnapshotCompositorKeyframes(
    Element& element,
    CSSAnimationUpdate& update,
    const ComputedStyle& style,
    const ComputedStyle* parent_style) {
  const auto& snapshot = [&element, &style,
                          parent_style](const AnimationEffect* effect) {
    const KeyframeEffectModelBase* keyframe_effect =
        GetKeyframeEffectModelBase(effect);
    if (keyframe_effect) {
      keyframe_effect->SnapshotAllCompositorKeyframesIfNecessary(element, style,
                                                                 parent_style);
    }
  };

  ElementAnimations* element_animations = element.GetElementAnimations();
  if (element_animations) {
    for (auto& entry : element_animations->Animations())
      snapshot(entry.key->effect());
  }

  for (const auto& new_animation : update.NewAnimations())
    snapshot(new_animation.effect.Get());

  for (const auto& updated_animation : update.AnimationsWithUpdates())
    snapshot(updated_animation.effect.Get());

  for (const auto& new_transition : update.NewTransitions())
    snapshot(new_transition.value->effect.Get());
}

namespace {

bool AffectsBackgroundColor(const AnimationEffect& effect) {
  return effect.Affects(PropertyHandle(GetCSSPropertyBackgroundColor()));
}

void UpdateAnimationFlagsForEffect(const AnimationEffect& effect,
                                   ComputedStyleBuilder& builder) {
  if (effect.Affects(PropertyHandle(GetCSSPropertyOpacity())))
    builder.SetHasCurrentOpacityAnimation(true);
  if (effect.Affects(PropertyHandle(GetCSSPropertyTransform())))
    builder.SetHasCurrentTransformAnimation(true);
  if (effect.Affects(PropertyHandle(GetCSSPropertyRotate())))
    builder.SetHasCurrentRotateAnimation(true);
  if (effect.Affects(PropertyHandle(GetCSSPropertyScale())))
    builder.SetHasCurrentScaleAnimation(true);
  if (effect.Affects(PropertyHandle(GetCSSPropertyTranslate())))
    builder.SetHasCurrentTranslateAnimation(true);
  if (effect.Affects(PropertyHandle(GetCSSPropertyFilter())))
    builder.SetHasCurrentFilterAnimation(true);
  if (effect.Affects(PropertyHandle(GetCSSPropertyBackdropFilter())))
    builder.SetHasCurrentBackdropFilterAnimation(true);
  if (AffectsBackgroundColor(effect))
    builder.SetHasCurrentBackgroundColorAnimation(true);
}

// Called for animations that are newly created or updated.
void UpdateAnimationFlagsForInertEffect(const InertEffect& effect,
                                        ComputedStyleBuilder& builder) {
  if (!effect.IsCurrent())
    return;

  UpdateAnimationFlagsForEffect(effect, builder);
}

// Called for existing animations that are not modified in this update.
void UpdateAnimationFlagsForAnimation(const Animation& animation,
                                      ComputedStyleBuilder& builder) {
  const AnimationEffect& effect = *animation.effect();

  if (!effect.IsCurrent() && !effect.IsInEffect()) {
    return;
  }

  UpdateAnimationFlagsForEffect(effect, builder);
}

}  // namespace

void CSSAnimations::UpdateAnimationFlags(Element& animating_element,
                                         CSSAnimationUpdate& update,
                                         ComputedStyleBuilder& builder) {
  for (const auto& new_animation : update.NewAnimations())
    UpdateAnimationFlagsForInertEffect(*new_animation.effect, builder);

  for (const auto& updated_animation : update.AnimationsWithUpdates())
    UpdateAnimationFlagsForInertEffect(*updated_animation.effect, builder);

  for (const auto& entry : update.NewTransitions())
    UpdateAnimationFlagsForInertEffect(*entry.value->effect, builder);

  if (auto* element_animations = animating_element.GetElementAnimations()) {
    HeapHashSet<Member<const Animation>> cancelled_transitions =
        CreateCancelledTransitionsSet(element_animations, update);
    const HeapHashSet<Member<const Animation>>& suppressed_animations =
        update.SuppressedAnimations();

    auto is_suppressed = [&cancelled_transitions, &suppressed_animations](
                             const Animation& animation) -> bool {
      return suppressed_animations.Contains(&animation) ||
             cancelled_transitions.Contains(&animation);
    };

    for (auto& entry : element_animations->Animations()) {
      if (!is_suppressed(*entry.key))
        UpdateAnimationFlagsForAnimation(*entry.key, builder);
    }

    for (auto& entry : element_animations->GetWorkletAnimations()) {
      // TODO(majidvp): we should check the effect's phase before updating the
      // style once the timing of effect is ready to use.
      // https://crbug.com/814851.
      UpdateAnimationFlagsForEffect(*entry->GetEffect(), builder);
    }

    EffectStack& effect_stack = element_animations->GetEffectStack();

    if (builder.HasCurrentOpacityAnimation()) {
      builder.SetIsRunningOpacityAnimationOnCompositor(
          effect_stack.HasActiveAnimationsOnCompositor(
              PropertyHandle(GetCSSPropertyOpacity())));
    }
    if (builder.HasCurrentTransformAnimation()) {
      builder.SetIsRunningTransformAnimationOnCompositor(
          effect_stack.HasActiveAnimationsOnCompositor(
              PropertyHandle(GetCSSPropertyTransform())));
    }
    if (builder.HasCurrentScaleAnimation()) {
      builder.SetIsRunningScaleAnimationOnCompositor(
          effect_stack.HasActiveAnimationsOnCompositor(
              PropertyHandle(GetCSSPropertyScale())));
    }
    if (builder.HasCurrentRotateAnimation()) {
      builder.SetIsRunningRotateAnimationOnCompositor(
          effect_stack.HasActiveAnimationsOnCompositor(
              PropertyHandle(GetCSSPropertyRotate())));
    }
    if (builder.HasCurrentTranslateAnimation()) {
      builder.SetIsRunningTranslateAnimationOnCompositor(
          effect_stack.HasActiveAnimationsOnCompositor(
              PropertyHandle(GetCSSPropertyTranslate())));
    }
    if (builder.HasCurrentFilterAnimation()) {
      builder.SetIsRunningFilterAnimationOnCompositor(
          effect_stack.HasActiveAnimationsOnCompositor(
              PropertyHandle(GetCSSPropertyFilter())));
    }
    if (builder.HasCurrentBackdropFilterAnimation()) {
      builder.SetIsRunningBackdropFilterAnimationOnCompositor(
          effect_stack.HasActiveAnimationsOnCompositor(
              PropertyHandle(GetCSSPropertyBackdropFilter())));
    }
  }
}

void CSSAnimations::MaybeApplyPendingUpdate(Element* element) {
  previous_active_interpolations_for_animations_.clear();
  if (pending_update_.IsEmpty()) {
    return;
  }

  previous_active_interpolations_for_animations_.swap(
      pending_update_.ActiveInterpolationsForAnimations());

  if (!pending_update_.HasUpdates()) {
    ClearPendingUpdate();
    return;
  }

  for (auto [name, value] : pending_update_.ChangedScrollTimelines()) {
    timeline_data_.SetScrollTimeline(*name, value.Get());
  }
  for (auto [name, value] : pending_update_.ChangedViewTimelines()) {
    timeline_data_.SetViewTimeline(*name, value.Get());
  }
  for (auto [name, value] : pending_update_.ChangedDeferredTimelines()) {
    timeline_data_.SetDeferredTimeline(*name, value.Get());
  }
  for (auto [attaching_timeline, deferred_timeline] :
       pending_update_.ChangedTimelineAttachments()) {
    if (DeferredTimeline* existing_deferred_timeline =
            timeline_data_.GetTimelineAttachment(attaching_timeline)) {
      existing_deferred_timeline->DetachTimeline(attaching_timeline);
    }
    if (deferred_timeline) {
      deferred_timeline->AttachTimeline(attaching_timeline);
    }
    timeline_data_.SetTimelineAttachment(attaching_timeline, deferred_timeline);
  }

  for (wtf_size_t paused_index :
       pending_update_.AnimationIndicesWithPauseToggled()) {
    CSSAnimation* animation = DynamicTo<CSSAnimation>(
        running_animations_[paused_index]->animation.Get());

    if (animation->Paused()) {
      animation->Unpause();
      animation->ResetIgnoreCSSPlayState();
    } else {
      animation->pause();
      animation->ResetIgnoreCSSPlayState();
    }
    if (animation->Outdated())
      animation->Update(kTimingUpdateOnDemand);
  }

  for (const auto& animation : pending_update_.UpdatedCompositorKeyframes()) {
    animation->SetCompositorPending(
        Animation::CompositorPendingReason::kPendingEffectChange);
  }

  for (const auto& entry : pending_update_.AnimationsWithUpdates()) {
    if (entry.animation->effect()) {
      auto* effect = To<KeyframeEffect>(entry.animation->effect());
      if (!effect->GetIgnoreCSSKeyframes())
        effect->SetModel(entry.effect->Model());
      effect->UpdateSpecifiedTiming(entry.effect->SpecifiedTiming());
    }
    CSSAnimation& css_animation = To<CSSAnimation>(*entry.animation);
    if (css_animation.TimelineInternal() != entry.timeline) {
      css_animation.setTimeline(entry.timeline);
      css_animation.ResetIgnoreCSSTimeline();
    }
    css_animation.SetRange(entry.range_start, entry.range_end);
    running_animations_[entry.index]->Update(entry);
    entry.animation->Update(kTimingUpdateOnDemand);
  }

  const Vector<wtf_size_t>& cancelled_indices =
      pending_update_.CancelledAnimationIndices();
  for (wtf_size_t i = cancelled_indices.size(); i-- > 0;) {
    DCHECK(i == cancelled_indices.size() - 1 ||
           cancelled_indices[i] < cancelled_indices[i + 1]);
    Animation& animation =
        *running_animations_[cancelled_indices[i]]->animation;
    animation.ClearOwningElement();
    if (animation.IsCSSAnimation() &&
        !DynamicTo<CSSAnimation>(animation)->GetIgnoreCSSPlayState()) {
      animation.cancel();
    }
    animation.Update(kTimingUpdateOnDemand);
    running_animations_.EraseAt(cancelled_indices[i]);
  }

  for (const auto& entry : pending_update_.NewAnimations()) {
    const InertEffect* inert_animation = entry.effect.Get();
    AnimationEventDelegate* event_delegate =
        MakeGarbageCollected<AnimationEventDelegate>(element, entry.name);
    auto* effect = MakeGarbageCollected<KeyframeEffect>(
        element, inert_animation->Model(), inert_animation->SpecifiedTiming(),
        KeyframeEffect::kDefaultPriority, event_delegate);
    auto* animation = MakeGarbageCollected<CSSAnimation>(
        element->GetExecutionContext(), entry.timeline, effect,
        entry.position_index, entry.name);
    animation->play();
    if (inert_animation->Paused())
      animation->pause();
    animation->ResetIgnoreCSSPlayState();
    animation->SetRange(entry.range_start, entry.range_end);
    animation->ResetIgnoreCSSRangeStart();
    animation->ResetIgnoreCSSRangeEnd();
    animation->Update(kTimingUpdateOnDemand);

    running_animations_.push_back(
        MakeGarbageCollected<RunningAnimation>(animation, entry));
  }

  // Track retargeted transitions that are running on the compositor in order
  // to update their start times.
  HashSet<PropertyHandle> retargeted_compositor_transitions;
  for (const PropertyHandle& property :
       pending_update_.CancelledTransitions()) {
    DCHECK(transitions_.Contains(property));

    Animation* animation = transitions_.Take(property)->animation;
    auto* effect = To<KeyframeEffect>(animation->effect());
    if (effect && effect->HasActiveAnimationsOnCompositor(property) &&
        base::Contains(pending_update_.NewTransitions(), property) &&
        !animation->Limited()) {
      retargeted_compositor_transitions.insert(property);
    }
    animation->ClearOwningElement();
    animation->cancel();
    // After cancellation, transitions must be downgraded or they'll fail
    // to be considered when retriggering themselves. This can happen if
    // the transition is captured through getAnimations then played.
    effect = DynamicTo<KeyframeEffect>(animation->effect());
    if (effect)
      effect->DowngradeToNormal();
    animation->Update(kTimingUpdateOnDemand);
  }

  for (const PropertyHandle& property : pending_update_.FinishedTransitions()) {
    // This transition can also be cancelled and finished at the same time
    if (transitions_.Contains(property)) {
      Animation* animation = transitions_.Take(property)->animation;
      // Transition must be downgraded
      if (auto* effect = DynamicTo<KeyframeEffect>(animation->effect()))
        effect->DowngradeToNormal();
    }
  }

  HashSet<PropertyHandle> suppressed_transitions;

  if (!pending_update_.NewTransitions().empty()) {
    element->GetDocument()
        .GetDocumentAnimations()
        .IncrementTrasitionGeneration();
  }

  for (const auto& entry : pending_update_.NewTransitions()) {
    const CSSAnimationUpdate::NewTransition* new_transition = entry.value;
    const PropertyHandle& property = new_transition->property;

    if (suppressed_transitions.Contains(property))
      continue;

    const InertEffect* inert_animation = new_transition->effect.Get();
    TransitionEventDelegate* event_delegate =
        MakeGarbageCollected<TransitionEventDelegate>(element, property);

    KeyframeEffectModelBase* model = inert_animation->Model();

    auto* transition_effect = MakeGarbageCollected<KeyframeEffect>(
        element, model, inert_animation->SpecifiedTiming(),
        KeyframeEffect::kTransitionPriority, event_delegate);
    auto* animation = MakeGarbageCollected<CSSTransition>(
        element->GetExecutionContext(), &(element->GetDocument().Timeline()),
        transition_effect,
        element->GetDocument().GetDocumentAnimations().TransitionGeneration(),
        property);

    animation->play();

    // Set the current time as the start time for retargeted transitions
    if (retargeted_compositor_transitions.Contains(property)) {
      animation->setStartTime(element->GetDocument().Timeline().currentTime(),
                              ASSERT_NO_EXCEPTION);
    }
    animation->Update(kTimingUpdateOnDemand);

    RunningTransition* running_transition =
        MakeGarbageCollected<RunningTransition>(
            animation, new_transition->from, new_transition->to,
            new_transition->reversing_adjusted_start_value,
            new_transition->reversing_shortening_factor);
    transitions_.Set(property, running_transition);
  }
  ClearPendingUpdate();
}

HeapHashSet<Member<const Animation>>
CSSAnimations::CreateCancelledTransitionsSet(
    ElementAnimations* element_animations,
    CSSAnimationUpdate& update) {
  HeapHashSet<Member<const Animation>> cancelled_transitions;
  if (!update.CancelledTransitions().empty()) {
    DCHECK(element_animations);
    const TransitionMap& transition_map =
        element_animations->CssAnimations().transitions_;
    for (const PropertyHandle& property : update.CancelledTransitions()) {
      DCHECK(transition_map.Contains(property));
      cancelled_transitions.insert(
          transition_map.at(property)->animation.Get());
    }
  }
  return cancelled_transitions;
}

bool CSSAnimations::CanCalculateTransitionUpdateForProperty(
    TransitionUpdateState& state,
    const PropertyHandle& property) {
  // TODO(crbug.com/1226772): We should transition if an !important property
  // changes even when an animation is running.
  if (state.update.ActiveInterpolationsForAnimations().Contains(property) ||
      (state.animating_element.GetElementAnimations() &&
       state.animating_element.GetElementAnimations()
           ->CssAnimations()
           .previous_active_interpolations_for_animations_.Contains(
               property))) {
    UseCounter::Count(state.animating_element.GetDocument(),
                      WebFeature::kCSSTransitionBlockedByAnimation);
    return false;
  }
  return true;
}

void CSSAnimations::CalculateTransitionUpdateForPropertyHandle(
    TransitionUpdateState& state,
    const CSSTransitionData::TransitionAnimationType type,
    const PropertyHandle& property,
    wtf_size_t transition_index,
    bool animate_all) {
  if (state.listed_properties) {
    state.listed_properties->insert(property);
  }

  if (!CanCalculateTransitionUpdateForProperty(state, property))
    return;

  bool is_animation_affecting = false;
  if (!animate_all || type != CSSTransitionData::kTransitionKnownProperty) {
    is_animation_affecting =
        IsAnimationAffectingProperty(property.GetCSSProperty());
  } else {
    // For transition:all, the standard properties (kTransitionKnownProperty)
    // to calculate update is filtered by PropertiesForTransitionAll(), which
    // will have a check on IsAnimationAffectingProperty(). All the filtered
    // properties stored in the static |properties| will return false on such
    // check. So we can bypass this check here to reduce the repeated overhead
    // for standard properties update of transition:all.
    DCHECK_EQ(false, IsAnimationAffectingProperty(property.GetCSSProperty()));
  }
  if (is_animation_affecting) {
    return;
  }

  const RunningTransition* interrupted_transition = nullptr;
  if (state.active_transitions) {
    TransitionMap::const_iterator active_transition_iter =
        state.active_transitions->find(property);
    if (active_transition_iter != state.active_transitions->end()) {
      const RunningTransition* running_transition =
          active_transition_iter->value;
      if (ComputedValuesEqual(property, state.base_style,
                              *running_transition->to)) {
        if (!state.transition_data) {
          if (!running_transition->animation->FinishedInternal()) {
            UseCounter::Count(
                state.animating_element.GetDocument(),
                WebFeature::kCSSTransitionCancelledByRemovingStyle);
          }
          // TODO(crbug.com/934700): Add a return to this branch to correctly
          // continue transitions under default settings (all 0s) in the absence
          // of a change in base computed style.
        } else {
          return;
        }
      }
      state.update.CancelTransition(property);
      DCHECK(!state.animating_element.GetElementAnimations() ||
             !state.animating_element.GetElementAnimations()
                  ->IsAnimationStyleChange());

      if (ComputedValuesEqual(
              property, state.base_style,
              *running_transition->reversing_adjusted_start_value)) {
        interrupted_transition = running_transition;
      }
    }
  }

  // In the default configuration (transition: all 0s) we continue and cancel
  // transitions but do not start them.
  if (!state.transition_data)
    return;

  const PropertyRegistry* registry =
      state.animating_element.GetDocument().GetPropertyRegistry();
  if (property.IsCSSCustomProperty()) {
    if (!registry || !registry->Registration(property.CustomPropertyName())) {
      return;
    }
  }

  // Lazy evaluation of the before change style. We only need to update where
  // we are transitioning from if the final destination is changing.
  if (!state.before_change_style) {
    // By calling GetBaseComputedStyleOrThis, we're using the style from the
    // previous frame if no base style is found. Elements that have not been
    // animated will not have a base style. Elements that were previously
    // animated, but where all previously running animations have stopped may
    // also be missing a base style. In both cases, the old style is equivalent
    // to the base computed style.
    state.before_change_style = CalculateBeforeChangeStyle(
        state.animating_element, *state.old_style.GetBaseComputedStyleOrThis());
  }

  if (ComputedValuesEqual(property, *state.before_change_style,
                          state.base_style)) {
    return;
  }

  CSSInterpolationTypesMap map(registry, state.animating_element.GetDocument());
  CSSInterpolationEnvironment old_environment(map, *state.before_change_style,
                                              state.base_style);
  CSSInterpolationEnvironment new_environment(map, state.base_style,
                                              state.base_style);
  const InterpolationType* transition_type = nullptr;
  InterpolationValue start = nullptr;
  InterpolationValue end = nullptr;
  bool discrete_interpolation = true;

  for (const auto& interpolation_type : map.Get(property)) {
    start = interpolation_type->MaybeConvertUnderlyingValue(old_environment);
    transition_type = interpolation_type.get();
    if (!start) {
      continue;
    }
    end = interpolation_type->MaybeConvertUnderlyingValue(new_environment);
    if (!end) {
      continue;
    }

    // If MaybeMergeSingles succeeds, then the two values have a defined
    // interpolation behavior. However, some properties like display and
    // content-visibility have an interpolation which behaves like a discrete
    // interpolation, so we use IsDiscrete to determine whether it should
    // transition by default.
    if (interpolation_type->MaybeMergeSingles(start.Clone(), end.Clone())) {
      if (!interpolation_type->IsDiscrete()) {
        discrete_interpolation = false;
      }
      break;
    }
  }

  auto behavior = CSSTimingData::GetRepeated(
      state.transition_data->BehaviorList(), transition_index);

  // If no smooth interpolation exists between the old and new values and
  // transition-behavior didn't indicate that we should do a discrete
  // transition, then don't start a transition.
  if (discrete_interpolation &&
      behavior != CSSTransitionData::TransitionBehavior::kAllowDiscrete) {
    state.update.UnstartTransition(property);
    return;
  }

  if (!start || !end) {
    const Document& document = state.animating_element.GetDocument();
    const CSSValue* start_css_value =
        AnimationUtils::KeyframeValueFromComputedStyle(
            property, state.old_style, document,
            state.animating_element.GetLayoutObject());
    const CSSValue* end_css_value =
        AnimationUtils::KeyframeValueFromComputedStyle(
            property, state.base_style, document,
            state.animating_element.GetLayoutObject());
    if (!start_css_value || !end_css_value) {
      // TODO(crbug.com/1425925): Handle newly registered custom properties
      // correctly. If that bug is fixed, then this should never happen.
      return;
    }
    start = InterpolationValue(
        MakeGarbageCollected<InterpolableList>(0),
        CSSDefaultNonInterpolableValue::Create(start_css_value));
    end = InterpolationValue(
        MakeGarbageCollected<InterpolableList>(0),
        CSSDefaultNonInterpolableValue::Create(end_css_value));
  }
  // If we have multiple transitions on the same property, we will use the
  // last one since we iterate over them in order.

  Timing timing = state.transition_data->ConvertToTiming(transition_index);
  // CSS Transitions always have a valid duration (i.e. the value 'auto' is not
  // supported), so iteration_duration will always be set.
  if (timing.start_delay.AsTimeValue() + timing.iteration_duration.value() <=
      AnimationTimeDelta()) {
    // We may have started a transition in a prior CSSTransitionData update,
    // this CSSTransitionData update needs to override them.
    // TODO(alancutter): Just iterate over the CSSTransitionDatas in reverse and
    // skip any properties that have already been visited so we don't need to
    // "undo" work like this.
    state.update.UnstartTransition(property);
    return;
  }

  const ComputedStyle* reversing_adjusted_start_value =
      state.before_change_style;
  double reversing_shortening_factor = 1;
  if (interrupted_transition) {
    AnimationEffect* effect = interrupted_transition->animation->effect();
    const std::optional<double> interrupted_progress =
        effect ? effect->Progress() : std::nullopt;
    if (interrupted_progress) {
      reversing_adjusted_start_value = interrupted_transition->to;
      reversing_shortening_factor =
          ClampTo((
"""


```