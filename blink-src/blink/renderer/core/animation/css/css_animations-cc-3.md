Response:
The user wants a summary of the functionality of the provided C++ code snippet from the Chromium Blink engine. I need to analyze the code and identify its purpose, its relationship to web technologies like JavaScript, HTML, and CSS, and provide examples and potential user errors.

**Functionality Breakdown:**

1. **Transition Calculations:** The code focuses on calculating and applying CSS transitions. This involves determining how property values change smoothly over time.
2. **`CalculateTransitionUpdateForPropertyHandle`:** This function seems to be the core of transition processing for a single property. It handles different scenarios, including interrupted transitions and creating keyframes.
3. **`CalculateTransitionUpdateForCustomProperty` and `CalculateTransitionUpdateForStandardProperty`:** These functions specialize the transition update for custom CSS properties and standard CSS properties, respectively.
4. **`CalculateTransitionUpdate`:** This function iterates through the transitions defined for an element and calls the appropriate update functions for each property.
5. **`CalculateBeforeChangeStyle`:** This function determines the style of an element *before* a transition begins, taking into account existing animations. This is crucial for creating smooth transitions from the previous state.
6. **Active Interpolations:** The code deals with "active interpolations," which represent the current values of animated properties. It calculates and manages these interpolations for both CSS animations and transitions.
7. **Event Handling:** The code includes classes (`AnimationEventDelegate`, `TransitionEventDelegate`) for dispatching animation and transition events (e.g., `animationstart`, `transitionend`).
8. **Property Handling:** The code uses `PropertyHandle` to represent CSS properties, including custom properties.
9. **Animation Management:** It interacts with the `ElementAnimations` object to manage the animations and transitions associated with an element.
10. **Timeline Management:** The code includes a `TimelineData` class to manage animation timelines, including scroll and view timelines.
11. **Utility Functions:** There are helper functions like `PropertiesForTransitionAll` and checks for animation-affecting properties.

**Relationships to Web Technologies:**

*   **CSS:** This code directly implements CSS transitions. It reads transition properties from stylesheets and calculates the intermediate values during the transition.
*   **JavaScript:** JavaScript can trigger transitions by modifying CSS properties. The events dispatched by this code (`transitionstart`, `transitionend`, etc.) can be listened to in JavaScript.
*   **HTML:** The transitions are applied to HTML elements. The structure of the HTML document influences which elements are animated.

**Hypothetical Input and Output:**

*   **Input:** An HTML element with a CSS rule like `transition: opacity 1s;`. The JavaScript modifies the `opacity` style.
*   **Output:** The code calculates the intermediate opacity values over 1 second, creating a smooth fade-in or fade-out effect. Transition events would be dispatched.

**Common User Errors:**

*   **Not defining transition properties:** If the CSS doesn't include a `transition` property, no transition will occur, even if the property value changes.
*   **Incorrect property names:**  Typos in the `transition-property` will prevent the transition from working.
*   **Conflicting transitions:** Applying multiple transitions to the same property can lead to unexpected behavior.
*   **Transitioning non-animatable properties:** Some CSS properties cannot be animated. Trying to transition them will have no effect.

**Code Structure (Part 4 Focus):**

This part of the code primarily focuses on:

*   **Calculating transition updates for different property types (standard and custom).**
*   **Handling the 'transition: all' case.**
*   **Managing the lifecycle of transitions, including starting, updating, canceling, and finishing them.**
*   **Determining the `before_change_style` by sampling active animations.**

**Summary of Functionality (Part 4):**

This section of `css_animations.cc` is responsible for calculating the necessary updates to initiate and manage CSS transitions on an element. It determines the starting and ending states of the transition, creates the animation model, and handles the case where 'transition: all' is specified. It also figures out the style of the element before the transition begins by considering any currently running animations, which is crucial for smooth transitions.

这是 `blink/renderer/core/animation/css/css_animations.cc` 文件的第 4 部分，主要功能是 **计算和管理 CSS 过渡 (transitions)**。 它负责处理当元素的 CSS 属性发生变化时，如何平滑地过渡到新的值。

以下是更详细的功能说明以及与 JavaScript, HTML, CSS 的关系：

**主要功能:**

1. **`CalculateTransitionUpdateForProperty`， `CalculateTransitionUpdateForCustomProperty`， `CalculateTransitionUpdateForStandardProperty`:**  这些函数负责为特定的 CSS 属性计算过渡更新。
    *   `CalculateTransitionUpdateForProperty` 是一个入口点，根据属性类型（自定义或标准）调用相应的处理函数。
    *   `CalculateTransitionUpdateForCustomProperty` 处理 CSS 自定义属性（CSS 变量）的过渡。
    *   `CalculateTransitionUpdateForStandardProperty` 处理标准的 CSS 属性的过渡，包括处理 `transition: all` 的情况，以及处理简写属性。它会展开简写属性，并为每个相关的长属性分别计算过渡。

2. **`CalculateTransitionUpdate`:**  这个函数是核心，它接收 `CSSAnimationUpdate` 对象、要进行动画的元素、样式构建器和旧的样式。它遍历元素上定义的过渡，并对每个需要过渡的属性调用 `CalculateTransitionUpdateForProperty`。它还会处理 `transition: all` 的情况，以及在没有定义 `transition` 属性但存在激活的过渡时的情况。

3. **`CalculateBeforeChangeStyle`:** 这个函数计算在过渡开始前的元素的样式。这非常重要，因为过渡是从当前样式值过渡到新的样式值。为了正确处理级联和继承，以及与其他动画的交互，需要确定过渡开始时的“起始”样式。它会考虑当前正在运行的动画效果，并基于这些效果对样式进行采样，以获得过渡开始时的准确样式。

4. **管理激活的插值 (Active Interpolations):**  代码中涉及到 `CalculateTransitionActiveInterpolations` 函数，虽然在这个代码片段中没有完整展示，但它负责计算在过渡期间哪些属性的值应该被插值，并如何插值。这会考虑其他可能影响同一属性的动画，以确保正确的渲染结果。

5. **事件处理:** 代码片段中定义了 `AnimationEventDelegate` 和 `TransitionEventDelegate` 类，用于处理动画和过渡相关的事件（例如 `transitionstart`, `transitionend`, `animationstart`, `animationend`）。这些类负责在合适的时机创建和分发这些事件。

**与 JavaScript, HTML, CSS 的关系:**

*   **CSS:**  这段代码的核心功能是实现 CSS 过渡。CSS 规则（例如 `transition: opacity 1s ease-in-out;`）定义了哪些属性可以过渡、过渡的时长和缓动函数。这段 C++ 代码负责解析这些 CSS 规则，并在属性值改变时执行过渡动画。
    *   **例子:**  在 CSS 中定义了 `transition: opacity 0.5s;`，当 JavaScript 修改元素的 `opacity` 样式时，这段 C++ 代码会启动一个持续 0.5 秒的透明度过渡动画。

*   **JavaScript:** JavaScript 通常用于触发 CSS 过渡。通过 JavaScript 修改元素的 CSS 属性（例如使用 `element.style.opacity = 0;`），如果该属性定义了过渡，Blink 引擎就会调用这段 C++ 代码来执行过渡。JavaScript 也可以监听过渡事件（`transitionstart`, `transitionend`, `transitioncancel`, `transitionrun`）来执行特定的操作。
    *   **假设输入:**  一个 HTML 元素 `<div>`，CSS 规则 `div { transition: left 1s; position: relative; }`，JavaScript 代码 `document.querySelector('div').style.left = '100px';`
    *   **输出:**  `<div>` 元素会从其初始的 `left` 值平滑地移动到 `100px`，耗时 1 秒。期间可能会触发 `transitionstart` 和 `transitionend` 事件。

*   **HTML:** HTML 定义了文档的结构和元素。CSS 过渡应用于 HTML 元素。
    *   **例子:**  HTML 中有一个 `<div id="box"></div>` 元素，CSS 中定义了 `#box { transition: width 0.3s; width: 100px; }`。当通过 JavaScript 或其他方式修改 `#box` 的 `width` 时，会触发宽度过渡动画。

**逻辑推理与假设输入/输出:**

*   **假设输入:**  一个元素的 `opacity` 从 `1` 变为 `0.5`，并且该元素定义了 `transition: opacity 0.2s linear;`。
*   **输出:**  `CalculateTransitionUpdateForPropertyHandle` 会创建一个从 `1` 到 `0.5` 的透明度动画，持续时间为 0.2 秒，使用线性缓动函数。在过渡期间，元素的实际 `opacity` 值会以线性的方式从 `1` 变化到 `0.5`。

**用户或编程常见的使用错误:**

*   **忘记定义 `transition` 属性:** 如果 CSS 中没有定义 `transition` 属性，即使属性值发生变化，也不会有过渡效果。
    *   **例子:**  CSS 中只有 `opacity: 0.5;`，没有 `transition: opacity 0.5s;`，那么当 JavaScript 修改 `opacity` 时，会立即生效，不会有平滑的过渡。
*   **`transition-property` 拼写错误:** 如果 `transition-property` 中指定的属性名拼写错误，则该属性的变化不会有过渡效果。
    *   **例子:**  CSS 中定义了 `transition: opcity 0.5s;` (拼写错误)，当修改 `opacity` 时，不会触发过渡。
*   **过渡非动画属性:**  有些 CSS 属性是不可动画的。尝试过渡这些属性不会有效果。
    *   **例子:**  尝试过渡 `overflow: hidden;` 或 `display: none;`（除非使用 `discrete` 过渡行为）。
*   **`transition: all` 的性能问题:**  使用 `transition: all` 会监听所有可过渡属性的变化，可能会影响性能，尤其是在有很多属性变化的情况下。

**归纳一下它的功能 (第 4 部分):**

这部分代码主要负责 **计算和启动 CSS 过渡动画**。它处理不同类型的 CSS 属性，包括标准属性和自定义属性。核心在于确定过渡的起始和结束状态，创建用于执行动画的模型，并处理 `transition: all` 这种特殊情况。此外，它还负责计算过渡开始前的元素样式，这对于确保平滑过渡至关重要，尤其是在存在其他动画影响的情况下。它为后续的动画执行和事件分发奠定了基础。

Prompt: 
```
这是目录为blink/renderer/core/animation/css/css_animations.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能

"""
interrupted_progress.value() *
                   interrupted_transition->reversing_shortening_factor) +
                      (1 - interrupted_transition->reversing_shortening_factor),
                  0.0, 1.0);
      timing.iteration_duration.value() *= reversing_shortening_factor;
      if (timing.start_delay.AsTimeValue() < AnimationTimeDelta()) {
        timing.start_delay.Scale(reversing_shortening_factor);
      }
    }
  }

  TransitionKeyframeVector keyframes;

  TransitionKeyframe* start_keyframe =
      MakeGarbageCollected<TransitionKeyframe>(property);
  start_keyframe->SetValue(MakeGarbageCollected<TypedInterpolationValue>(
      *transition_type, start.interpolable_value->Clone(),
      start.non_interpolable_value));
  start_keyframe->SetOffset(0);
  keyframes.push_back(start_keyframe);

  TransitionKeyframe* end_keyframe =
      MakeGarbageCollected<TransitionKeyframe>(property);
  end_keyframe->SetValue(MakeGarbageCollected<TypedInterpolationValue>(
      *transition_type, end.interpolable_value->Clone(),
      end.non_interpolable_value));
  end_keyframe->SetOffset(1);
  keyframes.push_back(end_keyframe);

  if (property.GetCSSProperty().IsCompositableProperty() &&
      CompositorAnimations::CompositedPropertyRequiresSnapshot(property)) {
    CompositorKeyframeValue* from = CompositorKeyframeValueFactory::Create(
        property, *state.before_change_style, start_keyframe->Offset().value());
    CompositorKeyframeValue* to = CompositorKeyframeValueFactory::Create(
        property, state.base_style, end_keyframe->Offset().value());
    start_keyframe->SetCompositorValue(from);
    end_keyframe->SetCompositorValue(to);
  }

  auto* model = MakeGarbageCollected<TransitionKeyframeEffectModel>(keyframes);
  state.update.StartTransition(
      property, state.before_change_style, &state.base_style,
      reversing_adjusted_start_value, reversing_shortening_factor,
      *MakeGarbageCollected<InertEffect>(
          model, timing, CSSTransitionProxy(AnimationTimeDelta())));
  DCHECK(!state.animating_element.GetElementAnimations() ||
         !state.animating_element.GetElementAnimations()
              ->IsAnimationStyleChange());
}

void CSSAnimations::CalculateTransitionUpdateForProperty(
    TransitionUpdateState& state,
    const CSSTransitionData::TransitionProperty& transition_property,
    wtf_size_t transition_index,
    WritingDirectionMode writing_direction) {
  switch (transition_property.property_type) {
    case CSSTransitionData::kTransitionUnknownProperty:
      CalculateTransitionUpdateForCustomProperty(state, transition_property,
                                                 transition_index);
      break;
    case CSSTransitionData::kTransitionKnownProperty:
      CalculateTransitionUpdateForStandardProperty(
          state, transition_property, transition_index, writing_direction);
      break;
    default:
      break;
  }
}

void CSSAnimations::CalculateTransitionUpdateForCustomProperty(
    TransitionUpdateState& state,
    const CSSTransitionData::TransitionProperty& transition_property,
    wtf_size_t transition_index) {
  DCHECK_EQ(transition_property.property_type,
            CSSTransitionData::kTransitionUnknownProperty);

  if (!CSSVariableParser::IsValidVariableName(
          transition_property.property_string)) {
    return;
  }

  CSSPropertyID resolved_id =
      ResolveCSSPropertyID(transition_property.unresolved_property);
  bool animate_all = resolved_id == CSSPropertyID::kAll;

  CalculateTransitionUpdateForPropertyHandle(
      state, transition_property.property_type,
      PropertyHandle(transition_property.property_string), transition_index,
      animate_all);
}

void CSSAnimations::CalculateTransitionUpdateForStandardProperty(
    TransitionUpdateState& state,
    const CSSTransitionData::TransitionProperty& transition_property,
    wtf_size_t transition_index,
    WritingDirectionMode writing_direction) {
  DCHECK_EQ(transition_property.property_type,
            CSSTransitionData::kTransitionKnownProperty);

  CSSPropertyID resolved_id =
      ResolveCSSPropertyID(transition_property.unresolved_property);
  bool animate_all = resolved_id == CSSPropertyID::kAll;
  bool with_discrete =
      state.transition_data &&
      CSSTimingData::GetRepeated(state.transition_data->BehaviorList(),
                                 transition_index) ==
          CSSTransitionData::TransitionBehavior::kAllowDiscrete;
  const StylePropertyShorthand& property_list =
      animate_all
          ? PropertiesForTransitionAll(
                with_discrete, state.animating_element.GetExecutionContext())
          : shorthandForProperty(resolved_id);
  // If not a shorthand we only execute one iteration of this loop, and
  // refer to the property directly.
  for (unsigned i = 0; !i || i < property_list.length(); ++i) {
    CSSPropertyID longhand_id =
        property_list.length() ? property_list.properties()[i]->PropertyID()
                               : resolved_id;
    DCHECK_GE(longhand_id, kFirstCSSProperty);
    const CSSProperty& property =
        CSSProperty::Get(longhand_id)
            .ResolveDirectionAwareProperty(writing_direction);
    PropertyHandle property_handle = PropertyHandle(property);

    CalculateTransitionUpdateForPropertyHandle(
        state, transition_property.property_type, property_handle,
        transition_index, animate_all);
  }
}

void CSSAnimations::CalculateTransitionUpdate(
    CSSAnimationUpdate& update,
    Element& animating_element,
    const ComputedStyleBuilder& style_builder,
    const ComputedStyle* old_style,
    bool can_trigger_animations) {
  if (animating_element.GetDocument().FinishingOrIsPrinting()) {
    return;
  }

  ElementAnimations* element_animations =
      animating_element.GetElementAnimations();
  const TransitionMap* active_transitions =
      element_animations ? &element_animations->CssAnimations().transitions_
                         : nullptr;
  const CSSTransitionData* transition_data = style_builder.Transitions();
  const WritingDirectionMode writing_direction =
      style_builder.GetWritingDirection();

  const bool animation_style_recalc =
      !can_trigger_animations ||
      (element_animations && element_animations->IsAnimationStyleChange());

  HashSet<PropertyHandle> listed_properties;
  bool any_transition_had_transition_all = false;

#if DCHECK_IS_ON()
  DCHECK(!old_style || !old_style->IsEnsuredInDisplayNone())
      << "Should always pass nullptr instead of ensured styles";
  const ComputedStyle* scope_old_style =
      PostStyleUpdateScope::GetOldStyle(animating_element);
  bool is_starting_style = old_style && old_style->IsStartingStyle();
  DCHECK(old_style == scope_old_style || !scope_old_style && is_starting_style)
      << "The old_style passed in should be the style for the element at the "
         "beginning of the lifecycle update, or a style based on the "
         "@starting-style style";
#endif

  if (old_style && !old_style->IsStartingStyle() &&
      !animating_element.GetDocument().RenderingHadBegunForLastStyleUpdate()) {
    // Only allow transitions on the first rendered frame for @starting-style.
    old_style = nullptr;
  }

  if (!animation_style_recalc && old_style) {
    // TODO: Don't run transitions if style.Display() == EDisplay::kNone
    // and display is not transitioned. I.e. display is actually none.
    // Don't bother updating listed_properties unless we need it below.
    HashSet<PropertyHandle>* listed_properties_maybe =
        active_transitions ? &listed_properties : nullptr;
    TransitionUpdateState state = {update,
                                   animating_element,
                                   *old_style,
                                   *style_builder.GetBaseComputedStyle(),
                                   /*before_change_style=*/nullptr,
                                   active_transitions,
                                   listed_properties_maybe,
                                   transition_data};

    if (transition_data) {
      for (wtf_size_t transition_index = 0;
           transition_index < transition_data->PropertyList().size();
           ++transition_index) {
        const CSSTransitionData::TransitionProperty& transition_property =
            transition_data->PropertyList()[transition_index];
        if (transition_property.unresolved_property == CSSPropertyID::kAll) {
          any_transition_had_transition_all = true;
          // We don't need to build listed_properties (which is expensive for
          // 'all').
          state.listed_properties = nullptr;
        }
        CalculateTransitionUpdateForProperty(
            state, transition_property, transition_index, writing_direction);
      }
    } else if (active_transitions && active_transitions->size()) {
      // !transition_data implies transition: all 0s
      any_transition_had_transition_all = true;
      CSSTransitionData::TransitionProperty default_property(
          CSSPropertyID::kAll);
      CalculateTransitionUpdateForProperty(state, default_property, 0,
                                           writing_direction);
    }
  }

  if (active_transitions) {
    for (const auto& entry : *active_transitions) {
      const PropertyHandle& property = entry.key;
      if (!any_transition_had_transition_all && !animation_style_recalc &&
          !listed_properties.Contains(property)) {
        update.CancelTransition(property);
      } else if (entry.value->animation->FinishedInternal()) {
        update.FinishTransition(property);
      }
    }
  }

  CalculateTransitionActiveInterpolations(update, animating_element);
}

const ComputedStyle* CSSAnimations::CalculateBeforeChangeStyle(
    Element& animating_element,
    const ComputedStyle& base_style) {
  ActiveInterpolationsMap interpolations_map;
  ElementAnimations* element_animations =
      animating_element.GetElementAnimations();
  if (element_animations) {
    const TransitionMap& transition_map =
        element_animations->CssAnimations().transitions_;

    // Assemble list of animations in composite ordering.
    // TODO(crbug.com/1082401): Per spec, the before change style should include
    // all declarative animations. Currently, only including transitions.
    HeapVector<Member<Animation>> animations;
    for (const auto& entry : transition_map) {
      RunningTransition* transition = entry.value;
      Animation* animation = transition->animation;
      animations.push_back(animation);
    }
    std::sort(animations.begin(), animations.end(),
              [](Animation* a, Animation* b) {
                return Animation::HasLowerCompositeOrdering(
                    a, b, Animation::CompareAnimationsOrdering::kPointerOrder);
              });

    // Sample animations and add to the interpolatzions map.
    for (Animation* animation : animations) {
      V8CSSNumberish* current_time_numberish = animation->currentTime();
      if (!current_time_numberish)
        continue;

      // CSSNumericValue is not yet supported, verify that it is not used
      DCHECK(!current_time_numberish->IsCSSNumericValue());

      std::optional<AnimationTimeDelta> current_time =
          ANIMATION_TIME_DELTA_FROM_MILLISECONDS(
              current_time_numberish->GetAsDouble());

      auto* effect = DynamicTo<KeyframeEffect>(animation->effect());
      if (!effect)
        continue;

      auto* inert_animation_for_sampling = MakeGarbageCollected<InertEffect>(
          effect->Model(), effect->SpecifiedTiming(),
          CSSTransitionProxy(current_time));

      HeapVector<Member<Interpolation>> sample;
      inert_animation_for_sampling->Sample(sample);

      for (const auto& interpolation : sample) {
        PropertyHandle handle = interpolation->GetProperty();
        auto interpolation_map_entry = interpolations_map.insert(
            handle, MakeGarbageCollected<ActiveInterpolations>());
        auto& active_interpolations =
            *interpolation_map_entry.stored_value->value;
        if (!interpolation->DependsOnUnderlyingValue())
          active_interpolations.clear();
        active_interpolations.push_back(interpolation);
      }
    }
  }

  StyleResolver& resolver = animating_element.GetDocument().GetStyleResolver();
  return resolver.BeforeChangeStyleForTransitionUpdate(
      animating_element, base_style, interpolations_map);
}

void CSSAnimations::Cancel() {
  for (const auto& running_animation : running_animations_) {
    running_animation->animation->cancel();
    running_animation->animation->Update(kTimingUpdateOnDemand);
  }

  for (const auto& entry : transitions_) {
    entry.value->animation->cancel();
    entry.value->animation->Update(kTimingUpdateOnDemand);
  }

  for (auto [attaching_timeline, deferred_timeline] :
       timeline_data_.GetTimelineAttachments()) {
    deferred_timeline->DetachTimeline(attaching_timeline);
  }

  running_animations_.clear();
  transitions_.clear();
  timeline_data_.Clear();
  pending_update_.Clear();
}

void CSSAnimations::TimelineData::SetScrollTimeline(const ScopedCSSName& name,
                                                    ScrollTimeline* timeline) {
  if (timeline == nullptr) {
    scroll_timelines_.erase(&name);
  } else {
    scroll_timelines_.Set(&name, timeline);
  }
}

void CSSAnimations::TimelineData::SetViewTimeline(const ScopedCSSName& name,
                                                  ViewTimeline* timeline) {
  if (timeline == nullptr) {
    view_timelines_.erase(&name);
  } else {
    view_timelines_.Set(&name, timeline);
  }
}

void CSSAnimations::TimelineData::SetDeferredTimeline(
    const ScopedCSSName& name,
    DeferredTimeline* timeline) {
  if (timeline == nullptr) {
    deferred_timelines_.erase(&name);
  } else {
    deferred_timelines_.Set(&name, timeline);
  }
}

void CSSAnimations::TimelineData::SetTimelineAttachment(
    ScrollSnapshotTimeline* attached_timeline,
    DeferredTimeline* deferred_timeline) {
  if (deferred_timeline == nullptr) {
    timeline_attachments_.erase(attached_timeline);
  } else {
    timeline_attachments_.Set(attached_timeline, deferred_timeline);
  }
}

DeferredTimeline* CSSAnimations::TimelineData::GetTimelineAttachment(
    ScrollSnapshotTimeline* attached_timeline) {
  auto i = timeline_attachments_.find(attached_timeline);
  return i != timeline_attachments_.end() ? i->value.Get() : nullptr;
}

void CSSAnimations::TimelineData::Trace(blink::Visitor* visitor) const {
  visitor->Trace(scroll_timelines_);
  visitor->Trace(view_timelines_);
  visitor->Trace(deferred_timelines_);
  visitor->Trace(timeline_attachments_);
}

namespace {

bool IsCustomPropertyHandle(const PropertyHandle& property) {
  return property.IsCSSCustomProperty();
}

bool IsFontAffectingPropertyHandle(const PropertyHandle& property) {
  if (property.IsCSSCustomProperty() || !property.IsCSSProperty())
    return false;
  return property.GetCSSProperty().AffectsFont();
}

// TODO(alancutter): CSS properties and presentation attributes may have
// identical effects. By grouping them in the same set we introduce a bug where
// arbitrary hash iteration will determine the order the apply in and thus which
// one "wins". We should be more deliberate about the order of application in
// the case of effect collisions.
// Example: Both 'color' and 'svg-color' set the color on ComputedStyle but are
// considered distinct properties in the ActiveInterpolationsMap.
bool IsCSSPropertyHandle(const PropertyHandle& property) {
  return property.IsCSSProperty() || property.IsPresentationAttribute();
}

bool IsLineHeightPropertyHandle(const PropertyHandle& property) {
  return property == PropertyHandle(GetCSSPropertyLineHeight());
}

bool IsDisplayPropertyHandle(const PropertyHandle& property) {
  return property == PropertyHandle(GetCSSPropertyDisplay());
}

void AdoptActiveAnimationInterpolations(
    EffectStack* effect_stack,
    CSSAnimationUpdate& update,
    const HeapVector<Member<const InertEffect>>* new_animations,
    const HeapHashSet<Member<const Animation>>* suppressed_animations) {
  ActiveInterpolationsMap interpolations(EffectStack::ActiveInterpolations(
      effect_stack, new_animations, suppressed_animations,
      KeyframeEffect::kDefaultPriority, IsCSSPropertyHandle));
  update.AdoptActiveInterpolationsForAnimations(interpolations);
}

}  // namespace

void CSSAnimations::CalculateAnimationActiveInterpolations(
    CSSAnimationUpdate& update,
    const Element& animating_element) {
  ElementAnimations* element_animations =
      animating_element.GetElementAnimations();
  EffectStack* effect_stack =
      element_animations ? &element_animations->GetEffectStack() : nullptr;

  if (update.NewAnimations().empty() && update.SuppressedAnimations().empty()) {
    AdoptActiveAnimationInterpolations(effect_stack, update, nullptr, nullptr);
    return;
  }

  HeapVector<Member<const InertEffect>> new_effects;
  for (const auto& new_animation : update.NewAnimations())
    new_effects.push_back(new_animation.effect);

  // Animations with updates use a temporary InertEffect for the current frame.
  for (const auto& updated_animation : update.AnimationsWithUpdates())
    new_effects.push_back(updated_animation.effect);

  AdoptActiveAnimationInterpolations(effect_stack, update, &new_effects,
                                     &update.SuppressedAnimations());
}

void CSSAnimations::CalculateTransitionActiveInterpolations(
    CSSAnimationUpdate& update,
    const Element& animating_element) {
  ElementAnimations* element_animations =
      animating_element.GetElementAnimations();
  EffectStack* effect_stack =
      element_animations ? &element_animations->GetEffectStack() : nullptr;

  ActiveInterpolationsMap active_interpolations_for_transitions;
  if (update.NewTransitions().empty() &&
      update.CancelledTransitions().empty()) {
    active_interpolations_for_transitions = EffectStack::ActiveInterpolations(
        effect_stack, nullptr, nullptr, KeyframeEffect::kTransitionPriority,
        IsCSSPropertyHandle);
  } else {
    HeapVector<Member<const InertEffect>> new_transitions;
    for (const auto& entry : update.NewTransitions())
      new_transitions.push_back(entry.value->effect.Get());

    HeapHashSet<Member<const Animation>> cancelled_animations =
        CreateCancelledTransitionsSet(element_animations, update);

    active_interpolations_for_transitions = EffectStack::ActiveInterpolations(
        effect_stack, &new_transitions, &cancelled_animations,
        KeyframeEffect::kTransitionPriority, IsCSSPropertyHandle);
  }

  const ActiveInterpolationsMap& animations =
      update.ActiveInterpolationsForAnimations();
  // Properties being animated by animations don't get values from transitions
  // applied.
  if (!animations.empty() && !active_interpolations_for_transitions.empty()) {
    for (const auto& entry : animations)
      active_interpolations_for_transitions.erase(entry.key);
  }

  update.AdoptActiveInterpolationsForTransitions(
      active_interpolations_for_transitions);
}

EventTarget* CSSAnimations::AnimationEventDelegate::GetEventTarget() const {
  return &EventPath::EventTargetRespectingTargetRules(*animation_target_);
}

void CSSAnimations::AnimationEventDelegate::MaybeDispatch(
    Document::ListenerType listener_type,
    const AtomicString& event_name,
    const AnimationTimeDelta& elapsed_time) {
  if (animation_target_->GetDocument().HasListenerType(listener_type)) {
    String pseudo_element_name =
        PseudoElement::PseudoElementNameForEvents(animation_target_);
    AnimationEvent* event = AnimationEvent::Create(
        event_name, name_, elapsed_time, pseudo_element_name);

    EventTarget* event_target = GetEventTarget();
    if (!event_target) {
      // TODO(crbug.com/1483390): Investigate why event target may be null.
      // This condition only appears to be possible for a disposed pseudo-
      // element. Though in this case, any attached CSS animations should be
      // canceled. This workaround is safe since there is no originating
      // element to listen to the event.
      return;
    }

    event->SetTarget(event_target);
    GetDocument().EnqueueAnimationFrameEvent(event);
  }
}

bool CSSAnimations::AnimationEventDelegate::RequiresIterationEvents(
    const AnimationEffect& animation_node) {
  return GetDocument().HasListenerType(Document::kAnimationIterationListener);
}

void CSSAnimations::AnimationEventDelegate::OnEventCondition(
    const AnimationEffect& animation_node,
    Timing::Phase current_phase) {
  const std::optional<double> current_iteration =
      animation_node.CurrentIteration();

  // See http://drafts.csswg.org/css-animations-2/#event-dispatch
  // When multiple events are dispatched for a single phase transition,
  // the animationstart event is to be dispatched before the animationend
  // event.

  // The following phase transitions trigger an animationstart event:
  //   idle or before --> active or after
  //   after --> active or before
  const bool phase_change = previous_phase_ != current_phase;
  const bool was_idle_or_before = (previous_phase_ == Timing::kPhaseNone ||
                                   previous_phase_ == Timing::kPhaseBefore);
  const bool is_active_or_after = (current_phase == Timing::kPhaseActive ||
                                   current_phase == Timing::kPhaseAfter);
  const bool is_active_or_before = (current_phase == Timing::kPhaseActive ||
                                    current_phase == Timing::kPhaseBefore);
  const bool was_after = (previous_phase_ == Timing::kPhaseAfter);
  if (phase_change && ((was_idle_or_before && is_active_or_after) ||
                       (was_after && is_active_or_before))) {
    AnimationTimeDelta elapsed_time =
        was_after ? IntervalEnd(animation_node) : IntervalStart(animation_node);
    MaybeDispatch(Document::kAnimationStartListener,
                  event_type_names::kAnimationstart, elapsed_time);
  }

  // The following phase transitions trigger an animationend event:
  //   idle, before or active--> after
  //   active or after--> before
  const bool was_active_or_after = (previous_phase_ == Timing::kPhaseActive ||
                                    previous_phase_ == Timing::kPhaseAfter);
  const bool is_after = (current_phase == Timing::kPhaseAfter);
  const bool is_before = (current_phase == Timing::kPhaseBefore);
  if (phase_change && (is_after || (was_active_or_after && is_before))) {
    AnimationTimeDelta elapsed_time =
        is_after ? IntervalEnd(animation_node) : IntervalStart(animation_node);
    MaybeDispatch(Document::kAnimationEndListener,
                  event_type_names::kAnimationend, elapsed_time);
  }

  // The following phase transitions trigger an animationcalcel event:
  //   not idle and not after --> idle
  if (phase_change && current_phase == Timing::kPhaseNone &&
      previous_phase_ != Timing::kPhaseAfter) {
    // TODO(crbug.com/1059968): Determine if animation direction or playback
    // rate factor into the calculation of the elapsed time.
    AnimationTimeDelta cancel_time = animation_node.GetCancelTime();
    MaybeDispatch(Document::kAnimationCancelListener,
                  event_type_names::kAnimationcancel, cancel_time);
  }

  if (!phase_change && current_phase == Timing::kPhaseActive &&
      previous_iteration_ != current_iteration) {
    // We fire only a single event for all iterations that terminate
    // between a single pair of samples. See http://crbug.com/275263. For
    // compatibility with the existing implementation, this event uses
    // the elapsedTime for the first iteration in question.
    DCHECK(previous_iteration_ && current_iteration);
    const AnimationTimeDelta elapsed_time =
        IterationElapsedTime(animation_node, previous_iteration_.value());
    MaybeDispatch(Document::kAnimationIterationListener,
                  event_type_names::kAnimationiteration, elapsed_time);
  }

  previous_iteration_ = current_iteration;
  previous_phase_ = current_phase;
}

void CSSAnimations::AnimationEventDelegate::Trace(Visitor* visitor) const {
  visitor->Trace(animation_target_);
  AnimationEffect::EventDelegate::Trace(visitor);
}

EventTarget* CSSAnimations::TransitionEventDelegate::GetEventTarget() const {
  return &EventPath::EventTargetRespectingTargetRules(*transition_target_);
}

void CSSAnimations::TransitionEventDelegate::OnEventCondition(
    const AnimationEffect& animation_node,
    Timing::Phase current_phase) {
  if (current_phase == previous_phase_)
    return;

  if (GetDocument().HasListenerType(Document::kTransitionRunListener)) {
    if (previous_phase_ == Timing::kPhaseNone) {
      EnqueueEvent(
          event_type_names::kTransitionrun,
          StartTimeFromDelay(animation_node.NormalizedTiming().start_delay));
    }
  }

  if (GetDocument().HasListenerType(Document::kTransitionStartListener)) {
    if ((current_phase == Timing::kPhaseActive ||
         current_phase == Timing::kPhaseAfter) &&
        (previous_phase_ == Timing::kPhaseNone ||
         previous_phase_ == Timing::kPhaseBefore)) {
      EnqueueEvent(
          event_type_names::kTransitionstart,
          StartTimeFromDelay(animation_node.NormalizedTiming().start_delay));
    } else if ((current_phase == Timing::kPhaseActive ||
                current_phase == Timing::kPhaseBefore) &&
               previous_phase_ == Timing::kPhaseAfter) {
      // If the transition is progressing backwards it is considered to have
      // started at the end position.
      EnqueueEvent(event_type_names::kTransitionstart,
                   animation_node.NormalizedTiming().iteration_duration);
    }
  }

  if (GetDocument().HasListenerType(Document::kTransitionEndListener)) {
    if (current_phase == Timing::kPhaseAfter &&
        (previous_phase_ == Timing::kPhaseActive ||
         previous_phase_ == Timing::kPhaseBefore ||
         previous_phase_ == Timing::kPhaseNone)) {
      EnqueueEvent(event_type_names::kTransitionend,
                   animation_node.NormalizedTiming().iteration_duration);
    } else if (current_phase == Timing::kPhaseBefore &&
               (previous_phase_ == Timing::kPhaseActive ||
                previous_phase_ == Timing::kPhaseAfter)) {
      // If the transition is progressing backwards it is considered to have
      // ended at the start position.
      EnqueueEvent(
          event_type_names::kTransitionend,
          StartTimeFromDelay(animation_node.NormalizedTiming().start_delay));
    }
  }

  if (GetDocument().HasListenerType(Document::kTransitionCancelListener)) {
    if (current_phase == Timing::kPhaseNone &&
        previous_phase_ != Timing::kPhaseAfter) {
      // Per the css-transitions-2 spec, transitioncancel is fired with the
      // "active time of the animation at the moment it was cancelled,
      // calculated using a fill mode of both".
      std::optional<AnimationTimeDelta> cancel_active_time =
          TimingCalculations::CalculateActiveTime(
              animation_node.NormalizedTiming(), Timing::FillMode::BOTH,
              animation_node.LocalTime(), previous_phase_);
      // Being the FillMode::BOTH the only possibility to get a null
      // cancel_active_time is that previous_phase_ is kPhaseNone. This cannot
      // happen because we know that current_phase == kPhaseNone and
      // current_phase != previous_phase_ (see early return at the beginning).
      DCHECK(cancel_active_time);
      EnqueueEvent(event_type_names::kTransitioncancel,
                   cancel_active_time.value());
    }
  }

  previous_phase_ = current_phase;
}

void CSSAnimations::TransitionEventDelegate::EnqueueEvent(
    const WTF::AtomicString& type,
    const AnimationTimeDelta& elapsed_time) {
  String property_name =
      property_.IsCSSCustomProperty()
          ? property_.CustomPropertyName()
          : property_.GetCSSProperty().GetPropertyNameString();
  String pseudo_element =
      PseudoElement::PseudoElementNameForEvents(transition_target_);
  TransitionEvent* event = TransitionEvent::Create(
      type, property_name, elapsed_time, pseudo_element);
  event->SetTarget(GetEventTarget());
  GetDocument().EnqueueAnimationFrameEvent(event);
}

void CSSAnimations::TransitionEventDelegate::Trace(Visitor* visitor) const {
  visitor->Trace(transition_target_);
  AnimationEffect::EventDelegate::Trace(visitor);
}

const StylePropertyShorthand& CSSAnimations::PropertiesForTransitionAll(
    bool with_discrete,
    const ExecutionContext* execution_context) {
  if (with_discrete) [[unlikely]] {
    return PropertiesForTransitionAllDiscrete(execution_context);
  }
  return PropertiesForTransitionAllNormal(execution_context);
}

// Properties that affect animations are not allowed to be affected by
// animations.
// https://w3.org/TR/web-animations-1/#animating-properties
bool CSSAnimations::IsAnimationAffectingProperty(const CSSProperty& property) {
  // Internal properties are not animatable because they should not be exposed
  // to the page/author in the first place.
  if (property.IsInternal()) {
    return true;
  }

  switch (property.PropertyID()) {
    case CSSPropertyID::kAlternativeAnimationWithTimeline:
    case CSSPropertyID::kAnimation:
    case CSSPropertyID::kAnimationComposition:
    case CSSPropertyID::kAnimationDelay:
    case CSSPropertyID::kAnimationDirection:
    case CSSPropertyID::kAnimationDuration:
    case CSSPropertyID::kAnimationFillMode:
    case CSSPropertyID::kAnimationIterationCount:
    case CSSPropertyID::kAnimationName:
    case CSSPropertyID::kAnimationPlayState:
    case CSSPropertyID::kAnimationRange:
    case CSSPropertyID::kAnimationRangeEnd:
    case CSSPropertyID::kAnimationRangeStart:
    case CSSPropertyID::kAnimationTimeline:
    case CSSPropertyID::kAnimationTimingFunction:
    case CSSPropertyID::kContain:
    case CSSPropertyID::kContainerName:
    case CSSPropertyID::kContainerType:
    case CSSPropertyID::kDirection:
    case CSSPropertyID::kInterpolateSize:
    case CSSPropertyID::kScrollTimelineAxis:
    case CSSPropertyID::kScrollTimelineName:
    case CSSPropertyID::kTextCombineUpright:
    case CSSPropertyID::kTextOrientation:
    case CSSPropertyID::kTimelineScope:
    case CSSPropertyID::kTransition:
    case CSSPropertyID::kTransitionBehavior:
    case CSSPropertyID::kTransitionDelay:
    case CSSPropertyID::kTransitionDuration:
    case CSSPropertyID::kTransitionProperty:
    case CSSPropertyID::kTransitionTimingFunction:
    case CSSPropertyID::kUnicodeBidi:
    case CSSPropertyID::kViewTimelineAxis:
    case CSSPropertyID::kViewTimelineInset:
    case CSSPropertyID::kViewTimelineName:
    case CSSPropertyID::kWebkitWritingMode:
    case CSSPropertyID::kWillChange:
    case CSSPropertyID::kWritingMode:
      return true;
    default:
      return false;
  }
}

bool CSSAnimations::IsAffectedByKeyframesFromScope(
    const Element& element,
    const TreeScope& tree_scope) {
  // Animated elements are affected by @keyframes rules from the same scope
  // and from their shadow sub-trees if they are shadow hosts.
  if (element.GetTreeScope() == tree_scope)
    return true;
  if (!IsShadowHost(element))
    return false;
  if (tree_scope.RootNode() == tree_scope.GetDocument())
    return false;
  return To<ShadowRoot>(tree_scope.RootNode()).host() == element;
}

bool CSSAnimations::IsAnimatingCustomProperties(
    const ElementAnimations* element_animations) {
  return element_animations &&
         element_animations->GetEffectStack().AffectsProperties(
             IsCustomPropertyHandle);
}

bool CSSAnimations::IsAnimatingStandardProperties(
    const ElementAnimations* element_animations,
    const CSSBitset* bitset,
    KeyframeEffect::Priority priority) {
  if (!element_animations || !bitset)
    return false;
  return element_animations->GetEffectStack().AffectsProperties(*bitset,
                                                                priority);
}

bool CSSAnimations::IsAnimatingFontAffectingProperties(
    const ElementAnimations* element_animations) {
  return element_animations &&
         element_animations->GetEffectStack().AffectsProperties(
             IsFontAffectingPropertyHandle);
}

bool CSSAnimations::IsAnimatingLineHeightProperty(
    const ElementAnimations* element_animations) {
  return element_animations &&
         element_animations->GetEffectStack().AffectsProperties(
             IsLineHeightPropertyHandle);
}

bool CSSAnimations::IsAnimatingRevert(
    const ElementAnimations* element_animations) {
  return element_animations && element_animations->GetEffectStack().HasRevert();
}

bool CSSAnimations::IsAnimatingDisplayProperty(
    const ElementAnimations* eleme
"""


```