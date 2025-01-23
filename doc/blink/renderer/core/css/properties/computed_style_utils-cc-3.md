Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from `computed_style_utils.cc`. I need to go through the code and identify the main tasks it performs. The prompt also asks to relate the code to web technologies like JavaScript, HTML, and CSS, provide examples if applicable, explain logical reasoning with input/output assumptions, mention common user or programming errors, describe how a user action might lead to this code being executed, and finally, summarize the function of this specific part of the file.

**Plan:**

1. **Identify core functionalities:** Look for functions that create or manipulate CSS values based on computed style data.
2. **Relate to web technologies:**  Think about how the generated CSS values are used in rendering web pages and how they interact with JavaScript, HTML, and CSS.
3. **Provide examples:**  Construct simple scenarios demonstrating the connection to web technologies.
4. **Explain logical reasoning:**  For functions with conditional logic, provide hypothetical inputs and their expected outputs.
5. **Mention common errors:** Consider mistakes developers might make when working with related CSS properties or JavaScript APIs.
6. **Describe user actions:** Trace back how user interactions in a browser could trigger the calculation of these computed style values.
7. **Summarize the function of this part:**  Condense the identified functionalities into a concise summary.
这是 `blink/renderer/core/css/properties/computed_style_utils.cc` 文件的第 4 部分，主要功能是**将内部的样式数据结构（如动画、过渡、变换等）转换为可以用于表示计算样式的 CSSValue 对象**。这些 `CSSValue` 对象是 Chromium Blink 引擎中用于表示 CSS 属性值的类。

以下是该部分代码功能的详细列举和与 Web 技术的关系：

**主要功能点:**

1. **处理动画相关属性:**
    *   `ValueForAnimationDirectionList`: 将 `CSSAnimationData` 中的动画方向列表转换为 `CSSValue` 列表。
    *   `ValueForAnimationDuration`: 将动画持续时间（可能为 `auto`）转换为 `CSSNumericLiteralValue` 或 `CSSIdentifierValue`。
    *   `ValueForAnimationDurationList`: 将 `CSSAnimationData` 或 `CSSTransitionData` 中的动画持续时间列表转换为 `CSSValue` 列表。
    *   `ValueForAnimationFillMode`: 将动画填充模式（`forwards`, `backwards`, `both`, `none`) 转换为 `CSSIdentifierValue`。
    *   `ValueForAnimationFillModeList`: 将 `CSSAnimationData` 中的动画填充模式列表转换为 `CSSValue` 列表。
    *   `ValueForAnimationIterationCount`: 将动画迭代次数（可以是 `infinite`）转换为 `CSSNumericLiteralValue` 或 `CSSIdentifierValue`。
    *   `ValueForAnimationIterationCountList`: 将 `CSSAnimationData` 中的动画迭代次数列表转换为 `CSSValue` 列表。
    *   `ValueForAnimationPlayState`: 将动画播放状态（`running`, `paused`) 转换为 `CSSIdentifierValue`。
    *   `ValueForAnimationPlayStateList`: 将 `CSSAnimationData` 中的动画播放状态列表转换为 `CSSValue` 列表。
    *   `ValueForAnimationRangeStart/End/List`: 将动画的范围开始和结束值转换为 `CSSValue` 对象，支持 `normal` 关键字和具体的偏移量。
    *   `ValueForAnimationTimingFunction`: 将 `TimingFunction` 对象（如 `cubic-bezier`, `steps`, `linear`）转换为对应的 `CSSValue` 表示。
    *   `ValueForAnimationTimingFunctionList`: 将 `CSSTimingData` 中的动画 timing 函数列表转换为 `CSSValue` 列表。
    *   `ValueForAnimationTimeline`: 将 `StyleTimeline` 对象转换为对应的 `CSSValue` 表示，包括 `auto`, `none`, 自定义名称、视口时间线和滚动时间线。
    *   `ValueForAnimationTimelineList`: 将 `CSSAnimationData` 中的动画时间线列表转换为 `CSSValue` 列表。

2. **处理时间线 Inset:**
    *   `ValueForTimelineInset`: 将 `TimelineInset` 对象转换为 `CSSValuePair`，表示起始和结束的偏移量。
    *   `SingleValueForTimelineShorthand`: 将时间线相关的简写属性值转换为 `CSSValueList`。

3. **处理边框半径:**
    *   `ValuesForBorderRadiusCorner`: 将 `LengthSize` 类型的边框半径值转换为包含宽度和高度的 `CSSValueList`。
    *   `ValueForBorderRadiusCorner`:  将 `LengthSize` 类型的边框半径值转换为 `CSSValuePair`。

4. **处理变换（Transform）:**
    *   `ValueForTransform`: 将 `gfx::Transform` 矩阵转换为 `CSSFunctionValue`，表示 `matrix()` 或 `matrix3d()` 函数。
    *   `CSSValueIDForScaleOperation/TranslateOperation/RotateOperation`:  辅助函数，根据变换操作类型返回对应的 CSS 函数名 (如 `scaleX`, `translateY`, `rotateZ`) 的 `CSSValueID`。
    *   `ValueForTransformOperation`: 将单个 `TransformOperation` 对象转换为对应的 CSS 函数表示，如 `translateX()`, `scale()`, `rotate()` 等。
    *   `ValueForTransformList`: 将 `TransformOperations` 列表转换为 `CSSValueList`，表示 `transform` 属性的值。
    *   `ValueForTransformFunction`:  将单个变换操作列表转换为 CSS 函数值。
    *   `ReferenceBoxForTransform`: 确定变换的参考框。
    *   `ComputedTransformList`:  获取计算后的 `transform` 属性值。
    *   `ResolvedTransform`:  获取解析后的 `transform` 属性值，通常表示为一个 `matrix()` 或 `matrix3d()` 函数。

5. **处理过渡（Transition）:**
    *   `CreateTransitionPropertyValue`: 将 `CSSTransitionData::TransitionProperty` 转换为 `CSSValue`，表示过渡的属性名（或 `none`）。
    *   `CreateTransitionBehaviorValue`: 将 `CSSTransitionData::TransitionBehavior` 转换为 `CSSValue`，表示过渡的行为（`normal`, `allow-discrete`）。
    *   `ValueForTransitionProperty`: 将 `CSSTransitionData` 中的过渡属性列表转换为 `CSSValue` 列表。
    *   `ValueForTransitionBehavior`: 将 `CSSTransitionData` 中的过渡行为列表转换为 `CSSValue` 列表。

6. **处理 `content` 属性:**
    *   `ValueForContentData`: 将 `ComputedStyle` 中的内容数据转换为 `CSSValue`，用于表示 `content` 属性的值，包括文本、图片、计数器、引号等。

7. **处理计数器指令:**
    *   `ValueForCounterDirectives`: 将 `ComputedStyle` 中的计数器指令（`counter-increment`, `counter-reset`, `counter-set`) 转换为 `CSSValue` 列表。

8. **处理形状 (`shape-outside`, `clip-path` 等):**
    *   `ValueForShape`:  开始处理形状相关的 CSS 属性值，但代码片段未完整展示。

**与 JavaScript, HTML, CSS 的关系及举例:**

*   **CSS:** 这个文件的核心功能就是处理 CSS 属性的计算值。例如，当 CSS 中定义了 `animation-duration: 2s;`，这个文件中的 `ValueForAnimationDuration` 函数会将 `2s` 这个值转换为 `CSSNumericLiteralValue` 对象。

    *   **例子:**  CSS 规则 `animation-duration: 1s, 2s;` 会导致 `ValueForAnimationDurationList` 函数创建一个包含两个 `CSSNumericLiteralValue` 对象的 `CSSValueList`。

*   **HTML:** HTML 结构定义了元素的样式来源。当浏览器解析 HTML 并构建 DOM 树时，会结合 CSS 规则计算每个元素的样式。这个文件中的代码就是在“计算样式”这个环节中起作用的。

    *   **例子:**  一个 `<div>` 元素应用了 CSS `transform: rotate(45deg);`。浏览器在计算该元素的 `transform` 属性值时，会调用 `ValueForTransformList` 和相关的函数将 `rotate(45deg)` 转换为 `CSSFunctionValue` 对象。

*   **JavaScript:** JavaScript 可以通过 DOM API 获取和修改元素的样式。`window.getComputedStyle(element)` 方法返回的样式信息就是由类似这样的代码计算出来的。

    *   **例子:**  JavaScript 代码 `element.style.animationPlayState = 'paused';` 会影响元素的动画状态。浏览器内部会更新 `CSSAnimationData`，而当需要获取该元素的计算样式时，`ValueForAnimationPlayState` 函数会将 `paused` 转换为 `CSSIdentifierValue`，最终通过 `getComputedStyle` 返回给 JavaScript。

**逻辑推理及假设输入与输出:**

*   **`ValueForAnimationDuration(std::optional<double> duration, bool resolve_auto_to_zero)`**

    *   **假设输入 1:** `duration` 为 `std::nullopt`, `resolve_auto_to_zero` 为 `false`。
    *   **预期输出 1:**  返回一个 `CSSIdentifierValue` 对象，其值为 `CSSValueID::kAuto`，对应 CSS 的 `auto` 关键字。

    *   **假设输入 2:** `duration` 为 `std::optional<double>(2.5)`, `resolve_auto_to_zero` 为 `true`。
    *   **预期输出 2:** 返回一个 `CSSNumericLiteralValue` 对象，其值为 2.5，单位为秒 (`CSSPrimitiveValue::UnitType::kSeconds`)。

    *   **假设输入 3:** `duration` 为 `std::nullopt`, `resolve_auto_to_zero` 为 `true`。
    *   **预期输出 3:** 返回一个 `CSSNumericLiteralValue` 对象，其值为 0，单位为秒。

*   **`ValueForAnimationFillMode(Timing::FillMode fill_mode)`**

    *   **假设输入:** `fill_mode` 为 `Timing::FillMode::FORWARDS`。
    *   **预期输出:** 返回一个 `CSSIdentifierValue` 对象，其值为 `CSSValueID::kForwards`，对应 CSS 的 `forwards` 关键字。

**用户或编程常见的使用错误及举例:**

*   **CSS 动画/过渡属性值错误:**  如果 CSS 中提供了无效的动画或过渡属性值（例如，`animation-duration: abc;`），解析器会处理这些错误，但这个文件中的函数会处理有效的已解析的值。

*   **JavaScript 中获取计算样式的类型假设错误:**  开发者可能会错误地假设 `getComputedStyle(element).animationDuration` 返回的是一个数字，但实际上它返回的是一个字符串（例如 "2s"）。需要进行额外的解析才能得到数值。

*   **忘记处理 `auto` 值:** 在处理动画持续时间等属性时，开发者可能会忘记 `auto` 值的特殊性。这个文件中的函数 `ValueForAnimationDuration` 就考虑了 `auto` 的情况，并根据上下文将其转换为 `0s` 或保留为 `auto`。

**用户操作如何一步步到达这里作为调试线索:**

1. **用户在浏览器中加载包含 CSS 动画或过渡的网页。**
2. **浏览器解析 HTML 和 CSS，构建 DOM 树和 CSSOM 树。**
3. **浏览器需要计算元素的最终样式，包括动画和过渡属性的计算值。**
4. **当需要获取某个元素的 `animation-duration` 的计算值时，会调用到 `ComputedStyleUtils::ValueForAnimationDuration` 或 `ComputedStyleUtils::ValueForAnimationDurationList`。**
5. **如果涉及到动画的播放状态，用户与页面的交互（例如，鼠标悬停触发动画）可能导致动画状态的改变，进而影响 `ComputedStyleUtils::ValueForAnimationPlayState` 的调用。**
6. **如果开发者使用浏览器的开发者工具（Elements 面板的 Computed 标签）查看元素的计算样式，也会触发这些函数的执行。**
7. **JavaScript 代码调用 `window.getComputedStyle(element)` 也会触发计算样式的过程，从而调用到这个文件中的相关函数。**

**功能归纳:**

这部分 `computed_style_utils.cc` 文件的主要功能是**将 Blink 引擎内部表示的各种样式数据（特别是与动画、过渡和变换相关的）转换成用于表示计算样式的 `CSSValue` 对象**。它负责将抽象的样式概念（如动画的持续时间、变换矩阵等）转换为可以在 CSSOM 中表示和传递的具体值。这些 `CSSValue` 对象是浏览器渲染引擎和 JavaScript 交互的基础。

### 提示词
```
这是目录为blink/renderer/core/css/properties/computed_style_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
ED();
  }
}

CSSValue* ComputedStyleUtils::ValueForAnimationDirectionList(
    const CSSAnimationData* animation_data) {
  return CreateAnimationValueList(
      animation_data
          ? animation_data->DirectionList()
          : Vector<Timing::PlaybackDirection>{CSSAnimationData::
                                                  InitialDirection()},
      &ValueForAnimationDirection);
}

CSSValue* ComputedStyleUtils::ValueForAnimationDuration(
    const std::optional<double>& duration,
    bool resolve_auto_to_zero) {
  std::optional<double> resolved_duration =
      (!duration.has_value() && resolve_auto_to_zero) ? 0 : duration;
  if (!resolved_duration.has_value()) {
    return CSSIdentifierValue::Create(CSSValueID::kAuto);
  }
  return CSSNumericLiteralValue::Create(resolved_duration.value(),
                                        CSSPrimitiveValue::UnitType::kSeconds);
}

CSSValue* ComputedStyleUtils::ValueForAnimationDurationList(
    const CSSAnimationData* animation_data,
    CSSValuePhase phase) {
  // https://drafts.csswg.org/css-animations-2/#animation-duration
  // For backwards-compatibility with Level 1, when the computed value of
  // animation-timeline is auto (i.e. only one list value, and that value being
  // auto), the resolved value of auto for animation-duration is 0s whenever its
  // used value would also be 0s.
  bool resolve_auto_to_zero =
      (phase == CSSValuePhase::kResolvedValue) &&
      (!animation_data || animation_data->HasSingleInitialTimeline());
  return CreateAnimationValueList(
      animation_data ? animation_data->DurationList()
                     : Vector<std::optional<double>,
                              1>{CSSAnimationData::InitialDuration()},
      ValueForAnimationDuration, resolve_auto_to_zero);
}

CSSValue* ComputedStyleUtils::ValueForAnimationDurationList(
    const CSSTransitionData* transition_data) {
  return CreateAnimationValueList(
      transition_data ? transition_data->DurationList()
                      : Vector<std::optional<double>,
                               1>{CSSTransitionData::InitialDuration()},
      ValueForAnimationDuration,
      /* resolve_auto_to_zero */ false);
}

CSSValue* ComputedStyleUtils::ValueForAnimationFillMode(
    Timing::FillMode fill_mode) {
  switch (fill_mode) {
    case Timing::FillMode::NONE:
      return CSSIdentifierValue::Create(CSSValueID::kNone);
    case Timing::FillMode::FORWARDS:
      return CSSIdentifierValue::Create(CSSValueID::kForwards);
    case Timing::FillMode::BACKWARDS:
      return CSSIdentifierValue::Create(CSSValueID::kBackwards);
    case Timing::FillMode::BOTH:
      return CSSIdentifierValue::Create(CSSValueID::kBoth);
    default:
      NOTREACHED();
  }
}

CSSValue* ComputedStyleUtils::ValueForAnimationFillModeList(
    const CSSAnimationData* animation_data) {
  return CreateAnimationValueList(
      animation_data
          ? animation_data->FillModeList()
          : Vector<Timing::FillMode>{CSSAnimationData::InitialFillMode()},
      &ValueForAnimationFillMode);
}

CSSValue* ComputedStyleUtils::ValueForAnimationIterationCount(
    double iteration_count) {
  if (iteration_count == std::numeric_limits<double>::infinity()) {
    return CSSIdentifierValue::Create(CSSValueID::kInfinite);
  }
  return CSSNumericLiteralValue::Create(iteration_count,
                                        CSSPrimitiveValue::UnitType::kNumber);
}

CSSValue* ComputedStyleUtils::ValueForAnimationIterationCountList(
    const CSSAnimationData* animation_data) {
  return CreateAnimationValueList(
      animation_data
          ? animation_data->IterationCountList()
          : Vector<double>{CSSAnimationData::InitialIterationCount()},
      &ValueForAnimationIterationCount);
}

CSSValue* ComputedStyleUtils::ValueForAnimationPlayState(
    EAnimPlayState play_state) {
  if (play_state == EAnimPlayState::kPlaying) {
    return CSSIdentifierValue::Create(CSSValueID::kRunning);
  }
  DCHECK_EQ(play_state, EAnimPlayState::kPaused);
  return CSSIdentifierValue::Create(CSSValueID::kPaused);
}

CSSValue* ComputedStyleUtils::ValueForAnimationPlayStateList(
    const CSSAnimationData* animation_data) {
  return CreateAnimationValueList(
      animation_data
          ? animation_data->PlayStateList()
          : Vector<EAnimPlayState>{CSSAnimationData::InitialPlayState()},
      &ValueForAnimationPlayState);
}

namespace {

CSSValue* ValueForAnimationRange(const std::optional<TimelineOffset>& offset,
                                 const ComputedStyle& style,
                                 const Length& default_offset) {
  if (!offset.has_value()) {
    return MakeGarbageCollected<CSSIdentifierValue>(CSSValueID::kNormal);
  }
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  if (offset->name != TimelineOffset::NamedRange::kNone) {
    list->Append(*MakeGarbageCollected<CSSIdentifierValue>(offset->name));
  }
  if (offset->offset != default_offset) {
    list->Append(*ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
        offset->offset, style));
  }
  return list;
}

}  // namespace

CSSValue* ComputedStyleUtils::ValueForAnimationRangeStart(
    const std::optional<TimelineOffset>& offset,
    const ComputedStyle& style) {
  return ValueForAnimationRange(offset, style, Length::Percent(0.0));
}

CSSValue* ComputedStyleUtils::ValueForAnimationRangeStartList(
    const CSSAnimationData* animation_data,
    const ComputedStyle& style) {
  return CreateAnimationValueList(
      animation_data
          ? animation_data->RangeStartList()
          : Vector<std::optional<TimelineOffset>>{CSSAnimationData::
                                                      InitialRangeStart()},
      &ValueForAnimationRangeStart, style);
}

CSSValue* ComputedStyleUtils::ValueForAnimationRangeEnd(
    const std::optional<TimelineOffset>& offset,
    const ComputedStyle& style) {
  return ValueForAnimationRange(offset, style, Length::Percent(100.0));
}

CSSValue* ComputedStyleUtils::ValueForAnimationRangeEndList(
    const CSSAnimationData* animation_data,
    const ComputedStyle& style) {
  return CreateAnimationValueList(
      animation_data
          ? animation_data->RangeEndList()
          : Vector<std::optional<TimelineOffset>>{CSSAnimationData::
                                                      InitialRangeEnd()},
      &ValueForAnimationRangeEnd, style);
}

CSSValue* ComputedStyleUtils::ValueForAnimationTimingFunction(
    const scoped_refptr<TimingFunction>& timing_function) {
  switch (timing_function->GetType()) {
    case TimingFunction::Type::CUBIC_BEZIER: {
      const auto* bezier_timing_function =
          To<CubicBezierTimingFunction>(timing_function.get());
      if (bezier_timing_function->GetEaseType() !=
          CubicBezierTimingFunction::EaseType::CUSTOM) {
        CSSValueID value_id = CSSValueID::kInvalid;
        switch (bezier_timing_function->GetEaseType()) {
          case CubicBezierTimingFunction::EaseType::EASE:
            value_id = CSSValueID::kEase;
            break;
          case CubicBezierTimingFunction::EaseType::EASE_IN:
            value_id = CSSValueID::kEaseIn;
            break;
          case CubicBezierTimingFunction::EaseType::EASE_OUT:
            value_id = CSSValueID::kEaseOut;
            break;
          case CubicBezierTimingFunction::EaseType::EASE_IN_OUT:
            value_id = CSSValueID::kEaseInOut;
            break;
          default:
            NOTREACHED();
        }
        return CSSIdentifierValue::Create(value_id);
      }
      return MakeGarbageCollected<cssvalue::CSSCubicBezierTimingFunctionValue>(
          bezier_timing_function->X1(), bezier_timing_function->Y1(),
          bezier_timing_function->X2(), bezier_timing_function->Y2());
    }

    case TimingFunction::Type::STEPS: {
      const auto* steps_timing_function =
          To<StepsTimingFunction>(timing_function.get());
      StepsTimingFunction::StepPosition position =
          steps_timing_function->GetStepPosition();
      int steps = steps_timing_function->NumberOfSteps();

      // Canonical form of step timing function is step(n, type) or step(n) even
      // if initially parsed as step-start or step-end.
      return MakeGarbageCollected<cssvalue::CSSStepsTimingFunctionValue>(
          steps, position);
    }

    default:
      const auto* linear_timing_function =
          To<LinearTimingFunction>(timing_function.get());
      if (linear_timing_function->IsTrivial()) {
        return CSSIdentifierValue::Create(CSSValueID::kLinear);
      }
      return MakeGarbageCollected<cssvalue::CSSLinearTimingFunctionValue>(
          linear_timing_function->Points());
  }
}

CSSValue* ComputedStyleUtils::ValueForAnimationTimingFunctionList(
    const CSSTimingData* timing_data) {
  return CreateAnimationValueList(
      timing_data ? timing_data->TimingFunctionList()
                  : Vector<scoped_refptr<TimingFunction>,
                           1>{CSSAnimationData::InitialTimingFunction()},
      &ValueForAnimationTimingFunction);
}

CSSValue* ComputedStyleUtils::ValueForAnimationTimeline(
    const StyleTimeline& timeline) {
  if (timeline.IsKeyword()) {
    DCHECK(timeline.GetKeyword() == CSSValueID::kAuto ||
           timeline.GetKeyword() == CSSValueID::kNone);
    return CSSIdentifierValue::Create(timeline.GetKeyword());
  }
  if (timeline.IsName()) {
    const ScopedCSSName& scoped_name = timeline.GetName();
    const AtomicString& name = scoped_name.GetName();
    // Serialize as <string> if the value is not a valid <custom-ident>.
    if (css_parsing_utils::IsCSSWideKeyword(name) ||
        EqualIgnoringASCIICase(name, "auto") ||
        EqualIgnoringASCIICase(name, "none")) {
      return MakeGarbageCollected<CSSStringValue>(name);
    }
    return MakeGarbageCollected<CSSCustomIdentValue>(name);
  }
  if (timeline.IsView()) {
    const StyleTimeline::ViewData& view_data = timeline.GetView();
    CSSValue* axis = view_data.HasDefaultAxis()
                         ? nullptr
                         : CSSIdentifierValue::Create(view_data.GetAxis());
    auto* inset =
        view_data.HasDefaultInset()
            ? nullptr
            : MakeGarbageCollected<CSSValuePair>(
                  CSSValue::Create(view_data.GetInset().GetStart(), 1),
                  CSSValue::Create(view_data.GetInset().GetEnd(), 1),
                  CSSValuePair::kDropIdenticalValues);
    return MakeGarbageCollected<cssvalue::CSSViewValue>(axis, inset);
  }
  DCHECK(timeline.IsScroll());
  const StyleTimeline::ScrollData& scroll_data = timeline.GetScroll();
  CSSValue* scroller =
      scroll_data.HasDefaultScroller()
          ? nullptr
          : CSSIdentifierValue::Create(scroll_data.GetScroller());
  CSSValue* axis = scroll_data.HasDefaultAxis()
                       ? nullptr
                       : CSSIdentifierValue::Create(scroll_data.GetAxis());

  return MakeGarbageCollected<cssvalue::CSSScrollValue>(scroller, axis);
}

CSSValue* ComputedStyleUtils::ValueForAnimationTimelineList(
    const CSSAnimationData* animation_data) {
  return CreateAnimationValueList(
      animation_data
          ? animation_data->TimelineList()
          : Vector<StyleTimeline>{CSSAnimationData::InitialTimeline()},
      &ValueForAnimationTimeline);
}

CSSValue* ComputedStyleUtils::ValueForTimelineInset(
    const TimelineInset& inset,
    const ComputedStyle& style) {
  return MakeGarbageCollected<CSSValuePair>(
      ComputedStyleUtils::ZoomAdjustedPixelValueForLength(inset.GetStart(),
                                                          style),
      ComputedStyleUtils::ZoomAdjustedPixelValueForLength(inset.GetEnd(),
                                                          style),
      CSSValuePair::kDropIdenticalValues);
}

CSSValue* ComputedStyleUtils::SingleValueForTimelineShorthand(
    const ScopedCSSName* name,
    TimelineAxis axis,
    std::optional<TimelineInset> inset,
    const ComputedStyle& style) {
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  list->Append(*ValueForCustomIdentOrNone(name));
  if (axis != TimelineAxis::kBlock) {
    list->Append(*CSSIdentifierValue::Create(axis));
  }
  if (inset.value_or(TimelineInset()) != TimelineInset()) {
    list->Append(*ValueForTimelineInset(inset.value(), style));
  }
  return list;
}

CSSValueList* ComputedStyleUtils::ValuesForBorderRadiusCorner(
    const LengthSize& radius,
    const ComputedStyle& style) {
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  if (radius.Width().IsPercent()) {
    list->Append(*CSSNumericLiteralValue::Create(
        radius.Width().Percent(), CSSPrimitiveValue::UnitType::kPercentage));
  } else {
    list->Append(*ZoomAdjustedPixelValueForLength(radius.Width(), style));
  }
  if (radius.Height().IsPercent()) {
    list->Append(*CSSNumericLiteralValue::Create(
        radius.Height().Percent(), CSSPrimitiveValue::UnitType::kPercentage));
  } else {
    list->Append(*ZoomAdjustedPixelValueForLength(radius.Height(), style));
  }
  return list;
}

CSSValue* ComputedStyleUtils::ValueForBorderRadiusCorner(
    const LengthSize& radius,
    const ComputedStyle& style) {
  return MakeGarbageCollected<CSSValuePair>(
      ZoomAdjustedPixelValueForLength(radius.Width(), style),
      ZoomAdjustedPixelValueForLength(radius.Height(), style),
      CSSValuePair::kDropIdenticalValues);
}

CSSFunctionValue* ComputedStyleUtils::ValueForTransform(
    const gfx::Transform& matrix,
    float zoom,
    bool force_matrix3d) {
  if (matrix.Is2dTransform() && !force_matrix3d) {
    auto* result = MakeGarbageCollected<CSSFunctionValue>(CSSValueID::kMatrix);
    // CSS matrix values are returned in column-major order.
    auto unzoomed = AffineTransform::FromTransform(matrix).Zoom(1.f / zoom);
    for (double value : {unzoomed.A(), unzoomed.B(), unzoomed.C(), unzoomed.D(),
                         unzoomed.E(), unzoomed.F()}) {
      result->Append(*CSSNumericLiteralValue::Create(
          value, CSSPrimitiveValue::UnitType::kNumber));
    }
    return result;
  } else {
    CSSFunctionValue* result =
        MakeGarbageCollected<CSSFunctionValue>(CSSValueID::kMatrix3d);
    // CSS matrix values are returned in column-major order.
    auto unzoomed = matrix;
    unzoomed.Zoom(1.f / zoom);
    for (int i = 0; i < 16; i++) {
      result->Append(*CSSNumericLiteralValue::Create(
          unzoomed.ColMajorData(i), CSSPrimitiveValue::UnitType::kNumber));
    }
    return result;
  }
}

CSSValueID ComputedStyleUtils::CSSValueIDForScaleOperation(
    const TransformOperation::OperationType type) {
  switch (type) {
    case TransformOperation::kScaleX:
      return CSSValueID::kScaleX;
    case TransformOperation::kScaleY:
      return CSSValueID::kScaleY;
    case TransformOperation::kScaleZ:
      return CSSValueID::kScaleZ;
    case TransformOperation::kScale3D:
      return CSSValueID::kScale3d;
    default:
      DCHECK(type == TransformOperation::kScale);
      return CSSValueID::kScale;
  }
}

CSSValueID ComputedStyleUtils::CSSValueIDForTranslateOperation(
    const TransformOperation::OperationType type) {
  switch (type) {
    case TransformOperation::kTranslateX:
      return CSSValueID::kTranslateX;
    case TransformOperation::kTranslateY:
      return CSSValueID::kTranslateY;
    case TransformOperation::kTranslateZ:
      return CSSValueID::kTranslateZ;
    case TransformOperation::kTranslate3D:
      return CSSValueID::kTranslate3d;
    default:
      DCHECK(type == TransformOperation::kTranslate);
      return CSSValueID::kTranslate;
  }
}

CSSValueID ComputedStyleUtils::CSSValueIDForRotateOperation(
    const TransformOperation::OperationType type) {
  switch (type) {
    case TransformOperation::kRotateX:
      return CSSValueID::kRotateX;
    case TransformOperation::kRotateY:
      return CSSValueID::kRotateY;
    case TransformOperation::kRotateZ:
      return CSSValueID::kRotateZ;
    case TransformOperation::kRotate3D:
      return CSSValueID::kRotate3d;
    default:
      return CSSValueID::kRotate;
  }
}

// We collapse functions like translateX into translate, since we will reify
// them as a translate anyway.
CSSFunctionValue* ComputedStyleUtils::ValueForTransformOperation(
    const TransformOperation& operation,
    float zoom,
    gfx::SizeF box_size) {
  switch (operation.GetType()) {
    case TransformOperation::kScaleX:
    case TransformOperation::kScaleY:
    case TransformOperation::kScaleZ:
    case TransformOperation::kScale:
    case TransformOperation::kScale3D: {
      const auto& scale = To<ScaleTransformOperation>(operation);

      CSSValueID id = CSSValueIDForScaleOperation(operation.GetType());

      CSSFunctionValue* result = MakeGarbageCollected<CSSFunctionValue>(id);
      if (id == CSSValueID::kScaleX || id == CSSValueID::kScale ||
          id == CSSValueID::kScale3d) {
        result->Append(*CSSNumericLiteralValue::Create(
            scale.X(), CSSPrimitiveValue::UnitType::kNumber));
      }
      if (id == CSSValueID::kScaleY ||
          (id == CSSValueID::kScale && scale.Y() != scale.X()) ||
          id == CSSValueID::kScale3d) {
        result->Append(*CSSNumericLiteralValue::Create(
            scale.Y(), CSSPrimitiveValue::UnitType::kNumber));
      }
      if (id == CSSValueID::kScale3d || id == CSSValueID::kScaleZ) {
        result->Append(*CSSNumericLiteralValue::Create(
            scale.Z(), CSSPrimitiveValue::UnitType::kNumber));
      }
      return result;
    }
    case TransformOperation::kTranslateX:
    case TransformOperation::kTranslateY:
    case TransformOperation::kTranslateZ:
    case TransformOperation::kTranslate:
    case TransformOperation::kTranslate3D: {
      const auto& translate = To<TranslateTransformOperation>(operation);

      CSSValueID id = CSSValueIDForTranslateOperation(operation.GetType());

      CSSFunctionValue* result = MakeGarbageCollected<CSSFunctionValue>(id);
      if (id == CSSValueID::kTranslateX || id == CSSValueID::kTranslate ||
          id == CSSValueID::kTranslate3d) {
        result->Append(
            *CSSPrimitiveValue::CreateFromLength(translate.X(), zoom));
      }
      if (id == CSSValueID::kTranslateY ||
          (id == CSSValueID::kTranslate && (translate.Y().Value() != 0.f)) ||
          id == CSSValueID::kTranslate3d) {
        result->Append(
            *CSSPrimitiveValue::CreateFromLength(translate.Y(), zoom));
      }
      if (id == CSSValueID::kTranslate3d || id == CSSValueID::kTranslateZ) {
        // Since this is pixel length, we must unzoom (CreateFromLength above
        // does the division internally).
        result->Append(*CSSNumericLiteralValue::Create(
            translate.Z() / zoom, CSSPrimitiveValue::UnitType::kPixels));
      }
      return result;
    }
    case TransformOperation::kRotateX:
    case TransformOperation::kRotateY:
    case TransformOperation::kRotateZ:
    case TransformOperation::kRotate3D:
    case TransformOperation::kRotate: {
      const auto& rotate = To<RotateTransformOperation>(operation);
      CSSValueID id = CSSValueIDForRotateOperation(operation.GetType());

      CSSFunctionValue* result = MakeGarbageCollected<CSSFunctionValue>(id);
      if (id == CSSValueID::kRotate3d) {
        result->Append(*CSSNumericLiteralValue::Create(
            rotate.X(), CSSPrimitiveValue::UnitType::kNumber));
        result->Append(*CSSNumericLiteralValue::Create(
            rotate.Y(), CSSPrimitiveValue::UnitType::kNumber));
        result->Append(*CSSNumericLiteralValue::Create(
            rotate.Z(), CSSPrimitiveValue::UnitType::kNumber));
      }
      result->Append(*CSSNumericLiteralValue::Create(
          rotate.Angle(), CSSPrimitiveValue::UnitType::kDegrees));
      return result;
    }
    case TransformOperation::kRotateAroundOrigin: {
      // TODO(https://github.com/w3c/csswg-drafts/issues/5011):
      // Update this once there is consensus.
      gfx::Transform matrix;
      operation.Apply(matrix, gfx::SizeF(0, 0));
      return ValueForTransform(matrix, zoom,
                               /*force_matrix3d=*/false);
    }
    case TransformOperation::kSkewX: {
      const auto& skew = To<SkewTransformOperation>(operation);
      auto* result = MakeGarbageCollected<CSSFunctionValue>(CSSValueID::kSkewX);
      result->Append(*CSSNumericLiteralValue::Create(
          skew.AngleX(), CSSPrimitiveValue::UnitType::kDegrees));
      return result;
    }
    case TransformOperation::kSkewY: {
      const auto& skew = To<SkewTransformOperation>(operation);
      auto* result = MakeGarbageCollected<CSSFunctionValue>(CSSValueID::kSkewY);
      result->Append(*CSSNumericLiteralValue::Create(
          skew.AngleY(), CSSPrimitiveValue::UnitType::kDegrees));
      return result;
    }
    case TransformOperation::kSkew: {
      const auto& skew = To<SkewTransformOperation>(operation);
      auto* result = MakeGarbageCollected<CSSFunctionValue>(CSSValueID::kSkew);
      result->Append(*CSSNumericLiteralValue::Create(
          skew.AngleX(), CSSPrimitiveValue::UnitType::kDegrees));
      result->Append(*CSSNumericLiteralValue::Create(
          skew.AngleY(), CSSPrimitiveValue::UnitType::kDegrees));
      return result;
    }
    case TransformOperation::kPerspective: {
      const auto& perspective = To<PerspectiveTransformOperation>(operation);
      auto* result =
          MakeGarbageCollected<CSSFunctionValue>(CSSValueID::kPerspective);
      if (perspective.Perspective()) {
        result->Append(*CSSNumericLiteralValue::Create(
            *perspective.Perspective() / zoom,
            CSSPrimitiveValue::UnitType::kPixels));
      } else {
        result->Append(*CSSIdentifierValue::Create(CSSValueID::kNone));
      }
      return result;
    }
    case TransformOperation::kMatrix: {
      const auto& matrix = To<MatrixTransformOperation>(operation).Matrix();
      return ValueForTransform(matrix, zoom,
                               /*force_matrix3d=*/false);
    }
    case TransformOperation::kMatrix3D: {
      const auto& matrix = To<Matrix3DTransformOperation>(operation).Matrix();
      // Force matrix3d serialization
      return ValueForTransform(matrix, zoom,
                               /*force_matrix3d=*/true);
    }
    case TransformOperation::kInterpolated:
      // TODO(https://github.com/w3c/csswg-drafts/issues/2854):
      // Deferred interpolations are currently unreperesentable in CSS.
      // This currently converts the operation to a matrix, using box_size if
      // provided, 0x0 if not (returning all but the relative translate
      // portion of the transform). Update this once the spec is updated.
      gfx::Transform matrix;
      operation.Apply(matrix, box_size);
      return ValueForTransform(matrix, zoom,
                               /*force_matrix3d=*/false);
  }
}

CSSValue* ComputedStyleUtils::ValueForTransformList(
    const TransformOperations& transform_list,
    float zoom,
    gfx::SizeF box_size) {
  if (!transform_list.Operations().size()) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }

  CSSValueList* components = CSSValueList::CreateSpaceSeparated();
  for (const auto& operation : transform_list.Operations()) {
    CSSValue* op_value = ValueForTransformOperation(*operation, zoom, box_size);
    components->Append(*op_value);
  }
  return components;
}

CSSValue* ComputedStyleUtils::ValueForTransformFunction(
    const TransformOperations& transform_list) {
  CHECK_EQ(transform_list.Operations().size(), 1u);
  return ValueForTransformOperation(*transform_list.Operations()[0], 1,
                                    gfx::SizeF());
}

gfx::RectF ComputedStyleUtils::ReferenceBoxForTransform(
    const LayoutObject& layout_object) {
  if (layout_object.IsSVGChild()) {
    return TransformHelper::ComputeReferenceBox(layout_object);
  }
  if (const auto* layout_box = DynamicTo<LayoutBox>(layout_object)) {
    return gfx::RectF(layout_box->PhysicalBorderBoxRect());
  }
  return gfx::RectF();
}

CSSValue* ComputedStyleUtils::ComputedTransformList(
    const ComputedStyle& style,
    const LayoutObject* layout_object) {
  gfx::SizeF box_size(0, 0);
  if (layout_object) {
    box_size = ReferenceBoxForTransform(*layout_object).size();
  }

  return ValueForTransformList(style.Transform(), style.EffectiveZoom(),
                               box_size);
}

CSSValue* ComputedStyleUtils::ResolvedTransform(
    const LayoutObject* layout_object,
    const ComputedStyle& style) {
  if (!layout_object || !style.HasTransformOperations()) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }

  gfx::RectF reference_box = ReferenceBoxForTransform(*layout_object);

  const auto* layout_box = layout_object->IsSVGChild()
                               ? nullptr
                               : DynamicTo<LayoutBox>(*layout_object);

  gfx::Transform transform;
  style.ApplyTransform(transform, layout_box, reference_box,
                       ComputedStyle::kIncludeTransformOperations,
                       ComputedStyle::kExcludeTransformOrigin,
                       ComputedStyle::kExcludeMotionPath,
                       ComputedStyle::kExcludeIndependentTransformProperties);

  // FIXME: Need to print out individual functions
  // (https://bugs.webkit.org/show_bug.cgi?id=23924)
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  list->Append(*ValueForTransform(transform, style.EffectiveZoom(),
                                  /*force_matrix3d=*/false));

  return list;
}

CSSValue* ComputedStyleUtils::CreateTransitionPropertyValue(
    const CSSTransitionData::TransitionProperty& property) {
  if (property.property_type == CSSTransitionData::kTransitionNone) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }
  if (property.property_type == CSSTransitionData::kTransitionUnknownProperty) {
    return MakeGarbageCollected<CSSCustomIdentValue>(property.property_string);
  }
  DCHECK_EQ(property.property_type,
            CSSTransitionData::kTransitionKnownProperty);
  return MakeGarbageCollected<CSSCustomIdentValue>(
      CSSUnresolvedProperty::Get(property.unresolved_property)
          .GetPropertyNameAtomicString());
}

CSSValue* ComputedStyleUtils::CreateTransitionBehaviorValue(
    const CSSTransitionData::TransitionBehavior& type) {
  switch (type) {
    case CSSTransitionData::TransitionBehavior::kNormal:
      return CSSIdentifierValue::Create(CSSValueID::kNormal);
    case CSSTransitionData::TransitionBehavior::kAllowDiscrete:
      return CSSIdentifierValue::Create(CSSValueID::kAllowDiscrete);
  }
  NOTREACHED() << " Unrecognized type: " << static_cast<unsigned>(type);
}

CSSValue* ComputedStyleUtils::ValueForTransitionProperty(
    const CSSTransitionData* transition_data) {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  if (transition_data) {
    for (wtf_size_t i = 0; i < transition_data->PropertyList().size(); ++i) {
      list->Append(
          *CreateTransitionPropertyValue(transition_data->PropertyList()[i]));
    }
  } else {
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kAll));
  }
  return list;
}

CSSValue* ComputedStyleUtils::ValueForTransitionBehavior(
    const CSSTransitionData* transition_data) {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  if (transition_data) {
    for (const auto& mode : transition_data->BehaviorList()) {
      list->Append(*CreateTransitionBehaviorValue(mode));
    }
  } else {
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kNormal));
  }
  return list;
}

CSSValueID ValueForQuoteType(const QuoteType quote_type) {
  switch (quote_type) {
    case QuoteType::kNoOpen:
      return CSSValueID::kNoOpenQuote;
    case QuoteType::kNoClose:
      return CSSValueID::kNoCloseQuote;
    case QuoteType::kClose:
      return CSSValueID::kCloseQuote;
    case QuoteType::kOpen:
      return CSSValueID::kOpenQuote;
  }
  NOTREACHED();
}

CSSValue* ComputedStyleUtils::ValueForContentData(const ComputedStyle& style,
                                                  bool allow_visited_style,
                                                  CSSValuePhase value_phase) {
  if (style.ContentPreventsBoxGeneration()) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }
  if (style.ContentBehavesAsNormal()) {
    return CSSIdentifierValue::Create(CSSValueID::kNormal);
  }

  CSSValueList* outer_list = CSSValueList::CreateSlashSeparated();
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();

  // Alternative text optionally specified after a forward slash appearing after
  // the last content list item.
  CSSStringValue* alt_text = nullptr;
  for (const ContentData* content_data = style.GetContentData(); content_data;
       content_data = content_data->Next()) {
    if (content_data->IsCounter()) {
      const CounterContentData& counter = To<CounterContentData>(*content_data);
      auto* identifier =
          MakeGarbageCollected<CSSCustomIdentValue>(counter.Identifier());
      auto* separator =
          MakeGarbageCollected<CSSStringValue>(counter.Separator());
      auto* list_style =
          MakeGarbageCollected<CSSCustomIdentValue>(counter.ListStyle());
      list->Append(*MakeGarbageCollected<cssvalue::CSSCounterValue>(
          identifier, list_style, separator));
    } else if (content_data->IsImage()) {
      const StyleImage* image = To<ImageContentData>(content_data)->GetImage();
      DCHECK(image);
      list->Append(
          *image->ComputedCSSValue(style, allow_visited_style, value_phase));
    } else if (content_data->IsText()) {
      list->Append(*MakeGarbageCollected<CSSStringValue>(
          To<TextContentData>(content_data)->GetText()));
    } else if (content_data->IsQuote()) {
      const QuoteType quote_type = To<QuoteContentData>(content_data)->Quote();
      list->Append(*CSSIdentifierValue::Create(ValueForQuoteType(quote_type)));
    } else if (content_data->IsAltText()) {
      alt_text = MakeGarbageCollected<CSSStringValue>(
          To<AltTextContentData>(content_data)->ConcatenateAltText());
      break;
    } else {
      NOTREACHED();
    }
  }
  DCHECK(list->length());

  outer_list->Append(*list);
  if (alt_text) {
    outer_list->Append(*alt_text);
  }
  return outer_list;
}

CSSValue* ComputedStyleUtils::ValueForCounterDirectives(
    const ComputedStyle& style,
    CountersAttachmentContext::Type type) {
  const CounterDirectiveMap* map = style.GetCounterDirectives();
  if (!map) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  for (const auto& item : *map) {
    bool is_valid_counter_value = false;
    switch (type) {
      case CountersAttachmentContext::Type::kIncrementType:
        is_valid_counter_value = item.value.IsIncrement();
        break;
      case CountersAttachmentContext::Type::kResetType:
        is_valid_counter_value = item.value.IsReset();
        break;
      case CountersAttachmentContext::Type::kSetType:
        is_valid_counter_value = item.value.IsSet();
        break;
    }

    if (!is_valid_counter_value) {
      continue;
    }

    int32_t number = 0;
    switch (type) {
      case CountersAttachmentContext::Type::kIncrementType:
        number = item.value.IncrementValue();
        break;
      case CountersAttachmentContext::Type::kResetType:
        number = item.value.ResetValue();
        break;
      case CountersAttachmentContext::Type::kSetType:
        number = item.value.SetValue();
        break;
    }
    list->Append(*MakeGarbageCollected<CSSValuePair>(
        MakeGarbageCollected<CSSCustomIdentValue>(item.key),
        CSSNumericLiteralValue::Create((double)number,
                                       CSSPrimitiveValue::UnitType::kInteger),
        CSSValuePair::IdenticalValuesPolicy::kDropIdenticalValues));
  }

  if (!list->length()) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }

  return list;
}

CSSValue* ComputedStyleUtils::ValueForShape(const ComputedStyle& style,
                                            bool allow_visited_style,
                                            ShapeValue* shape_value,
                                            CSSValuePhase value_phase) {
  if (!shape_value) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }
  if (shape_value->GetType() == ShapeValue::kBox) {
    return CSSIdentifierValue::Create(shape_value->CssBox());
  }
  if (shape_value->GetType() == ShapeValue::kImage) {
    if (shape_value->GetImage()) {
      return shape_value->GetImage()->ComputedCSSValue(
          style, allow_visited_style, value_phase);
    }
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }

  DCHECK_EQ(shape_value->GetType(), ShapeValue:
```