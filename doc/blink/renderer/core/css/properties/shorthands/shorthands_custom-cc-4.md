Response:
The user wants to understand the functionality of the provided C++ code file, which is part of the Chromium Blink rendering engine and deals with CSS shorthand properties. I need to analyze each function within the file, explain its role in CSS processing, and relate it to web development concepts like JavaScript, HTML, and CSS.

Here's a breakdown of the steps:

1. **Identify the main purpose:** The file `shorthands_custom.cc` handles the parsing and serialization of custom CSS shorthand properties. Shorthands are CSS properties that combine multiple other CSS properties into a single declaration.

2. **Analyze each function:** For each function, I need to determine:
    - What CSS shorthand property it handles.
    - How it parses the shorthand value from a stream of tokens.
    - How it extracts individual longhand values from the computed style.
    - If it interacts with JavaScript, HTML, or CSS, providing examples.
    - Any specific logic or assumptions made during parsing or serialization.
    - Common user errors related to the shorthand.

3. **Connect to web development concepts:**  Explain how these shorthands are used in CSS and how they affect the rendering of HTML elements. Consider the role of JavaScript in potentially manipulating these styles.

4. **Provide examples:** For each shorthand, create hypothetical input CSS and the corresponding output (the parsed longhand properties). Also, demonstrate potential user errors in writing the shorthand.

5. **Explain debugging:** Describe how a developer might end up inspecting this code during debugging, tracing the path from a user action to this code.

6. **Summarize the overall functionality:**  Provide a concise summary of the file's purpose based on the analysis.

**Specific considerations for each shorthand:**

* **ScrollTimeline/ViewTimeline:**  These handle timeline definitions for CSS animations and transitions driven by scroll or viewport position. Relate this to the `scroll()` and `view-transition-name` CSS properties.
* **TextDecoration:**  Deals with combining `text-decoration-line`, `text-decoration-style`, and `text-decoration-color`. Note the handling of the `auto` value for `text-decoration-thickness`.
* **TextWrap:** Manages `overflow-wrap` and the legacy `-webkit-line-break`.
* **Transition:**  Handles the `transition` shorthand, which defines animated changes between CSS property values. This is heavily used in CSS animations and interactive effects.
* **WebkitColumnBreakAfter/Before/Inside:** Legacy properties for controlling column breaks in multi-column layouts. Relate these to the standard `break-after`, `break-before`, and `break-inside` properties.
* **WebkitMaskBoxImage:**  A WebKit-specific shorthand for creating image-based masks with borders. Connect to the concept of image slicing and repeating.
* **Mask:**  Similar to `background`, this shorthand combines various mask-related properties.
* **MaskPosition:** Specifies the position of mask layers.
* **TextBox:**  A shorthand for `text-box-trim` and `text-box-edge`, controlling how the text box aligns with the text content.
* **TextEmphasis:**  Handles the `text-emphasis-style`, `text-emphasis-color`, and `text-emphasis-position` properties.
* **TextSpacing:**  A shorthand for `text-autospace` and `text-spacing-trim`, related to text spacing adjustments for specific languages.
* **WebkitTextStroke:**  A WebKit-specific property for adding a stroke (outline) to text.
* **WhiteSpace:** Combines `white-space-collapse` and `text-wrap-mode`. Highlight the backward compatibility aspect and the different ways this property can be parsed.

By carefully considering each shorthand and its nuances, I can provide a comprehensive and accurate explanation of the file's functionality.
这是目录为blink/renderer/core/css/properties/shorthands/shorthands_custom.cc的Chromium Blink引擎源代码文件，它定义了**自定义的 CSS 属性简写 (shorthand) 的解析和计算值的生成逻辑**。

**功能归纳:**

该文件的主要功能是为一些复杂的 CSS 属性简写提供自定义的解析和 computed style 值生成的实现。 这些简写属性将多个相关的 CSS 长属性组合在一起，方便开发者书写 CSS 样式。由于这些简写的结构和逻辑比较特殊，无法通过通用的方式处理，因此需要单独实现其解析和计算值的生成过程。

**与 javascript, html, css 的关系及举例说明:**

1. **CSS:** 该文件直接服务于 CSS。它定义了如何理解和处理 CSS 代码中的简写属性。
    * **举例:** 当浏览器解析到 CSS 样式 `transition: opacity 0.3s ease-in-out;` 时，`Transition::ParseShorthand` 函数会被调用，将这个简写值解析为 `transition-property: opacity; transition-duration: 0.3s; transition-timing-function: ease-in-out;` 等长属性。
    * **举例:** 当浏览器需要计算元素的最终样式时，例如计算 `text-emphasis` 属性的最终值，`TextEmphasis::CSSValueFromComputedStyleInternal` 函数会根据相关的长属性值（`text-emphasis-style`, `text-emphasis-color`, `text-emphasis-position`）生成简写形式的 CSS 值。

2. **HTML:** CSS 样式应用于 HTML 元素以控制其外观。该文件处理的 CSS 简写属性最终会影响 HTML 元素的渲染。
    * **举例:** HTML 中一个 `<div>` 元素的 `style` 属性设置为 `mask: url(#mymask) center/contain no-repeat;`，浏览器会调用 `Mask::ParseShorthand` 来解析这个简写，并最终决定如何遮罩这个 `<div>` 元素。

3. **JavaScript:** JavaScript 可以动态地修改 HTML 元素的样式。当 JavaScript 设置或获取 CSS 简写属性时，该文件中的代码会被间接调用。
    * **举例:** JavaScript 代码 `element.style.textDecoration = "underline dotted red";` 会触发 Blink 引擎解析这个简写值，并调用 `TextDecoration::ParseShorthand` 将其转换为对应的长属性。
    * **举例:** JavaScript 代码 `getComputedStyle(element).transition` 会调用 `Transition::CSSValueFromComputedStyleInternal` 来生成 `transition` 简写属性的计算值。

**逻辑推理 (假设输入与输出):**

* **假设输入 (CSS):** `scroll-timeline: my-timeline linear;`
* **调用函数:** `ScrollTimeline::ParseShorthand`
* **输出 (解析后的长属性):**
    * `scroll-timeline-name: my-timeline;`
    * `scroll-timeline-axis: linear;`

* **假设输入 (ComputedStyle 长属性值):**
    * `scroll-timeline-name: name(my-timeline);`
    * `scroll-timeline-axis: block;`
* **调用函数:** `ScrollTimeline::CSSValueFromComputedStyleInternal`
* **输出 (CSSValue):**  一个表示 `scroll-timeline: my-timeline block;` 的 `CSSValue` 对象。

* **假设输入 (CSS):** `text-wrap: balance pretty;`
* **调用函数:** `TextWrap::ParseShorthand`
* **输出 (解析后的长属性):**
    * `overflow-wrap: balance;`
    * `-webkit-line-break: pretty;` (假设启用了相关特性)

* **假设输入 (ComputedStyle 长属性值):**
    * `overflow-wrap: anywhere;`
    * `-webkit-line-break: normal;`
* **调用函数:** `TextWrap::CSSValueFromComputedStyleInternal`
* **输出 (CSSValue):** 一个表示 `text-wrap: anywhere;` 的 `CSSValue` 对象。

**用户或编程常见的使用错误举例:**

1. **`transition` 简写属性顺序错误:**
   * **错误示例:** `transition: 0.3s opacity ease-in-out;`  (duration应该在property之后)
   * **可能导致:** 样式不生效或解析错误。Blink 的 `Transition::ParseShorthand` 会尝试解析，但如果顺序不符合规范，可能会失败或得到意外的结果。

2. **`text-decoration` 简写属性中 `auto` 的使用:**
   * **场景:** 尝试设置 `text-decoration-thickness: auto` 作为 `text-decoration` 简写的一部分。
   * **用户操作:** 编写 CSS `text-decoration: underline auto red;`
   * **`TextDecoration::CSSValueFromComputedStyleInternal` 行为:** 该函数在生成计算值时，会忽略 `text-decoration-thickness` 的 `auto` 值。这意味着，即使你设置了，计算值中也不会包含 `auto`。这可能导致与预期不符的结果，尤其是在涉及到样式继承或级联时。

3. **`white-space` 简写属性的误用:**
   * **错误理解:**  认为 `white-space: normal nowrap;` 和 `white-space: nowrap normal;` 是等价的。
   * **实际情况:**  `white-space` 简写属性有特定的解析规则。`WhiteSpace::ParseShorthand` 会按照 `white-space-collapse` 和 `text-wrap-mode` 的顺序进行解析。交换顺序可能导致解析为不同的长属性值。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在网页上看到了一个元素的过渡效果不符合预期，想要调试 `transition` 属性：

1. **用户操作:**
   * 在浏览器的开发者工具中，选中该元素。
   * 在 "Elements" 或 "Inspector" 面板中查看该元素的样式。
   * 可能会看到 `transition: opacity 0.3s ease-in-out;` 这样的简写属性。
   * 如果效果有问题，用户可能会尝试修改这个值，例如改成错误的顺序 `transition: 0.3s opacity ease-in-out;`。

2. **浏览器行为:**
   * 当浏览器解析 CSS 样式时，会调用相应的解析函数。对于 `transition` 简写，会调用 `blink/renderer/core/css/properties/shorthands/shorthands_custom.cc` 文件中的 `Transition::ParseShorthand` 函数。
   * 如果用户修改了样式，浏览器会重新解析。

3. **调试线索:**
   * 如果开发者怀疑是 CSS 解析的问题，可以在 Blink 引擎的源代码中设置断点，例如在 `Transition::ParseShorthand` 函数的入口处。
   * 当浏览器解析到相关的 CSS 样式时，断点会触发，开发者可以查看解析过程中的变量值，例如 `stream` 中的 token 流，以及最终解析出的长属性值。
   * 如果计算出的样式值有问题，可以在 `Transition::CSSValueFromComputedStyleInternal` 函数中设置断点，查看计算值的生成逻辑和依赖的长属性值。

**总结它的功能 (作为第5部分):**

作为系列文章的最后一部分，该文件 `shorthands_custom.cc` 集中展示了 Blink 引擎中处理自定义 CSS 属性简写的具体实现细节。它通过提供专门的解析和计算值生成逻辑，确保了浏览器能够正确理解和应用这些复杂的 CSS 简写，从而实现了开发者预期的样式效果。该文件是 Blink 引擎 CSS 解析和渲染流程中的重要组成部分，体现了引擎对 CSS 标准的深入理解和高效实现。它弥补了通用简写处理逻辑的不足，为一些需要特殊处理的简写属性提供了灵活的解决方案。

Prompt: 
```
这是目录为blink/renderer/core/css/properties/shorthands/shorthands_custom.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共5部分，请归纳一下它的功能

"""
ties) const {
  return ParseTimelineShorthand(CSSPropertyID::kScrollTimeline,
                                scrollTimelineShorthand(), important, stream,
                                context, local_context, properties);
}

const CSSValue* ScrollTimeline::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const HeapVector<Member<const ScopedCSSName>>& name_vector =
      style.ScrollTimelineName() ? style.ScrollTimelineName()->GetNames()
                                 : HeapVector<Member<const ScopedCSSName>>{};
  const Vector<TimelineAxis>& axis_vector = style.ScrollTimelineAxis();
  return CSSValueForTimelineShorthand(name_vector, axis_vector,
                                      /* inset_vector */ nullptr, style);
}

bool TextDecoration::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  // Use RuntimeEnabledFeature-aware shorthandForProperty() method until
  // text-decoration-thickness ships, see style_property_shorthand.cc.tmpl.
  return css_parsing_utils::ConsumeShorthandGreedilyViaLonghands(
      shorthandForProperty(CSSPropertyID::kTextDecoration), important, context,
      stream, properties);
}

const CSSValue* TextDecoration::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  // Use RuntimeEnabledFeature-aware shorthandForProperty() method until
  // text-decoration-thickness ships, see style_property_shorthand.cc.tmpl.
  const StylePropertyShorthand& shorthand =
      shorthandForProperty(CSSPropertyID::kTextDecoration);

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  for (const CSSProperty* const longhand : shorthand.properties()) {
    const CSSValue* value = longhand->CSSValueFromComputedStyle(
        style, layout_object, allow_visited_style, value_phase);
    // Do not include initial value 'auto' for thickness.
    // TODO(https://crbug.com/1093826): general shorthand serialization issues
    // remain, in particular for text-decoration.
    if (longhand->PropertyID() == CSSPropertyID::kTextDecorationThickness) {
      if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
        CSSValueID value_id = identifier_value->GetValueID();
        if (value_id == CSSValueID::kAuto) {
          continue;
        }
      }
    }
    DCHECK(value);
    list->Append(*value);
  }
  return list;
}

bool TextWrap::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandGreedilyViaLonghands(
      textWrapShorthand(), important, context, stream, properties);
}

const CSSValue* TextWrap::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const TextWrapMode mode = style.GetTextWrapMode();
  const TextWrapStyle wrap_style = style.GetTextWrapStyle();
  if (wrap_style == ComputedStyleInitialValues::InitialTextWrapStyle()) {
    return CSSIdentifierValue::Create(mode);
  }
  if (mode == ComputedStyleInitialValues::InitialTextWrapMode()) {
    return CSSIdentifierValue::Create(wrap_style);
  }

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  list->Append(*CSSIdentifierValue::Create(mode));
  list->Append(*CSSIdentifierValue::Create(wrap_style));
  return list;
}

namespace {

CSSValue* ConsumeTransitionValue(CSSPropertyID property,
                                 CSSParserTokenStream& stream,
                                 const CSSParserContext& context,
                                 bool use_legacy_parsing) {
  switch (property) {
    case CSSPropertyID::kTransitionDelay:
      return css_parsing_utils::ConsumeTime(
          stream, context, CSSPrimitiveValue::ValueRange::kAll);
    case CSSPropertyID::kTransitionDuration:
      return css_parsing_utils::ConsumeTime(
          stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
    case CSSPropertyID::kTransitionProperty:
      return css_parsing_utils::ConsumeTransitionProperty(stream, context);
    case CSSPropertyID::kTransitionTimingFunction:
      return css_parsing_utils::ConsumeAnimationTimingFunction(stream, context);
    case CSSPropertyID::kTransitionBehavior:
      if (css_parsing_utils::IsValidTransitionBehavior(stream.Peek().Id())) {
        return CSSIdentifierValue::Create(
            stream.ConsumeIncludingWhitespace().Id());
      }
      return nullptr;
    default:
      NOTREACHED();
  }
}

}  // namespace

bool Transition::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  const StylePropertyShorthand shorthand = transitionShorthandForParsing();
  const unsigned longhand_count = shorthand.length();

  // Only relevant for 'animation'.
  auto is_reset_only_function = [](CSSPropertyID) { return false; };

  HeapVector<Member<CSSValueList>, css_parsing_utils::kMaxNumAnimationLonghands>
      longhands(longhand_count);
  if (!css_parsing_utils::ConsumeAnimationShorthand(
          shorthand, longhands, ConsumeTransitionValue, is_reset_only_function,
          stream, context, local_context.UseAliasParsing())) {
    return false;
  }

  for (unsigned i = 0; i < longhand_count; ++i) {
    if (shorthand.properties()[i]->IDEquals(
            CSSPropertyID::kTransitionProperty) &&
        !css_parsing_utils::IsValidPropertyList(*longhands[i])) {
      return false;
    }
  }

  for (unsigned i = 0; i < longhand_count; ++i) {
    css_parsing_utils::AddProperty(
        shorthand.properties()[i]->PropertyID(), shorthand.id(), *longhands[i],
        important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
        properties);
  }

  return true;
}

const CSSValue* Transition::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const CSSTransitionData* transition_data = style.Transitions();
  if (transition_data) {
    CSSValueList* transitions_list = CSSValueList::CreateCommaSeparated();
    for (wtf_size_t i = 0; i < transition_data->PropertyList().size(); ++i) {
      CSSValueList* list = CSSValueList::CreateSpaceSeparated();

      CSSTransitionData::TransitionProperty property =
          transition_data->PropertyList()[i];
      if (property != CSSTransitionData::InitialProperty()) {
        list->Append(
            *ComputedStyleUtils::CreateTransitionPropertyValue(property));
      }

      // If we have a transition-delay but no transition-duration set, we must
      // serialize the transition-duration because they're both <time> values
      // and transition-duration comes first.
      Timing::Delay delay =
          CSSTimingData::GetRepeated(transition_data->DelayStartList(), i);
      const double duration =
          CSSTimingData::GetRepeated(transition_data->DurationList(), i)
              .value();
      bool shows_delay = delay != CSSTimingData::InitialDelayStart();
      bool shows_duration =
          shows_delay || duration != CSSTransitionData::InitialDuration();

      if (shows_duration) {
        list->Append(*CSSNumericLiteralValue::Create(
            duration, CSSPrimitiveValue::UnitType::kSeconds));
      }

      CSSValue* timing_function =
          ComputedStyleUtils::ValueForAnimationTimingFunction(
              CSSTimingData::GetRepeated(transition_data->TimingFunctionList(),
                                         i));
      CSSIdentifierValue* timing_function_value_id =
          DynamicTo<CSSIdentifierValue>(timing_function);
      if (!timing_function_value_id ||
          timing_function_value_id->GetValueID() != CSSValueID::kEase) {
        list->Append(*timing_function);
      }

      if (shows_delay) {
        list->Append(*ComputedStyleUtils::ValueForAnimationDelay(delay));
      }

      const CSSTransitionData::TransitionBehavior behavior =
          CSSTimingData::GetRepeated(transition_data->BehaviorList(), i);
      if (behavior != CSSTransitionData::InitialBehavior()) {
        list->Append(
            *ComputedStyleUtils::CreateTransitionBehaviorValue(behavior));
      }

      if (!list->length()) {
        list->Append(*ComputedStyleUtils::CreateTransitionPropertyValue(
            CSSTransitionData::InitialProperty()));
      }

      transitions_list->Append(*list);
    }
    return transitions_list;
  }

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  // transition-property default value.
  list->Append(*CSSIdentifierValue::Create(CSSValueID::kAll));
  return list;
}

bool ViewTimeline::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return ParseTimelineShorthand(CSSPropertyID::kViewTimeline,
                                viewTimelineShorthand(), important, stream,
                                context, local_context, properties);
}

const CSSValue* ViewTimeline::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const HeapVector<Member<const ScopedCSSName>>& name_vector =
      style.ViewTimelineName() ? style.ViewTimelineName()->GetNames()
                               : HeapVector<Member<const ScopedCSSName>>{};
  const Vector<TimelineAxis>& axis_vector = style.ViewTimelineAxis();
  const Vector<TimelineInset>& inset_vector = style.ViewTimelineInset();
  return CSSValueForTimelineShorthand(name_vector, axis_vector, &inset_vector,
                                      style);
}

bool WebkitColumnBreakAfter::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext&,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  CSSValueID value;
  if (!css_parsing_utils::ConsumeFromColumnBreakBetween(stream, value)) {
    return false;
  }

  css_parsing_utils::AddProperty(
      CSSPropertyID::kBreakAfter, CSSPropertyID::kWebkitColumnBreakAfter,
      *CSSIdentifierValue::Create(value), important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  return true;
}

const CSSValue* WebkitColumnBreakAfter::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForWebkitColumnBreakBetween(
      style.BreakAfter());
}

bool WebkitColumnBreakBefore::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext&,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  CSSValueID value;
  if (!css_parsing_utils::ConsumeFromColumnBreakBetween(stream, value)) {
    return false;
  }

  css_parsing_utils::AddProperty(
      CSSPropertyID::kBreakBefore, CSSPropertyID::kWebkitColumnBreakBefore,
      *CSSIdentifierValue::Create(value), important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  return true;
}

const CSSValue* WebkitColumnBreakBefore::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForWebkitColumnBreakBetween(
      style.BreakBefore());
}

bool WebkitColumnBreakInside::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext&,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  CSSValueID value;
  if (!css_parsing_utils::ConsumeFromColumnOrPageBreakInside(stream, value)) {
    return false;
  }

  css_parsing_utils::AddProperty(
      CSSPropertyID::kBreakInside, CSSPropertyID::kWebkitColumnBreakInside,
      *CSSIdentifierValue::Create(value), important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  return true;
}

const CSSValue* WebkitColumnBreakInside::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForWebkitColumnBreakInside(
      style.BreakInside());
}

bool WebkitMaskBoxImage::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  CSSValue* source = nullptr;
  CSSValue* slice = nullptr;
  CSSValue* width = nullptr;
  CSSValue* outset = nullptr;
  CSSValue* repeat = nullptr;

  if (!css_parsing_utils::ConsumeBorderImageComponents(
          stream, context, source, slice, width, outset, repeat,
          css_parsing_utils::DefaultFill::kFill)) {
    return false;
  }

  css_parsing_utils::AddProperty(
      CSSPropertyID::kWebkitMaskBoxImageSource,
      CSSPropertyID::kWebkitMaskBoxImage,
      source ? *source : *CSSInitialValue::Create(), important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kWebkitMaskBoxImageSlice,
      CSSPropertyID::kWebkitMaskBoxImage,
      slice ? *slice : *CSSInitialValue::Create(), important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kWebkitMaskBoxImageWidth,
      CSSPropertyID::kWebkitMaskBoxImage,
      width ? *width : *CSSInitialValue::Create(), important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kWebkitMaskBoxImageOutset,
      CSSPropertyID::kWebkitMaskBoxImage,
      outset ? *outset : *CSSInitialValue::Create(), important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kWebkitMaskBoxImageRepeat,
      CSSPropertyID::kWebkitMaskBoxImage,
      repeat ? *repeat : *CSSInitialValue::Create(), important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);

  return true;
}

const CSSValue* WebkitMaskBoxImage::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForNinePieceImage(
      style.MaskBoxImage(), style, allow_visited_style, value_phase);
}

bool Mask::ParseShorthand(bool important,
                          CSSParserTokenStream& stream,
                          const CSSParserContext& context,
                          const CSSParserLocalContext& local_context,
                          HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ParseBackgroundOrMask(important, stream, context,
                                                  local_context, properties);
}

const CSSValue* Mask::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForMaskShorthand(
      maskShorthand(), style, layout_object, allow_visited_style, value_phase);
}

bool MaskPosition::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return ParseBackgroundOrMaskPosition(
      maskPositionShorthand(), important, stream, context,
      local_context.UseAliasParsing()
          ? WebFeature::kThreeValuedPositionBackground
          : std::optional<WebFeature>(),
      properties);
}

const CSSValue* MaskPosition::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::BackgroundPositionOrMaskPosition(
      *this, style, &style.MaskLayers());
}

bool TextBox::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  CSSValue* trim = nullptr;
  CSSValue* edge = nullptr;

  // Try `normal` first.
  if (css_parsing_utils::ConsumeIdent<CSSValueID::kNormal>(stream)) {
    trim = CSSIdentifierValue::Create(CSSValueID::kNone);
    edge = CSSIdentifierValue::Create(CSSValueID::kAuto);
  } else {
    // Try <`text-box-trim> || <'text-box-edge>`.
    while (!stream.AtEnd() && (!trim || !edge)) {
      if (!trim && (trim = css_parsing_utils::ConsumeTextBoxTrim(stream))) {
        continue;
      }
      if (!edge && (edge = css_parsing_utils::ConsumeTextBoxEdge(stream))) {
        continue;
      }

      // Parse error, but we must accept whatever junk might be after our own
      // tokens. Fail only if we didn't parse any useful values.
      break;
    }

    if (!trim && !edge) {
      return false;
    }
    if (!trim) {
      trim = CSSIdentifierValue::Create(CSSValueID::kTrimBoth);
    }
    if (!edge) {
      edge = CSSIdentifierValue::Create(CSSValueID::kAuto);
    }
  }

  CHECK(trim);
  AddProperty(CSSPropertyID::kTextBoxTrim, CSSPropertyID::kTextBox, *trim,
              important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
              properties);
  CHECK(edge);
  AddProperty(CSSPropertyID::kTextBoxEdge, CSSPropertyID::kTextBox, *edge,
              important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
              properties);
  return true;
}

const CSSValue* TextBox::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const ETextBoxTrim trim = style.TextBoxTrim();
  const TextBoxEdge edge = style.GetTextBoxEdge();

  // If `text-box-edge: auto`, produce `normal` or `<text-box-trim>`.
  if (edge.IsAuto()) {
    if (trim == ETextBoxTrim::kNone) {
      return CSSIdentifierValue::Create(CSSValueID::kNormal);
    }
    return CSSIdentifierValue::Create(trim);
  }

  const CSSValue* edge_value;
  if (edge.IsUnderDefault()) {
    edge_value = CSSIdentifierValue::Create(edge.Over());
  } else {
    CSSValueList* edge_list = CSSValueList::CreateSpaceSeparated();
    edge_list->Append(*CSSIdentifierValue::Create(edge.Over()));
    edge_list->Append(*CSSIdentifierValue::Create(edge.Under()));
    edge_value = edge_list;
  }

  // Omit `text-box-trim` if `trim-both`, not when it's initial.
  if (trim == ETextBoxTrim::kTrimBoth) {
    return edge_value;
  }

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  list->Append(*CSSIdentifierValue::Create(trim));
  list->Append(*edge_value);
  return list;
}

bool TextEmphasis::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandGreedilyViaLonghands(
      textEmphasisShorthand(), important, context, stream, properties);
}

const CSSValue* TextEmphasis::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForShorthandProperty(
      textEmphasisShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool TextSpacing::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  CSSValue* autospace = nullptr;
  CSSValue* spacing_trim = nullptr;

  // The `text-spacing` shorthand doesn't lean directly on the longhand's
  // grammar, instead uses the `autospace` and `spacing-trim` productions.
  // https://drafts.csswg.org/css-text-4/#text-spacing-property
  //
  // Try `none` first.
  if (css_parsing_utils::ConsumeIdent<CSSValueID::kNone>(stream)) {
    autospace = CSSIdentifierValue::Create(CSSValueID::kNoAutospace);
    spacing_trim = CSSIdentifierValue::Create(CSSValueID::kSpaceAll);
  } else {
    // Try `<autospace> || <spacing-trim>`.
    wtf_size_t num_values = 0;
    while (!stream.AtEnd() && ++num_values <= 2) {
      if (css_parsing_utils::ConsumeIdent<CSSValueID::kNormal>(stream)) {
        // `normal` can be either `text-autospace`, `text-spacing-trim`, or
        // both. Keep parsing without setting the value.
        continue;
      }
      if (!autospace &&
          (autospace = css_parsing_utils::ConsumeAutospace(stream))) {
        continue;
      }
      if (!spacing_trim &&
          (spacing_trim = css_parsing_utils::ConsumeSpacingTrim(stream))) {
        continue;
      }

      // Parse error, but we must accept whatever junk might be after our own
      // tokens. Fail only if we didn't parse any useful values.
      break;
    }

    if (!num_values) {
      return false;
    }
    if (!autospace) {
      autospace = CSSIdentifierValue::Create(CSSValueID::kNormal);
    }
    if (!spacing_trim) {
      spacing_trim = CSSIdentifierValue::Create(CSSValueID::kNormal);
    }
  }

  CHECK(autospace);
  AddProperty(CSSPropertyID::kTextAutospace, CSSPropertyID::kTextSpacing,
              *autospace, important,
              css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  CHECK(spacing_trim);
  AddProperty(CSSPropertyID::kTextSpacingTrim, CSSPropertyID::kTextSpacing,
              *spacing_trim, important,
              css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  return true;
}

const CSSValue* TextSpacing::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const ETextAutospace autospace = style.TextAutospace();
  const TextSpacingTrim spacing_trim =
      style.GetFontDescription().GetTextSpacingTrim();
  if (autospace == ComputedStyleInitialValues::InitialTextAutospace() &&
      spacing_trim == FontBuilder::InitialTextSpacingTrim()) {
    return CSSIdentifierValue::Create(CSSValueID::kNormal);
  }
  if (autospace == ETextAutospace::kNoAutospace &&
      spacing_trim == TextSpacingTrim::kSpaceAll) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }

  const CSSValue* autospace_value =
      autospace == ComputedStyleInitialValues::InitialTextAutospace()
          ? nullptr
          : CSSIdentifierValue::Create(autospace);
  const CSSValue* spacing_trim_value =
      spacing_trim == FontBuilder::InitialTextSpacingTrim()
          ? nullptr
          : CSSIdentifierValue::Create(spacing_trim);
  if (!autospace_value) {
    CHECK(spacing_trim_value);
    return spacing_trim_value;
  }
  if (!spacing_trim_value) {
    return autospace_value;
  }
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  list->Append(*spacing_trim_value);
  list->Append(*autospace_value);
  return list;
}

bool WebkitTextStroke::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandGreedilyViaLonghands(
      webkitTextStrokeShorthand(), important, context, stream, properties);
}

const CSSValue* WebkitTextStroke::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForShorthandProperty(
      webkitTextStrokeShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool WhiteSpace::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  CSSParserTokenStream::State savepoint = stream.Save();

  // Try to parse as a pre-defined keyword. The `white-space` has pre-defined
  // keywords in addition to the multi-values shorthand, for the backward
  // compatibility with when it was a longhand.
  if (const CSSIdentifierValue* value = css_parsing_utils::ConsumeIdent<
          CSSValueID::kBreakSpaces, CSSValueID::kNormal, CSSValueID::kNowrap,
          CSSValueID::kPre, CSSValueID::kPreLine, CSSValueID::kPreWrap>(
          stream)) {
    // Parse as a pre-defined keyword only if it is at the end. Some keywords
    // can be both a pre-defined keyword or a longhand value.
    //
    // TODO(sesse): Figure out some less hacky way of figuring out
    // whether we are at the end or not. In theory, we are supposed to
    // accept arbitrary junk after our input, but we are being saved
    // by the fact that shorthands only need to worry about !important
    // (and none of our longhands accept anything involving the ! delimiter).
    bool at_end = stream.AtEnd();
    if (!at_end) {
      stream.ConsumeWhitespace();
      at_end = stream.Peek().GetType() == kDelimiterToken &&
               stream.Peek().Delimiter() == '!';
    }
    if (at_end) {
      const EWhiteSpace whitespace =
          CssValueIDToPlatformEnum<EWhiteSpace>(value->GetValueID());
      DCHECK(IsValidWhiteSpace(whitespace));
      AddProperty(
          CSSPropertyID::kWhiteSpaceCollapse, CSSPropertyID::kWhiteSpace,
          *CSSIdentifierValue::Create(ToWhiteSpaceCollapse(whitespace)),
          important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
          properties);
      AddProperty(
          CSSPropertyID::kTextWrapMode, CSSPropertyID::kWhiteSpace,
          *CSSIdentifierValue::Create(ToTextWrapMode(whitespace)), important,
          css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
      return true;
    }

    // If `stream` is not at end, the keyword is for longhands. Restore
    // `stream`.
    stream.Restore(savepoint);
  }

  // Consume multi-value syntax if the first identifier is not pre-defined.
  return css_parsing_utils::ConsumeShorthandGreedilyViaLonghands(
      whiteSpaceShorthand(), important, context, stream, properties);
}

const CSSValue* WhiteSpace::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const EWhiteSpace whitespace = style.WhiteSpace();
  if (IsValidWhiteSpace(whitespace)) {
    const CSSValueID value = PlatformEnumToCSSValueID(whitespace);
    DCHECK_NE(value, CSSValueID::kNone);
    return CSSIdentifierValue::Create(value);
  }

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  const WhiteSpaceCollapse collapse = style.GetWhiteSpaceCollapse();
  if (collapse != ComputedStyleInitialValues::InitialWhiteSpaceCollapse()) {
    list->Append(*CSSIdentifierValue::Create(collapse));
  }
  const TextWrapMode wrap = style.GetTextWrapMode();
  if (wrap != ComputedStyleInitialValues::InitialTextWrapMode()) {
    list->Append(*CSSIdentifierValue::Create(wrap));
  }
  // When all longhands are initial values, it should be `normal`, covered by
  // `IsValidWhiteSpace()` above.
  DCHECK(list->length());
  return list;
}

}  // namespace css_shorthand
}  // namespace blink

"""


```