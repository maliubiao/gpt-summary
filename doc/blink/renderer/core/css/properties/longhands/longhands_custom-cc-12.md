Response:
The user wants a summary of the provided C++ code. This file seems to define the behavior of various individual CSS properties (longhands) within the Blink rendering engine. I need to analyze each function and determine its purpose related to CSS processing.

Here's a breakdown of the process:

1. **Identify the core functionality:** The file is named `longhands_custom.cc` and is part of the CSS properties processing. This suggests it defines how specific CSS properties are parsed, applied, and represented in the computed style.

2. **Analyze each class and its methods:**  Each class likely corresponds to a specific CSS property. The methods like `ParseSingleValue`, `ApplyValue`, `ApplyInitial`, `ApplyInherit`, and `CSSValueFromComputedStyleInternal` represent different stages of handling that property.

3. **Connect to CSS concepts:**  Relate the functions to how CSS works, such as parsing CSS text, applying styles to elements, inheritance, initial values, and retrieving computed values.

4. **Look for examples:** If a function manipulates CSS values or interacts with HTML elements or JavaScript, I need to provide illustrative examples.

5. **Consider potential errors:** Think about common mistakes developers might make when using these CSS properties.

6. **Trace user interaction:** Imagine how a user's actions in a browser would lead to this code being executed.

7. **Summarize the overall functionality:**  Based on the analysis, provide a concise summary of the file's role within Blink.

8. **Address the "part 13 of 13" aspect:**  This implies this file is the final part of a series. The summary should also reflect that it likely covers the less common or "custom" longhand CSS properties.

**Detailed analysis of specific functions:**

* **`TextEmphasisStyle`:** Handles the `text-emphasis` shorthand property. It parses the different ways `text-emphasis` can be specified (fill and mark, or a custom string).
* **`WebkitTextFillColor`, `WebkitTextStrokeColor`:** Deal with `-webkit-text-fill-color` and `-webkit-text-stroke-color`. They parse color values and handle cases like `currentcolor`.
* **`WebkitTextOrientation`:** Manages the `-webkit-text-orientation` property, mapping its internal representation to CSS values.
* **`WebkitTextSecurity`:** Handles the `-webkit-text-security` property.
* **`WebkitTextStrokeWidth`:** Parses and handles the `-webkit-text-stroke-width` property, dealing with lengths.
* **`TimelineScope`:**  Handles the `timeline-scope` property, which seems to involve a list of custom identifiers.
* **`WebkitTransformOriginX`, `WebkitTransformOriginY`, `WebkitTransformOriginZ`:** These handle the individual components of `transform-origin`, parsing length or keyword values and managing inheritance.
* **`Overlay`:**  Manages the `overlay` property.
* **`WebkitUserDrag`, `WebkitUserModify`:** Handle properties related to user interaction with elements.
* **`WebkitWritingMode`:**  Manages the `-webkit-writing-mode` property.
* **`WhiteSpaceCollapse`, `TextWrapMode`, `TextWrapStyle`:** Handle the sub-properties of `white-space`.
* **`Widows`:** Parses and handles the `widows` property, dealing with integer values.
* **`Width`:** A fundamental property, it parses width values and accounts for layout dependencies.
* **`WillChange`:**  A performance-related property, it parses values indicating which properties might change, and updates internal flags.
* **`WordBreak`:** Handles the `word-break` property.
* **`WordSpacing`:** Parses and handles the `word-spacing` property.
* **`WritingMode`:**  Manages the `writing-mode` property.
* **`TextSizeAdjust`:** Handles the `text-size-adjust` property.
* **`X`, `Y`:** Likely related to SVG, these handle coordinate values.
* **`ZIndex`:** Parses and handles the `z-index` property.
* **`Zoom`:**  Handles the `zoom` property.
* **`InternalAlignContentBlock`, `InternalEmptyLineHeight`:** These appear to be internal or less common properties.

By systematically going through each property handler, I can build a comprehensive understanding of the file's functionality.
这个文件 `longhands_custom.cc` 是 Chromium Blink 引擎中负责处理**自定义或不常见 CSS 属性的“长手”版本**的源代码文件。

**功能概括:**

该文件定义了多个 C++ 类，每个类都对应一个特定的 CSS 属性。这些类主要负责以下功能：

1. **解析 CSS 值 (`ParseSingleValue`)**:  接收 CSS 解析器提供的 token 流，根据 CSS 语法规则，将字符串形式的 CSS 属性值转换为 Blink 内部表示的 CSSValue 对象。
2. **应用 CSS 值 (`ApplyValue`)**:  接收解析后的 CSSValue 对象，并将其应用到 `StyleResolverState` 中，最终更新元素的 `ComputedStyle`。这涉及到修改 `ComputedStyleBuilder` 中的相应属性。
3. **处理初始值 (`ApplyInitial`)**:  定义了当 CSS 属性没有被显式设置时的初始值。
4. **处理继承 (`ApplyInherit`)**: 定义了当 CSS 属性被设置为 `inherit` 时如何从父元素继承值。
5. **生成 CSS 值 (`CSSValueFromComputedStyleInternal`)**:  根据元素的 `ComputedStyle`，将内部表示的属性值转换回 CSSValue 对象，以便在开发者工具或其他地方显示。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS**:  这个文件直接对应于 CSS 的功能。它定义了特定 CSS 属性的语法、解析规则和应用方式。
    * **举例:**  `TextEmphasisStyle` 类处理 `text-emphasis` 属性。在 CSS 中，你可以这样设置文本强调样式：
      ```css
      p {
        text-emphasis: filled sesame;
      }
      ```
      `TextEmphasisStyle::ParseSingleValue` 函数会解析 `filled` 和 `sesame` 这两个值，并将其转换为 `TextEmphasisFill` 和 `TextEmphasisMark` 枚举值。 `TextEmphasisStyle::ApplyValue` 函数则会将这些值设置到元素的样式中。

* **HTML**:  CSS 属性最终会应用于 HTML 元素，影响元素的渲染效果。
    * **举例:**  当浏览器解析包含 `<p style="text-emphasis: open dot;">This is emphasized.</p>` 的 HTML 时，CSS 解析器会调用 `TextEmphasisStyle` 相关的函数来处理 `text-emphasis` 属性，并将强调效果应用于该段落。

* **JavaScript**:  JavaScript 可以通过 DOM API 获取和设置元素的 CSS 样式。
    * **获取样式:**  `getComputedStyle(element).textEmphasis` 会调用 `TextEmphasisStyle::CSSValueFromComputedStyleInternal` 来获取元素最终计算出的 `text-emphasis` 值。
    * **设置样式:**  `element.style.textEmphasis = 'filled circle'` 会触发 CSS 解析器，最终调用 `TextEmphasisStyle::ApplyValue` 来更新元素的样式。

**逻辑推理 (假设输入与输出):**

* **假设输入 (对于 `TextEmphasisStyle`):**  CSS 样式字符串 `"open star"`
* **输出:** `TextEmphasisFill::kOpen`, `TextEmphasisMark::kStar` 会被设置到 `ComputedStyleBuilder` 中。

* **假设输入 (对于 `WebkitTextFillColor`):**  CSS 样式字符串 `"red"`
* **输出:**  一个表示红色 (`blink::Color::kRed`) 的 `StyleColor` 对象会被设置到 `ComputedStyleBuilder` 中。

**用户或编程常见的使用错误及举例说明:**

* **拼写错误或使用无效的 CSS 值:**
    * **错误示例:** `element.style.textEmphasis = 'fille circle';` (拼写错误) 或 `element.style.textEmphasis = 'invalid-value';` (无效值)。
    * **调试线索:**  CSS 解析器在 `TextEmphasisStyle::ParseSingleValue` 中会返回 `nullptr`，导致样式应用失败。开发者可能会在控制台中看到相关的 CSS 解析错误信息。

* **不理解 CSS 属性的语法规则:**
    * **错误示例:**  对于 `text-emphasis`，用户可能错误地认为可以先指定 mark 再指定 fill，例如 `text-emphasis: circle filled;`。
    * **调试线索:**  `TextEmphasisStyle::ApplyValue` 中会按照固定的顺序处理，可能会导致解析结果与预期不符。

* **忘记考虑属性的继承性:**
    * **错误示例:**  父元素设置了 `text-emphasis: filled dot;`，子元素没有设置，用户期望子元素没有强调效果。
    * **调试线索:**  如果属性没有被子元素覆盖，`ApplyInherit` 函数会将父元素的 `text-emphasis` 值传递给子元素。

**用户操作是如何一步步到达这里作为调试线索:**

1. **用户在浏览器中加载网页:**  浏览器开始解析 HTML 和 CSS。
2. **CSS 解析器遇到相关的 CSS 属性:**  例如，解析到 `<div style="text-emphasis: open triangle;">`。
3. **CSS 解析器根据属性名找到对应的 Longhand 类:**  对于 `text-emphasis`，会找到 `TextEmphasisStyle` 类。
4. **调用 `ParseSingleValue` 函数:**  将 `"open triangle"` 传递给 `TextEmphasisStyle::ParseSingleValue` 进行解析。
5. **如果解析成功，调用 `ApplyValue` 函数:**  将解析后的值应用到元素的样式中。
6. **在布局和渲染阶段，会使用 `ComputedStyle` 中的值:**  例如，在绘制文本时会根据 `text-emphasis-fill` 和 `text-emphasis-mark` 的值来添加强调符号。
7. **如果需要获取计算后的样式，JavaScript 会调用 `CSSValueFromComputedStyleInternal`:**  例如，当开发者在控制台执行 `getComputedStyle(element).textEmphasis` 时。

**作为第 13 部分，共 13 部分的功能归纳:**

考虑到这是系列文章的最后一部分，`longhands_custom.cc` 文件很可能包含了那些**不太常见、实验性或者带有浏览器前缀的 CSS 属性**的处理逻辑。这些属性可能不像 `color` 或 `font-size` 那样常用，但它们仍然是 CSS 规范的一部分，或者是一些浏览器特有的扩展。

总而言之，`longhands_custom.cc` 是 Blink 引擎中一个关键的文件，它负责将 CSS 规范中定义的各种属性（特别是那些不太常见的属性）转化为浏览器可以理解和应用的内部表示，从而实现网页的最终渲染效果。它在 CSS 解析、样式计算和 JavaScript 与 CSS 交互的各个环节都发挥着重要的作用。

### 提示词
```
这是目录为blink/renderer/core/css/properties/longhands/longhands_custom.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第13部分，共13部分，请归纳一下它的功能
```

### 源代码
```cpp
entStyle()->GetTextEmphasisFill());
  builder.SetTextEmphasisMark(state.ParentStyle()->GetTextEmphasisMark());
  builder.SetTextEmphasisCustomMark(
      state.ParentStyle()->TextEmphasisCustomMark());
}

void TextEmphasisStyle::ApplyValue(StyleResolverState& state,
                                   const CSSValue& in_value,
                                   ValueMode) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();

  const CSSValue* value = &in_value;
  if (const auto* list = DynamicTo<CSSValueList>(value)) {
    if (list->length() == 1) {
      value = &list->First();
    }
  }

  if (const auto* list = DynamicTo<CSSValueList>(value)) {
    DCHECK_EQ(list->length(), 2U);
    for (unsigned i = 0; i < 2; ++i) {
      const auto& ident_value = To<CSSIdentifierValue>(list->Item(i));
      if (ident_value.GetValueID() == CSSValueID::kFilled ||
          ident_value.GetValueID() == CSSValueID::kOpen) {
        builder.SetTextEmphasisFill(ident_value.ConvertTo<TextEmphasisFill>());
      } else {
        builder.SetTextEmphasisMark(ident_value.ConvertTo<TextEmphasisMark>());
      }
    }
    builder.SetTextEmphasisCustomMark(g_null_atom);
    return;
  }

  if (auto* string_value = DynamicTo<CSSStringValue>(value)) {
    builder.SetTextEmphasisFill(TextEmphasisFill::kFilled);
    builder.SetTextEmphasisMark(TextEmphasisMark::kCustom);
    builder.SetTextEmphasisCustomMark(AtomicString(string_value->Value()));
    return;
  }

  const CSSIdentifierValue& identifier_value = *To<CSSIdentifierValue>(value);

  builder.SetTextEmphasisCustomMark(g_null_atom);

  if (identifier_value.GetValueID() == CSSValueID::kFilled ||
      identifier_value.GetValueID() == CSSValueID::kOpen) {
    builder.SetTextEmphasisFill(identifier_value.ConvertTo<TextEmphasisFill>());
    builder.SetTextEmphasisMark(TextEmphasisMark::kAuto);
  } else {
    builder.SetTextEmphasisFill(TextEmphasisFill::kFilled);
    builder.SetTextEmphasisMark(identifier_value.ConvertTo<TextEmphasisMark>());
  }
}

const CSSValue* WebkitTextFillColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeColor(stream, context);
}

const blink::Color WebkitTextFillColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(!visited_link);
  const StyleColor& text_fill_color = style.TextFillColor();
  if (style.ShouldForceColor(text_fill_color)) {
    return style.GetInternalForcedCurrentColor(is_current_color);
  }
  return text_fill_color.Resolve(style.GetCurrentColor(),
                                 style.UsedColorScheme(), is_current_color);
}

const CSSValue* WebkitTextFillColor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::CurrentColorOrValidColor(
      style, style.TextFillColor(), value_phase);
}

const CSSValue* WebkitTextOrientation::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (style.GetTextOrientation() == ETextOrientation::kMixed) {
    return CSSIdentifierValue::Create(CSSValueID::kVerticalRight);
  }
  return CSSIdentifierValue::Create(style.GetTextOrientation());
}

const CSSValue* WebkitTextSecurity::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.TextSecurity());
}

const CSSValue* WebkitTextStrokeColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeColor(stream, context);
}

const blink::Color WebkitTextStrokeColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(!visited_link);
  const StyleColor& text_stroke_color = style.TextStrokeColor();
  if (style.ShouldForceColor(text_stroke_color)) {
    return style.GetInternalForcedCurrentColor(is_current_color);
  }
  return text_stroke_color.Resolve(style.GetCurrentColor(),
                                   style.UsedColorScheme(), is_current_color);
}

const CSSValue* WebkitTextStrokeColor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::CurrentColorOrValidColor(
      style, style.TextStrokeColor(), value_phase);
}

const CSSValue* WebkitTextStrokeWidth::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeLineWidth(
      stream, context, css_parsing_utils::UnitlessQuirk::kForbid);
}

const CSSValue* WebkitTextStrokeWidth::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ZoomAdjustedPixelValue(style.TextStrokeWidth(), style);
}

const CSSValue* TimelineScope::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kNone) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  using css_parsing_utils::ConsumeCommaSeparatedList;
  using css_parsing_utils::ConsumeCustomIdent;
  return ConsumeCommaSeparatedList<CSSCustomIdentValue*(
      CSSParserTokenStream&, const CSSParserContext&)>(ConsumeCustomIdent,
                                                       stream, context);
}

const CSSValue* TimelineScope::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (!style.TimelineScope()) {
    return MakeGarbageCollected<CSSIdentifierValue>(CSSValueID::kNone);
  }
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  for (const Member<const ScopedCSSName>& name :
       style.TimelineScope()->GetNames()) {
    list->Append(*MakeGarbageCollected<CSSCustomIdentValue>(name->GetName()));
  }
  return list;
}

const CSSValue* WebkitTransformOriginX::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumePositionLonghand<CSSValueID::kLeft,
                                                    CSSValueID::kRight>(
      stream, context);
}

void WebkitTransformOriginX::ApplyInherit(StyleResolverState& state) const {
  state.StyleBuilder().SetTransformOriginX(
      state.ParentStyle()->GetTransformOrigin().X());
}

const CSSValue* Overlay::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.Overlay());
}

const CSSValue* WebkitTransformOriginY::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumePositionLonghand<CSSValueID::kTop,
                                                    CSSValueID::kBottom>(
      stream, context);
}

void WebkitTransformOriginY::ApplyInherit(StyleResolverState& state) const {
  state.StyleBuilder().SetTransformOriginY(
      state.ParentStyle()->GetTransformOrigin().Y());
}

const CSSValue* WebkitTransformOriginZ::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeLength(stream, context,
                                          CSSPrimitiveValue::ValueRange::kAll);
}

void WebkitTransformOriginZ::ApplyInherit(StyleResolverState& state) const {
  state.StyleBuilder().SetTransformOriginZ(
      state.ParentStyle()->GetTransformOrigin().Z());
}

const CSSValue* WebkitUserDrag::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.UserDrag());
}

const CSSValue* WebkitUserModify::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.UserModify());
}

const CSSValue* WebkitWritingMode::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.GetWritingMode());
}

// Longhands for `white-space`: `white-space-collapse` and `text-wrap`.
const CSSValue* WhiteSpaceCollapse::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.GetWhiteSpaceCollapse());
}

const CSSValue* TextWrapMode::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.GetTextWrapMode());
}

const CSSValue* TextWrapStyle::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.GetTextWrapStyle());
}

const CSSValue* Widows::ParseSingleValue(CSSParserTokenStream& stream,
                                         const CSSParserContext& context,
                                         const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumePositiveInteger(stream, context);
}

const CSSValue* Widows::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSNumericLiteralValue::Create(style.Widows(),
                                        CSSPrimitiveValue::UnitType::kNumber);
}

const CSSValue* Width::ParseSingleValue(CSSParserTokenStream& stream,
                                        const CSSParserContext& context,
                                        const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeWidthOrHeight(
      stream, context, css_parsing_utils::UnitlessQuirk::kAllow);
}

bool Width::IsLayoutDependent(const ComputedStyle* style,
                              LayoutObject* layout_object) const {
  return layout_object && (layout_object->IsBox() || layout_object->IsSVG());
}

const CSSValue* Width::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (value_phase == CSSValuePhase::kResolvedValue &&
      ComputedStyleUtils::WidthOrHeightShouldReturnUsedValue(layout_object)) {
    return ZoomAdjustedPixelValue(
        ComputedStyleUtils::UsedBoxSize(*layout_object).width(), style);
  }
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(style.Width(),
                                                             style);
}

const CSSValue* WillChange::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kAuto) {
    return css_parsing_utils::ConsumeIdent(stream);
  }

  CSSValueList* values = CSSValueList::CreateCommaSeparated();
  // Every comma-separated list of identifiers is a valid will-change value,
  // unless the list includes an explicitly disallowed identifier.
  while (true) {
    if (stream.Peek().GetType() != kIdentToken) {
      return nullptr;
    }
    CSSPropertyID unresolved_property = UnresolvedCSSPropertyID(
        context.GetExecutionContext(), stream.Peek().Value());
    if (unresolved_property != CSSPropertyID::kInvalid &&
        unresolved_property != CSSPropertyID::kVariable) {
#if DCHECK_IS_ON()
      DCHECK(CSSProperty::Get(ResolveCSSPropertyID(unresolved_property))
                 .IsWebExposed(context.GetExecutionContext()));
#endif
      // Now "all" is used by both CSSValue and CSSPropertyValue.
      // Need to return nullptr when currentValue is CSSPropertyID::kAll.
      if (unresolved_property == CSSPropertyID::kWillChange ||
          unresolved_property == CSSPropertyID::kAll) {
        return nullptr;
      }
      values->Append(
          *MakeGarbageCollected<CSSCustomIdentValue>(unresolved_property));
      stream.ConsumeIncludingWhitespace();
    } else {
      switch (stream.Peek().Id()) {
        case CSSValueID::kNone:
        case CSSValueID::kAll:
        case CSSValueID::kAuto:
        case CSSValueID::kDefault:
        case CSSValueID::kInitial:
        case CSSValueID::kInherit:
        case CSSValueID::kRevert:
          return nullptr;
        case CSSValueID::kContents:
        case CSSValueID::kScrollPosition:
          values->Append(*css_parsing_utils::ConsumeIdent(stream));
          break;
        default:
          stream.ConsumeIncludingWhitespace();
          break;
      }
    }

    if (!css_parsing_utils::ConsumeCommaIncludingWhitespace(stream)) {
      break;
    }
  }

  return values;
}

const CSSValue* WillChange::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForWillChange(
      style.WillChangeProperties(), style.WillChangeContents(),
      style.WillChangeScrollPosition());
}

void WillChange::ApplyInitial(StyleResolverState& state) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  builder.SetWillChangeContents(false);
  builder.SetWillChangeScrollPosition(false);
  builder.SetWillChangeProperties(Vector<CSSPropertyID>());
  builder.SetSubtreeWillChangeContents(
      state.ParentStyle()->SubtreeWillChangeContents());
}

void WillChange::ApplyInherit(StyleResolverState& state) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  builder.SetWillChangeContents(state.ParentStyle()->WillChangeContents());
  builder.SetWillChangeScrollPosition(
      state.ParentStyle()->WillChangeScrollPosition());
  builder.SetWillChangeProperties(state.ParentStyle()->WillChangeProperties());
  builder.SetSubtreeWillChangeContents(
      state.ParentStyle()->SubtreeWillChangeContents());
}

void WillChange::ApplyValue(StyleResolverState& state,
                            const CSSValue& value,
                            ValueMode) const {
  bool will_change_contents = false;
  bool will_change_scroll_position = false;
  Vector<CSSPropertyID> will_change_properties;

  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(identifier_value->GetValueID(), CSSValueID::kAuto);
  } else {
    for (auto& will_change_value : To<CSSValueList>(value)) {
      if (auto* ident_value =
              DynamicTo<CSSCustomIdentValue>(will_change_value.Get())) {
        will_change_properties.push_back(ident_value->ValueAsPropertyID());
      } else if (To<CSSIdentifierValue>(*will_change_value).GetValueID() ==
                 CSSValueID::kContents) {
        will_change_contents = true;
      } else if (To<CSSIdentifierValue>(*will_change_value).GetValueID() ==
                 CSSValueID::kScrollPosition) {
        will_change_scroll_position = true;
      } else {
        NOTREACHED();
      }
    }
  }
  ComputedStyleBuilder& builder = state.StyleBuilder();
  builder.SetWillChangeContents(will_change_contents);
  builder.SetWillChangeScrollPosition(will_change_scroll_position);
  builder.SetWillChangeProperties(will_change_properties);
  builder.SetSubtreeWillChangeContents(
      will_change_contents || state.ParentStyle()->SubtreeWillChangeContents());
}

const CSSValue* WordBreak::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.WordBreak());
}

void WordBreak::ApplyValue(StyleResolverState& state,
                           const CSSValue& value,
                           ValueMode) const {
  blink::EWordBreak word_break =
      To<CSSIdentifierValue>(value).ConvertTo<blink::EWordBreak>();
  if (word_break == EWordBreak::kAutoPhrase) {
    UseCounter::Count(state.GetDocument(), WebFeature::kCSSWordBreakAutoPhrase);
  }
  state.StyleBuilder().SetWordBreak(word_break);
}

const CSSValue* WordSpacing::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ParseSpacing(stream, context);
}

const CSSValue* WordSpacing::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ZoomAdjustedPixelValue(style.WordSpacing(), style);
}

const CSSValue* WritingMode::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.GetWritingMode());
}

void WritingMode::ApplyInitial(StyleResolverState& state) const {
  state.SetWritingMode(ComputedStyleInitialValues::InitialWritingMode());
}

void WritingMode::ApplyInherit(StyleResolverState& state) const {
  state.SetWritingMode(state.ParentStyle()->GetWritingMode());
}

void WritingMode::ApplyValue(StyleResolverState& state,
                             const CSSValue& value,
                             ValueMode) const {
  state.SetWritingMode(
      To<CSSIdentifierValue>(value).ConvertTo<blink::WritingMode>());
}

void TextSizeAdjust::ApplyInitial(StyleResolverState& state) const {
  state.SetTextSizeAdjust(ComputedStyleInitialValues::InitialTextSizeAdjust());
}

void TextSizeAdjust::ApplyInherit(StyleResolverState& state) const {
  state.SetTextSizeAdjust(state.ParentStyle()->GetTextSizeAdjust());
}

void TextSizeAdjust::ApplyValue(StyleResolverState& state,
                                const CSSValue& value,
                                ValueMode) const {
  state.SetTextSizeAdjust(
      StyleBuilderConverter::ConvertTextSizeAdjust(state, value));
}

const CSSValue* X::ParseSingleValue(CSSParserTokenStream& stream,
                                    const CSSParserContext& context,
                                    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeSVGGeometryPropertyLength(
      stream, context, CSSPrimitiveValue::ValueRange::kAll);
}

const CSSValue* X::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(style.X(), style);
}

const CSSValue* Y::ParseSingleValue(CSSParserTokenStream& stream,
                                    const CSSParserContext& context,
                                    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeSVGGeometryPropertyLength(
      stream, context, CSSPrimitiveValue::ValueRange::kAll);
}

const CSSValue* Y::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(style.Y(), style);
}

const CSSValue* ZIndex::ParseSingleValue(CSSParserTokenStream& stream,
                                         const CSSParserContext& context,
                                         const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kAuto) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  return css_parsing_utils::ConsumeInteger(
      stream, context, /* minimum_value */ -std::numeric_limits<double>::max(),
      /* is_percentage_allowed */ false);
}

const CSSValue* ZIndex::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (style.HasAutoZIndex()) {
    return CSSIdentifierValue::Create(CSSValueID::kAuto);
  }
  return CSSNumericLiteralValue::Create(style.ZIndex(),
                                        CSSPrimitiveValue::UnitType::kInteger);
}

const CSSValue* Zoom::ParseSingleValue(CSSParserTokenStream& stream,
                                       const CSSParserContext& context,
                                       const CSSParserLocalContext&) const {
  const CSSParserToken token = stream.Peek();
  CSSValue* zoom = nullptr;
  if (token.GetType() == kIdentToken) {
    zoom = css_parsing_utils::ConsumeIdent<CSSValueID::kNormal>(stream);
  } else {
    zoom = css_parsing_utils::ConsumePercent(
        stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
    if (!zoom) {
      zoom = css_parsing_utils::ConsumeNumber(
          stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
    }
  }
  if (zoom) {
    if (!(token.Id() == CSSValueID::kNormal ||
          (token.GetType() == kNumberToken &&
           To<CSSPrimitiveValue>(zoom)->IsOne() ==
               CSSPrimitiveValue::BoolStatus::kTrue) ||
          (token.GetType() == kPercentageToken &&
           To<CSSPrimitiveValue>(zoom)->IsHundred() ==
               CSSPrimitiveValue::BoolStatus::kTrue))) {
      context.Count(WebFeature::kCSSZoomNotEqualToOne);
    }
  }
  return zoom;
}

const CSSValue* Zoom::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSNumericLiteralValue::Create(style.Zoom(),
                                        CSSPrimitiveValue::UnitType::kNumber);
}

void Zoom::ApplyInitial(StyleResolverState& state) const {
  state.SetZoom(ComputedStyleInitialValues::InitialZoom());
}

void Zoom::ApplyInherit(StyleResolverState& state) const {
  state.SetZoom(state.ParentStyle()->Zoom());
}

void Zoom::ApplyValue(StyleResolverState& state,
                      const CSSValue& value,
                      ValueMode) const {
  state.SetZoom(StyleBuilderConverter::ConvertZoom(state, value));
}

const CSSValue* InternalAlignContentBlock::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext&,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeIdent<CSSValueID::kCenter,
                                         CSSValueID::kNormal>(stream);
}

const CSSValue* InternalEmptyLineHeight::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext&,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeIdent<CSSValueID::kFabricated,
                                         CSSValueID::kNone>(stream);
}

}  // namespace css_longhand
}  // namespace blink
```