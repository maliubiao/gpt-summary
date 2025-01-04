Response:
The user wants to understand the functionality of the given C++ source code file `longhands_custom.cc` in the Chromium Blink engine. The file seems to define parsing and computed style retrieval logic for various CSS properties.

I need to:

1. **List the functionalities** of the code by analyzing the defined methods and the CSS properties they handle.
2. **Explain the relationship** between these functionalities and JavaScript, HTML, and CSS. Provide concrete examples.
3. **Perform logical reasoning** based on the code and provide input-output examples for specific parsing functions.
4. **Identify potential user or programming errors** based on how the CSS properties are handled.
5. **Describe the user actions** that could lead to the execution of this code, focusing on the CSS parsing and styling process.
6. **Summarize the overall function** of the code snippet provided, keeping in mind that this is part 10 of 13.

Based on the code, the file focuses on:

- **Parsing CSS values:**  Functions like `ParseSingleValue` consume tokens from a CSS parser stream and convert them into internal `CSSValue` objects.
- **Retrieving computed style values:** Functions like `CSSValueFromComputedStyleInternal` extract the computed values of CSS properties from the `ComputedStyle` object and convert them into `CSSValue` objects.
- **Handling specific CSS properties:** The code implements logic for various CSS properties related to scrolling, snapping, shapes, sizes, speaking, SVG appearance, text decoration, and more.
```
这是目录为blink/renderer/core/css/properties/longhands/longhands_custom.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第10部分，共13部分，请归纳一下它的功能

"""
e* ScrollPaddingBlockStart::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeScrollPadding(stream, context);
}

const CSSValue* ScrollPaddingBottom::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeScrollPadding(stream, context);
}

const CSSValue* ScrollPaddingBottom::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
      style.ScrollPaddingBottom(), style);
}

const CSSValue* ScrollPaddingInlineEnd::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeScrollPadding(stream, context);
}

const CSSValue* ScrollPaddingInlineStart::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeScrollPadding(stream, context);
}

const CSSValue* ScrollPaddingLeft::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeScrollPadding(stream, context);
}

const CSSValue* ScrollPaddingLeft::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
      style.ScrollPaddingLeft(), style);
}

const CSSValue* ScrollPaddingRight::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeScrollPadding(stream, context);
}

const CSSValue* ScrollPaddingRight::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
      style.ScrollPaddingRight(), style);
}

const CSSValue* ScrollPaddingTop::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeScrollPadding(stream, context);
}

const CSSValue* ScrollPaddingTop::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
      style.ScrollPaddingTop(), style);
}

const CSSValue* ScrollSnapAlign::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSValue* block_value =
      css_parsing_utils::ConsumeIdent<CSSValueID::kNone, CSSValueID::kStart,
                                      CSSValueID::kEnd, CSSValueID::kCenter>(
          stream);
  if (!block_value) {
    return nullptr;
  }

  CSSValue* inline_value =
      css_parsing_utils::ConsumeIdent<CSSValueID::kNone, CSSValueID::kStart,
                                      CSSValueID::kEnd, CSSValueID::kCenter>(
          stream);
  if (!inline_value) {
    return block_value;
  }
  auto* pair = MakeGarbageCollected<CSSValuePair>(
      block_value, inline_value, CSSValuePair::kDropIdenticalValues);
  return pair;
}

const CSSValue* ScrollSnapAlign::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForScrollSnapAlign(style.GetScrollSnapAlign(),
                                                     style);
}

const CSSValue* ScrollSnapStop::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.ScrollSnapStop());
}

const CSSValue* ScrollSnapType::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSValueID axis_id = stream.Peek().Id();
  if (axis_id != CSSValueID::kNone && axis_id != CSSValueID::kX &&
      axis_id != CSSValueID::kY && axis_id != CSSValueID::kBlock &&
      axis_id != CSSValueID::kInline && axis_id != CSSValueID::kBoth) {
    return nullptr;
  }
  CSSValue* axis_value = css_parsing_utils::ConsumeIdent(stream);
  if (axis_id == CSSValueID::kNone) {
    return axis_value;
  }

  CSSValueID strictness_id = stream.Peek().Id();
  if (strictness_id != CSSValueID::kProximity &&
      strictness_id != CSSValueID::kMandatory) {
    return axis_value;
  }
  CSSValue* strictness_value = css_parsing_utils::ConsumeIdent(stream);
  if (strictness_id == CSSValueID::kProximity) {
    return axis_value;  // Shortest serialization.
  }
  auto* pair = MakeGarbageCollected<CSSValuePair>(
      axis_value, strictness_value, CSSValuePair::kDropIdenticalValues);
  return pair;
}

const CSSValue* ScrollSnapType::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForScrollSnapType(style.GetScrollSnapType(),
                                                    style);
}

const CSSValue* ScrollStartBlock::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeScrollStart(stream, context);
}

const CSSValue* ScrollStartInline::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeScrollStart(stream, context);
}

const CSSValue* ScrollStartX::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeScrollStart(stream, context);
}

const CSSValue* ScrollStartX::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForScrollStart(style, style.ScrollStartX());
}

const CSSValue* ScrollStartY::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeScrollStart(stream, context);
}

const CSSValue* ScrollStartY::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForScrollStart(style, style.ScrollStartY());
}

const CSSValue* ScrollStartTarget::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.ScrollStartTarget());
}

const CSSValue* ScrollTimelineAxis::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  using css_parsing_utils::ConsumeCommaSeparatedList;
  using css_parsing_utils::ConsumeSingleTimelineAxis;
  return ConsumeCommaSeparatedList(ConsumeSingleTimelineAxis, stream);
}

const CSSValue* ScrollTimelineAxis::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const Vector<TimelineAxis>& vector = style.ScrollTimelineAxis();
  if (vector.empty()) {
    return InitialValue();
  }
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  for (TimelineAxis axis : vector) {
    list->Append(*CSSIdentifierValue::Create(axis));
  }
  return list;
}

const CSSValue* ScrollTimelineAxis::InitialValue() const {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  list->Append(*CSSIdentifierValue::Create(CSSValueID::kBlock));
  return list;
}

const CSSValue* ScrollTimelineName::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  using css_parsing_utils::ConsumeCommaSeparatedList;
  using css_parsing_utils::ConsumeSingleTimelineName;
  return ConsumeCommaSeparatedList(ConsumeSingleTimelineName, stream, context);
}

const CSSValue* ScrollTimelineName::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (!style.ScrollTimelineName()) {
    return InitialValue();
  }
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  for (const Member<const ScopedCSSName>& name :
       style.ScrollTimelineName()->GetNames()) {
    list->Append(*ComputedStyleUtils::ValueForCustomIdentOrNone(name.Get()));
  }
  return list;
}

const CSSValue* ScrollTimelineName::InitialValue() const {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  list->Append(*CSSIdentifierValue::Create(CSSValueID::kNone));
  return list;
}

const CSSValue* ShapeImageThreshold::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeAlphaValue(stream, context);
}

const CSSValue* ShapeImageThreshold::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSNumericLiteralValue::Create(style.ShapeImageThreshold(),
                                        CSSPrimitiveValue::UnitType::kNumber);
}

const CSSValue* ShapeMargin::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeLengthOrPercent(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
}

const CSSValue* ShapeMargin::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSValue::Create(style.ShapeMargin(), style.EffectiveZoom());
}

const CSSValue* ShapeOutside::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (CSSValue* image_value =
          css_parsing_utils::ConsumeImageOrNone(stream, context)) {
    return image_value;
  }
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  CSSValue* box_value = css_parsing_utils::ConsumeShapeBox(stream);
  CSSValue* shape_value = css_parsing_utils::ConsumeBasicShape(
      stream, context, css_parsing_utils::AllowPathValue::kForbid,
      css_parsing_utils::AllowBasicShapeRectValue::kForbid,
      css_parsing_utils::AllowBasicShapeXYWHValue::kForbid);
  if (shape_value) {
    list->Append(*shape_value);
    if (!box_value) {
      box_value = css_parsing_utils::ConsumeShapeBox(stream);
    }
  }
  if (box_value) {
    if (!shape_value || To<CSSIdentifierValue>(box_value)->GetValueID() !=
                            CSSValueID::kMarginBox) {
      list->Append(*box_value);
    }
  }
  if (!list->length()) {
    return nullptr;
  }
  return list;
}

const CSSValue* ShapeOutside::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForShape(style, allow_visited_style,
                                           style.ShapeOutside(), value_phase);
}

const CSSValue* ShapeRendering::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.ShapeRendering());
}

static CSSValue* ConsumePageSize(CSSParserTokenStream& stream) {
  return css_parsing_utils::ConsumeIdent<
      CSSValueID::kA3, CSSValueID::kA4, CSSValueID::kA5, CSSValueID::kB4,
      CSSValueID::kB5, CSSValueID::kJisB5, CSSValueID::kJisB4,
      CSSValueID::kLedger, CSSValueID::kLegal, CSSValueID::kLetter>(stream);
}

static float MmToPx(float mm) {
  return mm * kCssPixelsPerMillimeter;
}
static float InchToPx(float inch) {
  return inch * kCssPixelsPerInch;
}
static gfx::SizeF GetPageSizeFromName(
    const CSSIdentifierValue& page_size_name) {
  switch (page_size_name.GetValueID()) {
    case CSSValueID::kA5:
      return gfx::SizeF(MmToPx(148), MmToPx(210));
    case CSSValueID::kA4:
      return gfx::SizeF(MmToPx(210), MmToPx(297));
    case CSSValueID::kA3:
      return gfx::SizeF(MmToPx(297), MmToPx(420));
    case CSSValueID::kB5:
      return gfx::SizeF(MmToPx(176), MmToPx(250));
    case CSSValueID::kB4:
      return gfx::SizeF(MmToPx(250), MmToPx(353));
    case CSSValueID::kJisB5:
      return gfx::SizeF(MmToPx(182), MmToPx(257));
    case CSSValueID::kJisB4:
      return gfx::SizeF(MmToPx(257), MmToPx(364));
    case CSSValueID::kLetter:
      return gfx::SizeF(InchToPx(8.5), InchToPx(11));
    case CSSValueID::kLegal:
      return gfx::SizeF(InchToPx(8.5), InchToPx(14));
    case CSSValueID::kLedger:
      return gfx::SizeF(InchToPx(11), InchToPx(17));
    default:
      NOTREACHED();
  }
}

const CSSValue* Size::ParseSingleValue(CSSParserTokenStream& stream,
                                       const CSSParserContext& context,
                                       const CSSParserLocalContext&) const {
  CSSValueList* result = CSSValueList::CreateSpaceSeparated();

  if (stream.Peek().Id() == CSSValueID::kAuto) {
    result->Append(*css_parsing_utils::ConsumeIdent(stream));
    return result;
  }

  if (CSSValue* width = css_parsing_utils::ConsumeLength(
          stream, context, CSSPrimitiveValue::ValueRange::kNonNegative)) {
    CSSValue* height = css_parsing_utils::ConsumeLength(
        stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
    result->Append(*width);
    if (height) {
      result->Append(*height);
    }
    return result;
  }

  CSSValue* page_size = ConsumePageSize(stream);
  CSSValue* orientation =
      css_parsing_utils::ConsumeIdent<CSSValueID::kPortrait,
                                      CSSValueID::kLandscape>(stream);
  if (!page_size) {
    page_size = ConsumePageSize(stream);
  }

  if (!orientation && !page_size) {
    return nullptr;
  }
  if (page_size) {
    result->Append(*page_size);
  }
  if (orientation) {
    result->Append(*orientation);
  }
  return result;
}

void Size::ApplyInitial(StyleResolverState& state) const {}

void Size::ApplyInherit(StyleResolverState& state) const {}

void Size::ApplyValue(StyleResolverState& state,
                      const CSSValue& value,
                      ValueMode) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  builder.ResetPageSizeType();
  gfx::SizeF size;
  PageSizeType page_size_type = PageSizeType::kAuto;
  const auto& list = To<CSSValueList>(value);
  if (list.length() == 2) {
    // <length>{2} | <page-size> <orientation>
    const CSSValue& first = list.Item(0);
    const CSSValue& second = list.Item(1);
    auto* first_primitive_value = DynamicTo<CSSPrimitiveValue>(first);
    if (first_primitive_value && first_primitive_value->IsLength()) {
      CSSToLengthConversionData unzoomed_conversion_data =
          state.CssToLengthConversionData().Unzoomed();
      // <length>{2}
      size = gfx::SizeF(
          first_primitive_value->ComputeLength<float>(unzoomed_conversion_data),
          To<CSSPrimitiveValue>(second).ComputeLength<float>(
              unzoomed_conversion_data));
    } else {
      // <page-size> <orientation>
      size = GetPageSizeFromName(To<CSSIdentifierValue>(first));

      DCHECK(To<CSSIdentifierValue>(second).GetValueID() ==
                 CSSValueID::kLandscape ||
             To<CSSIdentifierValue>(second).GetValueID() ==
                 CSSValueID::kPortrait);
      if (To<CSSIdentifierValue>(second).GetValueID() ==
          CSSValueID::kLandscape) {
        size.Transpose();
      }
    }
    page_size_type = PageSizeType::kFixed;
  } else {
    DCHECK_EQ(list.length(), 1U);
    // <length> | auto | <page-size> | [ portrait | landscape]
    const CSSValue& first = list.Item(0);
    auto* first_primitive_value = DynamicTo<CSSPrimitiveValue>(first);
    if (first_primitive_value && first_primitive_value->IsLength()) {
      // <length>
      page_size_type = PageSizeType::kFixed;
      float width = first_primitive_value->ComputeLength<float>(
          state.CssToLengthConversionData().Unzoomed());
      size = gfx::SizeF(width, width);
    } else {
      const auto& ident = To<CSSIdentifierValue>(first);
      switch (ident.GetValueID()) {
        case CSSValueID::kAuto:
          page_size_type = PageSizeType::kAuto;
          break;
        case CSSValueID::kPortrait:
          page_size_type = PageSizeType::kPortrait;
          break;
        case CSSValueID::kLandscape:
          page_size_type = PageSizeType::kLandscape;
          break;
        default:
          // <page-size>
          page_size_type = PageSizeType::kFixed;
          size = GetPageSizeFromName(ident);
      }
    }
  }
  builder.SetPageSizeType(page_size_type);
  builder.SetPageSize(size);
}

const CSSValue* Speak::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.Speak());
}

const CSSValue* StopColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeColor(stream, context);
}

const blink::Color StopColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  const StyleColor& stop_color = style.StopColor();
  if (style.ShouldForceColor(stop_color)) {
    return style.GetInternalForcedCurrentColor(is_current_color);
  }
  return style.ResolvedColor(stop_color, is_current_color);
}

const CSSValue* StopColor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::CurrentColorOrValidColor(style, style.StopColor(),
                                                      value_phase);
}

const CSSValue* StopOpacity::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeAlphaValue(stream, context);
}

const CSSValue* StopOpacity::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSNumericLiteralValue::Create(style.StopOpacity(),
                                        CSSPrimitiveValue::UnitType::kNumber);
}

const CSSValue* Stroke::ParseSingleValue(CSSParserTokenStream& stream,
                                         const CSSParserContext& context,
                                         const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeSVGPaint(stream, context);
}

const CSSValue* Stroke::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForSVGPaint(style.StrokePaint(), style);
}

const blink::Color Stroke::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(!visited_link);
  DCHECK(style.StrokePaint().HasColor());
  const StyleColor& stroke_color = style.StrokePaint().GetColor();
  if (style.ShouldForceColor(stroke_color)) {
    return style.GetInternalForcedCurrentColor(is_current_color);
  }
  return stroke_color.Resolve(style.GetCurrentColor(), style.UsedColorScheme(),
                              is_current_color);
}

void Stroke::ApplyValue(StyleResolverState& state,
                        const CSSValue& value,
                        ValueMode) const {
  state.StyleBuilder().SetStrokePaint(StyleBuilderConverter::ConvertSVGPaint(
      state, value, false, PropertyID()));
}

const CSSValue* StrokeDasharray::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  // Syntax: comma- or whitespace-separated list of <length-or-percent>
  CSSValueID id = stream.Peek().Id();
  if (id == CSSValueID::kNone) {
    return css_parsing_utils::ConsumeIdent(stream);
  }

  CSSParserContext::ParserModeOverridingScope scope(context, kSVGAttributeMode);
  CSSValueList* dashes = CSSValueList::CreateCommaSeparated();
  bool need_next_value = true;
  for (;;) {
    CSSPrimitiveValue* dash = css_parsing_utils::ConsumeLengthOrPercent(
        stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
    if (!dash) {
      if (need_next_value) {
        return nullptr;
      } else {
        break;
      }
    }
    dashes->Append(*dash);
    need_next_value =
        css_parsing_utils::ConsumeCommaIncludingWhitespace(stream);
  }
  return dashes;
}

const CSSValue* StrokeDasharray::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::StrokeDashArrayToCSSValueList(
      *style.StrokeDashArray(), style);
}

const CSSValue* StrokeDashoffset::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSParserContext::ParserModeOverridingScope scope(context, kSVGAttributeMode);
  return css_parsing_utils::ConsumeLengthOrPercent(
      stream, context, CSSPrimitiveValue::ValueRange::kAll,
      css_parsing_utils::UnitlessQuirk::kForbid);
}

const CSSValue* StrokeDashoffset::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
      style.StrokeDashOffset(), style);
}

const CSSValue* StrokeLinecap::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.CapStyle());
}

const CSSValue* StrokeLinejoin::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.JoinStyle());
}

const CSSValue* StrokeMiterlimit::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeNumber(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
}

const CSSValue* StrokeMiterlimit::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSNumericLiteralValue::Create(style.StrokeMiterLimit(),
                                        CSSPrimitiveValue::UnitType::kNumber);
}

const CSSValue* StrokeOpacity::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeAlphaValue(stream, context);
}

const CSSValue* StrokeOpacity::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSNumericLiteralValue::Create(style.StrokeOpacity(),
                                        CSSPrimitiveValue::UnitType::kNumber);
}

const CSSValue* StrokeWidth::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSParserContext::ParserModeOverridingScope scope(context, kSVGAttributeMode);
  return css_parsing_utils::ConsumeLengthOrPercent(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative,
      css_parsing_utils::UnitlessQuirk::kForbid);
}

const CSSValue* StrokeWidth::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  // We store the unzoomed stroke-width value using ConvertUnzoomedLength().
  // Don't apply zoom here either.
  return CSSValue::Create(style.StrokeWidth().length(), 1);
}

const CSSValue* ContentVisibility::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.ContentVisibility());
}

const CSSValue* ContentVisibility::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeIdent<
      CSSValueID::kVisible, CSSValueID::kAuto, CSSValueID::kHidden>(stream);
}

const CSSValue* TabSize::ParseSingleValue(CSSParserTokenStream& stream,
                                          const CSSParserContext& context,
                                          const CSSParserLocalContext&) const {
  CSSPrimitiveValue* parsed_value = css_parsing_utils::ConsumeNumber(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
  if (parsed_value) {
    return parsed_value;
  }
  return css_parsing_utils::ConsumeLength(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
}

const CSSValue* TabSize::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSNumericLiteralValue::Create(
      style.GetTabSize().GetPixelSize(1.0),
      style.GetTabSize().IsSpaces() ? CSSPrimitiveValue::UnitType::kNumber
                                    : CSSPrimitiveValue::UnitType::kPixels);
}

const CSSValue* TableLayout::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.TableLayout());
}

const CSSValue* TextAlign::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.GetTextAlign());
}

void TextAlign::ApplyValue(StyleResolverState& state,
                           const CSSValue& value,
                           ValueMode) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  const auto* ident_value = DynamicTo<CSSIdentifierValue>(value);
  if (ident_value &&
      ident_value->GetValueID() != CSSValueID::kWebkitMatchParent) {
    // Special case for th elements - UA stylesheet text-align does not apply
    // if parent's computed value for text-align is not its initial value
    // https://html.spec.whatwg.org/C/#tables-2
    if (ident_value->GetValueID() == CSSValueID::kInternalCenter &&
        state.ParentStyle()->GetTextAlign() !=
            ComputedStyleInitialValues::InitialTextAlign()) {
      builder.SetTextAlign(state.ParentStyle()->GetTextAlign());
    } else {
      builder.SetTextAlign(ident_value->ConvertTo<ETextAlign>());
    }
  } else if (state.ParentStyle()->GetTextAlign() == ETextAlign::kStart) {
    builder.SetTextAlign(state.ParentStyle()->IsLeftToRightDirection()
                             ? ETextAlign::kLeft
                             : ETextAlign::kRight);
  } else if (state.ParentStyle()->GetTextAlign() == ETextAlign::kEnd) {
    builder.
Prompt: 
```
这是目录为blink/renderer/core/css/properties/longhands/longhands_custom.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第10部分，共13部分，请归纳一下它的功能

"""
e* ScrollPaddingBlockStart::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeScrollPadding(stream, context);
}

const CSSValue* ScrollPaddingBottom::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeScrollPadding(stream, context);
}

const CSSValue* ScrollPaddingBottom::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
      style.ScrollPaddingBottom(), style);
}

const CSSValue* ScrollPaddingInlineEnd::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeScrollPadding(stream, context);
}

const CSSValue* ScrollPaddingInlineStart::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeScrollPadding(stream, context);
}

const CSSValue* ScrollPaddingLeft::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeScrollPadding(stream, context);
}

const CSSValue* ScrollPaddingLeft::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
      style.ScrollPaddingLeft(), style);
}

const CSSValue* ScrollPaddingRight::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeScrollPadding(stream, context);
}

const CSSValue* ScrollPaddingRight::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
      style.ScrollPaddingRight(), style);
}

const CSSValue* ScrollPaddingTop::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeScrollPadding(stream, context);
}

const CSSValue* ScrollPaddingTop::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
      style.ScrollPaddingTop(), style);
}

const CSSValue* ScrollSnapAlign::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSValue* block_value =
      css_parsing_utils::ConsumeIdent<CSSValueID::kNone, CSSValueID::kStart,
                                      CSSValueID::kEnd, CSSValueID::kCenter>(
          stream);
  if (!block_value) {
    return nullptr;
  }

  CSSValue* inline_value =
      css_parsing_utils::ConsumeIdent<CSSValueID::kNone, CSSValueID::kStart,
                                      CSSValueID::kEnd, CSSValueID::kCenter>(
          stream);
  if (!inline_value) {
    return block_value;
  }
  auto* pair = MakeGarbageCollected<CSSValuePair>(
      block_value, inline_value, CSSValuePair::kDropIdenticalValues);
  return pair;
}

const CSSValue* ScrollSnapAlign::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForScrollSnapAlign(style.GetScrollSnapAlign(),
                                                     style);
}

const CSSValue* ScrollSnapStop::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.ScrollSnapStop());
}

const CSSValue* ScrollSnapType::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSValueID axis_id = stream.Peek().Id();
  if (axis_id != CSSValueID::kNone && axis_id != CSSValueID::kX &&
      axis_id != CSSValueID::kY && axis_id != CSSValueID::kBlock &&
      axis_id != CSSValueID::kInline && axis_id != CSSValueID::kBoth) {
    return nullptr;
  }
  CSSValue* axis_value = css_parsing_utils::ConsumeIdent(stream);
  if (axis_id == CSSValueID::kNone) {
    return axis_value;
  }

  CSSValueID strictness_id = stream.Peek().Id();
  if (strictness_id != CSSValueID::kProximity &&
      strictness_id != CSSValueID::kMandatory) {
    return axis_value;
  }
  CSSValue* strictness_value = css_parsing_utils::ConsumeIdent(stream);
  if (strictness_id == CSSValueID::kProximity) {
    return axis_value;  // Shortest serialization.
  }
  auto* pair = MakeGarbageCollected<CSSValuePair>(
      axis_value, strictness_value, CSSValuePair::kDropIdenticalValues);
  return pair;
}

const CSSValue* ScrollSnapType::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForScrollSnapType(style.GetScrollSnapType(),
                                                    style);
}

const CSSValue* ScrollStartBlock::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeScrollStart(stream, context);
}

const CSSValue* ScrollStartInline::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeScrollStart(stream, context);
}

const CSSValue* ScrollStartX::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeScrollStart(stream, context);
}

const CSSValue* ScrollStartX::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForScrollStart(style, style.ScrollStartX());
}

const CSSValue* ScrollStartY::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeScrollStart(stream, context);
}

const CSSValue* ScrollStartY::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForScrollStart(style, style.ScrollStartY());
}

const CSSValue* ScrollStartTarget::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.ScrollStartTarget());
}

const CSSValue* ScrollTimelineAxis::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  using css_parsing_utils::ConsumeCommaSeparatedList;
  using css_parsing_utils::ConsumeSingleTimelineAxis;
  return ConsumeCommaSeparatedList(ConsumeSingleTimelineAxis, stream);
}

const CSSValue* ScrollTimelineAxis::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const Vector<TimelineAxis>& vector = style.ScrollTimelineAxis();
  if (vector.empty()) {
    return InitialValue();
  }
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  for (TimelineAxis axis : vector) {
    list->Append(*CSSIdentifierValue::Create(axis));
  }
  return list;
}

const CSSValue* ScrollTimelineAxis::InitialValue() const {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  list->Append(*CSSIdentifierValue::Create(CSSValueID::kBlock));
  return list;
}

const CSSValue* ScrollTimelineName::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  using css_parsing_utils::ConsumeCommaSeparatedList;
  using css_parsing_utils::ConsumeSingleTimelineName;
  return ConsumeCommaSeparatedList(ConsumeSingleTimelineName, stream, context);
}

const CSSValue* ScrollTimelineName::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (!style.ScrollTimelineName()) {
    return InitialValue();
  }
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  for (const Member<const ScopedCSSName>& name :
       style.ScrollTimelineName()->GetNames()) {
    list->Append(*ComputedStyleUtils::ValueForCustomIdentOrNone(name.Get()));
  }
  return list;
}

const CSSValue* ScrollTimelineName::InitialValue() const {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  list->Append(*CSSIdentifierValue::Create(CSSValueID::kNone));
  return list;
}

const CSSValue* ShapeImageThreshold::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeAlphaValue(stream, context);
}

const CSSValue* ShapeImageThreshold::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSNumericLiteralValue::Create(style.ShapeImageThreshold(),
                                        CSSPrimitiveValue::UnitType::kNumber);
}

const CSSValue* ShapeMargin::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeLengthOrPercent(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
}

const CSSValue* ShapeMargin::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSValue::Create(style.ShapeMargin(), style.EffectiveZoom());
}

const CSSValue* ShapeOutside::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (CSSValue* image_value =
          css_parsing_utils::ConsumeImageOrNone(stream, context)) {
    return image_value;
  }
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  CSSValue* box_value = css_parsing_utils::ConsumeShapeBox(stream);
  CSSValue* shape_value = css_parsing_utils::ConsumeBasicShape(
      stream, context, css_parsing_utils::AllowPathValue::kForbid,
      css_parsing_utils::AllowBasicShapeRectValue::kForbid,
      css_parsing_utils::AllowBasicShapeXYWHValue::kForbid);
  if (shape_value) {
    list->Append(*shape_value);
    if (!box_value) {
      box_value = css_parsing_utils::ConsumeShapeBox(stream);
    }
  }
  if (box_value) {
    if (!shape_value || To<CSSIdentifierValue>(box_value)->GetValueID() !=
                            CSSValueID::kMarginBox) {
      list->Append(*box_value);
    }
  }
  if (!list->length()) {
    return nullptr;
  }
  return list;
}

const CSSValue* ShapeOutside::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForShape(style, allow_visited_style,
                                           style.ShapeOutside(), value_phase);
}

const CSSValue* ShapeRendering::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.ShapeRendering());
}

static CSSValue* ConsumePageSize(CSSParserTokenStream& stream) {
  return css_parsing_utils::ConsumeIdent<
      CSSValueID::kA3, CSSValueID::kA4, CSSValueID::kA5, CSSValueID::kB4,
      CSSValueID::kB5, CSSValueID::kJisB5, CSSValueID::kJisB4,
      CSSValueID::kLedger, CSSValueID::kLegal, CSSValueID::kLetter>(stream);
}

static float MmToPx(float mm) {
  return mm * kCssPixelsPerMillimeter;
}
static float InchToPx(float inch) {
  return inch * kCssPixelsPerInch;
}
static gfx::SizeF GetPageSizeFromName(
    const CSSIdentifierValue& page_size_name) {
  switch (page_size_name.GetValueID()) {
    case CSSValueID::kA5:
      return gfx::SizeF(MmToPx(148), MmToPx(210));
    case CSSValueID::kA4:
      return gfx::SizeF(MmToPx(210), MmToPx(297));
    case CSSValueID::kA3:
      return gfx::SizeF(MmToPx(297), MmToPx(420));
    case CSSValueID::kB5:
      return gfx::SizeF(MmToPx(176), MmToPx(250));
    case CSSValueID::kB4:
      return gfx::SizeF(MmToPx(250), MmToPx(353));
    case CSSValueID::kJisB5:
      return gfx::SizeF(MmToPx(182), MmToPx(257));
    case CSSValueID::kJisB4:
      return gfx::SizeF(MmToPx(257), MmToPx(364));
    case CSSValueID::kLetter:
      return gfx::SizeF(InchToPx(8.5), InchToPx(11));
    case CSSValueID::kLegal:
      return gfx::SizeF(InchToPx(8.5), InchToPx(14));
    case CSSValueID::kLedger:
      return gfx::SizeF(InchToPx(11), InchToPx(17));
    default:
      NOTREACHED();
  }
}

const CSSValue* Size::ParseSingleValue(CSSParserTokenStream& stream,
                                       const CSSParserContext& context,
                                       const CSSParserLocalContext&) const {
  CSSValueList* result = CSSValueList::CreateSpaceSeparated();

  if (stream.Peek().Id() == CSSValueID::kAuto) {
    result->Append(*css_parsing_utils::ConsumeIdent(stream));
    return result;
  }

  if (CSSValue* width = css_parsing_utils::ConsumeLength(
          stream, context, CSSPrimitiveValue::ValueRange::kNonNegative)) {
    CSSValue* height = css_parsing_utils::ConsumeLength(
        stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
    result->Append(*width);
    if (height) {
      result->Append(*height);
    }
    return result;
  }

  CSSValue* page_size = ConsumePageSize(stream);
  CSSValue* orientation =
      css_parsing_utils::ConsumeIdent<CSSValueID::kPortrait,
                                      CSSValueID::kLandscape>(stream);
  if (!page_size) {
    page_size = ConsumePageSize(stream);
  }

  if (!orientation && !page_size) {
    return nullptr;
  }
  if (page_size) {
    result->Append(*page_size);
  }
  if (orientation) {
    result->Append(*orientation);
  }
  return result;
}

void Size::ApplyInitial(StyleResolverState& state) const {}

void Size::ApplyInherit(StyleResolverState& state) const {}

void Size::ApplyValue(StyleResolverState& state,
                      const CSSValue& value,
                      ValueMode) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  builder.ResetPageSizeType();
  gfx::SizeF size;
  PageSizeType page_size_type = PageSizeType::kAuto;
  const auto& list = To<CSSValueList>(value);
  if (list.length() == 2) {
    // <length>{2} | <page-size> <orientation>
    const CSSValue& first = list.Item(0);
    const CSSValue& second = list.Item(1);
    auto* first_primitive_value = DynamicTo<CSSPrimitiveValue>(first);
    if (first_primitive_value && first_primitive_value->IsLength()) {
      CSSToLengthConversionData unzoomed_conversion_data =
          state.CssToLengthConversionData().Unzoomed();
      // <length>{2}
      size = gfx::SizeF(
          first_primitive_value->ComputeLength<float>(unzoomed_conversion_data),
          To<CSSPrimitiveValue>(second).ComputeLength<float>(
              unzoomed_conversion_data));
    } else {
      // <page-size> <orientation>
      size = GetPageSizeFromName(To<CSSIdentifierValue>(first));

      DCHECK(To<CSSIdentifierValue>(second).GetValueID() ==
                 CSSValueID::kLandscape ||
             To<CSSIdentifierValue>(second).GetValueID() ==
                 CSSValueID::kPortrait);
      if (To<CSSIdentifierValue>(second).GetValueID() ==
          CSSValueID::kLandscape) {
        size.Transpose();
      }
    }
    page_size_type = PageSizeType::kFixed;
  } else {
    DCHECK_EQ(list.length(), 1U);
    // <length> | auto | <page-size> | [ portrait | landscape]
    const CSSValue& first = list.Item(0);
    auto* first_primitive_value = DynamicTo<CSSPrimitiveValue>(first);
    if (first_primitive_value && first_primitive_value->IsLength()) {
      // <length>
      page_size_type = PageSizeType::kFixed;
      float width = first_primitive_value->ComputeLength<float>(
          state.CssToLengthConversionData().Unzoomed());
      size = gfx::SizeF(width, width);
    } else {
      const auto& ident = To<CSSIdentifierValue>(first);
      switch (ident.GetValueID()) {
        case CSSValueID::kAuto:
          page_size_type = PageSizeType::kAuto;
          break;
        case CSSValueID::kPortrait:
          page_size_type = PageSizeType::kPortrait;
          break;
        case CSSValueID::kLandscape:
          page_size_type = PageSizeType::kLandscape;
          break;
        default:
          // <page-size>
          page_size_type = PageSizeType::kFixed;
          size = GetPageSizeFromName(ident);
      }
    }
  }
  builder.SetPageSizeType(page_size_type);
  builder.SetPageSize(size);
}

const CSSValue* Speak::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.Speak());
}

const CSSValue* StopColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeColor(stream, context);
}

const blink::Color StopColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  const StyleColor& stop_color = style.StopColor();
  if (style.ShouldForceColor(stop_color)) {
    return style.GetInternalForcedCurrentColor(is_current_color);
  }
  return style.ResolvedColor(stop_color, is_current_color);
}

const CSSValue* StopColor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::CurrentColorOrValidColor(style, style.StopColor(),
                                                      value_phase);
}

const CSSValue* StopOpacity::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeAlphaValue(stream, context);
}

const CSSValue* StopOpacity::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSNumericLiteralValue::Create(style.StopOpacity(),
                                        CSSPrimitiveValue::UnitType::kNumber);
}

const CSSValue* Stroke::ParseSingleValue(CSSParserTokenStream& stream,
                                         const CSSParserContext& context,
                                         const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeSVGPaint(stream, context);
}

const CSSValue* Stroke::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForSVGPaint(style.StrokePaint(), style);
}

const blink::Color Stroke::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(!visited_link);
  DCHECK(style.StrokePaint().HasColor());
  const StyleColor& stroke_color = style.StrokePaint().GetColor();
  if (style.ShouldForceColor(stroke_color)) {
    return style.GetInternalForcedCurrentColor(is_current_color);
  }
  return stroke_color.Resolve(style.GetCurrentColor(), style.UsedColorScheme(),
                              is_current_color);
}

void Stroke::ApplyValue(StyleResolverState& state,
                        const CSSValue& value,
                        ValueMode) const {
  state.StyleBuilder().SetStrokePaint(StyleBuilderConverter::ConvertSVGPaint(
      state, value, false, PropertyID()));
}

const CSSValue* StrokeDasharray::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  // Syntax: comma- or whitespace-separated list of <length-or-percent>
  CSSValueID id = stream.Peek().Id();
  if (id == CSSValueID::kNone) {
    return css_parsing_utils::ConsumeIdent(stream);
  }

  CSSParserContext::ParserModeOverridingScope scope(context, kSVGAttributeMode);
  CSSValueList* dashes = CSSValueList::CreateCommaSeparated();
  bool need_next_value = true;
  for (;;) {
    CSSPrimitiveValue* dash = css_parsing_utils::ConsumeLengthOrPercent(
        stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
    if (!dash) {
      if (need_next_value) {
        return nullptr;
      } else {
        break;
      }
    }
    dashes->Append(*dash);
    need_next_value =
        css_parsing_utils::ConsumeCommaIncludingWhitespace(stream);
  }
  return dashes;
}

const CSSValue* StrokeDasharray::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::StrokeDashArrayToCSSValueList(
      *style.StrokeDashArray(), style);
}

const CSSValue* StrokeDashoffset::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSParserContext::ParserModeOverridingScope scope(context, kSVGAttributeMode);
  return css_parsing_utils::ConsumeLengthOrPercent(
      stream, context, CSSPrimitiveValue::ValueRange::kAll,
      css_parsing_utils::UnitlessQuirk::kForbid);
}

const CSSValue* StrokeDashoffset::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
      style.StrokeDashOffset(), style);
}

const CSSValue* StrokeLinecap::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.CapStyle());
}

const CSSValue* StrokeLinejoin::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.JoinStyle());
}

const CSSValue* StrokeMiterlimit::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeNumber(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
}

const CSSValue* StrokeMiterlimit::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSNumericLiteralValue::Create(style.StrokeMiterLimit(),
                                        CSSPrimitiveValue::UnitType::kNumber);
}

const CSSValue* StrokeOpacity::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeAlphaValue(stream, context);
}

const CSSValue* StrokeOpacity::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSNumericLiteralValue::Create(style.StrokeOpacity(),
                                        CSSPrimitiveValue::UnitType::kNumber);
}

const CSSValue* StrokeWidth::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSParserContext::ParserModeOverridingScope scope(context, kSVGAttributeMode);
  return css_parsing_utils::ConsumeLengthOrPercent(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative,
      css_parsing_utils::UnitlessQuirk::kForbid);
}

const CSSValue* StrokeWidth::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  // We store the unzoomed stroke-width value using ConvertUnzoomedLength().
  // Don't apply zoom here either.
  return CSSValue::Create(style.StrokeWidth().length(), 1);
}

const CSSValue* ContentVisibility::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.ContentVisibility());
}

const CSSValue* ContentVisibility::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeIdent<
      CSSValueID::kVisible, CSSValueID::kAuto, CSSValueID::kHidden>(stream);
}

const CSSValue* TabSize::ParseSingleValue(CSSParserTokenStream& stream,
                                          const CSSParserContext& context,
                                          const CSSParserLocalContext&) const {
  CSSPrimitiveValue* parsed_value = css_parsing_utils::ConsumeNumber(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
  if (parsed_value) {
    return parsed_value;
  }
  return css_parsing_utils::ConsumeLength(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
}

const CSSValue* TabSize::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSNumericLiteralValue::Create(
      style.GetTabSize().GetPixelSize(1.0),
      style.GetTabSize().IsSpaces() ? CSSPrimitiveValue::UnitType::kNumber
                                    : CSSPrimitiveValue::UnitType::kPixels);
}

const CSSValue* TableLayout::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.TableLayout());
}

const CSSValue* TextAlign::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.GetTextAlign());
}

void TextAlign::ApplyValue(StyleResolverState& state,
                           const CSSValue& value,
                           ValueMode) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  const auto* ident_value = DynamicTo<CSSIdentifierValue>(value);
  if (ident_value &&
      ident_value->GetValueID() != CSSValueID::kWebkitMatchParent) {
    // Special case for th elements - UA stylesheet text-align does not apply
    // if parent's computed value for text-align is not its initial value
    // https://html.spec.whatwg.org/C/#tables-2
    if (ident_value->GetValueID() == CSSValueID::kInternalCenter &&
        state.ParentStyle()->GetTextAlign() !=
            ComputedStyleInitialValues::InitialTextAlign()) {
      builder.SetTextAlign(state.ParentStyle()->GetTextAlign());
    } else {
      builder.SetTextAlign(ident_value->ConvertTo<ETextAlign>());
    }
  } else if (state.ParentStyle()->GetTextAlign() == ETextAlign::kStart) {
    builder.SetTextAlign(state.ParentStyle()->IsLeftToRightDirection()
                             ? ETextAlign::kLeft
                             : ETextAlign::kRight);
  } else if (state.ParentStyle()->GetTextAlign() == ETextAlign::kEnd) {
    builder.SetTextAlign(state.ParentStyle()->IsLeftToRightDirection()
                             ? ETextAlign::kRight
                             : ETextAlign::kLeft);
  } else {
    builder.SetTextAlign(state.ParentStyle()->GetTextAlign());
  }
}

const CSSValue* TextAlignLast::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.TextAlignLast());
}

const CSSValue* TextAnchor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.TextAnchor());
}

const CSSValue* TextAutospace::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.TextAutospace());
}

const CSSValue* TextBoxEdge::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const blink::TextBoxEdge& text_box_edge = style.GetTextBoxEdge();
  if (text_box_edge.IsUnderDefault()) {
    return CSSIdentifierValue::Create(text_box_edge.Over());
  }

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  list->Append(*CSSIdentifierValue::Create(text_box_edge.Over()));
  list->Append(*CSSIdentifierValue::Create(text_box_edge.Under()));
  return list;
}

const CSSValue* TextBoxEdge::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeTextBoxEdge(stream);
}

const CSSValue* TextBoxTrim::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.TextBoxTrim());
}

const CSSValue* TextCombineUpright::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.TextCombine());
}

const CSSValue* TextDecorationColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeColor(stream, context);
}

const blink::Color TextDecorationColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(!visited_link);
  const StyleColor& decoration_color =
      style.DecorationColorIncludingFallback(visited_link);
  if (style.ShouldForceColor(decoration_color)) {
    return style.GetInternalForcedCurrentColor(is_current_color);
  }
  return decoration_color.Resolve(style.GetCurrentColor(),
                                  style.UsedColorScheme(), is_current_color);
}

const CSSValue* TextDecorationColor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::CurrentColorOrValidColor(
      style, style.TextDecorationColor(), value_phase);
}

const CSSValue* TextDecorationLine::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext&,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeTextDecorationLine(stream);
}

const CSSValue* TextDecorationLine::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::RenderTextDecorationFlagsToCSSValue(
      style.GetTextDecorationLine());
}

const CSSValue* TextDecorationSkipInk::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForTextDecorationSkipInk(
      style.TextDecorationSkipInk());
}

const CSSValu
"""


```