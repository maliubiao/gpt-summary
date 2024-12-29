Response:
The user wants me to analyze a C++ source code file from the Chromium Blink engine. Specifically, they want me to describe its functionality, its relation to web technologies (JavaScript, HTML, CSS), provide examples of its use, discuss potential user/programming errors, outline how a user action might lead to this code being executed, and summarize its purpose. This is the third of five parts of the file, so the summary should focus on the functions within this snippet.

Here's a breakdown of how I'll approach this:

1. **Functionality:** I'll examine each function in the provided code snippet and describe what it does. The names of the functions are generally quite descriptive (e.g., `ConvertBorderWidth`, `ConvertLength`, `ConvertColor`). I'll focus on the input types (CSS values) and the output types (Blink internal representations).

2. **Relation to Web Technologies:**  I'll identify which functions directly correspond to CSS properties or concepts. For example, `ConvertBorderWidth` clearly relates to the `border-width` CSS property, and `ConvertLength` deals with CSS length units. I'll try to connect these C++ functions to how they affect the rendering of HTML elements styled with CSS.

3. **Examples:** For each relevant function, I'll create hypothetical CSS input and the corresponding output value in Blink's internal representation. This will illustrate the conversion process.

4. **User/Programming Errors:** I'll think about common mistakes users or developers might make when specifying CSS values that could lead to errors or unexpected behavior in these conversion functions. For instance, providing an invalid unit for a length or an incorrect keyword.

5. **User Action and Debugging:** I'll trace a simple user interaction (like setting a CSS style) that would trigger the CSS resolution process and eventually involve these conversion functions. This helps understand the context of this code within the broader browser architecture.

6. **Summary:** I'll synthesize the information gathered to provide a concise summary of the functionality of the code in this specific part of the file.

**Mental Sandbox:**

* **`ConvertHyphensLimitChars`:** Takes a CSS value, likely a list of numbers or `auto`, and converts it to a `StyleHyphenateLimitChars` struct.
    * *Web Technology:* Relates to the `hyphens-limit-chars` CSS property.
    * *Example:* Input: `3 auto 5`, Output: `StyleHyphenateLimitChars(3, 0, 5)`.
* **`ConvertBorderWidth`:** Handles `thin`, `medium`, `thick` keywords and length values for `border-width`.
    * *Web Technology:* Directly related to the `border-width` CSS property.
    * *Example:* Input: `thin`, Output: `1` (pixel value after zoom). Input: `2px`, Output: `2`.
* **`ConvertLayoutUnit`:** Converts a CSS length to a `LayoutUnit`, used for layout calculations.
    * *Web Technology:*  Generic conversion for layout-related CSS properties.
    * *Example:* Input: `10px`, Output: `LayoutUnit(10)`.
* **`ConvertGapLength`:** Converts length values for grid/flexbox gaps, handling the `normal` keyword.
    * *Web Technology:* Related to `row-gap`, `column-gap`.
    * *Example:* Input: `10px`, Output: `Length(10, kFixed)`. Input: `normal`, Output: `std::nullopt`.
* **`ConvertLength`:**  Basic conversion of CSS lengths to the `Length` type.
    * *Web Technology:* Fundamental for handling all CSS length values.
    * *Example:* Input: `1em`, Output: `Length` representing 1em.
* **`ConvertUnzoomedLength`:** Similar to `ConvertLength`, but for unzoomed lengths.
* **`ConvertZoom`:** Handles the `zoom` property, converting percentages and numbers.
    * *Web Technology:*  Related to the non-standard `zoom` CSS property.
    * *Example:* Input: `150%`, Output: `1.5`. Input: `normal`, Output: Initial zoom value.
* **`ConvertLengthOrAuto`:** Converts to `Length`, handling the `auto` keyword.
    * *Web Technology:* Common for properties like `width`, `height`.
    * *Example:* Input: `auto`, Output: `Length::Auto()`. Input: `50%`, Output: `Length::Percent(50)`.
* **`ConvertScrollStart`:**  Converts values for scroll start properties (`scroll-start-x`, `scroll-start-y`).
* **`ConvertLengthSizing`:**  Handles keywords like `min-content`, `max-content`, `stretch` for sizing properties.
    * *Web Technology:*  Used for properties like `width`, `height` in grid/flexbox.
    * *Example:* Input: `min-content`, Output: `Length::MinContent()`.
* **`ConvertLengthMaxSizing`:** Similar to `ConvertLengthSizing`, but also handles `none`.
* **`ConvertLengthOrTabSpaces`:** Converts values for the `tab-size` property.
* **`ConvertLineHeight`:**  Handles various values for `line-height`, including numbers (interpreted as multipliers), lengths, and percentages.
    * *Web Technology:* Directly related to the `line-height` CSS property.
    * *Example:* Input: `1.5`, Output: `Length::Percent(150)`. Input: `20px`, Output: `Length::Fixed(20)`.
* **`ConvertNumberOrPercentage`:**  Converts a CSS number or percentage to a float.
* **`ConvertInteger`:** Converts a CSS integer value to an `int`.
* **`ConvertAlpha`:** Converts a number or percentage to a float, clamped between 0 and 1.
* **`ConvertNoneOrCustomIdent`, `ConvertNormalOrCustomIdent`, `ConvertCustomIdent`, `ConvertPositionAnchor`:** Handle custom identifiers, potentially related to CSS variables or specific features.
* **`ConvertPositionVisibility`:** Converts keywords for the `position-visibility` property.
* **`ConvertAnchorName`, `ConvertAnchorScope`:**  Handle values related to CSS anchor positioning.
* **`ConvertInitialLetter`:** Converts values for the `initial-letter` property.
* **`ConvertOffsetRotate`:** Handles values for `offset-rotate`.
* **`ConvertPosition`, `ConvertPositionOrAuto`, `ConvertOffsetPosition`:** Deal with parsing values for positioning properties.
* **`ConvertPerspective`:** Converts values for the `perspective` property.
* **`ConvertPaintOrder`:**  Handles the `paint-order` property.
* **`ConvertQuirkyLength`:** Handles lengths with a specific quirk, likely for compatibility.
* **`ConvertQuotes`:**  Parses the `quotes` property.
* **`ConvertRadius`:**  Handles radius values, often for rounded corners.
* **`ConvertGapDecorationPropertyValue`, `ConvertGapDecorationDataList`, `ConvertGapDecorationColorDataList`, `ConvertGapDecorationWidthDataList`:**  Deal with the experimental CSS Gap Decorations feature.
* **`ConvertShadow`, `ConvertShadowList`:**  Parse `box-shadow` and `text-shadow` values.
* **`ConvertShapeValue`:** Handles values for `shape-outside` and `shape-inside`.
* **`ConvertSpacing`:** Converts values for properties like `word-spacing` and `letter-spacing`.
* **`ConvertStrokeDasharray`:**  Parses the `stroke-dasharray` property for SVG.
* **`ConvertViewTransitionGroup`, `ConvertViewTransitionCaptureMode`, `ConvertViewTransitionName`, `ConvertViewTransitionClass`:** Handle the experimental CSS View Transitions API.

Planning complete. I will now generate the response based on these considerations.

```cpp
eInteger(state.CssToLengthConversionData()));
      continue;
    }
    if (const auto* ident = DynamicTo<CSSIdentifierValue>(item.Get())) {
      DCHECK_EQ(ident->GetValueID(), CSSValueID::kAuto);
      values.push_back(0);
      continue;
    }
    NOTREACHED();
  }
  values.Grow(3);
  return StyleHyphenateLimitChars(values[0], values[1], values[2]);
}

int StyleBuilderConverter::ConvertBorderWidth(StyleResolverState& state,
                                              const CSSValue& value) {
  double result = 0;

  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    switch (identifier_value->GetValueID()) {
      case CSSValueID::kThin:
        result = 1;
        break;
      case CSSValueID::kMedium:
        result = 3;
        break;
      case CSSValueID::kThick:
        result = 5;
        break;
      default:
        NOTREACHED();
    }

    result = state.CssToLengthConversionData().ZoomedComputedPixels(
        result, CSSPrimitiveValue::UnitType::kPixels);
  } else {
    const auto& primitive_value = To<CSSPrimitiveValue>(value);
    result =
        primitive_value.ComputeLength<float>(state.CssToLengthConversionData());
  }

  if (result > 0.0 && result < 1.0) {
    return 1;
  }

  // Clamp the result to a reasonable range for layout.
  return ClampTo<int>(floor(result), 0, LayoutUnit::Max().ToInt());
}

LayoutUnit StyleBuilderConverter::ConvertLayoutUnit(
    const StyleResolverState& state,
    const CSSValue& value) {
  return LayoutUnit::Clamp(ConvertComputedLength<float>(state, value));
}

std::optional<Length> StyleBuilderConverter::ConvertGapLength(
    const StyleResolverState& state,
    const CSSValue& value) {
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (identifier_value &&
      identifier_value->GetValueID() == CSSValueID::kNormal) {
    return std::nullopt;
  }

  return ConvertLength(state, value);
}

Length StyleBuilderConverter::ConvertLength(const StyleResolverState& state,
                                            const CSSValue& value) {
  return To<CSSPrimitiveValue>(value).ConvertToLength(
      state.CssToLengthConversionData());
}

UnzoomedLength StyleBuilderConverter::ConvertUnzoomedLength(
    StyleResolverState& state,
    const CSSValue& value) {
  return UnzoomedLength(To<CSSPrimitiveValue>(value).ConvertToLength(
      state.UnzoomedLengthConversionData()));
}

float StyleBuilderConverter::ConvertZoom(const StyleResolverState& state,
                                         const CSSValue& value) {
  SECURITY_DCHECK(value.IsPrimitiveValue() || value.IsIdentifierValue());

  if (const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    if (identifier_value->GetValueID() == CSSValueID::kNormal) {
      return ComputedStyleInitialValues::InitialZoom();
    }
  } else if (const auto* primitive_value =
                 DynamicTo<CSSPrimitiveValue>(value)) {
    if (primitive_value->IsPercentage()) {
      float percent =
          primitive_value->ComputePercentage(state.CssToLengthConversionData());
      return percent ? (percent / 100.0f) : 1.0f;
    } else if (primitive_value->IsNumber()) {
      float number =
          primitive_value.ComputeNumber(state.CssToLengthConversionData());
      return number ? number : 1.0f;
    }
  }

  NOTREACHED();
}

Length StyleBuilderConverter::ConvertLengthOrAuto(
    const StyleResolverState& state,
    const CSSValue& value) {
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (identifier_value && identifier_value->GetValueID() == CSSValueID::kAuto) {
    return Length::Auto();
  }
  return To<CSSPrimitiveValue>(value).ConvertToLength(
      state.CssToLengthConversionData());
}

ScrollStartData StyleBuilderConverter::ConvertScrollStart(
    const StyleResolverState& state,
    const CSSValue& value) {
  ScrollStartData scroll_start_data;
  if (value.IsPrimitiveValue()) {
    scroll_start_data.value_type = ScrollStartValueType::kLengthOrPercentage;
    scroll_start_data.value = To<CSSPrimitiveValue>(value).ConvertToLength(
        state.CssToLengthConversionData());
    return scroll_start_data;
  }
  scroll_start_data.value_type =
      To<CSSIdentifierValue>(value).ConvertTo<ScrollStartValueType>();
  return scroll_start_data;
}

Length StyleBuilderConverter::ConvertLengthSizing(StyleResolverState& state,
                                                  const CSSValue& value) {
  const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (!identifier_value) {
    return ConvertLength(state, value);
  }

  switch (identifier_value->GetValueID()) {
    case CSSValueID::kMinContent:
    case CSSValueID::kWebkitMinContent:
      return Length::MinContent();
    case CSSValueID::kMaxContent:
    case CSSValueID::kWebkitMaxContent:
      return Length::MaxContent();
    case CSSValueID::kStretch:
    case CSSValueID::kWebkitFillAvailable:
      return Length::Stretch();
    case CSSValueID::kWebkitFitContent:
    case CSSValueID::kFitContent:
      return Length::FitContent();
    case CSSValueID::kContent:
      return Length::Content();
    case CSSValueID::kAuto:
      return Length::Auto();
    default:
      NOTREACHED();
  }
}

Length StyleBuilderConverter::ConvertLengthMaxSizing(StyleResolverState& state,
                                                     const CSSValue& value) {
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (identifier_value && identifier_value->GetValueID() == CSSValueID::kNone) {
    return Length::None();
  }
  return ConvertLengthSizing(state, value);
}

TabSize StyleBuilderConverter::ConvertLengthOrTabSpaces(
    StyleResolverState& state,
    const CSSValue& value) {
  const auto& primitive_value = To<CSSPrimitiveValue>(value);
  if (primitive_value.IsNumber()) {
    return TabSize(
        primitive_value.ComputeNumber(state.CssToLengthConversionData()),
        TabSizeValueType::kSpace);
  }
  return TabSize(
      primitive_value.ComputeLength<float>(state.CssToLengthConversionData()),
      TabSizeValueType::kLength);
}

static CSSToLengthConversionData LineHeightToLengthConversionData(
    StyleResolverState& state) {
  float multiplier = state.StyleBuilder().EffectiveZoom();
  if (LocalFrame* frame = state.GetDocument().GetFrame()) {
    multiplier *= frame->TextZoomFactor();
  }

  if (!state.StyleBuilder().GetTextSizeAdjust().IsAuto()) {
    if (RuntimeEnabledFeatures::TextSizeAdjustImprovementsEnabled()) {
      Settings* settings = state.GetDocument().GetSettings();
      if (settings && settings->GetTextAutosizingEnabled()) {
        multiplier *= state.StyleBuilder().GetTextSizeAdjust().Multiplier();
      }
    }
  }
  return state.CssToLengthConversionData().CopyWithAdjustedZoom(multiplier);
}

Length StyleBuilderConverter::ConvertLineHeight(StyleResolverState& state,
                                                const CSSValue& value) {
  if (const auto* primitive_value = DynamicTo<CSSPrimitiveValue>(value)) {
    if (primitive_value->IsLength()) {
      return primitive_value->ComputeLength<Length>(
          LineHeightToLengthConversionData(state));
    }
    if (primitive_value->IsNumber()) {
      return Length::Percent(
          ClampTo<float>(primitive_value->ComputeNumber(
                             LineHeightToLengthConversionData(state)) *
                         100.0));
    }
    float computed_font_size =
        state.StyleBuilder().GetFontDescription().ComputedSize();
    if (primitive_value->IsPercentage()) {
      return Length::Fixed(
          (computed_font_size * ClampTo<int>(primitive_value->ComputePercentage(
                                    LineHeightToLengthConversionData(state)))) /
          100.0);
    }
    if (primitive_value->IsCalculated()) {
      Length zoomed_length =
          Length(To<CSSMathFunctionValue>(primitive_value)
                     ->ToCalcValue(LineHeightToLengthConversionData(state)));
      return Length::Fixed(
          ValueForLength(zoomed_length, LayoutUnit(computed_font_size)));
    }
  }

  if (value.IsPendingSystemFontValue()) {
    return ComputedStyleInitialValues::InitialLineHeight();
  }

  DCHECK_EQ(To<CSSIdentifierValue>(value).GetValueID(), CSSValueID::kNormal);
  return ComputedStyleInitialValues::InitialLineHeight();
}

float StyleBuilderConverter::ConvertNumberOrPercentage(
    StyleResolverState& state,
    const CSSValue& value) {
  const auto& primitive_value = To<CSSPrimitiveValue>(value);
  DCHECK(primitive_value.IsNumber() || primitive_value.IsPercentage());
  if (primitive_value.IsNumber()) {
    return primitive_value.GetFloatValue();
  }
  return primitive_value.GetFloatValue() / 100.0f;
}

int StyleBuilderConverter::ConvertInteger(StyleResolverState& state,
                                          const CSSValue& value) {
  return To<CSSPrimitiveValue>(value).ComputeInteger(
      state.CssToLengthConversionData());
}

float StyleBuilderConverter::ConvertAlpha(StyleResolverState& state,
                                          const CSSValue& value) {
  return ClampTo<float>(ConvertNumberOrPercentage(state, value), 0, 1);
}

ScopedCSSName* StyleBuilderConverter::ConvertNoneOrCustomIdent(
    StyleResolverState& state,
    const CSSValue& value) {
  DCHECK(value.IsScopedValue());
  if (const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(identifier_value->GetValueID(), CSSValueID::kNone);
    return nullptr;
  }
  return ConvertCustomIdent(state, value);
}

ScopedCSSName* StyleBuilderConverter::ConvertNormalOrCustomIdent(
    StyleResolverState& state,
    const CSSValue& value) {
  DCHECK(value.IsScopedValue());
  if (const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(identifier_value->GetValueID(), CSSValueID::kNormal);
    return nullptr;
  }
  return ConvertCustomIdent(state, value);
}

ScopedCSSName* StyleBuilderConverter::ConvertCustomIdent(
    StyleResolverState& state,
    const CSSValue& value) {
  state.SetHasTreeScopedReference();
  const CSSCustomIdentValue& custom_ident = To<CSSCustomIdentValue>(value);
  return MakeGarbageCollected<ScopedCSSName>(custom_ident.Value(),
                                             custom_ident.GetTreeScope());
}

ScopedCSSName* StyleBuilderConverter::ConvertPositionAnchor(
    StyleResolverState& state,
    const CSSValue& value) {
  DCHECK(value.IsScopedValue());
  if (const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(identifier_value->GetValueID(), CSSValueID::kAuto);
    return nullptr;
  }
  return ConvertCustomIdent(state, value);
}

PositionVisibility StyleBuilderConverter::ConvertPositionVisibility(
    StyleResolverState& state,
    const CSSValue& value) {
  PositionVisibility flags = PositionVisibility::kAlways;

  auto process = [&flags](const CSSValue& identifier) {
    flags |= To<CSSIdentifierValue>(identifier).ConvertTo<PositionVisibility>();
  };
  if (auto* value_list = DynamicTo<CSSValueList>(value)) {
    for (auto& entry : *value_list) {
      process(*entry);
    }
  } else {
    process(value);
  }
  return flags;
}

ScopedCSSNameList* StyleBuilderConverter::ConvertAnchorName(
    StyleResolverState& state,
    const CSSValue& value) {
  DCHECK(value.IsScopedValue());
  if (const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(identifier_value->GetValueID(), CSSValueID::kNone);
    return nullptr;
  }
  DCHECK(value.IsBaseValueList());
  HeapVector<Member<const ScopedCSSName>> names;
  for (const Member<const CSSValue>& item : To<CSSValueList>(value)) {
    names.push_back(ConvertCustomIdent(state, *item));
  }
  return MakeGarbageCollected<ScopedCSSNameList>(std::move(names));
}

StyleAnchorScope StyleBuilderConverter::ConvertAnchorScope(
    StyleResolverState& state,
    const CSSValue& value) {
  CHECK(value.IsScopedValue());
  if (const auto* scoped_keyword_value =
          DynamicTo<cssvalue::CSSScopedKeywordValue>(value)) {
    CHECK_EQ(scoped_keyword_value->GetValueID(), CSSValueID::kAll);
    state.SetHasTreeScopedReference();
    return StyleAnchorScope(StyleAnchorScope::Type::kAll,
                            scoped_keyword_value->GetTreeScope(),
                            /* names */ nullptr);
  }
  if (const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    CHECK_EQ(identifier_value->GetValueID(), CSSValueID::kNone);
    return StyleAnchorScope();
  }
  CHECK(value.IsBaseValueList());
  HeapVector<Member<const ScopedCSSName>> names;
  for (const Member<const CSSValue>& item : To<CSSValueList>(value)) {
    names.push_back(ConvertCustomIdent(state, *item));
  }
  return StyleAnchorScope(
      StyleAnchorScope::Type::kNames, /* all_tree_scope */ nullptr,
      /* names */ MakeGarbageCollected<ScopedCSSNameList>(std::move(names)));
}

StyleInitialLetter StyleBuilderConverter::ConvertInitialLetter(
    StyleResolverState& state,
    const CSSValue& value) {
  if (auto* normal_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(normal_value->GetValueID(), CSSValueID::kNormal);
    return StyleInitialLetter::Normal();
  }

  const auto& list = To<CSSValueList>(value);
  DCHECK(list.length() == 1 || list.length() == 2);
  const float size = To<CSSPrimitiveValue>(list.Item(0))
                         .ComputeNumber(state.CssToLengthConversionData());
  DCHECK_GE(size, 1);
  if (list.length() == 1) {
    return StyleInitialLetter(size);
  }

  const CSSValue& second = list.Item(1);
  if (auto* sink_type = DynamicTo<CSSIdentifierValue>(second)) {
    if (sink_type->GetValueID() == CSSValueID::kDrop) {
      return StyleInitialLetter::Drop(size);
    }
    if (sink_type->GetValueID() == CSSValueID::kRaise) {
      return StyleInitialLetter::Raise(size);
    }
    NOTREACHED() << "Unexpected sink type " << sink_type;
  }

  if (auto* sink = DynamicTo<CSSPrimitiveValue>(second)) {
    DCHECK_GE(sink->ComputeNumber(state.CssToLengthConversionData()), 1);
    return StyleInitialLetter(
        size, sink->ComputeNumber(state.CssToLengthConversionData()));
  }

  return StyleInitialLetter::Normal();
}

StyleOffsetRotation StyleBuilderConverter::ConvertOffsetRotate(
    StyleResolverState& state,
    const CSSValue& value) {
  return ConvertOffsetRotate(state.CssToLengthConversionData(), value);
}

StyleOffsetRotation StyleBuilderConverter::ConvertOffsetRotate(
    const CSSLengthResolver& length_resolver,
    const CSSValue& value) {
  StyleOffsetRotation result(0, OffsetRotationType::kFixed);

  if (auto* identifier = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(identifier->GetValueID(), CSSValueID::kAuto);
    result.type = OffsetRotationType::kAuto;
    return result;
  }

  const auto& list = To<CSSValueList>(value);
  DCHECK(list.length() == 1 || list.length() == 2);
  for (const auto& item : list) {
    auto* identifier_value = DynamicTo<CSSIdentifierValue>(item.Get());
    if (identifier_value &&
        identifier_value->GetValueID() == CSSValueID::kAuto) {
      result.type = OffsetRotationType::kAuto;
    } else if (identifier_value &&
               identifier_value->GetValueID() == CSSValueID::kReverse) {
      result.type = OffsetRotationType::kAuto;
      result.angle = ClampTo<float>(result.angle + 180);
    } else {
      const auto& primitive_value = To<CSSPrimitiveValue>(*item);
      result.angle = ClampTo<float>(
          result.angle + primitive_value.ComputeDegrees(length_resolver));
    }
  }

  return result;
}

LengthPoint StyleBuilderConverter::ConvertPosition(StyleResolverState& state,
                                                   const CSSValue& value) {
  const auto& pair = To<CSSValuePair>(value);
  return LengthPoint(
      ConvertPositionLength<CSSValueID::kLeft, CSSValueID::kRight>(
          state, pair.First()),
      ConvertPositionLength<CSSValueID::kTop, CSSValueID::kBottom>(
          state, pair.Second()));
}

LengthPoint StyleBuilderConverter::ConvertPositionOrAuto(
    StyleResolverState& state,
    const CSSValue& value) {
  if (value.IsValuePair()) {
    return ConvertPosition(state, value);
  }
  DCHECK(To<CSSIdentifierValue>(value).GetValueID() == CSSValueID::kAuto);
  return LengthPoint(Length::Auto(), Length::Auto());
}

LengthPoint StyleBuilderConverter::ConvertOffsetPosition(
    StyleResolverState& state,
    const CSSValue& value) {
  if (value.IsValuePair()) {
    return ConvertPosition(state, value);
  }
  if (To<CSSIdentifierValue>(value).GetValueID() == CSSValueID::kAuto) {
    return LengthPoint(Length::Auto(), Length::Auto());
  }
  return LengthPoint(Length::None(), Length::None());
}

static float ConvertPerspectiveLength(
    StyleResolverState& state,
    const CSSPrimitiveValue& primitive_value) {
  return std::max(
      primitive_value.ComputeLength<float>(state.CssToLengthConversionData()),
      0.0f);
}

float StyleBuilderConverter::ConvertPerspective(StyleResolverState& state,
                                                const CSSValue& value) {
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (identifier_value && identifier_value->GetValueID() == CSSValueID::kNone) {
    return ComputedStyleInitialValues::InitialPerspective();
  }
  return ConvertPerspectiveLength(state, To<CSSPrimitiveValue>(value));
}

EPaintOrder StyleBuilderConverter::ConvertPaintOrder(
    StyleResolverState&,
    const CSSValue& css_paint_order) {
  if (const auto* order_type_list = DynamicTo<CSSValueList>(css_paint_order)) {
    switch (To<CSSIdentifierValue>(order_type_list->Item(0)).GetValueID()) {
      case CSSValueID::kFill:
        return order_type_list->length() > 1 ? kPaintOrderFillMarkersStroke
                                             : kPaintOrderFillStrokeMarkers;
      case CSSValueID::kStroke:
        return order_type_list->length() > 1 ? kPaintOrderStrokeMarkersFill
                                             : kPaintOrderStrokeFillMarkers;
      case CSSValueID::kMarkers:
        return order_type_list->length() > 1 ? kPaintOrderMarkersStrokeFill
                                             : kPaintOrderMarkersFillStroke;
      default:
        NOTREACHED();
    }
  }

  return kPaintOrderNormal;
}

Length StyleBuilderConverter::ConvertQuirkyLength(StyleResolverState& state,
                                                  const CSSValue& value) {
  Length length = ConvertLengthOrAuto(state, value);
  // This is only for margins which use __qem
  auto* numeric_literal = DynamicTo<CSSNumericLiteralValue>(value);
  length.SetQuirk(numeric_literal && numeric_literal->IsQuirkyEms());
  return length;
}

scoped_refptr<QuotesData> StyleBuilderConverter::ConvertQuotes(
    StyleResolverState&,
    const CSSValue& value) {
  if (const auto* list = DynamicTo<CSSValueList>(value)) {
    scoped_refptr<QuotesData> quotes = QuotesData::Create();
    for (wtf_size_t i = 0; i < list->length(); i += 2) {
      String start_quote = To<CSSStringValue>(list->Item(i)).Value();
      String end_quote = To<CSSStringValue>(list->Item(i + 1)).Value();
      quotes->AddPair(std::make_pair(start_quote, end_quote));
    }
    return quotes;
  }
  if (To<CSSIdentifierValue>(value).GetValueID() == CSSValueID::kNone) {
    return QuotesData::Create();
  }
  DCHECK_EQ(To<CSSIdentifierValue>(value).GetValueID(), CSSValueID::kAuto);
  return nullptr;
}

LengthSize StyleBuilderConverter::ConvertRadius(StyleResolverState& state,
                                                const CSSValue& value) {
  const auto& pair = To<CSSValuePair>(value);
  Length radius_width = To<CSSPrimitiveValue>(pair.First())
                            .ConvertToLength(state.CssToLengthConversionData());
  Length radius_height =
      To<CSSPrimitiveValue>(pair.Second())
          .ConvertToLength(state.CssToLengthConversionData());
  return LengthSize(radius_width, radius_height);
}

template <typename T>
T ConvertGapDecorationPropertyValue(
    StyleResolverState& state,
    const CSSValue& value,
    bool for_visited_link = false);

template <>
StyleColor ConvertGapDecorationPropertyValue<StyleColor>(
    StyleResolverState& state,
    const CSSValue& value,
    bool for_visited_link) {
  return StyleBuilderConverter::ConvertStyleColor(state, value,
                                                  for_visited_link);
}

template <>
int ConvertGapDecorationPropertyValue<int>(StyleResolverState& state,
                                           const CSSValue& value,
                                           bool for_visited_link) {
  return ClampTo<uint16_t>(
      StyleBuilderConverter::ConvertBorderWidth(state, value));
}

template <typename T>
GapDataList<T> ConvertGapDecorationDataList(StyleResolverState& state,
                                            const CSSValue& value,
                                            bool for_visited_link = false) {
  // The `value` will not be a list in two scenarios:
  // 1. When using the legacy 'column-rule-*' properties.
  // 2. When the fast parse path is taken (see
  // CSSParserFastPaths::MaybeParseValue). In these cases, construct a
  // GapDataList with a single Value.
  if (!DynamicTo<CSSValueList>(value)) {
    return GapDataList<T>(
        ConvertGapDecorationPropertyValue<T>(state, value, for_visited_link));
  }
  CHECK(RuntimeEnabledFeatures::CSSGapDecorationEnabled());

  // The CSS Gap Decorations API accepts a space separated list of values.
  // These values can be an auto repeater, an integer repeater, or a single
  // value.
  // See: https://kbabbitt.github.io/css-gap-decorations/#column-row-rule-color
  const auto& values = To<CSSValueList>(value);
  typename GapDataList<T>::GapDataVector gap_data_list;
  gap_data_list.ReserveInitialCapacity(values.length());

  for (const auto& curr_value : values) {
    GapData<T> gap_data;
    if (auto* gap_repeat_value =
            DynamicTo<cssvalue::CSSRepeatValue>(curr_value.Get())) {
      typename ValueRepeater<T>::VectorType gap_values;
      gap_values.ReserveInitialCapacity(gap_repeat_value->Values().length());
      for (const auto& repeat_value : gap_repeat_value->Values()) {
        gap_values.push_back(ConvertGapDecorationPropertyValue<T>(
            state, *repeat_value, for_visited_link));
      }

      std::optional<int> repeat_count = std::nullopt;
      if (!gap_repeat_value->IsAutoRepeatValue()) {
        repeat_count = gap_repeat_value->Repetitions()->ComputeInteger(
            state.CssToLengthConversionData());
      }
      ValueRepeater<T>* value_repeater = value_repeater =
          MakeGarbageCollected<ValueRepeater<T>>(std::move(gap_values),
                                                 repeat_count);
      gap_data = GapData<T>(value_repeater);
    } else {
      gap_data = GapData<T>(ConvertGapDecorationPropertyValue<T>(
          state, *curr_value.Get(), for_visited_link));
    }

    gap_data_list.push_back(gap_data);
  }

  return GapDataList<T>(std::move(gap_data_list));
}

GapDataList<StyleColor>
StyleBuilderConverter::ConvertGapDecorationColorDataList(
    StyleResolverState& state,
    const CSSValue& value,
    bool for_visited_link) {
  return ConvertGapDecorationDataList<blink::StyleColor>(state, value,
                                                         for_visited_link);
}

GapDataList<int> StyleBuilderConverter::ConvertGapDecorationWidthDataList(
    StyleResolverState& state,
    const CSSValue& value) {
  return ConvertGapDecorationDataList<int>(state, value);
}

ShadowData StyleBuilderConverter::ConvertShadow(
    const CSSToLengthConversionData& conversion_data,
    StyleResolverState* state,
    const CSSValue& value) {
  const auto& shadow = To<CSSShadowValue>(value);
  const gfx::Vector2dF offset(shadow.x->ComputeLength<float>(conversion_data),
                              shadow.y
Prompt: 
```
这是目录为blink/renderer/core/css/resolver/style_builder_converter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能

"""
eInteger(state.CssToLengthConversionData()));
      continue;
    }
    if (const auto* ident = DynamicTo<CSSIdentifierValue>(item.Get())) {
      DCHECK_EQ(ident->GetValueID(), CSSValueID::kAuto);
      values.push_back(0);
      continue;
    }
    NOTREACHED();
  }
  values.Grow(3);
  return StyleHyphenateLimitChars(values[0], values[1], values[2]);
}

int StyleBuilderConverter::ConvertBorderWidth(StyleResolverState& state,
                                              const CSSValue& value) {
  double result = 0;

  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    switch (identifier_value->GetValueID()) {
      case CSSValueID::kThin:
        result = 1;
        break;
      case CSSValueID::kMedium:
        result = 3;
        break;
      case CSSValueID::kThick:
        result = 5;
        break;
      default:
        NOTREACHED();
    }

    result = state.CssToLengthConversionData().ZoomedComputedPixels(
        result, CSSPrimitiveValue::UnitType::kPixels);
  } else {
    const auto& primitive_value = To<CSSPrimitiveValue>(value);
    result =
        primitive_value.ComputeLength<float>(state.CssToLengthConversionData());
  }

  if (result > 0.0 && result < 1.0) {
    return 1;
  }

  // Clamp the result to a reasonable range for layout.
  return ClampTo<int>(floor(result), 0, LayoutUnit::Max().ToInt());
}

LayoutUnit StyleBuilderConverter::ConvertLayoutUnit(
    const StyleResolverState& state,
    const CSSValue& value) {
  return LayoutUnit::Clamp(ConvertComputedLength<float>(state, value));
}

std::optional<Length> StyleBuilderConverter::ConvertGapLength(
    const StyleResolverState& state,
    const CSSValue& value) {
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (identifier_value &&
      identifier_value->GetValueID() == CSSValueID::kNormal) {
    return std::nullopt;
  }

  return ConvertLength(state, value);
}

Length StyleBuilderConverter::ConvertLength(const StyleResolverState& state,
                                            const CSSValue& value) {
  return To<CSSPrimitiveValue>(value).ConvertToLength(
      state.CssToLengthConversionData());
}

UnzoomedLength StyleBuilderConverter::ConvertUnzoomedLength(
    StyleResolverState& state,
    const CSSValue& value) {
  return UnzoomedLength(To<CSSPrimitiveValue>(value).ConvertToLength(
      state.UnzoomedLengthConversionData()));
}

float StyleBuilderConverter::ConvertZoom(const StyleResolverState& state,
                                         const CSSValue& value) {
  SECURITY_DCHECK(value.IsPrimitiveValue() || value.IsIdentifierValue());

  if (const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    if (identifier_value->GetValueID() == CSSValueID::kNormal) {
      return ComputedStyleInitialValues::InitialZoom();
    }
  } else if (const auto* primitive_value =
                 DynamicTo<CSSPrimitiveValue>(value)) {
    if (primitive_value->IsPercentage()) {
      float percent =
          primitive_value->ComputePercentage(state.CssToLengthConversionData());
      return percent ? (percent / 100.0f) : 1.0f;
    } else if (primitive_value->IsNumber()) {
      float number =
          primitive_value->ComputeNumber(state.CssToLengthConversionData());
      return number ? number : 1.0f;
    }
  }

  NOTREACHED();
}

Length StyleBuilderConverter::ConvertLengthOrAuto(
    const StyleResolverState& state,
    const CSSValue& value) {
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (identifier_value && identifier_value->GetValueID() == CSSValueID::kAuto) {
    return Length::Auto();
  }
  return To<CSSPrimitiveValue>(value).ConvertToLength(
      state.CssToLengthConversionData());
}

ScrollStartData StyleBuilderConverter::ConvertScrollStart(
    const StyleResolverState& state,
    const CSSValue& value) {
  ScrollStartData scroll_start_data;
  if (value.IsPrimitiveValue()) {
    scroll_start_data.value_type = ScrollStartValueType::kLengthOrPercentage;
    scroll_start_data.value = To<CSSPrimitiveValue>(value).ConvertToLength(
        state.CssToLengthConversionData());
    return scroll_start_data;
  }
  scroll_start_data.value_type =
      To<CSSIdentifierValue>(value).ConvertTo<ScrollStartValueType>();
  return scroll_start_data;
}

Length StyleBuilderConverter::ConvertLengthSizing(StyleResolverState& state,
                                                  const CSSValue& value) {
  const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (!identifier_value) {
    return ConvertLength(state, value);
  }

  switch (identifier_value->GetValueID()) {
    case CSSValueID::kMinContent:
    case CSSValueID::kWebkitMinContent:
      return Length::MinContent();
    case CSSValueID::kMaxContent:
    case CSSValueID::kWebkitMaxContent:
      return Length::MaxContent();
    case CSSValueID::kStretch:
    case CSSValueID::kWebkitFillAvailable:
      return Length::Stretch();
    case CSSValueID::kWebkitFitContent:
    case CSSValueID::kFitContent:
      return Length::FitContent();
    case CSSValueID::kContent:
      return Length::Content();
    case CSSValueID::kAuto:
      return Length::Auto();
    default:
      NOTREACHED();
  }
}

Length StyleBuilderConverter::ConvertLengthMaxSizing(StyleResolverState& state,
                                                     const CSSValue& value) {
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (identifier_value && identifier_value->GetValueID() == CSSValueID::kNone) {
    return Length::None();
  }
  return ConvertLengthSizing(state, value);
}

TabSize StyleBuilderConverter::ConvertLengthOrTabSpaces(
    StyleResolverState& state,
    const CSSValue& value) {
  const auto& primitive_value = To<CSSPrimitiveValue>(value);
  if (primitive_value.IsNumber()) {
    return TabSize(
        primitive_value.ComputeNumber(state.CssToLengthConversionData()),
        TabSizeValueType::kSpace);
  }
  return TabSize(
      primitive_value.ComputeLength<float>(state.CssToLengthConversionData()),
      TabSizeValueType::kLength);
}

static CSSToLengthConversionData LineHeightToLengthConversionData(
    StyleResolverState& state) {
  float multiplier = state.StyleBuilder().EffectiveZoom();
  if (LocalFrame* frame = state.GetDocument().GetFrame()) {
    multiplier *= frame->TextZoomFactor();
  }

  if (!state.StyleBuilder().GetTextSizeAdjust().IsAuto()) {
    if (RuntimeEnabledFeatures::TextSizeAdjustImprovementsEnabled()) {
      Settings* settings = state.GetDocument().GetSettings();
      if (settings && settings->GetTextAutosizingEnabled()) {
        multiplier *= state.StyleBuilder().GetTextSizeAdjust().Multiplier();
      }
    }
  }
  return state.CssToLengthConversionData().CopyWithAdjustedZoom(multiplier);
}

Length StyleBuilderConverter::ConvertLineHeight(StyleResolverState& state,
                                                const CSSValue& value) {
  if (const auto* primitive_value = DynamicTo<CSSPrimitiveValue>(value)) {
    if (primitive_value->IsLength()) {
      return primitive_value->ComputeLength<Length>(
          LineHeightToLengthConversionData(state));
    }
    if (primitive_value->IsNumber()) {
      return Length::Percent(
          ClampTo<float>(primitive_value->ComputeNumber(
                             LineHeightToLengthConversionData(state)) *
                         100.0));
    }
    float computed_font_size =
        state.StyleBuilder().GetFontDescription().ComputedSize();
    if (primitive_value->IsPercentage()) {
      return Length::Fixed(
          (computed_font_size * ClampTo<int>(primitive_value->ComputePercentage(
                                    LineHeightToLengthConversionData(state)))) /
          100.0);
    }
    if (primitive_value->IsCalculated()) {
      Length zoomed_length =
          Length(To<CSSMathFunctionValue>(primitive_value)
                     ->ToCalcValue(LineHeightToLengthConversionData(state)));
      return Length::Fixed(
          ValueForLength(zoomed_length, LayoutUnit(computed_font_size)));
    }
  }

  if (value.IsPendingSystemFontValue()) {
    return ComputedStyleInitialValues::InitialLineHeight();
  }

  DCHECK_EQ(To<CSSIdentifierValue>(value).GetValueID(), CSSValueID::kNormal);
  return ComputedStyleInitialValues::InitialLineHeight();
}

float StyleBuilderConverter::ConvertNumberOrPercentage(
    StyleResolverState& state,
    const CSSValue& value) {
  const auto& primitive_value = To<CSSPrimitiveValue>(value);
  DCHECK(primitive_value.IsNumber() || primitive_value.IsPercentage());
  if (primitive_value.IsNumber()) {
    return primitive_value.GetFloatValue();
  }
  return primitive_value.GetFloatValue() / 100.0f;
}

int StyleBuilderConverter::ConvertInteger(StyleResolverState& state,
                                          const CSSValue& value) {
  return To<CSSPrimitiveValue>(value).ComputeInteger(
      state.CssToLengthConversionData());
}

float StyleBuilderConverter::ConvertAlpha(StyleResolverState& state,
                                          const CSSValue& value) {
  return ClampTo<float>(ConvertNumberOrPercentage(state, value), 0, 1);
}

ScopedCSSName* StyleBuilderConverter::ConvertNoneOrCustomIdent(
    StyleResolverState& state,
    const CSSValue& value) {
  DCHECK(value.IsScopedValue());
  if (const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(identifier_value->GetValueID(), CSSValueID::kNone);
    return nullptr;
  }
  return ConvertCustomIdent(state, value);
}

ScopedCSSName* StyleBuilderConverter::ConvertNormalOrCustomIdent(
    StyleResolverState& state,
    const CSSValue& value) {
  DCHECK(value.IsScopedValue());
  if (const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(identifier_value->GetValueID(), CSSValueID::kNormal);
    return nullptr;
  }
  return ConvertCustomIdent(state, value);
}

ScopedCSSName* StyleBuilderConverter::ConvertCustomIdent(
    StyleResolverState& state,
    const CSSValue& value) {
  state.SetHasTreeScopedReference();
  const CSSCustomIdentValue& custom_ident = To<CSSCustomIdentValue>(value);
  return MakeGarbageCollected<ScopedCSSName>(custom_ident.Value(),
                                             custom_ident.GetTreeScope());
}

ScopedCSSName* StyleBuilderConverter::ConvertPositionAnchor(
    StyleResolverState& state,
    const CSSValue& value) {
  DCHECK(value.IsScopedValue());
  if (const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(identifier_value->GetValueID(), CSSValueID::kAuto);
    return nullptr;
  }
  return ConvertCustomIdent(state, value);
}

PositionVisibility StyleBuilderConverter::ConvertPositionVisibility(
    StyleResolverState& state,
    const CSSValue& value) {
  PositionVisibility flags = PositionVisibility::kAlways;

  auto process = [&flags](const CSSValue& identifier) {
    flags |= To<CSSIdentifierValue>(identifier).ConvertTo<PositionVisibility>();
  };
  if (auto* value_list = DynamicTo<CSSValueList>(value)) {
    for (auto& entry : *value_list) {
      process(*entry);
    }
  } else {
    process(value);
  }
  return flags;
}

ScopedCSSNameList* StyleBuilderConverter::ConvertAnchorName(
    StyleResolverState& state,
    const CSSValue& value) {
  DCHECK(value.IsScopedValue());
  if (const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(identifier_value->GetValueID(), CSSValueID::kNone);
    return nullptr;
  }
  DCHECK(value.IsBaseValueList());
  HeapVector<Member<const ScopedCSSName>> names;
  for (const Member<const CSSValue>& item : To<CSSValueList>(value)) {
    names.push_back(ConvertCustomIdent(state, *item));
  }
  return MakeGarbageCollected<ScopedCSSNameList>(std::move(names));
}

StyleAnchorScope StyleBuilderConverter::ConvertAnchorScope(
    StyleResolverState& state,
    const CSSValue& value) {
  CHECK(value.IsScopedValue());
  if (const auto* scoped_keyword_value =
          DynamicTo<cssvalue::CSSScopedKeywordValue>(value)) {
    CHECK_EQ(scoped_keyword_value->GetValueID(), CSSValueID::kAll);
    state.SetHasTreeScopedReference();
    return StyleAnchorScope(StyleAnchorScope::Type::kAll,
                            scoped_keyword_value->GetTreeScope(),
                            /* names */ nullptr);
  }
  if (const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    CHECK_EQ(identifier_value->GetValueID(), CSSValueID::kNone);
    return StyleAnchorScope();
  }
  CHECK(value.IsBaseValueList());
  HeapVector<Member<const ScopedCSSName>> names;
  for (const Member<const CSSValue>& item : To<CSSValueList>(value)) {
    names.push_back(ConvertCustomIdent(state, *item));
  }
  return StyleAnchorScope(
      StyleAnchorScope::Type::kNames, /* all_tree_scope */ nullptr,
      /* names */ MakeGarbageCollected<ScopedCSSNameList>(std::move(names)));
}

StyleInitialLetter StyleBuilderConverter::ConvertInitialLetter(
    StyleResolverState& state,
    const CSSValue& value) {
  if (auto* normal_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(normal_value->GetValueID(), CSSValueID::kNormal);
    return StyleInitialLetter::Normal();
  }

  const auto& list = To<CSSValueList>(value);
  DCHECK(list.length() == 1 || list.length() == 2);
  const float size = To<CSSPrimitiveValue>(list.Item(0))
                         .ComputeNumber(state.CssToLengthConversionData());
  DCHECK_GE(size, 1);
  if (list.length() == 1) {
    return StyleInitialLetter(size);
  }

  const CSSValue& second = list.Item(1);
  if (auto* sink_type = DynamicTo<CSSIdentifierValue>(second)) {
    if (sink_type->GetValueID() == CSSValueID::kDrop) {
      return StyleInitialLetter::Drop(size);
    }
    if (sink_type->GetValueID() == CSSValueID::kRaise) {
      return StyleInitialLetter::Raise(size);
    }
    NOTREACHED() << "Unexpected sink type " << sink_type;
  }

  if (auto* sink = DynamicTo<CSSPrimitiveValue>(second)) {
    DCHECK_GE(sink->ComputeNumber(state.CssToLengthConversionData()), 1);
    return StyleInitialLetter(
        size, sink->ComputeNumber(state.CssToLengthConversionData()));
  }

  return StyleInitialLetter::Normal();
}

StyleOffsetRotation StyleBuilderConverter::ConvertOffsetRotate(
    StyleResolverState& state,
    const CSSValue& value) {
  return ConvertOffsetRotate(state.CssToLengthConversionData(), value);
}

StyleOffsetRotation StyleBuilderConverter::ConvertOffsetRotate(
    const CSSLengthResolver& length_resolver,
    const CSSValue& value) {
  StyleOffsetRotation result(0, OffsetRotationType::kFixed);

  if (auto* identifier = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(identifier->GetValueID(), CSSValueID::kAuto);
    result.type = OffsetRotationType::kAuto;
    return result;
  }

  const auto& list = To<CSSValueList>(value);
  DCHECK(list.length() == 1 || list.length() == 2);
  for (const auto& item : list) {
    auto* identifier_value = DynamicTo<CSSIdentifierValue>(item.Get());
    if (identifier_value &&
        identifier_value->GetValueID() == CSSValueID::kAuto) {
      result.type = OffsetRotationType::kAuto;
    } else if (identifier_value &&
               identifier_value->GetValueID() == CSSValueID::kReverse) {
      result.type = OffsetRotationType::kAuto;
      result.angle = ClampTo<float>(result.angle + 180);
    } else {
      const auto& primitive_value = To<CSSPrimitiveValue>(*item);
      result.angle = ClampTo<float>(
          result.angle + primitive_value.ComputeDegrees(length_resolver));
    }
  }

  return result;
}

LengthPoint StyleBuilderConverter::ConvertPosition(StyleResolverState& state,
                                                   const CSSValue& value) {
  const auto& pair = To<CSSValuePair>(value);
  return LengthPoint(
      ConvertPositionLength<CSSValueID::kLeft, CSSValueID::kRight>(
          state, pair.First()),
      ConvertPositionLength<CSSValueID::kTop, CSSValueID::kBottom>(
          state, pair.Second()));
}

LengthPoint StyleBuilderConverter::ConvertPositionOrAuto(
    StyleResolverState& state,
    const CSSValue& value) {
  if (value.IsValuePair()) {
    return ConvertPosition(state, value);
  }
  DCHECK(To<CSSIdentifierValue>(value).GetValueID() == CSSValueID::kAuto);
  return LengthPoint(Length::Auto(), Length::Auto());
}

LengthPoint StyleBuilderConverter::ConvertOffsetPosition(
    StyleResolverState& state,
    const CSSValue& value) {
  if (value.IsValuePair()) {
    return ConvertPosition(state, value);
  }
  if (To<CSSIdentifierValue>(value).GetValueID() == CSSValueID::kAuto) {
    return LengthPoint(Length::Auto(), Length::Auto());
  }
  return LengthPoint(Length::None(), Length::None());
}

static float ConvertPerspectiveLength(
    StyleResolverState& state,
    const CSSPrimitiveValue& primitive_value) {
  return std::max(
      primitive_value.ComputeLength<float>(state.CssToLengthConversionData()),
      0.0f);
}

float StyleBuilderConverter::ConvertPerspective(StyleResolverState& state,
                                                const CSSValue& value) {
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (identifier_value && identifier_value->GetValueID() == CSSValueID::kNone) {
    return ComputedStyleInitialValues::InitialPerspective();
  }
  return ConvertPerspectiveLength(state, To<CSSPrimitiveValue>(value));
}

EPaintOrder StyleBuilderConverter::ConvertPaintOrder(
    StyleResolverState&,
    const CSSValue& css_paint_order) {
  if (const auto* order_type_list = DynamicTo<CSSValueList>(css_paint_order)) {
    switch (To<CSSIdentifierValue>(order_type_list->Item(0)).GetValueID()) {
      case CSSValueID::kFill:
        return order_type_list->length() > 1 ? kPaintOrderFillMarkersStroke
                                             : kPaintOrderFillStrokeMarkers;
      case CSSValueID::kStroke:
        return order_type_list->length() > 1 ? kPaintOrderStrokeMarkersFill
                                             : kPaintOrderStrokeFillMarkers;
      case CSSValueID::kMarkers:
        return order_type_list->length() > 1 ? kPaintOrderMarkersStrokeFill
                                             : kPaintOrderMarkersFillStroke;
      default:
        NOTREACHED();
    }
  }

  return kPaintOrderNormal;
}

Length StyleBuilderConverter::ConvertQuirkyLength(StyleResolverState& state,
                                                  const CSSValue& value) {
  Length length = ConvertLengthOrAuto(state, value);
  // This is only for margins which use __qem
  auto* numeric_literal = DynamicTo<CSSNumericLiteralValue>(value);
  length.SetQuirk(numeric_literal && numeric_literal->IsQuirkyEms());
  return length;
}

scoped_refptr<QuotesData> StyleBuilderConverter::ConvertQuotes(
    StyleResolverState&,
    const CSSValue& value) {
  if (const auto* list = DynamicTo<CSSValueList>(value)) {
    scoped_refptr<QuotesData> quotes = QuotesData::Create();
    for (wtf_size_t i = 0; i < list->length(); i += 2) {
      String start_quote = To<CSSStringValue>(list->Item(i)).Value();
      String end_quote = To<CSSStringValue>(list->Item(i + 1)).Value();
      quotes->AddPair(std::make_pair(start_quote, end_quote));
    }
    return quotes;
  }
  if (To<CSSIdentifierValue>(value).GetValueID() == CSSValueID::kNone) {
    return QuotesData::Create();
  }
  DCHECK_EQ(To<CSSIdentifierValue>(value).GetValueID(), CSSValueID::kAuto);
  return nullptr;
}

LengthSize StyleBuilderConverter::ConvertRadius(StyleResolverState& state,
                                                const CSSValue& value) {
  const auto& pair = To<CSSValuePair>(value);
  Length radius_width = To<CSSPrimitiveValue>(pair.First())
                            .ConvertToLength(state.CssToLengthConversionData());
  Length radius_height =
      To<CSSPrimitiveValue>(pair.Second())
          .ConvertToLength(state.CssToLengthConversionData());
  return LengthSize(radius_width, radius_height);
}

template <typename T>
T ConvertGapDecorationPropertyValue(
    StyleResolverState& state,
    const CSSValue& value,
    bool for_visited_link = false);

template <>
StyleColor ConvertGapDecorationPropertyValue<StyleColor>(
    StyleResolverState& state,
    const CSSValue& value,
    bool for_visited_link) {
  return StyleBuilderConverter::ConvertStyleColor(state, value,
                                                  for_visited_link);
}

template <>
int ConvertGapDecorationPropertyValue<int>(StyleResolverState& state,
                                           const CSSValue& value,
                                           bool for_visited_link) {
  return ClampTo<uint16_t>(
      StyleBuilderConverter::ConvertBorderWidth(state, value));
}

template <typename T>
GapDataList<T> ConvertGapDecorationDataList(StyleResolverState& state,
                                            const CSSValue& value,
                                            bool for_visited_link = false) {
  // The `value` will not be a list in two scenarios:
  // 1. When using the legacy 'column-rule-*' properties.
  // 2. When the fast parse path is taken (see
  // CSSParserFastPaths::MaybeParseValue). In these cases, construct a
  // GapDataList with a single Value.
  if (!DynamicTo<CSSValueList>(value)) {
    return GapDataList<T>(
        ConvertGapDecorationPropertyValue<T>(state, value, for_visited_link));
  }
  CHECK(RuntimeEnabledFeatures::CSSGapDecorationEnabled());

  // The CSS Gap Decorations API accepts a space separated list of values.
  // These values can be an auto repeater, an integer repeater, or a single
  // value.
  // See: https://kbabbitt.github.io/css-gap-decorations/#column-row-rule-color
  const auto& values = To<CSSValueList>(value);
  typename GapDataList<T>::GapDataVector gap_data_list;
  gap_data_list.ReserveInitialCapacity(values.length());

  for (const auto& curr_value : values) {
    GapData<T> gap_data;
    if (auto* gap_repeat_value =
            DynamicTo<cssvalue::CSSRepeatValue>(curr_value.Get())) {
      typename ValueRepeater<T>::VectorType gap_values;
      gap_values.ReserveInitialCapacity(gap_repeat_value->Values().length());
      for (const auto& repeat_value : gap_repeat_value->Values()) {
        gap_values.push_back(ConvertGapDecorationPropertyValue<T>(
            state, *repeat_value, for_visited_link));
      }

      std::optional<int> repeat_count = std::nullopt;
      if (!gap_repeat_value->IsAutoRepeatValue()) {
        repeat_count = gap_repeat_value->Repetitions()->ComputeInteger(
            state.CssToLengthConversionData());
      }
      ValueRepeater<T>* value_repeater = value_repeater =
          MakeGarbageCollected<ValueRepeater<T>>(std::move(gap_values),
                                                 repeat_count);
      gap_data = GapData<T>(value_repeater);
    } else {
      gap_data = GapData<T>(ConvertGapDecorationPropertyValue<T>(
          state, *curr_value.Get(), for_visited_link));
    }

    gap_data_list.push_back(gap_data);
  }

  return GapDataList<T>(std::move(gap_data_list));
}

GapDataList<StyleColor>
StyleBuilderConverter::ConvertGapDecorationColorDataList(
    StyleResolverState& state,
    const CSSValue& value,
    bool for_visited_link) {
  return ConvertGapDecorationDataList<blink::StyleColor>(state, value,
                                                         for_visited_link);
}

GapDataList<int> StyleBuilderConverter::ConvertGapDecorationWidthDataList(
    StyleResolverState& state,
    const CSSValue& value) {
  return ConvertGapDecorationDataList<int>(state, value);
}

ShadowData StyleBuilderConverter::ConvertShadow(
    const CSSToLengthConversionData& conversion_data,
    StyleResolverState* state,
    const CSSValue& value) {
  const auto& shadow = To<CSSShadowValue>(value);
  const gfx::Vector2dF offset(shadow.x->ComputeLength<float>(conversion_data),
                              shadow.y->ComputeLength<float>(conversion_data));
  float blur =
      shadow.blur ? shadow.blur->ComputeLength<float>(conversion_data) : 0;
  float spread =
      shadow.spread ? shadow.spread->ComputeLength<float>(conversion_data) : 0;
  ShadowStyle shadow_style =
      shadow.style && shadow.style->GetValueID() == CSSValueID::kInset
          ? ShadowStyle::kInset
          : ShadowStyle::kNormal;
  StyleColor color = StyleColor::CurrentColor();
  if (shadow.color) {
    if (state) {
      color = ConvertStyleColor(*state, *shadow.color);
    } else {
      // For OffScreen canvas, we default to black and only parse non
      // Document dependent CSS colors.
      TextLinkColors black_text_link_colors;
      black_text_link_colors.SetTextColor(Color::kBlack);
      black_text_link_colors.SetLinkColor(Color::kBlack);
      black_text_link_colors.SetVisitedLinkColor(Color::kBlack);
      black_text_link_colors.SetActiveLinkColor(Color::kBlack);

      const ResolveColorValueContext context{
          .length_resolver = conversion_data,
          .text_link_colors = black_text_link_colors};
      color = ResolveColorValue(*shadow.color, context);
      if (!color.IsAbsoluteColor()) {
        color = StyleColor(Color::kBlack);
      }
    }
  }
  return ShadowData(offset, blur, spread, shadow_style, color);
}

ShadowList* StyleBuilderConverter::ConvertShadowList(StyleResolverState& state,
                                                     const CSSValue& value) {
  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(identifier_value->GetValueID(), CSSValueID::kNone);
    return nullptr;
  }

  const auto& list = To<CSSValueList>(value);
  ShadowDataVector shadows;
  shadows.ReserveInitialCapacity(list.length());
  for (const auto& item : list) {
    shadows.push_back(
        ConvertShadow(state.CssToLengthConversionData(), &state, *item));
  }

  return MakeGarbageCollected<ShadowList>(std::move(shadows));
}

ShapeValue* StyleBuilderConverter::ConvertShapeValue(StyleResolverState& state,
                                                     const CSSValue& value) {
  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(identifier_value->GetValueID(), CSSValueID::kNone);
    return nullptr;
  }

  if (value.IsImageValue() || value.IsImageGeneratorValue() ||
      value.IsImageSetValue()) {
    return MakeGarbageCollected<ShapeValue>(
        state.GetStyleImage(CSSPropertyID::kShapeOutside, value));
  }

  scoped_refptr<const BasicShape> shape;
  CSSBoxType css_box = CSSBoxType::kMissing;
  const auto& value_list = To<CSSValueList>(value);
  for (unsigned i = 0; i < value_list.length(); ++i) {
    const CSSValue& item_value = value_list.Item(i);
    if (item_value.IsBasicShapeValue()) {
      shape = BasicShapeForValue(state, item_value);
    } else {
      css_box = To<CSSIdentifierValue>(item_value).ConvertTo<CSSBoxType>();
    }
  }

  if (shape) {
    return MakeGarbageCollected<ShapeValue>(std::move(shape), css_box);
  }

  DCHECK_NE(css_box, CSSBoxType::kMissing);
  return MakeGarbageCollected<ShapeValue>(css_box);
}

float StyleBuilderConverter::ConvertSpacing(StyleResolverState& state,
                                            const CSSValue& value) {
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (identifier_value &&
      identifier_value->GetValueID() == CSSValueID::kNormal) {
    return 0;
  }
  return To<CSSPrimitiveValue>(value).ComputeLength<float>(
      state.CssToLengthConversionData());
}

scoped_refptr<SVGDashArray> StyleBuilderConverter::ConvertStrokeDasharray(
    StyleResolverState& state,
    const CSSValue& value) {
  const auto* dashes = DynamicTo<CSSValueList>(value);
  if (!dashes) {
    return EmptyDashArray();
  }

  scoped_refptr<SVGDashArray> array = base::MakeRefCounted<SVGDashArray>();

  wtf_size_t length = dashes->length();
  for (wtf_size_t i = 0; i < length; ++i) {
    array->data.push_back(
        ConvertLength(state, To<CSSPrimitiveValue>(dashes->Item(i))));
  }

  return array;
}

StyleViewTransitionGroup StyleBuilderConverter::ConvertViewTransitionGroup(
    StyleResolverState& state,
    const CSSValue& value) {
  if (auto* ident = DynamicTo<CSSIdentifierValue>(value)) {
    switch (ident->GetValueID()) {
      case CSSValueID::kNearest:
        return StyleViewTransitionGroup::Nearest();
      case CSSValueID::kNormal:
        return StyleViewTransitionGroup::Normal();
      case CSSValueID::kContain:
        return StyleViewTransitionGroup::Contain();
      default:
        NOTREACHED();
    }
  }
  return StyleViewTransitionGroup::Create(
      ConvertCustomIdent(state, value)->GetName());
}

StyleViewTransitionCaptureMode
StyleBuilderConverter::ConvertViewTransitionCaptureMode(
    StyleResolverState& state,
    const CSSValue& value) {
  if (auto* ident = DynamicTo<CSSIdentifierValue>(value)) {
    switch (ident->GetValueID()) {
      case CSSValueID::kLayered:
        return StyleViewTransitionCaptureMode::kLayered;
      case CSSValueID::kFlat:
        return StyleViewTransitionCaptureMode::kFlat;
      default:
        NOTREACHED();
    }
  }

  return StyleViewTransitionCaptureMode::kLayered;
}

StyleViewTransitionName* StyleBuilderConverter::ConvertViewTransitionName(
    StyleResolverState& state,
    const CSSValue& value) {
  state.SetHasTreeScopedReference();
  if (auto* ident = DynamicTo<CSSIdentifierValue>(value)) {
    switch (ident->GetValueID()) {
      case CSSValueID::kNone:
        return nullptr;
      case CSSValueID::kAuto:
        // TODO: tree scope for auto
        return StyleViewTransitionName::Auto(&state.GetDocument());
      default:
        NOTREACHED();
    }
  }
  ScopedCSSName* name = ConvertCustomIdent(state, value);
  return StyleViewTransitionName::Create(name->GetName(), name->GetTreeScope());
}

ScopedCSSNameList* StyleBuilderConverter::ConvertViewTransitionClass(
    StyleResolverState& state,
    const CSSValue& value) {
  DCHECK(value.IsScopedValue());
  if (IsA<CSSIdentifierValue>(value)) {
    DCHECK_EQ(To<CSSIdentifierValue>(value).GetValueID(), CSSValueID::kNone);
    return nullptr;
  }
  DCHECK(value.IsBaseValueList());
  HeapVector<Member<const ScopedCSSName>> names;
  for (const Member<const CSSValue>& item : To<CSSValueList>(value)) {
    names.push_back(ConvertNoneOrCustomIdent(state, *item));
  }
  return MakeGarbageCollected<ScopedCSSNameList>(std::move(names));
}

namespace {

const CSSValue& ResolveLightDarkPair(const CSSLightDarkValuePair& value,
                                     const ResolveColorValueContext& context);

StyleColor ResolveColorValueImpl(const CSSValue& value,
                                 const ResolveColorValueContext& context) {
  if (auto* color_value = DynamicTo<cssvalue::CSSColor>(value)) {
    Color result_color = color_value->Value();
    result_color.ResolveNonFiniteValues();
    return StyleColor(result_color);
  }

  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    CSSValueID value_id = identifier_value->GetValueID();
    if (value_id == CSSValueID::kCurrentcolor) {
      return StyleColor::CurrentColor();
    }
    if (IsQuirkOrLinkOrFocusRingColor(value_id)) {
      return StyleColor(ResolveQuirkOrLinkOrFocusRingColor(
          value_id, context.text_link_colors, context.used_color_scheme,
          context.for_visited_link));
    }
    Color color = StyleColor::ColorFromKeyword(
        value_id, context.used_color_scheme, context.color_provider,
        context.is_in_web_app_scope);
    // Preserve the identifier for system colors since this is needed by
    // 'forced colors mode'.
    if (StyleColor::IsSystemColorIncludingDeprecated(value_id)) {
      return StyleColor(color, value_id);
    }
    return StyleColor(color);
  }

  if (auto* color_mix_value = DynamicTo<cssvalue::CSSColorMixValue>(value)) {
    const StyleColor style_color1 =
        ResolveColorValueImpl(color_mix_value->Color1(), context);
    const StyleColor style_color2 =
        ResolveColorValueImpl(color_mix_value->Color2(), context);
    double alpha_multiplier = 0.0;
    double mix_amount = 0.0;
    // TODO(crbug.com/40238188): Not sure what is appropriate to return when
    // both mix amounts are zero.
    color_mix_value->NormalizePercentages(mix_amount, alpha_multiplier,
                                          context.length_resolver);
    const StyleColor::UnresolvedColorMix* unresolved_color_mix =
        MakeGarbageCollected<StyleColor::UnresolvedColorMix>(
            color_mix_value->ColorInterpolationSpace(),
            color_mix_value->HueInterpolationMethod(), style_color1,
            style_color2, mix_amount, alpha_multiplier);
    // https://drafts.csswg.org/css-color-5/#resolving-mix
    // If both parameters are resolvable at computed-value time, the color-mix
    // function should be resolved at computed-value time as well.
    // Other
"""


```