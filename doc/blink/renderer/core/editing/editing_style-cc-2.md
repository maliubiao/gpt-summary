Response:

### 提示词
```
这是目录为blink/renderer/core/editing/editing_style.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
etExecutionContext()->GetSecureContextMode();

  // 1. Remove style from matched rules because style remain without repeating
  // it in inline style declaration
  MutableCSSPropertyValueSet* style_from_matched_rules =
      StyleFromMatchedRulesForElement(element, StyleResolver::kAllCSSRules);
  if (style_from_matched_rules && !style_from_matched_rules->IsEmpty()) {
    mutable_style_ =
        GetPropertiesNotIn(mutable_style_.Get(), element,
                           style_from_matched_rules->EnsureCSSStyleDeclaration(
                               element->GetExecutionContext()),
                           secure_context_mode);
  }

  // 2. Remove style present in context and not overriden by matched rules.
  EditingStyle* computed_style =
      MakeGarbageCollected<EditingStyle>(context, kEditingPropertiesInEffect);
  if (computed_style->mutable_style_) {
    if (!computed_style->mutable_style_->GetPropertyCSSValue(
            CSSPropertyID::kBackgroundColor)) {
      computed_style->mutable_style_->SetLonghandProperty(
          CSSPropertyID::kBackgroundColor, CSSValueID::kTransparent);
    }

    RemovePropertiesInStyle(computed_style->mutable_style_.Get(),
                            style_from_matched_rules);
    mutable_style_ = GetPropertiesNotIn(
        mutable_style_.Get(), element,
        computed_style->mutable_style_->EnsureCSSStyleDeclaration(
            element->GetExecutionContext()),
        secure_context_mode);
  }

  // 3. If this element is a span and has display: inline or float: none, remove
  // them unless they are overriden by rules. These rules are added by
  // serialization code to wrap text nodes.
  if (IsStyleSpanOrSpanWithOnlyStyleAttribute(element)) {
    if (!style_from_matched_rules->GetPropertyCSSValue(
            CSSPropertyID::kDisplay) &&
        GetProperty(CSSPropertyID::kDisplay) == CSSValueID::kInline)
      mutable_style_->RemoveProperty(CSSPropertyID::kDisplay);
    if (!style_from_matched_rules->GetPropertyCSSValue(CSSPropertyID::kFloat) &&
        GetProperty(CSSPropertyID::kFloat) == CSSValueID::kNone)
      mutable_style_->RemoveProperty(CSSPropertyID::kFloat);
  }
}

void EditingStyle::RemovePropertiesInElementDefaultStyle(Element* element) {
  if (!mutable_style_ || mutable_style_->IsEmpty())
    return;

  CSSPropertyValueSet* default_style = StyleFromMatchedRulesForElement(
      element, StyleResolver::kUAAndUserCSSRules);

  RemovePropertiesInStyle(mutable_style_.Get(), default_style);
}

void EditingStyle::ForceInline() {
  if (!mutable_style_) {
    mutable_style_ =
        MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLQuirksMode);
  }
  const bool kPropertyIsImportant = true;
  mutable_style_->SetLonghandProperty(
      CSSPropertyID::kDisplay, CSSValueID::kInline, kPropertyIsImportant);
}

int EditingStyle::LegacyFontSize(Document* document) const {
  const CSSValue* css_value =
      mutable_style_->GetPropertyCSSValue(CSSPropertyID::kFontSize);
  if (!css_value ||
      !(css_value->IsPrimitiveValue() || css_value->IsIdentifierValue()))
    return 0;
  return LegacyFontSizeFromCSSValue(document, css_value, is_monospace_font_,
                                    kAlwaysUseLegacyFontSize);
}

void EditingStyle::Trace(Visitor* visitor) const {
  visitor->Trace(mutable_style_);
  visitor->Trace(node_);
}

static void ReconcileTextDecorationProperties(
    MutableCSSPropertyValueSet* style,
    SecureContextMode secure_context_mode) {
  const CSSValue* text_decorations_in_effect =
      style->GetPropertyCSSValue(CSSPropertyID::kWebkitTextDecorationsInEffect);
  const CSSValue* text_decoration =
      style->GetPropertyCSSValue(CSSPropertyID::kTextDecorationLine);
  // "web_tests/editing/execCommand/insert-list-and-strikethrough.html" makes
  // both |textDecorationsInEffect| and |textDecoration| non-null.
  if (text_decorations_in_effect) {
    style->ParseAndSetProperty(CSSPropertyID::kTextDecorationLine,
                               text_decorations_in_effect->CssText(),
                               /* important */ false, secure_context_mode);
    style->RemoveProperty(CSSPropertyID::kWebkitTextDecorationsInEffect);
    text_decoration = text_decorations_in_effect;
  }

  // If text-decoration is set to "none", remove the property because we don't
  // want to add redundant "text-decoration: none".
  if (text_decoration && !text_decoration->IsValueList())
    style->RemoveProperty(CSSPropertyID::kTextDecorationLine);
}

StyleChange::StyleChange(EditingStyle* style, const Position& position)
    : apply_bold_(false),
      apply_italic_(false),
      apply_underline_(false),
      apply_line_through_(false),
      apply_subscript_(false),
      apply_superscript_(false) {
  Document* document = position.GetDocument();
  if (!style || !style->Style() || !document || !document->GetFrame())
    return;
  Element* const element = AssociatedElementOf(position);
  if (!element)
    return;

  CSSComputedStyleDeclaration* const computed_style =
      MakeGarbageCollected<CSSComputedStyleDeclaration>(element);
  // FIXME: take care of background-color in effect
  // Note: editing/undo/redo-selection-modify-crash.html needs to pass
  // |element| to |GetPropertiesNotIn()| to remove "text-align:left".
  MutableCSSPropertyValueSet* mutable_style = GetPropertiesNotIn(
      style->Style(), element, computed_style,
      document->GetExecutionContext()->GetSecureContextMode());
  DCHECK(mutable_style);

  ReconcileTextDecorationProperties(
      mutable_style, document->GetExecutionContext()->GetSecureContextMode());
  if (!document->GetFrame()->GetEditor().ShouldStyleWithCSS())
    ExtractTextStyles(document, mutable_style,
                      computed_style->IsMonospaceFont());

  // If unicode-bidi is present in mutableStyle and direction is not, then add
  // direction to mutableStyle.
  // FIXME: Shouldn't this be done in getPropertiesNotIn?
  if (mutable_style->GetPropertyCSSValue(CSSPropertyID::kUnicodeBidi) &&
      !style->Style()->GetPropertyCSSValue(CSSPropertyID::kDirection)) {
    mutable_style->ParseAndSetProperty(
        CSSPropertyID::kDirection,
        style->Style()->GetPropertyValue(CSSPropertyID::kDirection),
        /* important */ false,
        document->GetExecutionContext()->GetSecureContextMode());
  }

  // Save the result for later
  css_style_ = mutable_style->AsText().StripWhiteSpace();
}

static void SetTextDecorationProperty(MutableCSSPropertyValueSet* style,
                                      const CSSValueList* new_text_decoration,
                                      CSSPropertyID property_id,
                                      SecureContextMode secure_context_mode) {
  if (new_text_decoration->length()) {
    style->ParseAndSetProperty(property_id, new_text_decoration->CssText(),
                               style->PropertyIsImportant(property_id),
                               secure_context_mode);
  } else {
    // text-decoration: none is redundant since it does not remove any text
    // decorations.
    style->RemoveProperty(property_id);
  }
}

static bool GetPrimitiveValueNumber(CSSPropertyValueSet* style,
                                    CSSPropertyID property_id,
                                    float& number) {
  if (!style)
    return false;
  const CSSValue* value = style->GetPropertyCSSValue(property_id);
  const auto* primitive_value = DynamicTo<CSSPrimitiveValue>(value);
  if (!primitive_value)
    return false;
  number = primitive_value->GetFloatValue();
  return true;
}

void StyleChange::ExtractTextStyles(Document* document,
                                    MutableCSSPropertyValueSet* style,
                                    bool is_monospace_font) {
  DCHECK(style);

  float weight = 0;
  bool is_number =
      GetPrimitiveValueNumber(style, CSSPropertyID::kFontWeight, weight);
  if (GetIdentifierValue(style, CSSPropertyID::kFontWeight) ==
          CSSValueID::kBold ||
      (is_number && weight >= kBoldThreshold)) {
    style->RemoveProperty(CSSPropertyID::kFontWeight);
    apply_bold_ = true;
  }

  CSSValueID font_style = GetIdentifierValue(style, CSSPropertyID::kFontStyle);
  if (font_style == CSSValueID::kItalic || font_style == CSSValueID::kOblique) {
    style->RemoveProperty(CSSPropertyID::kFontStyle);
    apply_italic_ = true;
  }

  // Assuming reconcileTextDecorationProperties has been called, there should
  // not be -webkit-text-decorations-in-effect
  // Furthermore, text-decoration: none has been trimmed so that text-decoration
  // property is always a CSSValueList.
  const CSSValue* text_decoration =
      style->GetPropertyCSSValue(CSSPropertyID::kTextDecorationLine);
  if (const auto* text_decoration_value_list =
          DynamicTo<CSSValueList>(text_decoration)) {
    DEFINE_STATIC_LOCAL(Persistent<CSSIdentifierValue>, underline,
                        (CSSIdentifierValue::Create(CSSValueID::kUnderline)));
    DEFINE_STATIC_LOCAL(Persistent<CSSIdentifierValue>, line_through,
                        (CSSIdentifierValue::Create(CSSValueID::kLineThrough)));
    CSSValueList* new_text_decoration = text_decoration_value_list->Copy();
    if (new_text_decoration->RemoveAll(*underline))
      apply_underline_ = true;
    if (new_text_decoration->RemoveAll(*line_through))
      apply_line_through_ = true;

    // If trimTextDecorations, delete underline and line-through
    SetTextDecorationProperty(
        style, new_text_decoration, CSSPropertyID::kTextDecorationLine,
        document->GetExecutionContext()->GetSecureContextMode());
  }

  CSSValueID vertical_align =
      GetIdentifierValue(style, CSSPropertyID::kVerticalAlign);
  switch (vertical_align) {
    case CSSValueID::kSub:
      style->RemoveProperty(CSSPropertyID::kVerticalAlign);
      apply_subscript_ = true;
      break;
    case CSSValueID::kSuper:
      style->RemoveProperty(CSSPropertyID::kVerticalAlign);
      apply_superscript_ = true;
      break;
    default:
      break;
  }

  if (style->GetPropertyCSSValue(CSSPropertyID::kColor)) {
    // The <font> tag cannot handle rgb colors, so we need to serialize as hex
    // here in order to continue supporting it.
    apply_font_color_ = GetFontColor(style).SerializeAsCanvasColor();
    style->RemoveProperty(CSSPropertyID::kColor);
  }

  apply_font_face_ = style->GetPropertyValue(CSSPropertyID::kFontFamily);
  // Remove double quotes for Outlook 2007 compatibility. See
  // https://bugs.webkit.org/show_bug.cgi?id=79448
  apply_font_face_.Replace('"', "");
  style->RemoveProperty(CSSPropertyID::kFontFamily);

  if (const CSSValue* font_size =
          style->GetPropertyCSSValue(CSSPropertyID::kFontSize)) {
    if (!font_size->IsPrimitiveValue() && !font_size->IsIdentifierValue()) {
      // Can't make sense of the number. Put no font size.
      style->RemoveProperty(CSSPropertyID::kFontSize);
    } else if (int legacy_font_size = LegacyFontSizeFromCSSValue(
                   document, font_size, is_monospace_font,
                   kUseLegacyFontSizeOnlyIfPixelValuesMatch)) {
      apply_font_size_ = String::Number(legacy_font_size);
      style->RemoveProperty(CSSPropertyID::kFontSize);
    }
  }
}

static void DiffTextDecorations(MutableCSSPropertyValueSet* style,
                                CSSPropertyID property_id,
                                const CSSValue* ref_text_decoration,
                                SecureContextMode secure_context_mode) {
  const CSSValue* text_decoration = style->GetPropertyCSSValue(property_id);
  const auto* values_in_text_decoration =
      DynamicTo<CSSValueList>(text_decoration);
  const auto* values_in_ref_text_decoration =
      DynamicTo<CSSValueList>(ref_text_decoration);
  if (!values_in_text_decoration || !values_in_ref_text_decoration)
    return;

  CSSValueList* new_text_decoration = values_in_text_decoration->Copy();

  for (wtf_size_t i = 0; i < values_in_ref_text_decoration->length(); i++)
    new_text_decoration->RemoveAll(values_in_ref_text_decoration->Item(i));

  SetTextDecorationProperty(style, new_text_decoration, property_id,
                            secure_context_mode);
}

static bool FontWeightIsBold(const CSSValue* font_weight) {
  if (auto* font_weight_identifier_value =
          DynamicTo<CSSIdentifierValue>(font_weight)) {
    // Because b tag can only bold text, there are only two states in plain
    // html: bold and not bold. Collapse all other values to either one of these
    // two states for editing purposes.

    switch (font_weight_identifier_value->GetValueID()) {
      case CSSValueID::kNormal:
        return false;
      case CSSValueID::kBold:
        return true;
      default:
        break;
    }
  }

  CHECK(To<CSSPrimitiveValue>(font_weight)->IsNumber());
  return To<CSSPrimitiveValue>(font_weight)->GetFloatValue() >= kBoldThreshold;
}

static bool FontWeightNeedsResolving(const CSSValue* font_weight) {
  if (font_weight->IsPrimitiveValue())
    return false;
  auto* font_weight_identifier_value =
      DynamicTo<CSSIdentifierValue>(font_weight);
  if (!font_weight_identifier_value)
    return true;
  const CSSValueID value = font_weight_identifier_value->GetValueID();
  return value == CSSValueID::kLighter || value == CSSValueID::kBolder;
}

MutableCSSPropertyValueSet* GetPropertiesNotIn(
    CSSPropertyValueSet* style_with_redundant_properties,
    Node* node,
    CSSStyleDeclaration* base_style,
    SecureContextMode secure_context_mode) {
  DCHECK(style_with_redundant_properties);
  DCHECK(node);
  DCHECK(base_style);
  MutableCSSPropertyValueSet* result =
      style_with_redundant_properties->MutableCopy();

  result->RemoveEquivalentProperties(base_style);

  const CSSValue* base_text_decorations_in_effect =
      base_style->GetPropertyCSSValueInternal(
          CSSPropertyID::kWebkitTextDecorationsInEffect);
  DiffTextDecorations(result, CSSPropertyID::kTextDecorationLine,
                      base_text_decorations_in_effect, secure_context_mode);
  DiffTextDecorations(result, CSSPropertyID::kWebkitTextDecorationsInEffect,
                      base_text_decorations_in_effect, secure_context_mode);

  if (const CSSValue* base_font_weight =
          base_style->GetPropertyCSSValueInternal(CSSPropertyID::kFontWeight)) {
    if (const CSSValue* font_weight =
            result->GetPropertyCSSValue(CSSPropertyID::kFontWeight)) {
      if (!FontWeightNeedsResolving(font_weight) &&
          !FontWeightNeedsResolving(base_font_weight) &&
          (FontWeightIsBold(font_weight) == FontWeightIsBold(base_font_weight)))
        result->RemoveProperty(CSSPropertyID::kFontWeight);
    }
  }

  if (base_style->GetPropertyCSSValueInternal(CSSPropertyID::kColor) &&
      GetFontColor(result) == GetFontColor(base_style))
    result->RemoveProperty(CSSPropertyID::kColor);

  if (IsRedundantTextAlign(result, base_style, node))
    result->RemoveProperty(CSSPropertyID::kTextAlign);

  if (base_style->GetPropertyCSSValueInternal(
          CSSPropertyID::kBackgroundColor) &&
      GetBackgroundColor(result) == GetBackgroundColor(base_style))
    result->RemoveProperty(CSSPropertyID::kBackgroundColor);

  return result;
}

CSSValueID GetIdentifierValue(CSSPropertyValueSet* style,
                              CSSPropertyID property_id) {
  if (!style)
    return CSSValueID::kInvalid;
  const CSSValue* value = style->GetPropertyCSSValue(property_id);
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (!identifier_value)
    return CSSValueID::kInvalid;
  return identifier_value->GetValueID();
}

CSSValueID GetIdentifierValue(CSSStyleDeclaration* style,
                              CSSPropertyID property_id) {
  if (!style)
    return CSSValueID::kInvalid;
  const CSSValue* value = style->GetPropertyCSSValueInternal(property_id);
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (!identifier_value)
    return CSSValueID::kInvalid;
  return identifier_value->GetValueID();
}

int LegacyFontSizeFromCSSValue(Document* document,
                               const CSSValue* value,
                               bool is_monospace_font,
                               LegacyFontSizeMode mode) {
  if (const auto* primitive_value = DynamicTo<CSSPrimitiveValue>(value)) {
    if (primitive_value->IsLength()) {
      // TODO(crbug.com/979895): This doesn't seem to be handle math functions
      // correctly. This is the result of a refactoring, and may have revealed
      // an existing bug. Fix it if necessary.
      CSSPrimitiveValue::UnitType length_unit =
          primitive_value->IsNumericLiteralValue()
              ? To<CSSNumericLiteralValue>(primitive_value)->GetType()
              : CSSPrimitiveValue::UnitType::kPixels;
      if (!CSSPrimitiveValue::IsRelativeUnit(length_unit)) {
        double conversion =
            CSSPrimitiveValue::ConversionToCanonicalUnitsScaleFactor(
                length_unit);
        int pixel_font_size =
            ClampTo<int>(primitive_value->GetDoubleValue() * conversion);
        int legacy_font_size = FontSizeFunctions::LegacyFontSize(
            document, pixel_font_size, is_monospace_font);
        // Use legacy font size only if pixel value matches exactly to that of
        // legacy font size.
        if (mode == kAlwaysUseLegacyFontSize ||
            FontSizeFunctions::FontSizeForKeyword(document, legacy_font_size,
                                                  is_monospace_font) ==
                pixel_font_size)
          return legacy_font_size;

        return 0;
      }
    }
  }

  if (const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    if (identifier_value->GetValueID() == CSSValueID::kWebkitXxxLarge)
      return FontSizeFunctions::KeywordSize(CSSValueID::kXxxLarge) - 1;
    if (CSSValueID::kXSmall <= identifier_value->GetValueID() &&
        identifier_value->GetValueID() <= CSSValueID::kXxxLarge)
      return FontSizeFunctions::KeywordSize(identifier_value->GetValueID()) - 1;
  }

  return 0;
}

EditingTriState EditingStyle::SelectionHasStyle(const LocalFrame& frame,
                                                CSSPropertyID property_id,
                                                const String& value) {
  const SecureContextMode secure_context_mode =
      frame.DomWindow()->GetSecureContextMode();

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kSelection);

  return MakeGarbageCollected<EditingStyle>(property_id, value,
                                            secure_context_mode)
      ->TriStateOfStyle(frame.Selection().ComputeVisibleSelectionInDOMTree(),
                        secure_context_mode);
}

}  // namespace blink
```