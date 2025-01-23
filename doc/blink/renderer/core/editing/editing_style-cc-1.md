Response:

### 提示词
```
这是目录为blink/renderer/core/editing/editing_style.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
ection = MakeGarbageCollected<EditingStyle>();
  text_direction->mutable_style_ =
      MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLQuirksMode);
  text_direction->mutable_style_->SetLonghandProperty(
      CSSPropertyID::kUnicodeBidi, CSSValueID::kIsolate,
      mutable_style_->PropertyIsImportant(CSSPropertyID::kUnicodeBidi));

  text_direction->mutable_style_->ParseAndSetProperty(
      CSSPropertyID::kDirection,
      mutable_style_->GetPropertyValue(CSSPropertyID::kDirection),
      mutable_style_->PropertyIsImportant(CSSPropertyID::kDirection),
      secure_context_mode);

  mutable_style_->RemoveProperty(CSSPropertyID::kUnicodeBidi);
  mutable_style_->RemoveProperty(CSSPropertyID::kDirection);

  return text_direction;
}

void EditingStyle::RemoveBlockProperties(
    const ExecutionContext* execution_context) {
  if (!mutable_style_)
    return;

  mutable_style_->RemovePropertiesInSet(
      BlockPropertiesVector(execution_context));
}

void EditingStyle::RemoveStyleAddedByElement(Element* element) {
  if (!element || !element->parentElement()) {
    return;
  }
  MutableCSSPropertyValueSet* parent_style =
      CopyEditingProperties(element->parentElement()->GetExecutionContext(),
                            MakeGarbageCollected<CSSComputedStyleDeclaration>(
                                element->parentElement()),
                            kAllEditingProperties);
  MutableCSSPropertyValueSet* element_style = CopyEditingProperties(
      element->GetExecutionContext(),
      MakeGarbageCollected<CSSComputedStyleDeclaration>(element),
      kAllEditingProperties);
  element_style->RemoveEquivalentProperties(parent_style);
  mutable_style_->RemoveEquivalentProperties(element_style);
}

void EditingStyle::RemoveStyleConflictingWithStyleOfElement(Element* element) {
  if (!element || !element->parentElement() || !mutable_style_) {
    return;
  }

  MutableCSSPropertyValueSet* parent_style =
      CopyEditingProperties(element->parentElement()->GetExecutionContext(),
                            MakeGarbageCollected<CSSComputedStyleDeclaration>(
                                element->parentElement()),
                            kAllEditingProperties);
  MutableCSSPropertyValueSet* element_style = CopyEditingProperties(
      element->GetExecutionContext(),
      MakeGarbageCollected<CSSComputedStyleDeclaration>(element),
      kAllEditingProperties);
  element_style->RemoveEquivalentProperties(parent_style);

  unsigned property_count = element_style->PropertyCount();
  for (unsigned i = 0; i < property_count; ++i)
    mutable_style_->RemoveProperty(element_style->PropertyAt(i).Id());
}

void EditingStyle::CollapseTextDecorationProperties(
    SecureContextMode secure_context_mode) {
  if (!mutable_style_)
    return;

  const CSSValue* text_decorations_in_effect =
      mutable_style_->GetPropertyCSSValue(
          CSSPropertyID::kWebkitTextDecorationsInEffect);
  if (!text_decorations_in_effect)
    return;

  if (text_decorations_in_effect->IsValueList()) {
    mutable_style_->ParseAndSetProperty(
        CSSPropertyID::kTextDecorationLine,
        text_decorations_in_effect->CssText(),
        mutable_style_->PropertyIsImportant(CSSPropertyID::kTextDecorationLine),
        secure_context_mode);
  } else {
    mutable_style_->RemoveProperty(CSSPropertyID::kTextDecorationLine);
  }
  mutable_style_->RemoveProperty(CSSPropertyID::kWebkitTextDecorationsInEffect);
}

EditingTriState EditingStyle::TriStateOfStyle(
    ExecutionContext* execution_context,
    EditingStyle* style,
    SecureContextMode secure_context_mode) const {
  if (!style || !style->mutable_style_)
    return EditingTriState::kFalse;
  DCHECK(style->node_);
  return TriStateOfStyle(
      style->mutable_style_->EnsureCSSStyleDeclaration(execution_context),
      style->node_, kDoNotIgnoreTextOnlyProperties, secure_context_mode);
}

EditingTriState EditingStyle::TriStateOfStyle(
    CSSStyleDeclaration* style_to_compare,
    Node* node,
    ShouldIgnoreTextOnlyProperties should_ignore_text_only_properties,
    SecureContextMode secure_context_mode) const {
  // editing/execCommand/query-text-alignment.html requires |node|.
  DCHECK(node);
  MutableCSSPropertyValueSet* difference = GetPropertiesNotIn(
      mutable_style_.Get(), node, style_to_compare, secure_context_mode);

  // CSS properties that create a visual difference only when applied to text.
  static const CSSProperty* kTextOnlyProperties[] = {
      // FIXME: CSSPropertyID::kTextDecoration needs to be removed when CSS3
      // Text
      // Decoration feature is no longer experimental.
      &GetCSSPropertyTextDecoration(),
      &GetCSSPropertyTextDecorationLine(),
      &GetCSSPropertyWebkitTextDecorationsInEffect(),
      &GetCSSPropertyFontStyle(),
      &GetCSSPropertyFontWeight(),
      &GetCSSPropertyColor(),
  };
  if (should_ignore_text_only_properties == kIgnoreTextOnlyProperties) {
    difference->RemovePropertiesInSet(kTextOnlyProperties);
  }

  if (difference->IsEmpty())
    return EditingTriState::kTrue;
  if (difference->PropertyCount() == mutable_style_->PropertyCount())
    return EditingTriState::kFalse;

  return EditingTriState::kMixed;
}

EditingTriState EditingStyle::TriStateOfStyle(
    const VisibleSelection& selection,
    SecureContextMode secure_context_mode) const {
  if (selection.IsNone())
    return EditingTriState::kFalse;

  if (selection.IsCaret()) {
    return TriStateOfStyle(
        selection.Start().AnchorNode()->GetExecutionContext(),
        EditingStyleUtilities::CreateStyleAtSelectionStart(selection),
        secure_context_mode);
  }

  EditingTriState state = EditingTriState::kFalse;
  bool node_is_start = true;
  for (Node& node : NodeTraversal::StartsAt(*selection.Start().AnchorNode())) {
    if (node.GetLayoutObject() && IsEditable(node)) {
      auto* computed_style = MakeGarbageCollected<CSSComputedStyleDeclaration>(
          ElementFromStyledNode(&node));
      CSSStyleDeclaration* node_style = computed_style;
      if (computed_style) {
        // If the selected element has <sub> or <sup> ancestor element, apply
        // the corresponding style(vertical-align) to it so that
        // document.queryCommandState() works with the style. See bug
        // http://crbug.com/582225.
        if (is_vertical_align_ &&
            GetIdentifierValue(computed_style, CSSPropertyID::kVerticalAlign) ==
                CSSValueID::kBaseline) {
          const auto* vertical_align =
              To<CSSIdentifierValue>(mutable_style_->GetPropertyCSSValue(
                  CSSPropertyID::kVerticalAlign));
          if (EditingStyleUtilities::HasAncestorVerticalAlignStyle(
                  node, vertical_align->GetValueID())) {
            auto* mutable_style = computed_style->CopyProperties();
            mutable_style->SetProperty(CSSPropertyID::kVerticalAlign,
                                       *vertical_align);
            node_style = mutable_style->EnsureCSSStyleDeclaration(
                node.GetExecutionContext());
          }
        }

        // Pass EditingStyle::DoNotIgnoreTextOnlyProperties without checking if
        // node.isTextNode() because the node can be an element node. See bug
        // http://crbug.com/584939.
        EditingTriState node_state = TriStateOfStyle(
            node_style, &node, EditingStyle::kDoNotIgnoreTextOnlyProperties,
            secure_context_mode);
        if (node_is_start) {
          state = node_state;
          node_is_start = false;
        } else if (state != node_state && node.IsTextNode()) {
          state = EditingTriState::kMixed;
          break;
        }
      }
    }
    if (&node == selection.End().AnchorNode())
      break;
  }

  return state;
}

bool EditingStyle::ConflictsWithInlineStyleOfElement(
    HTMLElement* element,
    EditingStyle* extracted_style,
    Vector<CSSPropertyID>* conflicting_properties) const {
  DCHECK(element);
  DCHECK(!conflicting_properties || conflicting_properties->empty());

  const CSSPropertyValueSet* inline_style = element->InlineStyle();
  if (!mutable_style_ || !inline_style)
    return false;

  unsigned property_count = mutable_style_->PropertyCount();
  for (unsigned i = 0; i < property_count; ++i) {
    CSSPropertyID property_id = mutable_style_->PropertyAt(i).Id();

    // We don't override `white-space-collapse` property of a tab span because
    // that would collapse the tab into a space.
    //
    // Logically speaking, only `white-space-collapse` is needed (i.e.,
    // `text-wrap` is not needed.) But including other longhands helps producing
    // `white-space` instead of `white-space-collapse`. Because the snippet
    // produced by this logic may be sent to other browsers by copy&paste,
    // e-mail, etc., `white-space` is more interoperable when
    // `white-space-collapse` is not broadly supported. See crbug.com/1417543
    // and `editing/pasteboard/pasting-tabs.html`.
#if EXPENSIVE_DCHECKS_ARE_ON()
    DCHECK_NE(property_id, CSSPropertyID::kWhiteSpace);
    DCHECK_EQ(whiteSpaceShorthand().length(), 2u);
    DCHECK_EQ(whiteSpaceShorthand().properties()[0]->PropertyID(),
              CSSPropertyID::kWhiteSpaceCollapse);
    DCHECK_EQ(whiteSpaceShorthand().properties()[1]->PropertyID(),
              CSSPropertyID::kTextWrapMode);
#endif  // EXPENSIVE_DCHECKS_ARE_ON()
    const bool is_whitespace_property =
        property_id == CSSPropertyID::kWhiteSpaceCollapse ||
        property_id == CSSPropertyID::kTextWrapMode;
    if (is_whitespace_property && IsTabHTMLSpanElement(element)) {
      continue;
    }

    if (property_id == CSSPropertyID::kWebkitTextDecorationsInEffect &&
        inline_style->GetPropertyCSSValue(CSSPropertyID::kTextDecorationLine)) {
      if (!conflicting_properties)
        return true;
      conflicting_properties->push_back(CSSPropertyID::kTextDecoration);
      // Because text-decoration expands to text-decoration-line,
      // we also state it as conflicting.
      conflicting_properties->push_back(CSSPropertyID::kTextDecorationLine);
      if (extracted_style) {
        extracted_style->SetProperty(
            CSSPropertyID::kTextDecorationLine,
            inline_style->GetPropertyValue(CSSPropertyID::kTextDecorationLine),
            inline_style->PropertyIsImportant(
                CSSPropertyID::kTextDecorationLine),
            element->GetExecutionContext()->GetSecureContextMode());
      }
      continue;
    }

    if (!inline_style->GetPropertyCSSValue(property_id))
      continue;

    if (property_id == CSSPropertyID::kUnicodeBidi &&
        inline_style->GetPropertyCSSValue(CSSPropertyID::kDirection)) {
      if (!conflicting_properties)
        return true;
      conflicting_properties->push_back(CSSPropertyID::kDirection);
      if (extracted_style) {
        extracted_style->SetProperty(
            property_id, inline_style->GetPropertyValue(property_id),
            inline_style->PropertyIsImportant(property_id),
            element->GetExecutionContext()->GetSecureContextMode());
      }
    }

    if (!conflicting_properties)
      return true;

    conflicting_properties->push_back(property_id);

    if (extracted_style) {
      extracted_style->SetProperty(
          property_id, inline_style->GetPropertyValue(property_id),
          inline_style->PropertyIsImportant(property_id),
          element->GetExecutionContext()->GetSecureContextMode());
    }
  }

  return conflicting_properties && !conflicting_properties->empty();
}

static const HeapVector<Member<HTMLElementEquivalent>>&
HtmlElementEquivalents() {
  DEFINE_STATIC_LOCAL(
      Persistent<HeapVector<Member<HTMLElementEquivalent>>>,
      html_element_equivalents,
      (MakeGarbageCollected<HeapVector<Member<HTMLElementEquivalent>>>()));
  if (!html_element_equivalents->size()) {
    html_element_equivalents->push_back(
        MakeGarbageCollected<HTMLElementEquivalent>(
            CSSPropertyID::kFontWeight, CSSValueID::kBold, html_names::kBTag));
    html_element_equivalents->push_back(
        MakeGarbageCollected<HTMLElementEquivalent>(CSSPropertyID::kFontWeight,
                                                    CSSValueID::kBold,
                                                    html_names::kStrongTag));
    html_element_equivalents->push_back(
        MakeGarbageCollected<HTMLElementEquivalent>(
            CSSPropertyID::kVerticalAlign, CSSValueID::kSub,
            html_names::kSubTag));
    html_element_equivalents->push_back(
        MakeGarbageCollected<HTMLElementEquivalent>(
            CSSPropertyID::kVerticalAlign, CSSValueID::kSuper,
            html_names::kSupTag));
    html_element_equivalents->push_back(
        MakeGarbageCollected<HTMLElementEquivalent>(
            CSSPropertyID::kFontStyle, CSSValueID::kItalic, html_names::kITag));
    html_element_equivalents->push_back(
        MakeGarbageCollected<HTMLElementEquivalent>(CSSPropertyID::kFontStyle,
                                                    CSSValueID::kItalic,
                                                    html_names::kEmTag));

    html_element_equivalents->push_back(HTMLTextDecorationEquivalent::Create(
        CSSValueID::kUnderline, html_names::kUTag));
    html_element_equivalents->push_back(HTMLTextDecorationEquivalent::Create(
        CSSValueID::kLineThrough, html_names::kSTag));
    html_element_equivalents->push_back(HTMLTextDecorationEquivalent::Create(
        CSSValueID::kLineThrough, html_names::kStrikeTag));
  }

  return *html_element_equivalents;
}

bool EditingStyle::ConflictsWithImplicitStyleOfElement(
    HTMLElement* element,
    EditingStyle* extracted_style,
    ShouldExtractMatchingStyle should_extract_matching_style) const {
  if (!mutable_style_)
    return false;

  const HeapVector<Member<HTMLElementEquivalent>>& html_element_equivalents =
      HtmlElementEquivalents();
  for (wtf_size_t i = 0; i < html_element_equivalents.size(); ++i) {
    const HTMLElementEquivalent* equivalent = html_element_equivalents[i].Get();
    if (equivalent->Matches(element) &&
        equivalent->PropertyExistsInStyle(mutable_style_.Get()) &&
        (should_extract_matching_style == kExtractMatchingStyle ||
         !equivalent->ValueIsPresentInStyle(element, mutable_style_.Get()))) {
      if (extracted_style)
        equivalent->AddToStyle(element, extracted_style);
      return true;
    }
  }
  return false;
}

static const HeapVector<Member<HTMLAttributeEquivalent>>&
HtmlAttributeEquivalents() {
  DEFINE_STATIC_LOCAL(
      Persistent<HeapVector<Member<HTMLAttributeEquivalent>>>,
      html_attribute_equivalents,
      (MakeGarbageCollected<HeapVector<Member<HTMLAttributeEquivalent>>>()));
  if (!html_attribute_equivalents->size()) {
    // elementIsStyledSpanOrHTMLEquivalent depends on the fact each
    // HTMLAttriuteEquivalent matches exactly one attribute of exactly one
    // element except dirAttr.
    html_attribute_equivalents->push_back(
        MakeGarbageCollected<HTMLAttributeEquivalent>(CSSPropertyID::kColor,
                                                      html_names::kFontTag,
                                                      html_names::kColorAttr));
    html_attribute_equivalents->push_back(
        MakeGarbageCollected<HTMLAttributeEquivalent>(
            CSSPropertyID::kFontFamily, html_names::kFontTag,
            html_names::kFaceAttr));
    html_attribute_equivalents->push_back(HTMLFontSizeEquivalent::Create());

    html_attribute_equivalents->push_back(
        MakeGarbageCollected<HTMLAttributeEquivalent>(CSSPropertyID::kDirection,
                                                      html_names::kDirAttr));
    html_attribute_equivalents->push_back(
        MakeGarbageCollected<HTMLAttributeEquivalent>(
            CSSPropertyID::kUnicodeBidi, html_names::kDirAttr));
  }

  return *html_attribute_equivalents;
}

bool EditingStyle::ConflictsWithImplicitStyleOfAttributes(
    HTMLElement* element) const {
  DCHECK(element);
  if (!mutable_style_)
    return false;

  const HeapVector<Member<HTMLAttributeEquivalent>>&
      html_attribute_equivalents = HtmlAttributeEquivalents();
  for (const auto& equivalent : html_attribute_equivalents) {
    if (equivalent->Matches(element) &&
        equivalent->PropertyExistsInStyle(mutable_style_.Get()) &&
        !equivalent->ValueIsPresentInStyle(element, mutable_style_.Get()))
      return true;
  }

  return false;
}

bool EditingStyle::ExtractConflictingImplicitStyleOfAttributes(
    HTMLElement* element,
    ShouldPreserveWritingDirection should_preserve_writing_direction,
    EditingStyle* extracted_style,
    Vector<QualifiedName>& conflicting_attributes,
    ShouldExtractMatchingStyle should_extract_matching_style) const {
  DCHECK(element);
  // HTMLAttributeEquivalent::addToStyle doesn't support unicode-bidi and
  // direction properties
  if (extracted_style)
    DCHECK_EQ(should_preserve_writing_direction, kPreserveWritingDirection);
  if (!mutable_style_)
    return false;

  const HeapVector<Member<HTMLAttributeEquivalent>>&
      html_attribute_equivalents = HtmlAttributeEquivalents();
  bool removed = false;
  for (const auto& attribute : html_attribute_equivalents) {
    const HTMLAttributeEquivalent* equivalent = attribute.Get();

    // unicode-bidi and direction are pushed down separately so don't push down
    // with other styles.
    if (should_preserve_writing_direction == kPreserveWritingDirection &&
        equivalent->AttributeName() == html_names::kDirAttr)
      continue;

    if (!equivalent->Matches(element) ||
        !equivalent->PropertyExistsInStyle(mutable_style_.Get()) ||
        (should_extract_matching_style == kDoNotExtractMatchingStyle &&
         equivalent->ValueIsPresentInStyle(element, mutable_style_.Get())))
      continue;

    if (extracted_style)
      equivalent->AddToStyle(element, extracted_style);
    conflicting_attributes.push_back(equivalent->AttributeName());
    removed = true;
  }

  return removed;
}

bool EditingStyle::StyleIsPresentInComputedStyleOfNode(Node* node) const {
  return !mutable_style_ ||
         GetPropertiesNotIn(mutable_style_.Get(), node,
                            MakeGarbageCollected<CSSComputedStyleDeclaration>(
                                ElementFromStyledNode(node)),
                            node->GetExecutionContext()->GetSecureContextMode())
             ->IsEmpty();
}

bool EditingStyle::ElementIsStyledSpanOrHTMLEquivalent(
    const HTMLElement* element) {
  DCHECK(element);
  bool element_is_span_or_element_equivalent = false;
  if (IsA<HTMLSpanElement>(*element)) {
    element_is_span_or_element_equivalent = true;
  } else {
    const HeapVector<Member<HTMLElementEquivalent>>& html_element_equivalents =
        HtmlElementEquivalents();
    wtf_size_t i;
    for (i = 0; i < html_element_equivalents.size(); ++i) {
      if (html_element_equivalents[i]->Matches(element)) {
        element_is_span_or_element_equivalent = true;
        break;
      }
    }
  }

  AttributeCollection attributes = element->Attributes();
  if (attributes.IsEmpty()) {
    // span, b, etc... without any attributes
    return element_is_span_or_element_equivalent;
  }

  unsigned matched_attributes = 0;
  const HeapVector<Member<HTMLAttributeEquivalent>>&
      html_attribute_equivalents = HtmlAttributeEquivalents();
  for (const auto& equivalent : html_attribute_equivalents) {
    if (equivalent->Matches(element) &&
        equivalent->AttributeName() != html_names::kDirAttr)
      matched_attributes++;
  }

  if (!element_is_span_or_element_equivalent && !matched_attributes) {
    // element is not a span, a html element equivalent, or font element.
    return false;
  }

  if (element->hasAttribute(html_names::kStyleAttr)) {
    if (const CSSPropertyValueSet* style = element->InlineStyle()) {
      unsigned property_count = style->PropertyCount();
      for (unsigned i = 0; i < property_count; ++i) {
        if (!IsEditingProperty(element->GetExecutionContext(),
                               style->PropertyAt(i).Id()))
          return false;
      }
    }
    matched_attributes++;
  }

  // font with color attribute, span with style attribute, etc...
  DCHECK_LE(matched_attributes, attributes.size());
  return matched_attributes >= attributes.size();
}

void EditingStyle::PrepareToApplyAt(
    const Position& position,
    ShouldPreserveWritingDirection should_preserve_writing_direction) {
  if (!mutable_style_)
    return;
  DCHECK(position.IsNotNull());

  // ReplaceSelectionCommand::handleStyleSpans() requires that this function
  // only removes the editing style. If this function was modified in the future
  // to delete all redundant properties, then add a boolean value to indicate
  // which one of editingStyleAtPosition or computedStyle is called.
  EditingStyle* editing_style_at_position =
      MakeGarbageCollected<EditingStyle>(position, kEditingPropertiesInEffect);
  CSSPropertyValueSet* style_at_position =
      editing_style_at_position->mutable_style_.Get();

  const CSSValue* unicode_bidi = nullptr;
  const CSSValue* direction = nullptr;
  if (should_preserve_writing_direction == kPreserveWritingDirection) {
    unicode_bidi =
        mutable_style_->GetPropertyCSSValue(CSSPropertyID::kUnicodeBidi);
    direction = mutable_style_->GetPropertyCSSValue(CSSPropertyID::kDirection);
  }

  mutable_style_->RemoveEquivalentProperties(style_at_position);

  DCHECK(editing_style_at_position->node_);
  if (IsRedundantTextAlign(mutable_style_.Get(), style_at_position,
                           editing_style_at_position->node_))
    mutable_style_->RemoveProperty(CSSPropertyID::kTextAlign);

  if (GetFontColor(mutable_style_.Get()) == GetFontColor(style_at_position))
    mutable_style_->RemoveProperty(CSSPropertyID::kColor);

  if (EditingStyleUtilities::HasTransparentBackgroundColor(
          mutable_style_.Get()) ||
      CssValueToColor(mutable_style_->GetPropertyCSSValue(
          CSSPropertyID::kBackgroundColor)) ==
          BackgroundColorInEffect(position.ComputeContainerNode()))
    mutable_style_->RemoveProperty(CSSPropertyID::kBackgroundColor);

  if (auto* unicode_bidi_identifier_value =
          DynamicTo<CSSIdentifierValue>(unicode_bidi)) {
    mutable_style_->SetLonghandProperty(
        CSSPropertyID::kUnicodeBidi,
        unicode_bidi_identifier_value->GetValueID());
    if (auto* direction_identifier_value =
            DynamicTo<CSSIdentifierValue>(direction)) {
      mutable_style_->SetLonghandProperty(
          CSSPropertyID::kDirection, direction_identifier_value->GetValueID());
    }
  }
}

void EditingStyle::MergeTypingStyle(Document* document) {
  DCHECK(document);

  EditingStyle* typing_style = document->GetFrame()->GetEditor().TypingStyle();
  if (!typing_style || typing_style == this)
    return;

  MergeStyle(typing_style->Style(), kOverrideValues);
}

void EditingStyle::MergeInlineStyleOfElement(
    HTMLElement* element,
    CSSPropertyOverrideMode mode,
    PropertiesToInclude properties_to_include) {
  DCHECK(element);
  if (!element->InlineStyle())
    return;

  switch (properties_to_include) {
    case kAllProperties:
      MergeStyle(element->InlineStyle(), mode);
      return;
    case kOnlyEditingInheritableProperties:
      MergeStyle(CopyEditingProperties(element->GetExecutionContext(),
                                       element->InlineStyle(),
                                       kOnlyInheritableEditingProperties),
                 mode);
      return;
    case kEditingPropertiesInEffect:
      MergeStyle(
          CopyEditingProperties(element->GetExecutionContext(),
                                element->InlineStyle(), kAllEditingProperties),
          mode);
      return;
  }
}

static inline bool ElementMatchesAndPropertyIsNotInInlineStyleDecl(
    const HTMLElementEquivalent* equivalent,
    const Element* element,
    EditingStyle::CSSPropertyOverrideMode mode,
    CSSPropertyValueSet* style) {
  return equivalent->Matches(element) &&
         (!element->InlineStyle() ||
          !equivalent->PropertyExistsInStyle(element->InlineStyle())) &&
         (mode == EditingStyle::kOverrideValues ||
          !equivalent->PropertyExistsInStyle(style));
}

static MutableCSSPropertyValueSet* ExtractEditingProperties(
    const ExecutionContext* execution_context,
    const CSSPropertyValueSet* style,
    EditingStyle::PropertiesToInclude properties_to_include) {
  if (!style)
    return nullptr;

  switch (properties_to_include) {
    case EditingStyle::kAllProperties:
    case EditingStyle::kEditingPropertiesInEffect:
      return CopyEditingProperties(execution_context, style,
                                   kAllEditingProperties);
    case EditingStyle::kOnlyEditingInheritableProperties:
      return CopyEditingProperties(execution_context, style,
                                   kOnlyInheritableEditingProperties);
  }

  NOTREACHED();
}

void EditingStyle::MergeInlineAndImplicitStyleOfElement(
    Element* element,
    CSSPropertyOverrideMode mode,
    PropertiesToInclude properties_to_include) {
  EditingStyle* style_from_rules = MakeGarbageCollected<EditingStyle>();
  style_from_rules->MergeStyleFromRulesForSerialization(element);

  if (element->InlineStyle())
    style_from_rules->mutable_style_->MergeAndOverrideOnConflict(
        element->InlineStyle());

  style_from_rules->mutable_style_ = ExtractEditingProperties(
      element->GetExecutionContext(), style_from_rules->mutable_style_.Get(),
      properties_to_include);
  MergeStyle(style_from_rules->mutable_style_.Get(), mode);

  const HeapVector<Member<HTMLElementEquivalent>>& element_equivalents =
      HtmlElementEquivalents();
  for (const auto& equivalent : element_equivalents) {
    if (ElementMatchesAndPropertyIsNotInInlineStyleDecl(
            equivalent.Get(), element, mode, mutable_style_.Get()))
      equivalent->AddToStyle(element, this);
  }

  const HeapVector<Member<HTMLAttributeEquivalent>>& attribute_equivalents =
      HtmlAttributeEquivalents();
  for (const auto& attribute : attribute_equivalents) {
    if (attribute->AttributeName() == html_names::kDirAttr)
      continue;  // We don't want to include directionality
    if (ElementMatchesAndPropertyIsNotInInlineStyleDecl(
            attribute.Get(), element, mode, mutable_style_.Get()))
      attribute->AddToStyle(element, this);
  }
}

static const CSSValueList& MergeTextDecorationValues(
    const CSSValueList& merged_value,
    const CSSValueList& value_to_merge) {
  DEFINE_STATIC_LOCAL(Persistent<CSSIdentifierValue>, underline,
                      (CSSIdentifierValue::Create(CSSValueID::kUnderline)));
  DEFINE_STATIC_LOCAL(Persistent<CSSIdentifierValue>, line_through,
                      (CSSIdentifierValue::Create(CSSValueID::kLineThrough)));
  CSSValueList& result = *merged_value.Copy();
  if (value_to_merge.HasValue(*underline) && !merged_value.HasValue(*underline))
    result.Append(*underline);

  if (value_to_merge.HasValue(*line_through) &&
      !merged_value.HasValue(*line_through))
    result.Append(*line_through);

  return result;
}

void EditingStyle::MergeStyle(const CSSPropertyValueSet* style,
                              CSSPropertyOverrideMode mode) {
  if (!style)
    return;

  if (!mutable_style_) {
    mutable_style_ = style->MutableCopy();
    return;
  }

  unsigned property_count = style->PropertyCount();
  for (unsigned i = 0; i < property_count; ++i) {
    CSSPropertyValueSet::PropertyReference property = style->PropertyAt(i);
    const CSSValue* value = mutable_style_->GetPropertyCSSValue(property.Id());

    // text decorations never override values
    const auto* property_value_list = DynamicTo<CSSValueList>(property.Value());
    if ((property.Id() == CSSPropertyID::kTextDecorationLine ||
         property.Id() == CSSPropertyID::kWebkitTextDecorationsInEffect) &&
        property_value_list && value) {
      if (const auto* value_list = DynamicTo<CSSValueList>(value)) {
        const CSSValueList& result =
            MergeTextDecorationValues(*value_list, *property_value_list);
        mutable_style_->SetProperty(property.Id(), result,
                                    property.IsImportant());
        continue;
      }
      // text-decoration: none is equivalent to not having the property
      value = nullptr;
    }

    if (mode == kOverrideValues || (mode == kDoNotOverrideValues && !value)) {
      mutable_style_->SetLonghandProperty(
          CSSPropertyValue(property.PropertyMetadata(), property.Value()));
    }
  }
}

static MutableCSSPropertyValueSet* StyleFromMatchedRulesForElement(
    Element* element,
    unsigned rules_to_include) {
  auto* style =
      MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLQuirksMode);
  StyleRuleList* matched_rules =
      element->GetDocument().GetStyleResolver().StyleRulesForElement(
          element, rules_to_include);
  if (matched_rules) {
    for (unsigned i = 0; i < matched_rules->size(); ++i)
      style->MergeAndOverrideOnConflict(&matched_rules->at(i)->Properties());
  }
  return style;
}

void EditingStyle::MergeStyleFromRules(Element* element) {
  MutableCSSPropertyValueSet* style_from_matched_rules =
      StyleFromMatchedRulesForElement(element, StyleResolver::kAuthorCSSRules);
  // Styles from the inline style declaration, held in the variable "style",
  // take precedence over those from matched rules.
  if (mutable_style_)
    style_from_matched_rules->MergeAndOverrideOnConflict(mutable_style_.Get());

  Clear();
  mutable_style_ = style_from_matched_rules;
}

void EditingStyle::MergeStyleFromRulesForSerialization(Element* element) {
  MergeStyleFromRules(element);

  // The property value, if it's a percentage, may not reflect the actual
  // computed value.
  // For example: style="height: 1%; overflow: visible;" in quirksmode
  // FIXME: There are others like this, see <rdar://problem/5195123> Slashdot
  // copy/paste fidelity problem
  auto* computed_style_for_element =
      MakeGarbageCollected<CSSComputedStyleDeclaration>(element);
  auto* from_computed_style =
      MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLQuirksMode);
  {
    unsigned property_count = mutable_style_->PropertyCount();
    for (unsigned i = 0; i < property_count; ++i) {
      CSSPropertyValueSet::PropertyReference property =
          mutable_style_->PropertyAt(i);
      const CSSValue& value = property.Value();
      const auto* primitive_value = DynamicTo<CSSPrimitiveValue>(value);
      if (!primitive_value)
        continue;
      if (primitive_value->IsPercentage()) {
        CSSPropertyName name = property.Name();
        if (const CSSValue* computed_property_value =
                computed_style_for_element->GetPropertyCSSValue(name)) {
          from_computed_style->AddRespectingCascade(
              CSSPropertyValue(name, *computed_property_value));
        }
      }
    }
  }
  mutable_style_->MergeAndOverrideOnConflict(from_computed_style);

 // There are some scenarios, like when copying rich text while in ForcedColors
  // mode where we don't want to keep the ForcedColors styling, so that if it is
  // pasted and sent to someone with no ForcedColors applied it does not affect
  // their styling.
  if (element->GetDocument().InForcedColorsMode()) {
    mutable_style_->SetLonghandProperty(CSSPropertyID::kBackgroundColor,
                                        CSSValueID::kInitial, false);
    mutable_style_->SetLonghandProperty(CSSPropertyID::kColor,
                                        CSSValueID::kInitial, false);
    mutable_style_->SetLonghandProperty(CSSPropertyID::kTextDecorationColor,
                                        CSSValueID::kInitial, false);
  }
}

static void RemovePropertiesInStyle(
    MutableCSSPropertyValueSet* style_to_remove_properties_from,
    CSSPropertyValueSet* style) {
  unsigned property_count = style->PropertyCount();
  Vector<const CSSProperty*> properties_to_remove(property_count);
  for (unsigned i = 0; i < property_count; ++i) {
    // TODO(crbug.com/980160): Remove access to static Variable instance.
    properties_to_remove[i] = &CSSProperty::Get(style->PropertyAt(i).Id());
  }

  style_to_remove_properties_from->RemovePropertiesInSet(properties_to_remove);
}

void EditingStyle::RemoveStyleFromRulesAndContext(Element* element,
                                                  Element* context) {
  DCHECK(element);
  if (!mutable_style_)
    return;

  // StyleResolver requires clean style.
  DCHECK_GE(element->GetDocument().Lifecycle().GetState(),
            DocumentLifecycle::kStyleClean);
  DCHECK(element->GetDocument().IsActive());

  SecureContextMode secure_context_mode =
      element->G
```