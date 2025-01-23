Response:
The user wants me to analyze a specific C++ source code file from the Chromium Blink rendering engine. This file, `css_parser_impl.cc`, is responsible for parsing CSS.

My analysis should cover:
1. **Functionality:** What does this code do?
2. **Relation to web technologies:** How does it interact with JavaScript, HTML, and CSS?
3. **Logic and examples:** If there's any logic, provide examples with input and output.
4. **User errors:**  What common mistakes can users make that would lead to this code being executed?
5. **Debugging:** How does user interaction lead to this code, providing debugging clues?
6. **Summary:** A concise summary of the file's function.

This is part 3 of a 4-part analysis, so I need to keep track of the overall functionality as I go.

**Plan:**
1. **Examine the provided code snippet:**  Focus on the functions defined in this section.
2. **Identify the parsed CSS at-rules:** The code contains functions like `ConsumeFontFeatureValuesRule`, `ConsumePageRule`, `ConsumePropertyRule`, etc., each handling a specific CSS at-rule.
3. **Explain the parsing process:**  Describe how each function consumes tokens from the `CSSParserTokenStream` to build a corresponding `StyleRule` object.
4. **Connect to CSS:** Explain how these at-rules are used in CSS and how this code interprets them.
5. **Relate to HTML and JavaScript:**  Discuss how the parsed CSS affects the rendering of HTML and how JavaScript can interact with styles.
6. **Provide examples:**  For each major at-rule, give a simple CSS example and explain how this code would process it.
7. **Consider user errors:** Think about common CSS syntax errors users might make within these at-rules.
8. **Describe the user journey:**  How does a user writing CSS in a web page cause this parsing code to run in the browser?
9. **Summarize the functionality of this section:** Focus on the specific at-rules handled here.
```
这是目录为blink/renderer/core/css/parser/css_parser_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能

"""
itespace();

    font_feature_rule->UpdateAlias(alias, std::move(parsed_numbers));
  }

  return font_feature_rule;
}

StyleRuleFontFeatureValues* CSSParserImpl::ConsumeFontFeatureValuesRule(
    CSSParserTokenStream& stream) {
  // Parse the prelude.
  wtf_size_t prelude_offset_start = stream.LookAheadOffset();
  CSSValueList* family_list = css_parsing_utils::ConsumeFontFamily(stream);
  if (!family_list || !family_list->length()) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleFontFeatureValues);
    return nullptr;
  }
  wtf_size_t prelude_offset_end = stream.LookAheadOffset();
  if (!ConsumeEndOfPreludeForAtRuleWithBlock(
          stream, CSSAtRuleID::kCSSAtRuleFontFeatureValues)) {
    return nullptr;
  }
  CSSParserTokenStream::BlockGuard guard(stream);

  if (observer_) {
    observer_->StartRuleHeader(StyleRule::kFontFeatureValues,
                               prelude_offset_start);
    observer_->EndRuleHeader(prelude_offset_end);
    observer_->StartRuleBody(stream.Offset());
  }

  // Parse the actual block.

  // The nesting logic for parsing @font-feature-values looks as follow:
  // 1) ConsumeRuleList, calls ConsumeAtRule, and in turn ConsumeAtRuleContents
  // 2) ConsumeAtRuleContents uses new ids for inner at-rules, for swash,
  // styleset etc.
  // 3) ConsumeFeatureRule (with type) consumes the inner mappings from aliases
  // to number lists.

  FontFeatureAliases stylistic;
  FontFeatureAliases styleset;
  FontFeatureAliases character_variant;
  FontFeatureAliases swash;
  FontFeatureAliases ornaments;
  FontFeatureAliases annotation;

  HeapVector<Member<StyleRuleFontFeature>> feature_rules;
  bool had_valid_rules = false;
  // ConsumeRuleList returns true only if the first rule is true, but we need to
  // be more generous with the internals of what's inside a font feature value
  // declaration, e.g. inside a @stylsitic, @styleset, etc.
  if (ConsumeRuleList(
          stream, kFontFeatureRuleList, CSSNestingType::kNone,
          /*parent_rule_for_nesting=*/nullptr,
          /*is_within_scope=*/false,
          [&feature_rules, &had_valid_rules](StyleRuleBase* rule, wtf_size_t) {
            if (rule) {
              had_valid_rules = true;
            }
            feature_rules.push_back(To<StyleRuleFontFeature>(rule));
          }) ||
      had_valid_rules) {
    // https://drafts.csswg.org/css-fonts-4/#font-feature-values-syntax
    // "Specifying the same <font-feature-value-type> more than once is valid;
    // their contents are cascaded together."
    for (auto& feature_rule : feature_rules) {
      switch (feature_rule->GetFeatureType()) {
        case StyleRuleFontFeature::FeatureType::kStylistic:
          feature_rule->OverrideAliasesIn(stylistic);
          break;
        case StyleRuleFontFeature::FeatureType::kStyleset:
          feature_rule->OverrideAliasesIn(styleset);
          break;
        case StyleRuleFontFeature::FeatureType::kCharacterVariant:
          feature_rule->OverrideAliasesIn(character_variant);
          break;
        case StyleRuleFontFeature::FeatureType::kSwash:
          feature_rule->OverrideAliasesIn(swash);
          break;
        case StyleRuleFontFeature::FeatureType::kOrnaments:
          feature_rule->OverrideAliasesIn(ornaments);
          break;
        case StyleRuleFontFeature::FeatureType::kAnnotation:
          feature_rule->OverrideAliasesIn(annotation);
          break;
      }
    }
  }

  Vector<AtomicString> families;
  for (const auto family_entry : *family_list) {
    const CSSFontFamilyValue* family_value =
        DynamicTo<CSSFontFamilyValue>(*family_entry);
    if (!family_value) {
      return nullptr;
    }
    families.push_back(family_value->Value());
  }

  auto* feature_values_rule = MakeGarbageCollected<StyleRuleFontFeatureValues>(
      std::move(families), stylistic, styleset, character_variant, swash,
      ornaments, annotation);

  if (observer_) {
    observer_->EndRuleBody(stream.Offset());
  }

  return feature_values_rule;
}

// Parse an @page rule, with contents.
StyleRulePage* CSSParserImpl::ConsumePageRule(CSSParserTokenStream& stream) {
  // Parse the prelude.
  wtf_size_t prelude_offset_start = stream.LookAheadOffset();
  CSSSelectorList* selector_list =
      ParsePageSelector(stream, style_sheet_, *context_);
  if (!selector_list || !selector_list->IsValid()) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRulePage);
    return nullptr;  // Parse error, invalid @page selector
  }
  wtf_size_t prelude_offset_end = stream.LookAheadOffset();
  if (!ConsumeEndOfPreludeForAtRuleWithBlock(stream,
                                             CSSAtRuleID::kCSSAtRulePage)) {
    return nullptr;
  }

  // Parse the actual block.
  CSSParserTokenStream::BlockGuard guard(stream);

  if (observer_) {
    observer_->StartRuleHeader(StyleRule::kPage, prelude_offset_start);
    observer_->EndRuleHeader(prelude_offset_end);
    observer_->StartRuleBody(stream.Offset());
  }

  HeapVector<Member<StyleRuleBase>, 4> child_rules;
  ConsumeBlockContents(stream, StyleRule::kPage, CSSNestingType::kNone,
                       /*parent_rule_for_nesting=*/nullptr,
                       /*is_within_scope=*/false,
                       /*nested_declarations_start_index=*/kNotFound,
                       &child_rules);

  if (observer_) {
    observer_->EndRuleBody(stream.LookAheadOffset());
  }

  return MakeGarbageCollected<StyleRulePage>(
      selector_list,
      CreateCSSPropertyValueSet(parsed_properties_, context_->Mode(),
                                context_->GetDocument()),
      child_rules);
}

StyleRuleProperty* CSSParserImpl::ConsumePropertyRule(
    CSSParserTokenStream& stream) {
  // Parse the prelude.
  wtf_size_t prelude_offset_start = stream.LookAheadOffset();
  const CSSParserToken& name_token = stream.ConsumeIncludingWhitespace();
  if (!CSSVariableParser::IsValidVariableName(name_token)) {
    if (observer_) {
      observer_->ObserveErroneousAtRule(prelude_offset_start,
                                        CSSAtRuleID::kCSSAtRuleProperty);
    }
    return nullptr;
  }
  String name = name_token.Value().ToString();
  wtf_size_t prelude_offset_end = stream.LookAheadOffset();
  if (!ConsumeEndOfPreludeForAtRuleWithBlock(stream,
                                             CSSAtRuleID::kCSSAtRuleProperty)) {
    return nullptr;
  }

  // Parse the body.
  CSSParserTokenStream::BlockGuard guard(stream);

  if (observer_) {
    observer_->StartRuleHeader(StyleRule::kProperty, prelude_offset_start);
    observer_->EndRuleHeader(prelude_offset_end);
    observer_->StartRuleBody(stream.Offset());
  }

  ConsumeBlockContents(stream, StyleRule::kProperty, CSSNestingType::kNone,
                       /*parent_rule_for_nesting=*/nullptr,
                       /*is_within_scope=*/false,
                       /*nested_declarations_start_index=*/kNotFound,
                       /*child_rules=*/nullptr);

  if (observer_) {
    observer_->EndRuleBody(stream.LookAheadOffset());
  }

  StyleRuleProperty* rule = MakeGarbageCollected<StyleRuleProperty>(
      name, CreateCSSPropertyValueSet(parsed_properties_, kCSSPropertyRuleMode,
                                      context_->GetDocument()));

  std::optional<CSSSyntaxDefinition> syntax =
      PropertyRegistration::ConvertSyntax(rule->GetSyntax());
  std::optional<bool> inherits =
      PropertyRegistration::ConvertInherits(rule->Inherits());
  std::optional<const CSSValue*> initial =
      syntax.has_value() ? PropertyRegistration::ConvertInitial(
                               rule->GetInitialValue(), *syntax, *context_)
                         : std::nullopt;

  bool invalid_rule =
      !syntax.has_value() || !inherits.has_value() || !initial.has_value();

  if (observer_ && invalid_rule) {
    Vector<CSSPropertyID, 2> failed_properties;
    if (!syntax.has_value()) {
      failed_properties.push_back(CSSPropertyID::kSyntax);
    }
    if (!inherits.has_value()) {
      failed_properties.push_back(CSSPropertyID::kInherits);
    }
    if (!initial.has_value() && syntax.has_value()) {
      failed_properties.push_back(CSSPropertyID::kInitialValue);
    }
    DCHECK(!failed_properties.empty());
    observer_->ObserveErroneousAtRule(prelude_offset_start,
                                      CSSAtRuleID::kCSSAtRuleProperty,
                                      failed_properties);
  }
  if (invalid_rule) {
    return nullptr;
  }
  return rule;
}

StyleRuleCounterStyle* CSSParserImpl::ConsumeCounterStyleRule(
    CSSParserTokenStream& stream) {
  // Parse the prelude.
  wtf_size_t prelude_offset_start = stream.LookAheadOffset();
  AtomicString name = css_parsing_utils::ConsumeCounterStyleNameInPrelude(
      stream, *GetContext());
  if (!name) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleCounterStyle);
    return nullptr;
  }
  wtf_size_t prelude_offset_end = stream.LookAheadOffset();
  if (!ConsumeEndOfPreludeForAtRuleWithBlock(
          stream, CSSAtRuleID::kCSSAtRuleCounterStyle)) {
    return nullptr;
  }

  // Parse the actual block.
  CSSParserTokenStream::BlockGuard guard(stream);
  if (observer_) {
    observer_->StartRuleHeader(StyleRule::kCounterStyle, prelude_offset_start);
    observer_->EndRuleHeader(prelude_offset_end);
    observer_->StartRuleBody(stream.Offset());
  }

  ConsumeBlockContents(stream, StyleRule::kCounterStyle, CSSNestingType::kNone,
                       /*parent_rule_for_nesting=*/nullptr,
                       /*is_within_scope=*/false,
                       /*nested_declarations_start_index=*/kNotFound,
                       /*child_rules=*/nullptr);

  if (observer_) {
    observer_->EndRuleBody(stream.LookAheadOffset());
  }

  return MakeGarbageCollected<StyleRuleCounterStyle>(
      name, CreateCSSPropertyValueSet(parsed_properties_, context_->Mode(),
                                      context_->GetDocument()));
}

StyleRuleFontPaletteValues* CSSParserImpl::ConsumeFontPaletteValuesRule(
    CSSParserTokenStream& stream) {
  // Parse the prelude.
  wtf_size_t prelude_offset_start = stream.LookAheadOffset();
  const CSSParserToken& name_token = stream.Peek();
  if (!css_parsing_utils::IsDashedIdent(name_token)) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleFontPaletteValues);
    return nullptr;
  }
  AtomicString name = name_token.Value().ToAtomicString();
  if (!name) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleFontPaletteValues);
    return nullptr;
  }
  stream.ConsumeIncludingWhitespace();
  wtf_size_t prelude_offset_end = stream.LookAheadOffset();
  if (!ConsumeEndOfPreludeForAtRuleWithBlock(
          stream, CSSAtRuleID::kCSSAtRuleFontPaletteValues)) {
    return nullptr;
  }

  // Parse the actual block.
  CSSParserTokenStream::BlockGuard guard(stream);
  if (observer_) {
    observer_->StartRuleHeader(StyleRule::kFontPaletteValues,
                               prelude_offset_start);
    observer_->EndRuleHeader(prelude_offset_end);
    observer_->StartRuleBody(stream.Offset());
  }

  ConsumeBlockContents(stream, StyleRule::kFontPaletteValues,
                       CSSNestingType::kNone,
                       /*parent_rule_for_nesting=*/nullptr,
                       /*is_within_scope=*/false,
                       /*nested_declarations_start_index=*/kNotFound,
                       /*child_rules=*/nullptr);

  if (observer_) {
    observer_->EndRuleBody(stream.LookAheadOffset());
  }

  return MakeGarbageCollected<StyleRuleFontPaletteValues>(
      name, CreateCSSPropertyValueSet(parsed_properties_,
                                      kCSSFontPaletteValuesRuleMode,
                                      context_->GetDocument()));
}

StyleRuleBase* CSSParserImpl::ConsumeScopeRule(
    CSSParserTokenStream& stream,
    CSSNestingType nesting_type,
    StyleRule* parent_rule_for_nesting,
    bool is_within_scope) {
  // Parse the prelude.
  wtf_size_t prelude_offset_start = stream.LookAheadOffset();
  auto* style_scope =
      StyleScope::Parse(stream, context_, nesting_type, parent_rule_for_nesting,
                        is_within_scope, style_sheet_);
  if (!style_scope) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleScope);
    return nullptr;
  }

  wtf_size_t prelude_offset_end = stream.LookAheadOffset();
  if (!ConsumeEndOfPreludeForAtRuleWithBlock(stream,
                                             CSSAtRuleID::kCSSAtRuleScope)) {
    return nullptr;
  }

  if (observer_) {
    observer_->StartRuleHeader(StyleRule::kScope, prelude_offset_start);
    observer_->EndRuleHeader(prelude_offset_end);
    observer_->StartRuleBody(stream.Offset());
  }

  // Parse the actual block.
  CSSParserTokenStream::BlockGuard guard(stream);

  HeapVector<Member<StyleRuleBase>, 4> rules;
  ConsumeBlockContents(
      stream, StyleRule::kScope, CSSNestingType::kScope,
      /*parent_rule_for_nesting=*/style_scope->RuleForNesting(),
      /*is_within_scope=*/true,
      /*nested_declarations_start_index=*/0, &rules);

  if (observer_) {
    observer_->EndRuleBody(stream.Offset());
  }

  return MakeGarbageCollected<StyleRuleScope>(*style_scope, std::move(rules));
}

StyleRuleViewTransition* CSSParserImpl::ConsumeViewTransitionRule(
    CSSParserTokenStream& stream) {
  CHECK(RuntimeEnabledFeatures::ViewTransitionOnNavigationEnabled());
  // NOTE: @view-transition prelude should be empty.
  wtf_size_t prelude_offset_start = stream.LookAheadOffset();
  wtf_size_t prelude_offset_end = stream.LookAheadOffset();
  if (!ConsumeEndOfPreludeForAtRuleWithBlock(
          stream, CSSAtRuleID::kCSSAtRuleViewTransition)) {
    return nullptr;
  }

  CSSParserTokenStream::BlockGuard guard(stream);
  if (observer_) {
    observer_->StartRuleHeader(StyleRule::kViewTransition,
                               prelude_offset_start);
    observer_->EndRuleHeader(prelude_offset_end);
    observer_->StartRuleBody(stream.Offset());
  }
  ConsumeBlockContents(stream, StyleRule::kViewTransition,
                       CSSNestingType::kNone,
                       /*parent_rule_for_nesting=*/nullptr,
                       /*is_within_scope=*/false,
                       /*nested_declarations_start_index=*/kNotFound,
                       /*child_rules=*/nullptr);

  if (observer_) {
    observer_->EndRuleBody(stream.LookAheadOffset());
  }

  return MakeGarbageCollected<StyleRuleViewTransition>(
      *CreateCSSPropertyValueSet(parsed_properties_, context_->Mode(),
                                 context_->GetDocument()));
}

StyleRuleContainer* CSSParserImpl::ConsumeContainerRule(
    CSSParserTokenStream& stream,
    CSSNestingType nesting_type,
    StyleRule* parent_rule_for_nesting,
    bool is_within_scope) {
  // Consume the prelude.
  wtf_size_t prelude_offset_start = stream.LookAheadOffset();
  ContainerQueryParser query_parser(*context_);

  // <container-name>
  AtomicString name;
  if (stream.Peek().GetType() == kIdentToken) {
    auto* ident = DynamicTo<CSSCustomIdentValue>(
        css_parsing_utils::ConsumeSingleContainerName(stream, *context_));
    if (ident) {
      name = ident->Value();
    }
  }

  const MediaQueryExpNode* query = query_parser.ParseCondition(stream);
  if (!query) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleContainer);
    return nullptr;
  }
  ContainerQuery* container_query = MakeGarbageCollected<ContainerQuery>(
      ContainerSelector(std::move(name), *query), query);

  wtf_size_t prelude_offset_end = stream.LookAheadOffset();
  if (!ConsumeEndOfPreludeForAtRuleWithBlock(
          stream, CSSAtRuleID::kCSSAtRuleContainer)) {
    return nullptr;
  }

  // Consume the actual block.
  CSSParserTokenStream::BlockGuard guard(stream);

  if (observer_) {
    observer_->StartRuleHeader(StyleRule::kContainer, prelude_offset_start);
    observer_->EndRuleHeader(prelude_offset_end);
    observer_->StartRuleBody(stream.Offset());
  }

  HeapVector<Member<StyleRuleBase>, 4> rules;
  ConsumeRuleListOrNestedDeclarationList(
      stream,
      /* is_nested_group_rule */ nesting_type == CSSNestingType::kNesting,
      nesting_type, parent_rule_for_nesting, is_within_scope, &rules);

  if (observer_) {
    observer_->EndRuleBody(stream.Offset());
  }

  // NOTE: There will be a copy of rules here, to deal with the different inline
  // size.
  return MakeGarbageCollected<StyleRuleContainer>(*container_query,
                                                  std::move(rules));
}

StyleRuleBase* CSSParserImpl::ConsumeLayerRule(
    CSSParserTokenStream& stream,
    CSSNestingType nesting_type,
    StyleRule* parent_rule_for_nesting,
    bool is_within_scope) {
  // Consume the prelude.
  wtf_size_t prelude_offset_start = stream.LookAheadOffset();

  Vector<StyleRuleBase::LayerName> names;
  while (!stream.AtEnd() && stream.Peek().GetType() != kLeftBraceToken &&
         stream.Peek().GetType() != kSemicolonToken) {
    if (names.size()) {
      if (!css_parsing_utils::ConsumeCommaIncludingWhitespace(stream)) {
        ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleLayer);
        return nullptr;
      }
    }
    StyleRuleBase::LayerName name = ConsumeCascadeLayerName(stream);
    if (!name.size()) {
      ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleLayer);
      return nullptr;
    }
    names.push_back(std::move(name));
  }

  // @layer statement rule without style declarations.
  if (stream.AtEnd() || stream.UncheckedPeek().GetType() == kSemicolonToken) {
    if (!names.size()) {
      ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleLayer);
      return nullptr;
    }

    if (nesting_type == CSSNestingType::kNesting) {
      // @layer statement rules are not group rules, and can therefore
      // not be nested.
      //
      // https://drafts.csswg.org/css-nesting-1/#nested-group-rules
      ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleLayer);
      return nullptr;
    }

    wtf_size_t prelude_offset_end = stream.LookAheadOffset();
    if (!ConsumeEndOfPreludeForAtRuleWithoutBlock(
            stream, CSSAtRuleID::kCSSAtRuleLayer)) {
      return nullptr;
    }

    if (observer_) {
      observer_->StartRuleHeader(StyleRule::kLayerStatement,
                                 prelude_offset_start);
      observer_->EndRuleHeader(prelude_offset_end);
      observer_->StartRuleBody(prelude_offset_end);
      observer_->EndRuleBody(prelude_offset_end);
    }

    return MakeGarbageCollected<StyleRuleLayerStatement>(std::move(names));
  }

  // @layer block rule with style declarations.
  StyleRuleBase::LayerName name;
  if (names.empty()) {
    name.push_back(g_empty_atom);
  } else if (names.size() > 1) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleLayer);
    return nullptr;
  } else {
    name = std::move(names[0]);
  }

  wtf_size_t prelude_offset_end = stream.LookAheadOffset();

  if (!ConsumeEndOfPreludeForAtRuleWithBlock(stream,
                                             CSSAtRuleID::kCSSAtRuleLayer)) {
    return nullptr;
  }

  // Consume the actual block.
  CSSParserTokenStream::BlockGuard guard(stream);

  if (observer_) {
    observer_->StartRuleHeader(StyleRule::kLayerBlock, prelude_offset_start);
    observer_->EndRuleHeader(prelude_offset_end);
    observer_->StartRuleBody(stream.Offset());
  }

  HeapVector<Member<StyleRuleBase>, 4> rules;
  ConsumeRuleListOrNestedDeclarationList(
      stream,
      /* is_nested_group_rule */ nesting_type == CSSNestingType::kNesting,
      nesting_type, parent_rule_for_nesting, is_within_scope, &rules);

  if (observer_) {
    observer_->EndRuleBody(stream.Offset());
  }

  return MakeGarbageCollected<StyleRuleLayerBlock>(std::move(name),
                                                   std::move(rules));
}

StyleRulePositionTry* CSSParserImpl::ConsumePositionTryRule(
    CSSParserTokenStream& stream) {
  // Parse the prelude.
  wtf_size_t prelude_offset_start = stream.LookAheadOffset();
  const CSSParserToken& name_token = stream.Peek();
  // <dashed-ident>, and -internal-* for UA sheets only.
  String name;
  if (name_token.GetType() == kIdentToken) {
    name = name_token.Value().ToString();
    if (!name.StartsWith("--") &&
        !(context_->Mode() == kUASheetMode && name.StartsWith("-internal-"))) {
      ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRulePositionTry);
      return nullptr;
    }
  } else {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRulePositionTry);
    return nullptr;
  }
  stream.ConsumeIncludingWhitespace();
  wtf_size_t prelude_offset_end = stream.LookAheadOffset();
  if (!ConsumeEndOfPreludeForAtRuleWithBlock(
          stream, CSSAtRuleID::kCSSAtRulePositionTry)) {
    return nullptr;
  }

  // Parse the actual block.
  CSSParserTokenStream::BlockGuard guard(stream);
  if (observer_) {
    observer_->StartRuleHeader(StyleRule::kPositionTry, prelude_offset_start);
    observer_->EndRuleHeader(prelude_offset_end);
    observer_->StartRuleBody(stream.Offset());
  }

  ConsumeBlockContents(stream, StyleRule::kPositionTry, CSSNestingType::kNone,
                       /*parent_rule_for_nesting=*/nullptr,
                       /*is_within_scope=*/false,
                       /*nested_declarations_start_index=*/kNotFound,
                       /*child_rules=*/nullptr);

  if (observer_) {
    observer_->EndRuleBody(stream.LookAheadOffset());
  }

  return MakeGarbageCollected<StyleRulePositionTry>(
      AtomicString(name),
      CreateCSSPropertyValueSet(parsed_properties_, kCSSPositionTryRuleMode,
                                context_->GetDocument()));
}

// Parse a type for CSS Functions; e.g. length, color, etc..
// These are being converted to the syntax used by registered custom properties.
// The parameter is assumed to be a single ident token.
static std::optional<StyleRuleFunction::Type> ParseFunctionType(
    StringView type_name) {
  std::optional<CSSSyntaxDefinition> syntax_def;
  if (type_name == "any") {
    syntax_def = CSSSyntaxStringParser("*").Parse();
  } else {
    syntax_def =
        CSSSyntaxStringParser("<" + type_name.ToString() + ">").Parse();
  }
  if (!syntax_def) {
    return {};
  }

  CHECK_EQ(syntax_def->Components().size(), 1u);
  bool should_add_implicit_calc = false;
  if (!syntax_def->IsUniversal()) {
    // These are all the supported values in CSSSyntaxDefinition that are
    // acceptable as inputs to calc(); see
    // https://drafts.csswg.org/css-values/#math.
    switch (syntax_def->Components()[0].GetType()) {
      case CSSSyntaxType::kLength:
        // kFrequency is missing.
      case CSSSyntaxType::kAngle:
      case CSSSyntaxType::kTime:
        // kFlex is missing.
      case CSSSyntaxType::kResolution:
      case CSSSyntaxType::kPercentage:
      case CSSSyntaxType::kNumber:
      case CSSSyntaxType::kInteger:
      case CSSSyntaxType::kLengthPercentage:
        should_add_implicit_calc = true;
        break;
      case CSSSyntaxType::kTokenStream:
      case CSSSyntaxType::kIdent:
      case CSSSyntaxType::kColor:
      case CSSSyntaxType::kImage:
      case CSSSyntaxType::kUrl:
      case CSSSyntaxType::kTransformFunction:
      case CSSSyntaxType::kTransformList:
      case CSSSyntaxType::kCustomIdent:
        break;
      case CSSSyntaxType::kString:
        DCHECK(RuntimeEnabledFeatures::CSSAtPropertyStringSyntaxEnabled());
        break;
    }
  }

  return StyleRuleFunction::Type{std::move(*syntax_def),
                                 should_add_implicit_calc};
}

StyleRuleFunction* CSSParserImpl::ConsumeFunctionRule(
    CSSParserTokenStream& stream) {
  // Parse the prelude; first a function token (the name), then parameters,
  // then return type.
  if (stream.Peek().GetType() != kFunctionToken) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleFunction);
    return nullptr;  // Parse error.
  }
  AtomicString name =
      stream.Peek()
          .Value()
          .ToAtomicString();  // Includes the opening parenthesis.
  std::optional<Vector<StyleRuleFunction::Parameter>> parameters;
  {
    CSSParserTokenStream::BlockGuard guard(stream);
    stream.ConsumeWhitespace();
    parameters = ConsumeFunctionParameters(stream);
  }
  if (!parameters.has_value()) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleFunction);
    return nullptr;
  }
  stream.ConsumeWhitespace();

  // Parse the return type.
  if (stream.Peek().GetType() != kColonToken) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleFunction);
    return nullptr;
  }
  stream.ConsumeIncludingWhitespace();

  if (stream.Peek().GetType() != kIdentToken) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleFunction);
    return nullptr;
  }
  StringView return_type_name = stream.Peek().Value();
  std::optional<StyleRuleFunction::Type> return_type =
      ParseFunctionType(return_type_name);
  if (!return_type) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleFunction);
    return nullptr;  // Invalid type name.
  }
  stream.ConsumeIncludingWhitespace();

  if (!ConsumeEndOfPreludeForAtRuleWithBlock(stream,
                                             CSSAtRuleID::kCSSAtRuleFunction)) {
    return nullptr;
  }

  // Parse the actual block.
  CSSParserTokenStream::BlockGuard guard(stream);
  stream.ConsumeWhitespace();

  // TODO: Parse local variables.

  // Parse @return.
  if (stream.Peek().GetType() != kAtKeywordToken) {
    return nullptr;
  }
  const CSSParserToken return_token = stream.ConsumeIncludingWhitespace();
  if (return_token.Value() != "return") {
    return nullptr;
  }

  // Parse the actual returned value.
  CSSVariableData* return_value = nullptr;
  {
    CSSParserTokenStream::Boundary boundary(stream, kSemicolonToken);
    bool important_ignored;
    return_value = CSSVariableParser::ConsumeUnparsedDeclaration(
        stream, /*allow_important_annotation=*/false,
        /*is_animation_tainted=*/false,
        /*must_contain_variable_reference=*/false, /*restricted_value=*/false,
        /*comma_ends_declaration=*/false, important_ignored, *context_);
  }

  while (!stream.AtEnd()) {
    const CSSParserToken token = stream.ConsumeIncludingWhitespace();
    StringBuilder sb;
    token.Serialize(sb);
  }

  return MakeGarbageCollected<StyleRuleFunction>(
      name, std::move(*parameters), return_value, std::move(*return_type));
}

StyleRuleMixin* CSSParserImpl::ConsumeMixinRule(CSSParserTokenStream& stream) {
  // @mixin must be top-level, and as such, we need to clear the arena
  // after we're done parsing it (like ConsumeStyleRule() does).
  if (in_nested_style_rule_) {
    return nullptr;
  }
  auto func_clear_arena = [&](HeapVector<CSSSelector>* arena) {
    arena->resize(0);  // See class comment on CSSSelectorParser.
  };
  std::unique_ptr<HeapVector<CSSSelector>, decltype(func_clear_arena)>
      scope_guard(&arena_, std::move(func_clear_arena));

  // Parse the prelude; just a function token (the name).
  if (stream.Peek().GetType() != kIdentToken) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleMixin);
    return nullptr;  // Parse error.
  }
  AtomicString name =
      stream.ConsumeIncludingWhitespace().Value().ToAtomicString();
  if (!name.StartsWith("--")) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleMixin);
    return nullptr;
  }

  if (!ConsumeEndOf
### 提示词
```
这是目录为blink/renderer/core/css/parser/css_parser_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
itespace();

    font_feature_rule->UpdateAlias(alias, std::move(parsed_numbers));
  }

  return font_feature_rule;
}

StyleRuleFontFeatureValues* CSSParserImpl::ConsumeFontFeatureValuesRule(
    CSSParserTokenStream& stream) {
  // Parse the prelude.
  wtf_size_t prelude_offset_start = stream.LookAheadOffset();
  CSSValueList* family_list = css_parsing_utils::ConsumeFontFamily(stream);
  if (!family_list || !family_list->length()) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleFontFeatureValues);
    return nullptr;
  }
  wtf_size_t prelude_offset_end = stream.LookAheadOffset();
  if (!ConsumeEndOfPreludeForAtRuleWithBlock(
          stream, CSSAtRuleID::kCSSAtRuleFontFeatureValues)) {
    return nullptr;
  }
  CSSParserTokenStream::BlockGuard guard(stream);

  if (observer_) {
    observer_->StartRuleHeader(StyleRule::kFontFeatureValues,
                               prelude_offset_start);
    observer_->EndRuleHeader(prelude_offset_end);
    observer_->StartRuleBody(stream.Offset());
  }

  // Parse the actual block.

  // The nesting logic for parsing @font-feature-values looks as follow:
  // 1) ConsumeRuleList, calls ConsumeAtRule, and in turn ConsumeAtRuleContents
  // 2) ConsumeAtRuleContents uses new ids for inner at-rules, for swash,
  // styleset etc.
  // 3) ConsumeFeatureRule (with type) consumes the inner mappings from aliases
  // to number lists.

  FontFeatureAliases stylistic;
  FontFeatureAliases styleset;
  FontFeatureAliases character_variant;
  FontFeatureAliases swash;
  FontFeatureAliases ornaments;
  FontFeatureAliases annotation;

  HeapVector<Member<StyleRuleFontFeature>> feature_rules;
  bool had_valid_rules = false;
  // ConsumeRuleList returns true only if the first rule is true, but we need to
  // be more generous with the internals of what's inside a font feature value
  // declaration, e.g. inside a @stylsitic, @styleset, etc.
  if (ConsumeRuleList(
          stream, kFontFeatureRuleList, CSSNestingType::kNone,
          /*parent_rule_for_nesting=*/nullptr,
          /*is_within_scope=*/false,
          [&feature_rules, &had_valid_rules](StyleRuleBase* rule, wtf_size_t) {
            if (rule) {
              had_valid_rules = true;
            }
            feature_rules.push_back(To<StyleRuleFontFeature>(rule));
          }) ||
      had_valid_rules) {
    // https://drafts.csswg.org/css-fonts-4/#font-feature-values-syntax
    // "Specifying the same <font-feature-value-type> more than once is valid;
    // their contents are cascaded together."
    for (auto& feature_rule : feature_rules) {
      switch (feature_rule->GetFeatureType()) {
        case StyleRuleFontFeature::FeatureType::kStylistic:
          feature_rule->OverrideAliasesIn(stylistic);
          break;
        case StyleRuleFontFeature::FeatureType::kStyleset:
          feature_rule->OverrideAliasesIn(styleset);
          break;
        case StyleRuleFontFeature::FeatureType::kCharacterVariant:
          feature_rule->OverrideAliasesIn(character_variant);
          break;
        case StyleRuleFontFeature::FeatureType::kSwash:
          feature_rule->OverrideAliasesIn(swash);
          break;
        case StyleRuleFontFeature::FeatureType::kOrnaments:
          feature_rule->OverrideAliasesIn(ornaments);
          break;
        case StyleRuleFontFeature::FeatureType::kAnnotation:
          feature_rule->OverrideAliasesIn(annotation);
          break;
      }
    }
  }

  Vector<AtomicString> families;
  for (const auto family_entry : *family_list) {
    const CSSFontFamilyValue* family_value =
        DynamicTo<CSSFontFamilyValue>(*family_entry);
    if (!family_value) {
      return nullptr;
    }
    families.push_back(family_value->Value());
  }

  auto* feature_values_rule = MakeGarbageCollected<StyleRuleFontFeatureValues>(
      std::move(families), stylistic, styleset, character_variant, swash,
      ornaments, annotation);

  if (observer_) {
    observer_->EndRuleBody(stream.Offset());
  }

  return feature_values_rule;
}

// Parse an @page rule, with contents.
StyleRulePage* CSSParserImpl::ConsumePageRule(CSSParserTokenStream& stream) {
  // Parse the prelude.
  wtf_size_t prelude_offset_start = stream.LookAheadOffset();
  CSSSelectorList* selector_list =
      ParsePageSelector(stream, style_sheet_, *context_);
  if (!selector_list || !selector_list->IsValid()) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRulePage);
    return nullptr;  // Parse error, invalid @page selector
  }
  wtf_size_t prelude_offset_end = stream.LookAheadOffset();
  if (!ConsumeEndOfPreludeForAtRuleWithBlock(stream,
                                             CSSAtRuleID::kCSSAtRulePage)) {
    return nullptr;
  }

  // Parse the actual block.
  CSSParserTokenStream::BlockGuard guard(stream);

  if (observer_) {
    observer_->StartRuleHeader(StyleRule::kPage, prelude_offset_start);
    observer_->EndRuleHeader(prelude_offset_end);
    observer_->StartRuleBody(stream.Offset());
  }

  HeapVector<Member<StyleRuleBase>, 4> child_rules;
  ConsumeBlockContents(stream, StyleRule::kPage, CSSNestingType::kNone,
                       /*parent_rule_for_nesting=*/nullptr,
                       /*is_within_scope=*/false,
                       /*nested_declarations_start_index=*/kNotFound,
                       &child_rules);

  if (observer_) {
    observer_->EndRuleBody(stream.LookAheadOffset());
  }

  return MakeGarbageCollected<StyleRulePage>(
      selector_list,
      CreateCSSPropertyValueSet(parsed_properties_, context_->Mode(),
                                context_->GetDocument()),
      child_rules);
}

StyleRuleProperty* CSSParserImpl::ConsumePropertyRule(
    CSSParserTokenStream& stream) {
  // Parse the prelude.
  wtf_size_t prelude_offset_start = stream.LookAheadOffset();
  const CSSParserToken& name_token = stream.ConsumeIncludingWhitespace();
  if (!CSSVariableParser::IsValidVariableName(name_token)) {
    if (observer_) {
      observer_->ObserveErroneousAtRule(prelude_offset_start,
                                        CSSAtRuleID::kCSSAtRuleProperty);
    }
    return nullptr;
  }
  String name = name_token.Value().ToString();
  wtf_size_t prelude_offset_end = stream.LookAheadOffset();
  if (!ConsumeEndOfPreludeForAtRuleWithBlock(stream,
                                             CSSAtRuleID::kCSSAtRuleProperty)) {
    return nullptr;
  }

  // Parse the body.
  CSSParserTokenStream::BlockGuard guard(stream);

  if (observer_) {
    observer_->StartRuleHeader(StyleRule::kProperty, prelude_offset_start);
    observer_->EndRuleHeader(prelude_offset_end);
    observer_->StartRuleBody(stream.Offset());
  }

  ConsumeBlockContents(stream, StyleRule::kProperty, CSSNestingType::kNone,
                       /*parent_rule_for_nesting=*/nullptr,
                       /*is_within_scope=*/false,
                       /*nested_declarations_start_index=*/kNotFound,
                       /*child_rules=*/nullptr);

  if (observer_) {
    observer_->EndRuleBody(stream.LookAheadOffset());
  }

  StyleRuleProperty* rule = MakeGarbageCollected<StyleRuleProperty>(
      name, CreateCSSPropertyValueSet(parsed_properties_, kCSSPropertyRuleMode,
                                      context_->GetDocument()));

  std::optional<CSSSyntaxDefinition> syntax =
      PropertyRegistration::ConvertSyntax(rule->GetSyntax());
  std::optional<bool> inherits =
      PropertyRegistration::ConvertInherits(rule->Inherits());
  std::optional<const CSSValue*> initial =
      syntax.has_value() ? PropertyRegistration::ConvertInitial(
                               rule->GetInitialValue(), *syntax, *context_)
                         : std::nullopt;

  bool invalid_rule =
      !syntax.has_value() || !inherits.has_value() || !initial.has_value();

  if (observer_ && invalid_rule) {
    Vector<CSSPropertyID, 2> failed_properties;
    if (!syntax.has_value()) {
      failed_properties.push_back(CSSPropertyID::kSyntax);
    }
    if (!inherits.has_value()) {
      failed_properties.push_back(CSSPropertyID::kInherits);
    }
    if (!initial.has_value() && syntax.has_value()) {
      failed_properties.push_back(CSSPropertyID::kInitialValue);
    }
    DCHECK(!failed_properties.empty());
    observer_->ObserveErroneousAtRule(prelude_offset_start,
                                      CSSAtRuleID::kCSSAtRuleProperty,
                                      failed_properties);
  }
  if (invalid_rule) {
    return nullptr;
  }
  return rule;
}

StyleRuleCounterStyle* CSSParserImpl::ConsumeCounterStyleRule(
    CSSParserTokenStream& stream) {
  // Parse the prelude.
  wtf_size_t prelude_offset_start = stream.LookAheadOffset();
  AtomicString name = css_parsing_utils::ConsumeCounterStyleNameInPrelude(
      stream, *GetContext());
  if (!name) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleCounterStyle);
    return nullptr;
  }
  wtf_size_t prelude_offset_end = stream.LookAheadOffset();
  if (!ConsumeEndOfPreludeForAtRuleWithBlock(
          stream, CSSAtRuleID::kCSSAtRuleCounterStyle)) {
    return nullptr;
  }

  // Parse the actual block.
  CSSParserTokenStream::BlockGuard guard(stream);
  if (observer_) {
    observer_->StartRuleHeader(StyleRule::kCounterStyle, prelude_offset_start);
    observer_->EndRuleHeader(prelude_offset_end);
    observer_->StartRuleBody(stream.Offset());
  }

  ConsumeBlockContents(stream, StyleRule::kCounterStyle, CSSNestingType::kNone,
                       /*parent_rule_for_nesting=*/nullptr,
                       /*is_within_scope=*/false,
                       /*nested_declarations_start_index=*/kNotFound,
                       /*child_rules=*/nullptr);

  if (observer_) {
    observer_->EndRuleBody(stream.LookAheadOffset());
  }

  return MakeGarbageCollected<StyleRuleCounterStyle>(
      name, CreateCSSPropertyValueSet(parsed_properties_, context_->Mode(),
                                      context_->GetDocument()));
}

StyleRuleFontPaletteValues* CSSParserImpl::ConsumeFontPaletteValuesRule(
    CSSParserTokenStream& stream) {
  // Parse the prelude.
  wtf_size_t prelude_offset_start = stream.LookAheadOffset();
  const CSSParserToken& name_token = stream.Peek();
  if (!css_parsing_utils::IsDashedIdent(name_token)) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleFontPaletteValues);
    return nullptr;
  }
  AtomicString name = name_token.Value().ToAtomicString();
  if (!name) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleFontPaletteValues);
    return nullptr;
  }
  stream.ConsumeIncludingWhitespace();
  wtf_size_t prelude_offset_end = stream.LookAheadOffset();
  if (!ConsumeEndOfPreludeForAtRuleWithBlock(
          stream, CSSAtRuleID::kCSSAtRuleFontPaletteValues)) {
    return nullptr;
  }

  // Parse the actual block.
  CSSParserTokenStream::BlockGuard guard(stream);
  if (observer_) {
    observer_->StartRuleHeader(StyleRule::kFontPaletteValues,
                               prelude_offset_start);
    observer_->EndRuleHeader(prelude_offset_end);
    observer_->StartRuleBody(stream.Offset());
  }

  ConsumeBlockContents(stream, StyleRule::kFontPaletteValues,
                       CSSNestingType::kNone,
                       /*parent_rule_for_nesting=*/nullptr,
                       /*is_within_scope=*/false,
                       /*nested_declarations_start_index=*/kNotFound,
                       /*child_rules=*/nullptr);

  if (observer_) {
    observer_->EndRuleBody(stream.LookAheadOffset());
  }

  return MakeGarbageCollected<StyleRuleFontPaletteValues>(
      name, CreateCSSPropertyValueSet(parsed_properties_,
                                      kCSSFontPaletteValuesRuleMode,
                                      context_->GetDocument()));
}

StyleRuleBase* CSSParserImpl::ConsumeScopeRule(
    CSSParserTokenStream& stream,
    CSSNestingType nesting_type,
    StyleRule* parent_rule_for_nesting,
    bool is_within_scope) {
  // Parse the prelude.
  wtf_size_t prelude_offset_start = stream.LookAheadOffset();
  auto* style_scope =
      StyleScope::Parse(stream, context_, nesting_type, parent_rule_for_nesting,
                        is_within_scope, style_sheet_);
  if (!style_scope) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleScope);
    return nullptr;
  }

  wtf_size_t prelude_offset_end = stream.LookAheadOffset();
  if (!ConsumeEndOfPreludeForAtRuleWithBlock(stream,
                                             CSSAtRuleID::kCSSAtRuleScope)) {
    return nullptr;
  }

  if (observer_) {
    observer_->StartRuleHeader(StyleRule::kScope, prelude_offset_start);
    observer_->EndRuleHeader(prelude_offset_end);
    observer_->StartRuleBody(stream.Offset());
  }

  // Parse the actual block.
  CSSParserTokenStream::BlockGuard guard(stream);

  HeapVector<Member<StyleRuleBase>, 4> rules;
  ConsumeBlockContents(
      stream, StyleRule::kScope, CSSNestingType::kScope,
      /*parent_rule_for_nesting=*/style_scope->RuleForNesting(),
      /*is_within_scope=*/true,
      /*nested_declarations_start_index=*/0, &rules);

  if (observer_) {
    observer_->EndRuleBody(stream.Offset());
  }

  return MakeGarbageCollected<StyleRuleScope>(*style_scope, std::move(rules));
}

StyleRuleViewTransition* CSSParserImpl::ConsumeViewTransitionRule(
    CSSParserTokenStream& stream) {
  CHECK(RuntimeEnabledFeatures::ViewTransitionOnNavigationEnabled());
  // NOTE: @view-transition prelude should be empty.
  wtf_size_t prelude_offset_start = stream.LookAheadOffset();
  wtf_size_t prelude_offset_end = stream.LookAheadOffset();
  if (!ConsumeEndOfPreludeForAtRuleWithBlock(
          stream, CSSAtRuleID::kCSSAtRuleViewTransition)) {
    return nullptr;
  }

  CSSParserTokenStream::BlockGuard guard(stream);
  if (observer_) {
    observer_->StartRuleHeader(StyleRule::kViewTransition,
                               prelude_offset_start);
    observer_->EndRuleHeader(prelude_offset_end);
    observer_->StartRuleBody(stream.Offset());
  }
  ConsumeBlockContents(stream, StyleRule::kViewTransition,
                       CSSNestingType::kNone,
                       /*parent_rule_for_nesting=*/nullptr,
                       /*is_within_scope=*/false,
                       /*nested_declarations_start_index=*/kNotFound,
                       /*child_rules=*/nullptr);

  if (observer_) {
    observer_->EndRuleBody(stream.LookAheadOffset());
  }

  return MakeGarbageCollected<StyleRuleViewTransition>(
      *CreateCSSPropertyValueSet(parsed_properties_, context_->Mode(),
                                 context_->GetDocument()));
}

StyleRuleContainer* CSSParserImpl::ConsumeContainerRule(
    CSSParserTokenStream& stream,
    CSSNestingType nesting_type,
    StyleRule* parent_rule_for_nesting,
    bool is_within_scope) {
  // Consume the prelude.
  wtf_size_t prelude_offset_start = stream.LookAheadOffset();
  ContainerQueryParser query_parser(*context_);

  // <container-name>
  AtomicString name;
  if (stream.Peek().GetType() == kIdentToken) {
    auto* ident = DynamicTo<CSSCustomIdentValue>(
        css_parsing_utils::ConsumeSingleContainerName(stream, *context_));
    if (ident) {
      name = ident->Value();
    }
  }

  const MediaQueryExpNode* query = query_parser.ParseCondition(stream);
  if (!query) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleContainer);
    return nullptr;
  }
  ContainerQuery* container_query = MakeGarbageCollected<ContainerQuery>(
      ContainerSelector(std::move(name), *query), query);

  wtf_size_t prelude_offset_end = stream.LookAheadOffset();
  if (!ConsumeEndOfPreludeForAtRuleWithBlock(
          stream, CSSAtRuleID::kCSSAtRuleContainer)) {
    return nullptr;
  }

  // Consume the actual block.
  CSSParserTokenStream::BlockGuard guard(stream);

  if (observer_) {
    observer_->StartRuleHeader(StyleRule::kContainer, prelude_offset_start);
    observer_->EndRuleHeader(prelude_offset_end);
    observer_->StartRuleBody(stream.Offset());
  }

  HeapVector<Member<StyleRuleBase>, 4> rules;
  ConsumeRuleListOrNestedDeclarationList(
      stream,
      /* is_nested_group_rule */ nesting_type == CSSNestingType::kNesting,
      nesting_type, parent_rule_for_nesting, is_within_scope, &rules);

  if (observer_) {
    observer_->EndRuleBody(stream.Offset());
  }

  // NOTE: There will be a copy of rules here, to deal with the different inline
  // size.
  return MakeGarbageCollected<StyleRuleContainer>(*container_query,
                                                  std::move(rules));
}

StyleRuleBase* CSSParserImpl::ConsumeLayerRule(
    CSSParserTokenStream& stream,
    CSSNestingType nesting_type,
    StyleRule* parent_rule_for_nesting,
    bool is_within_scope) {
  // Consume the prelude.
  wtf_size_t prelude_offset_start = stream.LookAheadOffset();

  Vector<StyleRuleBase::LayerName> names;
  while (!stream.AtEnd() && stream.Peek().GetType() != kLeftBraceToken &&
         stream.Peek().GetType() != kSemicolonToken) {
    if (names.size()) {
      if (!css_parsing_utils::ConsumeCommaIncludingWhitespace(stream)) {
        ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleLayer);
        return nullptr;
      }
    }
    StyleRuleBase::LayerName name = ConsumeCascadeLayerName(stream);
    if (!name.size()) {
      ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleLayer);
      return nullptr;
    }
    names.push_back(std::move(name));
  }

  // @layer statement rule without style declarations.
  if (stream.AtEnd() || stream.UncheckedPeek().GetType() == kSemicolonToken) {
    if (!names.size()) {
      ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleLayer);
      return nullptr;
    }

    if (nesting_type == CSSNestingType::kNesting) {
      // @layer statement rules are not group rules, and can therefore
      // not be nested.
      //
      // https://drafts.csswg.org/css-nesting-1/#nested-group-rules
      ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleLayer);
      return nullptr;
    }

    wtf_size_t prelude_offset_end = stream.LookAheadOffset();
    if (!ConsumeEndOfPreludeForAtRuleWithoutBlock(
            stream, CSSAtRuleID::kCSSAtRuleLayer)) {
      return nullptr;
    }

    if (observer_) {
      observer_->StartRuleHeader(StyleRule::kLayerStatement,
                                 prelude_offset_start);
      observer_->EndRuleHeader(prelude_offset_end);
      observer_->StartRuleBody(prelude_offset_end);
      observer_->EndRuleBody(prelude_offset_end);
    }

    return MakeGarbageCollected<StyleRuleLayerStatement>(std::move(names));
  }

  // @layer block rule with style declarations.
  StyleRuleBase::LayerName name;
  if (names.empty()) {
    name.push_back(g_empty_atom);
  } else if (names.size() > 1) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleLayer);
    return nullptr;
  } else {
    name = std::move(names[0]);
  }

  wtf_size_t prelude_offset_end = stream.LookAheadOffset();

  if (!ConsumeEndOfPreludeForAtRuleWithBlock(stream,
                                             CSSAtRuleID::kCSSAtRuleLayer)) {
    return nullptr;
  }

  // Consume the actual block.
  CSSParserTokenStream::BlockGuard guard(stream);

  if (observer_) {
    observer_->StartRuleHeader(StyleRule::kLayerBlock, prelude_offset_start);
    observer_->EndRuleHeader(prelude_offset_end);
    observer_->StartRuleBody(stream.Offset());
  }

  HeapVector<Member<StyleRuleBase>, 4> rules;
  ConsumeRuleListOrNestedDeclarationList(
      stream,
      /* is_nested_group_rule */ nesting_type == CSSNestingType::kNesting,
      nesting_type, parent_rule_for_nesting, is_within_scope, &rules);

  if (observer_) {
    observer_->EndRuleBody(stream.Offset());
  }

  return MakeGarbageCollected<StyleRuleLayerBlock>(std::move(name),
                                                   std::move(rules));
}

StyleRulePositionTry* CSSParserImpl::ConsumePositionTryRule(
    CSSParserTokenStream& stream) {
  // Parse the prelude.
  wtf_size_t prelude_offset_start = stream.LookAheadOffset();
  const CSSParserToken& name_token = stream.Peek();
  // <dashed-ident>, and -internal-* for UA sheets only.
  String name;
  if (name_token.GetType() == kIdentToken) {
    name = name_token.Value().ToString();
    if (!name.StartsWith("--") &&
        !(context_->Mode() == kUASheetMode && name.StartsWith("-internal-"))) {
      ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRulePositionTry);
      return nullptr;
    }
  } else {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRulePositionTry);
    return nullptr;
  }
  stream.ConsumeIncludingWhitespace();
  wtf_size_t prelude_offset_end = stream.LookAheadOffset();
  if (!ConsumeEndOfPreludeForAtRuleWithBlock(
          stream, CSSAtRuleID::kCSSAtRulePositionTry)) {
    return nullptr;
  }

  // Parse the actual block.
  CSSParserTokenStream::BlockGuard guard(stream);
  if (observer_) {
    observer_->StartRuleHeader(StyleRule::kPositionTry, prelude_offset_start);
    observer_->EndRuleHeader(prelude_offset_end);
    observer_->StartRuleBody(stream.Offset());
  }

  ConsumeBlockContents(stream, StyleRule::kPositionTry, CSSNestingType::kNone,
                       /*parent_rule_for_nesting=*/nullptr,
                       /*is_within_scope=*/false,
                       /*nested_declarations_start_index=*/kNotFound,
                       /*child_rules=*/nullptr);

  if (observer_) {
    observer_->EndRuleBody(stream.LookAheadOffset());
  }

  return MakeGarbageCollected<StyleRulePositionTry>(
      AtomicString(name),
      CreateCSSPropertyValueSet(parsed_properties_, kCSSPositionTryRuleMode,
                                context_->GetDocument()));
}

// Parse a type for CSS Functions; e.g. length, color, etc..
// These are being converted to the syntax used by registered custom properties.
// The parameter is assumed to be a single ident token.
static std::optional<StyleRuleFunction::Type> ParseFunctionType(
    StringView type_name) {
  std::optional<CSSSyntaxDefinition> syntax_def;
  if (type_name == "any") {
    syntax_def = CSSSyntaxStringParser("*").Parse();
  } else {
    syntax_def =
        CSSSyntaxStringParser("<" + type_name.ToString() + ">").Parse();
  }
  if (!syntax_def) {
    return {};
  }

  CHECK_EQ(syntax_def->Components().size(), 1u);
  bool should_add_implicit_calc = false;
  if (!syntax_def->IsUniversal()) {
    // These are all the supported values in CSSSyntaxDefinition that are
    // acceptable as inputs to calc(); see
    // https://drafts.csswg.org/css-values/#math.
    switch (syntax_def->Components()[0].GetType()) {
      case CSSSyntaxType::kLength:
        // kFrequency is missing.
      case CSSSyntaxType::kAngle:
      case CSSSyntaxType::kTime:
        // kFlex is missing.
      case CSSSyntaxType::kResolution:
      case CSSSyntaxType::kPercentage:
      case CSSSyntaxType::kNumber:
      case CSSSyntaxType::kInteger:
      case CSSSyntaxType::kLengthPercentage:
        should_add_implicit_calc = true;
        break;
      case CSSSyntaxType::kTokenStream:
      case CSSSyntaxType::kIdent:
      case CSSSyntaxType::kColor:
      case CSSSyntaxType::kImage:
      case CSSSyntaxType::kUrl:
      case CSSSyntaxType::kTransformFunction:
      case CSSSyntaxType::kTransformList:
      case CSSSyntaxType::kCustomIdent:
        break;
      case CSSSyntaxType::kString:
        DCHECK(RuntimeEnabledFeatures::CSSAtPropertyStringSyntaxEnabled());
        break;
    }
  }

  return StyleRuleFunction::Type{std::move(*syntax_def),
                                 should_add_implicit_calc};
}

StyleRuleFunction* CSSParserImpl::ConsumeFunctionRule(
    CSSParserTokenStream& stream) {
  // Parse the prelude; first a function token (the name), then parameters,
  // then return type.
  if (stream.Peek().GetType() != kFunctionToken) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleFunction);
    return nullptr;  // Parse error.
  }
  AtomicString name =
      stream.Peek()
          .Value()
          .ToAtomicString();  // Includes the opening parenthesis.
  std::optional<Vector<StyleRuleFunction::Parameter>> parameters;
  {
    CSSParserTokenStream::BlockGuard guard(stream);
    stream.ConsumeWhitespace();
    parameters = ConsumeFunctionParameters(stream);
  }
  if (!parameters.has_value()) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleFunction);
    return nullptr;
  }
  stream.ConsumeWhitespace();

  // Parse the return type.
  if (stream.Peek().GetType() != kColonToken) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleFunction);
    return nullptr;
  }
  stream.ConsumeIncludingWhitespace();

  if (stream.Peek().GetType() != kIdentToken) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleFunction);
    return nullptr;
  }
  StringView return_type_name = stream.Peek().Value();
  std::optional<StyleRuleFunction::Type> return_type =
      ParseFunctionType(return_type_name);
  if (!return_type) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleFunction);
    return nullptr;  // Invalid type name.
  }
  stream.ConsumeIncludingWhitespace();

  if (!ConsumeEndOfPreludeForAtRuleWithBlock(stream,
                                             CSSAtRuleID::kCSSAtRuleFunction)) {
    return nullptr;
  }

  // Parse the actual block.
  CSSParserTokenStream::BlockGuard guard(stream);
  stream.ConsumeWhitespace();

  // TODO: Parse local variables.

  // Parse @return.
  if (stream.Peek().GetType() != kAtKeywordToken) {
    return nullptr;
  }
  const CSSParserToken return_token = stream.ConsumeIncludingWhitespace();
  if (return_token.Value() != "return") {
    return nullptr;
  }

  // Parse the actual returned value.
  CSSVariableData* return_value = nullptr;
  {
    CSSParserTokenStream::Boundary boundary(stream, kSemicolonToken);
    bool important_ignored;
    return_value = CSSVariableParser::ConsumeUnparsedDeclaration(
        stream, /*allow_important_annotation=*/false,
        /*is_animation_tainted=*/false,
        /*must_contain_variable_reference=*/false, /*restricted_value=*/false,
        /*comma_ends_declaration=*/false, important_ignored, *context_);
  }

  while (!stream.AtEnd()) {
    const CSSParserToken token = stream.ConsumeIncludingWhitespace();
    StringBuilder sb;
    token.Serialize(sb);
  }

  return MakeGarbageCollected<StyleRuleFunction>(
      name, std::move(*parameters), return_value, std::move(*return_type));
}

StyleRuleMixin* CSSParserImpl::ConsumeMixinRule(CSSParserTokenStream& stream) {
  // @mixin must be top-level, and as such, we need to clear the arena
  // after we're done parsing it (like ConsumeStyleRule() does).
  if (in_nested_style_rule_) {
    return nullptr;
  }
  auto func_clear_arena = [&](HeapVector<CSSSelector>* arena) {
    arena->resize(0);  // See class comment on CSSSelectorParser.
  };
  std::unique_ptr<HeapVector<CSSSelector>, decltype(func_clear_arena)>
      scope_guard(&arena_, std::move(func_clear_arena));

  // Parse the prelude; just a function token (the name).
  if (stream.Peek().GetType() != kIdentToken) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleMixin);
    return nullptr;  // Parse error.
  }
  AtomicString name =
      stream.ConsumeIncludingWhitespace().Value().ToAtomicString();
  if (!name.StartsWith("--")) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleMixin);
    return nullptr;
  }

  if (!ConsumeEndOfPreludeForAtRuleWithBlock(stream,
                                             CSSAtRuleID::kCSSAtRuleMixin)) {
    return nullptr;
  }

  // Parse the actual block.
  CSSParserTokenStream::BlockGuard guard(stream);

  // The destructor expects there to be at least one selector in the StyleRule.
  CSSSelector dummy;
  StyleRule* fake_parent_rule = StyleRule::Create(base::span_from_ref(dummy));
  HeapVector<Member<StyleRuleBase>, 4> child_rules;
  ConsumeRuleListOrNestedDeclarationList(
      stream,
      /*is_nested_group_rule=*/true, CSSNestingType::kNesting, fake_parent_rule,
      /*is_within_scope=*/false, &child_rules);
  for (StyleRuleBase* child_rule : child_rules) {
    fake_parent_rule->AddChildRule(child_rule);
  }
  return MakeGarbageCollected<StyleRuleMixin>(name, fake_parent_rule);
}

StyleRuleApplyMixin* CSSParserImpl::ConsumeApplyMixinRule(
    CSSParserTokenStream& stream) {
  if (stream.Peek().GetType() != kIdentToken) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleApplyMixin);
    return nullptr;  // Parse error.
  }
  AtomicString name =
      stream.ConsumeIncludingWhitespace().Value().ToAtomicString();
  if (!name.StartsWith("--")) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleApplyMixin);
    return nullptr;
  }
  if (!ConsumeEndOfPreludeForAtRuleWithoutBlock(
          stream, CSSAtRuleID::kCSSAtRuleApplyMixin)) {
    return nullptr;
  }
  return MakeGarbageCollected<StyleRuleApplyMixin>(name);
}

// Parse the parameters of a CSS function: Zero or more comma-separated
// instances of [<name> <colon> <type>]. Returns the empty value
// on parse error.
std::optional<Vector<StyleRuleFunction::Parameter>>
CSSParserImpl::ConsumeFunctionParameters(CSSParserTokenStream& stream) {
  Vector<StyleRuleFunction::Parameter> parameters;
  bool first_parameter = true;
  for (;;) {
    stream.ConsumeWhitespace();

    if (first_parameter && stream.Peek().GetType() == kRightParenthesisToken) {
      // No arguments.
      break;
    }
    if (stream.Peek().GetType() != kIdentToken) {
      return {};  // Parse error.
    }
    String parameter_name = stream.Peek().Value().ToString();
    if (!CSSVariableParser::IsValidVariableName(parameter_name)) {
      return {};
    }
    stream.ConsumeIncludingWhitespace();

    if (stream.Peek().GetType() != kColonToken) {
      return {};
    }
    stream.ConsumeIncludingWhitespace();

    if (stream.Peek().GetType() != kIdentToken) {
      return {};
    }
    StringView type_name = stream.Peek().Value();
    std::optional<StyleRuleFunction::Type> type = ParseFunctionType(type_name);
    if (!type) {
      return {};  // Invalid type name.
    }
    stream.ConsumeIncludingWhitespace();
    parameters.push_back(
        StyleRuleFunction::Parameter{parameter_name, std::move(*type)});
    if (stream.Peek().GetType() == kRightParenthesisToken) {
      // No more arguments.
      break;
    }
    if (stream.Peek().GetType() != kCommaToken) {
      return {};  // Expected more parameters, or end of argument list.
    }
    stream.ConsumeIncludingWhitespace();
    first_parameter = false;
  }
  return parameters;
}

StyleRuleKeyframe* CSSParserImpl::ConsumeKeyframeStyleRule(
    std::unique_ptr<Vector<KeyframeOffset>> key_list,
    const RangeOffset& prelude_offset,
    CSSParserTokenStream& block) {
  if (!key_list) {
    return nullptr;
  }

  if (observer_) {
    observer_->StartRuleHeader(StyleRule::kKeyframe, prelude_offset.start);
    observer_->EndRuleHeader(prelude_offset.end);
    observer_->StartRuleBody(block.Offset());
  }

  ConsumeBlockContents(block, StyleRule::kKeyframe, CSSNestingType::kNone,
                       /*parent_rule_for_nesting=*/nullptr,
                       /*is_within_scope=*/false,
                       /*nested_declarations_start_index=*/kNotFound,
                       /*child_rules=*/nullptr);

  if (observer_) {
    observer_->EndRuleBody(block.LookAheadOffset());
  }

  return MakeGarbageCollected<StyleRuleKeyframe>(
      std::move(key_list),
      CreateCSSPropertyValueSet(parsed_properties_, kCSSKeyframeRuleMode,
                                context_->GetDocument()));
}

// A (hopefully) fast check for whether the given declaration block could
// contain nested CSS rules. All of these have to involve { in some shape
// or form, so we simply check for the existence of that. (It means we will
// have false positives for e.g. { within comments or strings, but this
// only means we will turn off lazy parsing for that rule, nothing worse.)
// This will work even for UTF-16, although with some more false positives
// with certain Unicode characters such as U+017E (LATIN SMALL LETTER Z
// WITH CARON). This is, again, not a big problem for us.
static bool MayContainNestedRules(const String& text,
                                  wtf_size_t offset,
                                  wtf_size_t length) {
  if (length < 2u) {
    // {} is the shortest possible block (but if there's
    // a lone { and then EOF, we will be called with length 1).
    return false;
  }

  // Strip away the outer {} pair (the { would always give us a false positive).
  DCHECK_EQ(text[offset], '{');
  if (text[offset + length - 1] != '}') {
    // EOF within the block, so just be on the safe side
    // and use the normal (non-lazy) code path.
    return true;
  }
  ++offset;
  length -= 2;

  size_t char_size = text.Is8Bit() ?
```