Response:
The user wants a summary of the functionalities of the provided C++ code snippet from the `InspectorCSSAgent` class in Chromium's Blink rendering engine.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The file name `inspector_css_agent.cc` strongly suggests this code is responsible for handling CSS-related inspections within the developer tools. The methods within it will likely expose CSS data and allow modifications.

2. **Analyze individual functions:** Go through each function and understand its goal. Look for keywords and parameters that indicate the function's purpose.

    * **`GetDocument()`:** Retrieves the `CSSKeyframesRule` associated with a given element and animation name. It checks registered stylesheets and UA view transition stylesheets.
    * **`AnimationsForNode()`:**  Retrieves all animations applied to a given element by iterating through the element's computed style and finding associated keyframe rules.
    * **`getInlineStylesForNode()`:** Retrieves the inline styles and attribute styles directly applied to a node.
    * **`getComputedStyleForNode()`:**  Calculates and retrieves the final computed style of a node, considering all applied stylesheets and inheritance.
    * **`CollectPlatformFontsForLayoutObject()` and `getPlatformFontsForNode()`:**  These functions work together to collect information about the fonts used to render the text content of a node, including custom fonts.
    * **`getStyleSheetText()`:** Retrieves the raw text content of a specified stylesheet.
    * **`collectClassNames()`:** Extracts all the class names used within a given stylesheet.
    * **`setStyleSheetText()`:** Allows modification of the entire text content of a stylesheet.
    * **`JsonRangeToSourceRange()`:** A helper function to convert JSON-based text range representations to Blink's internal `SourceRange` format.
    * **`setRuleSelector()`:**  Modifies the selector of a specific CSS rule within a stylesheet.
    * **`setPropertyRulePropertyName()`:** Modifies the name of a CSS property within a rule.
    * **`setKeyframeKey()`:** Modifies the keyframe selector (e.g., "0%", "50%") within a keyframes rule.
    * **`MultipleStyleTextsActions()` and `setStyleTexts()`:** These functions allow applying multiple style modifications in a batch. `MultipleStyleTextsActions` prepares the actions, and `setStyleTexts` executes them, handling potential rollbacks and updating the DOM.
    * **`SetStyleText()`:**  A lower-level function to set the text content of a style declaration (either inline or within a rule).
    * **`setMediaText()`, `setContainerQueryText()`, `setScopeText()`, `setSupportsText()`:** Functions to modify the text content of specific types of CSS at-rules (@media, @container, @scope, @supports).
    * **`createStyleSheet()`:** Creates a new, empty stylesheet associated with a specific frame.
    * **`addRule()`:** Adds a new CSS rule to a stylesheet.
    * **`forcePseudoState()`:**  Allows forcing pseudo-classes (like `:hover`, `:focus`) on an element for inspection purposes.
    * **`IncrementFocusedCountForAncestors()` and `DecrementFocusedCountForAncestors()`:** Helper functions used by `forcePseudoState` to manage the `:focus-within` pseudo-class emulation.

3. **Categorize functionalities:** Group the functions based on their core actions. This helps in creating a structured summary. The categories identified are:

    * **Retrieving CSS Information:**  Functions starting with "get" or "AnimationsForNode".
    * **Modifying CSS:** Functions starting with "set", "addRule", and "setStyleSheetText".
    * **Internal Helpers:** Functions like `JsonRangeToSourceRange` and the focus management functions.

4. **Identify relationships with web technologies:** Note which functions directly relate to JavaScript, HTML, and CSS.

    * **JavaScript:** The methods are invoked via the Chrome DevTools protocol, which is often used by JavaScript-based developer tools.
    * **HTML:**  Many functions operate on `Element` objects, which are fundamental to the HTML DOM structure. Inspecting styles directly relates to how HTML elements are rendered.
    * **CSS:** This is the central focus of the code, with functions for retrieving and modifying stylesheets, rules, selectors, properties, and media queries.

5. **Identify potential user errors:** Consider how developers might misuse the provided functionality. Focus on incorrect input parameters, especially related to ranges and IDs.

6. **Address logical inferences:** Although the code itself doesn't perform high-level logical reasoning, some functions have implicit logic, such as the cascade in `getComputedStyleForNode` or the pseudo-class forcing in `forcePseudoState`. The provided examples in the extracted code snippet do contain some conditional logic.

7. **Synthesize the summary:** Combine the categorized functionalities and identified relationships into a concise summary. Ensure it captures the main purpose of the code.
```
GetDocument();
  // There might be that there aren't any active stylesheets for the document
  // which mean the document_to_css_style_sheets_ map won't contain the
  // entry for the document. So, we first check whether there are registered
  // stylesheets for the document.
  if (document_to_css_style_sheets_.Contains(&document)) {
    for (CSSStyleSheet* style_sheet :
         *document_to_css_style_sheets_.at(&document)) {
      CSSKeyframesRule* css_keyframes_rule =
          FindKeyframesRule(style_sheet, keyframes_style_rule);
      if (css_keyframes_rule) {
        return css_keyframes_rule;
      }
    }
  }

  if (IsTransitionPseudoElement(element->GetPseudoId())) {
    return FindKeyframesRuleFromUAViewTransitionStylesheet(
        element, keyframes_style_rule);
  }

  return nullptr;
}

std::unique_ptr<protocol::Array<protocol::CSS::CSSKeyframesRule>>
InspectorCSSAgent::AnimationsForNode(Element* element,
                                     Element* animating_element) {
  auto css_keyframes_rules =
      std::make_unique<protocol::Array<protocol::CSS::CSSKeyframesRule>>();
  Document& document = element->GetDocument();
  DCHECK(!document.NeedsLayoutTreeUpdateForNode(*element));
  // We want to match the animation name of the animating element not the parent
  // element's animation names for pseudo elements. When the `element` is a
  // non-pseudo element then `animating_element` and the `element` are the same.
  const ComputedStyle* style = animating_element->EnsureComputedStyle();
  if (!style)
    return css_keyframes_rules;
  const CSSAnimationData* animation_data = style->Animations();
  StyleResolver& style_resolver = document.GetStyleResolver();
  for (wtf_size_t i = 0;
       animation_data && i < animation_data->NameList().size(); ++i) {
    AtomicString animation_name(animation_data->NameList()[i]);
    if (animation_name == CSSAnimationData::InitialName())
      continue;

    StyleRuleKeyframes* keyframes_rule =
        style_resolver
            .FindKeyframesRule(element, animating_element, animation_name)
            .rule;
    if (!keyframes_rule) {
      continue;
    }

    CSSKeyframesRule* css_keyframes_rule =
        FindCSSOMWrapperForKeyframesRule(animating_element, keyframes_rule);
    if (!css_keyframes_rule) {
      continue;
    }

    auto keyframes =
        std::make_unique<protocol::Array<protocol::CSS::CSSKeyframeRule>>();
    for (unsigned j = 0; j < css_keyframes_rule->length(); ++j) {
      InspectorStyleSheet* inspector_style_sheet =
          BindStyleSheet(css_keyframes_rule->parentStyleSheet());
      keyframes->emplace_back(inspector_style_sheet->BuildObjectForKeyframeRule(
          css_keyframes_rule->Item(j), element));
    }

    InspectorStyleSheet* inspector_style_sheet =
        BindStyleSheet(css_keyframes_rule->parentStyleSheet());
    CSSRuleSourceData* source_data =
        inspector_style_sheet->SourceDataForRule(css_keyframes_rule);
    std::unique_ptr<protocol::CSS::Value> name =
        protocol::CSS::Value::create()
            .setText(css_keyframes_rule->name())
            .build();
    if (source_data)
      name->setRange(inspector_style_sheet->BuildSourceRangeObject(
          source_data->rule_header_range));
    css_keyframes_rules->emplace_back(protocol::CSS::CSSKeyframesRule::create()
                                          .setAnimationName(std::move(name))
                                          .setKeyframes(std::move(keyframes))
                                          .build());
  }
  return css_keyframes_rules;
}

protocol::Response InspectorCSSAgent::getInlineStylesForNode(
    int node_id,
    Maybe<protocol::CSS::CSSStyle>* inline_style,
    Maybe<protocol::CSS::CSSStyle>* attributes_style) {
  protocol::Response response = AssertEnabled();
  if (!response.IsSuccess())
    return response;
  Element* element = nullptr;
  response = dom_agent_->AssertElement(node_id, element);
  if (!response.IsSuccess())
    return response;

  InspectorStyleSheetForInlineStyle* style_sheet =
      AsInspectorStyleSheet(element);
  if (!style_sheet)
    return protocol::Response::ServerError("Element is not a style sheet");

  *inline_style = style_sheet->BuildObjectForStyle(element->style(), element);
  *attributes_style = BuildObjectForAttributesStyle(element);
  return protocol::Response::Success();
}

protocol::Response InspectorCSSAgent::getComputedStyleForNode(
    int node_id,
    std::unique_ptr<protocol::Array<protocol::CSS::CSSComputedStyleProperty>>*
        style) {
  protocol::Response response = AssertEnabled();
  if (!response.IsSuccess())
    return response;
  Node* node = nullptr;
  response = dom_agent_->AssertNode(node_id, node);
  if (!response.IsSuccess())
    return response;
  if (!node->ownerDocument()) {
    return protocol::Response::ServerError(
        "Node does not have an owner document");
  }
  Element* element = DynamicTo<Element>(node);
  if (!element && !node->IsDocumentFragment()) {
    element = FlatTreeTraversal::ParentElement(*node);
  }
  if (!element) {
    return protocol::Response::ServerError(
        "Node is not an element and does not have a parent element");
  }

  TRACE_EVENT1("devtools", "InspectorCSSAgent::getComputedStyleForNode", "node",
               element->DebugName());
  auto* computed_style_info =
      MakeGarbageCollected<CSSComputedStyleDeclaration>(element, true);
  CSSComputedStyleDeclaration::ScopedCleanStyleForAllProperties
      clean_style_scope(computed_style_info);
  *style = std::make_unique<
      protocol::Array<protocol::CSS::CSSComputedStyleProperty>>();
  for (CSSPropertyID property_id : CSSPropertyIDList()) {
    const CSSProperty& property_class =
        CSSProperty::Get(ResolveCSSPropertyID(property_id));
    if (!property_class.IsWebExposed(element->GetExecutionContext()) ||
        property_class.IsShorthand() || !property_class.IsProperty()) {
      continue;
    }
    (*style)->emplace_back(
        protocol::CSS::CSSComputedStyleProperty::create()
            .setName(property_class.GetPropertyNameString())
            .setValue(computed_style_info->GetPropertyValue(property_id))
            .build());
  }

  for (const auto& it : computed_style_info->GetVariables()) {
    (*style)->emplace_back(protocol::CSS::CSSComputedStyleProperty::create()
                               .setName(it.key)
                               .setValue(it.value->CssText())
                               .build());
  }
  return protocol::Response::Success();
}

void InspectorCSSAgent::CollectPlatformFontsForLayoutObject(
    LayoutObject* layout_object,
    HashMap<std::pair<int, String>, std::pair<int, String>>* font_stats,
    unsigned descendants_depth) {
  if (!layout_object->IsText()) {
    if (!descendants_depth)
      return;

    // Skip recursing inside a display-locked tree.
    if (DisplayLockUtilities::LockedInclusiveAncestorPreventingPaint(
            *layout_object)) {
      return;
    }

    if (!layout_object->IsAnonymous())
      --descendants_depth;
    for (LayoutObject* child = layout_object->SlowFirstChild(); child;
         child = child->NextSibling()) {
      CollectPlatformFontsForLayoutObject(child, font_stats, descendants_depth);
    }
    return;
  }

  // Don't gather text on a display-locked tree.
  if (DisplayLockUtilities::LockedAncestorPreventingPaint(*layout_object))
    return;

  FontCachePurgePreventer preventer;
  DCHECK(layout_object->IsInLayoutNGInlineFormattingContext());
  InlineCursor cursor;
  cursor.MoveTo(*layout_object);
  for (; cursor; cursor.MoveToNextForSameLayoutObject()) {
    const ShapeResultView* shape_result = cursor.Current().TextShapeResult();
    if (!shape_result) {
      continue;
    }
    HeapVector<ShapeResult::RunFontData> run_font_data_list;
    ClearCollectionScope clear_scope(&run_font_data_list);
    shape_result->GetRunFontData(&run_font_data_list);
    CollectPlatformFontsFromRunFontDataList(run_font_data_list, font_stats);
  }
}

protocol::Response InspectorCSSAgent::getPlatformFontsForNode(
    int node_id,
    std::unique_ptr<protocol::Array<protocol::CSS::PlatformFontUsage>>*
        platform_fonts) {
  protocol::Response response = AssertEnabled();
  if (!response.IsSuccess())
    return response;
  Node* node = nullptr;
  response = dom_agent_->AssertNode(node_id, node);
  if (!response.IsSuccess())
    return response;

  // Key: {isCustomFont, postscript_name}
  // Value: {glyph_count (which accumulates), family_name}
  HashMap<std::pair<int, String>, std::pair<int, String>> font_stats;
  LayoutObject* root = node->GetLayoutObject();
  if (root) {
    // Iterate upto two layers deep.
    const unsigned descendants_depth = 2;
    CollectPlatformFontsForLayoutObject(root, &font_stats, descendants_depth);
  }
  *platform_fonts =
      std::make_unique<protocol::Array<protocol::CSS::PlatformFontUsage>>();
  for (auto& font : font_stats) {
    std::pair<int, String>& font_description = font.key;
    std::pair<int, String>& font_value = font.value;
    bool is_custom_font = font_description.first == 1;
    (*platform_fonts)
        ->emplace_back(protocol::CSS::PlatformFontUsage::create()
                           .setFamilyName(font_value.second)
                           .setPostScriptName(font_description.second)
                           .setIsCustomFont(is_custom_font)
                           .setGlyphCount(font_value.first)
                           .build());
  }
  return protocol::Response::Success();
}

protocol::Response InspectorCSSAgent::getStyleSheetText(
    const String& style_sheet_id,
    String* result) {
  InspectorStyleSheetBase* inspector_style_sheet = nullptr;
  protocol::Response response =
      AssertStyleSheetForId(style_sheet_id, inspector_style_sheet);
  if (!response.IsSuccess())
    return response;

  inspector_style_sheet->GetText(result);
  return protocol::Response::Success();
}

protocol::Response InspectorCSSAgent::collectClassNames(
    const String& style_sheet_id,
    std::unique_ptr<protocol::Array<String>>* class_names) {
  InspectorStyleSheet* inspector_style_sheet = nullptr;
  protocol::Response response =
      AssertInspectorStyleSheetForId(style_sheet_id, inspector_style_sheet);
  if (!response.IsSuccess())
    return response;
  *class_names = inspector_style_sheet->CollectClassNames();
  return protocol::Response::Success();
}

protocol::Response InspectorCSSAgent::setStyleSheetText(
    const String& style_sheet_id,
    const String& text,
    protocol::Maybe<String>* source_map_url) {
  FrontendOperationScope scope;
  InspectorStyleSheetBase* inspector_style_sheet = nullptr;
  protocol::Response response =
      AssertStyleSheetForId(style_sheet_id, inspector_style_sheet);
  if (!response.IsSuccess())
    return response;

  DummyExceptionStateForTesting exception_state;
  dom_agent_->History()->Perform(MakeGarbageCollected<SetStyleSheetTextAction>(
                                     inspector_style_sheet, text),
                                 exception_state);
  response = InspectorDOMAgent::ToResponse(exception_state);
  if (!response.IsSuccess())
    return response;
  if (!inspector_style_sheet->SourceMapURL().empty())
    *source_map_url = inspector_style_sheet->SourceMapURL();
  return protocol::Response::Success();
}

static protocol::Response JsonRangeToSourceRange(
    InspectorStyleSheetBase* inspector_style_sheet,
    protocol::CSS::SourceRange* range,
    SourceRange* source_range) {
  if (range->getStartLine() < 0) {
    return protocol::Response::ServerError(
        "range.startLine must be a non-negative integer");
  }
  if (range->getStartColumn() < 0) {
    return protocol::Response::ServerError(
        "range.startColumn must be a non-negative integer");
  }
  if (range->getEndLine() < 0) {
    return protocol::Response::ServerError(
        "range.endLine must be a non-negative integer");
  }
  if (range->getEndColumn() < 0) {
    return protocol::Response::ServerError(
        "range.endColumn must be a non-negative integer");
  }

  unsigned start_offset = 0;
  unsigned end_offset = 0;
  bool success =
      inspector_style_sheet->LineNumberAndColumnToOffset(
          range->getStartLine(), range->getStartColumn(), &start_offset) &&
      inspector_style_sheet->LineNumberAndColumnToOffset(
          range->getEndLine(), range->getEndColumn(), &end_offset);
  if (!success)
    return protocol::Response::ServerError("Specified range is out of bounds");

  if (start_offset > end_offset) {
    return protocol::Response::ServerError(
        "Range start must not succeed its end");
  }
  source_range->start = start_offset;
  source_range->end = end_offset;
  return protocol::Response::Success();
}

protocol::Response InspectorCSSAgent::setRuleSelector(
    const String& style_sheet_id,
    std::unique_ptr<protocol::CSS::SourceRange> range,
    const String& selector,
    std::unique_ptr<protocol::CSS::SelectorList>* result) {
  FrontendOperationScope scope;
  InspectorStyleSheet* inspector_style_sheet = nullptr;
  protocol::Response response =
      AssertInspectorStyleSheetForId(style_sheet_id, inspector_style_sheet);
  if (!response.IsSuccess())
    return response;
  SourceRange selector_range;
  response = JsonRangeToSourceRange(inspector_style_sheet, range.get(),
                                    &selector_range);
  if (!response.IsSuccess())
    return response;

  DummyExceptionStateForTesting exception_state;
  ModifyRuleAction* action = MakeGarbageCollected<ModifyRuleAction>(
      ModifyRuleAction::kSetRuleSelector, inspector_style_sheet, selector_range,
      selector);
  bool success = dom_agent_->History()->Perform(action, exception_state);
  if (success) {
    CSSStyleRule* rule = InspectorCSSAgent::AsCSSStyleRule(action->TakeRule());
    inspector_style_sheet = InspectorStyleSheetForRule(rule);
    if (!inspector_style_sheet) {
      return protocol::Response::ServerError(
          "Failed to get inspector style sheet for rule.");
    }
    *result = inspector_style_sheet->BuildObjectForSelectorList(rule);
  }
  return InspectorDOMAgent::ToResponse(exception_state);
}

protocol::Response InspectorCSSAgent::setPropertyRulePropertyName(
    const String& in_styleSheetId,
    std::unique_ptr<protocol::CSS::SourceRange> in_range,
    const String& in_propertyName,
    std::unique_ptr<protocol::CSS::Value>* out_propertyName) {
  FrontendOperationScope scope;
  InspectorStyleSheet* inspector_style_sheet = nullptr;
  protocol::Response response =
      AssertInspectorStyleSheetForId(in_styleSheetId, inspector_style_sheet);
  if (!response.IsSuccess())
    return response;
  SourceRange name_range;
  response = JsonRangeToSourceRange(inspector_style_sheet, in_range.get(),
                                    &name_range);
  if (!response.IsSuccess())
    return response;
  DummyExceptionStateForTesting exception_state;
  ModifyRuleAction* action = MakeGarbageCollected<ModifyRuleAction>(
      ModifyRuleAction::kSetPropertyName, inspector_style_sheet, name_range,
      in_propertyName);
  bool success = dom_agent_->History()->Perform(action, exception_state);
  if (success) {
    auto* rule = To<CSSPropertyRule>(action->TakeRule());
    inspector_style_sheet = BindStyleSheet(rule->parentStyleSheet());
    if (!inspector_style_sheet) {
      return protocol::Response::ServerError(
          "Failed to get inspector style sheet for rule.");
    }
    CSSRuleSourceData* source_data =
        inspector_style_sheet->SourceDataForRule(rule);
    *out_propertyName =
        protocol::CSS::Value::create()
            .setText(rule->name())
            .setRange(inspector_style_sheet->BuildSourceRangeObject(
                source_data->rule_header_range))
            .build();
  }
  return InspectorDOMAgent::ToResponse(exception_state);
}

protocol::Response InspectorCSSAgent::setKeyframeKey(
    const String& style_sheet_id,
    std::unique_ptr<protocol::CSS::SourceRange> range,
    const String& key_text,
    std::unique_ptr<protocol::CSS::Value>* result) {
  FrontendOperationScope scope;
  InspectorStyleSheet* inspector_style_sheet = nullptr;
  protocol::Response response =
      AssertInspectorStyleSheetForId(style_sheet_id, inspector_style_sheet);
  if (!response.IsSuccess())
    return response;
  SourceRange key_range;
  response =
      JsonRangeToSourceRange(inspector_style_sheet, range.get(), &key_range);
  if (!response.IsSuccess())
    return response;

  DummyExceptionStateForTesting exception_state;
  ModifyRuleAction* action = MakeGarbageCollected<ModifyRuleAction>(
      ModifyRuleAction::kSetKeyframeKey, inspector_style_sheet, key_range,
      key_text);
  bool success = dom_agent_->History()->Perform(action, exception_state);
  if (success) {
    auto* rule = To<CSSKeyframeRule>(action->TakeRule());
    inspector_style_sheet = BindStyleSheet(rule->parentStyleSheet());
    if (!inspector_style_sheet) {
      return protocol::Response::ServerError(
          "Failed to get inspector style sheet for rule.");
    }
    CSSRuleSourceData* source_data =
        inspector_style_sheet->SourceDataForRule(rule);
    *result = protocol::CSS::Value::create()
                  .setText(rule->keyText())
                  .setRange(inspector_style_sheet->BuildSourceRangeObject(
                      source_data->rule_header_range))
                  .build();
  }
  return InspectorDOMAgent::ToResponse(exception_state);
}

protocol::Response InspectorCSSAgent::MultipleStyleTextsActions(
    std::unique_ptr<protocol::Array<protocol::CSS::StyleDeclarationEdit>> edits,
    HeapVector<Member<StyleSheetAction>>* actions) {
  size_t n = edits->size();
  if (n == 0)
    return protocol::Response::ServerError("Edits should not be empty");

  for (size_t i = 0; i < n; ++i) {
    protocol::CSS::StyleDeclarationEdit* edit = (*edits)[i].get();
    InspectorStyleSheetBase* inspector_style_sheet = nullptr;
    protocol::Response response =
        AssertStyleSheetForId(edit->getStyleSheetId(), inspector_style_sheet);
    if (!response.IsSuccess()) {
      return protocol::Response::ServerError(
          String::Format("StyleSheet not found for edit #%zu of %zu", i + 1, n)
              .Utf8());
    }

    SourceRange range;
    response =
        JsonRangeToSourceRange(inspector_style_sheet, edit->getRange(), &range);
    if (!response.IsSuccess())
      return response;

    if (inspector_style_sheet->IsInlineStyle()) {
      InspectorStyleSheetForInlineStyle* inline_style_sheet =
          static_cast<InspectorStyleSheetForInlineStyle*>(
              inspector_style_sheet);
      SetElementStyleAction* action =
          MakeGarbageCollected<SetElementStyleAction>(inline_style_sheet,
                                                      edit->getText());
      actions->push_back(action);
    } else {
      ModifyRuleAction* action = MakeGarbageCollected<ModifyRuleAction>(
          ModifyRuleAction::kSetStyleText,
          static_cast<InspectorStyleSheet*>(inspector_style_sheet), range,
          edit->getText());
      actions->push_back(action);
    }
  }
  return protocol::Response::Success();
}

protocol::Response InspectorCSSAgent::setStyleTexts(
    std::unique_ptr<protocol::Array<protocol::CSS::StyleDeclarationEdit>> edits,
    protocol::Maybe<int> node_for_property_syntax_validation,
    std::unique_ptr<protocol::Array<protocol::CSS::CSSStyle>>* result) {
  FrontendOperationScope scope;
  HeapVector<Member<StyleSheetAction>> actions;
  protocol::Response response =
      MultipleStyleTextsActions(std::move(edits), &actions);
  if (!response.IsSuccess())
    return response;

  DummyExceptionStateForTesting exception_state;

  Element* element = nullptr;
  if (node_for_property_syntax_validation.has_value()) {
    response = dom_agent_->AssertElement(
        node_for_property_syntax_validation.value(), element);
    if (!response.IsSuccess())
      return response;
  }

  int n = actions.size();
  auto serialized_styles =
      std::make_unique<protocol::Array<protocol::CSS::CSSStyle>>();
  for (int i = 0; i < n; ++i) {
    Member<StyleSheetAction> action = actions.at(i);
    bool success = action->Perform(exception_state);
    if (!success) {
      for (int j = i - 1; j >= 0; --j) {
        Member<StyleSheetAction> revert = actions.at(j);
        DummyExceptionStateForTesting undo_exception_state;
        revert->Undo(undo_exception_state);
        DCHECK(!undo_exception_state.HadException());
      }
      return protocol::Response::ServerError(
          String::Format("Failed applying edit #%d: ", i).Utf8() +
          InspectorDOMAgent::ToResponse(exception_state).Message());
    }
  }

  if (element) {
    element->GetDocument().UpdateStyleAndLayoutForNode(
        element, DocumentUpdateReason::kInspector);
  }
  for (int i = 0; i < n; ++i) {
    Member<StyleSheetAction> action = actions.at(i);
    serialized_styles->emplace_back(action->TakeSerializedStyle(element));
  }

  for (int i = 0; i < n; ++i) {
    Member<StyleSheetAction> action = actions.at(i);
    dom_agent_->History()->AppendPerformedAction(action);
  }
  *result = std::move(serialized_styles);
  return protocol::Response::Success();
}

protocol::Response InspectorCSSAgent::SetStyleText(
    InspectorStyleSheetBase* inspector_style_sheet,
    const SourceRange& range,
    const String& text,
    CSSStyleDeclaration*& result) {
  DummyExceptionStateForTesting exception_state;
  if (inspector_style_sheet->IsInlineStyle()) {
    InspectorStyleSheetForInlineStyle* inline_style_sheet =
        static_cast<InspectorStyleSheetForInlineStyle*>(inspector_style_sheet);
    SetElementStyleAction* action =
        MakeGarbageCollected<SetElementStyleAction>(inline_style_sheet, text);
    bool success = dom_agent_->History()->Perform(action, exception_state);
    if (success) {
      result = inline_style_sheet->InlineStyle();
      return protocol::Response::Success();
    }
  } else {
    ModifyRuleAction* action = MakeGarbageCollected<ModifyRuleAction>(
        ModifyRuleAction::kSetStyleText,
        static_cast<InspectorStyleSheet*>(inspector_style_sheet), range, text);
    bool success = dom_agent_->History()->Perform(action, exception_state);
    if (success) {
      CSSRule* rule = action->TakeRule();
      if (auto* style_rule = DynamicTo<CSSStyleRule>(rule)) {
        result = style_rule->style();
        return protocol::Response::Success();
      }
      if (auto* keyframe_rule = DynamicTo<CSSKeyframeRule>(rule)) {
        result = keyframe_rule->style();
        return protocol::Response::Success();
      }
    }
  }
  return InspectorDOMAgent::ToResponse(exception_state);
}

protocol::Response InspectorCSSAgent::setMediaText(
    const String& style_sheet_id,
    std::unique_ptr<protocol::CSS::SourceRange> range,
    const String& text,
    std::unique_ptr<protocol::CSS::CSSMedia>* result) {
  FrontendOperationScope scope;
  InspectorStyleSheet* inspector_style_sheet = nullptr;
  protocol::Response response =
      AssertInspectorStyleSheetForId(style_sheet_id, inspector_style_sheet);
  if (!response.IsSuccess())
    return response;
  SourceRange text_range;
  response =
      JsonRangeToSourceRange(inspector_style_sheet, range.get(), &text_range);
  if (!response.IsSuccess())
    return response;

  DummyExceptionStateForTesting exception_state;
  ModifyRuleAction* action = MakeGarbageCollected<ModifyRuleAction>(
      ModifyRuleAction::kSetMediaRuleText, inspector_style_sheet, text_range,
      text);
  bool success = dom_agent_->History()->Perform(action, exception_state);
  if (success) {
    CSSMediaRule* rule = InspectorCSSAgent::AsCSSMediaRule(action->TakeRule());
    String source_url = rule->parentStyleSheet()->Contents()->BaseURL();
    if (source_url.empty())
      source_url = InspectorDOMAgent::DocumentURLString(
          rule->parentStyleSheet()->OwnerDocument());
    *result = BuildMediaObject(rule->media(), kMediaListSourceMediaRule,
                               source_url, rule->parentStyleSheet());
  }
  return InspectorDOMAgent::ToResponse(exception_state);
}

protocol::Response InspectorCSSAgent::setContainerQueryText(
    const String& style_sheet_id,
    std::unique_ptr<protocol::CSS::SourceRange> range,
    const String& text,
    std::unique_ptr<protocol::CSS::CSSContainerQuery>* result) {
  FrontendOperationScope scope;
  InspectorStyleSheet* inspector_style_sheet = nullptr;
  protocol::Response response =
      AssertInspectorStyleSheetForId(style_sheet_id, inspector_style_sheet);
  if (!response.IsSuccess())
    return response;
  SourceRange text_range;
  response =
      JsonRangeToSourceRange(inspector_style_sheet, range.get(), &text_range);
  if (!response.IsSuccess())
    return response;

  DummyExceptionStateForTesting exception_state;
  ModifyRuleAction* action = MakeGarbageCollected<ModifyRuleAction>(
      ModifyRuleAction::kSetContainerRuleText, inspector_style_sheet,
      text_range, text);
  bool success = dom_agent_->History()->Perform(action, exception_state);
  if (success) {
    CSSContainerRule* rule =
        InspectorCSSAgent::AsCSSContainerRule(action->TakeRule());
    *result = BuildContainerQueryObject(rule);
  }
  return InspectorDOMAgent::ToResponse(exception_state);
}

protocol::Response InspectorCSSAgent::setScopeText(
    const String& style_sheet_id,
    std::unique_ptr<protocol::CSS::SourceRange> range,
    const String& text,
    std::unique_ptr<protocol::CSS::CSSScope>* result) {
  FrontendOperationScope scope;
  InspectorStyleSheet* inspector_style_sheet = nullptr;
  protocol::Response response =
      AssertInspectorStyleSheetForId(style_sheet_id, inspector_style_sheet);
  if (!response.IsSuccess())
    return response;
  SourceRange text_range;
  response =
      JsonRangeToSourceRange(inspector_style_sheet, range.get(), &text_range);
  if (!response.IsSuccess())
    return response;

  DummyExceptionStateForTesting exception_state;
  ModifyRuleAction* action = MakeGarbageCollected<ModifyRuleAction>(
      ModifyRuleAction::kSetScopeRuleText, inspector_style_sheet, text_range,
      text);
  bool success = dom_agent_->History()->Perform(action, exception_state);
  if (success) {
    CSSScopeRule* rule = InspectorCSSAgent::AsCSSScopeRule(action->TakeRule());
    *result = BuildScopeObject(rule);
  }
  return InspectorDOMAgent::ToResponse(exception_
Prompt: 
```
这是目录为blink/renderer/core/inspector/inspector_css_agent.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能

"""
GetDocument();
  // There might be that there aren't any active stylesheets for the document
  // which mean the document_to_css_style_sheets_ map won't contain the
  // entry for the document. So, we first check whether there are registered
  // stylesheets for the document.
  if (document_to_css_style_sheets_.Contains(&document)) {
    for (CSSStyleSheet* style_sheet :
         *document_to_css_style_sheets_.at(&document)) {
      CSSKeyframesRule* css_keyframes_rule =
          FindKeyframesRule(style_sheet, keyframes_style_rule);
      if (css_keyframes_rule) {
        return css_keyframes_rule;
      }
    }
  }

  if (IsTransitionPseudoElement(element->GetPseudoId())) {
    return FindKeyframesRuleFromUAViewTransitionStylesheet(
        element, keyframes_style_rule);
  }

  return nullptr;
}

std::unique_ptr<protocol::Array<protocol::CSS::CSSKeyframesRule>>
InspectorCSSAgent::AnimationsForNode(Element* element,
                                     Element* animating_element) {
  auto css_keyframes_rules =
      std::make_unique<protocol::Array<protocol::CSS::CSSKeyframesRule>>();
  Document& document = element->GetDocument();
  DCHECK(!document.NeedsLayoutTreeUpdateForNode(*element));
  // We want to match the animation name of the animating element not the parent
  // element's animation names for pseudo elements. When the `element` is a
  // non-pseudo element then `animating_element` and the `element` are the same.
  const ComputedStyle* style = animating_element->EnsureComputedStyle();
  if (!style)
    return css_keyframes_rules;
  const CSSAnimationData* animation_data = style->Animations();
  StyleResolver& style_resolver = document.GetStyleResolver();
  for (wtf_size_t i = 0;
       animation_data && i < animation_data->NameList().size(); ++i) {
    AtomicString animation_name(animation_data->NameList()[i]);
    if (animation_name == CSSAnimationData::InitialName())
      continue;

    StyleRuleKeyframes* keyframes_rule =
        style_resolver
            .FindKeyframesRule(element, animating_element, animation_name)
            .rule;
    if (!keyframes_rule) {
      continue;
    }

    CSSKeyframesRule* css_keyframes_rule =
        FindCSSOMWrapperForKeyframesRule(animating_element, keyframes_rule);
    if (!css_keyframes_rule) {
      continue;
    }

    auto keyframes =
        std::make_unique<protocol::Array<protocol::CSS::CSSKeyframeRule>>();
    for (unsigned j = 0; j < css_keyframes_rule->length(); ++j) {
      InspectorStyleSheet* inspector_style_sheet =
          BindStyleSheet(css_keyframes_rule->parentStyleSheet());
      keyframes->emplace_back(inspector_style_sheet->BuildObjectForKeyframeRule(
          css_keyframes_rule->Item(j), element));
    }

    InspectorStyleSheet* inspector_style_sheet =
        BindStyleSheet(css_keyframes_rule->parentStyleSheet());
    CSSRuleSourceData* source_data =
        inspector_style_sheet->SourceDataForRule(css_keyframes_rule);
    std::unique_ptr<protocol::CSS::Value> name =
        protocol::CSS::Value::create()
            .setText(css_keyframes_rule->name())
            .build();
    if (source_data)
      name->setRange(inspector_style_sheet->BuildSourceRangeObject(
          source_data->rule_header_range));
    css_keyframes_rules->emplace_back(protocol::CSS::CSSKeyframesRule::create()
                                          .setAnimationName(std::move(name))
                                          .setKeyframes(std::move(keyframes))
                                          .build());
  }
  return css_keyframes_rules;
}

protocol::Response InspectorCSSAgent::getInlineStylesForNode(
    int node_id,
    Maybe<protocol::CSS::CSSStyle>* inline_style,
    Maybe<protocol::CSS::CSSStyle>* attributes_style) {
  protocol::Response response = AssertEnabled();
  if (!response.IsSuccess())
    return response;
  Element* element = nullptr;
  response = dom_agent_->AssertElement(node_id, element);
  if (!response.IsSuccess())
    return response;

  InspectorStyleSheetForInlineStyle* style_sheet =
      AsInspectorStyleSheet(element);
  if (!style_sheet)
    return protocol::Response::ServerError("Element is not a style sheet");

  *inline_style = style_sheet->BuildObjectForStyle(element->style(), element);
  *attributes_style = BuildObjectForAttributesStyle(element);
  return protocol::Response::Success();
}

protocol::Response InspectorCSSAgent::getComputedStyleForNode(
    int node_id,
    std::unique_ptr<protocol::Array<protocol::CSS::CSSComputedStyleProperty>>*
        style) {
  protocol::Response response = AssertEnabled();
  if (!response.IsSuccess())
    return response;
  Node* node = nullptr;
  response = dom_agent_->AssertNode(node_id, node);
  if (!response.IsSuccess())
    return response;
  if (!node->ownerDocument()) {
    return protocol::Response::ServerError(
        "Node does not have an owner document");
  }
  Element* element = DynamicTo<Element>(node);
  if (!element && !node->IsDocumentFragment()) {
    element = FlatTreeTraversal::ParentElement(*node);
  }
  if (!element) {
    return protocol::Response::ServerError(
        "Node is not an element and does not have a parent element");
  }

  TRACE_EVENT1("devtools", "InspectorCSSAgent::getComputedStyleForNode", "node",
               element->DebugName());
  auto* computed_style_info =
      MakeGarbageCollected<CSSComputedStyleDeclaration>(element, true);
  CSSComputedStyleDeclaration::ScopedCleanStyleForAllProperties
      clean_style_scope(computed_style_info);
  *style = std::make_unique<
      protocol::Array<protocol::CSS::CSSComputedStyleProperty>>();
  for (CSSPropertyID property_id : CSSPropertyIDList()) {
    const CSSProperty& property_class =
        CSSProperty::Get(ResolveCSSPropertyID(property_id));
    if (!property_class.IsWebExposed(element->GetExecutionContext()) ||
        property_class.IsShorthand() || !property_class.IsProperty()) {
      continue;
    }
    (*style)->emplace_back(
        protocol::CSS::CSSComputedStyleProperty::create()
            .setName(property_class.GetPropertyNameString())
            .setValue(computed_style_info->GetPropertyValue(property_id))
            .build());
  }

  for (const auto& it : computed_style_info->GetVariables()) {
    (*style)->emplace_back(protocol::CSS::CSSComputedStyleProperty::create()
                               .setName(it.key)
                               .setValue(it.value->CssText())
                               .build());
  }
  return protocol::Response::Success();
}

void InspectorCSSAgent::CollectPlatformFontsForLayoutObject(
    LayoutObject* layout_object,
    HashMap<std::pair<int, String>, std::pair<int, String>>* font_stats,
    unsigned descendants_depth) {
  if (!layout_object->IsText()) {
    if (!descendants_depth)
      return;

    // Skip recursing inside a display-locked tree.
    if (DisplayLockUtilities::LockedInclusiveAncestorPreventingPaint(
            *layout_object)) {
      return;
    }

    if (!layout_object->IsAnonymous())
      --descendants_depth;
    for (LayoutObject* child = layout_object->SlowFirstChild(); child;
         child = child->NextSibling()) {
      CollectPlatformFontsForLayoutObject(child, font_stats, descendants_depth);
    }
    return;
  }

  // Don't gather text on a display-locked tree.
  if (DisplayLockUtilities::LockedAncestorPreventingPaint(*layout_object))
    return;

  FontCachePurgePreventer preventer;
  DCHECK(layout_object->IsInLayoutNGInlineFormattingContext());
  InlineCursor cursor;
  cursor.MoveTo(*layout_object);
  for (; cursor; cursor.MoveToNextForSameLayoutObject()) {
    const ShapeResultView* shape_result = cursor.Current().TextShapeResult();
    if (!shape_result) {
      continue;
    }
    HeapVector<ShapeResult::RunFontData> run_font_data_list;
    ClearCollectionScope clear_scope(&run_font_data_list);
    shape_result->GetRunFontData(&run_font_data_list);
    CollectPlatformFontsFromRunFontDataList(run_font_data_list, font_stats);
  }
}

protocol::Response InspectorCSSAgent::getPlatformFontsForNode(
    int node_id,
    std::unique_ptr<protocol::Array<protocol::CSS::PlatformFontUsage>>*
        platform_fonts) {
  protocol::Response response = AssertEnabled();
  if (!response.IsSuccess())
    return response;
  Node* node = nullptr;
  response = dom_agent_->AssertNode(node_id, node);
  if (!response.IsSuccess())
    return response;

  // Key: {isCustomFont, postscript_name}
  // Value: {glyph_count (which accumulates), family_name}
  HashMap<std::pair<int, String>, std::pair<int, String>> font_stats;
  LayoutObject* root = node->GetLayoutObject();
  if (root) {
    // Iterate upto two layers deep.
    const unsigned descendants_depth = 2;
    CollectPlatformFontsForLayoutObject(root, &font_stats, descendants_depth);
  }
  *platform_fonts =
      std::make_unique<protocol::Array<protocol::CSS::PlatformFontUsage>>();
  for (auto& font : font_stats) {
    std::pair<int, String>& font_description = font.key;
    std::pair<int, String>& font_value = font.value;
    bool is_custom_font = font_description.first == 1;
    (*platform_fonts)
        ->emplace_back(protocol::CSS::PlatformFontUsage::create()
                           .setFamilyName(font_value.second)
                           .setPostScriptName(font_description.second)
                           .setIsCustomFont(is_custom_font)
                           .setGlyphCount(font_value.first)
                           .build());
  }
  return protocol::Response::Success();
}

protocol::Response InspectorCSSAgent::getStyleSheetText(
    const String& style_sheet_id,
    String* result) {
  InspectorStyleSheetBase* inspector_style_sheet = nullptr;
  protocol::Response response =
      AssertStyleSheetForId(style_sheet_id, inspector_style_sheet);
  if (!response.IsSuccess())
    return response;

  inspector_style_sheet->GetText(result);
  return protocol::Response::Success();
}

protocol::Response InspectorCSSAgent::collectClassNames(
    const String& style_sheet_id,
    std::unique_ptr<protocol::Array<String>>* class_names) {
  InspectorStyleSheet* inspector_style_sheet = nullptr;
  protocol::Response response =
      AssertInspectorStyleSheetForId(style_sheet_id, inspector_style_sheet);
  if (!response.IsSuccess())
    return response;
  *class_names = inspector_style_sheet->CollectClassNames();
  return protocol::Response::Success();
}

protocol::Response InspectorCSSAgent::setStyleSheetText(
    const String& style_sheet_id,
    const String& text,
    protocol::Maybe<String>* source_map_url) {
  FrontendOperationScope scope;
  InspectorStyleSheetBase* inspector_style_sheet = nullptr;
  protocol::Response response =
      AssertStyleSheetForId(style_sheet_id, inspector_style_sheet);
  if (!response.IsSuccess())
    return response;

  DummyExceptionStateForTesting exception_state;
  dom_agent_->History()->Perform(MakeGarbageCollected<SetStyleSheetTextAction>(
                                     inspector_style_sheet, text),
                                 exception_state);
  response = InspectorDOMAgent::ToResponse(exception_state);
  if (!response.IsSuccess())
    return response;
  if (!inspector_style_sheet->SourceMapURL().empty())
    *source_map_url = inspector_style_sheet->SourceMapURL();
  return protocol::Response::Success();
}

static protocol::Response JsonRangeToSourceRange(
    InspectorStyleSheetBase* inspector_style_sheet,
    protocol::CSS::SourceRange* range,
    SourceRange* source_range) {
  if (range->getStartLine() < 0) {
    return protocol::Response::ServerError(
        "range.startLine must be a non-negative integer");
  }
  if (range->getStartColumn() < 0) {
    return protocol::Response::ServerError(
        "range.startColumn must be a non-negative integer");
  }
  if (range->getEndLine() < 0) {
    return protocol::Response::ServerError(
        "range.endLine must be a non-negative integer");
  }
  if (range->getEndColumn() < 0) {
    return protocol::Response::ServerError(
        "range.endColumn must be a non-negative integer");
  }

  unsigned start_offset = 0;
  unsigned end_offset = 0;
  bool success =
      inspector_style_sheet->LineNumberAndColumnToOffset(
          range->getStartLine(), range->getStartColumn(), &start_offset) &&
      inspector_style_sheet->LineNumberAndColumnToOffset(
          range->getEndLine(), range->getEndColumn(), &end_offset);
  if (!success)
    return protocol::Response::ServerError("Specified range is out of bounds");

  if (start_offset > end_offset) {
    return protocol::Response::ServerError(
        "Range start must not succeed its end");
  }
  source_range->start = start_offset;
  source_range->end = end_offset;
  return protocol::Response::Success();
}

protocol::Response InspectorCSSAgent::setRuleSelector(
    const String& style_sheet_id,
    std::unique_ptr<protocol::CSS::SourceRange> range,
    const String& selector,
    std::unique_ptr<protocol::CSS::SelectorList>* result) {
  FrontendOperationScope scope;
  InspectorStyleSheet* inspector_style_sheet = nullptr;
  protocol::Response response =
      AssertInspectorStyleSheetForId(style_sheet_id, inspector_style_sheet);
  if (!response.IsSuccess())
    return response;
  SourceRange selector_range;
  response = JsonRangeToSourceRange(inspector_style_sheet, range.get(),
                                    &selector_range);
  if (!response.IsSuccess())
    return response;

  DummyExceptionStateForTesting exception_state;
  ModifyRuleAction* action = MakeGarbageCollected<ModifyRuleAction>(
      ModifyRuleAction::kSetRuleSelector, inspector_style_sheet, selector_range,
      selector);
  bool success = dom_agent_->History()->Perform(action, exception_state);
  if (success) {
    CSSStyleRule* rule = InspectorCSSAgent::AsCSSStyleRule(action->TakeRule());
    inspector_style_sheet = InspectorStyleSheetForRule(rule);
    if (!inspector_style_sheet) {
      return protocol::Response::ServerError(
          "Failed to get inspector style sheet for rule.");
    }
    *result = inspector_style_sheet->BuildObjectForSelectorList(rule);
  }
  return InspectorDOMAgent::ToResponse(exception_state);
}

protocol::Response InspectorCSSAgent::setPropertyRulePropertyName(
    const String& in_styleSheetId,
    std::unique_ptr<protocol::CSS::SourceRange> in_range,
    const String& in_propertyName,
    std::unique_ptr<protocol::CSS::Value>* out_propertyName) {
  FrontendOperationScope scope;
  InspectorStyleSheet* inspector_style_sheet = nullptr;
  protocol::Response response =
      AssertInspectorStyleSheetForId(in_styleSheetId, inspector_style_sheet);
  if (!response.IsSuccess())
    return response;
  SourceRange name_range;
  response = JsonRangeToSourceRange(inspector_style_sheet, in_range.get(),
                                    &name_range);
  if (!response.IsSuccess())
    return response;
  DummyExceptionStateForTesting exception_state;
  ModifyRuleAction* action = MakeGarbageCollected<ModifyRuleAction>(
      ModifyRuleAction::kSetPropertyName, inspector_style_sheet, name_range,
      in_propertyName);
  bool success = dom_agent_->History()->Perform(action, exception_state);
  if (success) {
    auto* rule = To<CSSPropertyRule>(action->TakeRule());
    inspector_style_sheet = BindStyleSheet(rule->parentStyleSheet());
    if (!inspector_style_sheet) {
      return protocol::Response::ServerError(
          "Failed to get inspector style sheet for rule.");
    }
    CSSRuleSourceData* source_data =
        inspector_style_sheet->SourceDataForRule(rule);
    *out_propertyName =
        protocol::CSS::Value::create()
            .setText(rule->name())
            .setRange(inspector_style_sheet->BuildSourceRangeObject(
                source_data->rule_header_range))
            .build();
  }
  return InspectorDOMAgent::ToResponse(exception_state);
}

protocol::Response InspectorCSSAgent::setKeyframeKey(
    const String& style_sheet_id,
    std::unique_ptr<protocol::CSS::SourceRange> range,
    const String& key_text,
    std::unique_ptr<protocol::CSS::Value>* result) {
  FrontendOperationScope scope;
  InspectorStyleSheet* inspector_style_sheet = nullptr;
  protocol::Response response =
      AssertInspectorStyleSheetForId(style_sheet_id, inspector_style_sheet);
  if (!response.IsSuccess())
    return response;
  SourceRange key_range;
  response =
      JsonRangeToSourceRange(inspector_style_sheet, range.get(), &key_range);
  if (!response.IsSuccess())
    return response;

  DummyExceptionStateForTesting exception_state;
  ModifyRuleAction* action = MakeGarbageCollected<ModifyRuleAction>(
      ModifyRuleAction::kSetKeyframeKey, inspector_style_sheet, key_range,
      key_text);
  bool success = dom_agent_->History()->Perform(action, exception_state);
  if (success) {
    auto* rule = To<CSSKeyframeRule>(action->TakeRule());
    inspector_style_sheet = BindStyleSheet(rule->parentStyleSheet());
    if (!inspector_style_sheet) {
      return protocol::Response::ServerError(
          "Failed to get inspector style sheet for rule.");
    }
    CSSRuleSourceData* source_data =
        inspector_style_sheet->SourceDataForRule(rule);
    *result = protocol::CSS::Value::create()
                  .setText(rule->keyText())
                  .setRange(inspector_style_sheet->BuildSourceRangeObject(
                      source_data->rule_header_range))
                  .build();
  }
  return InspectorDOMAgent::ToResponse(exception_state);
}

protocol::Response InspectorCSSAgent::MultipleStyleTextsActions(
    std::unique_ptr<protocol::Array<protocol::CSS::StyleDeclarationEdit>> edits,
    HeapVector<Member<StyleSheetAction>>* actions) {
  size_t n = edits->size();
  if (n == 0)
    return protocol::Response::ServerError("Edits should not be empty");

  for (size_t i = 0; i < n; ++i) {
    protocol::CSS::StyleDeclarationEdit* edit = (*edits)[i].get();
    InspectorStyleSheetBase* inspector_style_sheet = nullptr;
    protocol::Response response =
        AssertStyleSheetForId(edit->getStyleSheetId(), inspector_style_sheet);
    if (!response.IsSuccess()) {
      return protocol::Response::ServerError(
          String::Format("StyleSheet not found for edit #%zu of %zu", i + 1, n)
              .Utf8());
    }

    SourceRange range;
    response =
        JsonRangeToSourceRange(inspector_style_sheet, edit->getRange(), &range);
    if (!response.IsSuccess())
      return response;

    if (inspector_style_sheet->IsInlineStyle()) {
      InspectorStyleSheetForInlineStyle* inline_style_sheet =
          static_cast<InspectorStyleSheetForInlineStyle*>(
              inspector_style_sheet);
      SetElementStyleAction* action =
          MakeGarbageCollected<SetElementStyleAction>(inline_style_sheet,
                                                      edit->getText());
      actions->push_back(action);
    } else {
      ModifyRuleAction* action = MakeGarbageCollected<ModifyRuleAction>(
          ModifyRuleAction::kSetStyleText,
          static_cast<InspectorStyleSheet*>(inspector_style_sheet), range,
          edit->getText());
      actions->push_back(action);
    }
  }
  return protocol::Response::Success();
}

protocol::Response InspectorCSSAgent::setStyleTexts(
    std::unique_ptr<protocol::Array<protocol::CSS::StyleDeclarationEdit>> edits,
    protocol::Maybe<int> node_for_property_syntax_validation,
    std::unique_ptr<protocol::Array<protocol::CSS::CSSStyle>>* result) {
  FrontendOperationScope scope;
  HeapVector<Member<StyleSheetAction>> actions;
  protocol::Response response =
      MultipleStyleTextsActions(std::move(edits), &actions);
  if (!response.IsSuccess())
    return response;

  DummyExceptionStateForTesting exception_state;

  Element* element = nullptr;
  if (node_for_property_syntax_validation.has_value()) {
    response = dom_agent_->AssertElement(
        node_for_property_syntax_validation.value(), element);
    if (!response.IsSuccess())
      return response;
  }

  int n = actions.size();
  auto serialized_styles =
      std::make_unique<protocol::Array<protocol::CSS::CSSStyle>>();
  for (int i = 0; i < n; ++i) {
    Member<StyleSheetAction> action = actions.at(i);
    bool success = action->Perform(exception_state);
    if (!success) {
      for (int j = i - 1; j >= 0; --j) {
        Member<StyleSheetAction> revert = actions.at(j);
        DummyExceptionStateForTesting undo_exception_state;
        revert->Undo(undo_exception_state);
        DCHECK(!undo_exception_state.HadException());
      }
      return protocol::Response::ServerError(
          String::Format("Failed applying edit #%d: ", i).Utf8() +
          InspectorDOMAgent::ToResponse(exception_state).Message());
    }
  }

  if (element) {
    element->GetDocument().UpdateStyleAndLayoutForNode(
        element, DocumentUpdateReason::kInspector);
  }
  for (int i = 0; i < n; ++i) {
    Member<StyleSheetAction> action = actions.at(i);
    serialized_styles->emplace_back(action->TakeSerializedStyle(element));
  }

  for (int i = 0; i < n; ++i) {
    Member<StyleSheetAction> action = actions.at(i);
    dom_agent_->History()->AppendPerformedAction(action);
  }
  *result = std::move(serialized_styles);
  return protocol::Response::Success();
}

protocol::Response InspectorCSSAgent::SetStyleText(
    InspectorStyleSheetBase* inspector_style_sheet,
    const SourceRange& range,
    const String& text,
    CSSStyleDeclaration*& result) {
  DummyExceptionStateForTesting exception_state;
  if (inspector_style_sheet->IsInlineStyle()) {
    InspectorStyleSheetForInlineStyle* inline_style_sheet =
        static_cast<InspectorStyleSheetForInlineStyle*>(inspector_style_sheet);
    SetElementStyleAction* action =
        MakeGarbageCollected<SetElementStyleAction>(inline_style_sheet, text);
    bool success = dom_agent_->History()->Perform(action, exception_state);
    if (success) {
      result = inline_style_sheet->InlineStyle();
      return protocol::Response::Success();
    }
  } else {
    ModifyRuleAction* action = MakeGarbageCollected<ModifyRuleAction>(
        ModifyRuleAction::kSetStyleText,
        static_cast<InspectorStyleSheet*>(inspector_style_sheet), range, text);
    bool success = dom_agent_->History()->Perform(action, exception_state);
    if (success) {
      CSSRule* rule = action->TakeRule();
      if (auto* style_rule = DynamicTo<CSSStyleRule>(rule)) {
        result = style_rule->style();
        return protocol::Response::Success();
      }
      if (auto* keyframe_rule = DynamicTo<CSSKeyframeRule>(rule)) {
        result = keyframe_rule->style();
        return protocol::Response::Success();
      }
    }
  }
  return InspectorDOMAgent::ToResponse(exception_state);
}

protocol::Response InspectorCSSAgent::setMediaText(
    const String& style_sheet_id,
    std::unique_ptr<protocol::CSS::SourceRange> range,
    const String& text,
    std::unique_ptr<protocol::CSS::CSSMedia>* result) {
  FrontendOperationScope scope;
  InspectorStyleSheet* inspector_style_sheet = nullptr;
  protocol::Response response =
      AssertInspectorStyleSheetForId(style_sheet_id, inspector_style_sheet);
  if (!response.IsSuccess())
    return response;
  SourceRange text_range;
  response =
      JsonRangeToSourceRange(inspector_style_sheet, range.get(), &text_range);
  if (!response.IsSuccess())
    return response;

  DummyExceptionStateForTesting exception_state;
  ModifyRuleAction* action = MakeGarbageCollected<ModifyRuleAction>(
      ModifyRuleAction::kSetMediaRuleText, inspector_style_sheet, text_range,
      text);
  bool success = dom_agent_->History()->Perform(action, exception_state);
  if (success) {
    CSSMediaRule* rule = InspectorCSSAgent::AsCSSMediaRule(action->TakeRule());
    String source_url = rule->parentStyleSheet()->Contents()->BaseURL();
    if (source_url.empty())
      source_url = InspectorDOMAgent::DocumentURLString(
          rule->parentStyleSheet()->OwnerDocument());
    *result = BuildMediaObject(rule->media(), kMediaListSourceMediaRule,
                               source_url, rule->parentStyleSheet());
  }
  return InspectorDOMAgent::ToResponse(exception_state);
}

protocol::Response InspectorCSSAgent::setContainerQueryText(
    const String& style_sheet_id,
    std::unique_ptr<protocol::CSS::SourceRange> range,
    const String& text,
    std::unique_ptr<protocol::CSS::CSSContainerQuery>* result) {
  FrontendOperationScope scope;
  InspectorStyleSheet* inspector_style_sheet = nullptr;
  protocol::Response response =
      AssertInspectorStyleSheetForId(style_sheet_id, inspector_style_sheet);
  if (!response.IsSuccess())
    return response;
  SourceRange text_range;
  response =
      JsonRangeToSourceRange(inspector_style_sheet, range.get(), &text_range);
  if (!response.IsSuccess())
    return response;

  DummyExceptionStateForTesting exception_state;
  ModifyRuleAction* action = MakeGarbageCollected<ModifyRuleAction>(
      ModifyRuleAction::kSetContainerRuleText, inspector_style_sheet,
      text_range, text);
  bool success = dom_agent_->History()->Perform(action, exception_state);
  if (success) {
    CSSContainerRule* rule =
        InspectorCSSAgent::AsCSSContainerRule(action->TakeRule());
    *result = BuildContainerQueryObject(rule);
  }
  return InspectorDOMAgent::ToResponse(exception_state);
}

protocol::Response InspectorCSSAgent::setScopeText(
    const String& style_sheet_id,
    std::unique_ptr<protocol::CSS::SourceRange> range,
    const String& text,
    std::unique_ptr<protocol::CSS::CSSScope>* result) {
  FrontendOperationScope scope;
  InspectorStyleSheet* inspector_style_sheet = nullptr;
  protocol::Response response =
      AssertInspectorStyleSheetForId(style_sheet_id, inspector_style_sheet);
  if (!response.IsSuccess())
    return response;
  SourceRange text_range;
  response =
      JsonRangeToSourceRange(inspector_style_sheet, range.get(), &text_range);
  if (!response.IsSuccess())
    return response;

  DummyExceptionStateForTesting exception_state;
  ModifyRuleAction* action = MakeGarbageCollected<ModifyRuleAction>(
      ModifyRuleAction::kSetScopeRuleText, inspector_style_sheet, text_range,
      text);
  bool success = dom_agent_->History()->Perform(action, exception_state);
  if (success) {
    CSSScopeRule* rule = InspectorCSSAgent::AsCSSScopeRule(action->TakeRule());
    *result = BuildScopeObject(rule);
  }
  return InspectorDOMAgent::ToResponse(exception_state);
}

protocol::Response InspectorCSSAgent::setSupportsText(
    const String& style_sheet_id,
    std::unique_ptr<protocol::CSS::SourceRange> range,
    const String& text,
    std::unique_ptr<protocol::CSS::CSSSupports>* result) {
  FrontendOperationScope scope;
  InspectorStyleSheet* inspector_style_sheet = nullptr;
  protocol::Response response =
      AssertInspectorStyleSheetForId(style_sheet_id, inspector_style_sheet);
  if (!response.IsSuccess())
    return response;
  SourceRange text_range;
  response =
      JsonRangeToSourceRange(inspector_style_sheet, range.get(), &text_range);
  if (!response.IsSuccess())
    return response;

  DummyExceptionStateForTesting exception_state;
  ModifyRuleAction* action = MakeGarbageCollected<ModifyRuleAction>(
      ModifyRuleAction::kSetSupportsRuleText, inspector_style_sheet, text_range,
      text);
  bool success = dom_agent_->History()->Perform(action, exception_state);
  if (success) {
    CSSSupportsRule* rule =
        InspectorCSSAgent::AsCSSSupportsRule(action->TakeRule());
    *result = BuildSupportsObject(rule);
  }
  return InspectorDOMAgent::ToResponse(exception_state);
}

protocol::Response InspectorCSSAgent::createStyleSheet(
    const String& frame_id,
    protocol::CSS::StyleSheetId* out_style_sheet_id) {
  LocalFrame* frame =
      IdentifiersFactory::FrameById(inspected_frames_, frame_id);
  if (!frame)
    return protocol::Response::ServerError("Frame not found");

  Document* document = frame->GetDocument();
  if (!document)
    return protocol::Response::ServerError("Frame does not have a document");

  InspectorStyleSheet* inspector_style_sheet = ViaInspectorStyleSheet(document);
  if (!inspector_style_sheet)
    return protocol::Response::ServerError("No target stylesheet found");

  UpdateActiveStyleSheets(document);

  *out_style_sheet_id = inspector_style_sheet->Id();
  return protocol::Response::Success();
}

protocol::Response InspectorCSSAgent::addRule(
    const String& style_sheet_id,
    const String& rule_text,
    std::unique_ptr<protocol::CSS::SourceRange> location,
    protocol::Maybe<int> node_for_property_syntax_validation,
    std::unique_ptr<protocol::CSS::CSSRule>* result) {
  FrontendOperationScope scope;
  InspectorStyleSheet* inspector_style_sheet = nullptr;
  protocol::Response response =
      AssertInspectorStyleSheetForId(style_sheet_id, inspector_style_sheet);
  if (!response.IsSuccess())
    return response;

  Element* element = nullptr;
  if (node_for_property_syntax_validation.has_value()) {
    response = dom_agent_->AssertElement(
        node_for_property_syntax_validation.value(), element);
    if (!response.IsSuccess())
      return response;
  }

  SourceRange rule_location;
  response = JsonRangeToSourceRange(inspector_style_sheet, location.get(),
                                    &rule_location);
  if (!response.IsSuccess())
    return response;

  DummyExceptionStateForTesting exception_state;
  AddRuleAction* action = MakeGarbageCollected<AddRuleAction>(
      inspector_style_sheet, rule_text, rule_location);
  bool success = dom_agent_->History()->Perform(action, exception_state);
  if (!success)
    return InspectorDOMAgent::ToResponse(exception_state);

  CSSStyleRule* rule = action->TakeRule();
  if (element) {
    element->GetDocument().UpdateStyleAndLayoutForNode(
        element, DocumentUpdateReason::kInspector);
  }
  *result = BuildObjectForRule(rule, element);
  return protocol::Response::Success();
}

protocol::Response InspectorCSSAgent::forcePseudoState(
    int node_id,
    std::unique_ptr<protocol::Array<String>> forced_pseudo_classes) {
  protocol::Response response = AssertEnabled();
  if (!response.IsSuccess())
    return response;
  Element* element = nullptr;
  response = dom_agent_->AssertElement(node_id, element);
  if (!response.IsSuccess())
    return response;

  unsigned forced_pseudo_state =
      ComputePseudoClassMask(std::move(forced_pseudo_classes));
  NodeIdToForcedPseudoState::iterator it =
      node_id_to_forced_pseudo_state_.find(node_id);
  unsigned current_forced_pseudo_state =
      it == node_id_to_forced_pseudo_state_.end() ? 0 : it->value;
  bool need_style_recalc = forced_pseudo_state != current_forced_pseudo_state;

  if (!need_style_recalc)
    return protocol::Response::Success();

  if (forced_pseudo_state)
    node_id_to_forced_pseudo_state_.Set(node_id, forced_pseudo_state);
  else
    node_id_to_forced_pseudo_state_.erase(node_id);

  // When adding focus or focus-within, we force focus-within for ancestor
  // nodes to emulate real focus for user convenience.

  // Flips from no forced focus to the forced focus (:focus or :focus-within).
  if (((forced_pseudo_state & kPseudoFocus) == kPseudoFocus &&
       (current_forced_pseudo_state & kPseudoFocus) == 0) ||
      ((forced_pseudo_state & kPseudoFocusWithin) == kPseudoFocusWithin &&
       (current_forced_pseudo_state & kPseudoFocusWithin) == 0)) {
    IncrementFocusedCountForAncestors(element);
  }

  // Flips from the forced focus (:focus or :focus-within) to no focus.
  if (((forced_pseudo_state & kPseudoFocus) == 0 &&
       (current_forced_pseudo_state & kPseudoFocus) == kPseudoFocus) ||
      ((forced_pseudo_state & kPseudoFocusWithin) == 0 &&
       (current_forced_pseudo_state & kPseudoFocusWithin) ==
           kPseudoFocusWithin)) {
    DecrementFocusedCountForAncestors(element);
  }

  element->GetDocument().GetStyleEngine().MarkAllElementsForStyleRecalc(
      StyleChangeReasonForTracing::Create(style_change_reason::kInspector));
  return protocol::Response::Success();
}

void InspectorCSSAgent::IncrementFocusedCountForAncestors(Element* element) {
  for (Node& ancestor : FlatTreeTraversal::AncestorsOf(*element)) {
    if (!IsA<Element>(ancestor))
      continue;
    int node_id = dom_agent_->BoundNodeId(&ancestor);
    if (!node_id)
      continue;
    NodeIdToNumberFocusedChildren::iterator it =
        node_id_to_number_focused_children_.find(node_id);
    unsigned count =
        it == node_id_to_number_focused_children_.end() ? 0 : it->value;
    node_id_to_number_focused_children_.Set(node_id, count + 1);
  }
}

void InspectorCSSAgent::DecrementFocusedCountForAncestors(Element* element) {
  for (Node& ancestor : FlatTreeTraversal::AncestorsOf(*element)) {
    if (!IsA<Element>(ancestor))
      continue;
    int node_id = 
"""


```