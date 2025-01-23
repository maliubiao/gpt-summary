Response:
The user wants a summary of the functionality of the provided C++ code snippet from the Chromium Blink engine. I need to identify the key actions performed by the `InspectorCSSAgent` class and its methods, specifically focusing on how it interacts with CSS, HTML, and JavaScript within the context of a web page inspection tool.

Here's a breakdown of the code's functionalities:

1. **Retrieving CSS Styles:**  Several methods are dedicated to fetching and processing CSS rules and declarations for specific elements, including pseudo-elements.
2. **Modifying CSS Styles:**  The code allows for modifying existing CSS properties and adding new ones, including handling shorthand properties and `!important` flags.
3. **Tracking CSS Usage:** Functionality exists to monitor which CSS rules are actually being applied to elements on the page.
4. **Tracking Computed Style Updates:** The code can track changes in the final computed styles of elements, allowing the inspector to notify when specific styles change.
5. **Providing Background Color Information:** A method retrieves the background colors of an element, which is useful for accessibility and debugging.

I will now synthesize this information into a comprehensive summary, addressing the user's request for examples, logical reasoning, common errors, and a final concise summary.
好的，这是对 `blink/renderer/core/inspector/inspector_css_agent.cc` 文件中提供的代码片段的功能总结：

**功能归纳：**

这段代码是 Chromium Blink 引擎中 `InspectorCSSAgent` 的一部分，其主要功能是**为开发者工具（DevTools）提供 CSS 相关的检查和修改能力**。具体来说，它允许开发者通过 DevTools 查看和编辑页面元素的样式，并跟踪 CSS 规则的使用情况和计算样式的更新。

**详细功能列表及说明：**

1. **获取元素的有效样式声明 (`MatchingStyles`):**
    *   **功能:**  获取指定元素（包括伪元素）的所有匹配的 CSS 样式声明。它会考虑所有的样式来源，包括内联样式、外部样式表以及用户代理样式表。
    *   **与 CSS 关系:** 核心功能，直接处理 CSS 规则和声明。
    *   **与 HTML 关系:** 通过 `element` 参数与 HTML 元素关联。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:** 一个 `Element` 对象，例如一个 `<div>` 元素。
        *   **输出:**  一个 `HeapVector<Member<CSSStyleDeclaration>>`，其中包含应用于该元素的所有样式声明对象。

2. **查找特定属性的有效声明 (`FindEffectiveDeclaration`):**
    *   **功能:** 在一组样式声明中，找到指定 CSS 属性的最终有效声明。它会考虑 `!important` 优先级。
    *   **与 CSS 关系:**  处理 CSS 属性和优先级。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:**  一个 `CSSPropertyName` 对象（例如 "color"）和一个 `HeapVector<Member<CSSStyleDeclaration>>`（来自 `MatchingStyles`）。
        *   **输出:**  一个指向 `CSSStyleDeclaration` 对象的指针，该对象包含指定属性的有效值，如果没有找到则返回 `nullptr`。

3. **设置元素的有效属性值 (`setEffectivePropertyValueForNode`):**
    *   **功能:**  修改指定元素的某个 CSS 属性的有效值。它会找到该属性的来源，并修改对应的样式表。可以修改内联样式或样式表中的规则。
    *   **与 CSS 关系:**  修改 CSS 属性值，包括处理简写属性和 `!important` 标记。
    *   **与 HTML 关系:** 通过 `node_id` 找到对应的 HTML 元素。
    *   **与 JavaScript 关系:**  DevTools 是一个 Web 应用，用户在 DevTools 上操作会触发 JavaScript 代码，最终调用到这个 C++ 函数来修改样式。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:**  `node_id` (元素的 ID), `property_name` (例如 "color"), `value` (例如 "red")。
        *   **输出:**  一个 `protocol::Response` 对象，表示操作是否成功。如果成功，相关的 CSS 规则会被修改。
    *   **用户或编程常见的使用错误:**
        *   尝试修改伪元素的样式（代码中已阻止）。
        *   尝试修改非激活文档中的元素样式。
        *   传入无效的属性名。

4. **获取元素的背景颜色 (`getBackgroundColors` 和 `GetBackgroundColors`):**
    *   **功能:**  获取指定元素的背景颜色、计算后的字体大小和字体粗细。
    *   **与 CSS 关系:** 获取与背景和文本相关的 CSS 属性值。
    *   **与 HTML 关系:** 通过 `node_id` 找到对应的 HTML 元素。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:** `node_id` (元素的 ID)。
        *   **输出:** `background_colors` (一个颜色字符串数组), `computed_font_size`, `computed_font_weight`。

5. **启用/禁用 CSS 覆盖率跟踪 (`SetCoverageEnabled`):**
    *   **功能:**  开启或关闭 CSS 规则使用情况的跟踪。
    *   **与 CSS 关系:** 监控 CSS 规则的应用情况。

6. **在样式元素改变时执行操作 (`WillChangeStyleElement`):**
    *   **功能:** 当一个 `<style>` 元素的内容即将改变时，清除相关的资源缓存。
    *   **与 CSS 关系:**  与 `<style>` 元素关联，用于管理样式。
    *   **与 HTML 关系:**  涉及到 HTML 中的 `<style>` 元素。

7. **开始/停止 CSS 规则使用情况跟踪 (`startRuleUsageTracking`, `stopRuleUsageTracking`, `takeCoverageDelta`):**
    *   **功能:** 启动、停止并获取 CSS 规则的使用情况数据。这可以帮助开发者识别未使用的 CSS 规则。
    *   **与 CSS 关系:**  核心功能，用于分析 CSS 规则的使用。
    *   **逻辑推理 (假设输入与输出):**
        *   **`startRuleUsageTracking`:**  开始跟踪，无主要输出。
        *   **`stopRuleUsageTracking`:** 停止跟踪并返回使用情况数据。
        *   **`takeCoverageDelta`:** 获取自上次调用以来的使用情况增量数据。
        *   **输出:** 一个 `protocol::Array<protocol::CSS::RuleUsage>` 对象，包含每个 CSS 规则的使用信息。

8. **跟踪计算样式更新 (`trackComputedStyleUpdatesForNode`, `trackComputedStyleUpdates`, `takeComputedStyleUpdates`, `NotifyComputedStyleUpdatedForNode`, `DidUpdateComputedStyle`):**
    *   **功能:** 允许 DevTools 跟踪特定节点的计算样式更新。当指定节点的计算样式发生变化时，DevTools 会收到通知。可以跟踪所有计算样式的更新，也可以只跟踪特定属性的更新。
    *   **与 CSS 关系:**  监控 CSS 属性最终计算后的值。
    *   **与 HTML 关系:**  通过 `node_id` 关联到 HTML 元素。
    *   **与 JavaScript 关系:**  DevTools 通过协议与 Blink 通信，接收计算样式更新的通知。
    *   **逻辑推理 (假设输入与输出):**
        *   **`trackComputedStyleUpdatesForNode`:**  设置要跟踪计算样式更新的特定节点 (可选)。
        *   **`trackComputedStyleUpdates`:**  设置要跟踪的 CSS 属性和可选的值。
        *   **`takeComputedStyleUpdates`:**  请求获取自上次请求以来的计算样式更新的节点列表。
        *   **`NotifyComputedStyleUpdatedForNode`:**  当指定节点的计算样式更新后被调用，发送通知给前端。
        *   **`DidUpdateComputedStyle`:**  当元素的计算样式更新时被调用，判断是否需要通知前端。
        *   **输出:**  一个包含已更新计算样式的节点 ID 数组。

9. **构建规则映射 (`BuildRulesMap`):**
    *   **功能:**  为给定的样式表构建一个从 `StyleRule` 对象到 `CSSStyleRule` 对象的映射。这用于在跟踪 CSS 使用情况时查找对应的 CSS 规则。
    *   **与 CSS 关系:**  处理 CSS 规则和样式表。

10. **处理本地字体启用状态 (`LocalFontsEnabled`, `setLocalFontsEnabled`):**
    *   **功能:**  获取和设置是否启用本地字体访问。这影响 DevTools 如何显示字体信息。
    *   **与 CSS 关系:**  与字体相关的 CSS 属性有关。

**总结:**

这段代码的核心职责是作为 DevTools 的后端，提供与 CSS 样式检查和修改相关的功能。它允许开发者查看和编辑元素的样式，跟踪 CSS 规则的使用情况，并监控计算样式的变化，从而帮助开发者更好地理解和调试页面的样式。它与 HTML 通过元素关联，与 CSS 直接交互，并为 DevTools 的 JavaScript 前端提供数据和控制接口。

### 提示词
```
这是目录为blink/renderer/core/inspector/inspector_css_agent.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第5部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
AtomicString view_transition_name = g_null_atom;
  element = GetPseudoIdAndTag(element, pseudo_id, view_transition_name);
  if (!element)
    return {};

  StyleResolver& style_resolver = element->GetDocument().GetStyleResolver();

  // TODO(masonf,futhark): We need to update slot assignments here, so that
  // the flat tree is up to date for the call to PseudoCSSRulesForElement().
  // Eventually, RecalcSlotAssignments() should be called directly in
  // PseudoCSSRulesForElement(), but there are a number of sites within
  // inspector code that traverse the tree and call PseudoCSSRulesForElement()
  // for each element.
  element->GetDocument().GetSlotAssignmentEngine().RecalcSlotAssignments();

  // This ensures that active stylesheets are up-to-date, such that
  // the subsequent collection of matching rules actually match against
  // the correct RuleSets.
  element->GetDocument().GetStyleEngine().UpdateActiveStyle();

  HeapVector<Member<CSSStyleRule>> rules =
      FilterDuplicateRules(style_resolver.PseudoCSSRulesForElement(
          element, pseudo_id, view_transition_name,
          StyleResolver::kAllCSSRules));
  HeapVector<Member<CSSStyleDeclaration>> styles;
  if (!pseudo_id && element->style())
    styles.push_back(element->style());
  for (unsigned i = rules.size(); i > 0; --i) {
    CSSStyleSheet* parent_style_sheet = rules.at(i - 1)->parentStyleSheet();
    if (!parent_style_sheet || !parent_style_sheet->ownerNode())
      continue;  // User agent.
    styles.push_back(rules.at(i - 1)->style());
  }
  return styles;
}

CSSStyleDeclaration* InspectorCSSAgent::FindEffectiveDeclaration(
    const CSSPropertyName& property_name,
    const HeapVector<Member<CSSStyleDeclaration>>& styles) {
  if (!styles.size())
    return nullptr;

  String longhand = property_name.ToAtomicString();
  CSSStyleDeclaration* found_style = nullptr;

  for (unsigned i = 0; i < styles.size(); ++i) {
    CSSStyleDeclaration* style = styles.at(i).Get();
    if (style->getPropertyValue(longhand).empty())
      continue;
    if (style->getPropertyPriority(longhand) == "important")
      return style;
    if (!found_style)
      found_style = style;
  }

  return found_style ? found_style : styles.at(0).Get();
}

protocol::Response InspectorCSSAgent::setEffectivePropertyValueForNode(
    int node_id,
    const String& property_name,
    const String& value) {
  Element* element = nullptr;
  protocol::Response response = dom_agent_->AssertElement(node_id, element);
  if (!response.IsSuccess())
    return response;
  if (element->GetPseudoId())
    return protocol::Response::ServerError("Elements is pseudo");

  if (!element->GetDocument().IsActive()) {
    return protocol::Response::ServerError(
        "Can't edit a node from a non-active document");
  }

  std::optional<CSSPropertyName> css_property_name =
      CSSPropertyName::From(element->GetExecutionContext(), property_name);
  if (!css_property_name.has_value())
    return protocol::Response::ServerError("Invalid property name");

  CSSStyleDeclaration* style =
      FindEffectiveDeclaration(*css_property_name, MatchingStyles(element));
  if (!style)
    return protocol::Response::ServerError("Can't find a style to edit");

  bool force_important = false;
  InspectorStyleSheetBase* inspector_style_sheet = nullptr;
  CSSRuleSourceData* source_data;
  // An absence of the parent rule means that given style is an inline style.
  if (style->parentRule()) {
    InspectorStyleSheet* style_sheet =
        BindStyleSheet(style->ParentStyleSheet());
    inspector_style_sheet = style_sheet;
    source_data = style_sheet->SourceDataForRule(style->parentRule());
  } else {
    InspectorStyleSheetForInlineStyle* inline_style_sheet =
        AsInspectorStyleSheet(element);
    inspector_style_sheet = inline_style_sheet;
    source_data = inline_style_sheet->RuleSourceData();
  }

  if (!source_data)
    return protocol::Response::ServerError("Can't find a source to edit");

  Vector<StylePropertyShorthand, 4> shorthands;
  getMatchingShorthandsForLonghand(css_property_name->Id(), &shorthands);

  String shorthand =
      shorthands.size() > 0
          ? CSSProperty::Get(shorthands[0].id()).GetPropertyNameString()
          : String();
  String longhand = css_property_name->ToAtomicString();

  int found_index = -1;
  Vector<CSSPropertySourceData>& properties = source_data->property_data;
  for (unsigned i = 0; i < properties.size(); ++i) {
    CSSPropertySourceData property = properties[properties.size() - i - 1];
    String name = property.name;
    if (property.disabled)
      continue;

    if (name != shorthand && name != longhand)
      continue;

    if (property.important || found_index == -1)
      found_index = properties.size() - i - 1;

    if (property.important)
      break;
  }

  SourceRange body_range = source_data->rule_body_range;
  String style_sheet_text;
  inspector_style_sheet->GetText(&style_sheet_text);
  String style_text =
      style_sheet_text.Substring(body_range.start, body_range.length());
  SourceRange change_range;
  if (found_index == -1) {
    String new_property_text = "\n" + longhand + ": " + value +
                               (force_important ? " !important" : "") + ";";
    if (!style_text.empty() && !style_text.StripWhiteSpace().EndsWith(';'))
      new_property_text = ";" + new_property_text;
    style_text = style_text + new_property_text;
    change_range.start = body_range.end;
    change_range.end = body_range.end + new_property_text.length();
  } else {
    CSSPropertySourceData declaration = properties[found_index];
    String new_value_text;
    if (declaration.name == shorthand) {
      new_value_text = CreateShorthandValue(element->GetDocument(), shorthand,
                                            declaration.value, longhand, value);
    } else {
      new_value_text = value;
    }

    String new_property_text =
        declaration.name + ": " + new_value_text +
        (declaration.important || force_important ? " !important" : "") + ";";
    style_text.replace(declaration.range.start - body_range.start,
                       declaration.range.length(), new_property_text);
    change_range.start = declaration.range.start;
    change_range.end = change_range.start + new_property_text.length();
  }
  CSSStyleDeclaration* result_style;
  return SetStyleText(inspector_style_sheet, body_range, style_text,
                      result_style);
}

protocol::Response InspectorCSSAgent::getBackgroundColors(
    int node_id,
    Maybe<protocol::Array<String>>* background_colors,
    Maybe<String>* computed_font_size,
    Maybe<String>* computed_font_weight) {
  Element* element = nullptr;
  protocol::Response response = dom_agent_->AssertElement(node_id, element);
  if (!response.IsSuccess())
    return response;

  Vector<Color> bgcolors;
  String fs;
  String fw;
  float text_opacity = 1.0f;
  InspectorCSSAgent::GetBackgroundColors(element, &bgcolors, &fs, &fw,
                                         &text_opacity);

  if (bgcolors.size()) {
    *background_colors = std::make_unique<protocol::Array<String>>();
    for (const auto& color : bgcolors) {
      (*background_colors)
          ->emplace_back(
              cssvalue::CSSColor::SerializeAsCSSComponentValue(color));
    }
  }
  if (!fs.empty())
    *computed_font_size = fs;
  if (!fw.empty())
    *computed_font_weight = fw;
  return protocol::Response::Success();
}

// static
void InspectorCSSAgent::GetBackgroundColors(Element* element,
                                            Vector<Color>* colors,
                                            String* computed_font_size,
                                            String* computed_font_weight,
                                            float* text_opacity) {
  InspectorContrast contrast(&element->GetDocument());
  *colors = contrast.GetBackgroundColors(element, text_opacity);
  auto text_info = contrast.GetTextInfo(element);
  *computed_font_size = text_info.font_size;
  *computed_font_weight = text_info.font_weight;
}

void InspectorCSSAgent::SetCoverageEnabled(bool enabled) {
  if (enabled == !!tracker_)
    return;
  tracker_ = enabled ? MakeGarbageCollected<StyleRuleUsageTracker>() : nullptr;

  for (Document* document : dom_agent_->Documents())
    document->GetStyleEngine().SetRuleUsageTracker(tracker_);
}

void InspectorCSSAgent::WillChangeStyleElement(Element* element) {
  resource_container_->EraseStyleElementContent(element->GetDomNodeId());
}

protocol::Response InspectorCSSAgent::startRuleUsageTracking() {
  coverage_enabled_.Set(true);
  SetCoverageEnabled(true);

  for (Document* document : dom_agent_->Documents()) {
    document->GetStyleEngine().MarkAllElementsForStyleRecalc(
        StyleChangeReasonForTracing::Create(style_change_reason::kInspector));
    document->UpdateStyleAndLayoutTree();
  }

  return protocol::Response::Success();
}

protocol::Response InspectorCSSAgent::trackComputedStyleUpdatesForNode(
    protocol::Maybe<int> node_id) {
  if (node_id.has_value()) {
    node_id_for_computed_style_updated_events_ = node_id.value();
  } else {
    node_id_for_computed_style_updated_events_ = std::nullopt;
  }

  return protocol::Response::Success();
}

protocol::Response InspectorCSSAgent::stopRuleUsageTracking(
    std::unique_ptr<protocol::Array<protocol::CSS::RuleUsage>>* result) {
  for (Document* document : dom_agent_->Documents())
    document->UpdateStyleAndLayoutTree();
  double timestamp;
  protocol::Response response = takeCoverageDelta(result, &timestamp);
  SetCoverageEnabled(false);
  return response;
}

void InspectorCSSAgent::BuildRulesMap(
    InspectorStyleSheet* style_sheet,
    HeapHashMap<Member<const StyleRule>, Member<CSSStyleRule>>*
        rule_to_css_rule) {
  const CSSRuleVector& css_rules = style_sheet->FlatRules();
  for (auto css_rule : css_rules) {
    if (css_rule->GetType() == CSSRule::kStyleRule) {
      CSSStyleRule* css_style_rule = DynamicTo<CSSStyleRule>(css_rule.Get());
      rule_to_css_rule->Set(css_style_rule->GetStyleRule(), css_style_rule);
    }
    if (css_rule->GetType() == CSSRule::kImportRule) {
      CSSImportRule* css_import_rule = DynamicTo<CSSImportRule>(css_rule.Get());
      if (!css_import_rule->styleSheet())
        continue;
      auto it = css_style_sheet_to_inspector_style_sheet_.find(
          const_cast<CSSStyleSheet*>(css_import_rule->styleSheet()));
      if (it == css_style_sheet_to_inspector_style_sheet_.end())
        continue;
      InspectorStyleSheet* imported_style_sheet = it->value;
      BuildRulesMap(imported_style_sheet, rule_to_css_rule);
    }
  }
}

protocol::Response InspectorCSSAgent::takeCoverageDelta(
    std::unique_ptr<protocol::Array<protocol::CSS::RuleUsage>>* result,
    double* out_timestamp) {
  if (!tracker_) {
    return protocol::Response::ServerError(
        "CSS rule usage tracking is not enabled");
  }

  StyleRuleUsageTracker::RuleListByStyleSheet coverage_delta =
      tracker_->TakeDelta();

  *out_timestamp = base::TimeTicks::Now().since_origin().InSecondsF();

  *result = std::make_unique<protocol::Array<protocol::CSS::RuleUsage>>();

  for (const auto& entry : coverage_delta) {
    const CSSStyleSheet* css_style_sheet = entry.key.Get();

    auto style_sheet_it = css_style_sheet_to_inspector_style_sheet_.find(
        const_cast<CSSStyleSheet*>(css_style_sheet));
    if (style_sheet_it == css_style_sheet_to_inspector_style_sheet_.end())
      continue;
    InspectorStyleSheet* style_sheet = style_sheet_it->value;

    HeapHashMap<Member<const StyleRule>, Member<CSSStyleRule>> rule_to_css_rule;
    BuildRulesMap(style_sheet, &rule_to_css_rule);

    for (auto used_rule : *entry.value) {
      auto rule_to_css_rule_it = rule_to_css_rule.find(used_rule);
      if (rule_to_css_rule_it == rule_to_css_rule.end())
        continue;
      CSSStyleRule* css_style_rule = rule_to_css_rule_it->value;
      auto it = css_style_sheet_to_inspector_style_sheet_.find(
          const_cast<CSSStyleSheet*>(css_style_rule->parentStyleSheet()));
      if (it == css_style_sheet_to_inspector_style_sheet_.end())
        continue;
      // If the rule comes from an @import'ed file, the `rule_style_sheet` is
      // different from `style_sheet`.
      InspectorStyleSheet* rule_style_sheet = it->value;
      CSSRule* rule = css_style_rule;
      while (rule) {
        if (std::unique_ptr<protocol::CSS::RuleUsage> rule_usage_object =
                rule_style_sheet->BuildObjectForRuleUsage(rule, true)) {
          (*result)->emplace_back(std::move(rule_usage_object));
        }
        rule = rule->parentRule();
      }
    }
  }

  return protocol::Response::Success();
}

protocol::Response InspectorCSSAgent::trackComputedStyleUpdates(
    std::unique_ptr<protocol::Array<protocol::CSS::CSSComputedStyleProperty>>
        properties_to_track) {
  tracked_computed_styles_.clear();
  if (properties_to_track->size() == 0) {
    if (computed_style_updated_callback_) {
      computed_style_updated_callback_->sendSuccess(
          BuildArrayForComputedStyleUpdatedNodes());
      computed_style_updated_callback_ = nullptr;
    }
    computed_style_updated_node_ids_.clear();
    return protocol::Response::Success();
  }

  for (const auto& property : *properties_to_track) {
    String property_name = property->getName();
    HashMap<String, HashSet<String>>::iterator it =
        tracked_computed_styles_.find(property_name);
    if (it != tracked_computed_styles_.end()) {
      it->value.insert(property->getValue());
    } else {
      HashSet<String> tracked_values;
      tracked_values.insert(property->getValue());
      tracked_computed_styles_.Set(property_name, tracked_values);
    }
  }

  return protocol::Response::Success();
}

void InspectorCSSAgent::takeComputedStyleUpdates(
    std::unique_ptr<TakeComputedStyleUpdatesCallback> callback) {
  if (tracked_computed_styles_.empty()) {
    callback->sendFailure(protocol::Response::ServerError(
        "No computed styles are being tracked right now."));
    return;
  }

  if (computed_style_updated_callback_) {
    callback->sendFailure(protocol::Response::ServerError(
        "A previous request has not been resolved yet."));
    return;
  }

  if (computed_style_updated_node_ids_.size()) {
    callback->sendSuccess(BuildArrayForComputedStyleUpdatedNodes());
    computed_style_updated_node_ids_.clear();
    return;
  }

  computed_style_updated_callback_ = std::move(callback);
}

void InspectorCSSAgent::NotifyComputedStyleUpdatedForNode(int node_id) {
  if (!notify_computed_style_updated_node_ids_.Contains(node_id)) {
    return;
  }

  notify_computed_style_updated_node_ids_.erase(node_id);
  if (!node_id_for_computed_style_updated_events_.has_value() ||
      node_id_for_computed_style_updated_events_.value() != node_id) {
    return;
  }

  GetFrontend()->computedStyleUpdated(node_id);
}

void InspectorCSSAgent::DidUpdateComputedStyle(Element* element,
                                               const ComputedStyle* old_style,
                                               const ComputedStyle* new_style) {
  if (tracked_computed_styles_.empty() &&
      !node_id_for_computed_style_updated_events_.has_value()) {
    return;
  }

  int id = dom_agent_->BoundNodeId(element);
  // If node is not mapped yet -> ignore the event.
  if (!id)
    return;

  // If the updated computed styles belong to the tracked node,
  // schedule a task to send `computedStyleUpdated` event.
  if (node_id_for_computed_style_updated_events_.has_value() &&
      node_id_for_computed_style_updated_events_.value() == id &&
      !notify_computed_style_updated_node_ids_.Contains(id)) {
    notify_computed_style_updated_node_ids_.insert(id);
    scoped_refptr<base::SingleThreadTaskRunner> task_runner =
        inspected_frames_->Root()->GetTaskRunner(TaskType::kInternalInspector);
    task_runner->PostDelayedTask(
        FROM_HERE,
        WTF::BindOnce(&InspectorCSSAgent::NotifyComputedStyleUpdatedForNode,
                      WrapPersistent(weak_factory_.GetWeakCell()), id),
        base::Milliseconds(50));
  }

  bool has_both_old_and_new_style = old_style && new_style;
  if (tracked_computed_styles_.empty() || !has_both_old_and_new_style) {
    return;
  }

  if (computed_style_updated_node_ids_.Contains(id))
    return;

  // Compares with the currently tracked styles to see if this node should be
  // included
  for (const auto& tracked_computed_style : tracked_computed_styles_) {
    const HashSet<String>& tracked_values = tracked_computed_style.value;
    CSSPropertyRef ref(tracked_computed_style.key, element->GetDocument());
    if (!ref.IsValid())
      continue;
    const CSSProperty& tracked_property = ref.GetProperty();
    // TODO(crbug/1108356): consider using the Prepared Value once it's ready
    const CSSValue* old_value = old_style
                                    ? ComputedStyleUtils::ComputedPropertyValue(
                                          tracked_property, *old_style)
                                    : nullptr;
    const CSSValue* new_value = new_style
                                    ? ComputedStyleUtils::ComputedPropertyValue(
                                          tracked_property, *new_style)
                                    : nullptr;
    if (old_value == new_value)
      continue;
    String old_value_text = old_value ? old_value->CssText() : "";
    String new_value_text = new_value ? new_value->CssText() : "";
    if (old_value_text == new_value_text)
      continue;
    if (tracked_values.Contains(old_value_text) ||
        tracked_values.Contains(new_value_text)) {
      computed_style_updated_node_ids_.insert(id);
      return;
    }
  }
}

void InspectorCSSAgent::Will(const probe::RecalculateStyle&) {}

void InspectorCSSAgent::Did(const probe::RecalculateStyle&) {
  if (computed_style_updated_callback_ &&
      computed_style_updated_node_ids_.size()) {
    computed_style_updated_callback_->sendSuccess(
        BuildArrayForComputedStyleUpdatedNodes());
    computed_style_updated_node_ids_.clear();
    computed_style_updated_callback_ = nullptr;
  }
}

std::unique_ptr<protocol::Array<int>>
InspectorCSSAgent::BuildArrayForComputedStyleUpdatedNodes() {
  std::unique_ptr<protocol::Array<int>> nodes =
      std::make_unique<protocol::Array<int>>();
  for (int node_id : computed_style_updated_node_ids_) {
    nodes->push_back(node_id);
  }
  return nodes;
}

void InspectorCSSAgent::Trace(Visitor* visitor) const {
  visitor->Trace(dom_agent_);
  visitor->Trace(inspected_frames_);
  visitor->Trace(network_agent_);
  visitor->Trace(resource_content_loader_);
  visitor->Trace(resource_container_);
  visitor->Trace(id_to_inspector_style_sheet_);
  visitor->Trace(id_to_inspector_style_sheet_for_inline_style_);
  visitor->Trace(css_style_sheet_to_inspector_style_sheet_);
  visitor->Trace(document_to_css_style_sheets_);
  visitor->Trace(invalidated_documents_);
  visitor->Trace(node_to_inspector_style_sheet_);
  visitor->Trace(inspector_user_agent_style_sheet_);
  visitor->Trace(user_agent_view_transition_style_sheet_);
  visitor->Trace(tracker_);
  visitor->Trace(weak_factory_);
  InspectorBaseAgent::Trace(visitor);
}

void InspectorCSSAgent::LocalFontsEnabled(bool* result) {
  if (!local_fonts_enabled_.Get())
    *result = false;
}

protocol::Response InspectorCSSAgent::setLocalFontsEnabled(bool enabled) {
  local_fonts_enabled_.Set(enabled);
  // TODO(alexrudenko): how to rerender fonts so that
  // local_fonts_enabled_ applies without page reload?
  return protocol::Response::Success();
}

}  // namespace blink
```