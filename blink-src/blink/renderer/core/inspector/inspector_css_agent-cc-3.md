Response:
The user wants a summary of the functionalities of the provided C++ code snippet from `inspector_css_agent.cc`. I need to identify the core responsibilities of this code and how it relates to web development concepts like JavaScript, HTML, and CSS.

Here's a breakdown of the code's purpose:

1. **Inspector Integration:** The code interacts with the browser's developer tools (Inspector), specifically the CSS inspection features. This involves providing data about stylesheets, rules, and styles to the Inspector's frontend.

2. **CSS Object Construction:**  The code contains several functions (e.g., `BuildMediaObject`, `BuildContainerQueryObject`, `BuildSupportsObject`) that construct objects representing various CSS concepts like `@media` rules, container queries, and `@supports` rules. These objects are likely formatted according to a protocol used by the Inspector.

3. **CSS Rule Traversal and Collection:** Functions like `CollectMediaQueriesFromStyleSheet`, `CollectMediaQueriesFromRule`, etc., demonstrate the code's ability to traverse the structure of CSS stylesheets and rules, extracting specific information (like media queries, container queries, etc.).

4. **Mapping and Tracking:** The code uses data structures (like `node_id_to_forced_pseudo_state_`, `css_style_sheet_to_inspector_style_sheet_`) to maintain a mapping between DOM nodes, CSS stylesheets, and their corresponding Inspector representations. This is crucial for associating information displayed in the Inspector with the underlying browser objects.

5. **Pseudo-Class Handling:** The code snippet includes logic for handling `:focus-within` pseudo-classes, demonstrating its awareness of dynamic CSS states.

6. **Source Location Information:**  The code seems to be involved in providing source location information for CSS rules and properties, allowing the Inspector to highlight the relevant lines in the source files.

7. **Style Recalculation and Updates:** Functions like `DidModifyDOMAttr` and `DidMutateStyleSheet` suggest that the code reacts to changes in the DOM and CSS, triggering updates in the Inspector.

8. **Protocol Communication:** The code uses types from a `protocol` namespace (e.g., `protocol::CSS::CSSMedia`), indicating that it's involved in communicating CSS-related information to the Inspector frontend using a defined protocol.

Based on this analysis, I can formulate the summary and examples.
好的，这是对提供的代码片段的功能归纳：

**功能归纳：**

这段代码主要负责构建和管理与 CSS 相关的各种数据结构，以便在 Chromium 的开发者工具 (Inspector) 中展示和交互。它专注于将 Blink 引擎内部的 CSS 对象（如 `MediaList`, `CSSMediaRule`, `CSSContainerRule`, `CSSSupportsRule` 等）转换为 Inspector 前端可以理解的协议对象 (`protocol::CSS::CSSMedia`, `protocol::CSS::CSSContainerQuery`, `protocol::CSS::CSSSupports` 等)。此外，它还负责维护一些状态信息，例如节点上强制应用的伪类状态和 `:focus-within` 状态。

**具体功能分解：**

1. **管理 `:focus-within` 状态:**  `UpdateFocusWithinAncestors` 函数用于维护一个映射 (`node_id_to_number_focused_children_`)，记录了每个节点有多少个后代元素获得了焦点。这用于确定是否应该强制应用 `:focus-within` 伪类。

    * **与 CSS 的关系:**  `:focus-within` 是一个 CSS 伪类选择器，当元素自身或其任何后代元素获得焦点时匹配。这段代码逻辑直接影响了浏览器如何判断一个元素是否应该匹配 `:focus-within`。
    * **假设输入与输出:** 假设一个 DOM 结构如下：
      ```html
      <div id="parent">
        <input id="child1">
      </div>
      ```
      - **假设输入:**  子元素 `#child1` 获得焦点。
      - **逻辑推理:** `UpdateFocusWithinAncestors` 会遍历 `#child1` 的祖先节点，找到 `#parent`，并在 `node_id_to_number_focused_children_` 中将 `#parent` 的计数加 1。
      - **假设输入:** 子元素 `#child1` 失去焦点。
      - **逻辑推理:** `UpdateFocusWithinAncestors` 会再次遍历 `#child1` 的祖先节点，找到 `#parent`，并将 `#parent` 的计数减 1。如果计数变为 0，则从映射中移除 `#parent`。

2. **构建 `CSSMedia` 对象:** `BuildMediaObject` 函数将 Blink 引擎的 `MediaList` 对象转换为 Inspector 协议的 `protocol::CSS::CSSMedia` 对象。这包括提取媒体查询的文本、来源、以及表达式等信息。

    * **与 CSS 的关系:**  `MediaList` 和 `CSSMediaRule` (通过 `kMediaListSourceMediaRule`) 代表了 CSS 中的 `@media` 规则。此函数将这些规则的信息传递给 Inspector。
    * **与 HTML 的关系:** 媒体查询通常与 `<link>` 标签或 `<style>` 标签一起使用，根据不同的媒体条件应用不同的样式。此函数处理来自这些上下文的媒体查询。
    * **与 JavaScript 的关系:** JavaScript 可以通过 DOM API 操作样式表和媒体查询，Inspector 提供的这些信息可以帮助开发者调试 JavaScript 对 CSS 的影响。
    * **假设输入与输出:** 假设有如下 CSS：
      ```css
      @media (max-width: 600px) {
        body {
          background-color: lightblue;
        }
      }
      ```
      - **假设输入:**  Blink 引擎解析到这个 `@media` 规则，创建了一个 `MediaList` 对象。
      - **输出:** `BuildMediaObject` 函数会创建一个 `protocol::CSS::CSSMedia` 对象，其中 `text` 属性为 "(max-width: 600px)"，`source` 属性为 "MediaRule"，并且 `mediaList` 包含一个 `protocol::CSS::MediaQuery` 对象，其 `expressions` 包含一个 `protocol::CSS::MediaQueryExpression` 对象，表示 "max-width" 特性，值为 600，单位为 "px"。

3. **收集媒体查询信息:** `CollectMediaQueriesFromStyleSheet` 和 `CollectMediaQueriesFromRule` 函数用于从样式表和 CSS 规则中提取媒体查询信息，并添加到提供的 `protocol::Array<protocol::CSS::CSSMedia>` 中。

    * **与 CSS 的关系:**  这些函数遍历 CSS 规则（例如 `@media` 规则和 `@import` 规则中的媒体查询），提取相关信息。

4. **构建其他 CSS 相关对象:**  `BuildContainerQueryObject`, `BuildSupportsObject`, `BuildLayerObject`, `BuildStartingStyleObject`, `BuildScopeObject`  等函数类似地负责将 Blink 引擎中表示容器查询、`@supports` 规则、CSS layers、`@starting-style` 规则、`@scope` 规则的对象转换为 Inspector 协议对象。

    * **与 CSS 的关系:** 这些函数对应于 CSS 的新特性，允许开发者进行更精细的样式控制。

5. **收集容器查询、`@supports`、CSS Layers 等信息:** `CollectContainerQueriesFromRule`, `CollectSupportsFromRule`, `CollectLayersFromRule`, `CollectStartingStylesFromRule`, `CollectScopesFromRule`  等函数负责从 CSS 规则中提取这些新特性的信息。

6. **填充祖先数据:** `FillAncestorData` 函数用于向上遍历 CSS 规则的父规则和父样式表，收集所有相关的 `@media`, `@supports`, `@container`, `@layer`, `@scope`, `@starting-style` 规则的信息，并添加到最终的 `protocol::CSS::CSSRule` 对象中。这使得 Inspector 可以展示规则的上下文信息。

7. **处理内联样式:**  `AsInspectorStyleSheet` 函数用于获取或创建与 DOM 元素的内联样式 (`style` 属性) 关联的 `InspectorStyleSheetForInlineStyle` 对象。

    * **与 HTML 的关系:** 内联样式直接在 HTML 元素的 `style` 属性中定义。

8. **收集所有样式表:** `CollectAllDocumentStyleSheets` 和 `CollectStyleSheets` 函数用于收集文档及其导入的样式表。

9. **绑定和管理 `InspectorStyleSheet`:** `BindStyleSheet` 函数用于将 Blink 引擎的 `CSSStyleSheet` 对象与 Inspector 的 `InspectorStyleSheet` 对象关联起来，并维护这些映射关系。

10. **检测样式表来源:** `DetectOrigin` 函数判断样式表的来源 (例如：用户代理样式表、注入的样式、正常的样式表等)。

**用户或编程常见的使用错误 (示例)：**

虽然这段代码本身不直接涉及用户的操作，但它处理的数据反映了用户在编写 CSS 时可能犯的错误，或者编程中对 CSS 操作不当的情况。

* **媒体查询语法错误:**  如果用户编写了错误的媒体查询语法 (例如 `(max-width: 600)` 而不是 `(max-width: 600px)`)，`BuildMediaObject` 在解析表达式时可能会遇到问题，虽然这段代码尝试处理这种情况 (例如，跳过非数字字面量值)，但最终 Inspector 可能无法正确展示或解释该媒体查询。
* **误用 `:focus-within`:** 开发者可能错误地认为 `:focus-within` 适用于所有场景，而没有考虑到焦点的实际传递和冒泡。这段代码的 `UpdateFocusWithinAncestors` 确保了 `:focus-within` 的行为符合规范，但开发者如果对其背后的逻辑不清楚，可能会在样式调试时感到困惑。
* **JavaScript 操作样式表的副作用:**  当 JavaScript 代码动态修改样式表时，例如添加或删除规则，`DidMutateStyleSheet` 会被触发，通知 Inspector 进行更新。如果 JavaScript 代码操作不当，可能会导致 Inspector 中展示的样式信息与实际渲染的样式不一致，从而误导开发者。

总而言之，这段代码是 Chromium 开发者工具中 CSS 相关功能的核心组成部分，它负责桥接 Blink 引擎的内部 CSS 表示和 Inspector 前端的显示需求。它处理了各种 CSS 特性，并提供了必要的元数据和结构，使得开发者能够有效地检查和调试网页的样式。

Prompt: 
```
这是目录为blink/renderer/core/inspector/inspector_css_agent.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能

"""
dom_agent_->BoundNodeId(&ancestor);
    if (!node_id)
      continue;
    NodeIdToNumberFocusedChildren::iterator it =
        node_id_to_number_focused_children_.find(node_id);
    unsigned count =
        it == node_id_to_number_focused_children_.end() ? 1 : it->value;
    if (count <= 1) {
      // If `count - 1` is zero or overflows, erase the node_id
      // from the map to save memory. If there is zero focused child
      // elements, :focus-within should not be forced.
      node_id_to_number_focused_children_.erase(node_id);
    } else {
      node_id_to_number_focused_children_.Set(node_id, count - 1);
    }
  }
}

std::unique_ptr<protocol::CSS::CSSMedia> InspectorCSSAgent::BuildMediaObject(
    const MediaList* media,
    MediaListSource media_list_source,
    const String& source_url,
    CSSStyleSheet* parent_style_sheet) {
  // Make certain compilers happy by initializing |source| up-front.
  String source = protocol::CSS::CSSMedia::SourceEnum::InlineSheet;
  switch (media_list_source) {
    case kMediaListSourceMediaRule:
      source = protocol::CSS::CSSMedia::SourceEnum::MediaRule;
      break;
    case kMediaListSourceImportRule:
      source = protocol::CSS::CSSMedia::SourceEnum::ImportRule;
      break;
    case kMediaListSourceLinkedSheet:
      source = protocol::CSS::CSSMedia::SourceEnum::LinkedSheet;
      break;
    case kMediaListSourceInlineSheet:
      source = protocol::CSS::CSSMedia::SourceEnum::InlineSheet;
      break;
  }

  const MediaQuerySet* queries = media->Queries();
  const HeapVector<Member<const MediaQuery>>& query_vector =
      queries->QueryVector();
  LocalFrame* frame = nullptr;
  if (parent_style_sheet) {
    if (Document* document = parent_style_sheet->OwnerDocument())
      frame = document->GetFrame();
  }
  MediaQueryEvaluator* media_evaluator =
      MakeGarbageCollected<MediaQueryEvaluator>(frame);

  InspectorStyleSheet* inspector_style_sheet = nullptr;
  if (parent_style_sheet) {
    auto it =
        css_style_sheet_to_inspector_style_sheet_.find(parent_style_sheet);
    if (it != css_style_sheet_to_inspector_style_sheet_.end())
      inspector_style_sheet = it->value;
  }

  auto media_list_array =
      std::make_unique<protocol::Array<protocol::CSS::MediaQuery>>();
  MediaValues* media_values = MediaValues::CreateDynamicIfFrameExists(frame);
  bool has_media_query_items = false;
  for (wtf_size_t i = 0; i < query_vector.size(); ++i) {
    const MediaQuery& query = *query_vector.at(i);
    HeapVector<MediaQueryExp> expressions;
    if (query.ExpNode())
      query.ExpNode()->CollectExpressions(expressions);
    auto expression_array = std::make_unique<
        protocol::Array<protocol::CSS::MediaQueryExpression>>();
    bool has_expression_items = false;
    for (wtf_size_t j = 0; j < expressions.size(); ++j) {
      const MediaQueryExp& media_query_exp = expressions.at(j);
      MediaQueryExpValue exp_value = media_query_exp.Bounds().right.value;
      if (!exp_value.IsNumericLiteralValue()) {
        continue;
      }
      const char* value_name =
          CSSPrimitiveValue::UnitTypeToString(exp_value.GetUnitType());
      std::unique_ptr<protocol::CSS::MediaQueryExpression>
          media_query_expression =
              protocol::CSS::MediaQueryExpression::create()
                  .setValue(exp_value.GetDoubleValue())
                  .setUnit(String(value_name))
                  .setFeature(media_query_exp.MediaFeature())
                  .build();

      if (inspector_style_sheet && media->ParentRule()) {
        media_query_expression->setValueRange(
            inspector_style_sheet->MediaQueryExpValueSourceRange(
                media->ParentRule(), i, j));
      }

      int computed_length;
      if (media_values->ComputeLength(exp_value.GetDoubleValue(),
                                      exp_value.GetUnitType(),
                                      computed_length)) {
        media_query_expression->setComputedLength(computed_length);
      }

      expression_array->emplace_back(std::move(media_query_expression));
      has_expression_items = true;
    }
    if (!has_expression_items)
      continue;
    std::unique_ptr<protocol::CSS::MediaQuery> media_query =
        protocol::CSS::MediaQuery::create()
            .setActive(media_evaluator->Eval(query))
            .setExpressions(std::move(expression_array))
            .build();
    media_list_array->emplace_back(std::move(media_query));
    has_media_query_items = true;
  }

  std::unique_ptr<protocol::CSS::CSSMedia> media_object =
      protocol::CSS::CSSMedia::create()
          .setText(media->MediaTextInternal())
          .setSource(source)
          .build();
  if (has_media_query_items)
    media_object->setMediaList(std::move(media_list_array));

  if (inspector_style_sheet && media_list_source != kMediaListSourceLinkedSheet)
    media_object->setStyleSheetId(inspector_style_sheet->Id());

  if (!source_url.empty()) {
    media_object->setSourceURL(source_url);

    CSSRule* parent_rule = media->ParentRule();
    if (!parent_rule)
      return media_object;
    inspector_style_sheet = BindStyleSheet(parent_rule->parentStyleSheet());
    media_object->setRange(
        inspector_style_sheet->RuleHeaderSourceRange(parent_rule));
  }
  return media_object;
}

void InspectorCSSAgent::CollectMediaQueriesFromStyleSheet(
    CSSStyleSheet* style_sheet,
    protocol::Array<protocol::CSS::CSSMedia>* media_array,
    protocol::Array<protocol::CSS::CSSRuleType>* rule_types) {
  MediaList* media_list = style_sheet->media();
  String source_url;
  if (media_list && media_list->length()) {
    Document* doc = style_sheet->OwnerDocument();
    if (doc)
      source_url = doc->Url();
    else if (!style_sheet->Contents()->BaseURL().IsEmpty())
      source_url = style_sheet->Contents()->BaseURL();
    else
      source_url = "";
    media_array->emplace_back(
        BuildMediaObject(media_list,
                         style_sheet->ownerNode() ? kMediaListSourceLinkedSheet
                                                  : kMediaListSourceInlineSheet,
                         source_url, style_sheet));
    if (rule_types) {
      rule_types->emplace_back(protocol::CSS::CSSRuleTypeEnum::MediaRule);
    }
  }
}

void InspectorCSSAgent::CollectMediaQueriesFromRule(
    CSSRule* rule,
    protocol::Array<protocol::CSS::CSSMedia>* media_array,
    protocol::Array<protocol::CSS::CSSRuleType>* rule_types) {
  MediaList* media_list;
  String source_url;
  CSSStyleSheet* parent_style_sheet = nullptr;
  bool is_media_rule = true;
  if (auto* media_rule = DynamicTo<CSSMediaRule>(rule)) {
    media_list = media_rule->media();
    parent_style_sheet = media_rule->parentStyleSheet();
  } else if (auto* import_rule = DynamicTo<CSSImportRule>(rule)) {
    media_list = import_rule->media();
    parent_style_sheet = import_rule->parentStyleSheet();
    is_media_rule = false;
  } else {
    media_list = nullptr;
  }

  if (parent_style_sheet) {
    source_url = parent_style_sheet->Contents()->BaseURL();
    if (source_url.empty())
      source_url = InspectorDOMAgent::DocumentURLString(
          parent_style_sheet->OwnerDocument());
  } else {
    source_url = "";
  }

  if (media_list && media_list->length()) {
    media_array->emplace_back(BuildMediaObject(
        media_list,
        is_media_rule ? kMediaListSourceMediaRule : kMediaListSourceImportRule,
        source_url, parent_style_sheet));
    if (rule_types) {
      rule_types->emplace_back(protocol::CSS::CSSRuleTypeEnum::MediaRule);
    }
  }
}

std::unique_ptr<protocol::CSS::CSSContainerQuery>
InspectorCSSAgent::BuildContainerQueryObject(CSSContainerRule* rule) {
  std::unique_ptr<protocol::CSS::CSSContainerQuery> container_query_object =
      protocol::CSS::CSSContainerQuery::create()
          .setText(rule->containerQuery())
          .build();

  auto it =
      css_style_sheet_to_inspector_style_sheet_.find(rule->parentStyleSheet());
  if (it != css_style_sheet_to_inspector_style_sheet_.end()) {
    InspectorStyleSheet* inspector_style_sheet = it->value;
    container_query_object->setStyleSheetId(inspector_style_sheet->Id());
  }

  InspectorStyleSheet* inspector_style_sheet =
      BindStyleSheet(rule->parentStyleSheet());
  container_query_object->setRange(
      inspector_style_sheet->RuleHeaderSourceRange(rule));

  if (!rule->Name().empty())
    container_query_object->setName(rule->Name());

  PhysicalAxes physical = rule->Selector().GetPhysicalAxes();
  if (physical != kPhysicalAxesNone) {
    protocol::DOM::PhysicalAxes physical_proto =
        protocol::DOM::PhysicalAxesEnum::Horizontal;
    if (physical == kPhysicalAxesVertical) {
      physical_proto = protocol::DOM::PhysicalAxesEnum::Vertical;
    } else if (physical == kPhysicalAxesBoth) {
      physical_proto = protocol::DOM::PhysicalAxesEnum::Both;
    } else {
      DCHECK(physical == kPhysicalAxesHorizontal);
    }
    container_query_object->setPhysicalAxes(physical_proto);
  }
  LogicalAxes logical = rule->Selector().GetLogicalAxes();
  if (logical != kLogicalAxesNone) {
    protocol::DOM::LogicalAxes logical_proto =
        protocol::DOM::LogicalAxesEnum::Inline;
    if (logical == kLogicalAxesBlock) {
      logical_proto = protocol::DOM::LogicalAxesEnum::Block;
    } else if (logical == kLogicalAxesBoth) {
      logical_proto = protocol::DOM::LogicalAxesEnum::Both;
    } else {
      DCHECK(logical == kLogicalAxesInline);
    }
    container_query_object->setLogicalAxes(logical_proto);
  }
  if (rule->Selector().SelectsScrollStateContainers()) {
    container_query_object->setQueriesScrollState(true);
  }
  return container_query_object;
}

void InspectorCSSAgent::CollectContainerQueriesFromRule(
    CSSRule* rule,
    protocol::Array<protocol::CSS::CSSContainerQuery>* container_queries,
    protocol::Array<protocol::CSS::CSSRuleType>* rule_types) {
  if (auto* container_rule = DynamicTo<CSSContainerRule>(rule)) {
    container_queries->emplace_back(BuildContainerQueryObject(container_rule));
    rule_types->emplace_back(protocol::CSS::CSSRuleTypeEnum::ContainerRule);
  }
}

std::unique_ptr<protocol::CSS::CSSSupports>
InspectorCSSAgent::BuildSupportsObject(CSSSupportsRule* rule) {
  std::unique_ptr<protocol::CSS::CSSSupports> supports_object =
      protocol::CSS::CSSSupports::create()
          .setText(rule->ConditionTextInternal())
          .setActive(rule->ConditionIsSupported())
          .build();

  auto it =
      css_style_sheet_to_inspector_style_sheet_.find(rule->parentStyleSheet());
  if (it != css_style_sheet_to_inspector_style_sheet_.end()) {
    InspectorStyleSheet* inspector_style_sheet = it->value;
    supports_object->setStyleSheetId(inspector_style_sheet->Id());
  }

  InspectorStyleSheet* inspector_style_sheet =
      BindStyleSheet(rule->parentStyleSheet());
  supports_object->setRange(inspector_style_sheet->RuleHeaderSourceRange(rule));

  return supports_object;
}

void InspectorCSSAgent::CollectSupportsFromRule(
    CSSRule* rule,
    protocol::Array<protocol::CSS::CSSSupports>* supports_list,
    protocol::Array<protocol::CSS::CSSRuleType>* rule_types) {
  if (auto* supports_rule = DynamicTo<CSSSupportsRule>(rule)) {
    supports_list->emplace_back(BuildSupportsObject(supports_rule));
    rule_types->emplace_back(protocol::CSS::CSSRuleTypeEnum::SupportsRule);
  }
}

std::unique_ptr<protocol::CSS::CSSLayer> InspectorCSSAgent::BuildLayerObject(
    CSSLayerBlockRule* rule) {
  std::unique_ptr<protocol::CSS::CSSLayer> layer_object =
      protocol::CSS::CSSLayer::create().setText(rule->name()).build();

  auto it =
      css_style_sheet_to_inspector_style_sheet_.find(rule->parentStyleSheet());
  if (it != css_style_sheet_to_inspector_style_sheet_.end()) {
    InspectorStyleSheet* inspector_style_sheet = it->value;
    layer_object->setStyleSheetId(inspector_style_sheet->Id());
  }

  InspectorStyleSheet* inspector_style_sheet =
      BindStyleSheet(rule->parentStyleSheet());
  layer_object->setRange(inspector_style_sheet->RuleHeaderSourceRange(rule));

  return layer_object;
}

std::unique_ptr<protocol::CSS::CSSLayer>
InspectorCSSAgent::BuildLayerObjectFromImport(CSSImportRule* rule) {
  std::unique_ptr<protocol::CSS::CSSLayer> layer_object =
      protocol::CSS::CSSLayer::create().setText(rule->layerName()).build();

  auto it =
      css_style_sheet_to_inspector_style_sheet_.find(rule->parentStyleSheet());
  if (it != css_style_sheet_to_inspector_style_sheet_.end()) {
    InspectorStyleSheet* inspector_style_sheet = it->value;
    layer_object->setStyleSheetId(inspector_style_sheet->Id());
  }

  InspectorStyleSheet* inspector_style_sheet =
      BindStyleSheet(rule->parentStyleSheet());
  layer_object->setRange(inspector_style_sheet->RuleHeaderSourceRange(rule));

  return layer_object;
}

void InspectorCSSAgent::CollectLayersFromRule(
    CSSRule* rule,
    protocol::Array<protocol::CSS::CSSLayer>* layers_list,
    protocol::Array<protocol::CSS::CSSRuleType>* rule_types) {
  if (auto* layer_rule = DynamicTo<CSSLayerBlockRule>(rule)) {
    layers_list->emplace_back(BuildLayerObject(layer_rule));
    rule_types->emplace_back(protocol::CSS::CSSRuleTypeEnum::LayerRule);
  } else if (auto* import_rule = DynamicTo<CSSImportRule>(rule)) {
    if (import_rule->layerName() != g_null_atom) {
      layers_list->emplace_back(BuildLayerObjectFromImport(import_rule));
      rule_types->emplace_back(protocol::CSS::CSSRuleTypeEnum::LayerRule);
    }
  }
}

std::unique_ptr<protocol::CSS::CSSStartingStyle>
InspectorCSSAgent::BuildStartingStyleObject(CSSStartingStyleRule* rule) {
  std::unique_ptr<protocol::CSS::CSSStartingStyle> starting_style_object =
      protocol::CSS::CSSStartingStyle::create().build();

  auto it =
      css_style_sheet_to_inspector_style_sheet_.find(rule->parentStyleSheet());
  if (it != css_style_sheet_to_inspector_style_sheet_.end()) {
    InspectorStyleSheet* inspector_style_sheet = it->value;
    starting_style_object->setStyleSheetId(inspector_style_sheet->Id());
  }

  InspectorStyleSheet* inspector_style_sheet =
      BindStyleSheet(rule->parentStyleSheet());
  starting_style_object->setRange(
      inspector_style_sheet->RuleHeaderSourceRange(rule));

  return starting_style_object;
}

void InspectorCSSAgent::CollectStartingStylesFromRule(
    CSSRule* rule,
    protocol::Array<protocol::CSS::CSSStartingStyle>* starting_style_list,
    protocol::Array<protocol::CSS::CSSRuleType>* rule_types) {
  if (auto* starting_style_rule = DynamicTo<CSSStartingStyleRule>(rule)) {
    starting_style_list->emplace_back(
        BuildStartingStyleObject(starting_style_rule));
    rule_types->emplace_back(protocol::CSS::CSSRuleTypeEnum::StartingStyleRule);
  }
}

void InspectorCSSAgent::FillAncestorData(CSSRule* rule,
                                         protocol::CSS::CSSRule* result) {
  auto layers_list =
      std::make_unique<protocol::Array<protocol::CSS::CSSLayer>>();
  auto media_list =
      std::make_unique<protocol::Array<protocol::CSS::CSSMedia>>();
  auto supports_list =
      std::make_unique<protocol::Array<protocol::CSS::CSSSupports>>();
  auto container_queries_list =
      std::make_unique<protocol::Array<protocol::CSS::CSSContainerQuery>>();
  auto scopes_list =
      std::make_unique<protocol::Array<protocol::CSS::CSSScope>>();
  auto rule_types_list =
      std::make_unique<protocol::Array<protocol::CSS::CSSRuleType>>();
  auto starting_style_list =
      std::make_unique<protocol::Array<protocol::CSS::CSSStartingStyle>>();

  CSSRule* parent_rule = rule;
  auto nesting_selectors = std::make_unique<protocol::Array<String>>();
  while (parent_rule) {
    CollectLayersFromRule(parent_rule, layers_list.get(),
                          rule_types_list.get());
    CollectMediaQueriesFromRule(parent_rule, media_list.get(),
                                rule_types_list.get());
    CollectContainerQueriesFromRule(parent_rule, container_queries_list.get(),
                                    rule_types_list.get());
    CollectSupportsFromRule(parent_rule, supports_list.get(),
                            rule_types_list.get());
    CollectScopesFromRule(parent_rule, scopes_list.get(),
                          rule_types_list.get());
    CollectStartingStylesFromRule(parent_rule, starting_style_list.get(),
                                  rule_types_list.get());

    if (parent_rule != rule) {
      if (auto* style_rule = DynamicTo<CSSStyleRule>(parent_rule)) {
        nesting_selectors->emplace_back(style_rule->selectorText());
        rule_types_list->emplace_back(
            protocol::CSS::CSSRuleTypeEnum::StyleRule);
      }
    }

    if (parent_rule->parentRule()) {
      parent_rule = parent_rule->parentRule();
    } else {
      CSSStyleSheet* style_sheet = parent_rule->parentStyleSheet();
      while (style_sheet) {
        CollectMediaQueriesFromStyleSheet(style_sheet, media_list.get(),
                                          rule_types_list.get());
        parent_rule = style_sheet->ownerRule();
        if (parent_rule)
          break;
        style_sheet = style_sheet->parentStyleSheet();
      }
    }
  }
  result->setMedia(std::move(media_list));
  result->setSupports(std::move(supports_list));
  result->setScopes(std::move(scopes_list));
  std::reverse(layers_list.get()->begin(), layers_list.get()->end());
  result->setLayers(std::move(layers_list));
  result->setContainerQueries(std::move(container_queries_list));
  result->setRuleTypes(std::move(rule_types_list));
  result->setStartingStyles(std::move(starting_style_list));
  if (nesting_selectors->size() > 0) {
    result->setNestingSelectors(std::move(nesting_selectors));
  }
}

std::unique_ptr<protocol::CSS::CSSScope> InspectorCSSAgent::BuildScopeObject(
    CSSScopeRule* rule) {
  std::unique_ptr<protocol::CSS::CSSScope> scope_object =
      protocol::CSS::CSSScope::create().setText(rule->PreludeText()).build();

  auto it =
      css_style_sheet_to_inspector_style_sheet_.find(rule->parentStyleSheet());
  if (it != css_style_sheet_to_inspector_style_sheet_.end()) {
    InspectorStyleSheet* inspector_style_sheet = it->value;
    scope_object->setStyleSheetId(inspector_style_sheet->Id());
  }

  InspectorStyleSheet* inspector_style_sheet =
      BindStyleSheet(rule->parentStyleSheet());
  scope_object->setRange(inspector_style_sheet->RuleHeaderSourceRange(rule));

  return scope_object;
}

void InspectorCSSAgent::CollectScopesFromRule(
    CSSRule* rule,
    protocol::Array<protocol::CSS::CSSScope>* scopes_list,
    protocol::Array<protocol::CSS::CSSRuleType>* rule_types) {
  if (auto* scope_rule = DynamicTo<CSSScopeRule>(rule)) {
    scopes_list->emplace_back(BuildScopeObject(scope_rule));
    rule_types->emplace_back(protocol::CSS::CSSRuleTypeEnum::ScopeRule);
  }
}

InspectorStyleSheetForInlineStyle* InspectorCSSAgent::AsInspectorStyleSheet(
    Element* element) {
  NodeToInspectorStyleSheet::iterator it =
      node_to_inspector_style_sheet_.find(element);
  if (it != node_to_inspector_style_sheet_.end())
    return it->value.Get();

  CSSStyleDeclaration* style = element->style();
  if (!style)
    return nullptr;

  InspectorStyleSheetForInlineStyle* inspector_style_sheet =
      MakeGarbageCollected<InspectorStyleSheetForInlineStyle>(element, this);
  id_to_inspector_style_sheet_for_inline_style_.Set(inspector_style_sheet->Id(),
                                                    inspector_style_sheet);
  node_to_inspector_style_sheet_.Set(element, inspector_style_sheet);
  return inspector_style_sheet;
}

// static
void InspectorCSSAgent::CollectAllDocumentStyleSheets(
    Document* document,
    HeapVector<Member<CSSStyleSheet>>& result) {
  for (const auto& style :
       document->GetStyleEngine().ActiveStyleSheetsForInspector())
    InspectorCSSAgent::CollectStyleSheets(style.first, result);
}

// static
void InspectorCSSAgent::CollectStyleSheets(
    CSSStyleSheet* style_sheet,
    HeapVector<Member<CSSStyleSheet>>& result) {
  result.push_back(style_sheet);
  for (unsigned i = 0, size = style_sheet->length(); i < size; ++i) {
    CSSRule* rule = style_sheet->ItemInternal(i);
    if (auto* import_rule = DynamicTo<CSSImportRule>(rule)) {
      CSSStyleSheet* imported_style_sheet = import_rule->styleSheet();
      if (imported_style_sheet)
        InspectorCSSAgent::CollectStyleSheets(imported_style_sheet, result);
    }
  }
}

InspectorStyleSheet* InspectorCSSAgent::BindStyleSheet(
    CSSStyleSheet* style_sheet) {
  auto it = css_style_sheet_to_inspector_style_sheet_.find(style_sheet);
  if (it != css_style_sheet_to_inspector_style_sheet_.end())
    return it->value;

  Document* document = style_sheet->OwnerDocument();
  InspectorStyleSheet* inspector_style_sheet =
      MakeGarbageCollected<InspectorStyleSheet>(
          network_agent_, style_sheet, DetectOrigin(style_sheet, document),
          InspectorDOMAgent::DocumentURLString(document), this,
          resource_container_);
  id_to_inspector_style_sheet_.Set(inspector_style_sheet->Id(),
                                   inspector_style_sheet);
  css_style_sheet_to_inspector_style_sheet_.Set(style_sheet,
                                                inspector_style_sheet);
  return inspector_style_sheet;
}

String InspectorCSSAgent::StyleSheetId(CSSStyleSheet* style_sheet) {
  return BindStyleSheet(style_sheet)->Id();
}

String InspectorCSSAgent::UnbindStyleSheet(
    InspectorStyleSheet* inspector_style_sheet) {
  String id = inspector_style_sheet->Id();
  id_to_inspector_style_sheet_.erase(id);
  if (inspector_style_sheet->PageStyleSheet())
    css_style_sheet_to_inspector_style_sheet_.erase(
        inspector_style_sheet->PageStyleSheet());
  return id;
}

InspectorStyleSheet* InspectorCSSAgent::InspectorStyleSheetForRule(
    CSSStyleRule* rule) {
  if (!rule)
    return nullptr;

  // CSSRules returned by StyleResolver::pseudoCSSRulesForElement lack parent
  // pointers if they are coming from user agent stylesheets. To work around
  // this issue, we use CSSOM wrapper created by inspector.
  if (!rule->parentStyleSheet()) {
    if (!inspector_user_agent_style_sheet_)
      inspector_user_agent_style_sheet_ = MakeGarbageCollected<CSSStyleSheet>(
          CSSDefaultStyleSheets::Instance().DefaultStyleSheet());
    rule->SetParentStyleSheet(inspector_user_agent_style_sheet_.Get());
  }
  return BindStyleSheet(rule->parentStyleSheet());
}

InspectorStyleSheet* InspectorCSSAgent::ViaInspectorStyleSheet(
    Document* document) {
  if (!document)
    return nullptr;

  if (!IsA<HTMLDocument>(document) && !document->IsSVGDocument())
    return nullptr;

  CSSStyleSheet& inspector_sheet =
      document->GetStyleEngine().EnsureInspectorStyleSheet();

  FlushPendingProtocolNotifications();

  auto it = css_style_sheet_to_inspector_style_sheet_.find(&inspector_sheet);
  return it != css_style_sheet_to_inspector_style_sheet_.end() ? it->value
                                                               : nullptr;
}

protocol::Response InspectorCSSAgent::AssertEnabled() {
  return enable_completed_
             ? protocol::Response::Success()
             : protocol::Response::ServerError("CSS agent was not enabled");
}

protocol::Response InspectorCSSAgent::AssertInspectorStyleSheetForId(
    const String& style_sheet_id,
    InspectorStyleSheet*& result) {
  protocol::Response response = AssertEnabled();
  if (!response.IsSuccess())
    return response;
  IdToInspectorStyleSheet::iterator it =
      id_to_inspector_style_sheet_.find(style_sheet_id);
  if (it == id_to_inspector_style_sheet_.end()) {
    return protocol::Response::ServerError(
        "No style sheet with given id found");
  }
  result = it->value.Get();
  return protocol::Response::Success();
}

protocol::Response InspectorCSSAgent::AssertStyleSheetForId(
    const String& style_sheet_id,
    InspectorStyleSheetBase*& result) {
  InspectorStyleSheet* style_sheet = nullptr;
  protocol::Response response =
      AssertInspectorStyleSheetForId(style_sheet_id, style_sheet);
  if (response.IsSuccess()) {
    result = style_sheet;
    return response;
  }
  IdToInspectorStyleSheetForInlineStyle::iterator it =
      id_to_inspector_style_sheet_for_inline_style_.find(style_sheet_id);
  if (it == id_to_inspector_style_sheet_for_inline_style_.end()) {
    return protocol::Response::ServerError(
        "No style sheet with given id found");
  }
  result = it->value.Get();
  return protocol::Response::Success();
}

protocol::CSS::StyleSheetOrigin InspectorCSSAgent::DetectOrigin(
    CSSStyleSheet* page_style_sheet,
    Document* owner_document) {
  DCHECK(page_style_sheet);

  if (!page_style_sheet->ownerNode() && page_style_sheet->href().empty() &&
      !page_style_sheet->IsConstructed())
    return protocol::CSS::StyleSheetOriginEnum::UserAgent;

  if (page_style_sheet->ownerNode() &&
      page_style_sheet->ownerNode()->IsDocumentNode()) {
    if (page_style_sheet ==
        owner_document->GetStyleEngine().InspectorStyleSheet())
      return protocol::CSS::StyleSheetOriginEnum::Inspector;
    return protocol::CSS::StyleSheetOriginEnum::Injected;
  }
  return protocol::CSS::StyleSheetOriginEnum::Regular;
}

std::unique_ptr<protocol::CSS::CSSRule> InspectorCSSAgent::BuildObjectForRule(
    CSSStyleRule* rule,
    Element* element,
    PseudoId pseudo_id,
    const AtomicString& pseudo_argument) {
  InspectorStyleSheet* inspector_style_sheet = InspectorStyleSheetForRule(rule);
  if (!inspector_style_sheet)
    return nullptr;

  std::unique_ptr<protocol::CSS::CSSRule> result =
      inspector_style_sheet->BuildObjectForRuleWithoutAncestorData(
          rule, element, pseudo_id, pseudo_argument);
  FillAncestorData(rule, result.get());
  return result;
}

std::unique_ptr<protocol::Array<protocol::CSS::RuleMatch>>
InspectorCSSAgent::BuildArrayForMatchedRuleList(
    RuleIndexList* rule_list,
    Element* element,
    const InspectorGhostRules& ghost_rules,
    PseudoId pseudo_id,
    const AtomicString& pseudo_argument) {
  auto result = std::make_unique<protocol::Array<protocol::CSS::RuleMatch>>();
  if (!rule_list)
    return result;

  // Dedupe matches coming from the same rule source.
  HeapVector<Member<CSSStyleRule>> uniq_rules;
  HeapHashSet<Member<CSSRule>> uniq_rules_set;
  HeapHashMap<Member<CSSStyleRule>, std::unique_ptr<Vector<unsigned>>>
      rule_indices;
  for (auto it = rule_list->rbegin(); it != rule_list->rend(); ++it) {
    CSSRule* rule = it->first;
    auto* style_rule = DynamicTo<CSSStyleRule>(rule);
    if (!style_rule)
      continue;
    if (!uniq_rules_set.Contains(rule)) {
      uniq_rules_set.insert(rule);
      uniq_rules.push_back(style_rule);
      rule_indices.Set(style_rule, std::make_unique<Vector<unsigned>>());
    }
    rule_indices.at(style_rule)->push_back(it->second);
  }

  for (auto it = uniq_rules.rbegin(); it != uniq_rules.rend(); ++it) {
    CSSStyleRule* rule = it->Get();
    std::unique_ptr<protocol::CSS::CSSRule> rule_object =
        BuildObjectForRule(rule, element, pseudo_id, pseudo_argument);
    if (!rule_object)
      continue;
    if (ghost_rules.Contains(rule)) {
      protocol::CSS::CSSStyle* style_object = rule_object->getStyle();
      if (!style_object || !style_object->getCssProperties() ||
          style_object->getCssProperties()->size() == 0) {
        // Skip empty ghost rules.
        continue;
      }
    }

    // Transform complex rule_indices into client-friendly, compound-basis for
    // matching_selectors.
    // e.g. ".foo + .bar, h1, body h1" for <h1>
    //  (complex): {.foo: 0, .bar: 1, h1: 2, body: 3, h1: 4}, matches: [2, 4]
    // (compound): {.foo: 0, .bar: 0, h1: 1, body: 2, h1: 2}, matches: [1, 2]
    auto matching_selectors = std::make_unique<protocol::Array<int>>();
    if (rule->GetStyleRule()) {
      // Compound index (0 -> 1 -> 2).
      int compound = 0;
      // Complex index of the next compound (0 -> 2 -> 3 -> kNotFound).
      wtf_size_t next_compound_start =
          rule->GetStyleRule()->IndexOfNextSelectorAfter(0);

      std::sort(rule_indices.at(rule)->begin(), rule_indices.at(rule)->end());
      for (unsigned complex_match : (*rule_indices.at(rule))) {
        while (complex_match >= next_compound_start &&
               next_compound_start != kNotFound) {
          next_compound_start = rule->GetStyleRule()->IndexOfNextSelectorAfter(
              next_compound_start);
          compound++;
        }
        matching_selectors->push_back(compound);
      }
    }

    result->emplace_back(
        protocol::CSS::RuleMatch::create()
            .setRule(std::move(rule_object))
            .setMatchingSelectors(std::move(matching_selectors))
            .build());
  }

  return result;
}

std::unique_ptr<protocol::CSS::CSSStyle>
InspectorCSSAgent::BuildObjectForAttributesStyle(Element* element) {
  if (!element->IsStyledElement())
    return nullptr;

  // FIXME: Ugliness below.
  auto* mutable_attribute_style = DynamicTo<MutableCSSPropertyValueSet>(
      const_cast<CSSPropertyValueSet*>(element->PresentationAttributeStyle()));
  if (!mutable_attribute_style)
    return nullptr;

  InspectorStyle* inspector_style = MakeGarbageCollected<InspectorStyle>(
      mutable_attribute_style->EnsureCSSStyleDeclaration(
          element->GetExecutionContext()),
      nullptr, nullptr);
  return inspector_style->BuildObjectForStyle();
}

void InspectorCSSAgent::DidAddDocument(Document* document) {
  if (!tracker_)
    return;

  document->GetStyleEngine().SetRuleUsageTracker(tracker_);
  document->GetStyleEngine().MarkAllElementsForStyleRecalc(
      StyleChangeReasonForTracing::Create(style_change_reason::kInspector));
}

void InspectorCSSAgent::WillRemoveDOMNode(Node* node) {
  DCHECK(node);

  int node_id = dom_agent_->BoundNodeId(node);
  DCHECK(node_id);
  node_id_to_forced_pseudo_state_.erase(node_id);
  computed_style_updated_node_ids_.erase(node_id);

  NodeToInspectorStyleSheet::iterator it =
      node_to_inspector_style_sheet_.find(node);
  if (it == node_to_inspector_style_sheet_.end())
    return;

  id_to_inspector_style_sheet_for_inline_style_.erase(it->value->Id());
  node_to_inspector_style_sheet_.erase(node);
}

void InspectorCSSAgent::DidModifyDOMAttr(Element* element) {
  if (!element)
    return;

  NodeToInspectorStyleSheet::iterator it =
      node_to_inspector_style_sheet_.find(element);
  if (it == node_to_inspector_style_sheet_.end())
    return;

  it->value->DidModifyElementAttribute();
}

void InspectorCSSAgent::DidMutateStyleSheet(CSSStyleSheet* css_style_sheet) {
  if (ignore_stylesheet_mutation_) {
    // The mutation comes from InspectorGhostRules. We don't care about these
    // mutations, because they'll be reverted when getMatchedStylesForNode
    // returns.
    return;
  }
  auto it = css_style_sheet_to_inspector_style_sheet_.find(css_style_sheet);
  if (it == css_style_sheet_to_inspector_style_sheet_.end())
    return;
  InspectorStyleSheet* style_sheet = it->value;
  style_sheet->MarkForSync();
  StyleSheetChanged(style_sheet);
}

void InspectorCSSAgent::GetTextPosition(wtf_size_t offset,
                                        const String* text,
                                        TextPosition* result) {
  std::unique_ptr<Vector<wtf_size_t>> line_endings = WTF::GetLineEndings(*text);
  *result = TextPosition::FromOffsetAndLineEndings(offset, *line_endings);
}

void InspectorCSSAgent::DidReplaceStyleSheetText(CSSStyleSheet* css_style_sheet,
                                                 const String& text) {
  BindStyleSheet(css_style_sheet)->CSSOMStyleSheetTextReplaced(text);
}

void InspectorCSSAgent::StyleSheetChanged(
    InspectorStyleSheetBase* style_sheet) {
  if (g_frontend_operation_counter)
    return;
  FlushPendingProtocolNotifications();
  GetFrontend()->styleSheetChanged(style_sheet->Id());
}

void InspectorCSSAgent::ResetPseudoStates() {
  HeapHashSet<Member<Document>> documents_to_change;
  for (auto& state : node_id_to_forced_pseudo_state_) {
    if (auto* element = To<Element>(dom_agent_->NodeForId(state.key)))
      documents_to_change.insert(&element->GetDocument());
  }

  for (auto& count : node_id_to_number_focused_children_) {
    if (auto* element = To<Element>(dom_agent_->NodeForId(count.key)))
      documents_to_change.insert(&element->GetDocument());
  }

  node_id_to_forced_pseudo_state_.clear();
  node_id_to_number_focused_children_.clear();
  for (auto& document : documents_to_change) {
    document->GetStyleEngine().MarkAllElementsForStyleRecalc(
        StyleChangeReasonForTracing::Create(style_change_reason::kInspector));
  }
}

HeapVector<Member<CSSStyleDeclaration>> InspectorCSSAgent::MatchingStyles(
    Element* element) {
  PseudoId pseudo_id = kPseudoIdNone;
 
"""


```