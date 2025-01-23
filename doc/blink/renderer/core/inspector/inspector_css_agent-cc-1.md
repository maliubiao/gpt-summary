Response:
The user wants a summary of the functionality of the provided C++ code snippet from the `InspectorCSSAgent` class in Chromium's Blink rendering engine. I need to identify the key actions performed by the methods in the snippet, focusing on how they relate to CSS inspection, JavaScript interaction (if any), and HTML structure. I should also look for logical reasoning, potential user errors, and how this section fits into the broader `InspectorCSSAgent` functionality.

Here's a breakdown of the code's functionality:

1. **`d(false)` and `return protocol::Response::Success();`**: This suggests a no-op or a successful completion of a previously initiated action. It likely belongs to a method that doesn't need to do anything when called in this particular context.

2. **`DidCommitLoadForLocalFrame(LocalFrame* frame)`**:  Resets the CSS agent's state when a new page is loaded in the main frame. This is crucial for ensuring correct information on each page load.

3. **`MediaQueryResultChanged()`**: Notifies the frontend (DevTools) about changes in media query results. This is essential for responsive design inspection.

4. **`FontsUpdated(...)`**:  Handles updates to font information. It extracts details like family, style, weight, stretch, display, and variation axes, then sends this information to the frontend. This is used to inspect font usage on the page.

5. **`ActiveStyleSheetsUpdated(Document* document)`**: Marks a document as having updated stylesheets, triggering a more thorough update later. This is an optimization to avoid redundant processing.

6. **`UpdateActiveStyleSheets(Document* document)`**:  Collects all stylesheets for a given document and then updates the internal state of the agent with these stylesheets.

7. **`SetActiveStyleSheets(...)`**:  This is a core method for managing the stylesheets associated with a document. It compares the current set of stylesheets with the new set, identifying added and removed stylesheets and notifying the frontend accordingly. This is fundamental to the "Styles" panel in DevTools.

8. **`DocumentDetached(Document* document)`**: Cleans up the agent's state when a document is removed from the DOM.

9. **`ForcePseudoState(...)`**:  Allows the DevTools to force the state of pseudo-classes (like `:hover`, `:focus`, etc.) on an element. This is crucial for debugging CSS styles under different interaction states.

10. **`getMediaQueries(...)`**:  Collects all media queries present in the stylesheets of the inspected page and sends them to the frontend.

11. **`BuildLayerDataObject(...)`**:  Recursively builds a data structure representing CSS cascade layers, including their order and sublayers.

12. **`getLayersForNode(...)`**:  Retrieves the cascade layers applicable to a specific node and sends this information to the frontend. This is used in the "Layers" panel in DevTools.

13. **`getLocationForSelector(...)`**:  Finds the source location (line and column) of a specific CSS selector within a given stylesheet. This is used to link styles in the DevTools back to their source code.

14. **`getMatchedStylesForNode(...)`**:  This is a very important method. It retrieves all the CSS rules that apply to a given node, including inline styles, attribute styles, matched rules, pseudo-element styles, inherited styles, keyframes, custom properties, and font palette values. This is the core functionality behind the "Styles" pane in DevTools.

15. **Helper functions related to finding specific types of CSS rules (`FindKeyframesRule`, `FindPositionTryRule`, `FindPropertyRule`, `FindFontPaletteValuesRule`)**: These functions are used to locate specific CSS rules within the stylesheet structure, likely to connect internal style representations with their CSSOM counterparts.

16. **`BuildObjectForPropertyRegistration(...)`**: Creates a frontend representation of a registered CSS property.

17. **`CustomPropertiesForNode(...)`**:  Gathers information about custom CSS properties (`--variable`) that apply to a given node, including both `@property` rules and properties registered via JavaScript.

18. **`FontPalettesForNode(...)`**:  Retrieves information about the font palettes applied to an element.

19. **`FindKeyframesRuleFromUAViewTransitionStylesheet(...)`**: Specifically looks for keyframes rules within the user-agent stylesheet related to view transitions.

20. **`FindCSSOMWrapperForKeyframesRule(...)`**:  Finds the CSSOM wrapper (the JavaScript object representing the CSS rule) for a given internal keyframes rule.

**Summary for Part 2:** This section of `InspectorCSSAgent` focuses on retrieving and managing CSS information for the DevTools frontend. Key functionalities include tracking stylesheets, handling font updates, allowing forced pseudo-states for inspection, gathering information about media queries and cascade layers, and crucially, providing detailed style information (matched rules, inherited styles, pseudo-element styles, etc.) for a specific DOM node. It also includes helper functions for finding specific types of CSS rules and handling custom properties and font palettes.

这是 `InspectorCSSAgent` 源代码文件的第 2 部分，主要功能是**提供和管理 CSS 信息的快照，以便在开发者工具中进行检查和调试。**  它负责跟踪页面中的样式表，并在样式发生变化时通知前端。此外，它还允许前端查询特定 DOM 节点的样式信息，包括匹配的规则、继承的样式、伪元素样式等。

以下是更详细的功能分解以及与 JavaScript、HTML、CSS 的关系和示例：

**核心功能：**

*   **跟踪和管理样式表:**
    *   `DidCommitLoadForLocalFrame`: 当主框架加载新页面时，会重置 CSS Agent 的状态，确保为新页面提供正确的样式信息。
        *   **与 HTML 关系:** 当用户导航到新的 HTML 页面时触发。
    *   `ActiveStyleSheetsUpdated`: 标记某个文档的样式表已更新，但尚未立即同步到前端。这是一种优化机制，可以批量处理样式更新。
        *   **与 CSS 关系:** 当 CSS 文件被修改、添加或删除时触发。
    *   `UpdateActiveStyleSheets`:  强制更新指定文档的活动样式表集合。
    *   `SetActiveStyleSheets`:  核心方法，负责比较当前文档的样式表和新的样式表，识别出新增和移除的样式表，并通知前端。
        *   **与 CSS 关系:**  当页面应用 CSS 样式时，此方法确保开发者工具能够反映最新的样式信息。
        *   **逻辑推理 (假设输入与输出):**
            *   **假设输入:**  页面加载完成，两个新的 `<style>` 标签被添加到 DOM 中。
            *   **输出:**  `SetActiveStyleSheets` 会检测到这两个新的样式表，并为每个样式表创建一个 `InspectorStyleSheet` 对象，然后通过 `GetFrontend()->styleSheetAdded()` 将样式表信息发送到开发者工具前端。
    *   `DocumentDetached`: 当文档从 DOM 中移除时，清理相关的样式表信息。
        *   **与 HTML 关系:** 当 `<iframe>` 被移除或页面卸载时触发。

*   **提供节点样式信息:**
    *   `getMatchedStylesForNode`:  这是最核心的方法之一，用于获取指定 DOM 节点的所有匹配样式信息。包括：
        *   内联样式 (`inline_style`)
        *   属性样式 (`attributes_style`)
        *   匹配的 CSS 规则 (`matched_css_rules`)
        *   伪元素匹配 (`pseudo_id_matches`)
        *   继承的样式 (`inherited_entries`)
        *   继承的伪元素匹配 (`inherited_pseudo_id_matches`)
        *   关键帧规则 (`css_keyframes_rules`)
        *   位置尝试规则 (`css_position_try_rules`)
        *   自定义属性规则 (`css_property_rules`)
        *   自定义属性注册 (`css_property_registrations`)
        *   字体调色板值规则 (`css_font_palette_values_rule`)
        *   父布局节点 ID (`parent_layout_node_id`)
        *   **与 HTML, CSS, JavaScript 关系:**
            *   **HTML:**  输入参数 `node_id` 指的是 HTML 元素。
            *   **CSS:**  返回的信息包含了应用于该元素的各种 CSS 规则和样式。
            *   **JavaScript:**  开发者工具前端通过 JavaScript 调用此方法来获取样式信息。例如，当用户在 Elements 面板中选择一个元素时。
        *   **逻辑推理 (假设输入与输出):**
            *   **假设输入:** 用户在 Elements 面板中选择了一个 `<div>` 元素，该元素有一个 CSS 类 `.container`，该类定义了 `background-color: red;`。
            *   **输出:** `getMatchedStylesForNode` 会返回一个包含 `.container` 规则的 `RuleMatch` 对象，其中包含了 `background-color: red;` 属性。
    *   辅助函数如 `FindKeyframesRule`, `FindPositionTryRule`, `FindPropertyRule`, `FindFontPaletteValuesRule` 等用于在样式表中查找特定类型的 CSS 规则。

*   **处理字体信息:**
    *   `FontsUpdated`:  当页面使用的字体发生变化时（例如，加载了新的 Web 字体），此方法会提取字体信息并发送到前端。
        *   **与 CSS 关系:**  与 `@font-face` 规则相关。
        *   **举例说明:** 当页面加载一个使用 `@font-face` 定义的新字体时，`FontsUpdated` 会提取字体的 `font-family`, `src`, `font-weight` 等信息，并将其传递给开发者工具，以便在 "Fonts" 面板中显示。

*   **模拟伪类状态:**
    *   `ForcePseudoState`:  允许开发者工具强制一个元素处于特定的伪类状态（如 `:hover`, `:focus`）。
        *   **与 CSS 关系:**  直接影响 CSS 伪类的应用。
        *   **举例说明:** 开发者可以使用此功能来查看一个按钮在 `:hover` 状态下的样式，即使鼠标没有悬停在该按钮上。

*   **获取媒体查询信息:**
    *   `MediaQueryResultChanged`:  通知前端媒体查询结果发生了变化。
        *   **与 CSS 关系:**  与 `@media` 规则相关。
    *   `getMediaQueries`:  获取页面中所有媒体查询的信息。
        *   **与 CSS 关系:**  遍历页面中的所有 `@media` 规则并提取其条件。

*   **获取 CSS 布局层叠信息:**
    *   `getLayersForNode`:  获取指定节点的 CSS 布局层叠信息，用于在开发者工具的 "Layers" 面板中显示。
        *   **与 CSS 关系:**  与 CSS 层叠上下文和 `z-index` 等属性相关。

*   **定位选择器源代码:**
    *   `getLocationForSelector`:  根据样式表 ID 和选择器文本，返回该选择器在源代码中的位置（行号和列号）。
        *   **与 CSS 关系:**  将开发者工具中显示的样式信息链接到 CSS 源代码。

*   **处理自定义 CSS 属性:**
    *   `CustomPropertiesForNode`:  获取应用于指定节点的自定义 CSS 属性 (`--*`) 的信息，包括通过 `@property` 规则定义的和通过 JavaScript 注册的。
        *   **与 CSS, JavaScript 关系:**
            *   **CSS:** 对应 `@property` 规则。
            *   **JavaScript:** 对应 `CSS.registerProperty()` 方法。
        *   **举例说明:** 如果一个组件使用了自定义属性 `--theme-color`，并且该属性通过 `@property` 定义了语法和初始值，`CustomPropertiesForNode` 会返回这些信息。

*   **处理字体调色板:**
    *   `FontPalettesForNode`: 获取应用于指定节点的字体调色板信息。
        *   **与 CSS 关系:** 对应 `font-palette` 属性和 `@font-palette-values` 规则。

**与 JavaScript, HTML, CSS 的关系举例:**

*   **JavaScript 修改样式:** 当 JavaScript 通过 `element.style.backgroundColor = 'blue'` 修改元素样式时，`ActiveStyleSheetsUpdated` 可能会被触发，然后 `getMatchedStylesForNode` 可以返回更新后的内联样式。
*   **HTML 结构变化:** 当新的 HTML 元素被添加到页面中时，如果该元素匹配了某些 CSS 规则，`getMatchedStylesForNode` 可以返回应用于该元素的样式信息。
*   **CSS 文件加载:** 当浏览器加载一个新的 CSS 文件时，`SetActiveStyleSheets` 会检测到新的样式表并将其信息发送到前端。

**逻辑推理举例:**

*   **假设输入:** 用户在 Styles 面板中勾选了一个 CSS 规则的复选框，禁用了该规则。
*   **输出:**  `InspectorCSSAgent` 会捕获这个操作，并通知渲染引擎重新计算样式。当开发者工具再次请求该节点的样式信息时，`getMatchedStylesForNode` 将不会包含被禁用的规则。

**用户或编程常见的使用错误举例:**

*   **前端请求了错误的 `style_sheet_id`:**  `getLocationForSelector` 和其他需要 `style_sheet_id` 的方法会返回错误，因为找不到对应的样式表。
*   **尝试在文档加载完成前获取样式信息:** 可能会导致获取到不完整的样式信息，因为所有的样式表可能尚未加载和解析。

**本部分功能归纳:**

总而言之，第 2 部分的 `InspectorCSSAgent` 代码专注于**收集、管理和提供 CSS 样式信息**，以便开发者工具能够向用户展示页面的样式结构和应用情况。它处理了样式表的生命周期管理，允许查询特定节点的详细样式信息，并支持模拟伪类状态和获取媒体查询等高级功能。这部分代码是开发者工具中 "Elements" 面板 "Styles" 部分的核心数据来源。

### 提示词
```
这是目录为blink/renderer/core/inspector/inspector_css_agent.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
d(false);
  return protocol::Response::Success();
}

void InspectorCSSAgent::DidCommitLoadForLocalFrame(LocalFrame* frame) {
  if (frame == inspected_frames_->Root())
    Reset();
}

void InspectorCSSAgent::MediaQueryResultChanged() {
  FlushPendingProtocolNotifications();
  GetFrontend()->mediaQueryResultChanged();
}

void InspectorCSSAgent::FontsUpdated(
    const FontFace* font,
    const String& src,
    const FontCustomPlatformData* fontCustomPlatformData) {
  FlushPendingProtocolNotifications();

  if (!(font && fontCustomPlatformData)) {
    GetFrontend()->fontsUpdated();
    return;
  }

  Vector<VariationAxis> variation_axis =
      fontCustomPlatformData->GetVariationAxes();

  auto variation_axes =
      std::make_unique<protocol::Array<protocol::CSS::FontVariationAxis>>();
  for (const VariationAxis& axis : variation_axis) {
    variation_axes->push_back(protocol::CSS::FontVariationAxis::create()
                                  .setMinValue(axis.minValue)
                                  .setMaxValue(axis.maxValue)
                                  .setDefaultValue(axis.defaultValue)
                                  .setName(axis.name)
                                  .setTag(axis.tag)
                                  .build());
  }

  // blink::FontFace returns sane property defaults per the web fonts spec,
  // so we don't perform null checks here.
  std::unique_ptr<protocol::CSS::FontFace> font_face =
      protocol::CSS::FontFace::create()
          .setFontFamily(font->family())
          .setFontStyle(font->style())
          .setFontVariant(font->variant())
          .setFontWeight(font->weight())
          .setFontStretch(font->stretch())
          .setFontDisplay(font->display())
          .setUnicodeRange(font->unicodeRange())
          .setSrc(src)
          .setPlatformFontFamily(
              fontCustomPlatformData->FamilyNameForInspector())
          .setFontVariationAxes(
              variation_axes->size() ? std::move(variation_axes) : nullptr)
          .build();
  GetFrontend()->fontsUpdated(std::move(font_face));
}

void InspectorCSSAgent::ActiveStyleSheetsUpdated(Document* document) {
  invalidated_documents_.insert(document);
}

void InspectorCSSAgent::UpdateActiveStyleSheets(Document* document) {
  HeapVector<Member<CSSStyleSheet>> new_sheets_vector;
  InspectorCSSAgent::CollectAllDocumentStyleSheets(document, new_sheets_vector);
  SetActiveStyleSheets(document, new_sheets_vector);
}

void InspectorCSSAgent::SetActiveStyleSheets(
    Document* document,
    const HeapVector<Member<CSSStyleSheet>>& all_sheets_vector) {
  auto it = document_to_css_style_sheets_.find(document);
  HeapHashSet<Member<CSSStyleSheet>>* document_css_style_sheets = nullptr;

  if (it != document_to_css_style_sheets_.end()) {
    document_css_style_sheets = it->value;
  } else {
    document_css_style_sheets =
        MakeGarbageCollected<HeapHashSet<Member<CSSStyleSheet>>>();
    document_to_css_style_sheets_.Set(document, document_css_style_sheets);
  }

  // Style engine sometimes returns the same stylesheet multiple
  // times, probably, because it's used in multiple places.
  // We need to deduplicate because the frontend does not expect
  // duplicate styleSheetAdded events.
  HeapHashSet<Member<CSSStyleSheet>> unique_sheets;
  for (CSSStyleSheet* css_style_sheet : all_sheets_vector) {
    if (!unique_sheets.Contains(css_style_sheet))
      unique_sheets.insert(css_style_sheet);
  }

  HeapHashSet<Member<CSSStyleSheet>> removed_sheets(*document_css_style_sheets);
  HeapVector<Member<CSSStyleSheet>> added_sheets;
  for (CSSStyleSheet* css_style_sheet : unique_sheets) {
    if (removed_sheets.Contains(css_style_sheet)) {
      removed_sheets.erase(css_style_sheet);
    } else {
      added_sheets.push_back(css_style_sheet);
    }
  }

  for (CSSStyleSheet* css_style_sheet : removed_sheets) {
    InspectorStyleSheet* inspector_style_sheet =
        css_style_sheet_to_inspector_style_sheet_.at(css_style_sheet);
    document_css_style_sheets->erase(css_style_sheet);
    if (id_to_inspector_style_sheet_.Contains(inspector_style_sheet->Id())) {
      String id = UnbindStyleSheet(inspector_style_sheet);
      if (GetFrontend())
        GetFrontend()->styleSheetRemoved(id);
    }
  }

  for (CSSStyleSheet* css_style_sheet : added_sheets) {
    InspectorStyleSheet* new_style_sheet = BindStyleSheet(css_style_sheet);
    document_css_style_sheets->insert(css_style_sheet);
    new_style_sheet->SyncTextIfNeeded();
    if (GetFrontend()) {
      GetFrontend()->styleSheetAdded(
          new_style_sheet->BuildObjectForStyleSheetInfo());
    }
  }

  if (document_css_style_sheets->empty())
    document_to_css_style_sheets_.erase(document);
}

void InspectorCSSAgent::DocumentDetached(Document* document) {
  invalidated_documents_.erase(document);
  SetActiveStyleSheets(document, HeapVector<Member<CSSStyleSheet>>());
}

void InspectorCSSAgent::ForcePseudoState(Element* element,
                                         CSSSelector::PseudoType pseudo_type,
                                         bool* result) {
  if (node_id_to_forced_pseudo_state_.empty())
    return;

  int node_id = dom_agent_->BoundNodeId(element);
  if (!node_id)
    return;

  // First check whether focus-within was set because focus or focus-within was
  // forced for a child node.
  NodeIdToNumberFocusedChildren::iterator focused_it =
      node_id_to_number_focused_children_.find(node_id);
  unsigned focused_count =
      focused_it == node_id_to_number_focused_children_.end()
          ? 0
          : focused_it->value;
  if (pseudo_type == CSSSelector::kPseudoFocusWithin && focused_count > 0) {
    *result = true;
    return;
  }

  NodeIdToForcedPseudoState::iterator it =
      node_id_to_forced_pseudo_state_.find(node_id);
  if (it == node_id_to_forced_pseudo_state_.end())
    return;

  bool force = false;
  unsigned forced_pseudo_state = it->value;

  switch (pseudo_type) {
    case CSSSelector::kPseudoActive:
      force = forced_pseudo_state & kPseudoActive;
      break;
    case CSSSelector::kPseudoFocus:
      force = forced_pseudo_state & kPseudoFocus;
      break;
    case CSSSelector::kPseudoFocusWithin:
      force = forced_pseudo_state & kPseudoFocusWithin;
      break;
    case CSSSelector::kPseudoFocusVisible:
      force = forced_pseudo_state & kPseudoFocusVisible;
      break;
    case CSSSelector::kPseudoHover:
      force = forced_pseudo_state & kPseudoHover;
      break;
    case CSSSelector::kPseudoTarget:
      force = forced_pseudo_state & kPseudoTarget;
      break;
    case CSSSelector::kPseudoEnabled:
      force = forced_pseudo_state & kPseudoEnabled;
      break;
    case CSSSelector::kPseudoDisabled:
      force = forced_pseudo_state & kPseudoDisabled;
      break;
    case CSSSelector::kPseudoValid:
      force = forced_pseudo_state & kPseudoValid;
      break;
    case CSSSelector::kPseudoInvalid:
      force = forced_pseudo_state & kPseudoInvalid;
      break;
    case CSSSelector::kPseudoUserValid:
      force = forced_pseudo_state & kPseudoUserValid;
      break;
    case CSSSelector::kPseudoUserInvalid:
      force = forced_pseudo_state & kPseudoUserInvalid;
      break;
    case CSSSelector::kPseudoRequired:
      force = forced_pseudo_state & kPseudoRequired;
      break;
    case CSSSelector::kPseudoOptional:
      force = forced_pseudo_state & kPseudoOptional;
      break;
    case CSSSelector::kPseudoReadOnly:
      force = forced_pseudo_state & kPseudoReadOnly;
      break;
    case CSSSelector::kPseudoReadWrite:
      force = forced_pseudo_state & kPseudoReadWrite;
      break;
    case CSSSelector::kPseudoInRange:
      force = forced_pseudo_state & kPseudoInRange;
      break;
    case CSSSelector::kPseudoOutOfRange:
      force = forced_pseudo_state & kPseudoOutOfRange;
      break;
    case CSSSelector::kPseudoVisited:
      force = forced_pseudo_state & kPseudoVisited;
      break;
    case CSSSelector::kPseudoLink:
      force = forced_pseudo_state & kPseudoLink;
      break;
    case CSSSelector::kPseudoChecked:
      force = forced_pseudo_state & kPseudoChecked;
      break;
    case CSSSelector::kPseudoIndeterminate:
      force = forced_pseudo_state & kPseudoIndeterminate;
      break;
    case CSSSelector::kPseudoPlaceholderShown:
      force = forced_pseudo_state & kPseudoPlaceholderShown;
      break;
    case CSSSelector::kPseudoAutofill:
      force = forced_pseudo_state & kPseudoAutofill;
      break;
    default:
      break;
  }
  if (force)
    *result = true;
}

protocol::Response InspectorCSSAgent::getMediaQueries(
    std::unique_ptr<protocol::Array<protocol::CSS::CSSMedia>>* medias) {
  *medias = std::make_unique<protocol::Array<protocol::CSS::CSSMedia>>();
  for (auto& style : id_to_inspector_style_sheet_) {
    InspectorStyleSheet* style_sheet = style.value;
    CollectMediaQueriesFromStyleSheet(style_sheet->PageStyleSheet(),
                                      medias->get(), nullptr);
    const CSSRuleVector& flat_rules = style_sheet->FlatRules();
    for (unsigned i = 0; i < flat_rules.size(); ++i) {
      CSSRule* rule = flat_rules.at(i).Get();
      if (rule->GetType() == CSSRule::kMediaRule ||
          rule->GetType() == CSSRule::kImportRule)
        CollectMediaQueriesFromRule(rule, medias->get(), nullptr);
    }
  }
  return protocol::Response::Success();
}

std::unique_ptr<protocol::CSS::CSSLayerData>
InspectorCSSAgent::BuildLayerDataObject(const CascadeLayer* layer,
                                        unsigned& max_order) {
  const unsigned order = layer->GetOrder().value_or(0);
  max_order = max(max_order, order);
  std::unique_ptr<protocol::CSS::CSSLayerData> layer_data =
      protocol::CSS::CSSLayerData::create()
          .setName(layer->GetName())
          .setOrder(order)
          .build();
  const auto& sublayers = layer->GetDirectSubLayers();
  if (sublayers.empty())
    return layer_data;

  auto sublayers_data =
      std::make_unique<protocol::Array<protocol::CSS::CSSLayerData>>();
  for (const CascadeLayer* sublayer : sublayers)
    sublayers_data->emplace_back(BuildLayerDataObject(sublayer, max_order));
  layer_data->setSubLayers(std::move(sublayers_data));
  return layer_data;
}

protocol::Response InspectorCSSAgent::getLayersForNode(
    int node_id,
    std::unique_ptr<protocol::CSS::CSSLayerData>* root_layer) {
  Element* element = nullptr;
  const protocol::Response response =
      dom_agent_->AssertElement(node_id, element);
  if (!response.IsSuccess())
    return response;

  *root_layer = protocol::CSS::CSSLayerData::create()
                    .setName("implicit outer layer")
                    .setOrder(0)
                    .build();

  const auto* scoped_resolver =
      element->GetTreeScope().GetScopedStyleResolver();
  // GetScopedStyleResolver returns a nullptr if the tree scope has no
  // stylesheets.
  if (!scoped_resolver)
    return protocol::Response::Success();

  const CascadeLayerMap* layer_map = scoped_resolver->GetCascadeLayerMap();

  if (!layer_map)
    return protocol::Response::Success();

  const CascadeLayer* root = layer_map->GetRootLayer();
  unsigned max_order = 0;
  auto sublayers_data =
      std::make_unique<protocol::Array<protocol::CSS::CSSLayerData>>();
  for (const auto& sublayer : root->GetDirectSubLayers())
    sublayers_data->emplace_back(BuildLayerDataObject(sublayer, max_order));
  (*root_layer)->setOrder(max_order + 1);
  (*root_layer)->setSubLayers(std::move(sublayers_data));

  return protocol::Response::Success();
}

protocol::Response InspectorCSSAgent::getLocationForSelector(
    const String& style_sheet_id,
    const String& selector_text,
    std::unique_ptr<protocol::Array<protocol::CSS::SourceRange>>* ranges) {
  InspectorStyleSheet* style_sheet = nullptr;
  protocol::Response response =
      AssertInspectorStyleSheetForId(style_sheet_id, style_sheet);
  if (response.IsError()) {
    return response;
  }

  *ranges = std::make_unique<protocol::Array<protocol::CSS::SourceRange>>();

  const CSSRuleVector& css_rules = style_sheet->FlatRules();
  for (auto css_rule : css_rules) {
    CSSStyleRule* css_style_rule = DynamicTo<CSSStyleRule>(css_rule.Get());
    if (css_style_rule == nullptr) {
      continue;
    }
    CHECK(css_style_rule->GetStyleRule());

    // Iterate over selector list. (eg. `.box, .alert` => ['.box', '.alert'])
    for (const CSSSelector* selector =
             css_style_rule->GetStyleRule()->FirstSelector();
         selector; selector = CSSSelectorList::Next(*selector)) {
      if (selector->SelectorText() == selector_text) {
        const CSSRuleSourceData* source_data =
            style_sheet->SourceDataForRule(css_style_rule);
        if (source_data == nullptr) {
          continue;
        }
        std::unique_ptr<protocol::CSS::SourceRange> range =
            style_sheet->BuildSourceRangeObject(source_data->rule_header_range);

        const CSSStyleSheet* page_style_sheet = style_sheet->PageStyleSheet();
        const TextPosition start_position =
            page_style_sheet->StartPositionInSource();
        if (range->getStartLine() == 0) {
          range->setStartColumn(range->getStartColumn() +
                                start_position.column_.ZeroBasedInt());
        }
        if (range->getEndLine() == 0) {
          range->setEndColumn(range->getEndColumn() +
                              start_position.column_.ZeroBasedInt());
        }
        range->setStartLine(range->getStartLine() +
                            start_position.line_.ZeroBasedInt());
        range->setEndLine(range->getEndLine() +
                          start_position.line_.ZeroBasedInt());
        (*ranges)->emplace_back(std::move(range));
      }
    }
  }

  if ((*ranges)->empty()) {
    String message = "Failed to find selector '" + selector_text +
                     "' in style sheet " + style_sheet->FinalURL();
    return protocol::Response::InvalidParams(message.Utf8());
  }

  return protocol::Response::Success();
}

protocol::Response InspectorCSSAgent::getMatchedStylesForNode(
    int node_id,
    Maybe<protocol::CSS::CSSStyle>* inline_style,
    Maybe<protocol::CSS::CSSStyle>* attributes_style,
    Maybe<protocol::Array<protocol::CSS::RuleMatch>>* matched_css_rules,
    Maybe<protocol::Array<protocol::CSS::PseudoElementMatches>>*
        pseudo_id_matches,
    Maybe<protocol::Array<protocol::CSS::InheritedStyleEntry>>*
        inherited_entries,
    Maybe<protocol::Array<protocol::CSS::InheritedPseudoElementMatches>>*
        inherited_pseudo_id_matches,
    Maybe<protocol::Array<protocol::CSS::CSSKeyframesRule>>*
        css_keyframes_rules,
    Maybe<protocol::Array<protocol::CSS::CSSPositionTryRule>>*
        css_position_try_rules,
    Maybe<int>* active_position_fallback_index,
    Maybe<protocol::Array<protocol::CSS::CSSPropertyRule>>* css_property_rules,
    Maybe<protocol::Array<protocol::CSS::CSSPropertyRegistration>>*
        css_property_registrations,
    Maybe<protocol::CSS::CSSFontPaletteValuesRule>*
        css_font_palette_values_rule,
    Maybe<int>* parent_layout_node_id) {
  protocol::Response response = AssertEnabled();
  if (!response.IsSuccess())
    return response;

  Element* element = nullptr;
  response = dom_agent_->AssertElement(node_id, element);
  if (!response.IsSuccess())
    return response;

  Element* animating_element = element;

  PseudoId element_pseudo_id = kPseudoIdNone;
  AtomicString view_transition_name = g_null_atom;
  // If the requested element is a pseudo element, `element` becomes
  // the first non-pseudo parent element or shadow host element
  // after `GetPseudoIdAndTag` call below.
  element = GetPseudoIdAndTag(element, element_pseudo_id, view_transition_name);
  if (!element)
    return protocol::Response::ServerError("Pseudo element has no parent");

  Document& document = element->GetDocument();
  // A non-active document has no styles.
  if (!document.IsActive())
    return protocol::Response::ServerError("Document is not active");

  base::AutoReset<bool> ignore_mutation(&ignore_stylesheet_mutation_, true);
  InspectorGhostRules ghost_rules;

  // The source text of mutable stylesheets needs to be updated
  // to sync the latest changes.
  for (InspectorStyleSheet* stylesheet :
       css_style_sheet_to_inspector_style_sheet_.Values()) {
    stylesheet->SyncTextIfNeeded();
    ghost_rules.Populate(*stylesheet->PageStyleSheet());
  }

  CheckPseudoHasCacheScope check_pseudo_has_cache_scope(
      &document, /*within_selector_checking=*/false);
  InspectorStyleResolver resolver(element, element_pseudo_id,
                                  view_transition_name);

  // Matched rules.
  *matched_css_rules = BuildArrayForMatchedRuleList(
      resolver.MatchedRules(), element, ghost_rules, element_pseudo_id,
      view_transition_name);

  // Inherited styles.
  *inherited_entries =
      std::make_unique<protocol::Array<protocol::CSS::InheritedStyleEntry>>();
  for (InspectorCSSMatchedRules* match : resolver.ParentRules()) {
    std::unique_ptr<protocol::CSS::InheritedStyleEntry> entry =
        protocol::CSS::InheritedStyleEntry::create()
            .setMatchedCSSRules(BuildArrayForMatchedRuleList(
                match->matched_rules, element, ghost_rules, element_pseudo_id,
                view_transition_name))
            .build();
    if (match->element->style() && match->element->style()->length()) {
      InspectorStyleSheetForInlineStyle* style_sheet =
          AsInspectorStyleSheet(match->element);
      if (style_sheet) {
        entry->setInlineStyle(style_sheet->BuildObjectForStyle(
            style_sheet->InlineStyle(), element, element_pseudo_id,
            view_transition_name));
      }
    }
    (*inherited_entries)->emplace_back(std::move(entry));
  }

  *css_keyframes_rules = AnimationsForNode(element, animating_element);

  std::tie(*css_property_rules, *css_property_registrations) =
      CustomPropertiesForNode(element);

  // Pseudo elements.
  if (element_pseudo_id)
    return protocol::Response::Success();

  InspectorStyleSheetForInlineStyle* inline_style_sheet =
      AsInspectorStyleSheet(element);
  if (inline_style_sheet) {
    *inline_style =
        inline_style_sheet->BuildObjectForStyle(element->style(), element);
    *attributes_style = BuildObjectForAttributesStyle(element);
  }

  *pseudo_id_matches =
      std::make_unique<protocol::Array<protocol::CSS::PseudoElementMatches>>();

  for (InspectorCSSMatchedRules* match : resolver.PseudoElementRules()) {
    (*pseudo_id_matches)
        ->emplace_back(
            protocol::CSS::PseudoElementMatches::create()
                .setPseudoType(InspectorDOMAgent::ProtocolPseudoElementType(
                    match->pseudo_id))
                .setMatches(BuildArrayForMatchedRuleList(
                    match->matched_rules, element, ghost_rules,
                    match->pseudo_id, match->view_transition_name))
                .build());
    if (match->view_transition_name) {
      (*pseudo_id_matches)
          ->back()
          ->setPseudoIdentifier(match->view_transition_name);
    }
  }

  *inherited_pseudo_id_matches = std::make_unique<
      protocol::Array<protocol::CSS::InheritedPseudoElementMatches>>();

  for (InspectorCSSMatchedPseudoElements* match :
       resolver.ParentPseudoElementRules()) {
    auto parent_pseudo_element_matches = std::make_unique<
        protocol::Array<protocol::CSS::PseudoElementMatches>>();
    for (InspectorCSSMatchedRules* pseudo_match : match->pseudo_element_rules) {
      parent_pseudo_element_matches->emplace_back(
          protocol::CSS::PseudoElementMatches::create()
              .setPseudoType(InspectorDOMAgent::ProtocolPseudoElementType(
                  pseudo_match->pseudo_id))
              .setMatches(BuildArrayForMatchedRuleList(
                  pseudo_match->matched_rules, element, ghost_rules))
              .build());
      if (pseudo_match->view_transition_name) {
        parent_pseudo_element_matches->back()->setPseudoIdentifier(
            pseudo_match->view_transition_name);
      }
    }

    std::unique_ptr<protocol::CSS::InheritedPseudoElementMatches>
        inherited_pseudo_element_matches =
            protocol::CSS::InheritedPseudoElementMatches::create()
                .setPseudoElements(std::move(parent_pseudo_element_matches))
                .build();

    (*inherited_pseudo_id_matches)
        ->emplace_back(std::move(inherited_pseudo_element_matches));
  }

  // Get the index of the active position try fallback index.
  std::optional<size_t> successful_position_fallback_index;
  if (OutOfFlowData* out_of_flow_data = element->GetOutOfFlowData()) {
    successful_position_fallback_index =
        out_of_flow_data->GetNewSuccessfulPositionFallbackIndex();
    if (successful_position_fallback_index.has_value()) {
      *active_position_fallback_index =
          static_cast<int>(successful_position_fallback_index.value());
    }
  }
  *css_position_try_rules =
      PositionTryRulesForElement(element, successful_position_fallback_index);

  if (auto rule = FontPalettesForNode(*element)) {
    *css_font_palette_values_rule = std::move(rule);
  }

  auto* parent_layout_node = LayoutTreeBuilderTraversal::LayoutParent(*element);
  if (parent_layout_node) {
    if (int bound_node_id = dom_agent_->BoundNodeId(parent_layout_node)) {
      *parent_layout_node_id = bound_node_id;
    }
  }

  return protocol::Response::Success();
}

template <class CSSRuleCollection>
static CSSKeyframesRule* FindKeyframesRule(CSSRuleCollection* css_rules,
                                           StyleRuleKeyframes* keyframes_rule) {
  if (!css_rules) {
    return nullptr;
  }

  CSSKeyframesRule* result = nullptr;
  for (unsigned j = 0; j < css_rules->length() && !result; ++j) {
    CSSRule* css_rule = css_rules->item(j);
    if (auto* css_style_rule = DynamicTo<CSSKeyframesRule>(css_rule)) {
      if (css_style_rule->Keyframes() == keyframes_rule)
        result = css_style_rule;
    } else if (auto* css_import_rule = DynamicTo<CSSImportRule>(css_rule)) {
      result = FindKeyframesRule(css_import_rule->styleSheet(), keyframes_rule);
    } else {
      result = FindKeyframesRule(css_rule->cssRules(), keyframes_rule);
    }
  }
  return result;
}

template <class CSSRuleCollection>
static CSSPositionTryRule* FindPositionTryRule(
    CSSRuleCollection* css_rules,
    StyleRulePositionTry* position_try_rule) {
  if (!css_rules) {
    return nullptr;
  }

  CSSPositionTryRule* result = nullptr;
  for (unsigned i = 0; i < css_rules->length() && !result; ++i) {
    CSSRule* css_rule = css_rules->item(i);
    if (auto* css_style_rule = DynamicTo<CSSPositionTryRule>(css_rule)) {
      if (css_style_rule->PositionTry() == position_try_rule) {
        result = css_style_rule;
      }
    } else if (auto* css_import_rule = DynamicTo<CSSImportRule>(css_rule)) {
      result =
          FindPositionTryRule(css_import_rule->styleSheet(), position_try_rule);
    } else {
      result = FindPositionTryRule(css_rule->cssRules(), position_try_rule);
    }
  }
  return result;
}

std::unique_ptr<protocol::Array<protocol::CSS::CSSPositionTryRule>>
InspectorCSSAgent::PositionTryRulesForElement(
    Element* element,
    std::optional<size_t> active_position_try_index) {
  Document& document = element->GetDocument();
  CHECK(!document.NeedsLayoutTreeUpdateForNode(*element));

  const ComputedStyle* style = element->EnsureComputedStyle();
  if (!style) {
    return nullptr;
  }

  const PositionTryFallbacks* position_try_fallbacks_ =
      style->GetPositionTryFallbacks();
  if (!position_try_fallbacks_) {
    return nullptr;
  }

  auto css_position_try_rules =
      std::make_unique<protocol::Array<protocol::CSS::CSSPositionTryRule>>();
  StyleResolver& style_resolver = document.GetStyleResolver();
  const HeapVector<PositionTryFallback>& fallbacks =
      position_try_fallbacks_->GetFallbacks();
  for (wtf_size_t i = 0; i < fallbacks.size(); ++i) {
    const PositionTryFallback& fallback = fallbacks[i];
    if (const ScopedCSSName* scoped_name = fallback.GetPositionTryName()) {
      const TreeScope* tree_scope = scoped_name->GetTreeScope();
      if (!tree_scope) {
        tree_scope = &document;
      }
      StyleRulePositionTry* position_try_rule =
          style_resolver.ResolvePositionTryRule(tree_scope,
                                                scoped_name->GetName());
      if (!position_try_rule) {
        continue;
      }
      // Find CSSOM wrapper from internal Style rule.
      DocumentStyleSheets::iterator css_style_sheets_for_document_it =
          document_to_css_style_sheets_.find(&document);
      if (css_style_sheets_for_document_it ==
          document_to_css_style_sheets_.end()) {
        continue;
      }
      bool is_active = active_position_try_index.has_value() &&
                       active_position_try_index.value() == i;
      for (CSSStyleSheet* style_sheet :
           *css_style_sheets_for_document_it->value) {
        if (CSSPositionTryRule* css_position_try_rule =
                FindPositionTryRule(style_sheet, position_try_rule)) {
          InspectorStyleSheet* inspector_style_sheet =
              BindStyleSheet(css_position_try_rule->parentStyleSheet());
          css_position_try_rules->emplace_back(
              inspector_style_sheet->BuildObjectForPositionTryRule(
                  css_position_try_rule, is_active));
          break;
        }
      }
    }
  }
  return css_position_try_rules;
}

template <class CSSRuleCollection>
static CSSPropertyRule* FindPropertyRule(CSSRuleCollection* css_rules,
                                         StyleRuleProperty* property_rule) {
  if (!css_rules) {
    return nullptr;
  }

  CSSPropertyRule* result = nullptr;
  for (unsigned j = 0; j < css_rules->length() && !result; ++j) {
    CSSRule* css_rule = css_rules->item(j);
    if (auto* css_style_rule = DynamicTo<CSSPropertyRule>(css_rule)) {
      if (css_style_rule->Property() == property_rule)
        result = css_style_rule;
    } else if (auto* css_import_rule = DynamicTo<CSSImportRule>(css_rule)) {
      result = FindPropertyRule(css_import_rule->styleSheet(), property_rule);
    } else {
      result = FindPropertyRule(css_rule->cssRules(), property_rule);
    }
  }
  return result;
}

std::unique_ptr<protocol::CSS::CSSPropertyRegistration>
BuildObjectForPropertyRegistration(const AtomicString& name,
                                   const PropertyRegistration& registration) {
  auto css_property_registration =
      protocol::CSS::CSSPropertyRegistration::create()
          .setPropertyName(name)
          .setInherits(registration.Inherits())
          .setSyntax(registration.Syntax().ToString())
          .build();
  if (registration.Initial()) {
    css_property_registration->setInitialValue(
        protocol::CSS::Value::create()
            .setText(registration.Initial()->CssText())
            .build());
  }
  return css_property_registration;
}

std::pair<
    std::unique_ptr<protocol::Array<protocol::CSS::CSSPropertyRule>>,
    std::unique_ptr<protocol::Array<protocol::CSS::CSSPropertyRegistration>>>
InspectorCSSAgent::CustomPropertiesForNode(Element* element) {
  auto result = std::make_pair(
      std::make_unique<protocol::Array<protocol::CSS::CSSPropertyRule>>(),
      std::make_unique<
          protocol::Array<protocol::CSS::CSSPropertyRegistration>>());
  Document& document = element->GetDocument();
  DCHECK(!document.NeedsLayoutTreeUpdateForNode(*element));

  const ComputedStyle* style = element->EnsureComputedStyle();
  if (!style /*|| !style->HasVariableReference()*/)
    return result;

  for (const AtomicString& var_name : style->GetVariableNames()) {
    const auto* registration =
        PropertyRegistration::From(document.GetExecutionContext(), var_name);
    if (!registration) {
      continue;
    }

    if (StyleRuleProperty* rule = registration->PropertyRule()) {
      // Find CSSOM wrapper.
      CSSPropertyRule* property_rule = nullptr;
      for (CSSStyleSheet* style_sheet :
           *document_to_css_style_sheets_.at(&document)) {
        property_rule = FindPropertyRule(style_sheet, rule);
        if (property_rule)
          break;
      }
      if (property_rule) {
        // @property
        InspectorStyleSheet* inspector_style_sheet =
            BindStyleSheet(property_rule->parentStyleSheet());
        result.first->push_back(
            inspector_style_sheet->BuildObjectForPropertyRule(property_rule));
      }
      // If the property_rule wasn't found, just ignore ignore it.
    } else {
      // CSS.registerProperty
      result.second->push_back(
          BuildObjectForPropertyRegistration(var_name, *registration));
    }
  }

  return result;
}

template <class CSSRuleCollection>
static CSSFontPaletteValuesRule* FindFontPaletteValuesRule(
    CSSRuleCollection* css_rules,
    StyleRuleFontPaletteValues* values_rule) {
  if (!css_rules) {
    return nullptr;
  }

  CSSFontPaletteValuesRule* result = nullptr;
  for (unsigned j = 0; j < css_rules->length() && !result; ++j) {
    CSSRule* css_rule = css_rules->item(j);
    if (auto* css_style_rule = DynamicTo<CSSFontPaletteValuesRule>(css_rule)) {
      if (css_style_rule->FontPaletteValues() == values_rule)
        result = css_style_rule;
    } else if (auto* css_import_rule = DynamicTo<CSSImportRule>(css_rule)) {
      result =
          FindFontPaletteValuesRule(css_import_rule->styleSheet(), values_rule);
    } else {
      result = FindFontPaletteValuesRule(css_rule->cssRules(), values_rule);
    }
  }
  return result;
}

std::unique_ptr<protocol::CSS::CSSFontPaletteValuesRule>
InspectorCSSAgent::FontPalettesForNode(Element& element) {
  const ComputedStyle* style = element.EnsureComputedStyle();
  const FontPalette* palette = style ? style->GetFontPalette() : nullptr;
  if (!palette || !palette->IsCustomPalette()) {
    return {};
  }
  Document& document = element.GetDocument();
  StyleRuleFontPaletteValues* rule =
      document.GetStyleEngine().FontPaletteValuesForNameAndFamily(
          palette->GetPaletteValuesName(),
          style->GetFontDescription().Family().FamilyName());
  if (!rule) {
    return {};
  }

  // Find CSSOM wrapper.
  CSSFontPaletteValuesRule* values_rule = nullptr;
  for (CSSStyleSheet* style_sheet :
       *document_to_css_style_sheets_.at(&document)) {
    values_rule = FindFontPaletteValuesRule(style_sheet, rule);
    if (values_rule)
      break;
  }

  InspectorStyleSheet* inspector_style_sheet =
      BindStyleSheet(values_rule->parentStyleSheet());
  return inspector_style_sheet->BuildObjectForFontPaletteValuesRule(
      values_rule);
}

CSSKeyframesRule*
InspectorCSSAgent::FindKeyframesRuleFromUAViewTransitionStylesheet(
    Element* element,
    StyleRuleKeyframes* keyframes_style_rule) {
  // This function should only be called for transition pseudo elements.
  CHECK(IsTransitionPseudoElement(element->GetPseudoId()));
  auto* transition = ViewTransitionUtils::GetTransition(element->GetDocument());

  // There must be a transition and an active UAStyleSheet for the
  // transition when the queried element is a transition pseudo element.
  CHECK(transition && transition->UAStyleSheet());

  if (!user_agent_view_transition_style_sheet_) {
    // Save the previous view transition style sheet.
    user_agent_view_transition_style_sheet_ = transition->UAStyleSheet();
  } else if (user_agent_view_transition_style_sheet_ !=
             transition->UAStyleSheet()) {
    // If the view transition stylesheet is invalidated
    // unbind the previous inspector stylesheet.
    user_agent_view_transition_style_sheet_ = transition->UAStyleSheet();
    auto previous_css_style_sheet_it =
        css_style_sheet_to_inspector_style_sheet_.find(
            user_agent_view_transition_style_sheet_);
    if (previous_css_style_sheet_it !=
        css_style_sheet_to_inspector_style_sheet_.end()) {
      UnbindStyleSheet(previous_css_style_sheet_it->value);
    }
  }

  for (wtf_size_t i = 0; i < user_agent_view_transition_style_sheet_->length();
       i++) {
    CSSKeyframesRule* css_keyframes_rule_from_stylesheet =
        DynamicTo<CSSKeyframesRule>(
            user_agent_view_transition_style_sheet_->ItemInternal(i));
    if (css_keyframes_rule_from_stylesheet &&
        css_keyframes_rule_from_stylesheet->name() ==
            keyframes_style_rule->GetName()) {
      return css_keyframes_rule_from_stylesheet;
    }
  }

  return nullptr;
}

CSSKeyframesRule* InspectorCSSAgent::FindCSSOMWrapperForKeyframesRule(
    Element* element,
    StyleRuleKeyframes* keyframes_style_rule) {
  Document& document = element->
```