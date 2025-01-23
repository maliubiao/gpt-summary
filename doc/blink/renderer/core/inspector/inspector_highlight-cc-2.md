Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from `inspector_highlight.cc`. Specifically, they want to understand:

1. **Overall Function:** What does this code do?
2. **Relationship to Web Technologies:** How does it relate to JavaScript, HTML, and CSS? Provide examples.
3. **Logical Reasoning:**  Illustrate the code's logic with hypothetical inputs and outputs.
4. **Common Errors:**  Point out potential mistakes users or programmers might make when using this functionality.

This is part 3 of a 4-part request, so the focus should be on summarizing the functionality covered in this specific snippet.

**Plan:**

1. **Identify Key Classes and Methods:** Look for the main classes and their core functions within the provided code.
2. **Analyze Functionality:** Understand what each section of code is responsible for.
3. **Connect to Web Technologies:** Relate the code's actions to how web pages are rendered and inspected.
4. **Develop Hypothetical Scenarios:** Create simple examples to demonstrate the input and output of key functions.
5. **Consider Potential Errors:** Think about common mistakes related to the concepts the code handles.
6. **Summarize the Functionality:**  Condense the analysis into a concise summary.
```
功能归纳：

这段代码主要负责 **高亮显示页面元素的不同区域**，用于 Chromium 浏览器的开发者工具（DevTools）的元素审查功能。  它计算并绘制元素的内容(content)、内边距(padding)、边框(border)和外边距(margin)的边界，以及其他与元素布局相关的可视化信息。

**功能详细分解:**

1. **计算元素盒模型区域 (Content, Padding, Border, Margin):**
   - `BuildNodeQuads` 函数负责计算给定节点的这些区域的四边形（QuadF）坐标。
   - 它会根据元素的 `LayoutObject` (布局对象) 的类型（例如，是否是 inline 元素）采取不同的计算方式。
   - 对于 inline 元素，它会忽略 `marginTop` 和 `marginBottom`。
   - 它会将局部坐标转换为绝对坐标，并最终转换为视口坐标。

2. **追加高亮路径:**
   - `AppendQuad` 函数将一个表示矩形的四边形转换为路径（Path），然后调用 `AppendPath`。
   - `AppendPath` 函数将一个路径、填充颜色和轮廓颜色等信息存储在一个 `protocol::DictionaryValue` 对象中，最终添加到 `highlight_paths_` 列表中。 这些路径将用于在 DevTools 中绘制高亮。

3. **源顺序高亮:**
   - `InspectorSourceOrderHighlight` 类用于高亮显示具有特定源顺序位置的元素。
   - 它继承自 `InspectorHighlightBase`，并使用 `BuildNodeQuads` 获取边框区域，然后使用 `AppendQuad` 添加高亮。
   - `AsProtocolValue` 方法将高亮信息转换为可用于 DevTools 通信的协议格式。

4. **通用的元素高亮 (`InspectorHighlight`):**
   - `InspectorHighlight` 是主要的高亮类，它处理更复杂的元素高亮需求。
   - 它接收 `InspectorHighlightConfig`，其中包含各种高亮颜色和配置选项。
   - 它会调用 `AppendPathsForShapeOutside` 来处理 `shape-outside` 属性定义的不规则形状的高亮。
   - **关键功能：`AppendNodeHighlight`**:  这是核心函数，它根据节点的布局对象类型，计算并添加内容、内边距、边框和外边距的高亮路径。
   - 它还会处理网格布局 (`css_grid`) 和弹性布局 (`flex_container_info_`, `flex_item_info_`) 的高亮信息，以及容器查询 (`container_query_container_info_`) 的高亮信息。 这些信息也会被添加到协议值中。

5. **距离信息 (`AppendDistanceInfo`):**
   - 此功能用于收集元素及其子元素、伪元素的盒模型信息，用于在 DevTools 中显示尺寸和间距。
   - 它会递归遍历文档树，收集每个布局对象的矩形信息。
   - 对于文本节点，它会获取每个文本行的矩形。
   - 它还会收集元素的计算样式 (`computed_style_`)，特别是颜色值。

6. **事件目标高亮 (`AppendEventTargetQuads`):**
   - 用于高亮显示作为事件目标的元素。

7. **形状外部高亮 (`AppendPathsForShapeOutside`):**
   -  处理使用 `shape-outside` CSS 属性定义的非矩形形状的高亮显示。

8. **转换为协议值 (`AsProtocolValue`):**
   - 将所有收集到的高亮信息（路径、标尺、扩展线、辅助功能信息、盒模型信息、网格/弹性布局信息等）转换为 `protocol::DictionaryValue` 对象，以便发送到 DevTools 前端。

9. **获取盒模型 (`GetBoxModel`):**
   -  一个静态方法，用于获取指定节点的盒模型信息，并将其转换为 `protocol::DOM::BoxModel` 对象。
   -  它会考虑绝对缩放 (absolute zoom)。
   -  它还会处理 `shape-outside` 属性。

10. **获取内容区域 (`GetContentQuads`):**
    - 一个静态方法，用于获取指定节点内容区域的四边形坐标。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **HTML:**  这段代码处理的是 HTML 元素在页面上的渲染和布局。它接收一个 `Node*` 对象作为输入，这个 `Node` 对象通常对应于 HTML 文档中的一个元素。
    * **例子:** 当你在 DevTools 中选中一个 `<div>` 元素时，这个 `<div>` 元素在 Blink 引擎中会被表示为一个 `Element` 对象，并传递给 `InspectorHighlight` 来计算其高亮信息。

* **CSS:**  CSS 样式决定了元素的盒模型属性 (如 `padding`, `border`, `margin`) 和布局方式 (如 `display: grid`, `display: flex`, `shape-outside`)。这段代码会读取和利用这些 CSS 属性来计算高亮区域。
    * **例子:** 如果一个 `<div>` 元素设置了 `padding: 10px; border: 1px solid black; margin: 5px;`，`BuildNodeQuads` 函数会读取这些值，计算出 padding box、border box 和 margin box 的位置和大小。
    * **例子:** 如果一个元素使用了 `shape-outside: circle();`， `AppendPathsForShapeOutside` 会根据这个 CSS 属性计算出圆形的高亮路径。
    * **例子:** 对于设置了 `display: grid;` 的元素， `AppendNodeHighlight` 会调用 `BuildGridInfo` 来生成网格线和轨道的高亮信息。

* **JavaScript:**  虽然这段 C++ 代码本身不直接与 JavaScript 交互，但它为 DevTools 提供了必要的数据，而 DevTools 是一个基于 Web 技术的应用程序，主要由 JavaScript 编写。当开发者在 DevTools 中与元素审查功能交互时，例如鼠标悬停在一个元素上，DevTools 的 JavaScript 代码会请求 Blink 引擎提供该元素的高亮信息。
    * **例子:** 当 DevTools 的 JavaScript 代码需要高亮显示某个元素时，它会通过 Chrome DevTools Protocol (CDP) 发送请求到 Blink 引擎，Blink 引擎会使用 `InspectorHighlight` 来生成高亮信息，并将这些信息（通常是 JSON 格式的）返回给 DevTools 的 JavaScript 代码，然后 JavaScript 代码会在页面上绘制高亮。

**逻辑推理 (假设输入与输出):**

**假设输入:** 一个 `<div>` 元素，其 CSS 样式如下：

```css
div {
  width: 100px;
  height: 50px;
  padding: 10px;
  border: 2px solid red;
  margin: 20px;
}
```

**假设调用:** `BuildNodeQuads(div_element, &content, &padding, &border, &margin)`

**预期输出:**

* `content`: 一个 `gfx::QuadF` 对象，表示内容区域的四个角的绝对屏幕坐标。 假设该 `<div>` 元素在屏幕上的起始位置是 (100, 100)，则 content 的坐标可能为: (112, 112), (212, 112), (212, 162), (112, 162)。  （计算方式：起始位置 + margin + border + padding）
* `padding`: 一个 `gfx::QuadF` 对象，表示内边距区域的坐标。 坐标可能为: (112, 112), (212, 112), (212, 162), (112, 162)。
* `border`: 一个 `gfx::QuadF` 对象，表示边框区域的坐标。 坐标可能为: (110, 110), (214, 110), (214, 164), (110, 164)。
* `margin`: 一个 `gfx::QuadF` 对象，表示外边距区域的坐标。 坐标可能为: (90, 90), (234, 90), (234, 184), (90, 184)。

**假设调用:** `AppendQuad(border, Color::kTransparent, Color::kBlue, "border")`

**预期输出:**  `highlight_paths_` 列表中会添加一个 `protocol::DictionaryValue` 对象，其中包含以下信息：

```json
{
  "path": [ /* 表示边框四边形的路径数据 */ ],
  "fillColor": "rgba(0,0,0,0)", // 透明
  "outlineColor": "rgb(0,0,255)", // 蓝色
  "name": "border"
}
```

**用户或编程常见的使用错误举例:**

1. **假设布局未完成就尝试高亮:**  如果过早地尝试获取元素的高亮信息，例如在页面加载的早期阶段，元素的布局可能尚未完成，`GetLayoutObject()` 可能会返回空指针，导致程序崩溃或高亮信息不准确。开发者需要确保在布局完成后再进行高亮操作。

2. **错误地配置高亮颜色:**  如果传递了错误的颜色值（例如，格式不正确），可能导致高亮不可见或显示为意外的颜色。

3. **忽略了元素的 `transform` 属性:** 代码中似乎考虑了坐标转换，但如果开发者在更高层级的代码中没有正确处理元素的 `transform` 属性，导致传递给 `InspectorHighlight` 的节点信息不准确，那么高亮的位置可能不正确。

4. **尝试高亮不存在的节点:** 如果尝试高亮一个已经被移除的 DOM 节点，`GetLayoutObject()` 会返回空指针，需要进行空指针检查以避免错误。

5. **不理解不同盒模型的概念:** 开发者可能不清楚 content-box, padding-box, border-box, margin-box 的区别，导致误解 DevTools 中显示的高亮区域。

这段代码是 Chromium 开发者工具中元素审查功能的核心组成部分，它连接了浏览器的渲染引擎和开发者工具的前端界面，为开发者提供了直观的元素布局和样式信息。
```
### 提示词
```
这是目录为blink/renderer/core/inspector/inspector_highlight.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
ox();
    padding_box =
        PhysicalRect(border_box.X() + layout_inline->BorderLeft(),
                     border_box.Y() + layout_inline->BorderTop(),
                     border_box.Width() - layout_inline->BorderLeft() -
                         layout_inline->BorderRight(),
                     border_box.Height() - layout_inline->BorderTop() -
                         layout_inline->BorderBottom());
    content_box =
        PhysicalRect(padding_box.X() + layout_inline->PaddingLeft(),
                     padding_box.Y() + layout_inline->PaddingTop(),
                     padding_box.Width() - layout_inline->PaddingLeft() -
                         layout_inline->PaddingRight(),
                     padding_box.Height() - layout_inline->PaddingTop() -
                         layout_inline->PaddingBottom());
    // Ignore marginTop and marginBottom for inlines.
    margin_box = PhysicalRect(
        border_box.X() - layout_inline->MarginLeft(), border_box.Y(),
        border_box.Width() + layout_inline->MarginWidth(), border_box.Height());
  }

  *content = layout_object->LocalRectToAbsoluteQuad(content_box);
  *padding = layout_object->LocalRectToAbsoluteQuad(padding_box);
  *border = layout_object->LocalRectToAbsoluteQuad(border_box);
  *margin = layout_object->LocalRectToAbsoluteQuad(margin_box);

  FrameQuadToViewport(containing_view, *content);
  FrameQuadToViewport(containing_view, *padding);
  FrameQuadToViewport(containing_view, *border);
  FrameQuadToViewport(containing_view, *margin);

  return true;
}

void InspectorHighlightBase::AppendQuad(const gfx::QuadF& quad,
                                        const Color& fill_color,
                                        const Color& outline_color,
                                        const String& name) {
  Path path = QuadToPath(quad);
  PathBuilder builder;
  builder.AppendPath(path, scale_);
  AppendPath(builder.Release(), fill_color, outline_color, name);
}

void InspectorHighlightBase::AppendPath(
    std::unique_ptr<protocol::ListValue> path,
    const Color& fill_color,
    const Color& outline_color,
    const String& name) {
  std::unique_ptr<protocol::DictionaryValue> object =
      protocol::DictionaryValue::create();
  object->setValue("path", std::move(path));
  object->setString("fillColor", fill_color.SerializeAsCSSColor());
  if (outline_color != Color::kTransparent)
    object->setString("outlineColor", outline_color.SerializeAsCSSColor());
  if (!name.empty())
    object->setString("name", name);
  highlight_paths_->pushValue(std::move(object));
}

InspectorSourceOrderHighlight::InspectorSourceOrderHighlight(
    Node* node,
    Color outline_color,
    int source_order_position)
    : InspectorHighlightBase(node),
      source_order_position_(source_order_position) {
  gfx::QuadF content, padding, border, margin;
  if (!BuildNodeQuads(node, &content, &padding, &border, &margin))
    return;
  AppendQuad(border, Color::kTransparent, outline_color, "border");
}

std::unique_ptr<protocol::DictionaryValue>
InspectorSourceOrderHighlight::AsProtocolValue() const {
  std::unique_ptr<protocol::DictionaryValue> object =
      protocol::DictionaryValue::create();
  object->setValue("paths", highlight_paths_->clone());
  object->setInteger("sourceOrder", source_order_position_);
  return object;
}

// static
InspectorSourceOrderConfig InspectorSourceOrderHighlight::DefaultConfig() {
  InspectorSourceOrderConfig config;
  config.parent_outline_color = Color(224, 90, 183, 1);
  config.child_outline_color = Color(0, 120, 212, 1);
  return config;
}

InspectorHighlight::InspectorHighlight(
    Node* node,
    const InspectorHighlightConfig& highlight_config,
    const InspectorHighlightContrastInfo& node_contrast,
    bool append_element_info,
    bool append_distance_info,
    NodeContentVisibilityState content_visibility_state)
    : InspectorHighlightBase(node),
      show_rulers_(highlight_config.show_rulers),
      show_extension_lines_(highlight_config.show_extension_lines),
      show_accessibility_info_(highlight_config.show_accessibility_info),
      color_format_(highlight_config.color_format) {
  DCHECK_GE(node->GetDocument().Lifecycle().GetState(),
            DocumentLifecycle::kLayoutClean);
  AppendPathsForShapeOutside(node, highlight_config);
  AppendNodeHighlight(node, highlight_config);
  auto* text_node = DynamicTo<Text>(node);
  auto* element = DynamicTo<Element>(node);
  if (append_element_info && element)
    element_info_ = BuildElementInfo(element);
  else if (append_element_info && text_node)
    element_info_ = BuildTextNodeInfo(text_node);
  if (element && element_info_ && highlight_config.show_styles) {
    AppendStyleInfo(element, element_info_.get(), node_contrast,
                    highlight_config.contrast_algorithm);
  }

  if (element_info_) {
    switch (content_visibility_state) {
      case NodeContentVisibilityState::kNone:
        break;
      case NodeContentVisibilityState::kIsLocked:
        element_info_->setBoolean("isLocked", true);
        break;
      case NodeContentVisibilityState::kIsLockedAncestor:
        element_info_->setBoolean("isLockedAncestor", true);
        break;
    }

    element_info_->setBoolean("showAccessibilityInfo",
                              show_accessibility_info_);
  }

  if (append_distance_info)
    AppendDistanceInfo(node);
}

InspectorHighlight::~InspectorHighlight() = default;

void InspectorHighlight::AppendDistanceInfo(Node* node) {
  if (!InspectorHighlight::GetBoxModel(node, &model_, false))
    return;
  boxes_ = std::make_unique<protocol::Array<protocol::Array<double>>>();
  computed_style_ = protocol::DictionaryValue::create();

  node->GetDocument().EnsurePaintLocationDataValidForNode(
      node, DocumentUpdateReason::kInspector);
  LayoutObject* layout_object = node->GetLayoutObject();
  if (!layout_object)
    return;

  if (Element* element = DynamicTo<Element>(node)) {
    CSSComputedStyleDeclaration* style =
        MakeGarbageCollected<CSSComputedStyleDeclaration>(element, true);
    for (unsigned i = 0; i < style->length(); ++i) {
      AtomicString name(style->item(i));
      const CSSValue* value = style->GetPropertyCSSValue(
          CssPropertyID(element->GetExecutionContext(), name));
      if (!value) {
        continue;
      }
      if (value->IsColorValue()) {
        Color color = static_cast<const cssvalue::CSSColor*>(value)->Value();
        computed_style_->setString(name, ToHEXA(color));
      } else {
        computed_style_->setString(name, value->CssText());
      }
    }
  }

  VisitAndCollectDistanceInfo(&(node->GetDocument()));
  PhysicalRect document_rect(
      node->GetDocument().GetLayoutView()->DocumentRect());
  LocalFrameView* local_frame_view = node->GetDocument().View();
  boxes_->emplace_back(
      RectForPhysicalRect(local_frame_view->ConvertToRootFrame(document_rect)));
}

void InspectorHighlight::VisitAndCollectDistanceInfo(Node* node) {
  LayoutObject* layout_object = node->GetLayoutObject();
  if (layout_object)
    AddLayoutBoxToDistanceInfo(layout_object);

  if (auto* element = DynamicTo<Element>(node)) {
    if (element->GetPseudoId()) {
      if (layout_object)
        VisitAndCollectDistanceInfo(element->GetPseudoId(), layout_object);
    } else {
      for (PseudoId pseudo_id :
           {kPseudoIdFirstLetter, kPseudoIdScrollMarkerGroupBefore,
            kPseudoIdCheck, kPseudoIdBefore, kPseudoIdAfter,
            kPseudoIdSelectArrow, kPseudoIdScrollMarkerGroupAfter,
            kPseudoIdScrollMarker, kPseudoIdScrollNextButton,
            kPseudoIdScrollPrevButton}) {
        if (Node* pseudo_node = element->GetPseudoElement(pseudo_id))
          VisitAndCollectDistanceInfo(pseudo_node);
      }
    }
  }

  if (!node->IsContainerNode())
    return;
  for (Node* child = blink::dom_traversal_utils::FirstChild(*node, false);
       child; child = blink::dom_traversal_utils::NextSibling(*child, false)) {
    VisitAndCollectDistanceInfo(child);
  }
}

void InspectorHighlight::VisitAndCollectDistanceInfo(
    PseudoId pseudo_id,
    LayoutObject* layout_object) {
  if (pseudo_id == kPseudoIdNone)
    return;
  for (LayoutObject* child = layout_object->SlowFirstChild(); child;
       child = child->NextSibling()) {
    if (child->IsAnonymous())
      AddLayoutBoxToDistanceInfo(child);
  }
}

void InspectorHighlight::AddLayoutBoxToDistanceInfo(
    LayoutObject* layout_object) {
  if (layout_object->IsText()) {
    auto* layout_text = To<LayoutText>(layout_object);
    for (const auto& text_box : layout_text->GetTextBoxInfo()) {
      PhysicalRect text_rect(
          TextFragmentRectInRootFrame(layout_object, text_box));
      boxes_->emplace_back(RectForPhysicalRect(text_rect));
    }
  } else {
    PhysicalRect rect(RectInRootFrame(layout_object));
    boxes_->emplace_back(RectForPhysicalRect(rect));
  }
}

void InspectorHighlight::AppendEventTargetQuads(
    Node* event_target_node,
    const InspectorHighlightConfig& highlight_config) {
  if (event_target_node->GetLayoutObject()) {
    gfx::QuadF border, unused;
    if (BuildNodeQuads(event_target_node, &unused, &unused, &border, &unused))
      AppendQuad(border, highlight_config.event_target);
  }
}

void InspectorHighlight::AppendPathsForShapeOutside(
    Node* node,
    const InspectorHighlightConfig& config) {
  Shape::DisplayPaths paths;
  gfx::QuadF bounds_quad;

  const ShapeOutsideInfo* shape_outside_info =
      ShapeOutsideInfoForNode(node, &paths, &bounds_quad);
  if (!shape_outside_info)
    return;

  if (!paths.shape.length()) {
    AppendQuad(bounds_quad, config.shape);
    return;
  }

  AppendPath(ShapePathBuilder::BuildPath(
                 *node->GetDocument().View(), *node->GetLayoutObject(),
                 *shape_outside_info, paths.shape, scale_),
             config.shape, Color::kTransparent);
  if (paths.margin_shape.length())
    AppendPath(ShapePathBuilder::BuildPath(
                   *node->GetDocument().View(), *node->GetLayoutObject(),
                   *shape_outside_info, paths.margin_shape, scale_),
               config.shape_margin, Color::kTransparent);
}

void InspectorHighlight::AppendNodeHighlight(
    Node* node,
    const InspectorHighlightConfig& highlight_config) {
  LayoutObject* layout_object = node->GetLayoutObject();
  if (!layout_object)
    return;

  Vector<gfx::QuadF> svg_quads;
  if (BuildSVGQuads(node, svg_quads)) {
    for (wtf_size_t i = 0; i < svg_quads.size(); ++i) {
      AppendQuad(svg_quads[i], highlight_config.content,
                 highlight_config.content_outline);
    }
    return;
  }

  gfx::QuadF content, padding, border, margin;
  if (!BuildNodeQuads(node, &content, &padding, &border, &margin))
    return;
  AppendQuad(content, highlight_config.content,
             highlight_config.content_outline, "content");
  AppendQuad(padding, highlight_config.padding, Color::kTransparent, "padding");
  AppendQuad(border, highlight_config.border, Color::kTransparent, "border");
  AppendQuad(margin, highlight_config.margin, Color::kTransparent, "margin");

  // Don't append node's grid / flex info if it's locked since those values may
  // not be generated yet.
  if (auto* context = layout_object->GetDisplayLockContext()) {
    if (context->IsLocked())
      return;
  }

  if (highlight_config.css_grid != Color::kTransparent ||
      highlight_config.grid_highlight_config) {
    grid_info_ = protocol::ListValue::create();
    if (layout_object->IsLayoutGrid()) {
      grid_info_->pushValue(
          BuildGridInfo(To<Element>(node), highlight_config, scale_, true));
    }
  }

  if (highlight_config.flex_container_highlight_config) {
    flex_container_info_ = protocol::ListValue::create();
    // Some objects are flexible boxes even though display:flex is not set, we
    // need to avoid those.
    if (IsLayoutNGFlexibleBox(*layout_object)) {
      flex_container_info_->pushValue(BuildFlexContainerInfo(
          To<Element>(node),
          *(highlight_config.flex_container_highlight_config), scale_));
    }
  }

  if (highlight_config.flex_item_highlight_config) {
    flex_item_info_ = protocol::ListValue::create();
    if (IsLayoutNGFlexItem(*layout_object)) {
      flex_item_info_->pushValue(BuildFlexItemInfo(
          To<Element>(node), *(highlight_config.flex_item_highlight_config),
          scale_));
    }
  }

  if (highlight_config.container_query_container_highlight_config) {
    container_query_container_info_ = protocol::ListValue::create();
    container_query_container_info_->pushValue(BuildContainerQueryContainerInfo(
        node, *(highlight_config.container_query_container_highlight_config),
        scale_));
  }
}

std::unique_ptr<protocol::DictionaryValue> InspectorHighlight::AsProtocolValue()
    const {
  std::unique_ptr<protocol::DictionaryValue> object =
      protocol::DictionaryValue::create();
  object->setValue("paths", highlight_paths_->clone());
  object->setBoolean("showRulers", show_rulers_);
  object->setBoolean("showExtensionLines", show_extension_lines_);
  object->setBoolean("showAccessibilityInfo", show_accessibility_info_);
  switch (color_format_) {
    case ColorFormat::kRgb:
      object->setString("colorFormat", "rgb");
      break;
    case ColorFormat::kHsl:
      object->setString("colorFormat", "hsl");
      break;
    case ColorFormat::kHwb:
      object->setString("colorFormat", "hwb");
      break;
    case ColorFormat::kHex:
      object->setString("colorFormat", "hex");
      break;
  }

  if (model_) {
    std::unique_ptr<protocol::DictionaryValue> distance_info =
        protocol::DictionaryValue::create();
    distance_info->setArray(
        "boxes",
        protocol::ValueConversions<std::vector<
            std::unique_ptr<std::vector<double>>>>::toValue(boxes_.get()));
    distance_info->setArray(
        "content", protocol::ValueConversions<std::vector<double>>::toValue(
                       model_->getContent()));
    distance_info->setArray(
        "padding", protocol::ValueConversions<std::vector<double>>::toValue(
                       model_->getPadding()));
    distance_info->setArray(
        "border", protocol::ValueConversions<std::vector<double>>::toValue(
                      model_->getBorder()));
    distance_info->setValue("style", computed_style_->clone());
    object->setValue("distanceInfo", std::move(distance_info));
  }
  if (element_info_)
    object->setValue("elementInfo", element_info_->clone());
  if (grid_info_ && grid_info_->size() > 0)
    object->setValue("gridInfo", grid_info_->clone());
  if (flex_container_info_ && flex_container_info_->size() > 0)
    object->setValue("flexInfo", flex_container_info_->clone());
  if (flex_item_info_ && flex_item_info_->size() > 0)
    object->setValue("flexItemInfo", flex_item_info_->clone());
  if (container_query_container_info_ &&
      container_query_container_info_->size() > 0) {
    object->setValue("containerQueryInfo",
                     container_query_container_info_->clone());
  }
  return object;
}

// static
bool InspectorHighlight::GetBoxModel(
    Node* node,
    std::unique_ptr<protocol::DOM::BoxModel>* model,
    bool use_absolute_zoom) {
  node->GetDocument().EnsurePaintLocationDataValidForNode(
      node, DocumentUpdateReason::kInspector);
  LayoutObject* layout_object = node->GetLayoutObject();
  LocalFrameView* view = node->GetDocument().View();
  if (!layout_object || !view)
    return false;

  gfx::QuadF content, padding, border, margin;
  Vector<gfx::QuadF> svg_quads;
  if (BuildSVGQuads(node, svg_quads)) {
    if (!svg_quads.size())
      return false;
    content = svg_quads[0];
    padding = svg_quads[0];
    border = svg_quads[0];
    margin = svg_quads[0];
  } else if (!BuildNodeQuads(node, &content, &padding, &border, &margin)) {
    return false;
  }

  if (use_absolute_zoom) {
    AdjustForAbsoluteZoom::AdjustQuadMaybeExcludingCSSZoom(content,
                                                           *layout_object);
    AdjustForAbsoluteZoom::AdjustQuadMaybeExcludingCSSZoom(padding,
                                                           *layout_object);
    AdjustForAbsoluteZoom::AdjustQuadMaybeExcludingCSSZoom(border,
                                                           *layout_object);
    AdjustForAbsoluteZoom::AdjustQuadMaybeExcludingCSSZoom(margin,
                                                           *layout_object);
  }

  float scale = PageScaleFromFrameView(view);
  content.Scale(scale, scale);
  padding.Scale(scale, scale);
  border.Scale(scale, scale);
  margin.Scale(scale, scale);

  gfx::Rect bounding_box =
      view->ConvertToRootFrame(layout_object->AbsoluteBoundingBoxRect());
  auto* model_object = DynamicTo<LayoutBoxModelObject>(layout_object);

  *model = protocol::DOM::BoxModel::create()
               .setContent(BuildArrayForQuad(content))
               .setPadding(BuildArrayForQuad(padding))
               .setBorder(BuildArrayForQuad(border))
               .setMargin(BuildArrayForQuad(margin))
               .setWidth(model_object
                             ? AdjustForAbsoluteZoom::AdjustLayoutUnit(
                                   model_object->OffsetWidth(), *model_object)
                                   .Round()
                             : bounding_box.width())
               .setHeight(model_object
                              ? AdjustForAbsoluteZoom::AdjustLayoutUnit(
                                    model_object->OffsetHeight(), *model_object)
                                    .Round()
                              : bounding_box.height())
               .build();

  Shape::DisplayPaths paths;
  gfx::QuadF bounds_quad;
  protocol::ErrorSupport errors;
  if (const ShapeOutsideInfo* shape_outside_info =
          ShapeOutsideInfoForNode(node, &paths, &bounds_quad)) {
    auto shape = ShapePathBuilder::BuildPath(
        *view, *layout_object, *shape_outside_info, paths.shape, 1.f);
    auto margin_shape = ShapePathBuilder::BuildPath(
        *view, *layout_object, *shape_outside_info, paths.margin_shape, 1.f);
    (*model)->setShapeOutside(
        protocol::DOM::ShapeOutsideInfo::create()
            .setBounds(BuildArrayForQuad(bounds_quad))
            .setShape(protocol::ValueConversions<
                      protocol::Array<protocol::Value>>::fromValue(shape.get(),
                                                                   &errors))
            .setMarginShape(
                protocol::ValueConversions<protocol::Array<protocol::Value>>::
                    fromValue(margin_shape.get(), &errors))
            .build());
  }

  return true;
}

// static
bool InspectorHighlight::BuildSVGQuads(Node* node, Vector<gfx::QuadF>& quads) {
  LayoutObject* layout_object = node->GetLayoutObject();
  if (!layout_object)
    return false;
  if (!layout_object->GetNode() || !layout_object->GetNode()->IsSVGElement() ||
      layout_object->IsSVGRoot())
    return false;
  CollectQuads(node, false /* adjust_for_absolute_zoom */, quads);
  return true;
}

// static
bool InspectorHighlight::GetContentQuads(
    Node* node,
    std::unique_ptr<protocol::Array<protocol::Array<double>>>* result) {
  LocalFrameView* view = node->GetDocument().View();
  if (!view)
    return false;
  Vector<gfx::QuadF> quads;
  CollectQuads(node, true /* adjust_for_absolute_zoom */, quads);
  float scale = PageScaleFromFrameView(view);
  for (gfx::QuadF& quad : quads)
    quad.Scale(scale, scale);

  *result = std::make_unique<protocol::Array<protocol::Array<double>>>();
  for (gfx::QuadF& quad : quads)
    (*result)->emplace_back(BuildArrayForQuad(quad));
  return true;
}

std::unique_ptr<protocol::DictionaryValue> InspectorGridHighlight(
    Node* node,
    const InspectorGridHighlightConfig& config) {
  if (DisplayLockUtilities::LockedAncestorPreventingPaint(*node)) {
    // Skip if node is part of display locked tree.
    return nullptr;
  }

  LocalFrameView* frame_view = node->GetDocument().View();
  if (!frame_view)
    return nullptr;

  float scale = DeviceScaleFromFrameView(frame_view);
  LayoutObject* layout_object = node->GetLayoutObject();
  if (!layout_object || !layout_object->IsLayoutGrid()) {
    return nullptr;
  }

  std::unique_ptr<protocol::DictionaryValue> grid_info =
      BuildGridInfo(To<Element>(node), config, scale, true);
  return grid_info;
}

std::unique_ptr<protocol::DictionaryValue> InspectorFlexContainerHighlight(
    Node* node,
    const InspectorFlexContainerHighlightConfig& config) {
  if (DisplayLockUtilities::LockedAncestorPreventingPaint(*node)) {
    // Skip if node is part of display locked tree.
    return nullptr;
  }

  LocalFrameView* frame_view = node->GetDocument().View();
  if (!frame_view)
    return nullptr;

  float scale = DeviceScaleFromFrameView(frame_view);
  LayoutObject* layout_object = node->GetLayoutObject();
  if (!layout_object || !IsLayoutNGFlexibleBox(*layout_object)) {
    return nullptr;
  }

  return BuildFlexContainerInfo(To<Element>(node), config, scale);
}

std::unique_ptr<protocol::DictionaryValue> BuildSnapContainerInfo(Node* node) {
  if (!node)
    return nullptr;

  // If scroll snapping is enabled for the document element, we should use
  // document's layout box for reading snap areas.
  LayoutBox* layout_box = node == node->GetDocument().documentElement()
                              ? node->GetDocument().GetLayoutBoxForScrolling()
                              : node->GetLayoutBox();

  if (!layout_box)
    return nullptr;

  LocalFrameView* containing_view = node->GetDocument().View();

  if (!containing_view)
    return nullptr;

  auto* scrollable_area = layout_box->GetScrollableArea();
  if (!scrollable_area)
    return nullptr;

  std::unique_ptr<protocol::DictionaryValue> scroll_snap_info =
      protocol::DictionaryValue::create();
  auto scroll_position = scrollable_area->ScrollPosition();
  auto* container_data = scrollable_area->GetSnapContainerData();

  if (!container_data)
    return nullptr;

  gfx::QuadF snapport_quad =
      layout_box->LocalToAbsoluteQuad(gfx::QuadF(container_data->rect()));
  scroll_snap_info->setValue("snapport",
                             BuildPathFromQuad(containing_view, snapport_quad));

  auto padding_box = layout_box->PhysicalPaddingBoxRect();
  gfx::QuadF padding_box_quad =
      layout_box->LocalRectToAbsoluteQuad(padding_box);
  scroll_snap_info->setValue(
      "paddingBox", BuildPathFromQuad(containing_view, padding_box_quad));

  auto snap_type = container_data->scroll_snap_type();
  std::unique_ptr<protocol::ListValue> result_areas =
      protocol::ListValue::create();
  std::vector<cc::SnapAreaData> snap_area_items;
  snap_area_items.reserve(container_data->size());
  for (size_t i = 0; i < container_data->size(); i++) {
    cc::SnapAreaData data = container_data->at(i);
    data.rect.Offset(-scroll_position.x(), -scroll_position.y());
    snap_area_items.push_back(std::move(data));
  }

  std::sort(snap_area_items.begin(), snap_area_items.end(),
            [](const cc::SnapAreaData& a, const cc::SnapAreaData& b) -> bool {
              return a.rect.origin() < b.rect.origin();
            });

  for (const auto& data : snap_area_items) {
    std::unique_ptr<protocol::DictionaryValue> result_area =
        protocol::DictionaryValue::create();

    gfx::QuadF area_quad =
        layout_box->LocalToAbsoluteQuad(gfx::QuadF(data.rect));
    result_area->setValue("path",
                          BuildPathFromQuad(containing_view, area_quad));

    Node* area_node = DOMNodeIds::NodeForId(
        DOMNodeIdFromCompositorElementId(data.element_id));
    DCHECK(area_node);
    if (!area_node)
      continue;

    auto* area_layout_box = area_node->GetLayoutBox();
    gfx::QuadF area_box_quad = area_layout_box->LocalRectToAbsoluteQuad(
        area_layout_box->PhysicalBorderBoxRect());
    result_area->setValue("borderBox",
                          BuildPathFromQuad(containing_view, area_box_quad));

    BuildSnapAlignment(snap_type, data.scroll_snap_align.alignment_block,
                       data.scroll_snap_align.alignment_inline, result_area);

    result_areas->pushValue(std::move(result_area));
  }
  scroll_snap_info->setArray("snapAreas", std::move(result_areas));

  return scroll_snap_info;
}

std::unique_ptr<protocol::DictionaryValue> InspectorScrollSnapHighlight(
    Node* node,
    const InspectorScrollSnapContainerHighlightConfig& config) {
  std::unique_ptr<protocol::DictionaryValue> scroll_snap_info =
      BuildSnapContainerInfo(node);

  if (!scroll_snap_info)
    return nullptr;

  AppendLineStyleConfig(config.snapport_border, scroll_snap_info,
                        "snapportBorder");
  AppendLineStyleConfig(config.snap_area_border, scroll_snap_info,
                        "snapAreaBorder");
  scroll_snap_info->setString("scrollMarginColor",
                              config.scroll_margin_color.SerializeAsCSSColor());
  scroll_snap_info->setString(
      "scrollPaddingColor", config.scroll_padding_color.SerializeAsCSSColor());

  return scroll_snap_info;
}

Vector<gfx::QuadF> GetContainerQueryingDescendantQuads(Element* container) {
  Vector<gfx::QuadF> descendant_quads;
  for (Element* descendant :
       InspectorDOMAgent::GetContainerQueryingDescendants(container)) {
    LayoutBox* layout_box = descendant->GetLayoutBox();
    if (!layout_box)
      continue;
    auto content_box = layout_box->PhysicalContentBoxRect();
    gfx::QuadF content_quad = layout_box->LocalRectToAbsoluteQuad(content_box);
    descendant_quads.push_back(content_quad);
  }

  return descendant_quads;
}

std::unique_ptr<protocol::DictionaryValue> BuildContainerQueryContainerInfo(
    Node* node,
    const InspectorContainerQueryContainerHighlightConfig&
        container_query_container_highlight_config,
    float scale) {
  if (!node)
    return nullptr;

  LayoutBox* layout_box = node->GetLayoutBox();
  if (!layout_box)
    return nullptr;

  LocalFrameView* containing_view = node->GetDocument().View();
  if (!containing_view)
    return nullptr;

  std::unique_ptr<protocol::DictionaryValue> container_query_container_info =
      protocol::DictionaryValue::create();

  PathBuilder container_builder;
  auto content_box = layout_box->PhysicalContentBoxRect();
  gfx::QuadF content_quad = layout_box->LocalRectToAbsoluteQuad(content_box);
  FrameQuadToViewport(containing_view, content_quad);
  container_builder.AppendPath(QuadToPath(content_quad), scale);
  container_query_container_info->setValue("containerBorder",
                                           container_builder.Release());

  auto* element = DynamicTo<Element>(node);
  bool include_descendants =
      container_query_container_highlight_config.descendant_border &&
      !container_query_container_highlight_config.descendant_border
           ->IsFullyTransparent();
  if (element && include_descendants) {
    std::unique_ptr<protocol::ListValue> descendants_info =
        protocol::ListValue::create();
    for (auto& descendant_quad : GetContainerQueryingDescendantQuads(element)) {
      std::unique_ptr<protocol::DictionaryValue> descendant_info =
          protocol::DictionaryValue::create();
      descendant_info->setValue(
          "descendantBorder",
          BuildPathFromQuad(containing_view, descendant_quad));
      descendants_info->pushValue(std::move(descendant_info));
    }
    container_query_container_info->setArray("queryingDescendants",
                                             std::move(descendants_info));
  }

  container_query_container_info->setValue(
      "containerQueryContainerHighlightConfig",
      BuildContainerQueryContainerHighlightConfigInfo(
          container_query_container_highlight_config));

  return container_query_container_info;
}

std::unique_ptr<protocol::DictionaryValue> BuildIsolatedElementInfo(
    Element& element,
    const InspectorIsolationModeHighlightConfig& config,
    float scale) {
  LayoutBox* layout_box = element.GetLayoutBox();
  if (!layout_box)
    return nullptr;

  LocalFrameView* containing_view = element.GetDocument().View();
  if (!containing_view)
    return nullptr;

  auto isolated_element_info = protocol::DictionaryValue::create();

  auto element_box = layout_box->PhysicalContentBoxRect();
  gfx::QuadF element_box_quad =
      layout_box->LocalRectToAbsoluteQuad(element_box);
  FrameQuadToViewport(containing_view, element_box_quad);
  isolated_element_info->setDouble("currentX", element_box_quad.p1().x());
  isolated_element_info->setDouble("currentY", element_box_quad.p1().y());

  // Isolation mode's resizer size should be consistent with
  // Device Mode's resizer size, which is 20px.
  const LayoutUnit resizer_size(20 / scale);
  PhysicalRect width_resizer_box(
      layout_box->ContentLeft() + layout_box->ContentWidth(),
      layout_box->ContentTop(), resizer_size, layout_box->ContentHeight());
  isolated_element_info->setValue(
      "widthResizerBorder",
      BuildPathFromQuad(containing_view, layout_box->LocalRectToAbsoluteQuad(
                                             width_resizer_box)));
  PhysicalRect height_resizer_box(
      layout_box->ContentLeft(),
      layout_box->ContentTop() + layout_box->ContentHeight(),
      layout_box->ContentWidth(), resizer_size);
  isolated_element_info->setValue(
      "heightResizerBorder",
      BuildPathFromQuad(containing_view, layout_box->LocalRectToAbsoluteQuad(
                                             height_resizer_box)));

  PhysicalRect bidirection_resizer_box(
      layout_box->ContentLeft() + layout_box->ContentWidth(),
      layout_box->ContentTop() + layout_box->ContentHeight(), resizer_size,
      resizer_size);
  isolated_element_info->setValue(
      "bidirectionResizerBorder",
      BuildPathFromQuad(containing_view, layout_box->LocalRectToAbsoluteQuad(
                                             bidirection_resizer_box)));

  CSSComputedStyleDeclaration* style =
      MakeGarbageCollected<CSSComputedStyleDeclaration>(&element, true);
  const CSSValue* width = style->GetPropertyCSSValue(CSSPropertyID::kWidth);
  if (width && width->IsNumericLiteralValue()) {
    isolated_element_info->setDouble(
        "currentWidth", To<CSSNumericLiteralValue>(width)->DoubleValue());
  }
  const CSSValue* height = style->GetPropertyCSSValue(CSSPropertyID::kHeight);
  if (height && height->IsNumericLiteralValue()) {
    isolated_element_info->setDouble(
        "currentHeight", To<CSSNumericLiteralValue>(height)->DoubleValue());
  }

  isolated_element_info->setValue(
      "isolationModeHighlightConfig",
      BuildIsolationModeHighlightConfigInfo(config));

  return isolated_element_info;
}

std::unique_ptr<protocol::DictionaryValue> InspectorContainerQueryHighlight(
    Node* node,
    const InspectorContainerQueryContainerHighlightConfig& config) {
  LocalFrameView* frame_view = node->GetDocument().View();
  if (!frame_view)
    return nullptr;

  std::unique_ptr<protocol::DictionaryValue> container_query_container_info =
      BuildContainerQueryContainerInfo(node, config,
                                       DeviceScaleFromFrameView(frame_view));

  if (!container_query_container_info)
    return nullptr;

  return container_query_container_info;
}

std::unique_ptr<protocol::DictionaryValue> InspectorIsolatedElementHighlight(
    Element* element,
    const InspectorIsolationModeHighlightConfig& config) {
  LocalFrameView* frame_view = element->GetDocument().View();
  if (!frame_view)
    return nullptr;

  std::unique_ptr<protocol::DictionaryValue> isolated_element_info =
      BuildIsolatedElementInfo(*element, config,
                               DeviceScaleFromFrameView(frame_view));

  if (!isolated_element_info)
    return nullptr;

  isolated_element_info->setInteger("highlightIndex", config.highlight_index);
  return isolated_element_info;
}

// static
InspectorHighlightConfig InspectorHighlight::DefaultConfig() {
  InspectorHighlightConfig config;
  config.content = Color(255, 0, 0, 0);
  config.content_outline = Color(128, 0, 0, 0);
  config.padding = Color(0, 255, 0, 0);
  config.border = Color(0, 0, 255, 0);
  config.margin = Color(255, 255, 255, 0);
  config.event_target = Color(128, 128, 128, 0);
  config.shape = Color(0, 0, 0, 0);
  config.shape_margin = Color(128, 128, 128, 0);
  config.show_info = true;
  config.show_styles = false;
  config.show_rulers = true;
  config.show_extension_lines = true;
  config.css_grid = Color::kTransparent;
  config.color_format = ColorFormat::kHex;
  config.grid_highlight_config = std::make_unique<InspectorGridHighlightConfig>(
      InspectorHighlight::DefaultGridConfig());
  config.flex_container_highlight_config =
```