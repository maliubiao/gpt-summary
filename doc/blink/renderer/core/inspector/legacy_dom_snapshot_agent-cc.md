Response:
Let's break down the thought process for analyzing this C++ code and generating the informative response.

1. **Understanding the Goal:** The request asks for a functional description of the `LegacyDOMSnapshotAgent.cc` file in the Chromium Blink engine. It also asks to connect its functionality to JavaScript, HTML, and CSS, provide hypothetical input/output examples for logical reasoning, and highlight potential usage errors.

2. **Initial Code Scan (Keywords and Includes):**  A quick scan of the `#include` directives provides immediate clues about the file's purpose. We see:
    * `inspector/...`:  Indicates this is part of the browser's developer tools (inspector).
    * `dom/...`:  Suggests interaction with the Document Object Model (DOM).
    * `layout/...`:  Points to involvement with the rendering layout of the page.
    * `css/...`:  Clearly indicates handling of Cascading Style Sheets (CSS).
    * `html/...`: Shows interaction with HTML elements.
    * `bindings/core/v8`:  Highlights the bridge between Blink's C++ and JavaScript's V8 engine.
    * `protocol::...`: Suggests communication using a predefined protocol, likely the Chrome DevTools Protocol (CDP).

3. **Class Name and Purpose:** The class name `LegacyDOMSnapshotAgent` strongly suggests this component is responsible for taking snapshots of the DOM. The "Legacy" prefix hints that there might be a newer version or a shift in approach over time.

4. **Core Function: `GetSnapshot()`:** This function is the entry point for the snapshot process. Its parameters (`document`, `style_filter`, `include_event_listeners`, etc.) tell us what information can be included in the snapshot. The return values (`dom_nodes`, `layout_tree_nodes`, `computed_styles`) reveal the structure of the snapshot data.

5. **Traversing the DOM:** The presence of `VisitNode()` and related functions like `VisitContainerChildren()` and `VisitPseudoElements()` makes it clear the agent iterates through the DOM tree. This aligns with the idea of creating a "snapshot."

6. **Layout Tree and Styling:**  The `VisitLayoutTreeNode()` function connects DOM nodes to their layout information (bounding boxes, text rendering details). The `GetStyleIndexForNode()` function suggests extraction of computed styles based on the `style_filter`.

7. **Data Structures and Output:** The use of `protocol::Array` and specific `protocol::DOMSnapshot::...` types reveals the structured format of the snapshot data, likely meant for transmission to the DevTools frontend.

8. **Connecting to Web Technologies (HTML, CSS, JavaScript):**

    * **HTML:** The code explicitly handles various HTML elements (input, textarea, image, etc.) and their attributes. The snapshot captures the structure and attributes of HTML.
    * **CSS:** The `style_filter` and the logic in `GetStyleIndexForNode()` demonstrate how the agent extracts specific CSS property values. The `ComputedStyle` data structure confirms this.
    * **JavaScript:** The `include_event_listeners` flag and the use of `InspectorDOMDebuggerAgent::CollectEventListeners()` show the agent's ability to gather information about JavaScript event handlers attached to DOM elements.

9. **Logical Reasoning and Examples:**

    * **Hypothetical Input/Output:**  Imagine calling `GetSnapshot()` on a simple button element. The output would include the button's tag name, attributes (like `id` or `class`), and potentially layout information (position, size). If `style_filter` included "color," the computed color would be present.
    * **Reasoning about CSS Filtering:** If the `style_filter` is empty, the `computed_styles` array would ideally be empty as well, or contain a representation of "no styles." If a specific CSS property is requested, only the computed value of that property is collected.

10. **Common Usage Errors:**

    * **Incorrect `style_filter`:**  Providing invalid CSS property names would result in those properties being ignored in the snapshot.
    * **Performance Impact:**  Requesting snapshots with a large DOM and including event listeners and all styles can be resource-intensive. This is a common pitfall for developers using such tools.

11. **Structure of the Response:**  Organizing the findings into clear categories (functionality, relationships to web technologies, logical reasoning, usage errors) makes the information easily digestible. Using examples helps illustrate abstract concepts.

12. **Refinement and Clarity:**  After drafting the initial response, reviewing it for clarity and accuracy is essential. Ensuring the language is precise and avoids jargon where possible improves understanding. For instance, explicitly stating that it's for the "Chrome DevTools" adds context.

By following these steps, one can systematically analyze the code, understand its purpose, and generate a comprehensive and informative response that addresses all aspects of the original request. The key is to break down the problem, examine the code's components, and connect them to the broader context of web development.这个文件 `blink/renderer/core/inspector/legacy_dom_snapshot_agent.cc` 是 Chromium Blink 引擎中负责**生成和提供 DOM 快照**的组件。它主要用于开发者工具（DevTools）的性能面板和内存面板等功能，以便在特定时间点记录页面的 DOM 结构、布局信息和样式信息。

以下是它的详细功能：

**核心功能：**

1. **生成 DOM 树的快照：** 遍历 DOM 树，记录每个节点的类型、名称、值、属性等信息。
2. **生成布局树的快照：** 关联 DOM 节点和其对应的布局对象（LayoutObject），并记录布局对象的边界框（bounding box）等几何信息。
3. **提取计算后的样式信息：**  根据指定的 CSS 属性过滤器，提取每个节点计算后的样式值。
4. **收集事件监听器信息：**  （可选）收集附加到 DOM 节点的 JavaScript 事件监听器信息。
5. **处理 Shadow DOM：** 可以选择是否包含 User-Agent Shadow Tree 中的节点。
6. **关联帧（Frames）：**  处理 iframe 等包含子文档的情况，记录文档所属的 frame ID，以及子文档的快照。
7. **提供节点在文档中的滚动偏移：**  记录文档的滚动位置。
8. **识别可点击元素：**  判断元素是否会响应鼠标点击事件。
9. **标记元素的 Origin URL：** 记录元素的来源 URL，用于区分不同来源的节点。
10. **记录输入元素的特定信息：**  例如，输入框的值、单选框/复选框的选中状态、下拉选项的选择状态等。
11. **处理伪元素：** 记录伪元素（如 ::before, ::after）的信息。
12. **记录 `contentDocument` 的索引：** 对于 iframe 等元素，记录其内部文档快照的索引。
13. **记录文档的 URL 和 Base URL。**
14. **记录 Document Type 的 public ID 和 system ID。**
15. **记录 Shadow Root 的类型。**
16. **记录文本节点的内联文本框信息：**  对于文本节点，记录其在页面上的多个内联文本框的位置和字符范围。
17. **记录元素的层叠上下文信息：**  标记元素是否是层叠上下文。
18. **记录元素的绘制顺序 (Paint Order)：** （可选）记录元素的绘制顺序，这对于理解渲染性能问题很有帮助。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **HTML:**
    * **功能关系：** 该 Agent 的主要工作就是分析和记录 HTML 结构。它遍历 HTML 标签，提取标签名、属性等信息。
    * **举例：**  对于一个 `<div id="container" class="main">Hello</div>` 元素，快照会记录 `nodeType: 1` (Element), `nodeName: "div"`, `attributes: [{name: "id", value: "container"}, {name: "class", value: "main"}]`。

* **CSS:**
    * **功能关系：**  该 Agent 可以根据 `style_filter` 参数提取元素的计算样式。
    * **举例：** 如果 `style_filter` 包含了 `"color"`，那么对于上述 `div` 元素，如果其计算后的颜色是红色，快照的 `computed_styles` 部分可能会包含类似 `{name: "color", value: "red"}` 的信息。
    * **假设输入与输出：**
        * **假设输入 (HTML):** `<p style="font-size: 16px;">Text</p>`
        * **假设输入 (style_filter):** `["font-size"]`
        * **输出 (computed_styles):**  对于该 `<p>` 节点，会生成一个 `ComputedStyle` 对象，其中包含 `{name: "font-size", value: "16px"}`。

* **JavaScript:**
    * **功能关系：**  可以选择包含附加到 DOM 元素的 JavaScript 事件监听器信息。这对于分析页面交互和性能瓶颈很有用。
    * **举例：**  如果一个按钮元素通过 JavaScript 添加了一个 `click` 事件监听器，当 `include_event_listeners` 为 true 时，快照会记录该监听器的类型 ("click") 和相关处理函数的信息。
    * **假设输入与输出：**
        * **假设输入 (HTML):** `<button id="myButton">Click Me</button>`
        * **假设输入 (JavaScript):** `document.getElementById('myButton').addEventListener('click', function() { console.log('Clicked!'); });`
        * **输出 (eventListeners):** 对于该 `<button>` 节点，会包含一个 `EventListener` 对象，描述了 `type: "click"` 以及处理函数的相关信息。

**逻辑推理的假设输入与输出：**

* **假设输入 (包含 iframe 的页面):**
    * 主文档包含一个 `<iframe src="child.html"></iframe>`
    * `child.html` 包含一个 `<h1>Child Document</h1>`
* **输出 (部分快照结构):**
    * 主文档的 DOM 快照会包含 iframe 元素，并设置 `contentDocumentIndex` 指向子文档的快照。
    * 子文档的 DOM 快照会包含 `<h1>Child Document</h1>` 元素。
    * 主文档 iframe 元素的 `frameId` 会指向子文档的 frame。

* **假设输入 (带有 CSS 样式的元素):**
    * HTML: `<div style="background-color: blue;"></div>`
    * `style_filter`: `["background-color"]`
* **输出 (部分快照结构):**
    * 该 `div` 元素的 `LayoutTreeNode` 会关联一个 `styleIndex`。
    * 在 `computed_styles` 数组中，会有一个对象，其 `properties` 数组包含 `{name: "background-color", value: "rgb(0, 0, 255)"}` (或类似的表示)。

**涉及用户或者编程常见的使用错误，请举例说明：**

1. **`style_filter` 中使用了不存在的 CSS 属性名：**
    * **错误：** 用户在 `style_filter` 中传递了 `"non-existent-property"`。
    * **结果：** 该属性会被忽略，不会出现在快照的 `computed_styles` 中，但不会导致程序崩溃。开发者需要确保提供的属性名是有效的 CSS 属性。

2. **过度使用 `include_event_listeners`：**
    * **错误：**  在大型复杂的页面上，设置 `include_event_listeners` 为 true 会导致快照数据量显著增加，并可能影响性能。
    * **结果：** 生成快照的时间变长，DevTools 的处理负担加重。开发者应该谨慎使用此选项，只在需要分析事件监听器时开启。

3. **假设输入与输出 (错误的 `style_filter`):**
    * **假设输入 (HTML):** `<p style="color: green;">Text</p>`
    * **假设输入 (style_filter):** `["font-family"]` (错误的属性)
    * **输出 (computed_styles):** 对于该 `<p>` 节点，生成的 `ComputedStyle` 对象的 `properties` 数组中可能不会包含任何内容，或者只包含默认值，因为 `font-family` 并没有通过内联样式设置。

4. **性能问题：**  频繁地请求完整 DOM 快照（特别是包含所有样式和事件监听器）可能会对页面性能产生负面影响，尤其是在动画或高交互的场景下。开发者应该理解快照操作的成本，避免不必要的频繁调用。

总而言之，`legacy_dom_snapshot_agent.cc` 是 Blink 引擎中一个关键的组件，它为开发者提供了强大的 DOM 快照功能，帮助他们理解页面的结构、样式和行为，从而进行性能分析和问题排查。理解其功能和使用场景对于高效地使用 Chrome DevTools 至关重要。

### 提示词
```
这是目录为blink/renderer/core/inspector/legacy_dom_snapshot_agent.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/inspector/legacy_dom_snapshot_agent.h"

#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/core/css/properties/css_property_ref.h"
#include "third_party/blink/renderer/core/dom/attribute.h"
#include "third_party/blink/renderer/core/dom/attribute_collection.h"
#include "third_party/blink/renderer/core/dom/character_data.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_type.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/dom/qualified_name.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_option_element.h"
#include "third_party/blink/renderer/core/html/forms/html_text_area_element.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/html_link_element.h"
#include "third_party/blink/renderer/core/html/html_template_element.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/inspector/dom_traversal_utils.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/inspector/inspector_dom_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_dom_debugger_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_dom_snapshot_agent.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/bindings/thread_debugger.h"
#include "v8/include/v8-inspector.h"

namespace blink {

using mojom::blink::FormControlType;
using protocol::Maybe;

namespace {

std::unique_ptr<protocol::DOM::Rect> LegacyBuildRectForPhysicalRect(
    const PhysicalRect& rect) {
  return protocol::DOM::Rect::create()
      .setX(rect.X())
      .setY(rect.Y())
      .setWidth(rect.Width())
      .setHeight(rect.Height())
      .build();
}

}  // namespace

struct LegacyDOMSnapshotAgent::VectorStringHashTraits
    : public WTF::GenericHashTraits<Vector<String>> {
  static unsigned GetHash(const Vector<String>& vec) {
    unsigned h = WTF::GetHash(vec.size());
    for (const String& s : vec) {
      h = WTF::HashInts(h, WTF::GetHash(s));
    }
    return h;
  }

  static bool Equal(const Vector<String>& a, const Vector<String>& b) {
    if (a.size() != b.size())
      return false;
    for (wtf_size_t i = 0; i < a.size(); i++) {
      if (a[i] != b[i])
        return false;
    }
    return true;
  }

  static void ConstructDeletedValue(Vector<String>& vec) {
    new (WTF::NotNullTag::kNotNull, &vec)
        Vector<String>(WTF::kHashTableDeletedValue);
  }

  static bool IsDeletedValue(const Vector<String>& vec) {
    return vec.IsHashTableDeletedValue();
  }

  static bool IsEmptyValue(const Vector<String>& vec) { return vec.empty(); }

  static constexpr bool kEmptyValueIsZero = false;
  static constexpr bool kSafeToCompareToEmptyOrDeleted = false;
};

LegacyDOMSnapshotAgent::LegacyDOMSnapshotAgent(
    InspectorDOMDebuggerAgent* dom_debugger_agent,
    OriginUrlMap* origin_url_map)
    : origin_url_map_(origin_url_map),
      dom_debugger_agent_(dom_debugger_agent) {}

LegacyDOMSnapshotAgent::~LegacyDOMSnapshotAgent() = default;

protocol::Response LegacyDOMSnapshotAgent::GetSnapshot(
    Document* document,
    std::unique_ptr<protocol::Array<String>> style_filter,
    protocol::Maybe<bool> include_event_listeners,
    protocol::Maybe<bool> include_paint_order,
    protocol::Maybe<bool> include_user_agent_shadow_tree,
    std::unique_ptr<protocol::Array<protocol::DOMSnapshot::DOMNode>>* dom_nodes,
    std::unique_ptr<protocol::Array<protocol::DOMSnapshot::LayoutTreeNode>>*
        layout_tree_nodes,
    std::unique_ptr<protocol::Array<protocol::DOMSnapshot::ComputedStyle>>*
        computed_styles) {
  document->View()->UpdateLifecycleToCompositingInputsClean(
      DocumentUpdateReason::kInspector);
  // Setup snapshot.
  dom_nodes_ =
      std::make_unique<protocol::Array<protocol::DOMSnapshot::DOMNode>>();
  layout_tree_nodes_ = std::make_unique<
      protocol::Array<protocol::DOMSnapshot::LayoutTreeNode>>();
  computed_styles_ =
      std::make_unique<protocol::Array<protocol::DOMSnapshot::ComputedStyle>>();
  computed_styles_map_ = std::make_unique<ComputedStylesMap>();
  css_property_filter_ = std::make_unique<CSSPropertyFilter>();

  // Look up the CSSPropertyIDs for each entry in |style_filter|.
  for (const String& entry : *style_filter) {
    CSSPropertyID property_id =
        CssPropertyID(document->GetExecutionContext(), entry);
    if (property_id == CSSPropertyID::kInvalid)
      continue;
    css_property_filter_->emplace_back(entry, property_id);
  }

  if (include_paint_order.value_or(false)) {
    paint_order_map_ = InspectorDOMSnapshotAgent::BuildPaintLayerTree(document);
  }

  // Actual traversal.
  VisitNode(document, include_event_listeners.value_or(false),
            include_user_agent_shadow_tree.value_or(false));

  // Extract results from state and reset.
  *dom_nodes = std::move(dom_nodes_);
  *layout_tree_nodes = std::move(layout_tree_nodes_);
  *computed_styles = std::move(computed_styles_);
  computed_styles_map_.reset();
  css_property_filter_.reset();
  paint_order_map_ = nullptr;
  return protocol::Response::Success();
}

int LegacyDOMSnapshotAgent::VisitNode(Node* node,
                                      bool include_event_listeners,
                                      bool include_user_agent_shadow_tree) {
  // Update layout tree before traversal of document so that we inspect a
  // current and consistent state of all trees. No need to do this if paint
  // order was calculated, since layout trees were already updated during
  // TraversePaintLayerTree().
  if (node->IsDocumentNode() && !paint_order_map_)
    node->GetDocument().UpdateStyleAndLayoutTree();

  String node_value;
  switch (node->getNodeType()) {
    case Node::kTextNode:
    case Node::kAttributeNode:
    case Node::kCommentNode:
    case Node::kCdataSectionNode:
    case Node::kDocumentFragmentNode:
      node_value = node->nodeValue();
      break;
    default:
      break;
  }

  // Create DOMNode object and add it to the result array before traversing
  // children, so that parents appear before their children in the array.
  std::unique_ptr<protocol::DOMSnapshot::DOMNode> owned_value =
      protocol::DOMSnapshot::DOMNode::create()
          .setNodeType(static_cast<int>(node->getNodeType()))
          .setNodeName(node->nodeName())
          .setNodeValue(node_value)
          .setBackendNodeId(IdentifiersFactory::IntIdForNode(node))
          .build();
  if (origin_url_map_ &&
      origin_url_map_->Contains(owned_value->getBackendNodeId())) {
    String origin_url = origin_url_map_->at(owned_value->getBackendNodeId());
    // In common cases, it is implicit that a child node would have the same
    // origin url as its parent, so no need to mark twice.
    if (!node->parentNode()) {
      owned_value->setOriginURL(std::move(origin_url));
    } else {
      DOMNodeId parent_id = node->parentNode()->GetDomNodeId();
      auto it = origin_url_map_->find(parent_id);
      String parent_url = it != origin_url_map_->end() ? it->value : String();
      if (parent_url != origin_url)
        owned_value->setOriginURL(std::move(origin_url));
    }
  }
  protocol::DOMSnapshot::DOMNode* value = owned_value.get();
  int index = static_cast<int>(dom_nodes_->size());
  dom_nodes_->emplace_back(std::move(owned_value));

  int layoutNodeIndex =
      VisitLayoutTreeNode(node->GetLayoutObject(), node, index);
  if (layoutNodeIndex != -1)
    value->setLayoutNodeIndex(layoutNodeIndex);

  if (node->WillRespondToMouseClickEvents())
    value->setIsClickable(true);

  if (include_event_listeners && node->GetDocument().GetFrame()) {
    ScriptState* script_state =
        ToScriptStateForMainWorld(node->GetDocument().GetFrame());
    if (script_state->ContextIsValid()) {
      ScriptState::Scope scope(script_state);
      v8::Local<v8::Context> context = script_state->GetContext();
      V8EventListenerInfoList event_information;
      InspectorDOMDebuggerAgent::CollectEventListeners(
          script_state->GetIsolate(), node, v8::Local<v8::Value>(), node, true,
          &event_information);
      if (!event_information.empty()) {
        value->setEventListeners(
            dom_debugger_agent_->BuildObjectsForEventListeners(
                event_information, context, v8_inspector::StringView()));
      }
    }
  }

  auto* element = DynamicTo<Element>(node);
  if (element) {
    value->setAttributes(BuildArrayForElementAttributes(element));

    if (auto* frame_owner = DynamicTo<HTMLFrameOwnerElement>(node)) {
      if (LocalFrame* frame =
              DynamicTo<LocalFrame>(frame_owner->ContentFrame()))
        value->setFrameId(IdentifiersFactory::FrameId(frame));

      if (Document* doc = frame_owner->contentDocument()) {
        value->setContentDocumentIndex(VisitNode(
            doc, include_event_listeners, include_user_agent_shadow_tree));
      }
    }

    if (node->parentNode() && node->parentNode()->IsDocumentNode()) {
      LocalFrame* frame = node->GetDocument().GetFrame();
      if (frame)
        value->setFrameId(IdentifiersFactory::FrameId(frame));
    }

    if (auto* textarea_element = DynamicTo<HTMLTextAreaElement>(*element))
      value->setTextValue(textarea_element->Value());

    if (auto* input_element = DynamicTo<HTMLInputElement>(*element)) {
      value->setInputValue(input_element->Value());
      if ((input_element->FormControlType() == FormControlType::kInputRadio) ||
          (input_element->FormControlType() ==
           FormControlType::kInputCheckbox)) {
        value->setInputChecked(input_element->Checked());
      }
    }

    if (auto* option_element = DynamicTo<HTMLOptionElement>(*element))
      value->setOptionSelected(option_element->Selected());

    if (element->IsPseudoElement()) {
      value->setPseudoType(InspectorDOMAgent::ProtocolPseudoElementType(
          element->GetPseudoIdForStyling()));
    }
    value->setPseudoElementIndexes(
        VisitPseudoElements(element, index, include_event_listeners,
                            include_user_agent_shadow_tree));

    auto* image_element = DynamicTo<HTMLImageElement>(node);
    if (image_element)
      value->setCurrentSourceURL(image_element->currentSrc());
  } else if (auto* document = DynamicTo<Document>(node)) {
    value->setDocumentURL(InspectorDOMAgent::DocumentURLString(document));
    value->setBaseURL(InspectorDOMAgent::DocumentBaseURLString(document));
    if (document->ContentLanguage())
      value->setContentLanguage(document->ContentLanguage().Utf8().c_str());
    if (document->EncodingName())
      value->setDocumentEncoding(document->EncodingName().Utf8().c_str());
    value->setFrameId(IdentifiersFactory::FrameId(document->GetFrame()));
    if (document->View() && document->View()->LayoutViewport()) {
      auto offset = document->View()->LayoutViewport()->GetScrollOffset();
      value->setScrollOffsetX(offset.x());
      value->setScrollOffsetY(offset.y());
    }
  } else if (auto* doc_type = DynamicTo<DocumentType>(node)) {
    value->setPublicId(doc_type->publicId());
    value->setSystemId(doc_type->systemId());
  }
  if (node->IsInShadowTree()) {
    value->setShadowRootType(
        InspectorDOMAgent::GetShadowRootType(node->ContainingShadowRoot()));
  }

  if (node->IsContainerNode()) {
    value->setChildNodeIndexes(VisitContainerChildren(
        node, include_event_listeners, include_user_agent_shadow_tree));
  }
  return index;
}

std::unique_ptr<protocol::Array<int>>
LegacyDOMSnapshotAgent::VisitContainerChildren(
    Node* container,
    bool include_event_listeners,
    bool include_user_agent_shadow_tree) {
  auto children = std::make_unique<protocol::Array<int>>();

  if (!blink::dom_traversal_utils::HasChildren(*container,
                                               include_user_agent_shadow_tree))
    return nullptr;

  Node* child = blink::dom_traversal_utils::FirstChild(
      *container, include_user_agent_shadow_tree);
  while (child) {
    children->emplace_back(VisitNode(child, include_event_listeners,
                                     include_user_agent_shadow_tree));
    child = blink::dom_traversal_utils::NextSibling(
        *child, include_user_agent_shadow_tree);
  }

  return children;
}

std::unique_ptr<protocol::Array<int>>
LegacyDOMSnapshotAgent::VisitPseudoElements(
    Element* parent,
    int index,
    bool include_event_listeners,
    bool include_user_agent_shadow_tree) {
  if (!parent->GetPseudoElement(kPseudoIdFirstLetter) &&
      !parent->GetPseudoElement(kPseudoIdCheck) &&
      !parent->GetPseudoElement(kPseudoIdBefore) &&
      !parent->GetPseudoElement(kPseudoIdAfter) &&
      !parent->GetPseudoElement(kPseudoIdSelectArrow)) {
    return nullptr;
  }

  auto pseudo_elements = std::make_unique<protocol::Array<int>>();
  for (PseudoId pseudo_id :
       {kPseudoIdFirstLetter, kPseudoIdCheck, kPseudoIdBefore, kPseudoIdAfter,
        kPseudoIdSelectArrow}) {
    if (Node* pseudo_node = parent->GetPseudoElement(pseudo_id)) {
      pseudo_elements->emplace_back(VisitNode(pseudo_node,
                                              include_event_listeners,
                                              include_user_agent_shadow_tree));
    }
  }
  return pseudo_elements;
}

std::unique_ptr<protocol::Array<protocol::DOMSnapshot::NameValue>>
LegacyDOMSnapshotAgent::BuildArrayForElementAttributes(Element* element) {
  AttributeCollection attributes = element->Attributes();
  if (attributes.IsEmpty())
    return nullptr;
  auto attributes_value =
      std::make_unique<protocol::Array<protocol::DOMSnapshot::NameValue>>();
  for (const auto& attribute : attributes) {
    attributes_value->emplace_back(protocol::DOMSnapshot::NameValue::create()
                                       .setName(attribute.GetName().ToString())
                                       .setValue(attribute.Value())
                                       .build());
  }
  return attributes_value;
}

int LegacyDOMSnapshotAgent::VisitLayoutTreeNode(LayoutObject* layout_object,
                                                Node* node,
                                                int node_index) {
  if (!layout_object)
    return -1;

  if (node->IsPseudoElement()) {
    // For pseudo elements, visit the children of the layout object.
    for (LayoutObject* child = layout_object->SlowFirstChild(); child;
         child = child->NextSibling()) {
      if (child->IsAnonymous())
        VisitLayoutTreeNode(child, node, node_index);
    }
  }

  auto layout_tree_node =
      protocol::DOMSnapshot::LayoutTreeNode::create()
          .setDomNodeIndex(node_index)
          .setBoundingBox(LegacyBuildRectForPhysicalRect(
              InspectorDOMSnapshotAgent::RectInDocument(layout_object)))
          .build();

  int style_index = GetStyleIndexForNode(node);
  if (style_index != -1)
    layout_tree_node->setStyleIndex(style_index);

  if (layout_object->Style() && layout_object->IsStackingContext())
    layout_tree_node->setIsStackingContext(true);

  if (paint_order_map_) {
    PaintLayer* paint_layer = layout_object->EnclosingLayer();

    // We visited all PaintLayers when building |paint_order_map_|.
    const auto paint_order = paint_order_map_->find(paint_layer);
    if (paint_order != paint_order_map_->end())
      layout_tree_node->setPaintOrder(paint_order->value);
  }

  if (layout_object->IsText()) {
    auto* layout_text = To<LayoutText>(layout_object);
    layout_tree_node->setLayoutText(layout_text->TransformedText());
    Vector<LayoutText::TextBoxInfo> text_boxes = layout_text->GetTextBoxInfo();
    if (!text_boxes.empty()) {
      auto inline_text_nodes = std::make_unique<
          protocol::Array<protocol::DOMSnapshot::InlineTextBox>>();
      for (const auto& text_box : text_boxes) {
        inline_text_nodes->emplace_back(
            protocol::DOMSnapshot::InlineTextBox::create()
                .setStartCharacterIndex(text_box.dom_start_offset)
                .setNumCharacters(text_box.dom_length)
                .setBoundingBox(LegacyBuildRectForPhysicalRect(
                    InspectorDOMSnapshotAgent::TextFragmentRectInDocument(
                        layout_object, text_box)))
                .build());
      }
      layout_tree_node->setInlineTextNodes(std::move(inline_text_nodes));
    }
  }

  int index = static_cast<int>(layout_tree_nodes_->size());
  layout_tree_nodes_->emplace_back(std::move(layout_tree_node));
  return index;
}

const ComputedStyle* ComputedStyleForNode(Node& node) {
  if (Element* element = DynamicTo<Element>(node)) {
    return element->EnsureComputedStyle();
  }
  if (!node.IsTextNode()) {
    return nullptr;
  }
  if (LayoutObject* layout_object = node.GetLayoutObject()) {
    return layout_object->Style();
  }
  if (Element* parent_element = FlatTreeTraversal::ParentElement(node)) {
    return parent_element->EnsureComputedStyle();
  }
  return nullptr;
}

int LegacyDOMSnapshotAgent::GetStyleIndexForNode(Node* node) {
  CHECK(node);
  const ComputedStyle* computed_style = ComputedStyleForNode(*node);
  if (!computed_style) {
    return -1;
  }
  Vector<String> style;
  bool all_properties_empty = true;
  for (const auto& pair : *css_property_filter_) {
    String value;
    if (const CSSValue* css_value =
            CSSProperty::Get(pair.second)
                .CSSValueFromComputedStyle(*computed_style,
                                           node->GetLayoutObject(), true,
                                           CSSValuePhase::kResolvedValue)) {
      value = css_value->CssText();
    }
    if (!value.empty())
      all_properties_empty = false;
    style.push_back(value);
  }

  // -1 means an empty style.
  if (all_properties_empty)
    return -1;

  ComputedStylesMap::iterator it = computed_styles_map_->find(style);
  if (it != computed_styles_map_->end())
    return it->value;

  // It's a distinct style, so append to |computedStyles|.
  auto style_properties =
      std::make_unique<protocol::Array<protocol::DOMSnapshot::NameValue>>();

  for (wtf_size_t i = 0; i < style.size(); i++) {
    if (style[i].empty())
      continue;
    style_properties->emplace_back(
        protocol::DOMSnapshot::NameValue::create()
            .setName((*css_property_filter_)[i].first)
            .setValue(style[i])
            .build());
  }

  wtf_size_t index = static_cast<wtf_size_t>(computed_styles_->size());
  computed_styles_->emplace_back(protocol::DOMSnapshot::ComputedStyle::create()
                                     .setProperties(std::move(style_properties))
                                     .build());
  computed_styles_map_->insert(std::move(style), index);
  return index;
}

}  // namespace blink
```