Response:
Let's break down the thought process for analyzing this `inspect_tools.cc` file.

1. **Understand the Goal:** The request asks for a functional breakdown of the file, focusing on its relationship with web technologies (HTML, CSS, JavaScript), logical reasoning (input/output), and common usage errors.

2. **Initial Scan and Keywords:**  Quickly read through the file, looking for recurring terms and keywords. "Inspector," "Overlay," "Highlight," "Node," "CSS," "DOM," "Event," and names like `SearchingForNodeTool`, `NodeHighlightTool`, etc., immediately stand out. These suggest the file is about the DevTools inspection functionality within the Blink rendering engine.

3. **Identify Core Classes:**  Note the different classes defined: `SearchingForNodeTool`, `QuadHighlightTool`, `NodeHighlightTool`, `PersistentTool`, `SourceOrderTool`, `NearbyDistanceTool`, `ShowViewSizeTool`, `ScreenshotTool`, `PausedInDebuggerTool`, and `WindowControlsOverlayTool`. Each class likely represents a specific inspection feature.

4. **Analyze Each Class Individually:**  Go through each class and try to determine its purpose based on its methods and member variables.

    * **`SearchingForNodeTool`:**  The name is a big clue. It handles mouse events (`HandleMouseMove`, `HandleMouseDown`) to identify and highlight the node the user is hovering over. The interaction with `InspectorDOMAgent` suggests it's responsible for mapping the visual element to its DOM representation.

    * **`QuadHighlightTool`:** This one seems straightforward. It takes a geometric quad and colors, implying it's for highlighting arbitrary rectangular areas.

    * **`NodeHighlightTool`:**  Similar to `SearchingForNodeTool`, but it seems to be for explicitly highlighting a given node, possibly based on a CSS selector.

    * **`PersistentTool`:** The name "Persistent" and the member variables related to "Grid," "Flex," "Scroll Snap," etc., suggest this tool handles the persistent overlays for these layout features. The `Dispatch` method hints at interactive resizing.

    * **`SourceOrderTool`:** The name and references to "source order" strongly indicate this tool visualizes the order of elements in the DOM.

    * **`NearbyDistanceTool`:**  The name and the `HandleMouseMove` suggest it's about showing distances between elements as the mouse moves.

    * **`ShowViewSizeTool`:** Simple – it displays the viewport size.

    * **`ScreenshotTool`:**  Handles capturing a portion of the screen based on user interaction. The `Dispatch` method handles receiving coordinates from the overlay.

    * **`PausedInDebuggerTool`:** The name and interaction with `v8_inspector::V8InspectorSession` clearly indicate its role in displaying an overlay when the debugger is paused and handling resume/step commands.

    * **`WindowControlsOverlayTool`:**  The name suggests it's related to the browser's window controls overlay feature.

5. **Identify Common Themes and Relationships:**  Look for how these classes interact and what common functionalities they share.

    * **Overlays:** All classes inherit from `InspectTool` and have a `GetOverlayName()` method, indicating they manage different visual overlays on the webpage.
    * **Highlighting:** Several classes deal with highlighting (`SearchingForNodeTool`, `QuadHighlightTool`, `NodeHighlightTool`, `PersistentTool`, `SourceOrderTool`, `NearbyDistanceTool`). They use `InspectorHighlight` to generate the overlay data.
    * **Event Handling:**  `SearchingForNodeTool` and `NearbyDistanceTool` actively handle mouse events.
    * **DOM Interaction:**  `SearchingForNodeTool`, `NodeHighlightTool`, `PersistentTool`, and `SourceOrderTool` heavily interact with the DOM (accessing nodes, querying selectors).
    * **CSS Interaction:**  `FetchContrast` retrieves CSS properties, and `PersistentTool::Dispatch` modifies inline styles.
    * **JavaScript Communication:** The `Dispatch` methods are the primary way these tools receive commands from the DevTools frontend (likely written in JavaScript). The `EvaluateInOverlay` method sends data to the overlay (also likely rendered with web technologies).

6. **Connect to Web Technologies (HTML, CSS, JavaScript):** Explicitly link the functionalities to these technologies.

    * **HTML:** The tools inspect and highlight DOM elements, which are the foundation of HTML structure.
    * **CSS:**  The tools visualize CSS layout features (Grid, Flexbox), retrieve CSS properties for contrast information, and `PersistentTool` can even modify CSS styles. The overlays themselves are likely styled with CSS.
    * **JavaScript:**  The DevTools frontend (written in JavaScript) sends commands to these tools via the `Dispatch` methods. The overlays likely use JavaScript for interactivity.

7. **Identify Logical Reasoning (Input/Output):** For classes that handle events or commands, think about the input and expected output. For example, for `SearchingForNodeTool`:

    * **Input:** Mouse move events with coordinates.
    * **Output:** Highlighting the corresponding DOM node.

    For `ScreenshotTool`:

    * **Input:** Coordinates and dimensions from the DevTools frontend (via `Dispatch`).
    * **Output:** A request to capture a screenshot of that region.

8. **Consider User/Programming Errors:** Think about potential mistakes users or developers might make when interacting with or using these tools (even indirectly through the DevTools UI).

    * **Incorrect Selectors:**  In `NodeHighlightTool`, an invalid CSS selector would lead to no elements being highlighted.
    * **Invalid Coordinates:** In `ScreenshotTool`, providing nonsensical coordinates could cause errors.
    * **Incorrect `Dispatch` Messages:**  In `PersistentTool` and `ScreenshotTool`, malformed JSON messages would be rejected.
    * **Misunderstanding Persistent Overlays:** Users might expect persistent overlays to update dynamically in all situations, but their behavior is tied to the DOM and layout.

9. **Structure the Answer:** Organize the findings logically. Start with a general overview, then detail the functionality of each class, and finally discuss the connections to web technologies, logical reasoning, and potential errors. Use clear headings and bullet points for readability.

10. **Refine and Elaborate:** Review the generated answer and add more specific examples and explanations where needed. Ensure the language is clear and concise. For instance, instead of just saying "handles mouse events," explain *what* it does with those events (identifies and highlights nodes). For the examples, be specific about the expected input and output.

By following these steps, you can systematically analyze the code and produce a comprehensive and accurate description of its functionality, its relation to web technologies, its logical behavior, and potential usage errors.
这个文件 `blink/renderer/core/inspector/inspect_tools.cc` 定义了多个用于 Chrome 开发者工具 (DevTools) **元素面板 (Elements Panel)** 中各种检查和高亮功能的工具类。 它的主要职责是响应来自 DevTools 前端的指令，在渲染引擎的视图上绘制各种高亮覆盖层，帮助开发者理解页面的结构、样式和行为。

以下是文件中定义的主要工具类及其功能，并说明它们与 JavaScript、HTML 和 CSS 的关系：

**1. `SearchingForNodeTool` (查找节点工具)**

* **功能:** 当开发者在 DevTools 的元素面板中使用“选择元素”工具（放大镜图标）时激活。它会在鼠标悬停在页面元素上时，高亮显示该元素及其相关信息（例如标签名、大小）。当点击时，它会将该元素选中并在元素面板中展示。
* **与 Web 技术的关系:**
    * **HTML:**  该工具的核心是识别和高亮 HTML 元素。它会根据鼠标位置找到对应的 DOM 节点。
    * **CSS:** 它会读取元素的计算样式，例如背景色、字体大小等，用于显示对比度信息 (`FetchContrast`)。高亮的外观样式也受到 CSS 的影响。
    * **JavaScript:** DevTools 前端使用 JavaScript 发送指令激活和控制此工具。工具本身通过 Blink 内部机制与 DOM 交互，但这部分不是直接的 JavaScript 代码。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** 鼠标在浏览器窗口坐标 (100, 200) 的位置移动。
    * **输出:**  如果该坐标下存在一个 `<div>` 元素，该工具会高亮显示该 `<div>`，并在 overlay 上显示其标签名 `div` 和尺寸信息。
* **常见使用错误:** 用户可能会误认为高亮框的颜色是元素实际的背景色，但实际上高亮框的颜色是 DevTools 自定义的。

**2. `QuadHighlightTool` (四边形高亮工具)**

* **功能:** 用于高亮页面上的任意四边形区域。这可以用于高亮非标准形状的元素或特定区域。
* **与 Web 技术的关系:**
    * **HTML/CSS:** 虽然可以用于任何区域，但它通常用于高亮与 HTML 元素相关的布局区域，例如元素的内容区域、内边距、边框、外边距等。这些区域的大小和位置由 CSS 决定。
    * **JavaScript:** DevTools 前端可以使用 JavaScript 计算出需要高亮的四边形坐标，然后发送给后端进行绘制。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** DevTools 前端发送指令，包含一个四边形的四个顶点坐标和填充颜色、边框颜色。
    * **输出:**  在浏览器窗口上绘制出带有指定颜色和边框的四边形高亮。

**3. `NodeHighlightTool` (节点高亮工具)**

* **功能:**  用于根据给定的 DOM 节点和可选的 CSS 选择器列表高亮显示一个或多个元素。通常用于在元素面板中选中元素后进行高亮。
* **与 Web 技术的关系:**
    * **HTML:**  直接针对 HTML 元素进行高亮。
    * **CSS:** 可以使用 CSS 选择器来定位需要高亮的元素。工具还会读取被高亮元素的样式信息。
    * **JavaScript:** DevTools 前端使用 JavaScript 发送要高亮的节点 ID 和 CSS 选择器列表。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** DevTools 前端发送指令，指定要高亮 ID 为 "myElement" 的节点，并且使用选择器 ".highlighted" 查找其他需要高亮的元素。
    * **输出:**  ID 为 "myElement" 的元素会被高亮，所有拥有 "highlighted" 类的元素也会被高亮显示。
* **常见使用错误:**  提供的 CSS 选择器可能不正确，导致没有元素被额外高亮。

**4. `PersistentTool` (持久化高亮工具)**

* **功能:** 用于持久化显示一些布局相关的辅助线和高亮，例如 Grid 布局的网格线、Flexbox 布局的辅助线、Scroll Snap 的对齐点、Container Query 的边界以及孤立元素的边界。这些高亮在鼠标移开后仍然保持显示。
* **与 Web 技术的关系:**
    * **HTML:** 关联到应用了 Grid、Flexbox、Scroll Snap 或 Container Query 属性的 HTML 元素。
    * **CSS:**  直接反映了 CSS 布局属性的效果，例如 `display: grid`, `display: flex`, `scroll-snap-type`, `@container` 等。
    * **JavaScript:** DevTools 前端通过 JavaScript 发送配置信息，例如哪些 Grid 容器需要高亮，高亮线的颜色等等。`Dispatch` 方法允许通过 JavaScript 修改孤立元素的尺寸。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** DevTools 前端发送指令，指定要高亮所有 `display: grid` 的元素。
    * **输出:**  所有应用了 `display: grid` 的元素都会被叠加一层网格线高亮。
    * **假设输入:** DevTools 前端发送指令，指定调整某个孤立元素高亮的宽度为 "200px"。
    * **输出:**  该孤立元素的 `width` 样式会被设置为 "200px"。
* **常见使用错误:**  用户可能误以为持久化高亮会动态更新，但实际上它只在特定的事件触发时更新，例如页面重绘或 DevTools 重新发送配置。

**5. `SourceOrderTool` (源代码顺序工具)**

* **功能:** 用于可视化元素的源代码顺序 (tab 键的遍历顺序)。它会高亮显示元素并显示一个数字，表示其在源代码中的相对顺序。
* **与 Web 技术的关系:**
    * **HTML:** 直接关联到 HTML 元素的排列顺序。
    * **CSS:**  尽管 CSS 可以改变元素的视觉呈现顺序，但此工具关注的是 HTML 的源代码顺序。
    * **JavaScript:** DevTools 前端发送指令来激活此工具并指定要分析的父节点。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** DevTools 前端发送指令，指定要分析的 `<div>` 元素。
    * **输出:**  该 `<div>` 元素及其子元素会被高亮，并显示数字表示它们在 `<div>` 元素内的源代码顺序。

**6. `NearbyDistanceTool` (附近距离工具)**

* **功能:**  当鼠标悬停在一个元素上时，显示该元素与其他附近元素之间的距离。
* **与 Web 技术的关系:**
    * **HTML:** 识别鼠标悬停的 HTML 元素以及附近的元素。
    * **CSS:**  依赖于元素的布局信息，例如 margin，padding，border 等，这些由 CSS 决定。
    * **JavaScript:** DevTools 前端激活此工具。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** 鼠标悬停在一个 `<span>` 元素上。
    * **输出:**  会显示该 `<span>` 元素与其他相邻元素（例如文本节点、其他兄弟元素）之间的距离，以像素值表示。

**7. `ShowViewSizeTool` (显示视口大小工具)**

* **功能:**  在页面上显示当前视口的尺寸。
* **与 Web 技术的关系:**
    * **HTML:**  关联到浏览器视口的大小，影响 HTML 页面的布局。
    * **CSS:** 视口大小会影响 CSS 的媒体查询和响应式布局。
    * **JavaScript:**  DevTools 前端激活此工具。

**8. `ScreenshotTool` (截图工具)**

* **功能:**  允许用户在页面上拖拽选择一个区域，并截取该区域的屏幕截图。
* **与 Web 技术的关系:**
    * **HTML:** 截图的内容来自渲染后的 HTML 页面。
    * **CSS:**  截图的内容包含了 CSS 样式渲染后的效果。
    * **JavaScript:** DevTools 前端接收用户拖拽的坐标，并发送给后端处理截图请求。`Dispatch` 方法接收来自 overlay 的截图区域信息。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** 用户在 overlay 上拖拽选择了一个矩形区域，左上角坐标 (10, 20)，宽度 100px，高度 50px。
    * **输出:**  DevTools 前端会收到一个截图请求，包含该矩形区域的坐标和尺寸信息。
* **常见使用错误:**  用户选择的区域可能超出页面可视范围，导致截图不完整。

**9. `PausedInDebuggerTool` (调试器暂停工具)**

* **功能:** 当 JavaScript 代码在断点处暂停时，显示一个覆盖层，提示用户程序已暂停，并提供继续、单步执行等操作按钮。
* **与 Web 技术的关系:**
    * **JavaScript:**  直接与 JavaScript 的调试过程相关。
    * **HTML/CSS:**  覆盖层的 UI 元素可能是用 HTML 和 CSS 构建的。
    * **JavaScript:**  覆盖层上的按钮会触发 DevTools 前端发送继续或单步执行的调试指令。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** JavaScript 代码执行到断点。
    * **输出:**  浏览器窗口上会显示一个半透明的覆盖层，包含“继续”、“单步执行”等按钮。
    * **假设输入:** 用户点击覆盖层上的“继续”按钮。
    * **输出:**  DevTools 前端会发送继续执行的指令给 V8 引擎。

**10. `WindowControlsOverlayTool` (窗口控件叠加层工具)**

* **功能:**  用于在可安装的 Web 应用 (PWAs) 中，自定义窗口控件叠加层 (Window Controls Overlay) 的显示。
* **与 Web 技术的关系:**
    * **HTML:**  与 PWA 的 manifest 文件中关于窗口控件叠加层的配置相关。
    * **CSS:**  可能影响叠加层的样式。
    * **JavaScript:**  DevTools 前端发送配置信息来控制叠加层的显示。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** DevTools 前端发送指令，包含窗口控件叠加层的配置信息。
    * **输出:**  如果 PWA 启用了窗口控件叠加层，会根据配置信息进行显示或隐藏。

**总结:**

`inspect_tools.cc` 文件是 Blink 渲染引擎中 DevTools 元素面板的核心组成部分，它提供了各种工具来帮助开发者检查和理解页面的结构、样式和行为。这些工具与 JavaScript、HTML 和 CSS 紧密相关：

* **HTML:** 大部分工具都直接操作或展示 HTML 元素及其属性。
* **CSS:**  工具会读取元素的 CSS 样式信息，并可视化 CSS 布局特性。
* **JavaScript:** DevTools 前端使用 JavaScript 与这些工具进行通信，发送指令并接收反馈。

该文件通过各种 `InspectTool` 子类实现了不同的检查功能，每个子类负责特定的高亮和信息展示。它们通过 `InspectorOverlayAgent` 与 DevTools 前端进行交互，并在渲染引擎的视图上绘制相应的覆盖层。 这些工具极大地提升了开发者调试和理解网页的能力。

### 提示词
```
这是目录为blink/renderer/core/inspector/inspect_tools.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/inspector/inspect_tools.h"

#include "third_party/blink/public/common/input/web_gesture_event.h"
#include "third_party/blink/public/common/input/web_input_event.h"
#include "third_party/blink/public/common/input/web_keyboard_event.h"
#include "third_party/blink/public/common/input/web_pointer_event.h"
#include "third_party/blink/public/platform/web_input_event_result.h"
#include "third_party/blink/public/resources/grit/inspector_overlay_resources_map.h"
#include "third_party/blink/renderer/bindings/core/v8/dictionary.h"
#include "third_party/blink/renderer/core/css/css_color.h"
#include "third_party/blink/renderer/core/css/css_computed_style_declaration.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/static_node_list.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/root_frame_viewport.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/inspector/inspector_css_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_dom_agent.h"
#include "third_party/blink/renderer/core/inspector/node_content_visibility_state.h"
#include "third_party/blink/renderer/core/layout/flex/layout_flexible_box.h"
#include "third_party/blink/renderer/core/layout/hit_test_location.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/platform/cursors.h"
#include "third_party/blink/renderer/platform/keyboard_codes.h"
#include "third_party/inspector_protocol/crdtp/json.h"
#include "ui/gfx/geometry/point_conversions.h"

namespace blink {

namespace {

static const char kInvalidOverlayCommand[] = "Invalid Overlay command";

InspectorHighlightContrastInfo FetchContrast(Node* node) {
  InspectorHighlightContrastInfo result;
  auto* element = DynamicTo<Element>(node);
  if (!element)
    return result;

  Vector<Color> bgcolors;
  String font_size;
  String font_weight;
  float text_opacity = 1.0f;
  InspectorCSSAgent::GetBackgroundColors(element, &bgcolors, &font_size,
                                         &font_weight, &text_opacity);
  if (bgcolors.size() == 1) {
    result.font_size = font_size;
    result.font_weight = font_weight;
    result.background_color = bgcolors[0];
    result.text_opacity = text_opacity;
  }
  return result;
}

Node* HoveredNodeForPoint(LocalFrame* frame,
                          const gfx::Point& point_in_root_frame,
                          bool ignore_pointer_events_none) {
  HitTestRequest::HitTestRequestType hit_type =
      HitTestRequest::kMove | HitTestRequest::kReadOnly |
      HitTestRequest::kAllowChildFrameContent;
  if (ignore_pointer_events_none)
    hit_type |= HitTestRequest::kIgnorePointerEventsNone;
  HitTestRequest request(hit_type);
  HitTestLocation location(
      frame->View()->ConvertFromRootFrame(point_in_root_frame));
  HitTestResult result(request, location);
  frame->ContentLayoutObject()->HitTest(location, result);
  Node* node = result.InnerPossiblyPseudoNode();
  while (node && node->getNodeType() == Node::kTextNode)
    node = node->parentNode();
  return node;
}

Node* HoveredNodeForEvent(LocalFrame* frame,
                          const WebGestureEvent& event,
                          bool ignore_pointer_events_none) {
  return HoveredNodeForPoint(frame,
                             gfx::ToRoundedPoint(event.PositionInRootFrame()),
                             ignore_pointer_events_none);
}

Node* HoveredNodeForEvent(LocalFrame* frame,
                          const WebMouseEvent& event,
                          bool ignore_pointer_events_none) {
  return HoveredNodeForPoint(frame,
                             gfx::ToRoundedPoint(event.PositionInRootFrame()),
                             ignore_pointer_events_none);
}

Node* HoveredNodeForEvent(LocalFrame* frame,
                          const WebPointerEvent& event,
                          bool ignore_pointer_events_none) {
  WebPointerEvent transformed_point = event.WebPointerEventInRootFrame();
  return HoveredNodeForPoint(
      frame, gfx::ToRoundedPoint(transformed_point.PositionInWidget()),
      ignore_pointer_events_none);
}

bool IsSelfLocked(Node* node) {
  auto* element = DynamicTo<Element>(node);
  if (!element)
    return false;

  auto* context = element->GetDisplayLockContext();
  if (!context)
    return false;

  return context->IsLocked();
}

NodeContentVisibilityState DetermineSelfContentVisibilityState(Node* node) {
  return IsSelfLocked(node) ? NodeContentVisibilityState::kIsLocked
                            : NodeContentVisibilityState::kNone;
}

std::pair<Node*, NodeContentVisibilityState> DetermineContentVisibilityState(
    Node* node) {
  DCHECK(node);
  std::pair<Node*, NodeContentVisibilityState> result;
  if (auto* locked_ancestor =
          DisplayLockUtilities::HighestLockedExclusiveAncestor(*node)) {
    result.first = locked_ancestor;
    result.second = NodeContentVisibilityState::kIsLockedAncestor;
  } else {
    result.first = node;
    result.second = DetermineSelfContentVisibilityState(node);
  }
  return result;
}

}  // namespace

// SearchingForNodeTool --------------------------------------------------------

SearchingForNodeTool::SearchingForNodeTool(InspectorOverlayAgent* overlay,
                                           OverlayFrontend* frontend,
                                           InspectorDOMAgent* dom_agent,
                                           bool ua_shadow,
                                           const std::vector<uint8_t>& config)
    : InspectTool(overlay, frontend),
      dom_agent_(dom_agent),
      ua_shadow_(ua_shadow) {
  auto parsed_config = protocol::Overlay::HighlightConfig::FromBinary(
      config.data(), config.size());
  if (parsed_config) {
    highlight_config_ =
        InspectorOverlayAgent::ToHighlightConfig(parsed_config.get());
  }
}

String SearchingForNodeTool::GetOverlayName() {
  return OverlayNames::OVERLAY_HIGHLIGHT;
}

void SearchingForNodeTool::Trace(Visitor* visitor) const {
  InspectTool::Trace(visitor);
  visitor->Trace(dom_agent_);
  visitor->Trace(hovered_node_);
  visitor->Trace(event_target_node_);
}

void SearchingForNodeTool::Draw(float scale) {
  if (!hovered_node_)
    return;

  Node* node = hovered_node_.Get();

  bool append_element_info = (node->IsElementNode() || node->IsTextNode()) &&
                             !omit_tooltip_ && highlight_config_->show_info &&
                             node->GetLayoutObject() &&
                             node->GetDocument().GetFrame();
  DCHECK(overlay_->HasAXContext(node));
  InspectorHighlight highlight(node, *highlight_config_, contrast_info_,
                               append_element_info, false,
                               content_visibility_state_);
  if (event_target_node_) {
    highlight.AppendEventTargetQuads(event_target_node_.Get(),
                                     *highlight_config_);
  }
  overlay_->EvaluateInOverlay("drawHighlight", highlight.AsProtocolValue());
}

bool SearchingForNodeTool::SupportsPersistentOverlays() {
  return true;
}

bool SearchingForNodeTool::HandleInputEvent(LocalFrameView* frame_view,
                                            const WebInputEvent& input_event,
                                            bool* swallow_next_mouse_up) {
  if (input_event.GetType() == WebInputEvent::Type::kGestureScrollBegin ||
      input_event.GetType() == WebInputEvent::Type::kGestureScrollUpdate ||
      input_event.GetType() == WebInputEvent::Type::kMouseLeave) {
    hovered_node_.Clear();
    event_target_node_.Clear();
    overlay_->ScheduleUpdate();
    return false;
  }
  return InspectTool::HandleInputEvent(frame_view, input_event,
                                       swallow_next_mouse_up);
}

bool SearchingForNodeTool::HandleMouseMove(const WebMouseEvent& event) {
  LocalFrame* frame = overlay_->GetFrame();
  if (!frame || !frame->View() || !frame->ContentLayoutObject())
    return false;
  Node* node = HoveredNodeForEvent(
      frame, event, event.GetModifiers() & WebInputEvent::kShiftKey);

  // Do not highlight within user agent shadow root unless requested.
  if (!ua_shadow_) {
    ShadowRoot* shadow_root = InspectorDOMAgent::UserAgentShadowRoot(node);
    if (shadow_root)
      node = &shadow_root->host();
  }

  // Shadow roots don't have boxes - use host element instead.
  if (node && node->IsShadowRoot())
    node = node->ParentOrShadowHostNode();

  // Keep last behavior if Ctrl + Alt(Gr) key is being pressed.
  bool hold_selected_node =
      (event.GetModifiers() &
       (WebInputEvent::kAltKey | WebInputEvent::kAltGrKey)) &&
      (event.GetModifiers() &
       (WebInputEvent::kControlKey | WebInputEvent::kMetaKey));
  if (!node || hold_selected_node)
    return true;

  std::tie(node, content_visibility_state_) =
      DetermineContentVisibilityState(node);

  if (auto* frame_owner = DynamicTo<HTMLFrameOwnerElement>(node)) {
    if (!IsA<LocalFrame>(frame_owner->ContentFrame())) {
      // Do not consume event so that remote frame can handle it.
      overlay_->hideHighlight();
      hovered_node_.Clear();
      return false;
    }
  }

  // Store values for the highlight.
  bool hovered_node_changed = node != hovered_node_;
  hovered_node_ = node;
  overlay_->EnsureAXContext(node);
  event_target_node_ = (event.GetModifiers() & WebInputEvent::kShiftKey)
                           ? HoveredNodeForEvent(frame, event, false)
                           : nullptr;
  if (event_target_node_ == hovered_node_)
    event_target_node_ = nullptr;
  omit_tooltip_ = event.GetModifiers() &
                  (WebInputEvent::kControlKey | WebInputEvent::kMetaKey);

  contrast_info_ = FetchContrast(node);
  if (hovered_node_changed) {
    if (auto* flexbox = DynamicTo<LayoutFlexibleBox>(node->GetLayoutObject())) {
      flexbox->SetNeedsLayoutForDevtools();
    }
    NodeHighlightRequested(node);
  }
  return true;
}

bool SearchingForNodeTool::HandleMouseDown(const WebMouseEvent& event,
                                           bool* swallow_next_mouse_up) {
  if (hovered_node_) {
    *swallow_next_mouse_up = true;
    overlay_->Inspect(hovered_node_.Get());
    hovered_node_.Clear();
    return true;
  }
  return false;
}

bool SearchingForNodeTool::HandleGestureTapEvent(const WebGestureEvent& event) {
  Node* node = HoveredNodeForEvent(overlay_->GetFrame(), event, false);
  if (node) {
    overlay_->Inspect(node);
    return true;
  }
  return false;
}

bool SearchingForNodeTool::HandlePointerEvent(const WebPointerEvent& event) {
  // Trigger Inspect only when a pointer device is pressed down.
  if (event.GetType() != WebInputEvent::Type::kPointerDown)
    return false;
  Node* node = HoveredNodeForEvent(overlay_->GetFrame(), event, false);
  if (node) {
    overlay_->Inspect(node);
    return true;
  }
  return false;
}

void SearchingForNodeTool::NodeHighlightRequested(Node* node) {
  while (node && !node->IsElementNode() && !node->IsDocumentNode() &&
         !node->IsDocumentFragment())
    node = node->ParentOrShadowHostNode();

  if (!node)
    return;

  int node_id = dom_agent_->PushNodePathToFrontend(node);
  if (node_id)
    frontend_->nodeHighlightRequested(node_id);
}

// QuadHighlightTool -----------------------------------------------------------

QuadHighlightTool::QuadHighlightTool(InspectorOverlayAgent* overlay,
                                     OverlayFrontend* frontend,
                                     std::unique_ptr<gfx::QuadF> quad,
                                     Color color,
                                     Color outline_color)
    : InspectTool(overlay, frontend),
      quad_(std::move(quad)),
      color_(color),
      outline_color_(outline_color) {}

String QuadHighlightTool::GetOverlayName() {
  return OverlayNames::OVERLAY_HIGHLIGHT;
}

bool QuadHighlightTool::ForwardEventsToOverlay() {
  return false;
}

bool QuadHighlightTool::HideOnHideHighlight() {
  return true;
}

void QuadHighlightTool::Draw(float scale) {
  InspectorHighlight highlight(scale);
  highlight.AppendQuad(*quad_, color_, outline_color_);
  overlay_->EvaluateInOverlay("drawHighlight", highlight.AsProtocolValue());
}

// NodeHighlightTool -----------------------------------------------------------

NodeHighlightTool::NodeHighlightTool(
    InspectorOverlayAgent* overlay,
    OverlayFrontend* frontend,
    Member<Node> node,
    String selector_list,
    std::unique_ptr<InspectorHighlightConfig> highlight_config)
    : InspectTool(overlay, frontend),
      selector_list_(selector_list),
      highlight_config_(std::move(highlight_config)) {
  std::tie(node_, content_visibility_state_) =
      DetermineContentVisibilityState(node);
  contrast_info_ = FetchContrast(node_);
  if (auto* flexbox = DynamicTo<LayoutFlexibleBox>(node->GetLayoutObject())) {
    flexbox->SetNeedsLayoutForDevtools();
  }
  overlay_->EnsureAXContext(node);
}

String NodeHighlightTool::GetOverlayName() {
  return OverlayNames::OVERLAY_HIGHLIGHT;
}

bool NodeHighlightTool::ForwardEventsToOverlay() {
  return false;
}

bool NodeHighlightTool::SupportsPersistentOverlays() {
  return true;
}

bool NodeHighlightTool::HideOnHideHighlight() {
  return true;
}

bool NodeHighlightTool::HideOnMouseMove() {
  return true;
}

void NodeHighlightTool::Draw(float scale) {
  DrawNode();
  DrawMatchingSelector();
}

void NodeHighlightTool::DrawNode() {
  bool append_element_info = (node_->IsElementNode() || node_->IsTextNode()) &&
                             highlight_config_->show_info &&
                             node_->GetLayoutObject() &&
                             node_->GetDocument().GetFrame();
  overlay_->EvaluateInOverlay(
      "drawHighlight",
      GetNodeInspectorHighlightAsJson(append_element_info,
                                      false /* append_distance_info */));
}

void NodeHighlightTool::DrawMatchingSelector() {
  if (selector_list_.empty() || !node_)
    return;
  DummyExceptionStateForTesting exception_state;
  ContainerNode* query_base = node_->ContainingShadowRoot();
  if (!query_base)
    query_base = node_->ownerDocument();
  DCHECK(overlay_->HasAXContext(query_base));

  StaticElementList* elements = query_base->QuerySelectorAll(
      AtomicString(selector_list_), exception_state);
  if (exception_state.HadException())
    return;

  for (unsigned i = 0; i < elements->length(); ++i) {
    Element* element = elements->item(i);
    // Skip elements in locked subtrees.
    if (DisplayLockUtilities::LockedAncestorPreventingPaint(*element))
      continue;
    NodeContentVisibilityState content_visibility_state =
        DetermineSelfContentVisibilityState(element);
    InspectorHighlight highlight(element, *highlight_config_, contrast_info_,
                                 false /* append_element_info */,
                                 false /* append_distance_info */,
                                 content_visibility_state);
    overlay_->EvaluateInOverlay("drawHighlight", highlight.AsProtocolValue());
  }
}

void NodeHighlightTool::Trace(Visitor* visitor) const {
  InspectTool::Trace(visitor);
  visitor->Trace(node_);
}

std::unique_ptr<protocol::DictionaryValue>
NodeHighlightTool::GetNodeInspectorHighlightAsJson(
    bool append_element_info,
    bool append_distance_info) const {
  DCHECK(overlay_->HasAXContext(node_.Get()));
  InspectorHighlight highlight(node_.Get(), *highlight_config_, contrast_info_,
                               append_element_info, append_distance_info,
                               content_visibility_state_);
  return highlight.AsProtocolValue();
}

// GridHighlightTool -----------------------------------------------------------
String PersistentTool::GetOverlayName() {
  return OverlayNames::OVERLAY_PERSISTENT;
}

bool PersistentTool::IsEmpty() {
  return !grid_node_highlights_.size() && !flex_container_configs_.size() &&
         !scroll_snap_configs_.size() && !container_query_configs_.size() &&
         !isolated_element_configs_.size();
}

void PersistentTool::SetGridConfigs(GridConfigs configs) {
  grid_node_highlights_ = std::move(configs);
}

void PersistentTool::SetFlexContainerConfigs(FlexContainerConfigs configs) {
  flex_container_configs_ = std::move(configs);
}

void PersistentTool::SetScrollSnapConfigs(ScrollSnapConfigs configs) {
  scroll_snap_configs_ = std::move(configs);
}

void PersistentTool::SetContainerQueryConfigs(ContainerQueryConfigs configs) {
  container_query_configs_ = std::move(configs);
}

void PersistentTool::SetIsolatedElementConfigs(IsolatedElementConfigs configs) {
  isolated_element_configs_ = std::move(configs);
}

bool PersistentTool::ForwardEventsToOverlay() {
  return isolated_element_configs_.size();
}

bool PersistentTool::HideOnHideHighlight() {
  return false;
}

bool PersistentTool::HideOnMouseMove() {
  return false;
}

void PersistentTool::Draw(float scale) {
  for (auto& entry : grid_node_highlights_) {
    std::unique_ptr<protocol::Value> highlight =
        InspectorGridHighlight(entry.key, *(entry.value));
    if (!highlight)
      continue;
    overlay_->EvaluateInOverlay("drawGridHighlight", std::move(highlight));
  }
  for (auto& entry : flex_container_configs_) {
    std::unique_ptr<protocol::Value> highlight =
        InspectorFlexContainerHighlight(entry.key, *(entry.value));
    if (!highlight)
      continue;
    overlay_->EvaluateInOverlay("drawFlexContainerHighlight",
                                std::move(highlight));
  }
  for (auto& entry : scroll_snap_configs_) {
    std::unique_ptr<protocol::Value> highlight =
        InspectorScrollSnapHighlight(entry.key, *(entry.value));
    if (!highlight)
      continue;
    overlay_->EvaluateInOverlay("drawScrollSnapHighlight",
                                std::move(highlight));
  }
  for (auto& entry : container_query_configs_) {
    std::unique_ptr<protocol::Value> highlight =
        InspectorContainerQueryHighlight(entry.key, *(entry.value));
    if (!highlight)
      continue;
    overlay_->EvaluateInOverlay("drawContainerQueryHighlight",
                                std::move(highlight));
  }
  for (auto& entry : isolated_element_configs_) {
    std::unique_ptr<protocol::Value> highlight =
        InspectorIsolatedElementHighlight(entry.key, *(entry.value));
    if (!highlight)
      continue;
    overlay_->EvaluateInOverlay("drawIsolatedElementHighlight",
                                std::move(highlight));
  }
}

// Accepts a message of the following format:
// {
//   highlightType: 'grid'|'flex'|'scrollSnap'|'container'|'isolatedElement',
//   highlightIndex: number,
//   newWidth: string,
//   newHeight: string,
//   resizerType: 'width'|'height'|'bidrection'
// }
// If the message is correct, sets the property inline style according to the
// message.
void PersistentTool::Dispatch(const ScriptValue& message,
                              ExceptionState& exception_state) {
  Dictionary dict(message);

  String highlight_type =
      dict.Get<IDLString>("highlightType", exception_state).value_or("");
  int32_t index =
      dict.Get<IDLLong>("highlightIndex", exception_state).value_or(-1);
  String new_width =
      dict.Get<IDLString>("newWidth", exception_state).value_or("");
  String new_height =
      dict.Get<IDLString>("newHeight", exception_state).value_or("");
  String resizer_type =
      dict.Get<IDLString>("resizerType", exception_state).value_or("");

  if (exception_state.HadException())
    return;

  Element* element = nullptr;
  if (highlight_type == "isolatedElement") {
    for (auto& entry : isolated_element_configs_) {
      if (entry.value->highlight_index == index) {
        element = entry.key;
        break;
      }
    }
  }

  if (!element) {
    exception_state.ThrowRangeError("invalid highlightIndex");
    return;
  }

  if (resizer_type == "width" || resizer_type == "bidirection")
    element->SetInlineStyleProperty(CSSPropertyID::kWidth, new_width, true);
  if (resizer_type == "height" || resizer_type == "bidirection")
    element->SetInlineStyleProperty(CSSPropertyID::kHeight, new_height, true);
}

std::unique_ptr<protocol::DictionaryValue>
PersistentTool::GetGridInspectorHighlightsAsJson() const {
  std::unique_ptr<protocol::ListValue> highlights =
      protocol::ListValue::create();
  for (auto& entry : grid_node_highlights_) {
    std::unique_ptr<protocol::Value> highlight =
        InspectorGridHighlight(entry.key, *(entry.value));
    if (!highlight)
      continue;
    highlights->pushValue(std::move(highlight));
  }
  std::unique_ptr<protocol::DictionaryValue> result =
      protocol::DictionaryValue::create();
  if (highlights->size() > 0) {
    result->setValue("gridHighlights", std::move(highlights));
  }
  return result;
}

void PersistentTool::Trace(Visitor* visitor) const {
  InspectTool::Trace(visitor);
  visitor->Trace(grid_node_highlights_);
  visitor->Trace(flex_container_configs_);
  visitor->Trace(scroll_snap_configs_);
  visitor->Trace(container_query_configs_);
  visitor->Trace(isolated_element_configs_);
}

// SourceOrderTool -----------------------------------------------------------

SourceOrderTool::SourceOrderTool(
    InspectorOverlayAgent* overlay,
    OverlayFrontend* frontend,
    Node* node,
    std::unique_ptr<InspectorSourceOrderConfig> source_order_config)
    : InspectTool(overlay, frontend),
      source_order_config_(std::move(source_order_config)) {
  node_ = DetermineContentVisibilityState(node).first;
}

String SourceOrderTool::GetOverlayName() {
  return OverlayNames::OVERLAY_SOURCE_ORDER;
}

void SourceOrderTool::Draw(float scale) {
  DrawParentNode();

  // Draw child outlines and labels.
  int position_number = 1;
  for (Node& child_node : NodeTraversal::ChildrenOf(*node_)) {
    // Don't draw if it's not an element or is not the direct child of the
    // parent node.
    auto* element = DynamicTo<Element>(child_node);
    if (!element) {
      continue;
    }
    // Don't draw if it's not rendered/would be ignored by a screen reader.
    if (const ComputedStyle* style = element->GetComputedStyle()) {
      if (style->Display() == EDisplay::kNone ||
          style->Visibility() == EVisibility::kHidden) {
        continue;
      }
    }
    DrawNode(element, position_number);
    position_number++;
  }
}

void SourceOrderTool::DrawNode(Node* node, int source_order_position) {
  InspectorSourceOrderHighlight highlight(
      node, source_order_config_->child_outline_color, source_order_position);
  overlay_->EvaluateInOverlay("drawSourceOrder", highlight.AsProtocolValue());
}

void SourceOrderTool::DrawParentNode() {
  InspectorSourceOrderHighlight highlight(
      node_.Get(), source_order_config_->parent_outline_color, 0);
  overlay_->EvaluateInOverlay("drawSourceOrder", highlight.AsProtocolValue());
}

bool SourceOrderTool::HideOnHideHighlight() {
  return true;
}

bool SourceOrderTool::HideOnMouseMove() {
  return false;
}

std::unique_ptr<protocol::DictionaryValue>
SourceOrderTool::GetNodeInspectorSourceOrderHighlightAsJson() const {
  InspectorSourceOrderHighlight highlight(
      node_.Get(), source_order_config_->parent_outline_color, 0);
  return highlight.AsProtocolValue();
}

void SourceOrderTool::Trace(Visitor* visitor) const {
  InspectTool::Trace(visitor);
  visitor->Trace(node_);
}

// NearbyDistanceTool ----------------------------------------------------------

String NearbyDistanceTool::GetOverlayName() {
  return OverlayNames::OVERLAY_DISTANCES;
}

bool NearbyDistanceTool::HandleMouseDown(const WebMouseEvent& event,
                                         bool* swallow_next_mouse_up) {
  return true;
}

bool NearbyDistanceTool::HandleMouseMove(const WebMouseEvent& event) {
  Node* node = HoveredNodeForEvent(overlay_->GetFrame(), event, true);

  // Do not highlight within user agent shadow root
  ShadowRoot* shadow_root = InspectorDOMAgent::UserAgentShadowRoot(node);
  if (shadow_root)
    node = &shadow_root->host();

  // Shadow roots don't have boxes - use host element instead.
  if (node && node->IsShadowRoot())
    node = node->ParentOrShadowHostNode();

  if (!node)
    return true;

  if (auto* frame_owner = DynamicTo<HTMLFrameOwnerElement>(node)) {
    if (!IsA<LocalFrame>(frame_owner->ContentFrame())) {
      // Do not consume event so that remote frame can handle it.
      overlay_->hideHighlight();
      hovered_node_.Clear();
      return false;
    }
  }
  node = DetermineContentVisibilityState(node).first;

  // Store values for the highlight.
  hovered_node_ = node;
  overlay_->EnsureAXContext(node);
  return true;
}

bool NearbyDistanceTool::HandleMouseUp(const WebMouseEvent& event) {
  return true;
}

void NearbyDistanceTool::Draw(float scale) {
  Node* node = hovered_node_.Get();
  if (!node)
    return;
  DCHECK(overlay_->HasAXContext(node));
  auto content_visibility_state = DetermineSelfContentVisibilityState(node);
  InspectorHighlight highlight(
      node, InspectorHighlight::DefaultConfig(),
      InspectorHighlightContrastInfo(), false /* append_element_info */,
      true /* append_distance_info */, content_visibility_state);
  overlay_->EvaluateInOverlay("drawDistances", highlight.AsProtocolValue());
}

void NearbyDistanceTool::Trace(Visitor* visitor) const {
  InspectTool::Trace(visitor);
  visitor->Trace(hovered_node_);
}

// ShowViewSizeTool ------------------------------------------------------------

void ShowViewSizeTool::Draw(float scale) {
  overlay_->EvaluateInOverlay("drawViewSize", "");
}

String ShowViewSizeTool::GetOverlayName() {
  return OverlayNames::OVERLAY_VIEWPORT_SIZE;
}

bool ShowViewSizeTool::ForwardEventsToOverlay() {
  return false;
}

// ScreenshotTool --------------------------------------------------------------

ScreenshotTool::ScreenshotTool(InspectorOverlayAgent* overlay,
                               OverlayFrontend* frontend)
    : InspectTool(overlay, frontend) {
  auto& client = overlay_->GetFrame()->GetPage()->GetChromeClient();
  client.SetCursorOverridden(false);
  client.SetCursor(CrossCursor(), overlay_->GetFrame());
  client.SetCursorOverridden(true);
}

String ScreenshotTool::GetOverlayName() {
  return OverlayNames::OVERLAY_SCREENSHOT;
}

void ScreenshotTool::Dispatch(const ScriptValue& message,
                              ExceptionState& exception_state) {
  Dictionary dict(message);

  auto x = dict.Get<IDLLong>("x", exception_state);
  if (exception_state.HadException())
    return;
  auto y = dict.Get<IDLLong>("y", exception_state);
  if (exception_state.HadException())
    return;
  auto width = dict.Get<IDLLong>("width", exception_state);
  if (exception_state.HadException())
    return;
  auto height = dict.Get<IDLLong>("height", exception_state);
  if (exception_state.HadException())
    return;

  if (!x || !y || !width || !height) {
    exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                      kInvalidOverlayCommand);
    return;
  }

  gfx::Point p1(*x, *y);
  gfx::Point p2(*x + *width, *y + *height);

  float scale = 1.0f;

  if (LocalFrame* frame = overlay_->GetFrame()) {
    float emulation_scale = overlay_->GetFrame()
                                ->GetPage()
                                ->GetChromeClient()
                                .InputEventsScaleForEmulation();
    // Convert from overlay terms into the absolute.
    p1 = gfx::ScaleToRoundedPoint(p1, 1 / emulation_scale);
    p2 = gfx::ScaleToRoundedPoint(p2, 1 / emulation_scale);

    // Scroll offset in the viewport is in the device pixels, convert before
    // calling ViewportToRootFrame.
    float dip_to_dp = overlay_->WindowToViewportScale();
    p1 = gfx::ScaleToRoundedPoint(p1, dip_to_dp);
    p2 = gfx::ScaleToRoundedPoint(p2, dip_to_dp);

    const VisualViewport& visual_viewport =
        frame->GetPage()->GetVisualViewport();
    p1 = visual_viewport.ViewportToRootFrame(p1);
    p2 = visual_viewport.ViewportToRootFrame(p2);

    scale = frame->GetPage()->PageScaleFactor();
    if (const RootFrameViewport* root_frame_viewport =
            frame->View()->GetRootFrameViewport()) {
      gfx::Vector2d scroll_offset = gfx::ToFlooredVector2d(
          root_frame_viewport->LayoutViewport().GetScrollOffset());
      // Accunt for the layout scroll (different from viewport scroll offset).
      p1 += scroll_offset;
      p2 += scroll_offset;
    }
  }

  // Go back to dip for the protocol.
  float dp_to_dip = 1.f / overlay_->WindowToViewportScale();
  p1 = gfx::ScaleToRoundedPoint(p1, dp_to_dip);
  p2 = gfx::ScaleToRoundedPoint(p2, dp_to_dip);

  // Points are in device independent pixels (dip) now.
  gfx::Rect rect = UnionRectsEvenIfEmpty(gfx::Rect(p1, gfx::Size()),
                                         gfx::Rect(p2, gfx::Size()));
  frontend_->screenshotRequested(protocol::Page::Viewport::create()
                                     .setX(rect.x())
                                     .setY(rect.y())
                                     .setWidth(rect.width())
                                     .setHeight(rect.height())
                                     .setScale(scale)
                                     .build());
}

// PausedInDebuggerTool --------------------------------------------------------

String PausedInDebuggerTool::GetOverlayName() {
  return OverlayNames::OVERLAY_PAUSED;
}

void PausedInDebuggerTool::Draw(float scale) {
  overlay_->EvaluateInOverlay("drawPausedInDebuggerMessage", message_);
}

void PausedInDebuggerTool::Dispatch(const ScriptValue& message,
                                    ExceptionState& exception_state) {
  String message_string;
  if (message.ToString(message_string)) {
    auto task_runner =
        overlay_->GetFrame()->GetTaskRunner(TaskType::kInternalInspector);
    if (message_string == "resume") {
      task_runner->PostTask(
          FROM_HERE, WTF::BindOnce(&v8_inspector::V8InspectorSession::resume,
                                   WTF::Unretained(v8_session_),
                                   /* setTerminateOnResume */ false));
      return;
    }
    if (message_string == "stepOver") {
      task_runner->PostTask(
          FROM_HERE, WTF::BindOnce(&v8_inspector::V8InspectorSession::stepOver,
                                   WTF::Unretained(v8_session_)));
      return;
    }
  }
  exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                    kInvalidOverlayCommand);
}

// WcoTool --------------------------------------------------------

WindowControlsOverlayTool::WindowControlsOverlayTool(
    InspectorOverlayAgent* overlay,
    OverlayFrontend* frontend,
    std::unique_ptr<protocol::DictionaryValue> wco_config)
    : InspectTool(overlay, frontend), wco_config_(std::move(wco_config)) {}

String WindowControlsOverlayTool::GetOverlayName() {
  return OverlayNames::OVERLAY_WINDOW_CONTROLS_OVERLAY;
}

void WindowControlsOverlayTool::Draw(float scale) {
  overlay_->EvaluateInOverlay("drawWindowControlsOverlay",
                              wco_config_->clone());
}

}  // namespace blink
```