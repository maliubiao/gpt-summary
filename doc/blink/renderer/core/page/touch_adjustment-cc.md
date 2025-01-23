Response:
Let's break down the thought process for analyzing the `touch_adjustment.cc` file.

1. **Understand the Goal:** The core request is to analyze the functionality of this specific Chromium Blink engine source file. This involves identifying its purpose, how it interacts with other web technologies, its internal logic, potential errors, and how it's invoked.

2. **Initial Skim and Keyword Identification:** Quickly read through the code, looking for obvious keywords and patterns. Notice things like:
    * `#include`:  This tells us the file depends on other Blink components related to DOM, editing, layout, pages, styles, and platform utilities (text, geometry).
    * Namespaces: `blink::touch_adjustment`. This clearly defines the area of functionality.
    * Constants: `kZeroTolerance`, `kMaxAdjustmentSizeDip`, `kMinAdjustmentSizeDip`. These hint at numerical calculations and limits related to touch interactions.
    * Class `SubtargetGeometry`:  This suggests the file deals with identifying and tracking specific interactive elements.
    * Functions with names like `NodeRespondsToTapGesture`, `NodeIsZoomTarget`, `ProvidesContextMenuItems`, `CompileSubtargetList`, `FindNodeWithLowestDistanceMetric`, `FindBestCandidate`, `FindBestTouchAdjustmentCandidate`, `GetHitTestRectForAdjustment`. These are the core operations of the file.
    * Comments: The initial copyright notice and the `TODO` comment provide some context.

3. **Identify Core Functionality - The "What":** Based on the keywords and function names, the central theme appears to be **adjusting touch targets**. The file seems to be about determining the intended target of a touch event, especially when the touch isn't perfectly precise.

4. **Deconstruct Key Functions - The "How":**  Focus on the most important functions to understand their logic:
    * **`NodeRespondsToTapGesture`:**  This function determines if a node is interactive and should be considered for touch adjustment. It checks for event listeners, focusability, and CSS effects.
    * **`NodeIsZoomTarget`:**  Identifies elements suitable for zoom gestures.
    * **`ProvidesContextMenuItems`:** Determines if a node should have a context menu.
    * **`CompileSubtargetList`:**  This is a crucial function. It iterates through intersected nodes and identifies the "responders" (nodes that handle touch events). It seems to prioritize the innermost interactive elements. The logic involving `responder_map` and `ancestors_to_responders_set` is about optimizing this search.
    * **`FindNodeWithLowestDistanceMetric`:** This function calculates a "distance metric" to determine how well a touch event matches a potential target. It uses a `DistanceFunction` (like `HybridDistanceFunction`). The `SnapTo` function helps adjust the touch point to be within the target's bounds.
    * **`HybridDistanceFunction`:** This function combines the distance to the target with the area of overlap between the touch area and the target. This is a key part of the adjustment logic.
    * **`FindBestCandidate`:**  Orchestrates the process of compiling subtargets and finding the best one using the distance metric.
    * **`FindBestTouchAdjustmentCandidate`:** Acts as a central entry point, selecting the appropriate filters and functions based on the `TouchAdjustmentCandidateType`.
    * **`GetHitTestRectForAdjustment`:**  Calculates the effective touch area based on device scale factor and page scale factor, with minimum and maximum size constraints.

5. **Relate to Web Technologies - The "Why":**  Consider how this functionality relates to JavaScript, HTML, and CSS:
    * **JavaScript:** Touch events in JavaScript (e.g., `touchstart`, `touchend`, `click`) are the triggers for this code. The adjusted target and point might be what the JavaScript event handler ultimately receives.
    * **HTML:** The structure of the HTML document determines the hierarchy of nodes that are being considered for touch adjustment. The types of elements (links, buttons, text fields, etc.) influence whether they are considered interactive.
    * **CSS:** CSS properties like `pointer-events`, `:hover`, `:active`, and touch-action directly affect the behavior considered by the touch adjustment logic. Layout and sizing of elements, crucial for hit-testing, are also determined by CSS.

6. **Logical Reasoning and Examples:**  Think about specific scenarios to illustrate the file's behavior. Consider edge cases and how the algorithms might behave:
    * **Overlapping links:**  The logic to prioritize the inner-most element is relevant here.
    * **Small touch targets:** The adjustment logic aims to make these easier to interact with.
    * **Text selection:** The special handling of text nodes for context menus is a good example.
    * **Zooming:** The `ZoomableIntersectionQuotient` function highlights the zoom-related functionality.

7. **Identify Potential Errors:** Consider common mistakes developers or users might make that could interact with this code:
    * **Tiny interactive elements:** While the code tries to help, extremely small targets can still be difficult.
    * **Overlapping interactive elements:** While the logic tries to resolve this, complex overlaps could lead to unexpected behavior.
    * **Incorrectly set `touch-action`:** Blocking panning when it's needed could lead to issues.
    * **Assumptions about touch area size:** Developers might assume a larger touch target than what's actually used by the browser.

8. **Debugging and User Flow:** Trace a hypothetical user action to see how the code might be reached. Start with a touch event and follow the path through the browser's event handling mechanisms to the hit-testing and finally to the touch adjustment logic.

9. **Structure the Answer:** Organize the findings logically with clear headings and examples. Start with a high-level summary of the file's purpose and then delve into more detail. Use bullet points, code snippets (where appropriate), and concrete examples to make the explanation clear and easy to understand.

10. **Review and Refine:** After drafting the initial answer, review it for clarity, accuracy, and completeness. Ensure that the explanations are easy to follow and that all aspects of the request have been addressed. For example, double-check the examples, the assumptions for input/output, and the debugging steps.

By following this structured approach, we can thoroughly analyze the `touch_adjustment.cc` file and provide a comprehensive explanation of its functionality.
这个文件 `blink/renderer/core/page/touch_adjustment.cc` 的主要功能是**优化触摸事件的目标，以提高用户在触摸设备上的交互体验，特别是对于小而密集的交互元素。** 它通过分析触摸点周围的潜在目标，并根据一定的算法调整触摸事件的目标和坐标，使其更准确地指向用户期望的元素。

以下是该文件的详细功能列表和说明：

**1. 目标识别和过滤 (Target Identification and Filtering):**

* **`NodeRespondsToTapGesture(Node* node)`:**  判断一个 DOM 节点是否响应 tap 手势。这包括：
    * 节点是否监听鼠标点击或移动事件 (`WillRespondToMouseClickEvents`, `WillRespondToMouseMoveEvents`).
    * 元素是否可获得鼠标焦点 (`IsMouseFocusable`)，排除 `iframe` 元素。
    * 元素是否具有触摸时的 CSS 效果，例如 `:hover` 或 `:active` 伪类影响子元素或兄弟元素，或者自身具有这些伪类效果。
* **`NodeIsZoomTarget(Node* node)`:** 判断一个 DOM 节点是否是缩放的目标。文本节点和 ShadowRoot 不是缩放目标。
* **`ProvidesContextMenuItems(Node* node)`:** 判断一个 DOM 节点是否提供上下文菜单项。这包括可编辑内容、链接、图片、媒体元素和 SVG 图片。对于可选择的节点，只有在上下文菜单手势将触发选择时才返回 true，或者节点已经被选择。
* **`NodeRespondsToTapOrMove(Node* node)`:** 判断一个节点是否响应 tap 或 move 事件。除了 `NodeRespondsToTapGesture` 覆盖的情况，还包括 `touch-action` CSS 属性阻止了 pan 手势的元素以及可使用触控笔写入的元素。

**2. 构建潜在目标列表 (Building the List of Potential Targets):**

* **`CompileSubtargetList(...)`:**  这是核心功能之一。它接收一组被触摸点相交的节点，并构建一个更精细的 "子目标" 列表。
    * 它使用 `node_filter` (如 `NodeRespondsToTapGesture`) 来识别实际处理触摸事件的 "响应者" 节点。
    * 它考虑了事件冒泡，优先选择最内层的事件处理者。
    * 它处理可编辑内容，将相邻的可编辑内容视为一个整体。
    * 它使用 `append_subtargets_for_node` (如 `AppendBasicSubtargetsForNode` 或 `AppendContextSubtargetsForNode`) 为每个响应者节点添加子目标。
* **`AppendBasicSubtargetsForNode(Node* node, SubtargetGeometryList& subtargets)`:** 为一个节点添加基本的子目标，通常是节点的所有绝对布局区域 (`AbsoluteQuads`)。
* **`AppendContextSubtargetsForNode(Node* node, SubtargetGeometryList& subtargets)`:** 为提供上下文菜单项的节点添加子目标。对于文本节点，如果启用了上下文菜单点击选择，则将每个单词作为单独的子目标；如果文本被选中，则只添加选中部分的子目标。

**3. 计算距离和选择最佳目标 (Calculating Distance and Selecting the Best Target):**

* **`ZoomableIntersectionQuotient(...)`:**  计算目标区域与触摸区域交集的商。用于评估缩放目标的适合程度。
* **`HybridDistanceFunction(...)`:**  计算触摸热点到目标区域的混合距离。它结合了触摸点到目标边缘的距离和触摸区域与目标区域的交集比例。这是用于选择最佳触摸目标的关键算法。
* **`SnapTo(...)`:**  尝试将触摸点 "吸附" 到目标元素的边界内。如果触摸点已经在目标内，则保持不变。如果触摸区域与目标相交，则将触摸点移动到交集区域的中心。对于非矩形的 `quad`，会进行更复杂的调整。
* **`FindNodeWithLowestDistanceMetric(...)`:**  在子目标列表中找到具有最低距离度量的节点。它使用提供的 `distance_function` (如 `HybridDistanceFunction`) 计算每个子目标的距离，并使用 `SnapTo` 调整触摸点。它还优先选择最内层的元素。
* **`FindBestCandidate(...)`:**  调用 `CompileSubtargetList` 构建子目标列表，然后调用 `FindNodeWithLowestDistanceMetric` 找到最佳候选目标。
* **`FindBestTouchAdjustmentCandidate(...)`:**  根据 `TouchAdjustmentCandidateType` 选择合适的节点过滤器和子目标添加方法，并调用 `FindBestCandidate` 找到最佳的触摸调整候选目标。`TouchAdjustmentCandidateType` 可以是：
    * `kClickable`: 用于调整点击目标。
    * `kContextMenu`: 用于调整上下文菜单目标。
    * `kStylusWritable`: 用于调整触控笔可写的目标。

**4. 获取调整后的触摸区域 (Getting the Adjusted Touch Area):**

* **`GetHitTestRectForAdjustment(...)`:**  根据设备像素比、页面缩放比例以及预定义的最大和最小调整尺寸（以 DIP 为单位），计算用于触摸调整的实际触摸区域。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:** 当用户触摸屏幕时，浏览器会生成触摸事件（例如 `touchstart`, `touchend`）。Blink 引擎会处理这些事件，并可能调用 `touch_adjustment.cc` 中的代码来确定实际的目标元素。调整后的目标和坐标可能会传递给 JavaScript 事件处理程序，从而影响 JavaScript 代码的执行。例如，如果用户触摸两个紧密排列的链接的边缘，触摸调整可能会将事件目标调整为用户期望点击的链接，即使原始触摸点更靠近另一个链接。
* **HTML:** HTML 定义了页面的结构和元素。`touch_adjustment.cc` 中的代码会检查 HTML 元素的属性和层叠关系，以确定哪些元素是潜在的交互目标。例如，`<a>` 标签定义的链接会被识别为可点击的目标。
* **CSS:** CSS 影响元素的布局、大小和外观。`touch_adjustment.cc` 中的代码会考虑 CSS 样式，例如：
    * **`pointer-events` 属性:** 如果一个元素设置了 `pointer-events: none;`，它将不会被视为触摸调整的目标。
    * **`:hover` 和 `:active` 伪类:**  `NodeRespondsToTapGesture` 会检查元素是否具有这些伪类效果，以判断是否应该进行触摸调整。
    * **`touch-action` 属性:** `NodeRespondsToTapOrMove` 会考虑 `touch-action` 属性来确定是否阻止了某些触摸行为（如 pan）。
    * **元素的布局和尺寸:**  `CompileSubtargetList` 和距离计算函数依赖于元素的布局信息来确定其边界和与其他元素的重叠情况。

**逻辑推理示例 (假设输入与输出):**

**假设输入:**

* 用户触摸屏幕上的点 (x: 100, y: 150)。
* 在该点附近有两个非常靠近的链接：
    * 链接 A 的边界框：(left: 90, top: 140, right: 110, bottom: 160)
    * 链接 B 的边界框：(left: 115, top: 145, right: 135, bottom: 155)
* 触摸区域的大小（由 `GetHitTestRectForAdjustment` 计算得出）。

**逻辑推理:**

1. **相交节点识别:** Blink 引擎会识别出触摸点与链接 A 的边界框相交。
2. **构建子目标列表:** `CompileSubtargetList` 会将链接 A 添加为潜在目标，并可能考虑其内部的文本节点作为更精细的子目标。
3. **计算距离:** `HybridDistanceFunction` 会计算触摸点到链接 A 的距离度量。
4. **调整触摸点 (SnapTo):** 由于触摸点在链接 A 的边界内，`SnapTo` 可能会保持触摸点不变。
5. **选择最佳目标:** 如果没有其他更合适的候选者，链接 A 将被选为最佳目标。

**假设输出:**

* 调整后的触摸事件的目标是链接 A 的 DOM 节点。
* 调整后的触摸点坐标可能保持不变，因为原始触摸点已经接近链接 A 的中心。

**用户或编程常见的使用错误示例:**

* **错误地设置 `touch-action: none;` 在需要交互的元素上:** 这会导致元素完全不响应触摸事件，触摸调整也无法生效，用户会觉得点击没有反应。
* **创建非常小的交互元素，没有足够的 padding 或 margin:** 即使触摸调整会尽力优化，过小的目标仍然难以精确点击，可能导致用户误触其他元素。
* **假设触摸目标总是精确的:** 开发者不应该假设用户触摸的坐标总是准确地落在目标元素的中心。触摸调整的存在是为了解决触摸的不精确性。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户触摸屏幕:** 用户用手指或触控笔触摸触摸屏设备。
2. **操作系统捕获触摸事件:** 操作系统（例如 Android, iOS, Windows）会捕获硬件产生的触摸事件。
3. **浏览器进程接收触摸事件:** 操作系统将触摸事件传递给浏览器的渲染器进程。
4. **Blink 引擎处理触摸事件:** Blink 引擎的输入处理模块会接收这些触摸事件。
5. **Hit Testing (命中测试):** Blink 引擎会进行命中测试，确定触摸点下的初始 DOM 元素。
6. **调用 `touch_adjustment.cc`:** 如果需要进行触摸调整（例如，触摸目标较小或密集），Blink 引擎可能会调用 `FindBestTouchAdjustmentCandidate` 或相关的函数。
7. **构建子目标列表和计算距离:**  `touch_adjustment.cc` 中的函数会构建潜在目标列表并计算距离度量。
8. **选择最佳目标并调整触摸点:** 根据计算结果，选择最合适的交互目标，并可能调整触摸事件的坐标。
9. **触发事件处理程序:** 最终，调整后的触摸事件（包括目标和坐标）会被分发到相应的 JavaScript 事件处理程序或其他浏览器内部的事件处理逻辑。

在调试与触摸事件相关的问题时，可以关注以下线索：

* **事件监听器:**  检查目标元素及其祖先元素上注册了哪些触摸事件监听器。
* **CSS 样式:**  检查目标元素的 CSS 样式，特别是 `pointer-events` 和 `touch-action` 属性。
* **布局信息:**  使用开发者工具查看元素的布局信息，包括其边界框和与其他元素的重叠情况。
* **断点调试:** 在 `touch_adjustment.cc` 中的关键函数（例如 `CompileSubtargetList`, `HybridDistanceFunction`, `FindBestTouchAdjustmentCandidate`) 设置断点，可以逐步跟踪触摸事件的处理过程，了解触摸调整是如何进行的。

总而言之，`touch_adjustment.cc` 是 Blink 引擎中一个至关重要的组件，它通过复杂的算法和逻辑，显著提升了触摸设备上的用户交互体验，尤其是在处理小而密集的交互元素时。理解其功能有助于开发者更好地设计和优化移动端的网页和应用。

### 提示词
```
这是目录为blink/renderer/core/page/touch_adjustment.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2012 Nokia Corporation and/or its subsidiary(-ies)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/page/touch_adjustment.h"

#include "third_party/blink/renderer/core/dom/container_node.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/editing_behavior.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/input/touch_action_util.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/text/text_break_iterator.h"
#include "ui/display/screen_info.h"
#include "ui/gfx/geometry/point_conversions.h"
#include "ui/gfx/geometry/point_f.h"
#include "ui/gfx/geometry/quad_f.h"
#include "ui/gfx/geometry/rect_conversions.h"
#include "ui/gfx/geometry/size.h"

namespace blink {

namespace touch_adjustment {

const float kZeroTolerance = 1e-6f;
// The touch adjustment range (diameters) in dip, using same as the value in
// gesture_configuration_android.cc
constexpr LayoutUnit kMaxAdjustmentSizeDip(32);
constexpr LayoutUnit kMinAdjustmentSizeDip(20);

// Class for remembering absolute quads of a target node and what node they
// represent.
class SubtargetGeometry {
  DISALLOW_NEW();

 public:
  SubtargetGeometry(Node* node, const gfx::QuadF& quad)
      : node_(node), quad_(quad) {}
  void Trace(Visitor* visitor) const { visitor->Trace(node_); }

  Node* GetNode() const { return node_.Get(); }
  gfx::QuadF Quad() const { return quad_; }
  gfx::Rect BoundingBox() const {
    return gfx::ToEnclosingRect(quad_.BoundingBox());
  }

 private:
  Member<Node> node_;
  gfx::QuadF quad_;
};

}  // namespace touch_adjustment

}  // namespace blink

WTF_ALLOW_MOVE_INIT_AND_COMPARE_WITH_MEM_FUNCTIONS(
    blink::touch_adjustment::SubtargetGeometry)

namespace blink {

namespace touch_adjustment {

typedef HeapVector<SubtargetGeometry> SubtargetGeometryList;
typedef bool (*NodeFilter)(Node*);
typedef void (*AppendSubtargetsForNode)(Node*, SubtargetGeometryList&);
typedef float (*DistanceFunction)(const gfx::Point&,
                                  const gfx::Rect&,
                                  const SubtargetGeometry&);

// Takes non-const |Node*| because |Node::WillRespondToMouseClickEvents()| is
// non-const.
bool NodeRespondsToTapGesture(Node* node) {
  if (node->WillRespondToMouseClickEvents() ||
      node->WillRespondToMouseMoveEvents())
    return true;
  if (auto* element = DynamicTo<Element>(node)) {
    // Tapping on a text field or other focusable item should trigger
    // adjustment, except that iframe elements are hard-coded to support focus
    // but the effect is often invisible so they should be excluded.
    if (element->IsMouseFocusable() && !IsA<HTMLIFrameElement>(element)) {
      return true;
    }
    // Accept nodes that has a CSS effect when touched.
    if (element->ChildrenOrSiblingsAffectedByActive() ||
        element->ChildrenOrSiblingsAffectedByHover()) {
      return true;
    }
    if (const ComputedStyle* computed_style = element->GetComputedStyle()) {
      if (computed_style->AffectedByActive() ||
          computed_style->AffectedByHover()) {
        return true;
      }
    }
  }
  return false;
}

bool NodeIsZoomTarget(Node* node) {
  if (node->IsTextNode() || node->IsShadowRoot())
    return false;

  DCHECK(node->GetLayoutObject());
  return node->GetLayoutObject()->IsBox();
}

bool ProvidesContextMenuItems(Node* node) {
  // This function tries to match the nodes that receive special context-menu
  // items in ContextMenuController::ShowContextMenu(), and should be kept up
  // to date with those.
  DCHECK(node->GetLayoutObject() || node->IsShadowRoot());
  if (!node->GetLayoutObject())
    return false;
  node->GetDocument().UpdateStyleAndLayoutTree();
  if (IsEditable(*node))
    return true;
  if (node->IsLink())
    return true;
  if (node->GetLayoutObject()->IsImage())
    return true;
  if (node->GetLayoutObject()->IsMedia())
    return true;
  if (node->GetLayoutObject()->IsSVGImage()) {
    return true;
  }
  if (node->GetLayoutObject()->CanBeSelectionLeaf()) {
    // If the context menu gesture will trigger a selection all selectable nodes
    // are valid targets.
    if (node->GetLayoutObject()
            ->GetFrame()
            ->GetEditor()
            .Behavior()
            .ShouldSelectOnContextualMenuClick())
      return true;
    // Only the selected part of the layoutObject is a valid target, but this
    // will be corrected in appendContextSubtargetsForNode.
    if (node->GetLayoutObject()->IsSelected())
      return true;
  }
  return false;
}

bool NodeRespondsToTapOrMove(Node* node) {
  // This method considers nodes from NodeRespondsToTapGesture, those where pan
  // touch action is disabled, and ones that are stylus writable. We do this to
  // avoid adjusting the pointer position on drawable area or slidable control
  // to the nearby writable input node.
  node->GetDocument().UpdateStyleAndLayoutTree();

  if (NodeRespondsToTapGesture(node))
    return true;

  TouchAction effective_touch_action =
      touch_action_util::ComputeEffectiveTouchAction(*node);

  if ((effective_touch_action & TouchAction::kPan) != TouchAction::kPan)
    return true;

  if ((effective_touch_action & TouchAction::kInternalNotWritable) !=
      TouchAction::kInternalNotWritable) {
    return true;
  }
  return false;
}

static inline void AppendQuadsToSubtargetList(
    Vector<gfx::QuadF>& quads,
    Node* node,
    SubtargetGeometryList& subtargets) {
  for (const auto& quad : quads) {
    subtargets.push_back(SubtargetGeometry(node, quad));
  }
}

static inline void AppendBasicSubtargetsForNode(
    Node* node,
    SubtargetGeometryList& subtargets) {
  // Node guaranteed to have layoutObject due to check in node filter.
  DCHECK(node->GetLayoutObject());

  Vector<gfx::QuadF> quads;
  node->GetLayoutObject()->AbsoluteQuads(quads);

  AppendQuadsToSubtargetList(quads, node, subtargets);
}

static inline void AppendContextSubtargetsForNode(
    Node* node,
    SubtargetGeometryList& subtargets) {
  // This is a variant of appendBasicSubtargetsForNode that adds special
  // subtargets for selected or auto-selectable parts of text nodes.
  DCHECK(node->GetLayoutObject());

  auto* text_node = DynamicTo<Text>(node);
  if (!text_node)
    return AppendBasicSubtargetsForNode(node, subtargets);

  LayoutText* text_layout_object = text_node->GetLayoutObject();

  if (text_layout_object->GetFrame()
          ->GetEditor()
          .Behavior()
          .ShouldSelectOnContextualMenuClick()) {
    // Make subtargets out of every word.
    String text_value = text_node->data();
    TextBreakIterator* word_iterator =
        WordBreakIterator(text_value, 0, text_value.length());
    int last_offset = word_iterator->first();
    if (last_offset == -1)
      return;
    int offset;
    while ((offset = word_iterator->next()) != -1) {
      if (IsWordTextBreak(word_iterator)) {
        Vector<gfx::QuadF> quads;
        text_layout_object->AbsoluteQuadsForRange(quads, last_offset, offset);
        AppendQuadsToSubtargetList(quads, text_node, subtargets);
      }
      last_offset = offset;
    }
  } else {
    if (!text_layout_object->IsSelected())
      return AppendBasicSubtargetsForNode(node, subtargets);
    const FrameSelection& frame_selection =
        text_layout_object->GetFrame()->Selection();
    const LayoutTextSelectionStatus& selection_status =
        frame_selection.ComputeLayoutSelectionStatus(*text_layout_object);
    // If selected, make subtargets out of only the selected part of the text.
    Vector<gfx::QuadF> quads;
    text_layout_object->AbsoluteQuadsForRange(quads, selection_status.start,
                                              selection_status.end);
    AppendQuadsToSubtargetList(quads, text_node, subtargets);
  }
}

static inline Node* ParentShadowHostOrOwner(const Node* node) {
  if (Node* ancestor = node->ParentOrShadowHostNode())
    return ancestor;
  if (auto* document = DynamicTo<Document>(node))
    return document->LocalOwner();
  return nullptr;
}

// Compiles a list of subtargets of all the relevant target nodes.
void CompileSubtargetList(const HeapVector<Member<Node>>& intersected_nodes,
                          SubtargetGeometryList& subtargets,
                          NodeFilter node_filter,
                          AppendSubtargetsForNode append_subtargets_for_node) {
  // Find candidates responding to tap gesture events in O(n) time.
  HeapHashMap<Member<Node>, Member<Node>> responder_map;
  HeapHashSet<Member<Node>> ancestors_to_responders_set;
  HeapVector<Member<Node>> candidates;
  HeapHashSet<Member<Node>> editable_ancestors;

  // A node matching the NodeFilter is called a responder. Candidate nodes must
  // either be a responder or have an ancestor that is a responder.  This
  // iteration tests all ancestors at most once by caching earlier results.
  for (unsigned i = 0; i < intersected_nodes.size(); ++i) {
    Node* node = intersected_nodes[i].Get();
    HeapVector<Member<Node>> visited_nodes;
    Node* responding_node = nullptr;
    for (Node* visited_node = node; visited_node;
         visited_node = visited_node->ParentOrShadowHostNode()) {
      // Check if we already have a result for a common ancestor from another
      // candidate.
      const auto it = responder_map.find(visited_node);
      if (it != responder_map.end()) {
        responding_node = it->value;
        break;
      }
      visited_nodes.push_back(visited_node);
      // Check if the node filter applies, which would mean we have found a
      // responding node.
      if (node_filter(visited_node)) {
        responding_node = visited_node;
        // Continue the iteration to collect the ancestors of the responder,
        // which we will need later.
        for (visited_node = ParentShadowHostOrOwner(visited_node); visited_node;
             visited_node = ParentShadowHostOrOwner(visited_node)) {
          HeapHashSet<Member<Node>>::AddResult add_result =
              ancestors_to_responders_set.insert(visited_node);
          if (!add_result.is_new_entry)
            break;
        }
        break;
      }
    }
    if (responding_node) {
      // Insert the detected responder for all the visited nodes.
      for (unsigned j = 0; j < visited_nodes.size(); j++)
        responder_map.insert(visited_nodes[j], responding_node);

      candidates.push_back(node);
    }
  }

  // We compile the list of component absolute quads instead of using the
  // bounding rect to be able to perform better hit-testing on inline links on
  // line-breaks.
  for (unsigned i = 0; i < candidates.size(); i++) {
    Node* candidate = candidates[i];

    // Skip nodes whose responders are ancestors of other responders. This gives
    // preference to the inner-most event-handlers. So that a link is always
    // preferred even when contained in an element that monitors all
    // click-events.
    Node* responding_node = responder_map.at(candidate);
    DCHECK(responding_node);
    if (ancestors_to_responders_set.Contains(responding_node))
      continue;

    // Consolidate bounds for editable content.
    if (editable_ancestors.Contains(candidate))
      continue;
    candidate->GetDocument().UpdateStyleAndLayoutTree();
    if (IsEditable(*candidate)) {
      Node* replacement = candidate;
      Node* parent = candidate->ParentOrShadowHostNode();

      // Ignore parents without layout objects.  E.g. editable elements with
      // display:contents.  https://crbug.com/1196872
      while (parent && IsEditable(*parent) && parent->GetLayoutObject()) {
        replacement = parent;
        if (editable_ancestors.Contains(replacement)) {
          replacement = nullptr;
          break;
        }
        editable_ancestors.insert(replacement);
        parent = parent->ParentOrShadowHostNode();
      }
      candidate = replacement;
    }
    if (candidate)
      append_subtargets_for_node(candidate, subtargets);
  }
}

// This returns quotient of the target area and its intersection with the touch
// area.  This will prioritize largest intersection and smallest area, while
// balancing the two against each other.
float ZoomableIntersectionQuotient(const gfx::Point& touch_hotspot,
                                   const gfx::Rect& touch_area,
                                   const SubtargetGeometry& subtarget) {
  gfx::Rect rect =
      subtarget.GetNode()->GetDocument().View()->ConvertToRootFrame(
          subtarget.BoundingBox());

  // Check the rectangle is meaningful zoom target. It should at least contain
  // the hotspot.
  if (!rect.Contains(touch_hotspot))
    return std::numeric_limits<float>::infinity();
  gfx::Rect intersection = rect;
  intersection.Intersect(touch_area);

  // Return the quotient of the intersection.
  return static_cast<float>(rect.size().Area64()) /
         static_cast<float>(intersection.size().Area64());
}

// Uses a hybrid of distance to adjust and intersect ratio, normalizing each
// score between 0 and 1 and combining them. The distance to adjust works best
// for disambiguating clicks on targets such as links, where the width may be
// significantly larger than the touch width.  Using area of overlap in such
// cases can lead to a bias towards shorter links. Conversely, percentage of
// overlap can provide strong confidence in tapping on a small target, where the
// overlap is often quite high, and works well for tightly packed controls.
float HybridDistanceFunction(const gfx::Point& touch_hotspot,
                             const gfx::Rect& touch_rect,
                             const SubtargetGeometry& subtarget) {
  gfx::RectF rect(subtarget.GetNode()->GetDocument().View()->ConvertToRootFrame(
      subtarget.BoundingBox()));
  float radius_squared =
      0.25f *
      gfx::Vector2dF(touch_rect.width(), touch_rect.height()).LengthSquared();
  gfx::PointF hotspot_f(touch_hotspot);
  float distance_to_adjust_score =
      (rect.ClosestPoint(hotspot_f) - hotspot_f).LengthSquared() /
      radius_squared;

  float max_overlap_width = std::min<float>(touch_rect.width(), rect.width());
  float max_overlap_height =
      std::min<float>(touch_rect.height(), rect.height());
  float max_overlap_area =
      std::max<float>(max_overlap_width * max_overlap_height, 1);
  rect.Intersect(gfx::RectF(touch_rect));
  float intersect_area = rect.size().GetArea();
  float intersection_score = 1 - intersect_area / max_overlap_area;

  float hybrid_score = intersection_score + distance_to_adjust_score;

  return hybrid_score;
}

gfx::PointF ConvertToRootFrame(LocalFrameView* view, gfx::PointF pt) {
  int x = static_cast<int>(pt.x() + 0.5f);
  int y = static_cast<int>(pt.y() + 0.5f);
  gfx::Point adjusted = view->ConvertToRootFrame(gfx::Point(x, y));
  return gfx::PointF(adjusted.x(), adjusted.y());
}

// Adjusts 'point' to the nearest point inside rect, and leaves it unchanged if
// already inside.
void AdjustPointToRect(gfx::PointF& point, const gfx::Rect& rect) {
  if (point.x() < rect.x()) {
    point.set_x(rect.x());
  } else if (point.x() >= rect.right()) {
    point.set_x(rect.right() - 1);
  }

  if (point.y() < rect.y()) {
    point.set_y(rect.y());
  } else if (point.y() >= rect.bottom()) {
    point.set_y(rect.bottom() - 1);
  }
}

bool SnapTo(const SubtargetGeometry& geom,
            const gfx::Point& touch_point,
            const gfx::Rect& touch_area,
            gfx::Point& snapped_point) {
  LocalFrameView* view = geom.GetNode()->GetDocument().View();
  gfx::QuadF quad = geom.Quad();

  if (quad.IsRectilinear()) {
    gfx::Rect bounds = view->ConvertToRootFrame(geom.BoundingBox());
    if (bounds.Contains(touch_point)) {
      snapped_point = touch_point;
      return true;
    }
    if (bounds.Intersects(touch_area)) {
      bounds.Intersect(touch_area);
      snapped_point = bounds.CenterPoint();
      return true;
    }
    return false;
  }

  // The following code tries to adjust the point to place inside a both the
  // touchArea and the non-rectilinear quad.
  // FIXME: This will return the point inside the touch area that is the closest
  // to the quad center, but does not guarantee that the point will be inside
  // the quad. Corner-cases exist where the quad will intersect but this will
  // fail to adjust the point to somewhere in the intersection.

  gfx::PointF p1 = ConvertToRootFrame(view, quad.p1());
  gfx::PointF p2 = ConvertToRootFrame(view, quad.p2());
  gfx::PointF p3 = ConvertToRootFrame(view, quad.p3());
  gfx::PointF p4 = ConvertToRootFrame(view, quad.p4());
  quad = gfx::QuadF(p1, p2, p3, p4);

  if (quad.Contains(gfx::PointF(touch_point))) {
    snapped_point = touch_point;
    return true;
  }

  // Pull point towards the center of the element.
  gfx::PointF center = quad.CenterPoint();

  AdjustPointToRect(center, touch_area);
  snapped_point = gfx::ToRoundedPoint(center);

  return quad.Contains(gfx::PointF(snapped_point));
}

// A generic function for finding the target node with the lowest distance
// metric. A distance metric here is the result of a distance-like function,
// that computes how well the touch hits the node.  Distance functions could for
// instance be distance squared or area of intersection.
bool FindNodeWithLowestDistanceMetric(Node*& adjusted_node,
                                      gfx::Point& adjusted_point,
                                      const gfx::Point& touch_hotspot,
                                      const gfx::Rect& touch_area,
                                      SubtargetGeometryList& subtargets,
                                      DistanceFunction distance_function) {
  adjusted_node = nullptr;
  float best_distance_metric = std::numeric_limits<float>::infinity();
  gfx::Point snapped_point;

  for (const auto& subtarget : subtargets) {
    Node* node = subtarget.GetNode();
    float distance_metric =
        distance_function(touch_hotspot, touch_area, subtarget);
    if (distance_metric < best_distance_metric) {
      if (SnapTo(subtarget, touch_hotspot, touch_area, snapped_point)) {
        adjusted_point = snapped_point;
        adjusted_node = node;
        best_distance_metric = distance_metric;
      }
    } else if (distance_metric - best_distance_metric < kZeroTolerance) {
      if (SnapTo(subtarget, touch_hotspot, touch_area, snapped_point)) {
        if (node->IsDescendantOf(adjusted_node)) {
          // Try to always return the inner-most element.
          adjusted_point = snapped_point;
          adjusted_node = node;
        }
      }
    }
  }

  // As for HitTestResult.innerNode, we skip over pseudo elements.
  if (adjusted_node && adjusted_node->IsPseudoElement() &&
      !adjusted_node->IsScrollMarkerPseudoElement()) {
    adjusted_node = adjusted_node->ParentOrShadowHostNode();
  }

  return adjusted_node != nullptr;
}

bool FindBestCandidate(Node*& adjusted_node,
                       gfx::Point& adjusted_point,
                       const gfx::Point& touch_hotspot,
                       const gfx::Rect& touch_area,
                       const HeapVector<Member<Node>>& nodes,
                       NodeFilter node_filter,
                       AppendSubtargetsForNode append_subtargets_for_node) {
  touch_adjustment::SubtargetGeometryList subtargets;
  touch_adjustment::CompileSubtargetList(nodes, subtargets, node_filter,
                                         append_subtargets_for_node);
  return touch_adjustment::FindNodeWithLowestDistanceMetric(
      adjusted_node, adjusted_point, touch_hotspot, touch_area, subtargets,
      touch_adjustment::HybridDistanceFunction);
}

}  // namespace touch_adjustment

bool FindBestTouchAdjustmentCandidate(
    TouchAdjustmentCandidateType candidate_type,
    Node*& candidate_node,
    gfx::Point& candidate_point,
    const gfx::Point& touch_hotspot,
    const gfx::Rect& touch_area,
    const HeapVector<Member<Node>>& nodes) {
  touch_adjustment::NodeFilter node_filter;
  touch_adjustment::AppendSubtargetsForNode append_subtargets_for_node;

  switch (candidate_type) {
    case TouchAdjustmentCandidateType::kClickable:
      node_filter = touch_adjustment::NodeRespondsToTapGesture;
      append_subtargets_for_node =
          touch_adjustment::AppendBasicSubtargetsForNode;
      break;
    case TouchAdjustmentCandidateType::kContextMenu:
      node_filter = touch_adjustment::ProvidesContextMenuItems;
      append_subtargets_for_node =
          touch_adjustment::AppendContextSubtargetsForNode;
      break;
    case TouchAdjustmentCandidateType::kStylusWritable:
      node_filter = touch_adjustment::NodeRespondsToTapOrMove;
      append_subtargets_for_node =
          touch_adjustment::AppendBasicSubtargetsForNode;
      break;
  }
  return FindBestCandidate(candidate_node, candidate_point, touch_hotspot,
                           touch_area, nodes, node_filter,
                           append_subtargets_for_node);
}

PhysicalSize GetHitTestRectForAdjustment(LocalFrame& frame,
                                         const PhysicalSize& touch_area) {
  ChromeClient& chrome_client = frame.GetChromeClient();
  float device_scale_factor =
      chrome_client.GetScreenInfo(frame).device_scale_factor;
  if (frame.GetPage()->InspectorDeviceScaleFactorOverride() != 1) {
    device_scale_factor = 1;
  }

  float page_scale_factor = frame.GetPage()->PageScaleFactor();
  const PhysicalSize max_size_in_dip(touch_adjustment::kMaxAdjustmentSizeDip,
                                     touch_adjustment::kMaxAdjustmentSizeDip);

  const PhysicalSize min_size_in_dip(touch_adjustment::kMinAdjustmentSizeDip,
                                     touch_adjustment::kMinAdjustmentSizeDip);
  // (when use-zoom-for-dsf enabled) touch_area is in physical pixel scaled,
  // max_size_in_dip should be converted to physical pixel and scale too.
  return touch_area
      .ShrunkTo(max_size_in_dip * (device_scale_factor / page_scale_factor))
      .ExpandedTo(min_size_in_dip * (device_scale_factor / page_scale_factor));
}

}  // namespace blink
```