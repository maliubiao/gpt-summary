Response:
Let's break down the thought process for analyzing the `hit_test_result.cc` file and generating the detailed explanation.

1. **Understand the Goal:** The request asks for the functionalities of the file, its relationship to web technologies (HTML, CSS, JavaScript), logical reasoning with examples, and common usage errors.

2. **Initial Scan and Keyword Identification:**  Quickly read through the code, looking for key terms and patterns. Things like `HitTestResult`, `Node`, `Element`, `LayoutObject`, `Point`, `Scrollbar`, `Image`, `Link`, `Editable`, and inclusion of headers like `<html/...>`, `<svg/...>`, and `<dom/...>` stand out. Copyright notices also hint at the file's age and purpose within a larger project.

3. **Deconstruct the Class Structure:** Focus on the `HitTestResult` class itself. Identify its member variables. These variables represent the information the class stores about a hit-test. List them out:
    * `hit_test_request_`:  Configuration of the hit-test.
    * `cacheable_`:  Whether the result can be cached.
    * `inner_node_`, `inner_element_`, `inner_possibly_pseudo_node_`: The DOM node hit.
    * `point_in_inner_node_frame_`, `local_point_`: Coordinates.
    * `inner_url_element_`:  Element if it's a link.
    * `scrollbar_`:  Scrollbar if hit.
    * `is_over_embedded_content_view_`, `is_over_resizer_`, `is_over_scroll_corner_`: Specific hit locations.
    * `list_based_test_result_`: For multiple hit results.

4. **Analyze the Methods:** Go through the public methods of the `HitTestResult` class and understand their purpose:
    * **Constructors/Destructor:**  Initialization and cleanup.
    * **Getters/Setters:** Access and modify the stored information. Pay attention to what each getter returns and what the setter does. For example, `GetPosition()` calculates the DOM position based on the hit point.
    * **`EqualForCacheability()`, `CacheValues()`, `PopulateFromCachedResult()`:**  Related to caching hit-test results.
    * **`SetNodeAndPosition()`, `OverrideNodeAndPosition()`:**  Setting the hit node and coordinates.
    * **`GetScrollableContainer()`:**  Finding the scrollable element.
    * **`ImageAreaForImage()`:**  Handling image map areas.
    * **`SetToShadowHostIfInUAShadowRoot()`:** Handling user-agent shadow DOM.
    * **URL/Image/Media related methods (`AbsoluteImageURL()`, `AbsoluteLinkURL()`, `MediaElement()`, etc.):** Extracting information about the hit element.
    * **`IsSelected()`, `Title()`, `AltDisplayString()`:**  Getting attributes of the hit element.
    * **`IsContentEditable()`:** Checking if the hit area is editable.
    * **`AddNodeToListBasedTestResultInternal()`, `AddNodeToListBasedTestResult()`:** Logic for accumulating results in list-based hit-tests.
    * **`Append()`:**  Merging results from multiple hit-tests.
    * **`ListBasedTestResult()`, `MutableListBasedTestResult()`:** Accessing the list of hit nodes.
    * **`ResolveRectBasedTest()`:** Handling hit-tests based on rectangles.
    * **`InnerNodeOrImageMapImage()`:**  Getting the relevant node for image maps.
    * **`Trace()`:** For debugging/serialization.

5. **Connect to Web Technologies (HTML, CSS, JavaScript):** For each significant method or data member, think about how it relates to web development concepts:
    * **HTML Elements:**  Many methods deal directly with specific HTML elements (`HTMLImageElement`, `HTMLAnchorElement`, `HTMLInputElement`, etc.). The file helps determine *which* element was clicked.
    * **CSS Styling:**  Methods like `Title()` retrieve information that might be styled. The position calculations are influenced by CSS layout. The concept of pseudo-elements (`::before`, `::after`) is explicitly handled.
    * **JavaScript Events:**  Hit-testing is fundamental to event handling. When a user clicks, the browser needs to determine *where* the click occurred, and this file plays a role in that. JavaScript can then act on the targeted element.

6. **Develop Examples:**  For each relationship to web technologies, create simple, illustrative examples:
    * **HTML:** Show basic HTML structures that the `HitTestResult` would interact with (links, images, form elements).
    * **CSS:** Demonstrate how CSS affects the layout and appearance, influencing the hit-test.
    * **JavaScript:** Illustrate how JavaScript would use hit-testing information (e.g., getting the target of a click event).

7. **Identify Logical Reasoning and Examples:** Look for methods where the code makes decisions based on the input. The `ImageAreaForImage()` method and the logic within `GetPosition()` are good examples.
    * **Assumptions:**  Define what the input to the function is.
    * **Logic:**  Explain the steps the function takes.
    * **Outputs:** Describe what the function returns.

8. **Consider Common Usage Errors:** Think about mistakes developers might make that relate to hit-testing concepts:
    * **Overlapping Elements:**  Explain how incorrect z-index or positioning can lead to unexpected hit-test results.
    * **Clickable Areas:** Discuss issues with making elements clickable (e.g., missing event listeners, incorrect element structure).
    * **Image Maps:**  Highlight potential problems with defining and using image maps.

9. **Structure the Explanation:** Organize the information logically:
    * Start with a high-level summary of the file's purpose.
    * Detail the core functionalities, grouping related methods.
    * Explain the connections to HTML, CSS, and JavaScript with examples.
    * Present logical reasoning with clear input/output examples.
    * Discuss common usage errors with specific scenarios.

10. **Refine and Clarify:** Review the explanation for clarity, accuracy, and completeness. Ensure that the language is accessible and that the examples are easy to understand. Use code snippets where appropriate to illustrate points. For instance, explicitly showing how JavaScript's `event.target` relates to the `HitTestResult`.

By following these steps, we can systematically analyze the given source code and generate a comprehensive and informative explanation. The process involves understanding the code's structure and purpose, connecting it to relevant web technologies, and providing concrete examples to illustrate its functionality and potential pitfalls.
好的， 让我们来分析一下 `blink/renderer/core/layout/hit_test_result.cc` 这个文件。

**功能概述:**

`hit_test_result.cc` 文件定义了 `HitTestResult` 类，这个类的主要功能是存储和管理在**命中测试 (hit testing)** 过程中产生的结果信息。命中测试是浏览器引擎用来确定用户在屏幕上的某个点击位置命中了哪个网页元素的过程。

更具体地说，`HitTestResult` 类会记录以下关键信息：

* **命中的节点 (Node):**  用户点击位置所在的 DOM 树节点。这可能是一个 HTML 元素，文本节点，甚至是一个伪元素。
* **命中的元素 (Element):** 如果命中的节点是一个元素，则会记录该元素。
* **命中的 URL 元素 (URLElement):** 如果命中的是一个链接 (<a> 标签)，则会记录该链接元素。
* **命中的滚动条 (Scrollbar):** 如果点击位置在滚动条上，则会记录该滚动条对象。
* **命中位置的局部坐标 (LocalPoint):** 点击位置相对于命中节点自身坐标系的坐标。
* **命中请求 (HitTestRequest):**  包含了执行命中测试的配置信息，例如是否需要返回所有命中的元素，还是只需要最顶层的。
* **是否覆盖嵌入内容视图 (is_over_embedded_content_view_):**  指示点击是否发生在嵌入的内容 (例如 iframe)。
* **是否覆盖调整大小的控件 (is_over_resizer_):** 指示点击是否发生在可以调整元素大小的控件上。
* **是否覆盖滚动角 (is_over_scroll_corner_):** 指示点击是否发生在滚动条的角落。
* **列表命中测试结果 (list_based_test_result_):**  如果执行的是列表命中测试（需要查找所有命中的元素），则会存储所有命中的节点集合。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`HitTestResult` 类在浏览器引擎的内部运作中扮演着至关重要的角色，它直接关联着用户与网页的交互，因此与 JavaScript, HTML, 和 CSS 都有着密切的关系。

1. **HTML (结构):**
   - `HitTestResult` 的核心功能是确定用户点击了哪个 HTML 元素。例如，如果用户点击了一个 `<div>` 元素，命中测试会找到这个 `<div>` 元素，并且 `HitTestResult` 对象会存储这个 `<div>` 元素的引用。
   - **举例:**
     ```html
     <div id="myDiv" style="width: 100px; height: 100px; background-color: red;"></div>
     <script>
       document.getElementById('myDiv').addEventListener('click', function(event) {
         // 当用户点击 div 元素时，浏览器内部的命中测试会找到这个 div。
         // 事件对象 event 中的 target 属性通常会关联到 HitTestResult 中记录的命中元素。
         console.log(event.target.id); // 输出 "myDiv"
       });
     </script>
     ```

2. **CSS (样式):**
   - CSS 决定了网页元素的布局和外观，这直接影响了命中测试的结果。元素的尺寸、位置、层叠顺序 (z-index) 等 CSS 属性都会影响点击事件发生时，哪个元素会被命中。
   - 伪元素 (如 `::before`, `::after`) 也可以被命中，`HitTestResult` 能够记录命中的伪元素。
   - **举例:**
     ```html
     <style>
       .container {
         position: relative;
         width: 200px;
         height: 200px;
         background-color: blue;
       }
       .overlay {
         position: absolute;
         top: 50px;
         left: 50px;
         width: 100px;
         height: 100px;
         background-color: yellow;
         z-index: 1; /* 确保 overlay 在 container 上面 */
       }
     </style>
     <div class="container">
       <div class="overlay" id="overlayDiv"></div>
     </div>
     <script>
       document.getElementById('overlayDiv').addEventListener('click', function(event) {
         console.log('Overlay clicked'); // 如果点击黄色区域，会输出
       });
       document.querySelector('.container').addEventListener('click', function(event) {
         console.log('Container clicked'); // 如果点击蓝色但不在黄色区域，会输出
       });
     </script>
     ```
     在这个例子中，CSS 的 `z-index` 属性决定了哪个 `div` 在前面。当点击重叠区域时，命中测试会根据层叠顺序确定命中的元素，`HitTestResult` 会记录 `overlayDiv`。

3. **JavaScript (交互):**
   - JavaScript 事件处理程序通常会依赖命中测试的结果。当用户触发一个事件（如点击、鼠标移动）时，浏览器会执行命中测试来确定哪个元素是事件的目标 (event target)。这个目标元素的信息很可能来源于 `HitTestResult` 对象。
   - **举例:**  在上面的 HTML 例子中，JavaScript 的 `addEventListener` 和事件对象 `event.target` 直接使用了命中测试的结果。`event.target` 会指向 `HitTestResult` 中记录的命中元素。
   - JavaScript 还可以通过一些 API (例如，拖放 API) 间接地依赖命中测试来确定拖动操作的目标元素。

**逻辑推理及假设输入与输出:**

假设用户点击了以下 HTML 结构中的链接 "Click Me":

```html
<div style="width: 200px; height: 100px;">
  <a href="https://example.com">Click Me</a>
</div>
```

**假设输入:**

* **点击位置的屏幕坐标:**  假设点击发生在相对于文档的 (50, 30) 像素位置。
* **当前的 DOM 树和布局信息:**  浏览器引擎已经构建了该 HTML 的 DOM 树和布局信息（包括元素的位置和尺寸）。

**逻辑推理过程 (简化):**

1. **命中测试启动:** 当用户点击时，浏览器引擎启动命中测试。
2. **遍历布局树:** 引擎会遍历布局树，检查点击位置是否在元素的边界内。
3. **找到命中元素:**  引擎会发现点击位置 (50, 30) 位于 `<a>` 标签的布局边界内。
4. **填充 HitTestResult:** 引擎创建一个 `HitTestResult` 对象并填充信息：
   - `inner_node_`: 指向 `<a>` 标签对应的 DOM 节点。
   - `inner_element_`: 指向 `<a>` 标签对应的元素对象。
   - `inner_url_element_`: 指向 `<a>` 标签对应的元素对象 (因为它是 URL 元素)。
   - `local_point_`: 点击位置相对于 `<a>` 标签自身坐标系的坐标 (例如，如果 `<a>` 标签的左上角在屏幕坐标 (10, 10)，则 local_point 为 (40, 20))。
   - 其他相关属性也会被填充。

**假设输出 (HitTestResult 对象的部分信息):**

* `inner_node_`:  指向 `<a>` 元素的指针
* `inner_element_`: 指向 `<a>` 元素的指针
* `inner_url_element_`: 指向 `<a>` 元素
### 提示词
```
这是目录为blink/renderer/core/layout/hit_test_result.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2006, 2008, 2011 Apple Inc. All rights reserved.
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
 *
 */

#include "third_party/blink/renderer/core/layout/hit_test_result.h"

#include "cc/base/region.h"
#include "third_party/abseil-cpp/absl/types/variant.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/text_affinity.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_text_area_element.h"
#include "third_party/blink/renderer/core/html/html_area_element.h"
#include "third_party/blink/renderer/core/html/html_embed_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/html_map_element.h"
#include "third_party/blink/renderer/core/html/html_object_element.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/html/media/media_source_handle.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/layout/hit_test_location.h"
#include "third_party/blink/renderer/core/layout/layout_block.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_image.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_image.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/scrolling/top_document_root_scroller_controller.h"
#include "third_party/blink/renderer/core/scroll/scrollbar.h"
#include "third_party/blink/renderer/core/svg/svg_element.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_descriptor.h"
#include "ui/gfx/geometry/rect_conversions.h"

namespace blink {

using mojom::blink::FormControlType;

namespace {

bool HasImageSourceURL(const Node& node) {
  // Always return a url for image elements and input elements with type=image,
  // even if they don't have a LayoutImage (e.g. because the image didn't load
  // and we are using an alt container). For other elements we don't create alt
  // containers so ensure they contain a loaded image.
  auto* html_input_element = DynamicTo<HTMLInputElement>(node);
  if (IsA<HTMLImageElement>(node) ||
      (html_input_element &&
       html_input_element->FormControlType() == FormControlType::kInputImage)) {
    return true;
  }
  const LayoutObject* layout_object = node.GetLayoutObject();
  if (!layout_object) {
    return false;
  }
  if (layout_object->IsImage() &&
      (IsA<HTMLEmbedElement>(node) || IsA<HTMLObjectElement>(node))) {
    return true;
  }
  if (layout_object->IsSVGImage()) {
    return true;
  }
  return false;
}

}  // namespace

HitTestResult::HitTestResult()
    : hit_test_request_(HitTestRequest::kReadOnly | HitTestRequest::kActive),
      cacheable_(true),
      is_over_embedded_content_view_(false) {}

HitTestResult::HitTestResult(const HitTestRequest& other_request,
                             const HitTestLocation& location)
    : hit_test_request_(other_request),
      cacheable_(true),
      point_in_inner_node_frame_(location.Point()),
      is_over_embedded_content_view_(false) {}

HitTestResult::HitTestResult(const HitTestResult& other)
    : hit_test_request_(other.hit_test_request_),
      cacheable_(other.cacheable_),
      inner_node_(other.InnerNode()),
      inner_element_(other.InnerElement()),
      inner_possibly_pseudo_node_(other.inner_possibly_pseudo_node_),
      point_in_inner_node_frame_(other.point_in_inner_node_frame_),
      local_point_(other.LocalPoint()),
      inner_url_element_(other.URLElement()),
      scrollbar_(other.GetScrollbar()),
      is_over_embedded_content_view_(other.IsOverEmbeddedContentView()),
      is_over_resizer_(other.is_over_resizer_),
      is_over_scroll_corner_(other.is_over_scroll_corner_) {
  // Only copy the NodeSet in case of list hit test.
  list_based_test_result_ =
      other.list_based_test_result_
          ? MakeGarbageCollected<NodeSet>(*other.list_based_test_result_)
          : nullptr;
}

HitTestResult::~HitTestResult() = default;

HitTestResult& HitTestResult::operator=(const HitTestResult& other) {
  hit_test_request_ = other.hit_test_request_;
  PopulateFromCachedResult(other);

  return *this;
}

bool HitTestResult::EqualForCacheability(const HitTestResult& other) const {
  return hit_test_request_.EqualForCacheability(other.hit_test_request_) &&
         inner_node_ == other.InnerNode() &&
         inner_element_ == other.InnerElement() &&
         inner_possibly_pseudo_node_ == other.InnerPossiblyPseudoNode() &&
         point_in_inner_node_frame_ == other.point_in_inner_node_frame_ &&
         local_point_ == other.LocalPoint() &&
         inner_url_element_ == other.URLElement() &&
         scrollbar_ == other.GetScrollbar() &&
         is_over_embedded_content_view_ == other.IsOverEmbeddedContentView();
}

void HitTestResult::CacheValues(const HitTestResult& other) {
  hit_test_request_ =
      other.hit_test_request_.GetType() & ~HitTestRequest::kAvoidCache;
}

void HitTestResult::PopulateFromCachedResult(const HitTestResult& other) {
  inner_node_ = other.InnerNode();
  inner_element_ = other.InnerElement();
  inner_possibly_pseudo_node_ = other.InnerPossiblyPseudoNode();
  point_in_inner_node_frame_ = other.point_in_inner_node_frame_;
  local_point_ = other.LocalPoint();
  inner_url_element_ = other.URLElement();
  scrollbar_ = other.GetScrollbar();

  is_over_embedded_content_view_ = other.IsOverEmbeddedContentView();
  cacheable_ = other.cacheable_;
  is_over_resizer_ = other.IsOverResizer();
  is_over_scroll_corner_ = other.IsOverScrollCorner();

  // Only copy the NodeSet in case of list hit test.
  list_based_test_result_ =
      other.list_based_test_result_
          ? MakeGarbageCollected<NodeSet>(*other.list_based_test_result_)
          : nullptr;
}

void HitTestResult::Trace(Visitor* visitor) const {
  visitor->Trace(hit_test_request_);
  visitor->Trace(inner_node_);
  visitor->Trace(inner_element_);
  visitor->Trace(inner_possibly_pseudo_node_);
  visitor->Trace(inner_url_element_);
  visitor->Trace(scrollbar_);
  visitor->Trace(list_based_test_result_);
}

void HitTestResult::SetNodeAndPosition(Node* node,
                                       const PhysicalBoxFragment* box_fragment,
                                       const PhysicalOffset& position) {
  if (box_fragment) {
    local_point_ = position + box_fragment->OffsetFromOwnerLayoutBox();
  } else {
    local_point_ = position;
  }
  SetInnerNode(node);
}

void HitTestResult::OverrideNodeAndPosition(Node* node,
                                            PhysicalOffset position) {
  local_point_ = position;
  SetInnerNode(node);
}

PositionWithAffinity HitTestResult::GetPosition() const {
  const Node* node = inner_possibly_pseudo_node_;
  if (!node)
    return PositionWithAffinity();
  // |LayoutObject::PositionForPoint()| requires |kPrePaintClean|.
  DCHECK_GE(node->GetDocument().Lifecycle().GetState(),
            DocumentLifecycle::kPrePaintClean);
  LayoutObject* layout_object = node->GetLayoutObject();
  if (!layout_object)
    return PositionWithAffinity();

  // We should never have a layout object that is within a locked subtree.
  CHECK(!DisplayLockUtilities::LockedAncestorPreventingPaint(*layout_object));

  // If the layout object is blocked by display lock, we return the beginning of
  // the node as the position. This is because we don't paint contents of the
  // element. Furthermore, any caret adjustments below can access layout-dirty
  // state in the subtree of this object.
  if (layout_object->ChildPaintBlockedByDisplayLock())
    return PositionWithAffinity(Position(*node, 0), TextAffinity::kDefault);

  if (node->IsPseudoElement() && node->GetPseudoId() == kPseudoIdBefore) {
    return PositionWithAffinity(
        MostForwardCaretPosition(Position::FirstPositionInNode(*inner_node_)));
  }

  if (node->IsPseudoElement() && node->GetPseudoId() == kPseudoIdCheck) {
    return PositionWithAffinity(
        MostForwardCaretPosition(Position::FirstPositionInNode(*inner_node_)));
  }

  return layout_object->PositionForPoint(LocalPoint());
}

PositionWithAffinity HitTestResult::GetPositionForInnerNodeOrImageMapImage()
    const {
  Node* node = InnerPossiblyPseudoNode();
  if (node && !node->IsPseudoElement())
    node = InnerNodeOrImageMapImage();
  if (!node)
    return PositionWithAffinity();
  // |LayoutObject::PositionForPoint()| requires |kPrePaintClean|.
  DCHECK_GE(node->GetDocument().Lifecycle().GetState(),
            DocumentLifecycle::kPrePaintClean);
  LayoutObject* layout_object = node->GetLayoutObject();
  if (!layout_object)
    return PositionWithAffinity();
  // We should never have a layout object that is within a locked subtree.
  CHECK(!DisplayLockUtilities::LockedAncestorPreventingPaint(*layout_object));

  // If the layout object is blocked by display lock, we return the beginning of
  // the node as the position. This is because we don't paint contents of the
  // element. Furthermore, any caret adjustments below can access layout-dirty
  // state in the subtree of this object.
  if (layout_object->ChildPaintBlockedByDisplayLock())
    return PositionWithAffinity(Position(*node, 0), TextAffinity::kDefault);

  PositionWithAffinity position = layout_object->PositionForPoint(LocalPoint());
  if (position.IsNull())
    return PositionWithAffinity(FirstPositionInOrBeforeNode(*node));
  return position;
}

void HitTestResult::SetToShadowHostIfInUAShadowRoot() {
  Node* node = InnerNode();
  if (!node)
    return;

  ShadowRoot* containing_shadow_root = node->ContainingShadowRoot();
  Element* shadow_host = nullptr;

  // Consider a closed shadow tree of SVG's <use> element as a special
  // case so that a toolip title in the shadow tree works.
  while (containing_shadow_root && containing_shadow_root->IsUserAgent()) {
    shadow_host = &containing_shadow_root->host();
    containing_shadow_root = shadow_host->ContainingShadowRoot();
    // TODO(layout-dev): Not updating local_point_ here seems like a mistake?
    OverrideNodeAndPosition(node->OwnerShadowHost(), local_point_);
  }

  // TODO(layout-dev): Not updating local_point_ here seems like a mistake?
  if (shadow_host)
    OverrideNodeAndPosition(shadow_host, local_point_);
}

CompositorElementId HitTestResult::GetScrollableContainer() const {
  // If no node was found, return an invalid element ID, which we check for in
  // InputHandlerProxy::ContinueScrollBeginAfterMainThreadHitTest.
  if (!InnerNode())
    return CompositorElementId();

  LayoutBox* cur_box = InnerNode()->GetLayoutObject()->EnclosingBox();

  // Scrolling propagates along the containing block chain and ends at the
  // RootScroller node. The RootScroller node will have a custom applyScroll
  // callback that performs scrolling as well as associated "root" actions like
  // browser control movement and overscroll glow.
  while (cur_box) {
    if (cur_box->IsGlobalRootScroller() ||
        (cur_box->IsScrollContainer() &&
         cur_box->GetScrollableArea()->ScrollsOverflow())) {
      return cur_box->GetScrollableArea()->GetScrollElementId();
    }

    if (IsA<LayoutView>(cur_box))
      cur_box = cur_box->GetFrame()->OwnerLayoutObject();
    else
      cur_box = cur_box->ContainingBlock();
  }

  return InnerNode()
      ->GetDocument()
      .GetPage()
      ->GetVisualViewport()
      .GetScrollElementId();
}

HTMLAreaElement* HitTestResult::ImageAreaForImage() const {
  DCHECK(inner_node_);
  auto* image_element = DynamicTo<HTMLImageElement>(inner_node_.Get());
  if (!image_element && inner_node_->IsInShadowTree()) {
    if (inner_node_->ContainingShadowRoot()->IsUserAgent()) {
      image_element =
          DynamicTo<HTMLImageElement>(inner_node_->OwnerShadowHost());
    }
  }

  if (!image_element || !image_element->GetLayoutObject() ||
      !image_element->GetLayoutObject()->IsBox())
    return nullptr;

  HTMLMapElement* map = image_element->GetTreeScope().GetImageMap(
      image_element->FastGetAttribute(html_names::kUsemapAttr));
  if (!map)
    return nullptr;

  return map->AreaForPoint(LocalPoint(), image_element->GetLayoutObject());
}

void HitTestResult::SetInnerNode(Node* n) {
  if (!n) {
    inner_possibly_pseudo_node_ = nullptr;
    inner_node_ = nullptr;
    inner_element_ = nullptr;
    return;
  }

  inner_possibly_pseudo_node_ = n;
  if (auto* pseudo_element = DynamicTo<PseudoElement>(n))
    n = pseudo_element->InnerNodeForHitTesting();
  inner_node_ = n;
  if (HTMLAreaElement* area = ImageAreaForImage()) {
    inner_node_ = area;
    inner_possibly_pseudo_node_ = area;
  }
  if (auto* element = DynamicTo<Element>(inner_node_.Get()))
    inner_element_ = element;
  else
    inner_element_ = FlatTreeTraversal::ParentElement(*inner_node_);
}

void HitTestResult::SetURLElement(Element* n) {
  inner_url_element_ = n;
}

void HitTestResult::SetScrollbar(Scrollbar* s) {
  scrollbar_ = s;
}

LocalFrame* HitTestResult::InnerNodeFrame() const {
  if (inner_node_)
    return inner_node_->GetDocument().GetFrame();
  return nullptr;
}

bool HitTestResult::IsSelected(const HitTestLocation& location) const {
  if (!inner_node_)
    return false;

  if (LocalFrame* frame = inner_node_->GetDocument().GetFrame())
    return frame->Selection().Contains(location.Point());
  return false;
}

String HitTestResult::Title(TextDirection& dir) const {
  dir = TextDirection::kLtr;
  // Find the title in the nearest enclosing DOM node.
  // For <area> tags in image maps, walk the tree for the <area>, not the <img>
  // using it.
  for (Node* title_node = inner_node_.Get(); title_node;
       title_node = FlatTreeTraversal::Parent(*title_node)) {
    if (auto* element = DynamicTo<Element>(title_node)) {
      String title = element->title();
      if (!title.IsNull()) {
        if (LayoutObject* layout_object = title_node->GetLayoutObject())
          dir = layout_object->StyleRef().Direction();
        return title;
      }
    }
  }
  return String();
}

const AtomicString& HitTestResult::AltDisplayString() const {
  Node* inner_node_or_image_map_image = InnerNodeOrImageMapImage();
  if (!inner_node_or_image_map_image)
    return g_null_atom;

  if (auto* image = DynamicTo<HTMLImageElement>(*inner_node_or_image_map_image))
    return image->FastGetAttribute(html_names::kAltAttr);

  if (auto* input = DynamicTo<HTMLInputElement>(*inner_node_or_image_map_image))
    return input->Alt();

  return g_null_atom;
}

Image* HitTestResult::GetImage() const {
  return GetImage(InnerNodeOrImageMapImage());
}

Image* HitTestResult::GetImage(const Node* node) {
  if (!node) {
    return nullptr;
  }
  const LayoutObject* layout_object = node->GetLayoutObject();
  if (!layout_object) {
    return nullptr;
  }
  const LayoutImageResource* layout_image_resource = nullptr;
  if (layout_object->IsImage()) {
    layout_image_resource = To<LayoutImage>(layout_object)->ImageResource();
  } else if (auto* svg_image = DynamicTo<LayoutSVGImage>(layout_object)) {
    layout_image_resource = svg_image->ImageResource();
  }
  const ImageResourceContent* image_content =
      layout_image_resource ? layout_image_resource->CachedImage() : nullptr;
  if (image_content && !image_content->ErrorOccurred()) {
    return image_content->GetImage();
  }
  return nullptr;
}

gfx::Rect HitTestResult::ImageRect() const {
  if (!GetImage())
    return gfx::Rect();
  return gfx::ToEnclosingRect(InnerNodeOrImageMapImage()
                                  ->GetLayoutBox()
                                  ->AbsoluteContentQuad()
                                  .BoundingBox());
}

KURL HitTestResult::AbsoluteImageURL(const Node* node) {
  if (!node || !HasImageSourceURL(*node)) {
    return KURL();
  }
  AtomicString url_string = To<Element>(*node).ImageSourceURL();
  if (url_string.empty()) {
    return KURL();
  }
  return node->GetDocument().CompleteURL(
      StripLeadingAndTrailingHTMLSpaces(url_string));
}

KURL HitTestResult::AbsoluteImageURL() const {
  return AbsoluteImageURL(InnerNodeOrImageMapImage());
}

KURL HitTestResult::AbsoluteMediaURL() const {
  if (HTMLMediaElement* media_elt = MediaElement())
    return media_elt->currentSrc();
  return KURL();
}

MediaStreamDescriptor* HitTestResult::GetMediaStreamDescriptor() const {
  if (HTMLMediaElement* media_elt = MediaElement()) {
    auto variant = media_elt->GetSrcObjectVariant();
    if (absl::holds_alternative<MediaStreamDescriptor*>(variant)) {
      // It might be nullptr-valued variant, too, here, but we return nullptr
      // for that, regardless.
      return absl::get<MediaStreamDescriptor*>(variant);
    }
  }
  return nullptr;
}

MediaSourceHandle* HitTestResult::GetMediaSourceHandle() const {
  if (HTMLMediaElement* media_elt = MediaElement()) {
    auto variant = media_elt->GetSrcObjectVariant();
    if (absl::holds_alternative<MediaSourceHandle*>(variant)) {
      // It might be a nullptr-valued MediaStreamDescriptor* variant, here, but
      // we return nullptr for that, regardless.
      return absl::get<MediaSourceHandle*>(variant);
    }
  }
  return nullptr;
}

HTMLMediaElement* HitTestResult::MediaElement() const {
  if (!inner_node_)
    return nullptr;

  if (!(inner_node_->GetLayoutObject() &&
        inner_node_->GetLayoutObject()->IsMedia()))
    return nullptr;

  return DynamicTo<HTMLMediaElement>(*inner_node_);
}

KURL HitTestResult::AbsoluteLinkURL() const {
  if (!inner_url_element_)
    return KURL();
  return inner_url_element_->HrefURL();
}

bool HitTestResult::IsLiveLink() const {
  return inner_url_element_ && inner_url_element_->IsLiveLink();
}

bool HitTestResult::IsOverLink() const {
  return inner_url_element_ && inner_url_element_->IsLink();
}

String HitTestResult::TextContent() const {
  if (!inner_url_element_)
    return String();
  return inner_url_element_->textContent();
}

// FIXME: This function needs a better name and may belong in a different class.
// It's not really isContentEditable(); it's more like needsEditingContextMenu.
// In many ways, this function would make more sense in the ContextMenu class,
// except that WebElementDictionary hooks into it. Anyway, we should architect
// this better.
bool HitTestResult::IsContentEditable() const {
  if (!inner_node_)
    return false;

  if (auto* textarea = DynamicTo<HTMLTextAreaElement>(*inner_node_))
    return !textarea->IsDisabledOrReadOnly();

  if (auto* input = DynamicTo<HTMLInputElement>(*inner_node_))
    return !input->IsDisabledOrReadOnly() && input->IsTextField();

  return IsEditable(*inner_node_);
}

std::tuple<bool, ListBasedHitTestBehavior>
HitTestResult::AddNodeToListBasedTestResultInternal(
    Node* node,
    const HitTestLocation& location) {
  // If not a list-based test, stop testing because the hit has been found.
  if (!GetHitTestRequest().ListBased())
    return std::make_tuple(false, kStopHitTesting);

  if (!node)
    return std::make_tuple(false, kContinueHitTesting);

  MutableListBasedTestResult().insert(node);
  if (GetHitTestRequest().PenetratingList()) {
    ListBasedHitTestBehavior behavior = kContinueHitTesting;
    if (GetHitTestRequest().UseHitNodeCb()) {
      LocalFrameView::InvalidationDisallowedScope invalidation_disallowed(
          *node->GetDocument().View());
      behavior = GetHitTestRequest().RunHitNodeCb(*node);
    }
    return std::make_tuple(false, behavior);
  }

  // The second argument will be ignored.
  return std::make_tuple(true, kContinueHitTesting);
}

ListBasedHitTestBehavior HitTestResult::AddNodeToListBasedTestResult(
    Node* node,
    const HitTestLocation& location,
    const PhysicalRect& rect) {
  bool should_check_containment;
  ListBasedHitTestBehavior behavior;
  std::tie(should_check_containment, behavior) =
      AddNodeToListBasedTestResultInternal(node, location);
  if (!should_check_containment)
    return behavior;
  return rect.Contains(location.BoundingBox()) ? kStopHitTesting
                                               : kContinueHitTesting;
}

ListBasedHitTestBehavior HitTestResult::AddNodeToListBasedTestResult(
    Node* node,
    const HitTestLocation& location,
    const gfx::QuadF& quad) {
  bool should_check_containment;
  ListBasedHitTestBehavior behavior;
  std::tie(should_check_containment, behavior) =
      AddNodeToListBasedTestResultInternal(node, location);
  if (!should_check_containment)
    return behavior;
  return quad.ContainsQuad(gfx::QuadF(gfx::RectF(location.BoundingBox())))
             ? kStopHitTesting
             : kContinueHitTesting;
}

ListBasedHitTestBehavior HitTestResult::AddNodeToListBasedTestResult(
    Node* node,
    const HitTestLocation& location,
    const cc::Region& region) {
  bool should_check_containment;
  ListBasedHitTestBehavior behavior;
  std::tie(should_check_containment, behavior) =
      AddNodeToListBasedTestResultInternal(node, location);
  if (!should_check_containment)
    return behavior;
  return region.Contains(location.ToEnclosingRect()) ? kStopHitTesting
                                                     : kContinueHitTesting;
}

void HitTestResult::Append(const HitTestResult& other) {
  DCHECK(GetHitTestRequest().ListBased());

  if (!scrollbar_ && other.GetScrollbar()) {
    SetScrollbar(other.GetScrollbar());
  }

  if (!inner_node_ && other.InnerNode()) {
    inner_node_ = other.InnerNode();
    inner_element_ = other.InnerElement();
    inner_possibly_pseudo_node_ = other.InnerPossiblyPseudoNode();
    local_point_ = other.LocalPoint();
    point_in_inner_node_frame_ = other.point_in_inner_node_frame_;
    inner_url_element_ = other.URLElement();
    is_over_embedded_content_view_ = other.IsOverEmbeddedContentView();
    is_over_resizer_ = other.IsOverResizer();
    is_over_scroll_corner_ = other.is_over_scroll_corner_;
  }

  if (other.list_based_test_result_) {
    NodeSet& set = MutableListBasedTestResult();
    for (NodeSet::const_iterator it = other.list_based_test_result_->begin(),
                                 last = other.list_based_test_result_->end();
         it != last; ++it)
      set.insert(it->Get());
  }
}

const HitTestResult::NodeSet& HitTestResult::ListBasedTestResult() const {
  if (!list_based_test_result_)
    list_based_test_result_ = MakeGarbageCollected<NodeSet>();
  return *list_based_test_result_;
}

HitTestResult::NodeSet& HitTestResult::MutableListBasedTestResult() {
  if (!list_based_test_result_)
    list_based_test_result_ = MakeGarbageCollected<NodeSet>();
  return *list_based_test_result_;
}

HitTestLocation HitTestResult::ResolveRectBasedTest(
    Node* resolved_inner_node,
    const PhysicalOffset& resolved_point_in_main_frame) {
  point_in_inner_node_frame_ = resolved_point_in_main_frame;
  SetInnerNode(nullptr);
  list_based_test_result_ = nullptr;

  // Update the HitTestResult as if the supplied node had been hit in normal
  // point-based hit-test.
  // Note that we don't know the local point after a rect-based hit-test, but we
  // never use it so shouldn't bother with the cost of computing it.
  DCHECK(resolved_inner_node);
  if (auto* layout_object = resolved_inner_node->GetLayoutObject())
    layout_object->UpdateHitTestResult(*this, PhysicalOffset());

  return HitTestLocation(resolved_point_in_main_frame);
}

Node* HitTestResult::InnerNodeOrImageMapImage() const {
  if (!inner_node_)
    return nullptr;

  HTMLImageElement* image_map_image_element = nullptr;
  if (auto* area = DynamicTo<HTMLAreaElement>(inner_node_.Get()))
    image_map_image_element = area->ImageElement();
  else if (auto* map = DynamicTo<HTMLMapElement>(inner_node_.Get()))
    image_map_image_element = map->ImageElement();

  if (!image_map_image_element)
    return inner_node_.Get();

  return image_map_image_element;
}

}  // namespace blink
```