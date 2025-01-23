Response:
My thinking process to analyze the `svg_svg_element.cc` file goes like this:

1. **Understand the Goal:** The request asks for the file's functionality, its relation to JavaScript/HTML/CSS, logical reasoning examples, common usage errors, and debugging clues. This means I need to go beyond simply listing code elements and understand *why* they exist and how they interact.

2. **Initial Scan and Keyword Identification:** I first read through the code quickly, noting down key classes, methods, and concepts. Keywords like `SVGSVGElement`, `SVGGraphicsElement`, `LayoutSVGRoot`, `viewBox`, `preserveAspectRatio`, `currentScale`, `currentTranslate`, `getIntersectionList`, `getEnclosureList`, and mentions of events (unload, resize, scroll, abort, error) jump out. Include headers provide valuable clues as well (`bindings/core/v8/js_event_handler_for_content_attribute.h`, `core/css/css_resolution_units.h`, `core/dom/document.h`, `core/layout/...`, `core/svg/animation/...`).

3. **Identify Core Functionality - The "What":**  Based on the keywords and the file name, the primary function is managing the `<svg>` element in the Blink rendering engine. This involves:
    * **Core SVG properties:** Handling attributes like `x`, `y`, `width`, `height`, `viewBox`, `preserveAspectRatio`, `zoomAndPan`.
    * **Layout integration:**  Interfacing with the layout engine (`LayoutSVGRoot`, `LayoutSVGViewportContainer`) to determine the size and position of the SVG.
    * **Event handling:**  Managing event listeners for the `<svg>` element itself and, in the case of the outermost SVG, for the window (unload, resize, scroll, abort, error).
    * **Coordinate transformations:** Implementing methods to calculate and manipulate coordinate systems within the SVG (e.g., `ComputeCTM`, `ViewBoxToViewTransform`).
    * **Hit testing:** Providing methods like `getIntersectionList` and `getEnclosureList` for determining which elements are within a given area.
    * **Animation:**  Integrating with the SMIL animation system (`SMILTimeContainer`).
    * **JavaScript API:** Exposing properties and methods to JavaScript (e.g., `currentScale`, `currentTranslate`, `createSVGNumber`, etc.).
    * **Document integration:**  Handling the element being inserted into and removed from the DOM.

4. **Connect to JavaScript, HTML, and CSS - The "How":** Now I analyze how the file interacts with the core web technologies:
    * **HTML:** The `<svg>` element is defined in HTML. This file is responsible for the behavior and rendering of those `<svg>` tags. The parsing of attributes from the HTML directly influences the state of the `SVGSVGElement` object.
    * **CSS:** CSS properties like `width`, `height`, `display`, and `overflow` can affect the layout of the `<svg>` element. The code checks and uses these styles. Presentation attributes on the `<svg>` element are also processed to influence styling.
    * **JavaScript:**  The file exposes a JavaScript API. This includes getters and setters for properties (e.g., `currentScale`, `currentTranslate`), and methods for tasks like creating SVG objects (`createSVGNumber`), performing hit testing (`getIntersectionList`), and controlling animations (`pauseAnimations`). Event handlers defined in HTML attributes (`onload`, `onerror`, etc.) are also managed.

5. **Logical Reasoning Examples - The "If/Then":** I look for specific methods that implement logical operations. `getIntersectionList` and `checkIntersection` are good examples. I need to create hypothetical inputs (an SVG structure, a rectangle) and explain what the expected output would be (a list of intersecting elements, a boolean). I also think about the logic within these functions, like how they use hit testing and traversal.

6. **Common Usage Errors - The "Watch Out":**  I consider what mistakes a developer might make when using the SVG API. This involves thinking about:
    * **Incorrect attribute values:** Providing invalid values for `viewBox` or `preserveAspectRatio`.
    * **Coordinate system misunderstandings:** Not correctly accounting for transformations when performing calculations.
    * **Animation issues:**  Incorrectly controlling or synchronizing animations.
    * **Hit testing caveats:**  Not realizing the limitations of hit testing (e.g., non-rendered elements).

7. **Debugging Clues - The "How Did I Get Here?":**  I consider how a developer might end up needing to look at this specific file during debugging. This often starts with a user action in the browser:
    * **Rendering issues:**  The SVG isn't displaying correctly.
    * **JavaScript errors:**  JavaScript code interacting with the SVG is failing.
    * **Performance problems:**  The SVG is causing layout or rendering bottlenecks.
    * **Unexpected behavior:** The SVG isn't responding to events or interactions as expected.

8. **Structure and Refine:** I organize the information into the requested categories. I use bullet points and clear language to make the explanation easy to understand. I review the code snippets and ensure my examples are accurate and relevant. I try to avoid overly technical jargon where possible, or explain it if necessary.

9. **Iterative Process:**  Analyzing code like this isn't always linear. I might go back and forth between sections, refining my understanding as I discover more connections and details. For example, while looking at the JavaScript API, I might realize the importance of the layout integration for the coordinate transformations.

By following this systematic process, I can thoroughly analyze the `svg_svg_element.cc` file and provide a comprehensive answer that addresses all aspects of the request.
好的，让我们来分析一下 `blink/renderer/core/svg/svg_svg_element.cc` 这个文件。

**文件功能概述:**

这个文件定义了 Blink 渲染引擎中用于处理 SVG `<svg>` 元素的核心逻辑。`SVGSVGElement` 类继承自 `SVGGraphicsElement`， 并且实现了 `SVGFitToViewBox` 接口。  它的主要职责包括：

1. **表示和管理 SVG 文档的根元素:**  `<svg>` 元素是 SVG 文档的根节点，这个文件负责创建、初始化和管理这个根元素及其相关属性。
2. **处理 SVG 元素的属性:** 包括 `x`, `y`, `width`, `height`, `viewBox`, `preserveAspectRatio`, `zoomAndPan` 等关键属性的解析、存储和更新。
3. **与布局引擎交互:**  当 `<svg>` 元素需要渲染时，它会与 Blink 的布局引擎进行交互，创建 `LayoutSVGRoot` (如果是最外层的 `<svg>`) 或 `LayoutSVGViewportContainer` (如果是嵌套的 `<svg>`) 对象，以便进行布局计算。
4. **处理事件:**  监听并处理与 `<svg>` 元素相关的事件，例如 `onload`, `onerror`, `onresize`, `onscroll` 等。特别是对于最外层的 `<svg>` 元素，它还负责监听窗口级别的事件。
5. **实现 SVG 的方法:**  实现了 SVG 规范中定义的 `getIntersectionList`, `getEnclosureList`, `checkIntersection`, `checkEnclosure`, `createSVGNumber`, `createSVGLength` 等方法，用于进行几何计算和创建 SVG 对象。
6. **管理动画:**  通过 `SMILTimeContainer` 管理 SVG 动画。
7. **处理坐标变换:**  负责计算和应用 SVG 的坐标变换，包括 `viewBox` 和 `preserveAspectRatio` 带来的变换。
8. **与 JavaScript 交互:**  提供 JavaScript 接口，允许脚本访问和操作 `<svg>` 元素的属性和方法。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    * **功能关系:**  HTML 用于声明 SVG 元素，例如 `<svg width="100" height="100">...</svg>`。
    * **举例说明:** 当浏览器解析到这样的 HTML 代码时，Blink 会创建 `SVGSVGElement` 的实例来表示这个 `<svg>` 元素。HTML 属性 `width` 和 `height` 的值会被解析并存储到 `SVGSVGElement` 对象的 `width_` 和 `height_` 成员变量中（通过 `SVGAnimatedLength` 管理）。

* **CSS:**
    * **功能关系:** CSS 可以用于设置 SVG 元素的样式，例如 `svg { background-color: red; }`。
    * **举例说明:**  虽然 `width` 和 `height` 属性在 SVG 中有自己的含义，但 CSS 的 `width` 和 `height` 属性也可以影响最外层 `<svg>` 元素的布局。`IsPresentationAttribute` 和 `CollectStyleForPresentationAttribute` 方法用于处理那些可以作为 CSS 属性的 SVG 属性。对于嵌套的 `<svg>`，CSS 的 `width` 和 `height` 可能会覆盖 SVG 属性的设定。

* **JavaScript:**
    * **功能关系:** JavaScript 可以通过 DOM API 来访问和操作 `SVGSVGElement` 对象，例如获取或设置属性、调用方法、监听事件。
    * **举例说明:**
        * **获取属性:**  JavaScript 代码可以使用 `element.width.baseVal.value` 来获取 `<svg>` 元素的 `width` 属性值。这会最终访问到 `SVGSVGElement` 中 `width_` 对应的 `SVGAnimatedLength` 对象。
        * **设置属性:**  JavaScript 可以使用 `element.setAttribute('viewBox', '0 0 50 50')` 来设置 `<svg>` 元素的 `viewBox` 属性。这会触发 `SVGSVGElement::ParseAttribute` 和 `SVGSVGElement::SvgAttributeChanged` 等方法的调用，更新内部状态并可能触发重新布局。
        * **调用方法:** JavaScript 可以调用 `element.getIntersectionList(rect, null)` 来获取与给定矩形相交的 SVG 元素列表。这个方法的实现就在 `svg_svg_element.cc` 文件中。
        * **监听事件:**  可以使用 `element.onload = function() { ... }` 来监听 `<svg>` 元素的 `onload` 事件。`SVGSVGElement::ParseAttribute` 方法会处理 HTML 属性中的事件处理器 (例如 `onload`)，并将其关联到相应的事件监听器。

**逻辑推理的假设输入与输出:**

**场景:** 调用 `getIntersectionList` 方法。

* **假设输入:**
    * 一个 `SVGSVGElement` 对象，其中包含一些子元素（例如 `<rect>`, `<circle>`）。
    * 一个 `SVGRectTearOff` 对象 `rect`，表示一个矩形区域，例如 `{x: 10, y: 10, width: 30, height: 30}`。
    * `reference_element` 参数为 `nullptr`。

* **逻辑推理过程:**
    1. `getIntersectionList` 方法被调用。
    2. 它会创建一个 `HitTestRequest` 对象，用于进行碰撞检测。
    3. 它会创建一个 `HitTestLocation` 对象，基于 `rect` 的中心点和矩形区域。
    4. 它会遍历 `SVGSVGElement` 的子元素，并对每个元素进行 hit testing，判断是否与 `rect` 相交。
    5. 只有 `SVGGraphicsElement` 及其子类会被考虑。
    6. 返回一个 `StaticNodeTypeList<Element>`，其中包含了与 `rect` 相交的 SVG 元素的列表。

* **假设输出:**  一个包含与给定矩形相交的 `<rect>` 和 `<circle>` 元素的 `StaticNodeTypeList<Element>`。 例如，如果一个 `<rect>` 元素的区域部分或全部覆盖了 `{x: 10, y: 10, width: 30, height: 30}`，那么这个 `<rect>` 元素就会包含在输出列表中。

**用户或编程常见的使用错误举例说明:**

1. **错误的 `viewBox` 值:**
    * **错误:** 用户设置了无效的 `viewBox` 属性值，例如 `viewBox="a b c d"` 或 `viewBox="10 20" `（缺少参数）。
    * **后果:**  SVG 内容可能无法正确缩放或定位，导致显示异常。Blink 的 SVG 解析器会尝试容错处理，但结果可能不是用户期望的。
    * **调试线索:** 检查开发者工具中的警告或错误信息，查看 `SVGSVGElement::SvgAttributeChanged` 和 `SVGFitToViewBox::ParseAttribute` 等方法是否被调用，以及相关日志输出。

2. **不理解坐标系统转换:**
    * **错误:**  开发者在 JavaScript 中直接使用鼠标事件的页面坐标来操作 SVG 内部元素，而没有考虑到 SVG 的 `viewBox` 和变换。
    * **后果:**  交互行为不符合预期，例如点击位置与实际操作对象不符。
    * **调试线索:**  可以使用开发者工具查看元素的变换矩阵 (CTM - Current Transformation Matrix)。在 `SVGSVGElement` 中，`ComputeCTM` 和 `ViewBoxToViewTransform` 方法负责计算这些变换。可以使用断点或日志输出查看这些方法的返回值，以理解坐标转换的过程。

3. **滥用最外层 `<svg>` 元素的事件监听:**
    * **错误:**  开发者在所有 `<svg>` 元素上都添加了 `onresize` 或 `onscroll` 事件监听器，期望只在窗口大小改变时触发一次。
    * **后果:**  如果页面中有多个 `<svg>` 元素，这些事件监听器可能会被多次触发，导致性能问题或意外行为。
    * **说明:**  `SVGSVGElement::ParseAttribute` 中可以看到，对于 `onunload`, `onresize`, `onscroll` 事件，只有当 `<svg>` 元素是最外层元素时，才会将其设置为窗口级别的事件监听器。
    * **调试线索:**  使用开发者工具的事件监听器面板查看哪些元素绑定了哪些事件。检查 `SVGSVGElement::nearestViewportElement()` 的返回值，判断是否是最外层元素。

**用户操作如何一步步到达这里，作为调试线索:**

假设用户在浏览器中打开一个包含以下 SVG 代码的 HTML 页面，并尝试点击 SVG 中的一个图形元素：

```html
<!DOCTYPE html>
<html>
<head>
<title>SVG Example</title>
</head>
<body>
  <svg width="200" height="100" viewBox="0 0 200 100">
    <rect id="myRect" x="10" y="10" width="80" height="80" fill="blue" />
  </svg>
  <script>
    const svg = document.querySelector('svg');
    const rect = document.getElementById('myRect');
    svg.addEventListener('click', function(event) {
      const point = svg.createSVGPoint();
      point.x = event.clientX;
      point.y = event.clientY;
      const cursorPoint = point.matrixTransform(svg.getScreenCTM().inverse());
      console.log('Click at SVG coordinates:', cursorPoint.x, cursorPoint.y);

      // 假设开发者想判断点击是否在矩形内
      // 这里可能会用到 getIntersectionList 或 getEnclosureList
    });
  </script>
</body>
</html>
```

**调试线索:**

1. **用户操作:** 用户点击了蓝色矩形。
2. **浏览器事件:** 浏览器捕获到 `click` 事件，并传递给绑定的事件监听器。
3. **JavaScript 执行:**  JavaScript 代码开始执行。
4. **`svg.createSVGPoint()`:**  这行代码会调用 `SVGSVGElement::createSVGPoint()`.
5. **`svg.getScreenCTM()`:** 这行代码最终会涉及到 `SVGSVGElement::LocalCoordinateSpaceTransform(kScreenScope)` 的调用，计算从 SVG 坐标到屏幕坐标的变换矩阵。
6. **可能使用 `getIntersectionList` 或 `getEnclosureList`:**  如果开发者想判断点击是否在矩形内，可能会调用 `svg.getIntersectionList()` 或 `svg.getEnclosureList()`，这会直接调用 `SVGSVGElement` 中对应的实现。在这些方法内部，会涉及到布局树的遍历和几何计算，这些计算依赖于 `SVGSVGElement` 对象的属性和状态。
7. **布局和渲染:**  如果 SVG 的属性发生变化（例如通过 JavaScript 修改），可能会触发布局和渲染的更新。这会涉及到 `SVGSVGElement` 与布局引擎的交互，例如创建或更新 `LayoutSVGRoot` 对象。

因此，当开发者在调试与 SVG 元素交互相关的 JavaScript 代码时，例如处理点击事件、判断元素是否在某个区域内，或者动态修改 SVG 属性导致渲染问题时，就有可能需要查看 `svg_svg_element.cc` 中的代码，以理解 SVG 元素是如何被创建、管理、以及如何与布局引擎和 JavaScript 进行交互的。他们可能会在这些关键方法上设置断点，例如 `createSVGPoint`, `getScreenCTM`, `getIntersectionList`, `SvgAttributeChanged` 等，以跟踪代码的执行流程和查看相关变量的值。

希望以上分析能够帮助你理解 `blink/renderer/core/svg/svg_svg_element.cc` 文件的功能和作用。

### 提示词
```
这是目录为blink/renderer/core/svg/svg_svg_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2004, 2005, 2006 Nikolas Zimmermann <zimmermann@kde.org>
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2010 Rob Buis <buis@kde.org>
 * Copyright (C) 2007 Apple Inc. All rights reserved.
 * Copyright (C) 2014 Google, Inc.
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

#include "third_party/blink/renderer/core/svg/svg_svg_element.h"

#include "base/ranges/algorithm.h"
#include "third_party/blink/renderer/bindings/core/v8/js_event_handler_for_content_attribute.h"
#include "third_party/blink/renderer/core/css/css_resolution_units.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/event_listener.h"
#include "third_party/blink/renderer/core/dom/static_node_list.h"
#include "third_party/blink/renderer/core/dom/xml_document.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/layout/hit_test_location.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_model_object.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_root.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_viewport_container.h"
#include "third_party/blink/renderer/core/layout/svg/svg_layout_support.h"
#include "third_party/blink/renderer/core/layout/svg/transformed_hit_test_location.h"
#include "third_party/blink/renderer/core/svg/animation/smil_time_container.h"
#include "third_party/blink/renderer/core/svg/svg_angle_tear_off.h"
#include "third_party/blink/renderer/core/svg/svg_animated_length.h"
#include "third_party/blink/renderer/core/svg/svg_animated_preserve_aspect_ratio.h"
#include "third_party/blink/renderer/core/svg/svg_animated_rect.h"
#include "third_party/blink/renderer/core/svg/svg_document_extensions.h"
#include "third_party/blink/renderer/core/svg/svg_g_element.h"
#include "third_party/blink/renderer/core/svg/svg_length_context.h"
#include "third_party/blink/renderer/core/svg/svg_length_tear_off.h"
#include "third_party/blink/renderer/core/svg/svg_matrix_tear_off.h"
#include "third_party/blink/renderer/core/svg/svg_number_tear_off.h"
#include "third_party/blink/renderer/core/svg/svg_point_tear_off.h"
#include "third_party/blink/renderer/core/svg/svg_preserve_aspect_ratio.h"
#include "third_party/blink/renderer/core/svg/svg_rect_tear_off.h"
#include "third_party/blink/renderer/core/svg/svg_transform.h"
#include "third_party/blink/renderer/core/svg/svg_transform_list.h"
#include "third_party/blink/renderer/core/svg/svg_transform_tear_off.h"
#include "third_party/blink/renderer/core/svg/svg_use_element.h"
#include "third_party/blink/renderer/core/svg/svg_view_element.h"
#include "third_party/blink/renderer/core/svg/svg_view_spec.h"
#include "third_party/blink/renderer/core/svg_names.h"
#include "third_party/blink/renderer/platform/geometry/length_functions.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/transforms/affine_transform.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "ui/gfx/geometry/rect_f.h"

namespace blink {

SVGSVGElement::SVGSVGElement(Document& doc)
    : SVGGraphicsElement(svg_names::kSVGTag, doc),
      SVGFitToViewBox(this),
      x_(MakeGarbageCollected<SVGAnimatedLength>(
          this,
          svg_names::kXAttr,
          SVGLengthMode::kWidth,
          SVGLength::Initial::kUnitlessZero,
          CSSPropertyID::kX)),
      y_(MakeGarbageCollected<SVGAnimatedLength>(
          this,
          svg_names::kYAttr,
          SVGLengthMode::kHeight,
          SVGLength::Initial::kUnitlessZero,
          CSSPropertyID::kY)),
      width_(MakeGarbageCollected<SVGAnimatedLength>(
          this,
          svg_names::kWidthAttr,
          SVGLengthMode::kWidth,
          SVGLength::Initial::kPercent100,
          CSSPropertyID::kWidth)),
      height_(MakeGarbageCollected<SVGAnimatedLength>(
          this,
          svg_names::kHeightAttr,
          SVGLengthMode::kHeight,
          SVGLength::Initial::kPercent100,
          CSSPropertyID::kHeight)),
      time_container_(MakeGarbageCollected<SMILTimeContainer>(*this)),
      translation_(MakeGarbageCollected<SVGPoint>()),
      current_scale_(1) {
  UseCounter::Count(doc, WebFeature::kSVGSVGElement);
}

SVGSVGElement::~SVGSVGElement() = default;

float SVGSVGElement::currentScale() const {
  if (!isConnected() || !IsOutermostSVGSVGElement())
    return 1;

  return current_scale_;
}

void SVGSVGElement::setCurrentScale(float scale) {
  DCHECK(std::isfinite(scale));
  if (!isConnected() || !IsOutermostSVGSVGElement())
    return;

  current_scale_ = scale;
  UpdateUserTransform();
}

class SVGCurrentTranslateTearOff : public SVGPointTearOff {
 public:
  SVGCurrentTranslateTearOff(SVGSVGElement* context_element)
      : SVGPointTearOff(context_element->translation_, context_element) {}

  void CommitChange(SVGPropertyCommitReason) override {
    DCHECK(ContextElement());
    To<SVGSVGElement>(ContextElement())->UpdateUserTransform();
  }
};

SVGPointTearOff* SVGSVGElement::currentTranslateFromJavascript() {
  return MakeGarbageCollected<SVGCurrentTranslateTearOff>(this);
}

void SVGSVGElement::SetCurrentTranslate(const gfx::Vector2dF& point) {
  translation_->SetValue(gfx::PointAtOffsetFromOrigin(point));
  UpdateUserTransform();
}

void SVGSVGElement::UpdateUserTransform() {
  if (LayoutObject* object = GetLayoutObject()) {
    object->SetNeedsLayoutAndFullPaintInvalidation(
        layout_invalidation_reason::kUnknown);
  }
}

bool SVGSVGElement::ZoomAndPanEnabled() const {
  SVGZoomAndPanType zoom_and_pan = zoomAndPan();
  if (view_spec_ && view_spec_->ZoomAndPan() != kSVGZoomAndPanUnknown)
    zoom_and_pan = view_spec_->ZoomAndPan();
  return zoom_and_pan == kSVGZoomAndPanMagnify;
}

void SVGSVGElement::ParseAttribute(const AttributeModificationParams& params) {
  const QualifiedName& name = params.name;
  const AtomicString& value = params.new_value;
  if (!nearestViewportElement()) {
    bool set_listener = true;

    // Only handle events if we're the outermost <svg> element
    if (name == html_names::kOnunloadAttr) {
      GetDocument().SetWindowAttributeEventListener(
          event_type_names::kUnload, JSEventHandlerForContentAttribute::Create(
                                         GetExecutionContext(), name, value));
    } else if (name == html_names::kOnresizeAttr) {
      GetDocument().SetWindowAttributeEventListener(
          event_type_names::kResize, JSEventHandlerForContentAttribute::Create(
                                         GetExecutionContext(), name, value));
    } else if (name == html_names::kOnscrollAttr) {
      GetDocument().SetWindowAttributeEventListener(
          event_type_names::kScroll, JSEventHandlerForContentAttribute::Create(
                                         GetExecutionContext(), name, value));
    } else {
      set_listener = false;
    }

    if (set_listener)
      return;
  }

  if (name == html_names::kOnabortAttr) {
    GetDocument().SetWindowAttributeEventListener(
        event_type_names::kAbort, JSEventHandlerForContentAttribute::Create(
                                      GetExecutionContext(), name, value));
  } else if (name == html_names::kOnerrorAttr) {
    GetDocument().SetWindowAttributeEventListener(
        event_type_names::kError,
        JSEventHandlerForContentAttribute::Create(
            GetExecutionContext(), name, value,
            JSEventHandler::HandlerType::kOnErrorEventHandler));
  } else if (SVGZoomAndPan::ParseAttribute(name, value)) {
  } else {
    SVGElement::ParseAttribute(params);
  }
}

bool SVGSVGElement::IsPresentationAttribute(const QualifiedName& name) const {
  if ((name == svg_names::kWidthAttr || name == svg_names::kHeightAttr) &&
      !IsOutermostSVGSVGElement())
    return false;
  return SVGGraphicsElement::IsPresentationAttribute(name);
}

void SVGSVGElement::CollectStyleForPresentationAttribute(
    const QualifiedName& name,
    const AtomicString& value,
    MutableCSSPropertyValueSet* style) {
  // We shouldn't collect style for 'width' and 'height' on inner <svg>, so
  // bail here in that case to avoid having the generic logic in SVGElement
  // picking it up.
  if ((name == svg_names::kWidthAttr || name == svg_names::kHeightAttr) &&
      !IsOutermostSVGSVGElement()) {
    return;
  }
  SVGGraphicsElement::CollectStyleForPresentationAttribute(name, value, style);
}

void SVGSVGElement::SvgAttributeChanged(
    const SvgAttributeChangedParams& params) {
  const QualifiedName& attr_name = params.name;
  bool update_relative_lengths_or_view_box = false;
  bool width_or_height_changed =
      attr_name == svg_names::kWidthAttr || attr_name == svg_names::kHeightAttr;
  if (width_or_height_changed || attr_name == svg_names::kXAttr ||
      attr_name == svg_names::kYAttr) {
    update_relative_lengths_or_view_box = true;
    UpdateRelativeLengthsInformation();
    InvalidateRelativeLengthClients();

    // At the SVG/HTML boundary (aka LayoutSVGRoot), the width and
    // height attributes can affect the replaced size so we need
    // to mark it for updating.
    if (width_or_height_changed) {
      LayoutObject* layout_object = GetLayoutObject();
      // If the element is not attached, we cannot be sure if it is (going to
      // be) an outermost root, so always mark presentation attributes dirty in
      // that case.
      if (!layout_object || layout_object->IsSVGRoot()) {
        UpdatePresentationAttributeStyle(params.property);
        if (layout_object)
          To<LayoutSVGRoot>(layout_object)->IntrinsicSizingInfoChanged();
      }
    } else {
      UpdatePresentationAttributeStyle(params.property);
    }
  }

  if (SVGFitToViewBox::IsKnownAttribute(attr_name)) {
    update_relative_lengths_or_view_box = true;
    InvalidateRelativeLengthClients();
    if (LayoutObject* object = GetLayoutObject()) {
      object->SetNeedsTransformUpdate();
      if (attr_name == svg_names::kViewBoxAttr && object->IsSVGRoot())
        To<LayoutSVGRoot>(object)->IntrinsicSizingInfoChanged();
    }
  }

  if (update_relative_lengths_or_view_box ||
      SVGZoomAndPan::IsKnownAttribute(attr_name)) {
    if (auto* layout_object = GetLayoutObject())
      MarkForLayoutAndParentResourceInvalidation(*layout_object);
    return;
  }

  SVGGraphicsElement::SvgAttributeChanged(params);
}

void SVGSVGElement::DidMoveToNewDocument(Document& old_document) {
  SVGGraphicsElement::DidMoveToNewDocument(old_document);
  if (TimeContainer()->IsStarted()) {
    TimeContainer()->ResetDocumentTime();
  }
}

namespace {

const SVGElement* InnermostCommonSubtreeRoot(
    const SVGSVGElement& svg_root,
    const SVGElement* reference_element) {
  if (reference_element) {
    // The reference element is a descendant of the <svg> element
    // -> reference element is root of the common subtree.
    if (svg_root.contains(reference_element)) {
      return reference_element;
    }
    // The <svg> element is not a descendant of the reference element
    // -> no common subtree.
    if (!svg_root.IsDescendantOf(reference_element)) {
      return nullptr;
    }
  }
  return &svg_root;
}

enum class ElementResultFilter {
  kOnlyDescendants,
  kDescendantsOrReference,
};

HeapVector<Member<Element>> ComputeIntersectionList(
    const SVGSVGElement& root,
    const SVGElement* reference_element,
    const gfx::RectF& rect,
    ElementResultFilter filter) {
  HeapVector<Member<Element>> elements;
  LocalFrameView* frame_view = root.GetDocument().View();
  if (!frame_view || !frame_view->UpdateAllLifecyclePhasesExceptPaint(
                         DocumentUpdateReason::kJavaScript)) {
    return elements;
  }
  const LayoutObject* layout_object = root.GetLayoutObject();
  if (!layout_object) {
    return elements;
  }
  const SVGElement* common_subtree_root =
      InnermostCommonSubtreeRoot(root, reference_element);
  if (!common_subtree_root) {
    return elements;
  }

  HitTestRequest request(HitTestRequest::kReadOnly | HitTestRequest::kActive |
                         HitTestRequest::kListBased |
                         HitTestRequest::kPenetratingList);
  HitTestLocation location(rect.CenterPoint(), gfx::QuadF(rect));
  HitTestResult result(request, location);
  // Transform to the local space of `root`.
  // We could transform the location to the space of the reference element (the
  // common subtree), but that quickly gets quite hairy.
  TransformedHitTestLocation local_location(
      location, root.ComputeCTM(SVGElement::kAncestorScope, &root));
  if (local_location) {
    if (const auto* layout_root = DynamicTo<LayoutSVGRoot>(layout_object)) {
      layout_root->IntersectChildren(result, *local_location);
    } else {
      To<LayoutSVGViewportContainer>(layout_object)
          ->IntersectChildren(result, *local_location);
    }
  }
  // Do a first pass transforming text-nodes to their parents.
  elements = root.GetTreeScope().ElementsFromHitTestResult(result);
  // We want all elements that are SVGGraphicsElements and descendants of the
  // common subtree root.
  auto partition_condition = [common_subtree_root,
                              filter](const Member<Element>& item) {
    if (!IsA<SVGGraphicsElement>(*item)) {
      return false;
    }
    return filter == ElementResultFilter::kDescendantsOrReference
               ? common_subtree_root->contains(item)
               : item->IsDescendantOf(common_subtree_root);
  };
  auto to_remove = std::stable_partition(elements.begin(), elements.end(),
                                         partition_condition);
  elements.erase(to_remove, elements.end());
  // Hit-testing traverses the tree from last to first child for each
  // container, so the result needs to be reversed.
  base::ranges::reverse(elements);
  return elements;
}

}  // namespace

StaticNodeTypeList<Element>* SVGSVGElement::getIntersectionList(
    SVGRectTearOff* rect,
    SVGElement* reference_element) const {
  // https://svgwg.org/svg2-draft/struct.html#__svg__SVGSVGElement__getIntersectionList
  HeapVector<Member<Element>> intersecting_elements =
      ComputeIntersectionList(*this, reference_element, rect->Target()->Rect(),
                              ElementResultFilter::kOnlyDescendants);
  return StaticNodeTypeList<Element>::Adopt(intersecting_elements);
}

bool SVGSVGElement::checkIntersection(SVGElement* element,
                                      SVGRectTearOff* rect) const {
  // https://svgwg.org/svg2-draft/struct.html#__svg__SVGSVGElement__checkIntersection
  DCHECK(element);
  auto* graphics_element = DynamicTo<SVGGraphicsElement>(*element);
  // If `element` is not an SVGGraphicsElement it can not intersect.
  if (!graphics_element) {
    return false;
  }

  // Collect intersecting descendants of the SVGSVGElement within `rect`.
  HeapVector<Member<Element>> intersecting_elements =
      ComputeIntersectionList(*this, element, rect->Target()->Rect(),
                              ElementResultFilter::kDescendantsOrReference);
  HeapHashSet<Member<Element>> intersecting_element_set;
  for (const auto& intersected_element : intersecting_elements) {
    intersecting_element_set.insert(intersected_element);
  }

  // This implements the spec section named "find the non-container graphics
  // elements" combined with the step that checks if all such elements are also
  // part of the intersecting descendants.
  size_t elements_matched = 0;
  for (SVGGraphicsElement& descendant :
       Traversal<SVGGraphicsElement>::InclusiveDescendantsOf(
           *graphics_element)) {
    if (IsA<SVGGElement>(descendant) || IsA<SVGSVGElement>(descendant)) {
      continue;
    }
    if (!intersecting_element_set.Contains(&descendant)) {
      return false;
    }
    elements_matched++;
  }
  // If at least one SVGGraphicsElement matched it's an intersection.
  return elements_matched > 0;
}

// One of the element types that can cause graphics to be drawn onto the target
// canvas. Specifically: circle, ellipse, image, line, path, polygon, polyline,
// rect, text and use.
static bool IsEnclosureTarget(const LayoutObject* layout_object) {
  if (!layout_object ||
      layout_object->StyleRef().UsedPointerEvents() == EPointerEvents::kNone) {
    return false;
  }
  return layout_object->IsSVGShape() || layout_object->IsSVGText() ||
         layout_object->IsSVGImage() ||
         IsA<SVGUseElement>(*layout_object->GetNode());
}

bool SVGSVGElement::CheckEnclosure(const SVGElement& element,
                                   const gfx::RectF& rect) const {
  const LayoutObject* layout_object = element.GetLayoutObject();
  if (!IsEnclosureTarget(layout_object)) {
    return false;
  }

  AffineTransform ctm =
      To<SVGGraphicsElement>(element).ComputeCTM(kAncestorScope, this);
  gfx::RectF visual_rect = layout_object->VisualRectInLocalSVGCoordinates();
  SVGLayoutSupport::AdjustWithClipPathAndMask(
      *layout_object, layout_object->ObjectBoundingBox(), visual_rect);
  gfx::RectF mapped_repaint_rect = ctm.MapRect(visual_rect);
  return rect.Contains(mapped_repaint_rect);
}

StaticNodeList* SVGSVGElement::getEnclosureList(
    SVGRectTearOff* query_rect,
    SVGElement* reference_element) const {
  GetDocument().UpdateStyleAndLayoutForNode(this,
                                            DocumentUpdateReason::kJavaScript);

  const gfx::RectF& rect = query_rect->Target()->Rect();
  HeapVector<Member<Node>> nodes;
  if (const SVGElement* root =
          InnermostCommonSubtreeRoot(*this, reference_element)) {
    for (SVGGraphicsElement& element :
         Traversal<SVGGraphicsElement>::DescendantsOf(*root)) {
      if (CheckEnclosure(element, rect)) {
        nodes.push_back(&element);
      }
    }
  }
  return StaticNodeList::Adopt(nodes);
}

bool SVGSVGElement::checkEnclosure(SVGElement* element,
                                   SVGRectTearOff* rect) const {
  DCHECK(element);
  GetDocument().UpdateStyleAndLayoutForNode(this,
                                            DocumentUpdateReason::kJavaScript);

  return CheckEnclosure(*element, rect->Target()->Rect());
}

void SVGSVGElement::deselectAll() {
  if (LocalFrame* frame = GetDocument().GetFrame())
    frame->Selection().Clear();
}

SVGNumberTearOff* SVGSVGElement::createSVGNumber() {
  return SVGNumberTearOff::CreateDetached();
}

SVGLengthTearOff* SVGSVGElement::createSVGLength() {
  return SVGLengthTearOff::CreateDetached();
}

SVGAngleTearOff* SVGSVGElement::createSVGAngle() {
  return SVGAngleTearOff::CreateDetached();
}

SVGPointTearOff* SVGSVGElement::createSVGPoint() {
  return SVGPointTearOff::CreateDetached(gfx::PointF(0, 0));
}

SVGMatrixTearOff* SVGSVGElement::createSVGMatrix() {
  return MakeGarbageCollected<SVGMatrixTearOff>(AffineTransform());
}

SVGRectTearOff* SVGSVGElement::createSVGRect() {
  return SVGRectTearOff::CreateDetached(0, 0, 0, 0);
}

SVGTransformTearOff* SVGSVGElement::createSVGTransform() {
  return SVGTransformTearOff::CreateDetached();
}

SVGTransformTearOff* SVGSVGElement::createSVGTransformFromMatrix(
    SVGMatrixTearOff* matrix) {
  return MakeGarbageCollected<SVGTransformTearOff>(matrix);
}

AffineTransform SVGSVGElement::LocalCoordinateSpaceTransform(
    CTMScope mode) const {
  const LayoutObject* layout_object = GetLayoutObject();
  gfx::SizeF viewport_size;
  AffineTransform transform;
  if (!IsOutermostSVGSVGElement()) {
    SVGLengthContext length_context(this);
    transform.Translate(x_->CurrentValue()->Value(length_context),
                        y_->CurrentValue()->Value(length_context));
    if (layout_object) {
      viewport_size =
          To<LayoutSVGViewportContainer>(*layout_object).Viewport().size();
    }
  } else if (layout_object) {
    if (mode == kScreenScope) {
      gfx::Transform matrix;
      // Adjust for the zoom level factored into CSS coordinates (WK bug
      // #96361).
      matrix.Scale(1.0 / layout_object->View()->StyleRef().EffectiveZoom());

      // Apply transforms from our ancestor coordinate space, including any
      // non-SVG ancestor transforms.
      matrix.PreConcat(layout_object->LocalToAbsoluteTransform());

      // At the SVG/HTML boundary (aka LayoutSVGRoot), we need to apply the
      // localToBorderBoxTransform to map an element from SVG viewport
      // coordinates to CSS box coordinates.
      matrix.PreConcat(To<LayoutSVGRoot>(layout_object)
                           ->LocalToBorderBoxTransform()
                           .ToTransform());
      // Drop any potential non-affine parts, because we're not able to convey
      // that information further anyway until getScreenCTM returns a DOMMatrix
      // (4x4 matrix.)
      return AffineTransform::FromTransform(matrix);
    }
    viewport_size = To<LayoutSVGRoot>(*layout_object).ViewportSize();
  }
  if (!HasEmptyViewBox()) {
    transform.PreConcat(ViewBoxToViewTransform(viewport_size));
  }
  return transform;
}

bool SVGSVGElement::LayoutObjectIsNeeded(const DisplayStyle& style) const {
  // FIXME: We should respect display: none on the documentElement svg element
  // but many things in LocalFrameView and SVGImage depend on the LayoutSVGRoot
  // when they should instead depend on the LayoutView.
  // https://bugs.webkit.org/show_bug.cgi?id=103493
  if (IsDocumentElement())
    return true;

  // <svg> elements don't need an SVG parent to render, so we bypass
  // SVGElement::layoutObjectIsNeeded.
  return IsValid() && Element::LayoutObjectIsNeeded(style);
}

void SVGSVGElement::AttachLayoutTree(AttachContext& context) {
  SVGGraphicsElement::AttachLayoutTree(context);

  if (GetLayoutObject() && GetLayoutObject()->IsSVGRoot()) {
    To<LayoutSVGRoot>(GetLayoutObject())->IntrinsicSizingInfoChanged();
  }
}

LayoutObject* SVGSVGElement::CreateLayoutObject(const ComputedStyle&) {
  if (IsOutermostSVGSVGElement())
    return MakeGarbageCollected<LayoutSVGRoot>(this);

  return MakeGarbageCollected<LayoutSVGViewportContainer>(this);
}

Node::InsertionNotificationRequest SVGSVGElement::InsertedInto(
    ContainerNode& root_parent) {
  if (root_parent.isConnected()) {
    UseCounter::Count(GetDocument(), WebFeature::kSVGSVGElementInDocument);
    if (IsA<XMLDocument>(root_parent.GetDocument()))
      UseCounter::Count(GetDocument(), WebFeature::kSVGSVGElementInXMLDocument);

    GetDocument().AccessSVGExtensions().AddTimeContainer(this);

    // Animations are started at the end of document parsing and after firing
    // the load event, but if we miss that train (deferred programmatic
    // element insertion for example) we need to initialize the time container
    // here.
    if (!GetDocument().Parsing() && GetDocument().LoadEventFinished() &&
        !TimeContainer()->IsStarted())
      TimeContainer()->Start();
  }
  return SVGGraphicsElement::InsertedInto(root_parent);
}

void SVGSVGElement::RemovedFrom(ContainerNode& root_parent) {
  if (root_parent.isConnected()) {
    SVGDocumentExtensions& svg_extensions = GetDocument().AccessSVGExtensions();
    svg_extensions.RemoveTimeContainer(this);
    svg_extensions.RemoveSVGRootWithRelativeLengthDescendents(this);
  }

  SVGGraphicsElement::RemovedFrom(root_parent);
}

void SVGSVGElement::pauseAnimations() {
  if (!time_container_->IsPaused())
    time_container_->Pause();
}

void SVGSVGElement::unpauseAnimations() {
  if (time_container_->IsPaused())
    time_container_->Unpause();
}

bool SVGSVGElement::animationsPaused() const {
  return time_container_->IsPaused();
}

float SVGSVGElement::getCurrentTime() const {
  return ClampTo<float>(time_container_->Elapsed().InSecondsF());
}

void SVGSVGElement::setCurrentTime(float seconds) {
  DCHECK(std::isfinite(seconds));
  time_container_->SetElapsed(SMILTime::FromSecondsD(std::max(seconds, 0.0f)));
}

bool SVGSVGElement::SelfHasRelativeLengths() const {
  return x_->CurrentValue()->IsRelative() || y_->CurrentValue()->IsRelative() ||
         width_->CurrentValue()->IsRelative() ||
         height_->CurrentValue()->IsRelative();
}

bool SVGSVGElement::HasEmptyViewBox() const {
  const SVGRect& view_box = CurrentViewBox();
  return HasValidViewBox(view_box) && view_box.Rect().IsEmpty();
}

bool SVGSVGElement::ShouldSynthesizeViewBox() const {
  if (!IsDocumentElement())
    return false;
  const auto* svg_root = DynamicTo<LayoutSVGRoot>(GetLayoutObject());
  return svg_root && svg_root->IsEmbeddedThroughSVGImage();
}

const SVGRect& SVGSVGElement::CurrentViewBox() const {
  if (view_spec_ && view_spec_->ViewBox()) {
    return *view_spec_->ViewBox();
  }
  return *viewBox()->CurrentValue();
}

gfx::RectF SVGSVGElement::CurrentViewBoxRect() const {
  gfx::RectF use_view_box = CurrentViewBox().Rect();
  if (!use_view_box.IsEmpty())
    return use_view_box;
  if (!ShouldSynthesizeViewBox())
    return gfx::RectF();

  // If no viewBox is specified but non-relative width/height values, then we
  // should always synthesize a viewBox if we're embedded through a SVGImage.
  SVGLengthContext length_context(this);
  gfx::SizeF synthesized_view_box_size(
      width()->CurrentValue()->Value(length_context),
      height()->CurrentValue()->Value(length_context));
  return gfx::RectF(synthesized_view_box_size);
}

const SVGPreserveAspectRatio* SVGSVGElement::CurrentPreserveAspectRatio()
    const {
  if (view_spec_ && view_spec_->PreserveAspectRatio())
    return view_spec_->PreserveAspectRatio();

  if (!HasValidViewBox(CurrentViewBox()) && ShouldSynthesizeViewBox()) {
    // If no (valid) viewBox is specified and we're embedded through SVGImage,
    // then synthesize a pAR with the value 'none'.
    auto* synthesized_par = MakeGarbageCollected<SVGPreserveAspectRatio>();
    synthesized_par->SetAlign(
        SVGPreserveAspectRatio::kSvgPreserveaspectratioNone);
    return synthesized_par;
  }
  return preserveAspectRatio()->CurrentValue();
}

std::optional<float> SVGSVGElement::IntrinsicWidth() const {
  const SVGLength& width_attr = *width()->CurrentValue();
  // TODO(crbug.com/979895): This is the result of a refactoring, which might
  // have revealed an existing bug that we are not handling math functions
  // involving percentages correctly. Fix it if necessary.
  if (width_attr.IsPercentage())
    return std::nullopt;
  SVGLengthContext length_context(this);
  return std::max(0.0f, width_attr.Value(length_context));
}

std::optional<float> SVGSVGElement::IntrinsicHeight() const {
  const SVGLength& height_attr = *height()->CurrentValue();
  // TODO(crbug.com/979895): This is the result of a refactoring, which might
  // have revealed an existing bug that we are not handling math functions
  // involving percentages correctly. Fix it if necessary.
  if (height_attr.IsPercentage())
    return std::nullopt;
  SVGLengthContext length_context(this);
  return std::max(0.0f, height_attr.Value(length_context));
}

AffineTransform SVGSVGElement::ViewBoxToViewTransform(
    const gfx::SizeF& viewport_size) const {
  AffineTransform ctm = SVGFitToViewBox::ViewBoxToViewTransform(
      CurrentViewBoxRect(), CurrentPreserveAspectRatio(), viewport_size);
  if (!view_spec_ || !view_spec_->Transform())
    return ctm;
  const SVGTransformList* transform_list = view_spec_->Transform();
  if (!transform_list->IsEmpty())
    ctm *= transform_list->Concatenate();
  return ctm;
}

void SVGSVGElement::SetViewSpec(const SVGViewSpec* view_spec) {
  // Even if the viewspec object itself doesn't change, it could still
  // have been mutated, so only treat a "no viewspec" -> "no viewspec"
  // transition as a no-op.
  if (!view_spec_ && !view_spec)
    return;
  view_spec_ = view_spec;
  if (LayoutObject* layout_object = GetLayoutObject())
    MarkForLayoutAndParentResourceInvalidation(*layout_object);
}

const SVGViewSpec* SVGSVGElement::ParseViewSpec(
    const String& fragment_identifier,
    Element* anchor_node) const {
  if (fragment_identifier.StartsWith("svgView(")) {
    const SVGViewSpec* view_spec =
        SVGViewSpec::CreateFromFragment(fragment_identifier);
    if (view_spec) {
      UseCounter::Count(GetDocument(),
                        WebFeature::kSVGSVGElementFragmentSVGView);
      return view_spec;
    }
  }
  if (auto* svg_view_element = DynamicTo<SVGViewElement>(anchor_node)) {
    // Spec: If the SVG fragment identifier addresses a 'view' element within an
    // SVG document (e.g., MyDrawing.svg#MyView) then the root 'svg' element is
    // displayed in the SVG viewport. Any view specification attributes included
    // on the given 'view' element override the corresponding view specification
    // attributes on the root 'svg' element.
    const SVGViewSpec* view_spec =
        SVGViewSpec::CreateForViewElement(*svg_view_element);
    UseCounter::Count(GetDocument(),
                      WebFeature::kSVGSVGElementFragmentSVGViewElement);
    return view_spec;
  }
  return nullptr;
}

void SVGSVGElement::FinishParsingChildren() {
  SVGGraphicsElement::FinishParsingChildren();

  // The outermost SVGSVGElement SVGLoad event is fired through
  // LocalDOMWindow::dispatchWindowLoadEvent.
  if (IsOutermostSVGSVGElement())
    return;

  // finishParsingChildren() is called when the close tag is reached for an
  // element (e.g. </svg>) we send SVGLoad events here if we can, otherwise
  // they'll be sent when any required loads finish
  SendSVGLoadEventIfPossible();
}

void SVGSVGElement::Trace(Visitor* visitor) const {
  visitor->Trace(x_);
  visitor->Trace(y_);
  visitor->Trace(width_);
  visitor->Trace(height_);
  visitor->Trace(translation_);
  visitor->Trace(time_container_);
  visitor->Trace(view_spec_);
  SVGGraphicsElement::Trace(visitor);
  SVGFitToViewBox::Trace(visitor);
}

SVGAnimatedPropertyBase* SVGSVGElement::PropertyFromAttribute(
    const QualifiedName& attribute_name) const {
  if (attribute_name == svg_names::kXAttr) {
    return x_.Get();
  } else if (attribute_name == svg_names::kYAttr) {
    return y_.Get();
  } else if (attribute_name == svg_names::kWidthAttr) {
    return width_.Get();
  } else if (attribute_name == svg_names::kHeightAttr) {
    return height_.Get();
  } else {
    SVGAnimatedPropertyBase* ret =
        SVGFitToViewBox::PropertyFromAttribute(attribute_name);
    if (ret) {
      return ret;
    } else {
      return SVGGraphicsElement::PropertyFromAttribute(attribute_name);
    }
  }
}

void SVGSVGElement::SynchronizeAllSVGAttributes() const {
  SVGAnimatedPropertyBase* attrs[]{x_.Get(), y_.Get(), width_.Get(),
                                   height_.Get()};
  SynchronizeListOfSVGAttributes(attrs);
  SVGFitToViewBox::SynchronizeAllSVGAttributes();
  SVGGraphicsElement::SynchronizeAllSVGAttributes();
}

void SVGSVGElement::CollectExtraStyleForPresentationAttribute(
    MutableCSSPropertyValueSet* style) {
  auto pres_attrs = std::to_array<const SVGAnimatedPropertyBase*>(
      {x_.Get(), y_.Get(), width_.Get(), height_.Get()});
  AddAnimatedPropertiesToPresentationAttributeStyle(pres_attrs, style);
  SVGGraphicsElement::CollectExtraStyleForPresentationAttribute(style);
}

}  // namespace blink
```