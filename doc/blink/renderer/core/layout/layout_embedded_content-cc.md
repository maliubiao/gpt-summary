Response:
Let's break down the thought process for analyzing the provided C++ code and generating the summary.

**1. Understanding the Goal:**

The core request is to understand the functionality of `layout_embedded_content.cc` in the Chromium Blink engine. Specifically, we need to:

* Describe its purpose.
* Identify its relationships with web technologies (HTML, CSS, JavaScript).
* Explain any logical reasoning within the code, including hypothetical inputs and outputs.
* Point out potential user or programming errors related to this component.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code for key terms and patterns. This gives a high-level overview. I'd look for:

* **Class Name:** `LayoutEmbeddedContent` -  Immediately suggests this class deals with the layout of embedded content.
* **Inheritance:** `LayoutReplaced` - Indicates it inherits functionality related to replaced elements (like `<img>`, `<video>`, `<iframe>`).
* **Includes:**  `HTMLFrameOwnerElement`, `HTMLFrameElementBase`, `HTMLPluginElement`, `HTMLFencedFrameElement`, `EmbeddedContentView`, `WebPluginContainerImpl`, `FrameView`, `LocalFrameView`, `RemoteFrameView` -  These headers point to its core responsibilities: handling iframes, plugins, and fenced frames.
* **Methods:**  `ChildFrameView`, `ChildLayoutView`, `Plugin`, `GetEmbeddedContentView`, `FrozenFrameSize`, `EmbeddedContentTransform`, `NodeAtPoint`, `StyleDidChange`, `PaintReplaced`, `PropagateZoomFactor`, `UpdateGeometry`, `IsThrottledFrameView` - These method names offer clues about specific functionalities, such as accessing child frames, handling hit testing, responding to style changes, painting, and managing zoom.
* **Keywords:** `DCHECK`, `NOT_DESTROYED`, `SetInline(false)`, `AffineTransform`, `HitTestResult`, `PaintInfo`, `CursorDirective` - These indicate internal checks, lifecycle management, and interactions with rendering and input.

**3. Deconstructing the Functionality (Method by Method):**

Once I have a general idea, I start analyzing the methods individually:

* **Constructor/Destructor (`LayoutEmbeddedContent`, `WillBeDestroyed`):**  Basic object lifecycle management, setting `inline` to `false` (meaning it behaves like a block element), and clearing references. Important for memory management.
* **Accessors (`ChildFrameView`, `ChildLayoutView`, `Plugin`, `GetEmbeddedContentView`):** These methods provide ways to access related objects, crucial for inter-component communication.
* **Size and Transformation (`FrozenFrameSize`, `EmbeddedContentTransform`, `EmbeddedContentFromBorderBox`, `BorderBoxFromEmbeddedContent`):** These are clearly about handling the size and positioning of the embedded content, especially in cases like fenced frames where the size might be fixed. The transformation methods indicate handling coordinate system conversions.
* **Hit Testing (`PointOverResizer`, `NodeAtPointOverEmbeddedContentView`, `NodeAtPoint`):**  This is a significant part. It's about determining if a point on the screen interacts with the embedded content, including handling resizers and delegating hit testing to child frames. The complexity of `NodeAtPoint` suggests careful handling of different scenarios (throttled frames, child frame hit testing).
* **Style Changes (`StyleDidChange`, `PropagateZoomFactor`):** This relates to how the layout object reacts to changes in CSS styles, including visibility, zoom, and color scheme. It also demonstrates how style changes are propagated to the embedded content.
* **Painting (`PaintReplaced`):**  Deals with rendering the embedded content, often delegating to a dedicated painter class.
* **Cursor Management (`GetCursor`):**  Determines the appropriate cursor to display when the mouse is over the embedded content. Plugins have their own cursor handling.
* **Sizing and Updates (`ReplacedContentRectFrom`, `UpdateOnEmbeddedContentViewChange`, `UpdateGeometry`):** These methods handle the sizing of the embedded content and updating its geometry based on various factors, including frozen sizes and changes in the embedded content view.
* **Throttling (`IsThrottledFrameView`):** Checks if the embedded frame is currently being throttled for performance reasons.

**4. Identifying Relationships with Web Technologies:**

As I analyze the methods, I actively think about how they connect to HTML, CSS, and JavaScript:

* **HTML:**  The class directly interacts with HTML elements like `<iframe>`, `<frame>`, `<object>`, `<embed>`, and `<fencedframe>`. The methods handle the layout and behavior of these elements.
* **CSS:** `StyleDidChange` and `PropagateZoomFactor` explicitly show the connection to CSS. Changes in CSS properties affect the layout and rendering of the embedded content. The concept of "replaced elements" is a CSS concept.
* **JavaScript:**  While not directly interacting with JavaScript code *here*, the functionality provided by this class is crucial for the behavior of embedded content that JavaScript might manipulate. For example, JavaScript might change the `src` of an iframe, triggering layout and rendering updates handled by this class. JavaScript in the *child* frame would also rely on the hit-testing logic to receive events.

**5. Logical Reasoning and Hypothetical Inputs/Outputs:**

For methods like `EmbeddedContentTransform` and `NodeAtPoint`, I consider the flow of logic and what different inputs would lead to.

* **`EmbeddedContentTransform`:**  If `FrozenFrameSize` is set, the transformation scales the embedded content to fit. Otherwise, it just translates it.
    * *Input (Frozen Size):*  `<fencedframe width="200" height="100">` with content that's naturally 400x200.
    * *Output:* An `AffineTransform` that scales the content by 0.5 in both directions.
    * *Input (No Frozen Size):* A regular `<iframe>`.
    * *Output:* An `AffineTransform` that only translates.
* **`NodeAtPoint`:** This is more complex, involving conditional logic based on whether the point is over the resizer, if the child frame is throttled, etc. I'd think about scenarios like clicking inside an iframe, clicking on its border, or clicking when the iframe is off-screen.

**6. Identifying Potential Errors:**

Based on the code and my understanding of web development, I consider common mistakes:

* **Incorrect Sizing:**  Forgetting to set `width` and `height` on embedded elements can lead to unexpected layout.
* **Z-Index Issues:** If the embedded content needs to appear above other content, incorrect `z-index` values can cause problems. While this class doesn't directly handle `z-index`, it's related to how embedded content is visually layered.
* **Event Handling in Iframes:** Developers often misunderstand how events propagate between parent and child frames. The hit-testing logic in this class is essential for correct event delivery.
* **Throttling Behavior:** Developers might not be aware that off-screen iframes are throttled, leading to unexpected behavior or delays.

**7. Structuring the Output:**

Finally, I organize the information into the requested categories: functionality, relationship with web technologies (with examples), logical reasoning (with hypothetical inputs/outputs), and common errors. I use clear and concise language, avoiding overly technical jargon where possible. The goal is to make the explanation understandable to someone with a good understanding of web development concepts.
好的，让我们来分析一下 `blink/renderer/core/layout/layout_embedded_content.cc` 这个文件的功能。

**文件功能概述:**

`LayoutEmbeddedContent.cc` 文件定义了 `LayoutEmbeddedContent` 类，这个类在 Chromium Blink 渲染引擎中负责**布局和渲染嵌入式内容**，例如 `<iframe>`, `<frame>`, `<object>`, `<embed>` 和 `<fencedframe>` 等 HTML 元素。它继承自 `LayoutReplaced`，表明它处理的是“被替换元素”。

**具体功能点:**

1. **表示嵌入式内容的布局对象:** `LayoutEmbeddedContent` 类是布局树中的一个节点，代表了页面中的一个嵌入式内容区域。

2. **管理子 FrameView 和 LayoutView:**
   - 提供方法 `ChildFrameView()` 和 `ChildLayoutView()` 来获取嵌入式内容关联的 `FrameView` (负责滚动和视口) 和 `LayoutView` (负责嵌入式内容的布局)。
   - 这使得主文档可以访问和管理嵌入式文档的布局信息。

3. **处理插件 (Plugins):**
   - 提供方法 `Plugin()` 来获取嵌入式内容中的插件对象 (`WebPluginContainerImpl`)，如果嵌入的是一个插件。

4. **访问 EmbeddedContentView:**
   - 提供方法 `GetEmbeddedContentView()` 来获取 `EmbeddedContentView` 对象，该对象是 `LayoutEmbeddedContent` 和实际嵌入的内容之间的桥梁。

5. **处理冻结帧大小 (Frozen Frame Size):**
   - 对于 `<fencedframe>` 元素，可以获取其冻结的帧大小 (`FrozenFrameSize()`)。这在某些场景下，例如导航后保持帧的大小不变很有用。

6. **坐标转换:**
   - 提供了一系列方法用于在父文档的坐标系和嵌入式内容的坐标系之间进行转换：
     - `EmbeddedContentTransform()`: 获取从嵌入式内容坐标系到父文档内容盒的仿射变换矩阵。
     - `EmbeddedContentFromBorderBox()`: 将父文档边框盒内的偏移量/点转换为嵌入式内容坐标系中的偏移量/点。
     - `BorderBoxFromEmbeddedContent()`: 将嵌入式内容坐标系中的偏移量/点转换为父文档边框盒内的偏移量/点。

7. **确定是否需要渲染层:**
   - `LayerTypeRequired()`:  确定是否需要为嵌入式内容创建独立的渲染层。通常，嵌入式内容会强制创建一个渲染层。

8. **处理调整大小的控制点:**
   - `PointOverResizer()`: 检查给定的点是否在嵌入式内容的可调整大小的控制点上。

9. **传播缩放因子:**
   - `PropagateZoomFactor()`: 将父文档的缩放因子传递给嵌入式内容。

10. **命中测试 (Hit Testing):**
    - `NodeAtPointOverEmbeddedContentView()`: 确定一个点是否在嵌入式内容的自身内容区域之上，而不是边框或内边距区域。
    - `NodeAtPoint()`:  负责更复杂的命中测试逻辑。它会考虑子框架的内容，并能判断一个点击事件是否发生在嵌入式内容内部。它会检查是否需要跳过子框架的命中测试（例如，目标节点是当前 `LayoutEmbeddedContent` 或者不允许测试子框架内容）。

11. **处理样式改变:**
    - `StyleDidChange()`: 当与嵌入式内容关联的元素的样式发生改变时被调用。它会更新嵌入式内容的状态，例如显示/隐藏，以及传播缩放因子。它还会处理 `inert` 属性的更新，以及颜色模式的改变。

12. **绘制嵌入式内容:**
    - `PaintReplaced()`: 负责绘制嵌入式内容。它会调用 `EmbeddedContentPainter` 来执行实际的绘制操作。

13. **获取光标:**
    - `GetCursor()`: 确定当鼠标悬停在嵌入式内容上时应显示的光标。如果嵌入的是插件，则插件负责设置光标。

14. **计算替换内容的矩形区域:**
    - `ReplacedContentRectFrom()`: 计算嵌入式内容在父文档中的矩形区域。这会考虑冻结帧大小和根滚动容器的情况。

15. **响应 EmbeddedContentView 的改变:**
    - `UpdateOnEmbeddedContentViewChange()`: 当 `EmbeddedContentView` 发生变化时被调用。它会更新布局和触发重绘。

16. **更新几何信息:**
    - `UpdateGeometry()`:  更新 `EmbeddedContentView` 的几何信息，例如在父文档中的位置和大小。这通常在布局发生变化后调用。

17. **判断是否是节流的 FrameView:**
    - `IsThrottledFrameView()`:  判断嵌入式内容的 `FrameView` 是否由于性能原因而被节流。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **HTML:** `LayoutEmbeddedContent` 直接对应于 HTML 中的嵌入式内容元素，如 `<iframe>`, `<object>`, `<embed>`, `<frame>`, `<fencedframe>`。
    * **例子:** 当浏览器解析到 `<iframe src="child.html"></iframe>` 时，会创建一个 `LayoutEmbeddedContent` 对象来负责这个 iframe 的布局。

* **CSS:** CSS 样式会影响 `LayoutEmbeddedContent` 的布局和渲染。
    * **例子:**
        - `width` 和 `height` CSS 属性决定了 `LayoutEmbeddedContent` 的尺寸。
        - `visibility: hidden` 会导致 `StyleDidChange()` 调用 `embedded_content_view->Hide()`。
        - `transform` CSS 属性可能会影响 `EmbeddedContentTransform()` 返回的变换矩阵。
        - 缩放（例如 `zoom: 2` 或 `transform: scale(2)`) 会触发 `PropagateZoomFactor()`，将缩放信息传递给子框架。
        - 颜色模式 CSS 属性 (`prefers-color-scheme`) 的改变会触发 `StyleDidChange()`，并可能更新子框架的颜色模式。

* **JavaScript:** JavaScript 可以操作与 `LayoutEmbeddedContent` 相关的 HTML 元素，从而间接地影响其行为。
    * **例子:**
        - JavaScript 可以动态地修改 `<iframe>` 的 `src` 属性，这会导致嵌入式内容的变化，`LayoutEmbeddedContent` 会负责新的内容的布局。
        - JavaScript 可以调用 `element.getBoundingClientRect()` 来获取嵌入式内容的位置和大小，这些信息与 `LayoutEmbeddedContent` 计算出的几何信息相关。
        - JavaScript 中监听的鼠标事件（如 `click`）的触发，依赖于 `LayoutEmbeddedContent` 的命中测试逻辑。

**逻辑推理及假设输入与输出:**

**假设输入:** 用户点击了浏览器窗口中的某个位置。

**涉及的 `LayoutEmbeddedContent` 方法和逻辑:**

1. **命中测试起点:**  渲染引擎会启动命中测试流程。
2. **`LayoutEmbeddedContent::NodeAtPoint()`:**  如果点击位置可能位于一个嵌入式内容区域内，会调用这个方法。
3. **判断是否需要进入子框架:** `NodeAtPoint()` 会检查命中测试请求是否允许进入子框架 (`result.GetHitTestRequest().AllowsChildFrameContent()`)，以及点击位置是否在调整大小的控制点上 (`PointOverResizer()`)。
4. **子框架命中测试:** 如果需要进入子框架，并且子框架的 `LocalFrameView` 存在且未被节流，则会计算相对于子框架的坐标 (`new_hit_test_location`)，并调用子框架的布局视图的命中测试方法 (`child_layout_view->HitTestNoLifecycleUpdate()`)。
5. **结果处理:**  `NodeAtPoint()` 会根据子框架的命中测试结果更新 `HitTestResult` 对象。如果点击发生在子框架内，`result` 将包含子框架中的节点信息。
6. **输出:** `HitTestResult` 对象最终会指示点击事件发生在哪个 HTML 元素上（可能在父文档或子框架中）。

**假设输入:** 一个包含 `<iframe>` 的页面加载完成，并且父窗口的缩放级别被设置为 125%。

**涉及的 `LayoutEmbeddedContent` 方法和逻辑:**

1. **页面加载和布局:**  浏览器会创建 `LayoutEmbeddedContent` 对象来表示 `<iframe>`。
2. **样式计算:**  浏览器会计算父文档和子文档的样式。
3. **`LayoutEmbeddedContent::StyleDidChange()`:**  父文档的缩放级别变化可能会导致父文档的样式变化，从而调用 `LayoutEmbeddedContent` 的 `StyleDidChange()` 方法。
4. **`LayoutEmbeddedContent::PropagateZoomFactor()`:**  `StyleDidChange()` 方法会调用 `PropagateZoomFactor(new_style.EffectiveZoom())`，将新的缩放因子（1.25）传递给子框架。
5. **子框架缩放更新:** 子框架的 `EmbeddedContentView` 会接收到缩放因子改变的通知，并进行相应的调整，例如更新其内部布局和渲染。

**用户或编程常见的使用错误举例:**

1. **未设置嵌入式内容的尺寸:**
   - **错误:** 在 HTML 中使用了 `<iframe>` 但没有设置 `width` 和 `height` 属性，也没有通过 CSS 设置尺寸。
   - **后果:**  `LayoutEmbeddedContent` 可能会使用默认的尺寸，或者根本无法正确计算其大小，导致页面布局混乱。

2. **错误的坐标转换:**
   - **错误:**  开发者试图手动计算父窗口和子框架之间的坐标关系，而没有使用 `LayoutEmbeddedContent` 提供的坐标转换方法。
   - **后果:**  可能导致鼠标事件定位错误，例如点击子框架中的某个元素，但事件却被父窗口的另一个元素接收到。

3. **Z-index 问题导致的遮挡:**
   - **错误:**  假设一个 `<iframe>` 需要显示在其他元素之上，但 CSS 的 `z-index` 设置不正确。
   - **后果:**  `<iframe>` 可能被其他元素遮挡，即使其内容应该可见。虽然 `LayoutEmbeddedContent` 不直接处理 `z-index`，但它是影响渲染结果的关键部分。

4. **忽略跨域安全限制:**
   - **错误:**  尝试通过 JavaScript 访问不同源的 `<iframe>` 的内容，而没有正确的跨域配置（CORS）。
   - **后果:**  浏览器会阻止这种访问，导致 JavaScript 错误。这虽然不是 `LayoutEmbeddedContent` 本身的问题，但嵌入式内容经常涉及到跨域问题。

5. **假设子框架总是加载完成:**
   - **错误:**  在父窗口的 JavaScript 中，直接操作子框架的 DOM，而没有确保子框架已经完全加载。
   - **后果:**  可能导致 JavaScript 错误，因为子框架的 DOM 结构可能尚未构建完成。 `LayoutEmbeddedContent` 负责布局，但内容的加载是另一个过程。

希望以上分析能够帮助你理解 `blink/renderer/core/layout/layout_embedded_content.cc` 文件的功能和作用。

### 提示词
```
这是目录为blink/renderer/core/layout/layout_embedded_content.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 2000 Simon Hausmann <hausmann@kde.org>
 *           (C) 2000 Stefan Schimanski (1Stein@gmx.de)
 * Copyright (C) 2004, 2005, 2006, 2009 Apple Inc. All rights reserved.
 * Copyright (C) Research In Motion Limited 2011. All rights reserved.
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

#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"

#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/exported/web_plugin_container_impl.h"
#include "third_party/blink/renderer/core/frame/embedded_content_view.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/remote_frame.h"
#include "third_party/blink/renderer/core/frame/remote_frame_view.h"
#include "third_party/blink/renderer/core/html/fenced_frame/html_fenced_frame_element.h"
#include "third_party/blink/renderer/core/html/html_frame_element_base.h"
#include "third_party/blink/renderer/core/html/html_plugin_element.h"
#include "third_party/blink/renderer/core/layout/geometry/physical_offset.h"
#include "third_party/blink/renderer/core/layout/hit_test_location.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_replaced.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/paint/embedded_content_painter.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/platform/transforms/affine_transform.h"
#include "ui/gfx/geometry/point_conversions.h"
#include "ui/gfx/geometry/point_f.h"

namespace blink {

LayoutEmbeddedContent::LayoutEmbeddedContent(HTMLFrameOwnerElement* element)
    : LayoutReplaced(element) {
  DCHECK(element);
  SetInline(false);
}

void LayoutEmbeddedContent::WillBeDestroyed() {
  NOT_DESTROYED();
  if (auto* frame_owner = GetFrameOwnerElement())
    frame_owner->SetEmbeddedContentView(nullptr);

  LayoutReplaced::WillBeDestroyed();

  ClearNode();
}

FrameView* LayoutEmbeddedContent::ChildFrameView() const {
  NOT_DESTROYED();
  return DynamicTo<FrameView>(GetEmbeddedContentView());
}

LayoutView* LayoutEmbeddedContent::ChildLayoutView() const {
  NOT_DESTROYED();
  if (HTMLFrameOwnerElement* owner_element = GetFrameOwnerElement()) {
    if (Document* content_document = owner_element->contentDocument())
      return content_document->GetLayoutView();
  }
  return nullptr;
}

WebPluginContainerImpl* LayoutEmbeddedContent::Plugin() const {
  NOT_DESTROYED();
  EmbeddedContentView* embedded_content_view = GetEmbeddedContentView();
  if (embedded_content_view && embedded_content_view->IsPluginView())
    return To<WebPluginContainerImpl>(embedded_content_view);
  return nullptr;
}

EmbeddedContentView* LayoutEmbeddedContent::GetEmbeddedContentView() const {
  NOT_DESTROYED();
  if (auto* frame_owner = GetFrameOwnerElement())
    return frame_owner->OwnedEmbeddedContentView();
  return nullptr;
}

const std::optional<PhysicalSize> LayoutEmbeddedContent::FrozenFrameSize()
    const {
  // The `<fencedframe>` element can freeze the child frame size when navigated.
  if (const auto* fenced_frame = DynamicTo<HTMLFencedFrameElement>(GetNode()))
    return fenced_frame->FrozenFrameSize();

  return std::nullopt;
}

AffineTransform LayoutEmbeddedContent::EmbeddedContentTransform() const {
  auto frozen_size = FrozenFrameSize();
  if (!frozen_size || frozen_size->IsEmpty()) {
    const PhysicalOffset content_box_offset = PhysicalContentBoxOffset();
    return AffineTransform().Translate(content_box_offset.left,
                                       content_box_offset.top);
  }

  AffineTransform translate_and_scale;
  auto replaced_rect = ReplacedContentRect();
  translate_and_scale.Translate(replaced_rect.X(), replaced_rect.Y());
  translate_and_scale.Scale(replaced_rect.Width() / frozen_size->width,
                            replaced_rect.Height() / frozen_size->height);
  return translate_and_scale;
}

PhysicalOffset LayoutEmbeddedContent::EmbeddedContentFromBorderBox(
    const PhysicalOffset& offset) const {
  gfx::PointF point(offset);
  return PhysicalOffset::FromPointFRound(
      EmbeddedContentTransform().Inverse().MapPoint(point));
}

gfx::PointF LayoutEmbeddedContent::EmbeddedContentFromBorderBox(
    const gfx::PointF& point) const {
  return EmbeddedContentTransform().Inverse().MapPoint(point);
}

PhysicalOffset LayoutEmbeddedContent::BorderBoxFromEmbeddedContent(
    const PhysicalOffset& offset) const {
  gfx::PointF point(offset);
  return PhysicalOffset::FromPointFRound(
      EmbeddedContentTransform().MapPoint(point));
}

gfx::Rect LayoutEmbeddedContent::BorderBoxFromEmbeddedContent(
    const gfx::Rect& rect) const {
  return EmbeddedContentTransform().MapRect(rect);
}

PaintLayerType LayoutEmbeddedContent::LayerTypeRequired() const {
  NOT_DESTROYED();
  PaintLayerType type = LayoutReplaced::LayerTypeRequired();
  if (type != kNoPaintLayer)
    return type;
  return kForcedPaintLayer;
}

bool LayoutEmbeddedContent::PointOverResizer(
    const HitTestResult& result,
    const HitTestLocation& location,
    const PhysicalOffset& accumulated_offset) const {
  NOT_DESTROYED();
  if (const auto* scrollable_area = GetScrollableArea()) {
    const HitTestRequest::HitTestRequestType hit_type =
        result.GetHitTestRequest().GetType();
    const blink::ResizerHitTestType resizer_type =
        hit_type & HitTestRequest::kTouchEvent ? kResizerForTouch
                                               : kResizerForPointer;
    return scrollable_area->IsAbsolutePointInResizeControl(
        ToRoundedPoint(location.Point() - accumulated_offset), resizer_type);
  }
  return false;
}

void LayoutEmbeddedContent::PropagateZoomFactor(double zoom_factor) {
  if (GetDocument().StandardizedBrowserZoomEnabled()) {
    const auto* fenced_frame = DynamicTo<HTMLFencedFrameElement>(GetNode());
    if (!fenced_frame) {
      if (auto* embedded_content_view = GetEmbeddedContentView()) {
        embedded_content_view->ZoomFactorChanged(zoom_factor);
      }
    }
  }
}

bool LayoutEmbeddedContent::NodeAtPointOverEmbeddedContentView(
    HitTestResult& result,
    const HitTestLocation& hit_test_location,
    const PhysicalOffset& accumulated_offset,
    HitTestPhase phase) {
  NOT_DESTROYED();
  bool had_result = result.InnerNode();
  bool inside = LayoutReplaced::NodeAtPoint(result, hit_test_location,
                                            accumulated_offset, phase);

  // Check to see if we are really over the EmbeddedContentView itself (and not
  // just in the border/padding area or the resizer area).
  if ((inside || hit_test_location.IsRectBasedTest()) && !had_result &&
      result.InnerNode() == GetNode()) {
    bool is_over_content_view =
        PhysicalContentBoxRect().Contains(result.LocalPoint()) &&
        !result.IsOverResizer();
    result.SetIsOverEmbeddedContentView(is_over_content_view);
  }
  return inside;
}

bool LayoutEmbeddedContent::NodeAtPoint(
    HitTestResult& result,
    const HitTestLocation& hit_test_location,
    const PhysicalOffset& accumulated_offset,
    HitTestPhase phase) {
  NOT_DESTROYED();
  auto* local_frame_view = DynamicTo<LocalFrameView>(ChildFrameView());
  bool skip_contents =
      (result.GetHitTestRequest().GetStopNode() == this ||
       !result.GetHitTestRequest().AllowsChildFrameContent() ||
       PointOverResizer(result, hit_test_location, accumulated_offset));

  if (!local_frame_view || skip_contents) {
    return NodeAtPointOverEmbeddedContentView(result, hit_test_location,
                                              accumulated_offset, phase);
  }

  // A hit test can never hit an off-screen element; only off-screen iframes are
  // throttled; therefore, hit tests can skip descending into throttled iframes.
  // We also check the document lifecycle state because the frame may have been
  // throttled at the time lifecycle updates happened, in which case it will not
  // be up-to-date and we can't hit test it.
  if (local_frame_view->ShouldThrottleRendering() ||
      !local_frame_view->GetFrame().GetDocument() ||
      local_frame_view->GetFrame().GetDocument()->Lifecycle().GetState() <
          DocumentLifecycle::kPrePaintClean) {
    return NodeAtPointOverEmbeddedContentView(result, hit_test_location,
                                              accumulated_offset, phase);
  }

  DCHECK_GE(GetDocument().Lifecycle().GetState(),
            DocumentLifecycle::kPrePaintClean);

  if (phase == HitTestPhase::kForeground) {
    auto* child_layout_view = local_frame_view->GetLayoutView();

    if (VisibleToHitTestRequest(result.GetHitTestRequest()) &&
        child_layout_view) {
      PhysicalOffset content_offset(BorderLeft() + PaddingLeft(),
                                    BorderTop() + PaddingTop());
      HitTestLocation new_hit_test_location(
          hit_test_location, -accumulated_offset - content_offset);
      HitTestRequest new_hit_test_request(
          result.GetHitTestRequest().GetType() |
              HitTestRequest::kChildFrameHitTest,
          result.GetHitTestRequest().GetStopNode());
      HitTestResult child_frame_result(new_hit_test_request,
                                       new_hit_test_location);

      // The frame's layout and style must be up to date if we reach here.
      bool is_inside_child_frame = child_layout_view->HitTestNoLifecycleUpdate(
          new_hit_test_location, child_frame_result);

      if (result.GetHitTestRequest().ListBased()) {
        result.Append(child_frame_result);
      } else if (is_inside_child_frame) {
        // Force the result not to be cacheable because the parent frame should
        // not cache this result; as it won't be notified of changes in the
        // child.
        child_frame_result.SetCacheable(false);
        result = child_frame_result;
      }

      // Don't trust |isInsideChildFrame|. For rect-based hit-test, returns
      // true only when the hit test rect is totally within the iframe,
      // i.e. nodeAtPointOverEmbeddedContentView() also returns true.
      // Use a temporary HitTestResult because we don't want to collect the
      // iframe element itself if the hit-test rect is totally within the
      // iframe.
      if (is_inside_child_frame) {
        if (!hit_test_location.IsRectBasedTest())
          return true;
        HitTestResult point_over_embedded_content_view_result = result;
        bool point_over_embedded_content_view =
            NodeAtPointOverEmbeddedContentView(
                point_over_embedded_content_view_result, hit_test_location,
                accumulated_offset, phase);
        if (point_over_embedded_content_view)
          return true;
        result = point_over_embedded_content_view_result;
        return false;
      }
    }
  }

  return NodeAtPointOverEmbeddedContentView(result, hit_test_location,
                                            accumulated_offset, phase);
}

void LayoutEmbeddedContent::StyleDidChange(StyleDifference diff,
                                           const ComputedStyle* old_style) {
  NOT_DESTROYED();
  LayoutReplaced::StyleDidChange(diff, old_style);
  const ComputedStyle& new_style = StyleRef();

  if (Frame* frame = GetFrameOwnerElement()->ContentFrame())
    frame->UpdateInertIfPossible();

  if (EmbeddedContentView* embedded_content_view = GetEmbeddedContentView()) {
    if (new_style.Visibility() != EVisibility::kVisible) {
      embedded_content_view->Hide();
    } else {
      embedded_content_view->Show();
    }
  }

  auto* frame_owner = GetFrameOwnerElement();
  if (!frame_owner)
    return;

  if (old_style &&
      new_style.UsedColorScheme() != old_style->UsedColorScheme()) {
    frame_owner->SetColorScheme(new_style.UsedColorScheme());
  }
  if (!old_style || new_style.EffectiveZoom() != old_style->EffectiveZoom()) {
    PropagateZoomFactor(new_style.EffectiveZoom());
  }

  if (old_style &&
      new_style.VisibleToHitTesting() == old_style->VisibleToHitTesting()) {
    return;
  }

  if (auto* frame = frame_owner->ContentFrame())
    frame->UpdateVisibleToHitTesting();
}

void LayoutEmbeddedContent::PaintReplaced(
    const PaintInfo& paint_info,
    const PhysicalOffset& paint_offset) const {
  NOT_DESTROYED();
  if (ChildPaintBlockedByDisplayLock())
    return;
  EmbeddedContentPainter(*this).PaintReplaced(paint_info, paint_offset);
}

CursorDirective LayoutEmbeddedContent::GetCursor(const PhysicalOffset& point,
                                                 ui::Cursor& cursor) const {
  NOT_DESTROYED();
  if (Plugin()) {
    // A plugin is responsible for setting the cursor when the pointer is over
    // it.
    return kDoNotSetCursor;
  }
  return LayoutReplaced::GetCursor(point, cursor);
}

PhysicalRect LayoutEmbeddedContent::ReplacedContentRectFrom(
    const PhysicalRect& base_content_rect) const {
  NOT_DESTROYED();
  PhysicalRect content_rect = base_content_rect;

  // IFrames set as the root scroller should get their size from their parent.
  // When scrolling starts so as to hide the URL bar, IFRAME wouldn't resize to
  // match the now expanded size of the viewport until the scrolling stops. This
  // makes sure the |ReplacedContentRect| matches the expanded viewport even
  // before IFRAME resizes, for clipping to work correctly.
  if (ChildFrameView() && View() && IsEffectiveRootScroller()) {
    content_rect.offset = PhysicalOffset();
    content_rect.size = View()->ViewRect().size;
  }

  if (const std::optional<PhysicalSize> frozen_size = FrozenFrameSize()) {
    // TODO(kojii): Setting the `offset` to non-zero values breaks
    // hit-testing/inputs. Even different size is suspicious, as the input
    // system forwards mouse events to the child frame even when the mouse is
    // outside of the child frame. Revisit this when the input system supports
    // different |ReplacedContentRect| from |PhysicalContentBoxRect|.
    PhysicalSize frozen_layout_size = *frozen_size;
    content_rect =
        ComputeReplacedContentRect(base_content_rect, &frozen_layout_size);
  }

  // We don't propagate sub-pixel into sub-frame layout, in other words, the
  // rect is snapped at the document boundary, and sub-pixel movement could
  // cause the sub-frame to layout due to the 1px snap difference. In order to
  // avoid that, the size of sub-frame is rounded in advance.
  return PreSnappedRectForPersistentSizing(content_rect);
}

void LayoutEmbeddedContent::UpdateOnEmbeddedContentViewChange() {
  NOT_DESTROYED();
  if (!Style())
    return;

  if (EmbeddedContentView* embedded_content_view = GetEmbeddedContentView()) {
    if (!NeedsLayout()) {
      UpdateGeometry(*embedded_content_view);
    }
    if (Style()) {
      PropagateZoomFactor(StyleRef().EffectiveZoom());
      if (StyleRef().Visibility() != EVisibility::kVisible) {
        embedded_content_view->Hide();
      } else {
        embedded_content_view->Show();
      }
    }
  }

  // One of the reasons of the following is that the layout tree in the new
  // embedded content view may have already had some paint property and paint
  // invalidation flags set, and we need to propagate the flags into the host
  // view. Adding, changing and removing are also significant changes to the
  // tree so setting the flags ensures the required updates.
  SetNeedsPaintPropertyUpdate();
  SetShouldDoFullPaintInvalidation();
}

void LayoutEmbeddedContent::UpdateGeometry(
    EmbeddedContentView& embedded_content_view) {
  NOT_DESTROYED();
  // TODO(wangxianzhu): We reset subpixel accumulation at some boundaries, so
  // the following code is incorrect when some ancestors are such boundaries.
  // What about multicol? Need a LayoutBox function to query sub-pixel
  // accumulation.
  PhysicalRect replaced_rect = ReplacedContentRect();
  TransformState transform_state(TransformState::kApplyTransformDirection,
                                 gfx::PointF(),
                                 gfx::QuadF(gfx::RectF(replaced_rect)));
  MapLocalToAncestor(nullptr, transform_state, 0);
  transform_state.Flatten();
  PhysicalOffset absolute_location =
      PhysicalOffset::FromPointFRound(transform_state.LastPlanarPoint());
  PhysicalRect absolute_replaced_rect = replaced_rect;
  absolute_replaced_rect.Move(absolute_location);
  gfx::RectF absolute_bounding_box =
      transform_state.LastPlanarQuad().BoundingBox();
  gfx::Rect frame_rect(gfx::Point(),
                       ToPixelSnappedRect(absolute_replaced_rect).size());
  // Normally the location of the frame rect is ignored by the painter, but
  // currently it is still used by a family of coordinate conversion function in
  // LocalFrameView. This is incorrect because coordinate conversion
  // needs to take transform and into account. A few callers still use the
  // family of conversion function, including but not exhaustive:
  // LocalFrameView::updateViewportIntersectionIfNeeded()
  // RemoteFrameView::frameRectsChanged().
  // WebPluginContainerImpl::reportGeometry()
  // TODO(trchen): Remove this hack once we fixed all callers.
  frame_rect.set_origin(gfx::ToRoundedPoint(absolute_bounding_box.origin()));

  // As an optimization, we don't include the root layer's scroll offset in the
  // frame rect.  As a result, we don't need to recalculate the frame rect every
  // time the root layer scrolls; however, each implementation of
  // EmbeddedContentView::FrameRect() must add the root layer's scroll offset
  // into its position.
  // TODO(szager): Refactor this functionality into EmbeddedContentView, rather
  // than reimplementing in each concrete subclass.
  LayoutView* layout_view = View();
  if (layout_view && layout_view->IsScrollContainer()) {
    // Floored because the PixelSnappedScrollOffset returns a ScrollOffset
    // which is a float-type but frame_rect in a content view is an gfx::Rect.
    // We may want to reevaluate the use of pixel snapping that since scroll
    // offsets/layout can be fractional.
    frame_rect.Offset(layout_view->PixelSnappedScrolledContentOffset());
  }

  embedded_content_view.SetFrameRect(frame_rect);
}

bool LayoutEmbeddedContent::IsThrottledFrameView() const {
  NOT_DESTROYED();
  if (auto* local_frame_view = DynamicTo<LocalFrameView>(ChildFrameView()))
    return local_frame_view->ShouldThrottleRendering();
  return false;
}

}  // namespace blink
```