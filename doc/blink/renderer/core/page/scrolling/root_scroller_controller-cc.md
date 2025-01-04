Response:
Let's break down the thought process for analyzing the `RootScrollerController.cc` file.

**1. Initial Read and Keyword Identification:**

The first step is a quick skim of the code, looking for recurring keywords and patterns. Terms like `scroller`, `root`, `viewport`, `frame`, `document`, `element`, `layout`, `implicit`, `fullscreen`, `resize`, `scroll`, and `properties` immediately jump out. The inclusion of headers like `LocalFrameView`, `VisualViewport`, `DocumentFullscreen`, and `ScrollableArea` further reinforces the theme of scrolling management.

**2. Core Function Identification (What's the Main Job?):**

Based on the keywords, the file clearly deals with managing the "root scroller" of a document. The class name itself is a dead giveaway. The key question then becomes: What *is* the root scroller, and why does it need a controller?

**3. Deconstructing the Key Methods:**

The next step is to examine the major methods within the class. Each method likely handles a specific aspect of root scroller management:

*   `RecomputeEffectiveRootScroller()`:  This is crucial. The name suggests the controller dynamically determines *which* element should be the root scroller. The logic within this function needs close examination.
*   `IsValidRootScroller()` and `IsValidImplicit()`: These functions likely define the criteria for an element to be considered a valid root scroller, both explicitly and implicitly.
*   `ApplyRootScrollerProperties()`: This indicates that once a root scroller is selected, certain properties are applied to it. What properties? Look for the logic within the method.
*   `DidResizeFrameView()`: This suggests handling events related to resizing the frame/viewport. How does this impact the root scroller?
*   `ImplicitRootScrollerFromCandidates()`: This points to a mechanism for automatically selecting a root scroller based on certain criteria, without explicit declaration.

**4. Identifying Relationships with Web Technologies:**

Now, connect the identified functionalities to HTML, CSS, and JavaScript:

*   **HTML:**  The root scroller is ultimately an HTML element. Iframes (`HTMLFrameOwnerElement`) are explicitly mentioned, indicating they can be root scrollers. The `<body>` element is the default root scroller.
*   **CSS:**  CSS properties like `overflow`, `opacity`, `visibility`, and clipping properties (`overflow`, `mask`, `clip`, `clip-path`) are used in the `IsValidImplicit()` logic. This shows CSS directly influences implicit root scroller selection. The concept of the viewport, controlled by CSS and browser behavior, is central.
*   **JavaScript:** While this file is C++, the functionality it provides is exposed to JavaScript. JavaScript can trigger resizes, change CSS properties that affect scrolling, and interact with the viewport. Features like `document.fullscreenElement` are directly referenced.

**5. Tracing User Interaction and Debugging:**

Consider how a user's actions might lead to this code being executed:

*   **Basic Scrolling:**  The most obvious scenario.
*   **Resizing the Browser Window:** Triggers `DidResizeFrameView()`.
*   **Entering/Exiting Fullscreen:**  Impacts `RecomputeEffectiveRootScroller()`.
*   **Using iframes:**  Brings the iframe-related logic into play.
*   **CSS Changes:** Dynamically altering CSS properties (especially `overflow`) can trigger root scroller re-evaluation.
*   **JavaScript Scrolling or Resizing:** JavaScript code that manipulates the scroll position or window size can also lead to this code being run.

For debugging, the key is to track how the "effective root scroller" changes and the reasons behind those changes. Logging the output of `RecomputeEffectiveRootScroller()` and the results of `IsValidRootScroller()` and `IsValidImplicit()` would be crucial.

**6. Logical Inference and Assumptions:**

When the code makes decisions (e.g., selecting an implicit root scroller), it relies on certain assumptions. These assumptions need to be explicitly stated. For example, the logic for implicit root scrollers assumes that if a single element fills the viewport and scrolls, it's a good candidate. Consider edge cases where this might not be true.

**7. Common User/Programming Errors:**

Think about how developers might misuse or misunderstand the concept of the root scroller:

*   **Assuming the `<body>` is always the root scroller:** Implicit root scrollers challenge this assumption.
*   **Not understanding the implications of `overflow: hidden` on parent elements:** This can prevent implicit root scroller promotion.
*   **Conflicting scrolling behaviors:** If multiple elements within the viewport have scrollbars, the behavior might be unexpected.

**8. Structuring the Output:**

Organize the information logically, starting with a high-level overview of the file's purpose, then drilling down into specific functionalities, relationships with web technologies, debugging scenarios, and potential errors. Use clear headings and examples.

**Self-Correction/Refinement during the process:**

*   **Initial thought:** "This file just handles scrolling."
*   **Correction:** "No, it handles *which element* is responsible for the main document scrolling, which is more nuanced."
*   **Initial thought:**  Focus only on explicit root scroller selection.
*   **Correction:**  Recognize the importance of *implicit* root scroller selection and its interaction with CSS.
*   **Initial thought:**  Only consider user-initiated actions.
*   **Correction:** Include programmatic actions (JavaScript) as well.

By following these steps, we can systematically analyze the provided code and extract meaningful information about its functionality and its relationship to the broader web development ecosystem.
好的，让我们来详细分析一下 `blink/renderer/core/page/scrolling/root_scroller_controller.cc` 文件的功能。

**主要功能：管理文档的根滚动器 (Root Scroller)**

这个文件的核心职责是管理和确定当前文档的“根滚动器”。  根滚动器是指负责整个文档视口滚动的元素。传统上，根滚动器是 `<html>` 元素或 `<body>` 元素。但是，现代 Web 开发中，尤其是在使用 CSS `position: fixed` 或其他布局技术时，可能需要将其他元素指定为根滚动器。

`RootScrollerController` 负责以下关键任务：

1. **确定有效的根滚动器：**  根据一系列规则和条件，判断当前哪个元素应该作为文档的根滚动器。这包括：
    *   检查是否有全屏元素 (`DocumentFullscreen::fullscreenElement`)，全屏元素通常是根滚动器。
    *   查找“隐式根滚动器”（Implicit Root Scroller）。
    *   默认情况下，文档本身（`document_`）作为根滚动器。

2. **应用根滚动器属性：**  一旦确定了根滚动器，就需要将相应的滚动属性应用到该元素。这通常涉及到设置元素的布局和渲染方式，以便正确处理滚动行为。对于 `<iframe>` 元素作为根滚动器的情况，还需要更新其几何信息和布局大小。

3. **响应视口大小变化：**  当浏览器窗口或视口大小发生变化时，`RootScrollerController` 需要做出相应的调整，确保根滚动器能够正确地处理新的视口尺寸。

4. **处理 `<iframe>` 元素的根滚动：**  当一个 `<iframe>` 元素填满其父文档的视口时，它可以成为其内部文档的根滚动器。`RootScrollerController` 负责检测和管理这种情况。

5. **支持隐式根滚动器：**  这是该文件的一个重要特性。它允许在满足特定条件时，将文档中的某个元素自动提升为根滚动器。这为开发者提供了更大的灵活性，可以创建具有自定义滚动体验的布局。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`RootScrollerController` 的功能与 JavaScript, HTML, CSS 紧密相关，因为它直接影响着网页的滚动行为和布局：

*   **HTML:**
    *   **元素作为滚动容器：**  HTML 元素（如 `<div>`）通过 CSS 的 `overflow` 属性可以变成滚动容器。`RootScrollerController` 会检查这些元素是否满足成为根滚动器的条件，特别是当它们填满视口时。
    *   **`<iframe>` 元素：**  `RootScrollerController` 特别处理了 `<iframe>` 元素作为根滚动器的情况。当一个 `<iframe>` 填满视口时，它的内部文档可能会使用该 `<iframe>` 作为根滚动器。
    *   **`<frameset>` (已过时，但可能仍然存在):** 虽然代码中没有直接提及，但早期的框架页面也有根滚动器的概念。

*   **CSS:**
    *   **`overflow` 属性：**  `RootScrollerController` 使用 `overflow` 属性来判断一个元素是否是滚动容器。只有 `overflow` 属性设置为 `scroll`、`auto` 或 `overlay` 的元素才可能成为隐式根滚动器。
    *   **视口单位 (vw, vh)：** 当一个元素使用视口单位来定义其尺寸，并填满视口时，它更有可能成为根滚动器的候选者。
    *   **`position: fixed`：**  拥有 `position: fixed` 的元素可能会影响根滚动器的选择，因为固定定位的元素是相对于视口定位的。
    *   **`opacity` 和 `visibility`：**  `IsValidImplicit()` 函数会检查元素的 `opacity` 和 `VisibleToHitTesting()` 属性。不透明或不可见的元素不会被提升为隐式根滚动器。
    *   **裁剪属性 (clip, mask, clip-path)：**  如果一个元素的祖先元素设置了裁剪属性，该元素可能不会被提升为隐式根滚动器，因为这可能会导致滚动行为不符合预期。

    **示例:**

    ```html
    <!DOCTYPE html>
    <html>
    <head>
    <style>
      body { margin: 0; } /* 防止默认边距 */
      #container {
        width: 100vw;
        height: 100vh;
        overflow: auto; /* 使容器可滚动 */
      }
      #content {
        height: 200vh; /* 内容超出容器高度 */
      }
    </style>
    </head>
    <body>
      <div id="container">
        <div id="content">
          一些超出容器的内容...
        </div>
      </div>
      <script>
        // JavaScript 可以监听滚动事件，但 RootScrollerController 的逻辑主要在 C++ 层
        document.getElementById('container').addEventListener('scroll', () => {
          console.log('Container scrolled');
        });
      </script>
    </body>
    </html>
    ```

    在这个例子中，如果满足特定条件，`#container` 可能会被 `RootScrollerController` 识别为隐式根滚动器，而不是默认的 `<body>` 或 `<html>`。

*   **JavaScript:**
    *   **滚动事件：**  虽然 `RootScrollerController` 本身是用 C++ 编写的，但它所管理的根滚动器会触发 JavaScript 的滚动事件。
    *   **DOM 操作：**  JavaScript 对 DOM 的修改（例如添加或删除元素，修改 CSS 样式）可能会触发 `RootScrollerController` 重新评估根滚动器。
    *   **全屏 API：**  `DocumentFullscreen::fullscreenElement` 的判断与 JavaScript 的 Fullscreen API 相关。当 JavaScript 代码请求将某个元素全屏显示时，该元素很可能会成为根滚动器。

**逻辑推理、假设输入与输出:**

**假设输入：**

1. 一个 HTML 文档加载完成。
2. 文档的 `<body>` 元素内有一个 `<div>` 元素，其 CSS 样式设置为 `width: 100vw; height: 100vh; overflow: auto;`，并且内部内容的高度超过了视口高度。
3. 文档没有全屏元素。

**逻辑推理：**

`RootScrollerController` 的 `RecomputeEffectiveRootScroller()` 方法会被调用。它会执行以下步骤：

1. 检查是否有全屏元素：没有。
2. 调用 `ImplicitRootScrollerFromCandidates()` 来查找隐式根滚动器。
3. `ImplicitRootScrollerFromCandidates()` 会遍历潜在的候选元素。
4. `IsValidImplicitCandidate()` 会检查 `<div>` 元素是否是有效的候选者（例如，是 `LayoutBox` 并且是滚动容器）。
5. `IsValidImplicit()` 会进一步检查 `<div>` 元素是否满足成为隐式根滚动器的条件：
    *   在树结构中。
    *   有布局对象。
    *   是 Box 类型。
    *   不在 FlowThread 中。
    *   其 `PaintLayerScrollableArea` 存在且可以滚动溢出。
    *   填充视口 (`FillsViewport`)。
    *   没有 `opacity` 或 `VisibleToHitTesting()` 阻止。
    *   其祖先元素没有裁剪溢出。
6. 如果 `<div>` 元素满足所有条件，它会被认为是有效的隐式根滚动器。
7. `RecomputeEffectiveRootScroller()` 会将 `effective_root_scroller_` 更新为该 `<div>` 元素。

**输出：**

文档的根滚动器被设置为该 `<div>` 元素。这意味着：

*   滚动条会出现在该 `<div>` 元素上，而不是浏览器的默认滚动条。
*   JavaScript 的滚动事件会首先在该 `<div>` 元素上触发。
*   与视口相关的计算可能会以该 `<div>` 元素的边界为基准。

**用户或编程常见的使用错误:**

1. **误以为 `<body>` 或 `<html>` 永远是根滚动器：**  在使用了 `position: fixed` 或实现了自定义滚动容器的布局中，情况并非如此。开发者需要理解隐式根滚动器的概念。

    **示例：**  开发者可能会监听 `document` 或 `body` 的滚动事件，但如果实际的根滚动器是一个内部 `<div>`，则这些事件可能不会按预期触发。

    ```javascript
    // 错误的假设：认为 body 是根滚动器
    document.body.addEventListener('scroll', () => {
      console.log('Body scrolled'); // 在隐式根滚动器场景下可能不会触发
    });

    // 正确的做法：监听实际的根滚动器
    document.getElementById('container').addEventListener('scroll', () => {
      console.log('Container scrolled');
    });
    ```

2. **CSS 冲突导致无法成为隐式根滚动器：**  开发者可能无意中设置了某些 CSS 属性，阻止元素被提升为隐式根滚动器。例如，在祖先元素上设置了 `overflow: hidden`。

    **示例：**

    ```html
    <style>
      #parent { overflow: hidden; } /* 阻止子元素成为隐式根滚动器 */
      #container { width: 100vw; height: 100vh; overflow: auto; }
    </style>
    <div id="parent">
      <div id="container">...</div>
    </div>
    ```

    在这种情况下，即使 `#container` 看起来像一个根滚动器的候选者，`#parent` 的 `overflow: hidden` 可能会阻止它成为隐式根滚动器。

3. **在 JavaScript 中错误地操作滚动位置：**  如果开发者试图直接操作 `document.documentElement.scrollTop` 或 `document.body.scrollTop`，但在一个使用了隐式根滚动器的页面上，这些操作可能不会产生预期的效果。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户打开一个网页：**  浏览器开始解析 HTML、CSS 并构建 DOM 树和渲染树。
2. **布局计算：**  Blink 引擎进行布局计算，确定元素的位置和大小。在此过程中，`RootScrollerController` 会被创建。
3. **首次根滚动器选择：**  在首次布局完成后，`RootScrollerController::PerformRootScrollerSelection()` 可能会被调用，以确定初始的根滚动器。通常，默认是文档本身。
4. **用户滚动页面：**  当用户使用鼠标滚轮、触摸板或键盘滚动页面时，浏览器会触发滚动事件。
5. **滚动处理：**  如果存在隐式根滚动器，滚动事件会首先被该元素捕获和处理。
6. **视口大小变化：**  用户调整浏览器窗口大小，或者设备方向改变，会导致视口大小变化。
7. **`DidResizeFrameView()` 调用：**  `LocalFrameView` 会通知 `RootScrollerController` 视口大小发生了变化，调用 `DidResizeFrameView()`。
8. **重新评估根滚动器：**  在视口大小变化后，或者当 DOM 结构或 CSS 样式发生变化时，`PerformRootScrollerSelection()` 可能会再次被调用，重新评估是否需要切换根滚动器。
9. **进入或退出全屏：**  用户点击全屏按钮或调用 Fullscreen API，会导致 `DocumentFullscreen::fullscreenElement` 的状态改变，从而触发 `RecomputeEffectiveRootScroller()`。
10. **`<iframe>` 加载：**  当一个 `<iframe>` 元素加载完成，并且其尺寸和布局能够填满父视口时，`RootScrollerController` 可能会将其提升为内部文档的根滚动器。

**调试线索：**

*   **查看 `effective_root_scroller_` 的值：**  在调试器中，可以查看 `RootScrollerController` 对象的 `effective_root_scroller_` 成员变量，以确定当前哪个元素被认为是根滚动器。
*   **断点在 `RecomputeEffectiveRootScroller()`：**  在该方法入口处设置断点，可以追踪根滚动器选择的逻辑。
*   **断点在 `IsValidImplicit()` 和 `IsValidRootScroller()`：**  这些方法决定了哪些元素可以成为根滚动器。通过断点可以了解为什么某个元素被选中或排除。
*   **检查相关的 CSS 属性：**  使用浏览器的开发者工具检查潜在根滚动器及其祖先元素的 CSS 属性，特别是 `overflow`、`opacity`、`visibility` 和裁剪相关的属性。
*   **监听滚动事件：**  在 JavaScript 中监听不同元素的滚动事件，以确定实际触发滚动的元素是哪个。
*   **使用 Blink 的 tracing 工具：**  Blink 引擎提供了 tracing 工具，可以记录代码执行的详细信息，包括 `RootScrollerController` 的相关操作。这对于深入理解根滚动器选择的过程非常有帮助。

希望以上详细的解释能够帮助你理解 `blink/renderer/core/page/scrolling/root_scroller_controller.cc` 文件的功能和它在 Blink 引擎中的作用。

Prompt: 
```
这是目录为blink/renderer/core/page/scrolling/root_scroller_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/page/scrolling/root_scroller_controller.h"

#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/frame/browser_controls.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/fullscreen/document_fullscreen.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/scrolling/top_document_root_scroller_controller.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/scroll/scrollable_area.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "ui/gfx/geometry/rect_conversions.h"
#include "ui/gfx/geometry/size_conversions.h"

namespace blink {

class RootFrameViewport;

namespace {

bool FillsViewport(const Element& element) {
  if (!element.GetLayoutObject())
    return false;

  auto* layout_box = To<LayoutBox>(element.GetLayoutObject());

  // TODO(bokan): Broken for OOPIF. crbug.com/642378.
  Document& top_document = element.GetDocument().TopDocument();
  if (!top_document.GetLayoutView())
    return false;

  // We need to be more strict for iframes and use the content box since the
  // iframe will use the parent's layout size. Using the padding box would mean
  // the content would relayout on promotion/demotion. The layout size matching
  // the parent is done to ensure consistent semantics with respect to how the
  // mobile URL bar affects layout, which isn't a concern for non-iframe
  // elements because those semantics will already be applied to the element.
  PhysicalRect rect = layout_box->IsLayoutIFrame()
                          ? layout_box->PhysicalContentBoxRect()
                          : layout_box->PhysicalPaddingBoxRect();

  gfx::QuadF quad = layout_box->LocalRectToAbsoluteQuad(rect);

  if (!quad.IsRectilinear())
    return false;

  gfx::Rect bounding_box = gfx::ToEnclosingRect(quad.BoundingBox());

  gfx::Size icb_size = top_document.GetLayoutView()->GetLayoutSize();

  float zoom = top_document.GetFrame()->LayoutZoomFactor();
  gfx::Size controls_hidden_size = gfx::ToCeiledSize(gfx::ScaleSize(
      top_document.View()->LargeViewportSizeForViewportUnits(), zoom));

  if (bounding_box.size() != icb_size &&
      bounding_box.size() != controls_hidden_size)
    return false;

  return bounding_box.origin().IsOrigin();
}

// If the element is an iframe this grabs the ScrollableArea for the owned
// LayoutView.
PaintLayerScrollableArea* GetScrollableArea(const Element& element) {
  if (const auto* frame_owner = DynamicTo<HTMLFrameOwnerElement>(element)) {
    EmbeddedContentView* content_view = frame_owner->OwnedEmbeddedContentView();
    if (!content_view)
      return nullptr;

    auto* frame_view = DynamicTo<LocalFrameView>(content_view);
    if (!frame_view)
      return nullptr;

    return frame_view->LayoutViewport();
  }

  if (!element.GetLayoutBoxForScrolling())
    return nullptr;

  return element.GetLayoutBoxForScrolling()->GetScrollableArea();
}

}  // namespace

RootScrollerController::RootScrollerController(Document& document)
    : document_(&document), effective_root_scroller_(&document) {}

void RootScrollerController::Trace(Visitor* visitor) const {
  visitor->Trace(document_);
  visitor->Trace(effective_root_scroller_);
  visitor->Trace(implicit_candidates_);
}

Node& RootScrollerController::EffectiveRootScroller() const {
  DCHECK(effective_root_scroller_);
  return *effective_root_scroller_;
}

void RootScrollerController::DidResizeFrameView() {
  DCHECK(document_);

  // TODO(bokan): This method is called from the LocalFrameView but before it's
  // attached to the document so View() can be nullptr. It's not great that we
  // might avoid calling DidResizeViewport on the initial size but it doesn't
  // currently matter since GlobalRootScrollerController().DidResizeViewport()
  // is used only to invalidate paint and compositing which is unnecessary when
  // creating the view.
  if (document_->View()) {
    // RootFrameViewport exists only in pages with a RootScroller, see
    // LocalFrameView::InitializeRootScroller.
    if (document_->View()->GetRootFrameViewport()) {
      DCHECK(document_->GetFrame()->IsMainFrame());
      document_->GetPage()->GlobalRootScrollerController().DidResizeViewport();
    }
  }

  // If the effective root scroller in this Document is a Frame, it'll match
  // its parent's frame rect. We can't rely on layout to kick it to update its
  // geometry so we do so explicitly here.
  if (auto* frame_owner =
          DynamicTo<HTMLFrameOwnerElement>(EffectiveRootScroller())) {
    UpdateIFrameGeometryAndLayoutSize(*frame_owner);
  }
}

void RootScrollerController::DidUpdateIFrameFrameView(
    HTMLFrameOwnerElement& element) {
  if (&element != effective_root_scroller_)
    return;

  // Ensure properties are re-applied even if the effective root scroller
  // doesn't change since the FrameView might have been swapped out and the new
  // one should have the properties reapplied.
  if (element.OwnedEmbeddedContentView())
    ApplyRootScrollerProperties(element);

  // Schedule a frame so we can reevaluate whether the iframe should be the
  // effective root scroller (e.g.  demote it if it became remote).
  if (LocalFrame* frame = document_->GetFrame())
    frame->ScheduleVisualUpdateUnlessThrottled();
}

bool RootScrollerController::RecomputeEffectiveRootScroller() {
  Node* new_effective_root_scroller = document_;

  if (!DocumentFullscreen::fullscreenElement(*document_)) {
    if (auto* implicit_root_scroller = ImplicitRootScrollerFromCandidates()) {
      new_effective_root_scroller = implicit_root_scroller;
      UseCounter::Count(document_, WebFeature::kActivatedImplicitRootScroller);
    }
  }

  // Note, the layout object can be replaced during a rebuild. In that case,
  // re-run process even if the element itself is the same.
  if (effective_root_scroller_ == new_effective_root_scroller &&
      effective_root_scroller_->IsEffectiveRootScroller())
    return false;

  Node* old_effective_root_scroller = effective_root_scroller_;
  effective_root_scroller_ = new_effective_root_scroller;

  DCHECK(new_effective_root_scroller);
  if (LayoutBoxModelObject* new_obj =
          new_effective_root_scroller->GetLayoutBoxModelObject()) {
    if (new_obj->Layer()) {
      new_effective_root_scroller->GetLayoutBoxModelObject()
          ->Layer()
          ->SetNeedsCompositingInputsUpdate();
    }
  }

  DCHECK(old_effective_root_scroller);
  if (LayoutBoxModelObject* old_obj =
          old_effective_root_scroller->GetLayoutBoxModelObject()) {
    if (old_obj->Layer()) {
      old_effective_root_scroller->GetLayoutBoxModelObject()
          ->Layer()
          ->SetNeedsCompositingInputsUpdate();
    }
  }

  if (auto* object = old_effective_root_scroller->GetLayoutObject())
    object->SetIsEffectiveRootScroller(false);

  if (auto* object = new_effective_root_scroller->GetLayoutObject())
    object->SetIsEffectiveRootScroller(true);

  ApplyRootScrollerProperties(*old_effective_root_scroller);
  ApplyRootScrollerProperties(*effective_root_scroller_);

  if (Page* page = document_->GetPage()) {
    page->GlobalRootScrollerController().DidChangeRootScroller();

    // Needed to set the |prevent_viewport_scrolling_from_inner| bit on the
    // VisualViewportScrollNode.
    page->GetVisualViewport().SetNeedsPaintPropertyUpdate();
  }

  return true;
}

bool RootScrollerController::IsValidRootScroller(const Element& element) const {
  if (!element.IsInTreeScope())
    return false;

  if (!element.GetLayoutObject())
    return false;

  if (!element.GetLayoutObject()->IsBox())
    return false;

  // Ignore anything inside a FlowThread (multi-col, paginated, etc.).
  if (element.GetLayoutObject()->IsInsideFlowThread())
    return false;

  if (!element.GetLayoutObject()->IsScrollContainer() &&
      !element.IsFrameOwnerElement())
    return false;

  if (const auto* frame_owner = DynamicTo<HTMLFrameOwnerElement>(element)) {
    if (!frame_owner->OwnedEmbeddedContentView())
      return false;

    // TODO(bokan): Make work with OOPIF. crbug.com/642378.
    if (!frame_owner->OwnedEmbeddedContentView()->IsLocalFrameView())
      return false;

    // It's possible for an iframe to have a LayoutView but not have performed
    // the lifecycle yet. We shouldn't promote such an iframe until it has
    // since we won't be able to use the scroller inside yet.
    Document* doc = frame_owner->contentDocument();
    if (!doc || !doc->View() || !doc->View()->DidFirstLayout())
      return false;
  }

  if (!FillsViewport(element))
    return false;

  return true;
}

bool RootScrollerController::IsValidImplicitCandidate(
    const Element& element) const {
  if (!element.IsInTreeScope())
    return false;

  if (!element.GetLayoutObject())
    return false;

  if (!element.GetLayoutObject()->IsBox())
    return false;

  // Ignore anything inside a FlowThread (multi-col, paginated, etc.).
  if (element.GetLayoutObject()->IsInsideFlowThread())
    return false;

  PaintLayerScrollableArea* scrollable_area = GetScrollableArea(element);
  if (!scrollable_area || !scrollable_area->ScrollsOverflow())
    return false;

  return true;
}

bool RootScrollerController::IsValidImplicit(const Element& element) const {
  // Valid implicit root scroller are a subset of valid root scrollers.
  if (!IsValidRootScroller(element))
    return false;

  const ComputedStyle* style = element.GetLayoutObject()->Style();
  if (!style)
    return false;

  // Do not implicitly promote things that are partially or fully invisible.
  if (style->HasOpacity() || !style->VisibleToHitTesting()) {
    return false;
  }

  PaintLayerScrollableArea* scrollable_area = GetScrollableArea(element);
  if (!scrollable_area)
    return false;

  if (!scrollable_area->ScrollsOverflow())
    return false;

  // If any of the ancestors clip overflow, don't promote. Promoting a
  // descendant of an overflow clip means it may not resize when the URL bar
  // hides so we'd leave a portion of the page hidden/unreachable.
  for (LayoutBox* ancestor = element.GetLayoutObject()->ContainingBlock();
       ancestor; ancestor = ancestor->ContainingBlock()) {
    // The LayoutView is allowed to have a clip (since its clip is resized by
    // the URL bar movement). Test it for scrolling so that we only promote if
    // we know we won't block scrolling the main document.
    if (IsA<LayoutView>(ancestor)) {
      const ComputedStyle* ancestor_style = ancestor->Style();
      DCHECK(ancestor_style);

      PaintLayerScrollableArea* area = ancestor->GetScrollableArea();
      DCHECK(area);

      if (ancestor_style->ScrollsOverflowY() && area->HasVerticalOverflow())
        return false;
    } else {
      if (ancestor->ShouldClipOverflowAlongEitherAxis() ||
          ancestor->HasMask() || ancestor->HasClip() ||
          ancestor->HasClipPath()) {
        return false;
      }
    }
  }

  return true;
}

void RootScrollerController::ApplyRootScrollerProperties(Node& node) {
  DCHECK(document_->GetFrame());
  DCHECK(document_->GetFrame()->View());

  // If the node has been removed from the Document, we shouldn't be touching
  // anything related to the Frame- or Layout- hierarchies.
  if (!node.IsInTreeScope())
    return;

  auto* frame_owner = DynamicTo<HTMLFrameOwnerElement>(node);
  if (!frame_owner)
    return;

  // The current effective root scroller may have lost its ContentFrame. If
  // that's the case, there's nothing to be done. https://crbug.com/805317 for
  // an example of how we get here.
  if (!frame_owner->ContentFrame())
    return;

  if (IsA<LocalFrame>(frame_owner->ContentFrame())) {
    LocalFrameView* frame_view =
        DynamicTo<LocalFrameView>(frame_owner->OwnedEmbeddedContentView());

    bool is_root_scroller = &EffectiveRootScroller() == &node;

    // If we're making the Frame the root scroller, it must have a FrameView
    // by now.
    DCHECK(frame_view || !is_root_scroller);
    if (frame_view) {
      frame_view->SetLayoutSizeFixedToFrameSize(!is_root_scroller);
      UpdateIFrameGeometryAndLayoutSize(*frame_owner);
    }
  } else {
    // TODO(bokan): Make work with OOPIF. crbug.com/642378.
  }
}

void RootScrollerController::UpdateIFrameGeometryAndLayoutSize(
    HTMLFrameOwnerElement& frame_owner) const {
  DCHECK(document_->GetFrame());
  DCHECK(document_->GetFrame()->View());

  LocalFrameView* child_view =
      To<LocalFrameView>(frame_owner.OwnedEmbeddedContentView());

  if (!child_view)
    return;

  child_view->UpdateGeometry();

  if (&EffectiveRootScroller() == frame_owner)
    child_view->SetLayoutSize(document_->GetFrame()->View()->GetLayoutSize());
}

Element* RootScrollerController::ImplicitRootScrollerFromCandidates() {
  if (!RuntimeEnabledFeatures::ImplicitRootScrollerEnabled())
    return nullptr;

  if (!document_->GetLayoutView())
    return nullptr;

  DCHECK(document_->View());

  // RootFrameViewport exists only in pages with a RootScroller, see
  // LocalFrameView::InitializeRootScroller.
  if (!document_->View()->GetRootFrameViewport())
    return nullptr;

  DCHECK(document_->GetFrame()->IsMainFrame());

  bool multiple_matches = false;

  Element* implicit_root_scroller = nullptr;
  HeapHashSet<WeakMember<Element>> copy(implicit_candidates_);
  for (auto& element : copy) {
    if (!IsValidImplicit(*element)) {
      if (!IsValidImplicitCandidate(*element))
        implicit_candidates_.erase(element);
      continue;
    }

    if (implicit_root_scroller)
      multiple_matches = true;

    implicit_root_scroller = element;
  }

  // Only promote an implicit root scroller if we have a unique match.
  return multiple_matches ? nullptr : implicit_root_scroller;
}

void RootScrollerController::ElementRemoved(const Element& element) {
  if (element != effective_root_scroller_.Get())
    return;

  effective_root_scroller_ = document_;
  if (Page* page = document_->GetPage())
    page->GlobalRootScrollerController().DidChangeRootScroller();
}

void RootScrollerController::ConsiderForImplicit(Node& node) {
  DCHECK(RuntimeEnabledFeatures::ImplicitRootScrollerEnabled());
  if (!document_->View()->GetRootFrameViewport())
    return;

  DCHECK(document_->GetFrame()->IsMainFrame());

  if (document_->GetPage()->GetChromeClient().IsPopup())
    return;

  auto* element = DynamicTo<Element>(node);
  if (!element)
    return;

  if (!IsValidImplicitCandidate(*element))
    return;

  implicit_candidates_.insert(element);
}

template <typename Function>
void RootScrollerController::ForAllNonThrottledLocalControllers(
    const Function& function) {
  if (!document_->View() || !document_->GetFrame())
    return;

  LocalFrameView* frame_view = document_->View();
  if (frame_view->ShouldThrottleRendering())
    return;

  LocalFrame* frame = document_->GetFrame();
  for (Frame* child = frame->Tree().FirstChild(); child;
       child = child->Tree().NextSibling()) {
    auto* child_local_frame = DynamicTo<LocalFrame>(child);
    if (!child_local_frame)
      continue;
    if (Document* child_document = child_local_frame->GetDocument()) {
      child_document->GetRootScrollerController()
          .ForAllNonThrottledLocalControllers(function);
    }
  }

  function(*this);
}

bool RootScrollerController::PerformRootScrollerSelection() {
  TRACE_EVENT0("blink", "RootScrollerController::PerformRootScrollerSelection");

  // Printing can cause a lifecycle update on a detached frame. In that case,
  // don't make any changes.
  if (!document_->GetFrame() || !document_->GetFrame()->IsLocalRoot())
    return false;

  DCHECK(document_->Lifecycle().GetState() >= DocumentLifecycle::kLayoutClean);

  bool result = false;
  ForAllNonThrottledLocalControllers(
      [&result](RootScrollerController& controller) {
        result |= controller.RecomputeEffectiveRootScroller();
      });
  return result;
}

}  // namespace blink

"""

```