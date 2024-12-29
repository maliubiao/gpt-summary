Response:
Let's break down the thought process for analyzing the `scrollable_area_painter.cc` file.

1. **Understand the Goal:** The request is to analyze the functionality of a specific Chromium source code file, `scrollable_area_painter.cc`, and relate it to web technologies, provide examples, and explain user interaction.

2. **Initial Scan for Keywords and Imports:**  The first step is to quickly scan the file for important keywords and included headers. This gives a high-level idea of the file's purpose.

    * **Keywords:** `Paint`, `ScrollableArea`, `Resizer`, `Scrollbar`, `OverflowControls`, `GraphicsContext`, `HitTesting`. These strongly suggest the file is responsible for drawing visual elements related to scrolling.
    * **Imports:**  Headers like `frame/visual_viewport.h`, `layout/custom_scrollbar.h`, `page/page.h`, `paint/`, `scroll/`, `platform/graphics/` reinforce the idea that this file deals with the visual representation of scrollable content. Specifically, the `paint/` directory suggests this file is deeply involved in the rendering process.

3. **Identify Core Functionalities (Public Methods):** The next step is to look at the public methods of the `ScrollableAreaPainter` class. These methods represent the primary actions this class can perform.

    * `PaintResizer()`:  Clearly handles drawing the resize handle.
    * `RecordResizerScrollHitTestData()`:  Deals with making the resizer interactive (for touch events).
    * `DrawPlatformResizerImage()`:  Specifically draws the platform-specific resize handle image.
    * `PaintOverflowControls()`:  A broad function likely responsible for drawing scrollbars and the scroll corner.
    * `PaintScrollbar()`:  Focuses on painting a single scrollbar.
    * `PaintNativeScrollbar()`: Handles painting the default, non-custom scrollbar.
    * `PaintScrollCorner()`: Deals with drawing the empty corner area.

4. **Analyze Individual Functionalities:** For each public method, analyze its internal logic and dependencies:

    * **`PaintResizer()`:** Checks visibility, calculates the resizer's rectangle, and then delegates the actual drawing to either a custom scrollbar theme or `DrawPlatformResizerImage()`. The drawing recorder is used for caching. It also draws a border around the resizer if scrollbars are present.

    * **`RecordResizerScrollHitTestData()`:**  Calculates the touch target area for the resizer and uses the paint controller to record hit-testing information. This makes the resizer tappable.

    * **`DrawPlatformResizerImage()`:**  Draws the characteristic diagonal lines of the resize handle, adjusting for left-side scrollbars and dark mode. This directly uses `GraphicsContext` drawing primitives.

    * **`PaintOverflowControls()`:** This is a central coordinating function. It determines *when* to paint overflow controls based on paint phases and whether the scroller is a self-painting layer. It then calls `PaintScrollbar()` and `PaintResizer()`. It also manages `ScopedPaintChunkProperties` for applying effects like clipping and transforms.

    * **`PaintScrollbar()`:**  Handles both custom and native scrollbars. It checks for overlay scrollbars in print mode, calculates the scrollbar's rectangle, and delegates painting to either a custom scrollbar's `Paint()` method or `PaintNativeScrollbar()`. It also records hit-test data for custom scrollbars.

    * **`PaintNativeScrollbar()`:**  Uses the `ScrollbarTheme` to draw the standard scrollbar. It also interacts with the paint controller for caching and hit-testing. The use of `ScrollbarDisplayItem::Record` suggests it's creating display items for the compositor.

    * **`PaintScrollCorner()`:**  Draws the empty corner. It prioritizes custom scroll corner drawing. If not custom, it defaults to the platform-specific scroll corner drawing using the `ScrollbarTheme`. It skips painting if overlay scrollbars are enabled.

5. **Relate to Web Technologies (HTML, CSS, JavaScript):**  Connect the code's functionality to how these technologies manifest in the browser:

    * **HTML:**  The structure of the page dictates where scrollable areas exist (e.g., `div` with `overflow: auto`). The presence of content overflowing a container triggers the need for scrollbars.
    * **CSS:**  Crucial for styling scrollbars (`::-webkit-scrollbar`, `scrollbar-color`), controlling overflow behavior (`overflow`, `overflow-x`, `overflow-y`), and enabling resizing (`resize`). CSS also influences dark mode, which is handled in the drawing.
    * **JavaScript:** Can programmatically scroll elements (`element.scroll()`, `element.scrollTo()`), which indirectly triggers repaints handled by this class. JavaScript can also dynamically change styles that affect scrollbars.

6. **Provide Examples:** Concrete examples make the concepts clearer. Illustrate how different CSS properties lead to the execution of code in this file.

7. **Logical Reasoning (Assumptions and Outputs):**  Demonstrate how the code behaves under specific conditions. Think of a simple scenario (e.g., a div with overflow) and trace the likely execution path and visual output.

8. **Common User/Programming Errors:**  Highlight mistakes that developers might make that could lead to issues related to this code (e.g., forgetting `overflow: auto`, incorrect z-indexing).

9. **Debugging Clues:** Explain how a developer might end up investigating this file during debugging. What user actions or observed behavior could lead them here?

10. **Structure and Refine:** Organize the information logically, using headings and bullet points for clarity. Review and refine the language for accuracy and conciseness. Ensure the explanation flows well and addresses all parts of the request. For example, initially, I might have just said "draws scrollbars," but refining it involves explaining the distinction between custom and native scrollbars, overlay scrollbars, and the different paint phases.

By following these steps, we can systematically analyze the code and provide a comprehensive explanation of its functionality and its relationship to web technologies. The iterative process of scanning, identifying key functions, analyzing their logic, and then connecting them to the bigger picture of web rendering is crucial.
这个文件 `blink/renderer/core/paint/scrollable_area_painter.cc` 的主要功能是**负责绘制可滚动区域的各种视觉元素**，包括滚动条、滚动条角落（scroll corner）和调整大小的拖拽手柄（resizer）。它是 Blink 渲染引擎中处理滚动相关视觉效果的关键组件。

**以下是它的具体功能列表：**

1. **绘制调整大小的拖拽手柄 (Resizer):**
   - `PaintResizer()`:  主函数，根据是否可以调整大小、可见性以及裁剪区域，决定是否绘制调整大小的手柄。它会调用平台相关的绘制函数或自定义滚动条的绘制逻辑。
   - `RecordResizerScrollHitTestData()`:  记录调整大小手柄的点击测试数据，用于确定用户是否点击了该区域以进行拖拽调整大小的操作。
   - `DrawPlatformResizerImage()`:  绘制平台默认的调整大小手柄的图像，通常是一些小三角形。

2. **绘制溢出控件 (Overflow Controls)，主要是滚动条:**
   - `PaintOverflowControls()`:  一个协调函数，根据不同的绘制阶段（PaintPhase）和元素属性，决定是否绘制滚动条和滚动条角落。它会调用 `PaintScrollbar()` 和 `PaintScrollCorner()`。

3. **绘制滚动条 (Scrollbar):**
   - `PaintScrollbar()`:  绘制单个滚动条。它会区分自定义滚动条和原生滚动条，并调用相应的绘制方法。它还会处理打印时的覆盖滚动条隐藏。
   - `PaintNativeScrollbar()`:  绘制原生平台的滚动条。它使用 `ScrollbarTheme` 来绘制不同平台的滚动条样式。

4. **绘制滚动条角落 (Scroll Corner):**
   - `PaintScrollCorner()`:  绘制滚动条交叉形成的空白角落区域。它可以填充颜色，或者在使用了非全覆盖的滚动条时填充白色。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件本身是用 C++ 编写的，是 Blink 渲染引擎的底层代码。但它的功能直接受到 HTML 结构和 CSS 样式的影响，并间接影响 JavaScript 的行为。

* **HTML:**
    - **功能关系:** HTML 元素的结构决定了哪些元素是可滚动的。例如，一个设置了 `overflow: auto` 或 `overflow: scroll` 的 `div` 元素会创建一个可滚动区域，从而触发 `ScrollableAreaPainter` 的工作。
    - **举例说明:**
      ```html
      <div style="width: 200px; height: 100px; overflow: auto;">
        很多超出容器大小的内容...
      </div>
      ```
      当 `div` 中的内容超出其设定的宽度和高度时，浏览器会显示滚动条，`ScrollableAreaPainter` 就负责绘制这些滚动条。

* **CSS:**
    - **功能关系:** CSS 样式决定了滚动条的外观、行为以及是否显示。例如，`overflow` 属性决定了是否需要滚动条，`::-webkit-scrollbar` 等伪元素可以自定义滚动条的样式，`resize` 属性控制元素是否可以被用户拖拽调整大小。
    - **举例说明:**
      ```css
      /* 自定义滚动条样式 */
      ::-webkit-scrollbar {
        width: 10px;
      }
      ::-webkit-scrollbar-thumb {
        background-color: gray;
      }

      /* 启用元素的调整大小功能 */
      div {
        resize: both;
        overflow: auto;
      }
      ```
      上述 CSS 代码会影响 `ScrollableAreaPainter` 如何绘制滚动条（通过 `CustomScrollbarTheme`）以及是否绘制调整大小的手柄。

* **JavaScript:**
    - **功能关系:** JavaScript 可以动态地修改元素的样式和内容，从而影响滚动条的显示和状态。例如，JavaScript 可以改变元素的 `overflow` 属性，或者通过改变元素的内容使其超出容器大小，从而触发滚动条的显示。JavaScript 还可以监听滚动事件。
    - **举例说明:**
      ```javascript
      const myDiv = document.getElementById('myDiv');
      myDiv.style.overflow = 'scroll'; // 通过 JavaScript 设置滚动条显示
      myDiv.innerHTML = '更多内容...'; // 如果内容超出容器，会显示滚动条
      ```
      当 JavaScript 代码导致元素需要显示滚动条时，`ScrollableAreaPainter` 会被调用来绘制它们。

**逻辑推理 (假设输入与输出):**

假设输入一个 `LayoutBox` 对象，该对象是一个设置了 `overflow: auto` 的 `div` 元素，并且其内容超出了容器的大小。

* **假设输入:**
    - 一个 `LayoutBox` 对象，代表一个 `div` 元素。
    - 该 `LayoutBox` 的样式包含 `overflow: auto`。
    - 该 `LayoutBox` 的内容在布局后发现超出其设定的边界。

* **输出 (`ScrollableAreaPainter` 的行为):**
    - `PaintOverflowControls()` 会被调用。
    - 根据平台和样式，`PaintScrollbar()` 会被调用来绘制水平和/或垂直滚动条。
    - 如果没有自定义滚动条样式，`PaintNativeScrollbar()` 会被调用来绘制平台默认的滚动条。
    - 如果存在调整大小的样式 (`resize: both` 等)，`PaintResizer()` 会被调用来绘制调整大小的手柄。
    - `PaintScrollCorner()` 可能会被调用来绘制滚动条角落。

**用户或编程常见的使用错误及举例说明:**

1. **忘记设置 `overflow` 属性:** 如果开发者创建了一个内容可能溢出的容器，但忘记设置 `overflow: auto`、`overflow: scroll` 或 `overflow: hidden`，那么内容会溢出容器，但不会显示滚动条。用户会看不到超出部分的内容，这可能不是预期的行为。
   ```html
   <div style="width: 100px; height: 50px;">
     很长很长的内容，超出容器范围。
   </div>
   ```
   在这个例子中，因为没有设置 `overflow`，所以不会出现滚动条。

2. **错误地使用 `overflow: hidden`:**  虽然 `overflow: hidden` 可以阻止内容溢出，但它也会裁剪掉超出部分的内容，并且不会显示滚动条。如果开发者希望用户能够看到所有内容，只是希望在必要时出现滚动条，那么应该使用 `overflow: auto` 或 `overflow: scroll`。

3. **自定义滚动条样式导致不可用或难以使用:**  过度或不合理的自定义滚动条样式可能会导致滚动条难以被用户识别或操作，例如，滚动条宽度过小、颜色与背景色过于接近等。这会影响用户体验。

4. **z-index 问题导致滚动条被遮挡:**  如果滚动容器的父元素或者其他兄弟元素设置了较高的 `z-index` 值，可能会导致滚动条被这些元素遮挡，用户无法看到或操作滚动条。

**用户操作是如何一步步到达这里，作为调试线索:**

1. **用户加载包含可滚动内容的网页:** 当用户在浏览器中打开一个网页时，HTML 被解析，CSS 被应用，布局引擎计算出元素的位置和大小。
2. **布局引擎确定需要滚动条:** 如果一个元素的内容在布局后发现超出了其设定的边界（例如，设置了固定宽度和高度的 `div` 中内容过多），并且其 `overflow` 属性允许显示滚动条（`auto` 或 `scroll`），布局引擎会标记该元素需要滚动条。
3. **进入绘制阶段:** 渲染引擎开始进行绘制操作。对于需要绘制滚动条的可滚动区域，会创建或更新相应的 `PaintLayer`。
4. **调用 `ScrollableAreaPainter`:** 在绘制 `PaintLayer` 的过程中，如果该 `PaintLayer` 对应一个可滚动区域，会创建或使用 `ScrollableAreaPainter` 对象。
5. **执行 `PaintOverflowControls` 等方法:** `ScrollableAreaPainter` 的 `PaintOverflowControls` 方法会被调用，根据需要绘制滚动条、滚动条角落和调整大小的手柄。具体的绘制工作会委托给 `PaintScrollbar`, `PaintNativeScrollbar`, `PaintResizer`, `PaintScrollCorner` 等方法。
6. **绘制到 GraphicsContext:** 这些绘制方法最终会调用 `GraphicsContext` 提供的方法，将滚动条的视觉元素绘制到屏幕上。

**作为调试线索:**

如果开发者在调试与滚动条显示相关的问题，例如：

* **滚动条不出现:**  可以检查 HTML 结构中是否确实存在内容溢出，以及 CSS 中 `overflow` 属性的设置是否正确。断点可以设置在布局引擎计算滚动条是否需要的阶段，以及 `ScrollableAreaPainter::PaintOverflowControls` 的入口处。
* **滚动条样式异常:**  可以检查相关的 CSS 样式是否生效，特别是 `::-webkit-scrollbar` 等伪元素。可以查看 `CustomScrollbarTheme::PaintIntoRect` 的调用情况。
* **调整大小手柄不出现或无法拖拽:**  检查元素是否设置了 `resize` 属性。断点可以设置在 `ScrollableAreaPainter::PaintResizer` 和 `ScrollableAreaPainter::RecordResizerScrollHitTestData`。
* **滚动条被遮挡:**  检查相关元素的 `z-index` 值。

通过理解 `ScrollableAreaPainter` 的功能和它与 HTML、CSS、JavaScript 的关系，开发者可以更好地理解浏览器是如何渲染滚动条的，并更有效地调试相关的渲染问题。

Prompt: 
```
这是目录为blink/renderer/core/paint/scrollable_area_painter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/scrollable_area_painter.h"

#include <optional>

#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/layout/custom_scrollbar.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/paint/custom_scrollbar_theme.h"
#include "third_party/blink/renderer/core/paint/object_paint_properties.h"
#include "third_party/blink/renderer/core/paint/object_painter.h"
#include "third_party/blink/renderer/core/paint/paint_auto_dark_mode.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_layer_delegate.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_theme.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context_state_saver.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"
#include "third_party/blink/renderer/platform/graphics/paint/scoped_paint_chunk_properties.h"
#include "third_party/blink/renderer/platform/graphics/paint/scrollbar_display_item.h"

namespace blink {

namespace {

bool VisibleToHitTesting(const LayoutBox& box) {
  if (RuntimeEnabledFeatures::HitTestOpaquenessEnabled()) {
    return ObjectPainter(box).GetHitTestOpaqueness() !=
           cc::HitTestOpaqueness::kTransparent;
  }
  return box.VisibleToHitTesting();
}

}  // namespace

void ScrollableAreaPainter::PaintResizer(GraphicsContext& context,
                                         const PhysicalOffset& paint_offset,
                                         const CullRect& cull_rect) {
  const auto* box = scrollable_area_.GetLayoutBox();
  DCHECK_EQ(box->StyleRef().Visibility(), EVisibility::kVisible);
  if (!box->CanResize())
    return;

  gfx::Rect visual_rect =
      scrollable_area_.ResizerCornerRect(kResizerForPointer);
  // TODO(crbug.com/40105990): We should not ignore paint_offset but should
  // consider subpixel accumulation when painting resizers.
  visual_rect.Offset(ToRoundedVector2d(paint_offset));
  if (!cull_rect.Intersects(visual_rect))
    return;

  const auto& client = scrollable_area_.GetScrollCornerDisplayItemClient();
  if (const auto* resizer = scrollable_area_.Resizer()) {
    CustomScrollbarTheme::PaintIntoRect(*resizer, context,
                                        PhysicalRect(visual_rect));
    return;
  }

  if (DrawingRecorder::UseCachedDrawingIfPossible(context, client,
                                                  DisplayItem::kResizer))
    return;

  DrawingRecorder recorder(context, client, DisplayItem::kResizer, visual_rect);

  DrawPlatformResizerImage(context, visual_rect);

  // Draw a frame around the resizer (1px grey line) if there are any scrollbars
  // present.  Clipping will exclude the right and bottom edges of this frame.
  if (scrollable_area_.NeedsScrollCorner()) {
    GraphicsContextStateSaver state_saver(context);
    context.Clip(visual_rect);
    gfx::Rect larger_corner = visual_rect;
    larger_corner.set_size(
        gfx::Size(larger_corner.width() + 1, larger_corner.height() + 1));
    context.SetStrokeColor(Color(217, 217, 217));
    context.SetStrokeThickness(1);
    gfx::RectF corner_outline(larger_corner);
    corner_outline.Inset(0.5f);
    context.StrokeRect(
        corner_outline,
        PaintAutoDarkMode(box->StyleRef(),
                          DarkModeFilter::ElementRole::kBackground));
  }
}

void ScrollableAreaPainter::RecordResizerScrollHitTestData(
    GraphicsContext& context,
    const PhysicalOffset& paint_offset) {
  const auto* box = scrollable_area_.GetLayoutBox();
  DCHECK(VisibleToHitTesting(*box));
  if (!box->CanResize())
    return;

  gfx::Rect touch_rect = scrollable_area_.ResizerCornerRect(kResizerForTouch);
  // TODO(crbug.com/40105990): We should not round paint_offset but should
  // consider subpixel accumulation when painting resizers.
  touch_rect.Offset(ToRoundedVector2d(paint_offset));
  context.GetPaintController().RecordScrollHitTestData(
      scrollable_area_.GetScrollCornerDisplayItemClient(),
      DisplayItem::kResizerScrollHitTest, nullptr, touch_rect,
      // Assume hit testing in some area may pass though.
      cc::HitTestOpaqueness::kMixed);
}

void ScrollableAreaPainter::DrawPlatformResizerImage(
    GraphicsContext& context,
    const gfx::Rect& resizer_corner_rect) {
  gfx::Point points[4];
  bool on_left = false;
  float paint_scale = scrollable_area_.ScaleFromDIP();
  int edge_offset = std::ceil(paint_scale);
  if (scrollable_area_.GetLayoutBox()
          ->ShouldPlaceBlockDirectionScrollbarOnLogicalLeft()) {
    on_left = true;
    points[0].set_x(resizer_corner_rect.x() + edge_offset);
    points[1].set_x(resizer_corner_rect.x() + resizer_corner_rect.width() -
                    resizer_corner_rect.width() / 2);
    points[2].set_x(points[0].x());
    points[3].set_x(resizer_corner_rect.x() + resizer_corner_rect.width() -
                    resizer_corner_rect.width() * 3 / 4);
  } else {
    points[0].set_x(resizer_corner_rect.x() + resizer_corner_rect.width() -
                    edge_offset);
    points[1].set_x(resizer_corner_rect.x() + resizer_corner_rect.width() / 2);
    points[2].set_x(points[0].x());
    points[3].set_x(resizer_corner_rect.x() +
                    resizer_corner_rect.width() * 3 / 4);
  }
  points[0].set_y(resizer_corner_rect.y() + resizer_corner_rect.height() / 2);
  points[1].set_y(resizer_corner_rect.y() + resizer_corner_rect.height() -
                  edge_offset);
  points[2].set_y(resizer_corner_rect.y() +
                  resizer_corner_rect.height() * 3 / 4);
  points[3].set_y(points[1].y());

  cc::PaintFlags paint_flags;
  paint_flags.setStyle(cc::PaintFlags::kStroke_Style);
  paint_flags.setStrokeWidth(std::ceil(paint_scale));

  SkPath line_path;

  AutoDarkMode auto_dark_mode(
      PaintAutoDarkMode(scrollable_area_.GetLayoutBox()->StyleRef(),
                        DarkModeFilter::ElementRole::kBackground));

  // Draw a dark line, to ensure contrast against a light background
  line_path.moveTo(points[0].x(), points[0].y());
  line_path.lineTo(points[1].x(), points[1].y());
  line_path.moveTo(points[2].x(), points[2].y());
  line_path.lineTo(points[3].x(), points[3].y());
  paint_flags.setColor(SkColorSetARGB(153, 0, 0, 0));
  context.DrawPath(line_path, paint_flags, auto_dark_mode);

  // Draw a light line one pixel below the light line,
  // to ensure contrast against a dark background
  int v_offset = std::ceil(paint_scale);
  int h_offset = on_left ? -v_offset : v_offset;
  line_path.reset();
  line_path.moveTo(points[0].x(), points[0].y() + v_offset);
  line_path.lineTo(points[1].x() + h_offset, points[1].y());
  line_path.moveTo(points[2].x(), points[2].y() + v_offset);
  line_path.lineTo(points[3].x() + h_offset, points[3].y());
  paint_flags.setColor(SkColorSetARGB(153, 255, 255, 255));
  context.DrawPath(line_path, paint_flags, auto_dark_mode);
}

bool ScrollableAreaPainter::PaintOverflowControls(
    const PaintInfo& paint_info,
    const PhysicalOffset& paint_offset,
    const FragmentData* fragment) {
  if (!fragment) {
    return false;
  }

  // Don't do anything if we have no overflow.
  const auto& box = *scrollable_area_.GetLayoutBox();
  CHECK(box.IsScrollContainer());
  if (box.StyleRef().Visibility() != EVisibility::kVisible) {
    return false;
  }

  // Overflow controls are painted in the following paint phases:
  // - Overlay overflow controls of self-painting layers or reordered overlay
  //   overflow controls are painted in PaintPhase::kOverlayOverflowControls,
  //   called from PaintLayerPainter::PaintChildren().
  // - Non-reordered overlay overflow controls of non-self-painting-layer
  //   scrollers are painted in PaintPhase::kForeground.
  // - Non-overlay overflow controls are painted in PaintPhase::kBackground.
  if (scrollable_area_.ShouldOverflowControlsPaintAsOverlay()) {
    if (box.HasSelfPaintingLayer() ||
        box.Layer()->NeedsReorderOverlayOverflowControls()) {
      if (paint_info.phase != PaintPhase::kOverlayOverflowControls)
        return false;
    } else if (paint_info.phase != PaintPhase::kForeground) {
      return false;
    }
  } else if (!ShouldPaintSelfBlockBackground(paint_info.phase)) {
    return false;
  }

  GraphicsContext& context = paint_info.context;

  const ClipPaintPropertyNode* clip = nullptr;
  const auto* properties = fragment->PaintProperties();
  // TODO(crbug.com/849278): Remove either the DCHECK or the if condition
  // when we figure out in what cases that the box doesn't have properties.
  DCHECK(properties);
  if (properties)
    clip = properties->OverflowControlsClip();

  const TransformPaintPropertyNodeOrAlias* transform = nullptr;
  if (box.IsGlobalRootScroller()) {
    LocalFrameView* frame_view = box.GetFrameView();
    DCHECK(frame_view);
    const auto* page = frame_view->GetPage();
    const auto& viewport = page->GetVisualViewport();
    if (const auto* scrollbar_transform =
            viewport.TransformNodeForViewportScrollbars()) {
      transform = scrollbar_transform;
    }
  }

  std::optional<ScopedPaintChunkProperties> scoped_paint_chunk_properties;
  if (clip || transform) {
    PaintController& paint_controller = context.GetPaintController();
    PropertyTreeStateOrAlias modified_properties(
        paint_controller.CurrentPaintChunkProperties());
    if (clip)
      modified_properties.SetClip(*clip);
    if (transform)
      modified_properties.SetTransform(*transform);

    scoped_paint_chunk_properties.emplace(paint_controller, modified_properties,
                                          box, DisplayItem::kOverflowControls);
  }

  if (scrollable_area_.HorizontalScrollbar()) {
    PaintScrollbar(context, *scrollable_area_.HorizontalScrollbar(),
                   paint_offset, paint_info.GetCullRect());
  }
  if (scrollable_area_.VerticalScrollbar()) {
    PaintScrollbar(context, *scrollable_area_.VerticalScrollbar(), paint_offset,
                   paint_info.GetCullRect());
  }

  // We fill our scroll corner with white if we have a scrollbar that doesn't
  // run all the way up to the edge of the box.
  PaintScrollCorner(context, paint_offset, paint_info.GetCullRect());

  // Paint our resizer last, since it sits on top of the scroll corner.
  PaintResizer(context, paint_offset, paint_info.GetCullRect());

  return true;
}

void ScrollableAreaPainter::PaintScrollbar(GraphicsContext& context,
                                           Scrollbar& scrollbar,
                                           const PhysicalOffset& paint_offset,
                                           const CullRect& cull_rect) {
  // Don't paint overlay scrollbars when printing otherwise all scrollbars will
  // be visible and cover contents.
  if (scrollbar.IsOverlayScrollbar() &&
      scrollable_area_.GetLayoutBox()->GetDocument().Printing()) {
    return;
  }

  // TODO(crbug.com/40105990): We should not round paint_offset but should
  // consider subpixel accumulation when painting scrollbars.
  gfx::Rect visual_rect = scrollbar.FrameRect();
  visual_rect.Offset(ToRoundedVector2d(paint_offset));
  if (!cull_rect.Intersects(visual_rect))
    return;

  const auto* properties =
      scrollable_area_.GetLayoutBox()->FirstFragment().PaintProperties();
  CHECK(properties);
  auto type = scrollbar.Orientation() == kHorizontalScrollbar
                  ? DisplayItem::kScrollbarHorizontal
                  : DisplayItem::kScrollbarVertical;
  std::optional<ScopedPaintChunkProperties> chunk_properties;
  if (const auto* effect = scrollbar.Orientation() == kHorizontalScrollbar
                               ? properties->HorizontalScrollbarEffect()
                               : properties->VerticalScrollbarEffect()) {
    chunk_properties.emplace(context.GetPaintController(), *effect, scrollbar,
                             type);
  }

  if (scrollbar.IsCustomScrollbar()) {
    To<CustomScrollbar>(scrollbar).Paint(context, paint_offset);
    // Custom scrollbars need main thread hit testing. The hit test rect will
    // contribute to the non-fast scrollable region of the containing layer.
    if (VisibleToHitTesting(*scrollable_area_.GetLayoutBox())) {
      context.GetPaintController().RecordScrollHitTestData(
          scrollbar, DisplayItem::kScrollbarHitTest, nullptr, visual_rect,
          // Assume hit testing in some area may pass though.
          cc::HitTestOpaqueness::kMixed);
    }
  } else {
    // If the scrollbar turns out to be not composited, PaintChunksToCcLayer
    // will add its visual rect into the containing layer's non-fast scrollable
    // region.
    PaintNativeScrollbar(context, scrollbar, visual_rect);
  }
}

void ScrollableAreaPainter::PaintNativeScrollbar(GraphicsContext& context,
                                                 Scrollbar& scrollbar,
                                                 gfx::Rect visual_rect) {
  auto type = scrollbar.Orientation() == kHorizontalScrollbar
                  ? DisplayItem::kScrollbarHorizontal
                  : DisplayItem::kScrollbarVertical;

  if (context.GetPaintController().UseCachedItemIfPossible(scrollbar, type))
    return;

  const auto* properties =
      scrollable_area_.GetLayoutBox()->FirstFragment().PaintProperties();
  CHECK(properties);

  const TransformPaintPropertyNode* scroll_translation = nullptr;
  if (scrollable_area_.MayCompositeScrollbar(scrollbar)) {
    scroll_translation = properties->ScrollTranslation();
    CHECK(scroll_translation);
    CHECK(scroll_translation->ScrollNode());
  }

  cc::HitTestOpaqueness hit_test_opaqueness;
  if (scrollbar.GetTheme().AllowsHitTest()) {
    hit_test_opaqueness =
        ObjectPainter(*scrollable_area_.GetLayoutBox()).GetHitTestOpaqueness();
    if (RuntimeEnabledFeatures::HitTestOpaquenessEnabled() &&
        hit_test_opaqueness == cc::HitTestOpaqueness::kMixed) {
      // A scrollbar is always opaque to hit test if it's visible to hit test,
      // which is assumed in cc for non-solid-color scrollbar layers.
      hit_test_opaqueness = cc::HitTestOpaqueness::kOpaque;
    }
  } else {
    hit_test_opaqueness = cc::HitTestOpaqueness::kTransparent;
  }

  auto delegate = base::MakeRefCounted<ScrollbarLayerDelegate>(scrollbar);
  ScrollbarDisplayItem::Record(context, scrollbar, type, std::move(delegate),
                               visual_rect, scroll_translation,
                               scrollbar.GetElementId(), hit_test_opaqueness);
}

void ScrollableAreaPainter::PaintScrollCorner(
    GraphicsContext& context,
    const PhysicalOffset& paint_offset,
    const CullRect& cull_rect) {
  gfx::Rect visual_rect = scrollable_area_.ScrollCornerRect();
  // TODO(crbug.com/40105990): We should not round paint_offset but should
  // consider subpixel accumulation when painting scroll corners.
  visual_rect.Offset(ToRoundedVector2d(paint_offset));
  if (!cull_rect.Intersects(visual_rect))
    return;

  const auto& client = scrollable_area_.GetScrollCornerDisplayItemClient();

  // Make sure to set up the effect node before painting custom or native
  // scrollbar.
  std::optional<ScopedPaintChunkProperties> chunk_properties;
  const auto* properties =
      scrollable_area_.GetLayoutBox()->FirstFragment().PaintProperties();
  if (const auto* effect = properties->ScrollCornerEffect()) {
    chunk_properties.emplace(context.GetPaintController(), *effect, client,
                             DisplayItem::kScrollCorner);
  }

  if (const auto* scroll_corner = scrollable_area_.ScrollCorner()) {
    CustomScrollbarTheme::PaintIntoRect(*scroll_corner, context,
                                        PhysicalRect(visual_rect));
    return;
  }

  // We don't want to paint opaque if we have overlay scrollbars, since we need
  // to see what is behind it.
  if (scrollable_area_.HasOverlayScrollbars()) {
    return;
  }

  ScrollbarTheme* theme = nullptr;

  if (scrollable_area_.HorizontalScrollbar()) {
    theme = &scrollable_area_.HorizontalScrollbar()->GetTheme();
  } else if (scrollable_area_.VerticalScrollbar()) {
    theme = &scrollable_area_.VerticalScrollbar()->GetTheme();
  } else {
    NOTREACHED();
  }

  theme->PaintScrollCorner(context, scrollable_area_, client, visual_rect);
}

}  // namespace blink

"""

```