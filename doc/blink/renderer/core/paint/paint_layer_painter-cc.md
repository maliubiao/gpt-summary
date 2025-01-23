Response:
Let's break down the thought process for analyzing this C++ source code. The goal is to understand its purpose, relationships to web technologies, potential errors, and debugging steps.

**1. Initial Skim and Keyword Identification:**

The first step is to quickly read through the code, looking for keywords and familiar terms. Things that immediately jump out are:

* `PaintLayerPainter`: The central class. "Painter" suggests responsibility for drawing or rendering something. "PaintLayer" hints at the concept of layers in web page rendering.
* `GraphicsContext`:  A clear indicator of drawing operations.
* `PaintFlags`: Configuration options for painting.
* `PaintPhase`: Different stages of the painting process (background, foreground, etc.).
* `FragmentData`, `LayoutBox`, `LayoutInline`:  Layout-related classes, pointing to the structure of the rendered page.
* `HTMLCanvasElement`, `LayoutVideo`: Specific HTML elements, suggesting handling of different content types.
* `opacity`, `will-change`, `clip-path`, `mask`: CSS properties, establishing a link to web styling.
* `JavaScript` (implied by interaction with HTML and CSS).
* `cull_rect`, `visual_rect`: Concepts related to optimization and visibility.
* `SubsequenceRecorder`: A potential caching mechanism.
* `ScrollableArea`: Handling of scrolling content.
* `Chrome`, `Blink`:  The broader context of the code.

**2. Deduce Core Functionality from Class Name and Key Methods:**

The name `PaintLayerPainter` strongly suggests its primary function is to handle the painting of individual `PaintLayer` objects. Looking at the main `Paint()` method confirms this. It orchestrates the drawing process for a given layer.

**3. Analyze Key Methods and Their Interactions:**

* **`Paint()`:** The main entry point. It handles various checks (layout needed, visibility), sets up scopes (`SubsequenceRecorder`, `ScopedEffectivelyInvisible`, `ScopedPaintChunkProperties`), and calls other `PaintWithPhase()` and `PaintChildren()` to delegate the actual drawing.
* **`PaintWithPhase()`:**  Responsible for painting specific phases (background, foreground, etc.) of a layer. It iterates through fragments of the layout object.
* **`PaintChildren()`:**  Recursively calls `Paint()` on the child layers, respecting the paint order.
* **`PaintedOutputInvisible()`:**  Determines if a layer is effectively invisible based on CSS properties like `opacity` and `backdrop-filter`.
* **Helper functions:** `ContentsVisualRect()`, `ShouldCreateSubsequence()`, `FirstFragmentVisualRect()` provide utility for the main painting process.

**4. Connect to Web Technologies (HTML, CSS, JavaScript):**

* **HTML:** The code interacts with specific HTML elements like `<canvas>` and `<video>`, indicating its role in rendering these elements.
* **CSS:** The presence of checks for CSS properties (`opacity`, `will-change`, `clip-path`, `mask`, `outline`) directly links this code to CSS styling and its effects on rendering.
* **JavaScript:**  While not directly present in this file, the functionality it provides (rendering elements, handling visibility, etc.) is crucial for JavaScript's interaction with the DOM and CSSOM. JavaScript manipulations often trigger repaints handled by this code.

**5. Identify Potential Errors and User Actions Leading to Them:**

* **Layout issues:** The check for `object.NeedsLayout()` highlights potential problems if painting occurs before layout is complete. This could be caused by JavaScript manipulating styles without waiting for the layout to update.
* **Infinite loops/Recursion (less likely here but worth considering in complex systems):**  If there were issues in the paint order or parent-child relationships, it *could* theoretically lead to infinite painting loops. This isn't apparent in the current code but is a general debugging consideration.
* **Performance issues:** The use of `SubsequenceRecorder` suggests performance optimization. Incorrect caching or unnecessary repaints could lead to jank. User actions causing rapid style changes or complex animations could trigger these.
* **Visual glitches:** Incorrect handling of `opacity`, `clip-path`, or `mask` could lead to elements not rendering as expected. User actions that trigger these CSS properties would be relevant.

**6. Develop Scenarios and Test Cases (Hypothetical Input/Output):**

* **Scenario 1 (Simple):** A `div` with a background color. Input: HTML `<div>`, CSS `background-color: red;`. Output: The `Paint()` method would likely call `PaintWithPhase(kSelfBlockBackgroundOnly, ...)` to draw the red background.
* **Scenario 2 (Opacity):** A `div` with `opacity: 0.5`. Input: HTML `<div>`, CSS `opacity: 0.5;`. Output: `PaintedOutputInvisible()` would return `false`, and the paint calls would proceed, potentially with adjustments to the alpha channel of drawing operations.
* **Scenario 3 (Invisible):** A `div` with `opacity: 0`. Input: HTML `<div>`, CSS `opacity: 0;`. Output: `PaintedOutputInvisible()` would likely return `true`, potentially causing the `Paint()` method to return early, skipping most drawing operations.

**7. Consider Debugging Steps:**

Understanding how a user action leads to this code is crucial for debugging. This involves tracing the rendering pipeline:

* **User Action:**  A user interacts with the page (e.g., hovers, scrolls, clicks).
* **Event Handling (JavaScript):**  JavaScript might respond to the event, potentially modifying the DOM or CSSOM.
* **Style Recalculation:** The browser recalculates styles based on the changes.
* **Layout:** The browser re-flows and re-positions elements if necessary.
* **Paint Invalidation:**  The browser marks parts of the page that need repainting.
* **Paint Tree Traversal:** The browser walks the paint tree, and for each `PaintLayer`, a `PaintLayerPainter` instance is involved to draw it.

**8. Iterative Refinement:**

The process isn't strictly linear. As you understand more, you might revisit earlier assumptions and refine your analysis. For example, realizing the significance of `FragmentData` requires understanding the concept of layout fragments.

By following these steps, we can systematically analyze the provided C++ code and gain a comprehensive understanding of its role in the Blink rendering engine.
这个文件 `blink/renderer/core/paint/paint_layer_painter.cc` 是 Chromium Blink 渲染引擎中的一个核心组件，其主要功能是**负责绘制 `PaintLayer` 对象**。`PaintLayer` 代表了渲染树中的一个绘制层，它包含了需要一起绘制的内容。`PaintLayerPainter` 遍历这些层，并指示如何将它们的内容渲染到屏幕上。

以下是该文件的详细功能列表以及与 JavaScript, HTML, CSS 的关系：

**核心功能:**

1. **绘制 PaintLayer:** 这是 `PaintLayerPainter` 的主要职责。它接收一个 `PaintLayer` 对象和 `GraphicsContext` 对象（提供绘图能力），并根据 `PaintLayer` 的属性和内容，将其绘制到上下文中。

2. **管理绘制阶段 (Paint Phases):**  网页的渲染不是一次完成的，而是分为多个阶段进行，例如绘制背景、前景、边框、轮廓等。`PaintLayerPainter` 中的 `PaintWithPhase` 方法负责在特定的绘制阶段执行绘制操作。

3. **处理子层的绘制 (Painting Children):**  `PaintLayerPainter` 会递归地调用自身来绘制其子 `PaintLayer`。`PaintChildren` 方法负责遍历子层并调用它们的 `Paint` 方法。

4. **优化绘制 (Culling and Skipping):**  为了提高性能，`PaintLayerPainter` 会进行一些优化：
    * **剔除 (Culling):**  通过比较裁剪矩形 (`cull_rect`) 和元素的可见矩形 (`visual_rect`)，判断元素是否在可视区域内，从而避免绘制不可见的内容。
    * **跳过不需要绘制的层:**  例如，如果一个层没有可见内容或者被完全遮挡，`PaintLayerPainter` 可以跳过绘制。
    * **子序列缓存 (Subsequence Caching):**  通过 `SubsequenceRecorder`，可以缓存某些绘制操作的结果，以便在后续绘制中重用，从而提高性能。

5. **处理不同的内容类型:**  `PaintLayerPainter` 需要处理各种类型的内容，例如：
    * 文本
    * 盒子模型 (背景、边框等)
    * 图片
    * 视频 (`LayoutVideo`)
    * Canvas (`HTMLCanvasElement`)
    * SVG 遮罩 (`SVGMaskPainter`)

6. **处理 CSS 视觉效果:** `PaintLayerPainter` 需要根据 CSS 属性来调整绘制行为，例如：
    * **透明度 (opacity):**  `PaintedOutputInvisible` 方法会检查 `opacity` 属性，如果透明度为 0，则可以跳过绘制。
    * **变换 (transform):**  `ContentsVisualRect` 方法会考虑变换对元素位置和大小的影响。
    * **滤镜 (filter, backdrop-filter):**  `PaintedOutputInvisible` 会考虑 `backdrop-filter`。
    * **裁剪路径 (clip-path):** 使用 `ClipPathClipper` 进行处理。
    * **遮罩 (mask):** 使用 `SVGMaskPainter` 或 `PaintWithPhase(PaintPhase::kMask, ...)` 进行处理。
    * **轮廓 (outline):**  在 `PaintWithPhase(PaintPhase::kSelfOutlineOnly, ...)` 中绘制。
    * **`will-change` 属性:** `PaintedOutputInvisible` 方法会检查 `will-change: opacity`，即使透明度很低也强制绘制，以优化动画性能。

7. **处理滚动 (Scrolling):**  `PaintLayerPainter` 与 `PaintLayerScrollableArea` 和 `ScrollableAreaPainter` 协同工作，处理滚动容器的绘制，包括滚动条等溢出控件。

8. **处理选中状态 (Selection):**  `Paint` 方法会检查 `PaintFlag::kSelectionDragImageOnly` 标志，以决定是否只绘制选中文本的拖动图像。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**  `PaintLayerPainter` 最终绘制的是由 HTML 结构构建的渲染树。它会处理 HTML 元素对应的 `LayoutObject`，例如 `<div>`, `<span>`, `<p>`, `<canvas>`, `<video>` 等。
    * **例子:** 当 HTML 中有一个 `<div style="background-color: blue;">Hello</div>` 时，`PaintLayerPainter` 会负责绘制这个蓝色背景的 `div` 元素。

* **CSS:** CSS 样式决定了 `PaintLayer` 的各种视觉属性，从而影响 `PaintLayerPainter` 的绘制行为。
    * **例子 (opacity):** 如果 CSS 为 `div { opacity: 0.5; }`，`PaintLayerPainter` 在绘制该 `div` 时会应用 50% 的透明度。`PaintedOutputInvisible` 方法会判断其是否小于 `kMinimumVisibleOpacity`，如果不是则会进行绘制。
    * **例子 (clip-path):** 如果 CSS 为 `div { clip-path: circle(50%); }`，`PaintLayerPainter` 会使用 `ClipPathClipper` 来裁剪 `div` 的绘制区域，使其变成圆形。
    * **例子 (transform):** 如果 CSS 为 `div { transform: translate(10px, 20px); }`，`PaintLayerPainter` 在绘制 `div` 的内容时，会将其平移 10 像素到右边，20 像素到下边。`ContentsVisualRect` 会考虑到这个变换。

* **JavaScript:** JavaScript 可以动态修改 HTML 结构和 CSS 样式，这些修改最终会触发重新布局和重绘，从而调用 `PaintLayerPainter` 来更新屏幕显示。
    * **例子:** JavaScript 代码 `document.getElementById('myDiv').style.backgroundColor = 'red';` 会修改 `div` 元素的背景色。浏览器会标记该 `div` 所在的 `PaintLayer` 为脏，并在下一次渲染时调用 `PaintLayerPainter` 重新绘制。
    * **例子:** JavaScript 创建动画效果，例如通过修改元素的 `opacity` 或 `transform` 属性，会导致浏览器不断调用 `PaintLayerPainter` 来更新动画的每一帧。

**逻辑推理的假设输入与输出:**

假设输入：一个 `PaintLayer` 对象，对应一个 HTML `<div>` 元素，其 CSS 样式为 `background-color: green; width: 100px; height: 50px;`，且该元素完全在视口内。

输出：`PaintLayerPainter` 的 `Paint` 方法会被调用，最终会调用 `PaintWithPhase(PaintPhase::kSelfBlockBackgroundOnly, ...)` 来绘制一个绿色的矩形，其位置和大小由布局信息决定（宽度 100px，高度 50px）。

假设输入：一个 `PaintLayer` 对象，对应一个 HTML `<img>` 元素，其 CSS 样式为 `opacity: 0;`。

输出：`PaintedOutputInvisible` 方法会返回 `true`，`PaintLayerPainter` 的 `Paint` 方法可能会提前返回，跳过大部分绘制操作，因为该元素是完全透明的。

**用户或编程常见的使用错误:**

1. **频繁触发重绘:**  在 JavaScript 中进行不必要的样式修改，例如在动画中使用 JavaScript 直接操作 `style` 属性，可能会导致浏览器频繁调用 `PaintLayerPainter` 进行重绘，影响性能。应该尽量使用 CSS 动画或 `requestAnimationFrame` 来优化动画。

2. **过度使用复杂的 CSS 效果:**  过度使用 `filter`, `clip-path`, `mask` 等复杂的 CSS 效果会增加 `PaintLayerPainter` 的绘制负担，可能导致性能下降。

3. **布局抖动 (Layout Thrashing):** JavaScript 代码中先读取元素的布局信息（例如 `offsetWidth`, `offsetHeight`），然后立即修改样式，会导致浏览器被迫进行同步布局和绘制，多次循环会严重影响性能。`PaintLayerPainter` 会被多次调用。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户发起操作:** 用户与网页进行交互，例如点击按钮、鼠标悬停、滚动页面、输入内容等。
2. **事件触发:** 用户的操作会触发相应的 DOM 事件（例如 `click`, `mouseover`, `scroll`, `input`）。
3. **JavaScript 处理:**  如果有 JavaScript 代码监听这些事件，相应的事件处理函数会被执行。
4. **DOM/CSSOM 修改:**  JavaScript 代码可能会修改 DOM 结构或 CSSOM (CSS 对象模型)，例如添加/删除元素、修改元素样式。
5. **样式计算 (Style Recalculation):** 浏览器会根据 DOM 和 CSSOM 的变化重新计算元素的样式。
6. **布局 (Layout):** 如果样式变化影响了元素的几何属性（例如位置、大小），浏览器会进行布局计算，确定元素在页面中的最终位置和大小。
7. **构建绘制树 (Paint Tree):**  浏览器会根据布局信息构建绘制树，`PaintLayer` 对象是绘制树的节点。
8. **绘制 (Paint):** 浏览器遍历绘制树，对于每个 `PaintLayer`，会创建或使用 `PaintLayerPainter` 对象来执行绘制操作。`PaintLayerPainter::Paint` 方法会被调用，传入相应的 `GraphicsContext` 和 `PaintFlags`。
9. **合成 (Compositing):** 如果使用了硬件加速，某些 `PaintLayer` 会被提升为合成层，由 GPU 进行合成。

**调试线索:**

当在调试过程中遇到与渲染相关的问题时，可以关注以下几点：

* **Performance 面板:**  使用 Chrome 开发者工具的 Performance 面板，可以查看帧率、渲染时间、绘制调用栈等信息，帮助定位性能瓶颈。
* **Layers 面板:**  Chrome 开发者工具的 Layers 面板可以查看页面的分层情况，了解哪些元素被提升为合成层，以及 `PaintLayer` 的结构。
* **Paint Flashing:**  在开发者工具的 Rendering 设置中启用 "Paint flashing"，可以高亮显示正在重绘的区域，帮助识别哪些元素触发了重绘。
* **断点调试:**  在 `paint_layer_painter.cc` 相关的代码中设置断点，可以跟踪绘制的执行流程，查看关键变量的值，例如 `cull_rect`, `visual_rect`, `paint_flags` 等。
* **日志输出:**  在 `PaintLayerPainter` 的关键方法中添加日志输出，记录绘制的参数和执行路径，帮助理解绘制过程。

总之，`blink/renderer/core/paint/paint_layer_painter.cc` 文件是 Blink 渲染引擎中负责将 `PaintLayer` 的视觉内容转化为屏幕像素的关键组件，它与 HTML 结构、CSS 样式以及 JavaScript 的动态操作紧密相关。理解其工作原理对于理解浏览器渲染过程和进行性能优化至关重要。

### 提示词
```
这是目录为blink/renderer/core/paint/paint_layer_painter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/paint_layer_painter.h"

#include <optional>

#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/core/layout/fragmentation_utils.h"
#include "third_party/blink/renderer/core/layout/layout_video.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/paint/box_fragment_painter.h"
#include "third_party/blink/renderer/core/paint/clip_path_clipper.h"
#include "third_party/blink/renderer/core/paint/fragment_data_iterator.h"
#include "third_party/blink/renderer/core/paint/inline_box_fragment_painter.h"
#include "third_party/blink/renderer/core/paint/object_paint_properties.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_paint_order_iterator.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/paint/scrollable_area_painter.h"
#include "third_party/blink/renderer/core/paint/svg_mask_painter.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing_detector.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"
#include "third_party/blink/renderer/platform/graphics/paint/geometry_mapper.h"
#include "third_party/blink/renderer/platform/graphics/paint/scoped_display_item_fragment.h"
#include "third_party/blink/renderer/platform/graphics/paint/scoped_effectively_invisible.h"
#include "third_party/blink/renderer/platform/graphics/paint/scoped_paint_chunk_properties.h"
#include "third_party/blink/renderer/platform/graphics/paint/subsequence_recorder.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "ui/gfx/geometry/point3_f.h"

namespace blink {

bool PaintLayerPainter::PaintedOutputInvisible(const ComputedStyle& style) {
  if (style.HasNonInitialBackdropFilter())
    return false;

  // Always paint when 'will-change: opacity' is present. Reduces jank for
  // common animation implementation approaches, for example, an element that
  // starts with opacity zero and later begins to animate.
  if (style.HasWillChangeOpacityHint())
    return false;

  if (style.HasCurrentOpacityAnimation())
    return false;

  // 0.0004f < 1/2048. With 10-bit color channels (only available on the
  // newest Macs; otherwise it's 8-bit), we see that an alpha of 1/2048 or
  // less leads to a color output of less than 0.5 in all channels, hence
  // not visible.
  static const float kMinimumVisibleOpacity = 0.0004f;
  if (style.Opacity() < kMinimumVisibleOpacity)
    return true;

  return false;
}

PhysicalRect PaintLayerPainter::ContentsVisualRect(const FragmentData& fragment,
                                                   const LayoutBox& box) {
  PhysicalRect contents_visual_rect = box.ContentsVisualOverflowRect();
  contents_visual_rect.Move(fragment.PaintOffset());
  const auto* replaced_transform =
      fragment.PaintProperties()
          ? fragment.PaintProperties()->ReplacedContentTransform()
          : nullptr;
  if (replaced_transform) {
    gfx::RectF float_contents_visual_rect(contents_visual_rect);
    GeometryMapper::SourceToDestinationRect(*replaced_transform->Parent(),
                                            *replaced_transform,
                                            float_contents_visual_rect);
    contents_visual_rect =
        PhysicalRect::EnclosingRect(float_contents_visual_rect);
  }
  return contents_visual_rect;
}

static bool ShouldCreateSubsequence(const PaintLayer& paint_layer,
                                    const GraphicsContext& context,
                                    PaintFlags paint_flags) {
  // Caching is not needed during printing or painting previews.
  if (paint_layer.GetLayoutObject().GetDocument().IsPrintingOrPaintingPreview())
    return false;

  if (context.GetPaintController().IsSkippingCache())
    return false;

  if (!paint_layer.SupportsSubsequenceCaching())
    return false;

  // Don't create subsequence during special painting to avoid cache conflict
  // with normal painting.
  if (paint_flags & PaintFlag::kOmitCompositingInfo)
    return false;

  return true;
}

static gfx::Rect FirstFragmentVisualRect(const LayoutBoxModelObject& object) {
  // We don't want to include overflowing contents.
  PhysicalRect overflow_rect =
      object.IsBox() ? To<LayoutBox>(object).SelfVisualOverflowRect()
                     : object.VisualOverflowRect();
  overflow_rect.Move(object.FirstFragment().PaintOffset());
  return ToEnclosingRect(overflow_rect);
}

PaintResult PaintLayerPainter::Paint(GraphicsContext& context,
                                     PaintFlags paint_flags) {
  const auto& object = paint_layer_.GetLayoutObject();
  if (object.NeedsLayout() && !object.ChildLayoutBlockedByDisplayLock())
      [[unlikely]] {
    // Skip if we need layout. This should never happen. See crbug.com/1423308
    // and crbug.com/330051489.
    return kFullyPainted;
  }

  if (object.GetFrameView()->ShouldThrottleRendering())
    return kFullyPainted;

  if (object.IsFragmentLessBox()) {
    return kFullyPainted;
  }

  // Non self-painting layers without self-painting descendants don't need to be
  // painted as their layoutObject() should properly paint itself.
  if (!paint_layer_.IsSelfPaintingLayer() &&
      !paint_layer_.HasSelfPaintingLayerDescendant())
    return kFullyPainted;

  if (auto* node = DynamicTo<Element>(object.GetNode())) {
    if (node->IsInCanvasSubtree() && !DynamicTo<HTMLCanvasElement>(node)) {
      // This prevents canvas fallback content from being rendered.
      return kFullyPainted;
    }
  }

  std::optional<CheckAncestorPositionVisibilityScope>
      check_position_visibility_scope;
  if (paint_layer_.InvisibleForPositionVisibility() ||
      paint_layer_.HasAncestorInvisibleForPositionVisibility()) {
    return kFullyPainted;
  }
  if (paint_layer_.GetLayoutObject().IsStackingContext()) {
    check_position_visibility_scope.emplace(paint_layer_);
  }

  // A paint layer should always have LocalBorderBoxProperties when it's ready
  // for paint.
  if (!object.FirstFragment().HasLocalBorderBoxProperties()) {
    // TODO(crbug.com/848056): This can happen e.g. when we paint a filter
    // referencing a SVG foreign object through feImage, especially when there
    // is circular references. Should find a better solution.
    return kMayBeClippedByCullRect;
  }

  bool selection_drag_image_only =
      paint_flags & PaintFlag::kSelectionDragImageOnly;
  if (selection_drag_image_only && !object.IsSelected())
    return kFullyPainted;

  IgnorePaintTimingScope ignore_paint_timing;
  if (object.StyleRef().Opacity() == 0.0f) {
    IgnorePaintTimingScope::IncrementIgnoreDepth();
  }
  // Explicitly compute opacity of documentElement, as it is special-cased in
  // Largest Contentful Paint.
  bool is_document_element_invisible = false;
  if (const auto* document_element = object.GetDocument().documentElement()) {
    if (document_element->GetLayoutObject() &&
        document_element->GetLayoutObject()->StyleRef().Opacity() == 0.0f) {
      is_document_element_invisible = true;
    }
  }
  IgnorePaintTimingScope::SetIsDocumentElementInvisible(
      is_document_element_invisible);

  bool is_self_painting_layer = paint_layer_.IsSelfPaintingLayer();
  bool should_paint_content =
      paint_layer_.HasVisibleContent() &&
      // Content under a LayoutSVGHiddenContainer is auxiliary resources for
      // painting. Foreign content should never paint in this situation, as it
      // is primary, not auxiliary.
      !paint_layer_.IsUnderSVGHiddenContainer() && is_self_painting_layer;

  PaintResult result = kFullyPainted;
  if (object.IsFragmented() ||
      // When printing, the LayoutView's background should extend infinitely
      // regardless of LayoutView's visual rect, so don't check intersection
      // between the visual rect and the cull rect (custom for each page).
      (IsA<LayoutView>(object) && object.GetDocument().Printing())) {
    result = kMayBeClippedByCullRect;
  } else {
    gfx::Rect visual_rect = FirstFragmentVisualRect(object);
    gfx::Rect cull_rect = object.FirstFragment().GetCullRect().Rect();
    bool cull_rect_intersects_self = cull_rect.Intersects(visual_rect);
    if (!cull_rect.Contains(visual_rect))
      result = kMayBeClippedByCullRect;

    bool cull_rect_intersects_contents = true;
    if (const auto* box = DynamicTo<LayoutBox>(object)) {
      PhysicalRect contents_visual_rect(
          ContentsVisualRect(object.FirstFragment(), *box));
      PhysicalRect contents_cull_rect(
          object.FirstFragment().GetContentsCullRect().Rect());
      cull_rect_intersects_contents =
          contents_cull_rect.Intersects(contents_visual_rect);
      if (!contents_cull_rect.Contains(contents_visual_rect))
        result = kMayBeClippedByCullRect;
    } else {
      cull_rect_intersects_contents = cull_rect_intersects_self;
    }

    if (!cull_rect_intersects_self && !cull_rect_intersects_contents) {
      if (paint_layer_.KnownToClipSubtreeToPaddingBox()) {
        paint_layer_.SetPreviousPaintResult(kMayBeClippedByCullRect);
        return kMayBeClippedByCullRect;
      }
      should_paint_content = false;
    }

    // The above doesn't consider clips on non-self-painting contents.
    // Will update in ScopedBoxContentsPaintState.
  }

  bool should_create_subsequence =
      should_paint_content &&
      ShouldCreateSubsequence(paint_layer_, context, paint_flags);
  std::optional<SubsequenceRecorder> subsequence_recorder;
  if (should_create_subsequence) {
    if (!paint_layer_.SelfOrDescendantNeedsRepaint() &&
        SubsequenceRecorder::UseCachedSubsequenceIfPossible(context,
                                                            paint_layer_)) {
      return paint_layer_.PreviousPaintResult();
    }
    DCHECK(paint_layer_.SupportsSubsequenceCaching());
    subsequence_recorder.emplace(context, paint_layer_);
  }

  std::optional<ScopedEffectivelyInvisible> effectively_invisible;
  if (PaintedOutputInvisible(object.StyleRef()))
    effectively_invisible.emplace(context.GetPaintController());

  std::optional<ScopedPaintChunkProperties> layer_chunk_properties;
  if (should_paint_content) {
    // If we will create a new paint chunk for this layer, this gives the chunk
    // a stable id.
    layer_chunk_properties.emplace(
        context.GetPaintController(),
        object.FirstFragment().LocalBorderBoxProperties(), paint_layer_,
        DisplayItem::kLayerChunk);
  }

  bool should_paint_background =
      should_paint_content && !selection_drag_image_only;
  if (should_paint_background) {
    PaintWithPhase(PaintPhase::kSelfBlockBackgroundOnly, context, paint_flags);
  }

  if (PaintChildren(kNegativeZOrderChildren, context, paint_flags) ==
      kMayBeClippedByCullRect)
    result = kMayBeClippedByCullRect;

  if (should_paint_content) {
    // If the negative-z-order children created paint chunks, this gives the
    // foreground paint chunk a stable id.
    ScopedPaintChunkProperties foreground_properties(
        context.GetPaintController(),
        object.FirstFragment().LocalBorderBoxProperties(), paint_layer_,
        DisplayItem::kLayerChunkForeground);

    if (selection_drag_image_only) {
      PaintWithPhase(PaintPhase::kSelectionDragImage, context, paint_flags);
    } else {
      PaintForegroundPhases(context, paint_flags);
    }
  }

  // Outline always needs to be painted even if we have no visible content.
  bool should_paint_self_outline =
      is_self_painting_layer && object.StyleRef().HasOutline();

  bool is_video = IsA<LayoutVideo>(object);
  if (!is_video && should_paint_self_outline)
    PaintWithPhase(PaintPhase::kSelfOutlineOnly, context, paint_flags);

  if (PaintChildren(kNormalFlowAndPositiveZOrderChildren, context,
                    paint_flags) == kMayBeClippedByCullRect)
    result = kMayBeClippedByCullRect;

  if (should_paint_content && paint_layer_.GetScrollableArea() &&
      paint_layer_.GetScrollableArea()
          ->ShouldOverflowControlsPaintAsOverlay()) {
    if (!paint_layer_.NeedsReorderOverlayOverflowControls())
      PaintOverlayOverflowControls(context, paint_flags);
    // Otherwise the overlay overflow controls will be painted after scrolling
    // children in PaintChildren().
  }
  // Overlay overflow controls of scrollers without a self-painting layer are
  // painted in the foreground paint phase. See ScrollableAreaPainter.

  if (is_video && should_paint_self_outline) {
    // We paint outlines for video later so that they aren't obscured by the
    // video controls.
    PaintWithPhase(PaintPhase::kSelfOutlineOnly, context, paint_flags);
  }

  if (should_paint_content && !selection_drag_image_only) {
    if (const auto* properties = object.FirstFragment().PaintProperties()) {
      if (properties->Mask()) {
        if (object.IsSVGForeignObject()) {
          SVGMaskPainter::Paint(context, object, object);
        } else {
          PaintWithPhase(PaintPhase::kMask, context, paint_flags);
        }
      }
      if (properties->ClipPathMask())
        ClipPathClipper::PaintClipPathAsMaskImage(context, object, object);
    }
  }

  paint_layer_.SetPreviousPaintResult(result);
  return result;
}

PaintResult PaintLayerPainter::PaintChildren(
    PaintLayerIteration children_to_visit,
    GraphicsContext& context,
    PaintFlags paint_flags) {
  PaintResult result = kFullyPainted;
  if (!paint_layer_.HasSelfPaintingLayerDescendant())
    return result;

  if (paint_layer_.GetLayoutObject().ChildPaintBlockedByDisplayLock())
    return result;

  PaintLayerPaintOrderIterator iterator(&paint_layer_, children_to_visit);
  while (PaintLayer* child = iterator.Next()) {
    if (child->IsReplacedNormalFlowStacking())
      continue;

    if (PaintLayerPainter(*child).Paint(context, paint_flags) ==
        kMayBeClippedByCullRect)
      result = kMayBeClippedByCullRect;

    if (const auto* layers_painting_overlay_overflow_controls_after =
            iterator.LayersPaintingOverlayOverflowControlsAfter(child)) {
      for (auto& reparent_overflow_controls_layer :
           *layers_painting_overlay_overflow_controls_after) {
        DCHECK(reparent_overflow_controls_layer
                   ->NeedsReorderOverlayOverflowControls());
        PaintLayerPainter(*reparent_overflow_controls_layer)
            .PaintOverlayOverflowControls(context, paint_flags);
        if (reparent_overflow_controls_layer->PreviousPaintResult() ==
            kMayBeClippedByCullRect) {
          result = kMayBeClippedByCullRect;
        }
      }
    }
  }

  return result;
}

void PaintLayerPainter::PaintOverlayOverflowControls(GraphicsContext& context,
                                                     PaintFlags paint_flags) {
  DCHECK(paint_layer_.GetScrollableArea());
  DCHECK(
      paint_layer_.GetScrollableArea()->ShouldOverflowControlsPaintAsOverlay());
  PaintWithPhase(PaintPhase::kOverlayOverflowControls, context, paint_flags);
}

void PaintLayerPainter::PaintFragmentWithPhase(
    PaintPhase phase,
    const FragmentData& fragment_data,
    wtf_size_t fragment_data_idx,
    const PhysicalBoxFragment* physical_fragment,
    GraphicsContext& context,
    PaintFlags paint_flags) {
  DCHECK(paint_layer_.IsSelfPaintingLayer() ||
         phase == PaintPhase::kOverlayOverflowControls);

  CullRect cull_rect = fragment_data.GetCullRect();
  if (cull_rect.Rect().IsEmpty())
    return;

  auto chunk_properties = fragment_data.LocalBorderBoxProperties();
  if (phase == PaintPhase::kMask) {
    const auto* properties = fragment_data.PaintProperties();
    DCHECK(properties);
    DCHECK(properties->Mask());
    DCHECK(properties->Mask()->OutputClip());
    chunk_properties.SetEffect(*properties->Mask());
    chunk_properties.SetClip(*properties->Mask()->OutputClip());
  }
  ScopedPaintChunkProperties fragment_paint_chunk_properties(
      context.GetPaintController(), chunk_properties, paint_layer_,
      DisplayItem::PaintPhaseToDrawingType(phase));

  PaintInfo paint_info(
      context, cull_rect, phase,
      paint_layer_.GetLayoutObject().ChildPaintBlockedByDisplayLock(),
      paint_flags);

  if (physical_fragment) {
    BoxFragmentPainter(*physical_fragment).Paint(paint_info);
  } else if (const auto* layout_inline =
                 DynamicTo<LayoutInline>(&paint_layer_.GetLayoutObject())) {
    InlineBoxFragmentPainter::PaintAllFragments(*layout_inline, fragment_data,
                                                fragment_data_idx, paint_info);
  } else {
    // We are about to enter legacy paint code. Set the right FragmentData
    // object, to use the right paint offset.
    paint_info.SetFragmentDataOverride(&fragment_data);
    paint_layer_.GetLayoutObject().Paint(paint_info);
  }
}

void PaintLayerPainter::PaintWithPhase(PaintPhase phase,
                                       GraphicsContext& context,
                                       PaintFlags paint_flags) {
  const auto* layout_box_with_fragments =
      paint_layer_.GetLayoutBoxWithBlockFragments();
  wtf_size_t fragment_idx = 0u;

  // The NG paint code guards against painting multiple fragments for content
  // that doesn't support it, but the legacy paint code has no such guards.
  // TODO(crbug.com/1229581): Remove this when everything is handled by NG.
  bool multiple_fragments_allowed =
      layout_box_with_fragments ||
      CanPaintMultipleFragments(paint_layer_.GetLayoutObject());

  for (const FragmentData& fragment :
       FragmentDataIterator(paint_layer_.GetLayoutObject())) {
    const PhysicalBoxFragment* physical_fragment = nullptr;
    if (layout_box_with_fragments) {
      physical_fragment =
          layout_box_with_fragments->GetPhysicalFragment(fragment_idx);
      DCHECK(physical_fragment);
    }

    std::optional<ScopedDisplayItemFragment> scoped_display_item_fragment;
    if (fragment_idx)
      scoped_display_item_fragment.emplace(context, fragment_idx);

    PaintFragmentWithPhase(phase, fragment, fragment_idx, physical_fragment,
                           context, paint_flags);

    if (!multiple_fragments_allowed)
      break;

    fragment_idx++;
  }
}

void PaintLayerPainter::PaintForegroundPhases(GraphicsContext& context,
                                              PaintFlags paint_flags) {
  PaintWithPhase(PaintPhase::kDescendantBlockBackgroundsOnly, context,
                 paint_flags);

  if (paint_layer_.GetLayoutObject().GetDocument().InForcedColorsMode()) {
    PaintWithPhase(PaintPhase::kForcedColorsModeBackplate, context,
                   paint_flags);
  }

  if (RuntimeEnabledFeatures::PaintUnderInvalidationCheckingEnabled() ||
      paint_layer_.NeedsPaintPhaseFloat()) {
    PaintWithPhase(PaintPhase::kFloat, context, paint_flags);
  }

  PaintWithPhase(PaintPhase::kForeground, context, paint_flags);

  if (RuntimeEnabledFeatures::PaintUnderInvalidationCheckingEnabled() ||
      paint_layer_.NeedsPaintPhaseDescendantOutlines()) {
    PaintWithPhase(PaintPhase::kDescendantOutlinesOnly, context, paint_flags);
  }
}

}  // namespace blink
```