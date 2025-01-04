Response:
Let's break down the thought process to generate the explanation for `inline_box_fragment_painter.cc`.

**1. Understanding the Core Purpose:**

The first step is to read the file and its comments to grasp its main responsibility. The filename itself is quite descriptive: `inline_box_fragment_painter`. This suggests it handles the painting of inline box fragments. The copyright notice and included headers confirm this is part of the Chromium rendering engine (Blink).

**2. Identifying Key Concepts and Relationships:**

As I read through the code, I start noting down important classes and concepts:

* **`InlineBoxFragmentPainter`:** The central class, responsible for painting.
* **`InlineBoxFragment`:**  Represents a fragment of an inline box. This is a key data structure the painter works with.
* **`FragmentItem`:**  An item within a fragment, likely representing a portion of the inline box.
* **`InlineCursor`:**  A cursor to iterate through inline items and fragments.
* **`PaintInfo`:**  Carries information about the current paint operation (phase, context, etc.).
* **`PaintPhase`:**  Different stages of painting (background, foreground, mask, etc.).
* **`GraphicsContext`:**  The object used for actual drawing.
* **`ComputedStyle`:**  Contains the CSS styles applied to the element.
* **`LayoutObject`:**  The layout representation of a DOM element.
* **`BoxFragmentPainter`:** A more general painter for box fragments, used internally.
* **`BoxBackgroundPaintContext`:**  Handles background painting details.
* **`NinePieceImagePainter`:** Used for painting border images and mask images.
* **`DisplayItem`:** Represents a recorded drawing operation for optimization.
* **`DrawingRecorder`:**  Used to record drawing operations for caching.

I also notice the inclusion of headers related to layout (`layout/...`), CSS properties (`css/properties/...`), and graphics (`platform/graphics/...`). This reinforces the idea that this code bridges layout and painting, using CSS styles to drive the drawing process.

**3. Deconstructing the `Paint()` Methods:**

The `Paint()` method is the core function. I analyze its different branches and actions based on the `PaintPhase`:

* **`PaintPhase::kMask`:**  Handles painting masks using `NinePieceImagePainter`.
* **`PaintPhase::kForeground` (non-SVG):** Paints background, borders, and shadows using `BoxBackgroundPaintContext` and `BoxFragmentPainter`.
* **`PaintPhase::kForeground` (SVG):** Sets up SVG-specific paint state.

This helps me understand the order and conditions under which different visual aspects are painted.

**4. Identifying Supporting Functions:**

I examine other methods like `PaintMask()`, `PaintBackgroundBorderShadow()`, `PaintBoxDecorationBackground()`, `PaintFillLayers()`, `PaintRectForImageStrip()`, etc. These provide more granular control over specific aspects of painting. For example, `PaintRectForImageStrip()` deals with background images that span multiple lines.

**5. Looking for Connections to Web Technologies (HTML, CSS, JavaScript):**

I actively search for how the code interacts with the web platform. Keywords like "background," "border," "mask," "visibility," and the inclusion of CSS property headers signal the strong connection to CSS. The mention of "LayoutObject" links it to the HTML structure (DOM). While this particular file doesn't directly interact with JavaScript, the rendering process as a whole is triggered by changes in the DOM or CSS, often caused by JavaScript actions.

**6. Inferring Logic and Potential Issues:**

I try to understand the "why" behind the code. For example, why is there a special handling for multi-line background images?  This leads to the understanding that the visual representation needs to be continuous even if the underlying HTML elements are broken across lines. I also look for potential edge cases or error conditions. The comment about `InlineCursor` and fragmented containers is a good example of an area where the current implementation might have limitations.

**7. Constructing Examples:**

To illustrate the connections to HTML, CSS, and potential issues, I create simple examples that would trigger the functionality in `inline_box_fragment_painter.cc`. These examples help solidify the understanding and make the explanation more concrete.

**8. Thinking About the Debugging Process:**

I consider how a developer might end up looking at this file during debugging. This involves thinking about the user actions that lead to specific visual outcomes. For instance, if a border isn't painting correctly on an inline element, a developer might trace the painting process and land in this file.

**9. Organizing and Refining the Explanation:**

Finally, I structure the information logically, starting with the main function and then delving into specifics. I use clear and concise language, avoiding overly technical jargon where possible. I also ensure I address all the points requested in the original prompt (functionality, relationships to web technologies, logic, potential errors, debugging). I review and refine the explanation for clarity and accuracy.

**Self-Correction/Refinement During the Process:**

* Initially, I might focus too much on the low-level graphics details. I then realize the prompt also asks for the *high-level* functionality and its connection to web technologies. So, I adjust my focus.
* I might initially miss some of the nuances, like the special handling of `::first-line` styles. A closer reading of the comments and code helps me identify these details.
* I might use overly technical terms. I then try to rephrase them in a way that's more accessible to someone with a general understanding of web development.

By following these steps, I can create a comprehensive and informative explanation of the `inline_box_fragment_painter.cc` file.
好的，让我们来详细分析 `blink/renderer/core/paint/inline_box_fragment_painter.cc` 这个文件的功能。

**文件功能概要**

`inline_box_fragment_painter.cc` 文件的主要职责是负责**绘制内联盒子的片段 (inline box fragments)**。在浏览器渲染引擎 Blink 中，当一个内联元素（如 `<span>`, `<a>` 等）跨越多行显示时，它会被分割成多个片段，每个片段被称为一个内联盒子片段。这个文件的作用就是处理这些片段的绘制工作，包括背景、边框、阴影、遮罩等视觉效果。

**与 JavaScript, HTML, CSS 的关系及举例说明**

这个文件与 HTML、CSS 的关系非常紧密，并且间接地受到 JavaScript 的影响，因为它负责将 CSS 样式应用到 HTML 元素上进行渲染。

* **HTML (结构):**
    *  `inline_box_fragment_painter.cc` 处理的是 HTML 中内联元素的渲染。当 HTML 结构中存在内联元素，并且这些元素由于宽度限制等原因被分割成多个片段时，这个文件就会被调用来绘制这些片段。
    * **例子:** 考虑以下 HTML 片段：
      ```html
      <p>This is a <span>very long inline text</span> that wraps to the next line.</p>
      ```
      `<span>` 元素中的文本如果太长，就会被分割成多个内联盒子片段，`inline_box_fragment_painter.cc` 负责绘制 `<span>` 元素在每一行上的片段。

* **CSS (样式):**
    *  这个文件直接读取和使用 CSS 属性来决定如何绘制内联盒子片段。例如，`background-color`, `border`, `box-shadow`, `mask` 等 CSS 属性都会影响这里的绘制逻辑。
    * **例子:**
        *  如果 CSS 中设置了 `span { background-color: red; }`，`inline_box_fragment_painter.cc` 中的代码会读取这个属性，并将相应的片段背景绘制成红色。
        *  如果设置了 `span { border: 1px solid black; }`，代码会绘制出黑色的边框。
        *  如果使用了 `mask-image` 等属性，`PaintMask` 函数会被调用来处理遮罩效果。

* **JavaScript (交互和动态修改):**
    *  虽然 `inline_box_fragment_painter.cc` 不直接执行 JavaScript 代码，但 JavaScript 可以动态地修改 HTML 结构和 CSS 样式。当 JavaScript 修改了影响内联元素布局或样式的属性时，会导致重新布局和重绘，最终会触发 `inline_box_fragment_painter.cc` 的执行。
    * **例子:**
      ```javascript
      const span = document.querySelector('span');
      span.style.backgroundColor = 'blue'; // 修改背景色
      span.textContent = 'An even longer text'; // 修改文本内容，可能导致换行
      ```
      这些 JavaScript 操作会触发浏览器重新渲染，`inline_box_fragment_painter.cc` 会使用新的样式和布局信息来绘制 `<span>` 元素的片段。

**逻辑推理 (假设输入与输出)**

假设输入是一个 `InlineBoxFragment` 对象，它包含了内联盒子片段的位置、尺寸和关联的样式信息，以及一个 `PaintInfo` 对象，描述了当前的绘制上下文和阶段。

* **假设输入:**
    * `InlineBoxFragment`: 代表 `<span>` 元素在某一行上的一个片段，例如：
        * 位置: `(10, 50)`
        * 尺寸: `(100, 20)`
        * 关联的 `ComputedStyle`: 包含 `background-color: yellow`, `border: 1px solid green` 等样式。
    * `PaintInfo`:  绘制阶段为 `PaintPhase::kForeground`，绘制上下文指向当前的图形设备。

* **逻辑推理:**
    1. `InlineBoxFragmentPainter::Paint` 方法会被调用。
    2. 由于 `paint_info.phase` 是 `PaintPhase::kForeground`，并且该片段不是 SVG，会进入绘制背景边框阴影的逻辑 `PaintBackgroundBorderShadow`。
    3. `PaintBackgroundBorderShadow` 方法会检查 visibility 和是否需要绘制背景装饰等条件。
    4. 如果需要绘制，会调用 `BoxBackgroundPaintContext` 来处理背景和边框的绘制。
    5. 根据 `ComputedStyle` 中的 `background-color: yellow`，会将该片段的背景填充为黄色。
    6. 根据 `ComputedStyle` 中的 `border: 1px solid green`，会绘制 1 像素宽的绿色实线边框。

* **输出:** 在屏幕上，`<span>` 元素在该行上的片段会显示为一个黄色的矩形，并带有绿色的边框。

**用户或编程常见的使用错误及举例说明**

* **CSS 属性错误:** 用户可能在 CSS 中设置了无效的属性值，导致绘制出现异常或与预期不符。
    * **例子:** `span { border-width: abc; }`  `abc` 不是一个有效的边框宽度值，浏览器可能会忽略这个属性，或者使用默认值，导致开发者疑惑边框为什么没有生效。
* **层叠顺序 (z-index) 错误:** 虽然 `inline_box_fragment_painter.cc` 主要负责内联元素的绘制，但错误的 `z-index` 设置可能导致内联元素被其他元素遮挡，给用户造成“没有绘制”的错觉。
    * **例子:**  如果一个内联元素的父元素设置了较低的 `z-index`，并且被一个 `z-index` 值更高的兄弟元素覆盖，那么内联元素的片段即使被正确绘制，也可能看不见。
* **遮罩属性使用不当:**  `mask-image` 等遮罩属性的使用较为复杂，如果参数设置错误，可能导致遮罩效果不正确，甚至元素完全不可见。
    * **例子:**  `span { mask-image: url('nonexistent.png'); }` 如果指定的遮罩图片不存在，可能导致元素无法正确显示。
* **误解内联元素的特性:**  有时开发者可能会误以为可以像块级元素一样直接设置内联元素的宽高，但内联元素的尺寸主要由内容决定。这与 `inline_box_fragment_painter.cc` 的工作有关，因为它根据内容的尺寸来绘制片段。

**用户操作如何一步步到达这里 (调试线索)**

假设用户在浏览器中访问一个网页，并注意到一个 `<span>` 元素的边框颜色显示不正确。作为开发者，为了调试这个问题，可能会经历以下步骤：

1. **打开开发者工具 (DevTools):** 按 F12 或右键点击网页选择“检查”。
2. **定位到目标元素:** 在“Elements”面板中找到那个 `<span>` 元素。
3. **查看 Computed 样式:** 在“Elements”面板的“Computed”选项卡中，查看该元素的最终计算样式，确认边框颜色是否如预期。
4. **查看 Styles 样式:** 在“Elements”面板的“Styles”选项卡中，查看该元素应用的 CSS 规则，检查是否有样式被覆盖或存在冲突。
5. **如果问题仍然存在，考虑渲染过程:**  开发者可能会开始怀疑是浏览器的渲染过程出现了问题。
6. **启用渲染相关的 DevTools 功能:**  在 Chrome DevTools 中，可以启用 "Rendering" 标签页，查看 "Paint flashing" 或 "Layer borders" 等选项，帮助理解页面的绘制情况。
7. **查找与绘制相关的代码:** 如果开发者需要深入了解渲染细节，可能会查看 Blink 引擎的源代码，搜索与内联元素绘制相关的代码，从而找到 `inline_box_fragment_painter.cc`。
8. **设置断点和日志:** 在 `inline_box_fragment_painter.cc` 中设置断点，查看 `PaintInfo`、`InlineBoxFragment` 和 `ComputedStyle` 的值，逐步跟踪绘制过程，分析为什么边框颜色不正确。
9. **分析调用栈:**  查看 `inline_box_fragment_painter.cc` 中函数的调用栈，了解是哪个上层模块触发了内联盒子片段的绘制。这有助于理解整个渲染流程。

总之，`inline_box_fragment_painter.cc` 是 Blink 渲染引擎中一个关键的组件，它负责将 CSS 样式转化为用户在屏幕上看到的内联元素的视觉效果。理解其功能有助于开发者诊断和解决与内联元素渲染相关的 Bug。

Prompt: 
```
这是目录为blink/renderer/core/paint/inline_box_fragment_painter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/inline_box_fragment_painter.h"

#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/layout/background_bleed_avoidance.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/logical_fragment.h"
#include "third_party/blink/renderer/core/paint/box_background_paint_context.h"
#include "third_party/blink/renderer/core/paint/nine_piece_image_painter.h"
#include "third_party/blink/renderer/core/paint/object_painter.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_phase.h"
#include "third_party/blink/renderer/core/paint/scoped_paint_state.h"
#include "third_party/blink/renderer/core/paint/scoped_svg_paint_state.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing_detector.h"
#include "third_party/blink/renderer/core/paint/url_metadata_utils.h"
#include "third_party/blink/renderer/core/style/nine_piece_image.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context_state_saver.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"
#include "third_party/blink/renderer/platform/graphics/paint/scoped_display_item_fragment.h"

namespace blink {

namespace {

template <class Items>
bool HasMultipleItems(const Items items) {
  auto iter = items.begin();
  DCHECK(iter != items.end());
  return iter != items.end() && ++iter != items.end();
}

inline bool MayHaveMultipleFragmentItems(const FragmentItem& item,
                                         const LayoutObject& layout_object) {
  if (!item.IsFirstForNode() || !item.IsLastForNode()) {
    return true;
  }
  // TODO(crbug.com/40122434): InlineCursor is currently unable to deal with
  // objects split into multiple fragmentainers (e.g. columns). Just return true
  // if it's possible that this object participates in a fragmentation context.
  // This will give false positives, but that should be harmless, given the way
  // the return value is used by the caller.
  if (layout_object.IsInsideFlowThread()) [[unlikely]] {
    return true;
  }
  return false;
}

}  // namespace

PhysicalBoxSides InlineBoxFragmentPainter::SidesToInclude() const {
  return BoxFragment().SidesToInclude();
}

void InlineBoxFragmentPainter::Paint(const PaintInfo& paint_info,
                                     const PhysicalOffset& paint_offset) {
  ScopedDisplayItemFragment display_item_fragment(
      paint_info.context, inline_box_item_.FragmentId());
  const LayoutObject& layout_object = *inline_box_fragment_.GetLayoutObject();
  std::optional<ScopedSVGPaintState> svg_paint_state;
  const PhysicalOffset adjusted_paint_offset =
      paint_offset + inline_box_item_.OffsetInContainerFragment();

  if (!layout_object.IsSVGInline()) {
    if (paint_info.phase == PaintPhase::kMask) {
      PaintMask(paint_info, adjusted_paint_offset);
      return;
    }
    if (paint_info.phase == PaintPhase::kForeground) {
      PaintBackgroundBorderShadow(paint_info, adjusted_paint_offset);
    }
  } else {
    svg_paint_state.emplace(layout_object, paint_info);
  }
  const bool suppress_box_decoration_background = true;
  DCHECK(inline_context_);
  InlinePaintContext::ScopedInlineItem scoped_item(inline_box_item_,
                                                   inline_context_);
  DCHECK(inline_box_cursor_);
  BoxFragmentPainter box_painter(*inline_box_cursor_, inline_box_item_,
                                 BoxFragment(), inline_context_);
  box_painter.PaintObject(paint_info, adjusted_paint_offset,
                          suppress_box_decoration_background);
}

void InlineBoxFragmentPainter::PaintMask(const PaintInfo& paint_info,
                                         const PhysicalOffset& paint_offset) {
  DCHECK_EQ(PaintPhase::kMask, paint_info.phase);
  if (!style_.HasMask() || style_.Visibility() != EVisibility::kVisible) {
    return;
  }

  const DisplayItemClient& display_item_client = GetDisplayItemClient();
  if (DrawingRecorder::UseCachedDrawingIfPossible(
          paint_info.context, display_item_client, paint_info.phase)) {
    return;
  }

  DrawingRecorder recorder(paint_info.context, display_item_client,
                           paint_info.phase, VisualRect(paint_offset));
  PhysicalRect adjusted_frame_rect(paint_offset,
                                   inline_box_fragment_.LocalRect().size);

  const LayoutObject& layout_object = *inline_box_fragment_.GetLayoutObject();
  bool object_may_have_multiple_boxes =
      MayHaveMultipleFragmentItems(inline_box_item_, layout_object);

  DCHECK(inline_box_cursor_);
  BoxFragmentPainter box_painter(*inline_box_cursor_, inline_box_item_,
                                 BoxFragment(), inline_context_);

  BoxBackgroundPaintContext bg_paint_context(
      static_cast<const LayoutBoxModelObject&>(layout_object));
  PaintFillLayers(box_painter, paint_info, Color::kTransparent,
                  style_.MaskLayers(), adjusted_frame_rect, bg_paint_context,
                  object_may_have_multiple_boxes);

  gfx::Rect adjusted_clip_rect;
  SlicePaintingType border_painting_type =
      GetSlicePaintType(style_.MaskBoxImage(), adjusted_frame_rect,
                        adjusted_clip_rect, object_may_have_multiple_boxes);
  if (border_painting_type == kDontPaint) {
    return;
  }
  GraphicsContextStateSaver state_saver(paint_info.context, false);
  PhysicalRect adjusted_paint_rect;
  if (border_painting_type == kPaintWithClip) {
    state_saver.Save();
    paint_info.context.Clip(adjusted_clip_rect);
    adjusted_paint_rect =
        PaintRectForImageStrip(adjusted_frame_rect, style_.Direction());
  } else {
    adjusted_paint_rect = adjusted_frame_rect;
  }
  NinePieceImagePainter::Paint(paint_info.context, image_observer_, *document_,
                               node_, adjusted_paint_rect, style_,
                               style_.MaskBoxImage(), SidesToInclude());
}

void InlineBoxFragmentPainterBase::PaintBackgroundBorderShadow(
    const PaintInfo& paint_info,
    const PhysicalOffset& paint_offset) {
  DCHECK(paint_info.phase == PaintPhase::kForeground);
  if (inline_box_fragment_.Style().Visibility() != EVisibility::kVisible ||
      inline_box_fragment_.IsOpaque()) {
    return;
  }

  // You can use p::first-line to specify a background. If so, the direct child
  // inline boxes of line boxes may actually have to paint a background.
  // TODO(layout-dev): Cache HasBoxDecorationBackground on the fragment like
  // we do for LayoutObject. Querying Style each time is too costly.
  bool should_paint_box_decoration_background =
      inline_box_fragment_.GetLayoutObject()->HasBoxDecorationBackground() ||
      inline_box_fragment_.UsesFirstLineStyle();

  if (!should_paint_box_decoration_background)
    return;

  const DisplayItemClient& display_item_client = GetDisplayItemClient();
  if (DrawingRecorder::UseCachedDrawingIfPossible(
          paint_info.context, display_item_client,
          DisplayItem::kBoxDecorationBackground))
    return;

  PhysicalRect frame_rect = inline_box_fragment_.LocalRect();
  PhysicalRect adjusted_frame_rect(paint_offset, frame_rect.size);

  DrawingRecorder recorder(paint_info.context, display_item_client,
                           DisplayItem::kBoxDecorationBackground,
                           VisualRect(paint_offset));

  DCHECK(inline_box_fragment_.GetLayoutObject());
  const LayoutObject& layout_object = *inline_box_fragment_.GetLayoutObject();
  bool object_may_have_multiple_boxes =
      MayHaveMultipleFragmentItems(inline_box_item_, layout_object);

  DCHECK(inline_box_cursor_);
  DCHECK(inline_context_);
  BoxFragmentPainter box_painter(*inline_box_cursor_, inline_box_item_,
                                 To<PhysicalBoxFragment>(inline_box_fragment_),
                                 inline_context_);
  // TODO(eae): Switch to LayoutNG version of BoxBackgroundPaintContext.
  BoxBackgroundPaintContext bg_paint_context(
      *static_cast<const LayoutBoxModelObject*>(
          inline_box_fragment_.GetLayoutObject()));
  PaintBoxDecorationBackground(
      box_painter, paint_info, paint_offset, adjusted_frame_rect,
      bg_paint_context, object_may_have_multiple_boxes, SidesToInclude());
}

gfx::Rect InlineBoxFragmentPainterBase::VisualRect(
    const PhysicalOffset& paint_offset) {
  PhysicalRect overflow_rect = inline_box_item_.SelfInkOverflowRect();
  overflow_rect.Move(paint_offset);
  return ToEnclosingRect(overflow_rect);
}

void LineBoxFragmentPainter::PaintBackgroundBorderShadow(
    const PaintInfo& paint_info,
    const PhysicalOffset& paint_offset) {
  DCHECK_EQ(paint_info.phase, PaintPhase::kForeground);
  DCHECK_EQ(inline_box_fragment_.Type(), PhysicalFragment::kFragmentLineBox);
  DCHECK(NeedsPaint(inline_box_fragment_));
  // |FragmentItem| uses the fragment id when painting the background of
  // line boxes. Please see |FragmentItem::kInitialLineFragmentId|.
  DCHECK_NE(paint_info.context.GetPaintController().CurrentFragment(), 0u);

  if (line_style_ == style_ ||
      line_style_.Visibility() != EVisibility::kVisible) {
    return;
  }

  const DisplayItemClient& display_item_client = GetDisplayItemClient();
  if (DrawingRecorder::UseCachedDrawingIfPossible(
          paint_info.context, display_item_client,
          DisplayItem::kBoxDecorationBackground))
    return;

  // Compute the content box for the `::first-line` box. It's different from
  // fragment size because the height of line box includes `line-height` while
  // the height of inline box does not. The box "behaves similar to that of an
  // inline-level element".
  // https://drafts.csswg.org/css-pseudo-4/#first-line-styling
  const PhysicalLineBoxFragment& line_box = LineBoxFragment();
  const FontHeight line_metrics = line_box.Metrics();
  const FontHeight text_metrics = line_style_.GetFontHeight();
  const WritingMode writing_mode = line_style_.GetWritingMode();
  PhysicalRect rect;
  if (IsHorizontalWritingMode(writing_mode)) {
    rect.offset.top = line_metrics.ascent - text_metrics.ascent;
    rect.size = {line_box.Size().width, text_metrics.LineHeight()};
  } else {
    rect.offset.left =
        line_box.Size().width - line_metrics.ascent - text_metrics.descent;
    rect.size = {text_metrics.LineHeight(), line_box.Size().height};
  }
  rect.offset += paint_offset;

  DrawingRecorder recorder(paint_info.context, display_item_client,
                           DisplayItem::kBoxDecorationBackground,
                           VisualRect(paint_offset));

  const LayoutBlockFlow& layout_block_flow =
      *To<LayoutBlockFlow>(block_fragment_.GetLayoutObject());
  BoxFragmentPainter box_painter(block_fragment_);
  BoxBackgroundPaintContext bg_paint_context(layout_block_flow);
  PaintBoxDecorationBackground(
      box_painter, paint_info, paint_offset, rect, bg_paint_context,
      /*object_has_multiple_boxes*/ false, PhysicalBoxSides());
}

void InlineBoxFragmentPainterBase::ComputeFragmentOffsetOnLine(
    TextDirection direction,
    LayoutUnit* offset_on_line,
    LayoutUnit* total_width) const {
  WritingDirectionMode writing_direction =
      inline_box_fragment_.Style().GetWritingDirection();
  InlineCursor cursor;
  DCHECK(inline_box_fragment_.GetLayoutObject());
  cursor.MoveTo(*inline_box_fragment_.GetLayoutObject());

  LayoutUnit before;
  LayoutUnit after;
  bool before_self = true;
  for (; cursor; cursor.MoveToNextForSameLayoutObject()) {
    DCHECK(cursor.CurrentItem());
    if (cursor.CurrentItem() == &inline_box_item_) {
      before_self = false;
      continue;
    }
    const PhysicalBoxFragment* box_fragment = cursor.Current().BoxFragment();
    DCHECK(box_fragment);
    if (before_self)
      before += LogicalFragment(writing_direction, *box_fragment).InlineSize();
    else
      after += LogicalFragment(writing_direction, *box_fragment).InlineSize();
  }

  *total_width =
      before + after +
      LogicalFragment(writing_direction, inline_box_fragment_).InlineSize();

  // We're iterating over the fragments in physical order before so we need to
  // swap before and after for RTL.
  *offset_on_line = direction == TextDirection::kLtr ? before : after;
}

PhysicalRect InlineBoxFragmentPainterBase::PaintRectForImageStrip(
    const PhysicalRect& paint_rect,
    TextDirection direction) const {
  // We have a fill/border/mask image that spans multiple lines.
  // We need to adjust the offset by the width of all previous lines.
  // Think of background painting on inlines as though you had one long line, a
  // single continuous strip. Even though that strip has been broken up across
  // multiple lines, you still paint it as though you had one single line. This
  // means each line has to pick up the background where the previous line left
  // off.
  LayoutUnit offset_on_line;
  LayoutUnit total_width;
  ComputeFragmentOffsetOnLine(direction, &offset_on_line, &total_width);

  if (inline_box_fragment_.Style().IsHorizontalWritingMode()) {
    return PhysicalRect(paint_rect.X() - offset_on_line, paint_rect.Y(),
                        total_width, paint_rect.Height());
  }
  return PhysicalRect(paint_rect.X(), paint_rect.Y() - offset_on_line,
                      paint_rect.Width(), total_width);
}

PhysicalRect InlineBoxFragmentPainterBase::ClipRectForNinePieceImageStrip(
    const ComputedStyle& style,
    PhysicalBoxSides sides_to_include,
    const NinePieceImage& image,
    const PhysicalRect& paint_rect) {
  PhysicalRect clip_rect(paint_rect);
  PhysicalBoxStrut outsets = style.ImageOutsets(image);
  if (sides_to_include.left) {
    clip_rect.SetX(paint_rect.X() - outsets.left);
    clip_rect.SetWidth(paint_rect.Width() + outsets.left);
  }
  if (sides_to_include.right) {
    clip_rect.SetWidth(clip_rect.Width() + outsets.right);
  }
  if (sides_to_include.top) {
    clip_rect.SetY(paint_rect.Y() - outsets.top);
    clip_rect.SetHeight(paint_rect.Height() + outsets.top);
  }
  if (sides_to_include.bottom) {
    clip_rect.SetHeight(clip_rect.Height() + outsets.bottom);
  }
  return clip_rect;
}

InlineBoxFragmentPainterBase::SlicePaintingType
InlineBoxFragmentPainterBase::GetBorderPaintType(
    const PhysicalRect& adjusted_frame_rect,
    gfx::Rect& adjusted_clip_rect,
    bool object_has_multiple_boxes) const {
  const ComputedStyle& style = inline_box_fragment_.Style();
  if (!style.HasBorderDecoration()) {
    return kDontPaint;
  }
  return GetSlicePaintType(style.BorderImage(), adjusted_frame_rect,
                           adjusted_clip_rect, object_has_multiple_boxes);
}

InlineBoxFragmentPainterBase::SlicePaintingType
InlineBoxFragmentPainterBase::GetSlicePaintType(
    const NinePieceImage& nine_piece_image,
    const PhysicalRect& adjusted_frame_rect,
    gfx::Rect& adjusted_clip_rect,
    bool object_has_multiple_boxes) const {
  StyleImage* nine_piece_image_source = nine_piece_image.GetImage();
  bool has_nine_piece_image =
      nine_piece_image_source && nine_piece_image_source->CanRender();
  if (has_nine_piece_image && !nine_piece_image_source->IsLoaded()) {
    return kDontPaint;
  }

  // The simple case is where we either have no border image or we are the
  // only box for this object.  In those cases only a single call to draw is
  // required.
  const ComputedStyle& style = inline_box_fragment_.Style();
  if (!has_nine_piece_image || !object_has_multiple_boxes ||
      style.BoxDecorationBreak() == EBoxDecorationBreak::kClone) {
    adjusted_clip_rect = ToPixelSnappedRect(adjusted_frame_rect);
    return kPaintWithoutClip;
  }

  // We have a border image that spans multiple lines.
  adjusted_clip_rect = ToPixelSnappedRect(ClipRectForNinePieceImageStrip(
      style, SidesToInclude(), nine_piece_image, adjusted_frame_rect));
  return kPaintWithClip;
}

void InlineBoxFragmentPainterBase::PaintNormalBoxShadow(
    const PaintInfo& info,
    const ComputedStyle& s,
    const PhysicalRect& paint_rect) {
  BoxPainterBase::PaintNormalBoxShadow(info, paint_rect, s, SidesToInclude());
}

void InlineBoxFragmentPainterBase::PaintInsetBoxShadow(
    const PaintInfo& info,
    const ComputedStyle& s,
    const PhysicalRect& paint_rect) {
  BoxPainterBase::PaintInsetBoxShadowWithBorderRect(info, paint_rect, s,
                                                    SidesToInclude());
}

void InlineBoxFragmentPainterBase::PaintBoxDecorationBackground(
    BoxPainterBase& box_painter,
    const PaintInfo& paint_info,
    const PhysicalOffset& paint_offset,
    const PhysicalRect& adjusted_frame_rect,
    const BoxBackgroundPaintContext& bg_paint_context,
    bool object_has_multiple_boxes,
    PhysicalBoxSides sides_to_include) {
  // Shadow comes first and is behind the background and border.
  PaintNormalBoxShadow(paint_info, line_style_, adjusted_frame_rect);

  Color background_color =
      line_style_.VisitedDependentColor(GetCSSPropertyBackgroundColor());
  PaintFillLayers(box_painter, paint_info, background_color,
                  line_style_.BackgroundLayers(), adjusted_frame_rect,
                  bg_paint_context, object_has_multiple_boxes);

  PaintInsetBoxShadow(paint_info, line_style_, adjusted_frame_rect);

  gfx::Rect adjusted_clip_rect;
  SlicePaintingType border_painting_type = GetBorderPaintType(
      adjusted_frame_rect, adjusted_clip_rect, object_has_multiple_boxes);
  switch (border_painting_type) {
    case kDontPaint:
      break;
    case kPaintWithoutClip:
      BoxPainterBase::PaintBorder(image_observer_, *document_, node_,
                                  paint_info, adjusted_frame_rect, line_style_,
                                  kBackgroundBleedNone, sides_to_include);
      break;
    case kPaintWithClip:
      // FIXME: What the heck do we do with RTL here? The math we're using is
      // obviously not right, but it isn't even clear how this should work at
      // all.
      PhysicalRect image_strip_paint_rect =
          PaintRectForImageStrip(adjusted_frame_rect, TextDirection::kLtr);
      GraphicsContextStateSaver state_saver(paint_info.context);
      paint_info.context.Clip(adjusted_clip_rect);
      BoxPainterBase::PaintBorder(image_observer_, *document_, node_,
                                  paint_info, image_strip_paint_rect,
                                  line_style_);
      break;
  }
}

void InlineBoxFragmentPainterBase::PaintFillLayers(
    BoxPainterBase& box_painter,
    const PaintInfo& info,
    const Color& c,
    const FillLayer& layer,
    const PhysicalRect& rect,
    const BoxBackgroundPaintContext& bg_paint_context,
    bool object_has_multiple_boxes) {
  // FIXME: This should be a for loop or similar. It's a little non-trivial to
  // do so, however, since the layers need to be painted in reverse order.
  if (layer.Next()) {
    PaintFillLayers(box_painter, info, c, *layer.Next(), rect, bg_paint_context,
                    object_has_multiple_boxes);
  }
  PaintFillLayer(box_painter, info, c, layer, rect, bg_paint_context,
                 object_has_multiple_boxes);
}

void InlineBoxFragmentPainterBase::PaintFillLayer(
    BoxPainterBase& box_painter,
    const PaintInfo& paint_info,
    const Color& c,
    const FillLayer& fill_layer,
    const PhysicalRect& paint_rect,
    const BoxBackgroundPaintContext& bg_paint_context,
    bool object_has_multiple_boxes) {
  StyleImage* img = fill_layer.GetImage();
  bool has_fill_image = img && img->CanRender();

  if (!object_has_multiple_boxes ||
      (!has_fill_image && !style_.HasBorderRadius())) {
    box_painter.PaintFillLayer(paint_info, c, fill_layer, paint_rect,
                               kBackgroundBleedNone, bg_paint_context, false);
    return;
  }

  // Handle fill images that clone or spans multiple lines.
  bool multi_line = object_has_multiple_boxes &&
                    style_.BoxDecorationBreak() != EBoxDecorationBreak::kClone;
  PhysicalRect rect =
      multi_line ? PaintRectForImageStrip(paint_rect, style_.Direction())
                 : paint_rect;
  GraphicsContextStateSaver state_saver(paint_info.context);
  paint_info.context.Clip(ToPixelSnappedRect(paint_rect));
  box_painter.PaintFillLayer(paint_info, c, fill_layer, rect,
                             kBackgroundBleedNone, bg_paint_context, multi_line,
                             paint_rect.size);
}

// Paint all fragments for the |layout_inline|. This function is used only for
// self-painting |LayoutInline|.
void InlineBoxFragmentPainter::PaintAllFragments(
    const LayoutInline& layout_inline,
    const FragmentData& fragment_data,
    wtf_size_t fragment_data_idx,
    const PaintInfo& paint_info) {
  // TODO(kojii): If the block flow is dirty, children of these fragments
  // maybe already deleted. crbug.com/963103
  const LayoutBlockFlow* block_flow = layout_inline.FragmentItemsContainer();
  if (block_flow->NeedsLayout()) [[unlikely]] {
    return;
  }

  ScopedPaintState paint_state(layout_inline, paint_info, &fragment_data);
  PhysicalOffset paint_offset = paint_state.PaintOffset();
  const PaintInfo& local_paint_info = paint_state.GetPaintInfo();

  if (local_paint_info.phase == PaintPhase::kForeground &&
      local_paint_info.ShouldAddUrlMetadata()) {
    ObjectPainter(layout_inline)
        .AddURLRectIfNeeded(local_paint_info, paint_offset);
  }

  ScopedPaintTimingDetectorBlockPaintHook
      scoped_paint_timing_detector_block_paint_hook;
  if (paint_info.phase == PaintPhase::kForeground) {
    scoped_paint_timing_detector_block_paint_hook.EmplaceIfNeeded(
        layout_inline,
        paint_info.context.GetPaintController().CurrentPaintChunkProperties());
  }

  if (paint_info.phase == PaintPhase::kForeground &&
      paint_info.ShouldAddUrlMetadata()) {
    // URLRects for descendants are normally added via BoxFragmentPainter::
    // PaintLineBoxes(), but relatively positioned (self-painting) inlines
    // are omitted. Do it now.
    AddURLRectsForInlineChildrenRecursively(layout_inline, paint_info,
                                            paint_offset);
  }

  InlinePaintContext inline_context;
  InlineCursor first_container_cursor(*block_flow);
  first_container_cursor.MoveTo(layout_inline);

  wtf_size_t container_fragment_idx =
      first_container_cursor.ContainerFragmentIndex() + fragment_data_idx;
  const PhysicalBoxFragment* container_fragment = nullptr;
  if (block_flow->MayBeNonContiguousIfc()) {
    // Skip over [*] container fragments with no items (it's likely that there
    // are such container fragments here, since the container has been marked as
    // potentially non-contiguous). This LayoutInline isn't represented in
    // container fragments with no items.
    //
    // [*] except leading item-less container fragments. The inline cursor has
    // already been moved past them, and thus baked into
    // `container_fragment_idx`.
    wtf_size_t idx = 0;
    bool found_items = false;
    for (const PhysicalBoxFragment& candidate :
         block_flow->PhysicalFragments()) {
      if (candidate.HasItems()) {
        found_items = true;
      } else if (found_items) {
        continue;
      }
      if (idx++ == container_fragment_idx) {
        container_fragment = &candidate;
        break;
      }
    }
    DCHECK(container_fragment);
  } else {
    container_fragment =
        block_flow->GetPhysicalFragment(container_fragment_idx);
  }

  InlineCursor cursor(*container_fragment);
  cursor.MoveTo(layout_inline);
  for (; cursor; cursor.MoveToNextForSameLayoutObject()) {
    InlinePaintContext::ScopedInlineBoxAncestors scoped_items(cursor,
                                                              &inline_context);
    const FragmentItem* item = cursor.CurrentItem();
    DCHECK(item);
    const PhysicalBoxFragment* box_fragment = item->BoxFragment();
    DCHECK(box_fragment);
    InlineBoxFragmentPainter(cursor, *item, *box_fragment, &inline_context)
        .Paint(paint_info, paint_offset);
  }
}

#if DCHECK_IS_ON()
void InlineBoxFragmentPainter::CheckValid() const {
  DCHECK(inline_box_cursor_);
  DCHECK_EQ(inline_box_cursor_->Current().Item(), &inline_box_item_);

  DCHECK(inline_box_fragment_.IsInlineBox());
}
#endif

}  // namespace blink

"""

```