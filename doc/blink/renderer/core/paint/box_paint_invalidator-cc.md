Response:
Let's break down the thought process for analyzing the provided C++ code and generating the explanation.

**1. Understanding the Goal:**

The request asks for an explanation of the `BoxPaintInvalidator` class in Chromium's Blink rendering engine, focusing on its functionality, relationships to web technologies (HTML, CSS, JavaScript), logical reasoning, potential usage errors, and debugging tips.

**2. Initial Code Scan and Keyword Identification:**

First, I'd quickly scan the code looking for keywords and patterns that hint at the class's purpose. Keywords like "Invalidate," "Paint," "Background," "Size," "Overflow," "Style," and "Layout" stand out. The class name itself, `BoxPaintInvalidator`, strongly suggests its responsibility is to determine when and how to invalidate the painting of a box (likely a layout box).

**3. Deeper Dive into Key Methods:**

Next, I would examine the key methods in more detail:

* **`ComputePaintInvalidationReason()`:** This looks central to determining *why* a repaint is needed. The logic involves comparing previous and current states (size, overflow, etc.) and considering style properties. The use of `ObjectPaintInvalidatorWithContext` suggests delegation to another class for part of the invalidation logic.
* **`ComputeBackgroundInvalidation()` and `ComputeViewBackgroundInvalidation()`:** These specifically address background repainting, considering factors like attachment (fixed, local), size changes, and scrollable overflow. The distinction between `Full` and `Incremental` invalidation is important.
* **`InvalidateBackground()` and `InvalidatePaint()`:** These methods execute the invalidation process. `InvalidateBackground()` handles background-specific invalidation, and `InvalidatePaint()` calls `InvalidateBackground()` and then delegates further invalidation.
* **`ShouldFullyInvalidateFillLayersOnWidthChange()`, `ShouldFullyInvalidateFillLayersOnHeightChange()`, `ShouldFullyInvalidateFillLayersOnSizeChange()`:** These helper functions analyze background image properties to decide if a size change necessitates a full repaint. The focus on `repeat`, `position`, and `size` properties of background images is key here.
* **`NeedsToSavePreviousContentBoxRect()` and `NeedsToSavePreviousOverflowData()`:** These methods indicate that the class maintains previous state for comparison, essential for incremental invalidation.
* **`SavePreviousBoxGeometriesIfNeeded()`:** This method updates the stored previous state.

**4. Identifying Relationships with Web Technologies:**

With an understanding of the core functionality, I'd connect it to web technologies:

* **CSS:** The code heavily relies on `ComputedStyle` and its properties (background, mask, border, etc.). The analysis of background image properties directly relates to CSS background properties.
* **HTML:**  The code interacts with `LayoutView`, `LayoutBox`, and `LayoutReplaced`, which represent HTML elements. The concept of the root element and document element is also present.
* **JavaScript:** While this specific C++ file doesn't directly interact with JavaScript, the *consequences* of its actions are visible to JavaScript. When content changes or styles are modified via JavaScript, this code determines how the browser repaints.

**5. Inferring Logic and Providing Examples:**

Based on the code, I'd try to deduce the logic and create illustrative examples:

* **Incremental vs. Full Invalidation:**  The code clearly distinguishes between these. I'd create scenarios where a simple size change might lead to incremental invalidation, while more complex changes (like background image properties or visual overflow) trigger a full repaint.
* **Background Invalidation based on Attachment:** The code explicitly checks for `local` and `fixed` background attachments. I'd explain how scrolling affects these differently and why it might trigger invalidation.
* **Content Box vs. Border Box:**  The code mentions background and mask layers using the content box. I'd explain this distinction and how changes in content size can trigger repaints.

**6. Considering User/Developer Errors and Debugging:**

I would then think about potential mistakes and how a developer might end up in this part of the code during debugging:

* **Excessive Repaints:**  Developers often encounter performance issues due to unnecessary repaints. Understanding the invalidation logic helps diagnose these issues.
* **Unexpected Background Behavior:**  Incorrectly specified background properties can lead to unexpected repaint behavior when the element or its container changes size or scrolls.
* **Debugging Tools:** I'd mention using browser developer tools to identify repainted areas.

**7. Structuring the Explanation:**

Finally, I would organize the information logically, using clear headings and examples:

* Start with a high-level overview of the class's purpose.
* Break down the functionality into key areas (paint invalidation reason, background invalidation).
* Provide specific examples linking the code to HTML, CSS, and JavaScript.
* Explain the logical reasoning with input/output scenarios.
* Discuss potential errors and debugging strategies.
* Summarize the user interaction flow leading to this code.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus heavily on the individual methods in isolation.
* **Correction:** Realize the importance of explaining how the methods *interact* and contribute to the overall goal of paint invalidation.
* **Initial thought:** Provide very technical code-level explanations.
* **Correction:**  Balance technical details with explanations that are understandable to someone familiar with web development concepts but not necessarily deeply familiar with the Blink rendering engine. Use analogies and simpler terms where possible.
* **Initial thought:**  Focus only on the "what."
* **Correction:**  Emphasize the "why" behind the code's logic and its implications for web page performance and rendering behavior.

By following this iterative process of scanning, deeper analysis, connection to web technologies, example creation, error consideration, and structured explanation, I can arrive at a comprehensive and helpful answer like the example provided in the prompt.
这是 Chromium Blink 渲染引擎中 `blink/renderer/core/paint/box_paint_invalidator.cc` 文件的功能列表和详细说明：

**核心功能：确定何时以及如何使一个盒模型（LayoutBox）的绘制失效（需要重绘）。**

该文件的主要职责是判断在盒模型的属性或状态发生变化时，是否需要触发重绘，以及重绘的范围和方式（例如，是全量重绘还是增量重绘）。它考虑了多种因素，包括盒模型的尺寸、位置、样式属性以及其子树的状态。

**具体功能点:**

1. **计算绘制失效的原因 (`ComputePaintInvalidationReason`)**:
   - 接收一个 `LayoutBox` 对象和一个上下文 (`PaintInvalidatorContext`) 作为输入。
   - 调用 `ObjectPaintInvalidatorWithContext` 来获取初步的失效原因。
   - 考虑布局相关的变化（例如，内容盒子的尺寸变化，对于 `LayoutReplaced` 元素的内容区域变化）。
   - 检查盒模型的尺寸和可视溢出区域是否发生变化。
   - 考虑样式属性的变化，例如 `mask-image` 使用 `content-box` 定位，并且内容盒子尺寸发生了变化。
   - 考虑是否有视觉溢出效果、外观效果、滤镜效果、遮罩、裁剪路径等影响绘制的属性。
   - 考虑边框半径和边框图像。
   - 区分全量绘制失效和增量绘制失效。

   **逻辑推理示例：**
   - **假设输入：** 一个 `div` 元素的 `LayoutBox` 对象，其文本内容发生变化，导致内容盒子的宽度增加。
   - **输出：** `PaintInvalidationReason::kLayout` （因为内容尺寸变化影响布局和绘制）。

2. **处理背景绘制失效 (`InvalidateBackground`, `ComputeBackgroundInvalidation`, `ComputeViewBackgroundInvalidation`)**:
   - **确定背景是否有效 (`HasEffectiveBackground`)**: 判断盒模型是否应该绘制背景（例如，`LayoutView` 总是绘制背景，或者样式中有背景属性且不传递到 `LayoutView`）。
   - **判断背景几何属性是否依赖于可滚动溢出区域 (`BackgroundGeometryDependsOnScrollableOverflowRect`)**: 例如，当背景附件属性为 `local` 时。
   - **判断背景绘制在内容区域还是边框区域 (`BackgroundPaintsInContentsSpace`, `BackgroundPaintsInBorderBoxSpace`)**: 这取决于 `background-clip` 属性。
   - **计算背景失效类型 (`ComputeBackgroundInvalidation`, `ComputeViewBackgroundInvalidation`)**:
     - `kNone`: 不需要失效。
     - `kIncremental`: 可以进行增量失效。
     - `kFull`: 需要进行全量失效。
     - 考虑背景图片附件属性 (`fixed`, `local`) 和位置、尺寸变化。
     - 特别处理 `LayoutView` 的背景失效，因为它涉及到整个视口和固定背景。
   - **执行背景失效 (`InvalidateBackground`)**: 根据计算出的失效类型，通知相关的绘制项客户端进行重绘。

   **逻辑推理示例：**
   - **假设输入：** 一个 `div` 元素的 `LayoutBox` 对象，其 `background-color` 属性通过 JavaScript 动态修改。
   - **输出：** `BackgroundInvalidationType::kFull` (因为背景颜色变化需要全量重绘背景)。

3. **执行整体绘制失效 (`InvalidatePaint`)**:
   - 先调用 `InvalidateBackground` 处理背景失效。
   - 然后调用 `ObjectPaintInvalidatorWithContext` 来执行基于 `ComputePaintInvalidationReason` 计算出的原因的绘制失效。
   - 如果盒模型有滚动区域，则失效滚动条的绘制。
   - 最后，保存当前的盒模型几何属性，以便下次失效判断时使用。

4. **判断是否需要保存之前的几何属性 (`NeedsToSavePreviousContentBoxRect`, `NeedsToSavePreviousOverflowData`)**:
   - 为了进行增量失效的判断，需要保存盒模型之前的尺寸、溢出区域等信息。
   - 如果背景或遮罩使用了 `content-box` 定位，并且内容尺寸与边框尺寸不同，则需要保存之前的内容盒子尺寸。
   - 如果有视觉溢出或可滚动溢出，或者背景几何属性依赖于可滚动溢出区域，则需要保存之前的溢出数据。

5. **保存之前的几何属性 (`SavePreviousBoxGeometriesIfNeeded`)**: 将当前的盒模型尺寸和溢出数据保存到之前的状态。

**与 JavaScript, HTML, CSS 的关系：**

- **HTML**: `LayoutBox` 对象对应于 HTML 元素。当 HTML 结构发生变化（添加、删除元素），会导致相关 `LayoutBox` 的状态变化，从而触发 `BoxPaintInvalidator` 的工作。
- **CSS**: 该文件的大部分逻辑都与 CSS 属性相关。CSS 属性的变化（例如，`background-color`, `width`, `height`, `border-radius`, `mask-image`, `overflow` 等）会导致盒模型的绘制状态变化，触发 `BoxPaintInvalidator` 判断是否需要重绘。
   - **举例：** 当 CSS 的 `border-radius` 属性发生变化时，`ComputePaintInvalidationReason` 会检测到 `style.HasBorderRadius()` 为真，从而可能返回 `PaintInvalidationReason::kLayout`，触发重绘。
- **JavaScript**: JavaScript 可以动态地修改 HTML 结构和 CSS 属性。这些修改最终会反映到 `LayoutBox` 对象的状态上，从而间接地触发 `BoxPaintInvalidator` 的工作。
   - **举例：**  一个 JavaScript 代码修改了一个 `div` 元素的 `style.backgroundColor` 属性。这个修改会导致 `LayoutBox` 的背景属性发生变化，`ComputeBackgroundInvalidation` 会检测到这种变化，并决定需要全量重绘背景。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中打开一个网页。**
2. **浏览器解析 HTML 和 CSS，构建 DOM 树和 CSSOM 树。**
3. **Blink 渲染引擎根据 DOM 树和 CSSOM 树构建渲染树（Render Tree），其中的元素对应 `LayoutBox` 对象。**
4. **用户进行某些操作，导致网页内容或样式发生变化：**
   - **滚动页面：** 可能导致背景图片为 `local` 附件的元素需要重绘。
   - **鼠标悬停在一个元素上：** 可能触发 CSS 伪类 `:hover` 样式变化，例如背景颜色改变。
   - **输入框内容变化：** 可能导致输入框尺寸或样式变化。
   - **JavaScript 动态修改元素属性或样式：** 例如，通过 `element.style.width = '200px'` 修改宽度。
5. **当 `LayoutBox` 的相关属性发生变化时，渲染引擎会调用 `BoxPaintInvalidator` 来判断是否需要重绘。**
6. **`BoxPaintInvalidator` 的各种方法会被调用，根据当前和之前的状态以及样式属性，计算出绘制失效的原因和范围。**
7. **如果需要重绘，渲染引擎会触发相应的绘制流程，更新屏幕显示。**

**编程常见的使用错误示例：**

- **过度使用 JavaScript 动态修改样式：** 如果频繁地、不必要地修改元素的样式，会导致 `BoxPaintInvalidator` 频繁触发重绘，影响页面性能。
   - **场景：** 一个动画效果，使用 JavaScript 每帧都修改元素的 `left` 和 `top` 属性，而不是使用 CSS `transform` 或 `will-change` 优化。
   - **后果：** 每次属性变化都可能触发 `BoxPaintInvalidator` 进行昂贵的布局和绘制计算。
- **不理解 CSS 属性对重绘的影响：** 有些 CSS 属性（例如，改变盒模型的几何属性）比其他属性（例如，改变 `opacity`）更容易触发重绘和重排。开发者应该了解哪些属性会带来更高的性能开销。
   - **场景：**  使用 JavaScript 动态修改元素的 `width` 和 `height`，而不是使用 `transform: scale()`。
   - **后果：** 修改 `width` 和 `height` 会导致布局变化，触发更多重绘。

**调试线索：**

- **Performance 面板 (Chrome DevTools):** 可以记录页面的性能信息，包括绘制（Paint）操作。通过观察 Paint 的次数和耗时，可以定位潜在的性能瓶颈。
- **"Show paint rectangles" (Chrome DevTools Rendering 设置):** 可以高亮显示发生重绘的区域，帮助开发者理解哪些元素正在被重绘。
- **断点调试 C++ 代码：** 如果你需要深入了解 `BoxPaintInvalidator` 的具体工作流程，可以在相关代码行设置断点，例如在 `ComputePaintInvalidationReason` 或 `InvalidateBackground` 方法中，观察代码的执行路径和变量的值。你需要编译 Chromium 才能进行 C++ 代码的调试。
- **检查 CSS 属性变化：** 使用浏览器的开发者工具的 "Changes" 面板，可以查看哪些 CSS 属性被修改，这可以帮助你理解哪些样式变化可能触发了重绘。

总而言之，`blink/renderer/core/paint/box_paint_invalidator.cc` 是 Blink 渲染引擎中负责管理盒模型绘制失效的核心组件。它连接了 HTML 结构、CSS 样式和 JavaScript 动态修改，确保在必要时以高效的方式更新页面的渲染。理解其工作原理对于优化网页性能至关重要。

### 提示词
```
这是目录为blink/renderer/core/paint/box_paint_invalidator.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/box_paint_invalidator.h"

#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/layout/ink_overflow.h"
#include "third_party/blink/renderer/core/layout/layout_replaced.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/paint/object_paint_invalidator.h"
#include "third_party/blink/renderer/core/paint/paint_invalidator.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"

namespace blink {

bool BoxPaintInvalidator::HasEffectiveBackground() {
  // The view can paint background not from the style.
  if (IsA<LayoutView>(box_))
    return true;
  return box_.StyleRef().HasBackground() && !box_.BackgroundTransfersToView();
}

// |width| is of the positioning area.
static bool ShouldFullyInvalidateFillLayersOnWidthChange(
    const FillLayer& layer) {
  // Nobody will use multiple layers without wanting fancy positioning.
  if (layer.Next())
    return true;

  // The layer properties checked below apply only when there is a valid image.
  const StyleImage* image = layer.GetImage();
  if (!image || !image->CanRender())
    return false;

  if (layer.Repeat().x != EFillRepeat::kRepeatFill &&
      layer.Repeat().x != EFillRepeat::kNoRepeatFill) {
    return true;
  }

  // TODO(alancutter): Make this work correctly for calc lengths.
  if (layer.PositionX().HasPercent() && !layer.PositionX().IsZero()) {
    return true;
  }

  if (layer.BackgroundXOrigin() != BackgroundEdgeOrigin::kLeft)
    return true;

  EFillSizeType size_type = layer.SizeType();

  if (size_type == EFillSizeType::kContain ||
      size_type == EFillSizeType::kCover)
    return true;

  DCHECK_EQ(size_type, EFillSizeType::kSizeLength);

  // TODO(alancutter): Make this work correctly for calc lengths.
  const Length& width = layer.SizeLength().Width();
  if (width.HasPercent() && !width.IsZero()) {
    return true;
  }

  if (width.IsAuto() && !image->HasIntrinsicSize())
    return true;

  return false;
}

// |height| is of the positioning area.
static bool ShouldFullyInvalidateFillLayersOnHeightChange(
    const FillLayer& layer) {
  // Nobody will use multiple layers without wanting fancy positioning.
  if (layer.Next())
    return true;

  // The layer properties checked below apply only when there is a valid image.
  const StyleImage* image = layer.GetImage();
  if (!image || !image->CanRender())
    return false;

  if (layer.Repeat().y != EFillRepeat::kRepeatFill &&
      layer.Repeat().y != EFillRepeat::kNoRepeatFill) {
    return true;
  }

  // TODO(alancutter): Make this work correctly for calc lengths.
  if (layer.PositionY().HasPercent() && !layer.PositionY().IsZero()) {
    return true;
  }

  if (layer.BackgroundYOrigin() != BackgroundEdgeOrigin::kTop)
    return true;

  EFillSizeType size_type = layer.SizeType();

  if (size_type == EFillSizeType::kContain ||
      size_type == EFillSizeType::kCover)
    return true;

  DCHECK_EQ(size_type, EFillSizeType::kSizeLength);

  // TODO(alancutter): Make this work correctly for calc lengths.
  const Length& height = layer.SizeLength().Height();
  if (height.HasPercent() && !height.IsZero()) {
    return true;
  }

  if (height.IsAuto() && !image->HasIntrinsicSize())
    return true;

  return false;
}

// old_size and new_size are the old and new sizes of the positioning area.
bool ShouldFullyInvalidateFillLayersOnSizeChange(const FillLayer& layer,
                                                 const PhysicalSize& old_size,
                                                 const PhysicalSize& new_size) {
  return (old_size.width != new_size.width &&
          ShouldFullyInvalidateFillLayersOnWidthChange(layer)) ||
         (old_size.height != new_size.height &&
          ShouldFullyInvalidateFillLayersOnHeightChange(layer));
}

PaintInvalidationReason BoxPaintInvalidator::ComputePaintInvalidationReason() {
  PaintInvalidationReason reason =
      ObjectPaintInvalidatorWithContext(box_, context_)
          .ComputePaintInvalidationReason();

  if (reason == PaintInvalidationReason::kNone)
    return reason;

  if (IsLayoutFullPaintInvalidationReason(reason)) {
    return reason;
  }

  if (IsFullPaintInvalidationReason(reason) &&
      !box_.ShouldCheckLayoutForPaintInvalidation()) {
    return reason;
  }

  const ComputedStyle& style = box_.StyleRef();

  if (style.MaskLayers().AnyLayerUsesContentBox() &&
      box_.PreviousPhysicalContentBoxRect() != box_.PhysicalContentBoxRect())
    return PaintInvalidationReason::kLayout;

  if (const auto* layout_replaced = DynamicTo<LayoutReplaced>(box_)) {
    if (layout_replaced->ReplacedContentRect() !=
        layout_replaced->ReplacedContentRectFrom(
            box_.PreviousPhysicalContentBoxRect())) {
      return PaintInvalidationReason::kLayout;
    }
  }

#if DCHECK_IS_ON()
  // TODO(crbug.com/1205708): Audit this.
  InkOverflow::ReadUnsetAsNoneScope read_unset_as_none;
#endif
  if (box_.PreviousSize() == box_.Size() &&
      box_.PreviousSelfVisualOverflowRect() == box_.SelfVisualOverflowRect()) {
    return IsFullPaintInvalidationReason(reason)
               ? reason
               : PaintInvalidationReason::kNone;
  }

  // Incremental invalidation is not applicable if there is visual overflow.
  if (box_.PreviousSelfVisualOverflowRect().size != box_.PreviousSize() ||
      box_.SelfVisualOverflowRect().size != box_.Size()) {
    return PaintInvalidationReason::kLayout;
  }

  // Incremental invalidation is not applicable if paint offset or size has
  // fraction.
  if (context_.old_paint_offset.HasFraction() ||
      context_.fragment_data->PaintOffset().HasFraction() ||
      box_.PreviousSize().HasFraction() || box_.Size().HasFraction()) {
    return PaintInvalidationReason::kLayout;
  }

  // Incremental invalidation is not applicable if there is border in the
  // direction of border box size change because we don't know the border
  // width when issuing incremental raster invalidations.
  if (box_.BorderRight() || box_.BorderBottom())
    return PaintInvalidationReason::kLayout;

  if (style.HasVisualOverflowingEffect() || style.HasEffectiveAppearance() ||
      style.HasFilterInducingProperty() || style.HasMask() ||
      style.HasClipPath())
    return PaintInvalidationReason::kLayout;

  if (style.HasBorderRadius() || style.CanRenderBorderImage())
    return PaintInvalidationReason::kLayout;

  // Needs to repaint frame boundaries.
  if (box_.IsFrameSet()) {
    return PaintInvalidationReason::kLayout;
  }

  // Background invalidation has been done during InvalidateBackground(), so
  // we don't need to check background in this function.

  return reason;
}

bool BoxPaintInvalidator::BackgroundGeometryDependsOnScrollableOverflowRect() {
  return HasEffectiveBackground() &&
         box_.StyleRef().BackgroundLayers().AnyLayerHasLocalAttachmentImage();
}

bool BoxPaintInvalidator::BackgroundPaintsInContentsSpace() {
  if (!HasEffectiveBackground())
    return false;
  return box_.GetBackgroundPaintLocation() & kBackgroundPaintInContentsSpace;
}

bool BoxPaintInvalidator::BackgroundPaintsInBorderBoxSpace() {
  if (!HasEffectiveBackground())
    return false;
  return box_.GetBackgroundPaintLocation() & kBackgroundPaintInBorderBoxSpace;
}

bool BoxPaintInvalidator::
    ShouldFullyInvalidateBackgroundOnScrollableOverflowChange(
        const PhysicalRect& old_scrollable_overflow,
        const PhysicalRect& new_scrollable_overflow) {
  if (new_scrollable_overflow == old_scrollable_overflow) {
    return false;
  }

  if (!BackgroundGeometryDependsOnScrollableOverflowRect()) {
    return false;
  }

  // The background should invalidate on most location changes.
  if (new_scrollable_overflow.offset != old_scrollable_overflow.offset) {
    return true;
  }

  return ShouldFullyInvalidateFillLayersOnSizeChange(
      box_.StyleRef().BackgroundLayers(), old_scrollable_overflow.size,
      new_scrollable_overflow.size);
}

BoxPaintInvalidator::BackgroundInvalidationType
BoxPaintInvalidator::ComputeViewBackgroundInvalidation() {
  DCHECK(IsA<LayoutView>(box_));

  const auto& layout_view = To<LayoutView>(box_);
  auto new_background_rect = layout_view.BackgroundRect();
  auto old_background_rect = layout_view.PreviousBackgroundRect();
  layout_view.SetPreviousBackgroundRect(new_background_rect);

  // BackgroundRect is the positioning area of all fixed attachment backgrounds,
  // including the LayoutView's and descendants'.
  bool background_location_changed =
      new_background_rect.offset != old_background_rect.offset;
  bool background_size_changed =
      new_background_rect.size != old_background_rect.size;
  if (background_location_changed || background_size_changed) {
    for (const auto& object :
         layout_view.GetFrameView()->BackgroundAttachmentFixedObjects())
      object->SetBackgroundNeedsFullPaintInvalidation();
  }

  if (background_location_changed ||
      layout_view.BackgroundNeedsFullPaintInvalidation() ||
      (context_.subtree_flags &
       PaintInvalidatorContext::kSubtreeFullInvalidation)) {
    return BackgroundInvalidationType::kFull;
  }

  if (Element* root_element = box_.GetDocument().documentElement()) {
    if (const auto* root_object = root_element->GetLayoutObject()) {
      if (root_object->IsBox()) {
        const auto* root_box = To<LayoutBox>(root_object);
        // LayoutView's non-fixed-attachment background is positioned in the
        // root element and needs to invalidate if the size changes.
        // See: https://drafts.csswg.org/css-backgrounds-3/#root-background.
        const auto& background_layers = box_.StyleRef().BackgroundLayers();
        if (ShouldFullyInvalidateFillLayersOnSizeChange(
                background_layers, root_box->PreviousSize(),
                root_box->Size())) {
          return BackgroundInvalidationType::kFull;
        }
        if (BackgroundGeometryDependsOnScrollableOverflowRect() &&
            ShouldFullyInvalidateBackgroundOnScrollableOverflowChange(
                root_box->PreviousScrollableOverflowRect(),
                root_box->ScrollableOverflowRect())) {
          return BackgroundInvalidationType::kFull;
        }
        // It also uses the root element's content box in case the background
        // comes from the root element and positioned in content box.
        if (background_layers.AnyLayerUsesContentBox() &&
            root_box->PreviousPhysicalContentBoxRect() !=
                root_box->PhysicalContentBoxRect()) {
          return BackgroundInvalidationType::kFull;
        }
      }
      // The view background paints with a transform but nevertheless extended
      // onto an infinite canvas. In cases where it has a transform we can't
      // apply incremental invalidation, because the visual rect is no longer
      // axis-aligned to the LayoutView.
      if (root_object->HasTransform())
        return BackgroundInvalidationType::kFull;
    }
  }

  return background_size_changed ? BackgroundInvalidationType::kIncremental
                                 : BackgroundInvalidationType::kNone;
}

BoxPaintInvalidator::BackgroundInvalidationType
BoxPaintInvalidator::ComputeBackgroundInvalidation(
    bool& should_invalidate_all_layers) {
  // If background changed, we may paint the background on different graphics
  // layer, so we need to fully invalidate the background on all layers.
  if (box_.BackgroundNeedsFullPaintInvalidation() ||
      (context_.subtree_flags &
       PaintInvalidatorContext::kSubtreeFullInvalidation)) {
    should_invalidate_all_layers = true;
    return BackgroundInvalidationType::kFull;
  }

  if (!HasEffectiveBackground())
    return BackgroundInvalidationType::kNone;

  const auto& background_layers = box_.StyleRef().BackgroundLayers();
  if (background_layers.AnyLayerHasDefaultAttachmentImage() &&
      ShouldFullyInvalidateFillLayersOnSizeChange(
          background_layers, box_.PreviousSize(), box_.Size())) {
    return BackgroundInvalidationType::kFull;
  }

  if (background_layers.AnyLayerUsesContentBox() &&
      box_.PreviousPhysicalContentBoxRect() != box_.PhysicalContentBoxRect())
    return BackgroundInvalidationType::kFull;

  bool scrollable_overflow_change_causes_invalidation =
      (BackgroundGeometryDependsOnScrollableOverflowRect() ||
       BackgroundPaintsInContentsSpace());

  if (!scrollable_overflow_change_causes_invalidation) {
    return BackgroundInvalidationType::kNone;
  }

  const auto& old_scrollable_overflow = box_.PreviousScrollableOverflowRect();
  auto new_scrollable_overflow = box_.ScrollableOverflowRect();
  if (ShouldFullyInvalidateBackgroundOnScrollableOverflowChange(
          old_scrollable_overflow, new_scrollable_overflow)) {
    return BackgroundInvalidationType::kFull;
  }

  if (new_scrollable_overflow != old_scrollable_overflow) {
    // Do incremental invalidation if possible.
    if (old_scrollable_overflow.offset == new_scrollable_overflow.offset) {
      return BackgroundInvalidationType::kIncremental;
    }
    return BackgroundInvalidationType::kFull;
  }
  return BackgroundInvalidationType::kNone;
}

void BoxPaintInvalidator::InvalidateBackground() {
  bool should_invalidate_in_both_spaces = false;
  auto background_invalidation_type =
      ComputeBackgroundInvalidation(should_invalidate_in_both_spaces);
  if (IsA<LayoutView>(box_)) {
    background_invalidation_type = std::max(
        background_invalidation_type, ComputeViewBackgroundInvalidation());
  }

  if (box_.GetScrollableArea()) {
    if (should_invalidate_in_both_spaces ||
        (BackgroundPaintsInContentsSpace() &&
         background_invalidation_type != BackgroundInvalidationType::kNone)) {
      auto reason =
          background_invalidation_type == BackgroundInvalidationType::kFull
              ? PaintInvalidationReason::kBackground
              : PaintInvalidationReason::kIncremental;
      context_.painting_layer->SetNeedsRepaint();
      ObjectPaintInvalidator(box_).InvalidateDisplayItemClient(
          box_.GetScrollableArea()->GetScrollingBackgroundDisplayItemClient(),
          reason);
    }
  }

  if (should_invalidate_in_both_spaces ||
      (BackgroundPaintsInBorderBoxSpace() &&
       background_invalidation_type == BackgroundInvalidationType::kFull)) {
    box_.GetMutableForPainting()
        .SetShouldDoFullPaintInvalidationWithoutLayoutChange(
            PaintInvalidationReason::kBackground);
  }

  if (background_invalidation_type == BackgroundInvalidationType::kNone &&
      box_.ScrollsOverflow() &&
      box_.PreviousScrollableOverflowRect() != box_.ScrollableOverflowRect()) {
    // We need to re-record the hit test data for scrolling contents.
    context_.painting_layer->SetNeedsRepaint();
  }
}

void BoxPaintInvalidator::InvalidatePaint() {
  InvalidateBackground();

  ObjectPaintInvalidatorWithContext(box_, context_)
      .InvalidatePaintWithComputedReason(ComputePaintInvalidationReason());

  if (PaintLayerScrollableArea* area = box_.GetScrollableArea())
    area->InvalidatePaintOfScrollControlsIfNeeded(context_);

  // This is for the next invalidatePaintIfNeeded so must be at the end.
  SavePreviousBoxGeometriesIfNeeded();
}

bool BoxPaintInvalidator::NeedsToSavePreviousContentBoxRect() {
  // Replaced elements are clipped to the content box thus we need to check
  // for its size.
  if (box_.IsLayoutReplaced())
    return true;

  const ComputedStyle& style = box_.StyleRef();

  // Background and mask layers can depend on other boxes than border box. See
  // crbug.com/490533
  if ((style.BackgroundLayers().AnyLayerUsesContentBox() ||
       style.MaskLayers().AnyLayerUsesContentBox()) &&
      box_.ContentSize() != box_.Size()) {
    return true;
  }

  return false;
}

bool BoxPaintInvalidator::NeedsToSavePreviousOverflowData() {
  if (box_.HasVisualOverflow() || box_.HasScrollableOverflow()) {
    return true;
  }

  // If we don't have scrollable overflow, the layout overflow rect is the
  // padding box rect, and we need to save it if the background depends on it.
  // We also need to save the rect for the document element because the
  // LayoutView may depend on the document element's scrollable overflow rect
  // (see: ComputeViewBackgroundInvalidation).
  if ((BackgroundGeometryDependsOnScrollableOverflowRect() ||
       BackgroundPaintsInContentsSpace() || box_.IsDocumentElement()) &&
      box_.ScrollableOverflowRect() != box_.PhysicalBorderBoxRect()) {
    return true;
  }

  return false;
}

void BoxPaintInvalidator::SavePreviousBoxGeometriesIfNeeded() {
  auto mutable_box = box_.GetMutableForPainting();
  mutable_box.SavePreviousSize();

#if DCHECK_IS_ON()
  // TODO(crbug.com/1205708): Audit this.
  InkOverflow::ReadUnsetAsNoneScope read_unset_as_none;
#endif
  if (NeedsToSavePreviousOverflowData())
    mutable_box.SavePreviousOverflowData();
  else
    mutable_box.ClearPreviousOverflowData();

  if (NeedsToSavePreviousContentBoxRect())
    mutable_box.SavePreviousContentBoxRect();
  else
    mutable_box.ClearPreviousContentBoxRect();
}

}  // namespace blink
```