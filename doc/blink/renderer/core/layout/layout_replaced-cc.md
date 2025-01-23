Response:
Let's break down the thought process for analyzing the `layout_replaced.cc` file and generating the comprehensive response.

1. **Understanding the Core Request:** The request asks for the functionality of the file, its relation to web technologies, examples, logical reasoning, and common errors. This requires a multi-faceted analysis, going beyond just reading the code.

2. **Initial Scan and High-Level Purpose:**  The filename `layout_replaced.cc` and the included headers immediately suggest this file deals with the layout of "replaced elements."  Replaced elements are things like `<img>`, `<video>`, `<canvas>`, etc., where the content is rendered by an external resource or agent. The copyright notices indicate it's a long-standing part of the Blink engine.

3. **Identifying Key Classes and Methods:**  The code defines the `LayoutReplaced` class, inheriting from `LayoutBox`. This is the central entity. Scanning the methods within this class reveals the core responsibilities:

    * **Lifecycle Management:** `WillBeDestroyed()`
    * **Style Changes:** `StyleDidChange()`
    * **Intrinsic Sizing:** `IntrinsicSizeChanged()`, `ComputeIntrinsicSizingInfo()`
    * **Painting:** `Paint()`
    * **Visual Overflow:** `AddVisualEffectOverflow()`, `RecalcVisualOverflow()`
    * **Object Fit and Position:** `ComputeObjectFitAndPositionRect()`, `ComputeReplacedContentRect()`, `ComputeObjectViewBoxRect()`
    * **Selection:** `PositionForPoint()`, `LocalSelectionVisualRect()`, `SelectionTopAndBottom()`
    * **Overflow and Clipping:** `RespectsCSSOverflow()`, `ClipsToContentBox()`

4. **Connecting to Web Technologies (HTML, CSS, JavaScript):**  This is a crucial step. For each identified functionality, think about how it manifests in web development:

    * **HTML:** Replaced elements are directly defined in HTML (`<img>`, `<video>`, `<canvas>`). The file deals with their layout representation.
    * **CSS:**  Many of the methods directly correspond to CSS properties:
        * `object-fit`:  `ComputeObjectFitAndPositionRect()`
        * `object-position`: `ComputeObjectFitAndPositionRect()`
        * `object-view-box`: `ComputeObjectViewBoxRect()`
        * `overflow`: `RespectsCSSOverflow()`, `ClipsToContentBox()`, `RecalcVisualOverflow()`
        * `border-radius`: `StyleDidChange()`
        * `zoom`: `StyleDidChange()`, `IntrinsicSizeChanged()`
    * **JavaScript:** While this C++ code doesn't directly interact with JavaScript *execution*, JavaScript manipulates the DOM and CSS styles, which indirectly triggers the logic within `LayoutReplaced`. For example, changing the `src` attribute of an `<img>` or setting CSS properties via JavaScript will lead to layout and paint updates handled by this code.

5. **Generating Examples:** For each connection to web technologies, construct simple, illustrative HTML/CSS examples. This solidifies the understanding and makes the explanation clearer.

6. **Logical Reasoning and Hypothetical Scenarios:**  Consider how different inputs affect the behavior. For instance:

    * **`object-fit`:** How does `contain` differ from `cover`?  What happens with different aspect ratios?
    * **`object-view-box`:** How do different `inset()` values affect the displayed portion of the image? What if the view box is outside the image bounds?
    * **Intrinsic Sizing:** What happens if the intrinsic size is zero?

7. **Identifying Common Errors:** Think about what mistakes web developers might make that relate to the functionalities of this file:

    * Incorrect `object-fit` or `object-position` values leading to unexpected scaling or cropping.
    * Misunderstanding how `object-view-box` affects the rendered content.
    * Issues with `overflow: visible` on replaced elements.
    * Forgetting about the default dimensions of replaced elements if width and height are not specified.

8. **Structuring the Response:** Organize the information logically:

    * Start with a concise summary of the file's purpose.
    * Detail the key functionalities with explanations.
    * Provide concrete examples for HTML, CSS, and their interactions.
    * Explain logical reasoning with clear input/output scenarios.
    * List common user/programming errors with examples.
    * Maintain a clear and readable format.

9. **Review and Refine:** After drafting the response, review it for accuracy, completeness, and clarity. Ensure the examples are correct and the explanations are easy to understand. For example, initially, I might have just listed the methods without explaining their relevance to CSS. The refinement step involves making those connections explicit. Also, double-check for any technical inaccuracies. For example, ensure the explanation of how `object-view-box` interacts with `object-fit` is precise.

By following these steps, combining code analysis with knowledge of web technologies and common development practices, a comprehensive and helpful response can be generated. The key is to not just describe *what* the code does, but also *why* it's important in the context of web development.
好的，让我们详细分析一下 `blink/renderer/core/layout/layout_replaced.cc` 文件的功能。

**核心功能：处理替换元素的布局**

`LayoutReplaced` 类是 Blink 渲染引擎中用于处理“替换元素”（Replaced Elements）布局的核心类。替换元素是指其显示内容并非由自身的 HTML 结构直接决定的元素，而是由外部资源或用户代理（浏览器）提供的，例如 `<img>`、`<video>`、`<canvas>`、`<iframe>` 等。

**主要功能点：**

1. **存储固有尺寸 (Intrinsic Size):**
   - `intrinsic_size_`:  存储替换元素的固有宽度和高度。这些尺寸是元素内容本身所具有的，例如图片的实际像素尺寸，视频的宽高比等。
   - `kDefaultWidth`, `kDefaultHeight`:  定义了替换元素在没有明确指定尺寸时的默认宽度和高度（分别为 300px 和 150px）。
   - `IntrinsicSizeChanged()`: 当影响固有尺寸的因素发生变化时（例如，图片加载完成，或者 `zoom` 属性改变），会调用此方法来更新 `intrinsic_size_` 并触发重新布局。

   **与 CSS 的关系：** 当你在 CSS 中不设置 `width` 和 `height` 时，替换元素会尝试使用其固有尺寸来渲染。

   **例子：**
   ```html
   <img src="image.png">
   ```
   如果 `image.png` 的实际尺寸是 600x400，那么 `LayoutReplaced` 对象会存储这个尺寸。

   **假设输入与输出：**
   - **假设输入:**  一个 `<img>` 元素，`image.png` 加载完成，其固有尺寸为 800x600。
   - **输出:** `intrinsic_size_` 被设置为 `PhysicalSize(LayoutUnit(800), LayoutUnit(600))`。

2. **处理 `object-fit` 和 `object-position` 属性:**
   - `ComputeObjectFitAndPositionRect()`:  根据 CSS 的 `object-fit` 和 `object-position` 属性，计算替换元素内容在元素内容盒子内的最终位置和尺寸。这决定了内容如何缩放、裁剪或填充。

   **与 CSS 的关系：**  直接对应 CSS 的 `object-fit` 和 `object-position` 属性。

   **例子：**
   ```html
   <img src="image.png" style="width: 200px; height: 150px; object-fit: cover; object-position: 50% 50%;">
   ```
   `ComputeObjectFitAndPositionRect()` 会计算如何将 `image.png` (假设固有尺寸大于 200x150) 缩放并定位到 200x150 的区域，并保持其宽高比并居中显示（因为 `object-fit: cover` 和 `object-position: 50% 50%`）。

   **假设输入与输出：**
   - **假设输入:** 一个 `<img>` 元素，固有尺寸 800x600，内容盒子尺寸 200x150，`object-fit: cover`，`object-position: 0 0`。
   - **输出:**  `ComputeObjectFitAndPositionRect()` 返回一个 `PhysicalRect`，例如 `PhysicalRect(PhysicalOffset(-133, 0), PhysicalSize(400, 300))`。这意味着图片会被放大裁剪，左上角与内容盒子的左上角对齐。

3. **处理 `object-view-box` 属性:**
   - `ComputeObjectViewBoxRect()`:  根据 CSS 的 `object-view-box` 属性，定义一个用于显示替换元素内容的视口。这允许你只显示替换元素内容的一部分。
   - `ComputeReplacedContentRect()`:  综合考虑 `object-view-box` 和 `object-fit`/`object-position` 来计算最终的渲染区域。

   **与 CSS 的关系：**  直接对应 CSS 的 `object-view-box` 属性。

   **例子：**
   ```html
   <img src="image.png" style="object-view-box: inset(10px 20px 30px 40px);">
   ```
   `ComputeObjectViewBoxRect()` 会计算出 `image.png` 中间的一个矩形区域作为视口。后续的 `object-fit` 和 `object-position` 会基于这个视口进行计算。

   **假设输入与输出：**
   - **假设输入:** 一个 `<img>` 元素，固有尺寸 800x600，`object-view-box: inset(50px)`。
   - **输出:** `ComputeObjectViewBoxRect()` 返回一个 `std::optional<PhysicalRect>`，其值为 `PhysicalRect(PhysicalOffset(50, 50), PhysicalSize(700, 500))`。

4. **绘制 (Painting):**
   - `Paint()`:  调用 `ReplacedPainter` 类来实际绘制替换元素的内容。

   **与渲染过程的关系：** 这是渲染流水线的一部分，负责将布局信息转化为屏幕上的像素。

5. **处理视觉溢出 (Visual Overflow):**
   - `AddVisualEffectOverflow()`:  考虑边框、阴影、轮廓等视觉效果造成的溢出。
   - `RecalcVisualOverflow()`:  重新计算替换元素的视觉溢出区域。
   - `RespectsCSSOverflow()`: 判断替换元素是否遵循 CSS 的 `overflow` 属性。
   - `ClipsToContentBox()`: 判断替换元素的内容是否裁剪到内容盒子。

   **与 CSS 的关系：**  与 CSS 的 `overflow`, `border-radius`, `box-shadow`, `outline` 等属性有关。

   **例子：**
   ```html
   <img src="image.png" style="border-radius: 10px; overflow: visible;">
   ```
   即使设置了 `border-radius`，如果 `overflow: visible`，图片内容仍然可能超出圆角边框的范围。`RecalcVisualOverflow()` 会计算这个溢出区域。

   **假设输入与输出：**
   - **假设输入:** 一个 `<img>` 元素，尺寸 100x100，`border-radius: 20px`。
   - **输出:**  `ClipsToContentBox()` 可能返回 `true`，因为默认情况下替换元素会裁剪到内容盒子。

6. **处理选择 (Selection):**
   - `PositionForPoint()`:  确定给定点在替换元素内的逻辑位置，用于文本选择等操作。
   - `LocalSelectionVisualRect()`:  返回替换元素内部选中文本的可视矩形。

   **与 JavaScript 和用户交互的关系：**  当用户尝试选中替换元素内的内容时（尽管通常替换元素的内容不可直接选中），或者通过 JavaScript 进行选择操作时，会用到这些方法。

7. **固有尺寸信息 (Intrinsic Sizing Info):**
   - `ComputeIntrinsicSizingInfo()`:  计算替换元素的固有尺寸信息，包括尺寸和宽高比，用于布局计算。

   **与 CSS 布局的关系：**  在自动布局、弹性布局等场景中，元素的固有尺寸信息对于确定其最终尺寸非常重要。

**逻辑推理的例子：**

**假设输入：** 一个 `<img>` 元素，没有设置 `width` 和 `height`，但设置了 `object-fit: contain`，且其父元素的宽度是 500px。图片的固有尺寸是 800x600。

**逻辑推理过程：**

1. `LayoutReplaced` 对象会获取图片的固有尺寸 (800x600)。
2. 由于没有设置 `width` 和 `height`，替换元素的初始尺寸会依赖于其内容。
3. `object-fit: contain` 指示图片应缩放以完全适应其内容盒子，同时保持其宽高比。
4. `ComputeObjectFitAndPositionRect()` 会计算缩放后的尺寸。在这种情况下，宽度会受父元素限制，高度会根据宽高比计算。
5. 计算出的替换元素的尺寸将小于或等于父元素的宽度 (500px)，例如，宽度为 500px，高度为 375px (500 * 600 / 800)。

**输出：** 替换元素的布局尺寸将是 500x375。

**用户或编程常见的使用错误：**

1. **错误地理解 `object-fit` 的行为：**
   - **错误：** 假设 `object-fit: cover` 会完整显示图片。
   - **正确：** `object-fit: cover` 会缩放并裁剪图片以填充内容盒子，可能会裁剪掉部分图片内容。

2. **忘记设置替换元素的尺寸：**
   - **错误：**  没有为 `<img>` 或 `<video>` 设置 `width` 和 `height`，期望它自动充满父元素。
   - **结果：** 替换元素可能以其固有尺寸或默认尺寸显示，导致布局不符合预期。

3. **误用 `object-view-box`：**
   - **错误：**  设置了超出替换元素固有尺寸的 `object-view-box`。
   - **结果：**  可能不会报错，但超出部分会显示为透明或空白。

4. **在 `overflow: visible` 的情况下，没有意识到替换元素的内容可能超出其边框：**
   - **错误：**  假设设置了 `border-radius` 就能保证内容不会超出圆角。
   - **结果：**  如果 `overflow: visible`，内容可能会溢出圆角区域。

5. **在 JavaScript 中操作替换元素尺寸时，没有考虑到 `object-fit` 和 `object-view-box` 的影响：**
   - **错误：**  通过 JavaScript 直接修改元素的 `width` 和 `height`，期望内容也随之缩放。
   - **结果：**  `object-fit` 和 `object-view-box` 仍然会影响内容的渲染方式，可能导致不一致的结果。

**总结：**

`layout_replaced.cc` 文件中的 `LayoutReplaced` 类是 Blink 渲染引擎中至关重要的部分，它负责处理各种替换元素的布局逻辑，并与 CSS 的相关属性紧密相关。理解其功能有助于我们更好地掌握浏览器如何渲染 `<img>`、`<video>` 等元素，并避免常见的布局错误。

### 提示词
```
这是目录为blink/renderer/core/layout/layout_replaced.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 * Copyright (C) 2000 Dirk Mueller (mueller@kde.org)
 * Copyright (C) 2004, 2006, 2007 Apple Inc. All rights reserved.
 * Copyright (C) Research In Motion Limited 2011-2012. All rights reserved.
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

#include "third_party/blink/renderer/core/layout/layout_replaced.h"

#include "base/memory/scoped_refptr.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/html/html_dimension.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/layout/fragmentation_utils.h"
#include "third_party/blink/renderer/core/layout/geometry/logical_offset.h"
#include "third_party/blink/renderer/core/layout/geometry/logical_size.h"
#include "third_party/blink/renderer/core/layout/geometry/physical_offset.h"
#include "third_party/blink/renderer/core/layout/geometry/physical_rect.h"
#include "third_party/blink/renderer/core/layout/geometry/physical_size.h"
#include "third_party/blink/renderer/core/layout/geometry/writing_mode_converter.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/intrinsic_sizing_info.h"
#include "third_party/blink/renderer/core/layout/layout_block.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_image.h"
#include "third_party/blink/renderer/core/layout/layout_inline.h"
#include "third_party/blink/renderer/core/layout/layout_video.h"
#include "third_party/blink/renderer/core/layout/layout_view_transition_content.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/replaced_painter.h"
#include "third_party/blink/renderer/core/style/basic_shapes.h"
#include "third_party/blink/renderer/core/style/computed_style_base_constants.h"
#include "third_party/blink/renderer/platform/geometry/layout_point.h"
#include "third_party/blink/renderer/platform/geometry/layout_unit.h"
#include "third_party/blink/renderer/platform/geometry/length_functions.h"
#include "ui/gfx/geometry/rect_f.h"
#include "ui/gfx/geometry/size_f.h"

namespace blink {

const int LayoutReplaced::kDefaultWidth = 300;
const int LayoutReplaced::kDefaultHeight = 150;

LayoutReplaced::LayoutReplaced(Element* element)
    : LayoutBox(element),
      intrinsic_size_(LayoutUnit(kDefaultWidth), LayoutUnit(kDefaultHeight)) {
  // TODO(jchaffraix): We should not set this boolean for block-level
  // replaced elements (crbug.com/567964).
  SetIsAtomicInlineLevel(true);
}

LayoutReplaced::LayoutReplaced(Element* element,
                               const PhysicalSize& intrinsic_size)
    : LayoutBox(element), intrinsic_size_(intrinsic_size) {
  // TODO(jchaffraix): We should not set this boolean for block-level
  // replaced elements (crbug.com/567964).
  SetIsAtomicInlineLevel(true);
}

LayoutReplaced::~LayoutReplaced() = default;

void LayoutReplaced::WillBeDestroyed() {
  NOT_DESTROYED();
  if (!DocumentBeingDestroyed() && Parent())
    Parent()->DirtyLinesFromChangedChild(this);

  LayoutBox::WillBeDestroyed();
}

void LayoutReplaced::StyleDidChange(StyleDifference diff,
                                    const ComputedStyle* old_style) {
  NOT_DESTROYED();
  LayoutBox::StyleDidChange(diff, old_style);

  // Replaced elements can have border-radius clips without clipping overflow;
  // the overflow clipping case is already covered in LayoutBox::StyleDidChange
  if (old_style && diff.BorderRadiusChanged()) {
    SetNeedsPaintPropertyUpdate();
  }

  bool had_style = !!old_style;
  float old_zoom = had_style ? old_style->EffectiveZoom()
                             : ComputedStyleInitialValues::InitialZoom();
  if (Style() && StyleRef().EffectiveZoom() != old_zoom)
    IntrinsicSizeChanged();

  if ((IsLayoutImage() || IsVideo() || IsCanvas()) && !ClipsToContentBox() &&
      !StyleRef().ObjectPropertiesPreventReplacedOverflow()) {
    static constexpr const char kErrorMessage[] =
        "Specifying 'overflow: visible' on img, video and canvas tags may "
        "cause them to produce visual content outside of the element bounds. "
        "See "
        "https://github.com/WICG/view-transitions/blob/main/"
        "debugging_overflow_on_images.md for details.";
    auto* console_message = MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kRendering,
        mojom::blink::ConsoleMessageLevel::kWarning, kErrorMessage);
    constexpr bool kDiscardDuplicates = true;
    GetDocument().AddConsoleMessage(console_message, kDiscardDuplicates);
  }
}

void LayoutReplaced::IntrinsicSizeChanged() {
  NOT_DESTROYED();
  LayoutUnit scaled_width =
      LayoutUnit(static_cast<int>(kDefaultWidth * StyleRef().EffectiveZoom()));
  LayoutUnit scaled_height =
      LayoutUnit(static_cast<int>(kDefaultHeight * StyleRef().EffectiveZoom()));
  intrinsic_size_ = PhysicalSize(scaled_width, scaled_height);
  SetNeedsLayoutAndIntrinsicWidthsRecalcAndFullPaintInvalidation(
      layout_invalidation_reason::kSizeChanged);
}

void LayoutReplaced::Paint(const PaintInfo& paint_info) const {
  NOT_DESTROYED();
  ReplacedPainter(*this).Paint(paint_info);
}

static inline bool LayoutObjectHasIntrinsicAspectRatio(
    const LayoutObject* layout_object) {
  DCHECK(layout_object);
  return layout_object->IsImage() || layout_object->IsCanvas() ||
         IsA<LayoutVideo>(layout_object) ||
         IsA<LayoutViewTransitionContent>(layout_object);
}

void LayoutReplaced::AddVisualEffectOverflow() {
  NOT_DESTROYED();
  if (!StyleRef().HasVisualOverflowingEffect()) {
    return;
  }

  // Add in the final overflow with shadows, outsets and outline combined.
  PhysicalRect visual_effect_overflow = PhysicalBorderBoxRect();
  PhysicalBoxStrut outsets = ComputeVisualEffectOverflowOutsets();
  visual_effect_overflow.Expand(outsets);
  AddSelfVisualOverflow(visual_effect_overflow);
  UpdateHasSubpixelVisualEffectOutsets(outsets);
}

void LayoutReplaced::RecalcVisualOverflow() {
  NOT_DESTROYED();
  ClearVisualOverflow();
  LayoutObject::RecalcVisualOverflow();
  AddVisualEffectOverflow();

  // Replaced elements clip the content to the element's content-box by default.
  // But if the CSS overflow property is respected, the content may paint
  // outside the element's bounds as ink overflow (with overflow:visible for
  // example). So we add |ReplacedContentRect()|, which provides the element's
  // painting rectangle relative to it's bounding box in its visual overflow if
  // the overflow property is respected.
  // Note that |overflow_| is meant to track the maximum potential ink overflow.
  // The actual painted overflow (based on the values for overflow,
  // overflow-clip-margin and paint containment) is computed in
  // LayoutBox::VisualOverflowRect.
  if (RespectsCSSOverflow())
    AddContentsVisualOverflow(ReplacedContentRect());
}

std::optional<PhysicalRect> LayoutReplaced::ComputeObjectViewBoxRect(
    const PhysicalSize* overridden_intrinsic_size) const {
  const BasicShape* object_view_box = StyleRef().ObjectViewBox();
  if (!object_view_box) [[likely]] {
    return std::nullopt;
  }

  const auto& intrinsic_size =
      overridden_intrinsic_size ? *overridden_intrinsic_size : intrinsic_size_;
  if (intrinsic_size.IsEmpty())
    return std::nullopt;

  if (!CanApplyObjectViewBox())
    return std::nullopt;

  DCHECK_EQ(object_view_box->GetType(), BasicShape::kBasicShapeInsetType);

  Path path;
  gfx::RectF bounding_box(0, 0, intrinsic_size.width.ToFloat(),
                          intrinsic_size.height.ToFloat());
  object_view_box->GetPath(path, bounding_box, 1.f);

  const PhysicalRect view_box_rect =
      PhysicalRect::EnclosingRect(path.BoundingRect());
  if (view_box_rect.IsEmpty())
    return std::nullopt;

  const PhysicalRect intrinsic_rect(PhysicalOffset(), intrinsic_size);
  if (view_box_rect == intrinsic_rect)
    return std::nullopt;

  return view_box_rect;
}

PhysicalRect LayoutReplaced::ComputeReplacedContentRect(
    const PhysicalRect& base_content_rect,
    const PhysicalSize* overridden_intrinsic_size) const {
  // |intrinsic_size| provides the size of the embedded content rendered in the
  // replaced element. This is the reference size that object-view-box applies
  // to.
  // If present, object-view-box changes the notion of embedded content used for
  // painting the element and applying rest of the object* properties. The
  // following cases are possible:
  //
  // - object-view-box is a subset of the embedded content. For example,
  // [0,0 50x50] on an image with bounds 100x100.
  //
  // - object-view-box is a superset of the embedded content. For example,
  // [-10, -10, 120x120] on an image with bounds 100x100.
  //
  // - object-view-box intersects with the embedded content. For example,
  // [-10, -10, 50x50] on an image with bounds 100x100.
  //
  // - object-view-box has no intersection with the embedded content. For
  // example, [-50, -50, 50x50] on any image.
  //
  // The image is scaled (by object-fit) and positioned (by object-position)
  // assuming the embedded content to be provided by the box identified by
  // object-view-box.
  //
  // Regions outside the image bounds (but within object-view-box) paint
  // transparent pixels. Regions outside object-view-box (but within image
  // bounds) are scaled as defined by object-fit above and treated as ink
  // overflow.
  const auto& intrinsic_size_for_object_view_box =
      overridden_intrinsic_size ? *overridden_intrinsic_size : intrinsic_size_;
  const auto view_box =
      ComputeObjectViewBoxRect(&intrinsic_size_for_object_view_box);

  // If no view box override was applied, then we don't need to adjust the
  // view-box paint rect.
  if (!view_box) {
    return ComputeObjectFitAndPositionRect(base_content_rect,
                                           overridden_intrinsic_size);
  }

  // Compute the paint rect based on bounds provided by the view box.
  DCHECK(!view_box->IsEmpty());
  const PhysicalSize view_box_size(view_box->Width(), view_box->Height());
  const auto view_box_paint_rect =
      ComputeObjectFitAndPositionRect(base_content_rect, &view_box_size);
  if (view_box_paint_rect.IsEmpty())
    return view_box_paint_rect;

  // Scale the original image bounds by the scale applied to the view box.
  auto scaled_width = intrinsic_size_for_object_view_box.width.MulDiv(
      view_box_paint_rect.Width(), view_box->Width());
  auto scaled_height = intrinsic_size_for_object_view_box.height.MulDiv(
      view_box_paint_rect.Height(), view_box->Height());
  const PhysicalSize scaled_image_size(scaled_width, scaled_height);

  // Scale the offset from the image origin by the scale applied to the view
  // box.
  auto scaled_x_offset =
      view_box->X().MulDiv(view_box_paint_rect.Width(), view_box->Width());
  auto scaled_y_offset =
      view_box->Y().MulDiv(view_box_paint_rect.Height(), view_box->Height());
  const PhysicalOffset scaled_offset(scaled_x_offset, scaled_y_offset);

  return PhysicalRect(view_box_paint_rect.offset - scaled_offset,
                      scaled_image_size);
}

PhysicalRect LayoutReplaced::ComputeObjectFitAndPositionRect(
    const PhysicalRect& base_content_rect,
    const PhysicalSize* overridden_intrinsic_size) const {
  NOT_DESTROYED();
  EObjectFit object_fit = StyleRef().GetObjectFit();

  if (object_fit == EObjectFit::kFill &&
      StyleRef().ObjectPosition() ==
          ComputedStyleInitialValues::InitialObjectPosition()) {
    return base_content_rect;
  }

  // TODO(davve): intrinsicSize doubles as both intrinsic size and intrinsic
  // ratio. In the case of SVG images this isn't correct since they can have
  // intrinsic ratio but no intrinsic size. In order to maintain aspect ratio,
  // the intrinsic size for SVG might be faked from the aspect ratio,
  // see SVGImage::containerSize().
  PhysicalSize intrinsic_size(
      overridden_intrinsic_size ? *overridden_intrinsic_size : IntrinsicSize());
  if (intrinsic_size.IsEmpty())
    return base_content_rect;

  PhysicalSize scaled_intrinsic_size(intrinsic_size);
  PhysicalRect final_rect = base_content_rect;
  switch (object_fit) {
    case EObjectFit::kScaleDown:
      // Srcset images have an intrinsic size depending on their destination,
      // but with object-fit: scale-down they need to use the underlying image
      // src's size. So revert back to the original size in that case.
      if (auto* image = DynamicTo<LayoutImage>(this)) {
        scaled_intrinsic_size.Scale(1.0 / image->ImageDevicePixelRatio());
      }
      [[fallthrough]];
    case EObjectFit::kContain:
    case EObjectFit::kCover:
      final_rect.size = final_rect.size.FitToAspectRatio(
          intrinsic_size, object_fit == EObjectFit::kCover
                              ? kAspectRatioFitGrow
                              : kAspectRatioFitShrink);
      if (object_fit != EObjectFit::kScaleDown ||
          final_rect.Width() <= scaled_intrinsic_size.width)
        break;
      [[fallthrough]];
    case EObjectFit::kNone:
      final_rect.size = scaled_intrinsic_size;
      break;
    case EObjectFit::kFill:
      break;
    default:
      NOTREACHED();
  }

  LayoutUnit x_offset =
      MinimumValueForLength(StyleRef().ObjectPosition().X(),
                            base_content_rect.Width() - final_rect.Width());
  LayoutUnit y_offset =
      MinimumValueForLength(StyleRef().ObjectPosition().Y(),
                            base_content_rect.Height() - final_rect.Height());
  final_rect.Move(PhysicalOffset(x_offset, y_offset));

  return final_rect;
}

PhysicalRect LayoutReplaced::ReplacedContentRect() const {
  NOT_DESTROYED();
  // This function should compute the result with old geometry even if a
  // BoxLayoutExtraInput exists.
  return ReplacedContentRectFrom(PhysicalContentBoxRect());
}

PhysicalRect LayoutReplaced::ReplacedContentRectFrom(
    const PhysicalRect& base_content_rect) const {
  NOT_DESTROYED();
  return ComputeReplacedContentRect(base_content_rect);
}

PhysicalRect LayoutReplaced::PreSnappedRectForPersistentSizing(
    const PhysicalRect& rect) {
  return PhysicalRect(rect.offset, PhysicalSize(ToRoundedSize(rect.size)));
}

void LayoutReplaced::ComputeIntrinsicSizingInfo(
    IntrinsicSizingInfo& intrinsic_sizing_info) const {
  NOT_DESTROYED();
  DCHECK(!ShouldApplySizeContainment());

  if (auto view_box = ComputeObjectViewBoxRect()) {
    intrinsic_sizing_info.size = gfx::SizeF(view_box->size);
  } else {
    intrinsic_sizing_info.size = gfx::SizeF(IntrinsicSize());
  }

  // Figure out if we need to compute an intrinsic ratio.
  if (!LayoutObjectHasIntrinsicAspectRatio(this))
    return;

  if (!intrinsic_sizing_info.size.IsEmpty())
    intrinsic_sizing_info.aspect_ratio = intrinsic_sizing_info.size;
}

static std::pair<LayoutUnit, LayoutUnit> SelectionTopAndBottom(
    const LayoutReplaced& layout_replaced) {
  // TODO(layout-dev): This code is buggy if the replaced element is relative
  // positioned.

  // The fallback answer when we can't find the containing line box of
  // |layout_replaced|.
  const std::pair<LayoutUnit, LayoutUnit> fallback(
      layout_replaced.LogicalTop(), layout_replaced.LogicalBottom());

  if (layout_replaced.IsInline() &&
      layout_replaced.IsInLayoutNGInlineFormattingContext()) {
    // Step 1: Find the line box containing |layout_replaced|.
    InlineCursor line_box;
    line_box.MoveTo(layout_replaced);
    if (!line_box)
      return fallback;
    line_box.MoveToContainingLine();
    if (!line_box)
      return fallback;

    // Step 2: Return the logical top and bottom of the line box.
    // TODO(layout-dev): Use selection top & bottom instead of line's, or decide
    // if we still want to distinguish line and selection heights in NG.
    const ComputedStyle& line_style = line_box.Current().Style();
    const auto writing_direction = line_style.GetWritingDirection();
    const WritingModeConverter converter(writing_direction,
                                         line_box.ContainerFragment().Size());
    PhysicalRect physical_rect = line_box.Current().RectInContainerFragment();
    // The caller expects it to be in the "stitched" coordinate space.
    physical_rect.offset +=
        OffsetInStitchedFragments(line_box.ContainerFragment());
    const LogicalRect logical_rect = converter.ToLogical(physical_rect);
    return {logical_rect.offset.block_offset, logical_rect.BlockEndOffset()};
  }

  return fallback;
}

PositionWithAffinity LayoutReplaced::PositionForPoint(
    const PhysicalOffset& point) const {
  NOT_DESTROYED();

  auto [top, bottom] = SelectionTopAndBottom(*this);

  LayoutUnit block_direction_position;
  LayoutUnit line_direction_position;
  if (RuntimeEnabledFeatures::SidewaysWritingModesEnabled()) {
    LogicalOffset logical_point =
        LocationContainer()->CreateWritingModeConverter().ToLogical(
            point + PhysicalLocation(), {});
    block_direction_position = logical_point.block_offset;
    line_direction_position = logical_point.inline_offset;
  } else {
    LayoutPoint flipped_point_in_container =
        LocationContainer()->FlipForWritingMode(point + PhysicalLocation());
    block_direction_position = IsHorizontalWritingMode()
                                   ? flipped_point_in_container.Y()
                                   : flipped_point_in_container.X();
    line_direction_position = IsHorizontalWritingMode()
                                  ? flipped_point_in_container.X()
                                  : flipped_point_in_container.Y();
  }

  if (block_direction_position < top)
    return PositionBeforeThis();  // coordinates are above

  if (block_direction_position >= bottom)
    return PositionBeforeThis();  // coordinates are below

  if (GetNode()) {
    const bool is_at_left_side =
        line_direction_position <= LogicalLeft() + (LogicalWidth() / 2);
    const bool is_at_start = is_at_left_side == IsLtr(ResolvedDirection());
    if (is_at_start)
      return PositionBeforeThis();
    return PositionAfterThis();
  }

  return LayoutBox::PositionForPoint(point);
}

PhysicalRect LayoutReplaced::LocalSelectionVisualRect() const {
  NOT_DESTROYED();
  if (GetSelectionState() == SelectionState::kNone ||
      GetSelectionState() == SelectionState::kContain) {
    return PhysicalRect();
  }

  if (IsInline() && IsInLayoutNGInlineFormattingContext()) {
    PhysicalRect rect;
    InlineCursor cursor;
    cursor.MoveTo(*this);
    for (; cursor; cursor.MoveToNextForSameLayoutObject())
      rect.Unite(cursor.CurrentLocalSelectionRectForReplaced());
    return rect;
  }

  // We're a block-level replaced element.  Just return our own dimensions.
  return PhysicalRect(PhysicalOffset(), Size());
}

bool LayoutReplaced::RespectsCSSOverflow() const {
  const Element* element = DynamicTo<Element>(GetNode());
  return element && element->IsReplacedElementRespectingCSSOverflow();
}

bool LayoutReplaced::ClipsToContentBox() const {
  if (!RespectsCSSOverflow()) {
    // If an svg is clipped, it is guaranteed to be clipped to the element's
    // content box.
    if (IsSVGRoot())
      return GetOverflowClipAxes() == kOverflowClipBothAxis;
    return true;
  }

  // TODO(khushalsagar): There can be more cases where the content clips to
  // content box. For instance, when padding is 0 and the reference box is the
  // padding box.
  const auto& overflow_clip_margin = StyleRef().OverflowClipMargin();
  return GetOverflowClipAxes() == kOverflowClipBothAxis &&
         overflow_clip_margin &&
         overflow_clip_margin->GetReferenceBox() ==
             StyleOverflowClipMargin::ReferenceBox::kContentBox &&
         !overflow_clip_margin->GetMargin();
}

}  // namespace blink
```