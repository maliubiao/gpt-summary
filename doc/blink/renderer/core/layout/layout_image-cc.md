Response:
Let's break down the thought process for analyzing the `LayoutImage.cc` file.

1. **Understand the Goal:** The request asks for the functionality of this specific Chromium Blink engine source file, its relationship to web technologies (JavaScript, HTML, CSS), examples of logical reasoning, and common usage errors.

2. **Initial Scan and Keywords:**  Quickly read through the code, looking for keywords and familiar concepts. Things that jump out include: `LayoutImage`, `ImageResource`, `HTMLImageElement`, `HTMLVideoElement`, `SVGImage`, `StyleDidChange`, `Paint`, `HitTest`, `IntrinsicSize`, `ObjectFit`, `ObjectPosition`. These keywords give a strong initial indication of the file's purpose: handling the layout and rendering of images (and potentially related media like video and SVG) within the browser.

3. **Identify Core Functionality:** Based on the keywords, start grouping related functionalities.

    * **Image Handling:**  The presence of `ImageResource`, `SetImageResource`, `ImageChanged`, and mentions of different image types (regular images, SVG) clearly points to the core responsibility of managing image loading, updating, and representation.
    * **Layout Integration:** The `LayoutImage` class itself, inheriting from `LayoutReplaced`, signifies its role in the layout process. Functions like `ComputeIntrinsicSizingInfo`, `NeedsLayoutOnIntrinsicSizeChange`, and `InvalidatePaintAndMarkForLayoutIfNeeded` confirm this.
    * **Rendering/Painting:**  Functions like `Paint`, `PaintReplaced`, and mentions of `ImagePainter` indicate involvement in the rendering pipeline.
    * **User Interaction:** `NodeAtPoint` and `AreaElementFocusChanged` suggest handling user interactions related to images, particularly image maps.
    * **Styling:** `StyleDidChange` and references to CSS properties like `object-fit`, `object-position`, `background-clip`, and `border` highlight the interaction with CSS styling.
    * **Performance:** The use of tracing (`TRACE_EVENT`), and comments about optimization (like the `MutableForPainting` section) suggest consideration for performance.

4. **Relate to Web Technologies (HTML, CSS, JavaScript):** Now, connect the identified functionalities to the core web technologies.

    * **HTML:**  The file directly interacts with HTML elements (`HTMLImageElement`, `HTMLVideoElement`, `HTMLAreaElement`). It manages the layout and rendering of these elements. The `<image>` tag is the primary target. Image maps (`<map>`, `<area>`) are also explicitly handled.
    * **CSS:** The file heavily relies on `ComputedStyle` and reacts to style changes (`StyleDidChange`). It interprets CSS properties related to image sizing, positioning, and rendering (`width`, `height`, `object-fit`, `object-position`, `background-clip`, `border`).
    * **JavaScript:** While this specific file isn't *directly* executing JavaScript, it's a core component of the browser that *enables* JavaScript to work with images. JavaScript can manipulate the `src` attribute of an `<img>` tag, trigger image loading, and potentially interact with image maps. The code itself doesn't execute JS, but it's part of the system that makes JS image manipulation possible.

5. **Identify Logical Reasoning and Create Examples:** Look for conditional logic and decision-making processes within the code.

    * **Intrinsic Size Calculation:** The code determines the image's natural size and how it should be displayed based on CSS properties. This involves logical checks based on whether the image is an SVG, whether explicit dimensions are set, and the `object-fit` property. A good example would be showing how different `object-fit` values affect the rendered size.
    * **Layout Invalidation:** The logic for determining when to relayout or repaint based on image loading or style changes involves conditional checks. An example would be the logic in `InvalidatePaintAndMarkForLayoutIfNeeded` based on `NeedsLayoutOnIntrinsicSizeChange`.
    * **Opacity Detection:** The `ForegroundIsKnownToBeOpaqueInRect` function has a series of checks to determine if the image is fully opaque. This is an example of logical deduction for optimization.

6. **Identify Potential Usage Errors:** Think about how developers might misuse HTML, CSS, or JavaScript in ways that relate to the functionality of this file.

    * **Incorrect `object-fit` and `object-position`:**  Misusing these properties can lead to unexpected image scaling or cropping.
    * **Missing Dimensions:** Not specifying dimensions for images can cause layout thrashing as the browser reflows when the image loads. The code highlights the concept of "unsized images."
    * **Incorrect Image Paths:**  Providing incorrect image URLs will trigger error handling within this file.
    * **Performance Issues with Large Images:** While the code doesn't directly *cause* this error, its role in rendering large images makes it relevant. Developers should optimize images for the web.

7. **Structure the Answer:** Organize the findings logically into categories like "Functionality," "Relationship to Web Technologies," "Logical Reasoning," and "Common Usage Errors."  Use clear and concise language, and provide specific code examples where possible (or describe the behavior the code implements).

8. **Review and Refine:**  Read through the generated answer, checking for accuracy, clarity, and completeness. Ensure the examples are relevant and easy to understand. For instance, initially, I might have focused too much on low-level implementation details. The refinement process helps to bring the explanation to a more user-centric and understandable level, focusing on the impact on web developers. Also, ensure the explanation flows well and addresses all parts of the original prompt.
好的，我们来详细分析一下 `blink/renderer/core/layout/layout_image.cc` 这个文件的功能。

**核心功能：**

`LayoutImage.cc` 文件定义了 `LayoutImage` 类，它是 Blink 渲染引擎中用于处理和布局 **图像** (包括 `<img>` 标签和通过 CSS `content` 属性插入的图像) 的核心类。它的主要职责包括：

1. **图像资源的持有和管理:**
   - 持有一个 `LayoutImageResource` 类型的成员变量 `image_resource_`，用于管理实际的图像数据（例如，从网络加载的图片）。
   - 负责初始化、更新和清理图像资源。
   - 监听图像加载状态的变化，并在图像加载完成、出错等状态改变时触发相应的操作。

2. **图像的布局计算:**
   - 继承自 `LayoutReplaced`，负责计算图像在页面布局中的位置和尺寸。
   - 考虑图像的固有尺寸 (intrinsic size)、CSS 样式 (如 `width`, `height`, `object-fit`, `object-position`) 以及容器的尺寸限制来确定最终的渲染尺寸。
   - 处理图像的 `intrinsic aspect ratio` (固有宽高比)。
   - 当图像的固有尺寸发生变化时，决定是否需要重新布局。

3. **图像的绘制 (Painting):**
   - 负责将图像绘制到屏幕上。
   - 使用 `ImagePainter` 类来执行实际的绘制操作。
   - 考虑图像的透明度、裁剪、滤镜等效果。
   - 处理图像的重绘需求。

4. **处理与图像相关的 HTML 元素:**
   - 与 `HTMLImageElement` 紧密关联，当 `HTMLImageElement` 的属性发生变化时，`LayoutImage` 会做出相应的更新。
   - 支持图像地图 (`<map>`, `<area>`) 的功能，响应用户在图像区域上的点击事件。

5. **性能优化:**
   - 实现了一些优化策略，例如判断图像是否完全不透明，以避免不必要的背景绘制。
   - 使用 tracing 技术来追踪图像大小变化的性能。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`LayoutImage` 类是连接 HTML、CSS 和 JavaScript 的关键桥梁，它负责将这些技术对图像的描述转化为实际的视觉呈现。

* **HTML:**
    - `LayoutImage` 直接对应 HTML 中的 `<img>` 标签。当浏览器解析到 `<img>` 标签时，会创建相应的 `LayoutImage` 对象。
    - **举例:** 当 HTML 中有 `<img src="image.png">` 时，Blink 会创建一个 `LayoutImage` 对象来处理 `image.png` 的加载、布局和绘制。
    - `LayoutImage` 也处理通过 CSS `content` 属性插入的图像，例如 `::before` 和 `::after` 伪元素。
    - **举例:** CSS 规则 `div::before { content: url(icon.png); }` 会导致创建一个匿名的 `LayoutImage` 对象来处理 `icon.png`。
    - `LayoutImage` 还会处理 `<video>` 元素的 poster 图像。

* **CSS:**
    - `LayoutImage` 广泛使用和解释 CSS 属性来确定图像的显示方式。
    - **举例:**
        - `width` 和 `height`:  CSS 的 `width` 和 `height` 属性直接影响 `LayoutImage` 计算出的图像尺寸。
        - `object-fit`:  `LayoutImage` 根据 `object-fit` 的值（如 `contain`, `cover`, `fill` 等）来调整图像在其容器内的缩放和裁剪方式。 例如，`object-fit: cover` 会让图像保持宽高比并尽可能覆盖整个容器，可能会裁剪图像。
        - `object-position`:  `LayoutImage` 根据 `object-position` 的值来调整图像在其容器内的位置。 例如，`object-position: top left` 会将图像的左上角对齐到容器的左上角。
        - `background-clip`: 影响 `LayoutImage` 中背景的绘制范围。
        - `border`: 影响 `LayoutImage` 的边框绘制。
        - `image-orientation`: 影响图像的显示方向。
    - 当 CSS 样式发生变化时 (`StyleDidChange`)，`LayoutImage` 会重新计算布局和触发重绘。

* **JavaScript:**
    - JavaScript 可以通过 DOM API 操作 `<img>` 标签的属性，例如修改 `src` 属性来更换图像源。
    - **举例:** JavaScript 代码 `document.getElementById('myImage').src = 'new_image.jpg';` 会导致 `LayoutImage` 重新加载并渲染新的图像。
    - JavaScript 可以监听图像的加载事件 (`onload`, `onerror`)，这些事件是由 Blink 引擎在 `LayoutImage` 处理图像加载状态时触发的。
    - JavaScript 可以通过 Canvas API 来操作图像，虽然 `LayoutImage` 本身不直接涉及 Canvas，但它是将 HTML 中的 `<img>` 元素渲染到屏幕的基础，Canvas 可以获取这些渲染结果进行进一步处理。

**逻辑推理举例 (假设输入与输出):**

假设我们有以下 HTML 和 CSS：

```html
<img id="myImage" src="flower.jpg" style="width: 200px; height: 150px; object-fit: contain;">
```

**假设输入:**

1. **HTML 解析器:**  解析到 `<img>` 标签，提取 `src` 属性为 "flower.jpg"，`id` 为 "myImage"。
2. **CSS 解析器:** 解析到内联样式 `width: 200px; height: 150px; object-fit: contain;`。
3. **图像加载器:** 成功加载了 "flower.jpg"，其固有尺寸为 400px x 300px。

**逻辑推理过程 (在 `LayoutImage.cc` 中可能发生的):**

1. **创建 `LayoutImage` 对象:**  为 `<img>` 元素创建一个 `LayoutImage` 对象。
2. **设置图像资源:** `LayoutImage` 开始加载 "flower.jpg"。
3. **应用 CSS 样式:**  `LayoutImage` 获取到 CSS 样式：`width: 200px`, `height: 150px`, `object-fit: contain`。
4. **计算布局尺寸:**
   - 容器尺寸为 200px x 150px。
   - 图像固有尺寸为 400px x 300px，固有宽高比为 4:3 (或 1.33)。
   - `object-fit: contain` 表示图像保持宽高比并完整显示在容器内，可能会有留白。
   - 计算缩放比例：
     - 宽度缩放比例: 200px / 400px = 0.5
     - 高度缩放比例: 150px / 300px = 0.5
   - 选择较小的缩放比例 (0.5) 以确保完整显示。
   - 计算最终渲染尺寸：200px x 150px (因为缩放后正好填满)。
5. **绘制图像:**  `ImagePainter` 使用计算出的尺寸和图像数据进行绘制。

**假设输出:**

- 图像将在页面上渲染，尺寸为 200px x 150px。
- 图像会完整显示在其 200px x 150px 的区域内，没有裁剪，可能会有背景留白 (如果容器背景不是透明的)。

**用户或编程常见的使用错误举例:**

1. **未指定图像尺寸:**
   - **错误:** HTML 中只写了 `<img src="myimage.jpg">`，没有指定 `width` 和 `height` 属性，CSS 中也没有明确指定尺寸。
   - **后果:** 浏览器需要等到图像加载完成后才能知道其固有尺寸，这可能导致页面布局在图像加载完成时发生跳动 (layout shift)。
   - **`LayoutImage` 的行为:**  `LayoutImage` 最初可能以 0x0 的尺寸布局，当图像加载完成后，会更新固有尺寸，并触发重新布局。

2. **`object-fit` 和 `object-position` 使用不当:**
   - **错误:**  错误地使用 `object-fit` 和 `object-position` 可能导致图像显示不符合预期，例如图像被过度拉伸或只显示一部分。
   - **`LayoutImage` 的行为:** `LayoutImage` 会严格按照 CSS 属性的定义来计算和渲染图像，如果属性值不合理，就会出现视觉问题。

3. **图像路径错误:**
   - **错误:**  `<img>` 标签的 `src` 属性指向一个不存在或无法访问的图像文件。
   - **`LayoutImage` 的行为:** `LayoutImage` 无法加载图像资源，会触发错误处理，可能显示一个默认的损坏图像图标或者 `alt` 属性的文本。代码中可以看到对 `image_resource_->ErrorOccurred()` 的检查。

4. **大量未优化的图像:**
   - **错误:** 页面包含大量体积过大、未压缩的图像。
   - **后果:** 页面加载速度慢，消耗用户流量。
   - **`LayoutImage` 的行为:** `LayoutImage` 负责渲染这些图像，但其性能受到图像大小的影响。虽然 `LayoutImage` 本身不负责图像优化，但它暴露的性能指标（例如加载时间）可以帮助开发者发现问题。

5. **在 JavaScript 中频繁修改图像 `src` 属性:**
   - **错误:**  JavaScript 代码频繁地修改 `<img>` 标签的 `src` 属性，导致浏览器不断地加载和渲染新的图像。
   - **后果:**  可能导致性能问题，消耗大量资源。
   - **`LayoutImage` 的行为:**  每次 `src` 属性改变，`LayoutImage` 都会尝试加载新的图像资源并触发重新布局和重绘。

总而言之，`LayoutImage.cc` 是 Blink 渲染引擎中处理图像显示的核心组件，它深入参与了图像的加载、布局、绘制以及与 HTML、CSS 和 JavaScript 的交互过程。理解其功能有助于开发者更好地掌握浏览器如何渲染图像，并避免常见的开发错误。

### 提示词
```
这是目录为blink/renderer/core/layout/layout_image.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2000 Dirk Mueller (mueller@kde.org)
 *           (C) 2006 Allan Sandfeld Jensen (kde@carewolf.com)
 *           (C) 2006 Samuel Weinig (sam.weinig@gmail.com)
 * Copyright (C) 2003, 2004, 2005, 2006, 2008, 2009, 2010, 2011 Apple Inc.
 *               All rights reserved.
 * Copyright (C) 2010 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/layout/layout_image.h"

#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/html_area_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/intrinsic_sizing_info.h"
#include "third_party/blink/renderer/core/layout/layout_video.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/loader/resource/image_resource_content.h"
#include "third_party/blink/renderer/core/paint/image_painter.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/timing/image_element_timing.h"
#include "third_party/blink/renderer/core/svg/graphics/svg_image.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "ui/gfx/geometry/size_conversions.h"

namespace blink {

LayoutImage::LayoutImage(Element* element)
    : LayoutReplaced(element, PhysicalSize()) {}

LayoutImage* LayoutImage::CreateAnonymous(Document& document) {
  LayoutImage* image = MakeGarbageCollected<LayoutImage>(nullptr);
  image->SetDocumentForAnonymous(&document);
  return image;
}

LayoutImage::~LayoutImage() = default;

void LayoutImage::Trace(Visitor* visitor) const {
  visitor->Trace(image_resource_);
  LayoutReplaced::Trace(visitor);
}

void LayoutImage::WillBeDestroyed() {
  NOT_DESTROYED();
  DCHECK(image_resource_);
  image_resource_->Shutdown();

  LayoutReplaced::WillBeDestroyed();
}

void GetImageSizeChangeTracingData(perfetto::TracedValue context,
                                   Node* node,
                                   LocalFrame* frame) {
  auto dict = std::move(context).WriteDictionary();
  dict.Add("nodeId", IdentifiersFactory::IntIdForNode(node));
  dict.Add("frameId", IdentifiersFactory::FrameId(frame));
}

void LayoutImage::StyleDidChange(StyleDifference diff,
                                 const ComputedStyle* old_style) {
  NOT_DESTROYED();
  LayoutReplaced::StyleDidChange(diff, old_style);

  RespectImageOrientationEnum old_orientation =
      old_style ? old_style->ImageOrientation()
                : ComputedStyleInitialValues::InitialImageOrientation();
  if (StyleRef().ImageOrientation() != old_orientation) {
    IntrinsicSizeChanged();
  }

  bool tracing_enabled;
  TRACE_EVENT_CATEGORY_GROUP_ENABLED(
      TRACE_DISABLED_BY_DEFAULT("devtools.timeline"), &tracing_enabled);

  if (tracing_enabled) {
    bool is_unsized = this->IsUnsizedImage();
    if (is_unsized) {
      Node* node = GetNode();
      TRACE_EVENT_INSTANT_WITH_TIMESTAMP1(
          "devtools.timeline", "LayoutImageUnsized", TRACE_EVENT_SCOPE_THREAD,
          base::TimeTicks::Now(), "data", [&](perfetto::TracedValue ctx) {
            GetImageSizeChangeTracingData(std::move(ctx), node, GetFrame());
          });
    }
  }
}

void LayoutImage::SetImageResource(LayoutImageResource* image_resource) {
  NOT_DESTROYED();
  DCHECK(!image_resource_);
  image_resource_ = image_resource;
  image_resource_->Initialize(this);
}

void LayoutImage::ImageChanged(WrappedImagePtr new_image,
                               CanDeferInvalidation defer) {
  NOT_DESTROYED();
  DCHECK(View());
  DCHECK(View()->GetFrameView());
  if (DocumentBeingDestroyed())
    return;

  if (HasBoxDecorationBackground() || HasMask() || HasShapeOutside() ||
      HasReflection())
    LayoutReplaced::ImageChanged(new_image, defer);

  if (!image_resource_)
    return;

  if (new_image != image_resource_->ImagePtr())
    return;

  auto* html_image_element = DynamicTo<HTMLImageElement>(GetNode());
  if (IsGeneratedContent() && html_image_element &&
      image_resource_->ErrorOccurred()) {
    html_image_element->EnsureFallbackForGeneratedContent();
    return;
  }

  // If error occurred, image marker should be replaced by a LayoutText.
  // NotifyOfSubtreeChange to make list item updating its marker content.
  if (IsListMarkerImage() && image_resource_->ErrorOccurred()) {
    LayoutObject* item = this;
    while (item->IsAnonymous())
      item = item->Parent();
    DCHECK(item);
    if (item->NotifyOfSubtreeChange())
      item->GetNode()->MarkAncestorsWithChildNeedsStyleRecalc();
  }

  // Per the spec, we let the server-sent header override srcset/other sources
  // of dpr.
  // https://github.com/igrigorik/http-client-hints/blob/master/draft-grigorik-http-client-hints-01.txt#L255
  if (image_resource_->CachedImage() &&
      image_resource_->CachedImage()->HasDevicePixelRatioHeaderValue()) {
    UseCounter::Count(GetDocument(), WebFeature::kClientHintsContentDPR);
    image_device_pixel_ratio_ =
        1 / image_resource_->CachedImage()->DevicePixelRatioHeaderValue();
  }

  if (!did_increment_visually_non_empty_pixel_count_) {
    // At a zoom level of 1 the image is guaranteed to have an integer size.
    View()->GetFrameView()->IncrementVisuallyNonEmptyPixelCount(
        gfx::ToFlooredSize(image_resource_->ImageSize(1.0f)));
    did_increment_visually_non_empty_pixel_count_ = true;
  }

  // The replaced content transform depends on the intrinsic size (see:
  // FragmentPaintPropertyTreeBuilder::UpdateReplacedContentTransform).
  SetNeedsPaintPropertyUpdate();
  InvalidatePaintAndMarkForLayoutIfNeeded(defer);
}

void LayoutImage::UpdateIntrinsicSizeIfNeeded(const PhysicalSize& new_size) {
  NOT_DESTROYED();
  if (image_resource_->ErrorOccurred())
    return;
  SetIntrinsicSize(new_size);
}

bool LayoutImage::NeedsLayoutOnIntrinsicSizeChange() const {
  NOT_DESTROYED();
  // Flex layout algorithm uses the intrinsic image width/height even if
  // width/height are specified.
  if (IsFlexItem()) {
    return true;
  }

  const auto& style = StyleRef();
  // TODO(https://crbug.com/313072): Should this test min/max-height as well?
  bool is_fixed_sized =
      style.LogicalWidth().IsFixed() && style.LogicalHeight().IsFixed() &&
      (style.LogicalMinWidth().IsFixed() || style.LogicalMinWidth().IsAuto()) &&
      (style.LogicalMaxWidth().IsFixed() || style.LogicalMaxWidth().IsNone());
  return !is_fixed_sized;
}

void LayoutImage::InvalidatePaintAndMarkForLayoutIfNeeded(
    CanDeferInvalidation defer) {
  NOT_DESTROYED();
  PhysicalSize old_intrinsic_size = IntrinsicSize();

  PhysicalSize new_intrinsic_size = PhysicalSize::FromSizeFRound(
      image_resource_->ImageSize(StyleRef().EffectiveZoom()));
  UpdateIntrinsicSizeIfNeeded(new_intrinsic_size);

  // In the case of generated image content using :before/:after/content, we
  // might not be in the layout tree yet. In that case, we just need to update
  // our intrinsic size. layout() will be called after we are inserted in the
  // tree which will take care of what we are doing here.
  if (!ContainingBlock())
    return;

  if (old_intrinsic_size != new_intrinsic_size) {
    SetIntrinsicLogicalWidthsDirty();

    if (NeedsLayoutOnIntrinsicSizeChange()) {
      SetNeedsLayoutAndFullPaintInvalidation(
          layout_invalidation_reason::kSizeChanged);
      return;
    }
  }

  SetShouldDoFullPaintInvalidationWithoutLayoutChange(
      PaintInvalidationReason::kImage);

  if (defer == CanDeferInvalidation::kYes && ImageResource() &&
      ImageResource()->MaybeAnimated())
    SetShouldDelayFullPaintInvalidation();
}

void LayoutImage::PaintReplaced(const PaintInfo& paint_info,
                                const PhysicalOffset& paint_offset) const {
  NOT_DESTROYED();
  if (ChildPaintBlockedByDisplayLock())
    return;
  ImagePainter(*this).PaintReplaced(paint_info, paint_offset);
}

void LayoutImage::Paint(const PaintInfo& paint_info) const {
  NOT_DESTROYED();
  ImagePainter(*this).Paint(paint_info);
}

void LayoutImage::AreaElementFocusChanged(HTMLAreaElement* area_element) {
  NOT_DESTROYED();
  DCHECK_EQ(area_element->ImageElement(), GetNode());

  if (area_element->GetPath(this).IsEmpty())
    return;

  InvalidatePaintAndMarkForLayoutIfNeeded(CanDeferInvalidation::kYes);
}

bool LayoutImage::ForegroundIsKnownToBeOpaqueInRect(
    const PhysicalRect& local_rect,
    unsigned) const {
  NOT_DESTROYED();
  if (ChildPaintBlockedByDisplayLock())
    return false;
  if (!image_resource_->HasImage() || image_resource_->ErrorOccurred())
    return false;
  ImageResourceContent* image_content = image_resource_->CachedImage();
  if (!image_content || !image_content->IsLoaded())
    return false;
  if (!PhysicalContentBoxRect().Contains(local_rect))
    return false;
  EFillBox background_clip = StyleRef().BackgroundClip();
  // Background paints under borders.
  if (background_clip == EFillBox::kBorder && StyleRef().HasBorder() &&
      !StyleRef().BorderObscuresBackground())
    return false;
  // Background shows in padding area.
  if ((background_clip == EFillBox::kBorder ||
       background_clip == EFillBox::kPadding) &&
      StyleRef().MayHavePadding())
    return false;
  // Object-position may leave parts of the content box empty, regardless of the
  // value of object-fit.
  if (StyleRef().ObjectPosition() !=
      ComputedStyleInitialValues::InitialObjectPosition())
    return false;
  // Object-fit may leave parts of the content box empty.
  EObjectFit object_fit = StyleRef().GetObjectFit();
  if (object_fit != EObjectFit::kFill && object_fit != EObjectFit::kCover)
    return false;
  // Check for image with alpha.
  DEVTOOLS_TIMELINE_TRACE_EVENT_WITH_CATEGORIES(
      TRACE_DISABLED_BY_DEFAULT("devtools.timeline"), "PaintImage",
      inspector_paint_image_event::Data, this, *image_content);
  return image_content->GetImage()->CurrentFrameKnownToBeOpaque();
}

bool LayoutImage::ComputeBackgroundIsKnownToBeObscured() const {
  NOT_DESTROYED();
  if (!StyleRef().HasBackground())
    return false;

  return ForegroundIsKnownToBeOpaqueInRect(BackgroundPaintedExtent(), 0);
}

HTMLMapElement* LayoutImage::ImageMap() const {
  NOT_DESTROYED();
  auto* i = DynamicTo<HTMLImageElement>(GetNode());
  return i ? i->GetTreeScope().GetImageMap(
                 i->FastGetAttribute(html_names::kUsemapAttr))
           : nullptr;
}

bool LayoutImage::NodeAtPoint(HitTestResult& result,
                              const HitTestLocation& hit_test_location,
                              const PhysicalOffset& accumulated_offset,
                              HitTestPhase phase) {
  NOT_DESTROYED();
  HitTestResult temp_result(result);
  bool inside = LayoutReplaced::NodeAtPoint(temp_result, hit_test_location,
                                            accumulated_offset, phase);

  if (!inside && result.GetHitTestRequest().ListBased())
    result.Append(temp_result);
  if (inside)
    result = temp_result;
  return inside;
}

bool LayoutImage::CanApplyObjectViewBox() const {
  if (!EmbeddedSVGImage()) {
    return true;
  }
  // Only apply object-view-box if the image has both natural width/height.
  const IntrinsicSizingInfo info =
      image_resource_->GetNaturalDimensions(StyleRef().EffectiveZoom());
  return info.has_width && info.has_height;
}

void LayoutImage::ComputeIntrinsicSizingInfo(
    IntrinsicSizingInfo& intrinsic_sizing_info) const {
  NOT_DESTROYED();
  DCHECK(!ShouldApplySizeContainment());
  if (EmbeddedSVGImage()) {
    intrinsic_sizing_info =
        image_resource_->GetNaturalDimensions(StyleRef().EffectiveZoom());

    if (auto view_box = ComputeObjectViewBoxRect()) {
      DCHECK(intrinsic_sizing_info.has_width);
      DCHECK(intrinsic_sizing_info.has_height);
      intrinsic_sizing_info.size = gfx::SizeF(view_box->size);
    }

    // The value returned by LayoutImageResource will be in zoomed CSS
    // pixels, but for the 'scale-down' object-fit value we want "zoomed
    // device pixels", so undo the DPR part here.
    if (StyleRef().GetObjectFit() == EObjectFit::kScaleDown) {
      intrinsic_sizing_info.size.InvScale(ImageDevicePixelRatio());
    }
    return;
  }

  LayoutReplaced::ComputeIntrinsicSizingInfo(intrinsic_sizing_info);

  // Don't compute an intrinsic ratio to preserve historical WebKit behavior if
  // we're painting alt text and/or a broken image.
  // Video is excluded from this behavior because video elements have a default
  // aspect ratio that a failed poster image load should not override.
  if (image_resource_ && image_resource_->ErrorOccurred() &&
      !IsA<LayoutVideo>(this)) {
    intrinsic_sizing_info.aspect_ratio = gfx::SizeF(1, 1);
    return;
  }
}

SVGImage* LayoutImage::EmbeddedSVGImage() const {
  NOT_DESTROYED();
  if (!image_resource_)
    return nullptr;
  ImageResourceContent* cached_image = image_resource_->CachedImage();
  // TODO(japhet): This shouldn't need to worry about cache validation.
  // https://crbug.com/761026
  if (!cached_image || cached_image->IsCacheValidator())
    return nullptr;
  return DynamicTo<SVGImage>(cached_image->GetImage());
}

bool LayoutImage::IsUnsizedImage() const {
  const ComputedStyle& style = this->StyleRef();
  const auto explicit_width = style.LogicalWidth().IsSpecified();
  const auto explicit_height = style.LogicalHeight().IsSpecified();
  bool has_aspect_ratio =
      style.AspectRatio().GetType() == EAspectRatioType::kRatio;
  const bool is_fixed_size =
      (explicit_width && explicit_height) ||
      (has_aspect_ratio && (explicit_width || explicit_height));
  return !is_fixed_size;
}

void LayoutImage::MutableForPainting::UpdatePaintedRect(
    const PhysicalRect& paint_rect) {
  // As an optimization for sprite sheets, an image may use the cull rect when
  // generating the display item. We need to invalidate the display item if
  // this rect changes.
  auto& image = To<LayoutImage>(layout_object_);
  if (image.last_paint_rect_ != paint_rect) {
    static_cast<const DisplayItemClient&>(layout_object_).Invalidate();
  }

  image.last_paint_rect_ = paint_rect;
}

}  // namespace blink
```