Response:
Let's break down the thought process to analyze the `svg_mask_painter.cc` file.

1. **Understand the Goal:** The primary goal is to analyze the provided C++ code snippet for its functionality, relationships with web technologies (HTML, CSS, JavaScript), logic, potential errors, and how a user might trigger its execution.

2. **Initial Scan and Keyword Recognition:**  Quickly read through the code, looking for familiar terms and patterns. Keywords like `SVG`, `Mask`, `Paint`, `GraphicsContext`, `Layout`, `Style`, `Image`, `Transform`, `Clip`, `Layer` immediately stand out. These provide strong hints about the file's purpose.

3. **Identify the Core Class:** The filename `svg_mask_painter.cc` and the presence of the `SVGMaskPainter` class indicate that this file is responsible for painting SVG masks.

4. **Function-by-Function Analysis (High-Level):** Go through each function in the class and try to understand its role based on its name and the code within.

    * `Paint()`: This is likely the main entry point for painting an SVG mask. It receives `GraphicsContext` and `LayoutObject` as arguments, standard parameters in Blink's rendering pipeline.
    * `PaintSVGMaskLayer()`:  This function seems responsible for painting a *single* SVG mask layer, as indicated by the `StyleMaskSourceImage` parameter.
    * `MaskIsValid()`:  This function likely checks if a given mask source is valid.
    * `ResourceBoundsForSVGChild()`: This function appears to calculate the bounding box of an SVG element that has a mask applied.

5. **Delve into Key Functions (Deeper Analysis):** Focus on the most important functions like `Paint()` and `PaintSVGMaskLayer()` to understand the core logic.

    * **`Paint()`:**
        * Notice the use of `PaintProperties`, `Mask`, `MaskClip`. This confirms the function deals with mask properties defined in CSS.
        * The use of `DrawingRecorder` suggests optimization by caching drawing operations.
        * The loop iterating through `MaskLayers()` hints at the possibility of multiple mask layers being applied.
        * The call to `PaintMaskLayer()` indicates that the actual painting of each layer is delegated.

    * **`PaintSVGMaskLayer()`:**
        * `ResolveElementReference()`:  This is crucial. It means the mask is likely defined as a `<mask>` element within the SVG or referenced externally.
        * `MaskToContentTransform()`:  This strongly suggests that the mask's coordinate system might be different from the element being masked, requiring transformations. The `objectBoundingBox` unit is a key factor here.
        * `CreatePaintRecord()`: This implies the mask itself is rendered into a separate paint record.
        * The `context.Clip()` confirms that the mask's boundaries are used for clipping.
        * The `context.BeginLayer()` and `context.EndLayer()` with blending modes (`composite_op`) are essential for how the mask is applied (e.g., alpha masks, luminance masks).

6. **Identify Connections to Web Technologies:**

    * **CSS:** The presence of `StyleMaskSourceImage`, `FillLayer`, `EFillMaskMode`, and the mention of mask properties (`mask-image`, `mask-mode`, `mask-units`, etc.) directly link this code to CSS mask properties.
    * **HTML:** The concept of an SVG `<mask>` element referenced by CSS is a direct HTML connection. The code also handles masking of foreign objects (`<foreignObject>`).
    * **JavaScript:** While the C++ code doesn't directly *execute* JavaScript, JavaScript can manipulate the DOM and CSS styles, which in turn triggers the rendering pipeline that calls this code. For example, JavaScript could change the `mask-image` property.

7. **Infer Logic and Potential Issues:**

    * **Assumptions:**  The code assumes that the `LayoutObject` and its associated `PaintProperties` are correctly set up. It also relies on the correct resolution of SVG resources.
    * **Potential Errors:**
        * Invalid mask URLs or IDs.
        * Circular dependencies in mask definitions.
        * Performance issues if masks are overly complex or frequently redrawn.
        * Incorrect understanding of `objectBoundingBox` units can lead to unexpected mask scaling.

8. **Construct Examples:** Based on the understanding of the code and its connections, create concrete examples of HTML, CSS, and JavaScript that would lead to this code being executed. Think about how a user would interact with a webpage to trigger the mask rendering.

9. **Debugging Scenarios:**  Consider how a developer might end up inspecting this code. Common scenarios include:
    * Visual rendering problems with masks.
    * Performance bottlenecks related to mask rendering.
    * Crashes or errors related to invalid mask definitions.

10. **Structure the Answer:** Organize the findings logically, starting with a summary of the file's function, then elaborating on connections to web technologies, logic, potential errors, and finally, debugging scenarios. Use clear headings and examples to make the information accessible.

11. **Refine and Review:**  Read through the generated answer to ensure clarity, accuracy, and completeness. Check for any inconsistencies or missing information. For example, initially, I might have missed the details about `mask-mode` (luminance vs. alpha) and would need to add that upon closer review of the `PaintSVGMaskLayer` function. Also, ensuring the explanation of `objectBoundingBox` is clear is important.
这个文件 `blink/renderer/core/paint/svg_mask_painter.cc` 的主要功能是 **负责在 Chromium Blink 渲染引擎中绘制 SVG 蒙版 (masks)**。它处理将 SVG 的 `<mask>` 元素应用到其他 HTML 或 SVG 元素上的过程。

以下是更详细的功能列表以及与 JavaScript、HTML 和 CSS 的关系说明：

**功能列表:**

1. **解析和访问 SVG 蒙版资源:**
   -  `ResolveElementReference`:  接收 CSS 中 `mask-image` 属性指定的 SVG 蒙版资源的 URL 或 ID，并解析它以获取对应的 `LayoutSVGResourceMasker` 对象。这个对象包含了蒙版的布局信息和绘制信息。
   -  `GetSVGResource` 和 `GetSVGResourceClient`: 用于获取 SVG 资源及其客户端，这是 Blink 中管理 SVG 资源的通用机制。

2. **计算蒙版坐标和变换:**
   - `MaskToContentTransform`:  根据 `mask-units` CSS 属性（`objectBoundingBox` 或 `userSpaceOnUse`）以及可能的缩放因子，计算将蒙版坐标空间转换到被蒙版元素内容空间的变换矩阵。
   -  处理 `objectBoundingBox`：如果 `mask-units` 设置为 `objectBoundingBox`，蒙版的大小和位置会相对于被蒙版元素的边界框进行缩放和定位。

3. **绘制蒙版内容:**
   - `PaintSVGMaskLayer`: 这是绘制单个 SVG 蒙版层的核心函数。它接收 `StyleMaskSourceImage` 对象（包含了蒙版资源的信息）、观察者（用于跟踪资源加载）、参考框、缩放因子、合成操作和蒙版类型。
   - `CreatePaintRecord`:  调用 `LayoutSVGResourceMasker` 的方法来生成蒙版的绘制记录（PaintRecord）。绘制记录包含了绘制蒙版所需的所有指令。
   - `context.Clip`:  使用蒙版的边界框对绘制上下文进行裁剪，确保只在蒙版区域内绘制。
   - `context.BeginLayer` 和 `context.EndLayer`:  创建图形上下文图层，用于应用合成操作（如混合模式）和蒙版类型（如亮度蒙版）。
   - `context.DrawRecord`:  将之前生成的蒙版绘制记录绘制到图形上下文中。

4. **处理蒙版图层:**
   - `PaintMaskLayer`: 处理 CSS 中可能存在的多个 `mask-image` 图层。它根据 `mask-mode` 属性（如 `alpha` 或 `luminance`）来设置相应的合成操作。
   - 迭代 `MaskLayers()`:  遍历元素上定义的所有蒙版图层。

5. **优化绘制:**
   - `DrawingRecorder::UseCachedDrawingIfPossible`: 尝试重用之前绘制的蒙版内容，以提高性能。

6. **验证蒙版:**
   - `MaskIsValid`: 检查指定的蒙版资源是否有效。

7. **计算蒙版影响的边界:**
   - `ResourceBoundsForSVGChild`:  计算应用了蒙版的 SVG 子元素的边界框。

**与 JavaScript, HTML, CSS 的关系：**

* **HTML:**
    - **`<mask>` 元素:**  这个文件处理的核心是 HTML 中的 `<mask>` 元素。用户在 HTML 中定义 `<mask>` 元素，其中包含了用于定义蒙版形状的图形元素（如 `<rect>`, `<circle>`, `<path>` 等）。
    - **`<img>`, `<div>` 等元素:**  虽然这个文件专注于蒙版的绘制，但蒙版最终会应用到其他 HTML 元素上，影响它们的可见区域。

* **CSS:**
    - **`mask-image`:**  这是最关键的 CSS 属性，用于指定要用作蒙版的图像或 SVG 元素。`SVGMaskPainter` 通过解析 `mask-image` 的值来找到对应的 `<mask>` 元素。
        ```css
        .masked-element {
          mask-image: url(#myMask); /* 引用 ID 为 "myMask" 的 <mask> 元素 */
        }
        ```
        **假设输入:** CSS 规则中 `mask-image: url(#myMask);`，其中 `#myMask` 指向 HTML 中定义的 `<mask id="myMask">...</mask>`。
        **输出:**  `ResolveElementReference` 函数会尝试找到并返回与 ID "myMask" 关联的 `LayoutSVGResourceMasker` 对象。
    - **`mask-mode`:**  决定蒙版是作为亮度蒙版还是 Alpha 蒙版。`PaintMaskLayer` 函数会根据这个属性设置合成操作。
        ```css
        .masked-element {
          mask-image: url(mask.png);
          mask-mode: luminance; /* 使用蒙版的亮度值来控制透明度 */
        }
        ```
        **假设输入:**  CSS 规则中 `mask-mode: luminance;`。
        **输出:**  在 `PaintMaskLayer` 中，会创建一个亮度图层，使用蒙版图像的亮度值来影响最终的颜色。
    - **`mask-units`:**  指定蒙版的坐标系统是相对于被蒙版元素的边界框 (`objectBoundingBox`) 还是用户空间 (`userSpaceOnUse`)。`MaskToContentTransform` 函数会根据这个属性计算变换。
        ```css
        .masked-element {
          mask-image: url(#myMask);
          mask-units: objectBoundingBox; /* 蒙版相对于元素的边界框 */
        }
        ```
        **假设输入:** CSS 规则中 `mask-units: objectBoundingBox;`。
        **输出:** `MaskToContentTransform` 会计算一个变换矩阵，将蒙版的坐标映射到被蒙版元素的边界框坐标系。
    - **`mask-repeat`, `mask-position`, `mask-size`, `mask-origin`, `mask-clip`:** 这些属性也会影响蒙版的绘制方式，尽管在这个文件中可能没有直接的处理逻辑，但它们会影响 `BackgroundImageGeometry` 的计算，进而影响蒙版的应用。

* **JavaScript:**
    - JavaScript 可以动态地修改元素的 CSS 样式，包括与蒙版相关的属性。当 JavaScript 更改了 `mask-image` 或其他蒙版属性时，会导致重新布局和重绘，最终会调用 `SVGMaskPainter` 来更新蒙版的绘制。
    ```javascript
    const element = document.querySelector('.masked-element');
    element.style.maskImage = 'url(#newMask)';
    ```
    **用户操作与调试线索：** 用户通过 JavaScript 改变元素的 `mask-image` 属性。作为调试线索，你可以在浏览器的开发者工具中观察到：
        1. **Elements 面板:** 检查被蒙版元素的样式，确认 `mask-image` 属性已更新。
        2. **Performance 面板:**  查看是否有 Layout 或 Paint 事件发生，这表明蒙版发生了变化需要重新绘制。
        3. **Sources 面板:**  在 `blink/renderer/core/paint/svg_mask_painter.cc` 中设置断点，例如在 `Paint` 或 `PaintSVGMaskLayer` 函数的入口处，来跟踪蒙版绘制的流程。

**逻辑推理的例子:**

假设输入：
- HTML 中定义了一个 `<mask id="circleMask"><circle cx="50" cy="50" r="40" fill="white"/></mask>`。
- CSS 中定义了 `.masked { mask-image: url(#circleMask); width: 100px; height: 100px; }`。

逻辑推理过程：
1. 当浏览器渲染带有 `.masked` 类的元素时，会遇到 `mask-image` 属性。
2. `SVGMaskPainter::Paint` 函数会被调用。
3. `ResolveElementReference` 会找到 ID 为 `circleMask` 的 `<mask>` 元素，并创建一个 `LayoutSVGResourceMasker` 对象。
4. `MaskToContentTransform` 根据默认的 `objectBoundingBox` 单位计算变换，将圆形蒙版缩放到 100x100 的边界框内。
5. `PaintSVGMaskLayer` 会创建一个包含白色圆形的绘制记录。
6. 最终，在被蒙版元素的区域内，只有与白色圆形重叠的部分会显示出来，形成一个圆形遮罩的效果。

**用户或编程常见的使用错误:**

1. **错误的 `mask-image` URL 或 ID:**
   - **错误示例:** CSS 中 `mask-image: url(#nonExistentMask);`，但 HTML 中没有定义 ID 为 `nonExistentMask` 的 `<mask>` 元素。
   - **结果:** 蒙版不会生效，或者浏览器会显示一个错误。
   - **调试线索:** 检查开发者工具的 Elements 面板，查看 `mask-image` 属性是否正确指向了现有的蒙版元素。查看控制台是否有关于资源加载失败的错误。

2. **循环引用:**
   - **错误示例:**  一个 `<mask>` 元素内部引用了自身，或者形成了循环依赖的引用链。
   - **结果:**  可能导致无限循环或堆栈溢出，浏览器可能会崩溃或卡死。
   - **调试线索:**  仔细检查 `<mask>` 元素内部的 `<mask>` 或其他引用，确保没有形成闭环。

3. **误解 `mask-units` 的作用:**
   - **错误示例:**  期望蒙版按照用户空间坐标工作，但 `mask-units` 设置为 `objectBoundingBox`，导致蒙版相对于被蒙版元素的大小进行缩放，可能产生意想不到的效果。
   - **结果:** 蒙版的大小和位置与预期不符。
   - **调试线索:**  检查 `mask-units` 属性的值，理解其对蒙版坐标系统的影响。在开发者工具中调整 `mask-units` 的值，观察效果变化。

4. **复杂的蒙版性能问题:**
   - **错误示例:**  使用包含大量复杂路径或滤镜的 `<mask>` 元素。
   - **结果:**  可能导致渲染性能下降，页面出现卡顿。
   - **调试线索:**  使用浏览器的 Performance 面板分析渲染性能，查看 Paint 操作的耗时。简化蒙版的内容，或者考虑使用其他优化技术。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在 HTML 中定义了带有 `<mask>` 元素的 SVG。**
2. **用户在 CSS 中为某个 HTML 元素设置了 `mask-image` 属性，指向了上面定义的 `<mask>` 元素。**
3. **当浏览器渲染这个 HTML 元素时，渲染引擎会解析 CSS 样式。**
4. **发现 `mask-image` 属性后，渲染引擎需要绘制蒙版效果。**
5. **Blink 的渲染流程会调用 `SVGMaskPainter::Paint` 函数。**
6. **`Paint` 函数会进一步调用其他辅助函数，如 `ResolveElementReference` 来获取蒙版资源，`MaskToContentTransform` 计算变换，以及 `PaintSVGMaskLayer` 来实际绘制蒙版。**

作为调试线索，当你遇到 SVG 蒙版显示不正确或性能问题时，可以按照以下步骤进行排查：

1. **检查 HTML 结构:** 确保 `<mask>` 元素的定义是正确的，包含了所需的图形元素。
2. **检查 CSS 样式:** 确认 `mask-image` 属性的值是否正确指向了 `<mask>` 元素，以及其他蒙版相关属性（如 `mask-mode`, `mask-units`）的设置是否符合预期。
3. **使用浏览器开发者工具:**
   - **Elements 面板:** 查看元素的 Computed 样式，确认蒙版相关的 CSS 属性是否生效。
   - **Performance 面板:**  记录渲染过程，查看是否有 Paint 操作，以及与蒙版相关的绘制操作的耗时。
   - **Sources 面板:** 在 `blink/renderer/core/paint/svg_mask_painter.cc` 文件中设置断点，跟踪代码执行流程，查看关键变量的值，例如蒙版资源的解析结果、变换矩阵的计算结果等。
4. **简化问题:**  尝试创建一个最小化的可复现问题的示例，排除其他因素的干扰。
5. **查阅文档:**  参考 SVG 和 CSS 蒙版的官方文档，了解各个属性的含义和用法。

通过以上分析，我们可以理解 `svg_mask_painter.cc` 文件在 Chromium Blink 渲染引擎中扮演着关键的角色，它连接了 HTML 中定义的 SVG 蒙版和 CSS 中应用的蒙版样式，最终将其渲染到屏幕上。理解其功能和与前端技术的关系，有助于我们更好地开发和调试使用了 SVG 蒙版的网页。

### 提示词
```
这是目录为blink/renderer/core/paint/svg_mask_painter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/svg_mask_painter.h"

#include "base/containers/adapters.h"
#include "cc/paint/color_filter.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_resource_masker.h"
#include "third_party/blink/renderer/core/layout/svg/svg_layout_support.h"
#include "third_party/blink/renderer/core/layout/svg/svg_resources.h"
#include "third_party/blink/renderer/core/paint/background_image_geometry.h"
#include "third_party/blink/renderer/core/paint/object_paint_properties.h"
#include "third_party/blink/renderer/core/paint/paint_auto_dark_mode.h"
#include "third_party/blink/renderer/core/paint/svg_background_paint_context.h"
#include "third_party/blink/renderer/core/style/style_mask_source_image.h"
#include "third_party/blink/renderer/core/svg/svg_length_functions.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context_state_saver.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_display_item.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_controller.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_record_builder.h"
#include "third_party/blink/renderer/platform/graphics/paint/scoped_paint_chunk_properties.h"
#include "third_party/blink/renderer/platform/graphics/scoped_image_rendering_settings.h"
#include "ui/gfx/geometry/rect_conversions.h"

namespace blink {

namespace {

AffineTransform MaskToContentTransform(const LayoutSVGResourceMasker& masker,
                                       const gfx::RectF& reference_box,
                                       float zoom) {
  AffineTransform content_transformation;
  if (masker.MaskContentUnits() ==
      SVGUnitTypes::kSvgUnitTypeObjectboundingbox) {
    content_transformation.Translate(reference_box.x(), reference_box.y());
    content_transformation.ScaleNonUniform(reference_box.width(),
                                           reference_box.height());
  } else if (zoom != 1) {
    content_transformation.Scale(zoom);
  }
  return content_transformation;
}

LayoutSVGResourceMasker* ResolveElementReference(
    const StyleMaskSourceImage& mask_source,
    const ImageResourceObserver& observer) {
  SVGResource* mask_resource = mask_source.GetSVGResource();
  SVGResourceClient* client = mask_source.GetSVGResourceClient(observer);
  // The client should only be null if the resource is null.
  if (!client) {
    CHECK(!mask_resource);
    return nullptr;
  }
  auto* masker =
      GetSVGResourceAsType<LayoutSVGResourceMasker>(*client, mask_resource);
  if (!masker) {
    return nullptr;
  }
  if (DisplayLockUtilities::LockedAncestorPreventingLayout(*masker)) {
    return nullptr;
  }
  SECURITY_CHECK(!masker->SelfNeedsFullLayout());
  masker->ClearInvalidationMask();
  return masker;
}

class ScopedMaskLuminanceLayer {
  STACK_ALLOCATED();

 public:
  ScopedMaskLuminanceLayer(GraphicsContext& context, SkBlendMode composite_op)
      : context_(context) {
    context.BeginLayer(cc::ColorFilter::MakeLuma(), &composite_op);
  }
  ~ScopedMaskLuminanceLayer() { context_.EndLayer(); }

 private:
  GraphicsContext& context_;
};

const StyleMaskSourceImage* ToMaskSourceIfSVGMask(
    const StyleImage& style_image) {
  const auto* mask_source = DynamicTo<StyleMaskSourceImage>(style_image);
  if (!mask_source || !mask_source->HasSVGMask()) {
    return nullptr;
  }
  return mask_source;
}

void PaintMaskLayer(const FillLayer& layer,
                    const LayoutObject& object,
                    const SVGBackgroundPaintContext& bg_paint_context,
                    GraphicsContext& context) {
  const StyleImage* style_image = layer.GetImage();
  if (!style_image) {
    return;
  }

  std::optional<ScopedMaskLuminanceLayer> mask_luminance_scope;
  SkBlendMode composite_op = SkBlendMode::kSrcOver;
  // Don't use the operator if this is the bottom layer.
  if (layer.Next()) {
    composite_op = WebCoreCompositeToSkiaComposite(layer.Composite(),
                                                   layer.GetBlendMode());
  }

  if (layer.MaskMode() == EFillMaskMode::kLuminance) {
    mask_luminance_scope.emplace(context, composite_op);
    composite_op = SkBlendMode::kSrcOver;
  }

  const ComputedStyle& style = bg_paint_context.Style();
  const ImageResourceObserver& observer = object;
  const bool uses_zoomed_coordinates = object.IsSVGForeignObject();
  GraphicsContextStateSaver saver(context, false);

  // If the "image" referenced by the FillLayer is an SVG <mask> reference (and
  // this is a layer for a mask), then repeat, position, clip, origin and size
  // should have no effect.
  if (const auto* mask_source = ToMaskSourceIfSVGMask(*style_image)) {
    const float zoom = uses_zoomed_coordinates ? style.EffectiveZoom() : 1;
    gfx::RectF reference_box = SVGResources::ReferenceBoxForEffects(
        object, GeometryBox::kFillBox,
        SVGResources::ForeignObjectQuirk::kDisabled);
    reference_box.Scale(zoom);

    saver.Save();
    SVGMaskPainter::PaintSVGMaskLayer(
        context, *mask_source, observer, reference_box, zoom, composite_op,
        layer.MaskMode() == EFillMaskMode::kMatchSource);
    return;
  }

  BackgroundImageGeometry geometry;
  geometry.Calculate(layer, bg_paint_context);

  if (geometry.TileSize().IsEmpty()) {
    return;
  }

  const Document& document = object.GetDocument();
  scoped_refptr<Image> image = style_image->GetImage(
      observer, document, style, gfx::SizeF(geometry.TileSize()));
  if (!image) {
    return;
  }

  ScopedImageRenderingSettings image_rendering_settings_context(
      context, style.GetInterpolationQuality(), style.GetDynamicRangeLimit());

  // Adjust the coordinate space to consider zoom - which is applied to the
  // computed image geometry.
  if (!uses_zoomed_coordinates && style.EffectiveZoom() != 1) {
    const float inv_zoom = 1 / style.EffectiveZoom();
    saver.Save();
    context.Scale(inv_zoom, inv_zoom);
  }

  std::optional<GeometryBox> clip_box;
  switch (layer.Clip()) {
    case EFillBox::kText:
    case EFillBox::kNoClip:
      break;
    case EFillBox::kContent:
    case EFillBox::kFillBox:
    case EFillBox::kPadding:
      clip_box.emplace(GeometryBox::kFillBox);
      break;
    case EFillBox::kStrokeBox:
    case EFillBox::kBorder:
      clip_box.emplace(GeometryBox::kStrokeBox);
      break;
    case EFillBox::kViewBox:
      clip_box.emplace(GeometryBox::kViewBox);
      break;
  }
  if (clip_box) {
    gfx::RectF clip_rect = SVGResources::ReferenceBoxForEffects(
        object, *clip_box, SVGResources::ForeignObjectQuirk::kDisabled);
    clip_rect.Scale(style.EffectiveZoom());

    saver.SaveIfNeeded();
    context.Clip(clip_rect);
  }

  const RespectImageOrientationEnum respect_orientation =
      style_image->ForceOrientationIfNecessary(style.ImageOrientation());

  // Use the intrinsic size of the image if it has one, otherwise force the
  // generated image to be the tile size.
  // image-resolution information is baked into the given parameters, but we
  // need oriented size. That requires explicitly applying orientation here.
  Image::SizeConfig size_config;
  size_config.apply_orientation = respect_orientation;
  const gfx::SizeF intrinsic_tile_size =
      image->SizeWithConfigAsFloat(size_config);

  const gfx::RectF dest_rect(geometry.UnsnappedDestRect());

  // Note that this tile rect uses the image's pre-scaled size.
  ImageTilingInfo tiling_info;
  tiling_info.image_rect.set_size(intrinsic_tile_size);
  tiling_info.phase =
      dest_rect.origin() + gfx::Vector2dF(geometry.ComputePhase());
  tiling_info.spacing = gfx::SizeF(geometry.SpaceSize());
  tiling_info.scale = {
      geometry.TileSize().width / tiling_info.image_rect.width(),
      geometry.TileSize().height / tiling_info.image_rect.height()};

  auto image_auto_dark_mode = ImageClassifierHelper::GetImageAutoDarkMode(
      *document.GetFrame(), style, dest_rect, tiling_info.image_rect);
  // This call takes the unscaled image, applies the given scale, and paints it
  // into the dest rect using phase and the given repeat spacing. Note the
  // phase is already scaled.
  const ImagePaintTimingInfo paint_timing_info(false, false);
  context.DrawImageTiled(*image, dest_rect, tiling_info, image_auto_dark_mode,
                         paint_timing_info, composite_op, respect_orientation);
}

}  // namespace

void SVGMaskPainter::Paint(GraphicsContext& context,
                           const LayoutObject& layout_object,
                           const DisplayItemClient& display_item_client) {
  const auto* properties = layout_object.FirstFragment().PaintProperties();
  DCHECK(properties);
  DCHECK(properties->Mask());
  DCHECK(properties->MaskClip());
  PropertyTreeStateOrAlias property_tree_state(
      properties->Mask()->LocalTransformSpace(), *properties->MaskClip(),
      *properties->Mask());
  ScopedPaintChunkProperties scoped_paint_chunk_properties(
      context.GetPaintController(), property_tree_state, display_item_client,
      DisplayItem::kSVGMask);

  if (DrawingRecorder::UseCachedDrawingIfPossible(context, display_item_client,
                                                  DisplayItem::kSVGMask))
    return;

  // TODO(fs): Should clip this with the bounds of the mask's PaintRecord.
  gfx::RectF visual_rect = properties->MaskClip()->PaintClipRect().Rect();
  DrawingRecorder recorder(context, display_item_client, DisplayItem::kSVGMask,
                           gfx::ToEnclosingRect(visual_rect));

  Vector<const FillLayer*, 8> layer_list;
  for (const FillLayer* layer = &layout_object.StyleRef().MaskLayers(); layer;
       layer = layer->Next()) {
    layer_list.push_back(layer);
  }
  const SVGBackgroundPaintContext bg_paint_context(layout_object);
  for (const auto* layer : base::Reversed(layer_list)) {
    PaintMaskLayer(*layer, layout_object, bg_paint_context, context);
  }
}

void SVGMaskPainter::PaintSVGMaskLayer(GraphicsContext& context,
                                       const StyleMaskSourceImage& mask_source,
                                       const ImageResourceObserver& observer,
                                       const gfx::RectF& reference_box,
                                       const float zoom,
                                       const SkBlendMode composite_op,
                                       const bool apply_mask_type) {
  LayoutSVGResourceMasker* masker =
      ResolveElementReference(mask_source, observer);
  if (!masker) {
    return;
  }
  const AffineTransform content_transformation =
      MaskToContentTransform(*masker, reference_box, zoom);
  SubtreeContentTransformScope content_transform_scope(content_transformation);
  PaintRecord record = masker->CreatePaintRecord();

  context.Clip(masker->ResourceBoundingBox(reference_box, zoom));

  bool has_layer = false;
  if (apply_mask_type &&
      masker->StyleRef().MaskType() == EMaskType::kLuminance) {
    context.BeginLayer(cc::ColorFilter::MakeLuma(), &composite_op);
    has_layer = true;
  } else if (composite_op != SkBlendMode::kSrcOver) {
    context.BeginLayer(composite_op);
    has_layer = true;
  }
  context.ConcatCTM(content_transformation);
  context.DrawRecord(std::move(record));
  if (has_layer) {
    context.EndLayer();
  }
}

bool SVGMaskPainter::MaskIsValid(const StyleMaskSourceImage& mask_source,
                                 const ImageResourceObserver& observer) {
  return ResolveElementReference(mask_source, observer);
}

gfx::RectF SVGMaskPainter::ResourceBoundsForSVGChild(
    const LayoutObject& object) {
  const ComputedStyle& style = object.StyleRef();
  const gfx::RectF reference_box = SVGResources::ReferenceBoxForEffects(
      object, GeometryBox::kFillBox,
      SVGResources::ForeignObjectQuirk::kDisabled);
  const float reference_box_zoom =
      object.IsSVGForeignObject() ? style.EffectiveZoom() : 1;
  gfx::RectF bounds;
  for (const FillLayer* layer = &style.MaskLayers(); layer;
       layer = layer->Next()) {
    const auto* mask_source =
        DynamicTo<StyleMaskSourceImage>(layer->GetImage());
    if (!mask_source) {
      continue;
    }
    LayoutSVGResourceMasker* masker =
        ResolveElementReference(*mask_source, object);
    if (!masker) {
      continue;
    }
    const gfx::RectF svg_mask_bounds =
        masker->ResourceBoundingBox(reference_box, reference_box_zoom);
    bounds.Union(svg_mask_bounds);
  }
  return gfx::UnionRects(bounds, object.VisualRectInLocalSVGCoordinates());
}

}  // namespace blink
```