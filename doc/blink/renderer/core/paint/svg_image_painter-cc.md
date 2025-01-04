Response:
Let's break down the request and plan the response step-by-step.

**1. Understanding the Core Request:**

The request is to analyze the `svg_image_painter.cc` file in the Chromium Blink rendering engine. The key is to identify its functionalities and relate them to web technologies (JavaScript, HTML, CSS) where applicable. The request also asks for logic examples, potential user errors, and debugging tips.

**2. Deconstructing the File's Purpose:**

The filename `svg_image_painter.cc` immediately suggests its primary role: painting SVG images. The included headers confirm this, referencing layout objects (`LayoutSVGImage`, `LayoutImageResource`), paint infrastructure (`PaintInfo`, `ScopedSVGPaintState`), and SVG specific elements (`SVGImageElement`, `SVGAnimatedPreserveAspectRatio`).

**3. Identifying Key Functionalities:**

I need to go through the code and extract the distinct actions the `SVGImagePainter` performs. This involves looking at the methods and the operations within them:

*   `Paint()`: The main entry point for painting. It handles visibility, culling, and calls the foreground painting.
*   `PaintForeground()`:  The core logic for drawing the SVG image. This involves:
    *   Calculating the viewport size.
    *   Retrieving the image data.
    *   Determining the source and destination rectangles.
    *   Handling `preserveAspectRatio`.
    *   Triggering paint timing events.
    *   Applying rendering settings.
    *   Drawing the image using the `GraphicsContext`.
*   `ComputeImageViewportSize()`:  Calculates the size at which the SVG image should be rendered, taking into account `preserveAspectRatio`.

**4. Connecting to Web Technologies:**

This is crucial. How do the functionalities relate to HTML, CSS, and JavaScript?

*   **HTML:** The `<image>` tag in SVG is directly rendered by this code. The `src` attribute of the `<image>` tag fetches the SVG.
*   **CSS:**  CSS properties like `visibility`, `opacity`, `transform`, `object-fit`, `object-position`, and `image-rendering` all influence how the `SVGImagePainter` works. The `zoom` property is explicitly mentioned.
*   **JavaScript:** While this C++ code doesn't directly interact with JavaScript, JavaScript can manipulate the DOM (e.g., changing the `src` of an `<image>` or modifying CSS styles) that indirectly triggers this painting process. Also, the Paint Timing API, triggered here, is accessible via JavaScript.

**5. Crafting Examples:**

For each connection to web technologies, I need concrete examples:

*   **HTML:**  A simple `<svg>` with an `<image>` element.
*   **CSS:** Examples showing how `visibility`, `transform`, and `object-fit` affect SVG image rendering.
*   **JavaScript:**  A script that changes the `src` of an SVG image.

**6. Logical Reasoning (Hypothetical Inputs and Outputs):**

I'll pick a specific function, like `ComputeImageViewportSize()`, and demonstrate how different inputs (`preserveAspectRatio` values, image dimensions, container dimensions) lead to different output viewport sizes. This requires understanding the logic within that function.

**7. Identifying User/Programming Errors:**

Common pitfalls when working with SVG images:

*   Incorrect `preserveAspectRatio` values leading to unexpected scaling.
*   Missing or incorrect `viewBox` attribute in the SVG.
*   Server-side issues preventing the SVG from loading.
*   CSS styles unintentionally clipping or distorting the image.

**8. Debugging Walkthrough:**

How does a user's action lead to this code being executed?  I'll trace a simple scenario:

1. User opens a web page containing an SVG `<image>` element.
2. The browser parses the HTML and creates the DOM.
3. The layout engine calculates the position and size of the SVG image.
4. During the paint phase, the `SVGImagePainter` is invoked.

**9. Structuring the Response:**

I need to organize the information logically:

*   Start with a general overview of the file's purpose.
*   List the key functionalities clearly.
*   Provide detailed explanations and examples for the connections to HTML, CSS, and JavaScript.
*   Illustrate logical reasoning with input/output examples.
*   Describe common errors and how they manifest.
*   Outline the debugging steps.

**Self-Correction/Refinement during thought process:**

*   Initially, I might focus too heavily on the C++ code details. I need to constantly relate it back to the user's perspective and web technologies.
*   The "logical reasoning" part needs careful selection of a function and clear input/output examples. I'll choose `ComputeImageViewportSize()` as it directly deals with the visual presentation.
*   For user errors, I should focus on problems that are directly related to *displaying* SVG images, not just general SVG syntax errors.
*   The debugging section needs to be practical and relatable to a developer's workflow.

By following these steps and constantly refining the thinking process, I can generate a comprehensive and helpful response to the user's request.
这个 `blink/renderer/core/paint/svg_image_painter.cc` 文件是 Chromium Blink 渲染引擎中负责绘制 SVG `<image>` 元素的关键组件。它的主要功能是将 SVG 图像渲染到屏幕上。

以下是它的详细功能列表，以及与 JavaScript, HTML, CSS 的关系、逻辑推理、常见错误和调试线索：

**功能列表:**

1. **确定是否需要绘制:**
    *   检查绘制阶段 (`PaintPhase::kForeground`)。
    *   检查元素的可见性 (`layout_svg_image_.StyleRef().Visibility() != EVisibility::kVisible`)。
    *   检查 SVG 图像资源是否已加载 (`layout_svg_image_.ImageResource()->HasImage()`)。如果条件不满足，则不进行绘制。

2. **视口裁剪优化:**
    *   如果启用了裁剪优化 (`SVGModelObjectPainter::CanUseCullRect`)，则检查元素的裁剪矩形是否与当前的裁剪区域相交。如果不相交，则跳过绘制，提高性能。

3. **应用变换:**
    *   使用 `ScopedSVGTransformState` 应用 SVG 元素的局部变换 (`layout_svg_image_.LocalSVGTransform()`)，确保图像按照其定义的变换进行绘制。

4. **管理绘制状态:**
    *   使用 `ScopedSVGPaintState` 管理 SVG 特有的绘制状态，例如填充、描边等。

5. **记录命中测试和区域捕获数据:**
    *   调用 `SVGModelObjectPainter::RecordHitTestData` 和 `SVGModelObjectPainter::RecordRegionCaptureData` 记录用于鼠标事件命中测试和区域捕获的数据。

6. **利用缓存绘制:**
    *   使用 `DrawingRecorder::UseCachedDrawingIfPossible` 尝试使用之前绘制的缓存结果，避免重复绘制，提高性能。如果无法使用缓存，则会执行实际的绘制操作。

7. **实际绘制前景内容:**
    *   调用 `PaintForeground` 函数执行实际的 SVG 图像绘制逻辑。

8. **绘制轮廓 (可选):**
    *   调用 `SVGModelObjectPainter(layout_svg_image_).PaintOutline` 绘制 SVG 图像的轮廓。

**`PaintForeground` 函数的主要功能:**

9. **计算图像视口大小:**
    *   使用 `ComputeImageViewportSize` 函数计算 SVG 图像应该渲染的视口大小，这会考虑到 `preserveAspectRatio` 属性。

10. **获取图像资源:**
    *   从 `LayoutImageResource` 获取实际的 `Image` 对象。

11. **确定目标和源矩形:**
    *   `dest_rect`:  SVG `<image>` 元素在布局中占据的矩形区域 (`layout_svg_image_.ObjectBoundingBox()`)。
    *   `src_rect`:  SVG 图像的源矩形。

12. **处理 `preserveAspectRatio` 属性:**
    *   获取 `<image>` 元素的 `preserveAspectRatio` 属性，并使用 `TransformRect` 方法根据该属性将源矩形映射到目标矩形。这决定了图像如何缩放和对齐以适应目标区域。

13. **记录图像绘制时间:**
    *   如果图像已加载，则通过 `ImageElementTiming` API 记录图像的绘制时间，用于性能分析。
    *   通过 `PaintTiming` API 标记首次内容绘制（FCP）。

14. **应用图像渲染设置:**
    *   使用 `ScopedImageRenderingSettings` 应用 CSS 的 `image-rendering` 属性，控制图像的渲染质量和性能。

15. **获取解码模式:**
    *   根据元素的属性获取图像的解码模式。

16. **处理自动暗黑模式:**
    *   使用 `ImageClassifierHelper::GetImageAutoDarkMode` 判断是否需要应用自动暗黑模式。

17. **绘制图像:**
    *   最终调用 `paint_info.context.DrawImage` 函数将 SVG 图像绘制到画布上。这个函数接收图像对象、解码模式、暗黑模式信息、目标矩形、源矩形、混合模式和方向等参数。

**`ComputeImageViewportSize` 函数的主要功能:**

18. **计算默认对象大小:**
    *   根据布局对象的边界框和缩放比例计算默认的对象大小。

19. **处理 `preserveAspectRatio="none"`:**
    *   如果 `preserveAspectRatio` 属性的值为 `none`，则强制进行非均匀缩放。这通过将图像的容器大小设置为其视口大小来实现。

20. **处理错误图像:**
    *   如果图像资源加载出错，则返回空的 `gfx::SizeF()`。

**与 JavaScript, HTML, CSS 的关系:**

*   **HTML:**  `SVGImagePainter` 负责渲染 HTML 中 `<svg>` 标签内的 `<image>` 元素。`<img>` 标签也可以加载 SVG 文件，但渲染路径可能有所不同。
    *   **举例:**  在 HTML 中使用 `<svg>` 嵌入一个 SVG 图像：
        ```html
        <svg width="200" height="200">
          <image href="my_image.svg" width="100%" height="100%" />
        </svg>
        ```

*   **CSS:**  CSS 属性会影响 `SVGImagePainter` 的行为：
    *   `visibility`: 控制图像是否可见。`SVGImagePainter::Paint` 函数会检查这个属性。
    *   `opacity`: 控制图像的透明度，在 `ScopedSVGPaintState` 中可能被应用。
    *   `transform`:  CSS 的 `transform` 属性会影响 `layout_svg_image_.LocalSVGTransform()`，从而影响图像的绘制位置和形状。
    *   `object-fit` 和 `object-position`: 虽然在 SVG `<image>` 元素中主要由 `preserveAspectRatio` 控制，但对于作为背景图的 SVG，这些 CSS 属性会影响其渲染。
    *   `image-rendering`:  `SVGImagePainter::PaintForeground` 中使用 `ScopedImageRenderingSettings` 应用此属性，控制图像的渲染质量（例如，`auto`, `crisp-edges`, `pixelated`）。
    *   `zoom`:  `ComputeImageViewportSize` 函数会考虑 CSS 的 `zoom` 属性。
    *   **举例:** 使用 CSS 设置 SVG 图像的宽度和高度：
        ```css
        svg image {
          width: 150px;
          height: 150px;
        }
        ```

*   **JavaScript:**  JavaScript 可以通过 DOM API 操作 SVG `<image>` 元素及其属性，从而间接影响 `SVGImagePainter` 的行为。
    *   **举例:**  使用 JavaScript 动态改变 SVG 图像的 `href` 属性：
        ```javascript
        const imageElement = document.querySelector('svg image');
        imageElement.setAttribute('href', 'new_image.svg');
        ```
        当 `href` 改变时，浏览器会重新加载图像，并触发 `SVGImagePainter` 进行绘制。
    *   **举例:** 使用 JavaScript 修改 CSS 样式来改变 SVG 图像的 `transform` 属性，也会影响其绘制。

**逻辑推理 (假设输入与输出):**

假设我们有以下 SVG 代码：

```svg
<svg viewBox="0 0 100 100" width="200" height="200">
  <image href="my_vector_image.svg" x="10" y="10" width="80" height="80" preserveAspectRatio="xMidYMid meet" />
</svg>
```

以及对应的 `my_vector_image.svg`，其内部 `viewBox` 为 `0 0 50 50`。

**假设输入:**

*   `layout_svg_image_.ObjectBoundingBox()` (目标矩形):  假设根据 SVG 的 `width` 和 `height` 属性以及可能的 CSS 样式，计算出的目标矩形为 `(0, 0, 200, 200)`。
*   `image->SizeAsFloat()` (源图像大小): 假设 `my_vector_image.svg` 的原始大小为 `(50, 50)`。
*   `image_element->preserveAspectRatio()->CurrentValue()->Align()`: `SVGPreserveAspectRatio::kMid` (对应 `xMidYMid`)
*   `image_element->preserveAspectRatio()->CurrentValue()->MeetOrSlice()`: `SVGPreserveAspectRatio::kMeet`

**逻辑推理过程 (主要在 `PaintForeground` 中):**

1. `dest_rect` 初始化为 `(0, 0, 200, 200)`。
2. `src_rect` 初始化为 `(0, 0, 50, 50)`。
3. `preserveAspectRatio` 的值为 `xMidYMid meet`。
4. `image_element->preserveAspectRatio()->CurrentValue()->TransformRect(dest_rect, src_rect)` 会根据 `xMidYMid meet` 的规则调整 `src_rect` 以适应 `dest_rect`，同时保持图像的宽高比。
5. 由于 `meet` 的规则，图像会被缩放以完全包含在 `dest_rect` 中，并且在水平和垂直方向都居中。
6. 最终传递给 `paint_info.context.DrawImage` 的 `src_rect` 可能会被调整为例如 `(0, 0, 50, 50)`，而 `dest_rect` 仍然是 `(0, 0, 200, 200)`，但绘制时会考虑到 `preserveAspectRatio` 的影响，使得 SVG 图像在 `(0, 0, 200, 200)` 的区域内居中显示，并保持其原始宽高比。

**假设输出:**

*   绘制在屏幕上的 SVG 图像会按照 `xMidYMid meet` 的规则，在 200x200 的区域内居中显示，并缩放到合适的大小，保持其 50x50 的宽高比。

**用户或编程常见的使用错误:**

1. **错误的 `preserveAspectRatio` 值:**  使用不合适的 `preserveAspectRatio` 值可能导致图像变形或显示不完整。
    *   **举例:**  用户可能错误地使用了 `preserveAspectRatio="none"`，导致 SVG 图像在目标区域被拉伸或压缩，失去原始宽高比。

2. **`viewBox` 设置不当:**  SVG 内部的 `viewBox` 属性定义了 SVG 内容的可见区域。如果 `viewBox` 设置不当，可能会导致图像内容被裁剪或显示不完整。
    *   **举例:**  SVG 文件的 `viewBox="0 0 10 10"`，但实际内容超出了这个范围，则超出部分可能不会被渲染。

3. **图像路径错误:**  `<image>` 元素的 `href` 属性指向的 SVG 文件路径错误，导致图像无法加载。
    *   **举例:**  ` <image href="wrong_path/my_image.svg" ... />`，浏览器会尝试加载该路径，但如果文件不存在，则无法绘制。

4. **服务器端问题:**  如果 SVG 文件是从服务器加载的，服务器可能返回错误状态码（例如 404），导致图像加载失败。

5. **CSS 冲突或覆盖:**  CSS 样式可能会意外地影响 SVG 图像的显示，例如设置了 `overflow: hidden` 的父元素可能裁剪图像。

6. **忘记设置尺寸:**  如果没有为 `<svg>` 或 `<image>` 元素设置 `width` 和 `height`，可能会导致图像不显示或显示异常。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在 HTML 文件中添加了一个 `<svg>` 元素，并在其中使用了 `<image>` 元素来引用一个 SVG 图像文件。**
    ```html
    <!DOCTYPE html>
    <html>
    <head>
      <title>SVG Image Example</title>
    </head>
    <body>
      <svg width="300" height="200">
        <image href="my_image.svg" x="0" y="0" width="300" height="200"/>
      </svg>
    </body>
    </html>
    ```

2. **用户在浏览器中打开该 HTML 文件。**

3. **浏览器开始解析 HTML 代码，构建 DOM 树。**  当解析到 `<svg>` 和 `<image>` 元素时，会创建相应的 DOM 节点。

4. **浏览器加载 `my_image.svg` 文件。**  网络请求会被发送到服务器获取该文件。

5. **Blink 渲染引擎的布局（Layout）阶段会计算 SVG 元素及其子元素的布局信息。**  `LayoutSVGImage` 对象会被创建，并关联到 `<image>` 元素。

6. **Blink 渲染引擎的绘制（Paint）阶段开始。**  当需要绘制 `<image>` 元素时：
    *   会创建一个 `SVGImagePainter` 对象，并传入对应的 `LayoutSVGImage` 对象。
    *   `SVGImagePainter::Paint` 方法会被调用。
    *   该方法会检查绘制条件，例如可见性、图像是否加载完成等。
    *   如果条件满足，`PaintForeground` 方法会被调用，执行实际的图像绘制逻辑。

7. **在 `PaintForeground` 中，会计算视口大小，获取图像资源，并根据 `preserveAspectRatio` 属性确定源和目标矩形。**

8. **最终，`paint_info.context.DrawImage` 方法会被调用，将 SVG 图像渲染到屏幕上。**

**调试线索:**

*   **查看开发者工具的 "Elements" 面板:**  检查 `<svg>` 和 `<image>` 元素的属性值，特别是 `width`, `height`, `href`, `preserveAspectRatio`。
*   **查看开发者工具的 "Network" 面板:**  确认 SVG 图像文件是否成功加载，检查 HTTP 状态码。
*   **查看开发者工具的 "Computed" 面板:**  检查应用于 `<svg>` 和 `<image>` 元素的 CSS 样式，特别是影响布局和渲染的属性。
*   **使用 "Paint Flashing" (渲染闪烁) 工具:**  在 Chrome 开发者工具的 "Rendering" 标签页中启用 "Paint Flashing"，可以高亮显示重绘区域，帮助定位问题。
*   **断点调试 C++ 代码:**  如果需要深入了解 Blink 的渲染过程，可以在 `blink/renderer/core/paint/svg_image_painter.cc` 文件中设置断点，例如在 `SVGImagePainter::Paint` 或 `SVGImagePainter::PaintForeground` 方法中，逐步跟踪代码执行流程，查看变量的值，理解图像的绘制过程。
*   **检查控制台错误信息:**  浏览器可能会在控制台输出与 SVG 图像加载或渲染相关的错误信息。

通过以上步骤和调试线索，开发者可以定位和解决 SVG 图像渲染过程中出现的问题。

Prompt: 
```
这是目录为blink/renderer/core/paint/svg_image_painter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/svg_image_painter.h"

#include "third_party/blink/renderer/core/layout/layout_box_model_object.h"
#include "third_party/blink/renderer/core/layout/layout_image_resource.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_image.h"
#include "third_party/blink/renderer/core/paint/paint_auto_dark_mode.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/paint/scoped_svg_paint_state.h"
#include "third_party/blink/renderer/core/paint/svg_model_object_painter.h"
#include "third_party/blink/renderer/core/paint/timing/image_element_timing.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing_detector.h"
#include "third_party/blink/renderer/core/svg/svg_animated_preserve_aspect_ratio.h"
#include "third_party/blink/renderer/core/svg/svg_animated_rect.h"
#include "third_party/blink/renderer/core/svg/svg_element.h"
#include "third_party/blink/renderer/core/svg/svg_image_element.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"
#include "third_party/blink/renderer/platform/graphics/scoped_image_rendering_settings.h"

namespace blink {

namespace {
ImagePaintTimingInfo ComputeImagePaintTimingInfo(
    const LayoutSVGImage& layout_image,
    const Image& image,
    const ImageResourceContent* image_content,
    const GraphicsContext& context,
    const gfx::Rect& image_border) {
  return ImagePaintTimingInfo(PaintTimingDetector::NotifyImagePaint(
      layout_image, image.Size(), *image_content,
      context.GetPaintController().CurrentPaintChunkProperties(),
      image_border));
}
}  // namespace

void SVGImagePainter::Paint(const PaintInfo& paint_info) {
  if (paint_info.phase != PaintPhase::kForeground ||
      layout_svg_image_.StyleRef().Visibility() != EVisibility::kVisible ||
      !layout_svg_image_.ImageResource()->HasImage()) {
    return;
  }

  if (SVGModelObjectPainter::CanUseCullRect(layout_svg_image_.StyleRef())) {
    if (!paint_info.GetCullRect().IntersectsTransformed(
            layout_svg_image_.LocalSVGTransform(),
            layout_svg_image_.VisualRectInLocalSVGCoordinates()))
      return;
  }
  // Images cannot have children so do not call TransformCullRect.

  ScopedSVGTransformState transform_state(paint_info, layout_svg_image_);
  {
    ScopedSVGPaintState paint_state(layout_svg_image_, paint_info);
    SVGModelObjectPainter::RecordHitTestData(layout_svg_image_, paint_info);
    SVGModelObjectPainter::RecordRegionCaptureData(layout_svg_image_,
                                                   paint_info);
    if (!DrawingRecorder::UseCachedDrawingIfPossible(
            paint_info.context, layout_svg_image_, paint_info.phase)) {
      SVGDrawingRecorder recorder(paint_info.context, layout_svg_image_,
                                  paint_info.phase);
      PaintForeground(paint_info);
    }
  }

  SVGModelObjectPainter(layout_svg_image_).PaintOutline(paint_info);
}

void SVGImagePainter::PaintForeground(const PaintInfo& paint_info) {
  gfx::SizeF image_viewport_size = ComputeImageViewportSize();
  if (image_viewport_size.IsEmpty())
    return;

  const LayoutImageResource& image_resource =
      *layout_svg_image_.ImageResource();
  scoped_refptr<Image> image = image_resource.GetImage(image_viewport_size);
  gfx::RectF dest_rect = layout_svg_image_.ObjectBoundingBox();
  auto* image_element = To<SVGImageElement>(layout_svg_image_.GetElement());
  RespectImageOrientationEnum respect_orientation =
      image_resource.ImageOrientation();

  gfx::RectF src_rect(image->SizeAsFloat(respect_orientation));
  if (respect_orientation && !image->HasDefaultOrientation()) {
    // We need the oriented source rect for adjusting the aspect ratio
    gfx::SizeF unadjusted_size = src_rect.size();
    image_element->preserveAspectRatio()->CurrentValue()->TransformRect(
        dest_rect, src_rect);

    // Map the oriented_src_rect back into the src_rect space
    src_rect =
        image->CorrectSrcRectForImageOrientation(unadjusted_size, src_rect);
  } else {
    image_element->preserveAspectRatio()->CurrentValue()->TransformRect(
        dest_rect, src_rect);
  }

  ImageResourceContent* image_content = image_resource.CachedImage();
  if (image_content->IsLoaded()) {
    LocalDOMWindow* window = layout_svg_image_.GetDocument().domWindow();
    DCHECK(window);
    ImageElementTiming::From(*window).NotifyImagePainted(
        layout_svg_image_, *image_content,
        paint_info.context.GetPaintController().CurrentPaintChunkProperties(),
        gfx::ToEnclosingRect(dest_rect));
  }
  PaintTiming& timing = PaintTiming::From(layout_svg_image_.GetDocument());
  timing.MarkFirstContentfulPaint();

  ScopedImageRenderingSettings image_rendering_settings_scope(
      paint_info.context,
      layout_svg_image_.StyleRef().GetInterpolationQuality(),
      layout_svg_image_.StyleRef().GetDynamicRangeLimit());
  Image::ImageDecodingMode decode_mode =
      image_element->GetDecodingModeForPainting(image->paint_image_id());
  auto image_auto_dark_mode = ImageClassifierHelper::GetImageAutoDarkMode(
      *layout_svg_image_.GetFrame(), layout_svg_image_.StyleRef(), dest_rect,
      src_rect);
  paint_info.context.DrawImage(
      *image, decode_mode, image_auto_dark_mode,
      ComputeImagePaintTimingInfo(layout_svg_image_, *image, image_content,
                                  paint_info.context,
                                  gfx::ToEnclosingRect(dest_rect)),
      dest_rect, &src_rect, SkBlendMode::kSrcOver, respect_orientation);
}

gfx::SizeF SVGImagePainter::ComputeImageViewportSize() const {
  DCHECK(layout_svg_image_.ImageResource()->HasImage());

  const float zoom = layout_svg_image_.StyleRef().EffectiveZoom();
  const gfx::SizeF default_object_size =
      gfx::ScaleSize(layout_svg_image_.ObjectBoundingBox().size(), zoom);

  if (To<SVGImageElement>(layout_svg_image_.GetElement())
          ->preserveAspectRatio()
          ->CurrentValue()
          ->Align() != SVGPreserveAspectRatio::kSvgPreserveaspectratioNone) {
    return default_object_size;
  }

  // Images with preserveAspectRatio=none should force non-uniform scaling. This
  // can be achieved by setting the image's container size to its viewport size
  // (i.e. concrete object size returned by the default sizing algorithm.)  See
  // https://www.w3.org/TR/SVG/single-page.html#coords-PreserveAspectRatioAttribute
  // and https://drafts.csswg.org/css-images-3/#default-sizing.

  const LayoutImageResource& image_resource =
      *layout_svg_image_.ImageResource();
  // Avoid returning the size of the broken image.
  if (image_resource.ErrorOccurred()) {
    return gfx::SizeF();
  }
  return image_resource.ConcreteObjectSize(zoom, default_object_size);
}

}  // namespace blink

"""

```