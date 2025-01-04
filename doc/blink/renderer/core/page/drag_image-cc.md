Response:
Let's break down the thought process to analyze the `drag_image.cc` file.

1. **Understand the Goal:** The primary goal is to understand the functionality of this specific file in the Chromium Blink rendering engine. Specifically, how it relates to drag-and-drop operations involving images.

2. **Initial Code Scan & Keyword Identification:**  Read through the code, looking for obvious keywords and function names. Terms like "DragImage," "Create," "Scale," "Bitmap," "Font," "Text," "URL," "Image," "Canvas," "Paint," "Resize," "Orientation" immediately stand out. These provide a high-level understanding of what the file likely handles. The copyright notice also confirms it's related to Apple's work (likely a historical artifact).

3. **Identify Core Data Structures:** Notice the use of `SkBitmap`, `PaintImage`, `Font`, `TextRun`, `KURL`, `String`, and the `DragImage` class itself. Recognizing these types helps in understanding the data the code manipulates.

4. **Analyze the `DragImage` Class:**  This is the central entity. Observe its constructor and destructor. The constructor takes a `SkBitmap` and `InterpolationQuality`. The destructor is default, suggesting no complex cleanup. The `Scale` method is present, which indicates image scaling is a key function.

5. **Deconstruct `Create` Methods:** The file has two `Create` methods for `DragImage`. This immediately signals two different creation paths.

    * **`Create(Image*, ...)`:** This overload clearly deals with existing `Image` objects. The parameters (`RespectImageOrientationEnum`, `InterpolationQuality`, `opacity`, `image_scale`) point to image manipulation. The code within confirms this: extracting `PaintImage`, handling orientation, resizing, applying opacity, and converting to `SkBitmap`.

    * **`Create(const KURL&, const String&, float)`:** This overload takes a URL and a label. This strongly suggests creating a drag image *representing* a link. The code confirms this by creating fonts, measuring text, drawing text onto a canvas, and generating a bitmap.

6. **Examine Helper Functions and Constants:**  The anonymous namespace contains constants like `kDragLabelBorderX`, `kDragLabelBorderY`, font sizes, and a maximum label width. The `DeriveDragLabelFont` function is a helper for creating fonts for the link label. The `ClampedImageScale` function is used for calculating scaling factors. Understanding these details provides context for how the drag image is constructed.

7. **Connect to Web Technologies (JavaScript, HTML, CSS):**  Consider how these C++ concepts map to web technologies.

    * **HTML:**  Dragging elements like `<img>` tags or links (`<a>`) would trigger the functionality in this file.
    * **CSS:**  While not directly manipulated here, CSS styles (like font properties) would influence the appearance of the *original* element being dragged, which in turn might affect how the drag image is created (especially for link previews). The layout of the page (affected by CSS) determines which element is being dragged.
    * **JavaScript:** JavaScript's Drag and Drop API (`dragstart`, `dragend`, etc.) initiates the drag operation that eventually uses this C++ code to generate the visual representation of the dragged item.

8. **Consider User Actions and Debugging:**  Think about how a user's actions in a browser would lead to this code being executed. Dragging an image or a link is the obvious trigger. For debugging, understanding this user flow is crucial. You'd need to trace back from the user interaction to the C++ code.

9. **Identify Potential Issues (User Errors/Common Mistakes):**  Consider scenarios where things might go wrong. Incorrect image paths, very long URLs, or conflicting CSS styles could lead to unexpected results in the drag image generation.

10. **Structure the Output:** Organize the findings into clear categories: Functionality, Relationship to Web Technologies, Logic and Examples, Common Errors, and User Interaction/Debugging. Use clear language and provide concrete examples where possible.

11. **Refine and Elaborate:** Review the initial analysis and add more detail. For instance, explain *why* certain decisions are made in the code (e.g., using `StringTruncator`). Expand on the JavaScript API connection.

**Self-Correction/Refinement Example During the Process:**

* **Initial Thought:**  "The file just creates a scaled version of the image."
* **Realization:** "Wait, there's another `Create` method for URLs. This means it also generates drag images for links, which involves drawing text."
* **Correction:**  Adjust the understanding of the file's scope to include both image and link drag image creation. Focus on the text rendering aspects for the link case.

By following these steps, combining code analysis with an understanding of web technologies and user interactions, a comprehensive explanation of the `drag_image.cc` file can be developed.
好的，让我们来分析一下 `blink/renderer/core/page/drag_image.cc` 这个文件。

**文件功能概要:**

`drag_image.cc` 文件的主要功能是**生成用于拖放操作的拖动图像**。当用户在网页上拖动某个元素（例如图片、链接或选中的文本）时，浏览器会创建一个临时的视觉表示，即拖动图像，跟随鼠标指针移动。这个文件负责创建和定制这个拖动图像。

**功能详细拆解:**

1. **创建图像:**
   - 接收一个 `Image` 对象作为输入，并根据需要进行缩放、旋转和调整透明度等操作，生成一个适合作为拖动图像的 `SkBitmap`。
   - 可以选择是否尊重图像的 EXIF 方向信息 (`RespectImageOrientationEnum`)。
   - 可以设置插值质量 (`InterpolationQuality`)，影响缩放时的图像质量。
   - 可以设置透明度 (`opacity`)。
   - 可以指定缩放比例 (`image_scale`)。

2. **创建链接拖动图像:**
   - 接收一个 `KURL` (URL) 和一个可选的标签 (`String`) 作为输入。
   - 生成一个包含链接 URL 或标签的文本图像作为拖动图像。
   - 可以自定义字体大小、粗细和边框样式。
   - 如果标签为空，则使用 URL 作为文本。
   - 会根据最大宽度限制对文本进行截断。

3. **缩放图像:**
   - 提供 `Scale` 方法，允许在已有的拖动图像上进行缩放操作。

4. **辅助功能:**
   - 提供 `ClampedImageScale` 静态方法，用于计算在给定原始尺寸、目标尺寸和最大尺寸限制下的缩放比例，并进行统一缩放以避免超出最大尺寸。

**与 JavaScript, HTML, CSS 的关系:**

这个文件虽然是 C++ 代码，但它直接服务于浏览器渲染引擎处理用户在网页上的拖放操作，而这些操作通常是由 JavaScript API 触发的，并且作用于 HTML 元素和由 CSS 定义的样式。

**举例说明:**

* **HTML:** 用户在 HTML 页面中拖动一个 `<img>` 标签。
  ```html
  <img id="draggableImage" src="my_image.png" draggable="true">
  ```
  当用户开始拖动这个图片时，Blink 引擎会调用 `drag_image.cc` 中的 `DragImage::Create` 方法，传入 `my_image.png` 对应的 `Image` 对象，生成拖动时显示的图像。

* **JavaScript:**  JavaScript 的 Drag and Drop API 可以自定义拖动行为，包括设置拖动图像。
  ```javascript
  const draggableImage = document.getElementById('draggableImage');
  draggableImage.addEventListener('dragstart', (event) => {
    // 自定义拖动图像
    const dragIcon = document.createElement('img');
    dragIcon.src = 'custom_drag_icon.png';
    event.dataTransfer.setDragImage(dragIcon, -10, -10); // 设置拖动图像和偏移量
  });
  ```
  即使 JavaScript 设置了自定义的拖动图像，在某些情况下，浏览器仍然可能使用 `drag_image.cc` 来生成默认的拖动图像，例如在没有设置 `setDragImage` 的情况下，或者用于生成链接的默认拖动图像。

* **CSS:** CSS 样式会影响被拖动元素的外观，这间接地影响了 `drag_image.cc` 如何创建拖动图像。例如，如果拖动的是一个带有边框或背景色的 `<div>` 元素，浏览器可能会捕获该元素的渲染结果作为拖动图像。

**逻辑推理 (假设输入与输出):**

**场景 1: 拖动一个简单的图片**

* **假设输入:**
    * `image`: 指向 `my_image.png` 的 `Image` 对象。
    * `should_respect_image_orientation`: `kRespectImageOrientation` (假设需要尊重 EXIF 信息)。
    * `interpolation_quality`: `kInterpolationHigh`。
    * `opacity`: 1.0。
    * `image_scale`: (1.0, 1.0) (不缩放)。
* **预期输出:**
    * 返回一个指向 `DragImage` 对象的指针，该对象内部包含 `my_image.png` 的 `SkBitmap` 表示，并且考虑了图像的 EXIF 方向信息，使用高质量插值，不透明。

**场景 2: 拖动一个链接**

* **假设输入:**
    * `url`: `https://www.example.com/page`.
    * `in_label`: "Example Page"。
    * `device_scale_factor`: 2.0 (高 DPI 屏幕)。
* **预期输出:**
    * 返回一个指向 `DragImage` 对象的指针，该对象内部包含一个文本图像的 `SkBitmap`，显示 "Example Page" (使用粗体字体) 和 "www.example.com/page" (使用普通字体)，带有灰色背景和圆角边框，并根据 `device_scale_factor` 进行了缩放以适应高 DPI 屏幕。

**用户或编程常见的使用错误:**

1. **图片资源无法加载:** 如果拖动的 `<img>` 标签的 `src` 指向的图片资源无法加载，`DragImage::Create` 方法可能会返回 `nullptr`，导致拖动时没有图像显示或显示一个默认的占位符。
2. **自定义拖动图像尺寸过大:**  如果通过 JavaScript 的 `setDragImage` 设置的拖动图像尺寸过大，可能会影响拖动体验，甚至导致性能问题。虽然 `drag_image.cc` 自身会进行一些限制（例如链接拖动图像的最大宽度），但自定义图像不受此限制。
3. **忘记设置 `draggable="true"`:** 如果 HTML 元素没有设置 `draggable="true"` 属性，用户无法拖动它，自然也不会触发 `drag_image.cc` 的相关代码。
4. **误解 `setDragImage` 的作用范围:**  开发者可能认为 `setDragImage` 可以完全控制所有拖动图像的生成，但浏览器在某些情况下仍然会使用默认的拖动图像生成逻辑。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户发起拖动:** 用户在浏览器窗口中，用鼠标点击并按住一个可以拖动的元素（例如图片、链接或选中文本）。
2. **浏览器识别拖动事件:** 浏览器事件循环捕获到 `mousedown` 事件，并判断该元素是否可以拖动。
3. **触发 `dragstart` 事件 (如果存在 JavaScript 监听器):** 如果该元素有 `dragstart` 事件监听器，则执行相应的 JavaScript 代码。
4. **Blink 引擎开始处理拖动:** Blink 渲染引擎的拖动控制器 (`DragController`) 开始介入处理拖动操作。
5. **创建拖动图像:**
   - 如果 JavaScript 代码中使用了 `event.dataTransfer.setDragImage()`，则使用指定的图像作为拖动图像。
   - 否则，`DragController` 会根据被拖动的元素类型，调用 `drag_image.cc` 中的 `DragImage::Create` 方法来生成默认的拖动图像。
     - 如果拖动的是 `<img>` 元素，则调用 `DragImage::Create(Image*, ...)`。
     - 如果拖动的是链接，则调用 `DragImage::Create(const KURL&, const String&, float)`。
     - 如果拖动的是其他类型的元素，可能会有其他的拖动图像生成逻辑，但 `drag_image.cc` 负责处理图片和链接的情况。
6. **显示拖动图像:** 生成的 `DragImage` 对象被用于在鼠标指针附近渲染拖动时的视觉反馈。
7. **用户移动鼠标:** 浏览器不断更新拖动图像的位置，使其跟随鼠标指针移动。
8. **用户释放鼠标:** 当用户释放鼠标按钮时，触发 `dragend` 或 `drop` 事件，拖动操作结束。

**调试线索:**

如果在调试拖放相关的问题，可以关注以下几点：

* **断点设置:** 在 `DragImage::Create` 的不同重载版本中设置断点，查看何时以及如何创建拖动图像。
* **检查 `Image` 对象:** 如果拖动的是图片，检查传入 `DragImage::Create` 的 `Image` 对象是否有效，图片资源是否加载成功。
* **检查 URL 和标签:** 如果拖动的是链接，检查传入 `DragImage::Create` 的 URL 和标签是否正确。
* **查看 `device_scale_factor`:**  在高 DPI 屏幕上，`device_scale_factor` 的值会影响链接拖动图像的渲染。
* **分析 JavaScript 代码:** 检查是否有 JavaScript 代码干扰了默认的拖动行为或自定义了拖动图像。
* **使用开发者工具:** 使用 Chrome 开发者工具的 "Elements" 面板查看被拖动元素的属性和事件监听器，使用 "Sources" 面板进行代码调试。

希望以上分析能够帮助你理解 `blink/renderer/core/page/drag_image.cc` 文件的功能和作用。

Prompt: 
```
这是目录为blink/renderer/core/page/drag_image.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2007 Apple Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/page/drag_image.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "base/memory/ptr_util.h"
#include "base/memory/scoped_refptr.h"
#include "skia/ext/image_operations.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/layout/layout_theme_font_provider.h"
#include "third_party/blink/renderer/platform/fonts/font.h"
#include "third_party/blink/renderer/platform/fonts/font_cache.h"
#include "third_party/blink/renderer/platform/fonts/font_description.h"
#include "third_party/blink/renderer/platform/fonts/font_metrics.h"
#include "third_party/blink/renderer/platform/fonts/string_truncator.h"
#include "third_party/blink/renderer/platform/fonts/text_run_paint_info.h"
#include "third_party/blink/renderer/platform/graphics/bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/canvas_resource_provider.h"
#include "third_party/blink/renderer/platform/graphics/color.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"
#include "third_party/blink/renderer/platform/graphics/static_bitmap_image.h"
#include "third_party/blink/renderer/platform/text/text_run.h"
#include "third_party/blink/renderer/platform/transforms/affine_transform.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "ui/gfx/geometry/point.h"
#include "ui/gfx/geometry/point_f.h"
#include "ui/gfx/geometry/rect_f.h"

namespace blink {

namespace {

const float kDragLabelBorderX = 4;
// Keep border_y in synch with DragController::LinkDragBorderInset.
const float kDragLabelBorderY = 2;
const float kLabelBorderYOffset = 2;

const float kMaxDragLabelWidth = 300;
const float kMaxDragLabelStringWidth =
    (kMaxDragLabelWidth - 2 * kDragLabelBorderX);

const float kDragLinkLabelFontSize = 11;
const float kDragLinkUrlFontSize = 10;

}  // anonymous namespace

gfx::Vector2dF DragImage::ClampedImageScale(const gfx::Size& image_size,
                                            const gfx::Size& size,
                                            const gfx::Size& max_size) {
  // Non-uniform scaling for size mapping.
  gfx::Vector2dF image_scale(
      static_cast<float>(size.width()) / image_size.width(),
      static_cast<float>(size.height()) / image_size.height());

  // Uniform scaling for clamping.
  const float clamp_scale_x =
      size.width() > max_size.width()
          ? static_cast<float>(max_size.width()) / size.width()
          : 1;
  const float clamp_scale_y =
      size.height() > max_size.height()
          ? static_cast<float>(max_size.height()) / size.height()
          : 1;
  image_scale.Scale(std::min(clamp_scale_x, clamp_scale_y));

  return image_scale;
}

std::unique_ptr<DragImage> DragImage::Create(
    Image* image,
    RespectImageOrientationEnum should_respect_image_orientation,
    InterpolationQuality interpolation_quality,
    float opacity,
    gfx::Vector2dF image_scale) {
  if (!image)
    return nullptr;

  PaintImage paint_image = image->PaintImageForCurrentFrame();
  if (!paint_image)
    return nullptr;

  ImageOrientation orientation;
  auto* bitmap_image = DynamicTo<BitmapImage>(image);
  if (should_respect_image_orientation == kRespectImageOrientation &&
      bitmap_image)
    orientation = bitmap_image->CurrentFrameOrientation();

  SkBitmap bm;
  paint_image = Image::ResizeAndOrientImage(
      paint_image, orientation, image_scale, opacity, interpolation_quality,
      SkColorSpace::MakeSRGB());
  if (!paint_image || !paint_image.GetSwSkImage()->asLegacyBitmap(&bm))
    return nullptr;

  return base::WrapUnique(new DragImage(bm, interpolation_quality));
}

static Font DeriveDragLabelFont(int size, FontSelectionValue font_weight) {
  const AtomicString& family =
      LayoutThemeFontProvider::SystemFontFamily(CSSValueID::kNone);

  FontDescription description;
  description.SetFamily(
      FontFamily(family, FontFamily::InferredTypeFor(family)));
  description.SetWeight(font_weight);
  description.SetSpecifiedSize(size);
  description.SetComputedSize(size);
  Font result(description);
  return result;
}

// static
std::unique_ptr<DragImage> DragImage::Create(const KURL& url,
                                             const String& in_label,
                                             float device_scale_factor) {
  const Font label_font =
      DeriveDragLabelFont(kDragLinkLabelFontSize, kBoldWeightValue);
  const SimpleFontData* label_font_data = label_font.PrimaryFont();
  DCHECK(label_font_data);
  const Font url_font =
      DeriveDragLabelFont(kDragLinkUrlFontSize, kNormalWeightValue);
  const SimpleFontData* url_font_data = url_font.PrimaryFont();
  DCHECK(url_font_data);

  if (!label_font_data || !url_font_data)
    return nullptr;

  FontCachePurgePreventer font_cache_purge_preventer;

  bool draw_url_string = true;
  bool clip_url_string = false;
  bool clip_label_string = false;
  float max_drag_label_string_width_dip =
      kMaxDragLabelStringWidth / device_scale_factor;

  String url_string = url.GetString();
  String label = in_label.StripWhiteSpace();
  if (label.empty()) {
    draw_url_string = false;
    label = url_string;
  }

  // First step is drawing the link drag image width.
  TextRun label_run(label.Impl());
  TextRun url_run(url_string.Impl());
  gfx::Size label_size(label_font.Width(label_run),
                       label_font_data->GetFontMetrics().Ascent() +
                           label_font_data->GetFontMetrics().Descent());

  if (label_size.width() > max_drag_label_string_width_dip) {
    label_size.set_width(max_drag_label_string_width_dip);
    clip_label_string = true;
  }

  gfx::Size url_string_size;
  gfx::Size image_size(label_size.width() + kDragLabelBorderX * 2,
                       label_size.height() + kDragLabelBorderY * 2);

  if (draw_url_string) {
    url_string_size.set_width(url_font.Width(url_run));
    url_string_size.set_height(url_font_data->GetFontMetrics().Ascent() +
                               url_font_data->GetFontMetrics().Descent());
    image_size.set_height(image_size.height() + url_string_size.height());
    if (url_string_size.width() > max_drag_label_string_width_dip) {
      image_size.set_width(max_drag_label_string_width_dip);
      clip_url_string = true;
    } else {
      image_size.set_width(
          std::max(label_size.width(), url_string_size.width()) +
          kDragLabelBorderX * 2);
    }
  }

  // We now know how big the image needs to be, so we create and
  // fill the background
  gfx::Size scaled_image_size =
      gfx::ScaleToFlooredSize(image_size, device_scale_factor);
  // TODO(fserb): are we sure this should be software?
  std::unique_ptr<CanvasResourceProvider> resource_provider(
      CanvasResourceProvider::CreateBitmapProvider(
          SkImageInfo::MakeN32Premul(scaled_image_size.width(),
                                     scaled_image_size.height()),
          cc::PaintFlags::FilterQuality::kLow,
          CanvasResourceProvider::ShouldInitialize::kNo));
  if (!resource_provider)
    return nullptr;

  resource_provider->Canvas().scale(device_scale_factor, device_scale_factor);

  const float kDragLabelRadius = 5;

  gfx::Rect rect(image_size);
  cc::PaintFlags background_paint;
  background_paint.setColor(SkColorSetRGB(140, 140, 140));
  background_paint.setAntiAlias(true);
  SkRRect rrect;
  rrect.setRectXY(SkRect::MakeWH(image_size.width(), image_size.height()),
                  kDragLabelRadius, kDragLabelRadius);
  resource_provider->Canvas().drawRRect(rrect, background_paint);

  // Draw the text
  cc::PaintFlags text_paint;
  if (draw_url_string) {
    if (clip_url_string)
      url_string = StringTruncator::CenterTruncate(
          url_string, image_size.width() - (kDragLabelBorderX * 2.0f),
          url_font);
    gfx::PointF text_pos(
        kDragLabelBorderX,
        image_size.height() -
            (kLabelBorderYOffset + url_font_data->GetFontMetrics().Descent()));
    TextRun text_run(url_string);
    url_font.DrawText(&resource_provider->Canvas(), TextRunPaintInfo(text_run),
                      text_pos, device_scale_factor, text_paint);
  }

  if (clip_label_string) {
    label = StringTruncator::RightTruncate(
        label, image_size.width() - (kDragLabelBorderX * 2.0f), label_font);
  }

  TextRun text_run(label);
  text_run.SetDirectionFromText();
  gfx::Point text_pos(
      kDragLabelBorderX,
      kDragLabelBorderY + label_font.GetFontDescription().ComputedPixelSize());
  if (text_run.Direction() == TextDirection::kRtl) {
    float text_width = label_font.Width(text_run);
    int available_width = image_size.width() - kDragLabelBorderX * 2;
    text_pos.set_x(available_width - ceilf(text_width));
  }
  label_font.DrawBidiText(&resource_provider->Canvas(),
                          TextRunPaintInfo(text_run), gfx::PointF(text_pos),
                          Font::kDoNotPaintIfFontNotReady, text_paint);

  scoped_refptr<StaticBitmapImage> image =
      resource_provider->Snapshot(FlushReason::kNon2DCanvas);
  return DragImage::Create(image.get(), kRespectImageOrientation);
}

DragImage::DragImage(const SkBitmap& bitmap,
                     InterpolationQuality interpolation_quality)
    : bitmap_(bitmap), interpolation_quality_(interpolation_quality) {}

DragImage::~DragImage() = default;

void DragImage::Scale(float scale_x, float scale_y) {
  skia::ImageOperations::ResizeMethod resize_method =
      interpolation_quality_ == kInterpolationNone
          ? skia::ImageOperations::RESIZE_BOX
          : skia::ImageOperations::RESIZE_LANCZOS3;
  int image_width = scale_x * bitmap_.width();
  int image_height = scale_y * bitmap_.height();
  bitmap_ = skia::ImageOperations::Resize(bitmap_, resize_method, image_width,
                                          image_height);
}

}  // namespace blink

"""

```